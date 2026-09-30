"""Tests for the trackcourier.io webhook receiver.

Each test guards a mistake that is easy to make in the other direction, and
each has been watched to fail: break the code it guards and it goes red.
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import Receiver, create_app
from signature import compute_signature

SECRET = "test-secret-do-not-use"
PREVIOUS_SECRET = "test-previous-secret-do-not-use"


def wire_body(
    event="tracking.in_transit",
    tn="ZZ000000001TEST",
    status="in_transit",
    courier="dtdc",
    enqueued_at="2026-08-28T10:00:00Z",
    checkpoints=(),
):
    """A payload shaped exactly like a live webhook delivery."""
    return {
        "event": event,
        "enqueued_at": enqueued_at,
        "data": {
            "tracking_number": tn,
            "courier": courier,
            "status": status,
            "most_recent_status": None,
            "origin_city": None,
            "destination_city": None,
            "delivered_date": None,
            "checkpoints": list(checkpoints),
            "enqueued_at": enqueued_at,
        },
    }


def checkpoint(activity, checkpoint_state, date, time):
    """One live-shaped checkpoint."""
    return {
        "activity": activity,
        "checkpoint_state": checkpoint_state,
        "courier_name": "DTDC",
        "date": date,
        "time": time,
        "location": "Delhi",
    }


@pytest.fixture
def receiver():
    return Receiver(secret=SECRET)


@pytest.fixture
def client(receiver):
    return TestClient(create_app(receiver))


def post(client, raw: bytes, signature=None, delivery="wh_abc-1", event=None, path="/webhook"):
    """POST raw bytes with the four headers a delivery carries.

    X-Webhook-Event defaults to the body's own event, as on the wire. Redirects
    are not followed: the sender re-issues a redirected delivery as a GET
    without the body, so a redirect must fail a test rather than be absorbed.
    """
    if event is None:
        try:
            event = str(json.loads(raw).get("event", ""))
        except (ValueError, AttributeError):
            event = ""
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Event": event,
        "X-Webhook-Delivery": delivery,
        "X-Webhook-Mode": "live",
    }
    if signature is not None:
        headers["X-Trackcourier-Signature"] = signature
    return client.post(path, content=raw, headers=headers, follow_redirects=False)


# --- A2: raw body handling -------------------------------------------------


def test_raw_body_captured_byte_identical(client, receiver):
    """The stored bytes are the bytes that arrived.

    Uses whitespace and key order NO serializer would reproduce, so a receiver
    that parsed and re-serialized would fail this.
    """
    raw = b'{"event":"tracking.in_transit",   "z":1,\n  "data":{"tracking_number":"A1","status":"in_transit"}}'
    assert post(client, raw).status_code == 200
    assert receiver.deliveries[0].raw_body == raw


def test_malformed_json_does_not_crash_the_endpoint(client, receiver):
    """A bad body is recorded with a parse error, never a 5xx.

    A crash on a malformed payload turns one bad delivery into a six-attempt
    retry chain against a dead endpoint.
    """
    resp = post(client, b'{"event": broken,,,')
    assert resp.status_code == 200
    assert resp.json()["received"] is True
    assert receiver.deliveries[0].parse_error is not None
    assert receiver.deliveries[0].body is None


def test_trailing_slash_url_is_answered_not_redirected(client, receiver):
    """A delivery is answered at the URL it was sent to, never redirected.

    The sender follows a redirect by re-issuing the request as a GET without
    the body, so a receiver that redirects /webhook/ to /webhook turns every
    delivery to that URL into a failure. Both spellings are registered.
    """
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature(SECRET, raw), path="/webhook/")
    assert resp.status_code == 200, f"answered {resp.status_code}, not 200"
    assert receiver.deliveries[0].signature_ok is True


# --- A3: signature verification --------------------------------------------


def test_valid_signature_accepted(client, receiver):
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
    assert resp.json()["signature_ok"] is True
    assert receiver.deliveries[0].signature_ok is True


def test_tampered_body_rejected(client, receiver):
    """Sign one body, deliver another. The signature must not verify."""
    raw = json.dumps(wire_body()).encode()
    good_sig = compute_signature(SECRET, raw)
    tampered = raw.replace(b"in_transit", b"delivered")
    assert tampered != raw
    resp = post(client, tampered, signature=good_sig)
    assert resp.json()["signature_ok"] is False


def test_reserialized_body_reproduces_the_mismatch(client):
    """Documents the trap by asserting the failure.

    Ours is compact-separated; a default json.dumps adds a space after ':' and
    ','. Same object, different bytes, different digest. This is why the raw
    body has to be captured before parsing.
    """
    ours = json.dumps(wire_body(), separators=(",", ":")).encode()
    theirs = json.dumps(json.loads(ours)).encode()
    assert ours != theirs, "the two serializations must differ for this to test anything"
    resp = post(client, theirs, signature=compute_signature(SECRET, ours))
    assert resp.json()["signature_ok"] is False


def test_signature_over_noncanonical_bytes_verifies(client):
    """Verification runs over the bytes that arrived, not a re-serialization.

    Whitespace and key order no serializer reproduces: a receiver that parsed
    and re-encoded the body before verifying would reject this valid delivery.
    """
    raw = b'{ "data" : {"tracking_number":"A1",\n "courier":"dtdc"},   "event":"tracking.in_transit" }'
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
    assert resp.json()["signature_ok"] is True


def test_signature_is_hmac_sha256_of_the_raw_body_keyed_with_the_secret(client):
    """The contract, computed here without the receiver's own helper.

    "sha256=" + hex(HMAC-SHA256(secret, raw body)). A test that signs with the
    receiver's helper cannot notice that helper drifting from this.
    """
    raw = json.dumps(wire_body()).encode()
    expected = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    assert post(client, raw, signature=expected).json()["signature_ok"] is True


def rotating_receiver_and_client():
    """A receiver mid-rotation: SECRET is the new secret, PREVIOUS_SECRET the old."""
    receiver = Receiver(secret=SECRET, previous_secret=PREVIOUS_SECRET)
    return receiver, TestClient(create_app(receiver))


def test_previous_secret_still_verifies_during_rotation():
    """Rotation is not atomic, so accept the old secret across the changeover.

    For a while after a rotation some deliveries are still signed with the old
    secret. A receiver that checks only the new one rejects them.
    """
    receiver, client = rotating_receiver_and_client()
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature(PREVIOUS_SECRET, raw))
    assert resp.json()["signature_ok"] is True
    assert receiver.deliveries[0].verified_only_by_previous_secret is True


def test_current_secret_verifies_without_the_previous_secret_mark():
    """The mark means "only the old secret verifies this", nothing wider.

    It is what tells you when the old secret can go, so it must not appear on
    deliveries the new secret verifies.
    """
    receiver, client = rotating_receiver_and_client()
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
    assert resp.json()["signature_ok"] is True
    assert receiver.deliveries[0].verified_only_by_previous_secret is False


def test_body_signed_with_neither_secret_is_rejected_during_rotation():
    """Holding two secrets widens what verifies to exactly those two."""
    _, client = rotating_receiver_and_client()
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature("test-unrelated-secret", raw))
    assert resp.json()["signature_ok"] is False


def test_empty_previous_secret_verifies_nothing():
    """No rotation in progress is the normal state: the previous secret is empty.

    An HMAC keyed with "" is one anyone can compute, so a receiver that
    accepted it would accept any forged body.
    """
    receiver = Receiver(secret=SECRET, previous_secret="")
    client = TestClient(create_app(receiver))
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature("", raw))
    assert resp.json()["signature_ok"] is False


def test_page_marks_a_delivery_only_the_previous_secret_verifies():
    """You drop the old secret once 15 minutes pass without such a delivery.

    So the page has to show which deliveries they are, and only those.
    """
    _, client = rotating_receiver_and_client()
    signed_with = {"ZZ000000001TEST": SECRET, "ZZ000000002TEST": PREVIOUS_SECRET}
    for tn, secret in signed_with.items():
        raw = json.dumps(wire_body(tn=tn)).encode()
        post(client, raw, signature=compute_signature(secret, raw))
    rows = client.get("/").text.split("<article>")[1:]
    marked = [row for row in rows if "previous secret" in row]
    assert len(rows) == 2
    assert len(marked) == 1
    assert "ZZ000000002TEST" in marked[0], "the mark is on the wrong delivery"


def test_page_shows_when_each_delivery_arrived(client, receiver):
    """Step 4 of a rotation is timed from the last delivery only the old secret
    verifies, so every row says when it arrived, in UTC."""
    before = datetime.now(timezone.utc)
    raw = json.dumps(wire_body()).encode()
    post(client, raw, signature=compute_signature(SECRET, raw))
    after = datetime.now(timezone.utc)
    received_at = receiver.deliveries[0].received_at
    assert before <= received_at <= after
    assert f"{received_at:%Y-%m-%d %H:%M:%S} UTC" in client.get("/").text


def test_receiver_started_from_the_environment_accepts_both_secrets(monkeypatch):
    """The two variables the README tells you to set are the two it reads."""
    monkeypatch.setenv("TRACKCOURIER_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET", PREVIOUS_SECRET)
    client = TestClient(create_app())
    for name, secret in (("current", SECRET), ("previous", PREVIOUS_SECRET)):
        raw = json.dumps(wire_body()).encode()
        resp = post(client, raw, signature=compute_signature(secret, raw))
        assert resp.json()["signature_ok"] is True, f"the {name} secret was not read"


# --- A4: duplicate handling ------------------------------------------------


def test_same_event_delivered_twice_is_flagged_duplicate(client, receiver):
    """The same event arriving twice is a duplicate."""
    raw = json.dumps(wire_body()).encode()
    sig = compute_signature(SECRET, raw)
    assert post(client, raw, signature=sig).json()["duplicate"] is False
    assert post(client, raw, signature=sig).json()["duplicate"] is True
    # Shown, not hidden: delivery is at-least-once and swallowing the row
    # silently is how a receiver hides a real problem.
    assert len(receiver.deliveries) == 2


@pytest.mark.parametrize(
    "changed_part",
    [
        {"event": "tracking.out_for_delivery"},
        {"courier": "blue-dart-courier"},
        {"tn": "ZZ000000002TEST"},
        {"enqueued_at": "2026-08-28T10:05:00Z"},
    ],
    ids=["event", "courier", "tracking_number", "enqueued_at"],
)
def test_changing_any_part_of_the_dedupe_key_makes_a_different_event(client, changed_part):
    """Every part of (event, courier, tracking_number, enqueued_at) counts.

    Change any one part and it is a different event, never a duplicate. The
    realistic cases: two tracking.updated events for one parcel with the same
    status, queued minutes apart (enqueued_at); two parcels whose events were
    queued in the same second (tracking_number); the same docket tracked with
    two couriers (courier). The key is fixed for one event but is not unique
    across events: two different tracking.updated events for one consignment
    queued in the same second share it.
    """
    first = json.dumps(wire_body(event="tracking.updated")).encode()
    second = json.dumps(wire_body(**{"event": "tracking.updated", **changed_part})).encode()
    assert first != second
    r1 = post(client, first, signature=compute_signature(SECRET, first))
    r2 = post(client, second, signature=compute_signature(SECRET, second))
    assert r1.json()["duplicate"] is False
    assert r2.json()["duplicate"] is False, f"{changed_part} is part of the key"


def test_retry_is_a_duplicate_even_when_its_data_has_moved_on(client, receiver):
    """A retry keeps its envelope but carries a rebuilt `data`.

    Each attempt rebuilds `data` from the sender's freshest record, so a retry
    of an in_transit event can arrive with a newer status and more checkpoints,
    and with the next attempt number in X-Webhook-Delivery. It is still the
    same event. A key that includes data.status, the checkpoints or that header
    fails to recognise the retry.
    """
    in_transit = checkpoint("Shipment in transit", "intransit", "28-Aug-2026", "09:41")
    out_for_delivery = checkpoint("Out for delivery", "outfordelivery", "28-Aug-2026", "11:02")
    first_attempt = json.dumps(wire_body(checkpoints=[in_transit])).encode()
    retry = json.dumps(
        wire_body(status="out_for_delivery", checkpoints=[in_transit, out_for_delivery])
    ).encode()
    r1 = post(
        client, first_attempt, signature=compute_signature(SECRET, first_attempt),
        delivery="wh_abc-1",
    )
    r2 = post(client, retry, signature=compute_signature(SECRET, retry), delivery="wh_abc-2")
    assert r1.json()["duplicate"] is False
    assert r2.json()["duplicate"] is True, "a retry is the same event"
    # Marked, never discarded: the retry carries the fresher data.
    assert receiver.deliveries[1].body["data"]["status"] == "out_for_delivery"


def test_forged_delivery_cannot_make_a_real_one_look_duplicate(client):
    """Only a delivery whose signature verifies takes part in de-duplication.

    Otherwise a forged body carrying a real event's key, arriving first, makes
    the real delivery look like a repeat, and a handler that skips repeat work
    skips the real event.
    """
    raw = json.dumps(wire_body()).encode()
    forged = post(client, raw, signature="sha256=" + "0" * 64)
    real = post(client, raw, signature=compute_signature(SECRET, raw))
    assert forged.json()["signature_ok"] is False
    assert real.json()["signature_ok"] is True
    assert real.json()["duplicate"] is False, "an unverified delivery set the key"


def test_same_delivery_header_on_two_different_events_is_not_a_duplicate(client):
    """We are NOT keyed on X-Webhook-Delivery.

    That header is webhook_id + attempt, so two genuinely DIFFERENT events both
    carry '<webhook_id>-1'. A receiver keyed on it would drop the second.
    """
    first = json.dumps(wire_body(status="in_transit")).encode()
    second = json.dumps(wire_body(event="tracking.delivered", status="delivered")).encode()
    same_header = "wh_abc-1"
    r1 = post(client, first, signature=compute_signature(SECRET, first), delivery=same_header)
    r2 = post(client, second, signature=compute_signature(SECRET, second), delivery=same_header)
    assert r1.json()["duplicate"] is False
    assert r2.json()["duplicate"] is False, "keyed on the header, not on the event"


# --- A5: escaping ----------------------------------------------------------


def test_html_payload_renders_escaped(client):
    """A courier free-text field carrying markup must not become live HTML."""
    raw = json.dumps(
        wire_body(tn="<script>alert('xss')</script>")
    ).encode()
    post(client, raw, signature=compute_signature(SECRET, raw))
    page = client.get("/").text
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert" in page
