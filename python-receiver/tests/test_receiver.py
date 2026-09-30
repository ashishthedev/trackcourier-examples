"""Tests for the trackcourier.io webhook receiver.

Each test guards a mistake that is easy to make in the other direction, and
each has been watched to fail: break the code it guards and it goes red.
"""

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import app as receiver_module
from app import (
    MAX_BODY_BYTES,
    MAX_BODY_BYTES_SHOWN_ON_PAGE,
    MAX_DELIVERIES_KEPT,
    VIEWER_PORT,
    WEBHOOK_PORT,
    Receiver,
    create_viewer_app,
    create_webhook_app,
    serve,
    webhook_and_viewer_servers,
)
from signature import compute_signature

SECRET = "test-secret-do-not-use"
PREVIOUS_SECRET = "test-previous-secret-do-not-use"
README = Path(__file__).resolve().parents[2] / "README.md"


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
    return TestClient(create_webhook_app(receiver))


@pytest.fixture
def client_that_sees_500s(receiver):
    """Sees a crash the way a sender does: as a 500 response.

    The default client re-raises the exception instead, which makes "this input
    causes a 500" look like a broken test rather than a failing one.
    """
    return TestClient(create_webhook_app(receiver), raise_server_exceptions=False)


def viewer_for(receiver):
    """A browser on this machine, looking at the page."""
    return TestClient(create_viewer_app(receiver), base_url=f"http://localhost:{VIEWER_PORT}")


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


def post_as_asgi(app, messages):
    """Drive the app directly with a scripted run of ASGI receive() messages.

    Once the script runs out, receive() waits for ever, like a client that has
    stopped sending without closing the connection. Returns what the app sent.
    """
    script = list(messages)
    sent = []

    async def receive():
        if script:
            return script.pop(0)
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/webhook",
        "raw_path": b"/webhook",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", WEBHOOK_PORT),
    }
    # The outer limit turns "the app never answers" into a failure, not a hang.
    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=2))
    return sent


def response_start(sent):
    return next(m for m in sent if m["type"] == "http.response.start")


# --- A2: raw body handling -------------------------------------------------


def test_raw_body_captured_byte_identical(client, receiver):
    """The stored bytes are the bytes that arrived.

    Uses whitespace and key order NO serializer would reproduce, so a receiver
    that parsed and re-serialized would fail this.
    """
    raw = b'{"event":"tracking.in_transit",   "z":1,\n  "data":{"tracking_number":"A1","status":"in_transit"}}'
    assert post(client, raw, signature=compute_signature(SECRET, raw)).status_code == 200
    assert receiver.deliveries[0].raw_body == raw


def test_malformed_json_does_not_crash_the_endpoint(client, receiver):
    """A bad body is recorded with a parse error, never a 5xx.

    A crash on a malformed payload turns one bad delivery into a six-attempt
    retry chain against a dead endpoint. Signed, so that what is tested is the
    parse: a body that does not verify is answered 401 whatever it holds.
    """
    raw = b'{"event": broken,,,'
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
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


def readme_python_block_under(heading):
    """The first python code block after a README heading, as source."""
    after_heading = README.read_text(encoding="utf-8").split(heading + "\n", 1)[1]
    return after_heading.split("```python\n", 1)[1].split("```", 1)[0]


def test_readme_verify_snippet_fails_a_missing_or_non_ascii_header_without_raising():
    """The README's verify() is code people paste into their own receiver.

    So it needs the guards signature.py has: hmac.compare_digest raises on None
    and on non-ASCII text rather than returning False, and a raise there is a
    500 in someone else's receiver.
    """
    namespace = {}
    exec(readme_python_block_under("## Verifying the signature"), namespace)
    verify = namespace["verify"]
    raw = json.dumps(wire_body()).encode()
    assert verify(SECRET, raw, compute_signature(SECRET, raw)) is True
    for header in (None, "", "sha256=" + "\u00e9" * 64):
        assert verify(SECRET, raw, header) is False, f"verify() passed {header!r}"


def rotating_receiver_and_client():
    """A receiver mid-rotation: SECRET is the new secret, PREVIOUS_SECRET the old."""
    receiver = Receiver(secret=SECRET, previous_secret=PREVIOUS_SECRET)
    return receiver, TestClient(create_webhook_app(receiver))


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


@pytest.mark.parametrize(
    "signed_with, expected_status",
    [
        (SECRET, 200),
        (PREVIOUS_SECRET, 200),
        ("test-unrelated-secret", 401),
        (None, 401),
    ],
    ids=["current-secret", "previous-secret", "neither-secret", "no-signature"],
)
def test_a_delivery_neither_secret_verifies_is_answered_401(signed_with, expected_status):
    """Answer 2xx only to what verifies, so the sender retries the rest.

    A 2xx ends a delivery. One signed with a new secret you have not stored yet
    (step 1 of a rotation) has to be retried, not ended, and a wrong secret has
    to fail loudly rather than be acknowledged and dropped.
    """
    _, client = rotating_receiver_and_client()
    raw = json.dumps(wire_body()).encode()
    signature = None if signed_with is None else compute_signature(signed_with, raw)
    assert post(client, raw, signature=signature).status_code == expected_status


def test_non_ascii_signature_header_is_a_401_not_a_500(client_that_sees_500s, receiver):
    """A signature header that is not ASCII is a signature that fails, nothing worse.

    hmac.compare_digest raises on non-ASCII text rather than returning False,
    so an unguarded compare turns a stranger's header into a 500.
    """
    raw = json.dumps(wire_body()).encode()
    resp = post(client_that_sees_500s, raw, signature=b"sha256=" + b"\xe9" * 64)
    assert resp.status_code == 401
    assert receiver.deliveries[0].signature_ok is False


def test_empty_previous_secret_verifies_nothing():
    """No rotation in progress is the normal state: the previous secret is empty.

    An HMAC keyed with "" is one anyone can compute, so a receiver that
    accepted it would accept any forged body.
    """
    receiver = Receiver(secret=SECRET, previous_secret="")
    client = TestClient(create_webhook_app(receiver))
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature=compute_signature("", raw))
    assert resp.json()["signature_ok"] is False


def test_page_marks_a_delivery_only_the_previous_secret_verifies():
    """You drop the old secret once 15 minutes pass without such a delivery.

    So the page has to show which deliveries they are, and only those.
    """
    receiver, client = rotating_receiver_and_client()
    signed_with = {"ZZ000000001TEST": SECRET, "ZZ000000002TEST": PREVIOUS_SECRET}
    for tn, secret in signed_with.items():
        raw = json.dumps(wire_body(tn=tn)).encode()
        post(client, raw, signature=compute_signature(secret, raw))
    rows = viewer_for(receiver).get("/").text.split("<article>")[1:]
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
    assert f"{received_at:%Y-%m-%d %H:%M:%S} UTC" in viewer_for(receiver).get("/").text


def test_receiver_started_from_the_environment_accepts_both_secrets(monkeypatch):
    """The two variables the README tells you to set are the two it reads."""
    monkeypatch.setenv("TRACKCOURIER_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET", PREVIOUS_SECRET)
    client = TestClient(create_webhook_app())
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


# --- A5: what a stranger can cost the receiver -----------------------------


def test_body_over_the_size_limit_is_refused_and_not_kept(client, receiver):
    """A body over MAX_BODY_BYTES gets a 413 and is not kept.

    Anyone who finds the tunnel's URL can POST to it, and without a limit one
    request makes the receiver hold as much as the sender cares to send. A
    valid signature does not change that: checking one means reading it all.
    The 413 closes the connection: left open, the server keeps reading the rest
    of the body for as long as the client keeps sending it.
    """
    raw = b"x" * (MAX_BODY_BYTES + 1)
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
    assert resp.status_code == 413
    assert resp.headers.get("connection") == "close"
    assert len(receiver.deliveries) == 0


def test_body_at_the_size_limit_is_accepted(client, receiver):
    """The limit refuses what is over it, and nothing at it."""
    prefix, suffix = b'{"event":"tracking.in_transit","pad":"', b'"}'
    raw = prefix + b"a" * (MAX_BODY_BYTES - len(prefix) - len(suffix)) + suffix
    assert len(raw) == MAX_BODY_BYTES
    resp = post(client, raw, signature=compute_signature(SECRET, raw))
    assert resp.status_code == 200
    assert receiver.deliveries[0].raw_body == raw


def test_only_the_most_recent_deliveries_are_kept(receiver):
    """Past MAX_DELIVERIES_KEPT, the oldest delivery drops off.

    Every POST adds one, verified or not, and anyone who finds the URL can
    POST, so an unbounded list is memory a stranger can fill.
    """
    for n in range(MAX_DELIVERIES_KEPT + 1):
        receiver.record(f'{{"n":{n}}}'.encode(), {})
    assert len(receiver.deliveries) == MAX_DELIVERIES_KEPT
    assert receiver.deliveries[0].raw_body == b'{"n":1}', "the oldest was not the one dropped"
    assert receiver.deliveries[-1].raw_body == f'{{"n":{MAX_DELIVERIES_KEPT}}}'.encode()


def test_repeat_detection_forgets_the_oldest_events_first(monkeypatch):
    """Repeat detection remembers the last MAX_EVENTS_REMEMBERED events, not all.

    Only a verified delivery adds a key, so a stranger cannot grow it, but a
    receiver left running would otherwise grow it for ever.
    """
    monkeypatch.setattr(receiver_module, "MAX_EVENTS_REMEMBERED", 3)
    receiver = Receiver(secret=SECRET)

    def deliver(tn):
        raw = json.dumps(wire_body(tn=tn)).encode()
        signature = compute_signature(SECRET, raw)
        return receiver.record(raw, {"x-trackcourier-signature": signature})

    for tn in ("ZZ000000001TEST", "ZZ000000002TEST", "ZZ000000003TEST", "ZZ000000004TEST"):
        assert deliver(tn).duplicate is False
    assert deliver("ZZ000000004TEST").duplicate is True, "a recent event was forgotten"
    assert deliver("ZZ000000001TEST").duplicate is False, "the oldest event was not forgotten"


def test_a_body_that_stops_arriving_is_cut_off_with_408(monkeypatch, receiver):
    """A body gets BODY_READ_TIMEOUT_SECONDS to arrive in full.

    Otherwise a client that sends part of a body and then nothing holds a
    connection, and everything received so far, for as long as it likes.
    """
    monkeypatch.setattr(receiver_module, "BODY_READ_TIMEOUT_SECONDS", 0.05)
    sent = post_as_asgi(
        create_webhook_app(receiver),
        [{"type": "http.request", "body": b'{"event":', "more_body": True}],
    )
    start = response_start(sent)
    assert start["status"] == 408
    assert (b"connection", b"close") in start["headers"]
    assert len(receiver.deliveries) == 0


def test_a_client_that_hangs_up_mid_body_is_not_an_error(receiver):
    """A client that disconnects halfway through a body is not an exception.

    Unhandled, the disconnect is logged as an application error with a full
    traceback, so anyone could fill your log by starting requests and hanging
    up.
    """
    post_as_asgi(
        create_webhook_app(receiver),
        [
            {"type": "http.request", "body": b'{"event":', "more_body": True},
            {"type": "http.disconnect"},
        ],
    )
    assert len(receiver.deliveries) == 0


# Deeper than json.loads can recurse, and still under 1 MiB.
DEEPLY_NESTED_JSON = b"[" * 500_000 + b"]" * 500_000


def test_deeply_nested_json_from_a_stranger_is_a_401_not_a_500(client_that_sees_500s):
    """A body that does not verify is answered 401 whatever it holds.

    json.loads raises RecursionError on JSON nested this deep, which is not a
    ValueError, so a receiver that parsed a stranger's body and caught only
    ValueError would answer this with a 500.
    """
    resp = post(client_that_sees_500s, DEEPLY_NESTED_JSON, event="tracking.in_transit")
    assert resp.status_code == 401


def test_deeply_nested_json_that_verifies_is_a_parse_error_not_a_500(
    client_that_sees_500s, receiver
):
    """Too deep to parse is a failed parse, like any other malformed body."""
    raw = DEEPLY_NESTED_JSON
    resp = post(
        client_that_sees_500s, raw, signature=compute_signature(SECRET, raw),
        event="tracking.in_transit",
    )
    assert resp.status_code == 200
    assert receiver.deliveries[0].parse_error is not None
    assert receiver.deliveries[0].body is None


def test_a_verified_body_with_a_deeply_nested_key_field_is_not_a_500(
    client_that_sees_500s, receiver
):
    """A verified body nesting a key field 100,000 deep is not a 500.

    Where json.loads can parse this depth (it can on 3.14), str() of it runs
    out of stack; elsewhere the parse fails first and is recorded as a parse
    error. The test below proves the rule that keeps str() out of it, on every
    supported Python.
    """
    nested = b"[" * 100_000 + b"]" * 100_000
    raw = (
        b'{"event":' + nested + b',"enqueued_at":"2026-08-28T10:00:00Z",'
        b'"data":{"courier":"dtdc","tracking_number":"ZZ000000001TEST"}}'
    )
    resp = post(
        client_that_sees_500s, raw, signature=compute_signature(SECRET, raw),
        event="tracking.in_transit",
    )
    assert resp.status_code == 200
    assert receiver.deliveries[0].duplicate is False


def test_a_key_field_that_is_not_a_string_makes_no_dedupe_key(client):
    """The dedupe key takes its fields only when they are strings.

    Never str() of whatever arrived: that is how a nested value becomes a 500,
    and how ["ZZ1"] and "['ZZ1']" would count as the same parcel.
    """
    body = wire_body()
    body["data"]["tracking_number"] = ["ZZ000000001TEST"]
    raw = json.dumps(body).encode()
    sig = compute_signature(SECRET, raw)
    assert post(client, raw, signature=sig).json()["duplicate"] is False
    assert post(client, raw, signature=sig).json()["duplicate"] is False, (
        "a key was built from a field that is not a string"
    )


def test_a_body_that_does_not_verify_is_kept_as_bytes_and_never_parsed(client, receiver):
    """Only a verified body is parsed; a stranger's stays bytes.

    Parsed, 1 MiB of '{"a":[{},{},...]}' is over 20 MiB of Python objects, so a
    receiver that parsed every body could not bound its memory by bounding
    body size. The page shows raw bytes either way.
    """
    raw = json.dumps(wire_body()).encode()
    resp = post(client, raw, signature="sha256=" + "0" * 64)
    assert resp.status_code == 401
    assert receiver.deliveries[0].raw_body == raw
    assert receiver.deliveries[0].body is None


# --- A6: what the tunnel exposes -------------------------------------------


@pytest.mark.parametrize("path", ["/", "/docs", "/redoc", "/openapi.json"])
def test_webhook_app_serves_nothing_but_the_webhook(client, path):
    """The tunnel forwards every path on the webhook's port to anyone.

    So nothing but the webhook may be served there: not the page that shows
    every delivery, and not the framework's generated API pages.
    """
    assert client.get(path).status_code == 404


def test_running_the_receiver_serves_the_page_on_its_own_port_on_this_machine_only(receiver):
    """What running app.py starts: the webhook on WEBHOOK_PORT, the page on VIEWER_PORT.

    Listening on 127.0.0.1 cannot keep a page private on a port a tunnel
    forwards: the tunnel runs on this machine, so it connects from 127.0.0.1
    too. So the page gets a port of its own, and both listen on 127.0.0.1 only.
    """
    webhook_server, viewer_server = webhook_and_viewer_servers(create_webhook_app(receiver))
    assert (webhook_server.config.host, webhook_server.config.port) == ("127.0.0.1", WEBHOOK_PORT)
    assert (viewer_server.config.host, viewer_server.config.port) == ("127.0.0.1", VIEWER_PORT)
    webhook = TestClient(webhook_server.config.app)
    viewer = TestClient(viewer_server.config.app, base_url=f"http://localhost:{VIEWER_PORT}")
    raw = json.dumps(wire_body()).encode()
    assert post(webhook, raw, signature=compute_signature(SECRET, raw)).status_code == 200
    assert webhook.get("/").status_code == 404
    assert "ZZ000000001TEST" in viewer.get("/").text, (
        "the page does not show the webhook's deliveries"
    )


@contextlib.contextmanager
def running_receiver(monkeypatch, receiver):
    """Run what app.py runs, on ports the OS picks; yield (webhook, page) servers."""
    monkeypatch.setattr(receiver_module, "WEBHOOK_PORT", 0)
    monkeypatch.setattr(receiver_module, "VIEWER_PORT", 0)
    servers = webhook_and_viewer_servers(create_webhook_app(receiver))
    thread = threading.Thread(target=asyncio.run, args=(serve(servers),), daemon=True)
    thread.start()
    try:
        wait_until(lambda: all(server.started for server in servers), "the servers did not start")
        yield servers
    finally:
        for server in servers:
            server.should_exit = True
        thread.join(timeout=5)
        assert not thread.is_alive(), "the servers did not stop"


def wait_until(condition, failure, seconds=5):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, failure
        time.sleep(0.01)


def port_of(server):
    return server.servers[0].sockets[0].getsockname()[1]


def test_running_the_receiver_serves_both_ports_over_real_sockets(monkeypatch, receiver):
    """serve() really starts both listeners, and they share one Receiver.

    The other launcher tests read the servers' settings. This one binds them,
    as running app.py does, and talks to them over TCP.
    """
    with running_receiver(monkeypatch, receiver) as (webhook_server, viewer_server):
        webhook = f"http://127.0.0.1:{port_of(webhook_server)}"
        raw = json.dumps(wire_body()).encode()
        with httpx.Client(trust_env=False) as http:
            delivered = http.post(
                f"{webhook}/webhook",
                content=raw,
                headers={"X-Trackcourier-Signature": compute_signature(SECRET, raw)},
            )
            assert delivered.status_code == 200
            assert http.get(f"{webhook}/").status_code == 404
            page = http.get(
                f"http://127.0.0.1:{port_of(viewer_server)}/",
                headers={"Host": f"localhost:{port_of(viewer_server)}"},
            )
            assert page.status_code == 200
            assert "ZZ000000001TEST" in page.text, "the page does not show the webhook's delivery"


def test_a_request_while_the_webhook_has_its_connections_full_gets_503(monkeypatch, receiver):
    """While MAX_WEBHOOK_CONNECTIONS connections are open, a request gets 503.

    Each request may hold up to MAX_BODY_BYTES while its body arrives, so the
    connections are capped too; the sender retries a 503 later. uvicorn counts
    the connection a request arrives on, so with a cap of 2, one connection
    held open mid-body leaves no room for another request.
    """
    monkeypatch.setattr(receiver_module, "MAX_WEBHOOK_CONNECTIONS", 2)
    with running_receiver(monkeypatch, receiver) as (webhook_server, _):
        port = port_of(webhook_server)
        held = socket.create_connection(("127.0.0.1", port))
        try:
            held.sendall(b"POST /webhook HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
            wait_until(
                lambda: len(webhook_server.server_state.tasks) == 1,
                "the held request never started",
            )
            with httpx.Client(trust_env=False) as http:
                assert http.get(f"http://127.0.0.1:{port}/healthz").status_code == 503
        finally:
            held.close()


def test_running_the_receiver_keeps_the_access_log_that_shows_each_delivery(receiver):
    """The terminal shows each delivery's status as it arrives: 200, 401, 413.

    uvicorn's access log is one logger shared by every server in the process,
    so switching it off to quieten the page would switch it off for the
    webhook too.
    """
    webhook_and_viewer_servers(create_webhook_app(receiver))
    assert logging.getLogger("uvicorn.access").hasHandlers()


@pytest.mark.parametrize(
    "host, expected_status",
    [
        (f"localhost:{VIEWER_PORT}", 200),
        (f"127.0.0.1:{VIEWER_PORT}", 200),
        ("abc.trycloudflare.com", 400),
        (f"attacker.example:{VIEWER_PORT}", 400),
    ],
    ids=["localhost", "127.0.0.1", "tunnel-hostname", "dns-rebinding"],
)
def test_page_answers_only_a_request_that_names_this_machine(receiver, host, expected_status):
    """The page refuses a request addressed to any other host.

    That covers a tunnel pointed at the page's port anyway, if it passes on
    its public hostname, and a web page you visit that re-points its own
    domain at 127.0.0.1 to read this page through your browser (DNS rebinding).
    """
    viewer = TestClient(create_viewer_app(receiver), base_url=f"http://{host}")
    assert viewer.get("/").status_code == expected_status


# --- A7: what the page renders ---------------------------------------------


def test_html_payload_renders_escaped(client, receiver):
    """A courier free-text field carrying markup must not become live HTML."""
    raw = json.dumps(
        wire_body(tn="<script>alert('xss')</script>")
    ).encode()
    post(client, raw, signature=compute_signature(SECRET, raw))
    page = viewer_for(receiver).get("/").text
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert" in page


def test_page_shows_only_the_start_of_a_long_body(receiver):
    """The page shows each body up to MAX_BODY_BYTES_SHOWN_ON_PAGE, and says what it left out.

    Shown whole, 100 kept bodies of 1 MiB make a page of hundreds of MiB:
    html.escape can make text six times longer, and the page reloads every 3
    seconds.
    """
    raw = b"a" * MAX_BODY_BYTES_SHOWN_ON_PAGE + b"TAIL-NOT-SHOWN"
    receiver.record(raw, {})
    page = viewer_for(receiver).get("/").text
    assert "TAIL-NOT-SHOWN" not in page
    assert "14 more bytes not shown" in page


def test_page_shows_bytes_that_are_not_utf8_as_escapes(receiver):
    """A body that is not valid UTF-8 still renders, its bad bytes as \\xNN."""
    receiver.record(b"caf\xe9 \xff", {})
    page = viewer_for(receiver).get("/").text
    assert "caf\\xe9 \\xff" in page
