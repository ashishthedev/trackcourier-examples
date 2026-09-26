"""Tests for the trackcourier.io webhook receiver.

Eight tests, each one guarding a mistake that is easy to make in the other
direction. All eight are mutation-checked (see MUTATION.md).
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import Receiver, create_app
from signature import compute_signature

SECRET = "test-secret-do-not-use"


def wire_body(event="tracking.in_transit", tn="ZZ000000001TEST", status="in_transit"):
    """A payload shaped exactly like a live webhook delivery."""
    return {
        "event": event,
        "enqueued_at": "2026-08-28T10:00:00Z",
        "data": {
            "tracking_number": tn,
            "courier": "dtdc",
            "status": status,
            "most_recent_status": None,
            "origin_city": None,
            "destination_city": None,
            "delivered_date": None,
            "checkpoints": [],
        },
    }


@pytest.fixture
def receiver():
    return Receiver(secret=SECRET)


@pytest.fixture
def client(receiver):
    return TestClient(create_app(receiver))


def post(client, raw: bytes, signature=None, delivery="wh_abc-1", event="tracking.in_transit"):
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Event": event,
        "X-Webhook-Delivery": delivery,
    }
    if signature is not None:
        headers["X-Trackcourier-Signature"] = signature
    return client.post("/webhook", content=raw, headers=headers)


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


# --- A4: duplicate handling ------------------------------------------------


def test_repeated_body_tuple_is_suppressed(client, receiver):
    """The same (event, tracking_number, status) twice is a duplicate."""
    raw = json.dumps(wire_body()).encode()
    sig = compute_signature(SECRET, raw)
    assert post(client, raw, signature=sig).json()["duplicate"] is False
    assert post(client, raw, signature=sig).json()["duplicate"] is True
    # Shown, not hidden: delivery is at-least-once and swallowing the row
    # silently is how a receiver hides a real problem.
    assert len(receiver.deliveries) == 2


def test_same_delivery_header_with_a_different_tuple_is_not_suppressed(client):
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
    assert r2.json()["duplicate"] is False, "keyed on the header, not the body tuple"


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
