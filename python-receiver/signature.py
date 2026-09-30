"""Signature verification for trackcourier.io webhooks.

The contract, exactly:

    X-Trackcourier-Signature: sha256=<hex hmac_sha256(secret, RAW_REQUEST_BODY)>

One secret signs every webhook on an account, test and live.

Rotating it is NOT atomic. The rotation returns the new secret at once and
deliveries start being signed with it straight away, but signing servers pick
it up independently, so for a while afterwards some deliveries still carry the
OLD secret's signature. Across the changeover, accept a body that matches
either secret (app.py checks both), keep both for at least 15 minutes, and drop
the old one only once 15 minutes have passed without a delivery that only it
verifies. Fifteen minutes is a floor, not a guaranteed bound.
"""

import hashlib
import hmac

SIGNATURE_PREFIX = "sha256="


def compute_signature(secret: str, raw_body: bytes) -> str:
    """Return the expected header value for these exact bytes."""
    digest = hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return SIGNATURE_PREFIX + digest


def verify_signature(secret: str, raw_body: bytes, header_value: str) -> bool:
    """Constant-time compare of the received header against the expected one.

    THE TRAP, and it is the top support question: `raw_body` must be the bytes
    exactly as they arrived. If you parse the JSON and re-serialize it to get
    them back, verification fails -- your serializer will differ from ours in
    key order, separator whitespace, or unicode escaping, and any one of those
    changes the digest. Capture the body before anything touches it.

    An empty secret never verifies: a receiver started without one must not
    silently accept everything. Nor does a header that is not ASCII: a digest
    is hex, and hmac.compare_digest raises on non-ASCII text rather than
    returning False, which would turn a stranger's header into a 500.
    """
    if not secret or not header_value or not header_value.isascii():
        return False
    return hmac.compare_digest(compute_signature(secret, raw_body), header_value)
