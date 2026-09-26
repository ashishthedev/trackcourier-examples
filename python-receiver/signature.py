"""Signature verification for trackcourier.io webhooks.

The contract, exactly:

    X-Trackcourier-Signature: sha256=<hex hmac_sha256(secret, RAW_REQUEST_BODY)>

The secret is per CUSTOMER, not per webhook. Rotating it switches every webhook
that customer owns, immediately.
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
    silently accept everything.
    """
    if not secret or not header_value:
        return False
    return hmac.compare_digest(compute_signature(secret, raw_body), header_value)
