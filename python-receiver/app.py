"""A minimal trackcourier.io webhook receiver.

Reference code, not a supported product. It does four things, and each one is a
mistake that is easy to make in the other direction:

1. Captures the RAW request body before parsing anything (signature.py explains
   why re-serializing breaks verification).
2. Verifies the HMAC signature with a constant-time compare.
3. Deduplicates on the BODY tuple, never on the X-Webhook-Delivery header.
4. Renders every received value as escaped text, never as HTML.
"""

import html
import json
import os
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from signature import verify_signature

SIGNATURE_HEADER = "X-Trackcourier-Signature"
EVENT_HEADER = "X-Webhook-Event"
DELIVERY_HEADER = "X-Webhook-Delivery"


@dataclass
class Delivery:
    """One received POST, kept exactly as it arrived."""

    raw_body: bytes
    headers: dict[str, str]
    signature_ok: bool
    duplicate: bool
    parse_error: str | None = None
    body: dict[str, Any] | None = field(default=None)


def dedupe_key_for(body: Any) -> tuple[str, str, str] | None:
    """The at-least-once dedupe key: (event, tracking_number, status).

    Deliberately NOT X-Webhook-Delivery. That header is webhook_id + attempt
    number, so every FIRST attempt of every event on every parcel for one
    webhook carries the identical value, while the retries it should collapse
    each carry a different one. Keying on it suppresses distinct events and
    fails to suppress retries -- exactly backwards.
    """
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    event = body.get("event")
    tracking_number = data.get("tracking_number")
    status = data.get("status")
    if event is None or tracking_number is None or status is None:
        return None
    return (str(event), str(tracking_number), str(status))


class Receiver:
    """Holds received deliveries. A class, so tests get a clean instance."""

    def __init__(self, secret: str = "") -> None:
        self.secret = secret
        self.deliveries: list[Delivery] = []
        self._seen: set[tuple[str, str, str]] = set()

    def record(self, raw_body: bytes, headers: dict[str, str]) -> Delivery:
        signature_ok = verify_signature(
            self.secret, raw_body, headers.get(SIGNATURE_HEADER.lower(), "")
        )

        body: dict[str, Any] | None = None
        parse_error: str | None = None
        try:
            parsed = json.loads(raw_body)
            body = parsed if isinstance(parsed, dict) else None
            if body is None:
                parse_error = "body is not a JSON object"
        except (ValueError, UnicodeDecodeError) as exc:
            # A malformed body must never take the endpoint down: the sender
            # retries on a non-2xx, and a crash loop turns one bad payload into
            # six.
            parse_error = f"{type(exc).__name__}: {exc}"

        key = dedupe_key_for(body)
        duplicate = key is not None and key in self._seen
        if key is not None:
            self._seen.add(key)

        delivery = Delivery(
            raw_body=raw_body,
            headers=headers,
            signature_ok=signature_ok,
            duplicate=duplicate,
            parse_error=parse_error,
            body=body,
        )
        self.deliveries.append(delivery)
        return delivery


def create_app(receiver: Receiver | None = None) -> FastAPI:
    app = FastAPI(title="trackcourier.io webhook receiver")
    app.state.receiver = receiver or Receiver(
        secret=os.getenv("TRACKCOURIER_WEBHOOK_SECRET", "")
    )

    @app.post("/webhook")
    async def receive(request: Request) -> JSONResponse:
        # The raw bytes, before anything parses them. Everything downstream
        # works from this; nothing re-serializes.
        raw_body = await request.body()
        headers = {k.lower(): v for k, v in request.headers.items()}
        delivery = request.app.state.receiver.record(raw_body, headers)
        # Always 2xx once the bytes are in hand. A parse failure is ours to
        # look at, not a reason to make the sender retry.
        return JSONResponse(
            {
                "received": True,
                "signature_ok": delivery.signature_ok,
                "duplicate": delivery.duplicate,
            },
            status_code=200,
        )

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return HTMLResponse(render_page(request.app.state.receiver))

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app


def render_page(receiver: Receiver) -> str:
    """Render deliveries. Every received value goes through html.escape.

    This receiver is not publicly hosted, but it ships as reference code that
    someone else will host, and the payload is attacker-influenced the moment a
    courier's free-text field reaches it.
    """
    rows = []
    for i, d in enumerate(reversed(receiver.deliveries), start=1):
        sig = "PASS" if d.signature_ok else "FAIL"
        sig_class = "ok" if d.signature_ok else "bad"
        flags = []
        if d.duplicate:
            flags.append('<span class="dup">duplicate suppressed</span>')
        if d.parse_error:
            flags.append(f'<span class="bad">{html.escape(d.parse_error)}</span>')
        try:
            shown = d.raw_body.decode("utf-8")
        except UnicodeDecodeError:
            shown = repr(d.raw_body)
        rows.append(
            f'<article><h2>#{i} '
            f'<span class="{sig_class}">signature {sig}</span> '
            + " ".join(flags)
            + "</h2><dl>"
            + f"<dt>{html.escape(EVENT_HEADER)}</dt>"
            f"<dd>{html.escape(d.headers.get(EVENT_HEADER.lower(), ''))}</dd>"
            + f"<dt>{html.escape(DELIVERY_HEADER)}</dt>"
            f"<dd>{html.escape(d.headers.get(DELIVERY_HEADER.lower(), ''))}</dd>"
            + "</dl><pre>"
            + html.escape(shown)
            + "</pre></article>"
        )

    body = "".join(rows) or "<p>Waiting for a delivery.</p>"
    return (
        "<title>trackcourier.io webhook receiver</title>"
        '<meta http-equiv="refresh" content="3">'
        "<style>body{font:14px/1.5 ui-monospace,monospace;max-width:60rem;"
        "margin:2rem auto;padding:0 1rem}article{border:1px solid #ccc;"
        "padding:.75rem 1rem;margin:1rem 0}.ok{color:#0a7d28}.bad{color:#b00020}"
        ".dup{color:#8a6d00}pre{white-space:pre-wrap;word-break:break-all;"
        "background:#f6f6f6;padding:.5rem}dt{font-weight:700}"
        "dd{margin:0 0 .25rem}</style>"
        f"<h1>Received deliveries ({len(receiver.deliveries)})</h1>{body}"
    )


app = create_app()
