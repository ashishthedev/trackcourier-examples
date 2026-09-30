"""A minimal trackcourier.io webhook receiver.

Reference code, not a supported product. It does five things, and each one is a
mistake that is easy to make in the other direction:

1. Captures the RAW request body before parsing anything (signature.py explains
   why re-serializing breaks verification).
2. Verifies the HMAC signature with a constant-time compare, against the
   current secret and, while a rotation is in progress, the previous one. It
   answers 401 when neither verifies, so the sender retries, and parses only a
   body that verifies.
3. Flags a repeat of an event it has already verified, keyed on
   (event, courier, tracking_number, enqueued_at), never on the
   X-Webhook-Delivery header.
4. Bounds what a stranger can make it hold, since anyone who finds the URL can
   POST to it: the size of a body, how long it may take to arrive, how many
   connections are open at once, and how many deliveries are kept.
5. Shows the deliveries it keeps on a page served on 127.0.0.1, on a port of
   its own, never on the port your tunnel exposes. The page renders every
   received value as escaped text, never as HTML, and only the start of a long
   body.

Run it with `python python-receiver/app.py`: deliveries on WEBHOOK_PORT, the
page on VIEWER_PORT.
"""

import asyncio
import contextlib
import html
import json
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import ClientDisconnect

from signature import verify_signature

SIGNATURE_HEADER = "X-Trackcourier-Signature"
EVENT_HEADER = "X-Webhook-Event"
DELIVERY_HEADER = "X-Webhook-Delivery"

# Point your tunnel at WEBHOOK_PORT and nothing else. VIEWER_PORT serves the
# page showing every delivery you have received; it must never be tunnelled.
WEBHOOK_PORT = 8080
VIEWER_PORT = 8081

# Anyone who finds your webhook's URL can POST to it, so a body over this is
# refused with a 413 before it is read in full. A checkpoint is about 150
# bytes, so 1 MiB holds thousands of them: no real delivery comes close.
MAX_BODY_BYTES = 1024 * 1024
# A body has this long to arrive in full, so a client that sends part of one
# and then nothing cannot hold a connection open for ever. Ample for 1 MiB.
BODY_READ_TIMEOUT_SECONDS = 10
# Each request may hold up to MAX_BODY_BYTES while its body arrives, so while
# this many connections are open to the webhook's port, uvicorn answers a new
# request 503 rather than take it, and the sender retries later. An idle
# keep-alive connection counts; uvicorn closes one after 5 seconds.
MAX_WEBHOOK_CONNECTIONS = 32
# Every POST adds a delivery, verified or not, so only the most recent are
# kept: with MAX_BODY_BYTES, about 100 MiB of bodies at most, however many
# arrive.
MAX_DELIVERIES_KEPT = 100
# Repeat detection remembers the keys of this many verified events. Only a
# verified delivery adds one, so a stranger cannot push them out.
MAX_EVENTS_REMEMBERED = 10_000
# The page shows each body up to this: about a hundred checkpoints. Escaping
# can make text six times longer, so whole bodies would make a page of
# hundreds of MiB, reloaded every 3 seconds.
MAX_BODY_BYTES_SHOWN_ON_PAGE = 16 * 1024


@dataclass
class Delivery:
    """One received POST, kept exactly as it arrived."""

    raw_body: bytes
    headers: dict[str, str]
    received_at: datetime  # UTC
    signature_ok: bool
    # True while a rotation is in progress and ONLY the old secret verified
    # this delivery. Drop the old secret once 15 minutes pass without one.
    verified_only_by_previous_secret: bool
    duplicate: bool
    parse_error: str | None = None
    body: dict[str, Any] | None = field(default=None)


def dedupe_key_for(body: Any) -> tuple[str, str, str, str] | None:
    """The at-least-once dedupe key: (event, courier, tracking_number, enqueued_at).

    Every part is fixed for the life of an event, across all its delivery
    attempts. enqueued_at is read from the envelope, which is stable; `data` is
    not, because each attempt rebuilds it from the sender's freshest record of
    the shipment. That is why data.status and the checkpoints are left out: a
    retry can carry a newer status and more checkpoints than the first attempt,
    and a key containing them would not recognise it.

    Stable, but not guaranteed unique: enqueued_at has one-second resolution,
    so two different tracking.updated events for one consignment queued in the
    same second share a key. Use it to skip duplicate work, never to discard an
    event you would otherwise act on.

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
    key = (
        body.get("event"),
        data.get("courier"),
        data.get("tracking_number"),
        body.get("enqueued_at"),
    )
    # Strings only, never str() of whatever arrived: str() of a list nested
    # deeply enough runs out of stack even where json.loads parsed it.
    if not all(isinstance(part, str) for part in key):
        return None
    return key


class Receiver:
    """Holds received deliveries. A class, so tests get a clean instance."""

    def __init__(self, secret: str = "", previous_secret: str = "") -> None:
        self.secret = secret
        # Set only while a rotation is in progress; empty verifies nothing.
        self.previous_secret = previous_secret
        # Both bounded: once full, adding one drops the oldest.
        self.deliveries: deque[Delivery] = deque(maxlen=MAX_DELIVERIES_KEPT)
        self._seen: deque[tuple[str, str, str, str]] = deque(
            maxlen=MAX_EVENTS_REMEMBERED
        )

    def record(self, raw_body: bytes, headers: dict[str, str]) -> Delivery:
        received_at = datetime.now(timezone.utc)
        # Rotation is not atomic: for a while after one, some deliveries are
        # still signed with the old secret, so a body matching either verifies.
        header_value = headers.get(SIGNATURE_HEADER.lower(), "")
        verified_by_current_secret = verify_signature(
            self.secret, raw_body, header_value
        )
        verified_by_previous_secret = verify_signature(
            self.previous_secret, raw_body, header_value
        )
        signature_ok = verified_by_current_secret or verified_by_previous_secret

        body: dict[str, Any] | None = None
        parse_error: str | None = None
        # Parse only a body whose signature verifies. Anyone can send the
        # rest, and parsed, 1 MiB of '{"a":[{},{},...]}' is over 20 MiB of
        # Python objects; kept as bytes, it is 1 MiB.
        if signature_ok:
            try:
                parsed = json.loads(raw_body)
                body = parsed if isinstance(parsed, dict) else None
                if body is None:
                    parse_error = "body is not a JSON object"
            except (ValueError, UnicodeDecodeError, RecursionError) as exc:
                # A malformed body must never take the endpoint down: the
                # sender retries on a non-2xx, and a crash loop turns one bad
                # payload into six. JSON nested deeper than the parser can
                # recurse raises RecursionError, which is not a ValueError.
                parse_error = f"{type(exc).__name__}: {exc}"

        # Only a verified delivery takes part in de-duplication. Otherwise a
        # forged body carrying a real event's key, arriving first, would make
        # the real delivery look like a repeat.
        key = dedupe_key_for(body) if signature_ok else None
        duplicate = key is not None and key in self._seen
        if key is not None:
            self._seen.append(key)

        delivery = Delivery(
            raw_body=raw_body,
            headers=headers,
            received_at=received_at,
            signature_ok=signature_ok,
            verified_only_by_previous_secret=(
                verified_by_previous_secret and not verified_by_current_secret
            ),
            duplicate=duplicate,
            parse_error=parse_error,
            body=body,
        )
        self.deliveries.append(delivery)
        return delivery


async def read_body_up_to(request: Request, limit: int) -> bytes | None:
    """The body exactly as it arrived, or None once more than `limit` bytes have.

    Reads it a chunk at a time and stops at the limit, so an oversized body is
    never held whole. Content-Length cannot be relied on for this: a chunked
    request has none.
    """
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def refused(status_code: int, error: str) -> JSONResponse:
    """A delivery turned away before its body was read in full.

    Connection: close, because left open the server goes on reading, and
    discarding, the rest of the body for as long as the client keeps sending.
    """
    return JSONResponse(
        {"received": False, "error": error},
        status_code=status_code,
        headers={"Connection": "close"},
    )


def create_webhook_app(receiver: Receiver | None = None) -> FastAPI:
    """The webhook, and nothing else.

    This is the app your tunnel exposes, so it serves no page, and none of the
    framework's generated API pages (/docs, /redoc, /openapi.json) either.
    """
    # No schema, so no generated API pages: /docs and /redoc need it too.
    app = FastAPI(title="trackcourier.io webhook receiver", openapi_url=None)
    app.state.receiver = receiver or Receiver(
        secret=os.getenv("TRACKCOURIER_WEBHOOK_SECRET", ""),
        previous_secret=os.getenv("TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET", ""),
    )

    # Both spellings, so neither is answered with a redirect: the sender
    # re-issues a redirected delivery as a GET without its body.
    @app.post("/webhook/")
    @app.post("/webhook")
    async def receive(request: Request) -> JSONResponse:
        # The raw bytes, before anything parses them. Everything downstream
        # works from this; nothing re-serializes.
        try:
            raw_body = await asyncio.wait_for(
                read_body_up_to(request, MAX_BODY_BYTES), BODY_READ_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            return refused(
                408, f"body not received within {BODY_READ_TIMEOUT_SECONDS} seconds"
            )
        except ClientDisconnect:
            # Nobody is left to read this answer. Returning one keeps the
            # disconnect out of the error log, which strangers could fill.
            return refused(400, "client disconnected before sending the whole body")
        if raw_body is None:
            return refused(413, f"body over {MAX_BODY_BYTES} bytes")
        headers = {k.lower(): v for k, v in request.headers.items()}
        delivery = request.app.state.receiver.record(raw_body, headers)
        # 401 when neither secret verifies, so the sender retries: a delivery
        # signed with a new secret you have not stored yet verifies on a later
        # attempt, and a wrong secret fails loudly instead of being
        # acknowledged and dropped. A 2xx ends a delivery. Once the signature
        # verifies, a parse failure is still a 2xx: it is ours to look at, not
        # a reason to make the sender retry.
        return JSONResponse(
            {
                "received": True,
                "signature_ok": delivery.signature_ok,
                "duplicate": delivery.duplicate,
            },
            status_code=200 if delivery.signature_ok else 401,
        )

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app


def create_viewer_app(receiver: Receiver) -> FastAPI:
    """The page that shows every delivery: tracking numbers, locations.

    Serve it only on 127.0.0.1, on a port no tunnel points at (see
    webhook_and_viewer_servers).
    """
    # No schema, so no generated API pages: /docs and /redoc need it too.
    app = FastAPI(title="trackcourier.io webhook viewer", openapi_url=None)
    # Answer only a request that names this machine. That refuses a tunnel
    # pointed at this port anyway, if it passes on its public hostname, and a
    # web page that re-points its own domain at 127.0.0.1 to read this page
    # through your browser (DNS rebinding).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(render_page(receiver))

    return app


def webhook_and_viewer_servers(
    webhook_app: FastAPI,
) -> tuple[uvicorn.Server, uvicorn.Server]:
    """The two listeners app.py runs: the webhook, and the page showing what it got.

    Two ports, not one, because of how a tunnel works. It forwards every path
    on the port it points at, and it runs on this machine, so it connects from
    127.0.0.1: listening on 127.0.0.1 does not keep a page on that port
    private. So the page gets a port no tunnel points at, and both listen on
    127.0.0.1 only.
    """
    viewer_app = create_viewer_app(webhook_app.state.receiver)
    return (
        uvicorn.Server(
            uvicorn.Config(
                webhook_app,
                host="127.0.0.1",
                port=WEBHOOK_PORT,
                limit_concurrency=MAX_WEBHOOK_CONNECTIONS,
            )
        ),
        # Not access_log=False, however noisy the page's reloads: uvicorn's
        # access log is one logger for the whole process, so that would also
        # silence the lines showing each delivery's status.
        uvicorn.Server(
            uvicorn.Config(viewer_app, host="127.0.0.1", port=VIEWER_PORT)
        ),
    )


async def serve(servers: tuple[uvicorn.Server, ...]) -> None:
    """Run the servers side by side in one process, so they share one Receiver."""
    await asyncio.gather(*(server.serve() for server in servers))


def render_page(receiver: Receiver) -> str:
    """Render deliveries. Every received value goes through html.escape.

    Only this machine can load the page, but what it shows is not yours: it is
    attacker-influenced the moment a courier's free-text field reaches it, and
    anyone who finds the webhook's URL can post a body of their own.
    """
    rows = []
    for i, d in enumerate(reversed(receiver.deliveries), start=1):
        sig = "PASS" if d.signature_ok else "FAIL"
        if d.verified_only_by_previous_secret:
            sig += " (previous secret)"
        sig_class = "ok" if d.signature_ok else "bad"
        flags = []
        if d.duplicate:
            flags.append(
                '<span class="dup">repeat: same key as an earlier delivery</span>'
            )
        if d.parse_error:
            flags.append(f'<span class="bad">{html.escape(d.parse_error)}</span>')
        preview = d.raw_body[:MAX_BODY_BYTES_SHOWN_ON_PAGE]
        # Bytes that are not UTF-8, including a character the cut splits in
        # two, show as \xNN escapes.
        shown = preview.decode("utf-8", errors="backslashreplace")
        if len(d.raw_body) > len(preview):
            shown += f"\n[{len(d.raw_body) - len(preview)} more bytes not shown]"
        rows.append(
            f'<article><h2>#{i} '
            f"<small>{d.received_at:%Y-%m-%d %H:%M:%S} UTC</small> "
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
        f"<h1>Received deliveries ({len(receiver.deliveries)})</h1>"
        f"<p>Newest first. The most recent {MAX_DELIVERIES_KEPT} are kept, in"
        f" memory.</p>{body}"
    )


# The webhook alone, for an ASGI server you run yourself. Running this file
# serves the page as well.
app = create_webhook_app()

if __name__ == "__main__":
    # Ctrl-C stops both servers; this only spares you the traceback after.
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(webhook_and_viewer_servers(app)))
