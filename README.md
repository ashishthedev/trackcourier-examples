# trackcourier.io examples

Reference code for integrating with [trackcourier.io](https://trackcourier.io).

> **This is reference code, not a supported product.** It is deliberately small
> and readable so you can copy the parts you need. It carries no SLA, and it is
> not the code that runs our production service.

Currently one example: a **webhook receiver** in Python. Receivers in other
languages follow.

## What a webhook delivery looks like

We POST JSON to your URL with three headers:

| header | value |
|---|---|
| `X-Trackcourier-Signature` | `sha256=<hex hmac_sha256(your_secret, RAW_BODY)>` |
| `X-Webhook-Event` | e.g. `tracking.in_transit` |
| `X-Webhook-Delivery` | `<webhook_id>-<attempt>` — **see the warning below** |

```json
{
  "event": "tracking.in_transit",
  "enqueued_at": "2026-08-28T10:00:00Z",
  "data": {
    "tracking_number": "H4000595466",
    "courier": "dtdc",
    "status": "in_transit",
    "most_recent_status": "IN TRANSIT",
    "origin_city": null,
    "destination_city": null,
    "delivered_date": null,
    "checkpoints": [
      {
        "activity": "Shipment in transit",
        "checkpoint_state": "intransit",
        "courier_name": "DTDC",
        "date": "28-Aug-2026",
        "time": "09:41",
        "location": "Delhi"
      }
    ]
  }
}
```

**Every key is `snake_case`, at every depth — including inside each checkpoint.** This is the
shape to build against.

⚠️ `GET /v1/track` still returns `PascalCase` today (`MostRecentStatus`, `Checkpoints`,
`CheckpointState`), and a model generated from one surface decodes nothing from the other — every
field null, no error. **That difference is on its way out: `/v1/track` is moving to the shape
above, so please do not invest in permanent machinery to bridge the two.** If you need both right
now, map the `PascalCase` names at the edge and keep your internal model `snake_case`; when the
change lands the edge mapping is all you delete. We will tell you before it does.

`origin_city`, `destination_city` and `delivered_date` are reserved and currently always `null`
on a live delivery — do not depend on them. For the delivery date, read the `date` of the
checkpoint whose `checkpoint_state` is `delivered`.

## Run the receiver

```bash
git clone https://github.com/ashishthedev/trackcourier-examples
cd trackcourier-examples
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

export TRACKCOURIER_WEBHOOK_SECRET="<your signing secret>"
.venv/bin/uvicorn app:app --app-dir python-receiver --port 8080
```

Open <http://localhost:8080> to watch deliveries arrive. Run the tests with
`.venv/bin/python -m pytest`. Each one has been watched to fail — a test that has never
failed has never been shown to guard anything.

Your receiver has to be reachable from the public internet — we require HTTPS
and reject hosts that resolve to private, loopback or link-local addresses. In
development, a tunnel is the usual answer:

```bash
cloudflared tunnel --url http://localhost:8080
```

Use a **named** tunnel rather than a quick one if you are going to leave it up.
A quick tunnel gets a new random hostname every restart, and the webhook you
registered then points at a hostname that no longer exists.

⚠️ If you already have a `cloudflared` config file, the command above may adopt a
named tunnel from it rather than creating a quick one, so the hostname you get may
not be the one you expect. Check the hostname `cloudflared` prints before you
register it.

## Verifying the signature

```python
import hmac, hashlib

def verify(secret: str, raw_body: bytes, header_value: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_value)
```

### The trap: sign the RAW body, never a re-serialized one

This is the single most common integration failure. Compute the HMAC over the
bytes **exactly as they arrived**. If you parse the JSON and re-serialize it to
get the body back, verification fails — your serializer will differ from ours in
key order, separator whitespace, or unicode escaping, and any one of those
changes the digest.

```python
# WRONG — a different byte string, so a different digest
body = json.dumps(await request.json()).encode()

# RIGHT — the bytes we signed
body = await request.body()
```

Worked example. These two are the same object and do not have the same digest:

```text
{"event":"tracking.in_transit","data":{}}      <- what we sent
{"event": "tracking.in_transit", "data": {}}   <- json.dumps() default separators
```

In FastAPI, call `await request.body()` first and work from that. In Express,
use `express.raw({type: 'application/json'})` rather than `express.json()`. In
Flask, use `request.get_data()`, not `request.get_json()`.

## Duplicates: key on the body, not on `X-Webhook-Delivery`

Delivery is **at-least-once**. You will occasionally receive the same event
twice, and you must make your handler idempotent.

> 🔴 **Do not deduplicate on `X-Webhook-Delivery`.** Despite the name, it is
> `<webhook_id>-<attempt>`, not a per-event id. Every *first* attempt of every
> event on every parcel carries the identical value `<webhook_id>-1`, while the
> retries it looks like it should collapse each carry a *different* value. A
> receiver keyed on that header suppresses distinct events and fails to suppress
> retries — exactly backwards.

Key on the body tuple instead:

```python
key = (body["event"], body["data"]["tracking_number"], body["data"]["status"])
```

A stable per-event delivery id is a known gap and is on our roadmap. Until it
ships, the body tuple is the honest key.

## Other things worth knowing

- **Reply 2xx quickly.** Anything else is treated as a failure and retried. Do
  the work asynchronously; acknowledge first.
- **The signing secret is per account, not per webhook.** Rotating it switches
  every webhook you own to the new secret, immediately.
- **Escape what you render.** Courier free-text fields reach you unmodified. The
  receiver here routes every displayed value through `html.escape`.

## Trying it without writing any code

Send yourself a delivery shaped like ours and check your verification:

```bash
SECRET='your-signing-secret'
BODY='{"event":"tracking.in_transit","enqueued_at":"2026-08-28T10:00:00Z","data":{"tracking_number":"H4000595466","courier":"dtdc","status":"in_transit"}}'

SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')"

curl -sS -X POST http://localhost:8080/webhook \
  -H 'Content-Type: application/json' \
  -H "X-Trackcourier-Signature: $SIG" \
  -H 'X-Webhook-Event: tracking.in_transit' \
  -H 'X-Webhook-Delivery: wh_example-1' \
  -d "$BODY"
```

Note `printf '%s'` rather than `echo` — `echo` appends a newline, which is one
more byte in the digest and a signature that will not verify.

## Licence

MIT. See [LICENSE](LICENSE).
