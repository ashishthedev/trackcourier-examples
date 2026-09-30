# trackcourier.io examples

Reference code for integrating with [trackcourier.io](https://trackcourier.io).

> **This is reference code, not a supported product.** It is deliberately small
> and readable so you can copy the parts you need. It carries no SLA, and it is
> not the code that runs our production service.

Currently one example: a **webhook receiver** in Python. Receivers in other
languages follow.

## What a webhook delivery looks like

We `POST` JSON (`Content-Type: application/json`) to your URL with four headers:

| header | value |
|---|---|
| `X-Trackcourier-Signature` | `sha256=<hex hmac_sha256(your_secret, RAW_BODY)>` |
| `X-Webhook-Event` | the event name, e.g. `tracking.in_transit` |
| `X-Webhook-Delivery` | `<webhook_id>-<attempt>`, which changes on every retry — **see the warning below** |
| `X-Webhook-Mode` | `live` for a real shipment event, `test` for a test fire you triggered |

```json
{
  "event": "tracking.in_transit",
  "enqueued_at": "2026-08-28T10:00:00Z",
  "data": {
    "tracking_number": "H4000595466",
    "courier": "dtdc",
    "status": "in_transit",
    "most_recent_status": "In Transit",
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
    ],
    "enqueued_at": "2026-08-28T10:00:00Z"
  }
}
```

**Every key is `snake_case`, at every depth — including inside each checkpoint.** This is the
shape to build against.

`enqueued_at` is when we queued the event, in UTC to the second, not when the courier recorded it.
It is fixed for the life of the event, and the same value appears inside `data`.

⚠️ This is **not** the shape `GET /v1/track` returns, and the difference is deliberate.
`/v1/track` uses `PascalCase` (`MostRecentStatus`, `Checkpoints`, `CheckpointState`) and calls the
shipment state `ShipmentState` where a delivery calls it `status`. A model generated from one
surface decodes nothing from the other — every field null, no error. If you use both, write two
mappings.

`origin_city`, `destination_city` and `delivered_date` are reserved and currently always `null`
on a live delivery — do not depend on them. For the delivery date, read the `date` of the
checkpoint whose `checkpoint_state` is `delivered`.

⚠️ `courier` is our own slug for the courier, and for most couriers it is not the one you send
to `GET /v1/track`: track with `courier=bluedart` and a delivery says
`"courier": "blue-dart-courier"`. `dtdc`, used above, is one of the few that match. Pair a
delivery with your own record on `tracking_number`, with leading and trailing whitespace removed.
If you track the same number with more than one courier, those deliveries are told apart only by
`courier`, and so by our slug rather than the one you sent.

A **test fire** (`X-Webhook-Mode: test`) arrives in the same envelope, signed the same way, with
`snake_case` keys — but it is not shaped like the sample above. Its `courier` is `synthetic-test-`
followed by a courier slug and its `tracking_number` is made up for that one fire, so do not reject
it for naming a courier or docket you do not know: verify its signature and answer 2xx. It fills
`origin_city` and `destination_city` (and `delivered_date` on a `tracking.delivered` fire), and its
checkpoints carry `status`, `location` and an ISO-8601 `date`, with no `activity`,
`checkpoint_state`, `courier_name` or `time`. Use test fires to prove your signature check and your
2xx, not your checkpoint parser.

## Run the receiver

```bash
git clone https://github.com/ashishthedev/trackcourier-examples
cd trackcourier-examples
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

export TRACKCOURIER_WEBHOOK_SECRET="<your signing secret>"
.venv/bin/uvicorn app:app --app-dir python-receiver --port 8080
```

Your signing secret is returned once: by your account's first webhook create (test or live), if
that create succeeds, or by a rotation, if you rotate before creating any webhook. Create that
first webhook on its own: two creates racing on an account with no secret yet can each return a
different secret, and only one of them keeps working. Every other create returns a notice in the
`secret` field instead, beginning with `<`. Do not store that notice; your secret is unchanged.
If you never received the secret, or have lost it, rotate: each rotation returns its new secret,
once.

Open <http://localhost:8080> to watch deliveries arrive. They are kept in memory, for viewing
only: a restart clears them, and a real handler must store a delivery durably before it answers
2xx. Run the tests with `.venv/bin/python -m pytest`. Each one has been watched to fail — a
test that has never failed has never been shown to guard anything.

Your receiver has to be reachable from the public internet — we require HTTPS
and reject hosts that resolve to private, loopback or link-local addresses. In
development, a tunnel is the usual answer:

```bash
cloudflared tunnel --url http://localhost:8080
```

Register `https://<the hostname it prints>/webhook` as the webhook's URL.

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
    if not secret:  # an HMAC keyed with "" is one anyone can compute
        return False
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

## Rotating the signing secret

`POST /v1/webhooks/rotate-secret` returns the new secret, once, and deliveries start being signed
with it straight away. **The switch is not atomic:** our signing servers pick up a new secret
independently, so for a while after you rotate, some deliveries still carry a signature made with
the **old** one. Verify against the new secret alone and you will reject them. So accept both
across the changeover, in this order:

1. **Before you rotate,** be ready to accept a secret you have not seen yet. The new secret is
   live from the moment of rotation, so a delivery signed with it can reach you before you have
   finished storing the value the call returns, and you cannot stage it in advance, because
   rotating is what creates it. This receiver answers 2xx to every delivery it records, and a 2xx
   ends a delivery, so such a delivery is not retried: it shows as `signature FAIL` only until
   the restart in step 2.
2. **Rotate, and keep the old secret.** Here: set the returned secret as
   `TRACKCOURIER_WEBHOOK_SECRET`, move the old one to `TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET`, and
   restart the receiver.
3. **Accept a body that matches either, for at least 15 minutes.** The receiver checks both, and
   marks a delivery that only the old secret verifies as `signature PASS (previous secret)`.
4. **Drop the old secret** once you have gone 15 minutes without such a delivery (each row shows
   when it arrived): unset `TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET` and restart.

Treat 15 minutes as a practical minimum, not a guaranteed bound. Step 4 — waiting until the old
secret has actually stopped being needed — is what makes the changeover safe.

## Duplicates: make the handler idempotent, and never key on `X-Webhook-Delivery`

Delivery is **at-least-once**. You will occasionally receive the same event
twice, and you must make your handler idempotent.

> 🔴 **Do not deduplicate on `X-Webhook-Delivery`.** Despite the name, it is
> `<webhook_id>-<attempt>`, not a per-event id. Every *first* attempt of every
> event on every parcel carries the identical value `<webhook_id>-1`, while the
> retries it looks like it should collapse each carry a *different* value. A
> receiver keyed on that header suppresses distinct events and fails to suppress
> retries — exactly backwards.

The reliable approach is to make a repeat harmless rather than to filter it
out. Every payload carries the shipment's full known history, so **upsert** it:
replace your stored checkpoints for that consignment with the ones in the
payload, rather than appending "the new event". One exception: `checkpoints`
is `null` when we could not read our record of the shipment at delivery time.
That means the history is unavailable for this delivery, not that there is
none, so do not let a `null` overwrite checkpoints you already hold.

If you also want to skip obvious retries, this key is fixed for the life of an
event:

```python
key = (
    body["event"],
    body["data"]["courier"],
    body["data"]["tracking_number"],
    body["enqueued_at"],
)
```

Do not add `data.status` or the checkpoints to it. Each retry rebuilds `data`
from our freshest record of the shipment, so a retry can carry a newer status
and more checkpoints than the first attempt did.

⚠️ The key is stable, but not guaranteed unique. `enqueued_at` has one-second
resolution, so two genuinely different `tracking.updated` events for the same
consignment queued in the same second share a key. Use it to skip duplicate
work, never to discard an event you would otherwise have acted on — that is
the case where filtering loses a real update and upserting does not.

This receiver computes the key only for a delivery whose signature verifies,
and marks a repeat on the page rather than hiding it.

## Other things worth knowing

- **Store the delivery, then reply 2xx quickly, at the URL you registered.** A
  2xx ends the delivery and there is no way to ask for it again, so verify it
  and store it durably before you answer; do the rest of the work
  asynchronously. Anything else is retried, up to six attempts in all, after
  which the delivery is abandoned, and an endpoint that keeps failing is
  eventually deactivated (we contact you first). Do not answer with a
  redirect: we follow it by re-issuing the request as a `GET` without the
  body, and if that gets a 2xx we record the delivery as successful although
  your endpoint never received it.
- **The signing secret is per account, not per webhook.** One secret signs
  every webhook you own, test and live, and rotating it switches them all —
  but not atomically. See [Rotating the signing secret](#rotating-the-signing-secret).
- **Escape what you render.** Courier free-text fields reach you unmodified. The
  receiver here routes every displayed value through `html.escape`.

## Trying it without writing any code

Send yourself a signed delivery and check your verification. The body is cut down to the
fields this receiver reads, so it is neither a complete live delivery nor a test fire:

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
