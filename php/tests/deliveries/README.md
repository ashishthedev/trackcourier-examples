# Recorded deliveries

Each `<name>.body` is a webhook delivery exactly as trackcourier.io's own webhook sender wrote it, byte for
byte, recorded on 2026-10-27. Each `<name>.json` holds the headers it was sent with and the secret that
signed it. The secrets are public test values: never use them for a real webhook.

| recording | what it is |
|---|---|
| `live_delivered` | a live `tracking.delivered` update with two checkpoints; the newest activity has Hindi text, a `/` and an HTML link, which the sender writes as `\u003c`, `\u003e` and `\u0026` |
| `live_without_checkpoints` | a live update whose `checkpoints` is `null` |
| `test_event` | a test event: `X-Webhook-Mode: test`, and a courier beginning `synthetic-test-` |
| `live_signed_with_the_previous_secret` | `live_delivered`, signed with the secret you had before a rotation |
| `live_signed_with_an_empty_secret` | `live_delivered`, signed with an empty secret, which no receiver may accept |

Re-record them rather than edit them: a body changed by hand no longer matches its signature.
