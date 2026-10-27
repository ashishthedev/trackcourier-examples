# PHP examples

Two files to copy, for PHP 7.2 or later with the curl extension. No framework and no Composer.
The documentation is at [api.trackcourier.io/docs#php](https://api.trackcourier.io/docs#php).

## `trackcourier_track.php`: track a shipment

Set `TRACKCOURIER_API_KEY` to your API key, from the
[API Keys](https://api.trackcourier.io/dashboard/keys) page of your dashboard. Put the courier and the
tracking number in the two lines at the top, then run it:

```sh
export TRACKCOURIER_API_KEY="your_api_key"
php trackcourier_track.php
```

It prints the shipment's state and each checkpoint, or the error's code and message. Every code is
listed under [Error Handling](https://api.trackcourier.io/docs#errors). If you would rather not receive
webhooks, run it on a schedule, for example from cron.

## `trackcourier_webhook.php`: receive webhooks

1. Save it on your server and paste your signing secret into `TRACKCOURIER_WEBHOOK_SECRET`.
2. Write your own code in `save_tracking_update()`, at the bottom. Until you do, the file answers every
   live update with `500`, so we send it again later instead of counting it delivered.
3. Add the file's `https://` address as a webhook on your dashboard's
   [Webhooks](https://api.trackcourier.io/dashboard/webhooks) page.

| It receives | It answers |
|---|---|
| anything but a `POST` | `405` |
| an update before you paste your secret, or one whose signature does not match | `401`, and we send it again later |
| a signed body that is not one of our updates | `400` |
| a test event | `200`, without calling your code |
| a live update | `200` once `save_tracking_update()` has run; `500` if it throws, and we send it again later |

After you rotate your signing secret, put the old one in `TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET` for at
least 15 minutes, so updates signed with it are still accepted.

## The tests

They run both files in Docker, on PHP 7.2 and PHP 8.5: the receiver under Apache, against deliveries
recorded from our webhook sender byte for byte (`tests/deliveries/`), and the track script against a
stand-in for the API. With Docker running:

```sh
pip install -r requirements.txt
pytest php/tests
```
