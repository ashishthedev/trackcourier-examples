"""Tests for php/trackcourier_webhook.php, run under Apache on PHP 7.2 and PHP 8.5.

Every delivery posted here is one our webhook sender recorded, byte for byte (deliveries/), except the
two bodies in test_a_signed_body_that_is_not_an_update_gets_400, which our sender never writes. The
receiver runs as a shared host runs it: errors logged to a file, never shown (like_a_production_server.ini).
Four copies are served side by side, each changed in one line at most:

  as_downloaded/            the file exactly as published
  with_secret/              the test secret pasted in
  saving/                   that, a previous secret, and save_tracking_update() logging what it was given
  saving_without_previous/  that, with no previous secret

Each test was watched failing: break the line it guards and it goes red.
"""
import hashlib
import hmac
import json
import re
import time
import uuid

import httpx
import pytest

from php_in_docker import (
    DELIVERIES,
    PHP,
    PHP_VERSIONS,
    PREVIOUS_SECRET_LINE,
    SECRET_LINE,
    STUB_LINE,
    TESTS,
    copy_with_one_change,
    docker,
    recorded,
)

# In the saving copies, save_tracking_update() writes what it was given to the error log.
SAVING_LINES = """    error_log('SAVED ' . json_encode(array(
        'tracking_number' => $tracking_number,
        'courier' => $courier,
        'status' => $status,
        'checkpoints' => $checkpoints,
    )));"""
PHP_PROBLEM = re.compile(r"PHP (Notice|Warning|Deprecated|Fatal error|Parse error)")


class Receiver:
    def __init__(self, base_url, log_file):
        self.base_url = base_url
        self.log_file = log_file

    def log(self):
        return self.log_file.read_text() if self.log_file.exists() else ""

    def send(self, copy, body=b"", headers=None, method="POST"):
        """One request to one copy: (the response, what the error log gained while it ran)."""
        before = len(self.log())
        response = httpx.request(method, f"{self.base_url}/{copy}/trackcourier_webhook.php", content=body,
                                 headers=headers or {}, timeout=30)
        return response, self.log()[before:]


def saved(log):
    return [json.loads(line) for line in re.findall(r"SAVED (\{.*\})", log)]


def signed_with(secret, body):
    return {"Content-Type": "application/json",
            "X-Trackcourier-Signature": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


@pytest.fixture(scope="module", params=PHP_VERSIONS, ids=lambda version: f"php{version}")
def receiver(request, tmp_path_factory):
    version = request.param
    site = tmp_path_factory.mktemp(f"site-php{version}")
    logs = tmp_path_factory.mktemp(f"logs-php{version}")
    logs.chmod(0o777)  # Apache's user writes the error log here
    source = (PHP / "trackcourier_webhook.php").read_text()
    secret = recorded("live_delivered")[1]["secret"]
    previous = recorded("live_signed_with_the_previous_secret")[1]["secret"]
    with_secret = copy_with_one_change(source, SECRET_LINE, f"const TRACKCOURIER_WEBHOOK_SECRET = '{secret}';")
    saving_without_previous = copy_with_one_change(with_secret, STUB_LINE, SAVING_LINES)
    saving = copy_with_one_change(
        saving_without_previous, PREVIOUS_SECRET_LINE, f"const TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET = '{previous}';")
    for copy, text in {"as_downloaded": source, "with_secret": with_secret, "saving": saving,
                       "saving_without_previous": saving_without_previous}.items():
        (site / copy).mkdir()
        (site / copy / "trackcourier_webhook.php").write_text(text)

    container = f"trackcourier-php-receiver-{version}-{uuid.uuid4().hex[:8]}"
    docker("run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::80",
           "-v", f"{site}:/var/www/html:ro", "-v", f"{logs}:/var/log/trackcourier-test",
           "-v", f"{TESTS / 'like_a_production_server.ini'}:/usr/local/etc/php/conf.d/zz-like-a-production-server.ini:ro",
           f"php:{version}-apache")
    request.addfinalizer(lambda: docker("rm", "-f", container, check=False))
    base_url = "http://" + docker("port", container, "80/tcp").stdout.splitlines()[0].strip()
    for _ in range(100):
        try:
            httpx.get(base_url, timeout=2)
            break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        pytest.fail(f"Apache in php:{version}-apache never answered")
    return Receiver(base_url, logs / "php_errors.log")


def test_anything_but_a_post_gets_405_and_allow_post(receiver):
    response, _ = receiver.send("as_downloaded", method="GET")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.json() == {"message": "Use POST."}


def test_as_downloaded_it_refuses_every_update_until_the_secret_is_pasted(receiver):
    body, delivery = recorded("live_delivered")
    response, log = receiver.send("as_downloaded", body, delivery["headers"])
    assert (response.status_code, response.json()) == (401, {"message": "Signing secret not set."})
    assert "paste your signing secret" in log


def test_with_the_secret_pasted_a_live_update_gets_500_until_save_tracking_update_is_written(receiver):
    body, delivery = recorded("live_delivered")
    response, log = receiver.send("with_secret", body, delivery["headers"])
    assert (response.status_code, response.json()) == (500, {"message": "Not saved."})
    assert "TrackCourier webhook not saved: Write your own code in save_tracking_update()." in log


def test_a_live_update_reaches_save_tracking_update_and_gets_200(receiver):
    body, delivery = recorded("live_delivered")
    response, log = receiver.send("saving", body, delivery["headers"])
    assert (response.status_code, response.json()) == (200, {"message": "Received."})
    assert saved(log) == [{"tracking_number": "ZZ000000001TEST", "courier": "dtdc", "status": "delivered",
                           "checkpoints": json.loads(body)["data"]["checkpoints"]}]


def test_an_update_without_checkpoints_reaches_save_tracking_update_as_null(receiver):
    body, delivery = recorded("live_without_checkpoints")
    response, log = receiver.send("saving", body, delivery["headers"])
    assert response.status_code == 200
    assert saved(log) == [{"tracking_number": "ZZ000000002TEST", "courier": "dtdc", "status": "in_transit",
                           "checkpoints": None}]


def test_a_test_event_gets_200_without_calling_save_tracking_update(receiver):
    body, delivery = recorded("test_event")
    assert delivery["headers"]["X-Webhook-Mode"] == "test"
    response, log = receiver.send("saving", body, delivery["headers"])
    assert (response.status_code, response.json()) == (200, {"message": "Test event received."})
    assert saved(log) == []


def test_a_body_changed_after_signing_gets_401(receiver):
    body, delivery = recorded("live_delivered")
    changed = body.replace(b"ZZ000000001TEST", b"ZZ000000009TEST")
    assert changed != body and len(changed) == len(body)
    response, log = receiver.send("saving", changed, delivery["headers"])
    assert (response.status_code, response.json()) == (401, {"message": "Signature does not match."})
    assert saved(log) == []


def test_an_update_without_a_signature_gets_401(receiver):
    body, delivery = recorded("live_delivered")
    headers = {k: v for k, v in delivery["headers"].items() if k != "X-Trackcourier-Signature"}
    response, log = receiver.send("saving", body, headers)
    assert response.status_code == 401
    assert saved(log) == []


def test_an_update_signed_with_the_previous_secret_is_accepted_while_it_is_set(receiver):
    body, delivery = recorded("live_signed_with_the_previous_secret")
    response, log = receiver.send("saving", body, delivery["headers"])
    assert response.status_code == 200
    assert [update["tracking_number"] for update in saved(log)] == ["ZZ000000001TEST"]


def test_an_update_signed_with_the_previous_secret_gets_401_when_none_is_set(receiver):
    body, delivery = recorded("live_signed_with_the_previous_secret")
    response, log = receiver.send("saving_without_previous", body, delivery["headers"])
    assert response.status_code == 401
    assert saved(log) == []


def test_an_update_signed_with_an_empty_secret_gets_401(receiver):
    """The previous secret is empty unless you set it: an empty key must never verify anything."""
    body, delivery = recorded("live_signed_with_an_empty_secret")
    assert delivery["secret"] == ""
    response, log = receiver.send("saving_without_previous", body, delivery["headers"])
    assert response.status_code == 401
    assert saved(log) == []


@pytest.mark.parametrize("body", [
    b'{"data":{}}',
    b'{"event":"tracking.delivered","data":{"courier":"dtdc","tracking_number":"   "}}',
], ids=["no_identifiers", "blank_tracking_number"])
def test_a_signed_body_that_is_not_an_update_gets_400(receiver, body):
    secret = recorded("live_delivered")[1]["secret"]
    response, log = receiver.send("saving", body, signed_with(secret, body))
    assert (response.status_code, response.json()) == (400, {"message": "Not a trackcourier.io update."})
    assert saved(log) == []


@pytest.mark.parametrize("version", PHP_VERSIONS, ids=lambda version: f"php{version}")
def test_reencoding_a_recorded_body_writes_different_bytes(version, tmp_path):
    """The docs' claim: json_encode(json_decode($body)) CAN change the bytes, so sign the raw body. For our
    recorded delivery it does; for a plain ASCII body with no slash it does not."""
    plain = b'{"a":"Delhi Hub","n":1}'
    (tmp_path / "plain.body").write_bytes(plain)
    reencode = 'echo json_encode(json_decode(file_get_contents($argv[1]), true));'

    def reencoded(path):
        return docker("run", "--rm", "-v", f"{DELIVERIES}:/deliveries:ro", "-v", f"{tmp_path}:/plain:ro",
                      f"php:{version}-cli", "php", "-r", reencode, path).stdout.encode()

    assert reencoded("/deliveries/live_delivered.body") != recorded("live_delivered")[0]
    assert reencoded("/plain/plain.body") == plain


def test_the_server_log_holds_no_php_notice_warning_deprecation_or_error(receiver):
    """Last in the file, so it reads the log of every request above on this PHP."""
    assert receiver.log(), "no request above wrote to the log, so this check would read nothing"
    assert PHP_PROBLEM.findall(receiver.log()) == [], receiver.log()
