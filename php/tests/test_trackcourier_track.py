"""Tests for php/trackcourier_track.php, on PHP 7.2 and PHP 8.5.

The script runs in php:<version>-cli with every error reported to stderr, so a notice or a deprecation
fails the test (PHP 8.5 deprecates curl_close(), for one). It talks to a stand-in for /v1/track
(stand_in.php under `php -S`, in the same container) through a copy whose one URL prefix points there.
The stand-in answers with answers/<name>.json and records what it was asked.

Each test was watched failing: break the line it guards and it goes red.
"""
import json
import shutil

import pytest

from php_in_docker import ANSWERS, PHP, PHP_VERSIONS, TESTS, TRACK_URL, copy_with_one_change, docker

STAND_IN_URL = "http://127.0.0.1:8099/v1/track?"
A_KEY = "tc_live_THE_KEY_FROM_THE_ENVIRONMENT"
START_THE_STAND_IN = (
    "php -S 127.0.0.1:8099 /app/stand_in.php >/dev/null 2>&1 & "
    "i=0; while [ $i -lt 50 ] && ! php -r 'exit(@fsockopen(\"127.0.0.1\", 8099) ? 0 : 1);'; "
    "do i=$((i+1)); sleep 0.1; done; ")
RUN_THE_SCRIPT = "php -d error_reporting=-1 -d display_errors=stderr /app/trackcourier_track.php"

each_php = pytest.mark.parametrize("version", PHP_VERSIONS, ids=lambda version: f"php{version}")


def run(version, tmp_path, answer=None, key=A_KEY):
    """Run the script once: (docker's result, what the stand-in was asked, or None if nothing reached it).
    With no answer, no stand-in runs, so the API cannot be reached."""
    app, out = tmp_path / "app", tmp_path / "out"
    app.mkdir()
    out.mkdir()
    script = copy_with_one_change((PHP / "trackcourier_track.php").read_text(), TRACK_URL, STAND_IN_URL)
    (app / "trackcourier_track.php").write_text(script)
    shutil.copy(TESTS / "stand_in.php", app / "stand_in.php")
    if answer:
        shutil.copy(ANSWERS / f"{answer}.json", app / "answer.json")
    environment = ["-e", f"TRACKCOURIER_API_KEY={key}"] if key is not None else []
    done = docker("run", "--rm", *environment, "-v", f"{app}:/app:ro", "-v", f"{out}:/out", f"php:{version}-cli",
                  "sh", "-c", (START_THE_STAND_IN if answer else "") + RUN_THE_SCRIPT, check=False)
    asked = out / "request.json"
    return done, json.loads(asked.read_text()) if asked.exists() else None


@each_php
def test_it_prints_the_state_and_each_checkpoint(version, tmp_path):
    done, _ = run(version, tmp_path, "delivered")
    assert (done.returncode, done.stderr) == (0, "")
    assert done.stdout == ("delivered: Delivered\n"
                           "18-Sep-2026 17:08  New Delhi  Delivered\n"
                           "18-Sep-2026 09:41  New Delhi  Out for Delivery\n")


@each_php
def test_it_asks_for_the_courier_and_number_with_the_key_from_the_environment(version, tmp_path):
    done, asked = run(version, tmp_path, "delivered")
    assert (done.returncode, done.stderr) == (0, "")
    assert asked == {"path": "/v1/track", "query": {"courier": "dtdc", "tracking_number": "YOUR_TRACKING_NUMBER"},
                     "api_key": A_KEY}


@each_php
def test_an_error_answer_prints_the_code_and_message_and_exits_1(version, tmp_path):
    done, _ = run(version, tmp_path, "invalid_api_key")
    assert (done.returncode, done.stdout, done.stderr) == (1, "INVALID_API_KEY: Invalid API key\n", "")


@each_php
def test_an_unreachable_api_is_said_so_and_exits_1(version, tmp_path):
    done, asked = run(version, tmp_path)
    assert (done.returncode, done.stderr, asked) == (1, "", None)
    assert done.stdout.startswith("Could not reach the API: "), done.stdout


@each_php
def test_without_a_key_it_says_where_to_get_one_and_asks_nothing(version, tmp_path):
    done, asked = run(version, tmp_path, "delivered", key=None)
    assert (done.returncode, done.stderr, asked) == (1, "", None)
    assert "TRACKCOURIER_API_KEY" in done.stdout and "https://api.trackcourier.io/dashboard/keys" in done.stdout


@each_php
def test_a_shipment_without_checkpoints_prints_its_state_alone(version, tmp_path):
    done, _ = run(version, tmp_path, "no_checkpoints")
    assert (done.returncode, done.stdout, done.stderr) == (0, "intransit: In Transit\n", "")
