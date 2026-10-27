"""What the PHP tests share: Docker, the PHP versions, the recordings, and copies with one change.

The tests run the two files in the official PHP images, on the oldest PHP they support and on a current one.
Without Docker they FAIL rather than skip, so a green run always means the files really ran.
"""
import json
import pathlib
import subprocess

import pytest

PHP = pathlib.Path(__file__).resolve().parents[1]
TESTS = pathlib.Path(__file__).resolve().parent
DELIVERIES = TESTS / "deliveries"
ANSWERS = TESTS / "answers"
PHP_VERSIONS = ("7.2", "8.5")

# The lines a test copy changes, exactly as the files have them.
SECRET_LINE = "const TRACKCOURIER_WEBHOOK_SECRET = 'paste-your-signing-secret-here';"
PREVIOUS_SECRET_LINE = "const TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET = '';"
STUB_LINE = "    throw new Exception('Write your own code in save_tracking_update().');"
TRACK_URL = "https://api.trackcourier.io/v1/track?"


def docker(*args, check=True, timeout=120):
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        pytest.fail("these tests run PHP in Docker, and the docker command is not installed")
    if check and done.returncode != 0:
        pytest.fail(f"docker {' '.join(args[:2])} failed: {done.stderr.strip()[-500:]}")
    return done


def recorded(name):
    """A delivery as our sender wrote it: (the body's bytes, {"secret": ..., "headers": {...}})."""
    return (DELIVERIES / f"{name}.body").read_bytes(), json.loads((DELIVERIES / f"{name}.json").read_text())


def copy_with_one_change(text, old, new):
    assert text.count(old) == 1, f"{old!r} occurs {text.count(old)} times, not once"
    return text.replace(old, new)
