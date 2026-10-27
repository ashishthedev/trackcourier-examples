"""No line in either PHP file is longer than 80 characters, so neither wraps when shown in a code box."""
import pytest

from php_in_docker import PHP


@pytest.mark.parametrize("name", ["trackcourier_track.php", "trackcourier_webhook.php"])
def test_no_line_is_longer_than_80_characters(name):
    lines = (PHP / name).read_text().splitlines()
    assert [(number, len(line)) for number, line in enumerate(lines, 1) if len(line) > 80] == []
