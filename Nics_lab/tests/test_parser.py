import pytest

from backend.parser import parse_ports


def test_parse_ports_accepts_ranges_and_deduplicates():
    assert parse_ports("80,443,8000-8002,443") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_rejects_invalid_values():
    with pytest.raises(ValueError):
        parse_ports("0,80")
    with pytest.raises(ValueError):
        parse_ports("90-80")

