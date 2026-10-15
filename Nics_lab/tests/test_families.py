from backend.collector import detect_family
from backend.families import probes_for


def test_family_detection():
    assert detect_family('{"tagline":"You Know, for Search"}', {}) == "elastic"
    assert detect_family("<link href='/wp-json/'>wp-content</link>", {}) == "wordpress"
    assert detect_family("Grafana dashboard", {}) == "grafana"
    assert detect_family('{"productname":"Nextcloud"}', {}) == "nextcloud"


def test_every_family_has_probes():
    for family in ("elastic", "synology", "wordpress", "grafana", "nextcloud", "generic"):
        assert probes_for(family)
