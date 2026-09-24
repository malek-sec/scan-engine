"""Tests for robots.txt parsing and URL filtering (no network)."""

from core.robots import parse_disallows, RobotsPolicy


def test_parse_disallows_for_wildcard_agent():
    txt = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /logout\n"
        "Disallow:\n"            # empty = allow all -> ignored
        "Allow: /public\n"
    )
    assert parse_disallows(txt) == ["/admin", "/logout"]


def test_parse_disallows_respects_agent_groups():
    txt = (
        "User-agent: googlebot\n"
        "Disallow: /nogoogle\n"
        "\n"
        "User-agent: *\n"
        "Disallow: /private\n"
    )
    # Only the '*' group applies to us.
    assert parse_disallows(txt) == ["/private"]


def test_policy_filters_disallowed_paths():
    policy = RobotsPolicy.from_map({
        "https://example.com": ["/admin", "/logout"],
    })
    urls = [
        "https://example.com/app.js",
        "https://example.com/admin/panel.js",
        "https://example.com/logout",
        "https://example.com/api/data",
    ]
    kept, dropped = policy.filter(urls)
    assert kept == ["https://example.com/app.js", "https://example.com/api/data"]
    assert dropped == ["https://example.com/admin/panel.js", "https://example.com/logout"]


def test_policy_allows_when_no_rules_for_origin():
    policy = RobotsPolicy.from_map({"https://example.com": ["/x"]})
    # Different origin -> no rules -> allowed.
    assert policy.is_allowed("https://other.com/x")
