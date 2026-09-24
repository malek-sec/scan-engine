"""Tests for the scope guard that bounds active traffic to authorised hosts."""

from core.scope import ScopeGuard


def test_from_target_covers_apex_and_subdomains():
    g = ScopeGuard.from_target("example.com")
    assert g.is_in_scope("example.com")
    assert g.is_in_scope("api.example.com")
    assert g.is_in_scope("https://deep.api.example.com/path?x=1")
    assert not g.is_in_scope("example.org")
    assert not g.is_in_scope("notexample.com")
    # Look-alike suffix must not slip through.
    assert not g.is_in_scope("example.com.evil.net")


def test_out_of_scope_beats_in_scope():
    g = ScopeGuard(["example.com"], ["admin.example.com"])
    assert g.is_in_scope("app.example.com")
    assert not g.is_in_scope("admin.example.com")
    # A subdomain of an excluded host is also excluded.
    assert not g.is_in_scope("db.admin.example.com")


def test_inline_bang_exclusion_in_scope_list():
    g = ScopeGuard(["example.com", "!secret.example.com"])
    assert g.is_in_scope("www.example.com")
    assert not g.is_in_scope("secret.example.com")


def test_wildcard_and_exact_patterns():
    g = ScopeGuard(["*.example.com", "app.other.com"])
    assert g.is_in_scope("x.example.com")
    assert g.is_in_scope("example.com")          # wildcard covers apex too
    assert g.is_in_scope("app.other.com")
    assert not g.is_in_scope("api.other.com")    # exact host only


def test_filter_splits_kept_and_dropped():
    g = ScopeGuard.from_target("example.com")
    hosts = [
        "https://a.example.com",
        "https://cdn.thirdparty.com",
        "https://b.example.com",
        "https://tracker.evil.net",
    ]
    kept, dropped = g.filter(hosts)
    assert kept == ["https://a.example.com", "https://b.example.com"]
    assert dropped == ["https://cdn.thirdparty.com", "https://tracker.evil.net"]


def test_filter_with_key_extractor():
    g = ScopeGuard.from_target("example.com")
    items = [{"url": "https://a.example.com/app.js"}, {"url": "https://evil.net/x.js"}]
    kept, dropped = g.filter(items, key=lambda d: d["url"])
    assert kept == [{"url": "https://a.example.com/app.js"}]
    assert dropped == [{"url": "https://evil.net/x.js"}]


def test_empty_guard_is_flagged():
    assert ScopeGuard([]).is_empty
    assert not ScopeGuard.from_target("example.com").is_empty


def test_from_files_reads_patterns(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# program scope\nexample.com\n*.example.org\n", encoding="utf-8")
    oos = tmp_path / "oos.txt"
    oos.write_text("staging.example.com\n", encoding="utf-8")
    g = ScopeGuard.from_files(str(scope), str(oos))
    assert g.is_in_scope("api.example.com")
    assert g.is_in_scope("sub.example.org")
    assert not g.is_in_scope("staging.example.com")
