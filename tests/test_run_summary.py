"""Tests for the whole-run summary builder."""

from core.run_summary import build_run_summary


def test_build_run_summary_rolls_up_counts():
    s = build_run_summary(
        target="example.com",
        scope_desc="in-scope: example.com | out-of-scope: (none)",
        live_hosts=["https://a.example.com", "https://b.example.com"],
        fp_data=[{"host": "a"}],
        js_files=["https://a.example.com/app.js"],
        historical_urls=["https://a.example.com/old"],
        active_data={"crawl": {"count": 12}, "nuclei": {"count": 3}},
        js_data={"js_files_analyzed": 1, "secrets": [{"x": 1}], "endpoints": [], "status": "ok"},
    )
    assert s["target"] == "example.com"
    assert s["totals"]["live_hosts"] == 2
    assert s["totals"]["active_crawl"] == 12
    assert s["totals"]["nuclei"] == 3
    assert s["js_analysis"]["files_analyzed"] == 1
    assert s["js_analysis"]["secrets"] == 1
    assert s["scope"].startswith("in-scope: example.com")


def test_build_run_summary_tolerates_empty_state():
    s = build_run_summary(
        target=None, scope_desc=None, live_hosts=[], fp_data=[],
        js_files=[], historical_urls=[], active_data=None, js_data=None,
    )
    assert s["totals"]["live_hosts"] == 0
    assert s["totals"]["nuclei"] == 0
    assert s["js_analysis"]["secrets"] == 0
    assert s["live_hosts"] == []
