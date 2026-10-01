from __future__ import annotations

import pytest

from security_toolkit.headers import analyze_headers, fetch_headers


def test_analyze_headers_reports_present_and_missing():
    findings = analyze_headers(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        },
        is_https=False,
    )

    by_name = {item.header: item for item in findings}
    assert by_name["Content-Security-Policy"].present is True
    assert by_name["X-Content-Type-Options"].present is True
    assert by_name["Permissions-Policy"].present is False
    assert "Strict-Transport-Security" not in by_name


@pytest.mark.parametrize("url", ["file:///tmp/test", "ftp://example.com/file", "example.com"])
def test_fetch_headers_rejects_non_http_schemes(url):
    with pytest.raises(ValueError):
        fetch_headers(url)
