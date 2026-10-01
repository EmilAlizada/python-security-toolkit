from __future__ import annotations

from security_toolkit.iocs import extract_indicators


def test_extract_indicators():
    digest = "a" * 64
    text = (
        "Observed 203.0.113.10 and 2001:db8::1. "
        "Callback https://malware.example/path and domain example.org. "
        f"SHA256 {digest}. Invalid 999.999.999.999."
    )

    result = extract_indicators(text)

    assert "203.0.113.10" in result.ip_addresses
    assert "2001:db8::1" in result.ip_addresses
    assert "999.999.999.999" not in result.ip_addresses
    assert "https://malware.example/path" in result.urls
    assert "example.org" in result.domains
    assert digest in result.sha256
