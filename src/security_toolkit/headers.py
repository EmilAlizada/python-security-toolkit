from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    present: bool
    value: str | None
    note: str


BASELINE_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "Restricts browser content sources.",
    "X-Content-Type-Options": "Helps prevent MIME type sniffing.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Restricts access to selected browser capabilities.",
    "X-Frame-Options": "Provides legacy clickjacking protection.",
}


def analyze_headers(headers: Mapping[str, str], is_https: bool = True) -> tuple[HeaderFinding, ...]:
    normalized = {name.lower(): value for name, value in headers.items()}
    expected = dict(BASELINE_HEADERS)
    if is_https:
        expected["Strict-Transport-Security"] = "Instructs browsers to prefer HTTPS."

    findings = []
    for header, note in expected.items():
        value = normalized.get(header.lower())
        findings.append(
            HeaderFinding(
                header=header,
                present=value is not None,
                value=value,
                note=note,
            )
        )
    return tuple(findings)


def fetch_headers(url: str, timeout: float = 5.0) -> tuple[str, Mapping[str, str]]:
    """Fetch response headers from one explicitly supplied HTTP(S) URL."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Only absolute http:// or https:// URLs are supported")

    request = Request(
        url,
        method="GET",
        headers={
            "User-Agent": "python-security-toolkit/0.1",
            "Range": "bytes=0-0",
        },
    )

    # The scheme and netloc are explicitly validated above before urlopen.
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        return response.geturl(), dict(response.headers.items())
