from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IP_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f:.]{3,})(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)


@dataclass(frozen=True)
class Indicators:
    ip_addresses: tuple[str, ...]
    urls: tuple[str, ...]
    domains: tuple[str, ...]
    sha256: tuple[str, ...]


def _extract_ips(text: str) -> set[str]:
    found: set[str] = set()
    for candidate in IP_CANDIDATE_RE.findall(text):
        candidate = candidate.strip(".,;()[]{}")
        try:
            found.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return found


def extract_indicators(text: str) -> Indicators:
    urls = {match.rstrip(".,;)") for match in URL_RE.findall(text)}
    hashes = {match.lower() for match in SHA256_RE.findall(text)}
    ips = _extract_ips(text)

    domains = {match.lower().rstrip(".") for match in DOMAIN_RE.findall(text)}
    for url in urls:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        domains.discard(host)

    return Indicators(
        ip_addresses=tuple(sorted(ips)),
        urls=tuple(sorted(urls)),
        domains=tuple(sorted(domains)),
        sha256=tuple(sorted(hashes)),
    )
