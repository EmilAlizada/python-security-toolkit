from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass

SOURCE_RE = re.compile(r"\bfrom\s+([^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthLogSummary:
    failed: int
    accepted: int
    invalid_user: int
    failed_sources: tuple[tuple[str, int], ...]


def _source_ip(line: str) -> str | None:
    match = SOURCE_RE.search(line)
    if not match:
        return None

    candidate = match.group(1).strip("[](),;")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def summarize_auth_log(text: str) -> AuthLogSummary:
    failed = 0
    accepted = 0
    invalid_user = 0
    failed_sources: Counter[str] = Counter()

    for line in text.splitlines():
        lower = line.lower()

        is_failed = "failed password" in lower or "authentication failure" in lower
        if is_failed:
            failed += 1
            source = _source_ip(line)
            if source:
                failed_sources[source] += 1

        if "accepted password" in lower or "accepted publickey" in lower:
            accepted += 1

        if "invalid user" in lower:
            invalid_user += 1

    return AuthLogSummary(
        failed=failed,
        accepted=accepted,
        invalid_user=invalid_user,
        failed_sources=tuple(sorted(failed_sources.items(), key=lambda item: (-item[1], item[0]))),
    )
