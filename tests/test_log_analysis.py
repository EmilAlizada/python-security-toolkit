from __future__ import annotations

from security_toolkit.log_analysis import summarize_auth_log


def test_summarize_auth_log():
    text = """
Oct 1 host sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 4444 ssh2
Oct 1 host sshd[2]: Failed password for root from 203.0.113.10 port 4445 ssh2
Oct 1 host sshd[3]: Invalid user guest from 198.51.100.20 port 4446
Oct 1 host sshd[4]: Accepted publickey for emil from 192.0.2.15 port 5555 ssh2
"""

    summary = summarize_auth_log(text)

    assert summary.failed == 2
    assert summary.accepted == 1
    assert summary.invalid_user == 2
    assert summary.failed_sources == (("203.0.113.10", 2),)
