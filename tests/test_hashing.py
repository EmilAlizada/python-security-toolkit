from __future__ import annotations

import hashlib

import pytest

from security_toolkit.hashing import hash_file


def test_hash_file_sha256(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"security toolkit\n")

    expected = hashlib.sha256(b"security toolkit\n").hexdigest()
    assert hash_file(sample) == expected


def test_hash_file_rejects_weak_or_unknown_algorithm(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("data", encoding="utf-8")

    with pytest.raises(ValueError):
        hash_file(sample, "md5")
