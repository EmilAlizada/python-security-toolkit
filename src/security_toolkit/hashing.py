from __future__ import annotations

import hashlib
from pathlib import Path

SUPPORTED_ALGORITHMS = ("sha256", "sha384", "sha512")


def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    """Return a cryptographic digest for a regular file."""
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        supported = ", ".join(SUPPORTED_ALGORITHMS)
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose one of: {supported}")

    if not path.is_file():
        raise FileNotFoundError(f"Not a regular file: {path}")

    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
