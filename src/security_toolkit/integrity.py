from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .hashing import hash_file


@dataclass(frozen=True)
class IntegrityResult:
    modified: tuple[str, ...]
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not (self.modified or self.missing or self.unexpected)


def _files_under(root: Path, excluded: set[Path] | None = None) -> list[Path]:
    excluded = {path.resolve() for path in (excluded or set())}
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.resolve() not in excluded
    )


def create_manifest(root: Path, output: Path) -> dict[str, Any]:
    """Create a SHA-256 integrity manifest for all regular files below root."""
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    output = output.resolve()
    files = {
        path.relative_to(root).as_posix(): hash_file(path)
        for path in _files_under(root, excluded={output})
    }

    manifest: dict[str, Any] = {
        "version": 1,
        "algorithm": "sha256",
        "created_at": datetime.now(UTC).isoformat(),
        "files": files,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Integrity manifest must be a JSON object")

    data = cast(dict[str, Any], raw)
    if data.get("version") != 1 or data.get("algorithm") != "sha256":
        raise ValueError("Unsupported integrity manifest format")
    if not isinstance(data.get("files"), dict):
        raise ValueError("Manifest does not contain a valid files mapping")
    return data


def verify_manifest(root: Path, manifest_path: Path) -> IntegrityResult:
    """Compare the current directory state with a stored integrity manifest."""
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    manifest_path = manifest_path.resolve()
    manifest = load_manifest(manifest_path)
    expected: dict[str, str] = manifest["files"]

    current_paths = {
        path.relative_to(root).as_posix(): path
        for path in _files_under(root, excluded={manifest_path})
    }

    expected_names = set(expected)
    current_names = set(current_paths)

    missing = sorted(expected_names - current_names)
    unexpected = sorted(current_names - expected_names)
    modified = sorted(
        name
        for name in expected_names & current_names
        if hash_file(current_paths[name]) != expected[name]
    )

    return IntegrityResult(
        modified=tuple(modified),
        missing=tuple(missing),
        unexpected=tuple(unexpected),
    )
