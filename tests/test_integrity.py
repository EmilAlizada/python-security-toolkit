from __future__ import annotations

from security_toolkit.integrity import create_manifest, verify_manifest


def test_integrity_clean_then_detects_changes(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "b.txt").write_text("beta", encoding="utf-8")

    manifest = tmp_path / "baseline.json"
    create_manifest(root, manifest)

    assert verify_manifest(root, manifest).clean

    (root / "a.txt").write_text("changed", encoding="utf-8")
    (root / "b.txt").unlink()
    (root / "new.txt").write_text("new", encoding="utf-8")

    result = verify_manifest(root, manifest)
    assert result.modified == ("a.txt",)
    assert result.missing == ("b.txt",)
    assert result.unexpected == ("new.txt",)


def test_manifest_does_not_hash_itself_when_inside_root(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.txt").write_text("alpha", encoding="utf-8")

    manifest = root / "baseline.json"
    created = create_manifest(root, manifest)

    assert "baseline.json" not in created["files"]
    assert verify_manifest(root, manifest).clean
