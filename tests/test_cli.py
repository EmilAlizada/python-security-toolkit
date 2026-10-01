from __future__ import annotations

from security_toolkit.cli import main


def test_cli_hash(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("abc", encoding="utf-8")

    assert main(["hash", str(sample)]) == 0
    output = capsys.readouterr().out.strip()
    assert len(output) == 64


def test_cli_integrity_returns_nonzero_on_change(tmp_path, capsys):
    root = tmp_path / "data"
    root.mkdir()
    sample = root / "sample.txt"
    sample.write_text("first", encoding="utf-8")
    manifest = tmp_path / "manifest.json"

    assert main(["integrity", "create", str(root), str(manifest)]) == 0

    sample.write_text("changed", encoding="utf-8")
    assert main(["integrity", "verify", str(root), str(manifest)]) == 1

    output = capsys.readouterr().out
    assert "modified: sample.txt" in output
