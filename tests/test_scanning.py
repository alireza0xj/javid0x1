"""Tests for file and directory scanning."""

from pathlib import Path

from vaultscrub import scan_directory, scan_file, scan_paths

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_scan_file(tmp_path: Path):
    path = tmp_path / "a.txt"
    path.write_text(f"key {AWS_KEY}", encoding="utf-8")
    findings = scan_file(path)
    assert [finding.detector for finding in findings] == ["aws-access-key"]


def test_scan_file_clean(tmp_path: Path):
    path = tmp_path / "a.txt"
    path.write_text("clean", encoding="utf-8")
    assert scan_file(path) == []


def test_scan_file_missing(tmp_path: Path):
    assert scan_file(tmp_path / "nope.txt") == []


def test_scan_file_respects_max_size(tmp_path: Path):
    path = tmp_path / "a.txt"
    path.write_text(f"key {AWS_KEY}", encoding="utf-8")
    assert scan_file(path, max_file_size=4) == []


def test_scan_directory_skips_git(tmp_path: Path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(f"key {AWS_KEY}", encoding="utf-8")
    (tmp_path / "a.txt").write_text(f"key {AWS_KEY}", encoding="utf-8")
    results = list(scan_directory(tmp_path))
    assert [str(path) for path, _ in results] == [str(tmp_path / "a.txt")]


def test_scan_paths_mixed(tmp_path: Path):
    file_path = tmp_path / "a.txt"
    file_path.write_text(f"key {AWS_KEY}", encoding="utf-8")
    results = scan_paths([file_path, tmp_path])
    # The file is scanned once directly and once via the directory.
    assert len(results) == 2
