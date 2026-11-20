"""Tests for the command-line interface."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vaultscrub.cli import main

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
ENTROPY_TOKEN = "aB3dEf7hIjKlMnOpQrStUvWx"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_scan_clean_file_exits_zero(tmp_path: Path):
    path = _write(tmp_path, "clean.txt", "hello world\n")
    assert main(["scan", str(path)]) == 0


def test_scan_dirty_file_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = _write(tmp_path, "dirty.txt", f"key {AWS_KEY}\n")
    assert main(["scan", str(path)]) == 1
    out = capsys.readouterr().out
    assert "aws-access-key" in out
    assert AWS_KEY not in out  # raw secret is never printed


def test_scan_json_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = _write(tmp_path, "dirty.txt", f"key {AWS_KEY}\n")
    assert main(["scan", str(path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_findings"] >= 1
    finding = payload["findings"][0]
    assert finding["detector"] == "aws-access-key"
    assert "fingerprint" in finding
    assert AWS_KEY not in json.dumps(payload)


def test_scan_sarif_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = _write(tmp_path, "dirty.txt", f"key {AWS_KEY}\n")
    assert main(["scan", str(path), "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    results = payload["runs"][0]["results"]
    assert results[0]["ruleId"] == "aws-access-key"


def test_scan_sarif_high_entropy(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = _write(tmp_path, "tok.txt", ENTROPY_TOKEN)
    assert main(["scan", str(path), "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"][0]["results"][0]["ruleId"] == "high-entropy"


def test_scan_fail_on_high_ignores_medium(tmp_path: Path):
    path = _write(tmp_path, "mail.txt", "contact jane@example.org\n")
    assert main(["scan", str(path), "--fail-on", "high"]) == 0
    assert main(["scan", str(path), "--fail-on", "low"]) == 1


def test_scan_missing_path(tmp_path: Path):
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_scan_directory_with_exclude(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    _write(tmp_path, "a.txt", f"key {AWS_KEY}\n")
    _write(tmp_path, "b.log", f"key {AWS_KEY}\n")
    assert main(["scan", str(tmp_path), "--exclude", "*.log"]) == 1
    out = capsys.readouterr().out
    assert "a.txt" in out
    assert "b.log" not in out


def test_scan_skips_binary_files(tmp_path: Path):
    path = tmp_path / "bin.dat"
    path.write_bytes(b"\x00\x01" + AWS_KEY.encode())
    assert main(["scan", str(path)]) == 0


def test_scan_no_entropy(tmp_path: Path):
    path = _write(tmp_path, "tok.txt", ENTROPY_TOKEN)
    assert main(["scan", str(path)]) == 1
    assert main(["scan", str(path), "--no-entropy"]) == 0


def test_redact_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = _write(tmp_path, "in.txt", f"key {AWS_KEY}\n")
    assert main(["redact", str(path)]) == 0
    assert capsys.readouterr().out == "key ***\n"


def test_redact_to_output_file(tmp_path: Path):
    path = _write(tmp_path, "in.txt", f"key {AWS_KEY}\n")
    out = tmp_path / "out.txt"
    assert main(["redact", str(path), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "key ***\n"


def test_redact_in_place(tmp_path: Path):
    path = _write(tmp_path, "in.txt", f"key {AWS_KEY}\n")
    assert main(["redact", str(path), "--in-place"]) == 0
    assert path.read_text(encoding="utf-8") == "key ***\n"


def test_redact_missing_file(tmp_path: Path):
    assert main(["redact", str(tmp_path / "nope.txt")]) == 2


def test_redact_invalid_utf8(tmp_path: Path):
    path = tmp_path / "bin.txt"
    path.write_bytes(b"\xff\xfe invalid")
    assert main(["redact", str(path)]) == 2


def test_redact_in_place_stdin_rejected():
    assert main(["redact", "-", "--in-place"]) == 2


def test_redact_stdin(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr("sys.stdin", io.StringIO(f"key {AWS_KEY}\n"))
    assert main(["redact", "-"]) == 0
    assert capsys.readouterr().out == "key ***\n"


def test_check_command():
    assert main(["check", f"key {AWS_KEY}"]) == 1
    assert main(["check", "totally clean"]) == 0


def test_check_stdin(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("clean"))
    assert main(["check", "-"]) == 0


def test_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "vaultscrub" in capsys.readouterr().out


def test_module_entrypoint(tmp_path: Path):
    path = _write(tmp_path, "dirty.txt", f"key {AWS_KEY}\n")
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "vaultscrub", "scan", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 1
    assert "aws-access-key" in result.stdout
