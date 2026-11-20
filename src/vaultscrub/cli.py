"""Command-line interface for VaultScrub."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from ._version import __version__
from .core import Redactor, scan_paths
from .detectors import DEFAULT_DETECTORS, SEVERITIES, Finding, severity_rank

__all__ = ["build_parser", "main"]

_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultscrub",
        description="Detect and redact secrets and PII in files, logs, and CI output.",
    )
    parser.add_argument("--version", action="version", version=f"vaultscrub {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan files or directories for secrets")
    scan.add_argument("paths", nargs="+", help="Files or directories to scan")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="low",
        help="Fail if a finding at or above this severity is found (default: low)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude paths matching GLOB (repeatable)",
    )
    scan.add_argument("--max-file-size", type=int, default=1_000_000, metavar="BYTES")
    scan.add_argument("--entropy-threshold", type=float, default=4.5)
    scan.add_argument("--no-entropy", action="store_true", help="Disable high-entropy detection")

    redact_cmd = subparsers.add_parser("redact", help="Redact secrets from a file")
    redact_cmd.add_argument("file", help="File to redact, or - for stdin")
    redact_cmd.add_argument("-o", "--output", help="Write to this file instead of stdout")
    redact_cmd.add_argument("--in-place", action="store_true", help="Rewrite the file in place")

    check = subparsers.add_parser("check", help="Check a string for secrets (exit 1 if found)")
    check.add_argument("text", help="Text to check, or - to read stdin")

    return parser


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _render_text(results: list[tuple[Path, list[Finding]]]) -> list[str]:
    lines = []
    for path, findings in results:
        for finding in findings:
            lines.append(
                f"{path}:{finding.line}:{finding.column}: "
                f"[{finding.severity.upper()}] {finding.detector}: {finding.redacted}"
            )
    return lines


def _to_json(results: list[tuple[Path, list[Finding]]]) -> dict[str, Any]:
    findings = []
    for path, path_findings in results:
        for finding in path_findings:
            findings.append(
                {
                    "path": str(path),
                    "line": finding.line,
                    "column": finding.column,
                    "detector": finding.detector,
                    "severity": finding.severity,
                    "redacted": finding.redacted,
                    "fingerprint": _fingerprint(finding.value),
                }
            )
    return {
        "tool": "vaultscrub",
        "version": __version__,
        "findings": findings,
        "summary": {
            "files_with_findings": len(results),
            "total_findings": len(findings),
        },
    }


def _to_sarif(results: list[tuple[Path, list[Finding]]]) -> dict[str, Any]:
    rules_by_id: dict[str, dict[str, Any]] = {}
    sarif_results = []
    for path, path_findings in results:
        for finding in path_findings:
            if finding.detector not in rules_by_id:
                detector = next(
                    (item for item in DEFAULT_DETECTORS if item.name == finding.detector),
                    None,
                )
                rules_by_id[finding.detector] = {
                    "id": finding.detector,
                    "name": finding.detector,
                    "shortDescription": {
                        "text": detector.description if detector else finding.detector
                    },
                    "defaultConfiguration": {"level": _LEVELS.get(finding.severity, "warning")},
                }
            sarif_results.append(
                {
                    "ruleId": finding.detector,
                    "level": _LEVELS.get(finding.severity, "warning"),
                    "message": {"text": f"Potential {finding.detector} secret detected."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(path)},
                                "region": {
                                    "startLine": finding.line,
                                    "startColumn": finding.column,
                                },
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VaultScrub",
                        "version": __version__,
                        "informationUri": "https://github.com/alireza0xj/javid0x1",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _cmd_scan(args: argparse.Namespace) -> int:
    redactor = Redactor(
        entropy_threshold=args.entropy_threshold,
        use_entropy=not args.no_entropy,
    )
    missing = [raw for raw in args.paths if not Path(raw).exists()]
    if missing:
        for raw in missing:
            print(f"vaultscrub: no such file or directory: {raw}", file=sys.stderr)
        return 2
    results = scan_paths(
        args.paths,
        redactor,
        exclude=args.exclude,
        max_file_size=args.max_file_size,
    )
    if args.format == "json":
        print(json.dumps(_to_json(results), indent=2))
    elif args.format == "sarif":
        print(json.dumps(_to_sarif(results), indent=2))
    else:
        for line in _render_text(results):
            print(line)
    failed = any(
        severity_rank(finding.severity) >= severity_rank(args.fail_on)
        for _, findings in results
        for finding in findings
    )
    total = sum(len(findings) for _, findings in results)
    print(f"vaultscrub: {total} finding(s) in {len(results)} file(s)", file=sys.stderr)
    return 1 if failed else 0


def _cmd_redact(args: argparse.Namespace) -> int:
    if args.in_place and args.file == "-":
        print("vaultscrub: --in-place cannot be used with stdin", file=sys.stderr)
        return 2
    if args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"vaultscrub: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
        except UnicodeDecodeError as exc:
            print(f"vaultscrub: {args.file} is not valid UTF-8: {exc}", file=sys.stderr)
            return 2
    redacted = Redactor().redact(text)
    if args.in_place:
        Path(args.file).write_text(redacted, encoding="utf-8")
    elif args.output:
        Path(args.output).write_text(redacted, encoding="utf-8")
    else:
        sys.stdout.write(redacted)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.text == "-" else args.text
    findings = Redactor().find(text)
    for finding in findings:
        print(
            f"{finding.line}:{finding.column}: "
            f"[{finding.severity.upper()}] {finding.detector}: {finding.redacted}"
        )
    return 1 if findings else 0


def main(argv: list[str] | tuple[str, ...] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "redact":
        return _cmd_redact(args)
    if args.command == "check":
        return _cmd_check(args)
    parser.error(f"Unknown command: {args.command}")
