"""Core redaction engine and file scanning for VaultScrub."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Iterator
from pathlib import Path

from .detectors import DEFAULT_DETECTORS, Detector, Finding, detect, severity_rank

__all__ = [
    "Redactor",
    "contains_secret",
    "find_secrets",
    "redact",
    "scan_directory",
    "scan_file",
    "scan_paths",
]

_DEFAULT_MAX_FILE_SIZE = 1_000_000
#: Directories that are never scanned (VCS metadata, virtualenvs, build
#: output, and tool caches). Use ``exclude`` for additional patterns.
_ALWAYS_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".eggs",
        "htmlcov",
    }
)


class Redactor:
    """Redact secrets and PII from text.

    Args:
        replacement: String used to replace each secret.
        detectors: Detectors to use; defaults to ``DEFAULT_DETECTORS``.
        entropy_threshold: Minimum Shannon entropy for the high-entropy detector.
        min_entropy_length: Minimum token length for the high-entropy detector.
        use_entropy: Enable the generic high-entropy detector.
        allowlist: Exact values that should never be flagged.
    """

    def __init__(
        self,
        *,
        replacement: str = "***",
        detectors: Iterable[Detector] | None = None,
        entropy_threshold: float = 4.5,
        min_entropy_length: int = 20,
        use_entropy: bool = True,
        allowlist: Iterable[str] = (),
    ) -> None:
        self.replacement = replacement
        self.detectors = tuple(detectors) if detectors is not None else DEFAULT_DETECTORS
        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length
        self.use_entropy = use_entropy
        self.allowlist = frozenset(allowlist)

    def find(self, text: str) -> list[Finding]:
        """Return all findings in text, sorted by position."""
        raw = detect(
            text,
            self.detectors,
            entropy_threshold=self.entropy_threshold,
            min_entropy_length=self.min_entropy_length,
            use_entropy=self.use_entropy,
        )
        # Drop allowlisted values and duplicate spans (keep highest severity).
        best: dict[tuple[int, int], Finding] = {}
        for finding in raw:
            if finding.value in self.allowlist:
                continue
            key = (finding.start, finding.end)
            current = best.get(key)
            if current is None or severity_rank(finding.severity) > severity_rank(current.severity):
                best[key] = finding
        return sorted(best.values(), key=lambda finding: (finding.start, finding.end))

    def redact(self, text: str) -> str:
        """Return text with every secret replaced.

        Overlapping findings are redacted as a union, so no part of a secret
        can survive because two detectors matched slightly different spans.
        """
        findings = self.find(text)
        if not findings:
            return text
        covered = bytearray(len(text))
        for finding in findings:
            covered[finding.start : finding.end] = b"\x01" * (finding.end - finding.start)
        output: list[str] = []
        index = 0
        length = len(text)
        while index < length:
            if covered[index]:
                output.append(self.replacement)
                while index < length and covered[index]:
                    index += 1
            else:
                output.append(text[index])
                index += 1
        return "".join(output)

    def contains(self, text: str) -> bool:
        """Return True if text contains any secret or PII."""
        return bool(self.find(text))


def redact(text: str, redactor: Redactor | None = None) -> str:
    """Redact secrets from text using a default-configured Redactor."""
    return (redactor or Redactor()).redact(text)


def find_secrets(text: str, redactor: Redactor | None = None) -> list[Finding]:
    """Return all secrets and PII found in text."""
    return (redactor or Redactor()).find(text)


def contains_secret(text: str, redactor: Redactor | None = None) -> bool:
    """Return True if text contains any secret or PII."""
    return (redactor or Redactor()).contains(text)


def scan_file(
    path: str | Path,
    redactor: Redactor | None = None,
    *,
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
) -> list[Finding]:
    """Scan a single file. Binary and oversized files are skipped."""
    file_path = Path(path)
    try:
        if file_path.stat().st_size > max_file_size:
            return []
        data = file_path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data:
        return []
    text = data.decode("utf-8", errors="ignore")
    return (redactor or Redactor()).find(text)


def _is_excluded(path: Path, root: Path, exclude: tuple[str, ...]) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    for pattern in exclude:
        if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True
    return False


def scan_directory(
    root: str | Path,
    redactor: Redactor | None = None,
    *,
    exclude: Iterable[str] = (),
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
) -> Iterator[tuple[Path, list[Finding]]]:
    """Yield (path, findings) for every file under root that has findings."""
    root_path = Path(root)
    patterns = tuple(exclude)
    active = redactor or Redactor()
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if _ALWAYS_EXCLUDED_DIRS.intersection(path.relative_to(root_path).parts):
            continue
        if _is_excluded(path, root_path, patterns):
            continue
        findings = scan_file(path, active, max_file_size=max_file_size)
        if findings:
            yield path, findings


def scan_paths(
    paths: Iterable[str | Path],
    redactor: Redactor | None = None,
    *,
    exclude: Iterable[str] = (),
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
) -> list[tuple[Path, list[Finding]]]:
    """Scan files and directories, returning findings grouped by path."""
    active = redactor or Redactor()
    results: list[tuple[Path, list[Finding]]] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            results.extend(
                scan_directory(path, active, exclude=exclude, max_file_size=max_file_size)
            )
        elif path.is_file():
            findings = scan_file(path, active, max_file_size=max_file_size)
            if findings:
                results.append((path, findings))
    return results
