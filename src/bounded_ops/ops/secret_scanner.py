"""Working-tree and git-history secret scanner for CI and release gates."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".mjs",
        ".json",
        ".html",
        ".css",
        ".md",
        ".service",
        ".timer",
        ".conf",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
    }
)
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".pytest_cache",
        "__pycache__",
        "dist",
        "build",
    }
)
SENSITIVE_FILENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
    }
)
SENSITIVE_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".kdbx"})

PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:[a-z][a-z0-9_-]{0,40}[_-])?"
        r"(?:api[_-]?key|client[_-]?secret|secret(?:[_-]?key)?|password|passwd|access[_-]?token|auth[_-]?token)\b"
        r"\s*[=:]\s*['\"]?[A-Za-z0-9_./+\-]{16,}['\"]?"
    ),
    re.compile(r"(?i)authorization\s*[=:]\s*['\"]bearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
        r"[^\s:/]+:[^\s@/]+@[^\s]+"
    ),
    re.compile(r"https://hooks\.slack\.com/services/[0-9A-Za-z/_-]{20,}"),
)

PLACEHOLDER_MARKERS = (
    "example.invalid",
    "example.com",
    "__app_",
    "__server_",
    "<secret>",
    "<token>",
    "your_secret",
    "your_token",
    "os.environ",
    "os.getenv",
    "process.env",
)

HISTORY_PICKAXE = (
    r"PRIVATE KEY|AKIA[0-9A-Z]|AIza|gh[pousr]_|sk_(live|test)_|xox[baprs]-|"
    r"authorization|api[_-]?key|client[_-]?secret|password|passwd|"
    r"access[_-]?token|auth[_-]?token|postgres|mysql://|mongodb|redis://|"
    r"hooks\.slack"
)


def is_excluded(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False
    parts = set(Path(relative).parts)
    if parts & EXCLUDED_PARTS:
        return True
    return any(relative == part or relative.startswith(part + "/") for part in EXCLUDED_PARTS)


def line_has_secret(line: str) -> bool:
    lower = line.lower()
    if any(marker in lower for marker in PLACEHOLDER_MARKERS):
        return False
    return any(pattern.search(line) for pattern in PATTERNS)


def scan_paths(paths: Sequence[Path], *, root: Optional[Path] = None) -> List[Tuple[Path, int]]:
    """Scan working tree files for sensitive filenames, extensions, and literal secrets."""
    resolved_root = (root or (paths[0] if paths else Path.cwd())).resolve()
    findings: List[Tuple[Path, int]] = []
    for base in paths:
        candidates = [base] if base.is_file() else base.rglob("*")
        for path in candidates:
            if not path.is_file() or is_excluded(path, resolved_root):
                continue
            if (
                path.name.lower() in SENSITIVE_FILENAMES
                or path.suffix.lower() in SENSITIVE_SUFFIXES
            ):
                findings.append((path, 0))
                continue
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(lines, 1):
                if line_has_secret(line):
                    findings.append((path, line_number))
    return findings


def scan_git_history(
    repo: Path,
    *,
    max_findings: int = 100,
) -> List[Tuple[str, str, int]]:
    """Scan added lines across reachable git commits without checking out old trees."""
    command = [
        "git",
        "log",
        "--all",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--unified=0",
        "--format=SCAN_COMMIT:%H",
        "--diff-filter=AM",
        f"-G{HISTORY_PICKAXE}",
        "-p",
    ]
    process = subprocess.Popen(
        command,
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    findings: List[Tuple[str, str, int]] = []
    commit = "unknown"
    file_path = "unknown"
    added_line = 0
    assert process.stdout is not None
    for line in process.stdout:
        line = line.rstrip("\n")
        if line.startswith("SCAN_COMMIT:"):
            commit = line.split(":", 1)[1]
            continue
        if line.startswith("+++ b/"):
            file_path = line[6:]
            continue
        match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if match:
            added_line = int(match.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if line_has_secret(line[1:]):
                findings.append((commit, file_path, added_line))
                if len(findings) >= max_findings:
                    process.kill()
                    break
            added_line += 1
        elif line.startswith(" "):
            added_line += 1
    _stdout, stderr = process.communicate()
    if process.returncode not in (0, -9, 1) and not findings:
        if "does not have any commits yet" not in stderr:
            raise RuntimeError(f"git history scan failed: {stderr.strip()}")
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-history", action="store_true")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("paths", nargs="*", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = args.root.resolve()
    targets = [p.resolve() for p in (args.paths or [root])]
    findings = scan_paths(targets, root=root)
    for path, line_number in findings:
        try:
            display = path.relative_to(root)
        except ValueError:
            display = path
        location = f":{line_number}" if line_number else ""
        print(f"Potential secret: {display}{location}", file=sys.stderr)

    history_findings = scan_git_history(root) if args.git_history else []
    for commit, path, line_number in history_findings:
        print(
            f"Potential historical secret: {commit[:12]} {path}:{line_number}",
            file=sys.stderr,
        )
    return 1 if findings or history_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
