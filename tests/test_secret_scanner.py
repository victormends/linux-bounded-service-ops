"""Tests for working-tree and git-history secret scanning."""

from __future__ import annotations

from pathlib import Path
import subprocess

from bounded_ops.ops.secret_scanner import (
    line_has_secret,
    scan_git_history,
    scan_paths,
)


def test_working_tree_scanner_detects_secrets_and_allows_placeholders(tmp_path: Path) -> None:
    clean = tmp_path / "config.py"
    clean.write_text(
        'WEBHOOK = "https://monitor.example.invalid/hook"\n'
        'API_KEY = os.environ.get("API_KEY", "")\n',
        encoding="utf-8",
    )
    assert scan_paths([tmp_path], root=tmp_path) == []

    leaked = tmp_path / "leaked.py"
    # Construct synthetic test pattern dynamically so this test file itself stays clean.
    fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    leaked.write_text(f'AWS_KEY = "{fake_aws}"\n', encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("PORT=8765\n", encoding="utf-8")

    findings = scan_paths([tmp_path], root=tmp_path)
    reported = {(p.name, ln) for p, ln in findings}
    assert ("leaked.py", 1) in reported
    assert (".env", 0) in reported


def test_git_history_scanner_catches_deleted_historical_secret(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Bot"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)

    target = tmp_path / "app.py"
    fake_token = "ghp_" + ("A1b2C3d4E5" * 4)
    target.write_text(f'TOKEN = "{fake_token}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "oops commit secret"], cwd=tmp_path, check=True, capture_output=True)

    # Remove secret in a subsequent commit; working tree is now clean, history still dirty.
    target.write_text('TOKEN = os.environ.get("TOKEN", "")\n', encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "remove secret"], cwd=tmp_path, check=True, capture_output=True)

    assert scan_paths([tmp_path], root=tmp_path) == []
    history_findings = scan_git_history(tmp_path)
    assert len(history_findings) == 1
    assert history_findings[0][1] == "app.py"
    assert history_findings[0][2] == 1


def test_repository_working_tree_has_zero_secrets() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert scan_paths([repo_root], root=repo_root) == []
    assert not line_has_secret('PASSWORD = "<secret>"')
