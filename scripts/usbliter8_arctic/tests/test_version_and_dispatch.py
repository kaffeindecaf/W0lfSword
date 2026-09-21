"""Tests for `version.py` and the CLI dispatch honesty.

Two bugs motivated these: `ul8.py version` was advertised in the help text but
never dispatched (it silently opened the menu), and `main.py build|flash|boot|
sshrd|net|vnc` did the same. A subcommand a user can read about must either work
or fail with a message.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import version  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    monkeypatch.setenv("UL8_LOG_FILE", str(tmp_path / "usbliter8.log"))
    import log_utils
    log_utils.configure(path=tmp_path / "usbliter8.log", level="DEBUG", enabled=True)
    yield
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False


# ── version data ────────────────────────────────────────────────────

def test_version_is_not_empty():
    assert version.VERSION
    assert re.match(r"^\d+\.\d+\.\d+", version.VERSION)


def test_describe_includes_the_version():
    assert version.describe().startswith(version.VERSION)


def test_commit_is_a_hash_or_empty():
    sha = version.commit()
    assert sha == "" or re.match(r"^[0-9a-f]{7,}", sha)


def test_info_shape():
    data = version.info()
    assert set(data) >= {"name", "version", "commit", "python", "platform", "repo"}
    assert data["name"] == "usbliter8-arctic"


def test_version_main_json(capsys):
    assert version.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == version.VERSION


def test_version_main_text(capsys):
    assert version.main([]) == 0
    out = capsys.readouterr().out
    assert version.VERSION in out
    assert "python" in out


def test_log_session_header_records_the_version(tmp_path):
    import log_utils
    log_utils.configure(path=tmp_path / "h.log", level="DEBUG", enabled=True)
    log_utils._state["installed"] = False
    log_utils.install(path=tmp_path / "h.log", level="DEBUG")
    body = (tmp_path / "h.log").read_text()
    assert version.VERSION in body
    assert "run start" in body
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["installed"] = False


# ── dispatch honesty ────────────────────────────────────────────────

def _dispatch_facts(module: str) -> tuple[set[str], set[str]]:
    """(advertised subcommands, handled subcommands) read from the source."""
    tree = ast.parse((ROOT / module).read_text())

    advertised: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "help" and isinstance(node.value, ast.Constant):
            text = str(node.value.value)
            if "Subcommand:" in text:
                names = text.split("Subcommand:", 1)[1]
                advertised.update(n.strip().rstrip(",") for n in names.split(",") if n.strip())
        elif isinstance(node, ast.keyword) and node.arg == "help" and isinstance(node.value, ast.BinOp):
            # multi-line concatenated help strings
            parts = []
            stack = [node.value]
            while stack:
                item = stack.pop()
                if isinstance(item, ast.Constant):
                    parts.append(str(item.value))
                elif isinstance(item, ast.BinOp):
                    stack.extend([item.left, item.right])
            text = "".join(reversed(parts))
            if "Subcommand:" in text:
                names = text.split("Subcommand:", 1)[1]
                advertised.update(n.strip().rstrip(",") for n in names.split(",") if n.strip())

    handled: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not (isinstance(node.left, ast.Attribute) and node.left.attr == "command"):
            continue
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, (ast.Eq, ast.In)):
                continue
            if isinstance(comparator, ast.Constant):
                handled.add(str(comparator.value))
            elif isinstance(comparator, (ast.Tuple, ast.List)):
                handled.update(str(e.value) for e in comparator.elts
                               if isinstance(e, ast.Constant))
    return {a for a in advertised if a}, handled


@pytest.mark.parametrize("module", ["ul8.py", "main.py"])
def test_every_advertised_subcommand_is_dispatched(module):
    advertised, handled = _dispatch_facts(module)
    missing = sorted(advertised - handled)
    assert not missing, f"{module} advertises {missing} but never dispatches them"


def test_version_is_dispatched_by_both_launchers():
    for module in ("ul8.py", "main.py"):
        _advertised, handled = _dispatch_facts(module)
        assert "version" in handled, module
        assert "logs" in handled, module


def _run(args: list[str], tmp_path: Path) -> subprocess.CompletedProcess:
    import os
    env = dict(os.environ, UL8_LOG_FILE=str(tmp_path / "cli.log"))
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                          text=True, env=env, timeout=180)


def test_cli_version_and_unknown_subcommand(tmp_path):
    ok = _run(["ul8.py", "version"], tmp_path)
    assert ok.returncode == 0, ok.stderr
    assert version.VERSION in ok.stdout

    bad = _run(["ul8.py", "definitely-not-a-command"], tmp_path)
    assert bad.returncode == 1
    assert "unknown subcommand" in bad.stdout
    assert "try: menu" in bad.stdout                    # tells the user what exists

    bad_main = _run(["main.py", "definitely-not-a-command"], tmp_path)
    assert bad_main.returncode == 1
    assert "unknown subcommand" in bad_main.stdout


def test_cfw_builder_flags_reach_module_globals(tmp_path):
    """`--dry-run`/`--quiet` must set the module flags, not a local copy."""
    import os
    env = dict(os.environ, UL8_LOG_FILE=str(tmp_path / "cfw.log"))
    out = subprocess.run([sys.executable, "cfw_builder.py", "--dry-run"],
                         cwd=ROOT, capture_output=True, text=True, env=env, timeout=180)
    # no arguments -> usage, but the flag handling must not crash first
    assert "Usage:" in out.stdout or "DRY RUN" in out.stdout
    assert "UnboundLocalError" not in out.stderr
