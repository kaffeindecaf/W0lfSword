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
# All verbs live in cli.py now; ul8.py and main.py must stay thin. These tests
# are what would have caught `ul8.py version` (advertised, never dispatched)
# and they are also what stops a second dispatcher from growing back.

def _verb_table() -> dict:
    sys.path.insert(0, str(ROOT))
    import importlib
    import cli
    importlib.reload(cli)
    return cli.VERBS


def test_verb_table_rows_are_complete():
    cli = __import__("cli")
    for verb, row in cli.VERBS.items():
        assert isinstance(row, tuple) and len(row) == 2, verb
        description, handler = row
        assert description and isinstance(description, str), verb
        assert callable(handler), verb
        assert verb == verb.lower() and " " not in verb, verb


def test_aliases_point_at_real_verbs():
    cli = __import__("cli")
    for alias, target in cli.ALIASES.items():
        assert target in cli.VERBS, f"{alias} -> {target}"


def test_help_lists_every_verb(tmp_path):
    out = _run(["ul8.py", "--help"], tmp_path)
    assert out.returncode == 0
    cli = __import__("cli")
    for verb in cli.verb_list():
        assert verb in out.stdout, f"{verb} missing from --help"


def test_dependency_features_cover_every_verb():
    """A verb without a deps mapping would silently skip the dependency check."""
    import deps
    cli = __import__("cli")
    unmapped = [v for v in cli.verb_list() if v not in deps.COMMAND_FEATURES]
    assert unmapped == [], unmapped


@pytest.mark.parametrize("module", ["ul8.py", "main.py"])
def test_launchers_do_not_reimplement_the_dispatch(module):
    tree = ast.parse((ROOT / module).read_text())
    dispatch = [n for n in ast.walk(tree)
                if isinstance(n, ast.Compare)
                and isinstance(n.left, ast.Attribute) and n.left.attr == "command"]
    assert not dispatch, f"{module} grew its own subcommand dispatch again"
    assert "cli.main" in (ROOT / module).read_text(), module


def test_version_is_dispatched_by_both_launchers(tmp_path):
    for module in ("ul8.py", "main.py"):
        out = _run([module, "version"], tmp_path)
        assert out.returncode == 0, out.stderr
        assert version.VERSION in out.stdout, module


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
    assert "try:" in bad.stdout and "preflight" in bad.stdout   # lists what exists

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
