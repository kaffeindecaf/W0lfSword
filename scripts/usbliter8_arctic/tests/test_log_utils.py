"""Tests for the logging feature (`log_utils.py`).

Every on-screen error/warning is mirrored into `usbliter8.log` in the repo root
so a user can hand over the actual reason a run failed. The rules that matter:
the file is capped and rotated, logging never breaks a flash, a test run never
appends to the developer's real log, and unhandled exceptions are recorded with
a traceback.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import log_utils  # noqa: E402
import colors  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    """Point logging at a throwaway file and restore the defaults afterwards."""
    path = tmp_path / "usbliter8.log"
    monkeypatch.setenv("UL8_LOG_FILE", str(path))
    monkeypatch.delenv("UL8_NO_LOG", raising=False)
    monkeypatch.delenv("UL8_LOG_LEVEL", raising=False)
    log_utils.configure(path=path, level="DEBUG", enabled=True)
    yield path
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["failed"] = False


def test_default_log_lives_in_the_repo_root():
    assert log_utils.DEFAULT_LOG_FILE == ROOT / "usbliter8.log"
    assert log_utils.LOG_LOCK is not None


def test_error_is_written_with_level_timestamp_and_location(isolated_log):
    log_utils.log_error("ipBSS repair failed")
    body = isolated_log.read_text()
    assert "[ERROR" in body
    assert "ipBSS repair failed" in body
    # timestamp + calling module:line, so a log can be attributed
    assert body.startswith("[")
    assert "test_log_utils:" in body


def test_warn_and_info_levels(isolated_log):
    log_utils.log_warn("offset below the confidence floor")
    log_utils.log_info("all 48 entries valid")
    body = isolated_log.read_text()
    assert "[WARN" in body and "confidence floor" in body
    assert "[INFO" in body and "48 entries valid" in body


def test_level_filter_keeps_lower_levels_out(isolated_log):
    log_utils.configure(path=isolated_log, level="ERROR")
    log_utils.log_info("not interesting")
    log_utils.log_warn("also filtered")
    log_utils.log_error("this one counts")
    body = isolated_log.read_text()
    assert "this one counts" in body
    assert "not interesting" not in body and "also filtered" not in body


def test_colors_err_and_warn_are_mirrored(isolated_log):
    """colors.err/warn are what every module prints errors through."""
    message = colors.err("RestoreRamdisk not found (no candidate) — skipping")
    assert "✗" in message                                   # still renders as before
    colors.warn("kernelcache does not match this device's component")
    body = isolated_log.read_text()
    assert "[ERROR" in body and "RestoreRamdisk not found" in body
    assert "[WARN" in body and "kernelcache does not match" in body


def test_exception_is_logged_with_traceback(isolated_log):
    try:
        raise ValueError("component j181ap has no iBSS")
    except ValueError as exc:
        log_utils.log_exception(exc, "build failed")
    body = isolated_log.read_text()
    assert "build failed" in body
    assert "ValueError: component j181ap has no iBSS" in body
    assert "Traceback (most recent call last)" in body


def test_excepthook_records_unhandled_exceptions(isolated_log, capsys):
    log_utils._state["installed"] = False
    log_utils.install(path=isolated_log, level="DEBUG")
    try:
        raise RuntimeError("unhandled boom")
    except RuntimeError as exc:
        sys.excepthook(type(exc), exc, exc.__traceback__)
    body = isolated_log.read_text()
    assert "unhandled exception" in body and "RuntimeError: unhandled boom" in body


def test_rotation_keeps_the_file_bounded(isolated_log):
    log_utils.configure(path=isolated_log, level="DEBUG")
    chunk = "x" * 500
    for _ in range((log_utils.MAX_BYTES // len(chunk)) + 40):
        log_utils.log_error(chunk)
    assert isolated_log.stat().st_size < log_utils.MAX_BYTES
    assert isolated_log.with_suffix(".log.1").exists()


def test_unwritable_path_disables_logging_instead_of_raising(tmp_path, capsys):
    log_utils._state["failed"] = False
    log_utils._state["announced"] = False
    blocked = tmp_path / "readonly"
    blocked.mkdir()
    blocked.chmod(0o500)
    log_utils.configure(path=blocked / "usbliter8.log", level="DEBUG")
    try:
        log_utils.log_error("cannot be written")
        assert not log_utils.is_enabled()
        assert "logging disabled" in capsys.readouterr().err
    finally:
        blocked.chmod(0o700)
        log_utils._state["failed"] = False


def test_disabled_logging_writes_nothing(isolated_log):
    log_utils.configure(path=isolated_log, enabled=False)
    assert log_utils.log_error("hidden") is None
    assert not isolated_log.exists()
    log_utils.configure(path=isolated_log, enabled=True)


def test_read_log_tail_and_filters(isolated_log):
    log_utils.configure(path=isolated_log, level="DEBUG")
    for i in range(5):
        log_utils.log_info(f"info {i}")
    log_utils.log_error("the one that matters")

    everything = log_utils.read_log(isolated_log)
    assert len(everything) == 6
    assert log_utils.read_log(isolated_log, tail=2) == everything[-2:]
    assert log_utils.read_log(isolated_log, min_level="ERROR") == [everything[-1]]
    assert log_utils.read_log(isolated_log, grep="matters") == [everything[-1]]
    assert log_utils.read_log(isolated_log, grep="nope") == []


def test_read_log_groups_tracebacks_with_their_entry(isolated_log):
    try:
        raise KeyError("missing")
    except KeyError as exc:
        log_utils.log_exception(exc, "boom")
    entries = log_utils.read_log(isolated_log, tail=1)
    assert len(entries) > 1                      # entry + traceback lines
    assert "boom" in entries[0]
    assert any("KeyError" in line for line in entries[1:])


def test_log_stats_and_clear(isolated_log):
    log_utils.log_error("one")
    log_utils.log_warn("two")
    stats = log_utils.log_stats(isolated_log)
    assert stats["entries"] == 2 and stats["levels"] == {"ERROR": 1, "WARN": 1}
    assert stats["bytes"] > 0 and stats["first"]

    assert log_utils.clear_log(isolated_log) is True
    assert not isolated_log.exists()
    assert log_utils.clear_log(isolated_log) is False


def test_missing_log_reports_empty(isolated_log):
    assert log_utils.read_log(isolated_log) == []
    assert log_utils.log_stats(isolated_log)["exists"] is False


def test_cli_paths(isolated_log, capsys):
    log_utils.log_error("from the cli test")
    assert log_utils.main(["--tail", "5"]) == 0
    out = capsys.readouterr().out
    assert "from the cli test" in out and "usbliter8.log" in out

    assert log_utils.main(["--path"]) == 0
    assert str(isolated_log) in capsys.readouterr().out

    assert log_utils.main(["--grep", "nothing-matches"]) == 1

    assert log_utils.main(["--clear"]) == 0
    assert not isolated_log.exists()


def test_cli_json_is_machine_readable(isolated_log, capsys):
    import json
    log_utils.log_error("json me")
    assert log_utils.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == str(isolated_log)
    assert payload["levels"]["ERROR"] == 1
    assert any("json me" in line for line in payload["lines"])


def test_pytest_runs_never_touch_the_repo_log(monkeypatch):
    """The autouse fixture opts tests into a temp file; without it, nothing is
    written to the developer's real log."""
    log_utils._state["explicit"] = False
    monkeypatch.delenv("UL8_LOG_FILE", raising=False)
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="DEBUG")
    log_utils._state["explicit"] = False
    before = log_utils.DEFAULT_LOG_FILE.stat().st_size if log_utils.DEFAULT_LOG_FILE.exists() else None
    assert log_utils.is_enabled() is False
    assert log_utils.log_error("must not land in the repo log") is None
    after = log_utils.DEFAULT_LOG_FILE.stat().st_size if log_utils.DEFAULT_LOG_FILE.exists() else None
    assert before == after


def test_configure_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("UL8_LOG_FILE", str(tmp_path / "custom.log"))
    monkeypatch.setenv("UL8_LOG_LEVEL", "ERROR")
    path = log_utils.configure(path=None)
    assert path == tmp_path / "custom.log"
    assert log_utils._state["level"] == "ERROR"

    monkeypatch.setenv("UL8_NO_LOG", "1")
    log_utils.configure(path=None)
    assert log_utils.is_enabled() is False
    monkeypatch.delenv("UL8_NO_LOG")
    log_utils.configure(path=None, enabled=True)


def test_level_aliases_and_defaults():
    assert log_utils.normalize_level("warning") == "WARN"
    assert log_utils.normalize_level("fatal") == "CRITICAL"
    assert log_utils.normalize_level("nonsense") == "WARN"
    assert log_utils.normalize_level("") == "WARN"


# ── the launcher wiring (`ul8.py logs` / `main.py logs`) ──

def _run(args, env):
    import subprocess
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                          text=True, env=env, timeout=120)


def test_cli_forwarding_through_the_launchers(tmp_path):
    """`logs --tail N` must reach the subcommand intact (the launcher's
    parse_known_args used to swallow the option value into a positional)."""
    import os
    env = dict(os.environ)
    log_file = tmp_path / "run.log"
    env.update({"UL8_LOG_FILE": str(log_file), "UL8_LOG_LEVEL": "DEBUG",
                "PYTEST_CURRENT_TEST": ""})
    env.pop("PYTEST_CURRENT_TEST", None)

    trigger = _run(["-c", "import log_utils; log_utils.install(); "
                          "import colors; print(colors.err('launcher wiring check'))"],
                   env)
    assert trigger.returncode == 0, trigger.stderr
    assert "launcher wiring check" in log_file.read_text()

    for launcher in ("ul8.py", "main.py"):
        # --grep proves the option value survived the launcher's arg parsing
        shown = _run([launcher, "logs", "--grep", "launcher wiring check"], env)
        assert shown.returncode == 0, shown.stderr
        assert "launcher wiring check" in shown.stdout
        assert "usbliter8.log" in shown.stdout

        tailed = _run([launcher, "logs", "--tail", "3"], env)
        assert tailed.returncode == 0 and tailed.stdout.strip()

    path_only = _run(["ul8.py", "logs", "--path"], env)
    assert str(log_file) in path_only.stdout

    as_json = _run(["main.py", "logs", "--json"], env)
    assert as_json.returncode == 0, as_json.stderr
    payload = json.loads(as_json.stdout)
    assert payload["levels"]["ERROR"] >= 1


# ── helpers other modules import from log_utils ──

def test_legacy_helpers_still_exist():
    """hardware_guide.py imports check_command from here; a rewrite that drops
    these breaks the health check at runtime, not at import."""
    for name in ("retry", "timeout", "check_command", "check_tools", "require_tool",
                 "status_summary", "log_info", "log_warn", "log_error",
                 "log_step"):
        assert hasattr(log_utils, name), f"log_utils.{name} disappeared"


def test_helpful_utilities_behave():
    assert log_utils.check_command("python3") is True
    assert log_utils.check_command("definitely-not-a-real-tool-xyz") is False
    assert log_utils.check_tools(["python3"]) == {"python3": True}
    with pytest.raises(FileNotFoundError):
        log_utils.require_tool("definitely-not-a-real-tool-xyz")
    assert "✓" in log_utils.status_summary({"tool": True})


def test_retry_loops_then_succeeds(isolated_log):
    attempts = {"n": 0}

    @log_utils.retry(max_attempts=3, delay=0)
    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("transient")
        return "ok"

    assert flaky() == "ok"
    assert attempts["n"] == 3
    assert "attempt 1/3 failed" in isolated_log.read_text()


# ── step timings and the run summary ────────────────────────────────

def test_timed_logs_a_start_and_finish_pair(tmp_path):
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="STEP", enabled=True)
    log_utils._reset_run_counters()

    with log_utils.timed("fetch", "ibss"):
        pass

    body = (tmp_path / "t.log").read_text()
    assert "[fetch] ibss: start" in body
    assert "ibss: done in" in body
    assert "s" in body.split("ibss: done in")[1][:8]
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False


def test_timed_records_failures_and_reraises(tmp_path):
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="STEP", enabled=True)
    log_utils._reset_run_counters()

    with pytest.raises(RuntimeError):
        with log_utils.timed("build", "patch"):
            raise RuntimeError("nope")

    timings = log_utils.run_timings()
    assert timings and timings[0][0] == "build: patch" and timings[0][2] is False
    assert "patch: failed in" in (tmp_path / "t.log").read_text()
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False


def test_run_summary_counts_and_exit_code(tmp_path, monkeypatch):
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="WARN", enabled=True)
    log_utils.install(path=tmp_path / "t.log", level="WARN")
    log_utils._state["installed"] = False

    log_utils.log_warn("something to report", module="t")
    log_utils.log_error("something broke", module="t")
    with log_utils.timed("step", "work"):
        pass
    summary = log_utils.run_summary()

    assert summary["warn"] == 1 and summary["error"] == 1 and summary["steps"] == 1
    assert summary["exit"] == 0
    body = (tmp_path / "t.log").read_text()
    assert "run summary:" in body and "1 warning(s)" in body and "exit 0" in body

    log_utils._state["exit_code"] = 2
    assert log_utils.run_summary()["exit"] == 2
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["installed"] = False


def test_bookkeeping_lines_survive_a_warn_level(tmp_path):
    """The header and the summary are bookkeeping: a WARN filter must keep them."""
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="WARN", enabled=True)
    log_utils._state["installed"] = False
    log_utils._state["counts"] = {}
    log_utils.install(path=tmp_path / "t.log", level="WARN")
    log_utils.run_summary()

    body = (tmp_path / "t.log").read_text()
    assert "run start" in body                       # forced INFO despite level=WARN
    assert "run summary:" in body
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["installed"] = False


def test_run_history_and_slow_steps_parse_the_log(tmp_path):
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="STEP", enabled=True)
    log_utils._state["installed"] = False
    log_utils._state["counts"] = {}
    log_utils.install(path=tmp_path / "t.log", level="STEP")
    with log_utils.timed("fetch", "kernelcache"):
        pass
    log_utils.log_warn("a warning", module="t")
    log_utils.run_summary()

    runs = log_utils.run_history(tmp_path / "t.log")
    assert runs and runs[0]["summary"]
    assert runs[0]["levels"].get("WARN") == 1
    steps = log_utils.slow_steps(tmp_path / "t.log")
    assert steps and steps[0][0] == "fetch: kernelcache"
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["installed"] = False


def test_logs_summary_cli(tmp_path, capsys, monkeypatch):
    import log_utils
    log_utils.configure(path=tmp_path / "t.log", level="STEP", enabled=True)
    log_utils._state["installed"] = False
    log_utils._state["counts"] = {}
    log_utils.install(path=tmp_path / "t.log", level="STEP")
    with log_utils.timed("fetch", "ibss"):
        pass
    log_utils.run_summary()
    monkeypatch.setattr(log_utils, "log_path", lambda *a, **k: tmp_path / "t.log")

    assert log_utils.main(["--summary"]) == 0
    out = capsys.readouterr().out
    assert "log summary" in out and "recent runs" in out and "slowest steps" in out
    assert "fetch: ibss" in out                       # the step that ran

    assert log_utils.main(["--summary", "--json"]) == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["runs"] and payload["slowest"]
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False
    log_utils._state["installed"] = False
