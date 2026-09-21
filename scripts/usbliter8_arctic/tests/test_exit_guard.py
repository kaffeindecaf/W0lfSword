"""Tests for the crash/exit layer in `log_utils.py`.

The toolkit is flashed onto hardware and run by beginners, so a Python traceback
is the wrong way to fail: every entry point goes through `guard()`, which turns
whatever happened into a documented exit code, one readable line, and a full
traceback in `usbliter8.log`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import log_utils  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    path = tmp_path / "usbliter8.log"
    monkeypatch.setenv("UL8_LOG_FILE", str(path))
    monkeypatch.delenv("UL8_DEBUG", raising=False)
    log_utils.configure(path=path, level="DEBUG", enabled=True)
    yield path
    log_utils.configure(path=log_utils.DEFAULT_LOG_FILE, level="WARN", enabled=True)
    log_utils._state["explicit"] = False


# ── exit codes are a documented contract ────────────────────────────

def test_exit_codes_are_stable():
    assert log_utils.EXIT_OK == 0
    assert log_utils.EXIT_ERROR == 1
    assert log_utils.EXIT_BLOCKED == 2
    assert log_utils.EXIT_CRASH == 3
    assert log_utils.EXIT_INTERRUPT == 130


# ── guard() ─────────────────────────────────────────────────────────

def test_guard_passes_through_the_return_value():
    assert log_utils.guard(lambda: 0) == 0
    assert log_utils.guard(lambda: 2) == 2
    assert log_utils.guard(lambda: None) == log_utils.EXIT_OK


def test_guard_turns_a_crash_into_code_3_and_a_friendly_line(isolated_log, capsys):
    def boom():
        raise ValueError("component is missing")

    assert log_utils.guard(boom) == log_utils.EXIT_CRASH
    out = capsys.readouterr().out
    assert "Something went wrong" in out
    assert "ValueError: component is missing" in out
    assert str(isolated_log) in out                  # where the details are
    assert "ul8.py logs" in out                      # and how to read them
    assert "Traceback" not in out                    # not dumped on the user

    log_body = isolated_log.read_text()
    assert "unhandled exception" in log_body
    assert "ValueError: component is missing" in log_body
    assert "Traceback (most recent call last)" in log_body


def test_guard_prints_the_traceback_only_in_debug_mode(isolated_log, capsys, monkeypatch):
    monkeypatch.setenv("UL8_DEBUG", "1")

    def boom():
        raise RuntimeError("dev only")

    assert log_utils.guard(boom) == log_utils.EXIT_CRASH
    captured = capsys.readouterr()
    # traceback.print_exception writes to stderr
    assert "Traceback (most recent call last)" in (captured.out + captured.err)


def test_guard_handles_keyboard_interrupt(isolated_log, capsys):
    def interrupted():
        raise KeyboardInterrupt

    assert log_utils.guard(interrupted) == log_utils.EXIT_INTERRUPT
    assert "Interrupted" in capsys.readouterr().out
    assert "interrupted by user" in isolated_log.read_text()


def test_guard_treats_a_broken_pipe_as_normal(isolated_log, capsys):
    def piped():
        raise BrokenPipeError

    assert log_utils.guard(piped) == log_utils.EXIT_OK
    assert capsys.readouterr().out == ""             # piping into head is not an error


def test_guard_respects_sys_exit_and_clean_exit():
    assert log_utils.guard(lambda: sys.exit(2)) == 2
    assert log_utils.guard(lambda: log_utils.fatal("refused")) == log_utils.EXIT_ERROR


def test_guard_returns_blocked_code_for_preflight_refusals():
    def blocked():
        raise log_utils.CleanExit(log_utils.EXIT_BLOCKED, "preflight blocked the build")

    assert log_utils.guard(blocked) == log_utils.EXIT_BLOCKED


# ── fatal() ─────────────────────────────────────────────────────────

def test_fatal_prints_logs_and_stops(isolated_log, capsys):
    with pytest.raises(log_utils.CleanExit) as exc:
        log_utils.fatal("iBSS not found", "check the profile's component names")
    assert exc.value.code == log_utils.EXIT_ERROR
    out = capsys.readouterr().out
    assert "iBSS not found" in out
    assert "check the profile's component names" in out
    body = isolated_log.read_text()
    assert "iBSS not found" in body
    assert "hint: check the profile's component names" in body


def test_fatal_can_use_a_custom_code():
    with pytest.raises(log_utils.CleanExit) as exc:
        log_utils.fatal("do not flash this", code=log_utils.EXIT_BLOCKED)
    assert exc.value.code == log_utils.EXIT_BLOCKED


# ── safe_input() ────────────────────────────────────────────────────

def test_safe_input_returns_what_was_typed(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    assert log_utils.safe_input("continue? ") == "y"


def test_safe_input_uses_the_default_on_eof_when_allowed(isolated_log, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: (_ for _ in ()).throw(EOFError()))
    assert log_utils.safe_input("continue? ", eof_default="n") == "n"
    assert "using default 'n'" in isolated_log.read_text()


def test_safe_input_stops_cleanly_on_eof_without_a_default(isolated_log, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: (_ for _ in ()).throw(EOFError()))
    with pytest.raises(log_utils.CleanExit) as exc:
        log_utils.safe_input("type YES to erase the device: ")
    assert exc.value.code == log_utils.EXIT_ERROR
    out = capsys.readouterr().out
    assert "input ended" in out
    assert "needs a terminal" in out
    assert "input ended" in isolated_log.read_text()


def test_safe_input_stops_on_ctrl_c(isolated_log, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(log_utils.CleanExit) as exc:
        log_utils.safe_input("continue? ")
    assert exc.value.code == log_utils.EXIT_INTERRUPT


def test_no_prompt_in_the_toolkit_uses_bare_input():
    """Every interactive prompt must tolerate EOF (piped/closed stdin)."""
    import re

    offenders = []
    for path in sorted(Path(__file__).parent.parent.glob("*.py")):
        if path.name in ("log_utils.py",):
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"(?<![\w.])input\(", line) and "safe_input" not in line:
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"bare input() found: {offenders}"


def test_entry_points_go_through_guard():
    """A module with a __main__ block must wrap its body in guard()."""
    offenders = []
    for path in sorted(Path(__file__).parent.parent.glob("*.py")):
        text = path.read_text()
        if 'if __name__ == "__main__":' not in text:
            continue
        tail = text[text.index('if __name__ == "__main__":'):]
        if "log_utils.guard" not in tail:
            offenders.append(path.name)
    assert not offenders, f"entry points without guard(): {offenders}"


def test_modules_using_log_utils_import_it_at_module_level():
    """A `log_utils.X` call inside a function needs a module-level import.

    An import that only exists in the `__main__` block works when the file is run
    as a script and raises NameError the moment the module is imported by someone
    else (tests, the wrapper, another module).
    """
    import re

    offenders = []
    root = Path(__file__).parent.parent
    for path in sorted(root.glob("*.py")):
        if path.name in ("log_utils.py", "colors.py"):     # colors imports lazily on purpose
            continue
        text = path.read_text()
        if "log_utils." not in text:
            continue
        if not re.search(r"^import log_utils$", text, re.M):
            offenders.append(path.name)
    assert not offenders, f"missing module-level `import log_utils`: {offenders}"


def test_clean_exit_cannot_be_swallowed_by_a_broad_handler():
    """CleanExit is a BaseException on purpose: `except Exception` around a prompt
    must not turn "input ended, stop" into a silent continue."""
    def swallower():
        try:
            raise log_utils.CleanExit(log_utils.EXIT_BLOCKED, "stop")
        except Exception:                                    # noqa: BLE001
            return "swallowed"
        return "survived"

    assert log_utils.guard(swallower) == log_utils.EXIT_BLOCKED


def test_flash_prompt_stops_with_closed_stdin(tmp_path):
    """The device-erasing path must refuse to guess when it has no terminal."""
    import os
    import subprocess

    env = dict(os.environ, UL8_LOG_FILE=str(tmp_path / "flash.log"))
    result = subprocess.run([sys.executable, "main.py", "flash"],
                            cwd=Path(__file__).parent.parent, capture_output=True,
                            text=True, env=env, stdin=subprocess.DEVNULL, timeout=180)
    assert result.returncode == log_utils.EXIT_ERROR
    combined = result.stdout + result.stderr
    assert "input ended" in combined
    assert "needs a terminal" in combined
    assert "erases the device" not in combined.lower() or "THIS ERASES" in combined


def test_missing_input_is_a_normal_failure_not_a_verification_refusal(tmp_path):
    """A missing file is exit 1; exit 2 is reserved for a refused build."""
    import subprocess

    proc = subprocess.run([sys.executable, "preflight.py", str(tmp_path / "nope.yaml")],
                          capture_output=True, text=True, env={"UL8_NO_DEPS": "1",
                                                               "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 1
    assert "profile not found" in proc.stdout + proc.stderr
