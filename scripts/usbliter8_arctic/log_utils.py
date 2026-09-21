"""Logging for usbliter8-arctic.

Every error and warning that reaches the screen is also written to
`usbliter8.log` in the repo root, together with unhandled exceptions (with
tracebacks) and the steps a run went through. The point is that a user can
report "it failed" with the actual reason attached instead of a screenshot of
the last line: `python3 ul8.py logs` prints the file.

Layout of a line:

    [2026-09-21 14:03:11] [ERROR] [cfw_builder:412] ipBSS not found ...

Design notes:
- stdlib only, never raises: if the log file cannot be written, one note lands
  on stderr and logging disables itself instead of breaking a flash.
- The repo root log is capped and rotated (usbliter8.log -> .1 -> .2 -> .3).
- Tests never touch the repo log: logging is off while pytest runs unless a
  test opts in with an explicit path.
- Coverage comes from two places: `colors.err/warn` (every on-screen error and
  warning goes through them) and `install()` (excepthook + threading excepthook
  for anything that escapes).

Environment:
    UL8_LOG_FILE   override the log path
    UL8_LOG_LEVEL  DEBUG|INFO|WARN|ERROR (default WARN, i.e. errors+warnings)
    UL8_NO_LOG     set to 1 to disable writing entirely
"""

from __future__ import annotations

import os
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).parent
DEFAULT_LOG_FILE = ROOT / "usbliter8.log"

LEVELS = {"DEBUG": 10, "INFO": 20, "STEP": 20, "WARN": 30, "ERROR": 40, "CRITICAL": 50}
LEVEL_ALIASES = {"WARNING": "WARN", "ERR": "ERROR", "FATAL": "CRITICAL", "TRACE": "DEBUG"}

MAX_BYTES = 2 * 1024 * 1024   # rotate at 2 MB
KEEP_BACKUPS = 3

# Process exit codes. Keep these documented in the README: the wrapper script and
# CI gate on them, so a change here is a user-visible change.
EXIT_OK = 0          # finished
EXIT_ERROR = 1       # refused or failed cleanly (bad input, missing file, ...)
EXIT_BLOCKED = 2     # verification refused to let the run continue (preflight)
EXIT_CRASH = 3       # unexpected exception, traceback recorded in the log
EXIT_INTERRUPT = 130 # Ctrl-C

LOG_LOCK = threading.RLock()
_state = {
    "path": DEFAULT_LOG_FILE,
    "level": "WARN",
    "enabled": True,
    "installed": False,
    "failed": False,
    "announced": False,
    "explicit": False,
}

_LEVEL_COLORS = {
    "DEBUG": "\033[38;5;240m",
    "INFO": "\033[38;5;195m",
    "STEP": "\033[38;5;117m",
    "WARN": "\033[1;33m",
    "ERROR": "\033[0;31m",
    "CRITICAL": "\033[1;31m",
}


class CleanExit(BaseException):
    """Raised to stop with a message and an exit code instead of a traceback.

    Deliberately a BaseException, like SystemExit/KeyboardInterrupt: a broad
    `except Exception` around a prompt must not be able to swallow an "input
    ended, stop before doing something destructive" signal.
    """

    def __init__(self, code: int = EXIT_ERROR, message: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message


def fatal(message: str, hint: str = "", code: int = EXIT_ERROR) -> None:
    """Print an error (and how to fix it), log it, then stop cleanly.

    Use this instead of letting an exception escape: the user gets one readable
    line plus a hint, the log gets the story, and the exit code says what
    happened.
    """
    from colors import C, err
    print(err(message))
    if hint:
        print(f"  {C.DIM}{hint}{C.NC}")
    log("ERROR", message, module=_caller_module())
    if hint:
        log("INFO", f"hint: {hint}", module=_caller_module())
    raise CleanExit(code, message)



def safe_input(prompt_text: str, default: str = "", *, eof_default: str | None = None,
               eof_code: int = EXIT_ERROR,
               eof_message: str = "input ended (stdin closed)") -> str:
    """input() that cannot crash the program.

    - EOF (piped or closed stdin): return `eof_default` when the caller says a
      default is safe, otherwise stop cleanly. Never silently take a destructive
      action because there was no input.
    - Ctrl-C: stop cleanly with EXIT_INTERRUPT.
    """
    from colors import C, err
    try:
        return input(prompt_text)
    except EOFError:
        if eof_default is not None:
            log("INFO", f"{eof_message} - using default {eof_default!r}",
                module=_caller_module())
            return eof_default
        print()
        print(err(eof_message))
        print(f"  {C.DIM}this prompt needs a terminal: run it interactively or pass "
              f"the arguments on the command line{C.NC}")
        log("ERROR", eof_message, module=_caller_module())
        raise CleanExit(eof_code, eof_message) from None
    except KeyboardInterrupt:
        print()
        log("INFO", "interrupted at a prompt (Ctrl-C)", module=_caller_module())
        raise CleanExit(EXIT_INTERRUPT, "interrupted") from None


def guard(func, *args, **kwargs) -> int:
    """Run an entry point and turn every outcome into a clean exit code.

    Wraps the whole run so a user never sees a raw traceback: the traceback goes
    to the log, the screen gets one line plus where to find the details.
    """
    from colors import C, err, warn
    try:
        result = func(*args, **kwargs)
        return int(result) if isinstance(result, int) else EXIT_OK
    except CleanExit as exc:
        if exc.message and exc.code != EXIT_OK:
            log("INFO", f"stopping: {exc.message}", module="guard")
        return exc.code
    except KeyboardInterrupt:
        print()
        print(warn("Interrupted - nothing further was changed."))
        log("INFO", "interrupted by user (Ctrl-C)", module="guard")
        return EXIT_INTERRUPT
    except BrokenPipeError:
        # piping into `head`/`less`: not an error, just close quietly
        log("DEBUG", "broken pipe (output closed early)", module="guard")
        return EXIT_OK
    except SystemExit as exc:
        return int(exc.code or EXIT_OK)
    except Exception as exc:                                  # noqa: BLE001
        log("ERROR", "unhandled exception", exc=exc, module="guard")
        print()
        print(err(f"Something went wrong: {type(exc).__name__}: {exc}"))
        print(f"  {C.DIM}The full traceback is in the log: "
              f"{log_path()}{C.NC}")
        print(f"  {C.DIM}Show it with: python3 ul8.py logs --level ERROR --tail 40{C.NC}")
        if os.environ.get("UL8_DEBUG") in ("1", "true", "yes"):
            traceback.print_exception(type(exc), exc, exc.__traceback__)
        print(f"  {C.DIM}Nothing else was changed. Please report it with that log "
              f"entry.{C.NC}")
        return EXIT_CRASH


def _under_pytest() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


def _caller_module() -> str:
    """module:line of the first frame outside log_utils, so a log entry points
    at the code that failed instead of at log_error/record_display."""
    here = Path(__file__).resolve()
    frame = sys._getframe(1)
    while frame is not None:
        try:
            same = Path(frame.f_code.co_filename).resolve() == here
        except (OSError, ValueError):
            same = False
        if not same:
            return f"{Path(frame.f_code.co_filename).stem}:{frame.f_lineno}"
        frame = frame.f_back
    return "usbliter8"


def normalize_level(level: str) -> str:
    name = (level or "").strip().upper()
    name = LEVEL_ALIASES.get(name, name)
    return name if name in LEVELS else "WARN"


def configure(path: Path | str | None = None, level: str = "", enabled: bool | None = None) -> Path:
    """Point logging at a file and/or set the level. Returns the active path."""
    if path is not None:
        _state["path"] = Path(path).expanduser()
        _state["explicit"] = True
    env_path = os.environ.get("UL8_LOG_FILE")
    if path is None and env_path:
        _state["path"] = Path(env_path).expanduser()
        _state["explicit"] = True
    if level:
        _state["level"] = normalize_level(level)
    elif os.environ.get("UL8_LOG_LEVEL"):
        _state["level"] = normalize_level(os.environ["UL8_LOG_LEVEL"])
    if enabled is not None:
        _state["enabled"] = enabled
    if os.environ.get("UL8_NO_LOG") in ("1", "true", "yes"):
        _state["enabled"] = False
    return Path(_state["path"])


def log_path() -> Path:
    return Path(_state["path"])


def is_enabled() -> bool:
    if _state["failed"] or not _state["enabled"]:
        return False
    # a test run must not append to the repo's real log; tests opt in with an
    # explicit path or by setting UL8_LOG_FILE
    if _under_pytest() and not _state["explicit"]:
        return False
    return True


def _rotate(path: Path) -> None:
    if not path.exists() or path.stat().st_size < MAX_BYTES:
        return
    for index in range(KEEP_BACKUPS, 0, -1):
        older = path.with_suffix(path.suffix + f".{index - 1}") if index > 1 else path
        newer = path.with_suffix(path.suffix + f".{index}")
        if older.exists():
            newer.unlink(missing_ok=True)
            older.rename(newer)


def _write(line: str) -> None:
    """Append one line, rotating first. Never raises."""
    path = log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with LOG_LOCK:
            _rotate(path)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
    except OSError as exc:                       # read-only dir, full disk, ...
        _state["failed"] = True
        if not _state["announced"]:
            _state["announced"] = True
            sys.stderr.write(f"  [log] cannot write {path}: {exc} (logging disabled)\n")


def log(level: str, msg: str, *, module: str = "", exc: BaseException | None = None) -> str | None:
    """Write one entry. Returns the line written, or None when filtered out."""
    level = normalize_level(level)
    if not is_enabled():
        return None
    if LEVELS[level] < LEVELS[normalize_level(_state["level"])]:
        return None

    if not module:
        module = _caller_module()

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = str(msg).replace("\r", "").rstrip("\n")
    lines = [f"[{stamp}] [{level:<8}] [{module}] {text}"]
    if exc is not None:
        for chunk in traceback.format_exception(type(exc), exc, exc.__traceback__):
            for piece in chunk.rstrip("\n").split("\n"):
                lines.append(f"    {piece}")
    payload = "\n".join(lines) + "\n"
    _write(payload)
    return payload


def session_header(argv: list[str] | None = None, *, note: str = "") -> None:
    """One-time banner so an old log can be attributed to a run."""
    if not is_enabled():
        return
    try:
        import platform
        from datetime import timezone
        here = Path.cwd()
        try:
            import version as version_module
            build = version_module.describe()
        except Exception:                                      # noqa: BLE001
            build = ""
        log("INFO", "-" * 72, module="log_utils")
        log("INFO", f"usbliter8-arctic run start {build}".strip(), module="log_utils")
        log("INFO", f"argv: {' '.join(argv if argv is not None else sys.argv)}", module="log_utils")
        log("INFO", f"cwd: {here}  user: {os.environ.get('USER', '?')}", module="log_utils")
        log("INFO", f"python {platform.python_version()} on {platform.platform()} "
                    f"({datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})",
            module="log_utils")
        if note:
            log("INFO", note, module="log_utils")
    except Exception:                                        # noqa: BLE001 - logging must not raise
        pass


# ── explicit helpers ────────────────────────────────────────────────
def log_debug(msg: str, **kw) -> str | None:    return log("DEBUG", msg, **kw)
def log_info(msg: str, **kw) -> str | None:     return log("INFO", msg, **kw)
def log_step(msg: str, **kw) -> str | None:     return log("STEP", msg, **kw)
def log_warn(msg: str, **kw) -> str | None:     return log("WARN", msg, **kw)
def log_error(msg: str, **kw) -> str | None:    return log("ERROR", msg, **kw)

def log_exception(exc: BaseException, msg: str = "unhandled exception") -> None:
    log("ERROR", msg, exc=exc, module="excepthook")


def record_display(level: str, msg: str) -> None:
    """Hook used by colors.err()/colors.warn() so on-screen errors reach the log."""
    log(level, msg, module="display")


def install(level: str = "", path: Path | str | None = None) -> None:
    """Hook unhandled exceptions and start the log with a session header."""
    configure(path=path, level=level)
    if _state["installed"]:
        return
    _state["installed"] = True

    def _hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            log("INFO", "interrupted by user (Ctrl-C)", module="excepthook")
            sys.stderr.write("\n  interrupted\n")
            return
        error = exc if isinstance(exc, BaseException) else exc_type
        log("ERROR", "unhandled exception", exc=error, module="excepthook")
        sys.stderr.write(
            f"\n  Something went wrong: {exc_type.__name__}: {error}\n"
            f"    full traceback: {log_path()}\n"
            f"    show it with: python3 ul8.py logs --level ERROR --tail 40\n")
        if os.environ.get("UL8_DEBUG") in ("1", "true", "yes"):
            traceback.print_exception(exc_type, exc, tb)

    sys.excepthook = _hook

    def _thread_hook(args):
        if args.exc_value is not None:
            log("ERROR", f"unhandled exception in thread {args.thread.name}",
                exc=args.exc_value, module="excepthook")

    if hasattr(threading, "excepthook"):
        threading.excepthook = _thread_hook

    session_header()


# ── reader (used by `ul8.py logs`) ──────────────────────────────────
def read_log(path: Path | str | None = None, *, tail: int = 0, min_level: str = "",
             since: str = "", grep: str = "") -> list[str]:
    """Read the log, newest-last, optionally filtered.

    `tail` keeps the last N entries (an entry is a timestamped line plus its
    indented continuation lines, e.g. a traceback).
    """
    target = Path(path) if path else log_path()
    if not target.exists():
        return []
    entries: list[list[str]] = []
    with open(target, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("[") and "] [" in line:
                entries.append([line])
            elif entries:
                entries[-1].append(line)
            elif line.strip():
                entries.append([line])

    threshold = LEVELS[normalize_level(min_level)] if min_level else 0
    kept: list[list[str]] = []
    for entry in entries:
        head = entry[0]
        level = ""
        if head.startswith("[") and "] [" in head:
            level = head.split("] [", 1)[1].split("]", 1)[0].strip()
        if threshold and LEVELS.get(level, 0) < threshold:
            continue
        if since and head[1:20] < since:
            continue
        if grep and grep.lower() not in "\n".join(entry).lower():
            continue
        kept.append(entry)
    if tail and tail > 0:
        kept = kept[-tail:]
    return [line for entry in kept for line in entry]


def log_stats(path: Path | str | None = None) -> dict:
    """Counts per level + file size, for the log viewer header and --json."""
    target = Path(path) if path else log_path()
    stats = {"path": str(target), "exists": target.exists(), "bytes": 0, "entries": 0,
             "levels": {}, "first": "", "last": ""}
    if not target.exists():
        return stats
    stats["bytes"] = target.stat().st_size
    with open(target, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not (line.startswith("[") and "] [" in line):
                continue
            stats["entries"] += 1
            level = line.split("] [", 1)[1].split("]", 1)[0].strip()
            stats["levels"][level] = stats["levels"].get(level, 0) + 1
            stamp = line[1:20]
            if len(stamp) >= 19:
                if not stats["first"]:
                    stats["first"] = stamp
                stats["last"] = stamp
    return stats


# ── small utilities other modules import from here ──────────────────


def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0,
          exceptions: tuple = (Exception,)):
    """Decorator: retry a function with exponential backoff (logged on failure)."""
    import functools
    import time

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:                    # noqa: BLE001
                    last_exc = exc
                    if attempt < max_attempts:
                        log_warn(f"{func.__name__} attempt {attempt}/{max_attempts} failed: {exc}")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        log_error(f"{func.__name__} failed after {max_attempts} attempts: {exc}")
            raise last_exc
        return wrapper
    return decorator


def timeout(seconds: int, msg: str = "Operation timed out"):
    """Context manager that raises TimeoutError after `seconds` (SIGALRM)."""
    import signal
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        def _handler(_signum, _frame):
            raise TimeoutError(msg)

        old = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

    return _ctx()


def check_command(name: str) -> bool:
    """Check if a shell command exists in PATH."""
    import shutil
    return shutil.which(name) is not None


def check_tools(required: list) -> dict:
    """Check which tools from a list are available."""
    return {tool: check_command(tool) for tool in required}


def require_tool(name: str) -> str:
    """Get a tool's path or raise if it is missing."""
    import shutil
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Required tool not found: {name}")
    return path


def status_summary(results: dict) -> str:
    """Colored OK/FAIL summary for a dict of check results."""
    from colors import C
    parts = []
    for name, passed in results.items():
        color = C.GRN if passed else C.RED
        parts.append(f"  {color}{'✓' if passed else '✗'}{C.NC} {name}")
    return "\n".join(parts)


# ── `ul8.py logs` ───────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    """Print the log: `logs [--tail N] [--level ERROR] [--grep TEXT] [--clear] [--json]`."""
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="logs", description="show usbliter8-arctic's log file")
    ap.add_argument("--tail", type=int, default=60, help="show the last N entries (0 = all)")
    ap.add_argument("--level", default="", help="DEBUG|INFO|STEP|WARN|ERROR|CRITICAL")
    ap.add_argument("--since", default="", help="only entries at/after this timestamp prefix")
    ap.add_argument("--grep", default="", help="substring filter (case-insensitive)")
    ap.add_argument("--path", action="store_true", help="print the log path and exit")
    ap.add_argument("--clear", action="store_true", help="delete the log (and backups)")
    ap.add_argument("--json", action="store_true", help="machine-readable summary + entries")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    target = log_path()
    if args.path:
        print(target)
        return 0
    if args.clear:
        removed = clear_log(target)
        if args.json:
            print(json.dumps({"path": str(target), "cleared": removed}, indent=2))
        else:
            from colors import C
            print(f"  {C.GRN}✓{C.NC} {'cleared' if removed else 'nothing to clear'}: {target}")
        return 0

    stats = log_stats(target)
    lines = read_log(target, tail=args.tail, min_level=args.level,
                     since=args.since, grep=args.grep)

    if args.json:
        print(json.dumps({**stats, "shown": len(lines), "lines": lines}, indent=2))
        return 0

    from colors import C
    if not stats["exists"]:
        print(f"  {C.AMB}⚠{C.NC} no log yet at {target}")
        print(f"    {C.DIM}it is written on the first error/warning of any run{C.NC}")
        return 0

    counts = "  ".join(f"{lvl}:{n}" for lvl, n in sorted(stats["levels"].items()))
    print(f"\n  {C.FROST}{C.B}usbliter8.log{C.NC}  {C.DIM}{target}{C.NC}")
    print(f"  {C.DIM}{stats['bytes']:,} bytes · {stats['entries']} entries · "
          f"{stats['first']} → {stats['last']}{C.NC}")
    if counts:
        print(f"  {C.DIM}{counts}{C.NC}")
    print(f"  {C.DIM}{'─' * 60}{C.NC}")
    if not lines:
        print(f"  {C.DIM}no entries match the filter{C.NC}")
        return 1
    for line in lines:
        level = line.split("] [", 1)[1].split("]", 1)[0].strip() if line.startswith("[") and "] [" in line else ""
        color = _LEVEL_COLORS.get(level, "")
        print(f"  {color}{level:<8}{C.NC} {line}" if level else f"  {C.DIM}{line}{C.NC}")
    return 0


def clear_log(path: Path | str | None = None) -> bool:
    """Truncate the log (and its backups). Returns True when something was removed."""
    target = Path(path) if path else log_path()
    removed = False
    for candidate in [target] + [target.with_suffix(target.suffix + f".{i}") for i in
                                 range(1, KEEP_BACKUPS + 1)]:
        if candidate.exists():
            try:
                candidate.unlink()
                removed = True
            except OSError:
                pass
    return removed
