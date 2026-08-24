"""Logging and retry utilities for usbliter8-arctic.

Provides thread-safe logging, retry decorator, timeout context manager,
and structured status reporting.
"""

import functools
import signal
import sys
import time
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable

from colors import C, err as _err, warn as _warn, info as _info, ok as _ok

LOG_LOCK = threading.Lock()
LOG_FILE = Path(__file__).parent / "session.log"

_log_initialized = False


def _init_log():
    global _log_initialized
    if not _log_initialized:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _log_initialized = True


def log(level: str, msg: str):
    """Write a timestamped log entry (thread-safe)."""
    _init_log()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level:5s}] {msg}\n"
    with LOG_LOCK:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line)
        except OSError:
            # fallback to stderr if log file is unwritable
            sys.stderr.write(line)


def log_info(msg: str):  log("INFO", msg)
def log_warn(msg: str):  log("WARN", msg)
def log_error(msg: str): log("ERROR", msg)
def log_step(msg: str):  log("STEP", msg)


def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0,
          exceptions: tuple = (Exception,)):
    """Decorator: retry a function with exponential backoff."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_attempts:
                        log_warn(f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        log_error(f"{func.__name__} failed after {max_attempts} attempts: {e}")
            raise last_exc
        return wrapper
    return decorator


@contextmanager
def timeout(seconds: int, msg: str = "Operation timed out"):
    """Context manager that raises TimeoutError after `seconds`."""
    def _handler(signum, frame):
        raise TimeoutError(msg)

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def check_command(name: str) -> bool:
    """Check if a shell command exists in PATH."""
    import shutil
    return shutil.which(name) is not None


def check_tools(required: list[str]) -> dict[str, bool]:
    """Check which tools from a list are available."""
    return {t: check_command(t) for t in required}


def require_tool(name: str) -> str:
    """Get tool path or raise if not found."""
    import shutil
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Required tool not found: {name}")
    return path


def status_summary(results: dict[str, bool]) -> str:
    """Return a colored OK/FAIL summary for a dict of check results."""
    parts = []
    for name, ok in results.items():
        color = C.GRN if ok else C.RED
        icon = "✓" if ok else "✗"
        parts.append(f"  {color}{icon}{C.NC} {name}")
    return "\n".join(parts)
