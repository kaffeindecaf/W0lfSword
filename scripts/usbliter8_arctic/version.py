"""Single source of truth for the toolkit version.

`VERSION` is the human-facing number; `describe()` adds the commit the checkout
is on, so a log entry or a bug report says which build produced it. Everything
degrades to the static number when git is unavailable (zip download, no repo).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
import log_utils

VERSION = "0.2.0-beta"
NAME = "usbliter8-arctic"
REPO_URL = "https://github.com/kaffeindecaf/usbliter8-arctic"


def commit(repo_root: Path | None = None) -> str:
    """Short commit hash of this checkout, plus '-dirty' when files changed."""
    root = Path(repo_root) if repo_root else Path(__file__).parent
    try:
        out = subprocess.run(["git", "describe", "--always", "--dirty", "--abbrev=7"],
                             cwd=root, capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def describe(repo_root: Path | None = None) -> str:
    """'0.2.0-beta (fac9be2-dirty)' or just the version."""
    sha = commit(repo_root)
    return f"{VERSION} ({sha})" if sha else VERSION


def info(repo_root: Path | None = None) -> dict:
    """Structured version data for `version --json` and the log header."""
    import platform

    return {
        "name": NAME,
        "version": VERSION,
        "commit": commit(repo_root),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "repo": REPO_URL,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    from colors import C, key_value

    ap = argparse.ArgumentParser(prog="version", description="show version information")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    data = info()
    if args.json:
        import json
        print(json.dumps(data, indent=2))
        return 0

    print(f"\n  {C.FROST}{C.B}{data['name']}{C.NC} {C.SNOW}{data['version']}{C.NC}"
          f" {C.DIM}{data['commit']}{C.NC}")
    print(key_value("python", data["python"]))
    print(key_value("platform", data["platform"]))
    try:
        import log_utils
        print(key_value("log", str(log_utils.log_path())))
    except Exception:                                          # noqa: BLE001
        pass
    print()
    return 0


if __name__ == "__main__":
    import sys

    import log_utils

    log_utils.install()
    sys.exit(log_utils.guard(main))
