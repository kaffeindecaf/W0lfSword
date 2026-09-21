"""Where the bundled binaries are, and how to run a command.

One home for three things that used to be copy-pasted per module:

- `tool(name)`: the path to use for a helper binary. The bundled `tools/` are
  macOS Mach-O, so on Linux/Windows they exist but cannot run: a usable binary
  on PATH wins there, and macOS prefers the bundled one.
- `tool_available(name)`: whether that binary can actually run here (used to
  decide between it and the built-in `img4wrap` codec).
- `run(...)`: one subprocess wrapper, so every module logs what it executed and
  every caller says only how talkative it wants to be.

Behaviour is the caller's: `DRY_RUN`/`VERBOSE` stay module globals
(`cfw_builder.DRY_RUN`, `boot_chain.DRY_RUN`), this module only does the work.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import log_utils
from colors import C

TOOLS_DIR = Path(__file__).resolve().parent / "tools"

def is_macho(path: Path) -> bool:
    """True when the file is a Mach-O binary (magic, thin or fat)."""
    try:
        magic = Path(path).read_bytes()[:4]
    except OSError:
        return False
    return magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                     b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def usable_path(name: str) -> str | None:
    """A path for this tool that can actually run here, or None.

    The bundled binary wins only when it runs on this platform, so Linux and
    Windows never exec a Mach-O by accident.
    """
    bundled = TOOLS_DIR / name
    if bundled.is_file() and (sys.platform == "darwin" or not is_macho(bundled)):
        return str(bundled)
    return shutil.which(name)


def tool(name: str) -> str:
    """Path to use for a helper binary: usable bundled copy, else PATH, else the name."""
    resolved = usable_path(name)
    if resolved:
        return resolved
    bundled = TOOLS_DIR / name
    return str(bundled) if bundled.is_file() else name


def tool_available(name: str) -> bool:
    """True when a tool can actually run here (not just exist on disk)."""
    return usable_path(name) is not None


def run(cmd: list[str], *, cwd: str | Path | None = None, env: dict | None = None,
        echo: bool = False, tail: int = 0) -> subprocess.CompletedProcess:
    """Run a command, capturing output; optionally echo it.

    `echo` prints the command line first, `tail` prints the last N stdout lines
    after it (that is how a build shows what a patching step said).
    """
    if echo:
        print(f"    {C.DIM}$ {' '.join(str(part) for part in cmd)}{C.NC}")
    log_utils.log_debug(f"run: {' '.join(str(part) for part in cmd)}", module="toolchain")

    run_env = {**os.environ, **env} if env else None
    result = subprocess.run([str(part) for part in cmd], cwd=cwd, capture_output=True,
                            text=True, env=run_env)
    if tail and result.stdout:
        for line in result.stdout.strip().splitlines()[-tail:]:
            print(f"      {C.DIM}{line}{C.NC}")
    return result
