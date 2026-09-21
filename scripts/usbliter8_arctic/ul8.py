#!/usr/bin/env python3
"""ul8 — standalone launcher for usbliter8-arctic.

This file exists so the toolkit has a name of its own (`./ul8.py <verb>`) and so
`./W0lfSword ul8 <verb>` keeps working. The verbs themselves live in `cli.py`;
the interactive menu lives in `main.py`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cli          # noqa: E402  (needs the path above)
import log_utils    # noqa: E402


if __name__ == "__main__":
    log_utils.install()          # usbliter8.log + clean exits
    sys.exit(log_utils.guard(cli.main))
