"""One CLI dispatcher for the whole toolkit.

`main.py` is the interactive TUI (menu, build/flash/boot flows, the banner).
`ul8.py` is a three-line shim that calls this module, because the standalone
launcher name is what W0lfSword and the docs use.

Everything a command line can ask for is registered exactly once, in `VERBS`
below: the verb, a one-line description, the features it needs (`deps.py` maps
those to packages) and the handler. The help text, the unknown-verb message and
the dependency gate all read from that one table, which is why there is no
second list to drift out of sync (that drift is how `ul8.py version` and
`main.py build` ended up advertised but not dispatched).

Adding a verb: write the handler, add one row to `VERBS`, done.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

import log_utils
from colors import err, info

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# ── handlers ───────────────────────────────────────────────────────
# Signature: (profile: str, extra: list[str]) -> int | None
# `profile` is the first positional after the verb, `extra` everything after it
# (so a wrapped tool's own flags survive untouched).

def _menu(profile: str, extra: list[str]) -> None:
    import main
    main.menu()


def _guided(profile: str, extra: list[str]) -> None:
    import main
    main.menu_configure()


def _pwn(profile: str, extra: list[str]) -> None:
    import pwn_utils
    pwn_utils.print_device_status()


def _health(profile: str, extra: list[str]) -> None:
    import hardware_guide
    hardware_guide.run_health_check()


def _offsets(profile: str, extra: list[str]) -> None:
    import device_offsets
    for entry in device_offsets.list_offset_files():
        icon = "✓" if entry["status"] == "ready" else "⚠"
        print(f"  {icon} {entry['device']} ({entry['model']}) — "
              f"iOS {entry['ios']} [{entry['soc']}]  {entry['passed']} patches")


def _coverage(profile: str, extra: list[str]) -> None:
    import profile_gen
    profile_gen.cmd_coverage(json_out="--json" in extra)


def _gaps(profile: str, extra: list[str]) -> None:
    import profile_gen
    profile_gen.cmd_gaps(json_out="--json" in extra)


def _preflight(profile: str, extra: list[str]) -> int:
    import preflight
    argv = ([profile] if profile else []) + extra
    return preflight.main(argv or None) or 0


def _audit(profile: str, extra: list[str]) -> int:
    argv = ([profile] if profile else []) + extra
    if len(argv) < 2:
        print(err("usage: audit <make_cfw.py> <profile.yaml>"))
        return log_utils.EXIT_BLOCKED      # a usage error, same code argparse uses
    import source_audit
    return source_audit.main(argv) or 0


def _fetch(profile: str, extra: list[str]) -> int:
    import fetch_components
    return fetch_components.main(extra) or 0


def _migrate(profile: str, extra: list[str]) -> int:
    import migrate
    return migrate.cli_main(([profile] if profile else []) + extra) or 0


def _build(profile: str, extra: list[str]) -> None:
    import main
    main.menu_build()


def _flash(profile: str, extra: list[str]) -> None:
    import main
    main.menu_flash()


def _boot(profile: str, extra: list[str]) -> None:
    import main
    main.menu_normal_boot()


def _sshrd(profile: str, extra: list[str]) -> None:
    import main
    main.menu_sshrd()


def _postboot(profile: str, extra: list[str]) -> None:
    import main
    main.menu_postboot()


def _net(profile: str, extra: list[str]) -> None:
    from boot_chain import setup_usb_network
    setup_usb_network()


def _vnc(profile: str, extra: list[str]) -> None:
    from boot_chain import setup_vnc
    setup_vnc()


def _ssh(profile: str, extra: list[str]) -> None:
    from boot_chain import ssh_connect
    ssh_connect()


def _explain(profile: str, extra: list[str]) -> None:
    from boot_chain import explain_usbliter8
    explain_usbliter8()


def _contribute(profile: str, extra: list[str]) -> int:
    import contribute
    return contribute.cli(([profile] if profile else []) + extra) or 0


def _deps(profile: str, extra: list[str]) -> int:
    import deps
    return 0 if deps.install_dependencies() else log_utils.EXIT_ERROR


def _share(profile: str, extra: list[str]) -> int:
    import share
    return share.cli(([profile] if profile else []) + extra) or 0


def _logs(profile: str, extra: list[str]) -> int:
    return log_utils.main(_argv_after("logs")) or 0


def _version(profile: str, extra: list[str]) -> int:
    import version
    return version.main(_argv_after("version")) or 0


Handler = Callable[[str, list[str]], "int | None"]

# verb -> (description, handler)
VERBS: dict[str, tuple[str, Handler]] = {
    "menu": ("interactive menu (default)", _menu),
    "guided": ("guided setup: wire, flash, first PWN", _guided),
    "pwn": ("show the connected device and its DFU state", _pwn),
    "health": ("environment + hardware health check", _health),
    "doctor": ("alias for health", _health),
    "offsets": ("list offset profiles and their patch counts", _offsets),
    "coverage": ("offset coverage matrix (--json to pipe)", _coverage),
    "gaps": ("which profile sections still need offsets", _gaps),
    "preflight": ("verify a profile against the real component bytes", _preflight),
    "verify": ("alias for preflight", _preflight),
    "audit": ("audit a profile against its upstream script", _audit),
    "fetch": ("fetch components out of an IPSW", _fetch),
    "migrate": ("carry offsets across beta builds", _migrate),
    "build": ("build a CFW from an IPSW + profile", _build),
    "flash": ("restore the built CFW to the device", _flash),
    "boot": ("normal boot via pwned DFU", _boot),
    "sshrd": ("boot the SSHRD ramdisk", _sshrd),
    "net": ("bring up the USB network", _net),
    "vnc": ("start VNC over USB", _vnc),
    "ssh": ("ssh into the device", _ssh),
    "postboot": ("post-boot setup on the device", _postboot),
    "explain": ("explain the exploit chain step by step", _explain),
    "contribute": ("contribute an offset profile (new/status/pr)", _contribute),
    "deps": ("check dependencies and offer to install what is missing", _deps),
    "share": ("send this device's verified data back (status/preview/send)", _share),
    "logs": ("read usbliter8.log (--tail/--level/--grep/--json)", _logs),
    "version": ("print version, commit and python", _version),
}

ALIASES = {"setup": "guided", "hw": "guided", "normal": "boot"}


def verb_list() -> list[str]:
    return sorted(VERBS)


def _argv_after(verb: str) -> list[str]:
    """Raw argv after a subcommand verb, so its own options pass through intact."""
    argv = sys.argv[1:]
    if verb in argv:
        return argv[argv.index(verb) + 1:]
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ul8",
        description="usbliter8-arctic — tethered iOS 27 jailbreak toolkit for A12/A13",
        epilog="verbs: " + ", ".join(verb_list()),
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="simulate without modifying files")
    parser.add_argument("--no-deps", action="store_true",
                        help="skip the dependency check (nothing is installed)")
    parser.add_argument(
        "command", nargs="?", default="menu",
        help="what to do (default: menu). One of: " + ", ".join(verb_list()),
    )
    parser.add_argument("profile", nargs="?",
                        help="arguments for the verb (e.g. a profile path)")
    # parse_known_args: flags meant for the wrapped tool (--json, --fetch,
    # --record, --quiet) must pass through instead of being rejected here.
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one verb. `guard()` at the entry point turns anything raised into a code."""
    args, extra = build_parser().parse_known_args(argv)

    verb = ALIASES.get(args.command, args.command)
    if verb not in VERBS:
        print(err(f"unknown subcommand '{args.command}'"))
        print(info("try: " + ", ".join(verb_list())))
        return log_utils.EXIT_ERROR

    if not args.no_deps and os.environ.get("UL8_NO_DEPS") not in ("1", "true", "yes"):
        import deps
        deps.ensure_for_command(verb, quiet="--json" in extra)

    if args.dry_run:
        import boot_chain
        import cfw_builder
        cfw_builder.DRY_RUN = True
        boot_chain.DRY_RUN = True

    log_utils.log_info(f"verb: {verb}", module="cli")
    result = VERBS[verb][1](args.profile or "", extra)
    return log_utils.EXIT_OK if result is None else int(result)


if __name__ == "__main__":
    log_utils.install()
    sys.exit(log_utils.guard(main))
