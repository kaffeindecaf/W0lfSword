#!/usr/bin/env python3
"""ul8 — standalone usbliter8-arctic launcher."""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        prog="ul8",
        description="usbliter8-arctic — iOS kernel exploit hub (standalone)",
    )
    p.add_argument("--dry-run", action="store_true", help="Simulate without modifying files")
    p.add_argument(
        "command",
        nargs="?",
        default="menu",
        help="Subcommand: menu, pwn, offsets, explain, health, deps",
    )
    args = p.parse_args()

    if args.dry_run:
        import cfw_builder
        import boot_chain
        cfw_builder.DRY_RUN = True
        boot_chain.DRY_RUN = True

    if args.command == "menu":
        import main
        main.menu()
    elif args.command == "pwn":
        import pwn_utils
        pwn_utils.print_device_status()
    elif args.command == "offsets":
        import device_offsets
        for f in device_offsets.list_offset_files():
            icon = "✓" if f["status"] == "ready" else "⚠"
            print(
                f"  {icon} {f['device']} ({f['model']}) — "
                f"iOS {f['ios']} [{f['soc']}]  {f['passed']} patches"
            )
    elif args.command == "explain":
        import boot_chain
        boot_chain.explain_usbliter8()
    elif args.command == "health":
        import hardware_guide
        hardware_guide.run_health_check()
    elif args.command == "deps":
        from deps import install_dependencies
        install_dependencies()
    else:
        import main
        main.menu()
