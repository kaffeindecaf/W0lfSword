#!/usr/bin/env python3
"""K1.7 - prove that every command the unknown-SoC route prints exists.

The route (``unknown_soc_route()`` in ``W0lfSword``) tells a user with an
unmapped SoC which commands identify that device's offsets. It replaced a footer
that said ``kernelcache (pull + XPF)`` - ``pull`` has never been a subcommand of
``cmd_kernelcache``, so the only hint that existed for such a device led
straight into a usage error. A hint is code: it has to name commands that exist.

Usage:  scripts/check_route_commands.py <file-with-route-output> [W0lfSword]
        scripts/check_route_commands.py --selftest

Checks, per ``./W0lfSword <cmd> [<sub>]`` the route text names:
  1. ``<cmd>`` is a row in W0LF_COMMANDS (the registry is what dispatch mirrors).
  2. ``<sub>``, when named, is a case arm of the command's handler - following
     one delegation hop, because handlers that fan out (``cmd_experimental`` ->
     ``experimental_body``) keep their subcommands one level down.
Placeholder arguments (``<file.ipsw>``, ``[board]``) are ignored.

Exit 0 when everything resolves, 1 otherwise.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import cli_consistency as cc  # registry + case-block parsing live there
except ImportError as exc:  # pragma: no cover - only if the vendored script moved
    print(f"  ERROR: cannot import cli_consistency: {exc}")
    sys.exit(1)

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# ./W0lfSword <cmd> [<sub>]   - placeholders (<x>, [x]) are not commands
ROUTE_CALL = re.compile(r"\./W0lfSword\s+([a-z][a-z0-9-]*)(?:\s+([a-z][a-z0-9-]*))?")
CASE_HEADERS = ('case "$sub" in', 'case "$cmd" in')


def arm_patterns(lines, func, header):
    """Case-arm tokens of <func>'s first <header> block (empty when no block)."""
    out = set()
    for _, pattern in cc.case_block_for(lines, func + "() {", header=header):
        for alt in pattern.split("|"):
            alt = alt.strip().strip('"')
            if alt and alt != "*":
                out.add(alt)
    return out


def body_of(lines, func):
    start = None
    for idx, raw in enumerate(lines):
        if raw.startswith(func + "() {"):
            start = idx
            break
    if start is None:
        return ""
    for idx in range(start + 1, len(lines)):
        if lines[idx].rstrip("\n") == "}":
            return "".join(lines[start:idx])
    return "".join(lines[start:])


def handler_of(lines, name):
    """The function main()'s dispatch calls for <name> ('' when unresolved)."""
    arms = cc.case_block_for(lines, "main() {", header='case "$cmd" in')
    for i, (lineno, pattern) in enumerate(arms):
        alts = [a.strip().strip('"') for a in pattern.split("|")]
        if name not in alts:
            continue
        # the arm runs from its own line to the line before the next arm
        end = arms[i + 1][0] - 1 if i + 1 < len(arms) else len(lines)
        body = "".join(lines[lineno - 1:end])
        m = re.search(r"\b(cmd_[a-z0-9_]+|[a-z0-9_]+_body)\b", body)
        return m.group(1) if m else ""
    return ""


def sub_exists(lines, handler, sub, depth=2):
    """<sub> is an arm of <handler>, or of a function <handler> calls."""
    if not handler or depth <= 0:
        return False
    for header in CASE_HEADERS:
        if sub in arm_patterns(lines, handler, header):
            return True
    body = body_of(lines, handler)
    callees = set(re.findall(r"\b([a-z0-9_]+_body|cmd_[a-z0-9_]+)\b", body))
    callees.discard(handler)
    return any(sub_exists(lines, c, sub, depth - 1) for c in callees)


def check(cli_path, route_text):
    findings = []
    lines = open(cli_path, "r", encoding="utf-8").readlines()
    rows, _ = cc.parse_registry(lines)
    names = {row["name"] for row in rows}
    checked = 0
    for raw in route_text.splitlines():
        for cmd, sub in ROUTE_CALL.findall(ANSI.sub("", raw)):
            checked += 1
            if cmd not in names:
                findings.append(f"route names './W0lfSword {cmd}' - not a registry command")
                continue
            if not sub:
                continue
            handler = handler_of(lines, cmd)
            if not handler:
                findings.append(f"'{cmd}': could not resolve the handler from main()'s dispatch")
            elif not sub_exists(lines, handler, sub):
                findings.append(f"'{cmd} {sub}': '{handler}' has no '{sub}' case arm")
    return checked, findings


def selftest():
    """Feed the checker a synthetic CLI: every failure mode must be caught."""
    lines = [
        "W0LF_COMMANDS=(\n",
        '    "alpha|-|-|-|catalog|-|a|-|1|-"\n',
        '    "beta|-|-|-|catalog|-|b|-|1|-"\n',
        ")\n",
        "main() {\n",
        '    case "$cmd" in\n',
        "        alpha)\n",
        "            cmd_alpha \"${args[@]}\" ;;\n",
        "        beta)\n",
        "            cmd_beta \"${args[@]}\" ;;\n",
        "    esac\n",
        "}\n",
        "cmd_alpha() {\n",
        '    case "$sub" in\n',
        "        go|run)\n",
        "            : ;;\n",
        "    esac\n",
        "}\n",
        "cmd_beta() {\n",
        '    case "$sub" in\n',
        "        *)\n",
        "            beta_body \"$sub\" ;;\n",
        "    esac\n",
        "}\n",
        "beta_body() {\n",
        '    case "$sub" in\n',
        "        deep)\n",
        "            : ;;\n",
        "    esac\n",
        "}\n",
    ]
    tmp = os.path.join(HERE, ".route_selftest_cli")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    cases = [
        ("./W0lfSword alpha go", []),
        ("./W0lfSword alpha run <file>", []),
        ("./W0lfSword beta deep", []),                 # one delegation hop
        ("./W0lfSword gamma go", ["registry"]),        # unknown command
        ("./W0lfSword alpha pull", ["case arm"]),      # the K1.7 bug itself
        ("./W0lfSword beta nope", ["case arm"]),       # not in the delegated body
    ]
    failures = 0
    try:
        for route, expect in cases:
            _, findings = check(tmp, route)
            if bool(findings) != bool(expect):
                print(f"  selftest FAIL: {route!r} -> {findings} (expected {expect})")
                failures += 1
            elif expect and expect[0] not in findings[0]:
                print(f"  selftest FAIL: {route!r} -> {findings[0]} (expected '{expect[0]}')")
                failures += 1
    finally:
        os.unlink(tmp)
    if failures:
        print(f"selftest: {failures} mutation(s) slipped through")
        return 1
    print(f"selftest: all {len(cases)} mutations caught")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if len(sys.argv) < 2:
        print("usage: scripts/check_route_commands.py <route-output-file> [W0lfSword]")
        return 1
    route_path = sys.argv[1]
    cli_path = sys.argv[2] if len(sys.argv) > 2 else "W0lfSword"
    if not os.path.isfile(route_path) or not os.path.isfile(cli_path):
        print(f"  ERROR: missing input ({route_path} / {cli_path})")
        return 1
    with open(route_path, "r", encoding="utf-8") as fh:
        route_text = fh.read()
    checked, findings = check(cli_path, route_text)
    for f in findings:
        print(f"  ERROR: {f}")
    print(f"route commands: {checked} checked, {len(findings)} findings")
    if checked == 0:
        print("  ERROR: the route text named no ./W0lfSword command at all")
        return 1
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
