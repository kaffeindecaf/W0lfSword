#!/usr/bin/env python3
"""Import Liter8 fixtures into usbliter8-arctic offset profiles.

Xplo8E/Liter8 (`fixtures/<build>/<board>/<resolver>.json`) publishes reviewed
resolver oracles for usbliter8 devices: for every patch it records the offset,
the ORIGINAL bytes and the replacement bytes it verified, plus the component
sha256. Those are exactly the inputs an offset profile needs, so this module
maps Liter8 patch ids onto our entry names, refuses anything whose payload
does not match our known semantics, and writes a profile where everything
unsupported stays `pending: true`.

Rules enforced (see RULES below):

* an entry is only filled when EVERY upstream patch id of the rule exists, the
  sites are contiguous, and the concatenated replacement equals the payload our
  profiles use for that entry (so a wrong mapping cannot rewrite a patch site);
* PC-relative sites (adrp/add redirects) and string slots are class-checked
  instead of byte-checked, and their bytes are copied from the fixture because
  the correct immediate depends on the site's own address;
* `--verify-components DIR` re-reads the fetched raw component and re-checks
  every mapped site's original bytes against the real binary (this is how the
  n104 24A435 fixtures were confirmed against the shipped 24A437 components).

Usage:
  python3 liter8_import.py --fixtures <Liter8>/fixtures --build 24A435 --board n104ap \\
      --model iPhone12,1 --ios 27.0 --profile-build 24A437 \\
      --verify-components research/extracted/iPhone121_27.0_24A437 [--write]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from colors import C, err, info, ok, section, warn
from device_offsets import SENTINEL, dump_profile_yaml, pending_entries, validate_offsets
from profile_gen import DEVICE_DB
import log_utils

ROOT = Path(__file__).parent
OFFSETS_DIR = ROOT / "offsets"
DEFAULT_SCHEMA = OFFSETS_DIR / "iPhone12,3_27.0b3.yaml"

# Our canonical payloads: an import is accepted only if the upstream bytes match.
P_MOV0_RET = "000080d2c0035fd6"          # mov x0,#0; ret
P_MOVW0_RET = "00008052c0035fd6"         # mov w0,#0; ret
P_MOV1_RET = "200080d2c0035fd6"          # mov x0,#1; ret
P_NOP = "1f2003d5"                       # nop
P_MOVW1 = "20008052"                     # mov w0,#1
P_CMP = "1f00006b"                       # cmp w0, w0 (never equal)
P_AMFI = "5f2403d5200080d2430000b4600000f9c0035fd6"  # BTI c; mov x0,#1; cbz; str; ret
P_IDENTITY = "/PATCHED_ARM64_T8030"

# payload "kind": exact bytes, PC-relative immediate, or ASCII string
K_EXACT, K_ADRP, K_ADD, K_STR = "exact", "adrp", "add", "string"


@dataclass
class Rule:
    """One profile entry, built from one or more upstream patch ids."""
    section: str                 # profile section
    path: str                    # entry path: "name" (list/dict) or "daemon.name"
    fixture: str                 # Liter8 fixture resolver to read
    ids: list[str]               # upstream patch ids, in ascending offset order
    payload: str = ""            # expected concatenated replacement (exact kind)
    kind: str = K_EXACT
    note: str = ""
    string: str = ""             # override for K_STR (our boot-args convention)


# ── the mapping table ──────────────────────────────────────────────
RULES: list[Rule] = [
    # iBSS / iBEC (the n104 and d421 iBSS and iBEC payloads are the same image;
    # see --ibec-from-ibss)
    Rule("ibss", "image4_validate_nop", "ibss-validate-asn1", ["ibss.validate-asn1.branch"], P_NOP),
    Rule("ibss", "image4_validate_ret0", "ibss-validate-asn1", ["ibss.validate-asn1.result"], P_MOV0_RET[:8]),
    Rule("ibss", "boot_args_adrp", "ibss-ramdisk", ["ibss.boot-args.adrp"], kind=K_ADRP,
         note="PC-relative: value copied from the fixture"),
    Rule("ibss", "boot_args_add", "ibss-ramdisk", ["ibss.boot-args.add"], kind=K_ADD,
         note="PC-relative: value copied from the fixture"),
    Rule("ibss", "boot_args_string", "ibss-ramdisk", ["ibss.boot-args.string"], kind=K_STR,
         string="-v wdt=-1 rd=md0 -restore",
         note="string slot; keeps our chain's boot-args convention"),

    # TXM
    Rule("txm", "query_module0", "txm-restore", ["txm.query-module.0"], "000080d2"),
    Rule("txm", "query_module1", "txm-restore", ["txm.query-module.1"], "000080d2"),
    Rule("txm", "query_module2", "txm-restore", ["txm.query-module.2"], "000080d2"),
    Rule("txm", "validate_constraints_sig_nop1", "txm-restore",
         ["txm.constraints.signature-type-range"], P_NOP),
    Rule("txm", "validate_constraints_sig_nop2", "txm-restore",
         ["txm.constraints.signature-type-null"], P_NOP),
    Rule("txm", "allowed_before_secure_channel", "txm-boot",
         ["txm.secure-channel.return-one", "txm.secure-channel.return"], P_MOV1_RET),

    # kernel
    Rule("kernel", "USB Restricted Mode bypass", "kernel-boot-policy",
         ["kernel.usb.restore-mode-result", "kernel.usb.restore-mode-return"], P_MOV1_RET),
    Rule("kernel", "Sandbox file_check_mmap", "kernel-sandbox",
         ["kernel.sandbox.file-check-mmap.result", "kernel.sandbox.file-check-mmap.return"], P_MOV0_RET),
    Rule("kernel", "Sandbox mount_check_mount", "kernel-sandbox",
         ["kernel.sandbox.mount-check-mount.result", "kernel.sandbox.mount-check-mount.return"], P_MOV0_RET),
    Rule("kernel", "Sandbox remount", "kernel-sandbox",
         ["kernel.sandbox.mount-check-remount.result", "kernel.sandbox.mount-check-remount.return"], P_MOV0_RET),
    Rule("kernel", "Sandbox umount", "kernel-sandbox",
         ["kernel.sandbox.mount-check-unmount.result", "kernel.sandbox.mount-check-unmount.return"], P_MOV0_RET),
    Rule("kernel", "Sandbox vnode_check_rename", "kernel-sandbox",
         ["kernel.sandbox.vnode-check-rename.result", "kernel.sandbox.vnode-check-rename.return"], P_MOV0_RET),
    Rule("kernel", "AMFI trust everything", "kernel-restore",
         [f"kernel.amfi.trust-cache.{i}" for i in range(5)], P_AMFI,
         note="full 5-instruction sequence, not just mov x0,#1; ret"),
    Rule("kernel", "Proc check launch constraints", "kernel-restore",
         ["kernel.amfi.launch-constraints.result", "kernel.amfi.launch-constraints.return"], P_MOVW0_RET),
    Rule("kernel", "PE i_can_has_debugger", "kernel-restore",
         ["kernel.debugger.result", "kernel.debugger.return"], P_MOV1_RET),
    Rule("kernel", "Post-validation bypass", "kernel-restore",
         ["kernel.amfi.post-validation.compare"], P_CMP),
    Rule("kernel", "Check dyld policy internal", "kernel-restore",
         ["kernel.amfi.dyld-policy.0"], P_MOVW1),
    Rule("kernel", "Check dyld policy internal (site 2)", "kernel-restore",
         ["kernel.amfi.dyld-policy.1"], P_MOVW1),
    Rule("kernel", "APFS mount SSV bypass", "kernel-restore",
         ["kernel.panic.root-snapshot"], P_NOP),
    Rule("kernel", "APFS seal_is_broken bypass", "kernel-restore",
         ["kernel.panic.seal-broken"], P_NOP),
    Rule("kernel", "BSD init rootvp bypass", "kernel-restore",
         ["kernel.panic.rootvp-authentication"], P_NOP),
    Rule("kernel", "Unencrypted data volume panic bypass", "kernel-restore",
         ["kernel.panic.unencrypted-data-volume"], P_NOP),
    Rule("kernel", "SEP panic check bypass", "kernel-sep",
         ["kernel.sep.panic-check.result", "kernel.sep.panic-check.return"], P_MOV0_RET),
    Rule("kernel", "SEP didTimeout bypass", "kernel-sep",
         ["kernel.sep.did-timeout.result", "kernel.sep.did-timeout.return"], P_MOV0_RET),
    Rule("kernel", "Kernel identity string 1", "kernel-restore",
         ["kernel.identity.0"], P_IDENTITY, kind=K_STR, string=P_IDENTITY),
    Rule("kernel", "Kernel identity string 2", "kernel-restore",
         ["kernel.identity.1"], P_IDENTITY, kind=K_STR, string=P_IDENTITY),

    # restore ramdisk payloads (inside the encrypted ramdisk; not byte-checkable)
    Rule("restoreramdisk", "asr_sig_bypass", "asr-signature",
         ["asr.signature-mismatch-branch"], P_NOP),
    Rule("restoreramdisk", "fdr_force_succeed", "restored-external-fdr",
         ["restored-external.fdr-result"], "000080d2"),

    # daemons (rootfs payloads; not byte-checkable)
    Rule("daemons", "coreauthd.anti_sep_crash", "coreauthd",
         ["coreauthd.dto-ratchet.start-controller"], P_NOP),
    Rule("daemons", "ctkd.anti_sep_crash_ret0", "ctkd",
         ["ctkd.sep-key-server.return-nil"], "000080d2"),
    Rule("daemons", "ctkd.anti_sep_crash_ret", "ctkd",
         ["ctkd.sep-key-server.return"], "c0035fd6"),
    Rule("daemons", "mobileactivationd.should_hactivate", "mobileactivationd",
         ["mobileactivationd.should-hactivate"], P_MOVW1),
    Rule("daemons", "mobileactivationd.get_activation_state_nop1", "mobileactivationd",
         ["mobileactivationd.activation-state.migration-gate"], P_NOP),
    Rule("daemons", "mobileactivationd.get_activation_state_adrp", "mobileactivationd",
         ["mobileactivationd.activation-state.adrp"], kind=K_ADRP),
    Rule("daemons", "mobileactivationd.get_activation_state_add", "mobileactivationd",
         ["mobileactivationd.activation-state.add"], kind=K_ADD),
    Rule("daemons", "mobileactivationd.get_activation_state_nop2", "mobileactivationd",
         ["mobileactivationd.activation-state.dereference"], P_NOP),
]

SECTION_COMPONENT = {"ibss": "iBSS", "ibec": "iBEC", "txm": "TXM"}
VERIFIABLE_SECTIONS = tuple(SECTION_COMPONENT)


# ── fixture access ──────────────────────────────────────────────────

@dataclass
class Fixture:
    resolver: str
    component: str
    size: int
    sha256: str
    patches: dict[str, dict] = field(default_factory=dict)  # id -> {offset, original, replacement}


def load_fixtures(fixtures_root: Path, build: str, board: str) -> dict[str, Fixture]:
    out: dict[str, Fixture] = {}
    for path in sorted(fixtures_root.glob(f"{build}/{board}/*.json")):
        data = json.loads(path.read_text())
        target = data.get("target", {})
        if target.get("board") != board:
            continue
        fx = Fixture(resolver=data.get("resolver", ""), component=target.get("component", ""),
                     size=data.get("expectedSize", 0), sha256=data.get("sha256", ""))
        for patch in data.get("expectedPatches", []):
            fx.patches[patch["id"]] = {
                "offset": int(patch["offset"]),
                "original": bytes.fromhex(patch["originalBytes"]),
                "replacement": bytes.fromhex(patch["replacementBytes"]),
            }
        out[fx.resolver] = fx
    return out


def check_contiguous(offsets: list[int], lengths: list[int],
                     word_aligned: bool = True) -> bool:
    """True when the listed sites are adjacent, so one write covers them all.

    `word_aligned` additionally requires every run to be a whole number of
    4-byte instructions — true for opcode runs, false for string slots.
    """
    for i in range(len(offsets) - 1):
        if offsets[i] + lengths[i] != offsets[i + 1]:
            return False
    if not word_aligned:
        return True
    return all(length % 4 == 0 for length in lengths)


@dataclass
class Imported:
    rule: Rule
    offset: int
    value: str
    original: bytes
    upstream_ids: list[str]
    length: int = 0


def apply_rule(rule: Rule, fixtures: dict[str, Fixture]) -> tuple[Imported | None, str]:
    """Resolve one rule against the fixtures. Returns (entry, reason_if_skipped)."""
    fx = fixtures.get(rule.fixture)
    if fx is None:
        return None, f"fixture {rule.fixture!r} not present for this build/board"
    missing = [pid for pid in rule.ids if pid not in fx.patches]
    if missing:
        return None, f"upstream id missing: {', '.join(missing)}"

    patches = [fx.patches[pid] for pid in rule.ids]
    offsets = [p["offset"] for p in patches]
    lengths = [len(p["replacement"]) for p in patches]
    if not check_contiguous(offsets, lengths, word_aligned=(rule.kind != K_STR)):
        return None, "upstream sites are not contiguous — not a single write"

    upstream = b"".join(p["replacement"] for p in patches)
    original = b"".join(p["original"] for p in patches)

    if rule.kind == K_EXACT:
        if upstream.hex() != rule.payload:
            return None, (f"payload mismatch: upstream {upstream.hex()} != canonical {rule.payload}")
        value = rule.payload
    elif rule.kind in (K_ADRP, K_ADD):
        value = upstream.hex()
    elif rule.kind == K_STR:
        if rule.payload:
            if upstream != rule.payload.encode():
                return None, f"string mismatch: upstream {upstream!r}"
        if len(rule.string.encode()) > len(upstream):
            return None, (f"string {rule.string!r} does not fit the slot "
                          f"({len(upstream)} B)")
        value = rule.string
    else:  # pragma: no cover
        return None, f"unknown kind {rule.kind}"

    return Imported(rule=rule, offset=offsets[0], value=value, original=original,
                    upstream_ids=list(rule.ids), length=len(upstream)), ""


def verify_against_component(imported: Imported, section: str, raw: bytes) -> str:
    """Re-check the fixture's original bytes in a fetched component.

    Returns "bytes" when the real binary still holds the recorded pre-patch
    bytes, "SHA-NOT-SAME-BUILD" when the site's bytes moved on, or
    "out-of-range" when the offset is past the end of the image.
    """
    end = imported.offset + len(imported.original)
    if end > len(raw):
        return "out-of-range"
    return "bytes" if raw[imported.offset:end] == imported.original else "bytes-differ"


# ── profile assembly ────────────────────────────────────────────────

def _pending_clone(entry: dict) -> dict:
    out = {k: v for k, v in entry.items() if k not in ("va",)}
    out["offset"] = SENTINEL
    out["pending"] = True
    return out


def build_profile(schema: dict, model: str, ios_tag: str, build: str,
                  imported: list[Imported], verification: dict[str, str],
                  sources: dict) -> dict:
    dev = DEVICE_DB.get(model, {"name": model, "soc": "?", "board": "?", "apticket": "?"})
    by_path = {}
    for imp in imported:
        by_path[(imp.rule.section, imp.rule.path)] = imp

    profile = {
        "device": dev["name"],
        "model": model,
        "ios_version": ios_tag,
        "build": build,
        "soc": dev["soc"],
        "board": dev["board"],
        "apticket": dev["apticket"],
        "verification": "imported",
        "sources": sources,
        "patches": {},
    }

    for sec, data in schema["patches"].items():
        if isinstance(data, list):
            entries = []
            for entry in data:
                name = entry.get("name", "")
                imp = by_path.get((sec, name))
                if imp is None:
                    entries.append(_pending_clone(entry))
                    continue
                new = {k: v for k, v in entry.items() if k not in ("va", "pending")}
                new["offset"] = imp.offset
                new["value"] = imp.value
                new["source"] = f"liter8:{imp.rule.fixture}:{'+'.join(imp.upstream_ids)}"
                if imp.original:
                    new["original"] = imp.original.hex()
                if verification.get(f"{sec}:{name}"):
                    new["verified"] = verification[f"{sec}:{name}"]
                entries.append(new)
            profile["patches"][sec] = entries

        elif isinstance(data, dict) and any(
                isinstance(v, dict) and "offset" in v for v in data.values()):
            section_entries = {}
            for name, entry in data.items():
                imp = by_path.get((sec, name))
                if imp is None:
                    section_entries[name] = _pending_clone(entry)
                    continue
                new = {k: v for k, v in entry.items() if k not in ("pending",)}
                new["offset"] = imp.offset
                new["value"] = imp.value
                new["source"] = f"liter8:{imp.rule.fixture}:{'+'.join(imp.upstream_ids)}"
                if verification.get(f"{sec}:{name}"):
                    new["verified"] = verification[f"{sec}:{name}"]
                section_entries[name] = new
            profile["patches"][sec] = section_entries

        elif isinstance(data, dict) and any(
                isinstance(v, dict) and any(isinstance(s, dict) and "offset" in s
                                            for s in v.values()) for v in data.values()):
            nested = {}
            for group, entries in data.items():
                group_out = {}
                for name, entry in entries.items():
                    path = f"{group}.{name}"
                    imp = by_path.get((sec, path))
                    if imp is None:
                        group_out[name] = _pending_clone(entry)
                        continue
                    new = {k: v for k, v in entry.items() if k not in ("pending",)}
                    new["offset"] = imp.offset
                    new["value"] = imp.value
                    new["source"] = f"liter8:{imp.rule.fixture}:{'+'.join(imp.upstream_ids)}"
                    if verification.get(f"{sec}:{path}"):
                        new["verified"] = verification[f"{sec}:{path}"]
                    group_out[name] = new
                nested[group] = group_out
            profile["patches"][sec] = nested

        else:  # structural flags (devicetree / userland)
            profile["patches"][sec] = dict(data)

    return profile


def upstream_only(fixtures: dict[str, Fixture], imported: list[Imported]) -> list[tuple[str, str, int]]:
    """Fixture sites no rule consumed: (resolver, patch id, offset)."""
    used = {(imp.rule.fixture, pid) for imp in imported for pid in imp.upstream_ids}
    out = []
    for fx in fixtures.values():
        for pid, patch in fx.patches.items():
            if (fx.resolver, pid) not in used:
                out.append((fx.resolver, pid, patch["offset"]))
    return sorted(out, key=lambda t: (t[0], t[2]))


# ── CLI ────────────────────────────────────────────────────────────

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="liter8_import.py")
    p.add_argument("--fixtures", required=True, help="Liter8 fixtures directory")
    p.add_argument("--build", required=True, help="build id, e.g. 24A435")
    p.add_argument("--board", required=True, help="board, e.g. n104ap")
    p.add_argument("--model", required=True, help="device model, e.g. iPhone12,1")
    p.add_argument("--ios", required=True, help="iOS version tag, e.g. 27.0")
    p.add_argument("--profile-build", default="", help="build id to record in the profile")
    p.add_argument("--schema", default=str(DEFAULT_SCHEMA),
                   help="profile used as the entry-name/section-shape schema")
    p.add_argument("--verify-components", default="",
                   help="directory of fetched raw components (ibss.raw/ibec.raw/txm.raw)")
    p.add_argument("--ibec-from-ibss", action="store_true",
                   help="also fill the ibec section from the iBSS sites (only when the "
                        "iBSS and iBEC payloads are the same image)")
    p.add_argument("--write", action="store_true", help="write offsets/<Model>_<ios>.yaml")
    p.add_argument("--out", default="", help="explicit output path")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    fixtures_root = Path(args.fixtures)
    if not fixtures_root.is_dir():
        print(err(f"fixtures dir not found: {fixtures_root}"))
        return 2
    fixtures = load_fixtures(fixtures_root, args.build, args.board)
    if not fixtures:
        print(err(f"no fixtures for build {args.build} board {args.board}"))
        return 2

    print(section(f"Liter8 import — {args.model} {args.ios} ({args.build})"))
    for fx in sorted(fixtures.values(), key=lambda f: f.resolver):
        print(f"  {C.EYE}{fx.component:<28}{C.NC} {fx.resolver:<26} {fx.size:>10} B  "
              f"{len(fx.patches):>3} patches  {C.DIM}{fx.sha256[:16]}{C.NC}")
    print()

    imported: list[Imported] = []
    skipped: list[tuple[Rule, str]] = []
    for rule in RULES:
        imp, why = apply_rule(rule, fixtures)
        if imp is None:
            skipped.append((rule, why))
            continue
        imported.append(imp)
        print(f"  {C.GRN}✓{C.NC} {rule.section + '.' + rule.path:<52} "
              f"0x{imp.offset:X}  {imp.value[:48]}{'…' if len(imp.value) > 48 else ''}")

    ibec_from_ibss = args.ibec_from_ibss
    if ibec_from_ibss and args.verify_components:
        comp_dir = Path(args.verify_components)
        ibss_p, ibec_p = comp_dir / "ibss.raw", comp_dir / "ibec.raw"
        if ibss_p.exists() and ibec_p.exists():
            same = ibss_p.read_bytes() == ibec_p.read_bytes()
            if not same:
                print(warn("--ibec-from-ibss refused: fetched ibss.raw and ibec.raw differ"))
                ibec_from_ibss = False
            else:
                print(info("--ibec-from-ibss: fetched iBSS and iBEC payloads are byte-identical"))
        else:
            print(warn("--ibec-from-ibss refused: need ibss.raw and ibec.raw to prove identity"))
            ibec_from_ibss = False
    elif ibec_from_ibss:
        print(warn("--ibec-from-ibss without --verify-components: derivation is unverified"))

    if ibec_from_ibss:
        for rule in [r for r in RULES if r.section == "ibss"]:
            imp = next((i for i in imported if i.rule is rule), None)
            if imp is None:
                continue
            clone = Imported(Rule("ibec", rule.path, rule.fixture, rule.ids, rule.payload,
                                  kind=rule.kind, string=rule.string), imp.offset, imp.value,
                             imp.original, imp.upstream_ids, imp.length)
            imported.append(clone)
            print(f"  {C.GRN}✓{C.NC} ibec.{rule.path:<47} 0x{imp.offset:X}  "
                  f"{C.DIM}(from ibss — identical image){C.NC}")

    # byte verification against fetched components
    verification: dict[str, str] = {}
    if args.verify_components:
        comp_dir = Path(args.verify_components)
        print()
        print(section("Component verification"))
        for sec in VERIFIABLE_SECTIONS:
            raw_path = comp_dir / f"{sec}.raw"
            if not raw_path.exists():
                print(warn(f"  {sec}: {raw_path.name} not found — skipped"))
                continue
            raw = raw_path.read_bytes()
            for imp in [i for i in imported if i.rule.section == sec]:
                status = verify_against_component(imp, sec, raw)
                key = f"{sec}:{imp.rule.path}"
                verification[key] = status
                icon = C.GRN + "✓" if status == "bytes" else C.AMB + "⚠"
                print(f"  {icon}{C.NC} {sec}.{imp.rule.path:<44} 0x{imp.offset:X} "
                      f"{C.DIM}{status}{C.NC}")

    schema = yaml.safe_load(Path(args.schema).read_text())
    sources = {
        "upstream": "Xplo8E/Liter8",
        "fixture_path": f"fixtures/{args.build}/{args.board}",
        "build": args.build,
        "board": args.board,
        "component_sha256": {fx.component: fx.sha256 for fx in fixtures.values() if fx.sha256},
        "imported_entries": str(len(imported)),
    }
    if args.verify_components:
        sources["verified_against"] = Path(args.verify_components).name
    profile = build_profile(schema, args.model, args.ios, args.profile_build or args.build,
                            imported, verification, sources)

    out_path = Path(args.out) if args.out else OFFSETS_DIR / f"{args.model}_{args.ios}.yaml"
    report = ROOT / "research" / "work" / f"liter8_import_{args.model}_{args.ios}.md"

    print()
    print(section("Not imported"))
    for rule, why in skipped:
        if "payload mismatch" in why or "not contiguous" in why or "string" in why:
            print(f"  {C.AMB}!{C.NC} {rule.section + '.' + rule.path:<52} {C.DIM}{why}{C.NC}")
    extras = upstream_only(fixtures, imported)
    print(f"  {C.DIM}{len(extras)} upstream site(s) have no entry in our scheme "
          f"(persona/credential-manager/aks/developer-mode etc.){C.NC}")
    print()

    if not args.write:
        print(info(f"dry run — would write {out_path}"))
        print(info(f"report: {report}"))
        _write_report(report, args, fixtures, imported, skipped, extras, verification,
                      out_path, written=False)
        return 0

    dump_profile_yaml(profile, out_path)
    _write_report(report, args, fixtures, imported, skipped, extras, verification,
                  out_path, written=True)
    passed, failed, errors = validate_offsets(out_path)
    pend = pending_entries(out_path)
    print(ok(f"wrote {out_path.name} — {passed} valid, {failed} failed, {pend} pending"))
    for e in errors:
        print(f"    {C.RED}{e}{C.NC}")
    print(info(f"report: {report}"))
    return 0 if failed == 0 else 1


def _write_report(report: Path, args, fixtures, imported, skipped, extras,
                  verification, out_path: Path, written: bool) -> None:
    lines = [f"# Liter8 fixture import — {args.model} {args.ios} ({args.build}/{args.board})", "",
             f"- upstream: Xplo8E/Liter8 `fixtures/{args.build}/{args.board}`",
             f"- profile: `{out_path.name}` ({'written' if written else 'dry run'})",
             f"- imported entries: {len(imported)}",
             f"- fixtures parsed: {len(fixtures)}", ""]
    if fixtures:
        lines += ["## components", "", "| component | resolver | size | sha256 | patches |",
                  "|---|---|---|---|---|"]
        for fx in sorted(fixtures.values(), key=lambda f: f.resolver):
            lines.append(f"| {fx.component} | {fx.resolver} | {fx.size} | `{fx.sha256[:16]}…` | "
                         f"{len(fx.patches)} |")
        lines.append("")
    lines += ["## imported entries", "",
              "| section | entry | offset | value | upstream id | verified |", "|---|---|---|---|---|---|"]
    for imp in imported:
        key = f"{imp.rule.section}:{imp.rule.path}"
        lines.append(f"| {imp.rule.section} | {imp.rule.path} | 0x{imp.offset:X} | "
                     f"`{imp.value[:40]}` | {'+'.join(imp.upstream_ids)} | "
                     f"{verification.get(key, '—')} |")
    lines.append("")
    lines += ["## not imported (payload/continuity gate)", ""]
    for rule, why in skipped:
        lines.append(f"- `{rule.section}.{rule.path}` — {why}")
    lines.append("")
    lines += ["## upstream-only sites (no entry in our scheme)", "",
              f"{len(extras)} site(s): persona, credential-manager, aks, developer-mode,",
              "mobileactivationd/devicetree extras. Not imported — the arctic chain does not",
              "patch them. Listed for completeness:", ""]
    for resolver, pid, offset in extras[:40]:
        lines.append(f"- {resolver}: `{pid}` @ 0x{offset:X}")
    if len(extras) > 40:
        lines.append(f"- … {len(extras) - 40} more")
    lines.append("")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    import log_utils
    log_utils.install()
    sys.exit(log_utils.guard(main))
