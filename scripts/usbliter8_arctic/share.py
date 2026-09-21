#!/usr/bin/env python3
"""Send verified work back to the repo, but only after asking.

Once the exploit is up and offsets can be checked (guided setup finished, the
device answers over SSH after a boot, or preflight verified a profile against
real firmware) this is the one thing worth offering: the data that makes the
next person's install work first try.

Rules it follows, because the user is on the other side of a y/N prompt:

- nothing is sent without an explicit yes. No terminal means no prompt and no
  upload, just a printed way to do it by hand
- the yes can be permanent: "never" is remembered in `.usbliter8/share.json`
  (`share on` turns it back on, `UL8_NO_SHARE=1` skips it for one run)
- what goes out is shown first, and it is scrubbed: UDIDs, serials, ECIDs,
  home paths, hostnames and IPs are replaced with `<redacted>` and the count is
  reported
- it goes out as a GitHub issue on the project repo (that is where the
  maintainer will look), and if `gh` is missing the bundle lands in
  `contribute/inbox/` with instructions instead of failing

Usage:
  python3 share.py status              # is it on, where does it send
  python3 share.py preview             # build the bundle and show exactly what would go
  python3 share.py send                # send it now (asks first)
  python3 share.py on | off            # remember the preference
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from colors import C, err, info, key_value, ok, section, warn
import log_utils

ROOT = Path(__file__).parent
REPO = "kaffeindecaf/usbliter8-arctic"
PREF_FILE = ROOT / ".usbliter8" / "share.json"
INBOX = ROOT / "contribute" / "inbox"
OFFSETS_DIR = ROOT / "offsets"
EXTRACTED_DIR = ROOT / "research" / "extracted"

# what must never leave the machine, even though it is useful diagnostics
REDACTIONS: tuple[tuple[str, str], ...] = (
    (r"\b[0-9a-fA-F]{40}\b", "<redacted-udid>"),                  # device UDID
    (r"\b[0-9a-fA-F]{8,16}-[0-9a-fA-F]{16,32}\b", "<redacted-udid>"),
    (r"\b\d{8,16}\b(?=\s*(?:ECID|ecid))", "<redacted-ecid>"),
    (r"\bECID[:= ]+[0-9]+", "ECID: <redacted>"),
    (r"/home/[A-Za-z0-9._-]+", "/home/<user>"),
    (r"/Users/[A-Za-z0-9._-]+", "/Users/<user>"),
    (r"C:\\\\Users\\\\[A-Za-z0-9._-]+", r"C:\\Users\\<user>"),
    (r"\b[A-Za-z0-9][A-Za-z0-9-]*\.(?:local|lan|internal|home|localdomain|home\.arpa)\b",
     "<host>"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<lan-ip>"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "<lan-ip>"),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "<lan-ip>"),
    (r"\b[A-Fa-f0-9]{12,}\b(?=\s*(?:serial|Serial|SERIAL))", "<redacted-serial>"),
)


# ── preferences ─────────────────────────────────────────────────────

def prefs() -> dict:
    try:
        return json.loads(PREF_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def set_ask(enabled: bool) -> None:
    data = prefs()
    data["ask"] = bool(enabled)
    data["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    PREF_FILE.parent.mkdir(parents=True, exist_ok=True)
    PREF_FILE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def enabled() -> bool:
    """False when the user said never, or the run opted out."""
    if os.environ.get("UL8_NO_SHARE") in ("1", "true", "yes"):
        return False
    return prefs().get("ask", True) is not False


def can_prompt() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


# ── collecting the bundle ───────────────────────────────────────────

def active_profile() -> Path | None:
    """The profile the toolkit is pointed at: active device, else the newest."""
    try:
        import device_offsets
        active = device_offsets.get_active_device() or {}
        source = str(active.get("_source_file") or "")
        if source and Path(source).exists():
            return Path(source)
    except Exception:                                          # noqa: BLE001
        pass
    files = [p for p in sorted(OFFSETS_DIR.glob("*.yaml"))
             if p.name not in ("sources.yaml", "template.yaml", "canonical.yaml")]
    return files[-1] if files else None


def _profile_facts(path: Path) -> dict:
    import yaml

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (yaml.YAMLError, OSError) as exc:
        return {"file": path.name, "error": str(exc)[:120]}

    patches = data.get("patches") or {}
    entries = 0
    for section_body in patches.values():
        if isinstance(section_body, list):
            entries += len(section_body)
        elif isinstance(section_body, dict):
            entries += sum(1 for value in section_body.values() if isinstance(value, dict))

    tracked = False
    try:
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(path)],
                                 cwd=ROOT, capture_output=True, text=True).returncode == 0
    except OSError:
        pass

    return {
        "file": path.name,
        "model": data.get("model"),
        "device": data.get("device"),
        "board": data.get("board"),
        "soc": data.get("soc"),
        "ios_version": data.get("ios_version"),
        "build": data.get("build"),
        "kernel_component": data.get("kernel_component"),
        "entries": entries,
        "sections": sorted(patches) if isinstance(patches, dict) else [],
        "blockers": sorted(data.get("blockers") or {}) if isinstance(data.get("blockers"), dict) else [],
        "tracked_in_git": tracked,
    }


def _component_facts(profile: dict) -> dict:
    """Component hashes for this device+build: fetched provenance, else evidence."""
    model = str(profile.get("model") or "")
    build = str(profile.get("build") or "")
    wanted_dir = EXTRACTED_DIR / f"{model.replace(',', '')}_{profile.get('ios_version')}_{build}"
    out: dict[str, dict] = {}

    provenance = wanted_dir / "provenance.json"
    if provenance.exists():
        try:
            data = json.loads(provenance.read_text())
            out = {comp: dict(row) for comp, row in (data.get("components") or {}).items()}
        except (OSError, json.JSONDecodeError):
            pass
    if out:
        return out

    try:
        import fetch_components
        for record in fetch_components.evidence_records():
            if record.get("model") != model or str(record.get("build", "")) != build:
                continue
            for comp, row in (record.get("components") or {}).items():
                out[comp] = {"evidence": f"match: {Path(record['_file']).name}",
                             "payload_size": row.get("size"),
                             "payload_sha256": row.get("sha256")}
    except Exception:                                          # noqa: BLE001
        pass
    return out


def _verification_facts(profile: dict, profile_path: Path | None) -> dict:
    """Run preflight when local components exist; never fetch from here."""
    if profile_path is None:
        return {}
    model = str(profile.get("model") or "")
    build = str(profile.get("build") or "")
    comp_dir = EXTRACTED_DIR / f"{model.replace(',', '')}_{profile.get('ios_version')}_{build}"
    if not comp_dir.exists():
        return {"skipped": "no local component dir", "dir": comp_dir.name}
    import contextlib
    import io

    try:
        import preflight
        with contextlib.redirect_stdout(io.StringIO()):        # keep --json output clean
            report = preflight.run_preflight(profile_path, components=comp_dir)
        counts = {"match": 0, "plausible": 0, "changed": 0, "skipped": 0}
        for site in report.sites:
            counts[site.status] = counts.get(site.status, 0) + 1
        return {"verdict": report.verdict, "components": comp_dir.name, **counts}
    except Exception as exc:                                   # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"[:160]}


def _environment_facts() -> dict:
    import platform
    facts = {"os": platform.system(), "release": platform.release(),
             "python": platform.python_version()}
    try:
        import version
        facts["usbliter8"] = version.VERSION
        facts["commit"] = version.commit()
    except Exception:                                          # noqa: BLE001
        pass
    return facts


def _log_tail(limit: int = 25) -> list[str]:
    """Recent warnings/errors, the part that makes a report actionable."""
    try:
        entries = log_utils.read_log(min_level="WARN", tail=limit)
    except Exception:                                          # noqa: BLE001
        return []
    return [line.rstrip() for line in entries][-limit:]


def collect(trigger: str = "manual", *, profile_path: Path | None = None,
            note: str = "") -> dict:
    """Build the bundle: what was done, on what device, and what it proved."""
    path = profile_path or active_profile()
    profile = _profile_facts(path) if path else {}
    bundle = {
        "schema": 1,
        "kind": "offset-report",
        "trigger": trigger,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": profile,
        "device": {key: profile.get(key) for key in
                   ("model", "device", "board", "soc", "ios_version", "build",
                    "kernel_component")},
        "components": _component_facts(profile),
        "verification": _verification_facts(profile, path),
        "environment": _environment_facts(),
        "log_tail": _log_tail(),
    }
    if note:
        bundle["note"] = note
    return bundle


def interesting(bundle: dict) -> bool:
    """Is there anything worth someone's attention in this bundle?"""
    profile = bundle.get("profile") or {}
    if profile and not profile.get("error"):
        if not profile.get("tracked_in_git"):
            return True                      # a new profile nobody has yet
        if profile.get("blockers"):
            return True                      # says what data is missing
    if bundle.get("components"):
        return True
    verification = bundle.get("verification") or {}
    return bool(verification.get("match"))


# ── scrubbing ───────────────────────────────────────────────────────

T = TypeVar("T")


def scrub(value: T, counts: dict[str, int] | None = None) -> T:
    """Redact identifiers anywhere in a nested structure. Returns the clean copy."""
    counts = counts if counts is not None else {}
    if isinstance(value, dict):
        return {key: scrub(item, counts) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, counts) for item in value]
    if not isinstance(value, str):
        return value

    text = value
    for pattern, replacement in REDACTIONS:
        text, hits = re.subn(pattern, replacement, text)
        if hits:
            counts[replacement] = counts.get(replacement, 0) + hits
    return text


def summarize(bundle: dict, redactions: dict[str, int] | None = None,
              files: list[dict] | None = None) -> list[str]:
    """The 'this is exactly what would be sent' lines."""
    profile = bundle.get("profile") or {}
    device = bundle.get("device") or {}
    rows = []
    for entry in files or []:
        rows.append(f"adds: {entry['path']} ({entry['state']}, {entry['bytes']} bytes)")
    if profile:
        rows.append(f"profile: {profile.get('file')} "
                    f"({profile.get('entries', '?')} entries"
                    + (", not committed yet" if not profile.get("tracked_in_git") else "")
                    + ")")
    rows.append(f"device: {device.get('device') or device.get('model') or '?'} "
                f"{device.get('model') or ''} iOS {device.get('ios_version') or '?'} "
                f"({device.get('build') or '?'})")
    comps = bundle.get("components") or {}
    if comps:
        rows.append(f"components: {', '.join(sorted(comps))} (sizes + sha256)")
    verification = bundle.get("verification") or {}
    if verification.get("verdict"):
        rows.append(f"verification: {verification['verdict']} "
                    f"({verification.get('match', 0)} match, "
                    f"{verification.get('changed', 0)} changed)")
    if verification.get("skipped"):
        rows.append(f"verification: skipped ({verification['skipped']})")
    rows.append(f"environment: {bundle.get('environment', {}).get('os', '?')} / "
                f"python {bundle.get('environment', {}).get('python', '?')} / "
                f"usbliter8 {bundle.get('environment', {}).get('usbliter8', '?')}")
    if bundle.get("log_tail"):
        rows.append(f"log: last {len(bundle['log_tail'])} warning/error line(s)")
    if redactions:
        total = sum(redactions.values())
        rows.append(f"redacted: {total} identifier(s) "
                    f"({', '.join(sorted(redactions))})")
    rows.append("no UDID, serial, ECID, username, hostname or local path leaves the machine")
    return rows


# ── the files a pull request would add ──────────────────────────────

ALLOWED_PREFIX = "offsets/"          # offset data only: nothing else may be committed


def repo_files(profile_path: Path | None = None) -> list[dict]:
    """Files under offsets/ that this run would add or update.

    Only what git already sees in the working tree, restricted to `offsets/`:
    the profile and its recorded evidence. That is exactly the content a pull
    request is good at, and the reason a PR beats an issue when it exists.
    """
    path = profile_path or active_profile()
    candidates: list[Path] = []
    if path is not None:
        candidates.append(path)
        candidates.append(OFFSETS_DIR / "evidence" / f"{path.stem}.json")

    try:
        status = subprocess.run(["git", "status", "--porcelain", "--", *map(str, candidates)],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        seen = {}
        for line in status.stdout.splitlines():
            code, _, rel = line[:2], line[2:], line[3:].strip()
            if not rel.startswith(ALLOWED_PREFIX):
                continue                       # never propose anything else
            state = "new" if code.strip() == "??" else "modified"
            seen[rel] = state
    except (OSError, subprocess.SubprocessError):
        return []

    out: list[dict] = []
    for rel, state in sorted(seen.items()):
        full = ROOT / rel
        out.append({"path": rel, "state": state,
                    "bytes": full.stat().st_size if full.exists() else 0})
    return out


def pr_branch(device: dict) -> str:
    """offsets/iPhone12-1-27.0b5-24A5400a: unique per device+build, readable."""
    model = str(device.get("model") or "device").replace(",", "-")
    ios = str(device.get("ios_version") or "ios").replace(",", "-")
    build = str(device.get("build") or time.strftime("%Y%m%d"))
    return f"offsets/{model}-{ios}-{build}"


def writable_access() -> bool:
    """Does this account have push access to the repo (else: fork first)?"""
    if not gh_ready():
        return False
    try:
        out = subprocess.run(["gh", "api", f"repos/{REPO}", "--jq", ".permissions.push"],
                             capture_output=True, text=True, timeout=30)
        return out.returncode == 0 and out.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def gh_login() -> str:
    try:
        out = subprocess.run(["gh", "api", "user", "--jq", ".login"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def pr_body(bundle: dict, files: list[dict]) -> tuple[str, str]:
    """(title, body) for the pull request that adds the files."""
    title, base = issue_body(bundle)
    device = bundle.get("device") or {}
    lines = [
        f"Adds {len(files)} file(s) from a verified run on "
        f"{device.get('device') or device.get('model') or 'a device'}:",
        "",
    ]
    for entry in files:
        lines.append(f"- `{entry['path']}` ({entry['state']}, "
                     f"{entry['bytes']} bytes)")
    lines += ["", "---", "", base]
    return title, "\n".join(lines)


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 600,
         check: bool = True) -> subprocess.CompletedProcess:
    """Run a git/gh command, logging it. Raises RuntimeError on failure."""
    log_utils.log_info(f"share: run {' '.join(cmd)}", module="share")
    result = subprocess.run(cmd, cwd=cwd or ROOT, capture_output=True, text=True,
                            timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{cmd[0]} {' '.join(cmd[1:3])} failed: "
                           f"{(result.stderr or result.stdout).strip()[:300]}")
    return result


def send_pr(files: list[dict], bundle: dict, *, dry_run: bool = False) -> str:
    """Open a pull request that adds `files`. Returns its URL.

    Uses a temporary worktree branched from origin/main, so the caller's
    checkout, branch and uncommitted work are never touched. Only files under
    offsets/ are copied in, and the branch is unique per device+build.
    """
    device = bundle.get("device") or {}
    branch = pr_branch(device)
    title, body = pr_body(bundle, files)
    if dry_run:
        return f"dry-run: would push {branch} and open a PR with {len(files)} file(s)"

    worktree = Path(tempfile.mkdtemp(prefix="ul8-pr-")) / "repo"
    body_file = worktree.parent / "pr-body.md"
    body_file.write_text(body)
    login = gh_login()
    keep = False
    try:
        _run(["git", "fetch", "origin", "main", "--quiet"])
        _run(["git", "worktree", "add", "--detach", str(worktree), "origin/main"])
        _run(["git", "-C", str(worktree), "checkout", "-b", branch])

        for entry in files:
            source = ROOT / entry["path"]
            target = worktree / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        _run(["git", "-C", str(worktree), "add", *[e["path"] for e in files]])
        _run(["git", "-C", str(worktree), "commit",
              "-m", f"offsets: add {device.get('model', 'device')} "
                    f"{device.get('ios_version', '')} ({device.get('build', '')})".strip()])

        if writable_access():
            _run(["git", "-C", str(worktree), "push", "-u", "origin", branch])
            head = branch
        else:
            if not login:
                raise RuntimeError("cannot determine the GitHub account to fork to")
            _run(["gh", "repo", "fork", REPO, "--clone=false", "--remote=false"])
            fork_url = f"https://github.com/{login}/{REPO.split('/')[1]}.git"
            _run(["git", "-C", str(worktree), "push", fork_url, f"HEAD:{branch}"])
            head = f"{login}:{branch}"

        result = _run(["gh", "pr", "create", "--repo", REPO, "--base", "main",
                       "--head", head, "--title", title, "--body-file", str(body_file)])
        url = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        if not url:
            raise RuntimeError("gh pr create returned no URL")
        log_utils.log_info(f"share: opened {url}", module="share")
        return url
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        keep = True                    # leave the worktree so the work is not lost
        log_utils.log_warn(f"share: pull request not created: {exc}", module="share")
        raise RuntimeError(f"{exc} | branch left at {worktree}") from exc
    finally:
        if not keep:
            _run(["git", "worktree", "remove", "--force", str(worktree)], check=False)
            shutil.rmtree(worktree.parent, ignore_errors=True)


def gh_ready() -> bool:
    if not shutil.which("gh"):
        return False
    try:
        return subprocess.run(["gh", "auth", "status"], capture_output=True,
                              text=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def issue_body(bundle: dict) -> tuple[str, str]:
    """(title, body) for the report issue."""
    device = bundle.get("device") or {}
    profile = bundle.get("profile") or {}
    title = (f"Offset report: {device.get('device') or device.get('model') or 'device'} "
             f"{device.get('ios_version') or '?'} ({device.get('build') or '?'})")
    lines = ["Sent by `share.py` after a successful run. Scrub before trusting: "
             "identifiers are replaced with `<redacted-*>`.",
             "",
             "| field | value |", "|---|---|"]
    for key in ("model", "device", "board", "soc", "ios_version", "build",
                "kernel_component"):
        value = device.get(key)
        if value:
            lines.append(f"| {key} | `{value}` |")
    if profile.get("file"):
        lines.append(f"| profile | `{profile['file']}` "
                     f"({profile.get('entries', '?')} entries, "
                     f"{'new' if not profile.get('tracked_in_git') else 'in repo'}) |")
    verification = bundle.get("verification") or {}
    if verification:
        lines.append(f"| verification | {verification.get('verdict', verification.get('skipped', '?'))}"
                     f" ({verification.get('match', 0)} match, "
                     f"{verification.get('changed', 0)} changed) |")
    lines += ["", "```json", json.dumps(bundle, indent=2), "```"]
    return title[:250], "\n".join(lines) + "\n"


def send(bundle: dict, *, dry_run: bool = False, files: list[dict] | None = None,
         prefer: str = "auto") -> str:
    """Ship the work: a pull request when there are files, else an issue.

    `prefer` picks explicitly: "auto" (default), "pr" or "issue".
    """
    files = repo_files() if files is None else files

    if prefer == "pr" and not files:
        print(info("no new profile or evidence to add, sending a report instead"))
        log_utils.log_info("share: --pr requested with no files, using an issue", module="share")

    if prefer != "issue" and files:
        try:
            url = send_pr(files, bundle, dry_run=dry_run)
            _remember(url)
            return url
        except RuntimeError as exc:
            log_utils.log_warn(f"share: falling back to an issue ({exc})", module="share")
            print(warn(f"pull request not opened ({exc})"))
            print(f"  {C.DIM}the files are unchanged in your tree; the report goes out "
                  f"as an issue instead{C.NC}")

    title, body = issue_body(bundle)
    if dry_run:
        return f"dry-run: would open an issue '{title}' on {REPO}"

    if gh_ready():
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(body)
            body_file = fh.name
        cmd = ["gh", "issue", "create", "--repo", REPO, "--title", title,
               "--body-file", body_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        finally:
            Path(body_file).unlink(missing_ok=True)
        if result.returncode == 0 and result.stdout.strip():
            url = result.stdout.strip().splitlines()[-1]
            log_utils.log_info(f"share: opened {url}", module="share")
            _remember(url)
            return url
        log_utils.log_warn(f"share: gh issue create failed: "
                           f"{(result.stderr or result.stdout).strip()[:200]}", module="share")

    INBOX.mkdir(parents=True, exist_ok=True)
    device = bundle.get("device") or {}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = (f"{device.get('model') or 'device'}_{device.get('ios_version') or 'ios'}_"
            f"{device.get('build') or 'build'}_{stamp}.json")
    target = INBOX / name
    target.write_text(json.dumps(bundle, indent=2) + "\n")
    log_utils.log_info(f"share: wrote {target}", module="share")
    return str(target)


# ── the prompt ──────────────────────────────────────────────────────

def _remember(url: str) -> None:
    """Record where the last submission went, so `share status` can show it."""
    data = prefs()
    data["last_sent"] = url
    data["last_sent_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    PREF_FILE.parent.mkdir(parents=True, exist_ok=True)
    PREF_FILE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def offer(trigger: str, *, profile_path: Path | None = None,
          interactive: bool | None = None, prefer: str = "auto") -> bool:
    """Ask once whether to send. Returns True when something was sent.

    Silent (False, no prompt) when the user said never, when the run opted out,
    when there is nothing interesting, or when there is no terminal to ask on.
    """
    if not enabled():
        log_utils.log_debug("share: disabled by preference or UL8_NO_SHARE", module="share")
        return False

    bundle = collect(trigger, profile_path=profile_path)
    files = [] if prefer == "issue" else repo_files(profile_path)
    if not interesting(bundle) and not files:
        log_utils.log_debug(f"share: nothing new to report ({trigger})", module="share")
        return False

    if interactive is None:
        interactive = can_prompt()
    if not interactive:
        how = "a pull request" if files else "an issue"
        print(info(f"nothing is sent without a yes: run `./usbliter8 share send` "
                   f"(or `python3 share.py send`) to open {how} for this device"))
        log_utils.log_info(f"share: skipped, not a terminal ({trigger})", module="share")
        return False

    counts: dict[str, int] = {}
    clean = scrub(bundle, counts)
    branch = pr_branch(clean.get("device") or {})
    print()
    print(section("Send this back?"))
    print()
    if files:
        print(f"  {C.DIM}These files are waiting in your tree. A pull request adds "
              f"them to the repo, and nothing lands until you merge it:{C.NC}")
        for entry in files:
            print(f"    {C.SNOW}{entry['path']}{C.NC}  {C.DIM}({entry['state']}, "
                  f"{entry['bytes']} bytes){C.NC}")
        print(f"    {C.DIM}branch: {branch}  ·  base: main{C.NC}")
        print()
    print(f"  {C.DIM}This is exactly what the {('pull request body' if files else 'report')} "
          f"would contain:{C.NC}")
    for row in summarize(clean, counts, files):
        print(f"    {C.SNOW}{row}{C.NC}")
    print()
    question = (f"  Open a pull request that adds these files? [y/N/never]: " if files
                else f"  Send this to {REPO} as an issue? [y/N/never]: ")
    answer = log_utils.safe_input(question, eof_default="n").strip().lower()

    if answer in ("never", "no", "n" + "ever"):
        if answer == "never":
            set_ask(False)
        print(info("Not sending. `./usbliter8 contribute share on` turns it back on."))
        log_utils.log_info(f"share: declined ({trigger}, answer={answer})", module="share")
        return False

    if answer in ("y", "yes"):
        destination = send(clean, files=files, prefer=prefer)
        if destination.startswith("http"):
            print(ok(f"{'pull request open' if '/pull/' in destination else 'issue open'}: "
                     f"{destination}"))
            if "/pull/" in destination:
                print(f"  {C.DIM}merge it yourself when you are happy with the diff{C.NC}")
        else:
            print(warn("gh is unavailable, everything is on disk instead:"))
            print(f"  {destination}")
            print(f"  {C.DIM}attach it to a new issue: https://github.com/{REPO}/issues/new{C.NC}")
        return True

    print(info("Not sending."))
    log_utils.log_info(f"share: declined ({trigger})", module="share")
    return False


# ── CLI ─────────────────────────────────────────────────────────────

def cmd_status() -> int:
    print(section("Contribution sharing"))
    print()
    print(key_value("asks before sending", "yes" if enabled() else "off (never)"))
    files = repo_files()
    if gh_ready():
        destination = (f"{REPO} pull request (branch from origin/main)"
                       if files else f"{REPO} issue (nothing to add right now)")
    else:
        destination = f"gh unavailable -> {INBOX}"
    print(key_value("destination", destination))
    if files:
        for entry in files:
            print(key_value("  would add", f"{entry['path']} ({entry['state']})"))
    print(key_value("push access", "yes" if writable_access() else "no (fork first)"))
    last = prefs().get("last_sent", "")
    print(key_value("last sent", last or "nothing yet"))
    print(key_value("terminal", "interactive" if can_prompt() else "not interactive"))
    print(f"  {C.DIM}UL8_NO_SHARE=1 skips it for one run; `share on|off` remembers{C.NC}")
    print()
    return 0


def cmd_preview(argv: list[str]) -> int:
    trigger = argv[0] if argv else "manual"
    bundle = collect(trigger)
    files = repo_files()
    counts: dict[str, int] = {}
    clean = scrub(bundle, counts)
    print(section("What would be sent"))
    print()
    if not interesting(bundle) and not files:
        print(warn("nothing new for this device yet (no profile, components or verification)"))
    if files:
        print(f"  {C.SNOW}pull request{C.NC} {C.DIM}(branch {pr_branch(clean.get('device') or {})}, "
              f"base main){C.NC}")
        for entry in files:
            print(f"    {entry['state']:<9} {entry['path']}  ({entry['bytes']} bytes)")
        print()
    else:
        print(f"  {C.DIM}no files to add (an existing profile with no new evidence), "
              f"so this would be an issue report{C.NC}")
        print()
    for row in summarize(clean, counts, files):
        print(f"  {row}")
    print()
    print(f"  {C.DIM}full bundle: python3 share.py preview --json{C.NC}")
    return 0


def cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return cmd_status()

    cmd, rest = argv[0], argv[1:]
    if cmd in ("status", "state"):
        return cmd_status()
    if cmd in ("on", "enable"):
        set_ask(True)
        print(ok("sharing prompt enabled"))
        return 0
    if cmd in ("off", "never", "disable"):
        set_ask(False)
        print(ok("sharing prompt disabled (nothing will be sent until `share on`)"))
        return 0
    if cmd == "preview":
        if "--json" in rest:
            bundle = collect(rest[0] if rest and not rest[0].startswith("-") else "manual")
            counts: dict[str, int] = {}
            clean = scrub(bundle, counts)
            print(json.dumps({"bundle": clean, "redactions": counts}, indent=2))
            return 0
        return cmd_preview(rest)
    if cmd in ("send", "share"):
        prefer = "issue" if "--issue" in rest else ("pr" if "--pr" in rest else "auto")
        offer("manual", interactive=None, prefer=prefer)      # asks first, always
        return log_utils.EXIT_OK
    if cmd in ("collect", "export"):
        counts: dict[str, int] = {}
        bundle = scrub(collect(rest[0] if rest else "manual"), counts)
        print(json.dumps(bundle, indent=2))
        print(f"  {C.DIM}({sum(counts.values())} identifier(s) redacted){C.NC}", file=sys.stderr)
        return 0

    print(err(f"unknown command: {cmd}"))
    print(info("try: status, preview, send, collect, on, off"))
    return log_utils.EXIT_ERROR


if __name__ == "__main__":
    log_utils.install()
    sys.exit(log_utils.guard(cli))
