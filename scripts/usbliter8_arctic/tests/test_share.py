"""Tests for `share.py`: what gets collected, what gets scrubbed, who gets asked.

The rule under test: nothing leaves the machine without a yes, and the yes can
be "never". No test talks to GitHub: `send()` is exercised with `gh` faked in
both states (available and missing).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import share  # noqa: E402

PROFILE = {
    "model": "iPhone12,1",
    "device": "iPhone 11",
    "board": "n104ap",
    "soc": "A13",
    "ios_version": "27.0",
    "build": "24A437",
    "kernel_component": "kernelcache.release.iphone12b",
    "patches": {"ibss": [{"offset": 16, "value": "deadbeef"}],
                "kernel": [{"offset": 32, "value": "cafebabe"}]},
}


@pytest.fixture(autouse=True)
def isolated_prefs(tmp_path, monkeypatch):
    """Preferences and the inbox live in tmp, and the env opt-out is cleared."""
    monkeypatch.setattr(share, "PREF_FILE", tmp_path / ".usbliter8" / "share.json")
    monkeypatch.setattr(share, "INBOX", tmp_path / "inbox")
    monkeypatch.delenv("UL8_NO_SHARE", raising=False)
    yield


@pytest.fixture
def profile_file(tmp_path):
    path = tmp_path / "iPhone12,1_27.0.yaml"
    path.write_text(yaml.safe_dump(PROFILE))
    return path


# ── collecting ──────────────────────────────────────────────────────

def test_bundle_describes_the_device_and_the_work(profile_file, monkeypatch, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "extracted")
    bundle = share.collect("guided", profile_path=profile_file)

    assert bundle["trigger"] == "guided"
    assert bundle["device"]["model"] == "iPhone12,1"
    assert bundle["device"]["build"] == "24A437"
    assert bundle["profile"]["entries"] == 2
    assert bundle["environment"]["python"]
    assert "usbliter8" in bundle["environment"]
    assert bundle["verification"]["skipped"]                   # no local components


def test_bundle_uses_fetched_component_hashes(profile_file, monkeypatch, tmp_path):
    extracted = tmp_path / "extracted" / "iPhone121_27.0_24A437"
    extracted.mkdir(parents=True)
    (extracted / "provenance.json").write_text(json.dumps({
        "components": {"ibss": {"payload_sha256": "a" * 64, "payload_size": 123,
                                "evidence": "match: iPhone12,1_27.0.json"}},
    }))
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "extracted")

    bundle = share.collect("manual", profile_path=profile_file)
    assert bundle["components"]["ibss"]["payload_sha256"] == "a" * 64
    assert bundle["components"]["ibss"]["evidence"].startswith("match")


def test_nothing_interesting_for_a_committed_profile(profile_file):
    monkeypatch_profile = {"tracked_in_git": True, "blockers": [], "entries": 2}
    bundle = {"profile": monkeypatch_profile, "components": {}, "verification": {}}
    assert share.interesting(bundle) is False
    bundle["profile"]["tracked_in_git"] = False                 # a new profile
    assert share.interesting(bundle) is True
    bundle["profile"]["tracked_in_git"] = True
    bundle["components"] = {"ibss": {}}                         # real hashes
    assert share.interesting(bundle) is True
    bundle["components"] = {}
    bundle["verification"] = {"match": 16}                      # verified bytes
    assert share.interesting(bundle) is True


# ── scrubbing ───────────────────────────────────────────────────────

def test_scrub_removes_identifiers_and_counts_them():
    bundle: dict[str, object] = {
        # these are the patterns the scrubber must catch
        "udid": "00008110-000408462E00A01E",       # safety-allow: redaction fixture
        "plain_udid": "0a595a23eb3f7e2b2145d5ea4e9df419635b6cf5",
        "paths": ["/home/kaffein/Desktop/usbliter8-arctic/usbliter8.log",  # safety-allow: redaction fixture
                  "/Users/tester/Library/Logs/x.log"],  # safety-allow: redaction fixture
        "host": "kaffein-mac.local",
        "ip": "192.168.1.44",
        "prose": "no local component dir",
    }
    counts: dict = {}
    clean = share.scrub(bundle, counts)

    flat = json.dumps(clean)
    assert "00008110" not in flat and "kaffein" not in flat and "tester" not in flat
    assert "192.168.1.44" not in flat and "kaffein-mac.local" not in flat
    assert "<redacted-udid>" in flat and "/home/<user>" in flat
    assert clean["prose"] == "no local component dir"          # prose survives
    assert sum(counts.values()) >= 5


def test_summarize_lists_what_would_go(profile_file, monkeypatch, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    bundle = share.collect("manual", profile_path=profile_file)
    counts: dict = {}
    rows = share.summarize(dict(share.scrub(bundle, counts)), counts)
    joined = "\n".join(rows)
    assert "iPhone 11" in joined and "24A437" in joined
    assert "environment" in joined
    assert "no UDID, serial, ECID" in joined


# ── preferences ─────────────────────────────────────────────────────

def test_preference_round_trip_and_env_opt_out(monkeypatch):
    assert share.enabled() is True
    share.set_ask(False)
    assert share.enabled() is False
    share.set_ask(True)
    assert share.enabled() is True
    monkeypatch.setenv("UL8_NO_SHARE", "1")
    assert share.enabled() is False


# ── the prompt ──────────────────────────────────────────────────────

def test_offer_is_silent_when_nothing_is_new(profile_file, monkeypatch, capsys,
                                             tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts", lambda path: {"file": path.name,
                                                               "tracked_in_git": True,
                                                               "entries": 2})
    monkeypatch.setattr("builtins.input",
                        lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))
    assert share.offer("guided", interactive=True) is False
    assert capsys.readouterr().out == ""


def test_offer_asks_and_declining_sends_nothing(profile_file, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts",
                        lambda path: {"file": path.name, "tracked_in_git": False,
                                      "entries": 2, "model": "iPhone12,1"})
    sent = []
    monkeypatch.setattr(share, "send", lambda bundle, **kw: sent.append(bundle) or "url")
    monkeypatch.setattr("builtins.input", lambda _p: "n")

    assert share.offer("guided", interactive=True) is False
    out = capsys.readouterr().out
    assert "Send this back?" in out and "exactly what the report would contain" in out
    assert sent == []


def test_offer_sends_on_yes(profile_file, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts",
                        lambda path: {"file": path.name, "tracked_in_git": False,
                                      "entries": 2, "model": "iPhone12,1"})
    sent = []
    monkeypatch.setattr(share, "send", lambda bundle, **kw: sent.append(bundle) or "https://x/y")
    monkeypatch.setattr("builtins.input", lambda _p: "y")

    assert share.offer("guided", interactive=True) is True
    assert sent and "https://x/y" in capsys.readouterr().out


def test_offer_never_remembers_the_answer(profile_file, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts",
                        lambda path: {"file": path.name, "tracked_in_git": False,
                                      "entries": 2, "model": "iPhone12,1"})
    monkeypatch.setattr(share, "send", lambda bundle, **kw: "url")
    monkeypatch.setattr("builtins.input", lambda _p: "never")

    assert share.offer("guided", interactive=True) is False
    assert share.enabled() is False                            # remembered

    # and the second time it does not even ask
    monkeypatch.setattr("builtins.input",
                        lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))
    assert share.offer("guided", interactive=True) is False


def test_offer_is_silent_without_a_terminal(profile_file, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts",
                        lambda path: {"file": path.name, "tracked_in_git": False,
                                      "entries": 2, "model": "iPhone12,1"})
    monkeypatch.setattr("builtins.input",
                        lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(share, "send", lambda bundle, **kw: (_ for _ in ()).throw(
        AssertionError("uploaded without asking")))

    assert share.offer("guided", interactive=False) is False
    out = capsys.readouterr().out
    assert "nothing is sent without a yes" in out


# ── sending ─────────────────────────────────────────────────────────

def test_send_falls_back_to_the_inbox_without_gh(profile_file, monkeypatch, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "gh_ready", lambda: False)
    bundle = share.collect("manual", profile_path=profile_file)

    destination = share.send(bundle)
    path = Path(destination)
    assert path.exists() and path.parent == share.INBOX
    saved = json.loads(path.read_text())
    assert saved["device"]["model"] == "iPhone12,1"


def test_send_opens_an_issue_when_gh_works(profile_file, monkeypatch, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "gh_ready", lambda: True)
    calls = []

    class Result:
        returncode = 0
        stdout = "https://github.com/kaffeindecaf/usbliter8-arctic/issues/99\n"
        stderr = ""

    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if list(cmd[:3]) != ["gh", "issue", "create"]:
            return real_run(cmd, **kwargs)          # the git check still runs
        calls.append(cmd)
        assert "Offset report" in cmd[cmd.index("--title") + 1]
        body = Path(cmd[cmd.index("--body-file") + 1]).read_text()
        assert "\"schema\": 1" in body and "| model | `iPhone12,1` |" in body
        return Result()

    monkeypatch.setattr(share.subprocess, "run", fake_run)
    bundle = share.collect("postboot", profile_path=profile_file)

    url = share.send(bundle)
    assert url.endswith("/issues/99")
    assert calls and calls[0][:3] == ["gh", "issue", "create"]
    assert share.prefs()["last_sent"].endswith("/issues/99")


def test_issue_body_has_the_table_and_the_bundle(profile_file, monkeypatch, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    bundle = share.collect("manual", profile_path=profile_file)
    title, body = share.issue_body(bundle)
    assert "iPhone 11" in title and "27.0" in title
    assert "| model | `iPhone12,1` |" in body
    assert "```json" in body


def test_status_and_cli_surface(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(share, "gh_ready", lambda: False)
    assert share.cli(["status"]) == 0
    out = capsys.readouterr().out
    assert "asks before sending" in out

    assert share.cli(["off"]) == 0
    assert share.enabled() is False
    assert share.cli(["on"]) == 0
    assert share.enabled() is True
    assert share.cli(["nonsense"]) == 1


# ── the pull request path ───────────────────────────────────────────

def test_repo_files_only_ever_proposes_offsets(tmp_path, monkeypatch):
    """A dirty README or source file must never end up in the PR."""
    monkeypatch.setattr(share, "ROOT", tmp_path)
    monkeypatch.setattr(share, "OFFSETS_DIR", tmp_path / "offsets")
    (tmp_path / "offsets" / "evidence").mkdir(parents=True)
    profile = tmp_path / "offsets" / "iPhone12,1_27.0b5.yaml"
    profile.write_text("model: iPhone12,1\n")
    (tmp_path / "README.md").write_text("edited\n")            # not ours to add
    (tmp_path / "offsets" / "evidence" / "iPhone12,1_27.0b5.json").write_text("{}")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["git", "status"]
        class R:
            returncode = 0
            stdout = ("?? offsets/iPhone12,1_27.0b5.yaml\n"
                      " M offsets/evidence/iPhone12,1_27.0b5.json\n"
                      " M README.md\n")
            stderr = ""
        return R()

    monkeypatch.setattr(share.subprocess, "run", fake_run)
    files = share.repo_files(profile)
    assert [f["path"] for f in files] == ["offsets/evidence/iPhone12,1_27.0b5.json",
                                          "offsets/iPhone12,1_27.0b5.yaml"]
    assert files[1]["state"] == "new" and files[0]["state"] == "modified"


def test_pr_branch_name_is_readable_and_unique():
    branch = share.pr_branch({"model": "iPhone12,1", "ios_version": "27.0b5",
                              "build": "24A5400a"})
    assert branch == "offsets/iPhone12-1-27.0b5-24A5400a"
    assert "," not in branch


def test_send_pr_uses_a_worktree_and_never_touches_the_checkout(tmp_path, monkeypatch,
                                                               profile_file):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    bundle = share.collect("manual", profile_path=profile_file)
    files = [{"path": "offsets/iPhone12,1_27.0b5.yaml", "state": "new", "bytes": 120}]

    real_mkdtemp = share.tempfile.mkdtemp
    monkeypatch.setattr(share.tempfile, "mkdtemp", lambda **kw: real_mkdtemp(dir=tmp_path))
    # the file the PR would carry has to exist in the tree
    (tmp_path / "offsets").mkdir(exist_ok=True)
    (tmp_path / "offsets" / "iPhone12,1_27.0b5.yaml").write_text("model: iPhone12,1\n")
    monkeypatch.setattr(share, "ROOT", tmp_path)

    commands: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = "https://github.com/kaffeindecaf/usbliter8-arctic/pull/7\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        return Result()

    monkeypatch.setattr(share, "writable_access", lambda: True)
    monkeypatch.setattr(share, "gh_login", lambda: "kaffeindecaf")
    monkeypatch.setattr(share.subprocess, "run", fake_run)

    url = share.send_pr(files, bundle)
    assert url.endswith("/pull/7")

    flat = [" ".join(c) for c in commands]
    assert any(c.startswith("git fetch origin main") for c in flat)
    assert any("worktree add" in c and "origin/main" in c for c in flat)
    branch = share.pr_branch(bundle["device"])
    assert any(c.startswith("git -C") and f"push -u origin {branch}" in c for c in flat)
    assert any(c.startswith("gh pr create") and "--base main" in c for c in flat)
    assert any("worktree remove" in c for c in flat)           # cleaned up
    assert not any(c.startswith("git push origin main") for c in flat)


def test_send_pr_forks_when_there_is_no_push_access(tmp_path, monkeypatch, profile_file):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    bundle = share.collect("manual", profile_path=profile_file)
    real_mkdtemp = share.tempfile.mkdtemp
    monkeypatch.setattr(share.tempfile, "mkdtemp", lambda **kw: real_mkdtemp(dir=tmp_path))
    files = [{"path": "offsets/x.yaml", "state": "new", "bytes": 10}]
    (tmp_path / "offsets").mkdir(exist_ok=True)
    (tmp_path / "offsets" / "x.yaml").write_text("model: x\n")
    monkeypatch.setattr(share, "ROOT", tmp_path)

    commands: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = "https://github.com/kaffeindecaf/usbliter8-arctic/pull/8\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        return Result()

    monkeypatch.setattr(share, "writable_access", lambda: False)
    monkeypatch.setattr(share, "gh_login", lambda: "someone")
    monkeypatch.setattr(share.subprocess, "run", fake_run)

    share.send_pr(files, bundle)
    flat = [" ".join(c) for c in commands]
    assert any("gh repo fork" in c for c in flat)
    assert any("https://github.com/someone/usbliter8-arctic.git" in c for c in flat)
    assert any("--head someone:offsets/" in c for c in flat)


def test_send_prefers_a_pull_request_and_falls_back_to_an_issue(monkeypatch, capsys,
                                                               tmp_path, profile_file):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "INBOX", tmp_path / "inbox")
    bundle = share.collect("manual", profile_path=profile_file)
    files = [{"path": "offsets/x.yaml", "state": "new", "bytes": 10}]

    monkeypatch.setattr(share, "send_pr",
                        lambda files, bundle, dry_run=False: (_ for _ in ()).throw(
                            RuntimeError("no push access")))
    monkeypatch.setattr(share, "gh_ready", lambda: False)

    destination = share.send(bundle, files=files)
    assert destination.endswith(".json") and Path(destination).exists()
    out = capsys.readouterr().out
    assert "pull request not opened" in out and "issue instead" in out


def test_offer_asks_for_a_pull_request_when_there_are_files(monkeypatch, capsys,
                                                           profile_file, tmp_path):
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    monkeypatch.setattr(share, "active_profile", lambda: profile_file)
    monkeypatch.setattr(share, "_profile_facts",
                        lambda path: {"file": path.name, "tracked_in_git": True,
                                      "entries": 2, "model": "iPhone12,1"})
    files = [{"path": "offsets/iPhone12,1_27.0b5.yaml", "state": "new", "bytes": 900}]
    monkeypatch.setattr(share, "repo_files", lambda *a, **k: files)
    sent: list = []
    questions: list[str] = []
    monkeypatch.setattr(share, "send", lambda bundle, **kw: sent.append(kw) or
                        "https://github.com/x/y/pull/1")

    def fake_input(question):
        questions.append(question)
        return "y"

    monkeypatch.setattr("builtins.input", fake_input)

    assert share.offer("guided", interactive=True) is True
    out = capsys.readouterr().out
    assert "These files are waiting in your tree" in out
    assert "offsets/iPhone12,1_27.0b5.yaml" in out
    assert f"branch: {share.pr_branch(share.collect('manual', profile_path=profile_file)['device'])}" \
        in out
    assert questions and "pull request" in questions[0]
    assert sent and sent[0]["files"] == files


def test_send_pr_really_pushes_a_branch_to_a_remote(tmp_path, monkeypatch):
    """Real git, no GitHub: build a local origin and check the branch lands.

    The gh calls are faked, everything else (fetch, worktree, commit, push) is
    the code under test, so this proves the mechanics a PR depends on.
    """
    origin = tmp_path / "origin.git"
    clone = tmp_path / "clone"
    real_run = subprocess.run

    real_run(["git", "init", "--bare", "-q", str(origin)], check=True)
    real_run(["git", "init", "-q", str(clone)], check=True)
    real_run(["git", "-C", str(clone), "symbolic-ref", "HEAD", "refs/heads/main"], check=True)
    real_run(["git", "-C", str(clone), "config", "user.email", "t@example.com"], check=True)
    real_run(["git", "-C", str(clone), "config", "user.name", "tester"], check=True)
    (clone / "offsets").mkdir()
    (clone / "offsets" / "existing.yaml").write_text("model: old\n")
    real_run(["git", "-C", str(clone), "add", "."], check=True)
    real_run(["git", "-C", str(clone), "commit", "-qm", "init"], check=True)
    real_run(["git", "-C", str(clone), "remote", "add", "origin", str(origin)], check=True)
    real_run(["git", "-C", str(clone), "push", "-q", "origin", "main"], check=True)
    real_run(["git", "-C", str(clone), "checkout", "-q", "-b", "work"], check=True)

    monkeypatch.setattr(share, "ROOT", clone)
    monkeypatch.setattr(share, "EXTRACTED_DIR", tmp_path / "none")
    real_mkdtemp = share.tempfile.mkdtemp
    monkeypatch.setattr(share.tempfile, "mkdtemp",
                        lambda **kw: real_mkdtemp(prefix="ul8-pr-test-", dir=tmp_path))
    monkeypatch.setattr(share, "writable_access", lambda: True)
    monkeypatch.setattr(share, "gh_login", lambda: "tester")

    gh_calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        if cmd and cmd[0] == "gh":
            gh_calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "https://github.com/x/y/pull/5\n", "")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(share.subprocess, "run", fake_run)

    new_profile = clone / "offsets" / "iPhone12,1_27.0b5.yaml"
    new_profile.write_text("model: iPhone12,1\npatches: {}\n")
    files = [{"path": "offsets/iPhone12,1_27.0b5.yaml", "state": "new",
              "bytes": new_profile.stat().st_size}]
    bundle = share.collect("manual", profile_path=new_profile)

    url = share.send_pr(files, bundle)
    assert url.endswith("/pull/5")
    assert gh_calls and gh_calls[0][:3] == ["gh", "pr", "create"]

    branch = share.pr_branch(bundle["device"])
    branches = real_run(["git", "-C", str(origin), "branch", "--list", branch],
                        capture_output=True, text=True).stdout
    assert branch in branches                                  # it really landed

    # the checkout never moved, and only the profile is on the branch
    assert real_run(["git", "-C", str(clone), "rev-parse", "--abbrev-ref", "HEAD"],
                    capture_output=True, text=True).stdout.strip() == "work"
    listing = real_run(["git", "-C", str(clone), "ls-tree", "-r", "--name-only", branch],
                       capture_output=True, text=True).stdout.split()
    assert "offsets/iPhone12,1_27.0b5.yaml" in listing
    assert "offsets/existing.yaml" in listing

    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith("ul8-pr-test-")]
    assert leftovers == []                                     # worktree removed
