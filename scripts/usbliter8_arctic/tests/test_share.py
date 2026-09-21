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
    assert "Send this back?" in out and "exactly what would go" in out
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
