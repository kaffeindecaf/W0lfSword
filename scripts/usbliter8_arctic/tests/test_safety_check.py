"""Tests for `safety_check.py` (the pre-push / CI safety gate).

Each check is exercised against a throwaway tree with ROOT patched, so the
tests prove the gate actually fails on a leak, a stale profile or a badge that
drifted from reality, instead of only passing on the current repo state.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import safety_check  # noqa: E402


# built at runtime so this test file does not itself contain a home path
FAKE_HOME = "/home/" + "alice"


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Point safety_check at an empty throwaway tree."""
    monkeypatch.setattr(safety_check, "ROOT", tmp_path)
    return tmp_path


def write(root: Path, rel: str, body: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return rel


# ── 1. secrets ──────────────────────────────────────────────────────

def test_private_key_is_caught(fake_repo):
    rel = write(fake_repo, "notes.md", "-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    assert safety_check.check_secrets([rel])


def test_token_shapes_are_caught(fake_repo):
    for body, label in (("ghp_" + "a" * 30, "github token"),
                        ("AKIAIOSFODNN7EXAMPLE", "aws"),
                        ("sk-" + "b" * 30, "openai"),
                        ("xoxb-1234567890-abcdefghijkl", "slack")):
        rel = write(fake_repo, f"{label.split()[0]}.md", body)
        assert safety_check.check_secrets([rel]), label


def test_device_udid_is_caught(fake_repo):
    rel = write(fake_repo, "device.md", "UDID 00008110-000408462E00A01E attached")
    problems = safety_check.check_secrets([rel])
    assert problems and "udid" in problems[0]


def test_safety_allow_marker_suppresses_one_line(fake_repo):
    rel = write(fake_repo, "device.md",
                "UDID 00008110-000408462E00A01E  # safety-allow: test fixture\n")
    assert safety_check.check_secrets([rel]) == []


def test_clean_files_pass(fake_repo):
    rel = write(fake_repo, "core.py", "def run():\n    return 1\n")
    assert safety_check.check_secrets([rel]) == []
    assert safety_check.check_machine_paths([rel]) == []


# ── 2. machine-local paths ──────────────────────────────────────────

def test_home_path_with_a_real_user_is_flagged(fake_repo):
    rel = write(fake_repo, "build.sh", f'CFW="{FAKE_HOME}/Desktop/usbliter8-arctic"\n')
    problems = safety_check.check_machine_paths([rel])
    assert problems and "machine-local" in problems[0]


def test_safety_allow_marker_suppresses_a_home_path(fake_repo):
    rel = write(fake_repo, "build.sh",
                f'CFW="{FAKE_HOME}/Desktop/x"  # safety-allow: fixture\n')
    assert safety_check.check_machine_paths([rel]) == []


@pytest.mark.parametrize("line", ["/home/user/tools", "/home/<user>/tools",
                                  "/Users/you/tools", "$HOME/tools"])
def test_generic_home_paths_are_allowed(fake_repo, line):
    rel = write(fake_repo, "doc.md", f"see {line}\n")
    assert safety_check.check_machine_paths([rel]) == []


def test_binary_files_are_not_scanned(fake_repo):
    path = fake_repo / "data.json"
    path.write_bytes(f"{FAKE_HOME}/x".encode())
    assert safety_check.check_machine_paths(["image.png"]) == []
    assert safety_check.check_secrets(["offsets/a.dm4p.im4p".replace("dm4p", "dmg")]) == []
    assert path.exists()


# ── 3. generated files ──────────────────────────────────────────────

@pytest.mark.parametrize("rel", ["usbliter8.log", "session.log", "active_device.yaml",
                                 "research/notes.md", "firmware/board.uf2",
                                 "checklist.md", "config.yaml"])
def test_tracked_generated_files_are_flagged(fake_repo, rel):
    write(fake_repo, rel, "x")
    assert safety_check.check_generated([rel]), rel


def test_gitignore_is_not_flagged(fake_repo):
    assert safety_check.check_generated([".gitignore"]) == []


# ── 4. offset profiles ──────────────────────────────────────────────

def _profile(model="iPhone12,3", ios="27.0b3", extra=None, entries=None) -> str:
    entries = entries or {"ibss": {"image4_validate_nop": {"offset": 0x23DB0,
                                                           "value": "1f2003d5"}}}
    body = {"device": "iPhone 11 Pro", "model": model, "ios_version": ios,
            "build": "24A5380h", "board": "d421ap", "patches": entries}
    if extra:
        body.update(extra)
    import yaml
    return yaml.safe_dump(body)


def test_profile_name_must_match_model_and_ios(fake_repo):
    rel = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile())
    assert safety_check.check_profiles([rel]) == []

    rel_bad = write(fake_repo, "offsets/iPhone12,3_27.0b9.yaml", _profile())
    problems = safety_check.check_profiles([rel_bad])
    assert problems and "does not match model" in problems[0]


def test_verified_claim_with_pending_data_is_flagged(fake_repo):
    rel = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile(
        entries={"ibss": {"image4_validate_nop": {"offset": 0xDEADBEEF,
                                                  "value": "1f2003d5", "pending": True}}},
        extra={"verification": "verified"}))
    problems = safety_check.check_profiles([rel])
    assert problems and "claims verification" in problems[0]


def test_blockers_conflict_with_a_verified_claim(fake_repo):
    rel = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile(
        extra={"verification": "ready", "blockers": {"kernel": {"reason": "wrong component"}}}))
    problems = safety_check.check_profiles([rel])
    assert problems and "claims verification" in problems[0]


def test_partial_verification_is_allowed(fake_repo):
    rel = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile(
        extra={"verification": "partial (bootloaders verified, kernel blocked)",
               "blockers": {"kernel": {"reason": "wrong component"}}}))
    assert safety_check.check_profiles([rel]) == []


def test_auxiliary_offset_yaml_is_not_a_profile(fake_repo):
    rel = write(fake_repo, "offsets/canonical.yaml", "constants:\n  seed: 1\n")
    assert safety_check.check_profiles([rel]) == []


# ── 5. evidence drift ───────────────────────────────────────────────

def test_evidence_offset_drift_is_flagged(fake_repo):
    profile = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile())
    write(fake_repo, "offsets/evidence/iPhone12,3_27.0b3.json", json.dumps({
        "profile": "iPhone12,3_27.0b3.yaml", "build": "24A5380h",
        "entries": {"ibss.image4_validate_nop": {"offset": 0x11111, "original": "00000000"}},
    }))
    problems, summary = safety_check.check_evidence([profile,
                                                     "offsets/evidence/iPhone12,3_27.0b3.json"])
    assert problems and "recorded 0x11111" in problems[0]
    assert summary


def test_matching_evidence_passes(fake_repo):
    profile = write(fake_repo, "offsets/iPhone12,3_27.0b3.yaml", _profile())
    write(fake_repo, "offsets/evidence/iPhone12,3_27.0b3.json", json.dumps({
        "profile": "iPhone12,3_27.0b3.yaml", "build": "24A5380h",
        "entries": {"ibss.image4_validate_nop": {"offset": 0x23DB0, "original": "00000000"}},
    }))
    problems, _summary = safety_check.check_evidence([profile,
                                                     "offsets/evidence/iPhone12,3_27.0b3.json"])
    assert problems == []


def test_evidence_pointing_at_a_missing_profile_is_flagged(fake_repo, monkeypatch):
    write(fake_repo, "offsets/evidence/gone.json",
          json.dumps({"profile": "gone.yaml", "entries": {}}))
    problems, _ = safety_check.check_evidence(["offsets/evidence/gone.json"])
    assert problems and "missing profile" in problems[0]


# ── 6/7. warnings ───────────────────────────────────────────────────

def test_badge_drift_is_reported(fake_repo, monkeypatch):
    write(fake_repo, "README.md", "![Tests](https://img.shields.io/badge/tests-7%20passing-x)")

    class Done:
        stdout = "156 tests collected in 0.10s"

    monkeypatch.setattr(safety_check.subprocess, "run", lambda *a, **k: Done())
    problems = safety_check.check_badge(["README.md"])
    assert problems and "badge says 7" in problems[0]


def test_em_dashes_in_readme_are_reported(fake_repo):
    write(fake_repo, "README.md", "a — b\n")
    assert safety_check.check_docs_style(["README.md"])


# ── the gate itself ─────────────────────────────────────────────────

def test_main_fails_on_a_leak(fake_repo, monkeypatch, capsys):
    monkeypatch.setattr(safety_check, "git_files", lambda: ["config.yaml"])
    write(fake_repo, "config.yaml", "token = 'x'\n")
    assert safety_check.main([]) == 1
    assert "generated/local file is tracked" in capsys.readouterr().out


def test_main_passes_on_a_clean_tree(fake_repo, monkeypatch, capsys):
    monkeypatch.setattr(safety_check, "git_files", lambda: [])
    assert safety_check.main([]) == 0
    assert "nothing to hide" in capsys.readouterr().out


def test_main_json_contract(fake_repo, monkeypatch, capsys):
    monkeypatch.setattr(safety_check, "git_files", lambda: [])
    assert safety_check.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert set(payload["checks"]) >= {"secrets", "offset profiles", "evidence drift"}


def test_strict_promotes_warnings_to_failures(fake_repo, monkeypatch, capsys):
    monkeypatch.setattr(safety_check, "git_files", lambda: ["README.md"])
    write(fake_repo, "README.md", "dash — here\n")
    assert safety_check.main([]) == 0                     # warning only
    capsys.readouterr()
    assert safety_check.main(["--strict"]) == 1


# ── file discovery ───────────────────────────────────────────────────

def test_git_files_includes_untracked_files_in_this_repo():
    """A leak in a staged-but-uncommitted file is exactly what the local gate
    must catch, so discovery cannot be a bare `git ls-files`."""
    import subprocess
    cmd = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                         cwd=safety_check.ROOT, capture_output=True, text=True)
    listed = set(cmd.stdout.split())
    assert "safety_check.py" in listed
    assert "SECURITY.md" in listed
    assert "tests/test_safety_check.py" in listed
    # ignored files stay out (the log is generated, not source)
    assert not any(f.endswith("usbliter8.log") for f in listed)


def test_git_files_falls_back_to_walking_a_plain_tree(fake_repo):
    write(fake_repo, "a.py", "x = 1\n")
    write(fake_repo, "sub/b.yaml", "k: v\n")
    found = safety_check.git_files()
    assert "a.py" in found
    assert any(f.endswith("b.yaml") for f in found)


def test_shadowed_import_check_catches_a_late_local_import(tmp_path, monkeypatch):
    """A function-local import used earlier in the same function is a crash."""
    fake = tmp_path / "late.py"
    fake.write_text(
        "import log_utils\n"
        "\n"
        "def run():\n"
        "    with log_utils.timed('x', 'y'):\n"
        "        pass\n"
        "    import log_utils\n"
        "    return log_utils.EXIT_OK\n"
    )
    monkeypatch.setattr(safety_check, "ROOT", tmp_path)
    monkeypatch.setattr(safety_check, "read", lambda rel: fake.read_text())
    problems = safety_check.check_shadowed_imports(["late.py"])
    assert problems and "UnboundLocalError" in problems[0]


def test_shadowed_import_check_allows_ordinary_lazy_imports(tmp_path, monkeypatch):
    """A lazy import used only after the import line stays legal."""
    fake = tmp_path / "lazy.py"
    fake.write_text(
        "def run():\n"
        "    import json\n"
        "    return json.dumps({'ok': True})\n"
    )
    monkeypatch.setattr(safety_check, "read", lambda rel: fake.read_text())
    assert safety_check.check_shadowed_imports(["lazy.py"]) == []
