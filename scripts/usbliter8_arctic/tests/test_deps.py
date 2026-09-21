"""Tests for `deps.py`: OS detection, package checks, and the install prompt.

The rule that matters: nothing is installed without a yes, and a non-interactive
run (piped stdin, CI) only reports. Declining is never fatal on its own: the
caller continues and the step that truly needs the package fails with its own
message.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import deps  # noqa: E402


@pytest.fixture(autouse=True)
def gate_enabled(monkeypatch):
    """The gate is off in the shared conftest; turn it back on for these tests."""
    monkeypatch.delenv("UL8_NO_DEPS", raising=False)
    monkeypatch.delenv("UL8_AUTO_INSTALL", raising=False)
    yield


@pytest.fixture(autouse=True)
def classic_pip(monkeypatch):
    """Pin the installer instead of inheriting the environment.

    A uv venv has no pip, so a test asserting the pip command line would fail
    there for the wrong reason; the uv fallback has its own tests.
    """
    monkeypatch.setattr(deps, "pip_available", lambda: True)
    monkeypatch.setattr(deps, "uv_available", lambda: False)
    yield


# ── detection ───────────────────────────────────────────────────────

def test_platform_info_shape_and_values():
    info = deps.platform_info()
    assert set(info) >= {"os", "release", "arch", "python", "venv", "root",
                         "package_manager", "externally_managed", "interactive"}
    assert info["os"] in ("Linux", "Darwin", "Windows")
    assert info["python"].count(".") == 2
    assert isinstance(info["venv"], bool)


def test_package_manager_is_known():
    assert deps.package_manager() in ("apt", "pacman", "dnf", "zypper", "brew", "pip-only")


def test_libusb_check_returns_a_bool():
    assert isinstance(deps.libusb_ok(), bool)


def test_is_root_and_interactive_are_booleans():
    assert isinstance(deps.is_root(), bool)
    assert isinstance(deps.is_interactive(), bool)


# ── requirement mapping ─────────────────────────────────────────────

def test_features_map_to_packages():
    assert [p.pip for p in deps.packages_for("profiles")] == ["pyyaml"]
    build = [p.pip for p in deps.packages_for("build")]
    assert "pyyaml" in build and "pyimg4" in build
    migrate = [p.pip for p in deps.packages_for("migrate")]
    assert set(migrate) == {"pyyaml", "capstone"}


def test_packages_are_not_duplicated_across_features():
    pkgs = [p.pip for p in deps.packages_for(("profiles", "build", "fetch"))]
    assert len(pkgs) == len(set(pkgs))


def test_command_features_cover_the_verbs():
    assert deps.COMMAND_FEATURES["build"] == ("profiles", "build")
    assert deps.COMMAND_FEATURES["flash"] == ("usb", "profiles", "build")
    assert deps.COMMAND_FEATURES["pwn"] == ("usb",)
    assert deps.COMMAND_FEATURES["logs"] == ()


def test_windows_only_package_is_not_missing_elsewhere(monkeypatch):
    pkg = next(p for p in deps.PACKAGES if p.key == "libusb_package")
    if sys.platform != "win32":
        assert deps.is_installed(pkg) is True              # n/a counts as satisfied


# ── install command per platform ────────────────────────────────────

def test_pip_command_user_install(monkeypatch):
    monkeypatch.setattr(deps, "in_venv", lambda: False)
    monkeypatch.setattr(deps, "externally_managed", lambda: False)
    monkeypatch.setattr(deps.platform, "system", lambda: "Linux")
    cmd = deps.install_command(deps.packages_for("migrate"))
    assert cmd[:4] == [sys.executable, "-m", "pip", "install"]
    assert "--user" in cmd and "capstone" in cmd


def test_pip_command_in_venv_has_no_user_flag(monkeypatch):
    monkeypatch.setattr(deps, "in_venv", lambda: True)
    monkeypatch.setattr(deps, "externally_managed", lambda: True)
    cmd = deps.install_command(deps.packages_for("profiles"))
    assert "--user" not in cmd and "--break-system-packages" not in cmd


def test_pep668_adds_break_system_packages(monkeypatch):
    monkeypatch.setattr(deps, "in_venv", lambda: False)
    monkeypatch.setattr(deps, "externally_managed", lambda: True)
    monkeypatch.setattr(deps.platform, "system", lambda: "Linux")
    assert "--break-system-packages" in deps.install_command(deps.packages_for("profiles"))


def test_windows_pip_command_has_no_user_flag(monkeypatch):
    monkeypatch.setattr(deps, "in_venv", lambda: False)
    monkeypatch.setattr(deps, "externally_managed", lambda: False)
    monkeypatch.setattr(deps.platform, "system", lambda: "Windows")
    assert "--user" not in deps.install_command(deps.packages_for("usb"))


@pytest.mark.parametrize("mgr,expected", [
    ("apt", ["sudo", "apt", "install"]),
    ("pacman", ["sudo", "pacman", "-S"]),
    ("dnf", ["sudo", "dnf", "install"]),
    ("zypper", ["sudo", "zypper"]),
    ("brew", ["brew", "install"]),
])
def test_system_install_command(monkeypatch, mgr, expected):
    monkeypatch.setattr(deps, "package_manager", lambda: mgr)
    libusb = deps.Package("libusb", "libusb-1.0", "backend", ("usb",),
                          {"apt": "libusb-1.0-0", "pacman": "libusb", "dnf": "libusb1",
                           "zypper": "libusb-1_0-0", "brew": "libusb"})
    cmd = deps.install_command([libusb], system=True)
    assert cmd[:len(expected)] == expected


def test_system_command_falls_back_to_pip_without_a_manager(monkeypatch):
    monkeypatch.setattr(deps, "package_manager", lambda: "pip-only")
    cmd = deps.install_command(deps.packages_for("usb"), system=True)
    assert "pip" in cmd


# ── ensure(): the prompt flow ───────────────────────────────────────

def _fake_missing(monkeypatch, packages=("pyimg4",)):
    """Pretend these pip names are not installed."""
    def fake_is_installed(pkg):
        return pkg.pip not in packages
    monkeypatch.setattr(deps, "is_installed", fake_is_installed)
    monkeypatch.setattr(deps, "libusb_ok", lambda: True)


def test_ensure_reports_ready_when_everything_is_there(monkeypatch, capsys):
    monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
    monkeypatch.setattr(deps, "libusb_ok", lambda: True)
    assert deps.ensure("build") is True
    assert capsys.readouterr().out == ""


def test_ensure_skipped_by_environment(monkeypatch):
    monkeypatch.setenv("UL8_NO_DEPS", "1")
    monkeypatch.setattr(deps, "is_installed", lambda pkg: False)
    assert deps.ensure("build") is True


def test_ensure_asks_then_installs(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    state = {"installed": False}
    monkeypatch.setattr(deps, "missing_for",
                        lambda features: [] if state["installed"]
                        else [p for p in deps.packages_for(features) if p.pip == "pyimg4"])
    ran = []

    def fake_run(cmd):
        ran.append(cmd)
        state["installed"] = True
        return 0

    monkeypatch.setattr(deps, "_run", fake_run)
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    monkeypatch.setattr(deps, "is_interactive", lambda: True)

    assert deps.ensure("build", interactive=True) is True
    assert ran and "pyimg4" in ran[0]
    out = capsys.readouterr().out
    assert "missing for build" in out
    assert "pyimg4" in out


def test_ensure_declining_installs_nothing(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    ran = []
    monkeypatch.setattr(deps, "_run", lambda cmd: ran.append(cmd) or 0)
    monkeypatch.setattr("builtins.input", lambda _p: "n")

    assert deps.ensure("build", interactive=True) is False
    assert ran == []
    out = capsys.readouterr().out
    assert "continuing without them" in out


def test_ensure_never_installs_without_a_terminal(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    ran = []
    monkeypatch.setattr(deps, "_run", lambda cmd: ran.append(cmd) or 0)
    monkeypatch.setattr(deps, "is_interactive", lambda: False)

    assert deps.ensure("build", interactive=False) is False
    assert ran == []
    assert "not a terminal" in capsys.readouterr().out


def test_ensure_eof_at_the_prompt_does_not_install(monkeypatch):
    _fake_missing(monkeypatch)
    ran = []
    monkeypatch.setattr(deps, "_run", lambda cmd: ran.append(cmd) or 0)
    monkeypatch.setattr("builtins.input", lambda _p: (_ for _ in ()).throw(EOFError()))

    assert deps.ensure("build", interactive=True) is False
    assert ran == []


def test_ensure_yes_flag_installs_without_prompt(monkeypatch):
    _fake_missing(monkeypatch)
    monkeypatch.setattr("builtins.input",
                        lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))
    ran = []

    def fake_run(cmd):
        ran.append(cmd)
        monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
        return 0

    monkeypatch.setattr(deps, "_run", fake_run)
    assert deps.ensure("build", yes=True) is True
    assert ran


def test_ensure_auto_install_environment(monkeypatch):
    _fake_missing(monkeypatch)
    monkeypatch.setenv("UL8_AUTO_INSTALL", "1")
    ran = []
    monkeypatch.setattr(deps, "_run", lambda cmd: ran.append(cmd) or 0)
    deps.ensure("build")
    assert ran


def test_ensure_reports_a_failed_install(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    monkeypatch.setattr(deps, "_run", lambda cmd: 1)
    monkeypatch.setattr(deps, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _p: "y")

    assert deps.ensure("build", interactive=True) is False
    out = capsys.readouterr().out
    assert "still missing" in out
    assert "pyimg4" in out


def test_ensure_libusb_prompt(monkeypatch, capsys):
    monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
    monkeypatch.setattr(deps, "libusb_ok", lambda: False)
    monkeypatch.setattr(deps, "package_manager", lambda: "apt")
    monkeypatch.setattr(deps, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    ran = []
    monkeypatch.setattr(deps, "_run", lambda cmd: ran.append(cmd) or 0)  # the apt call

    ready = deps.ensure("usb", interactive=True)
    out = capsys.readouterr().out
    assert "libusb-1.0" in out                      # the user is told what is broken
    assert any("libusb" in " ".join(cmd) for cmd in ran)
    assert ready is False                           # the backend is still missing
    assert "still missing" in out


# ── command mapping and the doctor CLI ──────────────────────────────

def test_ensure_for_command_uses_the_mapping(monkeypatch):
    seen = []
    monkeypatch.setattr(deps, "ensure", lambda features, **kw: seen.append(tuple(features)) or True)
    deps.ensure_for_command("build")
    deps.ensure_for_command("flash")
    deps.ensure_for_command("logs")
    deps.ensure_for_command("nonsense")
    assert seen == [("profiles", "build"), ("usb", "profiles", "build"), (),
                    ("profiles",)]


def test_doctor_json_is_machine_readable(monkeypatch, capsys):
    import json
    monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
    monkeypatch.setattr(deps, "libusb_ok", lambda: True)
    assert deps.doctor(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["missing"] == []
    assert payload["platform"]["os"] in ("Linux", "Darwin", "Windows")


def test_doctor_exit_code_reports_missing(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    assert deps.doctor(["--json"]) == 1
    payload = __import__("json").loads(capsys.readouterr().out)
    assert "pyimg4" in payload["missing"]


def test_doctor_text_shows_platform_and_hints(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    deps.doctor([])
    out = capsys.readouterr().out
    assert "system" in out and "python" in out
    assert "missing: pyimg4" in out
    assert "ul8.py deps" in out                       # tells the user what to run


def test_doctor_prompts_when_interactive_and_installs(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    monkeypatch.setattr(deps, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    ran = []

    def fake_run(cmd):
        ran.append(cmd)
        monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
        return 0

    monkeypatch.setattr(deps, "_run", fake_run)
    assert deps.doctor(["--feature", "build"]) == 0
    assert ran and any("pyimg4" in " ".join(c) for c in ran)


def test_doctor_check_flag_never_installs(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    monkeypatch.setattr(deps, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input",
                        lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(deps, "_run", lambda cmd: (_ for _ in ()).throw(AssertionError("ran")))
    assert deps.doctor(["--feature", "build", "--check"]) == 1


def test_doctor_in_a_pipe_reports_instead_of_prompting(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    monkeypatch.setattr(deps, "is_interactive", lambda: False)
    monkeypatch.setattr(deps, "_run", lambda cmd: (_ for _ in ()).throw(AssertionError("ran")))
    assert deps.doctor(["--feature", "build"]) == 1
    out = capsys.readouterr().out
    assert "not a terminal" in out and "--install --yes" in out


def test_no_installer_available_is_reported(monkeypatch, capsys):
    _fake_missing(monkeypatch)
    monkeypatch.setattr(deps, "pip_available", lambda: False)
    monkeypatch.setattr(deps, "uv_available", lambda: False)
    monkeypatch.setattr(deps, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    assert deps.ensure("build", interactive=True) is False
    out = capsys.readouterr().out
    assert "no pip and no uv" in out and "ensurepip" in out


def test_uv_is_used_when_pip_is_missing(monkeypatch):
    monkeypatch.setattr(deps, "pip_available", lambda: False)
    monkeypatch.setattr(deps, "uv_available", lambda: True)
    cmd = deps.install_command(deps.packages_for("profiles"))
    assert cmd[:3] == ["uv", "pip", "install"]
    assert "--user" not in cmd                       # uv rejects --user
    assert sys.executable in cmd                     # pinned to this interpreter


def test_ensurepip_hint_when_no_installer(monkeypatch):
    monkeypatch.setattr(deps, "pip_available", lambda: False)
    monkeypatch.setattr(deps, "uv_available", lambda: False)
    cmd = deps.install_command(deps.packages_for("profiles"))
    assert "ensurepip" in " ".join(cmd)


def test_unknown_feature_is_rejected(capsys):
    assert deps.unknown_features(("build", "bogus")) == ["bogus"]
    assert deps.doctor(["--feature", "bogus"]) == 2
    out = capsys.readouterr().out
    assert "unknown feature" in out and "known features" in out


def test_unknown_feature_is_ignored_by_ensure_but_logged(monkeypatch):
    monkeypatch.setattr(deps, "is_installed", lambda pkg: True)
    monkeypatch.setattr(deps, "libusb_ok", lambda: True)
    logged = []
    monkeypatch.setattr(deps.log_utils, "log_warn",
                        lambda message, **kw: logged.append(message))

    assert deps.ensure(("bogus",)) is True           # nothing to gate on
    assert any("unknown feature" in message for message in logged)


def test_feature_names_are_all_documented():
    for feature, description in deps.FEATURES.items():
        assert description, feature
    used = {f for pkg in deps.PACKAGES for f in pkg.features}
    assert used <= set(deps.FEATURES)               # no package claims a phantom feature
