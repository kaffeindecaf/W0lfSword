"""Shared test setup.

The dependency gate must not try to install anything while tests run, and it
should not print noise into captured output: tests opt back in by clearing the
environment variable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def no_dependency_gate(monkeypatch):
    monkeypatch.setenv("UL8_NO_DEPS", "1")
    yield
