"""Test configuration: reset shared mutable state between test files."""

import pytest
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))


@pytest.fixture(autouse=True)
def reset_tool_profiles():
    """Reset TOOL_PROFILES between tests to avoid cross-file contamination."""
    from provshield.monitor import TOOL_PROFILES
    # Snapshot the original profiles
    original = dict(TOOL_PROFILES)
    yield
    # Restore after test
    TOOL_PROFILES.clear()
    TOOL_PROFILES.update(original)
