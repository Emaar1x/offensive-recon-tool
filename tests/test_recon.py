"""
test_recon.py - Basic smoke tests for the CLI framework.

** Full test suite will be written by the Task 6 teammate. **

These are minimal sanity checks to confirm the CLI skeleton works
before teammates start integrating their modules.

Run with:  python -m pytest tests/ -v
"""

import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

RECON_PY = os.path.join(PROJECT_ROOT, "recon.py")


def test_help_flag():
    """CLI --help should exit 0 and show usage."""
    result = subprocess.run(
        [sys.executable, RECON_PY, "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Offensive Recon Tool" in result.stdout


def test_no_module_selected_shows_error():
    """Running with just a domain and no flags should fail."""
    result = subprocess.run(
        [sys.executable, RECON_PY, "example.com"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0


def test_all_flag_runs():
    """--all should execute without crashing (stubs return placeholders)."""
    result = subprocess.run(
        [sys.executable, RECON_PY, "--all", "example.com"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Scan complete" in result.stdout
