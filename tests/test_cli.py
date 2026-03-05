"""Tests for CLI entry point smoke tests."""

import subprocess
import sys


class TestCLI:
    def test_monitor_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "claude_monitoring.monitor", "--help"], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        assert "AI Runtime Monitor" in result.stdout

    def test_watch_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "claude_monitoring.watch", "--help"], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        assert "Claude Watch" in result.stdout or "Traffic Observatory" in result.stdout
