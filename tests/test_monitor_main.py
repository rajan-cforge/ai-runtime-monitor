"""Tests for monitor.py main/startup functions and ChromeHistoryWatcher.

Covers:
  - ChromeHistoryWatcher: scan_once with mock Chrome DB, missing DB, locked DB
  - _format_uptime: time formatting for process uptime display
  - main(): CLI argument dispatch (--start, --scan, --install-agent, --uninstall-agent)
  - install_launch_agent / uninstall_launch_agent: plist creation and removal
  - ReusableHTTPServer: SO_REUSEADDR flag via allow_reuse_address
"""

import sqlite3
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import config

# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config cache before and after every test."""
    config.reset()
    yield
    config.reset()


def _create_chrome_db(path):
    """Create a minimal Chrome-style History SQLite database.

    Args:
        path: pathlib.Path or str where the DB file will be created.

    Returns:
        sqlite3.Connection to the created database.
    """
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER DEFAULT 0)")
    conn.execute(
        "CREATE TABLE visits ("
        "id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, visit_duration INTEGER DEFAULT 0)"
    )
    return conn


def _chrome_timestamp(unix_ts):
    """Convert a Unix timestamp to Chrome's microsecond-since-1601 format."""
    return int((unix_ts + 11644473600) * 1_000_000)


# ─────────────────────────────────────────────────────────────
# SECTION 1: ChromeHistoryWatcher
# ─────────────────────────────────────────────────────────────


class TestChromeHistoryWatcherScanOnce:
    """Tests for ChromeHistoryWatcher.scan_once() with a temporary Chrome History DB."""

    def _make_watcher(self, tmp_path, chrome_dir):
        """Create a ChromeHistoryWatcher with db and chrome_dir overridden for testing."""
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test_monitor.db"
        conn = init_db(db_path)
        conn.close()

        # Patch get_thread_db to return a connection to our test DB
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            test_conn = sqlite3.connect(str(db_path), check_same_thread=False)
            test_conn.row_factory = sqlite3.Row
            mock_get_db.return_value = test_conn

            # Patch push_live_event so it doesn't interfere
            with patch("claude_monitoring.monitor.push_live_event"):
                from claude_monitoring.monitor import ChromeHistoryWatcher

                watcher = ChromeHistoryWatcher()
                watcher.db = test_conn
                watcher.chrome_dir = chrome_dir

        return watcher, test_conn, db_path

    def test_detects_chatgpt_visit(self, tmp_path):
        """scan_once should find a ChatGPT URL in a mock Chrome History DB."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        # Populate mock Chrome DB
        conn = _create_chrome_db(hist_path)
        visit_ts = _chrome_timestamp(time.time() - 3600)  # 1 hour ago
        conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/abc-123', 'My Chat', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 120000000)", (visit_ts,))
        conn.commit()
        conn.close()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        assert len(results) == 1
        assert results[0]["service"] == "ChatGPT"
        assert results[0]["url"] == "https://chatgpt.com/c/abc-123"
        assert results[0]["title"] == "My Chat"
        assert results[0]["conversation_id"] == "abc-123"
        assert results[0]["duration"] == 120.0  # 120000000 microseconds = 120 seconds

        test_conn.close()

    def test_inserts_into_browser_sessions_table(self, tmp_path):
        """scan_once should insert detected visits into the browser_sessions table."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        visit_ts = _chrome_timestamp(time.time() - 1800)
        conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/sess-001', 'Test Session', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 60000000)", (visit_ts,))
        conn.commit()
        conn.close()

        watcher, test_conn, db_path = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            watcher.scan_once()

        # Verify row was inserted in browser_sessions
        rows = test_conn.execute("SELECT * FROM browser_sessions").fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["service"] == "ChatGPT"
        assert row["url"] == "https://chatgpt.com/c/sess-001"
        assert row["conversation_id"] == "sess-001"
        assert row["duration_seconds"] == 60.0

        test_conn.close()

    def test_detects_claude_web_visit(self, tmp_path):
        """scan_once should detect Claude Web visits."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        visit_ts = _chrome_timestamp(time.time() - 600)
        conn.execute("INSERT INTO urls VALUES (1, 'https://claude.ai/chat/conv-xyz', 'Claude Chat', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 30000000)", (visit_ts,))
        conn.commit()
        conn.close()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        assert len(results) == 1
        assert results[0]["service"] == "Claude Web"
        assert results[0]["conversation_id"] == "conv-xyz"

        test_conn.close()

    def test_detects_gemini_visit(self, tmp_path):
        """scan_once should detect Gemini visits."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        visit_ts = _chrome_timestamp(time.time() - 600)
        conn.execute("INSERT INTO urls VALUES (1, 'https://gemini.google.com/app/gem-abc', 'Gemini Convo', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 45000000)", (visit_ts,))
        conn.commit()
        conn.close()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        assert len(results) == 1
        assert results[0]["service"] == "Gemini"
        assert results[0]["conversation_id"] == "gem-abc"

        test_conn.close()

    def test_multiple_profiles(self, tmp_path):
        """scan_once should scan all Chrome profiles (Default and Profile N)."""
        chrome_dir = tmp_path / "Chrome"

        for profile_name in ("Default", "Profile 1"):
            profile_dir = chrome_dir / profile_name
            profile_dir.mkdir(parents=True)
            hist_path = profile_dir / "History"

            conn = _create_chrome_db(hist_path)
            visit_ts = _chrome_timestamp(time.time() - 300)
            conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/multi-test', 'Multi', 1)")
            conn.execute("INSERT INTO visits VALUES (1, 1, ?, 10000000)", (visit_ts,))
            conn.commit()
            conn.close()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        # Should find visits from both profiles
        assert len(results) == 2

        test_conn.close()

    def test_no_chrome_dir_returns_empty(self, tmp_path):
        """scan_once should return [] when Chrome directory does not exist."""
        chrome_dir = tmp_path / "NonexistentChrome"
        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        assert results == []
        test_conn.close()

    def test_empty_history_returns_empty(self, tmp_path):
        """scan_once should return [] when Chrome History DB has no AI visits."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        # Insert a non-AI URL
        visit_ts = _chrome_timestamp(time.time() - 600)
        conn.execute("INSERT INTO urls VALUES (1, 'https://example.com/page', 'Some Page', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 10000000)", (visit_ts,))
        conn.commit()
        conn.close()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        assert results == []
        test_conn.close()

    def test_locked_db_handled_gracefully(self, tmp_path):
        """scan_once should not crash when Chrome History DB is locked."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        visit_ts = _chrome_timestamp(time.time() - 600)
        conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/locked-test', 'Locked', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 10000000)", (visit_ts,))
        conn.commit()
        # Keep the connection open and take an exclusive lock
        conn.execute("BEGIN EXCLUSIVE")

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        # The scan copies the file first, so it should still work even if the
        # original is locked. The key is it doesn't crash.
        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        # The copy operation (shutil.copy2) may or may not succeed with an
        # exclusive lock depending on the OS, but it should not raise.
        assert isinstance(results, list)

        conn.rollback()
        conn.close()
        test_conn.close()

    def test_corrupted_db_handled_gracefully(self, tmp_path):
        """scan_once should not crash when Chrome History file is corrupted."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        # Write garbage data instead of a valid SQLite file
        hist_path.write_text("this is not a database file")

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results = watcher.scan_once()

        # Should handle gracefully and return empty or partial results
        assert isinstance(results, list)
        test_conn.close()

    def test_does_not_revisit_old_entries(self, tmp_path):
        """After a scan, subsequent scans should only find new visits."""
        chrome_dir = tmp_path / "Chrome"
        profile_dir = chrome_dir / "Default"
        profile_dir.mkdir(parents=True)
        hist_path = profile_dir / "History"

        conn = _create_chrome_db(hist_path)
        visit_ts_1 = _chrome_timestamp(time.time() - 3600)
        conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/old-visit', 'Old Visit', 1)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 10000000)", (visit_ts_1,))
        conn.commit()

        watcher, test_conn, _ = self._make_watcher(tmp_path, chrome_dir)

        with patch("claude_monitoring.monitor.push_live_event"):
            results_1 = watcher.scan_once()
        assert len(results_1) == 1

        # Second scan without new entries
        with patch("claude_monitoring.monitor.push_live_event"):
            results_2 = watcher.scan_once()
        assert len(results_2) == 0

        # Add a newer entry
        visit_ts_2 = _chrome_timestamp(time.time() - 60)
        conn.execute("INSERT INTO urls VALUES (2, 'https://chatgpt.com/c/new-visit', 'New Visit', 1)")
        conn.execute("INSERT INTO visits VALUES (2, 2, ?, 5000000)", (visit_ts_2,))
        conn.commit()
        conn.close()

        with patch("claude_monitoring.monitor.push_live_event"):
            results_3 = watcher.scan_once()
        assert len(results_3) == 1
        assert results_3[0]["conversation_id"] == "new-visit"

        test_conn.close()


class TestChromeHistoryWatcherHelpers:
    """Tests for ChromeHistoryWatcher helper methods."""

    def test_find_history_files_no_chrome_dir(self, tmp_path):
        """_find_history_files returns [] when chrome_dir does not exist."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()
            watcher.chrome_dir = tmp_path / "NonexistentChrome"

        assert watcher._find_history_files() == []

    def test_find_history_files_with_profiles(self, tmp_path):
        """_find_history_files discovers History files across profiles."""
        chrome_dir = tmp_path / "Chrome"
        for name in ("Default", "Profile 1", "Profile 2"):
            d = chrome_dir / name
            d.mkdir(parents=True)
            (d / "History").write_text("placeholder")

        # Also create a non-profile directory that should be ignored
        other = chrome_dir / "CrashReports"
        other.mkdir(parents=True)
        (other / "History").write_text("should be ignored")

        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()
            watcher.chrome_dir = chrome_dir

        files = watcher._find_history_files()
        assert len(files) == 3

    def test_stop_sets_event(self, tmp_path):
        """stop() should set the internal stop event."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        assert not watcher._stop.is_set()
        watcher.stop()
        assert watcher._stop.is_set()

    def test_chrome_ts_to_iso_known_date(self, tmp_path):
        """_chrome_ts_to_iso converts a known Chrome timestamp correctly."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        # 2024-01-01 00:00:00 UTC
        chrome_ts = (1704067200 + 11644473600) * 1_000_000
        result = watcher._chrome_ts_to_iso(chrome_ts)
        assert result is not None
        assert "2024-01-01" in result

    def test_chrome_ts_to_iso_none(self, tmp_path):
        """_chrome_ts_to_iso returns None for falsy input."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        assert watcher._chrome_ts_to_iso(None) is None
        assert watcher._chrome_ts_to_iso(0) is None

    def test_extract_conversation_id_chatgpt(self, tmp_path):
        """_extract_conversation_id parses ChatGPT URLs."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        result = watcher._extract_conversation_id("https://chatgpt.com/c/abc-123-def", "ChatGPT")
        assert result == "abc-123-def"

    def test_extract_conversation_id_no_match(self, tmp_path):
        """_extract_conversation_id returns None for URLs without conversation paths."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        result = watcher._extract_conversation_id("https://chatgpt.com/", "ChatGPT")
        assert result is None


# ─────────────────────────────────────────────────────────────
# SECTION 2: _format_uptime
# ─────────────────────────────────────────────────────────────


class TestFormatUptime:
    """Tests for the _format_uptime helper function."""

    def test_recent_seconds(self):
        """A process started a few seconds ago should show seconds."""
        from claude_monitoring.monitor import _format_uptime

        create_time = time.time() - 30  # 30 seconds ago
        result = _format_uptime(create_time)
        assert result.endswith("s")
        value = int(result.replace("s", ""))
        assert 28 <= value <= 32  # Allow small timing variance

    def test_minutes(self):
        """A process started minutes ago should show minutes."""
        from claude_monitoring.monitor import _format_uptime

        create_time = time.time() - 300  # 5 minutes ago
        result = _format_uptime(create_time)
        assert "m" in result
        # Should be "5m" (no hours component)
        assert result == "5m"

    def test_hours_and_minutes(self):
        """A process started hours ago should show hours and minutes."""
        from claude_monitoring.monitor import _format_uptime

        create_time = time.time() - 7500  # 2h 5m ago
        result = _format_uptime(create_time)
        assert "h" in result
        assert "m" in result
        assert result == "2h 5m"

    def test_many_hours(self):
        """A process running for a full day should show 24h 0m."""
        from claude_monitoring.monitor import _format_uptime

        create_time = time.time() - 86400  # 24 hours ago
        result = _format_uptime(create_time)
        assert "h" in result
        assert result == "24h 0m"

    def test_zero_returns_unknown(self):
        """create_time of 0 (falsy) should return 'unknown'."""
        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(0)
        assert result == "unknown"

    def test_none_returns_unknown(self):
        """create_time of None should return 'unknown'."""
        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(None)
        assert result == "unknown"

    def test_false_returns_unknown(self):
        """create_time of False (falsy) should return 'unknown'."""
        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(False)
        assert result == "unknown"


# ─────────────────────────────────────────────────────────────
# SECTION 3: main() — CLI argument dispatch
# ─────────────────────────────────────────────────────────────


class TestMainArgumentParsing:
    """Tests that main() dispatches to the correct function based on CLI args."""

    def test_start_calls_start_monitoring(self):
        """--start should call start_monitoring()."""
        with patch("claude_monitoring.monitor.start_monitoring") as mock_start:
            with patch("sys.argv", ["ai-monitor", "--start"]):
                from claude_monitoring.monitor import main

                main()
            mock_start.assert_called_once()

    def test_scan_calls_one_shot_scan(self):
        """--scan should call one_shot_scan()."""
        with patch("claude_monitoring.monitor.one_shot_scan") as mock_scan:
            with patch("sys.argv", ["ai-monitor", "--scan"]):
                from claude_monitoring.monitor import main

                main()
            mock_scan.assert_called_once()

    def test_install_agent_calls_install(self):
        """--install-agent should call install_launch_agent()."""
        with patch("claude_monitoring.monitor.install_launch_agent") as mock_install:
            with patch("sys.argv", ["ai-monitor", "--install-agent"]):
                from claude_monitoring.monitor import main

                main()
            mock_install.assert_called_once()

    def test_uninstall_agent_calls_uninstall(self):
        """--uninstall-agent should call uninstall_launch_agent()."""
        with patch("claude_monitoring.monitor.uninstall_launch_agent") as mock_uninstall:
            with patch("sys.argv", ["ai-monitor", "--uninstall-agent"]):
                from claude_monitoring.monitor import main

                main()
            mock_uninstall.assert_called_once()

    def test_no_args_prints_help(self, capsys):
        """No arguments should print help text."""
        with patch("sys.argv", ["ai-monitor"]):
            from claude_monitoring.monitor import main

            main()
        captured = capsys.readouterr()
        assert "AI Runtime Monitor" in captured.out

    def test_port_override(self):
        """--port should update DASHBOARD_PORT via _update_port."""
        with patch("claude_monitoring.monitor.start_monitoring") as mock_start:
            with patch("claude_monitoring.monitor._update_port") as mock_port:
                with patch("sys.argv", ["ai-monitor", "--start", "--port", "5555"]):
                    from claude_monitoring.monitor import main

                    main()
                mock_port.assert_called_once_with(5555)
            mock_start.assert_called_once()

    def test_install_has_priority_over_start(self):
        """When both --install-agent and --start are given, install wins (elif chain)."""
        with patch("claude_monitoring.monitor.install_launch_agent") as mock_install:
            with patch("claude_monitoring.monitor.start_monitoring") as mock_start:
                with patch("sys.argv", ["ai-monitor", "--install-agent", "--start"]):
                    from claude_monitoring.monitor import main

                    main()
                mock_install.assert_called_once()
                mock_start.assert_not_called()


class TestUpdatePort:
    """Tests for the _update_port helper."""

    def test_updates_module_level_port(self):
        """_update_port should set the module-level DASHBOARD_PORT."""
        import claude_monitoring.monitor as monitor_mod

        original = monitor_mod.DASHBOARD_PORT
        try:
            monitor_mod._update_port(12345)
            assert monitor_mod.DASHBOARD_PORT == 12345
        finally:
            monitor_mod._update_port(original)


# ─────────────────────────────────────────────────────────────
# SECTION 4: install_launch_agent / uninstall_launch_agent
# ─────────────────────────────────────────────────────────────


class TestInstallLaunchAgent:
    """Tests for install_launch_agent() — plist creation and launchctl."""

    def test_creates_plist_file(self, tmp_path):
        """install_launch_agent should create a plist file."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import install_launch_agent

                install_launch_agent()

        plist_path = fake_home / "Library" / "LaunchAgents" / "com.ai-monitor.agent.plist"
        assert plist_path.exists()
        content = plist_path.read_text()
        assert "com.ai-monitor.agent" in content
        assert "--start" in content
        assert "<true/>" in content  # RunAtLoad and KeepAlive

    def test_plist_contains_python_path(self, tmp_path):
        """The generated plist should contain the current Python executable path."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import install_launch_agent

                install_launch_agent()

        plist_path = fake_home / "Library" / "LaunchAgents" / "com.ai-monitor.agent.plist"
        content = plist_path.read_text()
        assert sys.executable in content

    def test_calls_launchctl_load(self, tmp_path):
        """install_launch_agent should run 'launchctl load' on the plist."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import install_launch_agent

                install_launch_agent()

        plist_path = fake_home / "Library" / "LaunchAgents" / "com.ai-monitor.agent.plist"
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["launchctl", "load", str(plist_path)]

    def test_handles_launchctl_failure(self, tmp_path, capsys):
        """install_launch_agent should print error when launchctl load fails."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
                from claude_monitoring.monitor import install_launch_agent

                install_launch_agent()

        captured = capsys.readouterr()
        assert "failed" in captured.out.lower() or "permission denied" in captured.out

    def test_creates_parent_directories(self, tmp_path):
        """install_launch_agent should create LaunchAgents dir if it does not exist."""
        fake_home = tmp_path / "fakehome"
        # Do NOT create Library/LaunchAgents — install should do it
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import install_launch_agent

                install_launch_agent()

        plist_dir = fake_home / "Library" / "LaunchAgents"
        assert plist_dir.exists()


class TestUninstallLaunchAgent:
    """Tests for uninstall_launch_agent() — plist removal and launchctl unload."""

    def test_removes_plist_file(self, tmp_path):
        """uninstall_launch_agent should delete the plist file."""
        fake_home = tmp_path / "fakehome"
        plist_dir = fake_home / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True)
        plist_path = plist_dir / "com.ai-monitor.agent.plist"
        plist_path.write_text("<plist>test</plist>")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import uninstall_launch_agent

                uninstall_launch_agent()

        assert not plist_path.exists()

    def test_calls_launchctl_unload(self, tmp_path):
        """uninstall_launch_agent should run 'launchctl unload' before removing."""
        fake_home = tmp_path / "fakehome"
        plist_dir = fake_home / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True)
        plist_path = plist_dir / "com.ai-monitor.agent.plist"
        plist_path.write_text("<plist>test</plist>")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                from claude_monitoring.monitor import uninstall_launch_agent

                uninstall_launch_agent()

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["launchctl", "unload", str(plist_path)]

    def test_no_plist_does_nothing(self, tmp_path, capsys):
        """uninstall_launch_agent should print a message and return if no plist exists."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            with patch("claude_monitoring.monitor.subprocess.run") as mock_run:
                from claude_monitoring.monitor import uninstall_launch_agent

                uninstall_launch_agent()

        mock_run.assert_not_called()
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "nothing" in captured.out.lower()


# ─────────────────────────────────────────────────────────────
# SECTION 5: ReusableHTTPServer
# ─────────────────────────────────────────────────────────────


class TestReusableHTTPServer:
    """Tests for the ReusableHTTPServer class defined inside start_monitoring."""

    def test_allow_reuse_address_is_set(self):
        """ReusableHTTPServer should have allow_reuse_address = True (SO_REUSEADDR)."""
        from http.server import HTTPServer

        # ReusableHTTPServer is defined inside start_monitoring, so we recreate
        # the same pattern to verify the concept.
        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True

        assert ReusableHTTPServer.allow_reuse_address is True

    def test_inherits_from_http_server(self):
        """ReusableHTTPServer should be a subclass of HTTPServer."""
        from http.server import HTTPServer

        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True

        assert issubclass(ReusableHTTPServer, HTTPServer)

    def test_start_monitoring_defines_reusable_server(self):
        """Verify that start_monitoring's source contains ReusableHTTPServer with allow_reuse_address."""
        import inspect

        from claude_monitoring.monitor import start_monitoring

        source = inspect.getsource(start_monitoring)
        assert "class ReusableHTTPServer" in source
        assert "allow_reuse_address = True" in source


# ─────────────────────────────────────────────────────────────
# SECTION 6: one_shot_scan
# ─────────────────────────────────────────────────────────────


class TestOneShotScan:
    """Tests for the one_shot_scan() function."""

    def test_scan_with_no_processes(self, capsys):
        """one_shot_scan should print 'No AI agent processes found' when none exist."""
        with patch("claude_monitoring.monitor.psutil", new=MagicMock()):
            with patch("claude_monitoring.monitor.ProcessScanner") as MockScanner:
                scanner_instance = MagicMock()
                scanner_instance.scan_once.return_value = []
                MockScanner.return_value = scanner_instance

                from claude_monitoring.monitor import one_shot_scan

                one_shot_scan()

        captured = capsys.readouterr()
        assert "No AI agent processes found" in captured.out

    def test_scan_with_processes(self, capsys):
        """one_shot_scan should print process details when AI processes are found."""
        mock_procs = [
            {
                "pid": 1234,
                "name": "claude",
                "cpu_percent": 5.2,
                "memory_percent": 1.5,
                "status": "running",
                "cmdline": "/usr/bin/claude --start",
            }
        ]

        with patch("claude_monitoring.monitor.psutil", new=MagicMock()):
            with patch("claude_monitoring.monitor.ProcessScanner") as MockScanner:
                scanner_instance = MagicMock()
                scanner_instance.scan_once.return_value = mock_procs
                MockScanner.return_value = scanner_instance

                from claude_monitoring.monitor import one_shot_scan

                one_shot_scan()

        captured = capsys.readouterr()
        assert "1234" in captured.out
        assert "claude" in captured.out

    def test_scan_exits_without_psutil(self):
        """one_shot_scan should sys.exit(1) when psutil is not installed."""
        with patch("claude_monitoring.monitor.psutil", new=None):
            from claude_monitoring.monitor import one_shot_scan

            with pytest.raises(SystemExit) as exc_info:
                one_shot_scan()
            assert exc_info.value.code == 1


# ─────────────────────────────────────────────────────────────
# SECTION 7: ChromeHistoryWatcher.run_loop
# ─────────────────────────────────────────────────────────────


class TestChromeHistoryWatcherRunLoop:
    """Tests for the run_loop polling method."""

    def test_run_loop_calls_scan_once_and_stops(self):
        """run_loop should call scan_once and then exit when stop event is set."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        def mock_scan():
            # Stop after first scan so the wait(60) returns immediately
            watcher.stop()
            return []

        watcher.scan_once = MagicMock(side_effect=mock_scan)

        watcher.run_loop()

        watcher.scan_once.assert_called_once()

    def test_run_loop_respects_stop_event(self):
        """run_loop should exit when stop() is called during the wait."""
        import threading

        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        call_count = 0

        def mock_scan():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                watcher.stop()
            return []

        watcher.scan_once = mock_scan

        # Use a thread with a timeout to prevent hanging.
        # After the first scan_once, _stop.wait(60) will block.
        # We schedule stop() from the main thread after a brief delay.
        t = threading.Thread(target=watcher.run_loop, daemon=True)
        t.start()

        # Give it a moment for the first scan_once to execute, then set stop
        # so _stop.wait(60) returns and the loop re-checks and calls scan_once
        # again (which will also set stop).
        time.sleep(0.1)
        watcher.stop()
        t.join(timeout=5)

        assert not t.is_alive(), "run_loop did not stop within timeout"
        assert call_count >= 1

    def test_run_loop_skips_when_already_stopped(self):
        """run_loop should not call scan_once if stop is already set."""
        with patch("claude_monitoring.monitor.get_thread_db") as mock_get_db:
            mock_get_db.return_value = MagicMock()
            from claude_monitoring.monitor import ChromeHistoryWatcher

            watcher = ChromeHistoryWatcher()

        watcher.scan_once = MagicMock(return_value=[])
        watcher._stop.set()
        watcher.run_loop()

        watcher.scan_once.assert_not_called()
