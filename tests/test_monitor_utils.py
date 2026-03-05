"""Tests for monitor.py utility functions and scanner classes.

Covers:
  - push_live_event: live feed deque behavior and thread safety
  - compute_forecast: token burn rate calculations and trend detection
  - detect_plan_info: subscription detection from config files
  - ProcessScanner: AI process scanning with mocked psutil
  - NetworkMonitor: network connection scanning with mocked psutil
"""

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Helper: create a DB connection with row_factory=sqlite3.Row
# (compute_forecast accesses rows by column name)
# ---------------------------------------------------------------------------


def _make_db(tmp_path):
    """Create a test DB and return a Row-factory connection."""
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _insert_token_event(conn, day_str, input_tokens, output_tokens, session_id="sess-1"):
    """Insert a token_usage event into the events table for a given day."""
    timestamp = f"{day_str}T12:00:00+00:00"
    data = json.dumps({"input_tokens": input_tokens, "output_tokens": output_tokens})
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (timestamp, session_id, "token_usage", "network", data),
    )
    conn.commit()


# ===================================================================
# 1. push_live_event
# ===================================================================


class TestPushLiveEvent:
    """Tests for the push_live_event utility."""

    def setup_method(self):
        """Snapshot and restore the live_feed between tests."""
        import claude_monitoring.monitor as mod

        self._original_feed = mod.live_feed.copy()

    def teardown_method(self):
        import claude_monitoring.monitor as mod

        mod.live_feed.clear()
        mod.live_feed.extend(self._original_feed)

    def test_push_event_appears_in_feed(self):
        from claude_monitoring.monitor import live_feed, push_live_event

        live_feed.clear()
        event = {"event_type": "test", "summary": "hello"}
        push_live_event(event)
        assert len(live_feed) == 1
        assert live_feed[-1] is event

    def test_push_multiple_events_ordering(self):
        from claude_monitoring.monitor import live_feed, push_live_event

        live_feed.clear()
        for i in range(5):
            push_live_event({"seq": i})
        assert len(live_feed) == 5
        assert [e["seq"] for e in live_feed] == [0, 1, 2, 3, 4]

    def test_maxlen_caps_at_500(self):
        from claude_monitoring.monitor import live_feed, push_live_event

        live_feed.clear()
        for i in range(600):
            push_live_event({"seq": i})
        assert len(live_feed) == 500
        # Oldest events should have been evicted; first remaining is seq=100
        assert live_feed[0]["seq"] == 100
        assert live_feed[-1]["seq"] == 599

    def test_thread_safety(self):
        """Push from multiple threads concurrently — no crashes, no lost events."""
        from claude_monitoring.monitor import live_feed, push_live_event

        live_feed.clear()
        num_threads = 10
        events_per_thread = 40  # total 400 < maxlen 500

        def worker(thread_id):
            for j in range(events_per_thread):
                push_live_event({"tid": thread_id, "seq": j})

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(live_feed) == num_threads * events_per_thread


# ===================================================================
# 2. compute_forecast
# ===================================================================


class TestComputeForecast:
    """Tests for compute_forecast token burn calculations."""

    def test_empty_db_returns_defaults(self, tmp_path):
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        forecast = compute_forecast(conn)
        assert forecast["daily_burn_rate"] == 0
        assert forecast["avg_7d_burn"] == 0
        assert forecast["daily_breakdown"] == []
        assert forecast["burn_trend"] == "stable"
        assert forecast["days_remaining"] is None
        conn.close()

    def test_single_day_data(self, tmp_path):
        conn = _make_db(tmp_path)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _insert_token_event(conn, today, 1000, 500)

        from claude_monitoring.monitor import compute_forecast

        forecast = compute_forecast(conn)

        assert len(forecast["daily_breakdown"]) == 1
        day_entry = forecast["daily_breakdown"][0]
        assert day_entry["input_tokens"] == 1000
        assert day_entry["output_tokens"] == 500
        assert day_entry["total_tokens"] == 1500
        # With only 1 day, avg_7d and daily_burn both come from that single day
        assert forecast["avg_7d_burn"] == 1500
        assert forecast["daily_burn_rate"] == 1500
        conn.close()

    def test_daily_breakdown_multiple_days(self, tmp_path):
        conn = _make_db(tmp_path)

        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        for i in range(5):
            day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            _insert_token_event(conn, day, 1000 * (i + 1), 500 * (i + 1))

        forecast = compute_forecast(conn)
        assert len(forecast["daily_breakdown"]) == 5
        # Each day should have correct totals
        for entry in forecast["daily_breakdown"]:
            assert entry["total_tokens"] == entry["input_tokens"] + entry["output_tokens"]
        conn.close()

    def test_avg_7d_burn_calculation(self, tmp_path):
        """Insert exactly 7 days of data with known totals."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        daily_totals = []
        for i in range(7):
            day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
            inp = 1000
            out = 1000
            _insert_token_event(conn, day, inp, out)
            daily_totals.append(inp + out)

        forecast = compute_forecast(conn)
        expected_avg = int(sum(daily_totals) / 7)
        assert forecast["avg_7d_burn"] == expected_avg
        conn.close()

    def test_daily_burn_rate_uses_last_3(self, tmp_path):
        """daily_burn_rate should average the last 3 days of data."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        values = [100, 200, 300, 400, 500, 600, 700]
        for i, val in enumerate(values):
            day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
            _insert_token_event(conn, day, val, 0)

        forecast = compute_forecast(conn)
        last_3 = values[-3:]  # [500, 600, 700]
        expected = int(sum(last_3) / 3)
        assert forecast["daily_burn_rate"] == expected
        conn.close()

    def test_burn_trend_increasing(self, tmp_path):
        """Recent 3 days much higher than previous 4 days -> 'increasing'."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        # First 4 days: low usage (100 each)
        # Last 3 days: high usage (500 each)
        # ratio = 500/100 = 5.0 > 1.3 -> increasing
        for i in range(7):
            day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
            tokens = 100 if i < 4 else 500
            _insert_token_event(conn, day, tokens, 0)

        forecast = compute_forecast(conn)
        assert forecast["burn_trend"] == "increasing"
        conn.close()

    def test_burn_trend_decreasing(self, tmp_path):
        """Recent 3 days much lower than previous 4 days -> 'decreasing'."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        # First 4 days: high usage (500 each)
        # Last 3 days: low usage (100 each)
        # ratio = 100/500 = 0.2 < 0.7 -> decreasing
        for i in range(7):
            day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
            tokens = 500 if i < 4 else 100
            _insert_token_event(conn, day, tokens, 0)

        forecast = compute_forecast(conn)
        assert forecast["burn_trend"] == "decreasing"
        conn.close()

    def test_burn_trend_stable(self, tmp_path):
        """Similar usage across all 7 days -> 'stable'."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        for i in range(7):
            day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
            _insert_token_event(conn, day, 1000, 0)

        forecast = compute_forecast(conn)
        assert forecast["burn_trend"] == "stable"
        conn.close()

    def test_burn_trend_stable_with_fewer_than_7_days(self, tmp_path):
        """With <7 days of data, trend detection is skipped -> stays 'stable'."""
        conn = _make_db(tmp_path)
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        for i in range(5):
            day = (now - timedelta(days=4 - i)).strftime("%Y-%m-%d")
            _insert_token_event(conn, day, 1000 * (i + 1), 0)

        forecast = compute_forecast(conn)
        assert forecast["burn_trend"] == "stable"
        conn.close()

    def test_subscription_forecast_with_plan_info(self, tmp_path):
        """When plan_info indicates a subscription, forecast includes monthly limit."""
        conn = _make_db(tmp_path)

        import claude_monitoring.monitor as mod
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        for i in range(3):
            day = (now - timedelta(days=2 - i)).strftime("%Y-%m-%d")
            _insert_token_event(conn, day, 10000, 5000)

        saved_plan = mod.plan_info.copy()
        try:
            mod.plan_info = {"is_subscription": True, "plan_tier": "pro"}
            forecast = compute_forecast(conn)
            assert forecast["monthly_limit"] == 45_000_000
            assert forecast["plan_label"] == "Pro"
            assert forecast["monthly_used"] >= 0
            # days_remaining should be set since daily_burn_rate > 0
            assert forecast["days_remaining"] is not None
            assert forecast["days_remaining"] >= 0
        finally:
            mod.plan_info = saved_plan
        conn.close()

    def test_subscription_forecast_defaults_to_pro(self, tmp_path):
        """Unknown plan tier defaults to Pro limits."""
        conn = _make_db(tmp_path)

        import claude_monitoring.monitor as mod
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        _insert_token_event(conn, day, 1000, 500)

        saved_plan = mod.plan_info.copy()
        try:
            mod.plan_info = {"is_subscription": True, "plan_tier": "unknown_tier_xyz"}
            forecast = compute_forecast(conn)
            # Falls through loop, defaults to Pro
            assert forecast["monthly_limit"] == 45_000_000
            assert forecast["plan_label"] == "Pro"
        finally:
            mod.plan_info = saved_plan
        conn.close()

    def test_subscription_days_remaining_zero_when_exhausted(self, tmp_path):
        """When monthly_used exceeds the limit, days_remaining should be 0."""
        conn = _make_db(tmp_path)

        import claude_monitoring.monitor as mod
        from claude_monitoring.monitor import compute_forecast

        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        # Insert a huge amount that exceeds pro monthly limit
        _insert_token_event(conn, day, 50_000_000, 0)

        saved_plan = mod.plan_info.copy()
        try:
            mod.plan_info = {"is_subscription": True, "plan_tier": "pro"}
            forecast = compute_forecast(conn)
            assert forecast["days_remaining"] == 0
        finally:
            mod.plan_info = saved_plan
        conn.close()


# ===================================================================
# 3. detect_plan_info
# ===================================================================


class TestDetectPlanInfo:
    """Tests for detect_plan_info subscription/plan detection."""

    def setup_method(self):
        """Save and restore plan_info between tests."""
        import claude_monitoring.monitor as mod

        self._saved_plan_info = mod.plan_info.copy()

    def teardown_method(self):
        import claude_monitoring.monitor as mod

        mod.plan_info = self._saved_plan_info

    def test_no_config_files_assumes_subscription(self, tmp_path):
        """With no .claude directory at all, detect_plan_info assumes subscription."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is True
        assert info["cost_label"] == "Subscription"

    def test_stats_cache_all_zero_costs(self, tmp_path):
        """stats-cache.json with all zero costUSD -> subscription."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        stats = {
            "modelUsage": {
                "claude-sonnet-4": {"costUSD": 0, "inputTokens": 1000},
                "claude-opus-4": {"costUSD": 0, "inputTokens": 2000},
            }
        }
        (claude_dir / "stats-cache.json").write_text(json.dumps(stats))

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is True

    def test_stats_cache_nonzero_costs_not_subscription(self, tmp_path):
        """stats-cache.json with non-zero costUSD -> not flagged as subscription by stats alone."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        stats = {
            "modelUsage": {
                "claude-sonnet-4": {"costUSD": 0.50, "inputTokens": 1000},
            }
        }
        (claude_dir / "stats-cache.json").write_text(json.dumps(stats))
        # Also create api_key file so the fallback does not trigger subscription
        (claude_dir / "api_key").write_text("sk-ant-test")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is False

    def test_credentials_with_subscription_type(self, tmp_path):
        """credentials.json with subscriptionType -> subscription detected with tier."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        creds = {
            "claudeAiOauth": {
                "subscriptionType": "max_5x",
                "rateLimitTier": "tier4",
            }
        }
        (claude_dir / ".credentials.json").write_text(json.dumps(creds))

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is True
        assert info["plan_tier"] == "max_5x"
        assert info["rate_tier"] == "tier4"
        assert "max_5x" in info["cost_label"]

    def test_credentials_rate_tier_fallback(self, tmp_path):
        """credentials.json with only rateLimitTier (no subscriptionType) sets plan_tier
        but does NOT flag is_subscription since there is no explicit subscriptionType.
        The api_key fallback also does not trigger because plan_tier is already set."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        creds = {
            "claudeAiOauth": {
                "rateLimitTier": "pro",
            }
        }
        (claude_dir / ".credentials.json").write_text(json.dumps(creds))

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        # rateLimitTier alone does not set is_subscription; it only populates plan_tier
        assert info["is_subscription"] is False
        assert info["plan_tier"] == "pro"
        assert info["rate_tier"] == "pro"

    def test_credentials_rate_tier_with_subscription_type(self, tmp_path):
        """credentials.json with both subscriptionType and rateLimitTier -> subscription."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        creds = {
            "claudeAiOauth": {
                "subscriptionType": "pro",
                "rateLimitTier": "tier2",
            }
        }
        (claude_dir / ".credentials.json").write_text(json.dumps(creds))

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is True
        assert info["plan_tier"] == "pro"
        assert info["rate_tier"] == "tier2"

    def test_api_key_file_exists_no_subscription(self, tmp_path):
        """api_key file exists and no credentials -> not subscription (API user)."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        (claude_dir / "api_key").write_text("sk-ant-12345")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        assert info["is_subscription"] is False
        assert info["cost_label"] == "Total Cost"

    def test_malformed_stats_cache_gracefully_handled(self, tmp_path):
        """Malformed JSON in stats-cache.json should not crash."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        (claude_dir / "stats-cache.json").write_text("{invalid json!!")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            # Should not raise
            info = detect_plan_info()

        # Fallback: no api_key, no credentials -> assumes subscription
        assert info["is_subscription"] is True

    def test_malformed_credentials_gracefully_handled(self, tmp_path):
        """Malformed JSON in .credentials.json should not crash."""
        from claude_monitoring.monitor import detect_plan_info

        fake_home = tmp_path / "fakehome"
        claude_dir = fake_home / ".claude"
        claude_dir.mkdir(parents=True)

        (claude_dir / ".credentials.json").write_text("not json")
        (claude_dir / "api_key").write_text("sk-ant-12345")

        with patch("claude_monitoring.monitor.Path.home", return_value=fake_home):
            info = detect_plan_info()

        # Has api_key, no valid credentials -> not subscription
        assert info["is_subscription"] is False


# ===================================================================
# 4. ProcessScanner
# ===================================================================


def _make_mock_process(pid, name, cmdline_list, cpu=1.0, mem=0.5, status="running", exe_path=""):
    """Create a mock psutil.Process-like object for process_iter."""
    proc = MagicMock()
    create_time = time.time() - 3600  # started 1 hour ago
    proc.info = {
        "pid": pid,
        "name": name,
        "cmdline": cmdline_list,
        "cpu_percent": cpu,
        "memory_percent": mem,
        "create_time": create_time,
        "status": status,
    }
    proc.exe.return_value = exe_path
    return proc


class TestProcessScanner:
    """Tests for ProcessScanner.scan_once with mocked psutil."""

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_finds_ai_processes(self, mock_get_db):
        """scan_once should return only processes matching is_ai_process."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        claude_proc = _make_mock_process(1001, "claude", ["claude", "--help"])
        safari_proc = _make_mock_process(1002, "Safari", ["Safari"])

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [claude_proc, safari_proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            found = scanner.scan_once()

        assert len(found) == 1
        assert found[0]["pid"] == 1001
        assert found[0]["name"] == "claude"
        assert "claude --help" in found[0]["cmdline"]

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_records_process_data(self, mock_get_db):
        """Returned process data has all expected keys."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(2001, "claude", ["claude", "chat"], cpu=5.2, mem=1.3, status="running")

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            found = scanner.scan_once()

        assert len(found) == 1
        data = found[0]
        assert data["pid"] == 2001
        assert data["cpu_percent"] == 5.2
        assert data["memory_percent"] == 1.3
        assert data["status"] == "running"
        assert "create_time" in data
        assert data["create_time"]  # non-empty

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_detects_new_process(self, mock_get_db):
        """First scan should add PID to known_pids and insert into DB."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(3001, "claude", ["claude"])

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            scanner.scan_once()

        assert 3001 in scanner.known_pids
        # DB insert should have been called
        mock_db.execute.assert_called()

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_detects_terminated_process(self, mock_get_db):
        """Process disappears on second scan -> detected as terminated."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(4001, "claude", ["claude"])

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            scanner.scan_once()  # first scan: detect process
            assert 4001 in scanner.known_pids

            # Second scan: process gone
            mock_psutil.process_iter.return_value = []
            scanner.scan_once()

        assert 4001 not in scanner.known_pids

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_terminated_updates_db(self, mock_get_db):
        """Terminated process should trigger DB update with end_time."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(5001, "claude", ["claude"])

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            scanner.scan_once()
            mock_db.reset_mock()

            # Second scan: process gone
            mock_psutil.process_iter.return_value = []
            scanner.scan_once()

        # Check that an UPDATE with 'terminated' was executed
        update_calls = [call for call in mock_db.execute.call_args_list if "terminated" in str(call)]
        assert len(update_calls) >= 1

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_returns_empty_when_psutil_none(self, mock_get_db):
        """When psutil is None, scan_once should return an empty list."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil", None):
            found = scanner.scan_once()

        assert found == []

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_handles_access_denied(self, mock_get_db):
        """AccessDenied on proc.exe() should not crash the scanner."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(6001, "claude", ["claude"])

        # Make exe() raise AccessDenied
        access_denied = type("AccessDenied", (Exception,), {})
        proc.exe.side_effect = access_denied()

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = access_denied
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            found = scanner.scan_once()

        # Should still find the process (exe_path defaults to "" on AccessDenied)
        assert len(found) == 1

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_once_updates_existing_process(self, mock_get_db):
        """Second scan of same PID should update, not re-insert."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        proc = _make_mock_process(7001, "claude", ["claude"], cpu=1.0)

        scanner = ProcessScanner()
        scanner.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            scanner.scan_once()  # first scan: INSERT
            mock_db.reset_mock()

            # Update cpu
            proc.info["cpu_percent"] = 10.0
            scanner.scan_once()  # second scan: UPDATE

        # Should have done an UPDATE (not INSERT) on second scan
        update_calls = [call for call in mock_db.execute.call_args_list if "UPDATE" in str(call)]
        assert len(update_calls) >= 1

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_stop_flag(self, mock_get_db):
        """Setting stop() should set the internal _stop event."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import ProcessScanner

        scanner = ProcessScanner()
        scanner.db = mock_db

        assert not scanner._stop.is_set()
        scanner.stop()
        assert scanner._stop.is_set()


# ===================================================================
# 5. NetworkMonitor
# ===================================================================


class TestNetworkMonitor:
    """Tests for NetworkMonitor.scan_once with mocked psutil."""

    def _make_connection(self, remote_ip, remote_port, status="ESTABLISHED"):
        """Create a mock psutil connection object."""
        conn = MagicMock()
        conn.status = status
        if remote_ip is not None:
            raddr = MagicMock()
            raddr.ip = remote_ip
            raddr.port = remote_port
            conn.raddr = raddr
        else:
            conn.raddr = None
        return conn

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_returns_empty_when_psutil_none(self, mock_get_db):
        """When psutil is None, scan_once should return empty."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil", None):
            found = monitor.scan_once()

        assert found == []

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_finds_established_connections(self, mock_get_db):
        """Established connections from AI processes should be captured."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        mock_conn = self._make_connection("104.18.0.1", 443)

        proc = MagicMock()
        proc.info = {
            "pid": 8001,
            "name": "claude",
            "cmdline": ["claude"],
        }
        proc.net_connections.return_value = [mock_conn]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found = monitor.scan_once()

        assert len(found) == 1
        assert found[0]["pid"] == 8001
        assert found[0]["remote_port"] == 443

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_skips_non_established(self, mock_get_db):
        """Only ESTABLISHED connections should be captured."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        listening_conn = self._make_connection("0.0.0.0", 80, status="LISTEN")

        proc = MagicMock()
        proc.info = {
            "pid": 8002,
            "name": "claude",
            "cmdline": ["claude"],
        }
        proc.net_connections.return_value = [listening_conn]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found = monitor.scan_once()

        assert len(found) == 0

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_skips_connections_without_raddr(self, mock_get_db):
        """Connections with no remote address should be skipped."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        no_raddr_conn = self._make_connection(None, None)
        no_raddr_conn.status = "ESTABLISHED"
        no_raddr_conn.raddr = None

        proc = MagicMock()
        proc.info = {
            "pid": 8003,
            "name": "claude",
            "cmdline": ["claude"],
        }
        proc.net_connections.return_value = [no_raddr_conn]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found = monitor.scan_once()

        assert len(found) == 0

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_deduplicates_connections(self, mock_get_db):
        """Same (pid, host, port) seen twice should only be reported once."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        conn1 = self._make_connection("1.2.3.4", 443)

        proc = MagicMock()
        proc.info = {
            "pid": 8004,
            "name": "claude",
            "cmdline": ["claude"],
        }
        proc.net_connections.return_value = [conn1]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found1 = monitor.scan_once()
            found2 = monitor.scan_once()  # same connection again

        assert len(found1) == 1
        assert len(found2) == 0  # deduplicated

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_skips_non_ai_processes(self, mock_get_db):
        """Non-AI processes should be skipped entirely."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        proc = MagicMock()
        proc.info = {
            "pid": 8005,
            "name": "Safari",
            "cmdline": ["Safari"],
        }
        # net_connections should never be called
        proc.net_connections.return_value = [self._make_connection("1.2.3.4", 443)]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found = monitor.scan_once()

        assert len(found) == 0

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_scan_resolves_known_service(self, mock_get_db):
        """Connection to a known AI host should resolve to a service name."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        # "api.anthropic.com" should match AI_HOSTS
        mock_conn = self._make_connection("api.anthropic.com", 443)

        proc = MagicMock()
        proc.info = {
            "pid": 8006,
            "name": "claude",
            "cmdline": ["claude"],
        }
        proc.net_connections.return_value = [mock_conn]

        monitor = NetworkMonitor()
        monitor.db = mock_db

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            found = monitor.scan_once()

        assert len(found) == 1
        # Service should be resolved (not "unknown")
        assert found[0]["service"] != "unknown"

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_stop_flag(self, mock_get_db):
        """Setting stop() should set the internal _stop event."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        monitor = NetworkMonitor()
        monitor.db = mock_db

        assert not monitor._stop.is_set()
        monitor.stop()
        assert monitor._stop.is_set()

    @patch("claude_monitoring.monitor.get_thread_db")
    def test_seen_connections_cleanup_at_threshold(self, mock_get_db):
        """seen_connections set should be cleared when it exceeds 10000 entries."""
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        from claude_monitoring.monitor import NetworkMonitor

        monitor = NetworkMonitor()
        monitor.db = mock_db

        # Pre-populate seen_connections beyond the threshold
        for i in range(10001):
            monitor.seen_connections.add((i, f"host-{i}", 443))

        assert len(monitor.seen_connections) > 10000

        with patch("claude_monitoring.monitor.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = []
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})

            monitor.scan_once()

        assert len(monitor.seen_connections) == 0
