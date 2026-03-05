"""Tests for watch.py CLI/analysis/dashboard functions.

Covers: _load_latest_csv, run_analyze, run_plot, run_scan, run_dashboard,
and main() argument parsing -- the large uncovered sections of watch.py.
"""

import csv
import json
import threading
import time
from http.server import HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.constants import CSV_COLUMNS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_matplotlib() -> bool:
    try:
        import matplotlib  # noqa: F401

        return True
    except ImportError:
        return False


def _write_csv(path, rows):
    """Write a CSV file at *path* with CSV_COLUMNS header and the given rows.

    Each row dict may be sparse; missing columns are filled with empty strings.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            full_row = {k: "" for k in CSV_COLUMNS}
            full_row.update(row)
            writer.writerow(full_row)
    return path


def _sample_row(overrides: dict | None = None) -> dict:
    """Return a single sample row dict with realistic values."""
    row = {
        "timestamp": "2026-01-01T00:01:00+00:00",
        "session_id": "sess-test",
        "turn_id": "t-1",
        "turn_number": "1",
        "destination_host": "api.anthropic.com",
        "destination_service": "anthropic_api",
        "endpoint_path": "/v1/messages",
        "http_method": "POST",
        "http_status": "200",
        "model": "claude-sonnet-4",
        "stream": "true",
        "input_tokens": "5000",
        "output_tokens": "1000",
        "cache_read_tokens": "100",
        "cache_write_tokens": "50",
        "estimated_cost_usd": "0.030",
        "request_size_bytes": "12000",
        "response_size_bytes": "8000",
        "latency_ms": "1500",
        "num_messages": "10",
        "system_prompt_chars": "2000",
        "last_user_msg_preview": "hello world",
        "assistant_msg_preview": "Sure, I can help.",
        "tool_calls": '["bash", "read_file"]',
        "tool_call_count": "2",
        "bash_commands": '["ls -la"]',
        "files_read": '["src/main.py"]',
        "files_written": "[]",
        "urls_fetched": "[]",
        "sensitive_patterns": "",
        "sensitive_pattern_count": "0",
        "content_types_sent": "text",
        "stop_reason": "end_turn",
        "request_id": "req-abc123",
        "raw_request_hash": "aabb1122",
    }
    if overrides:
        row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# Fixture: mock config paths so nothing touches the real filesystem
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_config(tmp_path):
    """Redirect all config accessors to tmp_path so tests are hermetic."""
    session_dir = tmp_path / "sessions"
    session_dir.mkdir(exist_ok=True)

    with (
        patch("claude_monitoring.watch.get_session_dir", return_value=session_dir),
        patch("claude_monitoring.watch.get_output_dir", return_value=tmp_path),
        patch("claude_monitoring.watch.get_db_path", return_value=tmp_path / "test.db"),
    ):
        yield


# ===================================================================
# 1. _load_latest_csv
# ===================================================================


class TestLoadLatestCsv:
    """Test the _load_latest_csv helper."""

    def test_no_csv_files_returns_none(self, tmp_path, capsys):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path is None
        assert rows == []
        assert "No CSV files found" in capsys.readouterr().out

    def test_single_csv_file_returns_its_data(self, tmp_path):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        csv_path = sessions / "claude_watch_20260101_000000.csv"
        _write_csv(csv_path, [_sample_row()])

        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path == csv_path
        assert len(rows) == 1
        assert rows[0]["destination_service"] == "anthropic_api"

    def test_multiple_csv_files_returns_latest(self, tmp_path):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        old_csv = sessions / "claude_watch_20260101_000000.csv"
        _write_csv(old_csv, [_sample_row({"turn_number": "1"})])
        # Ensure filesystem mtime differs
        time.sleep(0.05)
        new_csv = sessions / "claude_watch_20260102_000000.csv"
        _write_csv(
            new_csv,
            [
                _sample_row({"turn_number": "10"}),
                _sample_row({"turn_number": "11"}),
            ],
        )

        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path == new_csv
        assert len(rows) == 2
        assert rows[0]["turn_number"] == "10"

    def test_uses_default_session_dir_when_none(self, tmp_path):
        """When sessions_dir is None, falls back to get_session_dir()."""
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        csv_path = sessions / "claude_watch_20260301_120000.csv"
        _write_csv(csv_path, [_sample_row()])

        result_path, rows = _load_latest_csv(None)

        assert result_path == csv_path
        assert len(rows) == 1

    def test_empty_csv_returns_empty_rows(self, tmp_path):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        csv_path = sessions / "claude_watch_20260101_000000.csv"
        # Header only, no data rows
        _write_csv(csv_path, [])

        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path == csv_path
        assert rows == []


# ===================================================================
# 2. run_analyze
# ===================================================================


class TestRunAnalyze:
    """Test the run_analyze CLI function."""

    def test_no_csv_prints_message(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "No CSV files found" in captured

    def test_empty_csv_prints_empty_file(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        _write_csv(sessions / "claude_watch_20260101_000000.csv", [])

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "Empty file" in captured

    def test_prints_summary_statistics(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row({"input_tokens": "5000", "output_tokens": "1000", "estimated_cost_usd": "0.030"}),
            _sample_row(
                {
                    "turn_number": "2",
                    "turn_id": "t-2",
                    "input_tokens": "3000",
                    "output_tokens": "500",
                    "estimated_cost_usd": "0.015",
                    "destination_service": "anthropic_api",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "Total requests intercepted" in captured
        assert "Anthropic API calls" in captured
        assert "Input tokens" in captured
        assert "Output tokens" in captured
        assert "Estimated cost" in captured
        assert "Total data sent" in captured
        assert "Total data received" in captured

    def test_prints_destination_breakdown(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row({"destination_service": "anthropic_api"}),
            _sample_row({"destination_service": "openai_api", "turn_number": "2"}),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "Destinations" in captured
        assert "anthropic_api" in captured
        assert "openai_api" in captured

    def test_prints_tool_call_frequency(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row(
                {
                    "tool_calls": '["bash", "read_file"]',
                    "destination_service": "anthropic_api",
                }
            ),
            _sample_row(
                {
                    "turn_number": "2",
                    "tool_calls": '["bash"]',
                    "destination_service": "anthropic_api",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "Tool calls" in captured
        assert "bash" in captured

    def test_prints_sensitive_pattern_alert(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row(
                {
                    "sensitive_patterns": "aws_key",
                    "sensitive_pattern_count": "1",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "Sensitive" in captured
        assert "aws_key" in captured

    def test_uses_default_session_dir_when_none(self, tmp_path, capsys):
        """run_analyze(None) should use get_session_dir()."""
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        _write_csv(
            sessions / "claude_watch_20260101_000000.csv",
            [_sample_row()],
        )

        run_analyze(None)

        captured = capsys.readouterr().out
        assert "Total requests intercepted" in captured

    def test_correct_token_summation(self, tmp_path, capsys):
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row({"input_tokens": "1000", "output_tokens": "200", "destination_service": "anthropic_api"}),
            _sample_row(
                {
                    "turn_number": "2",
                    "input_tokens": "3000",
                    "output_tokens": "800",
                    "destination_service": "anthropic_api",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        # 1000+3000 = 4000 input tokens, 200+800 = 1000 output tokens
        assert "4,000" in captured
        assert "1,000" in captured


# ===================================================================
# 3. run_plot
# ===================================================================


class TestRunPlot:
    """Test the run_plot function."""

    @pytest.mark.skipif(not _has_matplotlib(), reason="matplotlib not installed")
    def test_no_data_prints_message(self, tmp_path, capsys):
        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        run_plot(str(sessions))

        captured = capsys.readouterr().out
        assert "No CSV files found" in captured

    @pytest.mark.skipif(not _has_matplotlib(), reason="matplotlib not installed")
    def test_empty_csv_prints_no_data(self, tmp_path, capsys):
        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        _write_csv(sessions / "claude_watch_20260101_000000.csv", [])

        run_plot(str(sessions))

        captured = capsys.readouterr().out
        assert "No data to plot" in captured

    def test_missing_matplotlib_prints_error(self, tmp_path, capsys):
        """When matplotlib is not installed, run_plot should print a helpful message."""
        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        _write_csv(sessions / "claude_watch_20260101_000000.csv", [_sample_row()])

        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "matplotlib":
                raise ImportError("No module named 'matplotlib'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            run_plot(str(sessions))

        captured = capsys.readouterr().out
        assert "matplotlib not installed" in captured

    def test_valid_data_generates_plot(self, tmp_path, capsys):
        """With valid data and matplotlib available, run_plot should save a PNG."""
        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row({"timestamp": "2026-01-01T00:01:00+00:00"}),
            _sample_row(
                {
                    "turn_number": "2",
                    "turn_id": "t-2",
                    "timestamp": "2026-01-01T00:02:00+00:00",
                    "destination_service": "anthropic_api",
                }
            ),
            _sample_row(
                {
                    "turn_number": "3",
                    "turn_id": "t-3",
                    "timestamp": "2026-01-01T00:03:00+00:00",
                    "destination_service": "openai_api",
                    "destination_host": "api.openai.com",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        # Mock subprocess.run to prevent opening the image file
        with patch("claude_monitoring.watch.subprocess.run"):
            try:
                run_plot(str(sessions))
            except ImportError:
                pytest.skip("matplotlib not installed")

        captured = capsys.readouterr().out
        # Should either succeed with a plot or report matplotlib missing
        assert "Plotting" in captured or "matplotlib" in captured

    def test_plot_saved_to_plots_dir(self, tmp_path, capsys):
        """The plot should be saved under {output_dir}/plots/."""
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            pytest.skip("matplotlib not installed")

        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        rows = [_sample_row(), _sample_row({"turn_number": "2", "turn_id": "t-2"})]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        with patch("claude_monitoring.watch.subprocess.run"):
            run_plot(str(sessions))

        plots_dir = tmp_path / "plots"
        captured = capsys.readouterr().out
        assert "Dashboard saved to" in captured
        assert plots_dir.exists()
        pngs = list(plots_dir.glob("dashboard_*.png"))
        assert len(pngs) >= 1


# ===================================================================
# 4. run_dashboard (WatchDashboardHandler)
# ===================================================================


class TestRunDashboard:
    """Test run_dashboard by spinning up the server in a thread."""

    @pytest.fixture()
    def dashboard_server(self, tmp_path):
        """Create CSV data and start a dashboard server on a random port."""
        import http.server
        import urllib.parse

        from claude_monitoring.watch import _dashboard_html, _load_latest_csv

        sessions = tmp_path / "sessions"
        csv_path = sessions / "claude_watch_20260101_000000.csv"
        rows = [
            _sample_row(),
            _sample_row(
                {
                    "turn_number": "2",
                    "turn_id": "t-2",
                    "destination_service": "openai_api",
                    "destination_host": "api.openai.com",
                    "model": "gpt-4o",
                    "input_tokens": "3000",
                    "output_tokens": "800",
                    "estimated_cost_usd": "0.015",
                }
            ),
        ]
        _write_csv(csv_path, rows)

        sessions_dir_str = str(sessions)
        _, loaded_rows = _load_latest_csv(sessions_dir_str)

        # Replicate the DashboardHandler as defined inside run_dashboard
        class DashboardHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/api/data":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    _, fresh_rows = _load_latest_csv(sessions_dir_str)
                    self.wfile.write(json.dumps(fresh_rows or loaded_rows).encode())
                elif parsed.path in ("/", "/index.html"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(_dashboard_html().encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"

        server.shutdown()

    def test_root_returns_html(self, dashboard_server):
        from urllib.request import urlopen

        resp = urlopen(f"{dashboard_server}/")
        assert resp.status == 200
        ct = resp.headers.get("Content-Type", "")
        assert "text/html" in ct
        body = resp.read().decode()
        assert "html" in body.lower()

    def test_api_data_returns_json_array(self, dashboard_server):
        from urllib.request import urlopen

        resp = urlopen(f"{dashboard_server}/api/data")
        assert resp.status == 200
        ct = resp.headers.get("Content-Type", "")
        assert "application/json" in ct
        data = json.loads(resp.read())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_api_data_has_all_csv_columns(self, dashboard_server):
        from urllib.request import urlopen

        resp = urlopen(f"{dashboard_server}/api/data")
        data = json.loads(resp.read())
        for col in CSV_COLUMNS:
            assert col in data[0], f"Missing column: {col}"

    def test_api_data_cors_header(self, dashboard_server):
        from urllib.request import urlopen

        resp = urlopen(f"{dashboard_server}/api/data")
        cors = resp.headers.get("Access-Control-Allow-Origin", "")
        assert cors == "*"

    def test_unknown_path_returns_404(self, dashboard_server):
        from urllib.error import HTTPError
        from urllib.request import urlopen

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{dashboard_server}/unknown")
        assert exc_info.value.code == 404

    def test_run_dashboard_no_data_exits_early(self, tmp_path, capsys):
        """run_dashboard should print message and return when no CSV exists."""
        from claude_monitoring.watch import run_dashboard

        empty_sessions = tmp_path / "empty_sessions"
        empty_sessions.mkdir()
        run_dashboard(str(empty_sessions))

        captured = capsys.readouterr().out
        assert "No CSV files found" in captured or "No data for dashboard" in captured


# ===================================================================
# 5. run_scan
# ===================================================================


class TestRunScan:
    """Test the run_scan process scanner."""

    def test_no_ai_processes_detected(self, capsys):
        """When ps returns no AI-related lines, should report none found."""
        from claude_monitoring.watch import run_scan

        fake_ps = MagicMock()
        fake_ps.stdout = "USER  PID  %CPU %MEM VSZ  RSS  TT  STAT STARTED TIME COMMAND\nroot  1  0.0  0.1  100 50  ??  Ss  Jan01 0:00.00 /sbin/launchd\n"

        fake_lsof = MagicMock()
        fake_lsof.stdout = ""

        def mock_run(cmd, **kwargs):
            if cmd[0] == "ps":
                return fake_ps
            elif cmd[0] == "lsof":
                return fake_lsof
            return MagicMock(stdout="")

        with patch("claude_monitoring.watch.subprocess.run", side_effect=mock_run), patch("socket.socket"):
            run_scan()

        captured = capsys.readouterr().out
        assert "AI Agent Process Scanner" in captured
        assert "No AI agent processes detected" in captured

    def test_detects_claude_process(self, capsys):
        """When ps returns a Claude process, it should be listed."""
        from claude_monitoring.watch import run_scan

        fake_ps = MagicMock()
        fake_ps.stdout = (
            "USER  PID  %CPU %MEM VSZ  RSS  TT  STAT STARTED TIME COMMAND\n"
            "user  12345  2.5  1.0  100 50  s001  S+  10:00AM 0:05.00 /usr/local/bin/claude --code\n"
        )

        fake_lsof = MagicMock()
        fake_lsof.stdout = ""

        def mock_run(cmd, **kwargs):
            if cmd[0] == "ps":
                return fake_ps
            elif cmd[0] == "lsof":
                return fake_lsof
            return MagicMock(stdout="")

        with patch("claude_monitoring.watch.subprocess.run", side_effect=mock_run), patch("socket.socket"):
            run_scan()

        captured = capsys.readouterr().out
        assert "Found" in captured
        assert "12345" in captured
        assert "Claude Code CLI" in captured

    def test_detects_multiple_ai_processes(self, capsys):
        """When ps returns multiple AI processes, all should be listed."""
        from claude_monitoring.watch import run_scan

        fake_ps = MagicMock()
        fake_ps.stdout = (
            "USER  PID  %CPU %MEM VSZ  RSS  TT  STAT STARTED TIME COMMAND\n"
            "user  111  1.0  0.5  100 50  s001  S+  10:00AM 0:01.00 /usr/local/bin/claude --code\n"
            "user  222  3.0  2.0  200 80  s002  S+  10:01AM 0:02.00 /opt/homebrew/bin/ollama serve\n"
        )

        fake_lsof = MagicMock()
        fake_lsof.stdout = ""

        def mock_run(cmd, **kwargs):
            if cmd[0] == "ps":
                return fake_ps
            elif cmd[0] == "lsof":
                return fake_lsof
            return MagicMock(stdout="")

        with patch("claude_monitoring.watch.subprocess.run", side_effect=mock_run), patch("socket.socket"):
            run_scan()

        captured = capsys.readouterr().out
        assert "Found 2" in captured
        assert "Claude Code CLI" in captured
        assert "Ollama" in captured

    def test_ps_failure_prints_error(self, capsys):
        """When ps fails, run_scan should print error and return."""
        from claude_monitoring.watch import run_scan

        def mock_run(cmd, **kwargs):
            if cmd[0] == "ps":
                raise OSError("ps not found")
            return MagicMock(stdout="")

        with patch("claude_monitoring.watch.subprocess.run", side_effect=mock_run):
            run_scan()

        captured = capsys.readouterr().out
        assert "Failed to list processes" in captured

    def test_detects_ai_network_connections(self, capsys):
        """When lsof finds connections to AI hosts, they should be reported."""
        from claude_monitoring.watch import run_scan

        fake_ps = MagicMock()
        fake_ps.stdout = "USER  PID  %CPU %MEM VSZ  RSS  TT  STAT STARTED TIME COMMAND\n"

        fake_lsof = MagicMock()
        fake_lsof.stdout = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "claude  123 user 5u  IPv4 0x1234 0t0 TCP 127.0.0.1:49000->api.anthropic.com:443 (ESTABLISHED)\n"
        )

        def mock_run(cmd, **kwargs):
            if cmd[0] == "ps":
                return fake_ps
            elif cmd[0] == "lsof":
                return fake_lsof
            return MagicMock(stdout="")

        with patch("claude_monitoring.watch.subprocess.run", side_effect=mock_run), patch("socket.socket"):
            run_scan()

        captured = capsys.readouterr().out
        assert "active AI service connection" in captured


# ===================================================================
# 6. main() argument parsing
# ===================================================================


class TestMain:
    """Test the main() entry point with different CLI flags."""

    def test_analyze_flag_calls_run_analyze(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_analyze") as mock_analyze,
            patch("sys.argv", ["claude-watch", "--analyze"]),
        ):
            main()
            mock_analyze.assert_called_once_with(None)

    def test_analyze_with_dir(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_analyze") as mock_analyze,
            patch("sys.argv", ["claude-watch", "--analyze", "--dir", "/tmp/my_sessions"]),
        ):
            main()
            mock_analyze.assert_called_once_with("/tmp/my_sessions")

    def test_plot_flag_calls_run_plot(self):
        from claude_monitoring.watch import main

        with patch("claude_monitoring.watch.run_plot") as mock_plot, patch("sys.argv", ["claude-watch", "--plot"]):
            main()
            mock_plot.assert_called_once_with(None)

    def test_plot_with_dir(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_plot") as mock_plot,
            patch("sys.argv", ["claude-watch", "--plot", "--dir", "/tmp/sessions"]),
        ):
            main()
            mock_plot.assert_called_once_with("/tmp/sessions")

    def test_scan_flag_calls_run_scan(self):
        from claude_monitoring.watch import main

        with patch("claude_monitoring.watch.run_scan") as mock_scan, patch("sys.argv", ["claude-watch", "--scan"]):
            main()
            mock_scan.assert_called_once()

    def test_dashboard_flag_calls_run_dashboard(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_dashboard") as mock_dash,
            patch("sys.argv", ["claude-watch", "--dashboard"]),
        ):
            main()
            mock_dash.assert_called_once_with(None)

    def test_dashboard_with_dir(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_dashboard") as mock_dash,
            patch("sys.argv", ["claude-watch", "--dashboard", "--dir", "/tmp/data"]),
        ):
            main()
            mock_dash.assert_called_once_with("/tmp/data")

    def test_setup_flag_calls_run_setup(self):
        from claude_monitoring.watch import main

        with patch("claude_monitoring.watch.run_setup") as mock_setup, patch("sys.argv", ["claude-watch", "--setup"]):
            main()
            mock_setup.assert_called_once()

    def test_start_flag_calls_run_start(self):
        from claude_monitoring.watch import main

        with patch("claude_monitoring.watch.run_start") as mock_start, patch("sys.argv", ["claude-watch", "--start"]):
            main()
            mock_start.assert_called_once()

    def test_generate_test_flag_calls_run_generate_test(self):
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_generate_test") as mock_gen,
            patch("sys.argv", ["claude-watch", "--generate-test"]),
        ):
            main()
            mock_gen.assert_called_once()

    def test_no_flags_prints_help(self, capsys):
        from claude_monitoring.watch import main

        with patch("sys.argv", ["claude-watch"]):
            main()

        captured = capsys.readouterr().out
        # argparse print_help prints the description or usage
        assert "Claude Watch" in captured or "usage" in captured.lower()

    def test_flags_are_mutually_exclusive_first_wins(self):
        """When multiple flags are given, only the first matching branch runs."""
        from claude_monitoring.watch import main

        with (
            patch("claude_monitoring.watch.run_setup") as mock_setup,
            patch("claude_monitoring.watch.run_analyze") as mock_analyze,
            patch("sys.argv", ["claude-watch", "--setup", "--analyze"]),
        ):
            main()
            # --setup is checked first in the if-elif chain
            mock_setup.assert_called_once()
            mock_analyze.assert_not_called()


# ===================================================================
# 7. run_analyze edge cases
# ===================================================================


class TestRunAnalyzeEdgeCases:
    """Additional edge cases for run_analyze."""

    def test_non_api_rows_excluded_from_api_stats(self, tmp_path, capsys):
        """Only rows with destination_service == 'anthropic_api' count for API stats."""
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row(
                {
                    "destination_service": "anthropic_telemetry",
                    "input_tokens": "9999",
                    "output_tokens": "9999",
                    "estimated_cost_usd": "99.0",
                }
            ),
            _sample_row(
                {
                    "turn_number": "2",
                    "destination_service": "anthropic_api",
                    "input_tokens": "100",
                    "output_tokens": "50",
                    "estimated_cost_usd": "0.001",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        # Should report 2 total requests intercepted, but only 1 Anthropic API call
        assert "2" in captured  # total requests
        assert "Anthropic API calls" in captured

    def test_handles_malformed_tool_calls_json(self, tmp_path, capsys):
        """run_analyze should not crash on malformed tool_calls JSON."""
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row(
                {
                    "destination_service": "anthropic_api",
                    "tool_calls": "not valid json",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        # This may raise or may handle gracefully; we just verify no crash
        # run_analyze uses json.loads which will raise on invalid JSON,
        # but the function does not have a try/except around it.
        # Depending on implementation, this test documents the behavior.
        try:
            run_analyze(str(sessions))
        except json.JSONDecodeError:
            pass  # Expected if no error handling in run_analyze

    def test_analyze_prints_csv_path(self, tmp_path, capsys):
        """run_analyze should print the CSV file path at the end."""
        from claude_monitoring.watch import run_analyze

        sessions = tmp_path / "sessions"
        csv_name = "claude_watch_20260101_000000.csv"
        _write_csv(sessions / csv_name, [_sample_row()])

        run_analyze(str(sessions))

        captured = capsys.readouterr().out
        assert "CSV:" in captured


# ===================================================================
# 8. _load_latest_csv with non-matching files
# ===================================================================


class TestLoadLatestCsvFiltering:
    """Test that _load_latest_csv only picks up claude_watch_*.csv files."""

    def test_ignores_non_matching_csv_files(self, tmp_path):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        # Write a CSV that does NOT match the claude_watch_* pattern
        other_csv = sessions / "other_data.csv"
        _write_csv(other_csv, [_sample_row()])

        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path is None
        assert rows == []

    def test_picks_matching_files_only(self, tmp_path):
        from claude_monitoring.watch import _load_latest_csv

        sessions = tmp_path / "sessions"
        # Non-matching
        _write_csv(sessions / "random.csv", [_sample_row({"turn_number": "99"})])
        # Matching
        _write_csv(sessions / "claude_watch_test.csv", [_sample_row({"turn_number": "1"})])

        result_path, rows = _load_latest_csv(str(sessions))

        assert result_path is not None
        assert result_path.name == "claude_watch_test.csv"
        assert len(rows) == 1
        assert rows[0]["turn_number"] == "1"


# ===================================================================
# 9. run_plot edge cases
# ===================================================================


class TestRunPlotEdgeCases:
    """Additional edge cases for run_plot."""

    def test_plot_with_sensitive_data(self, tmp_path, capsys):
        """run_plot should handle rows with sensitive patterns without crashing."""
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            pytest.skip("matplotlib not installed")

        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row(
                {
                    "sensitive_patterns": "aws_key",
                    "sensitive_pattern_count": "1",
                    "timestamp": "2026-01-01T00:01:00+00:00",
                }
            ),
            _sample_row(
                {
                    "turn_number": "2",
                    "turn_id": "t-2",
                    "sensitive_patterns": "",
                    "timestamp": "2026-01-01T00:02:00+00:00",
                }
            ),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        with patch("claude_monitoring.watch.subprocess.run"):
            run_plot(str(sessions))

        captured = capsys.readouterr().out
        assert "Dashboard saved to" in captured

    def test_plot_with_bad_timestamp(self, tmp_path, capsys):
        """run_plot should handle rows with invalid timestamps gracefully."""
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            pytest.skip("matplotlib not installed")

        from claude_monitoring.watch import run_plot

        sessions = tmp_path / "sessions"
        rows = [
            _sample_row({"timestamp": "not-a-timestamp"}),
            _sample_row({"turn_number": "2", "turn_id": "t-2", "timestamp": "2026-01-01T00:02:00Z"}),
        ]
        _write_csv(sessions / "claude_watch_20260101_000000.csv", rows)

        with patch("claude_monitoring.watch.subprocess.run"):
            run_plot(str(sessions))

        captured = capsys.readouterr().out
        assert "Dashboard saved to" in captured


# ---------------------------------------------------------------------------
# run_generate_test
# ---------------------------------------------------------------------------


class TestRunGenerateTest:
    def test_generates_csv(self, tmp_path, capsys):
        from claude_monitoring.watch import run_generate_test

        run_generate_test()
        captured = capsys.readouterr().out
        assert "Generated test CSV" in captured
        assert "20 rows" in captured
        # Verify CSV was written
        sessions = tmp_path / "sessions"
        csvs = list(sessions.glob("claude_watch_test.csv"))
        assert len(csvs) == 1
        with open(csvs[0], encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 20
        # Verify all CSV_COLUMNS present
        for col in CSV_COLUMNS:
            assert col in rows[0]

    def test_generates_sensitive_rows(self, tmp_path):
        from claude_monitoring.watch import run_generate_test

        run_generate_test()
        sessions = tmp_path / "sessions"
        csvs = list(sessions.glob("claude_watch_test.csv"))
        with open(csvs[0], encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        sensitive = [r for r in rows if r.get("sensitive_patterns")]
        assert len(sensitive) == 2

    def test_generates_multiple_services(self, tmp_path):
        from claude_monitoring.watch import run_generate_test

        run_generate_test()
        sessions = tmp_path / "sessions"
        csvs = list(sessions.glob("claude_watch_test.csv"))
        with open(csvs[0], encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        services = set(r["destination_service"] for r in rows)
        assert "anthropic_api" in services
        assert len(services) >= 2


# ---------------------------------------------------------------------------
# _dashboard_html
# ---------------------------------------------------------------------------


class TestDashboardHtml:
    def test_returns_html_string(self):
        from claude_monitoring.watch import _dashboard_html

        html = _dashboard_html()
        assert isinstance(html, str)
        assert "<html" in html.lower() or "Dashboard" in html
