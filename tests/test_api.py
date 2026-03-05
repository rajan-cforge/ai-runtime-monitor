"""Tests for the DashboardHandler HTTP API routes."""

import json
import threading
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import urlopen

import pytest


def _setup_test_db(tmp_path):
    """Create a test database with schema and sample data."""
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)

    with patch("claude_monitoring.monitor.DB_PATH", db_path), patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir):
        from claude_monitoring.monitor import init_db

        conn = init_db()

    # Insert sample data
    conn.execute(
        "INSERT INTO sessions (session_id, start_time, model, total_turns, total_input_tokens, total_output_tokens, total_cost, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("test-sess-1", "2026-01-01T00:00:00Z", "claude-sonnet-4", 5, 1000, 500, 0.054, "2026-01-01T00:10:00Z"),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:00:00Z", "test-sess-1", "user_prompt", "network", '{"text":"hello"}'),
    )
    # Insert sample browser session data
    conn.execute(
        """INSERT INTO browser_sessions (service, url, title, conversation_id, visit_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("ChatGPT", "https://chatgpt.com/c/test-conv-1", "Test Chat", "test-conv-1", "2026-01-01T00:05:00Z", 120.0),
    )
    conn.execute(
        """INSERT INTO browser_sessions (service, url, title, conversation_id, visit_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            "ChatGPT",
            "https://chatgpt.com/c/test-conv-1",
            "Test Chat Continued",
            "test-conv-1",
            "2026-01-01T00:08:00Z",
            60.0,
        ),
    )
    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def api_server(tmp_path):
    """Start a real HTTP server on a random port for testing."""
    db_path, output_dir = _setup_test_db(tmp_path)

    with patch("claude_monitoring.monitor.DB_PATH", db_path), patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir):
        from claude_monitoring.monitor import DashboardHandler

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"

        server.shutdown()


class TestDashboardAPI:
    def test_root_returns_html(self, api_server):
        resp = urlopen(f"{api_server}/")
        assert resp.status == 200
        body = resp.read().decode()
        assert "<html" in body.lower()

    def test_api_stats(self, api_server):
        resp = urlopen(f"{api_server}/api/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "total_sessions" in data
        assert "total_input_tokens" in data
        assert "total_output_tokens" in data
        assert "total_cost" in data

    def test_api_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_api_feed(self, api_server):
        resp = urlopen(f"{api_server}/api/feed")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_api_export_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=sessions&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_unknown_path_404(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/unknown/path")
        assert exc_info.value.code == 404

    def test_api_processes(self, api_server):
        resp = urlopen(f"{api_server}/api/processes")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "processes" in data

    def test_api_connections(self, api_server):
        resp = urlopen(f"{api_server}/api/connections")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "connections" in data

    def test_api_browser_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/browser/sessions")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "browser_sessions" in data
        assert isinstance(data["browser_sessions"], list)
        # Should have our test conversation grouped
        assert len(data["browser_sessions"]) >= 1
        sess = data["browser_sessions"][0]
        assert sess["conversation_id"] == "test-conv-1"
        assert sess["visit_count"] == 2

    def test_api_browser_session_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/browser/session/test-conv-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["conversation_id"] == "test-conv-1"
        assert data["service"] == "ChatGPT"
        assert len(data["visits"]) == 2
        assert "correlated_connections" in data

    def test_api_activity_timeline(self, api_server):
        resp = urlopen(f"{api_server}/api/activity/timeline")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "timeline" in data
        assert "count" in data
        assert isinstance(data["timeline"], list)

    def test_api_timeline_source_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/activity/timeline?source=browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        for ev in data["timeline"]:
            assert ev["source"] == "browser"

    def test_api_sessions_include_browser(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?include_browser=true")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data
        sources = set(s.get("source") for s in data["sessions"])
        # Should have both cli and browser sessions
        assert "cli" in sources
        assert "browser" in sources

    def test_api_sessions_source_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?source=browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        for s in data["sessions"]:
            assert s["source"] == "browser"

    def test_api_process_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/process/1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "processes" in data
        assert "connections" in data
        assert "service_breakdown" in data
