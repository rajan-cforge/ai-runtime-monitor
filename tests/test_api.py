"""Tests for the DashboardHandler HTTP API routes."""

import json
import threading
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import urlopen

import pytest

from claude_monitoring.db import init_db


def _setup_test_db(tmp_path):
    """Create a test database with schema and sample data."""
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)

    conn = init_db(db_path)

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
    # Insert sample api_calls data for traffic endpoints
    conn.execute(
        """INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number,
            destination_host, destination_service, endpoint_path, http_method,
            http_status, model, stream, input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens, estimated_cost_usd,
            request_size_bytes, response_size_bytes, latency_ms, num_messages,
            system_prompt_chars, tool_call_count, sensitive_pattern_count,
            stop_reason, request_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-01-01T00:01:00Z",
            "test-sess-1",
            "turn-1",
            1,
            "api.anthropic.com",
            "anthropic_api",
            "/v1/messages",
            "POST",
            200,
            "claude-sonnet-4",
            "true",
            5000,
            1000,
            100,
            50,
            0.018,
            12000,
            8000,
            1500,
            10,
            5000,
            2,
            0,
            "end_turn",
            "req-abc123",
        ),
    )
    conn.execute(
        """INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number,
            destination_host, destination_service, endpoint_path, http_method,
            http_status, model, stream, input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens, estimated_cost_usd,
            request_size_bytes, response_size_bytes, latency_ms, num_messages,
            system_prompt_chars, tool_call_count, sensitive_pattern_count,
            stop_reason, request_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-01-01T00:02:00Z",
            "test-sess-1",
            "turn-2",
            2,
            "api.anthropic.com",
            "anthropic_api",
            "/v1/messages",
            "POST",
            200,
            "claude-sonnet-4",
            "true",
            8000,
            2000,
            200,
            100,
            0.033,
            20000,
            15000,
            2500,
            15,
            5000,
            3,
            1,
            "tool_use",
            "req-def456",
        ),
    )
    # Additional events for turns testing: tool_use and token_usage within the same session
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:01:00Z", "test-sess-1", "tool_use", "network", '{"name":"read_file","path":"/tmp/foo.py"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:02:00Z",
            "test-sess-1",
            "token_usage",
            "network",
            '{"input_tokens":800,"output_tokens":400,"cost":0.01}',
        ),
    )
    # Sensitive data event for alerts testing
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:03:00Z",
            "test-sess-1",
            "sensitive_data",
            "network",
            '{"patterns":["AWS_KEY"],"severity":"critical","categories":["credential"],"context":"found key","snippet":"AKIA..."}',
        ),
    )
    # A second sensitive_data event with different severity for filter testing
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:04:00Z",
            "test-sess-1",
            "sensitive_data",
            "network",
            '{"patterns":["PRIVATE_KEY"],"severity":"high","categories":["secret"],"context":"found pem","snippet":"-----BEGIN"}',
        ),
    )
    # File event for /api/files testing
    conn.execute(
        "INSERT INTO file_events (timestamp, path, operation, session_id, size) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:05:00Z", "/tmp/foo.py", "write", "test-sess-1", 1234),
    )
    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def api_server(tmp_path):
    """Start a real HTTP server on a random port for testing."""
    db_path, output_dir = _setup_test_db(tmp_path)

    with (
        patch("claude_monitoring.monitor.DB_PATH", db_path),
        patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
        patch("claude_monitoring.config.get_db_path", return_value=db_path),
        patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
        patch("claude_monitoring.db.get_db_path", return_value=db_path),
        patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
    ):
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

    def test_api_traffic(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "calls" in data
        assert "total" in data
        assert data["total"] == 2
        assert len(data["calls"]) == 2

    def test_api_traffic_with_limit(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?limit=1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["calls"]) == 1
        assert data["total"] == 2

    def test_api_traffic_with_service_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?service=anthropic_api")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total"] == 2
        for call in data["calls"]:
            assert call["destination_service"] == "anthropic_api"

    def test_api_traffic_with_model_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?model=sonnet")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total"] == 2

    def test_api_traffic_stats(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total_calls"] == 2
        assert data["total_input_tokens"] == 13000
        assert data["total_output_tokens"] == 3000
        assert data["total_cost"] > 0
        assert data["avg_latency"] > 0
        assert "by_service" in data
        assert "by_model" in data
        assert len(data["by_service"]) >= 1
        assert len(data["by_model"]) >= 1

    def test_api_session_traffic(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["session_id"] == "test-sess-1"
        assert data["total_calls"] == 2
        assert len(data["calls"]) == 2
        # Verify cumulative cost
        assert data["calls"][0]["cumulative_cost"] > 0
        assert data["calls"][1]["cumulative_cost"] > data["calls"][0]["cumulative_cost"]
        assert data["total_cost"] == data["calls"][-1]["cumulative_cost"]

    def test_api_session_traffic_empty(self, api_server):
        resp = urlopen(f"{api_server}/api/session/nonexistent/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total_calls"] == 0
        assert data["calls"] == []

    # ── Session detail endpoint ──────────────────────────────────────

    def test_api_session_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "session" in data
        assert "events" in data
        assert data["session"]["session_id"] == "test-sess-1"
        assert data["session"]["model"] == "claude-sonnet-4"
        assert data["session"]["total_turns"] == 5
        assert isinstance(data["events"], list)
        assert len(data["events"]) >= 1

    def test_api_session_detail_not_found(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/session/nonexistent-session-xyz")
        assert exc_info.value.code == 404

    def test_api_session_detail_events_structure(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        events = data["events"]
        # Should have at least the user_prompt, tool_use, token_usage, and sensitive_data events
        event_types = [e["event_type"] for e in events]
        assert "user_prompt" in event_types
        assert "tool_use" in event_types
        assert "token_usage" in event_types
        assert "sensitive_data" in event_types
        # Each event should have required fields
        for evt in events:
            assert "id" in evt
            assert "timestamp" in evt
            assert "event_type" in evt
            assert "source" in evt
            assert "data" in evt

    # ── Session turns endpoint ───────────────────────────────────────

    def test_api_session_turns(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/turns")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "session" in data
        assert "turns" in data
        assert "total_turns" in data
        assert "total_input" in data
        assert "total_output" in data
        assert data["session"]["session_id"] == "test-sess-1"
        # There is one user_prompt event so there should be exactly one turn
        assert data["total_turns"] == 1
        assert len(data["turns"]) == 1

    def test_api_session_turns_structure(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/turns")
        assert resp.status == 200
        data = json.loads(resp.read())
        turn = data["turns"][0]
        assert turn["turn_number"] == 1
        assert "timestamp" in turn
        assert "prompt_preview" in turn
        assert "events" in turn
        assert "tools_used" in turn
        assert "has_alert" in turn
        assert "token_delta" in turn
        assert "cumulative_tokens" in turn
        # The turn should contain tool_use, token_usage, and sensitive_data events
        assert "read_file" in turn["tools_used"]
        assert turn["has_alert"] is True
        assert turn["token_delta"]["input"] == 800
        assert turn["token_delta"]["output"] == 400
        assert turn["cumulative_tokens"]["input"] == 800
        assert turn["cumulative_tokens"]["output"] == 400
        assert data["total_input"] == 800
        assert data["total_output"] == 400

    def test_api_session_turns_not_found(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/session/nonexistent-session-xyz/turns")
        assert exc_info.value.code == 404

    # ── Alerts endpoint ──────────────────────────────────────────────

    def test_api_alerts(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "alerts" in data
        assert "severity_counts" in data
        assert "category_counts" in data
        assert "total" in data
        assert "has_more" in data
        assert data["total"] == 2
        assert isinstance(data["alerts"], list)
        assert len(data["alerts"]) == 2
        # Verify alert structure
        alert = data["alerts"][0]
        assert "id" in alert
        assert "timestamp" in alert
        assert "session_id" in alert
        assert "severity" in alert
        assert "categories" in alert
        assert "patterns" in alert
        assert "turn_number" in alert

    def test_api_alerts_severity_filter_critical(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?severity=critical")
        assert resp.status == 200
        data = json.loads(resp.read())
        # Only the critical alert should be in the filtered list
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["severity"] == "critical"
        assert "AWS_KEY" in data["alerts"][0]["patterns"]
        # severity_counts should still reflect ALL alerts (unfiltered counts)
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 1
        assert data["total"] == 2

    def test_api_alerts_severity_filter_no_match(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?severity=low")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["alerts"]) == 0
        # Total still counts all alerts regardless of filter
        assert data["total"] == 2

    # ── Files endpoint ───────────────────────────────────────────────

    def test_api_files(self, api_server):
        resp = urlopen(f"{api_server}/api/files")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "files" in data
        assert isinstance(data["files"], list)
        assert len(data["files"]) >= 1
        f = data["files"][0]
        assert f["path"] == "/tmp/foo.py"
        assert f["operation"] == "write"
        assert f["session_id"] == "test-sess-1"
        assert f["size"] == 1234

    # ── Export events endpoint ───────────────────────────────────────

    def test_api_export_events_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&format=json")
        assert resp.status == 200
        body = resp.read()
        data = json.loads(body)
        assert "data" in data
        assert "export_type" in data
        assert data["export_type"] == "events"
        assert "count" in data
        assert isinstance(data["data"], list)
        assert data["count"] >= 1
        # Each exported event should have parsed data (not raw data_json)
        evt = data["data"][0]
        assert "id" in evt
        assert "timestamp" in evt
        assert "session_id" in evt
        assert "event_type" in evt
        assert "data" in evt
        assert isinstance(evt["data"], dict)

    def test_api_export_events_ndjson(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&format=ndjson")
        assert resp.status == 200
        assert "application/x-ndjson" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        lines = [line for line in body.strip().split("\n") if line]
        assert len(lines) >= 1
        # Each line should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "event_type" in parsed
            assert "session_id" in parsed

    def test_api_export_alerts_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=alerts&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "alerts"
        assert data["count"] == 2
        assert isinstance(data["data"], list)
        # Should have inlined data_json fields
        alert = data["data"][0]
        assert "timestamp" in alert
        assert "session_id" in alert
        assert "patterns" in alert or "severity" in alert

    def test_api_export_connections_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=connections&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "connections"
        assert isinstance(data["data"], list)

    def test_api_export_unknown_type(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/export?type=bogus")
        assert exc_info.value.code == 400

    def test_api_export_sessions_ndjson(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=sessions&format=ndjson")
        assert resp.status == 200
        assert "application/x-ndjson" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        lines = [line for line in body.strip().split("\n") if line]
        assert len(lines) >= 1
        parsed = json.loads(lines[0])
        assert "session_id" in parsed

    def test_api_browser_raw(self, api_server):
        resp = urlopen(f"{api_server}/api/browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "browser_sessions" in data
        assert isinstance(data["browser_sessions"], list)

    def test_api_alerts_with_category_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?category=credential")
        assert resp.status == 200
        data = json.loads(resp.read())
        for alert in data["alerts"]:
            assert "credential" in alert["categories"]

    def test_api_alerts_with_offset(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?offset=1&limit=1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["alerts"]) == 1
        assert data["total"] == 2

    def test_api_export_events_with_session_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&session_id=test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        for evt in data["data"]:
            assert evt["session_id"] == "test-sess-1"

    def test_api_export_events_with_type_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&event_type=user_prompt")
        assert resp.status == 200
        data = json.loads(resp.read())
        for evt in data["data"]:
            assert evt["event_type"] == "user_prompt"
