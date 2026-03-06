"""Tests for init_db() and database operations."""

from claude_monitoring.db import init_db, insert_api_call


class TestInitDb:
    def _init(self, tmp_path):
        db_path = tmp_path / "test.db"
        (tmp_path / "output").mkdir(exist_ok=True)
        conn = init_db(db_path)
        return conn, db_path

    def test_creates_all_tables(self, tmp_path):
        conn, _ = self._init(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"events", "sessions", "processes", "connections", "file_events", "browser_sessions", "api_calls"}
        assert expected.issubset(tables)
        conn.close()

    def test_idempotent(self, tmp_path):
        """Calling init_db twice should not error."""
        db_path = tmp_path / "test.db"
        conn1 = init_db(db_path)
        conn1.close()
        conn2 = init_db(db_path)
        conn2.close()

    def test_wal_mode(self, tmp_path):
        conn, _ = self._init(tmp_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_session_insert_update(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, model) VALUES (?, ?, ?)",
            ("test-123", "2026-01-01T00:00:00Z", "claude-sonnet-4"),
        )
        conn.execute("UPDATE sessions SET total_turns = 5 WHERE session_id = ?", ("test-123",))
        conn.commit()
        row = conn.execute("SELECT total_turns FROM sessions WHERE session_id = ?", ("test-123",)).fetchone()
        assert row[0] == 5
        conn.close()

    def test_event_storage(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "sess-1", "user_prompt", "network", '{"text":"hello"}'),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        assert row[0] == 1
        conn.close()

    def test_indexes_created(self, tmp_path):
        conn, _ = self._init(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_events_ts" in indexes
        assert "idx_events_session" in indexes
        assert "idx_api_calls_ts" in indexes
        assert "idx_api_calls_session" in indexes
        conn.close()

    def test_file_events_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO file_events (timestamp, path, operation) VALUES (?, ?, ?)",
            ("2026-01-01T00:00:00Z", "/tmp/test.py", "created"),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM file_events").fetchone()
        assert row[0] == 1
        conn.close()

    def test_browser_sessions_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO browser_sessions (service, visit_time) VALUES (?, ?)", ("ChatGPT", "2026-01-01T00:00:00Z")
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()
        assert row[0] == 1
        conn.close()

    def test_api_calls_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            """INSERT INTO api_calls (timestamp, session_id, destination_service, model, input_tokens, output_tokens)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("2026-01-01T00:00:00Z", "sess-1", "anthropic_api", "claude-sonnet-4", 1000, 500),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM api_calls").fetchone()
        assert row[0] == 1
        conn.close()


class TestInsertApiCall:
    def test_insert_api_call_success(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        record = {
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "test-123",
            "turn_id": "turn-1",
            "turn_number": 1,
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic_api",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "http_status": 200,
            "model": "claude-sonnet-4",
            "stream": "true",
            "input_tokens": 5000,
            "output_tokens": 1000,
            "estimated_cost_usd": 0.0,
            "latency_ms": 1500,
            "stop_reason": "end_turn",
            "request_id": "req-abc",
        }
        result = insert_api_call(db_path, record)
        assert result is True

        # Verify data was inserted
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT COUNT(*) FROM api_calls").fetchone()
        assert row[0] == 1
        conn.close()

    def test_insert_api_call_no_db(self, tmp_path):
        db_path = tmp_path / "nonexistent.db"
        result = insert_api_call(db_path, {"timestamp": "now"})
        assert result is False

    def test_insert_api_call_none_path(self):
        result = insert_api_call(None, {"timestamp": "now"})
        assert result is False

    def test_insert_api_call_defaults(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        # Minimal record — should use defaults for missing fields
        record = {"timestamp": "2026-01-01T00:00:00Z"}
        result = insert_api_call(db_path, record)
        assert result is True
