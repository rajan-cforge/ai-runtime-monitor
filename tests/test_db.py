"""Tests for init_db() and database operations."""

from unittest.mock import patch

from claude_monitoring.monitor import init_db


class TestInitDb:
    def _init(self, tmp_path):
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)
        with patch("claude_monitoring.monitor.DB_PATH", db_path), \
             patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir):
            conn = init_db()
        return conn, db_path

    def test_creates_all_tables(self, tmp_path):
        conn, _ = self._init(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"events", "sessions", "processes", "connections", "file_events", "browser_sessions"}
        assert expected.issubset(tables)
        conn.close()

    def test_idempotent(self, tmp_path):
        """Calling init_db twice should not error."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)
        with patch("claude_monitoring.monitor.DB_PATH", db_path), \
             patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir):
            conn1 = init_db()
            conn1.close()
            conn2 = init_db()
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
            ("test-123", "2026-01-01T00:00:00Z", "claude-sonnet-4")
        )
        conn.execute(
            "UPDATE sessions SET total_turns = 5 WHERE session_id = ?", ("test-123",)
        )
        conn.commit()
        row = conn.execute("SELECT total_turns FROM sessions WHERE session_id = ?", ("test-123",)).fetchone()
        assert row[0] == 5
        conn.close()

    def test_event_storage(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "sess-1", "user_prompt", "network", '{"text":"hello"}')
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
        conn.close()

    def test_file_events_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO file_events (timestamp, path, operation) VALUES (?, ?, ?)",
            ("2026-01-01T00:00:00Z", "/tmp/test.py", "created")
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM file_events").fetchone()
        assert row[0] == 1
        conn.close()

    def test_browser_sessions_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO browser_sessions (service, visit_time) VALUES (?, ?)",
            ("ChatGPT", "2026-01-01T00:00:00Z")
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()
        assert row[0] == 1
        conn.close()
