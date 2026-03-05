"""Shared test fixtures for AI Runtime Monitor."""

from unittest.mock import patch

import pytest


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory for output."""
    return tmp_path


@pytest.fixture()
def tmp_db(tmp_path):
    """Create a temporary SQLite database with full schema via init_db()."""
    db_path = tmp_path / "test_monitor.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    with patch("claude_monitoring.monitor.DB_PATH", db_path), \
         patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir):
        from claude_monitoring.monitor import init_db
        conn = init_db()
        yield conn
        conn.close()


@pytest.fixture()
def db_path(tmp_path):
    """Return path for a temporary database."""
    return tmp_path / "test.db"
