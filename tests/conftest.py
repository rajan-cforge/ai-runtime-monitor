"""Shared test fixtures for AI Runtime Monitor."""

import pytest

from claude_monitoring.db import init_db


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory for output."""
    return tmp_path


@pytest.fixture()
def tmp_db(tmp_path):
    """Create a temporary SQLite database with full schema via init_db()."""
    db_path = tmp_path / "test_monitor.db"
    conn = init_db(db_path)
    yield conn
    conn.close()


@pytest.fixture()
def db_path(tmp_path):
    """Return path for a temporary database."""
    return tmp_path / "test.db"
