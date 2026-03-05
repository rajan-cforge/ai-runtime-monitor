"""Database layer for AI Runtime Monitor.

Handles SQLite initialization, schema management, and thread-safe connections.
"""

import sqlite3

from claude_monitoring.config import get_db_path, get_output_dir


def init_db(db_path=None):
    """Initialize SQLite database with all required tables.

    Args:
        db_path: Override database path (used in tests). If None, uses config.

    Returns:
        sqlite3.Connection with WAL mode enabled.
    """
    if db_path is None:
        db_path = get_db_path()

    get_output_dir().mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        start_time TEXT,
        cwd TEXT,
        model TEXT,
        total_cost REAL DEFAULT 0,
        total_input_tokens INTEGER DEFAULT 0,
        total_output_tokens INTEGER DEFAULT 0,
        total_turns INTEGER DEFAULT 0,
        jsonl_path TEXT,
        last_activity TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER NOT NULL,
        name TEXT,
        cmdline TEXT,
        start_time TEXT,
        end_time TEXT,
        cpu_percent REAL DEFAULT 0,
        memory_percent REAL DEFAULT 0,
        status TEXT DEFAULT 'running'
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        remote_host TEXT,
        remote_port INTEGER,
        status TEXT,
        service TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        path TEXT NOT NULL,
        operation TEXT NOT NULL,
        session_id TEXT,
        size INTEGER DEFAULT 0
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS browser_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        url TEXT,
        title TEXT,
        conversation_id TEXT,
        visit_time TEXT NOT NULL,
        duration_seconds REAL DEFAULT 0,
        foreground_seconds REAL DEFAULT 0,
        tab_id INTEGER,
        window_id INTEGER
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS api_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        turn_id TEXT,
        turn_number INTEGER,
        destination_host TEXT,
        destination_service TEXT,
        endpoint_path TEXT,
        http_method TEXT,
        http_status INTEGER,
        model TEXT,
        stream TEXT,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        cache_read_tokens INTEGER DEFAULT 0,
        cache_write_tokens INTEGER DEFAULT 0,
        estimated_cost_usd REAL DEFAULT 0,
        request_size_bytes INTEGER DEFAULT 0,
        response_size_bytes INTEGER DEFAULT 0,
        latency_ms INTEGER DEFAULT 0,
        num_messages INTEGER DEFAULT 0,
        system_prompt_chars INTEGER DEFAULT 0,
        last_user_msg_preview TEXT,
        assistant_msg_preview TEXT,
        tool_calls TEXT,
        tool_call_count INTEGER DEFAULT 0,
        bash_commands TEXT,
        files_read TEXT,
        files_written TEXT,
        urls_fetched TEXT,
        sensitive_patterns TEXT,
        sensitive_pattern_count INTEGER DEFAULT 0,
        stop_reason TEXT,
        request_id TEXT
    )""")

    # Add title column to sessions if missing (migration)
    try:
        c.execute("ALTER TABLE sessions ADD COLUMN title TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_last ON sessions(last_activity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_browser_conv ON browser_sessions(conversation_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_browser_visit ON browser_sessions(visit_time)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connections_pid ON connections(pid)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_ts ON api_calls(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_session ON api_calls(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_service ON api_calls(destination_service)")

    conn.commit()
    return conn


def get_thread_db(db_path=None):
    """Get a thread-local database connection with Row factory.

    Args:
        db_path: Override database path (used in tests). If None, uses config.

    Returns:
        sqlite3.Connection with WAL mode and Row factory enabled.
    """
    if db_path is None:
        db_path = get_db_path()

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def insert_api_call(db_path, record):
    """Insert an API call record into the api_calls table.

    Used by watch.py for dual-write (CSV + SQLite).
    Non-fatal: returns False on any error.

    Args:
        db_path: Path to the SQLite database.
        record: Dict with API call data (keys match CSV_COLUMNS).

    Returns:
        True if insert succeeded, False otherwise.
    """
    try:
        if not db_path or not db_path.exists():
            return False
        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.execute(
            """INSERT INTO api_calls (
                timestamp, session_id, turn_id, turn_number,
                destination_host, destination_service, endpoint_path, http_method,
                http_status, model, stream, input_tokens, output_tokens,
                cache_read_tokens, cache_write_tokens, estimated_cost_usd,
                request_size_bytes, response_size_bytes, latency_ms, num_messages,
                system_prompt_chars, last_user_msg_preview, assistant_msg_preview,
                tool_calls, tool_call_count, bash_commands, files_read, files_written,
                urls_fetched, sensitive_patterns, sensitive_pattern_count,
                stop_reason, request_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.get("timestamp", ""),
                record.get("session_id", ""),
                record.get("turn_id", ""),
                record.get("turn_number", 0),
                record.get("destination_host", ""),
                record.get("destination_service", ""),
                record.get("endpoint_path", ""),
                record.get("http_method", ""),
                record.get("http_status", 0),
                record.get("model", ""),
                record.get("stream", ""),
                record.get("input_tokens", 0),
                record.get("output_tokens", 0),
                record.get("cache_read_tokens", 0),
                record.get("cache_write_tokens", 0),
                record.get("estimated_cost_usd", 0),
                record.get("request_size_bytes", 0),
                record.get("response_size_bytes", 0),
                record.get("latency_ms", 0),
                record.get("num_messages", 0),
                record.get("system_prompt_chars", 0),
                record.get("last_user_msg_preview", ""),
                record.get("assistant_msg_preview", ""),
                record.get("tool_calls", "[]"),
                record.get("tool_call_count", 0),
                record.get("bash_commands", "[]"),
                record.get("files_read", "[]"),
                record.get("files_written", "[]"),
                record.get("urls_fetched", "[]"),
                record.get("sensitive_patterns", ""),
                record.get("sensitive_pattern_count", 0),
                record.get("stop_reason", ""),
                record.get("request_id", ""),
            ),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
