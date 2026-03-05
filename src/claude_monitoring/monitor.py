#!/usr/bin/env python3
"""
ai_monitor.py — AI Runtime Agent: CrowdStrike-Style Full Visibility Monitor
=============================================================================
Three-layer monitoring of ALL AI agent activity on your machine:
  Layer 1: NETWORK  — JSONL transcript tailing + network connection tracking
  Layer 2: FILESYSTEM — watchdog (FSEvents) file activity monitoring
  Layer 3: PROCESS — psutil process lifecycle and resource tracking

All events flow into a SQLite store and are served via a web dashboard on port 9081.

USAGE:
  python3 ai_monitor.py --start              # Start monitoring + dashboard
  python3 ai_monitor.py --scan               # One-shot process scan
  python3 ai_monitor.py --install-agent      # Install as macOS LaunchAgent
  python3 ai_monitor.py --uninstall-agent    # Remove LaunchAgent

DEPENDENCIES:
  pip3 install watchdog psutil
"""

import sys
import os
import re
import json
import time
import sqlite3
import signal
import hashlib
import shutil
import tempfile
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import deque

try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object


# ─────────────────────────────────────────────────────────────
# SECTION 1: CONFIG & CONSTANTS
# ─────────────────────────────────────────────────────────────

DASHBOARD_PORT = 9081
CLAUDE_PROJECTS_DIR = Path.home() / ".claude" / "projects"
OUTPUT_DIR = Path.home() / "claude_watch_output"
DB_PATH = OUTPUT_DIR / "monitor.db"
SCRIPT_PATH = Path(__file__).resolve()

# Two-tier process matching to reduce false positives
AI_PROCESS_EXACT = {
    "claude", "Claude", "ChatGPT", "ChatGPTHelper",
    "Ollama", "ollama", "Cursor", "Windsurf",
}

AI_PROCESS_PATTERNS = {
    "claude": {"exclude": []},
    "anthropic": {"exclude": []},
    "chatgpt": {"exclude": []},
    "ollama": {"exclude": []},
    "copilot": {"exclude": ["CursorUIViewService"]},
    "cursor": {"exclude": ["CursorUIViewService"]},
    "aider": {"exclude": []},
    "openai": {"exclude": []},
    "lmstudio": {"exclude": []},
    "cody": {"exclude": []},
    "gemini": {"exclude": []},
    "bedrock": {"exclude": []},
    "codex": {"exclude": []},
    "windsurf": {"exclude": []},
}

BROWSER_AI_PATTERNS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "gemini.google.com": "Gemini",
    "claude.ai": "Claude Web",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Copilot",
    "aistudio.google.com": "AI Studio",
    "deepseek.com": "DeepSeek",
}

SERVICE_CLASSIFICATION = {
    ".1e100.net": "Google APIs",
    ".googleapis.com": "Google APIs",
    ".anthropic.com": "Anthropic",
    ".openai.com": "OpenAI",
    ".azure.com": "Azure",
    ".amazonaws.com": "AWS",
    ".github.com": "GitHub",
    ".sentry.io": "Sentry",
    ".segment.io": "Segment",
    ".statsig.com": "Statsig",
    ".googleusercontent.com": "Anthropic API",
    ".bc.googleusercontent.com": "Anthropic API",
}

# Known Anthropic API IP prefixes (GCP-hosted)
ANTHROPIC_IP_PREFIXES = (
    "160.79.", "137.66.", "35.185.", "34.8.", "34.49.",
)

AI_HOSTS = {
    "api.anthropic.com": "anthropic_api",
    "statsig.anthropic.com": "anthropic_telemetry",
    "console.anthropic.com": "anthropic_console",
    "api.openai.com": "openai_api",
    "chatgpt.com": "chatgpt_web",
    "copilot.githubusercontent.com": "github_copilot",
    "api.githubcopilot.com": "github_copilot",
    "generativelanguage.googleapis.com": "gemini_api",
    "aiplatform.googleapis.com": "vertex_ai",
    "bedrock.amazonaws.com": "aws_bedrock",
    "api.mistral.ai": "mistral_api",
    "api.cohere.ai": "cohere_api",
    "api.groq.com": "groq_api",
    "api.together.xyz": "together_api",
    "api.perplexity.ai": "perplexity_api",
    "api.deepseek.com": "deepseek_api",
    "api.x.ai": "xai_grok_api",
    "api.replicate.com": "replicate_api",
    "api.fireworks.ai": "fireworks_api",
    "openrouter.ai": "openrouter_api",
    "sentry.io": "error_reporting",
    "ingest.sentry.io": "error_reporting",
    "api.statsig.com": "statsig_telemetry",
}

# Sensitive patterns with severity levels: critical, high, medium, low
SENSITIVE_PATTERNS = {
    # CRITICAL — immediate credential exposure
    "aws_key":           {"pattern": r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}",
                          "severity": "critical", "category": "credential"},
    "aws_secret":        {"pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
                          "severity": "critical", "category": "credential"},
    "private_key":       {"pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
                          "severity": "critical", "category": "credential"},
    "anthropic_key":     {"pattern": r"sk-ant-[A-Za-z0-9\-_]{40,}",
                          "severity": "critical", "category": "credential"},
    "openai_key":        {"pattern": r"sk-[A-Za-z0-9]{32,}",
                          "severity": "critical", "category": "credential"},
    "github_token":      {"pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
                          "severity": "critical", "category": "credential"},
    "slack_webhook":     {"pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                          "severity": "critical", "category": "credential"},
    "discord_webhook":   {"pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
                          "severity": "critical", "category": "credential"},
    "stripe_key":        {"pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",
                          "severity": "critical", "category": "credential"},

    # HIGH — secrets and tokens
    "jwt_token":         {"pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
                          "severity": "high", "category": "credential"},
    "bearer_token":      {"pattern": r"(?i)(?:Authorization|Bearer)\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9_\-\.]{20,}",
                          "severity": "high", "category": "credential"},
    "password_in_code":  {"pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
                          "severity": "high", "category": "credential"},
    "api_key_generic":   {"pattern": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
                          "severity": "high", "category": "credential"},
    "db_connection":     {"pattern": r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]{10,}",
                          "severity": "high", "category": "credential"},
    "base64_secret":     {"pattern": r"(?i)(?:secret|token|key|auth)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?",
                          "severity": "high", "category": "credential"},

    # MEDIUM — PII and sensitive data
    "ssn":               {"pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                          "severity": "medium", "category": "pii"},
    "credit_card":       {"pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b",
                          "severity": "medium", "category": "pii"},
    "phone_number":      {"pattern": r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
                          "severity": "medium", "category": "pii"},
    "email_bulk":        {"pattern": r"(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\s*[,;\n]\s*){3,}",
                          "severity": "medium", "category": "pii"},

    # LOW — informational / policy
    "env_file":          {"pattern": r"\.env(?:\.[a-z]+)?",
                          "severity": "low", "category": "policy"},
    "internal_url":      {"pattern": r"https?://(?:internal|staging|dev|local|corp|intranet)\.[a-z0-9.-]+",
                          "severity": "low", "category": "policy"},
    "ip_address_private":{"pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                          "severity": "low", "category": "policy"},
}

# Severity ordering for display
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

MODEL_PRICING = {
    "claude-opus-4":     {"input": 15.00, "output": 75.00},
    "claude-sonnet-4":   {"input": 3.00,  "output": 15.00},
    "claude-haiku-4":    {"input": 0.80,  "output": 4.00},
    "claude-3-5-sonnet": {"input": 3.00,  "output": 15.00},
    "claude-3-5-haiku":  {"input": 0.80,  "output": 4.00},
    "claude-3-opus":     {"input": 15.00, "output": 75.00},
    "default":           {"input": 3.00,  "output": 15.00},
}

# Subscription plan token limits (approximate monthly input+output tokens)
# Based on public Claude plan rate limits
PLAN_LIMITS = {
    "max_20x":       {"monthly_tokens": 900_000_000,  "label": "Max 20x"},
    "max_5x":        {"monthly_tokens": 225_000_000,  "label": "Max 5x"},
    "max":           {"monthly_tokens": 45_000_000,   "label": "Max"},
    "pro":           {"monthly_tokens": 45_000_000,   "label": "Pro"},
    "free":          {"monthly_tokens": 5_000_000,    "label": "Free"},
}

# In-memory live feed buffer
live_feed = deque(maxlen=500)
live_feed_lock = threading.Lock()

# Track active session CWDs for file monitoring
active_session_cwds = set()
active_cwds_lock = threading.Lock()

# Plan/subscription detection (populated on startup)
plan_info = {"is_subscription": False, "plan_tier": "", "cost_label": "Total Cost"}


# ─────────────────────────────────────────────────────────────
# SECTION 2: SQLITE EVENT STORE
# ─────────────────────────────────────────────────────────────

def init_db():
    """Initialize SQLite database with all required tables."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
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

    # Add title column to sessions if missing
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

    conn.commit()
    return conn


def get_thread_db():
    """Get a thread-local database connection."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────
# SECTION 3: UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def scan_sensitive(text):
    """Return list of dicts with pattern name, severity, category for matches found."""
    found = []
    if not text:
        return found
    # Limit scan size to prevent regex performance issues on huge texts
    scan_text = text[:50000] if len(text) > 50000 else text
    for name, info in SENSITIVE_PATTERNS.items():
        pattern = info["pattern"]
        try:
            if re.search(pattern, scan_text):
                found.append({
                    "name": name,
                    "severity": info["severity"],
                    "category": info["category"],
                })
        except re.error:
            continue
    return found


def estimate_cost(model, input_tokens, output_tokens, cache_read=0, cache_write=0):
    """Estimate USD cost from token counts."""
    pricing = MODEL_PRICING["default"]
    for key in sorted(MODEL_PRICING.keys(), key=len, reverse=True):
        if key != "default" and key in (model or ""):
            pricing = MODEL_PRICING[key]
            break
    cost = (input_tokens / 1_000_000 * pricing["input"] +
            output_tokens / 1_000_000 * pricing["output"] +
            cache_read / 1_000_000 * pricing["input"] * 0.1 +
            cache_write / 1_000_000 * pricing["input"] * 1.25)
    return round(cost, 6)


def now_iso():
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def push_live_event(event):
    """Push event to the in-memory live feed."""
    with live_feed_lock:
        live_feed.append(event)


def is_ai_process(name, cmdline, exe_path=""):
    """Check if a process is an AI process using two-tier matching."""
    if name in AI_PROCESS_EXACT:
        return True
    # Skip macOS system services
    if exe_path and (exe_path.startswith("/System/Library/") or exe_path.startswith("/usr/libexec/")):
        return False
    name_lower = (name or "").lower()
    cmdline_lower = (cmdline or "").lower()
    for pattern, config in AI_PROCESS_PATTERNS.items():
        if pattern in name_lower or pattern in cmdline_lower:
            if any(excl in name for excl in config.get("exclude", [])):
                continue
            return True
    return False


def compute_forecast(db):
    """Compute token burn rate and forecast from DB data."""
    forecast = {
        "daily_burn_rate": 0,
        "avg_7d_burn": 0,
        "daily_breakdown": [],
        "days_remaining": None,
        "monthly_limit": None,
        "monthly_used": 0,
        "burn_trend": "stable",
    }

    # Daily token usage for last 14 days
    rows = db.execute(
        """SELECT date(timestamp) as day,
                  SUM(json_extract(data_json, '$.input_tokens')) as input_t,
                  SUM(json_extract(data_json, '$.output_tokens')) as output_t
           FROM events
           WHERE event_type='token_usage'
             AND timestamp > datetime('now', '-14 days')
           GROUP BY day ORDER BY day"""
    ).fetchall()

    daily = []
    for r in rows:
        total = (r['input_t'] or 0) + (r['output_t'] or 0)
        daily.append({
            "day": r['day'],
            "input_tokens": r['input_t'] or 0,
            "output_tokens": r['output_t'] or 0,
            "total_tokens": total,
        })

    forecast["daily_breakdown"] = daily

    if not daily:
        return forecast

    # Calculate averages
    totals = [d["total_tokens"] for d in daily]
    last_7 = totals[-7:] if len(totals) >= 7 else totals
    last_3 = totals[-3:] if len(totals) >= 3 else totals

    forecast["avg_7d_burn"] = int(sum(last_7) / len(last_7)) if last_7 else 0
    forecast["daily_burn_rate"] = int(sum(last_3) / len(last_3)) if last_3 else 0

    # Trend: compare last 3 days avg to previous 4 days avg
    if len(totals) >= 7:
        recent_avg = sum(totals[-3:]) / 3
        earlier_avg = sum(totals[-7:-3]) / 4
        if earlier_avg > 0:
            ratio = recent_avg / earlier_avg
            if ratio > 1.3:
                forecast["burn_trend"] = "increasing"
            elif ratio < 0.7:
                forecast["burn_trend"] = "decreasing"

    # Subscription forecast
    if plan_info.get("is_subscription"):
        tier = (plan_info.get("plan_tier", "") or "").lower().replace(" ", "_")
        plan = None
        for key, data in PLAN_LIMITS.items():
            if key in tier:
                plan = data
                break
        if not plan:
            # Default to Pro limits
            plan = PLAN_LIMITS.get("pro", {"monthly_tokens": 45_000_000, "label": "Pro"})

        forecast["monthly_limit"] = plan["monthly_tokens"]
        forecast["plan_label"] = plan["label"]

        # Actual current-month token usage
        month_rows = db.execute(
            """SELECT COALESCE(SUM(json_extract(data_json, '$.input_tokens')), 0) +
                      COALESCE(SUM(json_extract(data_json, '$.output_tokens')), 0) as total
               FROM events WHERE event_type='token_usage'
                 AND timestamp >= date('now', 'start of month')"""
        ).fetchone()
        monthly_used = month_rows[0] if month_rows else 0
        forecast["monthly_used"] = monthly_used

        if forecast["daily_burn_rate"] > 0:
            remaining_tokens = plan["monthly_tokens"] - monthly_used
            if remaining_tokens <= 0:
                forecast["days_remaining"] = 0
            else:
                forecast["days_remaining"] = max(1, int(remaining_tokens / forecast["daily_burn_rate"]))

    return forecast


def detect_plan_info():
    """Detect Claude subscription plan from local config files."""
    global plan_info
    info = {"is_subscription": False, "plan_tier": "", "cost_label": "Total Cost"}

    # Check stats-cache.json for modelUsage costUSD
    stats_path = Path.home() / ".claude" / "stats-cache.json"
    if stats_path.exists():
        try:
            with open(stats_path) as f:
                stats = json.load(f)
            model_usage = stats.get("modelUsage", {})
            if model_usage:
                all_zero = all(
                    m.get("costUSD", 0) == 0
                    for m in model_usage.values()
                )
                if all_zero:
                    info["is_subscription"] = True
        except Exception:
            pass

    # Check credentials for plan tier
    creds_path = Path.home() / ".claude" / ".credentials.json"
    if creds_path.exists():
        try:
            with open(creds_path) as f:
                creds = json.load(f)
            oauth = creds.get("claudeAiOauth", {})
            sub_type = oauth.get("subscriptionType", "")
            rate_tier = oauth.get("rateLimitTier", "")
            if sub_type:
                info["plan_tier"] = sub_type
                info["is_subscription"] = True
            if rate_tier:
                info["rate_tier"] = rate_tier
                if not info["plan_tier"]:
                    info["plan_tier"] = rate_tier
        except Exception:
            pass

    # Fallback: if no API key files found, assume subscription
    api_key_path = Path.home() / ".claude" / "api_key"
    if not api_key_path.exists() and not info.get("plan_tier"):
        # No API key file — likely subscription user
        info["is_subscription"] = True

    if info["is_subscription"]:
        tier = info.get("plan_tier", "")
        info["cost_label"] = f"Plan: {tier}" if tier else "Subscription"

    plan_info = info
    return info


# ─────────────────────────────────────────────────────────────
# SECTION 4: JSONL SESSION WATCHER (Layer 1a — Network/Content)
# ─────────────────────────────────────────────────────────────

class JSONLSessionWatcher:
    """Watches Claude JSONL transcript files for new data."""

    def __init__(self):
        self.file_positions = {}  # path -> last_read_offset
        self._file_lock = threading.Lock()  # Thread safety for file positions
        self._seen_uuids = set()  # Dedup: track seen record UUIDs
        self.db = get_thread_db()
        self._stop = threading.Event()
        self._pending_commits = 0

    def stop(self):
        self._stop.set()

    def _ensure_session(self, session_id, jsonl_path, cwd=None, start_time=None):
        """Create or update session record."""
        try:
            self.db.execute(
                """INSERT INTO sessions (session_id, start_time, cwd, jsonl_path, last_activity)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     last_activity=excluded.last_activity,
                     cwd=COALESCE(excluded.cwd, sessions.cwd),
                     jsonl_path=COALESCE(excluded.jsonl_path, sessions.jsonl_path)""",
                (session_id, start_time or now_iso(), cwd, str(jsonl_path), now_iso())
            )
            self.db.commit()
        except Exception:
            pass

    def _update_session_stats(self, session_id, model=None, cost=0,
                               input_tokens=0, output_tokens=0, is_turn=False):
        """Update session aggregate statistics."""
        try:
            parts = ["last_activity=?"]
            vals = [now_iso()]
            if model:
                parts.append("model=?")
                vals.append(model)
            if cost:
                parts.append("total_cost=total_cost+?")
                vals.append(cost)
            if input_tokens:
                parts.append("total_input_tokens=total_input_tokens+?")
                vals.append(input_tokens)
            if output_tokens:
                parts.append("total_output_tokens=total_output_tokens+?")
                vals.append(output_tokens)
            if is_turn:
                parts.append("total_turns=total_turns+1")
            vals.append(session_id)
            self.db.execute(
                f"UPDATE sessions SET {', '.join(parts)} WHERE session_id=?", vals
            )
            self.db.commit()
        except Exception:
            pass

    def _store_event(self, timestamp, session_id, event_type, source, data):
        """Store event in database and push to live feed."""
        data_json = json.dumps(data, default=str)
        try:
            self.db.execute(
                "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?,?,?,?,?)",
                (timestamp, session_id, event_type, source, data_json)
            )
            self._pending_commits += 1
            # Batch commits for performance during backfill
            if self._pending_commits >= 50:
                self.db.commit()
                self._pending_commits = 0
        except Exception:
            pass

        feed_item = {
            "timestamp": timestamp,
            "session_id": session_id,
            "event_type": event_type,
            "source": source,
            "summary": self._make_summary(event_type, data),
        }
        push_live_event(feed_item)

    def _make_summary(self, event_type, data):
        """Create a short human-readable summary for the live feed."""
        if event_type == "user_prompt":
            text = data.get("text", "")
            return f'prompt: "{text[:80]}..."' if len(text) > 80 else f'prompt: "{text}"'
        elif event_type == "assistant_response":
            text = data.get("text", "")
            return f'response: "{text[:80]}..."' if len(text) > 80 else f'response: "{text}"'
        elif event_type == "thinking":
            return f'thinking ({data.get("length", 0)} chars)'
        elif event_type == "tool_use":
            name = data.get("name", "?")
            inp = data.get("input_preview", "")
            return f'{name}: {inp[:60]}'
        elif event_type == "tool_result":
            return f'result ({data.get("length", 0)} chars)'
        elif event_type == "token_usage":
            inp = data.get("input_tokens", 0)
            out = data.get("output_tokens", 0)
            cost = data.get("cost", 0)
            return f'↑{inp}t ↓{out}t ${cost:.4f}'
        elif event_type == "sensitive_data":
            sev = data.get("severity", "medium").upper()
            return f'ALERT [{sev}]: {", ".join(data.get("patterns", []))}'
        else:
            return event_type

    def process_jsonl_file(self, jsonl_path):
        """Read new lines from a JSONL file and process them."""
        path_str = str(jsonl_path)

        try:
            file_size = os.path.getsize(path_str)
        except OSError:
            return

        with self._file_lock:
            last_pos = self.file_positions.get(path_str, 0)
            if file_size <= last_pos:
                return

            try:
                with open(path_str, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(last_pos)
                    new_data = f.read()
                    self.file_positions[path_str] = f.tell()
            except (OSError, IOError):
                return

        for line in new_data.strip().split('\n'):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._process_record(record, jsonl_path)

        # Flush any pending commits
        if self._pending_commits > 0:
            try:
                self.db.commit()
                self._pending_commits = 0
            except Exception:
                pass

    def _process_record(self, record, jsonl_path):
        """Process a single JSONL record."""
        try:
            # Dedup: skip records we've already processed
            rec_uuid = record.get("uuid", "")
            if rec_uuid:
                if rec_uuid in self._seen_uuids:
                    return
                self._seen_uuids.add(rec_uuid)

            rec_type = record.get("type", "")
            session_id = record.get("sessionId", "")
            timestamp = record.get("timestamp", now_iso())
            cwd = record.get("cwd", "")

            if not session_id:
                return

            self._ensure_session(session_id, jsonl_path, cwd=cwd, start_time=timestamp)

            # Track active CWDs for file monitoring
            if cwd:
                with active_cwds_lock:
                    active_session_cwds.add(cwd)

            if rec_type == "user":
                self._process_user_message(record, session_id, timestamp)
            elif rec_type == "assistant":
                self._process_assistant_message(record, session_id, timestamp)
            elif rec_type == "system":
                self._store_event(timestamp, session_id, "system_event", "network",
                                  {"subtype": record.get("subtype", "")})
            elif rec_type == "progress":
                self._process_progress(record, session_id, timestamp)
        except Exception:
            pass  # Never crash on a single malformed record

    def _set_session_title(self, session_id, text):
        """Set session title from first user message if not already set."""
        try:
            row = self.db.execute(
                "SELECT title, total_turns FROM sessions WHERE session_id=?",
                (session_id,)
            ).fetchone()
            if row and not row[0] and (row[1] or 0) <= 1:
                # Truncate at word boundary around 100 chars
                title = text[:120]
                if len(text) > 120:
                    last_space = title.rfind(' ')
                    if last_space > 60:
                        title = title[:last_space]
                    title = title.rstrip() + "..."
                self.db.execute(
                    "UPDATE sessions SET title=? WHERE session_id=?",
                    (title, session_id)
                )
                self.db.commit()
        except Exception:
            pass

    def _process_user_message(self, record, session_id, timestamp):
        """Process a user message record."""
        message = record.get("message", {})
        content = message.get("content", "")

        if isinstance(content, str):
            # Simple text prompt
            self._store_event(timestamp, session_id, "user_prompt", "network",
                              {"text": content, "role": "user"})
            self._check_sensitive(content, session_id, timestamp, "user_prompt")
            self._update_session_stats(session_id, is_turn=True)
            self._set_session_title(session_id, content)

        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")

                if btype == "text":
                    text = block.get("text", "")
                    self._store_event(timestamp, session_id, "user_prompt", "network",
                                      {"text": text, "role": "user"})
                    self._check_sensitive(text, session_id, timestamp, "user_prompt")
                    self._update_session_stats(session_id, is_turn=True)
                    self._set_session_title(session_id, text)

                elif btype == "tool_result":
                    tool_use_id = block.get("tool_use_id", "")
                    result_content = block.get("content", "")
                    if isinstance(result_content, list):
                        parts = []
                        for rc in result_content:
                            if isinstance(rc, dict) and rc.get("type") == "text":
                                parts.append(rc.get("text", ""))
                        result_content = "\n".join(parts)
                    result_str = str(result_content)
                    self._store_event(timestamp, session_id, "tool_result", "network", {
                        "tool_use_id": tool_use_id,
                        "content": result_str[:5000],
                        "length": len(result_str),
                        "is_error": block.get("is_error", False),
                    })
                    self._check_sensitive(result_str, session_id, timestamp, "tool_result")

    def _process_assistant_message(self, record, session_id, timestamp):
        """Process an assistant message record."""
        message = record.get("message", {})
        content = message.get("content", [])
        model = message.get("model", "")
        usage = message.get("usage", {})
        stop_reason = message.get("stop_reason", "")

        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_write = usage.get("cache_creation_input_tokens", 0)
        cost = estimate_cost(model, input_tokens, output_tokens, cache_read, cache_write)

        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "")

            if btype == "thinking":
                thinking_text = block.get("thinking", "")
                self._store_event(timestamp, session_id, "thinking", "network", {
                    "text": thinking_text[:5000],
                    "length": len(thinking_text),
                })

            elif btype == "text":
                text = block.get("text", "")
                self._store_event(timestamp, session_id, "assistant_response", "network", {
                    "text": text,
                    "model": model,
                    "stop_reason": stop_reason,
                })
                self._check_sensitive(text, session_id, timestamp, "assistant_response")

            elif btype == "tool_use":
                tool_name = block.get("name", "")
                tool_input = block.get("input", {})
                tool_id = block.get("id", "")

                # Build a preview of the input
                input_preview = ""
                if tool_name in ("Bash", "bash"):
                    input_preview = tool_input.get("command", "")[:200]
                elif tool_name in ("Read", "read_file"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Write", "write_file", "create_file"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Edit", "str_replace_editor"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Glob", "Grep"):
                    input_preview = tool_input.get("pattern", "")
                elif tool_name == "WebFetch":
                    input_preview = tool_input.get("url", "")
                elif tool_name == "WebSearch":
                    input_preview = tool_input.get("query", "")
                else:
                    input_preview = json.dumps(tool_input, default=str)[:200]

                self._store_event(timestamp, session_id, "tool_use", "network", {
                    "name": tool_name,
                    "id": tool_id,
                    "input": tool_input,
                    "input_preview": input_preview,
                })
                self._check_sensitive(json.dumps(tool_input, default=str),
                                       session_id, timestamp, f"tool:{tool_name}")

        # Store token usage event
        if input_tokens or output_tokens:
            self._store_event(timestamp, session_id, "token_usage", "network", {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_read_tokens": cache_read,
                "cache_write_tokens": cache_write,
                "cost": cost,
                "stop_reason": stop_reason,
            })
            self._update_session_stats(session_id, model=model, cost=cost,
                                        input_tokens=input_tokens,
                                        output_tokens=output_tokens)

    def _process_progress(self, record, session_id, timestamp):
        """Process a progress record."""
        data = record.get("data", {})
        dtype = data.get("type", "")
        if dtype == "bash_progress":
            output = data.get("output", "") or data.get("fullOutput", "")
            if output:
                self._store_event(timestamp, session_id, "bash_progress", "network", {
                    "output": output[:2000],
                    "elapsed": data.get("elapsedTimeSeconds", 0),
                })

    def _check_sensitive(self, text, session_id, timestamp, context):
        """Scan text for sensitive patterns and store alerts."""
        if not text:
            return
        matches = scan_sensitive(text)
        if matches:
            # Find highest severity
            severity = min((m["severity"] for m in matches),
                           key=lambda s: SEVERITY_ORDER.get(s, 99))
            pattern_names = [m["name"] for m in matches]
            categories = list(set(m["category"] for m in matches))
            self._store_event(timestamp, session_id, "sensitive_data", "network", {
                "patterns": pattern_names,
                "severity": severity,
                "categories": categories,
                "context": context,
                "snippet": text[:200],
            })


class JSONLFileHandler(FileSystemEventHandler):
    """Watchdog handler for JSONL file changes."""

    def __init__(self, watcher):
        super().__init__()
        self.watcher = watcher

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.jsonl'):
            self.watcher.process_jsonl_file(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.jsonl'):
            self.watcher.process_jsonl_file(event.src_path)


# ─────────────────────────────────────────────────────────────
# SECTION 5: PROCESS SCANNER (Layer 3)
# ─────────────────────────────────────────────────────────────

class ProcessScanner:
    """Scans for AI agent processes and tracks their lifecycle."""

    def __init__(self):
        self.known_pids = {}  # pid -> process info
        self.db = get_thread_db()
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def scan_once(self):
        """Perform a single scan of running processes."""
        if not psutil:
            return []

        found = []
        current_pids = set()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline',
                                              'cpu_percent', 'memory_percent',
                                              'create_time', 'status']):
                try:
                    info = proc.info
                    pid = info['pid']
                    name = info.get('name') or ''
                    cmdline_str = ' '.join(info.get('cmdline') or [])

                    # Get executable path for system service detection
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ""

                    if not is_ai_process(name, cmdline_str, exe_path):
                        continue

                    current_pids.add(pid)
                    proc_data = {
                        "pid": pid,
                        "name": name,
                        "cmdline": cmdline_str[:500],
                        "cpu_percent": info.get('cpu_percent', 0) or 0,
                        "memory_percent": round(info.get('memory_percent', 0) or 0, 2),
                        "status": info.get('status', ''),
                        "create_time": datetime.fromtimestamp(
                            info.get('create_time', 0), tz=timezone.utc
                        ).isoformat() if info.get('create_time') else '',
                    }
                    found.append(proc_data)

                    if pid not in self.known_pids:
                        # New process detected
                        self.known_pids[pid] = proc_data
                        try:
                            self.db.execute(
                                """INSERT INTO processes (pid, name, cmdline, start_time,
                                   cpu_percent, memory_percent, status)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (pid, proc_data["name"], proc_data["cmdline"],
                                 proc_data["create_time"], proc_data["cpu_percent"],
                                 proc_data["memory_percent"], "running")
                            )
                            self.db.commit()
                        except Exception:
                            pass
                        push_live_event({
                            "timestamp": now_iso(),
                            "event_type": "process_start",
                            "source": "process",
                            "summary": f'NEW: {proc_data["name"]} (PID {pid})',
                        })
                    else:
                        # Update existing process
                        self.known_pids[pid] = proc_data
                        try:
                            self.db.execute(
                                "UPDATE processes SET cpu_percent=?, memory_percent=? WHERE pid=? AND end_time IS NULL",
                                (proc_data["cpu_percent"], proc_data["memory_percent"], pid)
                            )
                            self.db.commit()
                        except Exception:
                            pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception:
            pass

        # Detect terminated processes
        terminated = set(self.known_pids.keys()) - current_pids
        for pid in terminated:
            old = self.known_pids.pop(pid)
            try:
                self.db.execute(
                    "UPDATE processes SET end_time=?, status='terminated' WHERE pid=? AND end_time IS NULL",
                    (now_iso(), pid)
                )
                self.db.commit()
            except Exception:
                pass
            push_live_event({
                "timestamp": now_iso(),
                "event_type": "process_stop",
                "source": "process",
                "summary": f'STOPPED: {old["name"]} (PID {pid})',
            })

        return found

    def run_loop(self):
        """Continuous scanning loop."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(2)


# ─────────────────────────────────────────────────────────────
# SECTION 6: NETWORK CONNECTION MONITOR (Layer 1b)
# ─────────────────────────────────────────────────────────────

class NetworkMonitor:
    """Monitors network connections from AI agent processes."""

    def __init__(self):
        self.db = get_thread_db()
        self._stop = threading.Event()
        self.seen_connections = set()  # (pid, remote_host, remote_port)
        self._dns_cache = {}  # ip -> hostname (cached reverse DNS)

    def stop(self):
        self._stop.set()

    def _reverse_dns(self, ip):
        """Reverse DNS lookup with caching. Returns hostname or original IP."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except Exception:
            self._dns_cache[ip] = ip
            return ip

    def _resolve_service(self, host):
        """Map a hostname/IP to a known AI service, with reverse DNS fallback."""
        # First try direct match against host string
        for pattern, service in AI_HOSTS.items():
            if pattern in host:
                return service, host

        # Try SERVICE_CLASSIFICATION for friendly names
        for suffix, friendly in SERVICE_CLASSIFICATION.items():
            if host.endswith(suffix) or suffix[1:] in host:
                return friendly, host

        # If host looks like an IP, try known IP prefixes first
        if host and (host[0].isdigit() or ':' in host):
            if any(host.startswith(pfx) for pfx in ANTHROPIC_IP_PREFIXES):
                return "Anthropic API", host

            hostname = self._reverse_dns(host)
            if hostname != host:
                for pattern, service in AI_HOSTS.items():
                    if pattern in hostname:
                        return service, hostname
                for suffix, friendly in SERVICE_CLASSIFICATION.items():
                    if hostname.endswith(suffix) or suffix[1:] in hostname:
                        return friendly, hostname
                return None, hostname

        return None, host

    def scan_once(self):
        """Scan network connections of AI processes."""
        if not psutil:
            return []

        found = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    info = proc.info
                    name = info.get('name') or ''
                    cmdline_str = ' '.join(info.get('cmdline') or [])
                    if not is_ai_process(name, cmdline_str):
                        continue

                    pid = info['pid']
                    try:
                        conns = proc.net_connections(kind='inet')
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue

                    for conn in conns:
                        if conn.status != 'ESTABLISHED' or not conn.raddr:
                            continue
                        remote_host = conn.raddr.ip
                        remote_port = conn.raddr.port

                        conn_key = (pid, remote_host, remote_port)
                        if conn_key in self.seen_connections:
                            continue
                        self.seen_connections.add(conn_key)

                        service, resolved_host = self._resolve_service(remote_host)
                        display_host = resolved_host if resolved_host != remote_host else remote_host
                        conn_data = {
                            "pid": pid,
                            "process_name": info.get('name', ''),
                            "remote_host": display_host,
                            "remote_ip": remote_host,
                            "remote_port": remote_port,
                            "status": conn.status,
                            "service": service or "unknown",
                        }
                        found.append(conn_data)

                        try:
                            self.db.execute(
                                """INSERT INTO connections
                                   (timestamp, pid, process_name, remote_host, remote_port, status, service)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (now_iso(), pid, conn_data["process_name"],
                                 display_host, remote_port, conn.status,
                                 conn_data["service"])
                            )
                            self.db.commit()
                        except Exception:
                            pass

                        if service:
                            push_live_event({
                                "timestamp": now_iso(),
                                "event_type": "connection",
                                "source": "network",
                                "summary": f'{info.get("name","?")} → {display_host}:{remote_port} ({service})',
                            })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        # Clean stale connection keys periodically
        if len(self.seen_connections) > 10000:
            self.seen_connections.clear()

        return found

    def run_loop(self):
        """Continuous monitoring loop."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(5)


# ─────────────────────────────────────────────────────────────
# SECTION 7: FILE ACTIVITY MONITOR (Layer 2)
# ─────────────────────────────────────────────────────────────

class FileActivityHandler(FileSystemEventHandler):
    """Monitors file changes in AI agent working directories."""

    def __init__(self):
        super().__init__()
        self.db = get_thread_db()
        # Ignore patterns
        self._ignore = {'.git', '__pycache__', 'node_modules', '.DS_Store',
                        '.pyc', '.pyo', '.swp', '.swo'}

    def _should_ignore(self, path):
        parts = Path(path).parts
        return any(ig in parts or path.endswith(ig) for ig in self._ignore)

    def _record(self, event, operation):
        if event.is_directory:
            return
        path = event.src_path
        if self._should_ignore(path):
            return

        timestamp = now_iso()
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            size = 0

        try:
            self.db.execute(
                "INSERT INTO file_events (timestamp, path, operation, size) VALUES (?, ?, ?, ?)",
                (timestamp, path, operation, size)
            )
            self.db.commit()
        except Exception:
            pass

        push_live_event({
            "timestamp": timestamp,
            "event_type": f"file_{operation}",
            "source": "filesystem",
            "summary": f'{operation}: {Path(path).name} ({size} bytes)',
        })

    def on_created(self, event):
        self._record(event, "created")

    def on_modified(self, event):
        self._record(event, "modified")

    def on_deleted(self, event):
        self._record(event, "deleted")


# ─────────────────────────────────────────────────────────────
# SECTION 7b: CHROME HISTORY WATCHER (Browser AI)
# ─────────────────────────────────────────────────────────────

class ChromeHistoryWatcher:
    """Watches Chrome browser history for AI service visits."""

    def __init__(self):
        self.db = get_thread_db()
        self._stop = threading.Event()
        self.last_check_times = {}  # profile_path -> last chrome timestamp
        self.chrome_dir = (
            Path.home() / "Library" / "Application Support"
            / "Google" / "Chrome"
        )

    def stop(self):
        self._stop.set()

    def _chrome_ts_to_iso(self, chrome_ts):
        """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO string."""
        if not chrome_ts:
            return None
        try:
            unix_ts = chrome_ts / 1_000_000 - 11644473600
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _extract_conversation_id(self, url, service):
        """Extract conversation ID from AI service URLs."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            if service == "ChatGPT" and "/c/" in path:
                return path.split("/c/")[-1].split("/")[0].split("?")[0]
            elif service == "Gemini" and "/app/" in path:
                return path.split("/app/")[-1].split("/")[0].split("?")[0]
            elif service == "Claude Web" and "/chat/" in path:
                return path.split("/chat/")[-1].split("/")[0].split("?")[0]
        except Exception:
            pass
        return None

    def _find_history_files(self):
        """Find all Chrome History files across all profiles."""
        if not self.chrome_dir.exists():
            return []
        paths = []
        for entry in self.chrome_dir.iterdir():
            if entry.is_dir() and (entry.name == "Default" or entry.name.startswith("Profile")):
                hist = entry / "History"
                if hist.exists():
                    paths.append(hist)
        return paths

    def scan_once(self):
        """Copy Chrome history DBs and query for new AI visits across all profiles."""
        history_files = self._find_history_files()
        if not history_files:
            return []

        all_found = []
        url_conditions = " OR ".join(
            f"urls.url LIKE '%{domain}%'" for domain in BROWSER_AI_PATTERNS
        )

        for hist_path in history_files:
            profile_key = str(hist_path)
            tmp_path = None
            try:
                tmp_fd, tmp_path = tempfile.mkstemp(suffix='.db')
                os.close(tmp_fd)
                shutil.copy2(str(hist_path), tmp_path)

                conn = sqlite3.connect(tmp_path)
                conn.row_factory = sqlite3.Row

                last_check = self.last_check_times.get(profile_key, 0)
                if last_check == 0:
                    # First run: look back 7 days
                    cutoff = int((time.time() + 11644473600) * 1_000_000) - (7 * 24 * 3600 * 1_000_000)
                else:
                    cutoff = last_check

                query = f"""
                    SELECT urls.url, urls.title, visits.visit_time, visits.visit_duration
                    FROM visits
                    JOIN urls ON visits.url = urls.id
                    WHERE ({url_conditions})
                      AND visits.visit_time > ?
                    ORDER BY visits.visit_time ASC
                """

                rows = conn.execute(query, (cutoff,)).fetchall()

                for row in rows:
                    url = row['url']
                    title = row['title'] or ''
                    visit_time = row['visit_time']
                    duration = (row['visit_duration'] or 0) / 1_000_000

                    service = None
                    for domain, svc in BROWSER_AI_PATTERNS.items():
                        if domain in url:
                            service = svc
                            break
                    if not service:
                        continue

                    visit_iso = self._chrome_ts_to_iso(visit_time)
                    conv_id = self._extract_conversation_id(url, service)

                    try:
                        self.db.execute(
                            """INSERT INTO browser_sessions
                               (service, url, title, conversation_id, visit_time, duration_seconds)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (service, url, title, conv_id, visit_iso, duration)
                        )
                    except Exception:
                        pass

                    all_found.append({
                        "service": service,
                        "title": title,
                        "url": url,
                        "visit_time": visit_iso,
                        "duration": duration,
                        "conversation_id": conv_id,
                    })

                    if visit_time > self.last_check_times.get(profile_key, 0):
                        self.last_check_times[profile_key] = visit_time

                    push_live_event({
                        "timestamp": visit_iso,
                        "event_type": "browser_ai",
                        "source": "browser",
                        "summary": (
                            f'BROWSER: {service} — {title[:60]}'
                            + (f' ({int(duration)}s)' if duration else '')
                        ),
                    })

                conn.close()

            except Exception:
                pass
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

        if all_found:
            try:
                self.db.commit()
            except Exception:
                pass

        return all_found

    def run_loop(self):
        """Poll Chrome history every 60 seconds."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(60)


# ─────────────────────────────────────────────────────────────
# SECTION 8: WEB DASHBOARD SERVER
# ─────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        routes = {
            '/': self._serve_dashboard,
            '/api/sessions': self._api_sessions,
            '/api/session': self._api_session_detail,
            '/api/feed': self._api_feed,
            '/api/stats': self._api_stats,
            '/api/processes': self._api_processes,
            '/api/files': self._api_files,
            '/api/connections': self._api_connections,
            '/api/browser': self._api_browser,
            '/api/alerts': self._api_alerts,
            '/api/session_turns': self._api_session_turns,
            '/api/browser/sessions': self._api_browser_sessions,
            '/api/browser/session_detail': self._api_browser_session_detail,
            '/api/activity/timeline': self._api_activity_timeline,
            '/api/process_detail': self._api_process_detail,
            '/api/export': self._api_export,
        }

        # Match path prefixes for dynamic routes
        if path.startswith('/api/browser/session/'):
            params['conversation_id'] = [path.split('/api/browser/session/')[1]]
            path = '/api/browser/session_detail'
        elif path.startswith('/api/process/'):
            params['pid'] = [path.split('/api/process/')[1]]
            path = '/api/process_detail'
        elif path.startswith('/api/session/'):
            remainder = path.split('/api/session/')[1]
            if remainder.endswith('/turns'):
                params['id'] = [remainder[:-len('/turns')]]
                path = '/api/session_turns'
            else:
                params['id'] = [remainder]
                path = '/api/session'

        handler = routes.get(path)
        if handler:
            try:
                handler(params)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "not found", "path": path}, 404)

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self, params):
        self._send_html(DASHBOARD_HTML)

    def _api_sessions(self, params):
        db = get_thread_db()
        q = params.get('q', [''])[0].strip()
        sort = params.get('sort', ['recent'])[0]
        limit = int(params.get('limit', ['200'])[0])

        sort_map = {
            "recent": "last_activity DESC",
            "newest": "start_time DESC",
            "turns": "total_turns DESC",
            "tokens": "total_input_tokens DESC",
        }
        order = sort_map.get(sort, "last_activity DESC")

        if q:
            rows = db.execute(
                f"""SELECT session_id, start_time, cwd, model, total_cost,
                          total_input_tokens, total_output_tokens, total_turns,
                          jsonl_path, last_activity, title
                   FROM sessions
                   WHERE title LIKE ? OR session_id LIKE ? OR cwd LIKE ? OR model LIKE ?
                   ORDER BY {order} LIMIT ?""",
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', limit)
            ).fetchall()
        else:
            rows = db.execute(
                f"""SELECT session_id, start_time, cwd, model, total_cost,
                          total_input_tokens, total_output_tokens, total_turns,
                          jsonl_path, last_activity, title
                   FROM sessions ORDER BY {order} LIMIT ?""",
                (limit,)
            ).fetchall()
        sessions = [dict(r) for r in rows]

        # Add source field to CLI sessions
        for s in sessions:
            s['source'] = 'cli'

        # Batch-fetch alert counts per session
        session_ids = [s['session_id'] for s in sessions]
        if session_ids:
            placeholders = ','.join('?' * len(session_ids))
            alert_rows = db.execute(
                f"""SELECT session_id, COUNT(*) as cnt FROM events
                    WHERE event_type='sensitive_data' AND session_id IN ({placeholders})
                    GROUP BY session_id""",
                session_ids
            ).fetchall()
            alert_map = {r['session_id']: r['cnt'] for r in alert_rows}
            for s in sessions:
                s['alert_count'] = alert_map.get(s['session_id'], 0)

        # Optionally include browser sessions
        include_browser = params.get('include_browser', ['false'])[0].lower() == 'true'
        source_filter = params.get('source', [''])[0].lower()

        if include_browser or source_filter in ('all', 'browser'):
            browser_rows = db.execute(
                """SELECT conversation_id, service,
                          MIN(visit_time) as start_time,
                          MAX(visit_time) as last_activity,
                          COUNT(*) as total_turns,
                          COALESCE(SUM(duration_seconds), 0) as total_duration,
                          (SELECT b2.title FROM browser_sessions b2
                           WHERE b2.conversation_id = browser_sessions.conversation_id
                             AND b2.title IS NOT NULL AND b2.title != ''
                             AND b2.title != b2.service
                           ORDER BY b2.visit_time DESC LIMIT 1) as title
                   FROM browser_sessions
                   WHERE conversation_id IS NOT NULL AND conversation_id != ''
                   GROUP BY conversation_id
                   ORDER BY last_activity DESC
                   LIMIT 50"""
            ).fetchall()

            for r in browser_rows:
                rd = dict(r)
                sessions.append({
                    'session_id': 'browser_' + (rd['conversation_id'] or ''),
                    'conversation_id': rd['conversation_id'],
                    'source': 'browser',
                    'start_time': rd['start_time'],
                    'last_activity': rd['last_activity'],
                    'title': rd['title'] or rd['service'],
                    'model': rd['service'],
                    'service': rd['service'],
                    'cwd': '',
                    'total_cost': 0,
                    'total_input_tokens': 0,
                    'total_output_tokens': 0,
                    'total_turns': rd['total_turns'],
                    'total_duration': rd['total_duration'],
                    'alert_count': 0,
                })

        # Filter by source if requested
        if source_filter and source_filter not in ('all', ''):
            sessions = [s for s in sessions if s.get('source') == source_filter]

        # Re-sort mixed list
        if include_browser or source_filter == 'all':
            sort_key = {'recent': 'last_activity', 'newest': 'start_time'}.get(sort, 'last_activity')
            sessions.sort(key=lambda s: s.get(sort_key, '') or '', reverse=True)

        self._send_json({"sessions": sessions})

    def _api_session_detail(self, params):
        session_id = params.get('id', [''])[0]
        if not session_id:
            self._send_json({"error": "missing session id"}, 400)
            return

        db = get_thread_db()

        # Get session info
        session = db.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if not session:
            self._send_json({"error": "session not found"}, 404)
            return

        # Get all events for this session, ordered by timestamp
        events = db.execute(
            """SELECT id, timestamp, event_type, source_layer, data_json
               FROM events WHERE session_id=? ORDER BY id ASC""",
            (session_id,)
        ).fetchall()

        event_list = []
        for e in events:
            try:
                data = json.loads(e['data_json'])
            except (json.JSONDecodeError, TypeError):
                data = {}
            event_list.append({
                "id": e['id'],
                "timestamp": e['timestamp'],
                "event_type": e['event_type'],
                "source": e['source_layer'],
                "data": data,
            })

        self._send_json({
            "session": dict(session),
            "events": event_list,
        })

    def _api_session_turns(self, params):
        session_id = params.get('id', [''])[0]
        if not session_id:
            self._send_json({"error": "missing session id"}, 400)
            return

        db = get_thread_db()
        session = db.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if not session:
            self._send_json({"error": "not found"}, 404)
            return

        events = db.execute(
            """SELECT id, timestamp, event_type, source_layer, data_json
               FROM events WHERE session_id=? ORDER BY id ASC""",
            (session_id,)
        ).fetchall()

        turns = []
        current_turn = None
        turn_num = 0
        cumulative_input = 0
        cumulative_output = 0

        for e in events:
            try:
                data = json.loads(e['data_json']) if e['data_json'] else {}
            except (json.JSONDecodeError, TypeError):
                data = {}
            evt = {"id": e['id'], "timestamp": e['timestamp'],
                   "event_type": e['event_type'], "data": data}

            if e['event_type'] == 'user_prompt':
                if current_turn:
                    turns.append(current_turn)
                turn_num += 1
                current_turn = {
                    "turn_number": turn_num,
                    "timestamp": e['timestamp'],
                    "prompt_preview": (data.get('text', '') or '')[:120],
                    "events": [evt],
                    "tools_used": [],
                    "has_alert": False,
                    "token_delta": {"input": 0, "output": 0},
                    "cumulative_tokens": {"input": cumulative_input, "output": cumulative_output},
                }
            elif current_turn:
                current_turn["events"].append(evt)
                if e['event_type'] == 'tool_use':
                    current_turn["tools_used"].append(data.get('name', ''))
                elif e['event_type'] == 'token_usage':
                    inp = data.get('input_tokens', 0) or 0
                    out = data.get('output_tokens', 0) or 0
                    current_turn["token_delta"] = {"input": inp, "output": out}
                    cumulative_input += inp
                    cumulative_output += out
                    current_turn["cumulative_tokens"] = {
                        "input": cumulative_input, "output": cumulative_output
                    }
                elif e['event_type'] == 'sensitive_data':
                    current_turn["has_alert"] = True

        if current_turn:
            turns.append(current_turn)

        self._send_json({
            "session": dict(session),
            "turns": turns,
            "total_turns": turn_num,
            "total_input": cumulative_input,
            "total_output": cumulative_output,
        })

    def _api_feed(self, params):
        since = params.get('since', [''])[0]
        limit = int(params.get('limit', ['50'])[0])

        with live_feed_lock:
            items = list(live_feed)

        if since:
            items = [i for i in items if i.get('timestamp', '') > since]

        items = items[-limit:]
        self._send_json({"events": items})

    def _api_stats(self, params):
        db = get_thread_db()

        total_sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_cost = db.execute("SELECT COALESCE(SUM(total_cost), 0) FROM sessions").fetchone()[0]
        total_input = db.execute("SELECT COALESCE(SUM(total_input_tokens), 0) FROM sessions").fetchone()[0]
        total_output = db.execute("SELECT COALESCE(SUM(total_output_tokens), 0) FROM sessions").fetchone()[0]
        total_alerts = db.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='sensitive_data'"
        ).fetchone()[0]

        # Active processes count
        active_procs = 0
        if psutil:
            try:
                for proc in psutil.process_iter(['name', 'cmdline']):
                    try:
                        name = proc.info.get('name') or ''
                        cmdline_str = ' '.join(proc.info.get('cmdline') or [])
                        if is_ai_process(name, cmdline_str):
                            active_procs += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass

        # Token usage over time (last 24h, grouped by hour)
        token_timeline = db.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                      SUM(json_extract(data_json, '$.input_tokens')) as input_t,
                      SUM(json_extract(data_json, '$.output_tokens')) as output_t,
                      SUM(json_extract(data_json, '$.cost')) as cost
               FROM events
               WHERE event_type='token_usage'
                 AND timestamp > datetime('now', '-24 hours')
               GROUP BY hour ORDER BY hour"""
        ).fetchall()

        # Tool usage breakdown
        tool_counts = db.execute(
            """SELECT json_extract(data_json, '$.name') as tool, COUNT(*) as cnt
               FROM events WHERE event_type='tool_use'
               GROUP BY tool ORDER BY cnt DESC LIMIT 20"""
        ).fetchall()

        # Model usage
        model_usage = db.execute(
            """SELECT model, COUNT(*) as sessions, SUM(total_cost) as cost
               FROM sessions WHERE model IS NOT NULL AND model != ''
               GROUP BY model ORDER BY cost DESC"""
        ).fetchall()

        # Browser AI stats
        browser_today = 0
        browser_total_duration = 0
        try:
            row = db.execute(
                """SELECT COUNT(*) as cnt, COALESCE(SUM(duration_seconds), 0) as dur
                   FROM browser_sessions
                   WHERE date(visit_time) = date('now')"""
            ).fetchone()
            browser_today = row[0] if row else 0
            browser_total_duration = row[1] if row else 0
        except Exception:
            pass

        # Browser AI daily breakdown for chart
        browser_daily = []
        try:
            rows = db.execute(
                """SELECT service, date(visit_time) as day, COUNT(*) as visits,
                          COALESCE(SUM(duration_seconds), 0) as dur
                   FROM browser_sessions
                   WHERE visit_time > datetime('now', '-7 days')
                   GROUP BY service, day ORDER BY day"""
            ).fetchall()
            browser_daily = [dict(r) for r in rows]
        except Exception:
            pass

        # Token forecast
        forecast = compute_forecast(db)

        self._send_json({
            "total_sessions": total_sessions,
            "total_events": total_events,
            "total_cost": round(total_cost, 4),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_alerts": total_alerts,
            "active_processes": active_procs,
            "token_timeline": [dict(r) for r in token_timeline],
            "tool_counts": [dict(r) for r in tool_counts],
            "model_usage": [dict(r) for r in model_usage],
            "plan_info": plan_info,
            "browser_today": browser_today,
            "browser_total_duration": round(browser_total_duration, 0),
            "browser_daily": browser_daily,
            "forecast": forecast,
        })

    def _api_processes(self, params):
        if not psutil:
            self._send_json({"processes": [], "error": "psutil not installed"})
            return

        found = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline',
                                              'cpu_percent', 'memory_percent',
                                              'create_time', 'status']):
                try:
                    info = proc.info
                    name = info.get('name') or ''
                    cmdline_str = ' '.join(info.get('cmdline') or [])
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ""
                    if is_ai_process(name, cmdline_str, exe_path):
                        # Classify source type
                        source_type = "CLI"
                        name_lower = name.lower()
                        if any(n in name_lower for n in ("cursor", "windsurf", "chatgpt")):
                            source_type = "Desktop App"
                        found.append({
                            "pid": info['pid'],
                            "name": name,
                            "cmdline": cmdline_str[:300],
                            "source_type": source_type,
                            "cpu_percent": info.get('cpu_percent', 0) or 0,
                            "memory_percent": round(info.get('memory_percent', 0) or 0, 2),
                            "status": info.get('status', ''),
                            "uptime": _format_uptime(info.get('create_time', 0)),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        self._send_json({"processes": found})

    def _api_files(self, params):
        db = get_thread_db()
        limit = int(params.get('limit', ['100'])[0])
        rows = db.execute(
            """SELECT timestamp, path, operation, session_id, size
               FROM file_events ORDER BY id DESC LIMIT ?""", (limit,)
        ).fetchall()
        self._send_json({"files": [dict(r) for r in rows]})

    def _api_connections(self, params):
        db = get_thread_db()
        rows = db.execute(
            """SELECT timestamp, pid, process_name, remote_host, remote_port, status, service
               FROM connections ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        self._send_json({"connections": [dict(r) for r in rows]})

    def _api_alerts(self, params):
        db = get_thread_db()
        limit = int(params.get('limit', ['200'])[0])
        offset = int(params.get('offset', ['0'])[0])
        severity_filter = params.get('severity', [''])[0]
        category_filter = params.get('category', [''])[0]
        rows = db.execute(
            """SELECT e.id, e.timestamp, e.session_id, e.data_json,
                      s.title, s.cwd
               FROM events e
               LEFT JOIN sessions s ON e.session_id = s.session_id
               WHERE e.event_type='sensitive_data'
               ORDER BY e.id DESC LIMIT 1000"""
        ).fetchall()
        alerts = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}
        skipped = 0
        for r in rows:
            try:
                data = json.loads(r['data_json'])
            except (json.JSONDecodeError, TypeError):
                data = {}
            sev = data.get('severity', 'medium')
            cats = data.get('categories', ['credential'])
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            for cat in cats:
                category_counts[cat] = category_counts.get(cat, 0) + 1

            # Apply filters
            if severity_filter and sev != severity_filter:
                continue
            if category_filter and category_filter not in cats:
                continue

            # Apply offset for pagination
            if skipped < offset:
                skipped += 1
                continue
            if len(alerts) >= limit:
                continue

            # Compute turn number for this alert
            turn_count = 0
            if r['session_id']:
                tc_row = db.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE session_id=? AND event_type='user_prompt' AND id <= ?""",
                    (r['session_id'], r['id'])
                ).fetchone()
                turn_count = tc_row[0] if tc_row else 0

            alerts.append({
                "id": r['id'],
                "timestamp": r['timestamp'],
                "session_id": r['session_id'],
                "session_title": r['title'] or (r['session_id'] or '')[:8],
                "cwd": r['cwd'],
                "patterns": data.get('patterns', []),
                "severity": sev,
                "categories": cats,
                "context": data.get('context', ''),
                "snippet": data.get('snippet', ''),
                "turn_number": turn_count,
            })
        self._send_json({
            "alerts": alerts,
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "total": sum(severity_counts.values()),
            "has_more": len(alerts) >= limit,
        })

    def _api_browser(self, params):
        db = get_thread_db()
        limit = int(params.get('limit', ['100'])[0])
        rows = db.execute(
            """SELECT id, service, url, title, conversation_id, visit_time,
                      duration_seconds, foreground_seconds
               FROM browser_sessions ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        self._send_json({"browser_sessions": [dict(r) for r in rows]})

    def _api_browser_sessions(self, params):
        """Browser visits grouped by conversation_id as logical sessions."""
        db = get_thread_db()
        limit = int(params.get('limit', ['100'])[0])
        service_filter = params.get('service', [''])[0]
        q = params.get('q', [''])[0].strip()

        conditions = ["conversation_id IS NOT NULL AND conversation_id != ''"]
        bind_vals = []
        if service_filter:
            conditions.append("service = ?")
            bind_vals.append(service_filter)
        if q:
            conditions.append("(title LIKE ? OR url LIKE ? OR conversation_id LIKE ?)")
            bind_vals.extend([f'%{q}%', f'%{q}%', f'%{q}%'])

        where = " AND ".join(conditions)
        bind_vals.append(limit)

        rows = db.execute(
            f"""SELECT conversation_id, service,
                       MIN(visit_time) as first_visit,
                       MAX(visit_time) as last_visit,
                       COUNT(*) as visit_count,
                       COALESCE(SUM(duration_seconds), 0) as total_duration,
                       (SELECT b2.title FROM browser_sessions b2
                        WHERE b2.conversation_id = browser_sessions.conversation_id
                          AND b2.title IS NOT NULL AND b2.title != ''
                          AND b2.title != b2.service
                        ORDER BY b2.visit_time DESC LIMIT 1) as title
                FROM browser_sessions
                WHERE {where}
                GROUP BY conversation_id
                ORDER BY last_visit DESC
                LIMIT ?""",
            bind_vals
        ).fetchall()

        sessions = [dict(r) for r in rows]

        orphan_rows = db.execute(
            """SELECT id, service, url, title, visit_time, duration_seconds
               FROM browser_sessions
               WHERE conversation_id IS NULL OR conversation_id = ''
               ORDER BY visit_time DESC LIMIT 50"""
        ).fetchall()

        self._send_json({
            "browser_sessions": sessions,
            "orphan_visits": [dict(r) for r in orphan_rows],
        })

    def _api_browser_session_detail(self, params):
        """All visits for a specific browser conversation with correlated connections."""
        conv_id = params.get('conversation_id', [''])[0]
        if not conv_id:
            self._send_json({"error": "missing conversation_id"}, 400)
            return

        db = get_thread_db()
        rows = db.execute(
            """SELECT id, service, url, title, conversation_id, visit_time,
                      duration_seconds, foreground_seconds
               FROM browser_sessions
               WHERE conversation_id = ?
               ORDER BY visit_time ASC""",
            (conv_id,)
        ).fetchall()

        if not rows:
            self._send_json({"error": "conversation not found"}, 404)
            return

        visits = [dict(r) for r in rows]
        service = visits[0]['service']
        first_visit = visits[0]['visit_time']
        last_visit = visits[-1]['visit_time']
        total_duration = sum(v.get('duration_seconds', 0) or 0 for v in visits)

        # Temporally correlated network connections
        service_hosts = {
            "ChatGPT": ["chatgpt.com", "openai.com"],
            "Gemini": ["googleapis.com", "google.com"],
            "Claude Web": ["anthropic.com", "claude.ai"],
            "Perplexity": ["perplexity.ai"],
            "Copilot": ["microsoft.com", "github.com"],
            "AI Studio": ["googleapis.com", "google.com"],
            "DeepSeek": ["deepseek.com"],
        }

        correlated_connections = []
        hosts = service_hosts.get(service, [])
        if hosts and first_visit and last_visit:
            host_conditions = " OR ".join(["remote_host LIKE ?"] * len(hosts))
            host_binds = [f'%{h}%' for h in hosts]
            conn_rows = db.execute(
                f"""SELECT timestamp, pid, process_name, remote_host, remote_port, service
                    FROM connections
                    WHERE ({host_conditions})
                      AND timestamp >= datetime(?, '-5 minutes')
                      AND timestamp <= datetime(?, '+5 minutes')
                    ORDER BY timestamp ASC LIMIT 100""",
                host_binds + [first_visit, last_visit]
            ).fetchall()
            correlated_connections = [dict(r) for r in conn_rows]

        self._send_json({
            "conversation_id": conv_id,
            "service": service,
            "title": next((v['title'] for v in reversed(visits)
                           if v.get('title') and v['title'] != service), service),
            "first_visit": first_visit,
            "last_visit": last_visit,
            "visit_count": len(visits),
            "total_duration": total_duration,
            "visits": visits,
            "correlated_connections": correlated_connections,
        })

    def _api_process_detail(self, params):
        """Process lifecycle and connection history for a specific PID."""
        pid = int(params.get('pid', ['0'])[0])
        if not pid:
            self._send_json({"error": "missing pid"}, 400)
            return

        db = get_thread_db()
        proc_rows = db.execute(
            """SELECT MAX(id) as id, pid, name, cmdline,
                      MIN(start_time) as start_time,
                      MAX(end_time) as end_time,
                      cpu_percent, memory_percent, status
               FROM processes WHERE pid = ?
               GROUP BY pid, name, start_time
               ORDER BY start_time DESC""",
            (pid,)
        ).fetchall()

        conn_rows = db.execute(
            """SELECT timestamp, remote_host, remote_port, status, service
               FROM connections WHERE pid = ?
               ORDER BY timestamp DESC LIMIT 200""",
            (pid,)
        ).fetchall()
        connections = [dict(r) for r in conn_rows]

        service_counts = {}
        for c in connections:
            svc = c.get('service', 'unknown')
            service_counts[svc] = service_counts.get(svc, 0) + 1

        self._send_json({
            "pid": pid,
            "processes": [dict(r) for r in proc_rows],
            "connections": connections,
            "service_breakdown": service_counts,
        })

    def _api_activity_timeline(self, params):
        """Unified timeline of all AI activity across sources."""
        db = get_thread_db()
        limit = int(params.get('limit', ['100'])[0])
        since = params.get('since', [''])[0]
        source_filter = params.get('source', [''])[0]

        timeline = []

        # CLI session events
        if not source_filter or source_filter == 'cli':
            cli_conds = ["event_type IN ('user_prompt', 'assistant_response', 'sensitive_data')"]
            cli_binds = []
            if since:
                cli_conds.append("e.timestamp > ?")
                cli_binds.append(since)
            cli_binds.append(limit)
            cli_rows = db.execute(
                f"""SELECT e.timestamp, e.event_type, e.session_id, e.data_json,
                           s.title, s.model
                    FROM events e
                    LEFT JOIN sessions s ON e.session_id = s.session_id
                    WHERE {' AND '.join(cli_conds)}
                    ORDER BY e.timestamp DESC LIMIT ?""",
                cli_binds
            ).fetchall()
            for r in cli_rows:
                try:
                    data = json.loads(r['data_json']) if r['data_json'] else {}
                except (json.JSONDecodeError, TypeError):
                    data = {}
                timeline.append({
                    "timestamp": r['timestamp'],
                    "source": "cli",
                    "event_type": r['event_type'],
                    "session_id": r['session_id'],
                    "title": r['title'] or (r['session_id'] or '')[:8],
                    "model": r['model'] or '',
                    "summary": (data.get('text', '') or '')[:120],
                })

        # Browser visits
        if not source_filter or source_filter == 'browser':
            browser_conds = ["1=1"]
            browser_binds = []
            if since:
                browser_conds.append("visit_time > ?")
                browser_binds.append(since)
            browser_binds.append(limit)
            browser_rows = db.execute(
                f"""SELECT visit_time, service, title, url, conversation_id, duration_seconds
                    FROM browser_sessions
                    WHERE {' AND '.join(browser_conds)}
                    ORDER BY visit_time DESC LIMIT ?""",
                browser_binds
            ).fetchall()
            for r in browser_rows:
                rd = dict(r)
                dur = int(rd.get('duration_seconds') or 0)
                timeline.append({
                    "timestamp": rd['visit_time'],
                    "source": "browser",
                    "event_type": "browser_visit",
                    "session_id": 'browser_' + (rd['conversation_id'] or ''),
                    "title": rd['title'] or rd['service'],
                    "model": rd['service'],
                    "summary": f"{rd['service']}: {(rd['title'] or '')[:80]}"
                               + (f" ({dur}s)" if dur else ''),
                })

        # Network connections
        if not source_filter or source_filter == 'network':
            net_conds = ["1=1"]
            net_binds = []
            if since:
                net_conds.append("timestamp > ?")
                net_binds.append(since)
            net_binds.append(limit)
            net_rows = db.execute(
                f"""SELECT timestamp, pid, process_name, remote_host, remote_port, service
                    FROM connections
                    WHERE {' AND '.join(net_conds)}
                    ORDER BY timestamp DESC LIMIT ?""",
                net_binds
            ).fetchall()
            for r in net_rows:
                rd = dict(r)
                timeline.append({
                    "timestamp": rd['timestamp'],
                    "source": "network",
                    "event_type": "connection",
                    "session_id": None,
                    "title": rd['process_name'],
                    "model": '',
                    "summary": f"{rd['process_name']} \u2192 {rd['remote_host']}:{rd['remote_port']} ({rd['service']})",
                })

        timeline.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        timeline = timeline[:limit]

        self._send_json({"timeline": timeline, "count": len(timeline)})

    def _send_ndjson(self, rows, filename):
        """Send rows as NDJSON (newline-delimited JSON) with download headers."""
        lines = []
        for row in rows:
            lines.append(json.dumps(row, default=str))
        body = ('\n'.join(lines) + '\n').encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_json_download(self, data, filename):
        """Send JSON data with download headers."""
        body = json.dumps(data, default=str, indent=2).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _api_export(self, params):
        """Export data for SIEM integration."""
        export_type = params.get('type', ['sessions'])[0]
        fmt = params.get('format', ['json'])[0]
        since = params.get('since', [''])[0]
        until = params.get('until', [''])[0]
        session_id = params.get('session_id', [''])[0]
        event_types = params.get('event_type', [''])[0]
        limit = int(params.get('limit', ['10000'])[0])

        db = get_thread_db()

        if export_type == 'sessions':
            rows = db.execute(
                """SELECT session_id, start_time, cwd, model, total_cost,
                          total_input_tokens, total_output_tokens, total_turns,
                          last_activity, title
                   FROM sessions ORDER BY last_activity DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            data = [dict(r) for r in rows]
            fname = f'ai_monitor_sessions_{now_iso()[:10]}'

        elif export_type == 'events':
            conditions = ["1=1"]
            bind_vals = []
            if since:
                conditions.append("timestamp >= ?")
                bind_vals.append(since)
            if until:
                conditions.append("timestamp <= ?")
                bind_vals.append(until)
            if session_id:
                conditions.append("session_id = ?")
                bind_vals.append(session_id)
            if event_types:
                types = event_types.split(',')
                placeholders = ','.join('?' * len(types))
                conditions.append(f"event_type IN ({placeholders})")
                bind_vals.extend(types)
            bind_vals.append(limit)

            rows = db.execute(
                f"""SELECT id, timestamp, session_id, event_type, source_layer, data_json
                   FROM events
                   WHERE {' AND '.join(conditions)}
                   ORDER BY id DESC LIMIT ?""",
                bind_vals
            ).fetchall()
            data = []
            for r in rows:
                row = dict(r)
                try:
                    row['data'] = json.loads(row.pop('data_json', '{}'))
                except (json.JSONDecodeError, TypeError):
                    row['data'] = {}
                data.append(row)
            fname = f'ai_monitor_events_{now_iso()[:10]}'

        elif export_type == 'alerts':
            rows = db.execute(
                """SELECT e.id, e.timestamp, e.session_id, e.data_json,
                          s.title, s.cwd, s.model
                   FROM events e
                   LEFT JOIN sessions s ON e.session_id = s.session_id
                   WHERE e.event_type='sensitive_data'
                   ORDER BY e.id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            data = []
            for r in rows:
                row = dict(r)
                try:
                    d = json.loads(row.pop('data_json', '{}'))
                    row.update(d)
                except (json.JSONDecodeError, TypeError):
                    pass
                data.append(row)
            fname = f'ai_monitor_alerts_{now_iso()[:10]}'

        elif export_type == 'connections':
            rows = db.execute(
                """SELECT timestamp, pid, process_name, remote_host,
                          remote_port, status, service
                   FROM connections ORDER BY id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            data = [dict(r) for r in rows]
            fname = f'ai_monitor_connections_{now_iso()[:10]}'

        else:
            self._send_json({"error": f"Unknown export type: {export_type}"}, 400)
            return

        if fmt == 'ndjson':
            self._send_ndjson(data, fname + '.ndjson')
        else:
            self._send_json_download({"export_type": export_type, "count": len(data),
                                       "exported_at": now_iso(), "data": data},
                                      fname + '.json')


def _format_uptime(create_time):
    """Format process uptime from create_time."""
    if not create_time:
        return "unknown"
    try:
        elapsed = time.time() - create_time
        if elapsed < 60:
            return f"{int(elapsed)}s"
        elif elapsed < 3600:
            return f"{int(elapsed/60)}m"
        else:
            return f"{int(elapsed/3600)}h {int((elapsed%3600)/60)}m"
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────
# SECTION 9: DASHBOARD HTML/JS/CSS
# ─────────────────────────────────────────────────────────────


def _load_dashboard_html():
    """Load dashboard HTML from package data."""
    try:
        import importlib.resources
        return importlib.resources.files("claude_monitoring").joinpath("dashboard.html").read_text()
    except Exception:
        return "<html><body><h1>Dashboard HTML not found</h1></body></html>"

DASHBOARD_HTML = _load_dashboard_html()


# ─────────────────────────────────────────────────────────────
# SECTION 10: INITIAL JSONL BACKFILL
# ─────────────────────────────────────────────────────────────

def backfill_existing_sessions(watcher):
    """Scan existing JSONL files and backfill the database."""
    if not CLAUDE_PROJECTS_DIR.exists():
        return 0

    count = 0
    for jsonl_file in CLAUDE_PROJECTS_DIR.rglob("*.jsonl"):
        try:
            watcher.process_jsonl_file(str(jsonl_file))
            count += 1
        except Exception:
            continue
    return count


# ─────────────────────────────────────────────────────────────
# SECTION 11: MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def start_monitoring():
    """Start all monitoring layers and the web dashboard."""
    print("=" * 62)
    print("  AI Runtime Monitor — CrowdStrike-Style Full Visibility")
    print("=" * 62)

    # Check dependencies
    missing = []
    if not psutil:
        missing.append("psutil")
    if Observer is None:
        missing.append("watchdog")
    if missing:
        print(f"\n  WARNING: Missing optional dependencies: {', '.join(missing)}")
        print(f"  Install with: pip3 install {' '.join(missing)}")
        if Observer is None:
            print("  watchdog is REQUIRED for JSONL monitoring. Exiting.")
            sys.exit(1)

    # Init database
    db_conn = init_db()
    db_conn.close()
    print(f"\n  Database: {DB_PATH}")

    # Detect plan/subscription
    info = detect_plan_info()
    if info["is_subscription"]:
        print(f"  Plan: {info.get('cost_label', 'Subscription')} (cost shown as usage)")
    else:
        print(f"  Billing: API (cost shown in USD)")

    # Layer 1a: JSONL Session Watcher
    jsonl_watcher = JSONLSessionWatcher()
    jsonl_handler = JSONLFileHandler(jsonl_watcher)
    jsonl_observer = Observer()

    if CLAUDE_PROJECTS_DIR.exists():
        jsonl_observer.schedule(jsonl_handler, str(CLAUDE_PROJECTS_DIR), recursive=True)
        print(f"  Watching JSONL: {CLAUDE_PROJECTS_DIR}")
    else:
        print(f"  WARNING: {CLAUDE_PROJECTS_DIR} not found — will retry on first activity")

    # Backfill existing sessions in background
    def _backfill():
        n = backfill_existing_sessions(jsonl_watcher)
        print(f"  Backfill complete: {n} files processed")
    backfill_thread = threading.Thread(target=_backfill, daemon=True, name="Backfill")
    backfill_thread.start()
    print("  Backfilling existing sessions in background...")

    # Layer 2: File Activity Monitor
    file_handler = FileActivityHandler()
    file_observer = Observer()
    # We'll watch the current working directory as a start
    # Additional CWDs from active sessions will be added dynamically
    cwd = os.getcwd()
    file_observer.schedule(file_handler, cwd, recursive=True)
    print(f"  Watching files: {cwd}")

    # Layer 3: Process Scanner
    proc_scanner = ProcessScanner()
    proc_thread = threading.Thread(target=proc_scanner.run_loop, daemon=True, name="ProcessScanner")

    # Layer 1b: Network Monitor
    net_monitor = NetworkMonitor()
    net_thread = threading.Thread(target=net_monitor.run_loop, daemon=True, name="NetworkMonitor")

    # Layer 4: Chrome Browser History Watcher
    chrome_watcher = ChromeHistoryWatcher()
    chrome_thread = threading.Thread(target=chrome_watcher.run_loop, daemon=True, name="ChromeWatcher")

    # Start all observers and threads
    jsonl_observer.start()
    file_observer.start()
    proc_thread.start()
    net_thread.start()
    chrome_thread.start()
    print(f"  Process scanner: active (every 2s)")
    print(f"  Network monitor: active (every 5s)")
    chrome_profiles = chrome_watcher._find_history_files()
    if chrome_profiles:
        print(f"  Chrome AI watcher: active (every 60s, {len(chrome_profiles)} profile(s))")
    else:
        print(f"  Chrome AI watcher: Chrome history not found")

    # Web Dashboard
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True
    server = ReusableHTTPServer(('0.0.0.0', DASHBOARD_PORT), DashboardHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="Dashboard")
    server_thread.start()
    print(f"\n  Dashboard: http://localhost:{DASHBOARD_PORT}")
    print(f"\n  Press Ctrl+C to stop")
    print("=" * 62)

    # Initial process scan
    procs = proc_scanner.scan_once()
    if procs:
        print(f"\n  Found {len(procs)} AI process(es) running:")
        for p in procs:
            print(f"    PID {p['pid']}: {p['name']} ({p['cpu_percent']}% CPU, {p['memory_percent']}% MEM)")
    print()

    # Keep main thread alive
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        print("\n\n  Shutting down...")
        jsonl_watcher.stop()
        proc_scanner.stop()
        net_monitor.stop()
        chrome_watcher.stop()
        jsonl_observer.stop()
        file_observer.stop()
        server.shutdown()
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

    jsonl_observer.join(timeout=2)
    file_observer.join(timeout=2)
    print("  Stopped.\n")


def one_shot_scan():
    """Perform a one-time process and network scan."""
    print("\nAI Agent Process Scan")
    print("=" * 50)

    if not psutil:
        print("ERROR: psutil not installed. Run: pip3 install psutil")
        sys.exit(1)

    scanner = ProcessScanner()
    procs = scanner.scan_once()

    if not procs:
        print("  No AI agent processes found.")
    else:
        print(f"  Found {len(procs)} AI process(es):\n")
        for p in procs:
            print(f"  PID {p['pid']:>6}  {p['name']:<20} "
                  f"CPU:{p['cpu_percent']:>5.1f}%  MEM:{p['memory_percent']:>5.1f}%  "
                  f"Status:{p['status']}")
            if p.get('cmdline'):
                print(f"           cmd: {p['cmdline'][:80]}")
    print()


def install_launch_agent():
    """Install as a macOS LaunchAgent for auto-start on login."""
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / "com.ai-monitor.agent.plist"

    python_path = sys.executable
    script_path = str(SCRIPT_PATH)
    log_path = str(OUTPUT_DIR / "ai_monitor.log")

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ai-monitor.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{script_path}</string>
        <string>--start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
    <key>WorkingDirectory</key>
    <string>{str(Path.home())}</string>
</dict>
</plist>"""

    plist_path.write_text(plist_content)
    print(f"  Wrote: {plist_path}")

    result = subprocess.run(["launchctl", "load", str(plist_path)],
                            capture_output=True, text=True)
    if result.returncode == 0:
        print("  LaunchAgent loaded successfully!")
        print(f"  Log: {log_path}")
        print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    else:
        print(f"  launchctl load failed: {result.stderr}")
        print(f"  Try manually: launchctl load {plist_path}")


def uninstall_launch_agent():
    """Remove the macOS LaunchAgent."""
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ai-monitor.agent.plist"
    if not plist_path.exists():
        print("  LaunchAgent not found. Nothing to uninstall.")
        return

    subprocess.run(["launchctl", "unload", str(plist_path)],
                    capture_output=True, text=True)
    plist_path.unlink()
    print("  LaunchAgent unloaded and removed.")


# ─────────────────────────────────────────────────────────────
# SECTION 12: CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────

def _update_port(port):
    global DASHBOARD_PORT
    DASHBOARD_PORT = port


def main():
    parser = argparse.ArgumentParser(
        description="AI Runtime Monitor — Full visibility into AI agent activity"
    )
    parser.add_argument("--start", action="store_true",
                        help="Start monitoring and dashboard")
    parser.add_argument("--scan", action="store_true",
                        help="One-shot process scan")
    parser.add_argument("--install-agent", action="store_true",
                        help="Install as macOS LaunchAgent (auto-start on login)")
    parser.add_argument("--uninstall-agent", action="store_true",
                        help="Remove macOS LaunchAgent")
    parser.add_argument("--port", type=int, default=DASHBOARD_PORT,
                        help=f"Dashboard port (default: {DASHBOARD_PORT})")

    args = parser.parse_args()

    if args.port != DASHBOARD_PORT:
        # Update the module-level port if overridden
        _update_port(args.port)

    if args.install_agent:
        install_launch_agent()
    elif args.uninstall_agent:
        uninstall_launch_agent()
    elif args.scan:
        one_shot_scan()
    elif args.start:
        start_monitoring()
    else:
        parser.print_help()
        print("\n  Quick start: python3 ai_monitor.py --start")


if __name__ == "__main__":
    main()
