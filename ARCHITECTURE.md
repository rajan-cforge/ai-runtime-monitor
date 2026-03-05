# Architecture

## System Overview

```
┌──────────────────┐   JSONL transcripts    ┌─────────────────┐    SQLite     ┌────────────────┐
│  Claude Code     │ ─────────────────────→ │   monitor.py    │ ───────────→ │   Dashboard    │
│  Cursor, Aider   │   ~/.claude/projects/  │   (scanners)    │  monitor.db  │   :9081        │
│  (AI agents)     │                        └─────────────────┘              │   7 tabs       │
└────────┬─────────┘                               │                        └────────────────┘
         │                                         │ psutil                         ↑
         │                                         ▼                               │
         │                                  ┌─────────────┐                        │
         │                                  │ Processes    │─── processes table ────┤
         │                                  │ Connections  │─── connections table ──┤
         │                                  │ File events  │─── file_events table ──┤
         │                                  │ Chrome hist  │─── browser_sessions ───┘
         │                                  └─────────────┘
         │
         │  HTTPS_PROXY                    ┌─────────────────┐   dual-write
         └───────────────────────────────→ │   watch.py      │ ──────┐
            (optional deep capture)        │   (mitmproxy    │       │
                                           │    addon)       │       ▼
                                           └────────┬────────┘  ┌──────────┐
                                                    │           │monitor.db│──→ api_calls table
                                                    ▼           └──────────┘
                                              CSV session
                                              files (primary)
```

## Module Structure

```
src/claude_monitoring/
├── __init__.py           Package init
├── config.py             TOML config loading, defaults, accessors
├── constants.py          AI_HOSTS, SENSITIVE_PATTERNS, MODEL_PRICING, CSV_COLUMNS, etc.
├── utils.py              estimate_cost, scan_sensitive, extract_file_paths, now_iso
├── db.py                 init_db (7 tables + indexes), insert_api_call, get_thread_db
├── monitor.py            Main entry point: scanners, dashboard HTTP server, API endpoints
├── watch.py              mitmproxy addon, CLI analysis tools, proxy setup/verify/configure
├── dashboard.html        Self-contained HTML/CSS/JS dashboard (embedded in monitor.py)
└── watch_dashboard.html  Standalone watch session dashboard
```

## Data Sources

### Layer 1: JSONL Transcript Tailing (passive, no proxy needed)

`JSONLSessionWatcher` tails `~/.claude/projects/*/` for `.jsonl` files written by Claude Code. Each line is a structured event (user message, assistant response, tool call, result). Extracted data:

- Session metadata (model, cwd, start time, title)
- Turn-by-turn token usage and cost
- Tool calls (Bash, Read, Write, Edit, Glob, Grep, etc.)
- Sensitive pattern detection in message content
- File paths read/written

Stored in: `sessions`, `events` tables.

### Layer 2: System Monitoring (psutil + watchdog)

- **ProcessScanner**: Polls `psutil.process_iter()` every 30s for known AI process names (claude, cursor, copilot, aider, etc.)
- **NetworkMonitor**: Polls `psutil.net_connections()` for connections to known AI API hosts
- **FileSystemWatcher**: Uses `watchdog` FSEvents to detect file modifications
- **ChromeHistoryWatcher**: Reads Chrome's `History` SQLite DB for visits to AI service URLs

Stored in: `processes`, `connections`, `file_events`, `browser_sessions` tables.

### Layer 3: HTTPS Proxy Interception (optional, requires setup)

`ClaudeWatchAddon` is a mitmproxy addon that intercepts HTTPS traffic when agents are configured with `HTTPS_PROXY`. Captures full request/response payloads:

- Exact input/output/cache token counts from API response headers
- System prompt character count
- Message previews (user + assistant)
- Tool call names and arguments
- Sensitive pattern detection in payloads
- Latency, HTTP status, stop reason, request ID

Stored in: CSV files (primary) + `api_calls` table (dual-write, best-effort).

## Database Schema

All tables live in `~/claude_watch_output/monitor.db` (SQLite, WAL mode).

### sessions
| Column | Type | Description |
|--------|------|-------------|
| session_id | TEXT PK | Claude session UUID |
| start_time | TEXT | ISO 8601 timestamp |
| cwd | TEXT | Working directory |
| model | TEXT | Model name (claude-sonnet-4, etc.) |
| total_cost | REAL | Cumulative estimated cost USD |
| total_input_tokens | INTEGER | Cumulative input tokens |
| total_output_tokens | INTEGER | Cumulative output tokens |
| total_turns | INTEGER | Number of conversation turns |
| jsonl_path | TEXT | Path to source JSONL file |
| last_activity | TEXT | Most recent event timestamp |
| title | TEXT | Session title / first user message |

### events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| session_id | TEXT | FK to sessions |
| event_type | TEXT | user_prompt, assistant_response, tool_use, token_usage, sensitive_data, etc. |
| source_layer | TEXT | jsonl, network, process, filesystem |
| data_json | TEXT | JSON payload with event-specific fields |

### api_calls
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| session_id | TEXT | Claude session ID |
| turn_id | TEXT | Turn identifier |
| turn_number | INTEGER | Sequential turn number |
| destination_host | TEXT | API hostname |
| destination_service | TEXT | Service classifier (anthropic_api, openai_api, etc.) |
| endpoint_path | TEXT | /v1/messages, /v1/chat/completions, etc. |
| http_method | TEXT | POST, GET |
| http_status | INTEGER | 200, 429, 500, etc. |
| model | TEXT | Model name |
| stream | TEXT | true/false |
| input_tokens | INTEGER | Input token count |
| output_tokens | INTEGER | Output token count |
| cache_read_tokens | INTEGER | Cache read token count |
| cache_write_tokens | INTEGER | Cache write token count |
| estimated_cost_usd | REAL | Estimated cost |
| request_size_bytes | INTEGER | HTTP request body size |
| response_size_bytes | INTEGER | HTTP response body size |
| latency_ms | INTEGER | Request latency |
| num_messages | INTEGER | Messages in conversation |
| system_prompt_chars | INTEGER | System prompt length |
| last_user_msg_preview | TEXT | Truncated last user message |
| assistant_msg_preview | TEXT | Truncated assistant response |
| tool_calls | TEXT | JSON list of tool call names |
| tool_call_count | INTEGER | Number of tool calls |
| bash_commands | TEXT | Bash commands extracted |
| files_read | TEXT | Files read in this turn |
| files_written | TEXT | Files written in this turn |
| urls_fetched | TEXT | URLs fetched |
| sensitive_patterns | TEXT | Detected sensitive patterns |
| sensitive_pattern_count | INTEGER | Count of sensitive patterns |
| stop_reason | TEXT | end_turn, tool_use, max_tokens |
| request_id | TEXT | API request ID header |

### processes
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| pid | INTEGER | OS process ID |
| name | TEXT | Process name |
| cmdline | TEXT | Full command line |
| start_time | TEXT | Process start time |
| end_time | TEXT | Process end time (if terminated) |
| cpu_percent | REAL | CPU usage percentage |
| memory_percent | REAL | Memory usage percentage |
| status | TEXT | running / terminated |

### connections
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | When connection was observed |
| pid | INTEGER | Process ID |
| process_name | TEXT | Process name |
| remote_host | TEXT | Remote IP/hostname |
| remote_port | INTEGER | Remote port |
| status | TEXT | ESTABLISHED, etc. |
| service | TEXT | Classified service name |

### file_events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| path | TEXT | File path |
| operation | TEXT | created, modified, deleted |
| session_id | TEXT | Associated session |
| size | INTEGER | File size in bytes |

### browser_sessions
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| service | TEXT | ChatGPT, Gemini, Claude Web, etc. |
| url | TEXT | Full URL |
| title | TEXT | Page title |
| conversation_id | TEXT | Extracted conversation/chat ID |
| visit_time | TEXT | ISO 8601 |
| duration_seconds | REAL | Time on page |
| foreground_seconds | REAL | Active tab time |
| tab_id | INTEGER | Chrome tab ID |
| window_id | INTEGER | Chrome window ID |

### Indexes

- `idx_events_ts` — events(timestamp)
- `idx_events_session` — events(session_id)
- `idx_events_type` — events(event_type)
- `idx_sessions_last` — sessions(last_activity)
- `idx_file_events_ts` — file_events(timestamp)
- `idx_processes_pid` — processes(pid)
- `idx_browser_conv` — browser_sessions(conversation_id)
- `idx_browser_visit` — browser_sessions(visit_time)
- `idx_connections_pid` — connections(pid)
- `idx_connections_ts` — connections(timestamp)
- `idx_api_calls_ts` — api_calls(timestamp)
- `idx_api_calls_session` — api_calls(session_id)
- `idx_api_calls_service` — api_calls(destination_service)

## API Reference

All endpoints are served by the built-in HTTP server on the dashboard port (default 9081). Responses are JSON unless noted.

### Sessions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sessions` | List sessions. Params: `search`, `sort` (recent/cost/tokens), `limit`, `offset` |
| GET | `/api/session/<id>` | Session detail with metadata + event summary |
| GET | `/api/session/<id>/turns` | Turn-by-turn breakdown for Deep Dive |
| GET | `/api/session/<id>/traffic` | API calls for a specific session |

### Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregate stats (process count, connections, files, cost) |
| GET | `/api/feed` | Live event feed. Params: `limit`, `offset` |
| GET | `/api/processes` | Running/recent AI processes |
| GET | `/api/process/<pid>` | Process detail |
| GET | `/api/connections` | Network connections |
| GET | `/api/files` | File events. Params: `limit`, `offset` |

### API Traffic (from proxy)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/traffic` | Paginated API call list. Params: `service`, `limit`, `offset` |
| GET | `/api/traffic/stats` | Aggregated traffic stats (total calls, cost, tokens by service/model) |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | Sensitive data alerts. Params: `severity`, `category`, `session_id`, `limit`, `offset` |

### Browser
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/browser` | Browser AI activity summary |
| GET | `/api/browser/sessions` | List browser AI sessions |
| GET | `/api/browser/session/<conversation_id>` | Browser session detail |

### Timeline & Export
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/activity/timeline` | Unified chronological feed across all sources |
| GET | `/api/export` | Export data. Params: `type` (events/alerts/connections/sessions), `format` (json/ndjson/csv), `session_id` |

## Configuration

Config file: `~/.config/ai-runtime-monitor/config.toml` (XDG), fallback `~/claude_watch_output/config.toml`.

Generate a default config:
```bash
ai-monitor --init-config
```

Priority: CLI flags > config file > built-in defaults.

See [config.py](src/claude_monitoring/config.py) for the full default config template.

### Key settings

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| server | dashboard_port | 9081 | Dashboard HTTP port |
| server | proxy_port | 9080 | mitmproxy HTTPS proxy port |
| server | bind_address | 127.0.0.1 | Bind address (localhost only by default) |
| paths | output_dir | ~/claude_watch_output | Data directory |
| paths | db_name | monitor.db | SQLite database filename |
| proxy | enabled | false | Start proxy with dashboard |
| proxy | cert_path | ~/.mitmproxy/mitmproxy-ca-cert.pem | CA cert location |

## Security Model

- Dashboard and proxy bind to `127.0.0.1` by default (localhost only)
- Remote access requires explicit `--bind 0.0.0.0` opt-in
- mitmproxy CA cert is scoped to the proxy — not a wildcard system trust
- No secrets stored in config file
- Config file permissions are checked (warns if world-readable)
- `proxy_env.sh` is generated with `chmod 600`
- All SQL queries use parameterized statements (no string interpolation with user input)

## CLI Commands

### ai-monitor (main dashboard)
```
ai-monitor --start              # Start monitoring + dashboard
ai-monitor --start --with-proxy # Start with HTTPS proxy
ai-monitor --port 9082          # Custom port
ai-monitor --scan               # One-shot process/network scan
ai-monitor --install-agent      # macOS LaunchAgent (auto-start)
ai-monitor --uninstall-agent    # Remove LaunchAgent
ai-monitor --init-config        # Generate config.toml
```

### claude-watch (proxy + analysis)
```
claude-watch --setup             # First-time: install mitmproxy, trust cert
claude-watch --start             # Start mitmproxy interceptor
claude-watch --verify            # Health check proxy setup
claude-watch --configure <agent> # Configure HTTPS_PROXY for an agent
claude-watch --unconfigure       # Remove proxy config from shell
claude-watch --analyze           # Terminal analysis of latest session
claude-watch --plot              # Generate PNG charts
claude-watch --dashboard         # Standalone web dashboard
claude-watch --scan              # Detect running AI agents
claude-watch --generate-test     # Create synthetic test data
```
