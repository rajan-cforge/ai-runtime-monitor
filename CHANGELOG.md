# Changelog

## [0.1.0] - 2026-03-04

### Added
- Three-layer monitoring: network (JSONL transcript tailing), filesystem (watchdog), process (psutil)
- SQLite event store with WAL mode for concurrent reads
- Web dashboard on port 9081 with Session Explorer, Live Feed, Analytics, System, and Alerts tabs
- Sensitive data detection (DLP): AWS keys, GitHub tokens, private keys, JWTs, credit cards, SSNs, and more
- Cost estimation and burn rate forecasting with subscription plan detection
- Browser AI activity tracking via Chrome history
- Network connection monitoring with hostname resolution
- File activity monitoring for AI agent working directories
- Export to JSON and NDJSON (SIEM-compatible)
- `claude-watch` proxy-based traffic interceptor for deep API-level monitoring
- CLI entry points: `ai-monitor` and `claude-watch`
- macOS LaunchAgent install/uninstall support
