# AI Runtime Monitor

[![CI](https://github.com/rajan-cforge/ai-runtime-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/rajan-cforge/ai-runtime-monitor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ai-runtime-monitor)](https://pypi.org/project/ai-runtime-monitor/)
[![Python](https://img.shields.io/pypi/pyversions/ai-runtime-monitor)](https://pypi.org/project/ai-runtime-monitor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CrowdStrike-style runtime monitor for AI coding agents. Full visibility into what Claude Code, ChatGPT, Copilot, Cursor, and other AI tools are doing on your machine — network calls, file changes, process activity, token spend, and sensitive data exposure.

## Install

```bash
pip install ai-runtime-monitor
ai-monitor --start
# Open http://localhost:9081
```

**From source:**

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor.git
cd ai-runtime-monitor
make install   # pip install -e .
make start     # ai-monitor --start
```

That's it. Dashboard opens at `http://localhost:9081`.

## What It Does

**Three-layer monitoring — zero configuration required:**

| Layer | What it captures | How |
|-------|-----------------|-----|
| **Network** | AI API calls, connection endpoints, service classification | JSONL transcript tailing + `psutil` connection scanning |
| **Filesystem** | File reads/writes by AI agents | `watchdog` / FSEvents |
| **Process** | AI process lifecycle, CPU, memory | `psutil` process scanning |

**Security / DLP:**
- Detects AWS keys, GitHub tokens, private keys, JWTs, credit cards, SSNs, and 15+ other sensitive patterns in AI session data
- Severity-ranked alerts (Critical / High / Medium / Low) with drill-down to the exact turn where exposure occurred

**Cost tracking:**
- Token counting and cost estimation for Claude, GPT-4, and other models
- Burn rate forecasting with subscription plan detection

**Browser AI:**
- Tracks ChatGPT, Gemini, Claude Web, Copilot, Perplexity, and DeepSeek browser usage via Chrome history
- Unified Session Explorer shows CLI and browser AI activity side by side

**Dashboard tabs:**
- **Session Explorer** — Full conversation timeline replay with Deep Dive cockpit (turn rail, API inspector, context gauge)
- **Live Feed** — Real-time stream of all agent events
- **Analytics** — Token usage charts, cost trends, tool frequency, model distribution, burn rate
- **System** — Process table, network connections, file activity
- **Alerts** — Sensitive data alerts with pattern filtering and session-level triage
- **Activity Timeline** — Unified chronological feed across all AI sources

## Advanced: Network Interception

For deep API-level traffic capture (every prompt, response, and tool call sent to AI APIs):

```bash
pip install "ai-runtime-monitor[watch]"
claude-watch --setup    # First-time: install deps & trust cert
claude-watch --start    # Start mitmproxy-based interceptor
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 9081 | Dashboard HTTP port |
| `--start` | — | Start monitoring + dashboard |
| `--scan` | — | One-shot process/network scan |
| `--install-agent` | — | Install as macOS LaunchAgent (auto-start on login) |

Output directory: `~/claude_watch_output/`

## Development

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor.git
cd ai-runtime-monitor
make dev       # Install with dev deps
make test      # Run tests
make lint      # Lint check
make format    # Auto-format
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Contributing

Contributions welcome! Please read the [contributing guide](CONTRIBUTING.md) and our [code of conduct](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
