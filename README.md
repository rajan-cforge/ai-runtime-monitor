# AI Runtime Monitor

[![CI](https://github.com/rajan-cforge/ai-runtime-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/rajan-cforge/ai-runtime-monitor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ai-runtime-monitor)](https://pypi.org/project/ai-runtime-monitor/)
[![Python](https://img.shields.io/pypi/pyversions/ai-runtime-monitor)](https://pypi.org/project/ai-runtime-monitor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Runtime monitor for AI coding agents. Full visibility into what Claude Code, ChatGPT, Copilot, Cursor, and other AI tools are doing on your machine — network calls, file changes, process activity, token spend, and sensitive data exposure.

## Install

```bash
pip3 install ai-runtime-monitor
python3 -m claude_monitoring.monitor --start
# Open http://localhost:9081
```

**From source:**

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor.git
cd ai-runtime-monitor
make install   # auto-detects pip3/pip
make start     # launches dashboard on http://localhost:9081
```

> **Troubleshooting:** If `pip` / `pip3` is not found, install Python 3.9+ from [python.org](https://www.python.org/downloads/) or run `python3 -m ensurepip --upgrade`.

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

## Advanced: Deep API Capture

For full API-level traffic interception (every prompt, response, token count, and tool call):

```bash
pip install "ai-runtime-monitor[watch]"

# First-time setup
claude-watch --setup            # Install mitmproxy, generate & trust cert
claude-watch --verify           # Verify everything is ready

# Option A: Start both together
ai-monitor --start --with-proxy

# Option B: Start separately
ai-monitor --start              # Dashboard on :9081
claude-watch --start            # Proxy on :9080

# Route your AI agent through the proxy
export HTTPS_PROXY=http://127.0.0.1:9080
claude                          # API calls now appear in the API Traffic tab
```

**Per-agent proxy configuration:**

```bash
claude-watch --configure claude_code   # Adds HTTPS_PROXY to your shell profile
claude-watch --configure list          # Show supported agents and status
claude-watch --unconfigure             # Remove proxy config from shell
```

## Configuration

Generate a config file:
```bash
ai-monitor --init-config    # Creates ~/.config/ai-runtime-monitor/config.toml
```

**ai-monitor flags:**

| Option | Default | Description |
|--------|---------|-------------|
| `--start` | — | Start monitoring + dashboard |
| `--port` | 9081 | Dashboard HTTP port |
| `--with-proxy` | — | Also start HTTPS proxy for deep capture |
| `--scan` | — | One-shot process/network scan |
| `--install-agent` | — | Install as macOS LaunchAgent (auto-start on login) |
| `--init-config` | — | Generate default config.toml |

**claude-watch flags:**

| Option | Default | Description |
|--------|---------|-------------|
| `--setup` | — | First-time: install mitmproxy, trust cert |
| `--start` | — | Start proxy interceptor |
| `--verify` | — | Health-check proxy setup |
| `--configure <agent>` | — | Configure HTTPS_PROXY for an agent |
| `--unconfigure` | — | Remove proxy config from shell profiles |
| `--analyze` | — | Terminal analysis of latest session |
| `--plot` | — | Generate PNG dashboard charts |
| `--dashboard` | — | Launch standalone web dashboard |

Output directory: `~/claude_watch_output/`

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full API reference, database schema, and security model.

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
