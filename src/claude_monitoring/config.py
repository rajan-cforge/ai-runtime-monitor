"""Configuration management for AI Runtime Monitor.

Loads settings from TOML config file with sensible defaults.
Priority: CLI args > config file > defaults.

Config file search paths:
  1. ~/.config/ai-runtime-monitor/config.toml
  2. ~/claude_watch_output/config.toml
"""

import sys
from pathlib import Path

# Use tomllib (3.11+) or tomli fallback
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# ─────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────

DEFAULTS = {
    "server": {
        "dashboard_port": 9081,
        "proxy_port": 9080,
        "bind_address": "127.0.0.1",
    },
    "paths": {
        "output_dir": str(Path.home() / "claude_watch_output"),
        "db_name": "monitor.db",
        "session_dir": "sessions",
        "cert_dir": "certs",
    },
    "proxy": {
        "enabled": False,
        "auto_configure": False,
        "cert_path": str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"),
    },
}

CONFIG_SEARCH_PATHS = [
    Path.home() / ".config" / "ai-runtime-monitor" / "config.toml",
    Path.home() / "claude_watch_output" / "config.toml",
]

# Module-level config cache
_config = None
_cli_overrides = {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | None = None) -> dict:
    """Load config from TOML file, with defaults for missing keys.

    Args:
        path: Explicit config file path. If None, searches CONFIG_SEARCH_PATHS.

    Returns:
        Merged config dict (defaults + file + CLI overrides).
    """
    global _config

    config = DEFAULTS.copy()
    config = {k: v.copy() if isinstance(v, dict) else v for k, v in config.items()}

    # Find and load TOML config
    search_paths = [Path(path)] if path else CONFIG_SEARCH_PATHS
    for p in search_paths:
        if p.exists():
            if tomllib is None:
                break
            with open(p, "rb") as f:
                file_config = tomllib.load(f)
            config = _deep_merge(config, file_config)
            break

    # Apply CLI overrides
    if _cli_overrides:
        config = _deep_merge(config, _cli_overrides)

    _config = config
    return config


def set_cli_overrides(**kwargs):
    """Set CLI overrides that take priority over config file.

    Example:
        set_cli_overrides(dashboard_port=9082, bind_address="0.0.0.0")
    """
    global _cli_overrides
    mapping = {
        "dashboard_port": ("server", "dashboard_port"),
        "proxy_port": ("server", "proxy_port"),
        "bind_address": ("server", "bind_address"),
        "output_dir": ("paths", "output_dir"),
    }
    for key, value in kwargs.items():
        if value is not None and key in mapping:
            section, field = mapping[key]
            _cli_overrides.setdefault(section, {})[field] = value

    # Invalidate cache
    global _config
    _config = None


def _get_config() -> dict:
    """Get cached config, loading if needed."""
    global _config
    if _config is None:
        load_config()
    return _config


# ─────────────────────────────────────────────────────────────
# Accessor functions
# ─────────────────────────────────────────────────────────────


def get_output_dir() -> Path:
    """Get the output directory path."""
    cfg = _get_config()
    return Path(cfg["paths"]["output_dir"]).expanduser()


def get_db_path() -> Path:
    """Get the database file path."""
    cfg = _get_config()
    return get_output_dir() / cfg["paths"]["db_name"]


def get_session_dir() -> Path:
    """Get the session CSV directory path."""
    cfg = _get_config()
    return get_output_dir() / cfg["paths"]["session_dir"]


def get_cert_dir() -> Path:
    """Get the certificate directory path."""
    cfg = _get_config()
    return get_output_dir() / cfg["paths"]["cert_dir"]


def get_dashboard_port() -> int:
    """Get the dashboard HTTP port."""
    cfg = _get_config()
    return int(cfg["server"]["dashboard_port"])


def get_proxy_port() -> int:
    """Get the mitmproxy HTTPS proxy port."""
    cfg = _get_config()
    return int(cfg["server"]["proxy_port"])


def get_bind_address() -> str:
    """Get the server bind address."""
    cfg = _get_config()
    return cfg["server"]["bind_address"]


def get_cert_path() -> Path:
    """Get the mitmproxy CA cert path."""
    cfg = _get_config()
    return Path(cfg["proxy"]["cert_path"]).expanduser()


def is_proxy_enabled() -> bool:
    """Check if proxy is enabled in config."""
    cfg = _get_config()
    return bool(cfg["proxy"]["enabled"])


# ─────────────────────────────────────────────────────────────
# Config file generation
# ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG_TOML = """\
# AI Runtime Monitor Configuration
# Docs: https://github.com/rajan-cforge/ai-runtime-monitor

[server]
dashboard_port = 9081          # Dashboard HTTP port
proxy_port = 9080              # mitmproxy HTTPS proxy port
bind_address = "127.0.0.1"    # Localhost only (security default)

[paths]
output_dir = "~/claude_watch_output"
db_name = "monitor.db"
session_dir = "sessions"
cert_dir = "certs"

[proxy]
enabled = false                # Start proxy with dashboard (--with-proxy overrides)
auto_configure = false         # Auto-set HTTPS_PROXY for supported agents
cert_path = "~/.mitmproxy/mitmproxy-ca-cert.pem"

# Per-agent proxy configuration
# Uncomment and set enabled = true for agents you want to route through the proxy
# [proxy.agents.claude_code]
# enabled = true
# env_method = "shell_rc"     # shell_rc | app_config | env_file
#
# [proxy.agents.cursor]
# enabled = false
# env_method = "app_config"
"""


def generate_default_config(path: Path | None = None) -> Path:
    """Write default config.toml with comments.

    Args:
        path: Where to write. Defaults to ~/.config/ai-runtime-monitor/config.toml

    Returns:
        Path to the written config file.
    """
    if path is None:
        path = CONFIG_SEARCH_PATHS[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_CONFIG_TOML)
    return path


def reset():
    """Reset config cache (useful for testing)."""
    global _config, _cli_overrides
    _config = None
    _cli_overrides = {}
