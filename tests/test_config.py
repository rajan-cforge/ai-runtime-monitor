"""Tests for config module: loading, merging, overrides, accessors, and generation."""

import sys
from pathlib import Path

import pytest

from claude_monitoring import config


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config cache before and after every test to prevent cross-contamination."""
    config.reset()
    yield
    config.reset()


# ─────────────────────────────────────────────────────────────
# _deep_merge
# ─────────────────────────────────────────────────────────────


class TestDeepMerge:
    """Tests for the recursive dict merge helper."""

    def test_disjoint_keys(self):
        base = {"a": 1}
        override = {"b": 2}
        result = config._deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_override_scalar(self):
        base = {"a": 1, "b": 2}
        override = {"a": 99}
        result = config._deep_merge(base, override)
        assert result == {"a": 99, "b": 2}

    def test_nested_merge(self):
        base = {"server": {"port": 80, "host": "localhost"}}
        override = {"server": {"port": 9090}}
        result = config._deep_merge(base, override)
        assert result == {"server": {"port": 9090, "host": "localhost"}}

    def test_deeply_nested_merge(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 99}}}
        result = config._deep_merge(base, override)
        assert result == {"a": {"b": {"c": 99, "d": 2}}}

    def test_override_dict_with_scalar(self):
        """When override provides a scalar for a key that was a dict, the scalar wins."""
        base = {"a": {"nested": True}}
        override = {"a": "flat"}
        result = config._deep_merge(base, override)
        assert result == {"a": "flat"}

    def test_override_scalar_with_dict(self):
        """When override provides a dict for a key that was a scalar, the dict wins."""
        base = {"a": "flat"}
        override = {"a": {"nested": True}}
        result = config._deep_merge(base, override)
        assert result == {"a": {"nested": True}}

    def test_base_not_mutated(self):
        base = {"server": {"port": 80}}
        override = {"server": {"port": 9090}}
        config._deep_merge(base, override)
        assert base == {"server": {"port": 80}}

    def test_empty_override(self):
        base = {"a": 1}
        result = config._deep_merge(base, {})
        assert result == {"a": 1}

    def test_empty_base(self):
        result = config._deep_merge({}, {"a": 1})
        assert result == {"a": 1}

    def test_both_empty(self):
        result = config._deep_merge({}, {})
        assert result == {}


# ─────────────────────────────────────────────────────────────
# load_config – no file (defaults)
# ─────────────────────────────────────────────────────────────


class TestLoadConfigDefaults:
    """load_config() should return default values when no config file is found."""

    def test_returns_dict(self, tmp_path):
        # Point to a path that does not exist so no file is loaded.
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert isinstance(cfg, dict)

    def test_default_dashboard_port(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["server"]["dashboard_port"] == 9081

    def test_default_proxy_port(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["server"]["proxy_port"] == 9080

    def test_default_bind_address(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["server"]["bind_address"] == "127.0.0.1"

    def test_default_output_dir(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["paths"]["output_dir"] == str(Path.home() / "claude_watch_output")

    def test_default_db_name(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["paths"]["db_name"] == "monitor.db"

    def test_default_session_dir(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["paths"]["session_dir"] == "sessions"

    def test_default_cert_dir(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["paths"]["cert_dir"] == "certs"

    def test_default_proxy_disabled(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["proxy"]["enabled"] is False

    def test_default_auto_configure_disabled(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert cfg["proxy"]["auto_configure"] is False

    def test_default_cert_path(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        expected = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
        assert cfg["proxy"]["cert_path"] == expected

    def test_has_all_top_level_sections(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "nonexistent.toml"))
        assert set(cfg.keys()) == {"server", "paths", "proxy", "mcp"}


# ─────────────────────────────────────────────────────────────
# load_config – from explicit TOML file
# ─────────────────────────────────────────────────────────────


class TestLoadConfigFromFile:
    """load_config(path) should merge file values over defaults."""

    def _write_toml(self, tmp_path, content: str) -> Path:
        toml_path = tmp_path / "test_config.toml"
        toml_path.write_text(content)
        return toml_path

    def test_overrides_single_value(self, tmp_path):
        toml_path = self._write_toml(tmp_path, "[server]\ndashboard_port = 5555\n")
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 5555
        # Other defaults remain intact.
        assert cfg["server"]["proxy_port"] == 9080

    def test_overrides_nested_paths(self, tmp_path):
        content = '[paths]\noutput_dir = "/custom/output"\ndb_name = "custom.db"\n'
        toml_path = self._write_toml(tmp_path, content)
        cfg = config.load_config(str(toml_path))
        assert cfg["paths"]["output_dir"] == "/custom/output"
        assert cfg["paths"]["db_name"] == "custom.db"
        # Defaults for keys not in file.
        assert cfg["paths"]["session_dir"] == "sessions"
        assert cfg["paths"]["cert_dir"] == "certs"

    def test_overrides_proxy_enabled(self, tmp_path):
        content = "[proxy]\nenabled = true\n"
        toml_path = self._write_toml(tmp_path, content)
        cfg = config.load_config(str(toml_path))
        assert cfg["proxy"]["enabled"] is True

    def test_multiple_sections(self, tmp_path):
        content = '[server]\nbind_address = "0.0.0.0"\n\n[proxy]\nenabled = true\nauto_configure = true\n'
        toml_path = self._write_toml(tmp_path, content)
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["bind_address"] == "0.0.0.0"
        assert cfg["proxy"]["enabled"] is True
        assert cfg["proxy"]["auto_configure"] is True

    def test_extra_keys_preserved(self, tmp_path):
        """Keys in the TOML file that are not in DEFAULTS should still appear."""
        content = '[extras]\ncustom_key = "custom_value"\n'
        toml_path = self._write_toml(tmp_path, content)
        cfg = config.load_config(str(toml_path))
        assert cfg["extras"]["custom_key"] == "custom_value"

    def test_nonexistent_file_uses_defaults(self, tmp_path):
        cfg = config.load_config(str(tmp_path / "does_not_exist.toml"))
        assert cfg["server"]["dashboard_port"] == 9081

    def test_empty_toml_returns_defaults(self, tmp_path):
        toml_path = self._write_toml(tmp_path, "")
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 9081
        assert cfg["paths"]["output_dir"] == str(Path.home() / "claude_watch_output")


# ─────────────────────────────────────────────────────────────
# set_cli_overrides
# ─────────────────────────────────────────────────────────────


class TestSetCliOverrides:
    """set_cli_overrides() should take priority over file and defaults."""

    def test_override_dashboard_port(self, tmp_path):
        config.set_cli_overrides(dashboard_port=1234)
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["dashboard_port"] == 1234

    def test_override_proxy_port(self, tmp_path):
        config.set_cli_overrides(proxy_port=7777)
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["proxy_port"] == 7777

    def test_override_bind_address(self, tmp_path):
        config.set_cli_overrides(bind_address="0.0.0.0")
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["bind_address"] == "0.0.0.0"

    def test_override_output_dir(self, tmp_path):
        config.set_cli_overrides(output_dir="/tmp/custom_output")
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["paths"]["output_dir"] == "/tmp/custom_output"

    def test_override_beats_file(self, tmp_path):
        """CLI overrides should win over TOML file values."""
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 5555\n")
        config.set_cli_overrides(dashboard_port=9999)
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 9999

    def test_none_values_ignored(self, tmp_path):
        """set_cli_overrides should skip keys whose value is None."""
        config.set_cli_overrides(dashboard_port=None)
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["dashboard_port"] == 9081  # default

    def test_unknown_keys_ignored(self, tmp_path):
        """Keys not in the mapping should not cause errors or appear in config."""
        config.set_cli_overrides(unknown_key="value")
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["dashboard_port"] == 9081  # unaffected

    def test_multiple_overrides(self, tmp_path):
        config.set_cli_overrides(dashboard_port=1111, proxy_port=2222, bind_address="10.0.0.1")
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["dashboard_port"] == 1111
        assert cfg["server"]["proxy_port"] == 2222
        assert cfg["server"]["bind_address"] == "10.0.0.1"

    def test_invalidates_cache(self, tmp_path):
        """After set_cli_overrides the cached _config should be None until reload."""
        config.load_config(str(tmp_path / "none.toml"))
        assert config._config is not None
        config.set_cli_overrides(dashboard_port=4444)
        assert config._config is None


# ─────────────────────────────────────────────────────────────
# Accessor functions
# ─────────────────────────────────────────────────────────────


class TestAccessors:
    """Test all public accessor functions return correct types and values."""

    def _load_defaults(self, tmp_path):
        """Load config with no file to get pure defaults."""
        config.load_config(str(tmp_path / "nonexistent.toml"))

    # -- get_output_dir --

    def test_get_output_dir_returns_path(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_output_dir()
        assert isinstance(result, Path)

    def test_get_output_dir_default(self, tmp_path):
        self._load_defaults(tmp_path)
        assert config.get_output_dir() == Path.home() / "claude_watch_output"

    def test_get_output_dir_with_override(self, tmp_path):
        config.set_cli_overrides(output_dir="/custom/dir")
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_output_dir() == Path("/custom/dir")

    def test_get_output_dir_expands_tilde(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[paths]\noutput_dir = "~/my_output"\n')
        config.load_config(str(toml_path))
        result = config.get_output_dir()
        assert "~" not in str(result)
        assert result == Path.home() / "my_output"

    # -- get_db_path --

    def test_get_db_path_returns_path(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_db_path()
        assert isinstance(result, Path)

    def test_get_db_path_default(self, tmp_path):
        self._load_defaults(tmp_path)
        expected = Path.home() / "claude_watch_output" / "monitor.db"
        assert config.get_db_path() == expected

    def test_get_db_path_respects_output_dir_override(self, tmp_path):
        config.set_cli_overrides(output_dir="/custom")
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_db_path() == Path("/custom/monitor.db")

    def test_get_db_path_respects_db_name_override(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[paths]\ndb_name = "custom.db"\n')
        config.load_config(str(toml_path))
        expected = Path.home() / "claude_watch_output" / "custom.db"
        assert config.get_db_path() == expected

    # -- get_session_dir --

    def test_get_session_dir_returns_path(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_session_dir()
        assert isinstance(result, Path)

    def test_get_session_dir_default(self, tmp_path):
        self._load_defaults(tmp_path)
        expected = Path.home() / "claude_watch_output" / "sessions"
        assert config.get_session_dir() == expected

    def test_get_session_dir_respects_output_dir_override(self, tmp_path):
        config.set_cli_overrides(output_dir="/tmp/out")
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_session_dir() == Path("/tmp/out/sessions")

    def test_get_session_dir_respects_session_dir_override(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[paths]\nsession_dir = "my_sessions"\n')
        config.load_config(str(toml_path))
        expected = Path.home() / "claude_watch_output" / "my_sessions"
        assert config.get_session_dir() == expected

    # -- get_cert_dir --

    def test_get_cert_dir_returns_path(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_cert_dir()
        assert isinstance(result, Path)

    def test_get_cert_dir_default(self, tmp_path):
        self._load_defaults(tmp_path)
        expected = Path.home() / "claude_watch_output" / "certs"
        assert config.get_cert_dir() == expected

    def test_get_cert_dir_respects_output_dir_override(self, tmp_path):
        config.set_cli_overrides(output_dir="/tmp/out")
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_cert_dir() == Path("/tmp/out/certs")

    # -- get_dashboard_port --

    def test_get_dashboard_port_returns_int(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_dashboard_port()
        assert isinstance(result, int)

    def test_get_dashboard_port_default(self, tmp_path):
        self._load_defaults(tmp_path)
        assert config.get_dashboard_port() == 9081

    def test_get_dashboard_port_with_override(self, tmp_path):
        config.set_cli_overrides(dashboard_port=3000)
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_dashboard_port() == 3000

    def test_get_dashboard_port_from_file(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 7070\n")
        config.load_config(str(toml_path))
        assert config.get_dashboard_port() == 7070

    # -- get_proxy_port --

    def test_get_proxy_port_returns_int(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_proxy_port()
        assert isinstance(result, int)

    def test_get_proxy_port_default(self, tmp_path):
        self._load_defaults(tmp_path)
        assert config.get_proxy_port() == 9080

    def test_get_proxy_port_with_override(self, tmp_path):
        config.set_cli_overrides(proxy_port=8888)
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_proxy_port() == 8888

    # -- get_bind_address --

    def test_get_bind_address_returns_str(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_bind_address()
        assert isinstance(result, str)

    def test_get_bind_address_default(self, tmp_path):
        self._load_defaults(tmp_path)
        assert config.get_bind_address() == "127.0.0.1"

    def test_get_bind_address_with_override(self, tmp_path):
        config.set_cli_overrides(bind_address="0.0.0.0")
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_bind_address() == "0.0.0.0"

    # -- get_cert_path --

    def test_get_cert_path_returns_path(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.get_cert_path()
        assert isinstance(result, Path)

    def test_get_cert_path_default(self, tmp_path):
        self._load_defaults(tmp_path)
        expected = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        assert config.get_cert_path() == expected

    def test_get_cert_path_expands_tilde(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[proxy]\ncert_path = "~/custom/cert.pem"\n')
        config.load_config(str(toml_path))
        result = config.get_cert_path()
        assert "~" not in str(result)
        assert result == Path.home() / "custom" / "cert.pem"

    def test_get_cert_path_from_file(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text('[proxy]\ncert_path = "/etc/ssl/my-cert.pem"\n')
        config.load_config(str(toml_path))
        assert config.get_cert_path() == Path("/etc/ssl/my-cert.pem")

    # -- is_proxy_enabled --

    def test_is_proxy_enabled_returns_bool(self, tmp_path):
        self._load_defaults(tmp_path)
        result = config.is_proxy_enabled()
        assert isinstance(result, bool)

    def test_is_proxy_enabled_default_false(self, tmp_path):
        self._load_defaults(tmp_path)
        assert config.is_proxy_enabled() is False

    def test_is_proxy_enabled_true_from_file(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[proxy]\nenabled = true\n")
        config.load_config(str(toml_path))
        assert config.is_proxy_enabled() is True


# ─────────────────────────────────────────────────────────────
# Accessor auto-loads config via _get_config
# ─────────────────────────────────────────────────────────────


class TestAccessorAutoLoad:
    """Accessors should auto-load config if _config is None."""

    def test_accessor_works_without_explicit_load(self):
        # After reset (autouse fixture), _config is None.
        # Calling an accessor should trigger load_config() internally.
        result = config.get_dashboard_port()
        assert isinstance(result, int)

    def test_get_config_caches(self, tmp_path):
        """_get_config should return the same object on repeated calls."""
        config.load_config(str(tmp_path / "none.toml"))
        a = config._get_config()
        b = config._get_config()
        assert a is b


# ─────────────────────────────────────────────────────────────
# generate_default_config
# ─────────────────────────────────────────────────────────────


class TestGenerateDefaultConfig:
    """generate_default_config() should write a valid, parseable TOML file."""

    def test_creates_file(self, tmp_path):
        out = tmp_path / "config.toml"
        result = config.generate_default_config(out)
        assert result == out
        assert out.exists()

    def test_creates_parent_directories(self, tmp_path):
        out = tmp_path / "deeply" / "nested" / "dir" / "config.toml"
        config.generate_default_config(out)
        assert out.exists()

    def test_file_content_matches_template(self, tmp_path):
        out = tmp_path / "config.toml"
        config.generate_default_config(out)
        content = out.read_text()
        assert content == config.DEFAULT_CONFIG_TOML

    def test_file_is_valid_toml(self, tmp_path):
        """The generated file should be parseable by tomllib."""
        out = tmp_path / "config.toml"
        config.generate_default_config(out)

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                pytest.skip("tomli not available for TOML parsing test")

        with open(out, "rb") as f:
            parsed = tomllib.load(f)

        assert parsed["server"]["dashboard_port"] == 9081
        assert parsed["server"]["proxy_port"] == 9080
        assert parsed["server"]["bind_address"] == "127.0.0.1"
        assert parsed["paths"]["output_dir"] == "~/claude_watch_output"
        assert parsed["paths"]["db_name"] == "monitor.db"
        assert parsed["proxy"]["enabled"] is False

    def test_loadable_by_load_config(self, tmp_path):
        """The generated config file should be loadable and produce expected values."""
        out = tmp_path / "config.toml"
        config.generate_default_config(out)
        cfg = config.load_config(str(out))
        # The generated TOML uses "~/claude_watch_output" (with tilde),
        # which overrides the default (expanded) path.
        assert cfg["server"]["dashboard_port"] == 9081
        assert cfg["proxy"]["enabled"] is False

    def test_returns_path(self, tmp_path):
        out = tmp_path / "config.toml"
        result = config.generate_default_config(out)
        assert isinstance(result, Path)
        assert result == out

    def test_overwrites_existing_file(self, tmp_path):
        out = tmp_path / "config.toml"
        out.write_text("old content")
        config.generate_default_config(out)
        assert out.read_text() == config.DEFAULT_CONFIG_TOML


# ─────────────────────────────────────────────────────────────
# reset
# ─────────────────────────────────────────────────────────────


class TestReset:
    """reset() should clear both the cached config and CLI overrides."""

    def test_clears_cached_config(self, tmp_path):
        config.load_config(str(tmp_path / "none.toml"))
        assert config._config is not None
        config.reset()
        assert config._config is None

    def test_clears_cli_overrides(self, tmp_path):
        config.set_cli_overrides(dashboard_port=1234)
        assert config._cli_overrides != {}
        config.reset()
        assert config._cli_overrides == {}

    def test_subsequent_load_uses_defaults(self, tmp_path):
        """After reset, loading config should not retain previous overrides."""
        config.set_cli_overrides(dashboard_port=1234)
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_dashboard_port() == 1234

        config.reset()
        config.load_config(str(tmp_path / "none.toml"))
        assert config.get_dashboard_port() == 9081


# ─────────────────────────────────────────────────────────────
# Config caching behavior
# ─────────────────────────────────────────────────────────────


class TestConfigCaching:
    """Verify that config is cached and re-loaded correctly."""

    def test_load_config_sets_module_cache(self, tmp_path):
        config.load_config(str(tmp_path / "none.toml"))
        assert config._config is not None

    def test_load_config_returns_same_as_cache(self, tmp_path):
        result = config.load_config(str(tmp_path / "none.toml"))
        assert result is config._config

    def test_reload_after_reset_picks_up_changes(self, tmp_path):
        """After reset, a new load_config should re-read from file."""
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 1111\n")
        config.load_config(str(toml_path))
        assert config.get_dashboard_port() == 1111

        config.reset()

        # Update the file.
        toml_path.write_text("[server]\ndashboard_port = 2222\n")
        config.load_config(str(toml_path))
        assert config.get_dashboard_port() == 2222


# ─────────────────────────────────────────────────────────────
# Priority: CLI > file > defaults
# ─────────────────────────────────────────────────────────────


class TestConfigPriority:
    """Verify the merge priority: CLI overrides > TOML file > DEFAULTS."""

    def test_file_overrides_default(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 5000\n")
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 5000  # file wins over default 9081

    def test_cli_overrides_file(self, tmp_path):
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 5000\n")
        config.set_cli_overrides(dashboard_port=6000)
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 6000  # CLI wins over file 5000

    def test_cli_overrides_default(self, tmp_path):
        config.set_cli_overrides(dashboard_port=7000)
        cfg = config.load_config(str(tmp_path / "none.toml"))
        assert cfg["server"]["dashboard_port"] == 7000  # CLI wins over default 9081

    def test_unoverridden_keys_remain_default(self, tmp_path):
        """When only some keys are overridden, others keep their defaults."""
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\ndashboard_port = 5000\n")
        config.set_cli_overrides(proxy_port=8888)
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 5000  # from file
        assert cfg["server"]["proxy_port"] == 8888  # from CLI
        assert cfg["server"]["bind_address"] == "127.0.0.1"  # from defaults

    def test_full_three_layer_merge(self, tmp_path):
        """All three layers coexist: defaults for bind_address, file for proxy_port, CLI for dashboard_port."""
        toml_path = tmp_path / "config.toml"
        toml_path.write_text("[server]\nproxy_port = 4444\n")
        config.set_cli_overrides(dashboard_port=3333)
        cfg = config.load_config(str(toml_path))
        assert cfg["server"]["dashboard_port"] == 3333  # CLI
        assert cfg["server"]["proxy_port"] == 4444  # file
        assert cfg["server"]["bind_address"] == "127.0.0.1"  # default
