"""Tests for is_ai_process() and process matching logic."""

from claude_monitoring.utils import is_ai_process


class TestIsAiProcess:
    def test_exact_match_claude(self):
        assert is_ai_process("claude", "") is True

    def test_exact_match_chatgpt(self):
        assert is_ai_process("ChatGPT", "") is True

    def test_exact_match_cursor(self):
        assert is_ai_process("Cursor", "") is True

    def test_exact_match_ollama(self):
        assert is_ai_process("ollama", "") is True

    def test_cursor_ui_view_excluded(self):
        assert is_ai_process("CursorUIViewService", "") is False

    def test_system_path_excluded(self):
        # Exact matches bypass the system path check, so use a pattern match name
        assert is_ai_process("anthropic-helper", "", exe_path="/System/Library/Frameworks/something") is False

    def test_usr_libexec_excluded(self):
        assert is_ai_process("claude-helper", "", exe_path="/usr/libexec/claude-helper") is False

    def test_pattern_match_in_cmdline(self):
        assert is_ai_process("python3", "anthropic-cli --start") is True

    def test_pattern_match_copilot(self):
        assert is_ai_process("copilot-agent", "") is True

    def test_unrelated_process(self):
        assert is_ai_process("Safari", "com.apple.safari") is False

    def test_empty_name(self):
        assert is_ai_process("", "") is False

    def test_none_cmdline(self):
        # Should not crash with None
        assert is_ai_process("claude", None) is True
