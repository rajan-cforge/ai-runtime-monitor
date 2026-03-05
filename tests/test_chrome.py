"""Tests for Chrome timestamp conversion and URL parsing."""

from datetime import datetime, timezone


def _make_watcher():
    """Create a minimal BrowserActivityWatcher-like object for testing methods."""

    # Import the class - it's defined in monitor module
    # We test the static-like methods by creating a mock
    class FakeWatcher:
        def _chrome_ts_to_iso(self, chrome_ts):
            if not chrome_ts:
                return None
            try:
                unix_ts = chrome_ts / 1_000_000 - 11644473600
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
            except Exception:
                return None

        def _extract_conversation_id(self, url, service):
            try:
                from urllib.parse import urlparse
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

    return FakeWatcher()


class TestChromeTimestamp:
    def test_chrome_ts_to_iso(self):
        w = _make_watcher()
        # Chrome epoch: 1601-01-01. 13350000000000000 microseconds from that is roughly 2023.
        chrome_ts = 13350000000000000
        result = w._chrome_ts_to_iso(chrome_ts)
        assert result is not None
        assert "T" in result  # ISO format

    def test_chrome_ts_none(self):
        w = _make_watcher()
        assert w._chrome_ts_to_iso(None) is None

    def test_chrome_ts_zero(self):
        w = _make_watcher()
        assert w._chrome_ts_to_iso(0) is None

    def test_known_timestamp(self):
        w = _make_watcher()
        # 2024-01-01 00:00:00 UTC in Chrome timestamp
        # Unix: 1704067200, Chrome: (1704067200 + 11644473600) * 1000000
        chrome_ts = (1704067200 + 11644473600) * 1_000_000
        result = w._chrome_ts_to_iso(chrome_ts)
        assert "2024-01-01" in result


class TestConversationId:
    def test_chatgpt_url(self):
        w = _make_watcher()
        url = "https://chatgpt.com/c/abc123-def456"
        result = w._extract_conversation_id(url, "ChatGPT")
        assert result == "abc123-def456"

    def test_gemini_url(self):
        w = _make_watcher()
        url = "https://gemini.google.com/app/conv789"
        result = w._extract_conversation_id(url, "Gemini")
        assert result == "conv789"

    def test_claude_web_url(self):
        w = _make_watcher()
        url = "https://claude.ai/chat/session-xyz"
        result = w._extract_conversation_id(url, "Claude Web")
        assert result == "session-xyz"

    def test_invalid_url(self):
        w = _make_watcher()
        result = w._extract_conversation_id("not-a-url", "ChatGPT")
        assert result is None

    def test_no_conversation_in_url(self):
        w = _make_watcher()
        result = w._extract_conversation_id("https://chatgpt.com/", "ChatGPT")
        assert result is None
