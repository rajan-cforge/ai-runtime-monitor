"""Tests for claude_watch utility functions."""

from claude_monitoring.utils import estimate_cost, extract_file_paths, extract_urls


class TestExtractFilePaths:
    def test_finds_unix_paths(self):
        text = "Reading /Users/dev/project/main.py and /tmp/data.json"
        paths = extract_file_paths(text)
        assert "/Users/dev/project/main.py" in paths
        assert "/tmp/data.json" in paths

    def test_ignores_short_paths(self):
        text = "use /a or /b"
        paths = extract_file_paths(text)
        assert len(paths) == 0

    def test_requires_extension(self):
        text = "cd /usr/local/bin"
        paths = extract_file_paths(text)
        # /usr/local/bin has no file extension
        assert "/usr/local/bin" not in paths

    def test_empty_string(self):
        assert extract_file_paths("") == []

    def test_deduplicates(self):
        text = "/tmp/test.py /tmp/test.py /tmp/test.py"
        paths = extract_file_paths(text)
        assert len(paths) == 1


class TestExtractUrls:
    def test_finds_https_urls(self):
        text = "Visit https://api.anthropic.com/v1/messages for docs"
        urls = extract_urls(text)
        assert "https://api.anthropic.com/v1/messages" in urls

    def test_finds_http_urls(self):
        text = "Server at http://localhost:8080/api"
        urls = extract_urls(text)
        assert "http://localhost:8080/api" in urls

    def test_empty_string(self):
        assert extract_urls("") == []

    def test_no_urls(self):
        text = "This has no web addresses"
        assert extract_urls(text) == []


class TestWatchEstimateCost:
    def test_basic_cost(self):
        cost = estimate_cost("claude-sonnet-4", 1_000_000, 1_000_000)
        assert cost == 3.00 + 15.00

    def test_with_cache(self):
        cost = estimate_cost("claude-sonnet-4", 0, 0, cache_read=1_000_000)
        assert cost > 0

    def test_zero_tokens(self):
        cost = estimate_cost("claude-sonnet-4", 0, 0)
        assert cost == 0.0
