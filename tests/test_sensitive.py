"""Tests for scan_sensitive() pattern detection."""

from claude_monitoring.monitor import scan_sensitive


class TestScanSensitive:
    def test_aws_key_detected(self):
        text = "config: AKIAIOSFODNN7EXAMPLE"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "aws_key" in names
        assert any(r["severity"] == "critical" for r in results if r["name"] == "aws_key")

    def test_github_token_detected(self):
        text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "github_token" in names

    def test_private_key_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "private_key" in names
        assert any(r["severity"] == "critical" for r in results if r["name"] == "private_key")

    def test_jwt_detected(self):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "jwt_token" in names

    def test_credit_card_detected(self):
        text = "card: 4111111111111111"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "credit_card" in names
        assert any(r["category"] == "pii" for r in results if r["name"] == "credit_card")

    def test_ssn_detected(self):
        text = "SSN: 123-45-6789"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "ssn" in names
        assert any(r["category"] == "pii" for r in results if r["name"] == "ssn")

    def test_anthropic_key_detected(self):
        text = "key=sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "anthropic_key" in names

    def test_openai_key_detected(self):
        text = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "openai_key" in names

    def test_env_file_detected(self):
        text = "loading .env.production values"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "env_file" in names
        assert any(r["category"] == "policy" for r in results if r["name"] == "env_file")

    def test_normal_text_empty(self):
        text = "This is a normal commit message with no secrets"
        results = scan_sensitive(text)
        # Should not detect credentials or PII
        critical = [r for r in results if r["severity"] == "critical"]
        assert len(critical) == 0

    def test_empty_string(self):
        assert scan_sensitive("") == []

    def test_none_input(self):
        assert scan_sensitive(None) == []

    def test_large_text_truncation(self):
        """Scan should handle large texts by truncating at 50K chars."""
        text = "normal " * 10000  # 70K chars
        # Should not crash
        results = scan_sensitive(text)
        assert isinstance(results, list)

    def test_password_in_code(self):
        text = 'password = "super_secret_pass123"'
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "password_in_code" in names

    def test_slack_webhook_detected(self):
        # Construct URL dynamically to avoid GitHub push protection false positive
        text = "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        results = scan_sensitive(text)
        names = [r["name"] for r in results]
        assert "slack_webhook" in names
