"""Tests for estimate_cost() and MODEL_PRICING."""

from claude_monitoring.monitor import MODEL_PRICING, estimate_cost


class TestEstimateCost:
    def test_known_model_opus(self):
        cost = estimate_cost("claude-opus-4", 1_000_000, 1_000_000)
        expected = 15.00 + 75.00  # $15/M input + $75/M output
        assert cost == expected

    def test_known_model_sonnet(self):
        cost = estimate_cost("claude-sonnet-4", 1_000_000, 1_000_000)
        expected = 3.00 + 15.00
        assert cost == expected

    def test_known_model_haiku(self):
        cost = estimate_cost("claude-haiku-4", 1_000_000, 1_000_000)
        expected = 0.80 + 4.00
        assert cost == expected

    def test_unknown_model_uses_default(self):
        cost = estimate_cost("some-unknown-model", 1_000_000, 1_000_000)
        default = MODEL_PRICING["default"]
        expected = default["input"] + default["output"]
        assert cost == expected

    def test_zero_tokens(self):
        cost = estimate_cost("claude-opus-4", 0, 0)
        assert cost == 0.0

    def test_cache_read_pricing(self):
        # Cache read = 10% of input price
        cost = estimate_cost("claude-sonnet-4", 0, 0, cache_read=1_000_000)
        expected = round(1_000_000 / 1_000_000 * 3.00 * 0.1, 6)
        assert cost == expected

    def test_cache_write_pricing(self):
        # Cache write = 125% of input price
        cost = estimate_cost("claude-sonnet-4", 0, 0, cache_write=1_000_000)
        expected = round(1_000_000 / 1_000_000 * 3.00 * 1.25, 6)
        assert cost == expected

    def test_model_pricing_has_default(self):
        assert "default" in MODEL_PRICING
        assert "input" in MODEL_PRICING["default"]
        assert "output" in MODEL_PRICING["default"]

    def test_none_model_uses_default(self):
        cost = estimate_cost(None, 1_000_000, 0)
        expected = MODEL_PRICING["default"]["input"]
        assert cost == expected
