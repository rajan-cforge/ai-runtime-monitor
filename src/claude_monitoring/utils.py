"""Shared utility functions for AI Runtime Monitor.

Used by both monitor.py and watch.py.
"""

import re
from datetime import datetime, timezone

from claude_monitoring.constants import (
    AI_PROCESS_EXACT,
    AI_PROCESS_PATTERNS,
    MODEL_PRICING,
    SENSITIVE_PATTERNS,
)


def scan_sensitive(text, names_only=False):
    """Scan text for sensitive data patterns.

    Args:
        text: Text to scan. Truncated to 50K chars for performance.
        names_only: If True, return list of pattern name strings (watch.py compat).
                    If False, return list of dicts with name/severity/category.

    Returns:
        List of matches (dicts or strings depending on names_only).
    """
    if not text:
        return []
    scan_text = text[:50000] if len(text) > 50000 else text
    found = []
    for name, info in SENSITIVE_PATTERNS.items():
        pattern = info["pattern"]
        try:
            if re.search(pattern, scan_text):
                if names_only:
                    found.append(name)
                else:
                    found.append(
                        {
                            "name": name,
                            "severity": info["severity"],
                            "category": info["category"],
                        }
                    )
        except re.error:
            continue
    return found


def estimate_cost(model, input_tokens, output_tokens, cache_read=0, cache_write=0):
    """Estimate USD cost from token counts.

    Args:
        model: Model name string (e.g. "claude-sonnet-4").
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.
        cache_read: Cache read tokens (10% of input price).
        cache_write: Cache write tokens (125% of input price).

    Returns:
        Estimated cost in USD, rounded to 6 decimal places.
    """
    pricing = MODEL_PRICING["default"]
    # Match longest key first to avoid prefix collisions
    for key in sorted(MODEL_PRICING.keys(), key=len, reverse=True):
        if key != "default" and key in (model or ""):
            pricing = MODEL_PRICING[key]
            break
    cost = (
        input_tokens / 1_000_000 * pricing["input"]
        + output_tokens / 1_000_000 * pricing["output"]
        + cache_read / 1_000_000 * pricing["input"] * 0.1
        + cache_write / 1_000_000 * pricing["input"] * 1.25
    )
    return round(cost, 6)


def extract_file_paths(text):
    """Extract file paths mentioned in text.

    Returns:
        Deduplicated list of file paths found.
    """
    paths = re.findall(r'(?:^|[\s\'"])(/(?:[\w\-./]+))', text)
    return list(set(p for p in paths if len(p) > 3 and "." in p.split("/")[-1]))


def extract_urls(text):
    """Extract HTTP/HTTPS URLs from text.

    Returns:
        List of URL strings found.
    """
    return re.findall(r'https?://[^\s\'"<>]+', text)


def now_iso():
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def is_ai_process(name, cmdline, exe_path=""):
    """Check if a process is an AI process using two-tier matching.

    Tier 1: Exact process name match (fast).
    Tier 2: Substring pattern match with exclusion list.
    Skips macOS system services.

    Returns:
        True if the process is identified as an AI process.
    """
    if name in AI_PROCESS_EXACT:
        return True
    # Skip macOS system services
    if exe_path and (exe_path.startswith("/System/Library/") or exe_path.startswith("/usr/libexec/")):
        return False
    name_lower = (name or "").lower()
    cmdline_lower = (cmdline or "").lower()
    for pattern, config in AI_PROCESS_PATTERNS.items():
        if pattern in name_lower or pattern in cmdline_lower:
            if any(excl in name for excl in config.get("exclude", [])):
                continue
            return True
    return False
