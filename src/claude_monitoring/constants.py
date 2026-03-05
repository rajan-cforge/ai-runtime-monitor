"""Shared constants for AI Runtime Monitor.

Single source of truth for all constants used by both monitor.py and watch.py.
"""

# ─────────────────────────────────────────────────────────────
# AI Process Detection
# ─────────────────────────────────────────────────────────────

# Exact process name matches (case-sensitive)
AI_PROCESS_EXACT = {
    "claude",
    "Claude",
    "ChatGPT",
    "ChatGPTHelper",
    "Ollama",
    "ollama",
    "Cursor",
    "Windsurf",
}

# Substring pattern matching with exclusions
AI_PROCESS_PATTERNS = {
    "claude": {"exclude": []},
    "anthropic": {"exclude": []},
    "chatgpt": {"exclude": []},
    "ollama": {"exclude": []},
    "copilot": {"exclude": ["CursorUIViewService"]},
    "cursor": {"exclude": ["CursorUIViewService"]},
    "aider": {"exclude": []},
    "openai": {"exclude": []},
    "lmstudio": {"exclude": []},
    "cody": {"exclude": []},
    "gemini": {"exclude": []},
    "bedrock": {"exclude": []},
    "codex": {"exclude": []},
    "windsurf": {"exclude": []},
}

# ─────────────────────────────────────────────────────────────
# Browser AI Patterns (Chrome history matching)
# ─────────────────────────────────────────────────────────────

BROWSER_AI_PATTERNS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "gemini.google.com": "Gemini",
    "claude.ai": "Claude Web",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Copilot",
    "aistudio.google.com": "AI Studio",
    "deepseek.com": "DeepSeek",
}

# ─────────────────────────────────────────────────────────────
# AI Hosts — merged superset from monitor.py and watch.py
# ─────────────────────────────────────────────────────────────

AI_HOSTS = {
    # Anthropic
    "api.anthropic.com": "anthropic_api",
    "statsig.anthropic.com": "anthropic_telemetry",
    "console.anthropic.com": "anthropic_console",
    # OpenAI / ChatGPT / Copilot
    "api.openai.com": "openai_api",
    "chatgpt.com": "chatgpt_web",
    "copilot.githubusercontent.com": "github_copilot",
    "copilot-proxy.githubusercontent.com": "github_copilot",
    "githubcopilot.com": "github_copilot",
    "api.githubcopilot.com": "github_copilot",
    # Google
    "generativelanguage.googleapis.com": "gemini_api",
    "aistudio.google.com": "google_aistudio",
    "aiplatform.googleapis.com": "vertex_ai",
    # AWS
    "bedrock.amazonaws.com": "aws_bedrock",
    "bedrock-runtime.amazonaws.com": "aws_bedrock",
    # Mistral
    "api.mistral.ai": "mistral_api",
    # Cohere
    "api.cohere.ai": "cohere_api",
    "api.cohere.com": "cohere_api",
    # Groq
    "api.groq.com": "groq_api",
    # Together AI
    "api.together.xyz": "together_api",
    # Perplexity
    "api.perplexity.ai": "perplexity_api",
    # DeepSeek
    "api.deepseek.com": "deepseek_api",
    # xAI / Grok
    "api.x.ai": "xai_grok_api",
    # HuggingFace
    "api-inference.huggingface.co": "huggingface_api",
    "huggingface.co": "huggingface_web",
    # Replicate
    "api.replicate.com": "replicate_api",
    # Fireworks
    "api.fireworks.ai": "fireworks_api",
    # Ollama (local)
    "localhost:11434": "ollama_local",
    "127.0.0.1:11434": "ollama_local",
    # LM Studio (local)
    "localhost:1234": "lmstudio_local",
    "127.0.0.1:1234": "lmstudio_local",
    # OpenRouter
    "openrouter.ai": "openrouter_api",
    # Azure OpenAI
    "openai.azure.com": "azure_openai",
    # Telemetry / analytics
    "sentry.io": "error_reporting",
    "ingest.sentry.io": "error_reporting",
    "featuregates.cloud": "statsig_telemetry",
    "api.statsig.com": "statsig_telemetry",
    "events.statsig.com": "statsig_telemetry",
    "api.segment.io": "segment_telemetry",
    "api.amplitude.com": "amplitude_telemetry",
}

# ─────────────────────────────────────────────────────────────
# Service Classification (reverse DNS → service name)
# ─────────────────────────────────────────────────────────────

SERVICE_CLASSIFICATION = {
    ".1e100.net": "Google APIs",
    ".googleapis.com": "Google APIs",
    ".anthropic.com": "Anthropic",
    ".openai.com": "OpenAI",
    ".azure.com": "Azure",
    ".amazonaws.com": "AWS",
    ".github.com": "GitHub",
    ".sentry.io": "Sentry",
    ".segment.io": "Segment",
    ".statsig.com": "Statsig",
    ".googleusercontent.com": "Anthropic API",
    ".bc.googleusercontent.com": "Anthropic API",
}

# Known Anthropic API IP prefixes (GCP-hosted)
ANTHROPIC_IP_PREFIXES = (
    "160.79.",
    "137.66.",
    "35.185.",
    "34.8.",
    "34.49.",
)

# ─────────────────────────────────────────────────────────────
# Sensitive Data Patterns (with severity and category)
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    # CRITICAL — immediate credential exposure
    "aws_key": {"pattern": r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}", "severity": "critical", "category": "credential"},
    "aws_secret": {
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
        "severity": "critical",
        "category": "credential",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "severity": "critical",
        "category": "credential",
    },
    "anthropic_key": {"pattern": r"sk-ant-[A-Za-z0-9\-_]{40,}", "severity": "critical", "category": "credential"},
    "openai_key": {"pattern": r"sk-[A-Za-z0-9]{32,}", "severity": "critical", "category": "credential"},
    "github_token": {"pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}", "severity": "critical", "category": "credential"},
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "critical",
        "category": "credential",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "severity": "critical",
        "category": "credential",
    },
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",
        "severity": "critical",
        "category": "credential",
    },
    # HIGH — secrets and tokens
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "severity": "high",
        "category": "credential",
    },
    "bearer_token": {
        "pattern": r"(?i)(?:Authorization|Bearer)\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9_\-\.]{20,}",
        "severity": "high",
        "category": "credential",
    },
    "password_in_code": {
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "severity": "high",
        "category": "credential",
    },
    "api_key_generic": {
        "pattern": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "category": "credential",
    },
    "db_connection": {
        "pattern": r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]{10,}",
        "severity": "high",
        "category": "credential",
    },
    "base64_secret": {
        "pattern": r"(?i)(?:secret|token|key|auth)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?",
        "severity": "high",
        "category": "credential",
    },
    # MEDIUM — PII and sensitive data
    "ssn": {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "severity": "medium", "category": "pii"},
    "credit_card": {
        "pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b",
        "severity": "medium",
        "category": "pii",
    },
    "phone_number": {
        "pattern": r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        "severity": "medium",
        "category": "pii",
    },
    "email_bulk": {
        "pattern": r"(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\s*[,;\n]\s*){3,}",
        "severity": "medium",
        "category": "pii",
    },
    # LOW — informational / policy
    "env_file": {"pattern": r"\.env(?:\.[a-z]+)?", "severity": "low", "category": "policy"},
    "internal_url": {
        "pattern": r"https?://(?:internal|staging|dev|local|corp|intranet)\.[a-z0-9.-]+",
        "severity": "low",
        "category": "policy",
    },
    "ip_address_private": {
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "severity": "low",
        "category": "policy",
    },
}

# Severity ordering for display
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ─────────────────────────────────────────────────────────────
# Model Pricing (per 1M tokens)
# ─────────────────────────────────────────────────────────────

MODEL_PRICING = {
    "claude-opus-4": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4": {"input": 3.00, "output": 15.00},
    "claude-haiku-4": {"input": 0.80, "output": 4.00},
    "claude-opus-4-5": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5": {"input": 0.80, "output": 4.00},
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-5-haiku": {"input": 0.80, "output": 4.00},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "default": {"input": 3.00, "output": 15.00},
}

# Subscription plan token limits (approximate monthly)
PLAN_LIMITS = {
    "max_20x": {"monthly_tokens": 900_000_000, "label": "Max 20x"},
    "max_5x": {"monthly_tokens": 225_000_000, "label": "Max 5x"},
    "max": {"monthly_tokens": 45_000_000, "label": "Max"},
    "pro": {"monthly_tokens": 45_000_000, "label": "Pro"},
    "free": {"monthly_tokens": 5_000_000, "label": "Free"},
}

# ─────────────────────────────────────────────────────────────
# claude-watch Specific Constants
# ─────────────────────────────────────────────────────────────

# Claude Code tool names to track
TOOL_NAMES = {
    "bash",
    "computer",
    "str_replace_editor",
    "str_replace_based_edit_tool",
    "read_file",
    "write_file",
    "create_file",
    "list_directory",
    "web_search",
    "web_fetch",
    "execute_code",
    "file_editor",
    "TodoRead",
    "TodoWrite",
    "Task",
    "mcp__",
}

# CSV columns for watch.py traffic capture
CSV_COLUMNS = [
    "timestamp",
    "session_id",
    "turn_id",
    "turn_number",
    "destination_host",
    "destination_service",
    "endpoint_path",
    "http_method",
    "http_status",
    "model",
    "stream",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "estimated_cost_usd",
    "request_size_bytes",
    "response_size_bytes",
    "latency_ms",
    "num_messages",
    "system_prompt_chars",
    "last_user_msg_preview",
    "assistant_msg_preview",
    "tool_calls",
    "tool_call_count",
    "bash_commands",
    "files_read",
    "files_written",
    "urls_fetched",
    "sensitive_patterns",
    "sensitive_pattern_count",
    "content_types_sent",
    "stop_reason",
    "request_id",
    "raw_request_hash",
]
