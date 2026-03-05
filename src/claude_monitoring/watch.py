#!/usr/bin/env python3
"""
claude_watch.py — AI Agent Traffic Observatory
================================================
Intercepts ALL traffic from Claude Code (and any AI agent) running on your machine.
Logs every prompt, response, tool call, file access, and data pattern to CSV.

USAGE:
  # First-time setup (run once):
  claude-watch --setup

  # Start monitoring (in one terminal):
  claude-watch --start

  # Then in another terminal, run claude code normally:
  claude

  # Analyze captured CSV:
  claude-watch --analyze ~/claude_watch_output/sessions/

HOW IT WORKS:
  Runs mitmproxy as a local HTTPS proxy on port 8080.
  Intercepts api.anthropic.com, sentry.io, statsig.com traffic.
  Parses Anthropic API request/response payloads.
  Extracts tool calls, file paths, bash commands, sensitive patterns.
  Writes one CSV row per API turn.
"""

import sys
import os
import subprocess
import json
import re
import csv
import time
import uuid
import hashlib
import argparse
import signal
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Optional, List, Dict, Tuple

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

OUTPUT_DIR = Path.home() / "claude_watch_output"
SESSION_DIR = OUTPUT_DIR / "sessions"
CERT_DIR = OUTPUT_DIR / "certs"
PROXY_PORT = 9080

AI_HOSTS = {
    # Anthropic
    "api.anthropic.com":    "anthropic_api",
    "statsig.anthropic.com": "anthropic_telemetry",
    "console.anthropic.com": "anthropic_console",
    # OpenAI / ChatGPT / Copilot
    "api.openai.com":       "openai_api",
    "chatgpt.com":          "chatgpt_web",
    "copilot.githubusercontent.com": "github_copilot",
    "copilot-proxy.githubusercontent.com": "github_copilot",
    "githubcopilot.com":    "github_copilot",
    "api.githubcopilot.com":"github_copilot",
    # Google
    "generativelanguage.googleapis.com": "gemini_api",
    "aistudio.google.com":  "google_aistudio",
    "aiplatform.googleapis.com": "vertex_ai",
    # AWS
    "bedrock.amazonaws.com":"aws_bedrock",
    "bedrock-runtime.amazonaws.com": "aws_bedrock",
    # Mistral
    "api.mistral.ai":       "mistral_api",
    # Cohere
    "api.cohere.ai":        "cohere_api",
    "api.cohere.com":       "cohere_api",
    # Groq
    "api.groq.com":         "groq_api",
    # Together AI
    "api.together.xyz":     "together_api",
    # Perplexity
    "api.perplexity.ai":    "perplexity_api",
    # DeepSeek
    "api.deepseek.com":     "deepseek_api",
    # xAI / Grok
    "api.x.ai":             "xai_grok_api",
    # HuggingFace
    "api-inference.huggingface.co": "huggingface_api",
    "huggingface.co":       "huggingface_web",
    # Replicate
    "api.replicate.com":    "replicate_api",
    # Fireworks
    "api.fireworks.ai":     "fireworks_api",
    # Ollama (local)
    "localhost:11434":      "ollama_local",
    "127.0.0.1:11434":      "ollama_local",
    # LM Studio (local)
    "localhost:1234":       "lmstudio_local",
    "127.0.0.1:1234":       "lmstudio_local",
    # OpenRouter
    "openrouter.ai":        "openrouter_api",
    # Azure OpenAI
    "openai.azure.com":     "azure_openai",
    # Telemetry / analytics
    "sentry.io":            "error_reporting",
    "ingest.sentry.io":     "error_reporting",
    "featuregates.cloud":   "statsig_telemetry",
    "api.statsig.com":      "statsig_telemetry",
    "events.statsig.com":   "statsig_telemetry",
    "api.segment.io":       "segment_telemetry",
    "api.amplitude.com":    "amplitude_telemetry",
}

# Sensitive data patterns to flag before data leaves your machine
SENSITIVE_PATTERNS = {
    "aws_key":          r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}",
    "aws_secret":       r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
    "private_key":      r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "github_token":     r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "api_key_generic":  r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
    "password_in_code": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "jwt_token":        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "credit_card":      r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "ssn":              r"\b\d{3}-\d{2}-\d{4}\b",
    "anthropic_key":    r"sk-ant-[A-Za-z0-9\-_]{40,}",
    "env_file":         r"\.env(?:\.[a-z]+)?",
    "ip_address":       r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b",
}

# Claude Code tool names to track
TOOL_NAMES = {
    "bash", "computer", "str_replace_editor", "str_replace_based_edit_tool",
    "read_file", "write_file", "create_file", "list_directory",
    "web_search", "web_fetch", "execute_code", "file_editor",
    "TodoRead", "TodoWrite", "Task", "mcp__",
}

# Pricing per 1M tokens (Claude models, approximate)
MODEL_PRICING = {
    "claude-opus-4":        {"input": 15.00,  "output": 75.00},
    "claude-sonnet-4":      {"input": 3.00,   "output": 15.00},
    "claude-haiku-4":       {"input": 0.80,   "output": 4.00},
    "claude-opus-4-5":      {"input": 15.00,  "output": 75.00},
    "claude-sonnet-4-5":    {"input": 3.00,   "output": 15.00},
    "claude-haiku-4-5":     {"input": 0.80,   "output": 4.00},
    "claude-3-5-sonnet":    {"input": 3.00,   "output": 15.00},
    "claude-3-5-haiku":     {"input": 0.80,   "output": 4.00},
    "claude-3-opus":        {"input": 15.00,  "output": 75.00},
    "default":              {"input": 3.00,   "output": 15.00},
}

CSV_COLUMNS = [
    "timestamp",            # ISO 8601
    "session_id",           # UUID per mitmproxy launch
    "turn_id",              # UUID per request/response pair
    "turn_number",          # Sequential int
    "destination_host",     # e.g. api.anthropic.com
    "destination_service",  # e.g. anthropic_api
    "endpoint_path",        # e.g. /v1/messages
    "http_method",          # GET/POST
    "http_status",          # 200, 429, etc.
    "model",                # claude-sonnet-4-5 etc.
    "stream",               # true/false
    "input_tokens",         # from usage block
    "output_tokens",        # from usage block
    "cache_read_tokens",    # cache hits
    "cache_write_tokens",   # cache writes
    "estimated_cost_usd",   # computed from token counts
    "request_size_bytes",   # raw request body size
    "response_size_bytes",  # raw response body size
    "latency_ms",           # time from request to full response
    "num_messages",         # messages[] length in request
    "system_prompt_chars",  # length of system prompt
    "last_user_msg_preview",# first 300 chars of last user message
    "assistant_msg_preview",# first 300 chars of assistant response
    "tool_calls",           # JSON array of tool names invoked
    "tool_call_count",      # int
    "bash_commands",        # JSON array of bash commands run
    "files_read",           # JSON array of file paths read
    "files_written",        # JSON array of file paths written
    "urls_fetched",         # JSON array of URLs fetched by agent
    "sensitive_patterns",   # comma-separated pattern names detected
    "sensitive_pattern_count", # int
    "content_types_sent",   # text/image/tool_result etc
    "stop_reason",          # end_turn / tool_use / max_tokens
    "request_id",           # x-request-id header from Anthropic
    "raw_request_hash",     # sha256 of request body (for dedup)
]


# ─────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def scan_sensitive(text: str) -> List[str]:
    """Return list of sensitive pattern names found in text."""
    found = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, text):
            found.append(name)
    return found


def extract_file_paths(text: str) -> List[str]:
    """Extract file paths mentioned in text."""
    paths = re.findall(r'(?:^|[\s\'"])(/(?:[\w\-./]+))', text)
    return list(set(p for p in paths if len(p) > 3 and '.' in p.split('/')[-1]))


def extract_urls(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from text."""
    return re.findall(r'https?://[^\s\'"<>]+', text)


def estimate_cost(model: str, input_tokens: int, output_tokens: int,
                  cache_read: int = 0, cache_write: int = 0) -> float:
    """Estimate USD cost from token counts."""
    pricing = MODEL_PRICING["default"]
    # Match longest key first to avoid e.g. "claude-opus-4" matching before "claude-opus-4-5"
    for key in sorted(MODEL_PRICING.keys(), key=len, reverse=True):
        if key != "default" and key in model:
            pricing = MODEL_PRICING[key]
            break
    cost = (input_tokens / 1_000_000 * pricing["input"] +
            output_tokens / 1_000_000 * pricing["output"] +
            cache_read / 1_000_000 * pricing["input"] * 0.1 +
            cache_write / 1_000_000 * pricing["input"] * 1.25)
    return round(cost, 6)


def get_csv_path() -> Path:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return SESSION_DIR / f"claude_watch_{ts}.csv"


# ─────────────────────────────────────────────
# MITMPROXY ADDON (loaded by mitmdump -s)
# ─────────────────────────────────────────────

try:
    from mitmproxy import http as mhttp
    from mitmproxy import ctx

    class ClaudeWatchAddon:
        """
        Mitmproxy addon that intercepts AI agent traffic and writes CSV.
        """

        def __init__(self):
            self.session_id = str(uuid.uuid4())[:8]
            self.turn_counter = 0
            self.pending: Dict[int, dict] = {}  # flow.id -> metadata
            self.csv_path = get_csv_path()
            self._init_csv()
            self._print_banner()

        def _init_csv(self):
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()
            print(f"\n📄 Writing to: {self.csv_path}\n")

        def _print_banner(self):
            print("=" * 60)
            print("  🔭 CLAUDE WATCH — AI Agent Observatory")
            print(f"  Session: {self.session_id}")
            print(f"  Output:  {self.csv_path}")
            print("=" * 60)
            print("  Intercepting: api.anthropic.com + telemetry hosts")
            print("  Press Ctrl+C to stop and analyze\n")

        def _get_service(self, host: str) -> str:
            for h, svc in AI_HOSTS.items():
                if h in host:
                    return svc
            return "unknown"

        def request(self, flow: mhttp.HTTPFlow):
            host = flow.request.host
            if not any(h in host for h in AI_HOSTS):
                return

            self.turn_counter += 1
            turn_id = str(uuid.uuid4())[:8]

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id,
                "turn_id": turn_id,
                "turn_number": self.turn_counter,
                "destination_host": host,
                "destination_service": self._get_service(host),
                "endpoint_path": flow.request.path,
                "http_method": flow.request.method,
                "http_status": "",
                "model": "",
                "stream": "",
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "estimated_cost_usd": 0.0,
                "request_size_bytes": len(flow.request.content or b""),
                "response_size_bytes": 0,
                "latency_ms": 0,
                "num_messages": 0,
                "system_prompt_chars": 0,
                "last_user_msg_preview": "",
                "assistant_msg_preview": "",
                "tool_calls": "[]",
                "tool_call_count": 0,
                "bash_commands": "[]",
                "files_read": "[]",
                "files_written": "[]",
                "urls_fetched": "[]",
                "sensitive_patterns": "",
                "sensitive_pattern_count": 0,
                "content_types_sent": "",
                "stop_reason": "",
                "request_id": "",
                "raw_request_hash": "",
            }
            record["_start_time"] = time.time()

            # Parse Anthropic API request body
            if "api.anthropic.com" in host and flow.request.method == "POST":
                try:
                    body = json.loads(flow.request.content)
                    record = self._parse_request_body(body, record)
                    record["raw_request_hash"] = hashlib.sha256(
                        flow.request.content).hexdigest()[:12]
                except Exception:
                    pass

            self.pending[flow.id] = record

        def response(self, flow: mhttp.HTTPFlow):
            if flow.id not in self.pending:
                return

            record = self.pending.pop(flow.id)
            start = record.pop("_start_time", time.time())
            record["latency_ms"] = round((time.time() - start) * 1000)
            record["http_status"] = flow.response.status_code
            record["response_size_bytes"] = len(flow.response.content or b"")
            record["request_id"] = flow.response.headers.get("x-request-id", "")

            # Parse Anthropic API response
            if "api.anthropic.com" in flow.request.host:
                try:
                    # Handle streamed responses (SSE)
                    raw = flow.response.content.decode("utf-8", errors="replace")
                    if raw.startswith("data:"):
                        record = self._parse_sse_response(raw, record)
                    else:
                        body = json.loads(raw)
                        record = self._parse_response_body(body, record)
                except Exception:
                    pass

            self._write_row(record)
            self._print_turn(record)

        def _parse_request_body(self, body: dict, record: dict) -> dict:
            record["model"] = body.get("model", "")
            record["stream"] = str(body.get("stream", False)).lower()

            messages = body.get("messages", [])
            record["num_messages"] = len(messages)

            # System prompt length
            system = body.get("system", "")
            if isinstance(system, list):
                system = " ".join(
                    b.get("text", "") for b in system if isinstance(b, dict))
            record["system_prompt_chars"] = len(system)

            # Scan full request for sensitive patterns
            full_text = json.dumps(body)
            found = scan_sensitive(full_text)
            record["sensitive_patterns"] = ",".join(found)
            record["sensitive_pattern_count"] = len(found)

            # Analyze each message
            tool_calls, bash_cmds, files_read, files_written, urls = [], [], [], [], []
            content_types = set()
            last_user_text = ""

            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")

                if isinstance(content, str):
                    content_types.add("text")
                    if role == "user":
                        last_user_text = content
                elif isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type", "")
                        content_types.add(btype)

                        if btype == "tool_use":
                            name = block.get("name", "")
                            tool_calls.append(name)
                            inp = block.get("input", {})
                            inp_str = json.dumps(inp)

                            # Bash command extraction
                            if name == "bash":
                                cmd = inp.get("command", inp.get("cmd", ""))
                                if cmd:
                                    bash_cmds.append(cmd[:200])

                            # File path extraction
                            if name in ("str_replace_editor", "write_file",
                                        "create_file", "file_editor"):
                                fp = inp.get("path", inp.get("file_path", ""))
                                if fp:
                                    files_written.append(fp)
                            elif name in ("read_file", "view"):
                                fp = inp.get("path", inp.get("file_path", ""))
                                if fp:
                                    files_read.append(fp)

                            # URL extraction
                            urls.extend(extract_urls(inp_str))

                            # File paths from bash commands
                            if name == "bash":
                                cmd = inp.get("command", "")
                                files_read.extend(extract_file_paths(cmd))

                        elif btype == "tool_result":
                            result_content = block.get("content", "")
                            if isinstance(result_content, list):
                                result_content = json.dumps(result_content)
                            urls.extend(extract_urls(str(result_content)))

                        elif btype == "text":
                            if role == "user":
                                last_user_text = block.get("text", "")

            record["last_user_msg_preview"] = last_user_text[:300].replace(
                "\n", " ").replace(",", ";")
            record["tool_calls"] = json.dumps(list(set(tool_calls)))
            record["tool_call_count"] = len(tool_calls)
            record["bash_commands"] = json.dumps(bash_cmds[:10])
            record["files_read"] = json.dumps(list(set(files_read))[:20])
            record["files_written"] = json.dumps(list(set(files_written))[:20])
            record["urls_fetched"] = json.dumps(list(set(urls))[:20])
            record["content_types_sent"] = ",".join(sorted(content_types))

            return record

        def _parse_response_body(self, body: dict, record: dict) -> dict:
            usage = body.get("usage", {})
            record["input_tokens"] = usage.get("input_tokens", 0)
            record["output_tokens"] = usage.get("output_tokens", 0)
            record["cache_read_tokens"] = usage.get("cache_read_input_tokens", 0)
            record["cache_write_tokens"] = usage.get("cache_creation_input_tokens", 0)
            record["stop_reason"] = body.get("stop_reason", "")
            record["model"] = record["model"] or body.get("model", "")

            record["estimated_cost_usd"] = estimate_cost(
                record["model"],
                record["input_tokens"], record["output_tokens"],
                record["cache_read_tokens"], record["cache_write_tokens"])

            # Extract assistant text preview
            content = body.get("content", [])
            text_parts, tool_calls = [], []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        tool_calls.append(block.get("name", ""))

            record["assistant_msg_preview"] = " ".join(text_parts)[:300].replace(
                "\n", " ").replace(",", ";")

            if tool_calls:
                existing = json.loads(record.get("tool_calls", "[]"))
                record["tool_calls"] = json.dumps(
                    list(set(existing + tool_calls)))
                record["tool_call_count"] = len(
                    json.loads(record["tool_calls"]))

            return record

        def _parse_sse_response(self, raw: str, record: dict) -> dict:
            """Parse Server-Sent Events streaming response."""
            input_tok = output_tok = cache_read = cache_write = 0
            text_chunks, tool_calls = [], []
            stop_reason = ""

            for line in raw.split("\n"):
                if not line.startswith("data: "):
                    continue
                data_str = line[6:].strip()
                if data_str in ("[DONE]", ""):
                    continue
                try:
                    event = json.loads(data_str)
                    etype = event.get("type", "")

                    if etype == "message_start":
                        msg = event.get("message", {})
                        usage = msg.get("usage", {})
                        input_tok += usage.get("input_tokens", 0)
                        cache_read += usage.get("cache_read_input_tokens", 0)
                        cache_write += usage.get("cache_creation_input_tokens", 0)
                        record["model"] = record["model"] or msg.get("model", "")

                    elif etype == "content_block_start":
                        block = event.get("content_block", {})
                        if block.get("type") == "tool_use":
                            tool_calls.append(block.get("name", ""))

                    elif etype == "content_block_delta":
                        delta = event.get("delta", {})
                        if delta.get("type") == "text_delta":
                            text_chunks.append(delta.get("text", ""))

                    elif etype == "message_delta":
                        usage = event.get("usage", {})
                        output_tok += usage.get("output_tokens", 0)
                        stop_reason = event.get("delta", {}).get(
                            "stop_reason", "")

                    elif etype == "message_stop":
                        pass

                except json.JSONDecodeError:
                    continue

            record["input_tokens"] = input_tok
            record["output_tokens"] = output_tok
            record["cache_read_tokens"] = cache_read
            record["cache_write_tokens"] = cache_write
            record["stop_reason"] = stop_reason
            record["stream"] = "true"

            record["estimated_cost_usd"] = estimate_cost(
                record["model"], input_tok, output_tok, cache_read, cache_write)

            if text_chunks:
                record["assistant_msg_preview"] = "".join(
                    text_chunks)[:300].replace("\n", " ").replace(",", ";")

            if tool_calls:
                existing = json.loads(record.get("tool_calls", "[]"))
                record["tool_calls"] = json.dumps(
                    list(set(existing + tool_calls)))
                record["tool_call_count"] = len(
                    json.loads(record["tool_calls"]))

            return record

        def _write_row(self, record: dict):
            # Remove any internal keys
            row = {k: record.get(k, "") for k in CSV_COLUMNS}
            with open(self.csv_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writerow(row)

        def _print_turn(self, record: dict):
            svc = record.get("destination_service", "")
            status = record.get("http_status", "")
            model = record.get("model", "")
            in_tok = record.get("input_tokens", 0)
            out_tok = record.get("output_tokens", 0)
            cost = record.get("estimated_cost_usd", 0)
            latency = record.get("latency_ms", 0)
            tools = json.loads(record.get("tool_calls", "[]"))
            sensitive = record.get("sensitive_patterns", "")
            turn = record.get("turn_number", 0)

            icon = "🔴" if sensitive else ("🛠 " if tools else "💬")
            # Extract a readable short model name (e.g. "opus-4", "sonnet-4-5")
            if model:
                m = re.search(r"(opus|sonnet|haiku|gpt-\d|gemini)[^\s]*", model)
                model_short = m.group(0)[:12] if m else model[:12]
            else:
                model_short = "?"

            print(f"  {icon} [{turn:03d}] {svc:<22} {status}  "
                  f"{model_short:<8}  "
                  f"↑{in_tok:>5}t ↓{out_tok:>5}t  "
                  f"${cost:.4f}  {latency:>5}ms", end="")

            if tools:
                print(f"  tools={tools[:3]}", end="")
            if sensitive:
                print(f"  ⚠️  SENSITIVE: {sensitive}", end="")
            print()

    # Only instantiate addon when loaded by mitmdump (not CLI mode)
    if not any(x in sys.argv for x in
               ["--setup", "--start", "--analyze", "--plot", "--dashboard",
                "--scan", "--generate-test", "--help", "-h"]):
        addons = [ClaudeWatchAddon()]

except ImportError:
    pass  # mitmproxy not installed — only CLI mode available


# ─────────────────────────────────────────────
# SETUP & LAUNCH CLI
# ─────────────────────────────────────────────

def run_setup():
    """Install mitmproxy and trust its CA certificate."""
    print("\n🔧 Claude Watch Setup")
    print("=" * 50)

    # Install dependencies
    packages = ["mitmproxy", "matplotlib"]
    for idx, pkg in enumerate(packages, 1):
        print(f"\n[{idx}/4] Installing {pkg}...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade",
             pkg, "--break-system-packages"],
            capture_output=True, text=True)
        if result.returncode != 0:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                capture_output=True, text=True)

        if result.returncode == 0:
            print(f"   ✅ {pkg} installed")
        else:
            print(f"   ❌ {pkg} install failed. Try: pip3 install {pkg}")
            print(result.stderr[:200])

    # Generate mitmproxy cert by running it briefly
    print("\n[3/4] Generating mitmproxy CA certificate...")
    cert_dir = Path.home() / ".mitmproxy"
    if not (cert_dir / "mitmproxy-ca-cert.pem").exists():
        proc = subprocess.Popen(
            ["mitmdump", "--listen-port", "18080", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        proc.terminate()
        proc.wait()

    cert_path = cert_dir / "mitmproxy-ca-cert.pem"
    if cert_path.exists():
        print(f"   ✅ Certificate at: {cert_path}")
    else:
        print("   ⚠️  Certificate not found. It will be created on first run.")

    # Trust cert on macOS
    print("\n[4/4] Trusting CA certificate (requires sudo)...")
    import platform
    if platform.system() == "Darwin":
        if cert_path.exists():
            result = subprocess.run([
                "sudo", "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                str(cert_path)
            ], capture_output=True, text=True)
            if result.returncode == 0:
                print("   ✅ Certificate trusted in macOS System Keychain")
            else:
                print(f"   ⚠️  Auto-trust failed. Manual steps:")
                print(f"       sudo security add-trusted-cert -d -r trustRoot \\")
                print(f"         -k /Library/Keychains/System.keychain \\")
                print(f"         {cert_path}")
        else:
            print(f"   ⚠️  Run `mitmdump --listen-port 18080` briefly first to generate cert,")
            print(f"       then re-run setup.")
    elif platform.system() == "Linux":
        print("   📋 Linux: Copy cert to /usr/local/share/ca-certificates/ and run update-ca-certificates")
    else:
        print("   📋 Windows: Import cert to Trusted Root CAs via certmgr.msc")

    # Print launch instructions
    print("\n" + "=" * 50)
    print("✅ Setup complete!\n")
    print("📡 TO START MONITORING:")
    print(f"   claude-watch --start\n")
    print("📁 Captures saved to:")
    print(f"   {SESSION_DIR}\n")
    print("📊 TO ANALYZE / VISUALIZE:")
    print(f"   claude-watch --analyze        # terminal summary")
    print(f"   claude-watch --plot            # matplotlib PNG dashboard")
    print(f"   claude-watch --dashboard       # live web dashboard")
    print(f"   claude-watch --scan            # detect AI processes")
    print(f"   claude-watch --generate-test   # create test data\n")


def run_start():
    """Launch mitmproxy with the claude_watch addon."""
    script_path = Path(__file__).resolve()
    SESSION_DIR.mkdir(parents=True, exist_ok=True)

    # Write env file for easy sourcing
    env_file = OUTPUT_DIR / "proxy_env.sh"
    env_file.write_text(f"""#!/bin/bash
# Source this file before running Claude Code:
# source ~/claude_watch_output/proxy_env.sh

export HTTPS_PROXY=http://127.0.0.1:{PROXY_PORT}
export HTTP_PROXY=http://127.0.0.1:{PROXY_PORT}
export ALL_PROXY=http://127.0.0.1:{PROXY_PORT}
export NODE_EXTRA_CA_CERTS="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export SSL_CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export REQUESTS_CA_BUNDLE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
# NODE_TLS_REJECT_UNAUTHORIZED=0  # only if cert trust fails

echo "🔭 Claude Watch proxy active on port {PROXY_PORT}"
echo "   Run: claude"
""")

    print("\n🔭 Claude Watch")
    print("=" * 50)
    print(f"\n📡 Starting proxy on port {PROXY_PORT}...")
    print(f"\n🖥️  In ANOTHER terminal, run:")
    print(f"   source {env_file}")
    print(f"   claude\n")
    print("=" * 50 + "\n")

    # Launch mitmdump with this script as addon
    cmd = [
        "mitmdump",
        "--listen-port", str(PROXY_PORT),
        "--ssl-insecure",
        "-s", str(script_path),
        "--set", "flow_detail=0",
        "--quiet",
    ]

    try:
        os.execvp("mitmdump", cmd)  # replace this process
    except FileNotFoundError:
        print("❌ mitmdump not found. Run: claude-watch --setup")
        sys.exit(1)


def run_analyze(sessions_dir: Optional[str] = None):
    """Quick terminal analysis of latest CSV session."""
    search_dir = Path(sessions_dir) if sessions_dir else SESSION_DIR

    csvs = sorted(search_dir.glob("claude_watch_*.csv"), key=os.path.getmtime)
    if not csvs:
        print(f"No CSV files found in {search_dir}")
        return

    latest = csvs[-1]
    print(f"\n📊 Analyzing: {latest.name}\n")

    rows = []
    with open(latest, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print("Empty file.")
        return

    total_turns = len(rows)
    api_rows = [r for r in rows if r.get("destination_service") == "anthropic_api"]
    total_cost = sum(float(r.get("estimated_cost_usd", 0)) for r in api_rows)
    total_in_tok = sum(int(r.get("input_tokens", 0)) for r in api_rows)
    total_out_tok = sum(int(r.get("output_tokens", 0)) for r in api_rows)
    total_req_bytes = sum(int(r.get("request_size_bytes", 0)) for r in rows)
    total_res_bytes = sum(int(r.get("response_size_bytes", 0)) for r in rows)
    sensitive_rows = [r for r in rows if r.get("sensitive_patterns")]

    # Tool call frequency
    tool_freq = defaultdict(int)
    for r in api_rows:
        tools = json.loads(r.get("tool_calls", "[]"))
        for t in tools:
            tool_freq[t] += 1

    # Destination breakdown
    dest_freq = defaultdict(int)
    for r in rows:
        dest_freq[r.get("destination_service", "unknown")] += 1

    print("─" * 55)
    print(f"  Total requests intercepted : {total_turns}")
    print(f"  Anthropic API calls        : {len(api_rows)}")
    print(f"  Input tokens               : {total_in_tok:,}")
    print(f"  Output tokens              : {total_out_tok:,}")
    print(f"  Estimated cost             : ${total_cost:.4f}")
    print(f"  Total data sent            : {total_req_bytes/1024:.1f} KB")
    print(f"  Total data received        : {total_res_bytes/1024:.1f} KB")
    print(f"  ⚠️  Sensitive pattern hits  : {len(sensitive_rows)}")
    print("─" * 55)

    print("\n  📡 Destinations:")
    for svc, count in sorted(dest_freq.items(), key=lambda x: -x[1]):
        print(f"     {svc:<30} {count} requests")

    if tool_freq:
        print("\n  🛠  Tool calls:")
        for tool, count in sorted(tool_freq.items(), key=lambda x: -x[1])[:10]:
            print(f"     {tool:<30} {count}x")

    if sensitive_rows:
        print(f"\n  🔴 Sensitive data detected in {len(sensitive_rows)} turns:")
        for r in sensitive_rows[:5]:
            print(f"     Turn {r['turn_number']}: {r['sensitive_patterns']}")

    print(f"\n  CSV: {latest}\n")


# ─────────────────────────────────────────────
# PLOTTING (--plot)
# ─────────────────────────────────────────────

def _load_latest_csv(sessions_dir: Optional[str] = None) -> Tuple[Optional[Path], List[dict]]:
    """Load the latest CSV file and return (path, rows)."""
    search_dir = Path(sessions_dir) if sessions_dir else SESSION_DIR
    csvs = sorted(search_dir.glob("claude_watch_*.csv"), key=os.path.getmtime)
    if not csvs:
        print(f"No CSV files found in {search_dir}")
        return None, []
    latest = csvs[-1]
    with open(latest, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return latest, rows


def run_plot(sessions_dir: Optional[str] = None):
    """Generate comprehensive matplotlib dashboard from captured CSV data."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from matplotlib.gridspec import GridSpec
    except ImportError:
        print("matplotlib not installed. Run: pip3 install matplotlib")
        print("Or run: claude-watch --setup")
        return

    latest, rows = _load_latest_csv(sessions_dir)
    if not rows:
        print("No data to plot.")
        return

    print(f"\nPlotting {len(rows)} records from: {latest.name}\n")

    # ── Parse data ──
    timestamps = []
    for r in rows:
        ts = r.get("timestamp", "")
        try:
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            timestamps.append(datetime.fromisoformat(ts))
        except (ValueError, TypeError):
            timestamps.append(datetime.now(timezone.utc))

    input_tokens  = [int(r.get("input_tokens", 0))  for r in rows]
    output_tokens = [int(r.get("output_tokens", 0))  for r in rows]
    costs         = [float(r.get("estimated_cost_usd", 0)) for r in rows]
    latencies     = [int(r.get("latency_ms", 0))     for r in rows]
    req_sizes     = [int(r.get("request_size_bytes", 0))  for r in rows]
    res_sizes     = [int(r.get("response_size_bytes", 0)) for r in rows]
    cumulative_cost = []
    running = 0.0
    for c in costs:
        running += c
        cumulative_cost.append(running)

    services = [r.get("destination_service", "unknown") for r in rows]
    models   = [r.get("model", "unknown") or "unknown" for r in rows]

    # Tool frequency
    tool_freq = defaultdict(int)
    for r in rows:
        try:
            tools = json.loads(r.get("tool_calls", "[]"))
            for t in tools:
                if t:
                    tool_freq[t] += 1
        except json.JSONDecodeError:
            pass

    # Service frequency
    svc_freq = defaultdict(int)
    for s in services:
        svc_freq[s] += 1

    # Model frequency
    model_freq = defaultdict(int)
    for m in models:
        model_freq[m] += 1

    # Sensitive pattern timeline
    sensitive_turns = []
    sensitive_labels = []
    for i, r in enumerate(rows):
        sp = r.get("sensitive_patterns", "")
        if sp:
            sensitive_turns.append(i)
            sensitive_labels.append(sp)

    # ── Create figure ──
    fig = plt.figure(figsize=(24, 18))
    fig.suptitle(f"Claude Watch — AI Agent Observatory\n{latest.name}",
                 fontsize=16, fontweight="bold", y=0.98)
    gs = GridSpec(4, 3, figure=fig, hspace=0.35, wspace=0.3)

    colors = {
        "input": "#4A90D9", "output": "#E8744F", "cost": "#50C878",
        "latency": "#9B59B6", "sent": "#E74C3C", "recv": "#3498DB",
        "sensitive": "#FF0000", "bg": "#1a1a2e", "grid": "#333366",
    }

    # 1) Token usage over time (stacked area)
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.fill_between(range(len(rows)), input_tokens, alpha=0.7,
                     label="Input", color=colors["input"])
    ax1.fill_between(range(len(rows)), output_tokens, alpha=0.7,
                     label="Output", color=colors["output"])
    ax1.set_title("Token Usage Per Turn", fontweight="bold")
    ax1.set_xlabel("Turn #")
    ax1.set_ylabel("Tokens")
    ax1.legend(loc="upper left", fontsize=8)
    ax1.grid(True, alpha=0.3)

    # 2) Cumulative cost
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(range(len(rows)), cumulative_cost, color=colors["cost"],
             linewidth=2, label="Cumulative Cost")
    ax2.fill_between(range(len(rows)), cumulative_cost, alpha=0.2,
                     color=colors["cost"])
    ax2.set_title("Cumulative Cost (USD)", fontweight="bold")
    ax2.set_xlabel("Turn #")
    ax2.set_ylabel("USD")
    ax2.legend(fontsize=8)
    ax2.grid(True, alpha=0.3)
    # Annotate final cost
    if cumulative_cost:
        ax2.annotate(f"${cumulative_cost[-1]:.4f}",
                     xy=(len(rows)-1, cumulative_cost[-1]),
                     fontsize=10, fontweight="bold", color=colors["cost"],
                     ha="right")

    # 3) Service breakdown (pie)
    ax3 = fig.add_subplot(gs[0, 2])
    if svc_freq:
        labels = list(svc_freq.keys())
        sizes = list(svc_freq.values())
        wedges, texts, autotexts = ax3.pie(
            sizes, labels=None, autopct='%1.1f%%', startangle=90,
            textprops={'fontsize': 7})
        ax3.legend(labels, loc="center left", bbox_to_anchor=(0.85, 0.5),
                   fontsize=6)
    ax3.set_title("Destination Services", fontweight="bold")

    # 4) Latency distribution (histogram)
    ax4 = fig.add_subplot(gs[1, 0])
    nonzero_lat = [l for l in latencies if l > 0]
    if nonzero_lat:
        ax4.hist(nonzero_lat, bins=min(30, len(nonzero_lat)),
                 color=colors["latency"], alpha=0.8, edgecolor="white")
        median_lat = sorted(nonzero_lat)[len(nonzero_lat)//2]
        ax4.axvline(median_lat, color="red", linestyle="--", linewidth=1,
                    label=f"Median: {median_lat}ms")
        ax4.legend(fontsize=8)
    ax4.set_title("Latency Distribution (ms)", fontweight="bold")
    ax4.set_xlabel("Latency (ms)")
    ax4.set_ylabel("Count")
    ax4.grid(True, alpha=0.3)

    # 5) Tool call frequency (horizontal bar)
    ax5 = fig.add_subplot(gs[1, 1])
    if tool_freq:
        sorted_tools = sorted(tool_freq.items(), key=lambda x: x[1], reverse=True)[:12]
        tool_names = [t[0] for t in sorted_tools]
        tool_counts = [t[1] for t in sorted_tools]
        y_pos = range(len(tool_names))
        ax5.barh(y_pos, tool_counts, color=colors["input"], alpha=0.8)
        ax5.set_yticks(y_pos)
        ax5.set_yticklabels(tool_names, fontsize=7)
        ax5.invert_yaxis()
    ax5.set_title("Tool Call Frequency (Top 12)", fontweight="bold")
    ax5.set_xlabel("Count")
    ax5.grid(True, alpha=0.3, axis="x")

    # 6) Model usage (bar)
    ax6 = fig.add_subplot(gs[1, 2])
    if model_freq:
        sorted_models = sorted(model_freq.items(), key=lambda x: x[1], reverse=True)[:8]
        m_names = [m[0][:25] for m in sorted_models]
        m_counts = [m[1] for m in sorted_models]
        bars = ax6.bar(range(len(m_names)), m_counts, color=colors["output"],
                       alpha=0.8)
        ax6.set_xticks(range(len(m_names)))
        ax6.set_xticklabels(m_names, rotation=30, ha="right", fontsize=7)
        for bar, count in zip(bars, m_counts):
            ax6.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.1,
                     str(count), ha='center', va='bottom', fontsize=8)
    ax6.set_title("Model Usage", fontweight="bold")
    ax6.set_ylabel("Requests")
    ax6.grid(True, alpha=0.3, axis="y")

    # 7) Data volume over time (dual axis)
    ax7 = fig.add_subplot(gs[2, 0:2])
    ax7.plot(range(len(rows)), [s/1024 for s in req_sizes],
             color=colors["sent"], alpha=0.8, label="Request (KB)", linewidth=1)
    ax7.plot(range(len(rows)), [s/1024 for s in res_sizes],
             color=colors["recv"], alpha=0.8, label="Response (KB)", linewidth=1)
    ax7.fill_between(range(len(rows)), [s/1024 for s in req_sizes],
                     alpha=0.15, color=colors["sent"])
    ax7.fill_between(range(len(rows)), [s/1024 for s in res_sizes],
                     alpha=0.15, color=colors["recv"])
    ax7.set_title("Data Volume Per Turn (KB)", fontweight="bold")
    ax7.set_xlabel("Turn #")
    ax7.set_ylabel("KB")
    ax7.legend(fontsize=8)
    ax7.grid(True, alpha=0.3)
    total_sent = sum(req_sizes)/1024/1024
    total_recv = sum(res_sizes)/1024/1024
    ax7.annotate(f"Total: {total_sent:.1f}MB sent, {total_recv:.1f}MB recv",
                 xy=(0.02, 0.95), xycoords="axes fraction", fontsize=8,
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow"))

    # 8) Sensitive data alert timeline
    ax8 = fig.add_subplot(gs[2, 2])
    if sensitive_turns:
        ax8.scatter(sensitive_turns, [1]*len(sensitive_turns),
                    color=colors["sensitive"], s=100, marker="X",
                    zorder=5, label=f"{len(sensitive_turns)} alerts")
        for i, (turn, label) in enumerate(zip(sensitive_turns, sensitive_labels)):
            ax8.annotate(label, (turn, 1), textcoords="offset points",
                         xytext=(0, 10 + (i % 3) * 12), fontsize=6,
                         color="red", ha="center", rotation=30)
        ax8.legend(fontsize=8)
    else:
        ax8.text(0.5, 0.5, "No sensitive data detected",
                 transform=ax8.transAxes, ha="center", va="center",
                 fontsize=12, color="green", fontweight="bold")
    ax8.set_title("Sensitive Data Alerts", fontweight="bold")
    ax8.set_xlabel("Turn #")
    ax8.set_yticks([])
    ax8.grid(True, alpha=0.3, axis="x")

    # 9) Cost per turn (bar) — bottom left
    ax9 = fig.add_subplot(gs[3, 0])
    ax9.bar(range(len(rows)), costs, color=colors["cost"], alpha=0.8, width=1.0)
    ax9.set_title("Cost Per Turn (USD)", fontweight="bold")
    ax9.set_xlabel("Turn #")
    ax9.set_ylabel("USD")
    ax9.grid(True, alpha=0.3)

    # 10) Latency per turn (scatter, colored by service)
    ax10 = fig.add_subplot(gs[3, 1])
    unique_svcs = list(set(services))
    svc_colors = plt.cm.tab10(range(len(unique_svcs)))
    for idx, svc in enumerate(unique_svcs):
        svc_indices = [i for i, s in enumerate(services) if s == svc]
        svc_lats = [latencies[i] for i in svc_indices]
        ax10.scatter(svc_indices, svc_lats, s=15, alpha=0.7,
                     color=svc_colors[idx], label=svc[:20])
    ax10.set_title("Latency by Service (ms)", fontweight="bold")
    ax10.set_xlabel("Turn #")
    ax10.set_ylabel("ms")
    ax10.legend(fontsize=5, loc="upper left", ncol=2)
    ax10.grid(True, alpha=0.3)

    # 11) Summary stats text — bottom right
    ax11 = fig.add_subplot(gs[3, 2])
    ax11.axis("off")
    total_turns = len(rows)
    api_count = sum(1 for s in services if "api" in s)
    tel_count = sum(1 for s in services if "telemetry" in s or "reporting" in s)
    total_cost_val = sum(costs)
    total_in = sum(input_tokens)
    total_out = sum(output_tokens)
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    summary = (
        f"SUMMARY\n"
        f"{'─'*35}\n"
        f"Total requests:     {total_turns}\n"
        f"API calls:          {api_count}\n"
        f"Telemetry calls:    {tel_count}\n"
        f"{'─'*35}\n"
        f"Input tokens:       {total_in:,}\n"
        f"Output tokens:      {total_out:,}\n"
        f"Total cost:         ${total_cost_val:.4f}\n"
        f"{'─'*35}\n"
        f"Avg latency:        {avg_lat:.0f}ms\n"
        f"Data sent:          {total_sent:.2f} MB\n"
        f"Data received:      {total_recv:.2f} MB\n"
        f"{'─'*35}\n"
        f"Sensitive alerts:   {len(sensitive_turns)}\n"
        f"Unique tools:       {len(tool_freq)}\n"
        f"Unique services:    {len(svc_freq)}\n"
        f"Unique models:      {len(model_freq)}\n"
    )
    ax11.text(0.05, 0.95, summary, transform=ax11.transAxes,
              fontsize=10, verticalalignment="top", fontfamily="monospace",
              bbox=dict(boxstyle="round,pad=0.5", facecolor="#f0f0f0"))

    # Save
    PLOT_DIR = OUTPUT_DIR / "plots"
    PLOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    plot_path = PLOT_DIR / f"dashboard_{ts}.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight",
                facecolor="white", edgecolor="none")
    plt.close(fig)

    print(f"Dashboard saved to: {plot_path}")
    print(f"Opening...")

    # Auto-open on macOS
    import platform
    if platform.system() == "Darwin":
        subprocess.run(["open", str(plot_path)], check=False)
    elif platform.system() == "Linux":
        subprocess.run(["xdg-open", str(plot_path)], check=False)


# ─────────────────────────────────────────────
# LIVE WEB DASHBOARD (--dashboard)
# ─────────────────────────────────────────────

DASHBOARD_PORT = 9081

def run_dashboard(sessions_dir: Optional[str] = None):
    """Launch a live web dashboard to explore captured CSV data."""
    import http.server
    import urllib.parse
    import threading

    latest, rows = _load_latest_csv(sessions_dir)
    if not rows:
        print("No data for dashboard. Run monitoring first or provide a CSV.")
        return

    class DashboardHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # suppress default logging

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/data":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                # Reload CSV on each request for live updates
                _, fresh_rows = _load_latest_csv(sessions_dir)
                self.wfile.write(json.dumps(fresh_rows or rows).encode())
            elif parsed.path == "/" or parsed.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(_dashboard_html().encode())
            else:
                self.send_response(404)
                self.end_headers()

    print(f"\nClaude Watch Dashboard")
    print(f"=" * 50)
    print(f"CSV: {latest.name} ({len(rows)} rows)")
    print(f"Open: http://localhost:{DASHBOARD_PORT}")
    print(f"Press Ctrl+C to stop\n")

    import platform
    if platform.system() == "Darwin":
        threading.Timer(1.5, lambda: subprocess.run(
            ["open", f"http://localhost:{DASHBOARD_PORT}"], check=False)).start()

    server = http.server.HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()


def _dashboard_html() -> str:
    """Return a self-contained HTML/JS dashboard page."""
    try:
        import importlib.resources
        return importlib.resources.files("claude_monitoring").joinpath("watch_dashboard.html").read_text()
    except Exception:
        return "<html><body><h1>Dashboard HTML not found</h1></body></html>"


# ─────────────────────────────────────────────
# PROCESS SCANNER (--scan)
# ─────────────────────────────────────────────

AI_PROCESS_PATTERNS = {
    "claude":       "Claude Code CLI",
    "anthropic":    "Anthropic SDK",
    "openai":       "OpenAI SDK/CLI",
    "copilot":      "GitHub Copilot",
    "ollama":       "Ollama (local LLM)",
    "lmstudio":     "LM Studio",
    "lm-studio":    "LM Studio",
    "llamafile":    "Llamafile",
    "llama.cpp":    "llama.cpp",
    "mlx_lm":       "MLX LM (Apple Silicon)",
    "vllm":         "vLLM Server",
    "text-generation": "TGI Server",
    "chatgpt":      "ChatGPT Desktop",
    "cursor":       "Cursor IDE (AI)",
    "windsurf":     "Windsurf IDE (AI)",
    "aider":        "Aider (AI pair prog)",
    "continue":     "Continue.dev",
    "cody":         "Sourcegraph Cody",
    "tabby":        "TabbyML",
    "codium":       "Codium AI",
}


def run_scan():
    """Scan for running AI-related processes on this machine."""
    print("\nAI Agent Process Scanner")
    print("=" * 55)

    # Get all processes
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]  # skip header
    except Exception as e:
        print(f"Failed to list processes: {e}")
        return

    found = []
    for line in lines:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        pid = parts[1]
        cpu = parts[2]
        mem = parts[3]
        cmd = parts[10]

        for pattern, name in AI_PROCESS_PATTERNS.items():
            if pattern.lower() in cmd.lower():
                found.append({
                    "pid": pid, "cpu": cpu, "mem": mem,
                    "name": name, "pattern": pattern,
                    "cmd": cmd[:120]
                })
                break

    if found:
        print(f"\nFound {len(found)} AI-related process(es):\n")
        for p in found:
            print(f"  PID {p['pid']:>7}  CPU {p['cpu']:>5}%  MEM {p['mem']:>5}%  {p['name']}")
            print(f"           cmd: {p['cmd']}")
            print()
    else:
        print("\nNo AI agent processes detected.")

    # Check for AI-related network connections
    print("─" * 55)
    print("Checking network connections to AI services...\n")
    try:
        result = subprocess.run(["lsof", "-i", "-n", "-P"],
                                capture_output=True, text=True)
        ai_connections = []
        for line in result.stdout.strip().split("\n"):
            for host in AI_HOSTS:
                if host in line.lower():
                    ai_connections.append(line.strip())
                    break

        if ai_connections:
            print(f"  Found {len(ai_connections)} active AI service connections:\n")
            for conn in ai_connections[:20]:
                print(f"  {conn[:100]}")
        else:
            print("  No active connections to known AI services.")
    except Exception:
        print("  Could not check network connections (lsof not available)")

    # Check listening ports for local AI services
    print(f"\n{'─' * 55}")
    print("Checking local AI service ports...\n")
    local_ports = {
        11434: "Ollama",
        1234: "LM Studio",
        8080: "Generic proxy / llama.cpp",
        5000: "TGI / generic ML server",
        3000: "Generic dev server",
    }
    for port, name in local_ports.items():
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            if result == 0:
                print(f"  Port {port}: ACTIVE  ({name})")
            else:
                print(f"  Port {port}: closed  ({name})")
        except Exception:
            print(f"  Port {port}: error   ({name})")

    print()


# ─────────────────────────────────────────────
# TEST DATA GENERATOR (--generate-test)
# ─────────────────────────────────────────────

def run_generate_test():
    """Generate a synthetic test CSV with realistic data."""
    import random

    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = SESSION_DIR / "claude_watch_test.csv"

    session_id = str(uuid.uuid4())[:8]
    base_time = datetime.now(timezone.utc)
    prompts = [
        "Fix the authentication bug in login.py",
        "Add unit tests for the payment module",
        "Refactor the database connection pool",
        "Implement the REST API endpoint for user profiles",
        "Debug the memory leak in the worker process",
        "Update the Dockerfile to use multi-stage builds",
        "Add CORS headers to the API gateway",
        "Write a migration script for the new schema",
        "Optimize the search query performance",
        "Add rate limiting to the public API",
        "Implement webhook retry logic",
        "Fix CSS layout issues on mobile",
        "Add logging and monitoring to payment flow",
        "Create CI/CD pipeline configuration",
        "Implement file upload with S3 integration",
        "Add input validation for user registration",
        "Fix race condition in concurrent updates",
        "Implement caching layer with Redis",
        "Add health check endpoint",
        "Write integration tests for the order flow",
    ]
    assistant_previews = [
        "I'll fix the authentication bug by updating the token validation logic.",
        "Let me add comprehensive unit tests for the payment module.",
        "I'll refactor the database pool to use connection recycling.",
        "Here's the REST API endpoint implementation with proper error handling.",
        "The memory leak is caused by unclosed file handles in the worker.",
        "I'll update the Dockerfile with a multi-stage build for smaller images.",
        "Adding CORS headers to allow cross-origin requests from the frontend.",
        "Here's the migration script that handles the schema changes safely.",
        "I've optimized the query by adding proper indexes and using CTEs.",
        "Implementing rate limiting using a sliding window algorithm.",
    ]
    services = ["anthropic_api"] * 14 + ["anthropic_telemetry"] * 3 + \
               ["error_reporting"] * 2 + ["github_copilot"] * 1
    models = ["claude-sonnet-4-5-20250514"] * 12 + ["claude-opus-4-20250512"] * 8
    tool_sets = [
        '["bash", "str_replace_editor"]',
        '["bash"]',
        '["read_file", "str_replace_editor"]',
        '["web_search", "bash"]',
        '[]',
        '["str_replace_editor"]',
        '["bash", "read_file"]',
        '["bash", "str_replace_editor", "read_file"]',
    ]

    rows = []
    for i in range(20):
        t = base_time.replace(second=0)
        from datetime import timedelta
        t = t + timedelta(minutes=i * 2, seconds=random.randint(0, 59))
        in_tok = random.randint(1000, 80000)
        out_tok = random.randint(100, 4000)
        model = models[i]
        cost = estimate_cost(model, in_tok, out_tok,
                             random.randint(0, 5000), random.randint(0, 2000))
        service = services[i]
        tools_json = random.choice(tool_sets)
        tools_list = json.loads(tools_json)

        bash_cmds = []
        if "bash" in tools_list:
            bash_cmds = [random.choice([
                "python3 -m pytest tests/", "git diff --stat",
                "npm run build", "docker-compose up -d",
                "cat /etc/hosts", "ls -la src/"
            ])]

        sensitive = ""
        sensitive_count = 0
        if i == 7:
            sensitive = "aws_key"
            sensitive_count = 1
        elif i == 14:
            sensitive = "private_key"
            sensitive_count = 1

        row = {
            "timestamp": t.isoformat(),
            "session_id": session_id,
            "turn_id": str(uuid.uuid4())[:8],
            "turn_number": i + 1,
            "destination_host": "api.anthropic.com" if "anthropic_api" in service else "statsig.anthropic.com",
            "destination_service": service,
            "endpoint_path": "/v1/messages" if "api" in service else "/v1/log_event",
            "http_method": "POST",
            "http_status": random.choice([200] * 18 + [429, 500]),
            "model": model if "api" in service else "",
            "stream": "true" if "api" in service else "false",
            "input_tokens": in_tok if "api" in service else 0,
            "output_tokens": out_tok if "api" in service else 0,
            "cache_read_tokens": random.randint(0, 5000),
            "cache_write_tokens": random.randint(0, 2000),
            "estimated_cost_usd": cost if "api" in service else 0,
            "request_size_bytes": random.randint(5000, 500000),
            "response_size_bytes": random.randint(1000, 200000),
            "latency_ms": random.randint(800, 8000),
            "num_messages": random.randint(2, 30),
            "system_prompt_chars": random.randint(500, 15000),
            "last_user_msg_preview": prompts[i],
            "assistant_msg_preview": assistant_previews[i % len(assistant_previews)],
            "tool_calls": tools_json,
            "tool_call_count": len(tools_list),
            "bash_commands": json.dumps(bash_cmds),
            "files_read": json.dumps([f"/src/module_{i}.py"]),
            "files_written": json.dumps([f"/src/module_{i}.py"] if tools_list else []),
            "urls_fetched": "[]",
            "sensitive_patterns": sensitive,
            "sensitive_pattern_count": sensitive_count,
            "content_types_sent": "text,tool_use" if tools_list else "text",
            "stop_reason": random.choice(["end_turn", "tool_use"]),
            "request_id": f"req_{uuid.uuid4().hex[:12]}",
            "raw_request_hash": hashlib.sha256(str(i).encode()).hexdigest()[:12],
        }
        rows.append(row)

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"\nGenerated test CSV: {csv_path}")
    print(f"  {len(rows)} rows with realistic AI agent traffic data")
    print(f"\nNext steps:")
    print(f"  claude-watch --analyze")
    print(f"  claude-watch --plot")
    print(f"  claude-watch --dashboard")


# ─────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Claude Watch — AI Agent Traffic Observatory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  claude-watch --setup           # Install deps & trust cert (once)
  claude-watch --start           # Start proxy (terminal 1)
  source ~/claude_watch_output/proxy_env.sh && claude  # Run agent (terminal 2)
  claude-watch --analyze         # Quick terminal analysis
  claude-watch --plot            # Generate matplotlib dashboard PNG
  claude-watch --dashboard       # Launch live web dashboard
  claude-watch --scan            # Detect running AI agents
  claude-watch --generate-test   # Create test CSV data
        """
    )
    parser.add_argument("--setup",    action="store_true", help="Install deps, trust cert")
    parser.add_argument("--start",    action="store_true", help="Start the proxy")
    parser.add_argument("--analyze",  action="store_true", help="Analyze latest session CSV")
    parser.add_argument("--plot",     action="store_true", help="Generate dashboard plots (PNG)")
    parser.add_argument("--dashboard",action="store_true", help="Launch live web dashboard")
    parser.add_argument("--scan",     action="store_true", help="Scan for AI processes")
    parser.add_argument("--generate-test", action="store_true",
                        help="Generate synthetic test CSV")
    parser.add_argument("--dir",      type=str, default=None,
                        help="Session dir for --analyze/--plot/--dashboard")

    args = parser.parse_args()

    if args.setup:
        run_setup()
    elif args.start:
        run_start()
    elif args.analyze:
        run_analyze(args.dir)
    elif args.plot:
        run_plot(args.dir)
    elif args.dashboard:
        run_dashboard(args.dir)
    elif args.scan:
        run_scan()
    elif args.generate_test:
        run_generate_test()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
