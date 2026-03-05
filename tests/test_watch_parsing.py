"""Comprehensive tests for standalone parsing functions in watch.py.

Tests parse_request_body, parse_response_body, and parse_sse_response
with realistic Anthropic API payloads.
"""

import json

from claude_monitoring.watch import parse_request_body, parse_response_body, parse_sse_response


def _fresh_record():
    """Return a minimal record dict with sensible defaults for all fields
    that the parsing functions read or write."""
    return {
        "model": "",
        "stream": "",
        "num_messages": 0,
        "system_prompt_chars": 0,
        "sensitive_patterns": "",
        "sensitive_pattern_count": 0,
        "last_user_msg_preview": "",
        "assistant_msg_preview": "",
        "tool_calls": "[]",
        "tool_call_count": 0,
        "bash_commands": "[]",
        "files_read": "[]",
        "files_written": "[]",
        "urls_fetched": "[]",
        "content_types_sent": "",
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "estimated_cost_usd": 0.0,
        "stop_reason": "",
    }


# =====================================================================
# parse_request_body tests
# =====================================================================


class TestParseRequestBodyBasic:
    """Test basic field extraction from a request body."""

    def test_extracts_model_and_stream(self):
        body = {
            "model": "claude-sonnet-4-20250514",
            "stream": True,
            "messages": [],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["model"] == "claude-sonnet-4-20250514"
        assert result["stream"] == "true"

    def test_stream_false(self):
        body = {"model": "claude-sonnet-4", "stream": False, "messages": []}
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["stream"] == "false"

    def test_stream_missing_defaults_false(self):
        body = {"model": "claude-sonnet-4", "messages": []}
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["stream"] == "false"

    def test_num_messages(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "How are you?"},
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["num_messages"] == 3

    def test_empty_messages_list(self):
        body = {"model": "claude-sonnet-4", "messages": []}
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["num_messages"] == 0
        assert result["last_user_msg_preview"] == ""
        assert result["tool_calls"] == "[]"
        assert result["tool_call_count"] == 0
        assert result["bash_commands"] == "[]"
        assert result["files_read"] == "[]"
        assert result["files_written"] == "[]"
        assert result["content_types_sent"] == ""


class TestParseRequestBodySystemPrompt:
    """Test system prompt extraction."""

    def test_system_prompt_string(self):
        body = {
            "model": "claude-sonnet-4",
            "system": "You are a helpful coding assistant.",
            "messages": [],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["system_prompt_chars"] == len("You are a helpful coding assistant.")

    def test_system_prompt_list_of_dicts(self):
        body = {
            "model": "claude-sonnet-4",
            "system": [
                {"type": "text", "text": "You are a helpful assistant."},
                {"type": "text", "text": " Be concise."},
            ],
            "messages": [],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        expected_len = len("You are a helpful assistant.  Be concise.")
        assert result["system_prompt_chars"] == expected_len

    def test_system_prompt_missing(self):
        body = {"model": "claude-sonnet-4", "messages": []}
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["system_prompt_chars"] == 0

    def test_system_prompt_empty_string(self):
        body = {"model": "claude-sonnet-4", "system": "", "messages": []}
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["system_prompt_chars"] == 0


class TestParseRequestBodyToolCalls:
    """Test tool call extraction from messages."""

    def test_full_request_with_tool_use_blocks(self):
        """Simulate a realistic multi-turn conversation with tool_use blocks
        for bash, str_replace_editor, and read_file."""
        body = {
            "model": "claude-sonnet-4-20250514",
            "stream": True,
            "system": "You are Claude Code, an AI assistant by Anthropic.",
            "messages": [
                {
                    "role": "user",
                    "content": "Fix the bug in /Users/dev/project/main.py",
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "read_file",
                            "input": {"path": "/Users/dev/project/main.py"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": "def main():\n    print('hello')\n",
                        }
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_02",
                            "name": "bash",
                            "input": {"command": "cd /Users/dev/project && python main.py"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_02",
                            "content": "hello\n",
                        }
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_03",
                            "name": "str_replace_editor",
                            "input": {
                                "path": "/Users/dev/project/main.py",
                                "old_str": "print('hello')",
                                "new_str": "print('hello world')",
                            },
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_03",
                            "content": "File edited successfully.",
                        }
                    ],
                },
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        # Model and stream
        assert result["model"] == "claude-sonnet-4-20250514"
        assert result["stream"] == "true"

        # Message count
        assert result["num_messages"] == 7

        # System prompt
        assert result["system_prompt_chars"] == len("You are Claude Code, an AI assistant by Anthropic.")

        # Tool calls
        tool_calls = json.loads(result["tool_calls"])
        assert "read_file" in tool_calls
        assert "bash" in tool_calls
        assert "str_replace_editor" in tool_calls
        assert result["tool_call_count"] == 3  # 3 individual calls

        # Bash commands
        bash_cmds = json.loads(result["bash_commands"])
        assert len(bash_cmds) == 1
        assert "cd /Users/dev/project && python main.py" in bash_cmds[0]

        # Files read
        files_read = json.loads(result["files_read"])
        assert "/Users/dev/project/main.py" in files_read

        # Files written
        files_written = json.loads(result["files_written"])
        assert "/Users/dev/project/main.py" in files_written

        # Content types sent
        content_types = result["content_types_sent"].split(",")
        assert "tool_use" in content_types
        assert "tool_result" in content_types
        assert "text" in content_types

    def test_bash_command_truncated_at_200_chars(self):
        long_cmd = "echo " + "x" * 300
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"command": long_cmd},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        bash_cmds = json.loads(result["bash_commands"])
        assert len(bash_cmds) == 1
        assert len(bash_cmds[0]) == 200

    def test_bash_cmd_key_variant(self):
        """Some tool_use blocks use 'cmd' instead of 'command'."""
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"cmd": "ls -la /tmp"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        bash_cmds = json.loads(result["bash_commands"])
        assert len(bash_cmds) == 1
        assert "ls -la /tmp" in bash_cmds[0]

    def test_write_file_tool(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "write_file",
                            "input": {
                                "file_path": "/tmp/output.txt",
                                "content": "Hello world",
                            },
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        files_written = json.loads(result["files_written"])
        assert "/tmp/output.txt" in files_written

    def test_create_file_tool(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "create_file",
                            "input": {"path": "/tmp/new_file.py"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        files_written = json.loads(result["files_written"])
        assert "/tmp/new_file.py" in files_written

    def test_file_editor_tool(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "file_editor",
                            "input": {"path": "/tmp/edited.py"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        files_written = json.loads(result["files_written"])
        assert "/tmp/edited.py" in files_written

    def test_view_tool_for_read(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "view",
                            "input": {"file_path": "/tmp/readme.md"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        files_read = json.loads(result["files_read"])
        assert "/tmp/readme.md" in files_read

    def test_tool_calls_deduplicated(self):
        """Multiple calls to the same tool should be deduplicated in the set."""
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"command": "ls"},
                        },
                        {
                            "type": "tool_use",
                            "id": "toolu_02",
                            "name": "bash",
                            "input": {"command": "pwd"},
                        },
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        tool_calls = json.loads(result["tool_calls"])
        # Deduplicated: only one "bash" entry
        assert tool_calls == ["bash"]
        # But tool_call_count reflects the total number of calls
        assert result["tool_call_count"] == 2

    def test_bash_commands_limited_to_10(self):
        """At most 10 bash commands should be kept."""
        blocks = []
        for i in range(15):
            blocks.append(
                {
                    "type": "tool_use",
                    "id": f"toolu_{i:02d}",
                    "name": "bash",
                    "input": {"command": f"echo {i}"},
                }
            )
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "assistant", "content": blocks}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        bash_cmds = json.loads(result["bash_commands"])
        assert len(bash_cmds) == 10

    def test_file_paths_from_bash_command(self):
        """extract_file_paths is called on bash commands to find read files."""
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"command": "cat /Users/dev/config.yaml"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        files_read = json.loads(result["files_read"])
        assert "/Users/dev/config.yaml" in files_read


class TestParseRequestBodyUserMessage:
    """Test last_user_msg_preview extraction."""

    def test_last_user_text_from_string_content(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "user", "content": "First question"},
                {"role": "assistant", "content": "Answer"},
                {"role": "user", "content": "Second question"},
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["last_user_msg_preview"] == "Second question"

    def test_last_user_text_from_text_block(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Please help with this code."}],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["last_user_msg_preview"] == "Please help with this code."

    def test_last_user_msg_preview_truncated_at_300_chars(self):
        long_text = "A" * 500
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": long_text}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert len(result["last_user_msg_preview"]) == 300

    def test_last_user_msg_preview_newlines_replaced(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "Line one\nLine two\nLine three"}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "\n" not in result["last_user_msg_preview"]
        assert "Line one Line two Line three" == result["last_user_msg_preview"]

    def test_last_user_msg_preview_commas_replaced(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "a,b,c"}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "," not in result["last_user_msg_preview"]
        assert result["last_user_msg_preview"] == "a;b;c"

    def test_tool_result_does_not_set_user_text(self):
        """tool_result blocks should not override last_user_text."""
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "user", "content": "Run tests please"},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": "PASS: all tests passed",
                        }
                    ],
                },
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        # The last user text block of type "text" or plain string
        # is "Run tests please", not the tool_result content.
        assert result["last_user_msg_preview"] == "Run tests please"


class TestParseRequestBodySensitivePatterns:
    """Test sensitive pattern detection."""

    def test_aws_key_detected(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": "My key is AKIAIOSFODNN7EXAMPLE",
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "aws_key" in result["sensitive_patterns"]
        assert result["sensitive_pattern_count"] >= 1

    def test_private_key_detected(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...",
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "private_key" in result["sensitive_patterns"]
        assert result["sensitive_pattern_count"] >= 1

    def test_github_token_detected(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": "Use this token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "github_token" in result["sensitive_patterns"]

    def test_no_sensitive_patterns_in_clean_request(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "What is 2+2?"}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["sensitive_patterns"] == ""
        assert result["sensitive_pattern_count"] == 0

    def test_multiple_sensitive_patterns(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": ("AWS key: AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----\nfoo\n"),
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert result["sensitive_pattern_count"] >= 2
        patterns = result["sensitive_patterns"].split(",")
        assert "aws_key" in patterns
        assert "private_key" in patterns


class TestParseRequestBodyURLs:
    """Test URL extraction from tool inputs and tool results."""

    def test_url_from_tool_input(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "web_fetch",
                            "input": {"url": "https://example.com/api/data"},
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        urls = json.loads(result["urls_fetched"])
        assert "https://example.com/api/data" in urls

    def test_url_from_tool_result(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": "See https://docs.example.com/guide for more info.",
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        urls = json.loads(result["urls_fetched"])
        assert "https://docs.example.com/guide" in urls

    def test_url_from_tool_result_list(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": [{"type": "text", "text": "Visit https://example.org/page"}],
                        }
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        urls = json.loads(result["urls_fetched"])
        assert any("https://example.org/page" in u for u in urls)


class TestParseRequestBodyContentTypes:
    """Test content_types_sent tracking."""

    def test_text_only(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "text" in result["content_types_sent"]

    def test_mixed_content_types(self):
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Here is the plan"},
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "bash",
                            "input": {"command": "ls"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": "file1.py\nfile2.py",
                        }
                    ],
                },
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        types = set(result["content_types_sent"].split(","))
        assert "text" in types
        assert "tool_use" in types
        assert "tool_result" in types

    def test_non_dict_blocks_skipped(self):
        """Non-dict items in content list should be skipped without error."""
        body = {
            "model": "claude-sonnet-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        "a plain string in a list",
                        42,
                        {"type": "text", "text": "real block"},
                    ],
                }
            ],
        }
        record = _fresh_record()
        result = parse_request_body(body, record)

        assert "text" in result["content_types_sent"]


# =====================================================================
# parse_response_body tests
# =====================================================================


class TestParseResponseBodyUsage:
    """Test token usage extraction."""

    def test_extracts_all_usage_fields(self):
        body = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "usage": {
                "input_tokens": 1500,
                "output_tokens": 350,
                "cache_read_input_tokens": 1000,
                "cache_creation_input_tokens": 200,
            },
            "content": [],
            "stop_reason": "end_turn",
            "model": "claude-sonnet-4-20250514",
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["input_tokens"] == 1500
        assert result["output_tokens"] == 350
        assert result["cache_read_tokens"] == 1000
        assert result["cache_write_tokens"] == 200

    def test_missing_usage_defaults_to_zero(self):
        body = {"content": [], "stop_reason": "end_turn"}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["input_tokens"] == 0
        assert result["output_tokens"] == 0
        assert result["cache_read_tokens"] == 0
        assert result["cache_write_tokens"] == 0

    def test_partial_usage(self):
        body = {
            "usage": {"input_tokens": 500, "output_tokens": 100},
            "content": [],
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["input_tokens"] == 500
        assert result["output_tokens"] == 100
        assert result["cache_read_tokens"] == 0
        assert result["cache_write_tokens"] == 0


class TestParseResponseBodyCost:
    """Test estimated cost computation."""

    def test_cost_computed_for_sonnet(self):
        body = {
            "usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
            "content": [],
            "model": "claude-sonnet-4-20250514",
        }
        record = _fresh_record()
        record["model"] = "claude-sonnet-4-20250514"
        result = parse_response_body(body, record)

        # sonnet-4: input $3/M, output $15/M => 3 + 15 = 18.0
        assert result["estimated_cost_usd"] == 18.0

    def test_cost_with_cache_tokens(self):
        body = {
            "usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 1_000_000,
                "cache_creation_input_tokens": 1_000_000,
            },
            "content": [],
        }
        record = _fresh_record()
        record["model"] = "claude-sonnet-4"
        result = parse_response_body(body, record)

        # cache_read: 1M * $3/M * 0.1 = 0.3
        # cache_write: 1M * $3/M * 1.25 = 3.75
        assert result["estimated_cost_usd"] == round(0.3 + 3.75, 6)

    def test_cost_zero_tokens(self):
        body = {"usage": {}, "content": []}
        record = _fresh_record()
        record["model"] = "claude-sonnet-4"
        result = parse_response_body(body, record)

        assert result["estimated_cost_usd"] == 0.0


class TestParseResponseBodyStopReason:
    """Test stop_reason extraction."""

    def test_stop_reason_end_turn(self):
        body = {"content": [], "stop_reason": "end_turn", "usage": {}}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["stop_reason"] == "end_turn"

    def test_stop_reason_max_tokens(self):
        body = {"content": [], "stop_reason": "max_tokens", "usage": {}}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["stop_reason"] == "max_tokens"

    def test_stop_reason_tool_use(self):
        body = {"content": [], "stop_reason": "tool_use", "usage": {}}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["stop_reason"] == "tool_use"

    def test_stop_reason_missing(self):
        body = {"content": [], "usage": {}}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["stop_reason"] == ""


class TestParseResponseBodyContent:
    """Test assistant message preview and tool call extraction from response."""

    def test_assistant_msg_preview_from_text_blocks(self):
        body = {
            "content": [
                {"type": "text", "text": "Here is the solution. "},
                {"type": "text", "text": "I made the following changes."},
            ],
            "usage": {},
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert "Here is the solution." in result["assistant_msg_preview"]
        assert "I made the following changes." in result["assistant_msg_preview"]

    def test_assistant_msg_preview_truncated_at_300(self):
        body = {
            "content": [
                {"type": "text", "text": "B" * 500},
            ],
            "usage": {},
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert len(result["assistant_msg_preview"]) <= 300

    def test_assistant_msg_preview_newlines_replaced(self):
        body = {
            "content": [
                {"type": "text", "text": "Line1\nLine2\nLine3"},
            ],
            "usage": {},
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert "\n" not in result["assistant_msg_preview"]

    def test_assistant_msg_preview_commas_replaced(self):
        body = {
            "content": [
                {"type": "text", "text": "a,b,c"},
            ],
            "usage": {},
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert "," not in result["assistant_msg_preview"]
        assert "a;b;c" in result["assistant_msg_preview"]

    def test_tool_calls_from_response_content(self):
        body = {
            "content": [
                {"type": "text", "text": "Let me check the file."},
                {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "read_file",
                    "input": {"path": "/tmp/test.py"},
                },
            ],
            "usage": {},
        }
        record = _fresh_record()
        result = parse_response_body(body, record)

        tool_calls = json.loads(result["tool_calls"])
        assert "read_file" in tool_calls
        assert result["tool_call_count"] == 1

    def test_tool_calls_merged_with_existing(self):
        """Response tool_calls should merge with existing ones from request."""
        body = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_02",
                    "name": "str_replace_editor",
                    "input": {"path": "/tmp/test.py"},
                },
            ],
            "usage": {},
        }
        record = _fresh_record()
        record["tool_calls"] = json.dumps(["bash"])
        result = parse_response_body(body, record)

        tool_calls = json.loads(result["tool_calls"])
        assert "bash" in tool_calls
        assert "str_replace_editor" in tool_calls
        assert result["tool_call_count"] == 2

    def test_empty_content_list(self):
        body = {"content": [], "usage": {}}
        record = _fresh_record()
        result = parse_response_body(body, record)

        assert result["assistant_msg_preview"] == ""

    def test_model_from_response_when_record_model_empty(self):
        body = {
            "content": [],
            "usage": {},
            "model": "claude-sonnet-4-20250514",
        }
        record = _fresh_record()
        assert record["model"] == ""
        result = parse_response_body(body, record)

        assert result["model"] == "claude-sonnet-4-20250514"

    def test_model_preserved_from_record_when_set(self):
        body = {
            "content": [],
            "usage": {},
            "model": "claude-opus-4-20250514",
        }
        record = _fresh_record()
        record["model"] = "claude-sonnet-4-20250514"
        result = parse_response_body(body, record)

        # Record model was already set, so it should be preserved
        assert result["model"] == "claude-sonnet-4-20250514"


# =====================================================================
# parse_sse_response tests
# =====================================================================


def _build_sse(*events):
    """Build a raw SSE string from a list of (event_type_ignored, data_dict) or
    raw line strings."""
    lines = []
    for item in events:
        if isinstance(item, str):
            lines.append(item)
        else:
            lines.append(f"data: {json.dumps(item)}")
    return "\n".join(lines)


class TestParseSSEResponseBasic:
    """Test basic SSE parsing."""

    def test_realistic_sse_stream(self):
        """Parse a realistic SSE stream with message_start, content_block_start,
        content_block_delta, message_delta, and message_stop events."""
        raw = _build_sse(
            # message_start with usage
            {
                "type": "message_start",
                "message": {
                    "id": "msg_abc123",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {
                        "input_tokens": 2048,
                        "cache_read_input_tokens": 1500,
                        "cache_creation_input_tokens": 300,
                    },
                },
            },
            # content_block_start for text
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
            # text deltas
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Here is "},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "the answer."},
            },
            # content_block_stop
            {"type": "content_block_stop", "index": 0},
            # content_block_start for tool_use
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "bash",
                },
            },
            # input_json_delta for tool input
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"command": "ls"}',
                },
            },
            # content_block_stop for tool
            {"type": "content_block_stop", "index": 1},
            # message_delta with output tokens and stop reason
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 150},
            },
            # message_stop
            {"type": "message_stop"},
        )

        record = _fresh_record()
        result = parse_sse_response(raw, record)

        # Tokens
        assert result["input_tokens"] == 2048
        assert result["output_tokens"] == 150
        assert result["cache_read_tokens"] == 1500
        assert result["cache_write_tokens"] == 300

        # Model
        assert result["model"] == "claude-sonnet-4-20250514"

        # Stream flag
        assert result["stream"] == "true"

        # Stop reason
        assert result["stop_reason"] == "tool_use"

        # Text preview
        assert "Here is the answer." in result["assistant_msg_preview"]

        # Tool calls
        tool_calls = json.loads(result["tool_calls"])
        assert "bash" in tool_calls
        assert result["tool_call_count"] == 1

        # Cost should be computed
        assert result["estimated_cost_usd"] > 0

    def test_multiple_tool_use_blocks(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 100},
                },
            },
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "bash",
                },
            },
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_02",
                    "name": "read_file",
                },
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 50},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        tool_calls = json.loads(result["tool_calls"])
        assert "bash" in tool_calls
        assert "read_file" in tool_calls
        assert result["tool_call_count"] == 2

    def test_tool_calls_merged_with_existing(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "str_replace_editor",
                },
            },
            {
                "type": "message_delta",
                "delta": {},
                "usage": {"output_tokens": 10},
            },
        )
        record = _fresh_record()
        record["tool_calls"] = json.dumps(["bash"])
        result = parse_sse_response(raw, record)

        tool_calls = json.loads(result["tool_calls"])
        assert "bash" in tool_calls
        assert "str_replace_editor" in tool_calls

    def test_text_preview_truncated_at_300(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "C" * 500},
            },
            {
                "type": "message_delta",
                "delta": {},
                "usage": {"output_tokens": 100},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert len(result["assistant_msg_preview"]) <= 300


class TestParseSSEResponseTokenAggregation:
    """Test that tokens are summed across multiple events."""

    def test_multiple_message_delta_tokens_summed(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 100},
                },
            },
            {
                "type": "message_delta",
                "delta": {},
                "usage": {"output_tokens": 50},
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 30},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 80  # 50 + 30

    def test_cache_tokens_from_message_start(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 500,
                        "cache_read_input_tokens": 2000,
                        "cache_creation_input_tokens": 800,
                    },
                },
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 200},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["cache_read_tokens"] == 2000
        assert result["cache_write_tokens"] == 800


class TestParseSSEResponseCost:
    """Test cost estimation from SSE parsed data."""

    def test_cost_uses_model_and_tokens(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 1_000_000},
                },
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 1_000_000},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        # sonnet: $3/M input + $15/M output = $18
        assert result["estimated_cost_usd"] == 18.0


class TestParseSSEResponseEdgeCases:
    """Test edge cases and malformed SSE data."""

    def test_done_marker_ignored(self):
        raw = (
            'data: {"type": "message_start", "message": {"model": "claude-sonnet-4", "usage": {"input_tokens": 10}}}\n'
            'data: {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}}\n'
            "data: [DONE]\n"
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["input_tokens"] == 10
        assert result["output_tokens"] == 5

    def test_empty_data_lines_skipped(self):
        raw = (
            "data: \n"
            'data: {"type": "message_start", "message": {"model": "claude-sonnet-4", "usage": {"input_tokens": 42}}}\n'
            "data: \n"
            'data: {"type": "message_delta", "delta": {}, "usage": {"output_tokens": 7}}\n'
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["input_tokens"] == 42
        assert result["output_tokens"] == 7

    def test_malformed_json_lines_skipped(self):
        raw = (
            "data: {invalid json\n"
            'data: {"type": "message_start", "message": {"model": "claude-sonnet-4", "usage": {"input_tokens": 99}}}\n'
            "data: not json at all\n"
            'data: {"type": "message_delta", "delta": {}, "usage": {"output_tokens": 11}}\n'
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["input_tokens"] == 99
        assert result["output_tokens"] == 11

    def test_non_data_lines_ignored(self):
        raw = (
            "event: message_start\n"
            'data: {"type": "message_start", "message": {"model": "claude-sonnet-4", "usage": {"input_tokens": 20}}}\n'
            ": this is a comment\n"
            "\n"
            "retry: 3000\n"
            'data: {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}}\n'
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["input_tokens"] == 20
        assert result["output_tokens"] == 3

    def test_empty_raw_string(self):
        record = _fresh_record()
        result = parse_sse_response("", record)

        assert result["input_tokens"] == 0
        assert result["output_tokens"] == 0
        assert result["stream"] == "true"
        assert result["stop_reason"] == ""

    def test_model_not_overwritten_if_already_set(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-opus-4-20250514",
                    "usage": {},
                },
            },
        )
        record = _fresh_record()
        record["model"] = "claude-sonnet-4-20250514"
        result = parse_sse_response(raw, record)

        # Record model was already set, so it should be preserved
        assert result["model"] == "claude-sonnet-4-20250514"

    def test_model_set_from_sse_when_empty(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-opus-4-20250514",
                    "usage": {},
                },
            },
        )
        record = _fresh_record()
        assert record["model"] == ""
        result = parse_sse_response(raw, record)

        assert result["model"] == "claude-opus-4-20250514"

    def test_no_tool_calls_leaves_default(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Just text."},
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 5},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert result["tool_calls"] == "[]"
        assert result["tool_call_count"] == 0

    def test_no_text_chunks_leaves_assistant_preview_empty(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "bash",
                },
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 10},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        # assistant_msg_preview should remain the default empty string
        assert result["assistant_msg_preview"] == ""

    def test_text_preview_newlines_and_commas_replaced(self):
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "line1\nline2,value"},
            },
            {
                "type": "message_delta",
                "delta": {},
                "usage": {"output_tokens": 5},
            },
        )
        record = _fresh_record()
        result = parse_sse_response(raw, record)

        assert "\n" not in result["assistant_msg_preview"]
        assert "," not in result["assistant_msg_preview"]
        assert "line1 line2;value" == result["assistant_msg_preview"]

    def test_stream_always_true(self):
        """parse_sse_response always sets stream to 'true'."""
        raw = _build_sse(
            {
                "type": "message_start",
                "message": {"model": "claude-sonnet-4", "usage": {}},
            },
        )
        record = _fresh_record()
        record["stream"] = "false"
        result = parse_sse_response(raw, record)

        assert result["stream"] == "true"
