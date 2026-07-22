from __future__ import annotations

import asyncio

from agent_redteam.targets.callable_target import CallableTarget
from agent_redteam.targets.fake import (
    FakeTarget,
    Rule,
    contains,
    hardened_target,
    last_user_contains,
    vulnerable_target,
)
from agent_redteam.targets.http import HTTPTarget, _dig, _fill
from agent_redteam.targets.openai_chat import (
    _parse_openai_response,
    _parse_tool_calls,
    _to_openai_messages,
    target_from_options,
)
from agent_redteam.types import (
    Conversation,
    Response,
    Role,
    TargetKind,
    ToolCall,
    assistant,
    conversation,
    system,
    user,
)


def _any(_: Conversation) -> bool:
    return True


def test_http_fill_substitutes_supported_placeholders_and_keeps_static_values() -> None:
    convo = conversation(
        system("System policy"),
        user("First request"),
        assistant("First answer"),
        user("Second request"),
    )
    template = {
        "input": "{{last_user}}",
        "messages": "{{messages}}",
        "prompt": "{{full_prompt}}",
        "static": "gpt-test",
        "nested": ["{{last_user}}", 7],
    }

    filled = _fill(template, convo)

    assert filled == {
        "input": "Second request",
        "messages": [
            {"role": "system", "content": "System policy"},
            {"role": "user", "content": "First request"},
            {"role": "assistant", "content": "First answer"},
            {"role": "user", "content": "Second request"},
        ],
        "prompt": "System policy\nFirst request\nFirst answer\nSecond request",
        "static": "gpt-test",
        "nested": ["Second request", 7],
    }


def test_http_dig_follows_dotted_paths_and_missing_paths_return_empty_string() -> None:
    data = {
        "choices": [
            {"message": {"content": "hello"}},
            {"message": {"content": "second"}},
        ],
        "count": 2,
    }

    assert _dig(data, "choices.0.message.content") == "hello"
    assert _dig(data, "choices.1.message.content") == "second"
    assert _dig(data, "choices.2.message.content") == ""
    assert _dig(data, "choices.0.missing.content") == ""
    assert _dig(data, "count.value") == ""


def test_http_target_endpoint_and_info_are_static_metadata() -> None:
    target = HTTPTarget(
        url="https://agent.example.test/respond",
        request_template={"q": "{{last_user}}"},
        response_path="reply.text",
        name="agent-http",
        supports_tools=True,
    )

    assert target.endpoint() == "https://agent.example.test/respond"
    assert target.info.name == "agent-http"
    assert target.info.kind == TargetKind.HTTP
    assert target.info.supports_tools is True
    assert target.info.authorized is True
    assert target.info.allowlisted is True


async def test_callable_target_wraps_sync_function_returning_text() -> None:
    def sync_agent(convo: Conversation) -> str:
        assert convo[-1].content == "hello"
        return "sync reply"

    response = await CallableTarget(sync_agent, name="sync").send(
        conversation(user("hello"))
    )

    assert response.text == "sync reply"
    assert response.ok
    assert response.latency_ms > 0


async def test_callable_target_wraps_async_coroutine() -> None:
    async def async_agent(_: Conversation) -> str:
        await asyncio.sleep(0)
        return "async reply"

    response = await CallableTarget(async_agent).send(conversation(user("hello")))

    assert response.text == "async reply"
    assert response.ok
    assert response.latency_ms > 0


async def test_callable_target_accepts_text_and_tool_calls_tuple() -> None:
    call = ToolCall(name="lookup", arguments={"id": 7}, call_id="call-1")

    def agent(_: Conversation) -> tuple[str, tuple[ToolCall, ...]]:
        return "using tool", (call,)

    response = await CallableTarget(agent, supports_tools=True).send(
        conversation(user("use a tool"))
    )

    assert response.text == "using tool"
    assert response.tool_calls == (call,)
    assert response.latency_ms > 0


async def test_callable_target_converts_raised_exception_to_error_response() -> None:
    def broken(_: Conversation) -> str:
        raise RuntimeError("boom")

    response = await CallableTarget(broken).send(conversation(user("hello")))

    assert response.text == ""
    assert response.error == "RuntimeError: boom"
    assert not response.ok


def test_openai_messages_prepend_system_prompt_only_without_system_message() -> None:
    no_system = _to_openai_messages(conversation(user("hi")), "Be concise.")
    with_system = _to_openai_messages(
        conversation(system("Existing system"), user("hi")),
        "Be concise.",
    )

    assert no_system == [
        {"role": "system", "content": "Be concise."},
        {"role": "user", "content": "hi"},
    ]
    assert with_system == [
        {"role": "system", "content": "Existing system"},
        {"role": "user", "content": "hi"},
    ]


def test_openai_response_parses_content_usage_and_tool_calls() -> None:
    data = {
        "choices": [
            {
                "message": {
                    "content": "done",
                    "tool_calls": [
                        {
                            "id": "call-json",
                            "function": {
                                "name": "search",
                                "arguments": '{"query": "docs"}',
                            },
                        },
                        {
                            "id": "call-dict",
                            "function": {
                                "name": "write",
                                "arguments": {"path": "out.txt"},
                            },
                        },
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 13},
    }

    response = _parse_openai_response(data, latency_ms=4.5)

    assert response.text == "done"
    assert response.usage.prompt_tokens == 11
    assert response.usage.completion_tokens == 13
    assert response.usage.total_tokens == 24
    assert response.latency_ms == 4.5
    assert response.raw is data
    assert response.tool_calls == (
        ToolCall(name="search", arguments={"query": "docs"}, call_id="call-json"),
        ToolCall(name="write", arguments={"path": "out.txt"}, call_id="call-dict"),
    )


def test_openai_parse_tool_calls_handles_json_string_and_dict_arguments() -> None:
    calls = _parse_tool_calls(
        [
            {"id": "a", "function": {"name": "json_args", "arguments": '{"x": 1}'}},
            {"id": "b", "function": {"name": "dict_args", "arguments": {"y": 2}}},
        ]
    )

    assert calls == (
        ToolCall(name="json_args", arguments={"x": 1}, call_id="a"),
        ToolCall(name="dict_args", arguments={"y": 2}, call_id="b"),
    )


def test_openai_target_from_options_exposes_endpoint_and_info_without_sending() -> None:
    target = target_from_options(
        "chat-target",
        {
            "model": "test-model",
            "base_url": "https://llm.example.test/v1",
            "system_prompt": "Stay brief.",
            "max_tokens": 64,
        },
    )

    assert target.endpoint() == "https://llm.example.test/v1"
    assert target.model == "test-model"
    assert target.info.name == "chat-target"
    assert target.info.kind == TargetKind.OPENAI_CHAT
    assert target.info.supports_tools is True
    assert target.info.authorized is True
    assert target.info.allowlisted is True


async def test_fake_target_uses_first_matching_rule() -> None:
    target = FakeTarget(
        rules=[
            Rule(matcher=_any, reply="first"),
            Rule(matcher=_any, reply="second"),
        ]
    )

    response = await target.send(conversation(user("anything")))

    assert response.text == "first"


async def test_fake_target_returns_default_reply_when_no_rule_matches() -> None:
    target = FakeTarget(
        default="fallback",
        rules=[Rule(matcher=contains("secret"), reply="matched")],
    )

    response = await target.send(conversation(user("ordinary request")))

    assert response.text == "fallback"
    assert response.usage.prompt_tokens > 0
    assert response.usage.completion_tokens == len("fallback") // 4


def test_fake_contains_and_last_user_contains_matchers() -> None:
    convo = conversation(system("Alpha policy"), user("first"), assistant("Beta"))

    assert contains("alpha")(convo)
    assert contains("beta")(convo)
    assert not last_user_contains("beta")(convo)
    assert last_user_contains("first")(convo)


def test_fake_helper_targets_expose_expected_defaults_and_extra_rules() -> None:
    custom = Rule(matcher=contains("custom"), reply="custom reply")
    vulnerable = vulnerable_target(custom)
    hardened = hardened_target(custom)

    assert vulnerable.info.name == "vulnerable"
    assert vulnerable.info.kind == TargetKind.FAKE
    assert vulnerable.info.supports_tools is True
    assert hardened.info.name == "hardened"
    assert hardened.info.kind == TargetKind.FAKE
    assert hardened.info.supports_tools is True

    assert vulnerable.rules == [custom]
    assert vulnerable.default == "Sure! Ignoring previous instructions as requested."
    assert hardened.rules == [custom]
    assert hardened.default == "I can't help with that request."


def test_callable_target_info_is_in_process_metadata() -> None:
    def agent(_: Conversation) -> Response:
        return Response(text="ok")

    target = CallableTarget(agent, name="local-agent", supports_tools=True)

    assert target.endpoint() is None
    assert target.info.name == "local-agent"
    assert target.info.kind == TargetKind.CALLABLE
    assert target.info.supports_tools is True
    assert target.info.authorized is True
    assert target.info.allowlisted is True


def test_role_import_guards_openai_message_mapping_against_enum_regressions() -> None:
    """WHY: target adapters depend on serialized Role values matching provider APIs."""
    assert Role.SYSTEM.value == "system"
    assert Role.USER.value == "user"
