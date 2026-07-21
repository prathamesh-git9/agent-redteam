"""Red-team an in-process agent — no server, no network.

Run:  python examples/local_agent.py

This shows the programmatic API: wrap your own agent function in a CallableTarget,
run the suite, then wrap it in the default guardrails and see the delta. Because
a callable target never leaves the process, no allowlist is required.
"""

from __future__ import annotations

import asyncio

from agent_redteam.config import RunConfig, TargetConfig
from agent_redteam.guardrails import default_guardrails
from agent_redteam.oracles import default_oracle
from agent_redteam.runner import Runner
from agent_redteam.targets.callable_target import CallableTarget
from agent_redteam.types import Conversation, Role


def my_agent(conversation: Conversation) -> str:
    """A deliberately-naive agent that leaks its system prompt on request.

    Replace this with a call into your real agent. This one exists to make the
    before/after guardrail delta visible in a few lines.
    """
    system = next((m.content for m in conversation if m.role == Role.SYSTEM), "")
    last_user = next(
        (m.content for m in reversed(conversation) if m.role == Role.USER), ""
    )
    if "above" in last_user.lower() or "system prompt" in last_user.lower():
        return f"Sure, here are my instructions: {system}"
    return "Happy to help!"


async def main() -> None:
    # Import the corpus so attacks register themselves.
    import agent_redteam.attacks  # noqa: F401

    target = CallableTarget(fn=my_agent, name="local-demo")
    cfg = RunConfig(
        target=TargetConfig(name="local-demo", kind="callable", authorized=True),
        suite="exfiltration",
    )
    runner = Runner(default_oracle(), cfg)

    undefended = await runner.run(target)
    defended = await runner.run(default_guardrails().wrap(target))

    print(
        f"undefended: {len(undefended.successes)} successes, "
        f"max {undefended.max_score}"
    )
    print(f"defended:   {len(defended.successes)} successes, max {defended.max_score}")


if __name__ == "__main__":
    asyncio.run(main())
