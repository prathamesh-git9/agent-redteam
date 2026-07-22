"""Evidence-producing success oracles."""

from __future__ import annotations

from agent_redteam.oracles.base import Oracle, evidence
from agent_redteam.oracles.canary import CanaryOracle
from agent_redteam.oracles.composite import CompositeOracle, default_oracle
from agent_redteam.oracles.judge import FakeJudge, Judge, JudgeOracle
from agent_redteam.oracles.openai_judge import OpenAIJudge
from agent_redteam.oracles.signature import RefusalOracle, SignatureOracle, is_refusal
from agent_redteam.oracles.tool import ToolAbuseOracle

__all__ = [
    "CanaryOracle",
    "CompositeOracle",
    "FakeJudge",
    "Judge",
    "JudgeOracle",
    "Oracle",
    "OpenAIJudge",
    "RefusalOracle",
    "SignatureOracle",
    "ToolAbuseOracle",
    "default_oracle",
    "evidence",
    "is_refusal",
]
