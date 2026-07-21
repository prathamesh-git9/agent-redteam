"""Input-side guardrails for prompt-injection and obfuscation defenses."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from agent_redteam.oracles.signature import is_refusal
from agent_redteam.registry import register_guardrail
from agent_redteam.types import Evidence, GuardAction, GuardDecision, Message

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_PRINTABLE = set(chr(i) for i in range(32, 127)) | {"\n", "\r", "\t"}
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "А": "A",
        "Е": "E",
        "О": "O",
        "Р": "P",
        "С": "C",
    }
)
_LEET = str.maketrans(
    {
        "4": "a",
        "@": "a",
        "3": "e",
        "1": "i",
        "!": "i",
        "0": "o",
        "$": "s",
        "5": "s",
        "7": "t",
    }
)


@register_guardrail("encoding_normalizer")
@dataclass(frozen=True)
class EncodingNormalizer:
    """Decode evasive text before later guards inspect it.

    Normalize-then-inspect defeats common encoding evasions: the original text is
    preserved, while a decoded shadow string exposes base64, leetspeak, and
    homoglyph-obfuscated instructions to downstream guardrails.
    """

    name: str = "encoding_normalizer"

    def inspect_input(self, message: Message) -> GuardDecision:
        normalized = _normalize_text(message.content)
        if normalized == message.content:
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        return GuardDecision(
            GuardAction.REWRITE,
            guardrail=self.name,
            reason="decoded obfuscated input for downstream inspection",
            content=f"{message.content}\n[decoded]: {normalized}",
            evidence=(Evidence("normalization", "input normalization changed content"),),
        )


@register_guardrail("injection_detector")
@dataclass(frozen=True)
class InjectionDetector:
    """Conservative prompt-injection detector for high-confidence overrides."""

    sensitivity: str = "conservative"
    name: str = "injection_detector"

    SENSITIVITY: str = "conservative"
    strong_patterns: tuple[re.Pattern[str], ...] = field(
        default_factory=lambda: tuple(
            re.compile(pattern, re.IGNORECASE)
            for pattern in (
                r"\bignore\s+(?:all\s+)?previous\s+instructions\b",
                r"\bdisregard\s+(?:the\s+)?above\b",
                r"\byou\s+are\s+now\b",
                r"\bdeveloper\s+mode\b",
                r"\breveal\s+(?:your\s+)?system\s+prompt\b",
                r"\bprint\s+everything\s+above\b",
                r"\bnever\s+refuse\b",
            )
        )
    )

    def inspect_input(self, message: Message) -> GuardDecision:
        if is_refusal(message.content):
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        for pattern in self.strong_patterns:
            match = pattern.search(message.content)
            if match:
                return GuardDecision(
                    GuardAction.BLOCK,
                    guardrail=self.name,
                    reason="strong prompt-injection pattern matched",
                    evidence=(
                        Evidence(
                            "signature",
                            f"matched pattern: {pattern.pattern}",
                            span=match.group(0),
                        ),
                    ),
                )
        return GuardDecision(GuardAction.ALLOW, guardrail=self.name)


@register_guardrail("allowlist")
@dataclass(frozen=True)
class AllowlistGuard:
    """Opt-in topic allowlist; empty configuration permits all input."""

    allowed: tuple[str, ...] = ()
    name: str = "allowlist"

    def __init__(self, allowed: tuple[str, ...] | set[str] | list[str] = ()) -> None:
        object.__setattr__(self, "allowed", tuple(allowed))
        object.__setattr__(self, "name", "allowlist")

    def inspect_input(self, message: Message) -> GuardDecision:
        if not self.allowed:
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        lowered = message.content.lower()
        for item in self.allowed:
            if item.lower() in lowered:
                return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        return GuardDecision(
            GuardAction.BLOCK,
            guardrail=self.name,
            reason="input did not match configured allowlist",
            evidence=(Evidence("allowlist", "no allowed topic matched"),),
        )


def _normalize_text(text: str) -> str:
    current = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPHS)
    current = _decode_base64_blobs(current)
    current = _deleet_words(current)
    return current


def _decode_base64_blobs(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return token
        try:
            value = decoded.decode("ascii")
        except UnicodeDecodeError:
            return token
        printable = sum(char in _PRINTABLE for char in value)
        if value and printable / len(value) >= 0.85:
            return value
        return token

    return _BASE64_BLOB.sub(replace, text)


def _deleet_words(text: str) -> str:
    words = re.split(r"(\W+)", text)
    out: list[str] = []
    for word in words:
        candidate = word.translate(_LEET)
        if _looks_leet_obfuscated(word, candidate):
            out.append(candidate)
        else:
            out.append(word)
    return "".join(out)


def _looks_leet_obfuscated(original: str, candidate: str) -> bool:
    if original == candidate or not any(char.isalpha() for char in candidate):
        return False
    return bool(re.search(r"[013457@$!]", original))
