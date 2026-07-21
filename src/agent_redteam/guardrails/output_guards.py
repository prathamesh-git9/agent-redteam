"""Output-side guardrails for leakage, secrets, PII, and URL exfiltration."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

from agent_redteam.registry import register_guardrail
from agent_redteam.types import Evidence, GuardAction, GuardDecision

CANARY_RE = re.compile(r"ART-[a-z_]+-[0-9a-f-]+")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GENERIC_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|token|password)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){16}\b")
_MD_LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


@register_guardrail("canary_scanner")
@dataclass(frozen=True)
class CanaryScanner:
    """Block synthetic honeytokens before they leave the defended boundary."""

    extra_tokens: tuple[str, ...] = ()
    name: str = "canary_scanner"

    def __init__(self, extra_tokens: Iterable[str] = ()) -> None:
        object.__setattr__(self, "extra_tokens", tuple(extra_tokens))
        object.__setattr__(self, "name", "canary_scanner")

    def inspect_output(self, text: str) -> GuardDecision:
        token = _find_canary(text, self.extra_tokens)
        if token is None:
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        return GuardDecision(
            GuardAction.BLOCK,
            guardrail=self.name,
            reason="output contained a honeytoken",
            evidence=(Evidence("canary_hit", f"matched token: {_redact(token)}"),),
        )


@register_guardrail("secret_scanner")
@dataclass(frozen=True)
class SecretScanner:
    """Block high-confidence API keys, bearer tokens, and private-key material."""

    name: str = "secret_scanner"

    def inspect_output(self, text: str) -> GuardDecision:
        for kind, pattern in (
            ("openai_key", _OPENAI_KEY_RE),
            ("aws_key", _AWS_KEY_RE),
            ("generic_secret", _GENERIC_SECRET_RE),
            ("bearer_token", _BEARER_RE),
            ("private_key", _PRIVATE_KEY_RE),
        ):
            match = pattern.search(text)
            if match:
                return GuardDecision(
                    GuardAction.BLOCK,
                    guardrail=self.name,
                    reason=f"{kind} pattern matched",
                    evidence=(Evidence("secret", kind, span=_redact(match.group(0))),),
                )
        return GuardDecision(GuardAction.ALLOW, guardrail=self.name)


@register_guardrail("pii_scanner")
@dataclass(frozen=True)
class PIIScanner:
    """Redact PII instead of blocking the whole response.

    A single email address or identifier can appear in an otherwise useful answer,
    so the default is targeted REWRITE rather than a blunt BLOCK.
    """

    name: str = "pii_scanner"

    def inspect_output(self, text: str) -> GuardDecision:
        redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        redacted = _SSN_RE.sub("[REDACTED_SSN]", redacted)
        redacted = _CC_RE.sub(_redact_credit_card, redacted)
        if redacted == text:
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        return GuardDecision(
            GuardAction.REWRITE,
            guardrail=self.name,
            reason="redacted detected PII",
            content=redacted,
            evidence=(Evidence("pii", "PII redacted"),),
        )


@register_guardrail("exfil_url_blocker")
@dataclass(frozen=True)
class ExfilURLBlocker:
    """Strip markdown URLs that can carry protected data out of the session.

    Markdown-image links are a practical PII exfiltration side channel because a
    renderer may fetch the URL without an explicit user click.
    """

    allow_hosts: tuple[str, ...] = ()
    name: str = "exfil_url_blocker"

    def __init__(self, allow_hosts: Iterable[str] = ()) -> None:
        hosts = tuple(host.lower() for host in allow_hosts)
        object.__setattr__(self, "allow_hosts", hosts)
        object.__setattr__(self, "name", "exfil_url_blocker")

    def inspect_output(self, text: str) -> GuardDecision:
        evidence: list[Evidence] = []

        def replace(match: re.Match[str]) -> str:
            url = match.group(1)
            if not _url_is_exfil(url, self.allow_hosts):
                return match.group(0)
            evidence.append(Evidence("url_exfil", f"stripped URL: {_redact(url)}"))
            return "[removed unsafe URL]"

        rewritten = _MD_LINK_RE.sub(replace, text)
        if not evidence:
            return GuardDecision(GuardAction.ALLOW, guardrail=self.name)
        return GuardDecision(
            GuardAction.REWRITE,
            guardrail=self.name,
            reason="stripped markdown URL carrying protected data",
            content=rewritten,
            evidence=tuple(evidence),
        )


def _find_canary(text: str, extra_tokens: tuple[str, ...]) -> str | None:
    match = CANARY_RE.search(text)
    if match:
        return match.group(0)
    for token in extra_tokens:
        if token and token in text:
            return token
    return None


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "[REDACTED]"
    return f"{value[:5]}...[{len(value) - 10} chars]...{value[-5:]}"


def _redact_credit_card(match: re.Match[str]) -> str:
    value = match.group(0)
    digits = re.sub(r"\D", "", value)
    if len(digits) == 16 and _luhn_valid(digits):
        return "[REDACTED_CREDIT_CARD]"
    return value


def _luhn_valid(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for index, char in enumerate(reverse):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _url_is_exfil(url: str, allow_hosts: tuple[str, ...]) -> bool:
    parsed = urlparse(url)
    haystack = f"{parsed.path}?{parsed.query}#{parsed.fragment}"
    if CANARY_RE.search(haystack) or _contains_secret(haystack):
        return True
    host = (parsed.hostname or "").lower()
    if allow_hosts and host not in allow_hosts and _looks_like_data_channel(parsed):
        return True
    return False


def _contains_secret(text: str) -> bool:
    return any(
        pattern.search(text)
        for pattern in (_OPENAI_KEY_RE, _AWS_KEY_RE, _GENERIC_SECRET_RE, _BEARER_RE)
    )


def _looks_like_data_channel(parsed) -> bool:  # noqa: ANN001 - urllib returns ParseResult
    if not parsed.query:
        return False
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in {"data", "token", "secret", "key", "email", "payload"}:
            return True
        if len(value) >= 24:
            return True
    return False
