"""Central registries for attacks and guardrails.

Attacks and guardrails self-register at import time via decorators. A *suite* is
then just a named predicate over the attack registry — "all exfiltration
attacks", "everything tagged owasp-llm01", "the smoke suite" — which keeps suite
definitions declarative and lets new attacks join a suite simply by carrying the
right category/tags, with no central list to update and forget.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from agent_redteam.types import AttackCategory


@dataclass
class AttackSpec:
    """Registry entry describing one attack and how to instantiate it."""

    id: str
    category: AttackCategory
    factory: Callable[[], object]  # returns an Attack instance
    tags: frozenset[str] = field(default_factory=frozenset)
    summary: str = ""


_ATTACKS: dict[str, AttackSpec] = {}
_GUARDRAILS: dict[str, Callable[[], object]] = {}


def register_attack(
    attack_id: str,
    category: AttackCategory,
    *,
    tags: Iterable[str] = (),
    summary: str = "",
) -> Callable[[Callable[[], object]], Callable[[], object]]:
    """Decorator: register an attack factory under a stable id.

    Ids are required to be unique and stable across versions (``pi.override.v1``)
    because they appear in reports and regression baselines; silently colliding
    two attacks would make a baseline compare meaningless, so we raise instead.
    """

    def deco(factory: Callable[[], object]) -> Callable[[], object]:
        if attack_id in _ATTACKS:
            raise ValueError(f"duplicate attack id: {attack_id!r}")
        _ATTACKS[attack_id] = AttackSpec(
            id=attack_id,
            category=category,
            factory=factory,
            tags=frozenset(tags),
            summary=summary or (factory.__doc__ or "").strip().split("\n")[0],
        )
        return factory

    return deco


def register_guardrail(
    name: str,
) -> Callable[[Callable[[], object]], Callable[[], object]]:
    def deco(factory: Callable[[], object]) -> Callable[[], object]:
        if name in _GUARDRAILS:
            raise ValueError(f"duplicate guardrail: {name!r}")
        _GUARDRAILS[name] = factory
        return factory

    return deco


def all_attacks() -> list[AttackSpec]:
    return sorted(_ATTACKS.values(), key=lambda s: s.id)


def all_guardrails() -> list[str]:
    return sorted(_GUARDRAILS)


def make_attack(attack_id: str) -> object:
    return _ATTACKS[attack_id].factory()


def make_guardrail(name: str) -> object:
    return _GUARDRAILS[name]()


def select_suite(name: str) -> list[AttackSpec]:
    """Resolve a suite name to the attacks it contains.

    Built-in suites:
      * ``all``      — every registered attack.
      * ``default``  — everything except the resource-exhaustion attacks, which
                       cost real tokens and are opt-in.
      * ``smoke``    — one fast, deterministic attack per category, for CI.
      * a category name (e.g. ``exfiltration``) — every attack in that category.
      * ``tag:<t>``  — every attack carrying tag ``t``.
    """
    attacks = all_attacks()
    if name == "all":
        return attacks
    if name == "default":
        return [a for a in attacks if a.category != AttackCategory.RESOURCE_EXHAUSTION]
    if name == "smoke":
        seen: dict[AttackCategory, AttackSpec] = {}
        for a in attacks:
            if "smoke" in a.tags and a.category not in seen:
                seen[a.category] = a
        return list(seen.values())
    if name.startswith("tag:"):
        want = name[4:]
        return [a for a in attacks if want in a.tags]
    try:
        cat = AttackCategory(name)
    except ValueError as exc:
        raise KeyError(f"unknown suite: {name!r}") from exc
    return [a for a in attacks if a.category == cat]
