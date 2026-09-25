"""Deterministic checks applied after the LLM answers.

The model recommends. These rules decide what it is allowed to dismiss.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from pydantic import ValidationError

from .schema import DISMISS, Priority, TriageResult, Verdict


def priority_from_level(level: int) -> Priority:
    if level >= 12:
        return Priority.P1
    if level >= 10:
        return Priority.P2
    if level >= 7:
        return Priority.P3
    return Priority.P4


def fallback_result(level: int, reason: str) -> TriageResult:
    return TriageResult(
        verdict=Verdict.NEEDS_INVESTIGATION,
        confidence=0.0,
        priority=priority_from_level(level),
        summary="Automated triage unavailable. Escalated for manual review.",
        reasoning=reason[:2000],
        recommended_actions=["Triage this alert manually."],
    )


def validate(raw: Dict[str, Any], level: int) -> Tuple[TriageResult, List[str]]:
    try:
        return TriageResult.model_validate(raw), []
    except ValidationError as exc:
        return fallback_result(level, f"LLM output failed schema validation: {exc.errors()[:3]}"), ["invalid_llm_output"]


# v2: identity and persistence activity is never auto-closed. Added after the
# v1 evaluation showed the model dismissing account creation on a host that
# was under an active SSH brute-force attack (MITRE T1136).
PROTECTED_RULE_GROUPS = {"adduser", "addgroup", "account_changed", "userdel", "groupdel"}
PROTECTED_MITRE_PREFIXES = ("T1136", "T1098")  # Create Account, Account Manipulation


def is_protected(rule_groups: List[str], mitre_ids: List[str]) -> bool:
    if PROTECTED_RULE_GROUPS.intersection(g.lower() for g in rule_groups or []):
        return True
    return any(str(m).startswith(PROTECTED_MITRE_PREFIXES) for m in mitre_ids or [])


def apply_guardrails(
    result: TriageResult,
    rule_level: int,
    injection_hits: List[str],
    high_severity_level: int = 12,
    rule_groups: List[str] | None = None,
    mitre_ids: List[str] | None = None,
) -> Tuple[TriageResult, List[str]]:
    overrides: List[str] = []
    data = result.model_dump()

    # 0. Identity / persistence changes always go to a human.
    if result.verdict in DISMISS and is_protected(rule_groups or [], mitre_ids or []):
        data["verdict"] = Verdict.NEEDS_INVESTIGATION
        if result.priority in (Priority.P3, Priority.P4):
            data["priority"] = Priority.P2
        overrides.append("identity_change_no_auto_dismiss")
        result = TriageResult.model_validate(data)

    # 1. Suspected prompt injection is never dismissed, and never below P2.
    if injection_hits or result.injection_suspected:
        data["injection_suspected"] = True
        if result.verdict in DISMISS:
            data["verdict"] = Verdict.NEEDS_INVESTIGATION
            overrides.append("injection_blocked_dismissal")
        if result.priority in (Priority.P3, Priority.P4):
            data["priority"] = Priority.P2
            overrides.append("injection_raised_priority")

    # 2. High-severity rules cannot be auto-dismissed.
    if rule_level >= high_severity_level and data["verdict"] in DISMISS:
        data["verdict"] = Verdict.NEEDS_INVESTIGATION
        overrides.append("high_severity_no_auto_dismiss")

    # 3. Low-confidence dismissals go to a human.
    if data["verdict"] in DISMISS and result.confidence < 0.7:
        data["verdict"] = Verdict.NEEDS_INVESTIGATION
        overrides.append("low_confidence_dismissal")

    return TriageResult.model_validate(data), overrides
