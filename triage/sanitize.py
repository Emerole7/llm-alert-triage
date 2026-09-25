"""Reduce a raw Wazuh alert to the fields the LLM needs, and treat them as hostile.

Attackers control many alert fields (usernames, URLs, user agents, command
lines). Anything they control can carry text aimed at the model. This module:
  * keeps only the fields useful for triage
  * truncates long values and strips control characters
  * neutralises our own delimiter tags so data cannot "close" the data block
  * flags phrases that look like instructions to an AI
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

MAX_FIELD_CHARS = 800
MAX_FULL_LOG_CHARS = 1500

# Dotted paths kept from the alert _source.
KEEP_FIELDS = [
    "timestamp",
    "rule.id", "rule.level", "rule.description", "rule.groups",
    "rule.mitre.id", "rule.mitre.tactic", "rule.mitre.technique",
    "rule.firedtimes",
    "agent.id", "agent.name", "agent.ip",
    "manager.name",
    "location", "decoder.name",
    "data.srcip", "data.srcport", "data.dstip", "data.dstport", "data.srcuser", "data.dstuser",
    "data.url", "data.protocol", "data.status", "data.command",
    "data.win.system.eventID", "data.win.eventdata.targetUserName",
    "data.win.eventdata.commandLine", "data.win.eventdata.image",
    "data.win.eventdata.parentImage", "data.win.eventdata.ipAddress",
    "syscheck.path", "syscheck.event", "syscheck.sha256_after",
    "full_log",
]

DELIMITER_RE = re.compile(r"</?\s*(alert_data|enrichment|context)\s*>", re.IGNORECASE)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts?|rules)",
    r"disregard (all |any |the )?(previous|prior|above)",
    r"(forget|override) (your|all|the) (instructions|rules|prompt)",
    r"you are (now|no longer)",
    r"system prompt",
    r"(classify|mark|label|treat|report) (this|it|the alert|this alert) as (benign|false positive|safe|harmless)",
    r"do not (escalate|alert|report)",
    r"(new|updated) instructions",
    r"\bassistant\s*:",
    r"\bsystem\s*:",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def _get(src: Dict[str, Any], dotted: str) -> Any:
    cur: Any = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(dst: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = dst
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def clean_value(value: Any, limit: int = MAX_FIELD_CHARS) -> Any:
    if isinstance(value, list):
        return [clean_value(v, limit) for v in value[:20]]
    if isinstance(value, dict):
        return {k: clean_value(v, limit) for k, v in list(value.items())[:30]}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = CONTROL_RE.sub(" ", str(value))
    text = DELIMITER_RE.sub("[tag removed]", text)
    if len(text) > limit:
        text = text[:limit] + f"...[truncated {len(text) - limit} chars]"
    return text


def build_alert_view(source: Dict[str, Any]) -> Dict[str, Any]:
    view: Dict[str, Any] = {}
    for path in KEEP_FIELDS:
        val = _get(source, path)
        if val is None:
            continue
        limit = MAX_FULL_LOG_CHARS if path == "full_log" else MAX_FIELD_CHARS
        _set(view, path, clean_value(val, limit))
    return view


def _walk_strings(obj: Any) -> List[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _walk_strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _walk_strings(v)]
    return []


def detect_injection(view: Dict[str, Any]) -> List[str]:
    """Return the patterns that matched anywhere in the alert view.

    Separators like - _ . + are turned into spaces first, because attacker
    text often arrives squeezed into a username or URL path.
    """
    hits: List[str] = []
    for s in _walk_strings(view):
        normalised = re.sub(r"[-_.+/%]+", " ", s)
        for pattern in _INJECTION_RE:
            if pattern.search(normalised) and pattern.pattern not in hits:
                hits.append(pattern.pattern)
    return hits
