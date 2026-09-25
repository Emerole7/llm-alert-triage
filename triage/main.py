"""Poll Wazuh for new alerts, triage each one with an LLM, write verdicts back.

Usage:
    python -m triage.main            # run continuously
    python -m triage.main --once     # process one batch and exit
    python -m triage.main --check    # test the indexer connection only
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from .config import Settings, load_settings
from .enrich import Enricher
from .guardrails import apply_guardrails, fallback_result, validate
from .llm import make_backend
from .prompt import SYSTEM_PROMPT, build_user_message
from .sanitize import build_alert_view, detect_injection
from .wazuh_client import WazuhIndexer

log = logging.getLogger("triage")


def load_state(path: str, lookback_minutes: int) -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    since = int((time.time() - lookback_minutes * 60) * 1000)
    return {"since_ms": since, "seen_ids": []}


def save_state(path: str, state: Dict[str, Any]) -> None:
    state["seen_ids"] = state["seen_ids"][-1000:]
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def append_jsonl(path: str, doc: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(doc, default=str) + "\n")


def triage_hit(hit: Dict[str, Any], s: Settings, indexer: WazuhIndexer, enricher: Enricher, backend) -> Dict[str, Any]:
    src = hit["_source"]
    rule = src.get("rule", {}) or {}
    level = int(rule.get("level", 0))
    srcip = (src.get("data", {}) or {}).get("srcip")

    view = build_alert_view(src)
    injection_hits = detect_injection(view)
    enrichment = enricher.enrich(src)
    context = {
        "same_rule_same_source_last_hour": indexer.count_related(s.alerts_index, str(rule.get("id")), srcip),
        "pre_llm_injection_scan": injection_hits or "no patterns matched",
    }

    error = None
    started = time.perf_counter()
    try:
        raw = backend.triage(SYSTEM_PROMPT, build_user_message(view, enrichment, context))
        result, validation_flags = validate(raw, level)
    except Exception as exc:  # network, API or parsing failure: fail safe, escalate
        log.error("LLM call failed for alert %s: %s", hit["_id"], str(exc)[:300])
        error = type(exc).__name__
        result, validation_flags = fallback_result(level, f"LLM call failed: {exc}"), ["llm_call_failed"]
    latency_ms = int((time.perf_counter() - started) * 1000)

    rule_groups = list(rule.get("groups") or [])
    mitre_ids = list((rule.get("mitre") or {}).get("id") or [])
    result, overrides = apply_guardrails(
        result, level, injection_hits, s.high_severity_level, rule_groups, mitre_ids
    )

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": hit["_id"],
        "alert_index": hit["_index"],
        "alert_timestamp": src.get("timestamp"),
        "rule_id": str(rule.get("id")),
        "rule_level": level,
        "rule_description": rule.get("description"),
        "rule_groups": rule_groups,
        "rule_mitre": mitre_ids,
        "agent_name": (src.get("agent", {}) or {}).get("name"),
        "srcip": srcip,
        "full_log": (src.get("full_log") or "")[:500],
        **result.model_dump(mode="json"),
        "injection_patterns": injection_hits,
        "guardrail_overrides": validation_flags + overrides,
        "enrichment": enrichment,
        "llm_backend": backend.name,
        "llm_model": backend.model,
        "latency_ms": latency_ms,
        "error": error,
    }


def run_batch(s: Settings, indexer: WazuhIndexer, enricher: Enricher, backend, state: Dict[str, Any]) -> int:
    hits = indexer.fetch_alerts_since(s.alerts_index, state["since_ms"], s.min_rule_level, s.batch_size)
    seen = set(state["seen_ids"])
    processed = 0
    for hit in hits:
        if hit["_id"] in seen:
            continue
        doc = triage_hit(hit, s, indexer, enricher, backend)
        indexer.index_result(s.results_index, doc)
        append_jsonl(s.output_jsonl, doc)
        log.info(
            "rule=%s lvl=%s -> %s %s conf=%.2f %sms %s",
            doc["rule_id"], doc["rule_level"], doc["verdict"], doc["priority"],
            doc["confidence"], doc["latency_ms"],
            f"overrides={doc['guardrail_overrides']}" if doc["guardrail_overrides"] else "",
        )
        state["seen_ids"].append(hit["_id"])
        if hit.get("sort"):
            state["since_ms"] = int(hit["sort"][0])
        save_state(s.state_file, state)
        processed += 1
    return processed


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM alert triage for Wazuh")
    parser.add_argument("--once", action="store_true", help="process one batch and exit")
    parser.add_argument("--check", action="store_true", help="test indexer connection and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("httpx", "httpx2", "anthropic", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    s = load_settings()
    indexer = WazuhIndexer(s.indexer_url, s.indexer_user, s.indexer_pass, s.ca_cert, s.verify_tls)

    info = indexer.ping()
    log.info("connected to indexer %s (version %s)", info.get("cluster_name"), info.get("version", {}).get("number"))
    if args.check:
        return 0

    indexer.ensure_results_index(s.results_index)
    enricher = Enricher(s.abuseipdb_key, s.virustotal_key)
    backend = make_backend(s)
    state = load_state(s.state_file, s.lookback_minutes)
    log.info("backend=%s model=%s min_level=%s", backend.name, backend.model, s.min_rule_level)

    while True:
        try:
            n = run_batch(s, indexer, enricher, backend, state)
            if n:
                log.info("processed %d alerts", n)
        except KeyboardInterrupt:
            return 0
        except Exception:
            log.exception("batch failed, retrying next cycle")
        if args.once:
            return 0
        time.sleep(s.poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
