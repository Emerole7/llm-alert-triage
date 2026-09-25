"""Re-apply the current guardrails to recorded LLM decisions.

Lets you change guardrail logic and measure the effect on the exact same model
outputs, with no new API calls. Rule groups and MITRE IDs are fetched from the
Wazuh indexer by alert ID, so the SSH tunnel must be open.

    python eval/replay_guardrails.py \
        --in output/triage_results.jsonl --out output/triage_results_v2.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.config import load_settings  # noqa: E402
from triage.guardrails import apply_guardrails  # noqa: E402
from triage.schema import TriageResult  # noqa: E402
from triage.wazuh_client import WazuhIndexer  # noqa: E402

DECISION_FIELDS = ["verdict", "confidence", "priority", "mitre_techniques", "summary",
                   "reasoning", "recommended_actions", "injection_suspected"]


def fetch_rules(indexer: WazuhIndexer, index: str, ids: list) -> dict:
    out = {}
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        r = indexer.session.post(
            f"{indexer.url}/{index}/_search",
            json={"size": len(chunk), "_source": ["rule.groups", "rule.mitre.id"],
                  "query": {"ids": {"values": chunk}}},
            timeout=30,
        )
        r.raise_for_status()
        for h in r.json()["hits"]["hits"]:
            rule = h["_source"].get("rule", {})
            out[h["_id"]] = (rule.get("groups") or [], (rule.get("mitre") or {}).get("id") or [])
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="src", default="output/triage_results.jsonl")
    p.add_argument("--out", default="output/triage_results_v2.jsonl")
    args = p.parse_args()

    s = load_settings()
    indexer = WazuhIndexer(s.indexer_url, s.indexer_user, s.indexer_pass, s.ca_cert, s.verify_tls)
    rows = [json.loads(line) for line in open(args.src)]
    rules = fetch_rules(indexer, s.alerts_index, [r["alert_id"] for r in rows])

    changed = 0
    with open(args.out, "w") as fh:
        for r in rows:
            groups, mitre = rules.get(r["alert_id"], (r.get("rule_groups", []), r.get("rule_mitre", [])))
            decision = TriageResult.model_validate({k: r[k] for k in DECISION_FIELDS})
            new, overrides = apply_guardrails(decision, r["rule_level"], r.get("injection_patterns", []),
                                              s.high_severity_level, groups, mitre)
            if new.verdict.value != r["verdict"]:
                changed += 1
                print(f"changed: rule {r['rule_id']} {r['rule_description']!r}: "
                      f"{r['verdict']} -> {new.verdict.value} {overrides}")
            r.update(new.model_dump(mode="json"))
            r["rule_groups"], r["rule_mitre"] = groups, mitre
            r["guardrail_overrides"] = sorted(set(r.get("guardrail_overrides", []) + overrides))
            r["guardrail_version"] = "v2"
            fh.write(json.dumps(r, default=str) + "\n")
    print(f"replayed {len(rows)} decisions, {changed} verdicts changed -> {args.out}")


if __name__ == "__main__":
    main()
