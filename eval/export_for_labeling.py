"""Export triaged alerts to a CSV for blind human labelling.

The LLM verdict is deliberately left out so it cannot bias your label.

    python eval/export_for_labeling.py            # writes eval/labels.csv
    python eval/export_for_labeling.py --limit 50

Fill the analyst_label column with one of: escalate, dismiss
  escalate = a Tier 1 analyst should look at this (malicious or unclear)
  dismiss  = safe to close without investigation (expected activity or bad rule match)
"""
from __future__ import annotations

import argparse
import csv
import json
import os

FIELDS = ["alert_id", "alert_timestamp", "rule_id", "rule_level", "rule_description",
          "agent_name", "srcip", "full_log", "analyst_label", "analyst_notes"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="output/triage_results.jsonl")
    p.add_argument("--out", default="eval/labels.csv")
    p.add_argument("--limit", type=int, default=0)
    args = p.parse_args()

    existing = {}
    if os.path.exists(args.out):
        with open(args.out, newline="") as fh:
            existing = {row["alert_id"]: row for row in csv.DictReader(fh)}

    rows = []
    with open(args.results) as fh:
        for line in fh:
            d = json.loads(line)
            prev = existing.get(d["alert_id"], {})
            rows.append({
                **{k: d.get(k, "") for k in FIELDS[:-2]},
                "analyst_label": prev.get("analyst_label", ""),
                "analyst_notes": prev.get("analyst_notes", ""),
            })
    if args.limit:
        rows = rows[: args.limit]

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.out} (existing labels kept)")


if __name__ == "__main__":
    main()
