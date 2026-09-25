"""Compare LLM verdicts with your labels and write eval/report.md.

    python eval/evaluate.py

Key numbers:
  agreement         how often the tool made the same escalate/dismiss call as you
  missed threats    alerts you would escalate that the tool dismissed (the one that matters)
  workload removed  share of all alerts the tool dismissed correctly
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter

ESCALATE = {"true_positive", "needs_investigation"}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="output/triage_results.jsonl")
    p.add_argument("--labels", default="eval/labels.csv")
    p.add_argument("--out", default="eval/report.md")
    args = p.parse_args()

    results = {}
    with open(args.results) as fh:
        for line in fh:
            d = json.loads(line)
            results[d["alert_id"]] = d

    with open(args.labels, newline="") as fh:
        labels = {r["alert_id"]: r for r in csv.DictReader(fh)
                  if r.get("analyst_label", "").strip().lower() in {"escalate", "dismiss"}}

    pairs = [(labels[a]["analyst_label"].strip().lower(), results[a]) for a in labels if a in results]
    if not pairs:
        raise SystemExit("no labelled alerts found. Fill analyst_label in eval/labels.csv first.")

    matrix = Counter()
    missed = []
    for human, r in pairs:
        tool = "escalate" if r["verdict"] in ESCALATE else "dismiss"
        matrix[(human, tool)] += 1
        if human == "escalate" and tool == "dismiss":
            missed.append(r)

    n = len(pairs)
    agree = matrix[("escalate", "escalate")] + matrix[("dismiss", "dismiss")]
    human_escalate = matrix[("escalate", "escalate")] + matrix[("escalate", "dismiss")]
    correct_dismiss = matrix[("dismiss", "dismiss")]
    latencies = [r["latency_ms"] for _, r in pairs if r.get("latency_ms")]
    verdicts = Counter(r["verdict"] for _, r in pairs)
    overrides = Counter(o for _, r in pairs for o in r.get("guardrail_overrides", []))
    injections = sum(1 for _, r in pairs if r.get("injection_suspected"))
    model = pairs[0][1].get("llm_model")

    lines = [
        "# Evaluation report",
        "",
        f"Model: `{model}`  ",
        f"Labelled alerts: **{n}**",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Agreement with analyst | **{agree / n:.0%}** ({agree}/{n}) |",
        f"| Missed threats (analyst escalate, tool dismiss) | **{len(missed)}** of {human_escalate} |",
        f"| Workload removed (correct dismissals / all alerts) | **{correct_dismiss / n:.0%}** |",
        f"| Escalated noise (analyst dismiss, tool escalate) | {matrix[('dismiss', 'escalate')]} |",
        f"| Prompt injection flagged | {injections} |",
    ]
    if latencies:
        lines.append(f"| Median / p95 latency | {statistics.median(latencies):.0f} ms / "
                     f"{sorted(latencies)[int(0.95 * (len(latencies) - 1))]:.0f} ms |")
    lines += [
        "",
        "## Confusion matrix",
        "",
        "| | Tool: escalate | Tool: dismiss |",
        "|---|---|---|",
        f"| **Analyst: escalate** | {matrix[('escalate', 'escalate')]} | {matrix[('escalate', 'dismiss')]} |",
        f"| **Analyst: dismiss** | {matrix[('dismiss', 'escalate')]} | {matrix[('dismiss', 'dismiss')]} |",
        "",
        "## Verdict distribution",
        "",
        *[f"- {k}: {v}" for k, v in verdicts.most_common()],
        "",
        "## Guardrail overrides",
        "",
        *([f"- {k}: {v}" for k, v in overrides.most_common()] or ["- none"]),
        "",
        "## Missed threats",
        "",
        *([f"- `{r['alert_id']}` rule {r['rule_id']} ({r['rule_description']}): {r['summary']}" for r in missed]
          or ["- none"]),
        "",
    ]
    with open(args.out, "w") as fh:
        fh.write("\n".join(lines))
    print("\n".join(lines[:15]))
    print(f"\nfull report: {args.out}")


if __name__ == "__main__":
    main()
