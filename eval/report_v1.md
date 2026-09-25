# Evaluation report

Model: `claude-haiku-4-5-20251001`  
Labelled alerts: **46**

| Metric | Value |
|---|---|
| Agreement with analyst | **96%** (44/46) |
| Missed threats (analyst escalate, tool dismiss) | **2** of 42 |
| Workload removed (correct dismissals / all alerts) | **9%** |
| Escalated noise (analyst dismiss, tool escalate) | 0 |
| Prompt injection flagged | 2 |
| Median / p95 latency | 5884 ms / 6741 ms |

## Confusion matrix

| | Tool: escalate | Tool: dismiss |
|---|---|---|
| **Analyst: escalate** | 40 | 2 |
| **Analyst: dismiss** | 0 | 4 |

## Verdict distribution

- needs_investigation: 27
- true_positive: 13
- benign_true_positive: 6

## Guardrail overrides

- none

## Missed threats

- `_lvC2qABFyEi-9BobF-0` rule 5901 (New group added to the system.): New system group 'labuser1' (GID 1001) was created on pro1. Rule fired correctly but activity appears routine and isolated, consistent with legitimate account provisioning.
- `AFvC2qABFyEi-9BobGC0` rule 5902 (New user added to the system.): New user account 'labuser1' was created on the system. The activity appears routine for a lab environment with a single occurrence.
