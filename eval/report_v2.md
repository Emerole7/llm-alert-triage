# Evaluation report

Model: `claude-haiku-4-5-20251001`  
Labelled alerts: **46**

| Metric | Value |
|---|---|
| Agreement with analyst | **100%** (46/46) |
| Missed threats (analyst escalate, tool dismiss) | **0** of 42 |
| Workload removed (correct dismissals / all alerts) | **9%** |
| Escalated noise (analyst dismiss, tool escalate) | 0 |
| Prompt injection flagged | 2 |
| Median / p95 latency | 5884 ms / 6741 ms |

## Confusion matrix

| | Tool: escalate | Tool: dismiss |
|---|---|---|
| **Analyst: escalate** | 42 | 0 |
| **Analyst: dismiss** | 0 | 4 |

## Verdict distribution

- needs_investigation: 29
- true_positive: 13
- benign_true_positive: 4

## Guardrail overrides

- identity_change_no_auto_dismiss: 2

## Missed threats

- none
