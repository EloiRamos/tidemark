# TIDEMARK Demo Runbook

This public runbook reproduces the deterministic judge-facing demo from a clean checkout.

## Prerequisites

- Python 3.9 or newer
- The offline deterministic demo requires no provider secret.

## Standard and capture commands

```bash
DEMO_DIR="$(mktemp -d)"
make preflight PROFILE=standard OUTPUT_DIR="$DEMO_DIR"
make demo PROFILE=standard OUTPUT_DIR="$DEMO_DIR"
CAPTURE_DIR="$(mktemp -d)"
make demo PROFILE=capture OUTPUT_DIR="$CAPTURE_DIR"
python3 -m http.server --bind 127.0.0.1 --directory "$DEMO_DIR" 8000
```

The offline deterministic demo requires no provider secret.

## Scenario contract

| Scenario | Decision | Primary rule | Execution | Starts | Payments |
|---|---|---|---|---:|---:|
| `BENIGN_ALLOW` | `ALLOW` | `authorization.allow.v1` | `COMPLETED` | 1 | 1 |
| `RAW_PROTECTED_VALUE_DENY` | `DENY` | `protected.raw_value_supplied.v1` | `NOT_STARTED` | 0 | 0 |
| `FORGED_OR_MISBOUND_REFERENCE_DENY` | `DENY` | `reference.not_found.v1` | `NOT_STARTED` | 0 | 0 |
| `BOUND_DENY` | `DENY` | `value.constraint_failed.v1` | `NOT_STARTED` | 0 | 0 |
| `REPLAY_REJECTION` | `ALLOW` | `authorization.allow.v1` | `COMPLETED` | 1 | 1 |
| `MODEL_NON_ATTEMPT` | `MODEL_NON_ATTEMPT` | `NOT APPLICABLE` | `NOT_STARTED` | 0 | 0 |

MODEL_NON_ATTEMPT ≠ DENY ≠ callback veto ≠ policy enforcement success

Each scenario run uses fresh construction and disposal so state does not carry across runs.

CAPTURE_SEMANTIC_SNAPSHOT_SCHEMA=tidemark.demo.capture-semantic-snapshot.v1

## Scan roles

The preflight scanner self-test verifies that the scanner fails closed before execution.
The later safe-surface scan evaluates candidate public outputs after materialization.

## Non-claim

This runbook reproduces current offline evidence. Historical live-model and cloud-provider evidence remains separate and does not imply a current provider call.
