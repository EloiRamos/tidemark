# TIDEMARK Variant C W6 Prepared-Call Lifecycle

**Status:** W6 communication surface
**Scope:** Existing W1 ten-stage lifecycle

The diagram restates the committed W1 lifecycle without adding a second revalidation or stronger transaction semantics.

```mermaid
flowchart TB
    W1_L01["W1-L01 | untrusted proposal"]
    W1_L02["W1-L02 | representation and selection"]
    W1_L03["W1-L03 | trusted resolution and binding"]
    W1_L04["W1-L04 | deterministic policy decision"]
    W1_L05["W1-L05 | prepared-call sealing"]
    W1_L06["W1-L06 | execution-time revalidation"]
    W1_L07["W1-L07 | durable pre-execution evidence"]
    W1_L08["W1-L08 | atomic consume/effect boundary"]
    W1_L09["W1-L09 | execution/effect outcome"]
    W1_L10["W1-L10 | refusal, replay, and evidence distinction"]

    W1_L01 --> W1_L02
    W1_L02 --> W1_L03
    W1_L03 --> W1_L04
    W1_L04 --> W1_L05
    W1_L05 --> W1_L06
    W1_L06 --> W1_L07
    W1_L07 --> W1_L08
    W1_L08 --> W1_L09
    W1_L09 --> W1_L10

    VALID_PREPARED_CAPABILITY["valid prepared capability"]
    EXECUTION_TIME_GATE_VALIDATION["execution-time gate validation"]
    DURABLE_PRE_EXECUTION_EVIDENCE["durable pre-execution evidence"]
    LOCAL_ATOMIC_SINGLE_USE_CONSUMPTION_COMMIT["local atomic single-use consumption/commit"]
    ADAPTER_ENTRY["adapter entry"]
    OUTCOME_EVIDENCE["outcome evidence"]

    VALID_PREPARED_CAPABILITY --> EXECUTION_TIME_GATE_VALIDATION
    EXECUTION_TIME_GATE_VALIDATION --> DURABLE_PRE_EXECUTION_EVIDENCE
    DURABLE_PRE_EXECUTION_EVIDENCE --> LOCAL_ATOMIC_SINGLE_USE_CONSUMPTION_COMMIT
    LOCAL_ATOMIC_SINGLE_USE_CONSUMPTION_COMMIT --> ADAPTER_ENTRY
    ADAPTER_ENTRY --> OUTCOME_EVIDENCE

    W1_L04 -->|"DENY"| CONSTRUCTION_REFUSAL
    CONSTRUCTION_REFUSAL["construction refusal | DENY | no prepared call"]
    W1_L05 --> ALLOW_STATE
    ALLOW_STATE["ALLOW | prepared authority created, not execution"]
    EXECUTION_TIME_GATE_VALIDATION -->|"refusal"| POST_ALLOW_REFUSAL
    POST_ALLOW_REFUSAL["post-ALLOW execution refusal | zero adapter entry/effect"]
    OUTCOME_EVIDENCE --> COMPLETED_EXECUTION
    COMPLETED_EXECUTION["completed execution | separate adapter/payment/outcome evidence"]
    LOCAL_ATOMIC_SINGLE_USE_CONSUMPTION_COMMIT -->|"already consumed"| REPLAY_REJECTION
    REPLAY_REJECTION["replay rejection | no second effect"]
```

The authoritative transaction sequence is the single chain from `valid prepared capability` through `outcome evidence`. W1-L01 through W1-L10 preserve proposal, selection, trusted binding, deterministic decision, sealing, one execution-time validation, evidence-before-effect, the local atomic boundary, outcome, and refusal/replay distinctions.

The limits are explicit: `ALLOW != EXECUTED`, `LOCAL_AT_MOST_ONCE != EXTERNAL_EXACTLY_ONCE`, and `TEST_INTERLEAVING != DISTRIBUTED_EXACTLY_ONCE_PROOF`. This lifecycle does not assert a distributed transaction, scheduler fairness, or an external-effect exactly-once guarantee. It creates no evidence fact and grants no authority.
