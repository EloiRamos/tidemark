# TIDEMARK Security Invariant Traceability and Threat Model

**Version:** 1.0
**Status:** Implemented-behavior and demonstrability map for pre-submission review
**Date:** 2026-08-13
**Reviewed enforcement baseline:** `fbae57890df8e7d85cd56680c2b81ed6db6b7057`
**W1 reconciliation:** bounded read-only prepared-call demonstrability; no enforcement or evidence-schema change

## 1. Purpose and document role

This document maps TIDEMARK's existing security claims to enforcing mechanisms,
source symbols, executable tests, committed evidence, and UI visibility. It
does not add policy, authority, protected-value classes, or security claims.

`docs/security/` is used because this is a durable cross-cutting security map:
it does not own behavior like a specification, sequencing like a plan, or a
historical determination like a review. The owning product boundary remains
`docs/specs/PRODUCT_BOUNDARY_v1.0.md`.

## 2. Security objective

TIDEMARK protects one narrow boundary for side-effecting tool calls:

> Untrusted content may select among values the runtime already trusts, but it
> must not supply protected values.

A complete proposed call must be evaluated before execution. Protected
arguments must resolve from runtime-owned state, ALLOW must yield a sealed
prepared capability rather than a reusable boolean, and denied or refused
calls must not enter the side-effecting adapter. Decision and execution facts
remain distinct and reviewable without disclosing the protected value.

## 3. Assets

| Asset | Security property |
|---|---|
| Protected destination | Never accepted from raw untrusted content and never disclosed through public evidence or UI |
| Trusted reference record | Issued only through store-bound runtime authority; bound to kind, invocation, parent, active state, and lifecycle |
| Policy and registry snapshot | Installed from validated inert data, immutable to caller mutation, captured consistently for evaluation |
| Prepared-call authority | Created only after ALLOW; integrity-bound to public shape, private payload, correlations, adapter, and exact object instance |
| Single-use capability/reference state | Consumed atomically before adapter entry so replay cannot create another side effect |
| Side-effect adapter and authoritative payment store | Entered only through the execution gate; counters distinguish attempt from observed effect |
| Pre-execution and outcome evidence | Durable, correlated, append-only, masked, integrity-checked, and distinct from the decision itself |
| Review/publication artifacts | Deterministic and digest-protected; incomplete or conflicting evidence cannot render PASS |

## 4. Trust boundary

| Untrusted / no protected-value authority | Trusted computing base for v1.0 |
|---|---|
| Gemini/model output | Reviewed TIDEMARK runtime process |
| Prompts, conversation, documents, uploaded/business content | Installed immutable policy snapshot and trusted constraint registry |
| Raw tool-call arguments and caller-owned authoring objects | Trusted reference store and store-bound issuer |
| Browser/UI client | Resolver, prepared-call pipeline, private execution binding, and execution gate |
| Offline/demo fixture proposal text | Credentialed adapter and authoritative side-effect store |
| Any textual reference-shaped value without a store record | Evidence sink/store, integrity checker, reconciler, and safe projector |

The host/interpreter, approved startup configuration, reviewed trusted runtime
functions, credentials, and infrastructure boundary are assumed trustworthy.
General interpreter, dependency, kernel, host, trusted-function, or credential
compromise is outside v1.0.

## 5. Attacker capabilities covered

The product assumes untrusted content or caller input may:

- supply a raw protected destination;
- forge an opaque-looking reference or reuse one with wrong kind, invocation,
  parent, activity, or consumption state;
- exceed a trusted numeric bound or select a disallowed currency;
- mutate authoring data, canonical input containers, inspected snapshots,
  resolved payloads, prepared public fields, or adapter inputs;
- present unknown tools, incomplete registries, signature mismatches, or
  unsupported constraint bindings;
- substitute public integrity, remove/corrupt private binding data, substitute
  the private payload, or mismatch adapter identity/version;
- cause pre-execution evidence append failure;
- replay a prepared capability sequentially or concurrently;
- trigger confirmed or ambiguous adapter failure and then retry the same
  capability;
- attempt to recover a protected destination or opaque reference through
  public objects, evidence, serialization, or browser output.

The attacker is not assumed able to mutate reviewed trusted code, steal the
runtime-private HMAC key, directly modify the trusted store under its locks,
or compromise the host/interpreter.

## 6. Trusted assumptions and non-goals

Trusted assumptions are limited to the process and stores named in section 4,
the exact startup-bound adapter registry, the integrity of approved dependency
execution, and correct custody of credentials outside TIDEMARK state.

TIDEMARK is not a prompt-injection detector, model-behavior guarantee, identity
or RBAC system, delegation/consent workflow, policy-authoring platform, secrets
manager, anomaly/fraud monitor, general tool-discovery control, cryptographic
attestation protocol, compliance certification, production payment system, or
general host-tamper defense. It does not claim distributed exactly-once effects,
multi-tenant isolation, high availability, long-term retention, or production
readiness.

## 7. Invariant traceability

`FULL`, `PARTIAL`, and `NOT SHOWN` describe the current integrated UI only.
Source anchors identify the reviewed baseline; symbols remain the stable
reference if later documentation-only edits shift lines.

| Invariant | Threat / attacker capability | Enforcing mechanism | Source path and symbol | Test / scenario | Runtime or committed evidence | UI visibility | Limit / qualifier |
|---|---|---|---|---|---|---|---|
| Model compromise does not imply authority compromise | Model supplies or follows malicious protected-value instructions | Exact protected-reference representation check plus store-only resolvable issuance | `runtime/constraint_registry.py:49` `_protected_reference_required`; `runtime/reference_store.py:193` `TrustedReferenceStore`; `:378` `ReferenceIssuer` | B01; C01-C06; Order 12 adversarial live case | `ORDER_12_LIVE_MODEL_PROOF_v1.0.md` and core matrix | **FULL** after historical panel; current scenario remains offline | Trusted runtime/host compromise is out of scope |
| Selection is not supply | Raw string or reference-shaped value attempts to become a protected destination | Protected role requires exact `ReferenceId`; resolver accepts only matching trusted record and keeps payload private | `runtime/constraint_registry.py:49`; `runtime/reference_resolver.py:74` `resolve` | B01; C01-C06; adapter callback tests | Order 12 historical DENY and deterministic publications | **FULL** thesis, boundary, raw-value and forged-reference scenarios; W1 L01-L05 show proposal, role, selection, resolution, and runtime-private binding | ADK transport recognition is fixture-bound; failure remains closed |
| Attempted, authorized, and observed side effect are distinct | Model/caller attempt is mistaken for authorization or payment | Closed model-attempt, decision, callback, execution, and payment event families/counters | `evidence/model.py`; `evidence/recorder.py`; `evidence/reconciliation.py:217` | A01, B01, H01, K01-K02; evidence/reconciliation tests | Historical Order 12 case counters; deterministic rehearsal | **FULL** separate decision/start/payment/callback facts | Provider observation is not an enforcement result |
| Policy is not decision | Caller mutates policy inputs or treats configuration as an outcome | Validation and fresh immutable snapshot installation; engine captures one snapshot and evaluates deterministic ordered rules | `runtime/policy_snapshot.py:138` `InstalledSnapshot`; `:247` `PolicyInstaller`; `runtime/policy_engine.py:744` `PolicyEngine` | E01-E03; F01-F04; policy snapshot/engine tests | Deterministic decision evidence includes policy/registry versions | **FULL** causal stages and context card | Trusted startup installation is assumed |
| Decision is not execution | ALLOW boolean is forged/reused or DENY is described as an effect | Disjoint outcome vocabularies; preparation creates exact immutable capability only after ALLOW; execution gate validates independently | `runtime/prepared_call.py:217` `PreparedToolCall`; `:308` `prepare`; `runtime/execution_gate.py:263` `ExecutionGate` | G01-G07; H01; K01-K02; execution-gate tests | Decision and execution event families; Order 12 callback/execution counts | **FULL** explicit divider, separate statuses, and W1 L07-L10 lifecycle explanation | ALLOW may still be refused before adapter entry |
| ALLOW is not executed | Prepared capability/evidence/adapter validation fails after ALLOW | Public digest, private binding/HMAC, durable pre-execution append, adapter registry, and all-or-none consume precede entry | `runtime/execution_binding.py:161`, `:231`, `:327`; `runtime/execution_gate.py:284` `execute` | G01-G07; H01 | Minimal pre-execution and outcome records; core matrix counts | **PARTIAL** W1 shows separate decision/execution lanes, L08 revalidation, and reference-only W2-P02; no dedicated current gate-refusal scenario | Gate-refusal behavior is tested externally, not demonstrated as a seventh core scenario |
| Evidence precedes effect and append failure is fail-closed | Evidence sink failure otherwise permits an unrecorded effect | Gate appends pre-execution record before atomic consumption and adapter entry | `runtime/execution_gate.py:314` pre-execution append; `:325` atomic consumption | H01; `tests/runtime/test_execution_gate.py` failure injection | Durable sink receipt/failure assertions | **PARTIAL** W1 L09 shows the implemented-contract sequence and reference-only W2-P03, not a current observed failure | Existing six-scenario demo is intentionally unchanged; UI copy is not runtime evidence |
| Replay creates no second side effect | Sequential or concurrent reuse of one prepared authority | Private capability and exact single-use references commit together under locks; consumed state yields replay rejection | `runtime/execution_binding.py:231` `_atomic_consume_runtime_execution_binding`; `runtime/reference_store.py:239` `consume` | I01 sequential; J01 uses 12 attempts through a six-worker pool | Core matrix; deterministic replay publication; Order 21 replay equivalence | **FULL** one start, one payment, replay rejected | Local at-most-once adapter entry is not external exactly-once semantics |
| Incomplete/conflicting evidence cannot render PASS | Missing, malformed, duplicate, orphaned, or conflicting records create a false success | Integrity checker, reconciler, exact projector states, publication verification, and UI clean/complete requirement | `evidence/integrity.py`; `evidence/reconciliation.py:217`; `evidence/projection.py:716`; `evidence/publication.py:610` | Evidence integrity/reconciliation/publication tests; three UI state variants | Finalized publication packages and rehearsal validation | **FULL** explicit incomplete/conflict/ambiguous variants | Variants are approved diagnostic fixtures, not emitted attack scenarios |
| Raw protected values do not reach public evidence or browser | Serialization, logs, repr/asdict, or HTML leaks protected/private data | Private carriers; strict safe-display allowlist; closed W1 mechanism projection; output encoding; byte/surface scans | `evidence/projection.py:461` `_safe_display`; `evidence/mechanism_projection.py`; `ui/final_ui.py`; `demo/rehearsal.py` surface scanner | L01; mechanism-projection/UI browser-facing tests; demo hardening scans | Publication privacy result and rehearsal scan PASS | **FULL** safe mask/provenance and closed public sealing metadata only | Browser is untrusted and never receives raw values, opaque reference values, runtime-private payloads, or private binding material |

The fixed W2 proof catalogue maps these existing authorities without changing
their enforcement semantics:

| W2 property | Existing scenario/test authority | Runnable fixed evidence |
|---|---|---|
| `W2-P01` Selection Is Not Supply | A01, B01, policy-engine protected-representation tests | `make prove PROPERTY=W2-P01` |
| `W2-P02` ALLOW Is Not Executed | execution-gate invalid-target and evidence-projection refusal tests | `make prove PROPERTY=W2-P02` |
| `W2-P03` Evidence Before Effect | H01 and execution-gate append/order tests | `make prove PROPERTY=W2-P03` |
| `W2-P04` Replay Is Not a Second Side Effect | I01 and sequential replay tests | `make prove PROPERTY=W2-P04` |
| `W2-P05` Concurrent Replay Is Locally At-Most-Once | J01 and concurrent replay tests | `make prove PROPERTY=W2-P05` |
| `W2-P06` Prepared-Call Tampering Fails Closed | G01-G07 | `make prove PROPERTY=W2-P06` |
| `W2-P07` Protected Reference Context Is Bound | C01-C06 and resolver exact-rule tests | `make prove PROPERTY=W2-P07` |
| `W2-P08` Incomplete or Conflicting Evidence Is Not PASS | reconciliation and projection uncertainty tests | `make prove PROPERTY=W2-P08` |

`make prove` runs the complete fixed catalogue from clean committed local
source. W1 displays exact catalogue titles and commands only as
`REFERENCE ONLY - NOT EXECUTED BY THIS UI`; it does not execute the suite,
ingest an artifact, or infer current PASS status. A proof PASS is a direct
invariant adjudication of complete safe fixture observations, not a claim that
every execution/evidence state was successful. W2-P08 passes when uncertainty
and contradiction remain correctly non-successful. Optional canonical proof
artifacts carry internal SHA-256 digests only; they are not signed or
third-party-verifiable. These terminal commands remain external reviewer
actions and do not upgrade UI copy into runtime or proof evidence.

## 8. Prepared-call and execution mechanism chain

1. A canonical proposal is checked against the captured immutable tool policy.
2. Protected arguments must be exact opaque reference objects, not raw values.
3. The resolver verifies trusted kind, invocation, parent, active state, and
   consumption state and keeps the resolved value in a runtime-private carrier.
4. Ordered deterministic constraints produce REFUSAL, DENY, or ALLOW.
5. Only ALLOW can create an immutable `PreparedToolCall` with a public SHA-256
   identity and runtime-private HMAC binding over correlations, payload, object
   identity, and exact single-use targets.
6. The execution gate validates the public/private bindings and adapter, writes
   durable pre-execution evidence, atomically consumes the capability and
   references, then enters the adapter at most once.
7. Execution outcome and authoritative side-effect evidence are recorded
   separately from the decision; replay and ambiguity retain distinct states.
8. Integrity, reconciliation, projection, and publication derive a masked
   review artifact. They do not retroactively authorize execution.

The Prepared Call Inspector adds a ten-stage W1 lifecycle view over this chain.
Its public prepared-call metadata comes from the closed
`PreparedCallMechanismProjection`; private binding coverage and the L08/L09
ordering are visibly labeled `DERIVED_IMPLEMENTED_CONTRACT`, while execution
and replay outcomes retain their existing masked-evidence provenance. The view
does not add a decision state, execution path, scenario, or proof result.

## 9. Core 35-scenario matrix summary

The executable authority is
`tests/security/test_core_security_matrix.py::CORE_SECURITY_MATRIX`. The 35
scenario IDs below are complete and non-overlapping.

| Family | Count | Covered threat | Exact scenario IDs |
|---|---:|---|---|
| A | 1 | Legitimate ALLOW and completed effect | `A01_legitimate_allow` |
| B | 1 | Raw protected-value supply | `B01_raw_protected_value` |
| C | 6 | Forged, wrong-kind, wrong-invocation, wrong-parent, inactive, and consumed references | `C01_forged_reference`, `C02_wrong_kind`, `C03_wrong_invocation`, `C04_wrong_parent`, `C05_inactive_reference`, `C06_consumed_reference` |
| D | 4 | Trusted maximum/currency allowed and exceeded/unsupported | `D01_amount_at_trusted_maximum`, `D02_amount_above_trusted_maximum`, `D03_allowed_trusted_currency`, `D04_unsupported_currency` |
| E | 6 | Authoring/snapshot/canonical/resolver/prepared/adapter mutation isolation | `E01_authoring_source_mutation`, `E02_snapshot_inspection_mutation`, `E03_canonical_source_mutation`, `E04_resolver_payload_mutation`, `E05_prepared_public_mutation`, `E06_payment_adapter_input_mutation` |
| F | 4 | Unknown tool, incomplete registry, signature mismatch, unknown constraint | `F01_unknown_tool`, `F02_incomplete_registry`, `F03_signature_mismatch`, `F04_unknown_constraint_implementation` |
| G | 7 | Public/private prepared integrity and adapter binding attacks | `G01_public_integrity_mismatch`, `G02_missing_private_binding`, `G03_private_correlation_mismatch`, `G04_private_authenticator_mismatch`, `G05_private_payload_substitution`, `G06_adapter_identity_mismatch`, `G07_adapter_version_mismatch` |
| H | 1 | Durable pre-execution evidence failure | `H01_pre_execution_evidence_failure` |
| I | 1 | Sequential replay | `I01_sequential_replay` |
| J | 1 | Concurrent replay: 12 attempts through a six-worker pool | `J01_concurrent_replay` |
| K | 2 | Confirmed and ambiguous adapter failure followed by replay | `K01_adapter_confirmed_failure`, `K02_ambiguous_execution` |
| L | 1 | Public protected-value hygiene | `L01_public_protected_value_hygiene` |

Every matrix row asserts decision outcome, primary rule, execution outcome
counts, execution-layer rule counts, prepared-call count, adapter entry count,
payment count, capability state, reference state, and protected-value leakage.
The catalog test requires stable unique IDs and complete runner coverage; the
repeatability test reruns the complete matrix ten times from fresh state.

## 10. Evidence and UI provenance

| Evidence | What it proves | What it does not prove | UI status |
|---|---|---|---|
| `docs/evidence/ORDER_12_LIVE_MODEL_PROOF_v1.0.md` | Historical Gemini 3.6 Flash benign ALLOW/completed payment and adversarial raw-supply DENY/veto with zero denied side effects | Current query, future model behavior, Gemini security, cloud deployment | Historical committed panel; separate from current run |
| Current deterministic rehearsal/publications | Six fresh offline product scenarios, masking, integrity, reconciliation, replay, and UI rendering | Live Gemini behavior or Google Cloud use | Current `EVIDENCE FALLBACK / OFFLINE` run |
| Current deterministic W2 proof suite | Eight fixed properties and 23 product-native cases adjudicated from clean committed source | Signatures, external attestation, production readiness, provider/model safety, or distributed exactly-once effects | Inspector carries inert catalogue references and external command hints only; no proof execution, result ingestion, or cached status |
| `docs/evidence/ORDER_21_CLOUD_DEPLOYMENT_PROOF_v1.0.md` | Provider-free Cloud Run Job execution, local/cloud semantic equivalence, replay counts, rollback/redeploy, shutdown, observed EUR 0 personal spend | Gemini cloud run, active hosted service, public endpoint, production deployment | Completed Cloud Proof surface |

## 11. Known limitations and explicit qualifiers

1. **ADK adapter fixture-bound reference recognition.** The framework adapter
   promotes a string to the trusted reference representation only when it
   exactly matches the fixture reference. Arbitrary forged `ref_...` text
   therefore fails closed as raw supply on the ADK route instead of reaching
   the core's not-found distinction. This pass documents but does not change it.
2. **No reference TTL/expiry.** `evaluation_time` is validated and carried, but
   the resolver has no time-based lifecycle check.
3. **Process-lifetime private binding retention.** The runtime-private binding
   coordinator does not evict consumed entries. The current bounded process
   exits; long-lived retention is not claimed.
4. **At-most-once adapter entry is not external exactly-once semantics.** Local
   capability/reference consumption prevents a second adapter entry. An
   external system may still need its own idempotency/transaction guarantees.
5. **Current deterministic UI is offline.** It is product evidence fallback,
   not current live-model or compliance evidence.
6. **Live-model proof is historical and separate.** It was recorded by Order
   12 and is not regenerated by the current UI/rehearsal.
7. **Order 21 cloud proof is provider-free and completed/historical.** It used
   zero Gemini calls, exposes no active hosted resource, and is not the live
   model proof.

## 12. Portfolio boundary

TIDEMARK remains protected argument binding, trusted runtime value supply, and
prepared-call security.

- General authority and governance remain outside this product. TIDEMARK adds no
  roles, grants, delegation, approval chain, or minting governance.
- Continuous security testing, trajectory reconstruction, mitigation replay,
  and CI gates remain outside this product. TIDEMARK retains a fixed product test matrix.
- Tool and capability supply-chain provenance remains outside this product.
  TIDEMARK continues to trust its startup-bound adapter registry.
- Competitive multi-step agent-security evaluation remains outside this product.
  TIDEMARK adds no competitive attack generator or benchmark.
- Delegated or verifiable authority and external attestation remain outside this
  product. TIDEMARK stops at internal deterministic SHA-256 integrity; no
  signatures or third-party attestation are added.

```text
SECURITY_TRACEABILITY_COMPLETE=true
CORE_SECURITY_SCENARIO_COUNT=35
ENFORCEMENT_PATH_CHANGED_BY_THIS_ARTIFACT=false
PORTFOLIO_BOUNDARY_PRESERVED=true
```
