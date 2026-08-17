# TIDEMARK Runtime Contracts Specification

**Version:** 1.0
**Status:** execution baseline
**Date:** 2026-08-06

**Order 8 transaction reconciliation:** 2026-08-07

## 1. Purpose

This specification fixes the framework-neutral contracts needed for milestones M1–M3. It refines, but does not replace, the component boundaries in [System Architecture](../architecture/SYSTEM_ARCHITECTURE_v1.0.md). Product scope and trust assumptions remain owned by [Product Boundary](PRODUCT_BOUNDARY_v1.0.md) and [Implementation Principles](IMPLEMENTATION_PRINCIPLES_v1.0.md). Exact local execution ordering requires durable pre-execution evidence before one atomic local capability/reference consumption and adapter invocation.

Payment records, event envelopes, and UI projections are defined in [Evidence Model](TIDEMARK_EVIDENCE_MODEL_SPEC_v1.0.md). Names below are logical contract names; implementation language and serialization choices remain implementation decisions.

## 2. Normative conventions

- Inputs from agents, callers, documents, adapters, and policy-authoring objects are untrusted until validated and freshly canonicalized.
- `REFUSAL` means no executable runtime state or complete call could be constructed. `DENY` means a complete enough canonical proposal was evaluated and rejected. `ALLOW` is the only outcome that may create a prepared call.
- Identifiers are opaque non-empty strings with a named kind. Timestamps are UTC. Money uses an exact minor-unit integer and ISO currency code; floating-point money is unsupported.
- Public records are immutable values. No authoritative contract retains caller-owned collections, subclasses, callables, descriptors, or behavior-bearing objects.
- Every closed enum, rule identity, constraint identity, and evidence schema is versioned. Unknown values fail closed.

## 3. Runtime value contracts

### 3.1 Stable identities

| Identity | Purpose |
|---|---|
| `ToolId` | Registered tool, stable across framework adapters. |
| `ToolContractVersion` | Exact argument and role contract. |
| `PolicyVersion` | Installed immutable snapshot. |
| `RegistryVersion` | Tool and constraint registry set used at startup. |
| `InvocationId` | One agent/runtime invocation boundary. |
| `ParentId` | Trusted business record to which a reference is bound. |
| `ReferenceId` | Opaque lookup key; never a protected value. |
| `CallId` | One normalized proposed call. |
| `DecisionId` | One sealed authorization result. |
| `PreparedCallId` | One ALLOW-associated execution capability. |
| `ExecutionId` | One execution attempt/outcome correlation. |

IDs must not encode protected values or credentials. Logs and views may show only a short display form; correlation uses the full internal ID.

### 3.2 Tool registration

A `ToolRegistration` contains:

| Field | Required contract |
|---|---|
| `tool_id`, `contract_version` | Stable, unique pair. |
| `arguments` | Ordered, complete `ArgumentContract` collection. |
| `signature` | Canonical names, required/optional state, and supported scalar/domain types. |
| `effect_class` | Closed value; v1.0 reference workflow uses `SIDE_EFFECTING`. |
| `reversibility` | Closed value used for evidence only, not authorization inference. |
| `adapter_id`, `adapter_version` | Exact approved execution adapter. |
| `policy_version` | Snapshot that governs the tool. |
| `masking_profile_id` | Runtime-owned evidence projection. |

An `ArgumentContract` contains `name`, `position`, `type_id`, `required`, `role`, and ordered `constraint_bindings`. V1.0 roles are:

- `UNPROTECTED_INPUT`: caller/model proposal that is canonicalized and constrained.
- `PROTECTED_REFERENCE`: opaque reference that must resolve through trusted state.

Registration is atomic. Duplicate names or positions, signature mismatch, missing masking metadata, unknown roles/types/constraints, partial adapters, and incomplete policy coverage prevent the registry from becoming executable.

## 4. Immutable policy model

### 4.1 Authoring input

`PolicyAuthoringInput` is inert data containing a proposed `policy_version`, tool-to-contract bindings, ordered argument roles, and constraint bindings. Accepted leaves are exact supported scalars: string, boolean, bounded integer, or explicit null where the constraint schema permits it. Collections are accepted only at named structural locations.

An integer constraint-authoring parameter must be an exact integer value in the inclusive signed 64-bit interval `[-2^63, 2^63 - 1]` (`-9223372036854775808` through `9223372036854775807`). `bool`, integer subclasses, and values requiring coercion are not integer authoring values. This is an authoring representation bound only: it does not define runtime arithmetic semantics, add a constraint, or change any rule or constraint identity. Exact-type validation remains required.

The installer rejects internal runtime types, subclasses of accepted types, callables, descriptors, arbitrary objects, unsupported containers, extra fields, nested behavior-bearing values, unknown constraint IDs, invalid parameter names/types, and incomplete registry coverage.

### 4.2 Installation lifecycle

```text
validate exact authoring form
-> resolve closed registry identities
-> canonicalize into fresh runtime values
-> validate tool/signature/policy coverage
-> seal and publish snapshot atomically
```

`PolicyInstaller.install(authoring_input, tool_registry, constraint_registry)` returns exactly one of:

- `InstalledSnapshot(snapshot)`; or
- `InstallationRefusal(code, location, masked_detail)`.

No partial snapshot is published. Replacing an installed snapshot creates a new `PolicyVersion`; snapshots are never mutated in place. Evaluators receive a snapshot reference captured at call intake, so one call cannot observe a mid-evaluation policy change.

### 4.3 Policy snapshot

`PolicySnapshot` contains `policy_version`, `registry_version`, canonical tool policies, canonical argument contracts, ordered constraint bindings, `created_at`, and a non-secret integrity identifier. Inspection returns a detached masked view, never the authoritative internal graph.

Required invariants:

1. Equal canonical inputs and registry versions produce an equivalent snapshot.
2. Mutating authoring input or an inspection view cannot change evaluation.
3. Constraint behavior is absent from snapshot data and is selected only by the trusted registry.
4. Installation failure leaves the prior published snapshot unchanged and records a refusal.

## 5. Constraint and rule identities

### 5.1 Closed constraint IDs

| Constraint ID | Applies to | Parameters | Meaning |
|---|---|---|---|
| `protected.reference.required.v1` | Protected reference | none | Reject any raw or missing protected representation. |
| `reference.kind.equals.v1` | Resolution facts | `kind: string` | Require the trusted record kind. |
| `reference.invocation.equals.v1` | Resolution facts | none | Require binding to current invocation. |
| `reference.parent.equals.v1` | Resolution facts | none | Require binding to current trusted parent. |
| `reference.active.v1` | Resolution facts | none | Require unexpired, active lifecycle state. |
| `reference.single_use.v1` | Resolution facts/execution | none | Reject a consumed reference or prepared call. |
| `value.integer.maximum.v1` | Unprotected integer | `maximum: integer` | Require value at or below trusted bound. |
| `value.enum.member.v1` | Unprotected scalar | `members: ordered string list` | Require an exact member; list is freshly canonicalized. |

Adding or changing a constraint identity, parameters, or semantics requires explicit specification approval. Payment-specific labels are not permitted in the constraint registry.

### 5.2 Stable decision rule IDs and order

The first failing rule wins. All applicable arguments are validated within a stage before the pipeline proceeds; deterministic argument order is the tool contract order.

| Order | Rule ID | Result |
|---:|---|---|
| 1 | `runtime.policy_unavailable.v1` | `REFUSAL` |
| 2 | `contract.tool_unknown.v1` | `REFUSAL` |
| 3 | `contract.registry_incomplete.v1` | `REFUSAL` |
| 4 | `contract.signature_mismatch.v1` | `REFUSAL` |
| 5 | `contract.argument_shape_invalid.v1` | `DENY` |
| 6 | `protected.raw_value_supplied.v1` | `DENY` |
| 7 | `reference.not_found.v1` | `DENY` |
| 8 | `reference.kind_mismatch.v1` | `DENY` |
| 9 | `reference.invocation_mismatch.v1` | `DENY` |
| 10 | `reference.parent_mismatch.v1` | `DENY` |
| 11 | `reference.inactive.v1` | `DENY` |
| 12 | `reference.already_consumed.v1` | `DENY` |
| 13 | `value.constraint_failed.v1` | `DENY` |
| 14 | `authorization.allow.v1` | `ALLOW` |

Execution-time integrity failures use `execution.prepared_call_invalid.v1` or `execution.replay_rejected.v1`; they are execution refusals, not retroactive policy decisions.

## 6. Policy engine interfaces

`PolicyEngine.evaluate(snapshot, canonical_call, resolution_set, call_context) -> Decision`

Inputs:

- `canonical_call`: registered tool identity plus complete canonical unprotected inputs and opaque protected references;
- `resolution_set`: one runtime-only `ResolutionResult` per protected role;
- `call_context`: invocation, trusted parent, captured versions, and correlation IDs;
- `snapshot`: the exact installed snapshot captured at intake.

The engine performs no I/O, minting, persistence, model call, clock read, or side effect. Time-dependent facts are supplied by the resolver/context. It returns a sealed `Decision` with outcome, stage, primary rule ID, all evaluated rule results in stable order, versions, correlations, and masked facts. Only `ALLOW` carries authorization to construct a prepared call.

## 7. Resolver interfaces

`ReferenceResolver.resolve(request, trusted_store) -> ResolutionResult`

`ResolutionRequest` contains `reference_id`, expected kind, `invocation_id`, `parent_id`, protected argument name, and evaluation time. `ResolutionResult` is either:

- `Resolved`: runtime-only protected value plus trusted provenance, binding, expiry/lifecycle, and consumption facts; or
- `ResolutionFailure`: stable rule ID and masked facts.

The resolver must perform lookup and validation through the trusted store only. It must not accept a protected value from the request, return one to an adapter/model/UI, or mutate consumption state during policy evaluation.

`ReferenceIssuer.issue(trusted_record, binding, lifecycle) -> ReferenceId` is an internal runtime interface. It is not a registered model tool or UI action. Issuance and storage authority remain outside the policy engine.

## 8. Prepared tool call model

`PreparedToolCall` is created only after `ALLOW` and contains:

- `prepared_call_id`, `call_id`, `decision_id`, `invocation_id`;
- `tool_id`, contract/policy/registry versions;
- immutable canonical arguments, with resolved protected values held only in the runtime execution payload;
- `adapter_id` and version;
- single-use state reference and non-secret integrity identifier.

It must not contain raw agent argument objects, resolver/store handles, mutable policy structures, or evidence presentation data. It cannot be serialized to the model or UI.

Successful preparation also creates one runtime-private execution-consumption binding outside the public `PreparedToolCall` dataclass fields and all public inspection paths. The binding is keyed and correlated to `PreparedCallId` and `DecisionId`, binds the exact detached runtime payload through runtime-private integrity metadata, identifies the exact trusted-store `ReferenceId` targets governed by `reference.single_use.v1`, and owns authoritative `UNUSED`/`CONSUMED` capability state. It is created only by the trusted preparation path, cannot be caller-supplied or replaced, exposes no protected-value-derived public identifier, and never enters model, UI, log, evidence, adapter, `repr`, `vars`, or `asdict` data. The public integrity identifier remains non-secret and continues to exclude all runtime argument values.

`ExecutionGate.execute(prepared_call) -> ExecutionOutcome` accepts only the exact `PreparedToolCall` type and verifies the ALLOW correlations, captured versions, trusted adapter binding, public and runtime-private integrity, private consumption binding, and unused authoritative state. Raw proposals, canonical calls, resolution results, decisions, evidence receipts, and caller argument mappings are not executable inputs. The gate accepts no caller-supplied adapter callable.

Execution requires durable pre-execution evidence first; one atomic local transition that consumes the prepared capability and every required single-use protected reference; one trusted adapter invocation after commit; and one immutable execution outcome. Capability/reference state is never restored after adapter entry, including confirmed failure, timeout, interruption, ambiguous external result, or outcome-evidence failure. Automatic adapter retry is not permitted in v1.0, and execution never mutates the original policy `Decision`.

## 9. Evidence interfaces

Order 8 has a minimal prerequisite, `MinimalPreExecutionEvidenceSink`, that provides only append-only local durable pre-execution correlation and local execution-outcome records plus explicit success/failure receipts. A pre-execution append success receipt may be returned only after the complete allowlisted record is atomically appended, flushed, and synchronized through the local durability primitive. Failure occurs before capability claim, reference consumption, or adapter invocation and fails closed. The minimal record contains no protected value, runtime argument value, `ReferenceId`, private integrity metadata, secret, store handle, or evidence projection. It is prerequisite evidence only and cannot authorize execution.

The complete `EvidenceSink.append(event) -> AppendReceipt` interface remains append-only and returns a durable event identity. The full `EvidenceRecorder`, event families, queries, projection, reconciliation, payment/demo evidence, export, and broader local store are implemented in the later evidence milestone. That implementation must extend or replace the minimal sink without weakening evidence-before-effect ordering and atomic local consumption.

`EvidenceProjector.project(event_stream, masking_profile) -> ReviewProjection` is deterministic and read-only. It receives evidence records, never runtime-only protected values.

Runtime components emit through an `EvidenceRecorder` at intake, installation refusal, decision, callback transition, execution transition, and authoritative outcome. Event shapes and correlation invariants are defined in [Evidence Model](TIDEMARK_EVIDENCE_MODEL_SPEC_v1.0.md).

## 10. Failure boundaries and non-goals

- Startup/installation inconsistency produces refusal and no executable registry or new snapshot.
- Call-shape, protected representation, resolution, binding, lifecycle, replay, and value-bound failures never create a prepared call.
- Required pre-execution evidence append failure leaves the prepared capability and all protected references unconsumed and invokes no adapter.
- The prepared capability and all required single-use protected references are consumed atomically in one local transaction before adapter entry; partial consumption is forbidden.
- Adapter or external-system failure after `ALLOW` is `FAILED`, not `DENY`; ambiguous external results are also `FAILED` without asserting that no side effect occurred.
- Adapter failure, ambiguity, or post-execution evidence failure does not restore capability/reference state and never triggers automatic adapter retry.
- This specification does not define identity, roles, policy administration, distributed transactions, retries, multiple side-effecting tools, or general host tamper resistance.
