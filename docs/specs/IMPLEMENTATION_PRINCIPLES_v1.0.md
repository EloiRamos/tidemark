# TIDEMARK Implementation Principles

**Version:** 1.0
**Status:** normative
**Date:** 2026-08-06

## 1. Purpose

These principles govern product implementation and review. They translate validated feasibility evidence into repository-level engineering constraints without prescribing a programming language or copying an earlier design. Model selection, access verification, and zero-cost operation remain fixed release constraints.

## 2. Deterministic runtime

Authorization must be a deterministic function of canonical runtime inputs, a named policy snapshot, trusted resolution state, and explicit call context. Model output may propose a call, but it does not participate in policy interpretation.

Required consequences:

- policy evaluation performs no model calls, network lookups to untrusted sources, or probabilistic classification;
- validation and rule ordering are explicit and stable;
- equal canonical inputs under the same policy version produce equal decisions;
- failure to parse, resolve, validate, or identify required policy state produces refusal or DENY, never a permissive fallback;
- legitimate ALLOW behavior is tested alongside failure behavior.

## 3. Runtime-owned policy

The runtime owns the executable meaning of policy. Callers may provide data through an approved authoring surface, but they may not supply executable constraint behavior or authoritative internal representations.

Policy data uses closed identifiers, exact supported scalar parameters, and explicit versioning. Trusted constraint implementations are selected from a private runtime registry. Unknown identifiers, unsupported parameter types, subclasses, behavior-bearing objects, and caller-created internal types are rejected before an executable policy snapshot exists.

## 4. Immutable authorization state

Construction follows a strict lifecycle:

```text
validate authoring input -> canonicalize into fresh values -> seal snapshot -> evaluate only the snapshot
```

The evaluated state must not retain caller-owned mutable or executable objects. Public inspection views must not be authoritative write paths. Ordinary post-construction changes to source mappings, role definitions, metadata, constraint parameters, or exposed views must not alter decisions.

This is an application integrity guarantee within the stated boundary, not a claim of general host-language tamper resistance.

## 5. Trusted registries

Every executable tool must have complete runtime-owned registration metadata:

- tool identity and invocation adapter;
- canonical signature information;
- argument contract and protected-role metadata;
- effect classification;
- policy version;
- evidence classification and masking requirements.

Every executable constraint must be resolved by a closed runtime-owned registry. Registry coverage is checked at startup or policy installation. Empty, partial, inconsistent, or unknown entries fail closed. Model-visible tool discovery is not an authority source.

## 6. Protected arguments are references, not raw values

For a protected role, the proposed call carries an opaque reference. The resolver validates that reference and obtains the protected value from trusted state. Raw caller or model values do not become trusted because they match a schema, resemble a reference, or equal a known string.

References are bound as narrowly as required by the workflow, including kind, invocation, parent record, expiry or lifecycle, and single-use status where applicable. Minting and resolution remain runtime functions and are not exposed as unrestricted model tools.

## 7. Prepared tool calls

The execution adapter receives only a prepared tool call produced by the trusted pipeline. Preparation must:

1. identify the registered tool and policy snapshot;
2. validate contract and signature parity;
3. canonicalize non-protected inputs;
4. resolve and validate protected references;
5. evaluate all authorization rules;
6. create an immutable execution payload and decision correlation;
7. expose the payload to execution only after ALLOW.

Raw agent arguments and mutable intermediate structures must not bypass this pipeline.

## 8. Explicit threat-model boundaries

Security claims must name what is trusted, what is attacker-controlled, and what is excluded. A boundary is part of the product contract, not a caveat to be added after implementation.

At v1.0, TIDEMARK protects against untrusted or model-authored supply of protected tool arguments and ordinary caller mutation of authorization inputs. It does not protect against compromise of trusted runtime code, the host, interpreter, dependencies, credentials, or trusted stores; nor does it provide identity, delegation, or policy-authoring correctness.

Semantically wrong but structurally valid human-authored contracts remain a review risk. The runtime can validate structure and trusted registry coverage, not the intent of the author.

## 9. Evidence-first engineering

Every authorization-relevant behavior must have an observable result that can be verified without exposing protected data.

- Refusal, DENY, ALLOW, execution, replay, and model non-attempt are distinct states.
- A DENY record includes the policy version, rule identifier, tool, argument role or stage, correlation identifiers, and masked reason data.
- An ALLOW record is correlated with exactly one execution outcome in the bounded workflow.
- Denied side-effect absence is proved through an execution marker or authoritative store check.
- Evidence is produced from the definitive repository. Spike evidence may support design provenance but cannot satisfy product acceptance tests.
- Published evidence is immutable or versioned and integrity-checked after finalization.

## 10. Smallest sufficient mechanism

Prefer the least powerful mechanism that satisfies the documented boundary:

- closed registries over executable user policy;
- opaque server-side references over model-visible protected values;
- explicit adapters over framework-wide coupling;
- local deterministic tests before external integration;
- one reference workflow before generalized platforms;
- read-only review views before policy administration;
- bounded persistence interfaces before distributed infrastructure.

Additional mechanism requires a current product need, a boundary review, and acceptance evidence.

## 11. Separation of concerns

The policy core must remain independent of:

- payment-specific business records;
- a specific model provider;
- agent-framework callback types;
- UI rendering;
- cloud service APIs;
- evidence presentation formats.

Adapters translate those concerns into stable domain inputs and consume domain outputs. They do not redefine policy semantics.

The provider-independent core does not make the release model optional. The hackathon integration adapter must use Gemini 3.6 Flash through Google ADK after its access path passes the required verification.

## 12. Selected integration and zero-cost operation

- Gemini 3.6 Flash is the only authorized live implementation model; another model or path is not an automatic resilience mechanism.
- Before any live request, verify the exact identifier, supported Gemini API or Vertex AI path, quota, billing/funding source, coverage/expiry, and fail-closed exhaustion behavior.
- Do not assume Google AI Studio, Gemini API, Vertex AI, Google Cloud trial credits, or hackathon credits share a balance without official documentation or direct console evidence.
- Personal out-of-pocket spend is €0. Use only verified trial credits, granted hackathon credits, official free tiers, and open-source software.
- Cloud deployment must configure a budget alert before deployment, maximum capacity, scale-to-zero where supported, minimum viable resources, daily spend review, and shutdown/rollback.
- Offline deterministic operation is limited to development fallback, demo resilience, and evidence fallback. It does not satisfy live Gemini or cloud-deployment acceptance.

Unavailability or quota exhaustion stops live use, records a blocker, and requires human approval before any substitution or billing upgrade. No failure mode silently changes model, provider path, billing source, or cost exposure.

## 13. Review checklist

Before accepting an implementation slice, confirm:

- all policy inputs are canonical and runtime-owned at evaluation time;
- no caller executable or behavior-bearing parameter is retained;
- registry coverage is complete and checked;
- protected roles cannot accept raw values;
- the prepared-call path is the only route to execution;
- denied calls cannot invoke the tool body;
- ALLOW and DENY evidence are correlated and masked;
- replay and failure behavior match the declared lifecycle;
- live-model evidence names Gemini 3.6 Flash and the verified access path; no hidden substitution occurred;
- allowed funding, budget/capacity controls, daily consumption checks, and €0 personal spend are evidenced for live/cloud work;
- offline fallback is labeled and is not counted as mandatory live integration or deployment proof;
- the change stays within [Product Boundary](PRODUCT_BOUNDARY_v1.0.md);
- any reused feasibility code has a recorded manual provenance and invariant review.
