# TIDEMARK Product Boundary

**Version:** 1.0
**Status:** documentation baseline; pending human implementation start gate
**Date:** 2026-08-06

## 1. Definition

TIDEMARK is a deterministic runtime authorization boundary for side-effecting agent tool calls. It evaluates a complete proposed call before execution, requires protected arguments to resolve from runtime-trusted state, and records a masked explanation of the resulting authorization decision.

TIDEMARK is positioned between agent-authored tool-call arguments and the execution adapter. It does not ask the model to enforce policy and does not infer trust from the textual content of an argument.

## 2. Problem

Agent workflows routinely combine trusted operational data, untrusted documents, model-derived values, and side-effecting tools. A tool schema can constrain shape, but it cannot establish that a syntactically valid destination, recipient, account, or other protected value came from an authorized source. Prompt instructions are also not an enforcement boundary.

The product addresses one narrow failure mode: an untrusted or model-authored value reaching a protected argument of a side-effecting tool when that argument should be bound to a value selected from trusted runtime state.

## 3. Users

### Primary users

- Engineers building agent workflows that can cause external side effects.
- Security engineers reviewing tool authorization and provenance boundaries.
- Technical evaluators who need to inspect why a call was allowed or denied.

### Secondary users

- Demo operators validating a bounded reference workflow.
- Product reviewers assessing whether the control is understandable and correctly integrated.

End business users may see a decision explanation, but they are not policy authors in v1.0.

## 4. In-scope product behavior

The hackathon product will:

1. define explicit contracts for registered tools and their arguments;
2. classify argument roles, including which roles require runtime-resolved protected values;
3. mint opaque references inside trusted runtime components and keep resolved protected values server-side;
4. resolve and validate references against kind, invocation, parent binding, and lifecycle constraints;
5. canonicalize trusted policy authoring input into an immutable runtime snapshot;
6. resolve closed constraint identifiers through a runtime-owned trusted registry;
7. construct a complete prepared tool call before an execution decision;
8. apply deterministic structural, provenance, binding, lifecycle, and value-bound checks in a documented order;
9. prevent a denied call from reaching the side-effecting function;
10. execute an allowed call at most once under the reference workflow’s replay model;
11. emit correlated, masked evidence for preparation, decision, and execution outcome;
12. expose a read-only review surface that explains the call without disclosing protected values;
13. integrate Google ADK through a narrow adapter for the hackathon release while keeping the policy core free of ADK types;
14. use Gemini 3.6 Flash for the mandatory live model path only after its exact identifier, access path, quota, billing/funding source, and €0 personal-spend exposure are verified;
15. deploy a bounded backend component to Google Cloud for the hackathon submission under the mandatory zero-cost and human-approval controls.

## 5. Reference workflow boundary

The initial demonstration uses a business operation with a protected destination and a visible side effect. It must show:

- a legitimate call using untrusted business data and a runtime-resolved protected destination is allowed;
- a raw or forged protected destination is denied before execution;
- invocation, kind, and parent-binding mismatches are denied;
- a bounded business value outside trusted limits is denied;
- replay does not create a second side effect;
- decision output can be understood on one screen without exposing the protected value.

The workflow is a reference integration, not the definition of the core architecture. Payment-specific details must remain outside the reusable policy core.

## 6. Competition-constrained integration boundary

The official competition minimum is “Gemini 3.5 or newer”; TIDEMARK separately selects Gemini 3.6 Flash and Google ADK. Google Cloud deployment and proof are mandatory, and personal out-of-pocket spend is fixed at €0. Allowed funding, pre-integration verification, bounded cost controls, the no-substitution rule, and fail-closed exhaustion behavior remain fixed constraints.

These integration and deployment requirements do not expand TIDEMARK's security claim. The model remains untrusted, Google ADK remains a transport adapter, and Google Cloud remains a deployment boundary. A deterministic offline path may support development fallback, demo resilience, and evidence fallback, but it is not a substitute for live Gemini 3.6 Flash or mandatory Google Cloud proof.

## 7. Trust boundary

For v1.0, the trusted computing base consists of:

- the TIDEMARK runtime process and its reviewed implementation;
- the runtime-owned tool contract snapshot and constraint registry;
- configured trusted records used for protected-value resolution and bounds;
- the credentialed execution adapter and its authoritative side-effect store;
- the evidence sink for product-generated authorization records.

The model, prompts, conversation content, uploaded documents, raw tool-call arguments, UI client, and caller-owned policy authoring objects are not trusted sources of protected values.

Trusted runtime functions, module configuration loaded through the approved startup path, and the host/interpreter are assumed trustworthy. General interpreter, dependency, kernel, credential, or trusted-function compromise is outside v1.0.

## 8. What TIDEMARK is not

TIDEMARK is not:

- a prompt-injection detector or content classifier;
- a model behavior guarantee;
- a general authorization, identity, RBAC, delegation, or consent system;
- a policy authoring platform or general-purpose policy language;
- a secrets manager, key-management system, or cryptographic attestation protocol;
- an anomaly-detection, fraud-detection, or transaction-monitoring system;
- a substitute for tool input validation, business rules, authentication, or infrastructure security;
- a guarantee against malicious trusted runtime code or general host-language reflection;
- a production-ready payment system;
- the feasibility spike.

## 9. Explicit non-goals for the hackathon

- Multi-tenant isolation and tenant administration.
- End-user policy editing or dynamic policy deployment.
- Actor roles, permission grants, delegation, approval chains, or authority lifecycle.
- Declassification of protected values.
- Automatic discovery or protection of arbitrary third-party tools.
- Broad compatibility across agent frameworks.
- High availability, disaster recovery, regional failover, and production SLOs.
- Full cloud transaction semantics and retry correctness across distributed systems.
- Compliance certification, regulatory claims, or production security certification.
- General-purpose observability, analytics, or long-term evidence retention.
- Polished workflow management beyond the bounded review surface.
- A model-agnostic release path, silent provider/model fallback, personal paid usage, or an architecture dependent on recurring paid services.

## 10. Boundary-change rule

Any change that adds subjects, roles, grants, model-visible minting, policy authoring, new protected value classes, a new side-effecting tool, cloud persistence, a stronger security claim, a model/access-path substitution, or a change to the zero-cost boundary requires an explicit specification update and explicit human approval. It must not be introduced as an incidental implementation detail.

## 11. Related documents

- [System Architecture](../architecture/SYSTEM_ARCHITECTURE_v1.0.md)
- [Implementation Principles](IMPLEMENTATION_PRINCIPLES_v1.0.md)
