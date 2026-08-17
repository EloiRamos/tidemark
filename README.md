# TIDEMARK

> **Selection, not supply.** Untrusted content may select among values the
> runtime already trusts. It may never supply a protected value to a
> side-effecting tool.

TIDEMARK is a deterministic runtime boundary between model-authored tool
arguments and a trusted execution adapter. A model can propose an opaque
reference; the runtime alone can resolve it to a protected value. TIDEMARK then
evaluates the complete call under an immutable policy snapshot, creates sealed
single-use prepared authority only after `ALLOW`, vetoes invalid or replayed
calls before side effects, and emits masked evidence that keeps policy,
decision, execution, and observed effects distinct.

## Current status

The bounded product is implemented. It includes the framework-neutral runtime,
Google ADK callback adapter, synthetic payment vertical slice, append-only
evidence and publication pipeline, 35-scenario adversarial security matrix,
deterministic six-scenario demo, and integrated read-only Security Decision
Trace UI. The fresh full release suite passes all 1,107 tests under the
documented validation environment.

The provenance boundaries are deliberately explicit:

- **Current integrated demo:** deterministic `EVIDENCE FALLBACK / OFFLINE`;
  it makes no provider or Google Cloud request.
- **Historical live-model proof:** Gemini 3.6 Flash through Google ADK and the
  Gemini Developer API produced a benign ALLOW/completed payment and an
  adversarial raw-supply DENY/veto with zero denied side effects. See
  [Order 12 Historical Live-Model Proof](docs/evidence/ORDER_12_LIVE_MODEL_PROOF_v1.0.md).
- **Historical cloud proof:** the same deterministic semantics ran in a bounded
  provider-free Cloud Run Job, then rollback/redeploy and shutdown were
  verified. It used zero Gemini calls and is not an active hosted service. See
  [Order 21 Cloud Deployment Proof](docs/evidence/ORDER_21_CLOUD_DEPLOYMENT_PROOF_v1.0.md).

Video evidence is complete and the submission package is prepared.
TIDEMARK is a hackathon-quality security mechanism and evidence product, not a
production-ready payment or general agent-authorization system.

This validated release contains 120 files, including a proprietary
evaluation-only licence. The project licence decision is resolved.

## Third-party dependency notices

The runtime pins `google-adk==1.18.0` and `google-genai==1.47.0`
(Apache-2.0), while development verification pins `pytest==8.4.2` (MIT).
The historical live-model evidence also records `google-genai==1.47.0`.
These notices describe third-party
dependencies; they do not select or imply a licence for TIDEMARK. No dependency
wheel, site-package tree, model, TTS asset, or vendored payload is redistributed
in this source snapshot.

## Prepared Call Lifecycle Explorer

The existing **Prepared Call Inspector** now includes a read-only Prepared Call
Lifecycle Explorer. It explains the mechanism in ten fixed stages without
changing or claiming new enforcement behavior:

```text
UNTRUSTED PROPOSAL
-> PROTECTED-ROLE RECOGNITION
-> TRUSTED HANDLE SELECTION
-> RUNTIME RESOLUTION
-> TRUSTED VALUE BINDING
-> DETERMINISTIC POLICY EVALUATION
-> PREPARED-CALL SEALING
-> EXECUTION-TIME REVALIDATION
-> EVIDENCE BEFORE EFFECT
-> EFFECT / REFUSAL / REPLAY EVIDENCE
```

The explorer makes **Selection, not supply** and **ALLOW is not executed**
explicit. Decision and execution remain separate facts: an `ALLOW` may create a
prepared capability, while the execution gate may still refuse it before
adapter entry. W2 property titles and `make prove PROPERTY=<id>` commands are
reference-only reviewer hints; the UI does not run proofs, ingest proof status,
or display cached proof results. `make prove` remains an external command for a
clean committed checkout.

The browser receives only the closed, server-side mechanism projection and the
existing masked review projection. It receives no raw protected value, opaque
reference value, runtime-private payload, or private binding/authenticator
material.

## Strongest proven properties

- **Untrusted selection cannot mint trusted supply.** Protected arguments must
  be exact runtime reference objects backed by the trusted store; raw or forged
  values fail closed.
- **ALLOW is not reusable authority.** Prepared calls have a public content
  identity plus a runtime-private HMAC binding over correlations, payload,
  object identity, and exact single-use targets.
- **Evidence precedes effects.** Durable pre-execution append happens before
  atomic capability/reference consumption and adapter entry.
- **Replay is locally at most once.** Sequential replay and 12 concurrent
  attempts through a six-worker pool produce one adapter entry and one payment.
- **Evidence cannot manufacture success.** Missing, conflicting, malformed, or
  unreconciled records cannot render PASS.
- **Protected values stay server-side.** Public evidence and browser surfaces
  receive only allowlisted, output-encoded projections and are byte-scanned for
  protected/private/provider data.

The complete claim-to-code/test/evidence/UI map and the 35-scenario threat
summary are in the
[Security Invariant Traceability and Threat Model](docs/security/TIDEMARK_SECURITY_INVARIANT_TRACEABILITY_AND_THREAT_MODEL_v1.0.md).

## Explicit non-claims

TIDEMARK does not claim to prevent prompt injection, make Gemini secure, or
guarantee future model behavior. It is not identity/RBAC, delegation, approval
workflow, a general policy language, tool/MCP supply-chain provenance,
continuous adversarial testing, signed external attestation, or production
compliance. Local at-most-once adapter entry is not distributed external
exactly-once semantics. The current UI is not a live query; the removed Order
21 resources are not an active deployment; and the cloud proof is not a Gemini
cloud run.

## Quick start

Prerequisites: Python 3.9 or newer, a POSIX shell, and network access only for
initial dependency installation. No provider credential or Google Cloud access
is required. Run from the repository root:

```bash
python3 --version
venv_dir="$(mktemp -d /tmp/tidemark-venv.XXXXXX)"
python3 -m venv --upgrade-deps "$venv_dir"
source "$venv_dir/bin/activate"
python -m pip install -e ".[dev]"
demo_dir="$(mktemp -d /tmp/tidemark-demo.XXXXXX)"
make preflight PROFILE=standard OUTPUT_DIR="$demo_dir"
make verify
make demo PROFILE=standard OUTPUT_DIR="$demo_dir"
python3 -m http.server --bind 127.0.0.1 8000 --directory "$demo_dir/artifacts"
```

Open `http://127.0.0.1:8000/index.html`, then stop the local server with
`Ctrl-C`. `artifacts/index.html` is the integrated read-only UI; the same
directory contains six decision-review artifacts, the rehearsal report, and a
canonical source-revision-bound run manifest.

The `standard`, `capture`, and explicitly selected `fallback` profiles are
deterministic and offline. Generic reproduction preflight does not import or
version-check Google ADK; the pinned Google ADK requirement remains part of the
separate live path. Do not run
`scripts/verify_gemini_live.py` without a separately reviewed and explicitly
granted human live-call budget.

## Security property proof suite

From a clean committed checkout, reviewers can run all eight fixed W2 security
properties or one exact property:

```bash
make prove
make prove PROPERTY=W2-P05
proof_dir="$(mktemp -d /tmp/tidemark-proofs.XXXXXX)"
make prove OUTPUT_DIR="$proof_dir"
make prove PROPERTY=W2-P05 OUTPUT_DIR="$proof_dir"
```

`OUTPUT_DIR` is optional and must name an existing empty non-symlink directory.
When supplied, the command exclusively materializes the canonical verified
`security-proof-suite.json` leaf. A dirty checkout, changed source during the
run, invalid selection, output error, scan failure, or verification failure
fails closed without a completed suite claim or new artifact.

Proof `PASS` means only that the completely observed fixed fixture facts
satisfied the named invariant at the committed source revision. In `W2-P08`,
it specifically means incomplete, conflicting, and ambiguous evidence stayed
non-successful; it does not mean execution or evidence succeeded. The suite is
offline and makes zero live-model or Google Cloud calls. Its SHA-256 digests
provide deterministic internal integrity, not signatures, attestation,
third-party verification, production readiness, external exactly-once effects,
or a claim that Gemini is safe.

## Validation before publication

Run the Phase 1 focused verification, one manifest-backed standard demo, and
the diff check:

```bash
make verify
demo_root="$(mktemp -d /tmp/tidemark-rehearsal.XXXXXX)"
make demo PROFILE=standard OUTPUT_DIR="$demo_root"
git diff --check
```

Run the full regression separately when preparing closure evidence:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q
```

Manifest-backed commands require a commit, an initially clean worktree, and an
unchanged clean `HEAD` immediately before manifest construction. Capture and
fallback perform exactly three fresh runs and compare a closed typed semantic
snapshot; there is no fourth or replacement run.

## Repository map

```text
src/tidemark/runtime/    Deterministic policy, trusted references, prepared calls, execution gate
src/tidemark/adapters/   Google ADK callback and bounded Gemini live-request gate
src/tidemark/evidence/   Append-only records, integrity, reconciliation, projection, publication
src/tidemark/demo/       Six-scenario deterministic harness, rehearsal, cloud-proof entry point
src/tidemark/ui/         Read-only run summary, inspector, evidence trace, and cloud proof
tests/                   Runtime, adapter, evidence, demo, UI, and 35-scenario security proof
scripts/                 Offline rehearsal and separately gated manual live verifier
docs/architecture/       Product and submission architecture
docs/evidence/           Durable redacted historical live and cloud evidence
docs/runbooks/           Judge-facing deterministic demo instructions
docs/security/           Threat model and invariant-to-proof traceability
docs/specs/              Product boundary, runtime contracts, and evidence model
```

The authoritative scope and non-goals are in
[Product Boundary](docs/specs/PRODUCT_BOUNDARY_v1.0.md); the executable
interfaces are fixed by the
[Runtime Contracts](docs/specs/TIDEMARK_RUNTIME_CONTRACTS_SPEC_v1.0.md).

Release provenance: all canonical product bytes originate from source revision
`e18e068d13e027b0dbdd5bcb2bc51c5c7123be6a`; the judge-facing runbook and
release metadata are derived publication artifacts. Current offline evidence
remains distinct from the included historical live-model and cloud proofs.
