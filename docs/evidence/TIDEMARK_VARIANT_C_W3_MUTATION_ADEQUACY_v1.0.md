# TIDEMARK Variant C W3 Mutation Adequacy

Schema version: `tidemark.w3.mutation-adequacy.v1`
Source revision: `617d84e4effbd1fc4aad913fada1a01f0f0fc559`
Catalogue version: `tidemark.w3.mutant-catalogue.v1`
Domain contract: `tidemark.w3.property-domains.v1`
Artifact digest: `sha256:7c8ac78895c37111b2626b237277a50cafc70d737211a9726a2c66bcfd55a456`

## Summary

| Measure | Value |
| --- | --- |
| Overall status | PASS |
| Properties passed | 5 / 5 |
| Generated cases | 205 |
| Mutation adequacy | 12 / 12 |
| Concurrency shapes passed | 2 / 2 |

## Property domains

| ID | Seed | Cases | Controls | Detectors | Status |
| --- | --- | --- | --- | --- | --- |
| W3-D01 | tidemark-w3-d01-exact-representation-v1 | 48 | 1 | W3-DET-D01-EXACT-REPRESENTATION | PASS |
| W3-D02 | tidemark-w3-d02-unissued-reference-v1 | 32 | 1 | W3-DET-D02-UNISSUED-NOT-TRUSTED | PASS |
| W3-D03 | tidemark-w3-d03-canonical-json-v1 | 48 | 1 | W3-DET-D03-CANONICAL-ROUND-TRIP | PASS |
| W3-D04 | tidemark-w3-d04-safe-display-v1 | 64 | 1 | W3-DET-D04-SAFE-DISPLAY-CLOSED | PASS |
| W3-D05 | tidemark-w3-d05-evidence-corruption-order-v1 | 13 | 1 | W3-DET-D05-CORRUPTION-NOT-CLEAN-SUCCESS | PASS |

## Mutant catalogue

| ID | Category | Targets | Expected | Actual | Activated |
| --- | --- | --- | --- | --- | --- |
| W3-MUT-REP-001 | Representation corruption | W3-D01, SELECTION_NOT_SUPPLY | KILLED | KILLED | true |
| W3-MUT-REP-002 | Representation corruption | W3-D02, TRUSTED_STORE_ISSUANCE | KILLED | KILLED | true |
| W3-MUT-REP-003 | Representation corruption | W3-D03, CANONICAL_BYTES | KILLED | KILLED | true |
| W3-MUT-PROJ-001 | Projection corruption | W3-D04, SAFE_DISPLAY | KILLED | KILLED | true |
| W3-MUT-PROJ-002 | Projection corruption | W3-D04, REFERENCE_SECRECY | KILLED | KILLED | true |
| W3-MUT-PROJ-003 | Projection corruption | W3-D04, OUTPUT_ENCODING_BOUNDARY | KILLED | KILLED | true |
| W3-MUT-ORD-001 | Ordering/state corruption | W2-P03, EVIDENCE_BEFORE_EFFECT | KILLED | KILLED | true |
| W3-MUT-ORD-002 | Ordering/state corruption | W2-P04, W2-P05, LOCAL_SINGLE_USE | KILLED | KILLED | true |
| W3-MUT-EVID-001 | Evidence/proof-reference corruption | W3-D05, EVIDENCE_COMPLETENESS | KILLED | KILLED | true |
| W3-MUT-EVID-002 | Evidence/proof-reference corruption | W2-P08, UNCERTAINTY_PRESERVATION | KILLED | KILLED | true |
| W3-MUT-CON-001 | Concurrency/interleaving corruption | W3-C01, CURRENT_STATE_VETO | KILLED | KILLED | true |
| W3-MUT-CON-002 | Concurrency/interleaving corruption | W3-C02, DURABLE_RECEIPT_PREREQUISITE | KILLED | KILLED | true |

## Concurrency shapes

| ID | Repetitions | Passed | Detectors | Status |
| --- | --- | --- | --- | --- |
| W3-C01 | 3 | 3 | W3-DET-C01-STALE-PREPARATION-CURRENT-STATE-VETO | PASS |
| W3-C02 | 3 | 3 | W3-DET-C02-FAILED-APPEND-PRESERVES-AUTHORITY | PASS |

## Survivors and findings

None.

## Non-claims

- A killed mutant is not proof of production security.
- High mutation adequacy is not absence of unknown defects.
- No distributed or external exactly-once guarantee is claimed.
- No scheduler fairness guarantee is claimed.

## Offline execution state

| Boundary | Value |
| --- | --- |
| Live model calls | 0 |
| Provider calls | 0 |
| Google Cloud accessed | false |
| Network dependency required | false |
