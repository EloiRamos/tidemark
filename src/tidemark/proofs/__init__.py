"""Closed public model and fixed catalogue for TIDEMARK security proofs."""

from tidemark.proofs.catalogue import (
    CATALOGUE_VERSION,
    PROOF_CATALOGUE,
    PROOF_FIXTURE_COUNT,
    PROOF_PROPERTY_COUNT,
)
from tidemark.proofs.model import (
    PROOF_SUITE_KIND,
    PROOF_SUITE_SCHEMA,
    ProofInfrastructureErrorCode,
    ProofObservation,
    ProofRunOutcome,
    ProofRunResult,
    ProofStatus,
    ProofSuiteResult,
)
from tidemark.proofs.runner import (
    PROOF_ARTIFACT_NAME,
    proof_exit_code,
    render_proof_run,
    run_security_proofs,
)


__all__ = (
    "CATALOGUE_VERSION",
    "PROOF_CATALOGUE",
    "PROOF_FIXTURE_COUNT",
    "PROOF_PROPERTY_COUNT",
    "PROOF_SUITE_KIND",
    "PROOF_SUITE_SCHEMA",
    "PROOF_ARTIFACT_NAME",
    "ProofInfrastructureErrorCode",
    "ProofObservation",
    "ProofRunOutcome",
    "ProofRunResult",
    "ProofStatus",
    "ProofSuiteResult",
    "proof_exit_code",
    "render_proof_run",
    "run_security_proofs",
)
