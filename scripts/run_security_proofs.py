#!/usr/bin/env python3
"""Closed reviewer CLI for the deterministic W2 security proof suite."""

from pathlib import Path
import sys
from typing import Optional, Tuple

from tidemark.proofs.model import ProofInfrastructureErrorCode, ProofRunOutcome
from tidemark.proofs.runner import (
    proof_exit_code,
    render_error,
    render_proof_run,
    run_security_proofs,
)


def _parse_arguments(
    arguments: Tuple[str, ...],
) -> Optional[Tuple[Optional[str], Optional[Path]]]:
    property_id = None
    output_dir = None
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option not in ("--property", "--output-dir") or index + 1 >= len(arguments):
            return None
        value = arguments[index + 1]
        if not value or value.startswith("--"):
            return None
        if option == "--property":
            if property_id is not None:
                return None
            property_id = value
        else:
            if output_dir is not None:
                return None
            output_dir = Path(value)
        index += 2
    return property_id, output_dir


def main(arguments: Optional[Tuple[str, ...]] = None) -> int:
    parsed = _parse_arguments(
        tuple(sys.argv[1:]) if arguments is None else arguments
    )
    if parsed is None:
        sys.stdout.buffer.write(
            render_error(ProofInfrastructureErrorCode.SELECTION_INVALID)
        )
        return 2
    property_id, output_dir = parsed
    run = run_security_proofs(property_id=property_id, output_dir=output_dir)
    sys.stdout.buffer.write(
        render_proof_run(
            run,
            artifact_materialized=(
                output_dir is not None and run.outcome is ProofRunOutcome.COMPLETED
            ),
        )
    )
    return proof_exit_code(run)


if __name__ == "__main__":
    raise SystemExit(main())
