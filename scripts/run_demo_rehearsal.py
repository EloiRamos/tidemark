#!/usr/bin/env python3
"""Run the provider-free standard, capture, or deterministic fallback demo."""

import argparse

from tidemark.demo.rehearsal import (
    DEFAULT_REHEARSAL_SAMPLE_COUNT,
    DemoRehearsalError,
    materialize_demo_rehearsal,
)
from tidemark.demo.capture import (
    CaptureProfile,
    CaptureRehearsalError,
    run_capture_rehearsal,
)
from tidemark.demo.preflight import (
    LocalReadiness,
    PreflightProfile,
    run_preflight,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run fresh deterministic offline rehearsals and write verified "
            "read-only artifacts into an existing empty directory."
        )
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="existing empty temporary directory for read-only demo artifacts",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="bounded fresh standard rehearsal count (2-10; default: 2)",
    )
    parser.add_argument(
        "--profile",
        choices=("standard", "capture", "fallback"),
        default="standard",
        help="closed provider-free execution profile (default: standard)",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="run local readiness checks without generating artifacts",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.profile != "standard" and arguments.samples is not None:
        print("CAPTURE_REHEARSAL=FAIL")
        print("FAILURE_CODE=demo.rehearsal.invalid_input.v1")
        print("ARTIFACT_SET_MATERIALIZED=false")
        return 1
    preflight_profile = (
        PreflightProfile.REPRODUCTION
        if arguments.profile == "standard"
        else PreflightProfile.CAPTURE
    )
    if arguments.preflight_only:
        result = run_preflight(
            profile=preflight_profile,
            output_root=arguments.output_dir,
        )
        for line in result.diagnostic_lines():
            print(line)
        return 0 if result.local_readiness is LocalReadiness.PASS else 1
    if arguments.profile != "standard":
        profile = (
            CaptureProfile.CAPTURE
            if arguments.profile == "capture"
            else CaptureProfile.DETERMINISTIC_FALLBACK
        )
        try:
            result = run_capture_rehearsal(
                profile=profile,
                output_root=arguments.output_dir,
            )
        except (CaptureRehearsalError, TypeError, ValueError) as error:
            code = getattr(error, "code", None)
            value = getattr(code, "value", "demo.rehearsal.invalid_input.v1")
            print("CAPTURE_REHEARSAL=FAIL")
            print(f"FAILURE_CODE={value}")
            ordinal = getattr(error, "run_ordinal", None)
            if ordinal is not None:
                print(f"FAILING_RUN_ORDINAL={ordinal}")
            print("ARTIFACT_SET_MATERIALIZED=false")
            return 1
        print("CAPTURE_REHEARSAL=PASS")
        print(f"PROFILE={profile.value}")
        print("RUN_COUNT=3")
        print("SEMANTIC_EQUALITY=true")
        if profile is CaptureProfile.DETERMINISTIC_FALLBACK:
            print("DETERMINISTIC=true")
            print("OFFLINE=true")
            print("NOT_CURRENT_LIVE_PROVIDER_OUTPUT=true")
        print("ARTIFACT_SET_MATERIALIZED=true")
        print("OPEN_ARTIFACT=artifacts/index.html")
        print("LIVE_GATE_STATE=NOT_EVALUATED")
        print("LIVE_MODEL_CALLS_PERFORMED=0")
        print("GOOGLE_CLOUD_ACCESSED=false")
        return 0
    sample_count = (
        DEFAULT_REHEARSAL_SAMPLE_COUNT
        if arguments.samples is None
        else arguments.samples
    )
    try:
        result = materialize_demo_rehearsal(
            arguments.output_dir,
            sample_count=sample_count,
        )
    except (DemoRehearsalError, TypeError, ValueError) as error:
        code = getattr(error, "code", None)
        value = getattr(code, "value", "demo.rehearsal.invalid_input.v1")
        print("ORDER_19_REHEARSAL=FAIL")
        print(f"FAILURE_CODE={value}")
        print("ARTIFACT_SET_MATERIALIZED=false")
        return 1

    report = result.report
    print("ORDER_19_REHEARSAL=PASS")
    print(f"SAMPLE_COUNT={report.sample_count}")
    print(f"REQUIRED_SCENARIO_COUNT={report.required_scenario_count}")
    print("OFFLINE_FALLBACK_EXPLICIT=true")
    print("OFFLINE_PRESENTED_AS_LIVE=false")
    print("REAL_PROVIDER_CREDENTIAL_REQUIRED=false")
    print("PROVIDER_REQUESTS_PERFORMED=false")
    print("NETWORK_REQUESTS_PERFORMED=false")
    print("GOOGLE_CLOUD_USED=false")
    print(
        "HARNESS_RUNTIME_SECONDS_MEDIAN="
        f"{report.timings.full_harness_runtime.median_seconds:.6f}"
    )
    print(
        "COMPLETE_SAMPLE_SECONDS_MAX="
        f"{report.timings.complete_sample.maximum_seconds:.6f}"
    )
    print("ARTIFACT_SET_MATERIALIZED=true")
    print("OPEN_ARTIFACT=artifacts/index.html")
    print("LIVE_GATE_STATE=NOT_EVALUATED")
    print("LIVE_MODEL_CALLS_PERFORMED=0")
    print("GOOGLE_CLOUD_ACCESSED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
