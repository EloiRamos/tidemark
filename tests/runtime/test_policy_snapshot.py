from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import inspect

import pytest

from tidemark.runtime.identifiers import PolicyVersion, RegistryVersion
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_snapshot import (
    InstallationRefusal,
    InstalledSnapshot,
    PolicyInstaller,
    PolicySnapshot,
)
from tidemark.runtime.vocabulary import RuleId


def valid_authoring(
    policy_version="policy-2026-08-06",
    registry_version="registry-2026-08-06",
):
    return {
        "policy_version": policy_version,
        "registry_version": registry_version,
        "executable_tools": ("payments.create",),
        "tool_registrations": (
            {
                "tool_id": "payments.create",
                "contract_version": "payments.create.contract.v1",
                "policy_version": policy_version,
                "signature": (
                    {
                        "name": "amount_minor",
                        "required": True,
                        "type_id": "integer",
                    },
                    {
                        "name": "currency",
                        "required": True,
                        "type_id": "currency_code",
                    },
                    {
                        "name": "destination_reference",
                        "required": True,
                        "type_id": "destination_reference",
                    },
                ),
                "arguments": (
                    {
                        "name": "amount_minor",
                        "position": 0,
                        "type_id": "integer",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.integer.maximum.v1",
                                "parameters": {"maximum": 10_000},
                            },
                        ),
                    },
                    {
                        "name": "currency",
                        "position": 1,
                        "type_id": "currency_code",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.enum.member.v1",
                                "parameters": {"members": ("EUR", "USD")},
                            },
                        ),
                    },
                    {
                        "name": "destination_reference",
                        "position": 2,
                        "type_id": "destination_reference",
                        "required": True,
                        "role": "PROTECTED_REFERENCE",
                        "constraint_bindings": (
                            {
                                "constraint_id": (
                                    "protected.reference.required.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.kind.equals.v1",
                                "parameters": {
                                    "kind": "merchant_destination"
                                },
                            },
                            {
                                "constraint_id": (
                                    "reference.invocation.equals.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.parent.equals.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.active.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.single_use.v1",
                                "parameters": {},
                            },
                        ),
                    },
                ),
                "role_metadata": (
                    {
                        "name": "amount_minor",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "currency",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "destination_reference",
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "payments.local.adapter",
                "adapter_version": "payments.local.adapter.v1",
                "masking_profile_id": "payments.masking.v1",
            },
        ),
    }


def validated_policy(
    policy_version="policy-2026-08-06",
    registry_version="registry-2026-08-06",
):
    validated = validate_policy_authoring(
        valid_authoring(policy_version, registry_version)
    )
    assert type(validated) is ValidatedPolicyAuthoring
    return validated


def installed_snapshot(installer, validated=None):
    result = installer.install(validated or validated_policy())
    assert type(result) is InstalledSnapshot
    return result.snapshot


def maximum_parameter(snapshot):
    binding = snapshot.tool_policies[0].arguments[0].constraint_bindings[0]
    return binding.parameters[0]


def test_installer_starts_without_a_published_snapshot_or_inspection():
    installer = PolicyInstaller()

    assert installer.capture_snapshot() is None
    assert installer.inspect_snapshot() is None


def test_successful_installation_publishes_a_runtime_owned_snapshot():
    validated = validated_policy()
    installer = PolicyInstaller()

    result = installer.install(validated)

    assert type(result) is InstalledSnapshot
    assert type(result.snapshot) is PolicySnapshot
    assert installer.capture_snapshot() is result.snapshot
    assert result.snapshot.policy_version == validated.policy_version
    assert result.snapshot.policy_version is not validated.policy_version
    assert result.snapshot.registry_version == validated.registry_version
    assert result.snapshot.registry_version is not validated.registry_version
    assert result.snapshot.tool_policies is not validated.tool_registrations
    assert result.snapshot.tool_policies[0] is not validated.tool_registrations[0]


def test_snapshot_and_publication_records_are_immutable():
    result = PolicyInstaller().install(validated_policy())
    assert type(result) is InstalledSnapshot

    with pytest.raises(FrozenInstanceError):
        result.snapshot = result.snapshot
    with pytest.raises(FrozenInstanceError):
        result.snapshot.policy_version = PolicyVersion("changed")
    with pytest.raises(FrozenInstanceError):
        result.snapshot.tool_policies[0].adapter_id = "changed"
    with pytest.raises(TypeError):
        result.snapshot.tool_policies[0].arguments[0].constraint_bindings[
            0
        ].parameters[0] = ("maximum", 1)


def test_caller_mutation_after_installation_cannot_change_snapshot_state():
    authoring = valid_authoring()
    validated = validate_policy_authoring(authoring)
    assert type(validated) is ValidatedPolicyAuthoring
    snapshot = installed_snapshot(PolicyInstaller(), validated)
    identity = snapshot.integrity_id

    authoring["policy_version"] = "caller-changed"
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = 1

    assert snapshot.policy_version == PolicyVersion("policy-2026-08-06")
    assert maximum_parameter(snapshot) == ("maximum", 10_000)
    assert snapshot.integrity_id == identity


def test_successful_replacement_is_atomic_and_does_not_mutate_prior_snapshot():
    installer = PolicyInstaller()
    first = installed_snapshot(installer)
    second = installed_snapshot(installer, validated_policy("policy-v2"))

    assert installer.capture_snapshot() is second
    assert first.policy_version == PolicyVersion("policy-2026-08-06")
    assert second.policy_version == PolicyVersion("policy-v2")
    assert first is not second
    assert first.integrity_id != second.integrity_id


def test_failed_installation_preserves_the_previously_published_snapshot():
    installer = PolicyInstaller()
    published = installed_snapshot(installer)

    refusal = installer.install({"untrusted": "not-validated"})

    assert type(refusal) is InstallationRefusal
    assert refusal.code is RuleId.RUNTIME_POLICY_UNAVAILABLE
    assert installer.capture_snapshot() is published


def test_malformed_validated_graph_is_refused_without_partial_publication():
    installer = PolicyInstaller()
    published = installed_snapshot(installer)
    candidate = validated_policy("policy-v2")
    registration = candidate.tool_registrations[0]
    argument = registration.arguments[0]
    binding = argument.constraint_bindings[0]
    malformed_binding = replace(
        binding, parameters=(("maximum", [10_000]),)
    )
    malformed_argument = replace(
        argument, constraint_bindings=(malformed_binding,)
    )
    malformed_registration = replace(
        registration,
        arguments=(malformed_argument,) + registration.arguments[1:],
    )
    malformed_candidate = replace(
        candidate, tool_registrations=(malformed_registration,)
    )

    refusal = installer.install(malformed_candidate)

    assert type(refusal) is InstallationRefusal
    assert refusal.code is RuleId.CONTRACT_REGISTRY_INCOMPLETE
    assert installer.capture_snapshot() is published


def test_reinstalling_a_used_policy_version_refuses_and_preserves_snapshot():
    installer = PolicyInstaller()
    first = installed_snapshot(installer)
    second = installed_snapshot(installer, validated_policy("policy-v2"))

    refusal = installer.install(validated_policy())

    assert type(refusal) is InstallationRefusal
    assert refusal.code is RuleId.RUNTIME_POLICY_UNAVAILABLE
    assert refusal.location == ("policy_version",)
    assert installer.capture_snapshot() is second
    assert first.policy_version == PolicyVersion("policy-2026-08-06")


def test_repeated_installation_captures_each_new_policy_version():
    installer = PolicyInstaller()
    versions = ("policy-v1", "policy-v2", "policy-v3")

    snapshots = tuple(
        installed_snapshot(installer, validated_policy(version))
        for version in versions
    )

    assert tuple(snapshot.policy_version.value for snapshot in snapshots) == (
        versions
    )
    assert installer.capture_snapshot() is snapshots[-1]
    assert len({snapshot.integrity_id for snapshot in snapshots}) == 3


def test_registry_version_is_captured_as_a_fresh_runtime_value():
    validated = validated_policy(registry_version="registry-v7")
    snapshot = installed_snapshot(PolicyInstaller(), validated)

    assert snapshot.registry_version == RegistryVersion("registry-v7")
    assert snapshot.registry_version is not validated.registry_version
    assert snapshot.tool_policies[0].policy_version is snapshot.policy_version


def test_installation_timestamp_is_captured_as_utc():
    installer = PolicyInstaller()
    before = datetime.now(timezone.utc)
    snapshot = installed_snapshot(installer)
    after = datetime.now(timezone.utc)
    view = installer.inspect_snapshot()
    assert view is not None

    assert snapshot.created_at.tzinfo is timezone.utc
    assert before <= snapshot.created_at <= after
    assert view.created_at == snapshot.created_at.isoformat().replace(
        "+00:00", "Z"
    )


def test_snapshot_identity_is_content_derived_and_stable():
    first = installed_snapshot(PolicyInstaller())
    second = installed_snapshot(PolicyInstaller())

    assert first.integrity_id == second.integrity_id
    assert first.integrity_id.startswith("sha256:")
    assert len(first.integrity_id.removeprefix("sha256:")) == 64


def test_snapshot_equality_is_canonical_and_excludes_publication_time():
    first = installed_snapshot(PolicyInstaller())
    later = replace(first, created_at=first.created_at + timedelta(seconds=1))

    assert first == later
    assert hash(first) == hash(later)
    assert first.created_at != later.created_at


def test_distinct_policy_versions_are_distinct_snapshots():
    first = installed_snapshot(PolicyInstaller(), validated_policy("policy-v1"))
    second = installed_snapshot(
        PolicyInstaller(), validated_policy("policy-v2")
    )

    assert first != second
    assert first.integrity_id != second.integrity_id


def test_inspection_is_immutable_detached_and_non_authoritative():
    installer = PolicyInstaller()
    snapshot = installed_snapshot(installer)
    inspection = installer.inspect_snapshot()
    assert inspection is not None

    assert inspection.policy_version == snapshot.policy_version.value
    assert inspection.registry_version == snapshot.registry_version.value
    assert inspection.tool_policies is not snapshot.tool_policies
    assert type(inspection.tool_policies[0].tool_id) is str
    assert type(inspection.tool_policies[0].arguments[0].role) is str
    assert maximum_parameter(snapshot) == ("maximum", 10_000)
    with pytest.raises(FrozenInstanceError):
        inspection.policy_version = "caller-changed"
    with pytest.raises(FrozenInstanceError):
        inspection.tool_policies[0].tool_id = "caller-changed"
    assert snapshot.policy_version == PolicyVersion("policy-2026-08-06")


def test_each_inspection_is_an_equal_but_detached_object_graph():
    installer = PolicyInstaller()
    installed_snapshot(installer)

    first = installer.inspect_snapshot()
    second = installer.inspect_snapshot()

    assert first == second
    assert first is not second
    assert first.tool_policies is not second.tool_policies
    assert first.tool_policies[0] is not second.tool_policies[0]
    assert first.tool_policies[0].arguments[0] is not (
        second.tool_policies[0].arguments[0]
    )


def test_installation_refusal_is_immutable_masked_and_detached():
    supplied = "caller-secret-policy-value"
    refusal = PolicyInstaller().install({"policy_version": supplied})
    assert type(refusal) is InstallationRefusal

    assert supplied not in refusal.masked_detail
    assert type(refusal.location) is tuple
    with pytest.raises(FrozenInstanceError):
        refusal.masked_detail = supplied


def test_concurrent_same_version_installation_publishes_exactly_once():
    installer = PolicyInstaller()
    candidate = validated_policy()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(installer.install, (candidate,) * 8))

    installed = tuple(
        result for result in results if type(result) is InstalledSnapshot
    )
    refusals = tuple(
        result for result in results if type(result) is InstallationRefusal
    )
    assert len(installed) == 1
    assert len(refusals) == 7
    assert installer.capture_snapshot() is installed[0].snapshot


def test_snapshot_module_has_no_mutable_runtime_globals():
    from tidemark.runtime import policy_snapshot

    mutable_globals = {
        name: value
        for name, value in vars(policy_snapshot).items()
        if name != "__builtins__" and type(value) in (dict, list, set)
    }

    assert mutable_globals == {}


def test_order_3_surface_has_no_later_order_runtime_behavior():
    installer = PolicyInstaller()
    snapshot = installed_snapshot(installer)

    forbidden_methods = {
        "evaluate",
        "resolve",
        "prepare",
        "execute",
        "persist",
    }
    assert forbidden_methods.isdisjoint(dir(installer))
    assert forbidden_methods.isdisjoint(dir(snapshot))
    assert not any(
        name.startswith(("adk", "gemini", "google", "cloud", "payment"))
        for name, _ in inspect.getmembers(snapshot)
    )
