"""Runtime-private authority joining preparation to local execution.

The sidecar registry, payload MAC key, reference targets, store authority, and
authoritative capability state in this module are deliberately absent from the
public ``PreparedToolCall`` graph and all evidence/adapter values.  General
host-language reflection remains outside the v1.0 threat boundary.
"""

from hashlib import sha256
import hmac
import json
from secrets import token_bytes
from threading import RLock
from typing import Dict, Optional, Tuple

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    PreparedCallId,
    ReferenceId,
    RegistryVersion,
    ToolId,
)
from tidemark.runtime.reference_store import TrustedReferenceStore
from tidemark.runtime.vocabulary import PreparedCallState


_BINDING_CONSTRUCTION_AUTHORITY = object()


class _RuntimePrivateExecutionBinding:
    """One non-public prepared capability and its exact consumption targets."""

    __slots__ = (
        "_capability_state",
        "_payload_authenticator",
        "_prepared_object_identity",
        "_reference_targets",
        "_store",
        "_store_authority",
        "adapter_id",
        "adapter_version",
        "call_id",
        "decision_id",
        "invocation_id",
        "parent_id",
        "policy_version",
        "prepared_call_id",
        "public_integrity_id",
        "registry_version",
        "tool_id",
    )

    def __init__(
        self,
        *,
        prepared_call_id: PreparedCallId,
        decision_id: DecisionId,
        call_id: CallId,
        invocation_id: InvocationId,
        parent_id: ParentId,
        tool_id: ToolId,
        policy_version: PolicyVersion,
        registry_version: RegistryVersion,
        adapter_id: AdapterId,
        adapter_version: AdapterVersion,
        public_integrity_id: str,
        payload_authenticator: bytes,
        prepared_object_identity: int,
        reference_targets: Tuple[ReferenceId, ...],
        store: TrustedReferenceStore,
        store_authority: object,
        _authority: object = None,
    ) -> None:
        if _authority is not _BINDING_CONSTRUCTION_AUTHORITY:
            raise TypeError("runtime-private bindings are runtime-created only")
        object.__setattr__(self, "prepared_call_id", prepared_call_id)
        object.__setattr__(self, "decision_id", decision_id)
        object.__setattr__(self, "call_id", call_id)
        object.__setattr__(self, "invocation_id", invocation_id)
        object.__setattr__(self, "parent_id", parent_id)
        object.__setattr__(self, "tool_id", tool_id)
        object.__setattr__(self, "policy_version", policy_version)
        object.__setattr__(self, "registry_version", registry_version)
        object.__setattr__(self, "adapter_id", adapter_id)
        object.__setattr__(self, "adapter_version", adapter_version)
        object.__setattr__(self, "public_integrity_id", public_integrity_id)
        object.__setattr__(self, "_payload_authenticator", payload_authenticator)
        object.__setattr__(
            self, "_prepared_object_identity", prepared_object_identity
        )
        object.__setattr__(self, "_reference_targets", reference_targets)
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "_store_authority", store_authority)
        object.__setattr__(
            self, "_capability_state", PreparedCallState.UNUSED
        )

    def __repr__(self) -> str:
        return "RuntimePrivateExecutionBinding(<runtime-only>)"


class _RuntimeExecutionBindingCoordinator:
    """Own the private key, sidecars, and one local transaction lock."""

    __slots__ = ("_bindings", "_lock", "_secret")

    def __init__(self) -> None:
        self._bindings: Dict[
            Tuple[str, int], _RuntimePrivateExecutionBinding
        ] = {}
        self._lock = RLock()
        self._secret = token_bytes(32)

    def __repr__(self) -> str:
        return "RuntimeExecutionBindingCoordinator(<runtime-only>)"


_RUNTIME_BINDING_COORDINATOR = _RuntimeExecutionBindingCoordinator()


def _register_runtime_execution_binding(
    *,
    prepared_call: object,
    parent_id: ParentId,
    trusted_store: TrustedReferenceStore,
    reference_targets: Tuple[ReferenceId, ...],
) -> bool:
    """Register exactly one private sidecar before preparation returns."""

    from tidemark.runtime.prepared_call import PreparedToolCall

    if type(prepared_call) is not PreparedToolCall:
        return False
    if type(parent_id) is not ParentId:
        return False
    if type(trusted_store) is not TrustedReferenceStore:
        return False
    if type(reference_targets) is not tuple:
        return False
    if any(type(item) is not ReferenceId for item in reference_targets):
        return False
    if len(reference_targets) != len(set(reference_targets)):
        return False
    if not _adapter_payload_reference_free(prepared_call):
        return False

    message = _binding_message(
        prepared_call=prepared_call,
        parent_id=parent_id,
        reference_targets=reference_targets,
    )
    if message is None:
        return False
    coordinator = _RUNTIME_BINDING_COORDINATOR
    authenticator = hmac.new(coordinator._secret, message, sha256).digest()
    binding = _RuntimePrivateExecutionBinding(
        prepared_call_id=PreparedCallId(prepared_call.prepared_call_id.value),
        decision_id=DecisionId(prepared_call.decision_id.value),
        call_id=CallId(prepared_call.call_id.value),
        invocation_id=InvocationId(prepared_call.invocation_id.value),
        parent_id=ParentId(parent_id.value),
        tool_id=ToolId(prepared_call.tool_id.value),
        policy_version=PolicyVersion(prepared_call.policy_version.value),
        registry_version=RegistryVersion(prepared_call.registry_version.value),
        adapter_id=AdapterId(prepared_call.adapter_id.value),
        adapter_version=AdapterVersion(prepared_call.adapter_version.value),
        public_integrity_id=prepared_call.integrity_id,
        payload_authenticator=authenticator,
        prepared_object_identity=id(prepared_call),
        reference_targets=tuple(
            ReferenceId(item.value) for item in reference_targets
        ),
        store=trusted_store,
        store_authority=trusted_store._execution_authority,
        _authority=_BINDING_CONSTRUCTION_AUTHORITY,
    )
    key = (prepared_call.prepared_call_id.value, id(prepared_call))
    with coordinator._lock:
        if key in coordinator._bindings:
            return False
        coordinator._bindings[key] = binding
    return True


def _lookup_runtime_execution_binding(
    prepared_call_id: PreparedCallId,
) -> Optional[_RuntimePrivateExecutionBinding]:
    """Private lookup used by the execution coordinator and focused tests."""

    if type(prepared_call_id) is not PreparedCallId:
        return None
    coordinator = _RUNTIME_BINDING_COORDINATOR
    with coordinator._lock:
        matches = tuple(
            binding
            for (identifier, _), binding in coordinator._bindings.items()
            if identifier == prepared_call_id.value
        )
        if len(matches) != 1:
            return None
        return matches[0]


def _validate_runtime_execution_binding(
    prepared_call: object,
) -> Optional[_RuntimePrivateExecutionBinding]:
    """Validate exact public/private correlations and the payload MAC."""

    from tidemark.runtime.prepared_call import PreparedToolCall

    if type(prepared_call) is not PreparedToolCall:
        return None
    coordinator = _RUNTIME_BINDING_COORDINATOR
    with coordinator._lock:
        binding = coordinator._bindings.get(
            (prepared_call.prepared_call_id.value, id(prepared_call))
        )
        if binding is None:
            return None
        if not _binding_valid_unlocked(coordinator, prepared_call, binding):
            return None
        return binding


def _atomic_consume_runtime_execution_binding(
    prepared_call: object,
    binding: _RuntimePrivateExecutionBinding,
) -> str:
    """Commit capability and every reference together under local locks."""

    coordinator = _RUNTIME_BINDING_COORDINATOR
    with coordinator._lock:
        prepared_identifier = getattr(
            getattr(prepared_call, "prepared_call_id", None), "value", None
        )
        current = coordinator._bindings.get(
            (prepared_identifier, id(prepared_call))
        )
        if current is not binding:
            return "INVALID"
        if not _binding_valid_unlocked(coordinator, prepared_call, binding):
            return "INVALID"
        if binding._capability_state is PreparedCallState.CONSUMED:
            return "REPLAY"
        if binding._capability_state is not PreparedCallState.UNUSED:
            return "INVALID"
        store = binding._store
        if (
            type(store) is not TrustedReferenceStore
            or store._execution_authority is not binding._store_authority
        ):
            return "INVALID"
        with store._lock:
            status, plan = store._prepare_execution_consumption(
                binding._reference_targets,
                binding.invocation_id,
                binding.parent_id,
            )
            if status == "REPLAY":
                return "REPLAY"
            if status != "READY" or plan is None:
                return "INVALID"
            try:
                store._commit_execution_consumption(plan)
            except Exception:
                return "INVALID"
            object.__setattr__(
                binding, "_capability_state", PreparedCallState.CONSUMED
            )
        return "CONSUMED"


def _binding_valid_unlocked(
    coordinator: _RuntimeExecutionBindingCoordinator,
    prepared_call: object,
    binding: _RuntimePrivateExecutionBinding,
) -> bool:
    if type(binding) is not _RuntimePrivateExecutionBinding:
        return False
    if binding._prepared_object_identity != id(prepared_call):
        return False
    correlations = (
        (binding.prepared_call_id, prepared_call.prepared_call_id, PreparedCallId),
        (binding.decision_id, prepared_call.decision_id, DecisionId),
        (binding.call_id, prepared_call.call_id, CallId),
        (binding.invocation_id, prepared_call.invocation_id, InvocationId),
        (binding.tool_id, prepared_call.tool_id, ToolId),
        (binding.policy_version, prepared_call.policy_version, PolicyVersion),
        (binding.registry_version, prepared_call.registry_version, RegistryVersion),
        (binding.adapter_id, prepared_call.adapter_id, AdapterId),
        (binding.adapter_version, prepared_call.adapter_version, AdapterVersion),
    )
    if any(
        type(private) is not expected
        or type(public) is not expected
        or private != public
        for private, public, expected in correlations
    ):
        return False
    if (
        type(binding.parent_id) is not ParentId
        or type(binding.public_integrity_id) is not str
        or binding.public_integrity_id != prepared_call.integrity_id
        or type(binding._reference_targets) is not tuple
        or any(type(item) is not ReferenceId for item in binding._reference_targets)
        or len(binding._reference_targets) != len(set(binding._reference_targets))
        or type(binding._payload_authenticator) is not bytes
        or type(binding._store) is not TrustedReferenceStore
        or binding._store._execution_authority is not binding._store_authority
        or binding._capability_state
        not in (PreparedCallState.UNUSED, PreparedCallState.CONSUMED)
    ):
        return False
    message = _binding_message(
        prepared_call=prepared_call,
        parent_id=binding.parent_id,
        reference_targets=binding._reference_targets,
    )
    if message is None:
        return False
    expected = hmac.new(coordinator._secret, message, sha256).digest()
    return hmac.compare_digest(binding._payload_authenticator, expected)


def _binding_message(
    *,
    prepared_call: object,
    parent_id: ParentId,
    reference_targets: Tuple[ReferenceId, ...],
) -> Optional[bytes]:
    try:
        primitive = {
            "prepared_call_id": prepared_call.prepared_call_id.value,
            "decision_id": prepared_call.decision_id.value,
            "call_id": prepared_call.call_id.value,
            "invocation_id": prepared_call.invocation_id.value,
            "parent_id": parent_id.value,
            "tool_id": prepared_call.tool_id.value,
            "policy_version": prepared_call.policy_version.value,
            "registry_version": prepared_call.registry_version.value,
            "adapter_id": prepared_call.adapter_id.value,
            "adapter_version": prepared_call.adapter_version.value,
            "public_integrity_id": prepared_call.integrity_id,
            "payload": tuple(
                {
                    "name": argument.name,
                    "type_id": argument.type_id.value,
                    "role": argument.role.value,
                    "value": _prepared_value_primitive(
                        argument._copy_value_for_runtime()
                    ),
                }
                for argument in prepared_call.arguments
            ),
            "reference_targets": tuple(
                target.value for target in reference_targets
            ),
        }
        return json.dumps(
            primitive,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return None


def _adapter_payload_reference_free(prepared_call: object) -> bool:
    try:
        return all(
            not _prepared_value_contains_reference(
                argument._copy_value_for_runtime()
            )
            for argument in prepared_call.arguments
        )
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return False


def _prepared_value_contains_reference(value: object) -> bool:
    from tidemark.runtime.prepared_call import (
        PreparedListValue,
        PreparedMappingValue,
        PreparedTupleValue,
    )

    if type(value) is ReferenceId:
        return True
    if type(value) in (PreparedListValue, PreparedTupleValue):
        return any(_prepared_value_contains_reference(item) for item in value.items)
    if type(value) is PreparedMappingValue:
        return any(
            _prepared_value_contains_reference(entry.value)
            for entry in value.entries
        )
    return False


def _prepared_value_primitive(value: object) -> object:
    from tidemark.runtime.prepared_call import (
        PreparedListValue,
        PreparedMappingValue,
        PreparedTupleValue,
    )

    if value is None:
        return ("null",)
    if type(value) is str:
        return ("string", value)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int:
        return ("integer", value)
    if type(value) is ReferenceId:
        return ("reference", value.value)
    if type(value) is PreparedListValue:
        return (
            "list",
            tuple(_prepared_value_primitive(item) for item in value.items),
        )
    if type(value) is PreparedTupleValue:
        return (
            "tuple",
            tuple(_prepared_value_primitive(item) for item in value.items),
        )
    if type(value) is PreparedMappingValue:
        return (
            "mapping",
            tuple(
                (entry.key, _prepared_value_primitive(entry.value))
                for entry in value.entries
            ),
        )
    raise TypeError("unsupported prepared runtime value")


__all__ = ()
