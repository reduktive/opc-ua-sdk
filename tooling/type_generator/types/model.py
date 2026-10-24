# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from ..nodeset.model import ModellingRule


class DataTypeKind(str, Enum):
    structure = "structure"
    union = "union"
    enumeration = "enumeration"
    option_set = "option_set"
    alias = "alias"
    unknown = "unknown"


class DataType(BaseModel):
    """Codegen-facing DataType representation.

    This is intentionally minimal for the first iteration and will be extended
    as we port more of the C++ generator pipeline.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str
    kind: DataTypeKind
    parent_node_id: str | None = None


# --- Instance handle codegen models ---


class ChildKind(str, Enum):
    property = "property"
    data_variable = "data_variable"
    method = "method"
    child_object = "child_object"


class MethodArgumentInfo(BaseModel):
    """One argument of a method (input or output)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str  # e.g. "Mode", "FileHandle"
    cpp_type: str  # e.g. "uint8_t", "ByteString"
    is_move_type: bool = False  # True for types that should be std::move'd (ByteString, String, etc.)
    is_array: bool = False  # True when ValueRank >= 1


class ChildInfo(BaseModel):
    """Codegen-facing description of one child accessor to generate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    browse_name: str  # WIRE BrowseName string for QualifiedName{0, "..."} (never sanitised)
    # C++ identifier base for accessor/method names (snake-cased downstream).
    # Derived from the child's SymbolicName when present, else a sanitised
    # browse name. For NS0 this equals ``browse_name`` (byte-identical output).
    cpp_name: str = ""
    kind: ChildKind
    cpp_type: str
    is_array: bool = False
    modelling_rule: ModellingRule
    reference_type: str
    variant_type_check: str = ""  # e.g. "is_uint64" for type validation in read shortcuts
    input_arguments: list[MethodArgumentInfo] = []
    output_arguments: list[MethodArgumentInfo] = []
    child_type_class_name: str = ""  # C++ class name of child object/variable type handle (e.g. "ServerCapabilities")
    # Cross-spec child resolution: a child whose type-definition is owned by a
    # different spec than the one being emitted needs a namespace qualifier
    # (e.g. ``::ua::`` for an NS0 child referenced from ``ua::di``) and the
    # owning spec's filename prefix for its handle include. Empty qualifier +
    # ``ua_`` prefix is the in-spec / NS0 default (byte-identical output).
    child_type_qualifier: str = ""
    child_type_include_prefix: str = "ua_"
    # True when the child's BrowseName is in namespace 0 (the default). False when
    # the child is declared by a companion spec, in which case its BrowseName lives
    # in that spec's namespace - the runtime QualifiedName for the child lookup
    # must resolve the spec URI to its runtime index, not hardcode 0.
    browse_name_ns_zero: bool = True
    # True when the child's declared TypeDefinition is abstract. Such a member is created only with a
    # concrete subtype an InstantiationOptions::memberTypeResolver names (OPC 10000-3 section 6.2.1).
    declared_type_abstract: bool = False


class InstanceTypeKind(str, Enum):
    object_type = "object_type"
    variable_type = "variable_type"


class InstanceType(BaseModel):
    """Codegen-facing representation of a type to generate an instance handle for."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str
    class_name: str
    kind: InstanceTypeKind
    is_abstract: bool = False
    is_final: bool = False
    parent_type_id: str | None = None
    children: list[ChildInfo] = []


# --- Event type codegen models ---


class CompoundFieldKind(str, Enum):
    """Kind of compound variable-type child on an event struct."""
    none = "none"
    two_state = "two_state"        # TwoStateVariableType  -> TwoStateVariableState
    condition_var = "condition_var"  # ConditionVariableType -> ConditionVariableState
    finite_state = "finite_state"  # FiniteStateMachine component -> FiniteStateVariableState (CurrentState + .Id)
    shelved_state = "shelved_state"  # ShelvedStateMachineType -> ShelvedStateVariableState (+ UnshelveTime)


class EventFieldInfo(BaseModel):
    """One property field on a generated event struct."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    browse_name: str  # OPC UA BrowseName, e.g. "SystemState" - WIRE string (never sanitised)
    cpp_name: str = ""  # C++ identifier base for the member; equals browse_name for NS0
    cpp_type: str  # C++ type, e.g. "ServerState"
    variant_expression: str  # expression to wrap in Variant, e.g. "static_cast<int32_t>(system_state)"
    include_header: str = ""  # extra include needed for the C++ type, empty if none
    is_optional: bool = False  # from ModellingRule
    is_array: bool = False  # ValueRank >= 1; Variant fallbacks retain their dynamic shape
    compound_kind: CompoundFieldKind = CompoundFieldKind.none  # for variable-type children


class EventType(BaseModel):
    """Codegen-facing representation of an event type to generate a struct for."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str  # e.g. "i=11446"
    browse_name: str  # e.g. "SystemStatusChangeEventType"
    class_name: str  # e.g. "SystemStatusChangeEvent"
    is_abstract: bool = False
    parent_class_name: str  # e.g. "SystemEvent" or "BaseEvent"
    parent_header: str  # e.g. "ua_system_event.h" or "ua_base_event.h"
    own_fields: list[EventFieldInfo] = []
