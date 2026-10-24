# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from .model import (
    ChildInfo, ChildKind, CompoundFieldKind, DataType, DataTypeKind,
    EventFieldInfo, EventType,
    InstanceType, InstanceTypeKind, MethodArgumentInfo,
)
from ..nodeset.index import NodeSetIndex
from ..nodeset.instance_index import InstanceTypeIndex
from ..nodeset.model import ModellingRule, NodeClass
from ..naming import to_camel_back, cpp_identifier, get_symbolic_name, to_snake_case
from ..codegen.emit_simple import is_native_type


def _browse_name_ns_index(raw_browse_name: str) -> int:
    """Namespace index from a raw BrowseName ('N:Name' -> N, 'Name' -> 0)."""
    pos = raw_browse_name.find(":")
    if pos == -1:
        return 0
    prefix = raw_browse_name[:pos]
    try:
        return int(prefix)
    except ValueError:
        return 0


def is_built_in(symbolic_name: str) -> bool:
    # Mirrors C++ `is_built_in` list.
    return symbolic_name in {
        "Boolean",
        "Byte",
        "SByte",
        "Int16",
        "UInt16",
        "Int32",
        "UInt32",
        "Int64",
        "UInt64",
        "Float",
        "Double",
        "String",
        "DateTime",
        "Guid",
        "ByteString",
        "XmlElement",
        "NodeId",
        "ExpandedNodeId",
        "StatusCode",
        "QualifiedName",
        "LocalizedText",
        "Structure",
        "Union",
        "DataValue",
        "BaseDataType",
        "DiagnosticInfo",
        "Enumeration",
        "Number",
        "Integer",
        "UInteger",
        "Decimal",
    }


def is_excluded(symbolic_name: str) -> bool:
    # Mirrors C++ `is_excluded`.
    return symbolic_name in {
        "Union",
        "Managed",
        "VariableNode",
        "VariableTypeNode",
        "ObjectNode",
        "ObjectTypeNode",
        "ReferenceTypeNode",
        "ViewNode",
        "MethodNode",
        "DataTypeNode",
        "InstanceNode",
        "TypeNode",
        "Node",
        "DecimalDataType",
    }


def is_json_pubsub_message(symbolic_name: str) -> bool:
    """The PubSub JSON message-mapping category (OPC 10000-14).

    Types named ``Json<...>Message`` - ``JsonDataSetMessage``, ``JsonNetworkMessage``,
    ``JsonActionRequestMessage`` and the rest - describe the JSON wire shapes of
    PubSub network/dataset/action messages. In the Services NodeSet they carry no
    ``<Category>`` (so the ``PubSub`` ``<Category>`` skip misses them) and own no
    Binary/XML/JSON encoding Objects, so they are not encodable by the SDK codec.
    The SDK core does not implement PubSub, so this whole category is excluded.

    The pattern is anchored both ends so it cannot match the core
    ``NotificationMessage`` (no ``Json`` prefix) or the PubSub helper structs
    ``Json*ContentMask`` / ``Json*MessageDataType`` (which do not end in ``Message``
    and are already excluded by the ``PubSub`` ``<Category>`` skip).
    """
    return symbolic_name.startswith("Json") and symbolic_name.endswith("Message")


def classify_data_type(index: NodeSetIndex, node_id: str) -> DataTypeKind:
    # Mirrors the C++ high-level classification by subtype, with guards:
    # - some subtypes of Enumeration do not actually carry an enum field list
    # - structures should have a definition for reliable codegen
    node = index.find(node_id)
    definition = node.definition if node is not None else None

    if node is not None:
        symbolic = get_symbolic_name(node.browse_name)
        if is_built_in(symbolic):
            return DataTypeKind.unknown

    if definition is not None and definition.is_option_set:
        return DataTypeKind.option_set

    if index.is_subtype_of(node_id, "Enumeration"):
        if definition is not None and definition.fields:
            return DataTypeKind.enumeration
        return DataTypeKind.unknown

    if index.is_subtype_of(node_id, "Structure"):
        if definition is not None:
            if definition.is_union or index.is_subtype_of(node_id, "Union"):
                return DataTypeKind.union
            return DataTypeKind.structure
        return DataTypeKind.unknown

    return DataTypeKind.unknown


# Map from OPC UA DataType BrowseName to C++ type for instance-handle property accessors.
_INSTANCE_NATIVE_MAP: dict[str, tuple[str, str]] = {
    # (cpp_type, variant_type_check)
    "Boolean": ("bool", "is_boolean"),
    "Byte": ("uint8_t", "is_uint8"),
    "SByte": ("int8_t", "is_int8"),
    "UInt16": ("uint16_t", "is_uint16"),
    "UInt32": ("uint32_t", "is_uint32"),
    "UInt64": ("uint64_t", "is_uint64"),
    "Int16": ("int16_t", "is_int16"),
    "Int32": ("int32_t", "is_int32"),
    "Int64": ("int64_t", "is_int64"),
    "Double": ("double", "is_double"),
    "Float": ("float", "is_float"),
    "String": ("String", "is_string"),
    "DateTime": ("DateTime", "is_date_time"),
    "ByteString": ("ByteString", "is_byte_string"),
    "Guid": ("Guid", "is_guid"),
    "NodeId": ("NodeId", "is_node_id"),
    "StatusCode": ("StatusCode", "is_status_code"),
    "QualifiedName": ("QualifiedName", "is_qualified_name"),
    "LocalizedText": ("LocalizedText", "is_localized_text"),
}

# DataType NodeId -> BrowseName for well-known ns=0 data types.
# These can appear as raw NodeIds like "i=7" in DataType attributes.
_WELL_KNOWN_DATA_TYPE_IDS: dict[str, str] = {
    "i=1": "Boolean",
    "i=2": "SByte",
    "i=3": "Byte",
    "i=4": "Int16",
    "i=5": "UInt16",
    "i=6": "Int32",
    "i=7": "UInt32",
    "i=8": "Int64",
    "i=9": "UInt64",
    "i=10": "Float",
    "i=11": "Double",
    "i=12": "String",
    "i=13": "DateTime",
    "i=14": "Guid",
    "i=15": "ByteString",
    "i=19": "StatusCode",
    "i=20": "QualifiedName",
    "i=21": "LocalizedText",
    "i=17": "NodeId",
    "i=296": "Argument",
}


def _resolve_data_type_name(data_type_id: str | None) -> str | None:
    """Resolve a DataType NodeId to a BrowseName."""
    if data_type_id is None:
        return None
    # Try well-known IDs first
    name = _WELL_KNOWN_DATA_TYPE_IDS.get(data_type_id)
    if name:
        return name
    # If it's a BrowseName already (e.g. "UInt64"), use it directly
    if not data_type_id.startswith("i=") and not data_type_id.startswith("ns="):
        return data_type_id
    return None


def _resolve_cpp_type(data_type_name: str | None) -> tuple[str, str]:
    """Return (cpp_type, variant_type_check) for a DataType name, or ("Variant", "") as fallback."""
    if data_type_name and data_type_name in _INSTANCE_NATIVE_MAP:
        return _INSTANCE_NATIVE_MAP[data_type_name]
    return ("Variant", "")


# PropertyType and BaseDataVariableType NodeIds (ns=0)
_PROPERTY_TYPE_ID = "i=68"
_BASE_DATA_VARIABLE_TYPE_ID = "i=63"


# Types that should be passed by move in method adapters (non-trivial types)
_MOVE_TYPES = {"ByteString", "String", "NodeId", "QualifiedName", "LocalizedText", "Variant"}


def _is_move_type(cpp_type: str) -> bool:
    return cpp_type in _MOVE_TYPES


def _build_method_argument(arg) -> MethodArgumentInfo:
    """Build a MethodArgumentInfo from a UaMethodArgument."""
    data_type_name = _resolve_data_type_name(arg.data_type)
    cpp_type, _ = _resolve_cpp_type(data_type_name)
    is_array = arg.value_rank >= 1
    # Avoid an ill-formed `DateTime DateTime{};` when an argument's Name equals its
    # own scalar C++ type token - the injected member name would shadow the type in
    # its own declaration. Append `_` (mirrors emit_structures' field-name collision
    # handling). Arguments are wired positionally, so the literal name carries no
    # on-wire meaning; array args never collide (type token is `std::vector<...>`).
    field_name = arg.name
    if not is_array and field_name == cpp_type:
        field_name = field_name + "_"
    return MethodArgumentInfo(
        name=field_name,
        cpp_type=cpp_type,
        is_move_type=is_array or _is_move_type(cpp_type),
        is_array=is_array,
    )


def _classify_child(child) -> ChildKind:
    """Classify a UaChildDeclaration into a ChildKind."""
    if child.node_class == NodeClass.method:
        return ChildKind.method
    if child.node_class == NodeClass.object:
        return ChildKind.child_object
    # Variable node
    if child.reference_type == "HasProperty":
        return ChildKind.property
    return ChildKind.data_variable


# --- Instance type auto-discovery exclusion and category lists ---

_INSTANCE_TYPE_BUILT_IN = {
    "BaseObjectType",   # hand-coded base class (in instance_types/)
    "BaseVariableType", # hand-coded base class (in instance_types/)
}

# Types whose class name collides with existing non-generated SDK types.
_INSTANCE_TYPE_NAME_COLLISION = {
    "ApplicationConfigurationType",  # collides with ua_application_configuration.h struct
    "ServerConfigurationType",       # collides with ua_server_configuration.h struct
    "OptionSetType",                 # collides with ua_option_set.h generated data type
    "DataTypeDescriptionType",       # collides with ua_data_type_description.h generated data type
    "DataTypeDictionaryType",        # legacy type with special instantiation constraints
}

_INSTANCE_TYPE_SERVER_INFRA = {
    # Server object tree - remaining excluded types
    "TransparentRedundancyType",
    "NonTransparentRedundancyType",
    "NonTransparentNetworkRedundancyType",
    "SessionsDiagnosticsSummaryType",
    "HistoryServerCapabilitiesType",
    # Meta-infrastructure
    "ModellingRuleType",
    "DataTypeSystemType",
    "DataTypeEncodingType",
    "AggregateFunctionType",
    "AggregateConfigurationType",
    # Server diagnostics variable types (complex diagnostics not yet needed)
    "ServerDiagnosticsSummaryType",
    "SamplingIntervalDiagnosticsArrayType",
    "SamplingIntervalDiagnosticsType",
    "SubscriptionDiagnosticsArrayType",
    "SubscriptionDiagnosticsType",
    "SessionDiagnosticsArrayType",
    "SessionDiagnosticsVariableType",
    "SessionSecurityDiagnosticsArrayType",
    "SessionSecurityDiagnosticsType",
}

# Explicit class name overrides for types whose default "strip Type suffix" name
# would collide with other SDK types.
_CLASS_NAME_OVERRIDES: dict[str, str] = {
    "ServerType": "ServerObject",          # avoids confusion with ua::server::Server
    "BuildInfoType": "BuildInfoVariable",  # avoids collision with ua::BuildInfo data type
}

# Category assignment uses the <Category> element from the NodeSet XML.
# Each XML category string is mapped to a SDK category by prefix matching.
# Types whose XML category doesn't match any prefix remain in "core".
# Longer (more-specific) prefixes are checked first to avoid
# shorter prefixes matching too eagerly.
_XML_CATEGORY_PREFIX_MAP: list[tuple[str, str]] = sorted([
    ("A & C",                               "alarms"),
    ("PubSub",                              "pubsub"),
    ("Data Access",                         "dataaccess"),
    ("BNM",                                 "network"),
    ("GDS",                                 "security"),
    ("Authorization Service",               "security"),
    ("Security",                            "security"),
    ("Onboarding",                          "security"),
    ("Push Model",                          "security"),
    ("Program",                             "statemachine"),
    ("Base Info State Machine",             "statemachine"),
    ("Base Info Finite State Machine",      "statemachine"),
    ("Base Info Choice States",             "statemachine"),
    ("Base Info Available States",          "statemachine"),
    ("Base Info Spatial Data",              "geometry"),
    ("Base Info Rational Number",           "geometry"),
    ("Historical Access",                   "historizing"),
    ("Address Space Dictionary",            "dictionary"),
    ("Address Space Events",                "events"),
    ("Auditing",                            "events"),
    ("Base Info Client Events",             "events"),
    ("Base Info EventQueueOverflow",        "events"),
    ("Base Info Progress Events",           "events"),
    ("Base Info Model Change",              "events"),
    ("Base Info SemanticChange",            "events"),
    ("Base Info System Status",             "events"),
    ("Base Info Device Failure",            "events"),
    ("Redundancy",                          "server_infra"),
    ("Aggregate",                           "server_infra"),
], key=lambda x: -len(x[0]))

# Explicit overrides for types whose XML <Category> is missing or doesn't
# map cleanly to an SDK category via prefix.
_XML_CATEGORY_OVERRIDES: dict[str, str] = {
    "HistoricalDataConfigurationType":  "historizing",
    "ProgramDiagnosticType":            "statemachine",
    "ProgramTransitionAuditEventType":  "events",
    "UserCredentialCertificateType":    "security",
    "FileTransferStateMachineType":     "statemachine",
}

# All known SDK categories (used by --include-categories=all).
_ALL_CATEGORIES = {
    "alarms", "pubsub", "dataaccess", "network", "security",
    "statemachine", "historizing", "dictionary", "events",
}


def all_category_names() -> set[str]:
    """Return the set of all known category names."""
    return set(_ALL_CATEGORIES)


def _get_type_category(node) -> str | None:
    """Return the SDK category for a type based on its XML <Category>, or None for core."""
    browse_name = node.browse_name
    # Strip namespace prefix (e.g. "0:FolderType" -> "FolderType")
    if ":" in browse_name:
        browse_name = browse_name.split(":", 1)[1]
    override = _XML_CATEGORY_OVERRIDES.get(browse_name)
    if override is not None:
        return override
    xml_cat = node.category
    if not xml_cat:
        return None
    for prefix, sdk_cat in _XML_CATEGORY_PREFIX_MAP:
        if xml_cat.startswith(prefix):
            return sdk_cat
    return None


def _resolve_child_type_class_name(
    instance_index: InstanceTypeIndex,
    child,
    generated_type_ids: set[str] | None = None,
    ctx=None,
) -> tuple[str, str, str]:
    """Resolve a child's instance-handle class name + cross-spec qualification.

    Returns ``(class_name, qualifier, include_prefix)``. ``class_name`` is empty
    when the child has no generated handle. ``qualifier`` is ``""`` for an in-spec
    (or NS0) child and ``::<owner-namespace>::`` for a child owned by a different
    spec; ``include_prefix`` is the owning spec's filename prefix. ``ctx`` is the
    emitting EmitContext (duck-typed to avoid a codegen->types import cycle);
    when absent, callers get the legacy NS0 defaults.
    """
    td_id = child.type_definition_id
    if not td_id:
        return "", "", "ua_"
    # Only resolve if this type is actually being generated (or hand-coded)
    if generated_type_ids is not None and td_id not in generated_type_ids:
        return "", "", "ua_"
    td_node = instance_index.find(td_id)
    if td_node is None:
        return "", "", "ua_"
    td_symbolic = get_symbolic_name(td_node.browse_name)
    class_name = _CLASS_NAME_OVERRIDES.get(td_symbolic, "")
    if not class_name:
        class_name = td_symbolic
        if class_name.endswith("Type"):
            class_name = class_name[:-4]
    class_name = cpp_identifier(class_name)  # legal C++ for hyphenated BrowseNames

    qualifier = ""
    include_prefix = "ua_"
    if ctx is not None:
        include_prefix = ctx.include_prefix
        owner = ctx.index.config_for_source(td_node.source_nodeset) if td_node.source_nodeset else None
        if owner is not None and owner.uri != ctx.config.uri:
            # Child handle is owned by a different spec (e.g. an NS0 FolderType
            # referenced from ua::di) - qualify it and use the owner's prefix.
            qualifier = f"::{owner.cpp_namespace}::"
            include_prefix = owner.include_prefix
    return class_name, qualifier, include_prefix


def _declares_abstract_type(instance_index: InstanceTypeIndex, child) -> bool:
    """True when @p child's declared TypeDefinition is an abstract type the index holds."""
    if not child.type_definition_id:
        return False
    td_node = instance_index.find(child.type_definition_id)
    return td_node is not None and bool(td_node.is_abstract)


def _build_single_instance_type(
    instance_index: InstanceTypeIndex,
    node,
    generated_type_ids: set[str] | None = None,
    ctx=None,
) -> InstanceType:
    """Build an InstanceType from a UaTypeDefinitionNode."""
    symbolic = get_symbolic_name(node.browse_name)
    class_name = _CLASS_NAME_OVERRIDES.get(symbolic, "")
    if not class_name:
        class_name = symbolic
        if class_name.endswith("Type"):
            class_name = class_name[:-4]
    # Sanitise so a BrowseName with hyphens/spaces (e.g. DEXPI "ISO10209-2012")
    # yields a legal C++ class/file/guard. No-op on already-legal names (NS0 + the
    # green specs unchanged); the TypeId reference is sanitised identically.
    class_name = cpp_identifier(class_name)

    kind = (
        InstanceTypeKind.object_type
        if node.type_node_class == "ObjectType"
        else InstanceTypeKind.variable_type
    )

    is_final = not instance_index.has_subtypes(node.node_id)

    def _make_child_info(child) -> ChildInfo | None:
        # Skip placeholder declarations (Part 3 section 6.4.2): browse-name is a
        # template (`<...>`); concrete instances pick server-chosen names at
        # runtime. There's no fixed accessor to emit. Callers needing these
        # members enumerate dynamic children via the address-space API.
        if child.modelling_rule in (
            ModellingRule.mandatory_placeholder,
            ModellingRule.optional_placeholder,
        ):
            return None
        child_kind = _classify_child(child)
        data_type_name = _resolve_data_type_name(child.data_type)
        cpp_type, variant_type_check = _resolve_cpp_type(data_type_name)
        is_array = child.value_rank is not None and child.value_rank >= 1
        child_browse = get_symbolic_name(child.browse_name)
        # C++ identifier base: prefer the child's SymbolicName, else sanitise the
        # browse name. Equal to ``child_browse`` for NS0 (byte-identical output).
        child_cpp_name = cpp_identifier(child.browse_name, child.symbolic_name)
        # BrowseName namespace: the raw BrowseName prefix ("N:Name") is the local
        # ns index in the declaring nodeset; 0 (or no prefix) => NS0, any other =>
        # the declaring (companion) spec's namespace. NS0 children are always
        # ns-0 here (byte-identical); a companion type's own children carry the
        # companion namespace and must resolve it at runtime for the lookup.
        child_browse_name_ns_zero = _browse_name_ns_index(child.browse_name) == 0
        input_args = [_build_method_argument(a) for a in child.input_arguments]
        output_args = [_build_method_argument(a) for a in child.output_arguments]
        child_type_class = ""
        child_type_qualifier = ""
        child_type_include_prefix = "ua_"
        if child_kind in (ChildKind.child_object, ChildKind.data_variable):
            child_type_class, child_type_qualifier, child_type_include_prefix = (
                _resolve_child_type_class_name(instance_index, child, generated_type_ids, ctx))

        return ChildInfo(
            browse_name=child_browse,
            cpp_name=child_cpp_name,
            kind=child_kind,
            cpp_type=cpp_type,
            is_array=is_array,
            modelling_rule=child.modelling_rule,
            reference_type=child.reference_type,
            variant_type_check=variant_type_check,
            input_arguments=input_args,
            output_arguments=output_args,
            child_type_class_name=child_type_class,
            child_type_qualifier=child_type_qualifier,
            child_type_include_prefix=child_type_include_prefix,
            browse_name_ns_zero=child_browse_name_ns_zero,
            declared_type_abstract=_declares_abstract_type(instance_index, child),
        )

    # A handle must expose the members it *inherits*, not just the ones its type
    # redeclares. The instance-handle emitters only see ``InstanceType.children``,
    # so flatten the supertype chain here (most-derived first): own declarations,
    # then each ancestor's. A redeclaration (same browse name, most-derived) wins.
    #
    # Inherited *properties* are flattened - e.g. AnalogItemType inherits
    # EngineeringUnits/InstrumentRange from BaseAnalogType, and AnalogUnitType
    # inherits the mandatory EURange. Without this the inheriting handle silently
    # drops those accessors. Property accessors resolve their node by browse name
    # at runtime, so flattening is safe regardless of where the property is
    # declared. Inherited components/methods are intentionally NOT flattened yet
    # (own-only) - their child-type/include resolution is a larger change and not
    # required by any current consumer. Event types have their own flattening pass
    # (see ``_build_event_types``) and do not go through here.
    children: list[ChildInfo] = []
    seen_browse: set[str] = set()
    walk_node = node
    depth = 0
    while walk_node is not None:
        for child in walk_node.children:
            child_browse = get_symbolic_name(child.browse_name)
            if depth > 0:
                # Inherited: flatten properties only, and skip redeclarations a
                # more-derived type already contributed.
                if _classify_child(child) != ChildKind.property:
                    continue
                if child_browse in seen_browse:
                    continue
            info = _make_child_info(child)
            if info is None:
                continue
            seen_browse.add(child_browse)
            children.append(info)
        parent_id = walk_node.parent_type_id
        walk_node = instance_index.find(parent_id) if parent_id else None
        depth += 1

    return InstanceType(
        node_id=node.node_id,
        browse_name=symbolic,
        class_name=class_name,
        kind=kind,
        is_abstract=node.is_abstract,
        is_final=is_final,
        parent_type_id=node.parent_type_id,
        children=children,
    )


def _is_included_type(
    node, symbolic: str, included_categories: set[str] | None,
) -> bool:
    """Check if a type should be included in generation."""
    if node.is_abstract:
        return False
    if symbolic in _INSTANCE_TYPE_BUILT_IN:
        return False
    if symbolic in _INSTANCE_TYPE_NAME_COLLISION:
        return False
    if symbolic in _INSTANCE_TYPE_SERVER_INFRA:
        return False
    category = _get_type_category(node)
    if category == "server_infra":
        return False
    if category is not None:
        if included_categories is None or category not in included_categories:
            return False
    return True


# Node IDs for SDK-provided handles that can be used as child type references.
_SDK_HANDLE_TYPE_IDS: set[str] = {
    "i=58",   # BaseObjectType
    "i=62",   # BaseVariableType
    "i=63",   # BaseDataVariableType
}


def build_all_instance_types(
    instance_index: InstanceTypeIndex,
    included_categories: set[str] | None = None,
    ctx=None,
) -> list[InstanceType]:
    """Auto-discover and build InstanceTypes from the full NodeSet.

    Uses a two-pass approach: first collects which types will be generated,
    then builds models with child_type_class_name only for types that exist.
    ``ctx`` (the emitting EmitContext) drives cross-spec child resolution.
    """
    # Pass 1: collect node IDs of types that will be generated (or are hand-coded)
    generated_type_ids: set[str] = set(_SDK_HANDLE_TYPE_IDS)
    included_nodes: list = []

    for node in instance_index.type_nodes.values():
        symbolic = get_symbolic_name(node.browse_name)
        if _is_included_type(node, symbolic, included_categories):
            generated_type_ids.add(node.node_id)
            included_nodes.append(node)

    # Pass 2: build models with knowledge of which types exist
    result: list[InstanceType] = []
    for node in included_nodes:
        result.append(_build_single_instance_type(instance_index, node, generated_type_ids, ctx))

    result.sort(key=lambda t: t.browse_name)
    return result


def build_instance_types(
    instance_index: InstanceTypeIndex,
    include_list: list[str],
    ctx=None,
) -> list[InstanceType]:
    """Build InstanceType models for the specified type BrowseNames."""
    # Collect node IDs for the explicitly included types + hand-coded types
    generated_type_ids: set[str] = set(_SDK_HANDLE_TYPE_IDS)
    nodes: list = []
    for type_name in include_list:
        node = instance_index.find_by_browse_name(type_name)
        if node is None:
            raise KeyError(f"Type '{type_name}' not found in NodeSet")
        generated_type_ids.add(node.node_id)
        nodes.append(node)

    result: list[InstanceType] = []
    for node in nodes:
        result.append(_build_single_instance_type(instance_index, node, generated_type_ids, ctx))

    return result


def build_types(index: NodeSetIndex, ordered_node_ids: list[str] | None = None) -> list[DataType]:
    result: list[DataType] = []

    if ordered_node_ids is None:
        nodes = list(index.data_types.values())
        nodes.sort(key=lambda n: (n.node_id, n.browse_name))
    else:
        # Mirror the C++ generator: preserve first-seen ordering from NodeSet scans.
        nodes = []
        for node_id in ordered_node_ids:
            node = index.find(node_id)
            if node is None:
                continue
            nodes.append(node)

    for node in nodes:
        result.append(
            DataType(
                node_id=node.node_id,
                browse_name=node.browse_name,
                parent_node_id=node.parent_node_id,
                kind=classify_data_type(index, node.node_id),
            )
        )

    return result


# --- Event type discovery ---

# BaseEventType NodeId (ns=0)
_BASE_EVENT_TYPE_ID = "i=2041"

# Map from OPC UA enum DataType BrowseName to (C++ type, Variant expression template, include header).
# The expression template uses {field} as a placeholder for the snake_case field name.
_EVENT_ENUM_MAP: dict[str, tuple[str, str, str]] = {
    "ServerState": ("ServerState", "static_cast<int32_t>({field})", "ua_server_state.h"),
}

# Variable-type children to emit as compound struct members on event types.
# Maps TypeDefinition NodeId -> (C++ type, include header, CompoundFieldKind).
_COMPOUND_VARIABLE_TYPE_MAP: dict[str, tuple[str, str, CompoundFieldKind]] = {
    "i=8995": ("TwoStateVariableState", "ua_variable_states.h", CompoundFieldKind.two_state),
    "i=9002": ("ConditionVariableState", "ua_variable_states.h", CompoundFieldKind.condition_var),
}

# State-machine OBJECT children to emit as compound struct members on event types. A client selects
# the machine's CurrentState (Value = LocalizedText) and CurrentState.Id (NodeId) via an EventFilter,
# so the payload carries a FiniteStateVariableState snapshot. Maps the state-machine TypeDefinition
# NodeId -> (C++ type, include header, CompoundFieldKind). ExclusiveLimitStateMachineType (i=9318) is
# the LimitState component of ExclusiveLimitAlarmType (Part 9 section 5.8.4); ShelvedStateMachineType
# (i=2929) is the ShelvingState component of AlarmConditionType.
_STATE_MACHINE_COMPONENT_MAP: dict[str, tuple[str, str, CompoundFieldKind]] = {
    "i=9318": ("FiniteStateVariableState", "ua_variable_states.h", CompoundFieldKind.finite_state),
    # ShelvedStateMachineType, the Optional ShelvingState of AlarmConditionType (Part 9 5.8.10). Without
    # it a Client selecting ShelvingState/CurrentState receives null and cannot tell that an alarm
    # supports shelving at all.
    "i=2929": ("ShelvedStateVariableState", "ua_variable_states.h", CompoundFieldKind.shelved_state),
}


def _event_class_name(browse_name: str) -> str:
    """Derive event struct class name from the browse name.

    Strip the spec's trailing ``Type`` and append ``Payload``. The emitted struct
    is a field-data carrier for an event notification, not the EventType meta -
    the suffix makes that explicit and disambiguates against same-browse-name
    object-type instance handles (which live under ``object_types/`` with the
    bare browse-name-minus-Type). E.g. ``AcknowledgeableConditionType`` ->
    ``AcknowledgeableConditionPayload``; ``SystemEventType`` ->
    ``SystemEventPayload``.
    """
    symbolic = get_symbolic_name(browse_name)
    if symbolic.endswith("Type"):
        symbolic = symbolic[:-4]
    return symbolic + "Payload"


def build_event_types(
    instance_index: InstanceTypeIndex,
    ctx=None,
) -> list[EventType]:
    """Build EventType models for all event types under BaseEventType.

    Returns a topologically sorted list (parents before children). ``ctx`` (the
    emitting EmitContext) drives cross-spec parent resolution: an event whose
    parent payload is owned by another spec (e.g. a companion alarm type whose
    parent is NS0's AlarmConditionType) gets the owning spec's filename prefix
    and ``::ns::`` qualification.
    """
    def _parent_ref(parent_node) -> tuple[str, str]:
        """(class_name, header) for an event's parent payload, owner-aware."""
        pclass = _event_class_name(parent_node.browse_name)
        header_base = to_snake_case(pclass)
        if ctx is None:
            return pclass, f"ua_{header_base}.h"
        owner = (ctx.index.config_for_source(parent_node.source_nodeset)
                 if parent_node.source_nodeset else None)
        if owner is not None and owner.uri != ctx.config.uri:
            return f"::{owner.cpp_namespace}::{pclass}", f"{owner.include_prefix}{header_base}.h"
        return pclass, f"{ctx.include_prefix}{header_base}.h"

    # 1. Collect all subtypes of BaseEventType
    base_node = instance_index.find(_BASE_EVENT_TYPE_ID)
    if base_node is None:
        return []

    # Gather all transitive subtypes by parent_type_id walk
    event_node_ids: set[str] = set()
    for node in instance_index.type_nodes.values():
        if node.node_id == _BASE_EVENT_TYPE_ID:
            continue
        if instance_index.is_subtype_of(node.node_id, _BASE_EVENT_TYPE_ID):
            event_node_ids.add(node.node_id)

    # 2. Topological sort: parents before children
    sorted_ids: list[str] = []
    visited: set[str] = set()

    def _visit(nid: str) -> None:
        if nid in visited or nid not in event_node_ids:
            return
        visited.add(nid)
        node = instance_index.find(nid)
        if node and node.parent_type_id and node.parent_type_id in event_node_ids:
            _visit(node.parent_type_id)
        sorted_ids.append(nid)

    for nid in sorted(event_node_ids):
        _visit(nid)

    # 3. Build EventType models
    result: list[EventType] = []
    for nid in sorted_ids:
        node = instance_index.find(nid)
        if node is None:
            continue

        class_name = _event_class_name(node.browse_name)
        is_abstract = node.is_abstract

        # Determine parent class. ``BaseEvent`` is the NS0 root, reachable from a
        # companion spec via its aliases header (so it stays unqualified). A
        # concrete parent payload is resolved owner-aware.
        parent_id = node.parent_type_id
        if parent_id == _BASE_EVENT_TYPE_ID:
            parent_class_name = "BaseEvent"
            parent_header = "ua_base_event.h"
        else:
            parent_node = instance_index.find(parent_id) if parent_id else None
            if parent_node:
                parent_class_name, parent_header = _parent_ref(parent_node)
            else:
                parent_class_name = "BaseEvent"
                parent_header = "ua_base_event.h"

        # Collect compound field browse names declared by any ancestor event type
        # so we can skip redeclarations (e.g. EnabledState on AcknowledgeableConditionType
        # when it's already declared on ConditionType).
        # Same treatment for HasProperty fields - without this, e.g. KeyCredentialDeletedAuditEvent
        # re-declares ResourceUri from KeyCredentialAuditEvent and the redeclaration shadows
        # the parent's field via name lookup, but the parent's resolve_field intercepts the
        # browse path first -> the child's value is unreachable at runtime.
        ancestor_compound_fields: set[str] = set()
        ancestor_property_fields: set[str] = set()
        walk_id = node.parent_type_id
        while walk_id and walk_id != _BASE_EVENT_TYPE_ID:
            ancestor = instance_index.find(walk_id)
            if ancestor is None:
                break
            for ac in ancestor.children:
                if (ac.reference_type == "HasComponent"
                        and ac.node_class == NodeClass.object
                        and ac.type_definition_id in _STATE_MACHINE_COMPONENT_MAP):
                    ancestor_compound_fields.add(get_symbolic_name(ac.browse_name))
                    continue
                if ac.node_class != NodeClass.variable:
                    continue
                if (ac.reference_type == "HasComponent"
                        and ac.type_definition_id in _COMPOUND_VARIABLE_TYPE_MAP):
                    ancestor_compound_fields.add(get_symbolic_name(ac.browse_name))
                elif ac.reference_type == "HasProperty":
                    ancestor_property_fields.add(get_symbolic_name(ac.browse_name))
            walk_id = ancestor.parent_type_id

        # Extract own fields
        own_fields: list[EventFieldInfo] = []
        for child in node.children:
            # State-machine OBJECT component (e.g. LimitState: ExclusiveLimitStateMachine) -> a
            # FiniteStateVariableState compound field carrying CurrentState (+ .Id). Handled before
            # the variable-only filter below because the component is an Object, not a Variable.
            if (child.node_class == NodeClass.object
                    and child.reference_type == "HasComponent"
                    and child.type_definition_id in _STATE_MACHINE_COMPONENT_MAP):
                sm_browse = get_symbolic_name(child.browse_name)
                if sm_browse in ancestor_compound_fields:
                    continue  # Inherited from a parent type - skip
                sm_cpp = cpp_identifier(child.browse_name, child.symbolic_name)
                sm_type, sm_header, sm_kind = _STATE_MACHINE_COMPONENT_MAP[child.type_definition_id]
                own_fields.append(EventFieldInfo(
                    browse_name=sm_browse,
                    cpp_name=sm_cpp,
                    cpp_type=sm_type,
                    variant_expression=to_camel_back(sm_cpp),
                    include_header=sm_header,
                    is_optional=child.modelling_rule == ModellingRule.optional,
                    compound_kind=sm_kind,
                ))
                continue

            if child.node_class != NodeClass.variable:
                continue

            child_browse = get_symbolic_name(child.browse_name)
            # C++ identifier base for the event field member; equals child_browse
            # for NS0 (byte-identical output).
            child_cpp = cpp_identifier(child.browse_name, child.symbolic_name)
            is_optional = child.modelling_rule == ModellingRule.optional

            if child.reference_type == "HasProperty":
                if child_browse in ancestor_property_fields:
                    continue  # Redeclaration from parent type - skip
                # Simple property field
                data_type_name = _resolve_data_type_name(child.data_type)

                if data_type_name and data_type_name in _EVENT_ENUM_MAP:
                    cpp_type, expr_template, include_header = _EVENT_ENUM_MAP[data_type_name]
                    field_name = to_camel_back(child_cpp)
                    variant_expr = expr_template.format(field=field_name)
                else:
                    cpp_type, _ = _resolve_cpp_type(data_type_name)
                    field_name = to_camel_back(child_cpp)
                    variant_expr = field_name
                    include_header = ""

                own_fields.append(EventFieldInfo(
                    browse_name=child_browse,
                    cpp_name=child_cpp,
                    cpp_type=cpp_type,
                    variant_expression=variant_expr,
                    include_header=include_header,
                    is_optional=is_optional,
                    is_array=child.value_rank is not None and child.value_rank >= 1,
                ))

            elif (child.reference_type == "HasComponent"
                  and child.type_definition_id in _COMPOUND_VARIABLE_TYPE_MAP):
                # Compound variable-type child (TwoStateVariable, ConditionVariable)
                if child_browse in ancestor_compound_fields:
                    continue  # Redeclaration from parent type - skip

                cpp_type, include_header, compound_kind = _COMPOUND_VARIABLE_TYPE_MAP[
                    child.type_definition_id]
                field_name = to_camel_back(child_cpp)

                own_fields.append(EventFieldInfo(
                    browse_name=child_browse,
                    cpp_name=child_cpp,
                    cpp_type=cpp_type,
                    variant_expression=field_name,
                    include_header=include_header,
                    is_optional=is_optional,
                    compound_kind=compound_kind,
                ))

        result.append(EventType(
            node_id=nid,
            browse_name=get_symbolic_name(node.browse_name),
            class_name=class_name,
            is_abstract=is_abstract,
            parent_class_name=parent_class_name,
            parent_header=parent_header,
            own_fields=own_fields,
        ))

    return result
