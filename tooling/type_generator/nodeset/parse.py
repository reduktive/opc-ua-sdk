# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

import xml.etree.ElementTree as ET

from .model import (
    ModellingRule,
    NodeClass,
    UaChildDeclaration,
    UaDataTypeDefinition,
    UaDataTypeField,
    UaDataTypeNode,
    UaDataTypeNodeWithDefinition,
    UaDataTypeRef,
    UaMethodArgument,
    UaTypeDefinitionNode,
)
from .normalize import normalize_node_id_text


def _local_name(tag: str) -> str:
    # ElementTree uses `{namespace}LocalName` form for namespaced tags.
    if tag.startswith("{"):
        closing = tag.find("}")
        if closing != -1:
            return tag[closing + 1:]
    return tag


def _is_false(text: str) -> bool:
    return text in ("false", "False", "0")


def _is_has_subtype_reference_type(ref_type: str) -> bool:
    return ref_type in ("HasSubtype", "i=45", "ns=0;i=45")


def _parse_bool(text: str) -> bool | None:
    if text in ("true", "True", "1"):
        return True
    if text in ("false", "False", "0"):
        return False
    return None


def _parse_int(text: str) -> int | None:
    try:
        return int(text)
    except Exception:
        return None


def _parse_method_arguments(value_elem: ET.Element) -> list[UaMethodArgument]:
    """Parse Argument ExtensionObjects from a Value element (InputArguments/OutputArguments)."""
    args: list[UaMethodArgument] = []

    # Walk into ListOfExtensionObject > ExtensionObject > Body > Argument
    for child in value_elem.iter():
        if _local_name(child.tag) != "Argument":
            continue

        name: str | None = None
        data_type_id: str | None = None
        value_rank: int = -1

        for field in list(child):
            field_name = _local_name(field.tag)
            if field_name == "Name":
                name = (field.text or "").strip()
            elif field_name == "DataType":
                # DataType contains an <Identifier> child
                for id_elem in list(field):
                    if _local_name(id_elem.tag) == "Identifier":
                        data_type_id = normalize_node_id_text((id_elem.text or "").strip())
                        break
            elif field_name == "ValueRank":
                vr = _parse_int((field.text or "").strip())
                if vr is not None:
                    value_rank = vr

        if name and data_type_id:
            args.append(UaMethodArgument(name=name, data_type=data_type_id, value_rank=value_rank))

    return args


def _parse_definition(
    ua_data_type_elem: ET.Element, aliases: dict[str, str] | None = None
) -> UaDataTypeDefinition | None:
    definition_elem: ET.Element | None = None
    for child in list(ua_data_type_elem):
        if _local_name(child.tag) == "Definition":
            definition_elem = child
            break

    if definition_elem is None:
        return None

    is_option_set_attr = definition_elem.attrib.get("IsOptionSet")
    is_option_set = _parse_bool(is_option_set_attr) if is_option_set_attr is not None else None

    is_union_attr = definition_elem.attrib.get("IsUnion")
    is_union = _parse_bool(is_union_attr) if is_union_attr is not None else None

    fields: list[UaDataTypeField] = []
    for f in list(definition_elem):
        if _local_name(f.tag) != "Field":
            continue

        name = f.attrib.get("Name")
        if not name:
            continue
        symbolic_name = f.attrib.get("SymbolicName")

        # <Field> may carry a <Description> child describing the enum value /
        # structure field; capture it so the emitters can use the spec text as
        # the Doxygen brief (preferred over a name-derived fallback).
        description = None
        for child in list(f):
            if _local_name(child.tag) == "Description" and (child.text or "").strip():
                description = " ".join(child.text.split())
                break

        value = _parse_int(f.attrib["Value"]) if "Value" in f.attrib else None
        value_rank = _parse_int(f.attrib["ValueRank"]) if "ValueRank" in f.attrib else None
        is_optional = _parse_bool(f.attrib["IsOptional"]) if "IsOptional" in f.attrib else None
        allow_subtypes_attr = None
        if "AllowSubtypes" in f.attrib:
            allow_subtypes_attr = f.attrib["AllowSubtypes"]
        elif "AllowSubTypes" in f.attrib:
            # NodeSet2 commonly uses this capitalization.
            allow_subtypes_attr = f.attrib["AllowSubTypes"]
        allow_subtypes = _parse_bool(allow_subtypes_attr) if allow_subtypes_attr is not None else None
        data_type = f.attrib.get("DataType")
        if data_type:
            # Resolve an alias name (e.g. "String") to its NodeId via <Aliases>;
            # NodeId-form DataTypes pass through unchanged.
            if aliases and data_type in aliases:
                data_type = aliases[data_type]
            data_type = normalize_node_id_text(data_type)

        fields.append(
            UaDataTypeField(
                name=name,
                symbolic_name=symbolic_name,
                value=value,
                data_type=data_type,
                value_rank=value_rank,
                is_optional=is_optional,
                allow_subtypes=allow_subtypes,
                description=description,
            )
        )

    return UaDataTypeDefinition(
        name=definition_elem.attrib.get("Name"),
        is_option_set=bool(is_option_set) if is_option_set is not None else False,
        is_union=bool(is_union) if is_union is not None else False,
        fields=fields,
    )


def parse_namespace_uris(nodeset_path: str) -> list[str]:
    """Parse the NodeSet's `NamespaceUris` table.

    In NodeSet2, `NamespaceUris` typically contains `<Uri>...</Uri>` entries.
    Namespace index `0` always refers to `http://opcfoundation.org/UA/` and is
    not present in this table.
    """

    uris: list[str] = []
    in_namespace_uris = False

    for _ev, elem in ET.iterparse(nodeset_path, events=("start", "end")):
        lname = _local_name(elem.tag)
        if _ev == "start" and lname == "NamespaceUris":
            in_namespace_uris = True
        elif _ev == "end" and lname == "NamespaceUris":
            in_namespace_uris = False
            elem.clear()
        elif in_namespace_uris and _ev == "end" and lname == "Uri":
            text = (elem.text or "").strip()
            if text:
                uris.append(text)
            elem.clear()

    return uris


def parse_aliases(nodeset_path: str) -> dict[str, str]:
    """Parse the NodeSet's ``<Aliases>`` table -> ``{alias_name: normalized_node_id}``.

    Companion specs commonly reference standard types by alias name in field /
    argument ``DataType`` attributes (e.g. ``DataType="String"``) rather than by
    NodeId; the ``<Aliases>`` table maps each alias to its NodeId
    (``<Alias Alias="String">i=12</Alias>``). NS0 NodeSet2.xml uses NodeIds
    directly in those positions, so an empty/unused alias map there leaves output
    byte-identical.
    """
    aliases: dict[str, str] = {}
    in_aliases = False
    for _ev, elem in ET.iterparse(nodeset_path, events=("start", "end")):
        lname = _local_name(elem.tag)
        if _ev == "start" and lname == "Aliases":
            in_aliases = True
        elif _ev == "end" and lname == "Aliases":
            in_aliases = False
            elem.clear()
        elif in_aliases and _ev == "end" and lname == "Alias":
            alias = (elem.attrib.get("Alias") or "").strip()
            target = (elem.text or "").strip()
            if alias and target:
                aliases[alias] = normalize_node_id_text(target)
            elem.clear()
    return aliases


def list_ua_data_types(nodeset_path: str) -> list[tuple[str, str]]:
    """Return `(NodeId, BrowseName)` pairs for all `UADataType` elements.

    Phase 1: this intentionally mirrors the C++ `nodeset_lite::parse_data_types_from_nodeset_file` behavior.
    NodeId normalization and parent resolution are added in later phases.
    """

    results: list[UaDataTypeRef] = []

    # Stream parse to avoid loading entire file into memory.
    # We only need attributes, so clear elements as we go.
    for _event, elem in ET.iterparse(nodeset_path, events=("end",)):
        if _local_name(elem.tag) == "UADataType":
            results.append(
                UaDataTypeRef(
                    node_id=normalize_node_id_text(elem.attrib.get("NodeId", "")),
                    browse_name=elem.attrib.get("BrowseName", ""),
                )
            )
            elem.clear()

    return [(dt.node_id, dt.browse_name) for dt in results]


def parse_ua_data_type_nodes(nodeset_path: str) -> list[UaDataTypeNode]:
    """Parse `UADataType` nodes including parent via inverse `HasSubtype`.

    Mirrors the intent of C++ `parse_data_type_nodes_from_nodeset_file` in `nodeset_lite`.
    """

    results: list[UaDataTypeNode] = []

    for _event, elem in ET.iterparse(nodeset_path, events=("end",)):
        if _local_name(elem.tag) != "UADataType":
            continue

        node_id = normalize_node_id_text(elem.attrib.get("NodeId", ""))
        browse_name = elem.attrib.get("BrowseName", "")
        parent_node_id: str | None = None

        # Determine parent via inverse HasSubtype reference.
        for child in list(elem):
            if _local_name(child.tag) != "References":
                continue
            for ref in list(child):
                if _local_name(ref.tag) != "Reference":
                    continue

                ref_type = ref.attrib.get("ReferenceType")
                if not ref_type or not _is_has_subtype_reference_type(ref_type):
                    continue

                forward = True
                is_forward = ref.attrib.get("IsForward")
                if is_forward is not None:
                    forward = not _is_false(is_forward)
                if forward:
                    continue

                parent_text = (ref.text or "").strip()
                if parent_text:
                    parent_node_id = normalize_node_id_text(parent_text)
                break
            break

        if node_id:
            results.append(
                UaDataTypeNode(node_id=node_id, browse_name=browse_name, parent_node_id=parent_node_id)
            )

        elem.clear()

    return results


_MODELLING_RULE_MANDATORY = "i=78"
_MODELLING_RULE_OPTIONAL = "i=80"
_MODELLING_RULE_OPTIONAL_PLACEHOLDER = "i=11508"
_MODELLING_RULE_MANDATORY_PLACEHOLDER = "i=11510"

_REFERENCE_TYPE_HAS_PROPERTY = {"HasProperty", "i=46", "ns=0;i=46"}
_REFERENCE_TYPE_HAS_COMPONENT = {"HasComponent", "i=47", "ns=0;i=47"}
_REFERENCE_TYPE_HAS_TYPE_DEFINITION = {"HasTypeDefinition", "i=40", "ns=0;i=40"}
_REFERENCE_TYPE_HAS_MODELLING_RULE = {"HasModellingRule", "i=37", "ns=0;i=37"}

_TYPE_DEFINITION_TAGS = {"UAObjectType", "UAVariableType"}
_CHILD_TAGS = {"UAVariable", "UAObject", "UAMethod"}
_CHILD_TAG_TO_NODE_CLASS = {
    "UAVariable": NodeClass.variable,
    "UAObject": NodeClass.object,
    "UAMethod": NodeClass.method,
}


def parse_type_definitions(nodeset_path: str) -> list[UaTypeDefinitionNode]:
    """Parse UAObjectType and UAVariableType elements and their child declarations.

    Two-pass parse:
    1. Collect type definition nodes with their forward references
    2. Resolve child nodes (UAVariable, UAObject, UAMethod) to get BrowseName,
       DataType, TypeDefinition, ModellingRule
    """

    # First pass: parse the full XML tree so we can look up children by NodeId.
    tree = ET.parse(nodeset_path)
    root = tree.getroot()

    # Build a lookup of all elements by NodeId.
    elements_by_id: dict[str, ET.Element] = {}
    for elem in root:
        node_id_attr = elem.attrib.get("NodeId")
        if node_id_attr:
            elements_by_id[normalize_node_id_text(node_id_attr)] = elem

    results: list[UaTypeDefinitionNode] = []

    for elem in root:
        tag = _local_name(elem.tag)
        if tag not in _TYPE_DEFINITION_TAGS:
            continue

        node_id = normalize_node_id_text(elem.attrib.get("NodeId", ""))
        browse_name = elem.attrib.get("BrowseName", "")
        symbolic_name = elem.attrib.get("SymbolicName")
        is_abstract = _parse_bool(elem.attrib.get("IsAbstract", "false")) or False
        type_node_class = "ObjectType" if tag == "UAObjectType" else "VariableType"

        parent_type_id: str | None = None
        child_refs: list[tuple[str, str]] = []  # (target_node_id, reference_type_name)

        # Extract <Category> element
        category: str | None = None
        for child in list(elem):
            if _local_name(child.tag) == "Category":
                category = (child.text or "").strip() or None
                break

        # Walk references
        for child in list(elem):
            if _local_name(child.tag) != "References":
                continue
            for ref in list(child):
                if _local_name(ref.tag) != "Reference":
                    continue

                ref_type = ref.attrib.get("ReferenceType", "")
                is_forward_attr = ref.attrib.get("IsForward")
                forward = True
                if is_forward_attr is not None:
                    forward = not _is_false(is_forward_attr)

                target_text = normalize_node_id_text((ref.text or "").strip())

                # Inverse HasSubtype => parent
                if _is_has_subtype_reference_type(ref_type) and not forward:
                    parent_type_id = target_text
                    continue

                # Forward HasProperty / HasComponent => child reference
                if forward:
                    if ref_type in _REFERENCE_TYPE_HAS_PROPERTY:
                        child_refs.append((target_text, "HasProperty"))
                    elif ref_type in _REFERENCE_TYPE_HAS_COMPONENT:
                        child_refs.append((target_text, "HasComponent"))

        # Second pass: resolve each child
        children: list[UaChildDeclaration] = []
        for target_id, ref_type_name in child_refs:
            child_elem = elements_by_id.get(target_id)
            if child_elem is None:
                continue

            child_tag = _local_name(child_elem.tag)
            if child_tag not in _CHILD_TAGS:
                continue

            child_browse_name = child_elem.attrib.get("BrowseName", "")
            child_symbolic_name = child_elem.attrib.get("SymbolicName")
            child_node_class = _CHILD_TAG_TO_NODE_CLASS[child_tag]

            # DataType and ValueRank (for variables)
            data_type: str | None = None
            value_rank: int | None = None
            if child_tag == "UAVariable":
                dt_attr = child_elem.attrib.get("DataType")
                if dt_attr:
                    data_type = normalize_node_id_text(dt_attr)
                vr_attr = child_elem.attrib.get("ValueRank")
                if vr_attr is not None:
                    value_rank = _parse_int(vr_attr)

            # Resolve HasTypeDefinition and HasModellingRule from child's references
            type_def_id: str | None = None
            modelling_rule = ModellingRule.none
            for cc in list(child_elem):
                if _local_name(cc.tag) != "References":
                    continue
                for ref in list(cc):
                    if _local_name(ref.tag) != "Reference":
                        continue
                    rt = ref.attrib.get("ReferenceType", "")
                    target = normalize_node_id_text((ref.text or "").strip())
                    if rt in _REFERENCE_TYPE_HAS_TYPE_DEFINITION:
                        type_def_id = target
                    elif rt in _REFERENCE_TYPE_HAS_MODELLING_RULE:
                        if target == normalize_node_id_text(_MODELLING_RULE_MANDATORY):
                            modelling_rule = ModellingRule.mandatory
                        elif target == normalize_node_id_text(_MODELLING_RULE_OPTIONAL):
                            modelling_rule = ModellingRule.optional
                        elif target == normalize_node_id_text(_MODELLING_RULE_MANDATORY_PLACEHOLDER):
                            modelling_rule = ModellingRule.mandatory_placeholder
                        elif target == normalize_node_id_text(_MODELLING_RULE_OPTIONAL_PLACEHOLDER):
                            modelling_rule = ModellingRule.optional_placeholder

            # For methods, resolve InputArguments and OutputArguments
            input_args: list[UaMethodArgument] = []
            output_args: list[UaMethodArgument] = []
            if child_tag == "UAMethod":
                # Find HasProperty refs from the method to its argument variables
                for cc in list(child_elem):
                    if _local_name(cc.tag) != "References":
                        continue
                    for ref in list(cc):
                        if _local_name(ref.tag) != "Reference":
                            continue
                        rt = ref.attrib.get("ReferenceType", "")
                        if rt not in _REFERENCE_TYPE_HAS_PROPERTY:
                            continue
                        is_fwd_attr = ref.attrib.get("IsForward")
                        if is_fwd_attr is not None and _is_false(is_fwd_attr):
                            continue
                        arg_target = normalize_node_id_text((ref.text or "").strip())
                        arg_elem = elements_by_id.get(arg_target)
                        if arg_elem is None:
                            continue
                        arg_bn = arg_elem.attrib.get("BrowseName", "")
                        # Look for Value element containing Argument ExtensionObjects
                        for val_child in list(arg_elem):
                            if _local_name(val_child.tag) == "Value":
                                parsed_args = _parse_method_arguments(val_child)
                                if arg_bn == "InputArguments":
                                    input_args = parsed_args
                                elif arg_bn == "OutputArguments":
                                    output_args = parsed_args
                                break

            children.append(
                UaChildDeclaration(
                    node_id=target_id,
                    browse_name=child_browse_name,
                    symbolic_name=child_symbolic_name,
                    node_class=child_node_class,
                    data_type=data_type,
                    value_rank=value_rank,
                    type_definition_id=type_def_id,
                    reference_type=ref_type_name,
                    modelling_rule=modelling_rule,
                    input_arguments=input_args,
                    output_arguments=output_args,
                )
            )

        if node_id:
            results.append(
                UaTypeDefinitionNode(
                    node_id=node_id,
                    browse_name=browse_name,
                    symbolic_name=symbolic_name,
                    is_abstract=is_abstract,
                    parent_type_id=parent_type_id,
                    type_node_class=type_node_class,
                    category=category,
                    children=children,
                    source_nodeset=nodeset_path,
                )
            )

    return results


def parse_ua_data_type_nodes_with_definitions(nodeset_path: str) -> list[UaDataTypeNodeWithDefinition]:
    """Like `parse_ua_data_type_nodes`, but also parses `Definition` and its fields."""

    results: list[UaDataTypeNodeWithDefinition] = []
    aliases = parse_aliases(nodeset_path)

    for _event, elem in ET.iterparse(nodeset_path, events=("end",)):
        if _local_name(elem.tag) != "UADataType":
            continue

        node_id = normalize_node_id_text(elem.attrib.get("NodeId", ""))
        browse_name = elem.attrib.get("BrowseName", "")
        is_abstract = _parse_bool(elem.attrib.get("IsAbstract", "false"))
        if is_abstract is None:
            is_abstract = False
        parent_node_id: str | None = None

        # Extract <Category> element.
        dt_category: str | None = None
        for child in list(elem):
            if _local_name(child.tag) == "Category":
                dt_category = (child.text or "").strip() or None
                break

        # Parent via inverse HasSubtype.
        for child in list(elem):
            if _local_name(child.tag) != "References":
                continue
            for ref in list(child):
                if _local_name(ref.tag) != "Reference":
                    continue

                ref_type = ref.attrib.get("ReferenceType")
                if not ref_type or not _is_has_subtype_reference_type(ref_type):
                    continue

                forward = True
                is_forward = ref.attrib.get("IsForward")
                if is_forward is not None:
                    forward = not _is_false(is_forward)
                if forward:
                    continue

                parent_text = (ref.text or "").strip()
                if parent_text:
                    parent_node_id = normalize_node_id_text(parent_text)
                break
            break

        definition = _parse_definition(elem, aliases)

        if node_id:
            results.append(
                UaDataTypeNodeWithDefinition(
                    node_id=node_id,
                    browse_name=browse_name,
                    parent_node_id=parent_node_id,
                    source_nodeset=nodeset_path,
                    is_abstract=bool(is_abstract),
                    category=dt_category,
                    definition=definition,
                )
            )

        elem.clear()

    return results
