# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit facts of the namespace-0 type model as compiled-in tables (NS0-only).

Read from the same NodeSet XML file the NS0 byte array embeds, so the tables and the namespace 0 the server
loads come from one build input:

- every ReferenceType: its NodeId, its supertype (inverse HasSubtype) and IsAbstract. The SDK identifies
  References as Part 3 4.3.4 does, and decides a ReferenceType hint (``reference_type_may_match_hint``),
  from it without a lookup;
- the VariableTypes of the BaseAnalogType, ArrayItemType, MultiStateDiscreteType and
  MultiStateValueDiscreteType subtrees, each with the rule that applies to it, which the Write service's Data
  Access rules decide by NodeId: a range for the first two subtrees, EnumStrings and EnumValues for the others.

Namespace 0 holds only namespace-0 NodeIds (Part 5 6.3.1), so both tables are complete for the NodeSet
they were generated from.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..io import write_file
from .context import EmitContext

_UA_NS = "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}"
_HAS_SUBTYPE = "i=45"
# The roots of the Data Access subtrees (Part 8 5.3) and the DataAccessKind enumerator of each:
# BaseAnalogType and ArrayItemType are bounded by a range, MultiStateDiscreteType by EnumStrings and
# MultiStateValueDiscreteType by EnumValues.
_DATA_ACCESS_ROOTS = {
    "i=15318": "Analog",
    "i=12021": "Analog",
    "i=2376": "MultiStateDiscrete",
    "i=11238": "MultiStateValueDiscrete",
}

HEADER_NAME = "ua_namespace_zero_tables.h"
SOURCE_NAME = "ua_namespace_zero_tables.cpp"


class Ns0ModelTablesEmitter:
    """Emits ``ua_namespace_zero_tables.cpp`` (NS0-only); its declarations are hand-written in core."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, nodeset_xml_path: Path) -> Path:
        return emit_ns0_model_tables(self._ctx.implementation_dir_for("ns0_model"), nodeset_xml_path)


def _numeric_id(node_id: str, context: str) -> int:
    if not node_id.startswith("i="):
        raise ValueError(f"{context}: expected a namespace-0 numeric NodeId, got {node_id!r}")
    return int(node_id[2:])


def _read_model(nodeset_xml_path: Path) -> tuple[dict[int, tuple[int, bool]], dict[int, int]]:
    """ReferenceTypes as {id: (supertype or 0, isAbstract)}; VariableTypes as {id: supertype or 0}."""
    root = ET.parse(nodeset_xml_path).getroot()
    aliases = {
        alias.get("Alias"): (alias.text or "").strip()
        for alias in root.iter(f"{_UA_NS}Alias")
    }

    def resolve(text: str | None) -> str:
        value = (text or "").strip()
        return aliases.get(value, value)

    def supertype_of(element: ET.Element, context: str) -> int:
        supertypes = [
            resolve(reference.text)
            for reference in element.iter(f"{_UA_NS}Reference")
            if resolve(reference.get("ReferenceType")) == _HAS_SUBTYPE
            and reference.get("IsForward", "true").lower() == "false"
        ]
        if len(supertypes) > 1:
            raise ValueError(f"{context}: more than one supertype: {supertypes}")
        return _numeric_id(supertypes[0], context) if supertypes else 0

    reference_types: dict[int, tuple[int, bool]] = {}
    for element in root.iter(f"{_UA_NS}UAReferenceType"):
        node_id = element.get("NodeId", "")
        identifier = _numeric_id(node_id, "UAReferenceType")
        is_abstract = element.get("IsAbstract", "false").lower() == "true"
        reference_types[identifier] = (supertype_of(element, node_id), is_abstract)

    variable_types: dict[int, int] = {}
    for element in root.iter(f"{_UA_NS}UAVariableType"):
        node_id = element.get("NodeId", "")
        variable_types[_numeric_id(node_id, "UAVariableType")] = supertype_of(element, node_id)

    for identifier, (supertype, _) in reference_types.items():
        if supertype and supertype not in reference_types:
            raise ValueError(f"ReferenceType i={identifier}: supertype i={supertype} is not a ReferenceType")
        # The SDK walks this hierarchy upwards without a bound, so a cycle is refused here.
        seen = {identifier}
        current = supertype
        while current:
            if current in seen:
                raise ValueError(f"ReferenceType i={identifier}: its supertypes form a cycle")
            seen.add(current)
            current = reference_types[current][0]
    return reference_types, variable_types


def _data_access_types(variable_types: dict[int, int]) -> list[tuple[int, str]]:
    roots = {_numeric_id(root, "Data Access root"): kind for root, kind in _DATA_ACCESS_ROOTS.items()}
    missing = roots.keys() - variable_types.keys()
    if missing:
        raise ValueError(f"Data Access roots missing from the NodeSet: {sorted(missing)}")
    members: list[tuple[int, str]] = []
    for identifier in variable_types:
        current = identifier
        seen: set[int] = set()
        while current and current not in seen:
            if current in roots:
                members.append((identifier, roots[current]))
                break
            seen.add(current)
            current = variable_types.get(current, 0)
    return sorted(members)


def emit_ns0_model_tables(implementation_dir: Path, nodeset_xml_path: Path) -> Path:
    reference_types, variable_types = _read_model(nodeset_xml_path)
    data_access = _data_access_types(variable_types)

    lines: list[str] = []
    lines.append(f'#include "{HEADER_NAME}"\n')
    lines.append("\n")
    lines.append("#include <array>\n")
    lines.append("\n")
    lines.append("namespace ua::namespace_zero_tables\n{\n\n")
    lines.append("std::span<const ReferenceTypeRow> reference_types() noexcept\n{\n")
    lines.append(
        f"  static constexpr std::array<ReferenceTypeRow, {len(reference_types)}> rows{{{{\n"
    )
    for identifier in sorted(reference_types):
        supertype, is_abstract = reference_types[identifier]
        lines.append(
            f"    {{{identifier}U, {supertype}U, {'true' if is_abstract else 'false'}}},\n"
        )
    lines.append("  }};\n")
    lines.append("  return rows;\n}\n\n")
    lines.append("std::span<const DataAccessTypeRow> data_access_variable_types() noexcept\n{\n")
    lines.append(f"  static constexpr std::array<DataAccessTypeRow, {len(data_access)}> rows{{{{\n")
    for identifier, kind in data_access:
        lines.append(f"    {{{identifier}U, DataAccessKind::{kind}}},\n")
    lines.append("  }};\n")
    lines.append("  return rows;\n}\n\n")
    lines.append("}  // namespace ua::namespace_zero_tables\n")

    source_path = implementation_dir / SOURCE_NAME
    write_file(source_path, "".join(lines))
    return source_path
