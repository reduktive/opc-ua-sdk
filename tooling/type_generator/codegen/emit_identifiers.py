# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit per-NodeClass identifier headers (``ua_objecttype_id.h`` etc.).

``IdentifierEmitter`` is bound to one ``EmitContext`` and emits one
``<prefix><class>_id.h`` per NodeClass present in the spec's
``NodeIds.csv``.  Enums live in ``ctx.cpp_namespace`` so DI etc. can
land their own ``ua::di::ObjectId`` without colliding with NS0's
``ua::ObjectId``.
"""

from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from ..io import write_file
from ..naming import cpp_identifier, get_symbolic_name
from ..nodeset.index import browse_name_suffix
from ..nodeset.nodeid import parse_numeric_node_id
from .context import EmitContext


# Per-NodeClass: ``(enum_name, filename_stem, guard_infix)``.
#
# ``filename_stem`` builds ``<prefix><stem>.h`` (NS0: ``ua_objecttype_id.h``).
# ``guard_infix`` builds ``<PREFIX>_<INFIX>_IDENTIFIERS_H``
# (NS0: ``UA_OBJECTTYPE_IDENTIFIERS_H``).  They differ because the C++
# filename is by historical convention shorter than the screaming form.
_NODE_CLASS_MAP: dict[str, tuple[str, str, str]] = {
    "DataType":      ("DataTypeId",      "datatype_id",      "DATATYPE"),
    "Method":        ("MethodId",        "method_id",        "METHOD"),
    "Object":        ("ObjectId",        "object_id",        "OBJECT"),
    "ObjectType":    ("ObjectTypeId",    "objecttype_id",    "OBJECTTYPE"),
    "ReferenceType": ("ReferenceTypeId", "referencetype_id", "REFERENCETYPE"),
    "Variable":      ("VariableId",      "variable_id",      "VARIABLE"),
    "VariableType":  ("VariableTypeId",  "variabletype_id",  "VARIABLETYPE"),
}


class IdentifierEmitter:
    """Emits one ``<prefix><class>_id.h`` per NodeClass in NodeIds.csv."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, nodeids_csv: Path | None, instance_index=None) -> list[Path]:
        return _emit_identifier_headers(self._ctx, nodeids_csv, instance_index)


_ENCODING_SUFFIX_RE = re.compile(
    r"_Encoding_(DefaultBinary|DefaultXml|DefaultJson)$", re.IGNORECASE)
_ENCODING_CANONICAL = {
    "defaultbinary": "DefaultBinary",
    "defaultxml": "DefaultXml",
    "defaultjson": "DefaultJson",
}


def _canonicalise_encoding_suffix(name: str) -> str:
    """Normalise a ``<Type>_Encoding_<token>`` member's encoding token to the
    canonical casing the struct/union emitters reference (``DefaultXml`` etc.).
    Some NodeSets spell it ``DefaultXML`` (e.g. WireHarness), which would not
    match the ``ObjectId::<Type>_Encoding_DefaultXml`` reference. No-op for any
    non-encoding name and for NS0 (already canonical)."""
    match = _ENCODING_SUFFIX_RE.search(name)
    if not match:
        return name
    canonical = _ENCODING_CANONICAL[match.group(1).lower()]
    return name[: match.start()] + "_Encoding_" + canonical


def _recanonicalise_encoding_prefix(name: str, symbolic_to_canonical: dict[str, str]) -> str:
    """For an Object encoding member ``<prefix>_Encoding_<token>``, map ``<prefix>``
    (a DataType SymbolicName) to its canonical type name. No-op for non-encoding
    names and when the prefix is already canonical (NS0)."""
    idx = name.rfind("_Encoding_")
    if idx == -1:
        return name
    prefix = name[:idx]
    canonical = symbolic_to_canonical.get(prefix)
    return name if canonical is None else canonical + name[idx:]


def _dedupe_members(items: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Suffix duplicate enum-member names with their numeric id so the enum is
    well-formed. Two distinct nodes can share a CSV SymbolicName - e.g. per-type
    encoding nodes all named ``DefaultBinary``. NS0 has no duplicate (class, name)
    pairs, so this renames nothing for NS0 (byte-identical)."""
    counts = Counter(name for name, _ in items)
    if all(count == 1 for count in counts.values()):
        return items
    used: set[str] = set()
    out: list[tuple[str, int]] = []
    for name, val in items:
        if counts[name] > 1:
            candidate = f"{name}_{val}"
            while candidate in used:
                candidate = f"{candidate}_x"
            name = candidate
        used.add(name)
        out.append((name, val))
    return out


def _emit_identifier_headers(ctx: EmitContext, nodeids_csv: Path | None,
                             instance_index=None) -> list[Path]:
    entries: dict[str, list[tuple[str, int]]] = defaultdict(list)

    # The CSV's DataType SymbolicName is unreliable: some companion specs strip
    # the "DataType" suffix in the CSV (e.g. PADIM `ChemicalSubstance`) while the
    # NodeSet browse name keeps it (`ChemicalSubstanceDataType`). The structure
    # emitter references `DataTypeId::<browse-derived name>`, so deriving the
    # DataType enum member from the spec's own NodeSet nodes keeps the member and
    # the reference in lock-step. NS0 is unaffected: its CSV SymbolicName already
    # equals get_symbolic_name(browse_name) for every DataType.
    datatype_member_by_id: dict[int, str] = {}
    for node in ctx.index.data_types.values():
        owner = ctx.index.config_for_node(node)
        if owner is None or owner.uri != ctx.config.uri:
            continue
        numeric = parse_numeric_node_id(node.node_id)
        if numeric is not None:
            datatype_member_by_id[numeric.identifier] = get_symbolic_name(node.browse_name)

    # Maps a DataType's CSV SymbolicName -> its canonical type name, so an Object
    # encoding member (`<SymbolicName>_Encoding_<token>`) can be re-prefixed to the
    # name the struct references (`<canonical>_Encoding_<token>`). NS0's SymbolicName
    # already equals the canonical name, so this is a no-op for NS0.
    dt_symbolic_to_canonical: dict[str, str] = {}
    if nodeids_csv is not None:
        with open(nodeids_csv, encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                symbolic_name = row[0].strip()
                try:
                    numeric_id = int(row[1].strip())
                except ValueError:
                    continue
                node_class = row[2].strip()
                if node_class == "DataType":
                    canonical = datatype_member_by_id.get(numeric_id, symbolic_name)
                    dt_symbolic_to_canonical[symbolic_name] = canonical
                    symbolic_name = canonical
                symbolic_name = _canonicalise_encoding_suffix(symbolic_name)
                if node_class in _NODE_CLASS_MAP:
                    entries[node_class].append((symbolic_name, numeric_id))

    # Re-prefix Object encoding members from the DataType SymbolicName to the
    # canonical type name so they match the struct's ObjectId::<canonical>_Encoding_*
    # reference (e.g. GPOS S3DGeographicCoordinateDataType -> ThreeD...).
    if entries["Object"] and dt_symbolic_to_canonical:
        entries["Object"] = [
            (_recanonicalise_encoding_prefix(name, dt_symbolic_to_canonical), nid)
            for name, nid in entries["Object"]
        ]

    # NodeSet-derived fallback (append-only, deduped by numeric id, CSV-first): the
    # type/struct emitters #include id headers unconditionally, but the CSV may be
    # absent, omit a whole NodeClass, or be ;-delimited. Fill DataType from the owned
    # data_types index and ObjectType/VariableType from the instance index so the
    # header always exists with the members the emitters reference. NS0 ships a
    # complete CSV -> every id is already present -> nothing is appended (byte-identical).
    seen = {nc: {nid for _, nid in entries[nc]} for nc in _NODE_CLASS_MAP}
    for numeric_id, member in sorted(datatype_member_by_id.items()):
        if numeric_id not in seen["DataType"]:
            entries["DataType"].append((member, numeric_id))
            seen["DataType"].add(numeric_id)
    if instance_index is not None:
        derived: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for node in instance_index.type_nodes.values():
            node_class = node.type_node_class
            if node_class not in _NODE_CLASS_MAP:
                continue
            owner = (ctx.index.config_for_source(node.source_nodeset)
                     if node.source_nodeset else None)
            if owner is None or owner.uri != ctx.config.uri:
                continue  # only the spec's own type nodes; never leak NS0/dep ids
            numeric = parse_numeric_node_id(node.node_id)
            if numeric is None or numeric.identifier in seen[node_class]:
                continue
            derived[node_class].append((browse_name_suffix(node.browse_name), numeric.identifier))
            seen[node_class].add(numeric.identifier)
        for node_class, items in derived.items():
            entries[node_class].extend(sorted(items, key=lambda pair: pair[1]))

    output_dir = ctx.interface_dir_for("ids")
    generated: list[Path] = []

    for node_class, (enum_name, stem, guard_infix) in _NODE_CLASS_MAP.items():
        items = _dedupe_members(entries.get(node_class, []))
        # A companion struct/union header includes <prefix>object_id.h unconditionally
        # (encoding ids bind to the spec's own ObjectId enum). Emit it even when empty
        # so a non-encodable / CSV-less spec's include resolves rather than dangles.
        # NS0 (cpp_namespace=="ua") reaches ua::ObjectId via ua_node_id.h and always
        # ships Object rows, so it is unaffected.
        always_emit = node_class == "Object" and ctx.cpp_namespace != "ua"
        if not items and not always_emit:
            continue

        filename = f"{ctx.include_prefix}{stem}.h"
        guard = f"{ctx.guard_prefix}_{guard_infix}_IDENTIFIERS_H"

        lines: list[str] = []

        def ln(s: str = "") -> None:
            lines.append(s + "\n")

        ln(f"#ifndef {guard}")
        ln(f"#define {guard}")
        ln()
        ln('#include "ua_includes.h"')
        ln()
        ln(ctx.cpp_namespace_open())
        ln()
        doc = ctx.doc_comment(
            f"Well-known OPC UA {enum_name} identifiers (namespace 0).", "ua_node_ids"
        )
        if doc:
            ln(doc)
        # GCC's -Wshadow warns when a scoped-enum enumerator matches a global type alias
        # (e.g. the DataTypeId::IntegerId / DataTypeId::Duration enumerators vs the ua::IntegerId
        # / ua::Duration `using` aliases). Scoped-enum enumerators do NOT leak into the enclosing
        # scope, so there is no real shadowing hazard, and the enumerator names are OPC UA
        # spec-mandated (they are the canonical type names) so they cannot be renamed. Clang does
        # not warn. Suppress the GCC false positive narrowly around the enum only, so -Wshadow can
        # gate the hand-written tree at full strength. Guarded to __GNUC__ so MSVC is unaffected.
        ln("#if defined(__GNUC__)")
        ln('#  pragma GCC diagnostic push')
        ln('#  pragma GCC diagnostic ignored "-Wshadow"')
        ln("#endif")
        ln(f"enum class {enum_name} : uint32_t")
        ln("{")
        for i, (name, val) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""
            # Final sanitisation: a BrowseName may contain hyphens/spaces (e.g. DEXPI
            # "ISO10209-2012"); cpp_identifier is a no-op on already-legal names (so
            # NS0 + the 117 green specs are unchanged) and fixes the rest. The struct/
            # traits references are sanitised identically (build.py + FIX-1a sites).
            ln(f"  {cpp_identifier(name)} = {val}U{comma}")
        ln("};")
        ln("#if defined(__GNUC__)")
        ln('#  pragma GCC diagnostic pop')
        ln("#endif")
        ln()
        ln(ctx.cpp_namespace_close())
        ln()
        ln(f"#endif  // {guard}")

        out_path = output_dir / filename
        write_file(out_path, "".join(lines))
        generated.append(out_path)

    return generated
