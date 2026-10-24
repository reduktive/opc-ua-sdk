# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for codegen.emit_identifiers - DataType enum-member derivation.

A companion spec's NodeIds CSV may strip the "DataType" suffix from a DataType's
SymbolicName while the NodeSet browse name keeps it; the struct emitter references
the browse-derived name, so the identifier emitter must emit the same. These tests
pin that the DataType enum member is derived from the NodeSet node (by numeric id),
while other node classes keep the CSV SymbolicName.

Standalone - no pytest dependency.  Invoke via:

    python -m tooling.type_generator.tests.test_emit_identifiers
"""

from __future__ import annotations

import inspect
import sys
import tempfile
from pathlib import Path

from ..codegen.context import EmitContext
from ..codegen.emit_identifiers import (
    IdentifierEmitter,
    _canonicalise_encoding_suffix,
    _dedupe_members,
    _recanonicalise_encoding_prefix,
)
from ..manifest import NodesetConfig
from ..nodeset.index import NodeSetIndex
from ..nodeset.model import UaDataTypeDefinition, UaDataTypeNodeWithDefinition


DI_URI = "http://opcfoundation.org/UA/DI/"


def _di_cfg() -> NodesetConfig:
    return NodesetConfig(
        uri=DI_URI, sources=["di.xml"], include_prefix="ua_di_",
        cpp_namespace="ua::di", target="ua_di_types", emit=True,
    )


def _dt_node(node_id: str, browse_name: str, source: str) -> UaDataTypeNodeWithDefinition:
    return UaDataTypeNodeWithDefinition(
        node_id=node_id, browse_name=browse_name, parent_node_id="i=22",
        source_nodeset=source, is_abstract=False,
        definition=UaDataTypeDefinition(name=browse_name, fields=[]),
    )


def _ctx_with_dt(tmp_path: Path, browse_name: str, node_id: str = "ns=1;i=1275") -> EmitContext:
    node = _dt_node(node_id, browse_name, "/abs/di.xml")
    index = NodeSetIndex(
        data_types={node_id: node},
        namespace_uris_by_nodeset={"/abs/di.xml": [DI_URI]},
    ).with_config_by_source({"/abs/di.xml": _di_cfg()})
    return EmitContext.build(_di_cfg(), index, tmp_path)


def _write_csv(tmp_path: Path, rows: list[str]) -> Path:
    csv = tmp_path / "di.NodeIds.csv"
    csv.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return csv


def _datatype_id_header(tmp_path: Path) -> str:
    return (tmp_path / "ids" / "ua_di_datatype_id.h").read_text(encoding="utf-8")


def test_datatype_member_uses_browse_name_not_stripped_csv(tmp_path: Path):
    # CSV strips the suffix; NodeSet browse keeps it -> emit the browse-derived name.
    ctx = _ctx_with_dt(tmp_path, "3:ChemicalSubstanceDataType")
    csv = _write_csv(tmp_path, ["ChemicalSubstance,1275,DataType"])
    IdentifierEmitter(ctx).emit(csv)
    header = _datatype_id_header(tmp_path)
    assert "ChemicalSubstanceDataType = 1275U" in header
    assert "ChemicalSubstance = 1275U" not in header


def test_datatype_member_unchanged_when_csv_matches_browse(tmp_path: Path):
    # CSV symbolic already equals the browse-derived name (the NS0 case) -> no change.
    ctx = _ctx_with_dt(tmp_path, "1:DeviceHealthEnumeration")
    csv = _write_csv(tmp_path, ["DeviceHealthEnumeration,1275,DataType"])
    IdentifierEmitter(ctx).emit(csv)
    assert "DeviceHealthEnumeration = 1275U" in _datatype_id_header(tmp_path)


def test_datatype_member_falls_back_to_csv_when_node_absent(tmp_path: Path):
    # A CSV DataType id not present in the index keeps the CSV SymbolicName.
    ctx = _ctx_with_dt(tmp_path, "3:ChemicalSubstanceDataType", node_id="ns=1;i=1275")
    csv = _write_csv(tmp_path, ["OrphanType,9999,DataType"])
    IdentifierEmitter(ctx).emit(csv)
    assert "OrphanType = 9999U" in _datatype_id_header(tmp_path)


def test_non_datatype_rows_keep_csv_symbolic(tmp_path: Path):
    # ObjectType members come from the CSV verbatim (not the data_types index).
    ctx = _ctx_with_dt(tmp_path, "3:ChemicalSubstanceDataType")
    csv = _write_csv(tmp_path, ["ClassSet,6077,ObjectType"])
    IdentifierEmitter(ctx).emit(csv)
    objtype = (tmp_path / "ids" / "ua_di_objecttype_id.h").read_text(encoding="utf-8")
    assert "ClassSet = 6077U" in objtype


def test_datatype_header_emitted_without_csv(tmp_path: Path):
    # CSV-less spec: the DataType id header is still produced from the index nodes.
    ctx = _ctx_with_dt(tmp_path, "1:WidgetDataType", node_id="ns=1;i=42")
    IdentifierEmitter(ctx).emit(None)  # no CSV
    header = _datatype_id_header(tmp_path)
    assert "WidgetDataType = 42U" in header


def test_dedupe_members_suffixes_duplicates():
    # Two distinct nodes sharing a SymbolicName (e.g. encoding nodes) get unique members.
    out = _dedupe_members([("DefaultBinary", 5042), ("DefaultBinary", 5045), ("Foo", 1)])
    names = [n for n, _ in out]
    assert names == ["DefaultBinary_5042", "DefaultBinary_5045", "Foo"]
    assert len(set(names)) == 3


def test_dedupe_members_noop_when_unique():
    items = [("A", 1), ("B", 2)]
    assert _dedupe_members(items) is items  # unchanged, same object (no rename)


def test_object_id_header_always_emitted_for_companion(tmp_path: Path):
    # A companion struct includes <prefix>object_id.h unconditionally, so it must
    # exist even with no Object rows (e.g. a non-encodable / CSV-less spec).
    ctx = _ctx_with_dt(tmp_path, "1:WidgetDataType", node_id="ns=1;i=42")
    IdentifierEmitter(ctx).emit(None)  # no CSV, no Object entries
    obj = tmp_path / "ids" / "ua_di_object_id.h"
    assert obj.exists()
    assert "enum class ObjectId" in obj.read_text()


def test_canonicalise_encoding_suffix():
    # WireHarness-style uppercase XML -> canonical; canonical + non-encoding unchanged.
    assert _canonicalise_encoding_suffix("Crimp_Encoding_DefaultXML") == "Crimp_Encoding_DefaultXml"
    assert _canonicalise_encoding_suffix("Crimp_Encoding_DefaultXml") == "Crimp_Encoding_DefaultXml"
    assert _canonicalise_encoding_suffix("SomeObjectId") == "SomeObjectId"


def test_recanonicalise_encoding_prefix():
    # GPOS-style SymbolicName prefix -> canonical type name.
    m = {"S3DGeographicCoordinateDataType": "ThreeDGeographicCoordinateDataType"}
    assert (_recanonicalise_encoding_prefix("S3DGeographicCoordinateDataType_Encoding_DefaultBinary", m)
            == "ThreeDGeographicCoordinateDataType_Encoding_DefaultBinary")
    # Unknown prefix or non-encoding name unchanged.
    assert _recanonicalise_encoding_prefix("Foo_Encoding_DefaultBinary", m) == "Foo_Encoding_DefaultBinary"
    assert _recanonicalise_encoding_prefix("PlainObject", m) == "PlainObject"


def _run() -> int:
    failed = 0
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            if "tmp_path" in inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as td:
                    fn(tmp_path=Path(td))
            else:
                fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:  # noqa: BLE001
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    print(f"\n{len(tests)-failed}/{len(tests)} passed" if not failed else f"\n{failed} failed", file=sys.stderr if failed else sys.stdout)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
