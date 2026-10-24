# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""A member declared with an abstract type is created only with a concrete subtype an
InstantiationOptions::memberTypeResolver names (OPC 10000-3 section 6.2.1, D-26). The generated
instance-handle tests name none, so their all-optionals filter declines such a member.

Standalone (no pytest dependency). Invoke with:

    python -m tooling.type_generator.tests.test_abstract_member_declaration
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from ..codegen.emit_instance_tests import emit_instance_type_tests
from ..nodeset.instance_index import InstanceTypeIndex
from ..nodeset.model import ModellingRule, NodeClass, UaChildDeclaration, UaTypeDefinitionNode
from ..types.build import build_instance_types
from ..types.model import ChildInfo, ChildKind, InstanceType, InstanceTypeKind

_ABSTRACT_PART = UaTypeDefinitionNode(node_id="ns=1;i=2001", browse_name="1:AbstractPartType",
                                      is_abstract=True, parent_type_id="i=58")
_FOLDER = UaTypeDefinitionNode(node_id="i=61", browse_name="FolderType", parent_type_id="i=58")


def _member(browse_name: str, node_id: str, type_definition_id: str) -> UaChildDeclaration:
    return UaChildDeclaration(node_id=node_id, browse_name=browse_name, node_class=NodeClass.object,
                              type_definition_id=type_definition_id, reference_type="i=47",
                              modelling_rule=ModellingRule.optional)


def test_a_member_declared_with_an_abstract_type_is_flagged():
    owner = UaTypeDefinitionNode(node_id="ns=1;i=1001", browse_name="1:MachineType", parent_type_id="i=58",
                                 children=[_member("1:Part", "ns=1;i=1002", _ABSTRACT_PART.node_id),
                                           _member("1:Parts", "ns=1;i=1003", _FOLDER.node_id)])
    index = InstanceTypeIndex(type_nodes={n.node_id: n for n in (_ABSTRACT_PART, _FOLDER, owner)})

    (machine,) = build_instance_types(index, ["MachineType"])

    flags = {c.browse_name: c.declared_type_abstract for c in machine.children}
    assert flags == {"Part": True, "Parts": False}, flags


def _child(browse_name: str, abstract: bool, rule: ModellingRule = ModellingRule.optional) -> ChildInfo:
    return ChildInfo(browse_name=browse_name, kind=ChildKind.child_object, cpp_type="",
                     modelling_rule=rule, reference_type="i=47", child_type_class_name="Folder",
                     declared_type_abstract=abstract)


def _emit(children: list[ChildInfo]) -> str:
    machine = InstanceType(node_id="i=99001", browse_name="MachineType", class_name="Machine",
                           kind=InstanceTypeKind.object_type, children=children)
    with tempfile.TemporaryDirectory() as directory:
        text = emit_instance_type_tests(Path(directory), [machine]).read_text()
    start = text.index("TEST_F(GeneratedInstanceTypeTests, Machine_Children)")
    return text[start:text.index("\n}\n", start)]


def test_the_all_optionals_filter_declines_only_an_optional_member_declared_with_an_abstract_type():
    body = _emit([_child("Part", abstract=True), _child("Parts", abstract=False),
                  _child("Core", abstract=True, rule=ModellingRule.mandatory)])
    assert '[](const ChildFilterInfo& info) { return info.browseName.name() != "Part"; };' in body, body
    assert '"Parts"' not in body.split("try_create_sync")[0]
    assert '"Core"' not in body.split("try_create_sync")[0]


def test_without_such_a_member_the_filter_accepts_every_optional():
    body = _emit([_child("Parts", abstract=False)])
    assert "[](const ChildFilterInfo&) { return true; };" in body, body


def main() -> int:
    test_a_member_declared_with_an_abstract_type_is_flagged()
    test_the_all_optionals_filter_declines_only_an_optional_member_declared_with_an_abstract_type()
    test_without_such_a_member_the_filter_accepts_every_optional()
    print("abstract member declaration: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
