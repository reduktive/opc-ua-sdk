# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Regression tests for generated child-handle type resolution.

Standalone (no pytest dependency). Invoke with:

    python -m tooling.type_generator.tests.test_instance_child_type_resolution
"""

from __future__ import annotations

import sys

from ..nodeset.instance_index import InstanceTypeIndex
from ..nodeset.model import (
    ModellingRule,
    NodeClass,
    UaChildDeclaration,
    UaTypeDefinitionNode,
)
from ..types.build import build_instance_types
from ..types.model import ChildKind


def test_base_data_variable_child_gets_typed_accessor():
    base_data_variable = UaTypeDefinitionNode(
        node_id="i=63",
        browse_name="BaseDataVariableType",
        parent_type_id="i=62",
        type_node_class="VariableType",
    )
    demo_type = UaTypeDefinitionNode(
        node_id="ns=1;i=1001",
        browse_name="1:DemoType",
        parent_type_id="i=58",
        children=[
            UaChildDeclaration(
                node_id="ns=1;i=1002",
                browse_name="1:Setpoint",
                node_class=NodeClass.variable,
                data_type="i=11",
                type_definition_id="i=63",
                reference_type="i=47",
                modelling_rule=ModellingRule.mandatory,
            )
        ],
    )
    index = InstanceTypeIndex(
        type_nodes={
            base_data_variable.node_id: base_data_variable,
            demo_type.node_id: demo_type,
        }
    )

    generated_types = build_instance_types(index, ["DemoType"])

    assert len(generated_types) == 1
    assert len(generated_types[0].children) == 1
    child = generated_types[0].children[0]
    assert child.kind == ChildKind.data_variable
    assert child.child_type_class_name == "BaseDataVariable"
    assert child.child_type_include_prefix == "ua_"


def _run() -> int:
    try:
        test_base_data_variable_child_gets_typed_accessor()
    except Exception as ex:  # noqa: BLE001
        print(f"FAIL: {type(ex).__name__}: {ex}", file=sys.stderr)
        return 1
    print("1 test passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
