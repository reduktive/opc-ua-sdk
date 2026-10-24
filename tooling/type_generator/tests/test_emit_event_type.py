# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for generated EventType property cardinality.

Standalone (no pytest dependency). Invoke via:

    python -m tooling.type_generator.tests.test_emit_event_type
"""

from __future__ import annotations

import sys

from ..codegen.emit_event_type import (
    _field_cpp_type,
    _field_declaration,
    _field_includes,
    _field_test_value,
    _value_check_lines,
)
from ..nodeset.instance_index import InstanceTypeIndex
from ..nodeset.model import (
    ModellingRule,
    NodeClass,
    UaChildDeclaration,
    UaTypeDefinitionNode,
)
from ..types.build import build_event_types
from ..types.model import EventFieldInfo, EventType


def _array_event_field() -> EventFieldInfo:
    return EventFieldInfo(
        browse_name="EventIds",
        cpp_name="EventIds",
        cpp_type="ByteString",
        variant_expression="event_ids",
        is_array=True,
    )


def _array_event_type() -> EventType:
    return EventType(
        node_id="i=9999",
        browse_name="TestEventType",
        class_name="TestEventPayload",
        parent_class_name="BaseEvent",
        parent_header="ua_base_event.h",
        own_fields=[_array_event_field()],
    )


def test_build_event_types_preserves_property_value_rank():
    base = UaTypeDefinitionNode(node_id="i=2041", browse_name="BaseEventType")
    event = UaTypeDefinitionNode(
        node_id="i=9999",
        browse_name="TestEventType",
        parent_type_id="i=2041",
        children=[
            UaChildDeclaration(
                node_id="i=10000",
                browse_name="EventIds",
                node_class=NodeClass.variable,
                data_type="i=15",
                value_rank=1,
                reference_type="HasProperty",
                modelling_rule=ModellingRule.mandatory,
            )
        ],
    )

    event_types = build_event_types(
        InstanceTypeIndex(type_nodes={base.node_id: base, event.node_id: event})
    )

    assert len(event_types) == 1
    assert event_types[0].own_fields[0].is_array is True


def test_array_property_emission_uses_array_type_and_include():
    field = _array_event_field()

    assert _field_cpp_type(field) == "Array<ByteString>"
    assert _field_declaration(field) == "  Array<ByteString> eventIds{};"
    assert '#include "ua_array.h"' in _field_includes(_array_event_type())


def test_array_property_generated_test_round_trips_array_variant():
    field = _array_event_field()

    assert _field_test_value(field) == (
        "Array<ByteString>{ByteString{std::vector<std::byte>{std::byte{1}}}}"
    )
    assert _value_check_lines("result", field, "sentinel") == [
        "  EXPECT_EQ(result.as<Array<ByteString>>(), sentinel);"
    ]


def _run() -> int:
    failed = 0
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    for name, fn in tests:
        try:
            fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    if failed:
        print(f"\n{failed} test(s) failed", file=sys.stderr)
    else:
        print(f"\n{len(tests)} test(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
