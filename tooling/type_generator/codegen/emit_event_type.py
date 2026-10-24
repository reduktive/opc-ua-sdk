# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Generate C++ event struct headers, combined source, hierarchy, and tests."""
from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import to_camel_back, to_snake_case, to_screaming_snake_case
from ..types.model import CompoundFieldKind, EventFieldInfo, EventType


def _snake(name: str) -> str:
    return to_snake_case(name)


def _field(name: str) -> str:
    """The C++ name of a payload field: camelBack, as every public field (cpp_style.md section Naming)."""
    return to_camel_back(name)


def _screaming(name: str) -> str:
    return to_screaming_snake_case(name)


_TEST_VALUES: dict[str, str] = {
    "bool": "true",
    "uint8_t": "42",
    "int8_t": "42",
    "uint16_t": "100",
    "int16_t": "100",
    "uint32_t": "12345",
    "int32_t": "12345",
    "uint64_t": "123456",
    "int64_t": "123456",
    "double": "3.14",
    "float": "1.5f",
    "String": 'String{"test"}',
    "DateTime": "DateTime::now()",
    "ByteString": 'ByteString{std::vector<std::byte>{std::byte{1}}}',
    "Guid": "Guid{}",
    "NodeId": "NodeId{1, 42}",
    "StatusCode": "StatusCode{}",
    "QualifiedName": 'QualifiedName{0, "test"}',
    "LocalizedText": 'LocalizedText{"en", "test"}',
    "Variant": "Variant{42}",
    "TwoStateVariableState": 'TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()}',
    "ConditionVariableState": "ConditionVariableState{Variant{42}, DateTime::now()}",
    "FiniteStateVariableState": 'FiniteStateVariableState{LocalizedText{"", "High"}, NodeId{0, 9331u}}',
    "ShelvedStateVariableState": 'ShelvedStateVariableState{LocalizedText{"", "OneShotShelved"}, NodeId{0, 2930u}, 1000.0}',
}

# Compound kinds that model a state-machine component: resolvable at [<machine>], [<machine>, CurrentState]
# and [<machine>, CurrentState, Id].
_STATE_MACHINE_KINDS = (CompoundFieldKind.finite_state, CompoundFieldKind.shelved_state)


def _test_assignment(cpp_type: str, field_expr: str) -> str:
    """Generate a C++ assignment statement that sets a field to a non-default value."""
    val = _TEST_VALUES.get(cpp_type, f"Variant{{42}}")
    return f"{field_expr} = {val};"


def _field_cpp_type(field: EventFieldInfo) -> str:
    """Return the declared C++ type, retaining dynamic Variant fallbacks."""
    if field.is_array and field.cpp_type != "Variant":
        return f"Array<{field.cpp_type}>"
    return field.cpp_type


def _field_test_value(field: EventFieldInfo) -> str:
    """Return a non-default value matching an emitted event field's shape."""
    value = _TEST_VALUES.get(field.cpp_type, "Variant{42}")
    if field.is_array and field.cpp_type != "Variant":
        return f"Array<{field.cpp_type}>{{{value}}}"
    return value


def _value_check_lines(
    var: str,
    field: EventFieldInfo,
    sentinel_var: str,
    *,
    compound_kind: CompoundFieldKind = CompoundFieldKind.none,
) -> list[str]:
    """Produce the assertion lines that follow a successful ``resolve_field``.

    ``var`` is the C++ identifier of the ``Variant`` result. ``sentinel_var``
    is the local that holds the value used to populate the field. The exact
    ``.as<T>()`` extraction depends on the field shape:

    * Non-compound, non-Variant: ``EXPECT_EQ(var.as<cpp_type>(), sentinel)``.
    * Variant field: only assert non-empty - the inner Variant content cannot
      be reliably compared to a sentinel of unknown encoding.
    * TwoStateVariableState: root resolve returns ``Variant{<field>.currentState}``
      - a LocalizedText (the Value of a TwoStateVariableType). Assert against
      ``sentinel.currentState``.
    * ConditionVariableState: root resolve returns ``<field>.value`` which
      is itself a Variant - only assert non-empty.
    """
    cpp_type = _field_cpp_type(field)
    compound_kind = field.compound_kind
    if compound_kind == CompoundFieldKind.two_state:
        return [f"  EXPECT_EQ({var}.as<LocalizedText>(), {sentinel_var}.currentState);"]
    if compound_kind in _STATE_MACHINE_KINDS:
        # Root resolve returns the CurrentState Value (a LocalizedText).
        return [f"  EXPECT_EQ({var}.as<LocalizedText>(), {sentinel_var}.currentState);"]
    if compound_kind == CompoundFieldKind.condition_var:
        return []  # value pass-through; no extra check
    if cpp_type == "Variant":
        return []
    return [f"  EXPECT_EQ({var}.as<{cpp_type}>(), {sentinel_var});"]


def _compound_sub_paths(field: EventFieldInfo) -> list[tuple[str, str, str]]:
    """Return ``(browse_segment, member, as_type)`` for each 2-deep sub-path
    of a compound field. Empty list for non-compound fields."""
    if field.compound_kind == CompoundFieldKind.two_state:
        return [
            ("Id", "id", "bool"),
            ("TransitionTime", "transitionTime", "DateTime"),
            ("CurrentState", "currentState", "LocalizedText"),
        ]
    if field.compound_kind == CompoundFieldKind.condition_var:
        return [
            ("SourceTimestamp", "sourceTimestamp", "DateTime"),
        ]
    if field.compound_kind in _STATE_MACHINE_KINDS:
        # 2-deep: [<machine>, CurrentState] -> the FiniteStateVariable Value (LocalizedText).
        # The 3-deep [<machine>, CurrentState, Id] path is covered by a dedicated SDK unit test.
        paths = [("CurrentState", "currentState", "LocalizedText")]
        if field.compound_kind == CompoundFieldKind.shelved_state:
            paths.append(("UnshelveTime", "unshelveTime", "double"))
        return paths
    return []


def _field_declaration(field) -> str:
    """Return C++ field declaration for an EventFieldInfo."""
    cpp_type = _field_cpp_type(field)
    if field.is_optional:
        return f"  std::optional<{cpp_type}> {_field(field.cpp_name)};"
    return f"  {cpp_type} {_field(field.cpp_name)}{{}};"


def _field_includes(event_type: EventType) -> list[str]:
    """Collect extra #include directives needed for field types."""
    seen: set[str] = set()
    includes: list[str] = []
    for field in event_type.own_fields:
        if field.include_header and field.include_header not in seen:
            seen.add(field.include_header)
            includes.append(f'#include "{field.include_header}"')
    if any(f.is_array and f.cpp_type != "Variant" for f in event_type.own_fields):
        includes.append('#include "ua_array.h"')
    if any(f.is_optional for f in event_type.own_fields):
        includes.append("#include <optional>")
    return includes


# --- Headers (always individual) ---


class EventTypeEmitter:
    """Emits event-type headers + the combined source.

    EventType subtype matching (EventFilter OfType) is resolved at runtime
    against the address-space ``HasSubtype`` hierarchy by the EventBus /
    subscription layer, so the generated payloads carry no subtype-matching code
    and there is no baked hierarchy table to emit."""

    def __init__(self, ctx):
        self._ctx = ctx

    def emit_header(self, event_type: EventType) -> Path:
        return _emit_event_type_header(self._ctx, event_type)

    def emit_sources(
        self,
        event_types: list[EventType],
        headers_in_order: list[str],
    ) -> tuple[list[Path], list[str]]:
        """Emit event-type sources; return ``(paths, source_names)``.

        ``ctx.amalgamate_sources`` (NS0) -> one combined ``<prefix>event_types.cpp``;
        otherwise one ``<prefix><snake>.cpp`` per event type (consumer layout).
        """
        if self._ctx.amalgamate_sources:
            path = _emit_event_types_combined_source(
                self._ctx, event_types, headers_in_order
            )
            return [path], [path.name]
        return _emit_event_type_source_files(
            self._ctx, event_types, headers_in_order
        )


def _emit_event_type_header(ctx, event_type: EventType) -> Path:
    """Emit a generated event struct header file."""
    header_guard = ctx.simple_header_guard(event_type.class_name)

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln(f"#ifndef {header_guard}")
    ln(f"#define {header_guard}")
    ln()
    ln("// *** THIS FILE IS GENERATED - DO NOT EDIT ***")
    ln()
    ln(f'#include "{event_type.parent_header}"')
    # Companion specs emit into a nested namespace, so the core ``ua::`` names the
    # struct references (BaseEvent, Variant, QualifiedName, ExpandedNodeId, ...) must
    # be pulled in via the spec's aliases header. NS0 already has them in scope.
    if ctx.cpp_namespace != "ua":
        ln(f'#include "{ctx.include_prefix}aliases.h"')
    for inc in _field_includes(event_type):
        ln(inc)
    ln()
    ln(ctx.cpp_namespace_open())
    ln()
    doc = ctx.doc_comment(
        f"Event payload for the OPC UA {event_type.browse_name}.", "ua_information_model"
    )
    if doc:
        ln(doc)
    ln(f"struct {event_type.class_name} : public {event_type.parent_class_name}")
    ln("{")
    for field in event_type.own_fields:
        ln(f"  /// The `{field.browse_name}` event field.")
        ln(_field_declaration(field))
    if event_type.own_fields:
        ln()
    ln(f"  /// Constructs the payload with the event type's default field values.")
    ln(f"  {event_type.class_name}();")
    ln(f"  /// Polymorphically deep-copies this event payload.")
    ln(f"  /// @return A heap-allocated copy held by its `BaseEvent` base.")
    ln(f"  std::unique_ptr<BaseEvent> clone() const override;")
    ln(f"  /// Resolves a field value by its browse path; used to evaluate event filters.")
    ln(f"  /// @param browse_path The field's browse path relative to the event.")
    ln(f"  /// @return The field value, or an empty `Variant` if the path does not match a field.")
    ln(f"  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;")
    # Companion payloads carry their spec URI so the server resolves event_type's
    # namespace index at emit time (see Server::emit_event).
    if ctx.cpp_namespace != "ua":
        ln(f"  /// @return The payload's event-type `ExpandedNodeId`, carrying the spec namespace URI.")
        ln(f"  ExpandedNodeId event_type_expanded() const override;")
    ln("};")
    ln()
    ln(ctx.cpp_namespace_close())
    ln(f"#endif  // !{header_guard}")

    out_path = ctx.interface_dir_for("event_types") / ctx.header_file_name(event_type.class_name)
    write_file(out_path, "".join(lines))
    return out_path


# --- Combined source (NS0) ---


def _resolve_compound_field(field, field_name: str) -> list[str]:
    """Generate resolve_field lines for a compound variable-type field."""
    lines: list[str] = []
    opt = field.is_optional
    prefix = f"{field_name}.value()." if opt else f"{field_name}."

    if field.compound_kind == CompoundFieldKind.two_state:
        # Single-segment: return the CurrentState LocalizedText. The Value of a TwoStateVariableType
        # is the human-readable current-state name (Part 5 StateVariableType); the boolean state is the
        # .Id sub-property, reachable via the two-segment <name>/Id path.
        if opt:
            lines.append(f'    if (name == "{field.browse_name}" && {field_name}.has_value())')
        else:
            lines.append(f'    if (name == "{field.browse_name}")')
        lines.append(f"      return Variant{{{prefix}currentState}};")

    elif field.compound_kind == CompoundFieldKind.condition_var:
        # Single-segment: return the Value (the Value of a ConditionVariable)
        if opt:
            lines.append(f'    if (name == "{field.browse_name}" && {field_name}.has_value())')
        else:
            lines.append(f'    if (name == "{field.browse_name}")')
        lines.append(f"      return {prefix}value;")

    elif field.compound_kind in _STATE_MACHINE_KINDS:
        # Single-segment: return the CurrentState Value (LocalizedText). The state machine itself
        # has no scalar value; the CurrentState/CurrentState.Id are reached via the deeper paths.
        if opt:
            lines.append(f'    if (name == "{field.browse_name}" && {field_name}.has_value())')
        else:
            lines.append(f'    if (name == "{field.browse_name}")')
        lines.append(f"      return Variant{{{prefix}currentState}};")

    return lines


def _resolve_compound_two_segment(field, field_name: str) -> list[str]:
    """Generate two-segment resolve_field lines for a compound field."""
    lines: list[str] = []
    opt = field.is_optional
    prefix = f"{field_name}.value()." if opt else f"{field_name}."
    guard = f' && {field_name}.has_value()' if opt else ""

    if field.compound_kind == CompoundFieldKind.two_state:
        lines.append(f'      if (parent == "{field.browse_name}"{guard})')
        lines.append("      {")
        lines.append(f'        if (child == "Id") return Variant{{{prefix}id}};')
        lines.append(f'        if (child == "TransitionTime") return Variant{{{prefix}transitionTime}};')
        lines.append(f'        if (child == "CurrentState") return Variant{{{prefix}currentState}};')
        lines.append("      }")

    elif field.compound_kind == CompoundFieldKind.condition_var:
        lines.append(f'      if (parent == "{field.browse_name}"{guard})')
        lines.append("      {")
        lines.append(f'        if (child == "SourceTimestamp") return Variant{{{prefix}sourceTimestamp}};')
        lines.append("      }")

    elif field.compound_kind in _STATE_MACHINE_KINDS:
        # Two-segment: [<machine>, CurrentState] -> the FiniteStateVariable Value (LocalizedText); a
        # ShelvedStateMachineType also answers [<machine>, UnshelveTime] with its Duration.
        lines.append(f'      if (parent == "{field.browse_name}"{guard})')
        lines.append("      {")
        lines.append(f'        if (child == "CurrentState") return Variant{{{prefix}currentState}};')
        if field.compound_kind == CompoundFieldKind.shelved_state:
            lines.append(f'        if (child == "UnshelveTime") return Variant{{{prefix}unshelveTime}};')
        lines.append("      }")

    return lines


def _resolve_compound_three_segment(field, field_name: str) -> list[str]:
    """Generate three-segment resolve_field lines for a compound field.

    Only finite_state fields have a 3-deep selectable leaf: [<machine>, CurrentState, Id] ->
    the NodeId of the active state (CurrentState.Id)."""
    lines: list[str] = []
    if field.compound_kind not in _STATE_MACHINE_KINDS:
        return lines
    opt = field.is_optional
    prefix = f"{field_name}.value()." if opt else f"{field_name}."
    guard = f" && {field_name}.has_value()" if opt else ""
    lines.append(f'      if (a == "{field.browse_name}" && b == "CurrentState" && c == "Id"{guard})')
    lines.append(f"        return Variant{{{prefix}id}};")
    return lines


def _resolve_field_body(event_type: EventType) -> str:
    """Generate the body of resolve_field() for an event type."""
    parent = event_type.parent_class_name
    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln(f"  auto result = {parent}::resolve_field(browse_path);")
    ln("  if (!result.empty())")
    ln("    return result;")

    simple_fields = [f for f in event_type.own_fields if f.compound_kind == CompoundFieldKind.none]
    compound_fields = [f for f in event_type.own_fields if f.compound_kind != CompoundFieldKind.none]

    if simple_fields or compound_fields:
        ln()
        ln("  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)")
        ln("  {")
        ln("    const auto name = static_cast<std::string_view>(browse_path[0].name());")
        for field in simple_fields:
            variant_expr = field.variant_expression
            if field.is_optional:
                ln(f'    if (name == "{field.browse_name}" && {_field(field.cpp_name)})')
                ln(f"      return Variant{{{variant_expr}.value()}};")
            else:
                ln(f'    if (name == "{field.browse_name}")')
                ln(f"      return Variant{{{variant_expr}}};")
        for field in compound_fields:
            for line in _resolve_compound_field(field, _field(field.cpp_name)):
                ln(line)
        ln("  }")

    if compound_fields:
        ln()
        ln("  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0")
        ln("      && browse_path[1].namespace_index() == 0)")
        ln("  {")
        ln("    const auto parent = static_cast<std::string_view>(browse_path[0].name());")
        ln("    const auto child = static_cast<std::string_view>(browse_path[1].name());")
        for field in compound_fields:
            for line in _resolve_compound_two_segment(field, _field(field.cpp_name)):
                ln(line)
        ln("  }")

    finite_state_fields = [f for f in compound_fields if f.compound_kind in _STATE_MACHINE_KINDS]
    if finite_state_fields:
        ln()
        ln("  if (browse_path.size() == 3 && browse_path[0].namespace_index() == 0")
        ln("      && browse_path[1].namespace_index() == 0 && browse_path[2].namespace_index() == 0)")
        ln("  {")
        ln("    const auto a = static_cast<std::string_view>(browse_path[0].name());")
        ln("    const auto b = static_cast<std::string_view>(browse_path[1].name());")
        ln("    const auto c = static_cast<std::string_view>(browse_path[2].name());")
        for field in finite_state_fields:
            for line in _resolve_compound_three_segment(field, _field(field.cpp_name)):
                ln(line)
        ln("  }")

    ln()
    ln("  return Variant{};")
    return "".join(lines)


def _event_type_source_content(event_type: EventType, ctx) -> str:
    """Generate the source content for a single event type (no file wrapper)."""
    cn = event_type.class_name
    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    # NS0 event types live in namespace 0, so the ObjectTypeId enum ctor sets a
    # complete `event_type`. A companion-spec event type's namespace index is
    # only known to the emitting server, so the payload sets a namespace-index-free
    # id (ns 0 placeholder + numeric) and exposes its spec URI via
    # event_type_expanded(); Server::emit_event resolves the real index.
    ln(f"{cn}::{cn}()")
    ln("{")
    if ctx.cpp_namespace == "ua":
        ln(f"  eventType = NodeId{{ObjectTypeId::{event_type.browse_name}}};")
    else:
        ln(f"  eventType = NodeId{{0, utils::to_underlying(ObjectTypeId::{event_type.browse_name})}};")
    ln("}")
    ln()
    if ctx.cpp_namespace != "ua":
        ln(f"ExpandedNodeId {cn}::event_type_expanded() const")
        ln("{")
        ln(f"  return ExpandedNodeId{{NodeId{{0, utils::to_underlying(ObjectTypeId::{event_type.browse_name})}},")
        ln("    specNamespaceUri};")
        ln("}")
        ln()
    ln(f"std::unique_ptr<BaseEvent> {cn}::clone() const")
    ln("{")
    ln(f"  return std::make_unique<{cn}>(*this);")
    ln("}")
    ln()
    ln(f"Variant {cn}::resolve_field(std::span<const QualifiedName> browse_path) const")
    ln("{")
    lines.append(_resolve_field_body(event_type))
    ln("}")

    return "".join(lines)


def _event_source_prologue(ctx, headers_in_order: list[str]) -> str:
    """Shared include prologue for event-type sources (combined or per-type)."""
    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln("// *** THIS FILE IS GENERATED - DO NOT EDIT ***")
    ln()
    ln(f'#include "{ctx.include_prefix}objecttype_id.h"')
    ln('#include "ua_data_value.h"')
    if ctx.cpp_namespace != "ua":
        # Companion event ctors resolve their type id namespace at emit time via
        # the spec URI carried in an ExpandedNodeId. ``utils::to_underlying``
        # converts the companion ``ObjectTypeId`` (no NodeId ctor) to its numeric id.
        ln(f'#include "{ctx.include_prefix}namespace_uri.h"')
        ln('#include "ua_expanded_node_id.h"')
        ln('#include "ua_utilities.h"')
    ln()
    ln("#include <memory>")
    ln()
    for h in headers_in_order:
        ln(f'#include "{h}"')
    ln()
    return "".join(lines)


def _emit_event_types_combined_source(
    ctx,
    event_types: list[EventType],
    headers_in_order: list[str],
) -> Path:
    """Emit a single combined ``<prefix>event_types.cpp`` for all event types.

    Mirrors the data-type pattern: one compilation unit includes all
    headers and contains all constructor + resolve_field implementations.
    """
    lines: list[str] = [_event_source_prologue(ctx, headers_in_order)]

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln(ctx.cpp_namespace_open())
    ln()

    for et in event_types:
        lines.append(_event_type_source_content(et, ctx))
        ln()

    ln(ctx.cpp_namespace_close())

    out_path = ctx.implementation_dir_for("event_types") / f"{ctx.include_prefix}event_types.cpp"
    write_file(out_path, "".join(lines))
    return out_path


def _emit_event_type_source_files(
    ctx,
    event_types: list[EventType],
    headers_in_order: list[str],
) -> tuple[list[Path], list[str]]:
    """One ``<prefix><snake>.cpp`` per event type (consumer layout)."""
    paths: list[Path] = []
    names: list[str] = []
    for et, header in zip(event_types, headers_in_order):
        lines: list[str] = [_event_source_prologue(ctx, [header])]
        lines.append(ctx.cpp_namespace_open() + "\n")
        lines.append("\n")
        lines.append(_event_type_source_content(et, ctx))
        lines.append("\n")
        lines.append(ctx.cpp_namespace_close() + "\n")

        basename = header.removesuffix(".h") + ".cpp"
        out_path = ctx.implementation_dir_for("event_types") / basename
        write_file(out_path, "".join(lines))
        paths.append(out_path)
        names.append(basename)
    return paths, names


# --- Tests ---


def emit_event_type_tests(
    output_dir: Path,
    event_types: list[EventType],
) -> Path:
    """Emit generated event type tests."""
    text = load_template("generated_event_type_tests.in")

    includes: list[str] = []
    seen: set[str] = set()
    for et in event_types:
        header = f"ua_{_snake(et.class_name)}.h"
        if header not in seen:
            seen.add(header)
            includes.append(f'#include "{header}"')

    test_cases: list[str] = []

    for et in event_types:
        cn = et.class_name
        bn = et.browse_name

        non_optional = [f for f in et.own_fields if not f.is_optional]
        optional = [f for f in et.own_fields if f.is_optional]
        compound = [f for f in et.own_fields if f.compound_kind != CompoundFieldKind.none]

        # Construction test
        test_cases.append(
            f"\nTEST(GeneratedEventTypeTests, {cn}_Construction) {{\n"
            f"  {cn} event;\n"
            f"  EXPECT_EQ(event.eventType, NodeId{{ObjectTypeId::{bn}}});\n"
            "}\n"
        )

        # Strengthened own-field resolution: assigns each non-optional field
        # to a sentinel local, resolves via the public browse path, and
        # asserts the resolved Variant carries the same value (where the
        # value can be meaningfully compared).
        if non_optional:
            lines: list[str] = []
            lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_ResolveOwnFields) {{")
            lines.append(f"  {cn} event;")
            for field in non_optional:
                field_name = _snake(field.cpp_name)
                val = _field_test_value(field)
                lines.append(f"  auto sentinel_{field_name} = {val};")
                lines.append(f"  event.{_field(field.cpp_name)} = sentinel_{field_name};")
                lines.append(
                    f'  const QualifiedName path_{field_name}[]'
                    f'{{QualifiedName{{0, "{field.browse_name}"}}}};'
                )
                lines.append(
                    f"  auto result_{field_name} = event.resolve_field(path_{field_name});"
                )
                lines.append(
                    f"  ASSERT_FALSE(result_{field_name}.empty()) << "
                    f'"{field.browse_name} resolved to empty";'
                )
                lines.extend(_value_check_lines(
                    f"result_{field_name}",
                    field,
                    f"sentinel_{field_name}",
                ))
            lines.append("}")
            test_cases.append("\n".join(lines) + "\n")

        # Optional own fields - assert resolve returns empty when unset, and
        # returns the populated value once set. Covers both branches of the
        # ``name == "X" && optional_x.has_value()`` style guard.
        if optional:
            lines = []
            lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_OptionalFields_Unset) {{")
            lines.append(f"  {cn} event;")
            for field in optional:
                field_name = _snake(field.cpp_name)
                lines.append(
                    f'  const QualifiedName path_{field_name}[]'
                    f'{{QualifiedName{{0, "{field.browse_name}"}}}};'
                )
                lines.append(
                    f"  EXPECT_TRUE(event.resolve_field(path_{field_name}).empty())"
                    f' << "{field.browse_name} unexpectedly resolved while unset";'
                )
            lines.append("}")
            test_cases.append("\n".join(lines) + "\n")

            lines = []
            lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_OptionalFields_Set) {{")
            lines.append(f"  {cn} event;")
            for field in optional:
                field_name = _snake(field.cpp_name)
                val = _field_test_value(field)
                lines.append(f"  auto sentinel_{field_name} = {val};")
                lines.append(f"  event.{_field(field.cpp_name)} = sentinel_{field_name};")
                lines.append(
                    f'  const QualifiedName path_{field_name}[]'
                    f'{{QualifiedName{{0, "{field.browse_name}"}}}};'
                )
                lines.append(
                    f"  auto result_{field_name} = event.resolve_field(path_{field_name});"
                )
                lines.append(
                    f"  ASSERT_FALSE(result_{field_name}.empty()) << "
                    f'"{field.browse_name} resolved to empty after being set";'
                )
                lines.extend(_value_check_lines(
                    f"result_{field_name}",
                    field,
                    f"sentinel_{field_name}",
                ))
            lines.append("}")
            test_cases.append("\n".join(lines) + "\n")

        # Compound fields (TwoStateVariableState / ConditionVariableState):
        # resolve every 2-deep sub-path and check the leaf value. This hits
        # the per-sub-field branches in the generated resolve_field switch.
        compound_to_test = [
            f for f in compound
            if not f.is_optional or True  # include both - populate via optional
        ]
        # We need to cover both the always-instantiated branch and the
        # ``has_value()`` branch, so iterate over compound fields whose
        # resolve guard is always-true (non-optional) here; optional compound
        # fields are exercised separately below.
        non_optional_compound = [f for f in compound if not f.is_optional]
        if non_optional_compound:
            lines = []
            lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_CompoundSubFields) {{")
            lines.append(f"  {cn} event;")
            for field in non_optional_compound:
                field_name = _snake(field.cpp_name)
                val = _TEST_VALUES.get(field.cpp_type, "Variant{42}")
                lines.append(f"  auto sentinel_{field_name} = {val};")
                lines.append(f"  event.{_field(field.cpp_name)} = sentinel_{field_name};")
                for browse_seg, member, as_type in _compound_sub_paths(field):
                    safe = f"{field_name}_{_snake(browse_seg)}"
                    lines.append(
                        f"  const QualifiedName path_{safe}[]"
                        f'{{QualifiedName{{0, "{field.browse_name}"}}, '
                        f'QualifiedName{{0, "{browse_seg}"}}}};'
                    )
                    lines.append(
                        f"  auto result_{safe} = event.resolve_field(path_{safe});"
                    )
                    lines.append(
                        f"  ASSERT_FALSE(result_{safe}.empty()) << "
                        f'"{field.browse_name}.{browse_seg} resolved to empty";'
                    )
                    lines.append(
                        f"  EXPECT_EQ(result_{safe}.as<{as_type}>(),"
                        f" sentinel_{field_name}.{member});"
                    )
            lines.append("}")
            test_cases.append("\n".join(lines) + "\n")

        optional_compound = [f for f in compound if f.is_optional]
        if optional_compound:
            lines = []
            lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_OptionalCompoundSubFields) {{")
            lines.append(f"  {cn} event;")
            for field in optional_compound:
                field_name = _snake(field.cpp_name)
                val = _TEST_VALUES.get(field.cpp_type, "Variant{42}")
                # Sentinel is the bare struct value (TwoStateVariableState /
                # ConditionVariableState); the field is a std::optional<...>
                # which the assignment will implicitly wrap.
                lines.append(f"  auto sentinel_{field_name} = {val};")
                lines.append(f"  event.{_field(field.cpp_name)} = sentinel_{field_name};")
                for browse_seg, member, as_type in _compound_sub_paths(field):
                    safe = f"{field_name}_{_snake(browse_seg)}"
                    lines.append(
                        f"  const QualifiedName path_{safe}[]"
                        f'{{QualifiedName{{0, "{field.browse_name}"}}, '
                        f'QualifiedName{{0, "{browse_seg}"}}}};'
                    )
                    lines.append(
                        f"  auto result_{safe} = event.resolve_field(path_{safe});"
                    )
                    lines.append(
                        f"  ASSERT_FALSE(result_{safe}.empty()) << "
                        f'"{field.browse_name}.{browse_seg} resolved to empty after being set";'
                    )
                    lines.append(
                        f"  EXPECT_EQ(result_{safe}.as<{as_type}>(),"
                        f" sentinel_{field_name}.{member});"
                    )
            lines.append("}")
            test_cases.append("\n".join(lines) + "\n")

        # Clone test - covers the generated ``clone()`` override and verifies
        # that a copy carries the type discriminator + at least one populated
        # field through to the produced unique_ptr<BaseEvent>.
        clone_lines: list[str] = []
        clone_lines.append(f"\nTEST(GeneratedEventTypeTests, {cn}_Clone) {{")
        clone_lines.append(f"  {cn} event;")
        clone_lines.append("  event.severity = 511;")
        # Populate one non-optional own field if possible to make the clone
        # test exercise more than the inherited fields.
        own_witness: EventFieldInfo | None = None
        for field in non_optional:
            if field.compound_kind != CompoundFieldKind.none:
                continue
            if field.cpp_type in _TEST_VALUES:
                own_witness = field
                break
        if own_witness is not None:
            fname = _snake(own_witness.cpp_name)
            val = _field_test_value(own_witness)
            clone_lines.append(f"  auto sentinel_clone_{fname} = {val};")
            clone_lines.append(f"  event.{_field(own_witness.cpp_name)} = sentinel_clone_{fname};")
        clone_lines.append("  auto cloned = event.clone();")
        clone_lines.append("  ASSERT_NE(cloned, nullptr);")
        clone_lines.append(f"  auto* casted = dynamic_cast<{cn}*>(cloned.get());")
        clone_lines.append('  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";')
        clone_lines.append("  EXPECT_EQ(casted->eventType, event.eventType);")
        clone_lines.append("  EXPECT_EQ(casted->severity, event.severity);")
        if own_witness is not None:
            fname = _snake(own_witness.cpp_name)
            ct = _field_cpp_type(own_witness)
            if ct != "Variant":
                clone_lines.append(
                    f"  EXPECT_EQ(casted->{_field(own_witness.cpp_name)}, sentinel_clone_{fname});"
                )
        clone_lines.append("}")
        test_cases.append("\n".join(clone_lines) + "\n")

        # Parent delegation test - keeps the existing severity round-trip
        # but now also serves as a regression guard alongside the new tests.
        test_cases.append(
            f"\nTEST(GeneratedEventTypeTests, {cn}_ParentDelegation) {{\n"
            f"  {cn} event;\n"
            f"  event.severity = 500;\n"
            f'  const QualifiedName severityPath[]{{QualifiedName{{0, "Severity"}}}};\n'
            f"  auto result = event.resolve_field(severityPath);\n"
            f"  EXPECT_FALSE(result.empty());\n"
            f"  auto val = result.as<uint16_t>();\n"
            f"  EXPECT_EQ(val, 500);\n"
            "}\n"
        )

    # NOTE: EventType subtype matching (EventFilter OfType) is resolved at runtime
    # against the address-space HasSubtype hierarchy by the EventBus/subscription
    # layer - NOT by the generated event payloads - so it is tested there, not here.

    text = text.replace("PLACEHOLDER_INCLUDES", "\n".join(includes))
    text = text.replace("PLACEHOLDER_TEST_CASES", "".join(test_cases).rstrip("\n"))

    out_path = output_dir / "generated_event_type_tests.cpp"
    write_file(out_path, text)
    return out_path
