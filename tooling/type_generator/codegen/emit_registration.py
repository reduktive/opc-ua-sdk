# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit the per-spec data-type registration entry points.

``<prefix>data_type_registration.{h,cpp}`` exposes the data-type factory registrars. Historically
this was a single ``register_<prefix>data_types_with_factory(...)`` that registered every type. To
let a server link (and the linker keep) only the type families its profile needs, registration is now
split **per family** (see ``codegen.category_family``):

  * one ``register_<prefix><family>_data_types_with_factory(...)`` per non-empty family, and
  * the original aggregate ``register_<prefix>data_types_with_factory(...)`` which simply calls every
    family registrar - so existing callers and the Standard profile are unchanged.

This split is behaviour-neutral on its own (the aggregate registers the exact same set). Footprint
only changes once a caller invokes per-family registrars selectively *and* the type TUs are sharded
per family (a later phase), because the per-``::create`` references are what anchor the bundle ``.o``s.

Per-spec function-name prefixes (NS0 -> ``register_ua_...``; DI -> ``register_ua_di_...``) keep NS0 and
downstream specs linkable into one binary without name collisions.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import get_symbolic_name
from .category_family import FAMILIES, family_for
from .context import EmitContext

# Shared parameter list for every registrar (clang-format normalises the layout post-emit).
_SIGNATURE = (
    "(const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)"
)


class RegistrationEmitter:
    """Emits the per-spec data-type registration header + source."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    @property
    def header_name(self) -> str:
        return f"{self._ctx.include_prefix}data_type_registration.h"

    @property
    def function_name(self) -> str:
        """Aggregate entry point - registers every family (back-compat name, unchanged).

        NS0 (prefix=``ua_``) -> ``register_ua_data_types_with_factory``;
        DI (prefix=``ua_di_``) -> ``register_ua_di_data_types_with_factory``.
        """
        return f"register_{self._ctx.include_prefix}data_types_with_factory"

    def _family_function_name(self, family: str) -> str:
        return f"register_{self._ctx.include_prefix}{family}_data_types_with_factory"

    def _collect(
        self,
        structure_node_ids_in_order: list[str],
        binary_encoding_type_names: set[str] | None,
    ) -> tuple[list[str], dict[str, list[str]], list[str]]:
        """Bucket the registerable types by family, preserving declaration order.

        Returns ``(families_in_order, type_names_by_family, include_lines)``. Only non-abstract,
        encodable structures are included - mirroring the per-struct ``register_type`` emission so we
        never call ``register_type`` on a type that does not declare it.
        """
        type_names_by_family: dict[str, list[str]] = {}
        include_lines: list[str] = []
        seen_headers: set[str] = set()
        for node_id in structure_node_ids_in_order:
            node = self._ctx.index.find(node_id)
            if node is None or node.is_abstract:
                continue
            type_name = get_symbolic_name(node.browse_name)
            is_encodable = (
                binary_encoding_type_names is None or type_name in binary_encoding_type_names
            )
            if not is_encodable:
                continue
            header = self._ctx.header_file_name(type_name)
            if header not in seen_headers:
                seen_headers.add(header)
                include_lines.append(f'#include "{header}"\n')
            type_names_by_family.setdefault(family_for(node.category), []).append(type_name)

        # Canonical family order first, then any unexpected family deterministically (defensive - every
        # category maps into FAMILIES, with the unmatched fallback being ``core``).
        families_in_order = [f for f in FAMILIES if type_names_by_family.get(f)]
        families_in_order += [f for f in type_names_by_family if f not in families_in_order]
        return families_in_order, type_names_by_family, include_lines

    def emit_header(
        self,
        structure_node_ids_in_order: list[str],
        binary_encoding_type_names: set[str] | None = None,
    ) -> Path:
        families, _, _ = self._collect(structure_node_ids_in_order, binary_encoding_type_names)
        names = [self._family_function_name(f) for f in families] + [self.function_name]
        return _emit_registration_header(self._ctx, self.header_name, names)

    def emit_source(
        self,
        structure_node_ids_in_order: list[str],
        structure_headers_in_order: list[str] | None = None,
        binary_encoding_type_names: set[str] | None = None,
    ) -> Path:
        families, type_names_by_family, include_lines = self._collect(
            structure_node_ids_in_order, binary_encoding_type_names
        )
        return _emit_registration_source(
            self._ctx,
            self.header_name,
            self.function_name,
            families,
            type_names_by_family,
            [self._family_function_name(f) for f in families],
            include_lines,
        )


def _render_definition(name: str, body_lines: list[str]) -> str:
    return f"void {name}{_SIGNATURE}\n{{\n{''.join(body_lines)}}}\n"


def _render_declaration(name: str) -> str:
    return f"void {name}{_SIGNATURE};\n"


def _emit_registration_header(ctx: EmitContext, header_name: str, function_names: list[str]) -> Path:
    text = ctx.apply_template(load_template("structure_type_reg_header.in"))
    guard = f"{ctx.guard_prefix}_DATA_TYPE_REGISTRATION_H"
    text = text.replace("PLACEHOLDER_REGISTRATION_HEADER_GUARD", guard)
    # NS0 forward-declares ``ua::StructureFactory``; a companion spec instead pulls it (and
    # CodecNamespaceContext) in via ``<prefix>aliases.h`` - a forward decl would declare
    # ``ua::di::StructureFactory`` and clash with that alias. (NS0 emits no aliases include.)
    if ctx.cpp_namespace == "ua":
        text = text.replace("PLACEHOLDER_REG_ALIASES_INCLUDE", "")
        text = text.replace("PLACEHOLDER_REG_FACTORY_FWD", "class StructureFactory;\n")
    else:
        text = text.replace(
            "PLACEHOLDER_REG_ALIASES_INCLUDE", f'#include "{ctx.include_prefix}aliases.h"'
        )
        text = text.replace("PLACEHOLDER_REG_FACTORY_FWD", "")

    declarations = "".join(_render_declaration(name) for name in function_names).rstrip("\n")
    text = text.replace("PLACEHOLDER_DECLARATIONS", declarations)

    out_path = ctx.interface_dir / header_name
    write_file(out_path, text)
    return out_path


def _emit_registration_source(
    ctx: EmitContext,
    header_name: str,
    aggregate_function_name: str,
    families: list[str],
    type_names_by_family: dict[str, list[str]],
    family_function_names: list[str],
    include_lines: list[str],
) -> Path:
    text = ctx.apply_template(load_template("structure_type_reg_source.in"))
    text = text.replace("PLACEHOLDER_REGISTRATION_HEADER", header_name)

    definitions: list[str] = []
    for family, fn_name in zip(families, family_function_names):
        body = [
            f"  {type_name}::register_type(ns, uaBinaryFactory, xmlFactory);\n"
            for type_name in type_names_by_family[family]
        ]
        definitions.append(_render_definition(fn_name, body))

    # Aggregate: delegate to every family registrar (back-compat - same total set).
    aggregate_body = [
        f"  {fn_name}(ns, uaBinaryFactory, xmlFactory);\n" for fn_name in family_function_names
    ]
    definitions.append(_render_definition(aggregate_function_name, aggregate_body))

    text = text.replace("PLACEHOLDER_FUNCTIONS", "\n".join(definitions).rstrip("\n"))
    text = text.replace("PLACEHOLDER_INCLUDES", "".join(include_lines).rstrip("\n"))

    out_path = ctx.implementation_dir / f"{ctx.include_prefix}data_type_registration.cpp"
    write_file(out_path, text)
    return out_path
