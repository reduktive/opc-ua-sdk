# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit the per-spec ``<prefix>namespace_uri.h`` and ``<prefix>aliases.h``.

These two small headers centralise per-spec metadata that would
otherwise be duplicated in every emitted type header:

* **``<prefix>namespace_uri.h``** - declares
  ``inline constexpr string_view specNamespaceUri{...}`` once per spec.

  (Filename ends in ``_namespace_uri.h``, not ``_namespace.h``, to
  avoid colliding with the SDK's ``ua_namespace.h`` which declares the
  ``Namespace`` abstract class.)
  Every type header references it via
  ``static constexpr string_view typeNamespaceUri = specNamespaceUri;``
  instead of inlining the URI string literal.  Changing a spec's URI
  becomes a one-line edit in this header.

* **``<prefix>aliases.h``** - pulls every core ``ua::`` type the
  generated code references into the emitting spec's namespace via
  ``using ::ua::NodeId;`` etc.  Lets the templates keep using bare
  ``NodeId``, ``Structure``, ... without qualification regardless of
  the emitting spec's ``cpp_namespace``.

  For NS0 (``cpp_namespace == "ua"``), the aliases would be no-ops
  (the names are already in scope), so we emit a file with an empty
  body and a short comment.  Downstream specs that emit in
  ``ua::di``, ``ua::machinery``, etc. get the full alias block.
"""

from __future__ import annotations

from pathlib import Path

from ..io import write_file
from ..manifest import NS0_URI
from .context import EmitContext


# Core ``ua::`` names referenced by the type emission templates.
# Discovered by greping ``inputs/*.in`` + ``codegen/emit_*.py`` for
# bare identifiers that resolve to ``ua::<name>``.  Adding a new name
# to a template means adding it here too - otherwise downstream specs
# won't compile.
_UA_CORE_ALIASES: tuple[str, ...] = (
    "Array",
    "BaseEvent",
    "BuiltInTypeId",
    "ByteString",
    "CodecNamespaceContext",
    "DataValue",
    "DateTime",
    "Decoder",
    "DiagnosticInfo",
    "Encoder",
    "ExpandedNodeId",
    "Guid",
    "LocaleId",
    "LocalizedText",
    "NodeId",
    "OptionSet",
    "QualifiedName",
    "RefStructure",
    "Result",
    "StackDepth",
    "StatusCode",
    "String",
    "Structure",
    "StructureFactory",
    "Union",
    "Variant",
    "XmlElement",
    "get_typename",
    "optional",
    "span",
    "string_view",
)


# The headers `<prefix>aliases.h` pulls in so the ``using ::ua::*`` block resolves.
# Every name in `_UA_CORE_ALIASES` must be declared within the transitive include
# closure of these headers (verified by tests/test_aliases_coverage.py).
_UMBRELLA_HEADERS: tuple[str, ...] = (
    "ua_includes.h",
    "ua_structure.h",
    "ua_union.h",
    "ua_structure_factory.h",
    "ua_array.h",
    "ua_option_set.h",
    "ua_base_event.h",
)


class SpecHeadersEmitter:
    """Emits the two per-spec headers - ``namespace.h`` and ``aliases.h``."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit_namespace_header(self) -> Path:
        return _emit_namespace_header(self._ctx)

    def emit_aliases_header(self) -> Path:
        return _emit_aliases_header(self._ctx)

    # File names exposed so callers (templates, CMakeLists emitter)
    # can reference them consistently.

    @property
    def namespace_uri_header_name(self) -> str:
        return f"{self._ctx.include_prefix}namespace_uri.h"

    @property
    def aliases_header_name(self) -> str:
        return f"{self._ctx.include_prefix}aliases.h"


def _emit_namespace_header(ctx: EmitContext) -> Path:
    guard = f"{ctx.guard_prefix}_NAMESPACE_URI_H"
    lines: list[str] = [
        f"#ifndef {guard}\n",
        f"#define {guard}\n",
        "\n",
        "// *** THIS FILE IS GENERATED - DO NOT EDIT ***\n",
        "\n",
        '#include "ua_includes.h"\n',
        "\n",
        f"{ctx.cpp_namespace_open()}\n",
        "\n",
        f"/// Stable URI for this spec.  Every generated type's\n",
        f"/// ``typeNamespaceUri`` aliases this constant, so the URI\n",
        f"/// is defined exactly once per spec.\n",
        f'inline constexpr string_view specNamespaceUri{{"{ctx.config.uri}"}};\n',
        "\n",
        f"{ctx.cpp_namespace_close()}\n",
        "\n",
        f"#endif  // {guard}\n",
    ]

    out_path = ctx.interface_dir / f"{ctx.include_prefix}namespace_uri.h"
    write_file(out_path, "".join(lines))
    return out_path


def _emit_aliases_header(ctx: EmitContext) -> Path:
    guard = f"{ctx.guard_prefix}_ALIASES_H"
    lines: list[str] = [
        f"#ifndef {guard}\n",
        f"#define {guard}\n",
        "\n",
        "// *** THIS FILE IS GENERATED - DO NOT EDIT ***\n",
        "\n",
    ]

    if ctx.config.uri == NS0_URI:
        # NS0 emits in ``namespace ua`` - every core name is already
        # in scope, so the aliases block is empty.  We still emit the
        # file so the include in every type header resolves uniformly
        # across specs.
        lines.append(
            "// NS0 emits in ``namespace ua`` so the core types are already in scope.\n"
            "// This file is intentionally empty - kept for include-shape parity with\n"
            "// downstream specs which need the ``using ::ua::*`` block to compile.\n"
        )
    else:
        # Downstream specs need the core ``ua::`` types pulled into
        # their emitting namespace.  ``inline namespace`` blocks would
        # work too but ``using`` declarations keep ADL behaviour
        # predictable and are easier to debug.
        #
        # Pull in the umbrella headers that declare every aliased name so the
        # ``using`` block resolves regardless of include order in the consuming
        # type header.  ``ua_structure.h`` is a near-complete umbrella (built-in
        # fwd decls, get_typename, the codec context, Encoder/Decoder, LocaleId,
        # StackDepth, ...); the rest cover the names it doesn't transitively declare.
        for header in _UMBRELLA_HEADERS:
            lines.append(f'#include "{header}"\n')
        lines.append("\n")
        lines.append(f"{ctx.cpp_namespace_open()}\n")
        lines.append("\n")
        for name in _UA_CORE_ALIASES:
            lines.append(f"using ::ua::{name};\n")
        lines.append("\n")
        lines.append(f"{ctx.cpp_namespace_close()}\n")

    lines.append("\n")
    lines.append(f"#endif  // {guard}\n")

    out_path = ctx.interface_dir / f"{ctx.include_prefix}aliases.h"
    write_file(out_path, "".join(lines))
    return out_path
