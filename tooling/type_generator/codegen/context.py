# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Per-spec emission context.

``EmitContext`` is the single object an emitter needs.  It bundles the
spec's identity (``NodesetConfig``), the global type index, the
``TypeResolver``, the output directories, and all derived helpers
emitters share - filename construction, header-guard naming, namespace
block formatting, template substitution.

Building an emitter is::

    ctx = EmitContext.build(spec_config, index, output_root)
    emitter = StructureEmitter(ctx)

Emitters never reach past ``ctx`` for spec metadata; they never receive
ad-hoc ``include_prefix`` / ``cpp_namespace`` parameters.  This is what
keeps each emitter focused on its category (structure header, union
header, ...) instead of plumbing the spec identity everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..manifest import NS0_URI, NodesetConfig
from ..naming import to_snake_case, to_screaming_snake_case
from ..nodeset.index import NodeSetIndex
from ..types.refs import TypeResolver


@dataclass(frozen=True, slots=True)
class EmitContext:
    """Everything an emitter needs to produce code for one spec."""

    # The spec we're emitting for.
    config: NodesetConfig

    # All nodesets in scope (emit + lookup).  Used by emitters to walk
    # types and by the resolver for cross-spec lookup.
    index: NodeSetIndex

    # Always-returns-a-value type resolver.  Resolves any node-id
    # reference to a ``TypeRef`` regardless of in-spec / cross-spec.
    resolver: TypeResolver

    # Root output directory (the ``--output`` path).  Per-category
    # subdirectories are derived via ``interface_dir_for`` /
    # ``implementation_dir_for``.  The split is universal: every emitter
    # writes to one tree or the other.
    output_root: Path

    # ---- Spec-derived shortcuts --------------------------------------

    @property
    def cpp_namespace(self) -> str:
        return self.config.cpp_namespace

    @property
    def include_prefix(self) -> str:
        return self.config.include_prefix

    @property
    def core_qualifier(self) -> str:
        """Namespace qualifier for core (NS0 ``ua``) symbols referenced from
        generated code.

        Empty for NS0 itself (those symbols are already in ``ua``); ``::ua::``
        for a companion spec whose code lives in a nested namespace
        (e.g. ``ua::di``) and must reach core enums/types explicitly - the
        standard ``ReferenceTypeId::HasComponent`` etc. are always NS0-owned,
        so an unqualified reference would wrongly bind to the companion spec's
        own (HasComponent-less) ``ReferenceTypeId`` enum.
        """
        return "" if self.cpp_namespace == "ua" else "::ua::"

    @property
    def target_name(self) -> str:
        return self.config.target

    # Per-category CMake target for the layered NS0 build (library_layering.md
    # section 4.3/section 5).  NS0's generated categories are split across two SDK layer libs:
    # the wire/type categories are role-agnostic core; the instance-handle
    # categories and the ns0 NodeSet blob are the server information model.
    # Companion specs are single-target test fixtures, so they fall through to
    # ``target_name``.
    _NS0_CORE_CATEGORIES = frozenset({"data_types", "status", "ids", "ns0_model"})
    _NS0_ADDRESS_SPACE_CATEGORIES = frozenset(
        {"object_types", "variable_types", "event_types", "ns0"}
    )

    def target_for(self, category: str) -> str:
        """CMake target that owns ``category`` for this spec.

        For NS0 the generated tree is layered: ``data_types``/``status``/``ids``/``ns0_model``
        -> ``uasdk-core``; ``object_types``/``variable_types``/``event_types``/
        ``ns0`` -> ``uasdk-address-space``.  All other (companion) specs emit a
        single target (``target_name``).
        """
        if self.config.uri == NS0_URI:
            if category in self._NS0_CORE_CATEGORIES:
                return "uasdk-core"
            if category in self._NS0_ADDRESS_SPACE_CATEGORIES:
                return "uasdk-address-space"
        return self.target_name

    def layer_segment_for(self, category: str) -> str:
        """SDK source-tree layer folder ('core' or 'address_space') that owns
        ``category`` in NS0's split tree.

        Mirrors ``target_for``: the wire/type categories live under ``core/``,
        the instance-handle categories + the ns0 blob under ``address_space/``.
        (library_layering.md section 2.3/section 5.)
        """
        if category in self._NS0_CORE_CATEGORIES:
            return "core"
        return "address_space"

    @property
    def amalgamate_sources(self) -> bool:
        """Whether data-type / event-type bodies are merged into a single TU.

        An SDK build-time optimisation carried by the manifest; NS0 sets it,
        consumer specs leave it off (one ``.cpp`` per type). See
        ``NodesetConfig.amalgamate_sources``.
        """
        return self.config.amalgamate_sources

    @property
    def flat_layout(self) -> bool:
        """Whether to emit a single flat tree (no ``interface``/``implementation``
        split).

        The split is an SDK-internal visibility requirement that only NS0's
        committed tree needs; it is hardcoded to NS0 here rather than exposed as
        a manifest option.  Every consumer (non-NS0) spec emits a flat tree with
        per-category subfolders and ``.h`` + ``.cpp`` co-located.
        """
        return self.config.uri != NS0_URI

    @property
    def guard_prefix(self) -> str:
        """E.g. ``UA`` for ``include_prefix='ua_'``, ``UA_DI`` for ``'ua_di_'``."""
        return self.include_prefix.rstrip("_").upper()

    @property
    def is_ns0(self) -> bool:
        """True for the NS0 (core OPC UA) spec.

        NS0 is the only spec whose generated headers form the published public
        API reference (``sdk/interface``); companion specs emit test fixtures.
        """
        return self.config.uri == NS0_URI

    def doc_comment(self, brief: str, group: str, fallback: str = "") -> str:
        """Doxygen doc block (brief + ``@ingroup``) for a generated public type.

        Emitted only for NS0, whose generated headers are documented in the API
        reference. Companion-spec fixtures get ``fallback`` (the type's existing
        plain ``//`` comment, or an empty string), keeping their committed output
        byte-identical.
        """
        if not self.is_ns0:
            return fallback
        return f"/// {brief}\n/// @ingroup {group}"

    # ---- Output directory helpers ------------------------------------

    def interface_dir_for(self, category: str) -> Path:
        """Header tree for one generated category.

        ``category`` is one of ``data_types``, ``object_types``,
        ``variable_types``, ``event_types``, ``ids``, ``status``,
        ``ns0``, ``ns0_model``.

        NS0 splits headers into the layered tree
        ``interface/<layer>/generated/ua/<category>`` (layer = ``core`` for the
        wire/type categories, ``address_space`` for the instance-handle ones);
        a consumer (``flat_layout``) spec co-locates everything under
        ``<output>/<category>``.
        """
        if self.flat_layout:
            return self.output_root / category
        return (
            self.output_root
            / "interface" / self.layer_segment_for(category) / "generated" / "ua" / category
        )

    def implementation_dir_for(self, category: str) -> Path:
        """Source tree for one generated category.

        For a consumer (``flat_layout``) spec this is the **same** directory as
        ``interface_dir_for`` - ``.h`` and ``.cpp`` live side by side.
        """
        if self.flat_layout:
            return self.output_root / category
        return (
            self.output_root
            / "implementation" / self.layer_segment_for(category) / "generated" / "ua" / category
        )

    @property
    def interface_dir(self) -> Path:
        """Default interface dir (data_types) - the common case.

        Most emitters write here; instance-type and identifier emitters
        call ``interface_dir_for`` with their own category.
        """
        return self.interface_dir_for("data_types")

    @property
    def implementation_dir(self) -> Path:
        return self.implementation_dir_for("data_types")

    # ---- Derived helpers ---------------------------------------------

    def header_file_name(self, class_name: str) -> str:
        """Compute the public header filename for an emitted class.

        ``ua_<snake>.h`` for NS0, ``ua_di_<snake>.h`` for DI, etc.
        """
        return f"{self.include_prefix}{to_snake_case(class_name)}.h"

    def source_file_name(self, class_name: str) -> str:
        return f"{self.include_prefix}{to_snake_case(class_name)}.cpp"

    def header_guard(self, kind: str, type_name: str) -> str:
        """Build a header guard with a category infix.

        ``kind`` is the per-category infix (``DATA_TYPE``,
        ``INSTANCE_TYPE``, ``EVENT_TYPE``, ...).  Result:
        ``UA_DATA_TYPE_FOO_H`` (NS0), ``UA_DI_DATA_TYPE_FOO_H`` (DI).
        Pass an empty string to drop the infix entirely; use
        ``simple_header_guard`` for that case so intent is explicit.
        """
        infix = f"{kind}_" if kind else ""
        return f"{self.guard_prefix}_{infix}{to_screaming_snake_case(type_name)}_H"

    def simple_header_guard(self, type_name: str) -> str:
        """Build a header guard without a category infix.

        Used by instance-type headers (``UA_FILE_H``, ``UA_FOLDER_H``)
        and any other category that doesn't carry a kind tag.
        """
        return self.header_guard("", type_name)

    def cpp_namespace_open(self) -> str:
        """Two-line ``namespace <ns>\\n{`` block opener."""
        return f"namespace {self.cpp_namespace}\n{{"

    def cpp_namespace_close(self) -> str:
        """Single-line ``}} // namespace <ns>`` closer.

        Single-space form matches the existing template style; clang-format
        normalises it to double-space in the final output.
        """
        return f"}} // namespace {self.cpp_namespace}"

    def apply_template(self, text: str) -> str:
        """Substitute the context-driven placeholders in a template.

        Type-specific placeholders (class names, fields, includes,
        ...) are still applied by the per-category emitter; this pass
        handles only the substitutions that are uniform across every
        template.
        """
        return (
            text
            .replace("PLACEHOLDER_NS_OPEN", self.cpp_namespace_open())
            .replace("PLACEHOLDER_NS_CLOSE", self.cpp_namespace_close())
            .replace("PLACEHOLDER_SPEC_INCLUDES", self._spec_includes(text))
        )

    def _spec_includes(self, template_text: str) -> str:
        """Conditional ``#include`` block for the per-spec metadata headers.

        Each header is emitted only when the type actually needs it,
        rather than unconditionally on every type header:

        * ``<prefix>namespace_uri.h`` declares ``specNamespaceUri``.  It is
          emitted only when the template body references that symbol -
          i.e. structure and union headers (which set
          ``typeNamespaceUri = specNamespaceUri``).  Object-type, enum,
          optionset and simple headers never reference it.
        * ``<prefix>aliases.h`` pulls core ``ua::*`` types into scope for
          companion specs that emit into a *nested* namespace.  For NS0
          (``cpp_namespace == "ua"``) those types are already in scope and
          the aliases header is intentionally empty, so it is omitted.
        """
        includes: list[str] = []
        if "specNamespaceUri" in template_text:
            includes.append(f'#include "{self.include_prefix}namespace_uri.h"')
        # ``DataTypeId`` enum: structure / union headers initialise
        # ``typeId`` from ``DataTypeId::<Type>`` (the named identifier)
        # rather than a bare numeric literal.  Unlike ``ObjectId`` (which NS0
        # reaches transitively via ``ua_node_id.h``), ``DataTypeId`` is *not*
        # pulled in by ``ua_node_id.h``, so it must be included explicitly for
        # every spec - NS0 included.  Gated on the token actually appearing in
        # the template so only structure / union headers pay for it.
        if "DataTypeId" in template_text:
            includes.append(f'#include "{self.include_prefix}datatype_id.h"')
        if self.cpp_namespace != "ua":
            includes.append(f'#include "{self.include_prefix}aliases.h"')
            # Structure / union headers (which set ``typeNamespaceUri =
            # specNamespaceUri``) declare encoding ids via the spec's ``ObjectId``
            # enum.  A companion spec must include ITS OWN ``<prefix>object_id.h``
            # so bare ``ObjectId`` binds to e.g. ``ua::di::ObjectId`` (which has
            # the type's encoding members) rather than the enclosing
            # ``ua::ObjectId`` (NS0), which does not.  NS0 reaches ``ua::ObjectId``
            # transitively via ``ua_node_id.h`` and needs no extra include.
            if "specNamespaceUri" in template_text:
                includes.append(f'#include "{self.include_prefix}object_id.h"')
        return "\n".join(includes)

    # ---- Factory -----------------------------------------------------

    @staticmethod
    def build(
        config: NodesetConfig,
        index: NodeSetIndex,
        output_root: Path,
    ) -> "EmitContext":
        """Construct a context for the given emit-target spec."""
        resolver = TypeResolver(index, current_config=config)
        return EmitContext(
            config=config,
            index=index,
            resolver=resolver,
            output_root=output_root,
        )
