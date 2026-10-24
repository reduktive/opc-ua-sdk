# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Per-spec emission orchestration.

``SpecRunner`` owns one ``EmitContext`` and drives every emitter
through one full pass for a single ``emit=true`` nodeset.  Top-level
flow:

1. Compute the canonical type ordering (mirrors C++ generator's
   first-seen NodeId order across sources).
2. Build the ``DataType``/``InstanceType``/``EventType`` analysis
   models from the index.
3. For each model kind, invoke the per-category emitter (already
   bound to ``ctx``).
4. Run the aggregate emitters (sharded ``<prefix>data_types_<k>.cpp`` bodies,
   ``<prefix>data_type_registration.{h,cpp}``, helpers, CMakeLists).
5. Run the NS0-only emitters (status / attributes / NS0 byte array /
   data-type tests) when ``ctx.config.uri`` is NS0.

The output of ``run()`` is the list of paths produced.  Multi-spec
runs (Phase 5+) iterate ``SpecRunner`` per ``emit=true`` config; each
sees its own ``EmitContext``.
"""

from __future__ import annotations

from pathlib import Path

from ..formatting import clang_format_directory
from ..manifest import NS0_URI
from ..naming import get_symbolic_name
from ..nodeset.parse import list_ua_data_types
from ..types.build import (
    all_category_names,
    build_all_instance_types,
    build_event_types,
    build_instance_types,
    build_types,
    is_built_in,
    is_excluded,
    is_json_pubsub_message,
)
from ..types.model import DataTypeKind, InstanceTypeKind
from .context import EmitContext
from .emit_attributes import AttributeIdEmitter
from .emit_cmake import CMakeListsEmitter
from .emit_enums import EnumEmitter, OptionSetEmitter
from .emit_event_type import EventTypeEmitter, emit_event_type_tests
from .emit_identifiers import IdentifierEmitter
from .emit_instance_tests import InstanceTypeTestsEmitter
from .emit_ns0_byte_array import Ns0ByteArrayEmitter
from .emit_ns0_model_tables import Ns0ModelTablesEmitter
from .emit_object_type import ObjectTypeEmitter
from .emit_registration import RegistrationEmitter
from .emit_simple import SimpleAliasEmitter
from .emit_spec_headers import SpecHeadersEmitter
from .emit_status import StatusCodeEmitter
from .emit_structures import StructureEmitter
from .emit_tests import DataTypeTestsEmitter
from .emit_ua_data_types_cpp import AggregateSourceEmitter
from .emit_unions import UnionEmitter
from .emit_variable_type import VariableTypeEmitter


class SpecRunner:
    """Drives one full emission pass for a single emit-target spec.

    Per-spec emission policy (which categories to emit, explicit
    instance-type lists, event-type opt-in) comes from ``ctx.config``
    fields populated by the manifest.  CSV paths (NodeIds.csv,
    StatusCode.csv, AttributeIds.csv, NS0 byte-array source) come from
    the constructor - these are derived per-run from the manifest's
    NS0 entry resolved against the manifest file's directory.
    """

    def __init__(
        self,
        ctx: EmitContext,
        *,
        nodeset_paths: list[str],
        nodeids_csv: str | None,
        statuscode_csv: str | None,
        attribute_ids_csv: str | None,
        nodeset_ns0_xml: str | None,
    ):
        self._ctx = ctx
        self._nodeset_paths = nodeset_paths
        self._nodeids_csv = nodeids_csv
        self._statuscode_csv = statuscode_csv
        self._attribute_ids_csv = attribute_ids_csv
        self._nodeset_ns0_xml = nodeset_ns0_xml

    @property
    def is_ns0(self) -> bool:
        return self._ctx.config.uri == NS0_URI

    def _owns_type_node(self, instance_index, node_id: str) -> bool:
        """True if the object/variable/event type ``node_id`` is owned by the
        spec currently being emitted.

        Resolution walks the full index (every nodeset in scope), but emission
        is per-spec: a companion spec must not re-emit NS0's instance handles.
        Untracked nodes (no ``source_nodeset``) are kept so the NS0 self-host
        run stays byte-identical.
        """
        node = instance_index.find(node_id)
        source = node.source_nodeset if node is not None else None
        if not source:
            return True
        owner = self._ctx.index.config_for_source(source)
        return owner is None or owner.uri == self._ctx.config.uri

    @property
    def _emits_instance_types(self) -> bool:
        cfg = self._ctx.config
        return bool(cfg.instance_type_categories) or bool(cfg.instance_type_browse_names)

    @property
    def _emits_event_types(self) -> bool:
        return self._ctx.config.emit_event_types

    def run(self) -> list[Path]:
        """Emit every artifact in scope for this spec and return their paths."""
        self._flat_categories: list[str] = []
        outputs: list[Path] = []
        outputs.extend(self._emit_data_types())
        if self._emits_instance_types:
            outputs.extend(self._emit_instance_types())
        if self._emits_event_types:
            outputs.extend(self._emit_event_types())
        # Always attempt id headers (even with no CSV): the type/struct emitters
        # #include them unconditionally; _emit_identifiers derives from NodeSet nodes
        # when the CSV is absent/incomplete and no-ops when nothing is emittable.
        outputs.extend(self._emit_identifiers())
        if self._statuscode_csv:
            outputs.extend(self._emit_status())
        if self._nodeset_ns0_xml and self.is_ns0:
            outputs.extend(self._emit_ns0_byte_array())
            outputs.extend(self._emit_ns0_model_tables())
        # Consumer (flat) tree: a root CMakeLists ties the category subdirs
        # together so the whole tree is one ``add_subdirectory`` away.
        if self._ctx.flat_layout and self._flat_categories:
            outputs.append(
                CMakeListsEmitter(self._ctx).emit_flat_root(self._flat_categories)
            )
        return outputs

    def _note_flat_category(self, category: str) -> None:
        """Record a category that produced a flat-layout CMakeLists (for the root)."""
        if self._ctx.flat_layout and category not in self._flat_categories:
            self._flat_categories.append(category)

    # ---- Data types ----------------------------------------------------

    def _emit_data_types(self) -> list[Path]:
        ctx = self._ctx

        # Per-spec metadata headers (``<prefix>namespace.h`` +
        # ``<prefix>aliases.h``) emitted first so every type header's
        # ``#include`` resolves cleanly.
        spec_headers_emitter = SpecHeadersEmitter(ctx)

        enum_emitter = EnumEmitter(ctx)
        optionset_emitter = OptionSetEmitter(ctx)
        union_emitter = UnionEmitter(ctx)
        structure_emitter = StructureEmitter(ctx)
        simple_emitter = SimpleAliasEmitter(ctx)
        aggregate_emitter = AggregateSourceEmitter(ctx)
        registration_emitter = RegistrationEmitter(ctx)
        cmake_emitter = CMakeListsEmitter(ctx)
        tests_emitter = DataTypeTestsEmitter(ctx)

        binary_encoding_type_names = self._read_binary_encoding_type_names()
        types = build_types(ctx.index, ordered_node_ids=self._ordered_data_type_ids())

        # Spec metadata headers - one-time per run.
        spec_outputs: list[Path] = [
            spec_headers_emitter.emit_namespace_header(),
            spec_headers_emitter.emit_aliases_header(),
        ]

        # Per-kind accumulators feeding the aggregate emitters.
        enum_ids: list[str] = []
        enum_headers: list[str] = []
        optionset_ids: list[str] = []
        optionset_headers: list[str] = []
        structure_ids: list[str] = []
        structure_headers: list[str] = []
        all_dt_ids: list[str] = []
        all_dt_headers: list[str] = []
        outputs: list[Path] = []

        for t in types:
            symbolic = get_symbolic_name(t.browse_name)
            if is_built_in(symbolic) or is_excluded(symbolic):
                continue

            dt_node = ctx.index.find(t.node_id)
            if dt_node is not None and dt_node.category and dt_node.category.startswith("PubSub"):
                # PubSub data types are not needed by the SDK core.
                continue
            if is_json_pubsub_message(symbolic):
                continue

            # Multi-spec: emit only types OWNED by this spec.  Types from other
            # nodesets in the index (e.g. NS0 when emitting a companion spec)
            # are referenced externally via the TypeResolver, not re-emitted
            # here.  For an NS0-only (self-host) run every node is owned by NS0,
            # so this is a no-op and the output stays byte-identical.
            if dt_node is not None:
                owner = ctx.index.config_for_node(dt_node)
                if owner is not None and owner.uri != ctx.config.uri:
                    continue

            if t.kind == DataTypeKind.enumeration:
                out = enum_emitter.emit_header(t.node_id)
                enum_ids.append(t.node_id)
                enum_headers.append(out.name)
            elif t.kind == DataTypeKind.option_set:
                out = optionset_emitter.emit_header(t.node_id)
                optionset_ids.append(t.node_id)
                optionset_headers.append(out.name)
            elif t.kind == DataTypeKind.union:
                out = union_emitter.emit(t.node_id)
                # Unions piggyback the structure aggregates.
                structure_ids.append(t.node_id)
                structure_headers.append(out.name)
            elif t.kind == DataTypeKind.structure:
                out = structure_emitter.emit(t.node_id, binary_encoding_type_names)
                structure_ids.append(t.node_id)
                structure_headers.append(out.name)
            elif t.kind == DataTypeKind.unknown:
                # Simple aliases require a parent type.
                if not t.parent_node_id:
                    continue
                out = simple_emitter.emit(t.node_id)
            else:
                continue

            outputs.append(out)
            all_dt_ids.append(t.node_id)
            all_dt_headers.append(out.name)

        # Structure / union sources: one amalgamated TU (NS0) or one per type
        # (consumer).  ``source_names`` feeds the CMake source list below.
        agg_paths, source_names = aggregate_emitter.emit(
            structure_node_ids_in_order=structure_ids,
            generated_headers=structure_headers,
            binary_encoding_type_names=binary_encoding_type_names,
        )
        outputs.extend(agg_paths)
        outputs.append(enum_emitter.emit_helpers_source(
            node_ids_in_order=enum_ids, headers_in_order=enum_headers,
        ))
        outputs.append(optionset_emitter.emit_helpers_source(
            node_ids_in_order=optionset_ids, headers_in_order=optionset_headers,
        ))
        outputs.append(registration_emitter.emit_header(
            structure_node_ids_in_order=structure_ids,
            binary_encoding_type_names=binary_encoding_type_names,
        ))
        outputs.append(registration_emitter.emit_source(
            structure_node_ids_in_order=structure_ids,
            structure_headers_in_order=structure_headers,
            binary_encoding_type_names=binary_encoding_type_names,
        ))
        if self.is_ns0:
            outputs.append(tests_emitter.emit(
                data_type_node_ids_in_order=all_dt_ids,
                data_type_headers_in_order=all_dt_headers,
                binary_encoding_type_names=binary_encoding_type_names,
            ))
        # Spec headers join the public-header list so CMakeLists picks
        # them up and downstream consumers can include them.
        all_dt_headers = (
            [spec_outputs[0].name, spec_outputs[1].name] + all_dt_headers
        )
        outputs.extend(spec_outputs)
        # Private source list: the data-type bodies (amalgamated or per-type)
        # plus the always-single registration + helper translation units.
        impl_sources = list(source_names) + [
            f"{ctx.include_prefix}data_type_registration.cpp",
            f"{ctx.include_prefix}enum_helpers.cpp",
            f"{ctx.include_prefix}optionset_helpers.cpp",
        ]
        outputs.extend(cmake_emitter.emit_data_types(all_dt_headers, impl_sources))
        self._note_flat_category("data_types")

        if outputs:
            clang_format_directory(ctx.interface_dir)
            clang_format_directory(ctx.implementation_dir)
        return outputs

    # ---- Instance types ------------------------------------------------

    def _emit_instance_types(self) -> list[Path]:
        ctx = self._ctx
        from ..nodeset.instance_index import InstanceTypeIndex

        cfg = ctx.config
        instance_index = InstanceTypeIndex.from_nodesets(self._nodeset_paths)

        # Auto-discovered types (by category) come first, then explicit
        # BrowseNames augment the set.  Both sources are merged by the
        # build helpers so duplicates are collapsed.
        categories = set(cfg.instance_type_categories)
        if categories:
            included = all_category_names() if "all" in categories else categories
            auto_types = build_all_instance_types(instance_index, included, ctx)
        else:
            auto_types = []

        if cfg.instance_type_browse_names:
            explicit_types = build_instance_types(instance_index, cfg.instance_type_browse_names, ctx)
            seen = {it.browse_name for it in auto_types}
            instance_types = auto_types + [
                it for it in explicit_types if it.browse_name not in seen
            ]
        else:
            instance_types = auto_types

        # Multi-spec: keep only types OWNED by this spec.  The full index
        # (NS0 + companion specs) is still used above so subtype/category
        # resolution sees the complete hierarchy; we just don't re-emit the
        # other specs' handles here.  NS0 self-host keeps every type (all
        # owned by NS0) -> byte-identical output.
        instance_types = [
            it for it in instance_types if self._owns_type_node(instance_index, it.node_id)
        ]

        object_type_emitter = ObjectTypeEmitter(ctx)
        variable_type_emitter = VariableTypeEmitter(ctx)
        cmake_emitter = CMakeListsEmitter(ctx)

        object_headers: list[str] = []
        object_sources: list[str] = []
        variable_headers: list[str] = []
        variable_sources: list[str] = []
        outputs: list[Path] = []

        for it in instance_types:
            if it.kind == InstanceTypeKind.object_type:
                h = object_type_emitter.emit_header(it)
                s = object_type_emitter.emit_source(it)
                object_headers.append(h.name)
                object_sources.append(s.name)
                outputs.extend([h, s])
            elif it.kind == InstanceTypeKind.variable_type:
                h = variable_type_emitter.emit_header(it)
                s = variable_type_emitter.emit_source(it)
                variable_headers.append(h.name)
                variable_sources.append(s.name)
                outputs.extend([h, s])

        # Split (NS0): CMakeLists are always emitted so stale entries get
        # cleared when an instance type is removed.  Flat (consumer) trees are
        # regenerated fresh, so a category with no types is simply omitted (no
        # empty dir / dangling root entry).
        if object_headers or not ctx.flat_layout:
            cmake_emitter.emit_object_types(object_headers, object_sources)
        if variable_headers or not ctx.flat_layout:
            cmake_emitter.emit_variable_types(variable_headers, variable_sources)

        if object_headers:
            clang_format_directory(ctx.interface_dir_for("object_types"))
            clang_format_directory(ctx.implementation_dir_for("object_types"))
            self._note_flat_category("object_types")
        if variable_headers:
            clang_format_directory(ctx.interface_dir_for("variable_types"))
            clang_format_directory(ctx.implementation_dir_for("variable_types"))
            self._note_flat_category("variable_types")

        # Generated instance-type tests (NS0-only).
        if instance_types and self.is_ns0:
            tests_out = InstanceTypeTestsEmitter(ctx).emit(instance_types)
            clang_format_directory(tests_out.parent)
            outputs.append(tests_out)

        # Stash the index for the event-type pass.
        self._instance_index = instance_index
        return outputs

    # ---- Event types ---------------------------------------------------

    def _emit_event_types(self) -> list[Path]:
        ctx = self._ctx
        event_types = [
            et for et in build_event_types(self._instance_index, ctx)
            if self._owns_type_node(self._instance_index, et.node_id)
        ]
        event_emitter = EventTypeEmitter(ctx)
        cmake_emitter = CMakeListsEmitter(ctx)

        outputs: list[Path] = []
        event_headers: list[str] = []
        for et in event_types:
            h = event_emitter.emit_header(et)
            event_headers.append(h.name)
            outputs.append(h)

        # Subtype matching is done at runtime via the C++ class hierarchy
        # (``BaseEvent::is_of_type`` + per-type generated overrides), so no baked
        # ``is_standard_event_subtype`` hierarchy table is emitted. This works
        # uniformly for NS0 and companion (incl. multi-level) event types - a
        # companion event payload's override chains to its C++ base (which may be
        # an NS0 payload), and the runtime resolves its spec URI to a namespace
        # index - which a single-``ObjectTypeId``-enum table could not express.
        event_sources: list[str] = []
        if event_types:
            src_paths, event_sources = event_emitter.emit_sources(event_types, event_headers)
            outputs.extend(src_paths)

        if event_headers or not ctx.flat_layout:
            cmake_emitter.emit_event_types(event_headers, event_sources)

        if event_headers:
            clang_format_directory(ctx.interface_dir_for("event_types"))
            clang_format_directory(ctx.implementation_dir_for("event_types"))
            self._note_flat_category("event_types")

        if event_types and self.is_ns0:
            emit_event_type_tests(ctx.implementation_dir_for("event_types"), event_types)
            clang_format_directory(ctx.implementation_dir_for("event_types"))
        return outputs

    # ---- Identifiers, status, NS0 byte array --------------------------

    def _emit_identifiers(self) -> list[Path]:
        ctx = self._ctx
        cmake_emitter = CMakeListsEmitter(ctx)

        # Reuse the instance index if instance types were emitted; otherwise build it
        # so CSV-less / CSV-incomplete specs can still derive ObjectType/VariableType
        # id headers from their own NodeSet nodes.
        instance_index = getattr(self, "_instance_index", None)
        if instance_index is None:
            from ..nodeset.instance_index import InstanceTypeIndex
            instance_index = InstanceTypeIndex.from_nodesets(self._nodeset_paths)

        nodeids = Path(self._nodeids_csv) if self._nodeids_csv else None
        id_files = IdentifierEmitter(ctx).emit(nodeids, instance_index)
        if self._attribute_ids_csv:
            id_files.append(AttributeIdEmitter(ctx).emit(Path(self._attribute_ids_csv)))

        if not id_files:
            return []

        cmake_emitter.emit_ids([p.name for p in id_files])
        clang_format_directory(ctx.interface_dir_for("ids"))
        self._note_flat_category("ids")
        return list(id_files)

    def _emit_status(self) -> list[Path]:
        ctx = self._ctx
        emitter = StatusCodeEmitter(ctx)
        cmake_emitter = CMakeListsEmitter(ctx)

        outputs = [
            emitter.emit_header(Path(self._statuscode_csv)),
            emitter.emit_to_string_header(Path(self._statuscode_csv)),
            emitter.emit_to_string_source(Path(self._statuscode_csv)),
        ]
        cmake_emitter.emit_interface_status()
        cmake_emitter.emit_implementation_status()
        clang_format_directory(ctx.interface_dir_for("status"))
        clang_format_directory(ctx.implementation_dir_for("status"))
        return outputs

    def _emit_ns0_byte_array(self) -> list[Path]:
        ctx = self._ctx
        h, s = Ns0ByteArrayEmitter(ctx).emit(Path(self._nodeset_ns0_xml))
        cmake_emitter = CMakeListsEmitter(ctx)
        cmake_emitter.emit_interface_ns0()
        cmake_emitter.emit_implementation_ns0()
        return [h, s]

    def _emit_ns0_model_tables(self) -> list[Path]:
        # From the same NodeSet file as the byte array: the tables describe the namespace 0 the server loads.
        ctx = self._ctx
        source = Ns0ModelTablesEmitter(ctx).emit(Path(self._nodeset_ns0_xml))
        CMakeListsEmitter(ctx).emit_implementation_ns0_model()
        clang_format_directory(ctx.implementation_dir_for("ns0_model"))
        return [source]

    # ---- Helpers -------------------------------------------------------

    def _ordered_data_type_ids(self) -> list[str]:
        """First-seen NodeId ordering across the manifest's nodesets.

        Mirrors the C++ generator's deterministic ordering so emit-time
        diffs reflect input changes only.
        """
        ordered: list[str] = []
        seen: set[str] = set()
        for path in self._nodeset_paths:
            for node_id, _ in list_ua_data_types(path):
                if not node_id:
                    continue
                # Convert the raw per-file NodeId to the index's canonical key so
                # multi-spec cross-references resolve (no-op when not canonicalised).
                node_id = self._ctx.index.canonical_node_id(node_id, path)
                if node_id in seen:
                    continue
                seen.add(node_id)
                ordered.append(node_id)
        return ordered

    def _read_binary_encoding_type_names(self) -> set[str]:
        """Symbolic names of types that own a Default Binary encoding Object.

        Sourced from ``NodeIds.csv``; the structure emitters consult
        this to decide whether to emit codec machinery for a given
        concrete type (a type without an encoding object is not
        encodable and is emitted abstract-like).
        """
        result: set[str] = set()
        if not self._nodeids_csv:
            return result
        import csv

        from ..naming import get_symbolic_name
        from ..nodeset.nodeid import parse_numeric_node_id

        # The struct emitter keys encodability on get_symbolic_name(browse_name),
        # but an encoding object's CSV name uses the DataType's SymbolicName, which
        # can differ (e.g. GPOS "S3DGeographicCoordinateDataType" vs the canonical
        # "ThreeDGeographicCoordinateDataType"). Map CSV SymbolicName -> canonical
        # via the data_types index (joined by numeric id) so the encodable set
        # matches the emitted type names. NS0's CSV symbolic already equals the
        # canonical name, so its set - and omit_codec decisions - are unchanged.
        canonical_by_id: dict[int, str] = {}
        for node in self._ctx.index.data_types.values():
            numeric = parse_numeric_node_id(node.node_id)
            if numeric is not None:
                canonical_by_id[numeric.identifier] = get_symbolic_name(node.browse_name)

        suffix = "_Encoding_DefaultBinary"
        symbolic_to_canonical: dict[str, str] = {}
        encoding_prefixes: list[str] = []
        with open(self._nodeids_csv, encoding="utf-8", newline="") as f:
            for row in csv.reader(f):
                if len(row) < 3:
                    continue
                if row[2] == "DataType":
                    try:
                        nid = int(row[1].strip())
                    except ValueError:
                        continue
                    if nid in canonical_by_id:
                        symbolic_to_canonical[row[0].strip()] = canonical_by_id[nid]
                elif row[2] == "Object" and row[0].endswith(suffix):
                    encoding_prefixes.append(row[0][: -len(suffix)])

        for prefix in encoding_prefixes:
            result.add(symbolic_to_canonical.get(prefix, prefix))
        return result
