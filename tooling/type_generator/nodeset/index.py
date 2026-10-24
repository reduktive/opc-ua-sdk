# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .model import UaDataTypeNodeWithDefinition
from .parse import parse_namespace_uris, parse_ua_data_type_nodes_with_definitions

if TYPE_CHECKING:
    from ..manifest import NodesetConfig


def browse_name_suffix(browse_name: str) -> str:
    # BrowseName attribute often looks like `0:Structure`.
    pos = browse_name.find(":")
    if pos == -1:
        return browse_name
    return browse_name[pos + 1:]


@dataclass(frozen=True, slots=True)
class NodeSetIndex:
    data_types: dict[str, UaDataTypeNodeWithDefinition]
    namespace_uris_by_nodeset: dict[str, list[str]]
    # Source-path -> NodesetConfig lookup, populated when the index is
    # built from a manifest.  Emitters use this to decide whether a
    # referenced type is in-spec (generate locally) or cross-spec (emit
    # a #include into the owning spec's prefix).  Empty when the index
    # was built without manifest annotation.
    config_by_source: dict[str, "NodesetConfig"] = field(default_factory=dict)
    # URI -> canonical namespace index, set by ``canonicalize_namespaces``.
    # Lets callers that re-parse raw per-file NodeIds (e.g. emit ordering)
    # convert them to the same canonical keys used in ``data_types``.
    uri_to_canonical: dict[str, int] = field(default_factory=dict)

    @staticmethod
    def empty() -> "NodeSetIndex":
        return NodeSetIndex(
            data_types={},
            namespace_uris_by_nodeset={},
            config_by_source={},
        )

    @staticmethod
    def from_nodesets(
        nodeset_paths: list[str],
        uri_to_canonical: dict[str, int] | None = None,
    ) -> "NodeSetIndex":
        """Parse and merge every nodeset. When ``uri_to_canonical`` is supplied,
        each file's NodeIds are canonicalised to URI-keyed namespaces *before*
        merging - required for multi-spec stacks where two specs both define
        types under their local ``ns=1`` (which would otherwise collide in the
        shared dict)."""
        data_types: dict[str, UaDataTypeNodeWithDefinition] = {}
        namespace_uris: dict[str, list[str]] = {}
        for path in nodeset_paths:
            local_uris = parse_namespace_uris(path)
            namespace_uris.setdefault(path, local_uris)
            for node in parse_ua_data_type_nodes_with_definitions(path):
                if uri_to_canonical:
                    node = _canonicalize_node(node, local_uris, uri_to_canonical)
                if node.node_id:
                    data_types[node.node_id] = node
        return NodeSetIndex(
            data_types=data_types,
            namespace_uris_by_nodeset=namespace_uris,
            uri_to_canonical=dict(uri_to_canonical) if uri_to_canonical else {},
        )

    def merged(self, nodes: list[UaDataTypeNodeWithDefinition]) -> "NodeSetIndex":
        merged = dict(self.data_types)
        for n in nodes:
            if not n.node_id:
                continue
            merged[n.node_id] = n
        return NodeSetIndex(
            data_types=merged,
            namespace_uris_by_nodeset=dict(self.namespace_uris_by_nodeset),
            config_by_source=dict(self.config_by_source),
            uri_to_canonical=dict(self.uri_to_canonical),
        )

    def with_config_by_source(
        self, config_by_source: dict[str, "NodesetConfig"]
    ) -> "NodeSetIndex":
        return NodeSetIndex(
            data_types=dict(self.data_types),
            namespace_uris_by_nodeset=dict(self.namespace_uris_by_nodeset),
            config_by_source=dict(config_by_source),
            uri_to_canonical=dict(self.uri_to_canonical),
        )

    def canonical_node_id(self, raw_node_id: str, source_path: str) -> str:
        """Convert a raw per-file NodeId (as parsed from ``source_path``) to the
        canonical, URI-keyed form used as the ``data_types`` key. A no-op when
        the index has not been canonicalised."""
        if not self.uri_to_canonical:
            return raw_node_id
        from .normalize import remap_node_id_ns

        local_uris = self.namespace_uris_by_nodeset.get(source_path, [])
        return remap_node_id_ns(raw_node_id, local_uris, self.uri_to_canonical)

    def config_for_source(self, source_path: str) -> "NodesetConfig | None":
        """Return the ``NodesetConfig`` that owns ``source_path``.

        Returns ``None`` when the index wasn't built from a manifest or when
        the path isn't recognised.
        """
        return self.config_by_source.get(source_path)

    def config_for_node(
        self, node: UaDataTypeNodeWithDefinition
    ) -> "NodesetConfig | None":
        """Return the ``NodesetConfig`` that owns ``node`` (via source path)."""
        if not node.source_nodeset:
            return None
        return self.config_by_source.get(node.source_nodeset)

    def find(self, node_id: str) -> UaDataTypeNodeWithDefinition | None:
        return self.data_types.get(node_id)

    def find_by_browse_name_suffix(self, suffix: str) -> UaDataTypeNodeWithDefinition | None:
        for node in self.data_types.values():
            if browse_name_suffix(node.browse_name) == suffix:
                return node
        return None

    def is_subtype_of(self, node_id: str, ancestor_browse_name_suffix: str) -> bool:
        ancestor = self.find_by_browse_name_suffix(ancestor_browse_name_suffix)
        if ancestor is None:
            return False

        visited: set[str] = set()
        current = node_id
        while current and current not in visited:
            visited.add(current)
            if current == ancestor.node_id:
                return True

            node = self.find(current)
            if node is None:
                return False
            current = node.parent_node_id or ""

        return False


def _canonicalize_node(
    node: UaDataTypeNodeWithDefinition,
    local_uris: list[str],
    uri_to_canonical: dict[str, int],
) -> UaDataTypeNodeWithDefinition:
    """Return a copy of ``node`` with its NodeId, parent and field data-types
    remapped from the source file's local namespace indices to canonical,
    URI-keyed indices. See ``NodeSetIndex.from_nodesets``."""
    from .normalize import remap_node_id_ns

    def remap(nid: str | None) -> str | None:
        if not nid:
            return nid
        return remap_node_id_ns(nid, local_uris, uri_to_canonical)

    updates: dict = {
        "node_id": remap(node.node_id),
        "parent_node_id": remap(node.parent_node_id),
    }
    if node.definition is not None:
        new_fields = [
            f.model_copy(update={"data_type": remap(f.data_type)})
            for f in node.definition.fields
        ]
        updates["definition"] = node.definition.model_copy(update={"fields": new_fields})
    return node.model_copy(update=updates)
