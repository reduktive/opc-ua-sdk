# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from dataclasses import dataclass

from .model import UaTypeDefinitionNode
from .parse import parse_type_definitions


def _browse_name_suffix(browse_name: str) -> str:
    pos = browse_name.find(":")
    if pos == -1:
        return browse_name
    return browse_name[pos + 1:]


@dataclass(frozen=True, slots=True)
class InstanceTypeIndex:
    """Index of parsed object/variable types with resolved child declarations."""

    type_nodes: dict[str, UaTypeDefinitionNode]

    @staticmethod
    def empty() -> InstanceTypeIndex:
        return InstanceTypeIndex(type_nodes={})

    @staticmethod
    def from_nodesets(nodeset_paths: list[str]) -> InstanceTypeIndex:
        all_nodes: dict[str, UaTypeDefinitionNode] = {}
        for path in nodeset_paths:
            for node in parse_type_definitions(path):
                if node.node_id:
                    all_nodes[node.node_id] = node
        return InstanceTypeIndex(type_nodes=all_nodes)

    def find(self, node_id: str) -> UaTypeDefinitionNode | None:
        return self.type_nodes.get(node_id)

    def find_by_browse_name(self, name: str) -> UaTypeDefinitionNode | None:
        for node in self.type_nodes.values():
            if _browse_name_suffix(node.browse_name) == name:
                return node
        return None

    def has_subtypes(self, node_id: str) -> bool:
        """Check if any type in the index is a direct or indirect subtype."""
        for node in self.type_nodes.values():
            if node.parent_type_id == node_id:
                return True
        return False

    def is_subtype_of(self, node_id: str, ancestor_id: str) -> bool:
        visited: set[str] = set()
        current = node_id
        while current and current not in visited:
            visited.add(current)
            if current == ancestor_id:
                return True
            node = self.find(current)
            if node is None:
                return False
            current = node.parent_type_id or ""
        return False
