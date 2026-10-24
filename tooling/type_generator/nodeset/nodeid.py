# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

import re

_NUMERIC_NODE_ID_RE = re.compile(r"^(?:ns=(?P<ns>\d+);)?i=(?P<i>\d+)$")


class NumericNodeId:
    __slots__ = ("namespace_index", "identifier")

    def __init__(self, namespace_index: int, identifier: int):
        self.namespace_index = namespace_index
        self.identifier = identifier


def parse_numeric_node_id(node_id_text: str) -> NumericNodeId | None:
    """Parse a numeric NodeId from normalized text.

    Accepts:
    - `i=123`
    - `ns=2;i=123`
    """

    text = node_id_text.strip()
    m = _NUMERIC_NODE_ID_RE.match(text)
    if not m:
        return None
    ns = int(m.group("ns")) if m.group("ns") is not None else 0
    ident = int(m.group("i"))
    return NumericNodeId(namespace_index=ns, identifier=ident)
