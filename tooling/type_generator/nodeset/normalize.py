# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

import re

_NODE_ID_WITH_NS_RE = re.compile(r"^ns=(?P<ns>\d+);(?P<body>[isgb]=.+)$")
_NODE_ID_NO_NS_RE = re.compile(r"^(?P<body>[isgb]=.+)$")


def normalize_node_id_text(node_id_text: str) -> str:
    """Normalize a NodeId string similar to C++ `normalize_node_id_text()`.

    Today this is intentionally minimal and only ensures that a missing namespace
    is treated as `ns=0`.

    Examples:
    - `i=45` -> `ns=0;i=45`
    - `ns=2;s=Foo` -> `ns=2;s=Foo`
    """

    text = node_id_text.strip()
    if not text:
        return text

    with_ns = _NODE_ID_WITH_NS_RE.match(text)
    if with_ns:
        # Match the C++ generator output: `ns=0;...` is printed as `i=...` / `s=...`.
        if with_ns.group("ns") == "0":
            return with_ns.group("body")
        return text

    no_ns = _NODE_ID_NO_NS_RE.match(text)
    if no_ns:
        # NodeId without namespace is implicitly `ns=0`.
        return no_ns.group("body")

    # Unknown format; keep as-is.
    return text


def remap_node_id_ns(
    node_id_text: str,
    local_uris: list[str],
    uri_to_canonical: dict[str, int],
) -> str:
    """Rewrite a NodeId's namespace index from a file's *local* index to a
    canonical, cross-file index keyed by namespace URI.

    Multi-spec stacks reference types across companion specs (e.g. a level-2
    spec field typed by a level-1 spec struct). Each NodeSet file numbers its
    namespaces locally (``ns=1`` means a different URI in different files), so a
    raw per-file NodeId is ambiguous - and two specs both define their own types
    under ``ns=1``, which collide in a shared index. Canonicalising every NodeId
    to a single URI-keyed namespace makes cross-file references resolve and
    avoids collisions.

    ``local_uris`` is the file's ``NamespaceUris`` table (index 1 -> first URI).
    Namespace index 0 is always NS0 (canonical 0). Canonical 0 is emitted in the
    bare ``i=N`` form (matching :func:`normalize_node_id_text`), so a single-spec
    or single-companion run is unchanged (a companion's only non-NS0 namespace is
    its own ``ns=1`` -> canonical 1)."""

    text = normalize_node_id_text(node_id_text)
    if not text:
        return text

    with_ns = _NODE_ID_WITH_NS_RE.match(text)
    if not with_ns:
        # Bare form -> ns=0 (NS0), canonical 0, already bare.
        return text

    local_ns = int(with_ns.group("ns"))
    body = with_ns.group("body")
    if local_ns == 0:
        return body

    if local_ns - 1 >= len(local_uris):
        # Out-of-range local index - leave as-is (malformed nodeset).
        return text
    uri = local_uris[local_ns - 1]
    canonical = uri_to_canonical.get(uri)
    if canonical is None:
        return text
    if canonical == 0:
        return body
    return f"ns={canonical};{body}"
