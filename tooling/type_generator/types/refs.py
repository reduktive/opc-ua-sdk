# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Type-reference resolution across single- and multi-spec emission.

Every emitter that touches a type reference (parent class, field type,
method argument, ...) needs the same two facts: which header to
``#include`` for the target type, and the fully qualified C++ name to
write at the reference site.  For *in-spec* references the answers come
from the current emission context (``ua_<snake>.h``, bare class name);
for *cross-spec* references they come from the owning spec's metadata
(``ua_di_<snake>.h``, ``::ua::di::<ClassName>``).

The two cases differ in derivation, not in shape.  ``TypeRef`` is a
single value type carrying both facts; ``TypeResolver.resolve()`` always
returns one.  Emitters never branch on "is this external?" - they read
``ref.header_include`` and ``ref.qualified_class_name`` regardless.

This is the second iteration of what was originally ``ExternalRef`` /
``ExternalRefResolver`` in ``nodeset/external_refs.py`` (now removed):
that earlier shape returned ``None`` for in-spec refs and forced every
caller to branch around the optional, which encouraged the "hack"
patterns we're refactoring out.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..manifest import NodesetConfig
from ..naming import get_symbolic_name, to_snake_case
from ..nodeset.index import NodeSetIndex


@dataclass(frozen=True, slots=True)
class TypeRef:
    """A resolved reference to a type - uniformly in-spec or cross-spec."""

    # The header an emitter writes into ``#include "..."``.
    header_include: str

    # The fully qualified C++ name to use at the reference site.  For
    # in-spec references this is the bare class name (``Structure``);
    # for cross-spec references it is leading-``::`` qualified
    # (``::ua::Structure``).  The leading ``::`` short-circuits ADL so
    # an emitting spec like ``ua::di`` cannot accidentally resolve to a
    # nonexistent ``ua::di::Structure``.
    qualified_class_name: str

    # The unqualified class name (``Structure``).  Useful when the
    # template position requires a bare identifier (e.g. ``typeName``).
    short_name: str

    # ``True`` when the owning spec is the current emission target.
    # Most emitters don't need this - they just write ``header_include``
    # + ``qualified_class_name`` - but a few (e.g. registration) want to
    # filter out cross-spec types they shouldn't register locally.
    is_in_spec: bool


class TypeResolver:
    """Resolves any node-id reference to a ``TypeRef``.

    Constructed once per ``EmitContext`` with that context's owning
    ``NodesetConfig`` (the *current* spec).  Returns:

    * **in-spec** ``TypeRef`` when the referenced node is owned by the
      current spec, by an entry without manifest-derived ownership
      (single-spec legacy path), or by no entry at all - uses the
      current ctx's prefix/namespace to compute the header path and
      writes the class name bare.
    * **external** ``TypeRef`` when the referenced node is owned by a
      different spec - uses the owner's prefix/namespace.

    ``current_config`` may be ``None`` only when the resolver is being
    used outside any emission context (e.g. introspection tools).  In
    that case a node with a *known* owner resolves to an external,
    fully-qualified ref against that owner's namespace (there is no
    "current" spec for it to be in-spec relative to); a node with *no*
    owner still falls back to the legacy bare ``ua_`` / ``ua`` in-spec
    form.
    """

    def __init__(self, index: NodeSetIndex, current_config: NodesetConfig | None):
        self._index = index
        self._current = current_config

    def resolve(self, node_id: str) -> TypeRef:
        node = self._index.find(node_id)
        if node is None:
            # Unknown node - surface a fallback that won't compile but
            # is loud about what went wrong.  Realistically only hit by
            # malformed nodesets; the emitter is expected to validate
            # upstream.
            return TypeRef(
                header_include="ua_unknown.h",
                qualified_class_name=f"/*unresolved: {node_id}*/",
                short_name=node_id,
                is_in_spec=True,
            )

        owner = self._index.config_for_node(node)
        class_name = get_symbolic_name(node.browse_name)

        if _owns(self._current, owner):
            return _in_spec_ref(self._current, class_name)

        # Cross-spec: there's a known external owner, so its config
        # carries the prefix/namespace we need.  ``owner`` is non-None
        # in this branch (``_owns`` returned False).
        assert owner is not None
        return TypeRef(
            header_include=_header_for(owner, class_name),
            qualified_class_name=f"::{owner.cpp_namespace}::{class_name}",
            short_name=class_name,
            is_in_spec=False,
        )


# --- helpers ---------------------------------------------------------------


def _in_spec_ref(current: NodesetConfig | None, class_name: str) -> TypeRef:
    return TypeRef(
        header_include=_header_for(current, class_name),
        qualified_class_name=class_name,
        short_name=class_name,
        is_in_spec=True,
    )


# NS0 variable-state snapshot types consolidated into one hand-written header
# (ua_variable_states.h); a reference to any of them must include that header
# rather than the per-type name to_snake_case would otherwise derive.
_CONSOLIDATED_HEADER_STEMS = {
    "FiniteStateVariableState": "variable_states",
    "ConditionVariableState": "variable_states",
    "TwoStateVariableState": "variable_states",
}


def _header_for(config: NodesetConfig | None, class_name: str) -> str:
    prefix = config.include_prefix if config is not None else "ua_"
    stem = _CONSOLIDATED_HEADER_STEMS.get(class_name, to_snake_case(class_name))
    return f"{prefix}{stem}.h"


def _owns(current: NodesetConfig | None, owner: NodesetConfig | None) -> bool:
    """True when ``owner`` is the spec we're currently emitting for.

    ``owner is None`` (no manifest annotation for the node's source)
    counts as in-spec - preserves the legacy single-spec behaviour where
    every node lacks a NodesetConfig.
    """
    if owner is None:
        return True
    if current is None:
        return False
    return current is owner or current.uri == owner.uri
