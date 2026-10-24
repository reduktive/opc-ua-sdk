# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Map a NodeSet ``<Category>`` to a coarse functional *family*.

Data-type registration is gated per family so a server links (and the linker keeps) only the
families its profile needs. The discriminator is the ``<Category>`` element already parsed onto
every type (``nodeset.model.UaDataTypeNode.category``).

Taxonomy: coarse functional (~8 families, user decision 2026-06-17). The categories are fine-grained
(~270 distinct), so they are collapsed by **prefix**. Unmatched or empty categories fall back to
``core`` - a type is never dropped out of every family. ``core`` is always registered; the others are
additive. Events have no clean category prefix, so they currently fall into ``core``.
"""

from __future__ import annotations

CORE = "core"

# Emission order for the per-family registrars and the aggregate's call order. ``core`` first
# (mandatory base), then the optional families.
FAMILIES: tuple[str, ...] = (
    "core",
    "alarms_conditions",
    "data_access",
    "auditing",
    "pubsub",
    "certificates",
    "network_mgmt",
    "diagnostics",
)

# First matching prefix wins, so order encodes precedence. Category strings are entity-decoded by the
# XML parser (``A & C``, not ``A &amp; C``); the ``&amp;`` form is kept defensively.
_FAMILY_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    ("A & C", "alarms_conditions"),
    ("A &amp; C", "alarms_conditions"),
    ("Data Access", "data_access"),
    ("Auditing", "auditing"),
    ("PubSub", "pubsub"),
    ("BNM", "network_mgmt"),  # Base Network Model - LLDP / TSN
    ("GDS", "certificates"),
    ("Push Model", "certificates"),
    ("Certificate", "certificates"),
    ("TrustList", "certificates"),
    ("LogObject", "diagnostics"),
    ("Diagnostic", "diagnostics"),
)


def family_for(category: str | None) -> str:
    """Return the family for a ``<Category>`` string; unmatched/empty -> ``core``."""
    if not category:
        return CORE
    for prefix, family in _FAMILY_PREFIX_RULES:
        if category.startswith(prefix):
            return family
    return CORE
