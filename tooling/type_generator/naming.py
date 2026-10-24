# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

import re


def get_symbolic_name(browse_name: str) -> str:
    """Return the C++-identifier-friendly symbolic type name.

    Mirrors the C++ generator behavior:
    - remove namespace prefix from BrowseName if present (`0:Structure` -> `Structure`)
    - if the name starts with `3`, replace with `Three` prefix (`3DFrame` -> `ThreeDFrame`)
    """

    name = browse_name
    pos = name.find(":")
    if pos != -1:
        name = name[pos + 1:]

    if name.startswith("3"):
        name = "Three" + name[1:]
    return name


def _is_valid_cpp_identifier(name: str) -> bool:
    """True if ``name`` is already a legal C++ identifier."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


def _sanitise_identifier(name: str) -> str:
    """Coerce ``name`` into a valid C++ identifier.

    Replaces any run of characters outside ``[A-Za-z0-9_]`` with a single
    ``_`` and prefixes a leading digit with ``_``.
    """
    out = re.sub(r"[^A-Za-z0-9_]+", "_", name)
    if out and out[0].isdigit():
        out = "_" + out
    return out


def cpp_identifier(name: str, symbolic_name: str | None = None) -> str:
    """Return the C++ identifier for a NodeSet name.

    Per OPC 10000-6 Annex F (Tables F.2/F.12/F.13), ``SymbolicName`` is the
    identifier intended for use "as a class/field name in auto generated code";
    it "should only be specified if the BrowseName cannot be used for this
    purpose" and is constrained to legal identifier characters (letters, digits,
    underscore; leading letter). The consumer-side reading the spec implies is:
    **use ``SymbolicName`` when present, fall back to the BrowseName / field
    ``Name`` otherwise** (sanitising it if it is not a legal identifier).

    NOTE: this produces the C++ *identifier* only. The on-wire / browse-name
    *string* must keep the original spec name and must NOT be routed through
    here.
    """

    if symbolic_name:
        # SymbolicName is the spec-designated code-gen identifier. It is
        # guaranteed legal by the schema; sanitise defensively all the same.
        if _is_valid_cpp_identifier(symbolic_name):
            return symbolic_name
        return _sanitise_identifier(symbolic_name)

    base = get_symbolic_name(name)
    if _is_valid_cpp_identifier(base):
        return base
    return _sanitise_identifier(base)


def to_snake_case(name: str) -> str:
    """Convert to snake_case.

    This is a direct port of the C++ generator's `to_snake_case()` implementation
    from `tooling/data_type_generator/naming.cpp`.
    """

    r = re.compile(r"([A-Z](?=[A-Z][a-z]))|([^A-Z](?=[A-Z]))")
    result = r.sub(r"\g<0>_", name).lower()
    # Collapse runs of underscores (a browse name that already contains '_', e.g. "PriorityValue_PCP",
    # would otherwise yield "priority_value__pcp") and trim edges. A double underscore anywhere in an
    # identifier is RESERVED to the implementation by the C++ standard (bugprone-reserved-identifier).
    return re.sub(r"_+", "_", result).strip("_")


_CPP_KEYWORDS = frozenset("""alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t
char16_t char32_t class compl concept const consteval constexpr constinit const_cast continue co_await
co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern false
float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr operator or
or_eq private protected public register reinterpret_cast requires return short signed sizeof static
static_assert static_cast struct switch template this thread_local throw true try typedef typeid
typename union unsigned using virtual void volatile wchar_t while xor xor_eq""".split())


def to_camel_back(name: str) -> str:
    """The camelBack form of a NodeSet name, for a public field (cpp_style.md section Naming).

    Built from the snake_case form so acronyms read as words: ``EventId`` -> ``eventId``,
    ``EURange`` -> ``euRange``, ``PriorityValue_PCP`` -> ``priorityValuePcp``. A result that is a C++
    keyword takes the suffix ``Value`` (``Namespace`` -> ``namespaceValue``).
    """

    parts = [p for p in to_snake_case(name).split("_") if p]
    if not parts:
        return name
    out = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
    return out + "Value" if out in _CPP_KEYWORDS else out


def clean_brief_text(text: str) -> str:
    """Normalise spec text into a one-line Doxygen brief.

    Collapses internal whitespace, capitalises the first letter, and ensures the
    text ends with sentence-final punctuation. Used to turn a NodeSet
    ``<Description>`` into a house-style brief. Returns ``""`` for empty input.
    """

    cleaned = " ".join((text or "").split())
    if not cleaned:
        return ""
    cleaned = cleaned[0].upper() + cleaned[1:]
    if cleaned[-1] not in ".!?":
        cleaned += "."
    return cleaned


def to_screaming_snake_case(name: str) -> str:
    return to_snake_case(name).upper()
