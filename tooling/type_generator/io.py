# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from pathlib import Path

# The licence header every generated file carries.
#
# It lives here rather than in the seventeen emit modules because all of them create files
# through write_file(), which makes this the one place a generated file comes into being.
# Generated sources cannot be given headers by a sweep over the tree: the
# generated-code-freshness gate regenerates and diffs, so anything the generator does not
# emit is reverted the next time it runs.
#
# The identifier is the one LICENSE names; conanfile.py, both vcpkg manifests and the release
# SBOM repeat the same string, and a release check holds them to it.
# Generated code carries the product licence wherever it is emitted, including into the
# example trees. It is output of the SDK's own type generator rather than example code a
# licensee is invited to copy, so the permissive grant in examples/LICENSE does not reach it.
# A release check enforces the same split.
LICENCE_IDENTIFIER = "LicenseRef-Reduktive-Source-Available-1.0"
COPYRIGHT_LINE = "Copyright (c) 2026 Reduktive Limited. All rights reserved."


# Typography that arrives in text the generator embeds -- OPC Foundation status-code
# descriptions and NodeSet documentation carry curly quotation marks, dashes and ellipses.
# Source stays ASCII, which a release check enforces, and none of these characters mean
# anything a plain ASCII one does not, so they are folded on the way out.
# Anything NOT in this table is refused rather than emitted: a character with no obvious ASCII
# equivalent needs a person to decide, and silently writing it would fail the ASCII gate later
# with no clue where it came from.
_TYPOGRAPHY = {
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u2026": "...",
    "\u00a0": " ", "\u00b7": ".",
    # Companion-spec descriptions carry these, and they reach a `///<` comment rather than a
    # value: MachineTool writes a range with U+2264, engineering units appear as U+00B0/B2/B3,
    # and the German specs (Weihenstephan) quote with U+201E. Folding them is what io.py's own
    # refusal message asks for when the character is decoration. A character that IS the value
    # still has to be emitted as a \uXXXX escape by whatever emits it, which is why this table
    # never sees one.
    "\u2264": "<=", "\u00b0": "deg", "\u00b2": "^2", "\u00b3": "^3", "\u201e": '"',
    # Both mu characters: U+00B5 MICRO SIGN and U+03BC GREEK SMALL LETTER MU are visually
    # identical and the companion specs use both, so mapping one leaves the other to fail.
    "\u00b5": "u", "\u03bc": "u",
}


def to_ascii(text: str, path: Path) -> str:
    """Fold known typography to ASCII; refuse anything else."""
    for source, replacement in _TYPOGRAPHY.items():
        text = text.replace(source, replacement)
    stray = sorted({character for character in text if ord(character) > 127})
    if stray:
        listed = ", ".join(f"U+{ord(c):04X} {c!r}" for c in stray)
        raise ValueError(
            f"{path}: generated content holds non-ASCII with no ASCII equivalent: {listed}. "
            f"Add it to _TYPOGRAPHY in {__file__} if it is decoration, or emit it as a "
            f"\\uXXXX escape if it is data.")
    return text


def _comment_prefix(path: Path) -> str | None:
    """The line-comment marker for a generated file, or None where a header cannot go.

    Returning None rather than guessing keeps a data file the generator might one day emit
    from being corrupted by a comment its parser would reject. The licence-header CI gate
    covers the same file kinds, so a new kind that needs a header is reported rather than
    silently skipped.
    """
    if path.suffix in (".h", ".hpp", ".cpp"):
        return "//"
    if path.suffix in (".cmake", ".py", ".sh") or path.name in ("CMakeLists.txt", ".clang-tidy"):
        return "#"
    return None


def licence_header(path: Path) -> str:
    """The licence header for `path`, with its trailing blank line, or "" if it takes none."""
    prefix = _comment_prefix(path)
    if prefix is None:
        return ""
    return (f"{prefix} SPDX-License-Identifier: {LICENCE_IDENTIFIER}\n"
            f"{prefix} {COPYRIGHT_LINE}\n\n")


def load_template(name: str) -> str:
    templates_dir = Path(__file__).resolve().parent / "inputs"
    return (templates_dir / name).read_text(encoding="utf-8")


def write_file(path: Path, contents: str) -> None:
    header = licence_header(path)
    # An emitter that already supplied the header keeps its own copy rather than gaining a
    # second one, so a template may carry the header without this becoming a duplicate.
    if header and not contents.lstrip().startswith(header.split("\n", 1)[0]):
        contents = header + contents
    contents = to_ascii(contents, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
