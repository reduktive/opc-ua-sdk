# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Coverage guard for the companion-spec ``aliases.h`` ``using ::ua::*`` block.

Each companion spec emits ``<prefix>aliases.h`` which does ``using ::ua::Name;``
for every name in ``_UA_CORE_ALIASES`` and pulls in a fixed set of umbrella
headers (``_UMBRELLA_HEADERS``). For that block to compile, **every aliased name
must be declared within the transitive include closure of the umbrella headers**.

This test enforces that invariant so a future change can't add a bogus alias
(declared nowhere - the historical ``RefMember`` mistake) or remove an umbrella
header that a current alias depends on. It complements the companion fixtures,
whose compiles catch *missing* aliases for the core types those specs actually use.

Standalone (no pytest dependency):  python -m tooling.type_generator.tests.test_aliases_coverage
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from ..codegen.emit_spec_headers import _UA_CORE_ALIASES, _UMBRELLA_HEADERS

# Repo root: tooling/type_generator/tests/ -> ../../../
_REPO_ROOT = Path(__file__).resolve().parents[3]
_INTERFACE_ROOT = _REPO_ROOT / "sdk" / "interface"

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)


def _headers_by_basename() -> dict[str, Path]:
    """Map every interface header's basename to its path (basename includes are
    the convention - see the repository conventions: headers are included without directories)."""
    result: dict[str, Path] = {}
    for path in _INTERFACE_ROOT.rglob("*.h"):
        result.setdefault(path.name, path)
    return result


def _transitive_closure(roots: tuple[str, ...], by_basename: dict[str, Path]) -> list[Path]:
    """All interface headers reachable from ``roots`` via ``#include "..."``."""
    seen: set[str] = set()
    stack = list(roots)
    files: list[Path] = []
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        path = by_basename.get(name)
        if path is None:
            continue  # a non-interface include (std / vcpkg) - not our concern
        files.append(path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for inc in _INCLUDE_RE.findall(text):
            stack.append(Path(inc).name)
    return files


def _whole_word(name: str, text: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text) is not None


def test_core_aliases_unique() -> None:
    dupes = [n for n in set(_UA_CORE_ALIASES) if _UA_CORE_ALIASES.count(n) > 1]
    assert not dupes, f"_UA_CORE_ALIASES has duplicates: {sorted(dupes)}"


def test_core_aliases_declared_in_umbrella_closure() -> None:
    by_basename = _headers_by_basename()
    # Every umbrella header must itself exist in the interface tree.
    for header in _UMBRELLA_HEADERS:
        assert header in by_basename, f"umbrella header {header!r} not found under sdk/interface"

    closure = _transitive_closure(_UMBRELLA_HEADERS, by_basename)
    blob = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in closure)

    missing = [name for name in _UA_CORE_ALIASES if not _whole_word(name, blob)]
    assert not missing, (
        "These _UA_CORE_ALIASES names are not declared within the transitive include "
        f"closure of _UMBRELLA_HEADERS, so the companion 'using ::ua::<name>;' block "
        f"would not compile: {missing}. Add the declaring header to _UMBRELLA_HEADERS "
        "(or remove the bogus alias)."
    )


def main() -> int:
    failures = 0
    for fn in (test_core_aliases_unique, test_core_aliases_declared_in_umbrella_closure):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {fn.__name__}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
