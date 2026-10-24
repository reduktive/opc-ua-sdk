# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""The generated instance-handle tests register a Part 19 dictionary namespace before creating a
dictionary entry, because instantiation never registers one (public API review 2026-10, API-6.2).

Standalone (no pytest dependency). Invoke with:

    python -m tooling.type_generator.tests.test_emit_instance_tests_dictionary
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from ..codegen.emit_instance_tests import emit_instance_type_tests
from ..types.model import InstanceType, InstanceTypeKind

_IRDI = InstanceType(node_id="i=17598", browse_name="IrdiDictionaryEntryType", class_name="IrdiDictionaryEntry",
                     kind=InstanceTypeKind.object_type)
_URI = InstanceType(node_id="i=17600", browse_name="UriDictionaryEntryType", class_name="UriDictionaryEntry",
                    kind=InstanceTypeKind.object_type)
_FOLDER = InstanceType(node_id="i=61", browse_name="FolderType", class_name="Folder",
                       kind=InstanceTypeKind.object_type)
# A companion type that happens to share the class name is not an NS0 dictionary entry.
_COMPANION = InstanceType(node_id="ns=1;i=17598", browse_name="IrdiDictionaryEntryType",
                          class_name="CompanionIrdiDictionaryEntry", kind=InstanceTypeKind.object_type)


def _emit(types: list[InstanceType]) -> str:
    with tempfile.TemporaryDirectory() as directory:
        return emit_instance_type_tests(Path(directory), types).read_text()


def _test_body(text: str, name: str) -> str:
    start = text.index(f"TEST_F(GeneratedInstanceTypeTests, {name})")
    return text[start:text.index("\n}\n", start)]


def test_each_dictionary_entry_registers_its_own_namespace_before_creating():
    text = _emit([_IRDI, _URI, _FOLDER])
    irdi = _test_body(text, "IrdiDictionaryEntry_CreateAndAttach")
    uri = _test_body(text, "UriDictionaryEntry_CreateAndAttach")
    assert irdi.index("register_dictionary_namespace(*addressSpace, irdiDictionaryNamespaceUri);") \
        < irdi.index("try_create_sync")
    assert "register_dictionary_namespace(*addressSpace, uriDictionaryNamespaceUri);" in uri
    assert "register_dictionary_namespace" not in _test_body(text, "Folder_CreateAndAttach")
    assert text.count("void register_dictionary_namespace(") == 1


def test_no_helper_without_a_dictionary_entry_type():
    text = _emit([_FOLDER, _COMPANION])
    assert "register_dictionary_namespace" not in text


def main() -> int:
    test_each_dictionary_entry_registers_its_own_namespace_before_creating()
    test_no_helper_without_a_dictionary_entry_type()
    print("emit_instance_tests dictionary: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
