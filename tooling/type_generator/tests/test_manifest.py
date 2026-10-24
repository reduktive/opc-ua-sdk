# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for tooling.type_generator.manifest.

Standalone - no pytest dependency.  Invoke via:

    python -m tooling.type_generator.tests.test_manifest
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from pydantic import ValidationError

from ..manifest import (
    NS0_URI,
    Manifest,
    NodesetConfig,
    load_manifest,
    strip_json_comments,
    validate_manifest_against_files,
)


# -- strip_json_comments -----------------------------------------------------


def test_strip_line_comments():
    src = '{\n  "a": 1, // trailing\n  "b": 2 //\n}'
    out = strip_json_comments(src)
    assert json.loads(out) == {"a": 1, "b": 2}


def test_strip_block_comments():
    src = '{ /* block */ "a": /* inline */ 1, "b": 2 }'
    out = strip_json_comments(src)
    assert json.loads(out) == {"a": 1, "b": 2}


def test_strip_preserves_strings_with_slashes():
    # `//` inside a string must NOT be stripped.
    src = '{"u": "http://example.com/", "x": 1 // tail\n}'
    out = strip_json_comments(src)
    assert json.loads(out) == {"u": "http://example.com/", "x": 1}


def test_strip_preserves_escaped_quotes_inside_strings():
    src = '{"s": "she said \\"hi\\" // not a comment", "n": 1}'
    out = strip_json_comments(src)
    assert json.loads(out) == {
        "s": 'she said "hi" // not a comment',
        "n": 1,
    }


def test_strip_preserves_newlines_inside_block_comment():
    # Block comments span multiple lines; we keep the newlines so JSON error
    # line numbers stay accurate.
    src = '{ /* line1\nline2\nline3 */ "a": 1 }'
    out = strip_json_comments(src)
    # Three newlines preserved inside the stripped span.
    assert out.count("\n") == 2
    assert json.loads(out) == {"a": 1}


# -- NodesetConfig validation ------------------------------------------------


def test_nodeset_config_minimal_valid():
    cfg = NodesetConfig(
        uri="http://opcfoundation.org/UA/DI/",
        sources=["Opc.Ua.Di.NodeSet2.xml"],
        include_prefix="ua_di_",
        cpp_namespace="ua::di",
        target="ua_di_types",
    )
    assert cfg.emit is True


def test_nodeset_config_amalgamate_sources_defaults_off_and_settable():
    base = dict(
        uri="http://opcfoundation.org/UA/DI/",
        sources=["Opc.Ua.Di.NodeSet2.xml"],
        include_prefix="ua_di_",
        cpp_namespace="ua::di",
        target="ua_di_types",
    )
    assert NodesetConfig(**base).amalgamate_sources is False
    assert NodesetConfig(**base, amalgamate_sources=True).amalgamate_sources is True


def test_synthesise_sets_amalgamate_for_ns0_emit():
    from ..synthesise_manifest import _build_manifest, _parse_args

    args = _parse_args([
        "--out", "x.json",
        "--emit-source", "Opc.Ua.NodeSet2.xml",
        "--emit-uri", NS0_URI,
        "--emit-cpp-namespace", "ua",
        "--emit-include-prefix", "ua_",
        "--emit-target", "sdk",
    ])
    manifest = _build_manifest(args)
    emit = next(n for n in manifest["nodesets"] if n["uri"] == NS0_URI)
    assert emit["amalgamate_sources"] is True


def test_synthesise_omits_amalgamate_for_consumer_emit():
    from ..synthesise_manifest import _build_manifest, _parse_args

    args = _parse_args([
        "--out", "x.json",
        "--ns0-sources", "Opc.Ua.NodeSet2.xml",
        "--emit-source", "Opc.Ua.Di.NodeSet2.xml",
        "--emit-uri", "http://opcfoundation.org/UA/DI/",
        "--emit-cpp-namespace", "ua::di",
        "--emit-include-prefix", "ua_di_",
        "--emit-target", "ua_di_types",
    ])
    manifest = _build_manifest(args)
    emit = next(n for n in manifest["nodesets"] if n["emit"])
    # Consumer specs do not amalgamate; the field is omitted (schema default off).
    assert "amalgamate_sources" not in emit
    assert NodesetConfig(**emit).amalgamate_sources is False


def test_nodeset_config_include_prefix_must_end_underscore():
    try:
        NodesetConfig(
            uri="http://x/",
            sources=["x.xml"],
            include_prefix="ua_di",  # no trailing _
            cpp_namespace="ua::di",
            target="t",
        )
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


def test_nodeset_config_cpp_namespace_must_be_qualified_id():
    try:
        NodesetConfig(
            uri="http://x/",
            sources=["x.xml"],
            include_prefix="ua_di_",
            cpp_namespace="ua::1bad",  # leading digit after ::
            target="t",
        )
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


def test_nodeset_config_target_must_be_cmake_safe():
    try:
        NodesetConfig(
            uri="http://x/",
            sources=["x.xml"],
            include_prefix="ua_di_",
            cpp_namespace="ua::di",
            target="bad-target-name",  # hyphen not allowed
        )
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


def test_nodeset_config_rejects_extra_fields():
    try:
        NodesetConfig(
            uri="http://x/",
            sources=["x.xml"],
            include_prefix="ua_di_",
            cpp_namespace="ua::di",
            target="t",
            unknown_field="oops",
        )
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


def test_nodeset_config_sources_must_not_be_empty():
    try:
        NodesetConfig(
            uri="http://x/",
            sources=[],
            include_prefix="ua_di_",
            cpp_namespace="ua::di",
            target="t",
        )
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


# -- Manifest invariants -----------------------------------------------------


def _ns0_cfg(**overrides) -> NodesetConfig:
    fields = dict(
        uri=NS0_URI,
        sources=["Opc.Ua.NodeSet2.xml"],
        include_prefix="ua_",
        cpp_namespace="ua",
        target="sdk",
        emit=True,
    )
    fields.update(overrides)
    return NodesetConfig(**fields)


def _di_cfg(**overrides) -> NodesetConfig:
    fields = dict(
        uri="http://opcfoundation.org/UA/DI/",
        sources=["Opc.Ua.Di.NodeSet2.xml"],
        include_prefix="ua_di_",
        cpp_namespace="ua::di",
        target="ua_di_types",
        emit=True,
    )
    fields.update(overrides)
    return NodesetConfig(**fields)


def test_manifest_requires_ns0():
    try:
        Manifest(nodesets=[_di_cfg()])
    except ValidationError as ex:
        assert "NS0" in str(ex) or NS0_URI in str(ex)
        return
    raise AssertionError("expected ValidationError")


def test_manifest_rejects_two_ns0_entries():
    try:
        Manifest(nodesets=[_ns0_cfg(), _ns0_cfg(target="sdk_alt")])
    except ValidationError as ex:
        assert "exactly one is allowed" in str(ex) or "duplicate" in str(ex)
        return
    raise AssertionError("expected ValidationError")


def test_manifest_rejects_duplicate_uris():
    try:
        Manifest(nodesets=[_ns0_cfg(), _di_cfg(), _di_cfg(target="t2")])
    except ValidationError as ex:
        assert "duplicate uri" in str(ex)
        return
    raise AssertionError("expected ValidationError")


def test_manifest_rejects_duplicate_include_prefixes():
    try:
        Manifest(
            nodesets=[
                _ns0_cfg(),
                _di_cfg(),
                _di_cfg(
                    uri="http://x/",
                    target="t2",
                    cpp_namespace="ua::other",
                ),
            ]
        )
    except ValidationError as ex:
        assert "duplicate include_prefix" in str(ex)
        return
    raise AssertionError("expected ValidationError")


def test_manifest_rejects_duplicate_cpp_namespaces():
    try:
        Manifest(
            nodesets=[
                _ns0_cfg(),
                _di_cfg(),
                _di_cfg(
                    uri="http://x/",
                    target="t2",
                    include_prefix="ua_x_",
                ),
            ]
        )
    except ValidationError as ex:
        assert "duplicate cpp_namespace" in str(ex)
        return
    raise AssertionError("expected ValidationError")


def test_manifest_find_by_uri():
    m = Manifest(nodesets=[_ns0_cfg(), _di_cfg()])
    assert m.find_by_uri(NS0_URI) is not None
    assert m.find_by_uri("http://opcfoundation.org/UA/DI/") is not None
    assert m.find_by_uri("http://unknown/") is None


def test_manifest_emit_and_lookup_sets():
    m = Manifest(
        nodesets=[_ns0_cfg(emit=False), _di_cfg(emit=True)]
    )
    assert [c.uri for c in m.emit_set()] == ["http://opcfoundation.org/UA/DI/"]
    assert len(m.lookup_set()) == 2


# -- load_manifest -----------------------------------------------------------


def test_load_manifest_with_comments(tmp_path: Path):
    text = """\
{
  // top of file
  "nodesets": [
    {
      "uri": "http://opcfoundation.org/UA/",
      "sources": ["NS0.xml"],
      "include_prefix": "ua_",
      "cpp_namespace": "ua",
      "target": "sdk",
      "emit": false /* lookup-only */
    },
    {
      "uri": "http://opcfoundation.org/UA/DI/",
      "sources": ["DI.xml"],
      "include_prefix": "ua_di_",
      "cpp_namespace": "ua::di",
      "target": "ua_di_types"
    }
  ]
}
"""
    p = tmp_path / "manifest.json"
    p.write_text(text, encoding="utf-8")
    m = load_manifest(p)
    assert len(m.nodesets) == 2
    assert m.nodesets[0].emit is False
    assert m.nodesets[1].emit is True  # default


def test_load_manifest_rejects_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text('{"nodesets": [},,]', encoding="utf-8")
    try:
        load_manifest(p)
    except ValueError as ex:
        assert "not valid JSON" in str(ex)
        return
    raise AssertionError("expected ValueError")


# -- validate_manifest_against_files ----------------------------------------


_NS0_XML = """<?xml version="1.0" encoding="utf-8" ?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <Models>
    <Model ModelUri="http://opcfoundation.org/UA/" Version="1.05.06" />
  </Models>
</UANodeSet>
"""

_DI_XML = """<?xml version="1.0" encoding="utf-8" ?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://opcfoundation.org/UA/DI/</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="http://opcfoundation.org/UA/DI/" Version="1.04.0" />
  </Models>
</UANodeSet>
"""

_WRONG_URI_XML = """<?xml version="1.0" encoding="utf-8" ?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://wrong/</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="http://wrong/" Version="1.0" />
  </Models>
</UANodeSet>
"""


def test_validate_against_files_accepts_matching(tmp_path: Path):
    (tmp_path / "ns0.xml").write_text(_NS0_XML, encoding="utf-8")
    (tmp_path / "di.xml").write_text(_DI_XML, encoding="utf-8")

    m = Manifest(
        nodesets=[
            _ns0_cfg(sources=["ns0.xml"]),
            _di_cfg(sources=["di.xml"]),
        ]
    )
    validate_manifest_against_files(m, tmp_path)  # must not raise


def test_validate_against_files_rejects_uri_mismatch(tmp_path: Path):
    (tmp_path / "ns0.xml").write_text(_NS0_XML, encoding="utf-8")
    (tmp_path / "wrong.xml").write_text(_WRONG_URI_XML, encoding="utf-8")

    m = Manifest(
        nodesets=[
            _ns0_cfg(sources=["ns0.xml"]),
            _di_cfg(sources=["wrong.xml"]),
        ]
    )
    try:
        validate_manifest_against_files(m, tmp_path)
    except ValueError as ex:
        assert "no source file advertises" in str(ex)
        return
    raise AssertionError("expected ValueError")


def test_validate_against_files_missing_source(tmp_path: Path):
    (tmp_path / "ns0.xml").write_text(_NS0_XML, encoding="utf-8")

    m = Manifest(
        nodesets=[
            _ns0_cfg(sources=["ns0.xml"]),
            _di_cfg(sources=["missing.xml"]),
        ]
    )
    try:
        validate_manifest_against_files(m, tmp_path)
    except ValueError as ex:
        assert "source not found" in str(ex)
        return
    raise AssertionError("expected ValueError")


# -- runner ------------------------------------------------------------------


def _run() -> int:
    failed = 0
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    for name, fn in tests:
        try:
            # tmp_path-style: call with a fresh tempdir when the test asks for it.
            import inspect

            sig = inspect.signature(fn)
            if "tmp_path" in sig.parameters:
                with tempfile.TemporaryDirectory() as td:
                    fn(tmp_path=Path(td))
            else:
                fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    if failed:
        print(f"\n{failed} test(s) failed", file=sys.stderr)
    else:
        print(f"\n{len(tests)} test(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
