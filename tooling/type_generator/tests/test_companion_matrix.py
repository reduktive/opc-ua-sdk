# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for tooling.type_generator.companion_matrix (codegen-matrix P1).

Standalone - no pytest dependency.  Invoke via:

    python -m tooling.type_generator.tests.test_companion_matrix
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

from ..manifest import NS0_URI
from ..companion_matrix import (
    GeneratableSpec,
    build_registry,
    derive_slug,
    discover,
    find_nodeids_csv,
    names_for_slug,
    parse_models,
)


# -- helpers -----------------------------------------------------------------

UA = "http://opcfoundation.org/UA/"


def _nodeset_xml(model_uri: str, required: tuple[str, ...] = (), *, extra_models=()) -> str:
    """Minimal UANodeSet with one (or more) <Model> + <RequiredModel> entries."""
    def model(uri: str, reqs: tuple[str, ...]) -> str:
        body = "".join(f'<RequiredModel ModelUri="{r}"/>' for r in reqs)
        return f'<Model ModelUri="{uri}">{body}</Model>'

    models = model(model_uri, required) + "".join(model(u, r) for u, r in extra_models)
    return f"<UANodeSet><Models>{models}</Models></UANodeSet>"


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# -- parse_models ------------------------------------------------------------


def test_parse_models_single(tmp_path: Path):
    f = _write(tmp_path / "di.NodeSet2.xml", _nodeset_xml(UA + "DI/", (UA,)))
    models = parse_models(f)
    assert len(models) == 1
    assert models[0].uri == UA + "DI/"
    assert models[0].required_uris == (UA,)


def test_parse_models_multi_model(tmp_path: Path):
    f = _write(
        tmp_path / "multi.NodeSet2.xml",
        _nodeset_xml(UA + "A/", (UA,), extra_models=((UA + "B/", (UA, UA + "A/")),)),
    )
    models = parse_models(f)
    assert [m.uri for m in models] == [UA + "A/", UA + "B/"]
    assert models[1].required_uris == (UA, UA + "A/")


def test_parse_models_namespaced_tags(tmp_path: Path):
    # ElementTree must still find Model/RequiredModel through an xmlns.
    xml = (
        '<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">'
        f'<Models><Model ModelUri="{UA}DI/">'
        f'<RequiredModel ModelUri="{UA}"/></Model></Models></UANodeSet>'
    )
    f = _write(tmp_path / "ns.NodeSet2.xml", xml)
    models = parse_models(f)
    assert models[0].uri == UA + "DI/"
    assert models[0].required_uris == (UA,)


# -- find_nodeids_csv --------------------------------------------------------


def test_find_csv_case_insensitive(tmp_path: Path):
    ns = _write(tmp_path / "Opc.Ua.Di.NodeSet2.xml", "<x/>")
    csv = _write(tmp_path / "Opc.Ua.Di.NodeIds.csv", "")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_lowercase_nodeset_and_csv(tmp_path: Path):
    ns = _write(tmp_path / "opc.ua.isa95.nodeset2.xml", "<x/>")
    csv = _write(tmp_path / "opc.ua.isa95.nodeids.csv", "")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_absent_returns_none(tmp_path: Path):
    ns = _write(tmp_path / "Spec.NodeSet2.xml", "<x/>")
    assert find_nodeids_csv(ns) is None


def test_find_csv_ignores_examples_dump(tmp_path: Path):
    ns = _write(tmp_path / "Spec.NodeSet2.xml", "<x/>")
    _write(tmp_path / "Spec.NodeIds.examples.csv", "")
    assert find_nodeids_csv(ns) is None


def test_find_csv_bare_nodeids_name(tmp_path: Path):
    ns = _write(tmp_path / "Opc.Ua.Spec.NodeSet2.xml", "<x/>")
    csv = _write(tmp_path / "NodeIds.csv", "Foo,1,ObjectType\n")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_nodeset2_suffix_variant(tmp_path: Path):
    # FX-style: opc.ua.fx.data.nodeset2.xml <-> opc.ua.fx.data.nodeset2.csv
    ns = _write(tmp_path / "opc.ua.fx.data.nodeset2.xml", "<x/>")
    csv = _write(tmp_path / "opc.ua.fx.data.nodeset2.csv", "Foo,31,DataType\n")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_nodesids_typo(tmp_path: Path):
    ns = _write(tmp_path / "opc.ua.gms.nodeset2.xml", "<x/>")
    csv = _write(tmp_path / "opc.ua.gms.nodesids.csv", "Foo,1,ObjectType\n")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_lone_model_csv_content_validated(tmp_path: Path):
    # ADI-style: the only CSV has an unrecognised name but valid content.
    ns = _write(tmp_path / "Opc.Ua.Adi.NodeSet2.xml", "<x/>")
    csv = _write(tmp_path / "OpcUaAdiModel.csv", "AnalyserDeviceType,1001,ObjectType\n")
    assert find_nodeids_csv(ns) == csv


def test_find_csv_lone_csv_rejected_when_not_nodeids(tmp_path: Path):
    ns = _write(tmp_path / "Spec.NodeSet2.xml", "<x/>")
    _write(tmp_path / "Readme.csv", "this,is,not;a,nodeids,table\nx\n")
    assert find_nodeids_csv(ns) is None


def test_find_csv_ambiguous_multi_csv_unpaired(tmp_path: Path):
    # Two unlabelled valid CSVs, no name match -> refuse to guess.
    ns = _write(tmp_path / "Spec.NodeSet2.xml", "<x/>")
    _write(tmp_path / "ModelA.csv", "A,1,ObjectType\n")
    _write(tmp_path / "ModelB.csv", "B,2,ObjectType\n")
    assert find_nodeids_csv(ns) is None


# -- derive_slug / names -----------------------------------------------------


def test_slug_standard_paths():
    assert derive_slug(UA + "DI/") == "di"
    assert derive_slug(UA + "Machinery/Jobs/") == "machinery_jobs"
    assert derive_slug(UA + "ISA95-JOBCONTROL_V2/") == "isa95_jobcontrol_v2"
    assert derive_slug(UA + "BACnet_V2/") == "bacnet_v2"


def test_slug_drops_date_version_segments():
    assert derive_slug("http://www.OPCFoundation.org/UA/2013/01/ISA95") == "isa95"


def test_slug_host_fallback_when_path_is_only_marker():
    # Path is only the ``UA`` marker -> name comes from the host's primary label.
    assert derive_slug("http://sercos.org/UA/") == "sercos"


def test_slug_leading_digit_guarded():
    slug = derive_slug("http://example.com/UA/3DStuff/")
    assert slug and not slug[0].isdigit()


def test_names_for_slug():
    assert names_for_slug("di") == ("ua::di", "ua_di_", "ua_di_types")


# -- build_registry ----------------------------------------------------------


def test_registry_case_insensitive_glob(tmp_path: Path):
    # Three casings of the nodeset suffix must all be discovered.
    _write(tmp_path / "A.NodeSet2.xml", _nodeset_xml(UA + "A/"))
    _write(tmp_path / "B.Nodeset2.xml", _nodeset_xml(UA + "B/"))
    _write(tmp_path / "c.nodeset2.xml", _nodeset_xml(UA + "C/"))
    reg = build_registry(tmp_path)
    assert {UA + "A/", UA + "B/", UA + "C/"} <= set(reg)


def test_registry_prefers_non_example_provider(tmp_path: Path):
    real = _write(tmp_path / "Spec.NodeSet2.xml", _nodeset_xml(UA + "S/"))
    _write(tmp_path / "Spec-Example.NodeSet2.xml", _nodeset_xml(UA + "S/"))
    reg = build_registry(tmp_path)
    assert reg[UA + "S/"].path == real
    assert reg[UA + "S/"].is_example is False


def test_registry_pairs_csv(tmp_path: Path):
    _write(tmp_path / "Spec.NodeSet2.xml", _nodeset_xml(UA + "S/"))
    csv = _write(tmp_path / "Spec.NodeIds.csv", "")
    reg = build_registry(tmp_path)
    assert reg[UA + "S/"].nodeids_csv == csv


# -- discover (end-to-end on a synthetic tree) -------------------------------


def _spec_tree(root: Path) -> None:
    """NS0 + di + ia(->di) + mtool(->di,ia) + orphan(->missing) + an example."""
    _write(root / "Schema/Opc.Ua.NodeSet2.xml", _nodeset_xml(NS0_URI))
    _write(root / "DI/Opc.Ua.Di.NodeSet2.xml", _nodeset_xml(UA + "DI/", (NS0_URI,)))
    _write(root / "DI/Opc.Ua.Di.NodeIds.csv", "")
    _write(root / "IA/Opc.Ua.IA.NodeSet2.xml", _nodeset_xml(UA + "IA/", (NS0_URI, UA + "DI/")))
    _write(
        root / "MachineTool/Opc.Ua.MachineTool.NodeSet2.xml",
        _nodeset_xml(UA + "MachineTool/", (UA + "DI/", UA + "IA/")),
    )
    _write(
        root / "Orphan/Opc.Ua.Orphan.NodeSet2.xml",
        _nodeset_xml(UA + "Orphan/", (UA + "Missing/",)),
    )
    _write(
        root / "Ex/Thing-Example.NodeSet2.xml", _nodeset_xml(UA + "ExampleSpec/")
    )


def _by_slug(specs: list[GeneratableSpec]) -> dict[str, GeneratableSpec]:
    return {s.slug: s for s in specs}


def test_discover_generatable_and_skipped(tmp_path: Path):
    _spec_tree(tmp_path)
    plan = discover(tmp_path)
    gen = _by_slug(plan.generatable)
    assert {"di", "ia", "machinetool"} <= set(gen)
    # orphan -> skipped with the exact missing URI; example excluded by default.
    assert "examplespec" not in gen
    skipped = {s.slug: s for s in plan.skipped}
    assert "orphan" in skipped
    assert skipped["orphan"].missing == [UA + "Missing/"]


def test_discover_transitive_lookup_order(tmp_path: Path):
    _spec_tree(tmp_path)
    gen = _by_slug(discover(tmp_path).generatable)
    # ia depends only on di; mtool on di then ia (deps-first).
    assert [d.slug for d in gen["ia"].lookup_specs] == ["di"]
    assert [d.slug for d in gen["machinetool"].lookup_specs] == ["di", "ia"]


def test_discover_excludes_ns0_from_lookups(tmp_path: Path):
    _spec_tree(tmp_path)
    gen = _by_slug(discover(tmp_path).generatable)
    for spec in gen.values():
        assert all(d.uri != NS0_URI for d in spec.lookup_specs)
    # di required NS0 only -> no lookups at all.
    assert gen["di"].lookup_specs == []


def test_discover_global_topological_order(tmp_path: Path):
    _spec_tree(tmp_path)
    order = [s.slug for s in discover(tmp_path).generatable]
    assert order.index("di") < order.index("ia") < order.index("machinetool")


def test_discover_include_examples(tmp_path: Path):
    _spec_tree(tmp_path)
    gen = _by_slug(discover(tmp_path, include_examples=True).generatable)
    assert "examplespec" in gen


def test_discover_csv_none_when_absent(tmp_path: Path):
    _spec_tree(tmp_path)
    gen = _by_slug(discover(tmp_path).generatable)
    assert gen["di"].nodeids_csv is not None  # DI has a csv
    assert gen["ia"].nodeids_csv is None       # IA has none


def test_discover_skips_pubsub_fx_specs(tmp_path: Path):
    # OPC UA FX is PubSub-based and unsupported -> skipped-by-design, not generatable.
    _write(tmp_path / "Schema/Opc.Ua.NodeSet2.xml", _nodeset_xml(NS0_URI))
    _write(
        tmp_path / "UAFX/opc.ua.fx.data.nodeset2.xml",
        _nodeset_xml("http://opcfoundation.org/UA/FX/Data/", (NS0_URI,)),
    )
    plan = discover(tmp_path)
    assert "fx_data" not in {s.slug for s in plan.generatable}
    fx = next(s for s in plan.skipped if s.slug == "fx_data")
    assert "PubSub" in fx.reason


def test_discover_is_deterministic(tmp_path: Path):
    _spec_tree(tmp_path)
    a = discover(tmp_path).to_dict()
    b = discover(tmp_path).to_dict()
    assert a == b


# -- runner ------------------------------------------------------------------


def _run() -> int:
    failed = 0
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    import tempfile

    for name, fn in tests:
        try:
            if "tmp_path" in inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as td:
                    fn(tmp_path=Path(td))
            else:
                fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:  # noqa: BLE001
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    if failed:
        print(f"\n{failed} test(s) failed", file=sys.stderr)
    else:
        print(f"\n{len(tests)} test(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
