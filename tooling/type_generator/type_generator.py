# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Top-level orchestration for the OPC-UA type generator.

The heavy lifting lives in:

* ``cli.parse_args`` - argument parsing.
* ``manifest.load_manifest`` - JSON manifest loader + validation.
* ``nodeset.index.NodeSetIndex`` - typed model of every nodeset in scope.
* ``codegen.context.EmitContext`` - per-spec emission context.
* ``codegen.spec_runner.SpecRunner`` - drives the per-spec emit pass.

``main`` itself only wires those pieces together: load the manifest,
build the index, and run one ``SpecRunner`` per ``emit=true`` config.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .cli import parse_args


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        opts = parse_args(argv)
    except ModuleNotFoundError as ex:
        if ex.name == "pydantic":
            _print_pydantic_missing()
            return 1
        raise

    try:
        from .manifest import (
            NS0_URI,
            load_manifest,
            validate_manifest_against_files,
        )
    except ModuleNotFoundError as ex:
        if ex.name == "pydantic":
            _print_pydantic_missing()
            return 1
        raise

    manifest_path = Path(opts.manifest).resolve()
    try:
        manifest = load_manifest(manifest_path)
        validate_manifest_against_files(manifest, manifest_path.parent)
    except ValueError as ex:
        print(f"manifest error: {ex}", file=sys.stderr)
        return 1

    ns0_cfg = manifest.find_by_uri(NS0_URI)
    assert ns0_cfg is not None  # invariant enforced by manifest validation

    # Every source path in scope (emit + lookup) - fed to NodeSetIndex.
    all_source_paths = [
        str(src)
        for cfg in manifest.nodesets
        for src in cfg.resolved_sources(manifest_path.parent)
    ]

    if opts.list_datatypes:
        return _run_list_datatypes(all_source_paths)

    # --- Generation mode ---

    from .codegen.context import EmitContext
    from .codegen.spec_runner import SpecRunner
    from .formatting import set_clang_format_config
    from .nodeset.index import NodeSetIndex

    if opts.clang_format_config:
        set_clang_format_config(Path(opts.clang_format_config))

    output_root = Path(opts.output)

    # Canonicalise NodeId namespaces across all specs so cross-spec references
    # (a dependent spec's field typed by a lookup spec) resolve and per-file
    # ``ns=1`` ids don't collide in the shared index. NS0 is canonical 0; other
    # specs get a stable index in manifest order. No-op for single-companion
    # runs (its own ``ns=1`` -> canonical 1), so NS0/single-companion output is
    # unchanged.
    uri_to_canonical: dict[str, int] = {NS0_URI: 0}
    for cfg in manifest.nodesets:
        if cfg.uri not in uri_to_canonical:
            uri_to_canonical[cfg.uri] = len(uri_to_canonical)

    # Build the type index from every nodeset (canonicalising as it parses),
    # then annotate sources with their owning config for cross-spec resolution.
    index = NodeSetIndex.from_nodesets(all_source_paths, uri_to_canonical)
    config_by_source = {
        str(src): cfg
        for cfg in manifest.nodesets
        for src in cfg.resolved_sources(manifest_path.parent)
    }
    if config_by_source:
        index = index.with_config_by_source(config_by_source)

    # StatusCode / AttributeIds / NS0 byte-array are NS0-only inputs (companion
    # specs don't define status codes or attributes).  ``NodeIds.csv`` is now
    # per-spec: each emit spec gets its own identifier enums in its own
    # ``cpp_namespace`` (e.g. ``ua::di::ObjectId``) when its manifest entry
    # carries a ``nodeids_csv``.
    ns0_dir = manifest_path.parent
    nodeset_ns0_xml = str(ns0_cfg.resolved_sources(ns0_dir)[0])
    statuscode_csv = _resolve(ns0_cfg.statuscode_csv, ns0_dir)
    attribute_ids_csv = _resolve(ns0_cfg.attribute_ids_csv, ns0_dir)

    # Run one emitter pass per ``emit=true`` config.  Phase 2 lands the
    # NS0 case end-to-end; downstream specs gain their own SpecRunner
    # invocation in Phase 5.
    for cfg in manifest.emit_set():
        is_ns0 = cfg.uri == NS0_URI
        ctx = EmitContext.build(cfg, index, output_root)
        runner = SpecRunner(
            ctx,
            nodeset_paths=all_source_paths,
            nodeids_csv=_resolve(cfg.nodeids_csv, manifest_path.parent),
            statuscode_csv=statuscode_csv if is_ns0 else None,
            attribute_ids_csv=attribute_ids_csv if is_ns0 else None,
            nodeset_ns0_xml=nodeset_ns0_xml if is_ns0 else None,
        )
        runner.run()

    return 0


# --- Helpers ---------------------------------------------------------------


def _resolve(rel: str | None, base: Path) -> str | None:
    if not rel:
        return None
    return str((base / rel).resolve())


def _run_list_datatypes(nodeset_paths: list[str]) -> int:
    """``--list-datatypes`` inspection mode."""
    try:
        from .nodeset.parse import list_ua_data_types
    except ModuleNotFoundError as ex:
        if ex.name == "pydantic":
            _print_pydantic_missing()
            return 1
        raise

    all_dts: list[tuple[str, str]] = []
    for path in nodeset_paths:
        dts = list_ua_data_types(path)
        print(f"{len(dts)} UADataType nodes found in nodeset {path}")
        all_dts.extend(dts)

    all_dts.sort(key=lambda x: (x[0], x[1]))
    try:
        for node_id, browse_name in all_dts:
            print(f"{node_id} {browse_name}")
    except BrokenPipeError:
        # Typical Unix behavior when piping to `head` etc.
        pass
    return 0


def _print_pydantic_missing() -> None:
    print(
        "Missing Python dependency: pydantic. "
        "Create a venv and install with: "
        "python3 -m venv .venv-typegen && . .venv-typegen/bin/activate && "
        "python -m pip install -r tooling/type_generator/requirements.txt",
        file=sys.stderr,
    )


if __name__ == "__main__":
    sys.exit(main())
