# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Synthesise a JSON manifest from inline arguments.

Used by the ``ua_generate_types()`` CMake helper when the consumer
passes ``NODESETS`` / ``EMIT_FROM`` / ``CPP_NAMESPACE`` / etc. instead
of supplying a pre-authored manifest file.  Output is a JSON manifest
the type generator can consume directly.

Typical invocation::

    python -m tooling.type_generator.synthesise_manifest \\
        --out          manifest.json \\
        --ns0-sources  /path/to/Opc.Ua.NodeSet2.xml,/path/to/Opc.Ua.NodeSet2.Services.xml \\
        --ns0-nodeids-csv /path/to/NodeIds.csv \\
        --emit-source  /path/to/Opc.Ua.Di.NodeSet2.xml \\
        --emit-cpp-namespace ua::di \\
        --emit-include-prefix ua_di_ \\
        --emit-target  ua_di_types

The NS0 entry is always emitted as ``emit=false`` (lookup only) when
present in ``--ns0-sources`` and the consumer also supplies emit
sources - that's the standard "downstream spec depending on NS0"
shape.  Single-NS0 manifests (``--emit-source`` resolves to NS0 itself)
are also supported.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from .manifest import NS0_URI


# ---- Argument parsing -----------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synthesise a type-generator manifest from inline args.",
    )
    parser.add_argument(
        "--out", required=True,
        help="Output path for the synthesised JSON manifest.",
    )

    # NS0 (lookup-only, optional but recommended for any downstream spec).
    parser.add_argument(
        "--ns0-sources",
        help="Comma-separated NS0 NodeSet2 source paths (lookup only).",
    )
    parser.add_argument("--ns0-nodeids-csv", default=None)
    parser.add_argument("--ns0-statuscode-csv", default=None)
    parser.add_argument("--ns0-attribute-ids-csv", default=None)

    # Intermediate lookup specs (emit=false) for multi-level stacks - e.g. when
    # emitting IA (which depends on DI), DI is a lookup spec so cross-spec refs
    # resolve to ``ua::di::*``. Repeatable. Each value is a pipe-delimited
    # 5-tuple:  uri|cpp_namespace|include_prefix|nodeids_csv|src1,src2,...
    # (nodeids_csv may be empty). NS0 is added separately via --ns0-sources.
    parser.add_argument(
        "--lookup-spec", action="append", default=[], dest="lookup_specs",
        help="An emit=false lookup spec as "
             "'uri|cpp_namespace|include_prefix|nodeids_csv|comma-sep-sources'. "
             "Repeat for each intermediate spec in a multi-level stack.",
    )

    # Emit spec - what we're actually generating.
    parser.add_argument(
        "--emit-source", action="append", default=[],
        help="NodeSet2 source path for the emit-target spec. Repeat for "
             "multiple sources of one spec.",
    )
    parser.add_argument("--emit-uri", default=None,
        help="Spec URI.  If omitted, auto-detected from the first source's "
             "<NamespaceUris> or <Model ModelUri>.")
    parser.add_argument("--emit-nodeids-csv", default=None)
    parser.add_argument("--emit-cpp-namespace", required=True)
    parser.add_argument("--emit-include-prefix", required=True)
    parser.add_argument("--emit-target", required=True)

    # Emission policy (per emit spec).  Defaults match the manifest
    # defaults - no instance handles, no event types - so a downstream
    # consumer that just wants data types invokes ua_generate_types()
    # without these args.
    parser.add_argument(
        "--emit-instance-categories", default="",
        help="Comma-separated category names for instance-type "
             "auto-discovery.  ``all`` enables every category.  Empty = "
             "no auto-discovery.",
    )
    parser.add_argument(
        "--emit-instance-browse-names", default="",
        help="Comma-separated BrowseNames to add to the instance-type "
             "set (in addition to category auto-discovery).",
    )
    parser.add_argument(
        "--emit-event-types", action="store_true",
        help="Emit event-type headers + hierarchy.",
    )

    return parser.parse_args(argv)


# ---- URI auto-detection ---------------------------------------------------


def _local_name(tag: str) -> str:
    if tag.startswith("{"):
        closing = tag.find("}")
        if closing != -1:
            return tag[closing + 1:]
    return tag


def _detect_uri(nodeset_path: str) -> str | None:
    """Return the first ``<NamespaceUris><Uri>`` or ``<Model ModelUri>``."""
    in_ns_uris = False
    for event, elem in ET.iterparse(nodeset_path, events=("start", "end")):
        local = _local_name(elem.tag)
        if event == "start":
            if local == "NamespaceUris":
                in_ns_uris = True
            elif local == "Uri" and in_ns_uris:
                text = (elem.text or "").strip()
                if text:
                    return text
            elif local == "Model":
                # ``<Model>`` appears after ``<NamespaceUris>``.  Fall back
                # to it only if we haven't seen a Uri yet.
                uri = elem.attrib.get("ModelUri", "").strip()
                if uri:
                    return uri
        elif event == "end" and local == "NamespaceUris":
            in_ns_uris = False
    return None


# ---- Manifest building ----------------------------------------------------


def _build_manifest(args: argparse.Namespace) -> dict:
    nodesets: list[dict] = []

    # NS0 entry - always present in multi-spec runs.  For single-spec NS0
    # generation, the caller passes the NS0 sources as ``--emit-source``
    # instead and ``--ns0-sources`` is omitted; we detect that below.
    has_ns0_lookup = bool(args.ns0_sources)

    emit_uri = args.emit_uri
    if emit_uri is None:
        if not args.emit_source:
            raise SystemExit(
                "synthesise_manifest: --emit-uri omitted and no --emit-source "
                "to auto-detect from"
            )
        detected = _detect_uri(args.emit_source[0])
        if detected is None:
            raise SystemExit(
                f"synthesise_manifest: could not auto-detect URI from "
                f"{args.emit_source[0]}; supply --emit-uri explicitly"
            )
        emit_uri = detected

    # If we're emitting NS0 itself, skip the lookup-only NS0 entry and
    # flip the emit one to NS0-shaped.
    emitting_ns0 = (emit_uri == NS0_URI)

    if has_ns0_lookup and not emitting_ns0:
        ns0_sources = [p for p in args.ns0_sources.split(",") if p]
        ns0_entry: dict = {
            "uri": NS0_URI,
            "sources": ns0_sources,
            "include_prefix": "ua_",
            "cpp_namespace": "ua",
            "target": "sdk",
            "emit": False,
        }
        if args.ns0_nodeids_csv:
            ns0_entry["nodeids_csv"] = args.ns0_nodeids_csv
        if args.ns0_statuscode_csv:
            ns0_entry["statuscode_csv"] = args.ns0_statuscode_csv
        if args.ns0_attribute_ids_csv:
            ns0_entry["attribute_ids_csv"] = args.ns0_attribute_ids_csv
        nodesets.append(ns0_entry)

    # Intermediate lookup specs (emit=false) for multi-level stacks, in the
    # order supplied (dependencies should precede dependents, though the index
    # is order-independent for lookup).
    for raw in args.lookup_specs:
        parts = raw.split("|")
        if len(parts) != 5:
            raise SystemExit(
                "synthesise_manifest: --lookup-spec must have 5 pipe-delimited "
                f"fields 'uri|cpp_namespace|include_prefix|nodeids_csv|sources', got: {raw!r}"
            )
        uri, cpp_namespace, include_prefix, nodeids_csv, sources_csv = parts
        sources = [p for p in sources_csv.split(",") if p]
        if not uri or not cpp_namespace or not include_prefix or not sources:
            raise SystemExit(
                f"synthesise_manifest: --lookup-spec missing required field(s): {raw!r}"
            )
        # target is metadata only for a lookup (emit=false) spec - it is not
        # built in this run - but must be a valid CMake target name. Derive it
        # from the include prefix so it is stable and unique.
        lookup_target = include_prefix.rstrip("_") + "_lookup" if include_prefix else "lookup"
        lookup_entry: dict = {
            "uri": uri,
            "sources": sources,
            "include_prefix": include_prefix,
            "cpp_namespace": cpp_namespace,
            "target": lookup_target,
            "emit": False,
        }
        if nodeids_csv:
            lookup_entry["nodeids_csv"] = nodeids_csv
        nodesets.append(lookup_entry)

    categories = [c.strip() for c in args.emit_instance_categories.split(",") if c.strip()]
    browse_names = [b.strip() for b in args.emit_instance_browse_names.split(",") if b.strip()]

    emit_entry: dict = {
        "uri": emit_uri,
        "sources": args.emit_source,
        "include_prefix": args.emit_include_prefix,
        "cpp_namespace": args.emit_cpp_namespace,
        "target": args.emit_target,
        "emit": True,
        "instance_type_categories": categories,
        "instance_type_browse_names": browse_names,
        "emit_event_types": bool(args.emit_event_types),
    }
    if args.emit_nodeids_csv:
        emit_entry["nodeids_csv"] = args.emit_nodeids_csv
    if emitting_ns0:
        # When the emit target IS NS0, fold in the NS0-only CSVs the
        # consumer would otherwise have passed via --ns0-*.
        if args.ns0_nodeids_csv:
            emit_entry["nodeids_csv"] = args.ns0_nodeids_csv
        if args.ns0_statuscode_csv:
            emit_entry["statuscode_csv"] = args.ns0_statuscode_csv
        if args.ns0_attribute_ids_csv:
            emit_entry["attribute_ids_csv"] = args.ns0_attribute_ids_csv
        # NS0 is the SDK self-host: amalgamate the data-type / event-type bodies
        # into single TUs (build-time optimisation).  Consumer specs leave this
        # off -> one .cpp per type.  See NodesetConfig.amalgamate_sources.
        emit_entry["amalgamate_sources"] = True

    nodesets.append(emit_entry)

    return {"nodesets": nodesets}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = _parse_args(argv)
    manifest = _build_manifest(args)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
