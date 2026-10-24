# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Companion-spec discovery driver (codegen matrix, phase 1).

Scans a UA-Nodeset checkout, builds a registry of every ``<Model ModelUri>``
each NodeSet *provides*, resolves each spec's ``<RequiredModel>`` dependencies
transitively against that registry, and emits an ordered build plan plus a
pass/skip report.

The plan it produces is the single source of truth consumed by the CMake matrix
(phase 2): for every *generatable* spec it carries the emit source(s), NodeIds
CSV, derived ``ua::<slug>`` namespace / ``ua_<slug>_`` include prefix, and the
ordered list of cross-spec lookup dependencies (which become ``LOOKUP_SPECS``
5-tuples). Specs whose dependencies cannot be satisfied from the checkout are
recorded as *skipped* with the precise missing ModelUri(s) - no guessing, no
silent omission.

Keying is by parsed ``ModelUri``, never by directory name: e.g. the
``ISA95-JOBCONTROL/`` directory provides ModelUri ``.../ISA95-JOBCONTROL_V2/``,
and NodeIds CSV casing varies across specs.

Standalone (no third-party deps beyond the stdlib + the repo's ``NS0_URI``).
Invoke via::

    python -m tooling.type_generator.companion_matrix \\
        --root <uanodeset-src> --out plan.json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from .manifest import NS0_URI


# ---- XML helpers -----------------------------------------------------------


def _xml_local_name(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from an ElementTree tag."""
    if tag.startswith("{"):
        closing = tag.find("}")
        if closing != -1:
            return tag[closing + 1:]
    return tag


@dataclasses.dataclass(frozen=True)
class ModelDecl:
    """One ``<Model>`` element: the URI it provides + the URIs it requires."""

    uri: str
    required_uris: tuple[str, ...]


def parse_models(nodeset_path: Path) -> list[ModelDecl]:
    """Return every ``<Model>`` declared in a NodeSet2 file.

    A NodeSet may declare more than one ``<Model>`` (multi-model files); each
    carries its own nested ``<RequiredModel>`` entries.
    """

    models: list[ModelDecl] = []
    current_uri: str | None = None
    current_reqs: list[str] = []

    for event, elem in ET.iterparse(str(nodeset_path), events=("start", "end")):
        local = _xml_local_name(elem.tag)
        if event == "start" and local == "Model":
            current_uri = elem.attrib.get("ModelUri", "").strip() or None
            current_reqs = []
        elif event == "start" and local == "RequiredModel":
            req = elem.attrib.get("ModelUri", "").strip()
            if req:
                current_reqs.append(req)
        elif event == "end" and local == "Model":
            if current_uri:
                models.append(ModelDecl(current_uri, tuple(current_reqs)))
            current_uri = None
            current_reqs = []
    return models


# ---- NodeIds CSV discovery -------------------------------------------------

_NODESET_SUFFIX_RE = re.compile(r"\.nodeset2\.xml$", re.IGNORECASE)
# A NodeIds CSV is ``BrowseName,NumericId,NodeClass`` - used to content-validate
# a candidate whose filename doesn't follow a recognised naming convention.
_NODECLASS_TOKENS = frozenset({
    "object", "objecttype", "variable", "variabletype", "datatype",
    "referencetype", "method", "view",
})


def _looks_like_nodeids(path: Path) -> bool:
    """True if the file's first data rows look like a NodeIds table."""
    try:
        with path.open(encoding="utf-8", errors="ignore") as handle:
            for _ in range(5):
                line = handle.readline()
                if not line:
                    break
                fields = line.rstrip("\n").split(",")
                if len(fields) == 3 and fields[2].strip().lower() in _NODECLASS_TOKENS:
                    return True
    except OSError:
        return False
    return False


def find_nodeids_csv(nodeset_path: Path) -> Path | None:
    """Locate the NodeIds CSV paired with a NodeSet file, or ``None``.

    Naming is wildly inconsistent across the OPC companion specs, so this tries,
    in order: the standard ``<stem>.NodeIds.csv``; ``<stem>.csv`` /
    ``<stem>.nodeset2.csv`` (FX-style); a bare ``NodeIds.csv``; any name carrying
    ``nodeid`` (or the ``nodesid`` typo, e.g. GMS); finally a lone CSV that
    content-validates as a NodeIds table (e.g. ADI's ``OpcUaAdiModel.csv``). All
    case-insensitive; ``*documentation*`` and ``*.examples.csv`` are excluded.
    A multi-CSV directory with no name match stays unpaired (``None``) rather
    than risk grabbing the wrong model's IDs.
    """

    name = nodeset_path.name
    if not _NODESET_SUFFIX_RE.search(name):
        return None
    stem = _NODESET_SUFFIX_RE.sub("", name)

    csvs: dict[str, Path] = {}
    for candidate in nodeset_path.parent.iterdir():
        if not candidate.is_file() or candidate.suffix.lower() != ".csv":
            continue
        low = candidate.name.lower()
        if "documentation" in low or ".examples." in low:
            continue
        csvs[low] = candidate
    if not csvs:
        return None

    for named in (f"{stem}.nodeids.csv", f"{stem}.csv",
                  f"{stem}.nodeset2.csv", "nodeids.csv"):
        hit = csvs.get(named.lower())
        if hit is not None:
            return hit

    for low in sorted(csvs):
        if "nodeid" in low or "nodesid" in low:
            return csvs[low]

    if len(csvs) == 1:
        only = next(iter(csvs.values()))
        return only if _looks_like_nodeids(only) else None

    validated = [p for p in csvs.values() if _looks_like_nodeids(p)]
    return validated[0] if len(validated) == 1 else None


# ---- Naming derivation -----------------------------------------------------

_NON_IDENT_RE = re.compile(r"[^0-9A-Za-z]+")
_SCHEME_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]+)(/.*)?$")
# Host labels that carry no identifying value (TLDs, www) - dropped when a URI
# has to fall back to its host for a name.
_NOISE_HOST_LABELS = frozenset({"www", "org", "com", "net", "io", "opcfoundation"})


def derive_slug(uri: str) -> str:
    """Derive a stable, readable C++-identifier slug from a ModelUri.

    ``http://opcfoundation.org/UA/DI/`` -> ``di``;
    ``.../UA/Machinery/Jobs/`` -> ``machinery_jobs``;
    ``.../UA/ISA95-JOBCONTROL_V2/`` -> ``isa95_jobcontrol_v2``;
    ``.../UA/2013/01/ISA95`` -> ``isa95`` (date segments dropped);
    ``http://sercos.org/UA/`` -> ``sercos`` (path is only the ``UA`` marker, so
    the host's primary label names the spec).
    """

    match = _SCHEME_HOST_RE.match(uri)
    if match:
        host, path = match.group(1), match.group(2) or ""
    else:
        host, path = "", uri

    segments = [s for s in re.split(r"/+", path) if s]
    if segments and segments[0].lower() == "ua":
        segments = segments[1:]  # drop the leading ``UA`` namespace marker
    segments = [s for s in segments if not s.isdigit()]  # drop date/version ints

    if not segments:
        # Path carried no name (e.g. ".../UA/"): fall back to the host's primary
        # label. ``sercos.org`` -> ``sercos``; strip port and noise labels.
        label = host.split(":", 1)[0]
        parts = [p for p in label.split(".") if p and p.lower() not in _NOISE_HOST_LABELS]
        segments = parts[:1] or ([label] if label else [])

    slug = _NON_IDENT_RE.sub("_", "_".join(segments)).strip("_").lower()
    if not slug:
        slug = _NON_IDENT_RE.sub("_", uri).strip("_").lower()
    if slug and slug[0].isdigit():
        slug = "_" + slug
    return slug


def names_for_slug(slug: str) -> tuple[str, str, str]:
    """``slug`` -> (cpp_namespace, include_prefix, cmake_target)."""
    return (f"ua::{slug}", f"ua_{slug}_", f"ua_{slug}_types")


# ---- Registry --------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ModelFile:
    """A model provided by a concrete NodeSet file in the checkout."""

    uri: str
    path: Path
    nodeids_csv: Path | None
    required_uris: tuple[str, ...]
    is_example: bool


def _is_example_file(path: Path) -> bool:
    """Heuristic: example/instance NodeSets carry instances, not type defs."""
    return "example" in path.name.lower()


def build_registry(root: Path) -> dict[str, ModelFile]:
    """Map every provided ModelUri -> the file that provides it.

    Scans all ``*.NodeSet2.xml`` under ``root``. When a URI is provided by more
    than one file, a non-example provider wins over an example one, and among
    equals the shortest path wins (prefers the canonical top-level NodeSet over
    nested/versioned copies) - deterministic regardless of filesystem order.
    """

    registry: dict[str, ModelFile] = {}
    # Case-insensitive: the checkout mixes ``.NodeSet2.xml``, ``.Nodeset2.xml``
    # and ``.nodeset2.xml`` casing. A case-sensitive glob silently drops the
    # lowercase variants (e.g. Machinery/Jobs, ISA95-JOBCONTROL, UAFX), which
    # then surface as bogus "unresolved required model" skips downstream.
    files = sorted(
        (
            p
            for p in root.rglob("*")
            if p.is_file() and p.name.lower().endswith(".nodeset2.xml")
        ),
        key=lambda p: str(p).lower(),
    )
    for path in files:
        is_example = _is_example_file(path)
        csv = find_nodeids_csv(path)
        try:
            models = parse_models(path)
        except ET.ParseError:
            continue
        for model in models:
            entry = ModelFile(
                uri=model.uri,
                path=path,
                nodeids_csv=csv,
                required_uris=model.required_uris,
                is_example=is_example,
            )
            existing = registry.get(model.uri)
            if existing is None or _prefer(entry, existing):
                registry[model.uri] = entry
    return registry


def _prefer(candidate: ModelFile, incumbent: ModelFile) -> bool:
    """True if ``candidate`` should replace ``incumbent`` as a URI's provider."""
    if candidate.is_example != incumbent.is_example:
        return not candidate.is_example  # non-example wins
    cand_key = (len(str(candidate.path)), str(candidate.path).lower())
    inc_key = (len(str(incumbent.path)), str(incumbent.path).lower())
    return cand_key < inc_key


# ---- Out-of-scope specs ----------------------------------------------------

# OPC UA FX (Field eXchange) is architecturally built on OPC UA PubSub: its
# types reference PubSub-category data types that this SDK version deliberately
# does not generate. Such specs cannot compile and are not generator bugs, so
# they are reported as skipped-by-design rather than failing. Revisit if/when
# PubSub support lands.
_PUBSUB_UNSUPPORTED_URI_SUBSTRINGS = ("/UA/FX/",)


def _requires_unsupported_pubsub(uri: str) -> bool:
    return any(s in uri for s in _PUBSUB_UNSUPPORTED_URI_SUBSTRINGS)


# ---- Dependency resolution -------------------------------------------------


@dataclasses.dataclass
class LookupDep:
    """An emit=false cross-spec dependency (becomes a LOOKUP_SPECS tuple)."""

    uri: str
    slug: str
    cpp_namespace: str
    include_prefix: str
    nodeids_csv: str | None
    sources: list[str]  # POSIX paths relative to root


@dataclasses.dataclass
class GeneratableSpec:
    uri: str
    slug: str
    cpp_namespace: str
    include_prefix: str
    target: str
    sources: list[str]            # relative to root
    nodeids_csv: str | None       # relative to root, or None
    lookup_specs: list[LookupDep]  # ordered: dependencies first
    is_example: bool


@dataclasses.dataclass
class SkippedSpec:
    uri: str
    slug: str
    reason: str
    missing: list[str]


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _ordered_dependencies(
    uri: str, registry: dict[str, ModelFile]
) -> tuple[list[str], list[str]]:
    """Transitive non-NS0 deps of ``uri`` in dependency order, + missing URIs.

    Returns ``(ordered_uris, missing_uris)``. ``ordered_uris`` lists every
    transitive requirement (excluding NS0 and ``uri`` itself) with dependencies
    before dependents. ``missing_uris`` names any required URI absent from the
    registry - when non-empty the spec is unresolvable.
    """

    ordered: list[str] = []
    seen: set[str] = set()
    missing: list[str] = []
    missing_seen: set[str] = set()
    on_stack: set[str] = set()

    def visit(node: str) -> None:
        provider = registry.get(node)
        if provider is None:
            if node not in missing_seen:
                missing_seen.add(node)
                missing.append(node)
            return
        for req in provider.required_uris:
            if req == NS0_URI or req == node:
                continue
            if req in on_stack:
                continue  # defensive: ignore dependency cycles
            if req not in seen:
                on_stack.add(req)
                visit(req)
                on_stack.discard(req)
        if node not in seen:
            seen.add(node)
            ordered.append(node)

    provider = registry.get(uri)
    if provider is not None:
        for req in provider.required_uris:
            if req == NS0_URI or req == uri:
                continue
            on_stack.add(req)
            visit(req)
            on_stack.discard(req)
    return ordered, missing


def _slug_table(uris: list[str]) -> dict[str, str]:
    """Assign a unique slug to each URI, deduping collisions deterministically."""
    table: dict[str, str] = {}
    used: set[str] = set()
    for uri in sorted(uris):
        base = derive_slug(uri)
        slug = base
        suffix = 2
        while slug in used:
            slug = f"{base}_{suffix}"
            suffix += 1
        used.add(slug)
        table[uri] = slug
    return table


@dataclasses.dataclass
class MatrixPlan:
    root: str
    ns0_uri: str
    generatable: list[GeneratableSpec]
    skipped: list[SkippedSpec]

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "ns0_uri": self.ns0_uri,
            "stats": {
                "total": len(self.generatable) + len(self.skipped),
                "generatable": len(self.generatable),
                "skipped": len(self.skipped),
            },
            "generatable": [dataclasses.asdict(s) for s in self.generatable],
            "skipped": [dataclasses.asdict(s) for s in self.skipped],
        }


def discover(root: Path, include_examples: bool = False) -> MatrixPlan:
    """Build the full generate/skip plan for every spec the checkout provides."""

    registry = build_registry(root)

    # Emit candidates: every provided non-NS0 model whose canonical provider is
    # a type-defining (non-example) NodeSet. Stable slug assigned per URI.
    candidate_uris = [
        uri
        for uri, mf in registry.items()
        if uri != NS0_URI and (include_examples or not mf.is_example)
    ]
    # NS0 is the always-present base (never emitted, never a lookup), so it takes
    # no slug - keep it out of the table so it can't reserve a name a real spec
    # wants (e.g. block ``http://sercos.org/UA/`` from being forced to ``ua_2``).
    slugs = _slug_table([uri for uri in registry if uri != NS0_URI])

    generatable: list[GeneratableSpec] = []
    skipped: list[SkippedSpec] = []

    for uri in candidate_uris:
        mf = registry[uri]
        ordered_deps, missing = _ordered_dependencies(uri, registry)
        slug = slugs[uri]
        if _requires_unsupported_pubsub(uri):
            skipped.append(
                SkippedSpec(
                    uri=uri,
                    slug=slug,
                    reason="requires PubSub (not supported in this SDK version)",
                    missing=[],
                )
            )
            continue
        if missing:
            skipped.append(
                SkippedSpec(
                    uri=uri,
                    slug=slug,
                    reason="unresolved required model(s): " + ", ".join(missing),
                    missing=missing,
                )
            )
            continue

        lookups: list[LookupDep] = []
        for dep_uri in ordered_deps:
            dep_mf = registry[dep_uri]
            dep_ns, dep_prefix, _ = names_for_slug(slugs[dep_uri])
            lookups.append(
                LookupDep(
                    uri=dep_uri,
                    slug=slugs[dep_uri],
                    cpp_namespace=dep_ns,
                    include_prefix=dep_prefix,
                    nodeids_csv=(
                        _rel(dep_mf.nodeids_csv, root)
                        if dep_mf.nodeids_csv
                        else None
                    ),
                    sources=[_rel(dep_mf.path, root)],
                )
            )

        namespace, prefix, target = names_for_slug(slug)
        generatable.append(
            GeneratableSpec(
                uri=uri,
                slug=slug,
                cpp_namespace=namespace,
                include_prefix=prefix,
                target=target,
                sources=[_rel(mf.path, root)],
                nodeids_csv=_rel(mf.nodeids_csv, root) if mf.nodeids_csv else None,
                lookup_specs=lookups,
                is_example=mf.is_example,
            )
        )

    # Global emit order: dependencies before dependents (topological). A spec's
    # lookup_specs are already locally ordered; sort the spec list so any spec
    # appears after all specs it depends on.
    generatable = _topo_order(generatable)

    generatable.sort(key=lambda s: s.slug)  # secondary: stable display only
    generatable = _topo_order(generatable)  # re-assert topo after stable sort

    return MatrixPlan(
        root=str(root),
        ns0_uri=NS0_URI,
        generatable=generatable,
        skipped=sorted(skipped, key=lambda s: s.slug),
    )


def _topo_order(specs: list[GeneratableSpec]) -> list[GeneratableSpec]:
    """Order specs so each appears after every spec it depends on."""
    by_uri = {s.uri: s for s in specs}
    ordered: list[GeneratableSpec] = []
    placed: set[str] = set()

    def place(spec: GeneratableSpec, stack: set[str]) -> None:
        if spec.uri in placed or spec.uri in stack:
            return
        stack.add(spec.uri)
        for dep in spec.lookup_specs:
            dep_spec = by_uri.get(dep.uri)
            if dep_spec is not None:
                place(dep_spec, stack)
        stack.discard(spec.uri)
        if spec.uri not in placed:
            placed.add(spec.uri)
            ordered.append(spec)

    for spec in specs:
        place(spec, set())
    return ordered


# ---- CLI -------------------------------------------------------------------


def _format_summary(plan: MatrixPlan) -> str:
    lines: list[str] = []
    stats = plan.to_dict()["stats"]
    lines.append(
        f"Companion-spec matrix: {stats['generatable']} generatable, "
        f"{stats['skipped']} skipped (of {stats['total']})"
    )
    lines.append("")
    lines.append("Generatable (emit order):")
    for spec in plan.generatable:
        deps = ", ".join(d.slug for d in spec.lookup_specs) or "-"
        csv = "csv" if spec.nodeids_csv else "NO-CSV"
        lines.append(f"  {spec.slug:<28} {csv:<7} deps: {deps}")
    if plan.skipped:
        lines.append("")
        lines.append("Skipped:")
        for spec in plan.skipped:
            lines.append(f"  {spec.slug:<28} {spec.reason}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", required=True, type=Path,
        help="UA-Nodeset checkout root (the directory of spec subdirs).",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Write the JSON plan to this path (default: stdout summary only).",
    )
    parser.add_argument(
        "--include-examples", action="store_true",
        help="Also emit example/instance NodeSets as generation targets.",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress the human summary.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"companion_matrix: --root not a directory: {root}", file=sys.stderr)
        return 2

    plan = discover(root, include_examples=args.include_examples)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    if not args.quiet:
        print(_format_summary(plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
