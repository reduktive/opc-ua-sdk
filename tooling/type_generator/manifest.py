# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Multi-nodeset manifest schema, loader, and validation.

A *manifest* describes every NodeSet participating in a single generator
invocation, and gives each one the C++-facing metadata the emitters need:
include prefix, C++ namespace, CMake target, and whether the generator
should actually emit code for it (vs. use it only for cross-spec type
lookup).

The manifest is a single JSON document.  ``//`` line comments and
``/* ... */`` block comments are stripped before parsing so the file can
carry "why is this URI here?" annotations.

Schema::

    {
      "nodesets": [
        {
          "uri":               "http://opcfoundation.org/UA/",
          "sources":           ["Opc.Ua.NodeSet2.xml",
                                "Opc.Ua.NodeSet2.Services.xml"],
          "nodeids_csv":       "NodeIds.csv",         // optional
          "statuscode_csv":    "StatusCode.csv",      // optional, NS0 only
          "attribute_ids_csv": "AttributeIds.csv",    // optional, NS0 only
          "include_prefix":    "ua_",
          "cpp_namespace":     "ua",
          "target":            "sdk",
          "emit":              false                  // default: true
        }
      ]
    }

Exactly one entry with ``uri = "http://opcfoundation.org/UA/"`` must be
present (NS0 is mandatory because every other NodeSet references its
types).  Source paths are resolved relative to the manifest file's
directory unless absolute.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .nodeset.parse import parse_namespace_uris


def _xml_local_name(tag: str) -> str:
    # ElementTree uses `{namespace}LocalName` form for namespaced tags.
    if tag.startswith("{"):
        closing = tag.find("}")
        if closing != -1:
            return tag[closing + 1:]
    return tag


NS0_URI = "http://opcfoundation.org/UA/"


# -- Cpp identifier / qualified-id grammar -----------------------------------

_CPP_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_CPP_QUALIFIED_ID = re.compile(rf"^{_CPP_IDENT}(::{_CPP_IDENT})*$")
_INCLUDE_PREFIX = re.compile(r"^[a-z][a-z0-9_]*_$")


# -- Comment stripping -------------------------------------------------------


def strip_json_comments(text: str) -> str:
    """Remove ``//`` line comments and ``/* ... */`` block comments from JSON.

    String contents are preserved verbatim - only comments outside strings
    are stripped.  Escape sequences inside strings (``\\"``) are honoured.
    """

    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    in_line_comment = False
    in_block_comment = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            # Preserve newlines so line numbers in errors stay accurate.
            if ch == "\n":
                out.append(ch)
            i += 1
            continue

        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        # Not in string, not in comment.
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


# -- Pydantic models ---------------------------------------------------------


class NodesetConfig(BaseModel):
    """One nodeset's metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uri: str
    sources: list[str]
    nodeids_csv: str | None = None
    statuscode_csv: str | None = None
    attribute_ids_csv: str | None = None
    include_prefix: str
    cpp_namespace: str
    target: str
    emit: bool = True

    # ---- Emission policy (per emit=true entry) -----------------------
    #
    # Data-type emission is implicit: every emit=true spec produces its
    # data-type headers / sources / aggregate / registration.  The
    # fields below select what else gets emitted.

    # Instance-handle generation by category auto-discovery.
    # ``["all"]`` enables every category (the NS0 default).  Empty list
    # = no auto-discovery.  Other entries: specific category names
    # (``"alarms"``, ``"conditions"``, ``"pubsub"`` etc.).
    instance_type_categories: list[str] = []

    # Explicit additions to the auto-discovered instance-type set.
    # BrowseNames (``"FileType"``, ``"FolderType"``).  Useful for
    # pulling in specific types when the consumer doesn't want a whole
    # category.
    instance_type_browse_names: list[str] = []

    # Whether to emit event-type headers + hierarchy.  NS0 sets this
    # to ``true``; downstream specs opt in explicitly.
    emit_event_types: bool = False

    # Whether to amalgamate the data-type / event-type bodies into a small fixed
    # number of sharded ``<prefix>data_types_<k>.cpp`` / ``<prefix>event_types_<k>.cpp``
    # translation units (no single monolithic aggregate is emitted).
    # This is purely an SDK **build-time** optimisation (a few balanced TUs compile
    # faster and more parallel than hundreds of tiny ones) and NS0's manifest sets it ``true``.
    # Consumer specs leave it ``false`` -> one ``.cpp`` per structure / union /
    # event type, the layout a user library wants.  (The registration entry
    # point and the enum / option-set ``to_string`` helpers are inherently
    # cross-cutting and stay single files regardless.)
    amalgamate_sources: bool = False

    @field_validator("uri")
    @classmethod
    def _uri_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("uri must not be empty")
        return v

    @field_validator("sources")
    @classmethod
    def _sources_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("sources must contain at least one path")
        return v

    @field_validator("include_prefix")
    @classmethod
    def _include_prefix_valid(cls, v: str) -> str:
        if not _INCLUDE_PREFIX.match(v):
            raise ValueError(
                f"include_prefix {v!r} must match [a-z][a-z0-9_]*_ "
                f"(lowercase, ends with '_')"
            )
        return v

    @field_validator("cpp_namespace")
    @classmethod
    def _cpp_namespace_valid(cls, v: str) -> str:
        if not _CPP_QUALIFIED_ID.match(v):
            raise ValueError(
                f"cpp_namespace {v!r} must be a C++ qualified-id "
                f"(e.g. 'ua', 'ua::di', 'acme::factory')"
            )
        return v

    @field_validator("target")
    @classmethod
    def _target_valid(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", v):
            raise ValueError(
                f"target {v!r} must be a valid CMake target name "
                f"([A-Za-z_][A-Za-z0-9_]*)"
            )
        return v

    def resolved_sources(self, manifest_dir: Path) -> list[Path]:
        """Sources resolved against the manifest's directory."""
        result: list[Path] = []
        for src in self.sources:
            p = Path(src)
            if not p.is_absolute():
                p = (manifest_dir / p).resolve()
            result.append(p)
        return result


class Manifest(BaseModel):
    """Top-level manifest: a list of nodeset configs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    nodesets: list[NodesetConfig]

    @model_validator(mode="after")
    def _check_invariants(self) -> "Manifest":
        if not self.nodesets:
            raise ValueError("manifest must contain at least one nodeset")

        ns0 = [n for n in self.nodesets if n.uri == NS0_URI]
        if len(ns0) == 0:
            raise ValueError(
                f"manifest must contain exactly one entry with uri={NS0_URI!r} "
                f"(NS0 is required for cross-spec type lookup)"
            )
        if len(ns0) > 1:
            raise ValueError(
                f"manifest has {len(ns0)} entries with uri={NS0_URI!r}; "
                f"exactly one is allowed"
            )

        uris = [n.uri for n in self.nodesets]
        if len(set(uris)) != len(uris):
            dupes = {u for u in uris if uris.count(u) > 1}
            raise ValueError(f"duplicate uri(s) in manifest: {sorted(dupes)}")

        prefixes = [n.include_prefix for n in self.nodesets]
        if len(set(prefixes)) != len(prefixes):
            dupes = {p for p in prefixes if prefixes.count(p) > 1}
            raise ValueError(
                f"duplicate include_prefix(es) in manifest: {sorted(dupes)}"
            )

        cpp_namespaces = [n.cpp_namespace for n in self.nodesets]
        if len(set(cpp_namespaces)) != len(cpp_namespaces):
            dupes = {c for c in cpp_namespaces if cpp_namespaces.count(c) > 1}
            raise ValueError(
                f"duplicate cpp_namespace(s) in manifest: {sorted(dupes)}"
            )

        return self

    def find_by_uri(self, uri: str) -> NodesetConfig | None:
        for n in self.nodesets:
            if n.uri == uri:
                return n
        return None

    def emit_set(self) -> list[NodesetConfig]:
        return [n for n in self.nodesets if n.emit]

    def lookup_set(self) -> list[NodesetConfig]:
        """All nodesets (emit + lookup-only).  Lookup needs every entry."""
        return list(self.nodesets)


# -- Loading -----------------------------------------------------------------


def load_manifest(path: str | Path) -> Manifest:
    """Load and validate a manifest from a JSON-with-comments file.

    Raises ``ValueError`` (via pydantic) for schema violations.
    """

    manifest_path = Path(path)
    raw = manifest_path.read_text(encoding="utf-8")
    cleaned = strip_json_comments(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as ex:
        raise ValueError(
            f"manifest {manifest_path} is not valid JSON: {ex.msg} "
            f"(line {ex.lineno}, col {ex.colno})"
        ) from ex
    return Manifest.model_validate(data)


# -- Cross-validation against the actual NodeSet files -----------------------


def _parse_model_uri(nodeset_path: str | Path) -> str | None:
    """Read ``<Model ModelUri="...">`` from a NodeSet2 file.

    Returns the first model URI found, or ``None`` if the document has no
    ``<Models>`` table.
    """

    for _ev, elem in ET.iterparse(str(nodeset_path), events=("start",)):
        if _xml_local_name(elem.tag) == "Model":
            uri = elem.attrib.get("ModelUri", "").strip()
            return uri or None
    return None


def validate_manifest_against_files(
    manifest: Manifest, manifest_dir: Path
) -> None:
    """Cross-check each manifest entry against its NodeSet files.

    For NS0 (``uri == NS0_URI``), the file's ``<Model ModelUri>`` is
    checked (NS0 has no ``<NamespaceUris>`` table - it IS index 0).

    For every other entry, at least one source must have ``uri`` as the
    first ``<NamespaceUris><Uri>`` entry **or** as its ``<Model
    ModelUri>``.

    Raises ``ValueError`` with a precise message on mismatch.
    """

    for cfg in manifest.nodesets:
        sources = cfg.resolved_sources(manifest_dir)
        for src in sources:
            if not src.exists():
                raise ValueError(
                    f"manifest entry {cfg.uri!r}: source not found: {src}"
                )

        # Collect every URI hint each source advertises.
        hints: set[str] = set()
        for src in sources:
            uris = parse_namespace_uris(str(src))
            if uris:
                hints.add(uris[0])
            model_uri = _parse_model_uri(src)
            if model_uri:
                hints.add(model_uri)

        if cfg.uri == NS0_URI:
            # NS0 file commonly has no <NamespaceUris>; only <Model> is
            # required.
            if NS0_URI not in hints:
                raise ValueError(
                    f"NS0 manifest entry: none of {sources} declare "
                    f"ModelUri={NS0_URI!r} (found hints: {sorted(hints)})"
                )
            continue

        if cfg.uri not in hints:
            raise ValueError(
                f"manifest entry uri={cfg.uri!r}: no source file advertises "
                f"this URI (sources: {[str(s) for s in sources]}; "
                f"found hints: {sorted(hints)})"
            )


