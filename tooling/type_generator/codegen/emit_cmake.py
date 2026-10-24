# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit per-category ``CMakeLists.txt`` files.

One ``CMakeListsEmitter`` per ``EmitContext``.  Each category is a thin
method delegating to one of three shape helpers:

* **PUBLIC headers** - list public headers + ``target_include_directories``.
* **PRIVATE sources** - list private sources + ``target_include_directories``.
* **Fixed PUBLIC list** - single ``target_sources(... PUBLIC <fixed>)`` line.

The CMake target name comes from ``ctx.target_name`` (``sdk`` for NS0,
``ua_di_types`` for DI, etc.).  Output directory is the per-category
interface or implementation dir from ``ctx``.
"""

from __future__ import annotations

from pathlib import Path

from ..io import write_file
from .context import EmitContext


class CMakeListsEmitter:
    """Emits one ``CMakeLists.txt`` per generated category."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    # Per category, the split (NS0) layout writes two CMakeLists - public
    # headers under ``interface/`` and private sources under
    # ``implementation/`` - while the flat (consumer) layout merges both into
    # one CMakeLists in the single category dir.  ``flat_layout`` is the only
    # branch; the split helpers below are byte-identical to the prior output.

    # ---- Data types ---------------------------------------------------

    def emit_data_types(
        self, headers_in_order: list[str], sources_in_order: list[str]
    ) -> list[Path]:
        # The registration header is emitted unconditionally and is not
        # in ``headers_in_order``; append it so CMake lists it too.
        headers = list(headers_in_order) + [
            f"{self._ctx.include_prefix}data_type_registration.h"
        ]
        if self._ctx.flat_layout:
            return [self._emit_flat("data_types", headers, sources_in_order)]
        # NS0: indented ``PUBLIC`` header form (kept distinct from the other
        # categories' inline form for byte-identical output).
        return [
            self._emit_public_headers(
                self._ctx.interface_dir_for("data_types"), headers, "data_types"
            ),
            self._emit_private_sources(
                self._ctx.implementation_dir_for("data_types"),
                sources_in_order,
                "data_types",
            ),
        ]

    # ---- Object / variable / event types ------------------------------

    def emit_object_types(
        self, headers_in_order: list[str], sources_in_order: list[str]
    ) -> list[Path]:
        return self._emit_category("object_types", headers_in_order, sources_in_order)

    def emit_variable_types(
        self, headers_in_order: list[str], sources_in_order: list[str]
    ) -> list[Path]:
        return self._emit_category("variable_types", headers_in_order, sources_in_order)

    def emit_event_types(
        self, headers_in_order: list[str], sources_in_order: list[str]
    ) -> list[Path]:
        return self._emit_category("event_types", headers_in_order, sources_in_order)

    def _emit_category(
        self, category: str, headers: list[str], sources: list[str]
    ) -> list[Path]:
        """Object/variable/event categories: inline ``PUBLIC`` header form."""
        if self._ctx.flat_layout:
            return [self._emit_flat(category, headers, sources)]
        return [
            self._emit_public_headers_flat(
                self._ctx.interface_dir_for(category), headers, category
            ),
            self._emit_private_sources(
                self._ctx.implementation_dir_for(category), sources, category
            ),
        ]

    # ---- Identifier headers (no sources) ------------------------------

    def emit_ids(self, headers_in_order: list[str]) -> list[Path]:
        if self._ctx.flat_layout:
            return [self._emit_flat("ids", headers_in_order, [])]
        return [
            self._emit_public_headers_flat(
                self._ctx.interface_dir_for("ids"), headers_in_order, "ids"
            )
        ]

    # ---- Flat (consumer) root -----------------------------------------

    def emit_flat_root(self, categories: list[str]) -> Path:
        """Root ``CMakeLists.txt`` for the flat tree - ``add_subdirectory`` per
        emitted category, so a consumer can ``add_subdirectory(<output>)``."""
        lines = [f"add_subdirectory({category})\n" for category in categories]
        out_path = self._ctx.output_root / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path

    # ---- Status -------------------------------------------------------

    def emit_interface_status(self) -> Path:
        target = self._ctx.target_for("status")
        return self._emit_fixed_public(
            self._ctx.interface_dir_for("status"),
            f"target_sources({target} PUBLIC ua_status.h ua_status_to_string.h)\n",
            "status",
        )

    def emit_implementation_status(self) -> Path:
        return self._emit_private_sources(
            self._ctx.implementation_dir_for("status"),
            ["ua_status_to_string.cpp"],
            "status",
        )

    # ---- NS0 byte array (NS0-only) ------------------------------------

    def emit_interface_ns0(self) -> Path:
        target = self._ctx.target_for("ns0")
        return self._emit_fixed_public(
            self._ctx.interface_dir_for("ns0"),
            f"target_sources({target} PUBLIC nodeset_ns0.h)\n",
            "ns0",
        )

    def emit_implementation_ns0(self) -> Path:
        return self._emit_private_sources(
            self._ctx.implementation_dir_for("ns0"),
            ["nodeset_ns0.cpp"],
            "ns0",
        )

    # ---- NS0 type-model tables (NS0-only) ------------------------------

    def emit_implementation_ns0_model(self) -> Path:
        return self._emit_private_sources(
            self._ctx.implementation_dir_for("ns0_model"),
            ["ua_namespace_zero_tables.cpp"],
            "ns0_model",
        )

    # ---- Shape helpers ------------------------------------------------

    def _emit_public_headers(
        self, output_dir: Path, headers_in_order: list[str], category: str
    ) -> Path:
        """``target_sources(<tgt>\\n        PUBLIC\\n        ...)`` form."""
        target = self._ctx.target_for(category)
        lines: list[str] = []
        lines.append(f"target_sources({target}\n")
        lines.append("        PUBLIC\n")
        for h in headers_in_order:
            lines.append(f"        {h}\n")
        lines.append(")\n")
        lines.append("\n")
        lines.append("\n")
        lines.append(f"target_include_directories({target} PUBLIC .)\n")
        lines.append("\n")

        out_path = output_dir / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path

    def _emit_public_headers_flat(
        self, output_dir: Path, headers_in_order: list[str], category: str
    ) -> Path:
        """``target_sources(<tgt> PUBLIC\\n        ...)`` form (no extra indent)."""
        target = self._ctx.target_for(category)
        lines: list[str] = []
        lines.append(f"target_sources({target} PUBLIC\n")
        for h in headers_in_order:
            lines.append(f"        {h}\n")
        lines.append(")\n")
        lines.append("\n")
        lines.append(f"target_include_directories({target} PUBLIC .)\n")
        lines.append("\n")

        out_path = output_dir / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path

    def _emit_private_sources(
        self, output_dir: Path, sources_in_order: list[str], category: str
    ) -> Path:
        """``target_sources(<tgt> PUBLIC) ... target_sources(<tgt> PRIVATE ...)``."""
        target = self._ctx.target_for(category)
        lines: list[str] = []
        lines.append(f"target_sources({target} PUBLIC)\n")
        lines.append("\n")
        lines.append(f"target_sources({target} PRIVATE\n")
        for s in sources_in_order:
            lines.append(f"        {s}\n")
        lines.append(")\n")
        lines.append("\n")
        # The SDK's own private folders: PRIVATE to the library, shared through uasdk-internal (public
        # API review item 1, API-1.1). Only the namespace-0 split layout builds an SDK library.
        lines.append(f"uasdk_private_include_directory({target})\n")
        lines.append("\n")

        out_path = output_dir / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path

    def _emit_flat(
        self, category: str, headers: list[str], sources: list[str]
    ) -> Path:
        """Single merged CMakeLists for one category in the flat layout.

        Headers and sources co-locate in one dir, so one ``target_sources``
        lists both (``PUBLIC`` headers for IDEs / install, ``PRIVATE`` sources
        to compile) plus the include dir.
        """
        output_dir = self._ctx.interface_dir_for(category)  # == implementation dir
        target = self._ctx.target_for(category)
        lines: list[str] = [f"target_sources({target}\n"]
        if headers:
            lines.append("        PUBLIC\n")
            for h in headers:
                lines.append(f"        {h}\n")
        if sources:
            lines.append("        PRIVATE\n")
            for s in sources:
                lines.append(f"        {s}\n")
        lines.append(")\n")
        lines.append("\n")
        lines.append(f"target_include_directories({target} PUBLIC .)\n")

        out_path = output_dir / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path

    def _emit_fixed_public(
        self, output_dir: Path, header_line: str, category: str
    ) -> Path:
        """``<header_line>`` then ``target_include_directories``.

        ``header_line`` is the fully-formed ``target_sources(...)`` line (the
        caller builds it with the per-category layer target); ``category`` only
        selects the matching ``target_include_directories`` target so both lines
        name the same layer lib.
        """
        target = self._ctx.target_for(category)
        lines: list[str] = []
        lines.append(header_line)
        lines.append("\n")
        lines.append(f"target_include_directories({target} PUBLIC .)\n")
        lines.append("\n")

        out_path = output_dir / "CMakeLists.txt"
        write_file(out_path, "".join(lines))
        return out_path
