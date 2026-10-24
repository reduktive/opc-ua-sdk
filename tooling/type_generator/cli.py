# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

import argparse
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Options:
    manifest: str
    output: str | None
    list_datatypes: bool
    clang_format_config: str | None


def parse_args(argv: list[str]) -> Options:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to a multi-nodeset manifest (JSON with // and /* */ "
             "comments).  Sole input shape: the manifest describes every "
             "nodeset in scope, its C++ metadata, and (per emit=true entry) "
             "what to emit - data types, instance handles, event types.",
    )
    parser.add_argument(
        "--output",
        required=False,
        help="Directory to place generated types.",
    )
    parser.add_argument(
        "--list-datatypes",
        action="store_true",
        help="List UADataType nodes found across every nodeset in the "
             "manifest and exit.",
    )
    parser.add_argument(
        "--clang-format-config",
        required=False,
        help="Path to .clang-format config file (default: discover from "
             "repo root).",
    )

    ns = parser.parse_args(argv)

    if not ns.list_datatypes and ns.output is None:
        parser.error("--output is required (unless --list-datatypes is used)")

    return Options(
        manifest=str(ns.manifest),
        output=ns.output,
        list_datatypes=bool(ns.list_datatypes),
        clang_format_config=ns.clang_format_config,
    )
