# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations


def get_part(parts_text: str, placeholder: str) -> str:
    begin = f"{placeholder}_BEGIN"
    end = f"{placeholder}_END"

    start = parts_text.find(begin)
    if start == -1:
        raise KeyError(begin)
    start = start + len(begin)

    stop = parts_text.find(end, start)
    if stop == -1:
        raise KeyError(end)

    # Match C++ `get_part()`: return the substring exactly as-is.
    return parts_text[start:stop]
