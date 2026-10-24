# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# The type generator needs Python3 + the UA-Nodeset checkout. Generated sources are
# committed, so it is only wired in for a developer/regeneration build; a consumer
# build (UASDK_REGENERATE_TYPES OFF) omits the target entirely.
if (UASDK_REGENERATE_TYPES)
    add_subdirectory(type_generator)
endif ()
if (BUILD_FUZZER)
    add_subdirectory(fuzzer)
endif ()