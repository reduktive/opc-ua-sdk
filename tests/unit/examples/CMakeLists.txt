# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# The example support library is built only with UASDK_BUILD_EXAMPLES; its tests follow it.
if (TARGET example_support)
    target_sources(tests PRIVATE
            example_pki_tests.cpp)
    target_link_libraries(tests PRIVATE example_support)
endif ()
