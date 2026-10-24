# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

add_subdirectory(discovery)

if (TARGET reference_demo_model)
    target_sources(tests PRIVATE reference_demo_model_tests.cpp)
    target_link_libraries(tests PRIVATE reference_demo_model)
    target_compile_definitions(tests PRIVATE
        UA_REFERENCE_DEMO_MODEL_PATH="${CMAKE_SOURCE_DIR}/examples/reference_server/model/Reduktive.ReferenceServer.NodeSet2.xml")
endif ()
