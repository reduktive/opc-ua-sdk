# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

add_subdirectory(types)
add_subdirectory(codecs)
add_subdirectory(async)
add_subdirectory(security)
add_subdirectory(server)
add_subdirectory(address_space)
add_subdirectory(transport)
add_subdirectory(general)
if (TARGET client_unit_tests)
    get_target_property(_uasdk_sources_before_client tests SOURCES)
endif ()
add_subdirectory(client)
if (TARGET client_unit_tests)
    # Child lists still describe the same client sources and their helper include directories.
    # Move only the sources added by that subtree; retain the main target's include directories
    # because other unit sources also use the client test helpers.
    get_target_property(_uasdk_sources_after_client tests SOURCES)
    set(_uasdk_client_sources ${_uasdk_sources_after_client})
    list(REMOVE_ITEM _uasdk_client_sources ${_uasdk_sources_before_client})
    set_property(TARGET tests PROPERTY SOURCES "${_uasdk_sources_before_client}")
    target_sources(client_unit_tests PRIVATE ${_uasdk_client_sources})
    target_include_directories(client_unit_tests PRIVATE "$<TARGET_PROPERTY:tests,INCLUDE_DIRECTORIES>")
    target_compile_definitions(client_unit_tests PRIVATE "$<TARGET_PROPERTY:tests,COMPILE_DEFINITIONS>")
endif ()
add_subdirectory(conditions)
add_subdirectory(app)
add_subdirectory(history_reference)
add_subdirectory(examples)
