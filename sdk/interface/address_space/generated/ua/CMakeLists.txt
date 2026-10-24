# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

set(_GENERATED_SUBDIRS data_types event_types ids ns0 object_types status variable_types)
foreach(_subdir IN LISTS _GENERATED_SUBDIRS)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_subdir}/CMakeLists.txt")
        add_subdirectory(${_subdir})
    endif()
endforeach()
