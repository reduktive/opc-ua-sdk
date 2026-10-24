# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# UASyncGeneratedTree.cmake - invoked via `cmake -P` from the
# `<TARGET>_regenerate` custom target when `ua_generate_types()` was
# called with `SYNC_TO`.
#
# Mirrors the staged generator output (under STAGED_DIR) into the
# destination tree (DEST_DIR), preserving the layered
# {interface,implementation}/<layer>/generated/ua/<category>/ layout
# (layer = core | address_space; see _core_categories / _addr_categories below).
# Each category subdir is wiped and recopied so removed types don't
# leave stale files behind.
#
# Inputs (passed via -D):
#   STAGED_DIR - root of the generator's output (the `--output` path).
#   DEST_DIR   - root to sync into (e.g. ${CMAKE_SOURCE_DIR}/sdk).

# This file is run via `cmake -P`, where policies default to OLD. Enable the
# modern `if(... IN_LIST ...)` operator used in the per-layer category mapping.
cmake_policy(SET CMP0057 NEW)

if (NOT DEFINED STAGED_DIR)
    message(FATAL_ERROR "UASyncGeneratedTree: STAGED_DIR not set")
endif ()
if (NOT DEFINED DEST_DIR)
    message(FATAL_ERROR "UASyncGeneratedTree: DEST_DIR not set")
endif ()

# Category subdirs are listed explicitly so we sync exactly what the
# generator emits (no surprises from unrelated files under
# ``generated/`` getting wiped).
#
# The generated tree is layered: the wire/type
# categories live in the role-agnostic ``core/`` layer, the instance-handle
# categories + the ns0 blob in the ``address_space/`` layer.  This mapping MUST
# match ``EmitContext.layer_segment_for`` in the generator.
set(_core_categories  data_types ids status ns0_model)
set(_addr_categories  object_types variable_types event_types ns0)

foreach (_tree IN ITEMS interface implementation)
    foreach (_cat IN LISTS _core_categories _addr_categories)
        if (_cat IN_LIST _core_categories)
            set(_layer core)
        else ()
            set(_layer address_space)
        endif ()
        set(_src "${STAGED_DIR}/${_tree}/${_layer}/generated/ua/${_cat}")
        set(_dst "${DEST_DIR}/${_tree}/${_layer}/generated/ua/${_cat}")
        if (EXISTS "${_src}")
            message(STATUS "Syncing ${_tree}/${_layer}/${_cat} -> ${_dst}")
            file(REMOVE_RECURSE "${_dst}")
            file(MAKE_DIRECTORY "${_dst}")
            file(COPY "${_src}/" DESTINATION "${_dst}")
        endif ()
    endforeach ()
endforeach ()

# The generated instance-type tests live one level above the category subdirs,
# in the address-space layer's generated tree (the instance handles they
# exercise are address-space).
set(_inst_tests_src "${STAGED_DIR}/implementation/address_space/generated/ua/generated_instance_type_tests.cpp")
set(_inst_tests_dst_dir "${DEST_DIR}/implementation/address_space/generated/ua")
if (EXISTS "${_inst_tests_src}")
    message(STATUS "Syncing instance-type tests -> ${_inst_tests_dst_dir}")
    file(COPY "${_inst_tests_src}" DESTINATION "${_inst_tests_dst_dir}")
endif ()

message(STATUS "Sync complete")
