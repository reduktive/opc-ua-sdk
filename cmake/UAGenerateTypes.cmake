# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# UAGenerateTypes.cmake - `ua_generate_types()` helper
#
# Exposes the type generator behind a single CMake function so
# downstream consumers (companion specs, in-house NodeSets) can
# generate C++ types without writing custom_command boilerplate.
#
# Typical use:
#
#   include(UAGenerateTypes)
#
#   ua_generate_types(
#       TARGET         my_di_types
#       NS0_SOURCES    ${NS0_XML} ${NS0_SERVICES_XML}
#       EMIT_SOURCES   ${DI_XML}
#       OUTPUT_DIR     ${CMAKE_CURRENT_BINARY_DIR}/gen/di
#       CPP_NAMESPACE  ua::di
#       INCLUDE_PREFIX ua_di_
#       DEPENDS        uasdk::uasdk
#       # Optional emission policy (all default to off / empty):
#       # INSTANCE_TYPE_CATEGORIES  all
#       # INSTANCE_TYPE_BROWSE_NAMES DeviceType TopologyElementType
#       # EMIT_EVENT_TYPES
#   )
#
#   target_link_libraries(my_app PRIVATE my_di_types)
#
# Internally:
#
#   1. Synthesises a JSON manifest at configure time from the inline args
#      (or accepts one via `MANIFEST <path>`).
#   2. Runs `tooling/type_generator` at configure time so the generated
#      file tree exists and can be picked up by add_subdirectory().  Also
#      registers a custom target that re-runs the generator on demand.
#   3. Adds the generated interface/implementation subtrees, which carry
#      `target_sources(<TARGET> ...)` directives that attach to the
#      library target.
#   4. Creates the library and links DEPENDS publicly.

if (DEFINED _UA_GENERATE_TYPES_INCLUDED)
    return()
endif ()
set(_UA_GENERATE_TYPES_INCLUDED TRUE)

set(_UA_TYPE_GENERATOR_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../tooling/type_generator"
    CACHE INTERNAL "Path to the type-generator package root")

set(_UA_TYPE_GENERATOR_RUN_PY
    "${_UA_TYPE_GENERATOR_DIR}/run_type_generator.py"
    CACHE INTERNAL "Bootstrap script for the type generator (manages venv)")

find_package(Python3 QUIET COMPONENTS Interpreter)
if (NOT Python3_FOUND)
    message(WARNING "ua_generate_types: Python3 not found - the function "
            "will be a no-op.  Consumers must rely on committed generated "
            "sources only.")
endif ()


function(ua_generate_types)
    cmake_parse_arguments(GEN
        # Options (boolean flags)
        "EMIT_EVENT_TYPES;REGEN_ONLY"
        # Single-value keywords
        "TARGET;OUTPUT_DIR;CPP_NAMESPACE;INCLUDE_PREFIX;MANIFEST;LIBRARY_TYPE;SYNC_TO"
        # Multi-value keywords
        "NS0_SOURCES;NS0_NODEIDS_CSV;NS0_STATUSCODE_CSV;NS0_ATTRIBUTE_IDS_CSV;EMIT_SOURCES;EMIT_NODEIDS_CSV;DEPENDS;INSTANCE_TYPE_CATEGORIES;INSTANCE_TYPE_BROWSE_NAMES;LOOKUP_SPECS"
        ${ARGN}
    )

    # ---- Validate arguments -----------------------------------------------

    if (NOT GEN_TARGET)
        message(FATAL_ERROR "ua_generate_types: TARGET is required")
    endif ()
    if (NOT GEN_OUTPUT_DIR)
        message(FATAL_ERROR "ua_generate_types: OUTPUT_DIR is required")
    endif ()
    if (NOT GEN_MANIFEST AND NOT GEN_EMIT_SOURCES)
        message(FATAL_ERROR "ua_generate_types: either MANIFEST or EMIT_SOURCES is required")
    endif ()
    if (NOT GEN_LIBRARY_TYPE)
        set(GEN_LIBRARY_TYPE STATIC)
    endif ()

    if (NOT Python3_FOUND)
        message(STATUS "ua_generate_types(${GEN_TARGET}): skipped (Python3 not found)")
        return()
    endif ()

    # ---- Synthesise the manifest if not supplied --------------------------

    if (NOT GEN_MANIFEST)
        if (NOT GEN_CPP_NAMESPACE)
            message(FATAL_ERROR "ua_generate_types(${GEN_TARGET}): CPP_NAMESPACE is required when MANIFEST is not supplied")
        endif ()
        if (NOT GEN_INCLUDE_PREFIX)
            message(FATAL_ERROR "ua_generate_types(${GEN_TARGET}): INCLUDE_PREFIX is required when MANIFEST is not supplied")
        endif ()

        set(GEN_MANIFEST "${GEN_OUTPUT_DIR}/_manifest.json")
        _ua_synthesise_manifest(${GEN_TARGET} "${GEN_MANIFEST}")
    endif ()

    # ---- Run the generator at configure time (build flow only) -----------
    #
    # When ``REGEN_ONLY`` is set the consumer manages the generated tree
    # out-of-band (typically: files are committed to git and regenerated
    # by an explicit ``--target`` invocation).  Skipping configure-time
    # generation lets us avoid running the generator on every CMake
    # reconfigure for that case.
    #
    # When ``REGEN_ONLY`` is NOT set, we run the generator now so the
    # emitted ``CMakeLists.txt`` files under ``OUTPUT_DIR`` exist by the
    # time ``add_subdirectory()`` below tries to pick them up.

    if (NOT GEN_REGEN_ONLY)
        file(MAKE_DIRECTORY "${GEN_OUTPUT_DIR}")
        execute_process(
            COMMAND "${Python3_EXECUTABLE}" "${_UA_TYPE_GENERATOR_RUN_PY}"
                --manifest "${GEN_MANIFEST}"
                --output "${GEN_OUTPUT_DIR}"
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            RESULT_VARIABLE _gen_rv
            OUTPUT_VARIABLE _gen_out
            ERROR_VARIABLE  _gen_err
        )
        if (NOT _gen_rv EQUAL 0)
            message(FATAL_ERROR
                "ua_generate_types(${GEN_TARGET}): generator failed (exit ${_gen_rv})\n"
                "stdout:\n${_gen_out}\n"
                "stderr:\n${_gen_err}")
        endif ()
    endif ()

    # ---- Create the target ------------------------------------------------
    #
    # ``REGEN_ONLY`` skips this: the consumer already owns the target
    # (NS0 self-host case - the ``sdk`` library exists independently).

    if (NOT GEN_REGEN_ONLY)
        add_library(${GEN_TARGET} ${GEN_LIBRARY_TYPE})
        set_target_properties(${GEN_TARGET} PROPERTIES
            LINKER_LANGUAGE CXX
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON)
        # Generated code uses C++20 (concepts, std::span) from the SDK headers;
        # propagate the requirement to consumers of this generated library too.
        target_compile_features(${GEN_TARGET} PUBLIC cxx_std_20)

        if (GEN_DEPENDS)
            target_link_libraries(${GEN_TARGET} PUBLIC ${GEN_DEPENDS})
        endif ()
        # A generated Structure's encoding calls the SDK's private codecs (public API review item 1,
        # API-1.2), which are reached through uasdk::internal; every other generated source, and every
        # generated header, includes only public headers.
        if (TARGET uasdk::internal)
            target_link_libraries(${GEN_TARGET} PRIVATE uasdk::internal)
        endif ()

        # ---- Attach the generated tree ------------------------------------
        #
        # A consumer spec emits a flat tree: a root ``CMakeLists.txt`` that
        # ``add_subdirectory``s each per-category subdir, each of which carries
        # ``target_sources(<TARGET> ...)``.  One add_subdirectory wires the
        # whole tree into the just-created target.  (NS0 - the only spec using
        # the interface/implementation split - is ``REGEN_ONLY`` and never
        # reaches this branch; its committed tree is owned by sdk/CMakeLists.txt.)

        if (EXISTS "${GEN_OUTPUT_DIR}/CMakeLists.txt")
            add_subdirectory(
                "${GEN_OUTPUT_DIR}"
                "${CMAKE_CURRENT_BINARY_DIR}/_ua_${GEN_TARGET}_gen"
            )
        endif ()
    endif ()

    # ---- Regen-on-demand custom target ------------------------------------
    #
    # Always registered.  Build it (``--target <TARGET>_regenerate``) to
    # re-run the generator on demand.  When ``SYNC_TO`` is set, the staged
    # output is also mirrored into the destination tree afterwards - this
    # is how NS0 keeps its committed generated sources up to date.

    set(_regen_cmds
        COMMAND "${Python3_EXECUTABLE}" "${_UA_TYPE_GENERATOR_RUN_PY}"
            --manifest "${GEN_MANIFEST}"
            --output "${GEN_OUTPUT_DIR}"
    )
    if (GEN_SYNC_TO)
        list(APPEND _regen_cmds
            COMMAND "${CMAKE_COMMAND}"
                -D "STAGED_DIR=${GEN_OUTPUT_DIR}"
                -D "DEST_DIR=${GEN_SYNC_TO}"
                -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/UASyncGeneratedTree.cmake"
        )
    endif ()

    add_custom_target(${GEN_TARGET}_regenerate
        ${_regen_cmds}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Regenerating types for ${GEN_TARGET} from ${GEN_MANIFEST}"
        VERBATIM
    )
endfunction()


# Internal helper: build a JSON manifest from the inline args.
#
# Runs the Python ``synthesise_manifest`` helper which knows the schema
# and can auto-detect spec URIs from the NodeSet XML.
function(_ua_synthesise_manifest TARGET OUT_PATH)
    # All these variables are bound in the parent (ua_generate_types) scope.
    set(_args
        --out "${OUT_PATH}"
        --emit-cpp-namespace "${GEN_CPP_NAMESPACE}"
        --emit-include-prefix "${GEN_INCLUDE_PREFIX}"
        --emit-target "${TARGET}"
    )

    if (GEN_NS0_SOURCES)
        string(REPLACE ";" "," _ns0_sources_csv "${GEN_NS0_SOURCES}")
        list(APPEND _args --ns0-sources "${_ns0_sources_csv}")
    endif ()
    if (GEN_NS0_NODEIDS_CSV)
        list(APPEND _args --ns0-nodeids-csv "${GEN_NS0_NODEIDS_CSV}")
    endif ()
    if (GEN_NS0_STATUSCODE_CSV)
        list(APPEND _args --ns0-statuscode-csv "${GEN_NS0_STATUSCODE_CSV}")
    endif ()
    if (GEN_NS0_ATTRIBUTE_IDS_CSV)
        list(APPEND _args --ns0-attribute-ids-csv "${GEN_NS0_ATTRIBUTE_IDS_CSV}")
    endif ()
    foreach (_src IN LISTS GEN_EMIT_SOURCES)
        list(APPEND _args --emit-source "${_src}")
    endforeach ()
    if (GEN_EMIT_NODEIDS_CSV)
        list(APPEND _args --emit-nodeids-csv "${GEN_EMIT_NODEIDS_CSV}")
    endif ()
    if (GEN_INSTANCE_TYPE_CATEGORIES)
        string(REPLACE ";" "," _cats "${GEN_INSTANCE_TYPE_CATEGORIES}")
        list(APPEND _args --emit-instance-categories "${_cats}")
    endif ()
    if (GEN_INSTANCE_TYPE_BROWSE_NAMES)
        string(REPLACE ";" "," _bns "${GEN_INSTANCE_TYPE_BROWSE_NAMES}")
        list(APPEND _args --emit-instance-browse-names "${_bns}")
    endif ()
    if (GEN_EMIT_EVENT_TYPES)
        list(APPEND _args --emit-event-types)
    endif ()
    # Intermediate lookup specs for multi-level stacks. Each LOOKUP_SPECS entry
    # is a pipe-delimited 5-tuple:
    #   uri|cpp_namespace|include_prefix|nodeids_csv|src1,src2,...
    foreach (_lookup IN LISTS GEN_LOOKUP_SPECS)
        list(APPEND _args --lookup-spec "${_lookup}")
    endforeach ()

    file(MAKE_DIRECTORY "${GEN_OUTPUT_DIR}")
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${_UA_TYPE_GENERATOR_RUN_PY}"
            --py-module tooling.type_generator.synthesise_manifest
            ${_args}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _rv
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE  _err
    )
    if (NOT _rv EQUAL 0)
        message(FATAL_ERROR
            "ua_generate_types(${TARGET}): manifest synthesis failed (exit ${_rv})\n"
            "stdout:\n${_out}\n"
            "stderr:\n${_err}")
    endif ()
endfunction()
