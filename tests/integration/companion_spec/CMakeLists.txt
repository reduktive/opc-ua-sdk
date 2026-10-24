# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Phase 7 - multi-nodeset companion-spec integration tests.
#
# Generates a real OPC Foundation companion spec through the public
# ``ua_generate_types()`` helper and links it alongside ``sdk``:
#
#   * DI       (http://opcfoundation.org/UA/DI/)       -> ua::di  / ua_di_
#
# DI depends only on NS0, which the helper references for cross-spec resolution
# (emit=false) while emitting the DI types into their own namespace + prefix.
#
# VERTICAL SLICE (current): DI data types + identifier enums only - drives
# rows 2-6 (compile, codec round-trip, registration coexistence, runtime
# ns-index resolution). Instance-handle + event-type emission (rows 7-11) and
# the PROFINET spec (events/conditions, rows 10-11) are re-enabled once those
# generator layers are made cross-spec-correct.

include(UAGenerateTypes)

set(_UANODESET_DIR "${CMAKE_BINARY_DIR}/_deps/uanodeset-src")
set(_NS0_SCHEMA "${_UANODESET_DIR}/Schema")

# ---- DI -----------------------------------------------------------------
ua_generate_types(
    TARGET         ua_di_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/di"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${_UANODESET_DIR}/DI/Opc.Ua.Di.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${_UANODESET_DIR}/DI/Opc.Ua.Di.NodeIds.csv"
    CPP_NAMESPACE  ua::di
    INCLUDE_PREFIX ua_di_
    DEPENDS        uasdk::uasdk
    # Rows 7-9: object/variable instance handles. (Event types - rows 10-11 -
    # stay off until that generator layer is cross-spec-correct.)
    INSTANCE_TYPE_CATEGORIES all
)

# ---- PROFINET (rows 10-11: events / conditions) ------------------------
ua_generate_types(
    TARGET         ua_pn_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/pn"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${_UANODESET_DIR}/PROFINET/Opc.Ua.Pn.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${_UANODESET_DIR}/PROFINET/Opc.Ua.Pn.NodeIds.csv"
    CPP_NAMESPACE  ua::pn
    INCLUDE_PREFIX ua_pn_
    DEPENDS        uasdk::uasdk
    INSTANCE_TYPE_CATEGORIES all
    EMIT_EVENT_TYPES
)

# ---- BACnet (item 1: SymbolicName-based identifier sanitization) -------------
# BACnet's NodeSet uses field/enum names with hyphens, spaces and leading digits
# (e.g. ``Name="days numbered 1-7" SymbolicName="days_numbered_1_7"``) - invalid
# C++ identifiers that must be derived from SymbolicName (or sanitised) while the
# on-wire spelling stays the original Name. Data types only (NS0-only deps); the
# CSV is lowercase ``nodeids``.
ua_generate_types(
    TARGET         ua_bacnet_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/bacnet"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${_UANODESET_DIR}/BACnet/Opc.Ua.BACnet.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${_UANODESET_DIR}/BACnet/Opc.Ua.BACnet.nodeids.csv"
    CPP_NAMESPACE  ua::bacnet
    INCLUDE_PREFIX ua_bacnet_
    DEPENDS        uasdk::uasdk
)

# ---- Multi-level stacking (item 5) - synthetic lvl1 <- lvl2 chain ------------
# lvl2 depends on a NON-NS0 lookup spec (lvl1): Lvl2Line has fields typed by
# lvl1's Lvl1Point. Generating lvl2 with lvl1 as an emit=false LOOKUP_SPECS entry
# must resolve cross-spec refs to ``ua::lvl1::Lvl1Point`` (+ its include) and the
# canonical-namespace NodeId remapping must make the cross-file reference resolve.
# lvl1 is also generated as its own library so lvl2 can link its codec symbols.
ua_generate_types(
    TARGET         ua_lvl1_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/lvl1"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl1.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl1.NodeIds.csv"
    CPP_NAMESPACE  ua::lvl1
    INCLUDE_PREFIX ua_lvl1_
    DEPENDS        uasdk::uasdk
)

ua_generate_types(
    TARGET         ua_lvl2_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/lvl2"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl2.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl2.NodeIds.csv"
    CPP_NAMESPACE  ua::lvl2
    INCLUDE_PREFIX ua_lvl2_
    DEPENDS        uasdk::uasdk ua_lvl1_types
    LOOKUP_SPECS   "urn:example:lvl1|ua::lvl1|ua_lvl1_|${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl1.NodeIds.csv|${CMAKE_CURRENT_SOURCE_DIR}/resources/lvl1.NodeSet2.xml"
)

# ---- Synthetic union fixture - exercises UNION codegen + encode/decode --------
# A minimal one-union companion spec (clean C++-identifier field names) to verify
# cross-spec UAUnion generation and binary round-trip in isolation.
ua_generate_types(
    TARGET         ua_union_test_types
    OUTPUT_DIR     "${CMAKE_CURRENT_BINARY_DIR}/gen/uniontest"
    NS0_SOURCES    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA}/AttributeIds.csv"
    EMIT_SOURCES   "${CMAKE_CURRENT_SOURCE_DIR}/resources/union_test.NodeSet2.xml"
    EMIT_NODEIDS_CSV "${CMAKE_CURRENT_SOURCE_DIR}/resources/union_test.NodeIds.csv"
    CPP_NAMESPACE  ua::uniontest
    INCLUDE_PREFIX ua_uniontest_
    DEPENDS        uasdk::uasdk
)

# The generated data-type sources define concrete-codec encode/decode overloads
# (``encode(..., UaBinaryEncoder&)`` etc.), which live in sdk's private codec
# implementation dir. Generated companion types extend the same codec machinery,
# so they need that dir on their include path. (All other transitive codec deps
# are public sdk interface headers, reachable via the sdk link.)
foreach (_companion_target ua_di_types ua_pn_types ua_union_test_types ua_bacnet_types
                            ua_lvl1_types ua_lvl2_types)
    target_include_directories(${_companion_target}
        PRIVATE "${CMAKE_SOURCE_DIR}/sdk/implementation/core/codecs")
endforeach ()

# lvl2's generated headers #include lvl1's headers (cross-spec field type), so
# lvl2's compile needs lvl1's generated data_types dir on its include path.
# (Consumer specs emit a flat tree - category subdirs directly under the output.)
target_include_directories(ua_lvl2_types
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/gen/lvl1/data_types")

# ---- Test executable ----------------------------------------------------
add_executable(companion_spec_integration_tests)
set_property(TARGET companion_spec_integration_tests PROPERTY CXX_STANDARD 20)
if (MSVC)
    target_compile_options(companion_spec_integration_tests PRIVATE /bigobj)
endif ()

target_sources(companion_spec_integration_tests PRIVATE
    di_compile_tests.cpp
    di_codec_tests.cpp
    di_instance_tests.cpp
    union_codec_tests.cpp
    profinet_events_conditions_tests.cpp
    bacnet_codec_tests.cpp
    multi_level_tests.cpp
)

target_link_libraries(companion_spec_integration_tests
    PRIVATE ua_di_types ua_pn_types ua_union_test_types ua_bacnet_types
            ua_lvl1_types ua_lvl2_types uasdk::uasdk test_infra GTest::gtest GTest::gmock)
target_include_directories(companion_spec_integration_tests
    PRIVATE $<TARGET_PROPERTY:test_infra,INTERFACE_INCLUDE_DIRECTORIES>)

# DI NodeSet XML copied next to the binary so the tests can load it at runtime
# (server address-space population for the instance/browse/translate rows).
add_custom_command(
    TARGET companion_spec_integration_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${_UANODESET_DIR}/DI/Opc.Ua.Di.NodeSet2.xml" "${CMAKE_CURRENT_BINARY_DIR}/Opc.Ua.Di.NodeSet2.xml")

# NS0 NodeSet alongside the binary (loaded first).
add_custom_command(
    TARGET companion_spec_integration_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${_NS0_SCHEMA}/Opc.Ua.NodeSet2.xml" "${CMAKE_CURRENT_BINARY_DIR}/NodeSet2.xml")

include(GoogleTest)
# DISCOVERY_TIMEOUT 180, matching every other gtest_discover_tests call in the tree. This was the
# only one left on the 5s default, and 5s is not enough for an instrumented build: under
# -fsanitize=address,undefined against five SHARED SDK libraries, this binary's post-build
# --gtest_list_tests exceeded it and failed the `sanitizer / gcc14-asan` build outright
# ("Process terminated due to timeout", pipeline 2855965130). Build-time only - it bounds
# enumeration, not the tests.
gtest_discover_tests(companion_spec_integration_tests DISCOVERY_TIMEOUT 180)
uasdk_add_test_report(companion_spec_integration_tests)
