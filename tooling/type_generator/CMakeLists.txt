# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Self-host the SDK's own NS0 generated types on the same
# ``ua_generate_types()`` helper that downstream consumers use.
#
# The ``REGEN_ONLY`` + ``SYNC_TO`` modes carry the two NS0-specific
# behaviours:
#
#   * REGEN_ONLY    - the ``sdk`` library target is defined by
#                     ``sdk/CMakeLists.txt`` and gets its sources from
#                     the committed generated files; we don't want the
#                     helper to also call ``add_library(sdk)``.
#   * SYNC_TO <src> - after regeneration, mirror the staged tree into
#                     the in-tree source location so committed
#                     generated files stay current.

include(UAGenerateTypes)

set(_NS0_OUTPUT_DIR "${CMAKE_BINARY_DIR}/generated/type_generator")
set(_NS0_SCHEMA_DIR "${CMAKE_BINARY_DIR}/_deps/uanodeset-src/Schema")

ua_generate_types(
    TARGET sdk
    REGEN_ONLY
    OUTPUT_DIR "${_NS0_OUTPUT_DIR}"
    SYNC_TO    "${CMAKE_SOURCE_DIR}/sdk"

    EMIT_SOURCES
        "${_NS0_SCHEMA_DIR}/Opc.Ua.NodeSet2.xml"
        "${_NS0_SCHEMA_DIR}/Opc.Ua.NodeSet2.Services.xml"
    NS0_NODEIDS_CSV       "${_NS0_SCHEMA_DIR}/NodeIds.csv"
    NS0_STATUSCODE_CSV    "${_NS0_SCHEMA_DIR}/StatusCode.csv"
    NS0_ATTRIBUTE_IDS_CSV "${_NS0_SCHEMA_DIR}/AttributeIds.csv"

    CPP_NAMESPACE  ua
    INCLUDE_PREFIX ua_

    # NS0 emission policy: every instance-handle category EXCEPT PubSub.
    # The SDK core does not implement PubSub, so its object/variable
    # types (broker/datagram transports, data set readers/writers,
    # PubSub connections/groups, ...) are not emitted.  PubSub data types
    # and the PubSub JSON message-mapping category are skipped separately
    # in ``type_generator.py``.  Listing categories explicitly (rather
    # than ``all``) keeps this exclusion intentional and visible.
    INSTANCE_TYPE_CATEGORIES
        alarms
        dataaccess
        network
        security
        statemachine
        historizing
        dictionary
        events
    EMIT_EVENT_TYPES
)

# Friendlier aliases for existing build workflows.
if (TARGET sdk_regenerate)
    add_custom_target(generate_types                       DEPENDS sdk_regenerate)
    add_custom_target(update_generated_data_types_python   DEPENDS sdk_regenerate)
endif ()
