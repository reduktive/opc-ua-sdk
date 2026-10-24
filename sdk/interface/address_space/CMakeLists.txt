# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PUBLIC ua_address_space.h ua_namespace.h ua_namespace_context.h ua_namespace_array.h ua_namespace_monitoring.h
        ua_namespace_items.h ua_request_info.h ua_node_description.h ua_described_nodes.h
        ua_server_array.h ua_node.h ua_node_utilities.h ua_reference.h ua_reference_halves.h ua_value_source.h
        ua_node_accessor.h ua_weak_address_space.h
        ua_instance_utils.h
        ua_method_adapter.h ua_method_arguments.h ua_method_result.h ua_add_method.h
        ua_namespace_monitoring_support.h
       
        ua_base_event.h
        ua_generic_event.h
       
        ua_address_space_model_access.h
        ua_register_address_space_types.h
        ua_namespace_history_delegate.h
        ua_namespace_authorization.h
        ua_namespace_service_delegates.h
        ua_variable_states.h ua_sinks.h
       
       
       )

target_include_directories(uasdk-address-space PUBLIC .)

add_subdirectory(helpers)
add_subdirectory(instantiation)
add_subdirectory(nodeset_tools)
add_subdirectory(conditions)
add_subdirectory(instance_types)
add_subdirectory(generated)
