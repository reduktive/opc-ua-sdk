# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_address_space_change_event_emitter.h
        ua_address_space_change_event_emitter.cpp
        ua_audit_event_emitter.h
        ua_audit_event_emitter.cpp
        ua_event_bus.h
        ua_event_bus.cpp
        ua_event_type_model.h
        ua_event_type_model.cpp
)

uasdk_private_include_directory(uasdk-server)
