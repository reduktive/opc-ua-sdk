# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_tcp_endpoint.h
        ua_tcp_transport_acceptor.h
        ua_tcp_transport_connection.h
        ua_tcp_transport_connector.h
        ua_transport_connection.h
        ua_connection_protocol.h
        ua_connection_protocol.cpp
        ua_reverse_hello.h
        ua_reverse_hello.cpp
        ua_tcp_transport_connection.cpp
        ua_tcp_transport_acceptor.cpp
        ua_tcp_transport_connector.cpp
        ua_tcp_endpoint.cpp
        ua_tcp_endpoint_asio.h
        ua_tcp_endpoint_asio.cpp
        ua_url_parser.h
        ua_url_parser.cpp
)

uasdk_private_include_directory(uasdk-core)
