// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef REDUKTIVE_REFERENCE_SERVER_ENDPOINTS_H
#define REDUKTIVE_REFERENCE_SERVER_ENDPOINTS_H

/// @file
/// @brief The reference server's network identity: the certificate it presents and the endpoint
///        it advertises.

#include "reference_pki.h"

#include "ua_server.h"

#include <string>
#include <string_view>

namespace reduktive::reference
{

/// The server's stable OPC UA application identity, used both in the certificate it presents and
/// in the ApplicationDescription it advertises. Those two must agree or a peer rejects the
/// connection.
inline constexpr std::string_view applicationUri = "urn:reduktive:reference-server";

/// Builds the X.509 identity requested when the server provisions its own certificate.
///
/// The certificate always covers localhost and 127.0.0.1, and additionally the configured listen
/// host, so that a peer's hostname verification succeeds for the address an operator chose.
///
/// @throws std::invalid_argument if @p listenAddress is not `host:port`.
CertificateProfile server_certificate_profile(std::string_view listenAddress);

/// Opens the UA TCP listener and advertises this server's only endpoint: Basic256Sha256 with
/// SignAndEncrypt, accepting an anonymous user identity inside that protected channel.
ua::server::ListenerHandle add_secure_endpoint(ua::server::Server& server, const std::string& listenAddress);

}  // namespace reduktive::reference

#endif  // REDUKTIVE_REFERENCE_SERVER_ENDPOINTS_H
