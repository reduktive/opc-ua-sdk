// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REGISTRATION_ENDPOINT_CHOICE_H
#define UA_REGISTRATION_ENDPOINT_CHOICE_H

#include "ua_array.h"
#include "ua_discovery_registration.h"
#include "ua_crypto.h"
#include "ua_endpoint_description.h"
#include "ua_result.h"
#include "ua_x509_certificate.h"

#include <memory>

namespace ua::app::detail
{

/// The discovery server's endpoint to register over: the target's mode and, when set, its policy;
/// otherwise the strongest policy offered for that mode, skipping deprecated ones. Ranked as the client
/// ranks endpoints (client::default_easy_connect_ranker, then the advertised securityLevel, then the
/// policy URI, so the choice is deterministic). A policy this SDK does not implement is never chosen.
/// @param endpoints The discovery server's GetEndpoints answer.
/// @param target    The registration target.
/// @return The chosen endpoint, or null when none matches.
const ua::EndpointDescription* choose_registration_endpoint(
  const ua::Array<ua::EndpointDescription>& endpoints, const DiscoveryTarget& target);

/// The certificate the registration channel trusts for @p chosen: the leaf of its ServerCertificate field
/// (the field may carry the issuers after the leaf).
/// @param crypto Parses the field.
/// @param chosen The endpoint @ref choose_registration_endpoint returned.
/// @return The leaf certificate; null when the field is empty; the parse's Bad_CertificateInvalid when the
///         field does not parse.
ua::Result<std::shared_ptr<const ua::X509Certificate>> registration_server_certificate(
  const ua::Crypto& crypto, const ua::EndpointDescription& chosen);

}  // namespace ua::app::detail

#endif  // UA_REGISTRATION_ENDPOINT_CHOICE_H
