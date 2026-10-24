// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_HOSTNAME_H
#define UA_CERTIFICATE_HOSTNAME_H

#include <string>
#include <string_view>

namespace ua
{
class X509Certificate;

namespace detail
{

/// Matches an endpoint HostName against the certificate's DNS/IP SANs. DNS matching is
/// case-insensitive and accepts one trailing root dot; numeric addresses require exact address
/// equality and may be encoded as either iPAddress or dNSName by deployed UA certificates.
bool certificate_matches_hostname(std::string_view endpointHostname, const X509Certificate& certificate);

/// Renders the certificate's declared DNS/IP names for diagnostics.
std::string certificate_hostname_summary(const X509Certificate& certificate);

}  // namespace detail
}  // namespace ua

#endif  // !UA_CERTIFICATE_HOSTNAME_H
