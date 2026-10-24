// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Test-only constructor access for @ref ua::client::Discovery (client design section 7.6).
/// @ingroup client
///
/// Lets unit tests build a Discovery over a fake ephemeral-channel factory and a fake mDNS transport
/// without standing up a real Client / server. Not part of the public API.

#ifndef UA_DISCOVERY_TEST_ACCESS_H
#define UA_DISCOVERY_TEST_ACCESS_H

#include "ua_discovery.h"
#include "ua_discovery_channel.h"
#include "ua_mdns_transport.h"

#include <memory>
#include <utility>

namespace ua::client
{

/// Friend shim that exposes the private @ref Discovery constructor to tests.
class DiscoveryTestAccess
{
public:
  static Discovery make(std::shared_ptr<detail::DiscoveryChannelFactory> channelFactory,
    std::shared_ptr<ua::mdns::MdnsTransport> mdnsTransport, bool allowDeprecatedSecurityPolicies = false)
  {
    return Discovery{std::move(channelFactory), std::move(mdnsTransport), allowDeprecatedSecurityPolicies};
  }
};

}  // namespace ua::client

#endif  // !UA_DISCOVERY_TEST_ACCESS_H
