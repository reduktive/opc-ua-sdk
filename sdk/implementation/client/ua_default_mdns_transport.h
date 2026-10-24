// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Default in-tree mDNS transport (client design section 8.12).
/// @ingroup client
///
/// STUB STATUS: the interface is fully usable via injection, but the raw-socket multicast browse
/// (Boost.Asio UDP 224.0.0.251:5353 / ff02::fb) is not implemented in this release. `start_browse`
/// returns a valid, closeable  -  but inert  -  browser and logs a one-time warning.
///
/// What this component provides is the `MdnsTransport` interface and the injected-transport discovery
/// path: an application that needs live mDNS supplies its own transport through that interface. A
/// built-in RFC 6762 multicast socket, PTR/SRV/TXT/A caching, and TTL/goodbye eviction per section
/// 8.12 are not part of it.

#ifndef UA_DEFAULT_MDNS_TRANSPORT_H
#define UA_DEFAULT_MDNS_TRANSPORT_H

#include "ua_mdns_transport.h"

#include "ua_logger.h"
#include <boost/asio/any_io_executor.hpp>

#include <memory>

namespace ua::mdns
{

/// The default, always-compiled-in mDNS transport (client design section 8.12). See file-level STUB note.
class DefaultMdnsTransport : public MdnsTransport
{
public:
  /// @param executor Executor on which a future real implementation lands its callbacks.
  /// @param logger   Logger for diagnostics.
  DefaultMdnsTransport(boost::asio::any_io_executor executor, ua::Logger logger);

  /// Starts a (currently inert  -  see STUB note) browse for @p serviceType.
  ua::Result<std::shared_ptr<MdnsBrowser>> start_browse(
    std::string serviceType, MdnsBrowseConfig config) override;

private:
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;
};

}  // namespace ua::mdns

#endif  // !UA_DEFAULT_MDNS_TRANSPORT_H
