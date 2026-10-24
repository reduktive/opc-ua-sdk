// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Default mDNS transport implementation + scheme to service-type mapping (client design section 7.6 /
/// section 8.12).

#include "ua_default_mdns_transport.h"

#include <atomic>
#include <mutex>
#include <utility>

namespace ua::mdns
{

std::string service_type_for_scheme(OpcUaTransportScheme scheme)
{
  // Part 12 Annex C.3 Table 114. The `_tcp` proto literal is fixed for all OPC UA schemes (CL-DISC-015).
  switch (scheme)
  {
  case OpcUaTransportScheme::Tcp:
    return "_opcua-tcp._tcp.local.";
  case OpcUaTransportScheme::Wss:
    return "_opcua-tls._tcp.local.";
  case OpcUaTransportScheme::Https:
    return "_opcua-https._tcp.local.";
  }
  return "_opcua-tcp._tcp.local.";
}

namespace
{

/// A valid but inert browser (see the DefaultMdnsTransport STUB note). Stores callbacks and is cleanly
/// closeable; it never emits records because the raw multicast socket is not yet wired.
class InertMdnsBrowser : public MdnsBrowser
{
public:
  void set_callbacks(DiscoveredCallback discovered, LostCallback lost) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mDiscovered = std::move(discovered);
    mLost = std::move(lost);
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mDiscovered = nullptr;
      mLost = nullptr;
    }
    if (callback)
    {
      callback(ua::VoidResult{});
    }
  }

private:
  std::mutex mMutex;
  DiscoveredCallback mDiscovered;
  LostCallback mLost;
};

}  // namespace

DefaultMdnsTransport::DefaultMdnsTransport(boost::asio::any_io_executor executor, ua::Logger logger)
  : mExecutor(std::move(executor)), mLogger(std::move(logger))
{}

ua::Result<std::shared_ptr<MdnsBrowser>> DefaultMdnsTransport::start_browse(
  std::string serviceType, MdnsBrowseConfig /*config*/)
{
  // No multicast socket is opened: this transport is inert by design. An application needing live
  // discovery injects its own MdnsTransport rather than relying on this one.
  mLogger.warning(
    "default mDNS transport is a stub: no records will be delivered for browse of '{}'", serviceType);
  return ua::Result<std::shared_ptr<MdnsBrowser>>{std::make_shared<InertMdnsBrowser>()};
}

}  // namespace ua::mdns
