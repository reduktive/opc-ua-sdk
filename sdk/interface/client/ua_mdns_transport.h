// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Interface-first mDNS transport contract for OPC UA Subnet Discovery (client design section 7.6 /
/// section 8.12).
/// @ingroup client
///
/// The SDK currently ships an inert default placeholder behind this interface; it does not open a
/// multicast socket or deliver records. Applications that require subnet discovery must register a
/// production mDNS implementation via `Client::set_mdns_transport(...)`. The types live in `ua::mdns`
/// because they are transport-mechanism (not OPC UA service) concepts.

#ifndef UA_MDNS_TRANSPORT_H
#define UA_MDNS_TRANSPORT_H

#include "ua_result.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua::mdns
{

/// One resolved multicast-DNS service instance (client design section 7.6). Assembled from the
/// `(PTR, SRV, TXT, A/AAAA)` record set for a single OPC UA service instance.
/// @ingroup client
struct ServiceRecord
{
  /// Fully-qualified service instance name, e.g. `"MyServer._opcua-tcp._tcp.local."`.
  std::string serviceName;
  /// Resolved SRV target host name (the A/AAAA owner), e.g. `"uaserver.example.com"`.
  std::string hostName;
  /// Resolved IPv4/IPv6 addresses for @ref hostName (may be empty if only the host name is known).
  std::vector<std::string> addresses;
  /// SRV port.
  std::uint16_t port{0};
  /// Raw TXT record entries (`key=value`, verbatim). Per Part 12 Annex C these carry `path`, `caps`, etc.
  std::vector<std::string> txt;
  /// Local monotonic time this record was last (re)observed; used for TTL/goodbye bookkeeping.
  std::chrono::steady_clock::time_point seenAt{};
};

/// The OPC UA transport scheme selecting the mDNS service type (client design section 7.6, Part 12 Annex C.3
/// Table 114). Typed rather than a raw string so callers cannot mistype the service name.
enum class OpcUaTransportScheme
{
  Tcp,  ///< `opc.tcp`  to  service type `_opcua-tcp._tcp.local.`
  Wss,  ///< `opc.wss`  to  service type `_opcua-tls._tcp.local.`
  Https,  ///< `https`   to  service type `_opcua-https._tcp.local.`
};

/// Parameters for an mDNS browse (client design section 7.6).
/// @ingroup client
struct MdnsBrowseConfig
{
  /// The OPC UA transport scheme; selects the queried service type per Part 12 Annex C.3.
  OpcUaTransportScheme scheme{OpcUaTransportScheme::Tcp};

  /// Optional multicast interface address to bind (empty = default system interface).
  std::string interfaceAddress;
};

/// A live mDNS browse handle (client design section 7.6). Records arrive/expire via the registered callbacks;
/// the browse continues until @ref close_async completes. Move via the owning `shared_ptr`.
/// @ingroup client
class MdnsBrowser
{
public:
  virtual ~MdnsBrowser() = default;

  /// Fired when a service instance is first sighted or its record set is refreshed.
  using DiscoveredCallback = std::function<void(ServiceRecord)>;
  /// Fired when a service instance expires (TTL elapsed or explicit goodbye record). Carries the
  /// fully-qualified service instance name that was lost.
  using LostCallback = std::function<void(std::string serviceName)>;

  /// @param discovered The discovered.
  /// @param lost The lost.
  /// Installs the discovered/lost callbacks. Both may be empty (no notification for that event).
  /// Callbacks are delivered on the transport's executor and must not block.
  virtual void set_callbacks(DiscoveredCallback discovered, LostCallback lost) = 0;

  /// @param callback Completion callback that receives the operation result.
  /// Stops the browse and releases its socket/strand. Idempotent. The callback fires on completion
  /// and never throws.
  virtual void close_async(std::function<void(ua::VoidResult)> callback) = 0;

protected:
  MdnsBrowser() = default;
  /// Defaulted memberwise copy construction.
  MdnsBrowser(const MdnsBrowser&) = default;
  /// Defaulted memberwise copy assignment.
  /// @return This object after assignment.
  MdnsBrowser& operator=(const MdnsBrowser&) = default;
  /// Defaulted memberwise move construction.
  MdnsBrowser(MdnsBrowser&&) = default;
  /// Defaulted memberwise move assignment.
  /// @return This object after assignment.
  MdnsBrowser& operator=(MdnsBrowser&&) = default;
};

/// The abstract mDNS transport contract (client design section 7.6 / section 8.12). A concrete transport
/// starts a browse for a service type and hands back a @ref MdnsBrowser whose callbacks fire as records
/// arrive.
/// @ingroup client
class MdnsTransport
{
public:
  virtual ~MdnsTransport() = default;

  /// Starts a browse for @p serviceType (typically `"_opcua-tcp._tcp.local."`).
  ///
  /// @param serviceType Fully-qualified mDNS service type to browse.
  /// @param config      Browse parameters (interface, scheme).
  /// @return On success the browse handle; on failure a bad Result carrying an @ref ua::ErrorDetail.
  ///         The transport MUST NOT throw; failures are reported through the Result.
  virtual ua::Result<std::shared_ptr<MdnsBrowser>> start_browse(
    std::string serviceType, MdnsBrowseConfig config) = 0;

protected:
  MdnsTransport() = default;
  /// Defaulted memberwise copy construction.
  MdnsTransport(const MdnsTransport&) = default;
  /// Defaulted memberwise copy assignment.
  /// @return This object after assignment.
  MdnsTransport& operator=(const MdnsTransport&) = default;
  /// Defaulted memberwise move construction.
  MdnsTransport(MdnsTransport&&) = default;
  /// Defaulted memberwise move assignment.
  /// @return This object after assignment.
  MdnsTransport& operator=(MdnsTransport&&) = default;
};

/// Maps an OPC UA transport scheme to its mDNS service type per Part 12 Annex C.3 Table 114
/// (CL-DISC-015). The `_tcp` proto literal is fixed by the spec for all OPC UA schemes.
///
/// @param scheme The transport scheme.
/// @return The fully-qualified service type, e.g. `"_opcua-tcp._tcp.local."`.
[[nodiscard]] std::string service_type_for_scheme(OpcUaTransportScheme scheme);

}  // namespace ua::mdns

#endif  // !UA_MDNS_TRANSPORT_H
