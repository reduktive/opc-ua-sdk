// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-level Discovery facade: FindServers / GetEndpoints / FindServersOnNetwork over
///        ephemeral None-policy channels, cached-endpoint admin, and mDNS browse (client design section 7.6).
/// @ingroup client

#ifndef UA_DISCOVERY_H
#define UA_DISCOVERY_H

#include "ua_mdns_transport.h"

#include "ua_application_description.h"
#include "ua_byte_string.h"
#include "ua_connection_config.h"
#include "ua_endpoint_description.h"
#include "ua_message_security_mode.h"
#include "ua_result.h"
#include "ua_server_on_network.h"
#include "ua_utc_time.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua
{
class Logger;
}  // namespace ua

namespace ua::client
{

namespace detail
{
class DiscoveryChannelFactory;
}  // namespace detail

/// Filter/options for @ref Discovery::find_servers_async (client design section 7.6).
/// @ingroup client
struct FindServersOptions
{
  /// serverUris filter (Part 4 section 5.4.2.2). Empty = return all known servers. A serverUri matches an
  /// `ApplicationDescription.applicationUri`. Passed through verbatim (CL-DISC-008).
  std::vector<std::string> serverUris;
  /// Preferred locale ids for localized text in the response (server default if empty).
  std::vector<std::string> localeIds;
  /// Per-call timeout; `nullopt` uses the client default.
  std::optional<std::chrono::milliseconds> timeout;
};

/// Filter/options for @ref Discovery::get_endpoints_async (client design section 7.6).
/// @ingroup client
struct GetEndpointsOptions
{
  /// Transport profile URI filter. Empty = return all endpoints.
  std::vector<std::string> profileUris;
  /// Preferred locale ids for localized text in the response (server default if empty).
  std::vector<std::string> localeIds;
  /// Per-call timeout; `nullopt` uses the client default.
  std::optional<std::chrono::milliseconds> timeout;
};

/// Options for @ref Discovery::find_servers_on_network_async (client design section 7.6). Carries the
/// pagination inputs (CL-DISC-013); auto-pagination / counter-reset detection is a later slice.
/// @ingroup client
struct FindServersOnNetworkOptions
{
  /// Only records with an identifier greater than this are returned. `0` starts from the beginning.
  std::uint32_t startingRecordId{0};
  /// Maximum records to return. `0` = server default (no client cap).
  std::uint32_t maxRecordsToReturn{0};
  /// Server-capability filter (AND-combined by the LDS-ME). Empty = no capability filter.
  std::vector<std::string> serverCapabilityFilter;
  /// Per-call timeout; `nullopt` uses the client default.
  std::optional<std::chrono::milliseconds> timeout;
};

/// Filters and pagination inputs for @ref Discovery::gds_query_servers_async (Part 12 section 6.6.11).
/// @ingroup client
struct GdsServerFilter
{
  /// Only records with an identifier greater than this value are returned; `0` starts at the beginning.
  std::uint32_t startingRecordId{0};
  /// Maximum records to return; `0` means no limit.
  std::uint32_t maxRecordsToReturn{0};
  /// LIKE-pattern filter for the default ApplicationName; empty disables this filter.
  std::string applicationName;
  /// LIKE-pattern filter for ApplicationUri; empty disables this filter.
  std::string applicationUri;
  /// LIKE-pattern filter for ProductUri; empty disables this filter.
  std::string productUri;
  /// Required Server capabilities (AND-combined); empty disables this filter.
  std::vector<std::string> serverCapabilities;
};

/// Conjunctive filters and pagination inputs for QueryApplications (Part 12 section 6.6.10).
/// Every populated field is AND-combined by the GDS; every entry in @ref capabilities is itself required.
/// @ingroup client
struct GdsApplicationFilter
{
  std::uint32_t startingRecordId{0};  ///< `0` starts at the first record.
  std::uint32_t maxRecordsToReturn{0};  ///< `0` means no limit.
  std::string applicationName;  ///< LIKE-pattern; empty disables this filter.
  std::string applicationUri;  ///< LIKE-pattern; empty disables this filter.
  std::uint32_t applicationType{0};  ///< Bit mask: `0x1` Servers, `0x2` Clients, `0` all.
  std::string productUri;  ///< LIKE-pattern; empty disables this filter.
  std::vector<std::string> capabilities;  ///< Ordered conjunctive requirements; empty disables.
};

/// Administrator-supplied endpoint parameters for the cached-endpoint (discovery-disabled) path
/// (CL-DISC-001, client design section 7.6 / section 7.7). Lets an operator connect without invoking
/// GetEndpoints.
/// @ingroup client
struct ManualEndpointConfig
{
  /// The endpoint URL to connect to (required).
  std::string endpointUrl;
  /// The security policy URI governing the channel (required  -  an empty policy is rejected).
  std::string securityPolicyUri;
  /// The message security mode.
  ua::MessageSecurityMode securityMode{ua::MessageSecurityMode::None};
  /// The server's application-instance certificate (DER). Optional for `None`; required for
  /// authenticated policies at connect time (validated by the connect flow, not here).
  ua::ByteString serverCertificate;
};

/// The Client-level (tier-1) Discovery facade (client design section 7.6).
///
/// Not bound to any `Connection`: each query opens (and closes) its own ephemeral None-policy channel to
/// the target discovery URL via the underlying client, issues the session-less request (Part 4 section 5.4),
/// and closes the channel. Obtained from @ref Client::discovery(); a lightweight value handle (copyable).
/// The facade holds no per-call state, so repeat invocation is always safe (CL-DISC-007).
///
/// **Status codes.** A query's Result carries the response's ServiceResult (FindServers, GetEndpoints,
/// FindServersOnNetwork) or the QueryServers / QueryApplications Call's code (the service's and the Method's
/// combined, `ua::detail::combined_status`), so a Good subcode or an Uncertain code the server answers
/// reaches the caller with the payload; an Uncertain Call without output arguments is answered with its code
/// and no reply. The steps the SDK acts on itself use only Good answers: an Uncertain channel or GDS
/// Connection open is refused with `Bad_InternalError` (`ServiceAnswerUncertain`) and closed, and an
/// Uncertain GDS browse-path resolution is refused (`ReferencesAnswerUncertain`). Each `*_sync` form throws
/// unless the Result is Good; a Good subcode on the answer is returned only by its `try_*_sync` form.
///
/// @ingroup client
class Discovery
{
public:
  // --- FindServers (Part 4 section 5.4.2) ---

  /// Result of FindServers: the discovered servers, or an @ref ua::ErrorDetail.
  using FindServersResult = ua::Result<std::vector<ua::ApplicationDescription>>;
  /// Callback receiving the outcome of @ref find_servers_async.
  using FindServersCallback = std::function<void(FindServersResult)>;

  /// Queries the servers known to a discovery endpoint (FindServers).
  ///
  /// Opens an ephemeral None-policy channel to @p discoveryUrl, threads @p discoveryUrl into the
  /// request's `endpointUrl` (CL-DISC-003), issues the session-less request, and closes the channel.
  /// The callback runs on the client's executor and must not block.
  ///
  /// @param discoveryUrl The discovery endpoint URL (used verbatim  -  no hard-coded default, CL-DISC-002).
  /// @param options      Filter/options (serverUris, locales, timeout).
  /// @param callback     Receives the servers or an @ref ua::ErrorDetail. Never throws.
  void find_servers_async(
    std::string discoveryUrl, FindServersOptions options, FindServersCallback callback) noexcept;

  /// @param discoveryUrl The discovery url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking FindServers. @throws ua::UaException when the Result is not Good. Must not run on the client's
  /// executor. A Good subcode on the answer is not returned; try_find_servers_sync() returns it.
  std::vector<ua::ApplicationDescription> find_servers_sync(
    std::string discoveryUrl, FindServersOptions options);

  /// @param discoveryUrl The discovery url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking FindServers, never throws. Must not run on the client's executor.
  FindServersResult try_find_servers_sync(std::string discoveryUrl, FindServersOptions options) noexcept;

  // --- GetEndpoints (Part 4 section 5.4.4) ---

  /// Result of GetEndpoints: the endpoint descriptions, or an @ref ua::ErrorDetail.
  using GetEndpointsResult = ua::Result<std::vector<ua::EndpointDescription>>;
  /// Callback receiving the outcome of @ref get_endpoints_async.
  using GetEndpointsCallback = std::function<void(GetEndpointsResult)>;

  /// Queries the endpoint descriptions of a server (GetEndpoints).
  ///
  /// Opens an ephemeral None-policy channel to @p discoveryUrl, threads @p discoveryUrl into the
  /// request's `endpointUrl` (CL-DISC-009), issues the session-less request, and closes the channel.
  /// Each returned `EndpointDescription` is a distinct configuration  -  the facade does NOT de-duplicate
  /// by URL (CL-DISC-010). The callback runs on the client's executor and must not block.
  ///
  /// @param discoveryUrl The discovery endpoint URL (used verbatim, CL-DISC-002).
  /// @param options      Filter/options (profile URIs, locales, timeout).
  /// @param callback     Receives the endpoints or an @ref ua::ErrorDetail. Never throws.
  void get_endpoints_async(
    std::string discoveryUrl, GetEndpointsOptions options, GetEndpointsCallback callback) noexcept;

  /// @param discoveryUrl The discovery url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking GetEndpoints. @throws ua::UaException when the Result is not Good. Must not run on the client's
  /// executor. A Good subcode on the answer is not returned; try_get_endpoints_sync() returns it.
  std::vector<ua::EndpointDescription> get_endpoints_sync(
    std::string discoveryUrl, GetEndpointsOptions options);

  /// @param discoveryUrl The discovery url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking GetEndpoints, never throws. Must not run on the client's executor.
  GetEndpointsResult try_get_endpoints_sync(std::string discoveryUrl, GetEndpointsOptions options) noexcept;

  // --- FindServersOnNetwork (Part 4 section 5.4.3  -  LDS-ME branch) ---

  /// The payload of a successful FindServersOnNetwork: the network server records plus the server's
  /// `lastCounterResetTime` (CL-DISC-013). Per Part 4 section 5.4.3 a paginating Client compares
  /// `lastCounterResetTime` across calls: a value newer than the one seen on a prior page means the
  /// server's record counter was reset, so the Client must re-request from `startingRecordId = 0` (records
  /// may have been missed). This single-shot call surfaces the field so the caller can make that comparison;
  /// the SDK does not retain cross-call state or auto-re-issue (it owns no pagination loop to restart).
  struct FindServersOnNetworkReply
  {
    std::vector<ua::ServerOnNetwork> servers;  ///< The network server records returned by this page.
    ua::UtcTime lastCounterResetTime;  ///< When the LDS-ME last reset its record counter.
  };

  /// Result of FindServersOnNetwork: the @ref FindServersOnNetworkReply, or an @ref ua::ErrorDetail.
  using FindServersOnNetworkResult = ua::Result<FindServersOnNetworkReply>;
  /// Callback receiving the outcome of @ref find_servers_on_network_async.
  using FindServersOnNetworkCallback = std::function<void(FindServersOnNetworkResult)>;

  /// Queries the mDNS-registered servers via an LDS-ME (FindServersOnNetwork).
  ///
  /// Opens an ephemeral None-policy channel to @p ldsMeUrl, threads the pagination inputs
  /// (CL-DISC-013), issues the session-less request, and closes the channel. The callback runs on the
  /// client's executor and must not block.
  ///
  /// @param ldsMeUrl The LDS-ME endpoint URL (used verbatim, CL-DISC-002).
  /// @param options  Pagination and capability-filter inputs.
  /// @param callback Receives the records or an @ref ua::ErrorDetail. Never throws.
  void find_servers_on_network_async(std::string ldsMeUrl, FindServersOnNetworkOptions options,
    FindServersOnNetworkCallback callback) noexcept;

  /// @param ldsMeUrl The lds me url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking FindServersOnNetwork. @throws ua::UaException when the Result is not Good. Must not run on the
  /// executor. A Good subcode on the answer is not returned; try_find_servers_on_network_sync() returns it.
  FindServersOnNetworkReply find_servers_on_network_sync(
    std::string ldsMeUrl, FindServersOnNetworkOptions options);

  /// @param ldsMeUrl The lds me url.
  /// @param options Options controlling the operation.
  /// @return The requested value.
  /// Blocking FindServersOnNetwork, never throws. Must not run on the client's executor.
  FindServersOnNetworkResult try_find_servers_on_network_sync(
    std::string ldsMeUrl, FindServersOnNetworkOptions options) noexcept;

  // --- GDS QueryServers (Part 12 section 6.6.11) ---

  /// Successful QueryServers payload, including the counter-reset timestamp required for safe pagination.
  struct GdsQueryServersReply
  {
    /// The m last counter reset time.
    ua::UtcTime lastCounterResetTime;
    /// The m servers.
    std::vector<ua::ServerOnNetwork> servers;
  };

  /// Callback invoked for gds query servers result notifications.
  using GdsQueryServersResult = ua::Result<GdsQueryServersReply>;
  /// Callback invoked for gds query servers callback notifications.
  using GdsQueryServersCallback = std::function<void(GdsQueryServersResult)>;

  /// Runs one QueryServers action sequence against a GDS.
  ///
  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Every invocation opens a fresh Session/Connection using @p connectionConfig, resolves the standard
  /// GDS Directory/QueryServers nodes from the live namespace table, invokes the Method, and gracefully
  /// closes the Session and SecureChannel before firing @p callback. No GDS Connection is retained or
  /// pooled between invocations (CL-DISC-016, Part 12 section 6.3).
  void gds_query_servers_async(
    ConnectionConfig connectionConfig, GdsServerFilter filter, GdsQueryServersCallback callback) noexcept;

  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @return The requested value.
  /// Synchronously gds query servers. A Good subcode on the answer is not returned;
  /// try_gds_query_servers_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  GdsQueryServersReply gds_query_servers_sync(ConnectionConfig connectionConfig, GdsServerFilter filter);

  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @return The requested value.
  /// Attempts to gds query servers sync without throwing.
  GdsQueryServersResult try_gds_query_servers_sync(
    ConnectionConfig connectionConfig, GdsServerFilter filter) noexcept;

  // --- GDS QueryApplications (Part 12 section 6.6.10) ---

  /// Public gds query applications reply API.
  struct GdsQueryApplicationsReply
  {
    /// The m last counter reset time.
    ua::UtcTime lastCounterResetTime;
    /// The m next record id.
    std::uint32_t nextRecordId{0};
    /// The m applications.
    std::vector<ua::ApplicationDescription> applications;
  };

  /// Callback invoked for gds query applications result notifications.
  using GdsQueryApplicationsResult = ua::Result<GdsQueryApplicationsReply>;
  /// Callback invoked for gds query applications callback notifications.
  using GdsQueryApplicationsCallback = std::function<void(GdsQueryApplicationsResult)>;

  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @param callback Completion callback that receives the operation result.
  /// Runs one QueryApplications action sequence on a fresh GDS Session. Filter fields and capability order
  /// are passed verbatim; the Session/Connection is closed before @p callback fires.
  void gds_query_applications_async(ConnectionConfig connectionConfig, GdsApplicationFilter filter,
    GdsQueryApplicationsCallback callback) noexcept;
  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @return The requested value.
  /// Synchronously gds query applications. A Good subcode on the answer is not returned;
  /// try_gds_query_applications_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  GdsQueryApplicationsReply gds_query_applications_sync(
    ConnectionConfig connectionConfig, GdsApplicationFilter filter);
  /// @param connectionConfig The connection config.
  /// @param filter Filter applied to the operation.
  /// @return The requested value.
  /// Attempts to gds query applications sync without throwing.
  GdsQueryApplicationsResult try_gds_query_applications_sync(
    ConnectionConfig connectionConfig, GdsApplicationFilter filter) noexcept;

  // --- Cached-endpoint admin (CL-DISC-001) ---

  /// Builds an @ref ua::EndpointDescription directly from administrator-supplied parameters, WITHOUT
  /// invoking any Discovery Service.
  ///
  /// This is the "discovery-disabled" configuration path (Part 4 section 5.4.1): in production systems where
  /// Discovery is administratively disabled, the operator supplies the endpoint parameters directly.
  /// No channel is opened and no FindServers/GetEndpoints request is issued.
  ///
  /// @param config Administrator-supplied endpoint parameters.
  /// @return The constructed EndpointDescription, or a bad Result whose @ref ua::ErrorDetail names the
  ///         missing required field (empty endpoint URL or empty security policy URI). Never throws.
  [[nodiscard]] ua::Result<ua::EndpointDescription> configure_endpoint(
    ManualEndpointConfig config) const noexcept;

  // --- mDNS browse (Part 12 Annex C) ---

  /// Result of starting an mDNS browse: the live browse handle, or an @ref ua::ErrorDetail.
  using MdnsBrowseResult = ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>>;

  /// Starts a direct mDNS browse for OPC UA servers (no LDS).
  ///
  /// Maps @p config's scheme to the OPC UA service type per Part 12 Annex C.3 (CL-DISC-015) and delegates
  /// to the installed @ref ua::mdns::MdnsTransport (the default, or one set via
  /// @ref Client::set_mdns_transport). The browse is stream-shaped: records arrive/expire via the
  /// returned handle's callbacks. Returned synchronously since the handle carries its own callback
  /// channel; a start failure is surfaced through the Result.
  ///
  /// @param config Browse parameters.
  /// @return The browse handle, or a bad Result carrying the transport's @ref ua::ErrorDetail. This
  ///         failing branch never prevents the LDS query paths from working (CL-DISC-006). Never throws.
  [[nodiscard]] MdnsBrowseResult start_mdns_browse(ua::mdns::MdnsBrowseConfig config) noexcept;

private:
  friend class Client;
  friend class DiscoveryTestAccess;

  Discovery(std::shared_ptr<detail::DiscoveryChannelFactory> channelFactory,
    std::shared_ptr<ua::mdns::MdnsTransport> mdnsTransport, bool allowDeprecatedSecurityPolicies);

  std::shared_ptr<detail::DiscoveryChannelFactory> mChannelFactory;
  std::shared_ptr<ua::mdns::MdnsTransport> mMdnsTransport;
  bool mAllowDeprecatedSecurityPolicies{false};
};

}  // namespace ua::client

#endif  // !UA_DISCOVERY_H
