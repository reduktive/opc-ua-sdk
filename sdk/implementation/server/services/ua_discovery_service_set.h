// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DISCOVERY_SERVICE_SET_H
#define UA_DISCOVERY_SERVICE_SET_H

#include "ua_application_configuration.h"
#include "ua_server_configuration.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_node_utilities.h"
#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_request.h"
#include "ua_get_endpoints_request.h"
#include "ua_register_server_request.h"
#include "ua_register_server2_request.h"
#include "ua_endpoint_description.h"
#include "ua_message_security_mode.h"
#include "ua_timer.h"
#include "ua_await_callback.h"
#include "ua_coro.h"
#include "ua_service_base.h"
#include "ua_server.h"
#include "ua_result.h"
#include "ua_logger.h"

#include <optional>
#include <string>

namespace ua
{

class CertificateStore;

namespace server
{

class DiagnosticCollector;
class Session;
class RegisteredServerStore;

struct ServerEndpointConfig;

class DiscoveryDependencies
{
public:
  DiscoveryDependencies() = default;
  DiscoveryDependencies(const DiscoveryDependencies&) = delete;
  DiscoveryDependencies(DiscoveryDependencies&&) = delete;
  DiscoveryDependencies& operator=(const DiscoveryDependencies&) = delete;
  DiscoveryDependencies& operator=(DiscoveryDependencies&&) = delete;
  virtual ~DiscoveryDependencies() = default;

  virtual boost::asio::any_io_executor executor() = 0;
  /// BY VALUE, deliberately. An implementation that returned a reference had to keep the thing
  /// referred to alive for as long as the caller might read it, and the one that did so by locking
  /// a weak owner released that lock on return - a dangling view onto a temporary, which TSan
  /// caught as a discovery continuation reading the identity while the server destructor freed it.
  /// A continuation must not hold a lock, so the signature stops asking. The type is a handful of
  /// strings and this is read once per discovery request, so the copy is not worth a lifetime rule.
  virtual ::ua::ApplicationIdentity identity() = 0;
  virtual const ::ua::ApplicationConfig& configuration() = 0;
  virtual const ::ua::server::ServerConfig& server_configuration() = 0;
  virtual shared_ptr<ua::CertificateStore> default_application_group_certificate_store() = 0;

  /// The inbound LDS registry, or nullptr when the server-as-LDS feature is gated OFF.
  /// FindServers aggregates this store's online registrations alongside the server's own
  /// ApplicationDescription. Returning nullptr keeps the aggregation a null-check.
  virtual shared_ptr<RegisteredServerStore> registered_server_store() = 0;

  // Listener-aware discovery data.
  virtual ::ua::server::ListenerHandleList listeners() = 0;
  virtual std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle listener) = 0;
  virtual std::vector<::ua::transport::EndpointUrl> advertised_urls(
    ::ua::server::ListenerHandle listener) = 0;

  /// Server logger. The discovery error paths log the full ErrorDetail server-side (observability /
  /// audit) BEFORE the DiagnosticCollector masks it on the anonymous, no-message-security discovery
  /// wire - so the detail is preserved for operators (never silently discard ErrorDetail)
  /// while not being leaked to an untrusted caller (OPC 10000-2 6.3 / 10000-4 7.41.2.1: limit the
  /// error information exposed to pre-channel / unauthenticated callers).
  virtual ::ua::Logger logger() = 0;
};

// template<class T>
// concept IsDiscoveryRequestType =
//   IsAnyOf<FindServersRequest, FindServersOnNetworkRequest, GetEndpointsRequest>;

using EndpointDescriptionList = std::vector<EndpointDescription>;
using EndpointDescriptionListResult = Result<EndpointDescriptionList>;

// Channel-derived context required to validate inbound RegisterServer / RegisterServer2 requests
// (Part 4 5.4.5.1 / 7.32). The session-less secure-channel dispatch fills this from the channel
// state (message security mode + peer-certificate applicationUri). Empty / None for the
// session-borne discovery path, where registration is never accepted.
struct InboundRegistrationContext
{
  // The negotiated message security mode of the SecureChannel the request arrived on. An
  // unauthenticated channel (None) is rejected for RegisterServer / RegisterServer2.
  MessageSecurityMode messageSecurityMode{MessageSecurityMode::None};

  // The applicationUri (subjectAltName URI) of the peer certificate used to open the channel,
  // when one is present. Used to enforce serverUri == cert.applicationUri.
  std::optional<std::string> peerApplicationUri;
};

// Per-flow state lives in the .cpp; declared here only for the unique_ptr members.
template<typename RequestType>
struct FindServersState;
template<typename RequestType>
struct GetEndpointsState;
template<typename RequestType>
struct RegisterServerState;

template<typename RequestType>
class DiscoveryServiceSet : public ServiceBase<DiscoveryServiceSet<RequestType>>
{
  friend class ServiceBase<DiscoveryServiceSet<RequestType>>;

public:
  void abort(StatusCode reason) override;

  DiscoveryServiceSet(const DiscoveryServiceSet&) = delete;
  DiscoveryServiceSet(DiscoveryServiceSet&&) = delete;
  DiscoveryServiceSet& operator=(const DiscoveryServiceSet&) = delete;
  DiscoveryServiceSet& operator=(DiscoveryServiceSet&&) = delete;

  virtual ~DiscoveryServiceSet();

  using ServiceCallComplete = std::function<void(Response)>;

  static shared_ptr<DiscoveryServiceSet> create(weak_ptr<DiscoveryDependencies> dependencies,
    LocaleId sessionLocale, uint32_t requestId, RequestType&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback, InboundRegistrationContext registrationContext = {});

private:
  weak_ptr<DiscoveryDependencies> mDependencies;
  LocaleId mSessionLocale;
  uint32_t mRequestId;
  RequestType mRequest;
  ServiceCallComplete mServiceCallCompleteCallback;
  InboundRegistrationContext mRegistrationContext;

  std::unique_ptr<FindServersState<RequestType>> mFindServersState;
  std::unique_ptr<GetEndpointsState<RequestType>> mGetEndpointsState;
  std::unique_ptr<RegisterServerState<RequestType>> mRegisterServerState;

  DiscoveryServiceSet(weak_ptr<DiscoveryDependencies> dependencies, LocaleId sessionLocale,
    uint32_t requestId, RequestType&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback, InboundRegistrationContext registrationContext);

  // Kick-off hook called by ServiceBase::start(). Dispatches on RequestType
  // to start_find_servers or start_get_endpoints.
  void begin_processing();

  void start_find_servers();

  /// Resolves the endpoints and builds the answer. One await, so this is the whole flow: what it
  /// replaces was a start function, a posted completion, and a step enum to tell them apart.
  ua::async::Task<> run_find_servers(shared_ptr<DiscoveryDependencies> dependencies);
  void on_find_servers_endpoints_resolved(EndpointDescriptionListResult result);
  void complete_find_servers();
  void fail_find_servers(VoidResult error);

  // FindServersOnNetwork is an LDS-ME-only capability (Part 4 5.4.3). We are not
  // an LDS-ME, so this faults the call immediately with Bad_ServiceUnsupported
  // rather than leaving the request unanswered (DISC-FSN).
  void start_find_servers_on_network();

  void start_get_endpoints();
  ua::async::Task<> run_get_endpoints(shared_ptr<DiscoveryDependencies> dependencies);
  void on_get_endpoints_endpoints_resolved(EndpointDescriptionListResult result);
  void complete_get_endpoints();
  void fail_get_endpoints(VoidResult error);

  // RegisterServer / RegisterServer2 inbound (server-as-LDS write path). Validates the request
  // against the channel context, writes accepted registrations into the LDS store, and builds the
  // (per-config) response. Emits Bad_ServiceUnsupported when the feature is gated OFF.
  void start_register_server();
  ua::async::Task<> run_register_server(shared_ptr<RegisteredServerStore> store, RegisteredServer registered);
  void on_register_server_stored(VoidResult result);

  /// Awaits one collaborator call of one of this request's own bodies, on its strand. The answer is
  /// POSTED, which is what the chain's own `post_borrowing` did (R18).
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(this->mStrand,
      this->mLogger,
      this->weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          this->mStrand,
          this->mLogger,
          [completion = std::move(completion)](DiscoveryServiceSet&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  /// The request's own body. One service handles one request, so one task covers all three flows.
  ua::async::Task<> mRequestTask;
  void fail_register_server(VoidResult error);

  void timeout();

  void send_service_fault(StatusCode status, DiagnosticCollector& collector);
};

class Discovery : public std::enable_shared_from_this<Discovery>
{
public:
  using GetEndpointsCompleteCallback = std::function<void(EndpointDescriptionListResult)>;

  static shared_ptr<Discovery> create();

  // Transport-neutral validation helper used by session creation.
  // Returns true if `endpointUrl` exactly matches one of the server's advertised URLs.
  static bool is_endpoint_url_accepted(std::string_view endpointUrl, DiscoveryDependencies& dependencies);

  void get_endpoints_async(std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies,
    GetEndpointsCompleteCallback callback) const;

  EndpointDescriptionListResult try_get_endpoints_sync(
    std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies) const noexcept;

  // Throws unless the answer is Good. A Good subcode on the answer is not returned; try_get_endpoints_sync()
  // returns it.
  EndpointDescriptionList get_endpoints_sync(
    std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies) const;

private:
  Discovery() = default;
};

}  // namespace server

}  // namespace ua

#endif  // !UA_DISCOVERY_SERVICE_SET_H
