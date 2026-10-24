// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_certificate_validation_paths.h"
#include "ua_callback_safety.h"
#include "ua_discovery_service_set.h"
#include "ua_on_strand.h"
#include "ua_diagnostic_collector.h"
#include "ua_registered_server_store.h"
#include "ua_server.h"
#include "ua_node_utilities.h"
#include "ua_reference.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "../ua_server_endpoint_configuration.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_response.h"
#include "ua_register_server_response.h"
#include "ua_register_server2_response.h"
#include "ua_service_fault.h"
#include "ua_crypto_types.h"
#include "ua_security_policy.h"
#include "ua_security_policy_internal.h"
#include "ua_log_exception.h"
#include "ua_stack_utilities.h"
#include "ua_to_result.h"

#include "ua_url_parser.h"

#include <algorithm>
#include <future>
#include <span>

namespace ua::server
{

namespace
{

shared_ptr<const X509Certificate> get_application_certificate(
  const std::vector<CertificateStore::ApplicationCertificate>& certificates, CertificateType certificateType)
{
  shared_ptr<const X509Certificate> result;

  for (const auto& cert : certificates)
  {
    if (cert.certificateType == certificateType)
    {
      result = cert.certificate;
      check(result);
      break;
    }
  }

  return result;
}

// Project a RegisteredServer (the inbound LDS wire shape) onto the ApplicationDescription that
// FindServers returns. Part 12 4.3 / Part 4 5.4.2.2 - requested locales are ordered by client
// preference, so choose the first requested locale that the registered server supports. Absent a
// match, the first registered name remains the default.
ApplicationDescription registered_server_to_application_description(
  const RegisteredServer& registered, const Array<LocaleId>& requestedLocales)
{
  ApplicationDescription appDesc;
  appDesc.application_uri() = registered.server_uri();
  appDesc.product_uri() = registered.product_uri();
  appDesc.application_type() = registered.server_type();
  appDesc.gateway_server_uri() = registered.gateway_server_uri();

  const auto& names = registered.server_names();
  if (!names.empty())
  {
    LocalizedText chosen = names[0];
    bool matched = false;
    for (const auto& requestedLocale : requestedLocales)
    {
      for (const auto& name : names)
      {
        if (name.locale() == requestedLocale)
        {
          chosen = name;
          matched = true;
          break;
        }
      }
      if (matched)
        break;
    }
    appDesc.application_name() = chosen;
  }

  for (const auto& url : registered.discovery_urls())
  {
    appDesc.discovery_urls().payload().push_back(url);
  }

  return appDesc;
}

// Log a discovery failure's full StatusCode + ErrorDetail server-side. Discovery is anonymous /
// no-message-security, so the DiagnosticCollector masks this detail on the wire (OPC 10000-2 6.3);
// logging it here preserves it for operators/audit (never silently discard ErrorDetail).
void log_discovery_failure(
  const std::shared_ptr<DiscoveryDependencies>& deps, const char* site, const VoidResult& error)
{
  if (!deps)
  {
    return;
  }
  log_exception(deps->logger().with_category("discovery"),
    LogLevel::Warning,
    site,
    StatusCode{error.status_code().as_status(), error.shared_detail()});
}

}  // namespace

// =============================================================================================
// Per-flow state (private to this translation unit). Per-call services hold one flow at a time
// for the resolved request type; the flow struct concentrates locals that survive the
// Discovery::get_endpoints_async callback boundary plus the user-callback handle.
// =============================================================================================

template<typename RequestType>
struct FindServersState
{
  DiagnosticCollector collector;
  shared_ptr<Discovery> discovery;  // keeps the inner helper alive across the callback

  explicit FindServersState(uint32_t returnDiagnostics)
    // Discovery is session-less / pre-authentication; gate diagnostics with a fail-closed
    // DiagnosticSecurityContext{} (no diagnostics, mask) so internal ErrorDetail cannot leak to an
    // unauthenticated peer over a None discovery channel (OPC 10000-2 6.3 / 10000-4 7.41.2.1; the
    // three-gate / pre-auth-masking model). The full detail is logged server-side on the fail paths
    // before this masking, so it is preserved for operators. The single-arg DiagnosticCollector ctor
    // is test-only and bypasses all gating.
    : collector(returnDiagnostics, DiagnosticSecurityContext{}), discovery(Discovery::create())
  {}
};

template<typename RequestType>
struct GetEndpointsState
{
  DiagnosticCollector collector;
  shared_ptr<Discovery> discovery;

  explicit GetEndpointsState(uint32_t returnDiagnostics)
    // Discovery is session-less / pre-authentication; gate diagnostics with a fail-closed
    // DiagnosticSecurityContext{} (no diagnostics, mask) so internal ErrorDetail cannot leak to an
    // unauthenticated peer over a None discovery channel (OPC 10000-2 6.3 / 10000-4 7.41.2.1; the
    // three-gate / pre-auth-masking model). The full detail is logged server-side on the fail paths
    // before this masking, so it is preserved for operators. The single-arg DiagnosticCollector ctor
    // is test-only and bypasses all gating.
    : collector(returnDiagnostics, DiagnosticSecurityContext{}), discovery(Discovery::create())
  {}
};

template<typename RequestType>
struct RegisterServerState
{
  DiagnosticCollector collector;

  // Captured up front so the per-config response shape (RegisterServer2) can be built after the
  // async store write completes.
  std::size_t discoveryConfigurationCount{0};

  // Discovery is session-less / pre-authentication; gate diagnostics with a fail-closed
  // DiagnosticSecurityContext{} so internal ErrorDetail cannot leak to an unauthenticated peer.
  explicit RegisterServerState(uint32_t returnDiagnostics)
    : collector(returnDiagnostics, DiagnosticSecurityContext{})
  {}
};

template<typename RequestType>
shared_ptr<DiscoveryServiceSet<RequestType>> DiscoveryServiceSet<RequestType>::create(
  weak_ptr<DiscoveryDependencies> dependencies, LocaleId sessionLocale, uint32_t requestId,
  RequestType&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback,
  InboundRegistrationContext registrationContext)
{
  struct Wrapper : public DiscoveryServiceSet
  {
  public:
    Wrapper(weak_ptr<DiscoveryDependencies> dependencies, LocaleId sessionLocale, uint32_t requestId,
      RequestType&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback,
      InboundRegistrationContext registrationContext)
      : DiscoveryServiceSet(dependencies, std::move(sessionLocale), requestId, std::move(request), executor,
          callback, std::move(registrationContext))
    {}
  };

  auto service = make_shared<Wrapper>(dependencies,
    std::move(sessionLocale),
    requestId,
    std::move(request),
    executor,
    callback,
    std::move(registrationContext));
  service->start();
  return service;
}

template<typename RequestType>
DiscoveryServiceSet<RequestType>::DiscoveryServiceSet(weak_ptr<DiscoveryDependencies> dependencies,
  LocaleId sessionLocale, uint32_t requestId, RequestType&& request, boost::asio::any_io_executor executor,
  ServiceCallComplete callback, InboundRegistrationContext registrationContext)
  : ServiceBase<DiscoveryServiceSet<RequestType>>(request.request_header().request_handle(), executor),
    mDependencies(dependencies), mSessionLocale(std::move(sessionLocale)), mRequestId(requestId),
    mRequest(std::move(request)), mServiceCallCompleteCallback(callback),
    mRegistrationContext(std::move(registrationContext))
{
  // DiscoveryServiceSet uses the session-less ServiceBase constructor, so ServiceBase has no session
  // to source a logger from. Take one from the discovery dependencies (a ua::Logger is a value handle
  // that survives their destruction) so the post helpers can record a swallowed exception on drain.
  if (auto deps = dependencies.lock())
  {
    this->mLogger = deps->logger().with_category("discovery");
  }
}

// Destructor - fires Status::BadShutdown if a flow is still in flight when the service is
// destroyed. try_finish() is the idempotent gate; if a completion point already terminated the
// flow, try_finish returns false and the destructor drops silently.
template<typename RequestType>
DiscoveryServiceSet<RequestType>::~DiscoveryServiceSet()
{
  if (!mFindServersState && !mGetEndpointsState && !mRegisterServerState)
  {
    return;
  }
  if (!this->try_finish())
  {
    return;
  }
  // Move-out the user callback before resetting flow state so reentrant logic in the
  // callback cannot observe a partially-torn-down service.
  auto callback = std::move(mServiceCallCompleteCallback);
  mFindServersState.reset();
  mGetEndpointsState.reset();
  mRegisterServerState.reset();
  if (callback)
  {
    auto serviceFault = stack_utils::create_service_fault(&mRequest.request_header(), Status::BadShutdown);
    callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceFault)));
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::begin_processing()
{
  if constexpr (std::is_same_v<RequestType, FindServersRequest>)
  {
    start_find_servers();
  }
  else if constexpr (std::is_same_v<RequestType, FindServersOnNetworkRequest>)
  {
    start_find_servers_on_network();
  }
  else if constexpr (std::is_same_v<RequestType, GetEndpointsRequest>)
  {
    start_get_endpoints();
  }
  else if constexpr (std::is_same_v<RequestType, RegisterServerRequest> ||
                     std::is_same_v<RequestType, RegisterServer2Request>)
  {
    start_register_server();
  }
}

// =============================================================================================
// FindServers flow
// =============================================================================================
//
// ASCII flow:
//   start_find_servers (entry from begin_processing, on mStrand)
//     [synchronous validation: lock dependencies, set timeout]
//     -> Discovery::get_endpoints_async (callback re-enters mStrand via post)
//        -> on_find_servers_endpoints_resolved
//             [is_bad]  fail_find_servers(VoidResult{status, shared_detail()})
//             [success] complete_find_servers (build response, fire user callback)
//
// On cancel: send_service_fault(BadRequestCancelledByClient, ...).
// On timeout: send_service_fault(BadTimeout, ...).
// On destructor mid-flight: ~DiscoveryServiceSet fires BadShutdown via try_finish.

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::start_find_servers()
{
  auto& findServersRequest = mRequest;
  mFindServersState =
    std::make_unique<FindServersState<RequestType>>(findServersRequest.request_header().return_diagnostics());

  auto deps = mDependencies.lock();
  if (!deps)
  {
    fail_find_servers(VoidResult{Status::BadShutdown});
    return;
  }
  this->set_timeout(findServersRequest.request_header().timeout_hint());

  mRequestTask = run_find_servers(std::move(deps));
}

template<typename RequestType>
ua::async::Task<> DiscoveryServiceSet<RequestType>::run_find_servers(
  shared_ptr<DiscoveryDependencies> dependencies)
{
  // A ROOT task: nobody awaits `mRequestTask`, so an exception that escaped this body would be
  // stored in a promise nobody can read and the client's FindServers would go unanswered.
  try
  {
    const std::string endpointUrl{mRequest.endpoint_url()};
    auto result = co_await await_step<EndpointDescriptionListResult>(
      [&](auto completion) {
        mFindServersState->discovery->get_endpoints_async(endpointUrl, dependencies, std::move(completion));
      });

    if (!mFindServersState)
    {
      co_return;
    }
    on_find_servers_endpoints_resolved(std::move(result));
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the request and answered its caller.
    ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    ua::async::guarded(this->mLogger,
      [this]
      {
        if (mFindServersState)
        {
          fail_find_servers(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::on_find_servers_endpoints_resolved(
  EndpointDescriptionListResult result)
{
  if (!mFindServersState)
    return;
  if (!result.is_good())
  {
    // Forward both status and shared_detail() - the Result invariant.
    // Pinned by FS-D (CertStore failure surfaces ErrorDetail through wire).
    fail_find_servers(VoidResult{result.status_code(), result.shared_detail()});
    return;
  }

  auto endpoints = std::move(result).value();

  if constexpr (std::is_same_v<RequestType, FindServersRequest>)
  {
    auto deps = mDependencies.lock();
    if (!deps)
    {
      fail_find_servers(VoidResult{Status::BadShutdown});
      return;
    }

    auto response = make_shared<FindServersResponse>();

    std::vector<std::string_view> discoveryUrls;
    discoveryUrls.reserve(endpoints.size());
    for (const auto& ep : endpoints)
    {
      const auto& url = ep.endpoint_url();
      if (url.empty())
      {
        continue;
      }
      if (std::ranges::find(discoveryUrls, std::string_view{url}) == discoveryUrls.end())
      {
        discoveryUrls.push_back(url);
      }
    }

    // Part 4 5.4.2 / Part 12 4.3 - honour the optional serverUris filter (empty => return all).
    // The filter applies to EVERY returned server, including this server's own description - not
    // just to registered (LDS) servers (UACTT finding F2: the self-entry previously bypassed it).
    const auto& serverUrisFilter = mRequest.server_uris().payload();
    const bool filterEnabled = !serverUrisFilter.empty();
    auto matchesFilter = [&](const String& uri)
    {
      return !filterEnabled || std::ranges::find(serverUrisFilter, uri) != serverUrisFilter.end();
    };

    auto appDesc = deps->configuration().construct_application_description(deps->identity(), discoveryUrls);
    const auto& requestedLocales = mRequest.locale_ids().payload();
    const std::span<const LocaleId> localePriority{requestedLocales.data(), requestedLocales.size()};
    appDesc.application_name() = appDesc.application_name().resolve(localePriority);
    if (matchesFilter(String{appDesc.application_uri()}))
    {
      response->servers().payload().push_back(appDesc);
    }

    // Aggregate inbound LDS registrations (server-as-LDS). When the feature is gated OFF the
    // store accessor returns nullptr and the response is identical to the self-only behaviour.
    if (auto store = deps->registered_server_store())
    {
      for (const auto& registered : store->snapshot())
      {
        if (!matchesFilter(String{registered.server_uri()}))
        {
          continue;
        }
        response->servers().payload().push_back(
          registered_server_to_application_description(registered, mRequest.locale_ids()));
      }
    }

    Array<DiagnosticInfo> unused;
    mFindServersState->collector.apply_to(response->response_header(), unused, 0);
    stack_utils::prepare_response_header(mRequest.request_header(), response->response_header());

    if (!this->try_finish())
    {
      mFindServersState.reset();
      return;
    }

    auto callback = mServiceCallCompleteCallback;
    mFindServersState.reset();
    if (callback)
    {
      callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(response)));
    }
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::complete_find_servers()
{
  // Choke-point retained for symmetry with the merged 4.5g pattern. The success path
  // is small enough to inline in on_find_servers_endpoints_resolved; this method
  // exists to anchor the 5.4.5 firing pattern documentation.
  // (Currently unreached - kept for 5.4.5 conformance and future single-success choke.)
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::fail_find_servers(VoidResult error)
{
  if (!mFindServersState)
    return;
  // Log the full ErrorDetail server-side before the collector masks it on the anonymous discovery wire.
  log_discovery_failure(mDependencies.lock(), "DiscoveryServiceSet.FindServers", error);
  mFindServersState->collector.set_service_detail(error.status_code());
  send_service_fault(error.status_code(), mFindServersState->collector);
  mFindServersState.reset();
}

// =============================================================================================
// FindServersOnNetwork flow
// =============================================================================================
template<typename RequestType>
void DiscoveryServiceSet<RequestType>::start_find_servers_on_network()
{
  // FindServersOnNetwork is an LDS-ME capability (Part 4 5.4.3). A server that is not an
  // LDS-ME SHALL return Bad_ServiceUnsupported. We are not an LDS-ME, so fault the service
  // call immediately rather than leaving the request silently unanswered (DISC-FSN).
  // Discovery is session-less / pre-authentication; gate diagnostics with a fail-closed
  // DiagnosticSecurityContext{} so internal ErrorDetail cannot leak to an unauthenticated peer.
  DiagnosticCollector collector{mRequest.request_header().return_diagnostics(), DiagnosticSecurityContext{}};
  collector.set_service_detail(Status::BadServiceUnsupported);
  send_service_fault(Status::BadServiceUnsupported, collector);
}

// =============================================================================================
// GetEndpoints flow
// =============================================================================================
//
// ASCII flow:
//   start_get_endpoints (entry from begin_processing, on mStrand)
//     [synchronous validation: lock dependencies, set timeout]
//     -> Discovery::get_endpoints_async (callback re-enters mStrand via post)
//        -> on_get_endpoints_endpoints_resolved
//             [is_bad]  fail_get_endpoints(VoidResult{status, shared_detail()})
//             [success] filter_by_profile_uri (synchronous), build response, fire callback

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::start_get_endpoints()
{
  auto& getEndpointsRequest = mRequest;
  mGetEndpointsState = std::make_unique<GetEndpointsState<RequestType>>(
    getEndpointsRequest.request_header().return_diagnostics());

  auto deps = mDependencies.lock();
  if (!deps)
  {
    fail_get_endpoints(VoidResult{Status::BadShutdown});
    return;
  }
  this->set_timeout(getEndpointsRequest.request_header().timeout_hint());

  mRequestTask = run_get_endpoints(std::move(deps));
}

template<typename RequestType>
ua::async::Task<> DiscoveryServiceSet<RequestType>::run_get_endpoints(
  shared_ptr<DiscoveryDependencies> dependencies)
{
  try
  {
    const std::string endpointUrl{mRequest.endpoint_url()};
    auto result = co_await await_step<EndpointDescriptionListResult>(
      [&](auto completion) {
        mGetEndpointsState->discovery->get_endpoints_async(endpointUrl, dependencies, std::move(completion));
      });

    if (!mGetEndpointsState)
    {
      co_return;
    }
    on_get_endpoints_endpoints_resolved(std::move(result));
  }
  catch (const ua::async::Abandoned&)
  {
    ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    ua::async::guarded(this->mLogger,
      [this]
      {
        if (mGetEndpointsState)
        {
          fail_get_endpoints(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::on_get_endpoints_endpoints_resolved(
  EndpointDescriptionListResult result)
{
  if (!mGetEndpointsState)
    return;
  if (!result.is_good())
  {
    // Pinned by GE-D / GE-E - content fidelity through wire (status_code + shared_detail()).
    fail_get_endpoints(VoidResult{result.status_code(), result.shared_detail()});
    return;
  }

  auto endpoints = std::move(result).value();

  if constexpr (std::is_same_v<RequestType, GetEndpointsRequest>)
  {
    auto response = make_shared<GetEndpointsResponse>();

    const auto& profileUrisFilter = mRequest.profile_uris().payload();
    if (!profileUrisFilter.empty())
    {
      endpoints.erase(std::remove_if(endpoints.begin(),
                        endpoints.end(),
                        [&profileUrisFilter](const EndpointDescription& ep)
                        {
                          return std::ranges::find(profileUrisFilter, String{ep.transport_profile_uri()}) ==
                                 profileUrisFilter.end();
                        }),
        endpoints.end());
    }

    const auto& requestedLocales = mRequest.locale_ids().payload();
    const std::span<const LocaleId> localePriority{requestedLocales.data(), requestedLocales.size()};
    for (auto& endpoint : endpoints)
    {
      auto& applicationName = endpoint.server().application_name();
      applicationName = applicationName.resolve(localePriority);
    }

    response->endpoints() = endpoints;

    Array<DiagnosticInfo> unused;
    mGetEndpointsState->collector.apply_to(response->response_header(), unused, 0);
    stack_utils::prepare_response_header(mRequest.request_header(), response->response_header());

    if (!this->try_finish())
    {
      mGetEndpointsState.reset();
      return;
    }

    auto callback = mServiceCallCompleteCallback;
    mGetEndpointsState.reset();
    if (callback)
    {
      callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(response)));
    }
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::complete_get_endpoints()
{
  // See complete_find_servers - kept for 5.4.5 symmetry.
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::fail_get_endpoints(VoidResult error)
{
  if (!mGetEndpointsState)
    return;
  // Log the full ErrorDetail server-side before the collector masks it on the anonymous discovery wire.
  log_discovery_failure(mDependencies.lock(), "DiscoveryServiceSet.GetEndpoints", error);
  mGetEndpointsState->collector.set_service_detail(error.status_code());
  send_service_fault(error.status_code(), mGetEndpointsState->collector);
  mGetEndpointsState.reset();
}

// =============================================================================================
// RegisterServer / RegisterServer2 inbound flow (server-as-LDS write path)
// =============================================================================================
//
// ASCII flow:
//   start_register_server (entry from begin_processing, on mStrand)
//     [feature gate]  registered_server_store() == nullptr -> Bad_ServiceUnsupported
//                     (server.tier1.lds.inbound.feature_disabled)
//     [validation, Part 4 5.4.5.1 / 7.32]
//       channel unauthenticated (None)        -> Bad_SecurityModeInsufficient
//                                                (server.tier1.lds.inbound.unauthenticated_channel)
//       serverUri empty                        -> Bad_ServerUriInvalid (SVR-DISC-RS-016)
//       serverNames empty                      -> Bad_ServerNameMissing (SVR-DISC-RS-017)
//       discoveryUrls empty (online)           -> Bad_DiscoveryUrlMissing (SVR-DISC-RS-018)
//       serverType == Client / out-of-range    -> Bad_InvalidArgument (SVR-DISC-RS-020)
//       serverUri != peer cert applicationUri  -> Bad_ServerUriInvalid (SVR-DISC-RS-003 / SVR-DISC-LDS-005)
//                                                (server.tier1.lds.inbound.server_uri_mismatch)
//     -> store->register_async (callback re-enters mStrand via post)
//        -> on_register_server_stored
//             [is_bad]  fail_register_server(VoidResult{status, shared_detail()})
//             [success] build response (RegisterServer2: per-config configurationResults[]) + fire
//
// On cancel: send_service_fault(BadRequestCancelledByClient). On timeout: BadTimeout. On destructor
// mid-flight: ~DiscoveryServiceSet fires BadShutdown via try_finish.

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::start_register_server()
{
  if constexpr (std::is_same_v<RequestType, RegisterServerRequest> ||
                std::is_same_v<RequestType, RegisterServer2Request>)
  {
    mRegisterServerState =
      std::make_unique<RegisterServerState<RequestType>>(mRequest.request_header().return_diagnostics());

    auto deps = mDependencies.lock();
    if (!deps)
    {
      fail_register_server(VoidResult{Status::BadShutdown});
      return;
    }
    this->set_timeout(mRequest.request_header().timeout_hint());

    // Feature gate: the store accessor returns nullptr when the server-as-LDS feature is OFF.
    auto store = deps->registered_server_store();
    if (!store)
    {
      fail_register_server(VoidResult{Status::BadServiceUnsupported,
        make_error_detail("RegistrationDisabled",
          "RegisterServer rejected: the server-as-LDS feature is disabled",
          "server.tier1.lds.inbound.feature_disabled")});
      return;
    }

    // (1) Reject an unauthenticated channel (Part 4 5.4.5.1 / SVR-DISC-LDS-005). The registration
    // identity rests on the peer certificate, which only exists on a signed/encrypted channel.
    if (mRegistrationContext.messageSecurityMode == MessageSecurityMode::None)
    {
      fail_register_server(VoidResult{Status::BadSecurityModeInsufficient,
        make_error_detail("UnauthenticatedChannel",
          "RegisterServer rejected: the SecureChannel is not authenticated (MessageSecurityMode None)",
          "server.tier1.lds.inbound.unauthenticated_channel")});
      return;
    }

    const auto& registered = mRequest.server();

    // (2) serverUri non-empty (SVR-DISC-RS-016).
    const std::string serverUri{registered.server_uri()};
    if (serverUri.empty())
    {
      fail_register_server(VoidResult{Status::BadServerUriInvalid,
        make_error_detail("ServerUriInvalid",
          "RegisterServer rejected: serverUri is empty",
          "server.tier1.lds.inbound.server_uri_invalid")});
      return;
    }

    // (3) serverNames non-empty (SVR-DISC-RS-017).
    if (registered.server_names().payload().empty())
    {
      fail_register_server(VoidResult{Status::BadServerNameMissing,
        ErrorDetail::build("ServerNameMissing",
          "RegisterServer rejected: serverNames is empty",
          "server.tier1.lds.inbound.server_name_missing")
          .context(ua::ContextKeys::applicationUri, serverUri)});
      return;
    }

    // (4) serverType must be a valid, non-Client ApplicationType (SVR-DISC-RS-020).
    const auto serverType = registered.server_type();
    const bool validServerType = serverType == ApplicationType::Server ||
                                 serverType == ApplicationType::ClientAndServer ||
                                 serverType == ApplicationType::DiscoveryServer;
    if (!validServerType)
    {
      fail_register_server(VoidResult{Status::BadInvalidArgument,
        ErrorDetail::build("InvalidServerType",
          "RegisterServer rejected: serverType is Client or out of range",
          "server.tier1.lds.inbound.invalid_server_type")
          .context(ua::ContextKeys::actual, ua::to_string(serverType))
          .context(ua::ContextKeys::applicationUri, serverUri)});
      return;
    }

    // (5) For an online registration, discoveryUrls must be non-empty (SVR-DISC-RS-018). An offline
    // (isOnline=false) registration is an eviction and carries no URLs.
    if (registered.is_online() && registered.discovery_urls().payload().empty())
    {
      fail_register_server(VoidResult{Status::BadDiscoveryUrlMissing,
        ErrorDetail::build("DiscoveryUrlMissing",
          "RegisterServer rejected: discoveryUrls is empty for an online registration",
          "server.tier1.lds.inbound.discovery_url_missing")
          .context(ua::ContextKeys::applicationUri, serverUri)});
      return;
    }

    // (6) serverUri must match the peer certificate applicationUri (Part 4 5.4.5.1 / 7.32 -
    // SVR-DISC-RS-003 / SVR-DISC-LDS-005). When no peer cert URI is available the channel is not
    // client-authenticating for registration purposes; reject for the same reason.
    if (!mRegistrationContext.peerApplicationUri || *mRegistrationContext.peerApplicationUri != serverUri)
    {
      fail_register_server(VoidResult{Status::BadServerUriInvalid,
        ErrorDetail::build("ServerUriMismatch",
          "RegisterServer rejected: serverUri does not match the SecureChannel certificate applicationUri",
          "server.tier1.lds.inbound.server_uri_mismatch")
          .context(ua::ContextKeys::actual, serverUri)
          .context(
            ua::ContextKeys::expected, mRegistrationContext.peerApplicationUri.value_or(std::string{}))});
      return;
    }

    if constexpr (std::is_same_v<RequestType, RegisterServer2Request>)
    {
      mRegisterServerState->discoveryConfigurationCount = mRequest.discovery_configuration().payload().size();
    }

    mRequestTask = run_register_server(std::move(store), RegisteredServer{registered});
  }
}

template<typename RequestType>
ua::async::Task<> DiscoveryServiceSet<RequestType>::run_register_server(
  shared_ptr<RegisteredServerStore> store, RegisteredServer registered)
{
  try
  {
    auto result = co_await await_step<VoidResult>(
      [&](auto completion) { store->register_async(std::move(registered), std::move(completion)); });

    if (!mRegisterServerState)
    {
      co_return;
    }
    on_register_server_stored(std::move(result));
  }
  catch (const ua::async::Abandoned&)
  {
    ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    ua::async::guarded(this->mLogger,
      [this]
      {
        if (mRegisterServerState)
        {
          fail_register_server(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::on_register_server_stored(VoidResult result)
{
  if constexpr (std::is_same_v<RequestType, RegisterServerRequest> ||
                std::is_same_v<RequestType, RegisterServer2Request>)
  {
    if (!mRegisterServerState)
      return;
    if (result.is_bad())
    {
      // Forward both status and shared_detail() - the Result invariant.
      fail_register_server(VoidResult{result.status_code(), result.shared_detail()});
      return;
    }

    shared_ptr<ua::Structure> response;
    if constexpr (std::is_same_v<RequestType, RegisterServer2Request>)
    {
      auto registerResponse = make_shared<RegisterServer2Response>();
      // SVR-DISC-RS2-003: one positional StatusCode per discoveryConfiguration entry. This
      // implementation is not an LDS-ME and interprets no discovery configuration types, including
      // MdnsDiscoveryConfiguration, so every supplied entry is unsupported. The registration itself
      // still succeeds; BadNotSupported belongs in configurationResults, not the ServiceResult.
      auto& configurationResults = registerResponse->configuration_results().payload();
      configurationResults.reserve(mRegisterServerState->discoveryConfigurationCount);
      for (std::size_t i = 0; i < mRegisterServerState->discoveryConfigurationCount; ++i)
      {
        configurationResults.emplace_back(Status::BadNotSupported,
          ErrorDetail::build("DiscoveryConfigurationUnsupported",
            "Discovery Server does not understand the supplied discovery configuration",
            "server.tier1.lds.inbound.discovery_configuration")
            .context(ua::ContextKeys::operationIndex, i));
      }
      mRegisterServerState->collector.apply_to(
        registerResponse->response_header(),
        [&configurationResults](size_t index) { return configurationResults[index]; },
        configurationResults.size(),
        registerResponse->diagnostic_infos());
      stack_utils::prepare_response_header(mRequest.request_header(), registerResponse->response_header());
      response = std::static_pointer_cast<ua::Structure>(registerResponse);
    }
    else
    {
      auto registerResponse = make_shared<RegisterServerResponse>();
      Array<DiagnosticInfo> unused;
      mRegisterServerState->collector.apply_to(registerResponse->response_header(), unused, 0);
      stack_utils::prepare_response_header(mRequest.request_header(), registerResponse->response_header());
      response = std::static_pointer_cast<ua::Structure>(registerResponse);
    }

    if (!this->try_finish())
    {
      mRegisterServerState.reset();
      return;
    }

    auto callback = mServiceCallCompleteCallback;
    mRegisterServerState.reset();
    if (callback)
    {
      callback(std::make_pair(mRequestId, std::move(response)));
    }
  }
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::fail_register_server(VoidResult error)
{
  if (!mRegisterServerState)
    return;
  // Log the full ErrorDetail server-side before the collector masks it on the anonymous discovery wire.
  log_discovery_failure(mDependencies.lock(), "DiscoveryServiceSet.RegisterServer", error);
  mRegisterServerState->collector.set_service_detail(error.status_code());
  send_service_fault(error.status_code(), mRegisterServerState->collector);
  mRegisterServerState.reset();
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::abort(StatusCode reason)
{
  ua::async::post_borrowing(this,
    this->mStrand,
    this->mLogger,
    [reason = std::move(reason)](auto& self) mutable
    {
      DiagnosticCollector collector{0};
      self.send_service_fault(reason, collector);
      self.mFindServersState.reset();
      self.mGetEndpointsState.reset();
      self.mRequestTask = {};
      self.mRegisterServerState.reset();
    })();
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::timeout()
{
  DiagnosticCollector collector{0};
  send_service_fault(Status::BadTimeout, collector);
  mFindServersState.reset();
  mGetEndpointsState.reset();
  mRegisterServerState.reset();
}

template<typename RequestType>
void DiscoveryServiceSet<RequestType>::send_service_fault(StatusCode status, DiagnosticCollector& collector)
{
  if (!this->try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&mRequest.request_header(), status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(
      std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceFault)));
  }
}

template shared_ptr<DiscoveryServiceSet<GetEndpointsRequest>>
  DiscoveryServiceSet<GetEndpointsRequest>::create(weak_ptr<DiscoveryDependencies> dependencies,
    LocaleId sessionLocale, uint32_t requestId, GetEndpointsRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback,
    InboundRegistrationContext registrationContext);

template shared_ptr<DiscoveryServiceSet<FindServersRequest>> DiscoveryServiceSet<FindServersRequest>::create(
  weak_ptr<DiscoveryDependencies> dependencies, LocaleId sessionLocale, uint32_t requestId,
  FindServersRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback,
  InboundRegistrationContext registrationContext);

template shared_ptr<DiscoveryServiceSet<FindServersOnNetworkRequest>>
  DiscoveryServiceSet<FindServersOnNetworkRequest>::create(weak_ptr<DiscoveryDependencies> dependencies,
    LocaleId sessionLocale, uint32_t requestId, FindServersOnNetworkRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback,
    InboundRegistrationContext registrationContext);

template shared_ptr<DiscoveryServiceSet<RegisterServerRequest>>
  DiscoveryServiceSet<RegisterServerRequest>::create(weak_ptr<DiscoveryDependencies> dependencies,
    LocaleId sessionLocale, uint32_t requestId, RegisterServerRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback,
    InboundRegistrationContext registrationContext);

template shared_ptr<DiscoveryServiceSet<RegisterServer2Request>>
  DiscoveryServiceSet<RegisterServer2Request>::create(weak_ptr<DiscoveryDependencies> dependencies,
    LocaleId sessionLocale, uint32_t requestId, RegisterServer2Request&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback,
    InboundRegistrationContext registrationContext);

shared_ptr<Discovery> Discovery::create()
{
  struct Wrapper : public Discovery
  {
  public:
    Wrapper() : Discovery()
    {}
  };

  return make_shared<Wrapper>();
}

bool Discovery::is_endpoint_url_accepted(std::string_view endpointUrl, DiscoveryDependencies& dependencies)
{
  if (endpointUrl.empty())
  {
    return false;
  }

  auto incoming = transport::parse_opc_tcp_url(std::string{endpointUrl}, "Discovery");
  if (!incoming)
  {
    return false;
  }

  for (const auto listener : dependencies.listeners())
  {
    for (const auto& url : dependencies.advertised_urls(listener))
    {
      auto advertised = transport::parse_opc_tcp_url(url.str(), "Discovery");
      if (advertised && transport::matches_port_and_path(incoming.value(), advertised.value()))
      {
        return true;
      }
    }
  }

  return false;
}

namespace
{

EndpointDescriptionListResult build_endpoint_descriptions(const std::string& endpointUrl,
  const std::vector<CertificateStore::ApplicationCertificate>& certificates,
  DiscoveryDependencies& dependencies)
{
  const bool filterEnabled = !endpointUrl.empty();

  // Parse the client's request URL to extract the hostname for response rewriting.
  auto parsedRequest = filterEnabled ? transport::parse_opc_tcp_url(endpointUrl, "Discovery")
                                     : transport::ParsedOpcTcpUrlResult{transport::ParsedOpcTcpUrl{}};

  // Build the endpoint list. When applyFilter is true, only listeners whose advertised URL
  // matches the request URL (port + path) are included, and each response URL's host is
  // rewritten to the client-supplied host so the returned endpoint is reachable.
  auto build = [&](bool applyFilter) -> EndpointDescriptionList
  {
    EndpointDescriptionList results;

    for (const auto& listener : dependencies.listeners())
    {
      const auto advertisedUrls = dependencies.advertised_urls(listener);
      const auto endpoints = dependencies.endpoints(listener);

      for (const auto& adv : advertisedUrls)
      {
        const auto& advStr = adv.str();
        if (applyFilter)
        {
          auto parsedAdv = transport::parse_opc_tcp_url(advStr, "Discovery");
          if (!parsedRequest || !parsedAdv ||
              !transport::matches_port_and_path(parsedRequest.value(), parsedAdv.value()))
          {
            continue;
          }
        }

        // Part 4, 5.4.4.1: return endpoints "accessible to the Client via the provided URL".
        // Rewrite the host to match the client's request so the returned URL is reachable.
        auto responseUrl = (applyFilter && parsedRequest)
                             ? transport::rewrite_host(advStr, parsedRequest.value().hostname)
                             : advStr;

        std::array<string_view, 1> urls = {responseUrl};
        const auto appDesc =
          dependencies.configuration().construct_application_description(dependencies.identity(), urls);

        for (const auto& endpoint : endpoints)
        {
          EndpointDescription endpointDescription;

          endpointDescription.endpoint_url() = responseUrl;
          endpointDescription.server() = appDesc;

          auto securityPolicy = SecurityPolicy::create(endpoint.securityPolicyId);
          check(securityPolicy);
          endpointDescription.security_policy_uri() = securityPolicy->uri();

          // Determine which certificate to present for this endpoint.
          // For authenticated channels, use the channel policy's cert type.
          // For None channels with authenticated user token policies, resolve the cert type
          // from those policies so the client knows which cert to expect.
          // OPC 10000-4 Table 193 / OPC 10000-6 6.8.3: for a None channel, a held certificate valid for every
          // token policy.
          auto resolvedCertType = stack_utils::resolve_certificate_type_for_endpoint(
            securityPolicy->id(), endpoint.userIdentityTokens, certificates);

          if (resolvedCertType)
          {
            if (auto cert = get_application_certificate(certificates, *resolvedCertType))
            {
              // Decision 24: the leaf then the own issuer chain in order (OPC 10000-6 section 6.2.6).
              const auto entry = std::ranges::find(
                certificates, *resolvedCertType, &CertificateStore::ApplicationCertificate::certificateType);
              endpointDescription.server_certificate() = ::ua::detail::encode_certificate_field(cert,
                entry != certificates.end() ? entry->issuerCertificates
                                            : std::vector<shared_ptr<const X509Certificate>>{});
            }
            else if (securityPolicy->is_authenticated())
            {
              // Authenticated channel requires a certificate - skip endpoint if missing.
              continue;
            }
          }

          endpointDescription.security_mode() = endpoint.messageSecurityMode;

          for (auto& userTokenPolicy : endpoint.userIdentityTokens)
          {
            endpointDescription.user_identity_tokens().payload().push_back(userTokenPolicy);
          }

          endpointDescription.transport_profile_uri() =
            utils::get_transport_profile_uri(endpoint.transportProfile);

          endpointDescription.security_level() =
            compute_security_level(endpoint.messageSecurityMode, endpoint.securityPolicyId);

          results.push_back(std::move(endpointDescription));
        }
      }
    }

    std::sort(results.begin(),
      results.end(),
      [](const EndpointDescription& a, const EndpointDescription& b)
      { return a.security_level() > b.security_level(); });

    return results;
  };

  auto results = build(filterEnabled);

  // Part 4 5.4.4: endpointUrl is only a routing hint. An unmatched hint falls back to the
  // full default set rather than returning nothing.
  if (results.empty() && filterEnabled)
  {
    results = build(false);
  }

  return EndpointDescriptionListResult{std::move(results)};
}

}  // namespace

void Discovery::get_endpoints_async(std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies,
  GetEndpointsCompleteCallback callback) const
{
  auto strand = boost::asio::make_strand(dependencies->executor());
  // Snapshot the logger by value before `dependencies` is moved into the closure below: a ua::Logger
  // survives the dependencies' destruction, and reading it after the move would be use-after-move.
  auto discoveryLogger = dependencies->logger().with_category("discovery");

  // post_owning: the strong self-capture keeps this Discovery alive across the post; the certificate-
  // store callback re-enters the strand and fires the user callback. Inside the strand-posted body all
  // callbacks capture weak_from_this() so an outer release of the Discovery shared_ptr terminates work
  // cleanly.
  ua::async::post_owning(this,
    strand,
    discoveryLogger,
    [strand,
      endpointUrl = std::move(endpointUrl),
      dependencies = std::move(dependencies),
      callback = std::move(callback)](const Discovery& self) mutable
    {
      auto certificateStore = dependencies->default_application_group_certificate_store();
      if (!certificateStore)
      {
        callback(EndpointDescriptionListResult{Status::BadInternalError,
          make_error_detail("MissingCertificateStore",
            "DiscoveryDependencies::default_application_group_certificate_store() returned null",
            "Discovery")});
        return;
      }

      auto weakSelf = self.weak_from_this();
      certificateStore->get_application_certificates_async(

        [weakSelf,
          strand,
          endpointUrl = std::move(endpointUrl),
          dependencies = std::move(dependencies),
          callback = std::move(callback)](
          CertificateStore::ApplicationCertificateListResult certResult) mutable
        {
          auto innerSelf = weakSelf.lock();
          if (!innerSelf)
            return;
          // Snapshot the logger before `dependencies` is moved into the inner closure (use-after-move);
          // this inner post carries no self, so guarded (not a post helper) is the right tool.
          auto innerLogger = dependencies->logger().with_category("discovery");
          boost::asio::post(strand,
            ua::async::guarded(innerLogger,
              [endpointUrl = std::move(endpointUrl),
                dependencies = std::move(dependencies),
                callback = std::move(callback),
                certResult = std::move(certResult)]() mutable
              {
                if (!certResult.is_good())
                {
                  // A Bad answer is forwarded with its shared_detail() - pinned by GE-D / GE-E
                  // content-fidelity. The endpoints are built only from a Good answer: an Uncertain one is
                  // refused, so no Uncertain code reaches a GetEndpoints, FindServers or CreateSession fault.
                  callback(EndpointDescriptionListResult{ua::security_internal::not_good_store_answer(
                    certResult.status_code(), Status::BadInternalError, "Discovery")});
                  return;
                }
                auto certificates = std::move(certResult).value();
                try
                {
                  callback(build_endpoint_descriptions(endpointUrl, certificates, *dependencies));
                }
                catch (...)
                {
                  callback(::ua::exception_to_status_code(std::current_exception()));
                }
              }));
        });
    })();
}

EndpointDescriptionListResult Discovery::try_get_endpoints_sync(
  std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies) const noexcept
{
  try
  {
    // The operation runs on a strand of the dependencies' executor.
    const auto executor = dependencies ? dependencies->executor() : boost::asio::any_io_executor{};
    return ::ua::async::detail::blocking_call<EndpointDescriptionListResult>(executor,
      [&](std::function<void(EndpointDescriptionListResult)> complete)
      { get_endpoints_async(std::move(endpointUrl), std::move(dependencies), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

EndpointDescriptionList Discovery::get_endpoints_sync(
  std::string endpointUrl, shared_ptr<DiscoveryDependencies> dependencies) const
{
  return ::ua::detail::good_value(try_get_endpoints_sync(std::move(endpointUrl), std::move(dependencies)));
}

}  // namespace ua::server
