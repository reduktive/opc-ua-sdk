// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PUSH_MANAGEMENT_WIRING_H
#define UA_PUSH_MANAGEMENT_WIRING_H

#include "ua_address_space.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_sinks.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_method_response_correlation.h"
#include "ua_certificate_push_service.h"
#include "ua_trust_list_manager.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua
{

namespace server
{
class ServerObserver;
}

/// Parameters for wiring push certificate management into the server address space.
struct PushManagementWiringParams
{
  AddressSpace addressSpace;
  std::shared_ptr<CertificateStore> certificateStore;
  // Store behind the DefaultUserTokenGroup (Part 12 7.8.3.3). Null when the deployment configured
  // no user-token trust list, in which case that group's Methods are left unwired.
  std::shared_ptr<CertificateStore> userTokenCertificateStore;
  std::shared_ptr<const Crypto> crypto;
  boost::asio::any_io_executor executor;
  Logger logger;

  // Server identity for CSR generation
  std::string applicationUri;
  std::vector<std::string> hostnames;

  // Channel close trigger (immediate non-origin; exact origin deferred to its response boundary).
  std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
    closeAllChannels;

  // Certificate re-evaluation trigger (Part 12 7.8.2.3, 7.10.6): called after ApplyChanges wrote a
  // changed TrustList; every open SecureChannel and Session re-checks its Certificates and closes itself
  // when one is no longer valid.
  std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
    reevaluateCertificates;

  // Shutdown trigger (called by ResetToServerDefaults - Part 12 7.10.10). The
  // supplied hook transitions the server to SHUTDOWN with a credential-warning
  // ShutdownReason and a grace period. Optional: a null hook disables the
  // ResetToServerDefaults shutdown side-effect (the Method still clears state).
  std::function<void()> requestShutdown;

  // Audit events (optional - empty if auditing is disabled).
  // Held as weak_ptr so the wired handlers gracefully no-op if the bus
  // outlives the server (member-destruction-order safety).
  std::weak_ptr<EventSink> eventSink;
  std::string serverId;

  // Configuration
  uint32_t maxTrustListSize{65535};
  std::chrono::milliseconds activityTimeout{60000};

  // Whether a Session still exists (see CertificatePushService::Dependencies::sessionExists).
  // Optional: a null hook treats every Session as existing.
  std::function<bool(const NodeId&)> sessionExists;

  // See CertificatePushService::Dependencies::servedEndpointPolicies.
  std::function<std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>()>
    servedEndpointPolicies;
};

/// Result of wiring push certificate management - holds the created components and observer.
struct PushManagementComponents
{
  std::shared_ptr<TrustListManager> trustList;
  // Null when no user-token certificate store was supplied.
  std::shared_ptr<TrustListManager> userTokenTrustList;
  std::shared_ptr<CertificatePushService> certificatePushService;
  std::shared_ptr<server::ServerObserver> observer;
};

/// Wire push certificate management into the server address space.
///
/// Creates TrustListManager and CertificatePushService components, registers method handlers
/// on all well-known ServerConfiguration and TrustListManager NodeIds, initializes properties,
/// and returns the observer to register via add_internal_observer.
PushManagementComponents wire_push_management(PushManagementWiringParams params);

}  // namespace ua

#endif  // UA_PUSH_MANAGEMENT_WIRING_H
