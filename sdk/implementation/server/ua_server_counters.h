// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-side diagnostic counter aggregates feeding the OPC UA diagnostics nodes.
/// @ingroup server

#ifndef UA_SERVER_COUNTERS_H
#define UA_SERVER_COUNTERS_H

#include <atomic>
#include <cstdint>

namespace ua::server
{

/// Per-service request counter pair holding a total and an error subtotal.
///
/// Both fields are lock-free atomics updated from any thread on the request
/// path; `error_count` counts the subset of `total_count` that completed with a
/// bad status, so `error_count <= total_count` holds eventually but not
/// necessarily at any single observation. Counts are approximate by design (see
/// @ref ServerSummaryCounters for the ordering rationale).
/// @ingroup server
struct ServiceCounter
{
  std::atomic<uint32_t> totalCount{0};  ///< Total requests of this service counted so far.
  std::atomic<uint32_t> errorCount{0};  ///< Subset of `total_count` that completed with an error.
};

/// Server-wide diagnostic summary counters mirroring the OPC UA summary node.
///
/// Maps 1:1 to `ServerDiagnosticsSummaryDataType` (one atomic per field). Every
/// field uses relaxed memory ordering, so reads of distinct fields are not
/// mutually consistent and totals are approximate by design - they are intended
/// for diagnostics, not for exact accounting or synchronisation. Gauge fields
/// rise and fall with live resources; the remaining fields are monotonic and
/// increment only (until @ref reset). All fields are updated from any thread.
/// @ingroup server
struct ServerSummaryCounters
{
  // Gauges (increment/decrement)
  std::atomic<uint32_t> currentSessionCount{0};  ///< Sessions currently open.
  std::atomic<uint32_t> currentSubscriptionCount{0};  ///< Subscriptions currently active.
  /// Views currently present in the server. INERT-BY-DESIGN and always 0 in the current
  /// architecture: this is a gauge over address-space content, but there is no node-lifecycle hook to
  /// maintain it on View add/remove, and health_snapshot() is synchronous so it cannot enumerate the
  /// (strand-serialized) address space at read time. Driving it correctly needs one of those - a
  /// View-node lifecycle hook or an async snapshot that counts NodeClass::View nodes - not just a
  /// counter write. Tracked as a known limitation.
  std::atomic<uint32_t> serverViewCount{0};
  std::atomic<uint32_t> publishingIntervalCount{0};  ///< Distinct publishing intervals in use.

  // Monitored item gauge (server-wide total across all subscriptions)
  /// Monitored items currently active, summed across all subscriptions.
  std::atomic<uint32_t> currentMonitoredItemCount{0};

  // Monotonic counters (increment only)
  std::atomic<uint32_t> cumulatedSessionCount{0};  ///< Sessions opened since startup (cumulative).
  /// Sessions rejected for a security reason since startup.
  std::atomic<uint32_t> securityRejectedSessionCount{0};
  std::atomic<uint32_t> rejectedSessionCount{0};  ///< Sessions rejected for any reason since startup.
  std::atomic<uint32_t> sessionTimeoutCount{0};  ///< Sessions closed by timeout since startup.
  /// Sessions aborted abnormally since startup. INERT-BY-DESIGN and always 0: this server has no
  /// session-abort path - a session either closes cleanly (CloseSession) or times out (BadTimeout),
  /// and a lost channel/connection leaves the session to time out rather than aborting it. 0 is
  /// spec-conformant (OPC 10000-5 counts are approximate). If an abort path is ever added, wire this
  /// at the ServerImpl session-close site alongside sessionTimeoutCount.
  std::atomic<uint32_t> sessionAbortCount{0};
  /// Subscriptions created since startup (cumulative).
  std::atomic<uint32_t> cumulatedSubscriptionCount{0};
  /// Requests rejected for a security reason since startup. INERT-BY-DESIGN and always 0: security
  /// enforcement here is either per-item (AccessRestrictions -> per-operation Bad_SecurityModeInsufficient,
  /// which does not reject the request) or at session/channel establishment (counted by
  /// securityRejectedSessionCount and SecureChannelCounters::rejectedCount), so no whole-request
  /// security service-fault exists to count. Request-level, like unauthorizedRequestCount. 0 is
  /// spec-conformant.
  std::atomic<uint32_t> securityRejectedRequestsCount{0};
  std::atomic<uint32_t> rejectedRequestsCount{0};  ///< Requests rejected for any reason since startup.

  /// Resets collection using relaxed stores when diagnostics are enabled (OPC 10000-5 section 6.3.3).
  /// Cumulative Session and Subscription counts restart from their live gauges so they still include
  /// current resources (section 12.9); the other monotonic counters restart from zero. Gauges are
  /// preserved because they count live resources and must still support their later removal.
  ///
  /// Not atomic across fields: a concurrent reader may observe a partially reset
  /// snapshot.
  void reset()
  {
    cumulatedSessionCount.store(
      currentSessionCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    securityRejectedSessionCount.store(0, std::memory_order_relaxed);
    rejectedSessionCount.store(0, std::memory_order_relaxed);
    sessionTimeoutCount.store(0, std::memory_order_relaxed);
    sessionAbortCount.store(0, std::memory_order_relaxed);
    cumulatedSubscriptionCount.store(
      currentSubscriptionCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    securityRejectedRequestsCount.store(0, std::memory_order_relaxed);
    rejectedRequestsCount.store(0, std::memory_order_relaxed);
  }
};

/// Secure channel counters aggregated across the whole server.
///
/// Relaxed atomics updated from any thread; counts are approximate by design.
/// @ingroup server
struct SecureChannelCounters
{
  std::atomic<uint32_t> currentCount{0};  ///< Secure channels currently open (gauge).
  std::atomic<uint32_t> cumulatedCount{0};  ///< Secure channels opened since startup (cumulative).
  std::atomic<uint32_t> rejectedCount{0};  ///< Secure channel opens rejected since startup.

  /// Resets the cumulative and rejected counts using relaxed stores; the currentCount gauge counts live
  /// resources and is left alone (see ServerSummaryCounters::reset).
  ///
  /// Not atomic across fields.
  void reset()
  {
    cumulatedCount.store(0, std::memory_order_relaxed);
    rejectedCount.store(0, std::memory_order_relaxed);
  }
};

/// TCP connection counters aggregated across the whole server.
///
/// Relaxed atomics updated from any thread; counts are approximate by design.
/// @ingroup server
struct ConnectionCounters
{
  std::atomic<uint32_t> currentCount{0};  ///< TCP connections currently open (gauge).
  std::atomic<uint32_t> cumulatedCount{0};  ///< TCP connections accepted since startup (cumulative).
  std::atomic<uint32_t> rejectedCount{0};  ///< TCP connections rejected since startup.

  /// Resets the cumulative and rejected counts using relaxed stores; the currentCount gauge counts live
  /// resources and is left alone (see ServerSummaryCounters::reset).
  ///
  /// Not atomic across fields.
  void reset()
  {
    cumulatedCount.store(0, std::memory_order_relaxed);
    rejectedCount.store(0, std::memory_order_relaxed);
  }
};

/// Per-session diagnostic counters mirroring the OPC UA session diagnostics node.
///
/// Holds an aggregate request counter plus one @ref ServiceCounter per service,
/// matching the per-service fields of `SessionDiagnosticsDataType`. All fields
/// are relaxed atomics updated from any thread; counts are approximate by
/// design. One instance exists per live session.
/// @ingroup server
struct SessionCounters
{
  ServiceCounter totalRequests;  ///< Aggregate total/error counts across all services on this session.
  /// Requests on this session rejected because the user was not authorized. INERT-BY-DESIGN and always
  /// 0: this server authorizes PER-ITEM (a denied operation returns Bad_UserAccessDenied in its result
  /// slot while the Service serviceResult stays Good), so no whole Service *request* is rejected for
  /// authorization. UnauthorizedRequestCount is request-level (OPC 10000-5 12.11), so a per-item denial
  /// does not increment it and 0 is spec-conformant. If a whole-request authorization-rejection path is
  /// ever added, wire it there.
  std::atomic<uint32_t> unauthorizedRequestCount{0};

  // Per-service (matching OPC UA spec SessionDiagnosticsDataType)
  ServiceCounter read;  ///< Read service requests on this session.
  ServiceCounter historyRead;  ///< HistoryRead service requests on this session.
  ServiceCounter write;  ///< Write service requests on this session.
  ServiceCounter historyUpdate;  ///< HistoryUpdate service requests on this session.
  ServiceCounter call;  ///< Call service requests on this session.
  ServiceCounter createMonitoredItems;  ///< CreateMonitoredItems requests on this session.
  ServiceCounter modifyMonitoredItems;  ///< ModifyMonitoredItems requests on this session.
  ServiceCounter setMonitoringMode;  ///< SetMonitoringMode requests on this session.
  ServiceCounter setTriggering;  ///< SetTriggering requests on this session.
  ServiceCounter deleteMonitoredItems;  ///< DeleteMonitoredItems requests on this session.
  ServiceCounter createSubscription;  ///< CreateSubscription requests on this session.
  ServiceCounter modifySubscription;  ///< ModifySubscription requests on this session.
  ServiceCounter setPublishingMode;  ///< SetPublishingMode requests on this session.
  ServiceCounter publish;  ///< Publish service requests on this session.
  ServiceCounter republish;  ///< Republish service requests on this session.
  ServiceCounter transferSubscriptions;  ///< TransferSubscriptions requests on this session.
  ServiceCounter deleteSubscriptions;  ///< DeleteSubscriptions requests on this session.
  ServiceCounter addNodes;  ///< AddNodes service requests on this session.
  ServiceCounter addReferences;  ///< AddReferences service requests on this session.
  ServiceCounter deleteNodes;  ///< DeleteNodes service requests on this session.
  ServiceCounter deleteReferences;  ///< DeleteReferences service requests on this session.
  ServiceCounter browse;  ///< Browse service requests on this session.
  ServiceCounter browseNext;  ///< BrowseNext service requests on this session.
  ServiceCounter translateBrowsePaths;  ///< TranslateBrowsePathsToNodeIds requests on this session.
  ServiceCounter queryFirst;  ///< QueryFirst service requests on this session.
  ServiceCounter queryNext;  ///< QueryNext service requests on this session.
  ServiceCounter registerNodes;  ///< RegisterNodes service requests on this session.
  ServiceCounter unregisterNodes;  ///< UnregisterNodes service requests on this session.

  /// Resets the aggregate and every per-service counter to zero using relaxed stores.
  ///
  /// Not atomic across fields: a concurrent reader may observe a partially reset
  /// snapshot. Call only when no counter updates are in flight.
  void reset()
  {
    totalRequests.totalCount.store(0, std::memory_order_relaxed);
    totalRequests.errorCount.store(0, std::memory_order_relaxed);
    unauthorizedRequestCount.store(0, std::memory_order_relaxed);

    auto resetSc = [](ServiceCounter& sc)
    {
      sc.totalCount.store(0, std::memory_order_relaxed);
      sc.errorCount.store(0, std::memory_order_relaxed);
    };

    resetSc(read);
    resetSc(historyRead);
    resetSc(write);
    resetSc(historyUpdate);
    resetSc(call);
    resetSc(createMonitoredItems);
    resetSc(modifyMonitoredItems);
    resetSc(setMonitoringMode);
    resetSc(setTriggering);
    resetSc(deleteMonitoredItems);
    resetSc(createSubscription);
    resetSc(modifySubscription);
    resetSc(setPublishingMode);
    resetSc(publish);
    resetSc(republish);
    resetSc(transferSubscriptions);
    resetSc(deleteSubscriptions);
    resetSc(addNodes);
    resetSc(addReferences);
    resetSc(deleteNodes);
    resetSc(deleteReferences);
    resetSc(browse);
    resetSc(browseNext);
    resetSc(translateBrowsePaths);
    resetSc(queryFirst);
    resetSc(queryNext);
    resetSc(registerNodes);
    resetSc(unregisterNodes);
  }
};

}  // namespace ua::server

#endif  // UA_SERVER_COUNTERS_H
