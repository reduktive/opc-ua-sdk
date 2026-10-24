// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-1 concrete redundancy host shim
// ua::client::detail::RedundancyManagerConnectionHost (client design section 8.11, Slice W4/10e-wire). The
// shim IMPLEMENTS the narrow RedundancyManagerHost interface by weak-referencing a real ConnectionImpl: it serves
// the synchronous identity reads off ConnectionImpl's lock-free cross-strand snapshots, forwards each service
// primitive onto the orchestrator's strand (a gone Connection is completed with a source-tagged boundary
// failure, never a silent no-op), routes observer fan-out through the per-Connection ObserverSink, and owns
// the atomic RedundancyInfo backing store.
//
// The shim is driven through a REAL ConnectionImpl built with the injecting create_with_ops factory over the
// shared FakeSessionOps / FakeReopen tier-0 interface (testable_interfaces.md). Delivery is driven on a plain
// io_context so the test controls exactly when the executor / strand runs (pump()); there are NO real timers.
//
// Falsifiability: every test asserts a specific observable - the mapped DataValue vector, the exact source
// tag on a manufactured boundary failure, the captured discovery URL handed to the provider, the reused
// Subscription id (createSubscription issued exactly once), the observer counter transitioning 0->1 across
// the executor pump, or the atomically-stored snapshot pointer - so a shim that dropped, mis-routed, or
// double-issued a call fails a concrete assertion, not merely "did not crash".

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen (../../connection, via CMake)

#include "ua_application_description.h"
#include "ua_client_monitored_item.h"
#include "ua_client_observers.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_value.h"
#include "ua_discovery.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reconnect_policy.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_connection_host.h"
#include "ua_redundancy_manager_impl.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::ConnectionObserver;
using ua::client::ReconnectCause;
using ua::client::ReconnectOutcome;
using ua::client::RedundancyDegradeReason;
using ua::client::RedundancyManagerState;
using ua::client::RedundancyObserver;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::RedundancyDiscoveryProvider;
using ua::client::detail::RedundancyManagerConnectionHost;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

/// A near-zero backoff so any incidental FSM timer fires promptly (these tests drive primitives directly).
ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// --- Minimal observer fakes: capture the method that fired + its args (for the fan-out routing tests). ---

class FakeRedundancyObserver : public RedundancyObserver
{
public:
  int degraded = 0;
  std::string degradedUri;
  RedundancyDegradeReason degradedReason{};
  int failoverStarted = 0;
  std::string failoverFrom;
  std::string failoverTo;
  int recovered = 0;
  std::string recoveredUri;

  void on_redundancy_degraded(
    const Connection&, std::string activeUri, RedundancyDegradeReason reason) override
  {
    ++degraded;
    degradedUri = std::move(activeUri);
    degradedReason = reason;
  }

  void on_redundancy_failover_started(
    const Connection&, std::string fromUri, std::string toUri, ReconnectCause) override
  {
    ++failoverStarted;
    failoverFrom = std::move(fromUri);
    failoverTo = std::move(toUri);
  }

  void on_redundancy_failover_completed(const Connection&, std::string, ReconnectOutcome) override
  {}

  void on_redundancy_recovered(const Connection&, std::string activeUri) override
  {
    ++recovered;
    recoveredUri = std::move(activeUri);
  }
};

class FakeConnectionObserver : public ConnectionObserver
{
public:
  int advisory = 0;
  std::shared_ptr<const ua::ErrorDetail> advisoryDetail;

  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    ++advisory;
    advisoryDetail = std::move(detail);
  }
};

/// Builds an EndpointDescription carrying an application URI, endpoint URL, and (optionally) a discovery URL,
/// so a test can pin the identity + FindServers URL the shim serves off the cross-strand snapshot.
ua::EndpointDescription make_endpoint(
  const std::string& applicationUri, const std::string& endpointUrl, const std::string& discoveryUrl = {})
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = ua::String{endpointUrl};
  endpoint.server().application_uri() = ua::String{applicationUri};
  if (!discoveryUrl.empty())
  {
    endpoint.server().discovery_urls().push_back(ua::String{discoveryUrl});
  }
  return endpoint;
}

/// A live-io_context fixture that builds a REAL, reconnect-wired ConnectionImpl over the fake tier-0 interface and
/// hands back its eagerly-constructed redundancy host shim. Delivery is driven by pump().
class RedundancyConnectionHostTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  void SetUp() override
  {
    // Park the Publish pump so a subscription-driven test's run() returns (an inline-completing Publish would
    // re-post another Publish forever under a single-threaded io_context).
    mSession->publish.set_hold(true);
  }

  /// Runs all ready executor + strand work, then restarts so the context can be pumped again.
  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  /// Builds a reconnect-wired ConnectionImpl (keep-alive DISABLED so pump()'s run() returns) with @p config
  /// and @p provider, and (optionally) @p clientDefaults resolved into the observer sink.
  std::shared_ptr<ConnectionImpl> make_connection(
    ConnectionConfig config = {}, RedundancyDiscoveryProvider provider = {})
  {
    return TA::create_with_ops(mCtx.get_executor(),
      mSession,
      std::move(config),
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      KeepAlivePolicy{std::chrono::milliseconds{0}},
      /*clientObserverDefaults=*/{},
      /*enableRedundancy=*/true,
      /*redundancyPolicy=*/{},
      std::move(provider));
  }

  /// Drives the bootstrap to Active (so the wire-op dispatch gate lets Reads / Subscriptions through) and
  /// pumps the delivery so Active is reached on return.
  void drive_to_active(ConnectionImpl& connection)
  {
    connection.start_async([](VoidResult) {});
    pump();
  }
};

// ============================================================================
// Identity - synchronous cross-strand snapshot reads (section 8.2A.7)
// ============================================================================

// The shim serves current_application_uri / current_endpoint / connection_id off ConnectionImpl's lock-free
// cross-strand snapshots (the endpoint snapshot the test seeds + the session-id ConnectionInfo), never a
// strand-owned read.
TEST_F(RedundancyConnectionHostTest, IdentityReadsFromCrossStrandSnapshot)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  TA::set_endpoint_snapshot(
    *connection, make_endpoint("urn:server:a", "opc.tcp://a:4840", "opc.tcp://a/disc"));

  EXPECT_EQ(host->current_application_uri(), "urn:server:a");
  EXPECT_EQ(static_cast<std::string>(host->current_endpoint().endpoint_url()), "opc.tcp://a:4840");
  EXPECT_EQ(host->connection_id(), connection->info()->sessionId)
    << "connection_id is the orchestrator's ConnectionInfo sessionId snapshot";
}

// When the weak ConnectionImpl is gone every identity read must degrade to a default (empty NodeId / endpoint
// / uri) rather than dereference the expired weak pointer.
TEST_F(RedundancyConnectionHostTest, IdentityBailsWhenConnectionGone)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  TA::set_endpoint_snapshot(*connection, make_endpoint("urn:server:a", "opc.tcp://a:4840"));

  connection.reset();  // the host holds ConnectionImpl WEAK - the lock now fails.

  EXPECT_EQ(host->connection_id(), ua::NodeId{});
  EXPECT_EQ(host->current_application_uri(), std::string{});
  EXPECT_EQ(static_cast<std::string>(host->current_endpoint().endpoint_url()), std::string{})
    << "a gone Connection yields a default-constructed EndpointDescription, not a crash";
}

// ============================================================================
// read_attributes_async - forwards to the tier-1 wire Read, maps results
// ============================================================================

// A read forwards through ConnectionImpl::read_async (the dispatch gate) to the tier-0 session, and the
// ReadResponse.results() are mapped 1:1 into the vector<DataValue> the manager consumes.
TEST_F(RedundancyConnectionHostTest, ReadAttributesForwardsToWireRead)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  drive_to_active(*connection);

  // Park the redundancy Read so we deliver a scripted response deterministically.
  mSession->read.set_hold(true);

  std::vector<ua::ReadValueId> reads;
  ua::ReadValueId target;
  target.node_id() = ua::NodeId{1, 100};
  reads.push_back(std::move(target));

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  host->read_attributes_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  pump();
  ASSERT_EQ(mSession->read.pending_count(), 1u) << "the Read must reach the session (Active + gate)";

  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{7}}});
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{9}}});
  mSession->read.fire_next(ua::Result<ua::ReadResponse>{std::move(response)});
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 2u);
  EXPECT_EQ(captured->value()[0].value().to<std::int32_t>().value(), 7);
  EXPECT_EQ(captured->value()[1].value().to<std::int32_t>().value(), 9);
}

// A gone Connection is a source-tagged boundary failure completed on the executor (never a silent no-op).
TEST_F(RedundancyConnectionHostTest, ReadAttributesBoundaryFailureWhenConnectionGone)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  connection.reset();  // weak ConnectionImpl expires.

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  host->read_attributes_async(
    {}, [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  EXPECT_FALSE(captured.has_value()) << "the boundary failure is POSTED to the executor, not fired inline";
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.redundancy.read.connection_gone");
}

// ============================================================================
// find_servers_async - the RedundancyDiscoveryProvider interface (F2/J46)
// ============================================================================

// The provider is handed the discovery URL derived from the bound endpoint snapshot (advertised discovery
// URL preferred), and its scripted result is threaded back to the caller unchanged.
TEST_F(RedundancyConnectionHostTest, FindServersUsesProviderWithEndpointDiscoveryUrl)
{
  std::string capturedUrl;
  bool providerCalled = false;
  RedundancyDiscoveryProvider provider =
    [&](std::string discoveryUrl,
      ua::client::FindServersOptions,
      std::function<void(ua::Result<std::vector<ua::ApplicationDescription>>)>
        completion)
  {
    providerCalled = true;
    capturedUrl = std::move(discoveryUrl);
    ua::ApplicationDescription server;
    server.application_uri() = ua::String{"urn:server:b"};
    std::vector<ua::ApplicationDescription> servers;
    servers.push_back(std::move(server));
    completion(ua::Result<std::vector<ua::ApplicationDescription>>{std::move(servers)});
  };

  auto connection = make_connection({}, std::move(provider));
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  TA::set_endpoint_snapshot(
    *connection, make_endpoint("urn:server:a", "opc.tcp://a:4840", "opc.tcp://a/discovery"));

  std::optional<ua::Result<std::vector<ua::ApplicationDescription>>> captured;
  host->find_servers_async({},
    [&captured](ua::Result<std::vector<ua::ApplicationDescription>> result)
    { captured = std::move(result); });
  pump();

  EXPECT_TRUE(providerCalled);
  EXPECT_EQ(capturedUrl, "opc.tcp://a/discovery")
    << "the shim derives the discovery URL from the endpoint snapshot's advertised discovery URL";
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 1u);
  EXPECT_EQ(static_cast<std::string>(captured->value().front().application_uri()), "urn:server:b");
}

// With no provider wired (the current connect-path default) find_servers must complete a source-tagged
// Bad_NotImplemented on the executor - never a silent drop.
TEST_F(RedundancyConnectionHostTest, FindServersProviderAbsentIsSourceTaggedNotImplemented)
{
  auto connection = make_connection();  // default {} provider
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  std::optional<ua::Result<std::vector<ua::ApplicationDescription>>> captured;
  host->find_servers_async({},
    [&captured](ua::Result<std::vector<ua::ApplicationDescription>> result)
    { captured = std::move(result); });
  EXPECT_FALSE(captured.has_value()) << "the absent-provider failure is POSTED, not fired inline";
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadNotImplemented);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.redundancy.find_servers.provider_absent");
}

// ============================================================================
// Subscription / MonitoredItem primitives - the reused ServiceLevel Subscription
// ============================================================================

// The first monitor install creates the ONE reused redundancy Subscription and attaches the MI; a second
// install reuses the cached Subscription id (no second CreateSubscription) and attaches another MI.
TEST_F(RedundancyConnectionHostTest, MonitorAttributeCreatesReusedSubscriptionThenMI)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  drive_to_active(*connection);

  ua::CreateSubscriptionResponse createResponse;
  createResponse.subscription_id() = 4242;
  mSession->createSubscription.set_result(
    ua::Result<ua::CreateSubscriptionResponse>{std::move(createResponse)});

  ua::client::MonitorRequest request;
  request.nodeId = ua::NodeId{0, 2267};  // Server_ServiceLevel

  std::optional<ua::Result<ua::client::MonitoredItem>> first;
  host->monitor_attribute_async(
    request,
    [](ua::client::DataChangeEvent) {},
    [&first](ua::Result<ua::client::MonitoredItem> result) { first = std::move(result); });
  pump();
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(first->is_good());
  EXPECT_EQ(mSession->createSubscription.call_count(), 1u);
  EXPECT_EQ(mSession->createMonitoredItems.call_count(), 1u);

  std::optional<ua::Result<ua::client::MonitoredItem>> second;
  host->monitor_attribute_async(
    request,
    [](ua::client::DataChangeEvent) {},
    [&second](ua::Result<ua::client::MonitoredItem> result) { second = std::move(result); });
  pump();
  ASSERT_TRUE(second.has_value());
  ASSERT_TRUE(second->is_good());
  EXPECT_EQ(mSession->createSubscription.call_count(), 1u)
    << "the second install reuses the cached redundancy Subscription - no second CreateSubscription";
  EXPECT_EQ(mSession->createMonitoredItems.call_count(), 2u) << "but a second MonitoredItem is attached";
}

// Two concurrent generations both find the reused-Subscription cache empty and each issue a
// CreateSubscription (a discovery-restart race). Exactly one create wins and caches its id; the loser must
// DELETE the redundant Subscription it just created - otherwise it leaks server-side (a Subscription with no
// MonitoredItem attached, never cleaned up). The MI still attaches to the WINNER id in both completions.
TEST_F(RedundancyConnectionHostTest, MonitorRacedDoubleCreateDeletesLoserSubscription)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  drive_to_active(*connection);

  // Hold BOTH CreateSubscriptions so neither has cached the reused id when the other is issued - both
  // installs find the cache empty and both create (the raced double-create the fix guards against).
  mSession->createSubscription.set_hold(true);

  ua::client::MonitorRequest request;
  request.nodeId = ua::NodeId{0, 2267};  // Server_ServiceLevel

  std::optional<ua::Result<ua::client::MonitoredItem>> first;
  host->monitor_attribute_async(
    request,
    [](ua::client::DataChangeEvent) {},
    [&first](ua::Result<ua::client::MonitoredItem> result) { first = std::move(result); });
  std::optional<ua::Result<ua::client::MonitoredItem>> second;
  host->monitor_attribute_async(
    request,
    [](ua::client::DataChangeEvent) {},
    [&second](ua::Result<ua::client::MonitoredItem> result) { second = std::move(result); });
  pump();
  ASSERT_EQ(mSession->createSubscription.pending_count(), 2u)
    << "both installs found the reused-Subscription cache empty and issued a CreateSubscription";

  // create1 wins the race and caches id 100.
  ua::CreateSubscriptionResponse winner;
  winner.subscription_id() = 100;
  mSession->createSubscription.fire_next(ua::Result<ua::CreateSubscriptionResponse>{std::move(winner)});
  pump();

  // create2 loses: it must delete the subscription IT created (200), reusing 100 for the MI attach.
  ua::CreateSubscriptionResponse loser;
  loser.subscription_id() = 200;
  mSession->createSubscription.fire_next(ua::Result<ua::CreateSubscriptionResponse>{std::move(loser)});
  pump();

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(first->is_good());
  EXPECT_TRUE(second->is_good());

  ASSERT_EQ(mSession->deleteSubscriptions.call_count(), 1u)
    << "the loser create must delete the Subscription it abandoned - no server-side leak";
  const auto deletes = mSession->deleteSubscriptions.requests();
  ASSERT_EQ(deletes.size(), 1u);
  ASSERT_EQ(deletes[0].subscription_ids().size(), 1u);
  EXPECT_EQ(deletes[0].subscription_ids()[0], 200u)
    << "the LOSER Subscription (200) is deleted, never the winner (100) the MIs attach to";
}

// Cancelling a monitored item routes the delete through the item's own owner interface down to the tier-0
// DeleteMonitoredItems (the shim does not need a separate ConnectionImpl lock).
TEST_F(RedundancyConnectionHostTest, CancelMonitoredItemDeletesViaHandle)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);
  drive_to_active(*connection);

  ua::client::MonitorRequest request;
  request.nodeId = ua::NodeId{0, 2267};

  std::optional<ua::client::MonitoredItem> item;
  host->monitor_attribute_async(
    request,
    [](ua::client::DataChangeEvent) {},
    [&item](ua::Result<ua::client::MonitoredItem> result)
    {
      if (result.is_good())
      {
        item.emplace(std::move(result).value());
      }
    });
  pump();
  ASSERT_TRUE(item.has_value());

  // The self-acting delete issues a DeleteMonitoredItems whose per-item result the handle reads: script a
  // Good server response so the delete completes Good (an unscripted/empty response would surface Bad).
  ua::DeleteMonitoredItemsResponse deleteResponse;
  deleteResponse.results().push_back(ua::StatusCode{ua::Status::Good});
  mSession->deleteMonitoredItems.set_result(
    ua::Result<ua::DeleteMonitoredItemsResponse>{std::move(deleteResponse)});

  std::optional<VoidResult> cancelResult;
  host->cancel_monitored_item_async(
    std::move(*item), [&cancelResult](VoidResult result) { cancelResult = result; });
  pump();

  ASSERT_TRUE(cancelResult.has_value());
  EXPECT_TRUE(cancelResult->is_good());
  EXPECT_EQ(mSession->deleteMonitoredItems.call_count(), 1u)
    << "the item's self-acting delete must reach the tier-0 DeleteMonitoredItems";
}

// ============================================================================
// probe_backup_servicelevel_async - DEFER-STUB (J47, backup-probe channel is W9)
// ============================================================================

// The backup ServiceLevel probe is a source-tagged Bad_NotImplemented until W9 (so the manager's
// ScoringBackups path degrades explicitly rather than treating a backup as healthy).
TEST_F(RedundancyConnectionHostTest, ProbeIsDeferStubNotImplemented)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  std::optional<ua::Result<std::uint8_t>> captured;
  host->probe_backup_servicelevel_async(
    "opc.tcp://backup/disc", [&captured](ua::Result<std::uint8_t> result) { captured = std::move(result); });
  EXPECT_FALSE(captured.has_value()) << "the stub failure is POSTED to the executor, not fired inline";
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadNotImplemented);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.redundancy.probe.not_implemented");
}

// ============================================================================
// Observer fan-out - routed through the per-Connection ObserverSink (posted, off-strand)
// ============================================================================

// fire_observer_redundancy_degraded routes to the RedundancyObserver on the executor (posted, not inline).
TEST_F(RedundancyConnectionHostTest, FireObserverRedundancyDegradedRoutesToSink)
{
  auto fake = std::make_shared<FakeRedundancyObserver>();
  ConnectionConfig config;
  config.observers.redundancy = fake;
  auto connection = make_connection(std::move(config));
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  host->fire_observer_redundancy_degraded("urn:server:a", RedundancyDegradeReason::ServiceLevelBelowHealthy);
  EXPECT_EQ(fake->degraded, 0) << "observer delivery is posted to the executor, not fired inline";
  pump();

  ASSERT_EQ(fake->degraded, 1);
  EXPECT_EQ(fake->degradedUri, "urn:server:a");
  EXPECT_EQ(fake->degradedReason, RedundancyDegradeReason::ServiceLevelBelowHealthy);
}

// A second redundancy family (recovered) routes through the same sink with its argument intact.
TEST_F(RedundancyConnectionHostTest, FireObserverRedundancyRecoveredRoutesToSink)
{
  auto fake = std::make_shared<FakeRedundancyObserver>();
  ConnectionConfig config;
  config.observers.redundancy = fake;
  auto connection = make_connection(std::move(config));
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  host->fire_observer_redundancy_recovered("urn:server:b");
  EXPECT_EQ(fake->recovered, 0);
  pump();

  ASSERT_EQ(fake->recovered, 1);
  EXPECT_EQ(fake->recoveredUri, "urn:server:b");
}

// The advisory diagnostic routes to the ConnectionObserver (the advisory family), carrying the ErrorDetail
// intact across the async post.
TEST_F(RedundancyConnectionHostTest, FireObserverAdvisoryDiagnosticRoutesToConnectionSink)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_connection(std::move(config));
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  std::shared_ptr<const ua::ErrorDetail> detail =
    ua::ErrorDetail::build("BackupDegraded", "a backup probe degraded", "client.tier1.redundancy");
  host->fire_observer_advisory_diagnostic(detail);
  EXPECT_EQ(fake->advisory, 0);
  pump();

  ASSERT_EQ(fake->advisory, 1);
  EXPECT_EQ(fake->advisoryDetail.get(), detail.get()) << "the ErrorDetail must be propagated intact";
}

// ============================================================================
// publish_info_snapshot - the Rule-4 atomic backing store
// ============================================================================

// publish_info_snapshot stores the snapshot atomically; info_snapshot() reads back the exact same pointer.
TEST_F(RedundancyConnectionHostTest, PublishInfoSnapshotStoresAtomically)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  auto info = std::make_shared<ua::client::RedundancyInfo>();
  info->failoverCount = 7;
  info->state = RedundancyManagerState::Monitoring;
  std::shared_ptr<const ua::client::RedundancyInfo> published = info;

  host->publish_info_snapshot(published);
  const auto readBack = host->info_snapshot();

  EXPECT_EQ(readBack.get(), published.get()) << "info_snapshot returns the exact atomically-stored pointer";
  ASSERT_NE(readBack, nullptr);
  EXPECT_EQ(readBack->failoverCount, 7u);
  EXPECT_EQ(readBack->state, RedundancyManagerState::Monitoring);
}

}  // namespace
