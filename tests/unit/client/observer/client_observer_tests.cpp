// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-1 client observer fan-out infrastructure (client design section 7.8 / wiring
// section 1):
//   - resolve_observer_slots       (the per-Connection-overrides-Client-default resolution rule)
//   - ObserverSink                 (the per-Connection fan-out sink: one post_fire primitive; off-strand
//                                    delivery; null-slot no-op; Connection-gone drop; atomic slot replace;
//                                    close severs)
//   - ClientObserverSink           (the Client-scoped SecurityObserver sink: nullable const Connection*)
//   - ConnectionImpl integration   (ConnectionConfig slots resolved into the sink; per-Connection setters
//                                    re-resolve; Client-level default vs per-Connection override precedence)
//
// Falsifiability: every fire test asserts the CAPTURED method + args on a FakeObserver, not merely that
// nothing crashed. The off-strand test asserts the hook did NOT run before the executor was pumped; the
// gone-Connection test asserts the hook was DROPPED; the close/atomic-replace tests assert the delivered set.
//
// Delivery is driven on a plain io_context so the test controls exactly when the executor runs.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen (../connection, via CMake)

#include "stub_x509_certificate.h"  // ua::testing::make_stub_certificate

#include "ua_connection.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_client_observers.h"
#include "ua_error_detail.h"
#include "ua_observer_sink.h"
#include "ua_status.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace
{

using ua::StatusCode;
using ua::client::AddressSpaceObserver;
using ua::client::AlarmObserver;
using ua::client::ConnectionObserver;
using ua::client::DataIntegrityKind;
using ua::client::EventNotification;
using ua::client::ModelChangeStructure;
using ua::client::ProposedAdjustment;
using ua::client::PullCertLifecycleEvent;
using ua::client::ReconnectOutcome;
using ua::client::RedundancyDegradeReason;
using ua::client::RedundancyObserver;
using ua::client::SecurityObserver;
using ua::client::SemanticChangeStructure;
using ua::client::ServerStateObserver;
using ua::client::Session;
using ua::client::SubscriptionObserver;
using ua::client::SystemStatusOrigin;
using ua::client::TrackedKey;
using ua::client::TypeObserver;
using ua::client::detail::ClientObserverSink;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::ObserverSink;
using ua::client::detail::ObserverSlots;
using ua::client::detail::resolve_observer_slots;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// ---- Fake observers: capture the method that fired + its args. ----

class FakeConnectionObserver : public ConnectionObserver
{
public:
  int connecting = 0;
  int connected = 0;
  int closed = 0;
  int sessionActivated = 0;
  ConnectionState stateSeenOnConnected = ConnectionState::Closed;

  int disconnected = 0;
  std::optional<StatusCode> disconnectedReason;
  std::shared_ptr<const ua::ErrorDetail> disconnectedDetail;

  int reconnecting = 0;
  std::size_t reconnectingAttempt = 0;
  std::size_t reconnectingCauseIndex = 999;

  int reconnected = 0;
  ReconnectOutcome reconnectedOutcome;

  int sessionCreated = 0;
  ua::NodeId sessionCreatedId;

  int sessionRecreated = 0;
  ua::NodeId sessionRecreatedOld;
  ua::NodeId sessionRecreatedNew;

  int namespaceRemap = 0;
  std::size_t namespaceGeneration = 0;
  bool namespaceSizeChanged = false;
  bool namespaceIndexShifted = false;

  int errorChain = 0;
  StatusCode errorChainCode{ua::Status::Good};
  std::shared_ptr<const ua::ErrorDetail> errorChainDetail;
  std::string errorChainTag;

  int advisory = 0;
  std::shared_ptr<const ua::ErrorDetail> advisoryDetail;

  void on_connecting(const ua::client::Connection&) override
  {
    ++connecting;
  }

  void on_connected(const ua::client::Connection& conn) override
  {
    ++connected;
    stateSeenOnConnected = conn.state();
  }

  void on_disconnected(
    const ua::client::Connection&, StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    ++disconnected;
    disconnectedReason = reason;
    disconnectedDetail = std::move(detail);
  }

  void on_reconnecting(
    const ua::client::Connection&, std::size_t attempt, ua::client::ReconnectCause cause) override
  {
    ++reconnecting;
    reconnectingAttempt = attempt;
    reconnectingCauseIndex = cause.index();
  }

  void on_reconnected(const ua::client::Connection&, ReconnectOutcome outcome) override
  {
    ++reconnected;
    reconnectedOutcome = outcome;
  }

  void on_closed(const ua::client::Connection&) override
  {
    ++closed;
  }

  void on_session_created(const ua::client::Connection&, ua::NodeId sessionId) override
  {
    ++sessionCreated;
    sessionCreatedId = std::move(sessionId);
  }

  void on_session_activated(const ua::client::Connection&) override
  {
    ++sessionActivated;
  }

  void on_session_recreated(const ua::client::Connection&, ua::NodeId oldId, ua::NodeId newId) override
  {
    ++sessionRecreated;
    sessionRecreatedOld = std::move(oldId);
    sessionRecreatedNew = std::move(newId);
  }

  void on_namespace_remap(
    const ua::client::Connection&, std::size_t generation, bool sizeChanged, bool indexShifted) override
  {
    ++namespaceRemap;
    namespaceGeneration = generation;
    namespaceSizeChanged = sizeChanged;
    namespaceIndexShifted = indexShifted;
  }

  void on_error_chain(const ua::client::Connection&, StatusCode terminalCode,
    std::shared_ptr<const ua::ErrorDetail> chain, std::string_view operationTag) override
  {
    ++errorChain;
    errorChainCode = terminalCode;
    errorChainDetail = std::move(chain);
    errorChainTag = std::string{operationTag};
  }

  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    ++advisory;
    advisoryDetail = std::move(detail);
  }
};

class FakeSubscriptionObserver : public SubscriptionObserver
{
public:
  int transferred = 0;
  ua::IntegerId transferredId = 0;
  int recreated = 0;
  ua::IntegerId recreatedOld = 0;
  ua::IntegerId recreatedNew = 0;
  int publishGap = 0;
  ua::IntegerId gapSub = 0;
  std::uint32_t gapFrom = 0;
  std::uint32_t gapTo = 0;
  int recoveryAction = 0;
  ProposedAdjustment recoveryProposed;
  int terminated = 0;
  StatusCode terminatedReason{ua::Status::Good};

  void on_subscription_transferred(ua::IntegerId subscriptionId) override
  {
    ++transferred;
    transferredId = subscriptionId;
  }

  void on_subscription_recreated(ua::IntegerId oldId, ua::IntegerId newId) override
  {
    ++recreated;
    recreatedOld = oldId;
    recreatedNew = newId;
  }

  void on_publish_gap(ua::IntegerId subscriptionId, std::uint32_t lostFrom, std::uint32_t to) override
  {
    ++publishGap;
    gapSub = subscriptionId;
    gapFrom = lostFrom;
    gapTo = to;
  }

  void on_subscription_recovery_action(
    ua::IntegerId, StatusCode, std::shared_ptr<const ua::ErrorDetail>, ProposedAdjustment proposed) override
  {
    ++recoveryAction;
    recoveryProposed = proposed;
  }

  void on_subscription_terminated(
    ua::IntegerId, StatusCode reason, std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++terminated;
    terminatedReason = reason;
  }
};

class FakeTypeObserver : public TypeObserver
{
public:
  int registered = 0;
  ua::NodeId encodingId;
  std::string typeName;

  void on_type_registered(ua::NodeId id, std::string name) override
  {
    ++registered;
    encodingId = std::move(id);
    typeName = std::move(name);
  }
};

class FakeSecurityObserver : public SecurityObserver
{
public:
  int certRotated = 0;
  int pullCert = 0;
  bool pullCertConnWasNull = false;
  PullCertLifecycleEvent pullCertEvent{};

  void on_certificate_rotated(const ua::X509Certificate&) override
  {
    ++certRotated;
  }

  void on_pull_cert_management_lifecycle(const ua::client::Connection* conn, PullCertLifecycleEvent event,
    std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++pullCert;
    pullCertConnWasNull = (conn == nullptr);
    pullCertEvent = event;
  }
};

class FakeAddressSpaceObserver : public AddressSpaceObserver
{
public:
  int modelChange = 0;
  std::size_t modelCount = 0;
  ua::NodeId modelFirstAffected;
  int semanticChange = 0;
  std::size_t semanticCount = 0;

  void on_model_change(const ua::client::Connection&, std::vector<ModelChangeStructure> changes) override
  {
    ++modelChange;
    modelCount = changes.size();
    if (!changes.empty())
    {
      modelFirstAffected = changes.front().affected;
    }
  }

  void on_semantic_change(
    const ua::client::Connection&, std::vector<SemanticChangeStructure> changes) override
  {
    ++semanticChange;
    semanticCount = changes.size();
  }
};

class FakeServerStateObserver : public ServerStateObserver
{
public:
  int deviceFailure = 0;
  int progress = 0;
  int statusChange = 0;
  ua::ServerState statusState{ua::ServerState::Unknown};
  ua::NodeId statusSource;
  SystemStatusOrigin statusOrigin{SystemStatusOrigin::Server};

  void on_device_failure(const ua::client::Connection&, EventNotification) override
  {
    ++deviceFailure;
  }

  void on_progress_event(const ua::client::Connection&, EventNotification) override
  {
    ++progress;
  }

  void on_system_status_change(const ua::client::Connection&, ua::NodeId sourceNode, ua::String,
    ua::ServerState newState, SystemStatusOrigin origin) override
  {
    ++statusChange;
    statusState = newState;
    statusSource = std::move(sourceNode);
    statusOrigin = origin;
  }
};

class FakeAlarmObserver : public AlarmObserver
{
public:
  int refreshRequired = 0;
  std::size_t refreshCount = 0;
  int dataIntegrity = 0;
  DataIntegrityKind dataIntegrityKind{};
  int auditEvent = 0;
  int auditSecurity = 0;
  int auditChannel = 0;
  int auditSession = 0;
  int auditUpdate = 0;
  int auditUpdateMethod = 0;

  void on_refresh_required(const ua::client::Connection&, std::size_t conditionCount) override
  {
    ++refreshRequired;
    refreshCount = conditionCount;
  }

  void on_data_integrity_warning(const ua::client::Connection&, TrackedKey, DataIntegrityKind kind,
    std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++dataIntegrity;
    dataIntegrityKind = kind;
  }

  void on_audit_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditEvent;
  }

  void on_audit_security_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditSecurity;
  }

  void on_audit_channel_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditChannel;
  }

  void on_audit_session_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditSession;
  }

  void on_audit_update_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditUpdate;
  }

  void on_audit_update_method_event(const ua::client::Connection&, EventNotification) override
  {
    ++auditUpdateMethod;
  }
};

class FakeRedundancyObserver : public RedundancyObserver
{
public:
  int degraded = 0;
  std::string degradedUri;
  RedundancyDegradeReason degradedReason{};
  int failoverStarted = 0;
  std::string failoverFrom;
  std::string failoverTo;
  int failoverCompleted = 0;
  std::string failoverNowActive;
  int recovered = 0;
  std::string recoveredUri;

  void on_redundancy_degraded(
    const ua::client::Connection&, std::string activeUri, RedundancyDegradeReason reason) override
  {
    ++degraded;
    degradedUri = std::move(activeUri);
    degradedReason = reason;
  }

  void on_redundancy_failover_started(const ua::client::Connection&, std::string fromUri, std::string toUri,
    ua::client::ReconnectCause) override
  {
    ++failoverStarted;
    failoverFrom = std::move(fromUri);
    failoverTo = std::move(toUri);
  }

  void on_redundancy_failover_completed(
    const ua::client::Connection&, std::string nowActiveUri, ReconnectOutcome) override
  {
    ++failoverCompleted;
    failoverNowActive = std::move(nowActiveUri);
  }

  void on_redundancy_recovered(const ua::client::Connection&, std::string activeUri) override
  {
    ++recovered;
    recoveredUri = std::move(activeUri);
  }
};

// ===================== resolve_observer_slots (pure) =====================

TEST(ClientObserverResolve, PerConnectionSlotOverridesClientDefault)
{
  auto clientConn = std::make_shared<FakeConnectionObserver>();
  auto perConn = std::make_shared<FakeConnectionObserver>();

  ObserverSlots clientDefaults;
  clientDefaults.connection = clientConn;
  ObserverSlots perConnection;
  perConnection.connection = perConn;

  const ObserverSlots resolved = resolve_observer_slots(perConnection, clientDefaults);
  EXPECT_EQ(resolved.connection.get(), perConn.get())
    << "a non-null per-Connection slot must override the Client-level default";
}

TEST(ClientObserverResolve, NullPerConnectionSlotFallsBackToClientDefault)
{
  auto clientConn = std::make_shared<FakeConnectionObserver>();
  auto clientAlarm = std::make_shared<FakeAlarmObserver>();

  ObserverSlots clientDefaults;
  clientDefaults.connection = clientConn;
  clientDefaults.alarm = clientAlarm;
  ObserverSlots perConnection;  // all null

  const ObserverSlots resolved = resolve_observer_slots(perConnection, clientDefaults);
  EXPECT_EQ(resolved.connection.get(), clientConn.get()) << "null per-Connection slot => Client default";
  EXPECT_EQ(resolved.alarm.get(), clientAlarm.get());
}

TEST(ClientObserverResolve, ResolvesEachFamilyIndependently)
{
  auto perConn = std::make_shared<FakeConnectionObserver>();
  auto clientSub = std::make_shared<FakeSubscriptionObserver>();

  ObserverSlots clientDefaults;
  clientDefaults.subscription = clientSub;
  ObserverSlots perConnection;
  perConnection.connection = perConn;

  const ObserverSlots resolved = resolve_observer_slots(perConnection, clientDefaults);
  EXPECT_EQ(resolved.connection.get(), perConn.get()) << "per-Connection connection slot wins";
  EXPECT_EQ(resolved.subscription.get(), clientSub.get()) << "Client-default subscription slot fills the gap";
  EXPECT_EQ(resolved.type, nullptr) << "an unregistered family stays null";
}

// ===================== ObserverSink =====================

class ClientObserverSinkTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;
  std::shared_ptr<ObserverSink> mSink;

  void SetUp() override
  {
    mConnection = TA::create_with_ops(mCtx.get_executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    mSink = ObserverSink::create(mCtx.get_executor(), mConnection);
  }

  // Runs all ready executor work, then restarts so the context can be pumped again.
  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  ObserverSlots slots_with(std::shared_ptr<ConnectionObserver> connectionObserver)
  {
    ObserverSlots slots;
    slots.connection = std::move(connectionObserver);
    return slots;
  }
};

// --- ConnectionObserver: each fire_* invokes the right method with the right args. ---

TEST_F(ClientObserverSinkTest, FireConnectedInvokesObserverWithLiveBorrowedConnection)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));

  mSink->fire_connected();
  EXPECT_EQ(fake->connected, 0) << "delivery must be posted to the executor, not fired inline (off-strand)";

  pump();
  EXPECT_EQ(fake->connected, 1);
  EXPECT_EQ(fake->stateSeenOnConnected, ConnectionState::Connecting)
    << "the borrowed const Connection& is a real, usable handle over the live ConnectionImpl";
}

TEST_F(ClientObserverSinkTest, FireConnectingInvokesObserver)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_connecting();
  pump();
  EXPECT_EQ(fake->connecting, 1);
}

TEST_F(ClientObserverSinkTest, FireClosedInvokesObserver)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_closed();
  pump();
  EXPECT_EQ(fake->closed, 1);
}

TEST_F(ClientObserverSinkTest, FireDisconnectedCarriesReasonAndDetail)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("Drop", "transport dropped", "client.tier1.connection");
  mSink->fire_disconnected(StatusCode{ua::Status::BadConnectionClosed}, detail);
  pump();
  ASSERT_EQ(fake->disconnected, 1);
  ASSERT_TRUE(fake->disconnectedReason.has_value());
  EXPECT_EQ(fake->disconnectedReason->value(), StatusCode{ua::Status::BadConnectionClosed}.value());
  EXPECT_EQ(fake->disconnectedDetail.get(), detail.get()) << "the ErrorDetail must be propagated intact";
}

TEST_F(ClientObserverSinkTest, FireReconnectingCarriesAttemptAndCause)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_reconnecting(3, ua::client::ReconnectCause{ua::client::KeepAliveMissed{}});
  pump();
  ASSERT_EQ(fake->reconnecting, 1);
  EXPECT_EQ(fake->reconnectingAttempt, 3u);
  EXPECT_EQ(fake->reconnectingCauseIndex, ua::client::ReconnectCause{ua::client::KeepAliveMissed{}}.index());
}

TEST_F(ClientObserverSinkTest, FireReconnectedCarriesOutcome)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  ReconnectOutcome outcome;
  outcome.sessionPreserved = true;
  outcome.subscriptionsTransferred = true;
  outcome.monitoredItemsRecreated = 5;
  mSink->fire_reconnected(outcome);
  pump();
  ASSERT_EQ(fake->reconnected, 1);
  EXPECT_TRUE(fake->reconnectedOutcome.sessionPreserved);
  EXPECT_TRUE(fake->reconnectedOutcome.subscriptionsTransferred);
  EXPECT_EQ(fake->reconnectedOutcome.monitoredItemsRecreated, 5u);
}

TEST_F(ClientObserverSinkTest, FireSessionCreatedCarriesId)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_session_created(ua::NodeId{1, 4242});
  pump();
  ASSERT_EQ(fake->sessionCreated, 1);
  EXPECT_EQ(fake->sessionCreatedId, ua::NodeId(1, 4242));
}

TEST_F(ClientObserverSinkTest, FireSessionActivatedInvokesObserver)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_session_activated();
  pump();
  EXPECT_EQ(fake->sessionActivated, 1);
}

TEST_F(ClientObserverSinkTest, FireSessionRecreatedCarriesOldAndNewId)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_session_recreated(ua::NodeId{1, 10}, ua::NodeId{1, 20});
  pump();
  ASSERT_EQ(fake->sessionRecreated, 1);
  EXPECT_EQ(fake->sessionRecreatedOld, ua::NodeId(1, 10));
  EXPECT_EQ(fake->sessionRecreatedNew, ua::NodeId(1, 20));
}

TEST_F(ClientObserverSinkTest, FireNamespaceRemapCarriesFlags)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_namespace_remap(7, /*sizeChanged=*/true, /*indexShifted=*/false);
  pump();
  ASSERT_EQ(fake->namespaceRemap, 1);
  EXPECT_EQ(fake->namespaceGeneration, 7u);
  EXPECT_TRUE(fake->namespaceSizeChanged);
  EXPECT_FALSE(fake->namespaceIndexShifted);
}

TEST_F(ClientObserverSinkTest, FireErrorChainCarriesCodeDetailAndTag)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  std::shared_ptr<const ua::ErrorDetail> chain =
    ua::make_error_detail("Boom", "wire failure", "client.tier0.session.send_request");
  mSink->fire_error_chain(StatusCode{ua::Status::BadTimeout}, chain, "client.tier1.connection.read_async");
  pump();
  ASSERT_EQ(fake->errorChain, 1);
  EXPECT_EQ(fake->errorChainCode.value(), StatusCode{ua::Status::BadTimeout}.value());
  EXPECT_EQ(fake->errorChainDetail.get(), chain.get());
  EXPECT_EQ(fake->errorChainTag, "client.tier1.connection.read_async")
    << "the operation tag (a string_view at the interface) must survive the async post intact";
}

TEST_F(ClientObserverSinkTest, FireAdvisoryDiagnosticCarriesDetail)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("Advice", "slow server", "client.tier1.connection");
  mSink->fire_advisory_diagnostic(detail);
  pump();
  ASSERT_EQ(fake->advisory, 1);
  EXPECT_EQ(fake->advisoryDetail.get(), detail.get());
}

// --- SubscriptionObserver / TypeObserver / other families. ---

TEST_F(ClientObserverSinkTest, SubscriptionObserverFireMethodsCarryArgs)
{
  auto fake = std::make_shared<FakeSubscriptionObserver>();
  ObserverSlots slots;
  slots.subscription = fake;
  mSink->set_slots(std::move(slots));

  mSink->fire_subscription_transferred(11);
  mSink->fire_subscription_recreated(11, 12);
  mSink->fire_publish_gap(12, 100, 105);
  mSink->fire_subscription_recovery_action(12,
    StatusCode{ua::Status::BadResponseTooLarge},
    nullptr,
    ProposedAdjustment{.maxNotificationsPerPublish = 50});
  mSink->fire_subscription_terminated(12, StatusCode{ua::Status::BadNoSubscription}, nullptr);
  pump();

  EXPECT_EQ(fake->transferred, 1);
  EXPECT_EQ(fake->transferredId, 11u);
  EXPECT_EQ(fake->recreated, 1);
  EXPECT_EQ(fake->recreatedOld, 11u);
  EXPECT_EQ(fake->recreatedNew, 12u);
  EXPECT_EQ(fake->publishGap, 1);
  EXPECT_EQ(fake->gapSub, 12u);
  EXPECT_EQ(fake->gapFrom, 100u);
  EXPECT_EQ(fake->gapTo, 105u);
  EXPECT_EQ(fake->recoveryAction, 1);
  EXPECT_EQ(fake->recoveryProposed.maxNotificationsPerPublish, 50u);
  EXPECT_EQ(fake->terminated, 1);
  EXPECT_EQ(fake->terminatedReason.value(), StatusCode{ua::Status::BadNoSubscription}.value());
}

TEST_F(ClientObserverSinkTest, TypeObserverFireCarriesEncodingIdAndName)
{
  auto fake = std::make_shared<FakeTypeObserver>();
  ObserverSlots slots;
  slots.type = fake;
  mSink->set_slots(std::move(slots));
  mSink->fire_type_registered(ua::NodeId{2, 7001}, "MyStruct");
  pump();
  ASSERT_EQ(fake->registered, 1);
  EXPECT_EQ(fake->encodingId, ua::NodeId(2, 7001));
  EXPECT_EQ(fake->typeName, "MyStruct");
}

TEST_F(ClientObserverSinkTest, AddressSpaceObserverFireCarriesChanges)
{
  auto fake = std::make_shared<FakeAddressSpaceObserver>();
  ObserverSlots slots;
  slots.addressSpace = fake;
  mSink->set_slots(std::move(slots));

  std::vector<ModelChangeStructure> model;
  model.push_back(ModelChangeStructure{.affected = ua::NodeId{3, 55}, .affectedType = {}, .verb = 1});
  mSink->fire_model_change(std::move(model));
  mSink->fire_semantic_change(std::vector<SemanticChangeStructure>(2));
  pump();

  ASSERT_EQ(fake->modelChange, 1);
  EXPECT_EQ(fake->modelCount, 1u);
  EXPECT_EQ(fake->modelFirstAffected, ua::NodeId(3, 55));
  EXPECT_EQ(fake->semanticChange, 1);
  EXPECT_EQ(fake->semanticCount, 2u);
}

// @verifies CL-EVT-005
// @relation(CL-EVT-005, scope=function)
TEST_F(ClientObserverSinkTest, ServerStateObserverFireMethodsCarryArgs)
{
  auto fake = std::make_shared<FakeServerStateObserver>();
  ObserverSlots slots;
  slots.serverState = fake;
  mSink->set_slots(std::move(slots));

  mSink->fire_device_failure(EventNotification{});
  mSink->fire_progress_event(EventNotification{});
  mSink->fire_system_status_change(ua::NodeId{ua::ObjectId::Server},
    ua::String{"Server"},
    ua::ServerState::Shutdown,
    SystemStatusOrigin::Server);
  pump();

  EXPECT_EQ(fake->deviceFailure, 1);
  EXPECT_EQ(fake->progress, 1);
  ASSERT_EQ(fake->statusChange, 1);
  EXPECT_EQ(fake->statusState, ua::ServerState::Shutdown);
  EXPECT_EQ(fake->statusSource, ua::NodeId{ua::ObjectId::Server});
  EXPECT_EQ(fake->statusOrigin, SystemStatusOrigin::Server);
}

TEST_F(ClientObserverSinkTest, AlarmObserverFireMethodsCarryArgs)
{
  auto fake = std::make_shared<FakeAlarmObserver>();
  ObserverSlots slots;
  slots.alarm = fake;
  mSink->set_slots(std::move(slots));

  mSink->fire_refresh_required(4);
  mSink->fire_data_integrity_warning(TrackedKey{}, DataIntegrityKind::NonExclusiveCrossGroup, nullptr);
  mSink->fire_audit_event(EventNotification{});
  pump();

  ASSERT_EQ(fake->refreshRequired, 1);
  EXPECT_EQ(fake->refreshCount, 4u);
  ASSERT_EQ(fake->dataIntegrity, 1);
  EXPECT_EQ(fake->dataIntegrityKind, DataIntegrityKind::NonExclusiveCrossGroup);
  EXPECT_EQ(fake->auditEvent, 1);
}

// @verifies CL-AUDIT-006
// @relation(CL-AUDIT-006, scope=function)
TEST_F(ClientObserverSinkTest, AuditSubtypeCategoriesRouteToSpecificHookAndBaseHook)
{
  auto fake = std::make_shared<FakeAlarmObserver>();
  ObserverSlots slots;
  slots.alarm = fake;
  mSink->set_slots(std::move(slots));

  const std::array categories{
    ua::client::AuditEventCategory::Security,
    ua::client::AuditEventCategory::Channel,
    ua::client::AuditEventCategory::Session,
    ua::client::AuditEventCategory::Update,
    ua::client::AuditEventCategory::UpdateMethod,
  };
  for (const auto category : categories)
  {
    EventNotification event;
    event.auditSubtype = ua::client::AuditSubtypeFields{.category = category};
    mSink->fire_audit_event(std::move(event));
  }
  pump();

  EXPECT_EQ(fake->auditSecurity, 1);
  EXPECT_EQ(fake->auditChannel, 1);
  EXPECT_EQ(fake->auditSession, 1);
  EXPECT_EQ(fake->auditUpdate, 1);
  EXPECT_EQ(fake->auditUpdateMethod, 1);
  EXPECT_EQ(fake->auditEvent, categories.size())
    << "category delivery augments rather than replaces the base audit hook";
}

TEST_F(ClientObserverSinkTest, RedundancyObserverFireMethodsCarryArgs)
{
  auto fake = std::make_shared<FakeRedundancyObserver>();
  ObserverSlots slots;
  slots.redundancy = fake;
  mSink->set_slots(std::move(slots));

  mSink->fire_redundancy_degraded("opc.tcp://a", RedundancyDegradeReason::ServiceLevelBelowHealthy);
  mSink->fire_redundancy_failover_started(
    "opc.tcp://a", "opc.tcp://b", ua::client::ReconnectCause{ua::client::TransportDropped{}});
  mSink->fire_redundancy_failover_completed("opc.tcp://b", ReconnectOutcome{});
  mSink->fire_redundancy_recovered("opc.tcp://b");
  pump();

  ASSERT_EQ(fake->degraded, 1);
  EXPECT_EQ(fake->degradedUri, "opc.tcp://a");
  EXPECT_EQ(fake->degradedReason, RedundancyDegradeReason::ServiceLevelBelowHealthy);
  ASSERT_EQ(fake->failoverStarted, 1);
  EXPECT_EQ(fake->failoverFrom, "opc.tcp://a");
  EXPECT_EQ(fake->failoverTo, "opc.tcp://b");
  EXPECT_EQ(fake->failoverCompleted, 1);
  EXPECT_EQ(fake->failoverNowActive, "opc.tcp://b");
  EXPECT_EQ(fake->recovered, 1);
  EXPECT_EQ(fake->recoveredUri, "opc.tcp://b");
}

// --- Cross-cutting sink behaviours. ---

TEST_F(ClientObserverSinkTest, NullFamilySlotIsACheapNoOp)
{
  // Register only a ConnectionObserver; fire a Subscription event -> the subscription slot is null.
  auto conn = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(conn));
  mSink->fire_subscription_transferred(9);  // null subscription slot
  mSink->fire_connected();  // the registered family still fires
  pump();
  EXPECT_EQ(conn->connected, 1) << "the registered family fires";
  // Nothing to observe for the null subscription slot: the falsifiable check is that it did not crash and the
  // connection family is unaffected (no cross-talk).
}

TEST_F(ClientObserverSinkTest, NeverRegisteredSlotsAreANoOp)
{
  mSink->fire_connected();  // no set_slots was ever called -> snapshot is null
  pump();
  SUCCEED() << "firing before any set_slots is a safe no-op";
}

TEST_F(ClientObserverSinkTest, FireAfterConnectionExpiredIsDropped)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));

  mConnection.reset();  // the weak ConnectionImpl the sink holds now expires

  mSink->fire_connected();
  pump();
  EXPECT_EQ(fake->connected, 0)
    << "a fire after the weak Connection expired must be dropped (no borrowed Connection to hand over)";
}

TEST_F(ClientObserverSinkTest, SetSlotsReplacesTheObserverAtomically)
{
  auto first = std::make_shared<FakeConnectionObserver>();
  auto second = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(first));
  mSink->set_slots(slots_with(second));  // wholesale replacement

  mSink->fire_connected();
  pump();
  EXPECT_EQ(first->connected, 0) << "the replaced observer must not fire";
  EXPECT_EQ(second->connected, 1) << "only the current snapshot's observer fires";
}

TEST_F(ClientObserverSinkTest, CloseSeversDelivery)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->close();

  mSink->fire_connected();
  pump();
  EXPECT_EQ(fake->connected, 0) << "close() clears the slots so every subsequent fire is a no-op";
  EXPECT_EQ(mSink->slots(), nullptr);
}

// HIGH-1 (W3 section 3.1): close() FIFO-posts the sever onto the delivery strand, so a fire posted BEFORE
// close() is DELIVERED (it was enqueued first) and only a fire posted AFTER close() drops. This replaces the
// earlier "any queued fire is severed" contract, which relied on a synchronous slots.store racing ahead of
// the queued fires (single-thread-lucky) and could silently drop the terminal on_disconnected/on_closed on a
// multi-thread pool. The single observer here is fired twice; exactly the pre-close fire must land (connected
// == 1).
TEST_F(ClientObserverSinkTest, FirePostedBeforeCloseIsDeliveredFireAfterCloseIsDropped)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(fake));
  mSink->fire_connected();  // posted BEFORE close() -> delivered (the sever is FIFO-ordered behind it)
  mSink->close();  // posts the sever BEHIND the queued fire, not a store ahead of it
  mSink->fire_connected();  // posted AFTER close() -> reads the severed (null) snapshot and drops
  pump();
  EXPECT_EQ(fake->connected, 1)
    << "exactly the fire posted before close() is delivered; the one posted after is dropped";
  EXPECT_EQ(mSink->slots(), nullptr) << "after the delivery strand drains, the sink is severed";
}

// NOTE-6: a third-party observer whose hook throws must not reach std::terminate. The fire completes, the
// throw is swallowed (and logged), and the sink keeps working for a subsequent fire.
class ThrowingConnectionObserver : public ConnectionObserver
{
public:
  int connected = 0;

  void on_connected(const ua::client::Connection&) override
  {
    ++connected;
    throw std::runtime_error("observer boom");
  }
};

TEST_F(ClientObserverSinkTest, ThrowingHookIsSwallowedAndSinkKeepsWorking)
{
  auto thrower = std::make_shared<ThrowingConnectionObserver>();
  mSink->set_slots(slots_with(thrower));

  mSink->fire_connected();
  pump();  // must NOT std::terminate: the throw is caught + swallowed inside post_fire.
  EXPECT_EQ(thrower->connected, 1) << "the throwing hook did run";

  // The sink is not poisoned by the throw: a subsequent fire against a fresh observer still delivers.
  auto healthy = std::make_shared<FakeConnectionObserver>();
  mSink->set_slots(slots_with(healthy));
  mSink->fire_connected();
  pump();
  EXPECT_EQ(healthy->connected, 1) << "a throwing hook must not stop later fires from being delivered";
}

// NOTE-4/5(b): the borrowed const Connection& a hook receives must not extend the ConnectionImpl lifetime.
// The probe reads the impl use_count DURING the hook (borrow live => baseline + 1); the fixture asserts it
// falls back to baseline AFTER the hook returns and the borrow is destroyed.
class LifetimeProbeObserver : public ConnectionObserver
{
public:
  std::shared_ptr<ConnectionImpl>* target = nullptr;
  long useCountDuringHook = 0;
  int connected = 0;

  void on_connected(const ua::client::Connection&) override
  {
    ++connected;
    useCountDuringHook = target->use_count();
  }
};

TEST_F(ClientObserverSinkTest, BorrowedConnectionDoesNotExtendImplLifetime)
{
  auto probe = std::make_shared<LifetimeProbeObserver>();
  probe->target = &mConnection;  // the sink holds only a WEAK ref, so this is the single strong owner.
  mSink->set_slots(slots_with(probe));

  const long baseline = mConnection.use_count();
  mSink->fire_connected();
  pump();

  ASSERT_EQ(probe->connected, 1);
  EXPECT_GE(probe->useCountDuringHook, baseline + 1)
    << "at least one live strong ref (the borrowed handle) exists while the hook runs, so the handle is real";
  EXPECT_EQ(mConnection.use_count(), baseline)
    << "the borrowed const Connection& must not extend the ConnectionImpl lifetime past the hook";
}

// ===================== ClientObserverSink (Client-scoped SecurityObserver) =====================

class ClientObserverClientSinkTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;

  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  ObserverSlots security_slots(std::shared_ptr<SecurityObserver> observer)
  {
    ObserverSlots slots;
    slots.security = std::move(observer);
    return slots;
  }
};

TEST_F(ClientObserverClientSinkTest, PullCertLifecycleFiresWithNullConnectionWhenNoneAssociated)
{
  auto sink = ClientObserverSink::create(mCtx.get_executor());  // no associated Connection
  auto fake = std::make_shared<FakeSecurityObserver>();
  sink->set_slots(security_slots(fake));

  sink->fire_pull_cert_management_lifecycle(PullCertLifecycleEvent::CertificateCommitted, nullptr);
  EXPECT_EQ(fake->pullCert, 0) << "delivery is posted to the executor, not fired inline";
  pump();

  ASSERT_EQ(fake->pullCert, 1);
  EXPECT_TRUE(fake->pullCertConnWasNull)
    << "a Client-scoped facility with no associated Connection delivers a null const Connection*";
  EXPECT_EQ(fake->pullCertEvent, PullCertLifecycleEvent::CertificateCommitted);
}

TEST_F(ClientObserverClientSinkTest, PullCertLifecycleFiresWithLiveConnectionWhenAssociated)
{
  // A live ConnectionImpl associated with the Client-scoped sink -> a non-null const Connection*.
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = TA::create_with_ops(mCtx.get_executor(),
    session,
    ConnectionConfig{},
    ua::Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    {});

  auto sink = ClientObserverSink::create(mCtx.get_executor(), connection);
  auto fake = std::make_shared<FakeSecurityObserver>();
  sink->set_slots(security_slots(fake));

  sink->fire_pull_cert_management_lifecycle(PullCertLifecycleEvent::RevalidationCompleted, nullptr);
  pump();

  ASSERT_EQ(fake->pullCert, 1);
  EXPECT_FALSE(fake->pullCertConnWasNull)
    << "an associated live Connection is borrowed as a non-null pointer";
}

TEST_F(ClientObserverClientSinkTest, CertificateRotatedFiresWithStubCert)
{
  auto sink = ClientObserverSink::create(mCtx.get_executor());
  auto fake = std::make_shared<FakeSecurityObserver>();
  sink->set_slots(security_slots(fake));

  sink->fire_certificate_rotated(ua::testing::make_stub_certificate());
  pump();
  EXPECT_EQ(fake->certRotated, 1);
}

TEST_F(ClientObserverClientSinkTest, CertificateRotatedNullCertIsDropped)
{
  auto sink = ClientObserverSink::create(mCtx.get_executor());
  auto fake = std::make_shared<FakeSecurityObserver>();
  sink->set_slots(security_slots(fake));

  sink->fire_certificate_rotated(nullptr);  // a null cert is a producer bug -> nothing to deliver
  pump();
  EXPECT_EQ(fake->certRotated, 0);
}

TEST_F(ClientObserverClientSinkTest, NullSecuritySlotIsANoOp)
{
  auto sink = ClientObserverSink::create(mCtx.get_executor());
  sink->fire_pull_cert_management_lifecycle(PullCertLifecycleEvent::Started, nullptr);
  pump();
  SUCCEED() << "firing with no registered security observer is a safe no-op";
}

// ===================== ConnectionImpl integration =====================

class ClientObserverConnectionTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  std::shared_ptr<ConnectionImpl> make_connection(ConnectionConfig config, ObserverSlots clientDefaults = {})
  {
    return TA::create_with_ops(mCtx.get_executor(),
      mSession,
      std::move(config),
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {},
      std::move(clientDefaults));
  }

  // A reconnect-wired Connection with keep-alive DISABLED (interval 0). Keep-alive off matters here: the
  // W3 lifecycle-fire tests drive the bootstrap to Active under a run()-to-completion pump(), and a live
  // (default 5 s) keep-alive timer would keep the io_context busy so run() never returns.
  std::shared_ptr<ConnectionImpl> make_reconnectable_connection(ConnectionConfig config)
  {
    return TA::create_with_ops(mCtx.get_executor(),
      mSession,
      std::move(config),
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      ua::client::detail::KeepAlivePolicy{std::chrono::milliseconds{0}});
  }

  // Drives the initial bootstrap to Active and pumps the delivery strand so the on_connecting /
  // on_connected / on_session_activated fan-out has been delivered on return.
  void drive_to_active(ConnectionImpl& connection)
  {
    connection.start_async([](ua::VoidResult) {});
    pump();
  }
};

TEST_F(ClientObserverConnectionTest, ConnectionConfigObserverIsResolvedIntoTheSink)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_connection(std::move(config));

  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(fake->connected, 1)
    << "the per-Connection ConnectionConfig slot is resolved into the sink at ctor";
}

TEST_F(ClientObserverConnectionTest, PerConnectionConfigSlotOverridesClientLevelDefault)
{
  auto clientDefault = std::make_shared<FakeConnectionObserver>();
  auto perConnection = std::make_shared<FakeConnectionObserver>();

  ObserverSlots clientDefaults;
  clientDefaults.connection = clientDefault;
  ConnectionConfig config;
  config.observers.connection = perConnection;

  auto connection = make_connection(std::move(config), std::move(clientDefaults));
  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(perConnection->connected, 1) << "the per-Connection slot wins";
  EXPECT_EQ(clientDefault->connected, 0) << "the Client-level default is overridden for this family";
}

TEST_F(ClientObserverConnectionTest, ClientLevelDefaultFillsAnUnsetFamily)
{
  auto clientAlarm = std::make_shared<FakeAlarmObserver>();
  ObserverSlots clientDefaults;
  clientDefaults.alarm = clientAlarm;

  auto connection = make_connection(ConnectionConfig{}, std::move(clientDefaults));
  connection->observer_sink()->fire_refresh_required(2);
  pump();
  EXPECT_EQ(clientAlarm->refreshRequired, 1)
    << "an unset per-Connection family falls back to the Client default";
}

TEST_F(ClientObserverConnectionTest, SetterReresolvesTheSinkSnapshot)
{
  auto connection = make_connection(ConnectionConfig{});
  auto fake = std::make_shared<FakeConnectionObserver>();

  connection->set_connection_observer_async(fake);
  pump();  // run the strand post that updates the per-Connection slot + re-resolves

  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(fake->connected, 1) << "a runtime setter re-resolves the sink so the new observer receives fires";
}

TEST_F(ClientObserverConnectionTest, SetterNullClearsBackToClientDefault)
{
  auto clientDefault = std::make_shared<FakeConnectionObserver>();
  auto perConnection = std::make_shared<FakeConnectionObserver>();
  ObserverSlots clientDefaults;
  clientDefaults.connection = clientDefault;
  ConnectionConfig config;
  config.observers.connection = perConnection;

  auto connection = make_connection(std::move(config), std::move(clientDefaults));

  connection->set_connection_observer_async(nullptr);  // clear the per-Connection slot
  pump();

  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(perConnection->connected, 0) << "the cleared per-Connection slot no longer fires";
  EXPECT_EQ(clientDefault->connected, 1) << "clearing the per-Connection slot restores the Client default";
}

TEST_F(ClientObserverConnectionTest, CloseSeversTheSink)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_connection(std::move(config));

  connection->close_async([](ua::VoidResult) {});
  pump();  // the sink is severed at the END of the close chain (close_session), via a delivery-strand post

  EXPECT_EQ(connection->observer_sink()->slots(), nullptr) << "close severs the sink";
  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(fake->connected, 0) << "no fire is delivered after close";
}

// HIGH-1/WARN-3: a runtime setter that lands after the Connection has closed must never re-arm the severed
// sink (the terminal-state guard on reresolve + the sink's mClosed latch).
TEST_F(ClientObserverConnectionTest, SetterAfterCloseDoesNotReArmTheSeveredSink)
{
  auto connection = make_connection(ConnectionConfig{});

  connection->close_async([](ua::VoidResult) {});
  pump();  // full graceful close: mState=Closed, sink severed at the END of the close body (WARN-3)
  ASSERT_EQ(connection->observer_sink()->slots(), nullptr) << "close severs the sink";

  auto late = std::make_shared<FakeConnectionObserver>();
  connection->set_connection_observer_async(late);
  pump();
  EXPECT_EQ(connection->observer_sink()->slots(), nullptr)
    << "a setter after close must not re-arm the severed sink";

  connection->observer_sink()->fire_connected();
  pump();
  EXPECT_EQ(late->connected, 0) << "a late observer installed after close never receives a fire";
}

// ============ W3: ConnectionObserver lifecycle fires wired into the orchestrator transitions ============
//
// These drive the ConnectionImpl's own transitions (bootstrap -> Active, the reconnect FSM notify interfaces, and
// graceful close) via ConnectionImplTestAccess and assert the CAPTURED ConnectionObserver method + args on a
// FakeConnectionObserver - so a dropped outcome/cause/chain, a missing fire, or a mis-ordered close-sever all
// fail a concrete assertion (not merely "did not crash").

// The initial connect fires on_connecting when the bootstrap starts, then on_connected + on_session_activated
// exactly once on the first reach-Active. on_connected observes the already-published Active state.
TEST_F(ClientObserverConnectionTest, InitialConnectFiresConnectingConnectedAndSessionActivated)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));

  drive_to_active(*connection);

  EXPECT_EQ(fake->connecting, 1) << "on_connecting fires when the initial bootstrap starts";
  EXPECT_EQ(fake->connected, 1) << "on_connected fires once the bootstrap reaches Active";
  EXPECT_EQ(fake->sessionActivated, 1) << "on_session_activated fires on the first reach-Active";
  EXPECT_EQ(fake->stateSeenOnConnected, ConnectionState::Active)
    << "on_connected observes the published Active state (fired after publish_info)";
  EXPECT_EQ(fake->reconnecting, 0);
  EXPECT_EQ(fake->reconnected, 0);
  EXPECT_EQ(fake->closed, 0);
}

// on_reconnecting fires when the FSM starts an attempt, carrying the 1-based attempt counter and the driving
// cause (both threaded through reconnect_notify_reconnecting - not dropped).
TEST_F(ClientObserverConnectionTest, ReconnectingFiresOnReconnectingWithAttemptAndCause)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));
  drive_to_active(*connection);

  ua::client::RedundancySwitchInfo info;
  info.toUri = "opc.tcp://backup";
  TA::reconnect_notify_reconnecting(*connection, /*attempt=*/2, ua::client::ReconnectCause{info});
  pump();

  ASSERT_EQ(fake->reconnecting, 1) << "on_reconnecting fires when the FSM starts a reconnect attempt";
  EXPECT_EQ(fake->reconnectingAttempt, 2u) << "the attempt counter is threaded through (not dropped)";
  EXPECT_EQ(
    fake->reconnectingCauseIndex, (ua::client::ReconnectCause{ua::client::RedundancySwitchInfo{}}).index())
    << "the driving cause is threaded through (RedundancySwitch alternative)";
}

// PROPAGATION: reconnect_notify_active RECEIVES the ReconnectOutcome (with its optional cause) and fires
// on_reconnected carrying it wholesale. Falsifiable: were the outcome dropped, reconnectedOutcome would be
// default (sessionPreserved=false, cause=nullopt). A reconnect reach-Active is on_reconnected, NOT a second
// on_connected.
TEST_F(ClientObserverConnectionTest, ReconnectReachActiveFiresOnReconnectedCarryingOutcomeWithCause)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));
  drive_to_active(*connection);

  TA::reconnect_notify_reconnecting(*connection);  // Active -> Reconnecting (a realistic reconnect cycle)
  pump();

  ua::client::ReconnectOutcome outcome;
  outcome.sessionPreserved = true;
  outcome.subscriptionsTransferred = true;
  outcome.monitoredItemsRecreated = 3;
  ua::client::RedundancySwitchInfo landed;
  landed.toUri = "opc.tcp://backup";
  outcome.cause = ua::client::ReconnectCause{landed};

  TA::reconnect_notify_active(*connection, outcome);  // Reconnecting -> Active, fires on_reconnected(outcome)
  pump();

  ASSERT_EQ(fake->reconnected, 1) << "on_reconnected fires on the reconnect reach-Active";
  EXPECT_TRUE(fake->reconnectedOutcome.sessionPreserved)
    << "the outcome is threaded through reconnect_notify_active (not dropped)";
  EXPECT_TRUE(fake->reconnectedOutcome.subscriptionsTransferred);
  EXPECT_EQ(fake->reconnectedOutcome.monitoredItemsRecreated, 3u);
  ASSERT_TRUE(fake->reconnectedOutcome.cause.has_value()) << "the outcome.cause survives the plumbing";
  ASSERT_TRUE(std::holds_alternative<ua::client::RedundancySwitchInfo>(*fake->reconnectedOutcome.cause));
  EXPECT_EQ(
    std::get<ua::client::RedundancySwitchInfo>(*fake->reconnectedOutcome.cause).toUri, "opc.tcp://backup")
    << "the RedundancySwitch cause the tier-2 RedundancyManager keys on is preserved end to end";
  EXPECT_EQ(fake->connected, 1) << "a reconnect reach-Active is on_reconnected, NOT a second on_connected";
}

// PROPAGATION: reconnect_notify_failed RECEIVES the terminal ErrorDetail chain and fires BOTH on_disconnected
// (the terminal transition off Active) and on_error_chain (the boundary advisory) carrying that exact chain.
// Falsifiable: were the chain dropped, disconnectedDetail / errorChainDetail would be null.
TEST_F(ClientObserverConnectionTest, TerminalReconnectFailureFiresDisconnectedAndErrorChainCarryingTheChain)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));
  drive_to_active(*connection);

  std::shared_ptr<const ua::ErrorDetail> chain = ua::ErrorDetail::build(
    "ReconnectFailed", "reconnect gave up after 3 attempt(s)", "client.tier1.reconnection_fsm");
  const ua::StatusCode terminal{ua::Status::BadConnectionClosed};

  TA::reconnect_notify_failed(*connection, terminal, chain);
  pump();

  ASSERT_EQ(fake->disconnected, 1) << "the terminal reconnect failure fires on_disconnected off Active";
  ASSERT_TRUE(fake->disconnectedReason.has_value());
  EXPECT_EQ(*fake->disconnectedReason, terminal) << "on_disconnected carries the terminal reason";
  ASSERT_NE(fake->disconnectedDetail, nullptr)
    << "the terminal chain is NOT dropped on the disconnected path";
  EXPECT_EQ(fake->disconnectedDetail, chain) << "the exact chain shared_ptr is threaded through";
  ASSERT_EQ(fake->errorChain, 1) << "the terminal chain also crosses the boundary advisory (on_error_chain)";
  EXPECT_EQ(fake->errorChainCode, terminal);
  ASSERT_NE(fake->errorChainDetail, nullptr) << "the chain is NOT dropped on the error-chain path";
  EXPECT_EQ(fake->errorChainDetail, chain);
  EXPECT_EQ(fake->errorChainTag, "client.tier1.reconnection_fsm")
    << "the CL-DIAG source tag of the failing operation is preserved";
}

// W1-WARNING-3 close ordering: closing an ACTIVE connection delivers BOTH on_disconnected AND on_closed. They
// are fired in begin_close, before the sink is severed in close_session; close() FIFO-posts the sever onto
// the delivery strand so the queued terminal fires drain first. This is a SINGLE-THREADED behavioural check
// (the fires arrive and carry Good/no-chain); the multi-thread race oracle that would catch a sever racing
// the fires is ClientObserverCloseOrdering.TerminalFiresSurviveSeverOnMultiThreadPool.
TEST_F(ClientObserverConnectionTest, CloseOfActiveConnectionDeliversDisconnectedAndClosedBeforeSever)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));
  drive_to_active(*connection);
  ASSERT_EQ(fake->connected, 1) << "precondition: the connection reached Active";

  connection->close_async([](ua::VoidResult) {});
  pump();  // run the whole close chain AND the observer delivery strand to completion

  EXPECT_EQ(fake->disconnected, 1)
    << "closing an Active connection fires on_disconnected BEFORE the sink is severed (WARN-3)";
  EXPECT_EQ(fake->closed, 1)
    << "on_closed is delivered BEFORE the sink sever - firing it after close() would drop it";
  ASSERT_TRUE(fake->disconnectedReason.has_value());
  EXPECT_TRUE(fake->disconnectedReason->is_good())
    << "a graceful client-initiated close is not an error (reason Good, no chain)";
  EXPECT_EQ(fake->disconnectedDetail, nullptr) << "a graceful close carries no error chain";
  EXPECT_EQ(connection->observer_sink()->slots(), nullptr) << "the sink is severed after the terminal fires";
}

// Closing a NON-Active connection (never reached Active) fires on_closed but NOT on_disconnected (the
// connection never left an Active link). Guards the `if (wasActive)` branch in begin_close.
TEST_F(ClientObserverConnectionTest, CloseOfNonActiveConnectionFiresClosedButNotDisconnected)
{
  auto fake = std::make_shared<FakeConnectionObserver>();
  ConnectionConfig config;
  config.observers.connection = fake;
  auto connection = make_reconnectable_connection(std::move(config));
  // Do NOT drive to Active: close straight from Connecting.

  connection->close_async([](ua::VoidResult) {});
  pump();

  EXPECT_EQ(fake->closed, 1) << "every graceful close reaches Closed and fires on_closed";
  EXPECT_EQ(fake->disconnected, 0)
    << "a connection that never reached Active did not leave Active - on_disconnected must not fire";
}

// ============ ObserverSink delivery-strand serialization (WARN-2 / NOTE-4-5a) ============
//
// These run the sink over a REAL 2-thread pool so an unserialized (bare-executor) delivery is observably
// wrong: fires would run concurrently and out of order. The private per-sink delivery strand keeps delivery
// FIFO and one-at-a-time, DISTINCT from the connection strand.

ObserverSlots connection_slots(std::shared_ptr<ConnectionObserver> observer)
{
  ObserverSlots slots;
  slots.connection = std::move(observer);
  return slots;
}

std::shared_ptr<ConnectionImpl> make_pool_connection(
  boost::asio::thread_pool& pool, std::shared_ptr<FakeSessionOps> session, std::shared_ptr<FakeReopen> reopen)
{
  return TA::create_with_ops(pool.get_executor(),
    std::move(session),
    ConnectionConfig{},
    ua::Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    {});
}

// Records the exact delivery order of connecting(1)/connected(2) under a mutex (never contended under the
// strand - there is no concurrent access when delivery is serialized).
class OrderRecordingObserver : public ConnectionObserver
{
public:
  std::mutex mutex;
  std::vector<int> order;

  void on_connecting(const ua::client::Connection&) override
  {
    // Widen the interleaving window so an unserialized executor reorders/overlaps deterministically.
    std::this_thread::sleep_for(std::chrono::microseconds(200));
    std::lock_guard<std::mutex> lock(mutex);
    order.push_back(1);
  }

  void on_connected(const ua::client::Connection&) override
  {
    std::lock_guard<std::mutex> lock(mutex);
    order.push_back(2);
  }
};

TEST(ClientObserverSinkConcurrency, DeliveryIsOrderedOnASerializingStrand)
{
  boost::asio::thread_pool pool(2);
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_pool_connection(pool, session, reopen);
  auto sink = ObserverSink::create(pool.get_executor(), connection);
  auto observer = std::make_shared<OrderRecordingObserver>();
  sink->set_slots(connection_slots(observer));

  constexpr int pairs = 200;
  for (int i = 0; i < pairs; ++i)
  {
    sink->fire_connecting();
    sink->fire_connected();
  }
  pool.join();  // drain all delivery work

  ASSERT_EQ(observer->order.size(), static_cast<std::size_t>(pairs) * 2);
  // The strand preserves submission order: connecting(1) then connected(2), repeated. A bare executor on two
  // threads would let a connected(2) land before its connecting(1).
  for (int i = 0; i < pairs; ++i)
  {
    EXPECT_EQ(observer->order[static_cast<std::size_t>(i) * 2], 1) << "pair " << i << " connecting first";
    EXPECT_EQ(observer->order[static_cast<std::size_t>(i) * 2 + 1], 2) << "pair " << i << " connected second";
  }
}

// Detects concurrent hook execution: on a serializing strand the in-flight count never exceeds 1. A bare
// multi-thread executor would let two hooks overlap.
class ConcurrencyProbeObserver : public ConnectionObserver
{
public:
  std::atomic<int> active{0};
  std::atomic<int> maxObserved{0};
  std::atomic<int> connected{0};

  void on_connected(const ua::client::Connection&) override
  {
    const int now = ++active;
    int prev = maxObserved.load();
    while (now > prev && !maxObserved.compare_exchange_weak(prev, now))
    {
    }
    std::this_thread::sleep_for(std::chrono::microseconds(200));  // hold the slot so an overlap is visible
    --active;
    ++connected;
  }
};

TEST(ClientObserverSinkConcurrency, DeliveryIsMutuallyExclusiveOnTheSinkStrand)
{
  boost::asio::thread_pool pool(2);
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_pool_connection(pool, session, reopen);
  auto sink = ObserverSink::create(pool.get_executor(), connection);
  auto observer = std::make_shared<ConcurrencyProbeObserver>();
  sink->set_slots(connection_slots(observer));

  constexpr int fires = 200;
  for (int i = 0; i < fires; ++i)
  {
    sink->fire_connected();
  }
  pool.join();

  EXPECT_EQ(observer->connected.load(), fires);
  EXPECT_EQ(observer->maxObserved.load(), 1)
    << "delivery is serialized on the sink's own delivery strand (off the connection strand); no two hooks "
       "overlap. A bare-executor regression would observe concurrency > 1.";
}

// ============ HIGH-1 (W3 section 3.1): close-ordering under real concurrency ============
//
// close() must FIFO-post the slots sever ONTO the delivery strand so it runs BEHIND fires posted before it -
// not store null on the caller's (connection-strand) thread, which races the in-flight fires. These two tests
// run on a REAL 2-thread pool with a hook that seizes the delivery strand, so the pre-fix synchronous store
// deterministically wins the race and drops the queued fire(s) (RED); the delivery-strand-ordered sever
// delivers them (GREEN). They are the genuine multi-thread oracle the single-threaded close tests cannot be.

// Sink-level: a slow on_connecting holds the delivery strand while close() is called from the test thread;
// the on_connected queued before close() must survive the sever.
class SlowThenCountObserver : public ConnectionObserver
{
public:
  std::atomic<int> connecting{0};
  std::atomic<int> connected{0};

  void on_connecting(const ua::client::Connection&) override
  {
    ++connecting;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));  // seize the delivery strand across close()
  }

  void on_connected(const ua::client::Connection&) override
  {
    ++connected;
  }
};

TEST(ClientObserverCloseOrdering, FirePostedBeforeCloseSurvivesSeverOnMultiThreadPool)
{
  boost::asio::thread_pool pool(2);
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_pool_connection(pool, session, reopen);
  auto sink = ObserverSink::create(pool.get_executor(), connection);
  auto observer = std::make_shared<SlowThenCountObserver>();
  sink->set_slots(connection_slots(observer));

  sink->fire_connecting();  // SLOW hook: seizes the delivery strand for ~100 ms
  sink->fire_connected();  // queued behind it; must survive the sever
  sink->close();  // MUST post the sever behind the queued fires, not store null ahead of them
  pool.join();

  EXPECT_EQ(observer->connecting.load(), 1) << "the first (slow) fire ran";
  EXPECT_EQ(observer->connected.load(), 1)
    << "a fire posted before close() must be delivered, not lost to the sever race on a multi-thread pool";
}

// Connection-level (the actual HIGH-1 scenario): begin_close fires on_disconnected/on_closed onto the
// delivery strand, then close_session severs. A slow on_connected (held in-flight via a handshake) keeps the
// delivery strand busy across the whole close chain, so the terminal fires are still queued when the sever
// runs.
class SlowConnectedTerminalObserver : public ConnectionObserver
{
public:
  std::promise<void> connectedStarted;  // signalled when on_connected seizes the delivery strand
  std::atomic<int> connected{0};
  std::atomic<int> disconnected{0};
  std::atomic<int> closed{0};

  void on_connected(const ua::client::Connection&) override
  {
    ++connected;
    connectedStarted.set_value();  // the delivery strand is now occupied; the test may close()
    std::this_thread::sleep_for(std::chrono::milliseconds(100));  // hold it across the close chain + sever
  }

  void on_disconnected(
    const ua::client::Connection&, ua::StatusCode, std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++disconnected;
  }

  void on_closed(const ua::client::Connection&) override
  {
    ++closed;
  }
};

TEST(ClientObserverCloseOrdering, TerminalFiresSurviveSeverOnMultiThreadPool)
{
  boost::asio::thread_pool pool(2);
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto observer = std::make_shared<SlowConnectedTerminalObserver>();

  ConnectionConfig config;
  config.observers.connection = observer;
  // Keep-alive DISABLED (interval 0): we drive to Active, and a live keep-alive timer would keep the pool
  // busy so pool.join() never returns.
  auto connection = TA::create_with_ops(pool.get_executor(),
    session,
    std::move(config),
    ua::Logger{},
    reopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    ua::client::detail::KeepAlivePolicy{std::chrono::milliseconds{0}});

  connection->start_async([](ua::VoidResult) {});
  // Wait until on_connected is IN-FLIGHT on the delivery strand (Active). Bounded so a future bootstrap
  // regression that never reaches Active fails fast here instead of hanging CI.
  ASSERT_EQ(
    observer->connectedStarted.get_future().wait_for(std::chrono::seconds(5)), std::future_status::ready)
    << "the connection did not reach Active / fire on_connected within 5 s";
  connection->close_async(
    [](ua::VoidResult) {});  // begin_close queues on_disconnected/on_closed, then severs
  pool.join();

  EXPECT_EQ(observer->connected.load(), 1) << "precondition: the initial connect reached Active";
  EXPECT_EQ(observer->disconnected.load(), 1)
    << "the terminal on_disconnected fired in begin_close must not be lost to the sever race (multi-thread)";
  EXPECT_EQ(observer->closed.load(), 1)
    << "the terminal on_closed fired in begin_close must not be lost to the sever race (multi-thread)";
}

// ClientObserverSink::close() received the identical delivery-strand-ordered sever; prove it holds under the
// same race. A slow pull-cert callback seizes the delivery strand while a second callback queued before
// close() must survive the sever.
class SlowClientSecurityObserver : public SecurityObserver
{
public:
  std::atomic<int> pullCert{0};

  void on_pull_cert_management_lifecycle(
    const ua::client::Connection*, PullCertLifecycleEvent, std::shared_ptr<const ua::ErrorDetail>) override
  {
    if (++pullCert == 1)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));  // seize strand across close()
  }
};

TEST(ClientObserverCloseOrdering, ClientSinkFirePostedBeforeCloseSurvivesSeverOnMultiThreadPool)
{
  boost::asio::thread_pool pool(2);
  auto sink = ClientObserverSink::create(pool.get_executor());  // purely Client-scoped (no Connection)
  auto observer = std::make_shared<SlowClientSecurityObserver>();
  ObserverSlots slots;
  slots.security = observer;
  sink->set_slots(std::move(slots));

  sink->fire_pull_cert_management_lifecycle(PullCertLifecycleEvent::CertificateCommitted, nullptr);  // SLOW
  sink->fire_pull_cert_management_lifecycle(
    PullCertLifecycleEvent::TrustListCommitted, nullptr);  // queued behind it; must survive
  sink->close();  // FIFO-posts the sever behind the queued fires, not a store ahead of them
  pool.join();

  EXPECT_EQ(observer->pullCert.load(), 2)
    << "a Client-scoped fire posted before close() must survive the sever race on a multi-thread pool";
}

}  // namespace
