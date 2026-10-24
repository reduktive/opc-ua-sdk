// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientSubscriptionModify cluster of the client integration-test matrix (the 10
///        `ClientSubscriptionModify.*` rows).
///
/// These are END-TO-END integration tests of the TIER-1 public @ref ua::client::Subscription lifecycle
/// surface (modify / set_publishing_mode / close, client design section 7.4) reached through the
/// reconnect-surviving `SubscriptionsPipeline` (section 8.4). A real `Client` is bound to a
/// `MisbehavingServer` over ephemeral TCP; the tier-0 connect yields an activated Session wrapped into a
/// started `ConnectionImpl`, from which the public
/// @ref ua::client::Connection handle (and its `subscriptions()` sub-accessor) build real `Subscription`
/// handles. The server is bent with `set_response_mutator` to inject per-item bad statuses / a bad
/// serviceResult / a revised interval into the specific ModifySubscription / SetPublishingMode /
/// DeleteSubscriptions response under test (the CreateSubscription bootstrap is left un-mutated so the
/// handle exists first).
///
/// The observable surfaces are: (a) the VoidResult the tier-1 call completes with (the exact StatusCode the
/// facade surfaces - a mask would be caught here); (b) the tier-1 handle snapshot
/// (`publishing_interval` / `is_publishing_enabled`); (c) the pipeline INFO snapshot
/// (`subscriptionCount` - the strand-private registry, proving a record kept/dropped); (d) the pipeline
/// recovery descriptors (`ConnectionImplTestAccess::pipeline_recovery_descriptors` - the retained
/// replay-record interval a session-CHANGED recreate would replay); and (e) the DECODED outgoing request
/// stream (`MisbehavingServer::set_request_observer` - the presence/absence of a re-issued
/// ModifySubscription).
///
/// Calibrated to REAL built behaviour. The facade surfaces the EXACT serviceResult / per-item status (there
/// is no serviceResult-flatten mask in `flatten_status_result` or `modify_async`), so the surfacing rows are
/// GREEN.
///
/// REPORTED gaps (assert the built observable, pin the closest analog, record the unbuilt part - per the
/// ClientSubscription / ClientBrowse blocked-row precedent):
///   - ReplayRecordUpdatedSurvivesRecreate / ReplaySurvivesTransferFailureThenRecreate: a successful
///     ModifySubscription now updates the pipeline replay record (CL-SUB-012 BUILT - the completion wrapper
///     calls `update_publishing_interval_async`), so a session-CHANGED recreate replays the MODIFIED
///     interval. These rows assert the retained-record observable now tracks the modify; the full
///     reconnect+recreate / transfer-fail+recreate end-to-end remains reconnect-harness-blocked. The
///     DISTINCT tier-1 handle revised-value capture - UpdatesRevisedValuesOnSuccess - is now BUILT
///     (CL-SUB-011): a Good modify updates `publishing_interval()` to the server-revised value.
///   - SurfacesBadSubscriptionIdInvalidAndDropsRecord: a modify returning Bad_SubscriptionIdInvalid SURFACES
///     the status AND drops the local record (CL-SUB-013 BUILT - the completion wrapper removes the record on
///     the authoritative Bad_SubscriptionIdInvalid). Pins the surface +
///     records the drop unbuilt.
///   - ServiceLevelErrorsSurfacedNoStateChange: the exact service-level StatusCode surfaces (no mask) with no
///     local state change; the facade does not SYNTHESISE an ErrorDetail for a bare service-level bad (the
///     "with ErrorDetail" clause is an annotation gap - reported, not asserted).

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_connection_handle_factory.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_logger.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_node_id.h"
#include "ua_publish_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_subscriptions.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::RecoveryDescriptor;
using ua::test_helpers::MisbehavingServer;

namespace
{

// --- Response-mutator building blocks (each edits one typed response in place, before signing) ---

// Stamps ResponseHeader.serviceResult on a response of type @p ResponseT (leaving every other response type
// untouched, so the CreateSubscription bootstrap still succeeds).
template<class ResponseT>
void stamp_service_result(ua::Response& response, ua::StatusCode status)
{
  if (auto* typed = dynamic_cast<ResponseT*>(response.second.get()))
  {
    typed->response_header().service_result() = status;
  }
}

// Sets the first per-item StatusCode of a results()-bearing response (SetPublishingMode /
// DeleteSubscriptions), leaving the service-level result Good - the "per-item bad dominates a Good service
// result" input.
template<class ResponseT>
void stamp_first_item_result(ua::Response& response, ua::StatusCode status)
{
  if (auto* typed = dynamic_cast<ResponseT*>(response.second.get()))
  {
    if (typed->results().size() == 0)
    {
      typed->results().push_back(status);
    }
    else
    {
      typed->results()[0] = status;
    }
  }
}

// Rewrites the revisedPublishingInterval a ModifySubscription reports back (so the server-revised value is
// distinguishable from both the requested modify value and the create value).
void stamp_revised_publishing_interval(ua::Response& response, double revised)
{
  if (auto* modify = dynamic_cast<ua::ModifySubscriptionResponse*>(response.second.get()))
  {
    modify->revised_publishing_interval() = revised;
  }
}

// A read-only tally of the outgoing request types a row asserts the ABSENCE of. Populated on a server strand
// by the request observer, read by the test thread.
struct RequestTally
{
  mutable std::mutex mutex;
  std::size_t modifySubscriptionCount = 0;
  std::size_t publishCount = 0;

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (dynamic_cast<const ua::ModifySubscriptionRequest*>(&request))
    {
      ++modifySubscriptionCount;
    }
    else if (dynamic_cast<const ua::PublishRequest*>(&request))
    {
      ++publishCount;
    }
  }

  std::size_t modify_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return modifySubscriptionCount;
  }

  std::size_t publish_count() const
  {
    std::lock_guard lock(mutex);
    return publishCount;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 6000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

// ---------------------------------------------------------------------------------------------
// MisbehavingModifyFixture: a real client bound to a MisbehavingServer, on its own thread pool, with an
// activated Session wrapped into a started tier-1 ConnectionImpl (the same interface as the sibling
// ClientSubscription / ClientRepublish fixtures). It additionally exposes the public Connection handle so a
// test drives the tier-1 Subscription lifecycle (modify / set_publishing_mode / close) end-to-end, plus the
// pipeline info + recovery-descriptor snapshots.
// ---------------------------------------------------------------------------------------------
class MisbehavingModifyFixture
{
public:
  explicit MisbehavingModifyFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientSubscriptionModifyMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingModifyFixture()
  {
    if (mConnection)
      (void)close_and_wait(*mConnection);
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingModifyFixture(const MisbehavingModifyFixture&) = delete;
  MisbehavingModifyFixture& operator=(const MisbehavingModifyFixture&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  ConnectionState state() const
  {
    auto info = mConnection->info();
    return info ? info->state : ConnectionState::Closed;
  }

  std::size_t subscription_count() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->subscriptionCount : 0;
  }

  // The retained replay-record interval a session-CHANGED recreate would replay for @p subscriptionId, or
  // nullopt when the subscription is no longer registered.
  std::optional<double> retained_interval(std::uint32_t subscriptionId) const
  {
    for (const auto& descriptor : ConnectionImplTestAccess::pipeline_recovery_descriptors(*mConnection))
    {
      if (descriptor.subscriptionId == subscriptionId)
        return descriptor.publishingInterval;
    }
    return std::nullopt;
  }

  std::size_t retained_item_count(std::uint32_t subscriptionId) const
  {
    for (const auto& descriptor : ConnectionImplTestAccess::pipeline_recovery_descriptors(*mConnection))
    {
      if (descriptor.subscriptionId == subscriptionId)
        return descriptor.monitoredItems.size();
    }
    return 0;
  }

  Connection connection()
  {
    return ConnectionHandleFactory::make_connection(mConnection);
  }

  // Builds a real tier-1 Subscription handle through the public path (registers it in the pipeline).
  Result<Subscription> create_subscription(double publishingIntervalMs)
  {
    return connection().subscriptions().try_create_sync(SubscriptionConfig{publishingIntervalMs});
  }

  static VoidResult start_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

}  // namespace

class ClientSubscriptionModify : public ::testing::Test
{};

// =============================================================================================
// Row - SetPublishingModePerItemBadSurfaced  (MisbehavingServer)  [integration+unit]
// SetPublishingMode returns a Good service result but results[0]=Bad_SubscriptionIdInvalid: the affected
// Subscription's callback must receive the bad StatusCode (the per-item result dominates the Good service
// result), while an unaffected Subscription still receives Good. If the client trusted the Good service
// result alone, the failed subscription would be reported as succeeded. [neg: per-item dominates service
// Good]
// =============================================================================================
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(ClientSubscriptionModify, SetPublishingModePerItemBadSurfaced)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Two live Subscriptions (each set_publishing_mode is its own one-sub SetPublishingMode).
  auto affected = fixture.create_subscription(200.0);
  ASSERT_TRUE(affected.is_good()) << to_string(affected.status_code());
  auto unaffected = fixture.create_subscription(200.0);
  ASSERT_TRUE(unaffected.is_good()) << to_string(unaffected.status_code());

  // While ARMED, every SetPublishingModeResponse carries a Good service result but a per-item
  // Bad_SubscriptionIdInvalid; disarming lets the server's genuine Good pass through.
  auto armed = std::make_shared<std::atomic<bool>>(true);
  server.set_response_mutator(
    [armed](ua::Response& response)
    {
      if (armed->load())
        stamp_first_item_result<ua::SetPublishingModeResponse>(
          response, ua::StatusCode{Status::BadSubscriptionIdInvalid});
    });

  const VoidResult affectedResult = affected.value().try_set_publishing_mode_sync(false);
  EXPECT_TRUE(affectedResult.is_bad())
    << "a per-item Bad_SubscriptionIdInvalid must dominate the Good service result";
  EXPECT_EQ(affectedResult.status_code(), ua::StatusCode{Status::BadSubscriptionIdInvalid})
    << "the exact per-item status must reach the caller";
  EXPECT_TRUE(affected.value().is_publishing_enabled())
    << "a failed set_publishing_mode must NOT flip the handle's mode snapshot";

  armed->store(false);
  const VoidResult unaffectedResult = unaffected.value().try_set_publishing_mode_sync(false);
  EXPECT_TRUE(unaffectedResult.is_good())
    << "an unaffected Subscription (results[0]=Good) must report success";
  EXPECT_FALSE(unaffected.value().is_publishing_enabled())
    << "the unaffected Subscription's mode snapshot tracks the applied value";
}

// =============================================================================================
// Row - SetPublishingModeAllBadSurfacedToAll  (MisbehavingServer)
// SetPublishingMode returns results[*]=Bad_SubscriptionIdInvalid for every Subscription: every
// per-Subscription callback must receive the bad StatusCode. If any were reported Good the failure would be
// masked. [neg: all-bad per-item vector]
// =============================================================================================
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(ClientSubscriptionModify, SetPublishingModeAllBadSurfacedToAll)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  std::vector<Subscription> subscriptions;
  for (int i = 0; i < 3; ++i)
  {
    auto subscription = fixture.create_subscription(200.0);
    ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
    subscriptions.push_back(std::move(subscription.value()));
  }

  // Every SetPublishingModeResponse (each a one-sub request) reports a per-item bad - the "all bad" vector.
  server.set_response_mutator(
    [](ua::Response& response)
    {
      stamp_first_item_result<ua::SetPublishingModeResponse>(
        response, ua::StatusCode{Status::BadSubscriptionIdInvalid});
    });

  for (auto& subscription : subscriptions)
  {
    const VoidResult result = subscription.try_set_publishing_mode_sync(false);
    EXPECT_TRUE(result.is_bad()) << "every Subscription must see the all-bad per-item status (none masked)";
    EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadSubscriptionIdInvalid});
    EXPECT_TRUE(subscription.is_publishing_enabled())
      << "a failed set_publishing_mode must NOT flip the mode snapshot";
  }
}

// =============================================================================================
// Row - SurfacesBadInternalErrorKeepsRecord  (MisbehavingServer)
// A ModifySubscription returning a TRANSIENT Bad_InternalError must surface the error to the caller but must
// NOT drop the local Subscription record (the subscription is still valid server-side). If the client dropped
// it, a recoverable transient error would destroy a still-valid subscription. [neg: transient must NOT drop]
// =============================================================================================
// @verifies CL-SUB-013
// @relation(CL-SUB-013, scope=function)
TEST_F(ClientSubscriptionModify, SurfacesBadInternalErrorKeepsRecord)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();
  ASSERT_EQ(fixture.subscription_count(), 1u);

  server.set_response_mutator(
    [](ua::Response& response)
    {
      stamp_service_result<ua::ModifySubscriptionResponse>(
        response, ua::StatusCode{Status::BadInternalError});
    });

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = 300.0;
  const VoidResult result = subscription.value().try_modify_sync(config);

  EXPECT_TRUE(result.is_bad()) << "a Bad_InternalError service result must surface to the caller";
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadInternalError})
    << "the exact transient status must reach the caller (not a mask)";
  EXPECT_EQ(fixture.subscription_count(), 1u)
    << "a TRANSIENT error must NOT drop the local Subscription record";
  EXPECT_TRUE(fixture.retained_interval(subscriptionId).has_value())
    << "the replay record for a transiently-failed modify is retained";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - SurfacesBadSubscriptionIdInvalidAndDropsRecord  (MisbehavingServer)
// A ModifySubscription returning service-result Bad_SubscriptionIdInvalid must surface the status to the
// caller (the subscription is gone server-side) so later ops do not silently target a non-existent
// subscription. [neg: subscription gone -> surface + no retry]
//
// BUILT (CL-SUB-013): the caller receives the exact Bad_SubscriptionIdInvalid without a retry AND the stale
// local record is DROPPED from the pipeline registry - `modify_subscription_async` now wraps its completion
// (mirroring `delete_subscription_async`) to `remove_subscription_async` on the authoritative
// Bad_SubscriptionIdInvalid, so a later op cannot silently target a gone Subscription. A transient bad keeps
// the record (it may still be alive server-side); no retry either way.
// =============================================================================================
// @verifies CL-SUB-013
// @relation(CL-SUB-013, scope=function)
TEST_F(ClientSubscriptionModify, SurfacesBadSubscriptionIdInvalidAndDropsRecord)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  ASSERT_EQ(fixture.subscription_count(), 1u);

  server.set_response_mutator(
    [](ua::Response& response)
    {
      stamp_service_result<ua::ModifySubscriptionResponse>(
        response, ua::StatusCode{Status::BadSubscriptionIdInvalid});
    });

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = 300.0;
  const VoidResult result = subscription.value().try_modify_sync(config);

  // BUILT: the exact server status is surfaced to the caller (no mask, no retry).
  EXPECT_TRUE(result.is_bad()) << "a Bad_SubscriptionIdInvalid must surface to the caller";
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadSubscriptionIdInvalid})
    << "the exact server status must reach the caller";

  // BUILT (CL-SUB-013): the stale local record is DROPPED on Bad_SubscriptionIdInvalid - the Subscription is
  // gone server-side. The removal is an async pipeline post (fired before the sync caller unblocks), so poll.
  EXPECT_TRUE(wait_until([&] { return fixture.subscription_count() == 0; }))
    << "a Bad_SubscriptionIdInvalid ModifySubscription must drop the stale local Subscription record";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - DeleteSubscriptionsPerItemBadRemovesAffected  (MisbehavingServer)
// DeleteSubscriptions returns a Good service result with results[0]=Bad_SubscriptionIdInvalid: the per-item
// disposition surfaces to the caller AND the AFFECTED subscription's local record is reconciled (removed),
// while an UNAFFECTED subscription's record survives. If positional alignment were wrong the wrong
// subscription's record would be removed. [neg: per-item delete result alignment]
// =============================================================================================
// @verifies CL-SUB-013
// @relation(AC-CL-SUB-013-MODIFY-NO-RETRY, scope=function)
TEST_F(ClientSubscriptionModify, DeleteSubscriptionsPerItemBadRemovesAffected)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto affected = fixture.create_subscription(200.0);
  ASSERT_TRUE(affected.is_good()) << to_string(affected.status_code());
  auto survivor = fixture.create_subscription(200.0);
  ASSERT_TRUE(survivor.is_good()) << to_string(survivor.status_code());
  const std::uint32_t survivorId = survivor.value().server_subscription_id();
  ASSERT_EQ(fixture.subscription_count(), 2u);

  // Every DeleteSubscriptionsResponse: service-Good but results[0]=Bad_SubscriptionIdInvalid (the affected id
  // was already gone server-side). Only the AFFECTED subscription is closed.
  server.set_response_mutator(
    [](ua::Response& response)
    {
      stamp_first_item_result<ua::DeleteSubscriptionsResponse>(
        response, ua::StatusCode{Status::BadSubscriptionIdInvalid});
    });

  const VoidResult closeResult = affected.value().try_close_sync();
  EXPECT_TRUE(closeResult.is_bad()) << "the per-item Bad status must surface to the caller";
  EXPECT_EQ(closeResult.status_code(), ua::StatusCode{Status::BadSubscriptionIdInvalid})
    << "the exact per-item delete status must reach the caller";

  // Reconciliation is posted by the asynchronous pipeline before the sync close returns, but its
  // strand turn need not have executed yet on a loaded runner.
  EXPECT_TRUE(wait_until([&] { return fixture.subscription_count() == 1u; }))
    << "the AFFECTED subscription's record is reconciled (removed); one subscription remains";
  EXPECT_TRUE(fixture.retained_interval(survivorId).has_value())
    << "the UNAFFECTED subscription's record must survive the positional per-item disposition";
}

// =============================================================================================
// Row - ServiceLevelErrorsSurfacedNoStateChange  (MisbehavingServer)
// A service-level Bad (Bad_NothingToDo / Bad_TooManyOperations) on SetPublishingMode or DeleteSubscriptions
// must surface the EXACT status to the caller with NO local state change (publishing mode / registry
// untouched). If a Bad service result were swallowed the client's view would diverge from the server.
// [neg: service-level Bad on SetPublishingMode/Delete]
//
// A bad service result never mutates client state, so all four combinations reuse one live subscription: the
// registry and mode snapshot must be unchanged after each. REPORTED: the facade surfaces the exact code
// (there is NO serviceResult-flatten mask) but does not synthesise an ErrorDetail for a bare service-level
// bad (the "with ErrorDetail" clause is an annotation gap - not asserted).
// =============================================================================================
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(ClientSubscriptionModify, ServiceLevelErrorsSurfacedNoStateChange)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  ASSERT_EQ(fixture.subscription_count(), 1u);
  ASSERT_TRUE(subscription.value().is_publishing_enabled());

  for (const ua::Status code : {Status::BadNothingToDo, Status::BadTooManyOperations})
  {
    // SetPublishingMode with a bad service result: surface exact + no state change.
    server.set_response_mutator([code](ua::Response& response)
      { stamp_service_result<ua::SetPublishingModeResponse>(response, ua::StatusCode{code}); });
    const VoidResult modeResult = subscription.value().try_set_publishing_mode_sync(false);
    EXPECT_TRUE(modeResult.is_bad()) << "a bad SetPublishingMode service result must surface";
    EXPECT_EQ(modeResult.status_code(), ua::StatusCode{code})
      << "the EXACT service-level status must surface (not masked as Bad_UnexpectedError)";
    EXPECT_TRUE(subscription.value().is_publishing_enabled())
      << "a bad SetPublishingMode must NOT change the mode snapshot";
    EXPECT_EQ(fixture.subscription_count(), 1u) << "a bad SetPublishingMode must not touch the registry";

    // DeleteSubscriptions with a bad service result: surface exact + record kept.
    server.set_response_mutator([code](ua::Response& response)
      { stamp_service_result<ua::DeleteSubscriptionsResponse>(response, ua::StatusCode{code}); });
    const VoidResult closeResult = subscription.value().try_close_sync();
    EXPECT_TRUE(closeResult.is_bad()) << "a bad DeleteSubscriptions service result must surface";
    EXPECT_EQ(closeResult.status_code(), ua::StatusCode{code})
      << "the EXACT service-level status must surface";
    EXPECT_EQ(fixture.subscription_count(), 1u)
      << "a bad DeleteSubscriptions must NOT drop the local record (no state change)";
  }
}

// =============================================================================================
// Row - UpdatesRevisedValuesOnSuccess  (MisbehavingServer)  [ComplianceWithSession analog]
// On a Good ModifySubscription the subscription's revised publishing interval should update to the server's
// revised value (distinct from the requested value). [neg: revised value persistence]
//
// BUILT (CL-SUB-011): a Good `modify_async` reads the response's revisedPublishingInterval and updates the
// tier-1 handle's `publishing_interval()`, so the handle reflects the server's CURRENT cadence - distinct
// from both the create-time value and the requested modify value. Pins the end-to-end revised-value capture.
// =============================================================================================
// @verifies CL-SUB-011
// @relation(CL-SUB-011, scope=function)
TEST_F(ClientSubscriptionModify, UpdatesRevisedValuesOnSuccess)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const double createInterval = subscription.value().publishing_interval();

  // The server accepts the modify (Good) but revises the interval to a DISTINCT value.
  const double serverRevised = 999.0;
  const double requestedModify = 250.0;
  ASSERT_NE(createInterval, serverRevised) << "the revised value must differ from create for the pin to bite";
  server.set_response_mutator(
    [serverRevised](ua::Response& response) { stamp_revised_publishing_interval(response, serverRevised); });

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = requestedModify;
  const VoidResult result = subscription.value().try_modify_sync(config);
  ASSERT_TRUE(result.is_good()) << "the modify itself must succeed: " << to_string(result.status_code());

  // BUILT (CL-SUB-011): the handle's publishing interval now reflects the server-REVISED modify value, not
  // the create-time value nor the requested value.
  EXPECT_DOUBLE_EQ(subscription.value().publishing_interval(), serverRevised)
    << "a Good modify updates the handle to the server-revised interval (CL-SUB-011)";
  EXPECT_NE(subscription.value().publishing_interval(), createInterval)
    << "the create-time value must have been superseded";
  EXPECT_NE(subscription.value().publishing_interval(), requestedModify)
    << "the handle exposes the server-revised value, not the requested value";
}

// =============================================================================================
// Row - DoesNotRetryDuringGraceWindow  (MisbehavingServer)
// After a modify returns, an ongoing Publish stream (which, on a real server, may still reflect the OLD
// publishing interval within the grace window) must NOT cause the client to re-issue ModifySubscription or
// emit an observer error. If the client treated an old-interval Publish as a modify failure, a spurious
// ModifySubscription would appear on the wire. [neg: tolerate old-interval Publish in grace window]
//
// The client has no interval-monitoring machinery that could spuriously re-modify (the pipeline never
// inspects Publish intervals), so this guarantee holds - pinned by the wire-observable absence of a SECOND
// ModifySubscription while Publishes actively flow after the first modify.
// =============================================================================================
// @verifies CL-SUB-011
// @relation(CL-SUB-011, scope=function)
TEST_F(ClientSubscriptionModify, DoesNotRetryDuringGraceWindow)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto tally = std::make_shared<RequestTally>();
  server.set_request_observer([tally](const ua::Structure& request) { tally->observe(request); });

  // A small publishing interval so the server's keep-alive cadence (10x the interval) drives a steady Publish
  // stream after the modify - making the "no spurious re-modify" assertion non-vacuous.
  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = 30.0;
  ASSERT_TRUE(subscription.value().try_modify_sync(config).is_good());
  ASSERT_EQ(tally->modify_subscription_count(), 1u) << "exactly one ModifySubscription for the one modify";

  // Let the Publish pump run on well past the modify: Publishes actively flow, yet no SECOND
  // ModifySubscription may appear (a client re-modifying off an old-interval Publish would emit one).
  const std::size_t publishBaseline = tally->publish_count();
  ASSERT_TRUE(wait_until([&] { return tally->publish_count() >= publishBaseline + 4; }))
    << "Publishes must flow after the modify so the no-retry assertion is not vacuous";

  EXPECT_EQ(tally->modify_subscription_count(), 1u)
    << "an old-interval Publish in the grace window must NOT drive a spurious re-ModifySubscription";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a grace-window Publish must not fault the Connection";
}

// =============================================================================================
// Row - ReplayRecordUpdatedSurvivesRecreate  (MisbehavingServer)  [integration+unit]
// After modifying a Subscription's parameters, a session-CHANGED reconnect that runs the RECREATE path must
// issue its CreateSubscription with the MODIFIED parameters (not the original create parameters). If the
// replay record were not updated on modify, the reconnect would resurrect the pre-modify configuration.
// [neg: recreate must use modified params]
//
// RECONNECT-HARNESS-BLOCKED for the full drop->recreate, but the modify->replay-record link is now BUILT
// (CL-SUB-012): `modify_subscription_async` wraps its completion to `update_publishing_interval_async` on a
// successful modify. This pins the CLIENT-OBSERVABLE analog a recreate would replay - the pipeline's retained
// recovery-descriptor interval - and asserts it now tracks the MODIFIED interval (so a recreate replays the
// modified configuration, not the pre-modify one). Full drop->recreate remains reconnect-harness-blocked.
// =============================================================================================
// @verifies CL-SUB-012
// @relation(CL-SUB-012, scope=function)
TEST_F(ClientSubscriptionModify, ReplayRecordUpdatedSurvivesRecreate)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const double createInterval = 500.0;
  const double modifiedInterval = 250.0;
  auto subscription = fixture.create_subscription(createInterval);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();

  // The retained replay record (what a recreate replays) starts at the requested create interval.
  ASSERT_EQ(fixture.retained_interval(subscriptionId), std::optional<double>{createInterval})
    << "the pipeline retains the requested create interval as the replay record";

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = modifiedInterval;
  ASSERT_TRUE(subscription.value().try_modify_sync(config).is_good());

  // BUILT (CL-SUB-012): the replay record now tracks the modify - a recreate replays the MODIFIED interval,
  // not the pre-modify one. The update is an async pipeline post, so poll.
  EXPECT_TRUE(wait_until(
    [&] { return fixture.retained_interval(subscriptionId) == std::optional<double>{modifiedInterval}; }))
    << "a successful modify must update the pipeline replay record so a recreate replays the modified "
       "interval";
}

// =============================================================================================
// Row - ReplaySurvivesTransferFailureThenRecreate  (MisbehavingServer)
// After a modify, a reconnect using the default TransferThenRecreate policy where the Transfer is made to
// fail and recreate is invoked must recreate with the MODIFIED parameters. If replay only updated on the
// transfer path, the recreate fallback would lose the modify. [neg: transfer-fail then recreate path]
//
// RECONNECT-HARNESS-BLOCKED for the full drop+transfer-fail+recreate (none available here), but rests on the
// now-BUILT modify->replay-record link (CL-SUB-012). Pinned to a DISTINCT observable: the full recovery
// descriptor (interval + its monitored items) a transfer-fail recreate fallback would consume - the
// subscription survives as a recovery candidate WITH its monitored item AND carries the MODIFIED interval.
// =============================================================================================
// @verifies CL-SUB-012
// @relation(CL-SUB-012, scope=function)
TEST_F(ClientSubscriptionModify, ReplaySurvivesTransferFailureThenRecreate)
{
  MisbehavingServer server;
  MisbehavingModifyFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const double createInterval = 500.0;
  const double modifiedInterval = 250.0;
  auto subscription = fixture.create_subscription(createInterval);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();

  // A monitored item so the recovery descriptor a recreate would replay is non-trivial.
  MonitorRequest monitorRequest;
  monitorRequest.nodeId = ua::NodeId{ua::VariableId::Server_ServerStatus_State};
  const auto item = subscription.value().try_monitor_sync(monitorRequest, [](DataChangeEvent) {});
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.retained_item_count(subscriptionId) >= 1; }))
    << "the created monitored item must be registered in the recovery descriptor";

  SubscriptionModifyConfig config;
  config.publishingIntervalMs = modifiedInterval;
  ASSERT_TRUE(subscription.value().try_modify_sync(config).is_good());

  // The subscription survives as a recovery candidate WITH its monitored item (a transfer-fail recreate would
  // recreate both) ...
  EXPECT_GE(fixture.retained_item_count(subscriptionId), 1u)
    << "the modified subscription survives in the recovery descriptor with its monitored item";
  // ... AND (CL-SUB-012) the recreate fallback now replays the MODIFIED interval - the modify updated the
  // replay record. Async pipeline update, so poll.
  EXPECT_TRUE(wait_until(
    [&] { return fixture.retained_interval(subscriptionId) == std::optional<double>{modifiedInterval}; }))
    << "a transfer-fail recreate fallback must replay the modified interval (modify updated the replay "
       "record)";
}
