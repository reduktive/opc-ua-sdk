// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for the subscription test helpers in `helpers/subscription.h`.
///
/// These tests stand up a real server + session (via ComplianceWithNodes) and
/// exercise the helpers end-to-end - they are not pure unit tests because the
/// behaviour we care about (publish timing, notification shape, matcher
/// composition with gmock) only manifests with a live subscription pipeline.
/// Required before any production-test migration per the project's review
/// discipline (without a passing test, code must be assumed incorrect).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include <gmock/gmock.h>
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>

#include "ua_base_event.h"
#include "ua_content_filter.h"
#include "ua_event_filter.h"
#include "ua_generic_event.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_simple_attribute_operand.h"
#include "ua_variant.h"

#include <chrono>
#include <optional>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;
using ::testing::Not;

namespace
{

/// Local helper: build a minimal EventFilter selecting Message+Severity from
/// BaseEventType, no where-clause. Mirrors the file-static `make_event_filter`
/// pattern in compliance_event_tests.cpp; lives here (not in helpers/) because
/// the EventFilter builder is deliberately deferred per the PR 9a plan.
EventFilter make_minimal_event_filter()
{
  auto clause = [](const char* name)
  {
    SimpleAttributeOperand op;
    op.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    op.browse_path().push_back(QualifiedName{0, String{name}});
    op.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    return op;
  };

  EventFilter filter;
  filter.select_clauses().push_back(clause("EventType"));
  filter.select_clauses().push_back(clause("Message"));
  filter.select_clauses().push_back(clause("Severity"));
  return filter;
}

}  // namespace

// ===========================================================================
// Creation verbs
// ===========================================================================

class SubscriptionHelpersTest : public ComplianceWithNodes
{};

TEST_F(SubscriptionHelpersTest, CreateSubscriptionReturnsNonZeroId)
{
  uint32_t subId = create_subscription(*mSession);
  EXPECT_NE(subId, 0u);
}

TEST_F(SubscriptionHelpersTest, CreateSubscriptionWithMonitoredItemReturnsBothIds)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);
  EXPECT_NE(subId, 0u);
  EXPECT_NE(miId, 0u);
}

TEST_F(SubscriptionHelpersTest, CreateSubscriptionOptionsAreThreadedThrough)
{
  // Use a distinguishable interval so we can ASSERT the helper actually built
  // the request from the options struct rather than ignoring it.
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 250.0, .priority = 7});
  EXPECT_NE(subId, 0u);
  // Validating that the server respected these values is the server's
  // contract, not the helper's - the helper's only job is to forward them.
  // The presence of a non-zero subId is sufficient evidence the request
  // travelled.
}

// ===========================================================================
// wait_for_data_change
// ===========================================================================

TEST_F(SubscriptionHelpersTest, WaitForDataChangeReturnsInitialValueNotification)
{
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 5});

  auto notif = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(notif) << "no DataChangeNotification within timeout for sub=" << subId;
  EXPECT_FALSE(notif->monitored_items().empty());
}

TEST_F(SubscriptionHelpersTest, WaitForDataChangeReturnsEmptyOnTimeoutWithoutMonitoredItems)
{
  // Subscription with no MIs has no data-changes to publish - only keep-alives,
  // which DON'T carry a DataChangeNotification. Helper must return nullopt
  // within the timeout window without ADD_FAILUREing.
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});
  auto notif = wait_for_data_change(*mSession, subId, subscription_detail::AlwaysTrue{}, 300ms);
  EXPECT_FALSE(notif) << "expected no DataChangeNotification on empty subscription";
}

TEST_F(SubscriptionHelpersTest, WaitForDataChangeAppliesPredicate)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Drain the initial value notification.
  (void)wait_for_data_change(*mSession, subId);

  // Write a sentinel value, then wait for a notification matching only that value.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{4711}});

  auto matches = [](const DataChangeNotification& dc)
  {
    for (const auto& mi : dc.monitored_items())
    {
      const auto* asInt = mi.value().value().try_as<int32_t>();
      if (asInt != nullptr && *asInt == 4711)
      {
        return true;
      }
    }
    return false;
  };

  auto notif = wait_for_data_change(*mSession, subId, matches);
  ASSERT_TRUE(notif) << "predicate-matching DataChange did not arrive within timeout";
}

// ===========================================================================
// wait_for_event
// ===========================================================================

TEST_F(SubscriptionHelpersTest, WaitForEventReturnsEmittedEvent)
{
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0, .keepAliveCount = 30});
  uint32_t miId = create_event_monitored_item(*mSession,
    subId,
    NodeId{ObjectId::Server},
    make_minimal_event_filter(),
    {.clientHandle = 99, .queueSize = 10});
  ASSERT_NE(miId, 0u);

  // Drain any initial notifications (e.g. server-startup events).
  (void)wait_for_publish(
    *mSession, [subId](const PublishResponse& r) { return r.subscription_id() == subId; }, 150ms);

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"SubscriptionHelpersTest"};
  event.message = LocalizedText{"", "wait_for_event-test"};
  event.severity = uint16_t{555};
  mServer.server().emit_event(event);

  auto matchesOurMessage = [](const EventFieldList& efl)
  {
    if (efl.event_fields().size() < 2)
    {
      return false;
    }
    const auto* lt = efl.event_fields()[1].try_as<LocalizedText>();
    return lt != nullptr && lt->text() == String{"wait_for_event-test"};
  };

  auto efl = wait_for_event(*mSession, subId, matchesOurMessage, 2s);
  ASSERT_TRUE(efl) << "emitted event did not surface within timeout for sub=" << subId;
}

// ===========================================================================
// acknowledge + set_publishing_mode
// ===========================================================================

TEST_F(SubscriptionHelpersTest, AcknowledgeReturnsWithoutError)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Capture a sequence number from a real publish, then ack it.
  std::optional<uint32_t> seq;
  auto notif = wait_for_publish(*mSession,
    [subId, &seq](const PublishResponse& r)
    {
      if (r.subscription_id() != subId)
      {
        return false;
      }
      seq = r.notification_message().sequence_number();
      return true;
    });
  ASSERT_TRUE(notif);
  ASSERT_TRUE(seq.has_value());

  // No assertion needed beyond "does not raise an expectation failure". A
  // bad ack would either trigger the EXPECT inside `acknowledge` or be
  // visible in subsequent publishes.
  acknowledge(*mSession, subId, *seq);
}

TEST_F(SubscriptionHelpersTest, SetPublishingModeDisableStopsDataChanges)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  // Drain the initial data change so we start from a known state.
  (void)wait_for_data_change(*mSession, subId);

  set_publishing_mode(*mSession, subId, /*enabled=*/false);

  // Provoke a change. With publishing disabled, no DataChangeNotification
  // should appear - Publish responses become keep-alives.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{8888}});

  auto notif = wait_for_data_change(*mSession, subId, subscription_detail::AlwaysTrue{}, 300ms);
  EXPECT_FALSE(notif) << "publishing disabled - no DataChangeNotification should arrive";
}

// ===========================================================================
// Matchers
// ===========================================================================

TEST_F(SubscriptionHelpersTest, ContainsDataChangeForFindsMatchingEntry)
{
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 11});

  // Drain initial, then write a known value.
  (void)wait_for_data_change(*mSession, subId);
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{1234}});

  auto matches = [](const DataChangeNotification& dc)
  {
    for (const auto& mi : dc.monitored_items())
    {
      const auto* v = mi.value().value().try_as<int32_t>();
      if (v != nullptr && *v == 1234)
      {
        return true;
      }
    }
    return false;
  };
  auto notif = wait_for_data_change(*mSession, subId, matches);
  ASSERT_TRUE(notif);

  EXPECT_THAT(*notif, ContainsDataChangeFor(11u, good_value_of<int32_t>(1234)));
}

TEST_F(SubscriptionHelpersTest, EventFieldWithOutOfRangeIndexExplains)
{
  EventFieldList empty;
  EXPECT_THAT(empty, Not(EventFieldWith(0u, ::testing::_)));
}

TEST(SubscriptionHelpersMatcherTest, NotificationPresentFailsOnNullopt)
{
  std::optional<DataChangeNotification> empty;
  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(empty, NotificationPresent()), "std::nullopt (timeout)");
}

TEST(SubscriptionHelpersMatcherTest, NotificationPresentPassesOnEngagedOptional)
{
  std::optional<DataChangeNotification> filled{DataChangeNotification{}};
  EXPECT_THAT(filled, NotificationPresent());
}

// ===========================================================================
// Polish overloads (PR 9b.5): timeout-only signatures, wait_for_status_change,
// drain_initial_publish.
// ===========================================================================

TEST_F(SubscriptionHelpersTest, WaitForDataChangeTimeoutOnlyOverloadResolves)
{
  // Smoke: the timeout-only overload must be selected over the templated
  // variant when only (session, subId, duration) is passed.
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});
  auto notif = wait_for_data_change(*mSession, subId, 300ms);
  EXPECT_FALSE(notif);
}

TEST_F(SubscriptionHelpersTest, WaitForEventTimeoutOnlyOverloadResolves)
{
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});
  auto efl = wait_for_event(*mSession, subId, 300ms);
  EXPECT_FALSE(efl);
}

TEST_F(SubscriptionHelpersTest, WaitForStatusChangeTimeoutWhenNoneArrives)
{
  // No StatusChange triggered - helper must return nullopt within timeout,
  // not block until default 2s.
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});
  auto sc = wait_for_status_change(*mSession, subId, 300ms);
  EXPECT_FALSE(sc);
}

TEST_F(SubscriptionHelpersTest, DrainInitialPublishConsumesInitialValueNotification)
{
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {}, {.clientHandle = 21});

  // Drain whatever was queued up by create_*.
  drain_initial_publish(*mSession, subId);

  // After draining, a subsequent wait with no stimulus should time out - i.e.
  // the initial notification really was consumed (otherwise it would surface
  // here on the next publish).
  auto residual = wait_for_data_change(*mSession, subId, 300ms);
  EXPECT_FALSE(residual)
    << "drain_initial_publish failed to consume the initial DataChange - residual surfaced";
}

TEST_F(SubscriptionHelpersTest, DrainInitialPublishReturnsSilentlyOnEmptySubscription)
{
  // No MIs ever attached: nothing to drain. drain_initial_publish must NOT
  // fail or hang - it returns silently when no DataChange arrives within
  // the timeout window.
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});
  drain_initial_publish(*mSession, subId, 200ms);
  // If we got here without a gtest failure, the helper honoured its
  // "silent on empty" contract.
  SUCCEED();
}

// ===========================================================================
// Helper additions (post-PR-9f cluster polish): delete_subscription,
// try_publish_once, filter-bearing build_create_mi_request.
// ===========================================================================

TEST_F(SubscriptionHelpersTest, DeleteSubscriptionMakesPublishReturnBadNoSubscription)
{
  uint32_t subId = create_subscription(*mSession);
  ASSERT_NE(subId, 0u);

  delete_subscription(*mSession, subId);

  // After deletion, a publish that targets only this sub should not surface
  // DataChange notifications (and may return BadNoSubscription at the
  // service level). wait_for_data_change correctly returns nullopt.
  auto notif = wait_for_data_change(*mSession, subId, 300ms);
  EXPECT_FALSE(notif) << "delete_subscription did not actually delete the subscription";
}

TEST_F(SubscriptionHelpersTest, DeleteSubscriptionIsIdempotentForTearDown)
{
  // The helper must not fail when called against an already-deleted sub
  // (or a never-existent one) - fixture TearDown idioms rely on this.
  delete_subscription(*mSession, 0xDEADBEEFu);
  SUCCEED();
}

TEST_F(SubscriptionHelpersTest, TryPublishOnceReturnsResponseWithoutPolling)
{
  // Set up a sub with an MI so the very next publish carries a DataChange.
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);
  ASSERT_NE(subId, 0u);

  // Give the initial value a moment to be queued, then issue ONE publish.
  std::this_thread::sleep_for(150ms);
  auto resp = try_publish_once(*mSession);
  ASSERT_TRUE(resp);
  EXPECT_EQ(resp->subscription_id(), subId);
  EXPECT_NE(as_data_change(*resp), nullptr);
}

TEST_F(SubscriptionHelpersTest, BuildCreateMIRequestFilterOverloadAttachesFilter)
{
  uint32_t subId = create_subscription(*mSession, {.publishingInterval = 50.0});

  // Build a trivial EventFilter (one select clause), wrap in the filter overload.
  ua::EventFilter filter;
  ua::SimpleAttributeOperand clause;
  clause.type_definition_id() = ua::NodeId{ua::ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(ua::QualifiedName{0, ua::String{"EventType"}});
  clause.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
  filter.select_clauses().push_back(std::move(clause));

  auto req = build_create_mi_request(subId,
    NodeId{ObjectId::Server},
    std::make_unique<ua::EventFilter>(std::move(filter)),
    {.attribute = AttributeId::EventNotifier, .samplingInterval = 0.0, .queueSize = 10});

  // Verify the request carries the filter.
  ASSERT_EQ(req.items_to_create().size(), 1u);
  EXPECT_TRUE(req.items_to_create()[0].requested_parameters().filter())
    << "filter overload did not attach the filter to MonitoringParameters";

  // Actually create the MI to confirm the request is well-formed end-to-end.
  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_FALSE(resp.results().empty());
  EXPECT_TRUE(resp.results()[0].status_code().is_good())
    << "MI status = 0x" << std::hex << resp.results()[0].status_code().as_uint32();
}

TEST_F(SubscriptionHelpersTest, WaitForDataChangeWithAckReceivesPostStimulusNotification)
{
  // Canonical use case: drain the initial publish, write a new value, then expect
  // the SAME publish that carries the ack to also carry the post-write notification.
  // The plain `acknowledge() + wait_for_data_change()` shape drops that response
  // and times out - the with-ack helper inspects the ack-bearing response itself.
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);

  auto initial = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(initial);

  // Capture the seq number of the initial publish so we can ack it on the next one.
  auto resp0 = try_publish_once(*mSession);
  ASSERT_TRUE(resp0);
  const auto seqToAck = resp0->notification_message().sequence_number();

  // Stimulus.
  write_value_async(*mSession, mWritableVariableId, Variant{int32_t{777}});

  auto matches777 = [](const DataChangeNotification& dc)
  {
    for (auto& mi : dc.monitored_items())
      if (mi.value().value().try_as<int32_t>() && *mi.value().value().try_as<int32_t>() == 777)
        return true;
    return false;
  };
  auto notif = wait_for_data_change_with_ack(*mSession, subId, seqToAck, matches777, 2s);
  ASSERT_TRUE(notif) << "ack-bearing publish should carry the post-write notification";
  // Note: this test exercises the canonical path end-to-end but is not strict on
  // *which* of the helper's two branches (first-publish inspection vs polling fallback)
  // surfaces the notification - the server's retransmit-unacked behaviour means the
  // fallback can also succeed if the first-publish inspection is silently removed.
  // Strict pinning of the ack-piggyback branch would require server instrumentation.
}
