// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_INTEGRATION_HELPERS_SUBSCRIPTION_H
#define UA_INTEGRATION_HELPERS_SUBSCRIPTION_H

#include "sanitizer_budget.h"

#include "ua_attribute_id.h"
#include "ua_client_session.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_subscription_request.h"
#include "ua_data_change_notification.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_data_value.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_notification_list.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_node_id.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_status_change_notification.h"
#include "ua_variant.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua::test_helpers
{

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// SubscriptionOptions - POD struct, designated-init friendly.
//
//   create_subscription(*mSession, {.keepAliveCount = 1});
//
// Defaults match the historical file-static `make_subscription_request` in
// the compliance_subscription/monitored_item/event/transfer test files.
// ---------------------------------------------------------------------------
struct SubscriptionOptions
{
  double publishingInterval = 100.0;
  // Scaled, unlike the interval beside it. The interval sets the publish CADENCE, which tests
  // observe and time against, so it stays put; the lifetime count sets how long a Subscription
  // survives with nothing arriving, which is pure budget. An instrumented build can spend longer
  // than an unscaled 3 seconds getting from "create" to whatever the test does next, and the
  // Subscription is gone by then - a timing artefact wearing BadSubscriptionIdInvalid's clothes.
  // A test whose SUBJECT is expiry states its own lifetime rather than relying on this default.
  uint32_t lifetimeCount = 30U * static_cast<uint32_t>(ua::test_utils::sanitizer_slowdown());
  uint32_t keepAliveCount = 10;
  uint32_t maxNotificationsPerPublish = 0;  // 0 = no limit
  bool publishingEnabled = true;
  uint8_t priority = 0;
};

// ---------------------------------------------------------------------------
// MonitoringOptions - POD struct for a single data-change monitored item.
//
// Filter-bearing monitored items (events, conditions) use
// `create_event_monitored_item(...)` instead and pass an EventFilter
// directly; bloating this struct with a `filter` field would conflate the
// two and force every call site to acknowledge a field most don't care
// about. Keep it data-change only.
// ---------------------------------------------------------------------------
struct MonitoringOptions
{
  ua::AttributeId attribute = ua::AttributeId::Value;
  uint32_t clientHandle = 1;
  ua::MonitoringMode mode = ua::MonitoringMode::Reporting;
  double samplingInterval = 100.0;
  uint32_t queueSize = 1;
  bool discardOldest = true;
};

struct SubscriptionWithMonitoredItem
{
  uint32_t subscriptionId = 0;
  uint32_t monitoredItemId = 0;
};

// ---------------------------------------------------------------------------
// Creation verbs
//
//   uint32_t subId = create_subscription(*mSession);
//   auto [subId, miId] = create_subscription_with_monitored_item(*mSession, nodeId);
//   uint32_t miId = create_event_monitored_item(*mSession, subId, eventSourceId, filter);
//
// All three assert on the service result with non-fatal EXPECT_*; tests that
// want to inspect a failing service-result themselves (compliance negative
// paths) should call `*_sync` directly rather than these verbs.
// ---------------------------------------------------------------------------

uint32_t create_subscription(ua::client::Session& session, SubscriptionOptions options = {});

SubscriptionWithMonitoredItem create_subscription_with_monitored_item(ua::client::Session& session,
  const ua::NodeId& node, SubscriptionOptions subOptions = {}, MonitoringOptions miOptions = {});

uint32_t create_event_monitored_item(ua::client::Session& session, uint32_t subscriptionId,
  const ua::NodeId& eventSourceNode, ua::EventFilter filter, MonitoringOptions miOptions = {});

// ---------------------------------------------------------------------------
// Raw request builders - for tests that need to call the service directly to
// inspect the response (e.g. `revised_lifetime_count`, per-MI status codes).
// The helper verbs above assert success and discard most of the response; use
// these when the response itself is the unit under test.
//
//   auto resp = session.subscriptions().create_subscription_sync(
//                  build_subscription_request({.lifetimeCount = 3}));
//   EXPECT_GE(resp.revised_lifetime_count(), 3 * resp.revised_max_keep_alive_count());
//
//   auto miResp = session.monitored_items().create_monitored_items_sync(
//                    build_create_mi_request(subId, node, {.queueSize = 10}));
//   EXPECT_TRUE(miResp.results()[0].status_code().is_good());
//
// Both consume the same `SubscriptionOptions` / `MonitoringOptions` structs
// the verb helpers use, so default values stay in sync.
// ---------------------------------------------------------------------------

ua::CreateSubscriptionRequest build_subscription_request(SubscriptionOptions opts = {});

ua::CreateMonitoredItemsRequest build_create_mi_request(
  uint32_t subscriptionId, const ua::NodeId& nodeId, MonitoringOptions opts = {});

// Filter-bearing overload - for tests that attach an EventFilter (or any
// other MonitoringFilter subtype) to a monitored item and need to inspect
// the response. Same shape as the non-filter version but takes a
// `unique_ptr<Structure>` for the filter (move it via
// `std::make_unique<EventFilter>(std::move(filter))`).
//
// `opts.attribute` is NOT forced to EventNotifier here - the caller is
// responsible. For the common event-MI case, pass `{.attribute =
// AttributeId::EventNotifier, .samplingInterval = 0.0, .queueSize = ...}`.
//
// For the SIMPLER "attach an event MI, don't inspect the response" case,
// use `create_event_monitored_item(...)` above instead.
ua::CreateMonitoredItemsRequest build_create_mi_request(uint32_t subscriptionId, const ua::NodeId& nodeId,
  std::unique_ptr<ua::Structure> filter, MonitoringOptions opts = {});

// ---------------------------------------------------------------------------
// Lifecycle convenience
//
//   acknowledge(*mSession, subId, seqNumber);
//   set_publishing_mode(*mSession, subId, /*enabled=*/false);
//   drain_initial_publish(*mSession, subId);
//
// All three assert success. SetPublishingMode-with-bad-input tests should call
// the service directly.
//
// `drain_initial_publish` exists to consume the initial value DataChange that
// `create_subscription_with_monitored_item` triggers, so tests that want to
// assert against a fresh stimulus aren't tripped by the initial-value notif.
// It is a thin wrapper over `wait_for_data_change(...)` whose result is
// discarded. Returns silently if no DataChange arrives within `timeout` -
// the helper does NOT fail the test if there is nothing to drain.
// ---------------------------------------------------------------------------

void acknowledge(ua::client::Session& session, uint32_t subscriptionId, uint32_t sequenceNumber);

void set_publishing_mode(ua::client::Session& session, uint32_t subscriptionId, bool enabled);

void drain_initial_publish(ua::client::Session& session, uint32_t subscriptionId,
  std::chrono::milliseconds timeout = std::chrono::milliseconds{500});

// ---------------------------------------------------------------------------
// delete_subscription - fire-and-forget tear-down.
//
// Issues `DeleteSubscriptions` for the single `subId` and discards the
// response. Uses `try_*_sync` so a teardown race (server already closed the
// channel, BadSessionIdInvalid, etc.) does NOT fail the test - fixture
// `TearDown()` blocks are the dominant caller and they must be tolerant.
//
//   delete_subscription(*mSession, subId);
// ---------------------------------------------------------------------------

void delete_subscription(ua::client::Session& session, uint32_t subscriptionId);

// ---------------------------------------------------------------------------
// try_publish_once - send ONE publish and return the response.
//
// Returns nullopt when either (a) the transport call failed, or (b) the
// response carried a bad service result. Does NOT poll. Use this when you
// want the raw `PublishResponse` (sequence numbers, available_sequence_numbers,
// keep-alive `notification_data().empty()` checks) after a known-quiescent
// stimulus - `wait_for_publish` is the polling variant for "wait until
// something matches".
//
// Equivalent to the file-local `try_publish` helpers that lived in
// compliance_subscription / compliance_event / transfer_subscriptions during
// the migration; promoted here so the next file doesn't paste it a fourth
// time.
// ---------------------------------------------------------------------------

std::optional<ua::PublishResponse> try_publish_once(
  ua::client::Session& session, ua::PublishRequest request = {});

// ---------------------------------------------------------------------------
// Extractors - return non-owning pointer to the first matching NotificationData
// inside a PublishResponse. Returns nullptr when not present. Same as the
// file-static `find_*_notification` helpers being replaced.
//
// **`as_data_change` does NOT filter empty `monitored_items()`.** A
// DataChangeNotification with zero entries is returned as-is. Tests that
// want to assert "received a notification carrying values for our MI"
// should pair this with a `!dc.monitored_items().empty()` predicate or
// inspect the result accordingly. This matters for negative-path tests
// like XFER `SendInitialValues=False`, where the server may legally emit
// an empty DCN that should NOT be treated as a regression.
// ---------------------------------------------------------------------------

const ua::DataChangeNotification* as_data_change(const ua::PublishResponse& resp);
const ua::StatusChangeNotification* as_status_change(const ua::PublishResponse& resp);
const ua::EventNotificationList* as_event_notification(const ua::PublishResponse& resp);

// ---------------------------------------------------------------------------
// wait_for_publish - primitive polling loop.
//
// Sends Publish requests via `try_publish_sync` every `pollInterval` until
// the predicate accepts a successful response or `timeout` elapses. Returns
// the matching PublishResponse on success; std::nullopt on timeout.
//
// Threading: synchronous, runs on the caller's thread. The poll loop sleeps
// between Publish attempts; there is no io_context or deadline timer.
//
// ## Semantics
//
// - **No assertions, no ADD_FAILURE.** A timeout returns nullopt - the
//   caller decides whether absence is a failure (positive paths:
//   `ASSERT_TRUE(notif)`) or the assertion (negative paths:
//   `EXPECT_FALSE(notif)`).
// - **No automatic acknowledgement.** The helper does not consume
//   `available_sequence_numbers`. Tests that need to ack should call
//   `acknowledge(...)` between waits.
// - **Bad service-result responses are skipped, not returned.** A
//   `BadNoSubscription` from a teardown race counts as "no response yet".
// - **Predicate is move-only friendly.** Templated, passed by forwarding
//   reference. Predicate is not required to be copyable.
// ---------------------------------------------------------------------------

template<typename Predicate>
std::optional<ua::PublishResponse> wait_for_publish(ua::client::Session& session, Predicate&& predicate,
  std::chrono::milliseconds timeout = 2s, std::chrono::milliseconds pollInterval = 50ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  do
  {
    auto result = session.subscriptions().try_publish_sync(ua::PublishRequest{});
    if (result.is_good() && result.value().response_header().service_result().is_good())
    {
      if (predicate(result.value()))
      {
        return std::move(result.value());
      }
    }
    if (std::chrono::steady_clock::now() >= deadline)
    {
      return std::nullopt;
    }
    std::this_thread::sleep_for(pollInterval);
  }
  while (std::chrono::steady_clock::now() < deadline);
  return std::nullopt;
}

namespace subscription_detail
{

struct AlwaysTrue
{
  template<typename T>
  bool operator()(const T&) const noexcept
  {
    return true;
  }
};

}  // namespace subscription_detail

// ---------------------------------------------------------------------------
// wait_for_data_change - wait until a DataChangeNotification for `subId`
// arrives that satisfies the (optional) predicate, or timeout. The default
// predicate matches any DataChangeNotification.
//
//   auto notif = wait_for_data_change(*mSession, subId);
//   ASSERT_TRUE(notif);  // or EXPECT_FALSE(notif) on negative paths
//
//   auto notif = wait_for_data_change(*mSession, subId, [](const auto& dc) {
//     return std::any_of(dc.monitored_items().begin(), dc.monitored_items().end(),
//       [](const auto& mi) { return mi.client_handle() == 7u; });
//   });
//
// Returns by value (DataChangeNotification is copy-constructible). The
// underlying PublishResponse is consumed by the helper.
// ---------------------------------------------------------------------------

template<typename Predicate = subscription_detail::AlwaysTrue>
  requires std::is_invocable_r_v<bool, Predicate, const ua::DataChangeNotification&>
std::optional<ua::DataChangeNotification> wait_for_data_change(ua::client::Session& session,
  uint32_t subscriptionId, Predicate predicate = {}, std::chrono::milliseconds timeout = 2s)
{
  auto pubMatch = [subscriptionId, &predicate](const ua::PublishResponse& resp) -> bool
  {
    if (resp.subscription_id() != subscriptionId)
    {
      return false;
    }
    const auto* dc = as_data_change(resp);
    return dc != nullptr && predicate(*dc);
  };

  auto resp = wait_for_publish(session, pubMatch, timeout);
  if (!resp)
  {
    return std::nullopt;
  }
  const auto* dc = as_data_change(*resp);
  if (dc == nullptr)
  {
    return std::nullopt;
  }
  return *dc;
}

// Timeout-only overload - equivalent to `wait_for_data_change(s, sub, AlwaysTrue{}, timeout)`.
// Keeps negative-path call sites readable (`EXPECT_FALSE(wait_for_data_change(s, sub, 500ms))`).
std::optional<ua::DataChangeNotification> wait_for_data_change(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout);

// ---------------------------------------------------------------------------
// wait_for_data_change_with_ack - like `wait_for_data_change`, but the FIRST
// Publish round-trip carries a `SubscriptionAcknowledgement` for `ackSequenceNumber`.
//
// Use this when the test pattern is "drain initial publish -> stimulus -> expect
// notification on next publish": the next publish needs to acknowledge the
// drained sequence number, and the server typically attaches the post-stimulus
// notification to that ack-bearing response. A plain
// `acknowledge(...) + wait_for_data_change(...)` shape DROPS that response and
// then finds nothing on the next poll, causing spurious test failures.
//
//   auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
//   write_value_async(*mSession, node, ...);
//   auto notif = wait_for_data_change_with_ack(*mSession, subId,
//     resp0.notification_message().sequence_number(), predicate, 2s);
//   ASSERT_TRUE(notif);
//
// After the first ack-bearing publish, the implementation falls through to
// `wait_for_data_change` for the remaining timeout (so a server that delivers
// the notification a few ms late is still tolerated).
// ---------------------------------------------------------------------------

template<typename Predicate = subscription_detail::AlwaysTrue>
  requires std::is_invocable_r_v<bool, Predicate, const ua::DataChangeNotification&>
std::optional<ua::DataChangeNotification> wait_for_data_change_with_ack(ua::client::Session& session,
  uint32_t subscriptionId, uint32_t ackSequenceNumber, Predicate predicate = {},
  std::chrono::milliseconds timeout = 2s)
{
  ua::PublishRequest req;
  ua::SubscriptionAcknowledgement ack;
  ack.subscription_id() = subscriptionId;
  ack.sequence_number() = ackSequenceNumber;
  req.subscription_acknowledgements().push_back(std::move(ack));

  const auto startedAt = std::chrono::steady_clock::now();
  auto first = session.subscriptions().try_publish_sync(std::move(req));
  if (first.is_good() && first.value().response_header().service_result().is_good() &&
      first.value().subscription_id() == subscriptionId)
  {
    const auto* dc = as_data_change(first.value());
    if (dc != nullptr && predicate(*dc))
    {
      return *dc;
    }
  }

  const auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt);
  const auto remaining = timeout > elapsed ? timeout - elapsed : std::chrono::milliseconds{0};
  return wait_for_data_change(session, subscriptionId, predicate, remaining);
}

// ---------------------------------------------------------------------------
// wait_for_event - single-shot: return the first EventFieldList from `subId`
// that satisfies the predicate, or std::nullopt on timeout.
//
//   auto efl = wait_for_event(*mSession, subId);
//   ASSERT_TRUE(efl);
//   EXPECT_THAT(*efl, EventFieldWith(/*index=*/0, IsTrue()));
//
// For "collect every event from this poll window" use `collect_events`.
// ---------------------------------------------------------------------------

template<typename Predicate = subscription_detail::AlwaysTrue>
  requires std::is_invocable_r_v<bool, Predicate, const ua::EventFieldList&>
std::optional<ua::EventFieldList> wait_for_event(ua::client::Session& session, uint32_t subscriptionId,
  Predicate predicate = {}, std::chrono::milliseconds timeout = 2s)
{
  auto pubMatch = [subscriptionId, &predicate](const ua::PublishResponse& resp) -> bool
  {
    if (resp.subscription_id() != subscriptionId)
    {
      return false;
    }
    const auto* enl = as_event_notification(resp);
    if (enl == nullptr)
    {
      return false;
    }
    for (const auto& efl : enl->events())
    {
      if (predicate(efl))
      {
        return true;
      }
    }
    return false;
  };

  auto resp = wait_for_publish(session, pubMatch, timeout);
  if (!resp)
  {
    return std::nullopt;
  }
  const auto* enl = as_event_notification(*resp);
  if (enl == nullptr)
  {
    return std::nullopt;
  }
  for (const auto& efl : enl->events())
  {
    if (predicate(efl))
    {
      return efl;
    }
  }
  return std::nullopt;
}

// Timeout-only overload - equivalent to `wait_for_event(s, sub, AlwaysTrue{}, timeout)`.
std::optional<ua::EventFieldList> wait_for_event(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout);

// ---------------------------------------------------------------------------
// wait_for_status_change - wait for the first StatusChangeNotification for
// `subId` that satisfies the predicate.
//
//   auto sc = wait_for_status_change(*mSession, subId);
//   ASSERT_TRUE(sc);
//   EXPECT_EQ(sc->status(), StatusCode{Status::GoodSubscriptionTransferred});
//
// **Polling shape - read this.** This helper polls AFTER you call it.
// Patterns where the SCN arrives on a Publish that was queued BEFORE the
// triggering event (the classic XFER `StatusChangeNotification` test queues
// a publish on session A before TransferSubscriptions fires, expecting the
// SCN to be delivered to that pre-queued response) cannot use this helper -
// poll-after-event has nothing to find because the response was already
// dispatched to the queued slot. For those patterns, use `publish_async +
// std::promise + as_status_change` directly.
// ---------------------------------------------------------------------------

template<typename Predicate = subscription_detail::AlwaysTrue>
  requires std::is_invocable_r_v<bool, Predicate, const ua::StatusChangeNotification&>
std::optional<ua::StatusChangeNotification> wait_for_status_change(ua::client::Session& session,
  uint32_t subscriptionId, Predicate predicate = {}, std::chrono::milliseconds timeout = 2s)
{
  auto pubMatch = [subscriptionId, &predicate](const ua::PublishResponse& resp) -> bool
  {
    if (resp.subscription_id() != subscriptionId)
    {
      return false;
    }
    const auto* sc = as_status_change(resp);
    return sc != nullptr && predicate(*sc);
  };

  auto resp = wait_for_publish(session, pubMatch, timeout);
  if (!resp)
  {
    return std::nullopt;
  }
  const auto* sc = as_status_change(*resp);
  if (sc == nullptr)
  {
    return std::nullopt;
  }
  return *sc;
}

// Timeout-only overload.
std::optional<ua::StatusChangeNotification> wait_for_status_change(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout);

// ---------------------------------------------------------------------------
// collect_events - drain events across one or more Publish responses.
//
// Polls until at least `minCount` events have been collected or `timeout`
// elapses. Returns whatever was collected (may be fewer than minCount on
// timeout - caller asserts).
//
// Replaces the EventQueueOverflow-style loops that publish-and-accumulate
// until they have all the queued events.
// ---------------------------------------------------------------------------

struct CollectEventsOptions
{
  std::size_t minCount = 1;
  std::chrono::milliseconds timeout = 2s;
  std::chrono::milliseconds pollInterval = 50ms;
};

std::vector<ua::EventFieldList> collect_events(
  ua::client::Session& session, uint32_t subscriptionId, CollectEventsOptions options = {});

// ===========================================================================
// Matchers
// ===========================================================================

// ---------------------------------------------------------------------------
// MonitoredItemNotificationWith(clientHandle, valueMatcher)
//
// Element-level matcher over a single MonitoredItemNotification.
//
//   EXPECT_THAT(mi_notif, MonitoredItemNotificationWith(1, good_value_of<int32_t>(42)));
//
// `valueMatcher` is matched against the entry's `DataValue` field, so the
// existing good_value_of<T> / good_value_that<T> / HasStatus matchers all apply.
//
// **Composition note.** `ua::Array<T>` does not expose the `value_type`
// typedef that gmock's `Contains`/`ElementsAre` require. To assert "this
// DataChangeNotification carries an entry with handle H and value V", use
// `ContainsDataChangeFor(H, V)` (below) which iterates the array manually.
// `MonitoredItemNotificationWith` itself is still useful for asserting on a
// single MI extracted by hand.
// ---------------------------------------------------------------------------

MATCHER_P2(MonitoredItemNotificationWith, clientHandle, valueMatcher,
  std::string(negation ? "is not " : "is ") +
    "a MonitoredItemNotification for client_handle=" + ::testing::PrintToString(clientHandle) +
    " whose value " + ::testing::DescribeMatcher<ua::DataValue>(valueMatcher, negation))
{
  if (arg.client_handle() != static_cast<uint32_t>(clientHandle))
  {
    *result_listener << "client_handle = " << arg.client_handle();
    return false;
  }
  const auto inner = ::testing::SafeMatcherCast<const ua::DataValue&>(valueMatcher);
  return inner.MatchAndExplain(arg.value(), result_listener);
}

// ---------------------------------------------------------------------------
// ContainsDataChangeFor(clientHandle, valueMatcher)
//
// Asserts that a DataChangeNotification has at least one entry with the given
// client_handle whose DataValue matches `valueMatcher`:
//
//   EXPECT_THAT(*notif, ContainsDataChangeFor(1, good_value_of<int32_t>(42)));
//
// Equivalent to the element-level matcher composed with gmock's `Contains`,
// but works around `ua::Array<T>`'s missing container traits. Use this for
// "the notification carried what I expected" assertions; use
// `MonitoredItemNotificationWith` when you've already isolated a single entry.
// ---------------------------------------------------------------------------

MATCHER_P2(ContainsDataChangeFor, clientHandle, valueMatcher,
  std::string(negation ? "does not contain " : "contains ") +
    "a MonitoredItemNotification for client_handle=" + ::testing::PrintToString(clientHandle) +
    " whose value " + ::testing::DescribeMatcher<ua::DataValue>(valueMatcher, negation))
{
  const auto inner = ::testing::SafeMatcherCast<const ua::DataValue&>(valueMatcher);
  const auto expected = static_cast<uint32_t>(clientHandle);
  for (const auto& mi : arg.monitored_items())
  {
    if (mi.client_handle() == expected && inner.Matches(mi.value()))
    {
      return true;
    }
  }
  *result_listener << "monitored_items().size() = " << arg.monitored_items().size();
  return false;
}

// ---------------------------------------------------------------------------
// EventFieldWith(fieldIndex, valueMatcher)
//
// Element-level matcher over a single EventFieldList. Matches the Variant
// at `fieldIndex` against `valueMatcher` (which can use GMock's typed
// matchers, or `Eq(ua::Variant{...})`).
//
//   EXPECT_THAT(*efl, EventFieldWith(/*EventType=*/1,
//                       ::testing::Eq(ua::Variant{NodeId{ObjectTypeId::BaseEventType}})));
//
// Out-of-range index produces an explanatory failure rather than a crash.
// ---------------------------------------------------------------------------

MATCHER_P2(EventFieldWith, fieldIndex, valueMatcher,
  std::string(negation ? "is not " : "is ") + "an EventFieldList whose field[" +
    ::testing::PrintToString(fieldIndex) + "] " +
    ::testing::DescribeMatcher<ua::Variant>(valueMatcher, negation))
{
  const std::size_t index = static_cast<std::size_t>(fieldIndex);
  if (index >= arg.event_fields().size())
  {
    *result_listener << "event_fields().size() = " << arg.event_fields().size() << " (index " << index
                     << " out of range)";
    return false;
  }
  const auto inner = ::testing::SafeMatcherCast<const ua::Variant&>(valueMatcher);
  return inner.MatchAndExplain(arg.event_fields()[index], result_listener);
}

// ---------------------------------------------------------------------------
// NotificationPresent() - diagnostic matcher for the `optional<...>` returned
// by `wait_for_*`. Equivalent to `::testing::Optional(_)` but prints a
// helper-specific message that reads better in failure output:
//
//   EXPECT_THAT(wait_for_data_change(*mSession, subId), NotificationPresent());
//
// On failure: "expected a notification, got std::nullopt (timeout)".
//
// This is the reviewer's compromise for tests that want richer failure text
// than a bare ASSERT_TRUE(opt) provides while keeping `wait_for_data_change`
// free of any ADD_FAILURE side effect.
// ---------------------------------------------------------------------------

MATCHER(NotificationPresent,
  std::string(negation ? "is std::nullopt (timeout)" : "is a notification (not timeout)"))
{
  if (!arg.has_value())
  {
    *result_listener << "got std::nullopt (timeout)";
    return false;
  }
  return true;
}

}  // namespace ua::test_helpers

#endif  // UA_INTEGRATION_HELPERS_SUBSCRIPTION_H
