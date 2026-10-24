// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A Subscription gives back every monitoring handle a namespace issued to it, exactly once: when it closes,
// when it is destroyed, when DeleteMonitoredItems deletes the items, and when a create does not take an
// answer (NR-4 release rule 1, NR-42 A-3, finding NRF-1; delivery decision DL-13). CreateMonitoredItems calls
// the namespaces concurrently (NR-23 rule 1), and a namespace's short or throwing answer fails only what it
// should.
//
// The Subscription is driven through its asynchronous entries, as the pipeline drives it. The namespaces keep
// the default namespace's real Nodes, so the Subscription looks them up, authorizes and reads them as it does
// in production, but answer the monitoring calls themselves (MonitoringRecordingNamespace): they record every
// handle they issue and every delete_monitoring call, and the test scripts how they answer. A create or
// delete is ended before its namespace answers the way production ends it, by the Subscription going away.

#include <gtest/gtest.h>

#include "monitoring_release_fixture.h"

#include "ua_error_detail.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_status_to_string.h"
#include "ua_subscription_router.h"
#include "ua_to_string.h"

#include <algorithm>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ua::test::monitoring_release;

namespace
{

class CreateMonitoredItemsConcurrency : public MonitoringRelease
{};

class MonitoringCreate : public MonitoringRelease
{};

class MonitoringModify : public MonitoringRelease
{
protected:
  /// Modifies the items @p ids of @p subscription to @p samplingInterval in one request, as
  /// ModifyMonitoredItems does, and returns the results.
  std::vector<MonitoredItemModifyResult> modify(
    Subscription& subscription, const std::vector<IntegerId>& ids, Duration samplingInterval)
  {
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    uint32_t clientHandle = 1;
    for (const auto id : ids)
    {
      MonitoredItemModifyRequest item;
      item.monitored_item_id() = id;
      item.requested_parameters().client_handle() = clientHandle++;
      item.requested_parameters().sampling_interval() = samplingInterval;
      item.requested_parameters().queue_size() = 1;
      item.requested_parameters().discard_oldest() = true;
      request.items_to_modify().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemModifyResult>>>();
    auto future = promise->get_future();
    subscription.modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [promise](std::vector<MonitoredItemModifyResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the modify did not answer";
      return {};
    }
    return future.get();
  }

  /// The sampling interval of the item @p id of @p subscription; -1 when there is no such item.
  static Duration sampling_interval(Subscription& subscription, IntegerId id)
  {
    return STA::on_strand(subscription,
      [id](auto& guard)
      {
        const auto& items = guard.monitored_items();
        const auto found = items.find(id);
        return found == items.end() ? Duration{-1} : found->second->samplingInterval;
      });
  }
};

/// An Uncertain status without a result, as a namespace answers an item it can say nothing about.
StatusCode uncertain_without_result()
{
  return StatusCode{Status::Uncertain,
    ErrorDetail::build(
      "NoMonitoringResult", "The test namespace has no result for this item", "TestNamespace")};
}

/// Whether @p status carries the ErrorDetail a refused Uncertain answer gets: code
/// MonitoringAnswerWithoutResult, inner status Uncertain, cause NoMonitoringResult. Describes what it found
/// in @p found.
bool is_refused_uncertain_answer(const StatusCode& status, std::string& found)
{
  const auto& detail = status.shared_detail();
  if (!detail)
  {
    found = "no ErrorDetail";
    return false;
  }
  found = "code " + detail->code + ", inner status " + to_string(StatusCode{detail->innerStatus}) +
          ", cause " + (detail->cause ? detail->cause->code : std::string{"absent"});
  return detail->code == "MonitoringAnswerWithoutResult" &&
         detail->innerStatus == StatusCode{Status::Uncertain}.value() && detail->cause &&
         detail->cause->code == "NoMonitoringResult";
}

}  // namespace

// @relation(AC-SVR-SUB-GEN-124-DELETE-RELEASES-EVERY-NAMESPACES-MONITORING, scope=function)
TEST_F(MonitoringRelease, CloseReleasesEveryRemainingItemsHandles)
{
  auto subscription = make_subscription();
  create_good(*subscription, {NodeId{2, 1u}, NodeId{2, 2u}, NodeId{3, 1u}});
  ASSERT_EQ(mNs2->issued_handles().size(), 2u);
  ASSERT_EQ(mNs3->issued_handles().size(), 1u);

  close(*subscription);

  for (const auto& [ns, index] : {std::pair{mNs2, 2}, std::pair{mNs3, 3}})
  {
    EXPECT_TRUE(wait_until([&ns] { return sorted(ns->released_handles()) == sorted(ns->issued_handles()); }))
      << "namespace " << index << " issued " << text(ns->issued_handles()) << " and was asked to release "
      << text(ns->released_handles());
    EXPECT_EQ(ns->delete_calls().size(), 1u) << "namespace " << index << " was not called once";
  }
  destroy(subscription);
  EXPECT_EQ(sorted(mNs2->released_handles()), sorted(mNs2->issued_handles())) << "released more than once";
  EXPECT_EQ(sorted(mNs3->released_handles()), sorted(mNs3->issued_handles())) << "released more than once";
}

// A Subscription can be closed after the router of the server that created it has gone: a close a session's
// teardown queued runs once the server is destroyed. The close then reports its MonitoredItems' intervals to
// no router, and reaches nothing the server owned.
// @relation(AC-COMP-SVR-SUBSCRIPTION-SERVER-STATE-01-A-CLOSE-AFTER-THE-ROUTER-HAS-GONE-REACHES-NOTHING, scope=function)
TEST_F(MonitoringRelease, ASubscriptionClosedAfterItsRouterHasGoneDoesNotReachIt)
{
  auto router = std::make_unique<SubscriptionRouter>();
  auto subscription = Subscription::create(
    1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {}, router->weak());
  create_good(*subscription, {NodeId{2, 1u}});
  ASSERT_EQ(router->sampling_intervals_in_use().intervals.size(), 1u)
    << "precondition: the Subscription reported its MonitoredItem's interval to the router";

  router.reset();
  close(*subscription);
  destroy(subscription);
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-DESTRUCTOR-RELEASES, scope=function)
TEST_F(MonitoringRelease, TheDestructorReleasesWhatCloseDidNot)
{
  // S1: destroyed without close().
  auto first = make_subscription();
  create_good(*first, {NodeId{2, 1u}, NodeId{2, 2u}});
  const auto issuedToFirst = mNs2->issued_handles();
  ASSERT_EQ(issuedToFirst.size(), 2u);
  destroy(first);
  EXPECT_TRUE(
    wait_until([this, &issuedToFirst] { return sorted(mNs2->released_handles()) == sorted(issuedToFirst); }))
    << "S1 issued " << text(issuedToFirst)
    << "; released after its destruction: " << text(mNs2->released_handles());

  // S2: the namespace answers create_monitoring at once and the initial Value read is held; close() runs
  // while the read is held, so the create commits its item after close() and only the destructor can release
  // its handle.
  const auto releasedBefore = mNs2->released_handles().size();
  const auto issuedBefore = mNs2->issued_handles().size();
  auto second = make_subscription();
  mNs2->hold_value_reads();
  auto pending = start_create(*second, {value_item(NodeId{2, 3u}, 1)});
  ASSERT_TRUE(wait_until([this] { return mNs2->held_value_reads() == 1u; }))
    << "the create's initial Value read was not held";
  const auto issuedAtTheRead = mNs2->issued_handles();
  const std::vector<MonitoringHandle> issuedToSecond(
    issuedAtTheRead.begin() + static_cast<std::ptrdiff_t>(issuedBefore), issuedAtTheRead.end());
  ASSERT_EQ(issuedToSecond.size(), 1u) << "create_monitoring had not answered when the read was held";
  close(*second);
  mNs2->release_value_reads();
  const auto results = finish(pending);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good)
    << "S2's create did not commit its item: " << to_string(results[0].status_code());
  const auto releasedBeforeDestruction = mNs2->released_handles();
  EXPECT_EQ(std::count(releasedBeforeDestruction.begin() + static_cast<std::ptrdiff_t>(releasedBefore),
              releasedBeforeDestruction.end(),
              issuedToSecond[0]),
    0)
    << "S2's handle was released before S2 was destroyed, so the destructor's release is not what is tested";
  destroy(second);

  EXPECT_TRUE(wait_until(
    [this, releasedBefore, &issuedToSecond]
    {
      const auto released = mNs2->released_handles();
      return sorted(std::vector<MonitoringHandle>(
               released.begin() + static_cast<std::ptrdiff_t>(std::min(releasedBefore, released.size())),
               released.end())) == sorted(issuedToSecond);
    }))
    << "S2 issued " << text(issuedToSecond) << "; released overall: " << text(mNs2->released_handles());
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-DELETE-ITEMS-RELEASES-EVERY-NAMESPACE, scope=function)
TEST_F(MonitoringRelease, DeleteMonitoredItemsReleasesInEveryNamespaceAfterTheRequestEnds)
{
  auto subscription = make_subscription();
  const auto ids = create_good(*subscription, {NodeId{2, 1u}, NodeId{3, 1u}, NodeId{3, 2u}});
  ASSERT_EQ(ids.size(), 3u);
  mNs2->hold_delete_answers();

  auto deleted = start_delete(*subscription, ids);
  ASSERT_TRUE(wait_until([this] { return mNs2->held_delete_answers() == 1u; }))
    << "namespace 2 never received the delete";
  // The request ends while namespace 2's answer is held: the Subscription goes away.
  destroy(subscription);
  EXPECT_EQ(deleted.wait_for(5s), std::future_status::ready) << "the delete request was not ended";

  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs3->released_handles()) == sorted(mNs3->issued_handles()); }))
    << "namespace 3 issued " << text(mNs3->issued_handles()) << " and was asked to release "
    << text(mNs3->released_handles()) << " while namespace 2's answer was held";
  EXPECT_EQ(mNs2->held_delete_answers(), 1u) << "namespace 2's answer is still held";
  EXPECT_EQ(sorted(mNs2->released_handles()), sorted(mNs2->issued_handles()));
  mNs2->release_delete_answers();
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-LATE-AND-UNCOMMITTED-HANDLES-RELEASED, scope=function)
TEST_F(MonitoringRelease, ALateCreateAnswersHandlesAreReleased)
{
  auto subscription = make_subscription();
  mNs2->answer_creates(MonitoringRecordingNamespace::CreateAnswer::Hold);
  auto pending = start_create(*subscription, {value_item(NodeId{2, 1u}, 1), value_item(NodeId{2, 2u}, 2)});
  ASSERT_TRUE(wait_until([this] { return mNs2->held_create_answers() == 1u; }));
  // The create ends before its namespace answers: the Subscription goes away.
  destroy(subscription);
  finish(pending);

  mNs2->release_create_answers();
  const auto issued = mNs2->issued_handles();
  ASSERT_EQ(issued.size(), 2u);
  EXPECT_TRUE(wait_until([this, &issued] { return sorted(mNs2->released_handles()) == sorted(issued); }))
    << "the late answer issued " << text(issued) << "; released: " << text(mNs2->released_handles());
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-LATE-AND-UNCOMMITTED-HANDLES-RELEASED, scope=function)
TEST_F(MonitoringRelease, AHandleForAnItemNotCommittedIsReleased)
{
  auto subscription = make_subscription();
  // The second item asks for a PercentDeadband on a Variable without EURange: the create refuses it after the
  // namespace has answered a handle for it.
  const auto results = create(
    *subscription, {value_item(NodeId{2, 1u}, 1), value_item(NodeId{2, 2u}, 2, percent_deadband(10.0))});
  ASSERT_EQ(results.size(), 2u);
  ASSERT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  ASSERT_EQ(results[1].status_code().as_status(), Status::BadDeadbandFilterInvalid)
    << to_string(results[1].status_code());
  const auto issued = mNs2->issued_handles();
  ASSERT_EQ(issued.size(), 2u) << "precondition: the namespace answered a handle for each item";

  EXPECT_TRUE(wait_until(
    [this, &issued] { return mNs2->released_handles() == std::vector<MonitoringHandle>{issued[1]}; }))
    << "the refused item's handle " << issued[1]
    << " was not released; released: " << text(mNs2->released_handles());
  const auto released = mNs2->released_handles();
  EXPECT_EQ(std::count(released.begin(), released.end(), issued[0]), 0)
    << "the committed item's handle was released";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-TWO-ANSWERS-UNDER-ONE-TICKET, scope=function)
TEST_F(MonitoringRelease, ANamespaceThatAnswersTwiceHasItsSecondAnswerReleased)
{
  auto subscription = make_subscription();
  mNs2->issue_next({11, 12});
  mNs2->answer_creates(MonitoringRecordingNamespace::CreateAnswer::IssueTwice);
  const auto results = create(*subscription, {value_item(NodeId{2, 1u}, 1)});
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());

  EXPECT_TRUE(wait_until([this] { return mNs2->released_handles() == std::vector<MonitoringHandle>{12}; }))
    << "the second answer's handle 12 was not released on arrival; released: "
    << text(mNs2->released_handles());

  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs2->released_handles()) == std::vector<MonitoringHandle>{11, 12}; }))
    << "deleting the Subscription did not release handle 11 (once); released: "
    << text(mNs2->released_handles());
  EXPECT_FALSE(mNs2->deleted_inside_a_create_answer())
    << "delete_monitoring was called from inside the namespace's own create_monitoring";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-A-THROWING-NAMESPACE-FAILS-ONLY-ITS-ITEMS, scope=function)
TEST_F(MonitoringRelease, ANamespaceThatThrowsFailsOnlyItsOwnItems)
{
  auto subscription = make_subscription();
  mNs2->answer_creates(
    MonitoringRecordingNamespace::CreateAnswer::Throw, StatusCode{Status::BadResourceUnavailable});
  const auto results = create(*subscription,
    {value_item(NodeId{2, 1u}, 1), value_item(NodeId{3, 1u}, 2), value_item(NodeId{3, 2u}, 3)});
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  ASSERT_NE(results[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(results[0].status_code().shared_detail()->code, "NamespaceCallThrew");
  EXPECT_EQ(
    results[0].status_code().shared_detail()->innerStatus, StatusCode{Status::BadResourceUnavailable}.value())
    << "the thrown status is not the detail's inner status";
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good) << to_string(results[1].status_code());
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good) << to_string(results[2].status_code());
  EXPECT_TRUE(mNs3->delete_calls().empty()) << "namespace 3's handles were released before the deletion";

  const auto issuedBy3 = mNs3->issued_handles();
  EXPECT_EQ(issuedBy3.size(), 2u) << "namespace 3 was not asked to create its items";
  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this, &issuedBy3] { return sorted(mNs3->released_handles()) == sorted(issuedBy3); }))
    << "namespace 3 issued " << text(issuedBy3) << "; released: " << text(mNs3->released_handles());
  EXPECT_TRUE(mNs2->delete_calls().empty()) << "namespace 2, which issued nothing, was asked to release";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-THROW-AFTER-ANSWER-RELEASES-THE-ANSWER, scope=function)
TEST_F(MonitoringRelease, ANamespaceThatThrowsAfterAnsweringHasThatAnswerReleased)
{
  auto subscription = make_subscription();
  mNs2->issue_next({5, 6});
  mNs2->answer_creates(
    MonitoringRecordingNamespace::CreateAnswer::IssueThenThrow, StatusCode{Status::BadResourceUnavailable});
  const auto results = create(*subscription,
    {value_item(NodeId{2, 1u}, 1), value_item(NodeId{2, 2u}, 2), value_item(NodeId{3, 1u}, 3)});
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  EXPECT_EQ(results[1].status_code().as_status(), Status::BadInternalError)
    << to_string(results[1].status_code());
  ASSERT_NE(results[1].status_code().shared_detail(), nullptr);
  EXPECT_EQ(results[1].status_code().shared_detail()->code, "NamespaceCallThrew");
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good) << to_string(results[2].status_code());

  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs2->released_handles()) == std::vector<MonitoringHandle>{5, 6}; }))
    << "the answer given before the throw was not released; released: " << text(mNs2->released_handles());
  EXPECT_FALSE(mNs2->deleted_inside_a_create_answer()) << "the release ran inside the namespace's own call";
  EXPECT_TRUE(mNs3->delete_calls().empty())
    << "namespace 3's handle was released: " << text(mNs3->released_handles());
  destroy(subscription);
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-RELEASE-FROM-A-CALLBACK-IS-POSTED, scope=function)
TEST_F(MonitoringRelease, AReleaseTriggeredInsideANamespaceCallbackIsPosted)
{
  auto subscription = make_subscription();
  mNs2->answer_creates(MonitoringRecordingNamespace::CreateAnswer::Hold);
  auto pending = start_create(*subscription, {value_item(NodeId{2, 1u}, 1)});
  ASSERT_TRUE(wait_until([this] { return mNs2->held_create_answers() == 1u; }));
  destroy(subscription);
  finish(pending);

  // The namespace answers on this thread, after the create ended.
  mNs2->release_create_answers();
  const auto issued = mNs2->issued_handles();
  EXPECT_TRUE(wait_until([this, &issued] { return sorted(mNs2->released_handles()) == sorted(issued); }))
    << "the late handles " << text(issued)
    << " were not released; released: " << text(mNs2->released_handles());
  EXPECT_FALSE(mNs2->deleted_inside_a_create_answer())
    << "delete_monitoring was entered while the namespace's create_monitoring answer was on the stack";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-03-A-SLOW-NAMESPACE-DOES-NOT-DELAY-ANOTHER, scope=function)
TEST_F(CreateMonitoredItemsConcurrency, ASlowNamespaceDoesNotDelayAnother)
{
  auto subscription = make_subscription();
  mNs2->answer_creates(MonitoringRecordingNamespace::CreateAnswer::Hold);
  auto pending = start_create(*subscription, {value_item(NodeId{2, 1u}, 1), value_item(NodeId{3, 1u}, 2)});
  ASSERT_TRUE(wait_until([this] { return mNs2->held_create_answers() == 1u; }));

  EXPECT_TRUE(wait_until([this] { return mNs3->create_calls() == 1u; }))
    << "namespace 3's create_monitoring was not called while namespace 2's answer was held";
  EXPECT_EQ(mNs2->held_create_answers(), 1u);

  mNs2->release_create_answers();
  finish(pending);
  destroy(subscription);
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-04-A-SHORT-ANSWER-REFUSES-THE-UNCOVERED-ITEMS, scope=function)
TEST_F(MonitoringCreate, AShortAnswerRefusesTheItemsItDoesNotCover)
{
  auto subscription = make_subscription();
  mNs2->issue_next({5, 6});
  mNs2->answer_creates(MonitoringRecordingNamespace::CreateAnswer::OmitLast);
  const auto results = create(*subscription,
    {value_item(NodeId{2, 1u}, 1), value_item(NodeId{2, 2u}, 2), value_item(NodeId{2, 3u}, 3)});
  ASSERT_EQ(results.size(), 3u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::BadInternalError)
      << "item " << i << ": " << to_string(results[i].status_code());
    const auto& detail = results[i].status_code().shared_detail();
    EXPECT_TRUE(detail && detail->code == "NamespaceItemCountMismatch")
      << "item " << i << "'s ErrorDetail is " << (detail ? detail->code : std::string{"absent"});
  }
  EXPECT_EQ(item_count(*subscription), 0u) << "an item was created from an answer of the wrong size";
  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs2->released_handles()) == std::vector<MonitoringHandle>{5, 6}; }))
    << "without the Subscription being deleted, namespace 2 released " << text(mNs2->released_handles())
    << ", not {5, 6}";

  delete_subscription(subscription);
  EXPECT_FALSE(wait_until([this] { return mNs2->released_handles().size() > 2u; }, 200ms))
    << "deleting the Subscription released more: " << text(mNs2->released_handles());
}

// An Uncertain item result holds no value: the Subscription has no handle to monitor, so the row is refused
// with Bad_InternalError and the namespace's answer as its cause. The first item is the control that the
// namespace's other results are still used; the release of 5 alone shows no handle was taken from the
// Uncertain result.
// @relation(AC-COMP-SVR-MONITORING-RELEASE-05-AN-UNCERTAIN-ITEM-RESULT-IS-REFUSED, scope=function)
TEST_F(MonitoringCreate, AnUncertainItemResultRefusesTheItem)
{
  auto subscription = make_subscription();
  mNs2->issue_next({5});
  mNs2->answer_next_create_items({std::nullopt, uncertain_without_result()});
  const auto results = create(*subscription, {value_item(NodeId{2, 1u}, 1), value_item(NodeId{2, 2u}, 2)});
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  EXPECT_EQ(results[1].status_code().as_status(), Status::BadInternalError)
    << to_string(results[1].status_code());
  std::string found;
  EXPECT_TRUE(is_refused_uncertain_answer(results[1].status_code(), found))
    << "the second row's ErrorDetail is " << found;
  EXPECT_EQ(item_count(*subscription), 1u) << "an item was created for the Uncertain result";

  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs2->released_handles()) == std::vector<MonitoringHandle>{5}; }))
    << "deleting the Subscription released " << text(mNs2->released_handles()) << ", not {5}";
}

// At modify an Uncertain item result holds no revised values to apply, so the row is refused with
// Bad_InternalError and the item keeps its sampling interval. The first item is the control that the
// namespace's other results are still applied; the release of 7 and 8 alone shows the modify took no handle.
// @relation(AC-COMP-SVR-MONITORING-RELEASE-05-AN-UNCERTAIN-ITEM-RESULT-IS-REFUSED, scope=function)
TEST_F(MonitoringModify, AnUncertainItemResultRefusesTheItemAndLeavesItUnchanged)
{
  auto subscription = make_subscription();
  mNs2->issue_next({7, 8});
  const auto ids = create_good(*subscription, {NodeId{2, 2u}, NodeId{2, 3u}});
  ASSERT_EQ(ids.size(), 2u);
  const auto intervalBefore = sampling_interval(*subscription, ids[1]);
  ASSERT_NE(intervalBefore, Duration{500}) << "the second item already had the interval the modify asks for";

  mNs2->answer_next_modify_items({std::nullopt, uncertain_without_result()});
  const auto results = modify(*subscription, ids, 500);
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  EXPECT_EQ(sampling_interval(*subscription, ids[0]), Duration{500})
    << "the first item did not take the new sampling interval";
  EXPECT_EQ(results[1].status_code().as_status(), Status::BadInternalError)
    << to_string(results[1].status_code());
  std::string found;
  EXPECT_TRUE(is_refused_uncertain_answer(results[1].status_code(), found))
    << "the second row's ErrorDetail is " << found;
  EXPECT_EQ(sampling_interval(*subscription, ids[1]), intervalBefore)
    << "the second item's sampling interval changed although its namespace answer was Uncertain";

  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this] { return sorted(mNs2->released_handles()) == std::vector<MonitoringHandle>{7, 8}; }))
    << "deleting the Subscription released " << text(mNs2->released_handles()) << ", not {7, 8}";
}
