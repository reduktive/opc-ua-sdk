// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The Subscription's entry into the namespaces' batched monitoring members (NR-70 A3): the create, the modify
// and the release reach `create_monitoring_async`, `modify_monitoring_async` and `delete_monitoring_async`,
// and each call passes the route's guards (NR-23 rule 4). The namespaces here override only the batched
// members. The arm that observes the create's caller is in sampled_caller_tests.cpp, because it needs a
// security context that overrides `SessionSecurityContext::caller()`.

#include "monitoring_release_fixture.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

using namespace ua::test::monitoring_release;

namespace
{

using CreateAnswer = BatchedMonitoringNamespace::CreateAnswer;
using ModifyAnswer = BatchedMonitoringNamespace::ModifyAnswer;

}  // namespace

// A's create throws; B's answers. A's item is failed by the route's guard and B's is created: the throw fails
// only the throwing namespace's call. The one answer shows the request is answered once despite the throw.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-THROWING-CREATE-FAILS-ONLY-ITS-ITEMS, scope=function)
TEST_F(MonitoringRoute, AThrowingNamespaceAnswersBadInternalErrorForItsItems)
{
  auto subscription = make_subscription();
  mRouteA->answer_creates(CreateAnswer::Throw);
  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results = create_counted(
    *subscription, {value_item(NodeId{2, 1u}, 1), value_item(NodeId{3, 1u}, 2)}, mSecurityContext, answers);
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "NamespaceCallThrew");
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good) << to_string(results[1].status_code());
  EXPECT_EQ(item_count(*subscription), 1u) << "B's item was not the one item created";
  EXPECT_EQ(mRouteB->create_calls().size(), 1u) << "B's create_monitoring_async was not called once";

  delete_subscription(subscription);
  EXPECT_EQ(answers->load(), 1) << "the create answered more than once";
}

// N's modify throws. The modify answers once, and the item is failed by the route's guard.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-THROWING-MODIFY-FAILS-ITS-ITEMS, scope=function)
TEST_F(MonitoringRoute, AThrowingModifyAnswersBadInternalErrorForItsItems)
{
  auto subscription = make_subscription();
  mRouteA->answer_modifies(ModifyAnswer::Throw);
  const auto ids = create_good(*subscription, {NodeId{2, 1u}});
  ASSERT_EQ(ids.size(), 1u);

  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results = modify_counted(*subscription, ids, 500, answers);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "NamespaceCallThrew");

  delete_subscription(subscription);
  EXPECT_EQ(answers->load(), 1) << "the modify answered more than once";
}

// N completes its one create call twice, with handle 5 and then with handle 9. The first completion answers
// the item; the second is not passed on, and its handle 9 is released at once. Handle 5 belongs to the
// created item, so only deleting the Subscription releases it.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-SECOND-CREATE-COMPLETION-IS-IGNORED-AND-RELEASED, scope=function)
TEST_F(MonitoringRoute, ASecondCreateCompletionIsIgnoredAndItsHandlesAreReleased)
{
  auto subscription = make_subscription();
  mRouteA->issue_next({5, 9});
  mRouteA->answer_creates(CreateAnswer::IssueTwice);
  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results =
    create_counted(*subscription, {value_item(NodeId{2, 1u}, 1)}, mSecurityContext, answers);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  EXPECT_EQ(item_count(*subscription), 1u);

  EXPECT_TRUE(wait_until([this] { return mRouteA->released_handles() == std::vector<MonitoringHandle>{9}; }))
    << "without the Subscription being deleted, N released " << text(mRouteA->released_handles())
    << ", not {9}";
  EXPECT_EQ(mRouteA->released_handles(), std::vector<MonitoringHandle>{9})
    << "handle 5 was released before the Subscription was deleted";

  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this] { return sorted(mRouteA->released_handles()) == std::vector<MonitoringHandle>{5, 9}; }))
    << "after the deletion N had released " << text(mRouteA->released_handles()) << ", not {5, 9}";
  EXPECT_EQ(answers->load(), 1) << "the create answered more than once";
}

// N answers one result for a modify call of two items; M answers its item Good with 825. No N answer can be
// matched to its item, so both of N's items are failed and neither takes 725; M's item, in another call of
// the same request, keeps its answer.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-MODIFY-ANSWER-OF-ANOTHER-SIZE-FAILS-THE-CALLS-ITEMS, scope=function)
TEST_F(MonitoringRoute, AModifyAnswerOfAnotherSizeFailsEveryItemOfTheCall)
{
  auto subscription = make_subscription();
  mRouteA->answer_modifies(ModifyAnswer::OneResult, 725);
  mRouteB->answer_modifies(ModifyAnswer::Revise, 825);
  const auto ids = create_good(*subscription, {NodeId{2, 1u}, NodeId{2, 2u}, NodeId{3, 1u}});
  ASSERT_EQ(ids.size(), 3u);

  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results = modify_counted(*subscription, ids, 500, answers);
  ASSERT_EQ(results.size(), 3u);
  for (std::size_t i = 0; i < 2; ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::BadInternalError)
      << "N's item " << i << ": " << to_string(results[i].status_code());
    EXPECT_EQ(detail_code(results[i].status_code()), "NamespaceItemCountMismatch") << "N's item " << i;
    EXPECT_NE(sampling_interval(*subscription, ids[i]), 725.0)
      << "N's item " << i << " took the revised interval";
  }
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good) << to_string(results[2].status_code());
  EXPECT_EQ(results[2].revised_sampling_interval(), 825.0);

  delete_subscription(subscription);
  EXPECT_EQ(answers->load(), 1) << "the modify answered more than once";
}

// N answers its one item with handle 5 and then throws. The throw is the call's outcome: the item is failed
// and not created, and the answer's handle 5 is released at once.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-CREATE-THAT-ANSWERS-THEN-THROWS-FAILS-ITS-ITEMS, scope=function)
TEST_F(MonitoringRoute, ACreateThatAnswersThenThrowsFailsItsItemsAndReleasesTheAnswer)
{
  auto subscription = make_subscription();
  mRouteA->issue_next({5});
  mRouteA->answer_creates(CreateAnswer::IssueThenThrow);
  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results =
    create_counted(*subscription, {value_item(NodeId{2, 1u}, 1)}, mSecurityContext, answers);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "NamespaceCallThrew");
  EXPECT_EQ(item_count(*subscription), 0u) << "the item was created from the answer the throw followed";
  EXPECT_TRUE(wait_until([this] { return mRouteA->released_handles() == std::vector<MonitoringHandle>{5}; }))
    << "without the Subscription being deleted, N released " << text(mRouteA->released_handles())
    << ", not {5}";

  delete_subscription(subscription);
  EXPECT_EQ(answers->load(), 1) << "the create answered more than once";
}

// N's modify_monitoring_async answers 725 and then throws Bad_ResourceUnavailable. The throw is the call's
// outcome, so the item answers Bad_InternalError and keeps its sampling interval.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-AN-OLDER-MODIFY-THAT-ANSWERS-THEN-THROWS-FAILS-ITS-ITEMS, scope=function)
TEST_F(MonitoringRoute, AModifyThatAnswersThenThrowsFailsItsItems)
{
  auto subscription = make_subscription();
  mOlder->modify_answers_then_throws(725, StatusCode{Status::BadResourceUnavailable});
  const auto ids = create_good(*subscription, {NodeId{4, 1u}});
  ASSERT_EQ(ids.size(), 1u);

  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results = modify_counted(*subscription, ids, 500, answers);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError)
    << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "NamespaceCallThrew");
  EXPECT_NE(sampling_interval(*subscription, ids[0]), 725.0) << "the item took the revised interval";

  delete_subscription(subscription);
  EXPECT_EQ(answers->load(), 1) << "the modify answered more than once";
}

// N's delete_monitoring_async answers Good and then throws Bad_ResourceUnavailable. The throw is the
// release's outcome, so the release is logged as failed, naming namespace 4 and Bad_InternalError.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-02-A-RELEASE-THAT-ANSWERS-THEN-THROWS-IS-LOGGED, scope=function)
TEST_F(MonitoringRoute, AReleaseThatAnswersThenThrowsIsLogged)
{
  auto subscription = make_subscription();
  subscription->set_logger(captured_logger());
  mOlder->delete_answers_then_throws(StatusCode{Status::BadResourceUnavailable});
  const auto ids = create_good(*subscription, {NodeId{4, 1u}});
  ASSERT_EQ(ids.size(), 1u);

  delete_subscription(subscription);
  ASSERT_TRUE(wait_until([this] { return !mOlder->released_handles().empty(); }))
    << "N's delete_monitoring was not called";
  const std::string warning = "A namespace did not release monitoring handles the server no longer uses";
  const auto logged = [this, &warning]
  {
    for (const auto& entry : mLog->entries())
    {
      if (entry.level != LogLevel::Warning || entry.message != warning)
      {
        continue;
      }
      const auto has = [&entry](const auto& predicate)
      {
        return std::any_of(entry.fieldValues.begin(), entry.fieldValues.end(), predicate);
      };
      if (has([](const std::string& value) { return value == "4"; }) &&
          has([](const std::string& value) { return value.find("BadInternalError") != std::string::npos; }))
      {
        return true;
      }
    }
    return false;
  };
  EXPECT_TRUE(wait_until(logged)) << "no warning named namespace 4 and Bad_InternalError; "
                                  << mLog->entries().size() << " entries were logged";
}
