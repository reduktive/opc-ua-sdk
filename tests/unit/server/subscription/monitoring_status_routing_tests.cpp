// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The code a namespace puts on its monitoring answers reaches the client (COMP-SVR-STATUS-ROUTING-01). A
// create or modify answer that holds a result, with a Good subcode or an Uncertain code, creates or changes
// the item, and the item's result answers that code. DeleteMonitoredItems answers once the namespace has
// answered the release of the items' handles, and each item's result is the namespace's code for its handle.
// The code on the answer to the read of an item's initial Value is combined with the Value's own status in
// the item's first notification.
//
// The Subscription is driven through its asynchronous entries, as the pipeline drives it. The namespace keeps
// the default namespace's real Nodes, so the Subscription looks them up, authorizes and reads them as it does
// in production, but answers the monitoring calls itself with the codes the test gives.

#include <gtest/gtest.h>

#include "monitoring_release_fixture.h"

#include "ua_data_change_notification.h"
#include "ua_error_detail.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"

#include <deque>
#include <functional>
#include <future>
#include <map>
#include <thread>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace ua::test::monitoring_release;

namespace
{

/// A namespace with real Nodes whose monitoring answers carry the codes the test gives: the create issues a
/// handle from a counter for each item, with the next code given to @ref code_next_creates (plain Good when
/// none is left); the modify answers each item the sampling interval it was given, with the next code given
/// to
/// @ref code_next_modifies; the delete answers each handle the code given to @ref code_deletes for it (plain
/// Good otherwise), and can hold its answer back until @ref release_deletes. Every other answer is given
/// inline.
class CodedMonitoringNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<CodedMonitoringNamespace> create(
    string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<CodedMonitoringNamespace>(new CodedMonitoringNamespace(uri, std::move(executor)));
  }

  /// The codes of the next items the create answers, in order.
  void code_next_creates(std::vector<StatusCode> codes)
  {
    const std::lock_guard lock{mMutex};
    mCreateCodes.insert(mCreateCodes.end(), codes.begin(), codes.end());
  }

  /// The codes of the next items the modify answers, in order.
  void code_next_modifies(std::vector<StatusCode> codes)
  {
    const std::lock_guard lock{mMutex};
    mModifyCodes.insert(mModifyCodes.end(), codes.begin(), codes.end());
  }

  /// The code the delete answers for @p handle.
  void code_deletes(MonitoringHandle handle, StatusCode code)
  {
    const std::lock_guard lock{mMutex};
    mDeleteCodes.insert_or_assign(handle, std::move(code));
  }

  /// Holds back the answers of later deletes until @ref release_deletes.
  void hold_deletes()
  {
    const std::lock_guard lock{mMutex};
    mHoldDeletes = true;
  }

  /// The deletes whose answers are held back now.
  std::size_t held_deletes() const
  {
    const std::lock_guard lock{mMutex};
    return mHeldDeletes.size();
  }

  /// Stops holding the deletes' answers and gives every answer held back.
  void release_deletes()
  {
    std::vector<std::function<void()>> held;
    {
      const std::lock_guard lock{mMutex};
      mHoldDeletes = false;
      held.swap(mHeldDeletes);
    }
    for (auto& answer : held)
    {
      answer();
    }
  }

  /// Answers every later read of @p nodeId's Value with @p answer.
  void answer_value_reads(const NodeId& nodeId, DataValueResult answer)
  {
    const std::lock_guard lock{mMutex};
    mValueAnswers.insert_or_assign(nodeId, std::move(answer));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    std::vector<std::optional<DataValueResult>> scripted;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        const auto found = mValueAnswers.find(item.value.node_id());
        scripted.push_back(
          found == mValueAnswers.end() ? std::nullopt : std::optional<DataValueResult>{found->second});
      }
    }
    default_ns::Namespace::read_values_async(request,
      caller,
      items,
      maxAge,
      setSourceTimestamp,
      [scripted, complete](BatchResult<DataValueResult> answer)
      {
        if (!answer.batchStatus.is_bad())
        {
          for (std::size_t k = 0; k < answer.items.size() && k < scripted.size(); ++k)
          {
            if (scripted[k])
            {
              answer.items[k] = *scripted[k];
            }
          }
        }
        complete(std::move(answer));
      });
  }

  /// The handles the creates issued, in order.
  std::vector<MonitoringHandle> issued_handles() const
  {
    const std::lock_guard lock{mMutex};
    return mIssued;
  }

  void create_monitoring_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override
  {
    BatchResult<MonitoringCreateItemResult> answer;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        const MonitoringHandle handle = mNextHandle++;
        mIssued.push_back(handle);
        answer.items.emplace_back(
          MonitoringCreateSuccess{handle, item.samplingInterval}, next_code_locked(mCreateCodes));
      }
    }
    complete(std::move(answer));
  }

  void modify_monitoring_async(const RequestInfo& /*request*/, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override
  {
    BatchResult<MonitoringModifyItemResult> answer;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        answer.items.emplace_back(
          MonitoringModifySuccess{item.samplingInterval}, next_code_locked(mModifyCodes));
      }
    }
    complete(std::move(answer));
  }

  void delete_monitoring_async(const RequestInfo& /*request*/, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override
  {
    BatchResult<VoidResult> answer;
    bool hold = false;
    {
      const std::lock_guard lock{mMutex};
      for (const auto handle : handles)
      {
        const auto found = mDeleteCodes.find(handle);
        answer.items.emplace_back(found == mDeleteCodes.end() ? StatusCode{Status::Good} : found->second);
      }
      hold = mHoldDeletes;
      if (hold)
      {
        auto shared = std::make_shared<BatchResult<VoidResult>>(std::move(answer));
        mHeldDeletes.push_back([complete, shared]() { complete(std::move(*shared)); });
      }
    }
    if (!hold)
    {
      complete(std::move(answer));
    }
  }

private:
  CodedMonitoringNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// The next code of @p codes, plain Good when none is left. Called with the mutex held.
  static StatusCode next_code_locked(std::deque<StatusCode>& codes)
  {
    if (codes.empty())
    {
      return StatusCode{Status::Good};
    }
    StatusCode code = std::move(codes.front());
    codes.pop_front();
    return code;
  }

  mutable std::mutex mMutex;
  MonitoringHandle mNextHandle{100};
  std::vector<MonitoringHandle> mIssued;
  std::deque<StatusCode> mCreateCodes;
  std::deque<StatusCode> mModifyCodes;
  std::map<MonitoringHandle, StatusCode> mDeleteCodes;
  std::unordered_map<NodeId, DataValueResult> mValueAnswers;
  bool mHoldDeletes{false};
  std::vector<std::function<void()>> mHeldDeletes;
};

class MonitoringStatusRouting : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mNamespace = CodedMonitoringNamespace::create("urn:test:monitoring-status-routing", mExecutor);
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    ASSERT_EQ(index.value(), uint16_t{2}) << "the test names its Variables in namespace 2";
    for (uint32_t i = 1; i <= 3; ++i)
    {
      create_variable(NodeId{2, i});
    }
    // After the namespace is registered: the security context grants every default namespace to its Role.
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    mCapabilities.minSupportedSampleRate = 0;
    mSubscription =
      Subscription::create(1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  void TearDown() override
  {
    if (mNamespace)
    {
      mNamespace->release_deletes();
    }
    if (mSubscription)
    {
      std::promise<void> closed;
      auto done = closed.get_future();
      mSubscription->close_async([&closed] { closed.set_value(); });
      EXPECT_EQ(done.wait_for(5s), std::future_status::ready) << "close_async did not complete";
      mSubscription.reset();
    }
    mSecurityContext.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_variable(const NodeId& nodeId)
  {
    auto node = mAddressSpace->create_node_sync(nodeId, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{nodeId.namespace_index(), "Value"});
    accessor->set_data_type(NodeId{DataTypeId::Double});
    accessor->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    accessor->write_value_sync(Variant{0.0});
  }

  /// Creates one Value item on each of @p nodeIds in one request and returns the results.
  std::vector<MonitoredItemCreateResult> create(const std::vector<NodeId>& nodeIds)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    uint32_t clientHandle = 1;
    for (const auto& nodeId : nodeIds)
    {
      MonitoredItemCreateRequest item;
      item.item_to_monitor().node_id() = nodeId;
      item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
      item.monitoring_mode() = MonitoringMode::Reporting;
      item.requested_parameters().client_handle() = clientHandle++;
      item.requested_parameters().sampling_interval() = 100;
      item.requested_parameters().queue_size() = 1;
      item.requested_parameters().discard_oldest() = true;
      request.items_to_create().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      mSecurityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<MonitoredItemCreateResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return {};
    }
    return future.get();
  }

  /// Modifies the items @p ids to @p samplingInterval in one request and returns the results.
  std::vector<MonitoredItemModifyResult> modify(const std::vector<IntegerId>& ids, Duration samplingInterval)
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
    mSubscription->modify_monitored_items_async(std::move(request),
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

  /// Starts deleting the items @p ids in one request; the future holds the results.
  std::future<std::vector<StatusCode>> start_delete(std::vector<IntegerId> ids)
  {
    auto promise = std::make_shared<std::promise<std::vector<StatusCode>>>();
    auto future = promise->get_future();
    mSubscription->delete_monitored_items_async(std::move(ids),
      *mAddressSpace,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<StatusCode> results) { promise->set_value(std::move(results)); });
    return future;
  }

  /// The sampling interval of the item @p id; -1 when there is no such item.
  Duration sampling_interval(IntegerId id)
  {
    return STA::on_strand(*mSubscription,
      [id](auto& guard)
      {
        const auto& items = guard.monitored_items();
        const auto found = items.find(id);
        return found == items.end() ? Duration{-1} : found->second->samplingInterval;
      });
  }

  /// Publishes until a notification has been taken for each of @p count client handles, at most 3 s, and
  /// returns the first DataValue taken for each client handle.
  std::map<uint32_t, DataValue> first_notifications(std::size_t count)
  {
    std::map<uint32_t, DataValue> taken;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (taken.size() < count && std::chrono::steady_clock::now() < deadline)
    {
      auto published = STA::on_strand(*mSubscription,
        [](auto& guard)
        {
          guard.set_publish_req_queued(true);
          return guard.fulfill_publish(1);
        });
      for (const auto& result : published)
      {
        for (const auto& data : result.message.notification_data())
        {
          const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
          if (change == nullptr)
          {
            continue;
          }
          for (const auto& notification : change->monitored_items())
          {
            taken.try_emplace(notification.client_handle(), notification.value());
          }
        }
      }
      if (taken.size() < count)
      {
        std::this_thread::sleep_for(5ms);
      }
    }
    return taken;
  }

  std::size_t item_count()
  {
    return STA::on_strand(*mSubscription, [](auto& guard) { return guard.monitored_items().size(); });
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<CodedMonitoringNamespace> mNamespace;
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
  std::shared_ptr<Subscription> mSubscription;
};

}  // namespace

// A create answer holding a result with a Good subcode or an Uncertain code creates the item, whose result
// answers that code; so does a modify answer, which changes the item. The third item is the control: plain
// Good answers are answered Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-MONITORING-CREATE-AND-MODIFY-ANSWER-THE-NAMESPACES-CODE, scope=function)
TEST_F(MonitoringStatusRouting, CreateAndModifyAnswerTheNamespacesCode)
{
  mNamespace->code_next_creates({StatusCode{Status::GoodLocalOverride},
    StatusCode{Status::UncertainLastUsableValue},
    StatusCode{Status::Good}});
  const auto created = create({NodeId{2, 1u}, NodeId{2, 2u}, NodeId{2, 3u}});
  ASSERT_EQ(created.size(), 3u);
  EXPECT_EQ(created[0].status_code().as_status(), Status::GoodLocalOverride)
    << to_string(created[0].status_code());
  EXPECT_EQ(created[1].status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(created[1].status_code());
  EXPECT_EQ(created[2].status_code().as_status(), Status::Good)
    << "the control: " << to_string(created[2].status_code());
  std::vector<IntegerId> ids;
  for (const auto& result : created)
  {
    EXPECT_NE(result.monitored_item_id(), 0u)
      << "no item was created for " << to_string(result.status_code());
    ids.push_back(result.monitored_item_id());
  }
  EXPECT_EQ(item_count(), 3u) << "an item was not created for an answer that holds a result";

  mNamespace->code_next_modifies({StatusCode{Status::UncertainLastUsableValue},
    StatusCode{Status::GoodLocalOverride},
    StatusCode{Status::Good}});
  const auto modified = modify(ids, 500);
  ASSERT_EQ(modified.size(), 3u);
  EXPECT_EQ(modified[0].status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(modified[0].status_code());
  EXPECT_EQ(modified[1].status_code().as_status(), Status::GoodLocalOverride)
    << to_string(modified[1].status_code());
  EXPECT_EQ(modified[2].status_code().as_status(), Status::Good)
    << "the control: " << to_string(modified[2].status_code());
  for (std::size_t k = 0; k < ids.size(); ++k)
  {
    EXPECT_EQ(sampling_interval(ids[k]), Duration{500})
      << "item " << k << " did not take the sampling interval its namespace answered";
  }

  mNamespace->code_next_creates(
    {StatusCode{Status::GoodLocalOverride}, StatusCode{Status::UncertainInitialValue}});
  const auto declaredCreated = create({NodeId{2, 1u}, NodeId{2, 2u}});
  ASSERT_EQ(declaredCreated.size(), 2U);
  EXPECT_EQ(declaredCreated[0].status_code().as_status(), Status::GoodLocalOverride);
  EXPECT_EQ(declaredCreated[1].status_code().as_status(), Status::UncertainInitialValue);
  std::vector<IntegerId> declaredIds;
  for (const auto& result : declaredCreated)
  {
    ASSERT_NE(result.monitored_item_id(), 0U);
    declaredIds.push_back(result.monitored_item_id());
  }
  EXPECT_EQ(item_count(), 5U);

  mNamespace->code_next_modifies(
    {StatusCode{Status::UncertainInitialValue}, StatusCode{Status::UncertainInitialValue}});
  const auto declaredModified = modify(declaredIds, 750);
  ASSERT_EQ(declaredModified.size(), 2U);
  for (std::size_t index = 0; index < declaredIds.size(); ++index)
  {
    EXPECT_EQ(declaredModified[index].status_code().as_status(), Status::UncertainInitialValue);
    EXPECT_EQ(sampling_interval(declaredIds[index]), Duration{750});
  }
}

// DeleteMonitoredItems answers once the namespace has answered the release of the items' handles, and each
// item's result is the code the namespace answered for its handle: a Good subcode, an Uncertain code or a Bad
// code. The items are gone whatever the namespace answers.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-DELETE-MONITORED-ITEMS-ANSWERS-THE-NAMESPACES-CODE, scope=function)
TEST_F(MonitoringStatusRouting, DeleteMonitoredItemsAnswersTheNamespacesCode)
{
  const auto created = create({NodeId{2, 1u}, NodeId{2, 2u}, NodeId{2, 3u}});
  ASSERT_EQ(created.size(), 3u);
  std::vector<IntegerId> ids;
  for (const auto& result : created)
  {
    ASSERT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
    ids.push_back(result.monitored_item_id());
  }
  const auto handles = mNamespace->issued_handles();
  ASSERT_EQ(handles.size(), 3u);
  mNamespace->code_deletes(handles[0], StatusCode{Status::GoodLocalOverride});
  mNamespace->code_deletes(handles[1], StatusCode{Status::UncertainLastUsableValue});
  mNamespace->code_deletes(handles[2], StatusCode{Status::BadDeviceFailure});
  mNamespace->hold_deletes();

  auto deleted = start_delete(ids);
  ASSERT_TRUE(wait_until([this] { return mNamespace->held_deletes() == 1u; }))
    << "the namespace was not asked to release the handles";
  EXPECT_NE(deleted.wait_for(100ms), std::future_status::ready)
    << "DeleteMonitoredItems answered before the namespace answered";
  mNamespace->release_deletes();

  ASSERT_EQ(deleted.wait_for(5s), std::future_status::ready) << "DeleteMonitoredItems did not answer";
  const auto results = deleted.get();
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].as_status(), Status::GoodLocalOverride) << to_string(results[0]);
  EXPECT_EQ(results[1].as_status(), Status::UncertainLastUsableValue) << to_string(results[1]);
  EXPECT_EQ(results[2].as_status(), Status::BadDeviceFailure) << to_string(results[2]);
  EXPECT_EQ(item_count(), 0u) << "an item was kept";

  const auto declaredCreated = create({NodeId{2, 1u}, NodeId{2, 2u}});
  ASSERT_EQ(declaredCreated.size(), 2U);
  std::vector<IntegerId> declaredIds;
  for (const auto& result : declaredCreated)
  {
    ASSERT_EQ(result.status_code().as_status(), Status::Good);
    declaredIds.push_back(result.monitored_item_id());
  }
  const auto declaredHandles = mNamespace->issued_handles();
  ASSERT_EQ(declaredHandles.size(), 5U);
  mNamespace->code_deletes(declaredHandles[3], StatusCode{Status::GoodLocalOverride});
  mNamespace->code_deletes(declaredHandles[4], StatusCode{Status::BadNotFound});
  mNamespace->hold_deletes();

  auto declaredDeleted = start_delete(declaredIds);
  ASSERT_TRUE(wait_until([this] { return mNamespace->held_deletes() == 1U; }));
  EXPECT_EQ(declaredDeleted.wait_for(0ms), std::future_status::timeout);
  mNamespace->release_deletes();

  ASSERT_EQ(declaredDeleted.wait_for(5s), std::future_status::ready);
  const auto declaredResults = declaredDeleted.get();
  ASSERT_EQ(declaredResults.size(), 2U);
  EXPECT_EQ(declaredResults[0].as_status(), Status::GoodLocalOverride);
  EXPECT_EQ(declaredResults[1].as_status(), Status::BadNotFound);
  EXPECT_EQ(item_count(), 0U);
}

// The code on the answer to the read of an item's initial Value and the Value's own status share the initial
// notification's one status: a Good subcode or an Uncertain code on an answer whose Value is Good is the
// notification's status, with the Value; a Bad status on the Value is notified over a Good subcode on the
// answer.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-NOTIFICATIONS-CARRY-THE-COMBINED-CODE, scope=function)
TEST_F(MonitoringStatusRouting, TheInitialNotificationCarriesTheCombinedCode)
{
  DataValue badValue{Variant{3.0}};
  badValue.status() = StatusCode{Status::BadDeviceFailure};
  mNamespace->answer_value_reads(
    NodeId{2, 1u}, DataValueResult{DataValue{Variant{1.0}}, StatusCode{Status::GoodLocalOverride}});
  mNamespace->answer_value_reads(
    NodeId{2, 2u}, DataValueResult{DataValue{Variant{2.0}}, StatusCode{Status::UncertainLastUsableValue}});
  mNamespace->answer_value_reads(
    NodeId{2, 3u}, DataValueResult{badValue, StatusCode{Status::GoodLocalOverride}});

  const auto created = create({NodeId{2, 1u}, NodeId{2, 2u}, NodeId{2, 3u}});
  ASSERT_EQ(created.size(), 3u);
  for (const auto& result : created)
  {
    ASSERT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
  }

  const auto initial = first_notifications(3);
  ASSERT_EQ(initial.size(), 3u) << "not every item's initial value was published";
  const auto statusOf = [](const DataValue& value)
  {
    return value.status().value_or(StatusCode{Status::Good}).as_status();
  };
  EXPECT_EQ(statusOf(initial.at(1)), Status::GoodLocalOverride) << "the Good subcode on the answer";
  EXPECT_EQ(
    initial.at(1).value().try_as<double>() != nullptr ? *initial.at(1).value().try_as<double>() : -1.0, 1.0);
  EXPECT_EQ(statusOf(initial.at(2)), Status::UncertainLastUsableValue) << "the Uncertain code on the answer";
  EXPECT_EQ(
    initial.at(2).value().try_as<double>() != nullptr ? *initial.at(2).value().try_as<double>() : -1.0, 2.0);
  EXPECT_EQ(statusOf(initial.at(3)), Status::BadDeviceFailure)
    << "the Value's Bad status under a Good subcode";
}
