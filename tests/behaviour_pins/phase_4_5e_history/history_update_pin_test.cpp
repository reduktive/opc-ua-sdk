// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5e - HistoryUpdateService.
//
//
// Pinned (passes at HEAD):
//   HU-A  empty history_update_details      -> BadNothingToDo
//   HU-B  too-many ops                      -> BadTooManyOperations
//   HU-C  null per-item details             -> per-item BadHistoryOperationInvalid
//   HU-D  non-HistoryUpdateDetails subtype  -> per-item BadHistoryOperationInvalid
//   HU-E  UpdateDataDetails empty values    -> per-item BadHistoryOperationInvalid
//   HU-H  Variable without HistoryWrite bit -> per-item BadNotWritable
//   HU-K  namespace without history_delegate -> all items BadHistoryOperationUnsupported
//   HU-L  UpdateData batch failure          -> all items get batch status
//   HU-M  DeleteRaw batch failure           -> all items get batch status
//   HU-X  CompleteCallback fires on a strand-pool thread
//
// Pinned but cannot assert ErrorDetail at HEAD (see runbook section 3.2 TODO):
//   HU-Y/Z/AA/BB - same ErrorDetail-loss issue as HR-V/W/X/Y. The
//   non-null-detail half of the runbook contract is not pinned at HEAD per
//   the user's "MUST PASS at HEAD" rule.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_event_notifier_type.h"
#include "ua_history_update_details.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_service.h"
#include "ua_node_accessor.h"
#include "ua_perform_update_type.h"
#include "ua_read_raw_modified_details.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_update_data_details.h"

#include "fake_history_delegate.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"

namespace ua::test::behaviour_pins::phase_4_5e
{
namespace
{

using namespace std::chrono_literals;

class HistoryUpdatePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mTestThreadId = std::this_thread::get_id();
  }

  void TearDown() override
  {
    mSessionInfo.reset();
    mPool.join();
  }

  void build_server(ua::server::ServerConfig serverConfig = ua::server::ServerConfig{})
  {
    ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    mServer.emplace(ua::server::Server::create(mPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  }

  void install_namespace(bool withDelegate)
  {
    mNamespace = std::make_shared<HistoryPinNamespace>("uri://history-pin-ns", mPool.get_executor());
    if (withDelegate)
    {
      mDelegate = std::make_shared<FakeHistoryDelegate>(FakeHistoryDelegate::Mode::Inline);
      mNamespace->set_delegate(mDelegate);
    }
    mServer->address_space().add_namespace_sync(mNamespace);
    mNsIndex = mServer->address_space().namespace_array().get_namespace_index("uri://history-pin-ns");

    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(*mServer), mPool.get_executor());
    mServer.reset();
  }

  ua::NodeId create_variable_with_history_write(uint32_t numericId)
  {
    ua::NodeId nodeId{mNsIndex, numericId};
    auto as = mSessionInfo->address_space();
    auto varResult = as.try_create_sync<ua::VariableAccessor>(nodeId, ua::NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good());
    if (varResult.is_good())
    {
      ua::AccessLevelType al;
      al.set(ua::AccessLevelType::Bit::CurrentRead);
      al.set(ua::AccessLevelType::Bit::HistoryWrite);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  ua::NodeId create_variable_without_history_write(uint32_t numericId)
  {
    ua::NodeId nodeId{mNsIndex, numericId};
    auto as = mSessionInfo->address_space();
    auto varResult = as.try_create_sync<ua::VariableAccessor>(nodeId, ua::NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good());
    if (varResult.is_good())
    {
      ua::AccessLevelType al;
      al.set(ua::AccessLevelType::Bit::CurrentRead);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  // Build a request containing `count` UpdateDataDetails entries targeting
  // sequential node ids 100..100+count-1.
  ua::HistoryUpdateRequest make_update_data_request(size_t count)
  {
    ua::HistoryUpdateRequest request;
    request.request_header().request_handle() = 1;
    request.history_update_details().resize(count);
    for (size_t i = 0; i < count; ++i)
    {
      auto details = std::make_unique<ua::UpdateDataDetails>();
      details->node_id() = ua::NodeId{mNsIndex, static_cast<uint32_t>(100 + i)};
      details->perform_insert_replace() = ua::PerformUpdateType::Insert;
      details->update_values().resize(1);
      details->update_values()[0].value() = static_cast<int32_t>(i);
      request.history_update_details()[i] = std::move(details);
    }
    return request;
  }

  // Hand the response back through a heap-allocated, reference-counted promise
  // rather than a stack-local mutex+condition_variable. The service completes on
  // a pool thread, so a stack condition_variable could be destroyed by this
  // (waiter) thread the instant wait_for returns while the pool thread is still
  // inside notify_* - the pthread_cond_destroy data race TSan flags. The promise's
  // shared state is co-owned by the callback (via the shared_ptr) and by the
  // future here, and set_value->get is a defined synchronizes-with handoff, so the
  // shared state outlives the completing thread.
  ua::server::HistoryUpdateService::CompleteCallback make_callback(
    std::shared_ptr<std::promise<ua::Response>> resultPromise)
  {
    return [this, resultPromise = std::move(resultPromise)](ua::Response response)
    {
      mCallbackThreadId.store(
        std::hash<std::thread::id>{}(std::this_thread::get_id()), std::memory_order_relaxed);
      resultPromise->set_value(std::move(response));
    };
  }

  ua::Response run_service(ua::HistoryUpdateRequest request)
  {
    auto resultPromise = std::make_shared<std::promise<ua::Response>>();
    auto resultFuture = resultPromise->get_future();

    auto service = ua::server::HistoryUpdateService::create(
      mSessionInfo, 0, std::move(request), mPool.get_executor(), make_callback(resultPromise));

    if (resultFuture.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "HistoryUpdateService did not complete within timeout";
      return {};
    }
    return resultFuture.get();
  }

  static ua::HistoryUpdateResponse* update_response(const ua::Response& r)
  {
    return dynamic_cast<ua::HistoryUpdateResponse*>(std::get<std::shared_ptr<ua::Structure>>(r).get());
  }

  // A whole-request (service-level) rejection is delivered as a ServiceFault, NOT a
  // HistoryUpdateResponse carrying a Bad serviceResult (OPC 10000-4 5.3 / 7.35).
  static ua::ServiceFault* service_fault(const ua::Response& r)
  {
    return dynamic_cast<ua::ServiceFault*>(std::get<std::shared_ptr<ua::Structure>>(r).get());
  }

  boost::asio::thread_pool mPool;
  std::optional<ua::server::Server> mServer;
  std::shared_ptr<HistoryPinNamespace> mNamespace;
  std::shared_ptr<FakeHistoryDelegate> mDelegate;
  std::shared_ptr<SessionInfoStub> mSessionInfo;
  uint16_t mNsIndex{0};

  std::thread::id mTestThreadId{};
  std::atomic<size_t> mCallbackThreadId{0};
};

}  // namespace

// ---------------------------------------------------------------------------
// HU-A - empty details is a whole-request rejection, returned as a ServiceFault
// (OPC 10000-4 5.3 / 7.35), not a HistoryUpdateResponse with a Bad serviceResult.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, EmptyDetailsReturnsBadNothingToDoServiceFault)
{
  build_server();
  install_namespace(/*withDelegate=*/true);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  // history_update_details left empty.

  auto r = run_service(std::move(request));
  auto* fault = service_fault(r);
  ASSERT_NE(fault, nullptr)
    << "a whole-request rejection must be a ServiceFault, not a HistoryUpdateResponse";
  EXPECT_EQ(fault->response_header().service_result(), ua::StatusCode{ua::Status::BadNothingToDo});
  EXPECT_EQ(mDelegate->update_data_call_count(), 0u);
}

// ---------------------------------------------------------------------------
// HU-B - operation count above limit is a whole-request rejection, returned as a ServiceFault.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, OperationCountAboveLimitReturnsBadTooManyOperationsServiceFault)
{
  ua::server::ServerConfig sc;
  sc.server_capabilities().operationLimits.maxNodesPerHistoryUpdateData = 1;
  build_server(std::move(sc));
  install_namespace(/*withDelegate=*/true);

  create_variable_with_history_write(100);
  create_variable_with_history_write(101);

  auto r = run_service(make_update_data_request(2));
  auto* fault = service_fault(r);
  ASSERT_NE(fault, nullptr)
    << "a whole-request rejection must be a ServiceFault, not a HistoryUpdateResponse";
  EXPECT_EQ(fault->response_header().service_result(), ua::StatusCode{ua::Status::BadTooManyOperations});
  EXPECT_EQ(mDelegate->update_data_call_count(), 0u);
}

// ---------------------------------------------------------------------------
// HU-C - null per-item ExtensionObject yields BadHistoryOperationInvalid for
// that item and does not affect surrounding items.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, NullPerItemDetailsReturnsBadHistoryOperationInvalidPerItem)
{
  build_server();
  install_namespace(/*withDelegate=*/true);
  mDelegate->stage_update_data_per_item_success();

  create_variable_with_history_write(101);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);
  // [0] left null.
  auto details = std::make_unique<ua::UpdateDataDetails>();
  details->node_id() = ua::NodeId{mNsIndex, 101u};
  details->perform_insert_replace() = ua::PerformUpdateType::Insert;
  details->update_values().resize(1);
  details->update_values()[0].value() = static_cast<int32_t>(7);
  request.history_update_details()[1] = std::move(details);

  auto r = run_service(std::move(request));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);
  EXPECT_EQ(resp->results()[0].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationInvalid});
  EXPECT_TRUE(resp->results()[1].status_code().is_good());
}

// ---------------------------------------------------------------------------
// HU-D - ExtensionObject is not a HistoryUpdateDetails subtype: per-item
// BadHistoryOperationInvalid. (Use ReadRawModifiedDetails - wrong family.)
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, NonHistoryUpdateDetailsBaseReturnsBadHistoryOperationInvalidPerItem)
{
  build_server();
  install_namespace(/*withDelegate=*/true);

  // ReadRawModifiedDetails inherits Structure but not HistoryUpdateDetails.
  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::make_unique<ua::ReadRawModifiedDetails>();

  auto r = run_service(std::move(request));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationInvalid});
}

// ---------------------------------------------------------------------------
// HU-E - UpdateDataDetails with empty update_values yields per-item
// BadHistoryOperationInvalid.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, UpdateDataDetailsWithEmptyValuesReturnsBadHistoryOperationInvalidPerItem)
{
  build_server();
  install_namespace(/*withDelegate=*/true);

  create_variable_with_history_write(100);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(1);
  auto details = std::make_unique<ua::UpdateDataDetails>();
  details->node_id() = ua::NodeId{mNsIndex, 100u};
  // update_values left empty.
  request.history_update_details()[0] = std::move(details);

  auto r = run_service(std::move(request));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationInvalid});
}

// ---------------------------------------------------------------------------
// HU-H - Variable without HistoryWrite access returns BadNotWritable per-item.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, VariableWithoutHistoryWriteAccessLevelReturnsBadNotWritablePerItem)
{
  build_server();
  install_namespace(/*withDelegate=*/true);

  auto noWrite = create_variable_without_history_write(100);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(1);
  auto details = std::make_unique<ua::UpdateDataDetails>();
  details->node_id() = noWrite;
  details->update_values().resize(1);
  details->update_values()[0].value() = static_cast<int32_t>(0);
  request.history_update_details()[0] = std::move(details);

  auto r = run_service(std::move(request));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0].status_code(), ua::StatusCode{ua::Status::BadNotWritable});
}

// ---------------------------------------------------------------------------
// HU-K - namespace without history_delegate marks all items in the group
// BadHistoryOperationUnsupported.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, NamespaceWithoutHistoryDelegateMarksAllItemsBadHistoryOperationUnsupported)
{
  build_server();
  install_namespace(/*withDelegate=*/false);

  create_variable_with_history_write(100);
  create_variable_with_history_write(101);
  create_variable_with_history_write(102);

  auto r = run_service(make_update_data_request(3));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(resp->results()[i].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationUnsupported})
      << "item " << i << " must carry the per-namespace null-delegate status";
  }
}

// ---------------------------------------------------------------------------
// HU-L - UpdateData delegate batch failure fails every item in the group.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, UpdateDataDelegateBatchFailureFailsAllItemsInGroup)
{
  build_server();
  install_namespace(/*withDelegate=*/true);
  mDelegate->stage_update_data_batch_failure(ua::StatusCode{ua::Status::BadHistoryOperationUnsupported});

  create_variable_with_history_write(100);
  create_variable_with_history_write(101);
  create_variable_with_history_write(102);

  auto r = run_service(make_update_data_request(3));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(resp->results()[i].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationUnsupported})
      << "item " << i << " must inherit the batch-level status";
  }
}

// ---------------------------------------------------------------------------
// HU-M - DeleteRaw delegate batch failure fails every item in the group.
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, DeleteRawDelegateBatchFailureFailsAllItemsInGroup)
{
  build_server();
  install_namespace(/*withDelegate=*/true);
  mDelegate->stage_delete_raw_batch_failure(ua::StatusCode{ua::Status::BadHistoryOperationUnsupported});

  auto a = create_variable_with_history_write(100);
  auto b = create_variable_with_history_write(101);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);
  const ua::DateTime endTime = ua::DateTime::now();
  const ua::DateTime startTime{endTime.value() - std::chrono::hours{1}};
  for (size_t i = 0; i < 2; ++i)
  {
    auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
    details->node_id() = ua::NodeId{mNsIndex, static_cast<uint32_t>(100 + i)};
    details->is_delete_modified() = false;
    details->start_time() = startTime;
    details->end_time() = endTime;
    request.history_update_details()[i] = std::move(details);
  }

  auto r = run_service(std::move(request));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);
  for (size_t i = 0; i < 2; ++i)
  {
    EXPECT_EQ(resp->results()[i].status_code(), ua::StatusCode{ua::Status::BadHistoryOperationUnsupported});
  }
}

// ---------------------------------------------------------------------------
// HU-X - CompleteCallback fires on a strand-pool thread (not main test thread).
// ---------------------------------------------------------------------------
TEST_F(HistoryUpdatePin, CompleteCallbackFiresOnAStrandPoolThread)
{
  build_server();
  install_namespace(/*withDelegate=*/true);
  mDelegate->stage_update_data_per_item_success();

  create_variable_with_history_write(100);

  auto r = run_service(make_update_data_request(1));
  auto* resp = update_response(r);
  ASSERT_NE(resp, nullptr);

  const auto cbHash = mCallbackThreadId.load(std::memory_order_relaxed);
  ASSERT_NE(cbHash, 0u) << "callback never recorded its executing thread";
  EXPECT_NE(cbHash, std::hash<std::thread::id>{}(mTestThreadId))
    << "CompleteCallback fired on the main test thread - strand affinity is broken";
}

}  // namespace ua::test::behaviour_pins::phase_4_5e
