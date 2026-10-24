// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// A Session that ends aborts the requests it still has outstanding (OPC 10000-4 5.6.2.1: "When a Session is
// terminated, all outstanding requests on the Session are aborted and Bad_SessionClosed StatusCodes are
// returned to the Client"). A Variable's value source holds every read it is given and keeps the read's
// cancellation flag; a Client reads it on a second Session and closes that Session while the read is held.

#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_instance_utils.h"
#include "ua_node_accessor.h"
#include "ua_read_request.h"
#include "ua_to_string.h"
#include "ua_value_source.h"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// The reads a value source holds: each read's cancellation flag and its completion, answered on release.
class HeldReads
{
public:
  void hold(shared_ptr<const std::atomic_bool> cancelled, std::function<void(DataValueResult)> done)
  {
    const std::lock_guard lock{mMutex};
    mCancelled.push_back(std::move(cancelled));
    mDone.push_back(std::move(done));
  }

  std::size_t held() const
  {
    const std::lock_guard lock{mMutex};
    return mCancelled.size();
  }

  /// Whether the flag of the read held first is set.
  bool first_cancelled() const
  {
    const std::lock_guard lock{mMutex};
    return !mCancelled.empty() && mCancelled.front()->load();
  }

  /// Answers every held read.
  void release()
  {
    std::vector<std::function<void(DataValueResult)>> done;
    {
      const std::lock_guard lock{mMutex};
      done.swap(mDone);
    }
    for (auto& each : done)
    {
      each(DataValueResult{DataValue{Variant{int32_t{7}}}});
    }
  }

private:
  mutable std::mutex mMutex;
  std::vector<shared_ptr<const std::atomic_bool>> mCancelled;
  std::vector<std::function<void(DataValueResult)>> mDone;
};

bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(5ms);
  }
  return true;
}

class SessionEndAbort : public ComplianceSecuredWithSession
{
protected:
  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();
    auto addressSpace = mServer->address_space();
    auto heldNamespace =
      default_ns::Namespace::create("urn:test:session-end-abort", mServerThreadPool.get_executor());
    const auto index = addressSpace.add_namespace_sync(heldNamespace);
    grant_fixture_namespace_permissions(addressSpace);
    mVariableId = NodeId{index, uint32_t{1}};
    auto node = addressSpace.create_node_sync(mVariableId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{index, "Held"});
    variable->set_display_name(LocalizedText{"", "Held"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

    std::promise<VoidResult> installed;
    auto installedFuture = installed.get_future();
    instance_utils::resolve_and_set_value_source_async(addressSpace,
      mVariableId,
      make_value_source([held = mHeld](const ValueSource::ReadContext& context,
                          const Node& /*node*/,
                          const ReadValueId& /*read*/,
                          std::function<void(DataValueResult)>
                            done) { held->hold(context.request.cancelled, std::move(done)); }),
      [&installed](VoidResult result) { installed.set_value(std::move(result)); });
    const auto result = installedFuture.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  }

  void TearDown() override
  {
    mHeld->release();
    ComplianceSecuredWithSession::TearDown();
  }

  std::shared_ptr<HeldReads> mHeld = std::make_shared<HeldReads>();
  NodeId mVariableId;
};

}  // namespace

// The Read is outstanding when its Session is closed: the server sets the cancellation flag its namespace
// call carries, which a Cancel or a timeout sets otherwise, rather than leaving the read running.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-26-CLOSING-A-SESSION-ABORTS-ITS-OUTSTANDING-REQUESTS, scope=function)
TEST_F(SessionEndAbort, ClosingASessionAbortsItsOutstandingRead)
{
  auto second = mChannel->create_session_sync({.sessionName = "SessionEndAbort"});
  second.activate_sync();

  ReadRequest request;
  request.request_header().timeout_hint() = 60000;
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = mVariableId;
  request.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
  second.attributes().read_async(std::move(request), [](auto) {});
  ASSERT_TRUE(wait_until([this] { return mHeld->held() == 1; }, 5s)) << "the Read did not reach the source";
  ASSERT_FALSE(mHeld->first_cancelled()) << "the Read was cancelled before its Session was closed";

  (void)second.try_close_sync();

  EXPECT_TRUE(wait_until([this] { return mHeld->first_cancelled(); }, 5s))
    << "the Session closed and its outstanding Read was not aborted";
}
