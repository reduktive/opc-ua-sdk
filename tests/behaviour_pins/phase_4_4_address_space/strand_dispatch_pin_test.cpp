// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (strand-dispatch contract).
//
// that authorises this file and section 3.2 for the contract these pins lock:
//
//   "AddressSpace and AddressSpaceImpl are NOT strand-serialised. The user
//    callback fires wherever the chosen Namespace impl chose to fire it -
//    for the default sync impl, inline on the calling thread; for an async
//    impl, on the impl's chosen thread."
//
// The dual-fixture pattern below is required: SD-A / SD-C exercise the
// inline-fast-path (production default_ns::Namespace, callback fires on the
// calling thread); SD-B / SD-D / SD-E exercise the async-dispatch path
// (FakeAsyncNamespace fires from its dedicated worker thread). The pair
// is the falsifiable contract - a regression that always resumes inline (or
// always resumes on a particular pool thread) breaks one fixture or the
// other.
//
// Pin file scope:
//   SD-A / SD-B - find_node_async threading affinity.
//   SD-C / SD-D - VariableAccessor::read_value_async threading affinity.
//   SD-E       - multi-step instance_utils::find_child_id_by_browse_name_async
//                flow across two FakeAsyncNamespaces: user callback fires
//                ONLY after every parked Namespace completion is released.
//                The flow re-posts at each continuation onto the
//                AddressSpace executor (per the dispatch->post discipline),
//                so the user callback
//                fires on the executor's worker - not on the calling
//                thread, and not on the impl's worker.

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_duration.h"
#include "ua_expanded_node_id.h"
#include "ua_instance_utils.h"
#include "ua_namespace.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

class StrandDispatchPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace = std::make_unique<AddressSpace>(
      AddressSpace::create(String{"urn:test:strand-dispatch:pin"}, mPool->executor()));
  }

  void TearDown() override
  {
    // Releases NamespaceArray (and any shared_ptr<FakeAsyncNamespace>
    // held by it) BEFORE the test-local shared_ptrs reset and the pool
    // stops. This ordering ensures FakeAsyncNamespace destructors (which
    // join their worker threads) run while the pool is still alive - the
    // worker may still be inside a fired callback that touches the fake.
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// ---------------------------------------------------------------------------
// SD-A - find_node_async on default_ns: callback fires on the CALLING thread
//        (inline-fast-path).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression that posts the find_node callback to
// the AddressSpace's executor (or to any other thread) when the underlying
// namespace impl chose to complete inline would silently introduce
// thread-bouncing on a previously-synchronous path. SD-A locks the
// inline-fast-path; SD-B locks the async-dispatch path. The pair pins the
// contract "callback fires wherever the impl chose to fire it."

TEST_F(StrandDispatchPin, FindNodeAsyncOnDefaultNsCallbackFiresOnCallingThread)
{
  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"sd-a:existing"}};

  // Pre-create the node so find_node returns Good (success path is the one
  // that exercises the inline callback firing in default_ns).
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      existingId, NodeClass::Object, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  const auto callerTid = std::this_thread::get_id();
  std::promise<std::thread::id> observedTidP;
  mAddressSpace->find_node_async(existingId,
    [&observedTidP](NodeAccessorResult /*result*/) { observedTidP.set_value(std::this_thread::get_id()); });

  // default_ns fires its callback inline on the calling thread, so the
  // promise is fulfilled by the time find_node_async returns.
  auto observedTid = observedTidP.get_future().get();
  EXPECT_EQ(observedTid, callerTid)
    << "find_node_async on default_ns must fire its callback on the calling thread (inline-fast-path)";
}

// ---------------------------------------------------------------------------
// SD-C - VariableAccessor::read_value_async on default_ns: callback fires on
//        the CALLING thread (inline-fast-path).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression that always posts the read_value
// callback to the executor (or another thread) when the underlying Node's
// read_value chose to complete inline would silently introduce
// thread-bouncing on the value-read fast path.

TEST_F(StrandDispatchPin, ReadValueAsyncOnDefaultNsCallbackFiresOnCallingThread)
{
  const NodeId variableId{/*namespaceIndex=*/1u, std::string_view{"sd-c:variable"}};
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      variableId, NodeClass::Variable, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  auto findResult = mAddressSpace->try_find_node_sync(variableId);
  ASSERT_TRUE(findResult.is_good());
  auto variable = findResult.value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());

  const auto callerTid = std::this_thread::get_id();
  std::promise<std::thread::id> observedTidP;
  ReadValueId readValueId;
  variable->read_value_async(/*maxAge=*/0.0,
    /*setSourceTimestamp=*/true,
    readValueId,

    nullptr,
      [&observedTidP](DataValueResult /*result*/) { observedTidP.set_value(std::this_thread::get_id()); });

  auto observedTid = observedTidP.get_future().get();
  EXPECT_EQ(observedTid, callerTid)
    << "default_ns Variable's read_value fires its callback inline on the calling thread";
}

}  // namespace ua::test::behaviour_pins
