// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the CLIENT IndexRange read/write forwarding contract (client integration matrix rows
// ClientReadIndex.EqualOrDescendingBoundsRejectedLocallyNoWire, ClientWriteIndex.ArraySizeMustMatchRange,
// ClientWriteIndex.SingleElementWrapsAsArray - the [int+unit] rows).
//
// KEY TIER-1 CONTRACT PINNED HERE: `ServiceSet` is the raw wire-shaped explicit override and intentionally has
// no local NumericRange validation or single-element auto-wrap. `ConnectionImpl::read_async` validates only
// a negative MaxAge; `write_async` performs no request-input validation. So a malformed / oversized /
// single-element IndexRange is FORWARDED VERBATIM to the tier-0 session op rather than rejected client-side.
// The tier-2 `NumericRangeBuilder` and `TypedAccess` enforce CL-ADDRSP-006 separately. These tests drive the
// tier-1 `ServiceSet` funnel over FakeSessionOps and assert that the exact request the caller built reaches
// the session op (call_count advances; the captured ReadValueId / WriteValue carries the same index_range
// and the same value shape - array or scalar - unchanged).
//
// Falsifiability: if a client-side validator were added that rejected the malformed range before dispatch,
// the forwarded-request assertions (call_count, captured index_range) would fail; if an auto-wrap were
// added to tier 1, the scalar-stays-scalar assertion would fail. The server-side rejection of these same
// ranges is the subject of the sibling integration rows and of numeric_range_parser_tests /
// index_range_utils_tests.

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_value.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <future>
#include <memory>
#include <string_view>
#include <utility>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::ReconnectPolicy;
using ua::client::ServiceSet;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A live Active ConnectionImpl plus a ServiceSet wrapping it, over the FakeSessionOps interface. Mirrors
// service_set_tests.cpp's fixture. The bootstrap NamespaceArray Read is the FIRST captured read, so a
// forwarded test Read is `read.requests()[1]`.
class IndexForwardingTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  ServiceSet make_service_set()
  {
    return ConnectionHandleFactory::make_service_set(mConnection);
  }

  template<typename Response, typename Invoke>
  Result<Response> await(Invoke invoke)
  {
    std::promise<Result<Response>> done;
    auto future = done.get_future();
    invoke([&done](Result<Response> result) { done.set_value(std::move(result)); });
    return future.get();
  }

  static ua::ReadRequest read_with_range(std::string_view range)
  {
    ua::ReadValueId item;
    item.node_id() = ua::NodeId{2, 5000};
    item.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    item.index_range() = ua::String{range};
    ua::ReadRequest request;
    request.nodes_to_read().push_back(std::move(item));
    return request;
  }

  static ua::WriteRequest write_with_range(std::string_view range, ua::Variant value)
  {
    ua::WriteValue item;
    item.node_id() = ua::NodeId{2, 5000};
    item.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    item.index_range() = ua::String{range};
    item.value() = ua::DataValue{std::move(value)};
    ua::WriteRequest request;
    request.nodes_to_write().push_back(std::move(item));
    return request;
  }
};

// =============================================================================================
// ClientReadIndexForwarding - EqualOrDescendingBoundsRejectedLocallyNoWire (unit)
// An equal-bound ('5:5'), descending-bound ('7:5') or whitespace ('5 :7') IndexRange must be forwarded to
// the tier-0 read op VERBATIM - the client performs no local NumericRange validation, so no range is
// dropped or rewritten before dispatch. (The server rejects each; that is the sibling integration row.)
// =============================================================================================
// @verifies CL-ATTR-008
// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, CL-ATTR-008, scope=function)
TEST_F(IndexForwardingTest, MalformedReadIndexRangeForwardedVerbatimNoLocalRejection)
{
  auto serviceSet = make_service_set();

  for (std::string_view range : {std::string_view{"5:5"}, std::string_view{"7:5"}, std::string_view{"5 :7"}})
  {
    const std::size_t before = mSession->read.call_count();
    auto result =
      await<ua::ReadResponse>([&](auto cb) { serviceSet.read_async(read_with_range(range), std::move(cb)); });

    EXPECT_TRUE(result.is_good())
      << "the client forwards the request; it does not synthesize a local rejection for '" << range << "'";
    ASSERT_EQ(mSession->read.call_count(), before + 1)
      << "the malformed range '" << range << "' must reach the tier-0 read op (no local short-circuit)";

    auto captured = mSession->read.requests();
    ASSERT_FALSE(captured.empty());
    const auto& forwarded = captured.back();
    ASSERT_EQ(forwarded.nodes_to_read().size(), 1u);
    EXPECT_EQ(std::string_view{forwarded.nodes_to_read()[0].index_range()}, range)
      << "the IndexRange must be forwarded byte-for-byte, not validated/normalised client-side";
  }
}

// =============================================================================================
// ClientWriteIndexForwarding - ArraySizeMustMatchRange (unit)
// A write whose array cardinality does not match the IndexRange width ('3:5' is 3 wide, the array has 4
// elements) must be forwarded to the tier-0 write op VERBATIM - the client performs no local size check.
// (The server rejects the mismatch; that is the sibling integration row.)
// =============================================================================================
// @verifies CL-ATTR-023
// @relation(CL-ATTR-023, scope=function)
TEST_F(IndexForwardingTest, SizeMismatchedWriteForwardedVerbatimNoLocalRejection)
{
  auto serviceSet = make_service_set();

  ua::Array<int32_t> fourElements{700, 701, 702, 703};
  const std::size_t before = mSession->write.call_count();
  auto result = await<ua::WriteResponse>([&](auto cb)
    { serviceSet.write_async(write_with_range("3:5", ua::Variant{fourElements}), std::move(cb)); });

  EXPECT_TRUE(result.is_good())
    << "the client forwards the write; it does not synthesize a local size-mismatch rejection";
  ASSERT_EQ(mSession->write.call_count(), before + 1)
    << "a size-mismatched ranged write must reach the tier-0 write op (no local short-circuit)";

  auto captured = mSession->write.requests();
  ASSERT_FALSE(captured.empty());
  const auto& forwarded = captured.back();
  ASSERT_EQ(forwarded.nodes_to_write().size(), 1u);
  EXPECT_EQ(std::string_view{forwarded.nodes_to_write()[0].index_range()}, std::string_view{"3:5"})
    << "the IndexRange must be forwarded verbatim";
  const ua::Variant& value = forwarded.nodes_to_write()[0].value().value();
  ASSERT_TRUE(value.is_array()) << "the caller's array value must reach the wire unchanged";
  auto vec = value.to_vector<int32_t>();
  ASSERT_TRUE(vec.is_good());
  EXPECT_EQ(vec.value().size(), 4u)
    << "the client must not resize the array to the range width; the mismatch is the server's to reject";
}

// =============================================================================================
// ClientWriteIndexForwarding - SingleElementWrapsAsArray (unit)
// A single-index write ('4') carrying a SCALAR Variant must be forwarded to the tier-0 write op VERBATIM
// as a scalar - the client does NOT auto-wrap it into a 1-element array. (The server rejects the scalar
// partial with Bad_TypeMismatch; the correct wire shape is a caller-supplied 1-element array, exercised in
// the sibling integration row.)
// =============================================================================================
// @verifies CL-ATTR-022
// @relation(CL-ATTR-022, scope=function)
TEST_F(IndexForwardingTest, SingleElementScalarWriteForwardedUnwrapped)
{
  auto serviceSet = make_service_set();

  const std::size_t before = mSession->write.call_count();
  auto result = await<ua::WriteResponse>([&](auto cb)
    { serviceSet.write_async(write_with_range("4", ua::Variant{int32_t{909}}), std::move(cb)); });

  EXPECT_TRUE(result.is_good());
  ASSERT_EQ(mSession->write.call_count(), before + 1)
    << "the single-element write must reach the tier-0 write op";

  auto captured = mSession->write.requests();
  ASSERT_FALSE(captured.empty());
  const auto& forwarded = captured.back();
  ASSERT_EQ(forwarded.nodes_to_write().size(), 1u);
  const ua::Variant& value = forwarded.nodes_to_write()[0].value().value();
  EXPECT_FALSE(value.is_array())
    << "the client must NOT wrap the scalar as a 1-element array; it forwards the scalar verbatim";
  EXPECT_TRUE(value.is_scalar());
  const int32_t* scalar = value.try_as<int32_t>();
  ASSERT_NE(scalar, nullptr) << "the forwarded value must remain the caller's scalar Int32";
  EXPECT_EQ(*scalar, 909);
}

}  // namespace
