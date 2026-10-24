// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 typed-value sugar: ua::client::Connection::read_value<T> (section 7.2), the
// ua::client::TypedAccess sub-accessor (section 7.2A), and the ua::client::args method-call input packer.
//
// All are thin sugar over the same strand-serialized ConnectionImpl wire-op funnel. Pinned over the
// FakeSessionOps tier-0 interface:
//   - read_value<T> decodes the value Variant to a native T (Variant::to<T>), FLATTENING a Bad-SEVERITY
//     value quality into the Result<T> (CL-ATTR-005/006, matching the bulk read) while PRESERVING Uncertain;
//   - the TWO-LAYER model is scoped to the DataValue path: a good-service DataValue with a Bad value quality
//     yields a Good Result<DataValue> surfacing the quality on DataValue::status() (CL-DA-015 / CL-SM-002);
//   - a Bad DataValue carrying a null Value (the conformant case) yields a bad Result<T>
//     (CL-ATTR-005 / CL-ATTR-006 - tier-2 sugar never hands back a bogus typed value);
//   - a wrong-type value decodes to Bad_TypeMismatch;
//   - TypedAccess read_attribute/write_attribute/read_values/write_values/call_method compose the
//     right request and forward it once through the funnel (single-wrap of a bad downstream Result);
//   - ua::args boxes native C++ values into the right Variants and call_method forwards them verbatim
//     in order (CL-METH-001/002/003).
//
// Falsifiability: sugar that did NOT flatten a Bad-severity quality (or that flattened Uncertain) fails the
// CL-ATTR-005/006 assertions; a DataValue path that flattened the quality fails the two-layer assertion; one
// that handed back a typed value from a null Bad DataValue fails the CL-ATTR-006 assertion; a packer that
// reordered or mistyped arguments fails the args assertions; a forwarder that dropped the downstream
// ErrorDetail fails the single-wrap assertion.

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_client_observers.h"
#include "ua_address_space_cache.h"

#include "ua_attribute_id.h"
#include "ua_access_level_ex_type.h"
#include "ua_argument.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_response.h"
#include "ua_call_method_result.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_read_response.h"
#include "ua_range.h"
#include "ua_reference_description.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_string.h"
#include "ua_to_string.h"
#include "ua_browse_path_target.h"
#include "ua_expanded_node_id.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_hierarchical_path.h"
#include "ua_translated_node_id.h"
#include "ua_variant.h"
#include "ua_unknown_structure.h"
#include "ua_ref_structure.h"
#include "ua_write_response.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <condition_variable>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::TypedAccess;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

class AtomicityObserver : public ua::client::ConnectionObserver
{
public:
  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    std::lock_guard lock(mMutex);
    mAdvisory = std::move(detail);
    mCondition.notify_all();
  }

  bool wait_for_advisory()
  {
    std::unique_lock lock(mMutex);
    return mCondition.wait_for(lock, std::chrono::seconds{1}, [&]() { return mAdvisory != nullptr; });
  }

  std::shared_ptr<const ua::ErrorDetail> advisory_detail()
  {
    std::lock_guard lock(mMutex);
    return mAdvisory;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::shared_ptr<const ua::ErrorDetail> mAdvisory;
};

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// Builds a single-result ReadResponse carrying @p dataValue.
ua::ReadResponse make_read_response(ua::DataValue dataValue)
{
  ua::ReadResponse response;
  response.results().push_back(std::move(dataValue));
  return response;
}

// Builds a single-result CallResponse carrying @p methodResult.
ua::CallResponse make_call_response(ua::CallMethodResult methodResult)
{
  ua::CallResponse response;
  response.results().push_back(std::move(methodResult));
  return response;
}

// Walks an ErrorDetail cause chain from @p head, returning {link count, terminal link}.
std::pair<std::size_t, const ua::ErrorDetail*> walk_error_chain(const ua::ErrorDetail* head)
{
  std::size_t depth = 0;
  const ua::ErrorDetail* last = nullptr;
  for (const ua::ErrorDetail* cursor = head; cursor != nullptr; cursor = cursor->cause.get())
  {
    ++depth;
    last = cursor;
  }
  return {depth, last};
}

// Returns the value of context key @p key on @p detail, or nullptr when absent.
const std::string* find_context_value(const ua::ErrorDetail& detail, std::string_view key)
{
  for (const auto& fact : detail.context)
  {
    if (fact.key == key)
    {
      return &fact.value;
    }
  }
  return nullptr;
}

const ua::ErrorDetail* find_chain_code(const ua::ErrorDetail* head, std::string_view code)
{
  for (const ua::ErrorDetail* link = head; link != nullptr; link = link->cause.get())
  {
    if (link->code == code)
    {
      return link;
    }
  }
  return nullptr;
}

// Builds a per-argument DiagnosticInfo pointing at @p symbolicIndex / @p localizedIndex in the response
// string table and carrying @p innerStatus as its inner status code.
ua::DiagnosticInfo make_argument_diagnostic(
  int32_t symbolicIndex, int32_t localizedIndex, ua::StatusCode innerStatus)
{
  ua::DiagnosticInfo diagnostic;
  diagnostic.symbolic_id() = symbolicIndex;
  diagnostic.localized_text() = localizedIndex;
  diagnostic.inner_status_code() = innerStatus;
  return diagnostic;
}

// Builds a DiagnosticInfo nested @p levels deep via innerDiagnosticInfo (each layer symbolic_id 0), for
// the decode depth-cap pin.
ua::DiagnosticInfo make_deep_argument_diagnostic(int levels)
{
  std::unique_ptr<ua::DiagnosticInfo> chain;
  for (int level = 0; level < levels; ++level)
  {
    auto node = std::make_unique<ua::DiagnosticInfo>();
    node->symbolic_id() = 0;
    node->inner_diagnostic_info() = std::move(chain);
    chain = std::move(node);
  }
  return std::move(*chain);
}

// A live Active ConnectionImpl plus the handles under test.
class TypedAccessTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<AtomicityObserver> mAtomicityObserver = std::make_shared<AtomicityObserver>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    ConnectionConfig config;
    config.observers.connection = mAtomicityObserver;
    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      std::move(config),
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

  Connection make_connection()
  {
    return ConnectionHandleFactory::make_connection(mConnection);
  }

  TypedAccess make_typed_access()
  {
    return ConnectionHandleFactory::make_typed_access(mConnection);
  }

  /// Answers the next TranslateBrowsePaths call with one Good path result carrying these targets.
  void set_translate_targets(const std::vector<ua::client::TranslatedNodeId>& targets)
  {
    ua::BrowsePathResult perPath;
    for (const auto& translated : targets)
    {
      ua::BrowsePathTarget target;
      target.target_id() = translated.targetId;
      target.remaining_path_index() = translated.remainingPathIndex;
      perPath.targets().push_back(std::move(target));
    }
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    response.results().push_back(std::move(perPath));
    mSession->translateBrowsePaths.set_result(
      Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  }

  void restart_with_address_space_cache()
  {
    std::promise<VoidResult> closed;
    auto closeFuture = closed.get_future();
    mConnection->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
    ASSERT_TRUE(closeFuture.get().is_good());

    mSession = std::make_shared<FakeSessionOps>();
    mReopen = std::make_shared<FakeReopen>();
    ConnectionConfig config;
    config.addressSpaceCache.enabled = true;
    config.addressSpaceCache.useRegisterNodes = false;
    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      config,
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    std::promise<VoidResult> started;
    auto startFuture = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(startFuture.get().is_good());
  }

  void script_shape_metadata(
    std::vector<std::pair<std::int32_t, std::optional<std::vector<std::uint32_t>>>> shapes)
  {
    mSession->read.set_result_fn(
      [shapes = std::move(shapes)](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
      {
        if (request.nodes_to_read().size() != shapes.size() * 2)
        {
          return Result<ua::ReadResponse>{Status::BadUnexpectedError};
        }
        ua::ReadResponse response;
        for (const auto& [rank, dimensions] : shapes)
        {
          response.results().push_back(ua::DataValue{ua::Variant{rank}});
          if (!dimensions)
          {
            response.results().push_back(ua::DataValue{});
            continue;
          }
          ua::Array<std::uint32_t> dimensionArray;
          dimensionArray.payload() = *dimensions;
          response.results().push_back(ua::DataValue{ua::Variant{std::move(dimensionArray)}});
        }
        return Result<ua::ReadResponse>{std::move(response)};
      });
  }

  void script_scalar_shape_metadata(std::size_t count = 1)
  {
    script_shape_metadata(
      std::vector<std::pair<std::int32_t, std::optional<std::vector<std::uint32_t>>>>(count, {-1, {}}));
  }

  void script_single_method_input(ua::NodeId declaredDataType)
  {
    const ua::NodeId inputArgumentsNode{2, 3901U};
    mSession->browse.set_result_fn(
      [inputArgumentsNode](const ua::BrowseRequest& request) -> Result<ua::BrowseResponse>
      {
        ua::BrowseResponse response;
        ua::BrowseResult result;
        result.status_code() = ua::Status::Good;
        if (request.nodes_to_browse()[0].reference_type_id() == ua::NodeId{ua::ReferenceTypeId::HasProperty})
        {
          ua::ReferenceDescription description;
          description.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasProperty};
          description.is_forward() = true;
          description.node_id().node_id() = inputArgumentsNode;
          description.node_class() = ua::NodeClass::Variable;
          description.browse_name() = ua::QualifiedName{0, "InputArguments"};
          result.references().push_back(std::move(description));
        }
        response.results().push_back(std::move(result));
        return Result<ua::BrowseResponse>{std::move(response)};
      });
    mSession->read.set_result_fn(
      [inputArgumentsNode, declaredDataType = std::move(declaredDataType)](
        const ua::ReadRequest& request) -> Result<ua::ReadResponse>
      {
        EXPECT_EQ(request.nodes_to_read()[0].node_id(), inputArgumentsNode);
        auto argument = std::make_unique<ua::Argument>();
        argument->name() = ua::String{"value"};
        argument->data_type() = declaredDataType;
        argument->value_rank() = -1;
        ua::Array<ua::RefStructure<ua::Structure>> arguments;
        arguments.push_back(ua::RefStructure<ua::Structure>{std::move(argument)});
        return Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::move(arguments)}})};
      });
  }

  void script_ranged_value_read(ua::DataValue value, std::int32_t valueRank)
  {
    mSession->read.set_result_fn(
      [value = std::move(value), valueRank](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
      {
        if (!request.nodes_to_read().empty() && request.nodes_to_read()[0].attribute_id() ==
                                                  static_cast<ua::IntegerId>(ua::AttributeId::ValueRank))
        {
          return Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{valueRank}})};
        }
        return Result<ua::ReadResponse>{make_read_response(value)};
      });
  }

  template<typename Response, typename Invoke>
  Result<Response> await(Invoke invoke)
  {
    std::promise<Result<Response>> done;
    auto future = done.get_future();
    invoke([&done](Result<Response> result) { done.set_value(std::move(result)); });
    return future.get();
  }
};

// ===================== Connection::read_value<T> =====================

TEST_F(TypedAccessTest, ReadValueTypedDecodesGoodValue)
{
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{int32_t{42}}})});

  auto connection = make_connection();
  auto result =
    await<int32_t>([&](auto cb) { connection.read_value_async<int32_t>(ua::NodeId{0, 42}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 42);
}

// @verifies CL-ATTR-005
// @verifies CL-ATTR-006
// @relation(CL-ATTR-005, CL-ATTR-006, scope=function)
TEST_F(TypedAccessTest, ReadValueTypedFlattensBadSeverityValueQuality)
{
  // Good service, but the DataValue carries a Bad-SEVERITY value quality AND a present value (a
  // non-conformant but observed server shape - CTT Attr/Read Err-004/025). The typed sugar FLATTENS the Bad
  // quality into the outer Result (matching the bulk read's is_bad() gate) rather than handing back a value
  // the server marked bad. Uncertain / DA-substatus are preserved (see
  // ReadValueTypedPreservesUncertainQuality). RED before the flatten: the old two-layer path returned a Good
  // typed Result carrying the decoded 7.
  // The quality StatusCode carries an ErrorDetail so the flatten's detail-preservation is asserted, not just
  // assumed (section 3.1 coverage note): the funnel/server-attached quality detail must ride through the
  // flatten.
  ua::StatusCode badWithDetail{
    Status::BadDeviceFailure, ua::make_error_detail("Quality", "sensor fault", "server.device")};
  ua::DataValue badQuality{ua::Variant{int32_t{7}}, badWithDetail};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(badQuality)});

  auto connection = make_connection();
  auto typedResult =
    await<int32_t>([&](auto cb) { connection.read_value_async<int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(typedResult.is_bad()) << "a Bad-severity value quality flattens into the typed Result "
                                       "(CL-ATTR-005/006), not decoded to a bogus T";
  EXPECT_EQ(typedResult.status_code().value(), ua::StatusCode{Status::BadDeviceFailure}.value());
  ASSERT_NE(typedResult.shared_detail(), nullptr) << "the value-quality ErrorDetail must survive the flatten";
  EXPECT_EQ(typedResult.shared_detail()->source, "server.device");
}

// @verifies CL-DA-015
// @verifies CL-SM-002
// @relation(CL-DA-015, CL-SM-002, scope=function)
TEST_F(TypedAccessTest, ReadValueDataValuePreservesBadQualityTwoLayer)
{
  // The DataValue path KEEPS the two-layer model (CL-DA-015/CL-SM-002): a Bad value quality rides on
  // DataValue::status() while the outer Result<DataValue> stays Good. Only the TYPED sugar flattens; the
  // DataValue form preserves the quality distinct from the service status.
  ua::DataValue badQuality{ua::Variant{int32_t{7}}, ua::StatusCode{Status::BadDeviceFailure}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(badQuality)});

  auto connection = make_connection();
  auto dataValueResult =
    await<ua::DataValue>([&](auto cb) { connection.read_value_async(ua::NodeId{0, 7}, std::move(cb)); });
  ASSERT_TRUE(dataValueResult.is_good()) << "the outer Result is Good on a good service result";
  ASSERT_TRUE(dataValueResult.value().status().has_value());
  EXPECT_EQ(dataValueResult.value().status()->value(), ua::StatusCode{Status::BadDeviceFailure}.value())
    << "the value quality is visible on DataValue::status() (surfaced, not flattened)";
}

// @verifies CL-ATTR-005
// @relation(CL-ATTR-005, scope=function)
// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(TypedAccessTest, ReadValueTypedPreservesUncertainQuality)
{
  // Only BAD severity flattens: an Uncertain-severity quality with a present, decodable value still decodes,
  // and the typed Result holds the value with the Uncertain code. A gate that flattened !is_good() would
  // wrongly drop the value; one that answered plain Good would drop the code.
  ua::DataValue uncertain{ua::Variant{int32_t{42}}, ua::StatusCode{Status::UncertainInitialValue}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(uncertain)});

  auto connection = make_connection();
  auto typedResult =
    await<int32_t>([&](auto cb) { connection.read_value_async<int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(typedResult.is_uncertain()) << "an Uncertain quality is preserved (decoded), not flattened";
  EXPECT_EQ(typedResult.status_code().value(), ua::StatusCode{Status::UncertainInitialValue}.value());
  EXPECT_EQ(typedResult.value_or(0), 42);
}

// @verifies CL-ATTR-005
// @verifies CL-ATTR-005
// @verifies CL-ATTR-006
// @relation(CL-ATTR-005, CL-ATTR-006, scope=function)
TEST_F(TypedAccessTest, ReadValueTypedBadDataValueWithNullValueYieldsBadResult)
{
  // The conformant Bad case: a Bad DataValue carries a null Value (CL-ATTR-006). The typed sugar must NOT
  // hand back a bogus typed value. The Bad-severity flatten (CL-ATTR-005/006) now short-circuits this BEFORE
  // any decode attempt, surfacing the exact quality status (previously it relied on the null Variant failing
  // to decode to Bad_UnexpectedError - the flatten preserves the real Bad_NodeIdUnknown instead).
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::StatusCode{Status::BadNodeIdUnknown}})});

  auto connection = make_connection();
  auto result =
    await<int32_t>([&](auto cb) { connection.read_value_async<int32_t>(ua::NodeId{0, 99}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "a null-Value Bad DataValue must not decode to a typed value";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadNodeIdUnknown}.value())
    << "the flatten surfaces the exact quality status, not a generic decode-failure code";
}

// @verifies CL-ATTR-005
// @verifies CL-ATTR-006
// @relation(CL-ATTR-005, CL-ATTR-006, scope=function)
TEST_F(TypedAccessTest, TryReadValueSyncTypedFlattensBadSeverityQuality)
{
  // Sync/async parity (section 7.2): try_read_value_sync<T> flattens a Bad-severity value quality identically
  // to the async path (both single-typed-read sites in ua_connection.h). RED before the sync-path flatten.
  ua::DataValue badQuality{ua::Variant{int32_t{7}}, ua::StatusCode{Status::BadDeviceFailure}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(badQuality)});

  auto connection = make_connection();
  auto result = connection.try_read_value_sync<int32_t>(ua::NodeId{0, 7});
  ASSERT_TRUE(result.is_bad()) << "the sync typed read flattens Bad quality (parity with async)";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadDeviceFailure}.value());
}

TEST_F(TypedAccessTest, ReadValueTypedWrongTypeReturnsTypeMismatch)
{
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{int32_t{5}}})});

  auto connection = make_connection();
  auto result =
    await<double>([&](auto cb) { connection.read_value_async<double>(ua::NodeId{0, 5}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
}

TEST_F(TypedAccessTest, ReadValueTypedServiceFailurePropagatesUnchanged)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied},
    ua::make_error_detail("Downstream", "scripted tier-0 failure", "test.downstream")});

  auto connection = make_connection();
  auto result =
    await<int32_t>([&](auto cb) { connection.read_value_async<int32_t>(ua::NodeId{0, 1}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value());
  ASSERT_NE(result.shared_detail(), nullptr) << "the service ErrorDetail must survive the decode wrap";
}

// ===================== ua::args + call_method forwarding =====================

TEST_F(TypedAccessTest, ArgsBoxesNativeValuesToVariants)
{
  auto boxed = ua::client::args(int32_t{3}, "on", 4.2, true);
  ASSERT_EQ(boxed.size(), 4u);
  EXPECT_TRUE(boxed[0].is_int32());
  EXPECT_EQ(boxed[0].to<int32_t>().value(), 3);
  EXPECT_TRUE(boxed[1].is_string()) << "a string literal must box through ua::String";
  EXPECT_EQ(boxed[1].to<ua::String>().value(), ua::String{"on"});
  EXPECT_TRUE(boxed[2].is_double());
  EXPECT_DOUBLE_EQ(boxed[2].to<double>().value(), 4.2);
  EXPECT_TRUE(boxed[3].is_boolean());
  EXPECT_TRUE(boxed[3].to<bool>().value());
}

// @verifies CL-METH-001
// @verifies CL-METH-002
// @verifies CL-METH-003
// @relation(CL-METH-001, CL-METH-002, CL-METH-003, scope=function)
TEST_F(TypedAccessTest, CallMethodForwardsObjectMethodAndArgsInOrder)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::Good};
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(methodResult)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb)
    {
      typed.call_method_async(
        ua::NodeId{0, 100}, ua::NodeId{0, 200}, ua::client::args(int32_t{3}, 4.2), std::move(cb));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->call.call_count(), 1u);
  const auto requests = mSession->call.requests();
  ASSERT_EQ(requests.size(), 1u);
  const auto& methodsToCall = requests.back().methods_to_call();
  ASSERT_EQ(methodsToCall.size(), 1u);
  EXPECT_EQ(methodsToCall[0].object_id(), (ua::NodeId{0, 100}));
  EXPECT_EQ(methodsToCall[0].method_id(), (ua::NodeId{0, 200}));
  const auto& inputArguments = methodsToCall[0].input_arguments();
  ASSERT_EQ(inputArguments.size(), 2u);
  EXPECT_EQ(inputArguments[0].to<int32_t>().value(), 3);
  EXPECT_DOUBLE_EQ(inputArguments[1].to<double>().value(), 4.2);
}

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(TypedAccessTest, CallMethodStructuredInputMatchesDeclaredDataTypeThroughResolver)
{
  script_single_method_input(ua::NodeId{ua::DataTypeId::Range});
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::Good};
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(methodResult)});
  ua::Range range;
  range.low() = 1.0;
  range.high() = 2.0;

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto callback)
    {
      typed.call_method_async(
        ua::NodeId{2, 3800U}, ua::NodeId{2, 3801U}, {ua::Variant{range}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->call.call_count(), 1U);
  EXPECT_GE(mSession->browse.call_count(), 2U)
    << "structured Call preflight must inspect InputArguments and optional descriptions";
}

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(TypedAccessTest, CallMethodStructuredSubtypeMatchesDeclaredSupertype)
{
  script_single_method_input(ua::NodeId{ua::DataTypeId::Structure});
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::Good};
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(methodResult)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto callback)
    {
      typed.call_method_async(
        ua::NodeId{2, 3802U}, ua::NodeId{2, 3803U}, {ua::Variant{ua::Range{}}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(mSession->call.call_count(), 1U)
    << "a concrete Structure subtype must satisfy a declared Structure supertype";
}

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(TypedAccessTest, CallMethodStructuredArrayValidatesEveryElementDataType)
{
  script_single_method_input(ua::NodeId{ua::DataTypeId::Range});
  ua::Array<ua::RefStructure<ua::Structure>> values;
  values.push_back(ua::RefStructure<ua::Structure>{std::make_unique<ua::Range>()});
  values.push_back(ua::RefStructure<ua::Structure>{std::make_unique<ua::Argument>()});
  const auto callsBefore = mSession->call.call_count();

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto callback)
    {
      typed.call_method_async(
        ua::NodeId{2, 3804U}, ua::NodeId{2, 3805U}, {ua::Variant{std::move(values)}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MethodStructuredArgumentTypeMismatch");
  EXPECT_EQ(mSession->call.call_count(), callsBefore)
    << "one mismatched element must reject the complete structured-array argument before Call";
}

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(TypedAccessTest, CallMethodStructuredInputMismatchFailsLocallyWithDetail)
{
  script_single_method_input(ua::NodeId{ua::DataTypeId::Argument});
  ua::Range range;
  const auto callsBefore = mSession->call.call_count();

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto callback)
    {
      typed.call_method_async(
        ua::NodeId{2, 3810U}, ua::NodeId{2, 3811U}, {ua::Variant{range}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MethodStructuredArgumentTypeMismatch");
  EXPECT_EQ(mSession->call.call_count(), callsBefore);
}

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST_F(TypedAccessTest, CallMethodUnknownStructuredEncodingFailsLocallyWithDetail)
{
  script_single_method_input(ua::NodeId{ua::DataTypeId::Range});
  ua::UnknownStructure unknown{
    ua::NodeId{7, 987654U}, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{0x01, 0x02}};
  const auto callsBefore = mSession->call.call_count();

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto callback)
    {
      typed.call_method_async(
        ua::NodeId{2, 3820U}, ua::NodeId{2, 3821U}, {ua::Variant{std::move(unknown)}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadDataEncodingInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MethodStructuredArgumentEncodingUnknown");
  EXPECT_EQ(mSession->call.call_count(), callsBefore);
}

TEST_F(TypedAccessTest, CallMethodSurfacesPerMethodBadStatus)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadMethodInvalid};
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(methodResult)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a good service result yields a Good outer Result (two-layer)";
  EXPECT_TRUE(result.value().is_bad()) << "the inner CallResult carries the per-method Bad status";
  EXPECT_EQ(result.value().status_code().value(), ua::StatusCode{Status::BadMethodInvalid}.value());
}

// The Call facade must flatten a bad ResponseHeader.serviceResult into a bad outer Result (mirroring the
// read/write value facades); the tier-0 funnel returns the CallResponse verbatim, so a Good-looking
// per-method results array underneath must not mask a service-level failure.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodFlattensBadServiceResult)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::Good};
  ua::CallResponse response = make_call_response(methodResult);
  response.response_header().service_result() = ua::StatusCode{Status::BadServiceUnsupported};
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "a bad serviceResult must surface as a bad outer Result, not be masked "
                                  "by a Good-looking results array";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadServiceUnsupported}.value());
  ASSERT_NE(result.error_detail(), nullptr) << "the collapsed Result must carry the wire-crossing marker";
  // CL-DIAG-005: the funnel collapses the bad serviceResult (with the marker) before the facade's call_method
  // flatten wrap; the facade propagates the marker. CL-METH-005 non-masking still holds (bad Result
  // surfaces).
  EXPECT_EQ(result.error_detail()->source, "client.tier1.connection.call");
  ASSERT_NE(result.error_detail()->cause, nullptr);
  EXPECT_EQ(result.error_detail()->cause->source, "client.tier0.session.decode_diagnostic");
}

// The Call facade must reject a result-count mismatch: a single-method Call must return exactly one
// CallMethodResult. Zero or more-than-one cannot be positionally stitched to the one requested method.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodRejectsResultCountMismatch)
{
  // Two results for a single requested method: the funnel returns them verbatim, so the facade must reject.
  ua::CallResponse response;
  response.results().push_back(ua::CallMethodResult{});
  response.results().push_back(ua::CallMethodResult{});
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "a result count != 1 for a single-method Call must be rejected";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value());
}

// The empty-results boundary of the count guard: a Good service response carrying zero CallMethodResults
// for the single requested method must be rejected (not indexed as if a slot existed).
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodRejectsEmptyResults)
{
  ua::CallResponse response;  // zero results
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "an empty results array for a single-method Call must be rejected";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value());
}

// CL-METH-006: outputArguments are dropped only when Severity is Bad. An Uncertain per-method status must
// KEEP the full CallMethodResult (with its outputArguments) rather than collapse the inner CallResult, so
// the caller can still consume the outputs of an uncertain-but-successful invocation.
// @verifies CL-METH-006
// @relation(CL-METH-006, scope=function)
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(TypedAccessTest, CallMethodPreservesResultOnUncertainStatus)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::UncertainInitialValue};
  methodResult.output_arguments().push_back(ua::Variant{int32_t{111}});
  methodResult.output_arguments().push_back(ua::Variant{int32_t{222}});
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(methodResult)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a good service result yields a Good outer Result (two-layer)";
  ASSERT_TRUE(result.value().is_uncertain())
    << "an Uncertain per-method status is the inner CallResult's status, holding the CallMethodResult "
       "(CL-METH-006: only Bad drops outputArguments)";
  EXPECT_TRUE(result.value().value().status_code().is_uncertain());
  EXPECT_EQ(result.value().status_code(), ua::StatusCode{Status::UncertainInitialValue});
  EXPECT_EQ(result.value().value().status_code(), ua::StatusCode{Status::UncertainInitialValue});
  ASSERT_EQ(result.value().value().output_arguments().size(), 2u)
    << "an Uncertain status must preserve the server's outputArguments";
  EXPECT_EQ(result.value().value().output_arguments()[0].to<int32_t>().value(), 111);
  EXPECT_EQ(result.value().value().output_arguments()[1].to<int32_t>().value(), 222);
}

// ===================== CL-METH-005: per-argument inputArgumentDiagnosticInfos -> ErrorDetail =========

// The per-op twin of CL-BASEDIAG-001: on a Bad per-method Call status the facade must thread the
// server's per-argument DiagnosticInfo for the first-bad argument into the CallMethodBadPerMethodStatus
// ErrorDetail's cause chain (error_handling.md: never silently discard an ErrorDetail), not just chain the
// bare status. The decoded chain crosses the wire-boundary marker and carries the resolved symbolic id +
// localized text + inner status code.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodThreadsPerArgumentDiagnosticIntoCause)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  // The good argument has no diagnostic; the bad one (index 1) carries a rich server DiagnosticInfo.
  methodResult.input_argument_diagnostic_infos().push_back(ua::DiagnosticInfo{});
  methodResult.input_argument_diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/0, /*localizedIndex=*/1, ua::StatusCode{Status::BadTypeMismatch}));

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.response_header().string_table().payload().emplace_back("BadArgumentTypeSymbolic");  // index 0
  response.response_header().string_table().payload().emplace_back(
    "the input argument type does not match the method signature");  // index 1
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a good service result yields a Good outer Result (two-layer)";
  ASSERT_TRUE(result.value().is_bad()) << "the inner CallResult carries the per-method Bad status";
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr) << "the bad per-method path must carry a source-tagged ErrorDetail";
  EXPECT_EQ(detail->code, "CallMethodBadPerMethodStatus");

  // First-bad breadcrumb preserved on the outer layer.
  const std::string* operationIndex = find_context_value(*detail, "operation.index");
  ASSERT_NE(operationIndex, nullptr);
  EXPECT_EQ(*operationIndex, "1");
  const std::string* countTotal = find_context_value(*detail, "count.total");
  ASSERT_NE(countTotal, nullptr);
  EXPECT_EQ(*countTotal, "1");

  // The decoded per-argument DiagnosticInfo hangs below the outer layer, capped by the wire-crossing
  // marker. (RED before the fix: the cause is the bare status, which carries no ErrorDetail, so mCause is
  // null.)
  ASSERT_NE(detail->cause, nullptr)
    << "the first-bad argument's DiagnosticInfo must be threaded into the cause chain, not discarded";
  const ua::ErrorDetail* marker = detail->cause.get();
  EXPECT_EQ(marker->source, "client.tier0.session.decode_diagnostic")
    << "the decoded server chain must cross the wire-boundary marker";
  EXPECT_EQ(ua::StatusCode{marker->innerStatus}, ua::StatusCode{Status::BadTypeMismatch})
    << "the marker records the first-bad argument's status as the terminal code";
  const std::string* markerIndex = find_context_value(*marker, "operation.index");
  ASSERT_NE(markerIndex, nullptr);
  EXPECT_EQ(*markerIndex, "1");

  ASSERT_NE(marker->cause, nullptr) << "the decoded server DiagnosticInfo link must hang below the marker";
  const ua::ErrorDetail* serverLink = marker->cause.get();
  EXPECT_EQ(serverLink->code, "server.symbolic.BadArgumentTypeSymbolic")
    << "the symbolic id resolves via the response string table, server-prefixed";
  EXPECT_EQ(serverLink->summary, "the input argument type does not match the method signature")
    << "the localized text resolves via the response string table";
  EXPECT_EQ(ua::StatusCode{serverLink->innerStatus}, ua::StatusCode{Status::BadTypeMismatch})
    << "the server DiagnosticInfo's innerStatusCode is preserved";
}

// @verifies AC-CL-METH-005-PER-METHOD-DIAGNOSTIC-REACHES-STATUS
// @relation(AC-CL-METH-005-PER-METHOD-DIAGNOSTIC-REACHES-STATUS, scope=function)
TEST_F(TypedAccessTest, CallMethodThreadsPerOperationDiagnosticIntoStatusDetail)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/0, /*localizedIndex=*/1, ua::StatusCode{Status::BadInvalidArgument}));
  response.response_header().string_table().payload().emplace_back("ReferenceDivideByZero");
  response.response_header().string_table().payload().emplace_back(
    "Divide rejected the request because the divisor was zero");
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a good Call service result preserves the two-layer result shape";
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CallMethodBadPerMethodStatus");

  ASSERT_NE(detail->cause, nullptr)
    << "the parallel per-method DiagnosticInfo must remain attached to the inner StatusCode";
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  const std::string* operationIndex = find_context_value(*detail->cause, "operation.index");
  ASSERT_NE(operationIndex, nullptr);
  EXPECT_EQ(*operationIndex, "0");

  const ua::ErrorDetail* serverDetail = find_chain_code(detail, "server.symbolic.ReferenceDivideByZero");
  ASSERT_NE(serverDetail, nullptr);
  EXPECT_EQ(serverDetail->summary, "Divide rejected the request because the divisor was zero");
}

// @verifies AC-CL-METH-005-PER-METHOD-DIAGNOSTIC-REACHES-STATUS
// @relation(AC-CL-METH-005-PER-METHOD-DIAGNOSTIC-REACHES-STATUS, scope=function)
TEST_F(TypedAccessTest, CallMethodPreservesOperationAndArgumentDiagnostics)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  methodResult.input_argument_diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/2, /*localizedIndex=*/3, ua::StatusCode{Status::BadTypeMismatch}));

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/0, /*localizedIndex=*/1, ua::StatusCode{Status::BadInvalidArgument}));
  response.response_header().string_table().payload().emplace_back("ReferenceMethodRejected");
  response.response_header().string_table().payload().emplace_back("The Method rejected the request");
  response.response_header().string_table().payload().emplace_back("ReferenceArgumentRejected");
  response.response_header().string_table().payload().emplace_back("The first argument was invalid");
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_NE(find_chain_code(detail, "server.symbolic.ReferenceMethodRejected"), nullptr)
    << "the per-operation diagnostic must not be discarded";
  EXPECT_NE(find_chain_code(detail, "server.symbolic.ReferenceArgumentRejected"), nullptr)
    << "the per-argument diagnostic must not be discarded when an operation diagnostic also exists";
}

// Strict no-op guard: when the server sends NO per-argument diagnostics the detail is byte-for-byte the
// current first-bad-index + count + bare-status cause. Guards every existing bad-Call test against a
// spurious cause-chain mutation on the default (no-diagnostics) path.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodFallsBackToBareStatusWhenNoPerArgumentDiagnostics)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  // No input_argument_diagnostic_infos at all - the conformant returnDiagnostics=0 shape.
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(std::move(methodResult))});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CallMethodBadPerMethodStatus");
  const std::string* operationIndex = find_context_value(*detail, "operation.index");
  ASSERT_NE(operationIndex, nullptr);
  EXPECT_EQ(*operationIndex, "1");
  const std::string* countTotal = find_context_value(*detail, "count.total");
  ASSERT_NE(countTotal, nullptr);
  EXPECT_EQ(*countTotal, "1");
  EXPECT_EQ(ua::StatusCode{detail->innerStatus}, ua::StatusCode{Status::BadTypeMismatch})
    << "the first-bad argument's bare status is threaded as the inner status";
  EXPECT_EQ(detail->cause, nullptr)
    << "with no per-arg diagnostics the cause is the bare status only (strict no-op)";
}

// section 3.1 index-bounds pin: a non-conformant server may send fewer inputArgumentDiagnosticInfos than
// inputArgumentResults. The first-bad index (1) is then out of range for the diag-info array (size 1), so
// the decode must NOT index out of bounds and must NOT misuse the good argument's diagnostic at index 0 -
// it falls back to the bare-status cause.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodBoundsChecksFirstBadArgumentAgainstDiagnostics)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  // Only ONE diagnostic (for the good argument at index 0); index 1 (the first-bad) is out of range.
  methodResult.input_argument_diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/0, /*localizedIndex=*/0, ua::StatusCode{Status::BadInternalError}));

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.response_header().string_table().payload().emplace_back("WrongArgumentDiagnostic");
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CallMethodBadPerMethodStatus");
  EXPECT_EQ(ua::StatusCode{detail->innerStatus}, ua::StatusCode{Status::BadTypeMismatch})
    << "the first-bad argument's own status (not the mismatched index-0 diagnostic) is threaded";
  EXPECT_EQ(detail->cause, nullptr)
    << "an out-of-range first-bad index must fall back to the bare-status cause, never index OOB";
}

// section 3.1 decode-DoS depth-cap pin: a hostile per-argument DiagnosticInfo nested past maxChainDepth (32)
// must be truncated with a bounded amount of work - the decoded cause ends in a CHAIN_TRUNCATED sentinel and
// the total chain length is bounded (outer + marker + 32 server links + sentinel).
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodCapsDeepPerArgumentDiagnosticChain)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  methodResult.input_argument_diagnostic_infos().push_back(ua::DiagnosticInfo{});
  methodResult.input_argument_diagnostic_infos().push_back(make_deep_argument_diagnostic(/*levels=*/40));

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.response_header().string_table().payload().emplace_back("L");
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);

  auto [depth, terminal] = walk_error_chain(detail);
  // outer(1) + marker(1) + 32 server links + truncation sentinel(1).
  EXPECT_EQ(depth, 35u);
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
  EXPECT_EQ(terminal->source, "client.diagnostic.truncated");
  const std::string* omitted = find_context_value(*terminal, "omitted_depth");
  ASSERT_NE(omitted, nullptr);
  EXPECT_EQ(*omitted, "8") << "40 nested levels minus the 32-deep cap";
}

// section 3.1 malformed-index pin: a hostile per-argument DiagnosticInfo whose string-table indices are
// negative / out of range must not crash or throw out of the accessor - the decoder resolves them to bounded
// "<unknown:N>" placeholders and delivers a well-formed chain.
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodToleratesMalformedPerArgumentDiagnosticIndices)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  ua::DiagnosticInfo malformed;
  malformed.symbolic_id() = -1;  // negative index
  malformed.namespace_uri() = -1;
  malformed.localized_text() = 999999;  // out of range for the (empty) string table
  malformed.inner_status_code() = ua::StatusCode{Status::BadTypeMismatch};
  methodResult.input_argument_diagnostic_infos().push_back(ua::DiagnosticInfo{});
  methodResult.input_argument_diagnostic_infos().push_back(std::move(malformed));

  // Deliberately no string table entries - every index above is unresolvable.
  mSession->call.set_result(Result<ua::CallResponse>{make_call_response(std::move(methodResult))});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  // The call completes (no crash / no throw out of the accessor) and the chain is well-formed.
  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr) << "the malformed diagnostic still yields a decoded (marker) chain";
  const ua::ErrorDetail* marker = detail->cause.get();
  ASSERT_NE(marker->cause, nullptr);
  const ua::ErrorDetail* serverLink = marker->cause.get();
  EXPECT_EQ(serverLink->summary, "<unknown:999999>")
    << "an out-of-range localized-text index resolves to a bounded placeholder, not a crash";
  EXPECT_EQ(ua::StatusCode{serverLink->innerStatus}, ua::StatusCode{Status::BadTypeMismatch})
    << "the inner status code is still preserved through a malformed diagnostic";
}

// The decoded chain's recorded operation index must match the FIRST-bad argument index, even when earlier
// arguments are Good (the first-bad breadcrumb is index 2 here, not 0).
// @verifies CL-METH-005
// @relation(CL-METH-005, scope=function)
TEST_F(TypedAccessTest, CallMethodPerArgumentChainRecordsFirstBadArgumentIndex)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::BadInvalidArgument};
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::Good});
  methodResult.input_argument_results().push_back(ua::StatusCode{Status::BadTypeMismatch});
  methodResult.input_argument_diagnostic_infos().push_back(ua::DiagnosticInfo{});
  methodResult.input_argument_diagnostic_infos().push_back(ua::DiagnosticInfo{});
  methodResult.input_argument_diagnostic_infos().push_back(make_argument_diagnostic(
    /*symbolicIndex=*/0, /*localizedIndex=*/0, ua::StatusCode{Status::BadTypeMismatch}));

  ua::CallResponse response = make_call_response(std::move(methodResult));
  response.response_header().string_table().payload().emplace_back("ThirdArgumentBad");
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_bad());
  const ua::ErrorDetail* detail = result.value().error_detail();
  ASSERT_NE(detail, nullptr);
  const std::string* operationIndex = find_context_value(*detail, "operation.index");
  ASSERT_NE(operationIndex, nullptr);
  EXPECT_EQ(*operationIndex, "2") << "the first-bad breadcrumb is argument index 2";
  ASSERT_NE(detail->cause, nullptr);
  const std::string* markerIndex = find_context_value(*detail->cause, "operation.index");
  ASSERT_NE(markerIndex, nullptr);
  EXPECT_EQ(*markerIndex, "2") << "the decoded chain records the first-bad argument index";
}

// ===================== TypedAccess attribute + bulk forwarding =====================

// @verifies CL-ATTR-007
// @verifies CL-ATTR-014
// @relation(CL-ATTR-007, CL-ATTR-014, scope=function)
TEST_F(TypedAccessTest, ReadAttributeComposesRequestedAttributeId)
{
  auto typed = make_typed_access();
  auto result = await<ua::DataValue>([&](auto cb)
    { typed.read_attribute_async(ua::NodeId{0, 85}, ua::AttributeId::BrowseName, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  // Call 1 = bootstrap NamespaceArray Read; call 2 = the read_attribute under test.
  ASSERT_EQ(mSession->read.call_count(), 2u);
  const auto requests = mSession->read.requests();
  const auto& nodesToRead = requests.back().nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 1u);
  EXPECT_EQ(nodesToRead[0].node_id(), (ua::NodeId{0, 85}));
  EXPECT_EQ(nodesToRead[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::BrowseName));
  EXPECT_TRUE(nodesToRead[0].data_encoding().is_null())
    << "tier-2 non-Value attribute reads must never populate DataEncoding";
}

// @verifies CL-ATTR-016
// @relation(CL-ATTR-016, scope=function)
TEST_F(TypedAccessTest, ExplicitBinaryEncodingIsForwardedAndMatchingBinaryBodyAccepted)
{
  ua::Variant encoded{ua::RefStructure<ua::Structure>{std::make_unique<ua::UnknownStructure>(
    ua::NodeId{1, 5001}, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{0x01})}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(ua::DataValue{std::move(encoded)})});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_value_with_encoding_async(
        ua::NodeId{2, 1601}, ua::QualifiedName{0, "Default Binary"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  const auto requests = mSession->read.requests();
  const auto& target = requests.back().nodes_to_read()[0];
  EXPECT_EQ(target.attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::Value));
  EXPECT_EQ(target.data_encoding(), (ua::QualifiedName{0, "Default Binary"}));
}

// @verifies CL-ATTR-016
// @relation(CL-ATTR-016, scope=function)
TEST_F(TypedAccessTest, ExplicitBinaryEncodingRejectsXmlBodyWithRichDetail)
{
  ua::Variant encoded{ua::RefStructure<ua::Structure>{std::make_unique<ua::UnknownStructure>(
    ua::NodeId{1, 5002}, ua::UnknownStructure::BodyEncoding::Xml, ua::ByteString{0x3c, 0x2f, 0x3e})}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(ua::DataValue{std::move(encoded)})});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_value_with_encoding_async(
        ua::NodeId{2, 1602}, ua::QualifiedName{0, "Default Binary"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataEncodingMismatch");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find("Default Binary"), std::string::npos);
  EXPECT_NE(ua::to_string(*result.shared_detail()).find("Default XML"), std::string::npos);
}

// @verifies CL-ATTR-016
// @relation(CL-ATTR-016, scope=function)
TEST_F(TypedAccessTest, ExplicitXmlEncodingRejectsConcreteBinaryStructure)
{
  ua::Variant encoded{ua::RefStructure<ua::Structure>{std::make_unique<ua::Argument>()}};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(ua::DataValue{std::move(encoded)})});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_value_with_encoding_async(
        ua::NodeId{2, 1603}, ua::QualifiedName{0, "Default XML"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataEncodingMismatch");
}

// @verifies CL-ATTR-016
// @relation(CL-ATTR-016, scope=function)
TEST_F(TypedAccessTest, ExplicitEncodingRejectsGoodNonStructureResponse)
{
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::int32_t{42}}})});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_value_with_encoding_async(
        ua::NodeId{2, 1604}, ua::QualifiedName{0, "Default Binary"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DataEncodingNonStructureResponse");
}

// @verifies CL-ATTR-010
// @relation(CL-ATTR-010, scope=function)
TEST_F(TypedAccessTest, ReadAttributeIndexRangeEncodesRangeAndAcceptsClippedResultLength)
{
  ua::DataValue partial{ua::Variant{ua::Array<int32_t>{3, 4, 5, 6, 7, 8, 9}}};
  script_ranged_value_read(std::move(partial), 1);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"3:100"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  auto values = result.value().value().to_vector<int32_t>();
  ASSERT_TRUE(values.is_good());
  EXPECT_EQ(values.value(), (std::vector<int32_t>{3, 4, 5, 6, 7, 8, 9}))
    << "the facade returns the server's actual clipped length, not the requested span";

  const auto requests = mSession->read.requests();
  const auto& nodesToRead = requests.back().nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 1u);
  EXPECT_EQ(nodesToRead[0].index_range(), ua::String{"3:100"});
}

// @verifies CL-ATTR-010
// @relation(CL-ATTR-010, scope=function)
TEST_F(TypedAccessTest, ReadAttributeIndexRangePreservesLowerOverflowStatusAndDetail)
{
  ua::DataValue noData;
  noData.status() = ua::StatusCode{Status::BadIndexRangeNoData,
    ua::make_error_detail("IndexRangeLowerBound", "lower bound exceeds the array length", "test.server")};
  script_ranged_value_read(std::move(noData), 1);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"20:30"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good()) << "the service completed; IndexRange failure is per-item quality";
  ASSERT_TRUE(result.value().status().has_value());
  EXPECT_EQ(*result.value().status(), ua::StatusCode{Status::BadIndexRangeNoData});
  ASSERT_NE(result.value().status()->shared_detail(), nullptr);
  EXPECT_EQ(result.value().status()->shared_detail()->code, "IndexRangeLowerBound");
}

// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST_F(TypedAccessTest, ReadAttributePreservesScalarStringSubstringRangeAndResult)
{
  script_ranged_value_read(ua::DataValue{ua::Variant{ua::String{"lo, W"}}}, -1);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"3:7"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().value().try_as<ua::String>(), nullptr);
  EXPECT_EQ(*result.value().value().try_as<ua::String>(), ua::String{"lo, W"});
  EXPECT_EQ(mSession->read.requests().back().nodes_to_read()[0].index_range(), ua::String{"3:7"});
}

// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST_F(TypedAccessTest, ReadAttributePreservesScalarByteStringSubstringRangeAndResult)
{
  ua::ByteString sliced{std::vector<uint8_t>{3, 4, 5, 6, 7}};
  script_ranged_value_read(ua::DataValue{ua::Variant{std::move(sliced)}}, -1);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"3:7"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  const auto* value = result.value().value().try_as<ua::ByteString>();
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(std::vector<uint8_t>(value->begin(), value->end()), (std::vector<uint8_t>{3, 4, 5, 6, 7}));
  EXPECT_EQ(mSession->read.requests().back().nodes_to_read()[0].index_range(), ua::String{"3:7"});
}

// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST_F(TypedAccessTest, ReadAttributePreservesArrayFinalSubstringRange)
{
  script_ranged_value_read(ua::DataValue{ua::Variant{ua::Array<ua::String>{ua::String{"rlie1"}}}}, 2);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"2,3:7"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  auto values = result.value().value().to_vector<ua::String>();
  ASSERT_TRUE(values.is_good());
  EXPECT_EQ(values.value(), (std::vector<ua::String>{ua::String{"rlie1"}}));
  EXPECT_EQ(mSession->read.requests().back().nodes_to_read()[0].index_range(), ua::String{"2,3:7"});
}

// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST_F(TypedAccessTest, ReadAttributePreservesWholeByteStringElementRange)
{
  ua::ByteString complete{std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}};
  script_ranged_value_read(ua::DataValue{ua::Variant{ua::Array<ua::ByteString>{std::move(complete)}}}, 1);

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{0, 85}, ua::AttributeId::Value, ua::String{"2"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  auto values = result.value().value().to_vector<ua::ByteString>();
  ASSERT_TRUE(values.is_good());
  ASSERT_EQ(values.value().size(), 1u);
  EXPECT_EQ(std::vector<uint8_t>(values.value()[0].begin(), values.value()[0].end()),
    (std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
  EXPECT_EQ(mSession->read.requests().back().nodes_to_read()[0].index_range(), ua::String{"2"});
}

// @verifies CL-ADDRSP-006
// @verifies CL-ATTR-008
// @relation(CL-ADDRSP-006, CL-ATTR-008, scope=function)
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST_F(TypedAccessTest, ReadAttributeRejectsMalformedNumericRangeBeforeAnyWireRead)
{
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  for (const ua::String range : {ua::String{"5:5"}, ua::String{"7:5"}, ua::String{"5 :7"}})
  {
    auto result = await<ua::DataValue>(
      [&](auto callback) {
        typed.read_attribute_async(ua::NodeId{2, 5000}, ua::AttributeId::Value, range, std::move(callback));
      });
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadIndexRangeInvalid});
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "NumericRangeSyntaxInvalid");
  }
  EXPECT_EQ(mSession->read.call_count(), readsBefore)
    << "syntax failures must precede both metadata and value Reads";
}

// @verifies AC-CL-ADDRSP-006-NUMERICRANGE
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST_F(TypedAccessTest, ReadAttributeRejectsPartialFixedRankRangeAfterMetadataAndBeforeValueRead)
{
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::int32_t{2}}})});
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1"}, std::move(callback));
    });

  // Answered as the server's Read answers it (DL-7 (b), DL-16): the Read succeeds and the value's status is
  // Bad_IndexRangeNoData, with the value null.
  ASSERT_TRUE(result.is_good()) << "the Read failed instead of answering the range's status in its value";
  ASSERT_TRUE(result.value().status().has_value());
  EXPECT_EQ(result.value().status()->as_status(), Status::BadIndexRangeNoData);
  ASSERT_NE(result.value().status()->shared_detail(), nullptr) << "the value's status carries no ErrorDetail";
  EXPECT_EQ(result.value().status()->shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_TRUE(result.value().value().empty()) << "a value whose status is bad carries a value";
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1)
    << "only the ValueRank metadata Read is permitted; the ranged Value Read must not be issued";
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST_F(TypedAccessTest, ReadAttributeValidCompleteRangeReadsMetadataThenForwardsExactRange)
{
  ua::Array<std::int32_t> selected{{2, 2}, std::vector<std::int32_t>{1, 2, 3, 4}};
  script_ranged_value_read(ua::DataValue{ua::Variant{std::move(selected)}}, 2);
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1,2:3"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 2);
  const auto requests = mSession->read.requests();
  ASSERT_GE(requests.size(), 2u);
  EXPECT_EQ(requests[requests.size() - 2].nodes_to_read()[0].attribute_id(),
    static_cast<ua::IntegerId>(ua::AttributeId::ValueRank));
  EXPECT_EQ(requests.back().nodes_to_read()[0].index_range(), ua::String{"0:1,2:3"});
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST_F(TypedAccessTest, ReadAttributePropagatesValueRankServiceFailureWithoutValueRead)
{
  mSession->read.set_result(Result<ua::ReadResponse>{Status::BadSessionClosed,
    ua::make_error_detail(
      "ValueRankTransportMarker", "the ValueRank metadata transport failed", "test.session")});
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadSessionClosed});
  ASSERT_NE(result.shared_detail(), nullptr);
  const auto [depth, terminal] = walk_error_chain(result.error_detail());
  EXPECT_GE(depth, 1u);
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "ValueRankTransportMarker");
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1);
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST_F(TypedAccessTest, ReadAttributePropagatesValueRankItemFailureWithoutValueRead)
{
  ua::DataValue failedRank;
  failedRank.status() = ua::StatusCode{Status::BadAttributeIdInvalid};
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(std::move(failedRank))});
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadAttributeIdInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeValueRankReadFailed");
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1);
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST_F(TypedAccessTest, ReadAttributeRejectsNonInt32ValueRankWithoutValueRead)
{
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{ua::String{"two"}}})});
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeValueRankTypeMismatch");
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1);
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST_F(TypedAccessTest, ReadAttributeRejectsWrongValueRankResultCountWithoutValueRead)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::ReadResponse{}});
  const auto readsBefore = mSession->read.call_count();
  auto typed = make_typed_access();

  auto result = await<ua::DataValue>(
    [&](auto callback)
    {
      typed.read_attribute_async(
        ua::NodeId{2, 5000}, ua::AttributeId::Value, ua::String{"0:1"}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadUnexpectedError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeValueRankResultCountMismatch");
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1);
}

// @verifies CL-ATTR-027
// @relation(CL-ATTR-027, scope=function)
TEST_F(TypedAccessTest, WriteAttributeForwardsCompleteDataValue)
{
  script_scalar_shape_metadata();
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  const ua::DateTime sourceTimestamp = ua::DateTime::now();
  const ua::DateTime serverTimestamp = ua::DateTime::now();
  ua::DataValue dataValue{ua::Variant{int32_t{123}}, ua::StatusCode{Status::GoodClamped}};
  dataValue.source_timestamp() = sourceTimestamp;
  dataValue.server_timestamp() = serverTimestamp;
  auto result = await<void>([&](auto cb)
    { typed.write_attribute_async(ua::NodeId{0, 10}, ua::AttributeId::Value, dataValue, std::move(cb)); });

  EXPECT_TRUE(result.is_good());
  ASSERT_EQ(mSession->write.call_count(), 1u);
  const auto requests = mSession->write.requests();
  const auto& nodesToWrite = requests.back().nodes_to_write();
  ASSERT_EQ(nodesToWrite.size(), 1u);
  EXPECT_EQ(nodesToWrite[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::Value));
  const auto& written = nodesToWrite[0].value();
  ASSERT_NE(written.value().try_as<int32_t>(), nullptr);
  EXPECT_EQ(*written.value().try_as<int32_t>(), 123);
  ASSERT_TRUE(written.status().has_value());
  EXPECT_EQ(*written.status(), ua::StatusCode{Status::GoodClamped});
  ASSERT_TRUE(written.source_timestamp().has_value());
  EXPECT_EQ(*written.source_timestamp(), sourceTimestamp);
  ASSERT_TRUE(written.server_timestamp().has_value());
  EXPECT_EQ(*written.server_timestamp(), serverTimestamp);
}

// @verifies CL-ATTR-028
// @relation(CL-ATTR-028, scope=function)
TEST_F(TypedAccessTest, WriteAttributeUnsupportedCombinationNamesAttemptedTupleAndPreservesStatusDetail)
{
  script_scalar_shape_metadata();
  auto downstreamDetail = ua::make_error_detail(
    "ServerWriteCombinationUnsupported", "server rejected the write tuple", "test.server");
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(
    ua::StatusCode{Status::BadWriteNotSupported, std::move(downstreamDetail)});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  ua::DataValue dataValue{ua::Variant{int32_t{123}}, ua::StatusCode{Status::GoodClamped}};
  dataValue.source_timestamp() = ua::DateTime::now();
  dataValue.server_timestamp() = ua::DateTime::now();

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback) {
      typed.write_attribute_async(ua::NodeId{0, 10}, ua::AttributeId::Value, dataValue, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadWriteNotSupported});
  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "WriteAttributeCombinationUnsupported");
  const auto* attemptedTuple = find_context_value(*detail, "value");
  ASSERT_NE(attemptedTuple, nullptr);
  EXPECT_NE(attemptedTuple->find("value=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->find("status=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->find("sourceTimestamp=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->find("serverTimestamp=present"), std::string::npos);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->code, "ServerWriteCombinationUnsupported");
  EXPECT_EQ(mSession->write.call_count(), 1u) << "atomic rejection must not trigger a partial retry";
}

// @verifies CL-ATTR-024
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, CL-ATTR-024, scope=function)
TEST_F(TypedAccessTest, CachedWriteFullArrayOnlyRejectsRangedWriteBeforeMetadataOrWriteIo)
{
  restart_with_address_space_cache();
  const ua::NodeId variable{2, 2401};
  const auto writeFullArrayOnly =
    ua::AccessLevelExType{{ua::AccessLevelExType::Bit::WriteFullArrayOnly}}.as_underlying_type();
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{writeFullArrayOnly}})});

  auto typed = make_typed_access();
  auto observed = await<ua::DataValue>([&](auto callback)
    { typed.read_attribute_async(variable, ua::AttributeId::AccessLevelEx, std::move(callback)); });
  ASSERT_TRUE(observed.is_good());
  const auto readsAfterObservation = mSession->read.call_count();
  const auto writesBefore = mSession->write.call_count();

  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(variable,
        ua::AttributeId::Value,
        ua::String{"0:1"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{10, 11}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadWriteNotSupported});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "WriteFullArrayOnlyIndexRangeRejected");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find(ua::to_string(variable)), std::string::npos);
  EXPECT_EQ(mSession->read.call_count(), readsAfterObservation)
    << "cached rejection must occur before shape-metadata Read I/O";
  EXPECT_EQ(mSession->write.call_count(), writesBefore) << "cached rejection must emit no Write request";
}

// @verifies CL-ATTR-024
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, CL-ATTR-024, scope=function)
TEST_F(TypedAccessTest, CachedClearWriteFullArrayOnlyBitAllowsRangedWriteAndPreservesRange)
{
  restart_with_address_space_cache();
  const ua::NodeId variable{2, 2402};
  mSession->read.set_result_fn(
    [](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
    {
      if (request.nodes_to_read().size() == 1 && request.nodes_to_read()[0].attribute_id() ==
                                                   static_cast<ua::IntegerId>(ua::AttributeId::AccessLevelEx))
      {
        return Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::uint32_t{0}}})};
      }
      ua::ReadResponse response;
      response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{1}}});
      response.results().push_back(ua::DataValue{ua::Variant{ua::Array<std::uint32_t>{10}}});
      return Result<ua::ReadResponse>{std::move(response)};
    });
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  ASSERT_TRUE(await<ua::DataValue>(
    [&](auto callback) {
      typed.read_attribute_async(variable, ua::AttributeId::AccessLevelEx, std::move(callback));
    }).is_good());
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(variable,
        ua::AttributeId::Value,
        ua::String{"0:9"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->write.call_count(), 1u);
  const auto requests = mSession->write.requests();
  ASSERT_EQ(requests.back().nodes_to_write().size(), 1u);
  EXPECT_EQ(requests.back().nodes_to_write()[0].index_range(), ua::String{"0:9"});
}

// @verifies CL-ATTR-024
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, CL-ATTR-024, scope=function)
TEST_F(TypedAccessTest, CacheMissFallsThroughAndPreservesServerWriteNotSupported)
{
  restart_with_address_space_cache();
  script_shape_metadata({{1, std::vector<std::uint32_t>{10}}});
  auto serverDetail =
    ua::make_error_detail("ServerFullArrayOnly", "server rejected ranged write", "test.server");
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::BadWriteNotSupported, std::move(serverDetail)});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 2403},
        ua::AttributeId::Value,
        ua::String{"0:9"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadWriteNotSupported});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ServerFullArrayOnly")
    << "the ranged-write server verdict must not be mislabeled as a status/timestamp combination failure";
  ASSERT_EQ(mSession->write.call_count(), 1u)
    << "without cached AccessLevelEx, the server remains authoritative";
  EXPECT_EQ(mSession->write.requests().back().nodes_to_write()[0].index_range(), ua::String{"0:9"});
}

// @verifies CL-ATTR-024
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, CL-ATTR-024, scope=function)
TEST_F(TypedAccessTest, DisabledCacheDoesNotTurnObservedBitIntoLocalPolicy)
{
  const auto writeFullArrayOnly =
    ua::AccessLevelExType{{ua::AccessLevelExType::Bit::WriteFullArrayOnly}}.as_underlying_type();
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{writeFullArrayOnly}})});
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::BadWriteNotSupported});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  ASSERT_TRUE(await<ua::DataValue>(
    [&](auto callback) {
      typed.read_attribute_async(ua::NodeId{2, 2405}, ua::AttributeId::AccessLevelEx, std::move(callback));
    }).is_good());
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 2405},
        ua::AttributeId::Value,
        ua::String{"0"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{7}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadWriteNotSupported});
  EXPECT_EQ(mSession->write.call_count(), 1u)
    << "an explicitly disabled cache must remain pass-through even after an attribute read";
}

// @verifies CL-ATTR-008
// @verifies CL-ATTR-024
// @relation(CL-ATTR-008, CL-ATTR-024, scope=function)
TEST_F(TypedAccessTest, MalformedRangedWriteRejectedBeforeCacheMetadataOrWriteIo)
{
  restart_with_address_space_cache();
  const auto readsBefore = mSession->read.call_count();
  const auto writesBefore = mSession->write.call_count();
  auto typed = make_typed_access();

  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 2404},
        ua::AttributeId::Value,
        ua::String{"3:2"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{1, 2}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadIndexRangeInvalid});
  EXPECT_EQ(mSession->read.call_count(), readsBefore);
  EXPECT_EQ(mSession->write.call_count(), writesBefore);
}

// @verifies CL-ATTR-009
// @relation(CL-ATTR-009, scope=function)
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST_F(TypedAccessTest, CachedValueRankRejectsIncompleteRangedWriteBeforeIo)
{
  restart_with_address_space_cache();
  const ua::NodeId variable{2, 2406};
  ua::client::detail::ConnectionImplTestAccess::address_space_cache(*mConnection)
    ->install_attributes(variable, ua::client::detail::AttributeEntry{.valueRank = 2});
  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});
  const auto readsBefore = mSession->read.call_count();
  const auto writesBefore = mSession->write.call_count();

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(variable,
        ua::AttributeId::Value,
        ua::String{"0:1"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{10, 11}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadIndexRangeInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_EQ(mSession->read.call_count(), readsBefore);
  EXPECT_EQ(mSession->write.call_count(), writesBefore);
}

// @verifies CL-ATTR-009
// @verifies CL-ATTR-023
// @relation(CL-ATTR-009, CL-ATTR-023, scope=function)
TEST_F(TypedAccessTest, CachedValueRankAllowsCompleteRangedWriteAndPreservesRange)
{
  restart_with_address_space_cache();
  const ua::NodeId variable{2, 2407};
  ua::client::detail::ConnectionImplTestAccess::address_space_cache(*mConnection)
    ->install_attributes(variable, ua::client::detail::AttributeEntry{.valueRank = 2});
  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(variable,
        ua::AttributeId::Value,
        ua::String{"0:1,2:3"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{10, 11, 12, 13}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->write.call_count(), 1u);
  EXPECT_EQ(mSession->write.requests().back().nodes_to_write()[0].index_range(), ua::String{"0:1,2:3"});
}

// @verifies CL-ATTR-022
// @relation(CL-ATTR-022, scope=function)
TEST_F(TypedAccessTest, SingleElementRangedWriteWrapsScalarAndPreservesDataValueMetadata)
{
  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});

  const auto sourceTimestamp = ua::DateTime::now();
  ua::DataValue value{ua::Variant{std::int32_t{808}}, ua::StatusCode{Status::GoodClamped}};
  value.source_timestamp() = sourceTimestamp;
  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(
        ua::NodeId{2, 2408}, ua::AttributeId::Value, ua::String{"4"}, std::move(value), std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->write.call_count(), 1u);
  const auto requests = mSession->write.requests();
  const auto& written = requests.back().nodes_to_write()[0];
  EXPECT_EQ(written.index_range(), ua::String{"4"});
  ASSERT_TRUE(written.value().value().is_array())
    << "Part 4 section 5.10.4.2 requires an array even for one selected element";
  const auto& wrapped = written.value().value().as<ua::Array<std::int32_t>>();
  ASSERT_EQ(wrapped.payload().size(), 1u);
  EXPECT_EQ(wrapped.payload()[0], 808);
  ASSERT_TRUE(written.value().status().has_value());
  EXPECT_EQ(*written.value().status(), ua::StatusCode{Status::GoodClamped});
  ASSERT_TRUE(written.value().source_timestamp().has_value());
  EXPECT_EQ(*written.value().source_timestamp(), sourceTimestamp);
}

// @verifies CL-ATTR-022
// @relation(CL-ATTR-022, scope=function)
TEST_F(TypedAccessTest, SingleElementRangedWriteWrapsEverySupportedScalarBuiltInType)
{
  std::vector<ua::Variant> scalars;
  scalars.emplace_back(false);
  scalars.emplace_back(std::int8_t{-1});
  scalars.emplace_back(std::uint8_t{1});
  scalars.emplace_back(std::int16_t{-2});
  scalars.emplace_back(std::uint16_t{2});
  scalars.emplace_back(std::int32_t{-3});
  scalars.emplace_back(std::uint32_t{3});
  scalars.emplace_back(std::int64_t{-4});
  scalars.emplace_back(std::uint64_t{4});
  scalars.emplace_back(1.5F);
  scalars.emplace_back(2.5);
  scalars.emplace_back(ua::String{"text"});
  scalars.emplace_back(ua::DateTime{});
  scalars.emplace_back(ua::Guid{});
  scalars.emplace_back(ua::ByteString{});
  scalars.emplace_back(ua::XmlElement{});
  scalars.emplace_back(ua::NodeId{2, 1});
  scalars.emplace_back(ua::ExpandedNodeId{ua::NodeId{2, 2}});
  scalars.emplace_back(ua::StatusCode{Status::Good});
  scalars.emplace_back(ua::QualifiedName{2, "name"});
  scalars.emplace_back(ua::LocalizedText{"en", "text"});
  scalars.emplace_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::UnknownStructure>(ua::NodeId{2, 5000})});
  scalars.emplace_back(ua::DataValue{ua::Variant{std::int32_t{5}}});
  scalars.emplace_back(ua::Decimal{});

  auto typed = make_typed_access();
  for (std::size_t index = 0; index < scalars.size(); ++index)
  {
    ua::WriteResponse response;
    response.results().push_back(ua::StatusCode{Status::Good});
    mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});
    const auto expectedType = scalars[index].get_built_in_type();

    auto result = await<void>(
      [&](auto callback)
      {
        typed.write_attribute_async(ua::NodeId{2, static_cast<std::uint32_t>(2500 + index)},
          ua::AttributeId::Value,
          ua::String{"0"},
          ua::DataValue{std::move(scalars[index])},
          std::move(callback));
      });

    ASSERT_TRUE(result.is_good()) << "scalar case " << index;
    const auto requests = mSession->write.requests();
    const auto& wireValue = requests.back().nodes_to_write()[0].value().value();
    ASSERT_TRUE(wireValue.is_array()) << "scalar case " << index;
    EXPECT_EQ(wireValue.get_built_in_type(), expectedType) << "scalar case " << index;
    EXPECT_EQ(wireValue.get_array_base().size(), 1u) << "scalar case " << index;
  }
}

// @verifies CL-ATTR-023
// @relation(CL-ATTR-023, scope=function)
TEST_F(TypedAccessTest, RangedWriteRejectsArrayCardinalityMismatchBeforeWriteIo)
{
  const auto writesBefore = mSession->write.call_count();
  auto typed = make_typed_access();

  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 2525},
        ua::AttributeId::Value,
        ua::String{"3:5"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{10, 11, 12, 13}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeWriteCardinalityMismatch");
  EXPECT_EQ(mSession->write.call_count(), writesBefore);
}

// @verifies CL-ATTR-023
// @relation(CL-ATTR-023, scope=function)
TEST_F(TypedAccessTest, RangedWriteRejectsUnrepresentableCardinalityBeforeWriteIo)
{
  const auto writesBefore = mSession->write.call_count();
  auto typed = make_typed_access();

  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 2526},
        ua::AttributeId::Value,
        ua::String{"0:4294967295,0:4294967295"},
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{10}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeWriteCardinalityOverflow");
  EXPECT_EQ(mSession->write.call_count(), writesBefore);
}

// @verifies CL-ATTR-004
// @relation(CL-ATTR-004, scope=function)
TEST_F(TypedAccessTest, ReadValuesBulkComposesOneReadValueIdPerNode)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{int32_t{1}}});
  response.results().push_back(ua::DataValue{ua::Variant{int32_t{2}}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::DataValue>>(
    [&](auto cb) { typed.read_values_async({ua::NodeId{0, 1}, ua::NodeId{0, 2}}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().size(), 2u);
  const auto requests = mSession->read.requests();
  const auto& nodesToRead = requests.back().nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 2u);
  EXPECT_EQ(nodesToRead[0].node_id(), (ua::NodeId{0, 1}));
  EXPECT_EQ(nodesToRead[1].node_id(), (ua::NodeId{0, 2}));
  EXPECT_EQ(nodesToRead[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::Value));
}

// @verifies CL-ATTR-004
// @relation(CL-ATTR-004, scope=function)
TEST_F(TypedAccessTest, ReadValuesRejectsShortAndLongResultCountsWithDetail)
{
  auto typed = make_typed_access();
  for (const std::size_t resultCount : {1u, 3u})
  {
    ua::ReadResponse response;
    for (std::size_t index = 0; index < resultCount; ++index)
    {
      response.results().push_back(ua::DataValue{ua::Variant{static_cast<std::int32_t>(index)}});
    }
    mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

    auto result = await<std::vector<ua::DataValue>>([&](auto callback)
      { typed.read_values_async({ua::NodeId{0, 1}, ua::NodeId{0, 2}}, std::move(callback)); });

    ASSERT_TRUE(result.is_bad()) << "result count " << resultCount;
    EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadUnexpectedError});
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "ReadValuesResultCountMismatch");
  }
}

// @verifies CL-ADDRSP-010
// @relation(CL-ADDRSP-010, scope=function)
TEST_F(TypedAccessTest, VariableMetadataDecodesNonatomicFlags)
{
  const auto flags = ua::AccessLevelExType{
    ua::AccessLevelExType::Bit::NonatomicRead, ua::AccessLevelExType::Bit::NonatomicWrite};
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{flags.as_underlying_type()}})});

  auto typed = make_typed_access();
  auto result = await<ua::client::VariableMetadata>(
    [&](auto callback) { typed.read_variable_metadata_async(ua::NodeId{2, 100}, std::move(callback)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().accessLevelEx.has_value());
  EXPECT_TRUE(result.value().nonatomic_read());
  EXPECT_TRUE(result.value().nonatomic_write());
  const auto requests = mSession->read.requests();
  const auto& target = requests.back().nodes_to_read()[0];
  EXPECT_EQ(target.attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::AccessLevelEx));
}

// @verifies CL-ADDRSP-010
// @relation(CL-ADDRSP-010, scope=function)
TEST_F(TypedAccessTest, MissingAccessLevelExRemainsUnknown)
{
  ua::DataValue absent;
  absent.status() = ua::Status::BadAttributeIdInvalid;
  mSession->read.set_result(Result<ua::ReadResponse>{make_read_response(std::move(absent))});

  auto typed = make_typed_access();
  auto result = await<ua::client::VariableMetadata>(
    [&](auto callback) { typed.read_variable_metadata_async(ua::NodeId{2, 101}, std::move(callback)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().accessLevelEx.has_value())
    << "an absent optional attribute is unknown, not a fabricated zero/atomic value";
  EXPECT_FALSE(result.value().nonatomic_read());
  EXPECT_FALSE(result.value().nonatomic_write());
}

// @verifies CL-ADDRSP-010
// @relation(CL-ADDRSP-010, scope=function)
TEST_F(TypedAccessTest, AtomicityCheckedBatchReturnsValuesAndEmitsAdvisory)
{
  const auto nonatomic = ua::AccessLevelExType{ua::AccessLevelExType::Bit::NonatomicRead};
  mSession->read.set_result_fn(
    [nonatomic](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
    {
      ua::ReadResponse response;
      if (request.nodes_to_read().empty())
      {
        return Result<ua::ReadResponse>{std::move(response)};
      }
      const auto attribute = static_cast<ua::AttributeId>(request.nodes_to_read()[0].attribute_id());
      if (attribute == ua::AttributeId::AccessLevelEx)
      {
        response.results().push_back(
          ua::DataValue{ua::Variant{ua::AccessLevelExType{}.as_underlying_type()}});
        response.results().push_back(ua::DataValue{ua::Variant{nonatomic.as_underlying_type()}});
      }
      else
      {
        response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{10}}});
        response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{20}}});
      }
      return Result<ua::ReadResponse>{std::move(response)};
    });

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::DataValue>>(
    [&](auto callback)
    {
      typed.read_values_atomicity_checked_async(
        {ua::NodeId{2, 110}, ua::NodeId{2, 111}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_EQ(result.value()[0].value().as<std::int32_t>(), 10);
  EXPECT_EQ(result.value()[1].value().as<std::int32_t>(), 20);
  ASSERT_TRUE(mAtomicityObserver->wait_for_advisory());
  const auto advisory = mAtomicityObserver->advisory_detail();
  ASSERT_NE(advisory, nullptr);
  EXPECT_EQ(advisory->code, "NonatomicReadBatch");
  std::size_t relevantReads = 0;
  for (const auto& request : mSession->read.requests())
  {
    relevantReads += request.nodes_to_read().size() == 2 ? 1u : 0u;
  }
  EXPECT_EQ(relevantReads, 2u);
}

// The advisory follows the delivered values: a Value read answered with an Uncertain ServiceResult still
// delivers its values (with that code), so a non-atomic member is still reported.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(TypedAccessTest, AtomicityCheckedBatchEmitsTheAdvisoryForAnUncertainReadItDelivers)
{
  const auto nonatomic = ua::AccessLevelExType{ua::AccessLevelExType::Bit::NonatomicRead};
  mSession->read.set_result_fn(
    [nonatomic](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
    {
      ua::ReadResponse response;
      if (request.nodes_to_read().empty())
      {
        return Result<ua::ReadResponse>{std::move(response)};
      }
      const auto attribute = static_cast<ua::AttributeId>(request.nodes_to_read()[0].attribute_id());
      if (attribute == ua::AttributeId::AccessLevelEx)
      {
        response.results().push_back(
          ua::DataValue{ua::Variant{ua::AccessLevelExType{}.as_underlying_type()}});
        response.results().push_back(ua::DataValue{ua::Variant{nonatomic.as_underlying_type()}});
      }
      else
      {
        response.response_header().service_result() = ua::StatusCode{Status::UncertainLastUsableValue};
        response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{10}}});
        response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{20}}});
      }
      return Result<ua::ReadResponse>{std::move(response)};
    });

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::DataValue>>(
    [&](auto callback)
    {
      typed.read_values_atomicity_checked_async(
        {ua::NodeId{2, 110}, ua::NodeId{2, 111}}, std::move(callback));
    });

  ASSERT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_EQ(result.value()[1].value().as<std::int32_t>(), 20);
  ASSERT_TRUE(mAtomicityObserver->wait_for_advisory()) << "the values were delivered, so the advisory is due";
  const auto advisory = mAtomicityObserver->advisory_detail();
  ASSERT_NE(advisory, nullptr);
  EXPECT_EQ(advisory->code, "NonatomicReadBatch");
}

// @verifies CL-ADDRSP-015
// @relation(CL-ADDRSP-015, scope=function)
TEST_F(TypedAccessTest, DictionaryEntriesValidateCustomSubtypeAndSkipWrongTargetWithAdvisory)
{
  const ua::NodeId source{2, 200};
  const ua::NodeId standardTarget{2, 201};
  const ua::NodeId customTarget{2, 202};
  const ua::NodeId wrongTarget{2, 203};
  const ua::NodeId customType{2, 301};

  const auto reference = [](ua::NodeId target, ua::NodeId typeDefinition, ua::NodeClass nodeClass)
  {
    ua::ReferenceDescription description;
    description.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasDictionaryEntry};
    description.is_forward() = true;
    description.node_id().node_id() = std::move(target);
    description.node_class() = nodeClass;
    description.type_definition().node_id() = std::move(typeDefinition);
    return description;
  };

  mSession->browse.set_result_fn(
    [=](const ua::BrowseRequest& request) -> Result<ua::BrowseResponse>
    {
      ua::BrowseResponse response;
      ua::BrowseResult page;
      page.status_code() = ua::Status::Good;
      const auto& start = request.nodes_to_browse()[0].node_id();
      if (start == source)
      {
        page.references().push_back(reference(
          standardTarget, ua::NodeId{ua::ObjectTypeId::DictionaryEntryType}, ua::NodeClass::Object));
        page.references().push_back(reference(customTarget, customType, ua::NodeClass::Object));
        page.references().push_back(
          reference(wrongTarget, ua::NodeId{ua::ObjectTypeId::BaseObjectType}, ua::NodeClass::Object));
      }
      else if (start == customType)
      {
        auto parent =
          reference(ua::NodeId{ua::ObjectTypeId::DictionaryEntryType}, {}, ua::NodeClass::ObjectType);
        parent.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasSubtype};
        parent.is_forward() = false;
        page.references().push_back(std::move(parent));
      }
      response.results().push_back(std::move(page));
      return Result<ua::BrowseResponse>{std::move(response)};
    });

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::BrowseCursor::Entry>>(
    [&](auto callback) { typed.dictionary_entries_for_async(source, std::move(callback)); });

  ASSERT_TRUE(result.is_good()) << "status=0x" << std::hex << result.status_code().as_uint32() << " detail="
                                << (result.shared_detail() ? ua::to_string(*result.shared_detail())
                                                           : std::string{"<none>"});
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_EQ(result.value()[0].targetNodeId.node_id(), standardTarget);
  EXPECT_EQ(result.value()[1].targetNodeId.node_id(), customTarget);
  ASSERT_TRUE(mAtomicityObserver->wait_for_advisory());
  EXPECT_EQ(mAtomicityObserver->advisory_detail()->code, "NonConformantDictionaryEntryTarget");
}

// @verifies CL-METH-010
// @relation(CL-METH-010, scope=function)
TEST_F(TypedAccessTest, InspectMethodInputsComputesTrailingOptionalCountByArgumentName)
{
  const ua::NodeId method{2, 400};
  const ua::NodeId inputArguments{2, 401};
  const auto reference = [](ua::NodeId target, ua::NodeId type, std::string_view name)
  {
    ua::ReferenceDescription description;
    description.reference_type_id() = std::move(type);
    description.is_forward() = true;
    description.node_id().node_id() = std::move(target);
    description.node_class() = ua::NodeClass::Variable;
    description.browse_name() = ua::QualifiedName{0, name};
    return description;
  };
  mSession->browse.set_result_fn(
    [=](const ua::BrowseRequest& request) -> Result<ua::BrowseResponse>
    {
      ua::BrowseResponse response;
      ua::BrowseResult result;
      result.status_code() = ua::Status::Good;
      const auto referenceType = request.nodes_to_browse()[0].reference_type_id();
      if (referenceType == ua::NodeId{ua::ReferenceTypeId::HasProperty})
      {
        result.references().push_back(reference(inputArguments, referenceType, "InputArguments"));
      }
      else
      {
        result.references().push_back(reference(ua::NodeId{2, 402}, referenceType, "C"));
        result.references().push_back(reference(ua::NodeId{2, 403}, referenceType, "D"));
      }
      response.results().push_back(std::move(result));
      return Result<ua::BrowseResponse>{std::move(response)};
    });
  mSession->read.set_result_fn(
    [=](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
    {
      EXPECT_EQ(request.nodes_to_read()[0].node_id(), inputArguments);
      ua::Array<ua::RefStructure<ua::Structure>> arguments;
      for (std::string_view name : {"A", "B", "C", "D"})
      {
        auto argument = std::make_unique<ua::Argument>();
        argument->name() = ua::String{name};
        arguments.push_back(ua::RefStructure<ua::Structure>{std::move(argument)});
      }
      return Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::move(arguments)}})};
    });

  auto typed = make_typed_access();
  auto result = await<ua::client::MethodInputMetadata>(
    [&](auto callback) { typed.inspect_method_inputs_async(method, std::move(callback)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().inputArguments.size(), 4u);
  EXPECT_EQ(result.value().trailingOptionalCount, 2u);
  EXPECT_EQ(result.value().inputArguments[2].name(), ua::String{"C"});
  ASSERT_EQ(mSession->browse.call_count(), 2u);
  const auto reads = mSession->read.requests();
  ASSERT_FALSE(reads.empty());
  EXPECT_EQ(reads.back().nodes_to_read()[0].node_id(), inputArguments);
}

// @verifies CL-METH-010
// @relation(CL-METH-010, scope=function)
TEST_F(TypedAccessTest, InspectMethodInputsRejectsInteriorOptionalDescription)
{
  const ua::NodeId inputArguments{2, 411};
  mSession->browse.set_result_fn(
    [=](const ua::BrowseRequest& request) -> Result<ua::BrowseResponse>
    {
      ua::BrowseResponse response;
      ua::BrowseResult result;
      result.status_code() = ua::Status::Good;
      ua::ReferenceDescription description;
      description.reference_type_id() = request.nodes_to_browse()[0].reference_type_id();
      description.is_forward() = true;
      description.node_class() = ua::NodeClass::Variable;
      if (description.reference_type_id() == ua::NodeId{ua::ReferenceTypeId::HasProperty})
      {
        description.node_id().node_id() = inputArguments;
        description.browse_name() = ua::QualifiedName{0, "InputArguments"};
      }
      else
      {
        description.node_id().node_id() = ua::NodeId{2, 412};
        description.browse_name() = ua::QualifiedName{0, "B"};
      }
      result.references().push_back(std::move(description));
      response.results().push_back(std::move(result));
      return Result<ua::BrowseResponse>{std::move(response)};
    });
  ua::Array<ua::RefStructure<ua::Structure>> arguments;
  for (std::string_view name : {"A", "B", "C"})
  {
    auto argument = std::make_unique<ua::Argument>();
    argument->name() = ua::String{name};
    arguments.push_back(ua::RefStructure<ua::Structure>{std::move(argument)});
  }
  mSession->read.set_result(
    Result<ua::ReadResponse>{make_read_response(ua::DataValue{ua::Variant{std::move(arguments)}})});

  auto typed = make_typed_access();
  auto result = await<ua::client::MethodInputMetadata>(
    [&](auto callback) { typed.inspect_method_inputs_async(ua::NodeId{2, 410}, std::move(callback)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NonTrailingOptionalArguments");
}

// @verifies CL-METH-010
// @relation(CL-METH-010, scope=function)
TEST_F(TypedAccessTest, InspectMethodInputsPropagatesBrowseFailureDetail)
{
  mSession->browse.set_result(Result<ua::BrowseResponse>{ua::StatusCode{ua::Status::BadUserAccessDenied},
    ua::make_error_detail("Denied", "method metadata browse denied", "test.method.metadata")});

  auto typed = make_typed_access();
  auto result = await<ua::client::MethodInputMetadata>(
    [&](auto callback) { typed.inspect_method_inputs_async(ua::NodeId{2, 420}, std::move(callback)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadUserAccessDenied});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ConnectionServiceFailure");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "Denied");
}

TEST_F(TypedAccessTest, ReadValuesTypedDecodesEachElement)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{int32_t{10}}});
  response.results().push_back(ua::DataValue{ua::Variant{int32_t{20}}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<Result<int32_t>>>(
    [&](auto cb) { typed.read_values_async<int32_t>({ua::NodeId{0, 1}, ua::NodeId{0, 2}}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  ASSERT_TRUE(result.value()[0].is_good());
  EXPECT_EQ(result.value()[0].value(), 10);
  ASSERT_TRUE(result.value()[1].is_good());
  EXPECT_EQ(result.value()[1].value(), 20);
}

TEST_F(TypedAccessTest, WriteValuesBulkComposesOneWriteValuePerPair)
{
  script_scalar_shape_metadata(2);
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  writeResponse.results().push_back(ua::StatusCode{Status::BadUserAccessDenied});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{0, 1}, ua::Variant{int32_t{1}});
  pairs.emplace_back(ua::NodeId{0, 2}, ua::Variant{int32_t{2}});
  auto result = await<std::vector<VoidResult>>(
    [&](auto cb) { typed.write_values_async(std::move(pairs), std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_TRUE(result.value()[0].is_good());
  EXPECT_TRUE(result.value()[1].is_bad()) << "the per-item Write status is flattened positionally";
  EXPECT_EQ(mSession->write.requests().back().nodes_to_write().size(), 2u);
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteValuesReadsShapeMetadataAndRejectsRankMismatchBeforeWrite)
{
  script_shape_metadata({{2, std::vector<std::uint32_t>{3, 4}}});
  const auto readsBefore = mSession->read.call_count();

  auto typed = make_typed_access();
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{2, 1001}, ua::Variant{std::int32_t{7}});
  auto result = await<std::vector<VoidResult>>(
    [&](auto callback) { typed.write_values_async(std::move(pairs), std::move(callback)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "VariableValueRankMismatch");
  EXPECT_EQ(mSession->write.call_count(), 0u) << "a local shape mismatch must issue no Write request";

  const auto reads = mSession->read.requests();
  ASSERT_EQ(mSession->read.call_count(), readsBefore + 1);
  const auto& metadata = reads.back().nodes_to_read();
  ASSERT_EQ(metadata.size(), 2u);
  EXPECT_EQ(metadata[0].node_id(), (ua::NodeId{2, 1001}));
  EXPECT_EQ(metadata[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::ValueRank));
  EXPECT_EQ(metadata[1].node_id(), (ua::NodeId{2, 1001}));
  EXPECT_EQ(metadata[1].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::ArrayDimensions));
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteValuesValidatesBulkMetadataPositionallyThenIssuesOneWrite)
{
  script_shape_metadata(
    {{2, std::vector<std::uint32_t>{3, 4}}, {-1, std::optional<std::vector<std::uint32_t>>{}}});
  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{Status::Good});
  response.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});
  const auto readsBefore = mSession->read.call_count();

  ua::Array<std::int32_t> matrix{{2, 4}, std::vector<std::int32_t>(8, 7)};
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{2, 1001}, ua::Variant{std::move(matrix)});
  pairs.emplace_back(ua::NodeId{2, 1002}, ua::Variant{std::int32_t{9}});

  auto typed = make_typed_access();
  auto result = await<std::vector<VoidResult>>(
    [&](auto callback) { typed.write_values_async(std::move(pairs), std::move(callback)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(mSession->read.call_count(), readsBefore + 1);
  EXPECT_EQ(mSession->write.call_count(), 1u);
  const auto requests = mSession->read.requests();
  const auto& metadata = requests.back().nodes_to_read();
  ASSERT_EQ(metadata.size(), 4u);
  EXPECT_EQ(metadata[2].node_id(), (ua::NodeId{2, 1002}));
  EXPECT_EQ(metadata[2].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::ValueRank));
  EXPECT_EQ(metadata[3].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::ArrayDimensions));
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteValuesPropagatesMetadataReadFailureWithDetailAndNoWrite)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadTimeout},
    ua::make_error_detail("MetadataReadTimedOut", "scripted metadata read timeout", "test.session")});

  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{2, 1001}, ua::Variant{std::int32_t{7}});
  auto typed = make_typed_access();
  auto result = await<std::vector<VoidResult>>(
    [&](auto callback) { typed.write_values_async(std::move(pairs), std::move(callback)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTimeout});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ConnectionServiceFailure");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "MetadataReadTimedOut");
  EXPECT_EQ(mSession->write.call_count(), 0u);
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteAttributeTreatsOptionalArrayDimensionsAsAbsentForArray)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{1}}});
  response.results().push_back(ua::DataValue{ua::StatusCode{Status::BadAttributeIdInvalid}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 1001},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{1, 2}}},
        std::move(callback));
    });

  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->write.call_count(), 1u);
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteAttributeTreatsOptionalArrayDimensionsAsAbsentForScalar)
{
  ua::ReadResponse metadata;
  metadata.results().push_back(ua::DataValue{ua::Variant{std::int32_t{-1}}});
  metadata.results().push_back(ua::DataValue{ua::StatusCode{Status::BadAttributeIdInvalid}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(metadata)});
  ua::WriteResponse response;
  response.results().push_back(ua::StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 1001},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{std::int32_t{7}}},
        std::move(callback));
    });

  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->write.call_count(), 1u);
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(TypedAccessTest, WriteAttributePropagatesActualArrayDimensionsReadFailure)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{1}}});
  response.results().push_back(ua::DataValue{ua::StatusCode{Status::BadTimeout,
    ua::make_error_detail("ArrayDimensionsUnavailable", "scripted attribute failure", "test.server")}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto callback)
    {
      typed.write_attribute_async(ua::NodeId{2, 1001},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{ua::Array<std::int32_t>{1, 2}}},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadTimeout});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "WriteArrayDimensionsReadFailed");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "ArrayDimensionsUnavailable");
  EXPECT_EQ(mSession->write.call_count(), 0u);
}

// The bulk write facade must flatten a bad ResponseHeader.serviceResult into a bad outer Result; the
// tier-0 funnel returns the response verbatim, so a Good-looking results array underneath must not mask
// a service-level failure.
// @verifies CL-ATTR-017
// @relation(CL-ATTR-017, scope=function)
TEST_F(TypedAccessTest, WriteValuesFlattensBadServiceResult)
{
  script_scalar_shape_metadata(2);
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  writeResponse.results().push_back(ua::StatusCode{Status::Good});
  writeResponse.response_header().service_result() = ua::StatusCode{Status::BadServiceUnsupported};
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{0, 1}, ua::Variant{int32_t{1}});
  pairs.emplace_back(ua::NodeId{0, 2}, ua::Variant{int32_t{2}});
  auto result = await<std::vector<VoidResult>>(
    [&](auto cb) { typed.write_values_async(std::move(pairs), std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadServiceUnsupported}.value());
}

// A bulk write of N pairs must yield exactly N per-item statuses; a count mismatch cannot be
// positionally stitched to the request and must be rejected as Bad_UnexpectedError.
// @verifies CL-ATTR-017
// @relation(CL-ATTR-017, scope=function)
TEST_F(TypedAccessTest, WriteValuesRejectsResultCountMismatch)
{
  script_scalar_shape_metadata(2);
  auto typed = make_typed_access();
  for (const std::size_t resultCount : {1u, 3u})
  {
    ua::WriteResponse writeResponse;
    for (std::size_t index = 0; index < resultCount; ++index)
    {
      writeResponse.results().push_back(ua::StatusCode{Status::Good});
    }
    mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

    std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
    pairs.emplace_back(ua::NodeId{0, 1}, ua::Variant{int32_t{1}});
    pairs.emplace_back(ua::NodeId{0, 2}, ua::Variant{int32_t{2}});
    auto result = await<std::vector<VoidResult>>(
      [&](auto callback) { typed.write_values_async(std::move(pairs), std::move(callback)); });

    ASSERT_TRUE(result.is_bad()) << "result count " << resultCount;
    EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value())
      << "a bulk result count != request count must be rejected, not mis-mapped";
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "WriteValuesResultCountMismatch");
  }
}

// A single-attribute Write must return exactly one per-item status; an empty results array must be
// rejected with Bad_UnexpectedError rather than indexed out of bounds.
// @verifies CL-ATTR-017
// @verifies CL-DIAG-003
// @relation(CL-ATTR-017, CL-DIAG-003, scope=function)
TEST_F(TypedAccessTest, WriteAttributeRejectsResultCountMismatch)
{
  ua::WriteResponse writeResponse;  // zero results for a single-attribute write
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto cb)
    {
      typed.write_attribute_async(ua::NodeId{0, 10},
        ua::AttributeId::DisplayName,
        ua::DataValue{ua::Variant{ua::String{"name"}}},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.typed_access.write_attribute");
}

// @verifies CL-DIAG-001
// @relation(CL-DIAG-001, scope=function)
TEST_F(TypedAccessTest, ReadAttributePropagatesBadDownstreamResultUnchanged)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied},
    ua::make_error_detail("Downstream", "scripted tier-0 failure", "test.downstream")});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto cb) { typed.read_attribute_async(ua::NodeId{0, 1}, ua::AttributeId::Value, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value());
  ASSERT_NE(result.shared_detail(), nullptr) << "single-wrap: the downstream ErrorDetail survives";
}

// The read_attribute facade must flatten a bad ResponseHeader.serviceResult into a bad outer Result
// (mirroring write_attribute_async): the tier-0 funnel returns the ReadResponse verbatim, so a service-level
// fault must not be masked by the empty-results branch. Case A: bad serviceResult with EMPTY results[] -
// without the flatten, the empty-results branch masks it as Bad_UnexpectedError (ReadAttributeEmptyResults).
// @verifies CL-ATTR-007
// @relation(CL-ATTR-007, scope=function)
TEST_F(TypedAccessTest, ReadAttributeFlattensBadServiceResultWithEmptyResults)
{
  ua::ReadResponse response;  // zero results
  response.response_header().service_result() = ua::StatusCode{Status::BadTooManyOperations};
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto cb) { typed.read_attribute_async(ua::NodeId{0, 1}, ua::AttributeId::Value, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "a bad serviceResult must surface, not be masked as Bad_UnexpectedError";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTooManyOperations}.value());
  ASSERT_NE(result.error_detail(), nullptr) << "the collapsed Result must carry the wire-crossing marker";
  // CL-DIAG-005: the funnel now attaches the always-on wire-crossing marker on a bad serviceResult and
  // collapses the Result BEFORE the facade sees it, so the facade propagates the marker unchanged rather than
  // reaching its own ReadAttributeServiceFault flatten wrap (now production-dead). CL-ATTR-007 still holds:
  // the bad serviceResult surfaces as a bad Result, never masked as Bad_UnexpectedError.
  EXPECT_EQ(result.error_detail()->source, "client.tier1.connection.read");
  ASSERT_NE(result.error_detail()->cause, nullptr);
  EXPECT_EQ(result.error_detail()->cause->source, "client.tier0.session.decode_diagnostic");
}

// Case B (the worst masking path): bad serviceResult with a NON-empty results[] - without the flatten, the
// facade returns a Good outer Result{results[0]}, SILENTLY dropping the fault entirely.
// @verifies CL-ATTR-007
// @relation(CL-ATTR-007, scope=function)
TEST_F(TypedAccessTest, ReadAttributeFlattensBadServiceResultWithNonEmptyResults)
{
  ua::ReadResponse response = make_read_response(ua::DataValue{ua::Variant{int32_t{42}}});
  response.response_header().service_result() = ua::StatusCode{Status::BadSessionIdInvalid};
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::DataValue>(
    [&](auto cb) { typed.read_attribute_async(ua::NodeId{0, 2}, ua::AttributeId::Value, std::move(cb)); });

  ASSERT_TRUE(result.is_bad())
    << "a bad serviceResult must surface as a bad outer Result, never be silently returned as Good";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadSessionIdInvalid}.value());
  ASSERT_NE(result.error_detail(), nullptr);
  // CL-DIAG-005: funnel-collapsed marker (see WithEmptyResults); CL-ATTR-007 non-masking still upheld.
  EXPECT_EQ(result.error_detail()->source, "client.tier1.connection.read");
  ASSERT_NE(result.error_detail()->cause, nullptr);
  EXPECT_EQ(result.error_detail()->cause->source, "client.tier0.session.decode_diagnostic");
}

// @verifies CL-VIEW-014
// The tier-2 convenience composes a single BrowsePath and returns a fully-resolved local target as a
// TranslatedNodeId (is_fully_resolved + is_local + local_node_id).
// @relation(CL-VIEW-014, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathComposesSingleBrowsePath)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  ua::BrowsePathResult perPath;  // Good status
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{3, 55}};  // local (serverIndex 0, empty namespaceUri)
  target.remaining_path_index() = ua::client::TranslatedNodeId::fullyResolved;
  perPath.targets().push_back(std::move(target));
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->translateBrowsePaths.call_count(), 1u);
  const auto requests = mSession->translateBrowsePaths.requests();
  const auto& browsePaths = requests.back().browse_paths();
  ASSERT_EQ(browsePaths.size(), 1u);
  EXPECT_EQ(browsePaths[0].starting_node(), (ua::NodeId{0, 84}));
  // CL-VIEW-014/015: the fully-resolved local target is the one TranslatedNodeId.
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_TRUE(result.value().at(0).is_fully_resolved());
  EXPECT_TRUE(result.value().at(0).is_local());
  EXPECT_EQ(result.value().at(0).local_node_id(), (ua::NodeId{3, 55}));
}

// @verifies CL-VIEW-020
// @relation(CL-VIEW-020, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathLocalExpandedNodeIdUnwraps)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  ua::BrowsePathResult perPath;
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{1, 55}};
  target.remaining_path_index() = ua::client::TranslatedNodeId::fullyResolved;
  perPath.targets().push_back(std::move(target));
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>(
    [&](auto callback)
    {
      typed.translate_browse_path_async(
        ua::ExpandedNodeId{ua::NodeId{1, 42}}, ua::RelativePath{}, std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  const auto requests = mSession->translateBrowsePaths.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests.front().browse_paths()[0].starting_node(), (ua::NodeId{1, 42}));
}

// @verifies CL-VIEW-020
// @relation(CL-VIEW-020, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathRemoteExpandedNodeIdRejectedWithoutWire)
{
  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>(
    [&](auto callback)
    {
      typed.translate_browse_path_async(
        ua::ExpandedNodeId{ua::NodeId{1, 42}, std::uint32_t{3}}, ua::RelativePath{}, std::move(callback));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->summary, "Starting node must be local; connect to remote server first");
  EXPECT_EQ(mSession->translateBrowsePaths.call_count(), 0u);
}

// @verifies CL-VIEW-020
// @relation(CL-VIEW-020, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathUriExpandedNodeIdResolvesCurrentNamespaceTable)
{
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:other", "http://vendor/local"})
                .is_good());
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  ua::BrowsePathResult perPath;
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{2, 55}};
  target.remaining_path_index() = ua::client::TranslatedNodeId::fullyResolved;
  perPath.targets().push_back(std::move(target));
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>(
    [&](auto callback)
    {
      typed.translate_browse_path_async(ua::ExpandedNodeId{ua::NodeId{0, 42}, "http://vendor/local"},
        ua::RelativePath{},
        std::move(callback));
    });

  ASSERT_TRUE(result.is_good());
  const auto requests = mSession->translateBrowsePaths.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests.front().browse_paths()[0].starting_node(), (ua::NodeId{2, 42}));
}

// @verifies CL-VIEW-014
// A service-Good response whose single BrowsePathResult has EMPTY targets (the path resolved to nothing) is
// synthesised into a bad Result{Bad_NoMatch} rather than a Good empty result.
// @relation(CL-VIEW-014, scope=function)
TEST_F(TypedAccessTest, TranslateEmptyTargetsSynthesisesBadNoMatch)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(ua::BrowsePathResult{});  // Good status, no targets
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "an empty target set resolves to no node -> Bad_NoMatch (CL-VIEW-014)";
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch);
}

// @verifies CL-VIEW-015
// A PARTIAL resolution (remainingPathIndex != fullyResolved) is surfaced as a GOOD Result whose
// TranslatedNodeId records the partial (OPEN-VIEW-4 = success-with-partial); the caller inspects
// remainingPathIndex rather than getting an error.
// @relation(CL-VIEW-015, scope=function)
TEST_F(TypedAccessTest, TranslatePartialResolutionSurfacedAsSuccessWithPartial)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  ua::BrowsePathResult perPath;
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{3, 55}};
  target.remaining_path_index() = 2;  // the residual path begins at element 2 (partial)
  perPath.targets().push_back(std::move(target));
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "partial resolution is DATA, not an error (OPEN-VIEW-4)";
  EXPECT_FALSE(result.value().at(0).is_fully_resolved());
  EXPECT_EQ(result.value().at(0).remainingPathIndex, 2u);
}

// @verifies CL-VIEW-019
// A CROSS-SERVER target (serverIndex != 0) is surfaced verbatim on the TranslatedNodeId (is_local() false,
// the full ExpandedNodeId retained) with NO auto-connect (no second wire round-trip).
// @relation(CL-VIEW-019, scope=function)
TEST_F(TypedAccessTest, TranslateRemoteTargetSurfacedVerbatimNoAutoConnect)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  ua::BrowsePathResult perPath;
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{3, 55}, std::uint32_t{7}};  // serverIndex 7 = remote
  target.remaining_path_index() = 1;  // partial: residual to resolve on the remote server
  perPath.targets().push_back(std::move(target));
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().at(0).is_local()) << "a cross-server target is not a local node";
  EXPECT_EQ(result.value().at(0).targetId.server_index(), 7u)
    << "the remote serverIndex is surfaced verbatim";
  EXPECT_FALSE(result.value().at(0).is_fully_resolved());
  EXPECT_EQ(mSession->translateBrowsePaths.call_count(), 1u)
    << "the SDK must NOT auto-connect to resolve the residual (exactly one wire round-trip)";
}

// Part 4 section 5.8.4.2 narrows the generic RelativePath shape: TranslateBrowsePaths requires the final
// element's targetName. Tier-2 owns construction policy and rejects the malformed convenience call before
// wire I/O; tier-1 remains the unchecked wire-shaped API.
// @verifies CL-VIEW-013
// @relation(CL-VIEW-013, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathRejectsEmptyFinalTargetNameWithoutWireCall)
{
  ua::RelativePath relativePath;
  relativePath.elements().push_back(ua::RelativePathElement{});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, std::move(relativePath), std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "TranslateBrowsePathMissingFinalTargetName");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.typed_access.translate_browse_path");
  EXPECT_EQ(mSession->translateBrowsePaths.call_count(), 0u);
}

// Item 8c section 10 (API-8c.3): Part 4 5.8.4.2 allows several targets for one path; translate returns
// every one, in the server's order, a partial one included.
// @verifies CL-VIEW-015
// @relation(CL-VIEW-015, scope=function)
TEST_F(TypedAccessTest, TranslateBrowsePathReturnsEveryTarget)
{
  set_translate_targets({{ua::ExpandedNodeId{ua::NodeId{3, 55}}, ua::client::TranslatedNodeId::fullyResolved},
    {ua::ExpandedNodeId{ua::NodeId{3, 56}}, 1u}});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::client::TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u) << "both targets are returned, not only the first";
  EXPECT_EQ(result.value()[0].local_node_id(), (ua::NodeId{3, 55}));
  EXPECT_EQ(result.value()[1].local_node_id(), (ua::NodeId{3, 56}));
  EXPECT_EQ(result.value()[1].remainingPathIndex, 1u);
}

// Item 8c section 10 (API-8c.2): resolve_path gives a NodeId only for exactly one fully resolved local
// target.
TEST_F(TypedAccessTest, ResolvePathReturnsTheOneLocalTarget)
{
  set_translate_targets(
    {{ua::ExpandedNodeId{ua::NodeId{3, 55}}, ua::client::TranslatedNodeId::fullyResolved}});

  auto typed = make_typed_access();
  auto result = await<ua::NodeId>([&](auto cb)
    { typed.resolve_path_async(ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Plant"}), std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), (ua::NodeId{3, 55}));
}

TEST_F(TypedAccessTest, ResolvePathRefusesSeveralTargetsWithTheirCount)
{
  set_translate_targets({{ua::ExpandedNodeId{ua::NodeId{3, 55}}, ua::client::TranslatedNodeId::fullyResolved},
    {ua::ExpandedNodeId{ua::NodeId{3, 56}}, ua::client::TranslatedNodeId::fullyResolved}});

  auto typed = make_typed_access();
  auto result = await<ua::NodeId>([&](auto cb)
    { typed.resolve_path_async(ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Pump"}), std::move(cb)); });

  ASSERT_TRUE(result.is_bad()) << "the first of several is never chosen silently";
  EXPECT_EQ(result.status_code().as_status(), Status::BadTooManyMatches);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ResolvePathTooManyMatches");
  const std::string* count = find_context_value(*result.shared_detail(), "count.actual");
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(*count, "2");
}

TEST_F(TypedAccessTest, ResolvePathRefusesAPartialTargetNamingTheUnresolvedElement)
{
  set_translate_targets({{ua::ExpandedNodeId{ua::NodeId{3, 55}, std::uint32_t{7}}, 1u}});

  auto typed = make_typed_access();
  auto result = await<ua::NodeId>(
    [&](auto cb)
    {
      typed.resolve_path_async(
        ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Plant", "Boiler"}), std::move(cb));
    });

  ASSERT_TRUE(result.is_bad()) << "a partial or cross-server target is not a local node";
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ResolvePathNotLocal");
  const std::string* server = find_context_value(*result.shared_detail(), "server.index");
  const std::string* index = find_context_value(*result.shared_detail(), "index");
  const std::string* name = find_context_value(*result.shared_detail(), "node.browse_name");
  ASSERT_NE(server, nullptr);
  ASSERT_NE(index, nullptr);
  ASSERT_NE(name, nullptr);
  EXPECT_EQ(*server, "7");
  EXPECT_EQ(*index, "1");
  EXPECT_EQ(*name, "3:Boiler");
  EXPECT_EQ(mSession->translateBrowsePaths.call_count(), 1u) << "no connection to the other server";
}

// A partial target on THIS server (serverIndex 0; a server that stopped early without leaving itself, as
// ClientTranslate row 5 simulates) is not the node the path names either.
TEST_F(TypedAccessTest, ResolvePathRefusesALocalTargetThatIsOnlyPartlyResolved)
{
  set_translate_targets({{ua::ExpandedNodeId{ua::NodeId{3, 55}}, 1u}});

  auto typed = make_typed_access();
  auto result = await<ua::NodeId>(
    [&](auto cb)
    {
      typed.resolve_path_async(
        ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Plant", "Boiler"}), std::move(cb));
    });

  ASSERT_TRUE(result.is_bad()) << "a node one element short of the path is not the node it names";
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ResolvePathNotLocal");
  const std::string* index = find_context_value(*result.shared_detail(), "index");
  ASSERT_NE(index, nullptr);
  EXPECT_EQ(*index, "1");
}

TEST_F(TypedAccessTest, ResolvePathRefusesAFullyResolvedRemoteTarget)
{
  set_translate_targets(
    {{ua::ExpandedNodeId{ua::NodeId{3, 55}, std::uint32_t{2}}, ua::client::TranslatedNodeId::fullyResolved}});

  auto typed = make_typed_access();
  auto result = await<ua::NodeId>([&](auto cb)
    { typed.resolve_path_async(ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Plant"}), std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ResolvePathNotLocal");
  EXPECT_EQ(find_context_value(*result.shared_detail(), "index"), nullptr) << "the whole path resolved";
}

TEST_F(TypedAccessTest, ResolvePathPassesNoTargetOnAsBadNoMatch)
{
  set_translate_targets({});

  auto typed = make_typed_access();
  const auto result = typed.try_resolve_path_sync(ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Missing"}));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "TranslateBrowsePathNoMatch");
  EXPECT_THROW(
    (void)typed.resolve_path_sync(ua::NodeId{0, 84}, ua::hierarchical_path(3, {"Missing"})), ua::UaException);
}

// ===================== sync / try_sync wrappers (section 7.0) =====================

TEST_F(TypedAccessTest, CallMethodSyncThrowsOnServiceBad)
{
  mSession->call.set_result(Result<ua::CallResponse>{ua::StatusCode{Status::BadUserAccessDenied}});
  auto typed = make_typed_access();
  EXPECT_THROW((void)typed.call_method_sync(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}), ua::UaException);
}

TEST_F(TypedAccessTest, ReadValuesTrySyncReturnsResult)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{int32_t{1}}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = typed.try_read_values_sync({ua::NodeId{0, 1}});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().size(), 1u);
}

// Moved-from handle fast-fails rather than dereferencing a null pimpl.
TEST_F(TypedAccessTest, MovedFromHandleFailsFast)
{
  TypedAccess typed = ConnectionHandleFactory::make_typed_access(nullptr);
  bool failed = false;
  typed.read_attribute_async(ua::NodeId{0, 1},
    ua::AttributeId::Value,
    [&failed](Result<ua::DataValue> result) { failed = result.is_bad(); });
  EXPECT_TRUE(failed);
}

}  // namespace
