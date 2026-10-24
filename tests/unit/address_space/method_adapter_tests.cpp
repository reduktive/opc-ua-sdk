// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <atomic>
#include <optional>
#include "ua_method_adapter.h"
#include "ua_utilities.h"
#include "ua_node.h"
#include "ua_default_method_node.h"

using namespace ua;

namespace
{

// Returns the value stored under `key` in an ErrorDetail's structured context, or nullopt when
// the key is absent. Keys are compared by their controlled-vocabulary wire string.
std::optional<std::string> context_value(const ErrorDetail& detail, const ContextKey& key)
{
  for (const auto& namedValue : detail.context)
  {
    if (namedValue.key == key.value())
    {
      return namedValue.value;
    }
  }
  return std::nullopt;
}

// Extracts the ErrorDetail attached to a per-argument DiagnosticInfo. DiagnosticInfo has no
// ErrorDetail field of its own; the MethodAdapter carries it on the diagnostic's inner
// StatusCode, which holds it losslessly via shared_detail().
std::shared_ptr<const ErrorDetail> argument_detail(const DiagnosticInfo& info)
{
  if (!info.inner_status_code().has_value())
  {
    return nullptr;
  }
  return info.inner_status_code()->shared_detail();
}

}  // namespace

TEST(MethodAdapterTests, Success)
{
  using InputArgs = std::tuple<double, Array<DateTime>, String, Variant>;
  auto handler = [](const NodeId& objectId,
                   const InputArgs& inputArgs,
                   std::shared_ptr<const MethodCallContext> /*context*/,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    UA_UNUSED(objectId);

    const auto& [a, b, c, d] = inputArgs;

    UA_UNUSED(b);
    UA_UNUSED(d);
    UA_UNUSED(a);
    UA_UNUSED(c);

    callback(CallResult{std::move(result)});
  };

  MethodAdapter<InputArgs> methodAdapter{handler};

  auto node = default_ns::MethodNode::create(NodeId{1});
  node->set_handler(methodAdapter);

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(4);
  callMethodRequest.input_arguments()[0] = double{1.2};
  callMethodRequest.input_arguments()[1] = Array<DateTime>{};
  callMethodRequest.input_arguments()[2] = String{"Hello world!"};
  callMethodRequest.input_arguments()[3] = Variant{};

  bool gotResult{false};
  node->call(callMethodRequest,
    nullptr,

    [&gotResult](CallResult result)
    {
      UA_UNUSED(result);
      gotResult = true;
    });
  ASSERT_TRUE(gotResult);
}

// A type mismatch on an input argument (e.g. a String supplied where Int32 is required) must be
// reported per-argument: CallMethodResult.statusCode == Bad_InvalidArgument AND
// inputArgumentResults[i] == Bad_TypeMismatch for the offending argument (Part 4 section 5.11.2).
TEST(MethodAdapterTests, WrongInputArgumentTypeReportsPerArgumentTypeMismatch)
{
  using InputArgs = std::tuple<int32_t, int32_t>;
  bool handlerRan{false};
  auto handler = [&handlerRan](const NodeId&,
                   const InputArgs&,
                   std::shared_ptr<const MethodCallContext>,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    handlerRan = true;
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<InputArgs> methodAdapter{handler};

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(2);
  callMethodRequest.input_arguments()[0] = String{"32"};  // wrong: String where Int32 required
  callMethodRequest.input_arguments()[1] = String{"7"};  // wrong: String where Int32 required

  std::optional<CallResult> captured;
  methodAdapter(callMethodRequest, nullptr, [&captured](CallResult result) { captured = std::move(result); });

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << "adapter wraps the CallMethodResult as a value, not a bad Result";
  EXPECT_FALSE(handlerRan) << "handler must not run when an argument fails to decode";

  const auto& methodResult = captured->value();
  EXPECT_EQ(methodResult.status_code(), StatusCode{Status::BadInvalidArgument});
  // Every failing argument must carry its own Bad_TypeMismatch - not just the first one.
  ASSERT_EQ(methodResult.input_argument_results().size(), 2u);
  EXPECT_EQ(methodResult.input_argument_results()[0], StatusCode{Status::BadTypeMismatch});
  EXPECT_EQ(methodResult.input_argument_results()[1], StatusCode{Status::BadTypeMismatch});

  // ErrorDetail propagation: each failing slot must also carry per-argument diagnostic context
  // explaining WHY it failed (expected vs actual type + the failing slot index), sized to match
  // the input_argument_results() length.
  ASSERT_EQ(methodResult.input_argument_diagnostic_infos().size(), 2u);
  for (size_t i = 0; i < 2u; ++i)
  {
    auto detail = argument_detail(methodResult.input_argument_diagnostic_infos()[i]);
    ASSERT_TRUE(static_cast<bool>(detail)) << "slot " << i << " must carry an ErrorDetail";
    EXPECT_EQ(detail->code, "ArgumentTypeMismatch");
    EXPECT_EQ(context_value(*detail, ContextKeys::typeExpected), std::optional<std::string>{"Int32"});
    EXPECT_EQ(context_value(*detail, ContextKeys::typeActual), std::optional<std::string>{"String"});
    EXPECT_EQ(
      context_value(*detail, ContextKeys::operationIndex), std::optional<std::string>{std::to_string(i)});
  }
}

// Deliverable scenario: Add(Int32, Int32) called with [Int32(2), String]. The first argument
// decodes cleanly (Good result, null diagnostic); the second fails to decode. The failing slot
// must record Bad_TypeMismatch AND a per-argument ErrorDetail whose context names the expected
// type ("Int32"), the actual type ("String"), and the failing slot index ("1").
TEST(MethodAdapterTests, WrongTypedSecondArgumentCarriesPerArgumentErrorDetail)
{
  using InputArgs = std::tuple<int32_t, int32_t>;
  bool handlerRan{false};
  auto handler = [&handlerRan](const NodeId&,
                   const InputArgs&,
                   std::shared_ptr<const MethodCallContext>,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    handlerRan = true;
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<InputArgs> methodAdapter{handler};

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(2);
  callMethodRequest.input_arguments()[0] = int32_t{2};  // decodes fine
  callMethodRequest.input_arguments()[1] = String{"not an int"};  // wrong: String where Int32 required

  std::optional<CallResult> captured;
  methodAdapter(callMethodRequest, nullptr, [&captured](CallResult result) { captured = std::move(result); });

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_FALSE(handlerRan);

  const auto& methodResult = captured->value();
  EXPECT_EQ(methodResult.status_code(), StatusCode{Status::BadInvalidArgument});

  // Slot 0 decoded fine: Good result, and its diagnostic slot is null.
  ASSERT_EQ(methodResult.input_argument_results().size(), 2u);
  EXPECT_EQ(methodResult.input_argument_results()[0], StatusCode{Status::Good});
  EXPECT_EQ(methodResult.input_argument_results()[1], StatusCode{Status::BadTypeMismatch});

  ASSERT_EQ(methodResult.input_argument_diagnostic_infos().size(), 2u);
  EXPECT_TRUE(methodResult.input_argument_diagnostic_infos()[0].is_null())
    << "a slot that decoded fine must carry no diagnostic";
  EXPECT_EQ(argument_detail(methodResult.input_argument_diagnostic_infos()[0]), nullptr);

  // Slot 1 carries the required per-argument detail.
  auto detail = argument_detail(methodResult.input_argument_diagnostic_infos()[1]);
  ASSERT_TRUE(static_cast<bool>(detail));
  EXPECT_EQ(detail->code, "ArgumentTypeMismatch");
  EXPECT_EQ(detail->source, "MethodAdapter");
  EXPECT_EQ(context_value(*detail, ContextKeys::typeExpected), std::optional<std::string>{"Int32"});
  EXPECT_EQ(context_value(*detail, ContextKeys::typeActual), std::optional<std::string>{"String"});
  EXPECT_EQ(context_value(*detail, ContextKeys::operationIndex), std::optional<std::string>{"1"});
}

// Phase 5 end-to-end guarantee: when a method handler drops the std::function<void(CallResult)>
// without invoking it, the caller of node->call() must receive a bad Result whose
// ErrorDetail identifies the leak with code == "CallbackNotInvoked".
// Phase 5 end-to-end guarantee: a handler that stashes the callback in a member
// and then lets that member be destroyed (without invoking it) must still deliver
// a CallbackNotInvoked result to the caller. Exercises the same RAII path via a
// stored-then-destroyed instance rather than an inline drop.

namespace
{

// Optional trailing input arguments (OPC 10000-4 section 5.11.2.2 lines 4172-4178: fewer
// arguments MAY be passed when optional inputs are defined; section 5.11.2.4: Bad_ArgumentsMissing
// applies only to *non-optional* inputs). A handler models an optional trailing input by
// declaring it as a std::optional<T> tuple element; omitting it must NOT yield
// Bad_ArgumentsMissing.
using OptionalTailArgs = std::tuple<int32_t, std::optional<String>>;

}  // namespace

// Required count is the number of leading non-optional tuple elements (here 1). Supplying
// only the required int32_t and omitting the trailing std::optional<String> must invoke the
// handler with the optional absent and return Good - NOT Bad_ArgumentsMissing.
TEST(MethodAdapterTests, OmittedTrailingOptionalArgAccepted)
{
  bool handlerRan{false};
  bool optionalWasAbsent{false};
  int32_t seenRequired{0};

  auto handler = [&](const NodeId& objectId,
                   const OptionalTailArgs& inputArgs,
                   std::shared_ptr<const MethodCallContext> /*context*/,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    UA_UNUSED(objectId);
    handlerRan = true;
    seenRequired = std::get<0>(inputArgs);
    optionalWasAbsent = !std::get<1>(inputArgs).has_value();
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<OptionalTailArgs> methodAdapter{handler};

  auto node = default_ns::MethodNode::create(NodeId{1});
  node->set_handler(methodAdapter);

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(1);
  callMethodRequest.input_arguments()[0] = int32_t{42};

  std::optional<CallResult> delivered;
  node->call(callMethodRequest, nullptr, [&delivered](CallResult result) { delivered = std::move(result); });

  ASSERT_TRUE(delivered.has_value());
  EXPECT_TRUE(delivered->is_good());
  EXPECT_TRUE(handlerRan);
  EXPECT_TRUE(optionalWasAbsent);
  EXPECT_EQ(seenRequired, 42);
}

// When the optional trailing argument IS supplied, the handler must see it present and the
// decoded value must round-trip.
TEST(MethodAdapterTests, SuppliedOptionalArgForwarded)
{
  bool handlerRan{false};
  bool optionalPresent{false};
  String seenOptional;

  auto handler = [&](const NodeId& objectId,
                   const OptionalTailArgs& inputArgs,
                   std::shared_ptr<const MethodCallContext> /*context*/,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    UA_UNUSED(objectId);
    handlerRan = true;
    optionalPresent = std::get<1>(inputArgs).has_value();
    if (optionalPresent)
    {
      seenOptional = *std::get<1>(inputArgs);
    }
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<OptionalTailArgs> methodAdapter{handler};

  auto node = default_ns::MethodNode::create(NodeId{1});
  node->set_handler(methodAdapter);

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(2);
  callMethodRequest.input_arguments()[0] = int32_t{7};
  callMethodRequest.input_arguments()[1] = String{"present"};

  std::optional<CallResult> delivered;
  node->call(callMethodRequest, nullptr, [&delivered](CallResult result) { delivered = std::move(result); });

  ASSERT_TRUE(delivered.has_value());
  EXPECT_TRUE(delivered->is_good());
  EXPECT_TRUE(handlerRan);
  EXPECT_TRUE(optionalPresent);
  EXPECT_EQ(seenOptional, String{"present"});
}

// Regression pin: a genuinely-missing *required* argument (zero args supplied, required
// count 1) must still be rejected with Bad_ArgumentsMissing. The required/total split must
// not relax the required-argument check.
TEST(MethodAdapterTests, MissingRequiredStillRejected)
{
  bool handlerRan{false};

  auto handler = [&](const NodeId& objectId,
                   const OptionalTailArgs& /*inputArgs*/,
                   std::shared_ptr<const MethodCallContext> /*context*/,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    UA_UNUSED(objectId);
    handlerRan = true;
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<OptionalTailArgs> methodAdapter{handler};

  auto node = default_ns::MethodNode::create(NodeId{1});
  node->set_handler(methodAdapter);

  CallMethodRequest callMethodRequest;  // zero input arguments

  std::optional<CallResult> delivered;
  node->call(callMethodRequest, nullptr, [&delivered](CallResult result) { delivered = std::move(result); });

  ASSERT_TRUE(delivered.has_value());
  EXPECT_TRUE(delivered->is_bad());
  EXPECT_EQ(delivered->status_code().as_status(), Status::BadArgumentsMissing);
  EXPECT_FALSE(handlerRan);
}

// An all-required tuple with one extra argument must still be rejected with
// Bad_TooManyArguments - the upper bound stays keyed on the total tuple size, and the
// opt-in change must not alter all-required behaviour.
TEST(MethodAdapterTests, AllRequiredTooManyArgsRejected)
{
  using AllRequired = std::tuple<int32_t, String>;

  bool handlerRan{false};
  auto handler = [&](const NodeId& objectId,
                   const AllRequired& /*inputArgs*/,
                   std::shared_ptr<const MethodCallContext> /*context*/,
                   CallMethodResult result,
                   CallMethodCompleteCallback callback)
  {
    UA_UNUSED(objectId);
    handlerRan = true;
    callback(CallResult{std::move(result)});
  };

  MethodAdapter<AllRequired> methodAdapter{handler};

  auto node = default_ns::MethodNode::create(NodeId{1});
  node->set_handler(methodAdapter);

  CallMethodRequest callMethodRequest;
  callMethodRequest.input_arguments().resize(3);
  callMethodRequest.input_arguments()[0] = int32_t{1};
  callMethodRequest.input_arguments()[1] = String{"x"};
  callMethodRequest.input_arguments()[2] = String{"extra"};

  std::optional<CallResult> delivered;
  node->call(callMethodRequest, nullptr, [&delivered](CallResult result) { delivered = std::move(result); });

  ASSERT_TRUE(delivered.has_value());
  EXPECT_TRUE(delivered->is_bad());
  EXPECT_EQ(delivered->status_code().as_status(), Status::BadTooManyArguments);
  EXPECT_FALSE(handlerRan);
}

// Compile-time negative: the trailing-only invariant (OPC 10000-3 section 5.7.3 / CL-METH-010 -
// optional input arguments shall always follow any non-optional ones) is enforced by a
// static_assert in required_arg_count. A tuple with a required element AFTER an optional one
// must be ill-formed. We assert this without breaking the build via the detail trait that
// backs the static_assert: a well-formed (trailing-only) tuple is valid, an interleaved one
// is not.
TEST(MethodAdapterTests, TrailingOnlyInvariantHoldsForValidTuples)
{
  // Trailing-only tuples are well-formed and their required count counts leading
  // non-optionals.
  static_assert(detail::method_required_arg_count<std::tuple<int32_t, std::optional<String>>>() == 1);
  static_assert(detail::method_required_arg_count<std::tuple<int32_t, String>>() == 2);
  static_assert(detail::method_required_arg_count<std::tuple<>>() == 0);
  static_assert(
    detail::method_required_arg_count<std::tuple<std::optional<int32_t>, std::optional<String>>>() == 0);
  // detail::method_args_trailing_only_v is false when a required element follows an optional;
  // the static_assert inside method_required_arg_count would reject such a tuple at compile
  // time (we cannot instantiate it here without a hard error, so we pin the predicate
  // directly - see the static_assert in ua_method_adapter.h).
  static_assert(detail::method_args_trailing_only_v<std::tuple<int32_t, std::optional<String>>>);
  static_assert(detail::method_args_trailing_only_v<std::tuple<int32_t, String>>);
  static_assert(!detail::method_args_trailing_only_v<std::tuple<std::optional<int32_t>, String>>);
  SUCCEED();
}

// P6a (interface refactor): Node::call holds the MethodCallContext by shared ownership, so a handler that
// completes asynchronously can retain it past the synchronous portion of the call. This guards the
// fix for a latent dangling-context bug - the Call service previously built a stack-local context and
// passed it by raw pointer, which would dangle once the calling step returned. Falsifiable: reverting
// the signature to a raw pointer fails to compile here, and `retained` would dangle once the caller
// drops its own reference below.
TEST(MethodAdapterTests, HandlerRetainsContextPastSynchronousCall)
{
  auto node = default_ns::MethodNode::create(NodeId{1, 42});

  std::shared_ptr<const MethodCallContext> retained;
  CallMethodCompleteCallback parkedCallback;
  node->set_call_handler(
    [&retained, &parkedCallback](const CallMethodRequest&,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      // Co-own the context and defer completion, mimicking an async handler that offloads work.
      retained = std::move(context);
      parkedCallback = std::move(callback);
    });

  auto context = std::make_shared<MethodCallContext>();
  context->sessionId = NodeId{1, 999};

  CallMethodRequest request;
  request.method_id() = NodeId{1, 42};

  bool completed{false};
  node->call(request, context, [&completed](CallResult) { completed = true; });

  // The caller drops its own reference; only the handler's retained shared_ptr keeps the context
  // alive. With the former raw pointer this would be a dangling read.
  context.reset();

  ASSERT_TRUE(static_cast<bool>(retained));
  EXPECT_EQ(retained->sessionId, (NodeId{1, 999}));
  EXPECT_FALSE(completed);

  // The deferred completion still fires exactly once.
  ASSERT_TRUE(static_cast<bool>(parkedCallback));
  parkedCallback(CallResult{CallMethodResult{}});
  EXPECT_TRUE(completed);
}
