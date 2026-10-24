// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Typed method handlers (public API review 2026-10, item 8b sections 9.4, 9.5 and 9.8; D-21): the two
// handler forms, every Part 4 outcome a handler can report and how it reaches the Call's result, the
// argument rejection's ErrorDetail, and the completion's once-only rule.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "test_log_sink.h"
#include "ua_argument.h"
#include "ua_method_adapter.h"
#include "ua_method_arguments.h"
#include "ua_method_result.h"
#include "ua_node_class.h"
#include "ua_to_string.h"

namespace
{
using namespace ua;

const NodeId objectId{2, uint32_t{10}};
const NodeId methodId{2, uint32_t{11}};

std::optional<std::string> context_value(const ErrorDetail& detail, const ContextKey& key)
{
  for (const auto& entry : detail.context)
  {
    if (entry.key == key.value())
    {
      return entry.value;
    }
  }
  return std::nullopt;
}

CallMethodRequest request(std::vector<Variant> inputs)
{
  CallMethodRequest call;
  call.object_id() = objectId;
  call.method_id() = methodId;
  call.input_arguments() = inputs;
  return call;
}

/// Calls @p adapter and returns what it delivers, which must be delivered before it returns.
template<typename Adapter>
CallMethodResult call_now(const Adapter& adapter, std::vector<Variant> inputs)
{
  std::optional<CallResult> delivered;
  adapter(
    request(std::move(inputs)), nullptr, [&delivered](CallResult result) { delivered = std::move(result); });
  EXPECT_TRUE(delivered.has_value()) << "the adapter did not complete the call";
  if (!delivered || delivered->is_bad())
  {
    return CallMethodResult{};
  }
  return std::move(*delivered).value();
}

using Scale = MethodAdapter<std::tuple<double>, std::tuple<double>>;

TEST(MethodResultForms, ASynchronousHandlerReturnsItsOutputs)
{
  const Scale adapter{[](const MethodCall& call, double factor) -> MethodResult<double>
    {
      EXPECT_EQ(call.object_id(), objectId);
      EXPECT_EQ(call.method_id(), methodId);
      return factor * 2.0;
    }};
  const auto result = call_now(adapter, {Variant{3.0}});
  EXPECT_EQ(result.status_code(), StatusCode{Status::Good});
  ASSERT_EQ(result.output_arguments().size(), 1u);
  EXPECT_EQ(result.output_arguments()[0].as<double>(), 6.0);
}

TEST(MethodResultForms, AnAsynchronousHandlerCompletesFromAnotherThread)
{
  std::thread worker;
  const Scale adapter{[&worker](const MethodCall&, double factor, MethodResultCallback<double> done)
    {
      worker = std::thread{[done, factor]
        {
          done(factor + 1.0);
        }};
    }};
  std::promise<CallResult> delivered;
  auto future = delivered.get_future();
  adapter(request({Variant{1.5}}),
    nullptr,
    [&delivered](CallResult result) { delivered.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  worker.join();
  const auto result = future.get().value();
  EXPECT_EQ(result.status_code(), StatusCode{Status::Good});
  EXPECT_EQ(result.output_arguments()[0].as<double>(), 2.5);
}

// A generic lambda matches both forms; the adapter refuses it at compile time.
static_assert(SyncMethodHandler<MethodResult<double> (*)(const MethodCall&, const double&),
  std::tuple<double>, std::tuple<double>>);
static_assert(!AsyncMethodHandler<MethodResult<double> (*)(const MethodCall&, const double&),
              std::tuple<double>, std::tuple<double>>);
static_assert(AsyncMethodHandler<void (*)(const MethodCall&, const double&, MethodResultCallback<double>),
  std::tuple<double>, std::tuple<double>>);
inline constexpr auto genericHandler = [](const MethodCall&, auto&&...) -> MethodResult<>
{
  return {};
};
static_assert(SyncMethodHandler<decltype(genericHandler), std::tuple<>, std::tuple<>> &&
              AsyncMethodHandler<decltype(genericHandler), std::tuple<>, std::tuple<>>);

TEST(MethodResultOutcomes, AnUncertainStatusCarriesTheOutputs)
{
  const MethodAdapter<std::tuple<>, std::tuple<double, int32_t>> adapter{[](const MethodCall&)
    {
      return MethodResult<double, int32_t>::with_status(Status::UncertainDataSubNormal, 1.0, 7);
    }};
  const auto result = call_now(adapter, {});
  EXPECT_EQ(result.status_code(), StatusCode{Status::UncertainDataSubNormal});
  ASSERT_EQ(result.output_arguments().size(), 2u);
  EXPECT_EQ(result.output_arguments()[1].as<int32_t>(), 7);
}

/// Expects @p status to be the Good subcode @p given as the handler gave it: its code and its own
/// ErrorDetail, not the plain Good the Call service answers a client for it.
void expect_kept(const StatusCode& status, const StatusCode& given, const std::string& form)
{
  EXPECT_EQ(status.value(), given.value()) << form << ": " << to_string(status);
  EXPECT_EQ(status.shared_detail(), given.shared_detail()) << form << ": the given code's detail is not kept";
}

// A typed handler's result keeps the Good subcode the handler gave, in every form, with its outputs, and the
// adapter hands it on as the CallMethodResult's statusCode: only the Call service answers it plain Good, to
// a client (OPC 10000-4 5.11.2.4).
// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-TYPED-CALL-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST(MethodResultOutcomes, AGoodSubcodeIsKeptWithTheOutputs)
{
  const shared_ptr<const ErrorDetail> clamped =
    ErrorDetail::build("PumpRateClamped", "The pump clamped the requested rate", "Pump.Start");
  const StatusCode givenClamped{Status::GoodClamped, clamped};

  const auto withStatus = MethodResult<double>::with_status(givenClamped, 1.0);
  expect_kept(withStatus.status_code(), givenClamped, "with_status");
  ASSERT_TRUE(withStatus.has_outputs()) << "with_status dropped the outputs";
  EXPECT_EQ(withStatus.value(), 1.0);

  const StatusCode givenOverride{Status::GoodLocalOverride};
  const MethodResult<> noOutputs{givenOverride};
  expect_kept(noOutputs.status_code(), givenOverride, "a status for a Method with no outputs");
  EXPECT_TRUE(noOutputs.has_outputs());

  const MethodResult<double> fromResult{Result<double>{2.5, givenClamped}};
  expect_kept(fromResult.status_code(), givenClamped, "a Result of the only output's type");
  ASSERT_TRUE(fromResult.has_outputs()) << "a Result holding the output lost it";
  EXPECT_EQ(fromResult.value(), 2.5);

  const StatusCode givenAsync{Status::GoodCompletesAsynchronously};
  const MethodResult<> fromVoid{VoidResult{givenAsync}};
  expect_kept(fromVoid.status_code(), givenAsync, "a VoidResult for a Method with no outputs");
  EXPECT_TRUE(fromVoid.has_outputs());

  const MethodAdapter<std::tuple<>, std::tuple<double>> adapter{[givenClamped](const MethodCall&)
    {
      return MethodResult<double>::with_status(givenClamped, 4.0);
    }};
  const auto called = call_now(adapter, {});
  expect_kept(called.status_code(), givenClamped, "the adapter's CallMethodResult");
  ASSERT_EQ(called.output_arguments().size(), 1u);
  EXPECT_EQ(called.output_arguments()[0].as<double>(), 4.0);

  // Controls: plain Good is the outputs with no ErrorDetail, and a Bad status is not returned with outputs.
  const auto plain = MethodResult<double>::with_status(Status::Good, 1.0);
  EXPECT_EQ(plain.value(), 1.0) << "plain Good is the outputs";
  EXPECT_EQ(plain.status_code().shared_detail(), nullptr);
  EXPECT_EQ(MethodResult<double>::with_status(Status::BadDeviceFailure, 1.0).status_code(),
    StatusCode{Status::BadInternalError})
    << "a Bad status is returned without outputs, not through with_status";
}

// An Uncertain Result holding the only output is that output with its Uncertain status, as with_status gives
// it.
// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-TYPED-CALL-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST(MethodResultOutcomes, AnUncertainResultHoldingTheOutputKeepsItsStatus)
{
  const MethodResult<double> uncertain{Result<double>{3.5, StatusCode{Status::UncertainLastUsableValue}}};
  EXPECT_EQ(uncertain.status_code().value(), StatusCode{Status::UncertainLastUsableValue}.value());
  ASSERT_TRUE(uncertain.has_outputs());
  EXPECT_EQ(uncertain.value(), 3.5);
}

TEST(MethodResultOutcomes, AFailureCarriesItsStatusAndDetailWithoutOutputs)
{
  const MethodAdapter<std::tuple<>, std::tuple<double>> adapter{[](const MethodCall&) -> MethodResult<double>
    {
      return MethodResult<double>{
        Status::BadDeviceFailure, ErrorDetail::build("PumpOffline", "The pump is offline", "Pump.Start")};
    }};
  const auto result = call_now(adapter, {});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadDeviceFailure});
  ASSERT_NE(result.status_code().shared_detail(), nullptr);
  EXPECT_EQ(result.status_code().shared_detail()->code, "PumpOffline");
  EXPECT_TRUE(result.output_arguments().empty());
}

TEST(MethodResultOutcomes, AResultIsPassedOnAndASuccessfulOneNeedsNoOutputs)
{
  const VoidResult written{Status::BadNotWritable};
  EXPECT_EQ(MethodResult<double>{written}.status_code(), StatusCode{Status::BadNotWritable});
  EXPECT_EQ(MethodResult<>{VoidResult{}}.status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(MethodResult<>{VoidResult{}}.has_outputs());
  EXPECT_EQ(MethodResult<double>{Result<double>{2.5}}.value(), 2.5)
    << "a Result of the only output's type is it";
  const auto missing = MethodResult<double>{Result<int32_t>{5}};
  EXPECT_EQ(missing.status_code(), StatusCode{Status::BadInternalError})
    << "a successful Result carries none of the Method's outputs";
}

TEST(MethodResultOutcomes, OutputsThrowTheResultsOwnStatus)
{
  const MethodResult<double> failed{Status::BadDeviceFailure};
  try
  {
    (void)failed.value();
    FAIL() << "value() of a failure must throw";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadDeviceFailure);
  }
}

TEST(MethodResultOutcomes, AThrowingHandlerIsAnInternalErrorWithTheCause)
{
  const Scale adapter{[](const MethodCall&, double) -> MethodResult<double>
    {
      throw UaException{Status::BadOutOfRange, ErrorDetail::build("TooFast", "Too fast", "Mixer")};
    }};
  const auto result = call_now(adapter, {Variant{1.0}});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "MethodHandlerThrew");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->code, "TooFast");
}

TEST(MethodResultCompletion, ADroppedCompletionIsAnInternalErrorNamingTheMethod)
{
  const Scale adapter{[](const MethodCall&, double, MethodResultCallback<double>) {
  }};
  const auto result = call_now(adapter, {Variant{1.0}});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "MethodCompletionDropped");
  EXPECT_EQ(context_value(*detail, ContextKeys::methodId), to_string(methodId));
}

TEST(MethodResultCompletion, ASecondCompletionIsIgnoredAndLogged)
{
  ua::test::TestLogSink sink;
  int deliveries = 0;
  std::optional<CallResult> first;
  const Scale adapter{[](const MethodCall&, double, MethodResultCallback<double> done)
    {
      done(1.0);
      done(2.0);
    },
    inputs(arg<double>("Factor")),
    sink.logger()};
  adapter(request({Variant{1.0}}),
    nullptr,
    [&deliveries, &first](CallResult result)
    {
      ++deliveries;
      first = std::move(result);
    });
  EXPECT_EQ(deliveries, 1);
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first->value().output_arguments()[0].as<double>(), 1.0) << "the first result counts";
  EXPECT_EQ(sink.count(LogLevel::Error), 1u);
}

TEST(MethodResultRejection, ARejectedArgumentCarriesTheHandlersDetailAndTheSdksFacts)
{
  const MethodAdapter<std::tuple<double, std::optional<bool>>, std::tuple<double>> adapter{
    [](const MethodCall&, double, std::optional<bool>) -> MethodResult<double>
    {
      return reject_argument(0,
        Status::BadOutOfRange,
        ErrorDetail::build("NegativeSpeed", "Rpm must not be negative", "Mixer.SetSpeed")
          .context(ContextKeys::min, "0"))
        .and_argument(1, Status::BadTypeMismatch);
    },
    inputs(arg<double>("Rpm"), arg<std::optional<bool>>("Ramp"))};
  const auto result = call_now(adapter, {Variant{-5.0}});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_EQ(result.input_argument_results().size(), 2u);
  EXPECT_EQ(result.input_argument_results()[0], StatusCode{Status::BadOutOfRange});
  EXPECT_EQ(result.input_argument_results()[1], StatusCode{Status::BadTypeMismatch});

  const auto given = result.input_argument_diagnostic_infos()[0].inner_status_code()->shared_detail();
  ASSERT_NE(given, nullptr);
  EXPECT_EQ(given->code, "NegativeSpeed");
  EXPECT_TRUE(context_value(*given, ContextKeys::min).has_value()) << "the handler's own facts are kept";
  EXPECT_EQ(context_value(*given, ContextKeys::operationIndex), "0");
  EXPECT_EQ(context_value(*given, ContextKeys::argumentName), "Rpm");
  EXPECT_EQ(context_value(*given, ContextKeys::methodId), to_string(methodId));
  EXPECT_EQ(context_value(*given, ContextKeys::objectId), to_string(objectId));
  EXPECT_FALSE(context_value(*given, ContextKeys::value).has_value()) << "the SDK never adds the value";

  const auto minimal = result.input_argument_diagnostic_infos()[1].inner_status_code()->shared_detail();
  ASSERT_NE(minimal, nullptr);
  EXPECT_EQ(minimal->code, "MethodArgumentRejected");
  EXPECT_EQ(minimal->innerStatus, StatusCode{Status::BadTypeMismatch}.value());
  EXPECT_EQ(context_value(*minimal, ContextKeys::argumentName), "Ramp");
}

TEST(MethodResultRejection, AMalformedRejectionIsTheHandlersMistake)
{
  const Scale outOfRange{[](const MethodCall&, double) -> MethodResult<double>
    {
      return reject_argument(3, Status::BadOutOfRange);
    }};
  EXPECT_EQ(call_now(outOfRange, {Variant{1.0}}).status_code(), StatusCode{Status::BadInternalError});
  EXPECT_EQ(MethodResult<double>{reject_argument(0, Status::Good)}.status_code(),
    StatusCode{Status::BadInternalError});
  EXPECT_EQ(
    MethodResult<double>{reject_argument(0, Status::BadOutOfRange).and_argument(0, Status::BadTypeMismatch)}
      .status_code(),
    StatusCode{Status::BadInternalError});
}

TEST(MethodResultValues, EveryMappedKindDecodesAndEncodes)
{
  using Inputs = std::tuple<std::string, NodeClass, Argument, std::vector<double>, std::optional<int32_t>>;
  using Outputs = std::tuple<std::string, NodeClass, Argument, std::vector<double>>;
  std::optional<int32_t> optionalSeen{-1};
  const MethodAdapter<Inputs, Outputs> adapter{
    [&optionalSeen](const MethodCall&,
      const std::string& text,
      NodeClass nodeClass,
      const Argument& argument,
      const std::vector<double>& values,
      std::optional<int32_t>
        optional) -> MethodResult<std::string, NodeClass, Argument, std::vector<double>>
    {
      optionalSeen = optional;
      return {text + "!", nodeClass, argument, values};
    }};
  Argument described;
  described.name() = "Factor";
  Array<double> values;
  values = std::vector<double>{1.0, 2.0};
  const auto result = call_now(
    adapter, {Variant{String{"go"}}, Variant{int32_t{4}}, Variant{described}, Variant{std::move(values)}});
  ASSERT_EQ(result.status_code(), StatusCode{Status::Good});
  EXPECT_FALSE(optionalSeen.has_value()) << "an omitted trailing optional argument is nullopt";
  ASSERT_EQ(result.output_arguments().size(), 4u);
  EXPECT_EQ(result.output_arguments()[0].as<String>(), String{"go!"});
  EXPECT_EQ(result.output_arguments()[1].as<int32_t>(), 4) << "an enumeration travels as its Int32 value";
  ASSERT_NE(result.output_arguments()[2].try_as<Argument>(), nullptr);
  EXPECT_EQ(result.output_arguments()[2].try_as<Argument>()->name(), String{"Factor"});
  EXPECT_EQ(result.output_arguments()[3].as<Array<double>>().payload(), (std::vector<double>{1.0, 2.0}));
}

TEST(MethodResultValues, AMismatchedArgumentIsRejectedByNameWithoutCallingTheHandler)
{
  bool called = false;
  const Scale adapter{[&called](const MethodCall&, double) -> MethodResult<double>
    {
      called = true;
      return 0.0;
    },
    inputs(arg<double>("Factor"))};
  const auto result = call_now(adapter, {Variant{String{"two"}}});
  EXPECT_FALSE(called);
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(result.input_argument_results()[0], StatusCode{Status::BadTypeMismatch});
  const auto detail = result.input_argument_diagnostic_infos()[0].inner_status_code()->shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(context_value(*detail, ContextKeys::argumentName), "Factor");
  EXPECT_EQ(context_value(*detail, ContextKeys::typeExpected), "Double");
}

/// The outputs of a generated binding's Method, as one struct.
struct SpeedOutputs
{
  double speed{};
  int32_t driveCode{};
};

// Item 8b section 9.9: a generated binding's handler reports a struct; the struct reaches the adapter one
// output at a time, with its status and argument results, and the struct completion keeps the once-only
// rule (dropped -> Bad_InternalError, never a hung call).
TEST(MethodResultGenerated, AStructResultReachesThePerArgumentCompletion)
{
  const auto toTuple = [](const SpeedOutputs& out)
  {
    return std::tuple<double, int32_t>{out.speed, out.driveCode};
  };
  std::vector<MethodResult<double, int32_t>> delivered;
  auto inner = detail::MethodResultCallbackFactory::make<double, int32_t>(
    [&delivered](MethodResult<double, int32_t> result) { delivered.push_back(std::move(result)); },
    Logger{},
    methodId);
  {
    auto outer = detail::struct_method_result_callback<SpeedOutputs>(inner, toTuple, Logger{}, methodId);
    outer(MethodResult<SpeedOutputs>::with_status(Status::UncertainDataSubNormal, SpeedOutputs{12.5, 7}));
  }
  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_EQ(delivered[0].status_code(), StatusCode{Status::UncertainDataSubNormal});
  EXPECT_EQ(std::get<1>(delivered[0].outputs()), 7);

  const auto rejected = detail::method_result_from_struct<double, int32_t>(
    MethodResult<SpeedOutputs>{reject_argument(1, Status::BadOutOfRange)}, toTuple);
  EXPECT_EQ(rejected.status_code(), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(rejected.argument_results().at(1), StatusCode{Status::BadOutOfRange});

  std::vector<MethodResult<double, int32_t>> dropped;
  {
    auto innerDropped = detail::MethodResultCallbackFactory::make<double, int32_t>(
      [&dropped](MethodResult<double, int32_t> result) { dropped.push_back(std::move(result)); },
      Logger{},
      methodId);
    auto outer =
      detail::struct_method_result_callback<SpeedOutputs>(innerDropped, toTuple, Logger{}, methodId);
  }
  ASSERT_EQ(dropped.size(), 1u);
  EXPECT_EQ(dropped[0].status_code(), StatusCode{Status::BadInternalError});
  EXPECT_EQ(dropped[0].status_code().shared_detail()->code, "MethodCompletionDropped");
}

TEST(MethodArguments, AnArgumentNamesItsTypeAndARuntimeOneCarriesItsOwn)
{
  const auto described =
    inputs(arg<double>("Factor", "Multiplies the setpoint"), arg<std::optional<bool>>("Ramp"));
  EXPECT_EQ(std::get<0>(described.args).name, "Factor");
  EXPECT_EQ(std::get<0>(described.args).description.text(), String{"Multiplies the setpoint"});
  EXPECT_FALSE(std::get<0>(described.args).dataType.has_value());
  const auto runtime = argument("Recipe", NodeId{3, uint32_t{3005}}, ValueRank::scalar);
  EXPECT_EQ(runtime.dataType, (NodeId{3, uint32_t{3005}}));
  EXPECT_EQ(runtime.valueRank, ValueRank::scalar);
}

}  // namespace
