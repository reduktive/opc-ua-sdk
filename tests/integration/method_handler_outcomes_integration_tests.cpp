// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Each outcome a typed method handler can report reaches a client as OPC 10000-4 5.11.2.2 says (public API
// review 2026-10, item 8b section 9.6; D-21): the status, the outputs, the per-argument results and the
// diagnostics, over a real Call. Also which thread runs a handler (section 9.11).

#include <gtest/gtest.h>

#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "compliance_helpers.h"
#include "ua_add_method.h"
#include "ua_call_request.h"
#include "ua_call_response.h"

using namespace ua;
using namespace ua::client;

namespace
{

/// Whether a DiagnosticInfo, or one inside it, names @p text in its AdditionalInfo or in a string-table
/// entry it indexes.
bool names(const DiagnosticInfo& info, const Array<String>& table, const std::string& text)
{
  const auto indexed = [&](const std::optional<int32_t>& index)
  {
    return index.has_value() && *index >= 0 && static_cast<size_t>(*index) < table.size() &&
           std::string{static_cast<std::string_view>(table[static_cast<size_t>(*index)])}.find(text) !=
             std::string::npos;
  };
  for (const DiagnosticInfo* link = &info; link != nullptr; link = link->inner_diagnostic_info().get())
  {
    if (link->additional_info().has_value() && link->additional_info()->find(text) != std::string::npos)
    {
      return true;
    }
    if (indexed(link->symbolic_id()) || indexed(link->localized_text()) || indexed(link->namespace_uri()))
    {
      return true;
    }
  }
  return false;
}

class MethodHandlerOutcomes : public ComplianceSecuredWithSession
{
protected:
  // Diagnostics only cross a secured channel (the collector refuses SecurityPolicy None), so the session
  // is SignAndEncrypt and the server returns every diagnostic the client asks for.
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.diagnosticPolicy.defaultLevel = server::ServerConfig::DiagnosticPolicy::Level::Full;
  }

  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();
    auto addressSpace = mServer->address_space();
    RolePermissionType anonymous;
    anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymous.permissions() = ua::test_helpers::all_permissions();
    mTestNamespaceIndex =
      addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:method-outcomes", {anonymous}));
    mTestFolderId = NodeId{mTestNamespaceIndex, "Methods"};
    auto folder = addressSpace.create_node_sync(mTestFolderId, NodeClass::Object);
    folder.set_browse_name(QualifiedName{mTestNamespaceIndex, "Methods"});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mTestFolderId);

    add("Outputs",
      inputs(arg<double>("X")),
      outputs(arg<double>("Doubled")),
      [](const MethodCall&, double x) -> MethodResult<double> { return x * 2.0; });
    add("AsyncOutputs",
      inputs(arg<double>("X")),
      outputs(arg<double>("Doubled")),
      [this](const MethodCall&, double x, MethodResultCallback<double> done)
      {
        const std::lock_guard lock{mWorkersMutex};
        mWorkers.emplace_back([done, x] { done(x * 2.0); });
      });
    add("Uncertain",
      inputs(),
      outputs(arg<double>("Speed"), arg<int32_t>("DriveCode")),
      [](const MethodCall&)
      { return MethodResult<double, int32_t>::with_status(Status::UncertainDataSubNormal, 12.5, 7); });
    add("GoodSubcode",
      inputs(),
      outputs(arg<double>("Speed")),
      [](const MethodCall&) { return MethodResult<double>::with_status(Status::GoodClamped, 12.5); });
    add("Fails",
      inputs(),
      outputs(arg<double>("Speed")),
      [](const MethodCall&) -> MethodResult<double>
      {
        return MethodResult<double>{
          Status::BadDeviceFailure, ErrorDetail::build("PumpOffline", "The pump is offline", "Pump.Start")};
      });
    add("Rejects",
      inputs(arg<double>("Rpm")),
      outputs(),
      [](const MethodCall&, double rpm) -> MethodResult<>
      {
        if (rpm < 0.0)
        {
          return reject_argument(0,
            Status::BadOutOfRange,
            ErrorDetail::build("NegativeSpeed", "Rpm must not be negative", "Mixer"));
        }
        return {};
      });
    add("Throws",
      inputs(),
      outputs(),
      [](const MethodCall&) -> MethodResult<>
      { throw UaException{Status::BadOutOfRange, ErrorDetail::build("Overheated", "Overheated", "Pump")}; });
    add("Drops", inputs(), outputs(), [](const MethodCall&, MethodResultCallback<> done) { (void)done; });
    add("Thread",
      inputs(),
      outputs(arg<uint32_t>("FindStatus")),
      // Weak: the handler is stored in this address space, which a strong capture would keep alive forever.
      [weakAddressSpace = addressSpace.weak(), folder = mTestFolderId](
        const MethodCall&) -> MethodResult<uint32_t>
      {
        auto lockedAddressSpace = weakAddressSpace.lock();
        if (!lockedAddressSpace)
        {
          return MethodResult<uint32_t>{Status::BadShutdown,
            ErrorDetail::build("AddressSpaceGone", "The address space no longer exists", "Thread")};
        }
        return lockedAddressSpace->try_find_node_sync(folder).status_code().value();
      });
  }

  void TearDown() override
  {
    {
      const std::lock_guard lock{mWorkersMutex};
      for (auto& worker : mWorkers)
      {
        worker.join();
      }
    }
    ComplianceSecuredWithSession::TearDown();
  }

  template<typename... In, typename... Out, typename Handler>
  void add(const std::string& name, Inputs<In...> in, Outputs<Out...> out, Handler handler)
  {
    add_method_sync(mServer->address_space(),
      mTestFolderId,
      QualifiedName{mTestNamespaceIndex, name},
      std::move(in),
      std::move(out),
      std::move(handler),
      MethodConfig{.nodeId = NodeId{mTestNamespaceIndex, name}});
  }

  /// Calls the Method @p name on the test folder, asking for every operation-level diagnostic.
  CallResponse call(
    const std::string& name, std::vector<Variant> in = {}, uint32_t returnDiagnostics = 0x03E0)
  {
    CallRequest request;
    request.request_header().return_diagnostics() = returnDiagnostics;
    CallMethodRequest method;
    method.object_id() = mTestFolderId;
    method.method_id() = NodeId{mTestNamespaceIndex, name};
    method.input_arguments() = in;
    request.methods_to_call().push_back(std::move(method));
    auto response = mSession->methods().try_call_sync(std::move(request));
    EXPECT_TRUE(response.is_good()) << to_string(response.status_code());
    if (response.is_bad())
    {
      return CallResponse{};
    }
    EXPECT_EQ(response.value().results().size(), 1u);
    return std::move(response).value();
  }

  uint16_t mTestNamespaceIndex{0};
  NodeId mTestFolderId;
  std::mutex mWorkersMutex;
  std::vector<std::thread> mWorkers;
};

TEST_F(MethodHandlerOutcomes, OutputsReachTheClientFromEitherForm)
{
  for (const std::string name : {"Outputs", "AsyncOutputs"})
  {
    const auto response = call(name, {Variant{4.0}});
    ASSERT_EQ(response.results().size(), 1u);
    const auto& result = response.results()[0];
    EXPECT_EQ(result.status_code(), StatusCode{Status::Good}) << name;
    ASSERT_EQ(result.output_arguments().size(), 1u) << name;
    EXPECT_EQ(result.output_arguments()[0].as<double>(), 8.0) << name;
    EXPECT_TRUE(result.input_argument_results().empty()) << name;
  }
}

TEST_F(MethodHandlerOutcomes, AnUncertainStatusReachesTheClientWithTheOutputs)
{
  const auto response = call("Uncertain");
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results()[0];
  EXPECT_EQ(result.status_code(), StatusCode{Status::UncertainDataSubNormal});
  ASSERT_EQ(result.output_arguments().size(), 2u);
  EXPECT_EQ(result.output_arguments()[0].as<double>(), 12.5);
  EXPECT_EQ(result.output_arguments()[1].as<int32_t>(), 7);
}

TEST_F(MethodHandlerOutcomes, AFailureReachesTheClientWithItsDiagnosticAndNoOutputs)
{
  const auto response = call("Fails");
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results()[0];
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadDeviceFailure});
  EXPECT_TRUE(result.output_arguments().empty());
  ASSERT_EQ(response.diagnostic_infos().size(), 1u);
  EXPECT_TRUE(names(response.diagnostic_infos()[0], response.response_header().string_table(), "PumpOffline"))
    << "the handler's ErrorDetail reaches the client's diagnostics";
}

// A Good status with a subcode never reaches a client as a Method's statusCode (OPC 10000-4 5.11.2.4): the
// Call service answers a typed handler's Good subcode plain Good with the outputs, and the operation's
// diagnostics name MethodStatusQualified with the handler's code as the inner status.
// @relation(AC-SVR-METH-CALL-031-A-TYPED-HANDLERS-GOOD-SUBCODE-IS-ANSWERED-GOOD, scope=function)
TEST_F(MethodHandlerOutcomes, AGoodSubcodeReachesTheClientAsGoodWithTheOutputs)
{
  const auto response = call("GoodSubcode");
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results()[0];
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::Good}.value())
    << to_string(result.status_code());
  ASSERT_EQ(result.output_arguments().size(), 1u) << "the outputs were dropped";
  EXPECT_EQ(result.output_arguments()[0].as<double>(), 12.5);
  ASSERT_EQ(response.diagnostic_infos().size(), 1u);
  EXPECT_TRUE(names(
    response.diagnostic_infos()[0], response.response_header().string_table(), "MethodStatusQualified"));
  ASSERT_TRUE(response.diagnostic_infos()[0].inner_status_code().has_value())
    << "the handler's code does not reach the client's diagnostics";
  EXPECT_EQ(
    response.diagnostic_infos()[0].inner_status_code()->value(), StatusCode{Status::GoodClamped}.value());
}

TEST_F(MethodHandlerOutcomes, ARejectedArgumentReachesTheClientWithItsStatusAndDiagnostic)
{
  const auto response = call("Rejects", {Variant{-5.0}});
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results()[0];
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_EQ(result.input_argument_results().size(), 1u);
  EXPECT_EQ(result.input_argument_results()[0], StatusCode{Status::BadOutOfRange});
  ASSERT_EQ(result.input_argument_diagnostic_infos().size(), 1u);
  const auto& table = response.response_header().string_table();
  EXPECT_TRUE(names(result.input_argument_diagnostic_infos()[0], table, "NegativeSpeed"));
  EXPECT_TRUE(names(result.input_argument_diagnostic_infos()[0], table, "Rpm"))
    << "the SDK adds the argument's name";
  EXPECT_FALSE(names(result.input_argument_diagnostic_infos()[0], table, "-5"))
    << "the SDK never adds the argument's value";

  const auto unasked = call("Rejects", {Variant{-5.0}}, 0);
  ASSERT_EQ(unasked.results().size(), 1u);
  EXPECT_EQ(unasked.results()[0].input_argument_results()[0], StatusCode{Status::BadOutOfRange});
  EXPECT_TRUE(unasked.results()[0].input_argument_diagnostic_infos().empty())
    << "the list is empty when the client asked for no diagnostics (OPC 10000-4 5.11.2.2)";

  const auto accepted = call("Rejects", {Variant{5.0}});
  ASSERT_EQ(accepted.results().size(), 1u);
  EXPECT_EQ(accepted.results()[0].status_code(), StatusCode{Status::Good});
}

TEST_F(MethodHandlerOutcomes, AThrowAndADroppedCompletionReachTheClientAsInternalErrors)
{
  for (const auto& [name, code] : {std::pair{std::string{"Throws"}, std::string{"MethodHandlerThrew"}},
         std::pair{std::string{"Drops"}, std::string{"MethodCompletionDropped"}}})
  {
    const auto response = call(name);
    ASSERT_EQ(response.results().size(), 1u) << name;
    EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadInternalError}) << name;
    ASSERT_EQ(response.diagnostic_infos().size(), 1u) << name;
    EXPECT_TRUE(names(response.diagnostic_infos()[0], response.response_header().string_table(), code))
      << name;
  }
}

// Section 9.11: a handler runs on a thread of the server's executor, so a *_sync call from it is refused
// with Bad_WouldBlock rather than blocking that thread; a handler that needs the address space uses the
// asynchronous form.
TEST_F(MethodHandlerOutcomes, AHandlerRunsWhereABlockingCallIsRefused)
{
  const auto response = call("Thread");
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_EQ(response.results()[0].status_code(), StatusCode{Status::Good});
  ASSERT_EQ(response.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(
    response.results()[0].output_arguments()[0].as<uint32_t>(), StatusCode{Status::BadWouldBlock}.value());
}

}  // namespace
