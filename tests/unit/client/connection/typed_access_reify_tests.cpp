// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// End-to-end unit tests for the TypeResolver reify CONSUMER wired into the tier-2 typed accessors (Slice T1
// Phase A2, client design section 9.2). A structured value the wire decoder left as an UnknownStructure
// placeholder must be upgraded to its concrete typed Structure - using the per-Connection TypeRegistry -
// BEFORE it is delivered to the user completion, on the read-values and call-method application-data paths.
// Driven over a real ConnectionImpl (FakeSessionOps tier-0 interface) with a user-registered Argument prototype.
//
// Falsifiability: without the consumer wired into read_values_async / call_method_async, the caller receives
// the raw UnknownStructure and both ReadValuesReifiesRegisteredStructure and
// CallMethodReifiesRegisteredOutputArgument fail (they assert the concrete Argument). The fast-path control
// (ReadValuesNoStructureIsUnchanged) stays green either way, guarding against a regression that mangles the
// common no-structure response.
//
// @verifies CL-BASE-008 - user-registered type pre-knowledge reifies an application-data placeholder.
// @relation(CL-BASE-008, scope=file)
// @verifies CL-ATTR-012 - resolve_async is reached from the production read/call delivery path.
// @relation(CL-ATTR-012, scope=file)

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_type_resolver.h"

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_binary_codec.h"
#include "ua_call_method_result.h"
#include "ua_call_response.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <future>
#include <memory>
#include <utility>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::Session;
using ua::client::TypedAccess;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::RegistrationOutcome;
using ua::client::detail::UserTypeRegistration;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;
using ua::test_helpers::make_namespace_array_response;

using TA = ConnectionImplTestAccess;

ua::EncodingLimits limits()
{
  return ua::make_encoding_limits(ua::ApplicationConfig::load_default());
}

ua::NodeId argument_binary_encoding()
{
  return ua::NodeId{ua::Argument::defaultBinaryEncodingId};
}

// Encode then decode an Argument with NO resolver -> an opaque UnknownStructure, as the client
// secure-channel decoder leaves an unresolved encoding.
ua::Variant make_argument_opaque_variant()
{
  ua::Argument argument;
  argument.name() = "Speed";
  argument.data_type() = ua::NodeId{0, 11u};
  argument.value_rank() = -1;

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, stream};
  encoder.encode(limits().stack_depth(), &argument);
  stream.seek_from_start(0);
  ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits()};
  ua::unique_ptr<ua::Structure> opaque;
  decoder.decode(limits().stack_depth(), opaque);
  return ua::Variant{std::move(opaque)};
}

bool is_argument(const ua::Variant& value)
{
  return value.is_structure() && dynamic_cast<const ua::Argument*>(&value.as<ua::Structure>()) != nullptr;
}

class TypedAccessReifyTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    // Bootstrap NamespaceArray read: UA at index 0, so the user registration below binds immediately.
    mSession->read.set_result(
      Result<ua::ReadResponse>{make_namespace_array_response({"http://opcfoundation.org/UA/"})});

    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      ua::client::ReconnectPolicy{},
      {});
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());

    // Register the Argument type with a real decode prototype (URI = UA -> index 0). The bootstrap already
    // seeded the resolver's NamespaceTable, so the URI is bound and the registration installs immediately.
    UserTypeRegistration registration;
    registration.namespaceUri = "http://opcfoundation.org/UA/";
    registration.dataTypeIdentifier = ua::NodeId{0, 296};
    registration.binaryEncodingIdentifier = argument_binary_encoding();
    registration.decoder = std::make_shared<ua::Argument>();

    std::promise<std::vector<RegistrationOutcome>> registered;
    auto registeredFuture = registered.get_future();
    mConnection->type_resolver()->register_types_async(std::vector<UserTypeRegistration>{registration},
      [&registered](Result<std::vector<RegistrationOutcome>> result)
      { registered.set_value(result.value()); });
    const auto outcomes = registeredFuture.get();
    ASSERT_EQ(outcomes.size(), 1u);
    ASSERT_TRUE(outcomes[0].status.is_good()) << "the UA-namespace registration must bind immediately";
  }

  TypedAccess make_typed_access()
  {
    return ConnectionHandleFactory::make_typed_access(mConnection);
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

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST_F(TypedAccessReifyTest, ReadValuesReifiesRegisteredStructure)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{make_argument_opaque_variant()});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::DataValue>>(
    [&](auto cb) { typed.read_values_async({ua::NodeId{0, 42}}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1u);
  ASSERT_TRUE(is_argument(result.value()[0].value()))
    << "the read consumer must reify the UnknownStructure to the user-registered Argument";
  const auto* argument = dynamic_cast<const ua::Argument*>(&result.value()[0].value().as<ua::Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), ua::String{"Speed"});
}

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST_F(TypedAccessReifyTest, CallMethodReifiesRegisteredOutputArgument)
{
  ua::CallMethodResult methodResult;
  methodResult.status_code() = ua::StatusCode{Status::Good};
  methodResult.output_arguments().push_back(make_argument_opaque_variant());
  ua::CallResponse response;
  response.results().push_back(std::move(methodResult));
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().is_good());
  ASSERT_EQ(result.value().value().output_arguments().size(), 1u);
  ASSERT_TRUE(is_argument(result.value().value().output_arguments()[0]))
    << "the call consumer must reify the output-argument UnknownStructure to the registered Argument";
}

// Fast-path control: a response with no structured value is delivered unchanged (guards against a
// regression in the common path).
TEST_F(TypedAccessReifyTest, ReadValuesNoStructureIsUnchanged)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{7}}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<ua::DataValue>>(
    [&](auto cb) { typed.read_values_async({ua::NodeId{0, 42}}, std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(result.value()[0].value().to<std::int32_t>().value(), 7);
}

}  // namespace
