// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "demo_model.h"

#include "ua_call_method_request.h"
#include "ua_datatype_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_reference.h"
#include "ua_reference_demo_demo.h"
#include "ua_reference_demo_object_id.h"
#include "ua_reference_demo_objecttype_id.h"
#include "ua_reference_demo_variable_id.h"
#include "ua_referencetype_id.h"
#include "ua_test_server.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_variabletype_id.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace
{
namespace model = ua::reference_demo;
namespace reference = reduktive::reference;

ua::NodeId model_id(std::uint16_t namespaceIndex, model::ObjectId id)
{
  return ua::NodeId{namespaceIndex, static_cast<std::uint32_t>(id)};
}

ua::NodeId model_id(std::uint16_t namespaceIndex, model::ObjectTypeId id)
{
  return ua::NodeId{namespaceIndex, static_cast<std::uint32_t>(id)};
}

ua::NodeId model_id(std::uint16_t namespaceIndex, model::VariableId id)
{
  return ua::NodeId{namespaceIndex, static_cast<std::uint32_t>(id)};
}

bool has_reference(
  const ua::References& references, const ua::NodeId& type, const ua::NodeId& target, bool isForward)
{
  for (const auto& referenceEntry : references)
  {
    if (referenceEntry.type_id() == type && referenceEntry.is_forward() == isForward &&
        referenceEntry.target_id().is_local() && referenceEntry.target_id().node_id() == target)
    {
      return true;
    }
  }
  return false;
}

void expect_rich_failure(
  const ua::StatusCode& status, ua::Status expectedStatus, std::string_view expectedDetailCode)
{
  EXPECT_EQ(status.as_status(), expectedStatus);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_NE(ua::to_string(*status.shared_detail()).find(expectedDetailCode), std::string::npos);
}

// @relation(AC-COMP-REF-DEMO-MODEL-01-BOUNDARIES, scope=function)
TEST(ReferenceDemoModelLogic, AcceptsSetpointBoundariesAndInterior)
{
  const ua::NodeId setpointId{2, 2003U};
  for (const double value : {0.0, 37.5, 100.0})
  {
    const auto result = reference::try_validate_setpoint(ua::DataValue{ua::Variant{value}}, setpointId);
    ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
    EXPECT_EQ(result.value(), value);
  }
}

// @relation(AC-COMP-REF-DEMO-MODEL-01-TYPE, scope=function)
TEST(ReferenceDemoModelLogic, RejectsNonDoubleSetpointWithRichStatus)
{
  const ua::NodeId setpointId{2, 2003U};
  const auto result =
    reference::try_validate_setpoint(ua::DataValue{ua::Variant{ua::String{"not a Double"}}}, setpointId);

  ASSERT_FALSE(result.is_good());
  expect_rich_failure(result.status_code(), ua::Status::BadTypeMismatch, "ReferenceSetpointTypeMismatch");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find(ua::to_string(setpointId)), std::string::npos);
}

// @relation(AC-COMP-REF-DEMO-MODEL-01-RANGE, scope=function)
TEST(ReferenceDemoModelLogic, RejectsEveryInvalidSetpointNumericClass)
{
  const ua::NodeId setpointId{2, 2003U};
  const double invalidValues[]{
    -0.1, 100.1, std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN()};

  for (const double value : invalidValues)
  {
    const auto result = reference::try_validate_setpoint(ua::DataValue{ua::Variant{value}}, setpointId);
    ASSERT_FALSE(result.is_good());
    expect_rich_failure(result.status_code(), ua::Status::BadOutOfRange, "ReferenceSetpointOutOfRange");
    EXPECT_NE(ua::to_string(*result.shared_detail()).find(ua::to_string(setpointId)), std::string::npos);
  }
}

// @relation(AC-COMP-REF-DEMO-MODEL-02-QUOTIENT, scope=function)
TEST(ReferenceDemoModelLogic, DividesValidInt32Operands)
{
  const ua::NodeId methodId{2, 2004U};
  const auto positive = reference::try_divide(84, 2, methodId);
  const auto signedResult = reference::try_divide(-9, 2, methodId);

  ASSERT_TRUE(positive.is_good()) << ua::to_string(positive.status_code());
  ASSERT_TRUE(signedResult.is_good()) << ua::to_string(signedResult.status_code());
  EXPECT_EQ(positive.value(), 42);
  EXPECT_EQ(signedResult.value(), -4);
}

// @relation(AC-COMP-REF-DEMO-MODEL-02-ZERO, scope=function)
TEST(ReferenceDemoModelLogic, RejectsZeroDivisorWithRichStatus)
{
  const ua::NodeId methodId{2, 2004U};
  const auto result = reference::try_divide(84, 0, methodId);

  ASSERT_FALSE(result.is_good());
  expect_rich_failure(result.status_code(), ua::Status::BadInvalidArgument, "ReferenceDivideByZero");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find(ua::to_string(methodId)), std::string::npos);
}

// @relation(AC-COMP-REF-DEMO-MODEL-02-OVERFLOW, scope=function)
TEST(ReferenceDemoModelLogic, RejectsOverflowingDivisionWithRichStatus)
{
  const ua::NodeId methodId{2, 2004U};
  const auto result = reference::try_divide(std::numeric_limits<std::int32_t>::min(), -1, methodId);

  ASSERT_FALSE(result.is_good());
  expect_rich_failure(result.status_code(), ua::Status::BadOutOfRange, "ReferenceDivideOverflow");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find(ua::to_string(methodId)), std::string::npos);
}

// @relation(AC-COMP-REF-DEMO-MODEL-03-BINDING, scope=function)
TEST(ReferenceDemoModelBinding, ImportsExternalModelAndBindsTypedHandlers)
{
  ua::test_helpers::TestServer testServer;
  testServer.create();

  const auto configured = reference::try_configure_demo_model(
    testServer.server(), std::filesystem::path{UA_REFERENCE_DEMO_MODEL_PATH}, ua::Logger{});
  ASSERT_TRUE(configured.is_good()) << ua::to_string(configured.status_code());

  auto addressSpace = testServer.server().address_space();
  const std::uint16_t namespaceIndex =
    addressSpace.namespace_array().get_namespace_index(reference::demoNamespaceUri);

  const auto demoNamespace = addressSpace.namespace_array().get_namespace(namespaceIndex);
  ASSERT_NE(demoNamespace, nullptr);
  const auto namespacePermissions = demoNamespace->default_role_permissions();
  ASSERT_TRUE(namespacePermissions.has_value());
  ASSERT_EQ(namespacePermissions->size(), 1U);
  EXPECT_EQ(namespacePermissions->front().role_id(), ua::NodeId{ua::ObjectId::WellKnownRole_Observer});
  const auto observerPermissions = namespacePermissions->front().permissions();
  EXPECT_TRUE(observerPermissions.test(ua::PermissionType::Bit::Browse));
  EXPECT_TRUE(observerPermissions.test(ua::PermissionType::Bit::Read));
  EXPECT_TRUE(observerPermissions.test(ua::PermissionType::Bit::Write));
  EXPECT_TRUE(observerPermissions.test(ua::PermissionType::Bit::Call));

  auto demoResult =
    model::Demo::try_attach_sync(addressSpace, model_id(namespaceIndex, model::ObjectId::Demo));
  ASSERT_TRUE(demoResult.is_good()) << ua::to_string(demoResult.status_code());
  auto demo = std::move(demoResult).value();

  auto demoNodeResult = addressSpace.try_find_node_sync(demo.node_id());
  ASSERT_TRUE(demoNodeResult.is_good()) << ua::to_string(demoNodeResult.status_code());
  EXPECT_FALSE(demoNodeResult.value().get_role_permissions().has_value());
  auto demoReferencesResult = demoNodeResult.value().try_get_references_sync();
  ASSERT_TRUE(demoReferencesResult.is_good()) << ua::to_string(demoReferencesResult.status_code());
  EXPECT_TRUE(has_reference(demoReferencesResult.value(),
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
    model_id(namespaceIndex, model::ObjectTypeId::DemoType),
    true));

  auto uptimeResult = demo.try_uptime_seconds_sync();
  ASSERT_TRUE(uptimeResult.is_good()) << ua::to_string(uptimeResult.status_code());
  auto uptimeValueResult = uptimeResult.value().try_read_value_sync();
  ASSERT_TRUE(uptimeValueResult.is_good()) << ua::to_string(uptimeValueResult.status_code());
  auto uptimeDecoded = uptimeValueResult.value().value().to<std::uint32_t>();
  ASSERT_TRUE(uptimeDecoded.is_good()) << ua::to_string(uptimeDecoded.status_code());

  auto setpointResult = demo.try_setpoint_sync();
  ASSERT_TRUE(setpointResult.is_good()) << ua::to_string(setpointResult.status_code());
  auto setpointNodeResult = addressSpace.try_find_node_sync(setpointResult.value().node_id());
  ASSERT_TRUE(setpointNodeResult.is_good()) << ua::to_string(setpointNodeResult.status_code());
  EXPECT_FALSE(setpointNodeResult.value().get_role_permissions().has_value());
  const auto written = setpointResult.value().try_write_value_sync(ua::DataValue{ua::Variant{37.5}});
  ASSERT_TRUE(written.is_good()) << ua::to_string(written.status_code());
  auto setpointValueResult = setpointResult.value().try_read_value_sync();
  ASSERT_TRUE(setpointValueResult.is_good()) << ua::to_string(setpointValueResult.status_code());
  auto setpointDecoded = setpointValueResult.value().value().to<double>();
  ASSERT_TRUE(setpointDecoded.is_good()) << ua::to_string(setpointDecoded.status_code());
  EXPECT_EQ(setpointDecoded.value(), 37.5);

  auto methodResult = demo.try_divide_method_sync();
  ASSERT_TRUE(methodResult.is_good()) << ua::to_string(methodResult.status_code());
  auto method = std::move(methodResult).value();
  auto methodNodeResult = addressSpace.try_find_node_sync(method.get_node_id());
  ASSERT_TRUE(methodNodeResult.is_good()) << ua::to_string(methodNodeResult.status_code());
  EXPECT_FALSE(methodNodeResult.value().get_role_permissions().has_value());
  ua::CallMethodRequest request;
  request.object_id() = demo.node_id();
  request.method_id() = method.get_node_id();
  request.input_arguments().push_back(ua::Variant{std::int32_t{84}});
  request.input_arguments().push_back(ua::Variant{std::int32_t{2}});

  auto callResult = method.try_call_sync(request);
  ASSERT_TRUE(callResult.is_good()) << ua::to_string(callResult.status_code());
  ASSERT_TRUE(callResult.value().status_code().is_good()) << ua::to_string(callResult.value().status_code());
  ASSERT_EQ(callResult.value().output_arguments().size(), 1U);
  auto quotient = callResult.value().output_arguments()[0].to<std::int32_t>();
  ASSERT_TRUE(quotient.is_good()) << ua::to_string(quotient.status_code());
  EXPECT_EQ(quotient.value(), 42);

  request.input_arguments()[1] = ua::Variant{std::int32_t{0}};
  auto rejectedCall = method.try_call_sync(request);
  ASSERT_TRUE(rejectedCall.is_good()) << ua::to_string(rejectedCall.status_code());
  ASSERT_TRUE(rejectedCall.value().status_code().is_bad());
  expect_rich_failure(
    rejectedCall.value().status_code(), ua::Status::BadInvalidArgument, "ReferenceDivideByZero");

  for (const model::VariableId argumentId :
    {model::VariableId::Demo_Divide_InputArguments, model::VariableId::Demo_Divide_OutputArguments})
  {
    auto argumentResult = addressSpace.try_find_node_sync(model_id(namespaceIndex, argumentId));
    ASSERT_TRUE(argumentResult.is_good()) << ua::to_string(argumentResult.status_code());
    auto referencesResult = argumentResult.value().try_get_references_sync();
    ASSERT_TRUE(referencesResult.is_good()) << ua::to_string(referencesResult.status_code());
    EXPECT_TRUE(has_reference(referencesResult.value(),
      ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
      ua::NodeId{ua::VariableTypeId::PropertyType},
      true));
    EXPECT_TRUE(has_reference(
      referencesResult.value(), ua::NodeId{ua::ReferenceTypeId::HasProperty}, method.get_node_id(), false));
  }
}

// @relation(AC-COMP-REF-DEMO-MODEL-03-MISSING-FILE, scope=function)
TEST(ReferenceDemoModelBinding, RejectsMissingExternalModel)
{
  ua::test_helpers::TestServer testServer;
  testServer.create();
  const std::filesystem::path missingPath =
    std::filesystem::path{UA_REFERENCE_DEMO_MODEL_PATH}.concat(".missing");

  const auto configured = reference::try_configure_demo_model(testServer.server(), missingPath, ua::Logger{});

  EXPECT_FALSE(configured.is_good());
  EXPECT_NE(configured.status_code().shared_detail(), nullptr);
}

}  // namespace
