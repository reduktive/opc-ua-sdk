// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file read_service_requirement_tests.cpp
/// @brief Tests for Read service (section 5.10.2) mapped to ATTR-READ-xxx requirements.
///
/// Each test name includes the requirement ID for traceability.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <future>
#include <limits>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_attribute_write_mask.h"
#include "ua_continuation_points.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_event_notifier_type.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_event.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_permission_type.h"
#include "ua_range.h"
#include "ua_read_at_time_details.h"
#include "ua_read_event_details.h"
#include "ua_read_raw_modified_details.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_numeric_range_parser.h"
#include "ua_timestamps_to_return.h"
#include "ua_value_source.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include "stubs.h"
#include "access_control_test_support.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Test session stub - mirrors write_service_tests.cpp pattern
// ---------------------------------------------------------------------------

class TestReadSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  TestReadSessionInfo(boost::asio::any_io_executor ex, bool identityAvailable)
    : mExecutor(ex), mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->endpointPolicyId = "L/None";
    security->messageSecurityMode = MessageSecurityMode::None;
    security->securityPolicyId = SecurityPolicyId::None;
    mSecurity = std::move(security);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = UserTokenKind::Anonymous;
    mUser = std::move(user);

    if (identityAvailable)
      mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
  }

  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() const override
  {
    return serverCfg;
  }

  NodeId session_id() const override
  {
    return NodeId{1, Guid::create_and_generate()};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, serverCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  ServerConfig serverCfg;

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

auto make_allow_all()
{
  return true;
}

struct ReadResult
{
  ReadResponse response;
  bool isServiceFault{false};
  StatusCode serviceResult;
};

ReadResult do_read(std::shared_ptr<TestReadSessionInfo> si, boost::asio::any_io_executor ex, ReadRequest req)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(2s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Read service timed out";
    return {};
  }

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  if (rr)
  {
    return {*rr, false, rr->response_header().service_result()};
  }

  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  if (sf)
  {
    ReadResult result;
    result.isServiceFault = true;
    result.serviceResult = sf->response_header().service_result();
    return result;
  }

  ADD_FAILURE() << "Unexpected response type";
  return {};
}

// Write is the other half of the Attribute Service Set and shares this file's session fixture; it is
// unwrapped exactly as a Read is, because both refusals - the wholesale ServiceFault and the per-operation
// StatusCode - have to be distinguishable for a mutating Service.
struct WriteResult
{
  WriteResponse response;
  bool isServiceFault{false};
  StatusCode serviceResult;
};

WriteResult do_write(
  std::shared_ptr<TestReadSessionInfo> si, boost::asio::any_io_executor ex, WriteRequest req)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    AttributeServiceSet::create(si, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(2s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Write service timed out";
    return {};
  }

  auto resp = fut.get();
  auto* wr = dynamic_cast<WriteResponse*>(resp.second.get());
  if (wr)
  {
    return {*wr, false, wr->response_header().service_result()};
  }

  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  if (sf)
  {
    WriteResult result;
    result.isServiceFault = true;
    result.serviceResult = sf->response_header().service_result();
    return result;
  }

  ADD_FAILURE() << "Unexpected response type";
  return {};
}

}  // namespace

// ==========================================================================
// section 1.3 Service-Level Result Codes
// ==========================================================================

// SVR-ATTR-READ-012: BadNothingToDo - empty list
// @relation(SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-READ-012-BAD-NOTHINGTODO
TEST(ReadServiceRequirements, ATTR_READ_012_EmptyRequestReturnsBadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  ReadRequest req;
  req.request_header().request_handle() = 1;
  // No nodes_to_read - empty list

  auto result = do_read(si, ex, std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-012 positive: single node read succeeds
TEST(ReadServiceRequirements, ATTR_READ_012_NonEmptyRequestSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-013: BadTooManyOperations - exceeds limit
// @verifies AC-SVR-ATTR-READ-013-BAD-TOOMANYOPERATIONS
TEST(ReadServiceRequirements, ATTR_READ_013_TooManyOperationsReturnsBadTooManyOperations)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerRead = 1;

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  for (int i = 0; i < 2; ++i)
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadTooManyOperations);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-013 positive: within limit succeeds
TEST(ReadServiceRequirements, ATTR_READ_013_OperationsWithinLimitSucceed)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerRead = 2;

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  for (int i = 0; i < 2; ++i)
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  EXPECT_EQ(result.response.results().size(), 2u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-014: BadMaxAgeInvalid - negative maxAge
// @relation(SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-READ-014-BAD-MAXAGEINVALID
TEST(ReadServiceRequirements, ATTR_READ_014_NegativeMaxAgeReturnsBadMaxAgeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = -1.0;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadMaxAgeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-014 positive: zero maxAge succeeds (SVR-ATTR-READ-002 also)
TEST(ReadServiceRequirements, ATTR_READ_014_ZeroMaxAgeSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = 0.0;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-003 positive: large maxAge succeeds (cached read path)
TEST(ReadServiceRequirements, ATTR_READ_003_LargeMaxAgeSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = static_cast<double>(std::numeric_limits<int32_t>::max());
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.4 Operation-Level Result Codes
// ==========================================================================

// SVR-ATTR-READ-017: BadNodeIdUnknown - node does not exist
// @relation(SVR-ATTR-READ-029, scope=function)
// @relation(AC-SVR-AUTHZ-002-UNRESOLVED-NOT-DENIED, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_017_UnknownNodeReturnsBadNodeIdUnknown)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 9999u};  // Does not exist
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-017 positive: known node succeeds
TEST(ReadServiceRequirements, ATTR_READ_017_KnownNodeReadsSuccessfully)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  // Verify value is correct NodeClass
  EXPECT_TRUE(result.response.results()[0].value().is_int32());
  EXPECT_EQ(result.response.results()[0].value().as<int32_t>(), utils::to_underlying(NodeClass::Object));
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-017: Unknown namespace index also returns BadNodeIdUnknown
TEST(ReadServiceRequirements, ATTR_READ_017_UnknownNamespaceReturnsBadNodeIdUnknown)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{42, 1u};  // Namespace 42 does not exist
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-018: BadAttributeIdInvalid - attribute not valid for node
// @relation(SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-READ-018-BAD-ATTRIBUTEIDINVALID
TEST(ReadServiceRequirements, ATTR_READ_018_InvalidAttributeForNodeReturnsBadAttributeIdInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  // Value attribute is not valid for Object nodes (only Variables)
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadAttributeIdInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-005: Unrecognized attribute ID returns BadAttributeIdInvalid
TEST(ReadServiceRequirements, ATTR_READ_005_UnrecognizedAttributeIdReturnsBadAttributeIdInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = 999;  // Not a valid attribute id
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadAttributeIdInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-005 positive: valid attribute ID succeeds
TEST(ReadServiceRequirements, ATTR_READ_005_ValidAttributeIdSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-019: BadIndexRangeInvalid - malformed index range string
// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_019_InvalidIndexRangeReturnsBadIndexRangeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  DataValue dv;
  dv.value() = Variant{Array<int32_t>{1, 2, 3}};
  varResult.value().write_value_sync(std::move(dv));

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "abc";  // Malformed
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadIndexRangeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-019 positive + SVR-ATTR-READ-020 positive: valid index range slices array
// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_019_ValidIndexRangeSlicesArray)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "1:2";  // Elements at index 1 and 2
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  auto& dv = result.response.results()[0];
  EXPECT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  EXPECT_FALSE(dv.value().empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-020: BadIndexRangeNoData - range exceeds array bounds
// @verifies AC-SVR-ATTR-READ-020-BAD-INDEXRANGENODATA
TEST(ReadServiceRequirements, ATTR_READ_020_IndexRangeOutOfBoundsReturnsBadIndexRangeNoData)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{1, 2, 3}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "10:20";  // Way beyond bounds
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadIndexRangeNoData);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-024: BadUserAccessDenied-Namespace policy denies Read
TEST(ReadServiceRequirements, ATTR_READ_024_DeniedUserReturnsBadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto deniedNode = as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});
  ASSERT_TRUE(deniedNode.is_good());
  ua::test_helpers::set_test_node_permissions(deniedNode.value(), PermissionType{});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-024 positive: authorized user reads successfully
TEST(ReadServiceRequirements, ATTR_READ_024_AllowedUserReadsSuccessfully)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.2 ReadValueId - timestamps handling
// ==========================================================================

// Verify that server timestamps are applied when requested (TimestampsToReturn::Server)
TEST(ReadServiceRequirements, ATTR_READ_ServerTimestampsApplied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Server;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].server_timestamp().has_value());
  ::ua::test_utils::drain_with_timeout(tp);
}

// Verify that server timestamps are NOT applied when TimestampsToReturn::Neither
// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_NeitherTimestampsOmitsServerTimestamp)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_FALSE(result.response.results()[0].server_timestamp().has_value());
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.2.9 requires the raw RolePermissions Attribute to be an empty
// array when a standard Part-18 namespace permits per-Node overrides but the
// particular Node has no override. A configured Node in the same namespace is
// the control for the neighbouring state.
// @relation(AC-SVR-ADDRSP-059-UNCONFIGURED-OVERRIDE-IS-EMPTY, scope=function)
TEST(ReadServiceRequirements, UnconfiguredOverrideCapableRolePermissionsReadsAsEmptyArray)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  auto sessionInfo = std::make_shared<TestReadSessionInfo>(executor, make_allow_all());
  auto addressSpace = sessionInfo->address_space();

  const NodeId configuredNodeId{1, 7101u};
  const NodeId unconfiguredNodeId{1, 7102u};
  auto configuredNode = addressSpace.create_node_sync(configuredNodeId, NodeClass::Object);
  (void)addressSpace.create_node_sync(unconfiguredNodeId, NodeClass::Object);
  RolePermissionType configuredPermission;
  configuredPermission.role_id() = ua::test_helpers::test_access_role_id();
  configuredPermission.permissions() = ua::test_helpers::all_permissions();
  configuredNode.set_role_permissions(std::vector<RolePermissionType>{configuredPermission});

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : {configuredNodeId, unconfiguredNodeId})
  {
    ReadValueId nodeToRead;
    nodeToRead.node_id() = nodeId;
    nodeToRead.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
    request.nodes_to_read().payload().push_back(std::move(nodeToRead));
  }

  auto result = do_read(sessionInfo, executor, std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  const auto& configured = result.response.results()[0];
  EXPECT_TRUE(!configured.status().has_value() || configured.status()->is_good());
  ASSERT_TRUE(configured.value().is_array_of_structure());
  EXPECT_EQ(configured.value().as<Array<RefStructure<Structure>>>().size(), 1u);

  const auto& unconfigured = result.response.results()[1];
  EXPECT_TRUE(!unconfigured.status().has_value() || unconfigured.status()->is_good());
  ASSERT_TRUE(unconfigured.value().is_array_of_structure());
  EXPECT_TRUE(unconfigured.value().as<Array<RefStructure<Structure>>>().empty());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// ==========================================================================
// Mixed operations: some succeed, some fail
// ==========================================================================

// @relation(SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-READ-017-BAD-NODEIDUNKNOWN
TEST(ReadServiceRequirements, MixedResults_SomeSucceedSomeFail)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: valid read
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: unknown node
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 9999u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  // First should succeed
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());

  // Second should fail
  EXPECT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.3 SVR-ATTR-READ-015: BadTimestampsToReturnInvalid
// ==========================================================================

// SVR-ATTR-READ-015 negative: Invalid enum value
// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_015_InvalidTimestampsReturnsBadTimestampsToReturnInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Invalid;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadTimestampsToReturnInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-015 negative: out-of-range numeric value
// @verifies AC-SVR-ATTR-READ-015-BAD-TIMESTAMPSTORETURNINVALID
TEST(ReadServiceRequirements, ATTR_READ_015_OutOfRangeTimestampsReturnsBadTimestampsToReturnInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = static_cast<TimestampsToReturn>(99);
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadTimestampsToReturnInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-015 positive: Both is valid
TEST(ReadServiceRequirements, ATTR_READ_015_BothTimestampsSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].server_timestamp().has_value());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.4 SVR-ATTR-READ-023: BadNotReadable
// ==========================================================================

// SVR-ATTR-READ-023 negative: Variable without CurrentRead bit
// @relation(SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-READ-023-BAD-NOTREADABLE
TEST(ReadServiceRequirements, ATTR_READ_023_NoCurrentReadReturnsBadNotReadable)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  // Clear CurrentRead bit
  varResult.value().set_access_level(AccessLevelType{0});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNotReadable);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-023 positive: Variable with CurrentRead bit succeeds
TEST(ReadServiceRequirements, ATTR_READ_023_CurrentReadSetSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  // Default access level should have CurrentRead, but be explicit
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  {
    DataValue dv;
    dv.value() = Variant{int32_t{42}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-037 (UACTT): a DataEncoding on a non-Structure Value read is rejected with
// Bad_DataEncodingInvalid (Part 4 section 7.29: it is an error to specify a DataEncoding when the Value's
// DataType is not a subtype of Structure). But a Value read with Source/Both requested must still
// carry a SourceTimestamp even on that bad-status result - the UACTT ReadHelper checks SourceTimestamp
// on every Value read regardless of status.
TEST(ReadServiceRequirements, ATTR_READ_037_DataEncodingOnNonStructureValueStillSetsSourceTimestamp)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    DataValue dv;
    dv.value() = Variant{true};  // scalar Boolean - not a subtype of Structure
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.data_encoding() = QualifiedName{0, "Default Binary"};
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  const auto& resultValue = result.response.results()[0];
  ASSERT_TRUE(resultValue.status().has_value());
  EXPECT_EQ(*resultValue.status(), Status::BadDataEncodingInvalid);
  ASSERT_TRUE(resultValue.source_timestamp().has_value());
  EXPECT_FALSE(resultValue.source_timestamp()->is_null());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.4 SVR-ATTR-READ-021/022: Data Encoding Validation
// ==========================================================================

// SVR-ATTR-READ-021 negative: dataEncoding on non-Value attribute
TEST(ReadServiceRequirements, ATTR_READ_021_DataEncodingOnNonValueReturnsBadDataEncodingInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  rvid.data_encoding() = QualifiedName{0, "Default Binary"};
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadDataEncodingInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-022 negative: unsupported encoding name
// A Structure-typed Value with an unknown encoding name -> Bad_DataEncodingUnsupported (a dataEncoding
// CAN be applied, but this Server only provides Default Binary). Part 4 section 7.29 + Table 183.
// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_022_UnsupportedEncodingReturnsBadDataEncodingUnsupported)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    DataValue dv;
    dv.value() = Variant{range};  // Structure-typed Value
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.data_encoding() = QualifiedName{0, "SomeUnknownEncoding"};
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadDataEncodingUnsupported);
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-010 positive: empty dataEncoding uses session default (succeeds)
TEST(ReadServiceRequirements, ATTR_READ_010_EmptyDataEncodingSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    DataValue dv;
    dv.value() = Variant{int32_t{42}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  // data_encoding left empty - default
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-010 positive: a recognized dataEncoding ("Default Binary") on a Structure-typed Value
// succeeds (a dataEncoding is only applicable to Structure values - Part 4 section 7.29).
TEST(ReadServiceRequirements, ATTR_READ_010_RecognizedDataEncodingOnValueSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    DataValue dv;
    dv.value() = Variant{range};  // Structure-typed Value
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.data_encoding() = QualifiedName{0, "Default Binary"};
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// A dataEncoding on a non-Structure Value -> Bad_DataEncodingInvalid (no encoding can be applied -
// Part 4 section 7.29 + Table 183). The encoding name (even a valid one like "Default XML") is irrelevant.
TEST(ReadServiceRequirements, ATTR_READ_021_DataEncodingOnNonStructureValueReturnsBadDataEncodingInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  {
    DataValue dv;
    dv.value() = Variant{int32_t{42}};  // scalar (non-Structure)
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.data_encoding() = QualifiedName{0, "Default XML"};
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadDataEncodingInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.29, Table 171: a dataEncoding "only applies if the DataType of the Variable is a subtype
// of Structure"; the rule depends on the Variable's DataType, not on the status of the value read, so an
// Uncertain Int32 value with an encoding is Bad_DataEncodingInvalid and its Value is null (Table 135). The
// same value without an encoding is the control that the value is kept, and a Bad value keeps its own status
// (DL-4).
// @relation(AC-SVR-ATTR-READ-021-UNCERTAIN-NON-STRUCTURE-VALUE-ENCODING-INVALID, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_021_AnUncertainNonStructureValueWithAnEncodingIsInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto uncertain = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(uncertain.is_good());
  uncertain.value().set_data_type(NodeId{DataTypeId::Int32});
  {
    DataValue dv;
    dv.value() = Variant{int32_t{7}};
    dv.status() = StatusCode{Status::UncertainEngineeringUnitsExceeded};
    uncertain.value().write_value_sync(std::move(dv));
  }
  auto waiting = as.try_create_sync<VariableAccessor>(NodeId{1, 101u}, NodeClass::Variable);
  ASSERT_TRUE(waiting.is_good());
  waiting.value().set_data_type(NodeId{DataTypeId::Int32});
  {
    DataValue dv;
    dv.status() = StatusCode{Status::BadWaitingForInitialData};
    waiting.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  const std::pair<NodeId, bool> operations[] = {
    {NodeId{1, 100u}, true}, {NodeId{1, 100u}, false}, {NodeId{1, 101u}, true}};
  for (const auto& [nodeId, withEncoding] : operations)
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    if (withEncoding)
    {
      rvid.data_encoding() = QualifiedName{0, "Default Binary"};
    }
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);
  const auto& results = result.response.results();
  const auto statusOf = [&results](size_t op)
  {
    return results[op].status().value_or(StatusCode{Status::Good}).as_status();
  };

  EXPECT_EQ(statusOf(0), Status::BadDataEncodingInvalid) << "the Uncertain Int32 value read with an encoding";
  EXPECT_TRUE(results[0].value().empty()) << "the Uncertain Int32 value read with an encoding kept its Value";

  EXPECT_EQ(statusOf(1), Status::UncertainEngineeringUnitsExceeded) << "the control read with no encoding";
  const auto* kept = results[1].value().try_as<int32_t>();
  ASSERT_NE(kept, nullptr) << "the control read with no encoding lost its Value";
  EXPECT_EQ(*kept, 7);

  EXPECT_EQ(statusOf(2), Status::BadWaitingForInitialData) << "the Bad value read with an encoding";
  EXPECT_TRUE(results[2].value().empty()) << "the Bad value read with an encoding was given a Value";

  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.4 SVR-ATTR-READ-025: BadSecurityModeInsufficient
// ==========================================================================

// SVR-ATTR-READ-025: a node requiring encryption gates only its Value (and RolePermissions) Attribute over
// a None channel. Per Part 3 section 8.56 (Table 38) SigningRequired/EncryptionRequired do NOT apply to the
// Browse permission unless ApplyRestrictionsToBrowse is set, and per section 8.55 (Table 37) the Browse
// permission governs reading all Attributes except Value/RolePermissions. So a Value read is gated
// (BadSecurityModeInsufficient) while NodeClass remains readable.
TEST(ReadServiceRequirements, ATTR_READ_025_EncryptionRequiredGatesValueButNotNodeClassOverNone)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  // Session uses MessageSecurityMode::None (default in TestReadSessionInfo)
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Variable, {});

  // Set AccessRestrictions with EncryptionRequired on the node
  auto node = as.find_node_sync(NodeId{1, 100u});
  AccessRestrictionType restrictions;
  restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
  node.set_access_restrictions(restrictions);

  // Value read is gated by the channel security mode.
  {
    ReadRequest req;
    req.request_header().request_handle() = 1;
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));

    auto result = do_read(si, ex, std::move(req));
    EXPECT_FALSE(result.isServiceFault);
    ASSERT_EQ(result.response.results().size(), 1u);
    ASSERT_TRUE(result.response.results()[0].status().has_value());
    EXPECT_EQ(*result.response.results()[0].status(), Status::BadSecurityModeInsufficient);
  }

  // NodeClass (a Browse-permission Attribute) must still read Good over None.
  {
    ReadRequest req;
    req.request_header().request_handle() = 2;
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));

    auto result = do_read(si, ex, std::move(req));
    EXPECT_FALSE(result.isServiceFault);
    ASSERT_EQ(result.response.results().size(), 1u);
    const auto& st = result.response.results()[0].status();
    EXPECT_TRUE(!st.has_value() || st->is_good());
  }
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.1 SVR-ATTR-READ-001/002: maxAge as a freshness contract
// ==========================================================================

// Part 4 section 5.10.2.2: maxAge bounds how old a returned value may be - if the Server holds
// nothing that fresh it must go to the data source. A plausible implementation treats maxAge as a
// hint and always answers from the value it already has: the returned SourceTimestamp then still
// looks plausible (it is a real timestamp, just an old one) and nothing on the response marks the
// value as cached, so the client cannot tell. The observation is therefore twofold - the source is
// consulted again AND the SourceTimestamp advances.
// @verifies AC-SVR-ATTR-READ-001-MAXAGE-FRESH-READ
TEST(ReadServiceRequirements, ATTR_READ_001_ValueOlderThanMaxAgeIsReReadFromTheDataSource)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  // The device behind the Variable: each invocation is one data-source read and stamps the value
  // with the instant it was produced.
  auto deviceReads = std::make_shared<std::atomic<int>>(0);
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [deviceReads](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      const auto reads = deviceReads->fetch_add(1) + 1;
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(reads)};
      dv.source_timestamp() = DateTime::now();
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good());

  auto readValueWithMaxAge = [&si, &ex](double maxAge)
  {
    ReadRequest req;
    req.request_header().request_handle() = 1;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.max_age() = maxAge;
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
    return do_read(si, ex, std::move(req));
  };

  // Establish the value the Server holds, and its age.
  auto first = readValueWithMaxAge(0.0);
  ASSERT_FALSE(first.isServiceFault);
  ASSERT_EQ(first.response.results().size(), 1u);
  ASSERT_TRUE(
    !first.response.results()[0].status().has_value() || first.response.results()[0].status()->is_good());
  ASSERT_TRUE(first.response.results()[0].source_timestamp().has_value());
  const auto heldTimestamp = *first.response.results()[0].source_timestamp();
  const int readsAfterFirst = deviceReads->load();
  ASSERT_GE(readsAfterFirst, 1);

  // Let the held value age well past the maxAge the next Read will ask for.
  std::this_thread::sleep_for(30ms);

  auto second = readValueWithMaxAge(1.0);
  ASSERT_FALSE(second.isServiceFault);
  ASSERT_EQ(second.response.results().size(), 1u);
  EXPECT_TRUE(
    !second.response.results()[0].status().has_value() || second.response.results()[0].status()->is_good());

  // Conjunct 1: the data source was consulted again.
  EXPECT_GT(deviceReads->load(), readsAfterFirst);
  // Conjunct 2: the SourceTimestamp handed back is newer than the one already held.
  ASSERT_TRUE(second.response.results()[0].source_timestamp().has_value());
  EXPECT_GT(*second.response.results()[0].source_timestamp(), heldTimestamp);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.2.2: maxAge 0 is the strongest freshness request the parameter can make, not
// the absence of one. A plausible implementation compares the held value's age against maxAge with
// `age <= maxAge` and, for two Reads issued back to back, finds the age rounds to zero - so the
// second Read is answered from the value already held and never reaches the device.
// @verifies AC-SVR-ATTR-READ-002-MAXAGE-ZERO
TEST(ReadServiceRequirements, ATTR_READ_002_MaxAgeZeroReadsTheDataSourceOnEveryRead)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  // Each invocation is one data-source read; the value carries the read ordinal so the two Reads
  // are distinguishable from each other as well as countable.
  auto deviceReads = std::make_shared<std::atomic<int>>(0);
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [deviceReads](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      const auto reads = deviceReads->fetch_add(1) + 1;
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(reads)};
      dv.source_timestamp() = DateTime::now();
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good());

  auto readValueWithMaxAge = [&si, &ex](double maxAge)
  {
    ReadRequest req;
    req.request_header().request_handle() = 1;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.max_age() = maxAge;
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
    return do_read(si, ex, std::move(req));
  };

  auto first = readValueWithMaxAge(0.0);
  ASSERT_FALSE(first.isServiceFault);
  ASSERT_EQ(first.response.results().size(), 1u);
  ASSERT_TRUE(
    !first.response.results()[0].status().has_value() || first.response.results()[0].status()->is_good());
  const int readsAfterFirst = deviceReads->load();
  EXPECT_GE(readsAfterFirst, 1);

  auto second = readValueWithMaxAge(0.0);
  ASSERT_FALSE(second.isServiceFault);
  ASSERT_EQ(second.response.results().size(), 1u);
  EXPECT_TRUE(
    !second.response.results()[0].status().has_value() || second.response.results()[0].status()->is_good());

  // The data source was read on the second Read as well as the first.
  EXPECT_GT(deviceReads->load(), readsAfterFirst);

  // ...and the second Read returned what that second data-source read produced, not a replay of
  // the first - a Server that re-serves the held value would return the same ordinal.
  ASSERT_TRUE(first.response.results()[0].value().is_int32());
  ASSERT_TRUE(second.response.results()[0].value().is_int32());
  EXPECT_GT(
    second.response.results()[0].value().as<int32_t>(), first.response.results()[0].value().as<int32_t>());

  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// section 1.2 SVR-ATTR-READ-005: attributeId must name a defined Attribute
// ==========================================================================

// Part 4 section 7.29 (Table 171, attributeId): the attributeId shall be a valid Attribute id. This
// is the undefined-id case, distinct from SVR-ATTR-READ-018's defined-but-wrong-NodeClass one. A
// plausible implementation switches on the id and lets the default arm fall through to the Value
// read (Value is the id every Read path is built around), so an undefined id silently returns the
// Variable's Value with Good - the client believes it read the Attribute it asked for. The failure
// must therefore be observed together with the absence of a returned value, on a node whose Value
// is demonstrably readable at that moment.
// @verifies AC-SVR-ATTR-READ-005-ATTRIBUTEID-VALID
TEST(ReadServiceRequirements, ATTR_READ_005_UndefinedAttributeIdFailsInsteadOfReadingTheValue)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    DataValue dv;
    dv.value() = Variant{int32_t{4242}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: an attributeId that names no Attribute at all.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = 999;
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the same node's Value, as the control that makes the fall-through visible.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  // The undefined id fails...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadAttributeIdInvalid);
  // ...and no value came back with it.
  EXPECT_TRUE(result.response.results()[0].value().empty());

  // The control proves the Value was readable, so the empty result above is the rejection and not
  // an unreadable node.
  EXPECT_TRUE(
    !result.response.results()[1].status().has_value() || result.response.results()[1].status()->is_good());
  ASSERT_TRUE(result.response.results()[1].value().is_int32());
  EXPECT_EQ(result.response.results()[1].value().as<int32_t>(), 4242);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.11.5 requires a Server to return a null Value when the
// StatusCode severity is Bad.  The value-source interface deliberately supplies a
// stale payload beside Bad_DeviceFailure; the Uncertain arm proves the service
// normalizes by severity rather than erasing every non-Good value.
// @relation(AC-SVR-DA-032-BAD-IMPLIES-NULL-VALUE, scope=function)
TEST(ReadServiceRequirements, BadSeverityReadResultHasNullValueWhileUncertainKeepsItsValue)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  auto sessionInfo = std::make_shared<TestReadSessionInfo>(executor, make_allow_all());
  auto addressSpace = sessionInfo->address_space();

  const NodeId badNodeId{1, 7201u};
  const NodeId uncertainNodeId{1, 7202u};
  auto badVariable = addressSpace.create_sync<VariableAccessor>(badNodeId, NodeClass::Variable);
  auto uncertainVariable = addressSpace.create_sync<VariableAccessor>(uncertainNodeId, NodeClass::Variable);
  const AccessLevelType readable{AccessLevelType::Bit::CurrentRead};
  badVariable.set_access_level(readable);
  uncertainVariable.set_access_level(readable);

  ASSERT_TRUE(badVariable->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext& /*context*/,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         complete)
                  { complete(DataValue{Variant{int32_t{50}}, StatusCode{Status::BadDeviceFailure}}); }))
                .is_good());
  ASSERT_TRUE(uncertainVariable->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext& /*context*/,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         complete)
                  { complete(DataValue{Variant{int32_t{51}}, StatusCode{Status::Uncertain}}); }))
                .is_good());

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : {badNodeId, uncertainNodeId})
  {
    ReadValueId nodeToRead;
    nodeToRead.node_id() = nodeId;
    nodeToRead.attribute_id() = utils::to_underlying(AttributeId::Value);
    request.nodes_to_read().payload().push_back(std::move(nodeToRead));
  }

  auto result = do_read(sessionInfo, executor, std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  const auto& bad = result.response.results()[0];
  ASSERT_TRUE(bad.status().has_value());
  EXPECT_EQ(*bad.status(), Status::BadDeviceFailure);
  EXPECT_TRUE(bad.value().empty());

  const auto& uncertain = result.response.results()[1];
  ASSERT_TRUE(uncertain.status().has_value());
  EXPECT_EQ(*uncertain.status(), Status::Uncertain);
  ASSERT_TRUE(uncertain.value().is_int32());
  EXPECT_EQ(uncertain.value().as<int32_t>(), 51);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.10.2.2: maxAge at or above the maximum Int32 value is the sentinel by which a client
// says "whatever you have". The server does not answer it - it cannot, because it keeps no copy of a
// value a source produced - so its duty is to hand the parameter to the source unaltered and to return
// what the source decides. Two plausible implementations get this wrong in opposite directions, and the
// observation has to catch both: one discards maxAge before the source sees it, leaving a source that
// wants to honour the parameter unable to; the other keeps a copy per node and serves it, which cannot
// represent a Value that differs per caller and hands one Session another's answer. So the test asserts that
// the source SEES the value the client sent, that its answer stands, and that a source which does not honour
// maxAge is asked again every time rather than answered on its behalf. The endpoint and a value above it
// are both exercised, since the "or greater" clause is what stops a client's arithmetic overflowing into
// a device read on every poll.
// @verifies AC-SVR-ATTR-READ-003-MAXAGE-MAX-CACHED
TEST(ReadServiceRequirements, ATTR_READ_003_MaxAgeReachesTheValueSourceUnalteredAndItsAnswerStands)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  // A source that honours maxAge: it holds a value, records every maxAge it is handed, and only reaches
  // the device when the caller demands something fresher than what it holds. Each device read hands back
  // its ordinal, so a held answer and a fresh one differ by value as well as by count.
  auto deviceReads = std::make_shared<std::atomic<int>>(0);
  auto seenMaxAges = std::make_shared<std::vector<Duration>>();
  auto seenMutex = std::make_shared<std::mutex>();
  auto heldValue = std::make_shared<std::atomic<int32_t>>(0);
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [deviceReads, seenMaxAges, seenMutex, heldValue](const ValueSource::ReadContext& context,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      const Duration maxAge = context.maxAge;
      {
        const std::lock_guard<std::mutex> lock(*seenMutex);
        seenMaxAges->push_back(maxAge);
      }
      int32_t answer{};
      if (maxAge >= static_cast<Duration>(std::numeric_limits<int32_t>::max()) && heldValue->load() != 0)
      {
        answer = heldValue->load();
      }
      else
      {
        answer = static_cast<int32_t>(deviceReads->fetch_add(1) + 1);
        heldValue->store(answer);
      }
      DataValue dv;
      dv.value() = Variant{answer};
      dv.source_timestamp() = DateTime::now();
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good()) << installed.status_code().as_uint32();

  auto readValueWithMaxAge = [&si, &ex](const NodeId& nodeId, double maxAge)
  {
    ReadRequest req;
    req.request_header().request_handle() = 1;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.max_age() = maxAge;
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
    return do_read(si, ex, std::move(req));
  };
  const auto goodInt32 = [](const auto& read) -> std::optional<int32_t>
  {
    if (read.isServiceFault || read.response.results().size() != 1)
    {
      return std::nullopt;
    }
    const auto& result = read.response.results()[0];
    if (result.status().has_value() && result.status()->is_bad())
    {
      return std::nullopt;
    }
    if (!result.value().is_int32())
    {
      return std::nullopt;
    }
    // `read` is deduced, so `result` is a dependent type and `as` needs disambiguating.
    return result.value().template as<int32_t>();
  };

  // Establish what the source holds, and prove the device is reachable at all.
  const auto primed = goodInt32(readValueWithMaxAge(NodeId{1, 100u}, 0.0));
  ASSERT_TRUE(primed.has_value());
  const int readsAfterPriming = deviceReads->load();
  ASSERT_GE(readsAfterPriming, 1);

  const auto atMax = static_cast<double>(std::numeric_limits<int32_t>::max());
  for (const double requested : {atMax, 2.0 * atMax})
  {
    const auto answered = goodInt32(readValueWithMaxAge(NodeId{1, 100u}, requested));
    ASSERT_TRUE(answered.has_value()) << requested;
    // Conjunct 1: the source's decision stands - it answered from what it held, and the server did not
    // reach past it to the device.
    EXPECT_EQ(deviceReads->load(), readsAfterPriming) << requested;
    EXPECT_EQ(*answered, *primed) << requested;
  }

  // Conjunct 2: the source saw the maxAge the client sent, unaltered, every time.
  {
    const std::lock_guard<std::mutex> lock(*seenMutex);
    ASSERT_EQ(seenMaxAges->size(), 3u);
    EXPECT_DOUBLE_EQ((*seenMaxAges)[0], 0.0);
    EXPECT_DOUBLE_EQ((*seenMaxAges)[1], atMax);
    EXPECT_DOUBLE_EQ((*seenMaxAges)[2], 2.0 * atMax);
  }

  // Conjunct 3: a source that does NOT honour maxAge is asked again on every Read. Nothing answers a
  // cache-only Read on its behalf, which is what lets a per-caller Value be served safely at all.
  auto plainResult = as.try_create_sync<VariableAccessor>(NodeId{1, 101u}, NodeClass::Variable);
  ASSERT_TRUE(plainResult.is_good());
  auto& plainVariable = plainResult.value();
  plainVariable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  auto plainReads = std::make_shared<std::atomic<int>>(0);
  auto* plainSource = plainVariable->external_value_source();
  ASSERT_NE(plainSource, nullptr);
  ASSERT_TRUE(plainSource
                ->set_value_source(make_value_source(
                  [plainReads](const ValueSource::ReadContext& /*context*/,
                    const Node&,
                    const ReadValueId&,
                    std::function<void(DataValueResult)>
                      done)
                  {
                    DataValue dv;
                    dv.value() = Variant{static_cast<int32_t>(plainReads->fetch_add(1) + 1)};
                    dv.source_timestamp() = DateTime::now();
                    done(std::move(dv));
                  }))
                .is_good());

  const auto first = goodInt32(readValueWithMaxAge(NodeId{1, 101u}, atMax));
  const auto second = goodInt32(readValueWithMaxAge(NodeId{1, 101u}, atMax));
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(plainReads->load(), 2);
  EXPECT_NE(*first, *second);

  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// What a value handler was told about one call, copied out before the handler returned: the context is
/// valid only for the call, so the identity is kept as an address to compare against and never
/// dereferenced afterwards.
struct ValueContextRecord
{
  const AccessIdentity* identity{nullptr};
  Duration maxAge{-1.0};
  bool setSourceTimestamp{false};
  NodeId nodeId;
  uint32_t attributeId{0};
  String indexRange;
  DataValue writtenValue;
};

/// Thread-safe list of @ref ValueContextRecord, shared between a handler and the test body.
struct ValueContextRecorder
{
  std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
  std::shared_ptr<std::vector<ValueContextRecord>> seen = std::make_shared<std::vector<ValueContextRecord>>();

  std::vector<ValueContextRecord> snapshot() const
  {
    const std::lock_guard<std::mutex> lock(*mutex);
    return *seen;
  }
};

/// A Variable at @p nodeId the Session may read and write.
VariableAccessor make_readable_writable_variable(AddressSpace& as, const NodeId& nodeId)
{
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  EXPECT_TRUE(varResult.is_good());
  auto variable = varResult.value();
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  variable.set_access_level(al);
  return variable;
}

/// Installs the Variable's value source: its read records its context into @p reads (when given) and answers
/// @p answer narrowed to the Read's IndexRange; its write records its context and the value into @p writes
/// and accepts the write. A source with no @p writes is read-only.
VoidResult install_recording_value_source(VariableAccessor& variable,
  std::optional<ValueContextRecorder> reads, Variant answer, std::optional<ValueContextRecorder> writes)
{
  auto* source = variable->external_value_source();
  if (source == nullptr)
  {
    return VoidResult{StatusCode{Status::BadNotSupported}};
  }
  ValueSource::WriteValueHandler writeHandler;
  if (writes.has_value())
  {
    writeHandler = [recorder = *writes](const ValueSource::WriteContext& context,
                     const Node&,
                     const WriteValue& write,
                     std::function<void(ValueSource::WriteResult)>
                       done)
    {
      ValueContextRecord record;
      record.identity = context.caller != nullptr ? context.caller->identity.get() : nullptr;
      record.nodeId = write.node_id();
      record.attributeId = write.attribute_id();
      record.indexRange = write.index_range();
      record.writtenValue = write.value();
      {
        const std::lock_guard<std::mutex> lock(*recorder.mutex);
        recorder.seen->push_back(std::move(record));
      }
      done(ValueSource::Written{});
    };
  }
  return source->set_value_source(make_value_source(
    [reads = std::move(reads), answer = std::move(answer)](const ValueSource::ReadContext& context,
      const Node&,
      const ReadValueId& read,
      std::function<void(DataValueResult)>
        done)
    {
      if (reads.has_value())
      {
        ValueContextRecord record;
        record.identity = context.caller != nullptr ? context.caller->identity.get() : nullptr;
        record.maxAge = context.maxAge;
        record.setSourceTimestamp = context.setSourceTimestamp;
        record.nodeId = read.node_id();
        record.attributeId = read.attribute_id();
        record.indexRange = read.index_range();
        const std::lock_guard<std::mutex> lock(*reads->mutex);
        reads->seen->push_back(std::move(record));
      }
      DataValue dv;
      dv.value() = answer;
      ua::index_range_utils::apply_to_value(dv, read.index_range());
      done(std::move(dv));
    },
    std::move(writeHandler)));
}

ReadRequest make_value_read(const NodeId& nodeId, double maxAge)
{
  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.max_age() = maxAge;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));
  return req;
}

}  // namespace

// Part 4 section 5.10.2.2 defines maxAge as the caller's freshness request, and the SDK keeps no copy of a
// value a source produced, so the only thing able to honour it is the source. The server's whole duty is
// therefore to hand the Read's maxAge to the installed ReadValueHandler unchanged. Three values cover the
// parameter's shape: 0 (read the source), a value between the endpoints, and the Int32-maximum sentinel.
// A plausible bug - the node building the handler's ReadContext from a constant instead of the Read's
// maxAge - leaves the 0 case passing by accident, which is why the mid value and the
// sentinel are both asserted.
// @verifies AC-SVR-ATTR-READ-MAXAGE-REACHES-THE-VALUE-SOURCE
TEST(ReadServiceRequirements, MaxAgeReachesAnInstalledReadValueHandlerUnchanged)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  ValueContextRecorder recorder;
  auto installed = install_recording_value_source(variable, recorder, Variant{int32_t{7}}, std::nullopt);
  ASSERT_TRUE(installed.is_good()) << installed.status_code().as_uint32();

  const auto int32Max = static_cast<double>(std::numeric_limits<int32_t>::max());
  const std::array<double, 3> requested{0.0, 500.0, int32Max};
  for (const double maxAge : requested)
  {
    auto result = do_read(si, ex, make_value_read(NodeId{1, 100u}, maxAge));
    ASSERT_FALSE(result.isServiceFault) << maxAge;
    ASSERT_EQ(result.response.results().size(), 1u) << maxAge;
    const auto& value = result.response.results()[0];
    EXPECT_FALSE(value.status().has_value() && value.status()->is_bad()) << maxAge;
    ASSERT_TRUE(value.value().is_int32()) << maxAge;
    EXPECT_EQ(value.value().as<int32_t>(), 7) << maxAge;
  }

  const auto seen = recorder.snapshot();
  ASSERT_EQ(seen.size(), requested.size());
  EXPECT_DOUBLE_EQ(seen[0].maxAge, 0.0);
  EXPECT_DOUBLE_EQ(seen[1].maxAge, 500.0);
  EXPECT_DOUBLE_EQ(seen[2].maxAge, int32Max);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 asks the server only to *attempt* to serve a held value, so a source that ignores maxAge and
// always answers freshly is conformant. Receiving maxAge must not oblige a source to act on it: whatever
// maxAge the client sends, such a source's answer is returned Good and it is asked every time.
// @verifies AC-SVR-ATTR-READ-MAXAGE-REACHES-THE-VALUE-SOURCE
TEST(ReadServiceRequirements, AReadValueHandlerThatIgnoresMaxAgeStillAnswersGood)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  auto reads = std::make_shared<std::atomic<int>>(0);
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [reads](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(reads->fetch_add(1) + 1)};
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good()) << installed.status_code().as_uint32();

  const auto int32Max = static_cast<double>(std::numeric_limits<int32_t>::max());
  int expected = 0;
  for (const double maxAge : {0.0, 500.0, int32Max})
  {
    auto result = do_read(si, ex, make_value_read(NodeId{1, 100u}, maxAge));
    ASSERT_FALSE(result.isServiceFault) << maxAge;
    ASSERT_EQ(result.response.results().size(), 1u) << maxAge;
    const auto& value = result.response.results()[0];
    EXPECT_EQ(value.status().value_or(StatusCode{Status::Good}), Status::Good) << maxAge;
    ASSERT_TRUE(value.value().is_int32()) << maxAge;
    EXPECT_EQ(value.value().as<int32_t>(), ++expected) << maxAge;
  }
  EXPECT_EQ(reads->load(), 3);

  ::ua::test_utils::drain_with_timeout(tp);
}

// A negative maxAge is not a freshness request at all (Part 4 section 5.10.2.2, Table 51): the Read is
// refused with Bad_MaxAgeInvalid and the value source is never asked, so no source has to defend itself
// against a value outside the parameter's domain.
// @verifies AC-SVR-ATTR-READ-MAXAGE-REACHES-THE-VALUE-SOURCE
TEST(ReadServiceRequirements, ANegativeMaxAgeNeverReachesTheReadValueHandler)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  auto reads = std::make_shared<std::atomic<int>>(0);
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  ASSERT_TRUE(source
                ->set_value_source(make_value_source(
                  [reads](const ValueSource::ReadContext& /*context*/,
                    const Node&,
                    const ReadValueId&,
                    std::function<void(DataValueResult)>
                      done)
                  {
                    reads->fetch_add(1);
                    done(DataValue{Variant{int32_t{1}}});
                  }))
                .is_good());

  auto result = do_read(si, ex, make_value_read(NodeId{1, 100u}, -1.0));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadMaxAgeInvalid);
  EXPECT_EQ(reads->load(), 0);

  ::ua::test_utils::drain_with_timeout(tp);
}

// A value source whose answer differs per caller, or that audits who changed it, can only act on the
// caller it is told about: once the handler returns, the value has left the node and nothing downstream
// knows which Session asked. The Read service therefore hands the source the reading Session's own
// identity - the same AccessIdentity object the Session holds, not a copy or a stand-in - together with
// the Read's maxAge, the ReadValueId (node, attribute, IndexRange) and the timestamp request. A plausible
// bug passes nullptr (every source then sees "no Session") or forwards a default-constructed
// ReadValueId; the identity address, the mid-range maxAge and the IndexRange each catch one of those.
// @verifies AC-SVR-ATTR-VALUE-SOURCE-RECEIVES-THE-CALLER
TEST(ReadServiceRequirements, AReadValueHandlerReceivesTheReadingSessionIdentityAndTheReadValueId)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  const AccessIdentity* sessionIdentity = si->access_identity().get();
  ASSERT_NE(sessionIdentity, nullptr)
    << "the fixture Session must hold an identity for this test to mean anything";

  auto as = si->address_space();
  const NodeId nodeId{1, 100u};
  auto variable = make_readable_writable_variable(as, nodeId);
  ValueContextRecorder recorder;
  auto installed =
    install_recording_value_source(variable, recorder, Variant{Array<int32_t>{10, 20, 30, 40}}, std::nullopt);
  ASSERT_TRUE(installed.is_good()) << installed.status_code().as_uint32();

  ReadRequest req = make_value_read(nodeId, 500.0);
  req.nodes_to_read().payload()[0].index_range() = "1:2";
  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 1u);
  const auto& value = result.response.results()[0];
  EXPECT_FALSE(value.status().has_value() && value.status()->is_bad());
  ASSERT_TRUE(value.value().is_array());

  const auto seen = recorder.snapshot();
  ASSERT_EQ(seen.size(), 1u) << "the Read must reach the value source exactly once";
  EXPECT_EQ(seen[0].identity, sessionIdentity) << "the source was not handed the reading Session's identity";
  EXPECT_DOUBLE_EQ(seen[0].maxAge, 500.0);
  EXPECT_TRUE(seen[0].setSourceTimestamp) << "TimestampsToReturn::Both asks for the source timestamp";
  EXPECT_EQ(seen[0].nodeId, nodeId);
  EXPECT_EQ(seen[0].attributeId, utils::to_underlying(AttributeId::Value));
  EXPECT_EQ(seen[0].indexRange, String{"1:2"});

  ::ua::test_utils::drain_with_timeout(tp);
}

// The write half: a source that audits who wrote it needs the writing Session's identity, and needs it
// during the call. The Write service hands the source the same AccessIdentity object the Session holds,
// with the WriteValue being applied. Operation 1 is an IndexRange write: the source applies the range
// itself, so it is handed the partial value with its IndexRange - and still the writing Session's identity,
// which is the case a "pass the identity only on the simple path" bug would miss.
// @verifies AC-SVR-ATTR-VALUE-SOURCE-RECEIVES-THE-CALLER
TEST(ReadServiceRequirements, AWriteValueHandlerReceivesTheWritingSessionIdentityAndTheWriteValue)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  const AccessIdentity* sessionIdentity = si->access_identity().get();
  ASSERT_NE(sessionIdentity, nullptr)
    << "the fixture Session must hold an identity for this test to mean anything";

  auto as = si->address_space();
  const NodeId scalarId{1, 100u};
  const NodeId arrayId{1, 101u};
  auto scalar = make_readable_writable_variable(as, scalarId);
  auto array = make_readable_writable_variable(as, arrayId);
  array.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  ValueContextRecorder scalarWrites;
  ASSERT_TRUE(install_recording_value_source(scalar, std::nullopt, Variant{}, scalarWrites).is_good());
  ValueContextRecorder arrayReads;
  ValueContextRecorder arrayWrites;
  ASSERT_TRUE(
    install_recording_value_source(array, arrayReads, Variant{Array<int32_t>{1, 2, 3, 4}}, arrayWrites)
      .is_good());

  WriteRequest req;
  req.request_header().request_handle() = 1;
  {
    WriteValue wv;
    wv.node_id() = scalarId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{55}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  {
    WriteValue wv;
    wv.node_id() = arrayId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.index_range() = "1";
    wv.value().value() = Variant{Array<int32_t>{20}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 2u);
  EXPECT_TRUE(result.response.results()[0].is_good()) << result.response.results()[0].value();
  EXPECT_TRUE(result.response.results()[1].is_good()) << result.response.results()[1].value();

  const auto scalarSeen = scalarWrites.snapshot();
  ASSERT_EQ(scalarSeen.size(), 1u) << "the Write must reach the value source exactly once";
  EXPECT_EQ(scalarSeen[0].identity, sessionIdentity)
    << "the source was not handed the writing Session's identity";
  EXPECT_EQ(scalarSeen[0].nodeId, scalarId);
  EXPECT_EQ(scalarSeen[0].attributeId, utils::to_underlying(AttributeId::Value));
  EXPECT_TRUE(scalarSeen[0].indexRange.empty());
  ASSERT_TRUE(scalarSeen[0].writtenValue.value().is_int32());
  EXPECT_EQ(scalarSeen[0].writtenValue.value().as<int32_t>(), 55);

  const auto arraySeen = arrayWrites.snapshot();
  ASSERT_EQ(arraySeen.size(), 1u);
  EXPECT_EQ(arraySeen[0].identity, sessionIdentity)
    << "the IndexRange (read-modify-write) path did not hand the source the writing Session's identity";
  EXPECT_EQ(arraySeen[0].nodeId, arrayId);
  // Restated for NR-70 C3: the SDK no longer merges a ranged write, so the source receives the partial value
  // and its IndexRange.
  EXPECT_EQ(arraySeen[0].indexRange, String{"1"});
  ASSERT_TRUE(arraySeen[0].writtenValue.value().is_array_of_int32());
  EXPECT_EQ(arraySeen[0].writtenValue.value().as<Array<int32_t>>(), (Array<int32_t>{20}));

  // Restated for NR-70 C3: the SDK no longer reads the current value to merge into, so the source is not
  // read.
  EXPECT_TRUE(arrayReads.snapshot().empty()) << "the IndexRange write read the source to merge into";

  ::ua::test_utils::drain_with_timeout(tp);
}

// Control and negative arm: a read or write made with no Session in scope - the address-space
// conveniences a host or the server itself uses - reaches the same handlers with a null identity, so a
// source can tell "no Session" apart from any Session and never mistakes an internal access for a
// user's. The handlers are reached (the control), and the identity is exactly null (the assertion).
// @verifies AC-SVR-ATTR-VALUE-SOURCE-RECEIVES-THE-CALLER
TEST(ReadServiceRequirements, AValueHandlerReachedWithoutASessionReceivesANullIdentity)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId nodeId{1, 100u};
  auto variable = make_readable_writable_variable(as, nodeId);
  ValueContextRecorder reads;
  ValueContextRecorder writes;
  ASSERT_TRUE(install_recording_value_source(variable, reads, Variant{int32_t{3}}, writes).is_good());

  auto readResult = variable.try_read_value_sync();
  ASSERT_TRUE(readResult.is_good()) << readResult.status_code().as_uint32();
  DataValue written;
  written.value() = Variant{int32_t{4}};
  auto writeResult = variable.try_write_value_sync(std::move(written));
  ASSERT_TRUE(writeResult.is_good()) << writeResult.status_code().as_uint32();

  const auto readSeen = reads.snapshot();
  ASSERT_EQ(readSeen.size(), 1u);
  EXPECT_EQ(readSeen[0].identity, nullptr);
  EXPECT_EQ(readSeen[0].nodeId, nodeId);
  const auto writeSeen = writes.snapshot();
  ASSERT_EQ(writeSeen.size(), 1u);
  EXPECT_EQ(writeSeen[0].identity, nullptr);
  EXPECT_EQ(writeSeen[0].nodeId, nodeId);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.29 requires the three standard encoding BrowseNames to be recognised without visible
// DataTypeEncoding Nodes, but requires a DataType to support only at least one. Table 183 then requires
// Bad_DataEncodingUnsupported for a requested encoding this Server cannot produce. This server's
// Structure codec is UA Binary-only, so the same Structure Value must succeed for Default Binary and be
// refused without substitution for Default XML and Default JSON. A plausible bug equates recognition
// with support, accepts Default XML, and later serialises the untouched Value as UA Binary under Good.
// @verifies AC-SVR-ATTR-READ-006-DEFAULT-ENCODING-BROWSENAMES
// @verifies AC-SVR-ATTR-READ-022-BAD-DATAENCODINGUNSUPPORTED
TEST(ReadServiceRequirements, ATTR_READ_006_StandardNamesResolveWithoutEncodingNodesAndRespectCapabilities)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  // This address space holds only the node created below - no DataType or encoding Nodes are exposed.
  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    DataValue dv;
    dv.value() = Variant{range};  // Structure-typed Value - the only shape a dataEncoding applies to
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  const auto appendRead = [&](std::string_view encoding)
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.data_encoding() = QualifiedName{0, String{encoding}};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  };
  appendRead("Default Binary");
  appendRead("Default XML");
  appendRead("Default JSON");

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The supported standard encoding is resolved without consulting absent encoding Nodes.
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  EXPECT_TRUE(result.response.results()[0].value().is_structure());

  const std::array<std::string_view, 2> unsupported{"Default XML", "Default JSON"};
  for (size_t index = 0; index < unsupported.size(); ++index)
  {
    const auto operationIndex = index + 1;
    const auto& value = result.response.results()[operationIndex];
    EXPECT_TRUE(value.status().has_value()) << unsupported[index];
    if (!value.status().has_value())
      continue;
    EXPECT_EQ(*value.status(), Status::BadDataEncodingUnsupported) << unsupported[index];
    EXPECT_TRUE(value.value().empty()) << unsupported[index] << " was substituted with another encoding";
    const auto detail = value.status()->shared_detail();
    EXPECT_NE(detail, nullptr) << unsupported[index];
    if (!detail)
      continue;
    EXPECT_EQ(detail->code, "DataEncodingUnsupported") << unsupported[index];
    EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), "ns=1;i=100");
    EXPECT_EQ(
      ::ua::test_utils::error_context(detail.get(), ContextKeys::encoding.value()), unsupported[index]);
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.2.4: a ReadValueId whose nodeId is structurally invalid - the null NodeId, in any
// of its encodings (OPC 10000-6 section 5.2.2.9: numeric 0 or an empty String at NamespaceIndex 0) - is
// Bad_NodeIdInvalid, and that is a different recovery from Bad_NodeIdUnknown: invalid says the client
// built the id wrongly, unknown says the Node is gone and is worth re-resolving. A plausible
// implementation hands every id straight to the address-space lookup, which can only ever report "no such
// node", so the malformed id is reported as a missing one and the client re-resolves forever. Both null
// encodings are driven, with a control operation on a node that exists so the rejection is attributable to
// the id and not to a request the Server refused wholesale.
// @verifies AC-SVR-ATTR-READ-016-BAD-NODEIDINVALID
//
// DISABLED: the behaviour is unimplemented and this test is correct as written. The Read path applies no
// null-NodeId check anywhere: ua_attribute_service_set.cpp groups operations by NamespaceIndex (the null
// NodeId sits at NamespaceIndex 0, which exists, so it is not caught by the unknown-namespace branch), then
// on_read_node_resolved passes the address-space lookup's status through verbatim at
// ua_attribute_service_set.cpp:842 - so both null encodings are reported as Bad_NodeIdUnknown. The SDK
// already draws exactly this distinction on the sibling services, using NodeId::is_null() as the test for
// "structurally invalid": HistoryRead (ua_history_read_service.cpp:465) and DeleteNodes
// (ua_node_management_service.cpp:1301, whose comment reads "a null NodeId ... returns BadNodeIdInvalid
// (structurally invalid); a non-null NodeId that does not resolve keeps BadNodeIdUnknown"). Read is the
// outlier. Do not weaken these assertions to Bad_NodeIdUnknown - that is the exact confusion of recoveries
// SVR-ATTR-READ-016 and SVR-ATTR-READ-017 exist to keep apart. Re-enable once Read reclassifies a null
// nodeId ahead of, or in place of, the lookup status.
TEST(ReadServiceRequirements, ATTR_READ_016_StructurallyInvalidNodeIdIsRejectedAsInvalidNotUnknown)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: the canonical null NodeId - numeric identifier 0 at NamespaceIndex 0.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the same null NodeId in its String encoding - an empty String id at NamespaceIndex 0.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{0, ""};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - a Node that exists and reads Good in the same request.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The numeric null encoding is rejected as malformed...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNodeIdInvalid);
  // ...and so is the String null encoding, which denotes the very same null NodeId.
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadNodeIdInvalid);

  // The control proves the request was processed per operation rather than refused as a whole.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_int32());
  EXPECT_EQ(result.response.results()[2].value().as<int32_t>(), utils::to_underlying(NodeClass::Object));

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.27 with section 5.10.2.4: an IndexRange whose first index is not less than its second is
// invalid syntax, so the operation answers Bad_IndexRangeInvalid even though both bounds lie inside the
// array. A plausible implementation checks only that the characters parse and lets the slice attempt decide,
// which turns the syntax error into Bad_IndexRangeNoData: a semantic "nothing is there right now" in answer
// to an error the client must fix. The unranged read of the same Node is the control that the value is
// readable.
// @relation(AC-SVR-ATTR-READ-019-BAD-INDEXRANGEINVALID, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_019_ADescendingIndexRangeIsRejectedAsInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto arrayResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(arrayResult.is_good());
  arrayResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};
    arrayResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;
  // Operation 0: first index above second, inside the array's bounds, so only the syntax is wrong.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "7:5";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: control - the value read whole.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(result.response.results()[0].status()->as_status(), Status::BadIndexRangeInvalid);
  EXPECT_TRUE(
    !result.response.results()[1].status().has_value() || result.response.results()[1].status()->is_good());
  EXPECT_FALSE(result.response.results()[1].value().empty());

  ::ua::test_utils::drain_with_timeout(tp);
}

// A malformed-BrowseName arm was retired here on 2026-08-10. Part 4 Table 183 assigns
// Bad_DataEncodingInvalid to "no dataEncoding can be applied", which is what
// ATTR_READ_021_EncodingWhereNoEncodingCanBeAppliedIsInvalid drives and what the criterion's
// DISCHARGE names; the namespace-qualification axis it added is obliged by nothing in section 7.29.

// Part 4 section 5.10.2.4: a structurally invalid nodeId is Bad_NodeIdInvalid, which tells the client it
// built the id wrongly, while Bad_NodeIdUnknown tells it the Node is gone and is worth re-resolving.
// OPC 10000-6 section 5.2.2.9 defines the null NodeId in four identifier encodings, all denoting the same
// null id: numeric 0, an empty String, an all-zero Guid and an empty ByteString, each at NamespaceIndex 0.
// The Guid and opaque encodings are the ones a plausible implementation misses even once it special-cases
// the numeric and String forms, because an emptiness test is easy to write for the two textual shapes and
// the remaining two then fall through to the address-space lookup, which can only ever report "no such
// node". A control operation on a Node that exists is read in the same request, so the rejections are
// attributable to the ids and not to a request the Server refused as a whole.
// @verifies AC-SVR-ATTR-READ-016-BAD-NODEIDINVALID
TEST(ReadServiceRequirements, ATTR_READ_016_NullNodeIdInGuidAndOpaqueEncodingsIsRejectedAsInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: the null NodeId in its Guid encoding - the all-zero Guid at NamespaceIndex 0.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{0, Guid{}};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the null NodeId in its opaque encoding - an empty ByteString at NamespaceIndex 0.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{0, ByteString{}};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - a Node that exists and reads Good in the same request.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The Guid encoding of the null NodeId is rejected as malformed...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNodeIdInvalid);
  // ...and so is the opaque encoding, which denotes the very same null NodeId.
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadNodeIdInvalid);

  // The control proves the request was processed per operation rather than refused wholesale.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_int32());
  EXPECT_EQ(result.response.results()[2].value().as<int32_t>(), utils::to_underlying(NodeClass::Object));

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.2.4: Bad_NodeIdInvalid and Bad_NodeIdUnknown are two different answers to two
// different client mistakes, and the pair is the whole point of the obligation - invalid says the client
// built the id wrongly and must fix how it constructs ids, unknown says the Node is gone and the id is
// worth re-resolving against the Server. A plausible implementation has only one rejection to give,
// because every nodeId is handed straight to the address-space lookup and a lookup can only ever report
// "no such node": the malformed id is then answered with the same code as the merely absent one and the
// client re-resolves an id that can never resolve. Driving both shapes in a single request makes the
// distinction itself the observation rather than one code in isolation, with a Node that exists as the
// control that the request was processed per operation.
// @verifies AC-SVR-ATTR-READ-016-BAD-NODEIDINVALID
TEST(ReadServiceRequirements, ATTR_READ_016_MalformedNodeIdIsInvalidWhereAMerelyAbsentOneIsUnknown)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: structurally invalid - the null NodeId (OPC 10000-6 section 5.2.2.9), which denotes no
  // Node in any namespace and never will.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: well-formed but absent - a perfectly legal id in a namespace that exists, naming a Node
  // this Server does not hold.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 9999u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - a Node that exists and reads Good in the same request.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The control proves the request was processed per operation rather than refused wholesale, so each
  // rejection below is attributable to its own nodeId.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_int32());
  EXPECT_EQ(result.response.results()[2].value().as<int32_t>(), utils::to_underlying(NodeClass::Object));

  // The well-formed id that names nothing is the re-resolvable failure...
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadNodeIdUnknown);

  // ...and the malformed one is not: it is reported as the client's construction error...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadNodeIdInvalid);
  // ...and carries no value with the rejection.
  EXPECT_TRUE(result.response.results()[0].value().empty());

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 Table 55 defers Bad_DataEncodingInvalid to Table 183, which uses it in exactly one situation:
// no dataEncoding can be applied at all, because the request named an Attribute other than Value or
// because the Value Attribute's DataType is not a subtype of Structure. Both legs are driven against the
// same recognised encoding text ("Default Binary") that the control reads successfully, so a rejection
// cannot be attributed to the encoding name, to the session, or to the node being unreadable - only to
// the encoding being inapplicable to what was asked for.
// @verifies AC-SVR-ATTR-READ-021-BAD-DATAENCODINGINVALID
TEST(ReadServiceRequirements, ATTR_READ_021_EncodingWhereNoEncodingCanBeAppliedIsInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const auto readable =
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))};

  // Node 100 carries a Structure-typed Value, the one shape a dataEncoding does apply to.
  auto structVar = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(structVar.is_good());
  structVar.value().set_access_level(readable);
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    DataValue dv;
    dv.value() = Variant{range};
    structVar.value().write_value_sync(std::move(dv));
  }

  // Node 101 carries a scalar Value, whose DataType is not a subtype of Structure.
  auto scalarVar = as.try_create_sync<VariableAccessor>(NodeId{1, 101u}, NodeClass::Variable);
  ASSERT_TRUE(scalarVar.is_good());
  scalarVar.value().set_access_level(readable);
  {
    DataValue dv;
    dv.value() = Variant{int32_t{42}};
    scalarVar.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: an Attribute other than Value, so no dataEncoding can be applied.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
    rvid.data_encoding() = QualifiedName{0, "Default Binary"};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the Value Attribute of a Variable whose DataType is not a subtype of Structure.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 101u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.data_encoding() = QualifiedName{0, "Default Binary"};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - the same encoding on the Value it can be applied to.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.data_encoding() = QualifiedName{0, "Default Binary"};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The control proves the encoding text and the session are both fine at that same moment.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  EXPECT_TRUE(result.response.results()[2].value().is_structure());

  // Neither operation could have an encoding applied to it, so each is Bad_DataEncodingInvalid.
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadDataEncodingInvalid);
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadDataEncodingInvalid);

  ::ua::test_utils::drain_with_timeout(tp);
}

// SVR-ATTR-READ-025 positive: node without restrictions succeeds with None security
TEST(ReadServiceRequirements, ATTR_READ_025_NoRestrictionsWithNoneSucceeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  as.try_create_node_sync(NodeId{1, 100u}, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto result = do_read(si, ex, std::move(req));
  EXPECT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 1u);
  EXPECT_TRUE(
    !result.response.results()[0].status().has_value() || result.response.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// HistoryRead (Part 4 section 5.10.3): a different Service from Read, dispatched to the
// namespace's history delegate. The harness below stands one up so that the HistoryRead
// obligations can be driven end to end. The delegate supplies DATA only - never a verdict - so
// every status asserted below is one the Service itself decided.
// ==========================================================================

namespace
{

class HistoryFakeDelegate : public NamespaceHistoryDelegate
{
public:
  using ReadRawHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadRawItem>, ReadRawCallback)>;

  void set_on_read_raw(ReadRawHandler handler)
  {
    mOnReadRaw = std::move(handler);
  }

  void read_raw_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    if (mOnReadRaw)
    {
      mOnReadRaw(context, std::move(items), std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::read_raw_async(context, std::move(items), std::move(callback));
  }

  using ReadAtTimeHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>, ReadAtTimeCallback)>;

  void set_on_read_at_time(ReadAtTimeHandler handler)
  {
    mOnReadAtTime = std::move(handler);
  }

  void read_at_time_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadAtTimeItem> items,
    ReadAtTimeCallback callback) noexcept override
  {
    if (mOnReadAtTime)
    {
      mOnReadAtTime(context, std::move(items), std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::read_at_time_async(context, std::move(items), std::move(callback));
  }

  using ReadEventsHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadEventsItem>, ReadEventsCallback)>;

  void set_on_read_events(ReadEventsHandler handler)
  {
    mOnReadEvents = std::move(handler);
  }

  void read_events_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadEventsItem> items,
    ReadEventsCallback callback) noexcept override
  {
    if (mOnReadEvents)
    {
      mOnReadEvents(context, std::move(items), std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::read_events_async(context, std::move(items), std::move(callback));
  }

private:
  ReadRawHandler mOnReadRaw;
  ReadAtTimeHandler mOnReadAtTime;
  ReadEventsHandler mOnReadEvents;
};

class HistoryFixtureNamespace : public default_ns::Namespace,
                                public std::enable_shared_from_this<HistoryFixtureNamespace>
{
public:
  HistoryFixtureNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void set_delegate(shared_ptr<HistoryFakeDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<HistoryFakeDelegate> mDelegate;
};

struct HistoryFixture
{
  ~HistoryFixture()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  optional<Server> server;
  shared_ptr<HistoryFixtureNamespace> ns;
  shared_ptr<HistoryFakeDelegate> delegate;
  shared_ptr<SessionInfoStub> sessionInfo;
  uint16_t nsIndex{0};

  void setup()
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};

    server.emplace(Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

    ns = make_shared<HistoryFixtureNamespace>("uri://read-service-history-ns", threadPool.get_executor());
    delegate = make_shared<HistoryFakeDelegate>();
    ns->set_delegate(delegate);
    server->address_space().add_namespace_sync(ns);
    nsIndex = server->address_space().namespace_array().get_namespace_index("uri://read-service-history-ns");

    sessionInfo = make_shared<SessionInfoStub>(std::move(*server), threadPool.get_executor());
    server.reset();
  }

  // A Variable that advertises historical values: the HistoryRead AccessLevel bit is set.
  NodeId create_variable_with_history(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      al.set(AccessLevelType::Bit::HistoryRead);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  // A Variable with no historical values at all: the HistoryRead AccessLevel bit is clear.
  NodeId create_variable_without_history(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  // An Object that is an event notifier with historical Events.
  NodeId create_object_with_history_read(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(objResult.is_good()) << "Failed to create object node";
    if (objResult.is_good())
    {
      EventNotifierType en;
      en.set(EventNotifierType::Bit::HistoryRead);
      objResult.value().set_event_notifier(en);
    }
    return nodeId;
  }

  HistoryReadService::HistoryReadServiceResponse run_service(HistoryReadRequest request)
  {
    HistoryContinuationPoints sessionCPs;
    auto resultPromise = std::make_shared<std::promise<HistoryReadService::HistoryReadServiceResponse>>();
    auto resultFuture = resultPromise->get_future();

    auto service = HistoryReadService::create(sessionInfo,
      {},
      0,
      std::move(request),
      sessionCPs,
      threadPool.get_executor(),
      [resultPromise](HistoryReadService::HistoryReadServiceResponse response)
      { resultPromise->set_value(std::move(response)); });

    if (resultFuture.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "HistoryRead service did not complete within timeout";
      return {};
    }
    return resultFuture.get();
  }
};

HistoryReadRequest make_history_raw_request(std::initializer_list<NodeId> nodeIds)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto details = std::make_unique<ReadRawModifiedDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 100;
  details->return_bounds() = true;
  request.history_read_details() = std::move(details);

  request.nodes_to_read().resize(nodeIds.size());
  size_t i = 0;
  for (const auto& nid : nodeIds)
  {
    request.nodes_to_read()[i].node_id() = nid;
    ++i;
  }
  return request;
}

HistoryReadRequest make_history_events_request(std::initializer_list<NodeId> nodeIds)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand timeSelect;
  timeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  timeSelect.browse_path().push_back(QualifiedName{0, "Time"});
  timeSelect.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(timeSelect));
  request.history_read_details() = std::move(details);

  request.nodes_to_read().resize(nodeIds.size());
  size_t i = 0;
  for (const auto& nid : nodeIds)
  {
    request.nodes_to_read()[i].node_id() = nid;
    ++i;
  }
  return request;
}

// The Response is the same pair shape the Read tests unwrap: a typed response carries its verdict in
// the header, a wholesale refusal arrives as a ServiceFault. Both are checked, so a refusal cannot be
// missed just because it changed shape.
HistoryReadResponse* history_response_of(const Response& response)
{
  return dynamic_cast<HistoryReadResponse*>(response.second.get());
}

StatusCode history_service_result(const Response& response)
{
  if (auto* typed = dynamic_cast<HistoryReadResponse*>(response.second.get()))
    return typed->response_header().service_result();
  if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
    return fault->response_header().service_result();
  ADD_FAILURE() << "Unexpected HistoryRead response type";
  return StatusCode{Status::Good};
}

}  // namespace

// NEITHER is a well-formed value that a HistoryRead of historical values cannot honour: a value without a
// timestamp has no position in the history. OPC 10000-11 4.5: "A HistoryRead with invalid settings will be
// rejected with Bad_TimestampsToReturnInvalid", the Service-level code of Part 4 Table 57. Part 4 5.10.3.2
// names Bad_InvalidTimestampArgument instead, a code Part 4 tabulates only per operation (Table 58);
// SVR-ATTR-HREAD-004 follows the history-specific Part 11 text, which CTT Read Raw Err-002 enforces. The
// status alone cannot tell NEITHER from a malformed enumeration value, so the diagnostic must: the detail
// names NEITHER. The refusal is observed together with the delegate never being consulted, so it is a
// refusal and not a read whose result was relabelled.
// @verifies AC-SVR-ATTR-HREAD-004-NEITHER-INVALID
TEST(ReadServiceRequirements, ATTR_HREAD_004_NeitherTimestampsIsRefusedAsTimestampsToReturnInvalid)
{
  HistoryFixture h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(1)};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_history_raw_request({nodeId});
  request.timestamps_to_return() = TimestampsToReturn::Neither;

  auto result = h.run_service(std::move(request));

  // The value history read is refused at Service level, and the diagnostic names NEITHER.
  const StatusCode serviceStatus = history_service_result(result.response);
  EXPECT_EQ(serviceStatus, StatusCode{Status::BadTimestampsToReturnInvalid});
  ASSERT_NE(serviceStatus.shared_detail(), nullptr);
  EXPECT_EQ(serviceStatus.shared_detail()->code, "HistoryTimestampsToReturnNeither");

  // ...and it is a refusal: the history was never read.
  EXPECT_EQ(delegateCalls.load(), 0) << "a refused HistoryRead must not reach the history delegate";
  auto* response = history_response_of(result.response);
  if (response != nullptr)
  {
    for (const auto& operationResult : response->results())
      EXPECT_TRUE(operationResult.status_code().is_bad()) << "no operation may be served under a refusal";
  }
}

// Part 4 section 5.10.3.2 (Table 56) refuses a timestampsToReturn of NEITHER and then immediately defers:
// "OPC 10000-11 defines exceptions where this parameter shall be ignored". OPC 10000-11 4.5 excludes
// NEITHER only "for any HistoryRead accessing HistoricalDataNodes", and 6.5.5 gives ReadAtTime its own
// stamping - each returned value carries the timestamp that was requested for it, which is the key of the
// record rather than decoration on it. So both exceptions must survive a timestampsToReturn that would
// otherwise drop a timestamp: an Event read asked for NEITHER, and an at-time read asked for Server only.
// A plausible implementation applies one timestamp policy to everything it produces - validated up front
// before it knows which HistoryReadDetails it holds, and masked afterwards by the same generic helper the
// raw path needs - which refuses the Event read outright and silently deletes the SourceTimestamp that
// places every at-time row. Both exceptions are driven here because an implementation that special-cases
// only the one it met first passes half of the obligation.
// @verifies AC-SVR-ATTR-HREAD-005-PART11-TIMESTAMP-EXCEPTIONS
TEST(ReadServiceRequirements, ATTR_HREAD_005_Part11ExceptionsKeepTheirTimestampsWhateverIsAsked)
{
  HistoryFixture h;
  h.setup();

  auto eventNode = h.create_object_with_history_read(200);
  auto dataNode = h.create_variable_with_history(201);
  const DateTime eventTime = DateTime::now();
  const DateTime requestedTime = DateTime::now();

  std::atomic<int> eventCalls{0};
  h.delegate->set_on_read_events(
    [eventTime, &eventCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      eventCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        // Field 0 is the Event's Time - the Part 11 timestamp that places the record.
        fields.event_fields().push_back(Variant{eventTime});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  std::atomic<int> atTimeCalls{0};
  h.delegate->set_on_read_at_time(
    [&atTimeCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>
        items,
      NamespaceHistoryDelegate::ReadAtTimeCallback callback)
    {
      atTimeCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
        for (const auto& timestamp : item.timestamps)
        {
          DataValue dv;
          dv.value() = Variant{static_cast<int32_t>(11)};
          dv.source_timestamp() = timestamp;  // Part 11: the requested time keys the record
          dv.server_timestamp() = DateTime::now();
          success.values.push_back(std::move(dv));
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadAtTimeItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  // Exception 1: an Event history read asked for NEITHER - the parameter does not apply to it at all.
  {
    auto request = make_history_events_request({eventNode});
    request.timestamps_to_return() = TimestampsToReturn::Neither;

    auto result = h.run_service(std::move(request));

    EXPECT_EQ(history_service_result(result.response), StatusCode{Status::Good})
      << "an Event history read must not be refused for timestampsToReturn";
    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_TRUE(response->results()[0].status_code().is_good());
    EXPECT_EQ(eventCalls.load(), 1) << "the Event read must actually have been performed";

    auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(histEvent, nullptr) << "a successful Event history read carries HistoryEvent";
    ASSERT_EQ(histEvent->events().size(), 1u);
    auto& fields = histEvent->events()[0].event_fields();
    ASSERT_EQ(fields.size(), 1u);
    const DateTime* time = fields[0].try_as<DateTime>();
    ASSERT_NE(time, nullptr) << "the Event's Time field must survive: timestampsToReturn does not apply";
    EXPECT_EQ(*time, eventTime);
  }

  // An at-time block was retired here on 2026-08-10. Part 11 section 6.5.2.2 names only
  // HistoricalEventNodes as the TimestampsToReturn exception, and SPEC-SVR-ATTR-HREAD-031 obliges
  // the opposite for Raw, Modified and AtTime - so "ReadAtTime keeps its SourceTimestamp whatever
  // is asked" was this corpus contradicting itself, not a Part 11 exception.
}

// Part 4 section 5.10.3.2 (Table 56, nodeId): "If the Node does not support the requested access for
// historical values or historical Events the appropriate error response for the given Node shall be
// generated" - the access requested, not the Node alone. Historical values live on a Variable's
// AccessLevel.HistoryRead bit; historical Events live on an Object's EventNotifier.HistoryRead bit, and
// OPC 10000-11 6.5.2 says ReadEventDetails "is only valid for Objects that have the EventNotifier
// Attribute set to TRUE", so a Variable can never answer an Event history read however much value
// history it holds. A plausible implementation classifies the Node once, from its NodeClass and its own
// history bit, and reuses that one verdict for every HistoryReadDetails: a Variable that does hold value
// history then passes the gate for an Event read and is dispatched, and the Client is handed Events from
// a Node that has none instead of being told to stop asking. The refusal of the access the Node lacks is
// therefore asserted alongside the service of the access it has, on the very same Node.
// @verifies AC-SVR-ATTR-HREAD-011-NO-HISTORY-ACCESS
TEST(ReadServiceRequirements, ATTR_HREAD_011_HistoryAccessIsRefusedPerRequestedAccessNotPerNode)
{
  HistoryFixture h;
  h.setup();

  auto noValueHistory = h.create_variable_without_history(300);
  auto valueHistory = h.create_variable_with_history(301);

  // Neither delegate handler refuses anything: both serve whatever operation reaches them, so every
  // refusal below is the Service's own.
  std::vector<NodeId> rawDispatched;
  h.delegate->set_on_read_raw(
    [&rawDispatched](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        rawDispatched.push_back(item.nodeId);
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(5)};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  std::vector<NodeId> eventsDispatched;
  h.delegate->set_on_read_events(
    [&eventsDispatched](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        eventsDispatched.push_back(item.nodeId);
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        fields.event_fields().push_back(Variant{DateTime::now()});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  // A values history read: the Node with no historical values is refused, the Node that has them is
  // served - so the refusal is attributable to the missing values history and not to the request.
  {
    auto request = make_history_raw_request({noValueHistory, valueHistory});
    auto result = h.run_service(std::move(request));

    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr) << "a per-Node history capability must not fail the whole request";
    EXPECT_TRUE(response->response_header().service_result().is_good());
    ASSERT_EQ(response->results().size(), 2u);

    EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported})
      << "a values history read against a Node with no historical values must be refused";
    ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
    EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoricalValuesUnsupported");
    EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
      << "a refused operation must not hand back history as well";

    EXPECT_TRUE(response->results()[1].status_code().is_good())
      << "the Node that does hold value history is served";
    auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
    ASSERT_NE(histData, nullptr);
    EXPECT_EQ(histData->data_values().size(), 1u);

    ASSERT_FALSE(rawDispatched.empty()) << "the served operation must have reached the delegate";
    EXPECT_EQ(std::count(rawDispatched.begin(), rawDispatched.end(), noValueHistory), 0)
      << "the Node with no historical values must not be read for them";
    EXPECT_EQ(std::count(rawDispatched.begin(), rawDispatched.end(), valueHistory), 1);
  }

  // An Events history read against that same served Node: it is a Variable, so it is not an event
  // notifier and holds no historical Events, whatever its value history says.
  {
    auto request = make_history_events_request({valueHistory});
    auto result = h.run_service(std::move(request));

    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr);
    EXPECT_TRUE(response->response_header().service_result().is_good());
    ASSERT_EQ(response->results().size(), 1u);

    EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported})
      << "an Events history read against a Node that is not an event notifier must be refused";
    ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
    EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoricalEventsUnsupported");
    EXPECT_EQ(dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get()), nullptr)
      << "a Node with no historical Events must not hand any back";
    EXPECT_TRUE(eventsDispatched.empty())
      << "the Events read must not be dispatched for a Node that cannot answer it";
  }
}

// Part 4 section 5.10.3.4 (Table 58) lists Bad_DataEncodingUnsupported among the HistoryRead operation
// level result codes, and section 5.10.3.2 (Table 56) gives dataEncoding on HistoryReadValueId the same
// meaning it has on Read: it applies where the Variable's DataType is a subtype of Structure, and an
// encoding this Server does not provide for that DataType is an error rather than a preference. A
// plausible implementation carries dataEncoding only because the wire structure has the field, and hands
// back history in whichever encoding it happens to hold with a Good status - so a Client that asked for
// XML receives binary and has no way to tell. The refusal is observed together with the absence of any
// returned history, and alongside an operation in the same request that named no encoding and is served,
// so the refusal cannot be a wholesale failure of the read.
// @verifies AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED
TEST(ReadServiceRequirements, ATTR_HREAD_023_AnEncodingThisServerDoesNotProvideRefusesThatOperation)
{
  HistoryFixture h;
  h.setup();

  // A Variable whose DataType is Range (ns=0;i=884), a subtype of Structure, so a dataEncoding does
  // apply to it and the refusal can only ever be "unsupported", never "invalid".
  NodeId structuredNode{h.nsIndex, 400u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(structuredNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{884}});
  }
  auto plainNode = h.create_variable_with_history(401);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [structuredNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        if (item.nodeId == structuredNode)
        {
          Range range;
          range.low() = 0.0;
          range.high() = 100.0;
          dv.value() = Variant{range};  // Structure-typed history
        }
        else
        {
          dv.value() = Variant{static_cast<int32_t>(5)};
        }
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_history_raw_request({structuredNode, plainNode});
  // "Default XML" is a real OPC UA encoding BrowseName; this Server provides only Default Binary.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = history_response_of(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have run for the verdict to be about the encoding";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadDataEncodingUnsupported})
    << "an encoding this Server does not provide must be refused, not quietly substituted";
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "a refused operation must not also hand back the history it refused to encode";

  EXPECT_TRUE(response->results()[1].status_code().is_good())
    << "the operation that named no encoding is unaffected";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the unaffected operation must still return its history";
  EXPECT_EQ(histData->data_values().size(), 1u);
}

// Part 4 section 5.10.3.4 (Table 58) places Bad_UserAccessDenied at the OPERATION level of HistoryRead,
// and section 6.2.1 requires the check per Node for this user: history permission is its own permission,
// so a Node whose value a session may read is not necessarily one whose history it may read. A plausible
// implementation authorizes the request once - on the first Node, or on the session - and then dispatches
// the whole batch to the delegate, so one denied Node either sinks every other operation in the request
// or, worse, rides along and is read anyway. The denial is therefore observed together with the Node it
// does not concern being served in the same request, and with the denied Node never reaching the history
// delegate, which is what makes the denial a refusal rather than a relabelled result.
// @verifies AC-SVR-ATTR-HREAD-024-DENIED
TEST(ReadServiceRequirements, ATTR_HREAD_024_DeniedNodeIsRefusedWhileTheOtherNodeIsServed)
{
  HistoryFixture h;
  h.setup();

  auto deniedNode = h.create_variable_with_history(500);
  auto allowedNode = h.create_variable_with_history(501);

  // Deny HistoryRead on one Node only; every other operation stays allowed so that node resolution
  // and classification run normally and the refusal can only be the access-control gate.
  auto denied = h.sessionInfo->address_space().find_node_sync(deniedNode);
  ua::test_helpers::set_test_node_permissions(denied, PermissionType{});

  std::vector<NodeId> dispatched;
  h.delegate->set_on_read_raw(
    [&dispatched](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        dispatched.push_back(item.nodeId);
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(9)};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_history_raw_request({deniedNode, allowedNode});
  auto result = h.run_service(std::move(request));

  auto* response = history_response_of(result.response);
  ASSERT_NE(response, nullptr) << "a per-Node denial must not fail the whole request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);

  // The Node this session may not read the history of is refused...
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "a denied operation must not hand back the history it denied";

  // ...and the other Node in the same request is served.
  EXPECT_TRUE(response->results()[1].status_code().is_good());
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the permitted Node must still return its history";
  EXPECT_EQ(histData->data_values().size(), 1u);

  // The denial is enforced ahead of the read, not after it.
  ASSERT_FALSE(dispatched.empty()) << "the permitted operation must have reached the delegate";
  EXPECT_EQ(std::count(dispatched.begin(), dispatched.end(), deniedNode), 0)
    << "a denied HistoryRead must not reach the history delegate";
  EXPECT_EQ(std::count(dispatched.begin(), dispatched.end(), allowedNode), 1);
}

// The timestamps a Historian collects are a property of the individual HistoricalNode, so one Node of a
// request can be unable to answer a timestamp selection the rest of the request answers perfectly. Part 11
// section 4.5 makes the outcome mandatory for that Node - "the Server shall return
// Bad_TimestampNotSupported", and because a Historian aggregating other Historians may only discover the
// gap per Node, that code "can be returned on the service level or at the operation level" (Table 25:
// "The Client requested history using a TimestampsToReturn the Server does not support"). Part 4
// section 5.10.3.4's Bad_InvalidTimestampArgument is the neighbouring code for a selection that is itself
// invalid, not for a well formed one this Node cannot meet. A plausible implementation checks
// timestampsToReturn once, against the enumeration, finds it well formed, and then returns whatever rows
// the store held - handing back history with no timestamp at all under a Good status, which is history a
// Client cannot place in time and cannot detect. The Node whose history carries no timestamps is driven
// beside one whose history carries the requested one, so the refusal is attributable to the Node's
// timestamp capability and to nothing else.
// @verifies AC-SVR-ATTR-HREAD-026-INVALIDTIMESTAMPARGUMENT
TEST(ReadServiceRequirements, ATTR_HREAD_026_ANodeThatCannotHonourTheTimestampSelectionFailsItsOperation)
{
  HistoryFixture h;
  h.setup();

  auto untimestampedNode = h.create_variable_with_history(600);
  auto timestampedNode = h.create_variable_with_history(601);

  // The delegate supplies DATA, not verdicts: one Node's history simply carries no timestamp at all.
  // Deciding what that means for a request that asked for SourceTimestamps is the Service's job.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [untimestampedNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(3)};
        if (item.nodeId != untimestampedNode)
          dv.source_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_history_raw_request({untimestampedNode, timestampedNode});
  request.timestamps_to_return() = TimestampsToReturn::Source;

  auto result = h.run_service(std::move(request));

  auto* response = history_response_of(result.response);
  ASSERT_NE(response, nullptr) << "a per-Node timestamp refusal is per operation, not a service fault";
  EXPECT_TRUE(response->response_header().service_result().is_good())
    << "one Node's timestamp capability must not fail the service";
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  // The Node that cannot answer the timestamp selection says so...
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadTimestampNotSupported});
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "rows that cannot be placed in time must not be returned under the refusal";

  // ...while the Node that can is served, with the timestamp that was asked for.
  EXPECT_TRUE(response->results()[1].status_code().is_good()) << "the other operations still succeed";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the succeeding operation must still return its history";
  ASSERT_EQ(histData->data_values().size(), 1u);
  EXPECT_TRUE(histData->data_values()[0].source_timestamp().has_value());
}

// A timestampsToReturn of NEITHER is refused on a history read of values with Bad_TimestampsToReturnInvalid
// (OPC 10000-11 4.5; SVR-ATTR-HREAD-004). An at-time read is one instance of that Service-wide
// stimulus: OPC 10000-11 4.5 excludes NEITHER "for any HistoryRead accessing HistoricalDataNodes", and
// 6.5.5.2 keeps ReadAtTime sensitive to the parameter (a Node that cannot serve the requested timestamps
// answers Bad_TimestampNotSupported), so the at-time details is not one of the Part 11 exceptions where the
// parameter is ignored - that exception is HistoricalEventNodes.
//
// SVR-ATTR-HREAD-004 names the code and leaves its placement open, "at the service level (or per-op for
// some history operations)", so the code is accepted at either level. The delegate stub only keeps an
// unrefused read from stalling the fixture; nothing about the read it performs is asserted.
// @verifies AC-SVR-ATTR-HREAD-004-NEITHER-INVALID
TEST(ReadServiceRequirements, ATTR_HREAD_004_NeitherIsRefusedOnAnAtTimeHistoryRead)
{
  HistoryFixture h;
  h.setup();

  auto nodeId = h.create_variable_with_history(700);

  h.delegate->set_on_read_at_time(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>
        items,
      NamespaceHistoryDelegate::ReadAtTimeCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
        for (const auto& timestamp : item.timestamps)
        {
          DataValue dv;
          dv.value() = Variant{static_cast<int32_t>(7)};
          dv.source_timestamp() = timestamp;
          dv.server_timestamp() = DateTime::now();
          success.values.push_back(std::move(dv));
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadAtTimeItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  auto details = std::make_unique<ReadAtTimeDetails>();
  details->req_times().resize(1);
  details->req_times()[0] = DateTime::now();
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));

  const StatusCode required{Status::BadTimestampsToReturnInvalid};
  const StatusCode serviceResult = history_service_result(result.response);

  StatusCode operationResult{Status::Good};
  if (auto* response = history_response_of(result.response);
      response != nullptr && response->results().size() == 1u)
  {
    operationResult = response->results()[0].status_code();
  }

  if (serviceResult != required)
  {
    EXPECT_EQ(operationResult, required)
      << "NEITHER was answered with neither the Service-level nor the per-operation code the obligation "
         "names; the Service result was "
      << serviceResult.value();
  }

  const StatusCode refusal = serviceResult == required ? serviceResult : operationResult;
  ASSERT_NE(refusal.shared_detail(), nullptr);
  EXPECT_EQ(refusal.shared_detail()->code, "HistoryTimestampsToReturnNeither");
}

// Part 4 section 5.10.3 defers to OPC 10000-11 for the cases where timestampsToReturn does not apply, and
// 6.5.2 makes an Event history read one of them: an Event is placed in the history by its own Time field,
// which is an Event field and not a DataValue timestamp, so no timestamp selection can be honoured against
// it. That has to hold for the selections that DO drop a timestamp on a value read - Source drops the
// ServerTimestamp, Server drops the SourceTimestamp - and not merely for the NEITHER case a Server is most
// likely to have thought about. A plausible implementation applies one timestamp policy to everything it
// returns, through the same generic helper the raw path needs, and so blanks or rejects the Event field that
// carries the Event's Time. Both selections are driven against the same Node, and the Event's Time is
// asserted alongside the read having actually been performed, so a Server that quietly returned nothing
// cannot pass.
// @verifies AC-SVR-ATTR-HREAD-005-PART11-TIMESTAMP-EXCEPTIONS
TEST(ReadServiceRequirements, ATTR_HREAD_005_EventHistoryKeepsItsTimeUnderAnyTimestampSelection)
{
  HistoryFixture h;
  h.setup();

  auto eventNode = h.create_object_with_history_read(710);
  const DateTime eventTime = DateTime::now();

  std::atomic<int> eventCalls{0};
  h.delegate->set_on_read_events(
    [eventTime, &eventCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      eventCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        // Field 0 is the Event's Time - the Part 11 timestamp that places the record.
        fields.event_fields().push_back(Variant{eventTime});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  const TimestampsToReturn selections[] = {TimestampsToReturn::Source, TimestampsToReturn::Server};
  int expectedCalls = 0;
  for (const auto selection : selections)
  {
    auto request = make_history_events_request({eventNode});
    request.timestamps_to_return() = selection;

    auto result = h.run_service(std::move(request));

    EXPECT_EQ(history_service_result(result.response), StatusCode{Status::Good})
      << "an Event history read must not be refused for timestampsToReturn";
    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_TRUE(response->results()[0].status_code().is_good());

    ++expectedCalls;
    EXPECT_EQ(eventCalls.load(), expectedCalls) << "the Event read must actually have been performed";

    auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(histEvent, nullptr) << "a successful Event history read carries HistoryEvent";
    ASSERT_EQ(histEvent->events().size(), 1u);
    auto& fields = histEvent->events()[0].event_fields();
    ASSERT_EQ(fields.size(), 1u);
    const DateTime* time = fields[0].try_as<DateTime>();
    ASSERT_NE(time, nullptr) << "the Event's Time field must survive: timestampsToReturn does not apply";
    EXPECT_EQ(*time, eventTime);
  }
}

// Part 4 section 5.10.3.2 (Table 56, nodeId) requires "the appropriate error response for the given Node"
// when the Node does not support the requested access - the access requested, not the Node's history
// capability in the abstract. Historical Events live on an Object's EventNotifier.HistoryRead bit and
// historical values on a Variable's AccessLevel.HistoryRead bit, and OPC 10000-11 6.4 keeps them apart: an
// Object holds no Value Attribute, so a values history read against an event notifier asks for something
// that cannot exist however much Event history the Node holds. A plausible implementation classifies the
// Node once, from its NodeClass and its own history bit, and reuses that single verdict for every
// HistoryReadDetails - so an Object that does hold Event history passes the gate for a values read, is
// dispatched to the delegate, and the Client is handed values from a Node that has none. The refusal of the
// access the Node lacks is asserted alongside the service of the access it has, on the very same Node, with
// a Variable that does hold value history in the same request as the control.
// @verifies AC-SVR-ATTR-HREAD-011-NO-HISTORY-ACCESS
TEST(ReadServiceRequirements, ATTR_HREAD_011_AnEventNotifierIsRefusedTheValueHistoryItDoesNotHold)
{
  HistoryFixture h;
  h.setup();

  auto eventNotifier = h.create_object_with_history_read(720);
  auto valueHistory = h.create_variable_with_history(721);

  // Neither handler refuses anything: both serve whatever operation reaches them, so every refusal
  // below is the Service's own.
  std::vector<NodeId> rawDispatched;
  h.delegate->set_on_read_raw(
    [&rawDispatched](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        rawDispatched.push_back(item.nodeId);
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(8)};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  std::vector<NodeId> eventsDispatched;
  h.delegate->set_on_read_events(
    [&eventsDispatched](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        eventsDispatched.push_back(item.nodeId);
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        fields.event_fields().push_back(Variant{DateTime::now()});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  // The Events access this Object does advertise is served, so the Node is history-capable and the
  // refusal below cannot be put down to the Node being unknown or inert.
  {
    auto request = make_history_events_request({eventNotifier});
    auto result = h.run_service(std::move(request));

    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr);
    EXPECT_TRUE(response->response_header().service_result().is_good());
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_TRUE(response->results()[0].status_code().is_good())
      << "an event notifier with historical Events must be served an Events history read";
    auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(histEvent, nullptr);
    EXPECT_EQ(histEvent->events().size(), 1u);
    EXPECT_EQ(std::count(eventsDispatched.begin(), eventsDispatched.end(), eventNotifier), 1);
  }

  // A values history read against that same Object: it holds no Value Attribute, so it has no
  // historical values to give, whatever its Event history says.
  {
    auto request = make_history_raw_request({eventNotifier, valueHistory});
    auto result = h.run_service(std::move(request));

    auto* response = history_response_of(result.response);
    ASSERT_NE(response, nullptr) << "a per-Node history capability must not fail the whole request";
    EXPECT_TRUE(response->response_header().service_result().is_good());
    ASSERT_EQ(response->results().size(), 2u);

    EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported})
      << "a values history read against a Node with no historical values must be refused";
    ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
    EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoricalValuesUnsupported");
    EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
      << "a refused operation must not hand back values as well";

    EXPECT_TRUE(response->results()[1].status_code().is_good())
      << "the Variable that does hold value history is served in the same request";
    auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
    ASSERT_NE(histData, nullptr);
    EXPECT_EQ(histData->data_values().size(), 1u);

    ASSERT_FALSE(rawDispatched.empty()) << "the served operation must have reached the delegate";
    EXPECT_EQ(std::count(rawDispatched.begin(), rawDispatched.end(), eventNotifier), 0)
      << "a Node with no historical values must not be read for them";
    EXPECT_EQ(std::count(rawDispatched.begin(), rawDispatched.end(), valueHistory), 1);
  }
}

// ==========================================================================
// The DataTypeEncoding side of the Read contract (Part 4 section 7.29): the address-space invariants a
// Read depends on before any request is issued. The helpers below walk the DataType hierarchy the Server
// actually publishes, so the obligations are observed against the Server's own address space rather than
// against a fixture that was told the answer.
// ==========================================================================

namespace
{

// The DataTypes a Read can be asked to encode: the non-abstract DataTypes beneath Structure (ns=0;i=22),
// reached through HasSubtype (ns=0;i=45). Abstract DataTypes are excluded because no Value is ever of one,
// and DataTypes outside the Structure hierarchy are excluded because a DataTypeEncoding is defined only for
// structured DataTypes. A Node the Server does not publish is skipped: this collects what is exposed.
std::vector<NodeId> collect_exposed_structure_data_types(AddressSpace addressSpace)
{
  const NodeId hasSubtype{uint16_t{0}, uint32_t{45}};

  std::vector<NodeId> exposed;
  std::vector<NodeId> pending;
  pending.push_back(NodeId{uint16_t{0}, uint32_t{22}});

  size_t visited = 0;
  while (!pending.empty() && visited < 4096)
  {
    const NodeId current = pending.back();
    pending.pop_back();
    ++visited;

    auto dataType = addressSpace.try_find_sync<DataTypeAccessor>(current);
    if (dataType.is_bad())
      continue;

    bool isAbstract = false;
    try
    {
      isAbstract = dataType.value().get_is_abstract();
    }
    catch (...)
    {
      isAbstract = false;  // an unreadable IsAbstract is not a licence to skip the DataType
    }
    if (!isAbstract)
      exposed.push_back(current);

    auto references = dataType.value().try_get_references_sync();
    if (references.is_bad())
      continue;
    for (const auto& reference : references.value())
    {
      if (reference.is_forward() && !reference.is_remote() && (reference.type_id() == hasSubtype))
        pending.push_back(reference.target_id().node_id());
    }
  }
  return exposed;
}

// The DataTypeEncoding Objects a DataType points at through HasEncoding (ns=0;i=38), counted by
// BrowseName. This is the discovery path a Client has: the encodings a DataType offers are exactly the
// HasEncoding targets it publishes.
struct EncodingCensus
{
  size_t encodings{0};  ///< HasEncoding targets found on the DataType.
  size_t standardEncodings{0};  ///< ...whose BrowseName is one of the three standard encodings.
  size_t defaultXmlEncodings{0};  ///< ...whose BrowseName is exactly "Default XML".
};

EncodingCensus census_data_type_encodings(AddressSpace addressSpace, const NodeId& dataTypeId)
{
  const NodeId hasEncoding{uint16_t{0}, uint32_t{38}};

  EncodingCensus census;
  auto node = addressSpace.try_find_node_sync(dataTypeId);
  if (node.is_bad())
    return census;
  auto references = node.value().try_get_references_sync();
  if (references.is_bad())
    return census;

  for (const auto& reference : references.value())
  {
    if (!reference.is_forward() || reference.is_remote() || (reference.type_id() != hasEncoding))
      continue;
    auto encoding = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (encoding.is_bad())
      continue;

    const auto browseName = encoding.value().get_browse_name().name();
    ++census.encodings;
    if (browseName == "Default Binary" || browseName == "Default XML" || browseName == "Default JSON")
      ++census.standardEncodings;
    if (browseName == "Default XML")
      ++census.defaultXmlEncodings;
  }
  return census;
}

std::string data_type_name_for_message(AddressSpace addressSpace, const NodeId& dataTypeId)
{
  auto node = addressSpace.try_find_node_sync(dataTypeId);
  if (node.is_bad())
    return "<unresolvable DataType>";
  return std::string{static_cast<std::string_view>(node.value().get_browse_name().name())};
}

}  // namespace

// Part 4 section 7.29 (Table 171, dataEncoding): a Value is transferred in a DataTypeEncoding, and the
// encodings a DataType offers are the HasEncoding targets it publishes - so a structured DataType that
// publishes none cannot be read at all, while still browsing perfectly normally. A plausible implementation
// imports the DataType Nodes of the standard nodeset by walking the type hierarchy and never reaches the
// encoding Objects: they hang off no parent, only off the inverse HasEncoding of their DataType, so a
// hierarchy walk skips them and every structured DataType in the Server arrives with its encodings missing.
// Nothing about the address space looks wrong afterwards - the types browse, their subtype chains are
// intact - until a Client tries to decode a Value and has no encoding id to match. Every non-abstract
// DataType under Structure is checked, and the set is asserted non-empty first so an empty walk cannot pass
// for a clean one.
// @verifies AC-SVR-ATTR-READ-007-ONE-ENCODING
TEST(ReadServiceRequirements, ATTR_READ_007_EveryExposedStructureDataTypeOffersAStandardEncoding)
{
  HistoryFixture h;
  h.setup();

  auto addressSpace = h.sessionInfo->address_space();
  const auto dataTypes = collect_exposed_structure_data_types(addressSpace);
  ASSERT_FALSE(dataTypes.empty()) << "no structured DataType was found: the walk observed nothing";
  EXPECT_GT(dataTypes.size(), 50u) << "the standard nodeset publishes far more structured DataTypes";

  size_t offenders = 0;
  std::string offenderNames;
  for (const auto& dataTypeId : dataTypes)
  {
    const auto census = census_data_type_encodings(addressSpace, dataTypeId);
    if (census.standardEncodings != 0)
      continue;

    ++offenders;
    if (offenders <= 10)
    {
      if (!offenderNames.empty())
        offenderNames += ", ";
      offenderNames += data_type_name_for_message(addressSpace, dataTypeId);
    }
  }

  EXPECT_EQ(offenders, 0u) << offenders << " of " << dataTypes.size()
                           << " exposed structured DataTypes publish no Default Binary / Default XML / "
                              "Default JSON encoding, so their Values cannot be read: "
                           << offenderNames;
}

// Part 4 section 7.29 (Table 171, dataEncoding): a DataType that supports an XML-shaped encoding shall
// identify one of them as Default XML, and the standard nodeset gives every structured DataType an XML
// encoding - so for the DataTypes checked here the antecedent always holds. Exactly one is the observation
// because both failures are reachable and both are silent: none leaves an XML Client with no canonical
// encoding to name in a Read, and two make the choice ambiguous, with the Client's pick and the Server's
// disagreeing on the wire. A plausible implementation carries the encoding a Server's own transport uses
// and imports the rest as an afterthought, so the XML encoding Object is dropped while Default Binary
// survives - which reads as a working address space right up to the first XML Client. Every non-abstract
// DataType under Structure is checked, and the set is asserted non-empty first so an empty walk cannot pass
// for a clean one.
// @verifies AC-SVR-ATTR-READ-009-DEFAULT-XML
TEST(ReadServiceRequirements, ATTR_READ_009_EveryExposedStructureDataTypeNamesOneDefaultXmlEncoding)
{
  HistoryFixture h;
  h.setup();

  auto addressSpace = h.sessionInfo->address_space();
  const auto dataTypes = collect_exposed_structure_data_types(addressSpace);
  ASSERT_FALSE(dataTypes.empty()) << "no structured DataType was found: the walk observed nothing";
  EXPECT_GT(dataTypes.size(), 50u) << "the standard nodeset publishes far more structured DataTypes";

  size_t missing = 0;
  size_t duplicated = 0;
  std::string missingNames;
  std::string duplicatedNames;
  for (const auto& dataTypeId : dataTypes)
  {
    const auto census = census_data_type_encodings(addressSpace, dataTypeId);
    if (census.defaultXmlEncodings == 1)
      continue;

    if (census.defaultXmlEncodings == 0)
    {
      ++missing;
      if (missing <= 10)
      {
        if (!missingNames.empty())
          missingNames += ", ";
        missingNames += data_type_name_for_message(addressSpace, dataTypeId);
      }
    }
    else
    {
      ++duplicated;
      if (duplicated <= 10)
      {
        if (!duplicatedNames.empty())
          duplicatedNames += ", ";
        duplicatedNames += data_type_name_for_message(addressSpace, dataTypeId);
      }
    }
  }

  // Not zero: an XML Client must have a canonical encoding to name.
  EXPECT_EQ(missing, 0u) << missing << " of " << dataTypes.size()
                         << " exposed structured DataTypes publish no Default XML encoding: " << missingNames;
  // ...and not two: the canonical choice must be unambiguous.
  EXPECT_EQ(duplicated, 0u) << duplicated << " of " << dataTypes.size()
                            << " exposed structured DataTypes publish more than one Default XML encoding: "
                            << duplicatedNames;
}

// Part 4 section 5.10.2.4 with Table 183: a dataEncoding that names a real encoding the Server does not
// provide for that DataType is Bad_DataEncodingUnsupported, and the refusal must be total - nothing is
// handed back in a different encoding. The pairing with the null-dataEncoding fallback is what makes the
// no-substitution half required: the Server substitutes when it chose the default and refuses when the
// Client chose, because a Client that named an encoding has a decoder for that one and no other. A
// plausible implementation treats dataEncoding as a preference - it looks the name up, finds nothing it can
// honour, and serves the Value in the encoding it does hold under a Good status, or attaches the bad status
// but leaves the Value it had already produced in the result. Either way the Client is handed bytes it
// cannot decode while believing the request was answered. "Default JSON" is a real OPC UA encoding
// BrowseName, driven against a Structure-typed Value so that no encoding can be called inapplicable, with
// "Default Binary" on the same Value in the same request as the control that proves the Value is readable
// through an encoding at that moment.
// @verifies AC-SVR-ATTR-READ-022-BAD-DATAENCODINGUNSUPPORTED
TEST(ReadServiceRequirements, ATTR_READ_022_AnUnsupportedEncodingIsRefusedWithoutSubstitution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    DataValue dv;
    dv.value() = Variant{range};  // Structure-typed Value - a dataEncoding does apply to it
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: a well-formed encoding BrowseName this Server does not provide.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.data_encoding() = QualifiedName{0, "Default JSON"};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: control - the same Value through an encoding this Server does provide.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.data_encoding() = QualifiedName{0, "Default Binary"};
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  // The encoding the Server does not provide is refused...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadDataEncodingUnsupported);
  // ...and nothing was substituted for it: no Value came back in some other encoding.
  EXPECT_TRUE(result.response.results()[0].value().empty());

  // The control proves the Value, the node and the session are all fine at that same moment, so the
  // refusal above is attributable to the requested encoding alone.
  EXPECT_TRUE(
    !result.response.results()[1].status().has_value() || result.response.results()[1].status()->is_good());
  EXPECT_TRUE(result.response.results()[1].value().is_structure());

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.22: within one dimension of a NumericRange "the first integer shall always have a lower
// value than the second" - strictly lower, so the degenerate `5:5` is malformed as surely as the backwards
// `7:5`, a single element being written `5`. Both are Bad_IndexRangeInvalid: the fault is in the range the
// Client wrote, not in the data behind it. A plausible implementation parses the two integers, hands them
// to the slice loop and lets the data decide - `for (i = low; i <= high; ++i)` simply runs zero times for
// `7:5` and once for `5:5`, so the Server answers Good with an empty array for the backwards range and Good
// with one element for the equal-bounds one, and a Client whose range arithmetic is broken is told its
// request was fine. Both ranges are driven well inside the array's bounds so the only thing wrong with
// either is its syntax, alongside an unranged read of the same Node proving the value is readable in full.
// @verifies AC-SVR-ATTR-READ-026-RANGE-ASCENDING
TEST(ReadServiceRequirements, ATTR_READ_026_ARangeWhoseFirstIndexIsNotLowerThanTheSecondIsInvalidSyntax)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    // Ten elements, so indices 5 and 7 are both well inside the array: neither range below can be
    // refused for being out of range, only for being written the wrong way round.
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{0, 10, 20, 30, 40, 50, 60, 70, 80, 90}};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: the backwards range - first index above the second.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "7:5";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the degenerate range - first index equal to the second, which "5" already spells.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "5:5";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - the same Value read whole, with no range at all.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The backwards range is malformed...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadIndexRangeInvalid);
  // ...and so is the equal-bounds range, which the spec's "lower value than" excludes just as firmly.
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadIndexRangeInvalid);

  // The control proves the Value was readable at that moment, so neither refusal above is a missing or
  // unreadable value being reported through the range.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_array_of_int32());
  EXPECT_EQ(result.response.results()[2].value().as<Array<int32_t>>().size(), 10u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.27: "All dimensions shall be specified for a NumericRange to be valid", and
// "Bad_IndexRangeInvalid is only used for invalid syntax of the NumericRange. All other invalid requests with
// a valid syntax shall result in Bad_IndexRangeNoData." A range naming one or three dimensions of a
// two-dimensional array is valid syntax that is not valid for this Value, so it is refused with
// Bad_IndexRangeNoData and no value (NR-10 rule 9), not completed with the unnamed dimension selected whole.
// The range naming both dimensions over the same Node in the same request is the control.
// @relation(AC-SVR-ATTR-READ-027-ALL-DIMENSIONS-SPECIFIED, scope=function)
TEST(ReadServiceRequirements, ATTR_READ_027_ARangeNamingFewerDimensionsThanTheArrayHasIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    Array<int32_t> matrix;
    matrix.payload() = {1, 2, 3, 4, 5, 6};
    matrix.add_and_validate_dimensions({2, 3});
    DataValue dv;
    dv.value() = Variant{matrix};
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operations 0 and 1: one and three dimensions named against a two-dimensional array; operation 2: the
  // control, both dimensions named.
  for (const char* range : {"0:1", "0:1,0:1,0:1", "0:1,1:2"})
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = range;
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // A range with the wrong number of dimensions selects no data, and the result carries no value.
  for (size_t op : {size_t{0}, size_t{1}})
  {
    ASSERT_TRUE(result.response.results()[op].status().has_value()) << "operation " << op;
    EXPECT_EQ(result.response.results()[op].status()->as_status(), Status::BadIndexRangeNoData)
      << "operation " << op;
    EXPECT_TRUE(result.response.results()[op].value().empty()) << "operation " << op;
  }

  // The control proves a NumericRange does work on this Node when it names every dimension, so the
  // refusals above are attributable to the dimension count and to nothing else.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_array_of_int32());
  const auto& block = result.response.results()[2].value().as<Array<int32_t>>();
  EXPECT_EQ(std::vector<int32_t>(block.begin(), block.end()), (std::vector<int32_t>{2, 3, 5, 6}));
  ASSERT_TRUE(block.dimensions().has_value()) << "the narrowed matrix carries no dimensions";
  EXPECT_EQ(*block.dimensions(), (Dimensions{2, 2}));

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.22: "When reading a value and any of the lower bounds of the indexes is out of range the
// Server shall return a Bad_IndexRangeNoData. If any of the upper bounds of the indexes is out of range,
// the Server shall return partial results." The asymmetry is the obligation: a lower bound past the end
// selects nothing, so there is nothing to return, while a high upper bound still selects real elements and
// must be clamped to them. A plausible implementation validates both bounds against the array length in one
// loop and refuses anything that does not fit, which breaks every Client polling a growing array with a
// fixed range; the mirror-image implementation clamps both ends and hands back the last element of the
// array for a range that starts past it, which is silently wrong data. Both halves are driven against the
// same five-element array, and the clamped read is asserted on its contents and not merely on its status,
// because the elements returned are what "partial results" means.
// @verifies AC-SVR-ATTR-READ-028-LOWER-BOUND-OOB
TEST(ReadServiceRequirements, ATTR_READ_028_ALowerBoundPastTheArrayYieldsNoDataWhileAHighUpperBoundClamps)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};  // indices 0..4
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: the lower bound is past the end, so the range selects nothing at all.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "10:12";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: the lower bound is inside the array and only the upper bound is past the end.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "3:99";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 2u);

  // Nothing is selected, so the operation fails with the code that says exactly that - and it is a
  // semantic failure, not a malformed range.
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadIndexRangeNoData);

  // The high upper bound is clamped instead: the operation succeeds...
  EXPECT_TRUE(
    !result.response.results()[1].status().has_value() || result.response.results()[1].status()->is_good());
  // ...and the elements the range really does select, elements 3 and 4, are the ones returned.
  ASSERT_TRUE(result.response.results()[1].value().is_array_of_int32());
  const auto& clamped = result.response.results()[1].value().as<Array<int32_t>>();
  ASSERT_EQ(clamped.size(), 2u);
  EXPECT_EQ(clamped[0], 40);
  EXPECT_EQ(clamped[1], 50);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.22: "Bad_IndexRangeInvalid is only used for invalid syntax of the NumericRange. All
// other invalid requests with a valid syntax shall result in Bad_IndexRangeNoData." The partition is the
// obligation, not either code on its own: invalid tells the Client its range arithmetic is broken and must
// be fixed, no-data tells it the range was well formed and the data simply is not there right now, which
// for a shrinking array is a condition to retry rather than a bug to repair. A plausible implementation has
// one range failure to report, because parsing and slicing share a single error path, and answers a
// perfectly well-formed range over an array that has shrunk with the malformed-range code - sending the
// Client away to debug arithmetic that was never wrong. Both stimuli are driven in one request so the
// distinction itself is the observation, with an unranged read of the same Node as the control that the
// value is readable in full at that moment.
// @verifies AC-SVR-ATTR-READ-029-SYNTAX-ONLY
TEST(ReadServiceRequirements, ATTR_READ_029_IndexRangeInvalidIsForSyntaxWhileSemanticFailuresGetTheirOwnCode)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  varResult.value().set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});
  {
    DataValue dv;
    dv.value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};  // indices 0..4
    varResult.value().write_value_sync(std::move(dv));
  }

  ReadRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: syntactically bad - a dash where the NumericRange grammar requires a colon, so the
  // string is not a range at all and no array could ever satisfy it.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "2-4";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 1: syntactically perfect and semantically unsatisfiable - a well-formed ascending range
  // that selects nothing, because it starts past the end of this five-element array.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    rvid.index_range() = "10:20";
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }
  // Operation 2: control - the same Value read whole, with no range at all.
  {
    ReadValueId rvid;
    rvid.node_id() = NodeId{1, 100u};
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    req.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_EQ(result.response.results().size(), 3u);

  // The malformed range is the only one that gets the syntax code...
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadIndexRangeInvalid);

  // ...and the well-formed one that selects nothing carries its own semantic code instead.
  ASSERT_TRUE(result.response.results()[1].status().has_value());
  EXPECT_NE(*result.response.results()[1].status(), StatusCode{Status::BadIndexRangeInvalid});
  EXPECT_EQ(*result.response.results()[1].status(), Status::BadIndexRangeNoData);

  // The control proves the Value was readable in full at that moment, so neither code above is standing
  // in for an unreadable or absent value.
  EXPECT_TRUE(
    !result.response.results()[2].status().has_value() || result.response.results()[2].status()->is_good());
  ASSERT_TRUE(result.response.results()[2].value().is_array_of_int32());
  EXPECT_EQ(result.response.results()[2].value().as<Array<int32_t>>().size(), 5u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// ==========================================================================
// Write (Part 4 section 5.10.4): the mutating half of the Attribute Service Set, driven through the same
// session fixture the Read obligations above use. Because a Write changes state, every refusal below is
// observed together with what the Server was left holding - a status code on its own cannot tell a refusal
// apart from a change that was applied and then reported as having failed.
// ==========================================================================

// Part 4 section 5.10.4.3 - Bad_TooManyOperations: the request exceeds the Server's operation limit.
//
// The no-prefix half is what makes the code safe to act on. A Write mutates, so a Client that receives a
// service-level failure resends the batch; if the Server had already applied the operations it managed to
// process before it noticed the limit, the resend applies them twice. A plausible implementation checks the
// limit inside the per-operation loop, or checks it after dispatching, and produces exactly that: the first
// operation lands, the request is reported as refused, and nothing on the response says which prefix
// survived. The two Variables are primed with values a Client can tell apart from the values the refused
// batch carried, and read back afterwards, so a partial apply cannot hide behind the service-level code.
// @verifies AC-SVR-ATTR-WRITE-015-TOOMANYOPERATIONS
TEST(ReadServiceRequirements, ATTR_WRITE_015_AnOverLimitWriteIsRefusedWithNoPrefixOfTheBatchApplied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerWrite = 1;

  auto as = si->address_space();
  const NodeId firstNode{1, 100u};
  const NodeId secondNode{1, 101u};

  auto primeWritableVariable = [&as](const NodeId& nodeId, int32_t initialValue, const char* label)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "could not create " << label;
    if (varResult.is_bad())
      return;
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);
    DataValue dv;
    dv.value() = Variant{initialValue};
    varResult.value().write_value_sync(std::move(dv));
  };

  primeWritableVariable(firstNode, 1, "the first Variable");
  primeWritableVariable(secondNode, 2, "the second Variable");

  // Two operations against a limit of one.
  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (const auto& nodeId : {firstNode, secondNode})
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{99}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));

  // The request is refused as a whole, with the code that names the operation limit.
  EXPECT_TRUE(result.isServiceFault) << "an over-limit Write must be refused at the service level, but a "
                                        "typed WriteResponse came back carrying "
                                     << result.response.results().size() << " per-operation results";
  EXPECT_EQ(result.serviceResult, Status::BadTooManyOperations)
    << "the service result was " << result.serviceResult.value();

  // ...and no prefix of the batch was applied: both Variables still hold what they held before.
  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  for (const auto& nodeId : {firstNode, secondNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 2u);

  ASSERT_TRUE(after.response.results()[0].value().is_int32()) << "the first Variable read back no Int32";
  EXPECT_EQ(after.response.results()[0].value().as<int32_t>(), 1)
    << "operation 0 of a refused batch was applied: the first Variable now holds "
    << after.response.results()[0].value().as<int32_t>() << " instead of 1";

  ASSERT_TRUE(after.response.results()[1].value().is_int32()) << "the second Variable read back no Int32";
  EXPECT_EQ(after.response.results()[1].value().as<int32_t>(), 2)
    << "operation 1 of a refused batch was applied: the second Variable now holds "
    << after.response.results()[1].value().as<int32_t>() << " instead of 2";

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.4 - Bad_NodeIdInvalid: a syntactically invalid NodeId in a WriteValue.
//
// Invalid and unknown are two different instructions to the Client: invalid says it built the id wrongly
// and must fix how it constructs ids, unknown says the Node is gone and the id is worth re-resolving. A
// plausible implementation hands every nodeId straight to the address-space lookup, which can only ever
// report "no such node", so the malformed id is answered with the re-resolvable code and the Client
// re-resolves an id that can never resolve. The null NodeId (OPC 10000-6 section 5.2.2.9) is driven in its
// numeric and String encodings, both denoting the same null id, alongside a Variable that exists - the
// valid operation must still be written, because a per-operation fault may not sink the request.
// @verifies AC-SVR-ATTR-WRITE-017-NODEIDINVALID
TEST(ReadServiceRequirements, ATTR_WRITE_017_AMalformedNodeIdIsRejectedWhileTheValidNodeIsWritten)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId validNode{1, 100u};
  {
    auto varResult = as.try_create_sync<VariableAccessor>(validNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good());
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);
    DataValue dv;
    dv.value() = Variant{int32_t{1}};
    varResult.value().write_value_sync(std::move(dv));
  }

  WriteRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: the canonical null NodeId - numeric identifier 0 at NamespaceIndex 0.
  {
    WriteValue wv;
    wv.node_id() = NodeId{};
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{99}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: the same null NodeId in its String encoding - an empty String id at NamespaceIndex 0.
  {
    WriteValue wv;
    wv.node_id() = NodeId{0, ""};
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{99}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 2: a Node that exists, written in the same request.
  {
    WriteValue wv;
    wv.node_id() = validNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{42}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << "a malformed nodeId is a per-operation fault, not a refusal of "
                                         "the whole request; the service result was "
                                      << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 3u);

  // The numeric null encoding is reported as the Client's construction error...
  EXPECT_EQ(result.response.results()[0], Status::BadNodeIdInvalid)
    << "the numeric null NodeId was answered with " << result.response.results()[0].value();
  // ...and so is the String null encoding, which denotes the very same null NodeId.
  EXPECT_EQ(result.response.results()[1], Status::BadNodeIdInvalid)
    << "the String null NodeId was answered with " << result.response.results()[1].value();

  // The valid operation in the same request is written.
  EXPECT_TRUE(result.response.results()[2].is_good())
    << "the valid operation was refused alongside the malformed ones with "
    << result.response.results()[2].value();

  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  ReadValueId rvid;
  rvid.node_id() = validNode;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  readBack.nodes_to_read().payload().push_back(std::move(rvid));

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 1u);
  ASSERT_TRUE(after.response.results()[0].value().is_int32()) << "the valid Node read back no Int32";
  EXPECT_EQ(after.response.results()[0].value().as<int32_t>(), 42)
    << "the valid Node was not written: it holds " << after.response.results()[0].value().as<int32_t>()
    << " instead of 42";

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.1 - a locale that is syntactically invalid, or that the Server does not support, is
// answered with Bad_LocaleNotSupported.
//
// The obligation binds to Attributes whose DataType is LocalizedText - DisplayName, Description,
// InverseName - and the closing sentence of the same clause carves the Value Attribute of a LocalizedText
// Variable back out of it: "The Write behaviour for Value Attributes with a LocalizedText DataType is
// Server specific but it is recommended to follow the same rules", which CTT Err-015.js in turn records as
// implementation-defined ("aardvark may be accepted or rejected"). The stimulus is therefore driven on
// DisplayName, where the rule does bind, and deliberately not on a Variable's Value.
//
// Silently accepting the locale is the dangerous outcome rather than the harmless one: the read path picks
// the text to return by matching the Session's locales against the ones stored, so text filed under a
// locale the Server does not know is text no Client can ever be given back. The Write reports Good, the
// Attribute is changed, and the loss shows up only as an Attribute that reads back in the wrong language.
// A plausible implementation treats LocalizedText as an opaque pair and stores whatever arrives. Both
// stimuli named by the obligation are driven, each on its own Node so the rejected write cannot be masked
// by a later accepted one, with a supported locale on a third Node as the control that proves the
// DisplayName Attribute is writable on this session at that moment.
// @verifies AC-SVR-ATTR-WRITE-029-LOCALENOTSUPPORTED
TEST(ReadServiceRequirements, ATTR_WRITE_029_AnInvalidOrUnsupportedLocaleIsRefusedRatherThanStored)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  si->serverCfg.server_capabilities().localeIds = {"fr"};

  auto as = si->address_space();
  const NodeId malformedLocaleNode{1, 100u};
  const NodeId unsupportedLocaleNode{1, 101u};
  const NodeId controlNode{1, 102u};

  auto primeLocalizedTextNode = [&as](const NodeId& nodeId, const char* label)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "could not create " << label;
    if (varResult.is_bad())
      return;
    // DisplayName is governed by the WriteMask, not by the AccessLevel, which speaks for the Value only.
    varResult.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    varResult.value().set_display_name(LocalizedText{"fr", "Original"});
  };

  primeLocalizedTextNode(malformedLocaleNode, "the malformed-locale Node");
  primeLocalizedTextNode(unsupportedLocaleNode, "the unsupported-locale Node");
  primeLocalizedTextNode(controlNode, "the control Node");

  WriteRequest req;
  req.request_header().request_handle() = 1;

  // Operation 0: a locale id that is not a well-formed language tag at all - spaces are not permitted
  // between subtags, which are separated by hyphens.
  {
    WriteValue wv;
    wv.node_id() = malformedLocaleNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"not a locale", "Malformed"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: a well-formed locale id not present in the Server's configured LocaleIdArray.
  {
    WriteValue wv;
    wv.node_id() = unsupportedLocaleNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"de", "Unsupported"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 2: control - the non-default locale the Server advertises, on the same Attribute shape.
  {
    WriteValue wv;
    wv.node_id() = controlNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"fr", "Accepted"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << "an unsupported locale is a per-operation fault; the service "
                                         "result was "
                                      << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 3u);

  // The control proves the DisplayName Attribute is writable here, so the two refusals are attributable
  // to the locale ids alone.
  EXPECT_TRUE(result.response.results()[2].is_good())
    << "a supported locale was refused with " << result.response.results()[2].value();

  EXPECT_EQ(result.response.results()[0], Status::BadLocaleNotSupported)
    << "a syntactically invalid locale was answered with " << result.response.results()[0].value();
  EXPECT_EQ(result.response.results()[1], Status::BadLocaleNotSupported)
    << "an unsupported locale was answered with " << result.response.results()[1].value();
  ASSERT_NE(result.response.results()[0].shared_detail(), nullptr);
  EXPECT_EQ(result.response.results()[0].shared_detail()->code, "LocaleIdSyntacticallyInvalid");
  ASSERT_NE(result.response.results()[1].shared_detail(), nullptr);
  EXPECT_EQ(result.response.results()[1].shared_detail()->code, "LocaleIdUnsupported");

  // ...and neither rejected text was stored: the Attribute a Client would read back is unchanged.
  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  for (const auto& nodeId : {malformedLocaleNode, unsupportedLocaleNode, controlNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 3u);

  const LocalizedText* malformed = after.response.results()[0].value().try_as<LocalizedText>();
  ASSERT_NE(malformed, nullptr) << "the malformed-locale Node read back no LocalizedText DisplayName";
  EXPECT_EQ(malformed->text(), "Original")
    << "the text written under a malformed locale was stored: the DisplayName now reads back "
    << static_cast<std::string_view>(malformed->text()) << " in locale "
    << static_cast<std::string_view>(malformed->locale());

  const LocalizedText* unsupported = after.response.results()[1].value().try_as<LocalizedText>();
  ASSERT_NE(unsupported, nullptr) << "the unsupported-locale Node read back no LocalizedText DisplayName";
  EXPECT_EQ(unsupported->text(), "Original")
    << "the text written under an unsupported locale was stored: the DisplayName now reads back "
    << static_cast<std::string_view>(unsupported->text()) << " in locale "
    << static_cast<std::string_view>(unsupported->locale());

  const LocalizedText* control = after.response.results()[2].value().try_as<LocalizedText>();
  ASSERT_NE(control, nullptr) << "the control Node read back no LocalizedText DisplayName";
  EXPECT_EQ(control->text(), "Accepted") << "the accepted write did not land: the control DisplayName reads "
                                         << static_cast<std::string_view>(control->text());

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.2 - the Server shall assume that by receiving the correct wire representation for a
// simple DataType the correct type was chosen.
//
// A simple DataType has no distinguishing encoding: a Duration is a Double on the wire and a UtcTime is a
// DateTime, so the only thing that ever arrives is the built-in representation and the subtype is named
// nowhere but in the Variable's own DataType Attribute. A plausible implementation compares the Variant's
// built-in type id against the declared DataType id, finds 11 against 290, and refuses with
// Bad_TypeMismatch - which makes every simple subtype of a built-in permanently unwritable while leaving
// the plain built-in Variables beside them working, so the fault looks like a bad nodeset rather than a
// type check. Two simple DataTypes over two different built-in representations are driven, because an
// implementation that special-cases the numeric family still refuses the temporal one, and each write is
// asserted on the value that reads back so an accepted-and-discarded write cannot pass for an accepted one.
// @verifies AC-SVR-ATTR-WRITE-012-WIRE-REPR-IMPLIES-TYPE
TEST(ReadServiceRequirements, ATTR_WRITE_012_TheWireRepresentationOfASimpleDataTypeIsAcceptedAsThatType)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId hasSubtype{0, 45u};  // NS0 i=45 = HasSubtype
  const NodeId doubleDataType{0, 11u};  // NS0 i=11 = Double
  const NodeId dateTimeDataType{0, 13u};  // NS0 i=13 = DateTime
  const NodeId durationDataType{0, 290u};  // NS0 i=290 = Duration, a simple subtype of Double
  const NodeId utcTimeDataType{0, 294u};  // NS0 i=294 = UtcTime, a simple subtype of DateTime
  const NodeId durationNode{1, 100u};
  const NodeId utcTimeNode{1, 101u};

  ASSERT_TRUE(as.try_create_sync<DataTypeAccessor>(doubleDataType, NodeClass::DataType).is_good());
  ASSERT_TRUE(as.try_create_sync<DataTypeAccessor>(dateTimeDataType, NodeClass::DataType).is_good());

  // The subtype relation is published rather than assumed. Without the inverse HasSubtype the declared
  // DataType is a root the Server can learn nothing about, and accepting the write would prove only that an
  // unresolvable DataType is not enforced - a Server that walked the chain and then demanded the Client name
  // the subtype would pass just the same. With it, Duration reaches Double and UtcTime reaches DateTime, so
  // the Server decides with the hierarchy in front of it.
  auto declareSimpleDataType = [&as, &hasSubtype](
                                 const NodeId& subtypeId, const NodeId& baseTypeId, const char* label)
  {
    auto dtResult = as.try_create_sync<DataTypeAccessor>(subtypeId, NodeClass::DataType);
    EXPECT_TRUE(dtResult.is_good()) << "could not create " << label;
    if (dtResult.is_bad())
      return;
    EXPECT_TRUE(dtResult.value().try_add_reference_sync(hasSubtype, baseTypeId, false).is_good())
      << label << " could not be made a subtype of its built-in base type";
  };

  declareSimpleDataType(durationDataType, doubleDataType, "the Duration DataType");
  declareSimpleDataType(utcTimeDataType, dateTimeDataType, "the UtcTime DataType");

  auto declareVariable = [&as](const NodeId& nodeId, const NodeId& dataTypeId, const char* label)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "could not create " << label;
    if (varResult.is_bad())
      return;
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(dataTypeId);
  };

  declareVariable(durationNode, durationDataType, "the Duration Variable");
  declareVariable(utcTimeNode, utcTimeDataType, "the UtcTime Variable");

  const DateTime stamp = DateTime::now();

  WriteRequest req;
  req.request_header().request_handle() = 1;
  // Operation 0: the Double wire representation of a Duration, with the subtype named nowhere.
  {
    WriteValue wv;
    wv.node_id() = durationNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{double{2.5}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: the DateTime wire representation of a UtcTime, likewise unnamed.
  {
    WriteValue wv;
    wv.node_id() = utcTimeNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{stamp};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault)
    << "the service refused the request outright with " << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 2u);

  EXPECT_TRUE(result.response.results()[0].is_good())
    << "the Double wire representation of a Duration was refused with "
    << result.response.results()[0].value();
  EXPECT_TRUE(result.response.results()[1].is_good())
    << "the DateTime wire representation of a UtcTime was refused with "
    << result.response.results()[1].value();

  // Accepted rather than accepted-and-discarded: each Variable hands back what was written.
  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  for (const auto& nodeId : {durationNode, utcTimeNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 2u);

  ASSERT_TRUE(after.response.results()[0].value().is_double()) << "the Duration Variable read back no Double";
  EXPECT_DOUBLE_EQ(after.response.results()[0].value().as<double>(), 2.5);

  const DateTime* storedStamp = after.response.results()[1].value().try_as<DateTime>();
  ASSERT_NE(storedStamp, nullptr) << "the UtcTime Variable read back no DateTime";
  EXPECT_EQ(*storedStamp, stamp);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.4 with Table 183 - Bad_NoCommunication: communication with the data source is defined
// but not established, and there is no last known value available.
//
// The setpoint case is why the code exists. A write that reached the Server's cache and never reached the
// device must not read as Good, because the Client's next act is to stop asking and believe the plant is
// at the value it sent. A plausible implementation posts the write to the data source and answers the
// Client from the post rather than from the completion, or collapses whatever the source reported into a
// single generic failure, and either way the specific "the path is down, retry" instruction is lost. The
// data source below refuses because it cannot reach its device; a second Variable with a reachable source
// is written in the same request as the control, so the refusal is attributable to the source alone. The
// refused Variable is read back to show the source still reports its last known value, not the refused one.
// @verifies AC-SVR-ATTR-WRITE-031-BAD-NOCOMMUNICATION
TEST(ReadServiceRequirements, ATTR_WRITE_031_AWriteToAnUnreachableDataSourceIsNotReportedAsSuccess)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId unreachableNode{1, 100u};
  const NodeId reachableNode{1, 101u};

  auto unreachable = as.try_create_sync<VariableAccessor>(unreachableNode, NodeClass::Variable);
  ASSERT_TRUE(unreachable.is_good());
  auto reachable = as.try_create_sync<VariableAccessor>(reachableNode, NodeClass::Variable);
  ASSERT_TRUE(reachable.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  unreachable.value().set_access_level(al);
  reachable.value().set_access_level(al);
  {
    DataValue dv;
    dv.value() = Variant{int32_t{8}};
    reachable.value().write_value_sync(std::move(dv));
  }

  // The device behind the proxied Variable: the path to it is configured but currently down, so every
  // write attempt reaches the source and the source cannot commit it. The source is the whole value source:
  // reads answer its last known value (7, the setpoint the device last confirmed), which a committed write
  // would update.
  auto deviceWrites = std::make_shared<std::atomic<int>>(0);
  auto lastKnown = std::make_shared<std::atomic<int32_t>>(7);
  auto& proxied = unreachable.value();
  auto* source = proxied->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed =
    source->set_value_source(make_value_source([lastKnown](const ValueSource::ReadContext& /*context*/,
                                                 const Node&,
                                                 const ReadValueId&,
                                                 std::function<void(DataValueResult)>
                                                   done) { done(DataValue{Variant{lastKnown->load()}}); },
      [deviceWrites](const ValueSource::WriteContext& /*context*/,
        const Node&,
        const WriteValue&,
        std::function<void(ValueSource::WriteResult)>
          done)
      {
        deviceWrites->fetch_add(1);
        done(ValueSource::WriteResult{StatusCode{Status::BadNoCommunication}});
      }));
  ASSERT_TRUE(installed.is_good());

  WriteRequest req;
  req.request_header().request_handle() = 1;
  // Operation 0: the setpoint that cannot reach its device.
  {
    WriteValue wv;
    wv.node_id() = unreachableNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{99}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: control - a Variable whose data source is the Server's own store.
  {
    WriteValue wv;
    wv.node_id() = reachableNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{55}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << "an unreachable data source is a per-operation fault; the "
                                         "service result was "
                                      << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 2u);

  // The write did reach the data source, so the verdict below is about the data path and not about a
  // check made before it.
  EXPECT_GT(deviceWrites->load(), 0) << "the write never reached the data source at all";

  // The operation carries the code that says the path is down...
  EXPECT_EQ(result.response.results()[0], Status::BadNoCommunication)
    << "a write that could not reach its data source was answered with "
    << result.response.results()[0].value();
  // ...and above all it is not reported as success.
  EXPECT_FALSE(result.response.results()[0].is_good())
    << "a write that never reached the device was reported as applied";

  // The control proves the request and the session were fine at that moment.
  EXPECT_TRUE(result.response.results()[1].is_good())
    << "the control operation was refused with " << result.response.results()[1].value();

  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  for (const auto& nodeId : {unreachableNode, reachableNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 2u);

  ASSERT_TRUE(after.response.results()[0].value().is_int32()) << "the proxied Variable read back no Int32";
  EXPECT_EQ(after.response.results()[0].value().as<int32_t>(), 7)
    << "the setpoint was cached although the device never took it: the Variable now holds "
    << after.response.results()[0].value().as<int32_t>() << " instead of 7";

  ASSERT_TRUE(after.response.results()[1].value().is_int32()) << "the control Variable read back no Int32";
  EXPECT_EQ(after.response.results()[1].value().as<int32_t>(), 55);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.2 - the Server returns Bad_WriteNotSupported if it does not support writing of
// timestamps.
//
// A Server has two honest answers to a DataValue that carries the Client's own instants and one dishonest
// one. It may take them, in which case the Value it hands back afterwards carries the instants the Client
// sent; or it may refuse the operation with Bad_WriteNotSupported and leave the Attribute untouched, which
// tells the Client to resend without them. What it may not do is report the write as applied and quietly
// keep its own clock's instants instead. A historian backfilling a day of readings then sees every original
// instant replaced by the moment of the upload, with nothing anywhere in the response saying so, and the
// record is unrecoverable because the instants existed only in what it sent. A plausible implementation
// lifts the Variant out of the WriteValue and builds a fresh DataValue around it, stamping source and
// server time at the point of the store - which produces exactly that, and looks perfectly correct from
// every test that only reads the value back. The SourceTimestamp is the one asserted: it is the instant the
// reading was taken and the only one nothing downstream can recompute. The ServerTimestamp is supplied
// beside it so the DataValue is the timestamp-carrying shape the obligation names, but it is not asserted
// on read-back, because a Server may legitimately restamp it with the moment it served the Read. A second
// Variable is written with no timestamps at all in the same request, so a refusal of the first is
// attributable to the timestamps and not to writing.
// @verifies AC-SVR-ATTR-WRITE-030-TIMESTAMP-UNSUPPORTED
TEST(ReadServiceRequirements, ATTR_WRITE_030_ClientTimestampsAreHonouredOrRefusedNeverSilentlyDropped)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId timestampedNode{1, 100u};
  const NodeId controlNode{1, 101u};

  auto primeWritableVariable = [&as](const NodeId& nodeId, int32_t initialValue, const char* label)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "could not create " << label;
    if (varResult.is_bad())
      return;
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);
    DataValue dv;
    dv.value() = Variant{initialValue};
    varResult.value().write_value_sync(std::move(dv));
  };

  primeWritableVariable(timestampedNode, 1, "the timestamped Variable");
  primeWritableVariable(controlNode, 2, "the control Variable");

  // Instants from the recorder's own clock, far enough from now that the Server's clock cannot be mistaken
  // for either of them.
  const DateTime suppliedSource{2021, 3, 4, 5, 6, 7.0};
  const DateTime suppliedServer{2021, 3, 4, 5, 6, 8.0};

  WriteRequest req;
  req.request_header().request_handle() = 1;
  // Operation 0: the DataValue carrying the Client's timestamps.
  {
    WriteValue wv;
    wv.node_id() = timestampedNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{99}};
    wv.value().source_timestamp() = suppliedSource;
    wv.value().server_timestamp() = suppliedServer;
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: control - the same Attribute of the same shape, written with no timestamps at all.
  {
    WriteValue wv;
    wv.node_id() = controlNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{55}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << "timestamp support is a per-operation matter, not a refusal of the "
                                         "whole request; the service result was "
                                      << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 2u);

  // The control proves a Value write lands on this session at this moment.
  EXPECT_TRUE(result.response.results()[1].is_good())
    << "the untimestamped control write was refused with " << result.response.results()[1].value();

  const auto timestampedStatus = result.response.results()[0];

  ReadRequest readBack;
  readBack.request_header().request_handle() = 2;
  readBack.timestamps_to_return() = TimestampsToReturn::Both;
  for (const auto& nodeId : {timestampedNode, controlNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 2u);
  ASSERT_TRUE(after.response.results()[0].value().is_int32())
    << "the timestamped Variable read back no Int32";
  const int32_t heldValue = after.response.results()[0].value().as<int32_t>();

  if (timestampedStatus == Status::BadWriteNotSupported)
  {
    // Refused: the Attribute is left exactly as it was, so the Client can resend without the timestamps.
    EXPECT_EQ(heldValue, 1) << "the operation was refused with Bad_WriteNotSupported and applied anyway: "
                               "the Variable now holds "
                            << heldValue << " instead of 1";
  }
  else if (timestampedStatus.is_good())
  {
    // Honoured: the instants the Client sent are the instants the Server holds.
    EXPECT_EQ(heldValue, 99) << "the write was reported as applied but the Variable holds " << heldValue;

    const auto& storedSource = after.response.results()[0].source_timestamp();
    ASSERT_TRUE(storedSource.has_value()) << "the Variable read back with no SourceTimestamp at all";
    EXPECT_EQ(*storedSource, suppliedSource)
      << "the write reported success and the Client's SourceTimestamp was dropped: the Variable reads back "
      << storedSource->as_iso_string() << " where the Client wrote " << suppliedSource.as_iso_string();
  }
  else
  {
    ADD_FAILURE() << "a timestamped write is either honoured or refused with Bad_WriteNotSupported; this "
                     "one was answered with "
                  << timestampedStatus.value();
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.2 requires the Server to use a supplied SourceTimestamp or ServerTimestamp. Part 4
// section 7.11.4 makes the ServerTimestamp part of the value's provenance (when the Server received or knew
// the value to be accurate), while section 7.40 makes TimestampsToReturn a transmission selector. A Read
// response therefore preserves an existing ServerTimestamp, synthesizes one only when the value has
// none, and still omits it when the Client asks for Source only.
// @relation(AC-SVR-ATTR-WRITE-007-SUPPLIED-TIMESTAMPS, scope=function)
TEST(ReadServiceRequirements, ATTR_WRITE_007_SuppliedTimestampsAreStoredAndReturned)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  const NodeId suppliedTimestampNode{1, 107u};
  const NodeId missingServerTimestampNode{1, 108u};
  auto addressSpace = si->address_space();
  for (const auto& nodeId : {suppliedTimestampNode, missingServerTimestampNode})
  {
    auto variableResult = addressSpace.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    ASSERT_TRUE(variableResult.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    accessLevel.set(AccessLevelType::Bit::TimestampWrite);
    variableResult.value().set_access_level(accessLevel);
  }

  const DateTime suppliedSource{2021, 3, 4, 5, 6, 7.0};
  const DateTime suppliedServer{2021, 3, 4, 5, 6, 8.0};

  WriteRequest writeRequest;
  writeRequest.request_header().request_handle() = 1;
  {
    WriteValue writeValue;
    writeValue.node_id() = suppliedTimestampNode;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value().value() = Variant{int32_t{99}};
    writeValue.value().source_timestamp() = suppliedSource;
    writeValue.value().server_timestamp() = suppliedServer;
    writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));
  }
  {
    WriteValue writeValue;
    writeValue.node_id() = missingServerTimestampNode;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value().value() = Variant{int32_t{55}};
    writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));
  }

  auto writeResult = do_write(si, ex, std::move(writeRequest));
  ASSERT_FALSE(writeResult.isServiceFault);
  ASSERT_EQ(writeResult.response.results().size(), 2u);
  EXPECT_TRUE(writeResult.response.results()[0].is_good());
  EXPECT_TRUE(writeResult.response.results()[1].is_good());

  // maxAge Int32 max is the cached-value read (Part 4 5.10.2.2): the held ServerTimestamp is returned.
  // A smaller maxAge would be entitled to a fresh one once the held stamp is older than it.
  ReadRequest bothRequest;
  bothRequest.request_header().request_handle() = 2;
  bothRequest.timestamps_to_return() = TimestampsToReturn::Both;
  bothRequest.max_age() = static_cast<Duration>(std::numeric_limits<int32_t>::max());
  for (const auto& nodeId : {suppliedTimestampNode, missingServerTimestampNode})
  {
    ReadValueId readValue;
    readValue.node_id() = nodeId;
    readValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    bothRequest.nodes_to_read().payload().push_back(std::move(readValue));
  }

  auto bothResult = do_read(si, ex, std::move(bothRequest));
  ASSERT_FALSE(bothResult.isServiceFault);
  ASSERT_EQ(bothResult.response.results().size(), 2u);
  const auto& supplied = bothResult.response.results()[0];
  ASSERT_TRUE(supplied.value().is_int32());
  EXPECT_EQ(supplied.value().as<int32_t>(), 99);
  ASSERT_TRUE(supplied.source_timestamp().has_value());
  EXPECT_EQ(*supplied.source_timestamp(), suppliedSource);
  ASSERT_TRUE(supplied.server_timestamp().has_value());
  EXPECT_EQ(*supplied.server_timestamp(), suppliedServer);

  const auto& synthesized = bothResult.response.results()[1];
  ASSERT_TRUE(synthesized.server_timestamp().has_value());
  EXPECT_FALSE(synthesized.server_timestamp()->is_null());

  ReadRequest sourceOnlyRequest;
  sourceOnlyRequest.request_header().request_handle() = 3;
  sourceOnlyRequest.timestamps_to_return() = TimestampsToReturn::Source;
  ReadValueId readValue;
  readValue.node_id() = suppliedTimestampNode;
  readValue.attribute_id() = utils::to_underlying(AttributeId::Value);
  sourceOnlyRequest.nodes_to_read().payload().push_back(std::move(readValue));

  auto sourceOnlyResult = do_read(si, ex, std::move(sourceOnlyRequest));
  ASSERT_FALSE(sourceOnlyResult.isServiceFault);
  ASSERT_EQ(sourceOnlyResult.response.results().size(), 1u);
  ASSERT_TRUE(sourceOnlyResult.response.results()[0].source_timestamp().has_value());
  EXPECT_EQ(*sourceOnlyResult.response.results()[0].source_timestamp(), suppliedSource);
  EXPECT_FALSE(sourceOnlyResult.response.results()[0].server_timestamp().has_value());

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.3.2 (Table 56) gives `dataEncoding` on a HistoryReadValueId the meaning it has on Read:
// it "only applies if the DataType of the Variable is a subtype of Structure. It is an error to specify this
// parameter if the DataType of the Variable is not a subtype of Structure." Table 58 lists both
// Bad_DataEncodingInvalid and Bad_DataEncodingUnsupported among the HistoryRead operation-level codes and
// defers to Table 183 for their meaning, and Table 183 separates them by APPLICABILITY rather than by the
// name the Client passed: Bad_DataEncodingInvalid "is used if no dataEncoding can be applied because an
// Attribute other than Value was requested or the DataType of the Value Attribute is not a subtype of the
// Structure DataType", Bad_DataEncodingUnsupported "if a dataEncoding can be applied but the passed data
// encoding is not known to the Server". The second is AC-SVR-ATTR-HREAD-023; this criterion is the first,
// and the normative table decides which condition each code names.
//
// A plausible implementation carries one test - is this the encoding name I provide? - and answers
// everything else Bad_DataEncodingUnsupported, so a Client that attached an encoding to a scalar history
// Node is sent away to look for another encoding and will try every encoding it knows before discovering
// that none was ever applicable; the same implementation answers the encoding it does provide with Good and
// so accepts a parameter the specification calls an error outright. Both a provided encoding name and an
// unprovided one are therefore driven against the same non-Structure Node, because an implementation that
// reaches the name comparison at all gets the second wrong even where it happens to get the first right,
// alongside an operation naming no encoding at all as the control that proves the history is readable.
// @verifies AC-SVR-ATTR-HREAD-022-DATAENCODINGINVALID
TEST(ReadServiceRequirements, ATTR_HREAD_022_AnEncodingOnANodeNoEncodingAppliesToIsInvalidNotUnsupported)
{
  HistoryFixture h;
  h.setup();

  // A Variable whose DataType is Int32 (ns=0;i=6) - not a subtype of Structure, so no dataEncoding can be
  // applied to its history whatever the encoding names, and the Server can decide that from the DataType
  // Attribute alone.
  NodeId scalarNode{h.nsIndex, 500u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(scalarNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{6}});
  }

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = Variant{static_cast<int32_t>(7)};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_history_raw_request({scalarNode, scalarNode, scalarNode});
  // Operation 0: an encoding this Server does provide. Operation 1: one it does not. Neither can be
  // applied to this Node, so the name is beside the point and both are invalid rather than unsupported.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default Binary"};
  request.nodes_to_read()[1].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = history_response_of(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the whole request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 3u);

  // The control: the same Node, the same interval, no dataEncoding - served, so the two refusals below are
  // attributable to the parameter alone and not to a Node with no history.
  EXPECT_TRUE(response->results()[2].status_code().is_good())
    << "the operation that named no encoding was refused with "
    << response->results()[2].status_code().value();
  auto* served = dynamic_cast<HistoryData*>(response->results()[2].history_data().get());
  ASSERT_NE(served, nullptr) << "the unaffected operation returned no history at all";
  EXPECT_EQ(served->data_values().size(), 1u);
  EXPECT_GT(delegateCalls.load(), 0) << "the history was never read, so nothing here is about the encoding";

  for (const std::size_t op : {std::size_t{0}, std::size_t{1}})
  {
    EXPECT_EQ(response->results()[op].status_code(), StatusCode{Status::BadDataEncodingInvalid})
      << "operation " << op << " attached a dataEncoding to a Node whose DataType is not a subtype of "
      << "Structure and was answered with " << response->results()[op].status_code().value()
      << "; no encoding can be applied there, which is the condition Bad_DataEncodingInvalid names";
    ASSERT_NE(response->results()[op].status_code().shared_detail(), nullptr);
    EXPECT_EQ(response->results()[op].status_code().shared_detail()->code, "HistoryDataEncodingInvalid");
    EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[op].history_data().get()), nullptr)
      << "operation " << op << " was refused and still handed back the history it refused to encode";
  }
}

// Part 4 section 5.10.4.2 (Table 59, the `value` parameter): "Servers are allowed to impose additional data
// validations on the value independent of the encoding (e.g. having an image in GIF format in a
// ByteString). In this case the Server shall return a Bad_TypeMismatch error if the validation fails."
// The first sentence is a permission and names no validation any Server owes; the second binds only WHICH
// code a Server that has chosen to impose one must answer with when it fails. So the obligation here is a
// code mapping, and the criterion's own STATEMENT concedes as much - "one code for two distinguishable
// failures is the specification's choice". An earlier instancing of this test demanded that a Structure
// carrying a field its DataType's StructureDefinition does not declare be refused; that read a
// validation-existence obligation out of a permission, and no clause requires field-set conformance.
//
// The validation this Server has in fact chosen to impose is the one the same paragraph sets up: "Simple
// DataTypes use the same representation on the wire as their super types ... The Server shall assume that
// by receiving the correct wire representation for a simple DataType the correct type was chosen." A
// Variable declaring ImageGIF names a DataType with no built-in id of its own, so the only thing the
// Server can check is that what arrived carries the representation the chain ImageGIF  subset of  Image
// subset of  ByteString inherits - and it is elective, because a Server that cannot resolve the chain is not
// obliged to synthesise the check (this one gives up gracefully at every unresolvable hop). Elective,
// therefore the permission's clause governs it, and AC-SVR-ATTR-WRITE-012 records the division: the matching
// representation is accepted there, a genuinely wrong one is refused here.
//
// The code is the whole of the claim. Table 61 offers Bad_OutOfRange for "any value that has the right
// DataType but does not comply with the restrictions defined by the Server implementation" and
// Bad_DataEncodingUnsupported for an encoding the Server does not support, and an implementation reaching
// for either sends the Client to fix the wrong thing - the value's range, or its serialisation, when what
// is wrong is its type; an implementation that reads the shall-assume sentence as "never refuse what I
// cannot verify" answers Good and stores it. Two chains are driven: the clause's own GIF example, whose
// base is two hops away and not numeric, and a Variable declaring a nodeset-defined simple DataType in
// ns=1, which an implementation that resolves NS0 ids from a table can only reach by walking. A conforming
// write to each Variable runs first, in its own request because Part 4 section 5.10.4.1 leaves the order of
// operations naming the same Node and Attribute undefined, so a refusal is attributable to the
// representation and not to the Node being unwritable; both are read back to prove nothing landed. The
// control ByteString is a well-formed GIF header rather than arbitrary bytes, so it stays conforming under
// the content validation the clause permits as well as under the representation check actually imposed.
TEST(ReadServiceRequirements, ATTR_WRITE_009_AValueOfASiblingDataTypeIsRefusedWithTypeMismatch)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId hasSubtype{0, 45u};  // NS0 i=45 = HasSubtype
  const NodeId byteStringDataType{0, 15u};  // NS0 i=15 = ByteString
  const NodeId stringDataType{0, 12u};  // NS0 i=12 = String
  const NodeId imageDataType{0, 30u};  // NS0 i=30 = Image, a simple subtype of ByteString
  const NodeId imageGifDataType{0, 2001u};  // NS0 i=2001 = ImageGIF, a simple subtype of Image
  const NodeId serialNumberDataType{1, 7300u};  // a nodeset-defined simple subtype of String
  const NodeId imageNode{1, 100u};
  const NodeId serialNode{1, 101u};

  ASSERT_TRUE(as.try_create_sync<DataTypeAccessor>(byteStringDataType, NodeClass::DataType).is_good());
  ASSERT_TRUE(as.try_create_sync<DataTypeAccessor>(stringDataType, NodeClass::DataType).is_good());

  // The subtype relation is published rather than assumed. Without the inverse HasSubtype the declared
  // DataType is a root the Server can learn nothing about, and every write to it would be accepted for
  // want of anything to compare against - so a Server that never walks would look conforming.
  auto declareSimpleDataType = [&as, &hasSubtype](
                                 const NodeId& subtypeId, const NodeId& baseTypeId, const char* label)
  {
    auto dtResult = as.try_create_sync<DataTypeAccessor>(subtypeId, NodeClass::DataType);
    EXPECT_TRUE(dtResult.is_good()) << "could not create " << label;
    if (dtResult.is_bad())
      return;
    EXPECT_TRUE(dtResult.value().try_add_reference_sync(hasSubtype, baseTypeId, false).is_good())
      << label << " could not be made a subtype of its base type";
  };

  declareSimpleDataType(imageDataType, byteStringDataType, "the Image DataType");
  declareSimpleDataType(imageGifDataType, imageDataType, "the ImageGIF DataType");
  declareSimpleDataType(serialNumberDataType, stringDataType, "the SerialNumber DataType");

  auto declareVariable = [&as](const NodeId& nodeId, const NodeId& dataTypeId, const char* label)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "could not create " << label;
    if (varResult.is_bad())
      return;
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(dataTypeId);
  };

  declareVariable(imageNode, imageGifDataType, "the ImageGIF Variable");
  declareVariable(serialNode, serialNumberDataType, "the SerialNumber Variable");

  // "GIF89a" - the header of the format the clause names, so the control is a conforming value under the
  // content validation the clause permits as well as under the representation check imposed below.
  const ByteString gifHeader{0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
  const String serialText{"SN-000117"};

  {
    WriteRequest control;
    control.request_header().request_handle() = 1;
    {
      WriteValue wv;
      wv.node_id() = imageNode;
      wv.attribute_id() = utils::to_underlying(AttributeId::Value);
      wv.value().value() = Variant{gifHeader};
      control.nodes_to_write().payload().push_back(std::move(wv));
    }
    {
      WriteValue wv;
      wv.node_id() = serialNode;
      wv.attribute_id() = utils::to_underlying(AttributeId::Value);
      wv.value().value() = Variant{serialText};
      control.nodes_to_write().payload().push_back(std::move(wv));
    }

    auto controlResult = do_write(si, ex, std::move(control));
    ASSERT_FALSE(controlResult.isServiceFault)
      << "the control writes were refused outright with " << controlResult.serviceResult.value();
    ASSERT_EQ(controlResult.response.results().size(), 2u);
    // The controls prove each Node is writable at this moment through the same validation, so the
    // refusals asserted below are attributable to the representation alone.
    ASSERT_TRUE(controlResult.response.results()[0].is_good())
      << "the ByteString representation an ImageGIF inherits was refused with "
      << controlResult.response.results()[0].value();
    ASSERT_TRUE(controlResult.response.results()[1].is_good())
      << "the String representation a SerialNumber inherits was refused with "
      << controlResult.response.results()[1].value();
  }

  WriteRequest req;
  req.request_header().request_handle() = 2;
  // Operation 0: an Int32 where the ImageGIF chain bottoms out at ByteString, two hops up.
  {
    WriteValue wv;
    wv.node_id() = imageNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{2001}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  // Operation 1: a Double where the ns=1 SerialNumber bottoms out at String - the DataType an
  // implementation working from a table of NS0 ids can say nothing about without walking.
  {
    WriteValue wv;
    wv.node_id() = serialNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{double{117.0}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault)
    << "a value failure is per operation; the service result was " << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 2u);

  EXPECT_EQ(result.response.results()[0], Status::BadTypeMismatch)
    << "an Int32 written where the declared ImageGIF inherits a ByteString was answered with "
    << result.response.results()[0].value()
    << "; the validation this Server imposes on the value failed, and the clause binds Bad_TypeMismatch to "
       "that failure - not Bad_OutOfRange, which Table 61 gives to a value of the right DataType, nor "
       "Bad_DataEncodingUnsupported, which speaks for the encoding the validation is independent of";
  EXPECT_EQ(result.response.results()[1], Status::BadTypeMismatch)
    << "a Double written where the declared SerialNumber inherits a String was answered with "
    << result.response.results()[1].value()
    << "; the validation this Server imposes on the value failed, and the clause binds Bad_TypeMismatch to "
       "that failure - not Bad_OutOfRange, which Table 61 gives to a value of the right DataType, nor "
       "Bad_DataEncodingUnsupported, which speaks for the encoding the validation is independent of";

  // ...and each refusal is a refusal: both Variables still hold what the control wrote.
  ReadRequest readBack;
  readBack.request_header().request_handle() = 3;
  for (const auto& nodeId : {imageNode, serialNode})
  {
    ReadValueId rvid;
    rvid.node_id() = nodeId;
    rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
    readBack.nodes_to_read().payload().push_back(std::move(rvid));
  }

  auto after = do_read(si, ex, std::move(readBack));
  ASSERT_FALSE(after.isServiceFault);
  ASSERT_EQ(after.response.results().size(), 2u);

  const ByteString* heldImage = after.response.results()[0].value().try_as<ByteString>();
  ASSERT_NE(heldImage, nullptr)
    << "the ImageGIF Variable no longer holds a ByteString: the refused Int32 was stored anyway";
  EXPECT_EQ(*heldImage, gifHeader) << "the ImageGIF Variable no longer holds the bytes the control wrote";

  const String* heldSerial = after.response.results()[1].value().try_as<String>();
  ASSERT_NE(heldSerial, nullptr)
    << "the SerialNumber Variable no longer holds a String: the refused Double was stored anyway";
  EXPECT_EQ(*heldSerial, serialText) << "the SerialNumber Variable now reads back "
                                     << static_cast<std::string_view>(*heldSerial)
                                     << " where the control wrote "
                                     << static_cast<std::string_view>(serialText);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.1: "Writing a null String for the locale and a non-null String for the text is
// setting the text for an invariant locale." It is the third of three null patterns on the same parameter - a
// null text deletes that locale, a null text with a null locale deletes every locale - so the meaning of the
// null locale flips on whether the text beside it is null, which is exactly the confusion this criterion
// exists to pin. The clause binds where the DataType of the Attribute is LocalizedText, so the stimulus is
// driven on DisplayName; the same paragraph makes the behaviour of a Variable's Value "Server specific", so
// no Value is written here.
//
// A plausible implementation treats LocalizedText as one opaque pair and stores what arrived, replacing the
// whole Attribute: the invariant text then reads back, so the arm this criterion names looks satisfied,
// while every other translation the Node held has silently gone. The other direction is just as plausible -
// an implementation that recognises the null locale but routes it to the delete-all branch that a null
// locale WITH a null text selects, leaving the Attribute empty. So the surviving translations are asserted
// beside the invariant entry, per locale, against the stored Attribute rather than against a Read: a Read
// resolves one translation out of the set for the Session, and would report a pass whichever of the other
// entries survived.
// @verifies AC-SVR-ATTR-WRITE-028-NULL-LOCALE-INVARIANT
TEST(ReadServiceRequirements, ATTR_WRITE_028_ANullLocaleWithTextSetsTheInvariantOneAndLeavesTheOthers)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId nodeId{1, 100u};

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  // DisplayName is governed by the WriteMask, not by the AccessLevel, which speaks for the Value only.
  varResult.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  // Two locales, filed one at a time through the same per-locale merge the Service write below uses.
  varResult.value().set_display_name(LocalizedText{"en", "Pump"});
  varResult.value().set_display_name(LocalizedText{"de", "Pumpe"});

  {
    const auto primed = varResult.value().read_attribute(AttributeId::DisplayName);
    const auto* stored = primed.try_as<LocalizedText>();
    ASSERT_NE(stored, nullptr) << "the Node holds no DisplayName to begin with";
    ASSERT_TRUE(stored->text_for_locale("en").has_value()) << "the en translation was never filed";
    ASSERT_TRUE(stored->text_for_locale("de").has_value()) << "the de translation was never filed";
  }

  WriteRequest req;
  req.request_header().request_handle() = 1;
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    // Null locale, non-null text: the invariant-locale form.
    wv.value().value() = Variant{LocalizedText{"", "Invariant"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto result = do_write(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault)
    << "the write was refused outright with " << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 1u);
  ASSERT_TRUE(result.response.results()[0].is_good())
    << "a null locale with non-null text is a defined write and was refused with "
    << result.response.results()[0].value();

  const auto afterWrite = varResult.value().read_attribute(AttributeId::DisplayName);
  const auto* stored = afterWrite.try_as<LocalizedText>();
  ASSERT_NE(stored, nullptr) << "the DisplayName Attribute is gone entirely after the write";

  const auto invariant = stored->text_for_locale("");
  ASSERT_TRUE(invariant.has_value())
    << "no invariant-locale entry was set; the DisplayName now reads back as "
    << static_cast<std::string_view>(stored->text()) << " in locale "
    << static_cast<std::string_view>(stored->locale());
  EXPECT_EQ(*invariant, String{"Invariant"});

  const auto english = stored->text_for_locale("en");
  ASSERT_TRUE(english.has_value()) << "the en translation was deleted by a write that named no locale";
  EXPECT_EQ(*english, String{"Pump"});

  const auto german = stored->text_for_locale("de");
  ASSERT_TRUE(german.has_value()) << "the de translation was deleted by a write that named no locale";
  EXPECT_EQ(*german, String{"Pumpe"});

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 Table 59, the `value` row: "Servers are allowed to impose additional data validations on the
// value independent of the encoding (e.g. having an image in GIF format in a ByteString). **In this
// case the Server shall return a Bad_TypeMismatch error if the validation fails.**"
//
// The clause is permissive about WHETHER a server validates and mandatory about the CODE once it does,
// so the obligation cannot be driven by writing a wrongly-typed value - that is the first sentence of
// the same row, a plain mismatch, and the previously bound test drove exactly that. The subject has to
// be a value whose **type is right and whose content is not**, and this SDK's interface for imposing such a
// validation is `ExternalValueSource::set_value_source`, the same interface a host uses to put a
// device behind a Variable.
//
// The stimulus is the specification's own example. The Variable's DataType is ImageGIF, whose wire
// representation is a ByteString, so both writes below are correctly typed and indistinguishable to
// the decoder; only the content differs. The GIF89a header is written first as the CONTROL - without
// it, a server that refused every write of this type would satisfy the negative arm while validating
// nothing - and the non-GIF bytes second.
//
// The handler answers `Bad_TypeMismatch`, which is what the clause requires of the validating server,
// so this asserts the service delivers that verdict to the client rather than rewriting it into a
// generic write failure or reporting the operation Good. That is the SDK's half of the obligation:
// the validation is the host's to impose, the status code is the service's to carry.
// @verifies AC-SVR-ATTR-WRITE-013-ADDITIONAL-VALIDATION
TEST(ReadServiceRequirements, ATTR_WRITE_013_ACorrectlyTypedValueThatFailsTheHostsValidationIsATypeMismatch)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());

  auto as = si->address_space();
  const NodeId imageNode{1, 130u};
  auto image = as.try_create_sync<VariableAccessor>(imageNode, NodeClass::Variable);
  ASSERT_TRUE(image.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  image.value().set_access_level(al);
  // ImageGIF is a subtype of ByteString, so the wire representation of a conforming and a
  // non-conforming write is identical and the decoder cannot separate them. That is the point.
  image.value().set_data_type(NodeId{DataTypeId::ImageGIF});
  {
    DataValue seed;
    seed.value() = Variant{ByteString(std::size_t{1}, uint8_t{0x00})};
    image.value().write_value_sync(std::move(seed));
  }

  // The host's additional validation: GIF87a/GIF89a magic, or the value is not an image.
  auto validated = std::make_shared<std::atomic<int>>(0);
  auto& proxied = image.value();
  auto* source = proxied->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                                const Node&,
                                                                const ReadValueId&,
                                                                std::function<void(DataValueResult)>
                                                                  done) { done(DataValue{}); },

    [validated](const ValueSource::WriteContext& /*context*/,
      const Node&,
      const WriteValue& write,
      std::function<void(ValueSource::WriteResult)>
        done)
    {
      validated->fetch_add(1);
      const auto* bytes = write.value().value().try_as<ByteString>();
      const bool isGif = bytes != nullptr && bytes->size() >= 6 &&
                         std::string(reinterpret_cast<const char*>(bytes->data()), 3) == "GIF";
      done(isGif ? ValueSource::WriteResult{ValueSource::Written{}}
                 : ValueSource::WriteResult{StatusCode{Status::BadTypeMismatch}});
    }));
  ASSERT_TRUE(installed.is_good());

  const auto bytesOf = [](std::string_view text)
  {
    return ByteString(std::vector<uint8_t>(text.begin(), text.end()));
  };

  const auto writeBytes = [&](ByteString content)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = imageNode;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(content)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // CONTROL: correctly typed AND passing the host's validation.
  {
    auto accepted = writeBytes(bytesOf("GIF89a"));
    ASSERT_FALSE(accepted.isServiceFault)
      << "a conforming image write faulted at service level: " << accepted.serviceResult.value();
    ASSERT_EQ(accepted.response.results().size(), 1u);
    EXPECT_TRUE(accepted.response.results()[0].is_good())
      << "the control write of a valid GIF was refused with " << accepted.response.results()[0].as_uint32()
      << ", so the negative arm below cannot distinguish a validating server from one that refuses "
         "every write of this type";
  }

  // The obligation: right type, wrong content.
  auto refused = writeBytes(bytesOf("<html>"));
  ASSERT_FALSE(refused.isServiceFault)
    << "a failed additional validation is a per-operation fault, not a service fault; the service "
       "result was "
    << refused.serviceResult.value();
  ASSERT_EQ(refused.response.results().size(), 1u);
  EXPECT_EQ(refused.response.results()[0].as_uint32(), static_cast<uint32_t>(Status::BadTypeMismatch))
    << "a correctly-typed ByteString whose content failed the host's validation was answered "
    << refused.response.results()[0].as_uint32()
    << " rather than Bad_TypeMismatch. Part 4 Table 59 fixes that code for exactly this case, and a "
       "client cannot otherwise tell 'your bytes are not a GIF' from a transient write failure";
  EXPECT_EQ(validated->load(), 2) << "the host's validation was not consulted on both writes";
}

// Read and Write run to the full timeoutHint (OPC 10000-4 section 7.33: the Server should wait at least
// that long) and then answer per item instead of failing the request: a finished item carries its result
// and one still running is answered Bad_Timeout, its outcome unknown (section 7.39.2). Re-decided API-10.6.
namespace
{

/// Holds every read or write the value source receives until the test lets it go.
struct HeldValueCalls
{
  std::mutex mutex;
  std::vector<std::function<void(DataValueResult)>> reads;
  std::vector<std::function<void(ValueSource::WriteResult)>> writes;

  void release_all()
  {
    std::vector<std::function<void(DataValueResult)>> heldReads;
    std::vector<std::function<void(ValueSource::WriteResult)>> heldWrites;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      heldReads = std::move(reads);
      heldWrites = std::move(writes);
    }
    for (auto& read : heldReads)
    {
      read(DataValue{Variant{int32_t{-1}}});
    }
    for (auto& write : heldWrites)
    {
      write(ValueSource::Written{});
    }
  }
};

/// Registers a second in-memory namespace on @p as, for the held Variable: the service reads or writes
/// the Values of one namespace in one call, so the held Variable is put where it holds only its own call.
/// The Session's Role is granted every permission in it, as in the fixture's own namespace.
uint16_t add_held_namespace(AddressSpace& as, boost::asio::any_io_executor ex)
{
  auto held = default_ns::Namespace::create("urn:test:partial-results:held", ex);
  RolePermissionType permission;
  permission.role_id() = ua::test_helpers::test_access_role_id();
  permission.permissions() = ua::test_helpers::all_permissions();
  held->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
  return as.add_namespace_sync(std::move(held));
}

}  // namespace

// @relation(AC-SVR-PARTIAL-RESULTS-003-READ-WRITE-PER-ITEM, scope=function)
TEST(ReadServiceRequirements, PartialResults_ReadAnswersEachItemAtTheTimeoutHint)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  auto as = si->address_space();
  const NodeId fastId{1, 9101u};
  const uint16_t heldIndex = add_held_namespace(as, ex);
  const NodeId slowId{heldIndex, 9102u};
  auto fast = make_readable_writable_variable(as, fastId);
  auto slow = make_readable_writable_variable(as, slowId);
  auto held = std::make_shared<HeldValueCalls>();
  ASSERT_TRUE(fast->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{Variant{int32_t{7}}}); }))
                .is_good());
  ASSERT_TRUE(slow->external_value_source()
                ->set_value_source(make_value_source(
                  [held](const ValueSource::ReadContext&,
                    const Node&,
                    const ReadValueId&,
                    std::function<void(DataValueResult)>
                      done)
                  {
                    const std::lock_guard<std::mutex> lock(held->mutex);
                    held->reads.push_back(std::move(done));
                  }))
                .is_good());

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = 300;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : {fastId, slowId})
  {
    ReadValueId nodeToRead;
    nodeToRead.node_id() = nodeId;
    nodeToRead.attribute_id() = utils::to_underlying(AttributeId::Value);
    request.nodes_to_read().payload().push_back(std::move(nodeToRead));
  }

  const auto started = std::chrono::steady_clock::now();
  auto result = do_read(si, ex, std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_FALSE(result.isServiceFault) << "the request must not fail as a whole";
  ASSERT_EQ(result.response.results().size(), 2u);
  const auto& finished = result.response.results()[0];
  EXPECT_TRUE(!finished.status().has_value() || finished.status()->is_good());
  ASSERT_TRUE(finished.value().is_int32());
  EXPECT_EQ(finished.value().as<int32_t>(), 7);
  const auto& unfinished = result.response.results()[1];
  ASSERT_TRUE(unfinished.status().has_value());
  EXPECT_EQ(*unfinished.status(), StatusCode{Status::BadTimeout});
  EXPECT_GE(elapsed, 300ms) << "Read waits the full timeoutHint before answering";

  held->release_all();  // the late answer has nowhere to go
  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-PARTIAL-RESULTS-003-READ-WRITE-PER-ITEM, scope=function)
TEST(ReadServiceRequirements, PartialResults_WriteAnswersEachItemAtTheTimeoutHint)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  auto as = si->address_space();
  const NodeId fastId{1, 9111u};
  const uint16_t heldIndex = add_held_namespace(as, ex);
  const NodeId slowId{heldIndex, 9112u};
  auto fast = make_readable_writable_variable(as, fastId);
  auto slow = make_readable_writable_variable(as, slowId);
  auto held = std::make_shared<HeldValueCalls>();
  ASSERT_TRUE(fast->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{}); },

                  [](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      done) { done(ValueSource::Written{}); }))
                .is_good());
  ASSERT_TRUE(slow->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{}); },

                  [held](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      done)
                  {
                    const std::lock_guard<std::mutex> lock(held->mutex);
                    held->writes.push_back(std::move(done));
                  }))
                .is_good());

  WriteRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = 300;
  for (const auto& nodeId : {fastId, slowId})
  {
    WriteValue writeValue;
    writeValue.node_id() = nodeId;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value().value() = Variant{int32_t{5}};
    request.nodes_to_write().payload().push_back(std::move(writeValue));
  }

  const auto started = std::chrono::steady_clock::now();
  auto result = do_write(si, ex, std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_FALSE(result.isServiceFault) << "the request must not fail as a whole";
  ASSERT_EQ(result.response.results().size(), 2u);
  EXPECT_TRUE(result.response.results()[0].is_good()) << result.response.results()[0].value();
  EXPECT_EQ(result.response.results()[1], StatusCode{Status::BadTimeout});
  EXPECT_GE(elapsed, 300ms) << "Write waits the full timeoutHint before answering";

  held->release_all();
  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// An item is recorded when it finishes, not when the request's join reaches it: a finished item that
// follows a slow one in the request still carries its value at the hint.
// @relation(AC-SVR-PARTIAL-RESULTS-003-READ-WRITE-PER-ITEM, scope=function)
TEST(ReadServiceRequirements, PartialResults_ReadKeepsAFinishedItemThatFollowsASlowOne)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  auto as = si->address_space();
  const NodeId fastId{1, 9121u};
  const uint16_t heldIndex = add_held_namespace(as, ex);
  const NodeId slowId{heldIndex, 9122u};
  auto fast = make_readable_writable_variable(as, fastId);
  auto slow = make_readable_writable_variable(as, slowId);
  auto held = std::make_shared<HeldValueCalls>();
  ASSERT_TRUE(fast->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{Variant{int32_t{7}}}); }))
                .is_good());
  ASSERT_TRUE(slow->external_value_source()
                ->set_value_source(make_value_source(
                  [held](const ValueSource::ReadContext&,
                    const Node&,
                    const ReadValueId&,
                    std::function<void(DataValueResult)>
                      done)
                  {
                    const std::lock_guard<std::mutex> lock(held->mutex);
                    held->reads.push_back(std::move(done));
                  }))
                .is_good());

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = 300;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : {slowId, fastId})
  {
    ReadValueId nodeToRead;
    nodeToRead.node_id() = nodeId;
    nodeToRead.attribute_id() = utils::to_underlying(AttributeId::Value);
    request.nodes_to_read().payload().push_back(std::move(nodeToRead));
  }

  const auto started = std::chrono::steady_clock::now();
  auto result = do_read(si, ex, std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_FALSE(result.isServiceFault) << "the request must not fail as a whole";
  ASSERT_EQ(result.response.results().size(), 2u);
  const auto& finished = result.response.results()[1];
  EXPECT_TRUE(!finished.status().has_value() || finished.status()->is_good());
  ASSERT_TRUE(finished.value().is_int32());
  EXPECT_EQ(finished.value().as<int32_t>(), 7);
  const auto& unfinished = result.response.results()[0];
  ASSERT_TRUE(unfinished.status().has_value());
  EXPECT_EQ(*unfinished.status(), StatusCode{Status::BadTimeout});
  EXPECT_GE(elapsed, 300ms) << "Read waits the full timeoutHint before answering";

  held->release_all();  // the late answer has nowhere to go
  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// As for Read: the finished item after a slow one keeps its status.
// @relation(AC-SVR-PARTIAL-RESULTS-003-READ-WRITE-PER-ITEM, scope=function)
TEST(ReadServiceRequirements, PartialResults_WriteKeepsAFinishedItemThatFollowsASlowOne)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  auto as = si->address_space();
  const NodeId fastId{1, 9131u};
  const uint16_t heldIndex = add_held_namespace(as, ex);
  const NodeId slowId{heldIndex, 9132u};
  auto fast = make_readable_writable_variable(as, fastId);
  auto slow = make_readable_writable_variable(as, slowId);
  auto held = std::make_shared<HeldValueCalls>();
  ASSERT_TRUE(fast->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{}); },

                  [](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      done) { done(ValueSource::Written{}); }))
                .is_good());
  ASSERT_TRUE(slow->external_value_source()
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         done) { done(DataValue{}); },

                  [held](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      done)
                  {
                    const std::lock_guard<std::mutex> lock(held->mutex);
                    held->writes.push_back(std::move(done));
                  }))
                .is_good());

  WriteRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = 300;
  for (const auto& nodeId : {slowId, fastId})
  {
    WriteValue writeValue;
    writeValue.node_id() = nodeId;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value().value() = Variant{int32_t{5}};
    request.nodes_to_write().payload().push_back(std::move(writeValue));
  }

  const auto started = std::chrono::steady_clock::now();
  auto result = do_write(si, ex, std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_FALSE(result.isServiceFault) << "the request must not fail as a whole";
  ASSERT_EQ(result.response.results().size(), 2u);
  EXPECT_EQ(result.response.results()[0], StatusCode{Status::BadTimeout});
  EXPECT_TRUE(result.response.results()[1].is_good()) << result.response.results()[1].value();
  EXPECT_GE(elapsed, 300ms) << "Write waits the full timeoutHint before answering";

  held->release_all();
  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A guard of COMP-ADDRSP-ACCESSOR-ROUTE-05 item 1: the IndexRange of a Read of a Variable's Value is applied
// once. The source sees the range and narrows its array to it; the Read answers exactly what the source did.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-05-A-RANGED-READ-OF-A-VALUE-IS-NARROWED-ONCE, scope=function)
TEST(NodeAccessorRoute, ARangedReadOfAValueIsNarrowedOnce)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestReadSessionInfo>(ex, make_allow_all());
  auto as = si->address_space();
  const NodeId nodeId{1, 100u};
  auto variable = make_readable_writable_variable(as, nodeId);
  ValueContextRecorder recorder;
  const auto installed =
    install_recording_value_source(variable, recorder, Variant{Array<int32_t>{10, 20, 30, 40}}, std::nullopt);
  ASSERT_TRUE(installed.is_good()) << installed.status_code().as_uint32();

  ReadRequest req = make_value_read(nodeId, 0.0);
  req.nodes_to_read().payload()[0].index_range() = "1:2";
  auto result = do_read(si, ex, std::move(req));
  ASSERT_FALSE(result.isServiceFault) << result.serviceResult.value();
  ASSERT_EQ(result.response.results().size(), 1u);
  const auto& value = result.response.results()[0];
  EXPECT_TRUE(!value.status().has_value() || value.status()->is_good())
    << "the Read answered " << value.status()->as_uint32();
  ASSERT_TRUE(value.value().is_array()) << "the Read answered no array";
  const auto& range = value.value().as<Array<int32_t>>();
  // Restated for NR-70 C3: the SDK no longer narrows a source's Value, so the range in the answer is the one
  // the source applied.
  ASSERT_EQ(static_cast<std::size_t>(range.size()), 2u) << "the Read did not answer exactly the range 1:2";
  EXPECT_EQ(range[0], 20);
  EXPECT_EQ(range[1], 30);

  const auto seen = recorder.snapshot();
  ASSERT_EQ(seen.size(), 1u) << "the handler was called " << seen.size() << " times";
  EXPECT_EQ(seen[0].indexRange, String{"1:2"});

  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}
