// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the Write service asks the namespace that owns a Node whether a RolePermissions update is one it can
// operate under: one validate_role_permissions_updates_async call per namespace per request, holding every
// RolePermissions item of the request for that namespace; each item keeps the namespace's own answer, and an
// accepted update is written as proposed.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_attribute_write_mask.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_node_accessor.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

#include "access_control_test_support.h"
#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

// A server with one recording namespace registered, and a Session on it allowed every permission,
// WriteRolePermissions included.
struct RolePermissionsHarness
{
  ~RolePermissionsHarness()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  shared_ptr<SessionInfoStub> sessionInfo;

  uint16_t setup(const shared_ptr<ua::Namespace>& nameSpace)
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    const auto index = server.address_space().add_namespace_sync(nameSpace);
    sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
    return index;
  }

  // A Variable whose WriteMask advertises RolePermissions.
  NodeAccessor create_variable(const NodeId& nodeId)
  {
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    NodeAccessor node = created.value();
    node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
    return node;
  }

  std::optional<WriteResponse> write(WriteRequest request)
  {
    auto promise = std::make_shared<std::promise<std::optional<WriteResponse>>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        std::optional<WriteResponse> answer;
        if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        {
          answer = std::move(*writeResponse);
        }
        promise->set_value(std::move(answer));
      });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Write did not complete";
      return std::nullopt;
    }
    return future.get();
  }
};

std::vector<RolePermissionType> one_entry(PermissionType permissions)
{
  RolePermissionType entry;
  entry.role_id() = ua::test_helpers::test_access_role_id();
  entry.permissions() = permissions;
  return {entry};
}

WriteRequest role_permissions_write_of(
  const std::vector<std::pair<NodeId, std::vector<RolePermissionType>>>& items)
{
  WriteRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().return_diagnostics() = 0xFFFF;
  for (const auto& [nodeId, permissions] : items)
  {
    WriteValue item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
    item.value() = DataValue{Variant{array_utils::copy_to_array_of_references(permissions)}};
    request.nodes_to_write().payload().push_back(std::move(item));
  }
  return request;
}

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-03-A-REFUSAL-KEEPS-ITS-STATUS-AND-DETAIL-PER-ITEM, scope=function)
TEST(RolePermissionsUpdates, ARefusalKeepsItsStatusAndDetailPerItem)
{
  RolePermissionsHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:role-permissions-updates:refusal", harness.threadPool.get_executor());
  const auto index = harness.setup(r);
  const NodeId a{index, 100u};
  const NodeId b{index, 101u};
  auto aNode = harness.create_variable(a);
  auto bNode = harness.create_variable(b);
  const auto aBefore = aNode.get_role_permissions();
  r->refuse_role_permissions_update(a,
    StatusCode{Status::BadNotSupported,
      ErrorDetail::build("RefusedByTheNamespace",
        "The test namespace refuses this RolePermissions update",
        "RolePermissionsUpdates")});
  r->reset();

  const auto proposed = one_entry(PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
  const auto response = harness.write(role_permissions_write_of({{a, proposed}, {b, proposed}}));

  const auto validations = r->calls(Member::ValidateRolePermissionsUpdates);
  ASSERT_EQ(validations.size(), 1U) << "validate_role_permissions_updates_async calls";
  EXPECT_EQ(sorted(validations.front().nodeIds), sorted({a, b})) << "the call holds both updates";

  ASSERT_TRUE(response.has_value());
  ASSERT_EQ(response->results().size(), 2U);
  const auto& aResult = response->results()[0];
  EXPECT_EQ(aResult.as_status(), Status::BadNotSupported) << to_string(aResult);
  ASSERT_NE(aResult.shared_detail(), nullptr);
  EXPECT_EQ(aResult.shared_detail()->code, "RefusedByTheNamespace");
  EXPECT_EQ(aNode.get_role_permissions(), aBefore) << "A's refused RolePermissions were written";
  EXPECT_EQ(response->results()[1].as_status(), Status::Good) << to_string(response->results()[1]);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-03-AN-ACCEPTED-UPDATE-IS-WRITTEN, scope=function)
TEST(RolePermissionsUpdates, AnAcceptedUpdateIsWritten)
{
  RolePermissionsHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:role-permissions-updates:accepted", harness.threadPool.get_executor());
  const auto index = harness.setup(r);
  const NodeId a{index, 100u};
  auto aNode = harness.create_variable(a);
  r->reset();

  const auto proposed = one_entry(PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
  const auto response = harness.write(role_permissions_write_of({{a, proposed}}));

  const auto validations = r->calls(Member::ValidateRolePermissionsUpdates);
  ASSERT_EQ(validations.size(), 1U) << "validate_role_permissions_updates_async calls";
  ASSERT_EQ(validations.front().nodeIds, std::vector<NodeId>{a});
  ASSERT_EQ(validations.front().proposals.size(), 1U);
  EXPECT_EQ(
    validations.front().proposals.front(), (std::optional<std::vector<RolePermissionType>>{proposed}));

  ASSERT_TRUE(response.has_value());
  ASSERT_EQ(response->results().size(), 1U);
  EXPECT_EQ(response->results()[0].as_status(), Status::Good) << to_string(response->results()[0]);
  EXPECT_EQ(aNode.get_role_permissions(), (std::optional<std::vector<RolePermissionType>>{proposed}));
}
