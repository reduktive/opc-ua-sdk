// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Which of a namespace's permission forms access control asks: the immediate form taking the Node a lookup
// returned.

#include <gtest/gtest.h>

#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_role_permission_type.h"
#include "ua_server.h"
#include "ua_status_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include "../../address_space/scripted_node.h"
#include "access_control_test_support.h"
#include "per_item_join.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// DefaultRolePermissions granting every Role Browse and Read, so the Role model, asked, lets every Session
// read every Value whose own RolePermissions are absent.
std::vector<RolePermissionType> browse_and_read_for_every_role()
{
  PermissionType browseAndRead;
  browseAndRead.set(PermissionType::Bit::Browse);
  browseAndRead.set(PermissionType::Bit::Read);
  std::vector<RolePermissionType> grants;
  for (const NodeId& role : {ua::test_helpers::test_access_role_id(),
         NodeId{ObjectId::WellKnownRole_Anonymous},
         NodeId{ObjectId::WellKnownRole_AuthenticatedUser},
         NodeId{ObjectId::WellKnownRole_Observer},
         NodeId{ObjectId::WellKnownRole_Operator},
         NodeId{ObjectId::WellKnownRole_Engineer},
         NodeId{ObjectId::WellKnownRole_Supervisor},
         NodeId{ObjectId::WellKnownRole_ConfigureAdmin},
         NodeId{ObjectId::WellKnownRole_SecurityAdmin}})
  {
    RolePermissionType grant;
    grant.role_id() = role;
    grant.permissions() = browseAndRead;
    grants.push_back(std::move(grant));
  }
  return grants;
}

// A namespace that hands out Nodes of its own: every lookup form of the default namespace answers from
// resolve_here, so the immediate and the batched lookups both answer a handed-out Node for its NodeId. It
// publishes no default AccessRestrictions, and its DefaultRolePermissions grant every Role Browse and Read.
class OwnNodesNamespace final : public default_ns::Namespace
{
public:
  OwnNodesNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void hand_out(const NodeId& nodeId, shared_ptr<test::ScriptedNode> node)
  {
    const std::lock_guard lock{mOwnNodesMutex};
    mOwnNodes.insert_or_assign(nodeId, std::move(node));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return browse_and_read_for_every_role();
  }

  /// A handed-out Node's Value is its scripted Value; every other item's is read through the in-memory
  /// member.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    auto join = std::make_shared<test::PerItemJoin<DataValueResult>>(items.size(), std::move(complete));
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const ValueReadItem& item = items[index];
      if (shared_ptr<test::ScriptedNode> own = handed_out(item))
      {
        join->answer(index, own->read_value());
        continue;
      }
      const ValueReadItem one[]{item};
      default_ns::Namespace::read_values_async(request,
        caller,
        one,
        maxAge,
        setSourceTimestamp,
        [join, index](BatchResult<DataValueResult> read)
        { join->answer(index, test::only_item(std::move(read))); });
    }
    join->started();
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    {
      const std::lock_guard lock{mOwnNodesMutex};
      if (const auto found = mOwnNodes.find(nodeId); found != mOwnNodes.end())
      {
        return NodeResult{shared_ptr<Node>{found->second}};
      }
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  /// The handed-out Node @p item carries, or null when it carries another.
  shared_ptr<test::ScriptedNode> handed_out(const ValueReadItem& item)
  {
    const std::lock_guard lock{mOwnNodesMutex};
    const auto found = mOwnNodes.find(item.value.node_id());
    return found != mOwnNodes.end() && found->second.get() == &item.node ? found->second : nullptr;
  }

  std::mutex mOwnNodesMutex;
  std::map<NodeId, shared_ptr<test::ScriptedNode>> mOwnNodes;
};

// A Node of its own (not the in-memory Node, and keeping Node::attributes()) answering every Attribute as
// an ordinary readable Int32 Variable holding @p value, with AccessRestrictions and RolePermissions absent.
shared_ptr<test::ScriptedNode> readable_int32_variable(const NodeId& nodeId, int32_t value)
{
  auto node = std::make_shared<test::ScriptedNode>();
  node->answer_attribute(AttributeId::NodeId, Variant{nodeId});
  node->answer_attribute(AttributeId::NodeClass, Variant{static_cast<int32_t>(NodeClass::Variable)});
  node->answer_attribute(AttributeId::BrowseName, Variant{QualifiedName{nodeId.namespace_index(), "Own"}});
  node->answer_attribute(AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{"Own"}}});
  node->answer_attribute(AttributeId::Description, Variant{LocalizedText{LocaleId{"en"}, String{"Own"}}});
  node->answer_attribute(AttributeId::WriteMask, Variant{uint32_t{0}});
  node->answer_attribute(AttributeId::DataType, Variant{NodeId{DataTypeId::Int32}});
  node->answer_attribute(AttributeId::ValueRank, Variant{int32_t{-1}});
  const AccessLevelType readable{AccessLevelType::Bit::CurrentRead};
  node->answer_attribute(AttributeId::AccessLevel, Variant{readable.as_underlying_type()});
  node->answer_attribute(AttributeId::AccessLevelEx, Variant{uint32_t{readable.as_underlying_type()}});
  node->answer_attribute(AttributeId::MinimumSamplingInterval, Variant{double{0.0}});
  node->answer_attribute(AttributeId::Historizing, Variant{false});
  DataValue dataValue;
  dataValue.value() = Variant{value};
  node->answer_read_value(DataValueResult{std::move(dataValue)});
  return node;
}

// A namespace whose only permission override is the immediate form taking a Node: it answers the masks the
// test gives, and the default for any other Node. Its DefaultRolePermissions grant every Role Browse and
// Read, so the Role model, asked instead, would let every Session read every Value.
class ImmediateNodeFormNamespace final : public default_ns::Namespace
{
public:
  ImmediateNodeFormNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  using default_ns::Namespace::effective_permissions;

  void answer(const NodeId& nodeId, PermissionType permissions)
  {
    const std::lock_guard lock{mMutex};
    mAnswers.insert_or_assign(nodeId, permissions);
  }

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override
  {
    if (node != nullptr)
    {
      const std::lock_guard lock{mMutex};
      const NodeDescription description = node->attributes();
      if (const auto answer = mAnswers.find(description.node_id()); answer != mAnswers.end())
      {
        return answer->second;
      }
    }
    return default_ns::Namespace::effective_permissions(identity, node);
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return browse_and_read_for_every_role();
  }

private:
  mutable std::mutex mMutex;
  std::map<NodeId, PermissionType> mAnswers;
};

Status status_of(const DataValue& value)
{
  return value.status().has_value() ? value.status()->as_status() : Status::Good;
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-06-THE-IMMEDIATE-FORM-TAKING-A-NODE-IS-ASKED, scope=function)
TEST(AccessControlForms, TheImmediateFormTakingANodeIsAsked)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns = make_shared<ImmediateNodeFormNamespace>("urn:test:access-control-forms", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  const NodeId a{nsIndex, 100U};
  const NodeId b{nsIndex, 101U};
  for (const auto& [nodeId, value] : {std::pair{a, int32_t{1}}, std::pair{b, int32_t{2}}})
  {
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    ASSERT_TRUE(created.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    created.value().set_access_level(accessLevel);
    DataValue dataValue;
    dataValue.value() = Variant{value};
    created.value().write_value_sync(std::move(dataValue));
  }
  ns->answer(a, PermissionType{PermissionType::Bit::Browse});
  PermissionType readable;
  readable.set(PermissionType::Bit::Browse);
  readable.set(PermissionType::Bit::Read);
  readable.set(PermissionType::Bit::ReadRolePermissions);
  ns->answer(b, readable);

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[0].node_id() = a;
  request.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
  request.nodes_to_read()[1].node_id() = b;
  request.nodes_to_read()[1].attribute_id() = utils::to_underlying(AttributeId::Value);

  auto done = std::make_shared<std::promise<ReadResponse>>();
  auto answered = done->get_future();
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(request),
    executor,
    [done](Response response)
    {
      auto* read = dynamic_cast<ReadResponse*>(response.second.get());
      done->set_value(read != nullptr ? std::move(*read) : ReadResponse{});
    });
  ASSERT_EQ(answered.wait_for(3s), std::future_status::ready);
  const auto response = answered.get();

  ASSERT_EQ(response.results().size(), 2U);
  EXPECT_EQ(status_of(response.results()[0]), Status::BadUserAccessDenied)
    << "A's Value was read: the immediate form taking a Node was not asked";
  EXPECT_EQ(status_of(response.results()[1]), Status::Good);
  EXPECT_EQ(response.results()[1].value().as<int32_t>(), 2);

  service.reset();
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-06-A-SECURITY-ATTRIBUTE-OF-THE-WRONG-TYPE-IS-REFUSED, scope=function)
TEST(AccessControlForms, ASecurityAttributeOfTheWrongTypeIsRefused)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  // No answers are given, so every Node is decided by the Role model over default_role_permissions(), which
  // grants the Role R Browse and Read.
  auto ns = make_shared<ImmediateNodeFormNamespace>("urn:test:access-control-forms", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);
  const NodeId role = ua::test_helpers::test_access_role_id();

  const NodeId a{nsIndex, 200U};
  const NodeId b{nsIndex, 201U};
  std::map<NodeId, VariableAccessor> variables;
  for (const auto& nodeId : {a, b})
  {
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    ASSERT_TRUE(created.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    created.value().set_access_level(accessLevel);
    DataValue dataValue;
    dataValue.value() = Variant{int32_t{1}};
    created.value().write_value_sync(std::move(dataValue));
    variables.insert_or_assign(nodeId, created.value());
  }
  VariableAccessor& variableA = variables.at(a);
  VariableAccessor& variableB = variables.at(b);
  ua::test_helpers::set_test_node_permissions(variableA, PermissionType{PermissionType::Bit::Browse});
  ASSERT_TRUE(variableB.read_attribute(AttributeId::AccessRestrictions).empty());

  // A Session holding R reads A's Value through the Read service.
  std::vector<shared_ptr<AttributeServiceSet>> services;
  const auto readValueOfA = [&]() -> Status
  {
    ReadRequest request;
    request.request_header().request_handle() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Neither;
    request.nodes_to_read().resize(1);
    request.nodes_to_read()[0].node_id() = a;
    request.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
    auto done = std::make_shared<std::promise<ReadResponse>>();
    auto answered = done->get_future();
    std::vector<LocaleId> locales{"en"};
    services.push_back(AttributeServiceSet::create(sessionInfo,
      locales,
      0,
      std::move(request),
      executor,
      [done](Response response)
      {
        auto* read = dynamic_cast<ReadResponse*>(response.second.get());
        done->set_value(read != nullptr ? std::move(*read) : ReadResponse{});
      }));
    if (answered.wait_for(3s) != std::future_status::ready)
    {
      return Status::BadTimeout;
    }
    const auto response = answered.get();
    return response.results().size() == 1U ? status_of(response.results()[0]) : Status::BadUnexpectedError;
  };
  // The control: before the writes, A's own RolePermissions deny R the Read the namespace's default grants.
  EXPECT_EQ(readValueOfA(), Status::BadUserAccessDenied)
    << "A's Value was read before the writes: its RolePermissions do not govern it in this harness";

  const auto wroteRolePermissions =
    variableA.try_write_attribute_sync(AttributeId::RolePermissions, Variant{String{"Operator"}});
  const auto wroteAccessRestrictions =
    variableB.try_write_attribute_sync(AttributeId::AccessRestrictions, Variant{uint32_t{1}});

  EXPECT_EQ(wroteRolePermissions.status_code().as_status(), Status::BadTypeMismatch)
    << "A's RolePermissions were written as a String";
  EXPECT_EQ(wroteAccessRestrictions.status_code().as_status(), Status::BadTypeMismatch)
    << "B's AccessRestrictions were written as a UInt32";

  RolePermissionType browseOnly;
  browseOnly.role_id() = role;
  browseOnly.permissions() = PermissionType{PermissionType::Bit::Browse};
  EXPECT_EQ(variableA.get_role_permissions(), std::optional{std::vector{browseOnly}})
    << "A's RolePermissions no longer read as the entry granting R Browse only";
  EXPECT_TRUE(variableB.read_attribute(AttributeId::AccessRestrictions).empty())
    << "B's AccessRestrictions hold the UInt32 written";

  EXPECT_EQ(readValueOfA(), Status::BadUserAccessDenied)
    << "A's Value was read: its RolePermissions granting R Browse only no longer govern it";

  services.clear();
  variables.clear();
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// The control pair is A and B, Nodes of one implementation scripted alike except that A's AccessRestrictions
// read throws Bad_CommunicationError and B's answers absent.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-06-AN-UNREADABLE-ACCESS-RESTRICTIONS-DENIES, scope=function)
TEST(AccessControlForms, AnUnreadableAccessRestrictionsDenies)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns = make_shared<OwnNodesNamespace>("urn:test:access-control-forms", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  ASSERT_EQ(ns->default_access_restrictions(), std::nullopt);
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);
  ASSERT_EQ(sessionInfo->endpoint_security()->messageSecurityMode, MessageSecurityMode::None);

  const NodeId a{nsIndex, 300U};
  const NodeId b{nsIndex, 301U};
  auto variableA = readable_int32_variable(a, 1);
  variableA->refuse_attribute(AttributeId::AccessRestrictions, StatusCode{Status::BadCommunicationError});
  auto variableB = readable_int32_variable(b, 2);
  ns->hand_out(a, variableA);
  ns->hand_out(b, variableB);

  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[0].node_id() = a;
  request.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
  request.nodes_to_read()[1].node_id() = b;
  request.nodes_to_read()[1].attribute_id() = utils::to_underlying(AttributeId::Value);

  auto done = std::make_shared<std::promise<ReadResponse>>();
  auto answered = done->get_future();
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(request),
    executor,
    [done](Response response)
    {
      auto* read = dynamic_cast<ReadResponse*>(response.second.get());
      done->set_value(read != nullptr ? std::move(*read) : ReadResponse{});
    });
  ASSERT_EQ(answered.wait_for(3s), std::future_status::ready);
  const auto response = answered.get();

  ASSERT_EQ(response.results().size(), 2U);
  const Status statusOfA = status_of(response.results()[0]);
  EXPECT_TRUE(StatusCode{statusOfA}.is_bad())
    << "A's Value was read with " << to_string(statusOfA)
    << ": an AccessRestrictions that cannot be read was treated as unrestricted";
  EXPECT_TRUE(response.results()[0].value().empty())
    << "A's result carries a Value; its status is " << to_string(statusOfA);
  EXPECT_EQ(status_of(response.results()[1]), Status::Good)
    << "B's Value was not read: " << to_string(status_of(response.results()[1]));
  EXPECT_EQ(response.results()[1].value().as<int32_t>(), 2);
  std::cout << "A's status: " << to_string(statusOfA) << "\n";

  service.reset();
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
