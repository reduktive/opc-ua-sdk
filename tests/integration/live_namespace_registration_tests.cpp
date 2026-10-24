// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "compliance_helpers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_localized_text.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_session_attribute_services.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

constexpr string_view liveNodeNamespaceUri{"urn:test:live-namespace:node"};
constexpr string_view liveMonitorNamespaceUri{"urn:test:live-namespace:monitor"};
constexpr uint32_t liveVariableIdentifier{8100};
constexpr int32_t liveVariableValue{8675309};
constexpr uint32_t namespaceArrayClientHandle{47};

std::optional<std::vector<std::string>> namespace_array_from(const DataValue& value)
{
  if ((value.status().has_value() && value.status()->is_bad()) || !value.value().is_array_of_string())
  {
    return std::nullopt;
  }

  std::vector<std::string> result;
  for (const auto& uri : value.value().as<Array<String>>())
  {
    result.emplace_back(static_cast<string_view>(uri));
  }
  return result;
}

std::optional<std::vector<std::string>> read_namespace_array(Session& session)
{
  auto response = session.attributes().try_read_sync(read_value(NodeId{VariableId::Server_NamespaceArray}));
  if (response.is_bad() || response.value().results().size() != 1U)
  {
    return std::nullopt;
  }
  return namespace_array_from(response.value().results()[0]);
}

std::optional<std::vector<std::string>> namespace_array_from(
  const DataChangeNotification& notification, uint32_t clientHandle)
{
  for (const auto& item : notification.monitored_items())
  {
    if (item.client_handle() == clientHandle)
    {
      return namespace_array_from(item.value());
    }
  }
  return std::nullopt;
}

class LiveNamespaceRegistration : public ComplianceWithSession
{
protected:
  shared_ptr<default_ns::Namespace> make_readable_namespace(string_view uri)
  {
    auto nameSpace = default_ns::Namespace::create(uri, mServer.thread_pool().executor());
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() = all_permissions();
    nameSpace->set_namespace_defaults(
      std::vector<RolePermissionType>{std::move(anonymousPermissions)}, std::nullopt);
    return nameSpace;
  }
};

}  // namespace

// @relation(AC-SVR-BASE-047-NAMESPACEARRAY-APPEND-ONLY, scope=function)
// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-01-PERMANENT-PREFIX, scope=function)
TEST_F(LiveNamespaceRegistration, AddWhileSessionActivePreservesPrefixAndUsesNode)
{
  auto before = read_namespace_array(*mSession);
  ASSERT_TRUE(before.has_value());
  ASSERT_FALSE(before->empty());

  auto addressSpace = mServer.server().address_space();
  auto nameSpace = make_readable_namespace(liveNodeNamespaceUri);
  const auto namespaceIndex = addressSpace.add_namespace_sync(nameSpace);
  ASSERT_EQ(namespaceIndex, before->size());

  const NodeId variableId{namespaceIndex, liveVariableIdentifier};
  auto node = addressSpace.create_node_sync(variableId, NodeClass::Variable);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_browse_name(QualifiedName{namespaceIndex, "LiveVariable"});
  variable->set_display_name(LocalizedText{"", "LiveVariable"});
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->write_value_sync(liveVariableValue);
  variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

  auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
  objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, variableId);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}}, false);

  auto servedResponse = mSession->attributes().try_read_sync(read_value(variableId));
  ASSERT_TRUE(servedResponse.is_good()) << servedResponse.status_code().value();
  ASSERT_EQ(servedResponse.value().results().size(), 1U);
  const auto& served = servedResponse.value().results()[0];
  ASSERT_TRUE(!served.status().has_value() || served.status()->is_good());
  const auto* servedValue = served.value().try_as<int32_t>();
  ASSERT_NE(servedValue, nullptr);
  EXPECT_EQ(*servedValue, liveVariableValue);

  auto after = read_namespace_array(*mSession);
  ASSERT_TRUE(after.has_value());
  ASSERT_EQ(after->size(), before->size() + 1U);
  EXPECT_TRUE(std::equal(before->begin(), before->end(), after->begin()));
  EXPECT_EQ(after->back(), liveNodeNamespaceUri);
}

// @relation(AC-SVR-BASE-047-NAMESPACEARRAY-APPEND-ONLY, scope=function)
TEST_F(LiveNamespaceRegistration, ExistingNamespaceArrayMonitorReceivesAppend)
{
  auto before = read_namespace_array(*mSession);
  ASSERT_TRUE(before.has_value());

  const auto subscription = create_subscription_with_monitored_item(*mSession,
    NodeId{VariableId::Server_NamespaceArray},
    {.publishingInterval = 25.0, .lifetimeCount = 120, .keepAliveCount = 20},
    {.clientHandle = namespaceArrayClientHandle, .samplingInterval = 25.0, .queueSize = 4});
  ASSERT_NE(subscription.subscriptionId, 0U);
  ASSERT_NE(subscription.monitoredItemId, 0U);

  auto initial = wait_for_publish(
    *mSession,
    [subscriptionId = subscription.subscriptionId, expected = *before](const PublishResponse& response)
    {
      if (response.subscription_id() != subscriptionId)
      {
        return false;
      }
      const auto* change = as_data_change(response);
      return change != nullptr && namespace_array_from(*change, namespaceArrayClientHandle) ==
                                    std::optional<std::vector<std::string>>{expected};
    },
    3s);
  ASSERT_TRUE(initial.has_value()) << "the monitored item did not report its initial NamespaceArray";

  auto addressSpace = mServer.server().address_space();
  const auto namespaceIndex =
    addressSpace.add_namespace_sync(make_readable_namespace(liveMonitorNamespaceUri));
  ASSERT_EQ(namespaceIndex, before->size());

  auto expected = *before;
  expected.emplace_back(liveMonitorNamespaceUri);
  auto changed = wait_for_data_change_with_ack(
    *mSession,
    subscription.subscriptionId,
    initial->notification_message().sequence_number(),
    [expected](const DataChangeNotification& notification)
    {
      return namespace_array_from(notification, namespaceArrayClientHandle) ==
             std::optional<std::vector<std::string>>{expected};
    },
    3s);
  ASSERT_TRUE(changed.has_value())
    << "the existing monitored item did not report the committed NamespaceArray append";
  EXPECT_EQ(namespace_array_from(*changed, namespaceArrayClientHandle),
    std::optional<std::vector<std::string>>{expected});

  delete_subscription(*mSession, subscription.subscriptionId);
}
