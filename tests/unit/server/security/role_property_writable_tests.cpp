// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for SVR-SECADMIN-026 - the `CurrentWrite` AccessLevel bit is
/// FALSE on the `Identities`, `Applications`, and `Endpoints` Properties of
/// every Role Object (Part 18 section 4.4.1 L635-639). These three Properties are
/// mutated only via their Methods (AddIdentity / AddApplication / AddEndpoint
/// etc.); a generic Attribute Write must be rejected. The sibling
/// `ApplicationsExclude` / `EndpointsExclude` Properties are the spec carve-out
/// (configured with the Write Service).
///
/// The invariant is supplied by the NodeSet/importer default (AccessLevel
/// defaults to CurrentRead only - CurrentWrite unset - for these Properties),
/// so these are verification tests with no backing code change. The wire-level
/// `Bad_NotWritable` rejection of a generic Write is exercised by the
/// integration mirror `server_security_role_property_current_write_false_integration`.

#include <gtest/gtest.h>

#include "ua_access_level_type.h"
#include "ua_application_configuration.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_server_impl.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <memory>
#include <optional>
#include <string_view>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

constexpr uint32_t anonymousRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous);
constexpr uint32_t operatorRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Operator);

std::shared_ptr<ServerImpl> create_part18_server(boost::asio::any_io_executor ex)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  frozen.server = std::move(sc);

  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::make_shared<RoleConfiguration>();
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

std::optional<NodeAccessor> find_child(
  AddressSpace& addressSpace, NodeAccessor& parent, std::string_view name)
{
  auto refs = parent.try_get_references_sync();
  if (!refs)
    return std::nullopt;
  for (const auto& ref : refs.value())
  {
    if (!ref.is_forward() || !ref.type_id().is_numeric())
      continue;
    const auto type = ref.type_id().identifier().get_numeric();
    if (type != static_cast<uint32_t>(ReferenceTypeId::HasProperty) &&
        type != static_cast<uint32_t>(ReferenceTypeId::HasComponent))
      continue;
    auto child = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (child && static_cast<std::string_view>(child.value().get_browse_name().name()) == name)
      return child.value();
  }
  return std::nullopt;
}

std::optional<bool> current_write_bit(
  AddressSpace& addressSpace, NodeAccessor& role, std::string_view property)
{
  auto child = find_child(addressSpace, role, property);
  if (!child)
    return std::nullopt;
  auto variable = child->as<VariableAccessor>();
  if (!variable)
    return std::nullopt;
  return variable->get_access_level().test(AccessLevelType::Bit::CurrentWrite);
}

class RolePropertyWritableTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer = create_part18_server(mPool.get_executor());
  }

  NodeAccessor anonymous_role()
  {
    ServerImplTestAccess access{*mServer};
    auto role = access.address_space().try_find_node_sync(NodeId{0, anonymousRoleId});
    EXPECT_TRUE(role);
    return role.value();
  }

  // Operator is one of the six configurable Roles that carry the full per-role
  // surface (Identities + Applications + Endpoints). The fixed Anonymous Role
  // carries only Identities in UA-1.05.06.
  NodeAccessor operator_role()
  {
    ServerImplTestAccess access{*mServer};
    auto role = access.address_space().try_find_node_sync(NodeId{0, operatorRoleId});
    EXPECT_TRUE(role);
    return role.value();
  }

  AddressSpace address_space()
  {
    return ServerImplTestAccess{*mServer}.address_space();
  }

  boost::asio::thread_pool mPool;
  std::shared_ptr<ServerImpl> mServer;
};

// @relation(SVR-SECADMIN-026, scope=function)
TEST_F(RolePropertyWritableTest, IdentitiesPropertyCurrentWriteIsFalse)
{
  auto addressSpace = address_space();
  auto role = anonymous_role();
  auto bit = current_write_bit(addressSpace, role, "Identities");
  ASSERT_TRUE(bit.has_value()) << "Anonymous role must expose an Identities Property";
  EXPECT_FALSE(*bit) << "Identities Property must have CurrentWrite FALSE (Part 18 section 4.4.1 L639)";
}

// @relation(SVR-SECADMIN-026, scope=function)
TEST_F(RolePropertyWritableTest, ApplicationsAndEndpointsPropertiesCurrentWriteIsFalse)
{
  auto addressSpace = address_space();
  // Anonymous carries only Identities in UA-1.05.06; use Operator, which has the
  // full Applications/Endpoints surface.
  auto role = operator_role();

  auto applications = current_write_bit(addressSpace, role, "Applications");
  ASSERT_TRUE(applications.has_value()) << "Operator role must expose an Applications Property";
  EXPECT_FALSE(*applications) << "Applications Property must have CurrentWrite FALSE";

  auto endpoints = current_write_bit(addressSpace, role, "Endpoints");
  ASSERT_TRUE(endpoints.has_value()) << "Operator role must expose an Endpoints Property";
  EXPECT_FALSE(*endpoints) << "Endpoints Property must have CurrentWrite FALSE";
}

}  // namespace
