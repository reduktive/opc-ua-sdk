// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration test for the P3 NodeSet-import RolePermissions role-id
/// translation. A NodeSet is imported into a live, Part-18-wired server's address
/// space; a node guarded by RolePermissions that reference a role in a file-local
/// custom namespace is then read back over an encrypted, SecurityAdmin session.
///
/// The imported role id must carry the SERVER namespace index (the translate-at-
/// write-boundary fix), not the file-local index - otherwise the authorization
/// subsystem the server consults over the wire would never match the role node.
///
/// Falsifiability: the file-local index of the role namespace is 1; the test
/// asserts the server index differs (ASSERT_NE(.., 1)) before asserting the read
/// role id carries the server index, so an untranslated (file-local) id cannot pass.

#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_address_space.h"
#include "ua_built_in_authenticators.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_file_stream.h"
#include "ua_nodeset_import.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_role_permission_type.h"
#include "ua_session_attribute_services.h"
#include "ua_structure_factory.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace ns = ua::xml::nodeset;

namespace
{

constexpr string_view rolesUri = "urn:example:roles";

// D-R: NamespaceFactory is a callable - a lambda creating a default_ns namespace for the URI.
NamespaceFactory make_import_namespace_factory(boost::asio::any_io_executor executor)
{
  return [executor = std::move(executor)](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

/// Imports RolePermissionTranslationFixture into the server's address space and
/// grants SecurityAdmin to an authenticated UserName ("admin") so the guarded
/// node's RolePermissions Attribute is readable over the wire.
class RbacNodeSetImportFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    StructureFactory structureFactory;

    FileStream inputStream{"RolePermissionTranslationFixture.NodeSet2.xml"};
    inputStream.open_for_read();

    const EncodingLimits limits{100, 100};
    auto nodeSets = ns::Parser::parse(limits,
      inputStream,
      structureFactory,
      addressSpace.namespace_array(),
      addressSpace.server_array(),
      ns::Parser::GetDependentModelCallback{});
    ASSERT_EQ(nodeSets.size(), 1u);

    auto factory = make_import_namespace_factory(mServerThreadPool.executor());
    auto importer = ns::ImportEngine::create(limits, addressSpace, nodeSets, factory);
    importer->import_all_sync({}, {});

    mRolesNsIndex = addressSpace.namespace_array().get_namespace_index(rolesUri);
  }

  uint16_t mRolesNsIndex{0};
};

}  // namespace

TEST_F(RbacNodeSetImportFixture, ImportedCustomNamespaceRolePermissionCarriesServerIndex)
{
  ASSERT_NE(mRolesNsIndex, 0);
  // Falsifiability: the file-local index of urn:example:roles is 1; the server index must differ.
  ASSERT_NE(mRolesNsIndex, 1);

  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RpImportRead");

  const NodeId guardedObjectId{mRolesNsIndex, 5001u};
  auto resp = session.attributes().read_sync(
    ReadRequestBuilder{}.read(guardedObjectId).attribute(AttributeId::RolePermissions).build());

  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_FALSE(resp.results().empty());
  ASSERT_THAT(resp.results()[0], Good())
    << "SecurityAdmin must be able to read the imported node's RolePermissions Attribute";

  const auto& value = resp.results()[0].value();
  ASSERT_TRUE(value.is_array());
  const auto& arr = value.as<Array<RefStructure<Structure>>>();

  bool sawTranslatedCustomRole = false;
  for (const auto& element : arr.payload())
  {
    const auto* rolePermission = dynamic_cast<const RolePermissionType*>(element.get());
    ASSERT_NE(rolePermission, nullptr);
    const auto& roleId = rolePermission->role_id();
    if (roleId.id_type() == IdType::Numeric && roleId.identifier().get_numeric() == 100u)
    {
      // The custom-namespace role id must carry the SERVER index, never the file-local index 1.
      EXPECT_EQ(roleId.namespace_index(), mRolesNsIndex);
      sawTranslatedCustomRole = true;
    }
  }
  EXPECT_TRUE(sawTranslatedCustomRole)
    << "the imported custom-namespace role permission was not present / not translated";
}
