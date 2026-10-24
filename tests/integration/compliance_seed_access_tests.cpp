// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Runs the compliance_test_server's own AddressSpaceSeed, not a copy of it, and asks the namespace it
// creates what the Roles the compliance server grants may do with a seeded node.
//
// The compliance server maps an anonymous Session to Observer. When the seed created its namespace with
// no default RolePermissions, every undecorated node granted nothing, and the CTT's anonymous Sessions
// were refused Bad_UserAccessDenied on every Read of the test nodes - so most conformance units stopped
// in their initialize script. The fixtures in compliance_helpers.h grant their own namespaces, which is
// why no other test saw it.

#include <gtest/gtest.h>

#include "address_space_seed.h"
#include "ua_test_server.h"

#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_authorization.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_access_identity_facts.h"
#include "ua_server_authentication.h"

#include <boost/asio/thread_pool.hpp>

#include <filesystem>
#include <unistd.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using ua::PermissionType;
using Bit = ua::PermissionType::Bit;

std::shared_ptr<const ua::AccessIdentity> identity_holding(std::vector<ua::NodeId> roles)
{
  return std::make_shared<const ua::AccessIdentity>(ua::AccessIdentityKey{1},
    std::move(roles),
    std::make_shared<const ua::UserIdentity>(),
    std::make_shared<const ua::EndpointSecurityContext>(),
    ua::String{"urn:test:ctt"});
}

/// The seed writes its file-transfer fixtures into the working directory; keep them out of the build tree.
class ScopedWorkingDirectory
{
public:
  ScopedWorkingDirectory()
    : mPrevious{std::filesystem::current_path()},
      mDirectory{
        std::filesystem::temp_directory_path() / ("compliance_seed_access_" + std::to_string(::getpid()))}
  {
    std::filesystem::create_directories(mDirectory);
    std::filesystem::current_path(mDirectory);
  }

  ~ScopedWorkingDirectory()
  {
    std::error_code ignored;
    std::filesystem::current_path(mPrevious, ignored);
    std::filesystem::remove_all(mDirectory, ignored);
  }

  ScopedWorkingDirectory(const ScopedWorkingDirectory&) = delete;
  ScopedWorkingDirectory& operator=(const ScopedWorkingDirectory&) = delete;

private:
  std::filesystem::path mPrevious;
  std::filesystem::path mDirectory;
};

class ComplianceSeedAccess : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();
    mSeed = std::make_unique<ua::compliance_test_server::AddressSpaceSeed>(
      mServer.server(), mSeedWorker.get_executor());
    auto addressSpace = mServer.server().address_space();
    const auto index = addressSpace.namespace_array().get_namespace_index(
      std::string{ua::compliance_test_server::complianceNamespaceUri});
    mNamespace = addressSpace.namespace_array().get_namespace(index);
    ASSERT_NE(mNamespace, nullptr);
    // The CTT's first read: `/Server Test/NodeIds/Static/All Profiles/Scalar/Bool`. The compliance namespace
    // holds its Nodes in memory, so the immediate lookup answers.
    const auto found =
      mNamespace->find_node(ua::NodeId{index, std::string{"Surface.Scalars.Boolean"}}, std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good());
    mNode = found->value();
    ASSERT_NE(mNode, nullptr);
  }

  void TearDown() override
  {
    mSeed.reset();
    mSeedWorker.join();
  }

  PermissionType permissions_for(std::vector<ua::NodeId> roles) const
  {
    const auto mask = mNamespace->effective_permissions(*identity_holding(std::move(roles)), mNode.get());
    EXPECT_TRUE(mask.has_value()) << "an in-memory namespace always answers synchronously";
    return mask.value_or(PermissionType{});
  }

  ScopedWorkingDirectory mWorkingDirectory;
  ua::test_helpers::TestServer mServer;
  boost::asio::thread_pool mSeedWorker{1};
  std::unique_ptr<ua::compliance_test_server::AddressSpaceSeed> mSeed;
  std::shared_ptr<ua::Namespace> mNamespace;
  std::shared_ptr<ua::Node> mNode;
};

}  // namespace

TEST_F(ComplianceSeedAccess, NamespacePublishesADefault)
{
  const auto defaults = mNamespace->default_role_permissions();
  ASSERT_TRUE(defaults.has_value());
  EXPECT_FALSE(defaults->empty());
}

TEST_F(ComplianceSeedAccess, ObserverMayBrowseReadWriteAndCallSeededNodes)
{
  const auto mask = permissions_for({ua::NodeId{ua::ObjectId::WellKnownRole_Observer}});
  for (const auto bit : {Bit::Browse, Bit::Read, Bit::Write, Bit::Call, Bit::ReadHistory, Bit::ReceiveEvents})
  {
    EXPECT_TRUE(mask.test(bit)) << "Observer lacks permission bit " << static_cast<int>(bit);
  }
}

TEST_F(ComplianceSeedAccess, OnlySecurityAdminMayWriteRolePermissions)
{
  EXPECT_FALSE(
    permissions_for({ua::NodeId{ua::ObjectId::WellKnownRole_Observer}}).test(Bit::WriteRolePermissions));
  EXPECT_TRUE(
    permissions_for({ua::NodeId{ua::ObjectId::WellKnownRole_SecurityAdmin}}).test(Bit::WriteRolePermissions));
}
