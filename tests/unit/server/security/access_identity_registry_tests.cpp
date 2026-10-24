// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "ua_access_identity_registry.h"
#include "ua_access_control.h"
#include "ua_default_namespace.h"
#include "ua_role_configuration.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

class ReleaseRecordingNamespace final : public default_ns::Namespace
{
public:
  explicit ReleaseRecordingNamespace(boost::asio::any_io_executor executor)
    : default_ns::Namespace{"urn:test:access-identities", std::move(executor)}
  {}

  void on_identity_released(const AccessIdentityKey& key) noexcept override
  {
    released.push_back(key);
  }

  std::vector<AccessIdentityKey> released;
};

class DeferredIdentityNamespace final : public default_ns::Namespace
{
public:
  explicit DeferredIdentityNamespace(boost::asio::any_io_executor executor)
    : default_ns::Namespace{"urn:test:access-identities:live", std::move(executor)}
  {}

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node*) const override
  {
    immediateQuestions.push_back(identity.key());
    return std::nullopt;
  }

  void effective_permissions_async(const RequestInfo&, shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    EXPECT_FALSE(nodes.has_value());
    asyncQuestions.push_back(identity->key());
    mPendingIdentity = std::move(identity);
    mPendingCallback = std::move(callback);
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return std::nullopt;
  }

  void on_identity_released(const AccessIdentityKey& key) noexcept override
  {
    released.push_back(key);
  }

  void complete_permissions()
  {
    ASSERT_TRUE(mPendingCallback);
    auto callback = std::move(mPendingCallback);
    auto retainedIdentity = std::move(mPendingIdentity);
    EffectivePermissionsResult result;
    result.items.emplace_back(PermissionType{PermissionType::Bit::AddNode});
    callback(std::move(result));
  }

  mutable std::vector<AccessIdentityKey> immediateQuestions;
  std::vector<AccessIdentityKey> asyncQuestions;
  std::vector<AccessIdentityKey> released;

private:
  shared_ptr<const AccessIdentity> mPendingIdentity;
  EffectivePermissionsCallback mPendingCallback;
};

std::shared_ptr<const UserIdentity> make_user(std::string role = "operator")
{
  auto user = std::make_shared<UserIdentity>();
  user->userId = "alice";
  user->displayName = "Alice";
  user->kind = UserTokenKind::IssuedToken;
  user->claims.emplace("role", std::move(role));
  return user;
}

std::shared_ptr<const EndpointSecurityContext> make_endpoint(
  MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt, std::string userTokenPolicyId = "issued")
{
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = mode;
  endpoint->securityPolicyId = SecurityPolicyId::Basic256Sha256;
  endpoint->endpointPolicyId = "listener/secure";
  endpoint->userTokenPolicyId = std::move(userTokenPolicyId);
  endpoint->clientApplicationUri = String{"urn:test:client"};
  endpoint->endpointUrl = String{"opc.tcp://localhost:4840"};
  endpoint->transportProfileUri = String{"http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"};
  return endpoint;
}

class AccessIdentityRegistryTest : public ::testing::Test
{
protected:
  AccessIdentityRegistryTest()
    : mAddressSpace{AddressSpace::create(String{"urn:test:server"}, mPool.get_executor())},
      mRecordingNamespace{std::make_shared<ReleaseRecordingNamespace>(mPool.get_executor())}
  {
    mAddressSpace.add_namespace_sync(mRecordingNamespace);
  }

  ~AccessIdentityRegistryTest() override
  {
    mAddressSpace.shutdown_async([](VoidResult) {});
    mPool.join();
  }

  boost::asio::thread_pool mPool{1};
  AddressSpace mAddressSpace;
  std::shared_ptr<ReleaseRecordingNamespace> mRecordingNamespace;
};

}  // namespace

// @relation(AC-SVR-AUTHZ-021-KEYS-ARE-DISTINCT-AND-NOT-REUSED, scope=function)
TEST(AccessIdentityKeyTest, ClaimSetSplitsIdentityAndKeysAreNotReused)
{
  boost::asio::thread_pool pool{1};
  AddressSpace addressSpace = AddressSpace::create(String{"urn:test:server"}, pool.get_executor());
  AccessIdentityRegistry registry{addressSpace.weak(), 10};
  auto first = registry.acquire(make_user("operator"), make_endpoint(), {});
  auto second = registry.acquire(make_user("engineer"), make_endpoint(), {});
  ASSERT_TRUE(first.is_good());
  ASSERT_TRUE(second.is_good());
  const AccessIdentityKey firstKey = first.value()->key();
  const AccessIdentityKey secondKey = second.value()->key();
  EXPECT_NE(firstKey, secondKey);

  first = AccessIdentityRegistry::IdentityResult{StatusCode{Status::BadInvalidState}};
  second = AccessIdentityRegistry::IdentityResult{StatusCode{Status::BadInvalidState}};

  auto replacement = registry.acquire(make_user("operator"), make_endpoint(), {});
  ASSERT_TRUE(replacement.is_good());
  EXPECT_NE(replacement.value()->key(), firstKey);
  EXPECT_NE(replacement.value()->key(), secondKey);

  replacement = AccessIdentityRegistry::IdentityResult{StatusCode{Status::BadInvalidState}};
  addressSpace.shutdown_async([](VoidResult) {});
  pool.join();
}

// @relation(AC-SVR-AUTHZ-021-EQUAL-CALLERS-POOL, scope=function)
TEST_F(AccessIdentityRegistryTest, EqualLiveCallersPoolUntilFinalRelease)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  std::vector<std::shared_ptr<const AccessIdentity>> callers;
  for (size_t i = 0; i < 5; ++i)
  {
    auto acquired = registry.acquire(make_user(), make_endpoint(), {});
    ASSERT_TRUE(acquired.is_good());
    callers.push_back(std::move(acquired).value());
  }

  const AccessIdentityKey sharedKey = callers.front()->key();
  for (const auto& caller : callers)
  {
    EXPECT_EQ(caller->key(), sharedKey);
  }
  callers.erase(callers.begin(), callers.end() - 1);
  EXPECT_TRUE(mRecordingNamespace->released.empty());
  callers.clear();
  ASSERT_EQ(mRecordingNamespace->released.size(), 1U);
  EXPECT_EQ(mRecordingNamespace->released.front(), sharedKey);
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-06-LAZY-IDENTITY-RELEASE, scope=function)
TEST_F(AccessIdentityRegistryTest, ExistingIdentityInitializesLiveNamespaceLazilyAndReleasesAfterUse)
{
  using namespace std::chrono_literals;

  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  auto acquired = registry.acquire(make_user(), make_endpoint(), {});
  ASSERT_TRUE(acquired.is_good());
  auto identity = std::move(acquired).value();
  const auto identityKey = identity->key();
  AccessControl accessControl{mAddressSpace, 5s};

  auto liveNamespace = std::make_shared<DeferredIdentityNamespace>(mPool.get_executor());
  const auto namespaceIndex = mAddressSpace.add_namespace_sync(liveNamespace);
  EXPECT_TRUE(liveNamespace->immediateQuestions.empty());
  EXPECT_TRUE(liveNamespace->asyncQuestions.empty());
  EXPECT_TRUE(liveNamespace->released.empty());

  std::promise<AccessControl::Verdict> promise;
  auto future = promise.get_future();
  accessControl.authorize_namespace_async(ua::RequestInfo{},
    identity,
    namespaceIndex,
    identity->endpoint(),
    [&promise](AccessControl::Verdict verdict) { promise.set_value(std::move(verdict)); });

  ASSERT_EQ(liveNamespace->immediateQuestions.size(), 1U);
  EXPECT_EQ(liveNamespace->immediateQuestions.front(), identityKey);
  ASSERT_EQ(liveNamespace->asyncQuestions.size(), 1U);
  EXPECT_EQ(liveNamespace->asyncQuestions.front(), identityKey);

  identity.reset();
  EXPECT_TRUE(liveNamespace->released.empty())
    << "the in-flight authorization must retain the identity until namespace use completes";

  liveNamespace->complete_permissions();
  const auto verdict = future.get();
  EXPECT_TRUE(verdict.permitted);
  ASSERT_EQ(liveNamespace->released.size(), 1U);
  EXPECT_EQ(liveNamespace->released.front(), identityKey);
}

// @relation(AC-SVR-AUTHZ-021-LIVE-POPULATION-IS-BOUNDED, scope=function)
TEST_F(AccessIdentityRegistryTest, LivePopulationCapRefusesDistinctCaller)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 1};
  auto retained = registry.acquire(make_user("operator"), make_endpoint(), {});
  ASSERT_TRUE(retained.is_good());
  const AccessIdentityKey retainedKey = retained.value()->key();

  auto refused = registry.acquire(make_user("engineer"), make_endpoint(), {});
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), Status::BadTooManySessions);
  ASSERT_NE(refused.shared_detail(), nullptr);

  retained = AccessIdentityRegistry::IdentityResult{StatusCode{Status::BadInvalidState}};
  auto admitted = registry.acquire(make_user("engineer"), make_endpoint(), {});
  ASSERT_TRUE(admitted.is_good());
  EXPECT_NE(admitted.value()->key(), retainedKey);
}

// @relation(AC-SVR-AUTHZ-005-SECURITY-MODE-SPLITS-IDENTITY, scope=function)
TEST_F(AccessIdentityRegistryTest, EndpointSecurityModeSplitsIdentity)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  auto unsecured = registry.acquire(make_user(), make_endpoint(MessageSecurityMode::None), {});
  auto encrypted = registry.acquire(make_user(), make_endpoint(MessageSecurityMode::SignAndEncrypt), {});
  ASSERT_TRUE(unsecured.is_good());
  ASSERT_TRUE(encrypted.is_good());
  EXPECT_NE(unsecured.value()->key(), encrypted.value()->key());
}

// @relation(AC-SVR-AUTHZ-021-TOKEN-POLICY-SPLITS-IDENTITY, scope=function)
TEST_F(AccessIdentityRegistryTest, UserTokenPolicySplitsIdentity)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  auto issued =
    registry.acquire(make_user(), make_endpoint(MessageSecurityMode::SignAndEncrypt, "issued-policy"), {});
  auto certificate = registry.acquire(
    make_user(), make_endpoint(MessageSecurityMode::SignAndEncrypt, "certificate-policy"), {});
  auto issuedAgain =
    registry.acquire(make_user(), make_endpoint(MessageSecurityMode::SignAndEncrypt, "issued-policy"), {});

  ASSERT_TRUE(issued.is_good());
  ASSERT_TRUE(certificate.is_good());
  ASSERT_TRUE(issuedAgain.is_good());
  EXPECT_NE(issued.value()->key(), certificate.value()->key());
  EXPECT_EQ(issued.value()->key(), issuedAgain.value()->key());
}

TEST_F(AccessIdentityRegistryTest, RoleConfigurationEpochSplitsIdentityAndCarriesRegisteredRoles)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  const NodeId grantedRole{0, 15644u};
  const NodeId secondRegisteredRole{0, 15656u};

  auto first = registry.acquire(make_user(), make_endpoint(), {grantedRole}, {grantedRole}, 11);
  auto changed =
    registry.acquire(make_user(), make_endpoint(), {grantedRole}, {grantedRole, secondRegisteredRole}, 12);

  ASSERT_TRUE(first.is_good());
  ASSERT_TRUE(changed.is_good());
  EXPECT_NE(first.value()->key(), changed.value()->key());
  EXPECT_EQ(first.value()->role_configuration_epoch(), 11U);
  EXPECT_EQ(changed.value()->role_configuration_epoch(), 12U);
  ASSERT_TRUE(changed.value()->registered_roles().has_value());
  const std::array expectedRoles{grantedRole, secondRegisteredRole};
  EXPECT_TRUE(std::ranges::equal(*changed.value()->registered_roles(), expectedRoles));
}

// @relation(AC-SVR-SECADMIN-027-ACTIVE-SESSION-ROLE-REFRESH, scope=function)
TEST_F(AccessIdentityRegistryTest, RefreshesAnEstablishedIdentityAfterRoleMutation)
{
  AccessIdentityRegistry registry{mAddressSpace.weak(), 10};
  RoleConfiguration roles;
  const NodeId protectedRole{1, 700u};
  IdentityMappingRuleType aliceRule;
  aliceRule.criteria_type() = IdentityCriteriaType::Role;
  aliceRule.criteria() = String{"operator"};

  RoleConfiguration::RoleDefinition definition;
  definition.roleId = protectedRole;
  definition.roleBit = 4;
  definition.identities = {aliceRule};
  ASSERT_TRUE(roles.add_role(std::move(definition)));

  auto user = make_user();
  auto endpoint = make_endpoint();
  auto initialEvaluation = roles.evaluate_access_identity(*user, *endpoint);
  auto initial = registry.acquire(user,
    endpoint,
    std::move(initialEvaluation.grantedRoles),
    std::move(initialEvaluation.registeredRoles),
    initialEvaluation.configurationEpoch);
  ASSERT_TRUE(initial.is_good());
  EXPECT_NE(std::ranges::find(initial.value()->granted_roles(), protectedRole),
    initial.value()->granted_roles().end());

  ASSERT_TRUE(roles.remove_identity_rule(protectedRole, aliceRule));
  auto revoked = registry.refresh(initial.value(), user, endpoint, roles);
  ASSERT_TRUE(revoked.is_good());
  EXPECT_NE(revoked.value()->key(), initial.value()->key());
  EXPECT_EQ(revoked.value()->role_configuration_epoch(), roles.epoch());
  EXPECT_EQ(std::ranges::find(revoked.value()->granted_roles(), protectedRole),
    revoked.value()->granted_roles().end());

  ASSERT_TRUE(roles.add_identity_rule(protectedRole, aliceRule).is_good());
  auto restored = registry.refresh(revoked.value(), user, endpoint, roles);
  ASSERT_TRUE(restored.is_good());
  EXPECT_NE(restored.value()->key(), revoked.value()->key());
  EXPECT_EQ(restored.value()->role_configuration_epoch(), roles.epoch());
  EXPECT_NE(std::ranges::find(restored.value()->granted_roles(), protectedRole),
    restored.value()->granted_roles().end());
}
