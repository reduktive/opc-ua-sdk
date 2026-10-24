// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// The access-control members added to `ua::Namespace`, and the one claim that makes moving the interface
/// safe: **a namespace that overrides nothing computes the standard Role model.**
///
/// The operation arms evaluate one address space and one node operation by operation across every
/// `AccessOperation`, so a divergence in any single Table 37 bit fails. The remaining arms hold the
/// three states of `default_role_permissions()` and the C++ trap that makes the middle state easy to lose.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace_authorization.h"
#include "ua_node_accessor.h"
#include "ua_namespace_items.h"
#include "ua_object_id.h"
#include "ua_request_info.h"
#include "ua_role_permission_utils.h"
#include "ua_role_permissions.h"
#include "ua_security_policy.h"
#include "ua_server_authentication.h"

#include <boost/asio/thread_pool.hpp>

#include <array>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

constexpr std::array<AccessOperation, 14> everyOperation{AccessOperation::Read,
  AccessOperation::Write,
  AccessOperation::HistoryRead,
  AccessOperation::InsertHistory,
  AccessOperation::ModifyHistory,
  AccessOperation::DeleteHistory,
  AccessOperation::Browse,
  AccessOperation::Call,
  AccessOperation::TranslateBrowsePaths,
  AccessOperation::ReceiveEvents,
  AccessOperation::AddNodes,
  AccessOperation::DeleteNodes,
  AccessOperation::AddReferences,
  AccessOperation::DeleteReferences};

NodeId anonymous_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)};
}

NodeId authenticated_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_AuthenticatedUser)};
}

NodeId operator_role_id()
{
  return NodeId{1, 9001};
}

RolePermissionType make_permission(const NodeId& roleId, std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = PermissionType{bits};
  return entry;
}

std::shared_ptr<const UserIdentity> make_user(UserTokenKind kind, std::string name)
{
  auto user = std::make_shared<UserIdentity>();
  user->userId = std::move(name);
  user->displayName = user->userId;
  user->kind = kind;
  return user;
}

std::shared_ptr<const EndpointSecurityContext> make_security(
  MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt)
{
  auto security = std::make_shared<EndpointSecurityContext>();
  security->messageSecurityMode = mode;
  security->securityPolicyId = SecurityPolicyId::None;
  security->endpointPolicyId = "L/None";
  return security;
}

class NamespaceAccessControlDefaultsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mAddressSpace = std::make_unique<AddressSpace>(AddressSpace::create("urn:authz-defaults", mExecutor));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeAccessor make_node(uint32_t numericId, std::optional<std::vector<RolePermissionType>> permissions)
  {
    auto node = mAddressSpace->try_create_node_sync(NodeId{1, numericId}, NodeClass::Object, {}).value();
    if (permissions)
    {
      node.set_role_permissions(std::move(permissions));
    }
    return node;
  }

  ua::Namespace& test_namespace()
  {
    auto ns = mAddressSpace->namespace_array().get_namespace(static_cast<uint16_t>(1));
    EXPECT_NE(ns, nullptr);
    return *ns;
  }

  default_ns::Namespace& default_test_namespace()
  {
    auto* ns = dynamic_cast<default_ns::Namespace*>(&test_namespace());
    EXPECT_NE(ns, nullptr);
    return *ns;
  }

  void expect_operation_mapping(
    const AccessIdentity& identity, const NodeAccessor& node, const PermissionType& expected)
  {
    const auto mask = test_namespace().effective_permissions(identity, &*node);
    ASSERT_TRUE(mask.has_value()) << "The default never answers 'I cannot say' - it holds the node.";

    for (const auto operation : everyOperation)
    {
      const bool namespacePermits =
        mask->test(role_permission_utils::permission_bit_for_operation(operation));
      const bool expectedPermit =
        expected.test(role_permission_utils::permission_bit_for_operation(operation));
      EXPECT_EQ(namespacePermits, expectedPermit) << "operation index " << static_cast<int>(operation);
    }
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// @relation(AC-SVR-AUTHZ-023-ENGAGED-EMPTY-NODE-BATCH-IS-INVALID, scope=function)
TEST_F(NamespaceAccessControlDefaultsTest, EmptyAsyncNodeBatchIsInvalid)
{
  const auto identity = std::make_shared<const AccessIdentity>(AccessIdentityKey{100},
    std::vector<NodeId>{operator_role_id()},
    make_user(UserTokenKind::UserName, "alice"),
    make_security(),
    String{"urn:test:client"});
  std::optional<EffectivePermissionsResult> completed;

  test_namespace().effective_permissions_async(RequestInfo{},
    identity,
    std::vector<NodeId>{},
    [&](EffectivePermissionsResult result) { completed = std::move(result); });

  ASSERT_TRUE(completed.has_value());
  EXPECT_TRUE(completed->batchStatus.is_bad());
  EXPECT_EQ(completed->batchStatus.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(completed->batchStatus.shared_detail(), nullptr);
  EXPECT_EQ(completed->batchStatus.shared_detail()->code, "EmptyPermissionSubjectBatch");
  EXPECT_TRUE(completed->items.empty());
}

// A node carrying its own RolePermissions, decided both ways. The grant is deliberately partial - the
// Operator Role gets Read and Call and nothing else - so an implementation that returned "all bits" or
// "no bits" fails on the operations either side of the boundary rather than passing by accident.
TEST_F(NamespaceAccessControlDefaultsTest, ANamespaceOverridingNothingEvaluatesEveryOperation)
{
  const PermissionType expected{PermissionType::Bit::Read, PermissionType::Bit::Call};
  auto node = make_node(5000,
    std::vector<RolePermissionType>{
      make_permission(operator_role_id(), {PermissionType::Bit::Read, PermissionType::Bit::Call}),
      make_permission(authenticated_role_id(), {PermissionType::Bit::Browse})});

  const AccessIdentity identity{AccessIdentityKey{1},
    {operator_role_id()},
    make_user(UserTokenKind::UserName, "alice"),
    make_security(),
    String{""}};
  expect_operation_mapping(identity, node, expected);
}

// The same equivalence where the node carries nothing and the answer comes from the namespace default.
// This is the arm that would break if the immediate and asynchronous Namespace paths read different stores.
TEST_F(NamespaceAccessControlDefaultsTest, TheNamespaceDefaultFeedsEveryOperationEvaluation)
{
  default_test_namespace().set_namespace_defaults(
    std::vector<RolePermissionType>{
      make_permission(anonymous_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})},
    std::nullopt);

  auto node = make_node(5001, std::nullopt);
  const AccessIdentity identity{AccessIdentityKey{2},
    {anonymous_role_id()},
    make_user(UserTokenKind::Anonymous, "anon"),
    make_security(),
    String{""}};
  const PermissionType expected{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  expect_operation_mapping(identity, node, expected);
}

// An identity holding no Role at all gets an engaged, empty mask - not `nullopt`. The distinction is
// the whole of the deferred protocol: `nullopt` means "complete this decision asynchronously", while
// an in-memory namespace can answer immediately.
TEST_F(NamespaceAccessControlDefaultsTest, AnIdentityHoldingNoRoleGetsAnEmptyMaskAndNotIndeterminacy)
{
  auto node = make_node(
    5002, std::vector<RolePermissionType>{make_permission(operator_role_id(), {PermissionType::Bit::Read})});

  const AccessIdentity identity{
    AccessIdentityKey{2}, {}, make_user(UserTokenKind::Anonymous, "anon"), make_security(), String{""}};

  const auto mask = test_namespace().effective_permissions(identity, &*node);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(mask->as_underlying_type(), 0u);
}

// `return {};` on an `optional<vector<>>` yields nullopt, and nullopt is the vendor-model declaration
// that removes both Role Properties from the namespace's metadata Object. A namespace that overrides
// nothing must not make that declaration by accident, so the base is asserted to be ENGAGED and EMPTY.
TEST_F(NamespaceAccessControlDefaultsTest, TheBaseDefaultIsEngagedAndEmptyRatherThanAbsent)
{
  class BareNamespace final : public ua::Namespace
  {
  public:
    String uri() const override
    {
      return String{"urn:bare"};
    }

    void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
    {
      if (callback)
      {
        callback(VoidResult{});
      }
    }

    void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
      std::function<void(BatchResult<NodeResult>)> batchCallback) override
    {
      resolve_each(nodeIds,
        std::move(batchCallback),
        [](const NodeId&, std::function<void(NodeResult)> callback)
        { callback(NodeResult{StatusCode{Status::BadNodeIdUnknown}}); });
    }

    void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
      std::function<void(BatchResult<NodeReferencesResult>)> complete) override
    {
      complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
    }

    void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
      bool, std::function<void(BatchResult<DataValueResult>)> complete) override
    {
      complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
    }
  };

  BareNamespace bare;
  const auto defaults = bare.default_role_permissions();
  ASSERT_TRUE(defaults.has_value()) << "Engaged means 'this namespace uses the Role model'; absent "
                                       "means it does not, and that is only ever an explicit act.";
  EXPECT_TRUE(defaults->empty());

  EXPECT_FALSE(bare.default_access_restrictions().has_value());
  EXPECT_FALSE(bare.metadata_object().has_value());
}

// @relation(AC-SVR-AUTHZ-028-UNCONFIGURED-PUBLISHES-EMPTY-AND-HIDES, scope=function)
TEST_F(NamespaceAccessControlDefaultsTest, UnconfiguredNamespaceHidesOnlyUndecoratedNodes)
{
  const auto decoratedPermissions = std::vector<RolePermissionType>{
    make_permission(operator_role_id(), {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  auto decorated = make_node(5004, decoratedPermissions);
  auto undecorated = make_node(5005, std::nullopt);
  const AccessIdentity identity{AccessIdentityKey{4},
    {operator_role_id()},
    make_user(UserTokenKind::UserName, "operator"),
    make_security(),
    String{""}};

  const auto defaults = default_test_namespace().default_role_permissions();
  ASSERT_TRUE(defaults.has_value());
  EXPECT_TRUE(defaults->empty());

  const auto decoratedMask = default_test_namespace().effective_permissions(identity, &*decorated);
  ASSERT_TRUE(decoratedMask.has_value());
  EXPECT_TRUE(decoratedMask->test(PermissionType::Bit::Browse));
  EXPECT_TRUE(decoratedMask->test(PermissionType::Bit::Read));

  const auto undecoratedMask = default_test_namespace().effective_permissions(identity, &*undecorated);
  ASSERT_TRUE(undecoratedMask.has_value());
  EXPECT_EQ(undecoratedMask->as_underlying_type(), 0u);
}

// The two remaining states, held on the namespace the SDK actually ships.
TEST_F(NamespaceAccessControlDefaultsTest, TheThreeStatesOfTheNamespaceDefaultAreDistinguishable)
{
  // Unconfigured: the base answer, engaged and empty.
  EXPECT_TRUE(default_test_namespace().default_role_permissions().has_value());
  EXPECT_TRUE(default_test_namespace().default_role_permissions()->empty());

  // Configured with a value.
  default_test_namespace().set_namespace_defaults(
    std::vector<RolePermissionType>{make_permission(anonymous_role_id(), {PermissionType::Bit::Browse})},
    AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});

  const auto configured = default_test_namespace().default_role_permissions();
  ASSERT_TRUE(configured.has_value());
  ASSERT_EQ(configured->size(), 1U);
  EXPECT_EQ((*configured)[0].role_id(), anonymous_role_id());

  const auto restrictions = default_test_namespace().default_access_restrictions();
  ASSERT_TRUE(restrictions.has_value());
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-NO-GLOBAL-ADMIN, scope=function)
TEST_F(NamespaceAccessControlDefaultsTest, VendorSpecificModelMustProvideItsOwnUpdateValidator)
{
  default_test_namespace().set_namespace_defaults(std::nullopt, std::nullopt);
  const std::vector<RolePermissionsUpdate> updates{{NodeId{1, 5011U},
    std::vector<RolePermissionType>{
      make_permission(operator_role_id(), {PermissionType::Bit::WriteRolePermissions})}}};
  std::optional<BatchResult<VoidResult>> completed;
  test_namespace().validate_role_permissions_updates_async(
    RequestInfo{}, updates, [&completed](BatchResult<VoidResult> result) { completed = std::move(result); });

  ASSERT_TRUE(completed.has_value());
  ASSERT_EQ(completed->items.size(), 1U);
  EXPECT_EQ(completed->items[0].status_code().as_status(), Status::BadNotSupported);
  ASSERT_NE(completed->items[0].shared_detail(), nullptr);
  EXPECT_EQ(completed->items[0].shared_detail()->code, "RolePermissionsUpdateNotSupported");
}

// The vendor-model state, and the contract that goes with it: a namespace declaring it does not use
// the Role model is required to override `effective_permissions` too, because the base implementation
// IS the Role model. The base is asserted to deny rather than to grant, so forgetting the override
// fails closed.
TEST_F(NamespaceAccessControlDefaultsTest, DeclaringNoRoleModelDeniesRatherThanGrants)
{
  default_test_namespace().set_namespace_defaults(std::nullopt, std::nullopt);
  EXPECT_FALSE(default_test_namespace().default_role_permissions().has_value());

  auto node = make_node(5003, std::nullopt);
  const AccessIdentity identity{AccessIdentityKey{3},
    {anonymous_role_id()},
    make_user(UserTokenKind::Anonymous, "anon"),
    make_security(),
    String{""}};

  const auto mask = test_namespace().effective_permissions(identity, &*node);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(mask->as_underlying_type(), 0u);
}

// The identity key is what a namespace keys its own tables by, so its contract is tested rather than
// assumed: distinct values compare distinct, a default-constructed key names no identity, and the hash
// is usable in an unordered container.
TEST(AccessIdentityKeyTest, KeysAreComparableHashableAndDistinguishFromTheUnassignedOne)
{
  const AccessIdentityKey unassigned;
  const AccessIdentityKey first{1};
  const AccessIdentityKey alsoFirst{1};
  const AccessIdentityKey second{2};

  EXPECT_FALSE(unassigned.valid());
  EXPECT_TRUE(first.valid());
  EXPECT_EQ(first, alsoFirst);
  EXPECT_NE(first, second);
  EXPECT_NE(first, unassigned);

  std::unordered_map<AccessIdentityKey, int> table;
  table[first] = 10;
  table[second] = 20;
  table[alsoFirst] = 11;
  EXPECT_EQ(table.size(), 2U);
  EXPECT_EQ(table[first], 11);
}

// The identity carries the Roles and the client-supplied application URI the Role mapping partitions
// on; the two opaque handles are held, not copied, so a namespace deciding its own way can reach them.
TEST(AccessIdentityTest, CarriesTheRolesAndTheFactsTheMappingReads)
{
  auto user = make_user(UserTokenKind::UserName, "alice");
  auto security = make_security(MessageSecurityMode::Sign);

  const AccessIdentity identity{AccessIdentityKey{7},
    {anonymous_role_id(), operator_role_id()},
    user,
    security,
    String{"urn:client:acme"}};

  EXPECT_EQ(identity.key(), AccessIdentityKey{7});
  ASSERT_EQ(identity.granted_roles().size(), 2U);
  EXPECT_EQ(identity.granted_roles()[0], anonymous_role_id());
  EXPECT_EQ(identity.application_uri(), "urn:client:acme");
  EXPECT_EQ(identity.user().userId, "alice");
  EXPECT_EQ(identity.endpoint().messageSecurityMode, MessageSecurityMode::Sign);
}
