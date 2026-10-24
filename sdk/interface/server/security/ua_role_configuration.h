// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ROLE_CONFIGURATION_H
#define UA_ROLE_CONFIGURATION_H

/// @file
/// @brief Identity-to-role mapping used to construct immutable access identities.
/// @ingroup security

#include "ua_endpoint_type.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_server_configuration.h"
#include "ua_string.h"
#include "ua_server_authentication.h"
#include "ua_well_known_role_permissions.h"

#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <utility>
#include <vector>

namespace ua::server
{

class ServerImpl;

/// Identity-to-role mapping configuration used to commit immutable @ref AccessIdentity snapshots.
///
/// Owns the role definitions, the dense `uint64_t` role-bit slot assignment, and
/// the per-mutation epoch paired with each coherent access-identity evaluation.
///
/// Thread-safety: a `shared_mutex` guards the role list (shared on reads, unique
/// on mutations); the epoch is a separate atomic counter so the hot-path
/// staleness check needs no lock. All public methods are internally synchronised
/// and callable from any thread. The type is non-copyable and non-movable; share
/// it via `std::shared_ptr`, normally through `ServerComponents::roleConfiguration`.
/// @ingroup security
class RoleConfiguration
{
public:
  /// One declarative identity grant for a standard well-known Role.
  ///
  /// The SDK derives the Role Object NodeId and internal bit slot from @ref role. Most criteria
  /// types need no value; criteria-bearing types use @ref criteria.
  struct WellKnownRoleGrant
  {
    WellKnownRole role;  ///< Well-known Role to grant when the rule matches.
    IdentityCriteriaType criteriaType;  ///< Identity predicate used to grant the Role.
    String criteria;  ///< Optional predicate value, such as a user name or certificate thumbprint.

    /// @param wellKnownRole the well-known Role granted when the rule matches.
    /// @param identityCriteriaType the identity predicate that decides whether it matches.
    /// @param identityCriteria the predicate value, where the predicate takes one.
    WellKnownRoleGrant(WellKnownRole wellKnownRole, IdentityCriteriaType identityCriteriaType,
      String identityCriteria = {}) noexcept
      : role(wellKnownRole), criteriaType(identityCriteriaType), criteria(std::move(identityCriteria))
    {}
  };

  /// A single role: its node id, bit slot, identity rules, and access filters.
  ///
  /// A user is granted the role when its identity mapping rules match and the
  /// optional application/endpoint filters permit the request; @ref roleBit is
  /// then set in the granted-role bitmask returned by @ref evaluate_roles.
  struct RoleDefinition
  {
    /// Role node identifier (well-known roles use NS0 well-known IDs).
    NodeId roleId;

    /// Dense bit slot in the 64-bit granted-role bitmask.
    ///
    /// Must be unique across roles and within `[0, 63]`.
    uint8_t roleBit{0};

    /// Identity mapping rules; a user matching any one rule is granted the role.
    std::vector<IdentityMappingRuleType> identities;

    /// Optional application include/exclude filter.
    ///
    /// Evaluated as a pre-scan before the identity rules (Q-RBAC-4 fail-fast).
    /// An empty list disables the filter. Whether the listed URIs include or
    /// exclude is controlled by @ref applicationsExclude.
    std::vector<String> applications;

    /// Treat @ref applications as an exclude list rather than an include list.
    bool applicationsExclude{false};

    /// Optional endpoint include/exclude filter.
    ///
    /// Evaluated as a pre-scan alongside the application filter. An empty list
    /// disables the filter; @ref endpointsExclude selects include vs. exclude.
    /// Each `EndpointType` entry is a partial-match filter per Part 18 4.4.2:
    /// non-default fields (URL, SecurityMode, SecurityPolicyUri,
    /// TransportProfileUri) narrow the match; default-valued fields are ignored
    /// for comparison. Compared at request time against
    /// `EndpointSecurityContext::endpointUrl / mMessageSecurityMode /
    /// securityPolicyId / mTransportProfileUri`.
    std::vector<EndpointType> endpoints;

    /// Treat @ref endpoints as an exclude list rather than an include list.
    bool endpointsExclude{false};

    /// Whether Session assignment uses a vendor-specific configuration path.
    ///
    /// Published through the Role Object's optional `CustomConfiguration` Property. The SDK sets
    /// this for its opt-in authenticator-claim mapping because that assignment is outside the
    /// standard Role management Methods.
    bool customConfiguration{false};

    /// BrowseName of the Role's Object under the RoleSet Object; its name, with no locale, is also the
    /// Object's DisplayName.
    ///
    /// Required for a Role outside namespace 0 to be published. Start-up creates the Object of such a
    /// Role with this BrowseName; a Role without one, or whose BrowseName another child of the RoleSet
    /// Object already has (OPC 10000-18 4.2.2: unique within the RoleSet Object), is not created and is
    /// logged, and still grants its permissions. An Object that already exists at @ref roleId keeps its
    /// own BrowseName. The well-known Roles have theirs in namespace 0 and need none here; the AddRole
    /// Method records the BrowseName it builds.
    QualifiedName browseName;
  };

  /// Coherent Role snapshot committed into one access identity at activation.
  struct AccessEvaluation
  {
    std::vector<NodeId> grantedRoles;  ///< Roles this identity holds.
    std::vector<NodeId> registeredRoles;  ///< Every Role in configuration, granted or not.
    uint64_t configurationEpoch{0};  ///< Configuration generation both lists were read at.
  };

  /// Constructs an empty configuration with epoch 1 and no roles registered.
  RoleConfiguration() = default;

  RoleConfiguration(const RoleConfiguration&) = delete;
  RoleConfiguration& operator=(const RoleConfiguration&) = delete;
  RoleConfiguration(RoleConfiguration&&) = delete;
  RoleConfiguration& operator=(RoleConfiguration&&) = delete;

  /// Default destructor; completes the rule-of-five for the deleted copy/move set.
  ~RoleConfiguration() = default;

  /// Builds a Role configuration from a declarative list of well-known Role grants.
  ///
  /// Callers name policy only: Role, identity criterion type and its optional value. This helper
  /// derives the standard Role NodeId and dense bit slot, merges entries naming the same Role, and
  /// applies the same canonicalisation and duplicate checks as @ref add_identity_rule.
  ///
  /// @param grants Identity-to-Role grants to configure.
  /// @return A shareable Role configuration ready for ServerComponents::roleConfiguration.
  /// @throws UaException with `BadConfigurationError` when a Role value is invalid or a rule is
  ///         malformed or duplicated. The ErrorDetail retains the underlying rule failure.
  static std::shared_ptr<RoleConfiguration> from_well_known_grants(
    std::initializer_list<WellKnownRoleGrant> grants);

  /// Builds one shared identity rule across an explicit set of well-known Roles.
  ///
  /// This overload is the set-level form of the declarative builder above. It derives the same Role
  /// Object NodeIds and bit slots and applies the same rule validation, while allowing one borrowed
  /// Role set (for example @ref well_known_roles) to be reused when authoring matching namespace
  /// defaults. No Role receives special runtime treatment.
  ///
  /// @param roles        Well-known Roles that receive the shared rule, in declaration order.
  /// @param criteriaType Identity predicate shared by every Role.
  /// @param criteria     Optional predicate value, such as a user name or certificate thumbprint.
  /// @return A shareable Role configuration ready for ServerComponents::roleConfiguration.
  /// @throws UaException with `BadConfigurationError` when a Role value is invalid, a Role is
  ///         repeated, or the shared rule is malformed. The ErrorDetail retains the underlying cause.
  static std::shared_ptr<RoleConfiguration> from_well_known_grants(
    std::span<const WellKnownRole> roles, IdentityCriteriaType criteriaType, String criteria = {});

  /// Requests ordinary RolePermissions for registered Roles on the Part-18 Role-management surface.
  ///
  /// This is configuration-time policy authoring, not a runtime administrator list. Server startup
  /// materialises the requested grants on the RoleSet, RoleType, Role Objects and their protected
  /// Properties and Methods. Thereafter normal namespace authorization is the only source of truth;
  /// no service or Method handler consults this selection.
  ///
  /// The batch is atomic: every NodeId must be non-null and already registered in this
  /// RoleConfiguration before any request is retained. Repeated Roles are idempotent. Once a Server
  /// consumes the configuration the authoring selection is sealed while ordinary runtime Role
  /// mutations remain available through their existing APIs.
  ///
  /// @param roleIds Registered Role Object NodeIds to grant Role-management access.
  /// @return Good on success; otherwise `BadInvalidArgument`, `BadNodeIdUnknown` or `BadInvalidState`
  ///         with rich ErrorDetail. Never throws.
  [[nodiscard]] VoidResult grant_role_management_access(std::vector<NodeId> roleIds) noexcept;

  /// Replaces or inserts a role.
  ///
  /// The caller-supplied @ref RoleDefinition::roleBit is authoritative.
  /// Per-rule format discipline is applied to every entry in
  /// @ref RoleDefinition::identities (Thumbprint -> upper-case-hex-no-spaces,
  /// X509Subject -> Table-8 ordered); a rule that fails to canonicalise fails the
  /// call. Bumps @ref epoch on every successful call.
  ///
  /// @param definition Role to store (taken by value); its `roleId` keys the
  ///                   slot, overwriting an existing role with the same id.
  /// @return `true` if the role was stored; `false` if `roleBit` collides with
  ///         a different already-registered role or any identity rule fails to
  ///         canonicalise.
  [[nodiscard]] bool add_role(RoleDefinition definition);

  /// Removes a role by id.
  ///
  /// Bumps @ref epoch iff the role existed.
  ///
  /// @param roleId Node id of the role to remove.
  /// @return `true` if the role was removed; `false` if no role had that id.
  bool remove_role(const NodeId& roleId) noexcept;

  /// Seeds the well-known `Anonymous` (bit 0) and `AuthenticatedUser` (bit 1)
  /// roles with their default identity mapping rules.
  ///
  /// Anonymous receives both an `Anonymous`-criteria rule AND an
  /// `AuthenticatedUser`-criteria rule per Part 18 4.3 L408-414 (dual-rule);
  /// AuthenticatedUser receives the single `AuthenticatedUser`-criteria rule. The
  /// other well-known roles must be configured explicitly.
  ///
  /// @note Test-convenience helper that mirrors `seed_well_known_roles` in
  ///       `ua_server_impl.cpp` for the two roles that ship with default rules;
  ///       kept in sync via the
  ///       `RoleConfigurationTest.AddWellKnownDefaultsSeedsAnonymousAndAuthenticated`
  ///       pin.
  void add_well_known_defaults();

  /// Allocates a free bit slot in `[0, 63]` and registers a new custom role.
  ///
  /// Bumps @ref epoch on success. Applies the same per-rule format discipline as
  /// @ref add_role. Used by the `AddRole` Method on the `RoleSet` Object - the
  /// supplied definition's `roleBit` is overwritten with the allocated value.
  ///
  /// @param definition Role to register (taken by value); its `roleBit` is
  ///                   ignored and replaced with the allocated slot.
  /// @return The allocated bit slot on success, or `nullopt` if all 64 slots are
  ///         in use, the `roleId` is already registered, or any rule in
  ///         `identities` fails canonicalisation.
  std::optional<uint8_t> add_custom_role(RoleDefinition definition);

  // -- Per-rule mutators backing the RoleType management Methods.
  // -- Each takes the unique lock, mutates the role definition, bumps epoch.
  // -- All return `true` iff the change was applied (role exists; the
  // -- specific add/remove succeeded).

  /// Appends an `IdentityMappingRule` to a role.
  ///
  /// On success the stored rule is canonicalised (upper-case hex without spaces
  /// for Thumbprint; Table-8-ordered token sequence for X509Subject); the user
  /// side is normalised at compare time. The same canonicalisation runs inside
  /// @ref add_role / @ref add_custom_role, so every path that lands a rule in the
  /// configuration goes through the same discipline. Bumps @ref epoch on success.
  ///
  /// @param roleId Role to append to.
  /// @param rule   Identity mapping rule to append (taken by value).
  /// @return A success @ref VoidResult on success; otherwise an @ref ErrorDetail
  ///         carrying one of: `BadNotFound` (role not registered),
  ///         `BadEntryExists` (criteria_type + criteria pair already present), or
  ///         `BadInvalidArgument` (format-discipline failure for `Thumbprint`
  ///         with non-hex characters, or `X509Subject` containing a `"` in a
  ///         value or no parseable RDN tokens; Part 18 4.4.3 L766-769 +
  ///         L793-808). Never throws.
  VoidResult add_identity_rule(const NodeId& roleId, IdentityMappingRuleType rule);

  /// Removes an `IdentityMappingRule` from a role.
  ///
  /// Matches by criteria_type + criteria exact-string compare.
  ///
  /// @param roleId Role to remove the rule from.
  /// @param rule   Identity mapping rule to remove, matched by criteria type and
  ///               criteria string.
  /// @return `true` if the rule was removed; `false` if the role or rule was not
  ///         found.
  bool remove_identity_rule(const NodeId& roleId, const IdentityMappingRuleType& rule) noexcept;

  /// Appends a permitted-application URI to a role.
  ///
  /// @param roleId         Role to append the URI to.
  /// @param applicationUri Application URI to permit (taken by value).
  /// @return `true` if appended; `false` if the role is unknown or the URI is
  ///         already present (duplicates are rejected).
  bool add_application(const NodeId& roleId, String applicationUri) noexcept;

  /// Removes a permitted-application URI from a role.
  ///
  /// @param roleId         Role to remove the URI from.
  /// @param applicationUri Application URI to remove.
  /// @return `true` if removed; `false` if the role or URI was not found.
  bool remove_application(const NodeId& roleId, const String& applicationUri) noexcept;

  /// Appends an `EndpointType` filter entry to a role.
  ///
  /// @param roleId   Role to append the entry to.
  /// @param endpoint Endpoint filter entry to add (taken by value).
  /// @return `true` if appended; `false` if the role is unknown or an entry with
  ///         full 4-field equality is already present (duplicates are rejected).
  bool add_endpoint(const NodeId& roleId, EndpointType endpoint) noexcept;

  /// Removes an `EndpointType` filter entry from a role.
  ///
  /// Matches by full 4-field equality (mirrors the `EndpointType::operator==` the
  /// codec emits).
  ///
  /// @param roleId   Role to remove the entry from.
  /// @param endpoint Endpoint filter entry to remove, matched by full 4-field
  ///                 equality.
  /// @return `true` if removed; `false` if the role or entry was not found.
  bool remove_endpoint(const NodeId& roleId, const EndpointType& endpoint) noexcept;

  /// Replaces the applications include/exclude flag for a role.
  ///
  /// Backs the Write notifier on the `ApplicationsExclude` Variable (Part 18
  /// 4.4.1 carves this out as the one direct-Write Property).
  ///
  /// @param roleId  Role whose flag is updated.
  /// @param exclude `true` to treat the applications list as an exclude list;
  ///                `false` as an include list.
  /// @return `true` if the role exists and the flag was set; `false` otherwise.
  bool set_applications_exclude(const NodeId& roleId, bool exclude) noexcept;

  /// Replaces the endpoints include/exclude flag for a role.
  ///
  /// @param roleId  Role whose flag is updated.
  /// @param exclude `true` to treat the endpoints list as an exclude list;
  ///                `false` as an include list.
  /// @return `true` if the role exists and the flag was set; `false` otherwise.
  bool set_endpoints_exclude(const NodeId& roleId, bool exclude) noexcept;

  /// Resolves the granted-role bitmask for a `(user, security)` pair.
  ///
  /// For each role: applies the application include/exclude filter as a pre-scan,
  /// tests the role's `IdentityMappingRule`s (any match grants the role), and
  /// sets the role's `roleBit` in the returned mask if granted.
  ///
  /// @param user     Authenticated user identity to evaluate against the rules.
  /// @param security Endpoint security context the request arrived on; feeds the
  ///                 application/endpoint pre-scan filters.
  /// @return A bitmask with bit `roleBit` set for each granted role.
  /// @throws std::bad_alloc if the user-side normaliser for Thumbprint /
  ///         X509Subject criteria - which allocates a transient `std::string` per
  ///         compare - fails to allocate. This method is not `noexcept` for that
  ///         reason.
  uint64_t evaluate_roles(const UserIdentity& user, const EndpointSecurityContext& security) const;

  /// Resolves the Role NodeIds granted to a caller under the same rules as @ref evaluate_roles.
  ///
  /// @param user     Authenticated user identity to evaluate.
  /// @param security Endpoint security context used by application and endpoint filters.
  /// @return Granted Role NodeIds in configuration order.
  std::vector<NodeId> evaluate_role_ids(
    const UserIdentity& user, const EndpointSecurityContext& security) const;

  /// Resolves granted Roles and snapshots the complete registered Role set under one shared lock.
  ///
  /// This is the activation-path operation. Keeping both lists and the epoch coherent prevents a
  /// concurrent Role-management mutation from producing a caller identity whose diagnostic view
  /// combines two different configurations.
  ///
  /// @param user the authenticated user whose Roles are being resolved.
  /// @param security the endpoint's security context, which some criteria types test.
  /// @return the granted Roles, the registered Role set and the epoch all read together.
  AccessEvaluation evaluate_access_identity(
    const UserIdentity& user, const EndpointSecurityContext& security) const;

  /// Returns the NodeIds of every registered Role in configuration order.
  ///
  /// The snapshot is used when committing an access identity so an authorization denial can
  /// distinguish a Role absent from configuration from one that is registered but not granted.
  ///
  /// @return the NodeId of every registered Role, in configuration order.
  std::vector<NodeId> role_ids() const;

  /// Maps a role node id to its dense bit slot.
  ///
  /// @param roleId Node id of the role to look up.
  /// @return The role's bit slot, or `nullopt` if no role with that id is
  ///         registered.
  std::optional<uint8_t> role_bit(const NodeId& roleId) const noexcept;

  /// Returns the current configuration epoch, bumped on every mutation.
  ///
  /// Included in each `AccessEvaluation` and in the server's access-identity interning key, so a later
  /// activation after a Role mutation cannot reuse an identity evaluated against the older policy.
  /// Reads take no lock (lock-free atomic load).
  ///
  /// @return The current configuration epoch.
  uint64_t epoch() const noexcept
  {
    return mEpoch.load(std::memory_order_acquire);
  }

  /// Advances the epoch without mutating any Role, separating later access-identity evaluations from
  /// identities committed against the earlier policy.
  ///
  /// Used by the Part 18 2.4b per-Node `RolePermissions` Write gate: a
  /// successful Write changes per-Node permissions (not the granted-role
  /// bitmask), but the authorization outcome may change, so the epoch bump remains the configuration
  /// invalidation channel (SECADMIN-053).
  void bump_epoch() noexcept
  {
    mEpoch.fetch_add(1, std::memory_order_acq_rel);
  }

  /// Returns the number of roles currently registered.
  ///
  /// @return The number of registered roles.
  /// @note Test interface.
  size_t role_count() const noexcept;

  /// Returns a snapshot copy of a role definition by id.
  ///
  /// @param roleId Node id of the role to snapshot.
  /// @return A copy of the role definition, or `nullopt` if no role with that id
  ///         is registered.
  /// @note Test interface.
  std::optional<RoleDefinition> get_role(const NodeId& roleId) const noexcept;

  /// Returns a stable snapshot of every configured role.
  ///
  /// @return A copy of every registered role definition. A snapshot rather than a view, so it stays
  ///         valid and self-consistent while the configuration is concurrently modified.
  std::vector<RoleDefinition> roles() const;

private:
  friend class ServerImpl;

  /// Seals and snapshots the configuration-time Role-management authoring request.
  std::vector<NodeId> consume_role_management_access_roles();

  mutable std::shared_mutex mMutex;
  std::vector<RoleDefinition> mRoles;
  std::vector<NodeId> mRoleManagementAccessRoles;
  bool mRoleManagementAccessSealed{false};
  std::atomic<uint64_t> mEpoch{1};
};

}  // namespace ua::server

#endif  // UA_ROLE_CONFIGURATION_H
