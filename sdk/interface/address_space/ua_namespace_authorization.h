// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The access identity a namespace is asked about and the effective-permission completion shape.
/// @ingroup address_space

#ifndef UA_NAMESPACE_AUTHORIZATION_H
#define UA_NAMESPACE_AUTHORIZATION_H

#include "ua_access_identity_facts.h"
#include "ua_defines.h"
#include "ua_node_id.h"
#include "ua_permission_type.h"
#include "ua_result.h"
#include "ua_string.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace ua
{

/// Identifies an access identity for as long as it is live.
///
/// Opaque, stable for the identity's lifetime, never reused within a server, equality-comparable and
/// hashable - which is the whole of its contract, because its only purpose is to let a namespace key
/// its own tables by the caller it was asked about and drop the row when
/// @ref Namespace::on_identity_released names it.
///
/// A namespace shall not read anything into the value: it is a server-assigned token, not an index,
/// and two servers in one process assign from separate sequences.
///
/// @ingroup address_space
class AccessIdentityKey
{
public:
  /// Constructs the key no live identity ever carries, so a default-constructed key compares equal to
  /// no issued one. Present so the key can sit in a container slot before it is assigned.
  AccessIdentityKey() noexcept = default;

  /// Constructs a key over a server-assigned token.
  ///
  /// @param value Non-zero token; the server's identity table is the only thing that may assign one.
  explicit AccessIdentityKey(uint64_t value) noexcept : mValue{value}
  {}

  /// Whether this key names an identity at all.
  ///
  /// @return `true` iff the key was assigned rather than default-constructed.
  bool valid() const noexcept
  {
    return mValue != 0;
  }

  /// The opaque token, for hashing and for correlating a log line with a key.
  ///
  /// @return The assigned token, or zero for a default-constructed key.
  uint64_t value() const noexcept
  {
    return mValue;
  }

  /// Compares two keys by value.
  /// @param lhs Left-hand key.
  /// @param rhs Right-hand key.
  /// @return `true` when both name the same identity.
  friend bool operator==(const AccessIdentityKey& lhs, const AccessIdentityKey& rhs) noexcept
  {
    return lhs.mValue == rhs.mValue;
  }

  /// Compares two keys by value.
  /// @param lhs Left-hand key.
  /// @param rhs Right-hand key.
  /// @return `true` when they name different identities.
  friend bool operator!=(const AccessIdentityKey& lhs, const AccessIdentityKey& rhs) noexcept
  {
    return !(lhs == rhs);
  }

private:
  uint64_t mValue{0};
};

/// The equivalence class of callers a namespace is asked about.
///
/// **Not a Session.** Several sessions of one user, on one endpoint, with one application URI and one
/// claim set are one identity and are prepared once; the same user on an unsecured and on an encrypted
/// endpoint are two, because Part 18 4.4.1 compares Endpoint settings when granting Roles, so the two
/// can hold different Roles and must not share an answer.
///
/// The SDK keeps an identity alive from the moment it is first named until the last caller mapping to
/// it has gone, and issues no call naming it outside that window. A namespace may therefore hold the
/// key - never the object - in its own tables and rely on @ref Namespace::on_identity_released to tell
/// it when the row is dead.
///
/// @ingroup address_space
class AccessIdentity
{
public:
  /// Assembles an identity. Called by the server at the one commit point where a session's identity
  /// becomes final; a namespace receives identities, it does not build them.
  ///
  /// @param key            The server-assigned key, already unique among live identities.
  /// @param grantedRoles   Part-18 Role NodeIds granted to this identity; may be empty.
  /// @param user           The authenticated principal; non-null, and outlives this object.
  /// @param endpoint       The negotiated endpoint security context; non-null, and outlives this object.
  /// @param applicationUri The calling client's application URI, copied because the address-space layer
  ///                       cannot see inside @p endpoint.
  AccessIdentity(AccessIdentityKey key, std::vector<NodeId> grantedRoles, shared_ptr<const UserIdentity> user,
    shared_ptr<const EndpointSecurityContext> endpoint, String applicationUri) noexcept
    : mKey{key}, mGrantedRoles{std::move(grantedRoles)}, mUser{std::move(user)},
      mEndpoint{std::move(endpoint)}, mApplicationUri{std::move(applicationUri)}
  {}

  /// Assembles an identity with a coherent snapshot of every configured Role.
  ///
  /// This is the server activation path. The five-argument overload remains useful to namespaces and
  /// focused tests that do not have a RoleConfiguration; in that shape unknown-Role diagnostics are
  /// unavailable and authorization retains the ordinary `RoleNotGranted` cause.
  ///
  /// @param key The interning key for this identity.
  /// @param grantedRoles The Roles the identity holds.
  /// @param registeredRoles Every Role in configuration, granted or not.
  /// @param user The authenticated user the identity was activated for.
  /// @param endpoint The endpoint security context the Session activated over.
  /// @param applicationUri The client application URI the Session presented.
  /// @param roleConfigurationEpoch The RoleConfiguration generation the snapshots were read at;
  ///        zero when the identity was built without one.
  AccessIdentity(AccessIdentityKey key, std::vector<NodeId> grantedRoles, std::vector<NodeId> registeredRoles,
    shared_ptr<const UserIdentity> user, shared_ptr<const EndpointSecurityContext> endpoint,
    String applicationUri, uint64_t roleConfigurationEpoch = 0) noexcept
    : mKey{key}, mGrantedRoles{std::move(grantedRoles)}, mRegisteredRoles{std::move(registeredRoles)},
      mRoleConfigurationKnown{true}, mUser{std::move(user)}, mEndpoint{std::move(endpoint)},
      mApplicationUri{std::move(applicationUri)}, mRoleConfigurationEpoch{roleConfigurationEpoch}
  {}

  /// The key that names this identity for as long as it is live.
  ///
  /// @return The key; stable, and never reissued once the identity is released.
  const AccessIdentityKey& key() const noexcept
  {
    return mKey;
  }

  /// The Part-18 Roles granted to this identity, as NodeIds.
  ///
  /// NodeIds rather than a bit mask is what keeps the standard Role model evaluable in the
  /// address-space layer with no Part-18 dependency: a namespace tests membership of a node's
  /// `RolePermissions` Role against this span and needs to know nothing about role configuration.
  ///
  /// @return The granted Roles, in configuration order; may be empty. Valid while this object is.
  std::span<const NodeId> granted_roles() const noexcept
  {
    return mGrantedRoles;
  }

  /// Returns the complete registered Role set captured with @ref granted_roles.
  ///
  /// `nullopt` means the identity was constructed without a RoleConfiguration snapshot, not that the
  /// configuration was empty. An engaged empty span means the server authoritatively had no Roles.
  ///
  /// @return Every registered Role, or `nullopt` when no RoleConfiguration snapshot was taken.
  std::optional<std::span<const NodeId>> registered_roles() const noexcept
  {
    if (!mRoleConfigurationKnown)
    {
      return std::nullopt;
    }
    return std::span<const NodeId>{mRegisteredRoles};
  }

  /// The authenticated principal - kind, id and claims - for a namespace deciding its own way.
  ///
  /// @return The principal. Valid while this object is.
  const UserIdentity& user() const noexcept
  {
    return *mUser;
  }

  /// The calling client's verified application URI.
  ///
  /// On an authenticated channel this was matched to a URI SAN in the client certificate. It is empty on
  /// an unsecured endpoint; an unverified ApplicationDescription claim never enters authorization facts.
  ///
  /// @return The URI, possibly empty. Valid while this object is.
  std::string_view application_uri() const noexcept
  {
    return static_cast<std::string_view>(mApplicationUri);
  }

  /// RoleConfiguration epoch against which the Role snapshots were evaluated.
  ///
  /// Zero denotes an identity created without a RoleConfiguration. An active Session compares this value
  /// with the live configuration before each authorization operation.
  ///
  /// @return The epoch the Role snapshots were read at, or zero when there was no configuration.
  uint64_t role_configuration_epoch() const noexcept
  {
    return mRoleConfigurationEpoch;
  }

  /// The negotiated endpoint security context - mode, policy, endpoint and transport.
  ///
  /// @return The endpoint context. Valid while this object is.
  const EndpointSecurityContext& endpoint() const noexcept
  {
    return *mEndpoint;
  }

private:
  AccessIdentityKey mKey;
  std::vector<NodeId> mGrantedRoles;
  std::vector<NodeId> mRegisteredRoles;
  bool mRoleConfigurationKnown{false};
  shared_ptr<const UserIdentity> mUser;
  shared_ptr<const EndpointSecurityContext> mEndpoint;
  String mApplicationUri;
  uint64_t mRoleConfigurationEpoch{0};
};

/// Result returned by @ref Namespace::effective_permissions_async.
///
/// A good batch contains one effective permission result for the namespace subject, or one result per
/// requested node in request order. Each item can independently preserve a rich failure. A bad batch
/// means the namespace could not process the request as a whole and carries that failure's ErrorDetail.
///
/// @ingroup address_space
using EffectivePermissionsResult = BatchResult<Result<PermissionType>>;

/// Completion of @ref Namespace::effective_permissions_async.
///
/// Invoked exactly once with the effective masks themselves. A namespace may cache those answers, but
/// callers never require it to do so and never ask the immediate member again to complete this decision.
///
/// @ingroup address_space
using EffectivePermissionsCallback = std::function<void(EffectivePermissionsResult)>;

}  // namespace ua

namespace std
{

/// Hash over the opaque token, so a namespace can key an `unordered_map` by the identity it was asked
/// about without the SDK publishing what the token means.
template<>
struct hash<::ua::AccessIdentityKey>
{
  std::size_t operator()(const ::ua::AccessIdentityKey& key) const noexcept
  {
    return std::hash<uint64_t>{}(key.value());
  }
};

}  // namespace std

#endif  // UA_NAMESPACE_AUTHORIZATION_H
