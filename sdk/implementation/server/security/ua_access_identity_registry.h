// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-scoped interning and lifetime notification for access identities.

#ifndef UA_ACCESS_IDENTITY_REGISTRY_H
#define UA_ACCESS_IDENTITY_REGISTRY_H

#include "ua_address_space.h"
#include "ua_namespace_authorization.h"
#include "ua_result.h"
#include "security/ua_server_authentication.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ua::server
{

class RoleConfiguration;

/// Interns equal authorization identities for one Server and bounds their live population.
///
/// The table stores weak entries: Session and subscription security views own the identity, while
/// the registry only makes concurrent equal acquisitions converge. Destroying the final owner sends
/// exactly one @ref Namespace::on_identity_released notification to every registered namespace.
class AccessIdentityRegistry final
{
public:
  using IdentityResult = Result<std::shared_ptr<const AccessIdentity>>;

  AccessIdentityRegistry(WeakAddressSpace addressSpace, uint32_t maximumLiveIdentities) noexcept;

  AccessIdentityRegistry(const AccessIdentityRegistry&) = delete;
  AccessIdentityRegistry& operator=(const AccessIdentityRegistry&) = delete;
  AccessIdentityRegistry(AccessIdentityRegistry&&) = delete;
  AccessIdentityRegistry& operator=(AccessIdentityRegistry&&) = delete;
  ~AccessIdentityRegistry() = default;

  /// Acquires the one live identity matching all role-mapping inputs.
  ///
  /// @param user         Authenticated principal; must be non-null.
  /// @param endpoint     Endpoint security facts; must be non-null.
  /// @param grantedRoles Role NodeIds granted when this identity is first constructed.
  /// @param registeredRoles Complete RoleConfiguration NodeId snapshot paired with the grant.
  /// @param roleConfigurationEpoch Epoch of that coherent RoleConfiguration snapshot.
  /// @return The shared identity, or a detailed failure when inputs are missing or the cap is full.
  IdentityResult acquire(std::shared_ptr<const UserIdentity> user,
    std::shared_ptr<const EndpointSecurityContext> endpoint, std::vector<NodeId> grantedRoles,
    std::vector<NodeId> registeredRoles = {}, uint64_t roleConfigurationEpoch = 0);

  /// Returns @p current at the live RoleConfiguration epoch, or atomically evaluates and interns a
  /// replacement. A failed replacement never returns the stale grant.
  IdentityResult refresh(std::shared_ptr<const AccessIdentity> current,
    std::shared_ptr<const UserIdentity> user, std::shared_ptr<const EndpointSecurityContext> endpoint,
    const RoleConfiguration& roleConfiguration);

  /// Number of live identity entries, after dropping expired weak rows.
  size_t live_count();

private:
  struct Facts
  {
    std::string userId;
    UserTokenKind kind{UserTokenKind::Anonymous};
    std::unordered_map<std::string, std::string> claims;
    std::string applicationUri;
    MessageSecurityMode securityMode{MessageSecurityMode::Invalid};
    SecurityPolicyId securityPolicy{};
    std::string endpointPolicyId;
    optional<std::string> userTokenPolicyId;
    std::string endpointUrl;
    std::string transportProfileUri;
    uint64_t roleConfigurationEpoch{0};

    bool operator==(const Facts&) const = default;
  };

  struct FactsHash
  {
    size_t operator()(const Facts& facts) const noexcept;
  };

  struct Entry
  {
    Entry(AccessIdentity identity, WeakAddressSpace addressSpace) noexcept;
    Entry(const Entry&) = delete;
    Entry& operator=(const Entry&) = delete;
    Entry(Entry&&) = delete;
    Entry& operator=(Entry&&) = delete;
    ~Entry() noexcept;

    AccessIdentity identity;
    WeakAddressSpace addressSpace;
  };

  static Facts make_facts(
    const UserIdentity& user, const EndpointSecurityContext& endpoint, uint64_t roleConfigurationEpoch);
  static void notify_released(const WeakAddressSpace& addressSpace, const AccessIdentityKey& key) noexcept;
  void erase_expired_locked();

  std::mutex mMutex;
  std::unordered_map<Facts, std::weak_ptr<Entry>, FactsHash> mEntries;
  WeakAddressSpace mAddressSpace;
  uint32_t mMaximumLiveIdentities;
  uint64_t mNextKey{1};
};

}  // namespace ua::server

#endif  // UA_ACCESS_IDENTITY_REGISTRY_H
