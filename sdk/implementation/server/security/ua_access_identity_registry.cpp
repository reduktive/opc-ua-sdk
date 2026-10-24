// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_access_identity_registry.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_namespace_array.h"
#include "ua_role_configuration.h"
#include "ua_to_result.h"
#include "ua_utilities.h"

#include <limits>
#include <string_view>

namespace ua::server
{
namespace
{

void hash_combine(size_t& seed, size_t value) noexcept
{
  // The golden-ratio constant has to match the width of size_t. Written as a bare
  // 0x9e3779b97f4a7c15ULL the arithmetic promotes to unsigned long long, and assigning back into a
  // 32-bit size_t is a narrowing conversion - which -Werror=conversion rejects, so the SDK did not
  // build on any 32-bit target.
  //
  // The 32-bit arm is 0x9e3779b9, the real golden-ratio constant for that width, NOT the low half
  // of the 64-bit one. Truncating would give 0x7f4a7c15 and quietly cost hash quality on exactly
  // the platforms least able to afford collisions.
  constexpr size_t goldenRatio =
    sizeof(size_t) >= 8 ? static_cast<size_t>(0x9e3779b97f4a7c15ULL) : static_cast<size_t>(0x9e3779b9U);
  seed ^= value + goldenRatio + (seed << 6U) + (seed >> 2U);
}

template<typename T>
void hash_value(size_t& seed, const T& value) noexcept
{
  hash_combine(seed, std::hash<T>{}(value));
}

}  // namespace

AccessIdentityRegistry::AccessIdentityRegistry(
  WeakAddressSpace addressSpace, uint32_t maximumLiveIdentities) noexcept
  : mAddressSpace{std::move(addressSpace)}, mMaximumLiveIdentities{maximumLiveIdentities}
{}

size_t AccessIdentityRegistry::FactsHash::operator()(const Facts& facts) const noexcept
{
  size_t seed{0};
  hash_value(seed, facts.userId);
  hash_value(seed, utils::to_underlying(facts.kind));
  size_t claimsHash{0};
  for (const auto& [name, value] : facts.claims)
  {
    size_t claimHash{0};
    hash_value(claimHash, name);
    hash_value(claimHash, value);
    claimsHash ^= claimHash;
  }
  hash_combine(seed, claimsHash);
  hash_value(seed, facts.applicationUri);
  hash_value(seed, utils::to_underlying(facts.securityMode));
  hash_value(seed, utils::to_underlying(facts.securityPolicy));
  hash_value(seed, facts.endpointPolicyId);
  if (facts.userTokenPolicyId)
  {
    hash_value(seed, *facts.userTokenPolicyId);
  }
  hash_value(seed, facts.endpointUrl);
  hash_value(seed, facts.transportProfileUri);
  hash_value(seed, facts.roleConfigurationEpoch);
  return seed;
}

AccessIdentityRegistry::Entry::Entry(AccessIdentity identityIn, WeakAddressSpace addressSpaceIn) noexcept
  : identity{std::move(identityIn)}, addressSpace{std::move(addressSpaceIn)}
{}

AccessIdentityRegistry::Entry::~Entry() noexcept
{
  AccessIdentityRegistry::notify_released(addressSpace, identity.key());
}

AccessIdentityRegistry::Facts AccessIdentityRegistry::make_facts(
  const UserIdentity& user, const EndpointSecurityContext& endpoint, uint64_t roleConfigurationEpoch)
{
  return Facts{.userId = user.userId,
    .kind = user.kind,
    .claims = user.claims,
    .applicationUri = std::string{static_cast<std::string_view>(endpoint.clientApplicationUri)},
    .securityMode = endpoint.messageSecurityMode,
    .securityPolicy = endpoint.securityPolicyId,
    .endpointPolicyId = endpoint.endpointPolicyId,
    .userTokenPolicyId = endpoint.userTokenPolicyId,
    .endpointUrl = std::string{static_cast<std::string_view>(endpoint.endpointUrl)},
    .transportProfileUri = std::string{static_cast<std::string_view>(endpoint.transportProfileUri)},
    .roleConfigurationEpoch = roleConfigurationEpoch};
}

void AccessIdentityRegistry::notify_released(
  const WeakAddressSpace& addressSpace, const AccessIdentityKey& key) noexcept
{
  try
  {
    auto owner = addressSpace.lock();
    if (!owner)
    {
      return;
    }
    auto& namespaces = owner->namespace_array();
    for (uint32_t index = 0; index <= std::numeric_limits<uint16_t>::max(); ++index)
    {
      auto target = namespaces.get_namespace(static_cast<uint16_t>(index));
      if (!target)
      {
        break;
      }
      target->on_identity_released(key);
    }
  }
  catch (...)
  {
    // The release hook is a best-effort cache signal and is specified noexcept. A namespace hook is
    // also noexcept; this containment protects teardown from an unexpected address-space failure.
    ua::detail::ignore_expected_exception();
  }
}

void AccessIdentityRegistry::erase_expired_locked()
{
  for (auto entry = mEntries.begin(); entry != mEntries.end();)
  {
    if (entry->second.expired())
    {
      entry = mEntries.erase(entry);
    }
    else
    {
      ++entry;
    }
  }
}

AccessIdentityRegistry::IdentityResult AccessIdentityRegistry::acquire(
  std::shared_ptr<const UserIdentity> user, std::shared_ptr<const EndpointSecurityContext> endpoint,
  std::vector<NodeId> grantedRoles, std::vector<NodeId> registeredRoles, uint64_t roleConfigurationEpoch)
{
  if (!user || !endpoint)
  {
    return IdentityResult{StatusCode{Status::BadIdentityTokenInvalid},
      ErrorDetail::build("AccessIdentityFactsMissing",
        "An access identity requires both a user and endpoint security context.",
        "AccessIdentityRegistry")};
  }

  Facts facts = make_facts(*user, *endpoint, roleConfigurationEpoch);
  std::lock_guard lock{mMutex};
  erase_expired_locked();
  if (auto existing = mEntries.find(facts); existing != mEntries.end())
  {
    if (auto entry = existing->second.lock())
    {
      return IdentityResult{std::shared_ptr<const AccessIdentity>{entry, &entry->identity}};
    }
  }

  if (mEntries.size() >= mMaximumLiveIdentities)
  {
    return IdentityResult{StatusCode{Status::BadTooManySessions},
      ErrorDetail::build("AccessIdentityLimitReached",
        "The server's live access identity limit has been reached.",
        "AccessIdentityRegistry")
        .context(ContextKeys::limit, std::to_string(mMaximumLiveIdentities))
        .context(ContextKeys::countTotal, std::to_string(mEntries.size()))};
  }
  if (mNextKey == 0)
  {
    return IdentityResult{StatusCode{Status::BadOutOfRange},
      ErrorDetail::build("AccessIdentityKeySpaceExhausted",
        "The server has exhausted its non-reusable access identity key space.",
        "AccessIdentityRegistry")};
  }

  const AccessIdentityKey key{mNextKey++};
  auto entry = std::make_shared<Entry>(AccessIdentity{key,
                                         std::move(grantedRoles),
                                         std::move(registeredRoles),
                                         std::move(user),
                                         std::move(endpoint),
                                         String{facts.applicationUri},
                                         roleConfigurationEpoch},
    mAddressSpace);
  mEntries.insert_or_assign(std::move(facts), entry);
  return IdentityResult{std::shared_ptr<const AccessIdentity>{entry, &entry->identity}};
}

AccessIdentityRegistry::IdentityResult AccessIdentityRegistry::refresh(
  std::shared_ptr<const AccessIdentity> current, std::shared_ptr<const UserIdentity> user,
  std::shared_ptr<const EndpointSecurityContext> endpoint, const RoleConfiguration& roleConfiguration)
{
  if (current && current->role_configuration_epoch() == roleConfiguration.epoch())
  {
    return IdentityResult{std::move(current)};
  }

  if (!user || !endpoint)
  {
    return IdentityResult{StatusCode{Status::BadIdentityTokenInvalid},
      ErrorDetail::build("AccessIdentityRefreshFactsMissing",
        "An active Session cannot refresh Roles without its authenticated user and endpoint facts",
        "AccessIdentityRegistry")};
  }

  try
  {
    auto evaluation = roleConfiguration.evaluate_access_identity(*user, *endpoint);
    return acquire(std::move(user),
      std::move(endpoint),
      std::move(evaluation.grantedRoles),
      std::move(evaluation.registeredRoles),
      evaluation.configurationEpoch);
  }
  catch (...)
  {
    const auto cause = ua::exception_to_status_code(std::current_exception());
    return IdentityResult{StatusCode{Status::BadUserAccessDenied},
      ErrorDetail::build("AccessIdentityRoleRefreshFailed",
        "The active Session's Role configuration could not be refreshed",
        "AccessIdentityRegistry")
        .cause(cause)};
  }
}

size_t AccessIdentityRegistry::live_count()
{
  std::lock_guard lock{mMutex};
  erase_expired_locked();
  return mEntries.size();
}

}  // namespace ua::server
