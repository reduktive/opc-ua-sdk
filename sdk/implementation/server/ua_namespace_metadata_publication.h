// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_METADATA_PUBLICATION_H
#define UA_NAMESPACE_METADATA_PUBLICATION_H

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_namespace_authorization.h"
#include "ua_namespace_metadata_options.h"
#include "ua_namespace_registration_coordinator.h"
#include "ua_role_permission_type.h"
#include "ua_server_configuration.h"

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua::server
{

class RoleConfiguration;
struct NamespaceMetadataSnapshot;

class NamespaceMetadataPublication final : public ::ua::detail::NamespaceRegistrationParticipant,
                                           public std::enable_shared_from_this<NamespaceMetadataPublication>
{
public:
  static std::shared_ptr<NamespaceMetadataPublication> create(AddressSpace addressSpace);

  /// Prepares one coordinator candidate.
  void prepare_async(::ua::detail::NamespaceRegistrationCandidate candidate,
    ::ua::detail::NamespaceRegistrationPreparationCallback complete) noexcept override;

  /// Internal batch convenience retained for direct component tests. Successful preparation is
  /// committed before the callback; production registration uses the participant overload above.
  void prepare_async(
    std::vector<NamespaceMetadataSnapshot> namespaces, std::function<void(VoidResult)> complete) noexcept;

  /// Finds the live publication participant associated with a server-owned AddressSpace.
  static std::shared_ptr<const NamespaceMetadataPublication> for_address_space(
    const AddressSpace& addressSpace);

private:
  explicit NamespaceMetadataPublication(AddressSpace addressSpace);
  void publish_registry_entry();

  // No read-path state. The three governing Properties are answered by the nodes that hold them -
  // two from stamped values, and DefaultUserRolePermissions from a handler installed at creation that
  // captures which namespace it describes. There is therefore nothing for a reader to consult, and
  // nothing to publish atomically to readers while registration adds namespaces.
  WeakAddressSpace mAddressSpace;
  const NamespaceArray* mRegistryKey{nullptr};
};

/// Installs the materialised well-known-Role defaults as the enforcement interface for the two namespaces
/// owned by the server (NS0 and NS1). The publication component subsequently answers metadata Reads
/// from this interface; it does not maintain a second stored mirror. Roles absent from the materialised
/// RoleSet are absent from the array; an empty RoleSet therefore installs an engaged empty array.
void install_server_namespace_defaults(AddressSpace addressSpace, const RoleConfiguration& roleConfig,
  const std::optional<std::vector<WellKnownRole>>& selection);

/// Immutable startup input for one application namespace's metadata Object.
///
/// The caller builds these values while namespace configuration is stable. The
/// asynchronous publication flow owns the resulting snapshot and never retains a
/// namespace delegate or a reference into NamespaceArray.
struct NamespaceMetadataSnapshot
{
  uint16_t namespaceIndex{0};
  String namespaceUri;
  /// Engaged means the namespace uses the standard Role model, including an engaged empty array;
  /// absent means a vendor-specific model and suppresses both standard Role Properties.
  std::optional<std::vector<RolePermissionType>> defaultRolePermissions;
  std::optional<AccessRestrictionType> defaultAccessRestrictions;
  std::optional<NodeId> metadataObject;
  /// What the registering caller asked to be published for this namespace.
  NamespaceMetadataOptions options;
};

}  // namespace ua::server

#endif  // UA_NAMESPACE_METADATA_PUBLICATION_H
