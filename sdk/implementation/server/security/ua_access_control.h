// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Canonical per-node access-control decision and deterministic Attribute projection helper.
/// @ingroup security

#ifndef UA_ACCESS_CONTROL_H
#define UA_ACCESS_CONTROL_H

#include "ua_access_operation.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_namespace_authorization.h"
#include "ua_node_description.h"
#include "ua_permission_type.h"
#include "ua_request_info.h"
#include "ua_server_authentication.h"
#include "ua_status_code.h"
#include "ua_weak_address_space.h"

#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace ua::server
{

class SessionInfo;
class SessionSecurityContext;

/// Applies the channel condition and the owning namespace's permission answer for every protected node.
///
/// The immediate namespace answer is the common path. A `nullopt` answer is grouped with every other
/// miss for the same namespace and resolved once under one operation-wide deadline. The returned masks
/// complete the decision directly; no cache or second immediate question is required. No executor hop
/// is introduced when all answers are already available.
class AccessControl final
{
public:
  struct Item
  {
    NodeAccessor node;
    AccessOperation operation;
    /// The Node's Attributes, when the caller already holds them; when absent, access control takes
    /// `node->attributes()` once for the item.
    std::optional<NodeDescription> description{};
  };

  struct Verdict
  {
    NodeId subject{};
    AccessOperation operation{AccessOperation::Browse};
    bool permitted{false};
    bool channelRefused{false};
    PermissionType mask{};
    StatusCode cause{Status::BadUserAccessDenied};
  };

  using AuthorizeCallback = std::function<void(std::vector<Verdict>)>;
  using AuthorizeNamespaceCallback = std::function<void(Verdict)>;

  /// Binds the helper to the server's address space and one operation-wide resolution deadline.
  ///
  /// The helper holds the address space weakly, so that an operation keeping it across a namespace's answer
  /// (a Republish's re-authorization) does not keep the address space alive (CALLS-21 rule 1). Once the address
  /// space is gone, every decision is denied `Bad_Shutdown` (`AddressSpaceGone`).
  AccessControl(
    AddressSpace addressSpace, std::chrono::milliseconds authorizationTimeout, Logger logger = {});

  /// Authorizes a batch, completing inline unless at least one namespace answer misses.
  ///
  /// A deleted Node is denied `Bad_NodeIdUnknown` without asking its namespace. The AccessRestrictions and
  /// RolePermissions come from the item's description. A namespace whose immediate answer misses is asked
  /// once, through `effective_permissions_async` with @p request, for all of its missed items.
  void authorize_async(const RequestInfo& request, std::shared_ptr<const AccessIdentity> identity,
    std::span<const Item> items, const EndpointSecurityContext& channel, AuthorizeCallback done) const;

  /// Authorizes AddNodes against the destination namespace's default Role permissions.
  void authorize_namespace_async(const RequestInfo& request, std::shared_ptr<const AccessIdentity> identity,
    uint16_t namespaceIndex, const EndpointSecurityContext& channel, AuthorizeNamespaceCallback done) const;

  /// Returns the identity-independent Attribute that supplies the raw value for a client-facing
  /// Attribute. Identity-derived Attributes are backed by their corresponding ordinary Attribute;
  /// every other Attribute is its own source.
  static AttributeId user_independent_attribute(AttributeId clientAttribute) noexcept;

  /// Whether @ref make_client_attribute_value produces the client-visible value of @p clientAttribute
  /// rather than passing the user-independent value through: UserAccessLevel, UserWriteMask,
  /// UserExecutable, RolePermissions and UserRolePermissions. The server, not the namespace, applies an
  /// IndexRange to these, after the projection (NR-14 rule 2).
  static bool produces_value(AttributeId clientAttribute) noexcept;

  /// Returns the permission operation required to read an Attribute.
  ///
  /// Value requires Read, RolePermissions requires ReadRolePermissions, and every other Attribute
  /// requires Browse. Event-filter planning and ordinary Attribute reads use this same mapping.
  static AccessOperation attribute_read_operation(AttributeId attribute) noexcept;

  /// Constructs the client-visible value from one completed Attribute-read decision.
  ///
  /// This is a deterministic local transformation. It performs no permission acquisition, callback,
  /// scheduling, audit or cache mutation. @p readAccess shall be the verdict associated with @p node
  /// and the Attribute-read operation for @p attribute (`Read` for Value, `ReadRolePermissions` for
  /// RolePermissions, and `Browse` otherwise). A failed or mismatched association fails closed and
  /// retains its rich cause.
  DataValue make_client_attribute_value(const AccessIdentity& identity, const NodeAccessor& node,
    AttributeId attribute, DataValue userIndependentValue, const Verdict& readAccess,
    const EndpointSecurityContext& channel) const;

  /// As the overload above, but checks the association of @p readAccess against @p nodeId, the NodeId
  /// the verdict was made for, instead of the NodeId read from @p node.
  ///
  /// A NodeId survives the deletion of its Node, but a deleted Node no longer answers it. A monitored
  /// item's value read before its Node was deleted is projected after the deletion, so the subscription
  /// passes the NodeId it monitors. The Attributes whose projection reads the Node or its namespace
  /// (UserAccessLevel, UserWriteMask, UserExecutable, RolePermissions, UserRolePermissions) still read
  /// them, and fail once the Node is deleted.
  DataValue make_client_attribute_value(const AccessIdentity& identity, const NodeId& nodeId,
    const NodeAccessor& node, AttributeId attribute, DataValue userIndependentValue,
    const Verdict& readAccess, const EndpointSecurityContext& channel) const;

private:
  WeakAddressSpace mAddressSpace;
  std::chrono::milliseconds mAuthorizationTimeout;
  Logger mLogger;
};

/// Request-scoped binding of the canonical helper to one activated Session's immutable security
/// snapshots. Construction fails closed before activation or when the supplied execution context is
/// not a Session security context.
class SessionAccessControl final
{
public:
  using CreateResult = Result<SessionAccessControl>;

  static std::optional<SessionAccessControl> create(const SessionInfo& sessionInfo);
  static std::optional<SessionAccessControl> create(const SessionSecurityContext& securityContext,
    AddressSpace addressSpace, std::chrono::milliseconds authorizationTimeout, Logger logger = {});
  static CreateResult create_result(const SessionSecurityContext& securityContext, AddressSpace addressSpace,
    std::chrono::milliseconds authorizationTimeout, Logger logger = {});

  void authorize_async(const RequestInfo& request, std::span<const AccessControl::Item> items,
    AccessControl::AuthorizeCallback done) const;
  void authorize_namespace_async(const RequestInfo& request, uint16_t namespaceIndex,
    AccessControl::AuthorizeNamespaceCallback done) const;
  DataValue make_client_attribute_value(const NodeAccessor& node, AttributeId attribute,
    DataValue userIndependentValue, const AccessControl::Verdict& readAccess) const;
  /// As above, with the association checked against @p nodeId, the NodeId the verdict was made for
  /// (see AccessControl::make_client_attribute_value).
  DataValue make_client_attribute_value(const NodeId& nodeId, const NodeAccessor& node, AttributeId attribute,
    DataValue userIndependentValue, const AccessControl::Verdict& readAccess) const;

  const std::shared_ptr<const AccessIdentity>& identity() const noexcept;
  const EndpointSecurityContext& channel() const noexcept;

private:
  SessionAccessControl(AccessControl helper, std::shared_ptr<const AccessIdentity> identity,
    std::shared_ptr<const EndpointSecurityContext> channel);

  AccessControl mHelper;
  std::shared_ptr<const AccessIdentity> mIdentity;
  std::shared_ptr<const EndpointSecurityContext> mChannel;
};

}  // namespace ua::server

#endif  // UA_ACCESS_CONTROL_H
