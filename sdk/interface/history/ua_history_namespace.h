// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_NAMESPACE_H
#define UA_HISTORY_NAMESPACE_H

#include "ua_namespace_history_delegate.h"
#include "ua_namespace.h"

namespace ua::history
{

/// @ingroup history
/// Forwarding wrapper around an SDK-provided `Namespace` that attaches a history delegate without
/// changing the underlying address-space behaviour.
class HistoryNamespace : public ua::Namespace
{
public:
  /// Wrap `inner`, attaching `delegate` as the namespace's history delegate. All non-history behaviour
  /// is forwarded unchanged to `inner`.
  /// @param inner the SDK-provided namespace whose non-history behaviour is forwarded unchanged.
  /// @param delegate the history delegate attached to the wrapped namespace.
  HistoryNamespace(
    ua::shared_ptr<ua::Namespace> inner, ua::shared_ptr<ua::NamespaceHistoryDelegate> delegate);

  ua::String uri() const override;
  /// Forwards the shutdown to the wrapped namespace: this wrapper arms nothing of its own.
  /// @param callback invoked once the wrapped namespace has stopped its background work.
  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept override;
  ua::shared_ptr<ua::NamespaceHistoryDelegate> history_delegate() noexcept override;

  /// Forwards the wrapped namespace's RegisterNodes delegate.
  /// @return the wrapped namespace's delegate, or null when it registers nothing.
  ua::shared_ptr<ua::NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override;

  /// Forwards Method calls and their complete answers unchanged to the wrapped namespace.
  /// @param request the request served.
  /// @param caller the caller of the Methods, or null for the server's own calls.
  /// @param items the ordered Method calls passed to the wrapped namespace.
  /// @param complete receives the wrapped namespace's answer, including declines and refusals.
  void call_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::CallItem> items,
    std::function<void(ua::BatchResult<std::optional<ua::CallResult>>)> complete) override;

  // The batched members, forwarded unchanged with the request served: the wrapped namespace holds the Nodes,
  // and each item carries a Node the wrapped namespace returned.
  /// @copydoc ua::Namespace::find_nodes_async
  void find_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodeIds,
    std::optional<ua::Duration> maxAge,
    std::function<void(ua::BatchResult<ua::NodeResult>)> complete) override;
  /// @copydoc ua::Namespace::find_node
  std::optional<ua::NodeResult> find_node(
    const ua::NodeId& nodeId, std::optional<ua::Duration> maxAge) override;
  /// @copydoc ua::Namespace::enumerate_nodes_async
  void enumerate_nodes_async(const ua::RequestInfo& request,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> complete) override;
  /// @copydoc ua::Namespace::read_references_async
  void read_references_async(const ua::RequestInfo& request, std::span<const ua::ReferenceQuery> queries,
    std::function<void(ua::BatchResult<ua::NodeReferencesResult>)> complete) override;
  void release_resume_token(ua::ByteString token) override;
  /// @copydoc ua::Namespace::read_values_async
  void read_values_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::ValueReadItem> items, ua::Duration maxAge, bool setSourceTimestamp,
    std::function<void(ua::BatchResult<ua::DataValueResult>)> complete) override;
  /// @copydoc ua::Namespace::write_async
  void write_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::ValueWriteItem> items,
    std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete) override;
  /// @copydoc ua::Namespace::view_contains_async
  void view_contains_async(const ua::RequestInfo& request, const ua::NodeId& view,
    std::span<const ua::ExpandedNodeId> nodes,
    std::function<void(ua::BatchResult<ua::BoolResult>)> complete) override;
  /// @copydoc ua::Namespace::add_to_view_async
  void add_to_view_async(const ua::RequestInfo& request, const ua::NodeId& view,
    std::span<const ua::NodeId> nodes,
    std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete) override;
  /// @copydoc ua::Namespace::create_nodes_async
  void create_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeCreation> nodes,
    std::function<void(ua::BatchResult<ua::NodeResult>)> complete) override;
  /// @copydoc ua::Namespace::delete_nodes_async
  void delete_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodes,
    ua::ReferenceHalves halves,
    std::function<void(ua::BatchResult<ua::DeleteNodeResult>, std::vector<ua::VersionedNode>)> complete)
    override;
  /// @copydoc ua::Namespace::add_references_async
  void add_references_async(const ua::RequestInfo& request, std::span<const ua::ReferenceChange> changes,
    std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete) override;
  /// @copydoc ua::Namespace::remove_references_async
  void remove_references_async(const ua::RequestInfo& request, std::span<const ua::ReferenceChange> changes,
    std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete) override;
  /// @copydoc ua::Namespace::create_monitoring_async
  void create_monitoring_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::MonitoringCreateItem> items,
    std::function<void(ua::BatchResult<ua::MonitoringCreateItemResult>)> complete) override;
  /// @copydoc ua::Namespace::modify_monitoring_async
  void modify_monitoring_async(const ua::RequestInfo& request,
    std::span<const ua::MonitoringModifyItem> items,
    std::function<void(ua::BatchResult<ua::MonitoringModifyItemResult>)> complete) override;
  /// @copydoc ua::Namespace::delete_monitoring_async
  void delete_monitoring_async(const ua::RequestInfo& request, std::span<const ua::MonitoringHandle> handles,
    std::function<void(ua::BatchResult<ua::VoidResult>)> complete) override;

  /// Forwards the wrapped namespace's immediate access-control answer for a Node unchanged.
  ///
  /// @param identity the identity whose permissions are being resolved.
  /// @param node the Node the permissions are wanted for, or null for the namespace itself.
  /// @return the wrapped namespace's answer, unchanged.
  std::optional<ua::PermissionType> effective_permissions(
    const ua::AccessIdentity& identity, const ua::Node* node) const override;
  /// Forwards asynchronous effective-permission resolution, with the request it serves, to the wrapped
  /// namespace.
  ///
  /// @param request the request served.
  /// @param identity the identity whose permissions are being resolved.
  /// @param nodes the nodes the permissions are wanted for, or nullopt for the namespace itself.
  /// @param callback invoked with the resolved permissions.
  void effective_permissions_async(const ua::RequestInfo& request,
    ua::shared_ptr<const ua::AccessIdentity> identity, std::optional<std::vector<ua::NodeId>> nodes,
    ua::EffectivePermissionsCallback callback) override;
  /// Forwards prospective RolePermissions operability validation to the wrapped namespace.
  ///
  /// @param request the request served.
  /// @param updates the proposed changes.
  /// @param complete invoked with the wrapped namespace's verdict for each update.
  void validate_role_permissions_updates_async(const ua::RequestInfo& request,
    std::span<const ua::RolePermissionsUpdate> updates,
    std::function<void(ua::BatchResult<ua::VoidResult>)> complete) override;
  /// Forwards the wrapped namespace's Part-18 default.
  ///
  /// @return the wrapped namespace's default RolePermissions, or nullopt when it declares none.
  std::optional<std::vector<ua::RolePermissionType>> default_role_permissions() const override;
  /// Forwards the wrapped namespace's channel default.
  ///
  /// @return the wrapped namespace's default AccessRestrictions, or nullopt when it declares none.
  std::optional<ua::AccessRestrictionType> default_access_restrictions() const override;
  /// Forwards the identity-lifetime notification to the wrapped namespace.
  ///
  /// @param key the identity that has been released.
  void on_identity_released(const ua::AccessIdentityKey& key) noexcept override;
  /// Forwards the metadata Object already served by the wrapped namespace.
  ///
  /// @return the wrapped namespace's NamespaceMetadata Object, or nullopt when it serves none.
  std::optional<ua::NodeId> metadata_object() const override;

private:
  /// Attaches the wrapped namespace with this namespace's context, so that it reads the same index; its
  /// refusal is this namespace's.
  /// @param context the context this namespace was attached with.
  ua::VoidResult on_attached(const ua::NamespaceContext& context) override;

  ua::shared_ptr<ua::Namespace> mInner;
  ua::shared_ptr<ua::NamespaceHistoryDelegate> mDelegate;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_NAMESPACE_H
