// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_namespace.h"

#include "ua_key_value_pair.h"

namespace ua::history
{

HistoryNamespace::HistoryNamespace(
  ua::shared_ptr<ua::Namespace> inner, ua::shared_ptr<ua::NamespaceHistoryDelegate> delegate)
  : mInner(std::move(inner)), mDelegate(std::move(delegate))
{}

ua::String HistoryNamespace::uri() const
{
  return mInner->uri();
}

ua::VoidResult HistoryNamespace::on_attached(const ua::NamespaceContext& context)
{
  return mInner->attach(context);
}

void HistoryNamespace::shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  // This wrapper arms nothing of its own; the work belongs to the namespace it wraps.
  if (mInner)
  {
    mInner->shutdown_async(std::move(callback));
    return;
  }
  if (callback)
  {
    callback(ua::VoidResult{});
  }
}

ua::shared_ptr<ua::NamespaceHistoryDelegate> HistoryNamespace::history_delegate() noexcept
{
  return mDelegate;
}

ua::shared_ptr<ua::NamespaceRegisterNodesDelegate> HistoryNamespace::register_nodes_delegate() noexcept
{
  return mInner->register_nodes_delegate();
}

void HistoryNamespace::call_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
  std::span<const ua::CallItem> items,
  std::function<void(ua::BatchResult<std::optional<ua::CallResult>>)> complete)
{
  mInner->call_async(request, caller, items, std::move(complete));
}

void HistoryNamespace::find_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodeIds,
  std::optional<ua::Duration> maxAge, std::function<void(ua::BatchResult<ua::NodeResult>)> complete)
{
  mInner->find_nodes_async(request, nodeIds, maxAge, std::move(complete));
}

std::optional<ua::NodeResult> HistoryNamespace::find_node(
  const ua::NodeId& nodeId, std::optional<ua::Duration> maxAge)
{
  return mInner->find_node(nodeId, maxAge);
}

void HistoryNamespace::enumerate_nodes_async(
  const ua::RequestInfo& request, std::function<void(ua::Result<std::vector<ua::NodeId>>)> complete)
{
  mInner->enumerate_nodes_async(request, std::move(complete));
}

void HistoryNamespace::read_references_async(const ua::RequestInfo& request,
  std::span<const ua::ReferenceQuery> queries,
  std::function<void(ua::BatchResult<ua::NodeReferencesResult>)> complete)
{
  mInner->read_references_async(request, queries, std::move(complete));
}

void HistoryNamespace::release_resume_token(ua::ByteString token)
{
  mInner->release_resume_token(std::move(token));
}

void HistoryNamespace::read_values_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
  std::span<const ua::ValueReadItem> items, ua::Duration maxAge, bool setSourceTimestamp,
  std::function<void(ua::BatchResult<ua::DataValueResult>)> complete)
{
  mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
}

void HistoryNamespace::write_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
  std::span<const ua::ValueWriteItem> items,
  std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete)
{
  mInner->write_async(request, caller, items, std::move(complete));
}

void HistoryNamespace::view_contains_async(const ua::RequestInfo& request, const ua::NodeId& view,
  std::span<const ua::ExpandedNodeId> nodes, std::function<void(ua::BatchResult<ua::BoolResult>)> complete)
{
  mInner->view_contains_async(request, view, nodes, std::move(complete));
}

void HistoryNamespace::add_to_view_async(const ua::RequestInfo& request, const ua::NodeId& view,
  std::span<const ua::NodeId> nodes,
  std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete)
{
  mInner->add_to_view_async(request, view, nodes, std::move(complete));
}

void HistoryNamespace::create_nodes_async(const ua::RequestInfo& request,
  std::span<const ua::NodeCreation> nodes, std::function<void(ua::BatchResult<ua::NodeResult>)> complete)
{
  mInner->create_nodes_async(request, nodes, std::move(complete));
}

void HistoryNamespace::delete_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodes,
  ua::ReferenceHalves halves,
  std::function<void(ua::BatchResult<ua::DeleteNodeResult>, std::vector<ua::VersionedNode>)> complete)
{
  mInner->delete_nodes_async(request, nodes, halves, std::move(complete));
}

void HistoryNamespace::add_references_async(const ua::RequestInfo& request,
  std::span<const ua::ReferenceChange> changes,
  std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete)
{
  mInner->add_references_async(request, changes, std::move(complete));
}

void HistoryNamespace::remove_references_async(const ua::RequestInfo& request,
  std::span<const ua::ReferenceChange> changes,
  std::function<void(ua::BatchResult<ua::VoidResult>, std::vector<ua::VersionedNode>)> complete)
{
  mInner->remove_references_async(request, changes, std::move(complete));
}

void HistoryNamespace::create_monitoring_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
  std::span<const ua::MonitoringCreateItem> items,
  std::function<void(ua::BatchResult<ua::MonitoringCreateItemResult>)> complete)
{
  mInner->create_monitoring_async(request, caller, items, std::move(complete));
}

void HistoryNamespace::modify_monitoring_async(const ua::RequestInfo& request,
  std::span<const ua::MonitoringModifyItem> items,
  std::function<void(ua::BatchResult<ua::MonitoringModifyItemResult>)> complete)
{
  mInner->modify_monitoring_async(request, items, std::move(complete));
}

void HistoryNamespace::delete_monitoring_async(const ua::RequestInfo& request,
  std::span<const ua::MonitoringHandle> handles,
  std::function<void(ua::BatchResult<ua::VoidResult>)> complete)
{
  mInner->delete_monitoring_async(request, handles, std::move(complete));
}

std::optional<ua::PermissionType> HistoryNamespace::effective_permissions(
  const ua::AccessIdentity& identity, const ua::Node* node) const
{
  return mInner->effective_permissions(identity, node);
}

void HistoryNamespace::effective_permissions_async(const ua::RequestInfo& request,
  ua::shared_ptr<const ua::AccessIdentity> identity, std::optional<std::vector<ua::NodeId>> nodes,
  ua::EffectivePermissionsCallback callback)
{
  mInner->effective_permissions_async(request, std::move(identity), std::move(nodes), std::move(callback));
}

void HistoryNamespace::validate_role_permissions_updates_async(const ua::RequestInfo& request,
  std::span<const ua::RolePermissionsUpdate> updates,
  std::function<void(ua::BatchResult<ua::VoidResult>)> complete)
{
  mInner->validate_role_permissions_updates_async(request, updates, std::move(complete));
}

std::optional<std::vector<ua::RolePermissionType>> HistoryNamespace::default_role_permissions() const
{
  return mInner->default_role_permissions();
}

std::optional<ua::AccessRestrictionType> HistoryNamespace::default_access_restrictions() const
{
  return mInner->default_access_restrictions();
}

void HistoryNamespace::on_identity_released(const ua::AccessIdentityKey& key) noexcept
{
  mInner->on_identity_released(key);
}

std::optional<ua::NodeId> HistoryNamespace::metadata_object() const
{
  return mInner->metadata_object();
}

}  // namespace ua::history
