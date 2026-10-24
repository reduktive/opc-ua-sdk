// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 public `ServiceSet` handle: the 17 wire-shaped service-set operations of a managed
///        @ref ua::client::Connection (client design section 7.2A), reached via
///        `Connection::service_requests()`.
/// @ingroup client

#ifndef UA_SERVICE_SET_H
#define UA_SERVICE_SET_H

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <functional>
#include <memory>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct ConnectionHandleFactory;
}  // namespace detail

class Connection;

/// The wire-shaped service-set surface of a managed @ref Connection (section 7.2A).
///
/// A lightweight move-only value handle over the same `ConnectionImpl` as its parent @ref Connection
/// (reached via `Connection::service_requests()`, parallel to tier-0's `Session::view()` /
/// `Session::attributes()`). It owns no state of its own and is not directly constructible; every method
/// forwards straight through to `ConnectionImpl`'s already-built, gated, ErrorDetail-wrapping wire-op
/// funnel (section 7.2 `invoke_wire_op`). Relative to a raw tier-0 `Session` the managed surface adds:
/// paused/queued dispatch during reconnect (`ConnectionConfig.queueOnReconnect`), automatic NodeId
/// namespace-index renumbering via the `NamespaceTable`, the default service timeout, and a single
/// `ErrorDetail` wrap (section 7.10)  -  all applied ONCE inside the funnel, so this handle never
/// double-wraps.
///
/// Each operation follows the async / sync / try_sync triple (section 7.0):
///  - `*_async`    -  never throws; the callback receives a `Result<Response>` on the executor.
///  - `*_sync`     -  blocks; returns the bare `Response`; throws `UaException` on a bad service Result.
///  - `try_*_sync` -  blocks; returns `Result<Response>`; never throws.
///
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread on the async completion. They
///          MUST NOT be called from the Connection's executor thread (that would deadlock the executor).
///
/// @note Public methods may be called from any thread; the underlying `ConnectionImpl` posts to its
///       private strand internally.
/// @ingroup client
class ServiceSet
{
public:
  ServiceSet(const ServiceSet&) = delete;
  ServiceSet& operator=(const ServiceSet&) = delete;
  /// Returns or updates the service set.
  ServiceSet(ServiceSet&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  ServiceSet& operator=(ServiceSet&&) noexcept = default;
  ~ServiceSet() = default;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Reads one or more Node attributes (Read service).
  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously read.
  /// A Good subcode on the answer is not returned; try_read_sync() returns it.
  ua::ReadResponse read_sync(ua::ReadRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read sync without throwing.
  ua::Result<ua::ReadResponse> try_read_sync(ua::ReadRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Writes one or more Node attributes (Write service).
  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously write.
  /// A Good subcode on the answer is not returned; try_write_sync() returns it.
  ua::WriteResponse write_sync(ua::WriteRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write sync without throwing.
  ua::Result<ua::WriteResponse> try_write_sync(ua::WriteRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Browses the References of one or more Nodes (Browse service).
  void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously browse.
  /// A Good subcode on the answer is not returned; try_browse_sync() returns it.
  ua::BrowseResponse browse_sync(ua::BrowseRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to browse sync without throwing.
  ua::Result<ua::BrowseResponse> try_browse_sync(ua::BrowseRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Continues a Browse from a continuation point (BrowseNext service).
  void browse_next_async(
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously browse next.
  /// A Good subcode on the answer is not returned; try_browse_next_sync() returns it.
  ua::BrowseNextResponse browse_next_sync(ua::BrowseNextRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to browse next sync without throwing.
  ua::Result<ua::BrowseNextResponse> try_browse_next_sync(ua::BrowseNextRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Resolves relative browse paths to NodeIds (TranslateBrowsePathsToNodeIds service).
  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously translate browse paths.
  /// A Good subcode on the answer is not returned; try_translate_browse_paths_sync() returns it.
  ua::TranslateBrowsePathsToNodeIdsResponse translate_browse_paths_sync(
    ua::TranslateBrowsePathsToNodeIdsRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to translate browse paths sync without throwing.
  ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> try_translate_browse_paths_sync(
    ua::TranslateBrowsePathsToNodeIdsRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Invokes a Method (Call service).
  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously call.
  /// A Good subcode on the answer is not returned; try_call_sync() returns it.
  ua::CallResponse call_sync(ua::CallRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to call sync without throwing.
  ua::Result<ua::CallResponse> try_call_sync(ua::CallRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Registers NodeIds for optimised repeated access (RegisterNodes service).
  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously register nodes.
  /// A Good subcode on the answer is not returned; try_register_nodes_sync() returns it.
  ua::RegisterNodesResponse register_nodes_sync(ua::RegisterNodesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to register nodes sync without throwing.
  ua::Result<ua::RegisterNodesResponse> try_register_nodes_sync(ua::RegisterNodesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Releases previously registered NodeIds (UnregisterNodes service).
  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously unregister nodes.
  /// A Good subcode on the answer is not returned; try_unregister_nodes_sync() returns it.
  ua::UnregisterNodesResponse unregister_nodes_sync(ua::UnregisterNodesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to unregister nodes sync without throwing.
  ua::Result<ua::UnregisterNodesResponse> try_unregister_nodes_sync(
    ua::UnregisterNodesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Reads historical values or Events (HistoryRead service).
  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously history read.
  /// A Good subcode on the answer is not returned; try_history_read_sync() returns it.
  ua::HistoryReadResponse history_read_sync(ua::HistoryReadRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to history read sync without throwing.
  ua::Result<ua::HistoryReadResponse> try_history_read_sync(ua::HistoryReadRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Inserts, replaces, or deletes historical values or Events (HistoryUpdate service).
  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously history update.
  /// A Good subcode on the answer is not returned; try_history_update_sync() returns it.
  ua::HistoryUpdateResponse history_update_sync(ua::HistoryUpdateRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to history update sync without throwing.
  ua::Result<ua::HistoryUpdateResponse> try_history_update_sync(ua::HistoryUpdateRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Issues a query against the AddressSpace (QueryFirst service).
  void query_first_async(
    ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously query first.
  /// A Good subcode on the answer is not returned; try_query_first_sync() returns it.
  ua::QueryFirstResponse query_first_sync(ua::QueryFirstRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to query first sync without throwing.
  ua::Result<ua::QueryFirstResponse> try_query_first_sync(ua::QueryFirstRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Continues a query from a continuation point (QueryNext service).
  void query_next_async(
    ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously query next.
  /// A Good subcode on the answer is not returned; try_query_next_sync() returns it.
  ua::QueryNextResponse query_next_sync(ua::QueryNextRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to query next sync without throwing.
  ua::Result<ua::QueryNextResponse> try_query_next_sync(ua::QueryNextRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Adds Nodes to the server AddressSpace (AddNodes service).
  void add_nodes_async(
    ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously add nodes.
  /// A Good subcode on the answer is not returned; try_add_nodes_sync() returns it.
  ua::AddNodesResponse add_nodes_sync(ua::AddNodesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to add nodes sync without throwing.
  ua::Result<ua::AddNodesResponse> try_add_nodes_sync(ua::AddNodesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Adds References to the server AddressSpace (AddReferences service).
  void add_references_async(ua::AddReferencesRequest request,
    std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously add references.
  /// A Good subcode on the answer is not returned; try_add_references_sync() returns it.
  ua::AddReferencesResponse add_references_sync(ua::AddReferencesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to add references sync without throwing.
  ua::Result<ua::AddReferencesResponse> try_add_references_sync(ua::AddReferencesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Deletes Nodes from the server AddressSpace (DeleteNodes service).
  void delete_nodes_async(ua::DeleteNodesRequest request,
    std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously delete nodes.
  /// A Good subcode on the answer is not returned; try_delete_nodes_sync() returns it.
  ua::DeleteNodesResponse delete_nodes_sync(ua::DeleteNodesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to delete nodes sync without throwing.
  ua::Result<ua::DeleteNodesResponse> try_delete_nodes_sync(ua::DeleteNodesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Deletes References from the server AddressSpace (DeleteReferences service).
  void delete_references_async(ua::DeleteReferencesRequest request,
    std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously delete references.
  /// A Good subcode on the answer is not returned; try_delete_references_sync() returns it.
  ua::DeleteReferencesResponse delete_references_sync(ua::DeleteReferencesRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to delete references sync without throwing.
  ua::Result<ua::DeleteReferencesResponse> try_delete_references_sync(
    ua::DeleteReferencesRequest request) noexcept;

  /// @param request The request.
  /// @param callback Completion callback that receives the operation result.
  /// Requests cancellation of outstanding requests by request handle (Cancel service).
  void cancel_async(
    ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) noexcept;
  /// @param request The request.
  /// @return The requested value.
  /// Synchronously cancel.
  /// A Good subcode on the answer is not returned; try_cancel_sync() returns it.
  ua::CancelResponse cancel_sync(ua::CancelRequest request);
  /// @param request The request.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to cancel sync without throwing.
  ua::Result<ua::CancelResponse> try_cancel_sync(ua::CancelRequest request) noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::ConnectionHandleFactory;

  explicit ServiceSet(std::shared_ptr<detail::ConnectionImpl> impl);

  std::shared_ptr<detail::ConnectionImpl> mImpl;
};

}  // namespace ua::client

#endif  // UA_SERVICE_SET_H
