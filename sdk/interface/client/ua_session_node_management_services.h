// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA NodeManagement Service Set on a Session.
/// @ingroup client

#ifndef UA_SESSION_NODE_MANAGEMENT_SERVICES_H
#define UA_SESSION_NODE_MANAGEMENT_SERVICES_H

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_result.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for OPC UA NodeManagement Service Set operations on a Session.
///
/// Provides the AddNodes, AddReferences, DeleteNodes, and DeleteReferences services, which mutate
/// the server's address space. Instances are vended by a @ref Session and hold only a weak reference
/// to the owning session's implementation; they do not extend its lifetime and become inert once the
/// session is gone. Copyable as a lightweight handle.
/// @ingroup client
class SessionNodeManagementServices
{
public:
  // AddNodes

  /// Result of an AddNodes service invocation: an @ref AddNodesResponse, or an @ref ErrorDetail on
  /// failure.
  using AddNodesResponseResult = ua::Result<ua::AddNodesResponse>;
  /// Callback receiving the outcome of @ref add_nodes_async.
  using AddNodesCallback = std::function<void(AddNodesResponseResult)>;

  /// Adds one or more Nodes to the server's address space via the AddNodes service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an unspecified worker
  /// thread, so do not block it. A per-Node status is carried in the response's results - a
  /// successful Result indicates only that the service request itself completed.
  ///
  /// @param request  The AddNodes request listing the Nodes to add. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the @ref AddNodesResponse;
  ///                 on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see add_nodes_sync, try_add_nodes_sync
  void add_nodes_async(ua::AddNodesRequest request, AddNodesCallback callback) noexcept;

  /// Adds one or more Nodes to the server's address space, blocking until complete.
  ///
  /// @param request The AddNodes request listing the Nodes to add. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see add_nodes_async, try_add_nodes_sync
  /// A Good subcode on the answer is not returned; try_add_nodes_sync() returns it.
  ua::AddNodesResponse add_nodes_sync(ua::AddNodesRequest request);

  /// Adds one or more Nodes to the server's address space, blocking until complete.
  ///
  /// @param request The AddNodes request listing the Nodes to add. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see add_nodes_async, add_nodes_sync
  AddNodesResponseResult try_add_nodes_sync(ua::AddNodesRequest request) noexcept;

  // AddReferences

  /// Result of an AddReferences service invocation: an @ref AddReferencesResponse, or an
  /// @ref ErrorDetail on failure.
  using AddReferencesResponseResult = ua::Result<ua::AddReferencesResponse>;
  /// Callback receiving the outcome of @ref add_references_async.
  using AddReferencesCallback = std::function<void(AddReferencesResponseResult)>;

  /// Adds one or more References to the server's address space via the AddReferences service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an unspecified worker
  /// thread, so do not block it. A per-Reference status is carried in the response's results - a
  /// successful Result indicates only that the service request itself completed.
  ///
  /// @param request  The AddReferences request listing the References to add. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref AddReferencesResponse; on failure it carries an @ref ErrorDetail. This
  ///                 overload never throws.
  /// @see add_references_sync, try_add_references_sync
  void add_references_async(ua::AddReferencesRequest request, AddReferencesCallback callback) noexcept;

  /// Adds one or more References to the server's address space, blocking until complete.
  ///
  /// @param request The AddReferences request listing the References to add. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see add_references_async, try_add_references_sync
  /// A Good subcode on the answer is not returned; try_add_references_sync() returns it.
  ua::AddReferencesResponse add_references_sync(ua::AddReferencesRequest request);

  /// Adds one or more References to the server's address space, blocking until complete.
  ///
  /// @param request The AddReferences request listing the References to add. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see add_references_async, add_references_sync
  AddReferencesResponseResult try_add_references_sync(ua::AddReferencesRequest request) noexcept;

  // DeleteNodes

  /// Result of a DeleteNodes service invocation: a @ref DeleteNodesResponse, or an @ref ErrorDetail
  /// on failure.
  using DeleteNodesResponseResult = ua::Result<ua::DeleteNodesResponse>;
  /// Callback receiving the outcome of @ref delete_nodes_async.
  using DeleteNodesCallback = std::function<void(DeleteNodesResponseResult)>;

  /// Removes one or more Nodes from the server's address space via the DeleteNodes service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an unspecified worker
  /// thread, so do not block it. A per-Node status is carried in the response's results - a
  /// successful Result indicates only that the service request itself completed.
  ///
  /// @param request  The DeleteNodes request listing the Nodes to remove. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the @ref DeleteNodesResponse;
  ///                 on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see delete_nodes_sync, try_delete_nodes_sync
  void delete_nodes_async(ua::DeleteNodesRequest request, DeleteNodesCallback callback) noexcept;

  /// Removes one or more Nodes from the server's address space, blocking until complete.
  ///
  /// @param request The DeleteNodes request listing the Nodes to remove. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see delete_nodes_async, try_delete_nodes_sync
  /// A Good subcode on the answer is not returned; try_delete_nodes_sync() returns it.
  ua::DeleteNodesResponse delete_nodes_sync(ua::DeleteNodesRequest request);

  /// Removes one or more Nodes from the server's address space, blocking until complete.
  ///
  /// @param request The DeleteNodes request listing the Nodes to remove. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see delete_nodes_async, delete_nodes_sync
  DeleteNodesResponseResult try_delete_nodes_sync(ua::DeleteNodesRequest request) noexcept;

  // DeleteReferences

  /// Result of a DeleteReferences service invocation: a @ref DeleteReferencesResponse, or an
  /// @ref ErrorDetail on failure.
  using DeleteReferencesResponseResult = ua::Result<ua::DeleteReferencesResponse>;
  /// Callback receiving the outcome of @ref delete_references_async.
  using DeleteReferencesCallback = std::function<void(DeleteReferencesResponseResult)>;

  /// Removes one or more References from the server's address space via the DeleteReferences service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an unspecified worker
  /// thread, so do not block it. A per-Reference status is carried in the response's results - a
  /// successful Result indicates only that the service request itself completed.
  ///
  /// @param request  The DeleteReferences request listing the References to remove. Consumed by
  ///                 value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref DeleteReferencesResponse; on failure it carries an @ref ErrorDetail. This
  ///                 overload never throws.
  /// @see delete_references_sync, try_delete_references_sync
  void delete_references_async(
    ua::DeleteReferencesRequest request, DeleteReferencesCallback callback) noexcept;

  /// Removes one or more References from the server's address space, blocking until complete.
  ///
  /// @param request The DeleteReferences request listing the References to remove. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see delete_references_async, try_delete_references_sync
  /// A Good subcode on the answer is not returned; try_delete_references_sync() returns it.
  ua::DeleteReferencesResponse delete_references_sync(ua::DeleteReferencesRequest request);

  /// Removes one or more References from the server's address space, blocking until complete.
  ///
  /// @param request The DeleteReferences request listing the References to remove. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see delete_references_async, delete_references_sync
  DeleteReferencesResponseResult try_delete_references_sync(ua::DeleteReferencesRequest request) noexcept;

private:
  friend class Session;
  explicit SessionNodeManagementServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_NODE_MANAGEMENT_SERVICES_H
