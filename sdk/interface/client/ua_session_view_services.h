// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA View Service Set (Browse, Register/Unregister Nodes).
/// @ingroup client

#ifndef UA_SESSION_VIEW_SERVICES_H
#define UA_SESSION_VIEW_SERVICES_H

#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for OPC UA View Service Set operations on a Session.
///
/// Groups the View Service Set requests - Browse, BrowseNext, TranslateBrowsePathsToNodeIds,
/// RegisterNodes and UnregisterNodes - exposed by an owning @ref Session. The accessor holds
/// only a weak reference to the session implementation and does not extend its lifetime; calling
/// any operation after the owning session has been destroyed fails with an @ref ErrorDetail (or
/// throws, for the `*_sync` variants) rather than dangling. Obtain an instance from the session;
/// it is not independently constructible.
/// @ingroup client
class SessionViewServices
{
public:
  // Browse

  /// Result of a Browse operation: a @ref BrowseResponse on success, an @ref ErrorDetail on failure.
  using BrowseResponseResult = ua::Result<ua::BrowseResponse>;
  /// Callback invoked with the outcome of @ref browse_async.
  using BrowseCallback = std::function<void(BrowseResponseResult)>;

  /// Browses references of one or more nodes.
  ///
  /// Sends the Browse request to the server and completes asynchronously. The callback runs on an
  /// unspecified worker thread once the response arrives - do not block it.
  ///
  /// @param request  The Browse request describing the nodes and the references to follow.
  /// @param callback Receives the outcome: on success the @ref Result holds a @ref BrowseResponse;
  ///                 on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see browse_sync, try_browse_sync
  void browse_async(ua::BrowseRequest request, BrowseCallback callback) noexcept;

  /// Browses references of one or more nodes, blocking until the response arrives.
  ///
  /// @param request The Browse request describing the nodes and the references to follow.
  /// @return The Browse response.
  /// @throws UaException if the request fails or the owning session is no longer alive.
  /// @see browse_async, try_browse_sync
  /// A Good subcode on the answer is not returned; try_browse_sync() returns it.
  ua::BrowseResponse browse_sync(ua::BrowseRequest request);

  /// Browses references of one or more nodes, blocking until the response arrives.
  ///
  /// @param request The Browse request describing the nodes and the references to follow.
  /// @return The Browse response, or an @ref ErrorDetail on failure. Never throws.
  /// @see browse_async, browse_sync
  BrowseResponseResult try_browse_sync(ua::BrowseRequest request) noexcept;

  // BrowseNext

  /// Result of a BrowseNext operation: a @ref BrowseNextResponse on success, an @ref ErrorDetail
  /// on failure.
  using BrowseNextResponseResult = ua::Result<ua::BrowseNextResponse>;
  /// Callback invoked with the outcome of @ref browse_next_async.
  using BrowseNextCallback = std::function<void(BrowseNextResponseResult)>;

  /// Continues a Browse that returned a continuation point.
  ///
  /// Requests the next batch of references for a Browse whose result set exceeded the server's
  /// limit. Completes asynchronously; the callback runs on an unspecified worker thread once the
  /// response arrives - do not block it.
  ///
  /// @param request  The BrowseNext request carrying the continuation point(s) to resume from.
  /// @param callback Receives the outcome: on success the @ref Result holds a
  ///                 @ref BrowseNextResponse; on failure it carries an @ref ErrorDetail. This
  ///                 overload never throws.
  /// @see browse_next_sync, try_browse_next_sync
  void browse_next_async(ua::BrowseNextRequest request, BrowseNextCallback callback) noexcept;

  /// Continues a Browse that returned a continuation point, blocking until the response arrives.
  ///
  /// @param request The BrowseNext request carrying the continuation point(s) to resume from.
  /// @return The BrowseNext response.
  /// @throws UaException if the request fails or the owning session is no longer alive.
  /// @see browse_next_async, try_browse_next_sync
  /// A Good subcode on the answer is not returned; try_browse_next_sync() returns it.
  ua::BrowseNextResponse browse_next_sync(ua::BrowseNextRequest request);

  /// Continues a Browse that returned a continuation point, blocking until the response arrives.
  ///
  /// @param request The BrowseNext request carrying the continuation point(s) to resume from.
  /// @return The BrowseNext response, or an @ref ErrorDetail on failure. Never throws.
  /// @see browse_next_async, browse_next_sync
  BrowseNextResponseResult try_browse_next_sync(ua::BrowseNextRequest request) noexcept;

  // TranslateBrowsePathsToNodeIds

  /// Result of a TranslateBrowsePathsToNodeIds operation: a
  /// @ref TranslateBrowsePathsToNodeIdsResponse on success, an @ref ErrorDetail on failure.
  using TranslateResponseResult = ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>;
  /// Callback invoked with the outcome of @ref translate_browse_paths_async.
  using TranslateCallback = std::function<void(TranslateResponseResult)>;

  /// Translates relative browse paths into the target node ids.
  ///
  /// Resolves each browse path (a starting node plus a sequence of relative reference steps) to the
  /// node id(s) it reaches. Completes asynchronously; the callback runs on an unspecified worker
  /// thread once the response arrives - do not block it.
  ///
  /// @param request  The request listing the browse paths to translate.
  /// @param callback Receives the outcome: on success the @ref Result holds a
  ///                 @ref TranslateBrowsePathsToNodeIdsResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see translate_browse_paths_sync, try_translate_browse_paths_sync
  void translate_browse_paths_async(
    ua::TranslateBrowsePathsToNodeIdsRequest request, TranslateCallback callback) noexcept;

  /// Translates relative browse paths into the target node ids, blocking until complete.
  ///
  /// @param request The request listing the browse paths to translate.
  /// @return The TranslateBrowsePathsToNodeIds response.
  /// @throws UaException if the request fails or the owning session is no longer alive.
  /// @see translate_browse_paths_async, try_translate_browse_paths_sync
  /// A Good subcode on the answer is not returned; try_translate_browse_paths_sync() returns it.
  ua::TranslateBrowsePathsToNodeIdsResponse translate_browse_paths_sync(
    ua::TranslateBrowsePathsToNodeIdsRequest request);

  /// Translates relative browse paths into the target node ids, blocking until complete.
  ///
  /// @param request The request listing the browse paths to translate.
  /// @return The TranslateBrowsePathsToNodeIds response, or an @ref ErrorDetail on failure. Never
  ///         throws.
  /// @see translate_browse_paths_async, translate_browse_paths_sync
  TranslateResponseResult try_translate_browse_paths_sync(
    ua::TranslateBrowsePathsToNodeIdsRequest request) noexcept;

  // RegisterNodes

  /// Result of a RegisterNodes operation: a @ref RegisterNodesResponse on success, an
  /// @ref ErrorDetail on failure.
  using RegisterNodesResponseResult = ua::Result<ua::RegisterNodesResponse>;
  /// Callback invoked with the outcome of @ref register_nodes_async.
  using RegisterNodesCallback = std::function<void(RegisterNodesResponseResult)>;

  /// Registers nodes for optimised repeated access.
  ///
  /// Asks the server to return handle node ids that address the given nodes more efficiently on
  /// subsequent service calls. The registration is valid only for the lifetime of the session and
  /// the returned node ids must not be persisted. Completes asynchronously; the callback runs on an
  /// unspecified worker thread once the response arrives - do not block it.
  ///
  /// @param request  The request listing the nodes to register.
  /// @param callback Receives the outcome: on success the @ref Result holds a
  ///                 @ref RegisterNodesResponse; on failure it carries an @ref ErrorDetail. This
  ///                 overload never throws.
  /// @see register_nodes_sync, try_register_nodes_sync, unregister_nodes_async
  void register_nodes_async(ua::RegisterNodesRequest request, RegisterNodesCallback callback) noexcept;

  /// Registers nodes for optimised repeated access, blocking until complete.
  ///
  /// @param request The request listing the nodes to register.
  /// @return The RegisterNodes response holding the registered node ids.
  /// @throws UaException if the request fails or the owning session is no longer alive.
  /// @see register_nodes_async, try_register_nodes_sync
  /// A Good subcode on the answer is not returned; try_register_nodes_sync() returns it.
  ua::RegisterNodesResponse register_nodes_sync(ua::RegisterNodesRequest request);

  /// Registers nodes for optimised repeated access, blocking until complete.
  ///
  /// @param request The request listing the nodes to register.
  /// @return The RegisterNodes response holding the registered node ids, or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see register_nodes_async, register_nodes_sync
  RegisterNodesResponseResult try_register_nodes_sync(ua::RegisterNodesRequest request) noexcept;

  // UnregisterNodes

  /// Result of an UnregisterNodes operation: an @ref UnregisterNodesResponse on success, an
  /// @ref ErrorDetail on failure.
  using UnregisterNodesResponseResult = ua::Result<ua::UnregisterNodesResponse>;
  /// Callback invoked with the outcome of @ref unregister_nodes_async.
  using UnregisterNodesCallback = std::function<void(UnregisterNodesResponseResult)>;

  /// Releases nodes previously registered with @ref register_nodes_async.
  ///
  /// Tells the server that the registered node ids are no longer needed, allowing it to free the
  /// associated resources. Completes asynchronously; the callback runs on an unspecified worker
  /// thread once the response arrives - do not block it.
  ///
  /// @param request  The request listing the registered node ids to release.
  /// @param callback Receives the outcome: on success the @ref Result holds an
  ///                 @ref UnregisterNodesResponse; on failure it carries an @ref ErrorDetail. This
  ///                 overload never throws.
  /// @see unregister_nodes_sync, try_unregister_nodes_sync, register_nodes_async
  void unregister_nodes_async(ua::UnregisterNodesRequest request, UnregisterNodesCallback callback) noexcept;

  /// Releases nodes previously registered with @ref register_nodes_sync, blocking until complete.
  ///
  /// @param request The request listing the registered node ids to release.
  /// @return The UnregisterNodes response.
  /// @throws UaException if the request fails or the owning session is no longer alive.
  /// @see unregister_nodes_async, try_unregister_nodes_sync
  /// A Good subcode on the answer is not returned; try_unregister_nodes_sync() returns it.
  ua::UnregisterNodesResponse unregister_nodes_sync(ua::UnregisterNodesRequest request);

  /// Releases nodes previously registered with @ref register_nodes_sync, blocking until complete.
  ///
  /// @param request The request listing the registered node ids to release.
  /// @return The UnregisterNodes response, or an @ref ErrorDetail on failure. Never throws.
  /// @see unregister_nodes_async, unregister_nodes_sync
  UnregisterNodesResponseResult try_unregister_nodes_sync(ua::UnregisterNodesRequest request) noexcept;

private:
  friend class Session;
  explicit SessionViewServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_VIEW_SERVICES_H
