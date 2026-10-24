// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side @ref ua::dynamic_types::TypeModelAccess backed by a client Session.
/// @ingroup client

#ifndef UA_SESSION_MODEL_ACCESS_H
#define UA_SESSION_MODEL_ACCESS_H

#include "ua_type_model_access.h"
#include "ua_client_session.h"

namespace ua::dynamic_types
{

/// Client-side @ref TypeModelAccess that reads and browses an information model over a Session.
///
/// Satisfies @ref read_async and @ref browse_async by issuing OPC UA Read, Browse, and
/// BrowseNext service calls on a borrowed client @ref ua::client::Session, adapting the
/// batch-oriented @ref TypeModelAccess contract onto the live service surface.
///
/// Two layers of multiplexing are handled internally and are invisible to callers:
///   - Operation-limit chunking: on first use the server's MaxNodesPerRead /
///     MaxNodesPerBrowse limits are read and cached, then large batches are split across
///     as many service calls as the limits require.
///   - Continuation-point handling: BrowseNext is looped until every continuation point is
///     released, merging the partial responses into one complete BrowseResult per input.
///
/// The object is a borrowing view, not an owner: it holds the Session by reference and does
/// not extend its lifetime. The cached operation limits are mutable state, so a single
/// instance is not safe for concurrent use from multiple threads.
///
/// @note Inherits the @ref TypeModelAccess lifetime contract - the borrowed Session and this
///       object must both outlive every outstanding callback.
/// @ingroup client
class SessionModelAccess : public TypeModelAccess
{
public:
  /// Constructs a model-access view over an existing client Session.
  ///
  /// @param session Session through which Read/Browse/BrowseNext service calls are issued.
  ///                Borrowed by reference and not owned; it must outlive this object and any
  ///                flow it starts. Session is move-only by design, so this view never copies
  ///                or moves it.
  explicit SessionModelAccess(ua::client::Session& session);

  /// Reads one or more attribute values over the Session.
  ///
  /// Issues one or more Read service calls - splitting @p nodesToRead across the server's
  /// MaxNodesPerRead limit when necessary - and reassembles the responses into a single
  /// result, with one @ref ua::DataValue per input in the same order.
  ///
  /// @param nodesToRead Attributes to read; each entry names a NodeId and AttributeId.
  /// @param complete    Receives the outcome on an unspecified worker thread - do not block
  ///                    it. On success the @ref ua::Result holds one @ref ua::DataValue per
  ///                    input, and its status is the Read responses' ServiceResults combined (a
  ///                    Good subcode or an Uncertain code is kept); on failure it carries an
  ///                    @ref ua::ErrorDetail. Never throws.
  void read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete) override;

  /// Browses references from one or more nodes over the Session.
  ///
  /// Issues Browse service calls - splitting @p nodesToBrowse across the server's
  /// MaxNodesPerBrowse limit when necessary - and follows BrowseNext until all continuation
  /// points are released, merging the partial responses into a single result with one
  /// complete @ref ua::BrowseResult per input in the same order.
  ///
  /// @param nodesToBrowse Nodes to browse; each entry names a NodeId, browse direction,
  ///                      reference-type filter, and related options.
  /// @param complete      Receives the outcome on an unspecified worker thread - do not block
  ///                      it. On success the @ref ua::Result holds one @ref ua::BrowseResult
  ///                      per input, and its status is the responses' ServiceResults combined.
  ///                      Each BrowseResult's statusCode is its pages' codes combined; a Bad
  ///                      BrowseNext page ends that node's walk with its code. On failure the
  ///                      Result carries an @ref ua::ErrorDetail. Never throws.
  void browse_async(std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete) override;

private:
  friend class SessionModelAccessTestAccess;

  ua::client::Session* mSession{nullptr};
  uint32_t mMaxNodesPerRead{0};
  uint32_t mMaxNodesPerBrowse{0};
  bool mLimitsRead{false};
};

}  // namespace ua::dynamic_types

#endif  // !UA_SESSION_MODEL_ACCESS_H
