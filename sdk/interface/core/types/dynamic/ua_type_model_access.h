// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_MODEL_ACCESS_H
#define UA_TYPE_MODEL_ACCESS_H

/// @file
/// @brief Async Read/Browse interface over an OPC UA information model.
/// @ingroup core_types

#include "ua_includes.h"
#include "ua_result.h"
#include "ua_data_value.h"
#include "ua_read_value_id.h"
#include "ua_browse_description.h"
#include "ua_browse_result.h"
#include <functional>
#include <vector>

namespace ua::dynamic_types
{

/// General-purpose async interface for reading attributes and browsing
/// references on an OPC UA information model.
///
/// Mirrors the OPC UA Read and Browse services with a single batched,
/// callback-canonical async operation each. Two implementations are provided:
/// `AddressSpaceModelAccess` reads from a local `AddressSpace` (server-side) and
/// `SessionModelAccess` issues service calls over a `Session` (client-side).
/// Both accept batches so callers can minimise round trips.
///
/// @note Implementations may cache mutable state (for example operation limits
///       read from the server on first use), so a single instance is not safe to
///       call concurrently from multiple threads unless the implementation
///       documents otherwise.
/// @warning The caller must keep the `TypeModelAccess` alive until every
///          outstanding callback has fired.
/// @ingroup core_types
class TypeModelAccess
{
public:
  /// Callback for @ref read_async; on success the Result holds one @ref DataValue
  /// per requested @ref ReadValueId in request order, on failure it carries an
  /// @ref ErrorDetail. The invocation never throws.
  using ReadCallback = std::function<void(ua::Result<std::vector<ua::DataValue>>)>;

  /// Callback for @ref browse_async; on success the Result holds one
  /// @ref BrowseResult per requested @ref BrowseDescription in request order, on
  /// failure it carries an @ref ErrorDetail. The invocation never throws.
  using BrowseCallback = std::function<void(ua::Result<std::vector<ua::BrowseResult>>)>;

  virtual ~TypeModelAccess() = default;

  /// Deleted: this is a polymorphic interface, held by reference or `shared_ptr` and never
  /// value-copied; deleting copy and move prevents accidental slicing.
  TypeModelAccess(const TypeModelAccess&) = delete;
  TypeModelAccess& operator=(const TypeModelAccess&) = delete;
  TypeModelAccess(TypeModelAccess&&) = delete;
  TypeModelAccess& operator=(TypeModelAccess&&) = delete;

protected:
  /// Protected default constructor: the deleted copy/move members above suppress the
  /// implicit default ctor, but derived classes must be able to construct this base.
  TypeModelAccess() = default;

public:
  /// Reads one or more attribute values.
  ///
  /// Each @ref ReadValueId names a target NodeId and AttributeId. Completes
  /// asynchronously: the callback runs on an unspecified worker thread, so do not
  /// block it.
  ///
  /// @param nodesToRead Attributes to read; the result preserves this order.
  /// @param complete    Receives the outcome. On success the Result holds one
  ///                    @ref DataValue per entry in @p nodesToRead, in the same
  ///                    order; on failure it carries an @ref ErrorDetail. This
  ///                    overload never throws.
  virtual void read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete) = 0;

  /// Browses references from one or more nodes.
  ///
  /// Each @ref BrowseDescription names a starting NodeId, browse direction,
  /// reference-type filter and result mask. Completes asynchronously: the
  /// callback runs on an unspecified worker thread, so do not block it.
  ///
  /// @param nodesToBrowse Nodes to browse; the result preserves this order.
  /// @param complete      Receives the outcome. On success the Result holds one
  ///                      @ref BrowseResult per entry in @p nodesToBrowse, in the
  ///                      same order; on failure it carries an @ref ErrorDetail.
  ///                      This overload never throws.
  virtual void browse_async(std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete) = 0;
};

}  // namespace ua::dynamic_types

#endif  // !UA_TYPE_MODEL_ACCESS_H
