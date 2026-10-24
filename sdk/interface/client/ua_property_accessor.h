// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PROPERTY_ACCESSOR_H
#define UA_PROPERTY_ACCESSOR_H

/// @file
/// @brief Tier-2 public generic `PropertyAccessor` explicit override (client design section 8.18.1.d,
/// CL-AC-022): the
///        per-`Connection`, per-NodeId accessor for one-shot Property reads. Its single primitive is Browse
///        one level (`HasProperty`), match a BrowseName, Read the Value Attribute. Returned by
///        `Connection::node(NodeId)`.
/// @ingroup client

#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{

namespace detail
{
class WireOps;
class SupportOps;
struct DataAccessClientTestAccess;
}  // namespace detail

class Connection;

/// A BrowseName is a @ref ua::QualifiedName (a namespace-index + name pair).
using BrowseName = ua::QualifiedName;

/// Callback invoked for data value result notifications.
using DataValueResult = ua::Result<ua::DataValue>;

/// The per-`Connection`, per-NodeId generic Property accessor (client design section 8.18.1.d, CL-AC-022). A
/// lightweight, copyable value handle over the same tier-1 wire interface as its parent @ref Connection,
/// reached via `Connection::node(NodeId)`. It is the one-shot explicit override surfaced by section 8.8's
/// AlarmConditionTracker pass: Browse one level for `HasProperty` children, match the requested BrowseName,
/// Read the matched child's Value Attribute. No child matches  to  `Bad_NotFound`.
///
/// **Status codes.** The Value's DataValue is delivered whole; the Read's ServiceResult is the status of the
/// Result holding it, so a Good subcode or an Uncertain code is kept. The Browse that finds the child is a
/// lookup the next Read depends on, so only a Good answer is used: an Uncertain one is refused with
/// `Bad_InternalError` (`ReferencesAnswerUncertain`). Each `*_sync` form throws unless the Result is Good and
/// puts a Good subcode of the Result on the returned DataValue's status when that is plain Good.
///
/// **Cycle-safe (section 9.8.3).** Holds only `weak_ptr` interface roles (`detail::WireOps` +
/// `detail::SupportOps`), never a `weak_ptr<ConnectionImpl>`: every op locks them and completes
/// `Bad_ConnectionClosed` if the Connection is gone.
///
/// @note The AddressSpaceCache (section 8.7) is not wired here yet, so @ref read_property_uncached_async and
/// the
///       cache-honouring default @ref read_property_async behave identically for now; the cache-aware split
///       is a documented no-op until the cache lands.
/// @ingroup client
class PropertyAccessor
{
public:
  /// Returns or updates the property accessor.
  PropertyAccessor(const PropertyAccessor&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  PropertyAccessor& operator=(const PropertyAccessor&) = default;
  /// Returns or updates the property accessor.
  PropertyAccessor(PropertyAccessor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  PropertyAccessor& operator=(PropertyAccessor&&) noexcept = default;
  ~PropertyAccessor() = default;

  /// CL-AC-022  -  Browse one level (`HasProperty`), match @p propertyName, Read the matched child's Value
  /// @param propertyName The property name.
  /// @param callback Completion callback that receives the operation result.
  /// Attribute. `Bad_NotFound` when no child Property matches. The Result carries the Read's ServiceResult (a
  /// Good subcode or an Uncertain code kept).
  void read_property_async(BrowseName propertyName, std::function<void(DataValueResult)> callback) noexcept;
  /// @param propertyName The propertyname.
  /// @return The requested value.
  /// Synchronously read property. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  ua::DataValue read_property_sync(BrowseName propertyName);
  /// @param propertyName The propertyname.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read property sync without throwing.
  ua::Result<ua::DataValue> try_read_property_sync(BrowseName propertyName) noexcept;

  /// @param path The path.
  /// @param callback Completion callback that receives the operation result.
  /// Multi-hop Property path (e.g. `["ShelvingState", "CurrentState", "Id"]`). Each segment is resolved by a
  /// one-level hierarchical Browse; the final segment's Value Attribute is Read. `Bad_NotFound` when any
  /// segment fails to match. The Result carries the final Read's ServiceResult (a Good subcode or an
  /// Uncertain code kept); an Uncertain Browse answer is refused (`ReferencesAnswerUncertain`).
  void read_property_path_async(
    std::vector<BrowseName> path, std::function<void(DataValueResult)> callback) noexcept;
  /// @param path The path.
  /// @return The requested value.
  /// Synchronously read property path. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  ua::DataValue read_property_path_sync(std::vector<BrowseName> path);
  /// @param path The path.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read property path sync without throwing.
  ua::Result<ua::DataValue> try_read_property_path_sync(std::vector<BrowseName> path) noexcept;

  /// @param propertyName The property name.
  /// @param callback Completion callback that receives the operation result.
  /// The cache-bypassing variant of @ref read_property_async. Identical behaviour until the AddressSpaceCache
  /// (section 8.7) is wired  -  the cache-aware split is a documented no-op for now.
  void read_property_uncached_async(
    BrowseName propertyName, std::function<void(DataValueResult)> callback) noexcept;
  /// @param propertyName The propertyname.
  /// @return The requested value.
  /// Synchronously read property uncached. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  ua::DataValue read_property_uncached_sync(BrowseName propertyName);
  /// @param propertyName The propertyname.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read property uncached sync without throwing.
  ua::Result<ua::DataValue> try_read_property_uncached_sync(BrowseName propertyName) noexcept;

  /// @return The NodeId this accessor targets (empty NodeId when the accessor is a sentinel).
  [[nodiscard]] ua::NodeId node_id() const noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::DataAccessClientTestAccess;

  PropertyAccessor(ua::NodeId nodeId, std::weak_ptr<detail::WireOps> wireOps,
    std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor,
    ua::Logger logger = {});

  ua::NodeId mNodeId;  ///< the NodeId this accessor's Property reads originate from
  std::weak_ptr<detail::WireOps>
    mWireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<detail::SupportOps>
    mSupportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor mExecutor;  ///< where results / boundary failures are delivered
  ua::Logger mLogger;  ///< logs advisory outcomes at the wire boundary (CL-DIAG-002/-015)
};

}  // namespace ua::client

#endif  // UA_PROPERTY_ACCESSOR_H
