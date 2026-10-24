// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Free-function helpers for reading, writing, and classifying address-space nodes.
/// @ingroup address_space

#ifndef UA_NODE_UTILITIES_H
#define UA_NODE_UTILITIES_H

#include "ua_includes.h"
#include "ua_node.h"
#include "ua_attribute_id.h"
#include "ua_timestamps_to_return.h"
#include "ua_browse_direction.h"
#include "ua_node_accessor.h"
#include "ua_encoding_limits.h"

#include <mutex>
#include <optional>
#include <unordered_map>

namespace ua
{

class Variant;
class AddNodeItem;

namespace node_utils
{

/// Hash functor for an ordered pair of @ref NodeId values.
///
/// Combines the two element hashes into a single bucket index so that
/// `(refTypeId, typeId)` keys can be stored in an unordered container.
/// @ingroup address_space
struct NodeIdPairHash
{
  /// Returns a combined hash of the pair's two @ref NodeId elements.
  ///
  /// @param pair The (first, second) NodeId pair to hash; order is significant.
  /// @return A bucket-index hash mixing both element hashes.
  size_t operator()(const std::pair<NodeId, NodeId>& pair) const
  {
    auto h1 = std::hash<NodeId>{}(pair.first);
    auto h2 = std::hash<NodeId>{}(pair.second);
    // The 64-bit mix constant widens the expression to unsigned long long; narrowing the final bucket
    // index back to size_t is intended (a no-op on 64-bit, a deliberate fold on 32-bit where size_t is
    // 32-bit), make it explicit so -Werror=conversion is satisfied on the 32-bit matrix cells.
    return static_cast<size_t>(h1 ^ (h2 * 0x9e3779b97f4a7c15ULL + 0x9e3779b9 + (h1 << 6) + (h1 >> 2)));
  }
};

/// Internally-synchronised memoisation cache for reference-type subtype checks.
///
/// Keyed on `(refTypeId, typeId)` with the cached is-subtype-of result. @ref is_ref_of_type_cached_async
/// looks the key up on the caller's executor but, on a miss, stores the walk's result from the walk's
/// completion which runs on a DIFFERENT executor (the address-space pool, not the caller's strand). With
/// concurrent operations sharing one cache, a `find` on one executor races an `emplace` on another, so
/// the map must be synchronised (concurrent `std::unordered_map` access is UB - rehash/iterator
/// corruption). Held via `std::shared_ptr` and captured BY VALUE into the async walk so the cache
/// outlives any in-flight walk even if the owning service/AddressSpace is destroyed mid-walk (otherwise
/// a use-after-free). `lookup`/`store` release the lock before returning so callers never invoke a
/// continuation under it.
/// @ingroup address_space
class RefTypeCache
{
public:
  /// Returns the cached result for @p key, or `nullopt` if not yet memoised.
  ///
  /// @param key The `(refTypeId, typeId)` pair to look up.
  /// @return The memoised is-subtype-of result, or `std::nullopt` when the key is not cached.
  std::optional<bool> lookup(const std::pair<NodeId, NodeId>& key) const
  {
    const std::lock_guard lock(mMutex);
    const auto it = mEntries.find(key);
    return it == mEntries.end() ? std::nullopt : std::optional<bool>{it->second};
  }

  /// Memoises @p value for @p key (first writer wins; concurrent stores of the same key are idempotent).
  ///
  /// @param key   The `(refTypeId, typeId)` pair to memoise.
  /// @param value The is-subtype-of result to cache for @p key.
  void store(const std::pair<NodeId, NodeId>& key, bool value)
  {
    const std::lock_guard lock(mMutex);
    mEntries.emplace(key, value);
  }

private:
  mutable std::mutex mMutex;
  std::unordered_map<std::pair<NodeId, NodeId>, bool, NodeIdPairHash> mEntries;
};

/// Reads a node attribute synchronously into a `DataValue`.
///
/// Materialises the attribute from @p node, applying @p timestamps to control
/// which timestamps the returned value carries and resolving any localised text
/// against @p locales (falling back to @p defaultLocale). Operates directly on
/// the accessor and does not post to an address-space strand.
///
/// @param node          Accessor for the node whose attribute is read.
/// @param id            Attribute to read.
/// @param timestamps    Which timestamps (source/server) to include in the result.
/// @param locales       Preferred locales, in priority order, for localised attributes.
/// @param defaultLocale Locale used when none of @p locales matches.
/// @return The attribute value; a bad `StatusCode` is carried in the DataValue
///         when the attribute is unreadable.
/// @throws UaException if the attribute is not valid for the node's class.
DataValue read_node_sync_attribute(const NodeAccessor& node, AttributeId id, TimestampsToReturn timestamps,
  span<const LocaleId> locales, const LocaleId& defaultLocale);

/// Returns whether @p timestamps requests the source timestamp.
///
/// @param timestamps The TimestampsToReturn selector to test.
/// @return `true` if the source timestamp should be returned, otherwise `false`.
/// @see server_timestamp
bool source_timestamp(TimestampsToReturn timestamps);

/// Returns whether @p timestamps requests the server timestamp.
///
/// @param timestamps The TimestampsToReturn selector to test.
/// @return `true` if the server timestamp should be returned, otherwise `false`.
/// @see source_timestamp
bool server_timestamp(TimestampsToReturn timestamps);

/// Returns the immediate supertype of a type node, blocking until its references are read.
///
/// Resolves the `HasSubtype` inverse reference on @p node through `get_references_sync`, so it waits on
/// the node's namespace. For application threads only: SDK-internal code, which runs on SDK executors
/// and strands, uses `get_super_type_async`, because a namespace that answers by posting to the waiting
/// strand would never answer.
///
/// @param node Accessor for the type node whose supertype is read.
/// @return The supertype's `ExpandedNodeId`.
/// @throws UaException `Bad_InvalidArgument` if @p node is not a type node, `Bad_NotFound` if it has no
///         supertype.
/// @see get_super_type_async
ExpandedNodeId get_super_type_id(const NodeAccessor& node);

/// Returns the type-definition target of an instance node, blocking until its references are read.
///
/// Resolves the `HasTypeDefinition` forward reference on @p node through `get_references_sync`. For
/// application threads only; SDK-internal code uses `get_type_definition_async`.
///
/// @param node Accessor for the instance node whose type definition is read.
/// @return The type definition's `ExpandedNodeId`, or a null id if @p node has none.
/// @see get_type_definition_async
ExpandedNodeId get_type_definition_id(const NodeAccessor& node);

/// Result delivered by `get_type_definition_async`: the type definition's id (null when the node has
/// none), or the reason the node's references could not be read.
using ExpandedNodeIdResult = Result<ExpandedNodeId>;

/// Resolves the type-definition target of an instance node without blocking.
///
/// Reads @p node's references with `get_references_async` and delivers the `HasTypeDefinition` forward
/// target. Completes inline when the namespace answers inline, otherwise on the thread its answer
/// arrives on - do not block the callback.
///
/// @param node     Accessor for the instance node whose type definition is read.
/// @param callback Receives the type definition's `ExpandedNodeId` (null when there is none) with the code
///                 the namespace answered the References read with (a Good subcode, or an Uncertain code
///                 with the References it held, is kept), or the status and `ErrorDetail` of a read that
///                 answered no References.
/// @see get_type_definition_id
void get_type_definition_async(const NodeAccessor& node, std::function<void(ExpandedNodeIdResult)> callback);

/// Result delivered by `get_super_type_async` - an accessor for the supertype, if any.
///
/// On success the `Result` holds an engaged optional with the supertype's
/// accessor, or a disengaged optional when the node has no supertype; on failure
/// it carries an `ErrorDetail`.
using OptionalNodeAccessorResult = Result<optional<NodeAccessor>>;

/// Resolves the immediate supertype of a type node without blocking.
///
/// Reads @p type's references with `get_references_async` and resolves the `HasSubtype` inverse target
/// with `find_node_async`, so a type served by any namespace can be climbed from an SDK strand. Completes
/// inline when both answer inline, otherwise on the thread the last answer arrives on - do not block the
/// callback. A node that is not a type, or a type with no supertype, ends the walk (a disengaged optional).
///
/// @param addressSpace Address space owning @p type.
/// @param type         Accessor for the type node whose supertype is resolved.
/// @param callback     Receives `OptionalNodeAccessorResult` - an accessor for the supertype
///                     (disengaged when there is none) with the code the namespace answered the
///                     References read and the supertype's lookup with, combined by
///                     `detail::combined_status` (a Good subcode, or an Uncertain code with the data it
///                     held, is kept); otherwise the failure with its `ErrorDetail`. This overload never
///                     throws.
/// @see get_super_type_id
void get_super_type_async(
  AddressSpace addressSpace, NodeAccessor type, std::function<void(OptionalNodeAccessorResult)> callback);

/// Tests asynchronously whether a reference type is (a subtype of) a given type.
///
/// Walks the `HasSubtype` hierarchy from @p refId toward @p typeId on the owning
/// namespace's strand, then completes on an unspecified worker thread - do not
/// block the callback.
///
/// @param limits       Encoding limits bounding the hierarchy walk.
/// @param addressSpace Address space owning the reference and type nodes.
/// @param allowSubTypes When `true`, @p refId matches if it is @p typeId or any
///                      subtype of it; when `false`, only an exact match counts.
/// @param refId        Reference-type NodeId under test.
/// @param typeId       Target reference-type NodeId to match against.
/// @param callback     Receives the `BoolResult` - `true` when @p refId matches,
///                     or an `ErrorDetail` on failure. The walk does not act on an answer the
///                     namespace is uncertain of: an Uncertain lookup is answered `Bad_InternalError`
///                     (`LookupAnswerUncertain`) with the Uncertain code as its cause. This overload
///                     never throws.
/// @see is_ref_of_type_cached_async
void is_ref_of_type_async(ua::EncodingLimits limits, AddressSpace addressSpace, bool allowSubTypes,
  NodeId refId, NodeId typeId, std::function<void(BoolResult)> callback);

/// Tests whether a reference type matches a given type, memoising the result.
///
/// Behaves like `is_ref_of_type_async` but consults and populates @p cache so
/// repeated checks within one request skip re-walking the hierarchy. Completes on
/// an unspecified worker thread - do not block the callback.
///
/// @param limits       Encoding limits bounding the hierarchy walk.
/// @param addressSpace Address space owning the reference and type nodes.
/// @param allowSubTypes When `true`, @p refId matches if it is @p typeId or any
///                      subtype of it; when `false`, only an exact match counts.
/// @param refId        Reference-type NodeId under test.
/// @param typeId       Target reference-type NodeId to match against.
/// @param cache        Internally-synchronised, shared cache. Held by `shared_ptr` and captured by value
///                     into the async walk so it outlives the call even if the owning component is
///                     destroyed mid-walk; safe to share across concurrent operations.
/// @param callback     Receives the `BoolResult` - `true` when @p refId matches,
///                     or an `ErrorDetail` on failure. This overload never throws.
/// @see is_ref_of_type_async
void is_ref_of_type_cached_async(ua::EncodingLimits limits, AddressSpace addressSpace, bool allowSubTypes,
  NodeId refId, NodeId typeId, std::shared_ptr<RefTypeCache> cache, std::function<void(BoolResult)> callback);

/// Returns whether a reference matches a requested browse direction.
///
/// @param direction Browse direction filter (Forward, Inverse, or Both).
/// @param reference Reference to test against @p direction.
/// @return `true` if @p reference should be included for @p direction, otherwise `false`.
bool filter_reference_direction(BrowseDirection direction, const Reference& reference);

/// Encodes an attribute's new value exactly as the typed `NodeAccessor` setter for @p id does, except that an
/// empty ArrayDimensions array is encoded as null, which it means (Part 6 5.1.9).
///
/// Checks that @p id is writable through the attribute path and valid for @p node's class, extracts the
/// typed value from @p value, and returns the wire form an attribute write carries. The one
/// mapping behind both `write_node_sync_attribute` and `write_node_attribute_async`.
///
/// @param node  Accessor for the node the attribute belongs to.
/// @param id    Attribute to encode; the Value attribute only for a VariableType, whose Value is part of
///              its description (a Variable's is written through `VariableAccessor::write_value_async`).
/// @param value New attribute value, whose type must match @p id.
/// @return The encoded value, or `Bad_AttributeIdInvalid` / a type-mismatch status with an `ErrorDetail`.
Result<Variant> encode_writable_attribute(
  const NodeAccessor& node, AttributeId id, const Variant& value) noexcept;

/// Writes an attribute on a node from a `Variant`, blocking until the node's namespace answers.
///
/// For application threads only. SDK-internal code, which runs on SDK executors and strands, uses
/// `write_node_attribute_async`: a namespace that answers by posting to the waiting strand would never
/// answer.
///
/// @param node  Accessor for the node to modify.
/// @param id    Attribute to write; the Value attribute only for a VariableType.
/// @param value New attribute value, whose type must match @p id.
/// @throws UaException on type mismatch, if @p id is not valid for the node's class, or if the write fails.
/// @see write_node_attribute_async
void write_node_sync_attribute(NodeAccessor& node, AttributeId id, const Variant& value);

/// Writes an attribute on a node from a `Variant` without blocking.
///
/// Encodes @p value with `encode_writable_attribute` and writes it through
/// `NodeAccessor::write_attribute_async`, which calls the owning namespace's `write_async`. Completes inline
/// when the namespace answers inline, otherwise on the thread its answer arrives on - do not block the
/// callback.
///
/// @param node     Accessor for the node to modify.
/// @param id       Attribute to write; the Value attribute only for a VariableType.
/// @param value    New attribute value, whose type must match @p id.
/// @param callback Receives the write's outcome, or the encoding refusal.
/// @see encode_writable_attribute
void write_node_attribute_async(
  NodeAccessor node, AttributeId id, const Variant& value, std::function<void(VoidResult)> callback) noexcept;

}  // namespace node_utils

}  // namespace ua

#endif  // UA_NODE_UTILITIES_H
