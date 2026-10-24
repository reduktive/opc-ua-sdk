// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A single typed reference and the zero-copy collection that holds them.
/// @ingroup address_space

#ifndef UA_REFERENCE_H
#define UA_REFERENCE_H

#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"

#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace ua
{

/// A directed, typed edge between two nodes in the address space.
///
/// A reference connects a source node to a target node via a reference type
/// (e.g. @c HasComponent, @c Organizes) and records the direction in which the
/// edge is traversed. The source node is implied by the context that owns the
/// reference; only the reference type, the target, and the direction are stored.
///
/// @ingroup address_space
class Reference
{
public:
  /// Constructs an empty reference with default type and target and a forward direction.
  Reference() = default;

  /// Constructs a reference of the given type to the given target.
  ///
  /// @param[in] type      Reference-type node id (e.g. @c HasComponent).
  /// @param[in] target    Target node, which may be local or remote.
  /// @param[in] isForward         @c true for a forward edge from source to target;
  ///                              @c false for the inverse edge.
  /// @param[in] targetDisplayName DisplayName supplied by the authority for a remote target. Local
  ///                              targets normally omit it because Browse resolves their attributes.
  Reference(NodeId type, ExpandedNodeId target, bool isForward,
    std::optional<LocalizedText> targetDisplayName = std::nullopt);

  /// Compares two references for equality of type, target, and direction.
  ///
  /// @param other The reference to compare against.
  /// @return @c true if both references have the same type, target, and direction.
  bool operator==(const Reference& other) const;

  /// Whether this and @p other are the same Reference of one source Node, as OPC 10000-3 section 4.3.4
  /// identifies References: the same direction and target, and the same ReferenceType once a subtype of a
  /// concrete namespace-0 ReferenceType is taken as its base concrete type (@ref reference_identity_type).
  /// A HasOrderedComponent and a HasComponent to one target are the same Reference; an application
  /// ReferenceType is compared by its NodeId.
  ///
  /// @param other The reference to compare against.
  /// @return @c true if a source Node may hold only one of the two.
  bool identifies_same_reference_as(const Reference& other) const;

  /// Returns @c true if this is a forward edge, @c false if it is the inverse edge.
  ///
  /// @return @c true for a forward edge from source to target; @c false for the inverse edge.
  bool is_forward() const
  {
    return mIsForward;
  }

  /// Returns @c true if the target lives in a remote server or namespace.
  ///
  /// Equivalent to @c target_id().is_remote(); a remote target has a non-zero server index.
  ///
  /// @return @c true if the target has a non-zero server index (a remote server/namespace).
  bool is_remote() const
  {
    return mTarget.is_remote();
  }

  /// Returns the reference-type node id (e.g. @c HasComponent, @c Organizes).
  ///
  /// The returned reference is valid for the lifetime of this object.
  ///
  /// @return The reference-type node id.
  const NodeId& type_id() const
  {
    return mType;
  }

  /// Returns the target the reference points to.
  ///
  /// The returned reference is valid for the lifetime of this object.
  ///
  /// @return The reference's target node.
  const ExpandedNodeId& target_id() const
  {
    return mTarget;
  }

  /// Returns authority-supplied DisplayName metadata for the target, when available.
  ///
  /// This metadata is primarily used for remote targets, whose attributes cannot be resolved from
  /// the local address space. It is not part of reference identity.
  ///
  /// @return The target DisplayName, or @c std::nullopt when none was supplied.
  const std::optional<LocalizedText>& target_display_name() const
  {
    return mTargetDisplayName;
  }

private:
  NodeId mType;
  ExpandedNodeId mTarget;
  std::optional<LocalizedText> mTargetDisplayName;
  bool mIsForward{true};
};

/// A zero-copy, immutable collection of references over shared storage.
///
/// The references are held in a @c shared_ptr<const std::vector<Reference>>, so
/// copying a @ref References shares ownership of the underlying storage rather
/// than duplicating it. For in-memory namespaces this points directly at the
/// copy-on-write node storage, so iterating involves no copy. For
/// database/remote namespaces the vector is materialized from query results and
/// owned by the collection. Instances are lightweight value handles and are safe
/// to copy and pass across threads.
/// @ingroup address_space
class References
{
public:
  /// Constructs an empty collection backed by no storage.
  References() = default;

  /// Constructs a view that shares ownership of existing reference storage.
  ///
  /// No references are copied; the collection holds a second owner of @p storage.
  ///
  /// @param[in] storage Shared, immutable reference storage to view.
  explicit References(std::shared_ptr<const std::vector<Reference>> storage);

  /// Constructs a collection that takes ownership of a newly-built vector.
  ///
  /// @param[in] owned Reference vector to adopt as the backing storage.
  explicit References(std::vector<Reference> owned);

  /// Returns a sub-range view that shares the same backing storage.
  ///
  /// No references are copied; the returned collection refers to the same
  /// storage, narrowed to the requested window. A window that runs past the end
  /// of the storage is clamped to the available references.
  ///
  /// @param[in] offset Index of the first reference to include, from the start
  ///                   of this collection's window.
  /// @param[in] count  Number of references to include.
  /// @return A collection viewing references in @c [offset, offset + count).
  References slice(uint32_t offset, uint32_t count) const;

  /// Returns a contiguous, non-owning view of the references in this collection.
  ///
  /// The span is valid only while this collection (and therefore its backing
  /// storage) is alive.
  ///
  /// @return A span over the references in this collection's window.
  std::span<const Reference> span() const;

  /// Returns an iterator to the first reference.
  ///
  /// @return An iterator to the first reference, or the end iterator when empty.
  auto begin() const
  {
    return mStorage ? span().begin() : std::span<const Reference>{}.begin();
  }

  /// Returns an iterator one past the last reference.
  ///
  /// @return An iterator one past the last reference.
  auto end() const
  {
    return mStorage ? span().end() : std::span<const Reference>{}.end();
  }

  /// Returns @c true if the collection holds no references.
  ///
  /// @return @c true when the collection has no backing storage or an empty window.
  bool empty() const
  {
    return !mStorage || span().empty();
  }

  /// Returns the number of references in the collection.
  ///
  /// @return The number of references in this collection's window.
  size_t size() const
  {
    return mStorage ? span().size() : 0;
  }

private:
  std::shared_ptr<const std::vector<Reference>> mStorage;
  uint32_t mOffset{0};
  uint32_t mCount{0};  // 0 = all from offset to end
};

}  // namespace ua

#endif  // UA_REFERENCE_H
