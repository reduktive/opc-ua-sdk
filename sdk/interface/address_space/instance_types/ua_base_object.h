// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Handle to an Object node typed as the base `BaseObjectType` (i=58).
/// @ingroup address_space

#ifndef UA_BASE_OBJECT_H
#define UA_BASE_OBJECT_H

#include "ua_includes.h"
#include "ua_address_space.h"
#include "ua_instantiation_options.h"
#include "ua_node_subtree.h"
#include "ua_result.h"

#include <functional>

namespace ua
{

class BaseObject;

/// Result holding a `BaseObject` handle.
///
/// Some generated instance handles expose child accessors whose declared type
/// definition is `BaseObjectType` (i=58) - the hand-written `BaseObject`
/// class - and the generated `<ChildClass>Result` template needs this matching
/// alias to compile.
using BaseObjectResult = Result<BaseObject>;

/// Handle to an Object node whose type definition is the base `BaseObjectType`
/// (i=58).
///
/// Wraps an existing or freshly instantiated Object node together with the
/// @ref AddressSpace it lives in. When the handle owns the node subtree it
/// created, destroying the handle without first calling @ref release removes
/// that subtree from the address space; an attached handle (see
/// @ref attach_async) owns nothing and only references the node.
///
/// Move-only: copying would duplicate ownership of the underlying subtree. This
/// type serves both as a usable handle and as the base class for generated,
/// strongly typed Object handles, which call @ref create_object_impl_async to
/// instantiate.
/// @ingroup address_space
class BaseObject
{
public:
  /// Constructs an empty handle that references no node.
  BaseObject() = default;

  virtual ~BaseObject() = default;

  BaseObject(const BaseObject&) = delete;
  BaseObject& operator=(const BaseObject&) = delete;

  /// Transfers ownership of the referenced node and any owned subtree from the
  /// moved-from handle, leaving it empty.
  BaseObject(BaseObject&&) noexcept = default;

  /// Transfers ownership of the referenced node and any owned subtree from the
  /// moved-from handle, leaving it empty.
  ///
  /// @return Reference to this handle after the move.
  BaseObject& operator=(BaseObject&&) noexcept = default;

  /// Returns the NodeId of the referenced Object node.
  ///
  /// The reference is valid for the lifetime of this handle.
  ///
  /// @return The NodeId of the referenced node; a null NodeId when the handle is empty.
  const NodeId& node_id() const;

  /// Releases ownership of the node subtree this handle created.
  ///
  /// After this call the underlying node remains in the address space but is no
  /// longer owned by the handle, so destroying the handle will not remove it.
  /// A no-op on an attached handle (see @ref attach_async) or one that owns no
  /// subtree.
  void release();

  /// Outcome payload for a successful Object instantiation.
  struct CreateResultData
  {
    AddressSpace addressSpace;  ///< Address space the new node was created in.
    NodeId nodeId;  ///< NodeId of the newly created Object node.
    NodeSubtree subtree;  ///< Owned subtree rooted at the new node.
  };

  /// Result carrying the outcome of an Object instantiation.
  using CreateResult = Result<CreateResultData>;

  /// Callback receiving the @ref CreateResult of @ref create_object_impl_async.
  using CreateImplCompleteCallback = std::function<void(CreateResult)>;

  /// Callback receiving the @ref BaseObjectResult of @ref attach_async.
  using AttachCompleteCallback = std::function<void(BaseObjectResult)>;

  /// Attaches an existing Object node as a `BaseObject` handle.
  ///
  /// Used by generated child accessors whose declared type definition is the
  /// bare `BaseObjectType` (i=58): there is no narrower type to verify against,
  /// so the attach succeeds as long as the node exists and is in the
  /// `BaseObjectType` hierarchy. The resulting handle references the node but
  /// owns no subtree, so destroying it never removes the node.
  ///
  /// @param addressSpace    Address space containing the node.
  /// @param existingInstance NodeId of the Object node to attach.
  /// @param complete        Receives the outcome: on success the Result holds
  ///                        the @ref BaseObject handle; on failure it carries an
  ///                        @ref ErrorDetail. This overload never throws.
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

protected:
  /// Instantiates a new Object node under @p parent and reports the result.
  ///
  /// The extension point through which generated, strongly typed Object handles
  /// create their backing node; not called directly by SDK consumers.
  ///
  /// @param addressSpace   Address space to create the node in.
  /// @param parent         NodeId of the parent the new Object is organized under.
  /// @param browseName     BrowseName of the new node.
  /// @param typeDefinition NodeId of the Object type to instantiate.
  /// @param options        Controls instantiation behaviour (e.g. modelling-rule handling).
  /// @param complete       Receives the outcome: on success the Result holds the
  ///                       @ref CreateResultData (including the owned subtree); on
  ///                       failure it carries an @ref ErrorDetail. Never throws.
  static void create_object_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    NodeId typeDefinition, InstantiationOptions options, CreateImplCompleteCallback complete) noexcept;

  /// Constructs a handle that references @p nodeId, optionally owning @p owned.
  ///
  /// Used by derived handles and the attach/create paths. When @p owned holds a
  /// subtree, the handle is responsible for it until @ref release is called.
  ///
  /// @param addressSpace Address space the referenced node lives in.
  /// @param nodeId       NodeId of the Object node this handle references.
  /// @param owned        Subtree to take ownership of, or `std::nullopt` to reference without owning.
  BaseObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  optional<AddressSpace> mAddressSpace;  ///< Address space the handle is bound to; empty when the
                                         ///< handle references no node (default-constructed or moved-from).
  NodeId mNodeId;  ///< NodeId of the referenced Object node; null when the handle is empty.
  optional<NodeSubtree> mOwned;  ///< Subtree this handle owns and removes on destruction unless
                                 ///< @ref release is called first; empty for attached handles.
};

}  // namespace ua

#endif  // UA_BASE_OBJECT_H
