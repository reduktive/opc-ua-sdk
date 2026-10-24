// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODE_ACCESSOR_H
#define UA_NODE_ACCESSOR_H

/// @file
/// @brief Typed accessors over address-space nodes: attribute get/set plus the
///        async reference, value, method-call and view operations.
/// @ingroup address_space

#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_node.h"
#include "ua_date_time.h"
#include "ua_result.h"
#include "ua_reference_halves.h"
#include "ua_value_rank.h"
#include "ua_variant.h"
#include "ua_data_value.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_data_type_definition.h"
#include "ua_method_adapter.h"
#include "ua_method_result.h"
#include "ua_request_info.h"
#include "ua_weak_address_space.h"

namespace ua
{

class MethodAccessor;
class ObjectAccessor;
class VariableAccessor;
class VariableTypeAccessor;
class DataTypeAccessor;
class ReferenceTypeAccessor;
class ViewAccessor;

/// A typed handle over a single address-space @ref Node.
///
/// Wraps a shared owning pointer to the underlying node and exposes its base
/// attributes (NodeId, NodeClass, BrowseName, DisplayName, Description,
/// WriteMask, RolePermissions, AccessRestrictions) plus its reference graph.
/// Derived accessors (@ref VariableAccessor, @ref ObjectAccessor, ...) add the
/// attributes and operations specific to each NodeClass; downcast to one with
/// @ref as.
///
/// The attribute getters read the held node on the calling thread. Every other
/// operation (References, Reference changes, Value reads and writes, attribute
/// writes and the setters, Method calls, Views) is a one-item call, through the
/// address space that handed the accessor out, to the batched member of the
/// namespace that owns the node: the route the services take. An operation whose
/// address space no longer exists, or of an accessor built from a node alone,
/// answers `Bad_Shutdown`. The operations follow the callback-canonical async
/// pattern and are also offered as blocking `_sync` and `try_*_sync` convenience
/// wrappers (external consumers only - never call the blocking variants from
/// inside the SDK).
///
/// The blocking wrappers, and the setters, which wait for their write, refuse on a
/// thread of the address space's executor before they start the operation: a
/// `try_*_sync` form returns `Bad_WouldBlock`, and a `_sync` form or a setter throws
/// @ref UaException carrying it. Code that runs on that executor (a Method handler,
/// a value source, the completion of an `*_async` operation) uses the `*_async`
/// forms. An accessor without an address space has no executor to refuse on; its
/// operations answer `Bad_Shutdown`.
///
/// Copyable and movable (value-handle semantics): copies share ownership of the
/// same underlying node and refer to the same address space.
/// @ingroup address_space
class NodeAccessor
{
public:
  /// Copies the handle, sharing ownership of the same underlying node.
  NodeAccessor(const NodeAccessor&) = default;
  /// Moves the handle; the source is left wrapping no node.
  NodeAccessor(NodeAccessor&&) noexcept = default;
  /// Rebinds this handle to share ownership of @p other's node.
  /// @return A reference to this handle.
  NodeAccessor& operator=(const NodeAccessor&) = default;
  /// Rebinds this handle to @p other's node; @p other is left wrapping no node.
  /// @return A reference to this handle.
  NodeAccessor& operator=(NodeAccessor&&) noexcept = default;

  /// Result holding a node's full Reference set.
  using ReferencesResult = Result<References>;

  /// Completion of @ref get_references_async; carries the References or an @ref ErrorDetail.
  using GetReferencesCallback = std::function<void(ReferencesResult)>;

  /// One page of References plus a continuation token for resuming a paged traversal.
  struct ReferencePage
  {
    References references;  ///< References in this page.
    ByteString continuationToken;  ///< Token to resume from; empty when no more pages remain.
  };

  /// Result holding a single @ref ReferencePage.
  using ReferencesPageResult = Result<ReferencePage>;

  /// Completion of the paged @ref get_references_async; carries a page or an @ref ErrorDetail.
  using GetReferencesPageCallback = std::function<void(ReferencesPageResult)>;

  /// Completion of a Reference add or remove; signals success or an @ref ErrorDetail.
  using ReferenceModifyCallback = std::function<void(VoidResult)>;

  /// Completion of @ref write_attribute_async; signals success or an @ref ErrorDetail.
  using WriteAttributeCompleteCallback = std::function<void(VoidResult)>;

  /// Completion of a Value read; carries the value or an @ref ErrorDetail.
  using ReadValueCompleteCallback = std::function<void(DataValueResult)>;

  /// Completion of a Value write; signals success or an @ref ErrorDetail.
  using WriteValueCompleteCallback = std::function<void(VoidResult)>;

  /// Completion of a View membership test; carries the answer or an @ref ErrorDetail.
  using IsNodeInViewCallback = std::function<void(BoolResult)>;

  /// Completion of an addition to a View; signals success or an @ref ErrorDetail.
  using ViewModifyCallback = std::function<void(VoidResult)>;

  // NodeAccessor is a non-polymorphic value handle: it holds a shared_ptr<Node> and
  // a weak handle to its address space, and is passed by value throughout the SDK. Derived
  // accessors (DataTypeAccessor, VariableAccessor, ...) add no state and exist
  // only to expose class-specific helpers via the static as<T>() narrowing
  // below - so this destructor is intentionally non-virtual. Keeping it
  // non-virtual makes copying (and narrowing a derived to the base) by value
  // lossless and safe by construction.
  ~NodeAccessor() = default;

  /// Accesses the underlying node's members.
  /// @return A non-owning pointer to the wrapped node; never null.
  Node* operator->() const
  {
    return mNode.get();
  }

  /// Accesses the underlying node by reference.
  /// @return A reference to the wrapped node.
  Node& operator*() const
  {
    return *mNode;
  }

  /// Attempts to view this node through a more specific accessor type.
  ///
  /// Constructs a `T` over the same node and returns it only when the node's
  /// class matches `T` (per `T::is_matching_class`).
  ///
  /// @tparam T The target accessor type (e.g. @ref VariableAccessor).
  /// @return The typed accessor, or `std::nullopt` if the node's class does not
  ///         match `T`.
  template<typename T>
  optional<T> as() const
  {
    if (auto ptr = get_node_ptr())
    {
      T accessor{ptr, mAddressSpace};
      if (accessor.is_matching_class())
      {
        return accessor;
      }
    }
    return std::nullopt;
  }

  // --- get_references: get all ---

  /// Retrieves all of the node's references.
  ///
  /// Reads them through the owning namespace's `read_references_async`, page after page until
  /// none is left. The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param callback Receives the outcome: the @ref References with the code the namespace answered the
  ///                 pages with, combined by `detail::combined_status` (a Good subcode, or an Uncertain
  ///                 code with the References it held, is kept); a page answered without References gives
  ///                 its status and @ref ErrorDetail. This overload never throws.
  /// @see get_references_sync, try_get_references_sync
  void get_references_async(GetReferencesCallback callback) const noexcept;

  /// Retrieves all of the node's references, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_get_references_sync() returns it.
  /// @return The node's references.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see get_references_async
  References get_references_sync() const;

  /// Retrieves all of the node's references, blocking until complete.
  /// @return The node's references, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_references_async
  Result<References> try_get_references_sync() const noexcept;

  // --- get_references: paginated ---

  /// Retrieves a page of the node's references, supporting continuation.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param maxReferences     Maximum number of references to return in this page;
  ///                          0 means no per-page limit.
  /// @param continuationToken Token from a prior page's result, or empty to start
  ///                          from the first page.
  /// @param callback          Receives the outcome: on success the Result holds a
  ///                          @ref ReferencePage (whose continuation token is
  ///                          empty when no further pages remain); on failure it
  ///                          carries an @ref ErrorDetail. This overload never throws.
  /// @see get_references_sync, try_get_references_sync
  void get_references_async(
    uint32_t maxReferences, ByteString continuationToken, GetReferencesPageCallback callback) const noexcept;

  /// Retrieves a page of the node's references, blocking until complete.
  /// @param maxReferences     Maximum number of references in this page; 0 = no limit.
  /// @param continuationToken Token from a prior page, or empty to start.
  ///
  /// A Good subcode on the answer is not returned; try_get_references_sync() returns it.
  /// @return The reference page.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see get_references_async
  ReferencePage get_references_sync(uint32_t maxReferences, ByteString continuationToken) const;

  /// Retrieves a page of the node's references, blocking until complete.
  /// @param maxReferences     Maximum number of references in this page; 0 = no limit.
  /// @param continuationToken Token from a prior page, or empty to start.
  /// @return The reference page, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_references_async
  ReferencesPageResult try_get_references_sync(
    uint32_t maxReferences, ByteString continuationToken) const noexcept;

  // --- get_components ---

  /// Retrieves the node's HasComponent-referenced child nodes.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param callback Receives the outcome: the component @ref References with the code of the References
  ///                 read as @ref get_references_async gives it; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see get_components_sync, try_get_components_sync
  void get_components_async(GetReferencesCallback callback) const noexcept;

  /// Retrieves the node's components, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_get_components_sync() returns it.
  /// @return The component references.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see get_components_async
  References get_components_sync() const;

  /// Retrieves the node's components, blocking until complete.
  /// @return The component references, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_components_async
  Result<References> try_get_components_sync() const noexcept;

  // --- get_properties ---

  /// Retrieves the node's HasProperty-referenced property nodes.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param callback Receives the outcome: the property @ref References with the code of the References
  ///                 read as @ref get_references_async gives it; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see get_properties_sync, try_get_properties_sync
  void get_properties_async(GetReferencesCallback callback) const noexcept;

  /// Retrieves the node's properties, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_get_properties_sync() returns it.
  /// @return The property references.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see get_properties_async
  References get_properties_sync() const;

  /// Retrieves the node's properties, blocking until complete.
  /// @return The property references, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_properties_async
  Result<References> try_get_properties_sync() const noexcept;

  // --- add_reference ---

  /// Adds a reference of type @p type from this node to @p target.
  ///
  /// This node holds the half added. With @p halves `ReferenceHalves::Both`, for a hierarchical type,
  /// GeneratesEvent, HasSubtype and HasEncoding, and their subtypes, the address space then adds the other
  /// half on @p target, in its namespace, unless @p
  /// target is in another Server or does not exist: OPC 10000-3 requires the inverse of HasSubtype and
  /// HasEncoding and recommends the others bidirectional (5.3.2). That half already held is not a failure. A
  /// half the type requires (HasEncoding's, HasSubtype's inverse) that cannot be added is the result, with an
  /// ErrorDetail `OtherHalfNotAdded` naming @p target, and this node keeps its half; any other half that
  /// cannot be added is only logged. A half this node already holds answers
  /// `Bad_DuplicateReferenceNotAllowed`, except for these types: the address space adds their halves itself,
  /// so adding one it already holds answers Good. A Reference held with another type that is not a subtype of
  /// @p type is still refused, with the ErrorDetail `DuplicateReferenceOfAnotherType`.
  ///
  /// With @p halves `ReferenceHalves::ThisHalfOnly` no other half is added. A Reference with a target in this
  /// Server whose other half OPC 10000-3 requires, either half of HasEncoding and its subtypes (5.8.4) or the
  /// supertype's forward half of HasSubtype and its subtypes, whose subtype must hold the inverse half
  /// (5.3.3.3), is then refused with `Bad_NotSupported` and an ErrorDetail `RequiredOtherHalfLeftAlone`, and
  /// nothing is added. The subtype's inverse HasSubtype alone is added.
  ///
  /// A target in another Server (a non-zero server index) is best given with its namespace URI. Browse
  /// returns a remote target with a namespace URI (Part 4 7.30), and for a target given with a namespace
  /// index that URI is the one the index has in this Server's NamespaceArray. A Browse in the context of a
  /// View leaves out a Reference to a remote target, because View membership is decided by local NodeId.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param type      ReferenceType of the new reference.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` to add a forward reference, `false` for an inverse one.
  /// @param halves    `ReferenceHalves::Both` to have the address space add the other half as described,
  ///                  `ReferenceHalves::ThisHalfOnly` to add this node's half alone.
  /// @param callback  Receives a @ref VoidResult "VoidResult": the code the namespaces answered the change
  /// with
  ///                  (several answers combined by `detail::combined_status`, so a Good subcode is
  ///                  kept); on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see add_reference_sync, try_add_reference_sync
  void add_reference_async(NodeId type, ExpandedNodeId target, bool isForward, ReferenceHalves halves,
    ReferenceModifyCallback callback) noexcept;

  /// Adds a reference from this node to @p target, blocking until complete.
  /// @param type      ReferenceType of the new reference.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @throws UaException if the operation fails.
  /// @see add_reference_async
  void add_reference_sync(const NodeId& type, const ExpandedNodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Adds a reference from this node to @p target, blocking until complete.
  /// @param type      ReferenceType of the new reference.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_reference_async
  VoidResult try_add_reference_sync(const NodeId& type, const ExpandedNodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Adds a reference from this node to a local @p target, blocking until complete.
  /// @param type      ReferenceType of the new reference.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @throws UaException if the operation fails.
  /// @see add_reference_async
  void add_reference_sync(const NodeId& type, const NodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Adds a reference from this node to a local @p target, blocking until complete.
  /// @param type      ReferenceType of the new reference.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_reference_async
  VoidResult try_add_reference_sync(const NodeId& type, const NodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Adds a fully specified reference originating from this node, with its other half as @p halves says
  /// (see the type and target form).
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param reference The reference (type, target, direction) to add.
  /// @param halves    Which halves of the Reference are added; see the type and target form.
  /// @param callback  Receives a @ref VoidResult "VoidResult": the code the namespaces answered the change
  /// with
  ///                  (several answers combined by `detail::combined_status`, so a Good subcode is
  ///                  kept); on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see add_reference_sync, try_add_reference_sync
  void add_reference_async(
    const Reference& reference, ReferenceHalves halves, ReferenceModifyCallback callback) noexcept;

  /// Adds a fully specified reference, blocking until complete.
  /// @param reference The reference (type, target, direction) to add.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @throws UaException if the operation fails.
  /// @see add_reference_async
  void add_reference_sync(const Reference& reference, ReferenceHalves halves = ReferenceHalves::Both);

  /// Adds a fully specified reference, blocking until complete.
  /// @param reference The reference (type, target, direction) to add.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_reference_async
  VoidResult try_add_reference_sync(
    const Reference& reference, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  // --- add_references (batch) ---

  /// Adds multiple references originating from this node in one call to the owning namespace.
  ///
  /// Each reference is one change, answered alone: the callback receives the first refusal, and the
  /// references not refused may have been added. @p halves applies to every reference as @ref
  /// add_reference_async states; a reference refused under `ReferenceHalves::ThisHalfOnly` is one refusal.
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param references The references to add.
  /// @param halves     Which halves of each Reference are added; see @ref add_reference_async.
  /// @param callback   Receives a @ref VoidResult "VoidResult": the code the namespaces answered the change
  /// with
  ///                   (several answers combined by `detail::combined_status`, so a Good subcode is
  ///                   kept); on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see add_references_sync, try_add_references_sync
  void add_references_async(
    std::vector<Reference> references, ReferenceHalves halves, ReferenceModifyCallback callback) noexcept;

  /// Adds multiple references, blocking until complete.
  /// @param references The references to add.
  /// @param halves     Which halves of each Reference are added; see @ref add_reference_async.
  /// @throws UaException if the operation fails.
  /// @see add_references_async
  void add_references_sync(std::vector<Reference> references, ReferenceHalves halves = ReferenceHalves::Both);

  /// Adds multiple references, blocking until complete.
  /// @param references The references to add.
  /// @param halves     Which halves of each Reference are added; see @ref add_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_references_async
  VoidResult try_add_references_sync(
    std::vector<Reference> references, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  // --- add_reference_if_not_present (convenience) ---

  /// Adds a reference only if the Node does not already hold it.
  ///
  /// Idempotent: succeeds without change when the reference is already present: held as the same Reference
  /// (OPC 10000-3 section 4.3.4, @ref Reference::identifies_same_reference_as) of the type asked for or a
  /// subtype of it. When the same Reference is held with another type - asked for HasOrderedComponent where
  /// a HasComponent to the same target is held - nothing is added and the call answers
  /// `Bad_DuplicateReferenceNotAllowed`, naming both types: the Node cannot hold the Reference asked for.
  /// A reference that is absent is added as @ref add_reference_async adds it with @p halves. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param type      ReferenceType of the reference to add if absent.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference are added; see @ref add_reference_async.
  /// @param callback  Receives a @ref VoidResult "VoidResult": plain Good when the reference is present, the
  /// add's own
  ///                  answer (its code whatever it is) when it was added, as the sync form answers. The read
  ///                  of the Node's References decides whether to add, so an Uncertain read is answered
  ///                  `Bad_InternalError` (`ReferencesAnswerUncertain`) with the Uncertain code as its cause.
  ///                  This overload never throws.
  /// @see add_reference_if_not_present_sync, try_add_reference_if_not_present_sync
  void add_reference_if_not_present_async(NodeId type, NodeId target, bool isForward, ReferenceHalves halves,
    ReferenceModifyCallback callback) noexcept;

  /// Adds multiple references in one operation, skipping any that already exist.
  ///
  /// Equivalent to calling @ref add_reference_if_not_present_async for each reference, but it reads
  /// the existing references once and sends the (de-duplicated) batch in one call to the owning namespace.
  /// Duplicates already present on the node and duplicates within @p references are both dropped, so
  /// the operation is idempotent; a duplicate is a Reference OPC 10000-3 section 4.3.4 identifies as the
  /// same (@ref Reference::identifies_same_reference_as). References of @p references that are the same
  /// Reference are decided together, whatever their order: the node gets the one whose type is each one's
  /// type or a subtype of it (HasOrderedComponent for HasComponent and HasOrderedComponent to one target),
  /// and a held one counts when its type is each one's type or a subtype of it. When that cannot be - a held
  /// HasComponent where HasOrderedComponent is asked for, or two types neither of which is a subtype of the
  /// other - nothing is added and the call answers `Bad_DuplicateReferenceNotAllowed`, naming both types.
  /// When another add stores some of them between the read and the write, the node is read again and what it
  /// does not hold is sent again. The references sent are added as @ref add_references_async adds them with
  /// @p halves. The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param references The references to add if absent.
  /// @param halves     Which halves of each Reference are added; see @ref add_reference_async.
  /// @param callback   Receives a @ref VoidResult "VoidResult": plain Good when every reference is present,
  /// the add's
  ///                   own answer (its code whatever it is) otherwise. An Uncertain read of the Node's
  ///                   References is answered `Bad_InternalError` (`ReferencesAnswerUncertain`) with the
  ///                   Uncertain code as its cause. This overload never throws.
  void add_references_if_not_present_async(
    std::vector<Reference> references, ReferenceHalves halves, ReferenceModifyCallback callback) noexcept;

  /// Adds a reference if absent, blocking until complete.
  /// @param type      ReferenceType of the reference to add if absent.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @throws UaException if the operation fails.
  /// @see add_reference_if_not_present_async
  void add_reference_if_not_present_sync(const NodeId& type, const NodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Adds a reference if absent, blocking until complete.
  /// @param type      ReferenceType of the reference to add if absent.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref add_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_reference_if_not_present_async
  VoidResult try_add_reference_if_not_present_sync(const NodeId& type, const NodeId& target,
    bool isForward = true, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  // --- remove_reference ---

  /// Removes the reference of type @p type from this node to @p target.
  ///
  /// With @p halves `ReferenceHalves::Both` the address space also removes the other half from @p target, in
  /// its namespace, whatever the type, as DeleteReferences does with `deleteBidirectional` TRUE (OPC 10000-4
  /// 5.7.5.1); a target in another Server keeps its half, and an other half @p target does not hold, or a
  /// target that does not exist, is not a failure. A failure to remove a half the type requires
  /// (HasEncoding's, HasSubtype's inverse) is the result (`OtherHalfNotRemoved`), and any other failure is
  /// only logged.
  ///
  /// With `ReferenceHalves::ThisHalfOnly` only this node's half is removed, as DeleteReferences does with
  /// `deleteBidirectional` FALSE. A Reference with a target in this Server whose other half OPC 10000-3
  /// requires, HasEncoding and its subtypes (5.8.4) or the inverse half of HasSubtype and its subtypes, which
  /// the subtype holds (5.5.2), is then refused with `Bad_NotSupported` and an ErrorDetail
  /// `RequiredOtherHalfLeftAlone`, and nothing is removed. The supertype's forward HasSubtype alone is
  /// removed.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param type      ReferenceType of the reference to remove.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` to remove a forward reference, `false` for an inverse one.
  /// @param halves    `ReferenceHalves::Both` to remove the other half too, `ReferenceHalves::ThisHalfOnly`
  ///                  to remove this node's half alone.
  /// @param callback  Receives a @ref VoidResult; on failure it carries an
  ///                  @ref ErrorDetail. A Reference the node does not hold is not a
  ///                  failure: `Uncertain_ReferenceNotDeleted` or Good (see
  ///                  Namespace::remove_references_async). This overload never throws.
  /// @see remove_reference_sync, try_remove_reference_sync
  void remove_reference_async(NodeId type, ExpandedNodeId target, bool isForward, ReferenceHalves halves,
    ReferenceModifyCallback callback) noexcept;

  /// Removes a reference from this node to @p target, blocking until complete.
  /// @param type      ReferenceType of the reference to remove.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @throws UaException if the operation fails.
  /// @see remove_reference_async
  void remove_reference_sync(const NodeId& type, const ExpandedNodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Removes a reference from this node to @p target, blocking until complete.
  /// @param type      ReferenceType of the reference to remove.
  /// @param target    The reference's target node, possibly in another namespace/server.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_reference_async
  VoidResult try_remove_reference_sync(const NodeId& type, const ExpandedNodeId& target,
    bool isForward = true, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Removes a reference from this node to a local @p target, blocking until complete.
  /// @param type      ReferenceType of the reference to remove.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @throws UaException if the operation fails.
  /// @see remove_reference_async
  void remove_reference_sync(const NodeId& type, const NodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Removes a reference from this node to a local @p target, blocking until complete.
  /// @param type      ReferenceType of the reference to remove.
  /// @param target    The reference's local target node.
  /// @param isForward `true` for a forward reference, `false` for an inverse one.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_reference_async
  VoidResult try_remove_reference_sync(const NodeId& type, const NodeId& target, bool isForward = true,
    ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Removes a fully specified reference originating from this node, with its other half as @p halves says
  /// (see the type and target form).
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param reference The reference (type, target, direction) to remove.
  /// @param halves    Which halves of the Reference are removed; see the type and target form.
  /// @param callback  Receives a @ref VoidResult "VoidResult": the code the namespaces answered the change
  /// with
  ///                  (several answers combined by `detail::combined_status`, so a Good subcode is
  ///                  kept); on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see remove_reference_sync, try_remove_reference_sync
  void remove_reference_async(
    const Reference& reference, ReferenceHalves halves, ReferenceModifyCallback callback) noexcept;

  /// Removes a fully specified reference, blocking until complete.
  /// @param reference The reference (type, target, direction) to remove.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @throws UaException if the operation fails.
  /// @see remove_reference_async
  void remove_reference_sync(const Reference& reference, ReferenceHalves halves = ReferenceHalves::Both);

  /// Removes a fully specified reference, blocking until complete.
  /// @param reference The reference (type, target, direction) to remove.
  /// @param halves    Which halves of the Reference change; see @ref remove_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_reference_async
  VoidResult try_remove_reference_sync(
    const Reference& reference, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  // --- remove_references (batch) ---

  /// Removes multiple references originating from this node in one call to the owning namespace.
  ///
  /// Each reference is one change, answered alone: the callback receives the first Bad answer, else the first
  /// Uncertain one (the in-memory namespace answers `Uncertain_ReferenceNotDeleted` for a reference the node
  /// does not hold), and the other references are removed. @p halves applies to every reference as @ref
  /// remove_reference_async states; a reference refused under `ReferenceHalves::ThisHalfOnly` is one Bad
  /// answer. The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param references The references to remove.
  /// @param halves     Which halves of each Reference are removed; see @ref remove_reference_async.
  /// @param callback   Receives a @ref VoidResult "VoidResult": the code the namespaces answered the change
  /// with
  ///                   (several answers combined by `detail::combined_status`, so a Good subcode is
  ///                   kept); on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see remove_references_sync, try_remove_references_sync
  void remove_references_async(
    std::vector<Reference> references, ReferenceHalves halves, ReferenceModifyCallback callback) noexcept;

  /// Removes multiple references, blocking until complete.
  /// @param references The references to remove.
  /// @param halves     Which halves of each Reference are removed; see @ref remove_reference_async.
  /// @throws UaException if the operation fails.
  /// @see remove_references_async
  void remove_references_sync(
    std::vector<Reference> references, ReferenceHalves halves = ReferenceHalves::Both);

  /// Removes multiple references, blocking until complete.
  /// @param references The references to remove.
  /// @param halves     Which halves of each Reference are removed; see @ref remove_reference_async.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_references_async
  VoidResult try_remove_references_sync(
    std::vector<Reference> references, ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Returns `true` if the node's class is Object.
  /// @return `true` if the node's class is Object.
  bool is_object() const;
  /// Returns `true` if the node's class is ObjectType.
  /// @return `true` if the node's class is ObjectType.
  bool is_object_type() const;
  /// Returns `true` if the node's class is DataType.
  /// @return `true` if the node's class is DataType.
  bool is_data_type() const;
  /// Returns `true` if the node's class is Variable.
  /// @return `true` if the node's class is Variable.
  bool is_variable() const;
  /// Returns `true` if the node's class is VariableType.
  /// @return `true` if the node's class is VariableType.
  bool is_variable_type() const;
  /// Returns `true` if the node's class is ReferenceType.
  /// @return `true` if the node's class is ReferenceType.
  bool is_reference_type() const;
  /// Returns `true` if the node's class is View.
  /// @return `true` if the node's class is View.
  bool is_view() const;
  /// Returns `true` if the node's class is Method.
  /// @return `true` if the node's class is Method.
  bool is_method() const;
  /// Returns `true` if the node is a type node (DataType, ObjectType, VariableType or
  /// ReferenceType).
  /// @return `true` if the node is a DataType, ObjectType, VariableType or ReferenceType.
  bool is_type() const;

  // BaseNode methods

  /// Returns the node's NodeId.
  /// @return The node's NodeId.
  NodeId get_node_id() const;
  /// Returns the node's NodeClass.
  /// @return The node's NodeClass.
  NodeClass get_node_class() const;
  /// Returns the node's BrowseName, or an empty @ref QualifiedName when the node carries none.
  ///
  /// BrowseName is mandatory on every NodeClass (OPC 10000-3), so an empty result means the node is
  /// malformed rather than merely unnamed. This reports that rather than throwing, so a caller on a
  /// hot path need not guard every comparison; test `name().empty()` to tell the cases apart.
  /// @return The node's BrowseName, or an empty @ref QualifiedName when the attribute is absent.
  QualifiedName get_browse_name() const;

  /// Returns the node's WriteMask, or `std::nullopt` if the attribute is not set.
  /// @return The node's WriteMask, or `std::nullopt` when the attribute is not set.
  optional<AttributeWriteMask> get_write_mask() const;
  /// Returns the node's RolePermissions, or `std::nullopt` if the attribute is not set.
  /// @return The node's RolePermissions, or `std::nullopt` when the attribute is not set.
  optional<std::vector<RolePermissionType>> get_role_permissions() const;
  /// Returns the node's AccessRestrictions, or `std::nullopt` if the attribute is not set.
  /// @return The node's AccessRestrictions, or `std::nullopt` when the attribute is not set.
  optional<AccessRestrictionType> get_access_restrictions() const;

  /// Reads an attribute of the node's description (`Node::attributes()`) in its OPC UA wire form.
  ///
  /// The synchronous read counterpart to @ref write_attribute_async. Its purpose is to copy a node's
  /// static attributes verbatim - e.g. instantiating an instance from a resident type declaration - into
  /// an @ref InitialAttributes set for create-with-attributes, with no domain round-trip. A VariableType's
  /// Value is answered as the @ref DataValue it is held as. A Variable's live value is not a stored
  /// attribute: read it through the value path.
  ///
  /// @param attributeId Attribute to read.
  /// @return The attribute value in wire form, or an empty @ref Variant for an attribute the node does
  ///         not carry or its NodeClass does not define (a Variable's Value among them).
  /// @throws UaException `Bad_NodeIdUnknown` for a deleted node; `Bad_AttributeIdInvalid` for a
  ///         Session-derived attribute (@ref is_session_derived_attribute).
  Variant read_attribute(AttributeId attributeId) const;

  /// Writes an attribute in its OPC UA wire form.
  ///
  /// The asynchronous member of the attribute-write triad, and the one SDK code uses. The write is
  /// one item of the owning namespace's `write_async`, made as the server's own (no caller), whose
  /// DataValue holds @p attributeValue; for a VariableType's Value, which is stored as a
  /// @ref DataValue, the DataValue it holds. A null @p attributeValue clears an optional attribute,
  /// as the setters that take `std::nullopt` do.
  ///
  /// @param attributeId    Attribute to write.
  /// @param attributeValue New value in wire form, as the setters build it; consumed by the call.
  /// @param callback       Receives the outcome; a bad @ref StatusCode carries any @ref ErrorDetail.
  ///                       The callback runs on an unspecified thread - do not block it.
  /// @see write_attribute_sync, try_write_attribute_sync
  void write_attribute_async(
    AttributeId attributeId, Variant attributeValue, std::function<void(VoidResult)> callback) noexcept;

  /// Writes an attribute in its OPC UA wire form, blocking until complete.
  ///
  /// The `*_sync` member of the attribute-write triad: waits for @ref write_attribute_async and
  /// rethrows a bad outcome via `.value()`. Convenience for callers off the address space's executor:
  /// on a thread of that executor it throws `Bad_WouldBlock` without writing.
  ///
  /// @param attributeId    Attribute to write.
  /// @param attributeValue New value in wire form; consumed by the call.
  /// @throws UaException carrying the bad @ref StatusCode (and any @ref ErrorDetail).
  /// @see try_write_attribute_sync
  void write_attribute_sync(AttributeId attributeId, Variant attributeValue);

  /// Writes an attribute in its OPC UA wire form, blocking until complete (non-throwing).
  ///
  /// The `try_*_sync` member of the attribute-write triad: waits for @ref write_attribute_async
  /// and returns the @ref VoidResult. Never throws. Convenience for callers off the address space's executor:
  /// on a thread of that executor it returns `Bad_WouldBlock` without writing.
  ///
  /// @param attributeId    Attribute to write.
  /// @param attributeValue New value in wire form; consumed by the call.
  /// @return The write outcome; a bad @ref StatusCode (carrying any @ref ErrorDetail) on failure.
  /// @see write_attribute_sync
  [[nodiscard]] VoidResult try_write_attribute_sync(AttributeId attributeId, Variant attributeValue) noexcept;

  /// Sets the node's BrowseName.
  /// @param browseName The BrowseName to set.
  void set_browse_name(QualifiedName browseName);

  /// Sets the node's DisplayName.
  /// @param displayName The DisplayName to set.
  /// @throws UaException with Status::BadInvalidArgument if the display name text exceeds
  ///         512 bytes.
  void set_display_name(LocalizedText displayName);

  /// Sets the node's Description.
  /// @param description The Description to set.
  void set_description(LocalizedText description);

  /// Sets (or clears, with `std::nullopt`) the node's WriteMask.
  /// @param writeMask The WriteMask to set, or `std::nullopt` to clear the attribute.
  void set_write_mask(optional<AttributeWriteMask> writeMask);

  /// Sets (or clears, with `std::nullopt`) the node's RolePermissions.
  /// @param rolePermissions The RolePermissions to set, or `std::nullopt` to clear the attribute.
  void set_role_permissions(optional<std::vector<RolePermissionType>> rolePermissions);

  /// Sets (or clears, with `std::nullopt`) the node's AccessRestrictions.
  /// @param accessRestrictions The AccessRestrictions to set, or `std::nullopt` to clear the attribute.
  void set_access_restrictions(optional<AccessRestrictionType> accessRestrictions);

  /// Returns `true` if the wrapped node's class matches this accessor type.
  ///
  /// The base accessor matches any node; each derived accessor redefines this
  /// to require a specific NodeClass. Intentionally non-virtual: it is resolved
  /// statically by @ref as on the concrete target accessor type `T` (the only
  /// caller), never through a base reference - so no vtable is needed.
  ///
  /// @return `true` for @ref NodeAccessor; the derived contract narrows it.
  bool is_matching_class() const;

protected:
  /// Returns the shared owning pointer to the wrapped node; never null.
  /// @return The shared owning pointer to the wrapped node; never null.
  shared_ptr<Node> get_node_ptr() const
  {
    return mNode;
  }

  /// Returns a weak (non-owning) reference to the wrapped node.
  /// @return A weak (non-owning) pointer to the wrapped node.
  weak_ptr<Node> get_weak_node_ptr() const
  {
    return mNode;
  }

  /// Returns a const reference to the wrapped node.
  /// @return A const reference to the wrapped node.
  const Node& node() const;

  /// Returns a mutable reference to the wrapped node.
  /// @return A mutable reference to the wrapped node.
  Node& node();

protected:
  /// The Node's description, read after checking that the Node is not deleted (NR-2 rule 2, NR-44 rule 2).
  /// @return The immutable description of the live wrapped Node.
  /// @throws UaException Bad_NodeIdUnknown when the accessor holds no Node or the Node is deleted.
  NodeDescription described() const;

private:
  // Builds the accessors the address space hands out, and runs their operations.
  friend class detail::NodeAccessorRoute;

  // The accessors the address space hands out are built by the address space (NR-1 rule 1, NR-65).
  NodeAccessor(shared_ptr<Node> node, WeakAddressSpace addressSpace);

  shared_ptr<Node> mNode;
  WeakAddressSpace mAddressSpace;
};

/// Accessor for Variable nodes.
///
/// A Variable's value is dynamic and possibly externally sourced; it is never a
/// stored attribute. The value is accessed only through the async
/// `read_value` / `write_value` family below (each carrying a full
/// @ref DataValue - value, status and timestamps). There is intentionally no
/// `get_value()` / `set_value()` here - contrast @ref VariableTypeAccessor, which
/// stores a static default Value.
///
/// @ingroup address_space
class VariableAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is Variable.
  /// @return `true` if the wrapped node's class is Variable.
  bool is_matching_class() const;

  /// Returns the variable's DataType NodeId.
  /// @return The variable's DataType NodeId.
  NodeId get_data_type() const;
  /// Returns the variable's ValueRank.
  /// @return The variable's ValueRank.
  ValueRank get_value_rank() const;
  /// Returns the variable's ArrayDimensions, or `std::nullopt` if the attribute is not set.
  /// @return The variable's ArrayDimensions, or `std::nullopt` when the attribute is not set.
  optional<std::vector<uint32_t>> get_array_dimensions() const;
  /// Sets the variable's DataType.
  /// @param dataType The DataType NodeId to set.
  void set_data_type(NodeId dataType);
  /// Sets the variable's ValueRank.
  /// @param valueRank The ValueRank to set.
  void set_value_rank(ValueRank valueRank);
  /// Sets (or clears, with `std::nullopt`) the variable's ArrayDimensions.
  /// @param arrayDimensions The ArrayDimensions to set, or `std::nullopt` to clear the attribute.
  void set_array_dimensions(optional<std::vector<uint32_t>> arrayDimensions);

  /// Returns the variable's AccessLevel.
  /// @return The variable's AccessLevel.
  AccessLevelType get_access_level() const;
  /// Returns the variable's Historizing flag.
  /// @return The variable's Historizing flag.
  bool get_historizing() const;
  /// Returns the variable's MinimumSamplingInterval in milliseconds, or
  /// `std::nullopt` if the attribute is not set.
  /// @return The MinimumSamplingInterval in milliseconds, or `std::nullopt` when the attribute is
  ///         not set.
  optional<Duration> get_minimum_sampling_interval() const;
  /// Returns the variable's AccessLevelEx, or `std::nullopt` if the attribute is not set.
  /// @return The variable's AccessLevelEx, or `std::nullopt` when the attribute is not set.
  optional<AccessLevelExType> get_access_level_ex() const;
  /// Sets the variable's AccessLevel.
  /// @param accessLevel The AccessLevel to set.
  void set_access_level(const AccessLevelType& accessLevel);
  /// Sets the variable's Historizing flag.
  /// @param historizing The Historizing flag to set.
  void set_historizing(bool historizing);
  /// Sets (or clears, with `std::nullopt`) the variable's MinimumSamplingInterval (milliseconds).
  /// @param minimumSamplingInterval The MinimumSamplingInterval in milliseconds, or `std::nullopt`
  ///                                to clear the attribute.
  void set_minimum_sampling_interval(optional<Duration> minimumSamplingInterval);
  /// Sets (or clears, with `std::nullopt`) the variable's AccessLevelEx.
  /// @param accessLevelEx The AccessLevelEx to set, or `std::nullopt` to clear the attribute.
  void set_access_level_ex(optional<AccessLevelExType> accessLevelEx);

  /// Reads the variable's Value attribute.
  ///
  /// One item of the owning namespace's `read_values_async`, which answers the Value for
  /// @p nodeToRead's IndexRange; the value may be produced by an external source. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param maxAge            Maximum acceptable age of a cached value, in
  ///                          milliseconds; 0 requests the freshest value.
  /// @param setSourceTimestamp `true` to request the source timestamp be populated.
  /// @param nodeToRead        Identifies the attribute and index range to read; a null NodeId names this
  ///                          Variable.
  /// @param caller            On whose behalf the Value is read, or null for the server's own read;
  ///                          passed to the namespace unchanged, and valid until this call returns.
  /// @param callback          Receives the outcome: on success the Result holds the
  ///                          @ref DataValue; on failure it carries an
  ///                          @ref ErrorDetail. This overload never throws.
  /// @see read_value_sync, try_read_value_sync
  void read_value_async(Duration maxAge, bool setSourceTimestamp, const ReadValueId& nodeToRead,
    const CallerInfo* caller, ReadValueCompleteCallback callback) const noexcept;

  /// Reads the variable's Value attribute, blocking until complete.
  /// @return The value, or an @ref ErrorDetail on failure. Never throws.
  /// @see read_value_async
  DataValueResult try_read_value_sync() const noexcept;

  /// Reads the variable's Value attribute, blocking until complete.
  ///
  /// The DataValue's status is the one `detail::combined_status` gives for the answer's code and the
  /// Value's own status, so a Good subcode on the answer reaches the caller.
  /// @return The value.
  /// @throws UaException unless the answer is Good, an Uncertain answer included; try_read_value_sync()
  ///         returns an Uncertain answer's value.
  /// @see read_value_async
  DataValue read_value_sync() const;

  // --- write_value: WriteValue family (service-facing) ---

  /// Writes the variable's value from a service-level WriteValue.
  ///
  /// One item of the owning namespace's `write_async`. The callback runs on an unspecified worker
  /// thread - do not block it.
  ///
  /// @param nodeToWrite Identifies the attribute, index range and value to write.
  /// @param caller      On whose behalf the value is written, or null for the server's own write;
  ///                    passed to the namespace unchanged, and valid until this call returns.
  /// @param callback    Receives a @ref VoidResult; on failure it carries an
  ///                    @ref ErrorDetail. This overload never throws.
  /// @see write_value_sync, try_write_value_sync
  void write_value_async(
    const WriteValue& nodeToWrite, const CallerInfo* caller, WriteValueCompleteCallback callback) noexcept;

  /// Writes the variable's value from a WriteValue, blocking until complete. No Session is in scope,
  /// so the value source receives a null identity.
  /// @param writeValue Identifies the attribute, index range and value to write.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see write_value_async
  VoidResult try_write_value_sync(WriteValue writeValue) noexcept;

  /// Writes the variable's value from a WriteValue, blocking until complete.
  /// @param writeValue Identifies the attribute, index range and value to write.
  /// @throws UaException if the write fails.
  /// @see write_value_async
  void write_value_sync(WriteValue writeValue);

  // --- write_value: DataValue convenience family ---

  /// Writes the variable's Value attribute from a @ref DataValue.
  ///
  /// An internal write: no Session is in scope, so the value source receives a null identity.
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param value    The value, status and timestamps to write.
  /// @param callback Receives a @ref VoidResult; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see write_value_sync, try_write_value_sync
  void write_value_async(DataValue value, WriteValueCompleteCallback callback) noexcept;

  /// Writes the variable's Value from a @ref DataValue, blocking until complete.
  /// @param value The value, status and timestamps to write.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see write_value_async
  VoidResult try_write_value_sync(DataValue value) noexcept;

  /// Writes the variable's Value from a @ref DataValue, blocking until complete.
  /// @param value The value, status and timestamps to write.
  /// @throws UaException if the write fails.
  /// @see write_value_async
  void write_value_sync(DataValue value);

  /// Writes the variable's Value from a plain payload, blocking until complete.
  ///
  /// Wraps @p value in a @ref DataValue. When @p sourceTimestamp is supplied it is
  /// used as the source timestamp; otherwise the current time is recorded as the
  /// server timestamp.
  ///
  /// @tparam T     Value payload type convertible to a @ref Variant.
  /// @param value  The value to write.
  /// @param sourceTimestamp Optional source timestamp.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see write_value_async
  template<typename T>
  VoidResult try_write_value_sync(
    T value, optional<DateTime> sourceTimestamp = optional<DateTime>{}) noexcept;

  /// Writes the variable's Value from a plain payload, blocking until complete.
  ///
  /// Wraps @p value in a @ref DataValue (see the `try_*` overload for timestamp
  /// behaviour).
  ///
  /// @tparam T     Value payload type convertible to a @ref Variant.
  /// @param value  The value to write.
  /// @param sourceTimestamp Optional source timestamp.
  /// @throws UaException if the write fails.
  /// @see write_value_async
  template<typename T>
  void write_value_sync(T value, optional<DateTime> sourceTimestamp = optional<DateTime>{});
};

/// Accessor for VariableType nodes.
///
/// Unlike a Variable, a VariableType stores a static default @ref DataValue as a
/// plain attribute. This is the only node class for which Value is a stored
/// attribute, so @ref get_value / @ref set_value are synchronous attribute access
/// (distinct from a Variable's live, async value).
///
/// @ingroup address_space
class VariableTypeAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is VariableType.
  /// @return `true` if the wrapped node's class is VariableType.
  bool is_matching_class() const;

  /// Returns the variable type's DataType NodeId.
  /// @return The variable type's DataType NodeId.
  NodeId get_data_type() const;
  /// Returns the variable type's ValueRank.
  /// @return The variable type's ValueRank.
  ValueRank get_value_rank() const;
  /// Returns the variable type's ArrayDimensions, or `std::nullopt` if the attribute is not set.
  /// @return The variable type's ArrayDimensions, or `std::nullopt` when the attribute is not set.
  optional<std::vector<uint32_t>> get_array_dimensions() const;
  /// Sets the variable type's DataType.
  /// @param dataType The DataType NodeId to set.
  void set_data_type(NodeId dataType);
  /// Sets the variable type's ValueRank.
  /// @param valueRank The ValueRank to set.
  void set_value_rank(ValueRank valueRank);
  /// Sets (or clears, with `std::nullopt`) the variable type's ArrayDimensions.
  /// @param arrayDimensions The ArrayDimensions to set, or `std::nullopt` to clear the attribute.
  void set_array_dimensions(optional<std::vector<uint32_t>> arrayDimensions);

  /// Returns the variable type's IsAbstract flag.
  /// @return The variable type's IsAbstract flag.
  bool get_is_abstract() const;
  /// Sets the variable type's IsAbstract flag.
  /// @param isAbstract The IsAbstract flag to set.
  void set_is_abstract(bool isAbstract);

  /// Returns the variable type's stored default Value, or `std::nullopt` if unset.
  ///
  /// The node may hold the Value in a DataValue or, as given at creation, as the value's Variant; the
  /// latter is returned as the value of a DataValue.
  /// @return The stored default Value, or `std::nullopt` when unset.
  optional<DataValue> get_value() const;

  /// Sets (or clears, with `std::nullopt`) the variable type's stored default Value.
  /// @param value The default Value to store, or `std::nullopt` to clear it.
  void set_value(optional<DataValue> value);

  /// Sets the variable type's stored default Value from a plain payload.
  ///
  /// Wraps @p value in a @ref DataValue, applying @p sourceTimestamp as the source
  /// timestamp when present.
  ///
  /// @tparam T     Value payload type convertible to a @ref Variant.
  /// @param value  The value to store.
  /// @param sourceTimestamp Optional source timestamp.
  template<typename T>
  void set_value(T value, optional<DateTime> sourceTimestamp);
};

/// Accessor for Method nodes.
/// @ingroup address_space
class MethodAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is Method.
  /// @return `true` if the wrapped node's class is Method.
  bool is_matching_class() const;

  /// Returns the method's Executable flag.
  /// @return The method's Executable flag.
  bool get_executable() const;
  /// Sets the method's Executable flag.
  /// @param executable The Executable flag to set.
  void set_executable(bool executable);

  /// Invokes the method.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param methodToCall The method's object, method NodeId and input arguments.
  /// @param context      Optional invocation context (session, locale, ...); may be null. Held by
  ///                     shared ownership for the (possibly asynchronous) duration of the call.
  /// @param callback     Receives the outcome: on success the Result holds the
  ///                     @ref CallMethodResult; on failure it carries an
  ///                     @ref ErrorDetail. This overload never throws.
  /// @see call_sync, try_call_sync
  void call_async(const CallMethodRequest& methodToCall, shared_ptr<const MethodCallContext> context,
    CallMethodCompleteCallback callback) const noexcept;

  /// Invokes the method, blocking until complete.
  /// @param methodToCall The method's object, method NodeId and input arguments.
  /// @return The call result, or an @ref ErrorDetail on failure. Never throws.
  /// @see call_async
  CallResult try_call_sync(const CallMethodRequest& methodToCall) const noexcept;

  /// Invokes the method, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_call_sync() returns it.
  /// @param methodToCall The method's object, method NodeId and input arguments.
  /// @return The call result.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see call_async
  CallMethodResult call_sync(const CallMethodRequest& methodToCall) const;

  /// Calls the method from the server's own code with typed arguments, blocking until complete: for
  /// testing a handler without a client, or using a Method's logic locally.
  ///
  /// The inputs are encoded and the outputs decoded as a typed handler's are (@ref MethodAdapter); the
  /// call has no session, so the handler sees an empty @ref MethodCall::context.
  /// @tparam Out The output arguments' C++ types, given explicitly.
  /// @tparam In  The input arguments' C++ types, deduced; each must have an OPC UA DataType.
  /// @param objectId The Object to call the method on.
  /// @param inputs   The input arguments.
  /// @return The result: its status, the outputs when there are any, and the status of each input
  ///         argument when the call was rejected. The status is the one `detail::combined_status`
  ///         gives for the call's code and the Method's statusCode, so a namespace's Good subcode or
  ///         Uncertain code reaches the caller; the Call service answers a Good subcode plain Good to a
  ///         client (OPC 10000-4 5.11.2.4). Outputs that do not match @p Out make it
  ///         `Bad_TypeMismatch`. Never throws.
  template<typename... Out, typename... In>
  MethodResult<Out...> try_call_sync(const NodeId& objectId, const In&... inputs) const noexcept;

  /// Calls the method with typed arguments, blocking until complete, and returns its outputs.
  ///
  /// A Good subcode on the answer is not returned; try_call_sync() returns it.
  /// @tparam Out The output arguments' C++ types, given explicitly.
  /// @tparam In  The input arguments' C++ types, deduced.
  /// @param objectId The Object to call the method on.
  /// @param inputs   The input arguments.
  /// @return Nothing for a Method without outputs, the output for one, a `std::tuple` for several.
  /// @throws UaException with the call's status and ErrorDetail unless the status is Good.
  template<typename... Out, typename... In>
  auto call_sync(const NodeId& objectId, const In&... inputs) const;
};

/// @cond METHOD_CALL_DETAIL
namespace detail
{

/// The typed result of a method call made in the server's own code.
///
/// The call's code and the Method's statusCode have room for one status: the one `combined_status` gives,
/// so a namespace's Good subcode or Uncertain code on the call is not lost. A Good subcode is passed on as
/// it was answered; the Call service answers it plain Good to a client (OPC 10000-4 5.11.2.4). A call
/// answered without a result gives its own status and ErrorDetail.
template<typename... Out>
MethodResult<Out...> method_result_from(const CallResult& called)
{
  if (!called.has_value())
  {
    return MethodResultAccess::make<Out...>(called.status_code(), std::nullopt, {});
  }
  const CallMethodResult& wire = called.value();
  const StatusCode status = combined_status(called.status_code(), wire.status_code());
  if (status.is_bad())
  {
    std::vector<StatusCode> argumentResults;
    const auto& diagnostics = wire.input_argument_diagnostic_infos();
    for (std::size_t index = 0; index < wire.input_argument_results().size(); ++index)
    {
      StatusCode argumentStatus{wire.input_argument_results()[index].value()};
      if (index < diagnostics.size() && diagnostics[index].inner_status_code().has_value())
      {
        argumentStatus =
          StatusCode{argumentStatus.value(), diagnostics[index].inner_status_code()->shared_detail()};
      }
      argumentResults.push_back(std::move(argumentStatus));
    }
    return MethodResultAccess::make<Out...>(status, std::nullopt, std::move(argumentResults));
  }
  if (wire.output_arguments().size() != sizeof...(Out))
  {
    return MethodResultAccess::make<Out...>(
      StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build("MethodOutputsMismatch",
          "The method returned a different number of outputs than requested",
          "MethodAccessor")
          .context(ContextKeys::sizeExpected, sizeof...(Out))
          .context(ContextKeys::sizeActual, wire.output_arguments().size())},
      std::nullopt,
      {});
  }
  try
  {
    return [&wire, &status]<std::size_t... I>(std::index_sequence<I...>)
    {
      return MethodResultAccess::make<Out...>(
        status, std::tuple<Out...>{method_value_from<Out>(wire.output_arguments()[I])...}, {});
    }(std::index_sequence_for<Out...>{});
  }
  catch (const UaException& mismatch)
  {
    return MethodResultAccess::make<Out...>(StatusCode{Status::BadTypeMismatch,
                                              ErrorDetail::build("MethodOutputTypeMismatch",
                                                "An output of the method does not hold the requested type",
                                                "MethodAccessor")
                                                .cause(mismatch.take_detail())},
      std::nullopt,
      {});
  }
}

}  // namespace detail

/// @endcond

template<typename... Out, typename... In>
MethodResult<Out...> MethodAccessor::try_call_sync(const NodeId& objectId, const In&... inputs) const noexcept
{
  static_assert((hasDataType<In> && ...),
    "A typed method call's input has no OPC UA DataType: specialise ua::DataTypeOf for it, or pass a "
    "ua::Variant");
  try
  {
    CallMethodRequest request;
    request.object_id() = objectId;
    request.method_id() = get_node_id();
    request.input_arguments() = std::vector<Variant>{detail::method_value_to(inputs)...};
    return detail::method_result_from<Out...>(try_call_sync(request));
  }
  catch (...)
  {
    return MethodResult<Out...>{ua::exception_to_status_code(std::current_exception())};
  }
}

template<typename... Out, typename... In>
auto MethodAccessor::call_sync(const NodeId& objectId, const In&... inputs) const
{
  auto result = try_call_sync<Out...>(objectId, inputs...);
  if (!result.status_code().is_good())
  {
    if (auto detail = result.status_code().shared_detail())
    {
      throw UaException{result.status_code().as_status(), std::move(detail)};
    }
    throw UaException{result.status_code().as_status(),
      ErrorDetail::build("MethodCallNotGood", "The method call did not complete with Good", "MethodAccessor")
        .cause(result.status_code())};
  }
  if constexpr (sizeof...(Out) == 0)
  {
    return;
  }
  else if constexpr (sizeof...(Out) == 1)
  {
    return std::get<0>(result.outputs());
  }
  else
  {
    return result.outputs();
  }
}

/// Accessor for Object nodes.
/// @ingroup address_space
class ObjectAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is Object.
  /// @return `true` if the wrapped node's class is Object.
  bool is_matching_class() const;

  /// Returns the object's EventNotifier bit mask.
  /// @return The object's EventNotifier bit mask.
  EventNotifierType get_event_notifier() const;
  /// Sets the object's EventNotifier bit mask.
  /// @param eventNotifier The EventNotifier bit mask to set.
  void set_event_notifier(const EventNotifierType& eventNotifier);
};

/// Accessor for DataType nodes.
/// @ingroup address_space
class DataTypeAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is DataType.
  /// @return `true` if the wrapped node's class is DataType.
  bool is_matching_class() const;

  /// Returns the data type's IsAbstract flag.
  /// @return The data type's IsAbstract flag.
  bool get_is_abstract() const;
  /// Sets the data type's IsAbstract flag.
  /// @param isAbstract The IsAbstract flag to set.
  void set_is_abstract(bool isAbstract);

  /// Returns the data type's structure/enum definition, or null if none is set.
  /// @return The data type's structure/enum definition, or null when none is set.
  shared_ptr<const DataTypeDefinition> get_data_type_definition() const;
  /// Sets (or clears, with null) the data type's structure/enum definition.
  /// @param dataTypeDefinition The structure/enum definition to set, or null to clear it.
  void set_data_type_definition(shared_ptr<const DataTypeDefinition> dataTypeDefinition);
};

/// Accessor for ObjectType nodes.
/// @ingroup address_space
class ObjectTypeAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is ObjectType.
  /// @return `true` if the wrapped node's class is ObjectType.
  bool is_matching_class() const;

  /// Returns the object type's IsAbstract flag.
  /// @return The object type's IsAbstract flag.
  bool get_is_abstract() const;
  /// Sets the object type's IsAbstract flag.
  /// @param isAbstract The IsAbstract flag to set.
  void set_is_abstract(bool isAbstract);
};

/// Accessor for ReferenceType nodes.
/// @ingroup address_space
class ReferenceTypeAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is ReferenceType.
  /// @return `true` if the wrapped node's class is ReferenceType.
  bool is_matching_class() const;

  /// Returns the reference type's IsAbstract flag.
  /// @return The reference type's IsAbstract flag.
  bool get_is_abstract() const;
  /// Sets the reference type's IsAbstract flag.
  /// @param isAbstract The IsAbstract flag to set.
  void set_is_abstract(bool isAbstract);

  /// Returns the reference type's Symmetric flag.
  /// @return The reference type's Symmetric flag.
  bool get_symmetric() const;

  /// Sets the reference type's Symmetric flag.
  /// @param isSymmetric The Symmetric flag to set.
  void set_symmetric(bool isSymmetric);
  /// Sets the reference type's InverseName.
  /// @param inverseName The InverseName to set.
  void set_inverse_name(LocalizedText inverseName);
};

/// Accessor for View nodes.
/// @ingroup address_space
class ViewAccessor : public NodeAccessor
{
public:
  // Inherits NodeAccessor's constructors, including the wrapping constructor
  // that shares ownership of a node and the copy/move special members.
  using NodeAccessor::NodeAccessor;

  /// Returns `true` if the wrapped node's class is View.
  /// @return `true` if the wrapped node's class is View.
  bool is_matching_class() const;

  /// Returns the view's EventNotifier bit mask.
  /// @return The view's EventNotifier bit mask.
  EventNotifierType get_event_notifier() const;
  /// Sets the view's EventNotifier bit mask.
  /// @param eventNotifier The EventNotifier bit mask to set.
  void set_event_notifier(const EventNotifierType& eventNotifier);

  /// Returns the view's ContainsNoLoops flag.
  /// @return The view's ContainsNoLoops flag.
  bool get_contains_no_loops() const;
  /// Sets the view's ContainsNoLoops flag.
  /// @param containsNoLoops The ContainsNoLoops flag to set.
  void set_contains_no_loops(bool containsNoLoops);

  // --- is_node_in_view ---

  /// Tests whether @p nodeId is a member of this view.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param nodeId   The node to test for membership.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 membership boolean; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see is_node_in_view_sync, try_is_node_in_view_sync
  void is_node_in_view_async(NodeId nodeId, IsNodeInViewCallback callback) const noexcept;

  /// Tests view membership of @p nodeId, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_is_node_in_view_sync() returns it.
  /// @param nodeId The node to test for membership.
  /// @return `true` if the node is in the view.
  /// @throws UaException unless the answer is Good, an Uncertain answer included.
  /// @see is_node_in_view_async
  bool is_node_in_view_sync(const NodeId& nodeId) const;

  /// Tests view membership of @p nodeId, blocking until complete.
  /// @param nodeId The node to test for membership.
  /// @return `true` if the node is in the view, or an @ref ErrorDetail on failure. Never throws.
  /// @see is_node_in_view_async
  BoolResult try_is_node_in_view_sync(const NodeId& nodeId) const noexcept;

  // --- add_node_to_view ---

  /// Adds @p nodeId as a member of this view.
  ///
  /// The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param nodeId   The node to add to the view.
  /// @param callback Receives a @ref VoidResult; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see add_node_to_view_sync, try_add_node_to_view_sync
  void add_node_to_view_async(NodeId nodeId, ViewModifyCallback callback) noexcept;

  /// Adds @p nodeId to this view, blocking until complete.
  /// @param nodeId The node to add to the view.
  /// @throws UaException if the operation fails.
  /// @see add_node_to_view_async
  void add_node_to_view_sync(const NodeId& nodeId);

  /// Adds @p nodeId to this view, blocking until complete.
  /// @param nodeId The node to add to the view.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_node_to_view_async
  VoidResult try_add_node_to_view_sync(const NodeId& nodeId) noexcept;
};

template<typename T>
void VariableTypeAccessor::set_value(T value, optional<DateTime> sourceTimestamp)
{
  Variant variant{std::move(value)};
  DataValue dataValue;
  dataValue.value() = std::move(variant);
  if (sourceTimestamp)
  {
    dataValue.source_timestamp() = sourceTimestamp;
  }

  write_attribute_sync(AttributeId::Value, Variant{std::move(dataValue)});
}

/// Sets the variable type's stored default Value directly from a @ref DataValue.
///
/// @param value           The value to store; its own timestamps are preserved.
/// @param sourceTimestamp Optional source timestamp applied when set.
template<>
void VariableTypeAccessor::set_value<DataValue>(DataValue value, optional<DateTime> sourceTimestamp);

/// Sets the variable type's stored default Value from a @ref Variant.
///
/// @param value           The value to store.
/// @param sourceTimestamp Optional source timestamp applied when set.
template<>
void VariableTypeAccessor::set_value<Variant>(Variant value, optional<DateTime> sourceTimestamp);

template<typename T>
VoidResult VariableAccessor::try_write_value_sync(T value, optional<DateTime> sourceTimestamp) noexcept
{
  DataValue dataValue;
  dataValue.value() = std::move(value);
  if (sourceTimestamp)
  {
    dataValue.source_timestamp() = sourceTimestamp.value();
  }
  else
  {
    dataValue.server_timestamp() = DateTime::now();
  }
  return try_write_value_sync(std::move(dataValue));
}

template<typename T>
void VariableAccessor::write_value_sync(T value, optional<DateTime> sourceTimestamp)
{
  try_write_value_sync(std::move(value), sourceTimestamp).value();
}

/// Result of an operation yielding a @ref NodeAccessor.
using NodeAccessorResult = Result<NodeAccessor>;
/// Result of an operation yielding a @ref MethodAccessor.
using MethodAccessorResult = Result<MethodAccessor>;
/// Result of an operation yielding a @ref VariableAccessor.
using VariableAccessorResult = Result<VariableAccessor>;
/// Result of an operation yielding a node's @ref References.
using ReferencesResult = Result<References>;

}  // namespace ua

#endif  // UA_NODE_ACCESSOR_H
