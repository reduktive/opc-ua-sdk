// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_ITEMS_H
#define UA_NAMESPACE_ITEMS_H

/// @file
/// @brief The item and result types of the batched `Namespace` members.
/// @ingroup address_space

#include "ua_browse_direction.h"
#include "ua_byte_string.h"
#include "ua_defines.h"
#include "ua_expanded_node_id.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_reference.h"
#include "ua_result.h"
#include "ua_role_permission_type.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace ua
{

class CallMethodRequest;
class ReadValueId;
class WriteValue;
struct MethodCallContext;

// --- References ----------------------------------------------------------------------------------

/// One Node whose References `Namespace::read_references_async` is asked for.
///
/// `direction` and `referenceTypeHint` are hints. The service filters every answer again by
/// ReferenceType and subtypes, NodeClass mask and View, so a namespace that ignores both is correct. A
/// namespace that applies `referenceTypeHint` may leave a Reference out only when it knows the
/// Reference's type is neither a hinted type nor a subtype of one; when unsure it returns the Reference,
/// because the service cannot restore what was never returned. For namespace-0 ReferenceTypes the SDK
/// provides that test; a namespace cannot know subtypes defined in other namespaces, and a gateway that
/// forwards the hint upstream with `includeSubtypes` meets the rule through its upstream server.
///
/// **Lifetime.** `node` refers to a Node the caller holds until the call completes; every other field is
/// valid until the member returns.
/// @ingroup address_space
struct ReferenceQuery
{
  /// The Node this namespace returned for @ref nodeId, held by the caller until the call completes. A
  /// namespace with its own Node class checks it before use (a checked cast, its own Node, the same
  /// NodeId) and fails a mismatched item with `Bad_InvalidArgument` and the ErrorDetail `ForeignNode`;
  /// one that keeps no Node objects ignores it. A Node whose `deleted()` is true is answered
  /// `Bad_NodeIdUnknown`. Never `static_cast` it.
  const Node& node;

  /// The Node whose References are read.
  NodeId nodeId;

  /// The References wanted; a hint (see above). A symmetric Reference is always forward to the services
  /// (OPC 10000-4 5.8.2.2, Table 34), including one held as inverse, so a namespace that applies the
  /// direction leaves an inverse Reference out of a `Forward` query only when it knows the Reference's
  /// type is not symmetric; when unsure it returns the Reference.
  BrowseDirection direction{BrowseDirection::Both};

  /// ReferenceTypes the caller will keep, with their subtypes; empty for all. A hint (see above).
  std::vector<NodeId> referenceTypeHint;

  /// The most References to return in this answer; 0 for no limit.
  uint32_t maxReferences{0};

  /// Where to resume, from a previous answer's `resumeToken`; empty on the first call.
  ByteString resumeToken;
};

/// One answer of `Namespace::read_references_async`: References the Node holds, and where to resume.
///
/// Each Reference names its type, its target and its direction only. The namespace does not fill in the
/// target's Attributes; the services look targets up themselves.
/// @ingroup address_space
struct NodeReferences
{
  /// The References of this page.
  References references;

  /// Where the next call resumes; empty when there are no more References for this query. A token passed
  /// back is consumed by that call whatever it answers; a token the caller abandons instead is released
  /// through `Namespace::release_resume_token` of the namespace that issued it.
  ByteString resumeToken;
};

/// One item's answer of `Namespace::read_references_async`.
using NodeReferencesResult = Result<NodeReferences>;

/// One half of a Reference, held by a Node of the namespace it is sent to, for
/// `Namespace::add_references_async` and `Namespace::remove_references_async`.
///
/// A Reference between two Nodes is two halves (OPC 10000-3: "A bidirectional Reference is modelled as
/// two separate References"): the forward half on the source and the inverse half on the target. Each
/// half is a separate change, sent to the namespace of the Node that holds it. @ref both_halves builds
/// the pair.
/// @ingroup address_space
struct ReferenceChange
{
  /// The Node of this namespace that holds this half.
  NodeId source;

  /// The ReferenceType.
  NodeId referenceType;

  /// The other end. May be in another namespace or another Server.
  ExpandedNodeId target;

  /// `true` for a forward half, `false` for an inverse one.
  bool isForward{true};

  /// The address space created @ref source earlier in this same operation (a NodeSet import or an
  /// instantiation). Creating a Node does not advance versions: the Node keeps the NodeVersion it was
  /// created with, so the namespace advances nothing for the source for this half. It still reports
  /// the source as a @ref VersionedNode when it is versioned, so that the operation's
  /// GeneralModelChangeEvent lists it as added.
  bool sourceCreated{false};

  /// The DisplayName a target in another Server has, as its authority gives it; Browse returns it for that
  /// target
  /// (@ref Reference::target_display_name). Kept with the Reference by an add; unused for a local target and
  /// by a removal.
  std::optional<LocalizedText> targetDisplayName{};

  /// The two halves of one Reference: forward on @p source, inverse on @p target.
  ///
  /// Passed to `add_references_async` it adds both halves; to `remove_references_async` it removes both,
  /// the equivalent of DeleteReferences' `deleteBidirectional` TRUE. The address space sends each half to
  /// its holder's namespace. Both halves have `sourceCreated` false. A creator sets the flag on each half
  /// whose `source` it created in the same operation: for a new child under an existing parent, the
  /// second half, which the child holds; the parent's half keeps false, and the parent's NodeVersion
  /// advances.
  ///
  /// @param source        The Node holding the forward half.
  /// @param referenceType The ReferenceType.
  /// @param target        The Node holding the inverse half; local, so that it can hold one.
  /// @return `{forward half on source, inverse half on target}`.
  [[nodiscard]] static std::array<ReferenceChange, 2> both_halves(
    NodeId source, NodeId referenceType, NodeId target);
};

// --- Values ---------------------------------------------------------------------------------------

/// One Value read by `Namespace::read_values_async`: the Variable's Node and what is read of it.
///
/// **Lifetime.** `node` refers to a Node the caller holds until the call completes; `value` is valid
/// until the member returns, so a namespace that answers later copies what it needs from it first.
/// @ingroup address_space
struct ValueReadItem
{
  /// The Node this namespace returned for `value`'s NodeId, held by the caller until the call
  /// completes: the service's lookup, the accessor's own Node, or the monitoring helper's registration.
  /// Checked before use as @ref ReferenceQuery::node says; a mismatch fails this item only, with
  /// `Bad_InvalidArgument` and the ErrorDetail `ForeignNode`, and is never replaced by a lookup.
  const Node& node;

  /// The NodeId, the IndexRange to apply (OPC 10000-4 7.27) and the DataEncoding, which the service
  /// applies. The AttributeId is always Value.
  const ReadValueId& value;
};

/// One Value written by `Namespace::write_async`: the Node and the write.
///
/// **Lifetime.** `node` refers to a Node the caller holds until the call completes; `value` is valid
/// until the member returns, so a namespace that applies the write later copies it first.
/// @ingroup address_space
struct ValueWriteItem
{
  /// The Node this namespace returned for `value`'s NodeId; checked before use as
  /// @ref ValueReadItem::node says.
  const Node& node;

  /// The NodeId, the AttributeId, the IndexRange or OptionSet ValidBits to apply, and the DataValue.
  const WriteValue& value;
};

// --- Calls ----------------------------------------------------------------------------------------

/// One Method call for `Namespace::call_async`.
///
/// The Call service asks the Object's namespace first and the Method's namespace for the items the first
/// declines, so each namespace checks and uses only the Node that is its own: the Object's namespace
/// `object`, the Method's namespace `method`.
///
/// **Lifetime.** `object` and `method` refer to Nodes the caller holds until the call completes;
/// `request` is valid until the member returns, so a namespace that answers later copies it first;
/// `context` is shared and may be kept by a handler that answers later.
/// @ingroup address_space
struct CallItem
{
  /// The Object or ObjectType the Method is called on, as its namespace returned it.
  const Node& object;

  /// The Method, as its namespace returned it; may be of a different namespace from `object`.
  const Node& method;

  /// The objectId, methodId and input arguments.
  const CallMethodRequest& request;

  /// The per-call context handed to the Method's handler; null for a call with no Session.
  shared_ptr<const MethodCallContext> context;
};

// --- Creation, deletion and versions -------------------------------------------------------------

/// One Node to create with `Namespace::create_nodes_async`.
/// @ingroup address_space
struct NodeCreation
{
  /// The new Node's NodeId; not yet held by this namespace.
  NodeId nodeId;

  /// The new Node's NodeClass.
  NodeClass nodeClass{NodeClass::Unspecified};

  /// The new Node's Attributes in wire form, as AddNodes carries them; may be empty for a bare Node.
  /// `NodeDescription::try_from_attributes` builds a description from them in one step.
  InitialAttributes attributes;
};

/// A Node a call changed whose NodeVersion that change advanced. The output of the members that change
/// structure or a versioned Attribute.
///
/// A Node is versioned when it has a HasProperty Reference to a Node of the same namespace whose
/// BrowseName is 0:NodeVersion and that has no ModellingRule (an InstanceDeclaration does not count). A
/// NodeVersion Property held in another namespace than its owner is not supported.
///
/// The namespace that changes a versioned Node advances its NodeVersion in the same call and reports the
/// Node here; the address space then raises one GeneralModelChangeEvent for the operation (OPC 10000-3
/// 9.32.6, OPC 10000-5 6.4.32), listing the reported Nodes. OPC 10000-3 9.32.2: every NodeVersion change
/// raises a ModelChangeEvent, every ModelChangeEvent issued for a Node changes its NodeVersion, and only
/// Nodes that have a NodeVersion trigger one. So the output lists only Nodes whose NodeVersion the call
/// changed:
///
/// - a View Node only when it gained or lost a Reference. A change of a View's content advances its
///   ViewVersion, which the namespace does itself, and is never reported: the View Node's NodeVersion
///   does not change for it (OPC 10000-3 5.4, Table 10);
/// - the one exception is a Node the address space created earlier in the same operation and that
///   gains a half marked @ref ReferenceChange::sourceCreated "ReferenceChange::sourceCreated": it keeps the
///   NodeVersion it was created with and is still reported, so that the event lists it as added.
/// @ingroup address_space
struct VersionedNode
{
  /// The Node that changed.
  NodeId node;

  /// The Node's TypeDefinition when it is an Object or Variable, from the HasTypeDefinition the
  /// namespace holds (for a deleted Node, the TypeDefinition it had); otherwise null (OPC 10000-5 12.16,
  /// `affectedType`).
  NodeId affectedType;
};

/// One change a namespace made to its own Nodes outside the address space's routes, reported through
/// `NamespaceContext::model_changed` (NR-36 rule 3, NR-55).
///
/// Report only Nodes whose NodeVersion the change advanced, after advancing it, as @ref VersionedNode states:
/// a ModelChangeEvent for a Node whose NodeVersion did not change breaks OPC 10000-3 9.32.2.
/// @ingroup address_space
struct ModelChangeReport
{
  /// What changed.
  enum class Kind
  {
    NodeAdded,  ///< A verb of a GeneralModelChangeEvent (OPC 10000-5 12.16).
    NodeDeleted,  ///< A verb of a GeneralModelChangeEvent.
    ReferenceAdded,  ///< A verb of a GeneralModelChangeEvent, for the Node holding the half.
    ReferenceDeleted,  ///< A verb of a GeneralModelChangeEvent, for the Node holding the half.
    DataTypeChanged,  ///< A verb of a GeneralModelChangeEvent; Variables and VariableTypes only.
    ValueRankChanged,  ///< No verb names it: the event is a BaseModelChangeEvent.
    ArrayDimensionsChanged,  ///< No verb names it: the event is a BaseModelChangeEvent.
    ViewContentChanged,  ///< The View's ViewVersion advanced; listed in no event (OPC 10000-3 5.4).
  };

  /// What changed.
  Kind kind{Kind::NodeAdded};

  /// The Node that changed; for ViewContentChanged, the View.
  NodeId affected;

  /// The Node's TypeDefinition when it is an Object or Variable (for NodeDeleted, the one it had); otherwise
  /// null.
  NodeId affectedType;
};

/// One entry of a SemanticChangeEvent (OPC 10000-3 9.33.1, OPC 10000-5 12.17): a Property with the
/// SemanticChange flag changed its Value, and this is the Node that owns it. A namespace reports it through
/// @ref NamespaceContext::semantics_changed.
/// @ingroup address_space
struct SemanticChangeReport
{
  /// The Node that owns the Property.
  NodeId affected;

  /// Its TypeDefinition when it is an Object or Variable; otherwise null.
  NodeId affectedType;
};

// --- Access control -------------------------------------------------------------------------------

/// One proposed change of a Node's RolePermissions, for
/// `Namespace::validate_role_permissions_updates_async`.
/// @ingroup address_space
struct RolePermissionsUpdate
{
  /// The existing Node whose RolePermissions would change.
  NodeId nodeId;

  /// The exact non-empty array the Write service would store, or `nullopt` for the OPC 10000-3 5.2.9
  /// empty-array write that clears the Node's own RolePermissions so that the namespace's
  /// DefaultRolePermissions apply.
  std::optional<std::vector<RolePermissionType>> proposed;
};

}  // namespace ua

#endif  // UA_NAMESPACE_ITEMS_H
