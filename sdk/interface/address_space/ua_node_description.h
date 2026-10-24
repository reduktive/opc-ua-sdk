// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODE_DESCRIPTION_H
#define UA_NODE_DESCRIPTION_H

/// @file
/// @brief A Node's non-Value Attributes as one immutable value, and the creation input it is built from.
/// @ingroup address_space

#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_data_value.h"
#include "ua_defines.h"
#include "ua_duration.h"
#include "ua_event_notifier_type.h"
#include "ua_localized_text.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_role_permission_type.h"
#include "ua_value_rank.h"
#include "ua_variant.h"

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace ua
{

class DataTypeDefinition;

/// One standard OPC UA attribute (id + wire-form value) to apply to a node at creation.
///
/// The element type of `InitialAttributes`. The id selects the attribute and the
/// `Variant` carries its value in OPC UA wire form, as a Write of that attribute carries it.
using InitialAttribute = std::pair<AttributeId, Variant>;

/// An ordered set of attributes to apply atomically when a node is created.
///
/// Carried by `AddressSpace::create_node_async` into `Namespace::create_nodes_async` (as
/// `NodeCreation::attributes`) so a node is built with its full static state in **one** async op -
/// inline for an in-memory namespace, a single backend round-trip for a remote one - instead of a
/// post-create burst of individual attribute writes (one round-trip per attribute for a remote
/// namespace). Mirrors the wire `AddNodes` model, where attributes travel inside the `AddNodesItem`.
/// A Variable's live value is not a creation attribute (set it through a Write or the Variable's
/// value source);
/// a VariableType's static default Value may be supplied here, as the value's Variant (as
/// `VariableTypeAttributes.value` carries it) or as a DataValue holding it.
using InitialAttributes = std::vector<InitialAttribute>;

class NodeDescription;

/// A @ref NodeDescription, or the reason one could not be built.
using NodeDescriptionResult = Result<NodeDescription>;

/// A Node's non-Value Attributes, as one immutable value.
///
/// This is what `Node::attributes()` returns and what every reader of a Node's Attributes reads: the
/// accessor getters, Browse and TranslateBrowsePaths, access control, event filters and the Read service
/// for every Attribute but a Variable's Value. A namespace author builds descriptions with the factories
/// below (or @ref try_from_attributes from an `AddNodes`-shaped attribute list) and never writes a class
/// that stores Attributes.
///
/// **Not in a description.** A Variable's Value, which is read through `Namespace::read_values_async`
/// because it is live and may differ per caller; and the four Attributes derived per Session
/// (`UserAccessLevel`, `UserWriteMask`, `UserExecutable`, `UserRolePermissions`), which the services
/// compute from the stored Attribute and the Session's permissions (see @ref is_session_derived_attribute).
/// A VariableType's Value is a description Attribute: it is the type's static default.
///
/// **Storage and copying.** A description is a handle to one immutable body. Copying a description copies
/// a pointer; no Attribute is copied. A body never changes once built: each `with_...` member builds a new
/// body holding every field of the old one with one field replaced, and leaves the original untouched.
/// A reader that took a description before a change keeps reading the old body, consistently, until it
/// lets go of it. The body's layout is private to the implementation and may change without an API change.
///
/// **Readers return references into the body and are deleted on rvalues.**
/// `node->attributes().browse_name()` does not compile: hold the description in a variable first, so
/// the reference cannot outlive the body it points into.
///
/// **NodeClass-specific Attributes.** A reader of an Attribute the NodeClass does not define answers
/// absent (`nullopt` or `nullptr`), as it does for an optional Attribute the Node does not carry. A
/// `with_...` of an Attribute the NodeClass does not define throws `UaException` with
/// `Bad_InvalidArgument`; its `try_with_...` form returns that status instead. Attributes of every
/// NodeClass have only the `with_...` form, which cannot fail.
///
/// Attribute applicability follows OPC 10000-3 clause 5 (Tables 7 to 16).
/// @ingroup address_space
class NodeDescription
{
public:
  // --- Factories: mandatory Attributes are parameters ----------------------------------------------
  //
  // Defaults for the rest: DisplayName is the BrowseName's text with no locale; a Variable's
  // AccessLevel is CurrentRead and its Historizing false; a Method's Executable true; IsAbstract,
  // Symmetric and ContainsNoLoops false; EventNotifier none. Optional Attributes are absent.

  /// An Object (OPC 10000-3 5.5.1).
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @return The description.
  [[nodiscard]] static NodeDescription object(NodeId nodeId, QualifiedName browseName);

  /// A Variable (OPC 10000-3 5.6.2). Its Value is not part of the description.
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @param dataType   The NodeId of the Variable's DataType.
  /// @param valueRank  The Variable's ValueRank; scalar by default.
  /// @return The description.
  [[nodiscard]] static NodeDescription variable(
    NodeId nodeId, QualifiedName browseName, NodeId dataType, ValueRank valueRank = ValueRank::scalar);

  /// A Method (OPC 10000-3 5.7).
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @return The description.
  [[nodiscard]] static NodeDescription method(NodeId nodeId, QualifiedName browseName);

  /// An ObjectType (OPC 10000-3 5.5.2).
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @param isAbstract The IsAbstract Attribute.
  /// @return The description.
  [[nodiscard]] static NodeDescription object_type(
    NodeId nodeId, QualifiedName browseName, bool isAbstract = false);

  /// A VariableType (OPC 10000-3 5.6.5), with no default Value.
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @param dataType   The NodeId of the type's DataType.
  /// @param valueRank  The type's ValueRank.
  /// @param isAbstract The IsAbstract Attribute.
  /// @return The description.
  [[nodiscard]] static NodeDescription variable_type(
    NodeId nodeId, QualifiedName browseName, NodeId dataType, ValueRank valueRank, bool isAbstract = false);

  /// A DataType (OPC 10000-3 5.8.3), with no DataTypeDefinition.
  ///
  /// Overloads the static factory name with the @ref data_type() reader; the parameter lists differ.
  /// @param nodeId     The Node's NodeId.
  /// @param browseName The Node's BrowseName.
  /// @param isAbstract The IsAbstract Attribute.
  /// @return The description.
  [[nodiscard]] static NodeDescription data_type(
    NodeId nodeId, QualifiedName browseName, bool isAbstract = false);

  /// A ReferenceType (OPC 10000-3 5.3).
  ///
  /// Fallible because the Attributes constrain each other: a symmetric ReferenceType has no
  /// InverseName, and a non-symmetric one has one.
  /// @param nodeId      The Node's NodeId.
  /// @param browseName  The Node's BrowseName.
  /// @param isAbstract  The IsAbstract Attribute.
  /// @param symmetric   The Symmetric Attribute.
  /// @param inverseName The InverseName; engaged exactly when @p symmetric is false.
  /// @return The description, or `Bad_InvalidArgument` with an ErrorDetail naming the conflict. Never
  ///         throws.
  [[nodiscard]] static NodeDescriptionResult try_reference_type(NodeId nodeId, QualifiedName browseName,
    bool isAbstract, bool symmetric, std::optional<LocalizedText> inverseName) noexcept;

  /// A View (OPC 10000-3 5.4).
  /// @param nodeId          The Node's NodeId.
  /// @param browseName      The Node's BrowseName.
  /// @param containsNoLoops The ContainsNoLoops Attribute.
  /// @return The description.
  [[nodiscard]] static NodeDescription view(
    NodeId nodeId, QualifiedName browseName, bool containsNoLoops = false);

  /// Builds a description from an `AddNodes`-shaped attribute list, in one body.
  ///
  /// The form NodeSet import, instantiation and `AddressSpace::create_node_async` hand a namespace, so a
  /// namespace that keeps descriptions builds each new Node with this one call. Attributes the list does
  /// not carry take the factory defaults above. A Variable or VariableType with no DataType takes
  /// `BaseDataType` (i=24). One with no ValueRank takes scalar, which is what the SDK's accessor getters
  /// answer today for an in-memory Node created without one. A list that names no BrowseName gives an
  /// empty one: a bare Node, named by a later write, is permitted. For the same reason the InverseName
  /// rule of @ref try_reference_type is not applied. A VariableType's Value may be given as the value's
  /// Variant or as a DataValue holding it; either is held as a DataValue. A null or empty RolePermissions
  /// array gives no RolePermissions of the Node's own, and a null or empty ArrayDimensions array no
  /// ArrayDimensions (OPC 10000-6 5.1.9). AccessLevel and AccessLevelEx are one value, as
  /// @ref try_with_attribute writes them, applied in list order: an AccessLevel gives an AccessLevelEx too,
  /// and the last of the two decides the low 8 bits.
  ///
  /// The defaults are the factories', not those of any one namespace. A namespace whose own creation
  /// defaults differ adds them to the list before calling this. The SDK's in-memory namespace does so,
  /// keeping its defaults: a Variable created without an AccessLevel gets CurrentRead and CurrentWrite.
  ///
  /// @param nodeId     The new Node's NodeId.
  /// @param nodeClass  The new Node's NodeClass.
  /// @param attributes Attribute values in wire form; may be empty.
  /// @return The description; or `Bad_NodeClassInvalid` when @p nodeClass is `Unspecified` or not a
  ///         NodeClass; or `Bad_NodeAttributesInvalid` when the list carries an Attribute that
  ///         @p nodeClass does not have (a Session-derived Attribute and a Variable's Value included); or
  ///         `Bad_TypeMismatch` when a value is not of its Attribute's type; or `Bad_InvalidArgument` for a
  ///         ValueRank below the lowest defined ValueRank. Each failure carries an ErrorDetail naming the
  ///         Attribute. Never throws.
  [[nodiscard]] static NodeDescriptionResult try_from_attributes(
    const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& attributes) noexcept;

  /// Copies share the immutable body; both descriptions remain valid.
  NodeDescription(const NodeDescription&) noexcept = default;
  /// Copy-assigns, sharing the immutable body and retaining both descriptions.
  /// @return This object after assignment.
  NodeDescription& operator=(const NodeDescription&) noexcept = default;
  /// Moving copies the pointer: a moved-from description still reads the same body, so no reader can
  /// reach a description without one.
  /// @param other Description whose body is shared; remains valid.
  NodeDescription(NodeDescription&& other) noexcept;
  /// Moving copies the pointer; see the move constructor.
  /// @param other Description whose body is shared; remains valid.
  /// @return This object after assignment.
  NodeDescription& operator=(NodeDescription&& other) noexcept;
  ~NodeDescription() = default;

  // --- Modified copies: Attributes of every NodeClass ----------------------------------------------

  /// @param value The new BrowseName.
  /// @return A copy with the BrowseName replaced.
  [[nodiscard]] NodeDescription with_browse_name(QualifiedName value) const;
  /// @param value The new DisplayName, replaced whole (merging per locale is the writer's step).
  /// @return A copy with the DisplayName replaced.
  [[nodiscard]] NodeDescription with_display_name(LocalizedText value) const;
  /// @param value The new Description, or `nullopt` to remove it.
  /// @return A copy with the Description replaced.
  [[nodiscard]] NodeDescription with_description(std::optional<LocalizedText> value) const;
  /// @param value The new WriteMask, or `nullopt` to remove it.
  /// @return A copy with the WriteMask replaced.
  [[nodiscard]] NodeDescription with_write_mask(std::optional<AttributeWriteMask> value) const;
  /// @param value The Node's own RolePermissions, or `nullopt` or an empty list to remove them, so that the
  ///              namespace's DefaultRolePermissions apply (OPC 10000-3 5.2.9).
  /// @return A copy with the RolePermissions replaced.
  [[nodiscard]] NodeDescription with_role_permissions(
    std::optional<std::vector<RolePermissionType>> value) const;
  /// @param value The new AccessRestrictions, or `nullopt` to remove them.
  /// @return A copy with the AccessRestrictions replaced.
  [[nodiscard]] NodeDescription with_access_restrictions(std::optional<AccessRestrictionType> value) const;

  // --- Modified copies: NodeClass-specific Attributes ----------------------------------------------
  //
  // Each `with_...` throws UaException(Bad_InvalidArgument) when the NodeClass does not define the
  // Attribute; each `try_with_...` returns that status, with an ErrorDetail naming the Attribute and the
  // NodeClass, and never throws.

  /// @param value IsAbstract (ObjectType, VariableType, ReferenceType, DataType).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_is_abstract(bool value) const;
  /// @param value IsAbstract.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_is_abstract(bool value) const noexcept;
  /// @param value Symmetric (ReferenceType). The InverseName constraint is not checked here.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_symmetric(bool value) const;
  /// @param value Symmetric.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_symmetric(bool value) const noexcept;
  /// @param value InverseName (ReferenceType), or `nullopt` to remove it.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_inverse_name(std::optional<LocalizedText> value) const;
  /// @param value InverseName, or `nullopt`.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_inverse_name(
    std::optional<LocalizedText> value) const noexcept;
  /// @param value ContainsNoLoops (View).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_contains_no_loops(bool value) const;
  /// @param value ContainsNoLoops.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_contains_no_loops(bool value) const noexcept;
  /// @param value EventNotifier (Object, View).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_event_notifier(EventNotifierType value) const;
  /// @param value EventNotifier.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_event_notifier(EventNotifierType value) const noexcept;
  /// @param value DataType (Variable, VariableType).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_data_type(NodeId value) const;
  /// @param value DataType.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_data_type(NodeId value) const noexcept;
  /// @param value ValueRank (Variable, VariableType).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_value_rank(ValueRank value) const;
  /// @param value ValueRank.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_value_rank(ValueRank value) const noexcept;
  /// @param value ArrayDimensions (Variable, VariableType), or `nullopt` to remove it.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_array_dimensions(std::optional<std::vector<uint32_t>> value) const;
  /// @param value ArrayDimensions, or `nullopt` or an empty list for none.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_array_dimensions(
    std::optional<std::vector<uint32_t>> value) const noexcept;
  /// @param value AccessLevel (Variable).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_access_level(AccessLevelType value) const;
  /// @param value AccessLevel.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_access_level(AccessLevelType value) const noexcept;
  /// @param value MinimumSamplingInterval in milliseconds (Variable), or `nullopt` to remove it.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_minimum_sampling_interval(std::optional<Duration> value) const;
  /// @param value MinimumSamplingInterval, or `nullopt`.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_minimum_sampling_interval(
    std::optional<Duration> value) const noexcept;
  /// @param value Historizing (Variable).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_historizing(bool value) const;
  /// @param value Historizing.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_historizing(bool value) const noexcept;
  /// @param value AccessLevelEx (Variable), or `nullopt` to remove it.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_access_level_ex(std::optional<AccessLevelExType> value) const;
  /// @param value AccessLevelEx, or `nullopt`.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_access_level_ex(
    std::optional<AccessLevelExType> value) const noexcept;
  /// @param value Executable (Method).
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_executable(bool value) const;
  /// @param value Executable.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_executable(bool value) const noexcept;
  /// @param value DataTypeDefinition (DataType), or null to remove it. Shared, not copied: the new body
  ///              holds the same object. OPC 10000-3 5.8.4 forbids changing a definition once provided
  ///              to Clients; that is the namespace's rule to keep.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_data_type_definition(shared_ptr<const DataTypeDefinition> value) const;
  /// @param value DataTypeDefinition, or null.
  /// @return A copy, or Bad_InvalidArgument.
  [[nodiscard]] NodeDescriptionResult try_with_data_type_definition(
    shared_ptr<const DataTypeDefinition> value) const noexcept;
  /// @param value A VariableType's default Value, or `nullopt` to remove it. A held DataValue with an
  ///              empty value is a held null, distinct from no Value.
  /// @return A copy with the Attribute replaced.
  [[nodiscard]] NodeDescription with_value(std::optional<DataValue> value) const;
  /// @param value The default Value, or `nullopt`.
  /// @return A copy, or Bad_InvalidArgument (also for a Variable, whose Value is not a description
  ///         Attribute).
  [[nodiscard]] NodeDescriptionResult try_with_value(std::optional<DataValue> value) const noexcept;

  /// A copy with one Attribute set from its wire form, as a successful Write of it leaves the Node.
  ///
  /// LocalizedText Attributes (DisplayName, Description, InverseName) are merged per OPC 10000-4
  /// 5.10.4.1 with `LocalizedText::merged_with`: the written locale is replaced, added, or removed when
  /// its text is empty. Every other Attribute is replaced whole. This is the step NR-3 asks of a
  /// namespace that applies writes to its own Node class, and the step `DescribedNodes::record_write`
  /// applies.
  ///
  /// A null value removes nothing silently: it is refused, except where it has a meaning. On a
  /// LocalizedText Attribute it removes every locale. A null or an empty RolePermissions removes the
  /// Node's own RolePermissions, so that the namespace's DefaultRolePermissions apply (OPC 10000-3 5.2.9;
  /// OPC 10000-6 5.1.9); it is not held as an empty list, which would grant nothing. A null or an empty
  /// ArrayDimensions means no ArrayDimensions. A VariableType's Value may be written null. A null removes
  /// AccessRestrictions, MinimumSamplingInterval, AccessLevelEx and DataTypeDefinition, the optional
  /// Attributes the accessor's setters clear with a null.
  ///
  /// AccessLevel and AccessLevelEx are one value: AccessLevelEx "contains the 8 bits of the AccessLevel
  /// attribute as the first 8 bits" (OPC 10000-3 5.6.2). A write of AccessLevel replaces AccessLevelEx's low
  /// 8 bits, and gives the Node an AccessLevelEx from then on; a write of AccessLevelEx replaces AccessLevel.
  ///
  /// @param attributeId The Attribute written.
  /// @param value       The written value in wire form, as the Write service delivers it.
  /// @return The copy; or `Bad_AttributeIdInvalid` for NodeId, NodeClass, a Session-derived Attribute,
  ///         an Attribute the NodeClass does not define or a Variable's Value; or `Bad_TypeMismatch` when
  ///         the value does not fit the Attribute, a null on any Attribute but those above included; or
  ///         `Bad_InvalidArgument` for a ValueRank below the lowest defined ValueRank. Never throws.
  [[nodiscard]] NodeDescriptionResult try_with_attribute(
    AttributeId attributeId, const Variant& value) const noexcept;

  // --- Readers: from a named description only ------------------------------------------------------

  /// @return The NodeId.
  [[nodiscard]] const NodeId& node_id() const& noexcept;
  const NodeId& node_id() const&& = delete;
  /// @return The NodeClass.
  [[nodiscard]] NodeClass node_class() const noexcept;
  /// @return The BrowseName; empty for a bare Node not yet named.
  [[nodiscard]] const QualifiedName& browse_name() const& noexcept;
  const QualifiedName& browse_name() const&& = delete;
  /// @return The DisplayName, in every locale the Node holds.
  [[nodiscard]] const LocalizedText& display_name() const& noexcept;
  const LocalizedText& display_name() const&& = delete;
  /// @return The Description, or nullptr when the Node has none.
  [[nodiscard]] const LocalizedText* description() const& noexcept;
  const LocalizedText* description() const&& = delete;
  /// @return The WriteMask, or `nullopt` when the Node has none.
  [[nodiscard]] std::optional<AttributeWriteMask> write_mask() const noexcept;
  /// @return The Node's own RolePermissions, or nullptr when it has none and the namespace's
  ///         DefaultRolePermissions apply. An empty array is never held: every member reads an empty
  ///         RolePermissions as removing the Node's own (OPC 10000-3 5.2.9).
  [[nodiscard]] const std::vector<RolePermissionType>* role_permissions() const& noexcept;
  const std::vector<RolePermissionType>* role_permissions() const&& = delete;
  /// @return The AccessRestrictions, or `nullopt` when the Node has none.
  [[nodiscard]] std::optional<AccessRestrictionType> access_restrictions() const noexcept;
  /// @return IsAbstract, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<bool> is_abstract() const noexcept;
  /// @return Symmetric, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<bool> symmetric() const noexcept;
  /// @return The InverseName, or nullptr when the Node has none.
  [[nodiscard]] const LocalizedText* inverse_name() const& noexcept;
  const LocalizedText* inverse_name() const&& = delete;
  /// @return ContainsNoLoops, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<bool> contains_no_loops() const noexcept;
  /// @return EventNotifier, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<EventNotifierType> event_notifier() const noexcept;
  /// @return The DataType's NodeId, or nullptr when the NodeClass does not define it.
  [[nodiscard]] const NodeId* data_type() const& noexcept;
  const NodeId* data_type() const&& = delete;
  /// @return ValueRank, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<ValueRank> value_rank() const noexcept;
  /// @return ArrayDimensions, or nullptr when the Node has none.
  [[nodiscard]] const std::vector<uint32_t>* array_dimensions() const& noexcept;
  const std::vector<uint32_t>* array_dimensions() const&& = delete;
  /// @return AccessLevel, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<AccessLevelType> access_level() const noexcept;
  /// @return MinimumSamplingInterval in milliseconds, or `nullopt` when the Node has none.
  [[nodiscard]] std::optional<Duration> minimum_sampling_interval() const noexcept;
  /// @return Historizing, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<bool> historizing() const noexcept;
  /// @return AccessLevelEx, or `nullopt` when the Node has none.
  [[nodiscard]] std::optional<AccessLevelExType> access_level_ex() const noexcept;
  /// @return Executable, or `nullopt` when the NodeClass does not define it.
  [[nodiscard]] std::optional<bool> executable() const noexcept;
  /// @return The DataTypeDefinition, or null when the Node has none.
  [[nodiscard]] const shared_ptr<const DataTypeDefinition>& data_type_definition() const& noexcept;
  const shared_ptr<const DataTypeDefinition>& data_type_definition() const&& = delete;
  /// @return A VariableType's default Value, or nullptr when it has none or the Node is not a
  ///         VariableType.
  [[nodiscard]] const DataValue* value() const& noexcept;
  const DataValue* value() const&& = delete;

  /// Reads one Attribute in its wire form, as the Read service returns it. Copies the value.
  ///
  /// @param attributeId The Attribute to read.
  /// @return The value; or `Bad_AttributeIdInvalid` for an Attribute the NodeClass does not define, an
  ///         optional Attribute the Node does not carry, a Session-derived Attribute, or a Variable's
  ///         Value (read through `Namespace::read_values_async`). Never throws.
  [[nodiscard]] DataValueResult attribute(AttributeId attributeId) const noexcept;

private:
  struct Body;  // defined only in the implementation

  explicit NodeDescription(shared_ptr<const Body> body) noexcept;

  shared_ptr<const Body> mBody;  // never null
};

}  // namespace ua

#endif  // UA_NODE_DESCRIPTION_H
