// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Options and callbacks that control how a type is instantiated into the address space.
/// @ingroup address_space

#ifndef UA_INSTANTIATION_OPTIONS_H
#define UA_INSTANTIATION_OPTIONS_H

#include "ua_access_level_type.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>

namespace ua
{

/// The namespace of every direct `IrdiDictionaryEntryType` instance (OPC 10000-19 5.3). Register it
/// before instantiating such an entry: instantiation never registers a namespace.
inline constexpr std::string_view irdiDictionaryNamespaceUri{"http://opcfoundation.org/UA/Dictionary/IRDI"};

/// The namespace of every direct `UriDictionaryEntryType` instance (OPC 10000-19 5.4). Register it
/// before instantiating such an entry: instantiation never registers a namespace.
inline constexpr std::string_view uriDictionaryNamespaceUri{"http://opcfoundation.org/UA/Dictionary/URI"};

/// Callback that allocates the NodeId for a newly instantiated node.
///
/// Invoked once per node created during instantiation. It receives the namespace
/// index in which the node is being created and the browse name of the node, and
/// must return a NodeId that is unique within the address space. The browse name
/// lets an allocator assign specific (for example OPC-reserved) ids per member.
///
/// @param namespaceIndex Namespace index the new node is allocated in.
/// @param browseName     Browse name of the node being created.
/// @return A NodeId that must be unique within the address space.
using NodeIdAllocator = std::function<NodeId(uint16_t namespaceIndex, const QualifiedName& browseName)>;

/// Describes an Optional child declaration offered to the optional-child filter.
///
/// One instance is passed to an @ref OptionalChildFilter for each candidate child
/// so the filter can decide whether to instantiate it.
/// @ingroup address_space
struct ChildFilterInfo
{
  QualifiedName browseName;  ///< Browse name of the candidate child.
  NodeClass nodeClass{NodeClass::Unspecified};  ///< Node class of the candidate child.
  NodeId typeDefinition;  ///< Type definition of the child; empty if it has no
                          ///< HasTypeDefinition reference.
  /// Type definition of the node the child would be created under. An Optional declared on a
  /// supertype is offered under every subtype that inherits it, so this is what lets a filter accept
  /// it for one owner (say, LastTransition under a ShelvedStateMachineType) and not for another.
  NodeId parentTypeDefinition;
};

/// Predicate invoked for each Optional child during instantiation.
///
/// Called for each Node the type (or one of its InstanceDeclarations) references with
/// HierarchicalReferences or any subtype of it other than HasSubtype, and whose ModellingRule is
/// Optional. That includes a Node with no ModellingRule, which OPC 10000-3 section 6.4.2 leaves
/// off the instance; NS0 gives `ConditionType.SupportsFilteredRetain` none, and a filter may accept
/// it. A declaration whose ModellingRule is OptionalPlaceholder, MandatoryPlaceholder or
/// ExposesItsArray is never offered and never created: it names no member of its own (OPC 10000-3
/// sections 6.4.4.4.3 to 6.4.4.4.5), so the application adds those members itself. Return true to
/// instantiate the child, false to skip it.
///
/// @param info Description of the candidate child.
/// @return True to instantiate the child, false to skip it.
using OptionalChildFilter = std::function<bool(const ChildFilterInfo&)>;

/// Names the concrete type of a member whose declared type is abstract.
///
/// OPC 10000-3 section 6.2.1: "The type of an InstanceDeclaration may be abstract, however the instance
/// must be of a concrete type." When a member the instantiation creates is declared with an abstract type
/// that no concrete subtype of the instantiated type redeclares, the SDK cannot choose: it calls this, with
/// the member's description (its `typeDefinition` is the abstract declared type). The answer must be a
/// concrete subtype of that type. The member is then created with it, with the concrete type's own
/// Mandatory members; its own Optional members are offered to `InstantiationOptions::optionalChildFilter`
/// only when `InstantiationOptions::instantiateNestedTypeOptionals` is set, as for any member's type.
/// Returning `std::nullopt`, an abstract type or a type that is not a subtype refuses the instantiation with
/// `Bad_TypeDefinitionInvalid`, as does leaving the resolver unset.
///
/// @param info Description of the member; `typeDefinition` is its abstract declared type.
/// @return The concrete subtype to create the member with, or `std::nullopt` to refuse.
using MemberTypeResolver = std::function<std::optional<NodeId>(const ChildFilterInfo&)>;

/// Tunable options controlling a single type-instantiation operation.
///
/// All fields are optional; a default-constructed instance instantiates only
/// mandatory children using the SDK's default string-based NodeId allocation.
/// @ingroup address_space
struct InstantiationOptions
{
  std::optional<NodeId> parentReferenceType;  ///< Reference type linking the parent to the new
                                              ///< instance; unset uses the SDK default.

  /// Custom allocator for node IDs.
  ///
  /// When set, used instead of the default string-based allocator (`inst:{counter}`).
  /// Use @ref guid_node_id_allocator for Guid-based IDs. Unset selects the default.
  /// Direct IrdiDictionaryEntryType and UriDictionaryEntryType roots are the exception:
  /// OPC UA Part 19 requires their String NodeId identifier to equal the external
  /// dictionary identifier supplied as the BrowseName, so the service does not invoke
  /// this allocator for those roots.
  NodeIdAllocator nodeIdAllocator;

  /// Filter deciding which Optional children to instantiate.
  ///
  /// When set, called for each member whose ModellingRule is Optional, or that has none (see
  /// @ref OptionalChildFilter); return true to instantiate. When unset (default), only Mandatory
  /// members are instantiated.
  OptionalChildFilter optionalChildFilter;

  /// Namespace index override for the entire instantiated subtree.
  ///
  /// When set, the whole subtree is allocated in this namespace index regardless of
  /// the parent's namespace index, and this value is passed to the allocator and used
  /// by the default string-id fallback.
  ///
  /// When unset: the allocator receives the parent's namespace index; if the parent is
  /// in namespace index 0, the SDK falls back to namespace index 1 because OPC UA
  /// Part 5 4.1 forbids server-generated nodes from living in namespace index 0
  /// ("they are not defined by the OPC Foundation but generated by the Server").
  /// Namespace index 1 is the spec-reserved local-server slot.
  /// Direct IrdiDictionaryEntryType and UriDictionaryEntryType roots are the exception: OPC
  /// 10000-19 5.3 and 5.4 fix their namespaces to @ref irdiDictionaryNamespaceUri and
  /// @ref uriDictionaryNamespaceUri. For those roots, unset means that namespace, which must already
  /// be registered (instantiation never registers one; otherwise `Bad_InvalidState` naming the URI);
  /// an override naming any other namespace is refused with `Bad_InvalidArgument`. The root's NodeId
  /// is the external dictionary identifier, passed as the BrowseName's name, and
  /// @ref nodeIdAllocator applies to the children only.
  std::optional<uint16_t> targetNamespaceIndex;

  /// Also instantiate OPTIONAL children declared on a child's TYPE DEFINITION but not redeclared on
  /// its instance declaration (e.g. TwoStateVariableType.TransitionTime under a Condition's
  /// EnabledState). Off by default - the normal walk only surfaces children the declaring type
  /// redeclares, which is what most callers want and bounds instantiation depth. Opt-in callers (the
  /// conditions subsystem, whose state machines need these nested optionals) set this true; it is
  /// gated by @ref optionalChildFilter, so only filter-accepted optionals are added.
  bool instantiateNestedTypeOptionals = false;

  /// Names the concrete type of a member declared with an abstract type (see @ref MemberTypeResolver).
  /// Unset: such a member refuses the instantiation with `Bad_TypeDefinitionInvalid`. Of the NS0 types
  /// the server loads (it omits the PubSub model), only ServerUnitType needs one, and only when
  /// @ref optionalChildFilter accepts its Optional CoherentUnit, declared with UnitType; the
  /// specification does not say which concrete subtype that is. In the PubSub model, the Mandatory
  /// Address of PubSubConnectionType is declared with NetworkAddressType.
  MemberTypeResolver memberTypeResolver{};
};

/// Returns a `NodeIdAllocator` that generates Guid-based NodeIds.
///
/// Suitable as `InstantiationOptions::nodeIdAllocator` when globally unique,
/// non-deterministic NodeIds are desired instead of the default string-based ids.
///
/// @return An allocator producing a fresh Guid NodeId per node.
NodeIdAllocator guid_node_id_allocator();

/// Attribute overrides applied to a Variable node as it is instantiated.
///
/// Passed to @ref InstantiationService::instantiate_variable_async to set
/// instance-specific Variable attributes that differ from the VariableType
/// definition. Each field is optional: an absent (`std::nullopt`) field leaves
/// the attribute at the value inherited from the type definition, while a
/// present field overrides it on the new instance.
///
/// @ingroup address_space
struct VariableInstantiationAttributes
{
  /// DataType of the instance's Value, or `std::nullopt` to inherit from the type.
  std::optional<NodeId> dataType;

  /// ValueRank of the instance, or `std::nullopt` to inherit from the type.
  ///
  /// Encoded per OPC UA Part 3 5.6.2: `-3` ScalarOrOneDimension, `-2` Any,
  /// `-1` Scalar, `0` OneOrMoreDimensions, and `n > 0` a fixed dimension count.
  /// @see ValueRank
  std::optional<int32_t> valueRank;

  /// AccessLevel bitmask of the instance, or `std::nullopt` to leave the node's default.
  ///
  /// Unlike @ref dataType and @ref valueRank there is nothing to inherit: a VariableType
  /// has no AccessLevel attribute (OPC 10000-3 5.6.5), so a nullopt here is a default, not
  /// an inheritance.
  std::optional<AccessLevelType> accessLevel;
};

}  // namespace ua

#endif  // UA_INSTANTIATION_OPTIONS_H
