// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Asynchronous instantiation of objects, variables, and optional type members.
/// @ingroup address_space

#ifndef UA_INSTANTIATION_SERVICE_H
#define UA_INSTANTIATION_SERVICE_H

#include "ua_address_space.h"
#include "ua_resource_budgets.h"
#include "ua_instantiation_options.h"
#include "ua_node_subtree.h"
#include "ua_result.h"

#include <functional>
#include <utility>

namespace ua
{

/// Instantiates type-defined nodes (objects, variables, and optional members) into an address space.
///
/// Walks an ObjectType or VariableType definition and materialises its mandatory
/// children (and any selected optional members) under a parent node, allocating
/// NodeIds, attaching HasTypeDefinition and parent edges, and copying attributes
/// recursively. Every operation posts to the owning @ref AddressSpace strand and
/// completes asynchronously on an unspecified worker thread.
///
/// The service holds the @ref AddressSpace by value; the caller need not keep its
/// own copy alive for the duration of a call.
/// @ingroup address_space
class InstantiationService
{
public:
  /// Constructs a service that instantiates into the given address space.
  ///
  /// @param addressSpace Address space the service materialises nodes into; held by
  ///                     value for the lifetime of the service.
  explicit InstantiationService(AddressSpace addressSpace);

  /// Completion callback for an instantiation that creates a node subtree.
  ///
  /// Receives a @ref NodeSubtreeResult - on success the @ref NodeSubtree owning the
  /// created nodes, on failure an @ref ErrorDetail. Runs on an unspecified worker
  /// thread - do not block it.
  using InstantiateCompleteCallback = std::function<void(NodeSubtreeResult)>;

  /// Instantiates an object of `typeDefinition` as a child of `parent`.
  ///
  /// Posts to the address space's strand and completes asynchronously. Creates the
  /// instance node plus its mandatory children (and any optional members selected by
  /// `options.optionalChildFilter`), wiring HasTypeDefinition and the parent edge.
  ///
  /// An abstract `typeDefinition` is refused with `Bad_TypeDefinitionInvalid`
  /// (`InstantiateAbstractType`) before any node is created: no Object of an abstract ObjectType
  /// shall exist (OPC 10000-3 section 5.5.2). A member declared with an abstract type is created with
  /// the concrete subtype `options.memberTypeResolver` names; with no answer the call fails with
  /// `Bad_TypeDefinitionInvalid` (`MemberTypeAbstract`), and with an answer that is not a concrete
  /// subtype of the declared type, `Bad_TypeDefinitionInvalid` (`MemberTypeNotAConcreteSubtype`).
  ///
  /// @param parent         Node the new object is attached to as a child.
  /// @param browseName     Browse name of the new object node.
  /// @param typeDefinition ObjectType whose definition is instantiated.
  /// @param options        Allocation and filtering policy; see @ref InstantiationOptions.
  /// @param complete       Receives the outcome: on success a @ref NodeSubtree rooted at the
  ///                       new object, on failure an @ref ErrorDetail. This overload never throws.
  /// @see instantiate_variable_async, instantiate_optional_members_async
  void instantiate_object_async(const NodeId& parent, const QualifiedName& browseName,
    const NodeId& typeDefinition, const InstantiationOptions& options,
    InstantiateCompleteCallback complete) const noexcept;

  /// Instantiates a variable of `typeDefinition` as a child of `parent`.
  ///
  /// Posts to the address space's strand and completes asynchronously. Behaves like
  /// @ref instantiate_object_async but for a VariableType, applying `attributes` (value,
  /// data type, rank, dimensions) to the created variable node. An abstract VariableType is
  /// refused the same way (OPC 10000-3 section 5.6.5), as is a member declared with an abstract type
  /// that `options.memberTypeResolver` does not resolve.
  ///
  /// @param parent         Node the new variable is attached to as a child.
  /// @param browseName     Browse name of the new variable node.
  /// @param typeDefinition VariableType whose definition is instantiated.
  /// @param options        Allocation and filtering policy; see @ref InstantiationOptions.
  /// @param attributes     Variable-specific attributes applied to the created node.
  /// @param complete       Receives the outcome: on success a @ref NodeSubtree rooted at the
  ///                       new variable, on failure an @ref ErrorDetail. This overload never throws.
  /// @see instantiate_object_async, instantiate_optional_members_async
  void instantiate_variable_async(const NodeId& parent, const QualifiedName& browseName,
    const NodeId& typeDefinition, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes, InstantiateCompleteCallback complete) const noexcept;

  /// Materialises the optional members of `typeDefinition` onto an existing `instance`.
  ///
  /// Posts to the address space's strand and completes asynchronously. Walks the type's
  /// children from `typeDefinition`; for each Optional member accepted by
  /// `options.optionalChildFilter` a node is created (id via `options.nodeIdAllocator`, keyed
  /// by browse name), its HasTypeDefinition and parent edge attached, class-specific
  /// attributes copied, and its own subtree (e.g. a Method's InputArguments /
  /// OutputArguments) recursively instantiated. Mandatory children of selected members
  /// are always materialised. Idempotent: any child already present on `instance` is
  /// skipped.
  ///
  /// The `options` fields used are `optionalChildFilter` (required: it selects the members),
  /// `nodeIdAllocator`, `targetNamespaceIndex`, `instantiateNestedTypeOptionals` and
  /// `memberTypeResolver`; the others do not apply to an existing instance.
  ///
  /// @param instance       Existing node the selected members are added to.
  /// @param typeDefinition Type whose optional members are considered.
  /// @param options        The filter and allocation policy; see @ref InstantiationOptions.
  /// @param complete       Receives the outcome: a success @ref VoidResult, or an
  ///                       @ref ErrorDetail on failure - `Bad_InvalidArgument`
  ///                       (`OptionalMembersFilterUnset`) when `options.optionalChildFilter` is
  ///                       unset, because then no member would be added; `Bad_TypeDefinitionInvalid`
  ///                       when an accepted member is declared with an abstract type that
  ///                       `options.memberTypeResolver` does not resolve. Never throws.
  /// @see instantiate_object_async, instantiate_variable_async
  void instantiate_optional_members_async(const NodeId& instance, const NodeId& typeDefinition,
    const InstantiationOptions& options, std::function<void(VoidResult)> complete) const noexcept;

private:
  AddressSpace mAddressSpace;
};

}  // namespace ua

#endif  // UA_INSTANTIATION_SERVICE_H
