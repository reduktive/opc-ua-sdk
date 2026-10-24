// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Registry owning dynamically discovered structure, union, and enum type descriptors.
/// @ingroup core_types

#ifndef UA_DYNAMIC_TYPE_REGISTRY_H
#define UA_DYNAMIC_TYPE_REGISTRY_H

#include "ua_includes.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_expanded_node_id.h"
#include "ua_result.h"
#include "ua_structure_definition.h"
#include "ua_structure_factory.h"
#include "ua_enum_definition.h"
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace ua
{

/// Central registry that owns dynamic type descriptors keyed by DataType NodeId.
///
/// Holds the descriptors for structures, unions, enums, and option sets discovered at runtime
/// (for example from a server's type dictionary) and exposes them for decoding and resolution.
/// Types must be registered in dependency order - enums first, then structures from leaves
/// inward - because the registry eagerly resolves every field dependency at registration time.
///
/// Use @ref register_all_with to wire the registered types into a decoder pipeline, or
/// @ref make_resolver to obtain a self-contained @ref StructureResolver snapshot.
///
/// All public methods are thread-safe. Registration (write) and lookup/resolve (read) may be
/// called concurrently: registration takes an exclusive lock and lookups take a shared lock.
/// This supports gateway-style servers that discover new upstream types at runtime while
/// existing connections are actively decoding.
/// @ingroup core_types
class DynamicTypeRegistry
{
public:
  /// Constructs an empty registry with no registered types.
  DynamicTypeRegistry() = default;

  /// Registers a structure or union type.
  ///
  /// Builds a @ref DynamicStructureTypeDescriptor and eagerly resolves all field dependencies
  /// (nested structures and enum/option-set field types) against the already-registered types.
  /// Dependencies must therefore be registered first: a structure can only reference types that
  /// are already present. For Union and UnionWithSubtypedValues structure types,
  /// @ref make_resolver produces DynamicUnion instances; for all other structure types it
  /// produces DynamicStructure instances. Acquires the registry's exclusive lock.
  ///
  /// @param definition Field layout of the structure or union.
  /// @param typeId     DataType NodeId the descriptor is keyed by.
  /// @param encodingId Default binary encoding NodeId, used to index the type for resolution.
  /// @param typeName   Human-readable type name retained on the descriptor.
  /// @param nsLookup   Maps a namespace index to its URI; called once per field at registration
  ///                   time to qualify field DataType NodeIds. Empty by default.
  /// @return A successful result, or an @ref ErrorDetail if a field dependency is not yet
  ///         registered. Never throws.
  VoidResult register_type(StructureDefinition definition, ExpandedNodeId typeId, ExpandedNodeId encodingId,
    String typeName, NamespaceUriLookup nsLookup = {});

  /// Registers an enum or option-set type.
  ///
  /// Acquires the registry's exclusive lock.
  ///
  /// @param definition  Enumerated values of the type.
  /// @param typeId      DataType NodeId the descriptor is keyed by.
  /// @param typeName    Human-readable type name retained on the descriptor.
  /// @param isOptionSet `true` for a UInteger-based option set, `false` for a plain enum. Retained
  ///                    on the descriptor (see `DynamicEnumTypeDescriptor::is_option_set`) and used
  ///                    to encode referencing fields as UInt32 (option set) or Int32 (enum).
  /// @return A successful result, or an @ref ErrorDetail on failure. Never throws.
  VoidResult register_type(
    EnumDefinition definition, ExpandedNodeId typeId, String typeName, bool isOptionSet = false);

  /// Looks up a registered structure or union descriptor by DataType NodeId.
  ///
  /// Acquires the registry's shared lock.
  ///
  /// @param typeId DataType NodeId to look up.
  /// @return The descriptor, shared with the registry, or null if no type is registered under
  ///         @p typeId. It stays valid for as long as it is held, also after the type is registered
  ///         again; an instance is `DynamicStructure{descriptor}`.
  [[nodiscard]] shared_ptr<const DynamicStructureTypeDescriptor> find_structure(
    const ExpandedNodeId& typeId) const;

  /// Looks up a registered enum or option-set descriptor by DataType NodeId.
  ///
  /// Acquires the registry's shared lock.
  ///
  /// @param typeId DataType NodeId to look up.
  /// @return The descriptor, shared with the registry, or null if no type is registered under
  ///         @p typeId. It stays valid for as long as it is held, also after the type is registered
  ///         again.
  [[nodiscard]] shared_ptr<const DynamicEnumTypeDescriptor> find_enum(const ExpandedNodeId& typeId) const;

  /// Callback that registers one type with an external factory keyed by encoding NodeId.
  ///
  /// Invoked once per structure/union type by @ref register_all_with with the type's encoding
  /// NodeId and a factory that constructs a fresh empty instance of that type.
  using TypeRegistrar = std::function<void(const NodeId&, std::function<unique_ptr<Structure>()>)>;

  /// Registers all structure and union types with an external factory via @p registrar.
  ///
  /// Invokes @p registrar once per registered structure/union type. Acquires the shared lock.
  ///
  /// @param registrar Receives each type's encoding NodeId and instance factory.
  /// @throws UaException with BadInvalidArgument if the registry contains any non-NS0 type
  ///         (an encoding ID carrying a namespace URI); use the @p nsLookup overload instead.
  /// @see make_resolver
  void register_all_with(TypeRegistrar registrar) const;

  /// Registers all structure and union types with an external factory, mapping encoding NodeId
  /// namespace URIs to local namespace indices.
  ///
  /// Invokes @p registrar once per registered structure/union type. Acquires the shared lock.
  ///
  /// @param registrar Receives each type's encoding NodeId and instance factory.
  /// @param nsLookup  Maps each encoding NodeId's namespace URI to a local namespace index.
  /// @see make_resolver
  void register_all_with(TypeRegistrar registrar, NamespaceIndexLookup nsLookup) const;

  /// Creates a @ref StructureResolver that resolves encoding NodeIds against this registry.
  ///
  /// The returned resolver is a self-contained snapshot - it does not reference the registry
  /// after construction, so rebuild it whenever the registry changes.
  ///
  /// @return A resolver over the registry's current contents.
  /// @throws UaException with BadInvalidArgument if the registry contains any non-NS0 type
  ///         (an encoding ID carrying a namespace URI); use the @p nsLookup overload instead.
  /// @see register_all_with
  StructureResolver make_resolver() const;

  /// Creates a @ref StructureResolver that translates encoding NodeIds from local namespace
  /// indices to namespace URIs before looking them up in the registry.
  ///
  /// Builds a NodeId-keyed cache at construction time (O(n)) for O(1) lookups on the decode hot
  /// path. The returned resolver is a self-contained snapshot - it does not reference the
  /// registry after construction, so rebuild it whenever the registry or namespace table changes.
  ///
  /// @param nsLookup Maps a namespace URI to a local namespace index for the snapshot's lookups.
  /// @return A resolver over the registry's current contents.
  /// @see register_all_with
  StructureResolver make_resolver(NamespaceIndexLookup nsLookup) const;

private:
  mutable std::shared_mutex mMutex;
  std::unordered_map<ExpandedNodeId, shared_ptr<DynamicStructureTypeDescriptor>> mStructureDescriptors;
  std::unordered_map<NodeId, shared_ptr<const DynamicStructureTypeDescriptor>> mEncodingIndex;
  std::unordered_map<ExpandedNodeId, shared_ptr<DynamicEnumTypeDescriptor>> mEnumDescriptors;
  /// Throw UaException if any registered structure has a non-empty namespace URI in its encoding ID.
  void throw_if_has_non_ns0(const char* methodName) const;

  /// Create a factory lambda for the given descriptor.
  static std::function<unique_ptr<Structure>()> make_factory(
    shared_ptr<const DynamicStructureTypeDescriptor> descriptor);
};

}  // namespace ua

#endif  // !UA_DYNAMIC_TYPE_REGISTRY_H
