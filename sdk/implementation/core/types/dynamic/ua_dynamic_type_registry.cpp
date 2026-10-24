// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_type_registry.h"
#include "ua_data_value.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_union.h"
#include "ua_structure_type.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "fmt/format.h"

namespace ua
{

VoidResult DynamicTypeRegistry::register_type(StructureDefinition definition, ExpandedNodeId typeId,
  ExpandedNodeId encodingId, String typeName, NamespaceUriLookup nsLookup)
{
  auto descriptor = std::make_shared<DynamicStructureTypeDescriptor>(
    std::move(typeName), typeId, encodingId, std::move(definition), std::move(nsLookup));

  const WriteLock lk(mMutex);

  // Eagerly resolve all field dependencies from already-registered types
  for (size_t i = 0; i < descriptor->field_count(); ++i)
  {
    if (descriptor->field_built_in_type(i) != BuiltInTypeId::ExtensionObject)
    {
      continue;
    }

    const auto& fieldTypeExpanded = descriptor->field_data_type_expanded(i);

    // Check for nested structure
    auto structIt = mStructureDescriptors.find(fieldTypeExpanded);
    if (structIt != mStructureDescriptors.end())
    {
      descriptor->resolve_nested(i, structIt->second);
      continue;
    }

    // Check for enum/option set - set built-in type to Int32/UInt32
    auto enumIt = mEnumDescriptors.find(fieldTypeExpanded);
    if (enumIt != mEnumDescriptors.end())
    {
      descriptor->set_field_built_in_type(
        i, enumIt->second->is_option_set() ? BuiltInTypeId::UInt32 : BuiltInTypeId::Int32);
      continue;
    }

    // Field references an unknown type - this indicates a bug in the caller's
    // registration order (the loader guarantees topological order).
    // Skip NS0 abstract Structure (i=22) which means "any structure".
    const bool isAbstractStructure =
      (fieldTypeExpanded.namespace_uri().empty() && fieldTypeExpanded.node_id().namespace_index() == 0 &&
        fieldTypeExpanded.node_id().is_numeric() &&
        fieldTypeExpanded.node_id().identifier().get_numeric() == 22);
    if (!isAbstractStructure)
    {
      return VoidResult{StatusCode{Status::BadDataTypeIdUnknown},
        ErrorDetail::build("UnresolvedFieldDependency",
          "structure field references an unregistered data type",
          "DynamicTypeRegistry::register_type")
          .context(
            ua::ContextKeys::fieldName, std::string{static_cast<string_view>(descriptor->field(i).name())})
          .context(ua::ContextKeys::typeId, fieldTypeExpanded.as_definition())};
    }
  }

  // Store the descriptor
  mStructureDescriptors[typeId] = descriptor;
  mEncodingIndex[encodingId.node_id()] = descriptor;

  return VoidResult{};
}

VoidResult DynamicTypeRegistry::register_type(
  EnumDefinition definition, ExpandedNodeId typeId, String typeName, bool isOptionSet)
{
  auto descriptor = std::make_shared<DynamicEnumTypeDescriptor>(
    std::move(typeName), std::move(typeId), isOptionSet, std::move(definition));

  const WriteLock lk(mMutex);
  mEnumDescriptors[descriptor->type_id()] = std::move(descriptor);

  return VoidResult{};
}

std::function<unique_ptr<Structure>()> DynamicTypeRegistry::make_factory(
  shared_ptr<const DynamicStructureTypeDescriptor> descriptor)
{
  const bool isUnion = descriptor->structure_type() == StructureType::Union ||
                       descriptor->structure_type() == StructureType::UnionWithSubtypedValues;

  if (isUnion)
  {
    return [desc = std::move(descriptor)]()
    {
      return std::make_unique<DynamicUnion>(desc);
    };
  }
  else
  {
    return [desc = std::move(descriptor)]()
    {
      return std::make_unique<DynamicStructure>(desc);
    };
  }
}

void DynamicTypeRegistry::throw_if_has_non_ns0(const char* methodName) const
{
  for (const auto& [typeId, descriptor] : mStructureDescriptors)
  {
    if (!descriptor->encoding_id().namespace_uri().empty())
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("NamespaceLookupRequired",
          "registry contains non-NS0 types; use the overload that takes a "
          "NamespaceIndexLookup",
          methodName)
          .context(
            ua::ContextKeys::typeName, std::string{static_cast<string_view>(descriptor->type_name())}));
    }
  }
}

void DynamicTypeRegistry::register_all_with(TypeRegistrar registrar) const
{
  const ReadLock lk(mMutex);
  throw_if_has_non_ns0("register_all_with");
  for (const auto& [typeId, descriptor] : mStructureDescriptors)
  {
    auto encodingId = descriptor->encoding_id().node_id();
    registrar(encodingId, make_factory(descriptor));
  }
}

void DynamicTypeRegistry::register_all_with(TypeRegistrar registrar, NamespaceIndexLookup nsLookup) const
{
  const ReadLock lk(mMutex);
  for (const auto& [typeId, descriptor] : mStructureDescriptors)
  {
    const auto& encodingExpanded = descriptor->encoding_id();
    const auto& uri = encodingExpanded.namespace_uri();

    NodeId encodingId;
    if (uri.empty())
    {
      encodingId = encodingExpanded.node_id();
    }
    else
    {
      auto idx = nsLookup(static_cast<string_view>(uri));
      if (!idx.has_value())
      {
        continue;
      }
      encodingId = encodingExpanded.node_id();
      encodingId.namespace_index() = *idx;
    }

    registrar(encodingId, make_factory(descriptor));
  }
}

StructureResolver DynamicTypeRegistry::make_resolver() const
{
  const ReadLock lk(mMutex);
  throw_if_has_non_ns0("make_resolver");

  // Snapshot the encoding index - the resolver is decoupled from the registry after construction.
  auto cache = std::make_shared<std::unordered_map<NodeId, shared_ptr<const DynamicStructureTypeDescriptor>>>(
    mEncodingIndex);

  return [cache = std::move(cache)](const NodeId& encodingId) -> unique_ptr<Structure>
  {
    auto it = cache->find(encodingId);
    if (it == cache->end())
    {
      return nullptr;
    }
    return make_factory(it->second)();
  };
}

StructureResolver DynamicTypeRegistry::make_resolver(NamespaceIndexLookup nsLookup) const
{
  const ReadLock lk(mMutex);

  // Build a NodeId-keyed cache upfront: O(n) at construction, O(1) per lookup.
  auto cache =
    std::make_shared<std::unordered_map<NodeId, shared_ptr<const DynamicStructureTypeDescriptor>>>();
  for (const auto& [typeId, descriptor] : mStructureDescriptors)
  {
    const auto& encodingExpanded = descriptor->encoding_id();
    const auto& uri = encodingExpanded.namespace_uri();

    NodeId translatedId;
    if (uri.empty())
    {
      translatedId = encodingExpanded.node_id();
    }
    else
    {
      auto idx = nsLookup(static_cast<string_view>(uri));
      if (!idx.has_value())
      {
        continue;
      }
      translatedId = encodingExpanded.node_id();
      translatedId.namespace_index() = *idx;
    }

    (*cache)[translatedId] = descriptor;
  }

  return [cache = std::move(cache)](const NodeId& encodingId) -> unique_ptr<Structure>
  {
    auto it = cache->find(encodingId);
    if (it == cache->end())
    {
      return nullptr;
    }
    return make_factory(it->second)();
  };
}

shared_ptr<const DynamicStructureTypeDescriptor> DynamicTypeRegistry::find_structure(
  const ExpandedNodeId& typeId) const
{
  const ReadLock lk(mMutex);
  auto it = mStructureDescriptors.find(typeId);
  if (it == mStructureDescriptors.end())
  {
    return nullptr;
  }
  return it->second;
}

shared_ptr<const DynamicEnumTypeDescriptor> DynamicTypeRegistry::find_enum(const ExpandedNodeId& typeId) const
{
  const ReadLock lk(mMutex);
  auto it = mEnumDescriptors.find(typeId);
  if (it == mEnumDescriptors.end())
  {
    return nullptr;
  }
  return it->second;
}

}  // namespace ua
