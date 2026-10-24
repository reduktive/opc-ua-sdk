// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_type_registry.h"

#include "ua_built_in_type_id.h"
#include "ua_datatype_id.h"
#include "ua_node_id.h"
#include "ua_variant.h"

#include <cstdint>
#include <unordered_set>
#include <utility>

namespace ua::client::detail
{

StructureFactory::InstallResult StructureFactory::install(StructureType entry)
{
  const ua::NodeId encodingId = entry.encodingId;
  auto existing = mByEncoding.find(encodingId);
  if (existing != mByEncoding.end())
  {
    // Precedence-resolve: a new entry replaces an existing one only when strictly higher precedence
    // (smaller rank). An equal-precedence collision keeps the FIRST  -  "first user registration wins"
    // (CL-BASE-008 / section 9.6.18.2), and a lower-precedence source never clobbers a resolved type.
    if (precedence_rank(entry.source) >= precedence_rank(existing->second.source))
    {
      return InstallResult::ShadowedByHigher;
    }
    // The replacement may re-home the DataType to encoding mapping; erase the stale one first.
    mEncodingByDataType.erase(existing->second.dataTypeId);
  }
  mEncodingByDataType[entry.dataTypeId] = encodingId;
  mByEncoding[encodingId] = std::move(entry);
  return InstallResult::Installed;
}

StructureFactory::InstallResult StructureFactory::register_structure_type(
  ua::NodeId encodingId, ua::NodeId dataTypeId, std::shared_ptr<const ua::Structure> decoder)
{
  return install(StructureType{
    std::move(dataTypeId), std::move(encodingId), std::move(decoder), TypeSource::UserRegistered});
}

const StructureType* StructureFactory::find_by_encoding(const ua::NodeId& encodingId) const noexcept
{
  auto found = mByEncoding.find(encodingId);
  if (found == mByEncoding.end())
  {
    return nullptr;
  }
  return &found->second;
}

std::optional<ua::NodeId> StructureFactory::encoding_for_datatype(const ua::NodeId& dataTypeId) const noexcept
{
  auto found = mEncodingByDataType.find(dataTypeId);
  if (found == mEncodingByDataType.end())
  {
    return std::nullopt;
  }
  return found->second;
}

std::optional<TypeSource> StructureFactory::source_of(const ua::NodeId& encodingId) const noexcept
{
  auto found = mByEncoding.find(encodingId);
  if (found == mByEncoding.end())
  {
    return std::nullopt;
  }
  return found->second.source;
}

void StructureFactory::add_subtype_edge(ua::NodeId childDataType, ua::NodeId supertypeDataType)
{
  mSupertypeByDataType[std::move(childDataType)] = std::move(supertypeDataType);
}

std::optional<ua::NodeId> StructureFactory::immediate_supertype(const ua::NodeId& dataType) const noexcept
{
  auto found = mSupertypeByDataType.find(dataType);
  if (found == mSupertypeByDataType.end())
  {
    return std::nullopt;
  }
  return found->second;
}

void StructureFactory::merge_from(const StructureFactory& other)
{
  for (const auto& [encodingId, entry] : other.mByEncoding)
  {
    install(entry);
  }
  // Fold the discovered DataType hierarchy too  -  the immediate supertype of a DataType is unique, so a
  // collision records the same edge (later writer wins, harmlessly).
  for (const auto& [childDataType, supertypeDataType] : other.mSupertypeByDataType)
  {
    mSupertypeByDataType[childDataType] = supertypeDataType;
  }
}

std::shared_ptr<const TypeRegistry> TypeRegistry::create(StructureFactory factory, std::uint64_t generation)
{
  // Private ctor: use a wrapping shared_ptr rather than make_shared (which cannot reach the private ctor).
  return std::shared_ptr<const TypeRegistry>(new TypeRegistry(std::move(factory), generation));
}

TypeRegistry::TypeRegistry(StructureFactory factory, std::uint64_t generation)
  : mFactory(std::move(factory)), mGeneration(generation)
{}

std::optional<bool> TypeRegistry::is_subtype_of(
  const ua::NodeId& descendant, const ua::NodeId& ancestor) const noexcept
{
  if (descendant == ancestor)
  {
    return true;
  }
  const ua::NodeId baseDataType{ua::DataTypeId::BaseDataType};
  ua::NodeId current = descendant;
  std::unordered_set<ua::NodeId> visited;
  while (true)
  {
    if (current == baseDataType)
    {
      // Reached the universal hierarchy root without meeting the ancestor: a fully-known chain that
      // excludes it (e.g. a sibling type). Definitively NOT a subtype.
      return false;
    }
    if (!visited.insert(current).second)
    {
      // A cycle in the recorded edges  -  a malformed / hostile graph. Undecidable rather than loop forever.
      return std::nullopt;
    }
    const std::optional<ua::NodeId> parent = mFactory.immediate_supertype(current);
    if (!parent)
    {
      // An undiscovered edge: the relation is undecidable from THIS snapshot. The caller drives an async
      // supertype resolution and re-checks the next generation.
      return std::nullopt;
    }
    if (*parent == ancestor)
    {
      return true;
    }
    current = *parent;
  }
}

namespace
{
// The integer built-in encodings an Enumeration value can arrive as (OPC enums wire as Int32; the other
// integer widths are included defensively). Used to fail-open when the declared type could be an enum.
bool is_integer_built_in(ua::BuiltInTypeId id) noexcept
{
  switch (id)
  {
  case ua::BuiltInTypeId::SByte:
  case ua::BuiltInTypeId::Byte:
  case ua::BuiltInTypeId::Int16:
  case ua::BuiltInTypeId::UInt16:
  case ua::BuiltInTypeId::Int32:
  case ua::BuiltInTypeId::UInt32:
  case ua::BuiltInTypeId::Int64:
  case ua::BuiltInTypeId::UInt64:
    return true;
  default:
    return false;
  }
}
}  // namespace

std::optional<ua::NodeId> value_concrete_datatype(const ua::Variant& value)
{
  // Only a built-in SCALAR has a wire-derivable type; an empty value, an array, or a structured
  // (ExtensionObject) value is not classifiable here. is_scalar() excludes empty + array in one guard.
  if (!value.is_scalar())
  {
    return std::nullopt;
  }
  const ua::BuiltInTypeId builtIn = value.get_built_in_type();  // safe: a scalar is non-empty
  if (builtIn == ua::BuiltInTypeId::ExtensionObject)
  {
    return std::nullopt;  // structure DataType resolution is a follow-up
  }
  // The OPC built-in type ids (1..25) equal their NS0 DataType NodeIds (Int32 == i=6, String == i=12, ...).
  return ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(builtIn)};
}

SubtypeCheck check_value_subtype(
  const ua::Variant& value, const ua::NodeId& declaredDataType, const TypeRegistry& registry)
{
  // The wire carries only the built-in ENCODING type, not the value's true DataType  -  for encoded/refined
  // types the encoding aliases (an Enumeration wires as Int32; a Duration as Double; a LocaleId as String).
  // So the wire built-in type is a reliable REJECT signal only in a genuinely disjoint, non-aliased branch;
  // everywhere else we must fail-open (section 5.8.3: never reject a value we cannot prove wrong). A value
  // whose concrete DataType is not wire-derivable (empty / array / structured) is Undecidable.
  const std::optional<ua::NodeId> maybeWireType = value_concrete_datatype(value);
  if (!maybeWireType)
  {
    return SubtypeCheck::Undecidable;
  }
  const ua::BuiltInTypeId builtIn = value.get_built_in_type();
  const ua::NodeId wireType = *maybeWireType;

  // 1. The wire built-in type IS (a subtype of) the declared type -> a genuine value of the declared family.
  const std::optional<bool> wireIsSubtypeOfDeclared = registry.is_subtype_of(wireType, declaredDataType);
  if (wireIsSubtypeOfDeclared == std::optional<bool>{true})
  {
    return SubtypeCheck::Accept;  // e.g. Int32 <: Number, or wireType == declared (reflexive)
  }
  // 2. The declared type is a REFINEMENT that encodes AS the wire built-in (Duration <: Double, LocaleId <:
  //    String, UtcTime <: DateTime, IntegerId <: UInt32, ...). The encoding cannot distinguish it ->
  //    fail-open.
  //    (`!= false` covers both a decided refinement AND a still-undiscovered relation.)
  if (registry.is_subtype_of(declaredDataType, wireType) != std::optional<bool>{false})
  {
    return SubtypeCheck::Undecidable;
  }
  // 3. Enumerations wire as an integer but their DataType is under Enumeration (i=29), a branch DISJOINT from
  //    the integer types  -  so an integer wire value could be a valid enum of the declared type. Fail-open
  //    unless the declared type is DECIDABLY not an Enumeration subtype.
  if (is_integer_built_in(builtIn) &&
      registry.is_subtype_of(declaredDataType,
        ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(ua::DataTypeId::Enumeration)}) !=
        std::optional<bool>{false})
  {
    return SubtypeCheck::Undecidable;
  }
  // 4. The wire built-in is DECIDABLY not a subtype of declared, declared is not a refinement of it, and it
  // is
  //    not an integer-encoded enum -> a genuine, disjoint type mismatch (e.g. a String for a Number). Reject.
  if (wireIsSubtypeOfDeclared == std::optional<bool>{false})
  {
    return SubtypeCheck::Reject;
  }
  // 5. wireIsSubtypeOfDeclared is nullopt (the relation is not yet discovered) -> fail-open; the caller
  // drives
  //    async discovery and re-checks the next generation.
  return SubtypeCheck::Undecidable;
}

}  // namespace ua::client::detail
