// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_REGISTRY_H
#define UA_TYPE_REGISTRY_H

/// @file
/// @brief The precedence-ranked client-side structure registry (@ref
///        ua::client::detail::StructureFactory, client design section 8.6 / section 9.8.3) and the immutable
///        snapshot the codec consults (@ref ua::client::detail::TypeRegistry).
///
/// This is the section 9.8.3 "define StructureFactory as a real type" deliverable: a registry mapping a
/// structure's `DataTypeEncoding` NodeId to its decode/encode prototype, carrying a **precedence rank**
/// (user-registered beats the application overlay beats server-discovered beats built-in) and a
/// **consultation point** (`find_by_encoding`, called by the codec and by the resolver when it rebuilds
/// each immutable @ref TypeRegistry generation).
///
/// It is NOT the core `ua::StructureFactory` (`ua_structure_factory.h`), which is an
/// encoding-NodeId  to  construct-instance registry with no precedence. The client type adds the
/// four-source provenance + precedence the section 8.6.4 ladder needs.
/// @ingroup client

#include "ua_node_id.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>

namespace ua
{
class Structure;
class Variant;
}  // namespace ua

namespace ua::client::detail
{

/// Provenance of a registered structure type. The enumerator ORDER is the precedence rank
/// (lower ordinal = higher precedence): a `UserRegistered` entry wins over the application overlay,
/// which wins over a server `DataTypeDefinition`, which wins over the deprecated dictionary, which wins
/// over a built-in standard type (section 8.6.4 ladder, reconciled with section 9.8.3 / the Slice-7 task:
/// "user beats dictionary beats built-in"; the overlay ranks between user-registered and server-discovered).
enum class TypeSource
{
  UserRegistered = 0,  ///< per-Connection `register_structure_type`  -  highest precedence
  ClientOverlay = 1,  ///< application-supplied Client-wide `StructureFactory` overlay
  ServerDataTypeDefinition = 2,  ///< discovered via the `DataTypeDefinition` attribute (primary)
  ServerDataTypeDictionary = 3,  ///< discovered via the deprecated `DataTypeDictionary` (fallback)
  BuiltIn = 4,  ///< the SDK's compiled-in standard-types registry  -  base, lowest
};

/// @return The numeric precedence rank of @p source (lower = higher precedence).
[[nodiscard]] inline int precedence_rank(TypeSource source) noexcept
{
  return static_cast<int>(source);
}

/// One registered structure type: its DataType, its DefaultBinary encoding NodeId (the registry key),
/// its decode/encode prototype, and its provenance.
///
/// @note This slice populates @ref decoder for user registrations; server-discovered entries carry a
///       correct DataType/encoding/provenance with a null @ref decoder (building a dynamic `Structure`
///       from wire `DataTypeDefinition` / dictionary data is a later slice  -  the resolution WIRING and
///       precedence are complete here).
struct StructureType
{
  ua::NodeId dataTypeId;  ///< the structure DataType NodeId
  ua::NodeId encodingId;  ///< the DefaultBinary encoding NodeId  -  the `find_by_encoding` key
  std::shared_ptr<const ua::Structure> decoder;  ///< decode/encode prototype (may be null; see note)
  TypeSource source = TypeSource::BuiltIn;  ///< provenance + precedence rank
};

/// The precedence-ranked structure registry (client design section 8.6 / section 9.8.3).
///
/// Value type (copyable): the @ref TypeResolver keeps one working instance and freezes a copy into each
/// immutable @ref TypeRegistry generation; the application supplies one as a Client-wide overlay. Keyed
/// on the DefaultBinary encoding NodeId. Insertion is precedence-resolved: a new entry replaces an
/// existing one for the same encoding only when it has strictly-higher precedence; an equal-precedence
/// collision keeps the FIRST (so "first user registration wins", CL-BASE-008 / section 9.6.18.2).
class StructureFactory
{
public:
  /// Installs @p entry, resolving precedence against any existing entry for the same encoding NodeId.
  /// @return `Installed` when it took effect; `ShadowedByHigher` when an existing higher-or-equal
  ///         precedence entry blocked it (equal-precedence keeps the first).
  enum class InstallResult
  {
    Installed,
    ShadowedByHigher,
  };
  InstallResult install(StructureType entry);

  /// User-facing registration (source `UserRegistered`, highest precedence). Convenience over @ref
  /// install; this is the `register_structure_type` surface named by the Slice-7 task.
  /// @return As @ref install (`ShadowedByHigher` on a user-vs-user collision  -  first wins).
  InstallResult register_structure_type(
    ua::NodeId encodingId, ua::NodeId dataTypeId, std::shared_ptr<const ua::Structure> decoder);

  /// The synchronous consultation point: the entry for @p encodingId, or nullptr on a miss.
  [[nodiscard]] const StructureType* find_by_encoding(const ua::NodeId& encodingId) const noexcept;

  /// The outbound path (CL-METH-007): the DefaultBinary encoding NodeId for @p dataTypeId, or nullopt.
  [[nodiscard]] std::optional<ua::NodeId> encoding_for_datatype(const ua::NodeId& dataTypeId) const noexcept;

  /// The provenance of the entry for @p encodingId, or nullopt on a miss.
  [[nodiscard]] std::optional<TypeSource> source_of(const ua::NodeId& encodingId) const noexcept;

  /// Records a discovered `HasSubtype` edge in the DataType hierarchy (CL-ADDRSP-009): @p childDataType's
  /// IMMEDIATE supertype is @p supertypeDataType. Idempotent (the immediate supertype of a DataType is unique
  /// per Part 3 section 5.8.3, so a repeat records the same edge). Populated by the async supertype-discovery
  /// walk; consulted by @ref TypeRegistry::is_subtype_of.
  void add_subtype_edge(ua::NodeId childDataType, ua::NodeId supertypeDataType);

  /// The recorded immediate supertype of @p dataType, or nullopt when no edge has been discovered for it
  /// (an UNKNOWN edge  -  distinct from `BaseDataType`, the hierarchy root, which legitimately has none).
  [[nodiscard]] std::optional<ua::NodeId> immediate_supertype(const ua::NodeId& dataType) const noexcept;

  /// Merges every entry of @p other into this factory, each resolved by @ref install precedence. Used by
  /// the resolver to fold the Client-wide overlay + built-in base into a rebuilt snapshot.
  void merge_from(const StructureFactory& other);

  /// Visits every held entry (unspecified order). Used by the resolver to fold the Client-wide overlay
  /// into a rebuilt snapshot re-stamped at `ClientOverlay` precedence.
  template<class Visitor>
  void for_each(Visitor&& visitor) const
  {
    for (const auto& [encodingId, entry] : mByEncoding)
    {
      visitor(entry);
    }
  }

  /// @return The number of distinct encoding NodeIds held.
  [[nodiscard]] std::size_t size() const noexcept
  {
    return mByEncoding.size();
  }

private:
  std::unordered_map<ua::NodeId, StructureType> mByEncoding;
  std::unordered_map<ua::NodeId, ua::NodeId> mEncodingByDataType;
  std::unordered_map<ua::NodeId, ua::NodeId> mSupertypeByDataType;  ///< child DataType -> immediate supertype
};

/// The immutable resolution snapshot the codec consumes lock-free (client design section 8.6.1).
///
/// Built by @ref TypeResolver as a frozen @ref StructureFactory plus a monotone generation counter and
/// published via an atomic `shared_ptr<const TypeRegistry>`; a consumer holds its shared_ptr for the
/// duration of one encode/decode so an atomic-store of a new generation mid-flight cannot tear it.
class TypeRegistry
{
public:
  /// @return A shared immutable snapshot over @p factory at @p generation.
  [[nodiscard]] static std::shared_ptr<const TypeRegistry> create(
    StructureFactory factory, std::uint64_t generation);

  /// Synchronous decode path: the entry for @p encodingId, or nullptr (caller emits a placeholder).
  [[nodiscard]] const StructureType* find_by_encoding(const ua::NodeId& encodingId) const noexcept
  {
    return mFactory.find_by_encoding(encodingId);
  }

  /// Outbound encode path (CL-METH-007): the DefaultBinary encoding NodeId for @p dataTypeId, or nullopt.
  [[nodiscard]] std::optional<ua::NodeId> encoding_for_datatype(const ua::NodeId& dataTypeId) const noexcept
  {
    return mFactory.encoding_for_datatype(dataTypeId);
  }

  /// Provenance of the entry for @p encodingId, or nullopt (CL-BASE-008 diagnostics).
  [[nodiscard]] std::optional<TypeSource> source_of(const ua::NodeId& encodingId) const noexcept
  {
    return mFactory.source_of(encodingId);
  }

  /// Pure subtype check over the discovered DataType hierarchy (CL-ADDRSP-009). Walks @p descendant's
  /// immediate-supertype chain upward (the edges recorded via @ref StructureFactory::add_subtype_edge):
  ///   - `true` if @p descendant == @p ancestor or the chain reaches @p ancestor;
  ///   - `false` if the chain reaches the hierarchy root (`BaseDataType`) without hitting @p ancestor (a
  ///     fully-known chain that excludes it  -  e.g. a sibling type);
  ///   - `nullopt` when the chain hits an UNDISCOVERED edge (the relation is undecidable from THIS snapshot;
  ///     the caller drives an async supertype resolution, then re-checks the new generation), or when the
  ///     recorded edges form a cycle (a malformed/hostile graph).
  /// Never performs I/O.
  [[nodiscard]] std::optional<bool> is_subtype_of(
    const ua::NodeId& descendant, const ua::NodeId& ancestor) const noexcept;

  /// @return This snapshot's monotone generation (bumped on every registry replacement).
  [[nodiscard]] std::uint64_t generation() const noexcept
  {
    return mGeneration;
  }

private:
  TypeRegistry(StructureFactory factory, std::uint64_t generation);

  StructureFactory mFactory;
  std::uint64_t mGeneration;
};

/// The outcome of validating a read value's concrete DataType against a Variable's declared DataType
/// (CL-ADDRSP-009): a concrete value shall always be a (subtype of the) declared DataType (Part 3
/// section 5.8.3).
enum class SubtypeCheck
{
  Accept,  ///< the value's concrete type IS the declared type or a proven subtype of it  -  deliver it
  Reject,  ///< the value's concrete type is proven NOT a subtype of the declared type  -  reject the read
  Undecidable,  ///< the relation is not yet decidable (an undiscovered edge) or the concrete type cannot be
                ///< determined here (empty / array / structure)  -  the caller drives async subtype discovery
                ///< and re-checks, and fail-opens (Accept) if it stays undecidable rather than reject a valid
                ///< value
};

/// The wire-derivable concrete DataType NodeId of a scalar built-in @p value: `NodeId{0, builtInTypeId}` (the
/// OPC built-in type ids equal their NS0 DataType ids). Returns nullopt for an empty value, an array, or an
/// ExtensionObject (structured) value. NOTE: the wire type is the ENCODING, not necessarily the true DataType
/// (an enum wires as Int32, a Duration as Double)  -  a positive answer is only reliable as a REJECT signal
/// when combined with an is_subtype_of decision (see @ref check_value_subtype / CL-ATTR-025).
[[nodiscard]] std::optional<ua::NodeId> value_concrete_datatype(const ua::Variant& value);

/// Validates that @p value's concrete DataType is a subtype of @p declaredDataType per @p registry's DataType
/// hierarchy (CL-ADDRSP-009). For a built-in scalar the concrete DataType is `NodeId{0, builtInTypeId}` (the
/// OPC built-in type ids equal their NS0 DataType ids); an empty value, an array, or an ExtensionObject
/// (structured) value is `Undecidable` here (element/structure DataType resolution is a follow-up). The
/// subtype relation delegates to @ref TypeRegistry::is_subtype_of (`nullopt` -> `Undecidable`).
[[nodiscard]] SubtypeCheck check_value_subtype(
  const ua::Variant& value, const ua::NodeId& declaredDataType, const TypeRegistry& registry);

}  // namespace ua::client::detail

#endif  // UA_TYPE_REGISTRY_H
