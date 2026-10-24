// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Loads OPC UA custom DataTypes from a type model into a dynamic type registry.
/// @ingroup core_types

#ifndef UA_TYPE_LOADER_H
#define UA_TYPE_LOADER_H

#include "ua_includes.h"
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <functional>
#include <vector>

namespace ua
{
class DynamicTypeRegistry;
}

namespace ua::dynamic_types
{

class TypeModelAccess;

/// A single DataType that failed to register, with the cause explaining why.
///
/// Collected per type into LoaderRegistrationStats::failures while the rest of
/// the load proceeds; an individual failure does not abort the whole load.
/// @ingroup core_types
struct TypeRegistrationFailure
{
  ua::NodeId typeId;  ///< NodeId of the DataType that failed to register.
  ua::String typeName;  ///< Browse name of the DataType, if it was resolved before the failure.
  std::shared_ptr<const ua::ErrorDetail> detail;  ///< Cause chain for the failure; never null.
};

/// Outcome counters and per-type failures from a single load invocation.
///
/// A non-empty @ref failures list does not imply the surrounding operation
/// failed: types that could not be registered are recorded here while the
/// remainder of the load completes, so a successful @ref Result can still carry
/// failures.
/// @ingroup core_types
struct LoaderRegistrationStats
{
  size_t structureCount{0};  ///< Number of structure DataTypes successfully registered.
  size_t enumCount{0};  ///< Number of enumeration DataTypes successfully registered.
  size_t skippedAbstract{0};  ///< Number of abstract DataTypes skipped (never registered).
  size_t dependencyCount{0};  ///< Number of field-dependency DataTypes pulled in and registered.
  std::vector<TypeRegistrationFailure> failures;  ///< Per-type registration failures, in encounter order.

  /// Reports whether any type failed to register.
  ///
  /// @return `true` if at least one type failed to register, `false` otherwise.
  bool has_failures() const
  {
    return !failures.empty();
  }

  /// Returns the number of types that failed to register.
  ///
  /// @return The number of entries in @ref failures.
  size_t failure_count() const
  {
    return failures.size();
  }
};

/// Result alias carrying LoaderRegistrationStats or an @ref ua::ErrorDetail on a top-level failure.
///
/// The loader acts on every Read and Browse answer of the type model. An Uncertain answer, with or without
/// data, fails the load with `Bad_InternalError` and an ErrorDetail coded `ReadAnswerUncertain` or
/// `ReferencesAnswerUncertain` whose cause is the Uncertain code. A Bad answer fails it with its own code,
/// except a Bad Browse page below the first level of the DataType hierarchy, which ends the walk with the
/// types found so far.
using LoaderRegistrationStatsResult = ua::Result<LoaderRegistrationStats>;

/// Broad classification of a discovered DataType, as read from its DataTypeDefinition.
/// @ingroup core_types
enum class DiscoveredTypeKind
{
  Structure,  ///< Has a StructureDefinition (concrete or abstract structure/union).
  Enumeration,  ///< Has an EnumDefinition (plain enumeration or option set).
  Other,  ///< Neither - e.g. a subtype of a built-in scalar with no DataTypeDefinition.
};

/// A DataType surfaced by the loader's hierarchy walk, offered to a @ref TypeFilter.
///
/// The loader constructs one of these for every DataType it discovers and passes it to the
/// filter so the predicate can decide - by browse name, abstractness, supertype, or kind, not
/// just NodeId - whether the type should be registered. It is a non-owning view: the referenced
/// strings and NodeIds are owned by the loader and are valid only for the duration of the filter
/// call. Do not retain a `DiscoveredType` (or references obtained from it) beyond that call.
///
/// @note Selecting a type pulls in its field dependencies regardless of the filter's verdict on
///       those dependencies (see @ref TypeFilter).
/// @ingroup core_types
class DiscoveredType
{
public:
  /// @param nodeId Target node identifier.
  /// @param browseName The browse name.
  /// @param isAbstract The is abstract.
  /// @param superType The super type.
  /// @param kind The kind.
  /// Constructs a view over the given DataType attributes. The referenced objects must outlive
  /// the view. Callers other than the loader construct these only in tests.
  DiscoveredType(const ua::NodeId& nodeId, const ua::String& browseName, bool isAbstract,
    const ua::NodeId& superType, DiscoveredTypeKind kind) noexcept
    : mNodeId(&nodeId), mBrowseName(&browseName), mSuperType(&superType), mKind(kind), mIsAbstract(isAbstract)
  {}

  /// @return A reference to this object.
  /// DataType NodeId.
  const ua::NodeId& node_id() const noexcept
  {
    return *mNodeId;
  }

  /// @return A reference to this object.
  /// Browse name of the DataType (its unqualified name).
  const ua::String& browse_name() const noexcept
  {
    return *mBrowseName;
  }

  /// @return True when the requested condition is satisfied.
  /// Whether the DataType is abstract. Abstract types are never registered even if selected.
  bool is_abstract() const noexcept
  {
    return mIsAbstract;
  }

  /// @return A reference to this object.
  /// NodeId of the immediate supertype, or a null NodeId if none was resolved.
  const ua::NodeId& super_type() const noexcept
  {
    return *mSuperType;
  }

  /// @return The requested value.
  /// Structure / Enumeration / Other classification from the DataTypeDefinition.
  DiscoveredTypeKind kind() const noexcept
  {
    return mKind;
  }

private:
  const ua::NodeId* mNodeId;
  const ua::String* mBrowseName;
  const ua::NodeId* mSuperType;
  DiscoveredTypeKind mKind;
  bool mIsAbstract;
};

/// Predicate selecting which DataTypes are registered.
///
/// Returns true to register the given `DiscoveredType`. Field dependencies of a
/// selected type are always registered regardless of the predicate's verdict.
/// An empty (default-constructed) filter selects every DataType.
using TypeFilter = std::function<bool(const DiscoveredType& discoveredType)>;

// --- load_types: full hierarchy walk ---

/// Walks the full DataType hierarchy and registers the selected types.
///
/// Starting from BaseDataType (i=24), walks the DataType hierarchy reachable
/// through @p access, applies @p filter, resolves the field dependencies of
/// selected types, and registers them in @p registry. Abstract DataTypes are
/// skipped. The walk reads the model asynchronously and completes on an
/// unspecified worker thread - do not block the callback.
///
/// @param access   Type model the hierarchy is read from. Must outlive the operation.
/// @param registry Registry the resolved types are registered into. Must outlive the operation.
/// @param filter   Selects which DataTypes to register; an empty filter selects all.
/// @param callback Receives the outcome: on a top-level failure the `Result` carries an
///                 `ErrorDetail`, otherwise it holds the `LoaderRegistrationStats`. Note
///                 that a successful Result may still report per-type failures in
///                 `LoaderRegistrationStats::failures`. This overload never throws.
/// @see try_load_types_sync, load_types_sync
/// @param strand   Strand the load runs and resumes on. A STRAND, not a bare executor: the loader's
///                 collaborator is @ref ua::dynamic_types::TypeModelAccess, which says nothing about where
///                 the data comes from, so there is nothing here to make one from and it must be supplied.
/// @param logger   Reports a throw from an initiation or a resumption.
void load_types_async(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, TypeFilter filter,
  std::function<void(LoaderRegistrationStatsResult)> callback);

/// Walks the full DataType hierarchy and registers the selected types, blocking until complete.
///
/// @param access   Type model the hierarchy is read from. Must outlive the operation.
/// @param registry Registry the resolved types are registered into. Must outlive the operation.
/// @param filter   Selects which DataTypes to register; an empty filter selects all.
/// @return The load statistics, or an `ErrorDetail` on a top-level failure. Never throws.
/// @note Intended for external consumers only - internal SDK code uses load_types_async.
/// @see load_types_async, load_types_sync
LoaderRegistrationStatsResult try_load_types_sync(
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, TypeFilter filter = {}) noexcept;

/// Walks the full DataType hierarchy and registers the selected types, blocking until complete.
///
/// A Good subcode on the answer is not returned; try_load_types_sync() returns it.
///
/// @param access   Type model the hierarchy is read from. Must outlive the operation.
/// @param registry Registry the resolved types are registered into. Must outlive the operation.
/// @param filter   Selects which DataTypes to register; an empty filter selects all.
/// @return The load statistics.
/// @throws UaException if the load fails at the top level, or when the answer is not Good (an Uncertain one
/// included).
/// @note Intended for external consumers only - internal SDK code uses load_types_async.
/// @see load_types_async, try_load_types_sync
LoaderRegistrationStats load_types_sync(
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, TypeFilter filter = {});

// --- load_type: single type with dependency chase ---

/// Registers a single DataType and chases its field dependencies.
///
/// Resolves @p dataTypeId through @p access, registers it in @p registry, and
/// recursively registers the DataTypes it depends on through its fields. The
/// model is read asynchronously and the callback completes on an unspecified
/// worker thread - do not block it.
///
/// @param access     Type model the DataType is read from. Must outlive the operation.
/// @param registry   Registry the type and its dependencies are registered into. Must outlive the operation.
/// @param dataTypeId NodeId of the DataType to register.
/// @param callback   Receives the outcome: on a top-level failure the `Result` carries an
///                   `ErrorDetail`, otherwise it holds the `LoaderRegistrationStats` (which
///                   may still report per-type failures). This overload never throws.
/// @see try_load_type_sync, load_type_sync
/// @param strand   Strand the load runs and resumes on. A STRAND, not a bare executor: the loader's
///                 collaborator is @ref ua::dynamic_types::TypeModelAccess, which says nothing about where
///                 the data comes from, so there is nothing here to make one from and it must be supplied.
/// @param logger   Reports a throw from an initiation or a resumption.
void load_type_async(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, const ua::NodeId& dataTypeId,
  std::function<void(LoaderRegistrationStatsResult)> callback);

/// Registers a single DataType and chases its field dependencies, blocking until complete.
///
/// @param access     Type model the DataType is read from. Must outlive the operation.
/// @param registry   Registry the type and its dependencies are registered into. Must outlive the operation.
/// @param dataTypeId NodeId of the DataType to register.
/// @return The load statistics, or an `ErrorDetail` on a top-level failure. Never throws.
/// @note Intended for external consumers only - internal SDK code uses load_type_async.
/// @see load_type_async, load_type_sync
LoaderRegistrationStatsResult try_load_type_sync(
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, const ua::NodeId& dataTypeId) noexcept;

/// Registers a single DataType and chases its field dependencies, blocking until complete.
///
/// A Good subcode on the answer is not returned; try_load_type_sync() returns it.
///
/// @param access     Type model the DataType is read from. Must outlive the operation.
/// @param registry   Registry the type and its dependencies are registered into. Must outlive the operation.
/// @param dataTypeId NodeId of the DataType to register.
/// @return The load statistics.
/// @throws UaException if the load fails at the top level, or when the answer is not Good (an Uncertain one
/// included).
/// @note Intended for external consumers only - internal SDK code uses load_type_async.
/// @see load_type_async, try_load_type_sync
LoaderRegistrationStats load_type_sync(
  TypeModelAccess& access, ua::DynamicTypeRegistry& registry, const ua::NodeId& dataTypeId);

}  // namespace ua::dynamic_types

#endif  // !UA_TYPE_LOADER_H
