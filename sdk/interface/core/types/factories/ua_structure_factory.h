// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Thread-safe registry mapping encoding NodeIds to Structure factories.
/// @ingroup core_types

#ifndef UA_STRUCTURE_FACTORY_H
#define UA_STRUCTURE_FACTORY_H

#include <functional>
#include <memory>
#include <unordered_map>
#include "ua_includes.h"
#include "ua_node_id.h"

namespace ua
{

class Structure;

/// Creates a @ref Structure instance from an encoding NodeId.
///
/// Decouples decoders from the concrete factory type, letting callers compose
/// resolvers from any source - a static factory, a dynamic registry, or a
/// combination. Invoked synchronously on the caller's thread; the resolver
/// performs no async work and must not block.
///
/// The argument is the encoding NodeId of the structured DataType to construct.
/// On success the returned @ref Structure is owned by the caller. Returns
/// nullptr if the encoding NodeId is not recognised.
///
/// @ingroup core_types
using StructureResolver = std::function<std::unique_ptr<Structure>(const class NodeId&)>;

/// A thread-safe registry that creates Structure instances from encoding NodeIds.
///
/// Decoders register a factory callable against each encoding @ref NodeId, then
/// create freshly decoded @ref Structure instances by that id. All methods are
/// safe to call concurrently from any thread; access is serialized internally by
/// a shared mutex (concurrent reads, exclusive writes). The type is neither
/// copyable nor movable.
/// @ingroup core_types
class StructureFactory
{
public:
  StructureFactory() = default;
  ~StructureFactory() = default;
  StructureFactory(const StructureFactory&) = delete;
  StructureFactory(StructureFactory&& other) noexcept = delete;
  StructureFactory& operator=(const StructureFactory& other) = delete;
  StructureFactory& operator=(StructureFactory&& other) noexcept = delete;

  /// Callable that constructs a fresh, owned @ref Structure instance.
  ///
  /// Invoked once per @ref create_instance call to produce a new instance.
  using CreateMethod = std::function<unique_ptr<Structure>()>;

  /// Registers a factory callable for an encoding NodeId.
  ///
  /// If @p encodingId is already registered the existing registration is kept and
  /// this call has no effect.
  ///
  /// @param encodingId Encoding NodeId the factory is keyed by.
  /// @param method     Callable invoked to construct an instance for @p encodingId.
  void register_type(const NodeId& encodingId, CreateMethod method) noexcept;

  /// Creates a new Structure instance for an encoding NodeId.
  ///
  /// @param encodingId Encoding NodeId to look up.
  /// @return A newly constructed instance, or @c nullptr if @p encodingId is not
  ///         registered.
  /// @throws Whatever the registered @ref CreateMethod throws.
  unique_ptr<Structure> create_instance(const NodeId& encodingId) const;

  /// Returns a StructureResolver that delegates to this factory's create_instance().
  ///
  /// The returned resolver holds a non-owning reference to this factory.
  ///
  /// @return A @ref StructureResolver bound to this factory.
  /// @warning The caller must ensure this StructureFactory outlives the returned
  ///          resolver.
  StructureResolver resolver() const;

private:
  mutable std::shared_mutex mMutex;
  std::unordered_map<NodeId, CreateMethod> mCreateMethods;
};

}  // namespace ua

#endif  //! UA_STRUCTURE_FACTORY_H
