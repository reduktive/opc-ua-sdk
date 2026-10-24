// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief One-call discovery + registration of an address space's custom DataTypes into a
///        decode factory.
/// @ingroup address_space

#ifndef UA_REGISTER_ADDRESS_SPACE_TYPES_H
#define UA_REGISTER_ADDRESS_SPACE_TYPES_H

#include "ua_type_loader.h"

#include <functional>

namespace ua
{
class AddressSpace;
class StructureFactory;
}  // namespace ua

namespace ua::dynamic_types
{

/// Discovers the custom DataTypes in @p addressSpace and registers them into @p factory.
///
/// Composes the three otherwise-manual steps into one operation: builds an
/// @ref ua::dynamic_types::AddressSpaceModelAccess over @p addressSpace, runs the loader
/// (@ref ua::dynamic_types::load_types_async)
/// into a throwaway @ref ua::DynamicTypeRegistry, and bridges the discovered structure/union types
/// into @p factory keyed by their Default Binary encoding NodeId. After the call, an inbound
/// wire ExtensionObject of a registered type decodes as a typed @ref ua::DynamicStructure instead of
/// a preserved-verbatim @c UnknownStructure.
///
/// Only structure and union types reach @p factory; enums carry no encoding and are not
/// factory-registered. Types are registered first-writer-wins, so the generated NS0 types the
/// factory already holds are never overwritten. A type whose namespace URI is not present in the
/// address space's namespace table is skipped, so the call must run **after** the owning
/// namespace has been allocated (for example after the NodeSet that defines it has been imported).
///
/// @param addressSpace Address space whose custom DataTypes are discovered. A cheap value handle;
///                     a copy is retained for the duration of the operation.
/// @param factory      Decode factory the discovered types are registered into. Held by
///                     reference; must outlive the operation and every outstanding callback.
/// @param filter       Selects which discovered DataTypes to register; an empty filter selects
///                     all. Field dependencies of a selected type are always registered.
/// @param completion   Receives the outcome: on a top-level load failure the `Result` carries an
///                     @ref ua::ErrorDetail, otherwise it holds the
///                     @ref ua::dynamic_types::LoaderRegistrationStats
///                     (which may still report per-type failures). Runs on an unspecified worker
///                     thread. This overload never throws.
/// @see try_register_address_space_types_sync, register_address_space_types_sync
void register_address_space_types_async(ua::AddressSpace addressSpace, ua::StructureFactory& factory,
  TypeFilter filter, std::function<void(LoaderRegistrationStatsResult)> completion);

/// Discovers and registers the address space's custom DataTypes, blocking until complete.
///
/// @param addressSpace Address space whose custom DataTypes are discovered.
/// @param factory      Decode factory the discovered types are registered into. Must outlive the call.
/// @param filter       Selects which discovered DataTypes to register; an empty filter selects all.
/// @return The registration statistics, or an @ref ua::ErrorDetail on a top-level failure. Never throws.
/// @note Must be called from a thread that is not the address space's own executor thread.
/// @see register_address_space_types_async, register_address_space_types_sync
LoaderRegistrationStatsResult try_register_address_space_types_sync(
  ua::AddressSpace addressSpace, ua::StructureFactory& factory, TypeFilter filter = {}) noexcept;

/// Discovers and registers the address space's custom DataTypes, blocking until complete.
///
/// @param addressSpace Address space whose custom DataTypes are discovered.
/// @param factory      Decode factory the discovered types are registered into. Must outlive the call.
/// @param filter       Selects which discovered DataTypes to register; an empty filter selects all.
/// A Good subcode on the answer is not returned; try_register_address_space_types_sync() returns it.
/// @return The registration statistics.
/// @throws UaException if the load fails at the top level.
/// @note Must be called from a thread that is not the address space's own executor thread.
/// @see register_address_space_types_async, try_register_address_space_types_sync
LoaderRegistrationStats register_address_space_types_sync(
  ua::AddressSpace addressSpace, ua::StructureFactory& factory, TypeFilter filter = {});

}  // namespace ua::dynamic_types

#endif  // !UA_REGISTER_ADDRESS_SPACE_TYPES_H
