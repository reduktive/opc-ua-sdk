// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-side TypeModelAccess adapter backed by a local AddressSpace.
/// @ingroup address_space

#ifndef UA_ADDRESS_SPACE_MODEL_ACCESS_H
#define UA_ADDRESS_SPACE_MODEL_ACCESS_H

#include "ua_type_model_access.h"
#include "ua_weak_address_space.h"

namespace ua
{
class AddressSpace;
}

namespace ua::dynamic_types
{

/// TypeModelAccess implementation that reads and browses a local AddressSpace.
///
/// Server-side adapter that satisfies the @ref TypeModelAccess Read/Browse
/// contract by querying the local address space's namespaces directly, bypassing the
/// service layer (no authentication, session, or diagnostics). Use
/// @ref SessionModelAccess for the client-side variant that issues service
/// calls over a session.
///
/// The adapter holds the @ref AddressSpace weakly, so neither it nor an outstanding
/// read or browse keeps the address space alive: one started after the address
/// space is gone answers Bad_Shutdown with ErrorDetail code AddressSpaceGone. As
/// with the base interface, this
/// type is not safe for concurrent use from multiple threads against the same
/// instance.
///
/// @ingroup address_space
/// @see TypeModelAccess
class AddressSpaceModelAccess : public TypeModelAccess
{
public:
  /// Constructs an adapter over @p addressSpace.
  ///
  /// @param addressSpace Address space queried by read_async / browse_async.
  ///                     Held weakly.
  explicit AddressSpaceModelAccess(ua::AddressSpace& addressSpace);

  /// Reads one or more attribute values from the local address space.
  ///
  /// Queries the namespaces that hold the Nodes directly and completes asynchronously. The
  /// result vector holds one @ref ua::DataValue per input @ref ua::ReadValueId,
  /// in the same order.
  ///
  /// @param nodesToRead Attributes to read, each a NodeId + AttributeId pair.
  /// @param complete    Receives the outcome: on success a Result holding the
  ///                    per-input @ref ua::DataValue vector; on failure a Result
  ///                    carrying an @ref ua::ErrorDetail. Never throws.
  void read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete) override;

  /// Browses references from one or more nodes in the local address space.
  ///
  /// Queries the namespaces that hold the Nodes directly and completes asynchronously. The
  /// result vector holds one @ref ua::BrowseResult per input
  /// @ref ua::BrowseDescription, in the same order.
  ///
  /// @param nodesToBrowse Nodes to browse, each describing a starting NodeId,
  ///                      direction, and reference-type filter.
  /// @param complete      Receives the outcome: on success a Result holding the
  ///                      per-input @ref ua::BrowseResult vector; on failure a
  ///                      Result carrying an @ref ua::ErrorDetail. Never throws.
  void browse_async(std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete) override;

private:
  ua::WeakAddressSpace mAddressSpace;
};

}  // namespace ua::dynamic_types

#endif  // !UA_ADDRESS_SPACE_MODEL_ACCESS_H
