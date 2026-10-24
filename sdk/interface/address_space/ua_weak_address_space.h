// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A non-owning handle to an address space.
/// @ingroup address_space

#ifndef UA_WEAK_ADDRESS_SPACE_H
#define UA_WEAK_ADDRESS_SPACE_H

#include "ua_error_detail.h"
#include "ua_includes.h"
#include "ua_status_code.h"
#include "ua_to_result.h"

#include <string>
#include <string_view>

namespace ua
{

class AddressSpace;
class AddressSpaceImpl;

namespace detail
{
struct NamespaceRegistrationRoute;
class NodeAccessorRoute;
}  // namespace detail

/// A non-owning weak handle to an @ref AddressSpace.
///
/// Holds a weak reference to the shared graph; `lock()` yields an owning
/// @ref AddressSpace if the graph is still alive. Use this to break ownership
/// cycles and to safely reference an address space from async work.
/// @ingroup address_space
class WeakAddressSpace
{
public:
  /// Constructs an empty handle that locks to `nullopt`.
  WeakAddressSpace() = default;

  /// Constructs a weak handle referencing @p addressSpace.
  ///
  /// @param addressSpace Address space to observe; not kept alive by this handle.
  explicit WeakAddressSpace(const AddressSpace& addressSpace);

  /// Attempts to obtain an owning handle to the referenced address space.
  ///
  /// @return The @ref AddressSpace if it is still alive, otherwise `nullopt`.
  optional<AddressSpace> lock() const;

private:
  // The address space builds the handle its accessors hold; the accessor's route reads it.
  friend class AddressSpaceImpl;
  friend class detail::NodeAccessorRoute;

  WeakAddressSpace(weak_ptr<AddressSpaceImpl> impl, shared_ptr<const detail::NamespaceRegistrationRoute> route);

  weak_ptr<AddressSpaceImpl> mImpl;
  shared_ptr<const detail::NamespaceRegistrationRoute> mRegistrationRoute;
};

namespace detail
{

/// What an operation answers when the weak owner it requires, its address space, no longer locks:
/// `Bad_Shutdown` (`AddressSpaceGone`), with @p source as the detail's source. Built where the lock fails,
/// so an operation whose owner stays alive builds none. A detail that cannot be built answers the
/// allocation failure instead, as @ref exception_to_status_code converts it (`Bad_OutOfMemory`). Generated
/// type code answers it where its weak address space no longer locks.
///
/// @param source The ErrorDetail's source.
/// @return `Bad_Shutdown` with the `AddressSpaceGone` ErrorDetail.
inline StatusCode address_space_gone(std::string_view source) noexcept
{
  try
  {
    return StatusCode{Status::BadShutdown,
      ErrorDetail::build("AddressSpaceGone", "The address space no longer exists", std::string{source})};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

}  // namespace detail

}  // namespace ua

#endif  // UA_WEAK_ADDRESS_SPACE_H
