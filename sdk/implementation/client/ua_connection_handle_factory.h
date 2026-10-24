// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_HANDLE_FACTORY_H
#define UA_CONNECTION_HANDLE_FACTORY_H

/// @file
/// @brief The wrap interface that builds the public tier-2 value handles (@ref ua::client::Connection /
///        @ref ua::client::ServiceSet / @ref ua::client::Subscriptions) from a
///        @ref ua::client::detail::ConnectionImpl.
///
/// The public handles have private constructors (a handle is never user-constructed - it is produced by the
/// client machinery). This detail-namespace factory is a friend of each handle, so the connect path (and
/// the unit suite) can wrap an already-built `ConnectionImpl` into the public handle without exposing a
/// public constructor. A `detail::` interface, not part of the public API.

#include "ua_connection.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_subscriptions.h"
#include "ua_typed_access.h"

#include <memory>
#include <utility>

namespace ua::client::detail
{

/// Friend factory that constructs the public handles from a `shared_ptr<ConnectionImpl>`.
struct ConnectionHandleFactory
{
  /// Wraps @p impl in a public @ref ua::client::Connection handle.
  [[nodiscard]] static ua::client::Connection make_connection(std::shared_ptr<ConnectionImpl> impl)
  {
    return ua::client::Connection{std::move(impl)};
  }

  /// Wraps @p impl in a public @ref ua::client::ServiceSet handle (the wire-op sub-accessor).
  [[nodiscard]] static ua::client::ServiceSet make_service_set(std::shared_ptr<ConnectionImpl> impl)
  {
    return ua::client::ServiceSet{std::move(impl)};
  }

  /// Wraps @p impl in a public @ref ua::client::Subscriptions handle (the subscription sub-accessor).
  [[nodiscard]] static ua::client::Subscriptions make_subscriptions(std::shared_ptr<ConnectionImpl> impl)
  {
    return ua::client::Subscriptions{std::move(impl)};
  }

  /// Wraps @p impl in a public @ref ua::client::TypedAccess handle (the typed-value sub-accessor).
  [[nodiscard]] static ua::client::TypedAccess make_typed_access(std::shared_ptr<ConnectionImpl> impl)
  {
    return ua::client::TypedAccess{std::move(impl)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_HANDLE_FACTORY_H
