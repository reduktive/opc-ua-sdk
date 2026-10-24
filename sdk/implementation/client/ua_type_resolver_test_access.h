// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_RESOLVER_TEST_ACCESS_H
#define UA_TYPE_RESOLVER_TEST_ACCESS_H

/// @file
/// @brief Test-only access to @ref ua::client::detail::TypeResolver strand-private state, for the
///        TypeResolver unit suite (see the design specification).
///
/// A friend of @ref ua::client::detail::TypeResolver. Adds NO public members to the resolver for
/// testing: it reads the working factory, the in-flight map, the pending registrations, and the injected
/// strand directly.

#include "ua_node_id.h"
#include "ua_type_registry.h"
#include "ua_type_resolver.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <cstddef>
#include <memory>
#include <optional>

namespace ua::client::detail
{

/// Friend accessor for @ref TypeResolver unit tests.
struct TypeResolverTestAccess
{
  /// @return The number of distinct resolved encoding types in the working factory.
  static std::size_t working_size(const TypeResolver& resolver)
  {
    return resolver.mWorkingFactory.size();
  }

  /// @return The provenance of the working entry for @p encodingId, or nullopt on a miss.
  static std::optional<TypeSource> source_of(const TypeResolver& resolver, const ua::NodeId& encodingId)
  {
    return resolver.mWorkingFactory.source_of(encodingId);
  }

  /// @return The number of encodings currently mid-resolution (in flight).
  static std::size_t in_flight_count(const TypeResolver& resolver)
  {
    return resolver.mResolutionInFlight.size();
  }

  /// @return The number of coalesced waiters queued on @p encodingId (0 if not in flight).
  static std::size_t waiter_count(const TypeResolver& resolver, const ua::NodeId& encodingId)
  {
    auto found = resolver.mResolutionInFlight.find(encodingId);
    if (found == resolver.mResolutionInFlight.end())
    {
      return 0;
    }
    return found->second.size();
  }

  /// @return The number of parked (URI-not-yet-in-table) user registrations.
  static std::size_t pending_registration_count(const TypeResolver& resolver)
  {
    return resolver.mPendingUserRegistrations.size();
  }

  /// @return The resolver's last-seeded NamespaceTable snapshot (the strand-only `mNamespaces`), or null if
  ///         the resolver has never been seeded via @ref TypeResolver::on_namespace_table_replaced_async.
  ///         Lets a ConnectionImpl seeding test prove the connect-time / reconnect seed actually reached the
  ///         resolver (and, via `generation()`, that a reconnect re-read re-seeded it).
  static std::shared_ptr<const ua::client::NamespaceTable> namespace_snapshot(const TypeResolver& resolver)
  {
    return resolver.mNamespaces;
  }

  /// @return The strand the resolver posts async work onto. Structural section 8.6 check: must equal the
  /// injected
  ///         strand (ConnectionImpl's)  -  the resolver never fabricates its own.
  static boost::asio::strand<boost::asio::any_io_executor> post_strand(const TypeResolver& resolver)
  {
    return resolver.mStrand;
  }
};

}  // namespace ua::client::detail

#endif  // UA_TYPE_RESOLVER_TEST_ACCESS_H
