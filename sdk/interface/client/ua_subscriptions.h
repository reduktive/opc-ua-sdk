// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-1 public `Subscriptions` accessor: create + enumerate the reconnect-surviving Subscriptions
///        of a managed @ref ua::client::Connection (client design section 7.4), reached via
///        `Connection::subscriptions()`.
/// @ingroup client

#ifndef UA_SUBSCRIPTIONS_H
#define UA_SUBSCRIPTIONS_H

#include "ua_client_subscription.h"
#include "ua_result.h"

#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct ConnectionHandleFactory;
}  // namespace detail

class Connection;

/// The Subscription-lifecycle accessor of a managed @ref Connection (section 7.4).
///
/// A lightweight move-only value handle over the same `ConnectionImpl` as its parent @ref Connection
/// (reached via `Connection::subscriptions()`, parallel to `service_requests()`). Subscriptions are tier-1
/// core lifecycle: the `SubscriptionsPipeline` owns them and they survive reconnect via
/// TransferSubscriptions (default) or recreate. This handle creates a Subscription on the server and
/// enumerates the live (reconnect-surviving) set.
///
/// @warning The `*_sync` variants block the calling thread on the async completion; on a thread of the
///          Connection's executor they refuse with `Bad_WouldBlock` instead.
/// @ingroup client
class Subscriptions
{
public:
  Subscriptions(const Subscriptions&) = delete;
  Subscriptions& operator=(const Subscriptions&) = delete;
  /// Returns or updates the subscriptions.
  Subscriptions(Subscriptions&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  Subscriptions& operator=(Subscriptions&&) noexcept = default;
  ~Subscriptions() = default;

  /// Creates a Subscription on the server and registers it with the reconnect-surviving pipeline
  /// (section 7.4).
  ///
  /// @param config   The Subscription parameters (@ref SubscriptionConfig).
  /// @param callback Receives the typed @ref Subscription handle on success, or a bad Result carrying the
  ///                 @ref ua::ErrorDetail (on the executor). Never throws.
  void create_async(
    SubscriptionConfig config, std::function<void(ua::Result<Subscription>)> callback) noexcept;

  /// Creates a Subscription, blocking until complete.
  /// @param config The config.
  /// @return The requested value.
  /// @throws ua::UaException on a bad service Result.
  /// A Good subcode on the answer is not returned; try_create_sync() returns it.
  Subscription create_sync(SubscriptionConfig config);

  /// @param config The config.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Creates a Subscription, blocking until complete. Never throws.
  ua::Result<Subscription> try_create_sync(SubscriptionConfig config) noexcept;

  /// Enumerates the live (reconnect-surviving) Subscriptions.
  ///
  /// The answer is produced on the Connection's executor, so this is the form to use from an observer
  /// callback, for example to find the Subscription a manual ConditionRefresh is delivered on.
  ///
  /// @param callback Receives a @ref Subscription handle for every currently registered Subscription
  ///                 (empty when none), or a bad Result carrying `Bad_InvalidState` when this handle holds
  ///                 no Connection (moved-from). Runs on the executor. Never throws.
  void list_async(std::function<void(ua::Result<std::vector<Subscription>>)> callback) const noexcept;

  /// Enumerates the live (reconnect-surviving) Subscriptions, blocking until complete.
  /// @return A @ref Subscription handle for every currently registered Subscription (empty when none).
  /// @throws ua::UaException with `Bad_WouldBlock` when called on a thread of the Connection's executor,
  ///         which is where the answer is produced, and with the status of any other bad Result.
  /// A Good subcode on the answer is not returned; try_list_sync() returns it.
  [[nodiscard]] std::vector<Subscription> list_sync() const;

  /// Enumerates the live (reconnect-surviving) Subscriptions, blocking until complete. Never throws.
  /// @return The handles as for @ref list_sync, or a bad Result: `Bad_WouldBlock` on a thread of the
  ///         Connection's executor, `Bad_InvalidState` on a handle that holds no Connection.
  [[nodiscard]] ua::Result<std::vector<Subscription>> try_list_sync() const noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::ConnectionHandleFactory;

  explicit Subscriptions(std::shared_ptr<detail::ConnectionImpl> impl);

  std::shared_ptr<detail::ConnectionImpl> mImpl;
};

}  // namespace ua::client

#endif  // UA_SUBSCRIPTIONS_H
