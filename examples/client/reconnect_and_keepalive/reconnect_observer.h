// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_RECONNECT_OBSERVER_H
#define UASDK_EXAMPLE_RECONNECT_OBSERVER_H

/// @file
/// @brief Observing a Connection's reconnect, rather than polling it.

#include "example_queue.h"

#include "ua_client_observers.h"
#include "ua_reconnect_types.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>

namespace examples::reconnect
{

/// A ceiling on waiting for the operator to restart the server, not a delay anyone expects to spend.
inline constexpr auto outageBudget = std::chrono::milliseconds{60000};

/// The two reconnect notifications this example waits for.
enum class Notification
{
  Reconnecting,
  Reconnected
};

/// Records the reconnect notifications the Connection emits, for the thread waiting on them.
///
/// This is the alternative to polling `state()`: the SDK says when something happened, so the
/// example learns about the outage the moment it starts rather than up to a poll interval later.
/// Every hook runs on the Connection's executor and must not block, so each appends and returns.
class ReconnectObserver : public ua::client::ConnectionObserver
{
public:
  explicit ReconnectObserver(std::shared_ptr<examples::Queue<Notification>> notifications)
    : mNotifications(std::move(notifications))
  {}

  void on_reconnecting(const ua::client::Connection&, std::size_t, ua::client::ReconnectCause) override
  {
    mNotifications->push(Notification::Reconnecting);
  }

  void on_reconnected(const ua::client::Connection&, ua::client::ReconnectOutcome outcome) override
  {
    mOutcome = outcome;
    mNotifications->push(Notification::Reconnected);
  }

  /// What the completed reconnect preserved. Only meaningful once Reconnected has arrived.
  [[nodiscard]] ua::client::ReconnectOutcome outcome() const
  {
    return mOutcome;
  }

private:
  std::shared_ptr<examples::Queue<Notification>> mNotifications;
  ua::client::ReconnectOutcome mOutcome;
};

/// Waits for one reconnect notification, or fails saying which one never came.
void await(examples::Queue<Notification>& notifications, Notification wanted, std::string_view what);

}  // namespace examples::reconnect

#endif  // UASDK_EXAMPLE_RECONNECT_OBSERVER_H
