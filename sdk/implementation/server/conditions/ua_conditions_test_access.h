// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONDITIONS_TEST_ACCESS_H
#define UA_CONDITIONS_TEST_ACCESS_H

/// @file
/// @brief Test interface for @ref ua::Conditions' shutdown methods.
///
/// Closing a `Conditions` belongs to the server that owns it: `Server::conditions()` hands out a
/// reference to the instance `ServerImpl` created and tears down, and the server closes it as part
/// of its own shutdown. A fixture that constructs its own `Conditions` against its own pool owns
/// that one, and has to close it - so it reaches the same methods through here rather than the
/// methods being public for everyone.

#include "ua_conditions.h"

#include "ua_result.h"

#include <functional>
#include <memory>
#include <utility>

namespace ua
{

struct ConditionsTestAccess
{
  /// Constructs a registry the fixture itself owns, without address-space integration.
  /// Conditions created through it live only in the in-memory map.
  static std::shared_ptr<Conditions> create(
    boost::asio::any_io_executor executor, std::weak_ptr<EventSink> eventSink)
  {
    return std::make_shared<Conditions>(
      Conditions::ConstructionKey{}, std::move(executor), std::move(eventSink));
  }

  /// Constructs an address-space-integrated registry the fixture itself owns.
  static std::shared_ptr<Conditions> create(
    boost::asio::any_io_executor executor, std::weak_ptr<EventSink> eventSink, AddressSpace addressSpace)
  {
    return std::make_shared<Conditions>(
      Conditions::ConstructionKey{}, std::move(executor), std::move(eventSink), std::move(addressSpace));
  }

  /// Closes every registered condition instance and shuts the registry down.
  static void close_async(Conditions& conditions, std::function<void(VoidResult)> callback)
  {
    conditions.close_async(std::move(callback));
  }

  /// Closes all conditions and shuts down, blocking until complete.
  static void close_sync(Conditions& conditions)
  {
    conditions.close_sync();
  }

  /// Closes all conditions and shuts down, blocking until complete. Never throws.
  static VoidResult try_close_sync(Conditions& conditions) noexcept
  {
    return conditions.try_close_sync();
  }
};

}  // namespace ua

#endif  // UA_CONDITIONS_TEST_ACCESS_H
