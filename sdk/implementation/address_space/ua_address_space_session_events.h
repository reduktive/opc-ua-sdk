// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal interface carrying Session-lifetime notifications into the address space.

#ifndef UA_ADDRESS_SPACE_SESSION_EVENTS_H
#define UA_ADDRESS_SPACE_SESSION_EVENTS_H

#include "ua_address_space.h"

#include <functional>
#include <memory>

namespace ua::detail
{

/// Delivers "a Session has closed" from the server into the address space, and lets address-space
/// components subscribe to it.
///
/// Address-space state can be owned by a Session -- a FileType handle is valid only "while the
/// session is open" (OPC 10000-20 section 4.2.2) -- but Sessions live in the server layer, and the node
/// graph cannot see one end. The notification therefore has to arrive from outside, and it travels
/// server -> address space, which is the direction the link graph permits (`uasdk-server` links
/// `uasdk-address-space`, never the reverse).
///
/// It is a friend interface rather than public API deliberately. Declaring a Session closed releases
/// everything that Session owned, so the authority to say it belongs to the component that ends
/// Sessions; on @ref AddressSpace it would let any holder of a handle sweep away another Session's
/// open files. Applications that want to observe Session lifetime use
/// `ua::server::ServerObserver::on_session_closed`, which is the supported route.
class AddressSpaceSessionEvents
{
public:
  /// Registers @p handler to run whenever a Session closes.
  ///
  /// @param addressSpace Address space to subscribe to.
  /// @param handler      Invoked with the closed Session's NodeId. Ignored if empty. Runs on
  ///                     whichever thread ended the Session -- not an address-space strand -- so it
  ///                     must do its own locking and must not block.
  /// @return A token that keeps the registration alive; when the last copy is destroyed the
  ///         handler is unregistered, so a subscriber needs no explicit teardown. Null if
  ///         @p handler is empty.
  [[nodiscard]] static std::shared_ptr<const void> add_handler(
    AddressSpace& addressSpace, std::function<void(const NodeId&)> handler);

  /// Runs every registered handler for @p sessionId.
  ///
  /// Called by the server when a Session ends, by any route: an orderly CloseSession, a dropped
  /// transport and a timeout all reach it, because the Session's destructor is what reports the
  /// closure.
  ///
  /// @param addressSpace Address space whose subscribers are notified.
  /// @param sessionId    NodeId of the Session that closed.
  static void notify_closed(AddressSpace& addressSpace, const NodeId& sessionId);
};

}  // namespace ua::detail

#endif  // UA_ADDRESS_SPACE_SESSION_EVENTS_H
