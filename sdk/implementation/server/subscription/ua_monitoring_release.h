// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_MONITORING_RELEASE_H
#define UA_MONITORING_RELEASE_H

#include "ua_address_space.h"
#include "ua_logger.h"
#include "ua_namespace_monitoring.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::server
{

/// A namespace monitoring handle and the index of the namespace that issued it.
struct IssuedMonitoringHandle
{
  uint16_t namespaceIndex{0};
  MonitoringHandle handle{0};
};

/// Releases monitoring handles: groups them by namespace and sends every namespace one `delete_monitoring`,
/// all at once and without awaiting the answers.
///
/// The one routine every release goes through - closing or destroying a Subscription, DeleteMonitoredItems,
/// a create's answer that arrives after the create ended, and a handle obtained for an item the create
/// then does not commit - so a namespace sees one delete for every handle it issued. Each namespace is
/// looked up at release time; one that is gone is skipped. A failed release is logged. Never throws.
///
/// @param addressSpace Where each namespace is looked up.
/// @param handles      The handles to release; zero handles are ignored.
/// @param logger       Receives a failed release.
void release_monitoring_handles(const WeakAddressSpace& addressSpace,
  std::vector<IssuedMonitoringHandle> handles, const Logger& logger) noexcept;

/// @ref release_monitoring_handles, run later on the address space's executor: for a release that a
/// namespace's own answer triggers, so the namespace is not called back from inside its callback. Never
/// throws.
void post_release_monitoring_handles(const WeakAddressSpace& addressSpace,
  std::vector<IssuedMonitoringHandle> handles, const Logger& logger) noexcept;

/// The handles of `create_monitoring` answers that have arrived but that their create has not yet taken.
///
/// A create's answer is posted to the Subscription's strand, and a Subscription that has ended - or been
/// destroyed - before the post runs never receives it. The handles in it are therefore held here from
/// the namespace's own thread when the answer arrives; the create takes them when it resumes, and whatever
/// is still held when the Subscription ends is released. The create uses only a namespace's first answer,
/// so the handles of any later answer to the same call are released on arrival. Thread-safe.
class UnclaimedMonitoringHandles
{
public:
  /// @param logger Receives a failed release.
  explicit UnclaimedMonitoringHandles(Logger logger);

  /// A ticket naming one `create_monitoring` call; given to @ref hold and @ref claim.
  uint64_t open_ticket();

  /// Holds @p handles, the first answer to @p ticket's call, until @ref claim. The handles of a later answer
  /// to the same call, and of any answer after @ref end, @ref abandon or the claim, are released instead,
  /// posted to the address space's executor so the namespace is not called back from inside its own callback.
  /// Answers that race on two threads are told apart here, under one lock: only the first is the call's.
  ///
  /// @param ticket       From @ref open_ticket.
  /// @param addressSpace Where the issuing namespace is looked up if the handles are released.
  /// @param handles      The good handles of one answer; may be empty.
  /// @return `true` for the call's first answer, which the caller delivers; `false` for a later one, which it
  ///         drops.
  bool hold(
    uint64_t ticket, const WeakAddressSpace& addressSpace, std::vector<IssuedMonitoringHandle> handles);

  /// Takes what @ref hold holds under @p ticket: the caller owns those handles from here on, and a later
  /// answer to the same call is released on arrival.
  ///
  /// @return The handles of the first answer; empty when the namespace has not answered; `std::nullopt`
  ///         when @ref end has already released them, or the ticket was abandoned or claimed already.
  std::optional<std::vector<IssuedMonitoringHandle>> claim(uint64_t ticket);

  /// The caller will not claim @p ticket (its create was torn down first): what is held under it is released,
  /// and a later answer is released on arrival.
  void abandon(uint64_t ticket) noexcept;

  /// Ends the Subscription's monitoring: everything held is released, and later answers are released on
  /// arrival. A second call does nothing.
  void end() noexcept;

private:
  struct Held
  {
    WeakAddressSpace addressSpace;
    std::vector<IssuedMonitoringHandle> handles;
  };

  Logger mLogger;
  std::mutex mMutex;
  bool mEnded{false};
  uint64_t mNextTicket{1};
  // Tickets whose call has not answered yet; a ticket leaves on its first answer, its claim or its abandon.
  // Kept after the end, so a first answer that arrives then is still told apart from a later one.
  std::unordered_set<uint64_t> mUnanswered;
  std::unordered_map<uint64_t, Held> mHeld;
};

}  // namespace ua::server

#endif  // !UA_MONITORING_RELEASE_H
