// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Friend test interface for @ref ua::TrustListManager (not public API). Reaches the strand-private
/// queue of work that waits for the list writes (a reset waiting for a write in progress), so a test can hold
/// the "work queued, no write held" state that a real reset passes through only between two strand turns.
/// Header-only: no test-access code links into the library.

#ifndef UA_TRUST_LIST_MANAGER_TEST_ACCESS_H
#define UA_TRUST_LIST_MANAGER_TEST_ACCESS_H

#include "ua_on_strand.h"
#include "ua_trust_list_manager.h"

#include <functional>
#include <utility>

namespace ua
{

class TrustListManagerTestAccess
{
public:
  /// On the manager's strand: queues @p work behind the list writes, as a reset waiting for a write does,
  /// without running it even when no write is held; then calls @p queued. Until run_after_list_write, the
  /// manager refuses new list changes as it does while a reset waits.
  static void queue_after_list_write(
    TrustListManager& manager, std::function<void(TrustListManager&)> work, std::function<void()> queued)
  {
    ua::async::post_borrowing(&manager,
      manager.mStrand,
      manager.mLogger,
      [work = std::move(work), queued = std::move(queued)](TrustListManager& self) mutable
      {
        self.mAfterListWrite.push_back(std::move(work));
        queued();
      })();
  }

  /// On the manager's strand: runs the queued work while no write is held, then calls @p ran.
  static void run_after_list_write(TrustListManager& manager, std::function<void()> ran)
  {
    ua::async::post_borrowing(&manager,
      manager.mStrand,
      manager.mLogger,
      [ran = std::move(ran)](TrustListManager& self) mutable
      {
        self.run_after_list_write();
        ran();
      })();
  }
};

}  // namespace ua

#endif  // UA_TRUST_LIST_MANAGER_TEST_ACCESS_H
