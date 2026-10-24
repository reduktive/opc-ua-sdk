// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_REGISTERED_SERVER_STORE_TEST_ACCESS_H
#define UA_TESTS_HELPERS_REGISTERED_SERVER_STORE_TEST_ACCESS_H

#include "ua_registered_server_store.h"

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace ua::test_helpers
{

/// Friend-based accessor for RegisteredServerStore internals needed by unit tests.
/// Keeps test-only helpers out of the public store API. Exposes the strand-confined
/// entry map and expiry metadata for state assertions.
///
/// NOTE: the underlying fields are strand-confined. Tests must only read them from the
/// store's own strand (post() a query and block the result back to the main test thread),
/// never from an arbitrary thread, to avoid a data race.
class RegisteredServerStoreTestAccess
{
public:
  explicit RegisteredServerStoreTestAccess(ua::server::RegisteredServerStore& store) : mStore(store)
  {}

  /// Strand-confined: number of entries currently held.
  std::size_t entry_count() const
  {
    return mStore.mEntries.size();
  }

  /// Strand-confined: true if an entry keyed by `serverUri` is present.
  bool contains(const std::string& serverUri) const
  {
    return mStore.mEntries.find(serverUri) != mStore.mEntries.end();
  }

  /// Strand-confined: the absolute expiry deadline for `serverUri` (caller must ensure present).
  std::chrono::steady_clock::time_point expires_at(const std::string& serverUri) const
  {
    return mStore.mEntries.at(serverUri).expiresAt;
  }

  bool running() const
  {
    return mStore.mRunning;
  }

private:
  ua::server::RegisteredServerStore& mStore;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_REGISTERED_SERVER_STORE_TEST_ACCESS_H
