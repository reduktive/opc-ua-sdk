// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Test-only access to ServerWithDiscovery's private state. Header-only over the private pimpl State
// header, so no test-access code links into the library; not part of the public interface.

#ifndef UA_SERVER_WITH_DISCOVERY_TEST_ACCESS_H
#define UA_SERVER_WITH_DISCOVERY_TEST_ACCESS_H

#include "ua_certificate_store.h"
#include "ua_result.h"
#include "ua_server_with_discovery.h"
#include "ua_server_with_discovery_state.h"

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace ua::test_helpers
{

class ServerWithDiscoveryTestAccess
{
public:
  /// The registration client's certificate store.
  static std::shared_ptr<ua::CertificateStore> client_certificate_store(
    const ua::app::ServerWithDiscovery& wrapper)
  {
    return wrapper.mState->clientCertStore;
  }

  /// Runs the trust seeding start_async performs - the ldsTrustOverride, or the mirror of the server's
  /// application-group store - without starting the server or the registration driver.
  static void seed_client_trust(
    ua::app::ServerWithDiscovery& wrapper, std::function<void(ua::VoidResult)> seeded)
  {
    ua::app::ServerWithDiscovery::seed_client_trust(wrapper.mState.get(), std::move(seeded));
  }

  /// The directory the registration client's store lives in.
  static std::filesystem::path client_trust_directory(const ua::app::ServerWithDiscovery& wrapper)
  {
    return wrapper.mState->clientTrustDirectory;
  }

  /// Whether start created the registration driver.
  static bool has_registration(const ua::app::ServerWithDiscovery& wrapper)
  {
    const std::lock_guard lifecycle{wrapper.mState->lifecycleMutex};
    return wrapper.mState->registration != nullptr;
  }
};

}  // namespace ua::test_helpers

#endif  // !UA_SERVER_WITH_DISCOVERY_TEST_ACCESS_H
