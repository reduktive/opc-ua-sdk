// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_COMPONENTS_H
#define UA_TEST_COMPONENTS_H

#include "ua_client_components.h"
#include "ua_log_level.h"
#include "ua_server_components.h"

#include <memory>

namespace ua
{
class Crypto;
class CertificateStore;
class LogSink;
}  // namespace ua

namespace ua::test_helpers
{

/// The one crypto provider tests use when they do not need their own: the SDK's default provider
/// with a fixed private-key credential, so keys a test server or client writes can be read back. A
/// server or client no longer has a default provider (security review B3-8).
std::shared_ptr<const Crypto> test_crypto();

}  // namespace ua::test_helpers

#endif  // !UA_TEST_COMPONENTS_H
