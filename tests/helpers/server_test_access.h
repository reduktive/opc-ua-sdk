// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_SERVER_TEST_ACCESS_H
#define UA_TESTS_HELPERS_SERVER_TEST_ACCESS_H

#include "ua_server.h"
#include "ua_server_impl.h"

namespace ua::test_helpers
{

/// Friend-based accessor for Server internals needed by tests.
/// Provides access to the underlying ServerImpl from a Server reference.
class ServerTestAccess
{
public:
  static ua::server::ServerImpl& impl(ua::server::Server& server)
  {
    return *server.mImpl;
  }

  static const ua::server::ServerImpl& impl(const ua::server::Server& server)
  {
    return *server.mImpl;
  }

  static std::shared_ptr<ua::server::ServerImpl> impl_ptr(ua::server::Server& server)
  {
    return server.mImpl;
  }
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_SERVER_TEST_ACCESS_H
