// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::CoreClientTestAccess::set_test_hooks (the friend-based test/fuzzer injection
// interface).
//
// set_test_hooks moves the caller's transport-decorator and security-policy-factory callables into the
// CoreClientImpl behind the Client handle. There is no public getter, so retention is observed structurally:
// a sentinel captured by the installed callable must stay alive (owned by the client) after the caller's own
// copy is gone, and must be released when the client is destroyed. If set_test_hooks dropped the hook
// instead of storing it, the sentinel would expire immediately after the call - which these tests would
// catch.

#include <gtest/gtest.h>

#include "dev_factories.h"

#include "ua_core_client.h"
#include "ua_client_test_hooks.h"
#include "ua_security_policy.h"
#include "ua_transport_connection.h"

#include <boost/asio/thread_pool.hpp>

#include <memory>

// The transport-decorator hook is retained by the client until the client is destroyed.
TEST(ClientTestHooks, TransportDecoratorRetainedByClientThenReleasedOnDestroy)
{
  boost::asio::thread_pool tp;

  auto sentinel = std::make_shared<int>(0);
  std::weak_ptr<int> weakSentinel = sentinel;

  {
    auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [keep = sentinel](std::shared_ptr<ua::TransportConnection> connection)
    {
      return connection;
    };
    // From here the lambda inside `hooks` is the only owner of the sentinel.
    sentinel.reset();
    ASSERT_FALSE(weakSentinel.expired()) << "the decorator lambda owns the sentinel before install";

    ua::client::CoreClientTestAccess::set_test_hooks(client, std::move(hooks));

    // set_test_hooks moved the decorator into the client; my local `hooks` is moved-from. If the hook were
    // dropped rather than stored, the sentinel would already be gone.
    EXPECT_FALSE(weakSentinel.expired())
      << "set_test_hooks must store the transport decorator in the client, keeping its captures alive";
  }

  // Destroying the Client destroys CoreClientImpl and its retained hooks, releasing the decorator's captures.
  EXPECT_TRUE(weakSentinel.expired())
    << "destroying the client must release the retained transport decorator";

  tp.join();
}

// The security-policy-factory hook is retained by the client until the client is destroyed.
TEST(ClientTestHooks, SecurityPolicyFactoryRetainedByClientThenReleasedOnDestroy)
{
  boost::asio::thread_pool tp;

  auto sentinel = std::make_shared<int>(0);
  std::weak_ptr<int> weakSentinel = sentinel;

  {
    auto client = ua::test_helpers::make_dev_core_client(tp.get_executor());

    ua::client::ClientTestHooks hooks;
    hooks.securityPolicyFactory = [keep = sentinel](ua::SecurityPolicyId id)
    {
      return std::shared_ptr<ua::SecurityPolicy>{};
    };
    sentinel.reset();
    ASSERT_FALSE(weakSentinel.expired()) << "the factory lambda owns the sentinel before install";

    ua::client::CoreClientTestAccess::set_test_hooks(client, std::move(hooks));

    EXPECT_FALSE(weakSentinel.expired())
      << "set_test_hooks must store the security-policy factory in the client, keeping its captures alive";
  }

  EXPECT_TRUE(weakSentinel.expired())
    << "destroying the client must release the retained security-policy factory";

  tp.join();
}
