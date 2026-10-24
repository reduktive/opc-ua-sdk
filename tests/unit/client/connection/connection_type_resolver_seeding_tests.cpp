// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ConnectionImpl's TypeResolver connect-time seeding (Slice T1, Phase A1). The TypeResolver
// (ua::client::detail::TypeResolver, client design section 8.6) is a strand-serialised sub-object of
// ConnectionImpl. It is only useful once seeded with the Connection's NamespaceTable: a user registration
// whose namespace URI is not yet in the table PARKS, and resolution against a NodeId needs the URI->index
// binding. These tests drive a real ConnectionImpl over the FakeSessionOps tier-0 interface
// (ConnectionImplTestAccess::create_with_ops) and assert that ConnectionImpl seeds the resolver at the two
// lifecycle points where the NamespaceTable is known:
//   1. FIRST reach-Active (bootstrap): on_first_session_active() calls
//      type_resolver()->on_namespace_table_replaced_async(mNamespaceTable, ...). Proven by a user
//      registration parked during the bootstrap window that ATTACHES at first-active (pending -> 0) and by
//      the resolver's namespace snapshot becoming non-null.
//   2. RECONNECT re-read (CL-SESS-028): apply_namespace_read re-seeds with the bumped-generation table.
//      Proven by the resolver's snapshot picking up a namespace URI that only the reconnect re-read carried,
//      with generation() advanced.
//
// Falsifiability: with the seed removed the resolver is never handed a NamespaceTable, so the parked
// registration stays parked (pending stays 1) and the snapshot stays null - FirstActiveSeedsResolver... and
// ReconnectReReadReSeedsResolver both fail. These are the RED->GREEN pins for Edit 1 / Edit 2.
//
// @verifies CL-BASE-008 - the resolver's type pre-knowledge (user-registered types) is bound at connect time:
// @relation(CL-BASE-008, scope=file)
//           a registration parked during the bootstrap window attaches the moment the NamespaceTable is
//           known.
// @verifies CL-ATTR-012 - the connect-time namespace hook (on_namespace_table_replaced_async) is
// @relation(CL-ATTR-012, scope=file)
//           production-reachable: ConnectionImpl drives it at first-active with the bootstrap NamespaceTable.
// @verifies CL-VIEW-018 - resolution stays invariant under a namespace remap: a reconnect NamespaceArray
// @relation(CL-VIEW-018, scope=file)
//           re-read re-seeds the resolver with the bumped-generation table.

#include "fake_session_ops.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_logger.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_type_registry.h"
#include "ua_type_resolver.h"
#include "ua_type_resolver_test_access.h"

#include "async_test_runtime.h"

#include <boost/asio/post.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::NodeId;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::RegistrationOutcome;
using ua::client::detail::TypeResolver;
using ua::client::detail::TypeResolverTestAccess;
using ua::client::detail::TypeSource;
using ua::client::detail::UserTypeRegistration;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;
using ua::test_helpers::make_namespace_array_response;

using TA = ConnectionImplTestAccess;

constexpr std::string_view seedUri{"urn:test:seedtypes"};
constexpr std::string_view reconnectUri{"urn:test:reconnect"};

NodeId node(std::uint16_t ns, std::uint32_t id)
{
  return NodeId{ns, id};
}

template<class Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout = 2s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(2ms);
  }
  return pred();
}

/// A consistent strand-read of the resolver's strand-only state (mirrors the sync-wrapper exception in
/// lambdas.md: the promise/lambda outlive the blocking get()). The resolver shares ConnectionImpl's strand.
struct ResolverState
{
  std::shared_ptr<const ua::client::NamespaceTable> snapshot;
  std::size_t pending = 0;
  std::optional<TypeSource> userSource;
};

ResolverState read_resolver(TypeResolver& resolver, const NodeId& userEncoding)
{
  std::promise<ResolverState> promise;
  auto future = promise.get_future();
  boost::asio::post(TypeResolverTestAccess::post_strand(resolver),
    [&resolver, &userEncoding, &promise]
    {
      ResolverState state;
      state.snapshot = TypeResolverTestAccess::namespace_snapshot(resolver);
      state.pending = TypeResolverTestAccess::pending_registration_count(resolver);
      state.userSource = TypeResolverTestAccess::source_of(resolver, userEncoding);
      promise.set_value(std::move(state));
    });
  return future.get();
}

/// A user registration for a structure type in @p uri. The encoding / datatype identifiers carry ns 0; the
/// resolver overwrites the index with the URI's resolved NamespaceIndex on attach.
UserTypeRegistration registration_for(std::string_view uri)
{
  UserTypeRegistration registration;
  registration.namespaceUri = std::string{uri};
  registration.dataTypeIdentifier = node(0, 200);
  registration.binaryEncodingIdentifier = node(0, 100);
  return registration;
}

class ConnectionTypeResolverSeeding : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  /// Scripts the tier-0 read op to answer the NamespaceArray read with @p uris (bootstrap + reconnect
  /// re-read both flow through this one op on the fake session).
  void set_namespace_array(std::vector<std::string> uris)
  {
    mSession->read.set_result(ua::Result<ua::ReadResponse>{make_namespace_array_response(std::move(uris))});
  }

  std::shared_ptr<ConnectionImpl> make_connection(ConnectionConfig config = ConnectionConfig{})
  {
    return TA::create_with_ops(mRuntime.executor(),
      mSession,
      std::move(config),
      Logger{},
      mReopen->as_ops(),
      ua::client::Session::ActivateConfig{},
      ua::client::ReconnectPolicy{});
  }

  static void start(ConnectionImpl& connection)
  {
    std::promise<ua::VoidResult> started;
    auto future = started.get_future();
    connection.start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }
};

// @verifies CL-BASE-008 / CL-ATTR-012 - a user registration parked during the bootstrap window (the resolver
// has no NamespaceTable yet, so the URI cannot be bound) ATTACHES at first-active, when ConnectionImpl seeds
// the resolver with the bootstrap NamespaceTable. RED before Edit 1: the resolver is never seeded, so the
// registration stays parked (pending == 1) and the snapshot stays null.
// @relation(CL-ATTR-012, CL-BASE-008, scope=function)
TEST_F(ConnectionTypeResolverSeeding, FirstActiveSeedsResolverAndAttachesParkedRegistration)
{
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}});
  auto connection = make_connection();
  auto resolver = connection->type_resolver();

  // Park a registration BEFORE first-active: the resolver has no NamespaceTable snapshot (nothing seeded it)
  // and the cross-strand SupportOps snapshot is still null, so the URI is unbound and the registration parks.
  std::promise<std::vector<RegistrationOutcome>> registered;
  auto registeredFuture = registered.get_future();
  resolver->register_types_async({registration_for(seedUri)},
    [&registered](ua::Result<std::vector<RegistrationOutcome>> result)
    { registered.set_value(result.value()); });
  const auto outcomes = registeredFuture.get();
  ASSERT_EQ(outcomes.size(), 1U);
  ASSERT_TRUE(outcomes[0].retainedForLaterAttach) << "the registration must park (URI not yet bound)";

  const auto beforeActive = read_resolver(*resolver, node(1, 100));
  ASSERT_EQ(beforeActive.pending, 1U) << "the registration is parked before first-active";
  ASSERT_EQ(beforeActive.snapshot, nullptr) << "the resolver is unseeded before first-active";

  // Drive the bootstrap to Active - on_first_session_active must seed the resolver with mNamespaceTable.
  start(*connection);

  // The seed attaches the parked registration (pending -> 0) and publishes the namespace snapshot.
  ASSERT_TRUE(wait_until([&] { return read_resolver(*resolver, node(1, 100)).pending == 0U; }))
    << "first-active must seed the resolver so the parked registration attaches (CL-BASE-008/CL-ATTR-012)";
  const auto afterActive = read_resolver(*resolver, node(1, 100));
  ASSERT_NE(afterActive.snapshot, nullptr) << "first-active must seed the resolver's namespace snapshot";
  EXPECT_TRUE(afterActive.snapshot->lookup_index(seedUri).has_value())
    << "the seeded snapshot must be the bootstrap NamespaceTable (contains the test URI)";
  EXPECT_EQ(afterActive.userSource, TypeSource::UserRegistered)
    << "the attached registration installs at the URI's resolved index (ns 1)";
}

// @verifies CL-ATTR-012 - the seed is direct (no parked registration needed): at first-active the resolver's
// namespace snapshot becomes the bootstrap NamespaceTable. RED before Edit 1: the snapshot stays null.
// @relation(CL-ATTR-012, scope=function)
TEST_F(ConnectionTypeResolverSeeding, FirstActiveSeedsResolverNamespaceSnapshot)
{
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}});
  auto connection = make_connection();
  start(*connection);
  auto resolver = connection->type_resolver();

  ASSERT_TRUE(wait_until([&] { return read_resolver(*resolver, node(1, 100)).snapshot != nullptr; }))
    << "first-active must seed the resolver's NamespaceTable snapshot (CL-ATTR-012)";
  const auto state = read_resolver(*resolver, node(1, 100));
  ASSERT_NE(state.snapshot, nullptr);
  EXPECT_EQ(state.snapshot->generation(), 0U) << "the bootstrap snapshot is generation 0";
  EXPECT_TRUE(state.snapshot->lookup_index(seedUri).has_value());
}

// @verifies CL-VIEW-018 - a reconnect NamespaceArray re-read (CL-SESS-028) re-seeds the resolver with the
// bumped-generation table, so resolution stays invariant under a namespace remap. RED before Edit 2: the
// resolver keeps the bootstrap (generation-0) snapshot and never sees the reconnect-only URI.
// @relation(CL-SESS-028, CL-VIEW-018, scope=function)
TEST_F(ConnectionTypeResolverSeeding, ReconnectReReadReSeedsResolverWithBumpedGeneration)
{
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}});
  auto connection = make_connection();
  start(*connection);
  auto resolver = connection->type_resolver();
  ASSERT_TRUE(wait_until([&] { return read_resolver(*resolver, node(1, 100)).snapshot != nullptr; }))
    << "precondition: first-active seeded the bootstrap snapshot";

  // The reconnect re-read observes a remapped NamespaceArray (a new URI appears). apply_namespace_read
  // rebuilds the table with a bumped generation and must re-seed the resolver with it.
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}, std::string{reconnectUri}});
  std::promise<ua::VoidResult> reread;
  auto rereadFuture = reread.get_future();
  TA::reconnect_re_read_namespace_array(
    *connection, [&reread](ua::VoidResult result) { reread.set_value(std::move(result)); });
  ASSERT_TRUE(rereadFuture.get().is_good());

  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto state = read_resolver(*resolver, node(1, 100));
      return state.snapshot != nullptr && state.snapshot->generation() == 1U;
    }))
    << "the reconnect re-read must re-seed the resolver with the bumped-generation table (CL-VIEW-018)";
  const auto state = read_resolver(*resolver, node(1, 100));
  ASSERT_NE(state.snapshot, nullptr);
  EXPECT_EQ(state.snapshot->generation(), 1U) << "the reconnect re-read snapshot is generation 1";
  EXPECT_TRUE(state.snapshot->lookup_index(reconnectUri).has_value())
    << "the re-seeded snapshot carries the reconnect-only URI (remap tracked)";
}

// The type-resolution policy must reach the resolver from the Connection's CONFIG - the resolver's own
// tests hand a policy to a standalone resolver, which never traverses `ConnectionImpl::type_resolver()`.
//
// Asserted behaviourally rather than by reading the policy back: under Eager the connect-time seed runs the
// eager scan, which issues a Browse per declared eager type, and a Lazy Connection issues no browse at
// connect at all.
TEST_F(ConnectionTypeResolverSeeding, EagerModeFromConnectionConfigRunsTheConnectTimeScan)
{
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}});

  ConnectionConfig config;
  config.typeResolution.mode = ua::client::TypeResolutionMode::Eager;  // non-default: the default is Lazy
  config.typeResolution.eagerTypes = {node(0, 100)};
  auto connection = make_connection(std::move(config));
  auto resolver = connection->type_resolver();

  // The policy actually in force is the configured one, not a default-constructed placeholder.
  EXPECT_EQ(resolver->policy().mode, ua::client::TypeResolutionMode::Eager)
    << "ConnectionConfig::typeResolution must reach the resolver";
  ASSERT_EQ(resolver->policy().eagerTypes.size(), 1U);
  EXPECT_EQ(resolver->policy().eagerTypes[0], node(0, 100));

  ASSERT_EQ(mSession->browse.call_count(), 0U) << "nothing is scanned before the resolver is seeded";
  start(*connection);

  // The falsifier: the connect-time seed runs the eager scan, which resolves each declared eager type -
  // Browse HasEncoding on its encoding NodeId. With the policy unwired the mode is Lazy and this stays 0.
  ASSERT_TRUE(wait_until([&] { return mSession->browse.call_count() > 0U; }))
    << "Eager mode must run the connect-time scan when the resolver is seeded";
}

// The other half of the same claim: a Connection that does NOT ask for eager resolution must not acquire a
// connect-time scan by accident. Pins the default as "no extra wire traffic", so the test above is proving
// the config field and not merely that seeding browses.
TEST_F(ConnectionTypeResolverSeeding, DefaultLazyPolicyRunsNoConnectTimeScan)
{
  set_namespace_array({"http://opcfoundation.org/UA/", std::string{seedUri}});
  auto connection = make_connection();  // default config: Lazy, no eager interest
  auto resolver = connection->type_resolver();
  EXPECT_EQ(resolver->policy().mode, ua::client::TypeResolutionMode::Lazy);

  start(*connection);
  ASSERT_TRUE(wait_until([&] { return read_resolver(*resolver, node(1, 100)).snapshot != nullptr; }))
    << "precondition: the seed happened, so a scan WOULD have been issued had one been configured";
  EXPECT_EQ(mSession->browse.call_count(), 0U) << "Lazy resolution issues no connect-time Browse";
}

/// Thread-safe ConnectionObserver counting the two lifecycle hooks the first-reach-Active latch separates:
/// the one-off first-connect fan-out (on_connected) and the recovery fan-out (on_reconnected). Both are
/// delivered on the ObserverSink's own delivery strand - off the connection strand and off the test thread -
/// so the counters are atomic and are read only after a wait_until has observed the transition.
class LifecycleCountingObserver : public ua::client::ConnectionObserver
{
public:
  std::atomic<std::size_t> connected{0};
  std::atomic<std::size_t> reconnected{0};

  void on_connected(const ua::client::Connection&) override
  {
    connected.fetch_add(1, std::memory_order_relaxed);
  }

  void on_reconnected(const ua::client::Connection&, ua::client::ReconnectOutcome) override
  {
    reconnected.fetch_add(1, std::memory_order_relaxed);
  }
};

}  // namespace
