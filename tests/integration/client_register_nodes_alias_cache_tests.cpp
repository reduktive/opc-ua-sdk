// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief End-to-end integration row for the Slice V1 RegisterNodes alias cache (client design section 8.7,
///        CL-VIEW-009/010/011), driven over a REAL client stack (ConnectionImpl -> SecureChannel -> server).
///
/// Unlike the ClientRegisterNodes rows in client_register_browsenext_matrix_tests.cpp - which were authored
/// while the tier-2 wiring was UNBUILT and therefore construct a SEPARATE enabled AddressSpaceCache over the
/// Connection's wire interface while the Connection itself ran a DISABLED default cache - this row exercises
/// the Connection's OWN internal cache end-to-end: it builds the Connection with an ENABLED
/// AddressSpaceCachePolicy threaded through the connect ConnectionConfig, so the real register / read path
/// consults the wired cache.
///
/// Scenario (one test, two phases over the same live Connection):
///   1. RegisterNodes for a user NodeId X, with the server's RegisterNodes response mutated to hand back a
///      distinct numeric alias A. The Connection's register path installs X -> A into its internal cache.
///   2. A subsequent Read for X must carry the ALIAS A on the wire (observed on the server via the request
///      observer) - the register->substitute round trip end-to-end (CL-VIEW-009 / CL-VIEW-010).
///   3. A Session change (the production Session-scoped clear the reconnect session-CHANGED branch invokes)
///      is driven on the Connection's internal cache; a subsequent Read for X must now carry the RAW X - no
///      stale old-session alias survives (CL-VIEW-011).
///
/// A single-shot Connection owns no reconnect FSM, so a real new-sessionId reconnect cannot be produced here
/// (that is the reconnect cluster's fixture). Step 3 therefore drives the EXACT production clear method
/// (`AddressSpaceCache::on_session_changed_async`, via ConnectionImplTestAccess) on the Connection's own
/// cache and asserts the raw NodeId returns to the real wire; the full queue/flush/session-change ORDERING
/// (a request queued across the reconnect re-dispatching the raw NodeId - the section 3.1 fix) is
/// unit-covered by ConnectionAddressSpaceCacheWiring.QueuedReadAcrossSessionChangeDispatchesRawNodeId.
///
/// Falsifiability: with a DISABLED cache (or the pre-Slice-V1 unwired read path) the wire Read in step 2
/// would carry the ORIGINAL X, not A; with the Session-scope clear removed, step 3's Read would still carry
/// the stale alias A.

#include "misbehaving_server.h"
#include "test_utilities.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_service_set.h"

#include "ua_address_space_cache_policy.h"

#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_log_level.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_structure.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::MisbehavingServer;

namespace
{

// A started tier-2 Connection whose internal AddressSpaceCache is ENABLED via the connect ConnectionConfig,
// retaining the ConnectionImpl so a test can drive the production Session-scoped clear on the Connection's
// OWN cache (ConnectionImplTestAccess::drive_address_space_cache_session_changed).
class StartedEnabledConnection
{
public:
  StartedEnabledConnection(boost::asio::any_io_executor executor, Session session)
  {
    ua::client::detail::ConnectionConfig config;
    config.addressSpaceCache.enabled = true;  // opt in to the RegisterNodes alias cache (section 8.7)
    config.addressSpaceCache.useRegisterNodes = true;
    mImpl = ConnectionImpl::create(std::move(executor), std::move(session), std::move(config), Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    mImpl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(mImpl));
  }

  ~StartedEnabledConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedEnabledConnection(const StartedEnabledConnection&) = delete;
  StartedEnabledConnection& operator=(const StartedEnabledConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  ConnectionImpl& impl()
  {
    return *mImpl;
  }

private:
  std::shared_ptr<ConnectionImpl> mImpl;
  VoidResult mStartStatus{};
  std::optional<Connection> mConnection;
};

// A real client bound to a MisbehavingServer, with an activated Session wrapped into an ENABLED-cache
// Connection. Mirrors the ClientRegisterNodes fixture but opts the Connection's internal cache in.
class EnabledCacheClientFixture
{
public:
  explicit EnabledCacheClientFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientRegisterNodesAliasCache"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~EnabledCacheClientFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  EnabledCacheClientFixture(const EnabledCacheClientFixture&) = delete;
  EnabledCacheClientFixture& operator=(const EnabledCacheClientFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  StartedEnabledConnection& started()
  {
    return *mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedEnabledConnection> mConnection;
};

// A guarded record of the nodeId of the first ReadValueId of every Read request the client put on the wire,
// populated on a server strand by the request observer and read by the test thread.
struct ReadWireCapture
{
  mutable std::mutex mutex;
  std::vector<ua::NodeId> readNodeIds;

  void observe(const ua::Structure& request)
  {
    if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      if (!read->nodes_to_read().empty())
        readNodeIds.push_back(read->nodes_to_read()[0].node_id());
    }
  }

  std::size_t count() const
  {
    std::lock_guard lock(mutex);
    return readNodeIds.size();
  }

  ua::NodeId back() const
  {
    std::lock_guard lock(mutex);
    return readNodeIds.back();
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 3000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(5ms);
  }
  return predicate();
}

// Builds a one-attribute (Value) Read request for @p node.
ua::ReadRequest read_value_request(const ua::NodeId& node)
{
  ua::ReadRequest request;
  ua::ReadValueId valueId;
  valueId.node_id() = node;
  valueId.attribute_id() = static_cast<ua::IntegerId>(13);  // AttributeId::Value
  request.nodes_to_read().push_back(std::move(valueId));
  return request;
}

}  // namespace

// =============================================================================================
// ClientRegisterNodesAliasCache - the Connection's OWN internal cache, end-to-end over the real wire.
// =============================================================================================

// Row - RegisteredAliasSubstitutedOnWireThenClearedBySessionChange (CL-VIEW-009/010/011)
// Register X (server returns a distinct numeric alias A) -> a later Read for X carries A on the wire
// (register->substitute round trip, cache POPULATED by the RegisterNodes response and CONSULTED by the read
// path). Then a Session change clears the Session-scoped cache -> a later Read for X carries the RAW X.
// [neg: the alias, not the original, is used once registered; no stale alias survives a session change]
// @verifies CL-VIEW-009
// @verifies CL-VIEW-010
// @verifies CL-VIEW-011
// @relation(CL-VIEW-009, CL-VIEW-010, CL-VIEW-011, scope=function)
TEST(ClientRegisterNodesAliasCache, RegisteredAliasSubstitutedOnWireThenClearedBySessionChange)
{
  MisbehavingServer server;
  EnabledCacheClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId original{1, "AliasCache.Node"};  // a user NodeId (RegisterNodes is meant to alias these)
  const NodeId alias{0, static_cast<std::uint32_t>(424242)};  // the server-assigned numeric handle

  // The server hands back the distinct numeric alias A for the RegisterNodes of X, so substitution is
  // observable on the wire (a real reference server may echo the original, which would be indistinguishable).
  server.set_response_mutator(
    [alias](Response& response)
    {
      if (auto* registerResponse = dynamic_cast<ua::RegisterNodesResponse*>(response.second.get()))
      {
        ua::Array<ua::NodeId> registered;
        registered.push_back(alias);
        registerResponse->registered_node_ids() = std::move(registered);
      }
    });

  auto capture = std::make_shared<ReadWireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  // Phase 1 - register X: the Connection's internal cache installs X -> A (CL-VIEW-010 populate).
  ua::RegisterNodesRequest registerRequest;
  registerRequest.nodes_to_register().push_back(original);
  auto registerResult = fixture.conn().service_requests().try_register_nodes_sync(std::move(registerRequest));
  ASSERT_TRUE(registerResult.is_good()) << "the RegisterNodes must succeed to populate the alias cache";
  ASSERT_EQ(registerResult.value().registered_node_ids().size(), 1u);
  ASSERT_EQ(registerResult.value().registered_node_ids()[0], alias)
    << "the server (mutated) handed back the distinct numeric alias A";

  // Phase 2 - read X: the wire Read must carry the ALIAS A, not the original X (CL-VIEW-009 end-to-end).
  (void)fixture.conn().service_requests().try_read_sync(read_value_request(original));
  ASSERT_TRUE(wait_until([&] { return capture->count() >= 1; })) << "the tier-2 Read must reach the wire";
  EXPECT_EQ(capture->back(), alias)
    << "after RegisterNodes the wire Read for X must carry the server-assigned alias A (CL-VIEW-009)";

  // Phase 3 - Session change: the production Session-scoped clear on the Connection's own cache.
  const std::size_t readsBeforeSessionChange = capture->count();
  ConnectionImplTestAccess::drive_address_space_cache_session_changed(fixture.started().impl());

  // A later Read for X now carries the RAW X - no stale old-session alias survives (CL-VIEW-011 end-to-end).
  (void)fixture.conn().service_requests().try_read_sync(read_value_request(original));
  ASSERT_TRUE(wait_until([&] { return capture->count() > readsBeforeSessionChange; }))
    << "the post-session-change Read must reach the wire";
  EXPECT_EQ(capture->back(), original)
    << "after a Session change the wire Read for X must carry the RAW NodeId - the Session-scoped alias was "
       "cleared, so no stale alias is reused across Sessions (CL-VIEW-011)";
  EXPECT_NE(capture->back(), alias) << "the stale old-session alias A must not survive the Session change";
}
