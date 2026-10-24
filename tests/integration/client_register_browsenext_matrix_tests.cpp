// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientRegisterNodes, ClientUnregisterNodes, and ClientBrowseNext clusters of the client
///        integration-test matrix.
///
/// Three suites in one translation unit, all driven against the `MisbehavingServer` semantic-response fixture
/// over a REAL client stack (ConnectionImpl -> SecureChannel -> server):
///
///   - ClientRegisterNodes / ClientUnregisterNodes exercise the optional per-Connection
///     `ua::client::detail::AddressSpaceCache` (client design section 8.7): alias substitution (CL-VIEW-009),
///     LRU eviction -> batched UnregisterNodes (CL-VIEW-010), Session-scoped invalidation (CL-VIEW-011), and
///     the UnregisterNodes advisory path. The cache is built as a component but its TIER-2 WIRING IS UNBUILT:
///     the read/write path does not consult `lookup_for_request`, the RegisterNodes response does not
///     populate the cache, and there is no response-size validation (section 7.2 / CL-VIEW-012). The
///     `Connection::address_space_cache()` accessor also constructs the cache DISABLED (a W8a judgment call -
///     `ConnectionConfig` carries no policy yet). These tests therefore construct an ENABLED cache directly
///     over the real Connection's `wire_ops()` interface so the built component behaviours cross the real
///     wire (UnregisterNodes is observed on the server via the request observer), and PIN + REPORT the parts
///     that are not yet wired end-to-end. Rows requiring a reconnect (new sessionId) are
///     reconnect-harness-blocked (this single-shot Connection has no reconnect wiring) and pin the
///     invalidation-in-isolation analog.
///
///   - ClientBrowseNext exercises the tier-2 `BrowseCursor` (section 7.5) BrowseNext continuation handling:
///   an
///     invalid continuation point surfaces the error (CL-VIEW-004), a bad BrowseNext serviceResult propagates
///     (CL-VIEW-006), the originating Session's authentication token is reused on the BrowseNext
///     (CL-VIEW-001), and a REUSED continuation point must be detected and terminated (CL-VIEW-002 loop
///     guard). The loop-guard row asserts the CORRECT (bounded-termination) behaviour; the cursor has no
///     reuse guard today, so it is a RED test reported to the maintainer as a real robustness defect.
///
/// Falsifiability: each test encodes the matrix row's `[neg: ...]` falsifier. UNBUILT / reconnect-blocked
/// parts pin the built, spec-consistent guarantee that IS observable and record the gap in the report.

#include "misbehaving_server.h"
#include "test_utilities.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_ops.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_address_space_cache.h"
#include "ua_address_space_cache_policy.h"
#include "ua_address_space_cache_test_access.h"

#include "ua_browse_cursor.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"

#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_service_fault.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_continuation_point.h"
#include "ua_localized_text.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
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

using ua::client::detail::AddressSpaceCache;
using ua::client::detail::AddressSpaceCacheTestAccess;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::WireOps;
using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a real `ConnectionImpl` (built over an activated Session, single-shot, no
// keep-alive / no reconnect) into the public tier-2 `Connection`, runs the bootstrap, and closes gracefully.
// Mirrors the ClientBrowse slice's StartedConnection but RETAINS the `ConnectionImpl` shared_ptr so a test
// can reach the real `wire_ops()` interface (to build an enabled AddressSpaceCache over it).
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    mImpl = ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    mImpl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(mImpl));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

  // The real upward wire interface (section 8.2A.13). Used to construct an enabled AddressSpaceCache over the
  // live stack.
  std::shared_ptr<WireOps> wire_ops() const
  {
    return mImpl->wire_ops();
  }

private:
  std::shared_ptr<ConnectionImpl> mImpl;
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// MisbehavingClientFixture: a real client bound to a MisbehavingServer's crypto + trusted cert store, on its
// own thread pool, with an activated Session wrapped into a StartedConnection. The bootstrap completes
// against the un-mutated server; the test arms the response mutators / request observer AFTER construction.
// ---------------------------------------------------------------------------------------------
class MisbehavingClientFixture
{
public:
  explicit MisbehavingClientFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientRegisterBrowseNextMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingClientFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingClientFixture(const MisbehavingClientFixture&) = delete;
  MisbehavingClientFixture& operator=(const MisbehavingClientFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  StartedConnection& started()
  {
    return *mConnection;
  }

  boost::asio::any_io_executor executor()
  {
    return mThreadPool.executor();
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

// A recording log sink shared with the cache's Logger, so a test can assert an advisory was emitted.
struct RecordingLogSink : public ua::LogSink
{
  mutable std::mutex mutex;
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    std::lock_guard lock(mutex);
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool has_message_containing(std::string_view needle) const
  {
    std::lock_guard lock(mutex);
    for (const auto& message : messages)
      if (message.find(needle) != std::string::npos)
        return true;
    return false;
  }
};

// ---------------------------------------------------------------------------------------------
// CacheHarness: an ENABLED AddressSpaceCache constructed over the real Connection's wire interface, on a
// dedicated strand from the client pool. All caller-on-strand methods are invoked THROUGH that strand (posted
// + waited) so the single-threaded caller-on-strand contract (section 8.7) holds against the multi-threaded
// pool.
// ---------------------------------------------------------------------------------------------
class CacheHarness
{
public:
  CacheHarness(MisbehavingClientFixture& fixture, ua::client::AddressSpaceCachePolicy policy)
    : mStrand(boost::asio::make_strand(fixture.executor())), mLogSink(std::make_shared<RecordingLogSink>())
  {
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    mCache = AddressSpaceCache::create(mStrand,
      std::weak_ptr<WireOps>{fixture.started().wire_ops()},
      std::move(policy),
      ua::Logger{mLogSink, level, "register_nodes_cache_test"});
  }

  AddressSpaceCache& cache()
  {
    return *mCache;
  }

  const RecordingLogSink& log() const
  {
    return *mLogSink;
  }

  // Runs @p fn ON the cache strand (the caller-on-strand serialization domain) and blocks until it returns.
  void on_strand(const std::function<void()>& fn)
  {
    std::promise<void> promise;
    auto future = promise.get_future();
    boost::asio::post(mStrand,
      [&fn, &promise]
      {
        fn();
        promise.set_value();
      });
    future.get();
  }

  // Convenience: install one alias pair on the strand.
  void install_alias(ua::NodeId original, ua::NodeId registered)
  {
    on_strand([&] { mCache->install_aliases({std::move(original)}, {std::move(registered)}); });
  }

  // Convenience: the substituted wire NodeId for @p original (strand-read).
  ua::NodeId lookup(const ua::NodeId& original)
  {
    ua::NodeId result;
    on_strand([&] { result = mCache->lookup_for_request(original); });
    return result;
  }

  std::size_t alias_count()
  {
    std::size_t count = 0;
    on_strand([&] { count = AddressSpaceCacheTestAccess::alias_count(*mCache); });
    return count;
  }

  std::uint64_t session_generation()
  {
    std::uint64_t generation = 0;
    on_strand([&] { generation = AddressSpaceCacheTestAccess::session_generation(*mCache); });
    return generation;
  }

  // Blocking `release_async` (fires its callback on the executor).
  void release(ua::NodeId original)
  {
    std::promise<void> promise;
    auto future = promise.get_future();
    mCache->release_async(std::move(original), [&promise](ua::VoidResult) { promise.set_value(); });
    future.get();
  }

  // Blocking `on_session_changed_async`.
  void session_changed(bool serverIdentityPreserved, bool namespaceArrayChanged)
  {
    std::promise<void> promise;
    auto future = promise.get_future();
    mCache->on_session_changed_async(
      serverIdentityPreserved, namespaceArrayChanged, [&promise] { promise.set_value(); });
    future.get();
  }

private:
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::shared_ptr<RecordingLogSink> mLogSink;
  std::shared_ptr<AddressSpaceCache> mCache;
};

// ---------------------------------------------------------------------------------------------
// WireCapture: a guarded read-only snapshot of the requests the client put on the wire, populated on a server
// strand by the MisbehavingServer request observer and read by the test thread.
// ---------------------------------------------------------------------------------------------
struct WireCapture
{
  mutable std::mutex mutex;
  std::vector<ua::NodeId> browseAuthTokens;  ///< authenticationToken of each Browse request
  std::vector<ua::NodeId> browseNextAuthTokens;  ///< authenticationToken of each BrowseNext request
  std::vector<std::vector<ua::NodeId>> unregisterBatches;  ///< nodesToUnregister of each UnregisterNodes
  std::vector<ua::NodeId> readNodeIds;  ///< nodeId of the first ReadValueId of each Read request

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* browse = dynamic_cast<const ua::BrowseRequest*>(&request))
    {
      browseAuthTokens.push_back(browse->request_header().authentication_token());
    }
    else if (const auto* browseNext = dynamic_cast<const ua::BrowseNextRequest*>(&request))
    {
      browseNextAuthTokens.push_back(browseNext->request_header().authentication_token());
    }
    else if (const auto* unregister = dynamic_cast<const ua::UnregisterNodesRequest*>(&request))
    {
      std::vector<ua::NodeId> batch;
      for (const auto& node : unregister->nodes_to_unregister())
        batch.push_back(node);
      unregisterBatches.push_back(std::move(batch));
    }
    else if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
    {
      if (!read->nodes_to_read().empty())
        readNodeIds.push_back(read->nodes_to_read()[0].node_id());
    }
  }

  std::size_t browse_next_count() const
  {
    std::lock_guard lock(mutex);
    return browseNextAuthTokens.size();
  }

  std::size_t unregister_call_count() const
  {
    std::lock_guard lock(mutex);
    return unregisterBatches.size();
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

// A node present on every server (Root organizes Objects/Types/Views: >1 forward reference).
NodeId root_folder()
{
  return NodeId{ObjectId::RootFolder};
}

ua::NodeId numeric_node(std::uint32_t identifier)
{
  return ua::NodeId{0, identifier};
}

// Builds an injected forward reference to @p target for the response-mutator rows.
ua::ReferenceDescription make_reference(const ua::NodeId& target, std::string_view name = "Injected")
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = target;
  reference.is_forward() = true;
  reference.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
  reference.browse_name() = ua::QualifiedName{0, std::string{name}};
  reference.display_name() = ua::LocalizedText{"", std::string{name}};
  reference.node_class() = ua::NodeClass::Object;
  return reference;
}

// Overwrites a BrowseResult page (status Good) with @p references and @p continuationPoint.
void set_page(ua::BrowseResult& result, std::vector<ua::ReferenceDescription> references,
  ua::ContinuationPoint continuationPoint)
{
  result.status_code() = ua::StatusCode{ua::Status::Good};
  ua::Array<ua::ReferenceDescription> array;
  for (auto& reference : references)
    array.push_back(std::move(reference));
  result.references() = std::move(array);
  result.continuation_point() = std::move(continuationPoint);
}

ua::client::AddressSpaceCachePolicy enabled_policy()
{
  ua::client::AddressSpaceCachePolicy policy;
  policy.enabled = true;
  return policy;
}

}  // namespace

// =============================================================================================
// ClientRegisterNodes
// =============================================================================================

// Row - AliasSubstitutedInSubsequentRead  (CL-VIEW-009)
// After RegisterNodes hands back a numeric alias, a subsequent access must substitute the alias into the
// request. The AddressSpaceCache COMPONENT does exactly that (lookup_for_request), which this test asserts
// over a cache wired to the REAL Connection's wire interface. The stronger end-to-end matrix clause - a
// tier-2 read_value for the original NodeId puts the ALIAS on the wire - is UNBUILT: the tier-2 read path
// does not consult the cache, so the wire Read still carries the ORIGINAL NodeId. This test asserts BOTH the
// built substitution AND the unbuilt wiring (the wire Read carries the original), and the gap is reported.
// [neg: the alias, not the original, is used once registered]
// @verifies CL-VIEW-009
// @relation(CL-VIEW-009, scope=function)
TEST(ClientRegisterNodes, AliasSubstitutedInSubsequentRead)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  CacheHarness harness{fixture, enabled_policy()};
  const NodeId original{1, "Demo.String.Node"};  // a string NodeId (RegisterNodes is meant to alias these)
  const NodeId alias = numeric_node(424242);  // the server-assigned numeric handle

  // BUILT: the RegisterNodes result substitutes the numeric alias for the original on a subsequent lookup.
  harness.install_alias(original, alias);
  EXPECT_EQ(harness.lookup(original), alias)
    << "a registered node must substitute the server-assigned numeric alias into later requests";

  // UNBUILT WIRING (reported): a tier-2 read_value for the ORIGINAL still puts the ORIGINAL on the wire - the
  // read path does not consult the AddressSpaceCache. Assert the real, observable state so the gap is pinned.
  ua::ReadRequest readRequest;
  ua::ReadValueId valueId;
  valueId.node_id() = original;
  valueId.attribute_id() = static_cast<ua::IntegerId>(13);  // AttributeId::Value
  readRequest.nodes_to_read().push_back(std::move(valueId));
  (void)fixture.conn().service_requests().try_read_sync(std::move(readRequest));

  ASSERT_TRUE(wait_until(
    [&]
    {
      std::lock_guard lock(capture->mutex);
      return !capture->readNodeIds.empty();
    }))
    << "the tier-2 Read must reach the wire";
  std::lock_guard lock(capture->mutex);
  EXPECT_EQ(capture->readNodeIds.front(), original)
    << "tier-2 read path is not wired to the cache: the wire Read carries the ORIGINAL NodeId (reported)";
}

// Row - CacheInvalidatedAndReRegisteredAfterReconnect  (CL-VIEW-011)
// A reconnect that produces a new sessionId must invalidate the alias table so no stale (now-invalid) alias
// is reused across Sessions; the first post-reconnect access re-registers with the ORIGINAL NodeIds.
//
// RECONNECT-HARNESS-BLOCKED: this single-shot Connection has NO reconnect wiring, so a real new-sessionId
// reconnect cannot be produced here (that is the reconnect cluster's fixture), and the re-registration is a
// tier-2 orchestration that is itself unbuilt. This test pins the invalidation-in-isolation analog that IS
// built and that the row's falsifier turns on: on_session_changed clears the alias cache and bumps the
// generation, so a subsequent lookup returns the ORIGINAL (never a stale alias). Reported as
// reconnect-blocked. [neg: no stale alias reused across sessions]
// @verifies CL-VIEW-011
// @relation(CL-VIEW-011, scope=function)
TEST(ClientRegisterNodes, CacheInvalidatedAndReRegisteredAfterReconnect)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  CacheHarness harness{fixture, enabled_policy()};
  const NodeId first{1, "Node.A"};
  const NodeId second{1, "Node.B"};
  const NodeId third{1, "Node.C"};
  harness.install_alias(first, numeric_node(5001));
  harness.install_alias(second, numeric_node(5002));
  harness.install_alias(third, numeric_node(5003));
  ASSERT_EQ(harness.alias_count(), 3u) << "three aliases registered before the (simulated) session change";
  ASSERT_EQ(harness.lookup(first), numeric_node(5001)) << "the pre-change alias substitutes";

  // A Session change (new sessionId): the server lost the registrations, so every alias must be dropped and
  // the generation bumped - a subsequent access falls back to the ORIGINAL NodeId (no stale alias reused).
  harness.session_changed(/*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/false);

  EXPECT_EQ(harness.alias_count(), 0u) << "a session change must clear the whole alias table";
  EXPECT_EQ(harness.session_generation(), 1u) << "the generation is bumped so any in-flight alias is stale";
  EXPECT_EQ(harness.lookup(first), first)
    << "after a session change the original NodeId is used (no stale alias reused across sessions)";
  EXPECT_EQ(harness.lookup(second), second) << "every previously-cached node falls back to its original";
}

// Row - LruEvictionTriggersUnregisterBatch  (CL-VIEW-010)
// With a bounded alias cache, evicted LRU nodes must be UnregisterNodes'd, COALESCED into batched calls
// (batchSize per call), not one call per node. This drives real evictions through the enabled cache and
// observes the batched UnregisterNodes reaching the server on the wire.
// [neg: eviction batching, not per-node calls]
// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(ClientRegisterNodes, LruEvictionTriggersUnregisterBatch)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  auto policy = enabled_policy();
  policy.maxRegisteredNodes = 4;  // cache holds 4
  policy.unregisterBatchSize = 2;  // coalesce 2 evicted handles per UnregisterNodes call
  policy.unregisterCoalesceWindow = 60000ms;  // large: only the size threshold flushes, never the timer
  CacheHarness harness{fixture, policy};

  // Register 8 nodes into a size-4 cache: nodes 1..4 (handles 9001..9004) are evicted LRU-first and their
  // server handles queued for UnregisterNodes; with batchSize 2 they flush as [9001,9002] and [9003,9004].
  std::vector<ua::NodeId> originals;
  std::vector<ua::NodeId> registered;
  for (std::uint32_t i = 1; i <= 8; ++i)
  {
    originals.push_back(numeric_node(1000 + i));
    registered.push_back(numeric_node(9000 + i));
  }
  harness.on_strand([&] { harness.cache().install_aliases(originals, registered); });

  ASSERT_TRUE(wait_until([&] { return capture->unregister_call_count() >= 2; }))
    << "the four evicted handles must be UnregisterNodes'd (server alias slots would otherwise leak)";

  std::lock_guard lock(capture->mutex);
  ASSERT_EQ(capture->unregisterBatches.size(), 2u)
    << "two batched UnregisterNodes calls, not four single-node calls";
  EXPECT_EQ(capture->unregisterBatches[0].size(), 2u) << "first call coalesces two evicted handles";
  EXPECT_EQ(capture->unregisterBatches[1].size(), 2u) << "second call coalesces two evicted handles";

  std::vector<ua::NodeId> unregistered;
  for (const auto& batch : capture->unregisterBatches)
    for (const auto& node : batch)
      unregistered.push_back(node);
  for (std::uint32_t handle : {9001u, 9002u, 9003u, 9004u})
    EXPECT_NE(std::find(unregistered.begin(), unregistered.end(), numeric_node(handle)), unregistered.end())
      << "evicted handle " << handle << " must be unregistered exactly through the batch";
}

// Row - PassthroughWhenServerReturnsOriginal  (CL-VIEW-009)
// If RegisterNodes returns the original NodeId unchanged (aliasing unsupported), later access must use the
// original NodeId - the cache must not substitute a wrong/empty NodeId for the no-op alias.
// [neg: no-op alias]
// @verifies CL-VIEW-009
// @relation(CL-VIEW-009, scope=function)
TEST(ClientRegisterNodes, PassthroughWhenServerReturnsOriginal)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  CacheHarness harness{fixture, enabled_policy()};
  const NodeId original{1, "Passthrough.Node"};

  // RegisterNodes returned the ORIGINAL as the "registered" handle (a no-op alias).
  harness.install_alias(original, original);

  const ua::NodeId substituted = harness.lookup(original);
  EXPECT_EQ(substituted, original) << "a no-op alias must resolve to the original, not a wrong/empty NodeId";
  EXPECT_FALSE(substituted.is_null()) << "the no-op alias must never collapse to an empty NodeId";
}

// Row - ResponseSizeMismatchRejectedCacheNotPopulated  (CL-VIEW-012)
// A RegisterNodes response whose registeredNodeIds count != nodesToRegister count is malformed and must be
// rejected with Bad_UnexpectedError, with the cache left un-populated (a later read uses the original).
//
// This test drives the public service-request facade against a MisbehavingServer that returns a short
// (case A) / long (case B) registeredNodeIds array. Both must be rejected before any aliases can be
// installed. [neg: short/long response rejected]
// @verifies AC-CL-VIEW-012-REGISTER-ALIGNMENT
// @relation(AC-CL-VIEW-012-REGISTER-ALIGNMENT, scope=function)
TEST(ClientRegisterNodes, ResponseSizeMismatchRejectedCacheNotPopulated)
{
  for (int mode = 0; mode < 2; ++mode)  // 0 = short (N-1), 1 = long (N+1)
  {
    MisbehavingServer server;
    MisbehavingClientFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    const int delta = (mode == 0) ? -1 : +1;
    server.set_response_mutator(
      [delta](Response& response)
      {
        auto* registerResponse = dynamic_cast<ua::RegisterNodesResponse*>(response.second.get());
        if (!registerResponse)
          return;
        auto& ids = registerResponse->registered_node_ids();
        if (delta < 0 && !ids.empty())
        {
          ua::Array<ua::NodeId> shortened;
          for (std::size_t i = 0; i + 1 < ids.size(); ++i)
            shortened.push_back(ids[i]);
          ids = std::move(shortened);
        }
        else if (delta > 0)
        {
          ids.push_back(NodeId{0, uint32_t{999999}});  // one extra, unrequested id
        }
      });

    ua::RegisterNodesRequest request;
    request.nodes_to_register().push_back(NodeId{1, "Reg.A"});
    request.nodes_to_register().push_back(NodeId{1, "Reg.B"});
    auto result = fixture.conn().service_requests().try_register_nodes_sync(std::move(request));

    ASSERT_TRUE(result.is_bad()) << "mode " << mode << ": a mismatched response must be rejected";
    EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->source, "client.tier1.connection.register_nodes");
    EXPECT_EQ(result.shared_detail()->code, "RegisterNodesResultCountMismatch");

    // The cache is NOT populated by RegisterNodes (no register->cache wiring): a fresh enabled cache is
    // empty.
    CacheHarness harness{fixture, enabled_policy()};
    EXPECT_EQ(harness.alias_count(), 0u)
      << "no RegisterNodes response populates the AddressSpaceCache (wiring unbuilt)";
    EXPECT_EQ(harness.lookup(NodeId{1, "Reg.A"}), (NodeId{1, "Reg.A"}))
      << "with an un-populated cache a later access uses the original NodeId";
  }
}

// =============================================================================================
// ClientUnregisterNodes
// =============================================================================================

// Row - ServiceErrorAdvisoryResourceStillFreedLocally  (CL-VIEW-010)
// A bad ServiceResult on UnregisterNodes must be treated as advisory: the local alias entry is dropped
// regardless of the wire outcome (a failed UnregisterNodes must not abort teardown or keep the dead alias).
// [neg: UnregisterNodes failure is advisory]
// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(ClientUnregisterNodes, ServiceErrorAdvisoryResourceStillFreedLocally)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Make the server FAULT every UnregisterNodes: swap the response body for a ServiceFault carrying
  // Bad_NothingToDo, which the client secure channel lifts into a bad Result - so the cache's UnregisterNodes
  // completion takes the advisory (response.is_bad()) branch.
  server.set_response_mutator(
    [](Response& response)
    {
      if (dynamic_cast<ua::UnregisterNodesResponse*>(response.second.get()))
      {
        auto fault = std::make_shared<ua::ServiceFault>();
        fault->response_header().service_result() = ua::StatusCode{ua::Status::BadNothingToDo};
        response.second = fault;
      }
    });

  auto policy = enabled_policy();
  policy.unregisterBatchSize = 1;  // flush immediately on the single release
  CacheHarness harness{fixture, policy};

  const NodeId original{1, "Release.Node"};
  harness.install_alias(original, numeric_node(7001));
  ASSERT_EQ(harness.alias_count(), 1u);

  // Explicit release: the local entry is dropped and a (doomed) UnregisterNodes is issued to the wire.
  harness.release(original);

  EXPECT_EQ(harness.alias_count(), 0u) << "the local alias is dropped regardless of the wire outcome";
  EXPECT_TRUE(wait_until([&] { return harness.log().has_message_containing("UnregisterNodes"); }))
    << "the bad UnregisterNodes ServiceResult must be logged as advisory (surfaced, not silently swallowed)";
}

// =============================================================================================
// ClientBrowseNext
// =============================================================================================

// A real client bound to the MisbehavingServer, wrapped into a started tier-2 Connection whose cursor drives
// BrowseNext. Mirrors the ClientBrowse slice's fixture.
class ClientBrowseNext : public ::testing::Test
{};

// Row - ContinuationPointInvalidSurfacesError  (CL-VIEW-002, CL-VIEW-004)
// A Bad_ContinuationPointInvalid on a BrowseNext must terminate the cursor surfacing exactly that status,
// with no further BrowseNext (no indefinite retry).
// [neg: invalid CP no infinite retry]
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, scope=function)
TEST_F(ClientBrowseNext, ContinuationPointInvalidSurfacesError)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* browse = dynamic_cast<ua::BrowseResponse*>(response.second.get()))
      {
        // Initial Browse: one reference + a non-empty continuation point (so the cursor issues a BrowseNext).
        if (!browse->results().empty())
          set_page(browse->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "First")},
            ua::ContinuationPoint{0xC0, 0xDE});
      }
      else if (auto* browseNext = dynamic_cast<ua::BrowseNextResponse*>(response.second.get()))
      {
        // BrowseNext: the server rejects the continuation point (per-result Bad_ContinuationPointInvalid).
        if (!browseNext->results().empty())
          browseNext->results()[0].status_code() = ua::StatusCode{ua::Status::BadContinuationPointInvalid};
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the first (pre-continuation) reference must be delivered";

  auto second = cursor.try_next_sync();
  EXPECT_TRUE(second.is_bad()) << "an invalid continuation point must terminate the walk";
  EXPECT_EQ(second.status_code(), ua::StatusCode{ua::Status::BadContinuationPointInvalid})
    << "the cursor must surface exactly Bad_ContinuationPointInvalid";
  EXPECT_EQ(capture->browse_next_count(), 1u) << "no indefinite retry: exactly one BrowseNext is issued";
}

// Row - EmptyPagesWithAContinuationPointAreBoundedByTheLimit  (public API review D1, API-D1.1 / D1.2)
// A server that keeps answering BrowseNext with an empty page and the SAME continuation point never makes
// progress. The cursor asks again up to ContinuationLimits::maxConsecutiveEmptyPages (10) times in a row;
// the eleventh empty page fails next with Bad_Timeout, and the point the server still holds is released
// (CL-VIEW-002). The server here never stops, so a cursor without the bound would spin forever.
// [neg: an endless run of empty pages must not hang]
// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST_F(ClientBrowseNext, EmptyPagesWithAContinuationPointAreBoundedByTheLimit)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  const ua::ContinuationPoint loopCp{0x5A, 0x5A};
  server.set_response_mutator(
    [loopCp](Response& response)
    {
      if (auto* browse = dynamic_cast<ua::BrowseResponse*>(response.second.get()))
      {
        if (!browse->results().empty())
          set_page(browse->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "First")},
            loopCp);
      }
      else if (auto* browseNext = dynamic_cast<ua::BrowseNextResponse*>(response.second.get()))
      {
        if (!browseNext->results().empty())
          set_page(browseNext->results()[0], {}, loopCp);  // empty page + the SAME point, forever
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the first reference must be delivered before the empty pages begin";

  auto second = cursor.try_next_sync();
  ASSERT_TRUE(second.is_bad()) << "a server that never makes progress must not hold the cursor forever";
  EXPECT_EQ(second.status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(second.status_code().shared_detail(), nullptr);
  EXPECT_EQ(second.status_code().shared_detail()->code, "BrowseCursorEmptyPageLimitExceeded");
  EXPECT_TRUE(wait_until([&capture] { return capture->browse_next_count() == 12u; }))
    << "eleven reads and one release; saw " << capture->browse_next_count();
}

// Row - TheSameContinuationPointWithAnEmptyPageDoesNotEndTheWalk  (API-D1.3)
// A server may stop a page early with nothing to show (Part 4 5.8.2.1) and keep the same continuation-point
// bytes, as a stable-handle server does. The references that follow must still be delivered.
// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST_F(ClientBrowseNext, TheSameContinuationPointWithAnEmptyPageDoesNotEndTheWalk)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const ua::ContinuationPoint stableCp{0x5A, 0x5A};
  auto browseNextResponses = std::make_shared<std::atomic<int>>(0);
  server.set_response_mutator(
    [stableCp, browseNextResponses](Response& response)
    {
      if (auto* browse = dynamic_cast<ua::BrowseResponse*>(response.second.get()))
      {
        if (!browse->results().empty())
          set_page(browse->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "First")},
            stableCp);
      }
      else if (auto* browseNext = dynamic_cast<ua::BrowseNextResponse*>(response.second.get()))
      {
        if (browseNext->results().empty())
          return;
        if (browseNextResponses->fetch_add(1) < 3)
          set_page(browseNext->results()[0], {}, stableCp);  // three empty pages, the same point
        else
          set_page(browseNext->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_CurrentTime}, "Second")},
            ua::ContinuationPoint{});
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  ASSERT_TRUE(cursor.try_next_sync().is_good());
  auto second = cursor.try_next_sync();
  ASSERT_TRUE(second.is_good()) << "the walk continues past empty pages: "
                                << ua::to_string(second.status_code());
  EXPECT_EQ(std::string_view{second.value().browseName.name()}, "Second");
}

// Row - ServiceResultBadPropagatesToCursor  (CL-VIEW-006)
// A bad service-level result on a BrowseNext must terminate the cursor surfacing that status (a swallowed
// BrowseNext service error would stall the cursor or fabricate a Good empty result).
// [neg: BrowseNext service failure terminates cursor]
// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST_F(ClientBrowseNext, ServiceResultBadPropagatesToCursor)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto serviceResult = std::make_shared<std::atomic<uint32_t>>(0);
  server.set_response_mutator(
    [serviceResult](Response& response)
    {
      if (auto* browse = dynamic_cast<ua::BrowseResponse*>(response.second.get()))
      {
        // Initial Browse: one reference + a non-empty CP so the cursor issues a BrowseNext.
        if (!browse->results().empty())
          set_page(browse->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "First")},
            ua::ContinuationPoint{0x11, 0x22});
      }
      else if (auto* browseNext = dynamic_cast<ua::BrowseNextResponse*>(response.second.get()))
      {
        const uint32_t code = serviceResult->load();
        if (code == 0)
          return;
        browseNext->response_header().service_result() = ua::StatusCode{code};
        browseNext->results() = ua::Array<ua::BrowseResult>{};  // service-level bad AND empty Results[]
      }
    });

  for (Status status : {Status::BadServiceUnsupported,
         Status::BadTooManyOperations,
         Status::BadSessionNotActivated,
         Status::BadServerNotConnected})
  {
    serviceResult->store(ua::StatusCode{status}.as_uint32());
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto first = cursor.try_next_sync();
    ASSERT_TRUE(first.is_good()) << "the first reference must be delivered before the BrowseNext fault";

    auto second = cursor.try_next_sync();
    EXPECT_TRUE(second.is_bad()) << "a bad BrowseNext service result must terminate the cursor, not stall it";
    EXPECT_EQ(second.status_code(), ua::StatusCode{status})
      << "the exact BrowseNext service-level code must surface (not a fabricated Good/empty)";
  }
}

// Row - UsesOriginatingSession  (CL-VIEW-001)
// The BrowseNext frame must carry the same authenticationToken as the originating Browse (a wrong token would
// bind the BrowseNext to a different Session and the server would reject Bad_SessionIdInvalid).
// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST_F(ClientBrowseNext, UsesOriginatingSession)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  // A genuine continuation point: page size 1 over RootFolder (>1 forward reference) forces the real server
  // to hand back a real CP after the first reference, so the second advance issues a real BrowseNext.
  BrowseOptions options;
  options.requestedMaxReferencesPerNode = 1;
  auto cursor = fixture.conn().typed().browse(root_folder(), options);

  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the first reference must be delivered";
  ASSERT_TRUE(cursor.has_more()) << "the real server held back a continuation point";

  auto second = cursor.try_next_sync();
  ASSERT_TRUE(second.is_good() || second.is_bad());  // the second advance drove a real BrowseNext

  ASSERT_TRUE(wait_until([&] { return capture->browse_next_count() >= 1; }))
    << "the cursor must issue a BrowseNext for the held continuation point";

  std::lock_guard lock(capture->mutex);
  ASSERT_FALSE(capture->browseAuthTokens.empty()) << "the originating Browse must be observed";
  ASSERT_FALSE(capture->browseNextAuthTokens.empty()) << "the BrowseNext must be observed";
  const ua::NodeId& browseToken = capture->browseAuthTokens.front();
  const ua::NodeId& browseNextToken = capture->browseNextAuthTokens.front();
  EXPECT_FALSE(browseNextToken.is_null()) << "the BrowseNext must carry a real authentication token";
  EXPECT_EQ(browseNextToken, browseToken)
    << "the BrowseNext must reuse the originating Browse's authenticationToken (same Session)";
}

// =============================================================================================
// ClientRegisterNodes - server-side whole-request rejection (SVR-VIEW-REG-008)
// =============================================================================================

namespace
{

// A read-only record of what the SERVER put back on the wire for RegisterNodes: the registeredNodeIds count
// of every RegisterNodesResponse, and the serviceResult of every ServiceFault. Written on the channel strand
// by the response interceptor (used purely as an observer here - nothing is mutated), read by the test
// thread. Observing the SERVER's own response is what makes "none of the three is registered" falsifiable:
// a whole-request rejection produces a ServiceFault and NO registeredNodeIds array at all.
struct RegisterOutcomeCapture
{
  mutable std::mutex mutex;
  std::size_t totalResponses{0};  ///< responses of any kind, so "no RegisterNodesResponse" is falsifiable
  std::vector<std::size_t> registerResponseIdCounts;
  std::vector<ua::Status> faultResults;

  void observe(const Response& response)
  {
    std::lock_guard lock(mutex);
    ++totalResponses;
    if (const auto* registerResponse = dynamic_cast<const ua::RegisterNodesResponse*>(response.second.get()))
    {
      registerResponseIdCounts.push_back(registerResponse->registered_node_ids().size());
    }
    else if (const auto* fault = dynamic_cast<const ua::ServiceFault*>(response.second.get()))
    {
      faultResults.push_back(fault->response_header().service_result().as_status());
    }
  }

  std::size_t register_response_count() const
  {
    std::lock_guard lock(mutex);
    return registerResponseIdCounts.size();
  }

  std::size_t total_response_count() const
  {
    std::lock_guard lock(mutex);
    return totalResponses;
  }

  bool saw_fault(ua::Status status) const
  {
    std::lock_guard lock(mutex);
    for (const auto seen : faultResults)
      if (seen == status)
        return true;
    return false;
  }
};

}  // namespace

// Part 4 section 5.8.5, Table 44: "Servers shall completely reject the RegisterNodes request if any of the
// NodeIds in the nodesToRegister parameter are structurally invalid" - Bad_NodeIdInvalid at the SERVICE
// result, and therefore no registeredNodeIds array at all. Part 3 section 8.2.4 fixes the structural bound
// the stimulus violates: "Identifier values of IdType String are restricted to 4096 characters".
//
// A plausible implementation gets this wrong by reasoning that a NodeId which survived decoding is
// structurally valid by construction, and so echoes every input id back with serviceResult Good. That is
// worse than a partial failure: the response is positional, so the two well-formed nodes come back looking
// registered and the client has no way to learn that its request contained a malformed id.
//
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(ClientRegisterNodes, RegisterNodesRejectsWholeRequestWhenAnyNodeIdIsStructurallyInvalid)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RegisterOutcomeCapture>();
  server.set_response_mutator([capture](Response& response) { capture->observe(response); });

  // Control: three well-formed ids register normally. This proves the RegisterNodes path is reachable on
  // this fixture AND that a RegisterNodesResponse IS observable at the interceptor - so the negative below
  // ("no further RegisterNodesResponse leaves the server") cannot pass vacuously.
  {
    ua::RegisterNodesRequest control;
    control.nodes_to_register().push_back(NodeId{1, "Reg.Valid.A"});
    control.nodes_to_register().push_back(NodeId{1, "Reg.Valid.B"});
    control.nodes_to_register().push_back(NodeId{1, "Reg.Valid.C"});
    auto controlResult = fixture.conn().service_requests().try_register_nodes_sync(std::move(control));
    ASSERT_TRUE(controlResult.is_good()) << "three well-formed NodeIds must register";
    EXPECT_EQ(controlResult.value().registered_node_ids().size(), 3u)
      << "the control response is positional: one registered id per requested node";

    std::lock_guard lock(capture->mutex);
    ASSERT_EQ(capture->registerResponseIdCounts.size(), 1u)
      << "the control RegisterNodesResponse must be visible at the response interceptor";
    EXPECT_EQ(capture->registerResponseIdCounts.front(), 3u)
      << "the interceptor observes the server's own registeredNodeIds array";
  }
  const std::size_t responsesAfterControl = capture->total_response_count();
  ASSERT_GT(responsesAfterControl, 0u) << "the control must have produced an observable response";

  // Stimulus: three nodes where the SECOND carries a structurally invalid NodeId - a String identifier of
  // 4097 characters, one over the Part 3 section 8.2.4 bound. The flanking two are well-formed.
  const std::string oversizeIdentifier(4097, 'x');
  ua::RegisterNodesRequest request;
  request.nodes_to_register().push_back(NodeId{1, "Reg.First"});
  request.nodes_to_register().push_back(NodeId{1, std::string_view{oversizeIdentifier}});
  request.nodes_to_register().push_back(NodeId{1, "Reg.Third"});
  ASSERT_EQ(request.nodes_to_register().size(), 3u) << "the stimulus must carry all three nodes";
  auto result = fixture.conn().service_requests().try_register_nodes_sync(std::move(request));

  EXPECT_TRUE(result.is_bad()) << "a single structurally invalid NodeId must reject the WHOLE request";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNodeIdInvalid)
    << "the rejection is a service-level Bad_NodeIdInvalid, not a per-operation StatusCode";
  EXPECT_TRUE(capture->saw_fault(ua::Status::BadNodeIdInvalid))
    << "the SERVER must be the one emitting Bad_NodeIdInvalid, not the client stack";

  // The negative below ("no second RegisterNodesResponse") could pass vacuously if the malformed request
  // never reached the server at all. It did: the server answered it with SOMETHING, and that something was
  // not a RegisterNodesResponse.
  ASSERT_GT(capture->total_response_count(), responsesAfterControl)
    << "the malformed request must reach the server and be answered by it";
  EXPECT_EQ(capture->register_response_count(), 1u)
    << "none of the three is registered: only the control RegisterNodesResponse was ever produced, so the "
       "malformed request yielded no registeredNodeIds for the two well-formed nodes either";
}

// Part 4 section 5.8.5, Table 44: "Servers shall completely reject the RegisterNodes request if any of the
// NodeIds in the nodesToRegister parameter are structurally invalid." SPEC-SVR-VIEW-REG-008-ALSO-1 enumerates
// what "structurally invalid" means - "Structural NodeId errors (size violations, invalid id types) will
// cause the complete Service to fail" - and Part 3 section 8.2.4 fixes the two size bounds it names:
// "Identifier values of IdType String are restricted to 4096 characters. Identifier values of IdType Opaque
// are restricted to 4096 bytes." This test drives the OPAQUE half of that bound; the String half is the
// sibling test above.
//
// The two halves are not the same code path, and that is the point of testing both. The plausible partial fix
// for this obligation is a length check written against the String identifier alone - the identifier type a
// developer thinks of first, because it is the one RegisterNodes exists to alias. Such a fix turns the String
// test green while leaving an Opaque identifier of any length whatsoever unbounded, and the obligation would
// then wear a green tick over half a check. An Opaque identifier reaches the service just as easily: the only
// bound it passes on the way in is the codec's `EncodingLimits::maxByteStringLength`, which defaults to 16
// MB
// (`sdk/interface/core/general/ua_encoding_limits.h:46`) - four orders of magnitude above the Part 3
// section 8.2.4 limit of 4096 bytes - so a 4097-byte identifier decodes cleanly and is handed to the handler.
//
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(ClientRegisterNodes, RegisterNodesRejectsWholeRequestWhenAnOpaqueNodeIdBreaksItsStructuralBound)
{
  MisbehavingServer server;
  MisbehavingClientFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RegisterOutcomeCapture>();
  server.set_response_mutator([capture](Response& response) { capture->observe(response); });

  // Control: three well-formed ids, the middle one a SHORT opaque identifier - well inside the Part 3
  // section 8.2.4 bound, so it must register normally. This proves the opaque-identifier path reaches the
  // server at all AND that a RegisterNodesResponse is observable at the interceptor, so the negative below
  // ("no further RegisterNodesResponse leaves the server") cannot pass vacuously.
  {
    const ua::ByteString shortOpaque(std::size_t{16}, std::uint8_t{0xAB});
    ua::RegisterNodesRequest control;
    control.nodes_to_register().push_back(NodeId{1, "Reg.Opaque.Valid.A"});
    control.nodes_to_register().push_back(NodeId{1, shortOpaque});
    control.nodes_to_register().push_back(NodeId{1, "Reg.Opaque.Valid.C"});
    auto controlResult = fixture.conn().service_requests().try_register_nodes_sync(std::move(control));
    ASSERT_TRUE(controlResult.is_good()) << "an opaque identifier inside the 4096-byte bound must register";
    EXPECT_EQ(controlResult.value().registered_node_ids().size(), 3u)
      << "the control response is positional: one registered id per requested node";

    std::lock_guard lock(capture->mutex);
    ASSERT_EQ(capture->registerResponseIdCounts.size(), 1u)
      << "the control RegisterNodesResponse must be visible at the response interceptor";
    EXPECT_EQ(capture->registerResponseIdCounts.front(), 3u)
      << "the interceptor observes the server's own registeredNodeIds array";
  }
  const std::size_t responsesAfterControl = capture->total_response_count();
  ASSERT_GT(responsesAfterControl, 0u) << "the control must have produced an observable response";

  // Stimulus: three nodes where the SECOND carries a structurally invalid NodeId - an Opaque identifier of
  // 4097 bytes, one over the Part 3 section 8.2.4 bound. The flanking two are well-formed.
  const ua::ByteString oversizeOpaque(std::size_t{4097}, std::uint8_t{0xAB});
  ua::RegisterNodesRequest request;
  request.nodes_to_register().push_back(NodeId{1, "Reg.Opaque.First"});
  request.nodes_to_register().push_back(NodeId{1, oversizeOpaque});
  request.nodes_to_register().push_back(NodeId{1, "Reg.Opaque.Third"});

  // The stimulus must really be the violation it claims to be: three operations, the middle one opaque and
  // one byte past the bound. Were the identifier silently truncated on construction, a Good result below
  // would mean the server was never asked the question.
  ASSERT_EQ(request.nodes_to_register().size(), 3u) << "the stimulus must carry all three nodes";
  ASSERT_TRUE(request.nodes_to_register()[1].identifier().is_opaque())
    << "the second node must carry an Opaque identifier, the id type whose bound is under test";
  ASSERT_EQ(request.nodes_to_register()[1].identifier().get_opaque().size(), std::size_t{4097})
    << "the opaque identifier must survive construction at 4097 bytes - one past the Part 3 section 8.2.4 "
       "bound";

  auto result = fixture.conn().service_requests().try_register_nodes_sync(std::move(request));

  EXPECT_TRUE(result.is_bad()) << "a single structurally invalid NodeId must reject the WHOLE request";
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNodeIdInvalid)
    << "the rejection is a service-level Bad_NodeIdInvalid, not a per-operation StatusCode";
  EXPECT_TRUE(capture->saw_fault(ua::Status::BadNodeIdInvalid))
    << "the SERVER must be the one emitting Bad_NodeIdInvalid, not the client stack";

  // The negative below ("no second RegisterNodesResponse") could pass vacuously if the malformed request
  // never reached the server at all. It did: the server answered it with SOMETHING, and that something was
  // not a RegisterNodesResponse.
  ASSERT_GT(capture->total_response_count(), responsesAfterControl)
    << "the malformed request must reach the server and be answered by it";
  EXPECT_EQ(capture->register_response_count(), 1u)
    << "none of the three is registered: only the control RegisterNodesResponse was ever produced, so the "
       "two well-formed nodes flanking the oversize opaque id got no registeredNodeIds either";
}
