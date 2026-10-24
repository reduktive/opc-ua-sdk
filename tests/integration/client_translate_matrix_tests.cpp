// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientTranslate cluster of the client integration-test matrix (the 9 `ClientTranslate.*` rows).
///
/// END-TO-END integration tests of the client TranslateBrowsePathsToNodeIds surface reached through a
/// managed `ua::client::Connection`:
///   - the WIRE-SHAPED tier-1 `Connection::service_requests().translate_browse_paths_*` (section 7.2), which
///     exposes the full `TranslateBrowsePathsToNodeIdsResponse` (every `BrowsePathResult`, every
///     `BrowsePathTarget`, per-path status verbatim), and
///   - the tier-2 sugar `Connection::typed().translate_browse_path_*` (section 7.2A / CL-VIEW-014/015/019),
///     which composes a single `BrowsePath{start, relativePath}` and returns every target of `results[0]` as
///     a `ua::client::TranslatedNodeId` (a fully-resolved local target -> is_local() + is_fully_resolved(); a
///     partial or cross-server target -> a GOOD success-with-partial; a Good status with an empty target set
///     -> Bad_NoMatch; a bad per-path status propagates as the bad Result with its ErrorDetail).
///
/// The Connection is built by wrapping a real `ConnectionImpl` over an activated tier-0 Session (the same
/// construction the committed ClientRead / ClientBrowse / ClientWrite slices use) - single-shot, no
/// keep-alive poll, so no background traffic races the MisbehavingServer interfaces; the bootstrap runs
/// against the un-mutated server (mutators/observers are armed only AFTER `start`).
///
/// BUILT behavior (calibrated to the real surface - grep/code evidence in the authoring report):
///   - BUILT: tier-1 `translate_browse_paths_*` (all results / all targets / independent per-path status);
///     tier-2 `translate_browse_path_*(NodeId start, RelativePath, cb)` which returns every target of
///     `results[0]` as a `ua::client::TranslatedNodeId` per CL-VIEW-014/015/019: a service/transport failure
///     or a bad per-path status propagates as the bad Result (its ErrorDetail preserved); a Good per-path
///     status with an empty target set synthesises `Bad_NoMatch`; a PARTIAL (remainingPathIndex != max) or
///     CROSS-SERVER (serverIndex != 0) target is a GOOD success-with-partial whose
///     `is_fully_resolved()`/`is_local()` are false (the maintainer's OPEN-VIEW-4 policy: partial is DATA,
///     not an error). The SDK never auto-connects to resolve a residual on another server - still exactly
///     ONE translate round-trip (rows 1, 3, 5, 7-tier2, 8, 9).
///   - BUILT: tier-2 rejects a missing final targetName locally with Bad_InvalidArgument and no wire frame
///     (row 1).
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier.
/// `ClientTranslate.ServiceResultBadPropagates` asserts the SPEC-correct service-code propagation at tier-2
/// (RED-first if the facade masks it).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_translated_node_id.h"
#include "ua_typed_access.h"

#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_expanded_node_id.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring ->
// single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and closes
// gracefully on destruction. Copied verbatim from the ClientRead / ClientBrowse slices - the same tier-2
// interface.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
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

private:
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// MisbehavingTranslateFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection. Mirror
// of the ClientRead slice's MisbehavingReadFixture. The bootstrap completes against the un-mutated server;
// the test arms the response mutators / request observer AFTER construction.
// ---------------------------------------------------------------------------------------------
class MisbehavingTranslateFixture
{
public:
  explicit MisbehavingTranslateFixture(MisbehavingServer& server)
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
    auto session = channel.create_session_sync({.sessionName = "ClientTranslateMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingTranslateFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingTranslateFixture(const MisbehavingTranslateFixture&) = delete;
  MisbehavingTranslateFixture& operator=(const MisbehavingTranslateFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
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

// A read-only capture of the TranslateBrowsePaths requests the client put on the wire, populated on a server
// strand by the MisbehavingServer request observer and read by the test thread. Guarded because they run
// concurrently.
struct TranslateRequestCapture
{
  mutable std::mutex mutex;
  std::size_t translateCount = 0;
  std::vector<ua::NodeId> firstStartingNodes;  // first path's starting_node, one per request seen

  void observe(const ua::Structure& request)
  {
    if (const auto* translate = dynamic_cast<const ua::TranslateBrowsePathsToNodeIdsRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      ++translateCount;
      if (!translate->browse_paths().empty())
        firstStartingNodes.push_back(translate->browse_paths()[0].starting_node());
    }
  }

  std::size_t count() const
  {
    std::lock_guard lock(mutex);
    return translateCount;
  }

  std::optional<ua::NodeId> last_starting_node() const
  {
    std::lock_guard lock(mutex);
    if (firstStartingNodes.empty())
      return std::nullopt;
    return firstStartingNodes.back();
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

// Builds a forward, include-subtypes RelativePath following @p refType through each named step: the
// `ua::hierarchical_path` shape with the reference type as a parameter.
ua::RelativePath make_relative_path(std::vector<ua::QualifiedName> steps,
  ua::NodeId refType = ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences})
{
  ua::RelativePath path;
  for (auto& step : steps)
  {
    ua::RelativePathElement element;
    element.reference_type_id() = refType;
    element.is_inverse() = false;
    element.include_subtypes() = true;
    element.target_name() = std::move(step);
    path.elements().push_back(std::move(element));
  }
  return path;
}

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientTranslate`. Derives from `ComplianceWithNodes` so the real-server rows
// (well-formed resolution, duplicate-name multi-target) have a populated address space. The MisbehavingServer
// rows ignore the fixture server and stand up their own adversarial server + client + managed Connection.
// =============================================================================================
class ClientTranslate : public ComplianceWithNodes
{
protected:
  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }
};

// =============================================================================================
// Row 1 - EmptyFinalTargetNameRejectedAtBuilderNoWire  (MisbehavingServer)
// A BrowsePath whose last RelativePath element has an empty targetName is malformed. The matrix expects a
// tier-2 BUILDER to reject it synchronously (Bad_InvalidArgument) with NO wire frame.
// [neg: missing final targetName]
//
// This enters through the highest public production tier (`Connection::typed()`). The server observer is
// wire observation only and proves that local validation prevents dispatch.
// =============================================================================================
// @verifies CL-VIEW-013
// @relation(CL-VIEW-013, scope=function)
TEST_F(ClientTranslate, EmptyFinalTargetNameRejectedAtBuilderNoWire)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<TranslateRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  // A single-element RelativePath whose ONLY (hence final) element has an empty targetName.
  auto relativePath = make_relative_path({ua::QualifiedName{}});
  auto result = fixture.conn().typed().try_translate_browse_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, std::move(relativePath));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "TranslateBrowsePathMissingFinalTargetName");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.typed_access.translate_browse_path");
  EXPECT_EQ(capture->count(), 0u) << "local validation must prevent the TranslateBrowsePaths wire frame";
}

// =============================================================================================
// Row 2 - LocalExpandedNodeIdStartUnwrapsRemoteRejected  (MisbehavingServer)
// The tier-2 `translate_browse_path` ExpandedNodeId-start overload: serverIndex=0 (case A) emits a bare inner
// NodeId on the wire; serverIndex=3 (case B) is rejected synchronously with no frame.
// [neg: non-local start rejected at builder]
//
// This enters through the highest public production tier (`Connection::typed()`); the server request
// observer is wire observation only.
// =============================================================================================
// @verifies CL-VIEW-020
// @relation(CL-VIEW-020, scope=function)
TEST_F(ClientTranslate, LocalExpandedNodeIdStartUnwrapsRemoteRejected)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<TranslateRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  // Case A: a local ExpandedNodeId reaches the wire as its bare starting NodeId.
  const ua::NodeId localStart{ua::ObjectId::ObjectsFolder};
  auto localResult = fixture.conn().typed().try_translate_browse_path_sync(
    ua::ExpandedNodeId{localStart}, make_relative_path({ua::QualifiedName{0, "Server"}}));
  ASSERT_TRUE(localResult.is_good()) << to_string(localResult.status_code());

  ASSERT_TRUE(wait_until([&] { return capture->count() >= 1; }))
    << "the tier-2 translate must emit a TranslateBrowsePaths frame for a local start";
  auto startingNode = capture->last_starting_node();
  ASSERT_TRUE(startingNode.has_value());
  EXPECT_EQ(*startingNode, localStart)
    << "the local start must appear on the wire as the bare BrowsePath.starting_node (unwrapped, local)";

  // Case B: a remote ExpandedNodeId cannot fit the Translate wire request's bare NodeId. It fails locally,
  // preserves the routing information in ErrorDetail context, and emits no second frame.
  const std::size_t callsBeforeRemote = capture->count();
  auto remoteResult = fixture.conn().typed().try_translate_browse_path_sync(
    ua::ExpandedNodeId{localStart, std::uint32_t{3}}, make_relative_path({ua::QualifiedName{0, "Server"}}));
  ASSERT_TRUE(remoteResult.is_bad());
  EXPECT_EQ(remoteResult.status_code().as_status(), ua::Status::BadInvalidArgument);
  ASSERT_NE(remoteResult.shared_detail(), nullptr);
  EXPECT_EQ(
    remoteResult.shared_detail()->summary, "Starting node must be local; connect to remote server first");
  EXPECT_EQ(capture->count(), callsBeforeRemote) << "remote rejection must emit no Translate request";
}

// =============================================================================================
// Row 3 - PartialResolutionRemoteTargetSurfacedNoAutoConnect  (MisbehavingServer)
// A partial resolution whose residual target is on a remote server (remainingPathIndex=1,
// targetId.serverIndex=2) must be surfaced to the user WITHOUT the client auto-connecting to that server.
// [neg: cross-server continuation is user-driven]
//
// BUILT (CL-VIEW-019 / CL-VIEW-015): the facade FLATTENS the partial cross-server target onto a GOOD
// `TranslatedNodeId` (OPEN-VIEW-4 = success-with-partial) - the remote ExpandedNodeId + residual index are
// surfaced verbatim and the SDK never auto-connects (no cross-server continuation logic). This test pins that
// the remote target survives intact (targetId.serverIndex=2, remainingPathIndex=1, so is_local() and
// is_fully_resolved() are both false) and that exactly ONE translate round-trip is made (no second
// connection).
// =============================================================================================
// @verifies CL-VIEW-019
// @verifies CL-VIEW-015
// @relation(CL-VIEW-015, CL-VIEW-019, scope=function)
TEST_F(ClientTranslate, PartialResolutionRemoteTargetSurfacedNoAutoConnect)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<TranslateRequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  const ua::NodeId remoteInner{VariableId::Server_ServerStatus_State};
  server.set_response_mutator(
    [remoteInner](Response& response)
    {
      auto* translate = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
      if (!translate || translate->results().empty())
        return;
      // Overwrite the single result with a partial resolution to a remote server.
      ua::BrowsePathTarget target;
      target.target_id().node_id() = remoteInner;
      target.target_id().server_index() = 2;  // a different (remote) server
      target.remaining_path_index() = 1;  // one element left to resolve on the remote server
      ua::BrowsePathResult partial;
      partial.status_code() = StatusCode{Status::Good};
      partial.targets().push_back(std::move(target));
      translate->results()[0] = std::move(partial);
    });

  auto result = fixture.conn().typed().try_translate_browse_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, make_relative_path({ua::QualifiedName{0, "Server"}}));

  // BUILT: the partial cross-server target is a GOOD success-with-partial recorded on its
  // TranslatedNodeId.
  ASSERT_TRUE(result.is_good()) << "the partial resolution is surfaced, not an error: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u) << "the path names one node";
  EXPECT_FALSE(result.value()[0].is_local()) << "a cross-server target (serverIndex 2) is not a local node";
  EXPECT_EQ(result.value()[0].targetId.server_index(), 2u)
    << "the remote serverIndex must survive so the user can resume translation there";
  EXPECT_FALSE(result.value()[0].is_fully_resolved())
    << "a residual (remainingPathIndex 1) must not be treated as fully resolved";
  EXPECT_EQ(result.value()[0].remainingPathIndex, 1u) << "the residual path index must survive verbatim";
  EXPECT_EQ(result.value()[0].targetId.node_id(), remoteInner);

  // No auto-connect: exactly one translate round-trip reached the server (the SDK does not chase the
  // residual).
  EXPECT_EQ(capture->count(), 1u) << "the SDK must NOT auto-connect to resolve the cross-server residual "
                                     "(exactly one translate round-trip)";
}

// =============================================================================================
// Row 4 - PerPathBadStatusSurfacedIndependently  (MisbehavingServer)
// In a multi-path Translate, each per-path status surfaces at its own index while a Good peer resolves; an
// Uncertain code must NOT be reclassified as Bad. [neg: per-path isolation + Uncertain preserved]
// =============================================================================================
// @verifies CL-VIEW-016
// @relation(CL-VIEW-016, scope=function)
TEST_F(ClientTranslate, PerPathBadStatusSurfacedIndependently)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto injected = std::make_shared<std::atomic<uint32_t>>(0);
  server.set_response_mutator(
    [injected](Response& response)
    {
      auto* translate = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
      if (!translate || translate->results().size() != 2)
        return;
      const uint32_t code = injected->load();
      if (code != 0)
        translate->results()[0].status_code() = StatusCode{code};  // path 0 (index 0) parameterised
      // index 1 keeps the server's real Good result (the untouched peer)
    });

  for (Status status : {Status::BadNodeIdInvalid,
         Status::BadNodeIdUnknown,
         Status::BadNothingToDo,
         Status::BadBrowseNameInvalid,
         Status::BadTooManyMatches,
         Status::BadNoMatch,
         Status::UncertainReferenceOutOfServer})
  {
    injected->store(StatusCode{status}.as_uint32());
    // Two identical, well-formed NS0 paths (ObjectsFolder -> "Server") so the server produces two results.
    auto request = TranslateBrowsePathsBuilder()
                     .path(NodeId{ObjectId::ObjectsFolder})
                     .step(QualifiedName{0, "Server"})
                     .path(NodeId{ObjectId::ObjectsFolder})
                     .step(QualifiedName{0, "Server"})
                     .build();
    auto result = fixture.conn().service_requests().try_translate_browse_paths_sync(std::move(request));
    ASSERT_TRUE(result.is_good()) << "the Translate service itself succeeds; the failure is per-path";
    ASSERT_EQ(result.value().results().size(), 2u);

    EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{status})
      << "the injected per-path code 0x" << std::hex << StatusCode{status}.as_uint32()
      << " must surface at index 0";
    if (status == Status::UncertainReferenceOutOfServer)
      EXPECT_TRUE(result.value().results()[0].status_code().is_uncertain())
        << "Uncertain must NOT be reclassified as Bad";
    EXPECT_TRUE(result.value().results()[1].status_code().is_good())
      << "the untouched Good peer at index 1 must resolve normally (one bad path must not poison the batch)";
  }
}

// =============================================================================================
// Row 5 - RemainingIndexZeroWithTargetsSurfacesAdvisory  (MisbehavingServer)
// remainingPathIndex=0 with a populated local (serverIndex=0) target is a server contradiction (it claims to
// have resolved nothing yet returns a target). The matrix expects tier-2 to surface Bad_NoMatch with a
// diagnostic. [neg: partial resolution without external reference]
//
// BUILT (CL-VIEW-015 / OPEN-VIEW-4): the tier-2 facade FLATTENS results[0].targets[0] onto a
// TranslatedNodeId. remainingPathIndex=0 is a PARTIAL resolution (0 != fullyResolved), so - per the
// maintainer's OPEN-VIEW-4 policy that partial is DATA, not an error - it surfaces as a GOOD
// success-with-partial: is_fully_resolved() is false and remainingPathIndex is surfaced verbatim (0). The
// target is local (serverIndex 0), so is_local() is true and local_node_id() carries the target. The matrix's
// original Bad_NoMatch-with-diagnostic reading is superseded by OPEN-VIEW-4.
// =============================================================================================
// @verifies CL-VIEW-015
// @relation(CL-VIEW-015, scope=function)
TEST_F(ClientTranslate, RemainingIndexZeroWithTargetsSurfacesAdvisory)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const ua::NodeId bogusTarget{VariableId::Server_ServerStatus_State};
  server.set_response_mutator(
    [bogusTarget](Response& response)
    {
      auto* translate = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
      if (!translate || translate->results().empty())
        return;
      ua::BrowsePathTarget target;
      target.target_id().node_id() = bogusTarget;
      target.target_id().server_index() = 0;  // local
      target.remaining_path_index() = 0;  // "resolved nothing" - yet a target is present (contradiction)
      ua::BrowsePathResult contradictory;
      contradictory.status_code() = StatusCode{Status::Good};
      contradictory.targets().push_back(std::move(target));
      translate->results()[0] = std::move(contradictory);
    });

  auto result = fixture.conn().typed().try_translate_browse_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, make_relative_path({ua::QualifiedName{0, "Server"}}));

  // BUILT (OPEN-VIEW-4): remainingPathIndex=0 is a PARTIAL, surfaced as a GOOD success-with-partial.
  ASSERT_TRUE(result.is_good()) << "partial resolution is DATA, not an error (OPEN-VIEW-4): "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u) << "the path names one node";
  EXPECT_FALSE(result.value()[0].is_fully_resolved())
    << "remainingPathIndex 0 (!= fullyResolved) is a partial, not a full resolution";
  EXPECT_EQ(result.value()[0].remainingPathIndex, 0u) << "the residual index is surfaced verbatim";
  EXPECT_TRUE(result.value()[0].is_local()) << "the target's serverIndex is 0, so it is a local node";
  EXPECT_EQ(result.value()[0].local_node_id(), bogusTarget) << "the local target NodeId is passed through";
}

// =============================================================================================
// Row 6 - ServiceResultBadPropagates  (MisbehavingServer)
// A service-level bad ResponseHeader.serviceResult (parameterised) with an empty results[] array must
// propagate the SERVICE status to the caller; the failure must not be swallowed to Good, nor masked into a
// different code that discards the real service status. [neg: service-level failure propagates to all paths]
//
// SPEC-first: this asserts that the tier-2 facade surfaces the EXACT injected service code (mirroring the
// browse-cursor / read-value facades, which flatten a bad serviceResult BEFORE their empty-results contract
// check). If the translate facade instead masks it (e.g. Bad_UnexpectedError from the empty-results branch),
// this row goes RED - the service ErrorDetail is discarded (error_handling.md) - and the authoring report
// flags it as a product defect.
// =============================================================================================
// @verifies CL-VIEW-016
// @relation(CL-VIEW-016, scope=function)
TEST_F(ClientTranslate, ServiceResultBadPropagates)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto serviceResult = std::make_shared<std::atomic<uint32_t>>(0);
  server.set_response_mutator(
    [serviceResult](Response& response)
    {
      auto* translate = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
      if (!translate)
        return;
      const uint32_t code = serviceResult->load();
      if (code == 0)
        return;
      translate->response_header().service_result() = StatusCode{code};
      translate->results() =
        ua::Array<ua::BrowsePathResult>{};  // conformant service fault: no per-path results
    });

  for (Status status : {Status::BadNothingToDo, Status::BadTooManyOperations})
  {
    serviceResult->store(StatusCode{status}.as_uint32());

    // Tier-1 (wire-shaped): the service status surfaces on the response header (results[] empty), never
    // swallowed into a Good-with-targets.
    auto tier1 = fixture.conn().service_requests().try_translate_browse_paths_sync(
      translate_path(NodeId{ObjectId::ObjectsFolder}, QualifiedName{0, "Server"}));
    // CL-DIAG-005: the invoke_wire_op funnel now COLLAPSES a bad ResponseHeader.serviceResult onto the tier-1
    // Result (carrying the wire-crossing marker), so the service fault surfaces as a bad Result rather than a
    // Good Result whose header carries the bad code. The service fault is still not swallowed.
    ASSERT_TRUE(tier1.is_bad()) << "the service fault must not be swallowed to Good";
    EXPECT_EQ(tier1.status_code(), StatusCode{status})
      << "the exact service-level code must surface on the tier-1 Result";

    // Tier-2 (facade): the awaited result must surface the service failure - and the EXACT code, not a mask.
    auto tier2 = fixture.conn().typed().try_translate_browse_path_sync(
      ua::NodeId{ua::ObjectId::ObjectsFolder}, make_relative_path({ua::QualifiedName{0, "Server"}}));
    ASSERT_TRUE(tier2.is_bad()) << "a service fault must not be swallowed to Good by the tier-2 facade";
    EXPECT_EQ(tier2.status_code(), StatusCode{status})
      << "tier-2 must surface the exact service status 0x" << std::hex << StatusCode{status}.as_uint32()
      << ", not mask it (discarding the service ErrorDetail)";
  }
}

// =============================================================================================
// Row 7 - Tier2ReturnsEveryTargetAsTier1Does  (ComplianceWithNodes)
// A single path resolving to MULTIPLE targets: tier-1 exposes ALL targets in order, and so does tier-2.
// [neg: a first-only tier-2 hides the ambiguity]
//
// Public API review item 8c (API-8c.3): Part 4 5.8.4.2 allows several targets, so the tier-2 facade returns
// every one as a `TranslatedNodeId`, in tier-1's order, each a fully-resolved local node. The facade that
// names ONE node, `resolve_path`, refuses the ambiguity
// (ClientBrowse.EveryTargetMatchingTheFinalBrowseName...).
// =============================================================================================
// @verifies CL-VIEW-014
// @relation(CL-VIEW-014, scope=function)
TEST_F(ClientTranslate, Tier2ReturnsEveryTargetAsTier1Does)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("T7")};
  ASSERT_TRUE(connection.start_status().is_good());

  // BrowseChildObj0 has two children sharing the BrowseName "DuplicateTarget" (SVR-VIEW-TBP-002 setup) - one
  // path, multiple targets.
  const QualifiedName duplicateName{mTestNamespaceIndex, "DuplicateTarget"};

  // Tier-1: all targets, in order.
  auto tier1 = connection->service_requests().try_translate_browse_paths_sync(
    translate_path(mDuplicateNameParentId, duplicateName));
  ASSERT_TRUE(tier1.is_good());
  ASSERT_EQ(tier1.value().results().size(), 1u);
  EXPECT_THAT(tier1.value().results()[0], Good());
  const auto& tier1Targets = tier1.value().results()[0].targets();
  ASSERT_GE(tier1Targets.size(), 2u) << "tier-1 must expose every same-BrowseName target";

  // Tier-2: the same targets, in the same order, each a fully-resolved local node.
  auto tier2 = connection->typed().try_translate_browse_path_sync(
    mDuplicateNameParentId, make_relative_path({duplicateName}));
  ASSERT_TRUE(tier2.is_good());
  ASSERT_EQ(tier2.value().size(), tier1Targets.size()) << "tier-2 must not drop any target";
  for (std::size_t index = 0; index < tier1Targets.size(); ++index)
  {
    EXPECT_TRUE(tier2.value()[index].is_fully_resolved())
      << "a same-BrowseName single-hop path resolves fully (remainingPathIndex == max)";
    EXPECT_TRUE(tier2.value()[index].is_local()) << "each duplicate-name target is a local node";
    EXPECT_EQ(tier2.value()[index].local_node_id(), tier1Targets[index].target_id().node_id())
      << "tier-2 keeps tier-1's order (target " << index << ")";
  }
}

// =============================================================================================
// Row 8 - Tier2EmptyTargetsReturnsBadNoMatch  (MisbehavingServer)
// A Good BrowsePathResult status with an empty targets[] array: the matrix expects tier-2 to return
// Bad_NoMatch rather than a bogus empty/default success. [neg: Good + empty targets = NoMatch]
//
// BUILT (CL-VIEW-014): a service-Good response whose single BrowsePathResult has a Good status but an EMPTY
// target set resolves to no node, so the tier-2 facade synthesises a bad `Result{Bad_NoMatch}` (rather than a
// bogus empty/default success). This test pins that flatten (exactly the matrix's target behaviour).
// =============================================================================================
// @verifies CL-VIEW-014
// @relation(CL-VIEW-014, scope=function)
TEST_F(ClientTranslate, Tier2EmptyTargetsReturnsBadNoMatch)
{
  MisbehavingServer server;
  MisbehavingTranslateFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      auto* translate = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
      if (!translate || translate->results().empty())
        return;
      ua::BrowsePathResult goodButEmpty;
      goodButEmpty.status_code() = StatusCode{Status::Good};  // Good status ...
      goodButEmpty.targets() = ua::Array<ua::BrowsePathTarget>{};  // ... but no targets
      translate->results()[0] = std::move(goodButEmpty);
    });

  auto result = fixture.conn().typed().try_translate_browse_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, make_relative_path({ua::QualifiedName{0, "Server"}}));

  // BUILT: a Good status with an empty target set is synthesised into a bad Result{Bad_NoMatch}.
  ASSERT_TRUE(result.is_bad()) << "a Good status with no targets resolves to no node -> Bad_NoMatch: "
                               << to_string(result.status_code());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNoMatch)
    << "an empty target set on a Good per-path status flattens to Bad_NoMatch (CL-VIEW-014)";
}

// =============================================================================================
// Row 9 - WellFormedPathResolvesToTarget  (ComplianceWithNodes)
// A well-formed multi-hop RelativePath fully resolves: the tier-2 facade returns the resolved target NodeId
// and remainingPathIndex == UInt32::max. [functional; catches an inverted remainingPathIndex]
// =============================================================================================
// @verifies CL-VIEW-013
// @verifies CL-VIEW-015
// @relation(CL-VIEW-013, CL-VIEW-015, scope=function)
TEST_F(ClientTranslate, WellFormedPathResolvesToTarget)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("T9")};
  ASSERT_TRUE(connection.start_status().is_good());

  // ObjectsFolder -> "TestFolder" -> "TestMethod" (two hops, fully resolvable via hierarchical references).
  auto relativePath = make_relative_path(
    {QualifiedName{mTestNamespaceIndex, "TestFolder"}, QualifiedName{mTestNamespaceIndex, "TestMethod"}});
  auto result = connection->typed().try_translate_browse_path_sync(
    NodeId{ObjectId::ObjectsFolder}, std::move(relativePath));

  ASSERT_TRUE(result.is_good()) << "a well-formed path must resolve: " << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u) << "the path names one node";
  EXPECT_TRUE(result.value()[0].is_fully_resolved())
    << "a fully-resolved path reports remainingPathIndex == UInt32::max (not treated as partial)";
  EXPECT_TRUE(result.value()[0].is_local()) << "the resolved target is a local node";
  EXPECT_EQ(result.value()[0].local_node_id(), mTestMethodId)
    << "the path must resolve to the expected target NodeId";
  EXPECT_EQ(result.value()[0].remainingPathIndex, ua::client::TranslatedNodeId::fullyResolved)
    << "the remainingPathIndex sentinel marks a fully-resolved path";
}
