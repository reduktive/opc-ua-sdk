// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5g (BrowseService).
//
// These pins lock in externally-observable behaviour of `BrowseService::create`
// across the Browse and BrowseNext flows. They are written against the
// pre-flip coroutine implementation; the post-flip stair-stepped callback
// implementation must keep them green.
//
// Coverage authored here (runbook section 4 IDs in parentheses):
//   A  BrowsePin.SingleNodeYieldsGoodStatusAndReferenceCount
//   B  BrowsePin.EmptyNodesToBrowseYieldsServiceFaultBadNothingToDo
//   C  BrowsePin.TooManyNodesYieldsBadTooManyOperationsServiceFault
//   D  BrowsePin.AuthorizerDeniesPerItemYieldsBadUserAccessDenied
//   E  BrowsePin.NoSecurityContextYieldsBadUserAccessDeniedWithAuthorizationUnavailableDetail
//   F  BrowsePin.NodeIdNotFoundYieldsFindNodeStatusWithDetailPropagated
//   G  BrowsePin.UnknownViewIdYieldsServiceLevelBadViewIdUnknown
//   K  BrowsePin.BrowseNextWithUnknownContinuationPointYieldsBadContinuationPointInvalid
//   L  BrowsePin.BrowseNextWithReleaseFlagSetReturnsEmptyArrays
//   R  BrowsePin.UserCallbackFiresOnceOnHappyPath
//   S  BrowsePin.UserCallbackFiresOnceOnFault
//   X  BrowsePin.ViewVersionAndTimestampMutuallyExclusiveYieldsBadInvalidArgument
//   Y  BrowsePin.NoDelegateNamespaceUsesDefaultPerItemPath
//
// Pins NOT authored here (infrastructure gaps documented in the runbook
// pin-author summary):
//   H  unknown namespace_uri on a Reference target - no fake namespace exists
//      that emits References with a non-empty `namespace_uri()`; the default
//      in-memory namespace produces only index-based ExpandedNodeIds.
//   I  pagination cap creates CP - requires a fake namespace that paginates
//      its `get_references` response and returns a non-empty continuation
//      token. The default in-memory namespace returns all refs in one page.
//   J  pagination cap at exact boundary does NOT create CP - same gap as I.
//   T  concurrent-on-strand kick-off parks all operations at first await -
//      requires a deferred/pending mode on FakeAuthorizer (see helpers/
//      fake_authorizer.h: completion fires synchronously inside
//      authorize_async). Without it we cannot observe N concurrent in-flight
//      authorize calls.
//   V  ServiceFault on timeout - we can drive `set_timeout` but reaching the
//      timeout deterministically without sleep_for requires the same deferred
//      authorizer (so the flow is parked when the timer fires).
//   W  destructor-during-flight - same dependency as T/V (a deferred await
//      point so the flow is mid-flight when the service is destroyed).
//
// Diff-fence: this file is frozen for the
// duration of any 4.5g flip PR. Flip PRs must produce an empty diff against
// tests/behaviour_pins/phase_4_5g_browse/. Amendments require their own PR
// with `behaviour-pin-change-approved: <reason>` in the body.

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "ua_continuation_points.h"
#include "ua_namespace_service_delegates.h"
#include "ua_application_description.h"
#include "ua_create_session_request.h"
#include "ua_security_policy.h"
#include "ua_server_impl.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_service.h"
#include "ua_crypto_types.h"
#include "ua_default_namespace.h"
#include "ua_default_object_node.h"
#include "ua_default_view_node.h"
#include "ua_diagnostic_bits.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_message_security_mode.h"
#include "ua_referencetype_id.h"
#include "ua_register_nodes_service.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_transport_address.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

// Test-only access to SecureChannel / Session interfaces without exposing them publicly. The
// continuation-point capacity pins below observe `Session::browse_response_received`, which is where the
// MaxBrowseContinuationPoints decision is actually taken (BrowseService itself applies no throttle).
#include "ua_server_secure_channel_test_access.h"
#include "ua_server_session_test_access.h"

#include "access_control_test_support.h"
#include "fake_discovery_dependencies.h"
#include "pin_certificate_store.h"
#include "server_impl_test_access.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

// SessionInfoStub subclass that returns a fully-permissive DiagnosticSecurityContext.
// The pins for failure-path ErrorDetail propagation (E/F/G below) require the
// service-internal DiagnosticCollector to honour `add_item_detail` so that per-item
// failures surface as DiagnosticInfo entries the test can read at the SDK boundary.
// The default SessionInfoStub uses MessageSecurityMode::None which trips Gate 1
// (`securedChannel == false`) in DiagnosticCollector and zeroes diagnostic emission.
class PermissiveDiagsSessionInfo : public SessionInfoStub
{
public:
  using SessionInfoStub::SessionInfoStub;

  ua::server::DiagnosticSecurityContext diagnostic_security_context() const override
  {
    ua::server::DiagnosticSecurityContext ctx;
    ctx.authenticated = true;
    ctx.securedChannel = true;
    ctx.effectiveLevel = ua::server::ServerConfig::DiagnosticPolicy::Level::Full;
    ctx.maskPreAuthErrors = false;
    return ctx;
  }
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// Holds a real boost::asio::thread_pool, a Server, and a SessionInfoStub. Per-test code
// creates the namespace(s) it needs, attaches them to the address space, and
// then submits a Browse or BrowseNext request via the public
// `BrowseService::create` factory. The user callback delivers a
// `BrowseServiceResponse`; the test inspects the contained Response.

class BrowsePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = mServerCfg};

    mServer.emplace(ua::server::Server::create(mPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  }

  void TearDown() override
  {
    mSessionInfo.reset();
    mServer.reset();
    // Explicit pool stop before locals reverse-destruct.
    mPool.join();
  }

  // Construct the SessionInfo stub once the test has finished mutating the
  // server configuration (e.g. mMaxNodesPerBrowse). Some pins must override
  // mServerCfg first, then build the stub.
  void build_session_info()
  {
    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(*mServer), mPool.get_executor());
    mServer.reset();
  }

  // Like `build_session_info` but constructs a `PermissiveDiagsSessionInfo` so the
  // service-internal DiagnosticCollector emits per-item diagnostics - required for pins
  // that assert `diagnostic_infos()` content.
  void build_permissive_diags_session_info()
  {
    mSessionInfo = std::make_shared<PermissiveDiagsSessionInfo>(std::move(*mServer), mPool.get_executor());
    mServer.reset();
  }

  boost::asio::thread_pool mPool;
  ua::server::ServerConfig mServerCfg;
  std::optional<ua::server::Server> mServer;
  std::shared_ptr<SessionInfoStub> mSessionInfo;
  std::vector<LocaleId> mLocales{"en"};
};

// Convenience: invoke BrowseService and block on the main test thread for the
// callback to fire. Returns the captured BrowseServiceResponse. Two-second
// budget is generous; pins that need to deterministically detect "did not
// complete" use a tighter explicit budget instead.
BrowseService::BrowseServiceResponse run_browse(std::shared_ptr<SessionInfoStub> sessionInfo,
  std::vector<LocaleId> locales, BrowseRequest request, boost::asio::thread_pool& pool,
  std::shared_ptr<BrowseService>* outService = nullptr)
{
  std::promise<BrowseService::BrowseServiceResponse> promise;
  auto svc = BrowseService::create(sessionInfo,
    std::move(locales),
    /*requestId=*/0,
    std::move(request),
    pool.get_executor(),
    [&promise](BrowseService::BrowseServiceResponse response) { promise.set_value(std::move(response)); });
  if (outService)
    *outService = svc;
  auto fut = promise.get_future();
  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "BrowseService callback did not fire within 2s";
  return fut.get();
}

BrowseService::BrowseServiceResponse run_browse_next(std::shared_ptr<SessionInfoStub> sessionInfo,
  std::vector<LocaleId> locales, BrowseNextRequest request, BrowseContinuationPoints& cpMap,
  boost::asio::thread_pool& pool)
{
  std::promise<BrowseService::BrowseServiceResponse> promise;
  auto svc = BrowseService::create(sessionInfo,
    std::move(locales),
    /*requestId=*/1,
    std::move(request),
    cpMap,
    pool.get_executor(),
    [&promise](BrowseService::BrowseServiceResponse response) { promise.set_value(std::move(response)); });
  (void)svc;
  auto fut = promise.get_future();
  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "BrowseService callback did not fire within 2s";
  return fut.get();
}

}  // namespace

// ===========================================================================
// Pin A - Happy-path Browse on a single node yields Good with one result row.
// ===========================================================================

TEST_F(BrowsePin, SingleNodeYieldsGoodStatusAndReferenceCount)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-a", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  NodeId nodeId{2, 100};
  ns->create_node(nodeId, NodeClass::Object);

  build_session_info();

  BrowseRequest request;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = nodeId;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr) << "expected BrowseResponse, got ServiceFault";
  ASSERT_EQ(browseResponse->results().size(), 1u);
  EXPECT_TRUE(browseResponse->results()[0].status_code().is_good());
}

// ===========================================================================
// Pin B - Empty nodes_to_browse yields a ServiceFault with BadNothingToDo.
// ===========================================================================

TEST_F(BrowsePin, EmptyNodesToBrowseYieldsServiceFaultBadNothingToDo)
{
  build_session_info();

  BrowseRequest request;
  // Empty nodes_to_browse() - explicit zero size.

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* serviceFault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(serviceFault, nullptr) << "expected ServiceFault for empty browse";
  EXPECT_EQ(serviceFault->response_header().service_result(), Status::BadNothingToDo);
}

// ===========================================================================
// Pin C - More nodes than mMaxNodesPerBrowse yields a ServiceFault with
//          BadTooManyOperations.
// ===========================================================================

TEST_F(BrowsePin, TooManyNodesYieldsBadTooManyOperationsServiceFault)
{
  // Configure server so the operation limit is 1; submit 2 nodes.
  mServerCfg.server_capabilities().operationLimits.maxNodesPerBrowse = 1;

  // Recreate server with the configured limit (SetUp constructed it with the
  // default ServerConfig). We re-run a minimal version of SetUp.
  mServer.reset();
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = mServerCfg};
  mServer.emplace(ua::server::Server::create(mPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

  auto ns = default_ns::Namespace::create("uri://browse-pin-c", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  ns->create_node(NodeId{2, 1}, NodeClass::Object);
  ns->create_node(NodeId{2, 2}, NodeClass::Object);

  build_session_info();

  BrowseRequest request;
  request.nodes_to_browse().resize(2);
  request.nodes_to_browse()[0].node_id() = NodeId{2, 1};
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  request.nodes_to_browse()[1].node_id() = NodeId{2, 2};
  request.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* serviceFault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(serviceFault, nullptr) << "expected ServiceFault for over-limit";
  EXPECT_EQ(serviceFault->response_header().service_result(), Status::BadTooManyOperations);
}

// ===========================================================================
// Pin D - Per-item authz denial does NOT fail the whole request - items fail
//          individually with BadUserAccessDenied.
// ===========================================================================

TEST_F(BrowsePin, AuthorizerDeniesPerItemYieldsBadUserAccessDenied)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-d", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  NodeId allowedNode{2, 10};
  NodeId deniedNode{2, 20};
  ns->create_node(allowedNode, NodeClass::Object);
  ns->create_node(deniedNode, NodeClass::Object);

  build_session_info();
  auto denied = mSessionInfo->address_space().find_node_sync(deniedNode);
  ua::test_helpers::set_test_node_permissions(denied, PermissionType{});

  BrowseRequest request;
  request.nodes_to_browse().resize(2);
  request.nodes_to_browse()[0].node_id() = deniedNode;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  request.nodes_to_browse()[1].node_id() = allowedNode;
  request.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr) << "per-item denial must NOT cascade into a service-level fault";
  ASSERT_EQ(browseResponse->results().size(), 2u);
  EXPECT_EQ(browseResponse->results()[0].status_code(), Status::BadUserAccessDenied);
  EXPECT_TRUE(browseResponse->results()[1].status_code().is_good())
    << "an authorised peer node must succeed even when a sibling is denied";
}

// ===========================================================================
// Pin E - Missing authorizer (fail-closed): every item gets BadUserAccessDenied
//          with an "AuthorizationUnavailable" diagnostic when operation-level
//          diagnostics are requested.
// ===========================================================================

// Re-authored 2026-05-03 (MR2.5 R2): assertion of per-item DiagnosticInfo at the SDK
// boundary. The `PermissiveDiagsSessionInfo` subclass enables operation-level diagnostic
// emission so the pre-flip (and post-flip) ErrorDetail propagation produces an observable
// DiagnosticInfo entry carrying the source-code site name "AuthorizationUnavailable".
TEST_F(BrowsePin, NoSecurityContextYieldsBadUserAccessDeniedWithAuthorizationUnavailableDetail)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-e", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  NodeId nodeId{2, 50};
  ns->create_node(nodeId, NodeClass::Object);

  // Subclass that returns a null authorizer AND permits per-item diagnostics: the
  // BrowseService fail-closed path (ua_browse_service.cpp:166-175) must fire with
  // BadUserAccessDenied and emit an "AuthorizationUnavailable" code into the per-item
  // diagnostics.
  class NoAuthSessionInfo : public PermissiveDiagsSessionInfo
  {
  public:
    using PermissiveDiagsSessionInfo::PermissiveDiagsSessionInfo;

    std::shared_ptr<const ua::AccessIdentity> access_identity() const override
    {
      return nullptr;
    }
  };

  auto noAuth = std::make_shared<NoAuthSessionInfo>(std::move(*mServer), mPool.get_executor());
  mServer.reset();

  BrowseRequest request;
  // Request operation-level diagnostics so the AuthorizationUnavailable detail
  // surfaces in the response's per-item diagnosticInfos.
  request.request_header().return_diagnostics() =
    ua::server::diag::operationSymbolicId | ua::server::diag::operationLocalizedText;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = nodeId;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(noAuth, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 1u);
  EXPECT_EQ(browseResponse->results()[0].status_code(), Status::BadUserAccessDenied);

  // Per-item diagnostics must be emitted; the symbolic-id string must be
  // "AuthorizationUnavailable" (from make_error_detail at
  // ua_browse_service.cpp:170).
  ASSERT_EQ(browseResponse->diagnostic_infos().size(), 1u);
  const auto& info = browseResponse->diagnostic_infos()[0];
  ASSERT_TRUE(info.symbolic_id().has_value())
    << "operation-level symbolic id must be present when diagnostics requested";
  const auto& strings = browseResponse->response_header().string_table();
  const int32_t idx = info.symbolic_id().value();
  ASSERT_GE(idx, 0);
  ASSERT_LT(static_cast<size_t>(idx), strings.size());
  EXPECT_EQ(std::string_view{strings[static_cast<size_t>(idx)]}, "AuthorizationUnavailable");

  noAuth.reset();
}

// ===========================================================================
// Pin F - Source find_node failure: result.status_code matches the find_node
//          status, ErrorDetail propagated to the per-item diagnostics.
// ===========================================================================

// Re-authored 2026-05-03 (MR2.5 R2): asserts per-item DiagnosticInfo presence under
// operation-level diagnostics with permissive security-gate context.
TEST_F(BrowsePin, NodeIdNotFoundYieldsFindNodeStatusWithDetailPropagated)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-f", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  // Intentionally do NOT create the node - find_node must fail.

  build_permissive_diags_session_info();

  BrowseRequest request;
  request.request_header().return_diagnostics() =
    ua::server::diag::operationSymbolicId | ua::server::diag::operationLocalizedText;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = NodeId{2, 9999};
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 1u);
  EXPECT_EQ(browseResponse->results()[0].status_code(), Status::BadNodeIdUnknown);

  // The address-space layer attaches an ErrorDetail to the find_node result
  // (ua_address_space.cpp:46). BrowseService propagates it via
  // collector.add_item_detail (ua_browse_service.cpp:207-208). When the client
  // requests operation-level diagnostics, the detail surfaces as a
  // DiagnosticInfo entry - pin asserts presence (content-pin in the
  // string-table form below; pointer-identity is asserted by the
  // implementer's unit test through BrowseServiceTestAccess + the collector,
  // not externally observable here).
  ASSERT_EQ(browseResponse->diagnostic_infos().size(), 1u);
  const auto& info = browseResponse->diagnostic_infos()[0];
  EXPECT_TRUE(info.symbolic_id().has_value() || info.localized_text().has_value())
    << "BadNodeIdUnknown failure must carry an ErrorDetail through the collector";
}

// ===========================================================================
// Pin G - Unknown view id: BadViewIdUnknown with a chained inner detail
//          rooted in the find_node failure.
// ===========================================================================

// The ViewDescription applies to the WHOLE Browse request, so an unknown ViewId is a
// service-level failure (the whole request faults), not a per-operation result row.
// Covers SVR-VIEW-BRW-008 (coverage-audit retag).
TEST_F(BrowsePin, UnknownViewIdYieldsServiceLevelBadViewIdUnknown)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-g", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  NodeId nodeId{2, 60};
  ns->create_node(nodeId, NodeClass::Object);

  build_permissive_diags_session_info();

  BrowseRequest request;
  request.request_header().return_diagnostics() =
    ua::server::diag::operationSymbolicId | ua::server::diag::operationLocalizedText;
  request.view().view_id() = NodeId{2, 88888};  // unknown view id
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = nodeId;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* serviceFault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(serviceFault, nullptr) << "unknown ViewId must fault the whole Browse, not a single result row";
  EXPECT_EQ(serviceFault->response_header().service_result(), Status::BadViewIdUnknown);
}

// ===========================================================================
// Pin K - BrowseNext with a continuation point that is not in the stored map
//          yields BadContinuationPointInvalid for that result row.
// ===========================================================================

TEST_F(BrowsePin, BrowseNextWithUnknownContinuationPointYieldsBadContinuationPointInvalid)
{
  build_session_info();

  // Build a CP map with one stored entry; BrowseNext request asks for a
  // different (random) Guid.
  BrowseContinuationPoints cpMap;
  Guid storedGuid = Guid::create_and_generate();
  // Entry corresponds to a no-longer-relevant browse; we don't drive it back
  // through the flow - only the lookup miss matters for this pin.
  cpMap.emplace(storedGuid, BrowseContinuationPoint{ViewDescription{}, /*maxRefs=*/0, BrowseDescription{}});

  BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().resize(1);
  // Generate an unrelated Guid as bytes - BrowseService::process_browse_next
  // decodes via Guid::from_ua_binary; we feed it a freshly-generated, distinct
  // Guid serialised to UA binary.
  Guid otherGuid = Guid::create_and_generate();
  ASSERT_NE(otherGuid, storedGuid);
  request.continuation_points()[0] = ByteString{otherGuid.as_ua_binary()};

  auto response = run_browse_next(mSessionInfo, mLocales, std::move(request), cpMap, mPool);

  auto* nextResponse =
    dynamic_cast<BrowseNextResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(nextResponse, nullptr);
  ASSERT_EQ(nextResponse->results().size(), 1u);
  EXPECT_EQ(nextResponse->results()[0].status_code(), Status::BadContinuationPointInvalid);
}

// ===========================================================================
// Pin L - Part 4 section 5.8.3.2 requires empty results and diagnosticInfos
//          when release_continuation_points=true, including unknown points.
// ===========================================================================

// @relation(AC-SVR-VIEW-BNX-002-RELEASE-FREES, scope=function)
TEST_F(BrowsePin, BrowseNextWithReleaseFlagSetReturnsEmptyArrays)
{
  build_session_info();

  BrowseContinuationPoints cpMap;  // empty -> the supplied points are unknown

  BrowseNextRequest request;
  request.release_continuation_points() = true;
  request.continuation_points().resize(2);
  Guid g1 = Guid::create_and_generate();
  Guid g2 = Guid::create_and_generate();
  request.continuation_points()[0] = ByteString{g1.as_ua_binary()};
  request.continuation_points()[1] = ByteString{g2.as_ua_binary()};

  auto response = run_browse_next(mSessionInfo, mLocales, std::move(request), cpMap, mPool);

  auto* nextResponse =
    dynamic_cast<BrowseNextResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(nextResponse, nullptr);
  EXPECT_TRUE(nextResponse->response_header().service_result().is_good());
  EXPECT_TRUE(nextResponse->results().empty());
  EXPECT_TRUE(nextResponse->diagnostic_infos().empty());
  EXPECT_TRUE(response.continuationPoints.empty());
}

// ===========================================================================
// Pin R - Happy-path: the user callback fires exactly once.
// ===========================================================================

TEST_F(BrowsePin, UserCallbackFiresOnceOnHappyPath)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-r", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  NodeId nodeId{2, 130};
  ns->create_node(nodeId, NodeClass::Object);

  build_session_info();

  BrowseRequest request;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = nodeId;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  std::atomic<int> callCount{0};
  std::promise<void> done;
  auto svc = BrowseService::create(mSessionInfo,
    mLocales,
    /*requestId=*/0,
    std::move(request),
    mPool.get_executor(),
    [&callCount, &done](BrowseService::BrowseServiceResponse response)
    {
      (void)response;
      if (callCount.fetch_add(1) == 0)
        done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);
  // Give the strand a chance to fire any erroneous duplicate; observe via a
  // strand-posted synchronisation barrier rather than sleep_for.
  std::promise<void> barrier;
  boost::asio::post(mPool.get_executor(), [&barrier]() { barrier.set_value(); });
  ASSERT_EQ(barrier.get_future().wait_for(2s), std::future_status::ready);

  EXPECT_EQ(callCount.load(), 1) << "BrowseService user callback must fire exactly once";
  svc.reset();
}

// ===========================================================================
// Pin S - Fault path: the user callback fires exactly once on a service-level
//          fault (BadNothingToDo).
// ===========================================================================

TEST_F(BrowsePin, UserCallbackFiresOnceOnFault)
{
  build_session_info();

  std::atomic<int> callCount{0};
  std::promise<void> done;

  BrowseRequest request;  // empty nodes_to_browse -> BadNothingToDo

  auto svc = BrowseService::create(mSessionInfo,
    mLocales,
    /*requestId=*/0,
    std::move(request),
    mPool.get_executor(),
    [&callCount, &done](BrowseService::BrowseServiceResponse response)
    {
      (void)response;
      if (callCount.fetch_add(1) == 0)
        done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);
  std::promise<void> barrier;
  boost::asio::post(mPool.get_executor(), [&barrier]() { barrier.set_value(); });
  ASSERT_EQ(barrier.get_future().wait_for(2s), std::future_status::ready);

  EXPECT_EQ(callCount.load(), 1) << "ServiceFault path must fire user callback exactly once";
  svc.reset();
}

// ===========================================================================
// Pin X - view_version != 0 AND view.timestamp() not null - service-level
//          BadInvalidArgument (Part 4 section 7.45 mutual exclusion).
// ===========================================================================

// Covers SVR-VIEW-VWD-001, SVR-VIEW-VWD-002 (coverage-audit retag).
TEST_F(BrowsePin, ViewVersionAndTimestampMutuallyExclusiveYieldsBadInvalidArgument)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-x", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  ns->create_node(NodeId{2, 150}, NodeClass::Object);

  build_session_info();

  BrowseRequest request;
  request.view().view_version() = 1;
  request.view().timestamp() = DateTime::now();
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = NodeId{2, 150};
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* serviceFault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(serviceFault, nullptr) << "view-version+timestamp must yield ServiceFault";
  EXPECT_EQ(serviceFault->response_header().service_result(), Status::BadInvalidArgument);
}

// ===========================================================================
// Pin Y - Namespace with no NamespaceBrowseDelegate uses the default per-item
//          path; no override hook is consulted.
// ===========================================================================

TEST_F(BrowsePin, NoDelegateNamespaceUsesDefaultPerItemPath)
{
  // default_ns::Namespace returns nullptr from browse_delegate() - the
  // BrowseService groups this namespace's items into the default per-item
  // path with no delegate consulted.
  auto ns = default_ns::Namespace::create("uri://browse-pin-y", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  ns->create_node(NodeId{2, 160}, NodeClass::Object);

  build_session_info();

  BrowseRequest request;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = NodeId{2, 160};
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 1u);
  EXPECT_TRUE(browseResponse->results()[0].status_code().is_good());
}

// ===========================================================================
// diagnosticInfos must stay empty when the client asked for no diagnostics,
// and when diagnostics were asked for but processing produced none.
// ===========================================================================

// Part 4 section 5.8.2 (and the Browse service table): `diagnosticInfos` is either empty
// or exactly as long as `results`. The natural mistake is to treat it as one more
// positional array and size it to `results` unconditionally - every other array in
// the response is positional, so `resize(results.size())` reads as symmetry rather
// than as a bug. That costs a DiagnosticInfo slot per operation on requests that
// asked for nothing. Both arms below therefore drive a browse that *does* have
// results, so a padding implementation is caught: the first arm makes an operation
// fail (a diagnostic-relevant event genuinely occurred, only the client did not
// ask for it), the second arm asks for operation-level diagnostics through a
// permissive security gate but gives the service nothing to report.
// @verifies AC-SVR-VIEW-BRW-007-DIAGNOSTICINFOS-EMPTY
TEST_F(BrowsePin, DiagnosticInfosEmptyWhenNotRequestedOrNoneProduced)
{
  // --- Arm 1: returnDiagnostics == 0, and one operation fails ---------------
  auto ns = default_ns::Namespace::create("uri://browse-pin-brw007-a", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);
  NodeId presentNode{2, 180};
  ns->create_node(presentNode, NodeClass::Object);
  // NodeId{2, 9999} is deliberately NOT created - find_node fails and attaches an
  // ErrorDetail, so the collector has an item detail in hand and would emit it if
  // it ignored the mask.

  build_session_info();

  BrowseRequest request;
  request.request_header().return_diagnostics() = 0u;  // client asked for nothing
  request.nodes_to_browse().resize(2);
  request.nodes_to_browse()[0].node_id() = presentNode;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  request.nodes_to_browse()[1].node_id() = NodeId{2, 9999};
  request.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 2u);
  EXPECT_TRUE(browseResponse->results()[0].status_code().is_good());
  ASSERT_EQ(browseResponse->results()[1].status_code(), Status::BadNodeIdUnknown)
    << "arm is only falsifiable if a diagnostic-relevant failure actually occurred";
  EXPECT_EQ(browseResponse->diagnostic_infos().size(), 0u)
    << "diagnosticInfos must stay empty when returnDiagnostics is zero - not padded to results";

  // --- Arm 2: diagnostics requested, but nothing diagnostic-relevant happens -
  mSessionInfo.reset();
  mServer.emplace(ua::server::Server::create(mPool.get_executor(),
    ua::server::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = mServerCfg},
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

  auto ns2 = default_ns::Namespace::create("uri://browse-pin-brw007-b", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns2);
  NodeId okNodeA{2, 181};
  NodeId okNodeB{2, 182};
  ns2->create_node(okNodeA, NodeClass::Object);
  ns2->create_node(okNodeB, NodeClass::Object);

  // PermissiveDiagsSessionInfo opens the DiagnosticCollector security gate, so an
  // empty diagnosticInfos here is the service choosing not to emit rather than the
  // gate suppressing emission.
  build_permissive_diags_session_info();

  BrowseRequest okRequest;
  okRequest.request_header().return_diagnostics() =
    ua::server::diag::operationSymbolicId | ua::server::diag::operationLocalizedText;
  okRequest.nodes_to_browse().resize(2);
  okRequest.nodes_to_browse()[0].node_id() = okNodeA;
  okRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  okRequest.nodes_to_browse()[1].node_id() = okNodeB;
  okRequest.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  auto okResponse = run_browse(mSessionInfo, mLocales, std::move(okRequest), mPool);

  auto* okBrowseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(okResponse.response).get());
  ASSERT_NE(okBrowseResponse, nullptr);
  ASSERT_EQ(okBrowseResponse->results().size(), 2u);
  ASSERT_TRUE(okBrowseResponse->results()[0].status_code().is_good())
    << "arm is only meaningful if both operations succeeded";
  ASSERT_TRUE(okBrowseResponse->results()[1].status_code().is_good())
    << "arm is only meaningful if both operations succeeded";
  EXPECT_EQ(okBrowseResponse->diagnostic_infos().size(), 0u)
    << "diagnosticInfos must stay empty when processing produced no diagnostics, even though "
       "operation-level diagnostics were requested";
}

// ===========================================================================
// FindServers emits only the common service-level StatusCodes.
// ===========================================================================

namespace
{

// OPC 10000-4 (1.05) Table 182 - Common Service Result Codes, transcribed verbatim.
// `Bad_ViewParameterMismatchInvalid` is
// spelled `BadViewParameterMismatch` in the generated Status enum.
constexpr ::ua::Status table182CommonServiceResults[] = {
  ::ua::Status::Good,
  ::ua::Status::GoodCompletesAsynchronously,
  ::ua::Status::GoodSubscriptionTransferred,
  ::ua::Status::BadCertificateHostNameInvalid,
  ::ua::Status::BadCertificateChainIncomplete,
  ::ua::Status::BadCertificateIssuerRevocationUnknown,
  ::ua::Status::BadCertificateIssuerUseNotAllowed,
  ::ua::Status::BadCertificateIssuerTimeInvalid,
  ::ua::Status::BadCertificateIssuerRevoked,
  ::ua::Status::BadCertificateInvalid,
  ::ua::Status::BadCertificateRevocationUnknown,
  ::ua::Status::BadCertificateRevoked,
  ::ua::Status::BadCertificateTimeInvalid,
  ::ua::Status::BadCertificateUriInvalid,
  ::ua::Status::BadCertificateUntrusted,
  ::ua::Status::BadCertificateUseNotAllowed,
  ::ua::Status::BadCommunicationError,
  ::ua::Status::BadDataTypeIdUnknown,
  ::ua::Status::BadDecodingError,
  ::ua::Status::BadEncodingError,
  ::ua::Status::BadEncodingLimitsExceeded,
  ::ua::Status::BadIdentityTokenInvalid,
  ::ua::Status::BadIdentityTokenRejected,
  ::ua::Status::BadInternalError,
  ::ua::Status::BadInvalidArgument,
  ::ua::Status::BadInvalidState,
  ::ua::Status::BadInvalidTimestamp,
  ::ua::Status::BadLicenseExpired,
  ::ua::Status::BadLicenseLimitsExceeded,
  ::ua::Status::BadLicenseNotAvailable,
  ::ua::Status::BadNonceInvalid,
  ::ua::Status::BadNothingToDo,
  ::ua::Status::BadOutOfMemory,
  ::ua::Status::BadRequestCancelledByClient,
  ::ua::Status::BadRequestTooLarge,
  ::ua::Status::BadResponseTooLarge,
  ::ua::Status::BadRequestHeaderInvalid,
  ::ua::Status::BadResourceUnavailable,
  ::ua::Status::BadSecureChannelIdInvalid,
  ::ua::Status::BadSecurityChecksFailed,
  ::ua::Status::BadSecurityPolicyRejected,
  ::ua::Status::BadServerHalted,
  ::ua::Status::BadServerNotConnected,
  ::ua::Status::BadServerUriInvalid,
  ::ua::Status::BadServiceUnsupported,
  ::ua::Status::BadSessionIdInvalid,
  ::ua::Status::BadSessionClosed,
  ::ua::Status::BadSessionNotActivated,
  ::ua::Status::BadShutdown,
  ::ua::Status::BadSubscriptionIdInvalid,
  ::ua::Status::BadTimeout,
  ::ua::Status::BadTimestampsToReturnInvalid,
  ::ua::Status::BadTooManyOperations,
  ::ua::Status::BadUnexpectedError,
  ::ua::Status::BadUnknownResponse,
  ::ua::Status::BadUserAccessDenied,
  ::ua::Status::BadViewIdUnknown,
  ::ua::Status::BadViewTimestampInvalid,
  ::ua::Status::BadViewParameterMismatch,
  ::ua::Status::BadViewVersionInvalid,
};

bool is_table_182_code(const ::ua::StatusCode& code)
{
  for (const auto candidate : table182CommonServiceResults)
  {
    if (code.as_status() == candidate)
    {
      return true;
    }
  }
  return false;
}

// Pull the ResponseHeader serviceResult out of whichever shape came back. FindServers may
// answer with a FindServersResponse or a ServiceFault; both carry a ResponseHeader, and the
// obligation is about the code in that header regardless of the shape carrying it.
bool find_servers_service_result(const ::ua::Response& response, ::ua::StatusCode& outCode)
{
  if (auto* findResponse = dynamic_cast<::ua::FindServersResponse*>(response.second.get()))
  {
    outCode = findResponse->response_header().service_result();
    return true;
  }
  if (auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get()))
  {
    outCode = fault->response_header().service_result();
    return true;
  }
  return false;
}

// None-mode endpoints need no server certificate, so the discovery path emits them even
// though the pin certificate store hands back an empty certificate list.
::ua::server::ServerEndpointConfig make_discovery_pin_endpoint(std::string name)
{
  ::ua::server::ServerEndpointConfig cfg;
  cfg.name = std::move(name);
  cfg.securityPolicyId = ::ua::SecurityPolicyId::None;
  cfg.messageSecurityMode = ::ua::MessageSecurityMode::None;
  cfg.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  return cfg;
}

class FindServersStatusCodePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mCertStore = ::ua::test::behaviour_pins::discovery::PinCertificateStore::create();
    reset_dependencies();
  }

  void TearDown() override
  {
    mService.reset();
    mDeps.reset();
    mCertStore.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Each arm of the pin needs a clean listener set; FakeDiscoveryDependencies::add_listener
  // is additive, so the dependencies are rebuilt rather than mutated between arms.
  void reset_dependencies()
  {
    mService.reset();
    mDeps = std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(mPool->executor());
    mDeps->set_default_application_group_certificate_store(mCertStore);
  }

  void stage_two_listeners()
  {
    mDeps->add_listener(::ua::server::ListenerHandle{1},
      {make_discovery_pin_endpoint("ep1")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});
    mDeps->add_listener(::ua::server::ListenerHandle{2},
      {make_discovery_pin_endpoint("ep2")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4841/"}});
  }

  ::ua::Response run_find_servers(::ua::FindServersRequest&& req)
  {
    std::promise<::ua::Response> p;
    auto fut = p.get_future();
    mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>::create(mDeps,
      ::ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](::ua::Response r) { p.set_value(std::move(r)); });

    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "FindServers callback did not fire within 2s";
      return {};
    }
    return fut.get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<::ua::test::behaviour_pins::discovery::PinCertificateStore> mCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mDeps;
  std::shared_ptr<::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>> mService;
};

}  // namespace

// Part 4 section 5.4.2.3: FindServers defines no service-specific StatusCode table - only the common
// service-level codes of Table 182 may appear in its ResponseHeader. The absence of a code table
// in the spec reads like an oversight, and the tempting repair is to allocate a code for the cases
// where FindServers has nothing to say: an endpointUrl the server cannot parse looks like
// Bad_ServerUriInvalid/Bad_InvalidArgument territory, and a serverUris filter that matches
// nothing looks like Bad_NotFound. Both are wrong. endpointUrl is a routing hint, so an
// unparsable one falls back to the full set; and an empty server list is the correct, successful
// answer to "which of these servers do you know about?" - it is Good, not an error. The four arms
// below drive exactly those cases and check the emitted code against a verbatim transcription of
// Table 182, so a allocated code fails here whatever its spelling.
// @verifies AC-SVR-DISC-SVC-001-STATUSCODES
TEST_F(FindServersStatusCodePin, FindServersEmitsOnlyCommonServiceLevelStatusCodes)
{
  // --- Arm 1: control. Establishes that this fixture really does produce records, so the
  // empty-result arms below are falsifiable rather than vacuously empty. -------------------
  stage_two_listeners();

  ::ua::FindServersRequest controlRequest;
  auto controlResponse = run_find_servers(std::move(controlRequest));

  auto* controlFind = dynamic_cast<::ua::FindServersResponse*>(controlResponse.second.get());
  ASSERT_NE(controlFind, nullptr) << "unfiltered FindServers must answer with a FindServersResponse";
  ASSERT_FALSE(controlFind->servers().payload().empty())
    << "the empty-result arms are only meaningful if the staged fixture otherwise returns records";
  EXPECT_EQ(controlFind->response_header().service_result(), ::ua::Status::Good);
  EXPECT_TRUE(is_table_182_code(controlFind->response_header().service_result()));

  // Capture the server's own applicationUri so the filter arm below can prove its filter value
  // genuinely fails to match rather than coincidentally matching.
  const ::ua::String selfUri = controlFind->servers().payload()[0].application_uri();

  // --- Arm 2: malformed endpointUrl. The hint cannot be parsed; whatever the server answers,
  // the code must come from Table 182 and not from an invented FindServers-specific table. ---
  reset_dependencies();
  stage_two_listeners();

  ::ua::FindServersRequest malformedRequest;
  malformedRequest.endpoint_url() = "::this is not a URL::";
  auto malformedResponse = run_find_servers(std::move(malformedRequest));

  ::ua::StatusCode malformedCode{};
  ASSERT_TRUE(find_servers_service_result(malformedResponse, malformedCode))
    << "a malformed endpointUrl must still produce a response carrying a ResponseHeader";
  EXPECT_TRUE(is_table_182_code(malformedCode))
    << "malformed endpointUrl produced a code outside Part 4 Table 182: "
    << static_cast<uint32_t>(malformedCode.as_status());

  // --- Arm 3: serverUris filter that matches nothing. This is the empty-result case the
  // obligation calls out by name: the list is empty AND the serviceResult is Good. Both
  // conjuncts are asserted - a server that emptied the list but reported an error, or that
  // reported Good while ignoring the filter, fails here. -----------------------------------
  reset_dependencies();
  stage_two_listeners();

  const ::ua::String unmatchedUri{"urn:phase-4-5g-pin:no-such-server:unmatched-filter"};
  ASSERT_NE(std::string_view{unmatchedUri}, std::string_view{selfUri})
    << "the filter value must genuinely fail to match this server";

  ::ua::FindServersRequest filteredRequest;
  filteredRequest.server_uris().payload().push_back(unmatchedUri);
  auto filteredResponse = run_find_servers(std::move(filteredRequest));

  auto* filteredFind = dynamic_cast<::ua::FindServersResponse*>(filteredResponse.second.get());
  ASSERT_NE(filteredFind, nullptr)
    << "an unmatched serverUris filter is an empty result, not a service fault";
  EXPECT_TRUE(filteredFind->servers().payload().empty())
    << "a serverUris filter matching nothing must exclude this server's own description too";
  EXPECT_EQ(filteredFind->response_header().service_result(), ::ua::Status::Good)
    << "the empty-result case is Good - no service-specific code exists to report it";
  EXPECT_TRUE(is_table_182_code(filteredFind->response_header().service_result()));

  // --- Arm 4: no records at all. No listener is staged, so the server has nothing to
  // advertise. An implementation that allocates a code for "nothing to report" fails here. -----
  reset_dependencies();  // deliberately no stage_two_listeners()

  ::ua::FindServersRequest emptyRequest;
  auto emptyResponse = run_find_servers(std::move(emptyRequest));

  ::ua::StatusCode emptyCode{};
  ASSERT_TRUE(find_servers_service_result(emptyResponse, emptyCode))
    << "a server with no listeners must still produce a response carrying a ResponseHeader";
  EXPECT_EQ(emptyCode, ::ua::Status::Good) << "having no records to report is not an error condition";
  EXPECT_TRUE(is_table_182_code(emptyCode)) << "no-records case produced a code outside Part 4 Table 182: "
                                            << static_cast<uint32_t>(emptyCode.as_status());
}

// ===========================================================================
// View membership constrains the browsed node, not just the emitted references.
// ===========================================================================

// Part 4 section 5.8.2: when the request carries a non-null ViewDescription, each nodesToBrowse[i].nodeId
// must be a member of the named View, and a node outside it is rejected on its own operation. The
// plausible implementation applies the View only where the View is visibly a filter - to the
// references it emits - and never to the starting node. That reads as complete (nothing outside the
// View comes back in the result set) but leaves the boundary open at the one place a client can step
// over it by asking: browse the outside node directly and the server answers from the whole address
// space. The arms below give the outside node a reference whose target IS in the View, so a
// fall-back implementation returns Good with that reference rather than an empty, harmless result.
// @verifies AC-SVR-VIEW-BRW-001-NODE-IN-VIEW
TEST_F(BrowsePin, BrowsingANodeOutsideTheNamedViewIsRefused)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-brw001", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  const NodeId viewId{2, 300};
  const NodeId memberNode{2, 301};
  const NodeId outsideNode{2, 302};

  auto view = ns->create_node<default_ns::ViewNode>(viewId);
  ASSERT_NE(view, nullptr);
  ns->create_node(memberNode, NodeClass::Object);
  auto outside = ns->create_node<default_ns::ObjectNode>(outsideNode);
  ASSERT_NE(outside, nullptr);

  // Only memberNode joins the View; outsideNode is deliberately left out of it.
  auto addedToView = std::make_shared<std::promise<VoidResult>>();
  auto addedToViewFuture = addedToView->get_future();
  view->add_node_to_view_async(
    memberNode, [addedToView](VoidResult result) { addedToView->set_value(std::move(result)); });
  ASSERT_EQ(addedToViewFuture.wait_for(std::chrono::seconds{2}), std::future_status::ready);
  ASSERT_TRUE(addedToViewFuture.get().is_good()) << "fixture: the View must genuinely contain memberNode";

  // outsideNode -> memberNode. memberNode IS in the View, so this reference survives the
  // reference-level View filter: an implementation that falls back to the whole address space for
  // the starting node answers Good and hands the client this reference.
  bool addedReference = false;
  outside->add_reference_async(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{memberNode},
    /*isForward=*/true,
    [&addedReference](VoidResult result) { addedReference = result.is_good(); });
  ASSERT_TRUE(addedReference) << "fixture: outsideNode must carry a reference a fall-back would return";

  build_session_info();

  BrowseRequest request;
  request.view().view_id() = viewId;
  request.nodes_to_browse().resize(2);
  request.nodes_to_browse()[0].node_id() = memberNode;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  request.nodes_to_browse()[1].node_id() = outsideNode;
  request.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr)
    << "View membership is a per-operation rejection, not a service-level fault";
  ASSERT_EQ(browseResponse->results().size(), 2u);
  ASSERT_TRUE(browseResponse->results()[0].status_code().is_good())
    << "control: a node inside the named View must still browse successfully, otherwise the "
       "rejection below proves nothing about View membership";
  EXPECT_TRUE(browseResponse->results()[1].status_code().is_bad())
    << "a node outside the named View must be rejected on its own operation";
  EXPECT_TRUE(browseResponse->results()[1].references().empty())
    << "the rejected operation must not also carry references harvested from the whole address space";
}

// ===========================================================================
// Symmetric references are always forward and never answer an Inverse browse.
// ===========================================================================

// Part 4 section 5.8.2: a symmetric ReferenceType has no inverse leg, so every browse result for it carries
// isForward TRUE, and an INVERSE browse must not return it at all. The intuitive reading is the
// wrong one - a symmetric reference "goes both ways", so echoing the stored direction flag and
// letting the ordinary Forward/Inverse filter run over it looks obviously right. It is not: the
// address space records the relationship on both endpoints, and on the far endpoint it is stored as
// the inverse leg. Echoing that flag hides the reference from a Forward browse of the far node,
// surfaces it on an Inverse browse, and reports isForward FALSE on Both - and a client browsing
// Both by issuing Forward then Inverse sees the same reference twice.
// AssociatedWith (NS0 i=24137) is a concrete ReferenceType whose Symmetric attribute is TRUE in the
// standard nodeset the server loads at construction, so the symmetry is the server's own data.
// @verifies AC-SVR-VIEW-BRW-003-SYMMETRIC-ALWAYS-FORWARD
TEST_F(BrowsePin, SymmetricReferenceIsReportedForwardAndOmittedFromInverseBrowse)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-brw003", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  const NodeId nearNode{2, 310};
  const NodeId farNode{2, 311};
  const NodeId symmetricType{ReferenceTypeId::AssociatedWith};

  auto declaringEnd = ns->create_node<default_ns::ObjectNode>(nearNode);
  auto otherEnd = ns->create_node<default_ns::ObjectNode>(farNode);
  ASSERT_NE(declaringEnd, nullptr);
  ASSERT_NE(otherEnd, nullptr);

  // The relationship as an address space records it: the declaring endpoint holds the forward leg,
  // the other endpoint holds the matching inverse leg back to it.
  bool nearLegAdded = false;
  declaringEnd->add_reference_async(symmetricType,
    ExpandedNodeId{farNode},
    /*isForward=*/true,
    [&nearLegAdded](VoidResult result) { nearLegAdded = result.is_good(); });
  ASSERT_TRUE(nearLegAdded);

  bool farLegAdded = false;
  otherEnd->add_reference_async(symmetricType,
    ExpandedNodeId{nearNode},
    /*isForward=*/false,
    [&farLegAdded](VoidResult result) { farLegAdded = result.is_good(); });
  ASSERT_TRUE(farLegAdded);

  build_session_info();

  // Part 4 Table 35 BrowseResultMask bits: ReferenceTypeId (1) | IsForward (2).
  const uint32_t resultMask = 0x03u;

  auto browseFar = [&](BrowseDirection direction)
  {
    BrowseRequest request;
    request.nodes_to_browse().resize(1);
    request.nodes_to_browse()[0].node_id() = farNode;
    request.nodes_to_browse()[0].browse_direction() = direction;
    request.nodes_to_browse()[0].result_mask() = resultMask;
    return run_browse(mSessionInfo, mLocales, std::move(request), mPool);
  };

  // --- Control: the declaring endpoint. Proves the fixture really wired a symmetric reference the
  // browse path can see, so the three arms below are falsifiable rather than empty. -------------
  BrowseRequest controlRequest;
  controlRequest.nodes_to_browse().resize(1);
  controlRequest.nodes_to_browse()[0].node_id() = nearNode;
  controlRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  controlRequest.nodes_to_browse()[0].result_mask() = resultMask;
  auto controlResponse = run_browse(mSessionInfo, mLocales, std::move(controlRequest), mPool);
  auto* controlBrowse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(controlResponse.response).get());
  ASSERT_NE(controlBrowse, nullptr);
  ASSERT_EQ(controlBrowse->results().size(), 1u);
  ASSERT_TRUE(controlBrowse->results()[0].status_code().is_good());
  size_t controlMatches = 0;
  for (const auto& reference : controlBrowse->results()[0].references())
  {
    if (reference.reference_type_id() == symmetricType)
      ++controlMatches;
  }
  ASSERT_EQ(controlMatches, 1u)
    << "control: the declaring endpoint must expose the symmetric reference on a Forward browse";

  // --- Arm 1: Forward browse of the far endpoint must return it, marked forward. ---------------
  auto forwardResponse = browseFar(BrowseDirection::Forward);
  auto* forwardBrowse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(forwardResponse.response).get());
  ASSERT_NE(forwardBrowse, nullptr);
  ASSERT_EQ(forwardBrowse->results().size(), 1u);
  ASSERT_TRUE(forwardBrowse->results()[0].status_code().is_good());
  size_t forwardMatches = 0;
  for (const auto& reference : forwardBrowse->results()[0].references())
  {
    if (reference.reference_type_id() != symmetricType)
      continue;
    ++forwardMatches;
    EXPECT_TRUE(reference.is_forward())
      << "a symmetric reference must be reported with isForward TRUE on a Forward browse";
  }
  EXPECT_EQ(forwardMatches, 1u)
    << "a symmetric reference is forward at both endpoints, so a Forward browse of either must "
       "return it";

  // --- Arm 2: Inverse browse must not return it at all. ----------------------------------------
  auto inverseResponse = browseFar(BrowseDirection::Inverse);
  auto* inverseBrowse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(inverseResponse.response).get());
  ASSERT_NE(inverseBrowse, nullptr);
  ASSERT_EQ(inverseBrowse->results().size(), 1u);
  ASSERT_TRUE(inverseBrowse->results()[0].status_code().is_good());
  size_t inverseMatches = 0;
  for (const auto& reference : inverseBrowse->results()[0].references())
  {
    if (reference.reference_type_id() == symmetricType)
      ++inverseMatches;
  }
  EXPECT_EQ(inverseMatches, 0u) << "a symmetric reference has no inverse leg and must be omitted "
                                   "from an INVERSE browse";

  // --- Arm 3: Both must return it exactly once, marked forward. --------------------------------
  auto bothResponse = browseFar(BrowseDirection::Both);
  auto* bothBrowse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(bothResponse.response).get());
  ASSERT_NE(bothBrowse, nullptr);
  ASSERT_EQ(bothBrowse->results().size(), 1u);
  ASSERT_TRUE(bothBrowse->results()[0].status_code().is_good());
  size_t bothMatches = 0;
  for (const auto& reference : bothBrowse->results()[0].references())
  {
    if (reference.reference_type_id() != symmetricType)
      continue;
    ++bothMatches;
    EXPECT_TRUE(reference.is_forward())
      << "a symmetric reference must be reported with isForward TRUE on a Both browse";
  }
  EXPECT_EQ(bothMatches, 1u) << "Both must return the symmetric reference exactly once";
}

// ===========================================================================
// A ReferenceDescription for a remote target still carries a displayName.
// ===========================================================================

// Part 4 section 7.30: "The displayName shall be provided for remote Nodes." This is the exception to the
// sibling rule that a remote target's metadata is nulled, and that is exactly why it gets missed: an
// implementation that resolves the target node to fill in the ReferenceDescription and simply skips
// the whole metadata block when the target cannot be resolved locally implements "null the metadata
// for remote nodes" correctly, completely, and in violation of this clause. displayName is the one
// field a client has to identify the remote node with before it connects to the other server, so
// losing it turns the reference into a bare NodeId the user cannot be shown.
// @verifies AC-SVR-VIEW-RFD-004-DISPLAYNAME
TEST_F(BrowsePin, RemoteTargetReferenceDescriptionCarriesDisplayName)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-rfd004", mPool.get_executor());
  mServer->address_space().add_namespace_sync(ns);

  const NodeId localNode{2, 320};
  auto local = ns->create_node<default_ns::ObjectNode>(localNode);
  ASSERT_NE(local, nullptr);

  // A target on another server whose index-based namespace can be converted to a URI locally. This
  // exercises the projection branch that must retain serverIndex while changing namespace form.
  const ExpandedNodeId remoteTarget{NodeId{0, 4242}, /*serverIndex=*/1u};
  const LocalizedText remoteDisplayName{"", "Remote component"};
  bool addedReference = false;
  local->add_references_async(std::vector<Reference>{Reference{NodeId{ReferenceTypeId::HasComponent},
                                remoteTarget,
                                /*isForward=*/true,
                                remoteDisplayName}},
    [&addedReference](VoidResult result) { addedReference = result.is_good(); });
  ASSERT_TRUE(addedReference) << "fixture: the local node must carry a reference to a remote target";

  build_session_info();

  BrowseRequest request;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = localNode;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  // Part 4 Table 35 BrowseResultMask: all six bits - the client asks for every optional field, so an
  // absent displayName is the server withholding it rather than the client not requesting it.
  request.nodes_to_browse()[0].result_mask() = 0x3Fu;

  auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);

  auto* browseResponse =
    dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 1u);
  ASSERT_TRUE(browseResponse->results()[0].status_code().is_good())
    << "a reference into another server must not fail the operation";

  const auto& references = browseResponse->results()[0].references();
  ASSERT_FALSE(references.empty()) << "the cross-server reference must be returned to the client";

  size_t remoteSeen = 0;
  for (const auto& reference : references)
  {
    if (reference.node_id().server_index() == 0u)
      continue;
    ++remoteSeen;
    EXPECT_EQ(reference.node_id().server_index(), 1u)
      << "converting an index-based remote target to a namespace URI must retain serverIndex";
    EXPECT_EQ(reference.display_name(), remoteDisplayName)
      << "Browse must preserve the authority-supplied displayName for a remote Node even when the "
         "other optional metadata fields are null";
  }
  ASSERT_EQ(remoteSeen, 1u)
    << "the returned reference must still be marked as living on another server, otherwise the "
       "displayName assertion above is not about a remote Node at all";
}

// ===========================================================================
// BrowseNames are unique within a type definition.
// ===========================================================================

// Part 4 section 5.8.4.1: within one ObjectType or VariableType, no two children may share a BrowseName.
// This is the invariant that makes TranslateBrowsePathsToNodeIds deterministic - it is the service
// that exists because clients address nodes by name rather than by NodeId. Two children of one type
// sharing a BrowseName give a browse path two valid answers and the server returns whichever its
// traversal reaches first, so the same path resolves differently on two servers built from the same
// model and neither is wrong. The failure is silent by construction: nothing rejects the second
// child at load time and every individual Browse still looks correct, so the only way to see it is
// to enumerate the type nodes the server actually holds and compare the names side by side. This
// walks the loaded NS0 type definitions through the real Browse service and does exactly that.
// @verifies AC-SVR-VIEW-TBP-001-BROWSENAME-UNIQUE
TEST_F(BrowsePin, BrowseNamesAreUniqueWithinEachTypeDefinition)
{
  // NS0 is populated at Server construction, so the type definitions inspected below are the
  // server's own standard address space rather than anything this test authored.
  auto ns0 = mServer->address_space().namespace_array().get_namespace(uint16_t{0});
  ASSERT_NE(ns0, nullptr);

  std::promise<Result<std::vector<NodeId>>> enumeratePromise;
  ns0->enumerate_nodes_async(RequestInfo{},
    [&enumeratePromise](Result<std::vector<NodeId>> result)
    { enumeratePromise.set_value(std::move(result)); });
  auto enumerateFuture = enumeratePromise.get_future();
  ASSERT_EQ(enumerateFuture.wait_for(30s), std::future_status::ready);
  auto enumerateResult = enumerateFuture.get();
  ASSERT_TRUE(enumerateResult.is_good()) << "NS0 must be enumerable for this obligation to be checked";
  const std::vector<NodeId> ns0Ids = std::move(enumerateResult).value();
  ASSERT_FALSE(ns0Ids.empty()) << "NS0 was not loaded - there is nothing to check";

  auto addressSpace = mServer->address_space();
  std::vector<NodeId> typeIds;
  for (const auto& nodeId : ns0Ids)
  {
    auto found = addressSpace.try_find_node_sync(nodeId);
    if (!found.is_good())
      continue;
    const auto nodeClass = found.value().get_node_class();
    if ((nodeClass == NodeClass::ObjectType) || (nodeClass == NodeClass::VariableType))
      typeIds.push_back(nodeId);
  }
  ASSERT_GE(typeIds.size(), 100u)
    << "NS0 defines several hundred ObjectTypes and VariableTypes; a short list means the walk "
       "below covers almost nothing";

  build_session_info();

  // Part 4 Table 35 BrowseResultMask bits: ReferenceTypeId (1) | BrowseName (8).
  const uint32_t resultMask = 0x09u;

  size_t childrenSeen = 0;
  std::vector<std::string> duplicates;

  for (const auto& typeId : typeIds)
  {
    BrowseRequest request;
    request.nodes_to_browse().resize(1);
    request.nodes_to_browse()[0].node_id() = typeId;
    request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
    request.nodes_to_browse()[0].result_mask() = resultMask;

    auto response = run_browse(mSessionInfo, mLocales, std::move(request), mPool);
    auto* browseResponse =
      dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
    ASSERT_NE(browseResponse, nullptr) << "browsing an NS0 type definition must not fault the request";
    ASSERT_EQ(browseResponse->results().size(), 1u);
    ASSERT_TRUE(browseResponse->results()[0].status_code().is_good())
      << "browsing NS0 type " << ua::to_string(typeId)
      << " must succeed, status=" << ua::to_string(browseResponse->results()[0].status_code());

    // The InstanceDeclaration children of a type are its aggregated members: HasComponent,
    // HasProperty and HasOrderedComponent. HasSubtype is deliberately excluded - a subtype is not a
    // child of the type in this sense, and its BrowseName is scoped to itself.
    std::vector<QualifiedName> childNames;
    for (const auto& reference : browseResponse->results()[0].references())
    {
      const auto& referenceType = reference.reference_type_id();
      const bool isAggregation = (referenceType == NodeId{ReferenceTypeId::HasComponent}) ||
                                 (referenceType == NodeId{ReferenceTypeId::HasProperty}) ||
                                 (referenceType == NodeId{ReferenceTypeId::HasOrderedComponent});
      if (isAggregation)
        childNames.push_back(reference.browse_name());
    }
    childrenSeen += childNames.size();

    for (size_t i = 0; i < childNames.size(); ++i)
    {
      for (size_t j = i + 1; j < childNames.size(); ++j)
      {
        if ((childNames[i].namespace_index() == childNames[j].namespace_index()) &&
            (std::string_view{childNames[i].name()} == std::string_view{childNames[j].name()}))
        {
          duplicates.push_back(std::string(childNames[i].name()));
        }
      }
    }
  }

  ASSERT_GT(childrenSeen, 0u)
    << "no InstanceDeclaration children were collected at all, so uniqueness was never tested";

  std::string report;
  for (const auto& name : duplicates)
  {
    report += " ";
    report += name;
  }
  EXPECT_TRUE(duplicates.empty())
    << "these BrowseNames appear more than once among the children of a single type definition, "
       "which makes TranslateBrowsePathsToNodeIds non-deterministic for those paths:"
    << report;
}

// ===========================================================================
// TranslateBrowsePathsToNodeIds - the service that consumes what Browse names.
// ===========================================================================

namespace
{

// Same shape as `run_browse`: submit through the public service factory and block the test thread on
// the completion callback. TranslateBrowsePathsService answers with a plain `ua::Response`, so the
// caller dynamic_casts `response.second` to whichever of the two shapes came back.
::ua::Response run_translate_browse_paths(std::shared_ptr<SessionInfoStub> sessionInfo,
  ::ua::TranslateBrowsePathsToNodeIdsRequest request, boost::asio::thread_pool& pool)
{
  std::promise<::ua::Response> promise;
  auto svc = ::ua::server::TranslateBrowsePathsService::create(sessionInfo,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(request),
    pool.get_executor(),
    [&promise](::ua::Response response) { promise.set_value(std::move(response)); });
  (void)svc;
  auto fut = promise.get_future();
  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready)
    << "TranslateBrowsePathsService callback did not fire within 2s";
  return fut.get();
}

}  // namespace

// Part 4 section 5.8.4: a relativePath is a name-matching walk, and outside a type definition a BrowseName
// may legitimately be held by more than one node - AC-SVR-VIEW-TBP-001 forbids the duplicate only among the
// children of a single ObjectType or VariableType. The plausible implementation stops at the first hit,
// because the service reads as a lookup ("resolve this path to the node it names") and every path a
// developer writes by hand has exactly one answer, so taking targets[0] and moving on looks like the whole
// job. A client that asked for a name held twice then gets one NodeId back and nothing to tell it the other
// exists - indistinguishable from a model that only contains one. The path below ends on a BrowseName held
// by two distinct siblings, with a third sibling under a different name: a first-match-wins implementation
// returns one target and a return-every-child implementation returns three.
// @verifies AC-SVR-VIEW-TBP-002-MULTIPLE-TARGETS
TEST_F(BrowsePin, TranslateBrowsePathReturnsEveryTargetMatchingTheFinalBrowseName)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-tbp002", mPool.get_executor());
  const uint16_t nsIndex = mServer->address_space().add_namespace_sync(ns);

  const NodeId parentId{nsIndex, uint32_t{400}};
  const NodeId firstMatchId{nsIndex, uint32_t{401}};
  const NodeId secondMatchId{nsIndex, uint32_t{402}};
  const NodeId otherNameId{nsIndex, uint32_t{403}};

  auto parent = ns->create_node<default_ns::ObjectNode>(parentId);
  ASSERT_NE(parent, nullptr);
  ASSERT_NE(ns->create_node(firstMatchId, NodeClass::Object), nullptr);
  ASSERT_NE(ns->create_node(secondMatchId, NodeClass::Object), nullptr);
  ASSERT_NE(ns->create_node(otherNameId, NodeClass::Object), nullptr);

  auto addressSpace = mServer->address_space();
  const QualifiedName sharedName{nsIndex, "AmbiguousChild"};

  // Two siblings genuinely hold the same BrowseName. This is the server's own stored state, not something
  // the walk is told: the walk has to compare each resolved target's BrowseName itself.
  auto firstAccessor = addressSpace.try_find_node_sync(firstMatchId);
  ASSERT_TRUE(firstAccessor.is_good());
  firstAccessor.value().set_browse_name(sharedName);
  auto secondAccessor = addressSpace.try_find_node_sync(secondMatchId);
  ASSERT_TRUE(secondAccessor.is_good());
  secondAccessor.value().set_browse_name(sharedName);
  // The distractor: same parent, same reference type, different BrowseName. Its absence from the result is
  // what separates "returned every match" from "returned every child".
  auto otherAccessor = addressSpace.try_find_node_sync(otherNameId);
  ASSERT_TRUE(otherAccessor.is_good());
  otherAccessor.value().set_browse_name(QualifiedName{nsIndex, "UnrelatedChild"});

  for (const auto& childId : {firstMatchId, secondMatchId, otherNameId})
  {
    bool added = false;
    parent->add_reference_async(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{childId},
      /*isForward=*/true,
      [&added](VoidResult result) { added = result.is_good(); });
    ASSERT_TRUE(added) << "fixture: the parent must genuinely aggregate all three children";
  }

  build_session_info();

  ::ua::TranslateBrowsePathsToNodeIdsRequest request;
  request.browse_paths().resize(1);
  request.browse_paths()[0].starting_node() = parentId;
  auto& elements = request.browse_paths()[0].relative_path().elements().payload();
  elements.resize(1);
  elements[0].reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  elements[0].include_subtypes() = true;
  elements[0].is_inverse() = false;
  elements[0].target_name() = sharedName;

  auto response = run_translate_browse_paths(mSessionInfo, std::move(request), mPool);

  auto* translateResponse = dynamic_cast<::ua::TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
  ASSERT_NE(translateResponse, nullptr) << "a single well-formed path must not fault the whole request";
  ASSERT_EQ(translateResponse->results().size(), 1u);
  const auto& result = translateResponse->results()[0];
  ASSERT_TRUE(result.status_code().is_good())
    << "a path that matches at least one node resolves; ambiguity is not an error";

  const auto& targets = result.targets();
  ASSERT_FALSE(targets.empty()) << "the path matches two nodes, so an empty target list is not one of the "
                                   "outcomes this obligation admits";

  bool sawFirst = false;
  bool sawSecond = false;
  bool sawUnrelated = false;
  for (size_t i = 0; i < targets.size(); ++i)
  {
    const auto& targetNodeId = targets[i].target_id().node_id();
    if (targetNodeId == firstMatchId)
      sawFirst = true;
    else if (targetNodeId == secondMatchId)
      sawSecond = true;
    else if (targetNodeId == otherNameId)
      sawUnrelated = true;
  }

  EXPECT_TRUE(sawFirst) << "the first holder of the BrowseName must be returned";
  EXPECT_TRUE(sawSecond) << "the second holder of the BrowseName must be returned too - every match is "
                            "returned, not the first one the traversal happens to reach";
  EXPECT_FALSE(sawUnrelated) << "the walk must still filter by BrowseName: a sibling under a different "
                                "name is not a match";
  EXPECT_EQ(targets.size(), 2u) << "exactly the two nodes holding that BrowseName, each once";
}

// Part 4 section 5.8.4: when a relativePath step crosses into another server the local server cannot continue
// the walk, and what it owes the client is the pair that lets the client continue it elsewhere - the external
// Node as the target, and `remainingPathIndex` naming the first element that was not processed. The
// plausible implementation drops one half of that pair. A node the address space cannot resolve locally
// looks like a dead end, so the walk skips the reference and the path ends Bad_NoMatch; or the hop is
// reported but `remainingPathIndex` is left at the "everything was processed" sentinel, which tells the
// client the path is finished at a node on another server. Either way the continuation instruction is
// destroyed, and `AC-CL-VIEW-016-PERPATH-STATUS` has the client silently discard the path. The stimulus
// below is a two-element path whose FIRST step leaves the server, so a correct remainingPathIndex is the
// ordinary value 1 rather than the sentinel - an implementation that always writes the sentinel is caught.
// @verifies AC-SVR-VIEW-TBP-005-EXTERNAL-REFERENCE
TEST_F(BrowsePin, TranslateBrowsePathHaltedAtAnExternalReferenceReturnsTheRemoteNodeAndIndex)
{
  auto ns = default_ns::Namespace::create("uri://browse-pin-tbp005", mPool.get_executor());
  const uint16_t nsIndex = mServer->address_space().add_namespace_sync(ns);

  const NodeId crossingStartId{nsIndex, uint32_t{410}};
  const NodeId localStartId{nsIndex, uint32_t{412}};
  const NodeId localChildId{nsIndex, uint32_t{413}};
  // serverIndex 1 makes the target live on another server, so nothing about it can be resolved here.
  const ExpandedNodeId remoteTarget{NodeId{nsIndex, uint32_t{8000}}, uint32_t{1}};

  auto crossingStart = ns->create_node<default_ns::ObjectNode>(crossingStartId);
  auto localStart = ns->create_node<default_ns::ObjectNode>(localStartId);
  ASSERT_NE(crossingStart, nullptr);
  ASSERT_NE(localStart, nullptr);
  ASSERT_NE(ns->create_node(localChildId, NodeClass::Object), nullptr);

  auto addressSpace = mServer->address_space();
  auto localChildAccessor = addressSpace.try_find_node_sync(localChildId);
  ASSERT_TRUE(localChildAccessor.is_good());
  localChildAccessor.value().set_browse_name(QualifiedName{nsIndex, "LocalChild"});

  bool remoteAdded = false;
  crossingStart->add_reference_async(NodeId{ReferenceTypeId::Organizes},
    remoteTarget,
    /*isForward=*/true,
    [&remoteAdded](VoidResult result) { remoteAdded = result.is_good(); });
  ASSERT_TRUE(remoteAdded) << "fixture: the crossing node must genuinely carry a reference off this server";

  bool localAdded = false;
  localStart->add_reference_async(NodeId{ReferenceTypeId::Organizes},
    ExpandedNodeId{localChildId},
    /*isForward=*/true,
    [&localAdded](VoidResult result) { localAdded = result.is_good(); });
  ASSERT_TRUE(localAdded) << "fixture: the control path needs a reference it can actually follow";

  build_session_info();

  ::ua::TranslateBrowsePathsToNodeIdsRequest request;
  request.browse_paths().resize(2);

  // [0] control - a fully local single-step path. Proves this fixture's walk resolves paths at all, so the
  // Uncertain outcome below is about the cross-server hop rather than about a walk that never ran.
  request.browse_paths()[0].starting_node() = localStartId;
  auto& controlElements = request.browse_paths()[0].relative_path().elements().payload();
  controlElements.resize(1);
  controlElements[0].target_name() = QualifiedName{nsIndex, "LocalChild"};

  // [1] stimulus - two elements, the first of which can only be satisfied by the reference that leaves
  // this server. Element 1 is therefore the first element the server cannot process.
  request.browse_paths()[1].starting_node() = crossingStartId;
  auto& crossingElements = request.browse_paths()[1].relative_path().elements().payload();
  crossingElements.resize(2);
  crossingElements[0].target_name() = QualifiedName{nsIndex, "RemoteChild"};
  crossingElements[1].target_name() = QualifiedName{nsIndex, "DeeperOnTheOtherServer"};

  auto response = run_translate_browse_paths(mSessionInfo, std::move(request), mPool);

  auto* translateResponse = dynamic_cast<::ua::TranslateBrowsePathsToNodeIdsResponse*>(response.second.get());
  ASSERT_NE(translateResponse, nullptr) << "a cross-server hop is a per-path outcome, not a service fault";
  ASSERT_EQ(translateResponse->results().size(), 2u) << "one result per browse path, in request order";

  const auto& controlResult = translateResponse->results()[0];
  ASSERT_TRUE(controlResult.status_code().is_good())
    << "control: a fully local path must resolve, otherwise the arm below proves nothing";
  ASSERT_EQ(controlResult.targets().size(), 1u) << "control: the local path names exactly one node";
  EXPECT_EQ(controlResult.targets()[0].target_id().node_id(), localChildId);
  EXPECT_EQ(controlResult.targets()[0].target_id().server_index(), 0u)
    << "control: the local target lives on this server";

  const auto& crossingResult = translateResponse->results()[1];
  EXPECT_EQ(crossingResult.status_code(), Status::UncertainReferenceOutOfServer)
    << "a path halted at a reference leaving this server is Uncertain_ReferenceOutOfServer";
  EXPECT_TRUE(crossingResult.status_code().is_uncertain())
    << "the Uncertain severity is the substance - a Bad severity reads as failure and the client never "
       "continues at the other server";

  ASSERT_EQ(crossingResult.targets().size(), 1u)
    << "the halted path must still hand back the external Node to continue with";
  const auto& external = crossingResult.targets()[0];
  EXPECT_EQ(external.target_id().node_id(), remoteTarget.node_id())
    << "the returned target is the external Node the reference names";
  EXPECT_EQ(external.target_id().server_index(), 1u)
    << "the returned target must still say which server it lives on, or the client cannot go there";
  EXPECT_EQ(external.remaining_path_index(), uint32_t{1})
    << "remainingPathIndex names the FIRST unprocessed element: element 0 was consumed by the hop, so the "
       "continuation starts at element 1 - not the all-processed sentinel";
}

// ===========================================================================
// UnregisterNodes - the cleanup leg of the RegisterNodes pair.
// ===========================================================================

namespace
{

// A namespace that keeps a real registration table: a `default_ns::Namespace` that also serves as its own
// service delegate. It is the observation
// instrument for the "actually unregistered" half of the obligation - it records what the service hands
// it and what it therefore still holds. It decides nothing the obligation is about: it never rejects an
// id, so a refusal seen at the service boundary can only have come from the service.
class PinRegisterNodesNamespace final : public default_ns::Namespace,
                                        public NamespaceRegisterNodesDelegate,
                                        public std::enable_shared_from_this<PinRegisterNodesNamespace>
{
public:
  PinRegisterNodesNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return std::dynamic_pointer_cast<NamespaceRegisterNodesDelegate>(shared_from_this());
  }

  void register_nodes_async(
    const Context&, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override
  {
    BatchResult<NodeId> batch;
    batch.items.reserve(items.size());
    {
      std::lock_guard<std::mutex> lock(mMutex);
      for (const auto& item : items)
      {
        mRegistered.push_back(item.nodeId);
      }
    }
    for (auto& item : items)
    {
      // No handle optimisation to offer: hand back the id the client supplied.
      batch.items.emplace_back(std::move(item.nodeId));
    }
    callback(std::move(batch));
  }

  void unregister_nodes_async(
    const Context&, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      for (const auto& item : items)
      {
        mUnregisterRequested.push_back(item.nodeId);
        std::vector<NodeId> kept;
        kept.reserve(mRegistered.size());
        for (auto& held : mRegistered)
        {
          if (!(held == item.nodeId))
          {
            kept.push_back(held);
          }
        }
        mRegistered = std::move(kept);
      }
    }
    callback(VoidResult{});
  }

  std::vector<NodeId> registered_snapshot() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mRegistered;
  }

  std::vector<NodeId> unregister_requested_snapshot() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mUnregisterRequested;
  }

private:
  mutable std::mutex mMutex;
  std::vector<NodeId> mRegistered;
  std::vector<NodeId> mUnregisterRequested;
};

bool contains_node_id(const std::vector<NodeId>& ids, const NodeId& wanted)
{
  for (const auto& id : ids)
  {
    if (id == wanted)
    {
      return true;
    }
  }
  return false;
}

// Same shape as `run_browse`: submit through the public service factory and block the test thread on the
// completion callback. RegisterNodesServiceSet answers both legs through one variant, so the caller
// `std::get_if`s whichever of the three shapes came back.
RegisterNodesServiceSet::ResponseOrServiceFault run_register_nodes(
  std::shared_ptr<SessionInfoStub> sessionInfo, RegisterNodesRequest request, boost::asio::thread_pool& pool)
{
  std::promise<RegisterNodesServiceSet::ResponseOrServiceFault> promise;
  auto svc = RegisterNodesServiceSet::create(sessionInfo,
    std::move(request),
    pool.get_executor(),
    [&promise](RegisterNodesServiceSet::ResponseOrServiceFault response)
    { promise.set_value(std::move(response)); });
  (void)svc;
  auto fut = promise.get_future();
  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "RegisterNodes callback did not fire within 2s";
  return fut.get();
}

RegisterNodesServiceSet::ResponseOrServiceFault run_unregister_nodes(
  std::shared_ptr<SessionInfoStub> sessionInfo, UnregisterNodesRequest request,
  boost::asio::thread_pool& pool)
{
  std::promise<RegisterNodesServiceSet::ResponseOrServiceFault> promise;
  auto svc = RegisterNodesServiceSet::create(sessionInfo,
    std::move(request),
    pool.get_executor(),
    [&promise](RegisterNodesServiceSet::ResponseOrServiceFault response)
    { promise.set_value(std::move(response)); });
  (void)svc;
  auto fut = promise.get_future();
  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "UnregisterNodes callback did not fire within 2s";
  return fut.get();
}

}  // namespace

// Part 4 section 5.8.6: "UnregisterNodes does not validate the NodeIds from the request. Servers shall simply
// unregister NodeIds that are known as registered NodeIds. Any NodeIds that are in the list, but are not
// registered NodeIds are simply ignored." This is the opposite disposition to RegisterNodes, and that is
// exactly why it gets implemented wrong: the two services take the same request shape and sit next to
// each other in the same handler, so the id-validation the register leg does gets factored out and shared,
// and unregister inherits a rejection it must not have. It also reads as defensive - telling a client that
// an id it asked to release was never held looks like helpful diagnostics. It is not: unregistering is
// teardown, run when the client no longer knows precisely what it still holds, so an error there fails the
// tidy-up path on exactly the ids it no longer needs. The two arms below split the obligation's conjuncts.
// Arm 1 uses a namespace with no register-nodes delegate, so every decision in it is the server's own and
// no test-owned object can supply the Good; arm 2 adds a namespace that keeps a real registration table so
// the "the registered ones are unregistered" half is observable at all.
// @verifies AC-SVR-VIEW-URG-001-UNREGISTER-IGNORES-UNKNOWN
TEST_F(BrowsePin, UnregisterNodesReleasesKnownRegistrationsAndIgnoresIdsThatWereNeverRegistered)
{
  auto plainNs = default_ns::Namespace::create("uri://browse-pin-urg001-plain", mPool.get_executor());
  const uint16_t plainIndex = mServer->address_space().add_namespace_sync(plainNs);

  auto delegateNs =
    std::make_shared<PinRegisterNodesNamespace>("uri://browse-pin-urg001-delegate", mPool.get_executor());
  const uint16_t delegateIndex = mServer->address_space().add_namespace_sync(delegateNs);

  const NodeId registeredId{plainIndex, uint32_t{500}};
  const NodeId existingButUnregisteredId{plainIndex, uint32_t{501}};
  const NodeId neverCreatedId{plainIndex, uint32_t{502}};
  // Namespace index 55 is not in the namespace array at all - the least resolvable id a client can send,
  // and the one an implementation that resolves before releasing is most likely to reject.
  const NodeId foreignNamespaceId{uint16_t{55}, uint32_t{503}};
  ASSERT_EQ(mServer->address_space().namespace_array().get_namespace(uint16_t{55}), nullptr)
    << "fixture: namespace index 55 must genuinely be unknown to this server";

  ASSERT_NE(plainNs->create_node(registeredId, NodeClass::Object), nullptr);
  ASSERT_NE(plainNs->create_node(existingButUnregisteredId, NodeClass::Object), nullptr);

  const NodeId keptId{delegateIndex, uint32_t{510}};
  const NodeId droppedId{delegateIndex, uint32_t{511}};
  const NodeId unknownDelegateIdA{delegateIndex, uint32_t{512}};
  const NodeId unknownDelegateIdB{delegateIndex, uint32_t{513}};
  ASSERT_NE(delegateNs->create_node(keptId, NodeClass::Object), nullptr);
  ASSERT_NE(delegateNs->create_node(droppedId, NodeClass::Object), nullptr);

  build_session_info();

  // --- Arm 1: no delegate anywhere in the path, so the disposition under test is the server's -----
  // The antecedent is established through the real RegisterNodes service rather than asserted: one id
  // is genuinely registered, and every other id in the unregister list genuinely is not.
  RegisterNodesRequest registerRequest;
  registerRequest.nodes_to_register().resize(1);
  registerRequest.nodes_to_register()[0] = registeredId;

  auto registerOutcome = run_register_nodes(mSessionInfo, std::move(registerRequest), mPool);
  auto* registerResponse = std::get_if<RegisterNodesResponse>(&registerOutcome);
  ASSERT_NE(registerResponse, nullptr)
    << "control: the id must genuinely be registered, or the arm below says nothing about a mixed list";
  ASSERT_TRUE(registerResponse->response_header().service_result().is_good());
  ASSERT_EQ(registerResponse->registered_node_ids().size(), 1u);
  EXPECT_EQ(registerResponse->registered_node_ids()[0], registeredId);

  UnregisterNodesRequest mixedPlainRequest;
  mixedPlainRequest.nodes_to_unregister().resize(4);
  mixedPlainRequest.nodes_to_unregister()[0] = registeredId;
  mixedPlainRequest.nodes_to_unregister()[1] = existingButUnregisteredId;
  mixedPlainRequest.nodes_to_unregister()[2] = neverCreatedId;
  mixedPlainRequest.nodes_to_unregister()[3] = foreignNamespaceId;

  auto plainOutcome = run_unregister_nodes(mSessionInfo, std::move(mixedPlainRequest), mPool);
  if (auto* fault = std::get_if<ServiceFault>(&plainOutcome))
  {
    ADD_FAILURE() << "ids that were never registered must be ignored, not rejected; UnregisterNodes "
                     "faulted with "
                  << static_cast<uint32_t>(fault->response_header().service_result().as_status());
  }
  auto* plainResponse = std::get_if<UnregisterNodesResponse>(&plainOutcome);
  ASSERT_NE(plainResponse, nullptr) << "a mixed list must still answer with an UnregisterNodesResponse";
  EXPECT_EQ(plainResponse->response_header().service_result(), Status::Good)
    << "the service result is Good regardless of which ids were actually known";

  // Releasing the same id a second time is the already-unregistered case the requirement names beside
  // never-registered, and it is the one a teardown path actually hits.
  UnregisterNodesRequest repeatRequest;
  repeatRequest.nodes_to_unregister().resize(1);
  repeatRequest.nodes_to_unregister()[0] = registeredId;

  auto repeatOutcome = run_unregister_nodes(mSessionInfo, std::move(repeatRequest), mPool);
  auto* repeatResponse = std::get_if<UnregisterNodesResponse>(&repeatOutcome);
  ASSERT_NE(repeatResponse, nullptr)
    << "unregistering an already-unregistered id is cleanup too, and must not be rejected";
  EXPECT_EQ(repeatResponse->response_header().service_result(), Status::Good);

  // --- Arm 2: the registration table, so "the registered ones are unregistered" is observable ------
  RegisterNodesRequest delegateRegisterRequest;
  delegateRegisterRequest.nodes_to_register().resize(2);
  delegateRegisterRequest.nodes_to_register()[0] = keptId;
  delegateRegisterRequest.nodes_to_register()[1] = droppedId;

  auto delegateRegisterOutcome = run_register_nodes(mSessionInfo, std::move(delegateRegisterRequest), mPool);
  auto* delegateRegisterResponse = std::get_if<RegisterNodesResponse>(&delegateRegisterOutcome);
  ASSERT_NE(delegateRegisterResponse, nullptr);
  ASSERT_EQ(delegateRegisterResponse->registered_node_ids().size(), 2u);

  const auto beforeRelease = delegateNs->registered_snapshot();
  ASSERT_EQ(beforeRelease.size(), 2u)
    << "control: both ids must genuinely be held before the release below can prove anything";
  ASSERT_TRUE(contains_node_id(beforeRelease, droppedId));
  ASSERT_TRUE(contains_node_id(beforeRelease, keptId));

  UnregisterNodesRequest mixedDelegateRequest;
  mixedDelegateRequest.nodes_to_unregister().resize(3);
  mixedDelegateRequest.nodes_to_unregister()[0] = droppedId;
  mixedDelegateRequest.nodes_to_unregister()[1] = unknownDelegateIdA;
  mixedDelegateRequest.nodes_to_unregister()[2] = unknownDelegateIdB;

  auto delegateOutcome = run_unregister_nodes(mSessionInfo, std::move(mixedDelegateRequest), mPool);
  if (auto* fault = std::get_if<ServiceFault>(&delegateOutcome))
  {
    ADD_FAILURE() << "a list mixing held and never-registered ids must not fault; got "
                  << static_cast<uint32_t>(fault->response_header().service_result().as_status());
  }
  auto* delegateResponse = std::get_if<UnregisterNodesResponse>(&delegateOutcome);
  ASSERT_NE(delegateResponse, nullptr);
  EXPECT_EQ(delegateResponse->response_header().service_result(), Status::Good);

  const auto delivered = delegateNs->unregister_requested_snapshot();
  ASSERT_FALSE(delivered.empty())
    << "the release never reached the registration table at all, so nothing below is being tested";
  EXPECT_TRUE(contains_node_id(delivered, droppedId))
    << "the id that was registered must actually be carried through to the release";

  const auto afterRelease = delegateNs->registered_snapshot();
  EXPECT_FALSE(contains_node_id(afterRelease, droppedId))
    << "the registered id named in the request must actually be unregistered, not merely answered Good";
  EXPECT_TRUE(contains_node_id(afterRelease, keptId))
    << "a registration the request did not name must survive it";
  EXPECT_EQ(afterRelease.size(), 1u)
    << "ids that were never registered must remove nothing - ignoring them means exactly that";
}

// ===========================================================================
// Continuation-point capacity: served up to it, refused beyond it, never on a
// live point.
//
// BrowseService itself applies no capacity throttle - it emits a point for every
// operation that halted. The MaxBrowseContinuationPoints decision is taken in
// `Session::browse_response_received`, which post-processes the response and its
// points before they go on the wire, so that is the interface these two pins drive.
// ===========================================================================

namespace
{

using CpPinServerAccess = ::ua::test_helpers::ServerImplTestAccess;
using CpPinChannelAccess = ::ua::server::SecureChannelTestAccess;

// A server whose only interesting property is its continuation-point capacity. Shaped after
// `session_browse_continuation_point_tests.cpp`: a real ServerImpl with one None listener, which is the
// minimum a real Session can be built against.
shared_ptr<::ua::server::ServerImpl> create_cp_pin_server_impl(
  boost::asio::any_io_executor executor, uint16_t maxBrowseContinuationPoints)
{
  auto appCfg = ::ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ::ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.server_capabilities().maxBrowseContinuationPoints = maxBrowseContinuationPoints;
  // A long, explicit timeout: the expiry purge must never be the reason a point disappears here.
  sc.browseContinuationPointTimeout = std::chrono::milliseconds{600000};
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ::ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ::ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ::ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ::ua::MessageSecurityMode::None;
    ep.securityPolicyId = ::ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ::ua::server::create_user_token_policy(::ua::UserTokenType::Anonymous, ::ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  auto server = ::ua::server::ServerImpl::create(
    executor, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  CpPinServerAccess{*server}.initialise_listeners_from_config();
  return server;
}

struct CpPinHarness
{
  boost::asio::thread_pool threadPool;
  boost::asio::any_io_executor executor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> strand;

  shared_ptr<::ua::server::ServerImpl> server;
  weak_ptr<::ua::server::SecureChannelDependencies> deps;
  shared_ptr<::ua::server::SecureChannel> sc;
};

std::unique_ptr<CpPinHarness> create_cp_pin_harness(uint16_t maxBrowseContinuationPoints)
{
  auto h = std::make_unique<CpPinHarness>();
  h->executor = h->threadPool.get_executor();
  h->strand = boost::asio::make_strand(h->executor);

  h->server = create_cp_pin_server_impl(h->executor, maxBrowseContinuationPoints);
  h->deps = CpPinServerAccess{*h->server}.secure_channel_dependencies();

  h->sc = ::ua::server::SecureChannel::create(
    h->deps, nullptr, ::ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  CpPinServerAccess{*h->server}.add_secure_channel(h->sc);

  CpPinChannelAccess::on_strand(
    *h->sc, [&](auto& g) { g.set_minimal_context_none(h->executor, "TestListener/None"); });

  return h;
}

shared_ptr<::ua::server::Session> create_cp_pin_session(CpPinHarness& h)
{
  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  req.session_name() = "browse-cp-pin";
  req.client_description().application_name().text() = "client";

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  ::ua::server::SecureChannelInfo info(h.sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    CpPinChannelAccess::on_strand(*h.sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  return ::ua::server::Session::create(
    CpPinServerAccess{*h.server}.session_dependencies(), info, 1, std::move(req));
}

void tear_down_cp_pin_harness(std::unique_ptr<CpPinHarness>& h, shared_ptr<::ua::server::Session>& session)
{
  if (session)
  {
    session->terminate_for_shutdown();
    session.reset();
  }
  h->sc.reset();
  h->server.reset();
  h->strand.reset();
  h->executor = {};
  ::ua::test_utils::drain_with_timeout(h->threadPool);
}

BrowseContinuationPoint make_cp_pin_continuation_point()
{
  return BrowseContinuationPoint{ViewDescription{}, Counter{0}, BrowseDescription{}};
}

// A BrowseResponse shaped exactly as BrowseService would hand one over: one result per operation, each
// carrying the encoded identifier of the point that operation halted on.
std::pair<Response, shared_ptr<BrowseResponse>> make_cp_pin_browse_response(
  uint32_t requestId, const std::vector<Guid>& identifiers)
{
  auto resp = std::make_shared<BrowseResponse>();
  resp->results().resize(identifiers.size());
  for (size_t i = 0; i < identifiers.size(); ++i)
  {
    auto encoded = identifiers[i].as_ua_binary();
    resp->results()[i].continuation_point() = ByteString{span<const byte>{encoded}};
  }
  return {Response{requestId, resp}, resp};
}

}  // namespace

// Part 4 section 5.8.3: when a Browse needs more continuation points than the server can hold, the operations
// up to the capacity are served with points and the rest answer Bad_NoContinuationPoints - and the request
// itself still succeeds. Partial service is the obligation here, unlike the node-management services
// where a partial batch is forbidden: a browse that served half its nodes has given the client real data,
// and failing the whole request would throw that away. Both plausible wrong implementations are
// all-or-nothing, and both read as correct. One writes the capacity check as a precondition - "can I hold
// N more points? no -> refuse" - evaluated once for the whole response; the other accepts the points into
// storage and, on finding itself over budget, clears every one of them rather than the excess. Four
// operations against a capacity of two separate those from the obligation: exactly two must keep their
// point, exactly two must be refused by name, and the ResponseHeader must stay Good. Which two are served
// is the server's choice and is deliberately not asserted.
// @verifies AC-SVR-VIEW-CPT-005-NOCONTINUATIONPOINTS
TEST(BrowseContinuationPointCapacityPin, BrowseBeyondTheCapacityServesUpToItAndRefusesOnlyTheExcess)
{
  constexpr uint16_t capacity = 2;
  constexpr size_t operations = 4;

  auto harness = create_cp_pin_harness(capacity);
  auto session = create_cp_pin_session(*harness);

  GTEST_LOG_(INFO) << "continuation-point capacity " << capacity << "; operations needing a point "
                   << operations;

  std::vector<Guid> identifiers;
  std::vector<BrowseContinuationPoint> points;
  for (size_t i = 0; i < operations; ++i)
  {
    auto cp = make_cp_pin_continuation_point();
    identifiers.push_back(cp.identifier());
    points.push_back(std::move(cp));
  }

  auto made = make_cp_pin_browse_response(10u, identifiers);
  auto response = std::move(made.first);
  auto browseResponse = made.second;
  ASSERT_EQ(browseResponse->results().size(), operations)
    << "the stimulus must genuinely be a browse of four operations, each halted with its own point";

  SessionTestAccess::on_strand(
    *session, [&](auto& g) { g.browse_response_received(std::move(response), std::move(points)); });

  size_t served = 0;
  size_t refused = 0;
  for (const auto& result : browseResponse->results())
  {
    if (!result.continuation_point().empty())
    {
      ++served;
      EXPECT_FALSE(result.status_code().is_bad())
        << "an operation that kept its continuation point must not also carry a failure";
      continue;
    }
    ++refused;
    EXPECT_EQ(result.status_code(), Status::BadNoContinuationPoints)
      << "an operation the server had no point left for must say so by name; dropping the point and "
         "leaving the row Good tells the client its browse finished when it did not";
  }

  EXPECT_EQ(served, static_cast<size_t>(capacity))
    << "the operations up to the capacity must be served with points";
  EXPECT_EQ(refused, operations - static_cast<size_t>(capacity))
    << "only the excess is refused - a capacity check evaluated once for the whole response refuses all "
    << operations;

  EXPECT_TRUE(browseResponse->response_header().service_result().is_good())
    << "the request is not failed as a whole: the operations that were served carry real references the "
       "client must be allowed to keep";

  EXPECT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    static_cast<size_t>(capacity))
    << "the points reported as served must actually be held, or the client cannot continue them";

  tear_down_cp_pin_harness(harness, session);
}

// Part 4 section 5.8.3: "Servers shall never return Bad_NoContinuationPoints error when continuing a
// previously halted operation." The point is already allocated, so refusing to continue strands a browse the
// client can neither finish nor restart. The plausible implementation writes the capacity check once and
// applies it to both paths, because both arrive at the same place: a response carrying continuation points,
// to be admitted against the same budget. On the continuation path the budget is already full - by the very
// point being continued - so the check refuses the successor and the browse dies at the capacity limit
// instead of walking past it. The stimulus is the continuation as the service really performs it: the
// point handed in is consumed and a fresh identifier is issued for the remainder, so the session sees one
// candidate while it still counts the consumed point against the budget. Capacity one makes that
// collision certain.
// @verifies AC-SVR-VIEW-CPT-006-NEVER-ON-CONTINUE
TEST(BrowseContinuationPointCapacityPin, ContinuingALivePointAtFullCapacityIsNeverRefused)
{
  auto harness = create_cp_pin_harness(/*maxBrowseContinuationPoints=*/1);
  auto session = create_cp_pin_session(*harness);

  // --- Fill the capacity through the real admission path: one Browse that halts with one point. -----
  auto firstPoint = make_cp_pin_continuation_point();
  const Guid firstId = firstPoint.identifier();
  {
    std::vector<Guid> identifiers{firstId};
    auto made = make_cp_pin_browse_response(10u, identifiers);
    auto response = std::move(made.first);
    auto browseResponse = made.second;

    std::vector<BrowseContinuationPoint> points;
    points.push_back(std::move(firstPoint));

    SessionTestAccess::on_strand(
      *session, [&](auto& g) { g.browse_response_received(std::move(response), std::move(points)); });

    ASSERT_EQ(browseResponse->results().size(), 1u);
    ASSERT_FALSE(browseResponse->results()[0].status_code().is_bad())
      << "control: the first point must be admitted, or the arm below is not about a server at capacity";
    ASSERT_FALSE(browseResponse->results()[0].continuation_point().empty())
      << "control: the client must genuinely hold a live point to continue";
  }
  ASSERT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }), 1u)
    << "control: the server must genuinely be AT its continuation-point capacity";

  // --- Continue it. BrowseService pulls the supplied point out of the session's store before it runs
  // (`BrowseService::retrieve_continuation_points`) and allocates a fresh identifier for the remainder, so
  // the state the admission path meets is: store empty, budget still charged for the consumed point. ---
  SessionTestAccess::on_strand(*session, [&](auto& g) { g.browse_continuation_points().erase(firstId); });

  auto secondPoint = make_cp_pin_continuation_point();
  const Guid secondId = secondPoint.identifier();

  auto nextResp = std::make_shared<BrowseNextResponse>();
  nextResp->results().resize(1);
  {
    auto encoded = secondId.as_ua_binary();
    nextResp->results()[0].continuation_point() = ByteString{span<const byte>{encoded}};
  }

  std::vector<BrowseContinuationPoint> nextPoints;
  nextPoints.push_back(std::move(secondPoint));
  Response nextResponse{11u, nextResp};

  SessionTestAccess::on_strand(
    *session, [&](auto& g) { g.browse_response_received(std::move(nextResponse), std::move(nextPoints)); });

  ASSERT_EQ(nextResp->results().size(), 1u);
  EXPECT_NE(nextResp->results()[0].status_code(), StatusCode{Status::BadNoContinuationPoints})
    << "Bad_NoContinuationPoints is never the answer to a BrowseNext on a live point";
  EXPECT_FALSE(nextResp->results()[0].status_code().is_bad())
    << "the continuation of an already-allocated point must be served";
  EXPECT_FALSE(nextResp->results()[0].continuation_point().empty())
    << "the continuation has more to come, so its successor point must be handed back - dropping it "
       "strands the browse just as surely as refusing it";

  EXPECT_TRUE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(secondId); }))
    << "the successor point the client was told to come back with must actually be held";

  tear_down_cp_pin_harness(harness, session);
}

}  // namespace ua::test::behaviour_pins
