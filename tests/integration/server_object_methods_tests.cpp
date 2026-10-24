// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for two Server-object methods exercised over the full
/// client -> server -> session -> subscription / address-space pipeline:
///
///   * ResendData (Server_ResendData) - Part 4 Section 5.12.2.3.
///     Routing: SubscriptionRouter::find_owner -> Bad_SubscriptionIdInvalid
///     when absent; the calling session must own the subscription else
///     Bad_UserAccessDenied; success re-enqueues each Reporting monitored
///     item's last sent value so a fresh Publish carries it again with no
///     underlying data change.
///
///   * RequestServerStateChange (Server_RequestServerStateChange) - Part 5.
///     Accepts the full ServerState set, writing dynamicState->server_state
///     (observable via a ServerStatus.State read); a malformed/out-of-range
///     State -> Bad_InvalidArgument; Shutdown drives the graceful-shutdown
///     handler; the method is non-Executable by default (opt-in only).
///
/// These are not unit tests because the behaviour under test only manifests
/// with a live session, subscription pipeline, and address space - the wire
/// handlers (wire_resend_data / wire_request_server_state_change) are
/// file-local and reachable only through the Call service. The established
/// ComplianceWithNodes harness (also used by get_monitored_items_tests.cpp,
/// a sibling Server-object method) is reused here.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_referencetype_id.h"

#include "ua_access_restriction_type.h"
#include "ua_browse_next_response.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_build_info.h"
#include "ua_call_response.h"
#include "ua_continuation_point.h"
#include "ua_create_monitored_items_response.h"
#include "ua_data_change_notification.h"
#include "ua_datatype_id.h"
#include "ua_method_id.h"
#include "ua_monitored_item_create_result.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_server_state.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_utc_time.h"
#include "ua_variable_id.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <string_view>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// Call ResendData(subscriptionId) and return the operation-level result.
CallMethodResult call_resend_data(Session& session, uint32_t subscriptionId)
{
  auto resp = session.methods().call_sync(
    call_method(NodeId{ObjectId::Server}, NodeId{MethodId::Server_ResendData}, {Variant{subscriptionId}}));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

/// Call RequestServerStateChange with the supplied State variant (other args
/// defaulted) and return the operation-level result.
CallMethodResult call_request_state_change(Session& session, Variant state)
{
  // Args order: State, EstimatedReturnTime, SecondsTillShutdown, Reason, Restart.
  auto resp = session.methods().call_sync(call_method(NodeId{ObjectId::Server},
    NodeId{MethodId::Server_RequestServerStateChange},
    {std::move(state), Variant{DateTime{}}, Variant{uint32_t{0}}, Variant{LocalizedText{}}, Variant{false}}));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

/// Read Server_ServerStatus_State and return the raw Int32 enum value.
int32_t read_server_state(Session& session)
{
  auto resp = session.attributes().read_sync(read_value(NodeId{VariableId::Server_ServerStatus_State}));
  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.results().size(), 1u);
  return resp.results()[0].value().as<int32_t>();
}

/// Opt-in: mark the RequestServerStateChange method node Executable on the
/// server side (the wire setup defaults it to false). Returns true on success.
bool make_request_state_change_executable(AddressSpace addressSpace)
{
  auto findResult = addressSpace.try_find_node_sync(NodeId{MethodId::Server_RequestServerStateChange});
  if (!findResult)
  {
    return false;
  }
  auto method = findResult.value().as<MethodAccessor>();
  if (!method.has_value())
  {
    return false;
  }
  method->set_executable(true);
  return true;
}

}  // namespace

class SecuredDiagnosticsObserverFixture : public ComplianceSecuredWithSession
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration =
      RoleConfiguration::from_well_known_grants({{WellKnownRole::Observer, IdentityCriteriaType::Anonymous}});
  }
};

// ===========================================================================
// ResendData
// ===========================================================================

// Unknown subscription id -> Bad_SubscriptionIdInvalid (find_owner miss).
TEST_F(ComplianceWithNodes, ResendData_BadSubscriptionIdInvalid)
{
  auto result = call_resend_data(*mSession, 0xDEADBEEFu);
  EXPECT_THAT(result, HasStatus(Status::BadSubscriptionIdInvalid));
}

// A subscription owned by ANOTHER session -> Bad_UserAccessDenied. The router
// finds an owner, but its session_id does not match the calling context.
TEST_F(ComplianceWithNodes, ResendData_OtherSessionsSubscriptionDenied)
{
  // Second session on the same endpoint owns the subscription.
  auto channelB = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionB = channelB.create_session_sync({.sessionName = "ResendDataOwnerB"});
  sessionB.activate_sync();

  auto subId = create_subscription(sessionB, {.publishingInterval = 50.0});

  // Call ResendData from the fixture's primary session (not the owner).
  auto result = call_resend_data(*mSession, subId);
  EXPECT_THAT(result, HasStatus(Status::BadUserAccessDenied));

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();
}

// Success path: a subscription with a Reporting monitored item gets its last
// sent value re-enqueued, producing a fresh DataChange Publish even though no
// underlying value changed since the initial publish.
// Covers SVR-BASE-025 (coverage-audit retag).
TEST_F(ComplianceWithNodes, ResendData_ReEnqueuesLastValueForReportingItem)
{
  auto [subId, miId] = create_subscription_with_monitored_item(
    *mSession, mWritableVariableId, {.publishingInterval = 50.0}, {.clientHandle = 7u});

  // Drain the initial-value DataChange so the queue is empty before ResendData.
  auto initial = wait_for_data_change(
    *mSession, subId, [](const DataChangeNotification& dc) { return !dc.monitored_items().empty(); }, 2s);
  ASSERT_TRUE(initial) << "expected an initial-value DataChange before ResendData";

  // No value is written here - only ResendData should cause a new notification.
  auto result = call_resend_data(*mSession, subId);
  ASSERT_THAT(result, Good()) << "0x" << std::hex << result.status_code().as_uint32();

  // ResendData re-enqueues lastSentValue; expect a fresh DataChange carrying
  // our monitored item's client handle.
  auto resent = wait_for_data_change(
    *mSession,
    subId,
    [](const DataChangeNotification& dc)
    {
      return std::any_of(dc.monitored_items().begin(),
        dc.monitored_items().end(),
        [](const auto& item) { return item.client_handle() == 7u; });
    },
    2s);
  EXPECT_TRUE(resent) << "ResendData did not produce a fresh notification for the monitored item";

  delete_subscription(*mSession, subId);
}

// ===========================================================================
// RequestServerStateChange
// ===========================================================================
//
// The standard Server-object instance method node (i=12886) carries
// AccessRestrictions in NS0 (the test NodeSet sets AccessRestrictions="1",
// i.e. SigningRequired). ua_method_service_set.cpp enforces this BEFORE the
// Executable / argument checks, so a call over a None channel is rejected with
// Bad_SecurityModeInsufficient regardless of the method's other state. These
// tests therefore run over a Basic256Sha256 SignAndEncrypt channel (which
// satisfies both the SigningRequired and EncryptionRequired restrictions),
// using the ComplianceSecuredWithSession fixture. The
// RequestStateChange_NoneChannelInsufficient test below documents and pins the
// security precondition that motivates the secured fixture.

// Precondition / diagnosis pin: invoking RequestServerStateChange over a plain
// None channel is rejected with Bad_SecurityModeInsufficient because the method
// node carries an AccessRestriction. This is why the remaining tests use a
// secured channel.
// Covers SVR-BASE-091 (coverage-audit retag).
TEST_F(ComplianceWithNodes, RequestServerStateChange_NoneChannelSecurityModeInsufficient)
{
  // Even after opting the method in as Executable, the AccessRestriction check
  // (which runs first) rejects the None-channel call.
  ASSERT_TRUE(make_request_state_change_executable(mServer.server().address_space()));

  auto result = call_request_state_change(*mSession, Variant{static_cast<int32_t>(ServerState::Suspended)});
  EXPECT_THAT(result, HasStatus(Status::BadSecurityModeInsufficient));
}

// A non-Shutdown transition (Suspended) is accepted and reflected in a
// subsequent ServerStatus.State read.
TEST_F(ComplianceSecuredWithSession, RequestServerStateChange_SuspendedReflectedInStatus)
{
  ASSERT_TRUE(make_request_state_change_executable(mServer->address_space()));

  // Sanity: starts Running.
  ASSERT_EQ(read_server_state(*mSession), static_cast<int32_t>(ServerState::Running));

  auto result = call_request_state_change(*mSession, Variant{static_cast<int32_t>(ServerState::Suspended)});
  ASSERT_THAT(result, Good()) << "0x" << std::hex << result.status_code().as_uint32();

  EXPECT_EQ(read_server_state(*mSession), static_cast<int32_t>(ServerState::Suspended));
}

// An out-of-range Int32 State (passes the MethodAdapter Int32 type check, but
// decode_server_state rejects it) -> Bad_InvalidArgument.
// Covers SVR-BASE-092 (coverage-audit retag).
TEST_F(ComplianceSecuredWithSession, RequestServerStateChange_OutOfRangeStateInvalidArgument)
{
  ASSERT_TRUE(make_request_state_change_executable(mServer->address_space()));

  auto result = call_request_state_change(*mSession, Variant{int32_t{9999}});
  EXPECT_THAT(result, HasStatus(Status::BadInvalidArgument));

  // The rejected transition must NOT have mutated the reported state.
  EXPECT_EQ(read_server_state(*mSession), static_cast<int32_t>(ServerState::Running));
}

// A non-Int32 State (a String) fails the handler's is_int32() guard ->
// Bad_InvalidArgument. The State arg is typed Variant in the adapter, so it
// reaches the handler intact rather than being rejected at decode time.
TEST_F(ComplianceSecuredWithSession, RequestServerStateChange_NonInt32StateInvalidArgument)
{
  ASSERT_TRUE(make_request_state_change_executable(mServer->address_space()));

  auto result = call_request_state_change(*mSession, Variant{String{"not-a-state"}});
  EXPECT_THAT(result, HasStatus(Status::BadInvalidArgument));

  EXPECT_EQ(read_server_state(*mSession), static_cast<int32_t>(ServerState::Running));
}

// Shutdown routes to the graceful-shutdown handler rather than the generic
// node-write branch. Distinguishing observation: only the Shutdown branch calls
// the server's ShutdownRequestHandler -> shutdown_async, which transitions the
// server-side ServerStatus.State to Shutdown (the generic branch would store
// the requested state directly, but Shutdown specifically must route through
// the shutdown machinery). We cannot assert on the Call response: the default
// shutdown handler holds the method's completion callback until shutdown
// actually finishes (deferred for the grace period), so the request would
// otherwise time out. Instead we fire the call asynchronously and poll the
// server-side state node, with a non-zero grace period so the server stays
// alive (acceptors closed, channel up) long enough to observe the transition.
TEST_F(ComplianceSecuredWithSession, RequestServerStateChange_ShutdownRoutesToHandler)
{
  ASSERT_TRUE(make_request_state_change_executable(mServer->address_space()));

  auto serverAddressSpace = mServer->address_space();
  auto readServerSideState = [&serverAddressSpace]() -> int32_t
  {
    auto findResult = serverAddressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_State});
    EXPECT_TRUE(findResult);
    auto variable = findResult.value().as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    return variable->read_value_sync().value().as<int32_t>();
  };

  // Sanity: server reports Running before the request.
  ASSERT_EQ(readServerSideState(), static_cast<int32_t>(ServerState::Running));

  // Fire-and-forget: the shutdown handler defers the method completion until
  // shutdown finishes, so blocking on the response would time out. A grace
  // period keeps the server alive while we observe the routed transition.
  mSession->methods().call_async(call_method(NodeId{ObjectId::Server},
                                   NodeId{MethodId::Server_RequestServerStateChange},
                                   {Variant{static_cast<int32_t>(ServerState::Shutdown)},
                                     Variant{DateTime{}},
                                     Variant{uint32_t{3600}},
                                     Variant{LocalizedText{"", "test shutdown"}},
                                     Variant{false}}),
    [](auto) {});

  // Poll until the Shutdown branch has driven the server into Shutdown state.
  bool reachedShutdown = false;
  for (int attempt = 0; attempt < 100 && !reachedShutdown; ++attempt)
  {
    if (readServerSideState() == static_cast<int32_t>(ServerState::Shutdown))
    {
      reachedShutdown = true;
      break;
    }
    std::this_thread::sleep_for(20ms);
  }
  EXPECT_TRUE(reachedShutdown)
    << "Shutdown request did not route to the shutdown handler (server never reached Shutdown state)";
}

// @verifies CL-SESS-021
// Part 4 section 5.6.2: terminating a Session aborts every outstanding request with
// BadSessionClosed. The graceful-shutdown method deliberately defers its Call
// completion for the grace period, giving CloseSession a deterministic
// in-flight public request to drain.
// @relation(CL-SESS-021, scope=function)
TEST_F(ComplianceSecured, CloseSessionCompletesDeferredCallWithBadSessionClosed)
{
  ASSERT_TRUE(make_request_state_change_executable(mServer->address_space()));

  auto endpointUrl = mEndpointUrl;
  constexpr std::string_view loopbackAddress{"127.0.0.1"};
  endpointUrl.replace(endpointUrl.find(loopbackAddress), loopbackAddress.size(), "localhost");
  CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = endpointUrl;
  channelConfig.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelConfig.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelConfig.serverCertificate = mServerCert;
  auto channel = mClient->core().open_channel_sync(std::move(channelConfig));
  auto session = channel.create_session_sync({.sessionName = "OutstandingCloseDrain"});
  session.activate_sync();

  auto serverAddressSpace = mServer->address_space();
  auto readServerSideState = [&serverAddressSpace]() -> int32_t
  {
    auto findResult = serverAddressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_State});
    EXPECT_TRUE(findResult);
    auto variable = findResult.value().as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    return variable->read_value_sync().value().as<int32_t>();
  };

  auto callPromise = std::make_shared<std::promise<SessionMethodServices::CallResponseResult>>();
  auto callFuture = callPromise->get_future();
  session.methods().call_async(call_method(NodeId{ObjectId::Server},
                                 NodeId{MethodId::Server_RequestServerStateChange},
                                 {Variant{static_cast<int32_t>(ServerState::Shutdown)},
                                   Variant{DateTime{}},
                                   Variant{uint32_t{3600}},
                                   Variant{LocalizedText{"", "deferred close drain"}},
                                   Variant{false}}),
    [callPromise](SessionMethodServices::CallResponseResult result) mutable
    { callPromise->set_value(std::move(result)); });

  bool requestIsDeferred = false;
  for (int attempt = 0; attempt < 100 && !requestIsDeferred; ++attempt)
  {
    requestIsDeferred = readServerSideState() == static_cast<int32_t>(ServerState::Shutdown);
    if (!requestIsDeferred)
      std::this_thread::sleep_for(20ms);
  }
  ASSERT_TRUE(requestIsDeferred) << "the Call must enter the deferred shutdown handler before close";
  ASSERT_EQ(callFuture.wait_for(0ms), std::future_status::timeout)
    << "the Call must still be outstanding when CloseSession begins";

  session.close_sync();

  ASSERT_EQ(callFuture.wait_for(1s), std::future_status::ready)
    << "CloseSession must not silently drop an outstanding public callback";
  auto callResult = callFuture.get();
  ASSERT_TRUE(callResult.is_bad());
  EXPECT_EQ(callResult.status_code().as_status(), Status::BadSessionClosed);

  channel.close_sync();
}

// RequestServerStateChange is Executable, and refusing it is authorization's job.
//
// This test previously asserted the opposite - that the Method reads non-Executable until an
// application opts in. That was the SDK's own policy rather than a spec obligation, and OPC 10000-5
// section 5.5 Table 7 contradicts it: every Method the specification defines shall be Executable unless its
// own definition says otherwise, and this one's does not. Executable is what a Client reads to decide
// whether a Method is offered at all, so False on a fully wired Method advertises a missing feature
// rather than a refused one.
//
// The refusal has not gone away, it has moved to where the spec puts it: every Call is authorized for
// AccessOperation::Call, and ComplianceWithNodes.RequestServerStateChangeIsRefusedToAnAnonymousSession
// AndChangesNothing covers that path. This fixture's session is authorized, so the Call succeeds here
// - which is the observation that distinguishes "gated by access control" from "gated by an
// Attribute".
TEST_F(
  ComplianceSecuredWithSession, RequestServerStateChangeIsExecutableAndGatedByAuthorizationNotTheAttribute)
{
  auto result = call_request_state_change(*mSession, Variant{static_cast<int32_t>(ServerState::Suspended)});
  EXPECT_TRUE(result.status_code().is_good())
    << "an authorized session must reach the Method; the refusal path belongs to Namespace policy, and "
       "Part 5 Table 7 keeps Executable True on a Method the specification defines";
}

// ---------------------------------------------------------------------------
// SessionDiagnosticsArray / SessionSecurityDiagnosticsArray - live aggregate nodes
// ---------------------------------------------------------------------------
// Server.ServerDiagnostics.SessionsDiagnosticsSummary.SessionDiagnosticsArray is
// built per-read from the live session set. With the fixture's own session
// connected, the array must contain at least one SessionDiagnosticsDataType
// element. (Falsifiable: an unwired handler / empty array fails the size check.)
// @relation(AC-SVR-BASE-017-SESSION-DIAGNOSTICS-ARRAY-LIVE, scope=function)
TEST_F(ComplianceWithNodes, SessionDiagnosticsArray_ReflectsLiveSession)
{
  mServer.set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession = mChannel->create_session_sync({.sessionName = "SessionDiagnosticsArrayReader"});
  diagnosticsSession.activate_sync();

  auto resp = diagnosticsSession.attributes().read_sync(read_value(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.payload().size(), 1u) << "the live session must appear in SessionDiagnosticsArray";
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SessionDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr) << "each element must be a SessionDiagnosticsDataType";
  }
}

// SessionSecurityDiagnosticsArray exposes security details and carries an
// AccessRestriction in NS0, so a read over a None (unsecured) channel is rejected
// per-item with Bad_SecurityModeInsufficient (SVR-ATTR-READ-025, enforced in
// AttributeServiceSet). This protects the security diagnostics from unsecured peers.
// @relation(AC-SVR-BASE-077-AUTHORISED-ENCRYPTED-ARRAY, scope=function)
TEST_F(ComplianceWithNodes, SessionSecurityDiagnosticsArray_RestrictedOnNoneChannel)
{
  mServer.set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession =
    mChannel->create_session_sync({.sessionName = "SessionSecurityDiagnosticsNoneReader"});
  diagnosticsSession.activate_sync();

  auto resp = diagnosticsSession.attributes().read_sync(read_value(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  const auto status = resp.results()[0].status();
  ASSERT_TRUE(status.has_value());
  EXPECT_EQ(*status, StatusCode{Status::BadSecurityModeInsufficient})
    << "0x" << std::hex << status->as_uint32();
}

// @verifies AC-SVR-AUTHZ-018-THE-SECURITY-DIAGNOSTICS-SURFACE-REQUIRES-AN-ENCRYPTED-CHANNEL
// The per-session SessionSecurityDiagnostics Variable is created from the instance declaration i=2031,
// which takes the template's EncryptionRequired. The access-control engine decides the channel
// restriction before the Role permissions, so on a None channel the refusal is the channel's
// (Bad_SecurityModeInsufficient) whatever the Role. The Node ids are found on the server side: an
// Anonymous session may not Browse the security surface, and this arm is about the channel half only.
// The sibling SessionDiagnostics (no such restriction; its surface admits Anonymous) is the control.
TEST_F(ComplianceWithNodes, PerSessionSecurityDiagnosticsRestrictedOnNoneChannel)
{
  mServer.set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession =
    mChannel->create_session_sync({.sessionName = "PerSessionSecurityDiagnosticsNoneReader"});
  diagnosticsSession.activate_sync();
  // Server-side: SessionsDiagnosticsSummary -> the session's SessionDiagnosticsObject (by BrowseName)
  // -> its two Variables.
  auto addressSpace = mServer.server().address_space();
  const auto childNamed = [&](const NodeId& parentId, std::string_view name) -> std::optional<NodeId>
  {
    auto parent = addressSpace.try_find_node_sync(parentId);
    if (!parent.is_good())
      return std::nullopt;
    auto references = parent.value().try_get_references_sync();
    if (!references.is_good())
      return std::nullopt;
    for (const auto& reference : references.value())
    {
      if (!reference.is_forward() || !reference.target_id().is_local())
        continue;
      auto target = addressSpace.try_find_node_sync(reference.target_id().node_id());
      if (target.is_good() && static_cast<ua::string_view>(target.value().get_browse_name().name()) == name)
        return reference.target_id().node_id();
    }
    return std::nullopt;
  };
  // The per-session diagnostics object is created asynchronously after CreateSession; poll with a
  // bounded budget until both Variables resolve and the control reads Good (its read handler is
  // installed last), then take the restricted read.
  std::optional<NodeId> securityId;
  std::optional<NodeId> diagnosticsId;
  bool controlGood = false;
  for (int attempt = 0; attempt < 200 && !controlGood; ++attempt)
  {
    const auto sessionObjectId =
      childNamed(NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary},
        "PerSessionSecurityDiagnosticsNoneReader");
    if (sessionObjectId)
    {
      securityId = childNamed(*sessionObjectId, "SessionSecurityDiagnostics");
      diagnosticsId = childNamed(*sessionObjectId, "SessionDiagnostics");
      if (securityId && diagnosticsId)
      {
        auto probe = diagnosticsSession.attributes().try_read_sync(read_value(*diagnosticsId));
        controlGood = probe.is_good() && probe.value().results().size() == 1 &&
                      (!probe.value().results()[0].status().has_value() ||
                        probe.value().results()[0].status()->is_good());
      }
    }
    if (!controlGood)
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }
  ASSERT_TRUE(securityId.has_value())
    << "the session's SessionSecurityDiagnostics Variable exists on the server";
  ASSERT_TRUE(diagnosticsId.has_value());
  ASSERT_TRUE(controlGood) << "the per-session diagnostics object never became readable";
  auto secured = diagnosticsSession.attributes().read_sync(read_value(*securityId));
  ASSERT_THAT(secured, ServiceResultIsGood());
  ASSERT_EQ(secured.results().size(), 1u);
  ASSERT_TRUE(secured.results()[0].status().has_value());
  EXPECT_EQ(*secured.results()[0].status(), StatusCode{Status::BadSecurityModeInsufficient})
    << "0x" << std::hex << secured.results()[0].status()->as_uint32();
  auto control = diagnosticsSession.attributes().read_sync(read_value(*diagnosticsId));
  ASSERT_THAT(control, ServiceResultIsGood());
  ASSERT_EQ(control.results().size(), 1u);
  EXPECT_THAT(control.results()[0], Good()) << "the unrestricted sibling reads on the same channel";
}

// D1 - the AccessRestriction the Read test above enforces is NOT enforced on the subscription path.
// `i=3708` carries AccessRestrictions=3 (SigningRequired|EncryptionRequired) in the NS0 NodeSet, and
// OPC 10000-2 section 3.1.1 makes satisfying the restrictions a necessary condition for performing ANY
// operation on the Node, not only a Read.
//
// CONFORMANT SHAPE - OPC 10000-4 section 5.12.2.1 (verbatim): "When a user adds a monitored item that the
// user is denied read access to, the add operation for the item SHALL succeed and the bad status
// Bad_NotReadable or Bad_UserAccessDenied SHALL be returned in the Publish response." The clause that
// follows permits all possible errors "to be returned in the Publish response" - not in the create
// response - so there is no licence to fail the create. An earlier version of this arm asserted a
// failing CreateMonitoredItems and was therefore itself non-conformant.
//
// So the assertions are: the create SUCCEEDS, and the first Publish carries the denial as the item's
// DataValue status instead of the data. Today the create succeeds and the real value is delivered,
// which is what makes this red.
//
// The `diagnostics:full` claim is granted, so the OPC 10000-5 section 12.12 user half is already satisfied
// and the only condition under test is the channel half.
// NO relation marker, deliberately. A disabled test discharges nothing, so a coverage claim here
// would report AC-SVR-BASE-077 as verified on the strength of a test that does not run - which is
// what check_requirement_coverage.py means by "a verifies marker on a dead test hides a gap". The
// criterion's live coverage is the Read pair above and below (SessionSecurityDiagnosticsArray_
// RestrictedOnNoneChannel and _PopulatedOverSecuredChannel); the SUBSCRIPTION arm this test would
// prove is exactly what the defect below says is unproven, and it must stay visibly unproven.
// @pending(D-SVR-BASE-077-ACCESSRESTRICTIONS-NOT-ENFORCED-ON-SUBSCRIPTION)
// DISABLED, not deleted: the obligation is real and the defect is registered. Two things must be
// true before it is re-enabled - the defect fixed, AND this fixture's precondition corrected. It
// grants `diagnostics:full` believing that satisfies the section 12.12 USER half; that claim is
// consumed only by ua_diagnostic_policy.h:35 to set diagnostic DETAIL LEVEL and grants no Role, so
// an Anonymous session ({Browse, Read}) is denied on the user half and never reaches the channel
// half this test is about.
TEST_F(ComplianceWithNodes, DISABLED_SessionSecurityDiagnosticsArray_MonitoredItemRestrictedOnNoneChannel)
{
  mServer.set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession =
    mChannel->create_session_sync({.sessionName = "SessionSecurityDiagnosticsNoneMonitor"});
  diagnosticsSession.activate_sync();

  const NodeId restrictedNode{
    VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray};
  constexpr uint32_t handle = 77;

  const uint32_t subId = create_subscription(diagnosticsSession);
  ASSERT_NE(subId, 0u);

  auto miResp = diagnosticsSession.monitored_items().create_monitored_items_sync(
    build_create_mi_request(subId, restrictedNode, {.clientHandle = handle}));
  ASSERT_THAT(miResp, ServiceResultIsGood());
  ASSERT_EQ(miResp.results().size(), 1u);

  // Part 4 section 5.12.2.1: the add SHALL succeed even when access is denied.
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "CreateMonitoredItems must not fail on an access denial - the denial belongs in Publish. Got 0x"
    << std::hex << miResp.results()[0].status_code().as_uint32();

  // ...and the denial SHALL arrive as the item's status in the Publish response, in place of the data.
  auto notif = wait_for_data_change(diagnosticsSession,
    subId,
    [](const DataChangeNotification& dc)
    {
      return std::ranges::any_of(dc.monitored_items(),
        [](const MonitoredItemNotification& mi) { return mi.client_handle() == handle; });
    });
  ASSERT_TRUE(notif.has_value()) << "no DataChangeNotification arrived for the monitored item";

  const MonitoredItemNotification* ours = nullptr;
  for (const auto& mi : notif->monitored_items())
    if (mi.client_handle() == handle)
      ours = &mi;
  ASSERT_NE(ours, nullptr);

  const auto status = ours->value().status().value_or(StatusCode{});
  EXPECT_EQ(status, StatusCode{Status::BadSecurityModeInsufficient})
    << "SessionSecurityDiagnostics delivered over a None channel: the monitored item published a value "
       "where the channel restriction requires a denial status. Got 0x"
    << std::hex << status.as_uint32();

  delete_subscription(diagnosticsSession, subId);
}

// @relation(AC-SVR-AUTHZ-018-DIAGNOSTICS-GATED-ON-EVERY-PATH, scope=function)
TEST_F(SecuredDiagnosticsObserverFixture, SecurityDiagnosticsMonitoredItemIsDeniedToNonAdmin)
{
  const NodeId restrictedNode{
    VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray};
  constexpr uint32_t handle = 78;

  const uint32_t subscriptionId = create_subscription(*mSession);
  ASSERT_NE(subscriptionId, 0u);
  auto createResponse = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subscriptionId, restrictedNode, {.clientHandle = handle}));
  ASSERT_THAT(createResponse, ServiceResultIsGood());
  ASSERT_EQ(createResponse.results().size(), 1u);
  EXPECT_TRUE(createResponse.results()[0].status_code().is_good());

  auto notification = wait_for_data_change(*mSession,
    subscriptionId,
    [](const DataChangeNotification& dataChange)
    {
      return std::ranges::any_of(dataChange.monitored_items(),
        [](const MonitoredItemNotification& item) { return item.client_handle() == handle; });
    });
  ASSERT_TRUE(notification.has_value());
  const auto item = std::ranges::find_if(notification->monitored_items(),
    [](const MonitoredItemNotification& candidate) { return candidate.client_handle() == handle; });
  ASSERT_NE(item, notification->monitored_items().end());
  EXPECT_EQ(item->value().status().value_or(StatusCode{}), StatusCode{Status::BadUserAccessDenied});
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-SVR-AUTHZ-019-BROWSE-CARVE-OUT, scope=function)
TEST_F(ComplianceWithNodes, ApplyRestrictionsToBrowseAloneControlsBrowseGating)
{
  auto node = mServer.server().address_space().find_node_sync(mEncryptionRequiredVariableId);
  node.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});

  auto firstBrowse = mSession->view().browse_sync(browse(mEncryptionRequiredVariableId));
  ASSERT_THAT(firstBrowse, ServiceResultIsGood());
  ASSERT_EQ(firstBrowse.results().size(), 1u);
  EXPECT_THAT(firstBrowse.results()[0], Good());

  auto firstRead = mSession->attributes().read_sync(read_value(mEncryptionRequiredVariableId));
  ASSERT_THAT(firstRead, ServiceResultIsGood());
  ASSERT_EQ(firstRead.results().size(), 1u);
  EXPECT_THAT(firstRead.results()[0], HasStatus(Status::BadSecurityModeInsufficient));

  node.set_access_restrictions(AccessRestrictionType{
    {AccessRestrictionType::Bit::EncryptionRequired, AccessRestrictionType::Bit::ApplyRestrictionsToBrowse}});
  auto secondBrowse = mSession->view().browse_sync(browse(mEncryptionRequiredVariableId));
  ASSERT_THAT(secondBrowse, ServiceResultIsGood());
  ASSERT_EQ(secondBrowse.results().size(), 1u);
  EXPECT_THAT(secondBrowse.results()[0], HasStatus(Status::BadSecurityModeInsufficient));

  auto secondRead = mSession->attributes().read_sync(read_value(mEncryptionRequiredVariableId));
  ASSERT_THAT(secondRead, ServiceResultIsGood());
  ASSERT_EQ(secondRead.results().size(), 1u);
  EXPECT_THAT(secondRead.results()[0], HasStatus(Status::BadSecurityModeInsufficient));
}

// D2 - the Write path carries no AccessRestrictions check at all. `ua_attribute_service_set.cpp`
// contains exactly one `access_restrictions` reference and it sits on the Read path, so a Node marked
// EncryptionRequired could stay writable over an unsecured channel if the shared Namespace verdict were
// bypassed. OPC 10000-2 section 3.1.1 admits no such asymmetry - the restrictions gate every operation on the
// Node, and a Write is the operation whose consequences are hardest to undo.
//
// The Read assertion is a control, not decoration: it proves the stamp actually landed on the Node,
// so a failing Write assertion cannot be explained away as "the Attribute was never set".
TEST_F(ComplianceWithNodes, AccessRestrictionsGateWriteOnNoneChannel)
{
  auto addressSpace = mServer.server().address_space();
  auto node = addressSpace.find_node_sync(mWritableVariableId);
  node.set_access_restrictions(AccessRestrictionType{
    {AccessRestrictionType::Bit::SigningRequired, AccessRestrictionType::Bit::EncryptionRequired}});

  // Control - the Read path does enforce the restriction, so the stamp is live on this Node.
  auto readResp = mSession->attributes().read_sync(read_value(mWritableVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_EQ(readResp.results().size(), 1u);
  const auto readStatus = readResp.results()[0].status();
  ASSERT_TRUE(readStatus.has_value());
  ASSERT_EQ(*readStatus, StatusCode{Status::BadSecurityModeInsufficient})
    << "control failed - the AccessRestrictions stamp never took effect, so the Write arm below "
       "would prove nothing";

  // Arm - the same restriction, same Node, same channel, must gate the Write.
  auto writeResult = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{99}}));
  ASSERT_THAT(writeResult, Good());
  EXPECT_THAT(std::move(writeResult).value(), WriteFailsWith(Status::BadSecurityModeInsufficient));
}

// D5 - UserAccessLevel is a pure projection of the complete Namespace verdict retained by the Read
// service. The verdict already combines RolePermissions with AccessRestrictions, so the projection
// must clamp capabilities when the negotiated channel cannot exercise them.
//
// This arm deliberately does NOT rest on a normative claim about UserAccessLevel itself. Part 3
// section 5.6.2 scopes the Attribute to "taking user access rights into account", and a channel condition
// is not a user access right, so whether the specification REQUIRES the clamp is arguable. What is
// not arguable is the contradiction pinned here: the Server advertises CurrentRead for the very
// Read it then refuses with Bad_SecurityModeInsufficient, and UserAccessLevel is exactly what a
// client consults to decide whether to attempt that Read.
// @relation(AC-SVR-AUTHZ-011-NO-ADVERTISED-BUT-REFUSED-READ, scope=function)
// @verifies AC-SVR-AUTHZ-011-NO-ADVERTISED-BUT-REFUSED-READ
TEST_F(ComplianceWithNodes, AccessRestrictionsClampUserAccessLevelOnNoneChannel)
{
  auto addressSpace = mServer.server().address_space();
  auto node = addressSpace.find_node_sync(mWritableVariableId);
  node.set_access_restrictions(AccessRestrictionType{
    {AccessRestrictionType::Bit::SigningRequired, AccessRestrictionType::Bit::EncryptionRequired}});

  // Half one of the contradiction - the Value Read is refused over this channel.
  auto valueResp = mSession->attributes().read_sync(read_value(mWritableVariableId));
  ASSERT_THAT(valueResp, ServiceResultIsGood());
  ASSERT_EQ(valueResp.results().size(), 1u);
  const auto valueStatus = valueResp.results()[0].status().value_or(StatusCode{});
  ASSERT_EQ(valueStatus, StatusCode{Status::BadSecurityModeInsufficient})
    << "control failed - the Value Read was not refused, so there is no contradiction to pin";

  // Half two - UserAccessLevel must not advertise the Read the Server has just refused. The
  // UserAccessLevel Read itself succeeds: it is a non-Value Attribute and therefore exempt from the
  // channel bits under the Table 37 Browse-permission carve-out. Its VALUE is what is under test.
  auto ualResp =
    mSession->attributes().read_sync(read_value(mWritableVariableId, AttributeId::UserAccessLevel));
  ASSERT_THAT(ualResp, ServiceResultIsGood());
  ASSERT_EQ(ualResp.results().size(), 1u);
  const std::uint8_t* raw = ualResp.results()[0].value().try_as<std::uint8_t>();
  ASSERT_NE(raw, nullptr) << "UserAccessLevel did not read back as a Byte";
  EXPECT_FALSE(AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentRead))
    << "UserAccessLevel advertises CurrentRead (0x" << std::hex << unsigned{*raw}
    << ") on a Node whose Value Read is refused with Bad_SecurityModeInsufficient";
}

// D3 - Namespace DefaultAccessRestrictions must be applied by the namespace-owned access-control
// path whenever a Node carries no override. Part 3 section 5.2.11 defines that default as the value applying
// to every Node in the Namespace that does not override it.
//
// No Node in this fixture's Namespace carries its own AccessRestrictions, so the delegate default
// is the only possible source of the restriction - which is exactly what makes these two arms
// isolate the fallback rather than the per-Node path D2 covers.
class ComplianceNamespaceDefaultRestrictions : public ComplianceWithNodes
{
protected:
  std::optional<AccessRestrictionType> test_namespace_access_restrictions() const override
  {
    return AccessRestrictionType{
      {AccessRestrictionType::Bit::SigningRequired, AccessRestrictionType::Bit::EncryptionRequired}};
  }
};

TEST_F(ComplianceNamespaceDefaultRestrictions, NamespaceDefaultGatesReadOnNoneChannel)
{
  auto resp = mSession->attributes().read_sync(read_value(mWritableVariableId));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  // A Good Read carries no explicit status, so an absent status means the restriction was ignored
  // and the value was handed over. Fold that into the comparison rather than asserting has_value(),
  // which would fail with an opaque "Actual: false".
  const auto status = resp.results()[0].status().value_or(StatusCode{});
  EXPECT_EQ(status, StatusCode{Status::BadSecurityModeInsufficient})
    << "namespace DefaultAccessRestrictions ignored - Read returned 0x" << std::hex << status.as_uint32();
}

TEST_F(ComplianceNamespaceDefaultRestrictions, NamespaceDefaultGatesCallOnNoneChannel)
{
  auto resp = mSession->methods().call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{2}}, Variant{int32_t{3}}}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  const auto status = resp.results()[0].status_code();
  EXPECT_EQ(status, StatusCode{Status::BadSecurityModeInsufficient})
    << "0x" << std::hex << status.as_uint32();
}

// Over a SignAndEncrypt channel (which clears the AccessRestriction) the array is
// readable and carries one SessionSecurityDiagnosticsDataType per live session.
// @relation(AC-SVR-BASE-077-AUTHORISED-ENCRYPTED-ARRAY, scope=function)
TEST_F(ComplianceSecuredWithSession, SessionSecurityDiagnosticsArray_PopulatedOverSecuredChannel)
{
  set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession =
    mChannel->create_session_sync({.sessionName = "SessionSecurityDiagnosticsEncryptedReader"});
  diagnosticsSession.activate_sync();

  auto resp = diagnosticsSession.attributes().read_sync(read_value(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.payload().size(), 1u)
    << "the live secured session must appear in SessionSecurityDiagnosticsArray";
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SessionSecurityDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr) << "each element must be a SessionSecurityDiagnosticsDataType";
  }
}

// ---------------------------------------------------------------------------
// SubscriptionDiagnosticsArray / SamplingIntervalDiagnosticsArray - live aggregate nodes
// ---------------------------------------------------------------------------
// Server.ServerDiagnostics.SubscriptionDiagnosticsArray is built per-read from the live
// subscription set across all sessions (via the SubscriptionRouter). With a subscription + one
// monitored item active, the array must contain a SubscriptionDiagnosticsDataType for our
// subscription carrying its identity, config, and live monitored-item count. (Falsifiable: an
// unwired handler / empty array fails the lookup; wrong field plumbing fails the field asserts.)
TEST_F(ComplianceWithNodes, SubscriptionDiagnosticsArray_ReflectsLiveSubscription)
{
  auto [subId, miId] =
    create_subscription_with_monitored_item(*mSession, mWritableVariableId, {.publishingInterval = 200.0});
  ASSERT_NE(subId, 0u);
  ASSERT_NE(miId, 0u);

  auto resp = mSession->attributes().read_sync(
    read_value(NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.payload().size(), 1u) << "the live subscription must appear in SubscriptionDiagnosticsArray";

  const SubscriptionDiagnosticsDataType* ours = nullptr;
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SubscriptionDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr) << "each element must be a SubscriptionDiagnosticsDataType";
    if (record->subscription_id() == subId)
      ours = record;
  }
  ASSERT_NE(ours, nullptr) << "our subscription id must be present in the array";
  EXPECT_FALSE(ours->session_id().is_null()) << "SessionId must identify the owning session";
  EXPECT_EQ(ours->monitored_item_count(), 1u);
  EXPECT_GT(ours->publishing_interval(), 0.0);
  EXPECT_GT(ours->max_keep_alive_count(), 0u);
  EXPECT_GT(ours->max_lifetime_count(), 0u);
}

// Server.ServerDiagnostics.SamplingIntervalDiagnosticsArray aggregates all live monitored items by
// their revised sampling interval. With a monitored item active, the array must contain an entry
// counting it. (Falsifiable: an unwired handler / empty array fails the count check.)
TEST_F(ComplianceWithNodes, SamplingIntervalDiagnosticsArray_ReflectsMonitoredItems)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);
  ASSERT_NE(subId, 0u);
  ASSERT_NE(miId, 0u);

  auto resp = mSession->attributes().read_sync(
    read_value(NodeId{VariableId::Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.payload().size(), 1u) << "an active monitored item must produce a sampling-interval entry";

  uint32_t totalMonitoredItems = 0;
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SamplingIntervalDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr) << "each element must be a SamplingIntervalDiagnosticsDataType";
    EXPECT_GE(record->max_monitored_item_count(), record->monitored_item_count());
    totalMonitoredItems += record->monitored_item_count();
  }
  EXPECT_GE(totalMonitoredItems, 1u) << "the live monitored item must be counted in a sampling interval";
}

// The cumulative SubscriptionDiagnostics counters advance as the subscription is exercised:
// servicing a Publish to deliver the initial-value DataChange bumps PublishRequestCount,
// DataChangeNotificationsCount, and NotificationsCount. These are recorded inside fulfill_publish
// before the PublishResponse is sent, so they are observable once the client has the notification.
TEST_F(ComplianceWithNodes, SubscriptionDiagnosticsArray_PublishCountersAdvance)
{
  using namespace std::chrono_literals;
  auto [subId, miId] = create_subscription_with_monitored_item(*mSession, mWritableVariableId);
  ASSERT_NE(subId, 0u);

  // Drive one serviced Publish that delivers the monitored item's initial value.
  drain_initial_publish(*mSession, subId, 2s);

  auto resp = mSession->attributes().read_sync(
    read_value(NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();

  const SubscriptionDiagnosticsDataType* ours = nullptr;
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SubscriptionDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr);
    if (record->subscription_id() == subId)
      ours = record;
  }
  ASSERT_NE(ours, nullptr);
  EXPECT_GE(ours->publish_request_count(), 1u);
  EXPECT_GE(ours->data_change_notifications_count(), 1u);
  EXPECT_GE(ours->notifications_count(), 1u);
}

// Every DESCRIPTIVE member of SessionDiagnosticsDataType is populated, not just the counters.
// Part 5 7.14 Table 79 makes all eight Mandatory components of SessionDiagnosticsVariableType, and
// 12.11's "need not provide the exact value" relaxation covers only the counting values ("Those
// numbers"), so it does not license leaving these empty.
//
// The probe session carries values that cannot arise by accident - a distinctive name, a
// non-default requested timeout, and a locale list - and is located in the array BY that name, so
// the row cannot pass against some other session's record. Before this, every field asserted below
// read empty or zero.
// @relation(AC-SVR-BASE-017-SESSION-DIAGNOSTICS-ARRAY-LIVE, scope=function)
TEST_F(ComplianceSession, SessionDiagnosticsCarriesTheDescriptiveFieldsNotJustCounters)
{
  constexpr std::string_view probeName = "cfg-matrix-descriptive-probe";
  constexpr int64_t requestedTimeoutMs = 90000;

  const auto before = DateTime::now();

  set_authentication_claims({{"diagnostics:full", "1"}});
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = std::chrono::milliseconds{requestedTimeoutMs},
      .sessionName = std::string{probeName}});
  Session::ActivateConfig activateCfg;
  activateCfg.localeIds.emplace_back("de");
  activateCfg.localeIds.emplace_back("en");
  session.activate_sync(std::move(activateCfg));
  ASSERT_TRUE(session.is_active());

  auto resp = session.attributes().read_sync(read_value(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());
  const auto& arr = resp.results()[0].value().as<Array<RefStructure<Structure>>>();

  const SessionDiagnosticsDataType* probe = nullptr;
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SessionDiagnosticsDataType*>(element.get());
    if (record != nullptr && std::string_view{record->session_name()} == probeName)
    {
      probe = record;
      break;
    }
  }
  // Finding the record BY NAME is itself the SessionName assertion: an unpopulated name makes the
  // probe unfindable among the live sessions.
  ASSERT_NE(probe, nullptr) << "no SessionDiagnostics entry carries the probe's SessionName";

  EXPECT_EQ(std::string_view{probe->client_description().application_uri()}, "urn:test:compliance:client")
    << "ClientDescription must be the ApplicationDescription the client sent on CreateSession";

  EXPECT_FALSE(std::string_view{probe->endpoint_url()}.empty())
    << "EndpointUrl must be the address the client used to reach the endpoint";

  ASSERT_EQ(probe->locale_ids().payload().size(), 2u)
    << "LocaleIds must carry the list supplied at ActivateSession";
  EXPECT_EQ(std::string_view{probe->locale_ids().payload()[0]}, "de");
  EXPECT_EQ(std::string_view{probe->locale_ids().payload()[1]}, "en");

  // The GRANTED timeout, not the requested one: 90 s is inside the fixture's bounds so the two
  // coincide here, but a zero would mean the field is simply unwritten.
  EXPECT_GT(probe->actual_session_timeout(), 0.0)
    << "ActualSessionTimeout must report the timeout the server granted";

  const auto after = DateTime::now();
  EXPECT_GE(probe->client_connection_time(), before)
    << "ClientConnectionTime must be the server time at which this session opened";
  EXPECT_LE(probe->client_connection_time(), after);
  EXPECT_GE(probe->client_last_contact_time(), probe->client_connection_time())
    << "ClientLastContactTime must be at or after the connection time";

  session.close_sync();
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// ServerStatus.BuildInfo - the configured product identity, member for member
// ---------------------------------------------------------------------------

// Part 5 section 6.3: BuildInfo is the machine-readable statement of which software build is running, so all
// six members must come from the configured identity rather than from placeholders. A plausible
// implementation populates the six child Variables (ProductUri ... BuildDate) and leaves the AGGREGATE
// BuildInfo Variable - the one node a client reads to get the whole record in a single Read -
// default-constructed; or it carries the five Strings and drops BuildDate, the only non-String member.
// Either way a fleet stays indistinguishable at exactly the moment an operator is correlating a defect
// against a version.
class ServerObjectBuildInfo : public ComplianceWithSession
{
protected:
  void configure_application_identity(ua::ApplicationIdentity& identity) override
  {
    // Distinctive per member, so a member wired to the wrong source shows up rather than matching by
    // coincidence.
    identity.buildInfo.product_uri() = String{"urn:test:server-object:product"};
    identity.buildInfo.manufacturer_name() = String{"ServerObject Manufacturer"};
    identity.buildInfo.product_name() = String{"ServerObject Product"};
    identity.buildInfo.software_version() = String{"4.5.6"};
    identity.buildInfo.build_number() = String{"build-98765"};
    identity.buildInfo.build_date() = mConfiguredBuildDate;
  }

  UtcTime mConfiguredBuildDate{2031, 3, 4, 5, 6, 7};
};

// @verifies AC-SVR-BASE-006-BUILDINFO
TEST_F(ServerObjectBuildInfo, BuildInfoReportsTheConfiguredProductIdentity)
{
  auto resp = mSession->attributes().read_sync(read_value(NodeId{VariableId::Server_ServerStatus_BuildInfo}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());

  const auto& value = resp.results()[0].value();
  ASSERT_TRUE(value.is_structure()) << "the BuildInfo Variable must read back as a structure";
  const auto* buildInfo = value.try_as<BuildInfo>();
  ASSERT_NE(buildInfo, nullptr) << "the BuildInfo Variable must carry a BuildInfo";

  EXPECT_EQ(std::string_view{buildInfo->product_uri()}, "urn:test:server-object:product");
  EXPECT_EQ(std::string_view{buildInfo->manufacturer_name()}, "ServerObject Manufacturer");
  EXPECT_EQ(std::string_view{buildInfo->product_name()}, "ServerObject Product");
  EXPECT_EQ(std::string_view{buildInfo->software_version()}, "4.5.6");
  EXPECT_EQ(std::string_view{buildInfo->build_number()}, "build-98765");
  EXPECT_FALSE(buildInfo->build_date().is_null()) << "BuildDate must be populated, not the null DateTime";
  EXPECT_EQ(buildInfo->build_date(), mConfiguredBuildDate)
    << "BuildDate must be the configured build time of this binary";
}

// ---------------------------------------------------------------------------
// ServerCapabilities - continuation-point maxima
// ---------------------------------------------------------------------------

// A small ceiling makes the boundary reachable in a test, and makes the enforcement arm falsifiable: a
// server that reclaimed at a hard-coded number instead of at the number it advertises fails here.
class ServerObjectContinuationPointLimits : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.server_capabilities().maxBrowseContinuationPoints = sConfiguredMaxBrowseContinuationPoints;
  }

  static constexpr uint16_t sConfiguredMaxBrowseContinuationPoints{2};
};

// Part 5 section 6.3.11 advertises the continuation-point maxima; Part 4 section 5.8.3 makes the advertised
// maximum the point at which a Session's own oldest point is reclaimed to serve a new Browse, and each
// maximum must be at least one (a zero would make pagination refusable and large nodes unbrowsable). A
// plausible implementation advertises a number it never enforces - reclaiming at a compiled-in constant, or
// refusing the browse past the ceiling with Bad_NoContinuationPoints instead of freeing the oldest - and
// a test that only read the three Properties would not see it.
// @verifies AC-SVR-BASE-008-CONTINUATIONPOINT-LIMITS
TEST_F(ServerObjectContinuationPointLimits, AdvertisedContinuationPointMaximaAreTheReclamationPoint)
{
  auto limits = mSession->attributes().read_sync(
    read_values({NodeId{VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints},
      NodeId{VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints},
      NodeId{VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints}}));
  ASSERT_THAT(limits, ServiceResultIsGood());
  ASSERT_EQ(limits.results().size(), 3u);
  ASSERT_THAT(limits.results()[0], Good());
  ASSERT_THAT(limits.results()[1], Good());
  ASSERT_THAT(limits.results()[2], Good());

  const auto* maxBrowse = limits.results()[0].value().try_as<uint16_t>();
  const auto* maxQuery = limits.results()[1].value().try_as<uint16_t>();
  const auto* maxHistory = limits.results()[2].value().try_as<uint16_t>();
  ASSERT_NE(maxBrowse, nullptr) << "MaxBrowseContinuationPoints must be advertised as a UInt16";
  ASSERT_NE(maxQuery, nullptr) << "MaxQueryContinuationPoints must be advertised as a UInt16";
  ASSERT_NE(maxHistory, nullptr) << "MaxHistoryContinuationPoints must be advertised as a UInt16";

  EXPECT_GE(*maxBrowse, uint16_t{1}) << "a Session must be able to hold at least one Browse point";
  EXPECT_GE(*maxQuery, uint16_t{1}) << "a Session must be able to hold at least one Query point";
  EXPECT_GE(*maxHistory, uint16_t{1}) << "a Session must be able to hold at least one HistoryRead point";

  ASSERT_EQ(*maxBrowse, sConfiguredMaxBrowseContinuationPoints)
    << "the advertised maximum must be the configured one, else the enforcement checked below is a "
       "different number from the one clients are told";

  // Hold exactly the advertised maximum. Each Browse pages TestFolder one reference at a time, so each
  // one is issued its own continuation point.
  std::vector<ContinuationPoint> held;
  for (uint16_t issued = 0; issued < *maxBrowse; ++issued)
  {
    auto browseResp =
      mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
    ASSERT_THAT(browseResp, ServiceResultIsGood());
    ASSERT_EQ(browseResp.results().size(), 1u);
    ASSERT_THAT(browseResp.results()[0], Good());
    ASSERT_FALSE(browseResp.results()[0].continuation_point().empty())
      << "browse " << (issued + 1) << " of " << *maxBrowse << " must be issued a continuation point";
    held.push_back(browseResp.results()[0].continuation_point());
  }
  ASSERT_EQ(held.size(), static_cast<std::size_t>(*maxBrowse));

  // One past the advertised maximum: reclamation, not refusal.
  auto overflow =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_THAT(overflow, ServiceResultIsGood());
  ASSERT_EQ(overflow.results().size(), 1u);
  EXPECT_THAT(overflow.results()[0], Good()) << "the Browse past the ceiling must still succeed";
  EXPECT_FALSE(overflow.results()[0].continuation_point().empty())
    << "and must still be issued a continuation point of its own";

  // The Session's OLDEST point is the one freed...
  auto oldest = mSession->view().browse_next_sync(browse_next(held.front(), /*release=*/false));
  ASSERT_EQ(oldest.results().size(), 1u);
  EXPECT_THAT(oldest.results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "the oldest point must be the one reclaimed to make room";

  // ...and nothing below the maximum is: the point issued at the ceiling still continues its Browse.
  auto survivor = mSession->view().browse_next_sync(browse_next(held.back(), /*release=*/false));
  ASSERT_EQ(survivor.results().size(), 1u);
  EXPECT_THAT(survivor.results()[0], Good())
    << "reclamation must not begin before the advertised maximum is exceeded";
  EXPECT_FALSE(survivor.results()[0].references().empty())
    << "a surviving point must still return the next page";
}

// ---------------------------------------------------------------------------
// ServerCapabilities - MaxMonitoredItemsQueueSize
// ---------------------------------------------------------------------------

// A configured ceiling distinct from the SDK default: a server that clamped to a compiled-in 1000 rather
// than to the value it advertises is then visible.
class ServerObjectMonitoredItemQueueCeiling : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.server_capabilities().maxMonitoredItemsQueueSize = sConfiguredMaxQueueSize;
  }

  static constexpr uint32_t sConfiguredMaxQueueSize{5};
};

// Part 5 section 6.3: MaxMonitoredItemsQueueSize is the advertised form of the clamp CreateMonitoredItems
// applies, so a client can size its request upfront. A plausible implementation advertises the
// capability from configuration but clamps from an unrelated default (or rejects the over-large request
// outright), leaving a client that trusted the advertisement with a queue it did not ask for and no way
// to tell.
// @verifies AC-SVR-BASE-013-MAXQUEUESIZE
TEST_F(ServerObjectMonitoredItemQueueCeiling, RevisedQueueSizeIsTheAdvertisedMaximum)
{
  auto advertisedResp = mSession->attributes().read_sync(
    read_value(NodeId{VariableId::Server_ServerCapabilities_MaxMonitoredItemsQueueSize}));
  ASSERT_THAT(advertisedResp, ServiceResultIsGood());
  ASSERT_EQ(advertisedResp.results().size(), 1u);
  ASSERT_THAT(advertisedResp.results()[0], Good());
  const auto* advertised = advertisedResp.results()[0].value().try_as<uint32_t>();
  ASSERT_NE(advertised, nullptr) << "MaxMonitoredItemsQueueSize must be advertised as a UInt32";
  ASSERT_GE(*advertised, 1u);
  ASSERT_EQ(*advertised, sConfiguredMaxQueueSize)
    << "the advertised maximum must be the configured one, else the clamp checked below is a different "
       "number from the one clients are told";

  auto subId = create_subscription(*mSession, {.publishingInterval = 200.0});
  ASSERT_NE(subId, 0u);

  const uint32_t requested = *advertised + 10u;
  auto created = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subId, mWritableVariableId, {.queueSize = requested}));
  ASSERT_THAT(created, ServiceResultIsGood());
  ASSERT_EQ(created.results().size(), 1u);
  ASSERT_THAT(created.results()[0], Good()) << "an over-large queue request is clamped, not refused";
  EXPECT_EQ(created.results()[0].revised_queue_size(), *advertised)
    << "requested " << requested << ": the revised queue size must be the advertised maximum";

  delete_subscription(*mSession, subId);
}

// ---------------------------------------------------------------------------
// Built-in DataTypes
// ---------------------------------------------------------------------------

// Part 5 section 12: the built-in DataType NodeIds are hard-coded in every client, so a server that bound one
// of those ids to a different DataType would decode nothing correctly - and the failure would present as
// corruption, not as a mismatch. A plausible implementation imports a trimmed NodeSet that omits the
// abstract or less-common members of the family (Decimal, Number, UInteger, the DateTime subtypes) while
// every generated encode/decode test keeps passing, because those tests presume the ids rather than
// resolving them.
// @verifies AC-SVR-BASE-022-BUILTIN-DATATYPES
TEST_F(ComplianceWithNodes, BuiltInDataTypesAreRegisteredWithTheirSpecifiedNodeIds)
{
  struct BuiltInDataType
  {
    DataTypeId id;
    std::string_view browseName;
  };

  const std::vector<BuiltInDataType> builtIns{{DataTypeId::DateTime, "DateTime"},
    {DataTypeId::UtcTime, "UtcTime"},
    {DataTypeId::Duration, "Duration"},
    {DataTypeId::Decimal, "Decimal"},
    {DataTypeId::Number, "Number"},
    {DataTypeId::Integer, "Integer"},
    {DataTypeId::UInteger, "UInteger"},
    {DataTypeId::Enumeration, "Enumeration"},
    {DataTypeId::SByte, "SByte"},
    {DataTypeId::Byte, "Byte"},
    {DataTypeId::Int16, "Int16"},
    {DataTypeId::UInt16, "UInt16"},
    {DataTypeId::Int32, "Int32"},
    {DataTypeId::UInt32, "UInt32"},
    {DataTypeId::Int64, "Int64"},
    {DataTypeId::UInt64, "UInt64"},
    {DataTypeId::Float, "Float"},
    {DataTypeId::Double, "Double"}};
  ASSERT_FALSE(builtIns.empty());

  for (const auto& builtIn : builtIns)
  {
    auto resp =
      mSession->attributes().read_sync(ReadRequestBuilder()
                                         .read(NodeId{builtIn.id})
                                         .attributes({AttributeId::NodeClass, AttributeId::BrowseName}));
    ASSERT_THAT(resp, ServiceResultIsGood()) << builtIn.browseName;
    ASSERT_EQ(resp.results().size(), 2u) << builtIn.browseName;
    ASSERT_THAT(resp.results()[0], Good())
      << builtIn.browseName << " must resolve to a Node at its specified id";
    ASSERT_THAT(resp.results()[1], Good()) << builtIn.browseName;

    const auto* nodeClass = resp.results()[0].value().try_as<int32_t>();
    ASSERT_NE(nodeClass, nullptr) << builtIn.browseName;
    EXPECT_EQ(*nodeClass, static_cast<int32_t>(NodeClass::DataType))
      << builtIn.browseName << " must be registered as a DataType Node";

    const auto* browseName = resp.results()[1].value().try_as<QualifiedName>();
    ASSERT_NE(browseName, nullptr) << builtIn.browseName;
    EXPECT_EQ(browseName->namespace_index(), uint16_t{0})
      << builtIn.browseName << " is a standard type and belongs to namespace 0";
    EXPECT_EQ(std::string_view{browseName->name()}, builtIn.browseName)
      << "id " << static_cast<uint32_t>(builtIn.id)
      << " must be the DataType the specification assigns that id";
  }
}

// ---------------------------------------------------------------------------
// ResendData - every REPORTING item, not just one
// ---------------------------------------------------------------------------

// Part 5 section 9.2 (and Part 4 section 5.12.2.3): ResendData exists so a client that lost its cache can
// rebuild it, which requires the current value of EVERY MonitoredItem of the Subscription in REPORTING mode
// to be requeued, changed or not. A plausible implementation requeues only the first item of the
// Subscription, or routes the requeue through the ordinary change filter so unchanged items are dropped -
// both pass a single-item test and still hand the recovering client a half-rebuilt cache. Nothing in this
// test writes a value, so only ResendData can produce the second round of notifications.
// @verifies AC-SVR-BASE-025-RESENDDATA
TEST_F(ComplianceWithNodes, ResendDataRequeuesEveryReportingItemsCurrentValue)
{
  constexpr uint32_t firstHandle{21};
  constexpr uint32_t secondHandle{22};
  constexpr int32_t firstValue{42};  // WritableInt32, as seeded by the fixture
  constexpr int32_t secondValue{0};  // FullAccessInt32, as seeded by the fixture

  auto created = create_subscription_with_monitored_item(
    *mSession, mWritableVariableId, {.publishingInterval = 50.0}, {.clientHandle = firstHandle});
  const uint32_t subId = created.subscriptionId;
  ASSERT_NE(subId, 0u);
  ASSERT_NE(created.monitoredItemId, 0u);

  auto second = mSession->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subId, mFullAccessVariableId, {.clientHandle = secondHandle}));
  ASSERT_THAT(second, ServiceResultIsGood());
  ASSERT_EQ(second.results().size(), 1u);
  ASSERT_THAT(second.results()[0], Good()) << "the second REPORTING item must be created";

  bool sawFirst = false;
  bool sawSecond = false;
  auto collect = [&](std::chrono::milliseconds budget)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!(sawFirst && sawSecond) && std::chrono::steady_clock::now() < deadline)
    {
      auto notification = wait_for_data_change(*mSession, subId, 500ms);
      if (!notification)
        continue;
      for (const auto& item : notification->monitored_items())
      {
        const auto* payload = item.value().value().try_as<int32_t>();
        if (payload == nullptr)
          continue;
        if (item.client_handle() == firstHandle && *payload == firstValue)
          sawFirst = true;
        if (item.client_handle() == secondHandle && *payload == secondValue)
          sawSecond = true;
      }
    }
  };

  // Both items report their initial value first. Draining that is what stops the observation below from
  // being satisfied by a leftover initial-value notification.
  collect(4s);
  ASSERT_TRUE(sawFirst && sawSecond)
    << "both monitored items must have reported an initial value before ResendData can be shown to "
       "requeue them again";

  sawFirst = false;
  sawSecond = false;

  auto result = call_resend_data(*mSession, subId);
  ASSERT_THAT(result, Good()) << "0x" << std::hex << result.status_code().as_uint32();

  collect(4s);
  EXPECT_TRUE(sawFirst) << "the first REPORTING item's current value was not requeued by ResendData";
  EXPECT_TRUE(sawSecond) << "the second REPORTING item's current value was not requeued by ResendData";

  delete_subscription(*mSession, subId);
}

// Part 5 section 12.11, the `authenticationMechanism` row of SessionSecurityDiagnosticsDataType: "The String
// shall be one of the lexical names of the UserIdentityTokenType Enum." Those names are the UserTokenType
// (i=303) DataType Definition fields in Opc.Ua.NodeSet2.xml, which its EnumStrings repeat: `Anonymous`,
// `UserName`, `Certificate`, `IssuedToken`. Part 4 section 7.43 Table 197 renders them upper-cased, but that
// is the document's styling for every enumeration it tabulates - Table 115 shows ApplicationType as
// SERVER/CLIENT/CLIENTANDSERVER while the NodeSet spells it Server/Client/ClientAndServer - so the
// machine-readable definition, not the table, fixes the spelling.
//
// The obligation is about a closed vocabulary, not a human-readable label, and the difference is the
// point of the clause. This field is what an operator's audit tooling groups sessions by, and grouping
// only works if every Server spells the mechanism the same way - which is why the specification names
// the source of the spelling rather than describing it. A Server that invents its own casing produces
// diagnostics that read correctly to a person and cannot be joined against another Server's by a
// machine.
//
// It sits on this fixture rather than beside the negotiated-security rows because the array has to be
// populated and the reader must hold the `diagnostics:full` claim. The mutable fixture authenticator is
// updated first and a fresh secured Session is activated, matching the separately proven authorised-array
// control above.
//
// @relation(AC-SVR-BASE-096-AUTHENTICATIONMECHANISM-LEXICAL, scope=function)
TEST_F(ComplianceSecuredWithSession, EverySessionReportsItsAuthenticationMechanismAsAUserTokenTypeLexicalName)
{
  set_authentication_claims({{"diagnostics:full", "1"}});
  auto diagnosticsSession =
    mChannel->create_session_sync({.sessionName = "AuthenticationMechanismDiagnosticsReader"});
  diagnosticsSession.activate_sync();

  auto resp = diagnosticsSession.attributes().read_sync(read_value(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray}));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);

  ASSERT_THAT(resp.results()[0], Good())
    << "the lexical-name assertion requires an authorised diagnostics read";
  const auto& value = resp.results()[0].value();
  ASSERT_TRUE(value.is_array())
    << "SessionSecurityDiagnosticsArray did not answer an array at all, so the spelling of the field "
       "inside it cannot be read. That is a different failure from this obligation and is the one "
       "`SessionSecurityDiagnosticsArray_PopulatedOverSecuredChannel` pins";
  const auto& arr = value.as<Array<RefStructure<Structure>>>();
  ASSERT_GE(arr.payload().size(), 1u)
    << "no SessionSecurityDiagnostics entry was published, so the field this obligation is stated over "
       "was never read";

  // The NodeSet definition's names, and nothing else. The SDK's `Unknown` fallback is deliberately
  // not admitted: the enumeration has no such member, so a Server with nothing to report owes one
  // of these four rather than a fifth word of its own.
  const std::set<std::string> lexicalNames{"Anonymous", "UserName", "Certificate", "IssuedToken"};

  std::vector<std::string> wrong;
  std::size_t inspected = 0;
  for (const auto& element : arr.payload())
  {
    const auto* record = dynamic_cast<const SessionSecurityDiagnosticsDataType*>(element.get());
    ASSERT_NE(record, nullptr) << "each element must be a SessionSecurityDiagnosticsDataType";
    ++inspected;
    const std::string mechanism{static_cast<std::string_view>(record->authentication_mechanism())};
    if (lexicalNames.count(mechanism) == 0u)
      wrong.push_back(ua::to_string(record->session_id()) + " reports '" + mechanism + "'");
  }

  ASSERT_GT(inspected, 0u) << "no entry decoded, so this proves nothing";
  EXPECT_TRUE(wrong.empty())
    << wrong.size() << " session(s) report an authenticationMechanism that is not a UserIdentityTokenType "
    << "lexical name, first: " << (wrong.empty() ? std::string{} : wrong.front())
    << ". Part 5 names the enumeration as the source of the spelling precisely so that audit tooling can "
       "group sessions across Servers; a Server that invents its own casing produces diagnostics a person "
       "reads correctly and a machine cannot join";
}

// Part 4 5.12.2.3: ResendData resends the value last sent, not a new sample - so it carries the timestamps
// that value was published with (the CTT's Base Info ResendData Method 002). ServerStatus.CurrentTime
// comes from a source that sets no ServerTimestamp, so the server's own stamp is under test, and the long
// sampling interval keeps a fresh sample from arriving in between.
TEST_F(ComplianceWithNodes, ResendData_ResendsTheLastValueWithItsTimestamps)
{
  auto [subId, miId] = create_subscription_with_monitored_item(
    *mSession, NodeId{VariableId::Server_ServerStatus_CurrentTime}, {}, {.samplingInterval = 60000.0});
  auto first = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(first.has_value());
  ASSERT_EQ(first->monitored_items().size(), 1u);
  const DataValue published = first->monitored_items()[0].value();
  ASSERT_TRUE(published.server_timestamp().has_value());

  ASSERT_TRUE(call_resend_data(*mSession, subId).status_code().is_good());
  auto resent = wait_for_data_change(*mSession, subId);
  ASSERT_TRUE(resent.has_value()) << "ResendData must resend the last value";
  ASSERT_EQ(resent->monitored_items().size(), 1u);
  EXPECT_EQ(resent->monitored_items()[0].value(), published)
    << "the resent value is the published one, timestamps included";
}

namespace
{

/// Whether SessionsDiagnosticsSummary has a component with this BrowseName.
bool has_session_diagnostics_node(Session& session, const std::string& browseName)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));
  auto resp = session.view().browse_sync(std::move(req));
  if (resp.results().empty())
    return false;
  for (const auto& ref : resp.results()[0].references())
  {
    if (std::string{ref.browse_name().name()} == browseName)
      return true;
  }
  return false;
}

}  // namespace

// CloseSession answers once the Session is gone, its diagnostics node included (OPC 10000-5 6.3.4). The CTT's
// Base Info Diagnostics 019 browses SessionsDiagnosticsSummary the moment CloseSession returns, with no
// retry; a server that answered first and removed the node afterwards failed it whenever the removal lost the
// race.
TEST_F(ComplianceWithNodes, CloseSessionAnswersOnlyOnceTheSessionsDiagnosticsNodeIsGone)
{
  const std::string name = "DiagnosticsNodeCloseOrder";
  auto closing = mChannel->create_session_sync({.sessionName = name});
  closing.activate_sync();
  bool present = false;
  for (int attempt = 0; attempt < 50 && !present; ++attempt)
  {
    present = has_session_diagnostics_node(*mSession, name);
    if (!present)
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
  }
  ASSERT_TRUE(present) << "the Session's diagnostics node never appeared";

  ASSERT_TRUE(closing.try_close_sync().is_good());
  EXPECT_FALSE(has_session_diagnostics_node(*mSession, name))
    << "CloseSession answered while the Session's diagnostics node was still in the address space";
}
