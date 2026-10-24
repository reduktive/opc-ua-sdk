// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// ErrorDetail Integration Tests
///
/// Validates full round-trip propagation of ErrorDetail through the server's
/// DiagnosticCollector into DiagnosticInfo on the wire, and back into ErrorDetail
/// on the client side via diagnostic_to_error_detail().
///
/// The tests exercise:
///   1. Service faults (too many operations, empty requests) with full cause chains.
///   2. Per-item diagnostics on mixed valid/invalid reads and writes.
///   3. Gating: no cause chain when diagnostics are not requested.
///   4. ErrorDetail on UaException thrown by _sync methods.
///   5. to_string() produces readable chained output.

#include "compliance_helpers.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_view_services.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_diagnostic_to_error_detail.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_configuration.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <gmock/gmock.h>

using namespace ua;
using namespace ua::client;
using namespace ua::server;

// ===========================================================================
// Helpers
// ===========================================================================

static ReadValueId make_read_value_id(NodeId nodeId, AttributeId attr = AttributeId::Value)
{
  ReadValueId rv;
  rv.node_id() = std::move(nodeId);
  rv.attribute_id() = static_cast<uint32_t>(attr);
  return rv;
}

static void request_full_diagnostics(RequestHeader& header)
{
  header.return_diagnostics() = 0xFFFF;
}

// ===========================================================================
// ErrorDetailServiceFault - service-level faults with diagnostic cause chains
// ===========================================================================

class ErrorDetailServiceFault : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.server_capabilities().operationLimits.maxNodesPerRead = 1;
    cfg.server.server_capabilities().operationLimits.maxNodesPerWrite = 1;
    cfg.server.server_capabilities().operationLimits.maxNodesPerBrowse = 1;
    cfg.server.server_capabilities().operationLimits.maxNodesPerMethodCall = 1;
    cfg.server.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::Sign;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelCfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ErrorDetailTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ---------------------------------------------------------------------------
// Bug caught: server returns BadTooManyOperations but without diagnostics, the
// client has no idea *which* service or *why* it failed. With diagnostics, the
// ErrorDetail cause chain contains the service name and human-readable message.
// ---------------------------------------------------------------------------

// Covers SVR-DIAG-001, SVR-DIAG-002 (coverage-audit retag).
// @verifies CL-DIAG-005
// End-to-end proof (real server) that the always-on wire-crossing marker is attached on the general data
// surface: a bad service_result surfaces as ServiceFault -> marker -> server.symbolic.<code> server chain.
// @relation(CL-DIAG-005, SVR-DIAG-001, SVR-DIAG-002, SVR-DIAG-005, SVR-DIAG-009, SVR-DIAG-015, scope=function)
TEST_F(ErrorDetailServiceFault, ReadTooManyOperations_FullCauseChain)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_read_sync(std::move(req));
  ASSERT_TRUE(result.is_bad()) << "Expected BadTooManyOperations for 2 reads with limit 1";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});

  // The client wraps the server fault in a "ServiceFault" ErrorDetail with the server's
  // DiagnosticInfo as the cause.
  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "Expected ErrorDetail on the result";
  EXPECT_EQ(detail->code, "ServiceFault");
  EXPECT_EQ(detail->source, "server");

  // CL-DIAG-005: an always-on client "wire-crossing marker" ErrorDetail now sits between the
  // client ServiceFault wrapper and the server diagnostic, so the server cause hangs one level
  // deeper (under the marker) and its code gains a "server.symbolic." prefix.
  ASSERT_NE(detail->cause, nullptr) << "Expected the client wire-crossing marker";
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr) << "Expected server diagnostic cause chain";
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.TooManyNodesToRead");
  EXPECT_EQ(detail->cause->cause->source, "AttributeServiceSet");
  // The requested-vs-limit numbers now ride in structured context (size.*), not the prose.
  EXPECT_THAT(detail->cause->cause->summary, ::testing::HasSubstr("exceeds"));
  EXPECT_FALSE(detail->cause->cause->context.empty())
    << "too-many-operations facts must ride in structured context, not interpolated prose";

  std::cerr << "\n>>> " << ::testing::UnitTest::GetInstance()->current_test_info()->name()
            << " (client error_detail):\n"
            << to_string(*detail) << "\n";
}

// @relation(SVR-DIAG-002, scope=function)
TEST_F(ErrorDetailServiceFault, ReadEmptyRequest_FullCauseChain)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  // No nodes added - empty request.
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_read_sync(std::move(req));
  ASSERT_TRUE(result.is_bad()) << "Expected BadNothingToDo for empty read";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ServiceFault");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.EmptyReadRequest");
  EXPECT_EQ(detail->cause->cause->source, "AttributeServiceSet");
}

TEST_F(ErrorDetailServiceFault, WriteTooManyOperations_FullCauseChain)
{
  WriteRequest req;
  WriteValue wv1;
  wv1.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  wv1.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  wv1.value() = DataValue{Variant{int32_t{0}}};
  WriteValue wv2;
  wv2.node_id() = NodeId{VariableId::Server_ServerStatus_CurrentTime};
  wv2.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  wv2.value() = DataValue{Variant{int32_t{0}}};
  req.nodes_to_write().push_back(std::move(wv1));
  req.nodes_to_write().push_back(std::move(wv2));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_write_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ServiceFault");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.TooManyNodesToWrite");
  EXPECT_EQ(detail->cause->cause->source, "AttributeServiceSet");
  // The requested-vs-limit numbers now ride in structured context (size.*), not the prose.
  EXPECT_THAT(detail->cause->cause->summary, ::testing::HasSubstr("exceeds"));
  EXPECT_FALSE(detail->cause->cause->context.empty())
    << "too-many-operations facts must ride in structured context, not interpolated prose";
}

TEST_F(ErrorDetailServiceFault, WriteEmptyRequest_FullCauseChain)
{
  WriteRequest req;
  // No nodes added.
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_write_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.EmptyWriteRequest");
}

TEST_F(ErrorDetailServiceFault, BrowseTooManyOperations_FullCauseChain)
{
  BrowseRequest req;
  BrowseDescription desc1;
  desc1.node_id() = NodeId{ObjectId::ObjectsFolder};
  desc1.browse_direction() = BrowseDirection::Forward;
  desc1.include_subtypes() = true;
  desc1.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  BrowseDescription desc2;
  desc2.node_id() = NodeId{ObjectId::TypesFolder};
  desc2.browse_direction() = BrowseDirection::Forward;
  desc2.include_subtypes() = true;
  desc2.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc1));
  req.nodes_to_browse().push_back(std::move(desc2));
  request_full_diagnostics(req.request_header());

  auto result = mSession->view().try_browse_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ServiceFault");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.TooManyNodesToBrowse");
  EXPECT_EQ(detail->cause->cause->source, "BrowseService");
  // The requested-vs-limit numbers now ride in structured context (size.*), not the prose.
  EXPECT_THAT(detail->cause->cause->summary, ::testing::HasSubstr("exceeds"));
  EXPECT_FALSE(detail->cause->cause->context.empty())
    << "too-many-operations facts must ride in structured context, not interpolated prose";
}

TEST_F(ErrorDetailServiceFault, BrowseEmptyRequest_FullCauseChain)
{
  BrowseRequest req;
  // No nodes added.
  request_full_diagnostics(req.request_header());

  auto result = mSession->view().try_browse_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.EmptyBrowseRequest");
}

TEST_F(ErrorDetailServiceFault, CallTooManyOperations_FullCauseChain)
{
  CallRequest req;
  CallMethodRequest cm1;
  cm1.object_id() = NodeId{ObjectId::ObjectsFolder};
  cm1.method_id() = NodeId{0, uint32_t{12345}};  // Fake method, doesn't matter - limit check is first.
  CallMethodRequest cm2;
  cm2.object_id() = NodeId{ObjectId::ObjectsFolder};
  cm2.method_id() = NodeId{0, uint32_t{12346}};
  req.methods_to_call().push_back(std::move(cm1));
  req.methods_to_call().push_back(std::move(cm2));
  request_full_diagnostics(req.request_header());

  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ServiceFault");
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.TooManyMethodsToCall");
  EXPECT_EQ(detail->cause->cause->source, "MethodService");
}

TEST_F(ErrorDetailServiceFault, CallEmptyRequest_FullCauseChain)
{
  CallRequest req;
  // No methods added.
  request_full_diagnostics(req.request_header());

  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  ASSERT_NE(detail->cause->cause, nullptr);
  EXPECT_EQ(detail->cause->cause->code, "server.symbolic.EmptyCallRequest");
}

// ---------------------------------------------------------------------------
// Gating: when return_diagnostics is 0, the server must NOT emit diagnostic
// info. CL-DIAG-005's always-on client wire-crossing marker is still present
// beneath the "ServiceFault" wrapper, but it has no server diagnostic below it.
// ---------------------------------------------------------------------------

// @verifies CL-DIAG-005
// The marker is ALWAYS on: even at returnDiagnostics=0 (no server DiagnosticInfo) the wire-crossing marker is
// attached, with no server cause below it. This is the defining always-on property of CL-DIAG-005.
// @relation(CL-DIAG-005, SVR-DIAG-011, SVR-DIAG-015, scope=function)
TEST_F(ErrorDetailServiceFault, NoDiagnosticsRequested_NoCauseChain)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  // Explicitly set return_diagnostics to 0 - no diagnostics requested.
  req.request_header().return_diagnostics() = 0;

  auto result = mSession->attributes().try_read_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});

  // The client still creates the top-level "ServiceFault" wrapper.
  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ServiceFault");
  // The always-on wire-crossing marker is still present, but with no server diagnostic below it
  // because diagnostics were not requested.
  ASSERT_NE(detail->cause, nullptr) << "Expected the always-on client wire-crossing marker";
  EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
  EXPECT_EQ(detail->cause->cause, nullptr) << "Expected no server cause chain when diagnostics not requested";
}

// ---------------------------------------------------------------------------
// to_string() produces a readable representation of the chained ErrorDetail.
// ---------------------------------------------------------------------------

// @relation(SVR-DIAG-005, scope=function)
TEST_F(ErrorDetailServiceFault, ToString_ProducesReadableChainedOutput)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_read_sync(std::move(req));
  ASSERT_TRUE(result.is_bad());

  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);

  auto str = to_string(*detail);
  // The string should contain both the client wrapper and the server cause.
  EXPECT_THAT(str, ::testing::HasSubstr("ServiceFault"));
  EXPECT_THAT(str, ::testing::HasSubstr("TooManyNodesToRead"));
  EXPECT_THAT(str, ::testing::HasSubstr("caused by"));
}

// ---------------------------------------------------------------------------
// The _sync throwing variant should include ErrorDetail on UaException.
// ---------------------------------------------------------------------------

TEST_F(ErrorDetailServiceFault, UaExceptionFromSync_ContainsErrorDetail)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  request_full_diagnostics(req.request_header());

  try
  {
    mSession->attributes().read_sync(std::move(req));
    FAIL() << "Expected UaException to be thrown";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadTooManyOperations);
    auto* detail = ex.detail();
    ASSERT_NE(detail, nullptr) << "UaException should carry ErrorDetail";
    EXPECT_EQ(detail->code, "ServiceFault");
    ASSERT_NE(detail->cause, nullptr);
    EXPECT_EQ(detail->cause->source, "client.tier0.session.decode_diagnostic");
    ASSERT_NE(detail->cause->cause, nullptr);
    EXPECT_EQ(detail->cause->cause->code, "server.symbolic.TooManyNodesToRead");
  }
}

// ---------------------------------------------------------------------------
// returnDiagnostics is a per-field bitmask, honoured field by field.
// ---------------------------------------------------------------------------

// Single-item write to a read-only Variable: fails at the operation level with a leaf
// ErrorDetail (code + source + summary + node-id context, no inner status, no cause).
static WriteRequest make_read_only_write_request(uint32_t returnDiagnostics)
{
  WriteRequest req;
  WriteValue wv;
  wv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  wv.value() = DataValue{Variant{int32_t{0}}};
  req.nodes_to_write().push_back(std::move(wv));
  req.request_header().return_diagnostics() = returnDiagnostics;
  return req;
}

// Two reads against a MaxNodesPerRead of 1: fails at the service level with a leaf
// ErrorDetail (code + source + summary + size context, no inner status, no cause).
static ReadRequest make_over_limit_read_request(uint32_t returnDiagnostics)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  req.request_header().return_diagnostics() = returnDiagnostics;
  return req;
}

// Part 4 section 7.27: returnDiagnostics is a ten-bit field selector, not a boolean. Each bit names one
// DiagnosticInfo field at one level (service-wide vs per-operation), and zero means the server
// emits nothing at all even though it holds a full ErrorDetail chain internally. The plausible
// wrong implementation treats the mask as "any bit set => attach everything I have", which both
// leaks fields the client did not ask for and - at zero - leaks the whole chain to a client that
// asked for none precisely because the channel is untrusted. The second plausible error is
// cross-level bleed: an operation-level bit switching on ResponseHeader.serviceDiagnostics.
// @verifies AC-SVR-DIAG-011-RETURNDIAGNOSTICS-HONOURED
TEST_F(ErrorDetailServiceFault, ReturnDiagnosticsBitmaskDecidesWhichDiagnosticsAreReturned)
{
  constexpr uint32_t serviceSymbolicId = 0x0001;
  constexpr uint32_t serviceLocalizedText = 0x0002;
  constexpr uint32_t serviceAdditionalInfo = 0x0004;
  constexpr uint32_t serviceInnerStatusCode = 0x0008;
  constexpr uint32_t serviceInnerDiagnostics = 0x0010;
  constexpr uint32_t operationSymbolicId = 0x0020;
  constexpr uint32_t operationLocalizedText = 0x0040;
  constexpr uint32_t operationAdditionalInfo = 0x0080;
  constexpr uint32_t operationInnerStatusCode = 0x0100;
  constexpr uint32_t operationInnerDiagnostics = 0x0200;
  constexpr uint32_t allOperationBits = 0x03E0;
  constexpr uint32_t allServiceBits = 0x001F;

  // -------------------------------------------------------------------------
  // Non-vacuity, operation level: with every operation-level bit set the server DOES hold and
  // emit a per-operation diagnostic for this stimulus. Whatever the narrower masks below fail to
  // produce was therefore suppressed on purpose, not simply never generated.
  // -------------------------------------------------------------------------
  {
    SCOPED_TRACE("all operation-level bits");
    auto result = mSession->attributes().try_write_sync(make_read_only_write_request(allOperationBits));
    ASSERT_TRUE(result.is_good()) << "Single-item write is within the limit; the failure is per-item";
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].is_bad()) << "Writing to a read-only variable must be rejected";
    ASSERT_GE(resp.diagnostic_infos().size(), 1u);
    const auto& info = resp.diagnostic_infos()[0];
    ASSERT_FALSE(info.is_null()) << "The server has a per-operation ErrorDetail for this rejection";
    EXPECT_TRUE(info.symbolic_id().has_value());
    EXPECT_TRUE(info.namespace_uri().has_value());
    EXPECT_TRUE(info.localized_text().has_value());
    EXPECT_TRUE(info.additional_info().has_value());
  }

  // -------------------------------------------------------------------------
  // returnDiagnostics == 0: no diagnostic information reaches the wire - no per-operation
  // envelope, no service-wide envelope, and no string table to resolve either against. The
  // numeric StatusCode still reaches the client.
  // -------------------------------------------------------------------------
  {
    SCOPED_TRACE("returnDiagnostics == 0");
    auto result = mSession->attributes().try_write_sync(make_read_only_write_request(0));
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_bad()) << "The numeric StatusCode still crosses the wire";
    EXPECT_EQ(resp.diagnostic_infos().size(), 0u)
      << "No diagnostics requested: the per-operation array must stay empty";
    EXPECT_TRUE(resp.response_header().service_diagnostics().is_null())
      << "No diagnostics requested: serviceDiagnostics must stay empty";
    EXPECT_EQ(resp.response_header().string_table().size(), 0u)
      << "No diagnostics requested: nothing may be interned into the string table";
  }

  // -------------------------------------------------------------------------
  // Each operation-level bit in isolation returns exactly the field it names, and nothing else.
  // The rejection's ErrorDetail is a leaf (built with no cause and a Good inner status), so the
  // two chain bits must produce a completely empty envelope rather than falling back to the
  // fields that were not asked for.
  // -------------------------------------------------------------------------
  struct OperationBitCase
  {
    uint32_t mask;
    const char* name;
    bool symbolicId;
    bool localizedText;
    bool additionalInfo;
  };

  const OperationBitCase operationCases[] = {
    {operationSymbolicId, "OperationSymbolicId only", true, false, false},
    {operationLocalizedText, "OperationLocalizedText only", false, true, false},
    {operationAdditionalInfo, "OperationAdditionalInfo only", false, false, true},
    {operationInnerStatusCode, "OperationInnerStatusCode only", false, false, false},
    {operationInnerDiagnostics, "OperationInnerDiagnostics only", false, false, false},
  };

  for (const auto& bitCase : operationCases)
  {
    SCOPED_TRACE(bitCase.name);
    auto result = mSession->attributes().try_write_sync(make_read_only_write_request(bitCase.mask));
    ASSERT_TRUE(result.is_good());
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].is_bad()) << "The rejection itself must not depend on the mask";
    ASSERT_GE(resp.diagnostic_infos().size(), 1u)
      << "An operation-level bit is set, so the per-operation array must cover every result";

    const auto& info = resp.diagnostic_infos()[0];
    EXPECT_EQ(info.symbolic_id().has_value(), bitCase.symbolicId);
    EXPECT_EQ(info.namespace_uri().has_value(), bitCase.symbolicId);
    EXPECT_EQ(info.localized_text().has_value(), bitCase.localizedText);
    EXPECT_EQ(info.additional_info().has_value(), bitCase.additionalInfo);
    EXPECT_FALSE(info.inner_status_code().has_value())
      << "The rejection detail carries a Good inner status; nothing may be synthesised for it";
    EXPECT_EQ(info.inner_diagnostic_info().get(), nullptr)
      << "The rejection detail is a leaf; no inner diagnostic may be synthesised for it";
    EXPECT_TRUE(resp.response_header().service_diagnostics().is_null())
      << "An operation-level bit must not switch on service-level diagnostics";
  }

  // -------------------------------------------------------------------------
  // Non-vacuity, service level: with every service-level bit set the server DOES emit a
  // service-wide diagnostic for the over-limit Read, carrying code, source and summary.
  // -------------------------------------------------------------------------
  {
    SCOPED_TRACE("all service-level bits");
    auto result = mSession->attributes().try_read_sync(make_over_limit_read_request(allServiceBits));
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
    auto* detail = result.error_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr) << "Expected the always-on client wire-crossing marker";
    const auto* server = detail->cause->cause.get();
    ASSERT_NE(server, nullptr) << "Expected the decoded server service-level diagnostic";
    EXPECT_EQ(server->code, "server.symbolic.TooManyNodesToRead");
    EXPECT_EQ(server->source, "AttributeServiceSet");
    EXPECT_THAT(server->summary, ::testing::HasSubstr("exceeds"));
    EXPECT_FALSE(server->context.empty());
  }

  // -------------------------------------------------------------------------
  // Each service-level bit in isolation returns exactly the field it names. The decoded chain is
  // the client-side inverse of the server encode: symbolicId -> code, namespaceUri -> mSource,
  // localizedText -> summary, additionalInfo -> mContext/mDetail.
  // -------------------------------------------------------------------------
  {
    SCOPED_TRACE("ServiceSymbolicId only");
    auto result = mSession->attributes().try_read_sync(make_over_limit_read_request(serviceSymbolicId));
    ASSERT_TRUE(result.is_bad());
    auto* detail = result.error_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr);
    const auto* server = detail->cause->cause.get();
    ASSERT_NE(server, nullptr) << "SymbolicId was requested, so a service diagnostic must arrive";
    EXPECT_EQ(server->code, "server.symbolic.TooManyNodesToRead");
    EXPECT_EQ(server->source, "AttributeServiceSet");
    EXPECT_TRUE(server->summary.empty()) << "LocalizedText was not requested";
    EXPECT_TRUE(server->detail.empty()) << "AdditionalInfo was not requested";
    EXPECT_TRUE(server->context.empty()) << "AdditionalInfo was not requested";
    EXPECT_TRUE(StatusCode{server->innerStatus}.is_good()) << "InnerStatusCode was not requested";
    EXPECT_EQ(server->cause, nullptr) << "InnerDiagnostics was not requested";
  }

  {
    SCOPED_TRACE("ServiceLocalizedText only");
    auto result = mSession->attributes().try_read_sync(make_over_limit_read_request(serviceLocalizedText));
    ASSERT_TRUE(result.is_bad());
    auto* detail = result.error_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr);
    const auto* server = detail->cause->cause.get();
    ASSERT_NE(server, nullptr) << "LocalizedText was requested, so a service diagnostic must arrive";
    EXPECT_THAT(server->summary, ::testing::HasSubstr("exceeds"));
    EXPECT_TRUE(server->code.empty()) << "SymbolicId was not requested";
    EXPECT_TRUE(server->source.empty()) << "SymbolicId (namespaceUri) was not requested";
    EXPECT_TRUE(server->detail.empty()) << "AdditionalInfo was not requested";
    EXPECT_TRUE(server->context.empty()) << "AdditionalInfo was not requested";
    EXPECT_TRUE(StatusCode{server->innerStatus}.is_good()) << "InnerStatusCode was not requested";
    EXPECT_EQ(server->cause, nullptr) << "InnerDiagnostics was not requested";
  }

  {
    SCOPED_TRACE("ServiceAdditionalInfo only");
    auto result = mSession->attributes().try_read_sync(make_over_limit_read_request(serviceAdditionalInfo));
    ASSERT_TRUE(result.is_bad());
    auto* detail = result.error_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr);
    const auto* server = detail->cause->cause.get();
    ASSERT_NE(server, nullptr) << "AdditionalInfo was requested, so a service diagnostic must arrive";
    EXPECT_FALSE(server->context.empty())
      << "The over-limit facts ride in structured context carried by additionalInfo";
    EXPECT_TRUE(server->code.empty()) << "SymbolicId was not requested";
    EXPECT_TRUE(server->source.empty()) << "SymbolicId (namespaceUri) was not requested";
    EXPECT_TRUE(server->summary.empty()) << "LocalizedText was not requested";
    EXPECT_TRUE(StatusCode{server->innerStatus}.is_good()) << "InnerStatusCode was not requested";
    EXPECT_EQ(server->cause, nullptr) << "InnerDiagnostics was not requested";
  }

  // The over-limit ErrorDetail is a leaf, so asking only for the two chain fields must yield an
  // empty service-diagnostic envelope - the marker survives (it is always on) with nothing below.
  struct ServiceChainBitCase
  {
    uint32_t mask;
    const char* name;
  };

  const ServiceChainBitCase serviceChainCases[] = {
    {serviceInnerStatusCode, "ServiceInnerStatusCode only"},
    {serviceInnerDiagnostics, "ServiceInnerDiagnostics only"},
  };

  for (const auto& chainCase : serviceChainCases)
  {
    SCOPED_TRACE(chainCase.name);
    auto result = mSession->attributes().try_read_sync(make_over_limit_read_request(chainCase.mask));
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
    auto* detail = result.error_detail();
    ASSERT_NE(detail, nullptr);
    ASSERT_NE(detail->cause, nullptr) << "Expected the always-on client wire-crossing marker";
    EXPECT_EQ(detail->cause->cause, nullptr)
      << "The fault detail has neither an inner status nor a cause, so a mask naming only those "
         "two fields must leave the service-diagnostic envelope empty";
  }
}

// ===========================================================================
// ErrorDetailPerItemDiag - per-item diagnostics on mixed valid/invalid ops
// ===========================================================================

class ErrorDetailPerItemDiag : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::Sign;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelCfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ErrorDetailPerItemTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ---------------------------------------------------------------------------
// Bug caught: without per-item diagnostics, a mixed read response gives Bad
// statuses on individual items but no explanation of *why* each item failed.
// With diagnostics, each failed item has a DiagnosticInfo that resolves to an
// ErrorDetail with the specific failure reason.
// ---------------------------------------------------------------------------

// @relation(SVR-DIAG-010, scope=function)
TEST_F(ErrorDetailPerItemDiag, ReadMixedValidAndInvalidNodes_PerItemDiagnostics)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  // Item 0: valid node
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}));
  // Item 1: non-existent node in a valid namespace
  req.nodes_to_read().push_back(make_read_value_id(NodeId{0, uint32_t{999999}}));
  // Item 2: valid node
  req.nodes_to_read().push_back(make_read_value_id(NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_read_sync(std::move(req));
  ASSERT_TRUE(result.is_good())
    << "Mixed read should succeed at service level; per-item errors are in results";

  auto& resp = result.value();
  ASSERT_EQ(resp.results().size(), 3u);

  // Item 0: should be good.
  EXPECT_TRUE(!resp.results()[0].status().has_value() || resp.results()[0].status()->is_good());

  // Item 1: should be bad (node not found).
  ASSERT_TRUE(resp.results()[1].status().has_value());
  EXPECT_TRUE(resp.results()[1].status()->is_bad());

  // Item 2: should be good.
  EXPECT_TRUE(!resp.results()[2].status().has_value() || resp.results()[2].status()->is_good());

  // Per-item diagnostic for item 1 must be present and describe why it failed.
  ASSERT_GE(resp.diagnostic_infos().size(), 3u)
    << "Diagnostic infos array must cover all items when diagnostics are requested";
  ASSERT_FALSE(resp.diagnostic_infos()[1].is_null()) << "Bad item must have per-item DiagnosticInfo";
  auto perItemDetail =
    diagnostic_to_error_detail(resp.diagnostic_infos()[1], resp.response_header().string_table());
  ASSERT_NE(perItemDetail, nullptr);
  EXPECT_FALSE(perItemDetail->code.empty()) << "Per-item diagnostic must have a machine-readable error code";
  EXPECT_FALSE(perItemDetail->source.empty()) << "Per-item diagnostic must identify the source component";

  // Dump the full response diagnostics using the new helper.
  auto fullDiag = format_service_diagnostics(resp.response_header(),
    resp.diagnostic_infos(),
    resp.results().size(),
    [&](size_t i) -> StatusCode
    {
      return resp.results()[i].status().has_value() ? resp.results()[i].status().value()
                                                    : StatusCode{Status::Good};
    });
  std::cerr << "\n>>> " << ::testing::UnitTest::GetInstance()->current_test_info()->name()
            << " (format_service_diagnostics):\n"
            << fullDiag << "\n";
}

// @relation(SVR-DIAG-010, scope=function)
TEST_F(ErrorDetailPerItemDiag, ReadInvalidAttribute_PerItemBadStatus)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  // Attribute 99 does not exist.
  req.nodes_to_read().push_back(
    make_read_value_id(NodeId{VariableId::Server_ServerStatus_State}, static_cast<AttributeId>(99)));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_read_sync(std::move(req));
  // Single item read - service may succeed (per-item error) or fail (service fault).
  if (result.is_good())
  {
    auto& resp = result.value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].status().has_value());
    EXPECT_TRUE(resp.results()[0].status()->is_bad())
      << "Reading attribute 99 should produce a bad per-item status";
  }
  else
  {
    // If it's a service-level fault, that's also acceptable - just verify the status is bad.
    EXPECT_TRUE(result.status_code().is_bad());
  }
}

// @relation(SVR-DIAG-010, scope=function)
TEST_F(ErrorDetailPerItemDiag, WriteToReadOnlyNode_PerItemBadStatus)
{
  WriteRequest req;
  WriteValue wv;
  // Server_ServerStatus_State is read-only.
  wv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  wv.value() = DataValue{Variant{int32_t{0}}};
  req.nodes_to_write().push_back(std::move(wv));
  request_full_diagnostics(req.request_header());

  auto result = mSession->attributes().try_write_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Single-item write should succeed at service level";
  auto& resp = result.value();
  ASSERT_EQ(resp.results().size(), 1u);
  // The write should fail at the item level because the node is read-only.
  EXPECT_TRUE(resp.results()[0].is_bad()) << "Writing to a read-only variable should be rejected";

  // Per-item diagnostic must describe why the write was rejected.
  ASSERT_GE(resp.diagnostic_infos().size(), 1u);
  ASSERT_FALSE(resp.diagnostic_infos()[0].is_null()) << "Write rejection must have per-item DiagnosticInfo";
  auto perItemDetail =
    diagnostic_to_error_detail(resp.diagnostic_infos()[0], resp.response_header().string_table());
  ASSERT_NE(perItemDetail, nullptr);
  EXPECT_EQ(perItemDetail->code, "NotWritable");
  EXPECT_EQ(perItemDetail->source, "AttributeServiceSet");
  EXPECT_THAT(to_string(*perItemDetail),
    ::testing::HasSubstr(to_string(NodeId{VariableId::Server_ServerStatus_State})));

  auto fullDiag = format_service_diagnostics(resp.response_header(),
    resp.diagnostic_infos(),
    resp.results().size(),
    [&](size_t i) -> StatusCode { return resp.results()[i]; });
  std::cerr << "\n>>> " << ::testing::UnitTest::GetInstance()->current_test_info()->name()
            << " (format_service_diagnostics):\n"
            << fullDiag << "\n";
}

// @relation(SVR-DIAG-010, scope=function)
TEST_F(ErrorDetailPerItemDiag, BrowseMixedValidAndInvalidNodes_PerItemDiagnostics)
{
  BrowseRequest req;
  BrowseDescription desc1;
  desc1.node_id() = NodeId{ObjectId::ObjectsFolder};
  desc1.browse_direction() = BrowseDirection::Forward;
  desc1.include_subtypes() = true;
  desc1.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  BrowseDescription desc2;
  desc2.node_id() = NodeId{0, uint32_t{999999}};  // Non-existent node.
  desc2.browse_direction() = BrowseDirection::Forward;
  desc2.include_subtypes() = true;
  desc2.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc1));
  req.nodes_to_browse().push_back(std::move(desc2));
  request_full_diagnostics(req.request_header());

  auto result = mSession->view().try_browse_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Mixed browse should succeed at service level";
  auto& resp = result.value();
  ASSERT_EQ(resp.results().size(), 2u);

  // First item should be good (ObjectsFolder exists and has children).
  EXPECT_TRUE(resp.results()[0].status_code().is_good());

  // Second item should be bad (node does not exist).
  EXPECT_TRUE(resp.results()[1].status_code().is_bad())
    << "Browsing non-existent node should produce bad per-item status";

  // Per-item diagnostic must describe which node was not found.
  ASSERT_GE(resp.diagnostic_infos().size(), 2u);
  if (!resp.diagnostic_infos()[1].is_null())
  {
    auto perItemDetail =
      diagnostic_to_error_detail(resp.diagnostic_infos()[1], resp.response_header().string_table());
    ASSERT_NE(perItemDetail, nullptr);
    EXPECT_FALSE(perItemDetail->code.empty())
      << "Per-item browse diagnostic must have a machine-readable error code";
  }
}

// ===========================================================================
// ErrorDetailConnectionFault - client-side error detail for connection issues
// ===========================================================================

class ErrorDetailConnectionFault : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  }
};

TEST_F(ErrorDetailConnectionFault, ConnectionRefused_HasClientErrorDetail)
{
  // Try to open a channel to a port that is not listening.
  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = "opc.tcp://127.0.0.1:1";  // Port 1 - almost certainly not listening.
  channelCfg.securityMode = MessageSecurityMode::None;
  channelCfg.securityPolicyId = SecurityPolicyId::None;

  auto result = mClient->core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(result.is_bad()) << "Connecting to a closed port should fail";
  // The client should produce an ErrorDetail describing the connection failure.
  auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr) << "Connection failure should have ErrorDetail";
  EXPECT_FALSE(detail->code.empty()) << "ErrorDetail should have a machine-readable code";
}
