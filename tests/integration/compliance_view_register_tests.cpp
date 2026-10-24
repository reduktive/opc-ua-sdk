// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 5: View Service Set - RegisterNodes / UnregisterNodes
///
/// Tests covering Part 4 View requirements (VIEW-REG-*, VIEW-URG-*).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"

#include "ua_attribute_id.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_timestamps_to_return.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_variable_id.h"

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// RegisterNodes tests (VIEW-REG-*)
// ===========================================================================

// Every response echoes the request's RequestHandle in its ResponseHeader
// (Part 4 section 7.30). The RegisterNodes/UnregisterNodes service built its response
// header from scratch and left RequestHandle 0, failing UACTT View RegisterNodes
// across the whole CU ("RequestHandle ... Expected: 5 Received: 0").
TEST_F(ComplianceWithNodes, VIEW_REG_ResponseEchoesRequestHandle)
{
  auto req = register_nodes(mWritableVariableId);
  req.request_header().request_handle() = 4242;
  auto resp = mSession->view().register_nodes_sync(std::move(req));
  EXPECT_EQ(resp.response_header().request_handle(), 4242u)
    << "RegisterNodes response did not echo the request handle";
  ASSERT_FALSE(resp.registered_node_ids().empty());

  auto unreg = unregister_nodes(resp.registered_node_ids()[0]);
  unreg.request_header().request_handle() = 7777;
  auto unregResp = mSession->view().unregister_nodes_sync(std::move(unreg));
  EXPECT_EQ(unregResp.response_header().request_handle(), 7777u)
    << "UnregisterNodes response did not echo the request handle";
}

// Requirement: SVR-VIEW-REG-004 (SHALL)
// Returned IDs count matches request count.
// Spec: Part 4, section 5.8.5.2, lines 3275-3277
// @relation(SVR-VIEW-REG-004, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REG_004_ResultsSizeMatchesRequest)
{
  auto resp =
    mSession->view().register_nodes_sync(register_nodes({mWritableVariableId, mTestFolderId, mTestMethodId}));
  EXPECT_EQ(resp.registered_node_ids().size(), 3u)
    << "registeredNodeIds count must match nodesToRegister count";

  // Clean up.
  UnregisterNodesRequest unreg;
  for (const auto& id : resp.registered_node_ids())
    unreg.nodes_to_unregister().push_back(id);
  mSession->view().unregister_nodes_sync(std::move(unreg));
}

// Requirement: SVR-VIEW-REG-004 (SHALL)
// Returned IDs order matches request order.
// Spec: Part 4, section 5.8.5.2, lines 3275-3277
// @relation(SVR-VIEW-REG-004, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REG_004_ResultsOrderMatchesRequest)
{
  auto resp = mSession->view().register_nodes_sync(register_nodes({mWritableVariableId, mTestFolderId}));
  ASSERT_EQ(resp.registered_node_ids().size(), 2u);

  // Verify order: read through each registered ID and confirm the first resolves to a
  // Variable (mWritableVariableId is a Variable) and the second to an Object (mTestFolderId
  // is an Object). This proves order is preserved even if the server aliases the IDs.
  auto read1 = mSession->attributes().read_sync(read_value(resp.registered_node_ids()[0]));
  ASSERT_EQ(read1.results().size(), 1u);
  EXPECT_THAT(read1.results()[0], Good())
    << "First registered ID should resolve to a readable Variable (mWritableVariableId)";
  EXPECT_FALSE(read1.results()[0].value().empty()) << "First registered ID should be a Variable with a value";

  // Reading the Value attribute of mTestFolderId (an Object) should fail - Objects don't have Value.
  auto read2 = mSession->attributes().read_sync(read_value(resp.registered_node_ids()[1]));
  ASSERT_EQ(read2.results().size(), 1u);
  EXPECT_TRUE(read2.results()[0].status().has_value() && !read2.results()[0].status()->is_good())
    << "Second registered ID should resolve to mTestFolderId (Object, no Value attribute)";

  // Clean up.
  UnregisterNodesRequest unreg;
  for (const auto& id : resp.registered_node_ids())
    unreg.nodes_to_unregister().push_back(id);
  mSession->view().unregister_nodes_sync(std::move(unreg));
}

// Requirement: SVR-VIEW-REG-007 (SHALL)
// No optimization -> returns original NodeId.
// Spec: Part 4, section 5.8.5.2, lines 3280-3281
// @relation(SVR-VIEW-REG-007, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REG_007_NoOptimizationReturnsOriginal)
{
  auto resp = mSession->view().register_nodes_sync(register_nodes(mWritableVariableId));
  ASSERT_EQ(resp.registered_node_ids().size(), 1u);
  // When no optimization is supported, server returns the original NodeId.
  EXPECT_EQ(resp.registered_node_ids()[0], mWritableVariableId)
    << "No optimization -> server should return the original NodeId";

  mSession->view().unregister_nodes_sync(unregister_nodes(resp.registered_node_ids()[0]));
}

// Requirement: SVR-VIEW-REG-002 (SHALL)
// Registered NodeIds are only valid within the current session.
// Spec: Part 4, section 5.8.5.1, lines 3251-3252
//
// This test registers a node in one session, then verifies the registration
// is session-scoped by reading through the registered ID in the same session.
// @relation(SVR-VIEW-REG-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REG_002_RegisteredIdsSessionScoped)
{
  // Register in current session.
  auto resp = mSession->view().register_nodes_sync(register_nodes(mWritableVariableId));
  ASSERT_EQ(resp.registered_node_ids().size(), 1u);
  auto registeredId = resp.registered_node_ids()[0];

  // Read through registered ID in same session -> should succeed.
  auto readResp = mSession->attributes().read_sync(read_value(registeredId));
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], Good())
    << "Reading through registered NodeId in same session should succeed";

  mSession->view().unregister_nodes_sync(unregister_nodes(registeredId));
}

// Requirement: SVR-VIEW-REG-008 (SHALL)
// RegisterNodes does not validate whether NodeIds identify existing Nodes (Part 4 section 5.8.5): unknown /
// null NodeIds are copied back in the response. Complete Bad_NodeIdInvalid rejection (Table 44) is reserved
// for structurally invalid NodeIds. A null NodeId (i=0) is structurally valid, so the Server must echo it
// unchanged and return Good. (CTT View RegisterNodes Err-005/006.)
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REG_008_NullNodeIdEchoedBackNotRejected)
{
  auto result = mSession->view().try_register_nodes_sync(register_nodes({mWritableVariableId, NodeId{}}));
  ASSERT_TRUE(result.is_good()) << "RegisterNodes must not fault on a (structurally valid) null NodeId";
  EXPECT_TRUE(result.value().response_header().service_result().is_good())
    << "service result must be Good - null is structurally valid and requires no existence check";
  ASSERT_EQ(result.value().registered_node_ids().size(), 2u) << "response size/order matches request";
  EXPECT_EQ(result.value().registered_node_ids()[1], NodeId{}) << "the null NodeId is echoed back unchanged";
}

// Functional: Register -> Read with registered ID -> same value.
TEST_F(ComplianceWithNodes, RegisterThenRead)
{
  // Read original value.
  auto originalRead = mSession->attributes().read_sync(read_value(mWritableVariableId));
  ASSERT_EQ(originalRead.results().size(), 1u);
  ASSERT_THAT(originalRead.results()[0], Good());

  // Register and read through registered ID.
  auto regResp = mSession->view().register_nodes_sync(register_nodes(mWritableVariableId));
  ASSERT_EQ(regResp.registered_node_ids().size(), 1u);
  auto registeredId = regResp.registered_node_ids()[0];

  auto regRead = mSession->attributes().read_sync(read_value(registeredId));
  ASSERT_EQ(regRead.results().size(), 1u);
  EXPECT_THAT(regRead.results()[0], Good());

  // Values should match.
  if (!originalRead.results()[0].value().empty() && !regRead.results()[0].value().empty())
  {
    EXPECT_EQ(originalRead.results()[0].value(), regRead.results()[0].value())
      << "Reading through registered ID should yield same value as original";
  }

  mSession->view().unregister_nodes_sync(unregister_nodes(registeredId));
}

// Functional: Register multiple nodes in single request.
TEST_F(ComplianceWithNodes, RegisterMultipleNodes)
{
  auto resp = mSession->view().register_nodes_sync(
    register_nodes({mWritableVariableId, mFullAccessVariableId, mTestFolderId}));
  EXPECT_EQ(resp.registered_node_ids().size(), 3u);

  // Clean up.
  UnregisterNodesRequest unreg;
  for (const auto& id : resp.registered_node_ids())
    unreg.nodes_to_unregister().push_back(id);
  mSession->view().unregister_nodes_sync(std::move(unreg));
}

// Functional (negative): Empty list -> BadNothingToDo.
// @relation(SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, RegisterEmptyList)
{
  RegisterNodesRequest req;
  // Leave nodes_to_register empty.
  auto result = mSession->view().try_register_nodes_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}));
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// ===========================================================================
// UnregisterNodes tests (VIEW-URG-*)
// ===========================================================================

// Requirement: SVR-VIEW-URG-001 (SHALL)
// Unregister non-registered ID -> silently ignored.
// Spec: Part 4, section 5.8.6.1, lines 3302-3304
// @relation(SVR-VIEW-URG-001, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_URG_001_UnregisterUnknownSilent)
{
  // Unregister a node that was never registered.
  auto resp = mSession->view().unregister_nodes_sync(unregister_nodes(mWritableVariableId));
  EXPECT_THAT(resp, ServiceResultIsGood()) << "Unregistering a non-registered NodeId should succeed silently";
}

// Functional: Unregister previously registered ID -> succeeds.
TEST_F(ComplianceWithNodes, UnregisterRegistered)
{
  auto regResp = mSession->view().register_nodes_sync(register_nodes(mWritableVariableId));
  ASSERT_EQ(regResp.registered_node_ids().size(), 1u);

  auto unregResp = mSession->view().unregister_nodes_sync(unregister_nodes(regResp.registered_node_ids()[0]));
  EXPECT_THAT(unregResp, ServiceResultIsGood());
}

// Functional (negative): Empty list -> BadNothingToDo.
// @relation(SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, UnregisterEmptyList)
{
  UnregisterNodesRequest req;
  // Leave nodes_to_unregister empty.
  auto result = mSession->view().try_unregister_nodes_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}));
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// UnregisterNodes with a one-node ceiling. `MaxNodesPerRegisterNodes` governs both legs of the service
// pair (Part 4 section 5.8.6.2), so a server that wires the cap only into RegisterNodes leaves
// UnregisterNodes uncapped - the failure this fixture exists to catch. A ceiling of one keeps the over-limit
// request two nodes long, well inside every message and buffer limit, so nothing but the cap can reject it.
class ComplianceUnregisterNodesOperationLimit : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.server_capabilities().operationLimits.maxNodesPerRegisterNodes = 1;  // default 1000
  }
};

// Requirement: SVR-VIEW-URG-002 (SHALL)
// Part 4 section 5.8.6.3 Table 46: Bad_NothingToDo and Bad_TooManyOperations are the ENTIRE error surface of
// UnregisterNodes - the service has no per-operation results, so both faults must land on the service
// result. A plausible implementation gets this wrong two ways: it treats an empty list as a no-op and
// answers Good (there is, after all, nothing to undo), and it enforces the operation limit only on the
// RegisterNodes leg because that is the leg that allocates. Both leave a peer unable to tell a refused
// batch from a serviced one.
// @verifies AC-SVR-VIEW-URG-002-SERVICE-ERRORS
// @relation(AC-SVR-VIEW-URG-002-SERVICE-ERRORS, scope=function)
TEST_F(ComplianceUnregisterNodesOperationLimit, UNREGISTER_RefusesEmptyListAndOverLimitBatch)
{
  // Control: one node is within the ceiling and succeeds, so neither refusal below can be blamed on a
  // malformed request, an unknown NodeId, or an unreachable service.
  auto within = mSession->view().try_unregister_nodes_sync(unregister_nodes(mWritableVariableId));
  ASSERT_TRUE(within.is_good()) << "a single-node UnregisterNodes must be serviced at a ceiling of one";
  EXPECT_THAT(within.value(), ServiceResultIsGood())
    << "control call must succeed, otherwise the refusals below prove nothing";

  // First conjunct: empty nodesToUnregister -> Bad_NothingToDo at the service result.
  UnregisterNodesRequest emptyRequest;
  // Leave nodes_to_unregister empty.
  auto empty = mSession->view().try_unregister_nodes_sync(std::move(emptyRequest));
  if (empty.is_good())
  {
    EXPECT_THAT(empty.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}))
      << "an empty nodesToUnregister list must be refused, not silently serviced";
  }
  else
  {
    EXPECT_EQ(empty.status_code(), StatusCode{Status::BadNothingToDo})
      << "an empty nodesToUnregister list must be refused, not silently serviced";
  }

  // Second conjunct: batch above MaxNodesPerRegisterNodes -> Bad_TooManyOperations at the service result.
  // Under the default ceiling of 1000 this same two-node request succeeds, as the control above shows it
  // is otherwise well formed, so only the operation limit can be rejecting it.
  auto over =
    mSession->view().try_unregister_nodes_sync(unregister_nodes({mWritableVariableId, mTestFolderId}));
  if (over.is_good())
  {
    EXPECT_THAT(over.value(), ServiceResultIs(StatusCode{Status::BadTooManyOperations}))
      << "two nodes exceed a MaxNodesPerRegisterNodes ceiling of one";
  }
  else
  {
    EXPECT_EQ(over.status_code(), StatusCode{Status::BadTooManyOperations})
      << "two nodes exceed a MaxNodesPerRegisterNodes ceiling of one";
  }
}
