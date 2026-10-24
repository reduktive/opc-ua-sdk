// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 5: View Service Set - TranslateBrowsePathsToNodeIds + ViewDescription
///
/// Tests covering Part 4 View requirements (VIEW-TBP-*, VIEW-REL-*, VIEW-VWD-*).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_view_services.h"

#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_view_description.h"

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// TranslateBrowsePathsToNodeIds tests (VIEW-TBP-*)
// ===========================================================================

// Requirement: SVR-VIEW-TBP-002 (SHALL)
// Multiple targets with same BrowseName -> list of NodeIds returned.
// Spec: Part 4, section 5.8.4.1, lines 3159-3162
// @verifies CL-VIEW-014
// @relation(CL-VIEW-014, SVR-VIEW-TBP-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_TBP_002_MultipleTargetsSameBrowseName)
{
  // Translate from BrowseChildObj0 -> "DuplicateTarget" (two children share this BrowseName).
  auto resp = mSession->view().translate_browse_paths_sync(
    translate_path(mDuplicateNameParentId, QualifiedName{mTestNamespaceIndex, "DuplicateTarget"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_GE(resp.results()[0].targets().size(), 2u)
    << "Multiple targets with same BrowseName should return multiple NodeIds";
}

// Requirement: SVR-VIEW-TBP-003 (SHALL)
// Missing targetName on last element -> BadBrowseNameInvalid.
// Spec: Part 4, section 5.8.4.2, lines 3176-3178
// @relation(AC-SVR-VIEW-TBP-003-TARGETNAME-REQUIRED, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_TBP_003_BadBrowseNameInvalid_MissingTargetName)
{
  // Single hop with default-constructed (empty) QualifiedName as target name.
  auto resp = mSession->view().translate_browse_paths_sync(
    TranslateBrowsePathsBuilder().path(NodeId{ObjectId::ObjectsFolder}).step(QualifiedName{}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameInvalid))
    << "Missing targetName on last element should return BadBrowseNameInvalid";
}

// Requirement: SVR-VIEW-TBP-004 (SHALL)
// All elements processed -> remainingPathIndex = max value of Index.
// Spec: Part 4, section 5.8.4.2, lines 3198-3199
// @verifies CL-VIEW-015
// @relation(CL-VIEW-015, SVR-VIEW-TBP-004, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_TBP_004_RemainingPathIndexMaxWhenComplete)
{
  // Translate ObjectsFolder -> "TestFolder" (single hop, should fully resolve).
  auto resp = mSession->view().translate_browse_paths_sync(
    translate_path(NodeId{ObjectId::ObjectsFolder}, QualifiedName{mTestNamespaceIndex, "TestFolder"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_FALSE(resp.results()[0].targets().empty());

  // remainingPathIndex should be max uint32 value when all elements processed.
  constexpr uint32_t maxIndex = std::numeric_limits<uint32_t>::max();
  EXPECT_EQ(resp.results()[0].targets()[0].remaining_path_index(), maxIndex)
    << "remainingPathIndex should be max value when all elements processed";
}

// Requirement: SVR-VIEW-REL-001 (SHALL)
// isInverse=true follows inverse references.
// Spec: Part 4, section 7.31, lines 9616-9617
// @relation(SVR-VIEW-REL-001, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REL_001_InversePathFollowed)
{
  // From TestFolder, follow inverse Organizes -> should reach ObjectsFolder.
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(mTestFolderId)
                                                   .step(QualifiedName{0, "Objects"})
                                                   .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                   .is_inverse());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Inverse path from TestFolder to Objects should succeed. Got: 0x"
                                         << std::hex << resp.results()[0].status_code().as_uint32();
  ASSERT_FALSE(resp.results()[0].targets().empty());
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), NodeId{ObjectId::ObjectsFolder});
}

// Requirement: SVR-VIEW-REL-001 (SHALL)
// isInverse=false follows forward references.
// Spec: Part 4, section 7.31, lines 9616-9617
// @relation(SVR-VIEW-REL-001, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REL_001_ForwardPathFollowed)
{
  // From ObjectsFolder, follow forward Organizes -> "TestFolder".
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(NodeId{ObjectId::ObjectsFolder})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                                                   .reference_type(NodeId{ReferenceTypeId::Organizes}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_FALSE(resp.results()[0].targets().empty());
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mTestFolderId);
}

// Requirement: SVR-VIEW-REL-002 (SHALL)
// Empty targetName on non-final element -> BadBrowseNameInvalid.
// Spec: Part 4, section 7.31, lines 9621-9624
// @relation(SVR-VIEW-REL-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_REL_002_TargetNameRequiredForNonFinal)
{
  // First step: empty targetName (non-final -> should fail).
  // Second step: valid targetName (final).
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(NodeId{ObjectId::ObjectsFolder})
                                                   .step(QualifiedName{})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameInvalid))
    << "Empty targetName on non-final element should return BadBrowseNameInvalid";
}

// Functional: Single-hop browse path resolves correctly.
TEST_F(ComplianceWithNodes, TranslateSingleHopPath)
{
  // ObjectsFolder -> "WritableInt32" via Organizes.
  auto resp = mSession->view().translate_browse_paths_sync(
    translate_path(NodeId{ObjectId::ObjectsFolder}, QualifiedName{mTestNamespaceIndex, "WritableInt32"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_FALSE(resp.results()[0].targets().empty());
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mWritableVariableId);
}

// Functional: Multi-hop browse path resolves correctly.
TEST_F(ComplianceWithNodes, TranslateMultiHopPath)
{
  // ObjectsFolder -> "TestFolder" -> "TestMethod" (2 hops).
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(NodeId{ObjectId::ObjectsFolder})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_FALSE(resp.results()[0].targets().empty());
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mTestMethodId);
}

// Functional (negative): Unknown starting node -> BadNodeIdUnknown.
// @verifies CL-VIEW-016
// @relation(CL-VIEW-016, SVR-VIEW-TBP-009, scope=function)
TEST_F(ComplianceWithNodes, TranslateUnknownStartNode)
{
  NodeId nonExistent{mTestNamespaceIndex, uint32_t{99999}};
  auto resp =
    mSession->view().translate_browse_paths_sync(translate_path(nonExistent, QualifiedName{0, "Anything"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown));
}

// Functional (negative): Valid path but no matching target -> BadNoMatch.
// @verifies CL-VIEW-016
// @relation(CL-VIEW-016, SVR-VIEW-TBP-009, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, TranslateNoMatchingTarget)
{
  auto resp = mSession->view().translate_browse_paths_sync(
    translate_path(NodeId{ObjectId::ObjectsFolder}, QualifiedName{mTestNamespaceIndex, "NonExistentChild"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNoMatch));
}

// Functional (negative): Empty browsePaths -> BadNothingToDo.
// @relation(SVR-VIEW-TBP-008, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, TranslateEmptyList)
{
  TranslateBrowsePathsToNodeIdsRequest req;
  // Leave browse_paths empty.
  auto result = mSession->view().try_translate_browse_paths_sync(std::move(req));
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}));
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// Requirement: SVR-VIEW-TBP-009 (SHALL)
// Part 4 section 5.8.4.4 (Table 42): every entry of browsePaths carries its own StatusCode, and each of the
// listed conditions has its own code - a structurally invalid startingNode is Bad_NodeIdInvalid while one
// that merely names no node is Bad_NodeIdUnknown, an empty relativePath is a per-path Bad_NothingToDo, a
// null targetName is Bad_BrowseNameInvalid, a reference leaving this server is UNCERTAIN
// (Uncertain_ReferenceOutOfServer, an instruction to continue at the other server), and a path that simply
// does not resolve is Bad_NoMatch.
//
// A plausible implementation collapses this surface by forwarding the address-space lookup result for
// every bad startingNode. Driving all six conditions in one batch proves the codes are per-path rather
// than one code for the request and preserves the Uncertain severity of a cross-server continuation.
// @relation(AC-SVR-VIEW-TBP-009-OPERATION-CODES, SVR-VIEW-TBP-009, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_TBP_009_EachPerPathConditionReturnsItsOwnCode)
{
  // The cross-server condition needs a reference whose target lives in another server. serverIndex 1 makes
  // the target remote; the walk cannot resolve it locally, so the server must report the path as Uncertain
  // and hand back the remote target to continue with.
  const ExpandedNodeId remoteTarget{NodeId{mTestNamespaceIndex, uint32_t{8000}}, uint32_t{1}};
  {
    auto addressSpace = mServer.server().address_space();
    auto otherObject = addressSpace.find_node_sync(mOtherObjectId);
    auto added = otherObject.try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, remoteTarget);
    ASSERT_THAT(added, Good()) << "the cross-server case is only observable if the remote reference exists";
  }

  auto resp = mSession->view().translate_browse_paths_sync(
    TranslateBrowsePathsBuilder()
      // 0: malformed startingNode - a null NodeId is structurally invalid, not merely absent.
      .path(NodeId{})
      .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
      // 1: well-formed startingNode that names no node in an existing namespace.
      .path(NodeId{mTestNamespaceIndex, uint32_t{99999}})
      .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
      // 2: a relativePath with no elements at all.
      .path(mTestFolderId)
      // 3: an element with no targetName.
      .path(NodeId{ObjectId::ObjectsFolder})
      .step(QualifiedName{})
      // 4: the only matching reference out of OtherObject leaves this server.
      .path(mOtherObjectId)
      .step(QualifiedName{mTestNamespaceIndex, "RemoteChild"})
      // 5: everything well-formed and resolvable, but nothing carries that BrowseName.
      .path(NodeId{ObjectId::ObjectsFolder})
      .step(QualifiedName{mTestNamespaceIndex, "NonExistentChild"}));

  ASSERT_EQ(resp.results().size(), 6u) << "one result per browse path, in request order";

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "a null startingNode is structurally invalid, which is a different failure from an unknown node";
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNodeIdUnknown))
    << "a well-formed startingNode that names no node is Bad_NodeIdUnknown";
  EXPECT_THAT(resp.results()[2], HasStatus(Status::BadNothingToDo))
    << "an empty relativePath is a per-path Bad_NothingToDo, not a service fault for the whole request";
  EXPECT_THAT(resp.results()[3], HasStatus(Status::BadBrowseNameInvalid))
    << "an element with a null targetName is Bad_BrowseNameInvalid";

  EXPECT_THAT(resp.results()[4], HasStatus(Status::UncertainReferenceOutOfServer))
    << "a reference that leaves the server is Uncertain_ReferenceOutOfServer";
  EXPECT_TRUE(resp.results()[4].status_code().is_uncertain())
    << "the Uncertain severity is the substance - collapsing it into Bad discards the instruction to "
       "continue at the other server";
  ASSERT_FALSE(resp.results()[4].targets().empty())
    << "the uncertain path must still hand back the remote target to continue with";
  EXPECT_EQ(resp.results()[4].targets()[0].target_id().server_index(), 1u)
    << "the returned target must name the other server";

  EXPECT_THAT(resp.results()[5], HasStatus(Status::BadNoMatch))
    << "a resolvable path with no matching target is Bad_NoMatch";
}

// ===========================================================================
// TranslateBrowsePathsToNodeIds service-level faults (VIEW-TBP-008)
// ===========================================================================

// Caps the batch at two paths so the operation-limit refusal is reachable with a small request. The limit is
// ordinary server configuration that the service reads when it dispatches - the refusal under test is still
// the server's own check, not something the fixture supplies.
class ComplianceTranslateOperationLimit : public ComplianceWithNodes
{
protected:
  static constexpr uint32_t sMaxPathsPerTranslate = 2;

  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.server_capabilities().operationLimits.maxNodesPerTranslateBrowsePathsToNodeIds =
      sMaxPathsPerTranslate;
  }
};

// Requirement: SVR-VIEW-TBP-008 (SHALL)
// Part 4 section 5.8.4.4: an empty browsePaths list is Bad_NothingToDo and a batch larger than
// MaxNodesPerTranslateBrowsePathsToNodeIds is Bad_TooManyOperations, both returned as the SERVICE result
// before any path is resolved.
//
// A plausible implementation pushes these into the per-path results - answering an over-sized batch with one
// Bad_TooManyOperations per path, or quietly truncating it to the limit and answering the paths that fit.
// Either reads to a client as "the batch I sent was processed", so the whole-request nature of the refusal is
// the thing to observe: the fault arrives at the service level with no per-path results at all.
// @verifies AC-SVR-VIEW-TBP-008-SERVICE-ERRORS
TEST_F(ComplianceTranslateOperationLimit, VIEW_TBP_008_EmptyAndOverSizedBatchesAreServiceFaults)
{
  // Conjunct 1: nothing to translate.
  {
    TranslateBrowsePathsToNodeIdsRequest req;
    // Leave browse_paths empty.
    auto result = mSession->view().try_translate_browse_paths_sync(std::move(req));
    if (result.is_good())
    {
      EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}))
        << "an empty browsePaths list is a service-level Bad_NothingToDo";
      EXPECT_TRUE(result.value().results().empty()) << "a service-level refusal carries no per-path results";
    }
    else
    {
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo})
        << "an empty browsePaths list is a service-level Bad_NothingToDo";
    }
  }

  // Conjunct 2: one path more than the configured operation limit. Every path on its own is well-formed and
  // resolves, so nothing but the size of the batch can be the reason for the refusal.
  {
    TranslateBrowsePathsBuilder builder;
    for (uint32_t i = 0; i < sMaxPathsPerTranslate + 1; ++i)
    {
      builder.path(NodeId{ObjectId::ObjectsFolder}).step(QualifiedName{mTestNamespaceIndex, "TestFolder"});
    }

    auto result = mSession->view().try_translate_browse_paths_sync(builder.build());
    if (result.is_good())
    {
      EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadTooManyOperations}))
        << "a batch over MaxNodesPerTranslateBrowsePathsToNodeIds is refused as a whole";
      EXPECT_TRUE(result.value().results().empty())
        << "the over-sized batch must not be partly answered - no path may be resolved";
    }
    else
    {
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations})
        << "a batch over MaxNodesPerTranslateBrowsePathsToNodeIds is refused as a whole";
    }
  }
}

// ===========================================================================
// ViewDescription tests (VIEW-VWD-*)
// ===========================================================================

// Requirement: SVR-VIEW-VWD-001 (SHALL)
// If ViewVersion is set, the timestamp parameter shall be null.
// Spec: Part 4, section 7.45, lines 10706-10707
//
// The requirement constrains that viewVersion and timestamp are mutually exclusive.
// We submit an INVALID combination (both viewVersion AND timestamp set) and verify
// the server rejects it.
// @relation(SVR-VIEW-URG-002, SVR-VIEW-VWD-001, scope=function)
TEST_F(ComplianceWithNodes, VIEW_VWD_001_ViewVersionSetTimestampNull)
{
  BrowseRequest req;
  req.view().view_version() = 1;
  req.view().timestamp() = DateTime::now();  // INVALID: viewVersion is set, so timestamp shall be null.
  req.nodes_to_browse().push_back(BrowseDescription{});
  req.nodes_to_browse()[0].node_id() = mTestFolderId;
  req.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  req.nodes_to_browse()[0].result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

  auto result = mSession->view().try_browse_sync(std::move(req));
  // The server shall reject this request. The error may be BadViewIdUnknown
  // (if it validates the ViewDescription) or BadInvalidArgument.
  if (result.is_good())
  {
    auto serviceStatus = result.value().response_header().service_result();
    EXPECT_FALSE(serviceStatus.is_good())
      << "ViewDescription with both viewVersion and timestamp set shall be rejected";
  }
  else
  {
    // Service-level fault is acceptable - the combination is invalid.
    EXPECT_FALSE(result.status_code().is_good())
      << "ViewDescription with both viewVersion and timestamp set shall be rejected";
  }
}

// Requirement: SVR-VIEW-VWD-002 (SHALL)
// If timestamp is set, the viewVersion parameter shall be 0.
// Spec: Part 4, section 7.45, lines 10711-10712
//
// We submit an INVALID combination (timestamp set AND viewVersion non-zero) and verify
// the server rejects it.
// @relation(SVR-VIEW-URG-002, SVR-VIEW-VWD-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_VWD_002_TimestampSetViewVersionZero)
{
  BrowseRequest req;
  req.view().timestamp() = DateTime::now();
  req.view().view_version() = 5;  // INVALID: timestamp is set, so viewVersion shall be 0.
  req.nodes_to_browse().push_back(BrowseDescription{});
  req.nodes_to_browse()[0].node_id() = mTestFolderId;
  req.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  req.nodes_to_browse()[0].result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

  auto result = mSession->view().try_browse_sync(std::move(req));
  // The server shall reject this request.
  if (result.is_good())
  {
    auto serviceStatus = result.value().response_header().service_result();
    EXPECT_FALSE(serviceStatus.is_good())
      << "ViewDescription with timestamp set and viewVersion non-zero shall be rejected";
  }
  else
  {
    EXPECT_FALSE(result.status_code().is_good())
      << "ViewDescription with timestamp set and viewVersion non-zero shall be rejected";
  }
}

// Covers VIEW-TBP (null referenceTypeId) (CTT View TranslateBrowsePath/011, Err-020)
// Part 4 section 7.27: an unspecified (null) referenceTypeId in a RelativePathElement follows all references
// (includeSubtypes ignored), so a valid path still resolves.
TEST_F(ComplianceWithNodes, Mirror_Translate_NullReferenceTypeId_FollowsAllReferences)
{
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(NodeId{ObjectId::ObjectsFolder})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                                                   .reference_type(NodeId{}));

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Null referenceTypeId must follow all references (UACTT F18)";
  ASSERT_GE(resp.results()[0].targets().size(), 1u);
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mTestFolderId);
}

// Covers VIEW-TBP (null referenceTypeId, multi-element) (CTT View TranslateBrowsePath/011)
// A null referenceTypeId must follow all references at EVERY element of a multi-hop path.
TEST_F(ComplianceWithNodes, Mirror_Translate_NullReferenceTypeId_MultiHopFollowsAllReferences)
{
  auto resp =
    mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                   .path(NodeId{ObjectId::ObjectsFolder})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                                                   .reference_type(NodeId{})
                                                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"})
                                                   .reference_type(NodeId{}));

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good())
    << "Null referenceTypeId must follow all references at every hop (UACTT F18 / 011)";
  ASSERT_GE(resp.results()[0].targets().size(), 1u);
  EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mTestMethodId);
}

// Covers VIEW-TBP (null referenceTypeId encodings) (CTT View TranslateBrowsePath/011, Err-020)
// A null NodeId has several wire encodings (OPC 10000-6 section 5.2.2.9): numeric 0, empty/null String,
// null Guid, empty/null ByteString. Every one must be treated as "follow all references", not as a
// concrete (non-existent) reference type that yields Bad_NoMatch.
TEST_F(ComplianceWithNodes, Mirror_Translate_NullReferenceTypeId_AllNullEncodings)
{
  const std::vector<NodeId> nullEncodings = {
    NodeId{uint16_t{0}, uint32_t{0}},  // ns=0;i=0
    NodeId{uint16_t{0}, String{""}},  // ns=0;s=
    NodeId{uint16_t{0}, Guid::parse("00000000-0000-0000-0000-000000000000")},  // ns=0;g={0...0}
    NodeId{uint16_t{0}, ByteString{}},  // ns=0;b=
  };

  for (const auto& nullRefType : nullEncodings)
  {
    ASSERT_TRUE(nullRefType.is_null()) << "Encoding must be recognised as a null NodeId";
    auto resp =
      mSession->view().translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                     .path(NodeId{ObjectId::ObjectsFolder})
                                                     .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                                                     .reference_type(nullRefType));

    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good())
      << "Null referenceTypeId encoding must follow all references (UACTT 011)";
    ASSERT_GE(resp.results()[0].targets().size(), 1u);
    EXPECT_EQ(resp.results()[0].targets()[0].target_id().node_id(), mTestFolderId);
  }
}
