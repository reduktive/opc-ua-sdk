// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::BrowseCursor (client design section 7.5): the forward iterator over references
// from a start node that hides the BrowseResult / BrowseNext continuation-point dance. Covers the has_more()
// predicate, the section 7.0 next triple, multi-page BrowseNext paging, the close_async + destructor
// continuation-point release (a release-only BrowseNext), and the WireOps-gone bail.
//
// Falsifiability: a cursor that never browses fails IteratesReferencesFromStartNode; one that never pages
// fails MultiPageDrivesBrowseNext; one that leaks the continuation point fails
// CloseReleasesContinuationPoint / DestructorReleasesContinuationPoint; one that derefs a gone interface
// fails WireOpsGoneNextBailsCleanly.

#include "ua_browse_cursor.h"

#include "fake_connection_ops.h"

#include "ua_browse_cursor_test_access.h"
#include "ua_byte_string.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_table.h"
#include "ua_namespace_uri.h"
#include "ua_node_id.h"
#include "ua_reference_description.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::BrowseCursor;
using ua::client::BrowseOptions;
using ua::client::detail::BrowseCursorTestAccess;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{0, identifier};
}

ua::ReferenceDescription make_reference(std::uint32_t targetIdentifier)
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = node(targetIdentifier);
  reference.display_name() = ua::LocalizedText{ua::String{"target"}};
  reference.is_forward() = true;
  return reference;
}

// A remote reference: node_id().serverIndex = @p serverIndex (!= 0), with @p displayName (empty models a
// non-conformant server). browseName / typeDefinition / nodeClass are left default (null / Unspecified) to
// exercise the "tolerate null optional fields for a remote reference" contract (CL-VIEW-017).
ua::ReferenceDescription make_remote_reference(
  std::uint32_t targetIdentifier, std::uint32_t serverIndex, std::string_view displayName)
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = node(targetIdentifier);
  reference.node_id().server_index() = serverIndex;
  if (!displayName.empty())
  {
    reference.display_name() = ua::LocalizedText{ua::String{displayName}};
  }
  reference.is_forward() = true;
  return reference;
}

// A reference whose target ExpandedNodeId carries a non-empty @p namespaceUri (CL-VIEW-018). The encoded
// NamespaceIndex is 0 on the wire (per the codec invariant); the URI is the authoritative namespace. @p
// serverIndex defaults to 0 (a LOCAL target, eligible for URI->local-index resolution); a non-zero value
// models a REMOTE target whose URI belongs to the remote server's namespace space (never resolved locally).
ua::ReferenceDescription make_uri_reference(
  std::uint32_t targetIdentifier, std::string_view namespaceUri, std::uint32_t serverIndex = 0)
{
  ua::ReferenceDescription reference;
  reference.node_id() = ua::ExpandedNodeId{node(targetIdentifier), namespaceUri, serverIndex};
  reference.display_name() = ua::LocalizedText{ua::String{"target"}};
  reference.is_forward() = true;
  return reference;
}

// A two-entry NamespaceArray snapshot: NS0 at index 0, @p localUri at index 1 (CL-VIEW-018 resolution
// target).
std::shared_ptr<const ua::client::NamespaceTable> make_namespace_table(std::string_view localUri)
{
  return ua::client::NamespaceTable::create(
    {std::string{ua::specNamespaceUri}, std::string{localUri}}, std::nullopt, /*generation=*/1)
    .value();
}

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<std::atomic<std::uint64_t>> sessionGeneration =
    std::make_shared<std::atomic<std::uint64_t>>(0);

  BrowseCursor make(ua::NodeId start = node(85), BrowseOptions options = {})
  {
    return BrowseCursorTestAccess::make(
      wireOps, ctx.get_executor(), std::move(start), std::move(options), {}, {}, sessionGeneration);
  }

  // Builds a cursor wired to the NamespaceTable @p table (CL-VIEW-018) so the URI-resolution branch is
  // unit-driven against a real (concrete, non-mocked) namespace snapshot.
  BrowseCursor make_with_namespace_table(
    std::shared_ptr<const ua::client::NamespaceTable> table, ua::NodeId start = node(85))
  {
    return BrowseCursorTestAccess::make(
      wireOps, ctx.get_executor(), std::move(start), BrowseOptions{}, /*emitAdvisory=*/{}, std::move(table));
  }

  // Builds a cursor whose advisory interface is @p emitAdvisory (CL-VIEW-017) so the advisory branch is
  // unit-driven.
  BrowseCursor make_with_advisory(
    std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory, ua::NodeId start = node(85))
  {
    return BrowseCursorTestAccess::make(
      wireOps, ctx.get_executor(), std::move(start), BrowseOptions{}, std::move(emitAdvisory));
  }

  // Runs one next_async and drains the io_context, returning the delivered Result.
  ua::Result<BrowseCursor::Entry> next(BrowseCursor& cursor)
  {
    std::optional<ua::Result<BrowseCursor::Entry>> captured;
    cursor.next_async([&captured](ua::Result<BrowseCursor::Entry> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }
};

// @verifies CL-VIEW-005
// @relation(CL-VIEW-005, scope=function)
TEST(BrowseCursor, IteratesReferencesFromStartNode)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1), make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  EXPECT_TRUE(cursor.has_more()) << "an unstarted cursor optimistically has more";

  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good());
  EXPECT_EQ(first.value().targetNodeId, node(1));

  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good());
  EXPECT_EQ(second.value().targetNodeId, node(2));

  EXPECT_FALSE(cursor.has_more()) << "page consumed, no continuation point -> exhausted";
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u) << "exactly one Browse for the whole page";
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty()) << "no BrowseNext when there is no continuation point";
}

// A subset resultMask is emitted unchanged and a correspondingly partial ReferenceDescription is accepted.
// The target NodeId is always present; fields omitted by the server remain default-constructed rather than
// turning the Browse into an error.
// @verifies CL-VIEW-007
// @relation(CL-VIEW-007, scope=function)
TEST(BrowseCursor, ResultMaskSubsetAcceptsPartialReferenceDescription)
{
  Fixture f;
  ua::ReferenceDescription partial;
  partial.node_id().node_id() = node(7);
  partial.browse_name() = ua::QualifiedName{2, "Target"};
  partial.display_name() = ua::LocalizedText{ua::String{"Target display"}};
  f.wireOps->browsePages.push_back({{std::move(partial)}, ua::ContinuationPoint{}, {}});

  BrowseOptions options;
  options.resultMask = (1u << 3u) | (1u << 4u);  // BrowseName | DisplayName
  auto cursor = f.make(node(85), options);
  const auto result = f.next(cursor);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);
  ASSERT_EQ(f.wireOps->browseRequests.front().nodes_to_browse().size(), 1u);
  EXPECT_EQ(f.wireOps->browseRequests.front().nodes_to_browse()[0].result_mask(), options.resultMask);
  EXPECT_EQ(result.value().targetNodeId.node_id(), node(7));
  EXPECT_EQ(static_cast<std::string_view>(result.value().browseName.name()), "Target");
  EXPECT_EQ(static_cast<std::string_view>(result.value().displayName.text()), "Target display");
  EXPECT_TRUE(result.value().referenceTypeId.is_null());
  EXPECT_TRUE(result.value().typeDefinition.is_null());
  EXPECT_EQ(result.value().nodeClass, ua::NodeClass::Unspecified);
}

// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST(BrowseCursor, ViewTimestampIsEncodedWithZeroVersion)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  const ua::DateTime timestamp{2025, 1, 2, 3, 4, 5.0};
  BrowseOptions options;
  options.viewTimestamp = timestamp;

  auto cursor = f.make(node(85), options);
  ASSERT_TRUE(f.next(cursor).is_good());

  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);
  EXPECT_EQ(f.wireOps->browseRequests.front().view().timestamp(), timestamp);
  EXPECT_EQ(f.wireOps->browseRequests.front().view().view_version(), 0u);
}

// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST(BrowseCursor, ViewVersionIsEncodedWithNullTimestamp)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  BrowseOptions options;
  options.viewVersion = 7;

  auto cursor = f.make(node(85), options);
  ASSERT_TRUE(f.next(cursor).is_good());

  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->browseRequests.front().view().timestamp().is_null());
  EXPECT_EQ(f.wireOps->browseRequests.front().view().view_version(), 7u);
}

// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST(BrowseCursor, TimestampAndViewVersionAreRejectedBeforeWireIo)
{
  Fixture f;
  BrowseOptions options;
  options.viewTimestamp = ua::DateTime{2025, 1, 2, 3, 4, 5.0};
  options.viewVersion = 7;

  auto cursor = f.make(node(85), options);
  const auto result = f.next(cursor);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BrowseViewParametersMutuallyExclusive");
  EXPECT_TRUE(f.wireOps->browseRequests.empty()) << "invalid view parameters must fail before wire I/O";
}

// A remote reference (node_id().serverIndex != 0) must surface with its serverIndex PRESERVED on the Entry's
// ExpandedNodeId targetNodeId - the cursor no longer narrows the target to a bare local NodeId. RED before
// the Entry.targetNodeId : ExpandedNodeId change (targetNodeId was a NodeId with no server_index()).
// @verifies CL-VIEW-017
// @relation(CL-VIEW-017, scope=function)
TEST(BrowseCursor, RemoteReferenceServerIndexPreserved)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_remote_reference(1, /*serverIndex=*/10, "remote target")}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  auto entry = f.next(cursor);
  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 10u)
    << "the remote reference's serverIndex must be preserved on the ExpandedNodeId";
  EXPECT_EQ(entry.value().targetNodeId.node_id(), node(1));
}

// A remote reference with NULL/empty optional fields (browseName, typeDefinition, NodeClass=Unspecified) must
// be surfaced verbatim with those empty fields - the cursor tolerates them (no reject) since the local server
// may not monitor the remote server for changes (Part 4 section 7.30). @verifies CL-VIEW-017
TEST(BrowseCursor, RemoteReferenceOptionalFieldsNullTolerated)
{
  Fixture f;
  // A remote reference carrying a displayName (conformant) but null browseName / typeDefinition / nodeClass.
  f.wireOps->browsePages.push_back(
    {{make_remote_reference(2, /*serverIndex=*/5, "remote")}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  auto entry = f.next(cursor);
  ASSERT_TRUE(entry.is_good()) << "a remote reference with null optional fields is tolerated, not rejected";
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 5u);
  EXPECT_TRUE(static_cast<std::string_view>(entry.value().browseName.name()).empty())
    << "a null browseName is surfaced empty, not fabricated";
  EXPECT_EQ(entry.value().nodeClass, ua::NodeClass::Unspecified);
}

// A LOCAL reference (serverIndex 0) surfaces with server_index()==0 (a plain local NodeId in node_id()); the
// cursor issues no extra wire op (no auto-connect - there is nothing remote to follow). @verifies CL-VIEW-017
TEST(BrowseCursor, LocalReferenceServerIndexZero)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(7)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  auto entry = f.next(cursor);
  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 0u) << "a local reference has serverIndex 0";
  EXPECT_EQ(entry.value().targetNodeId.node_id(), node(7));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u) << "exactly one Browse; no auto-connect to a remote server";
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty());
}

// A REMOTE reference (serverIndex != 0) that OMITS its mandatory displayName is a non-conformant server: the
// cursor surfaces the entry AND emits an advisory carrying the RemoteReferenceMissingDisplayName code (Part 4
// section 7.30 fn1). RED before the to_entry advisory branch (no advisory was emitted).
// @verifies CL-VIEW-017
// @relation(CL-VIEW-017, scope=function)
TEST(BrowseCursor, RemoteReferenceMissingDisplayNameEmitsAdvisory)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_remote_reference(1, /*serverIndex=*/10, /*displayName=*/"")}, ua::ContinuationPoint{}, {}});

  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisories;
  auto cursor = f.make_with_advisory([&advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    { advisories.push_back(std::move(detail)); });
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good()) << "the entry is surfaced verbatim despite the missing displayName";
  ASSERT_EQ(advisories.size(), 1u) << "exactly one advisory for the non-conformant remote reference";
  EXPECT_EQ(advisories[0]->code, "RemoteReferenceMissingDisplayName");
}

// A REMOTE reference that CARRIES a displayName is conformant: no advisory. Pins that the advisory is gated
// on the empty-displayName half of the guard. @verifies CL-VIEW-017
TEST(BrowseCursor, RemoteReferenceWithDisplayNameEmitsNoAdvisory)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_remote_reference(1, /*serverIndex=*/10, /*displayName=*/"Remote")}, ua::ContinuationPoint{}, {}});

  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisories;
  auto cursor = f.make_with_advisory([&advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    { advisories.push_back(std::move(detail)); });
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_TRUE(advisories.empty()) << "a conformant remote reference (present displayName) fires no advisory";
}

// A LOCAL reference (serverIndex 0) with an empty displayName fires NO advisory - displayName is mandatory
// only for REMOTE nodes (Part 4 section 7.30 fn1). Pins the serverIndex != 0 half of the guard (untested at
// any level before this). @verifies CL-VIEW-017
TEST(BrowseCursor, LocalReferenceMissingDisplayNameEmitsNoAdvisory)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_remote_reference(1, /*serverIndex=*/0, /*displayName=*/"")}, ua::ContinuationPoint{}, {}});

  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisories;
  auto cursor = f.make_with_advisory([&advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    { advisories.push_back(std::move(detail)); });
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 0u);
  EXPECT_TRUE(advisories.empty())
    << "a local reference with an empty displayName is conformant (no advisory)";
}

// A BrowseResult with statusCode == Good_MoreData but an EMPTY continuation point is non-conformant (Part 4
// section 7.6: the CP is the ONLY normative "more" signal). The cursor treats the page as DONE (empty CP) and
// emits an advisory surfacing the server bug. RED before the CL-VIEW-005 advisory.
// @verifies CL-VIEW-005
// @relation(CL-VIEW-005, scope=function)
TEST(BrowseCursor, GoodMoreDataWithoutContinuationPointEmitsAdvisory)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_reference(1)}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::GoodMoreData}});

  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisories;
  auto cursor = f.make_with_advisory([&advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    { advisories.push_back(std::move(detail)); });
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.node_id(), node(1));
  EXPECT_FALSE(cursor.has_more())
    << "an empty CP is the only 'more' signal -> the walk is done despite Good_MoreData";
  ASSERT_EQ(advisories.size(), 1u) << "the non-conformant Good_MoreData-without-CP must emit one advisory";
  EXPECT_EQ(advisories[0]->code, "BrowseGoodMoreDataWithoutContinuationPoint");
}

// A plain Good status with an empty continuation point is NORMAL exhaustion - no advisory. Pins that the
// advisory is gated on the Good_MoreData status, not merely on an empty CP. @verifies CL-VIEW-005
TEST(BrowseCursor, GoodStatusWithoutContinuationPointEmitsNoAdvisory)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});  // plain Good, no CP

  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisories;
  auto cursor = f.make_with_advisory([&advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    { advisories.push_back(std::move(detail)); });
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_TRUE(advisories.empty()) << "a plain Good response with no CP is normal exhaustion, not an advisory";
}

// CL-VIEW-018: a LOCAL target whose ExpandedNodeId carries a non-empty NamespaceUri is resolved to a local
// NamespaceIndex against the Connection's NamespaceTable snapshot (the wire index is 0 per the codec
// invariant). The resolved entry collapses to a plain local NodeId at the mapped index with the URI dropped.
// @verifies CL-VIEW-018
// @relation(CL-VIEW-018, scope=function)
TEST(BrowseCursor, NamespaceUriResolvesToLocalIndexOnBrowse)
{
  Fixture f;
  // Wire index 0 + URI "http://vendor/local" (which the table maps to local index 1).
  f.wireOps->browsePages.push_back(
    {{make_uri_reference(42, "http://vendor/local")}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make_with_namespace_table(make_namespace_table("http://vendor/local"));
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.node_id().namespace_index(), 1u)
    << "the URI must resolve to its local NamespaceIndex (1), not the wire index (0)";
  EXPECT_EQ(entry.value().targetNodeId.node_id().identifier().get_numeric(), 42u)
    << "the identifier is preserved";
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 0u) << "a resolved local target stays local";
  EXPECT_TRUE(static_cast<std::string_view>(entry.value().targetNodeId.namespace_uri()).empty())
    << "a resolved URI is dropped - the local index is now authoritative";
}

// CL-VIEW-018: a URI absent from the local NamespaceArray is preserved VERBATIM - never substituted with a
// stale index - so the user can inspect the unresolved URI. @verifies CL-VIEW-018
TEST(BrowseCursor, NamespaceUriPreservedWhenUnmapped)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_uri_reference(42, "http://other/unmapped")}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make_with_namespace_table(make_namespace_table("http://vendor/local"));
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(
    static_cast<std::string_view>(entry.value().targetNodeId.namespace_uri()), "http://other/unmapped")
    << "an unmapped URI is preserved verbatim for user inspection";
  EXPECT_EQ(entry.value().targetNodeId.node_id().namespace_index(), 0u)
    << "an unmapped URI must NOT be substituted with a stale index (the wire index 0 is left as-is)";
}

// CL-VIEW-018 x CL-VIEW-017 boundary: a REMOTE target (serverIndex != 0) that carries a URI is NOT resolved
// against the LOCAL table - its URI belongs to the remote server's namespace space. The ExpandedNodeId is
// preserved verbatim. @verifies CL-VIEW-018
TEST(BrowseCursor, RemoteUriTargetNotResolvedLocally)
{
  Fixture f;
  // Same URI the local table maps to index 1, but on a REMOTE server (serverIndex 7).
  f.wireOps->browsePages.push_back(
    {{make_uri_reference(42, "http://vendor/local", /*serverIndex=*/7)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make_with_namespace_table(make_namespace_table("http://vendor/local"));
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 7u) << "a remote target keeps its serverIndex";
  EXPECT_EQ(static_cast<std::string_view>(entry.value().targetNodeId.namespace_uri()), "http://vendor/local")
    << "a remote target's URI is NOT resolved against the local table - it is preserved verbatim";
}

// CL-VIEW-018: a local target with NO URI is passed through untouched (the encoded index is already
// authoritative); resolution is gated on a non-empty URI, so an out-of-range-for-the-table index is not
// even consulted. @verifies CL-VIEW-018
TEST(BrowseCursor, LocalTargetWithoutUriUntouched)
{
  Fixture f;
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = ua::NodeId{5, 42};  // index 5, no URI (5 is out of the 2-entry table range)
  reference.display_name() = ua::LocalizedText{ua::String{"target"}};
  reference.is_forward() = true;
  f.wireOps->browsePages.push_back({{reference}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make_with_namespace_table(make_namespace_table("http://vendor/local"));
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().targetNodeId.node_id().namespace_index(), 5u)
    << "a target with no URI keeps its encoded index - resolution never runs for an empty URI";
  EXPECT_TRUE(static_cast<std::string_view>(entry.value().targetNodeId.namespace_uri()).empty());
}

// CL-VIEW-018: the typeDefinition ExpandedNodeId is subject to the SAME URI-overrides-index invariant as the
// target - a LOCAL URI-bearing type definition resolves to its local index, so the cursor is consistent (it
// would otherwise honour the invariant for the target yet yield a wrong NS0 index for the adjacent type
// definition). @verifies CL-VIEW-018
TEST(BrowseCursor, TypeDefinitionNamespaceUriResolvesToLocalIndex)
{
  Fixture f;
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = node(42);  // a plain local target (no URI) - the focus is the type def
  reference.display_name() = ua::LocalizedText{ua::String{"target"}};
  reference.is_forward() = true;
  // A URI-bearing type definition: wire index 0 (URI present), URI maps to local index 1.
  reference.type_definition() = ua::ExpandedNodeId{ua::NodeId{0, 1234}, "http://vendor/local"};
  f.wireOps->browsePages.push_back({{reference}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make_with_namespace_table(make_namespace_table("http://vendor/local"));
  auto entry = f.next(cursor);

  ASSERT_TRUE(entry.is_good());
  EXPECT_EQ(entry.value().typeDefinition.namespace_index(), 1u)
    << "the typeDefinition URI must resolve to its local index - consistent with the target resolution";
  EXPECT_EQ(entry.value().typeDefinition.identifier().get_numeric(), 1234u)
    << "the type definition identifier is preserved through resolution";
}

// @verifies CL-VIEW-003
// @relation(CL-VIEW-003, scope=function)
TEST(BrowseCursor, MultiPageDrivesBrowseNext)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x01}, {}});  // page 1 + CP
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});  // page 2, no CP

  auto cursor = f.make();
  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good());
  EXPECT_EQ(first.value().targetNodeId, node(1));
  EXPECT_TRUE(cursor.has_more()) << "a continuation point is held after page 1";

  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good());
  EXPECT_EQ(second.value().targetNodeId, node(2)) << "page 2 fetched transparently via BrowseNext";

  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 1u);
  EXPECT_FALSE(f.wireOps->browseNextRequests[0].release_continuation_points()) << "a data BrowseNext";
  EXPECT_FALSE(cursor.has_more());
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST(BrowseCursor, ReplacementSessionInvalidatesContinuationPointBeforeBrowseNext)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x01}, {}});

  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  f.sessionGeneration->fetch_add(1);

  auto result = f.next(cursor);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSessionIdInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BrowseCursorSessionChanged");
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty())
    << "a stale continuation point must never be sent on the replacement Session";
  EXPECT_FALSE(cursor.has_more()) << "the stale continuation point is discarded locally";
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST(BrowseCursor, PreservedSessionGenerationContinuesNormally)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x01}, {}});
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  auto result = f.next(cursor);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().targetNodeId, node(2));
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 1u);
}

// Public API review D1 (API-D1.3): the same continuation point with an empty page is not, on its own, a
// loop - a server may stop early with nothing to show, for example when access control filtered a whole page
// (Part 4 5.8.2.1). The cursor asks again, and the references that follow are delivered.
// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, TheSameContinuationPointWithAnEmptyPageThenReferencesDeliversThem)
{
  Fixture f;
  const ua::ContinuationPoint stableCp{0x5A, 0x5A};
  f.wireOps->browsePages.push_back({{make_reference(1)}, stableCp, {}});
  f.wireOps->browsePages.push_back({{}, stableCp, {}});  // empty page, the same point
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good()) << "the walk continues past an empty page: "
                                << ua::to_string(second.status_code());
  EXPECT_EQ(second.value().targetNodeId, node(2));
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 2u);
}

// API-D1.1 / D1.2: the cursor asks again after an empty page with a continuation point, up to the limit (10
// by default); one more empty page in a row fails next with Bad_Timeout and the count, and releases the
// point.
// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, OneMoreEmptyPageThanTheLimitFailsWithTimeoutAndReleasesThePoint)
{
  Fixture f;
  const ua::ContinuationPoint loopCp{0x5A, 0x5A};
  f.wireOps->browsePages.push_back({{make_reference(1)}, loopCp, {}});
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back({{}, loopCp, {}});
  }

  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_bad()) << "a server that never makes progress cannot hold the cursor forever";
  EXPECT_EQ(second.status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(second.status_code().shared_detail(), nullptr);
  EXPECT_EQ(second.status_code().shared_detail()->code, "BrowseCursorEmptyPageLimitExceeded");
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 12u) << "eleven reads, then one release";
  EXPECT_TRUE(f.wireOps->browseNextRequests.back().release_continuation_points())
    << "the point the server still holds is released (CL-VIEW-002)";
  EXPECT_FALSE(cursor.has_more());
}

TEST(BrowseCursor, TenEmptyPagesThenReferencesAreDelivered)
{
  Fixture f;
  const ua::ContinuationPoint cp{0x01};
  f.wireOps->browsePages.push_back({{}, cp, {}});  // the initial Browse is empty too
  for (int page = 0; page < 9; ++page)
  {
    f.wireOps->browsePages.push_back({{}, cp, {}});
  }
  f.wireOps->browsePages.push_back({{make_reference(7)}, ua::ContinuationPoint{}, {}});

  auto cursor = f.make();
  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good()) << "ten empty pages are within the default limit: "
                               << ua::to_string(first.status_code());
  EXPECT_EQ(first.value().targetNodeId, node(7)) << "no empty page is seen by the caller";
}

// The limit counts empty pages IN A ROW: a page with references resets it, so a long walk with scattered
// empty pages is never refused for their total.
TEST(BrowseCursor, APageWithReferencesResetsTheEmptyPageCount)
{
  Fixture f;
  const ua::ContinuationPoint cp{0x01};
  f.wireOps->browsePages.push_back({{make_reference(1)}, cp, {}});
  f.wireOps->browsePages.push_back({{}, cp, {}});
  f.wireOps->browsePages.push_back({{}, cp, {}});
  f.wireOps->browsePages.push_back({{make_reference(2)}, cp, {}});
  f.wireOps->browsePages.push_back({{}, cp, {}});
  f.wireOps->browsePages.push_back({{}, cp, {}});
  f.wireOps->browsePages.push_back({{make_reference(3)}, ua::ContinuationPoint{}, {}});

  BrowseOptions options;
  options.continuationLimits.maxConsecutiveEmptyPages = 2;
  auto cursor = f.make(node(85), options);
  for (std::uint32_t expected : {1u, 2u, 3u})
  {
    auto entry = f.next(cursor);
    ASSERT_TRUE(entry.is_good()) << "entry " << expected << ": " << ua::to_string(entry.status_code());
    EXPECT_EQ(entry.value().targetNodeId, node(expected));
  }
}

TEST(BrowseCursor, TheLimitComesFromTheBrowseOptions)
{
  Fixture f;
  const ua::ContinuationPoint cp{0x01};
  for (int page = 0; page < 3; ++page)
  {
    f.wireOps->browsePages.push_back({{}, cp, {}});
  }
  f.wireOps->browsePages.push_back({{make_reference(7)}, ua::ContinuationPoint{}, {}});

  BrowseOptions options;
  options.continuationLimits.maxConsecutiveEmptyPages = 2;
  auto cursor = f.make(node(85), options);
  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_bad()) << "three empty pages exceed a limit of two";
  EXPECT_EQ(first.status_code().as_status(), ua::Status::BadTimeout);
}

TEST(BrowseCursor, StableHandleServerSameCpWithProgressPagesContinues)
{
  // A conforming stable-handle server (e.g. open62541) returns the SAME continuation-point bytes on every
  // page while making forward progress (NON-EMPTY pages). OPC UA does not require the CP bytes to vary, so
  // this is legitimate - the no-progress loop guard must NOT fire; every reference must be delivered, and the
  // walk terminates only when the server finally returns a null continuation point. (Regression guard for the
  // over-broad "any reused CP == self-loop" form that would have dropped references against open62541.)
  Fixture f;
  const ua::ContinuationPoint stableCp{0x5A, 0x5A};
  f.wireOps->browsePages.push_back({{make_reference(1)}, stableCp, {}});  // initial Browse: ref1 + CP
  f.wireOps->browsePages.push_back({{make_reference(2)}, stableCp, {}});  // BrowseNext: ref2 + the SAME CP
  f.wireOps->browsePages.push_back(
    {{make_reference(3)}, ua::ContinuationPoint{}, {}});  // BrowseNext: ref3 + null CP (walk done)

  auto cursor = f.make();
  auto r1 = f.next(cursor);
  ASSERT_TRUE(r1.is_good());
  EXPECT_EQ(r1.value().targetNodeId, node(1));

  auto r2 = f.next(cursor);
  ASSERT_TRUE(r2.is_good()) << "a same-CP page carrying references is legitimate progress, not a self-loop";
  EXPECT_EQ(r2.value().targetNodeId, node(2));

  auto r3 = f.next(cursor);
  ASSERT_TRUE(r3.is_good());
  EXPECT_EQ(r3.value().targetNodeId, node(3));

  auto exhausted = f.next(cursor);
  EXPECT_TRUE(exhausted.is_bad()) << "the walk ends only when the server returns a null continuation point";
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 2u)
    << "two data BrowseNexts (page 2 and page 3), no early termination";
}

// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, scope=function)
TEST(BrowseCursor, NextOnEmptyResultReportsExhausted)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{}, ua::ContinuationPoint{}, {}});  // zero references, no CP

  auto cursor = f.make();
  auto result = f.next(cursor);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadNoData});
  EXPECT_FALSE(cursor.has_more());
}

// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST(BrowseCursor, ServiceResultFailurePropagates)
{
  Fixture f;
  f.wireOps->browseServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};
  auto cursor = f.make();
  auto result = f.next(cursor);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadServerNotConnected})
    << "a service-result failure surfaces to the caller (not a silent empty page)";
}

// The cursor FACADE flattens a bad ResponseHeader.serviceResult that the tier-0 funnel returns verbatim
// (mirrors ua_discovery.cpp:47 + the read/write value facades). A service-level bad must surface with THAT
// code even when the server also cleared Results[] - it must NOT be misreported as the empty-results
// BadUnexpectedError. Falsifier: without the flatten the cursor returns BadUnexpectedError (or trusts the
// Good transport frame), losing the real Bad_ViewIdUnknown.
// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST(BrowseCursor, ServiceLevelBadWithEmptyResultsSurfacesServiceCode)
{
  Fixture f;
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadViewIdUnknown};
  f.wireOps->browseOmitResults = true;  // service-bad AND empty Results[] (the Err-002 + service-fault shape)

  auto cursor = f.make();
  auto result = f.next(cursor);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadViewIdUnknown})
    << "a bad service-level result must surface with its own code, not the empty-results BadUnexpectedError";
}

// A Good transport frame with a Good service result but an EMPTY Results[] array is a server contract
// violation (Err-002): the cursor must reject it as Bad_UnexpectedError rather than reporting a silent
// empty success. Falsifier: trusting the Good frame yields a Good exhausted/empty walk with no error.
// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST(BrowseCursor, ServiceGoodWithEmptyResultsRejected)
{
  Fixture f;
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::Good};
  f.wireOps->browseOmitResults = true;  // Good service result, but no per-node result for the single node

  auto cursor = f.make();
  auto result = f.next(cursor);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadUnexpectedError})
    << "a Good service result with a missing per-node result is a contract violation, not an empty success";
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, CloseReleasesContinuationPoint)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A, 0x0B}, {}});

  auto cursor = f.make();
  (void)f.next(cursor);  // fetch page 1, holds a continuation point

  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult result) { closed = result.is_good(); });
  f.ctx.run();
  EXPECT_TRUE(closed);
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->browseNextRequests[0].release_continuation_points())
    << "close issues a release-only BrowseNext";
}

// The release-only BrowseNext's ServiceResult reaches close_async's callback: a Good subcode as it was sent.
// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(BrowseCursor, CloseKeepsTheReleasesGoodSubcode)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A, 0x0B}, {}});
  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());  // holds a continuation point
  f.wireOps->browseNextHeaderServiceResult = ua::StatusCode{ua::Status::GoodOverload};

  std::optional<ua::VoidResult> closed;
  cursor.close_async([&closed](ua::VoidResult result) { closed = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(closed.has_value());
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 1u) << "close issues the release-only BrowseNext";
  EXPECT_TRUE(closed->is_good());
  EXPECT_EQ(closed->status_code().value(), ua::StatusCode{ua::Status::GoodOverload}.value());
}

// An Uncertain ServiceResult on the release reaches close_async's callback; the cursor is closed regardless.
// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(BrowseCursor, CloseKeepsTheReleasesUncertainCode)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A, 0x0B}, {}});
  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  f.wireOps->browseNextHeaderServiceResult = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};

  std::optional<ua::VoidResult> closed;
  cursor.close_async([&closed](ua::VoidResult result) { closed = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(closed.has_value());
  EXPECT_TRUE(closed->is_uncertain());
  EXPECT_EQ(closed->status_code().value(), ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable}.value());
  EXPECT_FALSE(cursor.has_more());
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST(BrowseCursor, CloseDiscardsStaleContinuationPointWithoutWireIo)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A, 0x0B}, {}});

  auto cursor = f.make();
  ASSERT_TRUE(f.next(cursor).is_good());
  f.sessionGeneration->fetch_add(1);

  bool callbackCalled = false;
  cursor.close_async(
    [&callbackCalled](ua::VoidResult result)
    {
      callbackCalled = true;
      EXPECT_TRUE(result.is_good()) << "local disposal of a stale server resource remains idempotent";
    });
  f.ctx.run();

  EXPECT_TRUE(callbackCalled);
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty())
    << "close must not release a stale continuation point on the replacement Session";
  EXPECT_FALSE(cursor.has_more());
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, DestructorReleasesContinuationPoint)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A}, {}});
  {
    auto cursor = f.make();
    (void)f.next(cursor);  // holds a continuation point
  }  // ~BrowseCursor posts a release-only BrowseNext
  ASSERT_EQ(f.wireOps->browseNextRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->browseNextRequests[0].release_continuation_points());
}

// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST(BrowseCursor, DestructorDoesNotReleaseStaleContinuationPointOnReplacementSession)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A}, {}});
  {
    auto cursor = f.make();
    ASSERT_TRUE(f.next(cursor).is_good());
    f.sessionGeneration->fetch_add(1);
  }
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty())
    << "destruction must discard rather than release a continuation point on the wrong Session";
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, DestructorWithoutContinuationPointIssuesNoBrowseNext)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});  // no CP
  {
    auto cursor = f.make();
    (void)f.next(cursor);
  }
  EXPECT_TRUE(f.wireOps->browseNextRequests.empty()) << "nothing to release -> no BrowseNext (idempotent)";
}

// Robustness (no requirement): the wire-interface-gone bail is a lifetime guard (section 7.5 /
// section 8.2A.13).
TEST(BrowseCursor, WireOpsGoneNextBailsCleanly)
{
  Fixture f;
  auto cursor = f.make();
  f.wireOps.reset();  // the Connection (and its wire interface) is gone

  auto result = f.next(cursor);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadConnectionClosed})
    << "a dropped Connection completes the advance with a boundary failure, not a deref";
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, WireOpsGoneCloseBailsCleanly)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A}, {}});
  auto cursor = f.make();
  (void)f.next(cursor);  // holds a continuation point
  f.wireOps.reset();  // interface gone before close

  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult result) { closed = result.is_good(); });
  f.ctx.run();
  EXPECT_TRUE(closed) << "close is best-effort: reports Good when there is nothing to free server-side";
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, CloseDuringInflightAdvanceReleasesFreshContinuationPoint)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  const ua::ContinuationPoint cp2{0x02};
  f.wireOps->browsePages.push_back({{make_reference(1)}, cp1, {}});  // page 1 + CP1
  f.wireOps->browsePages.push_back(
    {{make_reference(2)}, cp2, {}});  // page 2 + CP2 (the raced advance fetches)
  f.wireOps->deferBrowseNext = true;  // leave the advance's BrowseNext in flight so close can race it

  auto cursor = f.make();
  auto first = f.next(cursor);  // initial Browse (not a BrowseNext, so it is not deferred): ref1, holds CP1
  ASSERT_TRUE(first.is_good());

  // next#2: page consumed + CP1 held -> issues a data BrowseNext(CP1) that is captured (in flight); its
  // callback (advanceResult) stays pending until fire_deferred_browse_next().
  std::optional<ua::Result<BrowseCursor::Entry>> advanceResult;
  cursor.next_async([&advanceResult](ua::Result<BrowseCursor::Entry> r) { advanceResult = std::move(r); });

  // Close races the in-flight advance: it releases CP1 and marks the cursor closed.
  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult r) { closed = r.is_good(); });

  // The advance now returns page 2 carrying CP2. Pre-fix: CP2 is stored into the (now closed) cursor and
  // ~BrowseCursor early-returns on `closed`, so CP2 leaks server-side. Fixed: apply_browse_result sees the
  // cursor closed and issues a release-only BrowseNext for CP2.
  f.wireOps->fire_deferred_browse_next();
  f.ctx.run();

  bool releasedCp2 = false;
  for (const auto& request : f.wireOps->browseNextRequests)
  {
    if (request.release_continuation_points() && !request.continuation_points().empty() &&
        request.continuation_points()[0] == cp2)
    {
      releasedCp2 = true;
    }
  }
  EXPECT_TRUE(releasedCp2) << "the continuation point returned by the raced advance must be released, not "
                              "leaked into a closed cursor";
  ASSERT_TRUE(advanceResult.has_value()) << "the pending next() must still be completed exactly once";
  EXPECT_TRUE(advanceResult->is_bad()) << "a next() that lost the race to close completes as closed";
}

// W (section 3.1): the close release path must not silently swallow a Bad release-only BrowseNext.
// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, TryCloseSyncReturnsBadWithDetailOnReleaseFailure)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A}, {}});
  auto cursor = f.make();
  (void)f.next(cursor);  // holds a continuation point (browseServiceStatus still Good)

  // Force the release-only BrowseNext (issued by close) to fail with a detail-bearing status.
  f.wireOps->browseServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected,
    ua::make_error_detail("ReleaseFailed", "release-only BrowseNext failed", "test.close")};

  // The sync bridge blocks the caller, so the io_context must run on another thread (section 7.0).
  auto work = boost::asio::make_work_guard(f.ctx);
  std::thread runner([&f] { f.ctx.run(); });

  auto result = cursor.try_close_sync();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadServerNotConnected}.value())
    << "a release failure surfaces on close (not silently swallowed)";
  ASSERT_NE(result.shared_detail(), nullptr) << "the server's ErrorDetail propagates through close";

  work.reset();
  runner.join();
}

// @verifies CL-VIEW-002
// @relation(CL-VIEW-002, scope=function)
TEST(BrowseCursor, CloseSyncRethrowsOnReleaseFailure)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x0A}, {}});
  auto cursor = f.make();
  (void)f.next(cursor);  // holds a continuation point
  f.wireOps->browseServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected,
    ua::make_error_detail("ReleaseFailed", "release-only BrowseNext failed", "test.close")};

  auto work = boost::asio::make_work_guard(f.ctx);
  std::thread runner([&f] { f.ctx.run(); });

  EXPECT_THROW(cursor.close_sync(), ua::UaException) << "close_sync re-throws a Bad release result";

  work.reset();
  runner.join();
}

// Handle hygiene (no requirement): a moved-from cursor fails fast rather than dereferencing null.
TEST(BrowseCursor, MovedFromCursorNextReturnsBad)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  auto cursor = f.make();
  BrowseCursor moved = std::move(cursor);

  auto result =
    f.next(cursor);  // NOLINT(bugprone-use-after-move) - deliberately exercising the moved-from guard
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidState});
}

// The section 7.0 sync triple over next_async (no separate requirement; exercises try_next_sync/next_sync).
TEST(BrowseCursor, TryNextSyncReturnsEntry)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(7)}, ua::ContinuationPoint{}, {}});
  auto cursor = f.make();

  // The blocking sync bridge must run on a thread other than the executor's (section 7.0); drive the
  // io_context on a background thread kept alive by a work guard.
  auto work = boost::asio::make_work_guard(f.ctx);
  std::thread runner([&f] { f.ctx.run(); });

  auto result = cursor.try_next_sync();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.value().targetNodeId, node(7));

  work.reset();
  runner.join();
}

}  // namespace
