// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::NamespaceTable (section 8.5) - the per-Connection immutable NamespaceArray
// snapshot. These pin the pure value-type contracts (construction validation, lookup, translate,
// resolve_local, source tags); the reconnect-driven re-read / pending-remap flow lives on
// ConnectionImpl (section 8.2A) and is tested there.
//
// Falsifiability: each behaviour is asserted against a concrete, hand-built table. A stub that fails
// to build mIndexByUri fails every lookup/translate/resolve assertion; a translate that ignores the
// source URI returns the wrong index; a construction that skips NS0 validation lets a malformed array
// through. The negative cases assert the exact status code AND the ErrorDetail chain (symbolic code +
// preserved URI), so a silently-dropped detail also fails.
//
// Anchors: CL-SESS-028, CL-BASE-001, CL-ADDRSP-004, CL-VIEW-018, CL-DIAG-007, CL-MULTI-001..003.

#include "ua_namespace_table.h"

#include "ua_byte_string.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_uri.h"  // ua::specNamespaceUri (NS0)
#include "ua_node_id.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

namespace
{

using ua::ExpandedNodeId;
using ua::NodeId;
using ua::client::NamespaceIndex;
using ua::client::NamespaceTable;

const std::string ns0{ua::specNamespaceUri};

// Builds a valid table {NS0, "urn:a", "urn:b"} at the given generation, asserting create succeeded.
std::shared_ptr<const NamespaceTable> make_table(std::uint64_t generation = 0)
{
  auto result = NamespaceTable::create({ns0, "urn:a", "urn:b"}, std::nullopt, generation);
  EXPECT_TRUE(result.is_good());
  return result.value();
}

// Returns the value stored under context key `key`, or nullopt if absent.
std::optional<std::string> context_value(const ua::ErrorDetail& detail, std::string_view key)
{
  for (const auto& namedValue : detail.context)
  {
    if (namedValue.key == key)
    {
      return namedValue.value;
    }
  }
  return std::nullopt;
}

// --- construction (CL-BASE-001, section 8.5.5) -------------------------------------

TEST(NamespaceTableCreate, RejectsMissingNs0)
{
  auto result = NamespaceTable::create({"urn:not-ns0", "urn:a"}, std::nullopt, 0);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadUnexpectedError));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "Ns0Missing");
}

TEST(NamespaceTableCreate, RejectsEmptyArray)
{
  auto result = NamespaceTable::create({}, std::nullopt, 0);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadUnexpectedError));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "Ns0Missing");
}

TEST(NamespaceTableCreate, SucceedsWithNs0AndPreservesGeneration)
{
  auto result = NamespaceTable::create({ns0, "urn:a"}, std::nullopt, 7);
  ASSERT_TRUE(result.is_good());
  auto table = result.value();
  ASSERT_NE(table, nullptr);
  EXPECT_EQ(table->size(), 2u);
  EXPECT_EQ(table->generation(), 7u);
}

TEST(NamespaceTableCreate, Ns0AlwaysAtIndexZero)
{
  auto table = make_table();
  EXPECT_EQ(table->lookup_index(ns0), std::optional<NamespaceIndex>{0});
  EXPECT_EQ(table->lookup_uri(0), std::optional<std::string_view>{ns0});
}

TEST(NamespaceTableCreate, DuplicateUriKeepsFirstIndex)
{
  auto result = NamespaceTable::create({ns0, "urn:dup", "urn:dup"}, std::nullopt, 0);
  ASSERT_TRUE(result.is_good());
  auto table = result.value();
  // The vector keeps both entries; the reverse map resolves the URI to its FIRST (lowest) index.
  EXPECT_EQ(table->size(), 3u);
  EXPECT_EQ(table->lookup_index("urn:dup"), std::optional<NamespaceIndex>{1});
}

TEST(NamespaceTableCreate, UrisVersionRoundTrips)
{
  // UrisVersion is a VersionTime (UInt32 change counter, OPC 10000-5) - CL-BASE-001.
  const std::uint32_t version = 0x0A0B0C0D;
  auto result = NamespaceTable::create({ns0}, version, 0);
  ASSERT_TRUE(result.is_good());
  auto table = result.value();
  ASSERT_TRUE(table->uris_version().has_value());
  EXPECT_EQ(*table->uris_version(), version);
}

TEST(NamespaceTableCreate, UrisVersionAbsentWhenNotProvided)
{
  auto table = make_table();
  EXPECT_FALSE(table->uris_version().has_value());
}

// --- lookup (CL-ADDRSP-004) -------------------------------------------------

TEST(NamespaceTableLookup, IndexAndUriRoundTrip)
{
  auto table = make_table();
  EXPECT_EQ(table->lookup_index("urn:a"), std::optional<NamespaceIndex>{1});
  EXPECT_EQ(table->lookup_index("urn:b"), std::optional<NamespaceIndex>{2});
  EXPECT_EQ(table->lookup_uri(1), std::optional<std::string_view>{"urn:a"});
  EXPECT_EQ(table->lookup_uri(2), std::optional<std::string_view>{"urn:b"});
}

TEST(NamespaceTableLookup, UnknownUriAndOutOfRangeIndexReturnNullopt)
{
  auto table = make_table();
  EXPECT_EQ(table->lookup_index("urn:nope"), std::nullopt);
  EXPECT_EQ(table->lookup_uri(9), std::nullopt);
}

// --- translate (CL-SESS-028 / CL-ADDRSP-004, section 8.5.6) ------------------------
//
// These pin the value-type remap mechanism CL-ADDRSP-004 mandates ("persisted NodeIds must
// round-trip through the table; the client must not assume a stable index across Sessions"). The
// end-to-end reconnect ordering of CL-SESS-028 is verified against ConnectionImpl (section 8.2A).
// @verifies CL-ADDRSP-004

// @relation(CL-ADDRSP-004, scope=function)
TEST(NamespaceTableTranslate, ResolvesUriIntoTargetIndexSpace)
{
  auto source = NamespaceTable::create({ns0, "urn:x"}, std::nullopt, 0).value();
  auto target = NamespaceTable::create({ns0, "urn:a", "urn:x"}, std::nullopt, 1).value();

  auto result = target->translate(NodeId(1, "the-node"), *source);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), NodeId(2, "the-node"));  // urn:x is index 1 in source, index 2 in target
}

TEST(NamespaceTableTranslate, UriUnresolvedInTargetReturnsBadWithChain)
{
  auto source = NamespaceTable::create({ns0, "urn:x"}, std::nullopt, 3).value();
  auto target = NamespaceTable::create({ns0, "urn:a"}, std::nullopt, 4).value();  // no urn:x

  auto result = target->translate(NodeId(1, "the-node"), *source);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNodeIdUnknown));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "UriUnresolved");
  EXPECT_EQ(context_value(*result.error_detail(), "namespace.uri"), std::optional<std::string>{"urn:x"});
}

TEST(NamespaceTableTranslate, SourceIndexOutOfRangeReturnsBadWithChain)
{
  auto source = NamespaceTable::create({ns0}, std::nullopt, 0).value();  // size 1
  auto target = make_table();

  auto result = target->translate(NodeId(5, "the-node"), *source);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNodeIdInvalid));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "IndexOutOfRange");
}

TEST(NamespaceTableTranslate, IdentityFastPathSameSnapshot)
{
  auto table = make_table();
  auto result = table->translate(NodeId(2, "the-node"), *table);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), NodeId(2, "the-node"));
}

// Adversarial-review regression (section 3.1, correctness + security lenses): the identity fast-path
// (this == &sourceTable) must NOT skip the bounds check the general path applies. An out-of-range
// index must be rejected with Bad_NodeIdInvalid on BOTH paths, never returned Good - otherwise the
// identity and non-identity paths disagree for the same malformed input and an invalid NodeId leaks.
TEST(NamespaceTableTranslate, IdentityFastPathRejectsOutOfRangeIndex)
{
  auto table = make_table();  // size 3
  auto result = table->translate(NodeId(99, "the-node"), *table);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNodeIdInvalid));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "IndexOutOfRange");
}

// Adversarial-review regression (section 3.1, spec-conformance + correctness lenses): section 8.5.6 mandates
// the uri_unresolved chain carry the source AND target snapshot generations, and translate() has both.
TEST(NamespaceTableTranslate, UriUnresolvedChainCarriesSnapshotGenerations)
{
  auto source = NamespaceTable::create({ns0, "urn:x"}, std::nullopt, 3).value();
  auto target = NamespaceTable::create({ns0, "urn:a"}, std::nullopt, 4).value();  // no urn:x

  auto result = target->translate(NodeId(1, "the-node"), *source);
  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(
    context_value(*result.error_detail(), "namespace.source_generation"), std::optional<std::string>{"3"});
  EXPECT_EQ(
    context_value(*result.error_detail(), "namespace.target_generation"), std::optional<std::string>{"4"});
}

TEST(NamespaceTableTranslate, Ns0AlwaysTranslatesToNs0)
{
  auto source = NamespaceTable::create({ns0, "urn:x"}, std::nullopt, 0).value();
  auto target = NamespaceTable::create({ns0, "urn:a", "urn:b"}, std::nullopt, 1).value();
  auto result = target->translate(NodeId(0, "root"), *source);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), NodeId(0, "root"));
}

// --- resolve_local (CL-VIEW-018, section 8.5.6) ------------------------------------
// @verifies CL-VIEW-018

// @relation(CL-VIEW-018, scope=function)
TEST(NamespaceTableResolveLocal, UriPresentOverridesEncodedIndex)
{
  auto table = make_table();  // urn:b at index 2
  // Wire encodes index 0 when a URI is present; the URI must win.
  ExpandedNodeId expanded{NodeId(0, "the-node"), "urn:b"};
  auto result = table->resolve_local(expanded);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), NodeId(2, "the-node"));
}

TEST(NamespaceTableResolveLocal, EmptyUriUsesEncodedIndex)
{
  auto table = make_table();
  ExpandedNodeId expanded{NodeId(1, "the-node")};  // no namespace URI
  auto result = table->resolve_local(expanded);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), NodeId(1, "the-node"));
}

TEST(NamespaceTableResolveLocal, UriAbsentReturnsBadWithUriPreserved)
{
  auto table = make_table();
  ExpandedNodeId expanded{NodeId(0, "the-node"), "urn:not-here"};
  auto result = table->resolve_local(expanded);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNodeIdUnknown));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "UriUnresolved");
  EXPECT_EQ(
    context_value(*result.error_detail(), "namespace.uri"), std::optional<std::string>{"urn:not-here"});
}

TEST(NamespaceTableResolveLocal, EmptyUriIndexOutOfRangeReturnsBad)
{
  auto table = make_table();
  ExpandedNodeId expanded{NodeId(9, "the-node")};
  auto result = table->resolve_local(expanded);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNodeIdInvalid));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "IndexOutOfRange");
}

// --- source tags (CL-DIAG-007) ----------------------------------------------
// @verifies CL-DIAG-007

// @relation(CL-DIAG-007, scope=function)
TEST(NamespaceTableSourceTag, KnownUriResolvesToNamespaceSource)
{
  auto table = make_table();
  EXPECT_EQ(table->source_tag_for_namespace_uri("urn:a"), "server.namespace.urn:a");
}

TEST(NamespaceTableSourceTag, UnknownUriRecordsLiteralUnderUnknown)
{
  auto table = make_table();
  EXPECT_EQ(table->source_tag_for_namespace_uri("http://other.com/"), "server.unknown.http://other.com/");
}

// --- per-Connection isolation (CL-MULTI-001..003) ---------------------------

TEST(NamespaceTableIsolation, DistinctTablesDoNotShareState)
{
  auto tableA = NamespaceTable::create({ns0, "urn:common", "urn:a"}, std::nullopt, 0).value();
  auto tableB = NamespaceTable::create({ns0, "urn:common", "urn:b"}, std::nullopt, 0).value();
  // Same URI at the same index in both, but the tables are independent snapshots.
  EXPECT_EQ(tableA->lookup_uri(2), std::optional<std::string_view>{"urn:a"});
  EXPECT_EQ(tableB->lookup_uri(2), std::optional<std::string_view>{"urn:b"});
  EXPECT_EQ(tableA->lookup_index("urn:a"), std::optional<NamespaceIndex>{2});
  EXPECT_EQ(tableB->lookup_index("urn:a"), std::nullopt);
}

}  // namespace
