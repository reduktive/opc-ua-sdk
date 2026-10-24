// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <boost/asio/thread_pool.hpp>
#include <array>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <type_traits>
#include "ua_includes.h"
#include "ua_address_space.h"
#include "ua_fmt.h"
#include "ua_qualified_name.h"
#include "ua_status_code.h"
#include "ua_xml_element.h"
#include "ua_guid.h"
#include "ua_string.h"
#include "ua_data_value.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_variant.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_array.h"
#include "ua_namespace.h"
#include "ua_node_id.h"
#include "ua_byte_string.h"

using namespace ua;

// Moved from guid_tests.cpp

TEST(GuidTests, DefaultIsNullAndClear)
{
  Guid g;
  // A default-constructed Guid is the null (all-zero) Guid, per the ua_guid.h contract and OPC 10000-6
  // section 5.2.2.9 (a NodeId holding an all-zero Guid is the null NodeId). A fresh random identifier comes
  // only from the explicit generate() / create_and_generate() factories, never the default constructor.
  EXPECT_TRUE(g.is_null());
  // clear() is idempotent on an already-null Guid
  g.clear();
  EXPECT_TRUE(g.is_null());
}

TEST(GuidTests, ConstructFromStringAndAsStringRoundTrip)
{
  const char* text = "01234567-89ab-cdef-0123-456789abcdef";
  Guid g = Guid::parse(text);
  EXPECT_FALSE(g.is_null());

  // Copy construct and compare
  Guid copy{g};
  EXPECT_TRUE(copy == g);

  // String round trip using as_string()
  std::string s = g.as_string();
  Guid g2 = Guid::parse(s);
  EXPECT_TRUE(g2 == g);
}

TEST(GuidTests, UA_BinaryRoundTrip)
{
  Guid g = Guid::parse("00112233-4455-6677-8899-aabbccddeeff");
  auto bytes = g.as_ua_binary();
  ASSERT_EQ(bytes.size(), Guid::length);

  Guid g2;
  g2.from_ua_binary(span<const byte>(bytes.data(), bytes.size()));
  EXPECT_TRUE(g2 == g);
}

TEST(GuidTests, SwapAndMoveAndAssign)
{
  Guid a = Guid::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  Guid b = Guid::parse("11111111-2222-3333-4444-555555555555");

  Guid aCopy{a};
  Guid bCopy{b};
  EXPECT_TRUE(a == aCopy);
  EXPECT_TRUE(b == bCopy);

  a.swap(b);
  EXPECT_TRUE(a == bCopy);
  EXPECT_TRUE(b == aCopy);

  // Move construct
  Guid m{std::move(a)};
  EXPECT_TRUE(m == bCopy);

  // Move assign
  Guid n;
  n = std::move(b);
  EXPECT_TRUE(n == aCopy);
}

TEST(GuidTests, GenerateAndCreateAndGenerateProduceNonNullAndRoundTrip)
{
  Guid g;
  g.generate();
  EXPECT_FALSE(g.is_null());

  // String round-trip of generated values is valid
  Guid fromStr = Guid::parse(g.as_string());
  EXPECT_TRUE(fromStr == g);

  // create_and_generate returns a generated non-null GUID
  Guid g2 = Guid::create_and_generate();
  EXPECT_FALSE(g2.is_null());

  // It is extremely unlikely they are equal; but do not assert inequality to avoid flakiness
}

TEST(GuidTests, HashConsistencyAndUseInUnorderedSet)
{
  Guid g = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  Guid h{g};

  std::hash<Guid> hasher;
  EXPECT_EQ(hasher(g), hasher(h));

  std::unordered_set<Guid> set;
  set.insert(g);
  EXPECT_EQ(set.count(h), 1u);
}

TEST(GuidTests, BuiltInTypeIdMatchesHelper)
{
  EXPECT_EQ(Guid::built_in_type_id(), built_in_type<Guid>());
}

TEST(GuidTests, FromUaBinaryWithExactSpanLength)
{
  Guid g = Guid::parse("fedcba98-7654-3210-0246-8aceeca86420");
  auto v = g.as_ua_binary();
  Guid g2;
  // Provide exact span length
  g2.from_ua_binary(span<const byte>(v.data(), v.size()));
  EXPECT_TRUE(g2 == g);
}

// ExpandedNodeId tests

namespace
{
// Minimal stub Namespace implementation for NamespaceArray usage in tests
class TestNamespace final : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  explicit TestNamespace(String uri) : mMUri(std::move(uri))
  {}

  String uri() const override
  {
    return mMUri;
  }

  void find_nodes_async(const RequestInfo& /*request*/, std::span<const NodeId> nodeIds,
    std::optional<Duration> /*maxAge*/, std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    resolve_each(nodeIds,
      std::move(batchCallback),
      [](const NodeId& /*nodeId*/, std::function<void(NodeResult)> callback)
      { callback(NodeResult{Status::BadNodeIdUnknown}); });
  }

  void read_references_async(const RequestInfo& /*request*/, std::span<const ReferenceQuery> /*queries*/,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  void read_values_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
    std::span<const ValueReadItem> /*items*/, Duration /*maxAge*/, bool /*setSourceTimestamp*/,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

private:
  String mMUri;
};
}  // namespace

TEST(ExpandedNodeIdTests, DefaultConstructionAndFlags)
{
  ExpandedNodeId x;
  EXPECT_TRUE(x.is_local());
  EXPECT_TRUE(x.is_index_based());
  EXPECT_FALSE(x.is_remote());
  EXPECT_FALSE(x.is_not_index_based());
  EXPECT_TRUE(x.node_id().is_null());
  EXPECT_TRUE(x.is_null());

  // Clear keeps it null
  x.clear();
  EXPECT_TRUE(x.is_null());
  EXPECT_TRUE(x.namespace_uri().empty());
  EXPECT_EQ(x.server_index(), 0u);
}

TEST(ExpandedNodeIdTests, ConstructorsAndEquality)
{
  // NodeId-only
  ExpandedNodeId a{NodeId{2, 100}};
  EXPECT_TRUE(a.is_local());
  EXPECT_TRUE(a.is_index_based());
  EXPECT_FALSE(a.is_null());
  EXPECT_TRUE(a.namespace_uri().empty());
  EXPECT_EQ(a.server_index(), 0u);
  EXPECT_EQ(a.node_id().namespace_index(), 2);
  EXPECT_EQ(a, ExpandedNodeId(NodeId{2, 100}));
  EXPECT_NE(a, ExpandedNodeId(NodeId{2, 101}));

  // With namespace URI (not index-based)
  ExpandedNodeId b{NodeId{100}, "urn:test"};
  EXPECT_TRUE(b.is_local());
  EXPECT_FALSE(b.is_index_based());
  EXPECT_TRUE(b.is_not_index_based());
  EXPECT_EQ(b.namespace_uri(), String{"urn:test"});
  EXPECT_EQ(b.server_index(), 0u);

  // With server index (remote)
  ExpandedNodeId c{NodeId{2, 345}, 1u};
  EXPECT_TRUE(c.is_index_based());
  EXPECT_TRUE(c.is_remote());
  EXPECT_FALSE(c.is_local());
  EXPECT_EQ(c.server_index(), 1u);
  EXPECT_TRUE(c.namespace_uri().empty());

  // With both namespace URI and server index
  ExpandedNodeId d{NodeId{0, "Name"}, "urn:x", 3u};
  EXPECT_FALSE(d.is_index_based());
  EXPECT_TRUE(d.is_not_index_based());
  EXPECT_TRUE(d.is_remote());
  EXPECT_EQ(d.namespace_uri(), String{"urn:x"});
  EXPECT_EQ(d.server_index(), 3u);
}

TEST(ExpandedNodeIdTests, SetFromDefinitionSuccessCases)
{
  {
    ExpandedNodeId x;
    x = ExpandedNodeId::parse("i=123");
    EXPECT_TRUE(x.is_local());
    EXPECT_TRUE(x.is_index_based());
    EXPECT_EQ(x.server_index(), 0u);
    EXPECT_TRUE(x.namespace_uri().empty());
    EXPECT_TRUE(x.node_id().is_numeric());
    EXPECT_EQ(x.node_id().identifier().get_numeric(), 123u);
  }

  {
    ExpandedNodeId x;
    x = ExpandedNodeId::parse("svr=1;ns=2;i=345");
    EXPECT_TRUE(x.is_index_based());
    EXPECT_TRUE(x.is_remote());
    EXPECT_EQ(x.server_index(), 1u);
    EXPECT_TRUE(x.namespace_uri().empty());
    EXPECT_EQ(x.node_id().namespace_index(), 2);
    EXPECT_EQ(x.node_id().identifier().get_numeric(), 345u);
  }

  {
    ExpandedNodeId x;
    x = ExpandedNodeId::parse("nsu=urn:test;s=Name");
    EXPECT_TRUE(x.is_local());
    EXPECT_FALSE(x.is_index_based());
    EXPECT_EQ(x.namespace_uri(), String{"urn:test"});
    EXPECT_TRUE(x.node_id().is_string());
    EXPECT_EQ(x.node_id().namespace_index(), 0);  // ns index must be provided by NamespaceArray later
    EXPECT_EQ(x.node_id().identifier().get_string(), String{"Name"});
  }

  {
    ExpandedNodeId x;
    x = ExpandedNodeId::parse("svr=2;nsu=urn:x;i=3");
    EXPECT_TRUE(x.is_remote());
    EXPECT_FALSE(x.is_index_based());
    EXPECT_EQ(x.server_index(), 2u);
    EXPECT_EQ(x.namespace_uri(), String{"urn:x"});
    EXPECT_TRUE(x.node_id().is_numeric());
    EXPECT_EQ(x.node_id().identifier().get_numeric(), 3u);
  }
}

TEST(ExpandedNodeIdTests, SetFromDefinitionErrorCases)
{
  // svr=0 not allowed
  EXPECT_THROW(ExpandedNodeId::parse("svr=0;ns=2;i=3"), UaException);

  // Non-numeric server index
  EXPECT_THROW(ExpandedNodeId::parse("svr=abc;ns=2;i=3"), UaException);

  // Missing semicolon after svr value
  EXPECT_THROW(ExpandedNodeId::parse("svr=1ns=2;i=3"), UaException);

  // nsu present but not terminated with semicolon
  EXPECT_THROW(ExpandedNodeId::parse("nsu=urn:x i=3"), UaException);

  // nsu terminated but overall definition missing semicolon separation
  EXPECT_THROW(ExpandedNodeId::parse("nsu=urn:x i=3"), UaException);
}

// The server index is read from the definition's own view and nothing past it: an empty index
// ("svr=" cut from "svr=7;i=1") and an index that ends the view with no ';' are Bad_DecodingError, never
// a read past the view or a std::out_of_range.
// @verifies AC-COMP-CORE-XML-CODEC-04-TEXT-IS-READ-WITHIN-ITS-OWN-VIEW
TEST(ExpandedNodeIdTests, AServerIndexIsReadWithinItsView)
{
  constexpr std::string_view buffer{"svr=7;i=1"};
  for (const auto definition : {buffer.substr(0, 4), buffer.substr(0, 5), std::string_view{"svr=5"}})
  {
    try
    {
      ExpandedNodeId::parse(definition);
      ADD_FAILURE() << "accepted: " << definition;
    }
    catch (const UaException& error)
    {
      EXPECT_EQ(error.status(), Status::BadDecodingError) << definition;
    }
    catch (const std::exception& error)
    {
      ADD_FAILURE() << "a non-UaException escaped for " << definition << ": " << error.what();
    }
  }
}

// control: a server index followed by its ';' is read.
// @verifies AC-COMP-CORE-XML-CODEC-04-TEXT-IS-READ-WITHIN-ITS-OWN-VIEW
TEST(ExpandedNodeIdTests, AServerIndexTerminatedBySemicolonIsRead)
{
  ExpandedNodeId value;
  value = ExpandedNodeId::parse("svr=7;i=1");
  EXPECT_EQ(value.server_index(), 7u);
  EXPECT_EQ(value.node_id(), (NodeId{0, 1u}));
}

// A numeric identifier is the whole rest of the definition and a namespace index runs exactly to its
// ';': "i=5abc" and "ns=2x;i=1" are Bad_DecodingError rather than i=5 and ns=2.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST(NodeIdTests, TrailingTextAfterANumericIdentifierOrNamespaceIndexIsRefused)
{
  for (const std::string_view definition : {std::string_view{"i=5abc"},
         std::string_view{"ns=2x;i=1"},
         std::string_view{"i="},
         std::string_view{"ns=;i=1"}})
  {
    try
    {
      NodeId::parse(definition);
      ADD_FAILURE() << "accepted: " << definition;
    }
    catch (const UaException& error)
    {
      EXPECT_EQ(error.status(), Status::BadDecodingError) << definition;
    }
  }
}

// control: well-formed numeric definitions, with and without a namespace index, are read.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST(NodeIdTests, WellFormedNumericDefinitionsAreRead)
{
  NodeId value;
  value = NodeId::parse("i=5");
  EXPECT_EQ(value, (NodeId{0, 5u}));
  value = NodeId::parse("ns=2;i=345");
  EXPECT_EQ(value, (NodeId{2, 345u}));
}

TEST(ExpandedNodeIdTests, ClearResetsAllFields)
{
  ExpandedNodeId x{NodeId{2, 10}, "urn:a", 5u};
  x.clear();
  EXPECT_TRUE(x.is_null());
  EXPECT_TRUE(x.namespace_uri().empty());
  EXPECT_EQ(x.server_index(), 0u);
  EXPECT_TRUE(x.node_id().is_null());
}

// @relation(AC-SVR-BASE-001-NAMESPACEARRAY, scope=function)

TEST(ExpandedNodeIdTests, ToNodeIdResolutionWithNamespaceArray)
{
  boost::asio::thread_pool pool{1};
  auto addressSpace = AddressSpace::create("urn:test:resolver", pool.get_executor());
  auto ns = std::make_shared<TestNamespace>(String{"urn:test"});
  uint16_t testIdx = addressSpace.add_namespace_sync(ns);

  // to_node_id takes the namespace-resolution interface, never a concrete NamespaceArray, so the value
  // type stays free of any address-space dependency. Bind the interface to the
  // NamespaceArray's resolver for this test.
  NamespaceIndexResolver resolve = [&addressSpace](string_view uri)
  {
    return addressSpace.namespace_array().get_namespace_index(uri);
  };

  // Index-based: should return original NodeId unchanged
  ExpandedNodeId indexBased{NodeId{7, 999}};
  NodeId ni = indexBased.to_node_id(resolve);
  EXPECT_EQ(ni.namespace_index(), 7);
  EXPECT_EQ(ni.identifier().get_numeric(), 999u);

  // URI-based: should resolve to the index assigned in the NamespaceArray
  ExpandedNodeId uriBased{NodeId{42}, String{"urn:test"}};
  NodeId nr = uriBased.to_node_id(resolve);
  EXPECT_EQ(nr.namespace_index(), testIdx);
  EXPECT_EQ(nr.identifier().get_numeric(), 42u);

  pool.join();
}

TEST(ExpandedNodeIdTests, BuiltInTypeId)
{
  EXPECT_EQ(ExpandedNodeId::built_in_type_id(), built_in_type<ExpandedNodeId>());
}

// NodeId tests

TEST(NodeIdTests, DefaultConstructionAndClear)
{
  NodeId a;
  EXPECT_TRUE(a.is_numeric());
  EXPECT_TRUE(a.is_null());
  EXPECT_EQ(a.namespace_index(), 0u);
  // Clear keeps it numeric zero
  a.clear();
  EXPECT_TRUE(a.is_null());
  EXPECT_TRUE(a.is_numeric());
}

TEST(NodeIdTests, NumericAndNamespaceIndex)
{
  NodeId n0{123u};
  EXPECT_TRUE(n0.is_numeric());
  EXPECT_EQ(n0.namespace_index(), 0u);
  EXPECT_EQ(n0.identifier().get_numeric(), 123u);

  NodeId n1{2, 456u};
  EXPECT_TRUE(n1.is_numeric());
  EXPECT_EQ(n1.namespace_index(), 2u);
  EXPECT_EQ(n1.identifier().get_numeric(), 456u);

  // namespace_index() mutator reference
  n1.namespace_index() = 3;
  EXPECT_EQ(n1.namespace_index(), 3u);
}

// @verifies CL-ADDRSP-001
// @relation(CL-ADDRSP-001, scope=function)
TEST(NodeIdTests, EnumAndStringGuidOpaqueConstructors)
{
  // Enum-based (ObjectId)
  NodeId e0{ObjectId::ObjectsFolder};
  EXPECT_TRUE(e0.is_numeric());
  NodeId e0copy{ObjectId::ObjectsFolder};
  EXPECT_EQ(e0, e0copy);

  // String identifier
  NodeId s0{0, "Name"};
  EXPECT_TRUE(s0.is_string());
  EXPECT_EQ(s0.identifier().get_string(), String{"Name"});
  EXPECT_FALSE(s0.is_null());

  // Guid identifier
  Guid g = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  NodeId gid{g};
  EXPECT_TRUE(gid.is_guid());
  EXPECT_EQ(gid.identifier().get_guid(), g);
  EXPECT_FALSE(gid.is_null());  // a non-null Guid identifier makes the NodeId non-null

  // A NodeId built from the default (null, all-zero) Guid is the null NodeId (OPC 10000-6 section 5.2.2.9).
  // This pins the Guid default-constructor contract at the NodeId composition level: a random default Guid
  // (the prior bug) would have made every such NodeId spuriously non-null.
  EXPECT_TRUE(NodeId{Guid{}}.is_null());

  // Opaque (ByteString)
  ByteString bytes{0x01, 0x02, 0x03};
  NodeId b0{bytes};
  EXPECT_TRUE(b0.is_opaque());
  EXPECT_EQ(b0.identifier().get_opaque(), bytes);
}

// CL-ADDRSP-003 (OPC 10000-3 section 8.2.4, Table 23): the null NodeId - the canonical form (IdType Numeric,
// NamespaceIndex 0, Identifier 0) and every alternative null form (empty/null String, all-zero Guid,
// empty/null Opaque) - is defined AT NamespaceIndex 0. The same null-identifier forms in a non-zero
// namespace are ordinary references, NOT the null NodeId.
// @verifies CL-ADDRSP-003
// @relation(CL-ADDRSP-003, scope=function)
TEST(NodeIdTests, NullOnlyAtNamespaceZero)
{
  // Canonical + the four Table-23 alternative null forms, all at ns=0 -> null.
  EXPECT_TRUE(NodeId{}.is_null()) << "canonical numeric ns=0 i=0";
  EXPECT_TRUE((NodeId{uint16_t{0}, uint32_t{0}}).is_null()) << "explicit numeric ns=0 i=0";
  EXPECT_TRUE((NodeId{uint16_t{0}, std::string_view{""}}).is_null()) << "empty String ns=0";
  EXPECT_TRUE((NodeId{uint16_t{0}, Guid{}}).is_null()) << "all-zero Guid ns=0";
  EXPECT_TRUE((NodeId{uint16_t{0}, ByteString{}}).is_null()) << "empty Opaque ns=0";

  // The SAME null-identifier forms in a NON-zero namespace are ordinary references, not null - the two
  // negative constraints Table 23 mandates that the tree previously lacked (is_null was namespace-agnostic).
  EXPECT_FALSE((NodeId{uint16_t{1}, uint32_t{0}}).is_null()) << "ns=1,i=0 is a real reference, not null";
  EXPECT_FALSE((NodeId{uint16_t{1}, std::string_view{""}}).is_null()) << "ns=1,empty-String is not null";
  EXPECT_FALSE((NodeId{uint16_t{1}, Guid{}}).is_null()) << "ns=1,all-zero-Guid is not null";
  EXPECT_FALSE((NodeId{uint16_t{1}, ByteString{}}).is_null()) << "ns=1,empty-Opaque is not null";
}

TEST(NodeIdTests, EqualityAndHash)
{
  NodeId a{2, 100u};
  NodeId b{2, 100u};
  NodeId c{3, 100u};
  NodeId d{2, 101u};

  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(a, d);

  std::hash<NodeId> hasher;
  EXPECT_EQ(hasher(a), hasher(b));
}

// @verifies CL-ADDRSP-002
// @relation(CL-ADDRSP-002, scope=function)
TEST(NodeIdTests, StringIdentifiersAreCaseSensitiveAcrossIdentityOperations)
{
  const NodeId upper{2, "Foo"};
  const NodeId lower{2, "foo"};

  EXPECT_NE(upper, lower);
  EXPECT_NE(upper < lower, lower < upper);

  std::unordered_map<NodeId, std::string> values;
  values.emplace(upper, "upper");
  values.emplace(lower, "lower");
  ASSERT_EQ(values.size(), 2u);
  EXPECT_EQ(values.at(upper), "upper");
  EXPECT_EQ(values.at(lower), "lower");
}

// @verifies CL-ADDRSP-001
// @relation(CL-ADDRSP-001, scope=function)
TEST(NodeIdTests, MaximumLengthStringAndOpaqueIdentifiersArePreserved)
{
  const std::string stringIdentifier(4096, 's');
  const NodeId stringNode{3, std::string_view{stringIdentifier}};
  ASSERT_TRUE(stringNode.is_string());
  EXPECT_EQ(stringNode.identifier().get_string().size(), 4096u);
  EXPECT_EQ(static_cast<std::string>(stringNode.identifier().get_string()), stringIdentifier);

  const ByteString opaqueIdentifier(4096, uint8_t{0xA5});
  const NodeId opaqueNode{4, opaqueIdentifier};
  ASSERT_TRUE(opaqueNode.is_opaque());
  EXPECT_EQ(opaqueNode.identifier().get_opaque().size(), 4096u);
  EXPECT_EQ(opaqueNode.identifier().get_opaque(), opaqueIdentifier);
}

// Part 3 section 8.2.4 counts String NodeId identifiers in characters, not UTF-8 bytes. Canonical
// UTF-8 is required to make that character count well-defined; malformed sequences are structural
// failures under the same RegisterNodes whole-request criterion.
// @verifies AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE
// @relation(AC-SVR-VIEW-REG-008-REGISTER-REJECTS-WHOLE, scope=function)
TEST(NodeIdTests, StructuralValidationCountsUnicodeCharactersAndRejectsMalformedUtf8)
{
  const auto repeatedCentSigns = [](size_t characterCount)
  {
    std::string value;
    value.reserve(characterCount * 2);
    for (size_t characterIndex = 0; characterIndex < characterCount; ++characterIndex)
    {
      value += "\xC2\xA2";
    }
    return value;
  };

  const std::string mixedWidthIdentifier{"A\xC2\xA2\xE6\xB0\xB4\xF0\x9F\x98\x80"};
  EXPECT_TRUE((NodeId{0, std::string_view{mixedWidthIdentifier}}.is_structurally_valid()))
    << "ASCII plus canonical two-, three-, and four-byte sequences are valid characters";

  const std::string maximumIdentifier = repeatedCentSigns(4096);
  EXPECT_TRUE((NodeId{0, std::string_view{maximumIdentifier}}.is_structurally_valid()));

  const std::string oversizedIdentifier = repeatedCentSigns(4097);
  EXPECT_FALSE((NodeId{0, std::string_view{oversizedIdentifier}}.is_structurally_valid()));

  const std::vector<std::string> malformedIdentifiers{
    "\x80",  // lone continuation
    "\xC0\xAF",  // overlong two-byte sequence
    "\xE2\x82",  // truncated sequence
    "\xE2"
    "A",  // non-continuation tail
    "\xE0\x80\x80",  // overlong three-byte sequence
    "\xED\xA0\x80",  // UTF-16 surrogate
    "\xF0\x80\x80\x80",  // overlong four-byte sequence
    "\xF4\x90\x80\x80",  // beyond U+10FFFF
  };
  for (const auto& malformedIdentifier : malformedIdentifiers)
  {
    EXPECT_FALSE((NodeId{0, std::string_view{malformedIdentifier}}.is_structurally_valid()));
  }
}

TEST(NodeIdTests, SetFromDefinitionSuccess)
{
  // Numeric without namespace
  {
    NodeId x;
    x = NodeId::parse("i=123");
    EXPECT_TRUE(x.is_numeric());
    EXPECT_EQ(x.namespace_index(), 0u);
    EXPECT_EQ(x.identifier().get_numeric(), 123u);
  }

  // Numeric with namespace
  {
    NodeId x;
    x = NodeId::parse("ns=2;i=345");
    EXPECT_EQ(x.namespace_index(), 2u);
    EXPECT_TRUE(x.is_numeric());
    EXPECT_EQ(x.identifier().get_numeric(), 345u);
  }

  // String
  {
    NodeId x;
    x = NodeId::parse("s=Hello");
    EXPECT_TRUE(x.is_string());
    EXPECT_EQ(x.identifier().get_string(), String{"Hello"});
    EXPECT_EQ(x.namespace_index(), 0u);
  }

  // Guid
  {
    NodeId x;
    x = NodeId::parse("g=00112233-4455-6677-8899-aabbccddeeff");
    EXPECT_TRUE(x.is_guid());
    EXPECT_EQ(x.identifier().get_guid(), Guid::parse("00112233-4455-6677-8899-aabbccddeeff"));
  }

  // Opaque (base64) - single byte 'a' -> YQ==
  {
    NodeId x;
    x = NodeId::parse("b=YQ==");
    EXPECT_TRUE(x.is_opaque());
    ByteString expected{uint8_t{'a'}};
    EXPECT_EQ(x.identifier().get_opaque(), expected);
  }
}

TEST(NodeIdTests, SetFromDefinitionErrorCases)
{
  // ns=0 is prohibited in textual form
  EXPECT_THROW(NodeId::parse("ns=0;i=1"), UaException);

  // Missing semicolon after namespace
  EXPECT_THROW(NodeId::parse("ns=2i=1"), UaException);

  // Unknown identifier prefix
  EXPECT_THROW(NodeId::parse("x=1"), UaException);

  // Namespace not permitted when flag set
  // A namespace URI and an index together name the namespace twice.
  EXPECT_THROW(ExpandedNodeId::parse("nsu=urn:x;ns=2;i=1"), UaException);
}

// @verifies CL-ADDRSP-001
// @relation(CL-ADDRSP-001, scope=function)
TEST(NodeIdTests, AsDefinitionAndRoundTrip)
{
  // Numeric without namespace
  NodeId a{123u};
  EXPECT_EQ(a.as_definition(), std::string{"i=123"});

  // Numeric with namespace
  NodeId b{2, 123u};
  EXPECT_EQ(b.as_definition(), std::string{"ns=2;i=123"});

  // String
  NodeId s{0, "Name"};
  EXPECT_EQ(s.as_definition(), std::string{"s=Name"});

  // Guid
  Guid g = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  NodeId gid{g};
  EXPECT_EQ(gid.as_definition(), std::string{"g=01234567-89ab-cdef-0123-456789abcdef"});

  // Opaque (ByteString) - encoded as "b=<base64>" (Part 6 section 5.3.1.10) and round-trips.
  ByteString bytes{0xAA};
  NodeId opaque{bytes};
  EXPECT_EQ(opaque.as_definition(), std::string{"b=qg=="});
  NodeId roundTripped;
  roundTripped = NodeId::parse(opaque.as_definition());
  EXPECT_EQ(roundTripped, opaque);
}

TEST(NodeIdTests, IdentifierGetterTypeErrors)
{
  NodeId a{123u};
  EXPECT_TRUE(a.is_numeric());
  EXPECT_THROW((void)a.identifier().get_string(), UaException);
  EXPECT_THROW((void)a.identifier().get_guid(), UaException);
  EXPECT_THROW((void)a.identifier().get_opaque(), UaException);
}

TEST(NodeIdTests, CopyMoveAndAssignment)
{
  NodeId a{2, 987u};
  NodeId b{a};
  EXPECT_EQ(a, b);

  NodeId c{std::move(b)};  // move ctor
  EXPECT_EQ(a, c);

  NodeId d;
  d = a;  // copy assign
  EXPECT_EQ(d, a);
}

TEST(NodeIdTests, ConversionFromExpandedNodeId)
{
  // Valid: local and index-based
  ExpandedNodeId x{NodeId{2, 100u}};
  NodeId y{x};
  EXPECT_EQ(y, NodeId(2, 100u));

  // Invalid: with namespace URI (not index-based)
  // The braces are required: a bare declaration as a macro argument
  // (`EXPECT_THROW(NodeId tmp{x}, ...)`) parses as a declarator to tree-sitter-cpp, and its
  // recovery swallowed the whole enclosing TEST node - so this was the one test case out of ~10,000
  // that the traceability gate could not resolve back to a declaration once the suites began
  // emitting execution evidence (qa_remediation_plan.md R8).
  ExpandedNodeId notIndexBased{NodeId{100u}, String{"urn:test"}};
  EXPECT_THROW(
    {
      NodeId tmp{notIndexBased};
      (void)tmp;
    },
    UaException);

  // Invalid: remote server index
  ExpandedNodeId remote{NodeId{2, 345u}, 1u};
  EXPECT_THROW(
    {
      NodeId tmp{remote};
      (void)tmp;
    },
    UaException);
}

TEST(NodeIdTests, BuiltInTypeId)
{
  EXPECT_EQ(NodeId::built_in_type_id(), BuiltInTypeId{BuiltInTypeId::NodeId});
}

// DiagnosticInfo tests

TEST(DiagnosticInfoTests, DefaultAndNullness)
{
  DiagnosticInfo di{};
  // A default-constructed DiagnosticInfo has no content and is null.
  EXPECT_TRUE(di.is_null());
  EXPECT_FALSE(di.is_not_null());
}

TEST(DiagnosticInfoTests, SettersGettersAndIsNotNull)
{
  DiagnosticInfo di{};

  // Set all optional primitive fields
  di.symbolic_id() = 1;
  di.namespace_uri() = 2;
  di.locale() = 3;
  di.localized_text() = 4;
  di.additional_info() = std::string{"extra"};
  di.inner_status_code() = StatusCode{Status::BadUnexpectedError};

  // Set inner diagnostic info
  di.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  di.inner_diagnostic_info()->symbolic_id() = 42;

  // Getters reflect the values
  ASSERT_TRUE(di.symbolic_id().has_value());
  EXPECT_EQ(*di.symbolic_id(), 1);
  ASSERT_TRUE(di.namespace_uri().has_value());
  EXPECT_EQ(*di.namespace_uri(), 2);
  ASSERT_TRUE(di.locale().has_value());
  EXPECT_EQ(*di.locale(), 3);
  ASSERT_TRUE(di.localized_text().has_value());
  EXPECT_EQ(*di.localized_text(), 4);
  ASSERT_TRUE(di.additional_info().has_value());
  EXPECT_EQ(*di.additional_info(), std::string("extra"));
  ASSERT_TRUE(di.inner_status_code().has_value());
  EXPECT_EQ(*di.inner_status_code(), StatusCode{Status::BadUnexpectedError});
  ASSERT_TRUE(static_cast<bool>(di.inner_diagnostic_info()));
  EXPECT_TRUE(di.inner_diagnostic_info()->symbolic_id().has_value());
  EXPECT_EQ(*di.inner_diagnostic_info()->symbolic_id(), 42);

  // With any field set, is_not_null() must be true while is_null() stays false
  EXPECT_TRUE(di.is_not_null());
  EXPECT_FALSE(di.is_null());
}

TEST(DiagnosticInfoTests, ClearResetsAll)
{
  DiagnosticInfo di{};
  di.symbolic_id() = 1;
  di.namespace_uri() = 2;
  di.locale() = 3;
  di.localized_text() = 4;
  di.additional_info() = std::string{"info"};
  di.inner_status_code() = StatusCode{Status::BadNodeIdUnknown};
  di.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  di.clear();

  EXPECT_FALSE(di.symbolic_id().has_value());
  EXPECT_FALSE(di.namespace_uri().has_value());
  EXPECT_FALSE(di.locale().has_value());
  EXPECT_FALSE(di.localized_text().has_value());
  EXPECT_FALSE(di.additional_info().has_value());
  EXPECT_FALSE(di.inner_status_code().has_value());
  EXPECT_FALSE(static_cast<bool>(di.inner_diagnostic_info()));
  EXPECT_FALSE(di.is_not_null());
  EXPECT_TRUE(di.is_null());
}

TEST(DiagnosticInfoTests, CopyConstructorDeepCopiesInner)
{
  DiagnosticInfo a{};
  a.symbolic_id() = 7;
  a.additional_info() = std::string{"alpha"};
  a.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  a.inner_diagnostic_info()->symbolic_id() = 8;

  DiagnosticInfo b{a};

  // All fields equal
  EXPECT_TRUE(b == a);

  // Ensure deep copy for inner_diagnostic_info
  ASSERT_TRUE(static_cast<bool>(a.inner_diagnostic_info()));
  ASSERT_TRUE(static_cast<bool>(b.inner_diagnostic_info()));
  EXPECT_NE(a.inner_diagnostic_info().get(), b.inner_diagnostic_info().get());

  // Mutate original and ensure copy remains unchanged
  *a.symbolic_id() = 9;
  *a.inner_diagnostic_info()->symbolic_id() = 10;
  EXPECT_NE(b.symbolic_id(), a.symbolic_id());
  EXPECT_NE(*b.inner_diagnostic_info()->symbolic_id(), *a.inner_diagnostic_info()->symbolic_id());
}

TEST(DiagnosticInfoTests, CopyAssignmentAndSelfAssignment)
{
  DiagnosticInfo a{};
  a.namespace_uri() = 11;
  a.locale() = 12;
  a.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  a.inner_diagnostic_info()->localized_text() = 13;

  DiagnosticInfo b{};
  b = a;  // copy assignment
  EXPECT_TRUE(b == a);
  ASSERT_TRUE(static_cast<bool>(b.inner_diagnostic_info()));
  EXPECT_NE(b.inner_diagnostic_info().get(), a.inner_diagnostic_info().get());  // deep copy

  // Self-assignment should be a no-op and not crash
  b = b;
  EXPECT_TRUE(b == b);
}

TEST(DiagnosticInfoTests, MoveConstructionAndAssignment)
{
  DiagnosticInfo src{};
  src.symbolic_id() = 100;
  src.additional_info() = std::string{"move"};
  src.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  src.inner_diagnostic_info()->symbolic_id() = 200;

  DiagnosticInfo moved{std::move(src)};  // move-construct
  EXPECT_TRUE(moved.is_not_null());
  ASSERT_TRUE(static_cast<bool>(moved.inner_diagnostic_info()));
  EXPECT_EQ(*moved.symbolic_id(), 100);
  EXPECT_EQ(*moved.inner_diagnostic_info()->symbolic_id(), 200);

  DiagnosticInfo assigned{};
  assigned = std::move(moved);  // move-assign
  ASSERT_TRUE(static_cast<bool>(assigned.inner_diagnostic_info()));
  EXPECT_EQ(*assigned.symbolic_id(), 100);
  EXPECT_EQ(*assigned.inner_diagnostic_info()->symbolic_id(), 200);
}

TEST(DiagnosticInfoTests, EqualityCoversAllFields)
{
  DiagnosticInfo a{};
  DiagnosticInfo b{};
  EXPECT_TRUE(a == b);

  a.symbolic_id() = 1;
  EXPECT_FALSE(a == b);
  b.symbolic_id() = 1;
  EXPECT_TRUE(a == b);

  a.namespace_uri() = 2;
  EXPECT_FALSE(a == b);
  b.namespace_uri() = 2;
  EXPECT_TRUE(a == b);

  a.locale() = 3;
  EXPECT_FALSE(a == b);
  b.locale() = 3;
  EXPECT_TRUE(a == b);

  a.localized_text() = 4;
  EXPECT_FALSE(a == b);
  b.localized_text() = 4;
  EXPECT_TRUE(a == b);

  a.additional_info() = std::string{"x"};
  EXPECT_FALSE(a == b);
  b.additional_info() = std::string{"x"};
  EXPECT_TRUE(a == b);

  a.inner_status_code() = StatusCode{Status::BadNotFound};
  EXPECT_FALSE(a == b);
  b.inner_status_code() = StatusCode{Status::BadNotFound};
  EXPECT_TRUE(a == b);

  a.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  a.inner_diagnostic_info()->symbolic_id() = 9;
  EXPECT_FALSE(a == b);
  b.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  b.inner_diagnostic_info()->symbolic_id() = 9;
  EXPECT_TRUE(a == b);
}

TEST(DiagnosticInfoTests, BuiltInTypeId)
{
  EXPECT_EQ(DiagnosticInfo::built_in_type_id(), built_in_type<DiagnosticInfo>());
}

// Moved from data_value_tests.cpp

TEST(DataValueTests, DefaultIsNull)
{
  DataValue dv;
  EXPECT_TRUE(dv.is_null());
  EXPECT_TRUE(dv.value().empty());
  EXPECT_FALSE(dv.status().has_value());
  EXPECT_FALSE(dv.source_timestamp().has_value());
  EXPECT_FALSE(dv.server_timestamp().has_value());
  EXPECT_FALSE(dv.source_pico_seconds().has_value());
  EXPECT_FALSE(dv.server_pico_seconds().has_value());
}

TEST(DataValueTests, SetValueAndStatus)
{
  DataValue dv;
  // Set Variant value
  dv.value() = int32_t{123};
  EXPECT_FALSE(dv.is_null());
  ASSERT_TRUE(dv.value().is_int32());
  EXPECT_EQ(dv.value().as<int32_t>(), 123);

  // Set StatusCode
  StatusCode sc{Status::BadNotFound};
  dv.status() = sc;
  ASSERT_TRUE(dv.status().has_value());
  EXPECT_TRUE(dv.status()->equivalent(StatusCode{Status::BadNotFound}));

  // Changing value changes equality
  DataValue other = dv;
  EXPECT_TRUE(other == dv);
  other.value() = int32_t{124};
  EXPECT_FALSE(other == dv);
}

TEST(DataValueTests, TimestampsAndPicoSeconds)
{
  DataValue dv;

  // Source timestamp and pico seconds
  DateTime srcTs{2023, 1, 2, 3, 4, 5.0};
  dv.source_timestamp() = srcTs;
  dv.source_pico_seconds() = static_cast<uint16_t>(0);
  ASSERT_TRUE(dv.source_timestamp().has_value());
  ASSERT_TRUE(dv.source_pico_seconds().has_value());
  EXPECT_EQ(dv.source_timestamp()->value(), srcTs.value());
  EXPECT_EQ(*dv.source_pico_seconds(), static_cast<uint16_t>(0));

  // Server timestamp and pico seconds with boundary value
  DateTime srvTs{2024, 5, 6, 7, 8, 9.5};
  dv.server_timestamp() = srvTs;
  dv.server_pico_seconds() = DataValue::maxPicoSeconds;
  ASSERT_TRUE(dv.server_timestamp().has_value());
  ASSERT_TRUE(dv.server_pico_seconds().has_value());
  EXPECT_EQ(dv.server_timestamp()->value(), srvTs.value());
  EXPECT_EQ(*dv.server_pico_seconds(), DataValue::maxPicoSeconds);

  // Equality reflects timestamps
  DataValue same = dv;
  EXPECT_TRUE(same == dv);
  same.server_pico_seconds() = static_cast<uint16_t>(1234);
  EXPECT_FALSE(same == dv);
}

TEST(DataValueTests, ClearResetsToNull)
{
  DataValue dv;
  dv.value() = String{"abc"};
  dv.status() = StatusCode{Status::UncertainNoCommunicationLastUsableValue};
  dv.source_timestamp() = DateTime{2022, 2, 2, 2, 2, 2.0};
  dv.server_timestamp() = DateTime{2022, 2, 2, 2, 2, 2.0};
  dv.source_pico_seconds() = static_cast<uint16_t>(1);
  dv.server_pico_seconds() = static_cast<uint16_t>(2);

  dv.clear();
  EXPECT_TRUE(dv.is_null());
  EXPECT_TRUE(dv.value().empty());
  EXPECT_FALSE(dv.status().has_value());
  EXPECT_FALSE(dv.source_timestamp().has_value());
  EXPECT_FALSE(dv.server_timestamp().has_value());
  EXPECT_FALSE(dv.source_pico_seconds().has_value());
  EXPECT_FALSE(dv.server_pico_seconds().has_value());
}

TEST(DataValueTests, CopyAndMoveSemantics)
{
  DataValue original;
  original.value() = double{3.14};
  original.status() = StatusCode{Status::BadInternalError};
  original.source_timestamp() = DateTime{2020, 1, 1, 0, 0, 0.0};
  original.server_timestamp() = DateTime{2020, 1, 1, 1, 1, 1.0};
  original.source_pico_seconds() = static_cast<uint16_t>(7);
  original.server_pico_seconds() = static_cast<uint16_t>(8);

  // Copy construct
  DataValue copy{original};
  EXPECT_TRUE(copy == original);

  // Copy assign
  DataValue copyAssign;
  copyAssign = original;
  EXPECT_TRUE(copyAssign == original);

  // Move construct
  DataValue moved{std::move(copy)};
  EXPECT_TRUE(moved == original);

  // Move assign
  DataValue movedAssign;
  movedAssign = std::move(copyAssign);
  EXPECT_TRUE(movedAssign == original);
}

// DateTime tests - comprehensive coverage

TEST(DateTimeTests, DefaultConstructionAndIsNullBehavior)
{
  DateTime dt;  // default initializes to min() and is considered null
  EXPECT_TRUE(dt.is_null());

  // Setting value to min() makes it null
  dt.value() = DateTime::min();
  EXPECT_TRUE(dt.is_null());

  // Setting to max clears null state
  dt.value() = DateTime::max();
  EXPECT_FALSE(dt.is_null());
}

TEST(DateTimeTests, IsNullWhenLessThanMin)
{
  using namespace ua::datetime;
  DateTime dt;
  // Force a value smaller than min() and verify it's still treated as null
  dt.value() = DateTime::min() - OneHundredNanoSeconds{1};
  EXPECT_TRUE(dt.is_null());
}

TEST(DateTimeTests, BuiltInTypeId)
{
  EXPECT_EQ(DateTime::built_in_type_id(), built_in_type<DateTime>());
}

TEST(DateTimeTests, ConstructFromYMDHMSAndOffset)
{
  // 2009-10-10 17:00:00 with -300 minutes offset equals 2009-10-10 12:00:00 UTC
  DateTime withOffset{2009, 10, 10, 17, 0, 0.0, -300};
  DateTime utc{2009, 10, 10, 12, 0, 0.0, 0};
  EXPECT_EQ(withOffset, utc);

  // Fractional seconds are supported
  DateTime frac{2023, 1, 2, 3, 4, 5.25, 0};
  DateTime later{2023, 1, 2, 3, 4, 5.30, 0};
  EXPECT_LT(frac, later);
}

TEST(DateTimeTests, ThrowsOnInvalidDate)
{
  // Invalid calendar date
  EXPECT_THROW((DateTime{2023, 4, 31, 0, 0, 0.0, 0}), UaException);
  // Invalid month
  EXPECT_THROW((DateTime{2023, 13, 1, 0, 0, 0.0, 0}), UaException);
}

TEST(DateTimeTests, ThrowsOnTooLargeOffset)
{
  // Offset greater than 14 hours in magnitude should throw
  EXPECT_THROW((DateTime{2023, 1, 1, 0, 0, 0.0, 15 * 60}), UaException);
  EXPECT_THROW((DateTime{2023, 1, 1, 0, 0, 0.0, -15 * 60}), UaException);
}

TEST(DateTimeTests, UtcNowIsReasonableAndNotNull)
{
  auto before = std::chrono::system_clock::now();
  DateTime now = DateTime::now();
  EXPECT_FALSE(now.is_null());
  auto after = std::chrono::system_clock::now();
  using std::chrono::seconds;
  using std::chrono::time_point_cast;
  EXPECT_LE(time_point_cast<seconds>(before), time_point_cast<seconds>(now.value()));
  EXPECT_LE(time_point_cast<seconds>(now.value()), time_point_cast<seconds>(after));
}

TEST(DateTimeTests, UnixEpochValueIsZero)
{
  // 1970-01-01T00:00:00Z must be the system_clock epoch.
  DateTime epoch{1970, 1, 1, 0, 0, 0.0, 0};
  EXPECT_EQ(epoch.value().time_since_epoch().count(), 0);
}

TEST(DateTimeTests, ValueGetterAndSetter)
{
  // Build a value using the same arithmetic as in implementation
  using namespace std::chrono;
  using namespace ua::datetime;

  std::chrono::year y{2024};
  std::chrono::month m{std::chrono::May};
  std::chrono::day d{std::chrono::day{6}};
  std::chrono::hours hh{7};
  std::chrono::minutes mm{8};
  // 9.5 seconds -> 9.5s
  PicoSeconds pico{static_cast<int64_t>(9.5 * 1e12)};
  OneHundredNanoSeconds secs{round<OneHundredNanoSeconds>(pico)};

  std::chrono::sys_time<OneHundredNanoSeconds> expected =
    std::chrono::sys_days{std::chrono::year_month_day{y, m, d}} + hh + mm + secs;

  DateTime dt;
  dt.value() = expected;
  EXPECT_EQ(dt.value(), expected);
}

TEST(DateTimeTests, FractionalSecondsRoundedToHundredNanoseconds)
{
  using namespace ua::datetime;
  // Build using double seconds and verify the stored value matches the rounded 100ns grid
  int year = 2021, month = 12, day = 31, hour = 23, minute = 59;
  double seconds = 1.12345678;  // has > 7 fractional digits

  DateTime dt{year, month, day, hour, minute, seconds, 0};

  PicoSeconds pico{static_cast<int64_t>(seconds * 1e12)};
  OneHundredNanoSeconds secs{round<OneHundredNanoSeconds>(pico)};
  auto expected = std::chrono::sys_days{std::chrono::year_month_day{std::chrono::year{year},
                    std::chrono::month{static_cast<unsigned>(month)},
                    std::chrono::day{static_cast<unsigned>(day)}}} +
                  std::chrono::hours{hour} + std::chrono::minutes{minute} + secs;

  EXPECT_EQ(dt.value(), expected);
}

TEST(DateTimeTests, MinAndMaxBoundaries)
{
  using namespace ua::datetime;

  // Build expected min and max using chrono arithmetic (no reliance on time_t)
  const auto expectedMin = []
  {
    using namespace std::chrono;
    return std::chrono::sys_time<OneHundredNanoSeconds>{
      (sys_days{std::chrono::year{1601} / 1 / 1}).time_since_epoch()};
  }();

  const auto expectedMax = []
  {
    using namespace std::chrono;
    auto epoch = sys_days{std::chrono::year{1601} / 1 / 1};
    auto date = sys_days{std::chrono::year{9999} / 12 / 31};
    sys_time<seconds> secs = sys_time<seconds>{date} + 23h + 59min + 59s;
    return sys_time<OneHundredNanoSeconds>{secs.time_since_epoch()};
  }();

  EXPECT_EQ(DateTime::min(), expectedMin);
  EXPECT_EQ(DateTime::max(), expectedMax);
}

TEST(DateTimeTests, ComparisonOperators)
{
  DateTime a{2020, 1, 1, 0, 0, 0.0};
  DateTime b{2020, 1, 1, 0, 0, 0.0};
  DateTime c{2020, 1, 1, 0, 0, 0.1};
  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_LT(a, c);
  EXPECT_GT(c, b);
}

TEST(DataValueTests, BuiltInTypeId)
{
  EXPECT_EQ(DataValue::built_in_type_id(), BuiltInTypeId::DataValue);
}

TEST(DataValueTests, VariantInterop)
{
  // Prepare a DataValue
  DataValue dv;
  dv.value() = int32_t{42};
  dv.status() = StatusCode{Status::Good};

  // Put DataValue into Variant
  Variant v;
  v = std::move(dv);

  EXPECT_TRUE(v.is_data_value());

  // Retrieve as RefMember<DataValue>
  DataValue dv1;
  EXPECT_NO_THROW(dv1 = v.as<DataValue>());
  EXPECT_TRUE(dv1.value().is_int32());
  EXPECT_EQ(dv1.value().as<int32_t>(), 42);
  ASSERT_TRUE(dv1.status().has_value());
  EXPECT_TRUE(dv1.status()->equivalent(StatusCode{Status::Good}));
}

// Moved from string_tests.cpp

TEST(StringTests, DefaultAndClear)
{
  String s;
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.size(), 0u);

  // clear on empty is a no-op
  s.clear();
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.size(), 0u);
}

TEST(StringTests, ConstructFromSourcesAndConversions)
{
  // const char*
  String a{"hello"};
  EXPECT_FALSE(a.empty());
  EXPECT_EQ(a.size(), 5u);
  std::string asStd = static_cast<std::string>(a);
  EXPECT_EQ(asStd, "hello");
  std::string_view asView = static_cast<std::string_view>(a);
  EXPECT_EQ(asView, "hello");

  // std::string
  std::string src{"world"};
  String b{src};
  EXPECT_EQ(static_cast<std::string>(b), src);

  // string_view
  std::string_view v{"view"};
  String c{v};
  EXPECT_EQ(static_cast<std::string_view>(c), v);

  // assignment operators
  b = "hello";
  EXPECT_EQ(static_cast<std::string>(b), "hello");
  b = std::string{"new"};
  EXPECT_EQ(static_cast<std::string_view>(b), std::string_view{"new"});
  b = std::string_view{"sv"};
  EXPECT_EQ(static_cast<std::string>(b), "sv");
}

TEST(StringTests, EqualityAndHash)
{
  String a{"abc"};
  String b{"abc"};
  String c{"abcd"};

  // operator== (defaulted)
  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a == c);

  // hash consistency and use in unordered_set
  std::hash<String> hasher;
  EXPECT_EQ(hasher(a), hasher(b));

  std::unordered_set<String> set;
  set.insert(a);
  EXPECT_EQ(set.count(b), 1u);
  EXPECT_EQ(set.count(c), 0u);
}

TEST(StringTests, BuiltInTypeIdMatchesHelper)
{
  EXPECT_EQ(String::built_in_type_id(), built_in_type<String>());
}

TEST(StringTests, EqualStringsCompareEqual)
{
  String a{"fly"};
  String b{"fly"};

  EXPECT_EQ(a, b);

  String c{"buzz"};
  EXPECT_NE(a, c);
}

TEST(StringTests, ClearDoesNotAffectCopies)
{
  String a{"keep"};
  String b = a;

  a.clear();
  EXPECT_TRUE(a.empty());
  EXPECT_TRUE(a.is_null());
  // b should remain valid and unchanged
  EXPECT_FALSE(b.empty());
  EXPECT_EQ(static_cast<std::string>(b), "keep");
}

TEST(StringTests, IsNullDistinguishedFromEmpty)
{
  String null;
  EXPECT_TRUE(null.is_null());
  EXPECT_TRUE(null.empty());

  String empty{""};
  EXPECT_TRUE(empty.is_null());  // empty string stored as null
  EXPECT_TRUE(empty.empty());

  String value{"hello"};
  EXPECT_FALSE(value.is_null());
  EXPECT_FALSE(value.empty());
}

// QualifiedName tests
TEST(QualifiedNameTests, DefaultIsNullAndClear)
{
  QualifiedName q;
  EXPECT_TRUE(q.is_null());
  EXPECT_EQ(q.namespace_index(), 0u);
  EXPECT_TRUE(q.name().empty());

  // clear on default keeps it null
  q.clear();
  EXPECT_TRUE(q.is_null());
  EXPECT_EQ(q.namespace_index(), 0u);
  EXPECT_TRUE(q.name().empty());
}

TEST(QualifiedNameTests, ConstructorsAndGetters)
{
  // name-only constructor => namespaceIndex = 0
  QualifiedName q1{"foo"};
  EXPECT_FALSE(q1.is_null());
  EXPECT_EQ(q1.namespace_index(), 0u);
  EXPECT_EQ(static_cast<std::string>(q1.name()), std::string{"foo"});

  // namespace + name constructor
  QualifiedName q2{2, "bar"};
  EXPECT_FALSE(q2.is_null());
  EXPECT_EQ(q2.namespace_index(), 2u);
  EXPECT_EQ(static_cast<std::string>(q2.name()), std::string{"bar"});
}

TEST(QualifiedNameTests, MutatorsViaAccessors)
{
  QualifiedName q;

  // mutate via non-const accessors
  q.namespace_index() = 3;
  q.name() = "x";
  EXPECT_EQ(q.namespace_index(), 3u);
  EXPECT_EQ(static_cast<std::string>(q.name()), std::string{"x"});
  EXPECT_FALSE(q.is_null());

  // empty name with non-zero namespace is NOT null
  q.name().clear();
  EXPECT_TRUE(q.name().empty());
  EXPECT_EQ(q.namespace_index(), 3u);
  EXPECT_FALSE(q.is_null());

  // zero namespace and empty name => null
  q.namespace_index() = 0;
  EXPECT_TRUE(q.is_null());
}

TEST(QualifiedNameTests, EqualityAndInequality)
{
  QualifiedName a{1, "n"};
  QualifiedName b{1, "n"};
  QualifiedName c{0, "n"};
  QualifiedName d{1, "m"};
  QualifiedName e;  // null
  QualifiedName f;  // null

  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a == c);
  EXPECT_FALSE(a == d);
  EXPECT_TRUE(e == f);
}

TEST(QualifiedNameTests, BuiltInTypeId)
{
  EXPECT_EQ(QualifiedName::built_in_type_id(), built_in_type<QualifiedName>());
}

TEST(QualifiedNameTests, CopyMoveAndAssignment)
{
  QualifiedName a{5, "name"};

  // copy construct
  QualifiedName b{a};
  EXPECT_TRUE(b == a);

  // move construct
  QualifiedName c{std::move(b)};
  EXPECT_TRUE(c == a);

  // copy assign
  QualifiedName d;
  d = a;
  EXPECT_TRUE(d == a);

  // move assign
  QualifiedName e;
  e = std::move(d);
  EXPECT_TRUE(e == a);
}

TEST(QualifiedNameTests, ClearResetsFields)
{
  QualifiedName q{4, "reset"};
  ASSERT_FALSE(q.is_null());
  q.clear();
  EXPECT_TRUE(q.is_null());
  EXPECT_EQ(q.namespace_index(), 0u);
  EXPECT_TRUE(q.name().empty());
}

// -------------------------
// Moved from variant_tests.cpp
// -------------------------

namespace
{

// A minimal concrete Structure for testing structure-related Variant functionality
class DummyStructure final : public Structure
{
public:
  // Identify with standard BaseDataType for simplicity
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override
  {
    UA_UNUSED(ns);
    return dataTypeId == this->type_id(ns);
  }

  NodeId type_id(const CodecNamespaceContext& ns) const override
  {
    UA_UNUSED(ns);
    return NodeId{DataTypeId::Structure};
  }

  ExpandedNodeId type_id() const override
  {
    return ExpandedNodeId{NodeId{DataTypeId::Structure}};
  }

  String type_name() const override
  {
    return "DummyStructure";
  }

  void encode_id(StackDepth, const CodecNamespaceContext&, Encoder&) const override
  {}

  void encode(StackDepth, Encoder&) const override
  {}

  void decode(StackDepth, Decoder&) override
  {}

  unique_ptr<Structure> clone() const override
  {
    return std::make_unique<DummyStructure>(*this);
  }

  std::string to_string(int /*indent*/ = 0) const override
  {
    return "DummyStructure{}";
  }

  static BuiltInTypeId built_in_type_id()
  {
    return Structure::built_in_type_id();
  }
};

}  // namespace

TEST(VariantTests, DefaultAndClear)
{
  Variant v;
  EXPECT_TRUE(v.empty());
  EXPECT_FALSE(v.is_array());
  EXPECT_FALSE(v.is_scalar());
  // clear() on empty is ok
  v.clear();
  EXPECT_TRUE(v.empty());
}

TEST(VariantTests, ScalarBoolean)
{
  Variant v{true};
  EXPECT_TRUE(v.is_scalar());
  EXPECT_TRUE(v.is_boolean());
  EXPECT_EQ(v.get_built_in_type(), built_in_type<bool>());
  EXPECT_EQ(v.as<bool>(), true);
}

TEST(VariantTests, ScalarIntegers)
{
  Variant v8{int8_t{-12}};
  EXPECT_TRUE(v8.is_int8());
  EXPECT_EQ(v8.as<int8_t>(), -12);
  Variant vu8{uint8_t{250}};
  EXPECT_TRUE(vu8.is_uint8());
  EXPECT_EQ(vu8.as<uint8_t>(), 250);
  Variant v16{int16_t{-1234}};
  EXPECT_TRUE(v16.is_int16());
  EXPECT_EQ(v16.as<int16_t>(), -1234);
  Variant vu16{uint16_t{65000}};
  EXPECT_TRUE(vu16.is_uint16());
  EXPECT_EQ(vu16.as<uint16_t>(), 65000);
  Variant v32{int32_t{-1234567}};
  EXPECT_TRUE(v32.is_int32());
  EXPECT_EQ(v32.as<int32_t>(), -1234567);
  Variant vu32{uint32_t{4000000000U}};
  EXPECT_TRUE(vu32.is_uint32());
  EXPECT_EQ(vu32.as<uint32_t>(), 4000000000U);
  Variant v64{int64_t{-1234567890123LL}};
  EXPECT_TRUE(v64.is_int64());
  EXPECT_EQ(v64.as<int64_t>(), -1234567890123LL);
  Variant vu64{uint64_t{1234567890123456789ULL}};
  EXPECT_TRUE(vu64.is_uint64());
  EXPECT_EQ(vu64.as<uint64_t>(), 1234567890123456789ULL);
}

TEST(VariantTests, ScalarFloats)
{
  Variant vf{float{3.5f}};
  EXPECT_TRUE(vf.is_float());
  EXPECT_FLOAT_EQ(vf.as<float>(), 3.5f);
  Variant vd{double{-2.25}};
  EXPECT_TRUE(vd.is_double());
  EXPECT_DOUBLE_EQ(vd.as<double>(), -2.25);
}

TEST(VariantTests, ScalarStringAndXmlAndByteString)
{
  String s{"hello"};
  Variant vs{s};
  EXPECT_TRUE(vs.is_string());
  EXPECT_EQ(std::string(vs.as<String>()), std::string("hello"));

  XmlElement xe;
  xe = std::string("<a/>");
  Variant vx{xe};
  EXPECT_TRUE(vx.is_xml_element());
  EXPECT_EQ(std::string(vx.as<XmlElement>()), std::string("<a/>"));

  ByteString bs{1, 2, 3};
  Variant vb{bs};
  EXPECT_TRUE(vb.is_byte_string());
  auto got = vb.as<ByteString>();
  ASSERT_EQ(got.size(), 3u);
  EXPECT_EQ(got[0], uint8_t{1});
}

TEST(VariantTests, ScalarNodeIdsAndNames)
{
  NodeId nid{uint32_t{1}};
  ExpandedNodeId enid{nid};
  Variant vn{nid};
  EXPECT_TRUE(vn.is_node_id());
  EXPECT_EQ(vn.as<NodeId>(), nid);
  Variant ven{enid};
  EXPECT_TRUE(ven.is_expanded_node_id());
  EXPECT_EQ(ven.as<ExpandedNodeId>(), enid);

  QualifiedName qn{1, "name"};
  Variant vqn{qn};
  EXPECT_TRUE(vqn.is_qualified_name());
  EXPECT_EQ(vqn.as<QualifiedName>(), qn);

  LocalizedText lt{String{"text"}};
  Variant vlt{lt};
  EXPECT_TRUE(vlt.is_localized_text());
  EXPECT_EQ(vlt.as<LocalizedText>(), lt);
}

TEST(VariantTests, ScalarGuidDateTimeStatusDecimalDataValue)
{
  Guid g = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  Variant vg{g};
  EXPECT_TRUE(vg.is_guid());
  EXPECT_EQ(vg.as<Guid>(), g);

  DateTime dt{std::chrono::sys_time<datetime::OneHundredNanoSeconds>{}};
  Variant vdt{dt};
  EXPECT_TRUE(vdt.is_date_time());
  EXPECT_EQ(vdt.as<DateTime>().value(), dt.value());

  StatusCode sc{Status::Good};
  Variant vsc{sc};
  EXPECT_TRUE(vsc.is_status_code());
  EXPECT_TRUE(vsc.as<StatusCode>().equivalent(sc));

  Decimal dec;  // default OK
  Variant vdec{dec};
  EXPECT_TRUE(vdec.is_decimal());

  DataValue dv;  // default OK
  Variant vdv{dv};
  EXPECT_TRUE(vdv.is_data_value());
}

TEST(VariantTests, ScalarStructureRef)
{
  // Use the Variant ctor taking unique_ptr<T> where T derives Structure
  auto ptr = std::make_unique<DummyStructure>();
  Variant vs{std::move(ptr)};  // stores as RefStructure<Structure>
  EXPECT_TRUE(vs.is_structure());
}

TEST(VariantTests, CopyMoveAndEquality)
{
  Variant a{int32_t{42}};
  Variant b{a};
  EXPECT_TRUE(b.is_int32());
  EXPECT_EQ(b, a);

  Variant c{std::move(b)};  // move
  EXPECT_TRUE(c.is_int32());
  EXPECT_EQ(c.as<int32_t>(), 42);

  Variant d;
  d = c;
  EXPECT_TRUE(d.is_int32());
  EXPECT_EQ(d.as<int32_t>(), 42);
  Variant e;
  e = std::move(c);
  EXPECT_TRUE(e.is_int32());
  EXPECT_EQ(e.as<int32_t>(), 42);
}

TEST(VariantTests, GetBuiltInTypeThrowsOnEmpty)
{
  Variant v;
  EXPECT_THROW(
    {
      auto t = v.get_built_in_type();
      UA_UNUSED(t);
    },
    UaException);
}

TEST(VariantTests, ArraysPrimitiveAndObjects)
{
  // Primitive arrays
  Array<int32_t> a32;
  a32.payload() = {1, 2, 3};
  Variant v32{a32};
  EXPECT_TRUE(v32.is_array());
  EXPECT_TRUE(v32.is_array_of_int32());
  EXPECT_EQ(v32.get_array_base().size(), 3u);

  Array<uint8_t> au8;
  au8.payload() = {1, 2};
  Variant vu8{au8};
  EXPECT_TRUE(vu8.is_array_of_uint8());

  Array<double> ad;
  ad.payload() = {1.0, 2.0};
  Variant vd{ad};
  EXPECT_TRUE(vd.is_array_of_double());

  Array<bool> ab;
  ab.payload() = {true, false};
  Variant vb{ab};
  EXPECT_TRUE(vb.is_array_of_boolean());

  // Object arrays
  Array<String> as;
  as.payload() = {String{"a"}, String{"b"}};
  Variant vAs{as};
  EXPECT_TRUE(vAs.is_array_of_string());

  Array<ByteString> abs;
  abs.payload() = {ByteString{uint8_t{1}}, ByteString{uint8_t{2}}};
  Variant vAbs{abs};
  EXPECT_TRUE(vAbs.is_array_of_byte_string());

  Array<DateTime> adt;
  adt.payload() = {DateTime{}, DateTime{}};
  Variant vAdt{adt};
  EXPECT_TRUE(vAdt.is_array_of_date_time());

  Array<Guid> ag;
  ag.payload() = {Guid::parse("01234567-89ab-cdef-0123-456789abcdef")};
  Variant vAg{ag};
  EXPECT_TRUE(vAg.is_array_of_guid());

  Array<XmlElement> ax;
  ax.payload() = {};  // empty is fine
  Variant vAx{ax};
  EXPECT_TRUE(vAx.is_array_of_xml_element());

  Array<NodeId> an;
  an.payload() = {NodeId{1u}};
  Variant vAn{an};
  EXPECT_TRUE(vAn.is_array_of_node_id());

  Array<ExpandedNodeId> aen;
  aen.payload() = {ExpandedNodeId{NodeId{1u}}};
  Variant vAen{aen};
  EXPECT_TRUE(vAen.is_array_of_expanded_node_id());

  Array<StatusCode> asc;
  asc.payload() = {StatusCode{Status::Good}};
  Variant vAsc{asc};
  EXPECT_TRUE(vAsc.is_array_of_status_code());

  Array<QualifiedName> aqn;
  aqn.payload() = {QualifiedName{0, "n"}};
  Variant vAqn{aqn};
  EXPECT_TRUE(vAqn.is_array_of_qualified_name());

  Array<LocalizedText> alt;
  alt.payload() = {LocalizedText{String{"t"}}};
  Variant vAlt{alt};
  EXPECT_TRUE(vAlt.is_array_of_localized_text());

  Array<DataValue> adv;
  adv.payload() = {DataValue{}};
  Variant vAdv{adv};
  EXPECT_TRUE(vAdv.is_array_of_data_value());

  Array<Decimal> adec;
  adec.payload() = {Decimal{}};
  Variant vAdec{adec};
  EXPECT_TRUE(vAdec.is_array_of_decimal());

  Array<RefStructure<Structure>> arst;  // empty
  Variant vArs{arst};
  EXPECT_TRUE(vArs.is_array_of_structure());

  Array<Variant> av;
  av.payload() = {Variant{int32_t{7}}, Variant{String{"x"}}};
  Variant vAv{av};
  EXPECT_TRUE(vAv.is_array_of_variant());
}

// ------------------------------- XmlElement tests -------------------------------

TEST(XmlElementTests, DefaultConstructedIsEmptyAndClears)
{
  XmlElement xe;
  EXPECT_TRUE(xe.empty());

  // assign and then clear
  xe = std::string{"<root/>"};
  EXPECT_FALSE(xe.empty());
  EXPECT_EQ(std::string(xe.value()), std::string("<root/>"));
  xe.clear();
  EXPECT_TRUE(xe.empty());
  EXPECT_EQ(std::string(xe.value()), std::string(""));
}

TEST(XmlElementTests, AssignFromStringAndStringView)
{
  XmlElement xe;
  std::string s{"<a attr=\"1\"/>"};
  xe = s;  // std::string overload
  EXPECT_EQ(std::string(xe.value()), s);

  // string_view overload
  string_view sv{"<b>text</b>"};
  xe = sv;
  EXPECT_EQ(std::string(xe.value()), std::string(sv));
}

TEST(XmlElementTests, ValueGettersAndImplicitConversion)
{
  XmlElement xe;
  xe = std::string{"<x>&amp;&lt;&gt;\"'</x>"};

  // const getter returns a view, implicit conversion also returns a view
  string_view v1 = xe.value();
  string_view v2 = xe;  // implicit operator string_view
  EXPECT_EQ(v1, v2);
  EXPECT_EQ(std::string(v1), std::string("<x>&amp;&lt;&gt;\"'</x>"));

  // non-const getter allows mutation of the underlying string
  auto& ref = xe.value();
  ref.append("<!--c-->");
  EXPECT_EQ(std::string(xe.value()), std::string("<x>&amp;&lt;&gt;\"'</x><!--c-->"));
}

TEST(XmlElementTests, EqualityAndInequality)
{
  XmlElement a;
  XmlElement b;
  EXPECT_TRUE(a == b);  // both empty

  a = std::string{"<t/>"};
  b = std::string{"<t/>"};
  EXPECT_TRUE(a == b);

  b = std::string{"<t></t>"};
  EXPECT_FALSE(a == b);
}

TEST(XmlElementTests, CopyAndMoveSemantics)
{
  XmlElement a;
  a = std::string{"<copy/>"};

  // copy ctor
  XmlElement b{a};
  EXPECT_TRUE(a == b);

  // copy assignment
  XmlElement c;
  c = a;
  EXPECT_TRUE(a == c);

  // move ctor
  XmlElement d{std::move(c)};
  EXPECT_EQ(std::string(d.value()), std::string("<copy/>"));

  // move assignment
  XmlElement e;
  e = std::move(d);
  EXPECT_EQ(std::string(e.value()), std::string("<copy/>"));
}

TEST(XmlElementTests, BuiltInTypeId)
{
  EXPECT_EQ(XmlElement::built_in_type_id(), built_in_type<XmlElement>());
}

TEST(XmlElementTests, VariantIntegrationScalar)
{
  XmlElement xe;
  xe = std::string{"<a/>"};
  Variant v{xe};
  EXPECT_TRUE(v.is_xml_element());
  EXPECT_EQ(std::string(v.as<XmlElement>()), std::string("<a/>"));

  // mutate through Variant-held XmlElement reference
  v.as<XmlElement>() = std::string{"<b attr=\"x\"/>"};
  EXPECT_EQ(std::string(v.as<XmlElement>()), std::string("<b attr=\"x\"/>"));
}

TEST(XmlElementTests, VariantIntegrationArrayReadAndMutate)
{
  Array<XmlElement> arr;
  arr.payload() = {};
  arr.payload().push_back(XmlElement{});
  arr.payload()[0] = std::string{"<one/>"};
  arr.payload().push_back(XmlElement{});
  arr.payload()[1] = std::string{"<two/>"};

  Variant v{arr};
  EXPECT_TRUE(v.is_array());
  EXPECT_TRUE(v.is_array_of_xml_element());

  const auto& got = v.as<Array<XmlElement>>();
  ASSERT_EQ(got.size(), 2u);
  EXPECT_EQ(std::string(got[0]), std::string("<one/>"));
  EXPECT_EQ(std::string(got[1]), std::string("<two/>"));

  // mutate via non-const accessor
  auto& mut = v.as<Array<XmlElement>>();
  mut[1] = std::string{"<two-mod/>"};
  EXPECT_EQ(std::string(v.as<Array<XmlElement>>()[1]), std::string("<two-mod/>"));
}

TEST(XmlElementTests, HandlesLargeContent)
{
  // create a large xml text
  std::string big;
  big.reserve(5000);
  big.append("<data>");
  for (int i = 0; i < 1000; ++i)
  {
    big.append("<e i=\"");
    big.append(std::to_string(i));
    big.append("\"/>");
  }
  big.append("</data>");

  XmlElement xe;
  xe = big;
  EXPECT_EQ(std::string(xe.value()), big);
}

TEST(VariantTests, GetArrayBaseThrowsWhenNotArray)
{
  Variant v{int32_t{5}};
  EXPECT_THROW(
    {
      auto& b = v.get_array_base();
      UA_UNUSED(b);
    },
    UaException);
  Variant e;
  EXPECT_THROW(
    {
      auto& b = e.get_array_base();
      UA_UNUSED(b);
    },
    UaException);
}

TEST(VariantTests, MutateThroughGetValue)
{
  Variant v{int32_t{10}};
  v.as<int32_t>() = 11;
  EXPECT_EQ(v.as<int32_t>(), 11);
}

TEST(VariantTests, TypeMismatchAndEmptyAccessThrow)
{
  // Wrong-type and empty access must report BadInvalidState (not UB). All of
  // these throw sites route through the single throw_variant_error() helper, so
  // this also exercises that helper across many as<T> instantiations.

  // Empty Variant - every accessor throws rather than dereferencing nothing.
  Variant empty;
  EXPECT_THROW((void)empty.as<int32_t>(), UaException);
  EXPECT_THROW((void)empty.as<Array<int32_t>>(), UaException);

  // Scalar holding int32: requesting a different scalar type, or an array, throws.
  // Iterate several requested types so each as<T> mismatch lambda is covered.
  Variant scalar{int32_t{7}};
  EXPECT_EQ(scalar.as<int32_t>(), 7);  // matching type: no throw
  EXPECT_THROW((void)scalar.as<bool>(), UaException);
  EXPECT_THROW((void)scalar.as<double>(), UaException);
  EXPECT_THROW((void)scalar.as<float>(), UaException);
  EXPECT_THROW((void)scalar.as<String>(), UaException);
  EXPECT_THROW((void)scalar.as<NodeId>(), UaException);
  EXPECT_THROW((void)scalar.as<Guid>(), UaException);
  EXPECT_THROW((void)scalar.as<Array<int32_t>>(), UaException);  // scalar accessed as array

  // Array holding Array<int32>: requesting a scalar, or a wrong element type, throws.
  Array<int32_t> a;
  a.payload() = {1, 2, 3};
  Variant arr{a};
  EXPECT_NO_THROW((void)arr.get_array_base());  // is an array: ok
  EXPECT_THROW((void)arr.as<int32_t>(), UaException);  // array accessed as scalar
  EXPECT_THROW((void)arr.as<Array<double>>(), UaException);  // wrong element type
  EXPECT_THROW((void)arr.as<Array<String>>(), UaException);
}

TEST(VariantTests, GetValueForArray_PrimitiveReadAndMutate)
{
  Array<int32_t> a;
  a.payload() = {1, 2, 3};
  Variant v{a};
  ASSERT_TRUE(v.is_array());
  ASSERT_TRUE(v.is_array_of_int32());

  // const access
  const Variant& cv = v;
  const auto& ca = cv.as<Array<int32_t>>();
  ASSERT_EQ(ca.size(), 3u);
  EXPECT_EQ(ca[0], 1);
  EXPECT_EQ(ca[1], 2);
  EXPECT_EQ(ca[2], 3);

  // non-const access and mutate
  auto& ma = v.as<Array<int32_t>>();
  ma[1] = 42;
  EXPECT_EQ(v.as<Array<int32_t>>()[1], 42);
}

TEST(VariantTests, GetValueForArray_ObjectReadAndMutate)
{
  Array<String> as;
  as.payload() = {String{"a"}, String{"b"}};
  Variant v{as};
  ASSERT_TRUE(v.is_array_of_string());

  // read
  const auto& r = static_cast<const Variant&>(v).as<Array<String>>();
  ASSERT_EQ(r.size(), 2u);
  EXPECT_EQ(std::string(r[0]), std::string("a"));
  EXPECT_EQ(std::string(r[1]), std::string("b"));

  // mutate string content through non-const reference
  auto& w = v.as<Array<String>>();
  w[1] = String{"bee"};
  EXPECT_EQ(std::string(v.as<Array<String>>()[1]), std::string("bee"));
}

TEST(VariantTests, GetValueForArray_VariantElementsAccess)
{
  Array<Variant> av;
  av.payload() = {Variant{int32_t{7}}, Variant{String{"x"}}};
  Variant v{av};
  ASSERT_TRUE(v.is_array_of_variant());

  auto& arr = v.as<Array<Variant>>();
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_TRUE(arr[0].is_int32());
  EXPECT_TRUE(arr[1].is_string());
  EXPECT_EQ(arr[0].as<int32_t>(), 7);
  EXPECT_EQ(std::string(arr[1].as<String>()), std::string("x"));

  // mutate element inside the array via nested get_value
  arr[0].as<int32_t>() = 9;
  EXPECT_EQ(v.as<Array<Variant>>()[0].as<int32_t>(), 9);
}

TEST(VariantTests, GetValueForArray_DataValueAndStructureRefs)
{
  // DataValue array
  Array<DataValue> adv;
  adv.payload() = {DataValue{}, DataValue{}};
  Variant vAdv{adv};
  ASSERT_TRUE(vAdv.is_array_of_data_value());
  const auto& dav = static_cast<const Variant&>(vAdv).as<Array<DataValue>>();
  EXPECT_EQ(dav.size(), 2u);

  // RefStructure array (empty payload is valid)
  Array<RefStructure<Structure>> ars;
  Variant vArs{ars};
  ASSERT_TRUE(vArs.is_array_of_structure());
  const auto& sref = static_cast<const Variant&>(vArs).as<Array<RefStructure<Structure>>>();
  EXPECT_EQ(sref.size(), 0u);
}

TEST(VariantTests, GetValueForArray_WrongTypeThrows)
{
  Array<int32_t> a;
  a.payload() = {1};
  Variant v{a};
  ASSERT_TRUE(v.is_array_of_int32());
  // Requesting wrong array element type should throw
  EXPECT_THROW(
    {
      auto& wrong = v.as<Array<uint32_t>>();
      UA_UNUSED(wrong);
    },
    UaException);
  // Requesting scalar type from array should throw
  EXPECT_THROW(
    {
      auto& wrong2 = v.as<int32_t>();
      UA_UNUSED(wrong2);
    },
    UaException);

  // Also ensure requesting array from scalar throws
  Variant scalar{int32_t{5}};
  EXPECT_THROW(
    {
      auto& wrong3 = scalar.as<Array<int32_t>>();
      UA_UNUSED(wrong3);
    },
    UaException);
}

TEST(VariantTests, BuiltInTypeIdsAndVariantSpecialization)
{
  // Static built-in type id for Variant
  EXPECT_EQ(Variant::built_in_type_id(), built_in_type<Variant>());

  // get_built_in_type for scalar and array
  Variant vs{int16_t{-7}};
  EXPECT_EQ(vs.get_built_in_type(), built_in_type<int16_t>());
  Array<int16_t> a16;
  a16.payload() = {int16_t{-1}, int16_t{2}};
  Variant va{a16};
  ASSERT_TRUE(va.is_array_of_int16());
  EXPECT_EQ(va.get_built_in_type(), built_in_type<int16_t>());

  // get_value<Variant>() specialization returns self (const)
  const Variant& cva = va;
  const Variant& self = cva.as<Variant>();
  EXPECT_EQ(&self, &cva);
}

TEST(VariantTests, ClearOnNonEmptyMakesEmpty)
{
  Variant vs{uint32_t{123}};
  EXPECT_FALSE(vs.empty());
  vs.clear();
  EXPECT_TRUE(vs.empty());

  Array<double> ad;
  ad.payload() = {1.0};
  Variant va{ad};
  EXPECT_TRUE(va.is_array());
  va.clear();
  EXPECT_TRUE(va.empty());
}

TEST(VariantTests, ScalarGetValueWrongTypeThrowsForConstAndNonConst)
{
  Variant v{int32_t{42}};
  // Wrong type requested (uint32_t)
  EXPECT_THROW(
    {
      auto& r = v.as<uint32_t>();
      UA_UNUSED(r);
    },
    UaException);
  const Variant& cv2 = v;
  EXPECT_THROW(
    {
      auto& r2 = cv2.as<uint32_t>();
      UA_UNUSED(r2);
    },
    UaException);
}

TEST(VariantTests, ArrayPredicatesAndEqualityAndAssignments)
{
  // Additional array predicate check for int16_t
  Array<int16_t> a16;
  a16.payload() = {int16_t{1}, int16_t{2}};
  Variant v16{a16};
  EXPECT_TRUE(v16.is_array());
  EXPECT_TRUE(v16.is_array_of_int16());

  // operator== equality and inequality for arrays
  Array<int32_t> a1;
  a1.payload() = {1, 2, 3};
  Array<int32_t> a2;
  a2.payload() = {1, 2, 3};
  Array<int32_t> a3;
  a3.payload() = {1, 2, 4};
  Variant vA{a1};
  Variant vB{a2};
  Variant vC{a3};
  EXPECT_TRUE(vA == vB);
  EXPECT_FALSE(vA == vC);

  // Copy assignment for array variant
  Variant copyAssigned;
  copyAssigned = vA;
  EXPECT_TRUE(copyAssigned.is_array_of_int32());
  EXPECT_EQ(copyAssigned.as<Array<int32_t>>().size(), 3u);
  EXPECT_TRUE(copyAssigned == vA);

  // Move assignment for array variant
  Variant movedAssigned;
  movedAssigned = std::move(vB);
  EXPECT_TRUE(movedAssigned.is_array_of_int32());
  EXPECT_EQ(movedAssigned.as<Array<int32_t>>()[2], 3);
}

TEST(VariantTests, AssignUniquePtrStructureStoresStructureRef)
{
  Variant v;
  auto p = std::make_unique<DummyStructure>();
  v = std::move(p);
  EXPECT_TRUE(v.is_structure());
}

// ===== Phase 6: API Consistency tests =====

// --- StatusCode hash ---

TEST(StatusCodeTests, SeverityQueriesPreserveEveryBitCombination)
{
  static_assert(std::is_nothrow_copy_constructible_v<StatusCode>);
  static_assert(std::is_nothrow_copy_assignable_v<StatusCode>);
  static_assert(std::is_nothrow_assignable_v<StatusCode&, Status>);
  static_assert(noexcept(std::declval<const StatusCode&>().is_good()));
  static_assert(noexcept(std::declval<const StatusCode&>().is_bad()));
  static_assert(noexcept(std::declval<const StatusCode&>().is_uncertain()));

  const std::array<StatusCodeValue, 4> lowerBits{0U, 1U, 0x2AA55555U, 0x3FFFFFFFU};
  for (StatusCodeValue severity = 0; severity < 4; ++severity)
  {
    for (const auto info : lowerBits)
    {
      const StatusCode status{(severity << 30U) | info};
      EXPECT_EQ(status.is_good(), severity == 0);
      EXPECT_EQ(status.is_bad(), severity >= 2);
      EXPECT_EQ(status.is_uncertain(), severity == 1);
      EXPECT_EQ(status.is_not_good(), !status.is_good());
      EXPECT_EQ(status.is_not_bad(), !status.is_bad());
      EXPECT_EQ(status.is_not_uncertain(), !status.is_uncertain());
    }
  }

  StatusCode status{Status::BadInternalError};
  status.structure_changed(true);
  status.semantics_changed(true);
  EXPECT_TRUE(status.structure_changed());
  EXPECT_TRUE(status.semantics_changed());
  EXPECT_TRUE(status.is_bad());
  status.structure_changed(false);
  status.semantics_changed(false);
  EXPECT_FALSE(status.structure_changed());
  EXPECT_FALSE(status.semantics_changed());
  EXPECT_TRUE(status.is_bad());
}

TEST(StatusCodeTests, HashConsistencyAndUnorderedSet)
{
  StatusCode good{Status::Good};
  StatusCode bad{Status::BadInternalError};
  StatusCode good2{Status::Good};

  std::hash<StatusCode> hasher;
  EXPECT_EQ(hasher(good), hasher(good2));
  EXPECT_NE(hasher(good), hasher(bad));

  std::unordered_set<StatusCode> set;
  set.insert(good);
  set.insert(bad);
  set.insert(good2);
  EXPECT_EQ(set.size(), 2u);
  EXPECT_TRUE(set.count(good));
  EXPECT_TRUE(set.count(bad));
}

// --- QualifiedName hash ---

TEST(QualifiedNameTests, HashConsistencyAndUnorderedSet)
{
  QualifiedName a{0, "Browse"};
  QualifiedName b{1, "Browse"};
  QualifiedName a2{0, "Browse"};

  std::hash<QualifiedName> hasher;
  EXPECT_EQ(hasher(a), hasher(a2));
  EXPECT_NE(hasher(a), hasher(b));

  std::unordered_set<QualifiedName> set;
  set.insert(a);
  set.insert(b);
  set.insert(a2);
  EXPECT_EQ(set.size(), 2u);
}

TEST(QualifiedNameTests, HashWorksInUnorderedMap)
{
  std::unordered_map<QualifiedName, int> map;
  map[QualifiedName{0, "A"}] = 1;
  map[QualifiedName{0, "B"}] = 2;
  map[QualifiedName{1, "A"}] = 3;
  EXPECT_EQ(map.size(), 3u);
  EXPECT_EQ((map[QualifiedName{0, "A"}]), 1);
  EXPECT_EQ((map[QualifiedName{1, "A"}]), 3);
}

// --- String ordering ---

TEST(StringTests, OrderingNullLessThanNonNull)
{
  String null;
  String empty{""};
  String hello{"hello"};

  // null is less than any non-null (including empty string after construction from "")
  // Note: String("") becomes null because of the empty check in the constructor
  // So both null and String("") are null. Let's use a non-empty string.
  EXPECT_TRUE(null < hello);
  EXPECT_FALSE(hello < null);
  EXPECT_FALSE(null < null);
}

TEST(StringTests, OrderingLexicographic)
{
  String a{"apple"};
  String b{"banana"};
  String a2{"apple"};

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
  EXPECT_FALSE(a < a2);
  EXPECT_FALSE(a2 < a);

  // Also test <=, >, >=
  EXPECT_TRUE(a <= b);
  EXPECT_TRUE(a <= a2);
  EXPECT_TRUE(b > a);
  EXPECT_TRUE(a >= a2);
}

TEST(StringTests, OrderingUsableInStdSet)
{
  std::set<String> set;
  set.insert(String{"cherry"});
  set.insert(String{"apple"});
  set.insert(String{"banana"});
  set.insert(String{"apple"});  // duplicate

  EXPECT_EQ(set.size(), 3u);
  auto it = set.begin();
  EXPECT_EQ(string_view{*it++}, string_view{"apple"});
  EXPECT_EQ(string_view{*it++}, string_view{"banana"});
  EXPECT_EQ(string_view{*it++}, string_view{"cherry"});
}

// --- Guid ordering ---

TEST(GuidTests, OrderingDeterministicAndUsableInSet)
{
  Guid a = Guid::parse("00000000-0000-0000-0000-000000000001");
  Guid b = Guid::parse("00000000-0000-0000-0000-000000000002");
  Guid a2 = Guid::parse("00000000-0000-0000-0000-000000000001");

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
  EXPECT_FALSE(a < a2);

  std::set<Guid> set;
  set.insert(a);
  set.insert(b);
  set.insert(a2);
  EXPECT_EQ(set.size(), 2u);
}

// --- QualifiedName ordering ---

TEST(QualifiedNameTests, OrderingNamespaceIndexFirst)
{
  QualifiedName ns0a{0, "Z"};
  QualifiedName ns1a{1, "A"};

  // Namespace index takes priority - ns0 < ns1 regardless of name
  EXPECT_TRUE(ns0a < ns1a);
  EXPECT_FALSE(ns1a < ns0a);
}

TEST(QualifiedNameTests, OrderingNameSecondWithinSameNamespace)
{
  QualifiedName a{0, "Apple"};
  QualifiedName b{0, "Banana"};
  QualifiedName a2{0, "Apple"};

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
  EXPECT_FALSE(a < a2);
  EXPECT_TRUE(a <= a2);
  EXPECT_TRUE(a >= a2);
}

TEST(QualifiedNameTests, OrderingUsableInStdMap)
{
  std::map<QualifiedName, int> map;
  map[QualifiedName{1, "B"}] = 1;
  map[QualifiedName{0, "A"}] = 2;
  map[QualifiedName{0, "C"}] = 3;

  auto it = map.begin();
  EXPECT_EQ(it->second, 2);  // {0, "A"} first
  ++it;
  EXPECT_EQ(it->second, 3);  // {0, "C"} second
  ++it;
  EXPECT_EQ(it->second, 1);  // {1, "B"} third
}

// --- NodeId ordering ---

TEST(NodeIdTests, OrderingNamespaceIndexFirst)
{
  NodeId ns0{0, uint32_t{100}};
  NodeId ns1{1, uint32_t{1}};

  EXPECT_TRUE(ns0 < ns1);
  EXPECT_FALSE(ns1 < ns0);
}

TEST(NodeIdTests, OrderingNumericIdentifiers)
{
  NodeId a{0, uint32_t{1}};
  NodeId b{0, uint32_t{2}};
  NodeId a2{0, uint32_t{1}};

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
  EXPECT_FALSE(a < a2);
  EXPECT_TRUE(a <= a2);
}

TEST(NodeIdTests, OrderingStringIdentifiers)
{
  NodeId a{0, "Alpha"};
  NodeId b{0, "Beta"};

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
}

TEST(NodeIdTests, OrderingDifferentIdTypes)
{
  // Numeric (0) < String (1) < Guid (2) < Opaque (3)
  NodeId numeric{0, uint32_t{999}};
  NodeId str{0, "A"};

  EXPECT_TRUE(numeric < str);
  EXPECT_FALSE(str < numeric);
}

TEST(NodeIdTests, OrderingGuidIdentifiers)
{
  Guid g1 = Guid::parse("00000000-0000-0000-0000-000000000001");
  Guid g2 = Guid::parse("00000000-0000-0000-0000-000000000002");
  NodeId a{0, g1};
  NodeId b{0, g2};

  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
}

TEST(NodeIdTests, OrderingUsableInStdSet)
{
  std::set<NodeId> set;
  set.insert(NodeId{1, uint32_t{1}});
  set.insert(NodeId{0, uint32_t{2}});
  set.insert(NodeId{0, uint32_t{1}});
  set.insert(NodeId{0, uint32_t{2}});  // duplicate

  EXPECT_EQ(set.size(), 3u);
  auto it = set.begin();
  EXPECT_EQ(it->identifier().get_numeric(), 1u);  // {0, 1}
  ++it;
  EXPECT_EQ(it->identifier().get_numeric(), 2u);  // {0, 2}
  ++it;
  EXPECT_EQ(it->namespace_index(), 1u);  // {1, 1}
}

TEST(NodeIdTests, OrderingUsableInStdMap)
{
  std::map<NodeId, std::string> map;
  map[NodeId{0, uint32_t{85}}] = "Objects";
  map[NodeId{0, uint32_t{84}}] = "Root";
  map[NodeId{1, uint32_t{1}}] = "Custom";

  auto it = map.begin();
  EXPECT_EQ(it->second, "Root");  // {0, 84}
  ++it;
  EXPECT_EQ(it->second, "Objects");  // {0, 85}
  ++it;
  EXPECT_EQ(it->second, "Custom");  // {1, 1}
}

// --- XmlElement::value() return type ---

TEST(XmlElementTests, ValueConstReturnsStringRef)
{
  XmlElement xe;
  xe = std::string{"<root/>"};

  const XmlElement& cxe = xe;
  const std::string& ref = cxe.value();
  EXPECT_EQ(ref, "<root/>");

  // Verify it's truly a reference to the member (address stability)
  const std::string* addr1 = &cxe.value();
  const std::string* addr2 = &cxe.value();
  EXPECT_EQ(addr1, addr2);
}

// ===== Phase 7: Ease of Use tests =====

// --- Variant::try_as<T>() for built-in scalar types ---

TEST(VariantTests, TryAsReturnsPointerForCorrectType)
{
  Variant v{int32_t{42}};
  const int32_t* p = v.try_as<int32_t>();
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(*p, 42);
}

TEST(VariantTests, TryAsReturnsNullptrForWrongType)
{
  Variant v{int32_t{42}};
  EXPECT_EQ(v.try_as<uint32_t>(), nullptr);
  EXPECT_EQ(v.try_as<double>(), nullptr);
  EXPECT_EQ(v.try_as<String>(), nullptr);
}

TEST(VariantTests, TryAsReturnsNullptrForEmptyVariant)
{
  Variant v;
  EXPECT_EQ(v.try_as<int32_t>(), nullptr);
  EXPECT_EQ(v.try_as<String>(), nullptr);
}

TEST(VariantTests, TryAsWorksForStringType)
{
  Variant v{String{"hello"}};
  const String* p = v.try_as<String>();
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(string_view{*p}, string_view{"hello"});
}

TEST(VariantTests, TryAsWorksForNodeId)
{
  Variant v{NodeId{0, uint32_t{85}}};
  const NodeId* p = v.try_as<NodeId>();
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(p->identifier().get_numeric(), 85u);
  EXPECT_EQ(v.try_as<String>(), nullptr);
}

TEST(VariantTests, TryAsWorksForStatusCode)
{
  Variant v{StatusCode{Status::BadInternalError}};
  const StatusCode* p = v.try_as<StatusCode>();
  ASSERT_NE(p, nullptr);
  EXPECT_TRUE(p->is_bad());
}

// --- Non-explicit Variant constructors ---

TEST(VariantTests, ExplicitConstructionFromScalars)
{
  Variant v1{int32_t{42}};
  EXPECT_TRUE(v1.is_int32());

  Variant v2{true};
  EXPECT_TRUE(v2.is_boolean());

  Variant v3{3.14};
  EXPECT_TRUE(v3.is_double());

  Variant v4{NodeId{0, uint32_t{85}}};
  EXPECT_TRUE(v4.is_node_id());

  Variant v5{String{"hello"}};
  EXPECT_TRUE(v5.is_string());

  Variant v6{StatusCode{Status::Good}};
  EXPECT_TRUE(v6.is_status_code());
}

TEST(VariantTests, ExplicitConstructionFromArrays)
{
  Variant v1{Array<int32_t>{1, 2, 3}};
  EXPECT_TRUE(v1.is_array_of_int32());

  Variant v2{Array<String>{String{"a"}, String{"b"}}};
  EXPECT_TRUE(v2.is_array_of_string());
}

// Public API review D2 (API-D2.1, D2.2): a Variant adopts the structure it is handed by rvalue unique_ptr -
// the same object, not a clone - by construction and by assignment; RefStructure adopts from an rvalue too,
// and still clones from a const reference (API-D2.3).
TEST(VariantTests, AUniquePtrStructureIsAdoptedNotCloned)
{
  auto owned = std::make_unique<ua::Range>();
  owned->low() = 1.0;
  const ua::Range* address = owned.get();
  const Variant constructed{std::move(owned)};
  EXPECT_EQ(owned, nullptr) << "the pointer was handed over";
  EXPECT_EQ(constructed.try_as<ua::Range>(), address) << "constructed: the same object, not a copy";

  auto assigned = std::make_unique<ua::Range>();
  const ua::Range* assignedAddress = assigned.get();
  Variant variant;
  variant = std::move(assigned);
  EXPECT_EQ(variant.try_as<ua::Range>(), assignedAddress) << "assigned: the same object, not a copy";

  std::unique_ptr<Structure> structure = std::make_unique<ua::Range>();
  const Structure* structureAddress = structure.get();
  const RefStructure<Structure> adopted{std::move(structure)};
  EXPECT_EQ(adopted.get(), structureAddress);
  std::unique_ptr<Structure> kept = std::make_unique<ua::Range>();
  const RefStructure<Structure> cloned{kept};
  EXPECT_NE(cloned.get(), kept.get()) << "a const reference is still cloned";
  EXPECT_NE(kept, nullptr);
}

// --- QualifiedName(string_view) is explicit ---

TEST(QualifiedNameTests, StringViewConstructorIsExplicit)
{
  // This must compile - explicit construction
  QualifiedName qn{"BrowseName"};
  EXPECT_EQ(string_view{qn.name()}, string_view{"BrowseName"});
  EXPECT_EQ(qn.namespace_index(), 0u);
}

// --- Array::reserve() ---

TEST(ArrayTests, ReserveDoesNotChangeSize)
{
  Array<int32_t> arr;
  arr.reserve(100);
  EXPECT_EQ(arr.size(), 0u);
  EXPECT_TRUE(arr.empty());
}

// @relation(AC-COMP-SDK-POST-ARRAY-COPY-SHAPE, scope=function)
TEST(ArrayTests, CopyAssignmentPreservesMultidimensionalShape)
{
  const Array<NodeId> source{Dimensions{3, 2},
    {NodeId{1, 1u}, NodeId{1, 2u}, NodeId{1, 3u}, NodeId{1, 4u}, NodeId{1, 5u}, NodeId{1, 6u}}};
  Array<NodeId> assigned{Dimensions{2, 3},
    {NodeId{2, 1u}, NodeId{2, 2u}, NodeId{2, 3u}, NodeId{2, 4u}, NodeId{2, 5u}, NodeId{2, 6u}}};

  assigned = source;

  ASSERT_TRUE(assigned.dimensions().has_value());
  EXPECT_EQ(*assigned.dimensions(), (Dimensions{3, 2}));
  EXPECT_EQ(assigned.payload(), source.payload());
}

TEST(ArrayTests, ReserveAllowsEfficientPushBack)
{
  Array<String> arr;
  arr.reserve(3);
  arr.push_back(String{"a"});
  arr.push_back(String{"b"});
  arr.push_back(String{"c"});
  EXPECT_EQ(arr.size(), 3u);
  EXPECT_EQ(string_view{arr[0]}, string_view{"a"});
  EXPECT_EQ(string_view{arr[2]}, string_view{"c"});
}

// ===== Phase 8a: fmt::formatter tests =====

TEST(FmtFormatterTests, StringFormatsCorrectly)
{
  String s{"hello"};
  EXPECT_EQ(fmt::format("{}", s), ua::to_string(s));
}

TEST(FmtFormatterTests, NodeIdFormatsCorrectly)
{
  NodeId id{0, uint32_t{85}};
  EXPECT_EQ(fmt::format("{}", id), ua::to_string(id));
}

TEST(FmtFormatterTests, StatusCodeFormatsCorrectly)
{
  StatusCode sc{Status::BadInternalError};
  EXPECT_EQ(fmt::format("{}", sc), ua::to_string(sc));
}

TEST(FmtFormatterTests, GuidFormatsCorrectly)
{
  Guid g = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  EXPECT_EQ(fmt::format("{}", g), ua::to_string(g));
}

TEST(FmtFormatterTests, QualifiedNameFormatsCorrectly)
{
  QualifiedName qn{1, "BrowseName"};
  EXPECT_EQ(fmt::format("{}", qn), ua::to_string(qn));
}

TEST(FmtFormatterTests, VariantFormatsCorrectly)
{
  Variant v{int32_t{42}};
  EXPECT_EQ(fmt::format("{}", v), ua::to_string(v));
}

TEST(FmtFormatterTests, DataValueFormatsCorrectly)
{
  DataValue dv;
  dv.value() = Variant{int32_t{42}};
  EXPECT_EQ(fmt::format("{}", dv), ua::to_string(dv));
}

TEST(FmtFormatterTests, XmlElementFormatsCorrectly)
{
  XmlElement xe;
  xe = std::string{"<root/>"};
  EXPECT_EQ(fmt::format("{}", xe), ua::to_string(xe));
}

TEST(FmtFormatterTests, UsableInFmtFormatCalls)
{
  NodeId id{0, uint32_t{85}};
  StatusCode sc{Status::Good};
  std::string result = fmt::format("Node={} Status={}", id, sc);
  EXPECT_FALSE(result.empty());
  EXPECT_NE(result.find("85"), std::string::npos);
}

// ===== Phase 8b: ByteString class + String simplification tests =====

// --- ByteString basics ---

TEST(ByteStringTests, DefaultConstructedIsEmpty)
{
  ByteString bs;
  EXPECT_TRUE(bs.empty());
  EXPECT_TRUE(bs.is_null());  // is_null() == empty()
  EXPECT_EQ(bs.size(), 0u);
}

TEST(ByteStringTests, InitializerListConstruction)
{
  ByteString bs{0x01, 0x02, 0x03};
  EXPECT_EQ(bs.size(), 3u);
  EXPECT_EQ(bs[0], 0x01);
  EXPECT_EQ(bs[1], 0x02);
  EXPECT_EQ(bs[2], 0x03);
}

TEST(ByteStringTests, CountValueConstruction)
{
  ByteString bs(4, uint8_t{0xFF});
  EXPECT_EQ(bs.size(), 4u);
  for (size_t i = 0; i < bs.size(); ++i)
  {
    EXPECT_EQ(bs[i], 0xFF);
  }
}

TEST(ByteStringTests, SpanOfByteConstruction)
{
  std::array<byte, 3> arr{byte{10}, byte{20}, byte{30}};
  ByteString bs{span<const byte>{arr}};
  EXPECT_EQ(bs.size(), 3u);
  EXPECT_EQ(bs[0], 10);
  EXPECT_EQ(bs[1], 20);
  EXPECT_EQ(bs[2], 30);
}

TEST(ByteStringTests, VectorConstruction)
{
  std::vector<uint8_t> vec{5, 6, 7, 8};
  ByteString bs{std::move(vec)};
  EXPECT_EQ(bs.size(), 4u);
  EXPECT_EQ(bs[0], 5);
}

TEST(ByteStringTests, CopyAndMoveSemantics)
{
  ByteString a{1, 2, 3};

  ByteString b{a};
  EXPECT_EQ(a, b);

  ByteString c;
  c = a;
  EXPECT_EQ(a, c);

  ByteString d{std::move(c)};
  EXPECT_EQ(d, a);

  ByteString e;
  e = std::move(d);
  EXPECT_EQ(e, a);
}

TEST(ByteStringTests, EqualityAndOrdering)
{
  ByteString a{1, 2, 3};
  ByteString b{1, 2, 3};
  ByteString c{1, 2, 4};
  ByteString empty1;
  ByteString empty2;

  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_TRUE(a < c);
  EXPECT_FALSE(c < a);
  EXPECT_EQ(empty1, empty2);
  EXPECT_TRUE(empty1 < a);
}

TEST(ByteStringTests, ResizeAndReserve)
{
  ByteString bs;
  bs.reserve(100);
  EXPECT_EQ(bs.size(), 0u);

  bs.resize(5);
  EXPECT_EQ(bs.size(), 5u);

  bs.resize(3, uint8_t{0xAA});
  EXPECT_EQ(bs.size(), 3u);
}

TEST(ByteStringTests, PushBackAndClear)
{
  ByteString bs;
  bs.push_back(0x10);
  bs.push_back(0x20);
  EXPECT_EQ(bs.size(), 2u);
  EXPECT_EQ(bs[0], 0x10);
  EXPECT_EQ(bs[1], 0x20);

  bs.clear();
  EXPECT_TRUE(bs.empty());
}

TEST(ByteStringTests, IteratorAccess)
{
  ByteString bs{10, 20, 30};
  std::vector<uint8_t> collected(bs.begin(), bs.end());
  ASSERT_EQ(collected.size(), 3u);
  EXPECT_EQ(collected[0], 10);
  EXPECT_EQ(collected[2], 30);
}

TEST(ByteStringTests, SpanConversions)
{
  ByteString bs{1, 2, 3};

  span<const uint8_t> u8span = bs;
  EXPECT_EQ(u8span.size(), 3u);
  EXPECT_EQ(u8span[0], 1);

  span<const byte> bspan = bs;
  EXPECT_EQ(bspan.size(), 3u);

  // Mutable spans
  span<uint8_t> mu8 = bs;
  mu8[0] = 99;
  EXPECT_EQ(bs[0], 99);

  span<byte> mb = bs;
  EXPECT_EQ(mb.size(), 3u);
}

TEST(ByteStringTests, PayloadAccess)
{
  ByteString bs{1, 2, 3};
  auto& vec = bs.payload();
  vec.push_back(4);
  EXPECT_EQ(bs.size(), 4u);
  EXPECT_EQ(bs[3], 4);
}

TEST(ByteStringTests, BuiltInTypeId)
{
  EXPECT_EQ(ByteString::built_in_type_id(), built_in_type<ByteString>());
}

TEST(ByteStringTests, UsableInVariant)
{
  Variant v{ByteString{0xAA, 0xBB}};
  EXPECT_TRUE(v.is_byte_string());
  EXPECT_EQ(v.as<ByteString>().size(), 2u);
  EXPECT_EQ(v.as<ByteString>()[0], 0xAA);
}

// --- String null==empty simplification ---

TEST(StringTests, NullAndEmptyAreEquivalent)
{
  String a;  // default - empty
  String b{""};  // from empty literal - also empty

  EXPECT_TRUE(a.empty());
  EXPECT_TRUE(a.is_null());
  EXPECT_TRUE(b.empty());
  EXPECT_TRUE(b.is_null());
  EXPECT_EQ(a, b);
}

TEST(StringTests, ClearMakesEmpty)
{
  String s{"hello"};
  EXPECT_FALSE(s.empty());
  s.clear();
  EXPECT_TRUE(s.empty());
  EXPECT_TRUE(s.is_null());
}

TEST(StringTests, DefaultedSpaceshipOrdering)
{
  String a{"apple"};
  String b{"banana"};
  String empty;

  EXPECT_TRUE(empty < a);
  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);

  std::set<String> sorted;
  sorted.insert(b);
  sorted.insert(a);
  sorted.insert(empty);
  auto it = sorted.begin();
  EXPECT_TRUE(it->empty());
  ++it;
  EXPECT_EQ(string_view{*it}, string_view{"apple"});
}
