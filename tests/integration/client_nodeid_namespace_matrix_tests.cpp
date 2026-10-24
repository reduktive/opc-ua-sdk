// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientNodeId + ClientNamespace clusters of the client integration-test matrix.
///
/// Two gtest suites in one file, both END-TO-END against a real in-tree server over a real secure
/// channel:
///
///   - `ClientNodeId.*` (3 rows) exercises the NodeId wire codec through the TIER-2 managed read
///     accessor: all four identifier types round-trip (section 10.4 NodeId wire codec, CL-ADDRSP-001), the
///     null NodeId in every Table-23 form is rejected (CL-ADDRSP-003), and a String identifier's case
///     is preserved verbatim on the wire (CL-ADDRSP-002). The tier-2 `Connection` is built by wrapping a
///     real `ConnectionImpl` over an activated tier-0 Session (same construction as client_read_matrix),
///     WITHOUT reconnect wiring, so it is single-shot with no keep-alive poll.
///
///   - `ClientNamespace.*` (4 rows) exercises the per-Connection immutable NamespaceTable snapshot
///     (`ua::client::NamespaceTable`, client design section 8.5) that a real Connection bootstraps by reading
///     `Server.NamespaceArray`, plus the URI-tagged ExpandedNodeId read wiring (OPEN-NSREMAP). Row 1
///     (resolve_local, CL-VIEW-018) is driven on the real bootstrapped snapshot. Row 2
///     (UriTaggedExpandedNodeIdReadResolvesEndToEnd, CL-ADDRSP-004) is END-TO-END through the BUILT
///     persist-by-URI read API: `read_value_sync(ExpandedNodeId{uri})` resolves per-Session and reaches the
///     real compliance-namespace Variable (and an absent URI is refused locally). Rows 3/4 (translate
///     re-numbering / URI-dropped rejection, CL-ADDRSP-004 + CL-SESS-028) model the reconnect index shift:
///     each grounds snapshot A on the REAL bootstrapped array and models the post-reconnect array the
///     re-read would produce as snapshot B, then drives the BUILT translate mechanism the reconnect remap
///     uses. The reconnect itself is driven for real in `connection_impl_reconnect_integration_tests.cpp`
///     (`ReconnectToAShuffledNamespaceArrayReportsAnIndexShift`), which reconnects to a second server
///     publishing the same URIs at swapped indices; these rows own the translate half of that story.
///
/// Falsifiability: every test encodes its matrix `[neg: ...]` falsifier. A codec that corrupts a Guid or
/// Opaque identifier fails ReadNodesOfAllFourIdTypes; a client that folds String case aliases s=foo onto
/// s=Foo and fails StringIdentifierCaseSensitiveOnWire; a client that silently accepts a null NodeId (a
/// Good read) fails NullNodeIdReadRejectedAllForms; a translate that ignores the source URI, or drops the
/// preserved-URI ErrorDetail, fails the ClientNamespace rows.
///
/// CALIBRATION (see the authoring report for the batched write-up):
///   - The matrix oracle for NullNodeIdReadRejectedAllForms expects `Bad_NodeIdInvalid` from a client-side
///     `NodeId::is_null` short-circuit (section 10.4). That short-circuit is NOT built: the client forwards
///     the null NodeId to the server, which resolves it as an ordinary (missing) lookup and returns
///     `Bad_NodeIdUnknown` for every form. The SAFETY property the row protects - every null form is
///     REJECTED, never silently accepted - holds, so this asserts the REAL rejection code
///     (`Bad_NodeIdUnknown`) and the report records the unbuilt local short-circuit + the Invalid-vs-Unknown
///     divergence.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_namespace_table.h"
#include "ua_server_table.h"

#include "ua_access_level_type.h"
#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_core_client.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring
// -> single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and
// closes gracefully on destruction. Mirrors client_read_matrix_tests.cpp's helper.
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

// Returns the value stored under context key `key` in `detail`, or nullopt if absent.
std::optional<std::string> context_value(const ua::ErrorDetail& detail, std::string_view key)
{
  for (const auto& namedValue : detail.context)
  {
    if (namedValue.key == key)
      return namedValue.value;
  }
  return std::nullopt;
}

// The URI of the custom namespace ComplianceWithNodes registers on the server (index mTestNamespaceIndex).
constexpr std::string_view complianceUri{"urn:test:compliance"};
constexpr std::string_view ns0Uri{"http://opcfoundation.org/UA/"};

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientNodeId`. Derives from ComplianceWithNodes and adds four Variables
// identified by Numeric / String / Guid / Opaque NodeIds plus a case-distinct String node ("Foo").
// =============================================================================================
class ClientNodeId : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    mNumericNodeId = NodeId{mTestNamespaceIndex, uint32_t{8001}};
    mStringNodeId = NodeId{mTestNamespaceIndex, std::string_view{"StringIdentifier"}};
    mGuidNodeId =
      NodeId{mTestNamespaceIndex, Guid::parse(std::string_view{"12345678-90AB-CDEF-1234-567890ABCDEF"})};
    mOpaqueNodeId = NodeId{mTestNamespaceIndex, ByteString{0x0A, 0x0B, 0x0C, 0x0D}};

    create_scalar_int32(mNumericNodeId, "NumericVar", 111);
    create_scalar_int32(mStringNodeId, "StringVar", 222);
    create_scalar_int32(mGuidNodeId, "GuidVar", 333);
    create_scalar_int32(mOpaqueNodeId, "OpaqueVar", 444);

    // Case-distinct String node: only "Foo" exists; "foo" must not alias onto it.
    mCaseFooNodeId = NodeId{mTestNamespaceIndex, std::string_view{"Foo"}};
    create_scalar_int32(mCaseFooNodeId, "CaseFooVar", 555);
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  void create_scalar_int32(const NodeId& nodeId, std::string_view name, int32_t value)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
    variable->set_display_name(LocalizedText{"", std::string{name}});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(value);
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);
  }

  NodeId mNumericNodeId;
  NodeId mStringNodeId;
  NodeId mGuidNodeId;
  NodeId mOpaqueNodeId;
  NodeId mCaseFooNodeId;
};

// =============================================================================================
// ClientNodeId.ReadNodesOfAllFourIdTypes - CL-ADDRSP-001
// Four Variables identified by Numeric, String, Guid and Opaque NodeIds each round-trip their exact
// value through read_value_sync - proving the NodeId wire codec encodes/decodes every IdType.
// [neg: Guid and Opaque (ByteString) identifier round-trip]
// =============================================================================================
// @verifies CL-ADDRSP-001
// @relation(CL-ADDRSP-001, scope=function)
TEST_F(ClientNodeId, ReadNodesOfAllFourIdTypes)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("FourIdTypes")};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap failed: " << to_string(connection.start_status().status_code());

  auto readInt32 = [&connection](const NodeId& node, int32_t expected, std::string_view idType)
  {
    auto result = connection->try_read_value_sync<int32_t>(node);
    ASSERT_TRUE(result.is_good()) << idType << " NodeId must resolve on the wire, got 0x" << std::hex
                                  << result.status_code().as_uint32();
    EXPECT_EQ(result.value(), expected) << idType << " NodeId's value must round-trip exactly";
  };

  readInt32(mNumericNodeId, 111, "Numeric");
  readInt32(mStringNodeId, 222, "String");
  readInt32(mGuidNodeId, 333, "Guid");
  readInt32(mOpaqueNodeId, 444, "Opaque");
}

// =============================================================================================
// ClientNodeId.StringIdentifierCaseSensitiveOnWire - CL-ADDRSP-002
// The server hosts only s=Foo. Reading s=Foo is Good; reading s=foo is Bad_NodeIdUnknown - proving the
// String identifier's case is carried verbatim on the wire and is never case-folded into an alias.
// [neg: case-differing identifier must not alias]
// =============================================================================================
// @verifies CL-ADDRSP-002
// @relation(CL-ADDRSP-002, scope=function)
TEST_F(ClientNodeId, StringIdentifierCaseSensitiveOnWire)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("StringCase")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto exact = connection->try_read_value_sync<int32_t>(mCaseFooNodeId);
  ASSERT_TRUE(exact.is_good()) << "the exact-case s=Foo must resolve, got 0x" << std::hex
                               << exact.status_code().as_uint32();
  EXPECT_EQ(exact.value(), 555) << "s=Foo must read its own value";

  const NodeId lowerCaseNode{mTestNamespaceIndex, std::string_view{"foo"}};
  auto folded = connection->try_read_value_sync(lowerCaseNode);
  ASSERT_TRUE(folded.is_good()) << "the service call itself succeeds; the failure is per-operation";
  EXPECT_THAT(folded.value(), HasStatusPresent(Status::BadNodeIdUnknown))
    << "s=foo must NOT alias onto s=Foo: a case-folded client would resolve it and return Good";
}

// =============================================================================================
// ClientNodeId.NullNodeIdReadRejectedAllForms - CL-ADDRSP-003
// The canonical null (ns=0,i=0) and each Table-23 alternative null (empty String, all-zero Guid, empty
// Opaque at ns=0) must be REJECTED, never silently accepted as a Good read. The near-null (ns=1,i=0) is
// NOT null and must reach the server as an ordinary (missing) lookup. [neg: five null encodings +
// near-null must NOT be null]
//
// CALIBRATED (see file header): the section 10.4 client-side is_null->Bad_NodeIdInvalid short-circuit is
// UNBUILT, so the client forwards every null form to the server, which resolves it as a missing lookup
// and returns Bad_NodeIdUnknown. The row's protected safety property (every null form REJECTED, never
// Good) holds; this asserts the REAL rejection code. Because there is no local short-circuit, the
// near-null is indistinguishable from the null forms by code (both Bad_NodeIdUnknown from the server) -
// asserting the near-null is also a server-reached miss falsifies an over-broad local null check.
// =============================================================================================
// @verifies CL-ADDRSP-003
// @relation(CL-ADDRSP-003, scope=function)
TEST_F(ClientNodeId, NullNodeIdReadRejectedAllForms)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("NullForms")};
  ASSERT_TRUE(connection.start_status().is_good());

  struct NullForm
  {
    NodeId node;
    std::string_view label;
  };

  // NOTE: the all-zero Guid is built by parsing the nil UUID string, NOT by the default `Guid{}`
  // constructor. `Guid{}` is DOCUMENTED to construct the null (all-zero) Guid (ua_guid.h) but its
  // implementation calls generate() and yields a RANDOM UUID - a product bug pinned by
  // DefaultConstructedGuidIsNullPerContract below and flagged in the authoring report.
  const std::vector<NullForm> nullForms{
    {NodeId{}, "canonical numeric ns=0 i=0"},
    {NodeId{uint16_t{0}, std::string_view{""}}, "empty String ns=0"},
    {NodeId{uint16_t{0}, Guid::parse(std::string_view{"00000000-0000-0000-0000-000000000000"})},
      "all-zero Guid ns=0"},
    {NodeId{uint16_t{0}, ByteString{}}, "empty Opaque ns=0"},
  };

  for (const auto& form : nullForms)
  {
    ASSERT_TRUE(form.node.is_null()) << form.label << " must classify as the null NodeId locally";
    auto result = connection->try_read_value_sync(form.node);
    ASSERT_TRUE(result.is_good()) << form.label << ": a per-operation status, not a service fault";
    // Bad_NodeIdInvalid rather than Bad_NodeIdUnknown: OPC 10000-4 section 5.10.2.4 separates a
    // syntactically malformed nodeId from a well-formed one that names nothing, and every form here
    // is the former. The assertion previously named Unknown, which is what the server returned
    // before it drew the distinction - the subject of this test is that a null id is rejected in
    // every encoding, and it still is, now with the code the obligation names
    // (`AC-SVR-ATTR-READ-016-BAD-NODEIDINVALID`).
    EXPECT_THAT(result.value(), HasStatusPresent(Status::BadNodeIdInvalid))
      << form.label << " must be rejected, never silently accepted as Good";
  }

  // Near-null: ns=1,i=0. Per OPC 10000-3 section 8.2.4 Table 23 the null NodeId lives AT NamespaceIndex 0, so
  // ns=1,i=0 is an ordinary reference to namespace 1, NOT null - NodeId::is_null is now namespace-strict
  // (CL-ADDRSP-003), matching reference stacks (open62541/.NET). Either way the read is unaffected (the
  // client read path never consults is_null), so ns=1,i=0 reaches the server as an ordinary (missing)
  // lookup and is rejected Bad_NodeIdUnknown - the real, meaningful behaviour this asserts. The previously
  // flagged namespace-agnostic divergence is now resolved in favour of the spec.
  const NodeId nearNull{uint16_t{1}, uint32_t{0}};
  EXPECT_FALSE(nearNull.is_null())
    << "ns=1,i=0 is a real reference to namespace 1, not the null NodeId (Table 23: null is at ns=0)";
  auto nearResult = connection->try_read_value_sync(nearNull);
  ASSERT_TRUE(nearResult.is_good());
  EXPECT_THAT(nearResult.value(), HasStatusPresent(Status::BadNodeIdUnknown))
    << "ns=1,i=0 must reach the server as a real miss (no local short-circuit exists)";
}

// =============================================================================================
// ClientNodeId.DefaultConstructedGuidIsNullPerContract - CL-ADDRSP-003 (product-bug pin)
// RED-because-BUG (reported): ua_guid.h documents the default `Guid()` constructor as "Constructs the
// null (all-zero) Guid" and directs callers to the separate `create_and_generate()` "to obtain a fresh
// random identifier". The implementation `Guid::Guid()` instead calls generate(), so `Guid{}` yields a
// RANDOM UUID that is NOT null - contradicting the header contract, making create_and_generate()
// redundant, and silently corrupting call sites that build a default value (e.g.
// ua_dynamic_field_codec.cpp's `Variant{Guid{}}`). This asserts the DOCUMENTED-correct behaviour so the
// gate stays RED until `Guid::Guid()` is fixed to construct the nil Guid. The falsifier is a random
// default Guid. (Kept here because the null-NodeId Guid form directly depends on this contract; the
// maintainer will most likely re-home the fix's regression test into a Guid unit test.)
// =============================================================================================
// @verifies CL-ADDRSP-003
// @relation(CL-ADDRSP-003, scope=function)
TEST(ClientNodeIdGuidContract, DefaultConstructedGuidIsNullPerContract)
{
  EXPECT_TRUE(Guid{}.is_null())
    << "ua_guid.h documents the default Guid() constructor as the null (all-zero) Guid, but the "
       "implementation generates a random UUID (product bug - see the authoring report)";
  EXPECT_TRUE(NodeId(uint16_t{0}, Guid{}).is_null())
    << "a NodeId holding a default-constructed Guid must be the null NodeId per OPC 10000-6 5.2.2.9";
}

// =============================================================================================
// Fixture: one gtest suite `ClientNamespace`. Derives from ComplianceWithNodes, which registers the
// "urn:test:compliance" namespace on the server, so a real Connection bootstraps a NamespaceTable whose
// array contains that URI at a known index.
// =============================================================================================
class ClientNamespace : public ComplianceWithNodes
{
protected:
  // A readable Int32 Variable in the compliance namespace, so an end-to-end URI-tagged read has a real
  // target.
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    mUriTaggedTargetId = NodeId{mTestNamespaceIndex, std::string_view{"UriTaggedTarget"}};
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.create_node_sync(mUriTaggedTargetId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "UriTaggedTarget"});
    variable->set_display_name(LocalizedText{"", "UriTaggedTarget"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{4242});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mUriTaggedTargetId);
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  NodeId mUriTaggedTargetId;

  // Collects a snapshot's URIs in index order (index 0 first) into a plain vector.
  static std::vector<std::string> uris_of(const NamespaceTable& table)
  {
    std::vector<std::string> uris;
    uris.reserve(table.size());
    for (std::size_t index = 0; index < table.size(); ++index)
      uris.emplace_back(*table.lookup_uri(static_cast<NamespaceIndex>(index)));
    return uris;
  }
};

// =============================================================================================
// ClientNamespace.ServerArrayCachedForSessionLifetime - CL-BASE-002
// Uses the highest public Connection surface. Two resolutions retain the same immutable snapshot identity,
// proving no accessor-triggered ServerArray re-read or replacement occurs within the open Session.
// =============================================================================================
// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST_F(ClientNamespace, ServerArrayCachedForSessionLifetime)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("ServerTableCache")};
  ASSERT_TRUE(connection.start_status().is_good());

  const auto first = connection->server_table();
  ASSERT_NE(first, nullptr);
  ASSERT_GE(first->size(), 1u);
  const auto localUri = first->resolve_server_uri(ExpandedNodeId{NodeId{0, 1}, std::uint32_t{0}});
  ASSERT_TRUE(localUri.is_good());
  EXPECT_FALSE(localUri.value().empty());

  const auto second = connection->server_table();
  EXPECT_EQ(second, first) << "the Session must retain one immutable ServerArray snapshot";
  const auto resolvedAgain = second->resolve_server_uri(ExpandedNodeId{NodeId{0, 2}, std::uint32_t{0}});
  ASSERT_TRUE(resolvedAgain.is_good());
  EXPECT_EQ(resolvedAgain.value(), localUri.value());
}

// =============================================================================================
// ClientNamespace.ExpandedNodeIdUriResolvesToLocalIndexElsePreserved - CL-VIEW-018
// Over the REAL bootstrapped NamespaceTable: an ExpandedNodeId whose namespaceUri matches a local entry
// resolves to that local index (the URI overrides the wire index, which is 0 when a URI is present); an
// ExpandedNodeId whose URI is absent is NOT substituted with a stale index - it is rejected with the
// unresolved URI preserved verbatim in the ErrorDetail. [neg: unmapped URI preserved, not indexed]
//
// This pins the BUILT resolver - NamespaceTable::resolve_local on the REAL bootstrapped snapshot - directly.
// The tier-2 Browse path now WIRES this resolver (CL-VIEW-018): a URI-bearing LOCAL reference target is
// resolved to its local index during flattening (see the end-to-end
// ClientBrowse.NamespaceUriTargetResolvedToLocalIndexOnBrowse over MisbehavingServer, which injects a
// URI-bearing reference and asserts the flattened Entry carries the resolved index).
// =============================================================================================
// @verifies CL-VIEW-018
// @relation(CL-VIEW-018, scope=function)
TEST_F(ClientNamespace, ExpandedNodeIdUriResolvesToLocalIndexElsePreserved)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("ResolveLocal")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto table = connection->namespace_table();
  ASSERT_NE(table, nullptr) << "the bootstrap must publish a NamespaceTable snapshot";

  const auto complianceIndex = table->lookup_index(complianceUri);
  ASSERT_TRUE(complianceIndex.has_value()) << "the server's array must carry " << complianceUri;
  EXPECT_EQ(*complianceIndex, mTestNamespaceIndex)
    << "the client's bootstrapped index must match the server's NamespaceArray index";

  // Present URI: overrides the wire index 0 and resolves to the local compliance index.
  ExpandedNodeId present{NodeId(uint16_t{0}, std::string_view{"the-node"}), complianceUri};
  auto resolved = table->resolve_local(present);
  ASSERT_TRUE(resolved.is_good()) << "a present URI must resolve: 0x" << std::hex
                                  << resolved.status_code().as_uint32();
  EXPECT_EQ(resolved.value(), NodeId(*complianceIndex, std::string_view{"the-node"}))
    << "the URI must drive the local index and the identifier must be preserved";

  // Absent URI: NOT substituted with a stale index - rejected with the URI preserved verbatim.
  const std::string absentUri = "urn:vendor:namespace-not-in-this-server";
  ExpandedNodeId absent{NodeId(uint16_t{0}, std::string_view{"the-node"}), absentUri};
  auto preserved = table->resolve_local(absent);
  ASSERT_TRUE(preserved.is_bad()) << "an unmapped URI must not silently resolve to a stale index";
  EXPECT_EQ(preserved.status_code().value(), static_cast<uint32_t>(Status::BadNodeIdUnknown));
  ASSERT_NE(preserved.error_detail(), nullptr) << "the rejection must carry a propagatable ErrorDetail";
  EXPECT_EQ(preserved.error_detail()->code, "UriUnresolved");
  EXPECT_EQ(context_value(*preserved.error_detail(), "namespace.uri"), std::optional<std::string>{absentUri})
    << "the unmapped URI must be preserved verbatim in the ErrorDetail, not dropped";
}

// =============================================================================================
// ClientNamespace.UriTaggedExpandedNodeIdReadResolvesEndToEnd - CL-ADDRSP-004
// END-TO-END over the REAL server + wire (the persist-by-URI read API is now BUILT): a URI-tagged
// ExpandedNodeId handed to the tier-2 read overload is resolved per-Session (URI -> the current
// NamespaceArray index) and the resulting single-node Read reaches the real compliance-namespace Variable,
// returning its value. A URI absent from the current Session is refused LOCALLY (Bad_NodeIdUnknown), never
// silently read against a stale/wrong index. [neg: absent URI is not substituted with a stale index]
//
// This drives the NEW production path (Connection::read_value_sync(ExpandedNodeId) -> resolve_local against
// namespace_table_snapshot() -> delegated NodeId read), NOT the resolver primitive in isolation.
// =============================================================================================
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ClientNamespace, UriTaggedExpandedNodeIdReadResolvesEndToEnd)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("UriTaggedRead")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Wire index 0 is ignored; the URI drives resolution to the compliance namespace's current index.
  const ExpandedNodeId byUri{NodeId(uint16_t{0}, std::string_view{"UriTaggedTarget"}), complianceUri};
  const auto value = connection->try_read_value_sync(byUri);
  ASSERT_TRUE(value.is_good()) << "the URI-tagged read must resolve + reach the real node: 0x" << std::hex
                               << value.status_code().as_uint32();
  const auto decoded = value.value().value().to<int32_t>();
  ASSERT_TRUE(decoded.is_good());
  EXPECT_EQ(decoded.value(), 4242)
    << "the resolved read must return the compliance-namespace Variable's value";

  // An absent URI is refused locally, not read against a stale index.
  const ExpandedNodeId absent{
    NodeId(uint16_t{0}, std::string_view{"UriTaggedTarget"}), "urn:vendor:namespace-not-in-this-server"};
  const auto rejected = connection->try_read_value_sync(absent);
  ASSERT_TRUE(rejected.is_bad()) << "an unresolved URI must fail, not read a wrong-namespace node";
  EXPECT_EQ(rejected.status_code().value(), static_cast<uint32_t>(Status::BadNodeIdUnknown));
}

// @relation(AC-SVR-BASE-001-NAMESPACEARRAY, scope=function)
// @relation(AC-SVR-BASE-047-NAMESPACEARRAY-APPEND-ONLY, scope=function)

// =============================================================================================
// ClientNamespace.PersistedNodeIdRenumberedAfterNamespaceArrayShuffle - CL-ADDRSP-004 / CL-SESS-028
// A NodeId persisted by URI is re-numbered against the CURRENT NamespaceArray: NamespaceTable::translate
// resolves the persisted node's index to its URI via the ORIGINAL snapshot, then re-resolves that URI to
// the SHUFFLED snapshot's index - preserving the identifier and changing only the namespace index. If the
// client cached the numeric index it would target the wrong namespace after the shuffle. [neg: namespace
// shuffle across sessions]
//
// SCOPE: there is no persist-by-URI read API, so the full "reconnect -> re-read shuffled array ->
// re-resolve on read" flow is not driven from one row. This grounds the ORIGINAL snapshot A on the REAL
// server's bootstrapped array and models the post-shuffle array as snapshot B (the same URIs,
// re-numbered - exactly the shape reconnect_re_read_namespace_array rebuilds), then drives the BUILT
// translate mechanism the reconnect remap uses. The reconnect half is real:
// ConnectionImplReconnect.ReconnectToAShuffledNamespaceArrayReportsAnIndexShift reconnects to a server
// whose array holds the same URIs at swapped indices and asserts the remap notification fires.
// =============================================================================================
// @verifies CL-ADDRSP-004
// @verifies CL-SESS-028
// @relation(CL-ADDRSP-004, CL-SESS-028, scope=function)
TEST_F(ClientNamespace, PersistedNodeIdRenumberedAfterNamespaceArrayShuffle)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("Renumber")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto original = connection->namespace_table();  // snapshot A - the REAL bootstrapped array
  ASSERT_NE(original, nullptr);
  const auto indexInA = original->lookup_index(complianceUri);
  ASSERT_TRUE(indexInA.has_value());

  // Snapshot B: the array a reconnect would rebuild after the server renumbered its namespaces. Insert a
  // filler URI at index 1 so every non-NS0 URI (including the compliance URI) shifts to a new index; NS0
  // stays at index 0 as create() requires.
  std::vector<std::string> shuffled = uris_of(*original);
  ASSERT_EQ(shuffled.front(), ns0Uri);
  shuffled.insert(shuffled.begin() + 1, "urn:vendor:shuffle-filler");
  auto builtB = NamespaceTable::create(std::move(shuffled), std::nullopt, original->generation() + 1);
  ASSERT_TRUE(builtB.is_good());
  auto renumbered = builtB.value();

  const auto indexInB = renumbered->lookup_index(complianceUri);
  ASSERT_TRUE(indexInB.has_value());
  ASSERT_NE(*indexInB, *indexInA) << "the shuffle must actually re-number the compliance URI";

  // The persisted NodeId (wire index from snapshot A) re-numbered against snapshot B.
  const NodeId persisted(*indexInA, std::string_view{"persisted-node"});
  auto result = renumbered->translate(persisted, *original);
  ASSERT_TRUE(result.is_good()) << "the persisted URI must re-resolve against the shuffled array: 0x"
                                << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(result.value(), NodeId(*indexInB, std::string_view{"persisted-node"}))
    << "the re-numbered NodeId must target the compliance URI's NEW index with the identifier preserved";
}

// =============================================================================================
// ClientNamespace.UnresolvedNamespaceUriAfterReconnectRejected - CL-ADDRSP-004
// When the server drops a namespace URI on reconnect, a NodeId persisted against that URI must NOT reuse
// a stale index and silently read the wrong namespace - translate rejects it with a bad Result carrying
// the "namespace URI is not present in the current Session NamespaceArray" ErrorDetail (the dropped URI
// preserved verbatim, plus the source/target snapshot generations). [neg: URI absent from new array]
//
// @verifies CL-SESS-028
// SCOPE: as with the renumber row, the reconnect half is driven separately (a URI DROPPED across a
// reconnect has no live counterpart - a server cannot be asked to forget a namespace). This grounds
// snapshot A on the REAL bootstrapped array and models the post-reconnect array as snapshot B with the
// compliance URI removed, then drives the BUILT translate rejection path.
// =============================================================================================
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, CL-SESS-028, scope=function)
TEST_F(ClientNamespace, UnresolvedNamespaceUriAfterReconnectRejected)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("UriDropped")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto original = connection->namespace_table();  // snapshot A - the REAL bootstrapped array
  ASSERT_NE(original, nullptr);
  const auto indexInA = original->lookup_index(complianceUri);
  ASSERT_TRUE(indexInA.has_value());

  // Snapshot B: the array a reconnect rebuilds after the server DROPPED the compliance URI (NS0 kept).
  std::vector<std::string> dropped;
  for (const auto& uri : uris_of(*original))
  {
    if (uri != complianceUri)
      dropped.push_back(uri);
  }
  ASSERT_EQ(dropped.front(), ns0Uri);
  auto builtB = NamespaceTable::create(std::move(dropped), std::nullopt, original->generation() + 1);
  ASSERT_TRUE(builtB.is_good());
  auto afterDrop = builtB.value();
  ASSERT_FALSE(afterDrop->lookup_index(complianceUri).has_value()) << "the URI must really be gone from B";

  const NodeId persisted(*indexInA, std::string_view{"persisted-node"});
  auto result = afterDrop->translate(persisted, *original);
  ASSERT_TRUE(result.is_bad()) << "a NodeId whose URI is gone must be rejected, not read from a stale index";
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(Status::BadNodeIdUnknown));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "UriUnresolved");
  EXPECT_EQ(context_value(*result.error_detail(), "namespace.uri"),
    std::optional<std::string>{std::string{complianceUri}})
    << "the dropped URI must be preserved verbatim in the ErrorDetail";
  EXPECT_EQ(context_value(*result.error_detail(), "namespace.target_generation"),
    std::optional<std::string>{std::to_string(afterDrop->generation())})
    << "the rejection must carry the current (target) snapshot generation for diagnosis";
}
