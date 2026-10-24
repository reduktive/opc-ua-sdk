// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientTypeResolver cluster of the client integration-test matrix (the 14 `ClientTypeResolver.*`
///        rows).
///
/// These exercise the per-Connection type-resolution component (`ua::client::detail::TypeResolver`,
/// client design section 8.6) and the decode-and-defer / DoS gate (section 9.2 / section 9.8 override 2)
/// against a REAL in-tree server over a REAL secure channel. The resolver is driven through the public upward
/// interfaces a real `ConnectionImpl` exposes (`wire_ops()` / `support_ops()`), so `resolve_async` issues
/// genuine Browse HasEncoding + Read DataTypeDefinition wire ops that the server answers - this is the
/// integration layer the FakeWireOps unit suite cannot reach.
///
/// STRUCTURAL REALITY (verified before authoring; updated for Slice T1(b)).
/// The TypeResolver, TypeDeferGate, and structure reify are BUILT and unit-tested as components. As of
/// Slice T1(a) the tier-2 `TypedAccess` read/call path consumes them: `TypedAccess::read_values_async`
/// and `call_method_async` run a gated-lazy reify pass (`ua_type_reify_consumer`) that upgrades a
/// post-decode `UnknownStructure` placeholder to its concrete typed `Structure` via the Connection's own
/// (first-active-seeded) TypeRegistry. As of Slice T1(b) this now covers SERVER-DISCOVERED structures too:
/// `on_definition_read` decodes the wire `DataTypeDefinition` and `finish_resolution` installs a real,
/// clone-able `DynamicStructure` decoder (was a `nullptr` placeholder), so a type resolved ONLY from the
/// server's `StructureDefinition` reifies to a typed C++ object (CL-ADDRSP-013).
/// `DecodesStructureViaDefinition` asserts this directly: the resolved entry now carries a non-null
/// `DynamicStructure` decoder over a real Browse + Read. Remaining scoped boundaries:
///   - ENUM / OPTION-SET DataTypeDefinitions resolve PROVENANCE-ONLY (no structure decoder): an enum value is
///     a plain integer, not an ExtensionObject-bodied structure, so there is nothing to reify - the numeric
///     value already round-trips (see `DecodesEnumAndOptionSetViaDefinition`). Localised enum-name surfacing
///     is a distinct, later concern, not a decoder-install gap.
///   - NESTED custom-struct fields are DEFERRED (MVP = built-in / NS0 scalar fields): a server struct whose
///     field references another unresolved custom type stays opaque rather than half-decoded (the
///     dependency-chase is a fast-follow), same top-level-only boundary as T1(a).
///   - the low-level ConnectionImpl read path is deliberately NOT reified - ONLY the `typed()` surface
///     carries the reify pass, not `conn()->try_read_value_sync` / `conn()->service_requests()`. So the
///     opaque-preservation rows that read through those paths (unknown ExtensionObject -> opaque
///     `UnknownStructure` whose bytes round-trip, message NOT aborted; injected with the MisbehavingServer
///     response mutator) remain correct: they observe the codec's raw opaque preservation, unaffected by
///     tier-2 reify.
///   - the core codec callsite still does NOT consult the `TypeDeferGate` on the handshake / security-body
///     decode path ("wiring the core codec callsite to consult this gate is a later slice"), so the matrix's
///     "handshake body fails closed" / "server observes at most B reads" clauses stay UNBUILT; those rows
///     assert the BUILT decision core (`classify_message`) from a real resolver and report the gap.
///
/// Falsifiability: every test encodes its matrix `[neg: ...]` falsifier. A resolver that mis-provenances
/// the primary path fails DecodesStructureViaDefinition; one that walks the dictionary when a definition
/// is present fails PrefersDataTypeDefinitionOverDictionary; one that keys its cache on the DataType (not
/// the encoding) fails InvalidatesCacheOnUnknownEncodingNodeId; a codec that aborts the whole message on
/// one unknown ExtensionObject fails UnknownExtensionObjectInReadDefersWithoutFailingMessage; a tier-2 read
/// path that fails to consume the reify consumer leaves the placeholder opaque and fails
/// ReifiesUserRegisteredStructureThroughTypedRead.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_client_observers.h"
#include "ua_attribute_id.h"
#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_type_defer_gate.h"
#include "ua_type_registry.h"
#include "ua_type_resolution_policy.h"
#include "ua_type_resolver.h"

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_binary_codec.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_encoding_limits.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_memory_stream.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_unknown_structure.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <mutex>
#include <algorithm>
#include <utility>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
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

using ua::client::detail::DeferDecision;
using ua::client::detail::MessageClass;
using ua::client::detail::RegistrationOutcome;
using ua::client::detail::TypeResolver;
using ua::client::detail::TypeSource;
using ua::client::detail::UserTypeRegistration;
using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// ResolverConnection: wraps a real `ConnectionImpl` (over an activated Session, no reconnect wiring ->
// single-shot, no keep-alive) and KEEPS the impl reachable so a test can build a standalone TypeResolver
// over the impl's real upward interfaces (`wire_ops()` / `support_ops()`). A private Connection handle drives
// the graceful close on destruction.
// ---------------------------------------------------------------------------------------------
class ResolverConnection
{
public:
  // @p config carries the per-Connection TypeResolutionPolicy the Connection's OWN resolver is built with,
  // so a test can drive a non-default policy through the production interface rather than through
  // make_resolver.
  ResolverConnection(
    boost::asio::any_io_executor executor, Session session, ua::client::detail::ConnectionConfig config = {})
  {
    mImpl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), std::move(config), Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    mImpl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(mImpl));
  }

  ~ResolverConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  ResolverConnection(const ResolverConnection&) = delete;
  ResolverConnection& operator=(const ResolverConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  ua::client::detail::ConnectionImpl& impl()
  {
    return *mImpl;
  }

  // Builds a standalone resolver over THIS connection's real wire/support interfaces with the supplied
  // policy. A fresh private strand over the connection executor serialises the resolver's own state; the wire
  // ops reach the real server and post their completions back onto this strand.
  std::shared_ptr<TypeResolver> make_resolver(TypeResolutionPolicy policy)
  {
    return TypeResolver::create(boost::asio::make_strand(mImpl->executor()),
      mImpl->wire_ops(),
      mImpl->support_ops(),
      std::move(policy),
      /*clientWideOverlay=*/nullptr,
      mImpl->logger());
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
  std::shared_ptr<ua::client::detail::ConnectionImpl> mImpl;
  VoidResult mStartStatus{};
  std::optional<Connection> mConnection;
};

// Drives `resolve_async` and blocks (with a deadline) for the resolver callback.
VoidResult resolve_sync(TypeResolver& resolver, const NodeId& encodingId)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  resolver.resolve_async(
    encodingId, nullptr, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
  if (future.wait_for(10s) != std::future_status::ready)
    return VoidResult{Status::BadTimeout};
  return future.get();
}

// Seeds the resolver's namespace snapshot (the connect-time hook the tier-0 slice leaves unwired) and
// blocks for the on-strand attach to complete.
void seed_namespaces_sync(TypeResolver& resolver, std::shared_ptr<const NamespaceTable> table)
{
  std::promise<void> promise;
  auto future = promise.get_future();
  resolver.on_namespace_table_replaced_async(std::move(table), [&promise] { promise.set_value(); });
  future.wait_for(10s);
}

// Drives `register_types_async` and blocks (with a deadline) for the per-registration outcome vector.
Result<std::vector<RegistrationOutcome>> register_sync(
  TypeResolver& resolver, std::vector<UserTypeRegistration> registrations)
{
  std::promise<Result<std::vector<RegistrationOutcome>>> promise;
  auto future = promise.get_future();
  resolver.register_types_async(std::move(registrations),
    [&promise](Result<std::vector<RegistrationOutcome>> result) { promise.set_value(std::move(result)); });
  if (future.wait_for(10s) != std::future_status::ready)
    return Result<std::vector<RegistrationOutcome>>{Status::BadTimeout};
  return future.get();
}

// A readable NS0 Variable present on every server (a value-bearing node with NO DataTypeDefinition).
NodeId server_state_node()
{
  return NodeId{VariableId::Server_ServerStatus_State};
}

NodeId current_time_node()
{
  return NodeId{VariableId::Server_ServerStatus_CurrentTime};
}

ByteString bytes(std::initializer_list<uint8_t> values)
{
  std::vector<byte> raw;
  raw.reserve(values.size());
  for (uint8_t value : values)
    raw.push_back(static_cast<byte>(value));
  return ByteString{std::move(raw)};
}

// Bounded-floor encoding limits for the local encode/decode round-trip (mirrors the reify consumer's
// unit test `limits()`); only used to build the injected placeholder body below.
EncodingLimits reify_test_limits()
{
  return make_encoding_limits(ApplicationConfig::load_default());
}

// Encodes a real Argument then decodes it with NO resolver, so the decoder leaves it as an opaque
// UnknownStructure carrying the Argument DefaultBinary encoding id + a VALID Argument body - exactly what
// the client secure-channel decoder produces for an unresolved encoding (mirrors the reify-consumer unit
// test's `make_argument_opaque()`). A test lifts the placeholder's encoding id + body to reconstruct fresh
// placeholders inside a response mutator.
ua::unique_ptr<Structure> make_opaque_argument()
{
  Argument argument;
  argument.name() = "Speed";
  argument.data_type() = NodeId{0, uint32_t{11}};
  argument.value_rank() = -1;

  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(reify_test_limits().stack_depth(), &argument);
  stream.seek_from_start(0);

  UaBinaryDecoder decoder{StructureResolver{}, stream, reify_test_limits()};
  ua::unique_ptr<Structure> opaque;
  decoder.decode(reify_test_limits().stack_depth(), opaque);
  return opaque;
}

// ---------------------------------------------------------------------------------------------
// MisbehavingResolverFixture: a real client bound to a MisbehavingServer's crypto + trusted store, on its
// own thread pool, with an activated Session wrapped into a ResolverConnection (so a test can reach the
// resolver over the real interfaces). Bootstrap completes against the un-mutated server; the test arms the
// response mutator AFTER construction. Mirrors client_read_matrix_tests.cpp's MisbehavingReadFixture.
// ---------------------------------------------------------------------------------------------
class MisbehavingResolverFixture
{
public:
  // @p connectionConfig is handed to the ConnectionImpl, so its TypeResolutionPolicy governs the resolver
  // the tier-2 reify path actually consults.
  explicit MisbehavingResolverFixture(
    MisbehavingServer& server, ua::client::detail::ConnectionConfig connectionConfig = {})
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientTypeResolverMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session), std::move(connectionConfig));
  }

  ~MisbehavingResolverFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingResolverFixture(const MisbehavingResolverFixture&) = delete;
  MisbehavingResolverFixture& operator=(const MisbehavingResolverFixture&) = delete;

  ResolverConnection& conn()
  {
    return *mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<ResolverConnection> mConnection;
};

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientTypeResolver` for the ComplianceWithNodes-server rows. Adds custom
// Structure / Enumeration DataType nodes (with DataTypeDefinition + DataTypeEncoding + HasEncoding) so
// the resolver's real Browse HasEncoding + Read DataTypeDefinition wire ops have something to resolve.
// =============================================================================================
class ClientTypeResolver : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // A custom Structure DataType WITH a DataTypeDefinition attribute + a DefaultBinary encoding node +
    // a HasEncoding reference (so an Inverse HasEncoding Browse from the encoding finds this DataType).
    mStructWithDefId = NodeId{mTestNamespaceIndex, uint32_t{9001}};
    mStructWithDefEncodingId = NodeId{mTestNamespaceIndex, uint32_t{9002}};
    create_structure_data_type(mStructWithDefId, mStructWithDefEncodingId, "StructWithDef", true);

    // A second DefaultBinary encoding for the SAME DataType (matrix "new DataTypeEncoding NodeId for the
    // same DataType" - drives InvalidatesCacheOnUnknownEncodingNodeId).
    mStructSecondEncodingId = NodeId{mTestNamespaceIndex, uint32_t{9003}};
    add_binary_encoding(mStructWithDefId, mStructSecondEncodingId, "Default Binary 2");

    // A custom Structure DataType WITHOUT a DataTypeDefinition attribute (drives the dictionary-disabled
    // rejection + missing-mandatory-definition rows).
    mStructNoDefId = NodeId{mTestNamespaceIndex, uint32_t{9011}};
    mStructNoDefEncodingId = NodeId{mTestNamespaceIndex, uint32_t{9012}};
    create_structure_data_type(mStructNoDefId, mStructNoDefEncodingId, "StructNoDef", false);

    // A plain UInt32 Variable (DecodesStandardVariantWhenTypeNodeAbsentFromAddressSpace).
    mUInt32VariableId = NodeId{mTestNamespaceIndex, uint32_t{9100}};
    make_scalar(mUInt32VariableId, NodeId{DataTypeId::UInt32}, "UInt32Var", Variant{uint32_t{4242}});

    // A custom Enumeration DataType + a Variable of it (DecodesEnumAndOptionSetViaDefinition, enum half).
    mEnumDataTypeId = NodeId{mTestNamespaceIndex, uint32_t{9200}};
    create_enum_data_type(mEnumDataTypeId, "CustomEnum", /*optionSet=*/false);
    mCustomEnumVariableId = NodeId{mTestNamespaceIndex, uint32_t{9201}};
    make_scalar(mCustomEnumVariableId, mEnumDataTypeId, "CustomEnumVar", Variant{int32_t{2}});

    // A Variable whose VALUE is a StructWithDef instance. The client's codec cannot decode encoding 9002
    // natively, so the value arrives as an opaque placeholder and only wire resolution + the reify pass
    // upgrade it - which is what makes it an oracle for the resolution policy. The body is the single
    // Int32 `Payload` field of StructWithDef (4242, little-endian).
    mStructValueVariableId = NodeId{mTestNamespaceIndex, uint32_t{9300}};
    make_scalar(mStructValueVariableId,
      mStructWithDefId,
      "StructWithDefVar",
      Variant{UnknownStructure{mStructWithDefEncodingId,
        UnknownStructure::BodyEncoding::Binary,
        ByteString{0x92, 0x10, 0x00, 0x00}}});

    // A custom OptionSet DataType (UInteger base) + a Variable of it (OptionSet half).
    mOptionSetDataTypeId = NodeId{mTestNamespaceIndex, uint32_t{9210}};
    create_enum_data_type(mOptionSetDataTypeId, "CustomOptionSet", /*optionSet=*/true);
    mCustomOptionSetVariableId = NodeId{mTestNamespaceIndex, uint32_t{9211}};
    make_scalar(
      mCustomOptionSetVariableId, mOptionSetDataTypeId, "CustomOptionSetVar", Variant{uint32_t{0b1011}});
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  // --- server-authoring helpers ---------------------------------------------------------------

  void make_scalar(const NodeId& nodeId, const NodeId& dataType, std::string_view name, Variant value)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
    variable->set_display_name(LocalizedText{"", std::string{name}});
    variable->set_data_type(dataType);
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(std::move(value));
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);
  }

  void add_binary_encoding(const NodeId& dataTypeId, const NodeId& encodingId, std::string_view name)
  {
    auto addressSpace = mServer.server().address_space();
    auto encodingNode = addressSpace.create_node_sync(encodingId, NodeClass::Object);
    encodingNode.set_browse_name(QualifiedName{0, std::string{name}});
    encodingNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::DataTypeEncodingType});
    // Forward HasEncoding DataType -> encoding; the address space adds the inverse half on the encoding node
    // (NR-70 B8). The resolver browses HasEncoding Inverse from the encoding node, so it needs the inverse edge
    // encoding -> DataType to find the DataType.
    auto dataTypeNode = addressSpace.find_node_sync(dataTypeId);
    dataTypeNode.add_reference_sync(NodeId{ReferenceTypeId::HasEncoding}, encodingId);
  }

  void create_structure_data_type(
    const NodeId& dataTypeId, const NodeId& encodingId, std::string_view name, bool withDefinition)
  {
    auto addressSpace = mServer.server().address_space();
    auto typeNode = addressSpace.create_node_sync(dataTypeId, NodeClass::DataType);
    typeNode.set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
    auto dtAccessor = typeNode.as<DataTypeAccessor>();
    dtAccessor->set_is_abstract(false);
    if (withDefinition)
    {
      auto structDef = std::make_shared<StructureDefinition>();
      structDef->structure_type() = ua::StructureType::Structure;
      structDef->base_data_type() = NodeId{DataTypeId::Structure};
      structDef->default_encoding_id() = encodingId;
      Array<StructureField> fields;
      StructureField field;
      field.name() = String{"Payload"};
      field.data_type() = NodeId{DataTypeId::Int32};
      field.value_rank() = -1;
      fields.push_back(std::move(field));
      structDef->fields() = std::move(fields);
      dtAccessor->set_data_type_definition(structDef);
    }
    auto structureNode = addressSpace.find_node_sync(NodeId{DataTypeId::Structure});
    structureNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, dataTypeId);
    add_binary_encoding(dataTypeId, encodingId, "Default Binary");
  }

  void create_enum_data_type(const NodeId& dataTypeId, std::string_view name, bool optionSet)
  {
    auto addressSpace = mServer.server().address_space();
    auto typeNode = addressSpace.create_node_sync(dataTypeId, NodeClass::DataType);
    typeNode.set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
    auto dtAccessor = typeNode.as<DataTypeAccessor>();
    dtAccessor->set_is_abstract(false);
    auto enumDef = std::make_shared<EnumDefinition>();
    Array<EnumField> fields;
    for (int64_t value : {int64_t{0}, int64_t{1}, int64_t{2}, int64_t{3}})
    {
      EnumField field;
      field.name() = String{"V" + std::to_string(value)};
      field.value() = value;
      fields.push_back(std::move(field));
    }
    enumDef->fields() = std::move(fields);
    dtAccessor->set_data_type_definition(enumDef);
    const NodeId base = optionSet ? NodeId{DataTypeId::UInteger} : NodeId{DataTypeId::Enumeration};
    auto baseNode = addressSpace.find_node_sync(base);
    baseNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, dataTypeId);
  }

  NodeId mStructWithDefId;
  NodeId mStructWithDefEncodingId;
  NodeId mStructSecondEncodingId;
  NodeId mStructNoDefId;
  NodeId mStructNoDefEncodingId;
  NodeId mStructValueVariableId;
  NodeId mUInt32VariableId;
  NodeId mEnumDataTypeId;
  NodeId mCustomEnumVariableId;
  NodeId mOptionSetDataTypeId;
  NodeId mCustomOptionSetVariableId;
};

// =============================================================================================
// Row: DecodesStructureViaDefinition  (ComplianceWithNodes) - CL-ADDRSP-013
// The resolver resolves a custom Structure via the primary DataTypeDefinition path over real Browse +
// Read wire ops; the resolution is tagged ServerDataTypeDefinition AND (Slice T1(b)) installs a real,
// clone-able DynamicStructure decoder built from the wire StructureDefinition - the type is now genuinely
// typed, not opaque. [neg: DataTypeDefinition not parsed / decoder still null]
// =============================================================================================
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST_F(ClientTypeResolver, DecodesStructureViaDefinition)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Struct")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto resolver = connection.make_resolver(TypeResolutionPolicy{});
  auto outcome = resolve_sync(*resolver, mStructWithDefEncodingId);
  ASSERT_TRUE(outcome.is_good()) << "primary DataTypeDefinition resolution must succeed: "
                                 << to_string(outcome.status_code());

  auto registry = resolver->registry();
  ASSERT_NE(registry, nullptr);
  EXPECT_EQ(registry->source_of(mStructWithDefEncodingId), TypeSource::ServerDataTypeDefinition)
    << "a Structure resolved via the DataTypeDefinition attribute must be provenance-tagged "
       "ServerDataTypeDefinition";

  // Slice T1(b): the wire DataTypeDefinition now builds a real decode prototype (was a nullptr placeholder).
  const auto* entry = registry->find_by_encoding(mStructWithDefEncodingId);
  ASSERT_NE(entry, nullptr);
  ASSERT_NE(entry->decoder, nullptr)
    << "a server-discovered Structure must install a real decoder built from its DataTypeDefinition";
  const auto* dynamic = dynamic_cast<const ua::DynamicStructure*>(entry->decoder.get());
  ASSERT_NE(dynamic, nullptr) << "the installed decoder must be a DynamicStructure built from the wire "
                                 "StructureDefinition (the server's StructWithDef)";
  ASSERT_EQ(dynamic->field_count(), 1u) << "the prototype must carry the server definition's single field";
  EXPECT_EQ(dynamic->descriptor().field(0).name(), String{"Payload"})
    << "the field layout must match the server's published StructureDefinition (field 'Payload')";
}

// =============================================================================================
// Row: DecodesStandardVariantWhenTypeNodeAbsentFromAddressSpace  (ComplianceWithNodes) - CL-BASE-008
// A UInt32 value decodes via the built-in registry regardless of whether its type Node is browseable.
// [neg: standard type refused because its type Node is absent]  (FULLY BUILT - no gap.)
// =============================================================================================
// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST_F(ClientTypeResolver, DecodesStandardVariantWhenTypeNodeAbsentFromAddressSpace)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("StdVariant")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->try_read_value_sync<uint32_t>(mUInt32VariableId);
  ASSERT_TRUE(result.is_good()) << "a standard UInt32 must decode via the built-in registry: "
                                << to_string(result.status_code());
  EXPECT_EQ(result.value(), 4242u) << "the UInt32 value must decode exactly";
}

// =============================================================================================
// Row: PrefersDataTypeDefinitionOverDictionary  (ComplianceWithNodes) - CL-ADDRSP-011
// With a DataTypeDefinition present AND dictionary fallback enabled, the resolver resolves via the
// DataTypeDefinition and provenance-tags ServerDataTypeDefinition - it never consults the dictionary.
// The provenance tag IS the precedence proof: had the dictionary been consulted-and-won, the source
// would be ServerDataTypeDictionary, and the resolver returns at definition-present BEFORE any dictionary
// (Value-attribute) read is issued. [neg: dictionary consulted when definition present]
// =============================================================================================
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST_F(ClientTypeResolver, PrefersDataTypeDefinitionOverDictionary)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Prefers")};
  ASSERT_TRUE(connection.start_status().is_good());

  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;  // dictionary is available but must NOT be preferred
  auto resolver = connection.make_resolver(policy);

  auto outcome = resolve_sync(*resolver, mStructWithDefEncodingId);
  ASSERT_TRUE(outcome.is_good()) << to_string(outcome.status_code());
  EXPECT_EQ(resolver->registry()->source_of(mStructWithDefEncodingId), TypeSource::ServerDataTypeDefinition)
    << "with a DataTypeDefinition present the resolver must resolve via it (not the dictionary), even "
       "when dictionary fallback is enabled";
}

// =============================================================================================
// Row: DictionaryFallbackDisabledRejectsWhenDefinitionAbsent  (ComplianceWithNodes) - CL-ADDRSP-011
// A Structure whose DataType has NO DataTypeDefinition, with allowDictionaryFallback=false, fails closed
// with Bad_DataTypeIdUnknown and installs nothing - and the failure carries the definition-absent /
// dictionary-DISABLED branch tag, proving the flag was honoured (no dictionary read attempted).
// [neg: fallback disabled must not read the dictionary]
// =============================================================================================
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST_F(ClientTypeResolver, DictionaryFallbackDisabledRejectsWhenDefinitionAbsent)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("NoDict")};
  ASSERT_TRUE(connection.start_status().is_good());

  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = false;
  auto resolver = connection.make_resolver(policy);

  auto outcome = resolve_sync(*resolver, mStructNoDefEncodingId);
  ASSERT_TRUE(outcome.is_bad()) << "a missing DataTypeDefinition with fallback disabled must fail closed";
  EXPECT_EQ(outcome.status_code(), StatusCode{Status::BadDataTypeIdUnknown});
  EXPECT_EQ(resolver->registry()->source_of(mStructNoDefEncodingId), std::nullopt)
    << "nothing must be installed on the fallback-disabled rejection path";

  const auto* detail = outcome.status_code().detail();
  ASSERT_NE(detail, nullptr) << "the rejection must carry a propagatable ErrorDetail";
  EXPECT_THAT(detail->source, ::testing::HasSubstr("dictionary_disabled"))
    << "the failure must be tagged the definition-absent/dictionary-DISABLED branch (proving the "
       "dictionary was NOT walked), not the dictionary-walk-failed branch";
}

// =============================================================================================
// Row: FallsBackToUserRegistrationForCustomStructure  (ComplianceWithNodes + register_types) - CL-BASE-008
// A custom struct that the SERVER does not host is resolved from a user register_types() registration -
// proving the user-registration rung of the precedence ladder. Because the server has no such node, a
// wire resolution would fail Bad_NodeIdUnknown; a Good resolve therefore proves the user registration
// short-circuited wire discovery. [neg: user registration ignored -> falls through to the wire]
// =============================================================================================
// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST_F(ClientTypeResolver, FallsBackToUserRegistrationForCustomStructure)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("UserReg")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto resolver = connection.make_resolver(TypeResolutionPolicy{});

  // Seed a namespace snapshot carrying the registration URI so attach-or-defer resolves URI -> index.
  const std::string userUri = "urn:test:type-resolver:user";
  auto table = NamespaceTable::create(
    {"http://opcfoundation.org/UA/", "urn:test:type-resolver:server", userUri}, std::nullopt, 1);
  ASSERT_TRUE(table.is_good());
  seed_namespaces_sync(*resolver, table.value());
  const auto userIndex = table.value()->lookup_index(userUri);
  ASSERT_TRUE(userIndex.has_value());

  UserTypeRegistration registration;
  registration.namespaceUri = userUri;
  registration.dataTypeIdentifier = NodeId{0, uint32_t{9500}};  // ns overwritten by the resolved index
  registration.binaryEncodingIdentifier = NodeId{0, uint32_t{9501}};
  auto outcomes = register_sync(*resolver, {registration});
  ASSERT_TRUE(outcomes.is_good());
  ASSERT_EQ(outcomes.value().size(), 1u);
  EXPECT_TRUE(outcomes.value()[0].status.is_good()) << "the registration must install";

  const NodeId encodingId{*userIndex, uint32_t{9501}};
  EXPECT_EQ(resolver->registry()->source_of(encodingId), TypeSource::UserRegistered);

  // The server has no such node; resolving succeeds ONLY because the user registration short-circuits the
  // wire - a wire resolution would fail Bad_NodeIdUnknown.
  auto outcome = resolve_sync(*resolver, encodingId);
  EXPECT_TRUE(outcome.is_good())
    << "a user-registered encoding must resolve from the registration without hitting the wire";
}

// =============================================================================================
// Row: DecodesEnumAndOptionSetViaDefinition  (ComplianceWithNodes) - CL-ADDRSP-013
// A custom-Enumeration-typed value and a custom-OptionSet-typed value round-trip their numeric wire form
// faithfully through the client read path (an enumerant Int32; an OptionSet UInteger bit-mask).
// [neg: OptionSetLength boundary / enum value corrupted]
//
// Scope note (Slice T1(b)): an enum / option-set DataTypeDefinition resolves PROVENANCE-ONLY by design -
// an enum value is a plain integer, NOT an ExtensionObject-bodied structure, so there is no structure
// decoder to install or placeholder to reify (unlike a server Structure, which now installs a real
// DynamicStructure decoder - see DecodesStructureViaDefinition). The faithful numeric round-trip asserted
// here IS the complete built observable for these types; localised enum-name surfacing is a separate,
// later concern, not a decoder-install gap.
// =============================================================================================
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST_F(ClientTypeResolver, DecodesEnumAndOptionSetViaDefinition)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("EnumOpt")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto enumValue = connection->try_read_value_sync<int32_t>(mCustomEnumVariableId);
  ASSERT_TRUE(enumValue.is_good()) << to_string(enumValue.status_code());
  EXPECT_EQ(enumValue.value(), 2) << "the custom Enumeration enumerant must round-trip as its Int32 value";

  auto optionSetValue = connection->try_read_value_sync<uint32_t>(mCustomOptionSetVariableId);
  ASSERT_TRUE(optionSetValue.is_good()) << to_string(optionSetValue.status_code());
  EXPECT_EQ(optionSetValue.value(), uint32_t{0b1011})
    << "the custom OptionSet bit-mask must round-trip exactly (every set bit preserved)";
}

// =============================================================================================
// Row: MissingMandatoryDefinitionForStructureReported  (ComplianceWithNodes) - CL-ADDRSP-013
// A Structure-derived DataType that (non-conformantly) omits its mandatory DataTypeDefinition, with
// fallback disabled, is REPORTED as a bad Result carrying a propagatable ErrorDetail - it is NOT silently
// degraded to an opaque value returned as if Good. [neg: mandatory attribute absent -> silent degrade]
//
// Scope note: the matrix's tier-2 message text "custom Structure missing mandatory DataTypeDefinition" is
// the (unbuilt) tier-2 typed-read wrapper's; this pins the resolver-level report - a bad Result with the
// TypeResolverDefinitionAbsent ErrorDetail - which the wrapper would surface.
// =============================================================================================
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST_F(ClientTypeResolver, MissingMandatoryDefinitionForStructureReported)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Missing")};
  ASSERT_TRUE(connection.start_status().is_good());

  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = false;
  auto resolver = connection.make_resolver(policy);

  auto outcome = resolve_sync(*resolver, mStructNoDefEncodingId);
  ASSERT_TRUE(outcome.is_bad()) << "a missing mandatory DataTypeDefinition must be reported, not degraded";
  const auto* detail = outcome.status_code().detail();
  ASSERT_NE(detail, nullptr) << "the report must carry an ErrorDetail (never a silent opaque-as-Good)";
  EXPECT_EQ(detail->code, "TypeResolverDefinitionAbsent")
    << "the ErrorDetail must name the definition-absent condition";
}

// =============================================================================================
// Row: InvalidatesCacheOnUnknownEncodingNodeId  (ComplianceWithNodes) - CL-ADDRSP-012
// The resolver cache is keyed on the DataTypeEncoding NodeId, NOT the DataType NodeId: after resolving
// encoding E1 (DataType D), a DIFFERENT encoding E2 of the SAME DataType D is a cache MISS (no stale hit
// that would mis-decode E2's bytes with E1's entry). E2 then resolves independently to D.
// [neg: unknown DataTypeEncoding NodeId reuses the DataType-keyed stale entry]
// =============================================================================================
// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST_F(ClientTypeResolver, InvalidatesCacheOnUnknownEncodingNodeId)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Cache")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto resolver = connection.make_resolver(TypeResolutionPolicy{});

  ASSERT_TRUE(resolve_sync(*resolver, mStructWithDefEncodingId).is_good());
  {
    auto registry = resolver->registry();
    ASSERT_NE(registry->find_by_encoding(mStructWithDefEncodingId), nullptr);
    EXPECT_EQ(registry->find_by_encoding(mStructSecondEncodingId), nullptr)
      << "a NEW encoding of the same DataType must be a cache MISS - the cache keys on the encoding "
         "NodeId, so E1's entry must not be a stale hit for E2";
  }

  ASSERT_TRUE(resolve_sync(*resolver, mStructSecondEncodingId).is_good())
    << "the new encoding must resolve independently (its own Browse + DataTypeDefinition read)";
  {
    auto registry = resolver->registry();
    const auto* first = registry->find_by_encoding(mStructWithDefEncodingId);
    const auto* second = registry->find_by_encoding(mStructSecondEncodingId);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first->dataTypeId, mStructWithDefId);
    EXPECT_EQ(second->dataTypeId, mStructWithDefId)
      << "both encodings resolve to the same DataType, but each is keyed on its own encoding NodeId";
  }
}

// =============================================================================================
// Row: CachesDefinitionAcrossSessions  (ComplianceWithNodes) - CL-ADDRSP-012
// BLOCKED (reconnect harness): the matrix drives a reconnect to the SAME server and asserts the second
// session does NOT re-read the DataTypeDefinition. The single-shot fixture has no reconnect wiring, so
// this pins the client-observable analog: a SECOND resolve of an already-cached encoding on the SAME
// session hits the cache - the registry generation does NOT advance (no re-install), proving no
// re-fetch. Cross-session survival is reported blocked-on-reconnect-harness. [neg: cache miss re-fetches]
// =============================================================================================
// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST_F(ClientTypeResolver, CachesDefinitionAcrossSessions)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("CacheHit")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto resolver = connection.make_resolver(TypeResolutionPolicy{});

  ASSERT_TRUE(resolve_sync(*resolver, mStructWithDefEncodingId).is_good());
  const auto generationAfterFirst = resolver->registry()->generation();

  // Second resolve of the SAME encoding: the fast path returns Good WITHOUT re-installing, so the
  // published registry generation is unchanged. A re-fetch would install again and advance it.
  ASSERT_TRUE(resolve_sync(*resolver, mStructWithDefEncodingId).is_good());
  EXPECT_EQ(resolver->registry()->generation(), generationAfterFirst)
    << "a second resolve of a cached encoding must hit the cache (no re-fetch / no re-install)";
}

// =============================================================================================
// Row: UnknownExtensionObjectInHandshakeBodyFailsClosed  (real resolver) - CL-ATTR-013 / section 9.2 strict
// The decode-and-defer eligibility gate is a security boundary: a SecurityCritical (handshake / auth)
// body must fail closed (StrictFail) for ANY count of unknown encodings, while an ApplicationData body
// with none defers. This asserts the BUILT decision core (TypeDeferGate::classify via the resolver).
// [neg: deferral applied to a security-critical body]
//
// BLOCKED (codec-callsite): the end-to-end "inject an unknown ExtensionObject into a CreateSession/
// ActivateSession body -> client returns Bad_DecodingError" is UNBUILT - the core codec callsite does NOT
// yet consult this gate (ua_type_defer_gate.h: "wiring the core codec callsite ... is a later slice"), so
// an unknown ExtensionObject is ALWAYS decoded to an opaque UnknownStructure regardless of message class.
// This pins the ratified decision the codec will consult; the wiring is reported blocked-on-unbuilt.
// =============================================================================================
// @verifies CL-ATTR-013
// @relation(CL-ATTR-013, scope=function)
TEST_F(ClientTypeResolver, UnknownExtensionObjectInHandshakeBodyFailsClosed)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Strict")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto resolver = connection.make_resolver(TypeResolutionPolicy{});

  EXPECT_EQ(resolver->classify_message(MessageClass::SecurityCritical, 0), DeferDecision::StrictFail)
    << "a security-critical body must fail closed even with zero unknown encodings";
  EXPECT_EQ(resolver->classify_message(MessageClass::SecurityCritical, 5), DeferDecision::StrictFail)
    << "a security-critical body must NEVER defer a check on attacker-influenced bytes";
  EXPECT_EQ(resolver->classify_message(MessageClass::ApplicationData, 0), DeferDecision::Defer)
    << "an application-data body with no unknown encodings is eligible to defer (control)";
}

// =============================================================================================
// Row: RedecodeBudgetCapsUnknownEncodingsInOneMessage  (real resolver) - CL-ATTR-013 / section 9.2 DoS cap
// The distinct-unresolved-type budget is a DoS guard: at or below the cap, an application body DEFERS
// (drives resolution); ABOVE the cap it surfaces terminal Placeholders WITHOUT further resolution (the
// decode still succeeds). This asserts the BUILT decision core with a small configured cap.
// [neg: decode-bomb via unbounded re-decode]
//
// BLOCKED (codec-callsite): the matrix's end-to-end "server observes at most B type-resolution reads" is
// UNBUILT - nothing drives resolve_async per unknown encoding from the codec yet (same later-slice gap as
// above). This pins the cap decision; the request-count observable is reported blocked-on-unbuilt.
// =============================================================================================
// @verifies CL-ATTR-013
// @relation(CL-ATTR-013, scope=function)
TEST_F(ClientTypeResolver, RedecodeBudgetCapsUnknownEncodingsInOneMessage)
{
  ResolverConnection connection{mClientThreadPool.executor(), open_activated_session("Budget")};
  ASSERT_TRUE(connection.start_status().is_good());

  TypeResolutionPolicy policy;
  policy.defer.maxDistinctUnresolvedTypesPerMessage = 3;
  auto resolver = connection.make_resolver(policy);

  EXPECT_EQ(resolver->classify_message(MessageClass::ApplicationData, 3), DeferDecision::Defer)
    << "at the distinct-type budget the message may still resolve (Defer)";
  EXPECT_EQ(resolver->classify_message(MessageClass::ApplicationData, 4), DeferDecision::Placeholder)
    << "one over the budget must cap resolution - terminal Placeholders, no further resolve work "
       "(the decode-bomb guard)";
}

// =============================================================================================
// Row: FallsBackToDictionaryWhenDefinitionAbsentAndEnabled  (MisbehavingServer) - CL-ADDRSP-011
// With allowDictionaryFallback=true and no DataTypeDefinition, the resolver walks the (deprecated)
// dictionary path and provenance-tags ServerDataTypeDictionary. [neg: fallback not wired -> stays
// unresolved]
//
// Matrix-oracle deviation (BATCHED): the built dictionary model is a STUB - it resolves by READING the
// Value attribute of the DataType node ("the full HasComponent -> DataTypeSystem walk is a later slice"),
// so a conformant DataTypeDictionaryType subtree on a plain ComplianceWithNodes server cannot drive it
// (a DataType node has no Value). This drives the BUILT stub over the real channel: the MisbehavingServer
// points the resolver's HasEncoding Browse at a real value-bearing Variable, whose DataTypeDefinition is
// absent (Variables have none) but whose Value read is Good+non-empty - exactly the stub's success input.
// =============================================================================================
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST_F(ClientTypeResolver, FallsBackToDictionaryWhenDefinitionAbsentAndEnabled)
{
  MisbehavingServer server;
  MisbehavingResolverFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good()) << "bootstrap must succeed against the un-mutated server: "
                                                << to_string(fixture.start_status().status_code());

  // Point the resolver's Inverse-HasEncoding Browse at a real Variable (Value present, DataTypeDefinition
  // absent) so the DataTypeDefinition read fails and the dictionary (Value) read succeeds.
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
      {
        if (!browse->results().empty())
        {
          ReferenceDescription reference;
          reference.node_id().node_id() = server_state_node();
          Array<ReferenceDescription> references;
          references.push_back(std::move(reference));
          browse->results()[0].references() = std::move(references);
          browse->results()[0].status_code() = StatusCode{Status::Good};
        }
      }
    });

  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;
  auto resolver = fixture.conn().make_resolver(policy);

  const NodeId syntheticEncodingId{1, uint32_t{55555}};
  auto outcome = resolve_sync(*resolver, syntheticEncodingId);
  ASSERT_TRUE(outcome.is_good()) << "the dictionary fallback must resolve the structure: "
                                 << to_string(outcome.status_code());
  EXPECT_EQ(resolver->registry()->source_of(syntheticEncodingId), TypeSource::ServerDataTypeDictionary)
    << "a resolution via the dictionary fallback must be provenance-tagged ServerDataTypeDictionary";
}

// =============================================================================================
// Row: ReturnsOpaqueWithErrorDetailWhenTypeFullyUnknown  (MisbehavingServer) - CL-BASE-008
// A Read value carrying an ExtensionObject of a fully-unknown encoding is preserved as an opaque
// UnknownStructure whose raw bytes round-trip - the whole Read is NOT hard-failed. [neg: whole Read fails
// hard, no bytes returned]
//
// Scope note (BATCHED): the matrix's "ErrorDetail source-tagged 'TypeResolver' naming the unresolved
// NodeId" is UNBUILT - the read/decode path does not consult the resolver, so no such ErrorDetail is
// attached (the value is opaque with Good status). This pins the BUILT opaque preservation (raw bytes +
// encoding id retained, message not aborted), which is the substrate that tagging would annotate.
// =============================================================================================
// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST_F(ClientTypeResolver, ReturnsOpaqueWithErrorDetailWhenTypeFullyUnknown)
{
  MisbehavingServer server;
  MisbehavingResolverFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId unknownEncodingId{5, uint32_t{424242}};  // unknown to built-in / dictionary / user layers
  const ByteString body = bytes({0xDE, 0xAD, 0xBE, 0xEF});
  server.set_response_mutator(
    [unknownEncodingId, body](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{
            Variant{UnknownStructure{unknownEncodingId, UnknownStructure::BodyEncoding::Binary, body}}};
      }
    });

  auto result = fixture.conn()->try_read_value_sync(server_state_node());
  ASSERT_TRUE(result.is_good()) << "an unknown ExtensionObject must NOT hard-fail the Read: "
                                << to_string(result.status_code());
  ASSERT_TRUE(result.value().value().is_structure()) << "the unknown value must survive as a structure";
  const auto* opaque = result.value().value().try_as<UnknownStructure>();
  ASSERT_NE(opaque, nullptr) << "a fully-unknown ExtensionObject must be preserved as an UnknownStructure";
  EXPECT_EQ(opaque->encoding_id(), unknownEncodingId) << "the unresolved encoding NodeId must be retained";
  EXPECT_EQ(opaque->encoded_data(), body) << "the raw encoded bytes must round-trip losslessly";
}

// =============================================================================================
// Row: UnknownExtensionObjectInReadDefersWithoutFailingMessage  (MisbehavingServer) - CL-BASE-008 /
// CL-ATTR-013
// In a 2-slot Read, one KNOWN field and one unknown-encoding ExtensionObject: the known field decodes to
// its sent value AND the unknown field is an opaque UnknownStructure whose bytes round-trip - the whole
// message is NOT aborted. [neg: partial-decode aborts the whole application-data message]
//
// Scope note (BATCHED): section 9.2 GATES lazy decode-and-defer-then-RE-DECODE-to-typed as "a design target,
// not a committed default"; the resolver-driven re-decode is UNBUILT (no codec callsite). What IS built -
// and asserted here - is the codec's inherent opaque preservation: an unknown ExtensionObject becomes an
// opaque placeholder without aborting the surrounding message, so the known field still flows.
// =============================================================================================
// @verifies CL-BASE-008
// @verifies CL-ATTR-013
// @relation(CL-ATTR-013, CL-BASE-008, scope=function)
TEST_F(ClientTypeResolver, UnknownExtensionObjectInReadDefersWithoutFailingMessage)
{
  MisbehavingServer server;
  MisbehavingResolverFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId unknownEncodingId{5, uint32_t{424243}};
  const ByteString body = bytes({0x01, 0x02, 0x03});
  server.set_response_mutator(
    [unknownEncodingId, body](Response& response)
    {
      auto* read = dynamic_cast<ReadResponse*>(response.second.get());
      if (!read || read->results().size() < 2)
        return;
      read->results()[0] = DataValue{Variant{int32_t{7}}};  // KNOWN field
      read->results()[1] =
        DataValue{Variant{UnknownStructure{unknownEncodingId, UnknownStructure::BodyEncoding::Binary, body}}};
    });

  auto result = fixture.conn()->service_requests().try_read_sync(ReadRequestBuilder()
                                                                   .read(server_state_node())
                                                                   .attribute(AttributeId::Value)
                                                                   .read(current_time_node())
                                                                   .attribute(AttributeId::Value)
                                                                   .build());
  ASSERT_TRUE(result.is_good()) << "one unknown ExtensionObject must not abort the whole Read: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);

  const int32_t* known = result.value().results()[0].value().try_as<int32_t>();
  ASSERT_NE(known, nullptr) << "the KNOWN field must still decode (message not aborted)";
  EXPECT_EQ(*known, 7);

  const auto* opaque = result.value().results()[1].value().try_as<UnknownStructure>();
  ASSERT_NE(opaque, nullptr) << "the unknown field must be preserved as an opaque UnknownStructure";
  EXPECT_EQ(opaque->encoded_data(), body) << "the deferred field's bytes must round-trip losslessly";
}

// =============================================================================================
// Row: ReifiesUserRegisteredStructureThroughTypedRead  (MisbehavingServer) - Slice T1(a) end-to-end
// The genuine end-to-end confirmation that the tier-2 typed read path REIFIES a user-registered type over a
// REAL server + secure channel. The wire decoder leaves a structured value it cannot resolve as an opaque
// UnknownStructure; the gated-lazy reify consumer wired into `TypedAccess::read_values_async` upgrades that
// placeholder to its concrete typed Structure via the Connection's own (first-active-seeded) TypeRegistry.
//
// Stimulus: register the Argument type into THE CONNECTION'S OWN resolver (not a standalone make_resolver
// one - only the Connection's resolver backs the read-path reify consumer), then inject an opaque Argument
// placeholder (valid Argument body + the Argument DefaultBinary encoding id) into the Read result via the
// MisbehavingServer response mutator, and read through the reify-wired `typed().try_read_values_sync` bulk
// path (the single-node `try_read_value_sync` / `service_requests()` paths are deliberately NOT reified).
//
// RED/GREEN: with the Slice T1(a) wiring the caller sees a CONCRETE ua::Argument (reified). [neg]: without
// the reify wiring `read_values_async` would deliver the injected value verbatim and the caller would see an
// UnknownStructure - the try_as<ua::Argument>() below would be null. The reify component's own branch logic
// is unit-covered by TypeReifyConsumer.ProductionAdapterReifiesUserRegisteredType; THIS proves the wired
// tier-2 read path performs that reification over a real server + secure channel.
// =============================================================================================
// @verifies CL-BASE-008
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, CL-BASE-008, scope=function)
TEST_F(ClientTypeResolver, ReifiesUserRegisteredStructureThroughTypedRead)
{
  MisbehavingServer server;
  MisbehavingResolverFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good()) << "bootstrap must succeed against the un-mutated server: "
                                                << to_string(fixture.start_status().status_code());

  // Build the opaque Argument placeholder the wire decoder would produce for an unresolved encoding, and lift
  // its encoding id + preserved body so the mutator can reconstruct fresh placeholders per response.
  auto placeholder = make_opaque_argument();
  const auto* opaqueArgument = dynamic_cast<const UnknownStructure*>(placeholder.get());
  ASSERT_NE(opaqueArgument, nullptr)
    << "the decoder must leave an unresolved Argument as an UnknownStructure";
  const NodeId argumentEncodingId = opaqueArgument->encoding_id();
  const ByteString argumentBody = opaqueArgument->encoded_data();

  // Register the Argument type into the Connection's OWN resolver (the one the reify consumer consults). URI
  // = the standard UA namespace, which is index 0 in the first-active-seeded table, so this installs
  // immediately rather than parking for a later namespace snapshot.
  auto resolver = fixture.conn().impl().type_resolver();
  ASSERT_NE(resolver, nullptr);
  UserTypeRegistration registration;
  registration.namespaceUri = "http://opcfoundation.org/UA/";
  registration.dataTypeIdentifier = NodeId{0, uint32_t{296}};  // the Argument DataType
  registration.binaryEncodingIdentifier = NodeId{Argument::defaultBinaryEncodingId};
  registration.decoder = std::make_shared<Argument>();
  auto outcomes = register_sync(*resolver, {registration});
  ASSERT_TRUE(outcomes.is_good()) << to_string(outcomes.status_code());
  ASSERT_EQ(outcomes.value().size(), 1u);
  EXPECT_TRUE(outcomes.value()[0].status.is_good()) << "the registration must install";
  EXPECT_FALSE(outcomes.value()[0].retainedForLaterAttach)
    << "the standard UA URI is index 0 after first-active seeding, so the registration must install (not "
       "park)";
  ASSERT_EQ(resolver->registry()->source_of(argumentEncodingId), TypeSource::UserRegistered)
    << "the Argument encoding must be present in the Connection's registry as a user-registered type";

  // Inject the opaque Argument (valid body + Argument encoding id) as the first Read result value.
  server.set_response_mutator(
    [argumentEncodingId, argumentBody](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{Variant{
            UnknownStructure{argumentEncodingId, UnknownStructure::BodyEncoding::Binary, argumentBody}}};
      }
    });

  // Read through the reify-wired tier-2 bulk path (read_values_async carries the reify pass).
  auto result = fixture.conn()->typed().try_read_values_sync(std::vector<NodeId>{server_state_node()});
  ASSERT_TRUE(result.is_good()) << "the reify-wired typed read must succeed: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u);

  const Variant& value = result.value()[0].value();
  ASSERT_TRUE(value.is_structure()) << "the reified value must still be a structure";
  const Argument* reified = value.try_as<Argument>();
  ASSERT_NE(reified, nullptr)
    << "the tier-2 typed read must upgrade the user-registered placeholder to a CONCRETE ua::Argument; "
       "without the Slice T1(a) reify wiring the caller would see an UnknownStructure";
  EXPECT_EQ(value.as<Structure>().type_name(), String{"Argument"})
    << "the reified structure must report its concrete type name";
}

// =============================================================================================
// Configuration coverage: TypeResolutionPolicy fields proven through the Connection's OWN resolver
// (configuration coverage matrix, Wave 0). Each sets the field to a NON-DEFAULT
// value on the ConnectionConfig the ConnectionImpl is constructed with, so the policy travels the
// production path - a standalone make_resolver would bypass the wiring under test. Each also runs the
// default-configured control against the same server, so the assertion distinguishes the field's effect
// from anything the fixture does on its own.
//
// The placeholder carries a SYNTHETIC encoding id (kSyntheticEncodingId) rather than Argument's own. A
// standard NS0 encoding is decoded natively by the core codec, so no placeholder would ever reach the
// reify pass and the oracle could not tell reify from ordinary decoding. Under an id the codec cannot
// know, the value arrives opaque and ONLY the registry-backed reify pass can upgrade it.
// =============================================================================================

// An NS0 identifier no standard encoding uses, so the core codec leaves a body under it opaque.
NodeId synthetic_encoding_id()
{
  return NodeId{0, uint32_t{60000}};
}

// How long the resolution-deadline row holds the discovery Browse. Two orders of magnitude above the 1 ms
// budget under test, so scheduling jitter on a loaded CI runner cannot close the gap.
constexpr auto resolveBrowseHold = 200ms;

// Registers the Argument decoder under the synthetic encoding id in @p resolver (the Connection's own),
// so a placeholder carrying that id is resolvable by the registry but not by the codec.
void register_synthetic_argument(TypeResolver& resolver)
{
  UserTypeRegistration registration;
  registration.namespaceUri = "http://opcfoundation.org/UA/";
  registration.dataTypeIdentifier = NodeId{0, uint32_t{296}};  // the Argument DataType
  registration.binaryEncodingIdentifier = synthetic_encoding_id();
  registration.decoder = std::make_shared<Argument>();
  auto outcomes = register_sync(resolver, {registration});
  ASSERT_TRUE(outcomes.is_good()) << to_string(outcomes.status_code());
  ASSERT_EQ(outcomes.value().size(), 1u);
  ASSERT_TRUE(outcomes.value()[0].status.is_good());
  ASSERT_EQ(resolver.registry()->source_of(synthetic_encoding_id()), TypeSource::UserRegistered);
}

// Replaces the first Read result with an opaque Argument body under the synthetic encoding id, but only
// while @p enabled is set. The gate matters because a Connection's bootstrap issues Reads of its own and
// rewriting their first result fails the start - and because the server's raw mutators COMPOSE, so an
// installed mutator cannot be removed, only switched off.
void inject_synthetic_placeholder(
  MisbehavingServer& server, const ByteString& body, std::shared_ptr<std::atomic<bool>> enabled)
{
  server.set_response_mutator(
    [body, enabled = std::move(enabled)](Response& response)
    {
      if (!enabled->load())
        return;
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{
            Variant{UnknownStructure{synthetic_encoding_id(), UnknownStructure::BodyEncoding::Binary, body}}};
      }
    });
}

// Row: tier2WaitForResolution - false hands back the decoder's placeholder instead of blocking for the
// reify pass, and resolves in the background so the next read finds a warm registry.
TEST_F(ClientTypeResolver, Tier2WaitForResolutionFalseDeliversPlaceholderUnreified)
{
  MisbehavingServer server;
  auto placeholder = make_opaque_argument();
  const auto* opaque = dynamic_cast<const UnknownStructure*>(placeholder.get());
  ASSERT_NE(opaque, nullptr);
  const ByteString body = opaque->encoded_data();
  auto injecting = std::make_shared<std::atomic<bool>>(false);
  inject_synthetic_placeholder(server, body, injecting);

  // Control: the default policy waits, so the registered type reifies to a concrete ua::Argument.
  {
    MisbehavingResolverFixture waiting{server};
    ASSERT_TRUE(waiting.start_status().is_good()) << to_string(waiting.start_status().status_code());
    auto resolver = waiting.conn().impl().type_resolver();
    ASSERT_NE(resolver, nullptr);
    ASSERT_TRUE(resolver->policy().tier2WaitForResolution) << "the control must run the default";
    ASSERT_NO_FATAL_FAILURE(register_synthetic_argument(*resolver));
    injecting->store(true);

    auto result = waiting.conn()->typed().try_read_values_sync(std::vector<NodeId>{server_state_node()});
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_NE(result.value()[0].value().try_as<Argument>(), nullptr)
      << "waiting for resolution must upgrade the placeholder to its registered concrete type";
    injecting->store(false);  // the next fixture must bootstrap against un-mutated responses
  }

  ua::client::detail::ConnectionConfig config;
  config.typeResolution.tier2WaitForResolution = false;  // default true
  MisbehavingResolverFixture notWaiting{server, config};
  ASSERT_TRUE(notWaiting.start_status().is_good()) << to_string(notWaiting.start_status().status_code());
  auto resolver = notWaiting.conn().impl().type_resolver();
  ASSERT_NE(resolver, nullptr);
  ASSERT_FALSE(resolver->policy().tier2WaitForResolution)
    << "the ConnectionConfig policy must reach the Connection's own resolver";
  ASSERT_NO_FATAL_FAILURE(register_synthetic_argument(*resolver));
  injecting->store(true);

  auto result = notWaiting.conn()->typed().try_read_values_sync(std::vector<NodeId>{server_state_node()});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u);

  const Variant& value = result.value()[0].value();
  ASSERT_TRUE(value.is_structure());
  EXPECT_EQ(value.try_as<Argument>(), nullptr)
    << "tier2WaitForResolution=false must NOT block for the reify pass, though the control above shows "
       "this same type reifies under the default";
  EXPECT_NE(value.try_as<UnknownStructure>(), nullptr)
    << "the un-awaited value must be delivered as the decoder's opaque placeholder, never dropped";
}

// Row: defer.maxReDecodePasses - a zero budget permits no re-decode pass, so a resolved placeholder is
// delivered opaque. Distinct from tier2WaitForResolution: this read DOES wait and the registry IS warm;
// only the in-place re-decode is withheld.
TEST_F(ClientTypeResolver, ZeroRedecodeBudgetDeliversResolvedTypeOpaque)
{
  MisbehavingServer server;
  auto placeholder = make_opaque_argument();
  const auto* opaque = dynamic_cast<const UnknownStructure*>(placeholder.get());
  ASSERT_NE(opaque, nullptr);
  const ByteString body = opaque->encoded_data();

  ua::client::detail::ConnectionConfig config;
  config.typeResolution.defer.maxReDecodePasses = 0;  // default 1
  MisbehavingResolverFixture fixture{server, config};
  ASSERT_TRUE(fixture.start_status().is_good()) << to_string(fixture.start_status().status_code());

  auto resolver = fixture.conn().impl().type_resolver();
  ASSERT_NE(resolver, nullptr);
  ASSERT_TRUE(resolver->policy().tier2WaitForResolution)
    << "this row isolates the re-decode budget, so the read must still wait for resolution";
  ASSERT_FALSE(resolver->may_redecode(0)) << "a zero budget must permit no pass";
  ASSERT_NO_FATAL_FAILURE(register_synthetic_argument(*resolver));
  auto injecting = std::make_shared<std::atomic<bool>>(true);
  inject_synthetic_placeholder(server, body, injecting);

  auto result = fixture.conn()->typed().try_read_values_sync(std::vector<NodeId>{server_state_node()});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u);

  const Variant& value = result.value()[0].value();
  EXPECT_EQ(value.try_as<Argument>(), nullptr)
    << "a zero re-decode budget must leave the placeholder opaque; the default budget of 1 reifies this "
       "same registered type (see the control in Tier2WaitForResolutionFalseDeliversPlaceholderUnreified)";
  EXPECT_NE(value.try_as<UnknownStructure>(), nullptr) << "the value must still be delivered losslessly";
}

// Row: resolutionTimeout - the deadline settles every waiter on the encoding Bad_Timeout rather than
// letting a slow discovery park the caller.
//
// The server is made to hold the discovery Browse well past the deadline, so the resolution is provably
// still in flight when the budget elapses. Against an unmodified loopback server the whole discovery
// (Browse HasEncoding plus the follow-on Read) completes in about a millisecond, which RACES the smallest
// enabled budget the policy can express - `resolutionTimeout` is a `std::chrono::milliseconds`, so 1 ms is
// its floor - and the round trip wins often enough to fail this row in CI. Delaying the response removes
// the race without weakening the oracle: the 1 ms budget is still the only thing that can settle the
// waiter, and the settle semantics themselves are pinned deterministically by the unit row
// TypeResolver.ResolutionDeadlineSettlesParkedWaitersBadTimeout.
TEST_F(ClientTypeResolver, ResolutionTimeoutSettlesWaitersBadTimeout)
{
  MisbehavingServer server;
  ua::client::detail::ConnectionConfig config;
  config.typeResolution.resolutionTimeout = 1ms;  // default 10 s
  MisbehavingResolverFixture fixture{server, config};
  ASSERT_TRUE(fixture.start_status().is_good()) << "bootstrap must succeed against the un-mutated server: "
                                                << to_string(fixture.start_status().status_code());

  auto resolver = fixture.conn().impl().type_resolver();
  ASSERT_NE(resolver, nullptr);
  ASSERT_EQ(resolver->policy().resolutionTimeout, 1ms)
    << "the ConnectionConfig deadline must reach the Connection's own resolver";

  // Armed after bootstrap so only the resolver's own discovery Browse is held back. The mutator runs on the
  // channel strand, so sleeping in it delays the response the client is waiting on.
  auto browseDelivered = std::make_shared<std::atomic<bool>>(false);
  server.set_response_mutator(
    [browseDelivered](Response& response)
    {
      if (dynamic_cast<BrowseResponse*>(response.second.get()) == nullptr)
        return;
      std::this_thread::sleep_for(resolveBrowseHold);
      browseDelivered->store(true);
    });

  const auto outcome = resolve_sync(*resolver, synthetic_encoding_id());
  ASSERT_TRUE(outcome.is_bad()) << "the deadline must fail the waiter, not leave it parked";
  EXPECT_EQ(outcome.status_code().as_status(), Status::BadTimeout)
    << "an elapsed resolutionTimeout settles waiters Bad_Timeout, whatever the held Browse goes on to say";
  ASSERT_NE(outcome.shared_detail(), nullptr) << "the timeout must carry an ErrorDetail";
  EXPECT_EQ(outcome.shared_detail()->code, "TypeResolutionTimedOut");

  // The held Browse response is still owed to a live Connection. It is collected here rather than left to
  // land during teardown, so the late completion is delivered to the object graph the resolver expects and
  // this row cannot leave a torn-down Connection racing a server thread behind it.
  const auto giveUpAt = std::chrono::steady_clock::now() + 10s;
  while (!browseDelivered->load() && std::chrono::steady_clock::now() < giveUpAt)
    std::this_thread::sleep_for(5ms);
  EXPECT_TRUE(browseDelivered->load()) << "the held Browse response must have been emitted";
  std::this_thread::sleep_for(resolveBrowseHold);  // and processed by the client before teardown
}

// Row: ConnectionConfig::typeResolution - the PUBLIC per-Connection policy reaches the engine. The three
// rows above set the INTERNAL detail::ConnectionConfig, which proves the resolver honours a policy but not
// that a user-supplied one ever arrives: that hop is the connect-plan copy, whose only other coverage
// asserts the struct was copied. This row connects through `Client::connect_sync` with a public
// ConnectionConfig, so the public field, the connect-plan forward and the resolver all sit under one
// oracle. `tier2WaitForResolution` is the lever because its effect is visible in the value a peer read
// returns; any policy field would do.
TEST_F(ClientTypeResolver, PublicConnectionConfigCarriesTypeResolutionPolicy)
{
  // Control FIRST, so the ordering cannot be read as the non-waiting connection warming a shared registry:
  // the registry is per-Connection, and this control resolves the type before the subject connects at all.
  ua::client::ConnectionConfig waiting;
  waiting.endpointUrl = mEndpointUrl;
  ASSERT_TRUE(waiting.typeResolution.tier2WaitForResolution) << "the control must run the default";

  auto control = mClient->connect_sync(waiting);
  auto controlRead = control.typed().try_read_values_sync(std::vector<NodeId>{mStructValueVariableId});
  ASSERT_TRUE(controlRead.is_good()) << to_string(controlRead.status_code());
  ASSERT_EQ(controlRead.value().size(), 1u);
  const Variant& controlValue = controlRead.value()[0].value();
  ASSERT_TRUE(controlValue.is_structure());
  EXPECT_EQ(controlValue.try_as<UnknownStructure>(), nullptr)
    << "under the default the tier-2 read waits for wire resolution and reifies the server-discovered "
       "structure, so nothing opaque reaches the caller";
  control.close_sync();

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.typeResolution.tier2WaitForResolution = false;  // default true

  auto connection = mClient->connect_sync(config);
  auto result = connection.typed().try_read_values_sync(std::vector<NodeId>{mStructValueVariableId});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 1u);

  const Variant& value = result.value()[0].value();
  ASSERT_TRUE(value.is_structure());
  EXPECT_NE(value.try_as<UnknownStructure>(), nullptr)
    << "a public ConnectionConfig policy that never reaches the resolver leaves the default in force, and "
       "this read would reify exactly like the control above";
  connection.close_sync();
}

// ---------------------------------------------------------------------------------------------
// Wave B of the configuration coverage matrix (section 5): ConnectionConfig::typeObserver.
//
// Housed here rather than in configuration_observer_matrix_tests.cpp because the trigger needs a server
// carrying a custom structure - this fixture already has one, and the resolution path is the same one
// PublicConnectionConfigCarriesTypeResolutionPolicy exercises.
// ---------------------------------------------------------------------------------------------

// Records every type registration the resolver announces.
class RecordingTypeObserver : public ua::client::TypeObserver
{
public:
  void on_type_registered(NodeId encodingId, std::string typeName) override
  {
    std::lock_guard lock(mMutex);
    mRegistered.emplace_back(std::move(encodingId), std::move(typeName));
  }

  std::size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mRegistered.size();
  }

  bool saw(const NodeId& encodingId) const
  {
    std::lock_guard lock(mMutex);
    return std::any_of(
      mRegistered.begin(), mRegistered.end(), [&](const auto& entry) { return entry.first == encodingId; });
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<NodeId, std::string>> mRegistered;
};

// Row: ConnectionConfig::typeObserver - a populated slot OVERRIDES the Client-level default.
//
// Trigger: a typed read of the custom-structure node, which resolves the encoding over the wire and
// announces the registration. Both halves are required: the client-level observer recording NOTHING is
// what distinguishes "the slot was used" from "both were notified", and a leak to a client-wide observer
// is precisely how one Connection's type events reach a handler that did not ask for them.
TEST_F(ClientTypeResolver, TypeObserverSlotOverridesTheClientDefault)
{
  auto clientDefault = std::make_shared<RecordingTypeObserver>();
  auto perConnection = std::make_shared<RecordingTypeObserver>();
  mClient->set_type_observer(clientDefault);

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.typeObserver = perConnection;  // default is null (the client-level observer applies)

  auto connection = mClient->connect_sync(config);
  auto result = connection.typed().try_read_values_sync(std::vector<NodeId>{mStructValueVariableId});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  // The read returning Good and the observer having been told are two different instants: the
  // registration is announced on the client's executor after the resolution completes. Same reason
  // the eager-resolution helper below polls - a fixed point in time is a flake, and this one flaked
  // in CI. Bounded, so the assertion still has to hold: an observer never told still fails.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (std::chrono::steady_clock::now() < deadline && !perConnection->saw(mStructWithDefEncodingId))
    std::this_thread::sleep_for(std::chrono::milliseconds{20});

  EXPECT_TRUE(perConnection->saw(mStructWithDefEncodingId))
    << "the per-connection slot must be told about the type this Connection resolved";
  EXPECT_EQ(clientDefault->count(), 0u)
    << "a populated slot OVERRIDES the client-level default; a client-level observer that also fired "
       "would mean this Connection's type events reach a handler that did not ask for them";
  connection.close_sync();
}

// Control: with the slot left null the client-level default IS the one that fires. Without this half, an
// implementation that never notified the client-level observer at all would satisfy the row above while
// making the override rule vacuous.
TEST_F(ClientTypeResolver, ClientDefaultTypeObserverAppliesWhenTheSlotIsNull)
{
  auto clientDefault = std::make_shared<RecordingTypeObserver>();
  mClient->set_type_observer(clientDefault);

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  ASSERT_EQ(config.typeObserver, nullptr) << "this control must run the default slot";

  auto connection = mClient->connect_sync(config);
  auto result = connection.typed().try_read_values_sync(std::vector<NodeId>{mStructValueVariableId});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  // The read returning Good and the observer having been told are two different instants: the
  // registration is announced on the client's executor after the resolution completes. Same reason
  // the eager-resolution helper below polls - a fixed point in time is a flake, and this one flaked
  // in CI. Bounded, so the assertion still has to hold: an observer never told still fails.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (std::chrono::steady_clock::now() < deadline && !clientDefault->saw(mStructWithDefEncodingId))
    std::this_thread::sleep_for(std::chrono::milliseconds{20});

  EXPECT_TRUE(clientDefault->saw(mStructWithDefEncodingId))
    << "with the slot null the client-level default must receive the registration";
  connection.close_sync();
}

// ===========================================================================
// Row: TypeResolutionPolicy::eagerTypes (configuration coverage matrix section 10).
//
// Declared types are resolved DURING CONNECT rather than at first use. The oracle is the typeObserver -
// which only became usable when D7 was fixed earlier in this campaign, since `fire_type_registered` had no
// production caller and the slot could never fire at all.
//
// The row asserts the registration has happened BEFORE any value of that type is read. That ordering is
// the entire content of the field: a lazy client reaches the same end state, just later, so an oracle that
// only checked "the type is known" would pass either way.
// ===========================================================================
class ConfigurationEagerTypes : public ClientTypeResolver
{
protected:
  // Connect with @p eager declared, and report whether the custom type was registered by the time connect
  // returned - i.e. WITHOUT anything of that type having been read.
  bool registered_at_connect(std::vector<ua::NodeId> eager)
  {
    auto observer = std::make_shared<RecordingTypeObserver>();

    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.typeObserver = observer;
    // The MODE is held at EagerThenLazy in BOTH halves. `eagerTypes` is inert on its own - the connect-time
    // scan runs only for Eager / EagerThenLazy (`ua_type_resolver.cpp:867`) - so varying the mode would
    // test the mode instead. Holding it constant leaves the declared set as the only variable.
    config.typeResolution.mode = ua::client::TypeResolutionMode::EagerThenLazy;
    config.typeResolution.eagerTypes = std::move(eager);
    config.reconnect = std::nullopt;

    auto connection = mClient->try_connect_sync(std::move(config));
    EXPECT_TRUE(connection.is_good()) << to_string(connection.status_code());
    if (connection.is_bad())
      return false;
    auto live = std::move(connection).value();

    // Eager resolution is dispatched during connect but completes asynchronously, so poll briefly rather
    // than sleeping a fixed amount. No read of the type is issued in this window - that is the point.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline && !observer->saw(mStructWithDefEncodingId))
      std::this_thread::sleep_for(std::chrono::milliseconds{20});

    const bool registered = observer->saw(mStructWithDefEncodingId);
    (void)std::move(live).try_close_sync();
    return registered;
  }
};

// DEFAULT (empty eagerTypes): nothing is resolved at connect and the same probe reports false, because
// resolution waits for the first value of that type to arrive.
TEST_F(ConfigurationEagerTypes, DeclaredTypeIsResolvedDuringConnect)
{
  EXPECT_TRUE(registered_at_connect({mStructWithDefEncodingId}))
    << "a declared eager type must be resolved during connect, before anything of that type is read";

  EXPECT_FALSE(registered_at_connect({}))
    << "with eagerTypes empty the same type must NOT be resolved at connect - without this half the row "
       "would pass against a client that eagerly resolved everything it could find";
}

// ===========================================================================
// Row: TypeResolutionPolicy::eagerScanBudget.
//
// Bounds how many of the declared eager types the connect-time scan actually resolves; the remainder fall
// back to lazy resolution. The fixture declares TWO encodings of the same DataType, so a budget of 1 must
// resolve exactly one at connect and leave the other for first use.
//
// The sibling is pinned: `eagerTypes` is identical in both halves, so only the budget varies. Without that,
// a shorter declared list would produce the same observation and the row would prove nothing.
// ===========================================================================
class ConfigurationEagerScanBudget : public ClientTypeResolver
{
protected:
  // How many of the two declared encodings were registered by the time connect settled.
  size_t registered_at_connect(std::size_t budget)
  {
    auto observer = std::make_shared<RecordingTypeObserver>();

    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.typeObserver = observer;
    config.typeResolution.mode = ua::client::TypeResolutionMode::EagerThenLazy;
    config.typeResolution.eagerTypes = {mStructWithDefEncodingId, mStructSecondEncodingId};
    config.typeResolution.eagerScanBudget = budget;
    config.reconnect = std::nullopt;

    auto connection = mClient->try_connect_sync(std::move(config));
    EXPECT_TRUE(connection.is_good()) << to_string(connection.status_code());
    if (connection.is_bad())
      return 0;
    auto live = std::move(connection).value();

    // Settle: wait until the count stops changing rather than for a target, so an OVER-resolving client is
    // observed rather than waited past.
    size_t previous = 0;
    for (int quiet = 0; quiet < 10; ++quiet)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{100});
      const size_t now = observer->count();
      if (now != previous)
      {
        previous = now;
        quiet = 0;
      }
    }

    const size_t count = observer->count();
    (void)std::move(live).try_close_sync();
    return count;
  }
};

// DEFAULT (large): both declared encodings are resolved at connect, so this same probe reports 2.
TEST_F(ConfigurationEagerScanBudget, ScanStopsAtTheConfiguredBudget)
{
  EXPECT_EQ(registered_at_connect(1), 1u)
    << "a budget of 1 must resolve exactly one of the two declared eager types at connect";

  EXPECT_EQ(registered_at_connect(8), 2u)
    << "with a budget above the declared count both are resolved - without this half the row would pass "
       "against a client that only ever resolved one type, budget or no budget";
}

// TypeDeferPolicy::advisoryDedupCap is NOT covered here. The advisory it dedups is emitted only on the
// MonitoredItem delivery path (`ua_connection_impl.cpp:7528`) - a plain read of an opaque value produces
// none - and proving EVICTION needs the same DataType observed again after another displaced it. Monitoring
// two opaque types produces one advisory each (verified), but a server-side write to the first never drove
// a second delivery within 6 s, so the third observation the row needs was never obtained. See the matrix.
