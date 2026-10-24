// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <future>
#include <string>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_localized_text.h"
#include "ua_memory_stream.h"
#include "ua_nodeset_import.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_nodeset_export.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"

using namespace ua;

namespace
{

constexpr auto npos = std::string::npos;

NamespaceFactory make_factory(boost::asio::thread_pool& pool)
{
  return [executor = pool.get_executor()](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

std::string as_string(const std::vector<byte>& bytes)
{
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // namespace

// The async-canonical entry point runs on the address space executor and completes with the document
// bytes plus a summary reporting the namespaces written and the node count.
TEST(NodeSetExportApiTest, ExportAsyncProducesDocumentAndSummary)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());  // ns1 == "urn:test"
  auto object = addressSpace.try_create_node_sync(NodeId{1, "Obj"}, NodeClass::Object, {});
  ASSERT_TRUE(object.is_good());
  object.value().set_browse_name(QualifiedName{1, "Obj"});

  NodeSetExportOptions options;
  options.namespaces = {1};

  auto promise = std::make_shared<std::promise<Result<NodeSetExportResult>>>();
  auto future = promise->get_future();
  export_nodeset_async(addressSpace,
    std::move(options),
    [promise](Result<NodeSetExportResult> result) { promise->set_value(std::move(result)); });

  // Block only on the main test thread (never on a pool thread).
  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const auto& [bytes, summary] = result.value();
  EXPECT_EQ(summary.nodesExported, 1u);
  ASSERT_EQ(summary.namespacesWritten.size(), 1u);
  EXPECT_EQ(summary.namespacesWritten.front().uri, "urn:test");
  EXPECT_EQ(summary.namespacesWritten.front().serverIndex, 1);
  EXPECT_NE(as_string(bytes).find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << as_string(bytes);

  ::ua::test_utils::drain_with_timeout(tp);
}

// The canonical async form serialises directly into a caller-owned (shared_ptr) Stream and reports
// only the summary - no document buffer is returned.
TEST(NodeSetExportApiTest, AsyncStreamFormWritesDirectlyToStream)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto object = addressSpace.try_create_node_sync(NodeId{1, "Obj"}, NodeClass::Object, {});
  ASSERT_TRUE(object.is_good());
  object.value().set_browse_name(QualifiedName{1, "Obj"});

  NodeSetExportOptions options;
  options.namespaces = {1};

  auto device = std::make_shared<memory_stream_device::Dynamic>();
  auto out = std::make_shared<MemoryStream<memory_stream_device::Dynamic>>(*device);

  auto promise = std::make_shared<std::promise<Result<NodeSetExportSummary>>>();
  auto future = promise->get_future();
  export_nodeset_async(addressSpace,
    out,
    std::move(options),
    [promise](Result<NodeSetExportSummary> result) { promise->set_value(std::move(result)); });

  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(result.value().nodesExported, 1u);

  const auto data = device->get_data();
  const std::string xml(reinterpret_cast<const char*>(data.data()), data.size());
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// The sync stream form writes the document to a caller-provided stream and returns the summary.
TEST(NodeSetExportApiTest, SyncStreamFormWritesDocument)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto object = addressSpace.try_create_node_sync(NodeId{1, "Obj"}, NodeClass::Object, {});
  ASSERT_TRUE(object.is_good());
  object.value().set_browse_name(QualifiedName{1, "Obj"});

  NodeSetExportOptions options;
  options.namespaces = {1};

  memory_stream_device::Dynamic device;
  MemoryStream stream(device);
  auto summary = try_export_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(summary.is_good()) << summary.status_code().value();
  EXPECT_EQ(summary.value().nodesExported, 1u);

  const auto data = device.get_data();
  const std::string xml(reinterpret_cast<const char*>(data.data()), data.size());
  EXPECT_NE(xml.find("<UANodeSet"), npos) << xml;
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// The public node_filter is honoured through the facade: only the accepted node is exported.
TEST(NodeSetExportApiTest, NodeFilterThreadsThrough)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto keep = addressSpace.try_create_node_sync(NodeId{1, 10u}, NodeClass::Object, {});
  ASSERT_TRUE(keep.is_good());
  keep.value().set_browse_name(QualifiedName{1, "Keep"});
  auto drop = addressSpace.try_create_node_sync(NodeId{1, 20u}, NodeClass::Object, {});
  ASSERT_TRUE(drop.is_good());
  drop.value().set_browse_name(QualifiedName{1, "Drop"});

  NodeSetExportOptions options;
  options.namespaces = {1};
  options.nodeFilter = [](const ExportNodeView& node)
  {
    return node.nodeId.identifier().get_numeric() == 10u;
  };

  auto result = try_export_nodeset_sync(addressSpace, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(result.value().second.nodesExported, 1u);
  const std::string xml = as_string(result.value().first);
  EXPECT_NE(xml.find("NodeId=\"ns=1;i=10\""), npos) << xml;
  EXPECT_EQ(xml.find("NodeId=\"ns=1;i=20\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// A NodeId value embedded in a `<Value>` whose namespace is NOT otherwise referenced by the node
// must still be collected into `<NamespaceUris>` and translated to its file index - never collapsed
// to NS0. (Regression for the embedded-namespace-collection gap.)
TEST(NodeSetExportApiTest, CrossNamespaceEmbeddedValueNamespaceIsCollected)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());  // ns1 = urn:test
  auto second = default_ns::Namespace::create("urn:second", tp.get_executor());
  const auto secondIndex = addressSpace.add_namespace_sync(second);
  ASSERT_EQ(secondIndex, 2);

  auto variable = addressSpace.try_create_node_sync(NodeId{1, "Var"}, NodeClass::Variable, {});
  ASSERT_TRUE(variable.is_good());
  variable.value().set_browse_name(QualifiedName{1, "Var"});
  auto variableAccessor = addressSpace.try_find_sync<VariableAccessor>(NodeId{1, "Var"});
  ASSERT_TRUE(variableAccessor.is_good());
  // Value embeds a NodeId in ns2 - a namespace the ns1 node references nowhere else.
  ASSERT_TRUE(
    variableAccessor.value().try_write_value_sync(DataValue{Variant{NodeId{secondIndex, 9001u}}}).is_good());

  NodeSetExportOptions options;
  options.namespaces = {1};  // export only ns1
  auto result = try_export_nodeset_sync(addressSpace, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const auto& [bytes, summary] = result.value();
  const std::string xml = as_string(bytes);

  // ns2 was collected from the embedded value: it appears in the table (file index 2) and the embedded
  // id carries that file index rather than collapsing to NS0.
  EXPECT_EQ(summary.namespacesWritten.size(), 2u) << xml;
  EXPECT_NE(xml.find("<Uri>urn:second</Uri>"), npos) << xml;
  EXPECT_NE(xml.find("ns=2;i=9001"), npos) << xml;
  EXPECT_EQ(xml.find("<Identifier>i=9001</Identifier>"), npos) << xml;  // the corrupt NS0 form

  ::ua::test_utils::drain_with_timeout(tp);
}

// A structure_resolver reifies an opaque BINARY-bodied ExtensionObject value to a typed Structure so
// it serialises as XML rather than failing/omitting.
TEST(NodeSetExportApiTest, StructureResolverReifiesOpaqueBinaryValue)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto variable = addressSpace.try_create_node_sync(NodeId{1, "Var"}, NodeClass::Variable, {});
  ASSERT_TRUE(variable.is_good());
  variable.value().set_browse_name(QualifiedName{1, "Var"});
  auto variableAccessor = addressSpace.try_find_sync<VariableAccessor>(NodeId{1, "Var"});
  ASSERT_TRUE(variableAccessor.is_good());

  // Build an opaque binary-bodied value: binary-encode an Argument's fields, then wrap them as an
  // UnknownStructure. DataType is an NS0 id so embedded-id translation is identity (sound).
  Argument argument;
  argument.name() = String{"ReifiedArg"};
  argument.data_type() = NodeId{6u};  // Int32 (NS0)
  argument.value_rank() = -1;
  memory_stream_device::Dynamic device;
  MemoryStream stream(device);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  encoder.encode(EncodingLimits{}.stack_depth(), static_cast<const Structure&>(argument));
  const auto body = device.get_data();
  auto opaque = make_unique<UnknownStructure>(
    NodeId{Argument::defaultBinaryEncodingId}, UnknownStructure::BodyEncoding::Binary, ByteString{body});
  ASSERT_TRUE(variableAccessor.value().try_write_value_sync(DataValue{Variant{std::move(opaque)}}).is_good());

  NodeSetExportOptions options;
  options.namespaces = {1};
  options.structureResolver = [](const NodeId& encodingId) -> unique_ptr<Structure>
  {
    if (encodingId == NodeId{Argument::defaultBinaryEncodingId})
    {
      return make_unique<Argument>();
    }
    return nullptr;
  };

  auto result = try_export_nodeset_sync(addressSpace, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const std::string xml = as_string(result.value().first);
  // The opaque body was reified to a typed Argument and serialised - its Name field appears.
  EXPECT_NE(xml.find("ReifiedArg"), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// A bad export status threads out through the buffer-returning sync facade.
TEST(NodeSetExportApiTest, UnknownNamespacePropagatesThroughFacade)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  NodeSetExportOptions options;
  options.namespaces = {99};  // unknown
  auto result = try_export_nodeset_sync(addressSpace, options);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// The throwing sync stream form throws on the same failure the try_* form reports.
TEST(NodeSetExportApiTest, ExportSyncThrowsOnError)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  NodeSetExportOptions options;
  options.namespaces = {99};
  memory_stream_device::Dynamic device;
  MemoryStream stream(device);
  EXPECT_THROW(export_nodeset_sync(addressSpace, stream, options), UaException);
  ::ua::test_utils::drain_with_timeout(tp);
}

/// Calls an ExportNamespace handler as the method adapter does, with no session, and returns how it
/// completes.
VoidResult call_export(const AddressSpaceFile::ExportNamespaceAsyncHandler& handler)
{
  std::promise<StatusCode> done;
  auto future = done.get_future();
  handler(MethodCall{NodeId{}, NodeId{}, nullptr},
    detail::MethodResultCallbackFactory::make<>(
      [&done](MethodResult<> result) { done.set_value(result.status_code()); }, Logger{}, NodeId{}));
  const StatusCode status = future.get();
  if (status.is_good())
  {
    return VoidResult{};
  }
  return VoidResult{status};
}

// The ExportNamespace handler reports BadInvalidArgument when built without a stream provider.
TEST(NodeSetExportApiTest, ExportNamespaceHandlerWithoutProviderFails)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  NodeSetExportOptions options;
  options.namespaces = {1};
  auto handler = make_export_namespace_handler(addressSpace, options, /*openOutput=*/{});

  const VoidResult outcome = call_export(handler);
  EXPECT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code().as_status(), Status::BadInvalidArgument);
  ::ua::test_utils::drain_with_timeout(tp);
}

// An export failure (here an unknown target namespace) surfaces through the handler's completion even
// when the stream opened fine.
TEST(NodeSetExportApiTest, ExportNamespaceHandlerSurfacesExportFailure)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto device = std::make_shared<memory_stream_device::Dynamic>();
  auto out = std::make_shared<MemoryStream<memory_stream_device::Dynamic>>(*device);

  NodeSetExportOptions options;
  options.namespaces = {99};  // unknown namespace -> export fails
  auto handler = make_export_namespace_handler(addressSpace,
    options,
    [out](shared_ptr<const MethodCallContext>)
    { return Result<shared_ptr<Stream>>{shared_ptr<Stream>{out}}; });

  const VoidResult outcome = call_export(handler);
  EXPECT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code().as_status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ExportNamespace handler does not write into a stream its provider answered Uncertain: the call is
// refused with Bad_InternalError (AnswerUncertain), the provider's code as the cause, and a Bad answer
// still fails the call with its own code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(NodeSetExportApiTest, ExportNamespaceHandlerRefusesAnUncertainStreamAnswer)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  NodeSetExportOptions options;
  options.namespaces = {1};

  auto uncertain = make_export_namespace_handler(addressSpace,
    options,
    [](shared_ptr<const MethodCallContext>)
    { return Result<shared_ptr<Stream>>{StatusCode{Status::UncertainLastUsableValue}}; });
  const VoidResult refused = call_export(uncertain);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError);
  const auto detail = refused.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "AnswerUncertain");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());

  // Control: a Bad answer fails the call with the provider's own code.
  auto bad = make_export_namespace_handler(addressSpace,
    options,
    [](shared_ptr<const MethodCallContext>)
    { return Result<shared_ptr<Stream>>{StatusCode{Status::BadNotWritable}}; });
  EXPECT_EQ(call_export(bad).status_code().as_status(), Status::BadNotWritable);
  ::ua::test_utils::drain_with_timeout(tp);
}

// LastModified set on export is written as the `<UANodeSet>` attribute and read back by the parser
// (which previously looked for a non-existent child element - a bug this exercises end-to-end).
TEST(NodeSetExportApiTest, LastModifiedRoundTripsThroughParser)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto object = addressSpace.try_create_node_sync(NodeId{1, "Obj"}, NodeClass::Object, {});
  ASSERT_TRUE(object.is_good());
  object.value().set_browse_name(QualifiedName{1, "Obj"});

  const DateTime lastModified{2024, 6, 1, 12, 30, 0, 0};
  NodeSetExportOptions options;
  options.namespaces = {1};
  options.lastModified = lastModified;

  auto exported = try_export_nodeset_sync(addressSpace, options);
  ASSERT_TRUE(exported.is_good()) << exported.status_code().value();
  const auto& bytes = exported.value().first;

  memory_stream_device::ExternalReadOnly device{span<const byte>{bytes.data(), bytes.size()}};
  MemoryStream parseStream(device);
  auto parsed = try_parse_nodeset_sync(parseStream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << parsed.status_code().value();
  EXPECT_EQ(parsed.value()->last_modified(), lastModified);

  ::ua::test_utils::drain_with_timeout(tp);
}

// The ExportNamespace() method handler factory: invoking the produced handler serialises the
// configured namespaces directly into the provider's stream, then reports success.
TEST(NodeSetExportApiTest, ExportNamespaceHandlerSerialisesToStream)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto object = addressSpace.try_create_node_sync(NodeId{1, "Obj"}, NodeClass::Object, {});
  ASSERT_TRUE(object.is_good());
  object.value().set_browse_name(QualifiedName{1, "Obj"});

  NodeSetExportOptions options;
  options.namespaces = {1};

  auto device = std::make_shared<memory_stream_device::Dynamic>();
  auto out = std::make_shared<MemoryStream<memory_stream_device::Dynamic>>(*device);
  auto handler = make_export_namespace_handler(addressSpace,
    options,
    [out](shared_ptr<const MethodCallContext>)
    { return Result<shared_ptr<Stream>>{shared_ptr<Stream>{out}}; });

  // The method takes no input args and ignores the call context; call it with no session.
  const VoidResult outcome = call_export(handler);
  ASSERT_TRUE(outcome.is_good()) << outcome.status_code().value();
  const auto data = device->get_data();
  const std::string xml(reinterpret_cast<const char*>(data.data()), data.size());
  EXPECT_NE(xml.find("<UANodeSet"), npos) << xml;
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// THE payoff: import a known NodeSet2 fixture, export it, re-import the exported bytes into a fresh
// address space, and assert the node graph is equivalent - including cross-namespace NodeId values
// embedded in `<Value>` (which exercises the full server->file->server index translation).
TEST(NodeSetExportApiTest, RoundTripMultiNamespaceFixture)
{
  boost::asio::thread_pool tp{1};

  // --- import the fixture into AS1 ---
  auto sourceSpace = AddressSpace::create("", tp.get_executor());
  FileStream in{"MultiNamespaceFixture.NodeSet2.xml"};
  in.open_for_read();
  NodeSetImportOptions importOptions;
  importOptions.namespaceFactory = make_factory(tp);
  auto imported = try_import_nodeset_sync(sourceSpace, in, importOptions);
  ASSERT_TRUE(imported.is_good()) << imported.status_code().value();

  const auto customNs1 = sourceSpace.namespace_array().get_namespace_index("urn:example:custom");
  const auto otherNs1 = sourceSpace.namespace_array().get_namespace_index("urn:example:other");
  ASSERT_NE(customNs1, 0);
  ASSERT_NE(otherNs1, 0);

  // --- export both fixture namespaces from AS1 ---
  NodeSetExportOptions exportOptions;
  exportOptions.namespaces = {customNs1, otherNs1};
  auto exported = try_export_nodeset_sync(sourceSpace, exportOptions);
  ASSERT_TRUE(exported.is_good()) << exported.status_code().value();
  const auto& bytes = exported.value().first;
  EXPECT_EQ(exported.value().second.nodesExported, 5u);

  // --- re-import the exported bytes into a fresh AS2 ---
  auto roundTripSpace = AddressSpace::create("", tp.get_executor());
  memory_stream_device::ExternalReadOnly device{span<const byte>{bytes.data(), bytes.size()}};
  MemoryStream reimportStream(device);
  NodeSetImportOptions reimportOptions;
  reimportOptions.namespaceFactory = make_factory(tp);
  auto reimported = try_import_nodeset_sync(roundTripSpace, reimportStream, reimportOptions);
  ASSERT_TRUE(reimported.is_good()) << reimported.status_code().value();
  EXPECT_EQ(reimported.value().nodesImported, 5u);

  const auto customNs2 = roundTripSpace.namespace_array().get_namespace_index("urn:example:custom");
  const auto otherNs2 = roundTripSpace.namespace_array().get_namespace_index("urn:example:other");
  ASSERT_NE(customNs2, 0);
  ASSERT_NE(otherNs2, 0);

  // The five fixture nodes survive with their identifiers and classes.
  EXPECT_TRUE(roundTripSpace.try_find_sync<NodeAccessor>(NodeId{customNs2, 6001u}).is_good());  // MyDataType
  EXPECT_TRUE(roundTripSpace.try_find_sync<NodeAccessor>(NodeId{customNs2, 5001u}).is_good());  // MyObject
  EXPECT_TRUE(roundTripSpace.try_find_sync<NodeAccessor>(NodeId{otherNs2, 7001u}).is_good());  // OtherObject
  auto myVar = roundTripSpace.try_find_sync<VariableAccessor>(NodeId{customNs2, 5002u});
  ASSERT_TRUE(myVar.is_good());
  auto otherVar = roundTripSpace.try_find_sync<VariableAccessor>(NodeId{otherNs2, 7002u});
  ASSERT_TRUE(otherVar.is_good());

  // The embedded NodeId values survived the round-trip with correct namespaces: MyVar's value points
  // at MyObject (custom ns), OtherVar's at OtherObject (other ns). This proves cross-namespace
  // embedded-id translation (server -> file on export, file -> server on re-import).
  auto myVarValue = myVar.value().try_read_value_sync();
  ASSERT_TRUE(myVarValue.is_good());
  ASSERT_TRUE(myVarValue.value().value().is_node_id());
  const NodeId& myVarTarget = myVarValue.value().value().as<NodeId>();
  EXPECT_EQ(myVarTarget.namespace_index(), customNs2);
  EXPECT_EQ(myVarTarget.identifier().get_numeric(), 5001u);

  auto otherVarValue = otherVar.value().try_read_value_sync();
  ASSERT_TRUE(otherVarValue.is_good());
  ASSERT_TRUE(otherVarValue.value().value().is_node_id());
  const NodeId& otherVarTarget = otherVarValue.value().value().as<NodeId>();
  EXPECT_EQ(otherVarTarget.namespace_index(), otherNs2);
  EXPECT_EQ(otherVarTarget.identifier().get_numeric(), 7001u);

  ::ua::test_utils::drain_with_timeout(tp);
}
