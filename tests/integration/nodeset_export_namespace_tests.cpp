// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration test for the AddressSpaceFileType.ExportNamespace() method, wired via
/// ua::make_export_namespace_handler. A client invokes ExportNamespace over the wire; the server-side
/// handler serialises the target namespace and hands the bytes to a content sink. The test asserts the
/// method dispatches end-to-end and that the produced bytes re-parse as a valid NodeSet2 carrying the
/// expected node.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_address_space_file.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_encoding_limits.h"
#include "ua_instantiation_options.h"
#include "ua_memory_stream.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_nodeset_document.h"
#include "ua_nodeset_export.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_server.h"
#include "ua_session_method_services.h"
#include "ua_variant.h"

#include <memory>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// Hosts an AddressSpaceFileType instance whose ExportNamespace() handler serialises the fixture's test
// namespace into a captured byte buffer.
class ExportNamespaceMethodTest : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();
    mDevice = std::make_shared<memory_stream_device::Dynamic>();
    mStream = std::make_shared<MemoryStream<memory_stream_device::Dynamic>>(*mDevice);

    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
    // ExportNamespace is an optional component of AddressSpaceFileType; instantiate the optionals so
    // the method node exists to invoke.
    options.optionalChildFilter = [](const ChildFilterInfo&)
    {
      return true;
    };

    auto createResult = AddressSpaceFile::try_create_sync(
      addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "NsExportFile"}, options);
    ASSERT_TRUE(createResult.is_good()) << "0x" << std::hex << createResult.status_code().as_uint32();
    auto file = std::move(createResult).value();

    mFileObjectId = file.node_id();
    auto method = file.try_export_namespace_method_sync();
    ASSERT_TRUE(method.is_good()) << "0x" << std::hex << method.status_code().as_uint32();
    mExportMethodId = method.value().get_node_id();

    NodeSetExportOptions exportOptions;
    exportOptions.namespaces = {mTestNamespaceIndex};
    auto stream = mStream;
    auto handler = make_export_namespace_handler(addressSpace,
      std::move(exportOptions),
      [stream](shared_ptr<const MethodCallContext>)
      { return Result<shared_ptr<Stream>>{shared_ptr<Stream>{stream}}; });
    ASSERT_TRUE(file.try_set_export_namespace_handler_sync(std::move(handler)).is_good());

    // Detach RAII ownership so the node lives for the server's lifetime.
    file.release();
  }

  std::shared_ptr<memory_stream_device::Dynamic> mDevice;
  std::shared_ptr<MemoryStream<memory_stream_device::Dynamic>> mStream;
  NodeId mFileObjectId;
  NodeId mExportMethodId;
};

// A client Call of ExportNamespace runs the handler end-to-end; the produced bytes re-parse as a valid
// NodeSet2 declaring the test namespace and containing the fixture's WritableInt32 variable.
TEST_F(ExportNamespaceMethodTest, ClientCallExportsValidNodeSet)
{
  auto response = mSession->methods().call_sync(CallRequestBuilder().call(mFileObjectId, mExportMethodId));
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_THAT(response.results()[0].status_code(), Good());

  const auto data = mDevice->get_data();
  ASSERT_FALSE(data.empty());
  memory_stream_device::ExternalReadOnly readDevice{data};
  MemoryStream readStream(readDevice);
  auto parsed = try_parse_nodeset_sync(readStream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << "0x" << std::hex << parsed.status_code().as_uint32();

  // The test namespace is declared; resolve its file-local index, then find the fixture variable.
  uint16_t fileIndex = 0;
  for (const auto& mapping : parsed.value()->declared_namespaces())
  {
    if (mapping.uri == "urn:test:compliance")
    {
      fileIndex = mapping.serverIndex;
    }
  }
  ASSERT_NE(fileIndex, 0) << "exported document did not declare the test namespace";

  auto variable = parsed.value()->find(NodeId{fileIndex, uint32_t{1000}});  // WritableInt32
  ASSERT_TRUE(variable.has_value());
  EXPECT_EQ(variable->node_class(), NodeClass::Variable);
}
