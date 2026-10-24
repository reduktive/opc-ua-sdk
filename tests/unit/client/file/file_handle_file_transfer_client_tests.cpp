// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::FileTransferClient + ua::client::FileHandle (client design section 8.10): the
// tier-2 File Transfer facade and its move-only, close-on-destruct file handle. Covers the FileType
// Method-Call composition (Open / Read / Write / GetPosition / SetPosition / Close), the caller-side
// pre-flight rejections (mode-without-Read/Write, write-on-read-only), the Read MaxByteStringLength cap, the
// RAII close-on-destruct exactly-once contract (incl. move + explicit-close-then-drop), the section 9.8.3
// cycle fix (weak-owner bail after the handle drops; the wire interface is not kept alive by a handle), and
// the read_all aggregate ceiling (section 9.6.23.2).
//
// Falsifiability: a facade that mis-composes the Open Call fails OpenComposes*; one that skips the length
// cap fails ReadCapsLength; one that leaks/duplicates the Close fails Drop*/Move*/ExplicitClose*; one that
// derefs a freed handle fails CompletionAfterHandleDroppedBails; one that keeps the interface alive fails
// WireOpsNotKeptAliveByHandle; one that reads unbounded fails ReadAllRespectsCeiling.

#include "ua_file_transfer_client.h"

#include "fake_connection_ops.h"

#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_browse_result.h"
#include "ua_byte_string.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_file_transfer_client_test_access.h"
#include "ua_objecttype_id.h"
#include "ua_reference_description.h"
#include "ua_read_response.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_variant.h"
#include "ua_variable_id.h"

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::ByteStringResult;
using ua::client::FileHandle;
using ua::client::FileHandleResult;
using ua::client::FileOpenMode;
using ua::client::FileSystemEntryKind;
using ua::client::FileTransferClient;
using ua::client::UInt64Result;
using ua::client::detail::FileTransferClientTestAccess;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{std::uint16_t{0}, identifier};
}

ua::ReferenceDescription directory_entry(
  std::uint32_t identifier, ua::ObjectTypeId typeDefinition, std::string_view browseName)
{
  ua::ReferenceDescription reference;
  reference.node_id() = ua::ExpandedNodeId{node(identifier)};
  reference.browse_name() = ua::QualifiedName{1, browseName};
  reference.type_definition() = ua::ExpandedNodeId{ua::NodeId{typeDefinition}};
  reference.node_class() = ua::NodeClass::Object;
  return reference;
}

ua::ReferenceDescription directory_method(std::string_view browseName)
{
  ua::ReferenceDescription reference;
  reference.node_id() = ua::ExpandedNodeId{node(8001)};
  reference.browse_name() = ua::QualifiedName{0, browseName};
  reference.node_class() = ua::NodeClass::Method;
  return reference;
}

// The resolved INSTANCE method node an op Calls (OPC 10000-4 section 5.11.2), never the abstract FileType id.
// These ids mirror FileTransferClientTestAccess::default_method_nodes so the make_handle per-op tests and the
// open-path tests (whose translateHandler resolves to the same ids) agree.
constexpr std::uint32_t openNode = 7001;
constexpr std::uint32_t readNode = 7002;
constexpr std::uint32_t writeNode = 7003;
constexpr std::uint32_t closeNode = 7004;
constexpr std::uint32_t getPositionNode = 7005;
constexpr std::uint32_t setPositionNode = 7006;
constexpr std::uint32_t userWritableNode = 7007;

ua::NodeId instance_node(std::uint32_t identifier)
{
  return ua::NodeId{identifier};
}

// A Good BrowsePathResult resolving to one local instance NodeId (the resolved shape a conformant server
// returns for a single-hop HasComponent method path).
ua::BrowsePathResult good_browse_target(std::uint32_t identifier)
{
  ua::BrowsePathResult result;
  result.status_code() = ua::StatusCode{ua::Status::Good};
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{identifier}};
  result.targets().push_back(std::move(target));
  return result;
}

// A well-formed 7-result TranslateBrowsePaths response resolving the six FileType method paths (Open, Read,
// Write, Close, GetPosition, SetPosition - in that order) and reporting the optional per-file cap absent.
// FakeWireOps::translateHandler so the open_async / read_all_async paths reach the Open Call.
ua::TranslateBrowsePathsToNodeIdsResponse resolve_all_methods(const ua::TranslateBrowsePathsToNodeIdsRequest&)
{
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  for (const std::uint32_t id : {openNode, readNode, writeNode, closeNode, getPositionNode, setPositionNode})
  {
    response.results().push_back(good_browse_target(id));
  }
  ua::BrowsePathResult absentCap;
  absentCap.status_code() = ua::StatusCode{ua::Status::BadNoMatch};
  response.results().push_back(std::move(absentCap));
  response.results().push_back(good_browse_target(userWritableNode));
  return response;
}

ua::Variant u32(std::uint32_t value)
{
  return ua::Variant{value};
}

ua::Variant u64(std::uint64_t value)
{
  return ua::Variant{value};
}

ua::Variant bytes(std::initializer_list<std::uint8_t> data)
{
  return ua::Variant{ua::ByteString{data}};
}

ua::Result<ua::ReadResponse> cap_read(std::uint32_t value)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{value}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

ua::Result<ua::ReadResponse> cap_and_writable_read(std::uint32_t cap, bool writable)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{cap}});
  response.results().push_back(ua::DataValue{ua::Variant{writable}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

ua::Result<ua::ReadResponse> absent_cap_read()
{
  ua::ReadResponse response;
  ua::DataValue value;
  value.status() = ua::StatusCode{ua::Status::BadNodeIdUnknown};
  response.results().push_back(std::move(value));
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

ua::Result<ua::ReadResponse> absent_cap_and_writable_read(bool writable)
{
  auto result = absent_cap_read();
  result.value().results().push_back(ua::DataValue{ua::Variant{writable}});
  return result;
}

ua::TranslateBrowsePathsToNodeIdsResponse resolve_with_file_cap(std::uint32_t propertyNode)
{
  auto response = resolve_all_methods({});
  response.results()[6] = good_browse_target(propertyNode);
  return response;
}

ua::TranslateBrowsePathsToNodeIdsResponse resolve_with_file_cap_and_user_writable(
  std::uint32_t capNode, std::uint32_t writableNode)
{
  auto response = resolve_with_file_cap(capNode);
  response.results()[7] = good_browse_target(writableNode);
  return response;
}

// ----- move-only compile guard (section 7.0 / section 8.10.1): a resource-releasing handle is move-only
// -----
static_assert(!std::is_copy_constructible_v<FileHandle>, "FileHandle must not be copy-constructible");
static_assert(!std::is_copy_assignable_v<FileHandle>, "FileHandle must not be copy-assignable");
static_assert(std::is_move_constructible_v<FileHandle>, "FileHandle must be move-constructible");
static_assert(std::is_move_assignable_v<FileHandle>, "FileHandle must be move-assignable");

constexpr std::uint32_t fileNode = 99;
constexpr std::uint32_t serverFileHandle = 42;

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();

  Fixture()
  {
    // By default the Open path resolves the six FileType instance method nodes (to the ids make_handle
    // injects), so open_async / read_all_async reach the Open Call. A test needing an UNRESOLVED open
    // overrides wireOps->translateHandler.
    wireOps->translateHandler = resolve_all_methods;
    wireOps->scriptedReadResponses.push_back(absent_cap_read());
  }

  FileTransferClient client()
  {
    return FileTransferClientTestAccess::make_client(wireOps, ctx.get_executor());
  }

  // Builds a live handle over the fake interface directly (bypasses Open), for the per-op composition tests.
  FileHandle handle(FileOpenMode mode, std::uint32_t cap = 0x10000,
    std::uint32_t serverHandle = serverFileHandle,
    std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration =
      std::make_shared<const std::atomic<std::uint64_t>>(0))
  {
    return FileTransferClientTestAccess::make_handle(wireOps,
      ctx.get_executor(),
      node(fileNode),
      serverHandle,
      mode,
      cap,
      {},
      FileTransferClientTestAccess::default_method_nodes(),
      std::move(sessionGeneration));
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }

  // Counts how many issued Calls targeted the instance method node @p methodNode.
  std::size_t call_count(const ua::NodeId& methodNode) const
  {
    std::size_t count = 0;
    for (const auto& request : wireOps->callRequests)
    {
      if (!request.methods_to_call().empty() && request.methods_to_call()[0].method_id() == methodNode)
      {
        ++count;
      }
    }
    return count;
  }
};

// ===========================================================================
// Open - composition + handle identity (CL-FILE-001 / CL-FILE-004)
// ===========================================================================

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenComposesMethodCallAndReturnsHandleCarryingServerFileHandle)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({7})}});  // follow-up Read

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  // The Open Call is composed with the right objectId + RESOLVED instance Open node + Byte(mode) input. The
  // resolve is a TranslateBrowsePaths (not a Call), so callRequests still holds only the Open Call at [0].
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);
  const auto& openMethod = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(openMethod.object_id(), node(fileNode));
  EXPECT_EQ(openMethod.method_id(), instance_node(openNode));
  ASSERT_EQ(openMethod.input_arguments().size(), 1U);
  EXPECT_EQ(openMethod.input_arguments()[0].to<std::uint8_t>().value(),
    static_cast<std::uint8_t>(FileOpenMode::Read));

  FileHandle handle = std::move(*captured).value();
  EXPECT_TRUE(handle.is_valid());
  EXPECT_EQ(handle.file_node(), node(fileNode));
  EXPECT_EQ(handle.mode(), FileOpenMode::Read);

  // The returned handle carries the SERVER fileHandle: a follow-up Read Call carries 42 as its input.
  handle.read_async(4, [](ByteStringResult) {});
  f.run();
  const auto& readMethod = f.wireOps->callRequests[1].methods_to_call()[0];
  EXPECT_EQ(readMethod.method_id(), instance_node(readNode));
  EXPECT_EQ(readMethod.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, ResolvesPerFileMaxByteStringLengthBeforeOpen)
{
  Fixture f;
  constexpr std::uint32_t fileCapNode = 7010;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap(fileCapNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(cap_read(512));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().max_byte_string_length(), 512U);
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(fileCapNode));
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, FallsBackToServerCapabilitiesMaxByteStringLength)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(cap_read(4096));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().max_byte_string_length(), 4096U);
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(),
    (ua::NodeId{ua::VariableId::Server_ServerCapabilities_MaxByteStringLength}));
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, MissingServerCapabilitiesPropertyUsesSafeDefault)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().max_byte_string_length(), 0x10000U);
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, PerFileCapReadFailurePropagatesRichError)
{
  Fixture f;
  constexpr std::uint32_t fileCapNode = 7010;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap(fileCapNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  auto cause = ua::make_error_detail("InjectedCapReadFailure", "injected cap read failure", "test.file");
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{ua::StatusCode{ua::Status::BadUserAccessDenied}, std::move(cause)});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileMaxByteStringLengthReadFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "InjectedCapReadFailure");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, MalformedPerFileCapFailsBeforeOpen)
{
  Fixture f;
  constexpr std::uint32_t fileCapNode = 7010;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap(fileCapNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{ua::String{"not-u32"}}});
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileMaxByteStringLengthDecode");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, ZeroPerFileCapFailsBeforeOpen)
{
  Fixture f;
  constexpr std::uint32_t fileCapNode = 7010;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap(fileCapNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(cap_read(0));

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadOutOfRange);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileMaxByteStringLengthZero");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientOpen, OpenRejectsModeWithoutReadOrWriteWithNoWireOp)
{
  Fixture f;
  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::EraseExisting,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidArgument);
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // rejected locally: no Open sent
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesServerPerCallStatusVerbatimAndConstructsNoHandle)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(absent_cap_and_writable_read(true));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::BadNotWritable}, {}});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Write | FileOpenMode::EraseExisting,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotWritable);
  // No FileHandle was constructed -> no Close is owed: only the Open Call was issued.
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 0U);
}

// @verifies CL-FILE-001
// OPC 10000-4 section 5.11.2: if the FileType Object's Open path does not resolve to an instance method node,
// the object is not a usable FileType - open fails Bad_MethodInvalid and issues NO Open Call (the pre-fix
// code would have Called the abstract FileType.Open, which a conformant server rejects).
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenFailsMethodInvalidWhenOpenMethodUnresolvedAndIssuesNoCall)
{
  Fixture f;
  // A well-formed 7-result response whose Open path did not match; the other methods resolve and the
  // optional MaxByteStringLength Property is absent.
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    ua::BrowsePathResult openResult;
    openResult.status_code() = ua::StatusCode{ua::Status::BadNoMatch};  // Open unresolved
    response.results().push_back(std::move(openResult));
    for (const std::uint32_t id : {readNode, writeNode, closeNode, getPositionNode, setPositionNode})
    {
      response.results().push_back(good_browse_target(id));
    }
    ua::BrowsePathResult capResult;
    capResult.status_code() = ua::StatusCode{ua::Status::BadNoMatch};
    response.results().push_back(std::move(capResult));
    response.results().push_back(good_browse_target(userWritableNode));
    return response;
  };

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadMethodInvalid);
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // resolution failed first -> no Open Call issued
}

// @verifies CL-FILE-001
// The instance-method resolve completes AFTER the Connection drops: open_async re-locks the wire interface in
// its post-resolve completion (seam2), and a gone Connection makes that lock fail -> Bad_ConnectionClosed,
// exactly once. Driven by deferring the translate completion, destroying the WireOps, then firing it. (This
// new two-hop branch is otherwise structurally untestable - the inline-firing fake keeps the first interface
// alive.)
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenConnectionDroppedDuringResolveReturnsConnectionClosed)
{
  Fixture f;
  f.wireOps->translateHandler = resolve_all_methods;  // resolution WOULD succeed...
  f.wireOps->deferTranslate = true;  // ...but its completion is deferred past the drop

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });

  // Extract the deferred resolve completion, then destroy the WireOps so the post-resolve seam2.lock() fails.
  ASSERT_EQ(f.wireOps->deferredTranslateInvocations.size(), 1U);
  auto fire = std::move(f.wireOps->deferredTranslateInvocations.back());
  f.wireOps->deferredTranslateInvocations.clear();
  f.wireOps.reset();  // the Connection is gone
  fire();  // resolve completes Good -> seam2.lock() null -> Bad_ConnectionClosed
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientOpen, ConnectionDroppedDuringCapReadReturnsConnectionClosedBeforeOpen)
{
  Fixture f;
  f.wireOps->deferReads = true;

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();  // Translate completion posts the cap Read, whose fake completion is deferred.

  ASSERT_EQ(f.wireOps->deferredReadInvocations.size(), 1U);
  auto fire = std::move(f.wireOps->deferredReadInvocations.back());
  f.wireOps->deferredReadInvocations.clear();
  f.wireOps.reset();
  fire();
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
}

// @verifies CL-FILE-001
// A transport-level failure of the TranslateBrowsePaths resolve itself is surfaced (chained under
// FileOpenMethodResolveFailed) rather than the file being opened against an unresolved method.
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesResolveServiceFault)
{
  Fixture f;
  f.wireOps->translateServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadServerNotConnected);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenMethodResolveFailed");
  EXPECT_TRUE(f.wireOps->callRequests.empty());  // resolution failed -> no Open Call issued
}

// @verifies CL-FILE-001
// A transport failure of the Open Call (after a successful resolve) is surfaced verbatim.
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesTransportFailureOnTheOpenCall)
{
  Fixture f;
  f.wireOps->translateHandler = resolve_all_methods;
  f.wireOps->callServiceStatus = ua::StatusCode{ua::Status::BadCommunicationError};

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadCommunicationError);
}

// @verifies CL-FILE-001
// A Good Open response carrying NO result is Bad_UnexpectedError (FileOpenEmptyResults), not a crash/hang.
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesEmptyResultsAsUnexpectedError)
{
  Fixture f;
  f.wireOps->translateHandler = resolve_all_methods;
  // No callOutcomes pushed -> the fake returns a Good CallResponse with an EMPTY results[].

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenEmptyResults");
}

// @verifies CL-FILE-001
// A Good Open result with no fileHandle output argument is Bad_UnexpectedError (FileOpenNoHandle).
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesGoodResultWithNoHandleOutput)
{
  Fixture f;
  f.wireOps->translateHandler = resolve_all_methods;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Good, empty outputs

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenNoHandle");
}

// @verifies CL-FILE-001
// A fileHandle output argument that is not a UInt32 is a decode error (FileOpenHandleDecode).
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesNonUInt32HandleAsDecodeError)
{
  Fixture f;
  f.wireOps->translateHandler = resolve_all_methods;
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::Good}, {ua::Variant{ua::String{"not-a-handle"}}}});

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenHandleDecode");
}

// ===========================================================================
// Read / Write / GetPosition / SetPosition - composition (CL-FILE-002 / CL-FILE-004)
// ===========================================================================

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileHandleOps, ReadComposesCallWithFileHandleAndReturnsBytes)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1, 2, 3})}});

  std::optional<ByteStringResult> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.read_async(10, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::ByteString({1, 2, 3}));
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.method_id(), instance_node(readNode));
  ASSERT_EQ(method.input_arguments().size(), 2U);
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
  EXPECT_EQ(method.input_arguments()[1].to<std::int32_t>().value(), 10);
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileHandleOps, ReadCapsLengthAtMaxByteStringLength)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({0})}});

  auto handle = f.handle(FileOpenMode::Read, /*cap=*/8);
  handle.read_async(1000, [](ByteStringResult) {});
  f.run();

  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.input_arguments()[1].to<std::int32_t>().value(), 8);  // capped, not 1000
}

// @verifies CL-FILE-003
// @relation(CL-FILE-003, scope=function)
TEST(FileHandleOps, ReadZeroBytesIsInlineEmptyWithNoWireOp)
{
  Fixture f;
  std::optional<ByteStringResult> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.read_async(0, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().empty());
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileHandleOps, WriteComposesCallWithFileHandleAndData)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});

  std::optional<ua::VoidResult> captured;
  auto handle = f.handle(FileOpenMode::Write);
  handle.write_async(ua::ByteString{9, 9}, [&captured](ua::VoidResult result) { captured = result; });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.method_id(), instance_node(writeNode));
  ASSERT_EQ(method.input_arguments().size(), 2U);
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
  EXPECT_EQ(method.input_arguments()[1].to<ua::ByteString>().value(), ua::ByteString({9, 9}));
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileHandleOps, WriteOnReadOnlyHandleRejectedLocallyWithNoWireOp)
{
  Fixture f;
  std::optional<ua::VoidResult> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.write_async(ua::ByteString{1}, [&captured](ua::VoidResult result) { captured = result; });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidState);
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileHandleOps, GetPositionComposesCallAndReturnsPosition)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u64(77)}});

  std::optional<UInt64Result> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.get_position_async([&captured](UInt64Result result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), 77U);
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.method_id(), instance_node(getPositionNode));
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileHandleOps, SetPositionComposesCallWithFileHandleAndPosition)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});

  std::optional<ua::VoidResult> captured;
  auto handle = f.handle(FileOpenMode::Write);
  handle.set_position_async(123, [&captured](ua::VoidResult result) { captured = result; });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.method_id(), instance_node(setPositionNode));
  ASSERT_EQ(method.input_arguments().size(), 2U);
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
  EXPECT_EQ(method.input_arguments()[1].to<std::uint64_t>().value(), 123U);
}

// @verifies CL-FILE-006
// @relation(CL-FILE-006, scope=function)
TEST(FileHandleSessionScope, SessionGenerationChangeRejectsReadWithoutWireCall)
{
  Fixture f;
  auto generation = std::make_shared<std::atomic<std::uint64_t>>(4);
  auto handle = f.handle(FileOpenMode::Read, 0x10000, serverFileHandle, generation);
  generation->store(5, std::memory_order_release);

  std::optional<ByteStringResult> captured;
  handle.read_async(8, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileHandleSessionEnded");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.file_transfer.session_end");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-006
// @relation(CL-FILE-006, scope=function)
TEST(FileHandleSessionScope, SessionChangeDuringReadOverridesLateWireCompletion)
{
  Fixture f;
  auto generation = std::make_shared<std::atomic<std::uint64_t>>(9);
  auto handle = f.handle(FileOpenMode::Read, 0x10000, serverFileHandle, generation);
  f.wireOps->deferCalls = true;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1})}});

  std::optional<ByteStringResult> captured;
  handle.read_async(8, [&captured](ByteStringResult result) { captured = std::move(result); });
  ASSERT_EQ(f.wireOps->deferredCallInvocations.size(), 1U);
  generation->store(10, std::memory_order_release);
  f.wireOps->fire_deferred_calls();
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);
}

// @verifies CL-FILE-006
// @relation(CL-FILE-006, scope=function)
TEST(FileHandleSessionScope, StaleHandleCloseDoesNotSendNumericHandleOnNewSession)
{
  Fixture f;
  auto generation = std::make_shared<std::atomic<std::uint64_t>>(1);
  auto handle = f.handle(FileOpenMode::Read, 0x10000, serverFileHandle, generation);
  generation->store(2, std::memory_order_release);

  std::optional<ua::VoidResult> captured;
  handle.close_async([&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-006
// @relation(CL-FILE-006, scope=function)
TEST(FileHandleSessionScope, UnchangedGenerationRetainsHandleAcrossTransportReconnect)
{
  Fixture f;
  auto generation = std::make_shared<std::atomic<std::uint64_t>>(7);
  auto handle = f.handle(FileOpenMode::Read, 0x10000, serverFileHandle, generation);
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({4, 5})}});

  std::optional<ByteStringResult> captured;
  handle.read_async(8, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::ByteString({4, 5}));
  EXPECT_EQ(f.call_count(instance_node(readNode)), 1U);
}

// ===========================================================================
// Close - explicit + RAII exactly-once (CL-FILE-001)
// ===========================================================================

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, ExplicitCloseIssuesCloseCall)
{
  Fixture f;
  std::optional<ua::VoidResult> captured;
  {
    auto handle = f.handle(FileOpenMode::Read);
    handle.close_async([&captured](ua::VoidResult result) { captured = result; });
    f.run();
  }
  f.run();  // drain any dtor work

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  ASSERT_EQ(f.call_count(instance_node(closeNode)), 1U);
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), serverFileHandle);
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, DropFiresCloseExactlyOnce)
{
  Fixture f;
  {
    auto handle = f.handle(FileOpenMode::Read);
    // No explicit close: the dtor owes exactly one Close.
  }
  f.run();

  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, MoveTransfersCloseDutyExactlyOnce)
{
  Fixture f;
  {
    auto first = f.handle(FileOpenMode::Read);
    FileHandle second = std::move(first);
    // `first` is moved-from -> its dtor is a no-op; `second` owns the sole Close duty.
  }
  f.run();

  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);  // exactly one - no double-close, no leak
}

// @verifies CL-FILE-001
// Move-ASSIGNMENT onto a live handle must Close the DISPLACED server handle (a defaulted move-assign would
// drop the displaced state through the shared_ptr's default deleter, leaking that fileHandle - the close-duty
// lives only in the dtor / fire_close_if_owed, not the deleter).
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, MoveAssignOntoLiveHandleClosesDisplacedHandleExactlyOnce)
{
  Fixture f;
  {
    auto a = f.handle(FileOpenMode::Read, 0x10000, /*serverHandle=*/42);
    auto b = f.handle(FileOpenMode::Read, 0x10000, /*serverHandle=*/43);
    a = std::move(b);  // must Close 42 here (displaced); `b` is moved-from -> no-op; `a` later Closes 43.
  }
  f.run();

  // Two Closes total - the displaced 42 (on move-assign) and the adopted 43 (on scope-exit). A defaulted
  // move-assign would leak 42 and fire only 1.
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 2U);
  bool closed42 = false;
  bool closed43 = false;
  for (const auto& request : f.wireOps->callRequests)
  {
    const auto& method = request.methods_to_call()[0];
    if (method.method_id() != instance_node(closeNode))
    {
      continue;
    }
    const auto closedHandle = method.input_arguments()[0].to<std::uint32_t>().value();
    closed42 = closed42 || closedHandle == 42;
    closed43 = closed43 || closedHandle == 43;
  }
  EXPECT_TRUE(closed42);  // the displaced handle was actually closed, not merely dropped
  EXPECT_TRUE(closed43);  // and the adopted handle was closed on scope-exit
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, ExplicitCloseThenDropDoesNotDoubleClose)
{
  Fixture f;
  {
    auto handle = f.handle(FileOpenMode::Read);
    handle.close_async([](ua::VoidResult) {});
    f.run();
    // handle now drops at end of scope - the dtor must NOT issue a second Close.
  }
  f.run();

  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileHandleClose, CloseIsIdempotent)
{
  Fixture f;
  std::optional<ua::VoidResult> second;
  auto handle = f.handle(FileOpenMode::Read);
  handle.close_async([](ua::VoidResult) {});
  f.run();
  handle.close_async([&second](ua::VoidResult result) { second = result; });
  f.run();

  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(second->is_good());
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);  // second close issues no wire op
}

// ===========================================================================
// section 9.8.3 cycle fix - weak-owner bail + no strong interface retention
// ===========================================================================

// @verifies CL-FILE-006
// @relation(CL-FILE-006, scope=function)
TEST(FileHandleLifetime, ReadCompletionAfterHandleDroppedBailsCleanly)
{
  Fixture f;
  f.wireOps->deferCalls = true;  // capture completions; fire them after the handle is gone
  bool readFired = false;
  {
    auto handle = f.handle(FileOpenMode::Read);
    handle.read_async(4, [&readFired](ByteStringResult) { readFired = true; });
    // handle drops here -> the pending Read completion's weak state expires.
  }
  // Fire the deferred completions (Read, plus the dtor's Close). The Read completion must weak-bail; no deref
  // of freed state, no crash, and the user callback is NOT invoked.
  f.wireOps->fire_deferred_calls();
  f.run();

  EXPECT_FALSE(readFired);
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(FileHandleLifetime, WireOpsNotKeptAliveByHandleAndOpsFailWhenGone)
{
  Fixture f;
  std::weak_ptr<FakeWireOps> weakWireOps = f.wireOps;
  auto handle = f.handle(FileOpenMode::Read);

  // The handle holds only a weak_ptr to the interface: dropping the last strong ref must expire it even while
  // the handle is alive (proves no self-owning strong cycle keeps the facade/impl alive - section 9.8.3).
  f.wireOps.reset();
  EXPECT_TRUE(weakWireOps.expired());

  std::optional<ByteStringResult> captured;
  handle.read_async(4, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
}

// ===========================================================================
// read_all - aggregate ceiling + EOF accumulation (section 9.6.23.2 / CL-FILE-002 / CL-FILE-003)
// ===========================================================================

// @verifies CL-FILE-003
// @relation(CL-FILE-003, scope=function)
TEST(FileTransferClientReadAll, AccumulatesUntilEofThenFiresClose)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1, 2, 3})}});  // Read #1
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({4, 5})}});  // Read #2
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({})}});  // Read #3 = EOF

  std::optional<ByteStringResult> captured;
  auto client = f.client();
  client.read_all_async(
    node(fileNode), [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::ByteString({1, 2, 3, 4, 5}));
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);  // handle dropped -> Close fired once
}

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientReadAll, RespectsAggregateCeiling)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1, 2, 3, 4, 5, 6, 7, 8})}});
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::Good}, {bytes({9, 10, 11, 12, 13, 14, 15, 16})}});

  std::optional<ByteStringResult> captured;
  auto client = f.client();
  client.set_max_read_all_bytes(10);  // second 8-byte chunk pushes the accumulation past the ceiling
  client.read_all_async(
    node(fileNode), [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadResponseTooLarge);
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);  // Close still fires on the error path
}

// @verifies CL-FILE-002
// Design section 8.10.3: the read_all loop must be trampolined so a synchronously-completing interface cannot
// grow the stack by one frame per chunk. FakeWireOps completes inline (deferCalls=false), so a
// non-trampolined loop would recurse once per chunk and overflow on a large file. The real loop re-enters on
// a fresh executor task per chunk (read_async posts its completion), so tens of thousands of chunks complete
// with bounded depth.
// @relation(CL-FILE-002, scope=function)
TEST(FileTransferClientReadAll, SynchronousInterfaceDoesNotOverflowStackOverManyChunks)
{
  Fixture f;
  constexpr int chunks = 20000;  // far beyond any stack that per-chunk nested recursion could survive
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  for (int chunk = 0; chunk < chunks; ++chunk)
  {
    f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1})}});  // 1-byte chunk
  }
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({})}});  // EOF

  std::optional<ByteStringResult> captured;
  auto client = f.client();
  client.read_all_async(
    node(fileNode), [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().size(), static_cast<std::size_t>(chunks));  // all chunks accumulated
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, RejectsFalseUserWritableBeforeOpenOrWrite)
{
  Fixture f;
  constexpr std::uint32_t capNode = 7010;
  constexpr std::uint32_t writableNode = 7011;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap_and_user_writable(capNode, writableNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(cap_and_writable_read(512, false));

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(node(fileNode),
    ua::ByteString{1, 2, 3},
    [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileUserNotWritable");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.file_transfer.open");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, ChunksSequentiallyAtEffectiveCap)
{
  Fixture f;
  constexpr std::uint32_t capNode = 7010;
  constexpr std::uint32_t writableNode = 7011;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap_and_user_writable(capNode, writableNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(cap_and_writable_read(4, true));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Write 1
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Write 2
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Write 3
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Close

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(node(fileNode),
    ua::ByteString{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.call_count(instance_node(writeNode)), 3U);
  std::vector<std::size_t> chunkSizes;
  for (const auto& request : f.wireOps->callRequests)
  {
    if (request.methods_to_call()[0].method_id() == instance_node(writeNode))
    {
      chunkSizes.push_back(
        request.methods_to_call()[0].input_arguments()[1].to<ua::ByteString>().value().size());
    }
  }
  EXPECT_EQ(chunkSizes, (std::vector<std::size_t>{4, 4, 2}));
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, SurfacesBadNotWritableFromOpenWithoutWrite)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(absent_cap_and_writable_read(true));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::BadNotWritable}, {}});

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(
    node(fileNode), ua::ByteString{1}, [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadNotWritable);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenBad");
  EXPECT_EQ(f.call_count(instance_node(writeNode)), 0U);
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, BadInvalidStateFromWriteAbortsWithoutRetryAndCloses)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.clear();
  f.wireOps->scriptedReadResponses.push_back(absent_cap_and_writable_read(true));
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::BadInvalidState}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // RAII Close

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(node(fileNode),
    ua::ByteString{1, 2, 3},
    [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInvalidState);
  EXPECT_EQ(f.call_count(instance_node(writeNode)), 1U);
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, MissingUserWritablePropertyFailsBeforeReadOrOpen)
{
  Fixture f;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    auto response = resolve_all_methods({});
    ua::BrowsePathResult missing;
    missing.status_code() = ua::StatusCode{ua::Status::BadNoMatch};
    response.results()[7] = std::move(missing);
    return response;
  };

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(
    node(fileNode), ua::ByteString{1}, [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileUserWritableMissing");
  EXPECT_TRUE(f.wireOps->readRequests.empty());
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// @verifies CL-FILE-004
// @relation(CL-FILE-004, scope=function)
TEST(FileTransferClientWriteAll, MalformedUserWritableFailsBeforeOpen)
{
  Fixture f;
  constexpr std::uint32_t capNode = 7010;
  constexpr std::uint32_t writableNode = 7011;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    return resolve_with_file_cap_and_user_writable(capNode, writableNode);
  };
  f.wireOps->scriptedReadResponses.clear();
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::uint32_t{512}}});
  response.results().push_back(ua::DataValue{ua::Variant{ua::String{"not-bool"}}});
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});

  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.write_all_async(
    node(fileNode), ua::ByteString{1}, [&captured](ua::VoidResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileUserWritableDecode");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// ===========================================================================
// ServiceFault flatten (error_handling.md): the tier-0 Call funnel returns the CallResponse VERBATIM, so a
// bad ResponseHeader.serviceResult with empty results[] must surface that EXACT service status - never masked
// as Bad_UnexpectedError ("FileCallEmptyResults") nor silently returned Good. flatten_call is the single
// point that heals all five FileType ops, so one op (Read) exercising it discharges the whole helper.
// ===========================================================================

// @verifies CL-FILE-002
// @relation(CL-FILE-002, scope=function)
TEST(FileHandleServiceFault, ReadSurfacesBadCallServiceResultNotUnexpectedError)
{
  Fixture f;
  // A Good-transport CallResponse whose SERVICE-level serviceResult is bad, with an empty results[] (the
  // spec-legal service-fault shape): no callOutcome is scripted, so results[] is empty.
  f.wireOps->callHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionIdInvalid};

  std::optional<ByteStringResult> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.read_async(10, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(
    captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);  // the real fault, verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileCallServiceFault");  // not "FileCallEmptyResults"
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.file_transfer.read");
}

// @verifies CL-FILE-001
// @relation(CL-FILE-001, scope=function)
TEST(FileTransferClientOpen, OpenSurfacesBadCallServiceResultNotUnexpectedError)
{
  Fixture f;
  // A Good-transport Open CallResponse whose SERVICE-level serviceResult is bad, with an empty results[].
  f.wireOps->callHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(
    captured->status_code().as_status(), ua::Status::BadTooManyOperations);  // not Bad_UnexpectedError
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenServiceFault");  // not "FileOpenEmptyResults"
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.file_transfer.open");
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 0U);  // no handle built -> no Close owed
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, ListPartitionsByTypeDefinitionAndDrainsContinuationPoint)
{
  Fixture f;
  FakeWireOps::BrowsePage first;
  first.references.push_back(directory_entry(201, ua::ObjectTypeId::FileDirectoryType, "looks-like-file"));
  first.continuationPoint = ua::ContinuationPoint{{1}};
  FakeWireOps::BrowsePage second;
  second.references.push_back(directory_entry(202, ua::ObjectTypeId::FileType, "looks-like-directory"));
  f.wireOps->browsePages.push_back(std::move(first));
  f.wireOps->browsePages.push_back(std::move(second));

  std::optional<ua::client::FileSystemEntryListResult> captured;
  auto client = f.client();
  client.list_directory_async(node(200), [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 2U);
  EXPECT_EQ(captured->value()[0].kind, FileSystemEntryKind::Directory);
  EXPECT_EQ(captured->value()[1].kind, FileSystemEntryKind::File);
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].reference_type_id(),
    ua::NodeId{ua::ReferenceTypeId::Organizes});
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 1U);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// Public API review D1 (API-D1.4): ten empty pages in a row are asked again; the eleventh ends the listing
// with Bad_Timeout and the point is released.
TEST(FileTransferClientDirectory, ListDirectoryEndsADrainAfterTooManyEmptyPagesInARow)
{
  Fixture f;
  FakeWireOps::BrowsePage first;
  first.references.push_back(directory_entry(201, ua::ObjectTypeId::FileDirectoryType, "dir"));
  first.continuationPoint = ua::ContinuationPoint{{1}};
  FakeWireOps::BrowsePage looping;
  looping.continuationPoint = ua::ContinuationPoint{{1}};
  f.wireOps->browsePages.push_back(std::move(first));
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back(looping);
  }

  std::optional<ua::client::FileSystemEntryListResult> captured;
  auto client = f.client();
  client.list_directory_async(node(200), [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 12U)
    << "eleven reads, then one release of the point the server still holds";
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, CreateDirectoryCallsResolvedInstanceMethod)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{directory_method("CreateDirectory")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {ua::Variant{node(301)}}});
  std::optional<ua::client::NodeIdResult> captured;
  auto client = f.client();
  client.create_directory_async(
    node(300), ua::String{"child"}, [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), node(301));
  ASSERT_EQ(f.wireOps->callRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].object_id(), node(300));
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(8001));
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, CreateFileCallsResolvedInstanceMethodAndDecodesNode)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{directory_method("CreateFile")}, {}, {}});
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::Good}, {ua::Variant{node(401)}, ua::Variant{std::uint32_t{0}}}});
  std::optional<ua::client::NodeIdResult> captured;
  auto client = f.client();
  client.create_file_async(
    node(400), ua::String{"data.bin"}, [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), node(401));
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.method_id(), node(8001));
  EXPECT_FALSE(method.input_arguments()[1].to<bool>().value());
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, DeleteCallsDirectoryMethodRatherThanNodeManagement)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{directory_method("Delete")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});
  std::optional<ua::VoidResult> captured;
  auto client = f.client();
  client.delete_async(node(500), node(501), [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), node(500));
  EXPECT_EQ(method.method_id(), node(8001));
  EXPECT_EQ(method.input_arguments()[0].to<ua::NodeId>().value(), node(501));
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, MoveOrCopyCallsSourceDirectoryMethodWithNormativeArguments)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{directory_method("MoveOrCopy")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {ua::Variant{node(603)}}});
  std::optional<ua::client::NodeIdResult> captured;
  auto client = f.client();
  client.move_or_copy_async(node(600),
    node(601),
    node(602),
    true,
    ua::String{"copy"},
    [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), node(603));
  const auto& method = f.wireOps->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), node(600));
  EXPECT_EQ(method.method_id(), node(8001));
  ASSERT_EQ(method.input_arguments().size(), 4U);
  EXPECT_EQ(method.input_arguments()[0].to<ua::NodeId>().value(), node(601));
  EXPECT_EQ(method.input_arguments()[1].to<ua::NodeId>().value(), node(602));
  EXPECT_TRUE(method.input_arguments()[2].to<bool>().value());
}

// @verifies CL-FILE-005
// @relation(CL-FILE-005, scope=function)
TEST(FileTransferClientDirectory, MissingInstanceMethodReturnsSourceTaggedErrorDetailWithoutCalling)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{}, {}, {}});
  std::optional<ua::client::NodeIdResult> captured;
  auto client = f.client();
  client.create_directory_async(
    node(700), ua::String{"child"}, [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadMethodInvalid);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileDirectoryOperationFailed");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.file_transfer.directory");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

// Part 20 section 4.2.1-4.2.2: a fileHandle is only usable between its Open and its Close, and every Open
// owes exactly one Close INCLUDING on the error paths. A plausible implementation gets both halves wrong the
// same way: it keeps serving ops off a stale server fileHandle after Close (the server has already freed it,
// so the numeric handle now names nothing - or worse, a handle another Open has since been given), and it
// abandons the handle when an op fails mid-transfer, leaking a server-side lock that makes the file
// undeletable. Driven end-to-end: the handle comes from the real Open path, and the error-path Open/Close
// pairing is observed through read_all's internally-owned handle when the server refuses the first Read.
// @verifies AC-CL-FILE-001-HANDLE-LIFECYCLE
TEST(FileHandleLifecycle, HandleServesOpsUntilCloseAndIsRefusedAfterwardsWithEveryOpenPairedByAClose)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(absent_cap_read());  // cap read for the second (read_all) Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open #1
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({1, 2, 3})}});  // Read #1
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Close #1
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(43)}});  // Open #2 (read_all)
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::BadUserAccessDenied}, {}});  // Read #2 fails
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});  // Close #2 (owed on the error)

  auto client = f.client();
  std::optional<FileHandleResult> opened;
  client.open_async(
    node(fileNode), FileOpenMode::Read, [&opened](FileHandleResult result) { opened = std::move(result); });
  f.run();

  ASSERT_TRUE(opened.has_value());
  ASSERT_TRUE(opened->is_good());
  FileHandle handle = std::move(*opened).value();
  EXPECT_TRUE(handle.is_valid());
  ASSERT_EQ(f.call_count(instance_node(openNode)), 1U);

  // Between Open and Close the handle works: the Read reaches the wire and returns the server's bytes.
  std::optional<ByteStringResult> beforeClose;
  handle.read_async(3, [&beforeClose](ByteStringResult result) { beforeClose = std::move(result); });
  f.run();

  ASSERT_TRUE(beforeClose.has_value());
  ASSERT_TRUE(beforeClose->is_good());
  EXPECT_EQ(beforeClose->value(), ua::ByteString({1, 2, 3}));
  ASSERT_EQ(f.call_count(instance_node(readNode)), 1U);

  std::optional<ua::VoidResult> closed;
  handle.close_async([&closed](ua::VoidResult result) { closed = std::move(result); });
  f.run();

  ASSERT_TRUE(closed.has_value());
  EXPECT_TRUE(closed->is_good());
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 1U);
  EXPECT_FALSE(handle.is_valid());  // the handle no longer owns a server fileHandle

  // After the Close the SAME handle is refused - locally, before any wire op, for every positional op.
  std::optional<ByteStringResult> afterClose;
  handle.read_async(3, [&afterClose](ByteStringResult result) { afterClose = std::move(result); });
  std::optional<UInt64Result> positionAfterClose;
  handle.get_position_async(
    [&positionAfterClose](UInt64Result result) { positionAfterClose = std::move(result); });
  f.run();

  ASSERT_TRUE(afterClose.has_value());
  ASSERT_TRUE(afterClose->is_bad());
  EXPECT_EQ(afterClose->status_code().as_status(), ua::Status::BadInvalidState);
  ASSERT_NE(afterClose->shared_detail(), nullptr);
  EXPECT_EQ(afterClose->shared_detail()->code, "FileHandleClosed");
  ASSERT_TRUE(positionAfterClose.has_value());
  ASSERT_TRUE(positionAfterClose->is_bad());
  EXPECT_EQ(positionAfterClose->status_code().as_status(), ua::Status::BadInvalidState);
  EXPECT_EQ(f.call_count(instance_node(readNode)), 1U);  // no second Read issued on the freed handle
  EXPECT_EQ(f.call_count(instance_node(getPositionNode)), 0U);

  // The ERROR path still pairs its Open with a Close: read_all opens, the server refuses the first Read, and
  // the internally-owned handle must still discharge its Close rather than leak the server-side handle.
  std::optional<ByteStringResult> readAll;
  client.read_all_async(node(fileNode), [&readAll](ByteStringResult result) { readAll = std::move(result); });
  f.run();

  ASSERT_TRUE(readAll.has_value());
  ASSERT_TRUE(readAll->is_bad());
  EXPECT_EQ(readAll->status_code().as_status(), ua::Status::BadUserAccessDenied);
  EXPECT_EQ(f.call_count(instance_node(openNode)), 2U);
  EXPECT_EQ(f.call_count(instance_node(closeNode)), 2U);  // one Close per Open - neither handle leaked
}

// Part 20 section 4.3: a FileDirectoryType instance is traversed by its Organizes references, and its
// mandatory Methods (CreateDirectory / CreateFile / Delete / MoveOrCopy) are components of the directory that
// a naive traversal reports as entries - a client listing everything it browses would show "CreateFile"
// beside the files, and would then be tempted to emulate a delete by dropping the Organizes reference. Both
// halves are driven here: the browse page deliberately carries the four Method references alongside the real
// children (the fake ignores nodeClassMask, so the CLIENT must do the partitioning), and the same four names
// are then exercised as directory operations, each resolved as a HasComponent instance Method and Called.
// @verifies AC-CL-FILE-005-DIRECTORY-TRAVERSAL
TEST(FileTransferClientDirectory, TraversalListsOrganizesChildrenAndTreatsDirectoryMethodsAsOperations)
{
  Fixture f;
  const auto methodReference = [](std::uint32_t identifier, std::string_view browseName)
  {
    ua::ReferenceDescription reference;
    reference.node_id() = ua::ExpandedNodeId{node(identifier)};
    reference.browse_name() = ua::QualifiedName{0, browseName};
    reference.node_class() = ua::NodeClass::Method;
    return reference;
  };

  FakeWireOps::BrowsePage children;
  children.references.push_back(directory_entry(201, ua::ObjectTypeId::FileDirectoryType, "logs"));
  children.references.push_back(directory_entry(202, ua::ObjectTypeId::FileType, "trace.bin"));
  children.references.push_back(methodReference(8101, "CreateDirectory"));
  children.references.push_back(methodReference(8102, "CreateFile"));
  children.references.push_back(methodReference(8103, "Delete"));
  children.references.push_back(methodReference(8104, "MoveOrCopy"));
  f.wireOps->browsePages.push_back(std::move(children));

  auto client = f.client();
  std::optional<ua::client::FileSystemEntryListResult> listed;
  client.list_directory_async(node(200), [&listed](auto result) { listed = std::move(result); });
  f.run();

  ASSERT_TRUE(listed.has_value());
  ASSERT_TRUE(listed->is_good());
  // The sub-directory and the file are both reached, classified from TypeDefinition, and the four Methods
  // are NOT among them.
  ASSERT_EQ(listed->value().size(), 2U);
  EXPECT_EQ(listed->value()[0].nodeId, node(201));
  EXPECT_EQ(listed->value()[0].kind, FileSystemEntryKind::Directory);
  EXPECT_EQ(listed->value()[1].nodeId, node(202));
  EXPECT_EQ(listed->value()[1].kind, FileSystemEntryKind::File);
  for (const auto& entry : listed->value())
  {
    EXPECT_NE(entry.nodeId, node(8101));
    EXPECT_NE(entry.nodeId, node(8102));
    EXPECT_NE(entry.nodeId, node(8103));
    EXPECT_NE(entry.nodeId, node(8104));
  }
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1U);
  EXPECT_EQ(f.wireOps->browseRequests[0].nodes_to_browse()[0].reference_type_id(),
    ua::NodeId{ua::ReferenceTypeId::Organizes});

  // Each of the four Methods is an OPERATION on the directory: resolved as a HasComponent instance Method
  // and invoked by Call on the directory Object.
  f.wireOps->browsePages.push_back({{methodReference(8101, "CreateDirectory")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {ua::Variant{node(203)}}});
  std::optional<ua::client::NodeIdResult> createdDirectory;
  client.create_directory_async(node(200),
    ua::String{"archive"},
    [&createdDirectory](auto result) { createdDirectory = std::move(result); });
  f.run();

  ASSERT_TRUE(createdDirectory.has_value());
  ASSERT_TRUE(createdDirectory->is_good());
  EXPECT_EQ(createdDirectory->value(), node(203));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 2U);
  EXPECT_EQ(f.wireOps->browseRequests[1].nodes_to_browse()[0].reference_type_id(),
    ua::NodeId{ua::ReferenceTypeId::HasComponent});

  f.wireOps->browsePages.push_back({{methodReference(8102, "CreateFile")}, {}, {}});
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::Good}, {ua::Variant{node(204)}, ua::Variant{std::uint32_t{0}}}});
  std::optional<ua::client::NodeIdResult> createdFile;
  client.create_file_async(
    node(200), ua::String{"next.bin"}, [&createdFile](auto result) { createdFile = std::move(result); });
  f.run();

  ASSERT_TRUE(createdFile.has_value());
  ASSERT_TRUE(createdFile->is_good());
  EXPECT_EQ(createdFile->value(), node(204));

  f.wireOps->browsePages.push_back({{methodReference(8103, "Delete")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {}});
  std::optional<ua::VoidResult> deleted;
  client.delete_async(node(200), node(202), [&deleted](auto result) { deleted = std::move(result); });
  f.run();

  ASSERT_TRUE(deleted.has_value());
  EXPECT_TRUE(deleted->is_good());

  f.wireOps->browsePages.push_back({{methodReference(8104, "MoveOrCopy")}, {}, {}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {ua::Variant{node(205)}}});
  std::optional<ua::client::NodeIdResult> moved;
  client.move_or_copy_async(node(200),
    node(201),
    node(200),
    true,
    ua::String{"logs-copy"},
    [&moved](auto result) { moved = std::move(result); });
  f.run();

  ASSERT_TRUE(moved.has_value());
  ASSERT_TRUE(moved->is_good());
  EXPECT_EQ(moved->value(), node(205));

  // Exactly four Calls, one per Method, each on the directory Object and each on the resolved instance node -
  // no operation was emulated by touching the address space directly.
  ASSERT_EQ(f.wireOps->callRequests.size(), 4U);
  for (const auto& request : f.wireOps->callRequests)
  {
    ASSERT_FALSE(request.methods_to_call().empty());
    EXPECT_EQ(request.methods_to_call()[0].object_id(), node(200));
  }
  EXPECT_EQ(f.wireOps->callRequests[0].methods_to_call()[0].method_id(), node(8101));
  EXPECT_EQ(f.wireOps->callRequests[1].methods_to_call()[0].method_id(), node(8102));
  EXPECT_EQ(f.wireOps->callRequests[2].methods_to_call()[0].method_id(), node(8103));
  EXPECT_EQ(f.wireOps->callRequests[3].methods_to_call()[0].method_id(), node(8104));
}

// ===========================================================================
// A Good subcode or an Uncertain code the server answers reaches the application
// ===========================================================================

// A Write the Method answers with a Good subcode completes with that code, not plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileHandleStatusRouting, AWritesMethodGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    Fixture f;
    f.wireOps->callOutcomes.push_back({ua::StatusCode{methodStatus}, {}});

    std::optional<ua::VoidResult> captured;
    auto handle = f.handle(FileOpenMode::Write);
    handle.write_async(ua::ByteString{1, 2}, [&captured](ua::VoidResult result) { captured = result; });
    f.run();

    ASSERT_TRUE(captured.has_value());
    EXPECT_TRUE(captured->is_good());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{methodStatus});
  }
}

// A Read the Method answers Uncertain with data holds the bytes with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileHandleStatusRouting, AnUncertainReadKeepsItsBytesAndCode)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::UncertainDataSubNormal}, {bytes({5, 6})}});

  std::optional<ByteStringResult> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.read_async(8, [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainDataSubNormal});
  EXPECT_EQ(captured->value_or(ua::ByteString{}), ua::ByteString({5, 6}));
}

// A GetPosition the Method answers Uncertain without an output argument is that code with no position.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileHandleStatusRouting, AnUncertainCallWithoutOutputsIsItsCodeWithoutAValue)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue}, {}});

  std::optional<UInt64Result> captured;
  auto handle = f.handle(FileOpenMode::Read);
  handle.get_position_async([&captured](UInt64Result result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue});
  EXPECT_THROW((void)captured->value(), ua::UaException);
}

// A Good subcode on the Open Call's ServiceResult is the status of the Result holding the handle.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileTransferClientStatusRouting, TheOpensServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    f.wireOps->callHeaderServiceResult = ua::StatusCode{serviceStatus};
    f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});

    std::optional<FileHandleResult> captured;
    auto client = f.client();
    client.open_async(node(fileNode),
      FileOpenMode::Read,
      [&captured](FileHandleResult result) { captured = std::move(result); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{serviceStatus});
    ASSERT_TRUE(captured->is_good());
    EXPECT_TRUE(captured->value().is_valid());
    EXPECT_EQ(captured->value().file_node(), node(fileNode));
    EXPECT_EQ(captured->value().mode(), FileOpenMode::Read);
  }
}

// read_all completes with the code of every chunk combined: an Uncertain chunk makes the whole read
// Uncertain, holding every byte.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileTransferClientStatusRouting, ReadAllKeepsAnUncertainChunksCode)
{
  Fixture f;
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {u32(serverFileHandle)}});  // Open
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::UncertainSubstituteValue}, {bytes({1, 2})}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({3})}});
  f.wireOps->callOutcomes.push_back({ua::StatusCode{ua::Status::Good}, {bytes({})}});  // EOF

  std::optional<ByteStringResult> captured;
  auto client = f.client();
  client.read_all_async(
    node(fileNode), [&captured](ByteStringResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainSubstituteValue});
  EXPECT_EQ(captured->value_or(ua::ByteString{}), ua::ByteString({1, 2, 3}));
}

// A FileDirectoryType Method answered Uncertain with an output holds the decoded NodeId with that code.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileTransferClientStatusRouting, ADirectoryMethodsUncertainCodeReachesTheApplication)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{directory_method("CreateDirectory")}, {}, {}});
  f.wireOps->callOutcomes.push_back(
    {ua::StatusCode{ua::Status::UncertainReferenceNotDeleted}, {ua::Variant{node(311)}}});

  std::optional<ua::client::NodeIdResult> captured;
  auto client = f.client();
  client.create_directory_async(
    node(310), ua::String{"child"}, [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainReferenceNotDeleted});
  EXPECT_EQ(captured->value_or(ua::NodeId{}), node(311));
}

// list_directory carries a Good subcode of the Browse page with the entries.
// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(FileTransferClientStatusRouting, ListDirectoryKeepsTheBrowsePagesCode)
{
  Fixture f;
  FakeWireOps::BrowsePage page;
  page.references.push_back(directory_entry(321, ua::ObjectTypeId::FileType, "a-file"));
  page.status = ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete};
  f.wireOps->browsePages.push_back(std::move(page));

  std::optional<ua::client::FileSystemEntryListResult> captured;
  auto client = f.client();
  client.list_directory_async(node(320), [&captured](auto result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete});
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().size(), 1U);
}

// The open acts on UserWritable itself, so an Uncertain UserWritable is refused with Bad_InternalError
// (ReadAnswerUncertain) and no Open is called.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(FileTransferClientStatusRouting, AnUncertainUserWritableRefusesTheOpen)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.clear();
  auto read = absent_cap_and_writable_read(true);
  read.value().results()[1].status() = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  f.wireOps->scriptedReadResponses.push_back(std::move(read));

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Write,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(f.call_count(instance_node(openNode)), 0U);
}

// The FileType Method lookup is one the SDK acts on, so an Uncertain path answer is refused with
// Bad_InternalError (ReferencesAnswerUncertain) and no Open is called.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(FileTransferClientStatusRouting, AnUncertainMethodLookupRefusesTheOpen)
{
  Fixture f;
  f.wireOps->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    auto response = resolve_all_methods(request);
    response.results()[1].status_code() = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
    return response;
  };

  std::optional<FileHandleResult> captured;
  auto client = f.client();
  client.open_async(node(fileNode),
    FileOpenMode::Read,
    [&captured](FileHandleResult result) { captured = std::move(result); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "FileOpenMethodResolveFailed");
  ASSERT_NE(captured->shared_detail()->cause, nullptr);
  EXPECT_EQ(captured->shared_detail()->cause->code, "ReferencesAnswerUncertain");
  EXPECT_TRUE(f.wireOps->callRequests.empty());
}

}  // namespace
