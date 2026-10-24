// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for ua::FileDirectoryHelper - backs a FileDirectoryType node with a real
/// directory and wires CreateDirectory / CreateFile / DeleteFileSystemObject. Drives the methods
/// over the wire and checks both the address space and the on-disk filesystem.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_argument.h"
#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_codec_namespace_context.h"
#include "ua_core_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "ua_file.h"
#include "ua_file_directory.h"
#include "ua_file_system_helpers.h"
#include "ua_guid.h"
#include "ua_instantiation_options.h"
#include "ua_localized_text.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_property.h"
#include "ua_read_response.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_view_services.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_ua_binary_file_data_type.h"
#include "ua_variant.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// Server-wide ByteString capability advertised by this fixture's server. Deliberately small so a
// FileType Object that declares no MaxByteStringLength of its own can be read with a chunk larger
// than the capability and the fallback cap becomes observable in the returned data.
constexpr std::uint32_t serverMaxByteStringLength = 4096;

class FileDirectoryTest : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceBase::configure_server_config(cfg);
    cfg.server_capabilities().maxByteStringLength = serverMaxByteStringLength;
  }

  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    // One unique root per test: the served directory sits one level below it, so an escape attempt's
    // target (the parent, or an absolute path under the root) is still inside what TearDown removes.
    mRootPath =
      std::filesystem::temp_directory_path() / ("ua_filedir_" + Guid::create_and_generate().as_string());
    std::error_code ec;
    std::filesystem::remove_all(mRootPath, ec);
    mDirPath = mRootPath / "served";
    std::filesystem::create_directories(mDirPath, ec);

    auto addressSpace = mServer.server().address_space();
    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

    auto result = FileDirectoryHelper::try_create_sync(
      addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "FileSystem"}, mDirPath, options, true);
    ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
    auto helper = std::move(result).value();

    mDirNodeId = helper.node_id();
    mCreateDirMethodId = helper.directory().try_create_directory_method_sync().value().get_node_id();
    mCreateFileMethodId = helper.directory().try_create_file_method_sync().value().get_node_id();
    mDeleteMethodId = helper.directory().try_delete_file_system_object_method_sync().value().get_node_id();
    helper.release();

    mCapFilePath = mDirPath / "capped.bin";
    mCapFileBytes.resize(2000);
    for (std::size_t index = 0; index < mCapFileBytes.size(); ++index)
    {
      mCapFileBytes[index] = static_cast<std::uint8_t>(index % 251);
    }
    std::ofstream output{mCapFilePath, std::ios::binary};
    output.write(reinterpret_cast<const char*>(mCapFileBytes.data()),
      static_cast<std::streamsize>(mCapFileBytes.size()));
    output.close();

    InstantiationOptions fileOptions = options;
    fileOptions.optionalChildFilter = [](const ChildFilterInfo& child)
    {
      return child.browseName.name() == "MaxByteStringLength";
    };
    auto fileResult = FileHelper::try_create_sync(addressSpace,
      mTestFolderId,
      QualifiedName{mTestNamespaceIndex, "CappedFile"},
      mCapFilePath,
      fileOptions,
      true);
    ASSERT_TRUE(fileResult.is_good()) << "0x" << std::hex << fileResult.status_code().as_uint32();
    auto fileHelper = std::move(fileResult).value();
    mCapFileNodeId = fileHelper.node_id();
    mCapOpenMethodId = fileHelper.file().try_open_method_sync().value().get_node_id();
    mCapCloseMethodId = fileHelper.file().try_close_method_sync().value().get_node_id();
    mCapReadMethodId = fileHelper.file().try_read_method_sync().value().get_node_id();
    mCapWriteMethodId = fileHelper.file().try_write_method_sync().value().get_node_id();
    mCapGetPositionMethodId = fileHelper.file().try_get_position_method_sync().value().get_node_id();
    mCapOpenCountPropertyId = fileHelper.file().try_open_count_property_sync().value().node_id();
    fileHelper.file().write_max_byte_string_length_sync(512);
    fileHelper.release();

    // Plain file: mandatory children only, so it declares no MaxByteStringLength of its own and
    // the server-wide capability is the only cap in play. Made larger than that capability so a
    // capped read is distinguishable from an uncapped one.
    mPlainFilePath = mDirPath / "plain.bin";
    mPlainFileBytes.resize(static_cast<std::size_t>(serverMaxByteStringLength) + 2000);
    for (std::size_t index = 0; index < mPlainFileBytes.size(); ++index)
    {
      mPlainFileBytes[index] = static_cast<std::uint8_t>((index * 3) % 251);
    }
    {
      std::ofstream plainOutput{mPlainFilePath, std::ios::binary};
      plainOutput.write(reinterpret_cast<const char*>(mPlainFileBytes.data()),
        static_cast<std::streamsize>(mPlainFileBytes.size()));
    }
    auto plainResult = FileHelper::try_create_sync(addressSpace,
      mTestFolderId,
      QualifiedName{mTestNamespaceIndex, "PlainFile"},
      mPlainFilePath,
      options,
      true);
    ASSERT_TRUE(plainResult.is_good()) << "0x" << std::hex << plainResult.status_code().as_uint32();
    auto plainHelper = std::move(plainResult).value();
    mPlainFileNodeId = plainHelper.node_id();
    mPlainOpenMethodId = plainHelper.file().try_open_method_sync().value().get_node_id();
    mPlainReadMethodId = plainHelper.file().try_read_method_sync().value().get_node_id();
    mPlainSizePropertyId = plainHelper.file().try_size_property_sync().value().node_id();
    mPlainDeclaresMaxByteStringLength =
      plainHelper.file().try_max_byte_string_length_property_sync().is_good();
    plainHelper.release();

    // File carrying the optional LastModifiedTime Property, backed by a real path so both a
    // server-side write and an out-of-band edit are changes the server can detect.
    mStampFilePath = mDirPath / "stamped.bin";
    {
      std::ofstream stampOutput{mStampFilePath, std::ios::binary};
      stampOutput.write("seed", 4);
    }
    // An hour back, so the server's own write lands on a later modification time than the seed's: the
    // filesystem stamps times from a coarse clock, and two writes milliseconds apart can share one.
    std::filesystem::last_write_time(
      mStampFilePath, std::filesystem::last_write_time(mStampFilePath) - std::chrono::hours{1});
    InstantiationOptions stampOptions = options;
    stampOptions.optionalChildFilter = [](const ChildFilterInfo& child)
    {
      return child.browseName.name() == "LastModifiedTime";
    };
    auto stampResult = FileHelper::try_create_sync(addressSpace,
      mTestFolderId,
      QualifiedName{mTestNamespaceIndex, "StampedFile"},
      mStampFilePath,
      stampOptions,
      true);
    ASSERT_TRUE(stampResult.is_good()) << "0x" << std::hex << stampResult.status_code().as_uint32();
    auto stampHelper = std::move(stampResult).value();
    mStampFileNodeId = stampHelper.node_id();
    mStampOpenMethodId = stampHelper.file().try_open_method_sync().value().get_node_id();
    mStampWriteMethodId = stampHelper.file().try_write_method_sync().value().get_node_id();
    mStampCloseMethodId = stampHelper.file().try_close_method_sync().value().get_node_id();
    auto stampProperty = stampHelper.file().try_last_modified_time_property_sync();
    if (stampProperty.is_good())
    {
      mStampLastModifiedTimePropertyId = stampProperty.value().node_id();
    }
    stampHelper.release();
  }

  void TearDown() override
  {
    ComplianceWithNodes::TearDown();
    std::error_code ec;
    std::filesystem::remove_all(mRootPath, ec);
  }

  std::filesystem::path mRootPath;
  std::filesystem::path mDirPath;
  NodeId mDirNodeId;
  NodeId mCreateDirMethodId;
  NodeId mCreateFileMethodId;
  NodeId mDeleteMethodId;
  std::filesystem::path mCapFilePath;
  std::vector<std::uint8_t> mCapFileBytes;
  NodeId mCapFileNodeId;
  NodeId mCapOpenMethodId;
  NodeId mCapCloseMethodId;
  NodeId mCapReadMethodId;
  NodeId mCapWriteMethodId;
  NodeId mCapGetPositionMethodId;
  NodeId mCapOpenCountPropertyId;
  std::filesystem::path mPlainFilePath;
  std::vector<std::uint8_t> mPlainFileBytes;
  NodeId mPlainFileNodeId;
  NodeId mPlainOpenMethodId;
  NodeId mPlainReadMethodId;
  NodeId mPlainSizePropertyId;
  bool mPlainDeclaresMaxByteStringLength{false};
  std::filesystem::path mStampFilePath;
  NodeId mStampFileNodeId;
  NodeId mStampOpenMethodId;
  NodeId mStampWriteMethodId;
  NodeId mStampCloseMethodId;
  NodeId mStampLastModifiedTimePropertyId;
};

TEST_F(FileDirectoryTest, CreateDirectoryCreatesNodeAndDiskDir)
{
  auto resp = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mCreateDirMethodId, {Variant{String{"sub"}}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0].status_code(), Good());
  ASSERT_EQ(resp.results()[0].output_arguments().size(), 1u);
  EXPECT_FALSE(resp.results()[0].output_arguments()[0].as<NodeId>().is_null());
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "sub"));
}

TEST_F(FileDirectoryTest, CreateFileCreatesNodeAndDiskFile)
{
  auto resp = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"data.bin"}}, Variant{false}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0].status_code(), Good());
  ASSERT_GE(resp.results()[0].output_arguments().size(), 1u);
  EXPECT_FALSE(resp.results()[0].output_arguments()[0].as<NodeId>().is_null());
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "data.bin"));
}

// A FileName or DirectoryName argument names one child of the directory: a single path component.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryTest, CreateFileRefusesANameThatIsNotASinglePathComponent)
{
  const std::string absolute = (mRootPath / "absolute.bin").string();
  for (const std::string& name :
    std::vector<std::string>{"../escaped.bin", "sub/inner.bin", absolute, "..", "."})
  {
    auto resp = mSession->methods().call_sync(
      CallRequestBuilder().call(mDirNodeId, mCreateFileMethodId, {Variant{String{name}}, Variant{false}}));
    ASSERT_EQ(resp.results().size(), 1u) << name;
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadBrowseNameInvalid}) << name;
  }
  EXPECT_FALSE(std::filesystem::exists(mRootPath / "escaped.bin"));
  EXPECT_FALSE(std::filesystem::exists(mDirPath / "sub" / "inner.bin"));
  EXPECT_FALSE(std::filesystem::exists(absolute));
}

// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryTest, CreateDirectoryRefusesANameThatIsNotASinglePathComponent)
{
  const std::string absolute = (mRootPath / "absolute").string();
  for (const std::string& name : std::vector<std::string>{"../escaped", "a/b", absolute, ".."})
  {
    auto resp = mSession->methods().call_sync(
      CallRequestBuilder().call(mDirNodeId, mCreateDirMethodId, {Variant{String{name}}}));
    ASSERT_EQ(resp.results().size(), 1u) << name;
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadBrowseNameInvalid}) << name;
  }
  EXPECT_FALSE(std::filesystem::exists(mRootPath / "escaped"));
  EXPECT_FALSE(std::filesystem::exists(absolute));
}

// Part 20 section 4.3.4: a file with the name already exists -> Bad_BrowseNameDuplicated.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryTest, CreateFileRefusesAnExistingFileName)
{
  auto first = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"once.bin"}}, Variant{false}}));
  ASSERT_EQ(first.results().size(), 1u);
  ASSERT_THAT(first.results()[0].status_code(), Good());

  auto second = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"once.bin"}}, Variant{false}}));
  ASSERT_EQ(second.results().size(), 1u);
  EXPECT_EQ(second.results()[0].status_code(), StatusCode{Status::BadBrowseNameDuplicated})
    << "creating a file must never adopt an existing one";
}

TEST_F(FileDirectoryTest, DeleteRemovesNodeAndDiskObject)
{
  auto created = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"todelete.bin"}}, Variant{false}}));
  ASSERT_THAT(created.results()[0].status_code(), Good());
  const auto fileNode = created.results()[0].output_arguments()[0].as<NodeId>();
  ASSERT_TRUE(std::filesystem::exists(mDirPath / "todelete.bin"));

  auto del = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mDeleteMethodId, {Variant{fileNode}}));
  ASSERT_EQ(del.results().size(), 1u);
  EXPECT_THAT(del.results()[0].status_code(), Good());
  EXPECT_FALSE(std::filesystem::exists(mDirPath / "todelete.bin"));

  // The file node must already be gone from the address space the instant
  // DeleteFileSystemObject reports Good: the handler sequences its completion
  // after the asynchronous node delete, so a client never observes Good while
  // the node is still browsable. Read it back over the wire to confirm.
  auto readBack = mSession->attributes().read_sync(read_value(fileNode, AttributeId::NodeClass));
  ASSERT_THAT(readBack, ServiceResultIsGood());
  ASSERT_FALSE(readBack.results().empty());
  EXPECT_THAT(readBack.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "DeleteFileSystemObject reported Good but the file node is still readable";
}

// @verifies CL-FILE-005 [integration]
// Highest public production tier: the managed Connection's FileTransferClient resolves and Calls the
// FileDirectoryType instance methods, then classifies the Organizes child from its TypeDefinition.
// @relation(CL-FILE-005, scope=function)
TEST_F(FileDirectoryTest, Tier2FacadeCreatesListsAndDeletesDirectory)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  auto connection = mClient->connect_sync(std::move(config));
  auto files = connection.files();

  const NodeId child = files.create_directory_sync(mDirNodeId, String{"tier2-child"});
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "tier2-child"));

  const auto entries = files.list_directory_sync(mDirNodeId);
  const auto found = std::find_if(entries.begin(),
    entries.end(),
    [&child](const auto& entry)
    { return entry.nodeId == child && entry.kind == FileSystemEntryKind::Directory; });
  EXPECT_NE(found, entries.end());

  files.delete_sync(mDirNodeId, child);
  EXPECT_FALSE(std::filesystem::exists(mDirPath / "tier2-child"));
  connection.close_sync();
}

// @verifies CL-FILE-002 [integration]
// Highest public production tier: Open resolves the optional per-file Property once, the handle exposes the
// effective cap, and read_all reconstructs a file larger than one cap-sized chunk.
// @relation(CL-FILE-002, scope=function)
TEST_F(FileDirectoryTest, Tier2FileReadUsesPerFileMaxByteStringLength)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  auto connection = mClient->connect_sync(std::move(config));
  auto files = connection.files();

  {
    auto handle = files.open_sync(mCapFileNodeId, FileOpenMode::Read);
    EXPECT_EQ(handle.max_byte_string_length(), 512U);
  }

  const auto content = files.read_all_sync(mCapFileNodeId);
  EXPECT_EQ(content.payload(), mCapFileBytes);
  connection.close_sync();
}

// @verifies CL-FILE-004 [integration]
// Highest public production tier: UserWritable is read before Open, then write_all uses cap-sized sequential
// Write calls and the resulting bytes round-trip through read_all.
// @relation(CL-FILE-004, scope=function)
TEST_F(FileDirectoryTest, Tier2FileWriteAllChecksUserWritableAndRoundTripsChunks)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  auto connection = mClient->connect_sync(std::move(config));
  auto files = connection.files();

  std::vector<std::uint8_t> expected(1300);
  for (std::size_t index = 0; index < expected.size(); ++index)
  {
    expected[index] = static_cast<std::uint8_t>((index * 7) % 251);
  }
  files.write_all_sync(mCapFileNodeId, ByteString{expected});
  EXPECT_EQ(files.read_all_sync(mCapFileNodeId).payload(), expected);
  connection.close_sync();
}

// @verifies CL-FILE-006 [integration]
// Highest public production tier: a FileHandle retained past its owning Session is rejected locally with a
// Session-specific diagnostic instead of sending the stale numeric handle through a closed Connection.
// @relation(CL-FILE-006, scope=function)
TEST_F(FileDirectoryTest, Tier2FileHandleIsInvalidatedWhenSessionCloses)
{
  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  auto connection = mClient->connect_sync(std::move(config));
  auto handle = connection.files().open_sync(mCapFileNodeId, FileOpenMode::Read);

  connection.close_sync();

  const auto readResult = handle.try_read_sync(1);
  ASSERT_TRUE(readResult.is_bad());
  EXPECT_EQ(readResult.status_code().as_status(), Status::BadSessionClosed);
  ASSERT_TRUE(readResult.shared_detail());
  EXPECT_EQ(readResult.shared_detail()->code, "FileHandleSessionEnded");
  EXPECT_EQ(readResult.shared_detail()->source, "client.tier2.file_transfer.session_end");
}

// Part 20 section 4.2.1: Size is best-effort, and a server that cannot give an authoritative byte-count
// must read Bad_NotSupported. A plausible implementation queries the backing store, swallows the
// failure, and reports its zero-initialised local as a Good value - indistinguishable from an
// empty file, so a client stops reading before it has read anything.
// @verifies AC-SVR-FILE-002-SIZE-UNKNOWN
TEST_F(FileDirectoryTest, SizeIsNotSupportedWhenTheServerCannotDetermineIt)
{
  // The condition under test is created by unlinking the backing store while the server still holds it
  // open. POSIX allows that; Windows refuses it - a file opened without FILE_SHARE_DELETE cannot be
  // removed - so there the Size stays determinable and there is nothing for the read to observe. The
  // arm is a documented no-op off POSIX rather than a skip, so the requirement it discharges stays
  // discharged by a test that runs.
#ifndef _WIN32
  auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
    mPlainFileNodeId, mPlainOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  ASSERT_NE(opened.results()[0].output_arguments()[0].as<std::uint32_t>(), 0u);

  // Take the backing store out from under the open write handle. The size is now genuinely
  // indeterminable for the server; the condition is driven on disk, not by overriding the Property.
  std::error_code ec;
  ASSERT_TRUE(std::filesystem::remove(mPlainFilePath, ec));
  ASSERT_FALSE(ec);

  auto sizeRead = mSession->attributes().read_sync(read_value(mPlainSizePropertyId));
  ASSERT_THAT(sizeRead, ServiceResultIsGood());
  ASSERT_EQ(sizeRead.results().size(), 1u);
  EXPECT_THAT(sizeRead.results()[0], HasStatusPresent(Status::BadNotSupported));
  EXPECT_EQ(sizeRead.results()[0].value().try_as<std::uint64_t>(), nullptr)
    << "Size reported a byte-count the server had no way to determine";
#else
  GTEST_SUCCEED() << "an indeterminable Size cannot be staged on a platform that will not unlink an "
                     "open file; the POSIX arm carries this requirement";
#endif
}

// Part 20 section 4.2.1: OpenCount is the number of currently valid file handles. A plausible
// implementation counts Open calls (never decrementing on Close), or counts the sessions holding
// handles rather than the handles themselves, so a delete refused by a lock cannot be explained.
// @verifies AC-SVR-FILE-004-OPENCOUNT
TEST_F(FileDirectoryTest, OpenCountEqualsTheNumberOfCurrentlyValidHandles)
{
  std::vector<std::uint32_t> handles;
  for (int attempt = 0; attempt < 3; ++attempt)
  {
    auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
      mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
    ASSERT_EQ(opened.results().size(), 1u);
    ASSERT_THAT(opened.results()[0].status_code(), Good());
    ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
    handles.push_back(opened.results()[0].output_arguments()[0].as<std::uint32_t>());
    ASSERT_NE(handles.back(), 0u);
  }
  ASSERT_EQ(handles.size(), 3u);

  auto beforeClose = mSession->attributes().read_sync(read_value(mCapOpenCountPropertyId));
  ASSERT_THAT(beforeClose, ServiceResultIsGood());
  ASSERT_EQ(beforeClose.results().size(), 1u);
  EXPECT_THAT(beforeClose.results()[0], good_value_of<std::uint16_t>(static_cast<std::uint16_t>(3)));

  auto closed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{handles.front()}}));
  ASSERT_EQ(closed.results().size(), 1u);
  ASSERT_THAT(closed.results()[0].status_code(), Good());

  // The two handles left are never closed: an abandoned handle still counts until the server
  // reclaims it, so the tally must be 2 and not 0.
  auto afterClose = mSession->attributes().read_sync(read_value(mCapOpenCountPropertyId));
  ASSERT_THAT(afterClose, ServiceResultIsGood());
  ASSERT_EQ(afterClose.results().size(), 1u);
  EXPECT_THAT(afterClose.results()[0], good_value_of<std::uint16_t>(static_cast<std::uint16_t>(2)));
}

// Part 20 section 4.2.1: an absent MaxByteStringLength Property means "no file-specific cap", and the
// ServerCapabilities value applies instead. A plausible implementation reads the per-file Property,
// finds nothing, and treats the chunk size as unbounded - serving a Read far larger than anything
// the server advertises it can carry.
// @verifies AC-SVR-FILE-005-MAXBYTESTRING-FALLBACK
TEST_F(FileDirectoryTest, AnAbsentMaxByteStringLengthFallsBackToTheServerCapability)
{
  ASSERT_FALSE(mPlainDeclaresMaxByteStringLength)
    << "the file under test declares its own MaxByteStringLength, so no fallback is exercised";
  ASSERT_GT(mPlainFileBytes.size(), static_cast<std::size_t>(serverMaxByteStringLength));

  auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
    mPlainFileNodeId, mPlainOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  const auto handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(handle, 0u);

  // Ask for the whole file in one chunk - more than the advertised capability. Whether the server
  // refuses the request or shortens it, no more than the capability may come back.
  const auto requested = static_cast<std::int32_t>(mPlainFileBytes.size());
  auto readCall = mSession->methods().try_call_sync(
    CallRequestBuilder().call(mPlainFileNodeId, mPlainReadMethodId, {Variant{handle}, Variant{requested}}));

  std::size_t returned = 0;
  if (readCall.is_good() && readCall.value().results().size() == 1u &&
      readCall.value().results()[0].status_code().is_good() &&
      !readCall.value().results()[0].output_arguments().empty())
  {
    const auto* data = readCall.value().results()[0].output_arguments()[0].try_as<ByteString>();
    ASSERT_NE(data, nullptr);
    returned = data->size();
  }
  EXPECT_LE(returned, static_cast<std::size_t>(serverMaxByteStringLength))
    << "Read served " << returned << " bytes from a file declaring no MaxByteStringLength, past the "
    << serverMaxByteStringLength << "-byte server capability";
}

// Part 20 section 4.2.1: LastModifiedTime shall be updated whenever the server detects that the file has
// changed. A plausible implementation stamps the Property from its own write path only, so a file
// rewritten out of band still reads as unchanged and a client caching on the timestamp never
// re-reads it.
// @verifies AC-SVR-FILE-006-LASTMODIFIEDTIME
TEST_F(FileDirectoryTest, LastModifiedTimeTracksServerSideAndDetectableExternalChanges)
{
  ASSERT_FALSE(mStampLastModifiedTimePropertyId.is_null())
    << "the FileType instance exposes no LastModifiedTime Property to observe";

  const auto readStamp = [this]()
  {
    auto response = mSession->attributes().read_sync(read_value(mStampLastModifiedTimePropertyId));
    EXPECT_THAT(response, ServiceResultIsGood());
    EXPECT_EQ(response.results().size(), 1u);
    DateTime stamp;
    if (response.results().size() == 1u)
    {
      const auto* held = response.results()[0].value().try_as<DateTime>();
      EXPECT_NE(held, nullptr) << "LastModifiedTime does not read as a DateTime";
      if (held != nullptr)
      {
        stamp = *held;
      }
    }
    return stamp;
  };

  const DateTime beforeAnyChange = readStamp();

  auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
    mStampFileNodeId, mStampOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  const auto handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(handle, 0u);

  const std::vector<std::uint8_t> payload{1, 2, 3, 4, 5, 6, 7, 8};
  auto written = mSession->methods().call_sync(CallRequestBuilder().call(
    mStampFileNodeId, mStampWriteMethodId, {Variant{handle}, Variant{ByteString{payload}}}));
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_THAT(written.results()[0].status_code(), Good());

  auto closed = mSession->methods().call_sync(
    CallRequestBuilder().call(mStampFileNodeId, mStampCloseMethodId, {Variant{handle}}));
  ASSERT_EQ(closed.results().size(), 1u);
  ASSERT_THAT(closed.results()[0].status_code(), Good());

  const DateTime afterServerWrite = readStamp();
  EXPECT_GT(afterServerWrite, beforeAnyChange)
    << "LastModifiedTime did not move for a write the server itself performed";

  // Out-of-band edit of the same backing file: the server can detect this one, so it is not
  // covered by the "detects" exemption.
  {
    std::ofstream external{mStampFilePath, std::ios::binary | std::ios::app};
    external.write("external", 8);
  }
  // A second later than the server's write, as an edit made later would be: the append alone can land on the
  // same coarse modification time as the server's write a few milliseconds before it.
  std::filesystem::last_write_time(
    mStampFilePath, std::filesystem::last_write_time(mStampFilePath) + std::chrono::seconds{1});

  const DateTime afterExternalChange = readStamp();
  EXPECT_GT(afterExternalChange, afterServerWrite)
    << "LastModifiedTime did not move for a detectable change made outside the server";
}

// Part 20 section 4.2.2: a fileHandle is unique for the Session and clients cannot transfer it to another
// Session. Handles are small integers, so a server keeping one global handle table - the obvious
// implementation - lets any client read a file it never opened by guessing.
// @verifies AC-SVR-FILE-007-HANDLE-SESSION-SCOPED
TEST_F(FileDirectoryTest, AFileHandleIsRefusedOnASessionThatDidNotOpenIt)
{
  auto opened = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  const auto handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(handle, 0u);

  auto borrower = mChannel->create_session_sync({.sessionName = "FileHandleScopeBorrower"});
  borrower.activate_sync();

  auto borrowed = borrower.methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{handle}, Variant{static_cast<std::int32_t>(16)}}));
  ASSERT_EQ(borrowed.results().size(), 1u);
  EXPECT_TRUE(borrowed.results()[0].status_code().is_bad())
    << "a fileHandle issued to another Session was accepted; status = 0x" << std::hex
    << borrowed.results()[0].status_code().as_uint32();

  std::size_t leaked = 0;
  if (!borrowed.results()[0].output_arguments().empty())
  {
    const auto* data = borrowed.results()[0].output_arguments()[0].try_as<ByteString>();
    if (data != nullptr)
    {
      leaked = data->size();
    }
  }
  EXPECT_EQ(leaked, 0u) << "file content was served to a Session that never opened the file";

  // Control: the handle is still live on the Session that owns it, so the refusal above is the
  // Session scope and not an expired or malformed handle.
  auto owner = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{handle}, Variant{static_cast<std::int32_t>(16)}}));
  ASSERT_EQ(owner.results().size(), 1u);
  EXPECT_THAT(owner.results()[0].status_code(), Good());

  (void)borrower.try_close_sync();
}

// Part 20 section 4.2.1: the mode byte is a permission mask - the Read and Write bits each gate the
// matching operation on the handle, and EraseExisting and Append take effect at Open. A plausible
// implementation opens the backing file in a stdio mode that happens to allow both directions
// ("r+" reads and writes) and never re-checks the bits, so a handle opened Write-only still serves
// the file's contents to a caller that asked for no read access at all.
// @verifies AC-SVR-FILE-008-OPEN-MODE-BITS
TEST_F(FileDirectoryTest, OpenModeBitsGovernWhichOperationsTheHandlePermits)
{
  const auto openWithMode = [this](std::uint8_t mode)
  {
    auto opened = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{mode}}));
    std::uint32_t handle = 0;
    EXPECT_EQ(opened.results().size(), 1u);
    if (opened.results().size() == 1u)
    {
      EXPECT_THAT(opened.results()[0].status_code(), Good())
        << "Open refused mode 0x" << std::hex << static_cast<unsigned>(mode);
      if (opened.results()[0].status_code().is_good() && !opened.results()[0].output_arguments().empty())
      {
        handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
      }
    }
    EXPECT_NE(handle, 0u);
    return handle;
  };

  const auto closeHandle = [this](std::uint32_t handle)
  {
    auto closed = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{handle}}));
    EXPECT_EQ(closed.results().size(), 1u);
    if (closed.results().size() == 1u)
    {
      EXPECT_THAT(closed.results()[0].status_code(), Good());
    }
  };

  const auto readDisk = [](const std::filesystem::path& path)
  {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    std::vector<std::uint8_t> bytes;
    if (!ec)
    {
      bytes.resize(static_cast<std::size_t>(size));
      std::ifstream input{path, std::ios::binary};
      if (!bytes.empty())
      {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      }
    }
    return bytes;
  };

  ASSERT_FALSE(mCapFileBytes.empty());
  ASSERT_EQ(readDisk(mCapFilePath), mCapFileBytes);

  // Read bit only: Write is not permitted, and a refusal that still mutated the file would be no
  // refusal at all, so the bytes on disk are the second half of the observation.
  const std::uint32_t readOnly = openWithMode(static_cast<std::uint8_t>(0x01));
  if (readOnly != 0u)
  {
    const std::vector<std::uint8_t> payload(64, static_cast<std::uint8_t>(0xEE));
    auto written = mSession->methods().call_sync(CallRequestBuilder().call(
      mCapFileNodeId, mCapWriteMethodId, {Variant{readOnly}, Variant{ByteString{payload}}}));
    ASSERT_EQ(written.results().size(), 1u);
    EXPECT_TRUE(written.results()[0].status_code().is_bad())
      << "Write was accepted on a handle opened without the Write bit";
    EXPECT_EQ(readDisk(mCapFilePath), mCapFileBytes)
      << "a Write issued on a read-only handle changed the file";
    closeHandle(readOnly);
  }

  // Write bit only: Read is not permitted, and no content may come back.
  const std::uint32_t writeOnly = openWithMode(static_cast<std::uint8_t>(0x02));
  if (writeOnly != 0u)
  {
    auto readBack = mSession->methods().call_sync(CallRequestBuilder().call(
      mCapFileNodeId, mCapReadMethodId, {Variant{writeOnly}, Variant{static_cast<std::int32_t>(32)}}));
    ASSERT_EQ(readBack.results().size(), 1u);
    EXPECT_TRUE(readBack.results()[0].status_code().is_bad())
      << "Read was accepted on a handle opened without the Read bit";
    std::size_t served = 0;
    if (!readBack.results()[0].output_arguments().empty())
    {
      const auto* data = readBack.results()[0].output_arguments()[0].try_as<ByteString>();
      if (data != nullptr)
      {
        served = data->size();
      }
    }
    EXPECT_EQ(served, 0u) << "file content was served through a handle opened without the Read bit";
    closeHandle(writeOnly);
  }

  // Append bit: the position is end-of-file the instant the handle exists, and the existing content
  // is untouched - both are decided at Open, not at the first Write.
  const std::uint32_t appending = openWithMode(static_cast<std::uint8_t>(0x02 | 0x08));
  if (appending != 0u)
  {
    auto position = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapGetPositionMethodId, {Variant{appending}}));
    ASSERT_EQ(position.results().size(), 1u);
    ASSERT_THAT(position.results()[0].status_code(), Good());
    ASSERT_EQ(position.results()[0].output_arguments().size(), 1u);
    EXPECT_EQ(position.results()[0].output_arguments()[0].as<std::uint64_t>(),
      static_cast<std::uint64_t>(mCapFileBytes.size()))
      << "the Append bit did not place the handle at the end of the file";
    EXPECT_EQ(readDisk(mCapFilePath), mCapFileBytes) << "opening with Append altered the file";
    closeHandle(appending);
  }

  // EraseExisting bit: the content is gone at Open, before anything has been written through it.
  const std::uint32_t erasing = openWithMode(static_cast<std::uint8_t>(0x02 | 0x04));
  if (erasing != 0u)
  {
    auto position = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapGetPositionMethodId, {Variant{erasing}}));
    ASSERT_EQ(position.results().size(), 1u);
    ASSERT_THAT(position.results()[0].status_code(), Good());
    ASSERT_EQ(position.results()[0].output_arguments().size(), 1u);
    EXPECT_EQ(position.results()[0].output_arguments()[0].as<std::uint64_t>(), std::uint64_t{0})
      << "the EraseExisting bit did not reset the position to the start of an emptied file";
    closeHandle(erasing);
    EXPECT_TRUE(readDisk(mCapFilePath).empty()) << "the EraseExisting bit left the previous content in place";
  }
}

// Part 20 section 4.2.1: writes are exclusive. While any handle is open on the file an Open-with-Write must
// fail Bad_NotWritable, yet several concurrent reads stay permitted - that second half is what keeps
// the rule from degenerating into an exclusive lock. A plausible implementation keeps no open-handle
// registry and just opens the backing file again, so a writer and a reader interleave on the same
// bytes and nothing in either result says so.
// @verifies AC-SVR-FILE-009-OPEN-WRITE-WHILE-OPEN
TEST_F(FileDirectoryTest, OpeningForWriteWhileTheFileIsOpenIsRefusedAndConcurrentReadsRemain)
{
  // Control: with nothing open, a write Open succeeds. The refusal asserted below is therefore the
  // lock and not a read-only file.
  auto control = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(control.results().size(), 1u);
  ASSERT_THAT(control.results()[0].status_code(), Good());
  ASSERT_EQ(control.results()[0].output_arguments().size(), 1u);
  const auto controlHandle = control.results()[0].output_arguments()[0].as<std::uint32_t>();
  auto controlClosed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{controlHandle}}));
  ASSERT_EQ(controlClosed.results().size(), 1u);
  ASSERT_THAT(controlClosed.results()[0].status_code(), Good());

  auto firstRead = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(firstRead.results().size(), 1u);
  ASSERT_THAT(firstRead.results()[0].status_code(), Good());
  ASSERT_EQ(firstRead.results()[0].output_arguments().size(), 1u);
  const auto firstHandle = firstRead.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(firstHandle, 0u);

  // Concurrent reads remain permitted.
  auto secondRead = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(secondRead.results().size(), 1u);
  EXPECT_THAT(secondRead.results()[0].status_code(), Good())
    << "a second concurrent read Open was refused; the write lock has become an exclusive lock";
  std::uint32_t secondHandle = 0;
  if (secondRead.results()[0].status_code().is_good() && !secondRead.results()[0].output_arguments().empty())
  {
    secondHandle = secondRead.results()[0].output_arguments()[0].as<std::uint32_t>();
    EXPECT_NE(secondHandle, firstHandle) << "the second read Open returned the first handle again";
  }

  auto writeOpen = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(writeOpen.results().size(), 1u);
  EXPECT_EQ(writeOpen.results()[0].status_code().as_status(), Status::BadNotWritable)
    << "Open-with-Write while a read handle is open returned 0x" << std::hex
    << writeOpen.results()[0].status_code().as_uint32();

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{firstHandle}}));
  if (secondHandle != 0u)
  {
    (void)mSession->methods().try_call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{secondHandle}}));
  }
}

// Part 20 section 4.2.1: while a writer holds a handle, a read Open is refused with Bad_NotReadable. The
// code names the operation that was requested, not the one already held, and that is the pair an
// implementation inverts - returning Bad_NotWritable because a writer is what it found. A server
// tracking no writer at all hands out the handle and lets the reader see half the old file and half
// the new.
// @verifies AC-SVR-FILE-010-OPEN-READ-WHILE-WRITING
TEST_F(FileDirectoryTest, OpeningForReadWhileTheFileIsOpenForWritingIsRefused)
{
  // Control: with no writer holding it, the file opens for read. The refusal below is therefore the
  // writer and not an unreadable file.
  auto control = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(control.results().size(), 1u);
  ASSERT_THAT(control.results()[0].status_code(), Good());
  ASSERT_EQ(control.results()[0].output_arguments().size(), 1u);
  const auto controlHandle = control.results()[0].output_arguments()[0].as<std::uint32_t>();
  auto controlClosed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{controlHandle}}));
  ASSERT_EQ(controlClosed.results().size(), 1u);
  ASSERT_THAT(controlClosed.results()[0].status_code(), Good());

  auto writer = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(writer.results().size(), 1u);
  ASSERT_THAT(writer.results()[0].status_code(), Good());
  ASSERT_EQ(writer.results()[0].output_arguments().size(), 1u);
  const auto writerHandle = writer.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(writerHandle, 0u);

  auto readOpen = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(readOpen.results().size(), 1u);
  EXPECT_EQ(readOpen.results()[0].status_code().as_status(), Status::BadNotReadable)
    << "Open-with-Read while a writer holds the file returned 0x" << std::hex
    << readOpen.results()[0].status_code().as_uint32()
    << " (Bad_NotWritable here would be the inverted pair)";

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{writerHandle}}));
}

// Part 20 section 4.2.2 Open result-code table: a mode the server cannot interpret - neither Read nor Write
// set, a reserved bit set, or EraseExisting without Write - is Bad_InvalidArgument. A plausible
// implementation reads only the two bits it needs and ignores the rest, so an undefined mode still
// yields a working handle: one that counts toward OpenCount and, until it is closed, blocks a delete.
// @verifies AC-SVR-FILE-011-INVALID-MODE
// @relation(AC-SVR-FILE-011-INVALID-MODE, scope=function)
TEST_F(FileDirectoryTest, OpenWithAnUndefinedModeIsRefusedWithoutIssuingAHandle)
{
  const auto expectRefused = [this](std::uint8_t mode, string_view what)
  {
    auto opened = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{mode}}));
    ASSERT_EQ(opened.results().size(), 1u);
    EXPECT_EQ(opened.results()[0].status_code().as_status(), Status::BadInvalidArgument)
      << what << " (mode 0x" << std::hex << numeric_cast<unsigned>(mode) << ") returned 0x"
      << opened.results()[0].status_code().as_uint32();

    std::uint32_t issued = 0;
    if (!opened.results()[0].output_arguments().empty())
    {
      const auto* held = opened.results()[0].output_arguments()[0].try_as<std::uint32_t>();
      if (held != nullptr)
      {
        issued = *held;
      }
    }
    EXPECT_EQ(issued, 0u) << what << " was refused but a file handle was issued anyway";
    if (issued != 0u)
    {
      // Release it, or the leaked handle keeps the file open for the rest of the test.
      (void)mSession->methods().try_call_sync(
        CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{issued}}));
    }
  };

  expectRefused(numeric_cast<std::uint8_t>(0x00), "a mode of zero");
  expectRefused(numeric_cast<std::uint8_t>(0x01 | 0x04), "EraseExisting without the Write bit");
  expectRefused(numeric_cast<std::uint8_t>(0x01 | 0x10), "a reserved bit set alongside Read");
}

// Part 20 section 4.2.2/section 4.2.3: Close ends the handle's life. Handles are allocated from a small
// integer space, so a server that only stops tracking the stream while still accepting the number may serve
// a later caller the wrong file; and a server that forgets to decrement OpenCount leaves the file
// looking permanently open. Both halves of the observation are asserted.
// @verifies AC-SVR-FILE-012-CLOSE-INVALIDATES
TEST_F(FileDirectoryTest, ClosingAFileInvalidatesTheHandleAndDecrementsOpenCount)
{
  const auto readOpenCount = [this]() -> std::optional<std::uint16_t>
  {
    auto response = mSession->attributes().read_sync(read_value(mCapOpenCountPropertyId));
    if (response.response_header().service_result().is_bad() || response.results().size() != 1u)
    {
      return std::nullopt;
    }
    const auto* held = response.results()[0].value().try_as<std::uint16_t>();
    if (held == nullptr)
    {
      return std::nullopt;
    }
    return *held;
  };

  const auto openReadHandle = [this]()
  {
    auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
      mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
    std::uint32_t handle = 0;
    EXPECT_EQ(opened.results().size(), 1u);
    if (opened.results().size() == 1u && opened.results()[0].status_code().is_good() &&
        !opened.results()[0].output_arguments().empty())
    {
      handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
    }
    EXPECT_NE(handle, 0u);
    return handle;
  };

  // Two handles, so the decrement is a fall from two to one and not merely a reset to zero.
  const std::uint32_t doomed = openReadHandle();
  const std::uint32_t survivor = openReadHandle();
  ASSERT_NE(doomed, 0u);
  ASSERT_NE(survivor, 0u);
  ASSERT_NE(doomed, survivor);

  const auto before = readOpenCount();
  ASSERT_TRUE(before.has_value());
  ASSERT_EQ(*before, static_cast<std::uint16_t>(2));

  auto closed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{doomed}}));
  ASSERT_EQ(closed.results().size(), 1u);
  ASSERT_THAT(closed.results()[0].status_code(), Good());

  const auto after = readOpenCount();
  ASSERT_TRUE(after.has_value());
  EXPECT_LT(*after, *before) << "OpenCount did not fall when a handle was closed";
  EXPECT_EQ(*after, static_cast<std::uint16_t>(1))
    << "the handle left open must still be counted after its sibling was closed";

  // The closed handle is dead for every per-handle method, and a Read that is refused must also
  // serve no bytes.
  auto staleRead = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{doomed}, Variant{static_cast<std::int32_t>(16)}}));
  ASSERT_EQ(staleRead.results().size(), 1u);
  EXPECT_EQ(staleRead.results()[0].status_code().as_status(), Status::BadInvalidArgument)
    << "Read accepted a closed file handle; status = 0x" << std::hex
    << staleRead.results()[0].status_code().as_uint32();
  std::size_t served = 0;
  if (!staleRead.results()[0].output_arguments().empty())
  {
    const auto* data = staleRead.results()[0].output_arguments()[0].try_as<ByteString>();
    if (data != nullptr)
    {
      served = data->size();
    }
  }
  EXPECT_EQ(served, 0u) << "file content was served through a closed handle";

  auto stalePosition = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapGetPositionMethodId, {Variant{doomed}}));
  ASSERT_EQ(stalePosition.results().size(), 1u);
  EXPECT_EQ(stalePosition.results()[0].status_code().as_status(), Status::BadInvalidArgument)
    << "GetPosition accepted a closed file handle";

  auto staleClose = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{doomed}}));
  ASSERT_EQ(staleClose.results().size(), 1u);
  EXPECT_EQ(staleClose.results()[0].status_code().as_status(), Status::BadInvalidArgument)
    << "Close accepted the handle it had already invalidated";

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{survivor}}));
}

// Part 20 section 4.2.4 result-code table: Read separates the caller's mistake from the handle's state - an
// unknown handle or a non-positive length is Bad_InvalidArgument, a handle opened without the Read
// bit is Bad_InvalidState. A plausible implementation clamps a negative length to zero and answers
// Good with an empty ByteString, which a client reads as end-of-file, and serves bytes on a
// write-only handle because the backing file was opened in a mode that happens to allow reading.
// @verifies AC-SVR-FILE-013-READ-VALIDATION
TEST_F(FileDirectoryTest, ReadRefusesAnUnknownHandleANegativeLengthAndAWriteOnlyHandle)
{
  const auto servedBytes = [](const auto& result)
  {
    std::size_t served = 0;
    if (!result.output_arguments().empty())
    {
      // `result` is a generic-lambda parameter, so the element type is dependent and `try_as`
      // needs the `template` disambiguator to parse as a template-id rather than a comparison.
      const auto* data = result.output_arguments()[0].template try_as<ByteString>();
      if (data != nullptr)
      {
        served = data->size();
      }
    }
    return served;
  };

  // (a) A handle that was never issued. mNextHandle counts up from 1, so this value cannot collide.
  const auto neverIssued = static_cast<std::uint32_t>(0x7FFFFFFF);
  auto unknownHandle = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{neverIssued}, Variant{static_cast<std::int32_t>(16)}}));
  ASSERT_EQ(unknownHandle.results().size(), 1u);
  EXPECT_EQ(unknownHandle.results()[0].status_code().as_status(), Status::BadInvalidArgument)
    << "Read on a handle that was never opened returned 0x" << std::hex
    << unknownHandle.results()[0].status_code().as_uint32();
  EXPECT_EQ(servedBytes(unknownHandle.results()[0]), 0u)
    << "file content was served for a handle that was never opened";

  // (b) A negative length on a perfectly good read handle.
  auto reader = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(reader.results().size(), 1u);
  ASSERT_THAT(reader.results()[0].status_code(), Good());
  ASSERT_EQ(reader.results()[0].output_arguments().size(), 1u);
  const auto readHandle = reader.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(readHandle, 0u);

  auto negativeLength = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{readHandle}, Variant{static_cast<std::int32_t>(-1)}}));
  ASSERT_EQ(negativeLength.results().size(), 1u);
  EXPECT_EQ(negativeLength.results()[0].status_code().as_status(), Status::BadInvalidArgument)
    << "Read with a negative length returned 0x" << std::hex
    << negativeLength.results()[0].status_code().as_uint32()
    << "; a Good empty ByteString here is indistinguishable from end-of-file";

  auto readerClosed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{readHandle}}));
  ASSERT_EQ(readerClosed.results().size(), 1u);
  ASSERT_THAT(readerClosed.results()[0].status_code(), Good());

  // (c) A handle opened for writing only: the fault is the handle's state, not the arguments.
  auto writer = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(writer.results().size(), 1u);
  ASSERT_THAT(writer.results()[0].status_code(), Good());
  ASSERT_EQ(writer.results()[0].output_arguments().size(), 1u);
  const auto writeHandle = writer.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(writeHandle, 0u);

  auto wrongMode = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapReadMethodId, {Variant{writeHandle}, Variant{static_cast<std::int32_t>(16)}}));
  ASSERT_EQ(wrongMode.results().size(), 1u);
  EXPECT_EQ(wrongMode.results()[0].status_code().as_status(), Status::BadInvalidState)
    << "Read on a handle opened without the Read bit returned 0x" << std::hex
    << wrongMode.results()[0].status_code().as_uint32()
    << "; Bad_InvalidArgument here would send the client to fix its arguments instead of its mode";
  EXPECT_EQ(servedBytes(wrongMode.results()[0]), 0u)
    << "file content was served through a handle opened without the Read bit";

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{writeHandle}}));
}

// Part 20 section 4.2.4: a Read that asks for more than remains returns everything up to the end with a
// Good status, a server may always return fewer bytes than asked for, and end-of-file is signalled
// by an EMPTY ByteString - not by a bad status. A plausible implementation reports a failure once it
// cannot fill the requested length, and a client streaming the file then throws away the tail it has
// already been handed and reports an error for a transfer that in fact completed.
// @verifies AC-SVR-FILE-014-READ-EOF
TEST_F(FileDirectoryTest, ReadReturnsWhatRemainsAndSignalsEndOfFileWithAnEmptyByteString)
{
  ASSERT_FALSE(mCapFileBytes.empty());

  auto opened = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  const auto handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(handle, 0u);

  // 512 is this file's own MaxByteStringLength, so a short answer is the end of the file or the
  // server's own chunking - never a request the server had to refuse for being oversized. The file
  // is 2000 bytes, so the last data-bearing Read necessarily asks for more than remains.
  const auto requested = static_cast<std::int32_t>(512);
  std::vector<std::uint8_t> assembled;
  bool sawShortRead = false;
  bool sawEndOfFile = false;
  for (int round = 0; round < 64 && !sawEndOfFile; ++round)
  {
    auto readBack = mSession->methods().call_sync(
      CallRequestBuilder().call(mCapFileNodeId, mCapReadMethodId, {Variant{handle}, Variant{requested}}));
    ASSERT_EQ(readBack.results().size(), 1u);
    ASSERT_THAT(readBack.results()[0].status_code(), Good())
      << "a Read reported a bad status after " << assembled.size() << " of " << mCapFileBytes.size()
      << " bytes; neither a short read nor end-of-file is an error";
    ASSERT_EQ(readBack.results()[0].output_arguments().size(), 1u);
    const auto* data = readBack.results()[0].output_arguments()[0].try_as<ByteString>();
    ASSERT_NE(data, nullptr);
    if (data->size() == 0u)
    {
      sawEndOfFile = true;
      break;
    }
    if (data->size() < static_cast<std::size_t>(requested))
    {
      sawShortRead = true;
    }
    assembled.insert(assembled.end(), data->begin(), data->end());
  }

  EXPECT_TRUE(sawEndOfFile)
    << "reading on past the last byte never produced the empty ByteString that signals end-of-file";
  EXPECT_TRUE(sawShortRead)
    << "no Read returned fewer bytes than requested, so the short-read path was never exercised";
  EXPECT_EQ(assembled, mCapFileBytes) << "the file was not delivered in full up to its end";

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{handle}}));
}

// Part 20 section 4.2.5: Write has three outcomes that must stay apart. Nothing to write is Good and leaves
// the file alone; a handle opened without the Write bit is Bad_InvalidState, the caller's own fault;
// a backing store that will not take the bytes is Bad_NotWritable, which is not. A plausible
// implementation lets whatever the backing adapter threw travel outward unchanged, so the store's
// refusal arrives as a generic internal error and the client is told to fix its own request.
// @relation(AC-SVR-FILE-015-WRITE-CONTRACT, scope=function)
TEST_F(FileDirectoryTest, WriteIsGoodForNoBytesInvalidStateOnAReadHandleAndNotWritableOnALockedStore)
{
  const auto readDisk = [](const std::filesystem::path& path)
  {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    std::vector<std::uint8_t> bytes;
    if (!ec)
    {
      bytes.resize(static_cast<std::size_t>(size));
      std::ifstream input{path, std::ios::binary};
      if (!bytes.empty())
      {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      }
    }
    return bytes;
  };

  ASSERT_FALSE(mCapFileBytes.empty());
  ASSERT_EQ(readDisk(mCapFilePath), mCapFileBytes);

  // (a) An empty ByteString on a genuine write handle: Good, and not one byte of the file moves.
  auto writer = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(writer.results().size(), 1u);
  ASSERT_THAT(writer.results()[0].status_code(), Good());
  ASSERT_EQ(writer.results()[0].output_arguments().size(), 1u);
  const auto writeHandle = writer.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(writeHandle, 0u);

  auto emptyWrite = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapWriteMethodId, {Variant{writeHandle}, Variant{ByteString{}}}));
  ASSERT_EQ(emptyWrite.results().size(), 1u);
  EXPECT_THAT(emptyWrite.results()[0].status_code(), Good()) << "writing no bytes is a no-op, not an error";
  EXPECT_EQ(readDisk(mCapFilePath), mCapFileBytes) << "an empty Write changed the file";

  auto writerClosed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{writeHandle}}));
  ASSERT_EQ(writerClosed.results().size(), 1u);
  ASSERT_THAT(writerClosed.results()[0].status_code(), Good());

  // (b) A handle opened for reading only: the handle is in the wrong state for the operation.
  auto reader = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(reader.results().size(), 1u);
  ASSERT_THAT(reader.results()[0].status_code(), Good());
  ASSERT_EQ(reader.results()[0].output_arguments().size(), 1u);
  const auto readHandle = reader.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(readHandle, 0u);

  const std::vector<std::uint8_t> payload(64, static_cast<std::uint8_t>(0xC3));
  auto wrongMode = mSession->methods().call_sync(CallRequestBuilder().call(
    mCapFileNodeId, mCapWriteMethodId, {Variant{readHandle}, Variant{ByteString{payload}}}));
  ASSERT_EQ(wrongMode.results().size(), 1u);
  EXPECT_EQ(wrongMode.results()[0].status_code().as_status(), Status::BadInvalidState)
    << "Write on a handle opened without the Write bit returned 0x" << std::hex
    << wrongMode.results()[0].status_code().as_uint32();
  EXPECT_EQ(readDisk(mCapFilePath), mCapFileBytes)
    << "a Write refused on a read handle still changed the file";

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{readHandle}}));

  // (c) A backing store that accepts no bytes at all. /dev/full opens for writing and then fails
  // every write with ENOSPC, which is the "file might be locked and thus not writable" condition of
  // the result table driven through the real adapter rather than simulated in the test. Windows ships
  // no equivalent always-unwritable device, so this arm is POSIX-only; (a) and (b) above are not.
#ifndef _WIN32
  const std::filesystem::path unwritableStore{"/dev/full"};
  ASSERT_TRUE(std::filesystem::exists(unwritableStore))
    << "no always-unwritable store is available to back a FileType with on this platform";

  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  auto lockedResult = FileHelper::try_create_sync(addressSpace,
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "LockedStoreFile"},
    unwritableStore,
    options,
    true);
  ASSERT_TRUE(lockedResult.is_good()) << "0x" << std::hex << lockedResult.status_code().as_uint32();
  auto lockedHelper = std::move(lockedResult).value();
  const NodeId lockedNodeId = lockedHelper.node_id();
  const NodeId lockedOpenId = lockedHelper.file().try_open_method_sync().value().get_node_id();
  const NodeId lockedWriteId = lockedHelper.file().try_write_method_sync().value().get_node_id();
  const NodeId lockedCloseId = lockedHelper.file().try_close_method_sync().value().get_node_id();
  lockedHelper.release();

  auto lockedOpen = mSession->methods().call_sync(
    CallRequestBuilder().call(lockedNodeId, lockedOpenId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(lockedOpen.results().size(), 1u);
  ASSERT_THAT(lockedOpen.results()[0].status_code(), Good())
    << "the unwritable store must open, or the Write below never reaches it";
  ASSERT_EQ(lockedOpen.results()[0].output_arguments().size(), 1u);
  const auto lockedHandle = lockedOpen.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(lockedHandle, 0u);

  // Several blocks, so the refusal cannot be hidden inside the adapter's own buffering.
  const std::vector<std::uint8_t> block(4000, static_cast<std::uint8_t>(0x5A));
  std::optional<StatusCode> firstRefusal;
  for (int round = 0; round < 8 && !firstRefusal.has_value(); ++round)
  {
    auto blocked = mSession->methods().call_sync(CallRequestBuilder().call(
      lockedNodeId, lockedWriteId, {Variant{lockedHandle}, Variant{ByteString{block}}}));
    ASSERT_EQ(blocked.results().size(), 1u);
    if (blocked.results()[0].status_code().is_bad())
    {
      firstRefusal = blocked.results()[0].status_code();
    }
  }
  EXPECT_TRUE(firstRefusal.has_value())
    << "every Write was reported Good against a store that cannot accept a single byte";
  if (firstRefusal.has_value())
  {
    EXPECT_EQ(firstRefusal->as_status(), Status::BadNotWritable)
      << "an unwritable backing store surfaced as 0x" << std::hex << firstRefusal->as_uint32()
      << " instead of Bad_NotWritable, which sends the client to fix its own request";
  }

  (void)mSession->methods().try_call_sync(
    CallRequestBuilder().call(lockedNodeId, lockedCloseId, {Variant{lockedHandle}}));
#endif
}

// Part 20 section 4.2.7: SetPosition saturates at the file size - a position past the end is not an error,
// it is how a client seeks to the end without first reading Size (which Part 20 section 4.2.1 lets a server
// refuse to give). A plausible implementation forwards the offset to the underlying stream, which
// rejects a seek beyond the length, so the call fails and the position is left wherever it was.
// @relation(AC-SVR-FILE-016-SETPOSITION-CLAMPS, scope=function)
TEST_F(FileDirectoryTest, SetPositionBeyondTheEndClampsToEndOfFile)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

  const auto seekPath = mDirPath / "seek.bin";
  const std::vector<std::uint8_t> seed(64, static_cast<std::uint8_t>(0xA5));
  {
    std::ofstream output{seekPath, std::ios::binary};
    output.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
  }

  auto createdResult = FileHelper::try_create_sync(
    addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "SeekFile"}, seekPath, options, true);
  ASSERT_TRUE(createdResult.is_good()) << "0x" << std::hex << createdResult.status_code().as_uint32();
  auto helper = std::move(createdResult).value();
  const NodeId nodeId = helper.node_id();
  const NodeId openId = helper.file().try_open_method_sync().value().get_node_id();
  const NodeId readId = helper.file().try_read_method_sync().value().get_node_id();
  const NodeId writeId = helper.file().try_write_method_sync().value().get_node_id();
  const NodeId getPositionId = helper.file().try_get_position_method_sync().value().get_node_id();
  const NodeId setPositionId = helper.file().try_set_position_method_sync().value().get_node_id();
  const NodeId closeId = helper.file().try_close_method_sync().value().get_node_id();
  helper.release();

  // Read and Write both set, so neither leg of the observation can be refused for the mode.
  auto opened = mSession->methods().call_sync(
    CallRequestBuilder().call(nodeId, openId, {Variant{static_cast<std::uint8_t>(0x01 | 0x02)}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
  const auto handle = opened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(handle, 0u);

  const auto beyondEnd = static_cast<std::uint64_t>(seed.size()) + 1000u;
  auto positioned = mSession->methods().call_sync(
    CallRequestBuilder().call(nodeId, setPositionId, {Variant{handle}, Variant{beyondEnd}}));
  ASSERT_EQ(positioned.results().size(), 1u);
  EXPECT_THAT(positioned.results()[0].status_code(), Good())
    << "SetPosition past the end must clamp, not fail; status = 0x" << std::hex
    << positioned.results()[0].status_code().as_uint32();

  auto position =
    mSession->methods().call_sync(CallRequestBuilder().call(nodeId, getPositionId, {Variant{handle}}));
  ASSERT_EQ(position.results().size(), 1u);
  ASSERT_THAT(position.results()[0].status_code(), Good());
  ASSERT_EQ(position.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(
    position.results()[0].output_arguments()[0].as<std::uint64_t>(), static_cast<std::uint64_t>(seed.size()))
    << "the position was not clamped to the end of the file";

  auto readBack = mSession->methods().call_sync(
    CallRequestBuilder().call(nodeId, readId, {Variant{handle}, Variant{static_cast<std::int32_t>(32)}}));
  ASSERT_EQ(readBack.results().size(), 1u);
  EXPECT_THAT(readBack.results()[0].status_code(), Good())
    << "a Read at the clamped end-of-file position is end-of-file, not an error";
  std::size_t served = 0;
  if (!readBack.results()[0].output_arguments().empty())
  {
    const auto* data = readBack.results()[0].output_arguments()[0].try_as<ByteString>();
    if (data != nullptr)
    {
      served = data->size();
    }
  }
  EXPECT_EQ(served, 0u) << "a Read at the end of the file returned bytes";

  const std::vector<std::uint8_t> appended(16, static_cast<std::uint8_t>(0x3C));
  auto written = mSession->methods().call_sync(
    CallRequestBuilder().call(nodeId, writeId, {Variant{handle}, Variant{ByteString{appended}}}));
  ASSERT_EQ(written.results().size(), 1u);
  EXPECT_THAT(written.results()[0].status_code(), Good());

  auto closed = mSession->methods().call_sync(CallRequestBuilder().call(nodeId, closeId, {Variant{handle}}));
  ASSERT_EQ(closed.results().size(), 1u);
  ASSERT_THAT(closed.results()[0].status_code(), Good());

  std::vector<std::uint8_t> expected = seed;
  expected.insert(expected.end(), appended.begin(), appended.end());
  std::vector<std::uint8_t> onDisk;
  {
    std::error_code ec;
    const auto size = std::filesystem::file_size(seekPath, ec);
    ASSERT_FALSE(ec);
    onDisk.resize(static_cast<std::size_t>(size));
    std::ifstream input{seekPath, std::ios::binary};
    if (!onDisk.empty())
    {
      input.read(reinterpret_cast<char*>(onDisk.data()), static_cast<std::streamsize>(onDisk.size()));
    }
  }
  EXPECT_EQ(onDisk, expected)
    << "the Write after a clamped SetPosition did not append to the end of the file";
}

// Part 20 section 4.2.2: a file handle is valid only while the Session that opened it is open, so a Session
// that ends without closing its handles must have them released for it. A plausible implementation
// keys its open-handle table by handle id alone, with nothing tying a handle to a Session, so a
// client that disconnects leaves the file open for the life of the server - and by Part 20 section 4.2.1
// an open file cannot be opened for writing, making it permanently read-only for everyone else.
// @verifies AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE
// @relation(AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE, scope=function)
TEST_F(FileDirectoryTest, ClosingASessionReleasesTheFileHandlesItLeftOpen)
{
  const auto readOpenCount = [this]() -> std::optional<std::uint16_t>
  {
    auto response = mSession->attributes().read_sync(read_value(mCapOpenCountPropertyId));
    if (response.response_header().service_result().is_bad() || response.results().size() != 1u)
    {
      return std::nullopt;
    }
    const auto* held = response.results()[0].value().try_as<std::uint16_t>();
    if (held == nullptr)
    {
      return std::nullopt;
    }
    return *held;
  };

  const auto before = readOpenCount();
  ASSERT_TRUE(before.has_value());

  auto leaver = mChannel->create_session_sync({.sessionName = "FileHandleLeaver"});
  leaver.activate_sync();

  for (int attempt = 0; attempt < 2; ++attempt)
  {
    auto opened = leaver.methods().call_sync(CallRequestBuilder().call(
      mCapFileNodeId, mCapOpenMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
    ASSERT_EQ(opened.results().size(), 1u);
    ASSERT_THAT(opened.results()[0].status_code(), Good());
    ASSERT_EQ(opened.results()[0].output_arguments().size(), 1u);
    ASSERT_NE(opened.results()[0].output_arguments()[0].as<std::uint32_t>(), 0u);
  }

  // Observed from the surviving Session: the handles really are registered, so the reading after the
  // close is a release and not a count that never moved.
  const auto whileOpen = readOpenCount();
  ASSERT_TRUE(whileOpen.has_value());
  ASSERT_EQ(*whileOpen, static_cast<std::uint16_t>(*before + 2))
    << "the second Session's handles were never counted, so nothing here is being released";

  // The handles are deliberately NOT closed: ending the Session is the only release.
  const auto sessionClosed = leaver.try_close_sync();
  ASSERT_TRUE(sessionClosed.is_good()) << "0x" << std::hex << sessionClosed.status_code().as_uint32();

  std::optional<std::uint16_t> after;
  for (int attempt = 0; attempt < 100; ++attempt)
  {
    after = readOpenCount();
    if (after.has_value() && *after == *before)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  ASSERT_TRUE(after.has_value());
  EXPECT_EQ(*after, *before) << "OpenCount stayed at " << *after
                             << " after the Session holding the handles closed; the file "
                                "is now held open by a client that no longer exists";
}

// Part 20 section 4.3.2: the Object at the root of a file directory structure shall have the BrowseName
// FileSystem, and section 4.3.3 requires CreateDirectory to refuse a name already present under the same
// parent with Bad_BrowseNameDuplicated. The application configures the generic helper's designated
// root with the normative name; the negative then proves that a filesystem no-op cannot publish a
// second same-name child and make every path beneath it ambiguous.
// @relation(AC-SVR-FILE-018-FILESYSTEM-ROOT-BROWSENAME, scope=function)
// @relation(AC-SVR-FILE-018-DUPLICATE-DIRECTORY-REFUSED, scope=function)
TEST_F(FileDirectoryTest, TheFileDirectoryRootIsNamedFileSystemAndDuplicateDirectoriesAreRefused)
{
  auto rootRead = mSession->attributes().read_sync(read_value(mDirNodeId, AttributeId::BrowseName));
  ASSERT_THAT(rootRead, ServiceResultIsGood());
  ASSERT_EQ(rootRead.results().size(), 1u);
  const auto* rootName = rootRead.results()[0].value().try_as<QualifiedName>();
  ASSERT_NE(rootName, nullptr) << "the file-directory root has no readable BrowseName";
  EXPECT_EQ(std::string_view{rootName->name()}, "FileSystem")
    << "the root of the file directory structure carries an application-chosen BrowseName, so a "
       "client navigating to the normative FileSystem root finds nothing";

  auto first = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mCreateDirMethodId, {Variant{String{"twice"}}}));
  ASSERT_EQ(first.results().size(), 1u);
  ASSERT_THAT(first.results()[0].status_code(), Good());
  ASSERT_EQ(first.results()[0].output_arguments().size(), 1u);
  const auto firstNode = first.results()[0].output_arguments()[0].as<NodeId>();
  ASSERT_FALSE(firstNode.is_null());
  ASSERT_TRUE(std::filesystem::exists(mDirPath / "twice"));

  auto second = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mCreateDirMethodId, {Variant{String{"twice"}}}));
  ASSERT_EQ(second.results().size(), 1u);
  EXPECT_EQ(second.results()[0].status_code().as_status(), Status::BadBrowseNameDuplicated)
    << "creating a directory whose name already exists returned 0x" << std::hex
    << second.results()[0].status_code().as_uint32();

  NodeId secondNode;
  if (!second.results()[0].output_arguments().empty())
  {
    const auto* held = second.results()[0].output_arguments()[0].try_as<NodeId>();
    if (held != nullptr)
    {
      secondNode = *held;
    }
  }
  EXPECT_TRUE(secondNode.is_null() || secondNode == firstNode)
    << "a second directory node was created for a name that was already taken";

  // The duplicate, if one was made, is still in the address space at this point: browse the parent
  // and count the children carrying the name.
  auto browsed = mSession->view().browse_sync(browse(mDirNodeId));
  ASSERT_EQ(browsed.results().size(), 1u);
  ASSERT_FALSE(browsed.results()[0].status_code().is_bad());
  ASSERT_FALSE(browsed.results()[0].references().empty())
    << "the file-directory root browses to nothing, so no duplicate could be seen either way";
  std::size_t namedTwice = 0;
  for (const auto& reference : browsed.results()[0].references())
  {
    if (std::string_view{reference.browse_name().name()} == std::string_view{"twice"})
    {
      ++namedTwice;
    }
  }
  EXPECT_EQ(namedTwice, 1u) << "the directory holds " << namedTwice
                            << " children named 'twice'; every path beneath them is ambiguous";
}

// Part 20 section 4.3.4: CreateFile is "create, and maybe open". With `requestFileOpen` TRUE the server
// creates the file, opens it with the Read and Write bits set, and returns that handle; with FALSE
// the returned fileHandle shall be 0 and the caller is told to ignore it. A plausible implementation
// returns one value in both branches - always 0, so the TRUE branch is a promise the client only
// discovers is empty at its first Read; or always a live handle, which leaks one the caller never
// asked for and, by Part 20 section 4.2.1, keeps the new file open and undeletable until the Session ends.
// @verifies AC-SVR-FILE-019-CREATEFILE-REQUESTFILEOPEN
TEST_F(FileDirectoryTest, CreateFileIssuesAUsableHandleExactlyWhenRequestFileOpenIsSet)
{
  const auto findChild = [this](const NodeId& parent, std::string_view name)
  {
    NodeId found;
    auto browsed = mSession->view().browse_sync(browse(parent));
    if (browsed.results().size() == 1u && !browsed.results()[0].status_code().is_bad())
    {
      for (const auto& reference : browsed.results()[0].references())
      {
        if (std::string_view{reference.browse_name().name()} == name)
        {
          found = reference.node_id().node_id();
          break;
        }
      }
    }
    return found;
  };

  const auto readOpenCount = [this, &findChild](const NodeId& fileNode) -> std::optional<std::uint16_t>
  {
    const NodeId openCountId = findChild(fileNode, "OpenCount");
    if (openCountId.is_null())
    {
      return std::nullopt;
    }
    auto response = mSession->attributes().read_sync(read_value(openCountId));
    if (response.response_header().service_result().is_bad() || response.results().size() != 1u)
    {
      return std::nullopt;
    }
    const auto* held = response.results()[0].value().try_as<std::uint16_t>();
    if (held == nullptr)
    {
      return std::nullopt;
    }
    return *held;
  };

  // (a) requestFileOpen TRUE: the handle must actually carry both bits, so both directions are
  // driven through it rather than trusting the number to be non-zero.
  auto opened = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"opened.bin"}}, Variant{true}}));
  ASSERT_EQ(opened.results().size(), 1u);
  ASSERT_THAT(opened.results()[0].status_code(), Good());
  ASSERT_GE(opened.results()[0].output_arguments().size(), 2u)
    << "CreateFile returned no fileHandle output at all, so neither branch is expressible";
  const auto openedNode = opened.results()[0].output_arguments()[0].as<NodeId>();
  const auto openedHandle = opened.results()[0].output_arguments()[1].as<std::uint32_t>();
  ASSERT_FALSE(openedNode.is_null());
  ASSERT_TRUE(std::filesystem::exists(mDirPath / "opened.bin"));
  EXPECT_NE(openedHandle, 0u)
    << "requestFileOpen TRUE returned the 0 sentinel, which the specification tells the caller to ignore";

  const NodeId openedReadId = findChild(openedNode, "Read");
  const NodeId openedWriteId = findChild(openedNode, "Write");
  ASSERT_FALSE(openedReadId.is_null()) << "the created FileType node exposes no Read Method";
  ASSERT_FALSE(openedWriteId.is_null()) << "the created FileType node exposes no Write Method";

  if (openedHandle != 0u)
  {
    auto readBack = mSession->methods().call_sync(CallRequestBuilder().call(
      openedNode, openedReadId, {Variant{openedHandle}, Variant{static_cast<std::int32_t>(16)}}));
    ASSERT_EQ(readBack.results().size(), 1u);
    EXPECT_THAT(readBack.results()[0].status_code(), Good())
      << "the handle CreateFile issued does not carry the Read bit; status = 0x" << std::hex
      << readBack.results()[0].status_code().as_uint32();

    const std::vector<std::uint8_t> payload(8, static_cast<std::uint8_t>(0x7E));
    auto written = mSession->methods().call_sync(CallRequestBuilder().call(
      openedNode, openedWriteId, {Variant{openedHandle}, Variant{ByteString{payload}}}));
    ASSERT_EQ(written.results().size(), 1u);
    EXPECT_THAT(written.results()[0].status_code(), Good())
      << "the handle CreateFile issued does not carry the Write bit; status = 0x" << std::hex
      << written.results()[0].status_code().as_uint32();
  }

  const auto openedCount = readOpenCount(openedNode);
  ASSERT_TRUE(openedCount.has_value()) << "the created FileType node exposes no readable OpenCount";
  EXPECT_EQ(*openedCount, static_cast<std::uint16_t>(1))
    << "a file created with requestFileOpen TRUE reports OpenCount " << *openedCount
    << ", so the handle it handed back is not registered against the file";

  // (b) requestFileOpen FALSE: no handle, and nothing is holding the new file open.
  auto plain = mSession->methods().call_sync(CallRequestBuilder().call(
    mDirNodeId, mCreateFileMethodId, {Variant{String{"unopened.bin"}}, Variant{false}}));
  ASSERT_EQ(plain.results().size(), 1u);
  ASSERT_THAT(plain.results()[0].status_code(), Good());
  ASSERT_GE(plain.results()[0].output_arguments().size(), 2u);
  const auto plainNode = plain.results()[0].output_arguments()[0].as<NodeId>();
  ASSERT_FALSE(plainNode.is_null());
  ASSERT_TRUE(std::filesystem::exists(mDirPath / "unopened.bin"));
  EXPECT_EQ(plain.results()[0].output_arguments()[1].as<std::uint32_t>(), 0u)
    << "requestFileOpen FALSE returned an apparently-valid fileHandle the client may try to use";

  const auto plainCount = readOpenCount(plainNode);
  ASSERT_TRUE(plainCount.has_value()) << "the created FileType node exposes no readable OpenCount";
  EXPECT_EQ(*plainCount, static_cast<std::uint16_t>(0))
    << "a file created without requestFileOpen already counts " << *plainCount
    << " open handles, so a handle nobody asked for is holding it open";
}

// Part 20 section 4.3.5: deleting a directory deletes every file and directory Object below it in one call,
// and a file or directory that is locked - any node under it holding an open handle - must be
// refused with Bad_InvalidState. A plausible implementation tests the lock only on the node it was
// handed and then walks the subtree removing as it goes, so a directory holding one open file loses
// its siblings before the walk reaches the lock and the caller is left with a half-deleted tree and
// an error naming none of it.
// @verifies AC-SVR-FILE-020-DELETE-RECURSIVE
TEST_F(FileDirectoryTest, DeletingADirectoryRemovesItsWholeSubtreeAndIsRefusedWhileAnythingUnderItIsOpen)
{
  const auto findChild = [this](const NodeId& parent, std::string_view name)
  {
    NodeId found;
    auto browsed = mSession->view().browse_sync(browse(parent));
    if (browsed.results().size() == 1u && !browsed.results()[0].status_code().is_bad())
    {
      for (const auto& reference : browsed.results()[0].references())
      {
        if (std::string_view{reference.browse_name().name()} == name)
        {
          found = reference.node_id().node_id();
          break;
        }
      }
    }
    return found;
  };

  const auto nodeIsPresent = [this](const NodeId& nodeId)
  {
    auto probe = mSession->attributes().read_sync(read_value(nodeId, AttributeId::NodeClass));
    if (probe.response_header().service_result().is_bad() || probe.results().size() != 1u)
    {
      return false;
    }
    return probe.results()[0].status().value_or(StatusCode{Status::Good}).is_good();
  };

  const auto createChild = [this](const NodeId& directory,
                             const NodeId& method,
                             const char* name,
                             std::initializer_list<Variant>
                               arguments)
  {
    auto response = mSession->methods().call_sync(CallRequestBuilder().call(directory, method, arguments));
    NodeId created;
    EXPECT_EQ(response.results().size(), 1u);
    if (response.results().size() == 1u)
    {
      EXPECT_THAT(response.results()[0].status_code(), Good()) << "creating '" << name << "' failed";
      if (!response.results()[0].output_arguments().empty())
      {
        created = response.results()[0].output_arguments()[0].as<NodeId>();
      }
    }
    EXPECT_FALSE(created.is_null()) << "creating '" << name << "' returned no node";
    return created;
  };

  // (a) A directory holding a file and a sub-directory that itself holds a file.
  const NodeId treeNode = createChild(mDirNodeId, mCreateDirMethodId, "tree", {Variant{String{"tree"}}});
  ASSERT_FALSE(treeNode.is_null());
  const NodeId treeCreateFileId = findChild(treeNode, "CreateFile");
  const NodeId treeCreateDirId = findChild(treeNode, "CreateDirectory");
  ASSERT_FALSE(treeCreateFileId.is_null()) << "the created directory exposes no CreateFile Method";
  ASSERT_FALSE(treeCreateDirId.is_null()) << "the created directory exposes no CreateDirectory Method";

  const NodeId leafNode =
    createChild(treeNode, treeCreateFileId, "tree/leaf.bin", {Variant{String{"leaf.bin"}}, Variant{false}});
  const NodeId nestedNode =
    createChild(treeNode, treeCreateDirId, "tree/nested", {Variant{String{"nested"}}});
  ASSERT_FALSE(leafNode.is_null());
  ASSERT_FALSE(nestedNode.is_null());
  const NodeId nestedCreateFileId = findChild(nestedNode, "CreateFile");
  ASSERT_FALSE(nestedCreateFileId.is_null()) << "the nested directory exposes no CreateFile Method";
  const NodeId deepNode = createChild(
    nestedNode, nestedCreateFileId, "tree/nested/deep.bin", {Variant{String{"deep.bin"}}, Variant{false}});
  ASSERT_FALSE(deepNode.is_null());

  ASSERT_TRUE(std::filesystem::exists(mDirPath / "tree" / "leaf.bin"));
  ASSERT_TRUE(std::filesystem::exists(mDirPath / "tree" / "nested" / "deep.bin"));
  ASSERT_TRUE(nodeIsPresent(deepNode)) << "the deepest node was never in the address space";

  auto recursive = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mDeleteMethodId, {Variant{treeNode}}));
  ASSERT_EQ(recursive.results().size(), 1u);
  EXPECT_THAT(recursive.results()[0].status_code(), Good())
    << "deleting a non-empty directory returned 0x" << std::hex
    << recursive.results()[0].status_code().as_uint32() << "; the deletion is recursive, not refused";
  EXPECT_FALSE(std::filesystem::exists(mDirPath / "tree")) << "the directory tree survived a Delete on disk";
  EXPECT_FALSE(nodeIsPresent(leafNode)) << "the child file node survived its directory's Delete";
  EXPECT_FALSE(nodeIsPresent(nestedNode)) << "the sub-directory node survived its parent's Delete";
  EXPECT_FALSE(nodeIsPresent(deepNode))
    << "a file two levels down survived the Delete, so the removal did not recurse";

  // (b) A file with an open handle is locked and cannot be deleted.
  const NodeId heldNode =
    createChild(mDirNodeId, mCreateFileMethodId, "held.bin", {Variant{String{"held.bin"}}, Variant{false}});
  ASSERT_FALSE(heldNode.is_null());
  const NodeId heldOpenId = findChild(heldNode, "Open");
  ASSERT_FALSE(heldOpenId.is_null()) << "the created FileType node exposes no Open Method";
  auto heldOpened = mSession->methods().call_sync(
    CallRequestBuilder().call(heldNode, heldOpenId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(heldOpened.results().size(), 1u);
  ASSERT_THAT(heldOpened.results()[0].status_code(), Good());
  ASSERT_EQ(heldOpened.results()[0].output_arguments().size(), 1u);
  const auto heldHandle = heldOpened.results()[0].output_arguments()[0].as<std::uint32_t>();
  ASSERT_NE(heldHandle, 0u);

  auto deleteHeld = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mDeleteMethodId, {Variant{heldNode}}));
  ASSERT_EQ(deleteHeld.results().size(), 1u);
  EXPECT_EQ(deleteHeld.results()[0].status_code().as_status(), Status::BadInvalidState)
    << "deleting a file that a client holds open returned 0x" << std::hex
    << deleteHeld.results()[0].status_code().as_uint32();
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "held.bin"))
    << "a Delete refused for the lock still removed the file from disk";
  EXPECT_TRUE(nodeIsPresent(heldNode)) << "a Delete refused for the lock still removed the file node";

  // (c) A directory whose descendant is open: the lock is below the target, and nothing may be
  // removed before the refusal is decided.
  const NodeId lockedDirNode =
    createChild(mDirNodeId, mCreateDirMethodId, "lockeddir", {Variant{String{"lockeddir"}}});
  ASSERT_FALSE(lockedDirNode.is_null());
  const NodeId lockedCreateFileId = findChild(lockedDirNode, "CreateFile");
  ASSERT_FALSE(lockedCreateFileId.is_null()) << "the created directory exposes no CreateFile Method";
  const NodeId innerNode = createChild(
    lockedDirNode, lockedCreateFileId, "lockeddir/inner.bin", {Variant{String{"inner.bin"}}, Variant{false}});
  const NodeId siblingNode = createChild(lockedDirNode,
    lockedCreateFileId,
    "lockeddir/sibling.bin",
    {Variant{String{"sibling.bin"}}, Variant{false}});
  ASSERT_FALSE(innerNode.is_null());
  ASSERT_FALSE(siblingNode.is_null());

  const NodeId innerOpenId = findChild(innerNode, "Open");
  ASSERT_FALSE(innerOpenId.is_null()) << "the nested FileType node exposes no Open Method";
  auto innerOpened = mSession->methods().call_sync(
    CallRequestBuilder().call(innerNode, innerOpenId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  ASSERT_EQ(innerOpened.results().size(), 1u);
  ASSERT_THAT(innerOpened.results()[0].status_code(), Good());
  ASSERT_EQ(innerOpened.results()[0].output_arguments().size(), 1u);
  ASSERT_NE(innerOpened.results()[0].output_arguments()[0].as<std::uint32_t>(), 0u);

  auto deleteLockedDir = mSession->methods().call_sync(
    CallRequestBuilder().call(mDirNodeId, mDeleteMethodId, {Variant{lockedDirNode}}));
  ASSERT_EQ(deleteLockedDir.results().size(), 1u);
  EXPECT_EQ(deleteLockedDir.results()[0].status_code().as_status(), Status::BadInvalidState)
    << "deleting a directory holding an open file returned 0x" << std::hex
    << deleteLockedDir.results()[0].status_code().as_uint32();
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "lockeddir" / "sibling.bin"))
    << "the sibling of the locked file was removed before the Delete was refused";
  EXPECT_TRUE(std::filesystem::exists(mDirPath / "lockeddir" / "inner.bin"))
    << "the locked file itself was removed by a Delete that then reported failure";
  EXPECT_TRUE(nodeIsPresent(siblingNode))
    << "the sibling node was removed before the Delete was refused, leaving a partly-deleted tree";
  EXPECT_TRUE(nodeIsPresent(lockedDirNode)) << "the refused directory node was removed anyway";
}

namespace
{

/// The NodeIds a temporary-file-transfer obligation is driven through, resolved once from a live
/// TemporaryFileTransferType instance.
///
/// Any member left null means the instance did not expose that member; every test asserts on the
/// members it uses before driving them, so a missing member is reported rather than skipped past.
struct TempTransferNodes
{
  NodeId transferId;  ///< The TemporaryFileTransferType instance itself.
  NodeId generateForReadId;  ///< Its GenerateFileForRead Method.
  NodeId generateForWriteId;  ///< Its GenerateFileForWrite Method.
  NodeId closeAndCommitId;  ///< Its CloseAndCommit Method.
  NodeId clientProcessingTimeoutId;  ///< Its ClientProcessingTimeout Property.
};

/// Instantiates a TemporaryFileTransferType node backed by @p tempDir and resolves its members.
///
/// The host hooks are deliberately left unset: the obligations below are about the transfer
/// machinery - what it returns, what it publishes, and what it reclaims - not about what an
/// application makes of the transferred bytes.
TempTransferNodes make_temp_transfer(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, InstantiationOptions options, std::filesystem::path tempDir)
{
  options.optionalChildFilter = [](const ChildFilterInfo& child)
  {
    return child.browseName.name() == "ClientProcessingTimeout";
  };

  TemporaryFileTransferConfig config;
  config.tempDir = std::move(tempDir);
  config.transientFileParent = parent;

  TempTransferNodes nodes;
  auto result = TemporaryFileTransferHelper::try_create_sync(
    addressSpace, parent, browseName, options, std::move(config));
  if (result.is_bad())
  {
    return nodes;
  }
  auto helper = std::move(result).value();
  nodes.transferId = helper.node_id();
  if (auto method = helper.transfer().try_generate_file_for_read_method_sync(); method.is_good())
  {
    nodes.generateForReadId = method.value().get_node_id();
  }
  if (auto method = helper.transfer().try_generate_file_for_write_method_sync(); method.is_good())
  {
    nodes.generateForWriteId = method.value().get_node_id();
  }
  if (auto method = helper.transfer().try_close_and_commit_method_sync(); method.is_good())
  {
    nodes.closeAndCommitId = method.value().get_node_id();
  }
  if (auto property = helper.transfer().try_client_processing_timeout_property_sync(); property.is_good())
  {
    nodes.clientProcessingTimeoutId = property.value().node_id();
  }
  helper.release();
  return nodes;
}

}  // namespace

// Part 20 section 4.4.1: the temporary FileType Object a transfer Method generates is not browsable in the
// AddressSpace and can only be reached with the NodeId and FileHandle the Method returned. A
// plausible implementation instantiates the transient node under an ordinary parent like every other
// node, so it appears in that parent's Browse response and its NodeId - the Method's only capability
// token - becomes discoverable by any client that browses the tree.
// @verifies AC-SVR-FILE-021-TEMP-FILE-NOT-BROWSABLE
TEST_F(FileDirectoryTest, AGeneratedTemporaryFileIsReachableByNodeIdButNotByBrowsing)
{
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  const auto nodes = make_temp_transfer(mServer.server().address_space(),
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "BrowseHiddenXfer"},
    options,
    mDirPath / "xfer_browse");
  ASSERT_FALSE(nodes.transferId.is_null()) << "the TemporaryFileTransferType instance was not created";
  ASSERT_FALSE(nodes.generateForReadId.is_null()) << "the transfer exposes no GenerateFileForRead Method";

  auto generated = mSession->methods().call_sync(
    CallRequestBuilder().call(nodes.transferId, nodes.generateForReadId, {Variant{}}));
  ASSERT_EQ(generated.results().size(), 1u);
  ASSERT_THAT(generated.results()[0].status_code(), Good());
  ASSERT_GE(generated.results()[0].output_arguments().size(), 2u);
  const auto tempNode = generated.results()[0].output_arguments()[0].as<NodeId>();
  ASSERT_FALSE(tempNode.is_null()) << "GenerateFileForRead returned no temporary FileType NodeId";

  // The other half of the obligation: the NodeId the Method handed back is the way in, so it must
  // resolve. Without this a server that returned a NodeId for nothing at all would pass.
  auto direct = mSession->attributes().read_sync(read_value(tempNode, AttributeId::NodeClass));
  ASSERT_THAT(direct, ServiceResultIsGood());
  ASSERT_EQ(direct.results().size(), 1u);
  EXPECT_TRUE(direct.results()[0].status().value_or(StatusCode{Status::Good}).is_good())
    << "the temporary FileType NodeId the Method returned does not resolve, so nothing is accessible";

  const auto browseShowsTempNode = [this, &tempNode](const NodeId& parent, std::string& offender)
  {
    auto browsed = mSession->view().browse_sync(browse(parent));
    EXPECT_EQ(browsed.results().size(), 1u);
    if (browsed.results().size() != 1u || browsed.results()[0].status_code().is_bad())
    {
      return false;
    }
    for (const auto& reference : browsed.results()[0].references())
    {
      if (reference.node_id().node_id() == tempNode)
      {
        offender = std::string{std::string_view{reference.browse_name().name()}};
        return true;
      }
    }
    return false;
  };

  // The folder the transfer object was configured to hang its transient nodes under, and the
  // transfer object itself - the two places a client would find it by walking the hierarchy.
  auto siblings = mSession->view().browse_sync(browse(mTestFolderId));
  ASSERT_EQ(siblings.results().size(), 1u);
  ASSERT_FALSE(siblings.results()[0].references().empty())
    << "the folder under test browses to nothing, so no leak could be seen either way";

  std::string offender;
  EXPECT_FALSE(browseShowsTempNode(mTestFolderId, offender))
    << "the temporary FileType Object is browsable as '" << offender
    << "', so its NodeId is discoverable by any client instead of only by the caller";
  offender.clear();
  EXPECT_FALSE(browseShowsTempNode(nodes.transferId, offender))
    << "the temporary FileType Object is browsable under the transfer Object as '" << offender << "'";
}

// Part 20 section 4.4.1: any open temporary transfer file shall be deleted once the Session that created it
// is no longer valid. A plausible implementation ties the transient node's life to CloseAndCommit
// alone, so a client that disconnects mid-transfer leaves the node and its backing file behind - and
// because temporary files are deliberately not browsable, nothing can afterwards find what was left.
// @relation(AC-SVR-FILE-022-TEMP-FILES-DELETED-ON-SESSION-END, scope=function)
TEST_F(FileDirectoryTest, ATemporaryTransferFileIsDeletedWhenTheSessionThatCreatedItEnds)
{
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  const auto nodes = make_temp_transfer(mServer.server().address_space(),
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "SessionEndXfer"},
    options,
    mDirPath / "xfer_session");
  ASSERT_FALSE(nodes.transferId.is_null()) << "the TemporaryFileTransferType instance was not created";
  ASSERT_FALSE(nodes.generateForReadId.is_null()) << "the transfer exposes no GenerateFileForRead Method";

  auto creator = mChannel->create_session_sync({.sessionName = "TempFileCreator"});
  creator.activate_sync();

  auto generated = creator.methods().call_sync(
    CallRequestBuilder().call(nodes.transferId, nodes.generateForReadId, {Variant{}}));
  ASSERT_EQ(generated.results().size(), 1u);
  ASSERT_THAT(generated.results()[0].status_code(), Good());
  ASSERT_GE(generated.results()[0].output_arguments().size(), 2u);
  const auto tempNode = generated.results()[0].output_arguments()[0].as<NodeId>();
  ASSERT_FALSE(tempNode.is_null());

  const auto tempNodeResolves = [this, &tempNode]()
  {
    auto probe = mSession->attributes().read_sync(read_value(tempNode, AttributeId::NodeClass));
    if (probe.response_header().service_result().is_bad() || probe.results().size() != 1u)
    {
      return false;
    }
    return probe.results()[0].status().value_or(StatusCode{Status::Good}).is_good();
  };

  // Observed from the surviving Session, so the reading after the close is a deletion and not a node
  // that never existed.
  ASSERT_TRUE(tempNodeResolves())
    << "the temporary FileType node was never in the address space, so nothing here is being deleted";

  // The transfer is deliberately NOT committed or closed: ending the Session is the only release.
  const auto sessionClosed = creator.try_close_sync();
  ASSERT_TRUE(sessionClosed.is_good()) << "0x" << std::hex << sessionClosed.status_code().as_uint32();

  bool deleted = false;
  for (int attempt = 0; attempt < 100 && !deleted; ++attempt)
  {
    deleted = !tempNodeResolves();
    if (!deleted)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
  EXPECT_TRUE(deleted) << "the temporary FileType node outlived the Session that created it; nothing "
                          "can browse to it, so the storage it holds is unreachable and unreclaimable";
}

// Part 20 section 4.4.1: ClientProcessingTimeout is the longest gap the Server accepts between the Method
// calls that complete a transfer. The clause is permissive - on a client that overruns it the Server
// *may* close the file and cancel the transaction - so the obligation is not "it must cancel" but
// that whichever it does, it does wholly: a cancelled transfer has released its temporary file and
// rejects the abandoned handle with Bad_InvalidArgument (SVR-FILE-012), and a transfer the Server
// chose to leave running is still committable. A plausible implementation reclaims the temporary
// file on the timer but leaves the handle registered, so a later CloseAndCommit reports success over
// storage that is already gone; the inverse leaks a file that, temporary files being non-browsable,
// nothing can afterwards find.
// @verifies AC-SVR-FILE-023-CLIENTPROCESSINGTIMEOUT-POLICED
TEST_F(FileDirectoryTest, ClientProcessingTimeoutCancelsAnAbandonedTransferWhollyOrNotAtAll)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  const auto nodes = make_temp_transfer(addressSpace,
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "TimeoutXfer"},
    options,
    mDirPath / "xfer_timeout");
  ASSERT_FALSE(nodes.transferId.is_null()) << "the TemporaryFileTransferType instance was not created";
  ASSERT_FALSE(nodes.generateForWriteId.is_null()) << "the transfer exposes no GenerateFileForWrite Method";
  ASSERT_FALSE(nodes.closeAndCommitId.is_null()) << "the transfer exposes no CloseAndCommit Method";
  ASSERT_FALSE(nodes.clientProcessingTimeoutId.is_null())
    << "the transfer advertises no ClientProcessingTimeout Property, so the gap it accepts between "
       "Method calls is not published at all";

  // The Property is the value a policing server has to use, so the test sets it rather than guessing
  // a default: a quarter of a second, short enough that the pause below is unambiguous.
  constexpr double timeoutMilliseconds = 250.0;
  auto timeoutProperty = Property::try_attach_sync(addressSpace, nodes.clientProcessingTimeoutId);
  ASSERT_TRUE(timeoutProperty.is_good()) << "0x" << std::hex << timeoutProperty.status_code().as_uint32();
  const auto wroteTimeout =
    timeoutProperty.value().try_write_value_sync(DataValue{Variant{timeoutMilliseconds}});
  ASSERT_TRUE(wroteTimeout.is_good()) << "0x" << std::hex << wroteTimeout.status_code().as_uint32();

  struct Transfer
  {
    NodeId fileNode;
    std::uint32_t handle{0};
  };

  const auto beginTransfer = [this, &nodes]()
  {
    auto generated = mSession->methods().call_sync(
      CallRequestBuilder().call(nodes.transferId, nodes.generateForWriteId, {Variant{}}));
    Transfer transfer;
    EXPECT_EQ(generated.results().size(), 1u);
    if (generated.results().size() == 1u)
    {
      EXPECT_THAT(generated.results()[0].status_code(), Good());
      if (generated.results()[0].output_arguments().size() >= 2u)
      {
        transfer.fileNode = generated.results()[0].output_arguments()[0].as<NodeId>();
        transfer.handle = generated.results()[0].output_arguments()[1].as<std::uint32_t>();
      }
    }
    EXPECT_NE(transfer.handle, 0u);
    return transfer;
  };

  const auto nodeIsPresent = [this](const NodeId& nodeId)
  {
    auto probe = mSession->attributes().read_sync(read_value(nodeId, AttributeId::NodeClass));
    if (probe.response_header().service_result().is_bad() || probe.results().size() != 1u)
    {
      return false;
    }
    return probe.results()[0].status().value_or(StatusCode{Status::Good}).is_good();
  };

  // Control: a transfer committed without a pause succeeds and takes its temporary file with it, so
  // the two outcomes distinguished below are the elapsed time and not a CloseAndCommit or a node
  // lifecycle that never works in the first place.
  const Transfer prompt = beginTransfer();
  ASSERT_NE(prompt.handle, 0u);
  ASSERT_FALSE(prompt.fileNode.is_null());
  ASSERT_TRUE(nodeIsPresent(prompt.fileNode));
  auto promptCommit = mSession->methods().call_sync(
    CallRequestBuilder().call(nodes.transferId, nodes.closeAndCommitId, {Variant{prompt.handle}}));
  ASSERT_EQ(promptCommit.results().size(), 1u);
  ASSERT_THAT(promptCommit.results()[0].status_code(), Good())
    << "a transfer committed immediately was refused, so nothing below distinguishes the timeout";
  ASSERT_FALSE(nodeIsPresent(prompt.fileNode))
    << "a committed transfer left its temporary file behind, so its presence says nothing later on";

  const Transfer abandoned = beginTransfer();
  ASSERT_NE(abandoned.handle, 0u);
  ASSERT_FALSE(abandoned.fileNode.is_null());
  ASSERT_TRUE(nodeIsPresent(abandoned.fileNode));
  std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(timeoutMilliseconds) * 8));

  // Whether to cancel is the Server's own choice (Part 20 section 4.4.1 says "may"), so the temporary file
  // is read first and its fate decides which answer the abandoned handle now owes. Demanding the
  // cancellation itself would fail a server that conformantly declines to police the timeout.
  const bool reclaimed = !nodeIsPresent(abandoned.fileNode);

  auto lateCommit = mSession->methods().call_sync(
    CallRequestBuilder().call(nodes.transferId, nodes.closeAndCommitId, {Variant{abandoned.handle}}));
  ASSERT_EQ(lateCommit.results().size(), 1u);
  if (reclaimed)
  {
    EXPECT_EQ(lateCommit.results()[0].status_code().as_status(), Status::BadInvalidArgument)
      << "the transfer's temporary file was reclaimed once the ClientProcessingTimeout had elapsed, "
         "yet its handle was still accepted, so the client is told a transfer succeeded over storage "
         "that is already gone; status = 0x"
      << std::hex << lateCommit.results()[0].status_code().as_uint32();
  }
  else
  {
    EXPECT_THAT(lateCommit.results()[0].status_code(), Good())
      << "the transfer's temporary file is still in the address space - the server did not cancel - "
         "yet its handle was refused, so the transfer is neither live nor reclaimed; status = 0x"
      << std::hex << lateCommit.results()[0].status_code().as_uint32();
    EXPECT_FALSE(nodeIsPresent(abandoned.fileNode))
      << "the temporary file outlived the CloseAndCommit that reported success on it";
  }
}

// Part 20 section 4.4.3: GenerateFileForRead returns the NodeId of a FileTransferStateMachineType Object when
// the file is created asynchronously and a null NodeId when creation is already complete; while a
// returned machine sits in ReadPrepare the temporary file's Read fails, and it may succeed only once
// the TransferState has changed to ReadTransfer. A plausible implementation omits the output
// altogether, or hands one back on every call - either way the null/non-null signal carries no
// information, and a client on the synchronous path waits for a transition that never comes.
// @verifies AC-SVR-FILE-024-ASYNC-GATE
TEST_F(FileDirectoryTest, GenerateFileForReadGatesTheReadUntilItsStateMachineReachesReadTransfer)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

  // The generated file carries real content, so "the Read succeeded" means bytes arrived and is not
  // also satisfied by the empty answer a file whose generation has not finished would give.
  const auto sourcePath = mDirPath / "async_source.bin";
  const std::vector<std::uint8_t> sourceBytes(256, static_cast<std::uint8_t>(0x6D));
  {
    std::ofstream output{sourcePath, std::ios::binary};
    output.write(
      reinterpret_cast<const char*>(sourceBytes.data()), static_cast<std::streamsize>(sourceBytes.size()));
  }

  TemporaryFileTransferConfig config;
  config.tempDir = mDirPath / "xfer_async";
  config.transientFileParent = mTestFolderId;
  config.onGenerateForRead = [sourcePath](const Variant&,
                               std::shared_ptr<const MethodCallContext>) -> Result<std::filesystem::path>
  {
    return sourcePath;
  };

  auto createdTransfer = TemporaryFileTransferHelper::try_create_sync(
    addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "AsyncGateXfer"}, options, config);
  ASSERT_TRUE(createdTransfer.is_good()) << "0x" << std::hex << createdTransfer.status_code().as_uint32();
  auto transferHelper = std::move(createdTransfer).value();
  const NodeId transferId = transferHelper.node_id();
  auto generateMethod = transferHelper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generateMethod.is_good()) << "the transfer exposes no GenerateFileForRead Method";
  const NodeId generateForReadId = generateMethod.value().get_node_id();
  transferHelper.release();

  auto generated =
    mSession->methods().call_sync(CallRequestBuilder().call(transferId, generateForReadId, {Variant{}}));
  ASSERT_EQ(generated.results().size(), 1u);
  ASSERT_THAT(generated.results()[0].status_code(), Good());
  ASSERT_GE(generated.results()[0].output_arguments().size(), 3u)
    << "GenerateFileForRead returned " << generated.results()[0].output_arguments().size()
    << " output arguments; with no completionStateMachine among them a client cannot tell an "
       "asynchronous generation from one that is already complete";

  const auto tempNode = generated.results()[0].output_arguments()[0].as<NodeId>();
  const auto handle = generated.results()[0].output_arguments()[1].as<std::uint32_t>();
  ASSERT_FALSE(tempNode.is_null()) << "GenerateFileForRead returned no temporary FileType NodeId";
  ASSERT_NE(handle, 0u) << "GenerateFileForRead returned no file handle";

  NodeId completionStateMachine;
  if (const auto* held = generated.results()[0].output_arguments()[2].try_as<NodeId>(); held != nullptr)
  {
    completionStateMachine = *held;
  }

  auto attached = File::try_attach_sync(addressSpace, tempNode);
  ASSERT_TRUE(attached.is_good())
    << "the temporary FileType NodeId the Method returned does not resolve to a FileType Object";
  auto readMethod = attached.value().try_read_method_sync();
  ASSERT_TRUE(readMethod.is_good()) << "the temporary FileType Object exposes no Read Method";
  const NodeId readMethodId = readMethod.value().get_node_id();

  const auto readChunk = [&]()
  {
    return mSession->methods().call_sync(CallRequestBuilder().call(
      tempNode, readMethodId, {Variant{handle}, Variant{static_cast<std::int32_t>(sourceBytes.size())}}));
  };

  const auto servedBytes = [](const auto& result)
  {
    std::size_t served = 0;
    if (!result.output_arguments().empty())
    {
      // `result` is a generic-lambda parameter, so the element type is dependent and `try_as` needs
      // the `template` disambiguator to parse as a template-id rather than a comparison.
      const auto* data = result.output_arguments()[0].template try_as<ByteString>();
      if (data != nullptr)
      {
        served = data->size();
      }
    }
    return served;
  };

  if (completionStateMachine.is_null())
  {
    // Null is the server's own statement that creation is already complete, so there is no
    // transition left to wait for and the file must read now.
    auto immediate = readChunk();
    ASSERT_EQ(immediate.results().size(), 1u);
    EXPECT_THAT(immediate.results()[0].status_code(), Good())
      << "completionStateMachine came back null - the server's statement that creation is already "
         "complete - yet the Read was refused; status = 0x"
      << std::hex << immediate.results()[0].status_code().as_uint32();
    EXPECT_GT(servedBytes(immediate.results()[0]), 0u)
      << "a Read on a file the server declared already complete served nothing, which a client reads "
         "as end-of-file on a transfer that in fact has content";
    return;
  }

  // A machine came back, so the asynchronous contract applies in full: ReadPrepare first, the Read
  // refused there, and the Read permitted only once the state has become ReadTransfer.
  const auto readCurrentState = [this, &completionStateMachine]()
  {
    NodeId currentStateId;
    auto browsed = mSession->view().browse_sync(browse(completionStateMachine));
    if (browsed.results().size() == 1u && !browsed.results()[0].status_code().is_bad())
    {
      for (const auto& reference : browsed.results()[0].references())
      {
        if (std::string_view{reference.browse_name().name()} == "CurrentState")
        {
          currentStateId = reference.node_id().node_id();
          break;
        }
      }
    }
    std::string state;
    if (currentStateId.is_null())
    {
      return state;
    }
    auto response = mSession->attributes().read_sync(read_value(currentStateId));
    if (response.response_header().service_result().is_bad() || response.results().size() != 1u)
    {
      return state;
    }
    const auto* held = response.results()[0].value().try_as<LocalizedText>();
    if (held != nullptr)
    {
      state = std::string{std::string_view{held->text()}};
    }
    return state;
  };

  // Generation runs on the server's clock, so the machine may already have advanced by the time the
  // client gets to read it. ReadTransfer here is therefore conformant and only ReadPrepare gates the
  // Read; demanding ReadPrepare outright would fail a server that merely finished quickly.
  const std::string firstState = readCurrentState();
  ASSERT_TRUE(firstState == "ReadPrepare" || firstState == "ReadTransfer")
    << "a returned completionStateMachine must be a FileTransferStateMachineType whose CurrentState "
       "runs ReadPrepare then ReadTransfer; it reads '"
    << firstState << "', which a client subscribing to it cannot act on";

  if (firstState == "ReadPrepare")
  {
    auto early = readChunk();
    ASSERT_EQ(early.results().size(), 1u);
    EXPECT_TRUE(early.results()[0].status_code().is_bad())
      << "Read was permitted while the transfer state machine was still preparing the file, so the "
         "client is handed content the server has not finished producing";
    EXPECT_EQ(servedBytes(early.results()[0]), 0u)
      << "bytes were served from a file whose generation had not yet reached ReadTransfer";
  }

  std::string state;
  for (int attempt = 0; attempt < 250; ++attempt)
  {
    state = readCurrentState();
    if (state == "ReadTransfer")
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_EQ(state, std::string{"ReadTransfer"})
    << "the transfer state machine never left '" << state << "', so the Read it gates can never be permitted";

  auto late = readChunk();
  ASSERT_EQ(late.results().size(), 1u);
  EXPECT_THAT(late.results()[0].status_code(), Good())
    << "Read was still refused after the state machine reached ReadTransfer; status = 0x" << std::hex
    << late.results()[0].status_code().as_uint32();
  EXPECT_GT(servedBytes(late.results()[0]), 0u)
    << "the Read permitted at ReadTransfer served no bytes of the generated file";
}

// Part 20 section 4.4.3: `GenerateOptions` is declared BaseDataType in the type table, and a Server that
// wants options shall put a concrete DataType in the Argument Structure of the Method INSTANCE. The
// Argument's normative name is `GenerateOptions` (NS0 i=15747); the lower-case `generateOptions` is
// only section 4.4.3's signature-line spelling, so matching on it finds nothing. A plausible implementation
// omits the per-instance Argument Structure altogether, leaving a client with no DataType at all to
// build a value from - that is what the resolution of the declared DataType below catches.
// @verifies AC-SVR-FILE-026-GENERATEOPTIONS-READ
TEST_F(FileDirectoryTest, GenerateFileForReadDeclaresAConcreteGenerateOptionsTypeOrAcceptsOnlyNull)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  const auto nodes = make_temp_transfer(addressSpace,
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "ReadOptionsXfer"},
    options,
    mDirPath / "xfer_read_options");
  ASSERT_FALSE(nodes.transferId.is_null()) << "the TemporaryFileTransferType instance was not created";
  ASSERT_FALSE(nodes.generateForReadId.is_null()) << "the transfer exposes no GenerateFileForRead Method";

  NodeId inputArgumentsId;
  auto browsed = mSession->view().browse_sync(browse(nodes.generateForReadId));
  ASSERT_EQ(browsed.results().size(), 1u);
  for (const auto& reference : browsed.results()[0].references())
  {
    if (std::string_view{reference.browse_name().name()} == "InputArguments")
    {
      inputArgumentsId = reference.node_id().node_id();
      break;
    }
  }
  ASSERT_FALSE(inputArgumentsId.is_null())
    << "the GenerateFileForRead instance declares no InputArguments Property, so a client cannot "
       "discover what generateOptions to send";

  auto property = Property::try_attach_sync(addressSpace, inputArgumentsId);
  ASSERT_TRUE(property.is_good()) << "0x" << std::hex << property.status_code().as_uint32();
  auto declared = property.value().try_read_value_sync();
  ASSERT_TRUE(declared.is_good()) << "0x" << std::hex << declared.status_code().as_uint32();
  const auto& metadata = declared.value().value();
  ASSERT_TRUE(metadata.is_array_of_structure()) << "InputArguments does not hold an Argument array";
  const auto& arguments = metadata.as<Array<RefStructure<Structure>>>();
  const Argument* generateOptions = nullptr;
  for (const auto& entry : arguments.payload())
  {
    const auto* argument = dynamic_cast<const Argument*>(entry.get());
    if (argument != nullptr && std::string_view{argument->name()} == "GenerateOptions")
    {
      generateOptions = argument;
      break;
    }
  }
  ASSERT_NE(generateOptions, nullptr)
    << "the GenerateFileForRead instance declares no GenerateOptions Argument at all, so there is "
       "nothing for a client to read a DataType from";

  // Naming a DataType a client can resolve is the whole of what section 4.4.3 asks of the Server, so the
  // IsAbstract read is the whole observable. The clause's other sentence - "If the DataType is
  // BaseDataType, the Client shall pass Null for this argument" - is addressed to the Client, so a
  // server that accepts a non-null value against an abstract declaration breaks no server-side
  // "shall"; calling the Method to see it refused would be testing an obligation nobody owes here.
  auto declaredType =
    mSession->attributes().read_sync(read_value(generateOptions->data_type(), AttributeId::IsAbstract));
  ASSERT_THAT(declaredType, ServiceResultIsGood());
  ASSERT_EQ(declaredType.results().size(), 1u);
  const auto* isAbstract = declaredType.results()[0].value().try_as<bool>();
  ASSERT_NE(isAbstract, nullptr)
    << "the DataType the GenerateOptions Argument names does not resolve to a DataType node, so the "
       "declaration names nothing a client could encode against";
}

// Part 20 section 4.4.4: the write-side twin of the read obligation - GenerateFileForWrite's
// `GenerateOptions` Argument on the live Method instance must name a DataType a client can encode
// against. The two Methods are instantiated independently, so a server can rewrite the Argument
// Structure on one and forget the other; that is precisely the failure a single merged check would
// hide, and why this is asserted separately from the read side. The Argument's normative name is
// `GenerateOptions` - the lower-case form is only section 4.4.4's signature-line spelling. As on the read
// side, "only Null is accepted" is not asserted: section 4.4.4 puts that rule on the Client.
// @verifies AC-SVR-FILE-027-GENERATEOPTIONS-WRITE
TEST_F(FileDirectoryTest, GenerateFileForWriteDeclaresAConcreteGenerateOptionsTypeOrAcceptsOnlyNull)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  const auto nodes = make_temp_transfer(addressSpace,
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "WriteOptionsXfer"},
    options,
    mDirPath / "xfer_write_options");
  ASSERT_FALSE(nodes.transferId.is_null()) << "the TemporaryFileTransferType instance was not created";
  ASSERT_FALSE(nodes.generateForWriteId.is_null()) << "the transfer exposes no GenerateFileForWrite Method";

  NodeId inputArgumentsId;
  auto browsed = mSession->view().browse_sync(browse(nodes.generateForWriteId));
  ASSERT_EQ(browsed.results().size(), 1u);
  for (const auto& reference : browsed.results()[0].references())
  {
    if (std::string_view{reference.browse_name().name()} == "InputArguments")
    {
      inputArgumentsId = reference.node_id().node_id();
      break;
    }
  }
  ASSERT_FALSE(inputArgumentsId.is_null())
    << "the GenerateFileForWrite instance declares no InputArguments Property, so a client cannot "
       "discover what generateOptions to send";

  auto property = Property::try_attach_sync(addressSpace, inputArgumentsId);
  ASSERT_TRUE(property.is_good()) << "0x" << std::hex << property.status_code().as_uint32();
  auto declared = property.value().try_read_value_sync();
  ASSERT_TRUE(declared.is_good()) << "0x" << std::hex << declared.status_code().as_uint32();
  const auto& metadata = declared.value().value();
  ASSERT_TRUE(metadata.is_array_of_structure()) << "InputArguments does not hold an Argument array";
  const auto& arguments = metadata.as<Array<RefStructure<Structure>>>();
  const Argument* generateOptions = nullptr;
  for (const auto& entry : arguments.payload())
  {
    const auto* argument = dynamic_cast<const Argument*>(entry.get());
    if (argument != nullptr && std::string_view{argument->name()} == "GenerateOptions")
    {
      generateOptions = argument;
      break;
    }
  }
  ASSERT_NE(generateOptions, nullptr)
    << "the GenerateFileForWrite instance declares no GenerateOptions Argument at all, so there is "
       "nothing for a client to read a DataType from";

  // As on the read side, the DataType read is the whole observable: section 4.4.4 addresses the Null rule to
  // the Client, so a server accepting a non-null value against an abstract declaration breaks no
  // server-side "shall" and is not asserted here.
  auto declaredType =
    mSession->attributes().read_sync(read_value(generateOptions->data_type(), AttributeId::IsAbstract));
  ASSERT_THAT(declaredType, ServiceResultIsGood());
  ASSERT_EQ(declaredType.results().size(), 1u);
  const auto* isAbstract = declaredType.results()[0].value().try_as<bool>();
  ASSERT_NE(isAbstract, nullptr)
    << "the DataType the GenerateOptions Argument names does not resolve to a DataType node, so the "
       "declaration names nothing a client could encode against";
}

// @relation(AC-SVR-BASE-101-UABINARY-MIMETYPE, scope=function)

// Part 5 section 12.36: "If the file is provided through a FileType Object, the MimeType Property of the
// Object shall have the value application/opcua+uabinary." The clause's antecedent is that the
// content IS a UABinaryFileDataType encoded as ExtensionObject, so the backing file below carries a
// real one rather than arbitrary bytes. The sibling sentence about the `uabinary` file extension is
// a separate obligation on on-disc storage (AC-SVR-FILE-028), not a mechanism by which a server may
// infer a content type from a filename - no clause licenses that inference, and the SDK's FileType
// backing is handed only a path and a writable flag. Declaring the content type is therefore a
// deployment act on an ordinary Property node, which is what this test performs before reading.
// What remains observable of the SDK is the client-visible half: a FileType Object serving UA Binary
// content exposes MimeType, holds what the deployment declared on it, and serves it over the wire.
// @verifies AC-SVR-FILE-025-UABINARY-MIMETYPE
TEST_F(FileDirectoryTest, AFileServingUABinaryContentDeclaresTheUABinaryMimeType)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  options.optionalChildFilter = [](const ChildFilterInfo& child)
  {
    return child.browseName.name() == "MimeType";
  };

  // section 12.36's antecedent has to hold before its consequent can be asked for: the file's content is
  // the UABinaryFileDataType encoded as an ExtensionObject, not 64 arbitrary bytes under a name.
  UABinaryFileDataType content;
  content.schema_location() = String{"http://opcfoundation.org/UA/"};
  memory_stream_device::Dynamic device(4096, /*reserve=*/true);
  MemoryStream<memory_stream_device::Dynamic> stream(device);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  const Structure* asExtensionObject = &content;
  encoder.encode(EncodingLimits{}.stack_depth(), asExtensionObject);
  const auto encoded = device.get_data();

  const auto binaryPath = mDirPath / "types.uabinary";
  {
    std::ofstream output{binaryPath, std::ios::binary};
    output.write(reinterpret_cast<const char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
  }

  auto created = FileHelper::try_create_sync(addressSpace,
    mTestFolderId,
    QualifiedName{mTestNamespaceIndex, "UABinaryFile"},
    binaryPath,
    options,
    true);
  ASSERT_TRUE(created.is_good()) << "0x" << std::hex << created.status_code().as_uint32();
  auto helper = std::move(created).value();
  auto mimeProperty = helper.file().try_mime_type_property_sync();
  NodeId mimeTypeId;
  if (mimeProperty.is_good())
  {
    mimeTypeId = mimeProperty.value().node_id();
  }
  helper.release();

  ASSERT_FALSE(mimeTypeId.is_null())
    << "the FileType Object serving UA Binary content exposes no MimeType Property, so it carries no "
       "content-type signal at all";

  // The declaration itself belongs to whoever serves the content: MimeType is an ordinary Property
  // node and the SDK has no content-type input for section 12.36 to bind to - FileHelper is told a path and
  // a writable flag and nothing more. So the deployment step is performed here, and what the test
  // holds the SDK to is that the declared value is the one a client subsequently reads.
  auto mimeNode = Property::try_attach_sync(addressSpace, mimeTypeId);
  ASSERT_TRUE(mimeNode.is_good()) << "0x" << std::hex << mimeNode.status_code().as_uint32();
  const auto declaredMimeType =
    mimeNode.value().try_write_value_sync(DataValue{Variant{String{"application/opcua+uabinary"}}});
  ASSERT_TRUE(declaredMimeType.is_good()) << "0x" << std::hex << declaredMimeType.status_code().as_uint32();

  auto read = mSession->attributes().read_sync(read_value(mimeTypeId));
  ASSERT_THAT(read, ServiceResultIsGood());
  ASSERT_EQ(read.results().size(), 1u);
  const auto* held = read.results()[0].value().try_as<String>();
  ASSERT_NE(held, nullptr) << "MimeType does not read as a String";
  EXPECT_EQ(std::string_view{*held}, "application/opcua+uabinary")
    << "a FileType Object serving a UA Binary file declares MimeType '" << std::string_view{*held}
    << "', so a client cannot tell the body apart from opaque bytes";
}

namespace
{

constexpr std::string_view fileWriterUser{"file-writer"};
constexpr std::string_view fileReaderUser{"file-reader"};
constexpr std::string_view fileUserPassword{"file-user-password"};

}  // namespace

// Fixture for the per-user half of FileType writability. FileDirectoryTest's server is built by
// TestServer, which offers no route to ServerComponents, so it can neither authenticate two
// different users nor express one of them holding no write right -- both are prerequisites of the
// obligation below. ComplianceSecured supplies the crypto, certificate stores and client needed to
// stand up a server that can, and the server itself is built in the test body because the endpoint
// list ComplianceSecured installs advertises Anonymous tokens only.
class FileUserWritableTest : public ComplianceSecured
{};

// Part 20 section 4.2: `Writable` advertises the file's writability in the abstract; `UserWritable` returns
// the same boolean evaluated against the CURRENT authenticated user's permissions. The obvious
// implementation -- and the one this SDK's FileHelper documents, where a single `writable` flag
// "drives the Writable / UserWritable properties" -- computes both from one static value at
// instantiation, so `UserWritable` reads TRUE for a user who may not write the file and a client that
// checks it before opening is told to proceed into a refusal. All three conjuncts of the observation
// are asserted: Writable identical across the two users, UserWritable FALSE for the restricted one,
// and its open-for-write refused with no handle issued. The permitted user's own open-for-write is
// performed and CLOSED first, so the restricted user's refusal cannot be the write-exclusivity lock of
// AC-SVR-FILE-009 wearing this obligation's clothes.
// @verifies AC-SVR-FILE-003-USERWRITABLE
TEST_F(FileUserWritableTest, UserWritableAccountsForTheCallingUsersWriteRights)
{
  const auto dirPath = std::filesystem::temp_directory_path() /
                       ("ua_filedir_userwritable_" + Guid::create_and_generate().as_string());
  std::error_code ec;
  std::filesystem::remove_all(dirPath, ec);
  ASSERT_TRUE(std::filesystem::create_directories(dirPath, ec));
  const auto filePath = dirPath / "shared.bin";
  {
    std::ofstream seed{filePath, std::ios::binary};
    seed.write("seed", 4);
  }

  ServerComponents components{.crypto = mCrypto,
    .applicationGroupCertificateStore = mServerCertStore,
    .logSink = test_log_sink(),
    .logLevel = LogLevel::Debug};
  auto composite = std::make_shared<CompositeAuthenticator>();
  composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
  composite->add(UserTokenKind::UserName,
    std::make_shared<SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        return (username == fileWriterUser || username == fileReaderUser) &&
               std::string_view{password.c_str()} == fileUserPassword;
      }));
  components.authenticator = composite;
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::AuthenticatedUser, IdentityCriteriaType::AuthenticatedUser},
      {WellKnownRole::SecurityAdmin, IdentityCriteriaType::UserName, String{fileWriterUser}}});

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ua::server::CreateConfig fileServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  // Declared before the server so the namespace outlives the address space that holds it.
  std::shared_ptr<default_ns::Namespace> fileNamespace;
  std::optional<ua::server::Server> fileServer;
  fileServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(fileServerCfg), std::move(components)));

  auto addressSpace = fileServer->address_space();
  fileNamespace =
    default_ns::Namespace::create("urn:test:filedir:userwritable", mServerThreadPool.executor());
  const auto nsIndex = addressSpace.add_namespace_sync(fileNamespace);
  RolePermissionType authenticatedDefaults;
  authenticatedDefaults.role_id() = NodeId{ObjectId::WellKnownRole_AuthenticatedUser};
  authenticatedDefaults.permissions() = PermissionType{{PermissionType::Bit::Browse,
    PermissionType::Bit::Read,
    PermissionType::Bit::WriteAttribute,
    PermissionType::Bit::Write,
    PermissionType::Bit::Call,
    PermissionType::Bit::AddReference,
    PermissionType::Bit::RemoveReference,
    PermissionType::Bit::AddNode,
    PermissionType::Bit::DeleteNode}};
  fileNamespace->set_namespace_defaults(std::vector<RolePermissionType>{authenticatedDefaults}, std::nullopt);

  const NodeId folderId{nsIndex, uint32_t{2000}};
  auto folderNode = addressSpace.create_node_sync(folderId, NodeClass::Object);
  folderNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
  auto folder = folderNode.as<ObjectAccessor>();
  ASSERT_TRUE(folder.has_value());
  folder->set_browse_name(QualifiedName{nsIndex, "UserWritableFolder"});
  folder->set_display_name(LocalizedText{"", "UserWritableFolder"});
  auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
  objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, folderId);

  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

  auto fileResult = FileHelper::try_create_sync(
    addressSpace, folderId, QualifiedName{nsIndex, "UserWritableFile"}, filePath, options, true);
  ASSERT_TRUE(fileResult.is_good()) << "0x" << std::hex << fileResult.status_code().as_uint32();
  auto fileHelper = std::move(fileResult).value();
  const NodeId fileNodeId = fileHelper.node_id();
  const NodeId openMethodId = fileHelper.file().try_open_method_sync().value().get_node_id();
  const NodeId closeMethodId = fileHelper.file().try_close_method_sync().value().get_node_id();
  const NodeId writablePropertyId = fileHelper.file().try_writable_property_sync().value().node_id();
  const NodeId userWritablePropertyId = fileHelper.file().try_user_writable_property_sync().value().node_id();
  fileHelper.release();
  RolePermissionType authenticatedFilePermissions;
  authenticatedFilePermissions.role_id() = NodeId{ObjectId::WellKnownRole_AuthenticatedUser};
  authenticatedFilePermissions.permissions() =
    PermissionType{{PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Call}};
  RolePermissionType writerFilePermissions;
  writerFilePermissions.role_id() = NodeId{ObjectId::WellKnownRole_SecurityAdmin};
  writerFilePermissions.permissions() = PermissionType{{PermissionType::Bit::Browse,
    PermissionType::Bit::Read,
    PermissionType::Bit::Write,
    PermissionType::Bit::Call}};
  addressSpace.find_node_sync(fileNodeId)
    .set_role_permissions(
      std::vector<RolePermissionType>{authenticatedFilePermissions, writerFilePermissions});

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto listener = fileServer->listen_sync(std::move(bind), {});

  auto userNamePolicy = create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256);
  const std::string userNamePolicyId{userNamePolicy.policy_id()};
  ASSERT_FALSE(userNamePolicyId.empty());

  ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256_SignAndEncrypt";
  endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  endpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  endpoint.userIdentityTokens.push_back(std::move(userNamePolicy));
  fileServer->add_endpoint(listener, std::move(endpoint));

  fileServer->start_sync();

  auto urls = fileServer->advertised_urls(listener);
  ASSERT_FALSE(urls.empty());

  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = urls.front().str();
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = mServerCert;
  auto channelResult = mClient->core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good())
    << "channel open must succeed; status 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();

  auto writerSessionResult = channel.try_create_session_sync({.sessionName = "FilePermittedUser"});
  ASSERT_TRUE(writerSessionResult.is_good())
    << "status 0x" << std::hex << writerSessionResult.status_code().as_uint32();
  auto writerSession = std::move(writerSessionResult).value();
  ua::client::Session::ActivateConfig writerCfg;
  writerCfg.policyId = userNamePolicyId;
  writerCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{fileWriterUser}, .password = std::string{fileUserPassword}};
  auto writerActivate = writerSession.try_activate_sync(std::move(writerCfg));
  ASSERT_TRUE(writerActivate.is_good())
    << "the permitted user must activate; status 0x" << std::hex << writerActivate.status_code().as_uint32();

  auto readerSessionResult = channel.try_create_session_sync({.sessionName = "FileRestrictedUser"});
  ASSERT_TRUE(readerSessionResult.is_good())
    << "status 0x" << std::hex << readerSessionResult.status_code().as_uint32();
  auto readerSession = std::move(readerSessionResult).value();
  ua::client::Session::ActivateConfig readerCfg;
  readerCfg.policyId = userNamePolicyId;
  readerCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{fileReaderUser}, .password = std::string{fileUserPassword}};
  auto readerActivate = readerSession.try_activate_sync(std::move(readerCfg));
  ASSERT_TRUE(readerActivate.is_good())
    << "the restricted user must activate -- it is denied a write right, not access; status 0x" << std::hex
    << readerActivate.status_code().as_uint32();

  const auto readBool =
    [](ua::client::Session& session, const NodeId& nodeId, const char* what) -> std::optional<bool>
  {
    auto response = session.attributes().read_sync(read_value(nodeId));
    EXPECT_THAT(response, ServiceResultIsGood()) << what;
    EXPECT_EQ(response.results().size(), 1u) << what;
    if (response.results().size() != 1u)
    {
      return std::nullopt;
    }
    const auto* held = response.results()[0].value().try_as<bool>();
    EXPECT_NE(held, nullptr) << what << " did not read as a Boolean";
    if (held == nullptr)
    {
      return std::nullopt;
    }
    return *held;
  };

  // UserWriteMask is deliberately not used as a harness control: it projects WriteAttribute
  // (configuration-Attribute mutation), while this criterion denies Write (live file content). The
  // permitted user's successful Open(write) and the restricted user's refusal below are the direct
  // control pair for the access-control verdict this obligation consumes.

  const auto writerWritable = readBool(writerSession, writablePropertyId, "Writable (permitted user)");
  const auto readerWritable = readBool(readerSession, writablePropertyId, "Writable (restricted user)");
  ASSERT_TRUE(writerWritable.has_value());
  ASSERT_TRUE(readerWritable.has_value());
  EXPECT_TRUE(*writerWritable) << "the file was created writable, so Writable must be TRUE";
  EXPECT_EQ(*writerWritable, *readerWritable)
    << "Writable describes the file, not the caller, and must not differ between the two users";

  const auto writerUserWritable =
    readBool(writerSession, userWritablePropertyId, "UserWritable (permitted user)");
  const auto readerUserWritable =
    readBool(readerSession, userWritablePropertyId, "UserWritable (restricted user)");
  ASSERT_TRUE(writerUserWritable.has_value());
  ASSERT_TRUE(readerUserWritable.has_value());
  EXPECT_TRUE(*writerUserWritable)
    << "UserWritable was FALSE for the user that may write the file, so the pair carries no "
       "per-user information at all";
  EXPECT_FALSE(*readerUserWritable) << "UserWritable was TRUE for a user holding no write right on the file";

  // The permitted user's write open, taken and released before the restricted user tries. It proves
  // the file opens for write at all, and closing it removes the write-exclusivity lock so the refusal
  // asserted next can only be the caller's rights.
  auto writerOpen = writerSession.methods().call_sync(
    CallRequestBuilder().call(fileNodeId, openMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(writerOpen.results().size(), 1u);
  EXPECT_THAT(writerOpen.results()[0].status_code(), Good())
    << "the permitted user could not open the file for write";
  if (writerOpen.results()[0].status_code().is_good() && !writerOpen.results()[0].output_arguments().empty())
  {
    const auto writerHandle = writerOpen.results()[0].output_arguments()[0].as<std::uint32_t>();
    auto writerClosed = writerSession.methods().call_sync(
      CallRequestBuilder().call(fileNodeId, closeMethodId, {Variant{writerHandle}}));
    ASSERT_EQ(writerClosed.results().size(), 1u);
    ASSERT_THAT(writerClosed.results()[0].status_code(), Good());
  }

  auto readerOpen = readerSession.methods().call_sync(
    CallRequestBuilder().call(fileNodeId, openMethodId, {Variant{static_cast<std::uint8_t>(0x02)}}));
  ASSERT_EQ(readerOpen.results().size(), 1u);
  EXPECT_TRUE(readerOpen.results()[0].status_code().is_bad())
    << "open-for-write was granted to a user holding no write right; status 0x" << std::hex
    << readerOpen.results()[0].status_code().as_uint32();
  std::uint32_t issuedHandle = 0;
  if (readerOpen.results()[0].status_code().is_good() && !readerOpen.results()[0].output_arguments().empty())
  {
    issuedHandle = readerOpen.results()[0].output_arguments()[0].as<std::uint32_t>();
  }
  EXPECT_EQ(issuedHandle, 0u) << "a write handle was issued to a user holding no write right";

  (void)readerSession.try_close_sync();
  (void)writerSession.try_close_sync();
  (void)channel.try_close_sync();
  if (fileServer)
  {
    (void)fileServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  }
  fileServer.reset();
  std::filesystem::remove_all(dirPath, ec);
}

// ServerConfig::ResourceLimits::openFileHandlesPerSession and openFileHandles, over the wire. The control is
// the default fixture, whose limits (16 per Session, 256 in all) a third Open of one Session is well under;
// the configured fixture sets them to 2 and 3.
class FileHandleLimitsTest : public FileDirectoryTest
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    FileDirectoryTest::configure_server_config(cfg);
    cfg.resourceLimits.openFileHandlesPerSession = 2;
    cfg.resourceLimits.openFileHandles = 3;
  }
};

namespace
{

CallMethodResult open_for_read(ua::client::Session& session, const NodeId& fileId, const NodeId& openMethodId)
{
  auto opened = session.methods().call_sync(
    CallRequestBuilder().call(fileId, openMethodId, {Variant{static_cast<std::uint8_t>(0x01)}}));
  EXPECT_EQ(opened.results().size(), 1u);
  return opened.results().empty() ? CallMethodResult{} : opened.results()[0];
}

}  // namespace

// Control: under the default limits one Session's three read handles on one file all open.
// @relation(AC-SVR-FILE-032-OPEN-HANDLES-PER-SESSION-BOUNDED, scope=function)
TEST_F(FileDirectoryTest, ThreeOpensOfOneSessionSucceedUnderTheDefaultHandleLimits)
{
  for (int opened = 0; opened < 3; ++opened)
  {
    auto open = open_for_read(*mSession, mCapFileNodeId, mCapOpenMethodId);
    EXPECT_THAT(open.status_code(), Good()) << "open " << opened;
  }
}

// openFileHandlesPerSession = 2: a Session's third Open is refused with Bad_TooManyOperations, a Close
// frees its slot, and another Session's quota is its own. openFileHandles = 3: with three handles open
// across both Sessions, the second Session's next Open is refused although its own quota has room.
// @relation(AC-SVR-FILE-032-OPEN-HANDLES-PER-SESSION-BOUNDED, scope=function)
// @relation(AC-SVR-FILE-033-OPEN-HANDLES-SERVER-WIDE-BOUNDED, scope=function)
TEST_F(FileHandleLimitsTest, OpensBeyondTheConfiguredLimitsAreRefused)
{
  auto first = open_for_read(*mSession, mCapFileNodeId, mCapOpenMethodId);
  ASSERT_THAT(first.status_code(), Good());
  auto second = open_for_read(*mSession, mCapFileNodeId, mCapOpenMethodId);
  ASSERT_THAT(second.status_code(), Good());
  auto third = open_for_read(*mSession, mCapFileNodeId, mCapOpenMethodId);
  EXPECT_EQ(third.status_code().as_status(), Status::BadTooManyOperations)
    << "0x" << std::hex << third.status_code().as_uint32();

  const auto secondHandle = second.output_arguments()[0].as<std::uint32_t>();
  auto closed = mSession->methods().call_sync(
    CallRequestBuilder().call(mCapFileNodeId, mCapCloseMethodId, {Variant{secondHandle}}));
  ASSERT_EQ(closed.results().size(), 1u);
  ASSERT_THAT(closed.results()[0].status_code(), Good());
  auto reopened = open_for_read(*mSession, mCapFileNodeId, mCapOpenMethodId);
  EXPECT_THAT(reopened.status_code(), Good()) << "a Close frees a slot";

  auto other = mChannel->create_session_sync({.sessionName = "FileHandleLimitsOther"});
  other.activate_sync();
  auto otherFirst = open_for_read(other, mCapFileNodeId, mCapOpenMethodId);
  EXPECT_THAT(otherFirst.status_code(), Good()) << "another Session's quota is its own";
  auto otherSecond = open_for_read(other, mCapFileNodeId, mCapOpenMethodId);
  EXPECT_EQ(otherSecond.status_code().as_status(), Status::BadTooManyOperations)
    << "four handles open with a server-wide limit of three; 0x" << std::hex
    << otherSecond.status_code().as_uint32();
}
