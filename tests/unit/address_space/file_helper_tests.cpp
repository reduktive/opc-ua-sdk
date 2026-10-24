// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/stat.h>
#endif
#include "ua_file_helper_test_access.h"

#include "posting_writes_namespace.h"
#include "ua_to_string.h"
#include "test_utilities.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>

#include "ua_address_space_session_events.h"
#include "ua_file_handle_budget.h"
#include "ua_exceptions.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_type_registration.h"
#include "ua_default_method_node.h"
#include "ua_file.h"
#include "ua_file_system_helpers.h"
#include "ua_file_stream.h"
#include "ua_instance_utils.h"
#include "ua_method_call_authorization_internal.h"
#include "ua_namespace_array.h"
#include "ua_node.h"
#include "ua_object_id.h"
#include "ua_structure_factory.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

using namespace ua;

// D-24 (N11): with InstantiationOptions::limits removed, TemporaryFileTransferConfig::limits, which only
// filled it, is removed too.
template<typename Config>
concept CarriesLimits = requires(Config config) { config.limits; };
static_assert(!CarriesLimits<ua::TemporaryFileTransferConfig>);
using namespace ua::xml::nodeset;
using namespace std::chrono_literals;

namespace
{

void load_and_import_nodeset2(
  const EncodingLimits& limits, AddressSpace addressSpace, StructureFactory& structureFactory)
{
  auto lookupFn = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
  register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});
}

// Test fixture providing an address space with NS0 imported and a temp file.
class FileHelperTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    const auto cfg = ApplicationConfig::load_default();
    mLimits = make_encoding_limits(cfg);

    mThreadPool = pool_threads() == 0 ? std::make_unique<boost::asio::thread_pool>()
                                      : std::make_unique<boost::asio::thread_pool>(pool_threads());
    mAddressSpace = AddressSpace::create("uri:test", mThreadPool->get_executor());
    load_and_import_nodeset2(mLimits, *mAddressSpace, mStructureFactory);

    // Create a temp file path. Must be unique per test instance: the system temp
    // dir is shared across parallel test shards, so a fixed name races (see
    // ua::test_utils::unique_temp_path).
    mTempPath = ua::test_utils::unique_temp_path("file_helper_test", ".bin");
    // Ensure clean state.
    std::filesystem::remove(mTempPath);
  }

  void TearDown() override
  {
    mThreadPool->stop();
    mThreadPool->join();
    std::filesystem::remove(mTempPath);
  }

  /// Threads in the address space's pool; 0 = the library default.
  [[nodiscard]] virtual std::size_t pool_threads() const
  {
    return 0;
  }

  // Helper: create a FileHelper synchronously.
  FileHelperResult create_helper(const std::string& browseName = "TestFile")
  {
    InstantiationOptions options{};
    return FileHelper::try_create_sync(
      *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, browseName}, mTempPath, options);
  }

  // Helper: get a MethodAccessor for a named method on the file helper's node.
  optional<MethodAccessor> get_method(const FileHelper& helper, const std::string& methodName)
  {
    std::promise<MethodAccessorResult> promise;
    auto future = promise.get_future();

    instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
      helper.node_id(),
      NodeId{ReferenceTypeId::HasComponent},
      QualifiedName{0, methodName},

      [&promise](MethodAccessorResult res) { promise.set_value(std::move(res)); });

    auto res = future.get();
    if (res.is_good())
    {
      return std::move(res).value();
    }
    return std::nullopt;
  }

  // Helper: call Open and preserve the complete Method result, including rich status details.
  CallMethodResult call_open_result(const FileHelper& helper, uint8_t mode)
  {
    auto method = get_method(helper, "Open");
    if (!method)
    {
      CallMethodResult result;
      result.status_code() = Status::BadNotFound;
      return result;
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(1);
    req.input_arguments()[0] = Variant{mode};

    return method->call_sync(req);
  }

  // Helper: call Open and return the file handle.
  std::pair<StatusCode, uint32_t> call_open(const FileHelper& helper, uint8_t mode)
  {
    auto result = call_open_result(helper, mode);
    if (result.status_code().is_bad())
    {
      return {result.status_code(), uint32_t{0}};
    }
    if (result.output_arguments().size() < 1)
    {
      return {StatusCode{Status::BadUnexpectedError}, uint32_t{0}};
    }
    return {result.status_code(), result.output_arguments()[0].as<uint32_t>()};
  }

  // Helper: invoke a FileType method as a named Session.
  //
  // The other helpers in this fixture use `call_sync`, which carries no MethodCallContext - so every
  // other test in this file runs as the contextless internal caller. `call_async` is the interface the
  // Call service uses to supply one, and it is the only way to express "Session A" and "Session B"
  // from here.
  CallMethodResult call_as_session(const FileHelper& helper, const std::string& methodName,
    std::vector<Variant> arguments, const NodeId& sessionId,
    std::optional<bool> objectWriteAllowed = std::nullopt)
  {
    auto method = get_method(helper, methodName);
    EXPECT_TRUE(method.has_value()) << "method not found: " << methodName;
    if (!method)
    {
      return {};
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments() = std::move(arguments);

    auto context = std::make_shared<MethodCallContext>();
    context->sessionId = sessionId;
    if (objectWriteAllowed.has_value())
    {
      const VoidResult authorization =
        *objectWriteAllowed
          ? VoidResult{}
          : VoidResult{Status::BadUserAccessDenied,
              ErrorDetail::build("TestFileWriteDenied", "Injected file Write denial", "FileHelperTest")};
      detail::MethodCallAuthorizationInternalAccess::set_object_write_authorizer(
        *context, [authorization] { return authorization; });
    }

    std::promise<CallResult> promise;
    auto future = promise.get_future();
    method->call_async(
      req, std::move(context), [&promise](CallResult res) { promise.set_value(std::move(res)); });

    auto res = future.get();
    EXPECT_TRUE(res.is_good()) << "call_async failed for " << methodName;
    if (!res.is_good())
    {
      return {};
    }
    return std::move(res).value();
  }

  CallMethodResult call_as_session(
    const NodeId& objectId, MethodAccessor method, std::vector<Variant> arguments, const NodeId& sessionId)
  {
    CallMethodRequest request;
    request.object_id() = objectId;
    request.method_id() = method.get_node_id();
    request.input_arguments() = std::move(arguments);

    auto context = std::make_shared<MethodCallContext>();
    context->sessionId = sessionId;

    std::promise<CallResult> promise;
    auto future = promise.get_future();
    method.call_async(
      request, std::move(context), [&promise](CallResult result) { promise.set_value(std::move(result)); });
    auto result = future.get();
    EXPECT_TRUE(result.is_good());
    return result.is_good() ? std::move(result).value() : CallMethodResult{};
  }

  // Helper: call Close.
  StatusCode call_close(const FileHelper& helper, uint32_t handle)
  {
    auto method = get_method(helper, "Close");
    if (!method)
    {
      return StatusCode{Status::BadNotFound};
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(1);
    req.input_arguments()[0] = Variant{handle};

    return method->call_sync(req).status_code();
  }

  // Helper: call Read and preserve the complete Method result, including rich status details.
  CallMethodResult call_read_result(const FileHelper& helper, uint32_t handle, int32_t length)
  {
    auto method = get_method(helper, "Read");
    if (!method)
    {
      CallMethodResult result;
      result.status_code() = Status::BadNotFound;
      return result;
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(2);
    req.input_arguments()[0] = Variant{handle};
    req.input_arguments()[1] = Variant{length};
    return method->call_sync(req);
  }

  // Helper: call Read.
  std::pair<StatusCode, ByteString> call_read(const FileHelper& helper, uint32_t handle, int32_t length)
  {
    auto result = call_read_result(helper, handle, length);
    if (result.status_code().is_bad())
    {
      return {result.status_code(), {}};
    }
    if (result.output_arguments().size() < 1)
    {
      return {StatusCode{Status::BadUnexpectedError}, {}};
    }
    return {result.status_code(), result.output_arguments()[0].as<ByteString>()};
  }

  // Helper: call Write.
  StatusCode call_write(const FileHelper& helper, uint32_t handle, const ByteString& data)
  {
    auto method = get_method(helper, "Write");
    if (!method)
    {
      return StatusCode{Status::BadNotFound};
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(2);
    req.input_arguments()[0] = Variant{handle};
    req.input_arguments()[1] = Variant{ByteString{data}};

    return method->call_sync(req).status_code();
  }

  // Helper: call GetPosition.
  std::pair<StatusCode, uint64_t> call_get_position(const FileHelper& helper, uint32_t handle)
  {
    auto method = get_method(helper, "GetPosition");
    if (!method)
    {
      return {StatusCode{Status::BadNotFound}, 0};
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(1);
    req.input_arguments()[0] = Variant{handle};

    auto result = method->call_sync(req);
    if (result.status_code().is_bad())
    {
      return {result.status_code(), 0};
    }
    if (result.output_arguments().size() < 1)
    {
      return {StatusCode{Status::BadUnexpectedError}, 0};
    }
    return {result.status_code(), result.output_arguments()[0].as<uint64_t>()};
  }

  // Helper: call SetPosition.
  StatusCode call_set_position(const FileHelper& helper, uint32_t handle, uint64_t position)
  {
    auto method = get_method(helper, "SetPosition");
    if (!method)
    {
      return StatusCode{Status::BadNotFound};
    }

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method->get_node_id();
    req.input_arguments().resize(2);
    req.input_arguments()[0] = Variant{handle};
    req.input_arguments()[1] = Variant{position};

    return method->call_sync(req).status_code();
  }

  EncodingLimits mLimits;
  std::unique_ptr<boost::asio::thread_pool> mThreadPool;
  optional<AddressSpace> mAddressSpace;
  StructureFactory mStructureFactory;
  std::filesystem::path mTempPath;
};

class FileDirectoryHelperTest : public FileHelperTest
{
protected:
  void SetUp() override
  {
    FileHelperTest::SetUp();
    mDirectoryPath = ua::test_utils::unique_temp_path("file_directory_helper_test", "");
    mOutsideRoot = ua::test_utils::unique_temp_path("file_directory_helper_outside", "");
    std::error_code error;
    std::filesystem::remove_all(mDirectoryPath, error);
    std::filesystem::remove_all(mOutsideRoot, error);
  }

  void TearDown() override
  {
    ua::detail::file_helper_tests::set_handler_install_fault_for_tests(std::nullopt);
    std::error_code error;
    std::filesystem::remove_all(mDirectoryPath, error);
    std::filesystem::remove_all(mOutsideRoot, error);
    FileHelperTest::TearDown();
  }

  FileDirectoryHelperResult create_directory_helper(const std::string& browseName = "FileSystem")
  {
    InstantiationOptions options{};
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
    return FileDirectoryHelper::try_create_sync(*mAddressSpace,
      NodeId{ObjectId::ObjectsFolder},
      QualifiedName{1, browseName},
      mDirectoryPath,
      options,
      true);
  }

  CallMethodResult call_create_directory(const FileDirectoryHelper& helper, std::string_view name)
  {
    const auto method = helper.directory().create_directory_method_sync();
    CallMethodRequest request;
    request.object_id() = helper.node_id();
    request.method_id() = method.get_node_id();
    request.input_arguments().resize(1);
    request.input_arguments()[0] = Variant{String{name}};
    return method.call_sync(request);
  }

  CallMethodResult call_create_file(const FileDirectoryHelper& helper, std::string_view name)
  {
    const auto method = helper.directory().try_create_file_method_sync().value();
    CallMethodRequest request;
    request.object_id() = helper.node_id();
    request.method_id() = method.get_node_id();
    request.input_arguments().resize(2);
    request.input_arguments()[0] = Variant{String{name}};
    request.input_arguments()[1] = Variant{false};  // RequestFileOpen
    return method.call_sync(request);
  }

  std::size_t count_children_named(const FileDirectoryHelper& helper, std::string_view name)
  {
    std::size_t count = 0;
    const auto directoryNode = mAddressSpace->find_node_sync(helper.node_id());
    for (const auto& reference : directoryNode.get_references_sync())
    {
      if (!reference.is_forward() || reference.target_id().is_remote())
      {
        continue;
      }
      auto child = mAddressSpace->try_find_node_sync(reference.target_id().node_id());
      if (child.is_good() && std::string_view{child.value().get_browse_name().name()} == name)
      {
        ++count;
      }
    }
    return count;
  }

  std::filesystem::path mDirectoryPath;

  std::filesystem::path mOutsideRoot;
};

}  // namespace

// --- Existing File tests (kept as-is) ---

TEST(FileTests, CreateCreatesMandatoryChildrenAndCleansUp)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_and_import_nodeset2(limits, addressSpace, structureFactory);

  const NodeId parent{ObjectId::ObjectsFolder};
  const QualifiedName browseName{1, "MyFile"};
  InstantiationOptions options{};

  std::promise<FileResult> createPromise;
  auto createFuture = createPromise.get_future();
  File::create_async(addressSpace,
    parent,
    browseName,
    options,
    [&createPromise](FileResult r) mutable { createPromise.set_value(std::move(r)); });
  auto createResult = createFuture.get();
  ASSERT_TRUE(createResult.is_good()) << "create_async failed";

  auto file = std::move(createResult).value();
  const auto rootId = file.node_id();

  std::promise<MethodAccessorResult> openPromise;
  auto openFuture = openPromise.get_future();
  file.open_method_async(
    [&openPromise](MethodAccessorResult r) mutable { openPromise.set_value(std::move(r)); });
  auto openResult = openFuture.get();
  ASSERT_TRUE(openResult.is_good() && !openResult.value().get_node_id().is_null());

  std::promise<PropertyResult> sizePromise;
  auto sizeFuture = sizePromise.get_future();
  file.size_property_async([&sizePromise](PropertyResult r) mutable { sizePromise.set_value(std::move(r)); });
  auto sizeResult = sizeFuture.get();
  ASSERT_TRUE(sizeResult.is_good() && !sizeResult.value().node_id().is_null());

  // Let the helper go out of scope to trigger RAII cleanup. Cleanup is an async
  // fire-and-forget cascade delete, so drain before asserting the node is gone.
  file = File{};

  ::ua::test_utils::drain_with_timeout(threadPool);
  auto afterResult = addressSpace.try_find_node_sync(rootId);
  ASSERT_TRUE(afterResult.is_bad());
}

TEST(FileTests, AttachValidatesExactTypeDefinition)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_and_import_nodeset2(limits, addressSpace, structureFactory);

  // Create a file, then `release()` so it persists, then attach to it.
  const NodeId parent{ObjectId::ObjectsFolder};
  const QualifiedName browseName{1, "MyFile"};
  InstantiationOptions options{};

  std::promise<FileResult> createPromise;
  auto createFuture = createPromise.get_future();
  File::create_async(addressSpace,
    parent,
    browseName,
    options,
    [&createPromise](FileResult r) mutable { createPromise.set_value(std::move(r)); });
  auto createResult = createFuture.get();
  ASSERT_TRUE(createResult.is_good()) << "create_async failed";

  auto file = std::move(createResult).value();
  const auto id = file.node_id();
  file.release();

  std::promise<FileResult> attachPromise;
  auto attachFuture = attachPromise.get_future();
  File::attach_async(
    addressSpace, id, [&attachPromise](FileResult r) mutable { attachPromise.set_value(std::move(r)); });
  auto attachResult = attachFuture.get();
  ASSERT_TRUE(attachResult.is_good()) << "attach_async failed";

  auto attached = std::move(attachResult).value();
  // Cleanup explicitly since we released ownership.
  const auto deleteResult = addressSpace.try_delete_node_sync(attached.node_id(), true);
  ASSERT_TRUE(deleteResult.is_good());

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// --- FileHelper tests ---

// Covers SVR-FILE-012 (coverage-audit retag).
TEST_F(FileHelperTest, CreateAndOpenClose)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good()) << "create_sync failed";
  auto helper = std::move(helperResult).value();

  // Open for read (mode=1). The file doesn't exist yet, so open for write+erase first.
  auto [stOpen, handle] = call_open(helper, 0x02 | 0x04);  // Write + EraseExisting
  ASSERT_TRUE(stOpen.is_good()) << "Open failed";
  ASSERT_NE(handle, 0u);

  auto stClose = call_close(helper, handle);
  ASSERT_TRUE(stClose.is_good()) << "Close failed";

  helper.release();
}

TEST_F(FileHelperTest, ReadWriteRoundTrip)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Write data.
  const ByteString testData = ByteString{0x48, 0x65, 0x6C, 0x6C, 0x6F};

  auto [stOpen, wHandle] = call_open(helper, 0x02 | 0x04);  // Write + EraseExisting
  ASSERT_TRUE(stOpen.is_good());

  auto stWrite = call_write(helper, wHandle, testData);
  ASSERT_TRUE(stWrite.is_good());

  auto stClose = call_close(helper, wHandle);
  ASSERT_TRUE(stClose.is_good());

  // Read back.
  auto [stOpen2, rHandle] = call_open(helper, 0x01);  // Read
  ASSERT_TRUE(stOpen2.is_good());

  auto [stRead, readData] = call_read(helper, rHandle, static_cast<int32_t>(testData.size()));
  ASSERT_TRUE(stRead.is_good());
  ASSERT_EQ(readData, testData);

  call_close(helper, rHandle);
  helper.release();
}

// @relation(AC-SVR-FILE-013-READ-VALIDATION, scope=function)
TEST_F(FileHelperTest, ReadValidatesHandleLengthAndModeAndCompletesOnceOutsideMutex)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const auto expectReadError =
    [](const CallMethodResult& result, Status expectedStatus, string_view expectedCode)
  {
    EXPECT_EQ(result.status_code().as_status(), expectedStatus);
    ASSERT_NE(result.status_code().shared_detail(), nullptr);
    EXPECT_EQ(result.status_code().shared_detail()->code, expectedCode);
    EXPECT_EQ(result.status_code().shared_detail()->source, "FileHelper");
    EXPECT_FALSE(result.status_code().shared_detail()->context.empty());
    EXPECT_TRUE(result.output_arguments().empty());
  };

  const ByteString expectedData{uint8_t{0x10}, uint8_t{0x20}, uint8_t{0x30}};
  auto [seedStatus, seedHandle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(seedStatus.is_good());
  ASSERT_TRUE(call_write(helper, seedHandle, expectedData).is_good());
  ASSERT_TRUE(call_close(helper, seedHandle).is_good());

  auto [readOpenStatus, readHandle] = call_open(helper, 0x01);
  ASSERT_TRUE(readOpenStatus.is_good());

  const auto zeroLength = call_read_result(helper, readHandle, 0);
  expectReadError(zeroLength, Status::BadInvalidArgument, "NonPositiveFileReadLength");

  auto readMethod = get_method(helper, "Read");
  ASSERT_TRUE(readMethod.has_value());
  CallMethodRequest negativeRequest;
  negativeRequest.object_id() = helper.node_id();
  negativeRequest.method_id() = readMethod->get_node_id();
  negativeRequest.input_arguments().resize(2);
  negativeRequest.input_arguments()[0] = Variant{readHandle};
  negativeRequest.input_arguments()[1] = Variant{int32_t{-1}};

  auto state = helper.shared_state();
  std::atomic<size_t> completionCount{0};
  bool completionOutsideMutex = false;
  StatusCode reentrantOpenStatus{Status::BadUnexpectedError};
  optional<CallMethodResult> negativeLength;
  readMethod->call_async(negativeRequest,
    nullptr,
    [&](CallResult result)
    {
      completionCount.fetch_add(1, std::memory_order_relaxed);
      std::unique_lock stateLock{state->mutex, std::try_to_lock};
      completionOutsideMutex = stateLock.owns_lock();
      if (completionOutsideMutex)
      {
        stateLock.unlock();
        reentrantOpenStatus = helper.try_open_handle(0x02).status_code();
      }
      if (result.is_good())
      {
        negativeLength = std::move(result).value();
      }
    });

  EXPECT_EQ(completionCount.load(std::memory_order_relaxed), 1u);
  EXPECT_TRUE(completionOutsideMutex);
  EXPECT_EQ(reentrantOpenStatus.as_status(), Status::BadNotWritable);
  ASSERT_TRUE(negativeLength.has_value());
  expectReadError(*negativeLength, Status::BadInvalidArgument, "NonPositiveFileReadLength");

  const auto unknownHandle = call_read_result(helper, uint32_t{0x7FFFFFFF}, 1);
  expectReadError(unknownHandle, Status::BadInvalidArgument, "InvalidFileHandle");

  const auto positiveLength =
    call_read_result(helper, readHandle, numeric_cast<int32_t>(expectedData.size()));
  ASSERT_TRUE(positiveLength.status_code().is_good());
  ASSERT_EQ(positiveLength.output_arguments().size(), 1u);
  EXPECT_EQ(positiveLength.output_arguments()[0].as<ByteString>(), expectedData);
  ASSERT_TRUE(call_close(helper, readHandle).is_good());

  auto [writeOpenStatus, writeHandle] = call_open(helper, 0x02);
  ASSERT_TRUE(writeOpenStatus.is_good());
  const auto wrongMode = call_read_result(helper, writeHandle, 1);
  expectReadError(wrongMode, Status::BadInvalidState, "FileHandleNotOpenedForRead");
  ASSERT_TRUE(call_close(helper, writeHandle).is_good());

  helper.release();
}

TEST_F(FileHelperTest, GetSetPosition)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Write some data first.
  const ByteString testData = ByteString{0x01, 0x02, 0x03, 0x04, 0x05};

  auto [stOpen, wHandle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen.is_good());
  call_write(helper, wHandle, testData);
  call_close(helper, wHandle);

  // Open for read.
  auto [stOpen2, rHandle] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpen2.is_good());

  // Read 3 bytes.
  auto [stRead, data] = call_read(helper, rHandle, 3);
  ASSERT_TRUE(stRead.is_good());
  ASSERT_EQ(data.size(), 3u);

  // GetPosition should be 3.
  auto [stPos, pos] = call_get_position(helper, rHandle);
  ASSERT_TRUE(stPos.is_good());
  ASSERT_EQ(pos, 3u);

  // SetPosition to 0.
  auto stSet = call_set_position(helper, rHandle, 0);
  ASSERT_TRUE(stSet.is_good());

  // GetPosition should be 0.
  auto [stPos2, pos2] = call_get_position(helper, rHandle);
  ASSERT_TRUE(stPos2.is_good());
  ASSERT_EQ(pos2, 0u);

  call_close(helper, rHandle);
  helper.release();
}

// @relation(AC-SVR-FILE-015-WRITE-CONTRACT, scope=function)
TEST_F(FileHelperTest, WriteDistinguishesEmptyWrongModeAndBackingStoreRefusal)
{
  const ByteString seed{0x10, 0x20, 0x30, 0x40};
  {
    std::ofstream output{mTempPath, std::ios::binary};
    output.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
  }

  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto [writeOpenStatus, writeHandle] = call_open(helper, 0x02);
  ASSERT_TRUE(writeOpenStatus.is_good());
  const StatusCode emptyStatus = call_write(helper, writeHandle, ByteString{});
  EXPECT_TRUE(emptyStatus.is_good()) << "an empty ByteString is a Good no-op";
  ASSERT_TRUE(call_close(helper, writeHandle).is_good());

  ByteString afterEmpty(seed.size(), uint8_t{0});
  {
    std::ifstream input{mTempPath, std::ios::binary};
    input.read(reinterpret_cast<char*>(afterEmpty.data()), static_cast<std::streamsize>(afterEmpty.size()));
  }
  EXPECT_EQ(afterEmpty, seed) << "an empty Write changed the backing file";

  auto [readOpenStatus, readHandle] = call_open(helper, 0x01);
  ASSERT_TRUE(readOpenStatus.is_good());
  const StatusCode wrongModeStatus = call_write(helper, readHandle, ByteString{0x55});
  EXPECT_EQ(wrongModeStatus.as_status(), Status::BadInvalidState);
  ASSERT_NE(wrongModeStatus.shared_detail(), nullptr);
  EXPECT_EQ(wrongModeStatus.shared_detail()->code, "FileHandleNotOpenedForWrite");
  ASSERT_TRUE(call_close(helper, readHandle).is_good());

  const std::filesystem::path unwritableStore{"/dev/full"};
  ASSERT_TRUE(std::filesystem::exists(unwritableStore));
  InstantiationOptions options{};
  auto unwritableResult = FileHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "UnwritableStoreFile"},
    unwritableStore,
    options,
    true);
  ASSERT_TRUE(unwritableResult.is_good());
  auto unwritable = std::move(unwritableResult).value();

  auto [unwritableOpenStatus, unwritableHandle] = call_open(unwritable, 0x02);
  ASSERT_TRUE(unwritableOpenStatus.is_good());
  const ByteString block(4000, uint8_t{0x5A});
  optional<StatusCode> refusal;
  for (int attempt = 0; attempt < 8 && !refusal.has_value(); ++attempt)
  {
    const StatusCode status = call_write(unwritable, unwritableHandle, block);
    if (status.is_bad())
      refusal = status;
  }

  ASSERT_TRUE(refusal.has_value()) << "the real backing store accepted every byte unexpectedly";
  EXPECT_EQ(refusal->as_status(), Status::BadNotWritable);
  ASSERT_NE(refusal->shared_detail(), nullptr);
  EXPECT_EQ(refusal->shared_detail()->code, "FileBackingStoreNotWritable");
  EXPECT_EQ(refusal->shared_detail()->source, "FileHelper");
  EXPECT_EQ(refusal->shared_detail()->innerStatus, static_cast<StatusCodeValue>(Status::BadUnexpectedError));
  ASSERT_NE(refusal->shared_detail()->cause, nullptr);
  EXPECT_EQ(refusal->shared_detail()->cause->code, "StreamWriteFailed");

  (void)call_close(unwritable, unwritableHandle);
  unwritable.release();
  helper.release();
}

// @relation(AC-SVR-FILE-016-SETPOSITION-CLAMPS, scope=function)
TEST_F(FileHelperTest, SetPositionPastEndClampsForReadAndWrite)
{
  const ByteString seed(64, uint8_t{0xA5});
  {
    std::ofstream output{mTempPath, std::ios::binary};
    output.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
  }

  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  auto [openStatus, handle] = call_open(helper, 0x03);
  ASSERT_TRUE(openStatus.is_good());

  const StatusCode setForRead = call_set_position(helper, handle, std::numeric_limits<uint64_t>::max());
  EXPECT_TRUE(setForRead.is_good());
  auto [positionStatus, position] = call_get_position(helper, handle);
  EXPECT_TRUE(positionStatus.is_good());
  EXPECT_EQ(position, seed.size());
  auto [readStatus, tail] = call_read(helper, handle, 1);
  EXPECT_TRUE(readStatus.is_good());
  EXPECT_TRUE(tail.empty());

  const StatusCode setForWrite = call_set_position(helper, handle, seed.size() + 1000u);
  EXPECT_TRUE(setForWrite.is_good());
  ASSERT_TRUE(call_write(helper, handle, ByteString{0xB6}).is_good());
  ASSERT_TRUE(call_close(helper, handle).is_good());

  ByteString expected = seed;
  expected.push_back(0xB6);
  ByteString onDisk(expected.size(), uint8_t{0});
  {
    std::ifstream input{mTempPath, std::ios::binary};
    input.read(reinterpret_cast<char*>(onDisk.data()), static_cast<std::streamsize>(onDisk.size()));
  }
  EXPECT_EQ(onDisk, expected);

  helper.release();
}

TEST_F(FileHelperTest, InvalidHandle)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const uint32_t bogus = 9999;

  EXPECT_TRUE(call_close(helper, bogus).is_bad());

  auto [stRead, readData] = call_read(helper, bogus, 10);
  EXPECT_TRUE(stRead.is_bad());

  ByteString dummy = ByteString{uint8_t{0x00}};
  EXPECT_TRUE(call_write(helper, bogus, dummy).is_bad());

  auto [stPos, pos] = call_get_position(helper, bogus);
  EXPECT_TRUE(stPos.is_bad());

  EXPECT_TRUE(call_set_position(helper, bogus, 0).is_bad());

  helper.release();
}

// @relation(AC-SVR-FILE-011-INVALID-MODE, scope=function)
TEST_F(FileHelperTest, OpenRejectsUndefinedModesWithoutAllocatingAHandleOrHoldingTheMutex)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  {
    std::ofstream file(mTempPath, std::ios::binary);
    file << "x";
  }

  auto state = helper.shared_state();
  {
    const std::lock_guard lock{state->mutex};
    state->maxByteStringLengthResolved = true;
  }
  auto openMethod = get_method(helper, "Open");
  ASSERT_TRUE(openMethod.has_value());

  const auto expectInvalidStatus = [this](const StatusCode& status, uint8_t mode)
  {
    EXPECT_EQ(status.as_status(), Status::BadInvalidArgument);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "InvalidFileOpenMode");
    EXPECT_EQ(status.shared_detail()->summary, "File open mode setting is invalid");
    EXPECT_EQ(status.shared_detail()->source, "FileHelper");
    ASSERT_EQ(status.shared_detail()->context.size(), 2u);
    EXPECT_EQ(status.shared_detail()->context[0].key, ContextKeys::filePath.value());
    EXPECT_EQ(status.shared_detail()->context[0].value, mTempPath.string());
    EXPECT_EQ(status.shared_detail()->context[1].key, ContextKeys::value.value());
    EXPECT_EQ(status.shared_detail()->context[1].value, std::to_string(mode));
  };

  const auto expectNoHandleAllocated = [&]
  {
    const std::lock_guard lock{state->mutex};
    EXPECT_TRUE(state->handles.empty());
    EXPECT_EQ(state->nextHandle, 1u);
  };

  const std::array invalidModes{uint8_t{0x00}, uint8_t{0x01 | 0x04}, uint8_t{0x01 | 0x10}};
  for (const uint8_t mode : invalidModes)
  {
    auto directResult = helper.try_open_handle(mode);
    expectInvalidStatus(directResult.status_code(), mode);
    expectNoHandleAllocated();

    CallMethodRequest request;
    request.object_id() = helper.node_id();
    request.method_id() = openMethod->get_node_id();
    request.input_arguments().resize(1);
    request.input_arguments()[0] = Variant{mode};

    std::atomic<size_t> completionCount{0};
    bool completionOutsideMutex = false;
    optional<CallMethodResult> methodResult;
    openMethod->call_async(request,
      nullptr,
      [&](CallResult result)
      {
        completionCount.fetch_add(1, std::memory_order_relaxed);
        std::unique_lock stateLock{state->mutex, std::try_to_lock};
        completionOutsideMutex = stateLock.owns_lock();
        if (completionOutsideMutex)
        {
          stateLock.unlock();
        }
        if (result.is_good())
        {
          methodResult = std::move(result).value();
        }
      });

    EXPECT_EQ(completionCount.load(std::memory_order_relaxed), 1u);
    EXPECT_TRUE(completionOutsideMutex);
    ASSERT_TRUE(methodResult.has_value());
    expectInvalidStatus(methodResult->status_code(), mode);
    EXPECT_TRUE(methodResult->output_arguments().empty());
    expectNoHandleAllocated();
  }

  helper.release();
}

// @relation(AC-SVR-FILE-009-OPEN-WRITE-WHILE-OPEN, scope=function)
// @relation(AC-SVR-FILE-010-OPEN-READ-WHILE-WRITING, scope=function)
TEST_F(FileHelperTest, ConflictingOpenCompletesOnceOutsideMutexWithItsOriginalDetailAndPermitsReentry)
{
  std::ofstream{mTempPath, std::ios::binary} << "conflict control";
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  auto state = helper.shared_state();
  {
    const std::lock_guard lock{state->mutex};
    state->maxByteStringLengthResolved = true;
  }
  auto openMethod = get_method(helper, "Open");
  auto closeMethod = get_method(helper, "Close");
  ASSERT_TRUE(openMethod.has_value());
  ASSERT_TRUE(closeMethod.has_value());

  for (const bool heldWriter : {false, true})
  {
    SCOPED_TRACE(heldWriter ? "read while writer holds a handle" : "write while reader holds a handle");
    const auto [opened, heldHandle] = call_open(helper, heldWriter ? uint8_t{0x02} : uint8_t{0x01});
    ASSERT_TRUE(opened.is_good());

    CallMethodRequest conflictRequest;
    conflictRequest.object_id() = helper.node_id();
    conflictRequest.method_id() = openMethod->get_node_id();
    conflictRequest.input_arguments() = Array<Variant>{Variant{heldWriter ? uint8_t{0x01} : uint8_t{0x02}}};
    CallMethodRequest permittedRequest = conflictRequest;
    permittedRequest.input_arguments() = Array<Variant>{Variant{uint8_t{0x01}}};
    CallMethodRequest closeRequest;
    closeRequest.object_id() = helper.node_id();
    closeRequest.method_id() = closeMethod->get_node_id();
    closeRequest.input_arguments() = Array<Variant>{Variant{heldHandle}};

    auto completionCount = std::make_shared<std::atomic<size_t>>(0);
    auto mutexAvailable = std::make_shared<std::atomic<bool>>(false);
    auto conflictPromise = std::make_shared<std::promise<CallResult>>();
    auto conflictFuture = conflictPromise->get_future();
    auto reentryPromise = std::make_shared<std::promise<CallResult>>();
    auto reentryFuture = reentryPromise->get_future();
    openMethod->call_async(conflictRequest,
      nullptr,
      [state,
        open = *openMethod,
        close = *closeMethod,
        heldWriter,
        permittedRequest,
        closeRequest,
        completionCount,
        mutexAvailable,
        conflictPromise,
        reentryPromise](CallResult result) mutable
      {
        if (completionCount->fetch_add(1) != 0)
          return;
        std::unique_lock stateLock{state->mutex, std::try_to_lock};
        mutexAvailable->store(stateLock.owns_lock());
        conflictPromise->set_value(std::move(result));
        if (!stateLock.owns_lock())
        {
          // Report the safety failure without re-entering a locked helper and hanging the test.
          reentryPromise->set_value(CallResult{StatusCode{Status::BadUnexpectedError}});
          return;
        }
        stateLock.unlock();
        auto openPermitted = [open, permittedRequest, reentryPromise]() mutable
        {
          open.call_async(permittedRequest,
            nullptr,
            [reentryPromise](CallResult reentered) { reentryPromise->set_value(std::move(reentered)); });
        };
        if (heldWriter)
        {
          close.call_async(closeRequest,
            nullptr,
            [openPermitted = std::move(openPermitted), reentryPromise](CallResult closed) mutable
            {
              if (closed.is_bad() || closed.value().status_code().is_bad())
              {
                reentryPromise->set_value(std::move(closed));
                return;
              }
              openPermitted();
            });
        }
        else
        {
          openPermitted();
        }
      });

    auto conflict = conflictFuture.get();
    const auto reentry = reentryFuture.get();
    EXPECT_EQ(completionCount->load(), 1u);
    EXPECT_TRUE(mutexAvailable->load());
    ASSERT_TRUE(conflict.is_good());
    const auto& refusal = conflict.value();
    EXPECT_EQ(
      refusal.status_code().as_status(), heldWriter ? Status::BadNotReadable : Status::BadNotWritable);
    EXPECT_TRUE(refusal.output_arguments().empty());
    const auto detail = refusal.status_code().shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, heldWriter ? "FileReadBlockedByWriter" : "FileWriteNotExclusive");
    EXPECT_EQ(detail->summary,
      heldWriter ? "A read Open was requested while a writer holds a handle on the file"
                 : "A write Open was requested while the file is already open");
    EXPECT_EQ(detail->source, "FileHelper");
    ASSERT_EQ(detail->context.size(), heldWriter ? 1u : 2u);
    EXPECT_EQ(detail->context[0].key, ContextKeys::filePath.value());
    EXPECT_EQ(detail->context[0].value, mTempPath.string());
    if (!heldWriter)
    {
      EXPECT_EQ(detail->context[1].key, ContextKeys::countActual.value());
      EXPECT_EQ(detail->context[1].value, "1");
      ASSERT_TRUE(call_close(helper, heldHandle).is_good());
    }
    if (mutexAvailable->load())
    {
      ASSERT_TRUE(reentry.is_good());
      ASSERT_TRUE(reentry.value().status_code().is_good());
      ASSERT_EQ(reentry.value().output_arguments().size(), 1u);
      ASSERT_TRUE(call_close(helper, reentry.value().output_arguments()[0].as<uint32_t>()).is_good());
    }
    else if (heldWriter)
    {
      ASSERT_TRUE(call_close(helper, heldHandle).is_good());
    }
  }
  helper.release();
}

// @relation(AC-SVR-FILE-011-INVALID-MODE, scope=function)
TEST_F(FileHelperTest, OpenAcceptsEveryDefinedModeCombination)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  {
    std::ofstream file(mTempPath, std::ios::binary);
    file << "x";
  }

  const std::array validModes{uint8_t{0x01},
    uint8_t{0x02},
    uint8_t{0x01 | 0x02},
    uint8_t{0x02 | 0x04},
    uint8_t{0x01 | 0x02 | 0x04},
    uint8_t{0x01 | 0x08},
    uint8_t{0x02 | 0x08},
    uint8_t{0x01 | 0x02 | 0x08},
    uint8_t{0x02 | 0x04 | 0x08},
    uint8_t{0x01 | 0x02 | 0x04 | 0x08}};
  for (const uint8_t mode : validModes)
  {
    auto directResult = helper.try_open_handle(mode);
    ASSERT_TRUE(directResult.is_good())
      << "direct Open rejected defined mode " << numeric_cast<unsigned>(mode);
    ASSERT_TRUE(call_close(helper, directResult.value()).is_good());

    auto [status, handle] = call_open(helper, mode);
    ASSERT_TRUE(status.is_good()) << "Open Method rejected defined mode " << numeric_cast<unsigned>(mode);
    ASSERT_NE(handle, 0u);
    ASSERT_TRUE(call_close(helper, handle).is_good());
  }

  helper.release();
}

// A slot is counted before its token exists; when making the token throws, the count is returned. A
// budget no shared_ptr owns makes the token's shared_from_this throw, so a second acquire shows whether
// the first one's slot leaked: it throws again, rather than being refused at a limit of one.
// @relation(AC-SVR-FILE-033-OPEN-HANDLES-SERVER-WIDE-BOUNDED, scope=function)
TEST(FileHandleBudgetTest, ASlotWhoseTokenCannotBeMadeIsReturned)
{
  detail::FileHandleBudget unowned;
  unowned.set_limits(/*perSession*/ 1, /*total*/ 1);
  const NodeId session{1, uint32_t{77}};
  EXPECT_THROW((void)unowned.acquire(session), std::bad_weak_ptr);
  EXPECT_THROW((void)unowned.acquire(session), std::bad_weak_ptr) << "the first acquire's slot leaked";
  EXPECT_THROW((void)unowned.acquire(NodeId{}), std::bad_weak_ptr) << "the first acquire's slot leaked";
}

// Each open FileType handle holds an operating-system file descriptor until Close or the end of its
// Session. Without a bound, one Session calling Open in a loop - or many Sessions together - takes every
// descriptor the server has, and the server can then accept no socket. The address space's handle budget
// bounds the handles one Session may hold across every file, and the handles all Sessions hold together;
// a Close frees a slot.
// @relation(AC-SVR-FILE-032-OPEN-HANDLES-PER-SESSION-BOUNDED, scope=function)
// @relation(AC-SVR-FILE-033-OPEN-HANDLES-SERVER-WIDE-BOUNDED, scope=function)
TEST_F(FileHelperTest, OpenHandlesAreBoundedPerSessionAcrossFilesAndInTotal)
{
  detail::AddressSpaceFileHandles::set_limits(*mAddressSpace, /*perSession*/ 2, /*total*/ 3);
  auto firstResult = create_helper("QuotaFileA");
  ASSERT_TRUE(firstResult.is_good());
  auto first = std::move(firstResult).value();
  auto secondResult = create_helper("QuotaFileB");
  ASSERT_TRUE(secondResult.is_good());
  auto second = std::move(secondResult).value();
  // The file exists once it has been opened for writing.
  auto [created, createHandle] = call_open(first, 0x02 | 0x04);  // Write + EraseExisting
  ASSERT_TRUE(created.is_good()) << to_string(created);
  ASSERT_TRUE(call_close(first, createHandle).is_good());

  const NodeId sessionA{1, "quota-a"};
  const NodeId sessionB{1, "quota-b"};
  const auto open_as = [&](const FileHelper& helper, const NodeId& session)
  {
    return call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, session);
  };
  const auto limit_named = [](const CallMethodResult& result) -> std::string
  {
    const auto& detail = result.status_code().shared_detail();
    if (!detail)
      return {};
    for (const auto& entry : detail->context)
      if (entry.key == ContextKeys::fieldName.value())
        return std::string{entry.value};
    return {};
  };

  // Session A: its two handles may be on different files, and a third on either is refused.
  auto a1 = open_as(first, sessionA);
  ASSERT_TRUE(a1.status_code().is_good()) << to_string(a1.status_code());
  auto a2 = open_as(second, sessionA);
  ASSERT_TRUE(a2.status_code().is_good()) << to_string(a2.status_code());
  auto aRefused = open_as(first, sessionA);
  EXPECT_EQ(aRefused.status_code().as_status(), Status::BadTooManyOperations)
    << to_string(aRefused.status_code());
  ASSERT_NE(aRefused.status_code().shared_detail(), nullptr);
  EXPECT_EQ(aRefused.status_code().shared_detail()->code, "FileHandleLimitReached");
  EXPECT_EQ(limit_named(aRefused), "ResourceLimits.OpenFileHandlesPerSession");

  // Session B has a quota of its own, but the server holds three handles in all.
  auto b1 = open_as(first, sessionB);
  ASSERT_TRUE(b1.status_code().is_good()) << "another Session's quota is its own";
  auto bRefused = open_as(second, sessionB);
  EXPECT_EQ(bRefused.status_code().as_status(), Status::BadTooManyOperations)
    << to_string(bRefused.status_code());
  EXPECT_EQ(limit_named(bRefused), "ResourceLimits.OpenFileHandles");

  // A Close frees a slot, of the Session's quota and of the total.
  const auto a2Handle = a2.output_arguments()[0].as<uint32_t>();
  ASSERT_TRUE(call_as_session(second, "Close", {Variant{a2Handle}}, sessionA).status_code().is_good());
  auto again = open_as(second, sessionB);
  EXPECT_TRUE(again.status_code().is_good()) << "a Close frees a slot: " << to_string(again.status_code());

  // A Session that ends returns the slots of the handles it never closed.
  const NodeId sessionC{1, "quota-c"};
  EXPECT_EQ(open_as(first, sessionC).status_code().as_status(), Status::BadTooManyOperations)
    << "three handles are open, the server-wide limit";
  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionA);
  auto afterEnd = open_as(first, sessionC);
  EXPECT_TRUE(afterEnd.status_code().is_good())
    << "the ended Session's handle still holds its slot: " << to_string(afterEnd.status_code());
  if (afterEnd.status_code().is_good())
    (void)call_as_session(first, "Close", {Variant{afterEnd.output_arguments()[0].as<uint32_t>()}}, sessionC);

  (void)call_as_session(first, "Close", {Variant{a1.output_arguments()[0].as<uint32_t>()}}, sessionA);
  (void)call_as_session(first, "Close", {Variant{b1.output_arguments()[0].as<uint32_t>()}}, sessionB);
  if (again.status_code().is_good())
    (void)call_as_session(second, "Close", {Variant{again.output_arguments()[0].as<uint32_t>()}}, sessionB);
  first.release();
  second.release();
}

// SVR-FILE-007 / Part 20 section 4.2.1 lines 320-322: "The fileHandle is generated by the server and is
// unique for the Session. Clients cannot transfer the fileHandle to another Session but need to get
// a new fileHandle by calling the Open Method." section 4.2.2 line 284 adds that the handle "is valid while
// the session is open".
//
// The handle is an index into the server's open-file table, not authority over it. Handle ids come
// from a monotonic counter, so a second Session does not even have to guess: it opens its own file,
// sees handle N, and knows N-1 and N-2 are live handles belonging to somebody else. Every FileType
// method then acts on whatever the id resolves to.
//
// What that buys an attacker is read of another Session's file content regardless of its own
// permissions, write into a file it may hold no writable handle for, a seek that corrupts another
// Session's sequential read, and a Close that revokes another Session's access - a denial of service
// needing no privilege at all.
//
// The refusal is Bad_InvalidArgument, the same code section 4.2.3 gives for an unknown handle, and that
// sameness is deliberate: a distinguishable "exists, but not yours" would answer "does handle N
// exist?" for handles the caller does not own.
//
// Falsifiable: a server that keys handles on the id alone lets every assertion below succeed for the
// wrong Session - which is what this test found before the fix.
// @verifies AC-SVR-FILE-007-HANDLE-SESSION-SCOPED
// @relation(AC-SVR-FILE-007-HANDLE-SESSION-SCOPED, scope=function)
TEST_F(FileHelperTest, AFileHandleIsUsableOnlyByTheSessionThatOpenedIt)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const NodeId sessionA{1, "session-a"};
  const NodeId sessionB{1, "session-b"};

  // Session A seeds the file through a write handle, then closes it. The seeding write and the two
  // read handles below are deliberately not concurrent: Part 20 section 4.2.1 makes writes exclusive, so a
  // reader opened while this writer is live would be refused for that reason and this test would be
  // measuring concurrency rather than handle ownership.
  {
    auto seed = call_as_session(helper, "Open", {Variant{uint8_t{0x02 | 0x04}}}, sessionA);
    ASSERT_TRUE(seed.status_code().is_good());
    ASSERT_EQ(seed.output_arguments().size(), 1u);
    const auto seedHandle = seed.output_arguments()[0].as<uint32_t>();
    const ByteString secret = ByteString{0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_TRUE(call_as_session(helper, "Write", {Variant{seedHandle}, Variant{secret}}, sessionA)
                  .status_code()
                  .is_good());
    ASSERT_TRUE(call_as_session(helper, "Close", {Variant{seedHandle}}, sessionA).status_code().is_good());
  }

  auto openA = call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, sessionA);
  ASSERT_TRUE(openA.status_code().is_good());
  ASSERT_EQ(openA.output_arguments().size(), 1u);
  const auto handleA = openA.output_arguments()[0].as<uint32_t>();

  // Session B holds a handle of its own, so it is a legitimate client of this file - it simply has
  // no claim on A's. This also pins that the refusal is about the handle's owner and not about
  // whether the caller has opened anything. Two readers may coexist, which is what makes this
  // arrangement possible at all.
  auto openB = call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, sessionB);
  ASSERT_TRUE(openB.status_code().is_good());
  const auto handleB = openB.output_arguments()[0].as<uint32_t>();
  ASSERT_NE(handleA, handleB);

  // Every method that consumes a handle refuses A's handle when B presents it.
  EXPECT_EQ(call_as_session(helper, "Read", {Variant{handleA}, Variant{int32_t{4}}}, sessionB)
              .status_code()
              .as_status(),
    Status::BadInvalidArgument)
    << "Session B read the file through Session A's handle";

  // Ownership is checked before the handle's mode is, so this is refused as an unknown handle rather
  // than as a read handle asked to write - which is the answer that matters: B must not learn that
  // A's handle exists.
  EXPECT_EQ(call_as_session(helper, "Write", {Variant{handleA}, Variant{ByteString{0x00}}}, sessionB)
              .status_code()
              .as_status(),
    Status::BadInvalidArgument)
    << "Session B wrote through Session A's handle";

  EXPECT_EQ(call_as_session(helper, "GetPosition", {Variant{handleA}}, sessionB).status_code().as_status(),
    Status::BadInvalidArgument)
    << "Session B read the position of Session A's handle";

  EXPECT_EQ(call_as_session(helper, "SetPosition", {Variant{handleA}, Variant{uint64_t{0}}}, sessionB)
              .status_code()
              .as_status(),
    Status::BadInvalidArgument)
    << "Session B moved the position of Session A's handle, corrupting A's sequential access";

  EXPECT_EQ(call_as_session(helper, "Close", {Variant{handleA}}, sessionB).status_code().as_status(),
    Status::BadInvalidArgument)
    << "Session B closed Session A's handle, revoking access it did not own";

  // The refusals must not have cost A anything: its handle is still live and still positioned where
  // it left it. Without this, a fix that simply invalidated the handle on a foreign touch would pass
  // every assertion above while breaking the owner.
  auto setPosA = call_as_session(helper, "SetPosition", {Variant{handleA}, Variant{uint64_t{0}}}, sessionA);
  EXPECT_TRUE(setPosA.status_code().is_good()) << "Session A lost its own handle";

  auto closeA = call_as_session(helper, "Close", {Variant{handleA}}, sessionA);
  EXPECT_TRUE(closeA.status_code().is_good()) << "Session A could not close its own handle";

  auto closeB = call_as_session(helper, "Close", {Variant{handleB}}, sessionB);
  EXPECT_TRUE(closeB.status_code().is_good()) << "Session B could not close its own handle";

  helper.release();
}

// @verifies AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE
// @relation(AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE, scope=function)
TEST_F(FileHelperTest, ClosingASessionReleasesTheHandlesItOpened)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const NodeId sessionA{1, "session-a"};
  const NodeId sessionB{1, "session-b"};

  // Session A opens for writing and then vanishes without calling Close - the ordinary shape of a
  // dropped connection, and the one OPC 10000-20 section 4.2.2 answers: the handle "is valid while the
  // session is open", so ending the Session ends the handle.
  auto openA = call_as_session(helper, "Open", {Variant{uint8_t{0x02 | 0x04}}}, sessionA);
  ASSERT_TRUE(openA.status_code().is_good());
  ASSERT_EQ(openA.output_arguments().size(), 1u);
  const auto handleA = openA.output_arguments()[0].as<uint32_t>();

  auto countWhileOpen = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(countWhileOpen.is_good());
  ASSERT_EQ(countWhileOpen.value(), 1u);

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionA);

  // OpenCount is Mandatory and counts "the file handles currently valid on the file" (section 4.2.1), so a
  // handle whose Session has gone must not still be counted.
  auto countAfterClose = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(countAfterClose.is_good());
  EXPECT_EQ(countAfterClose.value(), 0u) << "a handle outlived the Session that opened it";

  // The consequence that makes this more than a leak. section 4.2.2 refuses a write Open while the file is
  // already open, so an unreclaimed write handle locks the file against every later Client - not
  // just against the one that disconnected - with no route back short of a restart.
  auto openB = call_as_session(helper, "Open", {Variant{uint8_t{0x02 | 0x04}}}, sessionB);
  EXPECT_TRUE(openB.status_code().is_good())
    << "a new Session could not open the file for writing after the previous owner disconnected: "
    << openB.status_code().as_uint32();
  ASSERT_EQ(openB.output_arguments().size(), 1u);
  const auto handleB = openB.output_arguments()[0].as<uint32_t>();

  // A released handle is released for everyone: the number A held names nothing now, even when A's
  // own Session presents it.
  EXPECT_EQ(call_as_session(helper, "Read", {Variant{handleA}, Variant{int32_t{1}}}, sessionA)
              .status_code()
              .as_status(),
    Status::BadInvalidArgument)
    << "a handle survived the close of the Session that owned it";

  // Only the closed Session's handles go. A notification naming a Session that holds nothing must
  // leave the live handles of every other Session alone.
  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionA);
  EXPECT_EQ(call_as_session(helper, "GetPosition", {Variant{handleB}}, sessionB).status_code().as_status(),
    Status::Good)
    << "closing one Session took another Session's handle with it";

  ASSERT_TRUE(call_as_session(helper, "Close", {Variant{handleB}}, sessionB).status_code().is_good());
  helper.release();
}

// @verifies AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE
// @relation(AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE, scope=function)
// @relation(AC-COMP-SDK-POST-FILE-SESSION, scope=function)
TEST_F(FileHelperTest, ClosingASessionLeavesInternallyOpenedHandlesAlone)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // `call_open` carries no MethodCallContext, so this handle belongs to the contextless internal
  // caller and is recorded against a null session id. Sessions close all the time; the SDK's own
  // handles must not be swept away with them, and a reclamation keyed on "same session id" would do
  // exactly that for any Session whose id happened to be null.
  auto [stOpen, handle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen.is_good());

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, NodeId{});
  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, NodeId{1, "some-session"});

  auto count = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(count.is_good());
  EXPECT_EQ(count.value(), 1u) << "an internally opened handle was reclaimed by a Session closing";

  EXPECT_TRUE(call_write(helper, handle, ByteString{0x01}).is_good())
    << "an internally opened handle stopped working after a Session closed";

  call_close(helper, handle);
  helper.release();
}

TEST_F(FileHelperTest, MultipleHandles)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Write data.
  const ByteString testData = ByteString{0xAA, 0xBB, 0xCC, 0xDD};
  auto [stOpen, wHandle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen.is_good());
  call_write(helper, wHandle, testData);
  call_close(helper, wHandle);

  // Open two read handles.
  auto [stOpen1, h1] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpen1.is_good());
  auto [stOpen2, h2] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpen2.is_good());
  EXPECT_NE(h1, h2);

  // Read 2 bytes from h1 - position should be 2.
  call_read(helper, h1, 2);
  auto [stPos1, pos1] = call_get_position(helper, h1);
  ASSERT_EQ(pos1, 2u);

  // h2 should still be at 0.
  auto [stPos2, pos2] = call_get_position(helper, h2);
  ASSERT_EQ(pos2, 0u);

  call_close(helper, h1);
  call_close(helper, h2);
  helper.release();
}

TEST_F(FileHelperTest, PropertyValuesWritableAndUserWritable)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Default is writable=true.
  auto writableResult = helper.file().try_read_writable_sync();
  ASSERT_TRUE(writableResult.is_good());
  EXPECT_TRUE(writableResult.value());

  auto userWritableResult = helper.file().try_read_user_writable_sync();
  ASSERT_TRUE(userWritableResult.is_good());
  EXPECT_TRUE(userWritableResult.value());

  helper.release();
}

TEST_F(FileHelperTest, PropertyValuesReadOnly)
{
  InstantiationOptions options{};
  auto helperResult = FileHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "ReadOnlyFile"},
    mTempPath,
    options,
    false);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto writableResult = helper.file().try_read_writable_sync();
  ASSERT_TRUE(writableResult.is_good());
  EXPECT_FALSE(writableResult.value());

  auto userWritableResult = helper.file().try_read_user_writable_sync();
  ASSERT_TRUE(userWritableResult.is_good());
  EXPECT_FALSE(userWritableResult.value());

  helper.release();
}

TEST_F(FileHelperTest, ReadOnlyRejectsWriteMode)
{
  InstantiationOptions options{};
  auto helperResult = FileHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "ReadOnlyFile"},
    mTempPath,
    options,
    false);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Create the file so read mode works.
  {
    std::ofstream ofs(mTempPath);
  }

  // Read mode should succeed.
  auto [stRead, rHandle] = call_open(helper, 0x01);
  ASSERT_TRUE(stRead.is_good());
  call_close(helper, rHandle);

  // Write mode should be rejected.
  auto [stWrite, wHandle] = call_open(helper, 0x02);
  EXPECT_TRUE(stWrite.is_bad());

  // Erase mode should be rejected.
  auto [stErase, eHandle] = call_open(helper, 0x01 | 0x04);
  EXPECT_TRUE(stErase.is_bad());

  // Append is independent of Write, so Read + Append remains valid on a read-only file.
  auto [stAppend, aHandle] = call_open(helper, 0x01 | 0x08);
  ASSERT_TRUE(stAppend.is_good());
  ASSERT_TRUE(call_close(helper, aHandle).is_good());

  helper.release();
}

// Part 20 section 4.2.1: UserWritable includes the calling user's rights. FileHelper receives the
// service-computed verdict in MethodCallContext and must apply it to write Open before allocating a
// handle; read Open is the control and remains permitted for that same user.
// @relation(AC-SVR-FILE-003-USERWRITABLE, scope=function)
TEST_F(FileHelperTest, OpenForWriteRejectsAUserWithoutWritePermissionBeforeIssuingAHandle)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  {
    std::ofstream seed{mTempPath, std::ios::binary};
    seed.write("seed", 4);
  }

  const NodeId restrictedSession{1, "restricted-file-user"};
  auto readOpen = call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, restrictedSession, false);
  ASSERT_TRUE(readOpen.status_code().is_good());
  ASSERT_EQ(readOpen.output_arguments().size(), 1u);
  const auto readHandle = readOpen.output_arguments()[0].as<uint32_t>();
  ASSERT_TRUE(call_as_session(helper, "Close", {Variant{readHandle}}, restrictedSession, false)
                .status_code()
                .is_good());

  auto writeOpen = call_as_session(helper, "Open", {Variant{uint8_t{0x02}}}, restrictedSession, false);
  EXPECT_EQ(writeOpen.status_code().as_status(), Status::BadUserAccessDenied);
  EXPECT_TRUE(writeOpen.output_arguments().empty());
  ASSERT_TRUE(writeOpen.status_code().shared_detail());
  EXPECT_EQ(writeOpen.status_code().shared_detail()->code, "TestFileWriteDenied");

  auto permittedWriteOpen =
    call_as_session(helper, "Open", {Variant{uint8_t{0x02}}}, restrictedSession, true);
  ASSERT_TRUE(permittedWriteOpen.status_code().is_good());
  ASSERT_EQ(permittedWriteOpen.output_arguments().size(), 1u);
  const auto writeHandle = permittedWriteOpen.output_arguments()[0].as<uint32_t>();
  ASSERT_TRUE(call_as_session(helper, "Close", {Variant{writeHandle}}, restrictedSession, true)
                .status_code()
                .is_good());

  auto openCount = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(openCount.is_good());
  EXPECT_EQ(openCount.value(), 0u);
  helper.release();
}

TEST_F(FileHelperTest, SizePropertyReflectsFileSize)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Write some data.
  const ByteString testData = ByteString{0x01, 0x02, 0x03, 0x04, 0x05};
  auto [stOpen, wHandle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen.is_good());
  call_write(helper, wHandle, testData);
  call_close(helper, wHandle);

  // Read the Size property - should reflect actual file size.
  auto sizeResult = helper.file().try_read_size_sync();
  ASSERT_TRUE(sizeResult.is_good());
  EXPECT_EQ(sizeResult.value(), 5u);

  helper.release();
}

// Covers SVR-FILE-004 (coverage-audit retag).
TEST_F(FileHelperTest, OpenCountPropertyTracksHandles)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Create the file.
  auto [stOpen1, h1] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen1.is_good());

  auto countResult1 = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(countResult1.is_good());
  EXPECT_EQ(countResult1.value(), 1u);

  // Open another handle.
  call_close(helper, h1);
  {
    std::ofstream ofs(mTempPath);
  }  // Ensure file exists for read.
  auto [stOpen2, h2] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpen2.is_good());
  auto [stOpen3, h3] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpen3.is_good());

  auto countResult2 = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(countResult2.is_good());
  EXPECT_EQ(countResult2.value(), 2u);

  // Close one - count should drop.
  call_close(helper, h2);
  auto countResult3 = helper.file().try_read_open_count_sync();
  ASSERT_TRUE(countResult3.is_good());
  EXPECT_EQ(countResult3.value(), 1u);

  call_close(helper, h3);
  helper.release();
}

// @relation(AC-SVR-FILE-017-HANDLES-RELEASED-ON-CLOSE, scope=function)
TEST_F(FileHelperTest, SessionCleanupReleasesOnlyTheClosingSessionsHandles)
{
  std::ofstream{mTempPath, std::ios::binary | std::ios::trunc} << "session-owned";
  auto helperResult = create_helper("SessionCleanupFile");
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const NodeId sessionA{1, 401u};
  const NodeId sessionB{1, 402u};
  const auto openA = call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, sessionA);
  const auto openB = call_as_session(helper, "Open", {Variant{uint8_t{0x01}}}, sessionB);
  ASSERT_TRUE(openA.status_code().is_good());
  ASSERT_TRUE(openB.status_code().is_good());
  const auto handleA = openA.output_arguments()[0].as<uint32_t>();
  const auto handleB = openB.output_arguments()[0].as<uint32_t>();
  ASSERT_EQ(helper.file().try_read_open_count_sync().value(), 2u);

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionA);

  EXPECT_EQ(helper.file().try_read_open_count_sync().value(), 1u);
  const auto readA = call_as_session(helper, "Read", {Variant{handleA}, Variant{int32_t{1}}}, sessionA);
  const auto readB = call_as_session(helper, "Read", {Variant{handleB}, Variant{int32_t{1}}}, sessionB);
  EXPECT_EQ(readA.status_code().as_status(), Status::BadInvalidArgument);
  EXPECT_TRUE(readB.status_code().is_good());

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionB);
  EXPECT_EQ(helper.file().try_read_open_count_sync().value(), 0u);
  helper.release();
}

class TemporaryFileTransferHelperTest : public FileHelperTest
{
protected:
  void SetUp() override
  {
    FileHelperTest::SetUp();
    mTransferDirectory = ua::test_utils::unique_temp_path("temporary_transfer_session_cleanup", "");
    std::filesystem::create_directories(mTransferDirectory);
  }

  void TearDown() override
  {
    std::error_code error;
    std::filesystem::remove_all(mTransferDirectory, error);
    FileHelperTest::TearDown();
  }

  void expect_commit_failure_cleanup(TemporaryFileTransferConfig config, const StatusCode& expectedCause,
    bool hookThrows, const std::string& expectedExceptionMessage = {})
  {
    InstantiationOptions options{};
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
    config.tempDir = mTransferDirectory;
    config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
    config.maxActiveTransfersPerSession = 1;
    auto created = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
      NodeId{ObjectId::ObjectsFolder},
      QualifiedName{1, "FailingCommitTransfer"},
      options,
      config);
    ASSERT_TRUE(created.is_good());
    auto helper = std::move(created).value();
    auto generate = helper.transfer().try_generate_file_for_write_method_sync();
    auto closeAndCommit = helper.transfer().try_close_and_commit_method_sync();
    ASSERT_TRUE(generate.is_good());
    ASSERT_TRUE(closeAndCommit.is_good());
    const NodeId session{1, 655u};

    for (int round = 0; round < 3; ++round)
    {
      SCOPED_TRACE(round);
      const auto generated = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
      ASSERT_TRUE(generated.status_code().is_good()) << "the previous failed commit must release its slot";
      ASSERT_EQ(generated.output_arguments().size(), 2u);
      const auto fileNode = generated.output_arguments()[0].as<NodeId>();
      const auto fileHandle = generated.output_arguments()[1].as<uint32_t>();
      auto write = get_method_of(fileNode, "Write");
      ASSERT_TRUE(write.has_value());
      const auto writeNode = write->get_node_id();
      const ByteString payload{uint8_t{0xA5}, uint8_t{0x5A}};
      ASSERT_TRUE(call_as_session(fileNode, *write, {Variant{fileHandle}, Variant{payload}}, session)
                    .status_code()
                    .is_good());
      std::vector<std::filesystem::path> files;
      for (const auto& entry : std::filesystem::directory_iterator(mTransferDirectory))
        files.push_back(entry.path());
      EXPECT_EQ(files.size(), 1u) << "a quota of one must not leave previous failed transfers on disk";
      ASSERT_FALSE(files.empty());
      const auto path = files.back();

      CallMethodRequest request;
      request.object_id() = helper.node_id();
      request.method_id() = closeAndCommit.value().get_node_id();
      request.input_arguments() = Array<Variant>{Variant{fileHandle}};
      auto context = std::make_shared<MethodCallContext>();
      context->sessionId = session;
      auto completionCount = std::make_shared<std::atomic<size_t>>(0);
      auto promise = std::make_shared<std::promise<CallResult>>();
      auto future = promise->get_future();
      closeAndCommit.value().call_async(request,
        std::move(context),
        [path, fileNode, addressSpace = *mAddressSpace, completionCount, promise](CallResult result) mutable
        {
          if (completionCount->fetch_add(1) != 0)
            return;
          EXPECT_FALSE(std::filesystem::exists(path)) << "the file must be removed before completion";
          addressSpace.find_node_async(fileNode,
            [promise, result = std::move(result)](NodeAccessorResult node) mutable
            {
              EXPECT_EQ(node.status_code().as_status(), Status::BadNodeIdUnknown)
                << "the transient node must be removed before completion";
              promise->set_value(std::move(result));
            });
        });
      auto result = future.get();
      EXPECT_EQ(completionCount->load(), 1u);
      ASSERT_TRUE(result.is_good());
      const auto& committed = result.value();
      EXPECT_TRUE(committed.output_arguments().empty());
      const auto status = committed.status_code();
      EXPECT_EQ(status.as_status(), hookThrows ? Status::BadInternalError : expectedCause.as_status());
      ASSERT_NE(status.shared_detail(), nullptr);
      if (hookThrows)
      {
        EXPECT_EQ(status.shared_detail()->innerStatus, expectedCause.value());
        ASSERT_NE(status.shared_detail()->cause, nullptr);
        if (expectedCause.shared_detail())
        {
          EXPECT_EQ(status.shared_detail()->cause, expectedCause.shared_detail())
            << "the original rich exception cause must survive unchanged";
        }
        else
        {
          const auto cause = status.shared_detail()->cause;
          EXPECT_EQ(cause->code, "StdException");
          ASSERT_EQ(cause->context.size(), 1u);
          EXPECT_EQ(cause->context[0].key, ContextKeys::errorMessage.value());
          EXPECT_EQ(cause->context[0].value, expectedExceptionMessage);
        }
      }
      else
      {
        EXPECT_EQ(status.shared_detail(), expectedCause.shared_detail());
      }
      EXPECT_EQ(
        mAddressSpace->try_find_node_sync(fileNode).status_code().as_status(), Status::BadNodeIdUnknown);
      EXPECT_EQ(
        mAddressSpace->try_find_node_sync(writeNode).status_code().as_status(), Status::BadNodeIdUnknown)
        << "the transient method subtree must be removed";
      EXPECT_TRUE(std::filesystem::is_empty(mTransferDirectory))
        << "failed commits may not create untracked resources outside the active-transfer quota";
    }
    helper.release();
  }

  std::filesystem::path mTransferDirectory;

  /// A method of an arbitrary node (the transient FileType nodes the transfers create).
  optional<MethodAccessor> get_method_of(const NodeId& objectId, const std::string& methodName)
  {
    std::promise<MethodAccessorResult> promise;
    auto future = promise.get_future();
    instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
      objectId,
      NodeId{ReferenceTypeId::HasComponent},
      QualifiedName{0, methodName},
      [&promise](MethodAccessorResult res) { promise.set_value(std::move(res)); });
    auto res = future.get();
    if (res.is_good())
      return std::move(res).value();
    return std::nullopt;
  }
};

// @relation(AC-SVR-FILE-022-TEMP-FILES-DELETED-ON-SESSION-END, scope=function)
TEST_F(TemporaryFileTransferHelperTest, SessionCleanupDeletesOnlyTheClosingSessionsFiles)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};

  auto helperResult = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "SessionCleanupTransfer"},
    options,
    std::move(config));
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());

  const NodeId sessionA{1, 501u};
  const NodeId sessionB{1, 502u};
  const auto generatedA = call_as_session(helper.node_id(), generate.value(), {Variant{}}, sessionA);
  std::vector<std::filesystem::path> filesAfterA;
  for (const auto& entry : std::filesystem::directory_iterator(mTransferDirectory))
    filesAfterA.push_back(entry.path());
  ASSERT_EQ(filesAfterA.size(), 1u) << "A's transfer file";
  const auto generatedB = call_as_session(helper.node_id(), generate.value(), {Variant{}}, sessionB);
  ASSERT_TRUE(generatedA.status_code().is_good());
  ASSERT_TRUE(generatedB.status_code().is_good());
  const NodeId nodeA = generatedA.output_arguments()[0].as<NodeId>();
  const NodeId nodeB = generatedB.output_arguments()[0].as<NodeId>();
  ASSERT_TRUE(mAddressSpace->try_find_node_sync(nodeA).is_good());
  ASSERT_TRUE(mAddressSpace->try_find_node_sync(nodeB).is_good());
  // DEF-7: the transfer files carry unpredictable names now; the test observes them by listing the
  // directory, one file per generated transfer, and tells them apart by which survives the close.
  const auto transferFiles = [&]
  {
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(mTransferDirectory))
      files.push_back(entry.path());
    return files;
  };
  ASSERT_EQ(transferFiles().size(), 2u) << "one transfer file per generated transfer";
  // Which file is whose: B's is the one that appeared after A's.
  const auto fileOfA = filesAfterA.front();
  std::filesystem::path fileOfB;
  for (const auto& file : transferFiles())
    if (file != fileOfA)
      fileOfB = file;
  ASSERT_FALSE(fileOfB.empty());

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionA);
  ::ua::test_utils::drain_with_timeout(*mThreadPool);

  EXPECT_TRUE(mAddressSpace->try_find_node_sync(nodeA).is_bad());
  EXPECT_FALSE(std::filesystem::exists(fileOfA)) << "session A's file is gone";
  EXPECT_TRUE(std::filesystem::exists(fileOfB)) << "session B's file is untouched";
  EXPECT_TRUE(mAddressSpace->try_find_node_sync(nodeB).is_good());
  EXPECT_TRUE(std::filesystem::exists(fileOfB)) << "session B's file survives A's close";

  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, sessionB);
  ::ua::test_utils::drain_with_timeout(*mThreadPool);
  helper.release();
}

TEST_F(FileHelperTest, AttachWiresHandlers)
{
  // First create a bare File node.
  InstantiationOptions options{};
  auto fileCreateResult = File::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "AttachFile"}, options);
  ASSERT_TRUE(fileCreateResult.is_good());
  auto file = std::move(fileCreateResult).value();

  const auto nodeId = file.node_id();
  file.release();

  // Now attach a FileHelper to it.
  auto attachResult = FileHelper::try_attach_sync(*mAddressSpace, nodeId, mTempPath);
  ASSERT_TRUE(attachResult.is_good());
  auto helper = std::move(attachResult).value();
  EXPECT_EQ(helper.node_id(), nodeId);

  // The helper should work - write and read back.
  auto [stOpen, wHandle] = call_open(helper, 0x02 | 0x04);
  ASSERT_TRUE(stOpen.is_good());

  const ByteString testData = ByteString{0xDE, 0xAD};
  call_write(helper, wHandle, testData);
  call_close(helper, wHandle);

  auto [stOpenR, rHandle] = call_open(helper, 0x01);
  ASSERT_TRUE(stOpenR.is_good());
  auto [stRead, data] = call_read(helper, rHandle, 2);
  ASSERT_TRUE(stRead.is_good());
  EXPECT_EQ(data, testData);
  call_close(helper, rHandle);

  // Cleanup - attached helper doesn't own the node.
  mAddressSpace->delete_node_sync(nodeId, true);
}

TEST_F(FileHelperTest, FileAccessor)
{
  auto helperResult = create_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // file() should return a reference to the underlying File.
  const File& f = helper.file();
  EXPECT_EQ(f.node_id(), helper.node_id());

  helper.release();
}

// @relation(AC-SVR-FILE-018-FILESYSTEM-ROOT-BROWSENAME, scope=function)
TEST_F(FileDirectoryHelperTest, FileSystemBrowseNameIsPreservedForConfiguredRoot)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const auto browseName = mAddressSpace->find_node_sync(helper.node_id()).get_browse_name();
  EXPECT_EQ(browseName.namespace_index(), 1u);
  EXPECT_EQ(std::string_view{browseName.name()}, "FileSystem");
}

// A FileName / DirectoryName argument names one child of the directory: a single path component.
// Separators, parent references, a root or an empty name would resolve outside the directory.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryHelperTest, ChildNamesThatAreNotASinglePathComponentAreRefused)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  const auto outside = mDirectoryPath.parent_path() / "escape";
  std::error_code ignored;
  std::filesystem::remove_all(outside, ignored);
  const std::string absoluteEscape = (mOutsideRoot / "escape").string();

  for (const std::string& name :
    std::vector<std::string>{"..", ".", "../escape", "a/b", "a\\b", absoluteEscape, ""})
  {
    const auto directory = call_create_directory(helper, name);
    EXPECT_EQ(directory.status_code().as_status(), Status::BadBrowseNameInvalid)
      << "CreateDirectory " << name;
    EXPECT_TRUE(directory.output_arguments().empty()) << name;
    const auto file = call_create_file(helper, name);
    EXPECT_EQ(file.status_code().as_status(), Status::BadBrowseNameInvalid) << "CreateFile " << name;
    EXPECT_TRUE(file.output_arguments().empty()) << name;
  }
  EXPECT_FALSE(std::filesystem::exists(outside)) << "nothing may be created outside the directory";
  EXPECT_FALSE(std::filesystem::exists(mDirectoryPath / "a"));
  EXPECT_FALSE(std::filesystem::exists(mOutsideRoot / "escape"));
  EXPECT_EQ(count_children_named(helper, "escape"), 0u);
  EXPECT_EQ(count_children_named(helper, "a"), 0u);

  const auto control = call_create_file(helper, "plain.bin");
  EXPECT_TRUE(control.status_code().is_good()) << "control: a single component is created";
  EXPECT_TRUE(std::filesystem::is_regular_file(mDirectoryPath / "plain.bin"));
}

// Part 20 section 4.3.4: a file with the name already exists -> Bad_BrowseNameDuplicated. Creating
// means creating: an existing file is never adopted, and a symbolic link planted under the directory
// (dangling or not) is never followed to create its target.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryHelperTest, CreateFileRefusesAnExistingFileAndNeverFollowsAPlantedLink)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  {
    std::ofstream present{mDirectoryPath / "present.bin", std::ios::binary};
    present << "kept";
  }
  const auto duplicate = call_create_file(helper, "present.bin");
  EXPECT_EQ(duplicate.status_code().as_status(), Status::BadBrowseNameDuplicated);
  const auto detail = duplicate.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "FileNameDuplicated");
  EXPECT_TRUE(duplicate.output_arguments().empty());
  EXPECT_EQ(std::filesystem::file_size(mDirectoryPath / "present.bin"), 4u)
    << "the existing file is untouched";
  EXPECT_EQ(count_children_named(helper, "present.bin"), 0u) << "no node adopts the existing file";

#ifndef _WIN32
  const auto target = mDirectoryPath.parent_path() / "planted-target.bin";
  std::error_code ignored;
  std::filesystem::remove(target, ignored);
  std::filesystem::create_symlink(target, mDirectoryPath / "link.bin");
  const auto viaLink = call_create_file(helper, "link.bin");
  EXPECT_EQ(viaLink.status_code().as_status(), Status::BadBrowseNameDuplicated)
    << "a planted link occupies the name; it is refused, not followed";
  EXPECT_FALSE(std::filesystem::exists(target)) << "the link's target outside the directory was not created";
  EXPECT_EQ(count_children_named(helper, "link.bin"), 0u);
#endif
}

// The file is created before its node: when the node cannot be registered, the file is removed
// again, so the name is free for a retry instead of being refused as a duplicate for ever.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryHelperTest, AFileWhoseNodeCannotBeRegisteredIsRemovedAgain)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  const auto method = helper.directory().try_create_file_method_sync().value();

  // Take the directory Object away from under its handler: the exclusive create succeeds, then
  // FileHelper::create_async fails to instantiate the FileType node under a parent that is gone.
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(helper.node_id(), false).is_good());

  CallMethodRequest request;
  request.object_id() = helper.node_id();
  request.method_id() = method.get_node_id();
  request.input_arguments().resize(2);
  request.input_arguments()[0] = Variant{String{"stranded.bin"}};
  request.input_arguments()[1] = Variant{false};
  // The handler is run on the in-memory Method Node itself: through the address space the call is answered
  // Bad_NodeIdUnknown for the deleted Object before any handler runs (NR-15).
  auto* methodNode = dynamic_cast<default_ns::MethodNode*>(&*method);
  ASSERT_NE(methodNode, nullptr);
  std::promise<CallResult> called;
  methodNode->call(request, nullptr, [&called](CallResult result) { called.set_value(std::move(result)); });
  const auto stranded = called.get_future().get().value();
  // The instantiation's parent lookup is what fails (the exact status proves the handler ran and
  // the node creation, not the call or the name check, refused it).
  EXPECT_EQ(stranded.status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_FALSE(std::filesystem::exists(mDirectoryPath / "stranded.bin"))
    << "a file no node registers is removed again";
}

// The node exists but its Method handlers cannot be installed: FileHelper removes the node again and
// reports the install failure, so the directory sees "no node" and frees the name for a retry.
// @relation(AC-SVR-FILE-029-CHILD-NAMES-ARE-SINGLE-PATH-COMPONENTS, scope=function)
TEST_F(FileDirectoryHelperTest, ANodeWhoseHandlersCannotBeInstalledIsRolledBack)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const auto failed = [&]
  {
    const ua::detail::file_helper_tests::ScopedHandlerInstallFault fault{StatusCode{Status::BadInternalError,
      ErrorDetail::build("InjectedHandlerInstallFault", "Injected by the test", "FileHelperTest")}};
    return call_create_file(helper, "rolled.bin");
  }();
  EXPECT_EQ(failed.status_code().as_status(), Status::BadInternalError) << "the install failure is reported";
  const auto detail = failed.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "InjectedHandlerInstallFault") << "the ORIGINAL failure, not the rollback's result";
  EXPECT_TRUE(failed.output_arguments().empty());
  EXPECT_EQ(count_children_named(helper, "rolled.bin"), 0u) << "the node was rolled back";
  EXPECT_FALSE(std::filesystem::exists(mDirectoryPath / "rolled.bin")) << "and the file removed";

  const auto retried = call_create_file(helper, "rolled.bin");
  EXPECT_TRUE(retried.status_code().is_good()) << "the name is free again for a retry";
  EXPECT_EQ(count_children_named(helper, "rolled.bin"), 1u);
  EXPECT_TRUE(std::filesystem::is_regular_file(mDirectoryPath / "rolled.bin"));
}

// @relation(AC-SVR-FILE-018-DUPLICATE-DIRECTORY-REFUSED, scope=function)
TEST_F(FileDirectoryHelperTest, DuplicateDirectoryNameIsRejectedBeforeNodeCreation)
{
  auto helperResult = create_directory_helper();
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  const auto first = call_create_directory(helper, "twice");
  ASSERT_TRUE(first.status_code().is_good());
  ASSERT_EQ(first.output_arguments().size(), 1u);
  const auto firstNodeId = first.output_arguments()[0].as<NodeId>();
  ASSERT_FALSE(firstNodeId.is_null());
  ASSERT_TRUE(std::filesystem::is_directory(mDirectoryPath / "twice"));

  const auto second = call_create_directory(helper, "twice");
  EXPECT_EQ(second.status_code().as_status(), Status::BadBrowseNameDuplicated);
  const auto detail = second.status_code().shared_detail();
  EXPECT_NE(detail, nullptr);
  if (detail)
  {
    EXPECT_EQ(detail->code, "FileDirectoryNameDuplicated");
  }
  EXPECT_TRUE(second.output_arguments().empty());

  EXPECT_TRUE(mAddressSpace->try_find_node_sync(firstNodeId).is_good());
  EXPECT_EQ(count_children_named(helper, "twice"), 1u);
}

// Stage 3b #3: a throwing application CreateCompleteCallback must be contained inside the create flow
// (invoke_user_callback), never escape the Asio-posted handler-install continuation -> std::terminate.
// The completion captures shared state by value so it stays valid past the test body while the worker
// finishes; pre-fix the throw aborts the whole process.
TEST_F(FileHelperTest, ThrowingCreateCallbackIsContainedNotTerminate)
{
  const InstantiationOptions options{};
  auto fired = std::make_shared<std::atomic<int>>(0);
  auto delivered = std::make_shared<std::promise<void>>();
  auto deliveredFuture = delivered->get_future();

  FileHelper::create_async(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "ThrowCbFile"},
    mTempPath,
    options,
    /*writable=*/true,
    [fired, delivered](FileHelperResult) mutable
    {
      fired->fetch_add(1);
      delivered->set_value();  // signal delivery BEFORE throwing so the test can proceed
      throw std::runtime_error("application create callback failed");  // must be swallowed, not terminate
    });

  ASSERT_EQ(deliveredFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready)
    << "the create completion must be delivered";
  EXPECT_EQ(fired->load(), 1) << "the completion must be delivered exactly once";
  // Reaching here proves the throw was contained: had it escaped the Asio worker the process would have
  // std::terminate'd before this line.
}

// DEF-7: a transfer file's name carries a fresh GUID, so a local user cannot pre-plant a file or
// symlink at the path the next transfer will use.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(TemporaryFileTransferHelperTest, GeneratedFileNameIsNotPredictable)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  auto helper = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "UnpredictableTransfer"},
    options,
    config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 601u};
  ASSERT_TRUE(
    call_as_session(helper.node_id(), generate.value(), {Variant{}}, session).status_code().is_good());
  ASSERT_TRUE(
    call_as_session(helper.node_id(), generate.value(), {Variant{}}, session).status_code().is_good());
  std::vector<std::string> names;
  for (const auto& entry : std::filesystem::directory_iterator(mTransferDirectory))
    names.push_back(entry.path().filename().string());
  ASSERT_EQ(names.size(), 2u);
  EXPECT_NE(names[0], names[1]);
  for (const auto& name : names)
  {
    EXPECT_NE(name, "xfer_r_1.bin") << "the old counter name";
    EXPECT_NE(name, "xfer_r_2.bin");
    EXPECT_GT(name.size(), std::string{"xfer_r_.bin"}.size() + 30) << "a GUID-length name: " << name;
  }
}

// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(TemporaryFileTransferHelperTest, SessionTransferQuotaIsEnforced)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  config.maxActiveTransfersPerSession = 2;
  auto helper = TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "QuotaTransfer"}, options, config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId greedy{1, 611u};
  const NodeId other{1, 612u};
  ASSERT_TRUE(
    call_as_session(helper.node_id(), generate.value(), {Variant{}}, greedy).status_code().is_good());
  ASSERT_TRUE(
    call_as_session(helper.node_id(), generate.value(), {Variant{}}, greedy).status_code().is_good());
  const auto third = call_as_session(helper.node_id(), generate.value(), {Variant{}}, greedy);
  EXPECT_EQ(third.status_code(), Status::BadTooManyOperations) << "the third transfer of one Session";
  EXPECT_TRUE(call_as_session(helper.node_id(), generate.value(), {Variant{}}, other).status_code().is_good())
    << "another Session's first transfer is unaffected";
  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, greedy);
  EXPECT_TRUE(
    call_as_session(helper.node_id(), generate.value(), {Variant{}}, greedy).status_code().is_good())
    << "closing the Session releases its quota";
}

// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(TemporaryFileTransferHelperTest, EmptyTempDirIsAConfigurationError)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;  // tempDir left empty: "the current directory" is not a choice
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  const auto refused = TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "NoDirTransfer"}, options, config);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), Status::BadConfigurationError);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "TemporaryFileTransferDirectoryUnset");
}

// DEF-7: an upload may not grow past the configured ceiling; the Write that would is refused whole.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(FileHelperTest, WriteBeyondConfiguredMaxFileSizeIsRefused)
{
  InstantiationOptions options{};
  const auto path = ua::test_utils::unique_temp_path("file_helper_size_limit", ".bin");
  auto helper = FileHelper::create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "Bounded"}, path, options, true, 8);
  const NodeId session{1, 621u};
  const auto opened = call_as_session(helper, "Open", {Variant{uint8_t{0x02 | 0x04}}}, session);
  ASSERT_TRUE(opened.status_code().is_good());
  const auto handle = opened.output_arguments()[0].as<uint32_t>();
  const ByteString five{std::vector<uint8_t>{1, 2, 3, 4, 5}};
  ASSERT_TRUE(
    call_as_session(helper, "Write", {Variant{handle}, Variant{five}}, session).status_code().is_good());
  const auto refused = call_as_session(helper, "Write", {Variant{handle}, Variant{five}}, session);
  EXPECT_EQ(refused.status_code(), Status::BadOutOfRange) << "5 + 5 exceeds the 8-byte ceiling";
  const ByteString three{std::vector<uint8_t>{6, 7, 8}};
  EXPECT_TRUE(
    call_as_session(helper, "Write", {Variant{handle}, Variant{three}}, session).status_code().is_good())
    << "a Write that fits is still accepted after a refused one";
  ASSERT_TRUE(call_as_session(helper, "Close", {Variant{handle}}, session).status_code().is_good());
  EXPECT_EQ(std::filesystem::file_size(path), 8u) << "the refused Write wrote nothing";
  std::filesystem::remove(path);
}

// DEF-7 / Part 20 4.4: a read transfer ends with the client's Close on the transient file, and that
// releases the Session's quota slot (and the transient node and temp file) - a spec-conformant client
// that downloads more than `quota` files in one Session is not locked out.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(TemporaryFileTransferHelperTest, ClosingATransientFileReleasesTheSessionsQuotaSlot)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  config.maxActiveTransfersPerSession = 1;
  auto helper = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "CloseReleasesTransfer"},
    options,
    config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 631u};
  for (int round = 0; round < 3; ++round)
  {
    const auto generated = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
    ASSERT_TRUE(generated.status_code().is_good())
      << "round " << round << ": the previous Close freed the slot";
    const NodeId fileNode = generated.output_arguments()[0].as<NodeId>();
    const auto fileHandle = generated.output_arguments()[1].as<uint32_t>();
    auto close = get_method_of(fileNode, "Close");
    ASSERT_TRUE(close.has_value());
    ASSERT_TRUE(call_as_session(fileNode, *close, {Variant{fileHandle}}, session).status_code().is_good());
    // The transfer is over: node and file are gone with the slot.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (
      std::chrono::steady_clock::now() < deadline && mAddressSpace->try_find_node_sync(fileNode).is_good())
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    EXPECT_FALSE(mAddressSpace->try_find_node_sync(fileNode).is_good()) << "the transient node is removed";
    EXPECT_TRUE(
      std::filesystem::directory_iterator(mTransferDirectory) == std::filesystem::directory_iterator{})
      << "the temp file is removed";
  }
}

// DEF-7: the quota holds under concurrency. N GenerateFileForRead calls started together (as one Call
// request with N entries starts them) get exactly `quota` successes; the slot is reserved when the
// call is admitted, not when its asynchronous creation completes.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
/// One pool thread, so a posted blocker holds back every creation until the test releases it and
/// the order of admissions and creations is fixed rather than a matter of scheduling.
class TemporaryFileTransferHelperSingleThreadTest : public TemporaryFileTransferHelperTest
{
protected:
  [[nodiscard]] std::size_t pool_threads() const override
  {
    return 1;
  }
};

TEST_F(TemporaryFileTransferHelperSingleThreadTest, ConcurrentGeneratesCannotExceedTheSessionQuota)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  config.maxActiveTransfersPerSession = 2;
  auto helper = TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "ConcurrentQuota"}, options, config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 641u};
  constexpr int calls = 6;
  std::vector<std::promise<CallResult>> promises(calls);
  std::vector<std::future<CallResult>> futures;
  for (auto& promise : promises)
    futures.push_back(promise.get_future());
  // The one pool thread is held here until every call has been issued: whether the method dispatch
  // runs inline or is posted, all six admissions are decided before any creation can complete, so
  // only a slot reserved at admission can keep the count right.
  std::promise<void> releasePool;
  const auto poolReleased = releasePool.get_future().share();
  boost::asio::post(*mThreadPool, [poolReleased] { poolReleased.wait(); });
  for (int i = 0; i < calls; ++i)
  {
    CallMethodRequest request;
    request.object_id() = helper.node_id();
    request.method_id() = generate.value().get_node_id();
    request.input_arguments() = std::vector<Variant>{Variant{}};
    auto context = std::make_shared<MethodCallContext>();
    context->sessionId = session;
    generate.value().call_async(request,
      std::move(context),
      [&promise = promises[static_cast<size_t>(i)]](CallResult result)
      { promise.set_value(std::move(result)); });
  }
  releasePool.set_value();
  int good = 0;
  int refused = 0;
  for (auto& future : futures)
  {
    ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
    auto result = future.get();
    ASSERT_TRUE(result.is_good());
    if (result.value().status_code().is_good())
      ++good;
    else if (result.value().status_code() == Status::BadTooManyOperations)
      ++refused;
  }
  EXPECT_EQ(good, 2) << "exactly the quota succeeds";
  EXPECT_EQ(refused, calls - 2) << "the rest are refused, not admitted while creations are in flight";
}

// DEF-7: the upload ceiling reaches the write transfer through the production wiring (the transient
// file's own Write handler), not only through FileHelper's parameter.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
TEST_F(TemporaryFileTransferHelperTest, AnUploadCannotGrowPastTheConfiguredMaxFileSize)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  config.maxFileSize = 8;
  auto helper = TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "BoundedUpload"}, options, config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_write_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 651u};
  const auto generated = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
  ASSERT_TRUE(generated.status_code().is_good());
  const NodeId fileNode = generated.output_arguments()[0].as<NodeId>();
  const auto fileHandle = generated.output_arguments()[1].as<uint32_t>();
  auto write = get_method_of(fileNode, "Write");
  ASSERT_TRUE(write.has_value());
  const ByteString five{std::vector<uint8_t>{1, 2, 3, 4, 5}};
  EXPECT_TRUE(
    call_as_session(fileNode, *write, {Variant{fileHandle}, Variant{five}}, session).status_code().is_good());
  EXPECT_EQ(call_as_session(fileNode, *write, {Variant{fileHandle}, Variant{five}}, session).status_code(),
    Status::BadOutOfRange)
    << "5 + 5 exceeds the configured 8-byte upload ceiling";
}

// DEF-7: a directory the operator supplies keeps its permissions; only a directory the helper creates
// is made owner-only.
// @verifies AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE
#ifndef _WIN32
TEST_F(TemporaryFileTransferHelperTest, APreexistingTempDirKeepsItsPermissionsAndACreatedOneIsOwnerOnly)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  std::filesystem::permissions(
    mTransferDirectory, std::filesystem::perms::all, std::filesystem::perm_options::replace);
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;  // pre-existing, 0777
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  ASSERT_TRUE(TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "SharedDirTransfer"}, options, config)
                .is_good());

  struct stat shared
  {};

  ASSERT_EQ(::stat(mTransferDirectory.c_str(), &shared), 0);
  EXPECT_EQ(shared.st_mode & 0777, 0777u) << "the operator's directory is left as it was";

  const auto created = mTransferDirectory / "created-by-helper";
  TemporaryFileTransferConfig createdConfig;
  createdConfig.tempDir = created;
  createdConfig.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  const auto previousUmask = ::umask(0);
  const auto result = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "CreatedDirTransfer"},
    options,
    createdConfig);
  ::umask(previousUmask);
  ASSERT_TRUE(result.is_good());

  struct stat own
  {};

  ASSERT_EQ(::stat(created.c_str(), &own), 0);
  EXPECT_EQ(own.st_mode & 0777, 0700u) << "a directory the helper created is owner-only";
}
#endif  // !_WIN32

// GenerateFileForRead runs on a thread of the address space's executor and, on its first call, creates
// the non-browsable holder its transient files hang off - in the namespace the deployment named, which
// may answer by posting to that executor. On a one-thread executor a blocking create-and-name there
// waits for an answer that can only run there, with the helper's lock held, and the Method never
// returns; the asynchronous create must let it return.
// @relation(AC-SVR-FILE-022-TEMP-FILES-DELETED-ON-SESSION-END, scope=function)
TEST(TemporaryFileTransferHelperNonBlocking, GenerateCompletesWhenTheNamespaceAnswersByPosting)
{
  ua::test::OneThreadExecutor executor;
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto addressSpace = AddressSpace::create("uri:test", executor.executor());
  StructureFactory structureFactory;
  load_and_import_nodeset2(limits, addressSpace, structureFactory);
  auto postingNamespace =
    ua::test::PostingWritesNamespace::create("urn:test:posting-writes", executor.executor());
  auto namespaceIndex = addressSpace.try_add_namespace_sync(postingNamespace);
  ASSERT_TRUE(namespaceIndex.is_good());

  const auto transferDirectory = ua::test_utils::unique_temp_path("temporary_transfer_posting", "");
  std::filesystem::create_directories(transferDirectory);
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = transferDirectory;
  config.transientFileParent = NodeId{namespaceIndex.value(), "TransientFiles"};
  auto helperResult = TemporaryFileTransferHelper::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "PostingTransfer"},
    options,
    std::move(config));
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());

  CallMethodRequest request;
  request.object_id() = helper.node_id();
  request.method_id() = generate.value().get_node_id();
  request.input_arguments() = std::vector<Variant>{Variant{}};
  auto context = std::make_shared<MethodCallContext>();
  context->sessionId = NodeId{1, 601u};
  auto promise = std::make_shared<std::promise<CallResult>>();
  auto future = promise->get_future();
  // Called FROM the executor's thread, as a Call service would call it.
  boost::asio::post(executor.executor(),
    [method = generate.value(), request, context, promise]() mutable
    {
      method.call_async(
        request, context, [promise](CallResult result) { promise->set_value(std::move(result)); });
    });

  ASSERT_EQ(future.wait_for(10s), std::future_status::ready)
    << "GenerateFileForRead blocked the thread its namespace answers on";
  auto result = future.get();
  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().status_code().is_good());
  ASSERT_FALSE(result.value().output_arguments().empty());
  const NodeId transientId = result.value().output_arguments()[0].as<NodeId>();
  EXPECT_EQ(transientId.namespace_index(), namespaceIndex.value());
  EXPECT_TRUE(addressSpace.try_find_node_sync(transientId).is_good());
  // The holder was created in the posting namespace, named as before.
  const std::string holderName = "__TransientFiles_" + ua::to_string(helper.node_id());
  auto holder = addressSpace.try_find_node_sync(NodeId{namespaceIndex.value(), String{holderName}});
  ASSERT_TRUE(holder.is_good());
  EXPECT_EQ(holder.value().get_browse_name(), (QualifiedName{namespaceIndex.value(), holderName}));

  detail::AddressSpaceSessionEvents::notify_closed(addressSpace, context->sessionId);
  helper.release();
  std::error_code error;
  std::filesystem::remove_all(transferDirectory, error);
}

namespace
{

/// A default namespace that answers the creation of one Node, when it succeeds, Uncertain while holding the
/// Node: a namespace that made the Node but is not sure it is usable.
class UncertainCreationNamespace final : public default_ns::Namespace
{
public:
  UncertainCreationNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// Answers every later creation of @p nodeId that succeeds Uncertain, with the Node.
  void answer_creation_uncertain(const NodeId& nodeId)
  {
    const std::lock_guard lock{mMutex};
    mUncertain = nodeId;
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    std::vector<bool> qualified;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& node : nodes)
      {
        qualified.push_back(mUncertain.has_value() && node.nodeId == *mUncertain);
      }
    }
    default_ns::Namespace::create_nodes_async(request,
      nodes,
      [qualified = std::move(qualified), complete = std::move(complete)](
        BatchResult<NodeResult> created) mutable
      {
        for (std::size_t i = 0; i < created.items.size() && i < qualified.size(); ++i)
        {
          if (qualified[i] && created.items[i].is_good())
          {
            created.items[i] =
              NodeResult{std::move(created.items[i]).value(), StatusCode{Status::UncertainLastUsableValue}};
          }
        }
        complete(std::move(created));
      });
  }

private:
  std::mutex mMutex;
  std::optional<NodeId> mUncertain;
};

}  // namespace

// The helper creates the read transfer from the path onGenerateForRead names, so an Uncertain answer is
// refused with Bad_InternalError (AnswerUncertain) whose cause is the hook's code, and nothing is generated;
// a Bad answer is the Method's status.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TemporaryFileTransferHelperTest, AnUncertainGenerateForReadAnswerIsRefused)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  auto hookCalls = std::make_shared<std::atomic<int>>(0);
  config.onGenerateForRead = [hookCalls](const Variant&, shared_ptr<const MethodCallContext>)
  {
    // The first call is answered Uncertain without a path, the second Bad.
    return hookCalls->fetch_add(1) == 0
             ? Result<std::filesystem::path>{StatusCode{Status::UncertainLastUsableValue}}
             : Result<std::filesystem::path>{StatusCode{Status::BadNotFound}};
  };
  auto helper = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "UncertainHookTransfer"},
    options,
    config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 651u};

  const auto refused = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError) << to_string(refused.status_code());
  const auto refusalDetail = refused.status_code().shared_detail();
  ASSERT_NE(refusalDetail, nullptr) << "the refusal carries no ErrorDetail";
  EXPECT_EQ(refusalDetail->code, "AnswerUncertain");
  EXPECT_EQ(refusalDetail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_TRUE(refused.output_arguments().empty());
  EXPECT_TRUE(
    std::filesystem::directory_iterator(mTransferDirectory) == std::filesystem::directory_iterator{})
    << "a transfer was generated from an answer the hook was uncertain of";

  // Control: a Bad answer is the Method's own status.
  const auto failed = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
  EXPECT_EQ(failed.status_code().as_status(), Status::BadNotFound) << to_string(failed.status_code());
  helper.release();
}

// A transient holder the namespace created but answered Uncertain is refused and removed again, so the next
// GenerateFileFor* does not take it, through Bad_NodeIdExists, as the holder a racing call made.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TemporaryFileTransferHelperTest, ATransientHolderAnsweredUncertainIsRemovedAndNotReused)
{
  auto uncertain =
    std::make_shared<UncertainCreationNamespace>("urn:test:uncertain-creation", mThreadPool->get_executor());
  auto index = mAddressSpace->try_add_namespace_sync(uncertain);
  ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{index.value(), "TransientFiles"};
  auto helper = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "UncertainHolderTransfer"},
    options,
    config)
                  .value();
  const NodeId holderId{index.value(), String{"__TransientFiles_" + ua::to_string(helper.node_id())}};
  uncertain->answer_creation_uncertain(holderId);
  auto generate = helper.transfer().try_generate_file_for_read_method_sync();
  ASSERT_TRUE(generate.is_good());
  const NodeId session{1, 652u};

  for (int call = 1; call <= 2; ++call)
  {
    SCOPED_TRACE(call == 1 ? "the first GenerateFileForRead" : "the second GenerateFileForRead");
    const auto refused = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
    EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError)
      << to_string(refused.status_code());
    const auto refusalDetail = refused.status_code().shared_detail();
    ASSERT_NE(refusalDetail, nullptr) << "the refusal carries no ErrorDetail";
    EXPECT_EQ(refusalDetail->code, "LookupAnswerUncertain");
    EXPECT_EQ(refusalDetail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
    EXPECT_EQ(mAddressSpace->try_find_node_sync(holderId).status_code().as_status(), Status::BadNodeIdUnknown)
      << "the holder answered Uncertain is left behind";
  }
  detail::AddressSpaceSessionEvents::notify_closed(*mAddressSpace, session);
  helper.release();
}

// An onCommit answer that is not Bad keeps its code as CloseAndCommit's status, with the Method's output: an
// Uncertain commit reaches the caller Uncertain, not plain Good, and a Good subcode is passed on by the
// in-process call (only the Call service answers it plain Good, OPC 10000-4 5.11.2.4).
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-CALL-PASSES-AN-UNCERTAIN-ANSWER-WITH-ITS-OUTPUTS, scope=function)
TEST_F(TemporaryFileTransferHelperTest, CloseAndCommitPassesTheCommitHooksCodeWithItsOutput)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  auto commits = std::make_shared<std::atomic<int>>(0);
  config.onCommit = [commits](const std::filesystem::path&, shared_ptr<const MethodCallContext>)
  {
    // The first commit is answered Uncertain, the second with a Good subcode.
    return commits->fetch_add(1) == 0 ? VoidResult{StatusCode{Status::UncertainLastUsableValue}}
                                      : VoidResult{StatusCode{Status::GoodLocalOverride}};
  };
  auto helper = TemporaryFileTransferHelper::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1, "CommitCodeTransfer"}, options, config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_write_method_sync();
  ASSERT_TRUE(generate.is_good());
  auto closeAndCommit = helper.transfer().try_close_and_commit_method_sync();
  ASSERT_TRUE(closeAndCommit.is_good());
  const NodeId session{1, 653u};

  for (const Status expected : {Status::UncertainLastUsableValue, Status::GoodLocalOverride})
  {
    SCOPED_TRACE(to_string(StatusCode{expected}));
    const auto generated = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
    ASSERT_TRUE(generated.status_code().is_good()) << to_string(generated.status_code());
    ASSERT_EQ(generated.output_arguments().size(), 2u);
    const auto fileHandle = generated.output_arguments()[1].as<uint32_t>();

    const auto committed =
      call_as_session(helper.node_id(), closeAndCommit.value(), {Variant{fileHandle}}, session);
    EXPECT_EQ(committed.status_code().as_status(), expected) << to_string(committed.status_code());
    ASSERT_EQ(committed.output_arguments().size(), 1u) << "the Method's output is answered with the code";
    EXPECT_TRUE(committed.output_arguments()[0].as<NodeId>().is_null())
      << "a synchronous transfer has no CompletionStateMachine";
  }
  EXPECT_EQ(commits->load(), 2);
  helper.release();
}

// The onCommit hook is told to apply the written file, so it must see every byte the Session wrote. The
// payload is not a multiple of any stdio buffer size: while the transfer's write handle is still open, its
// last partial buffer has not reached the file, and a hook that reads the path sees a truncated file.
// @relation(AC-SVR-FILE-031-COMMIT-SEES-EVERY-WRITTEN-BYTE, scope=function)
TEST_F(TemporaryFileTransferHelperTest, CloseAndCommitHandsTheHookTheWholeWrittenFile)
{
  InstantiationOptions options{};
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  TemporaryFileTransferConfig config;
  config.tempDir = mTransferDirectory;
  config.transientFileParent = NodeId{ObjectId::ObjectsFolder};
  auto committedContent = std::make_shared<std::vector<uint8_t>>();
  config.onCommit = [committedContent](const std::filesystem::path& path, shared_ptr<const MethodCallContext>)
  {
    std::ifstream in{path, std::ios::binary};
    committedContent->assign(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    return VoidResult{};
  };
  auto helper = TemporaryFileTransferHelper::try_create_sync(*mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "CommitContentTransfer"},
    options,
    config)
                  .value();
  auto generate = helper.transfer().try_generate_file_for_write_method_sync();
  ASSERT_TRUE(generate.is_good());
  auto closeAndCommit = helper.transfer().try_close_and_commit_method_sync();
  ASSERT_TRUE(closeAndCommit.is_good());
  const NodeId session{1, 654u};

  const auto generated = call_as_session(helper.node_id(), generate.value(), {Variant{}}, session);
  ASSERT_TRUE(generated.status_code().is_good()) << to_string(generated.status_code());
  ASSERT_EQ(generated.output_arguments().size(), 2u);
  const auto fileNode = generated.output_arguments()[0].as<NodeId>();
  const auto fileHandle = generated.output_arguments()[1].as<uint32_t>();
  auto write = get_method_of(fileNode, "Write");
  ASSERT_TRUE(write.has_value());

  std::vector<uint8_t> payload(5003);
  for (size_t index = 0; index < payload.size(); ++index)
    payload[index] = static_cast<uint8_t>(index % 251);
  const auto written =
    call_as_session(fileNode, *write, {Variant{fileHandle}, Variant{ByteString{payload}}}, session);
  ASSERT_TRUE(written.status_code().is_good()) << to_string(written.status_code());

  const auto committed =
    call_as_session(helper.node_id(), closeAndCommit.value(), {Variant{fileHandle}}, session);
  EXPECT_TRUE(committed.status_code().is_good()) << to_string(committed.status_code());
  EXPECT_EQ(committedContent->size(), payload.size())
    << "the hook read a file missing the last buffered Write";
  EXPECT_EQ(*committedContent, payload);
  helper.release();
}

// @relation(AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE, scope=function)
TEST_F(TemporaryFileTransferHelperTest, ThrowingUaCommitHookCleansResourcesBeforeCompletionAndPreservesCause)
{
  const StatusCode cause{Status::BadResourceUnavailable,
    ErrorDetail::build("CommitStorageUnavailable", "The upload target cannot accept this file", "CommitHost")
      .context(ContextKeys::method, "apply-upload")};
  TemporaryFileTransferConfig config;
  config.onCommit = [cause](const std::filesystem::path&, shared_ptr<const MethodCallContext>) -> VoidResult
  {
    throw UaException{cause};
  };
  expect_commit_failure_cleanup(std::move(config), cause, true);
}

// @relation(AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE, scope=function)
TEST_F(
  TemporaryFileTransferHelperTest, ThrowingStandardCommitHookCleansResourcesBeforeCompletionAndPreservesCause)
{
  TemporaryFileTransferConfig config;
  config.onCommit = [](const std::filesystem::path&, shared_ptr<const MethodCallContext>) -> VoidResult
  {
    throw std::runtime_error{"commit storage failed"};
  };
  expect_commit_failure_cleanup(
    std::move(config), StatusCode{Status::BadInternalError}, true, "commit storage failed");
}

// @relation(AC-SVR-FILE-030-TRANSFER-FILES-ARE-UNPREDICTABLE-BOUNDED-AND-EXCLUSIVE, scope=function)
TEST_F(
  TemporaryFileTransferHelperTest, ReturnedBadCommitHookCleansResourcesBeforeCompletionAndPreservesDetail)
{
  const StatusCode refusal{Status::BadNotWritable,
    ErrorDetail::build("CommitStorageRefused", "The upload target refused the file", "CommitHost")
      .context(ContextKeys::method, "apply-upload")};
  TemporaryFileTransferConfig config;
  config.onCommit = [refusal](const std::filesystem::path&, shared_ptr<const MethodCallContext>)
  {
    return VoidResult{refusal};
  };
  expect_commit_failure_cleanup(std::move(config), refusal, false);
}
