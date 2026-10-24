// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (FileHelper end-to-end).
//
// authorising this file. FH pins lock the multi-step
// FileHelper::create_async / attach_async install-handlers chain end-to-end
// against the production default_ns Namespace plus NodeSet2-imported NS0:
//
//   - FileHelper::create_async - successful instantiate + handler chain
//     (FH-A, FH-D, FH-G, FH-H), failure propagation (FH-B, FH-C, FH-E,
//     FH-F, FH-I), and per-method semantics through the registered handler.
//   - FileHelper::attach_async - wires handlers on an existing File node
//     (FH-J).
//
// Test working directory is `cmake-build-debug-gcc/tests/behaviour_pins/`,
// where NodeSet2.xml is copied at build time (see
// `tests/behaviour_pins/CMakeLists.txt`). FileType (i=11575) and its
// mandatory child declarations live in NS0 and are loaded once per fixture
// SetUp.
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. These pins drive `*_async` only at the FileHelper
// surface; calls down to MethodAccessor::call_sync are permitted because
// `*_sync` wrappers are async-canonical bridges (and we run on the main
// test thread, not on a pool thread).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_type_registration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_file.h"
#include "ua_file_system_helpers.h"
#include "ua_file_stream.h"
#include "ua_instance_utils.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

namespace ua::test::behaviour_pins
{
namespace
{

class FileHelperPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    const auto cfg = ApplicationConfig::load_default();
    mLimits = make_encoding_limits(cfg);

    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace =
      std::make_unique<AddressSpace>(AddressSpace::create(String{"urn:test:fh-pin"}, mPool->executor()));

    // Import NS0 so FileType (i=11575) and its mandatory children/methods
    // are present. NodeSet2.xml is copied next to the test binary by the
    // behaviour_pins CMakeLists.
    auto lookupFn = namespace_array_utils::get_index_lookup_function(*mAddressSpace);
    const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
    register_ua_data_types_with_factory(nsConfig, &mStructureFactory, &mStructureFactory);

    FileStream inputStream{"NodeSet2.xml"};
    inputStream.open_for_read();
    auto nodeSets = ua::xml::nodeset::Parser::parse(mLimits,
      inputStream,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      ua::xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = ua::xml::nodeset::ImportEngine::create(mLimits, *mAddressSpace, nodeSets, /*factory=*/{});
    importer->import_all_sync({}, {});

    // Unique temp file path per test to avoid cross-test interference and
    // allow the deterministic-content rule (runbook section 4.6).
    const auto& info = *::testing::UnitTest::GetInstance()->current_test_info();
    mTempPath = std::filesystem::temp_directory_path() /
                (std::string{"ua_fh_pin_"} + info.test_suite_name() + "_" + info.name() + ".bin");
    std::error_code removeEc;
    std::filesystem::remove(mTempPath, removeEc);
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
    std::error_code removeEc;
    std::filesystem::remove(mTempPath, removeEc);
  }

  // Drive FileHelper::create_async synchronously via promise on the test
  // thread. The address space + handlers all complete inline because
  // default_ns is sync; using a promise here is safe.
  FileHelperResult create_helper_blocking(
    const QualifiedName& browseName, bool writable, const NodeId& parent = NodeId{ObjectId::ObjectsFolder})
  {
    InstantiationOptions options{};
    std::promise<FileHelperResult> p;
    FileHelper::create_async(*mAddressSpace,
      parent,
      browseName,
      mTempPath,
      options,
      writable,
      [&p](FileHelperResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  FileHelperResult attach_helper_blocking(const NodeId& existingInstance, bool writable)
  {
    std::promise<FileHelperResult> p;
    FileHelper::attach_async(*mAddressSpace,
      existingInstance,
      mTempPath,
      writable,
      [&p](FileHelperResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  // Resolve the method `methodName` (browse name) under the file's instance
  // node via the public *_async surface. Used to build CallMethodRequests
  // that route through MethodCallSource::CallHandler installed by the
  // FileHelper.
  MethodAccessorResult resolve_method_blocking(const NodeId& instanceId, std::string_view methodName)
  {
    std::promise<MethodAccessorResult> p;
    instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
      instanceId,
      NodeId{ReferenceTypeId::HasComponent},
      QualifiedName{0u, methodName},
      [&p](MethodAccessorResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  CallMethodResult call_open(const FileHelper& helper, uint8_t mode)
  {
    auto methodResult = resolve_method_blocking(helper.node_id(), "Open");
    EXPECT_TRUE(methodResult.is_good())
      << "Open method must be reachable; status 0x" << std::hex << methodResult.status_code().as_uint32();
    auto method = std::move(methodResult).value();

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method.get_node_id();
    req.input_arguments().resize(1);
    req.input_arguments()[0] = Variant{mode};
    return method.call_sync(req);
  }

  CallMethodResult call_close(const FileHelper& helper, uint32_t handle)
  {
    auto methodResult = resolve_method_blocking(helper.node_id(), "Close");
    EXPECT_TRUE(methodResult.is_good())
      << "Close method must be reachable; status 0x" << std::hex << methodResult.status_code().as_uint32();
    auto method = std::move(methodResult).value();

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method.get_node_id();
    req.input_arguments().resize(1);
    req.input_arguments()[0] = Variant{handle};
    return method.call_sync(req);
  }

  CallMethodResult call_read(const FileHelper& helper, uint32_t handle, int32_t length)
  {
    auto methodResult = resolve_method_blocking(helper.node_id(), "Read");
    EXPECT_TRUE(methodResult.is_good())
      << "Read method must be reachable; status 0x" << std::hex << methodResult.status_code().as_uint32();
    auto method = std::move(methodResult).value();

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method.get_node_id();
    req.input_arguments().resize(2);
    req.input_arguments()[0] = Variant{handle};
    req.input_arguments()[1] = Variant{length};
    return method.call_sync(req);
  }

  CallMethodResult call_write(const FileHelper& helper, uint32_t handle, ByteString data)
  {
    auto methodResult = resolve_method_blocking(helper.node_id(), "Write");
    EXPECT_TRUE(methodResult.is_good())
      << "Write method must be reachable; status 0x" << std::hex << methodResult.status_code().as_uint32();
    auto method = std::move(methodResult).value();

    CallMethodRequest req;
    req.object_id() = helper.node_id();
    req.method_id() = method.get_node_id();
    req.input_arguments().resize(2);
    req.input_arguments()[0] = Variant{handle};
    req.input_arguments()[1] = Variant{std::move(data)};
    return method.call_sync(req);
  }

  EncodingLimits mLimits;
  StructureFactory mStructureFactory;
  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
  std::filesystem::path mTempPath;
};

}  // namespace

// ---------------------------------------------------------------------------
// FH-A - create_async instantiates a FileType node and installs handlers
//        such that calling Open through MethodCallSource::CallHandler
//        succeeds.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in CreateOrAttachFlow's chaining (e.g.
// the InstallHandlersFlow never being kicked off, or the open-handler step
// being skipped) would yield a FileHelperResult{Good} with a node whose
// Open method has no handler installed - calling Open would then return
// BadNotSupported instead of executing the file-stream open path.

TEST_F(FileHelperPin, FileHelperCreateInstantiatesFileTypeAndInstallsHandlers)
{
  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-A-File"}, /*writable=*/true);
  ASSERT_TRUE(helperResult.is_good())
    << "create_async returned bad; status 0x" << std::hex << helperResult.status_code().as_uint32();
  auto helper = std::move(helperResult).value();

  // (ii) reachability via find_node_async.
  std::promise<NodeAccessorResult> findP;
  mAddressSpace->find_node_async(
    helper.node_id(), [&findP](NodeAccessorResult r) { findP.set_value(std::move(r)); });
  auto findResult = findP.get_future().get();
  ASSERT_TRUE(findResult.is_good()) << "find_node could not see the helper's instance";

  // (iii) call Open via the CallHandler installed by set_open_handler_async.
  // Mode = Write|EraseExisting (0x06) succeeds against a fresh temp path.
  auto openResult = call_open(helper, /*mode=*/0x02 | 0x04);
  EXPECT_TRUE(openResult.status_code().is_good()) << "Open call failed via the installed handler; status 0x"
                                                  << std::hex << openResult.status_code().as_uint32();
  ASSERT_GE(openResult.output_arguments().size(), 1u);
  EXPECT_NE(openResult.output_arguments()[0].as<uint32_t>(), 0u) << "Open returned a zero file handle";

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-B - create_async surfaces File::create_async failure as a bad
//        FileHelperResult carrying status + ErrorDetail.
// ---------------------------------------------------------------------------
//
// Setup: drive create_async with a parent NodeId that does not exist.
// File::create_async resolves the parent via the AddressSpace; an unknown
// id yields BadNodeIdUnknown propagated through the CreateOrAttachFlow's
// on_file_initialised at ua_file_helper.cpp:684-695. The user callback
// must receive that bad status with a non-null detail.
//
// Bug this would catch: a regression that swallows File::create_async's
// failure (e.g. a fire-and-forget subscription that drops the result)
// would produce a FileHelperResult{Good} with an empty FileHelper -
// catastrophically misleading to the caller. Asserting bad status +
// non-null detail catches both lossy substitution and missed propagation.

TEST_F(FileHelperPin, FileHelperCreatePropagatesFileCreateFailure)
{
  const NodeId unknownParent{/*namespaceIndex=*/1u, std::string_view{"fh-b:no-such-parent"}};

  InstantiationOptions options{};
  std::promise<FileHelperResult> p;
  FileHelper::create_async(*mAddressSpace,
    unknownParent,
    QualifiedName{1u, "FH-B-File"},
    mTempPath,
    options,
    /*writable=*/true,
    [&p](FileHelperResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown)
    << "FileHelper::create_async with unknown parent must surface BadNodeIdUnknown; got 0x" << std::hex
    << result.status_code().as_uint32();
  ASSERT_NE(result.shared_detail(), nullptr)
    << "primary File::create_async failure must carry ErrorDetail (the error-propagation contract)";
}

// ---------------------------------------------------------------------------
// FH-C - attach_async aborts the install chain when the first
//        set_open_handler_async step fails; subsequent installs are not
//        attempted.
// ---------------------------------------------------------------------------
//
// Setup: create a real File via File::try_create_sync (no handlers
// installed yet - File::create only creates the FileType instance). Then
// delete the Open method node from the address space before driving
// FileHelper::attach_async. The resulting set_open_handler_async fails
// inside resolve_and_set_method_handler_async (find_child returns
// BadNodeIdUnknown), and InstallHandlersFlow::on_open_handler_set must
// forward bad -> fail and skip the close/read/... steps.
//
// Verifying "subsequent installs not attempted" without a fake namespace:
// after the failed attach, the Close method's CallHandler must still be
// unset (default_ns::MethodNode returns BadNotSupported when called with
// no handler - see ua_default_method_node.cpp:55-61). A regression that
// continued past the failed Open install would have set Close's handler
// (the production close handler returns BadInvalidArgument for unknown
// handles, distinguishable from BadNotSupported).

TEST_F(FileHelperPin, FileHelperCreateAbortsOnHandlerInstallFailure)
{
  // Step 1 - create a bare File instance (no handlers yet).
  InstantiationOptions options{};
  auto fileResult = File::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1u, "FH-C-File"}, options);
  ASSERT_TRUE(fileResult.is_good());
  auto file = std::move(fileResult).value();
  const auto fileId = file.node_id();
  file.release();  // keep the node alive for attach.

  // Step 2 - locate Open and Close methods, capture their NodeIds, then
  // delete Open so set_open_handler_async will fail at resolve time.
  auto openMethod = resolve_method_blocking(fileId, "Open");
  ASSERT_TRUE(openMethod.is_good());
  const auto openMethodId = openMethod.value().get_node_id();

  auto closeMethod = resolve_method_blocking(fileId, "Close");
  ASSERT_TRUE(closeMethod.is_good());
  const auto closeMethodId = closeMethod.value().get_node_id();

  std::promise<VoidResult> deleteP;
  mAddressSpace->delete_node_async(openMethodId,
    /*deleteForwardHierarchicalRefs=*/true,
    ReferenceHalves::Both,
    [&deleteP](VoidResult r) { deleteP.set_value(std::move(r)); });
  ASSERT_TRUE(deleteP.get_future().get().is_good());

  // Step 3 - drive FileHelper::attach_async; it must fail with status +
  // detail.
  std::promise<FileHelperResult> attachP;
  FileHelper::attach_async(*mAddressSpace,
    fileId,
    mTempPath,
    /*writable=*/true,
    [&attachP](FileHelperResult r) { attachP.set_value(std::move(r)); });
  auto attachResult = attachP.get_future().get();

  EXPECT_TRUE(attachResult.is_bad());
  ASSERT_NE(attachResult.shared_detail(), nullptr)
    << "handler-install failure must carry ErrorDetail (the error-propagation contract)";

  // Step 4 - verify subsequent installs were NOT attempted: Close still
  // has no handler (returns BadNotSupported), proving the chain aborted
  // at Open.
  std::promise<NodeAccessorResult> closeFindP;
  mAddressSpace->find_node_async(closeMethodId,

    [&closeFindP](NodeAccessorResult r) { closeFindP.set_value(std::move(r)); });
  auto closeFind = closeFindP.get_future().get();
  ASSERT_TRUE(closeFind.is_good()) << "Close method must still be in the AddressSpace";

  CallMethodRequest closeReq;
  closeReq.object_id() = fileId;
  closeReq.method_id() = closeMethodId;
  closeReq.input_arguments().resize(1);
  closeReq.input_arguments()[0] = Variant{uint32_t{1u}};
  auto closeMethodAcc = closeFind.value().as<MethodAccessor>();
  ASSERT_TRUE(closeMethodAcc);
  auto closeCall = closeMethodAcc->call_sync(closeReq);
  EXPECT_EQ(closeCall.status_code(), Status::BadNotSupported)
    << "Close handler must NOT have been installed after Open install failed; got 0x" << std::hex
    << closeCall.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// FH-D - Open with Mode=Read returns a non-zero file handle when the
//        underlying file exists and the helper was created read-only.
// ---------------------------------------------------------------------------

TEST_F(FileHelperPin, FileHelperOpenForReadReturnsHandle)
{
  // Pre-create the temp file with deterministic content so Read mode can
  // open it. The runbook's "deterministic-content pin" rule (section 4.6).
  const std::string content{"FH-D content"};
  {
    std::ofstream ofs(mTempPath, std::ios::binary);
    ofs << content;
  }

  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-D-File"}, /*writable=*/false);
  ASSERT_TRUE(helperResult.is_good())
    << "create_async returned bad; status 0x" << std::hex << helperResult.status_code().as_uint32();
  auto helper = std::move(helperResult).value();

  // Mode = Read (0x01).
  auto openResult = call_open(helper, /*mode=*/0x01);
  ASSERT_TRUE(openResult.status_code().is_good())
    << "Open(Read) failed; status 0x" << std::hex << openResult.status_code().as_uint32();
  ASSERT_GE(openResult.output_arguments().size(), 1u);
  EXPECT_NE(openResult.output_arguments()[0].as<uint32_t>(), 0u);

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-E - Open with Mode=0 (neither Read nor Write) is rejected with
//        BadInvalidArgument.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in make_open_handler at
// ua_file_helper.cpp:48-52 that drops the mode validation would let
// Open(0) fall through to FileStream::open_for_read which would then
// either silently succeed (an empty file does exist) or yield a different
// status, breaking the OPC UA spec.
//
// Note on ErrorDetail: the production handler now attaches a structured
// detail (file path + the offending open-mode bitmask) to the
// BadInvalidArgument, so shared_detail() is non-null and the filePath
// context key is present.

// Covers SVR-FILE-011 (coverage-audit retag).
TEST_F(FileHelperPin, FileHelperOpenWithoutReadOrWriteRejectsBadInvalidArgument)
{
  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-E-File"}, /*writable=*/true);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto openResult = call_open(helper, /*mode=*/0x00);
  EXPECT_TRUE(openResult.status_code().is_bad());
  EXPECT_EQ(openResult.status_code(), Status::BadInvalidArgument)
    << "Mode=0 must be rejected with BadInvalidArgument; got 0x" << std::hex
    << openResult.status_code().as_uint32();
  // Enriched: the rejection carries the file path context.
  const auto detail = openResult.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const NamedValue& entry) { return entry.key == ContextKeys::filePath.value(); }));

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-F - Open with a write-mode bit on a non-writable helper is rejected
//        with BadNotWritable.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in make_open_handler at
// ua_file_helper.cpp:53-57 that drops the writable check would allow a
// read-only File instance to be opened for write - corrupting the
// file-system state and the Writable property's contract.

TEST_F(FileHelperPin, FileHelperOpenForWriteOnNonWritableInstanceRejectsBadNotWritable)
{
  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-F-File"}, /*writable=*/false);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto openResult = call_open(helper, /*mode=*/0x02);  // Write
  EXPECT_TRUE(openResult.status_code().is_bad());
  EXPECT_EQ(openResult.status_code(), Status::BadNotWritable)
    << "Open(Write) on writable=false helper must be rejected with BadNotWritable; got 0x" << std::hex
    << openResult.status_code().as_uint32();
  // Enriched: the rejection carries the file path context.
  const auto detail = openResult.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const NamedValue& entry) { return entry.key == ContextKeys::filePath.value(); }));

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-G - Read returns the file's bytes through the installed handler.
// ---------------------------------------------------------------------------

TEST_F(FileHelperPin, FileHelperReadDeliversFileBytes)
{
  // Deterministic 5-byte content per section 4.6.
  const ByteString expected = ByteString{0x46u, 0x47u, 0x48u, 0x49u, 0x4Au};  // "FGHIJ"
  {
    std::ofstream ofs(mTempPath, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(expected.data()), static_cast<std::streamsize>(expected.size()));
  }

  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-G-File"}, /*writable=*/false);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto openResult = call_open(helper, /*mode=*/0x01);  // Read
  ASSERT_TRUE(openResult.status_code().is_good());
  ASSERT_GE(openResult.output_arguments().size(), 1u);
  const auto handle = openResult.output_arguments()[0].as<uint32_t>();
  ASSERT_NE(handle, 0u);

  auto readResult = call_read(helper, handle, static_cast<int32_t>(expected.size()));
  ASSERT_TRUE(readResult.status_code().is_good())
    << "Read failed; status 0x" << std::hex << readResult.status_code().as_uint32();
  ASSERT_GE(readResult.output_arguments().size(), 1u);
  const auto data = readResult.output_arguments()[0].as<ByteString>();
  EXPECT_EQ(data, expected);

  call_close(helper, handle);
  helper.release();
}

// ---------------------------------------------------------------------------
// FH-H - Write appends bytes to the file.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in make_write_handler at
// ua_file_helper.cpp:144-171 that drops the FileStream::write_all call
// would leave the file empty after Write - the Writable property would
// claim writability the implementation doesn't honour.

TEST_F(FileHelperPin, FileHelperWriteAppendsBytesToFile)
{
  const ByteString payload = ByteString{0xDEu, 0xADu, 0xBEu, 0xEFu};

  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-H-File"}, /*writable=*/true);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  // Open Write|EraseExisting so we start from an empty file.
  auto openResult = call_open(helper, /*mode=*/0x02 | 0x04);
  ASSERT_TRUE(openResult.status_code().is_good());
  const auto handle = openResult.output_arguments()[0].as<uint32_t>();

  auto writeResult = call_write(helper, handle, ByteString{payload});
  ASSERT_TRUE(writeResult.status_code().is_good())
    << "Write failed; status 0x" << std::hex << writeResult.status_code().as_uint32();

  auto closeResult = call_close(helper, handle);
  ASSERT_TRUE(closeResult.status_code().is_good());

  // Verify file content via the file system. This catches a regression
  // where Write succeeds at the SDK layer but never reaches disk.
  std::ifstream ifs(mTempPath, std::ios::binary);
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  ASSERT_EQ(bytes.size(), payload.size());
  for (size_t i = 0; i < payload.size(); ++i)
  {
    EXPECT_EQ(bytes[i], payload[i]) << "byte " << i << " mismatch";
  }

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-I - Close with an invalid handle returns BadInvalidArgument.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in make_close_handler at
// ua_file_helper.cpp:92-113 that drops the handle lookup would let an
// arbitrary uint32 close any other client's handle (or no-op silently).

TEST_F(FileHelperPin, FileHelperCloseInvalidHandleReturnsBadInvalidArgument)
{
  auto helperResult = create_helper_blocking(QualifiedName{1u, "FH-I-File"}, /*writable=*/true);
  ASSERT_TRUE(helperResult.is_good());
  auto helper = std::move(helperResult).value();

  auto closeResult = call_close(helper, /*handle=*/0xDEADBEEFu);
  EXPECT_TRUE(closeResult.status_code().is_bad());
  EXPECT_EQ(closeResult.status_code(), Status::BadInvalidArgument)
    << "Close(0xDEADBEEF) must be rejected with BadInvalidArgument; got 0x" << std::hex
    << closeResult.status_code().as_uint32();

  helper.release();
}

// ---------------------------------------------------------------------------
// FH-J - attach_async wires handlers on a pre-existing FileType node so
//        Open succeeds against the attached helper.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in CreateOrAttachFlow's attach
// branch (ua_file_helper.cpp:808-825) that skips the InstallHandlersFlow
// would yield a FileHelperResult{Good} whose Open call returns
// BadNotSupported - the attached helper would advertise itself as ready
// but be non-functional.

TEST_F(FileHelperPin, FileHelperAttachInstallsHandlersOnExistingInstance)
{
  // Create a bare File via File::try_create_sync so the FileType instance
  // exists but no method handlers are installed yet.
  InstantiationOptions options{};
  auto fileResult = File::try_create_sync(
    *mAddressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{1u, "FH-J-File"}, options);
  ASSERT_TRUE(fileResult.is_good());
  auto file = std::move(fileResult).value();
  const auto existingId = file.node_id();
  file.release();  // detach RAII so attach_async owns the lifecycle.

  auto helperResult = attach_helper_blocking(existingId, /*writable=*/true);
  ASSERT_TRUE(helperResult.is_good())
    << "attach_async returned bad; status 0x" << std::hex << helperResult.status_code().as_uint32();
  auto helper = std::move(helperResult).value();
  EXPECT_EQ(helper.node_id(), existingId);

  // Calling Open through the attached helper exercises the Open handler
  // installed by attach_async's InstallHandlersFlow.
  auto openResult = call_open(helper, /*mode=*/0x02 | 0x04);
  EXPECT_TRUE(openResult.status_code().is_good()) << "Open call against attached helper failed; status 0x"
                                                  << std::hex << openResult.status_code().as_uint32();
}

}  // namespace ua::test::behaviour_pins
