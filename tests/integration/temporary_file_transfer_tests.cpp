// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for ua::TemporaryFileTransferHelper - backs a TemporaryFileTransferType node and
/// implements GenerateFileForWrite / GenerateFileForRead / CloseAndCommit. Drives the methods over the
/// wire and checks the transient-node lifecycle + the host commit hook.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_encoding_limits.h"
#include "ua_guid.h"
#include "ua_instantiation_options.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_session_method_services.h"
#include "ua_temporary_file_transfer.h"
#include "ua_file_system_helpers.h"
#include "ua_variant.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <optional>
#include <system_error>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

class TempTransferTest : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_tempxfer_" + Guid::create_and_generate().as_string());
    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
    mCommitted = std::make_shared<std::atomic<bool>>(false);

    auto addressSpace = mServer.server().address_space();
    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

    TemporaryFileTransferConfig config;
    config.tempDir = mTempDir;
    config.transientFileParent = mTestFolderId;
    auto committed = mCommitted;
    config.onCommit = [committed](
                        const std::filesystem::path&, std::shared_ptr<const MethodCallContext>) -> VoidResult
    {
      committed->store(true);
      return {};
    };
    auto tempDir = mTempDir;
    config.onGenerateForRead = [tempDir](const Variant&,
                                 std::shared_ptr<const MethodCallContext>) -> Result<std::filesystem::path>
    {
      auto source = tempDir / "source.txt";
      std::ofstream out{source, std::ios::binary | std::ios::trunc};
      out << "hello";
      return source;
    };

    auto result = TemporaryFileTransferHelper::try_create_sync(
      addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "TempXfer"}, options, config);
    ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
    auto helper = std::move(result).value();

    mTransferNodeId = helper.node_id();
    mGenWriteId = helper.transfer().try_generate_file_for_write_method_sync().value().get_node_id();
    mGenReadId = helper.transfer().try_generate_file_for_read_method_sync().value().get_node_id();
    mCloseCommitId = helper.transfer().try_close_and_commit_method_sync().value().get_node_id();
    helper.release();
  }

  void TearDown() override
  {
    ComplianceWithNodes::TearDown();
    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  std::filesystem::path mTempDir;
  std::shared_ptr<std::atomic<bool>> mCommitted;
  NodeId mTransferNodeId;
  NodeId mGenWriteId;
  NodeId mGenReadId;
  NodeId mCloseCommitId;
};

TEST_F(TempTransferTest, GenerateForWriteThenCommitFiresHookAndCleansUp)
{
  auto gen =
    mSession->methods().call_sync(CallRequestBuilder().call(mTransferNodeId, mGenWriteId, {Variant{}}));
  ASSERT_EQ(gen.results().size(), 1u);
  ASSERT_THAT(gen.results()[0].status_code(), Good());
  ASSERT_GE(gen.results()[0].output_arguments().size(), 2u);
  const auto fileNode = gen.results()[0].output_arguments()[0].as<NodeId>();
  const auto handle = gen.results()[0].output_arguments()[1].as<uint32_t>();
  EXPECT_FALSE(fileNode.is_null());
  EXPECT_NE(handle, 0u);
  EXPECT_TRUE(mServer.server().address_space().try_find_node_sync(fileNode).is_good());

  auto commit = mSession->methods().call_sync(
    CallRequestBuilder().call(mTransferNodeId, mCloseCommitId, {Variant{handle}}));
  ASSERT_EQ(commit.results().size(), 1u);
  EXPECT_THAT(commit.results()[0].status_code(), Good());
  EXPECT_TRUE(mCommitted->load()) << "the commit hook must fire on CloseAndCommit";
  EXPECT_TRUE(mServer.server().address_space().try_find_node_sync(fileNode).is_bad())
    << "the transient node must be removed after commit";
}

TEST_F(TempTransferTest, GenerateForReadReturnsTransientNode)
{
  auto gen =
    mSession->methods().call_sync(CallRequestBuilder().call(mTransferNodeId, mGenReadId, {Variant{}}));
  ASSERT_EQ(gen.results().size(), 1u);
  ASSERT_THAT(gen.results()[0].status_code(), Good());
  ASSERT_GE(gen.results()[0].output_arguments().size(), 2u);
  EXPECT_FALSE(gen.results()[0].output_arguments()[0].as<NodeId>().is_null());
}

TEST_F(TempTransferTest, CloseAndCommitUnknownHandleRejected)
{
  auto commit = mSession->methods().call_sync(
    CallRequestBuilder().call(mTransferNodeId, mCloseCommitId, {Variant{uint32_t{9999}}}));
  ASSERT_EQ(commit.results().size(), 1u);
  EXPECT_THAT(commit.results()[0].status_code(), Bad(Status::BadInvalidArgument));
}

// SVR-FILE-007 / Part 20 section 4.4.1: the temporary FileType Object the generate Methods produce "is not
// browsable in the AddressSpace and can only be accessed with the NodeId and FileHandle returned by
// the Methods in the same Session."
//
// Not being browsable is not what protects it. Transfer handles come from a monotonic counter, so a
// second Session that generates one transfer of its own learns the ids either side of it without
// searching, and the FileNodeId is returned in the clear to whoever calls the Method. The Session is
// the only thing standing between a client and someone else's in-flight transfer - and CloseAndCommit
// is the destructive end of it: it fires the host's onCommit hook over the other Session's file and
// then deletes the transient node, so a stolen handle both publishes a file its owner had not
// finished writing and destroys the transfer.
//
// This is the sibling of FileHelperTest.AFileHandleIsUsableOnlyByTheSessionThatOpenedIt. The two
// helpers keyed their handle tables the same way and had the same hole; fixing one and not the other
// would have left the same defect reachable by a different Method.
//
// Falsifiable: a helper keyed on the handle alone lets session 2's commit succeed, fire the hook and
// remove the node.
// @verifies AC-SVR-FILE-007-HANDLE-SESSION-SCOPED
// @relation(AC-SVR-FILE-007-HANDLE-SESSION-SCOPED, scope=function)
TEST_F(TempTransferTest, ATransferHandleIsUsableOnlyByTheSessionThatGeneratedIt)
{
  auto gen =
    mSession->methods().call_sync(CallRequestBuilder().call(mTransferNodeId, mGenWriteId, {Variant{}}));
  ASSERT_EQ(gen.results().size(), 1u);
  ASSERT_THAT(gen.results()[0].status_code(), Good());
  ASSERT_GE(gen.results()[0].output_arguments().size(), 2u);
  const auto fileNode = gen.results()[0].output_arguments()[0].as<NodeId>();
  const auto handle = gen.results()[0].output_arguments()[1].as<uint32_t>();

  auto session2 = mChannel->create_session_sync({.sessionName = "TempXferIntruder"});
  session2.activate_sync();

  auto stolen = session2.methods().call_sync(
    CallRequestBuilder().call(mTransferNodeId, mCloseCommitId, {Variant{handle}}));
  ASSERT_EQ(stolen.results().size(), 1u);
  EXPECT_THAT(stolen.results()[0].status_code(), Bad(Status::BadInvalidArgument))
    << "a second Session committed a transfer it did not generate";
  EXPECT_FALSE(mCommitted->load())
    << "the host's onCommit hook ran over another Session's file, publishing a partial transfer";
  EXPECT_TRUE(mServer.server().address_space().try_find_node_sync(fileNode).is_good())
    << "a second Session's refused commit destroyed the transient node anyway";

  // The refusal must cost the owner nothing: its transfer is still live and still commits.
  auto commit = mSession->methods().call_sync(
    CallRequestBuilder().call(mTransferNodeId, mCloseCommitId, {Variant{handle}}));
  ASSERT_EQ(commit.results().size(), 1u);
  EXPECT_THAT(commit.results()[0].status_code(), Good()) << "the generating Session lost its own transfer";
  EXPECT_TRUE(mCommitted->load());

  session2.close_sync();
}

// Stage 3b #4 (callback-under-lock): the host-pluggable onGenerateForRead / onCommit hooks must be
// fired with NO internal lock held, so a hook that synchronously re-enters another transfer method on
// the SAME helper does not self-deadlock the non-recursive state->mutex. This fixture wires an
// onGenerateForRead hook that, on its first invocation, re-enters CloseAndCommit on the same helper via
// a MethodAccessor (inline, same thread). Before the fix the hook fired under state->mutex, so the
// re-entrant CloseAndCommit re-locked the non-recursive mutex on the same thread -> deadlock.
class TempTransferReentrancyTest : public ComplianceWithNodes
{
protected:
  struct Reentry
  {
    std::optional<MethodAccessor> closeAndCommit;  ///< accessor used by the hook to re-enter
    CallMethodRequest request;  ///< CloseAndCommit(unknown handle) request
    std::atomic<bool> fired{false};  ///< re-enter only on the first hook call
    std::atomic<bool> returned{false};  ///< set true iff the re-entrant call returned
    std::atomic<uint32_t> reentrantStatus{0};  ///< CallMethodResult status of the re-entrant call
  };

  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_tempxfer_re_" + Guid::create_and_generate().as_string());
    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);

    mReentry = std::make_shared<Reentry>();
    auto reentry = mReentry;

    auto addressSpace = mServer.server().address_space();
    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};

    TemporaryFileTransferConfig config;
    config.tempDir = mTempDir;
    config.transientFileParent = mTestFolderId;
    auto tempDir = mTempDir;
    config.onGenerateForRead = [tempDir, reentry](const Variant&,
                                 std::shared_ptr<const MethodCallContext>) -> Result<std::filesystem::path>
    {
      // Re-enter another transfer method on the SAME helper, synchronously, on this thread. This must
      // NOT deadlock: the hook is required to run with no internal lock held.
      if (reentry->closeAndCommit && !reentry->fired.exchange(true))
      {
        const CallResult r = reentry->closeAndCommit->try_call_sync(reentry->request);
        reentry->reentrantStatus.store(
          r.is_good() ? r.value().status_code().as_uint32() : r.status_code().as_uint32());
        reentry->returned.store(true);
      }
      auto source = tempDir / "source.txt";
      std::ofstream out{source, std::ios::binary | std::ios::trunc};
      out << "hello";
      return source;
    };

    auto result = TemporaryFileTransferHelper::try_create_sync(
      addressSpace, mTestFolderId, QualifiedName{mTestNamespaceIndex, "TempXferRe"}, options, config);
    ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
    // Keep the helper alive (do not release): the MethodAccessors below reference its method nodes.
    mHelper.emplace(std::move(result).value());

    mTransferNodeId = mHelper->node_id();
    mGenReadAccessor = mHelper->transfer().try_generate_file_for_read_method_sync().value();
    const NodeId genReadId = mGenReadAccessor->get_node_id();
    (void)genReadId;

    auto closeAndCommit = mHelper->transfer().try_close_and_commit_method_sync().value();
    mReentry->request.object_id() = mTransferNodeId;
    mReentry->request.method_id() = closeAndCommit.get_node_id();
    mReentry->request.input_arguments().resize(1);
    mReentry->request.input_arguments()[0] = Variant{uint32_t{9999}};  // unknown handle -> no nested commit
    mReentry->closeAndCommit = std::move(closeAndCommit);

    // Drive GenerateFileForRead directly through its accessor (no wire): the hook re-enters inline on
    // the calling thread, so any deadlock is confined to the worker thread the test spawns.
    CallMethodRequest readReq;
    readReq.object_id() = mTransferNodeId;
    readReq.method_id() = mGenReadAccessor->get_node_id();
    readReq.input_arguments().resize(1);
    readReq.input_arguments()[0] = Variant{};  // GenerateOptions: empty (mirrors the wire test)
    mReadRequest = std::move(readReq);
  }

  void TearDown() override
  {
    // Break the re-entrancy retain cycle BEFORE shutting the server down. The onGenerateForRead hook
    // is held by the GenerateFileForRead method node (via the shared helper State), and it captures
    // mReentry, whose closeAndCommit MethodAccessor holds the CloseAndCommit node strongly. That closes
    // a node -> handler -> State -> hook -> Reentry -> accessor -> node cycle that outlives server
    // shutdown and leaks the entire address space (ASan/LSan). Dropping the accessor the hook can reach
    // (the Reentry is shared with the hook, so this clears it there too) severs the cycle; the graph
    // then tears down normally.
    if (mReentry)
    {
      mReentry->closeAndCommit.reset();
    }
    mGenReadAccessor.reset();
    mReentry.reset();
    mHelper.reset();
    ComplianceWithNodes::TearDown();
    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  std::filesystem::path mTempDir;
  std::shared_ptr<Reentry> mReentry;
  std::optional<TemporaryFileTransferHelper> mHelper;
  std::optional<MethodAccessor> mGenReadAccessor;
  CallMethodRequest mReadRequest;
  NodeId mTransferNodeId;
};

TEST_F(TempTransferReentrancyTest, HostHookMayReenterAnotherMethodWithoutDeadlock)
{
  ASSERT_TRUE(mGenReadAccessor.has_value());

  // Run the (inline, re-entrant) call on a worker thread so a regression deadlocks only that thread and
  // is surfaced as a watchdog FAIL rather than wedging the whole test binary.
  auto accessor = *mGenReadAccessor;
  auto request = mReadRequest;
  auto fut = std::make_shared<std::future<CallResult>>(
    std::async(std::launch::async, [accessor, request]() { return accessor.try_call_sync(request); }));

  if (fut->wait_for(std::chrono::seconds(15)) == std::future_status::timeout)
  {
    // Intentionally leak the future so its destructor does not join the deadlocked worker thread (which
    // still holds state->mutex), which would otherwise hang the whole test binary. The FAIL records it.
    new std::shared_ptr<std::future<CallResult>>(fut);
    FAIL() << "GenerateFileForRead host hook deadlocked: the hook fired while the helper's mutex was "
              "held and the re-entrant CloseAndCommit re-locked the non-recursive mutex (Stage 3b #4).";
  }

  const CallResult readResult = fut->get();
  ASSERT_TRUE(readResult.is_good()) << "0x" << std::hex << readResult.status_code().as_uint32();
  EXPECT_THAT(readResult.value().status_code(), Good());

  EXPECT_TRUE(mReentry->returned.load()) << "the re-entrant host hook must have run and returned";
  EXPECT_EQ(mReentry->reentrantStatus.load(), StatusCode{Status::BadInvalidArgument}.as_uint32())
    << "the re-entrant CloseAndCommit(unknown handle) must complete with BadInvalidArgument, not deadlock";
}
