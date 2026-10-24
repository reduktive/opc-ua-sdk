// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_TRANSFER_CLIENT_TEST_ACCESS_H
#define UA_FILE_TRANSFER_CLIENT_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::FileTransferClient and a @ref ua::client::FileHandle
///        over a fake wire interface, for the FileTransferClient unit suite (see
///        the design specification).
///
/// A friend of both handles. It adds NO public constructor: it builds the facade / a per-handle state
/// directly and hands them to the private constructors, so both can be exercised against a `FakeWireOps` with
/// no real `ConnectionImpl`.

#include "ua_file_handle_state.h"
#include "ua_file_transfer_client.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <memory>
#include <utility>

namespace ua::client::detail
{

/// Friend constructor for @ref FileTransferClient / @ref FileHandle unit tests.
struct FileTransferClientTestAccess
{
  /// Builds a @ref FileTransferClient over @p wireOps delivering on @p executor.
  static FileTransferClient make_client(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::Logger logger = {}, std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration = {})
  {
    return FileTransferClient{
      std::move(wireOps), std::move(executor), std::move(logger), std::move(sessionGeneration)};
  }

  /// The default resolved INSTANCE method nodes injected by @ref make_handle: six DISTINCT non-null NodeIds
  /// so a per-op test can assert that the op Calls the correct instance node (never the abstract FileType
  /// id).
  static FileMethodNodes default_method_nodes()
  {
    FileMethodNodes methods;
    methods.open = ua::NodeId{std::uint32_t{7001}};
    methods.read = ua::NodeId{std::uint32_t{7002}};
    methods.write = ua::NodeId{std::uint32_t{7003}};
    methods.close = ua::NodeId{std::uint32_t{7004}};
    methods.getPosition = ua::NodeId{std::uint32_t{7005}};
    methods.setPosition = ua::NodeId{std::uint32_t{7006}};
    return methods;
  }

  /// Builds a @ref FileHandle directly over a scripted per-handle state, so the read / write / position /
  /// close paths can be exercised without going through an Open. @p methods carries the resolved INSTANCE
  /// method nodes the ops Call (defaults to @ref default_method_nodes  -  six distinct non-null ids); a test
  /// can inject a null-per-method set to exercise the missing-method local-fail path.
  static FileHandle make_handle(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::NodeId fileNode, std::uint32_t fileHandle, FileOpenMode mode,
    std::uint32_t effectiveMaxByteStringLength = 0x10000, ua::Logger logger = {},
    FileMethodNodes methods = default_method_nodes(),
    std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration =
      std::make_shared<const std::atomic<std::uint64_t>>(0))
  {
    auto state = std::make_shared<FileHandleState>();
    state->wireOps = std::move(wireOps);
    state->executor = std::move(executor);
    state->logger = std::move(logger);
    state->sessionGeneration = std::move(sessionGeneration);
    state->openedSessionGeneration =
      state->sessionGeneration ? state->sessionGeneration->load(std::memory_order_acquire) : 0;
    state->fileNode = std::move(fileNode);
    state->methods = std::move(methods);
    state->fileHandle = fileHandle;
    state->mode = mode;
    state->effectiveMaxByteStringLength = effectiveMaxByteStringLength;
    return FileHandle{std::move(state)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_FILE_TRANSFER_CLIENT_TEST_ACCESS_H
