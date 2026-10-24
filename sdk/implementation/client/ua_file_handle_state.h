// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_HANDLE_STATE_H
#define UA_FILE_HANDLE_STATE_H

/// @file
/// @brief The strand-free per-handle state a @ref ua::client::FileHandle owns (client design section 8.10),
/// shared
///        between the handle implementation and the `FileTransferClient::open_async` that constructs it.
/// @ingroup client

#include "ua_file_method_resolution.h"
#include "ua_file_transfer_client.h"
#include "ua_logger.h"
#include "ua_node_id.h"

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <cstdint>
#include <memory>

namespace ua::client::detail
{

class WireOps;

/// The per-handle state a @ref ua::client::FileHandle carries (client design section 8.10.2). Held by a
/// `std::shared_ptr` so every wire-op completion can weak-capture it and bail cleanly if the handle was
/// dropped mid-flight (section 9.8.3: liveness is not guaranteed across an async boundary  -  the completion
/// must not deref a freed handle). The ONLY back-reference is @ref wireOps, a `weak_ptr` to the wire interface:
/// there is no strong `shared_ptr` back to the owning `FileTransferClient` / `ConnectionImpl`, so the
/// self-owning cycle section 9.8.3 flagged cannot form.
struct FileHandleState
{
  std::weak_ptr<WireOps> wireOps;  ///< the upward wire interface (section 8.2A.13); locked per op, bail if gone
  boost::asio::any_io_executor executor;  ///< where results / boundary failures are delivered
  ua::Logger logger;  ///< logs the best-effort dtor/close outcome at the wire boundary (CL-FILE-001)
  std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration;
  std::uint64_t openedSessionGeneration = 0;

  ua::NodeId fileNode;  ///< the FileType Object the handle was opened on (Call objectId for every op)
  FileMethodNodes methods;  ///< resolved INSTANCE method nodes (Call methodId per op; null = server omits it)
  std::uint32_t fileHandle = 0;  ///< server-allocated handle from Open (Call input for Read/Write/... )
  FileOpenMode mode{};  ///< the mode the handle was opened with (drives the write-on-readonly guard)
  std::uint32_t effectiveMaxByteStringLength =
    0x10000;  ///< per-read cap (default; server resolution deferred)
  bool closed = false;  ///< close_async-once flag; idempotent (CL-FILE-001)
};

}  // namespace ua::client::detail

#endif  // UA_FILE_HANDLE_STATE_H
