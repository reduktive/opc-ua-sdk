// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_HANDLE_BUDGET_H
#define UA_FILE_HANDLE_BUDGET_H

#include "ua_address_space.h"
#include "ua_node_id.h"
#include "ua_result.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace ua::detail
{

/// The FileType handles open in one address space, counted per Session and in total against the limits
/// the server configures (`ServerConfig::ResourceLimits::openFileHandlesPerSession` and
/// `openFileHandles`).
///
/// Each open handle holds an operating-system file descriptor until it is closed or its Session ends.
/// Descriptors are a process-wide resource the server also needs for its sockets, so one Session must
/// not hold an unbounded number of them, and neither may all Sessions together. Every FileType helper
/// in the address space takes a slot here before it opens the file and keeps it in the open-handle
/// entry; the slot's destruction returns it, so every way a handle ends releases it.
///
/// Until the server sets the limits both are unbounded: an address space with no server has no Sessions.
class FileHandleBudget final : public std::enable_shared_from_this<FileHandleBudget>
{
public:
  /// Sets the most handles one Session, and all callers together, may hold open. Applies to later
  /// acquisitions; handles already open are kept.
  void set_limits(uint32_t perSession, uint32_t total) noexcept;

  /// A slot for one handle opened by @p sessionId, released when the returned token is destroyed.
  ///
  /// A null @p sessionId (an internal caller) counts toward the total only.
  ///
  /// @return The slot, or Bad_TooManyOperations (`FileHandleLimitReached`) when the Session or the
  ///         server already holds the most handles it may have open.
  Result<std::shared_ptr<const void>> acquire(const NodeId& sessionId);

private:
  class Slot;

  void release(const NodeId& sessionId) noexcept;

  std::mutex mMutex;
  std::unordered_map<NodeId, uint32_t> mPerSession;
  uint32_t mTotal{0};
  uint32_t mPerSessionLimit{std::numeric_limits<uint32_t>::max()};
  uint32_t mTotalLimit{std::numeric_limits<uint32_t>::max()};
};

/// Internal access to an address space's @ref FileHandleBudget. Not part of the supported API.
class AddressSpaceFileHandles
{
public:
  /// The budget the FileType helpers of @p addressSpace take their slots from.
  static std::shared_ptr<FileHandleBudget> budget(const AddressSpace& addressSpace);

  /// Sets the limits of @p addressSpace's budget; called by the server from its ResourceLimits.
  static void set_limits(const AddressSpace& addressSpace, uint32_t perSession, uint32_t total) noexcept;
};

}  // namespace ua::detail

#endif  // UA_FILE_HANDLE_BUDGET_H
