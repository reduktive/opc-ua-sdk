// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_handle_budget.h"

#include "ua_address_space_impl.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <string>
#include <string_view>
#include <utility>

namespace ua::detail
{

namespace
{

StatusCode limit_reached(std::string_view scope, uint32_t held, uint32_t limit)
{
  return StatusCode{Status::BadTooManyOperations,
    ErrorDetail::build("FileHandleLimitReached",
      "The most FileType handles that may be open at once are already open",
      "FileHandleBudget")
      .context(ContextKeys::fieldName, std::string{scope})
      .context(ContextKeys::countActual, std::to_string(held))
      .context(ContextKeys::limit, std::to_string(limit))};
}

}  // namespace

// The token an open handle holds: returns its slot when the handle ends.
class FileHandleBudget::Slot final
{
public:
  Slot(std::shared_ptr<FileHandleBudget> budget, NodeId sessionId)
    : mBudget(std::move(budget)), mSessionId(std::move(sessionId))
  {}

  Slot(const Slot&) = delete;
  Slot& operator=(const Slot&) = delete;

  ~Slot()
  {
    mBudget->release(mSessionId);
  }

private:
  std::shared_ptr<FileHandleBudget> mBudget;
  NodeId mSessionId;
};

void FileHandleBudget::set_limits(uint32_t perSession, uint32_t total) noexcept
{
  const std::lock_guard lock{mMutex};
  mPerSessionLimit = perSession;
  mTotalLimit = total;
}

Result<std::shared_ptr<const void>> FileHandleBudget::acquire(const NodeId& sessionId)
{
  {
    const std::lock_guard lock{mMutex};
    if (mTotal >= mTotalLimit)
      return limit_reached("ResourceLimits.OpenFileHandles", mTotal, mTotalLimit);
    if (!sessionId.is_null())
    {
      const auto found = mPerSession.find(sessionId);
      const uint32_t held = found == mPerSession.end() ? 0 : found->second;
      if (held >= mPerSessionLimit)
        return limit_reached("ResourceLimits.OpenFileHandlesPerSession", held, mPerSessionLimit);
      ++mPerSession[sessionId];
    }
    ++mTotal;
  }
  try
  {
    return std::shared_ptr<const void>{std::make_shared<Slot>(shared_from_this(), sessionId)};
  }
  catch (...)
  {
    // The slot was counted above but no token exists to return it.
    release(sessionId);
    throw;
  }
}

void FileHandleBudget::release(const NodeId& sessionId) noexcept
{
  const std::lock_guard lock{mMutex};
  if (mTotal > 0)
    --mTotal;
  if (sessionId.is_null())
    return;
  const auto found = mPerSession.find(sessionId);
  if (found == mPerSession.end())
    return;
  if (--found->second == 0)
    mPerSession.erase(found);
}

std::shared_ptr<FileHandleBudget> AddressSpaceFileHandles::budget(const AddressSpace& addressSpace)
{
  return addressSpace.mImpl->file_handle_budget();
}

void AddressSpaceFileHandles::set_limits(
  const AddressSpace& addressSpace, uint32_t perSession, uint32_t total) noexcept
{
  addressSpace.mImpl->file_handle_budget()->set_limits(perSession, total);
}

}  // namespace ua::detail
