// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reference.h"
#include "ua_reference_type_model.h"

namespace ua
{

Reference::Reference(
  NodeId type, ExpandedNodeId target, bool isForward, std::optional<LocalizedText> targetDisplayName)
  : mType(std::move(type)), mTarget(std::move(target)), mTargetDisplayName(std::move(targetDisplayName)),
    mIsForward(isForward)
{}

bool Reference::operator==(const Reference& other) const
{
  return mIsForward == other.mIsForward && mType == other.mType && mTarget == other.mTarget;
}

bool Reference::identifies_same_reference_as(const Reference& other) const
{
  if (mIsForward != other.mIsForward || mTarget != other.mTarget)
  {
    return false;
  }
  return mType == other.mType || reference_identity_type(mType) == reference_identity_type(other.mType);
}

References::References(std::shared_ptr<const std::vector<Reference>> storage) : mStorage(std::move(storage))
{}

References::References(std::vector<Reference> owned)
  : mStorage(std::make_shared<const std::vector<Reference>>(std::move(owned)))
{}

References References::slice(uint32_t offset, uint32_t count) const
{
  References result;
  result.mStorage = mStorage;
  result.mOffset = mOffset + offset;
  result.mCount = count;
  return result;
}

std::span<const Reference> References::span() const
{
  if (!mStorage || mStorage->empty())
  {
    return {};
  }

  auto totalSize = numeric_cast<uint32_t>(mStorage->size());
  auto start = std::min(mOffset, totalSize);
  auto remaining = totalSize - start;
  auto count = (mCount == 0) ? remaining : std::min(mCount, remaining);

  return std::span<const Reference>{mStorage->data() + start, count};
}

}  // namespace ua
