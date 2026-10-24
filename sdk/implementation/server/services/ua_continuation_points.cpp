// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_continuation_points.h"

#include "ua_node_accessor_route.h"

#include <memory>
#include <utility>

namespace ua::server
{

namespace
{

/// A holder for @p token, or none for an empty token.
std::unique_ptr<ua::detail::ResumeToken> held(ua::detail::ResumeToken&& token)
{
  if (token.empty())
  {
    return nullptr;
  }
  return std::make_unique<ua::detail::ResumeToken>(std::move(token));
}

}  // namespace

BrowseContinuationPoint::BrowseContinuationPoint(
  ViewDescription viewDescription, Counter maxRefsPerNode, const BrowseDescription& browseDescription)
  : mViewDescription(std::move(viewDescription)), mMaxRefsPerNode(maxRefsPerNode),
    mBrowseDescription(browseDescription)
{
  mIdentifier.generate();
}

BrowseContinuationPoint::BrowseContinuationPoint(ViewDescription viewDescription, Counter maxRefsPerNode,
  const BrowseDescription& browseDescription, ua::detail::ResumeToken&& resumeToken,
  References bufferedReferences)
  : mViewDescription(std::move(viewDescription)), mMaxRefsPerNode(maxRefsPerNode),
    mBrowseDescription(browseDescription), mResumeToken(held(std::move(resumeToken))),
    mBufferedReferences(std::move(bufferedReferences))
{
  mIdentifier.generate();
}

BrowseContinuationPoint::BrowseContinuationPoint(ViewDescription viewDescription, Counter maxRefsPerNode,
  const BrowseDescription& browseDescription, shared_ptr<PausedOperation> paused)
  : mViewDescription(std::move(viewDescription)), mMaxRefsPerNode(maxRefsPerNode),
    mBrowseDescription(browseDescription), mPaused(std::move(paused))
{
  mIdentifier.generate();
}

BrowseContinuationPoint::~BrowseContinuationPoint()
{
  // The token's holder releases it through its issuer as it is destroyed.
  mResumeToken.reset();
  if (mPaused)
  {
    release_paused_operation(*mPaused);
  }
}

BrowseContinuationPoint::BrowseContinuationPoint(BrowseContinuationPoint&& other) noexcept
  : mIdentifier(other.mIdentifier), mViewDescription(std::move(other.mViewDescription)),
    mMaxRefsPerNode(other.mMaxRefsPerNode), mBrowseDescription(std::move(other.mBrowseDescription)),
    mResumeToken(std::move(other.mResumeToken)), mBufferedReferences(std::move(other.mBufferedReferences)),
    mPaused(std::exchange(other.mPaused, nullptr))
{}

BrowseContinuationPoint& BrowseContinuationPoint::operator=(BrowseContinuationPoint&& other) noexcept
{
  if (this != &other)
  {
    mIdentifier = other.mIdentifier;
    mViewDescription = std::move(other.mViewDescription);
    mMaxRefsPerNode = other.mMaxRefsPerNode;
    mBrowseDescription = std::move(other.mBrowseDescription);
    // The token held is released as its holder is replaced.
    mResumeToken = std::move(other.mResumeToken);
    mBufferedReferences = std::move(other.mBufferedReferences);
    if (mPaused)
    {
      release_paused_operation(*mPaused);
    }
    mPaused = std::exchange(other.mPaused, nullptr);
  }
  return *this;
}

bool BrowseContinuationPoint::has_resume_token() const noexcept
{
  return mResumeToken && !mResumeToken->empty();
}

ua::detail::ResumeToken BrowseContinuationPoint::take_resume_token() noexcept
{
  auto holder = std::move(mResumeToken);
  if (!holder)
  {
    return ua::detail::ResumeToken{};
  }
  return std::move(*holder);
}

}  // namespace ua::server
