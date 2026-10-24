// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_model_access.h"
#include "ua_browse_drain_guard.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_variant.h"

#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_variable_id.h"

#include <memory>

namespace ua::dynamic_types
{

namespace
{

using DataValuesResult = ua::Result<std::vector<ua::DataValue>>;
using BrowseResultsResult = ua::Result<std::vector<ua::BrowseResult>>;

/// Flow for SessionModelAccess::read_async. Handles "ensure limits read" pre-step
/// and per-chunk batching. Self-keeps via mSelf until completion.
///
/// Lifetime contract: the SessionModelAccess reference must outlive the flow. The
/// flow is fire-and-forget; the user callback is the only externally observable
/// signal of completion.
class SessionReadFlow : public std::enable_shared_from_this<SessionReadFlow>
{
public:
  static void run(SessionModelAccess& access, ua::client::Session& session, uint32_t& maxNodesPerRead,
    uint32_t& maxNodesPerBrowse, bool& limitsRead, std::vector<ua::ReadValueId> nodesToRead,
    TypeModelAccess::ReadCallback complete)
  {
    auto flow = std::shared_ptr<SessionReadFlow>(new SessionReadFlow(access,
      session,
      maxNodesPerRead,
      maxNodesPerBrowse,
      limitsRead,
      std::move(nodesToRead),
      std::move(complete)));
    flow->mSelf = flow;
    flow->start();
  }

private:
  // The SessionModelAccess& is accepted and deliberately NOT stored: nothing in this flow reads
  // it. Holding it was dead state that clang reports as -Wunused-private-field, and an unnamed
  // parameter keeps the signature its callers use while saying the value is unused.
  SessionReadFlow(SessionModelAccess&, ua::client::Session& session, uint32_t& maxNodesPerRead,
    uint32_t& maxNodesPerBrowse, bool& limitsRead, std::vector<ua::ReadValueId> nodesToRead,
    TypeModelAccess::ReadCallback complete)
    : mSession(session), mMaxNodesPerRead(maxNodesPerRead), mMaxNodesPerBrowse(maxNodesPerBrowse),
      mLimitsRead(limitsRead), mNodesToRead(std::move(nodesToRead)), mUserCallback(std::move(complete))
  {
    mAccumulated.reserve(mNodesToRead.size());
  }

  void start()
  {
    if (!mLimitsRead)
    {
      issue_limits_read();
    }
    else
    {
      issue_next_chunk();
    }
  }

  void issue_limits_read()
  {
    ua::ReadRequest request;
    auto& nodes = request.nodes_to_read();
    nodes.resize(2);
    nodes[0].node_id() =
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead};
    nodes[0].attribute_id() = 13;  // AttributeId::Value
    nodes[1].node_id() =
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse};
    nodes[1].attribute_id() = 13;

    auto self = shared_from_this();
    mSession.attributes().read_async(std::move(request),
      [self = std::move(self)](ua::client::SessionAttributeServices::ReadResponseResult result) mutable
      { self->on_limits_read(std::move(result)); });
  }

  void on_limits_read(ua::client::SessionAttributeServices::ReadResponseResult result)
  {
    if (result.is_good())
    {
      auto& results = result.value().results();
      if (results.size() >= 2)
      {
        const auto& readStatus = results[0].status();
        if ((!readStatus.has_value() || readStatus->is_good()) && results[0].value().is_uint32())
        {
          mMaxNodesPerRead = results[0].value().as<uint32_t>();
        }
        const auto& browseStatus = results[1].status();
        if ((!browseStatus.has_value() || browseStatus->is_good()) && results[1].value().is_uint32())
        {
          mMaxNodesPerBrowse = results[1].value().as<uint32_t>();
        }
      }
    }
    // Limits read failure is non-fatal: fall back to a single chunk per the pre-flip
    // behaviour (chunkSize == totalCount). The error is intentionally swallowed because
    // operation-limit metadata is optional and the actual operation should still attempt.
    mLimitsRead = true;
    issue_next_chunk();
  }

  void issue_next_chunk()
  {
    if (mOffset >= mNodesToRead.size())
    {
      complete_success();
      return;
    }

    const size_t total = mNodesToRead.size();
    const size_t chunkSize = (mMaxNodesPerRead > 0) ? numeric_cast<size_t>(mMaxNodesPerRead) : total;
    const size_t end = std::min(mOffset + chunkSize, total);

    ua::ReadRequest request;
    auto& nodes = request.nodes_to_read();
    nodes.resize(end - mOffset);
    for (size_t i = mOffset; i < end; ++i)
    {
      nodes[i - mOffset] = std::move(mNodesToRead[i]);
    }
    mOffset = end;

    auto self = shared_from_this();
    mSession.attributes().read_async(std::move(request),
      [self = std::move(self)](ua::client::SessionAttributeServices::ReadResponseResult result) mutable
      { self->on_chunk_read(std::move(result)); });
  }

  void on_chunk_read(ua::client::SessionAttributeServices::ReadResponseResult result)
  {
    if (!result.is_good())
    {
      fail(result.status_code(), result.shared_detail());
      return;
    }

    // Facade flatten: the Session Read funnel returns the ReadResponse verbatim; a bad
    // ResponseHeader.serviceResult is a service-level failure surfaced to the user callback as bad,
    // preserving the exact service status + detail chain. Without this an empty results[] (a legal
    // service-fault shape) would be silently stitched into a Good/short accumulated vector.
    const ua::StatusCode serviceResult = result.value().response_header().service_result();
    if (serviceResult.is_bad())
    {
      fail(serviceResult,
        ua::ErrorDetail::build(
          "SessionReadServiceFault", "the batched Read returned a service-level fault", "SessionModelAccess")
          .cause(serviceResult));
      return;
    }

    mServiceStatus = ua::detail::combined_status(mServiceStatus, serviceResult);
    auto& results = result.value().results();
    for (auto& dv : results)
    {
      mAccumulated.push_back(std::move(dv));
    }
    issue_next_chunk();
  }

  void complete_success()
  {
    auto callback = std::move(mUserCallback);
    auto results = std::move(mAccumulated);
    mSelf.reset();
    // Two layers: the chunks' ServiceResults, combined, are the status of the outer Result, so a Good
    // subcode or an Uncertain code of any chunk is kept; each DataValue keeps its own status.
    callback(ua::detail::held(std::move(results), mServiceStatus));
  }

  void fail(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
  {
    auto callback = std::move(mUserCallback);
    mSelf.reset();
    callback(DataValuesResult{status, std::move(detail)});
  }

  ua::client::Session& mSession;
  uint32_t& mMaxNodesPerRead;
  uint32_t& mMaxNodesPerBrowse;
  bool& mLimitsRead;
  std::vector<ua::ReadValueId> mNodesToRead;
  TypeModelAccess::ReadCallback mUserCallback;
  std::vector<ua::DataValue> mAccumulated;
  /// The ServiceResults of the chunks answered so far, combined.
  ua::StatusCode mServiceStatus{ua::Status::Good};
  size_t mOffset{0};
  std::shared_ptr<SessionReadFlow> mSelf;
};

/// Flow for SessionModelAccess::browse_async. Mirrors SessionReadFlow but also
/// handles BrowseNext continuation-point loops on each chunk.
class SessionBrowseFlow : public std::enable_shared_from_this<SessionBrowseFlow>
{
public:
  static void run(SessionModelAccess& access, ua::client::Session& session, uint32_t& maxNodesPerRead,
    uint32_t& maxNodesPerBrowse, bool& limitsRead, std::vector<ua::BrowseDescription> nodesToBrowse,
    TypeModelAccess::BrowseCallback complete)
  {
    auto flow = std::shared_ptr<SessionBrowseFlow>(new SessionBrowseFlow(access,
      session,
      maxNodesPerRead,
      maxNodesPerBrowse,
      limitsRead,
      std::move(nodesToBrowse),
      std::move(complete)));
    flow->mSelf = flow;
    flow->start();
  }

private:
  // Same as SessionReadFlow: accepted, never read, so not stored.
  SessionBrowseFlow(SessionModelAccess&, ua::client::Session& session, uint32_t& maxNodesPerRead,
    uint32_t& maxNodesPerBrowse, bool& limitsRead, std::vector<ua::BrowseDescription> nodesToBrowse,
    TypeModelAccess::BrowseCallback complete)
    : mSession(session), mMaxNodesPerRead(maxNodesPerRead), mMaxNodesPerBrowse(maxNodesPerBrowse),
      mLimitsRead(limitsRead), mNodesToBrowse(std::move(nodesToBrowse)), mUserCallback(std::move(complete))
  {
    mAccumulated.reserve(mNodesToBrowse.size());
  }

  void start()
  {
    if (!mLimitsRead)
    {
      issue_limits_read();
    }
    else
    {
      issue_next_chunk();
    }
  }

  void issue_limits_read()
  {
    ua::ReadRequest request;
    auto& nodes = request.nodes_to_read();
    nodes.resize(2);
    nodes[0].node_id() =
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead};
    nodes[0].attribute_id() = 13;
    nodes[1].node_id() =
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse};
    nodes[1].attribute_id() = 13;

    auto self = shared_from_this();
    mSession.attributes().read_async(std::move(request),
      [self = std::move(self)](ua::client::SessionAttributeServices::ReadResponseResult result) mutable
      { self->on_limits_read(std::move(result)); });
  }

  void on_limits_read(ua::client::SessionAttributeServices::ReadResponseResult result)
  {
    if (result.is_good())
    {
      auto& results = result.value().results();
      if (results.size() >= 2)
      {
        const auto& readStatus = results[0].status();
        if ((!readStatus.has_value() || readStatus->is_good()) && results[0].value().is_uint32())
        {
          mMaxNodesPerRead = results[0].value().as<uint32_t>();
        }
        const auto& browseStatus = results[1].status();
        if ((!browseStatus.has_value() || browseStatus->is_good()) && results[1].value().is_uint32())
        {
          mMaxNodesPerBrowse = results[1].value().as<uint32_t>();
        }
      }
    }
    // See SessionReadFlow::on_limits_read - limits failure is non-fatal by design.
    mLimitsRead = true;
    issue_next_chunk();
  }

  void issue_next_chunk()
  {
    if (mOffset >= mNodesToBrowse.size())
    {
      complete_success();
      return;
    }

    const size_t total = mNodesToBrowse.size();
    const size_t chunkSize = (mMaxNodesPerBrowse > 0) ? numeric_cast<size_t>(mMaxNodesPerBrowse) : total;
    const size_t end = std::min(mOffset + chunkSize, total);

    ua::BrowseRequest request;
    auto& nodes = request.nodes_to_browse();
    nodes.resize(end - mOffset);
    for (size_t i = mOffset; i < end; ++i)
    {
      nodes[i - mOffset] = std::move(mNodesToBrowse[i]);
    }
    mOffset = end;

    auto self = shared_from_this();
    mSession.view().browse_async(std::move(request),
      [self = std::move(self)](ua::client::SessionViewServices::BrowseResponseResult result) mutable
      { self->on_chunk_browsed(std::move(result)); });
  }

  void on_chunk_browsed(ua::client::SessionViewServices::BrowseResponseResult result)
  {
    if (!result.is_good())
    {
      fail(result.status_code(), result.shared_detail());
      return;
    }

    // Facade flatten: the Session Browse funnel returns the BrowseResponse verbatim; a bad
    // ResponseHeader.serviceResult is a service-level failure surfaced to the user callback as bad,
    // preserving the exact service status + detail chain. Without this an empty results[] (a legal
    // service-fault shape) would be silently stitched into a Good/short accumulated vector.
    const ua::StatusCode serviceResult = result.value().response_header().service_result();
    if (serviceResult.is_bad())
    {
      fail(serviceResult,
        ua::ErrorDetail::build("SessionBrowseServiceFault",
          "the batched Browse returned a service-level fault",
          "SessionModelAccess")
          .cause(serviceResult));
      return;
    }

    mServiceStatus = ua::detail::combined_status(mServiceStatus, serviceResult);
    auto& results = result.value().results();
    mPendingIndices.clear();
    for (auto& br : results)
    {
      mAccumulated.push_back(std::move(br));
      auto resultIndex = mAccumulated.size() - 1;
      if (!mAccumulated[resultIndex].continuation_point().empty())
      {
        mPendingIndices.push_back(resultIndex);
      }
    }

    issue_browse_next_if_pending();
  }

  void issue_browse_next_if_pending()
  {
    if (mPendingIndices.empty())
    {
      issue_next_chunk();
      return;
    }

    ua::BrowseNextRequest nextRequest;
    nextRequest.release_continuation_points() = false;
    auto& continuationPoints = nextRequest.continuation_points();
    continuationPoints.resize(mPendingIndices.size());
    for (size_t i = 0; i < mPendingIndices.size(); ++i)
    {
      continuationPoints[i] = mAccumulated[mPendingIndices[i]].continuation_point();
    }

    auto self = shared_from_this();
    mSession.view().browse_next_async(std::move(nextRequest),
      [self = std::move(self)](ua::client::SessionViewServices::BrowseNextResponseResult result) mutable
      { self->on_browse_next(std::move(result)); });
  }

  void on_browse_next(ua::client::SessionViewServices::BrowseNextResponseResult result)
  {
    if (!result.is_good())
    {
      fail(result.status_code(), result.shared_detail());
      return;
    }

    // Facade flatten: the Session BrowseNext funnel returns the BrowseNextResponse verbatim; a bad
    // ResponseHeader.serviceResult is a service-level failure surfaced to the user callback as bad,
    // preserving the exact service status + detail chain. Without this an empty results[] would trip the
    // count-mismatch guard below and mask the real service fault as Bad_UnexpectedError.
    const ua::StatusCode serviceResult = result.value().response_header().service_result();
    if (serviceResult.is_bad())
    {
      fail(serviceResult,
        ua::ErrorDetail::build("SessionBrowseNextServiceFault",
          "the BrowseNext continuation returned a service-level fault",
          "SessionModelAccess")
          .cause(serviceResult));
      return;
    }
    mServiceStatus = ua::detail::combined_status(mServiceStatus, serviceResult);

    auto& nextResults = result.value().results();

    // A conformant server returns exactly one BrowseNext result per continuation point we sent
    // (Part 4 5.8.3). The loop below indexes mPendingIndices[i] (and then mAccumulated[...]) by the
    // SERVER-controlled result count, so a malicious or buggy server returning MORE results than we
    // requested would read past mPendingIndices - an out-of-bounds read on attacker-controlled data.
    // Treat any count mismatch as a protocol violation rather than indexing past the pending set.
    if (nextResults.size() != mPendingIndices.size())
    {
      fail(ua::StatusCode{ua::Status::BadUnexpectedError},
        ua::ErrorDetail::build("BrowseNextResultCountMismatch",
          "Server returned a BrowseNext result count that does not match the continuation points sent",
          "SessionModelAccess")
          .context(ua::ContextKeys::actual, std::to_string(nextResults.size()))
          .context(ua::ContextKeys::expected, std::to_string(mPendingIndices.size())));
      return;
    }

    std::vector<size_t> stillPending;
    for (size_t i = 0; i < nextResults.size(); ++i)
    {
      auto targetIndex = mPendingIndices[i];
      auto& target = mAccumulated[targetIndex];
      auto& source = nextResults[i];

      // CL-VIEW-005: every page is admitted before it is kept, against the guard of ITS node (one budget per
      // node's drain, not per browse). On a refusal the points the server still holds are released
      // (CL-VIEW-002): the new points already stored for the nodes before this one, the points this and
      // the later results carry - except a looping point, which is never re-sent.
      // One guard per node, seeded with the references its first Browse page already holds; nodes a later
      // chunk added get theirs appended (never rebuilt), so the cost stays one construction per node.
      while (mDrainGuards.size() < mAccumulated.size())
      {
        mDrainGuards.emplace_back("SessionModelAccess",
          ua::client::detail::BrowseDrainLimits{},
          mAccumulated[mDrainGuards.size()].references().payload().size());
      }
      if (auto admitted = mDrainGuards[targetIndex].admit_page(source); admitted.is_bad())
      {
        std::vector<ua::ContinuationPoint> toRelease;
        for (size_t k = 0; k < i; ++k)
        {
          if (!mAccumulated[mPendingIndices[k]].continuation_point().empty())
            toRelease.push_back(mAccumulated[mPendingIndices[k]].continuation_point());
        }
        for (size_t k = i; k < nextResults.size(); ++k)
        {
          // Every point the server still holds is released (CL-VIEW-002).
          if (!nextResults[k].continuation_point().empty())
            toRelease.push_back(nextResults[k].continuation_point());
        }
        mPendingIndices.clear();  // fail() must not release the points the server has already replaced
        release_points(std::move(toRelease));
        fail(admitted.status_code(), admitted.shared_detail());
        return;
      }

      // Each page answers for its node: a Bad page ends that node's walk with its code (the server
      // releases the continuation point of a page it fails), and a Good subcode or an Uncertain code of a
      // page is kept on the node's merged result.
      if (source.status_code().is_bad())
      {
        target.status_code() = source.status_code();
        target.continuation_point() = ua::ContinuationPoint{};
        continue;
      }
      target.status_code() = ua::detail::combined_status(target.status_code(), source.status_code());

      auto& targetRefs = target.references();
      auto& sourceRefs = source.references();
      auto existingSize = targetRefs.size();
      targetRefs.resize(existingSize + sourceRefs.size());
      for (size_t j = 0; j < sourceRefs.size(); ++j)
      {
        targetRefs[existingSize + j] = std::move(sourceRefs[j]);
      }

      target.continuation_point() = std::move(source.continuation_point());
      if (!target.continuation_point().empty())
      {
        stillPending.push_back(targetIndex);
      }
    }

    mPendingIndices = std::move(stillPending);
    issue_browse_next_if_pending();
  }

  void complete_success()
  {
    auto callback = std::move(mUserCallback);
    auto results = std::move(mAccumulated);
    mSelf.reset();
    // Two layers: the responses' ServiceResults, combined, are the status of the outer Result; each
    // BrowseResult keeps the status of its node's pages.
    callback(ua::detail::held(std::move(results), mServiceStatus));
  }

  /// Best-effort release of continuation points the server still holds (CL-VIEW-002); nobody waits for it.
  void release_points(std::vector<ua::ContinuationPoint> points)
  {
    if (points.empty())
      return;
    ua::BrowseNextRequest releaseRequest;
    releaseRequest.release_continuation_points() = true;
    releaseRequest.continuation_points() = std::move(points);
    mSession.view().browse_next_async(
      std::move(releaseRequest), [](ua::client::SessionViewServices::BrowseNextResponseResult) {});
  }

  void fail(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
  {
    // Part 4 5.8.3: the client SHALL release outstanding continuation points
    // when it abandons a browse. Issue BrowseNext(releaseContinuationPoints=true)
    // best-effort and ignore the response - we just want the server to free its
    // per-channel resources. Do not block the user callback on the release.
    if (!mPendingIndices.empty())
    {
      ua::BrowseNextRequest releaseRequest;
      releaseRequest.release_continuation_points() = true;
      auto& continuationPoints = releaseRequest.continuation_points();
      continuationPoints.resize(mPendingIndices.size());
      for (size_t i = 0; i < mPendingIndices.size(); ++i)
      {
        continuationPoints[i] = mAccumulated[mPendingIndices[i]].continuation_point();
      }
      mSession.view().browse_next_async(
        std::move(releaseRequest), [](ua::client::SessionViewServices::BrowseNextResponseResult) {});
      mPendingIndices.clear();
    }

    auto callback = std::move(mUserCallback);
    mSelf.reset();
    callback(BrowseResultsResult{status, std::move(detail)});
  }

  ua::client::Session& mSession;
  uint32_t& mMaxNodesPerRead;
  uint32_t& mMaxNodesPerBrowse;
  bool& mLimitsRead;
  std::vector<ua::BrowseDescription> mNodesToBrowse;
  TypeModelAccess::BrowseCallback mUserCallback;
  std::vector<ua::BrowseResult> mAccumulated;
  /// The ServiceResults of the Browse and BrowseNext responses answered so far, combined.
  ua::StatusCode mServiceStatus{ua::Status::Good};
  std::vector<size_t> mPendingIndices;
  std::vector<ua::client::detail::BrowseDrainGuard> mDrainGuards;  // one budget per node's drain
  size_t mOffset{0};
  std::shared_ptr<SessionBrowseFlow> mSelf;
};

}  // namespace

SessionModelAccess::SessionModelAccess(ua::client::Session& session) : mSession{&session}
{}

void SessionModelAccess::read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete)
{
  SessionReadFlow::run(*this,
    *mSession,
    mMaxNodesPerRead,
    mMaxNodesPerBrowse,
    mLimitsRead,
    std::move(nodesToRead),
    std::move(complete));
}

void SessionModelAccess::browse_async(
  std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete)
{
  SessionBrowseFlow::run(*this,
    *mSession,
    mMaxNodesPerRead,
    mMaxNodesPerBrowse,
    mLimitsRead,
    std::move(nodesToBrowse),
    std::move(complete));
}

}  // namespace ua::dynamic_types
