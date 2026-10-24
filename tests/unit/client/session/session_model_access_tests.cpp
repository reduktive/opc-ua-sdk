// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::dynamic_types::SessionModelAccess (client-side TypeModelAccess over a Session).
//
// SessionModelAccess adapts the batched TypeModelAccess Read/Browse contract onto the live client service
// surface. On first use it reads the server's OperationLimits.MaxNodesPerRead / MaxNodesPerBrowse, caches
// them, and then splits oversized batches into as many service calls as those limits require. These tests
// drive the real chunking flow through a null-connection SecureChannel, capture the outgoing requests the
// client actually sends, and assert the batch is split at the server limit (CL-BASE-003).

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "test_utilities.h"

#include "ua_session_model_access.h"

#include "ua_browse_description.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_byte_string.h"
#include "ua_continuation_point.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <condition_variable>
#include <mutex>
#include <optional>
#include <vector>

using namespace std::chrono_literals;
using ua::client::test_capture::CaptureHarness;
using ua::client::test_capture::wait_until;

namespace
{

/// Thread-safe sink for a Read result delivered on a pool worker thread.
struct ReadOutcome
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  bool good{false};
  std::vector<ua::DataValue> values;
  ua::StatusCode status;  ///< the outer Result status (captured for the failure paths)
  std::shared_ptr<const ua::ErrorDetail> detail;  ///< the outer Result ErrorDetail (failure paths)

  void set(ua::Result<std::vector<ua::DataValue>> result)
  {
    // notify_one() INSIDE the lock, deliberately. Notifying after the unlock is the usual
    // optimisation and is wrong here: the waiter is the test body, and the moment wait() returns
    // the test may leave its scope and destroy this object - while the pool worker is still inside
    // notify_one(). Destroying a condition_variable under a concurrent notify is undefined, and it
    // is what ThreadSanitizer reported against ~ReadOutcome in pipeline 2853776712. Holding the
    // mutex across the notify means the waiter cannot return until this thread has finished with
    // the variable.
    std::lock_guard<std::mutex> lk(mx);
    fired = true;
    good = result.is_good();
    status = result.status_code();
    detail = result.shared_detail();
    if (good)
    {
      values = std::move(result).value();
    }
    cv.notify_one();
  }

  bool wait(std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

/// Thread-safe sink for a Browse result delivered on a pool worker thread.
struct BrowseOutcome
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  bool good{false};
  std::vector<ua::BrowseResult> values;
  ua::StatusCode status;  ///< the outer Result status (captured for the failure paths)
  std::shared_ptr<const ua::ErrorDetail> detail;  ///< the outer Result ErrorDetail (failure paths)

  void set(ua::Result<std::vector<ua::BrowseResult>> result)
  {
    // Same reasoning as ReadOutcome::set above: the notify is under the lock because the waiter is
    // the test body and may destroy this object the instant wait() returns.
    std::lock_guard<std::mutex> lk(mx);
    fired = true;
    good = result.is_good();
    status = result.status_code();
    detail = result.shared_detail();
    if (good)
    {
      values = std::move(result).value();
    }
    cv.notify_one();
  }

  bool wait(std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fired; });
  }
};

/// A Read response carrying the two OperationLimits values the SessionModelAccess probe reads:
/// results[0] = MaxNodesPerRead, results[1] = MaxNodesPerBrowse.
std::shared_ptr<ua::ReadResponse> make_limits_response(uint32_t maxNodesPerRead, uint32_t maxNodesPerBrowse)
{
  auto resp = std::make_shared<ua::ReadResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  resp->results().push_back(ua::DataValue{ua::Variant{maxNodesPerRead}});
  resp->results().push_back(ua::DataValue{ua::Variant{maxNodesPerBrowse}});
  return resp;
}

/// A Read response whose two probe slots carry no UInt32 value (models an absent OperationLimits Object):
/// SessionModelAccess must treat this as "no client-imposed limit".
std::shared_ptr<ua::ReadResponse> make_absent_limits_response()
{
  auto resp = std::make_shared<ua::ReadResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  resp->results().push_back(ua::DataValue{});  // null Variant -> is_uint32() == false
  resp->results().push_back(ua::DataValue{});
  return resp;
}

/// A Read response of @p count arbitrary DataValues (one per requested node in a chunk).
std::shared_ptr<ua::ReadResponse> make_read_chunk_response(size_t count)
{
  auto resp = std::make_shared<ua::ReadResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  for (size_t i = 0; i < count; ++i)
  {
    resp->results().push_back(ua::DataValue{});
  }
  return resp;
}

/// A Browse response of @p count BrowseResults with empty continuation points (no BrowseNext needed).
std::shared_ptr<ua::BrowseResponse> make_browse_chunk_response(size_t count)
{
  auto resp = std::make_shared<ua::BrowseResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  for (size_t i = 0; i < count; ++i)
  {
    resp->results().push_back(ua::BrowseResult{});
  }
  return resp;
}

/// A Browse response of @p count BrowseResults each carrying a non-empty continuation point, so the flow
/// issues a BrowseNext to continue the paged Browse.
std::shared_ptr<ua::BrowseResponse> make_browse_chunk_with_continuation(size_t count)
{
  auto resp = std::make_shared<ua::BrowseResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  for (size_t i = 0; i < count; ++i)
  {
    ua::BrowseResult br;
    br.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
    resp->results().push_back(std::move(br));
  }
  return resp;
}

/// A transport-Good Read response whose ResponseHeader.serviceResult is Bad and whose results[] is EMPTY (a
/// legal service-fault shape the per-chunk stitch must surface, not mask).
std::shared_ptr<ua::ReadResponse> make_read_service_fault(ua::Status status)
{
  auto resp = std::make_shared<ua::ReadResponse>();
  resp->response_header().service_result() = ua::StatusCode{status};
  return resp;
}

/// A transport-Good Browse response whose ResponseHeader.serviceResult is Bad and whose results[] is EMPTY.
std::shared_ptr<ua::BrowseResponse> make_browse_service_fault(ua::Status status)
{
  auto resp = std::make_shared<ua::BrowseResponse>();
  resp->response_header().service_result() = ua::StatusCode{status};
  return resp;
}

/// A transport-Good BrowseNext response whose ResponseHeader.serviceResult is Bad and whose results[] is
/// EMPTY.
std::shared_ptr<ua::BrowseNextResponse> make_browse_next_service_fault(ua::Status status)
{
  auto resp = std::make_shared<ua::BrowseNextResponse>();
  resp->response_header().service_result() = ua::StatusCode{status};
  return resp;
}

/// A transport-Good BrowseNext response that echoes the continuation point it was sent (0x2A) for each of
/// @p count results and returns no references: an empty page, which a server that never makes progress
/// returns forever.
std::shared_ptr<ua::BrowseNextResponse> make_browse_next_echoing_continuation_points(size_t count)
{
  auto resp = std::make_shared<ua::BrowseNextResponse>();
  resp->response_header().service_result() = ua::Status::Good;
  for (size_t i = 0; i < count; ++i)
  {
    ua::BrowseResult br;
    br.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
    resp->results().push_back(std::move(br));
  }
  return resp;
}

/// Wait for the next parked request, then resolve it with @p response.
void serve_next(CaptureHarness& harness, std::shared_ptr<ua::Structure> response)
{
  ASSERT_TRUE(harness.wait_for_pending_request()) << "expected the client to park a service request";
  ASSERT_TRUE(harness.inject_channel_response(std::move(response)));
}

}  // namespace

// The client reads OperationLimits.MaxNodesPerRead first, then splits a 25-node Read into 10/10/5 sub-Reads.
// The first captured request is the two-node OperationLimits probe; the three that follow are the chunks.
// This proves the batch is split exactly at the server limit and reassembled into one result per input.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessChunking, ReadPagesBatchAtMaxNodesPerRead)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    ReadOutcome outcome;
    access.read_async(std::vector<ua::ReadValueId>(25), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_limits_response(10, 0));  // OperationLimits probe: MaxNodesPerRead = 10
    serve_next(harness, make_read_chunk_response(10));  // chunk 1
    serve_next(harness, make_read_chunk_response(10));  // chunk 2
    serve_next(harness, make_read_chunk_response(5));  // chunk 3

    ASSERT_TRUE(outcome.wait()) << "the read callback must fire once every chunk is served";
    EXPECT_TRUE(outcome.good);
    EXPECT_EQ(outcome.values.size(), 25u) << "the merged result holds one DataValue per input node";

    auto reads = harness.all_captured<ua::ReadRequest>();
    ASSERT_EQ(reads.size(), 4u) << "one OperationLimits probe plus three chunked Reads";

    // Request 0 is the OperationLimits probe (two specific Server-object Variables).
    ASSERT_EQ(reads[0].nodes_to_read().size(), 2u);
    EXPECT_EQ(reads[0].nodes_to_read()[0].node_id(),
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead});
    EXPECT_EQ(reads[0].nodes_to_read()[1].node_id(),
      ua::NodeId{ua::VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse});

    // Requests 1..3 are the data Reads, split at the server limit of 10.
    EXPECT_EQ(reads[1].nodes_to_read().size(), 10u);
    EXPECT_EQ(reads[2].nodes_to_read().size(), 10u);
    EXPECT_EQ(reads[3].nodes_to_read().size(), 5u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// When the server exposes no OperationLimits (the probe returns non-UInt32 values), the client treats the
// limit as "unlimited" and sends the whole batch as a single unchunked Read - the negative arm of
// CL-BASE-003 (a value of 0 / an absent Property means no client-imposed limit).
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessChunking, ReadSendsSingleBatchWhenOperationLimitsAbsent)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    ReadOutcome outcome;
    access.read_async(std::vector<ua::ReadValueId>(25), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());  // probe: no limit advertised
    serve_next(harness, make_read_chunk_response(25));  // single unchunked Read

    ASSERT_TRUE(outcome.wait());
    EXPECT_TRUE(outcome.good);
    EXPECT_EQ(outcome.values.size(), 25u);

    auto reads = harness.all_captured<ua::ReadRequest>();
    ASSERT_EQ(reads.size(), 2u) << "the OperationLimits probe plus exactly one data Read";
    EXPECT_EQ(reads[0].nodes_to_read().size(), 2u) << "request 0 is the probe";
    EXPECT_EQ(reads[1].nodes_to_read().size(), 25u) << "the data Read is not chunked when no limit applies";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// After the first Read has probed and cached the limits, a second Read must NOT re-probe: it chunks
// straight away using the cached MaxNodesPerRead. This proves the "read once and cache" half of
// CL-BASE-003 - the probe is a per-instance, not per-call, cost.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessChunking, SecondReadReusesCachedLimitsWithoutReprobing)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    // First Read: probe (MaxNodesPerRead = 10) then chunks 10/10/5.
    ReadOutcome first;
    access.read_async(std::vector<ua::ReadValueId>(25), [&](auto result) { first.set(std::move(result)); });
    serve_next(harness, make_limits_response(10, 0));
    serve_next(harness, make_read_chunk_response(10));
    serve_next(harness, make_read_chunk_response(10));
    serve_next(harness, make_read_chunk_response(5));
    ASSERT_TRUE(first.wait());
    ASSERT_TRUE(first.good);

    const size_t countAfterFirst = harness.all_captured<ua::ReadRequest>().size();
    ASSERT_EQ(countAfterFirst, 4u);

    // Second Read of 15 nodes: cached limit -> chunks 10/5 with NO fresh probe.
    ReadOutcome second;
    access.read_async(std::vector<ua::ReadValueId>(15), [&](auto result) { second.set(std::move(result)); });
    serve_next(harness, make_read_chunk_response(10));
    serve_next(harness, make_read_chunk_response(5));
    ASSERT_TRUE(second.wait());
    EXPECT_TRUE(second.good);
    EXPECT_EQ(second.values.size(), 15u);

    auto reads = harness.all_captured<ua::ReadRequest>();
    ASSERT_EQ(reads.size(), 6u) << "no second OperationLimits probe was sent";
    // The first request of the second Read is a data chunk (10), not a two-node probe.
    EXPECT_EQ(reads[countAfterFirst].nodes_to_read().size(), 10u)
      << "the cached limit is reused: the second Read starts chunking immediately";
    EXPECT_EQ(reads[countAfterFirst + 1].nodes_to_read().size(), 5u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The Browse path mirrors the Read path: the client probes OperationLimits (a Read of MaxNodesPer*), then
// splits a 25-node Browse into 10/10/5 sub-Browses at the server's MaxNodesPerBrowse.
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessChunking, BrowsePagesBatchAtMaxNodesPerBrowse)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(25), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_limits_response(0, 10));  // probe: MaxNodesPerBrowse = 10
    serve_next(harness, make_browse_chunk_response(10));  // chunk 1
    serve_next(harness, make_browse_chunk_response(10));  // chunk 2
    serve_next(harness, make_browse_chunk_response(5));  // chunk 3

    ASSERT_TRUE(outcome.wait());
    EXPECT_TRUE(outcome.good);
    EXPECT_EQ(outcome.values.size(), 25u) << "one BrowseResult per input node";

    // The probe travels as a Read of the two OperationLimits Variables.
    auto probes = harness.all_captured<ua::ReadRequest>();
    ASSERT_EQ(probes.size(), 1u);
    EXPECT_EQ(probes[0].nodes_to_read().size(), 2u);

    auto browses = harness.all_captured<ua::BrowseRequest>();
    ASSERT_EQ(browses.size(), 3u) << "the Browse batch is split at MaxNodesPerBrowse";
    EXPECT_EQ(browses[0].nodes_to_browse().size(), 10u);
    EXPECT_EQ(browses[1].nodes_to_browse().size(), 10u);
    EXPECT_EQ(browses[2].nodes_to_browse().size(), 5u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A transport-Good Read chunk whose ResponseHeader.serviceResult is Bad with an empty results[] (a legal
// service-fault shape) MUST surface the true serviceResult to the user callback, not be silently stitched
// into a Good/short accumulated vector (SessionReadFlow::on_chunk_read serviceResult FLATTEN).
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessServiceFault, ReadChunkServiceFaultSurfacesServiceResultNotMasked)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    ReadOutcome outcome;
    access.read_async(std::vector<ua::ReadValueId>(3), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());  // probe: no limit -> single unchunked Read
    serve_next(harness, make_read_service_fault(ua::Status::BadSessionIdInvalid));

    ASSERT_TRUE(outcome.wait());
    EXPECT_FALSE(outcome.good);
    EXPECT_EQ(outcome.status.as_status(), ua::Status::BadSessionIdInvalid);
    EXPECT_NE(outcome.status.as_status(), ua::Status::BadUnexpectedError);
    ASSERT_NE(outcome.detail, nullptr);
    EXPECT_EQ(outcome.detail->source, "SessionModelAccess");
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A transport-Good Browse chunk whose ResponseHeader.serviceResult is Bad with an empty results[] MUST
// surface the true serviceResult to the user callback (SessionBrowseFlow::on_chunk_browsed FLATTEN).
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessServiceFault, BrowseChunkServiceFaultSurfacesServiceResultNotMasked)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(3), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());  // probe: no limit -> single unchunked Browse
    serve_next(harness, make_browse_service_fault(ua::Status::BadTooManyOperations));

    ASSERT_TRUE(outcome.wait());
    EXPECT_FALSE(outcome.good);
    EXPECT_EQ(outcome.status.as_status(), ua::Status::BadTooManyOperations);
    EXPECT_NE(outcome.status.as_status(), ua::Status::BadUnexpectedError);
    ASSERT_NE(outcome.detail, nullptr);
    EXPECT_EQ(outcome.detail->source, "SessionModelAccess");
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// Public API review D1 (API-D1.4): one node returns an empty page with the same point while the other two
// make progress. The drain does not end there (a server may stop a page early with nothing to show): the
// point is sent again with the others, and the references that follow are kept.
TEST(SessionModelAccessServiceFault, AnEmptyPageWithTheSamePointIsSentAgainAndTheDrainCompletes)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(3), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    serve_next(harness, make_browse_chunk_with_continuation(3));  // every node: point 0x2A
    auto resp = std::make_shared<ua::BrowseNextResponse>();
    resp->response_header().service_result() = ua::Status::Good;
    ua::BrowseResult empty;  // node 0: the same point, no references
    empty.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
    resp->results().push_back(std::move(empty));
    for (std::uint8_t tag : {std::uint8_t{0x2B}, std::uint8_t{0x2C}})
    {
      ua::BrowseResult progressing;  // nodes 1 and 2 return a reference and a NEW point
      progressing.references().payload().resize(1);
      progressing.continuation_point() =
        ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{tag}}};
      resp->results().push_back(std::move(progressing));
    }
    serve_next(harness, resp);

    ASSERT_TRUE(harness.wait_for_pending_request()) << "the drain continues with all three points";
    const auto* again = dynamic_cast<const ua::BrowseNextRequest*>(harness.capturedRequests->back().get());
    ASSERT_NE(again, nullptr);
    EXPECT_FALSE(again->release_continuation_points());
    ASSERT_EQ(again->continuation_points().size(), 3u);
    EXPECT_EQ(
      again->continuation_points()[0], ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}})
      << "the point that came back with an empty page is sent again";
    auto last = std::make_shared<ua::BrowseNextResponse>();
    last->response_header().service_result() = ua::Status::Good;
    for (int node = 0; node < 3; ++node)
    {
      ua::BrowseResult done;  // one reference each, no further point
      done.references().payload().resize(1);
      last->results().push_back(std::move(done));
    }
    ASSERT_TRUE(harness.inject_channel_response(last));

    ASSERT_TRUE(outcome.wait());
    ASSERT_TRUE(outcome.good) << ua::to_string(outcome.status);
    ASSERT_EQ(outcome.values.size(), 3u);
    EXPECT_EQ(outcome.values[0].references().size(), 1u);
    EXPECT_EQ(outcome.values[1].references().size(), 2u);
    EXPECT_EQ(outcome.values[2].references().size(), 2u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-VIEW-002-A-BUDGET-REFUSAL-RELEASES-THE-CONTINUATION-POINT
// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// A budget refusal on the SECOND node: its first page (60,000, counted by the seeded guard) plus its
// BrowseNext page (60,000) cross the budget. The release carries the first node's NEW point (already stored
// before the refusal) and the refused page's own point.
TEST(SessionModelAccessServiceFault, ABudgetRefusalReleasesEarlierNodesNewPointsAndTheRefusedPagesPoint)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(2), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    auto first = std::make_shared<ua::BrowseResponse>();
    first->response_header().service_result() = ua::Status::Good;
    {
      ua::BrowseResult node0;  // nothing yet, more to come
      node0.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
      first->results().push_back(std::move(node0));
      ua::BrowseResult node1;  // 60,000 references already, more to come
      node1.references().payload().resize(60'000);
      node1.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2A}}};
      first->results().push_back(std::move(node1));
    }
    serve_next(harness, first);
    auto next = std::make_shared<ua::BrowseNextResponse>();
    next->response_header().service_result() = ua::Status::Good;
    {
      ua::BrowseResult node0;  // one reference and a NEW point
      node0.references().payload().resize(1);
      node0.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2B}}};
      next->results().push_back(std::move(node0));
      ua::BrowseResult node1;  // 60,000 more: over the budget, with a new point of its own
      node1.references().payload().resize(60'000);
      node1.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2C}}};
      next->results().push_back(std::move(node1));
    }
    serve_next(harness, next);

    ASSERT_TRUE(outcome.wait());
    EXPECT_EQ(outcome.status.as_status(), ua::Status::BadResponseTooLarge);
    ASSERT_TRUE(harness.wait_for_pending_request()) << "the release BrowseNext must have been sent";
    ASSERT_FALSE(harness.capturedRequests->empty());
    const auto* release = dynamic_cast<const ua::BrowseNextRequest*>(harness.capturedRequests->back().get());
    ASSERT_NE(release, nullptr);
    EXPECT_TRUE(release->release_continuation_points());
    ASSERT_EQ(release->continuation_points().size(), 2u);
    EXPECT_EQ(release->continuation_points()[0],
      ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2B}}})
      << "the earlier node's new point, already stored";
    EXPECT_EQ(release->continuation_points()[1],
      ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2C}}})
      << "the refused page's own point";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// The budgets belong to each node's drain, not to the whole browse: two nodes with 60,000 references each
// are within their own reference budgets (a single shared budget would refuse the second at 120,000).
TEST(SessionModelAccessServiceFault, BudgetsAreCountedPerNodeNotPerBrowse)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(2), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    serve_next(harness, make_browse_chunk_with_continuation(2));
    auto resp = std::make_shared<ua::BrowseNextResponse>();
    resp->response_header().service_result() = ua::Status::Good;
    for (int node = 0; node < 2; ++node)
    {
      ua::BrowseResult last;  // 60,000 references, no further point
      last.references().payload().resize(60'000);
      resp->results().push_back(std::move(last));
    }
    serve_next(harness, resp);

    ASSERT_TRUE(outcome.wait());
    EXPECT_TRUE(outcome.good) << "each node's drain is within its own budget: "
                              << ua::to_string(outcome.status.as_status());
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-CL-VIEW-002-A-BUDGET-REFUSAL-RELEASES-THE-CONTINUATION-POINT
// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
// The multi-continuation drain against a server that never makes progress: every result echoes its point
// with no references. Ten such pages in a row are asked again; the eleventh ends the drain with Bad_Timeout
// (API-D1.4), and the points the server still holds are released in one BrowseNext.
TEST(SessionModelAccessServiceFault, ElevenEmptyPagesInARowEndTheDrainAndReleaseThePoints)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(3), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    serve_next(harness, make_browse_chunk_with_continuation(3));  // 3 results with CP 0x2A -> BrowseNext
    for (int page = 0; page < 11; ++page)
    {
      serve_next(harness, make_browse_next_echoing_continuation_points(3));  // the same points, no references
    }

    ASSERT_TRUE(outcome.wait());
    EXPECT_FALSE(outcome.good);
    EXPECT_EQ(outcome.status.as_status(), ua::Status::BadTimeout);
    ASSERT_NE(outcome.detail, nullptr);
    EXPECT_EQ(outcome.detail->code, "BrowseDrainEmptyPageLimitExceeded");
    ASSERT_TRUE(harness.wait_for_pending_request()) << "the release BrowseNext must have been sent";
    const auto* release = dynamic_cast<const ua::BrowseNextRequest*>(harness.capturedRequests->back().get());
    ASSERT_NE(release, nullptr);
    EXPECT_TRUE(release->release_continuation_points());
    EXPECT_FALSE(release->continuation_points().empty());
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A transport-Good BrowseNext (continuing a paged Browse) whose ResponseHeader.serviceResult is Bad with an
// empty results[] MUST surface the true serviceResult, not the masked Bad_UnexpectedError the count-mismatch
// guard would otherwise fabricate (SessionBrowseFlow::on_browse_next FLATTEN).
// @verifies CL-BASE-003
// @relation(CL-BASE-003, scope=function)
TEST(SessionModelAccessServiceFault, BrowseNextServiceFaultSurfacesServiceResultNotMasked)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(3), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());  // probe: no limit -> single unchunked Browse
    serve_next(harness, make_browse_chunk_with_continuation(3));  // 3 results with CPs -> BrowseNext issued
    serve_next(harness, make_browse_next_service_fault(ua::Status::BadSessionClosed));

    ASSERT_TRUE(outcome.wait());
    EXPECT_FALSE(outcome.good);
    EXPECT_EQ(outcome.status.as_status(), ua::Status::BadSessionClosed);
    EXPECT_NE(outcome.status.as_status(), ua::Status::BadUnexpectedError);
    ASSERT_NE(outcome.detail, nullptr);
    EXPECT_EQ(outcome.detail->source, "SessionModelAccess");
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A BrowseNext page's Uncertain status is kept on its node's merged BrowseResult, with the page's
// references, rather than being replaced by the first page's Good.
// @relation(AC-CL-STATUS-ROUTING-03-A-BROWSE-NEXT-PAGE-STATUS-IS-CHECKED, scope=function)
TEST(SessionModelAccessStatusRouting, AnUncertainBrowseNextPageStatusIsKeptOnItsNode)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(1), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    serve_next(harness, make_browse_chunk_with_continuation(1));  // a Good page with a point, no references
    auto page = std::make_shared<ua::BrowseNextResponse>();
    page->response_header().service_result() = ua::Status::Good;
    ua::BrowseResult last;  // the Uncertain last page: one reference, no further point
    last.status_code() = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
    last.references().payload().resize(1);
    page->results().push_back(std::move(last));
    serve_next(harness, page);

    ASSERT_TRUE(outcome.wait());
    ASSERT_TRUE(outcome.good) << ua::to_string(outcome.status);
    ASSERT_EQ(outcome.values.size(), 1u);
    EXPECT_EQ(outcome.values[0].status_code(), ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable})
      << "the page's code answers for its node";
    EXPECT_EQ(outcome.values[0].references().size(), 1u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Bad BrowseNext page ends its node's walk with the page's code: no further BrowseNext is sent for it.
// @relation(AC-CL-STATUS-ROUTING-03-A-BROWSE-NEXT-PAGE-STATUS-IS-CHECKED, scope=function)
TEST(SessionModelAccessStatusRouting, ABadBrowseNextPageEndsItsNodesWalkWithItsCode)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    BrowseOutcome outcome;
    access.browse_async(
      std::vector<ua::BrowseDescription>(1), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    serve_next(harness, make_browse_chunk_with_continuation(1));
    auto page = std::make_shared<ua::BrowseNextResponse>();
    page->response_header().service_result() = ua::Status::Good;
    ua::BrowseResult failed;  // a Bad page that still names a point: the walk must not follow it
    failed.status_code() = ua::StatusCode{ua::Status::BadContinuationPointInvalid};
    failed.continuation_point() = ua::ContinuationPoint{ua::ByteString{std::vector<std::uint8_t>{0x2B}}};
    page->results().push_back(std::move(failed));
    serve_next(harness, page);

    ASSERT_TRUE(outcome.wait());
    ASSERT_TRUE(outcome.good) << ua::to_string(outcome.status);
    ASSERT_EQ(outcome.values.size(), 1u);
    EXPECT_EQ(outcome.values[0].status_code(), ua::StatusCode{ua::Status::BadContinuationPointInvalid});
    EXPECT_TRUE(outcome.values[0].continuation_point().empty());
    EXPECT_EQ(harness.all_captured<ua::BrowseNextRequest>().size(), 1u)
      << "the walk of a node whose page failed ends there";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Read response's Good subcode ServiceResult is the status of the Result the caller receives.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(SessionModelAccessStatusRouting, AReadsGoodSubcodeServiceResultReachesTheCaller)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    boost::asio::thread_pool tp;
    auto harness = CaptureHarness::create_active(tp.get_executor());
    {
      auto sessionHandle = harness.session_handle();
      ua::dynamic_types::SessionModelAccess access{sessionHandle};

      ReadOutcome outcome;
      access.read_async(
        std::vector<ua::ReadValueId>(2), [&](auto result) { outcome.set(std::move(result)); });

      serve_next(harness, make_absent_limits_response());
      auto response = make_read_chunk_response(2);
      response->response_header().service_result() = ua::StatusCode{serviceStatus};
      if (serviceStatus == ua::Status::GoodLocalOverride)
      {
        response->results()[0].value() = ua::Variant{std::int32_t{4711}};
        response->results()[1].value() = ua::Variant{std::int32_t{4712}};
      }
      serve_next(harness, response);

      ASSERT_TRUE(outcome.wait());
      EXPECT_TRUE(outcome.good);
      EXPECT_EQ(outcome.status, ua::StatusCode{serviceStatus});
      ASSERT_EQ(outcome.values.size(), 2u);
      if (serviceStatus == ua::Status::GoodLocalOverride)
      {
        EXPECT_EQ(outcome.values[0].value(), ua::Variant{std::int32_t{4711}});
        EXPECT_EQ(outcome.values[1].value(), ua::Variant{std::int32_t{4712}});
      }
      else
      {
        EXPECT_TRUE(outcome.values[0].value().empty());
        EXPECT_TRUE(outcome.values[1].value().empty());
      }
    }

    harness.cleanup_sync();
    harness.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// A ServiceFault with an Uncertain code reaches the session as a result with that code and no response; the
// Read's callback runs with that code.
// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST(SessionModelAccessStatusRouting, AnUncertainServiceFaultCompletesTheReadCallback)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    ua::dynamic_types::SessionModelAccess access{sessionHandle};

    ReadOutcome outcome;
    access.read_async(std::vector<ua::ReadValueId>(2), [&](auto result) { outcome.set(std::move(result)); });

    serve_next(harness, make_absent_limits_response());
    ASSERT_TRUE(harness.wait_for_pending_request());
    ASSERT_TRUE(
      harness.inject_channel_failure(ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue}));

    ASSERT_TRUE(outcome.wait()) << "the callback ran";
    EXPECT_FALSE(outcome.good);
    EXPECT_EQ(
      outcome.status.value(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue}.value());
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
