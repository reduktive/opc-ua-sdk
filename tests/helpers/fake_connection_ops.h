// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_FAKE_CONNECTION_OPS_H
#define UA_TESTS_HELPERS_FAKE_CONNECTION_OPS_H

/// @file
/// @brief Fakes for the UPWARD tier-1 interface roles (@ref ua::client::detail::WireOps /
///        @ref ua::client::detail::SubscriptionOps / @ref ua::client::detail::SupportOps) so a consumer
///        (@ref ua::client::detail::SubscriptionsPipeline, tier-2 facades) can be unit-tested with no real
///        @ref ua::client::detail::ConnectionImpl / Session / executor (the testable-interfaces rule).

#include "ua_array.h"
#include "ua_browse_result.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_data_value.h"
#include "ua_history_data.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_history_update_result.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_reference_description.h"
#include "ua_result.h"
#include "ua_semantic_change_cache.h"
#include "ua_status.h"
#include "ua_subscription_factory.h"
#include "ua_update_data_details.h"
#include "ua_variant.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace ua::test_helpers
{

/// Fake @ref ua::client::detail::WireOps. `read_async` records each request and, by default, answers each
/// `nodesToRead` entry with a Good @ref ua::DataValue carrying a monotonically-increasing Int32 (so a
/// paged, stitched read is order-verifiable). `max_nodes_per_read` returns a settable page size and counts
/// its own consultations. The remaining wire ops are inert (complete Good-empty); they exist only to
/// satisfy the pure-virtual interface.
class FakeWireOps : public ua::client::detail::WireOps
{
public:
  // --- read_async instrumentation (the polled-Read fallback surface) ---
  std::vector<ua::ReadRequest> readRequests;  ///< every Read the fallback issued, in call order
  std::size_t readCalls = 0;  ///< number of read_async invocations (== page count)
  mutable std::size_t maxNodesPerReadCalls = 0;  ///< number of times the fallback consulted the limit
  std::uint32_t maxNodesPerRead = 100;  ///< the page-size limit the fallback pages by (CL-SUB-020)
  ua::StatusCode readStatus{ua::Status::Good};  ///< when bad, read_async completes with it (no results)
  int resultsPerReadDelta = 0;  ///< per-page adjustment to the DataValue count returned vs ReadValueIds
                                ///< sent (negative under-returns, positive over-returns): exercises the
                                ///< paged stitcher's per-page results.size() == nodesToRead.size() check

  // --- scripted-read surface (TypeResolver DataTypeDefinition / dictionary discovery) ---
  // When `scriptedReadResponses` is non-empty it is consumed FIRST, in FIFO order, in preference to the
  // default Int32 answer - so a test can script a DataTypeDefinition-present / -absent Read. When
  // `deferReads` is set the completion is captured instead of fired (exercises the weak-owner bail when
  // the resolver is destroyed before the response lands). Both default-inert (empty / false), so existing
  // FakeWireOps consumers are unaffected.
  std::deque<ua::Result<ua::ReadResponse>> scriptedReadResponses;
  bool deferReads = false;
  std::vector<std::function<void()>> deferredReadInvocations;

  // A mid-flight interposition hook fired at the TOP of every read_async, before the response is served. It
  // lets a test inject a concurrent event (e.g. a SemanticChange invalidation) precisely when a re-resolve
  // Property Read is in flight - the deterministic stand-in for an invalidate that races the re-resolve
  // window (used by the CL-DA-010 lost-invalidation tests). Default-empty (no-op), so existing consumers are
  // unaffected.
  std::function<void()> onReadServed;

  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept override
  {
    ++readCalls;
    readRequests.push_back(request);
    if (onReadServed)
    {
      onReadServed();
    }
    if (!scriptedReadResponses.empty())
    {
      auto scripted = std::move(scriptedReadResponses.front());
      scriptedReadResponses.pop_front();
      // Honour resultsPerReadDelta on a scripted Good response too (default 0 == inert): a positive delta
      // pads with default Int32 DataValues, a negative delta drops from the back - so a test can script a
      // conforming Property-Value read yet force a per-page results.size() != nodesToRead.size() mismatch.
      if (scripted.is_good() && resultsPerReadDelta != 0)
      {
        auto& results = scripted.value().results();
        if (resultsPerReadDelta < 0)
        {
          const std::size_t drop =
            std::min<std::size_t>(static_cast<std::size_t>(-resultsPerReadDelta), results.size());
          results.resize(results.size() - drop);
        }
        else
        {
          for (int i = 0; i < resultsPerReadDelta; ++i)
          {
            results.push_back(ua::DataValue{ua::Variant{static_cast<std::int32_t>(mNextValue++)}});
          }
        }
      }
      auto deliver = [scripted = std::move(scripted), callback = std::move(callback)]() mutable
      {
        callback(std::move(scripted));
      };
      if (deferReads)
      {
        deferredReadInvocations.push_back(std::move(deliver));
        return;
      }
      deliver();
      return;
    }
    if (readStatus.is_bad())
    {
      callback(ua::Result<ua::ReadResponse>{readStatus});
      return;
    }
    // By default answer one DataValue per ReadValueId; resultsPerReadDelta perturbs the count (clamped at 0)
    // so a test can force a non-conforming server that under/over-returns per page.
    const std::size_t requested = request.nodes_to_read().size();
    std::size_t toReturn = requested;
    if (resultsPerReadDelta < 0)
    {
      toReturn -= std::min<std::size_t>(static_cast<std::size_t>(-resultsPerReadDelta), requested);
    }
    else
    {
      toReturn += static_cast<std::size_t>(resultsPerReadDelta);
    }
    ua::ReadResponse response;
    for (std::size_t i = 0; i < toReturn; ++i)
    {
      response.results().push_back(ua::DataValue{ua::Variant{static_cast<std::int32_t>(mNextValue++)}});
    }
    callback(ua::Result<ua::ReadResponse>{std::move(response)});
  }

  [[nodiscard]] std::uint32_t max_nodes_per_read() const noexcept override
  {
    ++maxNodesPerReadCalls;
    return maxNodesPerRead;
  }

  // --- write instrumentation (DataAccess write / write_via_dictionary surface) ---
  std::vector<ua::WriteRequest> writeRequests;  ///< every Write issued, in order
  std::deque<ua::StatusCode> writeOutcomes;  ///< scripted per-write StatusCodes, consumed FIFO
  ua::StatusCode writeServiceStatus{ua::Status::Good};  ///< when bad, the service call itself fails
  /// Stamped on the WriteResponse.response_header().service_result() (a well-formed transport response whose
  /// SERVICE-level result is bad). Distinct from `writeServiceStatus` (which fails the outer wire-op Result):
  /// the tier-0 funnel returns the response verbatim, so this exercises do_write_value's serviceResult
  /// FLATTEN facade. Default Good == inert.
  ua::StatusCode writeHeaderServiceResult{ua::Status::Good};
  int writeResultsDelta = 0;  ///< per-Write adjustment to the StatusCode count returned vs nodes_to_write
                              ///< sent (negative under-returns, positive over-returns): exercises a
                              ///< consumer's per-write results.size() == nodes_to_write.size() check

  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept override
  {
    // Default-conforming: one Good StatusCode per nodes_to_write entry (so a consumer that inspects the
    // per-write result sees a Good passthrough), overridable per write via `writeOutcomes` (e.g. to model a
    // server clamp/reject verbatim, CL-DA-007). `writeServiceStatus` fails the service call itself.
    // `writeResultsDelta` perturbs the returned StatusCode count (clamped at 0) so a test can force a
    // non-conforming server that under/over-returns (e.g. an empty Good Write response, CL-BASEDIAG-003).
    const std::size_t requested = request.nodes_to_write().size();
    std::size_t writeCount = requested;
    if (writeResultsDelta < 0)
    {
      writeCount -= std::min<std::size_t>(static_cast<std::size_t>(-writeResultsDelta), requested);
    }
    else
    {
      writeCount += static_cast<std::size_t>(writeResultsDelta);
    }
    writeRequests.push_back(std::move(request));
    if (writeServiceStatus.is_bad())
    {
      callback(ua::Result<ua::WriteResponse>{writeServiceStatus});
      return;
    }
    ua::WriteResponse response;
    response.response_header().service_result() = writeHeaderServiceResult;
    for (std::size_t i = 0; i < writeCount; ++i)
    {
      if (!writeOutcomes.empty())
      {
        response.results().push_back(writeOutcomes.front());
        writeOutcomes.pop_front();
      }
      else
      {
        response.results().push_back(ua::StatusCode{ua::Status::Good});
      }
    }
    callback(ua::Result<ua::WriteResponse>{std::move(response)});
  }

  // --- browse instrumentation (BrowseCursor surface) ---
  /// One scripted Browse/BrowseNext page: its references, the continuation point the server hands back (a
  /// non-empty one means "call BrowseNext for more"), and the per-node status.
  struct BrowsePage
  {
    std::vector<ua::ReferenceDescription> references;
    ua::ContinuationPoint continuationPoint;
    ua::StatusCode status{ua::Status::Good};
  };

  std::deque<BrowsePage> browsePages;  ///< scripted pages, consumed in order by browse/browse_next
  std::vector<ua::BrowseRequest> browseRequests;  ///< every Browse issued
  std::vector<ua::BrowseNextRequest> browseNextRequests;  ///< every BrowseNext issued (incl. release-only)
  ua::StatusCode browseServiceStatus{ua::Status::Good};  ///< when bad, the service call itself fails
  /// Stamped on the BrowseResponse.response_header().service_result() (a well-formed transport response whose
  /// SERVICE-level result is bad). Distinct from `browseServiceStatus` (which fails the outer wire-op
  /// Result): the tier-0 funnel returns the response verbatim, so this exercises the cursor's serviceResult
  /// FLATTEN facade (CL-VIEW-006). Default Good == inert.
  ua::StatusCode browseHeaderServiceResult{ua::Status::Good};
  /// When true, the Browse response carries an EMPTY Results[] array (a Good-transport response with no
  /// per-node result - the Err-002 server contract violation the cursor must reject as BadUnexpectedError).
  bool browseOmitResults = false;
  /// Stamped on the BrowseNextResponse.response_header().service_result() (a well-formed transport response
  /// whose SERVICE-level result is bad) - exercises drain_property_children's serviceResult FLATTEN facade.
  /// Default Good == inert.
  ua::StatusCode browseNextHeaderServiceResult{ua::Status::Good};
  /// When true, the BrowseNext response carries an EMPTY Results[] array (a Good-transport response with no
  /// per-node result - the service-fault shape drain_property_children must reject/flatten).
  bool browseNextOmitResults = false;
  bool deferBrowseNext = false;  ///< when true, capture the BrowseNext completion instead of firing it now
  std::vector<std::function<void()>>
    deferredBrowseNextInvocations;  ///< captured completions, fired on demand

  void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept override
  {
    browseRequests.push_back(request);
    if (browseServiceStatus.is_bad())
    {
      callback(ua::Result<ua::BrowseResponse>{browseServiceStatus});
      return;
    }
    ua::BrowseResponse response;
    response.response_header().service_result() = browseHeaderServiceResult;
    if (!browseOmitResults)
    {
      // OPC 10000-4 5.8.2: Browse returns one BrowseResult per nodesToBrowse entry, positionally paired.
      // One scripted page is consumed per description, so a caller batching several nodes into one request
      // reads its results back by index (a single-description request behaves exactly as before).
      const std::size_t descriptions = std::max<std::size_t>(request.nodes_to_browse().size(), 1U);
      for (std::size_t i = 0; i < descriptions; ++i)
      {
        response.results().push_back(next_browse_result());
      }
    }
    callback(ua::Result<ua::BrowseResponse>{std::move(response)});
  }

  void browse_next_async(ua::BrowseNextRequest request,
    std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept override
  {
    // The request is recorded synchronously (so a test can assert it was ISSUED even when deferred); the
    // response is built and delivered in `deliver`, which either fires now or is captured for a later
    // fire_deferred_browse_next() - the latter lets a test leave an advance in flight while it calls
    // close_async (the close-races-advance CP-leak path).
    browseNextRequests.push_back(request);
    auto deliver =
      [this, release = request.release_continuation_points(), callback = std::move(callback)]() mutable
    {
      if (browseServiceStatus.is_bad())
      {
        callback(ua::Result<ua::BrowseNextResponse>{browseServiceStatus});
        return;
      }
      ua::BrowseNextResponse response;
      response.response_header().service_result() = browseNextHeaderServiceResult;
      if (browseNextOmitResults)
      {
        // A Good-transport response with an EMPTY Results[] (the service-fault shape): exercises the
        // serviceResult FLATTEN / empty-results guard in drain_property_children.
      }
      else if (release)
      {
        // A release-only BrowseNext frees the server continuation point and returns no references.
        response.results().push_back(ua::BrowseResult{});
      }
      else
      {
        response.results().push_back(next_browse_result());
      }
      callback(ua::Result<ua::BrowseNextResponse>{std::move(response)});
    };
    if (deferBrowseNext)
    {
      deferredBrowseNextInvocations.push_back(std::move(deliver));
      return;
    }
    deliver();
  }

  /// Fires every captured deferred BrowseNext completion in issue order (simulates an in-flight advance
  /// returning after the caller has raced a close against it). Reentrancy-safe: the pending list is moved out
  /// first, so a completion that itself issues another BrowseNext queues into a fresh list.
  void fire_deferred_browse_next()
  {
    auto pending = std::move(deferredBrowseNextInvocations);
    deferredBrowseNextInvocations.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }

  /// Fires every captured deferred Read completion in issue order (simulates a DataTypeDefinition Read
  /// returning after the TypeResolver that issued it has been destroyed - the weak-owner bail).
  void fire_deferred_reads()
  {
    auto pending = std::move(deferredReadInvocations);
    deferredReadInvocations.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }

  // --- translate instrumentation (FileTransferClient instance-method resolution surface) ---
  /// When set, `translate_browse_paths_async` answers with `translateHandler(request)` (so a File-open test
  /// can resolve the six FileType method paths to instance nodes). Default-empty -> the historical Good
  /// empty-response default, so the other WireOps consumers are unaffected.
  std::function<ua::TranslateBrowsePathsToNodeIdsResponse(const ua::TranslateBrowsePathsToNodeIdsRequest&)>
    translateHandler;
  /// When bad, the translate wire-op Result itself fails (transport-level) - exercises the FileTransfer
  /// open path's `interpret_file_method_resolution` service-bad -> FileOpenMethodResolveFailed wrap. Inert
  /// Good.
  ua::StatusCode translateServiceStatus{ua::Status::Good};
  bool deferTranslate = false;  ///< when true, capture the translate completion instead of firing it now
  std::vector<std::function<void()>> deferredTranslateInvocations;  ///< captured completions

  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept override
  {
    // Compute the response NOW (capture it + the callback by value, never `this`) so a DEFERRED completion
    // can fire safely even after the FakeWireOps is destroyed - the seam2-gone open test drops the WireOps
    // before firing to make FileTransferClient::open_async's inner wireOps.lock() (seam2) return null.
    ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> result =
      translateServiceStatus.is_bad()
        ? ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{translateServiceStatus}
        : ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{
            translateHandler ? translateHandler(request) : ua::TranslateBrowsePathsToNodeIdsResponse{}};
    auto deliver = [result = std::move(result), callback = std::move(callback)]() mutable
    {
      callback(std::move(result));
    };
    if (deferTranslate)
    {
      deferredTranslateInvocations.push_back(std::move(deliver));
      return;
    }
    deliver();
  }

  /// Fires every captured deferred translate completion in issue order (simulates the resolve completing
  /// after the Connection dropped - the seam2-gone Bad_ConnectionClosed path in
  /// FileTransferClient::open_async).
  void fire_deferred_translates()
  {
    auto pending = std::move(deferredTranslateInvocations);
    deferredTranslateInvocations.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }

  // --- call instrumentation (FileTransferClient / FileHandle + method-call facades surface) ---
  /// One scripted Call outcome: the single method's per-call status plus its output arguments. When
  /// `callOutcomes` is empty the call is answered with a Good, empty-output `CallResponse` (the historical
  /// inert default), so existing consumers are unaffected.
  struct CallOutcome
  {
    ua::StatusCode status{ua::Status::Good};  ///< the per-call CallMethodResult status
    std::vector<ua::Variant> outputs;  ///< the method's output arguments
  };

  std::deque<CallOutcome> callOutcomes;  ///< scripted outcomes, consumed in order by call_async
  std::vector<ua::CallRequest> callRequests;  ///< every Call issued, in order
  ua::StatusCode callServiceStatus{
    ua::Status::Good};  ///< when bad, the service call itself fails (transport)
  /// Stamped on the CallResponse.response_header().service_result() (a well-formed transport response whose
  /// SERVICE-level result is bad). Distinct from `callServiceStatus` (which fails the outer wire-op Result):
  /// the tier-0 funnel returns the response verbatim, so this exercises the FileHandle / FileTransfer /
  /// state-machine Call serviceResult FLATTEN facade. Default Good == inert.
  ua::StatusCode callHeaderServiceResult{ua::Status::Good};
  bool deferCalls = false;  ///< when true, capture the call completion instead of firing it now
  std::vector<std::function<void()>> deferredCallInvocations;  ///< captured completions

  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept override
  {
    // Record synchronously (so a test can assert the request even when deferred); build + deliver the
    // response in `deliver`, which fires now or is captured for a later fire_deferred_calls() (the weak-owner
    // bail).
    callRequests.push_back(request);
    auto deliver = [this, callback = std::move(callback)]() mutable
    {
      if (callServiceStatus.is_bad())
      {
        callback(ua::Result<ua::CallResponse>{callServiceStatus});
        return;
      }
      ua::CallResponse response;
      response.response_header().service_result() = callHeaderServiceResult;
      if (!callOutcomes.empty())
      {
        CallOutcome outcome = std::move(callOutcomes.front());
        callOutcomes.pop_front();
        ua::CallMethodResult result;
        result.status_code() = outcome.status;
        for (auto& output : outcome.outputs)
        {
          result.output_arguments().push_back(std::move(output));
        }
        response.results().push_back(std::move(result));
      }
      callback(ua::Result<ua::CallResponse>{std::move(response)});
    };
    if (deferCalls)
    {
      deferredCallInvocations.push_back(std::move(deliver));
      return;
    }
    deliver();
  }

  /// Fires every captured deferred Call completion in issue order (simulates an in-flight FileType Call
  /// returning after the FileHandle / facade that issued it has been destroyed - the weak-owner bail).
  void fire_deferred_calls()
  {
    auto pending = std::move(deferredCallInvocations);
    deferredCallInvocations.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }

  // --- history read instrumentation (HistoryFacade / HistoryReadCursor surface) ---
  /// One scripted HistoryRead page: its `DataValue`s, the continuation point the server hands back (a
  /// non-empty one means "call HistoryRead again with it for more"), and the per-node status.
  struct HistoryPage
  {
    std::vector<ua::DataValue> values;
    ua::ContinuationPoint continuationPoint;
    ua::StatusCode status{ua::Status::Good};
  };

  std::deque<HistoryPage> historyReadPages;  ///< scripted pages, consumed in order by non-release reads
  std::vector<ua::HistoryReadRequest> historyReadRequests;  ///< every HistoryRead issued (incl. release-only)
  ua::StatusCode historyReadServiceStatus{ua::Status::Good};  ///< when bad, the service call itself fails
  /// Stamped on the HistoryReadResponse.response_header().service_result() (a well-formed transport response
  /// whose SERVICE-level result is bad). Distinct from `historyReadServiceStatus` (which fails the outer
  /// wire-op Result): the tier-0 funnel returns the response verbatim, so this exercises the HistoryFacade
  /// issue_read / HistoryReadCursor next_async / close_async serviceResult FLATTEN facade. Default Good ==
  /// inert.
  ua::StatusCode historyReadHeaderServiceResult{ua::Status::Good};
  bool deferHistoryRead = false;  ///< when true, capture the read completion instead of firing it now
  std::vector<std::function<void()>> deferredHistoryReadInvocations;  ///< captured completions

  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept override
  {
    // Record synchronously (so a test can assert the request even when deferred); build + deliver the
    // response in `deliver`, which fires now or is captured for a later fire_deferred_history_reads().
    historyReadRequests.push_back(request);
    const bool release = request.release_continuation_points();
    auto deliver = [this, release, callback = std::move(callback)]() mutable
    {
      if (historyReadServiceStatus.is_bad())
      {
        callback(ua::Result<ua::HistoryReadResponse>{historyReadServiceStatus});
        return;
      }
      ua::HistoryReadResponse response;
      response.response_header().service_result() = historyReadHeaderServiceResult;
      ua::HistoryReadResult result;
      if (release)
      {
        // A release-only HistoryRead frees the server continuation point and returns no data.
        result.status_code() = ua::StatusCode{ua::Status::Good};
      }
      else
      {
        HistoryPage page;
        if (!historyReadPages.empty())
        {
          page = std::move(historyReadPages.front());
          historyReadPages.pop_front();
        }
        result.status_code() = page.status;
        result.continuation_point() = std::move(page.continuationPoint);
        auto data = std::make_unique<ua::HistoryData>();
        for (auto& value : page.values)
        {
          data->data_values().push_back(std::move(value));
        }
        result.history_data() = std::move(data);
      }
      response.results().push_back(std::move(result));
      callback(ua::Result<ua::HistoryReadResponse>{std::move(response)});
    };
    if (deferHistoryRead)
    {
      deferredHistoryReadInvocations.push_back(std::move(deliver));
      return;
    }
    deliver();
  }

  /// Fires every captured deferred HistoryRead completion in issue order.
  void fire_deferred_history_reads()
  {
    auto pending = std::move(deferredHistoryReadInvocations);
    deferredHistoryReadInvocations.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }

  // --- history update instrumentation ---
  /// One scripted HistoryUpdate per-node outcome: the per-node status and the per-entry operation results.
  struct HistoryUpdateOutcome
  {
    ua::StatusCode statusCode{ua::Status::Good};
    std::vector<ua::StatusCode> operationResults;
  };

  std::deque<HistoryUpdateOutcome> historyUpdateOutcomes;  ///< scripted outcomes, consumed in order
  std::vector<ua::HistoryUpdateRequest> historyUpdateRequests;  ///< every HistoryUpdate issued
  ua::StatusCode historyUpdateServiceStatus{ua::Status::Good};  ///< when bad, the service call itself fails
  /// Stamped on the HistoryUpdateResponse.response_header().service_result() (a well-formed transport
  /// response whose SERVICE-level result is bad). Distinct from `historyUpdateServiceStatus` (which fails the
  /// outer wire-op Result): the tier-0 funnel returns the response verbatim, so this exercises issue_update's
  /// serviceResult FLATTEN facade. Default Good == inert.
  ua::StatusCode historyUpdateHeaderServiceResult{ua::Status::Good};

  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept override
  {
    // Model a CONFORMING server by default (no scripted outcome): return one Good operationResult per
    // updateValue for an UpdateData* call, so the CL-HIST-021 length invariant holds unless a test explicitly
    // scripts a mismatch. Deletes carry no updateValues, so they default to none. Snapshot the count before
    // the request is moved into the recorder.
    std::size_t conformingOperationResults = 0;
    if (!request.history_update_details().empty())
    {
      if (const auto* update =
            dynamic_cast<const ua::UpdateDataDetails*>(request.history_update_details()[0].get()))
      {
        conformingOperationResults = update->update_values().size();
      }
    }
    historyUpdateRequests.push_back(std::move(request));
    if (historyUpdateServiceStatus.is_bad())
    {
      callback(ua::Result<ua::HistoryUpdateResponse>{historyUpdateServiceStatus});
      return;
    }
    ua::HistoryUpdateResponse response;
    response.response_header().service_result() = historyUpdateHeaderServiceResult;
    ua::HistoryUpdateResult result;
    if (!historyUpdateOutcomes.empty())
    {
      HistoryUpdateOutcome outcome = std::move(historyUpdateOutcomes.front());
      historyUpdateOutcomes.pop_front();
      result.status_code() = outcome.statusCode;
      for (const auto& operationResult : outcome.operationResults)
      {
        result.operation_results().push_back(operationResult);
      }
    }
    else
    {
      for (std::size_t i = 0; i < conformingOperationResults; ++i)
      {
        result.operation_results().push_back(ua::StatusCode{ua::Status::Good});
      }
    }
    response.results().push_back(std::move(result));
    callback(ua::Result<ua::HistoryUpdateResponse>{std::move(response)});
  }

  std::vector<ua::RegisterNodesRequest> registerRequests;  ///< every RegisterNodes issued

  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept override
  {
    registerRequests.push_back(request);
    callback(ua::Result<ua::RegisterNodesResponse>{ua::RegisterNodesResponse{}});
  }

  // --- unregister instrumentation (AddressSpaceCache release / drain surface) ---
  std::vector<ua::UnregisterNodesRequest> unregisterRequests;  ///< every UnregisterNodes issued
  ua::StatusCode unregisterServiceStatus{ua::Status::Good};  ///< when bad, the service result is bad
  bool deferUnregister = false;  ///< when true, capture the completion instead of firing it
  std::vector<std::function<void(ua::Result<ua::UnregisterNodesResponse>)>> deferredUnregisterCbs;

  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept override
  {
    unregisterRequests.push_back(request);
    if (deferUnregister)
    {
      deferredUnregisterCbs.push_back(std::move(callback));
      return;
    }
    if (unregisterServiceStatus.is_bad())
    {
      callback(ua::Result<ua::UnregisterNodesResponse>{unregisterServiceStatus});
      return;
    }
    callback(ua::Result<ua::UnregisterNodesResponse>{ua::UnregisterNodesResponse{}});
  }

  /// Fires every captured deferred UnregisterNodes completion with @p status (simulates the response
  /// arriving later - e.g. after the cache owner has been destroyed, exercising the weak-owner bail).
  void fire_deferred_unregisters(ua::StatusCode status = ua::Status::Good)
  {
    auto pending = std::move(deferredUnregisterCbs);
    deferredUnregisterCbs.clear();
    for (auto& callback : pending)
    {
      if (status.is_bad())
      {
        callback(ua::Result<ua::UnregisterNodesResponse>{status});
      }
      else
      {
        callback(ua::Result<ua::UnregisterNodesResponse>{ua::UnregisterNodesResponse{}});
      }
    }
  }

private:
  /// Pops the next scripted @ref BrowsePage into a @ref ua::BrowseResult (an empty Good page when the
  /// script is exhausted).
  ua::BrowseResult next_browse_result()
  {
    ua::BrowseResult result;
    if (browsePages.empty())
    {
      return result;  // Good status, no references, empty continuation point
    }
    BrowsePage page = std::move(browsePages.front());
    browsePages.pop_front();
    result.status_code() = page.status;
    result.continuation_point() = std::move(page.continuationPoint);
    for (auto& reference : page.references)
    {
      result.references().push_back(std::move(reference));
    }
    return result;
  }

  std::int32_t mNextValue = 0;
};

/// Fake @ref ua::client::detail::SubscriptionOps: records the Publish/Republish send interface calls (the
/// renamed former `SubscriptionsPipelineHost` recorder).
class FakeSubscriptionOps : public ua::client::detail::SubscriptionOps
{
public:
  struct Adjustment
  {
    std::uint32_t subscriptionId = 0;
    double publishingInterval = 0.0;
    std::uint32_t maxNotificationsPerPublish = 0;
  };

  std::vector<std::vector<ua::client::detail::SubscriptionAcknowledgement>> publishes;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> republishes;  // (subId, seqNum)
  std::vector<Adjustment> adjustments;
  std::deque<ua::StatusCode> adjustmentOutcomes;

  void send_publish(std::vector<ua::client::detail::SubscriptionAcknowledgement> acknowledgements) override
  {
    publishes.push_back(std::move(acknowledgements));
  }

  void republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber) override
  {
    republishes.emplace_back(subscriptionId, sequenceNumber);
  }

  void adjust_max_notifications_per_publish(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) override
  {
    adjustments.push_back(Adjustment{subscriptionId, publishingInterval, maxNotificationsPerPublish});
    const ua::StatusCode outcome =
      adjustmentOutcomes.empty() ? ua::StatusCode{ua::Status::Good} : adjustmentOutcomes.front();
    if (!adjustmentOutcomes.empty())
    {
      adjustmentOutcomes.pop_front();
    }
    callback(outcome.is_good() ? ua::VoidResult{} : ua::VoidResult{outcome});
  }
};

/// Fake @ref ua::client::detail::SubscriptionFactoryOps (wiring section 2): records every
/// `create_subscription_managed_async` + `monitor_data_change_async` call so a ServerDiagnostics
/// subscribe-over-poll test (CL-BASEDIAG-004) can assert the MonitorRequest (target Variable + filter), then
/// drive an array data-change into the wrapper's captured @ref ua::client::DataChangeCallback. Also acts as
/// the returned item's @ref ua::client::detail::MonitoredItemOwner so a test can prove persist-on-drop
/// (dropping the handle issues NO delete; only an explicit `delete_async` does).
class FakeSubscriptionFactory : public ua::client::detail::SubscriptionFactoryOps,
                                public ua::client::detail::MonitoredItemOwner,
                                public std::enable_shared_from_this<FakeSubscriptionFactory>
{
public:
  struct CreateCall
  {
    double publishingInterval = 0.0;
    bool publishingEnabled = true;
  };

  std::vector<CreateCall> creates;  ///< every create_subscription_managed_async, in order
  std::vector<ua::client::MonitorRequest> monitorRequests;  ///< every monitor_data_change_async request
  std::uint32_t lastMonitorSubscriptionId = 0;  ///< the subscriptionId the last monitor targeted
  ua::client::DataChangeCallback lastOnData;  ///< the wrapper's decode-wrapping onData (drive deliveries)

  std::uint32_t nextSubscriptionId = 4242;  ///< the id create hands back
  std::uint32_t nextClientHandle = 7;  ///< the client handle monitor stamps on the returned item
  ua::StatusCode createStatus{ua::Status::Good};  ///< when bad, create completes with it
  ua::StatusCode monitorStatus{ua::Status::Good};  ///< when bad, monitor completes with it

  std::size_t deleteCalls = 0;  ///< number of mi_delete_async invocations (persist-on-drop proof)
  std::size_t modifyCalls = 0;
  std::size_t setModeCalls = 0;

  void create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
    std::function<void(ua::Result<ua::client::detail::SubscriptionCreated>)> callback) noexcept override
  {
    creates.push_back(CreateCall{publishingInterval, publishingEnabled});
    if (createStatus.is_bad())
    {
      callback(ua::Result<ua::client::detail::SubscriptionCreated>{createStatus});
      return;
    }
    ua::client::detail::SubscriptionCreated created;
    created.subscriptionId = nextSubscriptionId;
    created.revisedPublishingInterval = publishingInterval;
    created.publishingEnabled = publishingEnabled;
    callback(ua::Result<ua::client::detail::SubscriptionCreated>{created});
  }

  void monitor_data_change_async(std::uint32_t subscriptionId, ua::client::MonitorRequest request,
    ua::client::DataChangeCallback onData,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept override
  {
    lastMonitorSubscriptionId = subscriptionId;
    const ua::NodeId node = request.nodeId;
    const ua::AttributeId attribute = request.attribute;
    monitorRequests.push_back(std::move(request));
    lastOnData = std::move(onData);
    if (monitorStatus.is_bad())
    {
      callback(ua::client::MonitoredItemResult{monitorStatus});
      return;
    }
    ua::client::MonitoredItem item = ua::client::detail::MonitoredItemFactory::create(
      std::weak_ptr<ua::client::detail::MonitoredItemOwner>{shared_from_this()},
      nextClientHandle,
      node,
      attribute,
      ua::client::MonitoredItemKind::DataChange,
      ua::MonitoringMode::Reporting);
    callback(ua::client::MonitoredItemResult{std::move(item)});
  }

  /// Delivers @p value as one data-change notification to the wrapper's captured onData (simulates a Publish
  /// notification for the array Variable). No-op when no monitor was created.
  void deliver_data_change(ua::DataValue value)
  {
    if (!lastOnData)
    {
      return;
    }
    ua::client::DataChangeEvent event;
    event.itemId = nextClientHandle;
    event.nodeId = monitorRequests.empty() ? ua::NodeId{} : monitorRequests.back().nodeId;
    event.attribute = ua::AttributeId::Value;
    event.value = std::move(value);
    lastOnData(std::move(event));
  }

  // --- MonitoredItemOwner: record self-actions (persist-on-drop proof) ---
  void mi_modify_async(ua::client::MonitoredItemId, ua::client::MonitorRequest,
    std::function<void(ua::VoidResult)> callback) noexcept override
  {
    ++modifyCalls;
    callback(ua::VoidResult{});
  }

  void mi_set_mode_async(ua::client::MonitoredItemId, ua::MonitoringMode,
    std::function<void(ua::VoidResult)> callback) noexcept override
  {
    ++setModeCalls;
    callback(ua::VoidResult{});
  }

  void mi_delete_async(
    ua::client::MonitoredItemId, std::function<void(ua::VoidResult)> callback) noexcept override
  {
    ++deleteCalls;
    callback(ua::VoidResult{});
  }
};

/// Fake @ref ua::client::detail::SupportOps: `post_to_executor` posts to a settable executor (so a test's
/// io_context drains the hand-off); `namespace_table` and `state` return settable values. The three tier-2
/// reach-through handles (@ref event_subscriber / @ref type_resolver / @ref subscription_factory, wiring
/// section 2) return settable slots - default-null so existing read-cluster consumers are unaffected and so a
/// test can exercise the gone-interface (null) path; a subscribe test sets the relevant slot (a real
/// `EventSubscriberImpl` driven by a `FakeEventBackboneOps`, or a @ref FakeSubscriptionFactory).
class FakeSupportOps : public ua::client::detail::SupportOps
{
public:
  boost::asio::any_io_executor executor;  ///< where post_to_executor delivers (set by the test)
  std::shared_ptr<const ua::client::NamespaceTable> namespaceTable;  ///< returned by namespace_table()
  ua::client::detail::ConnectionState connectionState = ua::client::detail::ConnectionState::Active;
  std::shared_ptr<ua::client::detail::EventSubscriberImpl>
    eventSubscriber;  ///< returned by event_subscriber()
  std::shared_ptr<ua::client::detail::TypeResolver> typeResolver;  ///< returned by type_resolver()
  std::shared_ptr<ua::client::detail::SubscriptionFactoryOps>
    subscriptionFactory;  ///< returned by subscription_factory()
  /// Returned by semantic_change_cache() (section 8.18.2 / Slice W2a). A test that exercises the DataAccess
  /// SemanticChange auto-invalidation (CL-DA-010) sets this to a real cache over its own strand, or sets
  /// @ref executor so the slot is lazily built over it on first query. Default-null and no `executor` set ->
  /// a DataAccess handle simply skips registration (a clean no-op - the manual refresh path still works), so
  /// existing DataAccess read tests are unaffected. `mutable` so the lazy build works from the const query.
  mutable std::shared_ptr<ua::client::detail::SemanticChangeCache> semanticChangeCache;

  [[nodiscard]] std::shared_ptr<const ua::client::NamespaceTable> namespace_table() const override
  {
    return namespaceTable;
  }

  void post_to_executor(std::function<void()> work) override
  {
    if (executor)
    {
      boost::asio::post(executor, std::move(work));
      return;
    }
    work();  // no executor configured: run inline (single-threaded test convenience)
  }

  [[nodiscard]] ua::client::detail::ConnectionState state() const override
  {
    return connectionState;
  }

  [[nodiscard]] std::shared_ptr<ua::client::detail::EventSubscriberImpl> event_subscriber() const override
  {
    return eventSubscriber;
  }

  [[nodiscard]] std::shared_ptr<ua::client::detail::TypeResolver> type_resolver() const override
  {
    return typeResolver;  // W2 wrappers under test do not exercise the resolver; default-null.
  }

  [[nodiscard]] std::shared_ptr<ua::client::detail::SubscriptionFactoryOps>
    subscription_factory() const override
  {
    return subscriptionFactory;
  }

  [[nodiscard]] std::shared_ptr<ua::client::detail::SemanticChangeCache>
    semantic_change_cache() const override
  {
    // Lazily build a real, empty cache over `executor` (a settable test strand) when a test wired one but did
    // not pre-set the slot; when neither is set the slot stays null and DataAccess registration is a no-op.
    if (!semanticChangeCache && executor)
    {
      semanticChangeCache =
        ua::client::detail::SemanticChangeCache::create(boost::asio::make_strand(executor), ua::Logger{});
    }
    return semanticChangeCache;
  }
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_FAKE_CONNECTION_OPS_H
