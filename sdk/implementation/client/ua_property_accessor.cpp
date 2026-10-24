// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_property_accessor.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_browse_drain_guard.h"
#include "ua_client_answer_status.h"
#include "ua_error_detail.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view connClosedSource = "client.tier2.property.connection_closed";
constexpr std::string_view readSource = "client.tier2.property.read_property";
constexpr std::string_view pathSource = "client.tier2.property.read_property_path";

/// Posts @p result to @p executor for a callback (callbacks always run on the executor); inline when no
/// executor is set (a moved-from accessor's inert path).
template<typename Result>
void deliver(
  const boost::asio::any_io_executor& executor, std::function<void(Result)> callback, Result result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Reads @p nodeId's Value Attribute, delivering the single @ref ua::DataValue (or a Bad Result chaining the
/// wire detail under @p source) on the executor. @p interface is held strong for the round-trip.
void read_value(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  boost::asio::any_io_executor executor, std::string source, std::function<void(DataValueResult)> callback)
{
  ua::ReadValueId readValue;
  readValue.node_id() = std::move(nodeId);
  readValue.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(readValue));

  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->read_async(std::move(request),
    [lockedWireOps = std::move(lockedWireOps),
      executor,
      source = std::move(source),
      callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        deliver<DataValueResult>(
          executor, std::move(callback), DataValueResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (empty-results
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<DataValueResult>(executor,
          std::move(callback),
          DataValueResult{serviceResult,
            ua::make_error_detail("PropertyReadServiceFault",
              "the Property Value Read returned a service-level fault",
              source,
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver<DataValueResult>(executor,
          std::move(callback),
          DataValueResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail(
              "PropertyReadEmpty", "the server returned a Good Read response with no result", source)});
        return;
      }
      // The DataValue is delivered whole; the ServiceResult is the status of the Result holding it, so a Good
      // subcode or an Uncertain code of it reaches the caller.
      deliver<DataValueResult>(executor, std::move(callback), ua::detail::held(results[0], serviceResult));
    });
}

/// The children accumulated from a one-level Browse (across all continuation pages).
using ReferenceList = std::vector<ua::ReferenceDescription>;

/// Builds a continuing (non-release) BrowseNext for @p continuationPoint.
ua::BrowseNextRequest make_browse_next(const ua::ContinuationPoint& continuationPoint)
{
  ua::BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(continuationPoint);
  return request;
}

/// Continuation of @ref browse_children: drains the remaining continuation pages via BrowseNext, appending
/// references into @p accumulated, until the server returns an empty continuation point (it releases the
/// continuation point on exhaustion). @p interface is held strong; @p done is invoked inline.
void drain_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  std::shared_ptr<ReferenceList> accumulated, ua::ContinuationPoint continuationPoint, std::string source,
  std::function<void(ua::Result<ReferenceList>)> done,
  std::shared_ptr<ua::client::detail::BrowseDrainGuard> guard = {})
{
  if (!guard)
  {
    guard = std::make_shared<ua::client::detail::BrowseDrainGuard>(
      source, ua::client::detail::BrowseDrainLimits{}, accumulated->size());
  }
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_next_async(make_browse_next(continuationPoint),
    [lockedWireOps = std::move(lockedWireOps),
      accumulated = std::move(accumulated),
      source = std::move(source),
      done = std::move(done),
      guard](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      // The SDK picks the child it reads next from these References, so only a Good answer is used: an
      // Uncertain one is refused (ReferencesAnswerUncertain), as a Bad one fails the walk.
      if (!response.is_good())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::answer_refused(response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseNextResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("PropertyBrowseNextServiceFault",
            "a BrowseNext continuing the Property Browse returned a service-level fault",
            source,
            serviceResult)});
        return;
      }
      auto& results = response.value().results();
      if (!results.empty() && results[0].status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          results[0].status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (results.empty() || results[0].status_code().is_bad())
      {
        const ua::StatusCode status =
          results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code();
        done(ua::Result<ReferenceList>{status,
          ua::make_error_detail(
            "PropertyBrowseNextFailed", "a BrowseNext continuing the Property Browse failed", source)});
        return;
      }
      // CL-VIEW-005: the page is admitted before its references are kept; a self-loop or an exhausted
      // budget ends the drain (a budget refusal releases the server's continuation point best-effort).
      if (auto admitted = guard->admit_page(results[0]); admitted.is_bad())
      {
        ua::client::detail::release_continuation_point_best_effort(
          *lockedWireOps, results[0].continuation_point());
        done(ua::Result<ReferenceList>{admitted.status_code(), admitted.shared_detail()});
        return;
      }
      for (const auto& reference : results[0].references())
      {
        accumulated->push_back(reference);
      }
      if (!results[0].continuation_point().empty())
      {
        drain_children(std::move(lockedWireOps),
          std::move(accumulated),
          results[0].continuation_point(),
          std::move(source),
          std::move(done),
          guard);
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

/// Browses @p nodeId one level along @p referenceType and accumulates EVERY child reference across all
/// continuation pages (so a Property on page 2+ is not silently dropped, nor the server continuation point
/// leaked). Delivers the full reference list (or a Bad Result) inline. @p interface is held strong for the
/// walk.
void browse_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  ua::ReferenceTypeId referenceType, std::string source, std::function<void(ua::Result<ReferenceList>)> done)
{
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = std::move(nodeId);
  browseDescription.browse_direction() = ua::BrowseDirection::Forward;
  browseDescription.reference_type_id() = ua::NodeId{std::uint16_t{0}, referenceType};
  browseDescription.include_subtypes() = true;
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::BrowseName);
  ua::BrowseRequest browse;
  browse.nodes_to_browse().push_back(std::move(browseDescription));

  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_async(std::move(browse),
    [lockedWireOps = std::move(lockedWireOps), source = std::move(source), done = std::move(done)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      // The SDK picks the child it reads next from these References, so only a Good answer is used: an
      // Uncertain one is refused (ReferencesAnswerUncertain), as a Bad one fails the walk.
      if (!response.is_good())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::answer_refused(response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("PropertyBrowseServiceFault",
            "the one-level Property Browse returned a service-level fault",
            source,
            serviceResult)});
        return;
      }
      auto& results = response.value().results();
      if (!results.empty() && results[0].status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          results[0].status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (results.empty() || results[0].status_code().is_bad())
      {
        const ua::StatusCode status =
          results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code();
        done(ua::Result<ReferenceList>{status,
          ua::make_error_detail("PropertyBrowseFailed", "the one-level Property Browse failed", source)});
        return;
      }
      auto accumulated = std::make_shared<ReferenceList>();
      for (const auto& reference : results[0].references())
      {
        accumulated->push_back(reference);
      }
      if (!results[0].continuation_point().empty())
      {
        drain_children(std::move(lockedWireOps),
          std::move(accumulated),
          results[0].continuation_point(),
          std::move(source),
          std::move(done));
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

/// Browses @p nodeId one level along @p referenceType (across all pages), matches the ns0 @p browseName, and
/// delivers the matched child's local NodeId (or `Bad_NotFound` when no child matches / the Browse fails) via
/// @p done on @p executor. @p interface is held strong for the round-trips.
void browse_match_child(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  ua::ReferenceTypeId referenceType, BrowseName browseName, boost::asio::any_io_executor executor,
  std::string source, std::function<void(ua::Result<ua::NodeId>)> done)
{
  browse_children(std::move(lockedWireOps),
    std::move(nodeId),
    referenceType,
    source,
    [browseName = std::move(browseName), executor, source, done = std::move(done)](
      ua::Result<ReferenceList> references) mutable
    {
      if (!references.is_good())
      {
        deliver<ua::Result<ua::NodeId>>(executor,
          std::move(done),
          ua::Result<ua::NodeId>{references.status_code(), references.shared_detail()});
        return;
      }
      const std::string_view wanted = static_cast<std::string_view>(browseName.name());
      const std::uint16_t wantedNs = browseName.namespace_index();
      for (const auto& reference : references.value())
      {
        const ua::QualifiedName& candidate = reference.browse_name();
        if (candidate.namespace_index() == wantedNs &&
            static_cast<std::string_view>(candidate.name()) == wanted)
        {
          deliver<ua::Result<ua::NodeId>>(
            executor, std::move(done), ua::Result<ua::NodeId>{reference.node_id().node_id()});
          return;
        }
      }
      // CL-AC-022: no child Property matched the requested BrowseName -> Bad_NotFound.
      deliver<ua::Result<ua::NodeId>>(executor,
        std::move(done),
        ua::Result<ua::NodeId>{ua::Status::BadNotFound,
          ua::make_error_detail(
            "PropertyNotFound", "no child Property matched the requested BrowseName", source)});
    });
}

/// Walks @p path segment-by-segment via a hierarchical one-level Browse (starting from @p nodeId), then Reads
/// the resolved final node's Value Attribute. @p index is the next segment to resolve.
void resolve_path(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  std::shared_ptr<std::vector<BrowseName>> path, std::size_t index, boost::asio::any_io_executor executor,
  std::function<void(DataValueResult)> callback)
{
  if (index >= path->size())
  {
    read_value(
      std::move(lockedWireOps), std::move(nodeId), executor, std::string{pathSource}, std::move(callback));
    return;
  }
  browse_match_child(lockedWireOps,
    std::move(nodeId),
    ua::ReferenceTypeId::HierarchicalReferences,
    (*path)[index],
    executor,
    std::string{pathSource},
    [lockedWireOps, path, index, executor, callback = std::move(callback)](
      ua::Result<ua::NodeId> matched) mutable
    {
      if (!matched.is_good())
      {
        deliver<DataValueResult>(
          executor, std::move(callback), DataValueResult{matched.status_code(), matched.shared_detail()});
        return;
      }
      resolve_path(std::move(lockedWireOps),
        std::move(matched).value(),
        std::move(path),
        index + 1,
        executor,
        std::move(callback));
    });
}

}  // namespace

PropertyAccessor::PropertyAccessor(ua::NodeId nodeId, std::weak_ptr<detail::WireOps> wireOps,
  std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger)
  : mNodeId(std::move(nodeId)), mWireOps(std::move(wireOps)), mSupportOps(std::move(supportOps)),
    mExecutor(std::move(executor)), mLogger(std::move(logger))
{}

void PropertyAccessor::read_property_async(
  BrowseName propertyName, std::function<void(DataValueResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    deliver<DataValueResult>(mExecutor,
      std::move(callback),
      DataValueResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("PropertyConnectionGone",
          "the Connection was dropped before the Property read could be issued",
          std::string{connClosedSource})});
    return;
  }
  const boost::asio::any_io_executor executor = mExecutor;
  browse_match_child(lockedWireOps,
    mNodeId,
    ua::ReferenceTypeId::HasProperty,
    std::move(propertyName),
    executor,
    std::string{readSource},
    [lockedWireOps, executor, callback = std::move(callback)](ua::Result<ua::NodeId> matched) mutable
    {
      if (!matched.is_good())
      {
        deliver<DataValueResult>(
          executor, std::move(callback), DataValueResult{matched.status_code(), matched.shared_detail()});
        return;
      }
      read_value(std::move(lockedWireOps),
        std::move(matched).value(),
        executor,
        std::string{readSource},
        std::move(callback));
    });
}

void PropertyAccessor::read_property_uncached_async(
  BrowseName propertyName, std::function<void(DataValueResult)> callback) noexcept
{
  // No-op cache split until the AddressSpaceCache (section 8.7) is wired: behaves identically to the
  // cache-honouring default read_property_async for now (documented on the header).
  read_property_async(std::move(propertyName), std::move(callback));
}

void PropertyAccessor::read_property_path_async(
  std::vector<BrowseName> path, std::function<void(DataValueResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    deliver<DataValueResult>(mExecutor,
      std::move(callback),
      DataValueResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("PropertyConnectionGone",
          "the Connection was dropped before the Property path read could be issued",
          std::string{connClosedSource})});
    return;
  }
  if (path.empty())
  {
    // An empty path resolves to this node's own Value Attribute.
    read_value(std::move(lockedWireOps), mNodeId, mExecutor, std::string{pathSource}, std::move(callback));
    return;
  }
  resolve_path(std::move(lockedWireOps),
    mNodeId,
    std::make_shared<std::vector<BrowseName>>(std::move(path)),
    0,
    mExecutor,
    std::move(callback));
}

ua::NodeId PropertyAccessor::node_id() const noexcept
{
  return mNodeId;
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form returns the DataValue of a Good answer of `try_*_sync(...)`
// (ua::detail::good_data_value, which puts a Good subcode of the Result on the DataValue's status), and the
// non-throwing form arms the existing `*_async`. No operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

ua::DataValue PropertyAccessor::read_property_sync(BrowseName propertyName)
{
  return ua::detail::good_data_value(try_read_property_sync(std::move(propertyName)));
}

ua::Result<ua::DataValue> PropertyAccessor::try_read_property_sync(BrowseName propertyName) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(mExecutor,
    [this, propertyName = std::move(propertyName)](auto completion) mutable
    { read_property_async(std::move(propertyName), std::move(completion)); });
}

ua::DataValue PropertyAccessor::read_property_path_sync(std::vector<BrowseName> path)
{
  return ua::detail::good_data_value(try_read_property_path_sync(std::move(path)));
}

ua::Result<ua::DataValue> PropertyAccessor::try_read_property_path_sync(std::vector<BrowseName> path) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(mExecutor,
    [this, path = std::move(path)](auto completion) mutable
    { read_property_path_async(std::move(path), std::move(completion)); });
}

ua::DataValue PropertyAccessor::read_property_uncached_sync(BrowseName propertyName)
{
  return ua::detail::good_data_value(try_read_property_uncached_sync(std::move(propertyName)));
}

ua::Result<ua::DataValue> PropertyAccessor::try_read_property_uncached_sync(BrowseName propertyName) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(mExecutor,
    [this, propertyName = std::move(propertyName)](auto completion) mutable
    { read_property_uncached_async(std::move(propertyName), std::move(completion)); });
}

}  // namespace ua::client
