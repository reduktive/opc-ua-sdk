// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_server_diagnostics_access.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_connection_ops.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_server_diagnostics_access_state.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_subscription_factory.h"
#include "ua_to_result.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/post.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-BASEDIAG-002/003).
constexpr std::string_view connClosedSource = "client.tier2.server_diagnostics.connection_closed";
constexpr std::string_view summarySource = "client.tier2.server_diagnostics.summary";
constexpr std::string_view sessionsSource = "client.tier2.server_diagnostics.sessions";
constexpr std::string_view sessionsSecuritySource = "client.tier2.server_diagnostics.sessions_security";
constexpr std::string_view subscriptionsSource = "client.tier2.server_diagnostics.subscriptions";
constexpr std::string_view samplingSource = "client.tier2.server_diagnostics.sampling_intervals";
constexpr std::string_view setEnabledFlagSource = "client.tier2.server_diagnostics.set_enabled_flag";
constexpr std::string_view subscribeSessionsSource = "client.tier2.server_diagnostics.subscribe_sessions";
constexpr std::string_view subscribeSubscriptionsSource =
  "client.tier2.server_diagnostics.subscribe_subscriptions";
// The disabled-advisory tag shared by the wire-boundary log and ConnectionObserver fan-out.
constexpr std::string_view disabledAdvisorySource = "client.tier2.server_diagnostics.diagnostics_disabled";

constexpr std::uint32_t valueAttribute = static_cast<std::uint32_t>(ua::AttributeId::Value);

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

/// @return A single-node Read of @p nodeId's Value Attribute.
ua::ReadValueId make_value_read(const ua::NodeId& nodeId)
{
  ua::ReadValueId readValue;
  readValue.node_id() = nodeId;
  readValue.attribute_id() = valueAttribute;
  return readValue;
}

// The well-known ns0 ServerDiagnostics node ids (section 8.18.1.c). Built from the generated VariableId enum.
ua::NodeId summary_node()
{
  return ua::NodeId{ua::VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary};
}

ua::NodeId enabled_flag_node()
{
  return ua::NodeId{ua::VariableId::Server_ServerDiagnostics_EnabledFlag};
}

/// Decodes a Variant holding an array of ExtensionObjects into a vector of the generated @p T DataType (via
/// the codec's already-decoded `RefStructure<Structure>` payload). A null / empty Variant decodes to an empty
/// vector (the server exposes no entries  -  e.g. while diagnostics are disabled). A non-structure-array
/// value, or an element that is not a @p T, is an undecodable server response and yields `nullopt`.
template<typename T>
std::optional<std::vector<T>> decode_structure_array(const ua::Variant& value)
{
  std::vector<T> out;
  if (value.empty())
  {
    return out;  // no value set: no diagnostic entries
  }
  if (!value.is_array_of_structure())
  {
    return std::nullopt;  // a non-structure-array Value is undecodable for a diagnostics array
  }
  try
  {
    const auto& array = value.as<ua::Array<ua::RefStructure<ua::Structure>>>();
    for (const auto& element : array.payload())
    {
      const auto* entry = dynamic_cast<const T*>(element.get());
      if (!entry)
      {
        return std::nullopt;  // heterogeneous / wrong element type -> decode error
      }
      out.push_back(*entry);
    }
    return out;
  }
  catch (...)
  {
    return std::nullopt;  // not an Array<RefStructure<Structure>>
  }
}

/// The shared array-read plumbing for the four diagnostic-array reads (CL-BASEDIAG-003). Locks the interface,
/// consults the EnabledFlag TTL cache and (when stale/absent) batches an EnabledFlag Read alongside the array
/// Read, decodes the array of @p T ExtensionObjects, refreshes the cache, logs the disabled-advisory when the
/// flag resolves `false`, and delivers the array result on the executor REGARDLESS of the flag. @p cacheState
/// is strong-captured across the in-flight Read so a temporary accessor still completes (section 8.18.2).
template<typename T>
void run_array_read(const std::weak_ptr<detail::WireOps>& wireWeak,
  const std::weak_ptr<detail::SupportOps>& supportWeak,
  const std::shared_ptr<detail::ServerDiagnosticsCacheState>& cacheState,
  const boost::asio::any_io_executor& executor, ua::Logger logger,
  std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory, ua::NodeId arrayNode,
  std::string_view source, std::function<void(ua::Result<std::vector<T>>)> callback)
{
  using R = ua::Result<std::vector<T>>;
  auto lockedWireOps = wireWeak.lock();
  auto support = supportWeak.lock();
  if (!lockedWireOps || !support)
  {
    deliver<R>(executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("ServerDiagnosticsConnectionGone",
          "the Connection was dropped before the diagnostic-array read could be issued",
          std::string{connClosedSource})});
    return;
  }

  // Consult the TTL cache. When absent / stale (>60 s) the EnabledFlag is batched alongside the array Read so
  // the disabled-advisory decision uses a fresh value without a second round-trip (CL-BASEDIAG-003 step 1).
  std::optional<bool> cachedFlag = cacheState->fresh_value();
  const bool needFlagRead = !cachedFlag.has_value();

  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_value_read(arrayNode));
  if (needFlagRead)
  {
    read.nodes_to_read().push_back(make_value_read(enabled_flag_node()));
  }

  lockedWireOps->read_async(std::move(read),
    [cacheState,
      executor,
      logger = std::move(logger),
      emitAdvisory = std::move(emitAdvisory),
      needFlagRead,
      cachedFlag,
      source,
      callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{response.status_code(),
            ua::make_error_detail("ServerDiagnosticsArrayReadFailed",
              "the Read of a ServerDiagnostics diagnostic array failed",
              std::string{source},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (count-mismatch
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{serviceResult,
            ua::make_error_detail("ServerDiagnosticsArrayServiceFault",
              "the Read of a ServerDiagnostics diagnostic array returned a service-level fault",
              std::string{source},
              serviceResult)});
        return;
      }
      auto& results = response.value().results();
      const std::size_t expected = 1U + static_cast<std::size_t>(needFlagRead ? 1 : 0);
      // W1  -  a batched Read MUST return exactly one DataValue per ReadValueId; a length mismatch means the
      // response cannot be positionally stitched (array vs EnabledFlag), so reject it rather than mis-map.
      if (results.size() != expected)
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadUnexpectedError,
            ua::make_error_detail("ServerDiagnosticsArrayReadCountMismatch",
              "the diagnostic-array Read returned a result count different from the number of ReadValueIds "
              "sent",
              std::string{source},
              response.shared_detail())});
        return;
      }

      // H1  -  inspect the per-node DataValue quality BEFORE decoding the value. A Bad per-node status (e.g.
      // Bad_UserAccessDenied) means the array is not to be trusted: surface it as an outer Bad Result
      // carrying that status + a source-tagged detail (chaining any inner detail off the per-node StatusCode)
      // rather than decoding a null/empty value into a Good/empty vector and silently swallowing the Bad
      // status. Mirrors the summary path's Bad-quality handling.
      if (const auto& perNodeStatus = results[0].status(); perNodeStatus && perNodeStatus->is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{*perNodeStatus,
            ua::make_error_detail("ServerDiagnosticsArrayBadQuality",
              "a ServerDiagnostics diagnostic-array DataValue carried a Bad quality",
              std::string{source},
              *perNodeStatus)});
        return;
      }

      // The array comes with the Read's code: the ServiceResult and the array DataValue's status combined
      // (ua::detail::combined_status), so a Good subcode or an Uncertain code reaches the caller. A code that
      // is not Good on a null value is answered without an array.
      const ua::StatusCode answered =
        ua::detail::combined_status(ua::detail::combined_status(response.status_code(), serviceResult),
          results[0].status().value_or(ua::StatusCode{ua::Status::Good}));
      if (!answered.is_good() && results[0].value().empty())
      {
        deliver<R>(executor, std::move(callback), R{answered});
        return;
      }

      auto decoded = decode_structure_array<T>(results[0].value());
      if (!decoded)
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadDecodingError,
            ua::make_error_detail("ServerDiagnosticsArrayDecodeFailed",
              "a diagnostic-array element did not decode to the expected DataType",
              std::string{source})});
        return;
      }

      // Resolve the effective EnabledFlag (freshly-read when batched; cached otherwise) and refresh the
      // cache.
      // The SDK decides on the flag itself (the cache, the advisory), so only a flag read Good is used; one
      // that is Uncertain or Bad is treated as unread.
      std::optional<bool> enabledFlag = cachedFlag;
      if (needFlagRead && results[1].status().value_or(ua::StatusCode{ua::Status::Good}).is_good())
      {
        if (auto flag = results[1].value().to<bool>(); flag.is_good())
        {
          enabledFlag = flag.value();
          cacheState->store(flag.value());
        }
      }

      // CL-BASEDIAG-003 step 3: a freshly-read false flag produces a rich observer advisory and the existing
      // wire-boundary log. The data is still delivered (step 4): data + advisory, not a blocked call. Cached
      // false values do not re-fire, so a burst inside the 60 s TTL cannot spam either surface.
      if (needFlagRead && enabledFlag.has_value() && !*enabledFlag)
      {
        logger.warning(
          "ServerDiagnostics is disabled on the server (EnabledFlag=false); the returned diagnostic array "
          "may be empty or stale [{}]",
          disabledAdvisorySource);
        try
        {
          if (emitAdvisory)
          {
            emitAdvisory(ua::make_error_detail("ServerDiagnosticsDisabled",
              "ServerDiagnostics is disabled; the returned diagnostic array may be empty or stale",
              std::string{disabledAdvisorySource}));
          }
        }
        catch (...)
        {
          const ua::StatusCode advisoryFailure = ua::exception_to_status_code(std::current_exception());
          logger.warning("ServerDiagnostics disabled advisory delivery failed; array delivery continues [{}]",
            ua::format(advisoryFailure));
        }
      }

      deliver<R>(executor, std::move(callback), ua::detail::held(std::move(*decoded), answered));
    });
}

/// The shared subscribe-over-poll plumbing for the two streaming reads (CL-BASEDIAG-004). Reaches the
/// subscription-factory interface, creates a managed Subscription + a data-change MonitoredItem on @p
/// arrayNode (server-chosen sampling, `StatusValueTimestamp` `DataChangeFilter`), decodes each notification's
/// array of
/// @p T ExtensionObjects and delivers it to @p onArray, and returns the unified persist-on-drop MonitoredItem
/// (or a bad Result) on the executor. A gone interface completes `Bad_ConnectionClosed`. @p factory is
/// strong-held across the create->monitor chain so a temporary accessor still completes.
template<typename T>
void run_subscribe(const std::weak_ptr<detail::SupportOps>& supportWeak,
  const boost::asio::any_io_executor& executor, ua::NodeId arrayNode, std::string_view source,
  std::function<void(std::vector<T>)> onArray, std::function<void(ua::client::MonitoredItemResult)> callback)
{
  using R = ua::client::MonitoredItemResult;
  auto support = supportWeak.lock();
  std::shared_ptr<detail::SubscriptionFactoryOps> factory =
    support ? support->subscription_factory() : nullptr;
  if (!factory)
  {
    deliver<R>(executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("ServerDiagnosticsConnectionGone",
          "the Connection was dropped before the diagnostic-array subscription could be created",
          std::string{source})});
    return;
  }

  factory->create_subscription_managed_async(/*publishingInterval=*/0.0,
    /*publishingEnabled=*/true,
    [factory,
      executor,
      arrayNode = std::move(arrayNode),
      source,
      onArray = std::move(onArray),
      callback = std::move(callback)](ua::Result<detail::SubscriptionCreated> created) mutable
    {
      if (!created.has_value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{created.status_code(),
            ua::make_error_detail("ServerDiagnosticsSubscribeCreateFailed",
              "the CreateSubscription for a diagnostic-array stream failed",
              std::string{source},
              created.shared_detail())});
        return;
      }

      // CL-BASEDIAG-004: a data-change MonitoredItem on the array Variable, server-chosen sampling
      // (samplingIntervalMs = 0.0), with a StatusValueTimestamp DataChangeFilter.
      ua::client::MonitorRequest request;
      request.nodeId = arrayNode;
      request.attribute = ua::AttributeId::Value;
      request.samplingIntervalMs = 0.0;
      ua::DataChangeFilter dataChangeFilter;
      dataChangeFilter.trigger() = ua::DataChangeTrigger::StatusValueTimestamp;
      request.filter = std::move(dataChangeFilter);

      // Each notification's array Value is decoded and delivered to the user's array callback (runs on the
      // executor - the factory delivers the DataChangeEvent there). The void(vector) callback has no place
      // for a status: it receives the array of every notification that holds one, whatever its status, and
      // a Bad notification (whose value is null, OPC 10000-4 7.11.1) or an undecodable one is not delivered.
      auto onData = [onArray](ua::client::DataChangeEvent event)
      {
        if (event.value.status().value_or(ua::StatusCode{ua::Status::Good}).is_bad())
        {
          return;
        }
        if (auto decoded = decode_structure_array<T>(event.value.value()))
        {
          onArray(std::move(*decoded));
        }
      };

      // The item's Result carries the Subscription's code and the item's combined (ua::detail::carried).
      factory->monitor_data_change_async(created.value().subscriptionId,
        std::move(request),
        std::move(onData),
        [callback = std::move(callback), subscriptionStatus = created.status_code()](
          ua::client::MonitoredItemResult miResult) mutable
        { callback(ua::detail::carried(std::move(miResult), subscriptionStatus)); });
    });
}

}  // namespace

// ============================================================================
// ServerDiagnosticsCacheState (the EnabledFlag TTL cache)
// ============================================================================

namespace detail
{

bool ServerDiagnosticsCacheState::fresh_at(ua::DateTime current) const
{
  if (!cachedFlag)
  {
    return false;
  }
  const auto age = current.value() - cachedFlag->readAt.value();
  // Fresh iff the cached read is between 0 and the 60 s TTL old. A negative age (clock moved backwards) is
  // treated as stale so a re-read re-establishes a sane timestamp.
  const auto ttl = std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(std::chrono::seconds{60});
  return age >= ua::datetime::OneHundredNanoSeconds{0} && age <= ttl;
}

std::optional<bool> ServerDiagnosticsCacheState::fresh_value()
{
  std::lock_guard<std::mutex> lock{mutex};
  if (cachedFlag && fresh_at(now()))
  {
    return cachedFlag->value;
  }
  return std::nullopt;
}

void ServerDiagnosticsCacheState::store(bool value)
{
  std::lock_guard<std::mutex> lock{mutex};
  cachedFlag = CachedEnabledFlag{value, now()};
}

}  // namespace detail

// ============================================================================
// ServerDiagnosticsAccessor
// ============================================================================

ServerDiagnosticsAccessor::ServerDiagnosticsAccessor(std::weak_ptr<detail::WireOps> wireOps,
  std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger,
  std::shared_ptr<detail::ServerDiagnosticsCacheState> cacheState,
  std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory)
  : mWireOps(std::move(wireOps)), mSupportOps(std::move(supportOps)), mExecutor(std::move(executor)),
    mLogger(std::move(logger)), mCacheState(std::move(cacheState)), mEmitAdvisory(std::move(emitAdvisory))
{}

void ServerDiagnosticsAccessor::summary_async(
  std::function<void(ServerDiagnosticsSummaryResult)> callback) noexcept
{
  using R = ServerDiagnosticsSummaryResult;
  auto lockedWireOps = mWireOps.lock();
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  if (!lockedWireOps || !support)
  {
    deliver<R>(executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("ServerDiagnosticsConnectionGone",
          "the Connection was dropped before the ServerDiagnosticsSummary read could be issued",
          std::string{connClosedSource})});
    return;
  }
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_value_read(summary_node()));
  lockedWireOps->read_async(std::move(read),
    [executor, callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{response.status_code(),
            ua::make_error_detail("ServerDiagnosticsSummaryReadFailed",
              "the Read of Server.ServerDiagnostics.ServerDiagnosticsSummary failed",
              std::string{summarySource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (count-mismatch
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{serviceResult,
            ua::make_error_detail("ServerDiagnosticsSummaryServiceFault",
              "the Read of the ServerDiagnosticsSummary returned a service-level fault",
              std::string{summarySource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      // W1  -  the single-node summary Read MUST return exactly one DataValue. An empty response (no result)
      // or an over-return (more than one) cannot be positionally trusted, so reject it rather than blindly
      // decoding results[0]  -  uniform with the array read's count guard.
      if (results.size() != 1U)
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadUnexpectedError,
            ua::make_error_detail("ServerDiagnosticsSummaryReadCountMismatch",
              "the summary Read returned a result count other than the single expected DataValue",
              std::string{summarySource})});
        return;
      }
      const ua::DataValue& dataValue = results[0];
      // CL-BASEDIAG-002  -  a Bad summary DataValue quality surfaces via the Result (unlike the StateVariable
      // two-layer model, the summary is a single structured value: a Bad quality means the value is not to be
      // trusted).
      if (const auto& status = dataValue.status(); status && status->is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{*status,
            ua::make_error_detail("ServerDiagnosticsSummaryBadQuality",
              "the ServerDiagnosticsSummary DataValue carried a Bad quality",
              std::string{summarySource})});
        return;
      }
      // The summary comes with the Read's code: the ServiceResult and the DataValue's status combined
      // (ua::detail::combined_status), so a Good subcode or an Uncertain code reaches the caller. A code that
      // is not Good on a null value is answered without a summary.
      const ua::StatusCode answered =
        ua::detail::combined_status(ua::detail::combined_status(response.status_code(), serviceResult),
          dataValue.status().value_or(ua::StatusCode{ua::Status::Good}));
      if (!answered.is_good() && dataValue.value().empty())
      {
        deliver<R>(executor, std::move(callback), R{answered});
        return;
      }
      const auto* summary = dataValue.value().try_as<ua::ServerDiagnosticsSummaryDataType>();
      if (!summary)
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadDecodingError,
            ua::make_error_detail("ServerDiagnosticsSummaryDecodeFailed",
              "the ServerDiagnosticsSummary Value did not decode to a ServerDiagnosticsSummaryDataType",
              std::string{summarySource})});
        return;
      }
      deliver<R>(executor, std::move(callback), ua::detail::held(*summary, answered));
    });
}

void ServerDiagnosticsAccessor::sessions_async(
  std::function<void(SessionDiagnosticsArrayResult)> callback) noexcept
{
  run_array_read<ua::SessionDiagnosticsDataType>(mWireOps,
    mSupportOps,
    mCacheState,
    mExecutor,
    mLogger,
    mEmitAdvisory,
    ua::NodeId{ua::VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray},
    sessionsSource,
    std::move(callback));
}

void ServerDiagnosticsAccessor::sessions_security_async(
  std::function<void(SessionSecurityDiagnosticsArrayResult)> callback) noexcept
{
  run_array_read<ua::SessionSecurityDiagnosticsDataType>(mWireOps,
    mSupportOps,
    mCacheState,
    mExecutor,
    mLogger,
    mEmitAdvisory,
    ua::NodeId{
      ua::VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
    sessionsSecuritySource,
    std::move(callback));
}

void ServerDiagnosticsAccessor::subscriptions_async(
  std::function<void(SubscriptionDiagnosticsArrayResult)> callback) noexcept
{
  run_array_read<ua::SubscriptionDiagnosticsDataType>(mWireOps,
    mSupportOps,
    mCacheState,
    mExecutor,
    mLogger,
    mEmitAdvisory,
    ua::NodeId{ua::VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray},
    subscriptionsSource,
    std::move(callback));
}

void ServerDiagnosticsAccessor::sampling_intervals_async(
  std::function<void(SamplingIntervalDiagnosticsArrayResult)> callback) noexcept
{
  run_array_read<ua::SamplingIntervalDiagnosticsDataType>(mWireOps,
    mSupportOps,
    mCacheState,
    mExecutor,
    mLogger,
    mEmitAdvisory,
    ua::NodeId{ua::VariableId::Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray},
    samplingSource,
    std::move(callback));
}

void ServerDiagnosticsAccessor::set_enabled_flag_async(
  bool enabled, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  if (!lockedWireOps || !support)
  {
    deliver<ua::VoidResult>(executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("ServerDiagnosticsConnectionGone",
          "the Connection was dropped before the EnabledFlag write could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto cacheState = mCacheState;
  ua::WriteValue writeValue;
  writeValue.node_id() = enabled_flag_node();
  writeValue.attribute_id() = valueAttribute;
  writeValue.value() = ua::DataValue{ua::Variant{enabled}};
  ua::WriteRequest request;
  request.nodes_to_write().push_back(std::move(writeValue));
  lockedWireOps->write_async(std::move(request),
    [cacheState, executor, enabled, callback = std::move(callback)](
      ua::Result<ua::WriteResponse> response) mutable
    {
      if (!response.has_value())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{response.status_code(),
            ua::make_error_detail("ServerDiagnosticsSetEnabledFlagFailed",
              "the Write of Server.ServerDiagnostics.EnabledFlag failed",
              std::string{setEnabledFlagSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the WriteResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{serviceResult,
            ua::make_error_detail("ServerDiagnosticsSetEnabledFlagServiceFault",
              "the Write of the ServerDiagnostics EnabledFlag returned a service-level fault",
              std::string{setEnabledFlagSource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("ServerDiagnosticsSetEnabledFlagEmpty",
              "the server returned a Good Write response with no result",
              std::string{setEnabledFlagSource})});
        return;
      }
      const ua::StatusCode status = results[0];
      if (status.is_bad())
      {
        // CL-BASEDIAG-003  -  the server's per-write status (e.g. Bad_UserAccessDenied) surfaces verbatim,
        // chained beneath the set-enabled-flag source. The cache is NOT updated on a rejected write.
        deliver<ua::VoidResult>(executor,
          std::move(callback),
          ua::VoidResult{status,
            ua::make_error_detail("ServerDiagnosticsSetEnabledFlagRejected",
              "the server rejected the EnabledFlag write",
              std::string{setEnabledFlagSource},
              response.shared_detail())});
        return;
      }
      // The write's result is the ServiceResult and the write's status combined
      // (ua::detail::combined_status), so a Good subcode or an Uncertain code reaches the caller. Only a Good
      // write refreshes the TTL cache with the written value: an Uncertain one may not have taken effect.
      const ua::StatusCode answered = ua::detail::combined_status(
        ua::detail::combined_status(response.status_code(), serviceResult), status);
      if (answered.is_good())
      {
        cacheState->store(enabled);
      }
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{answered});
    });
}

void ServerDiagnosticsAccessor::subscribe_sessions_async(
  SessionsArrayCallback onSessions, std::function<void(ua::client::MonitoredItemResult)> callback) noexcept
{
  run_subscribe<ua::SessionDiagnosticsDataType>(mSupportOps,
    mExecutor,
    ua::NodeId{ua::VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray},
    subscribeSessionsSource,
    std::move(onSessions),
    std::move(callback));
}

void ServerDiagnosticsAccessor::subscribe_subscriptions_async(SubscriptionsArrayCallback onSubscriptions,
  std::function<void(ua::client::MonitoredItemResult)> callback) noexcept
{
  run_subscribe<ua::SubscriptionDiagnosticsDataType>(mSupportOps,
    mExecutor,
    ua::NodeId{ua::VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray},
    subscribeSubscriptionsSource,
    std::move(onSubscriptions),
    std::move(callback));
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form returns the value of a Good `try_*_sync(...)` result
// (ua::detail::good_value) and throws otherwise, and the non-throwing form arms the existing `*_async`. No
// operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

ua::ServerDiagnosticsSummaryDataType ServerDiagnosticsAccessor::summary_sync()
{
  return ua::detail::good_value(try_summary_sync());
}

ua::Result<ua::ServerDiagnosticsSummaryDataType> ServerDiagnosticsAccessor::try_summary_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::ServerDiagnosticsSummaryDataType>>(
    mExecutor, [this](auto completion) mutable { summary_async(std::move(completion)); });
}

std::vector<ua::SessionDiagnosticsDataType> ServerDiagnosticsAccessor::sessions_sync()
{
  return ua::detail::good_value(try_sessions_sync());
}

ua::Result<std::vector<ua::SessionDiagnosticsDataType>>
  ServerDiagnosticsAccessor::try_sessions_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::SessionDiagnosticsDataType>>>(
    mExecutor, [this](auto completion) mutable { sessions_async(std::move(completion)); });
}

std::vector<ua::SessionSecurityDiagnosticsDataType> ServerDiagnosticsAccessor::sessions_security_sync()
{
  return ua::detail::good_value(try_sessions_security_sync());
}

ua::Result<std::vector<ua::SessionSecurityDiagnosticsDataType>>
  ServerDiagnosticsAccessor::try_sessions_security_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::SessionSecurityDiagnosticsDataType>>>(
    mExecutor, [this](auto completion) mutable { sessions_security_async(std::move(completion)); });
}

std::vector<ua::SubscriptionDiagnosticsDataType> ServerDiagnosticsAccessor::subscriptions_sync()
{
  return ua::detail::good_value(try_subscriptions_sync());
}

ua::Result<std::vector<ua::SubscriptionDiagnosticsDataType>>
  ServerDiagnosticsAccessor::try_subscriptions_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::SubscriptionDiagnosticsDataType>>>(
    mExecutor, [this](auto completion) mutable { subscriptions_async(std::move(completion)); });
}

std::vector<ua::SamplingIntervalDiagnosticsDataType> ServerDiagnosticsAccessor::sampling_intervals_sync()
{
  return ua::detail::good_value(try_sampling_intervals_sync());
}

ua::Result<std::vector<ua::SamplingIntervalDiagnosticsDataType>>
  ServerDiagnosticsAccessor::try_sampling_intervals_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::SamplingIntervalDiagnosticsDataType>>>(
    mExecutor, [this](auto completion) mutable { sampling_intervals_async(std::move(completion)); });
}

void ServerDiagnosticsAccessor::set_enabled_flag_sync(bool enabled)
{
  try_set_enabled_flag_sync(std::move(enabled)).value();
}

ua::VoidResult ServerDiagnosticsAccessor::try_set_enabled_flag_sync(bool enabled) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(mExecutor,
    [this, enabled = std::move(enabled)](auto completion) mutable
    { set_enabled_flag_async(std::move(enabled), std::move(completion)); });
}

ua::client::MonitoredItem ServerDiagnosticsAccessor::subscribe_sessions_sync(SessionsArrayCallback onSessions)
{
  return ua::detail::good_value(try_subscribe_sessions_sync(std::move(onSessions)));
}

ua::Result<ua::client::MonitoredItem> ServerDiagnosticsAccessor::try_subscribe_sessions_sync(
  SessionsArrayCallback onSessions) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::client::MonitoredItem>>(mExecutor,
    [this, onSessions = std::move(onSessions)](auto completion) mutable
    { subscribe_sessions_async(std::move(onSessions), std::move(completion)); });
}

ua::client::MonitoredItem ServerDiagnosticsAccessor::subscribe_subscriptions_sync(
  SubscriptionsArrayCallback onSubscriptions)
{
  return ua::detail::good_value(try_subscribe_subscriptions_sync(std::move(onSubscriptions)));
}

ua::Result<ua::client::MonitoredItem> ServerDiagnosticsAccessor::try_subscribe_subscriptions_sync(
  SubscriptionsArrayCallback onSubscriptions) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::client::MonitoredItem>>(mExecutor,
    [this, onSubscriptions = std::move(onSubscriptions)](auto completion) mutable
    { subscribe_subscriptions_async(std::move(onSubscriptions), std::move(completion)); });
}

}  // namespace ua::client
