// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_subscriptions_pipeline.h"

#include "ua_array.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_error_detail.h"
#include "ua_on_strand.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_status.h"
#include "ua_status_to_string.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::client::detail
{

namespace
{
// Upper bound on Republish requests in a single gap drain: a non-conforming server that always returns a
// retained message (never Bad_MessageNotAvailable) would otherwise spin Republish -> Republish forever
// (request amplification). Generous: real retransmission queues are far smaller.
constexpr std::size_t maxRepublishDrainIterations = 4096;
constexpr std::size_t oversizedRecoveryAttemptCap = 3;

// Source tags for the manufactured poll-read boundary failures (the design specification - a boundary failure
// the SDK synthesises must be source-tagged so the ErrorDetail identifies where it originated). They mirror
// the ConnectionOpsShim's `connection_gone` tag convention.
constexpr std::string_view pollReadResultCountMismatchSource =
  "client.tier1.subscriptions_pipeline.poll_read.result_count_mismatch";
constexpr std::string_view pollReadPipelineGoneSource =
  "client.tier1.subscriptions_pipeline.poll_read.pipeline_gone";

// CL-SUB-021: widen any built-in numeric scalar the Variant may hold to `double` for deadband arithmetic.
// `Variant::to<T>()` is EXACT-type extraction (no numeric coercion), so a single `to<double>()` would only
// match a `Double`-typed value and silently miss `Float` (the dominant analog type) and every integer width.
// Try each built-in numeric type in turn and widen. Returns nullopt for a non-numeric (e.g. String/Boolean)
// value, which then falls through to a plain inequality comparison.
std::optional<double> fallback_numeric_as_double(const ua::Variant& value)
{
  if (const auto asDouble = value.to<double>(); asDouble.is_good())
    return asDouble.value();
  if (const auto asFloat = value.to<float>(); asFloat.is_good())
    return static_cast<double>(asFloat.value());
  if (const auto asInt64 = value.to<std::int64_t>(); asInt64.is_good())
    return static_cast<double>(asInt64.value());
  if (const auto asUInt64 = value.to<std::uint64_t>(); asUInt64.is_good())
    return static_cast<double>(asUInt64.value());
  if (const auto asInt32 = value.to<std::int32_t>(); asInt32.is_good())
    return static_cast<double>(asInt32.value());
  if (const auto asUInt32 = value.to<std::uint32_t>(); asUInt32.is_good())
    return static_cast<double>(asUInt32.value());
  if (const auto asInt16 = value.to<std::int16_t>(); asInt16.is_good())
    return static_cast<double>(asInt16.value());
  if (const auto asUInt16 = value.to<std::uint16_t>(); asUInt16.is_good())
    return static_cast<double>(asUInt16.value());
  if (const auto asSByte = value.to<std::int8_t>(); asSByte.is_good())
    return static_cast<double>(asSByte.value());
  if (const auto asByte = value.to<std::uint8_t>(); asByte.is_good())
    return static_cast<double>(asByte.value());
  return std::nullopt;
}

// CL-SUB-021: has the polled Value changed vs the last-dispatched Value, respecting the DataChangeFilter's
// deadband? An Absolute deadband on a numeric value reports iff |delta| > deadbandValue; otherwise
// (DeadbandType None, or a non-numeric value) any inequality is a change. PercentDeadband never reaches here
//  -  it is refused at attach time (no server-side EURange in fallback), so only None/Absolute are evaluated.
bool fallback_value_changed_beyond_deadband(
  const ua::DataChangeFilter& filter, const ua::Variant& last, const ua::Variant& current)
{
  if (filter.deadband_type() == static_cast<std::uint32_t>(ua::DeadbandType::Absolute))
  {
    const auto lastNumber = fallback_numeric_as_double(last);
    const auto currentNumber = fallback_numeric_as_double(current);
    if (lastNumber && currentNumber)
    {
      // NaN handling (section 3.1: a naive "any NaN -> change" both latches AND over-reports). `std::abs(x -
      // NaN)` is always NaN, so `> deadband` is always false  -  a value operand transitioning to/from NaN
      // must be handled explicitly or it would latch the item into permanent silence. A transition is a
      // change IFF the NaN-ness differs (enter or exit the NaN/bad state): NaN -> finite MUST report (so the
      // item recovers and can never latch), finite -> NaN MUST report (the value went bad), but NaN -> NaN is
      // UNCHANGED and must NOT re-report every poll (spec/MI DataChange dedup  -  the SDK's own server
      // reports a stuck NaN once).
      const bool lastNan = std::isnan(*lastNumber);
      const bool currentNan = std::isnan(*currentNumber);
      if (lastNan || currentNan)
      {
        return lastNan != currentNan;
      }
      // A usable AbsoluteDeadband is finite AND non-negative. A non-finite band (NaN/inf) makes
      // `|delta| > deadband` always FALSE (latches the item silent); a NEGATIVE band makes it always TRUE
      // (`|0| > -1`  -  an UNCHANGED value dispatches every poll, a dedup violation). A conformant server
      // rejects a negative deadband with Bad_DeadbandFilterInvalid, but a server-less fallback has no server
      // to reject it  -  so treat any unusable band as no deadband (any value inequality is a change;
      // unchanged stays silent) rather than trust it. (The attach-time validator only finiteness/range-checks
      // Percent, not Absolute  -  a follow-up may add the Absolute check there; this is the fallback-scoped
      // remedy.)
      const double deadband = filter.deadband_value();
      if (!std::isfinite(deadband) || deadband < 0.0)
      {
        return *currentNumber != *lastNumber;
      }
      return std::abs(*currentNumber - *lastNumber) > deadband;
    }
    // A non-numeric value carrying an Absolute deadband is nonsensical; fall through to a plain inequality.
  }
  return !(last == current);
}

// CL-SUB-021: does a polled DataValue pass the item's DataChangeFilter vs its last-dispatched value? The
// Trigger selects which components are compared: Status (StatusCode only); StatusValue (+ Value,
// deadband-gated); StatusValueTimestamp (+ SourceTimestamp). A Status change reports under EVERY trigger. The
// first sample (no last value) always dispatches (a change from nothing).
bool fallback_data_change_passes(
  const ua::DataChangeFilter& filter, const std::optional<ua::DataValue>& last, const ua::DataValue& current)
{
  if (!last)
  {
    return true;  // first poll: always a change
  }
  if (last->status() != current.status())
  {
    return true;  // a StatusCode change reports under every trigger mode
  }
  if (filter.trigger() == ua::DataChangeTrigger::Status)
  {
    return false;  // Status-only: nothing but a StatusCode change reports
  }
  if (fallback_value_changed_beyond_deadband(filter, last->value(), current.value()))
  {
    return true;
  }
  if (filter.trigger() == ua::DataChangeTrigger::StatusValue)
  {
    return false;  // StatusValue: a timestamp-only change does NOT report
  }
  // StatusValueTimestamp: a SourceTimestamp change also reports.
  return last->source_timestamp() != current.source_timestamp();
}
}  // namespace

std::shared_ptr<SubscriptionsPipeline> SubscriptionsPipeline::create(boost::asio::any_io_executor executor,
  std::shared_ptr<SubscriptionOps> subOps, std::shared_ptr<WireOps> wireOps,
  std::shared_ptr<SupportOps> support, ua::Logger logger,
  std::function<void(std::uint32_t)> onSubscriptionEventLoss,
  std::function<void(ua::NodeId)> onSemanticsChanged,
  std::function<void(std::uint32_t, ua::StatusCode)> onSubscriptionTerminated,
  std::function<void(std::uint32_t, ua::StatusCode, std::uint32_t)> onOversizedRecoveryExhausted,
  std::function<void(std::uint32_t, std::uint32_t, std::uint32_t)> onPublishGap)
{
  return std::shared_ptr<SubscriptionsPipeline>(new SubscriptionsPipeline(std::move(executor),
    std::move(subOps),
    std::move(wireOps),
    std::move(support),
    std::move(logger),
    std::move(onSubscriptionEventLoss),
    std::move(onSemanticsChanged),
    std::move(onSubscriptionTerminated),
    std::move(onOversizedRecoveryExhausted),
    std::move(onPublishGap)));
}

SubscriptionsPipeline::SubscriptionsPipeline(boost::asio::any_io_executor executor,
  std::shared_ptr<SubscriptionOps> subOps, std::shared_ptr<WireOps> wireOps,
  std::shared_ptr<SupportOps> support, ua::Logger logger,
  std::function<void(std::uint32_t)> onSubscriptionEventLoss,
  std::function<void(ua::NodeId)> onSemanticsChanged,
  std::function<void(std::uint32_t, ua::StatusCode)> onSubscriptionTerminated,
  std::function<void(std::uint32_t, ua::StatusCode, std::uint32_t)> onOversizedRecoveryExhausted,
  std::function<void(std::uint32_t, std::uint32_t, std::uint32_t)> onPublishGap)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)),
    mDeliveryStrand(boost::asio::make_strand(mExecutor)), mSubOps(std::move(subOps)),
    mWireOps(std::move(wireOps)), mSupport(std::move(support)), mLogger(std::move(logger)),
    mOnSubscriptionEventLoss(std::move(onSubscriptionEventLoss)),
    mOnSemanticsChanged(std::move(onSemanticsChanged)),
    mOnSubscriptionTerminated(std::move(onSubscriptionTerminated)),
    mOnOversizedRecoveryExhausted(std::move(onOversizedRecoveryExhausted)),
    mOnPublishGap(std::move(onPublishGap)), mPump(*this)
{
  publish_info();
}

void SubscriptionsPipeline::add_subscription_async(
  std::uint32_t subscriptionId, double publishingInterval, std::uint32_t maxNotificationsPerPublish) noexcept
{
  // This overload deliberately provides fire-and-forget registration; its caller has no use for the result.
  add_subscription_async(
    subscriptionId, publishingInterval, maxNotificationsPerPublish, [](ua::VoidResult) {});
}

void SubscriptionsPipeline::add_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
  std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadShutdown},
    [subscriptionId, publishingInterval, maxNotificationsPerPublish](
      SubscriptionsPipeline& self, std::function<void(ua::VoidResult)> completion)
    {
      // fresh SequenceTracker (expects seq 1); retain the publishing interval for a session-CHANGED recreate
      auto [entry, inserted] = self.mSubscriptions.try_emplace(subscriptionId);
      entry->second.publishingInterval = publishingInterval;
      entry->second.maxNotificationsPerPublish = maxNotificationsPerPublish;
      // CL-SUB-009: a new Subscription lifts a Bad_NoSubscription drain-and-hold  -  resume the pump so
      // Publishes flow again for it. resume() clears the stale outstanding count left over from the hold and
      // refills to target. Only when actually held: a normal add while the pump is already Running is a no-op
      // here (the pump keeps running).
      if (self.mPublishHeldNoSubscription)
      {
        self.mPublishHeldNoSubscription = false;
        self.mPump.resume();
      }
      self.publish_info();
      completion(ua::VoidResult{});
    })();
}

void SubscriptionsPipeline::engage_fallback_subscription_async(
  std::uint32_t subscriptionId, double publishingInterval, bool publishingEnabled) noexcept
{
  // This overload deliberately provides fire-and-forget fallback setup; its caller has no use for the result.
  engage_fallback_subscription_async(
    subscriptionId, publishingInterval, publishingEnabled, [](ua::VoidResult) {});
}

void SubscriptionsPipeline::engage_fallback_subscription_async(std::uint32_t subscriptionId,
  double publishingInterval, bool publishingEnabled, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadShutdown},
    [subscriptionId, publishingInterval, publishingEnabled](
      SubscriptionsPipeline& self, std::function<void(ua::VoidResult)> completion)
    {
      // A fallback Subscription has NO server counterpart, so it lives in mFallbackSubs (NOT mSubscriptions)
      //  -  taking NO part in the Publish pump, sequence tracking, or reconnect recovery, and never colliding
      // with a server-assigned id. Register it and arm the driver.
      auto& entry = self.mFallbackSubs[subscriptionId];
      entry.interval = publishingInterval;
      entry.deliver = publishingEnabled;
      entry.pollInFlight = false;
      self.arm_fallback_timer(subscriptionId);
      self.publish_info();
      completion(ua::VoidResult{});
    })();
}

void SubscriptionsPipeline::arm_fallback_timer(std::uint32_t subscriptionId)
{
  const auto found = mFallbackSubs.find(subscriptionId);
  if (found == mFallbackSubs.end())
  {
    return;
  }
  // Floor a non-positive interval to a conservative cadence so the fixed-grid timer always makes progress.
  const double intervalMs = found->second.interval > 0.0 ? found->second.interval : 100.0;
  const auto period = std::chrono::milliseconds{static_cast<std::int64_t>(intervalMs)};
  // The notifier runs on mStrand (schedule_every dispatches through it), so it is strand-serialised with
  // every other pipeline turn. Weak self-capture: a fire after this pipeline is destroyed locks a dead weak
  // and does nothing; move-assigning/erasing the timer cancels it, and ua::Timer cancellation is final, so
  // a queued fire is suppressed rather than delivered.
  std::weak_ptr<SubscriptionsPipeline> weakSelf =
    std::static_pointer_cast<SubscriptionsPipeline>(shared_from_this());
  found->second.timer = ua::Timer::schedule_every(mStrand,
    period,
    [weakSelf, subscriptionId](boost::system::error_code error)
    {
      if (error)
      {
        return;  // an Asio-level failure ends the schedule; cancellation never reaches here at all
      }
      if (const auto self = weakSelf.lock())
      {
        self->poll_fallback_tick(subscriptionId);
      }
    });
}

void SubscriptionsPipeline::poll_fallback_tick(std::uint32_t subscriptionId)
{
  const auto found = mFallbackSubs.find(subscriptionId);
  if (found == mFallbackSubs.end())
  {
    return;  // the Subscription was removed (its timer is cancelled on erase)  -  nothing to poll
  }
  if (!found->second.deliver)
  {
    return;  // publishing disabled (create-time publishingEnabled=false): a fallback Subscription polls
             // nothing
  }
  if (found->second.pollInFlight)
  {
    // A prior poll is still outstanding (a slow/stalled server, or an interval shorter than the round-trip).
    // The fixed-grid timer re-arms independently of poll completion, so skip this tick rather than pile up
    // overlapping bulk Reads (request amplification against a struggling server).
    return;
  }

  // Gather this Subscription's Reporting items in a STABLE order so the Read results align positionally to
  // the client handles they must be delivered to. Non-Reporting (Sampling/Disabled) items are
  // polled-but-undelivered per the monitoring-mode contract, so they are simply not read.
  std::vector<std::uint32_t> handles;
  std::vector<ua::ReadValueId> reads;
  for (const auto& [clientHandle, item] : mMonitoredItems)
  {
    if (item.subscriptionId != subscriptionId || item.monitoringMode != ua::MonitoringMode::Reporting)
    {
      continue;
    }
    ua::ReadValueId readValue;
    readValue.node_id() = item.nodeId;
    readValue.attribute_id() = static_cast<ua::IntegerId>(item.attribute);
    if (item.indexRange)
    {
      readValue.index_range() = *item.indexRange;
    }
    handles.push_back(clientHandle);
    reads.push_back(std::move(readValue));
  }

  if (reads.empty())
  {
    return;  // no Reporting items  -  poll_read_async would no-op, but skip the hop entirely
  }

  found->second.pollInFlight = true;
  std::weak_ptr<SubscriptionsPipeline> weakSelf =
    std::static_pointer_cast<SubscriptionsPipeline>(shared_from_this());
  poll_read_async(std::move(reads),
    [weakSelf = std::move(weakSelf), subscriptionId, handles = std::move(handles)](
      ua::Result<std::vector<ua::DataValue>> result) mutable
    {
      const auto self = weakSelf.lock();
      if (!self)
      {
        return;
      }
      // poll_read_async delivers this completion on the RAW executor (never the strand, per WireOps), so it
      // runs OFF the strand. mFallbackSubs + the delivery dispatch are strand-only, so re-hop onto mStrand
      // first. post_borrowing_or_else weak-tracks the pipeline: a concurrent teardown drops the completion.
      ua::async::post_borrowing_or_else(
        self.get(),
        self->mStrand,
        self->mLogger,
        [subscriptionId, handles = std::move(handles), result = std::move(result)](
          SubscriptionsPipeline& pipeline) mutable
        {
          // Clear the in-flight guard so the next tick can poll (the Subscription may have been removed
          // mid-poll, in which case there is nothing to clear  -  guard the lookup).
          if (const auto entry = pipeline.mFallbackSubs.find(subscriptionId);
              entry != pipeline.mFallbackSubs.end())
          {
            entry->second.pollInFlight = false;
          }
          if (!result.has_value())
          {
            // A transient poll failure  -  the next tick retries. Do NOT deliver a partial/misaligned page,
            // but do not silently swallow the ErrorDetail at this wire boundary (the design specification):
            // surface it as an advisory log carrying the status + any chained detail.
            pipeline.mLogger.debug(
              {{"subscription_id", std::to_string(subscriptionId)},
                {"status", ua::to_string(result.status_code().as_status())},
                {"detail", result.shared_detail() ? ua::to_string(*result.shared_detail()) : std::string{}}},
              "polled-Read fallback poll failed; the next tick retries");
            return;
          }
          auto& values = result.value();
          if (values.size() != handles.size())
          {
            return;  // defensive: a count mismatch means the page cannot be positionally stitched  -  drop it
          }
          for (std::size_t index = 0; index < handles.size(); ++index)
          {
            const auto item = pipeline.mMonitoredItems.find(handles[index]);
            if (item == pipeline.mMonitoredItems.end())
            {
              continue;  // the item was removed between the tick's gather and this completion
            }
            auto& entry = item->second;
            // CL-SUB-021: apply the item's DataChangeFilter client-side (a fallback has no server-side
            // filtering). No filter (monostate) or an AggregateFilter (unsupported in fallback) -> dispatch
            // every value; a DataChangeFilter dispatches only a change (Trigger + AbsoluteDeadband).
            bool dispatch = true;
            if (const auto* dataChangeFilter = std::get_if<ua::DataChangeFilter>(&entry.filter))
            {
              dispatch = fallback_data_change_passes(*dataChangeFilter, entry.lastPolledValue, values[index]);
            }
            if (dispatch)
            {
              entry.lastPolledValue = values[index];  // remember the DISPATCHED value for the next comparison
              pipeline.deliver_notification_async(handles[index], std::move(values[index]));
            }
          }
        },
        []() {})();
    });
}

void SubscriptionsPipeline::update_publishing_interval_async(
  std::uint32_t subscriptionId, double publishingInterval) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [subscriptionId, publishingInterval](SubscriptionsPipeline& self)
    {
      // CL-SUB-013: a successful ModifySubscription changed the server's publishing interval  -  refresh the
      // RETAINED interval so a session-CHANGED recreate rebuilds the Subscription at the modified interval,
      // not the stale create-time one (otherwise the reconnect silently reverts the user's modify). Update
      // ONLY (never creates a record): a modify targets an existing Subscription; if the record is already
      // gone locally (e.g. a concurrent drop) there is nothing to retain.
      const auto entry = self.mSubscriptions.find(subscriptionId);
      if (entry != self.mSubscriptions.end())
      {
        entry->second.publishingInterval = publishingInterval;
        self.publish_info();
      }
    },
    []() {})();
}

void SubscriptionsPipeline::remove_subscription_async(std::uint32_t subscriptionId) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [subscriptionId](SubscriptionsPipeline& self)
    {
      // N2 (defensive): if this Subscription is participating in an in-flight recovery, service the barrier
      // for it before erasing - otherwise mRecoveryPending would never reach 0 and the recover step would
      // stall to its deadline. (Currently not reachable - a user delete is dispatch-gated until Active while
      // recovery runs during Reconnecting - but cheap to make robust to any future reordering.)
      if (const auto it = self.mSubscriptions.find(subscriptionId);
          it != self.mSubscriptions.end() && it->second.inRecovery)
      {
        self.finish_drain_terminal(
          it->second, ua::StatusCode{ua::Status::Good});  // removed = clean-for-barrier
      }
      self.mSubscriptions.erase(subscriptionId);
      // CL-SUB-019: a fallback (server-less) Subscription lives in mFallbackSubs; erasing the entry cancels
      // its poll timer (the Timer destructor; a queued fire is suppressed, not delivered). A given id is
      // in exactly one of the two maps, so this is a no-op for a real Subscription.
      self.mFallbackSubs.erase(subscriptionId);
      // Cascade: a subscription delete implicitly deletes all its monitored items server-side (OPC UA
      // 10000-4 section 5.13.8), so drop their callbacks here too - otherwise they leak and
      // monitoredItemCount stays inflated for the pipeline's lifetime.
      for (auto item = self.mMonitoredItems.begin(); item != self.mMonitoredItems.end();)
      {
        item = (item->second.subscriptionId == subscriptionId) ? self.mMonitoredItems.erase(item)
                                                               : std::next(item);
      }
      self.resize_pump();  // CL-SUB-015: the cascade purge may shrink the pump target
    },
    []() {})();
}

void SubscriptionsPipeline::remove_monitored_item_async(std::uint32_t clientHandle) noexcept
{
  // This overload deliberately provides fire-and-forget deregistration; its caller has no use for the result.
  remove_monitored_item_async(clientHandle, [](ua::VoidResult) {});
}

void SubscriptionsPipeline::remove_monitored_item_async(
  std::uint32_t clientHandle, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadShutdown},
    [clientHandle](SubscriptionsPipeline& self, std::function<void(ua::VoidResult)> completion)
    {
      self.mMonitoredItems.erase(clientHandle);
      self.resize_pump();  // CL-SUB-015: a removed item may shrink the pump target
      completion(ua::VoidResult{});
    })();
}

void SubscriptionsPipeline::start_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](SubscriptionsPipeline& self)
    {
      // Starting the pump supersedes any Bad_NoSubscription hold: clear the flag so it cannot linger true
      // while the pump is Running (section 3.1 note) - the flag means "held Idle after Bad_NoSubscription"
      // only.
      self.mPublishHeldNoSubscription = false;
      self.mPump.start();  // fills to target -> issue_publish -> send_publish
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::stop_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](SubscriptionsPipeline& self)
    {
      self.mPump.stop();
      self.mPublishHeldNoSubscription = false;  // a reconnect/close supersedes a Bad_NoSubscription hold
      // Cancel every polled-Read fallback driver (CL-SUB-019): a stop means the Connection is closing or
      // reconnecting, so stop polling on the dead/old channel. The timer is cancelled (a queued fire is
      // inert) but the fallback entry + its interval are RETAINED (mFallbackSubs), so a resume re-arms the
      // driver on the fresh channel. Removing the Subscription (remove_subscription_async) is the terminal
      // teardown. A poll in flight on the dead channel is abandoned; the next tick re-polls.
      for (auto& [id, entry] : self.mFallbackSubs)
      {
        entry.timer = {};
        entry.pollInFlight = false;
      }
      // Purge any in-flight recovery barrier: a stop means the Connection is entering Reconnecting (a fresh
      // recover step will re-arm it) or closing (its FSM done is inert). Discard without firing so a stale
      // barrier cannot linger and mis-fire against a later recovery (its per-sub inRecovery is reset too).
      self.clear_recovery();
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::resume_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](SubscriptionsPipeline& self)
    {
      // A reconnect resume supersedes any Bad_NoSubscription hold (the fresh channel + recreated
      // subscriptions restart publishing on their own path).
      self.mPublishHeldNoSubscription = false;
      // Re-arm every polled-Read fallback driver (CL-SUB-019) so a fallback Subscription keeps delivering
      // across a reconnect (it polls the fresh channel). arm_fallback_timer mutates only the entry's timer
      // member, not the map's key set, so this direct range-for is safe.
      for (auto& [id, entry] : self.mFallbackSubs)
      {
        self.arm_fallback_timer(id);
      }
      if (self.mSubscriptions.empty())
      {
        return;  // no subscriptions to publish for - leave the pump idle
      }
      // A pump resume is only meaningful for real (server-backed) subscriptions; a pipeline holding ONLY
      // fallback subscriptions has nothing for the pump to do, but resume() is a harmless no-op there.
      self.mPump.resume();  // clear the stale outstanding count and refill on the fresh channel
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::on_publish_no_subscription_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](SubscriptionsPipeline& self)
    {
      // CL-SUB-009 / Part 4 section 5.13.8.1: the last Subscription was deleted and the server de-queued the
      // outstanding Publishes with Bad_NoSubscription. Drain-and-HOLD, but ONLY when the client genuinely has
      // no Subscriptions left (section 3.1 CRITICAL): a Bad_NoSubscription that arrives while a LIVE
      // Subscription exists is either a STALE de-queued Publish from a prior delete that reordered past a
      // fresh CreateSubscription (the hold post and the add/start posts originate on DIFFERENT strands - the
      // publish completion on the connection strand, the create completion on the executor - so asio gives no
      // relative ordering) or a spurious/misbehaving server response. Holding on it would stop the pump with
      // no path back to Running, permanently starving the live Subscription. So gate on
      // mSubscriptions.empty():
      //   - empty  -> HOLD (stop the pump; a subsequent add_subscription_async resumes it). Idempotent.
      //   - non-empty -> do NOT hold; account the response against the pump (decrement + refill) so the live
      //     Subscription keeps pumping. (The connection callback SKIPS feed_publish_response for a
      //     Bad_NoSubscription, so without this the outstanding count would leak and stall the pump anyway.)
      if (self.mSubscriptions.empty())
      {
        self.mPublishHeldNoSubscription = true;
        self.mPump.stop();
      }
      else
      {
        self.mPump.on_publish_response(/*tooManyPublishRequests=*/false);
      }
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::on_publish_response_async(std::uint32_t subscriptionId,
  std::uint32_t sequenceNumber, bool hasNotifications, bool hasAvailableSequenceNumbers,
  bool tooManyPublishRequests, std::function<void(SequenceClass)> onClassified,
  std::optional<ua::StatusCode> terminalStatus) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [subscriptionId,
      sequenceNumber,
      hasNotifications,
      hasAvailableSequenceNumbers,
      tooManyPublishRequests,
      onClassified = std::move(onClassified),
      terminalStatus = std::move(terminalStatus)](SubscriptionsPipeline& self)
    {
      // Demux to the Subscription and classify the sequence number. Queue the ack BEFORE the pump
      // refills, so the ack rides the refill Publish. Default to Invalid so an unknown/spoofed
      // subscriptionId (no matching Subscription) reports Invalid and its payload is dropped by the caller.
      SequenceClass classification = SequenceClass::Invalid;
      const auto subscription = self.mSubscriptions.find(subscriptionId);
      if (subscription != self.mSubscriptions.end())
      {
        auto& state = subscription->second;
        // A decoded Publish proves the current message limit is usable. End the prior oversized incident so
        // a later, independent incident receives a fresh three-step recovery budget.
        state.oversizedRecoveryAttempts = 0;
        state.oversizedRecoveryHandedOff = false;
        classification = state.tracker.classify(sequenceNumber);
        const bool transferred = terminalStatus.has_value() &&
                                 terminalStatus->as_status() == ua::Status::GoodSubscriptionTransferred;
        const bool terminate = terminalStatus.has_value() &&
                               (terminalStatus->as_status() == ua::Status::BadTimeout || transferred) &&
                               should_deliver(classification);
        if (terminate)
        {
          // CL-SUB-008: Bad_Timeout means the Server has already closed this Subscription, and
          // Good_SubscriptionTransferred that another Session now owns it (OPC 10000-4 7.25.4); either way it
          // no longer exists on this Session. Cleanup is part of this SAME strand turn and precedes pump
          // refill, so neither a pending acknowledgement nor any later Republish completion can reference or
          // revive the id. The application receives the Server's code, a Good one included, unchanged.
          if (state.inRecovery)
          {
            self.finish_drain_terminal(state, *terminalStatus);
          }

          ua::DataValue terminatedValue;
          terminatedValue.status() = ua::StatusCode{ua::Status::BadSubscriptionIdInvalid,
            ua::make_error_detail("SubscriptionTerminated",
              transferred ? "the Server transferred the Subscription to another Session"
                          : "the Server closed the Subscription after its lifetime expired",
              "client.subscriptions.status_change",
              *terminalStatus)};
          for (auto item = self.mMonitoredItems.begin(); item != self.mMonitoredItems.end();)
          {
            if (item->second.subscriptionId != subscriptionId)
            {
              ++item;
              continue;
            }
            ua::async::post_owning(&self,
              self.mDeliveryStrand,
              self.mLogger,
              [callback = item->second.callback, value = terminatedValue](SubscriptionsPipeline&) mutable
              { callback(std::move(value)); })();
            item = self.mMonitoredItems.erase(item);
          }
          // Release stale queued/latch state first. The terminal NotificationMessage itself still carries
          // the Part 4 section 5.13.1.1 acknowledgement obligation when availableSequenceNumbers is
          // non-empty, so queue exactly that one acknowledgement after the purge.
          self.mAckQueue.remove_subscription(subscriptionId);
          if (hasAvailableSequenceNumbers)
          {
            self.mAckQueue.acknowledge(
              subscriptionId, sequenceNumber, /*serverReportedAvailableSequenceNumbers=*/true);
          }
          self.mSubscriptions.erase(subscriptionId);
          if (self.mSubscriptions.empty())
          {
            // No server-backed Subscription remains. Send at most one final Publish to carry the terminal
            // NotificationMessage acknowledgement, then hold immediately rather than start another refill.
            if (self.mAckQueue.pending() != 0)
            {
              self.issue_publish();
            }
            self.mPublishHeldNoSubscription = true;
            self.mPump.stop();
            self.publish_info();
          }
          else
          {
            self.resize_pump();
          }
          if (self.mOnSubscriptionTerminated)
          {
            self.mOnSubscriptionTerminated(subscriptionId, *terminalStatus);
          }
        }
        else if (classification == SequenceClass::InOrder && hasNotifications)
        {
          // A real, in-order message: advance past it and queue its ack.
          state.tracker.advance_past(sequenceNumber);
          self.mAckQueue.acknowledge(subscriptionId, sequenceNumber, hasAvailableSequenceNumbers);
        }
        // An in-order KEEP-ALIVE (empty NotificationMessage, !hasNotifications) is deliberately left alone:
        // per OPC UA 10000-4 section 5.13.5 it carries the sequence number of the NEXT NotificationMessage to
        // be sent (a peek, not an allocation), so advancing/acking it would consume the number the next REAL
        // message reuses - which would then classify Duplicate and be dropped (silent data loss). Leaving
        // next_expected where it is keeps that reused number in-order so the real message is delivered.
        else if (classification == SequenceClass::Gap)
        {
          // Track the high-water sequence target the live Publish revealed (Finding 2 / CL-AC-003), whether
          // or not a drain is already running: a later live Publish at a HIGHER seq while draining bumps the
          // target the terminal is judged against. Wrap-safe: bump when gapTarget is unset (classify != Gap,
          // e.g. the initial 0) or when the new number is strictly AHEAD of it (signed 32-bit distance idiom,
          // matching SequenceTracker::classify  -  correct across the max->1 wrap).
          if (state.tracker.classify(state.gapTarget) != SequenceClass::Gap ||
              static_cast<std::int32_t>(sequenceNumber - state.gapTarget) > 0)
          {
            state.gapTarget = sequenceNumber;
          }
          if (!state.republishing)
          {
            state.republishIterations = 0;  // fresh drain: reset the iteration budget
            // One or more messages were missed: drain the gap via Republish before advancing (CL-SUB-002).
            state.republishing = true;
            const auto firstMissed = state.tracker.next_expected();
            // Report the gap to the application before the drain begins: whether Republish recovers the
            // messages or not, the client saw a discontinuity, and only the pipeline knows it.
            if (self.mOnPublishGap)
            {
              self.mOnPublishGap(subscriptionId, firstMissed, sequenceNumber);
            }
            self.mSubOps->republish(subscriptionId, firstMissed);
          }
        }
        // Duplicate / Invalid -> dropped (no ack, no dispatch).
      }
      self.mPump.on_publish_response(tooManyPublishRequests);  // pause/resume + refill (drains the ack)
      self.publish_info();
      // Report the classification back to the delivery site so it can gate dispatch (deliver only InOrder /
      // Gap, drop Duplicate / Invalid / unknown - CL-SUB-002). Still on the pipeline strand: this mirrors how
      // the republish drain calls deliver_notification_async from within its strand hop, so it is safe to
      // invoke here (the caller re-posts through deliver_notification_async); do NOT re-post.
      if (onClassified)
      {
        onClassified(classification);
      }
    },
    []() {})();
}

void SubscriptionsPipeline::on_publish_failure_async(ua::StatusCode status) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [status](SubscriptionsPipeline& self)
    {
      if (status.as_status() == ua::Status::BadResponseTooLarge)
      {
        // A failed Publish has no decodable Subscription id. Apply the conservative, deterministic recovery
        // to every live server-backed Subscription; fallback subscriptions have no server object and live in
        // a separate map, so they are naturally excluded.
        for (auto& [subscriptionId, state] : self.mSubscriptions)
        {
          self.begin_oversized_recovery(subscriptionId, state, status);
        }
      }
      // A server answers a Publish over its queue limit with a ServiceFault, which arrives here as a failed
      // Publish, not as a typed PublishResponse: OPC 10000-4 5.14.5.1 then forbids another Publish until an
      // outstanding one returns, so this is the pump's pause, not a failure to replace.
      self.mPump.on_publish_response(status.as_status() == ua::Status::BadTooManyPublishRequests);
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::begin_oversized_recovery(
  std::uint32_t subscriptionId, SubscriptionState& state, ua::StatusCode failure)
{
  if (state.oversizedRecoveryInFlight)
  {
    return;  // coalesce concurrent oversized completions while the one ModifySubscription is outstanding
  }
  if (state.oversizedRecoveryHandedOff)
  {
    return;  // one observer handoff per unresolved incident; do not flood on every doomed Publish
  }

  const std::uint32_t proposed = state.maxNotificationsPerPublish == 0
                                   ? 1
                                   : std::max<std::uint32_t>(1, state.maxNotificationsPerPublish / 2);
  if (state.maxNotificationsPerPublish == 1 || state.oversizedRecoveryAttempts >= oversizedRecoveryAttemptCap)
  {
    state.oversizedRecoveryHandedOff = true;
    if (mOnOversizedRecoveryExhausted)
    {
      mOnOversizedRecoveryExhausted(subscriptionId, failure, proposed);
    }
    return;
  }

  state.oversizedRecoveryInFlight = true;
  ++state.oversizedRecoveryAttempts;
  const std::uint64_t generation = ++state.oversizedRecoveryGeneration;
  const double publishingInterval = state.publishingInterval;
  std::weak_ptr<SubscriptionsPipeline> weakSelf =
    std::static_pointer_cast<SubscriptionsPipeline>(shared_from_this());
  mSubOps->adjust_max_notifications_per_publish(subscriptionId,
    publishingInterval,
    proposed,
    [weakSelf = std::move(weakSelf), subscriptionId, proposed, generation, failure](
      ua::VoidResult result) mutable
    {
      const auto self = weakSelf.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing_or_else(
        self.get(),
        self->mStrand,
        self->mLogger,
        [subscriptionId, proposed, generation, failure, result = std::move(result)](
          SubscriptionsPipeline& pipeline) mutable
        {
          const auto found = pipeline.mSubscriptions.find(subscriptionId);
          if (found == pipeline.mSubscriptions.end() ||
              found->second.oversizedRecoveryGeneration != generation)
          {
            return;  // removed/recreated/superseded Subscription: stale completion is inert
          }
          auto& current = found->second;
          current.oversizedRecoveryInFlight = false;
          // The Connection retains the new cap for every answer that is not Bad (an Uncertain answer without
          // a response arrives refused), so the pipeline applies it for the same answers.
          if (!result.is_bad())
          {
            current.maxNotificationsPerPublish = proposed;
            return;
          }

          // The automatic adjustment itself failed. Preserve the original oversized failure for the
          // observer decision and log the ModifySubscription failure with its independent rich detail so
          // neither chain is silently discarded at this wire boundary.
          pipeline.mLogger.warning(
            {{"subscription_id", std::to_string(subscriptionId)},
              {"status", ua::to_string(result.status_code().as_status())},
              {"detail", result.shared_detail() ? ua::to_string(*result.shared_detail()) : std::string{}}},
            "automatic oversized-message ModifySubscription failed; handing recovery to the observer");
          current.oversizedRecoveryHandedOff = true;
          if (pipeline.mOnOversizedRecoveryExhausted)
          {
            pipeline.mOnOversizedRecoveryExhausted(subscriptionId, failure, proposed);
          }
        },
        []() {})();
    });
}

void SubscriptionsPipeline::on_republish_response_async(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, ua::StatusCode status) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [subscriptionId, sequenceNumber, status](SubscriptionsPipeline& self)
    {
      const auto subscription = self.mSubscriptions.find(subscriptionId);
      if (subscription == self.mSubscriptions.end() || !subscription->second.republishing)
      {
        return;  // unknown Subscription, or not draining a gap - ignore
      }
      auto& state = subscription->second;
      if (status.is_good() && state.tracker.classify(sequenceNumber) == SequenceClass::InOrder)
      {
        state.oversizedRecoveryAttempts = 0;
        state.oversizedRecoveryHandedOff = false;
        // A retained message was recovered: acknowledge it and step the drain to the next number.
        state.tracker.advance_past(sequenceNumber);
        self.mAckQueue.acknowledge(subscriptionId, sequenceNumber, /*hasAvailable=*/true);
        if (++state.republishIterations >= maxRepublishDrainIterations)
        {
          // Iteration budget exhausted: a non-conforming server is not returning the terminator. Stop.
          const std::string subIdText = std::to_string(subscriptionId);
          const std::string iterText = std::to_string(state.republishIterations);
          self.mLogger.warning({{"subscription_id", subIdText}, {"iterations", iterText}},
            "Republish drain hit its iteration budget; ending drain (server never returned "
            "Bad_MessageNotAvailable)");
          state.republishing = false;
          // The cap-hit carries a Good status, so finish_drain_terminal treats it as clean-for-recovery
          // (N3): recovery proceeds rather than retrying - a cap-hit is a permanent per-reconnect property of
          // a non-conforming server, so retrying can never converge and would let it DoS the reconnect into
          // Failed. The loss was already logged just above.
          self.finish_drain_terminal(state, status);
          // Event-loss signal (Finding 2 / CL-AC-003): a non-conforming server that never returns the
          // terminator has forfeited sequence trust, so the drain cannot certify it caught up - fire
          // UNCONDITIONALLY. Fires on THIS strand (like onClassified), after finish_drain_terminal; the
          // signal is ORTHOGONAL to the clean/bad recovery decision above.
          if (self.mOnSubscriptionEventLoss)
          {
            self.mOnSubscriptionEventLoss(subscriptionId);
          }
        }
        else
        {
          self.mSubOps->republish(subscriptionId, state.tracker.next_expected());
        }
        self.publish_info();
        return;
      }

      // A non-Good status (or a Good-but-off-sequence reply) ends the drain. Match the terminators on the
      // status proper (as_status(), so info bits cannot defeat the branch) and never silently discard a
      // non-Good status or its ErrorDetail (the design specification).
      state.republishing = false;
      const ua::Status terminator = status.as_status();
      if (terminator == ua::Status::BadResponseTooLarge)
      {
        self.begin_oversized_recovery(subscriptionId, state, status);
      }
      // Finding 2 / CL-AC-003: was the reactive gap the drain set out to close EVER recovered? Judged at the
      // terminal against the high-water gapTarget, INDEPENDENT of the recovery barrier (a recovery drain
      // reset gapTarget to 0, so classify(0) == Invalid and this is false for it - the KEY CORRECTION: loss
      // is decidable only on the REACTIVE drain). A still-Gap classification means dropped messages survived
      // the drain (possibly a lost ConditionRefresh RefreshEnd) -> confirmed event loss.
      const bool unrecoveredGap = state.tracker.classify(state.gapTarget) == SequenceClass::Gap;
      bool goneSubscription = false;
      bool fireLoss = false;  // signal event loss on this terminal (Finding 2)
      if (terminator == ua::Status::BadMessageNotAvailable)
      {
        // The normal, clean terminator: the server's retransmission queue is fully drained. If the hole was
        // never closed the drain still LOST messages, so signal loss (orthogonal to the clean terminator).
        fireLoss = unrecoveredGap;
      }
      else if (terminator == ua::Status::BadSubscriptionIdInvalid)
      {
        // A3: the Subscription is gone server-side (its lifetime expired during the outage, or the reconnect
        // recreated the Session so the old id no longer exists - the common CL-RECONN-003 case). section 6.7
        // says the Client should then recreate it; recreate is not yet wired (the session-CHANGED branch).
        // REMOVE it here rather than leave it: a dead Subscription left in the pipeline would keep the pump
        // Publishing against it, inflate subscriptionCount/monitoredItemCount, and - since this is a clean
        // terminator for the barrier - let the recovery report a dead Subscription as "recovered". Log the
        // loss (its monitored items stop delivering until a future recreate) rather than hide it.
        const std::string subIdText = std::to_string(subscriptionId);
        self.mLogger.warning({{"subscription_id", subIdText}},
          "Republish returned Bad_SubscriptionIdInvalid: the Subscription no longer exists on the server; "
          "removing it (recreate not yet wired - its monitored items stop delivering)");
        goneSubscription = true;
      }
      else if (!status.is_good())
      {
        // Any other non-Good status (Bad OR Uncertain) mid-drain: end and log, surfacing the ErrorDetail so
        // it is not lost at this wire boundary; queued notifications may remain unrecovered.
        const std::string subIdText = std::to_string(subscriptionId);
        const std::string statusText = ua::to_string(terminator);
        const std::string detailText =
          status.shared_detail() ? ua::to_string(*status.shared_detail()) : std::string{};
        self.mLogger.warning({{"subscription_id", subIdText}, {"status", statusText}, {"detail", detailText}},
          "Republish drain ended on a non-terminator status; queued notifications may remain unrecovered");
      }
      else
      {
        // A Good but off-sequence reply (Duplicate/Invalid classification) - end the drain; unexpected
        // ordering, not a fault, so nothing to surface. But if the hole was never closed it is still a
        // confirmed loss, so fire on an unrecovered gap here too.
        fireLoss = unrecoveredGap;
      }
      // Service the recovery barrier: a clean terminal (Bad_MessageNotAvailable / Bad_SubscriptionIdInvalid /
      // a Good-status cap-hit) keeps the recovery Good (F6/N3); a genuinely bad status makes it report Bad so
      // the FSM recover step retries. finish_drain_terminal uses `state`, so it MUST run before the erase.
      self.finish_drain_terminal(state, status);
      if (fireLoss)
      {
        // Flood control (a CORRECTNESS requirement, Finding 2 section 1): advance the tracker PAST the gap
        // target BEFORE firing, so the next live Publish classifies InOrder and exactly ONE signal fires per
        // loss episode. Without it next_expected stays behind the hole, every subsequent live Publish
        // re-classifies Gap and re-fires - and since the reset ABORTS the in-flight resync ConditionRefresh,
        // a flood would prevent the resync from ever settling. Lossy branch only (the clean branch keeps
        // today's stop-at-next_expected behaviour). fireLoss is set only on non-gone branches, so `state` is
        // still valid here - the goneSubscription erase below cannot race it. Fires on THIS strand (like
        // onClassified / deliver_notification_async), never under a lock (the pipeline holds none).
        state.tracker.advance_past(state.gapTarget);
        if (self.mOnSubscriptionEventLoss)
        {
          self.mOnSubscriptionEventLoss(subscriptionId);
        }
      }
      if (goneSubscription)
      {
        // Erase the dead Subscription + its monitored-item callbacks (mirror remove_subscription_async's
        // cascade). `state` dangles after this - it is the last use of the map entry.
        self.mSubscriptions.erase(subscriptionId);
        for (auto item = self.mMonitoredItems.begin(); item != self.mMonitoredItems.end();)
        {
          item = (item->second.subscriptionId == subscriptionId) ? self.mMonitoredItems.erase(item)
                                                                 : std::next(item);
        }
        self.resize_pump();  // CL-SUB-015: the gone-subscription purge may shrink the pump target
      }
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::recover_subscriptions_async(std::function<void(ua::VoidResult)> done) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [done = std::move(done)](SubscriptionsPipeline& self) mutable
    {
      // F2 cancel interface: a prior in-flight recovery (from a superseded reconnect attempt) is discarded
      // WITHOUT firing its callback, and every Subscription's inRecovery flag is reset, before this fresh
      // recovery starts. The abandoned attempt's FSM generation is already superseded, so its dropped done
      // is inert (on_step's is_current guard). Also resets the worst-status accumulator to Good.
      self.clear_recovery();

      if (self.mSubscriptions.empty())
      {
        // Only fallback Subscriptions (mFallbackSubs, server-less) may remain  -  they take NO part in
        // recovery.
        done(ua::VoidResult{});  // nothing (server-backed) to recover: the recover step succeeds immediately
        return;
      }

      self.mRecoveryActive = true;
      self.mRecoveryDone = std::move(done);
      self.mRecoveryPending = self.mSubscriptions.size();
      for (auto& [subscriptionId, state] : self.mSubscriptions)
      {
        // Always start a FRESH, current-epoch Republish drain for every Subscription. clear_recovery() above
        // reset republishing/republishIterations for all of them, so no pre-drop reactive drain lingers.
        // Do NOT try to "adopt" an already-in-flight drain: its Republish was issued under the pre-drop
        // channel, so the connection-strand epoch guard drops its response - its terminal never arrives, so
        // an adopted drain would never decrement the barrier and the recover step would stall to its deadline
        // and eventually FAIL the reconnect against a healthy server. The stale in-flight response being
        // epoch-dropped also means the "two chains" hazard cannot occur (the old chain is already dead).
        state.inRecovery = true;
        state.republishing = true;
        state.republishIterations = 0;
        // The recovery drain blindly walks next_expected with no server-progress knowledge, so it can never
        // decide loss (KEY CORRECTION, Finding 2): clear any reactive gapTarget so its terminal never
        // false-fires the event-loss signal.
        state.gapTarget = 0;
        self.mSubOps->republish(subscriptionId, state.tracker.next_expected());
      }
    },
    []() {})();
}

void SubscriptionsPipeline::finish_drain_terminal(SubscriptionState& state, ua::StatusCode terminalStatus)
{
  // Strand only. Called at every terminal exit of a drain, AFTER state.republishing was cleared.
  if (!state.inRecovery)
  {
    return;  // a purely reactive (non-recovery) drain: no barrier to service
  }
  state.inRecovery = false;

  // F6: fold this terminal into the worst recovery outcome. Clean-for-recovery = the two normative
  // terminators (queue fully drained / Subscription gone) OR any Good-status terminal (an iteration-cap-hit
  // or an off-sequence reply - not a fault). Only a genuinely BAD status mid-drain (a transient/connection
  // error) makes the recovery report Bad so the FSM recover step backs off and re-drains (no-loss,
  // section 6.7). The bad status carries its own ErrorDetail (the design specification). N3: a cap-hit is NOT
  // treated as a retryable failure - it is a permanent per-reconnect property of a non-conforming server, so
  // retrying can never converge and would let such a server DoS the client into Failed; the cap-hit was
  // already logged at the drain site, and recovery proceeds to Active with whatever was recovered.
  const ua::Status terminal = terminalStatus.as_status();
  const bool cleanTerminal = terminalStatus.is_good() || terminal == ua::Status::BadMessageNotAvailable ||
                             terminal == ua::Status::BadSubscriptionIdInvalid;
  if (!cleanTerminal && mRecoveryWorstStatus.is_good())
  {
    mRecoveryWorstStatus = terminalStatus;
  }

  if (mRecoveryActive && mRecoveryPending > 0 && --mRecoveryPending == 0)
  {
    mRecoveryActive = false;
    auto done = std::exchange(mRecoveryDone, {});
    if (done)
    {
      done(mRecoveryWorstStatus.is_good() ? ua::VoidResult{} : ua::VoidResult{mRecoveryWorstStatus});
    }
  }
}

void SubscriptionsPipeline::clear_recovery()
{
  // Strand only. Discard any in-flight recovery WITHOUT firing its callback (the caller has superseded or
  // cancelled it; its FSM done is inert) and reset every Subscription's drain state so the next recovery
  // starts clean.
  mRecoveryDone = {};
  mRecoveryActive = false;
  mRecoveryPending = 0;
  mRecoveryWorstStatus = ua::StatusCode{ua::Status::Good};
  for (auto& [subscriptionId, state] : mSubscriptions)
  {
    state.inRecovery = false;
    // Also clear any in-flight drain (reactive or recovery) so the next recover_subscriptions_async issues a
    // FRESH, current-epoch Republish per Subscription. A pre-drop drain's Republish was issued under the old
    // channel, so its response is epoch-dropped and its terminal never arrives to clear republishing; leaving
    // it set would make the next recovery skip re-issuing (a dead drain) and stall the barrier (A1). This
    // runs from stop_async (entering Reconnecting / closing) and at the start of each recovery.
    state.republishing = false;
    state.republishIterations = 0;
    // Clear the reactive loss target too (Finding 2): the next recovery drain must not inherit a stale
    // gapTarget and false-fire event loss on a blind recovery walk.
    state.gapTarget = 0;
  }
}

void SubscriptionsPipeline::recovery_descriptors_async(
  std::function<void(std::vector<RecoveryDescriptor>)> callback) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [callback = std::move(callback)](SubscriptionsPipeline& self) mutable
    {
      // Build one CALLBACK-FREE descriptor per Subscription: its retained publishing interval plus every
      // monitored item it owns (node + client handle). The data-change callbacks stay on the strand and are
      // NEVER copied out (Q5). Callback fires on the strand; the connection-strand caller re-posts.
      std::vector<RecoveryDescriptor> descriptors;
      descriptors.reserve(self.mSubscriptions.size());
      std::unordered_map<std::uint32_t, std::size_t> indexBySubscriptionId;
      indexBySubscriptionId.reserve(self.mSubscriptions.size());
      for (const auto& [subscriptionId, state] : self.mSubscriptions)
      {
        indexBySubscriptionId.emplace(subscriptionId, descriptors.size());
        descriptors.push_back(
          RecoveryDescriptor{subscriptionId, state.publishingInterval, {}, state.maxNotificationsPerPublish});
      }
      for (const auto& [clientHandle, item] : self.mMonitoredItems)
      {
        const auto index = indexBySubscriptionId.find(item.subscriptionId);
        if (index != indexBySubscriptionId.end())
        {
          descriptors[index->second].monitoredItems.push_back(MonitoredItemDescriptor{item.nodeId,
            clientHandle,
            item.attribute,
            item.indexRange,
            item.samplingIntervalMs,
            item.queueSize,
            item.monitoringMode,
            item.discardOldest,
            item.filter});  // CL-MI-011 / OPEN-MI-011: carry the retained filter into the recreate descriptor
        }
      }
      callback(std::move(descriptors));
    },
    []() {})();
}

void SubscriptionsPipeline::apply_recreate_rekeys_async(
  std::vector<std::pair<std::uint32_t, std::uint32_t>> rekeys) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [rekeys = std::move(rekeys)](SubscriptionsPipeline& self)
    {
      if (rekeys.empty())
      {
        return;
      }
      // Two-phase, collision-safe apply (session-CHANGED recovery commit, section 6.7 / #24). EXTRACT every
      // old Subscription's state (and erase its old id) against the PRE-IMAGE first, THEN insert every new
      // id. A recreated Subscription's newId can legitimately equal another still-pending Subscription's
      // oldId (all old ids were freed when the old Session died), so a naive one-at-a-time move would clobber
      // a pristine entry that has not been re-keyed yet. Extracting all olds before inserting any new avoids
      // it.
      std::vector<std::pair<std::uint32_t, SubscriptionState>>
        staged;  // newId -> moved (tracker-reset) state
      staged.reserve(rekeys.size());
      std::unordered_map<std::uint32_t, std::uint32_t> oldToNew;
      oldToNew.reserve(rekeys.size());
      for (const auto& [oldId, newId] : rekeys)
      {
        const auto existing = self.mSubscriptions.find(oldId);
        if (existing == self.mSubscriptions.end())
        {
          continue;  // no longer registered (removed since staging): skip
        }
        SubscriptionState moved = std::move(existing->second);
        self.mSubscriptions.erase(existing);
        // EVERY entry is a recreate (transferred subs never stage a re-key), so ALWAYS reset the tracker to
        // the fresh server sequence space (next_expected == 1) - even when newId == oldId, because the server
        // restarted the recreated Subscription's sequence numbering regardless of the id it handed back.
        moved.tracker = SequenceTracker{};
        oldToNew.emplace(oldId, newId);
        staged.emplace_back(newId, std::move(moved));
      }
      for (auto& [newId, state] : staged)
      {
        self.mSubscriptions[newId] = std::move(state);
      }
      // Repoint every monitored item exactly once by its ORIGINAL owning id (preserving callback + handle).
      for (auto& [clientHandle, item] : self.mMonitoredItems)
      {
        const auto mapped = oldToNew.find(item.subscriptionId);
        if (mapped != oldToNew.end())
        {
          item.subscriptionId = mapped->second;
        }
      }
      self.publish_info();
    },
    []() {})();
}

void SubscriptionsPipeline::add_monitored_item_async(std::uint32_t subscriptionId, std::uint32_t clientHandle,
  ua::NodeId nodeId, std::function<void(ua::DataValue)> callback, ua::AttributeId attribute,
  std::optional<std::string> indexRange, double samplingIntervalMs, std::uint32_t queueSize,
  ua::MonitoringMode monitoringMode, bool discardOldest,
  std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [subscriptionId,
      clientHandle,
      nodeId = std::move(nodeId),
      callback = std::move(callback),
      attribute,
      indexRange = std::move(indexRange),
      samplingIntervalMs,
      queueSize,
      monitoringMode,
      discardOldest,
      filter = std::move(filter)](SubscriptionsPipeline& self) mutable
    {
      // Retain the caller's tuning alongside the node so a session-CHANGED recreate rebuilds the item with
      // the SAME parameters, not the builder's defaults (section 6.7, Q5) - including discardOldest
      // (CL-MI-020) and the DataChangeFilter (CL-MI-011 / OPEN-MI-011) so a recreate does not silently revert
      // a requested overflow policy or drop the caller's deadband/trigger filter.
      self.mMonitoredItems[clientHandle] = MonitoredItemEntry{subscriptionId,
        std::move(nodeId),
        attribute,
        std::move(indexRange),
        samplingIntervalMs,
        queueSize,
        monitoringMode,
        discardOldest,
        std::move(filter),
        std::move(callback),
        std::nullopt};  // lastPolledValue: unset until the fallback driver's first dispatch (CL-SUB-021)
      self.resize_pump();  // CL-SUB-015: an added item may grow the pump target
    },
    []() {})();
}

void SubscriptionsPipeline::deliver_notification_async(
  std::uint32_t clientHandle, ua::DataValue value) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [clientHandle, value = std::move(value)](SubscriptionsPipeline& self) mutable
    {
      const auto item = self.mMonitoredItems.find(clientHandle);
      if (item == self.mMonitoredItems.end())
      {
        ++self.mUnknownHandleDrops;  // notification for an unregistered handle - advisory drop (CL-MI-003)
        self.publish_info();
        return;
      }
      // CL-DA-010: an in-band SemanticsChanged StatusCode bit on a delivered DataChange (Part 8 section 5.2 /
      // Part 3 section 6.5.4) marks this node's Data-Access Properties stale - route the node into the
      // invalidation interface ON THE STRAND so the DA typed-accessor Property cache re-resolves fresh
      // Properties on the next read. The interface is an INTERNAL invalidation (not the user callback), so
      // invoking it here (not on the delivery strand) is safe; the value is still delivered to the user
      // callback below, unchanged (the SemanticsChanged bit is advisory metadata, never suppresses delivery).
      if (value.status().has_value() && value.status()->semantics_changed() && self.mOnSemanticsChanged)
      {
        self.mOnSemanticsChanged(item->second.nodeId);
      }
      // Hop the user callback onto the dedicated DELIVERY STRAND (never run user code under the processing
      // strand's serialization, and never bare-post to mExecutor). The processing strand handles
      // notifications in arrival order and posts to the delivery strand in that order; a strand is FIFO and
      // non-concurrent, so same-clientHandle callbacks fire in arrival order and never overlap  -  satisfying
      // CL-MI-026 for ANY executor thread count (a bare mExecutor post is reordered by a multi-threaded
      // pool). The delivery strand is separate from mStrand, so a slow user callback stalls only delivery,
      // never the publish pump. Copy the callback (multi-shot: it fires once per notification).
      ua::async::post_owning(&self,
        self.mDeliveryStrand,
        self.mLogger,
        [callback = item->second.callback, value = std::move(value)](SubscriptionsPipeline&) mutable
        { callback(std::move(value)); })();
    },
    []() {})();
}

void SubscriptionsPipeline::issue_publish()
{
  // Runs on the strand (from the pump). Each Publish carries the batched acks.
  if (mSubOps)
  {
    mSubOps->send_publish(mAckQueue.drain());
  }
}

void SubscriptionsPipeline::poll_read_async(std::vector<ua::ReadValueId> reads,
  std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept
{
  // Completion-owning post: the callback is owed exactly once. On the (practically unreachable) gone path -
  // the pipeline destroyed between this post and the strand turn - it fires Bad_ConnectionClosed carrying a
  // source-tagged ErrorDetail (the design specification) rather than a bare status or being dropped.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::Result<std::vector<ua::DataValue>>{ua::Status::BadConnectionClosed,
      ua::make_error_detail("PollReadPipelineGone",
        "the SubscriptionsPipeline was destroyed before the poll-read could run on its strand",
        std::string{pollReadPipelineGoneSource})},
    [reads = std::move(reads)](
      SubscriptionsPipeline& self, std::function<void(ua::Result<std::vector<ua::DataValue>>)> owed) mutable
    {
      auto state = std::make_shared<PollReadState>();
      state->reads = std::move(reads);
      const std::uint32_t limit = self.mWireOps->max_nodes_per_read();
      state->pageSize = limit == 0 ? 1U : limit;  // a zero limit would stall paging; floor to 1 (CL-SUB-020)
      state->results.reserve(state->reads.size());
      state->callback = std::move(owed);
      self.issue_next_poll_page(std::move(state));
    })();
}

void SubscriptionsPipeline::issue_next_poll_page(std::shared_ptr<PollReadState> state)
{
  // Drained: hand the stitched results to the executor (never fire the user callback on the strand).
  if (state->nextIndex >= state->reads.size())
  {
    mSupport->post_to_executor(
      [callback = std::move(state->callback), results = std::move(state->results)]() mutable
      { callback(ua::Result<std::vector<ua::DataValue>>{std::move(results)}); });
    return;
  }

  // Carve the next page of at most pageSize nodes (CL-SUB-020) and issue it.
  const std::size_t begin = state->nextIndex;
  const std::size_t end = std::min(begin + state->pageSize, state->reads.size());
  std::vector<ua::ReadValueId> page(state->reads.begin() + static_cast<std::ptrdiff_t>(begin),
    state->reads.begin() + static_cast<std::ptrdiff_t>(end));
  state->nextIndex = end;
  state->requested = end - begin;  // ReadValueId count this page sent, checked against the returned count

  ua::ReadRequest request;
  request.nodes_to_read() = page;

  mWireOps->read_async(std::move(request),
    ua::async::post_owning(this,
      mStrand,
      mLogger,
      [state = std::move(state)](SubscriptionsPipeline& self, ua::Result<ua::ReadResponse> result) mutable
      {
        if (!result.has_value())
        {
          // A page failure short-circuits the whole fallback. Forward the page's full StatusCode INCLUDING
          // its ErrorDetail chain (the design specification - never discard it): the detail rides inside the
          // StatusCode, so the caller receives the wire failure with its source-tagged cause intact.
          self.mSupport->post_to_executor(
            [callback = std::move(state->callback), error = result.status_code()]() mutable
            { callback(ua::Result<std::vector<ua::DataValue>>{std::move(error)}); });
          return;
        }
        const ua::StatusCode pageStatus = ua::detail::combined_status(
          result.status_code(), result.value().response_header().service_result());
        if (pageStatus.is_bad())
        {
          self.mSupport->post_to_executor(
            [callback = std::move(state->callback), error = pageStatus]() mutable
            { callback(ua::Result<std::vector<ua::DataValue>>{std::move(error)}); });
          return;
        }
        const auto& payload = result.value().results().payload();
        if (payload.size() != state->requested)
        {
          // OPC UA mandates results.size() == nodesToRead.size() (10000-4 section 5.10.2). A service-Good
          // response with a mismatched count would misalign values to the wrong nodes (results[i] <->
          // reads[i] is positional) and leave the stitched vector length != reads.size() (an OOB risk
          // downstream). Short-circuit the whole fallback with a source-tagged Bad rather than append a
          // misaligned page; this guarantees the stitched vector length == reads.size() on every Good path.
          self.mSupport->post_to_executor(
            [callback = std::move(state->callback)]() mutable
            {
              callback(ua::Result<std::vector<ua::DataValue>>{ua::Status::BadUnexpectedError,
                ua::make_error_detail("PollReadResultCountMismatch",
                  "a Read page returned a DataValue count that does not match its ReadValueId count",
                  std::string{pollReadResultCountMismatchSource})});
            });
          return;
        }
        // A polled value has no notification of its own to carry the page's code, so a Good subcode or an
        // Uncertain code on the Read's result or ServiceResult becomes the status of each value it is worse
        // than (or, for a Good subcode, each plain Good value).
        for (const auto& value : payload)
        {
          state->results.push_back(value);
          if (ua::detail::outer_status_answered(
                pageStatus, value.status().value_or(ua::StatusCode{ua::Status::Good})))
          {
            state->results.back().status() = pageStatus;
          }
        }
        self.issue_next_poll_page(std::move(state));
      }));
}

void SubscriptionsPipeline::resize_pump()
{
  // CL-SUB-015: the single per-Connection pump sizes on the TOTAL monitored-item count.
  // set_monitored_item_count recomputes target = max(2, ceil(items / 100)) and, if the pump is Running, fills
  // up to a grown target in-line (a shrunk target is not force-drained - outstanding falls as responses
  // arrive). Then re-publish the diagnostics so pumpTarget/monitoredItemCount stay coherent.
  mPump.set_monitored_item_count(mMonitoredItems.size());
  publish_info();
}

void SubscriptionsPipeline::publish_info()
{
  mInfoSnapshot.store(std::make_shared<const PipelineInfo>(PipelineInfo{mPump.state(),
    mSubscriptions.size(),
    mPump.outstanding(),
    mPump.target(),
    mMonitoredItems.size(),
    mUnknownHandleDrops}));
}

std::shared_ptr<const PipelineInfo> SubscriptionsPipeline::info() const noexcept
{
  return mInfoSnapshot.load();
}

}  // namespace ua::client::detail
