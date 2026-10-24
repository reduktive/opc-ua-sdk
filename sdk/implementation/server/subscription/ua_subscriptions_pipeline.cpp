// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscriptions_pipeline.h"

#include <cmath>

#include "ua_address_space.h"
#include "ua_data_change_notification.h"
#include "ua_diagnostic_bits.h"
#include "ua_audit_session_event_payload.h"
#include "ua_date_time.h"
#include "ua_diagnostic_collector.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_log_exception.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_callback_safety.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_status_change_notification.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_transfer_result.h"
#include "session/ua_server_session.h"

#include <algorithm>
#include <limits>

namespace ua::server
{

namespace
{

/// The answer for a result that is not Good, which holds no value: a Bad @p answer as it is; any other (an
/// Uncertain one, which a client would read as a success) `Bad_InternalError` under the ErrorDetail @p code,
/// with @p answer as its cause.
StatusCode refusal_of(const StatusCode& answer, std::string code, std::string summary)
{
  if (answer.is_bad())
  {
    return answer;
  }
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build(std::move(code), std::move(summary), "SubscriptionsPipeline").cause(answer)};
}

}  // namespace

std::shared_ptr<SubscriptionsPipeline> SubscriptionsPipeline::create(Config config)
{
  return std::shared_ptr<SubscriptionsPipeline>(new SubscriptionsPipeline(std::move(config)));
}

SubscriptionsPipeline::SubscriptionsPipeline(Config config)
  : mExecutor(config.executor), mSessionStrand(config.sessionStrand), mLogger(std::move(config.logger)),
    mIdAllocator(config.idAllocator), mSummaryCounters(std::move(config.summaryCounters)),
    mCapabilities(std::move(config.capabilities)), mSubscriptionLimits(std::move(config.subscriptionLimits)),
    mAccessRecheckInterval(config.monitoredItemAccessRecheckInterval),
    mAccessControlTimeout(config.accessControlTimeout), mSendResponse(std::move(config.sendResponse)),
    mAddressSpace(std::move(config.addressSpace)), mSubscriptionRouter(config.subscriptionRouter),
    mOrphanedSubscriptionStore(config.orphanedSubscriptionStore),
    mOwningSession(std::move(config.owningSession)), mSecurityContext(std::move(config.securityContext)),
    mDiagnosticSecurityContext(std::move(config.diagnosticSecurityContext)),
    mDiagnosticsObject(std::move(config.diagnosticsObject)), mEventBus(std::move(config.eventBus)),
    mMaxResponseMessageSize(config.maxResponseMessageSize), mAuditingEnabled(config.auditingEnabled),
    mApplicationUri(std::move(config.applicationUri)), mMonotonicNow(std::move(config.monotonicNow)),
    mMaxPendingPublishRequests(mSubscriptionLimits.maxPublishRequestsPerSession.value_or(
      std::max(2 * mCapabilities.maxSubscriptionsPerSession.value_or(100), 10u))),
    mMaxRetransmissionQueueSize(2 * mMaxPendingPublishRequests),
    mMaxPendingStatusChanges(mSubscriptionLimits.maxPendingStatusChanges.value_or(100))
{}

void SubscriptionsPipeline::reauthorize_all_async(std::function<void(VoidResult)> callback)
{
  auto guardedCompletion = ua::detail::make_fire_once<VoidResult>(std::move(callback));
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    std::move(guardedCompletion),
    VoidResult{StatusCode{Status::BadSessionClosed}},
    [](SubscriptionsPipeline& self, std::function<void(VoidResult)> completion) mutable
    {
      try
      {
        if (self.mReauthorizeAllRunning)
        {
          completion(VoidResult{StatusCode{Status::BadServerTooBusy,
            make_error_detail("ReauthorizationBusy",
              "A Session MonitoredItem reauthorization walk is already active",
              "SubscriptionsPipeline")}});
          return;
        }

        std::vector<std::shared_ptr<Subscription>> subscriptions;
        subscriptions.reserve(self.mSubscriptions.size());
        for (const auto& entry : self.mSubscriptions)
          subscriptions.push_back(entry.second);

        self.mReauthorizeAllRunning = true;
        self.mReauthorizeAllCompletion = completion;
        self.start_reauthorize_all(std::move(subscriptions));
      }
      catch (...)
      {
        // The body contains itself; what is left out here is the snapshot and the frame allocation,
        // which happen after the walk has been marked running and would otherwise latch it.
        auto failure = VoidResult{ua::exception_to_status_code(std::current_exception())};
        if (self.mReauthorizeAllRunning)
          self.finish_reauthorize_all(std::move(failure));
        else
          completion(std::move(failure));
      }
    })();
}

/// One reauthorization walk, in the order the handler chain walked it.
void SubscriptionsPipeline::start_reauthorize_all(std::vector<std::shared_ptr<Subscription>> subscriptions)
{
  // A task is EAGER, and a walk over a Session with no subscriptions finishes without ever
  // suspending, firing its answer before this returns. @see Subscription::start_delete
  const uint64_t generation = ++mReauthorizeAllGeneration;
  auto walk = run_reauthorize_all(std::move(subscriptions));
  if (mReauthorizeAllGeneration == generation)
  {
    mReauthorizeAllTask = std::move(walk);
  }
}

ua::async::Task<> SubscriptionsPipeline::run_reauthorize_all(
  std::vector<std::shared_ptr<Subscription>> subscriptions)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads. The caller - a Session whose identity has just changed - would wait for ever, and
  // `mReauthorizeAllRunning` would refuse every later walk on this Session.
  try
  {
    co_await walk_reauthorize_all(subscriptions);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the walk and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mReauthorizeAllRunning)
        {
          finish_reauthorize_all(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

ua::async::Task<> SubscriptionsPipeline::walk_reauthorize_all(
  const std::vector<std::shared_ptr<Subscription>>& subscriptions)
{
  for (const auto& subscription : subscriptions)
  {
    if (!mReauthorizeAllRunning)
    {
      // Something else ended this walk and answered its caller.
      co_return;
    }

    VoidResult result{};
    try
    {
      result = co_await await_step<VoidResult>(
        [&subscription](auto completion) { subscription->reauthorize_all_async(std::move(completion)); });
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      // A subscription that throws out of the CALL has answered nothing. The chain this replaces
      // ended the whole walk on such a throw, and so does this.
      result = VoidResult{ua::exception_to_status_code(std::current_exception())};
    }

    if (!mReauthorizeAllRunning)
    {
      co_return;
    }

    // The first refusal ends the walk. An identity that may not see one subscription's items is not
    // a partial answer: the Session is told its reauthorization failed.
    if (result.is_bad())
    {
      finish_reauthorize_all(std::move(result));
      co_return;
    }
  }

  if (mReauthorizeAllRunning)
  {
    finish_reauthorize_all(VoidResult{});
  }
  co_return;
}

std::function<void(VoidResult)> SubscriptionsPipeline::take_reauthorize_all_completion()
{
  // Whoever gets here first ends the walk and answers it once - the body on its way out, or
  // ~SubscriptionsPipeline answering for a body that can no longer be asked.
  auto completion = std::move(mReauthorizeAllCompletion);
  mReauthorizeAllCompletion = nullptr;
  mReauthorizeAllRunning = false;

  // What the slot pins is the root task's parameter: a strong handle to every subscription the walk
  // was about. Nothing would release them until the NEXT walk overwrote the slot, which for a
  // Session whose identity never changes again is never. Released on a later turn, because this is
  // reached from inside that very frame, and guarded by the generation because the answer may start
  // the next walk before that turn runs.
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [generation = mReauthorizeAllGeneration](SubscriptionsPipeline& self)
    {
      if (self.mReauthorizeAllGeneration == generation && !self.mReauthorizeAllRunning)
      {
        self.mReauthorizeAllTask = {};
      }
    })();

  return completion;
}

void SubscriptionsPipeline::finish_reauthorize_all(VoidResult result)
{
  auto completion = take_reauthorize_all_completion();
  if (completion)
    completion(std::move(result));
}

SubscriptionsPipeline::~SubscriptionsPipeline()
{
  // An in-flight walk is answered here, because nothing else will. Every hop of the chain this
  // replaces carried the caller's completion through a completion-owning post, so a pipeline that
  // went away answered BadSessionClosed on its way out; a body that holds its answer in a member
  // has to say that itself.
  if (mReauthorizeAllRunning)
  {
    ua::async::guarded(
      mLogger, [this] { finish_reauthorize_all(VoidResult{StatusCode{Status::BadSessionClosed}}); })();
  }
}

// --- Parameter revision ---

SubscriptionsPipeline::RevisedParams SubscriptionsPipeline::revise_parameters(Duration requestedInterval,
  uint32_t requestedLifetimeCount, uint32_t requestedMaxKeepAliveCount,
  uint32_t requestedMaxNotificationsPerPublish) const
{
  using namespace std::chrono;

  // Publishing interval: clamp to [min, max], 0/negative -> min.
  // Duration is double milliseconds; config fields are std::chrono::milliseconds.
  const Duration minInterval =
    static_cast<Duration>(mSubscriptionLimits.minPublishingInterval.value_or(milliseconds{100}).count());
  const Duration maxInterval =
    static_cast<Duration>(mSubscriptionLimits.maxPublishingInterval.value_or(milliseconds{60000}).count());

  Duration revisedInterval = requestedInterval;
  // NaN, non-positive, or below-minimum requests all revise to the fastest supported interval. NaN
  // fails every ordered comparison (`NaN <= 0`, `NaN < min`, `NaN > max` are all false), so it is
  // tested explicitly; otherwise it would pass through unrevised and be echoed back as NaN.
  if (std::isnan(revisedInterval) || revisedInterval <= Duration{0} || revisedInterval < minInterval)
  {
    revisedInterval = minInterval;
  }
  else if (revisedInterval > maxInterval)
  {
    revisedInterval = maxInterval;
  }

  // Keep-alive count: clamp to [1, maxKeepAliveCount], 0 -> 1.
  const uint32_t maxKeepAlive = mSubscriptionLimits.maxKeepAliveCount.value_or(3000);
  uint32_t revisedKeepAlive = requestedMaxKeepAliveCount;
  if (revisedKeepAlive == 0)
  {
    revisedKeepAlive = 1;
  }
  else if (revisedKeepAlive > maxKeepAlive)
  {
    revisedKeepAlive = maxKeepAlive;
  }

  // Lifetime count: at least 3 * keepAliveCount, and no more than the configured maximum (a parked
  // subscription otherwise lives, with every slot it holds, for as long as the client asked).
  uint32_t revisedLifetime = requestedLifetimeCount;
  const uint32_t minLifetime = 3 * revisedKeepAlive;
  if (const auto maxLifetime = mSubscriptionLimits.maxLifetimeCount;
      maxLifetime && revisedLifetime > std::max(*maxLifetime, minLifetime))
  {
    revisedLifetime = std::max(*maxLifetime, minLifetime);
  }
  if (revisedLifetime < minLifetime)
  {
    revisedLifetime = minLifetime;
  }

  // Max notifications per publish: apply server cap if configured.
  uint32_t revisedMaxNotifications = requestedMaxNotificationsPerPublish;
  const auto serverCap = mSubscriptionLimits.maxNotificationsPerPublish.value_or(0);
  if (serverCap > 0 && (revisedMaxNotifications == 0 || revisedMaxNotifications > serverCap))
  {
    revisedMaxNotifications = serverCap;
  }

  return RevisedParams{
    .publishingInterval = revisedInterval,
    .lifetimeCount = revisedLifetime,
    .maxKeepAliveCount = revisedKeepAlive,
    .maxNotificationsPerPublish = revisedMaxNotifications,
  };
}

// --- CreateSubscription ---

void SubscriptionsPipeline::handle_create_subscription(
  uint32_t requestId, const CreateSubscriptionRequest& request)
{
  // Runs the body INLINE when the caller is already on the session strand - which every production
  // caller is, because the Session dispatches service calls on it - so the common path costs
  // nothing and copies nothing. A caller that is NOT on the strand gets a hop, and pays for a copy
  // of the request, because its own may not outlive that hop.
  //
  // This replaces a precondition that lived in a comment ("run on session strand") and was violated
  // by 84 call sites. A precondition a caller can get wrong is a defect waiting to be written; one
  // the entry point honours itself cannot be.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_create_subscription_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_create_subscription_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_create_subscription_on_strand(
  uint32_t requestId, const CreateSubscriptionRequest& request)
{
  // Check per-session subscription limit.
  const auto maxPerSession = mCapabilities.maxSubscriptionsPerSession;
  if (maxPerSession && mSubscriptions.size() >= *maxPerSession)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadTooManySubscriptions};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Check server-wide subscription limit.
  if (mSummaryCounters)
  {
    const auto maxTotal = mCapabilities.maxSubscriptions;
    if (maxTotal && mSummaryCounters->currentSubscriptionCount.load(std::memory_order_relaxed) >= *maxTotal)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManySubscriptions};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  // Revise parameters.
  const auto revised = revise_parameters(request.requested_publishing_interval(),
    request.requested_lifetime_count(),
    request.requested_max_keep_alive_count(),
    request.max_notifications_per_publish());

  // Allocate subscription ID.
  const IntegerId subscriptionId = mIdAllocator.allocate();

  // Create Subscription component.
  // Callbacks are invoked from the subscription strand but must access session-strand state, so they
  // post to the session strand. post_borrowing captures weak_from_this() internally, keeping `this`
  // alive only while the posted task actually runs.
  auto subscription = Subscription::create(subscriptionId,
    revised.publishingInterval,
    revised.lifetimeCount,
    revised.maxKeepAliveCount,
    revised.maxNotificationsPerPublish,
    request.publishing_enabled(),
    request.priority(),
    mExecutor,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [](SubscriptionsPipeline& self, IntegerId id) { self.on_subscription_ready(id); }),
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [](SubscriptionsPipeline& self, IntegerId id) { self.on_subscription_expired(id); }),
    mSubscriptionRouter,
    mOwningSession,
    mMaxResponseMessageSize);

  // Seed the subscription's logger (and, through it, its sample sink's) before it is published or
  // sampled, so its async continuations can be guarded.
  subscription->set_logger(mLogger.with_category("subscription"));
  subscription->set_summary_counters(mSummaryCounters);
  subscription->set_access_control_timeout(mAccessControlTimeout);

  // Configure periodic per-MonitoredItem authorization re-evaluation (Part 4 5.12.2.1). The pipeline
  // owns the session security context / address space / EventBus the recheck needs; hand them to the
  // subscription so it can re-resolve and re-authorize each item on its own strand.
  subscription->configure_access_recheck(
    mAccessRecheckInterval, mSecurityContext.lock(), mAddressSpace, mEventBus);

  // Register.
  mSubscriptions.emplace(subscriptionId, subscription);
  mAtomicSubscriptionCount.fetch_add(1, std::memory_order_relaxed);

  // Update server counters.
  if (mSummaryCounters)
  {
    mSummaryCounters->currentSubscriptionCount.fetch_add(1, std::memory_order_relaxed);
    mSummaryCounters->cumulatedSubscriptionCount.fetch_add(1, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_add(1, std::memory_order_relaxed);
  }

  mLogger.info("Subscription {} created (interval={:.0f}ms, keepAlive={}, lifetime={})",
    subscriptionId,
    revised.publishingInterval,
    revised.maxKeepAliveCount,
    revised.lifetimeCount);

  // Build response.
  auto response = std::make_shared<CreateSubscriptionResponse>();
  stack_utils::prepare_response_header(request.request_header(), response->response_header());
  response->subscription_id() = subscriptionId;
  response->revised_publishing_interval() = revised.publishingInterval;
  response->revised_lifetime_count() = revised.lifetimeCount;
  response->revised_max_keep_alive_count() = revised.maxKeepAliveCount;

  // When per-subscription diagnostic nodes are maintained, defer the response until the node is
  // visible, so a client that immediately browses diagnostics finds it. The readiness callback fires
  // from the manager's address-space executor, so hop back to the session strand to send. When no
  // diagnostics-node manager is wired (the common case, and all unit tests), keep the original
  // synchronous response so callers that inspect the result inline still see it.
  if (auto router = mSubscriptionRouter.lock(); router && router->has_node_readiness_callback())
  {
    router->when_subscription_node_ready(subscriptionId,
      ua::async::post_borrowing(this,
        mSessionStrand,
        mLogger,
        [requestId, response = std::move(response)](SubscriptionsPipeline& self) mutable
        { self.mSendResponse(std::make_pair(requestId, std::move(response))); }));
  }
  else
  {
    mSendResponse(std::make_pair(requestId, std::move(response)));
  }
}

// --- ModifySubscription ---

void SubscriptionsPipeline::handle_modify_subscription(
  uint32_t requestId, const ModifySubscriptionRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_modify_subscription_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_modify_subscription_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_modify_subscription_on_strand(
  uint32_t requestId, const ModifySubscriptionRequest& request)
{
  auto it = mSubscriptions.find(request.subscription_id());
  if (it == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  it->second->on_service_call_async();

  const auto revised = revise_parameters(request.requested_publishing_interval(),
    request.requested_lifetime_count(),
    request.requested_max_keep_alive_count(),
    request.max_notifications_per_publish());

  auto& subscription = it->second;

  // Fire-and-forget modify on subscription strand.
  subscription->modify_async(revised.publishingInterval,
    revised.lifetimeCount,
    revised.maxKeepAliveCount,
    revised.maxNotificationsPerPublish,
    request.priority());

  mLogger.info("Subscription {} modified (interval={:.0f}ms, keepAlive={}, lifetime={})",
    request.subscription_id(),
    revised.publishingInterval,
    revised.maxKeepAliveCount,
    revised.lifetimeCount);

  // Build response.
  auto response = std::make_shared<ModifySubscriptionResponse>();
  stack_utils::prepare_response_header(request.request_header(), response->response_header());
  response->revised_publishing_interval() = revised.publishingInterval;
  response->revised_lifetime_count() = revised.lifetimeCount;
  response->revised_max_keep_alive_count() = revised.maxKeepAliveCount;

  mSendResponse(std::make_pair(requestId, std::move(response)));
}

// --- DeleteSubscriptions ---

void SubscriptionsPipeline::handle_delete_subscriptions(
  uint32_t requestId, const DeleteSubscriptionsRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_delete_subscriptions_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_delete_subscriptions_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_delete_subscriptions_on_strand(
  uint32_t requestId, const DeleteSubscriptionsRequest& request)
{
  const auto& ids = request.subscription_ids();

  // Validate: non-empty.
  if (ids.empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto response = std::make_shared<DeleteSubscriptionsResponse>();
  stack_utils::prepare_response_header(request.request_header(), response->response_header());

  auto& results = response->results();
  results.resize(ids.size());

  std::vector<IntegerId> subscriptionsToClose;
  subscriptionsToClose.reserve(ids.size());
  for (size_t i = 0; i < ids.size(); ++i)
  {
    const bool duplicate = std::find(subscriptionsToClose.begin(), subscriptionsToClose.end(), ids[i]) !=
                           subscriptionsToClose.end();
    if (duplicate || mSubscriptions.find(ids[i]) == mSubscriptions.end())
    {
      results[i] = StatusCode{Status::BadSubscriptionIdInvalid};
      continue;
    }

    results[i] = StatusCode{Status::Good};
    subscriptionsToClose.push_back(ids[i]);
  }

  if (subscriptionsToClose.empty())
  {
    if (mSubscriptions.empty())
      drain_publish_queue(StatusCode{Status::BadNoSubscription});
    mSendResponse(std::make_pair(requestId, std::move(response)));
    return;
  }

  auto remainingCloses = std::make_shared<size_t>(subscriptionsToClose.size());
  for (const IntegerId subscriptionId : subscriptionsToClose)
  {
    auto closeCompletion = ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [requestId, response, remainingCloses](SubscriptionsPipeline& self) mutable
      {
        --*remainingCloses;
        if (*remainingCloses != 0)
          return;

        // Part 4 section 5.13.8.1: Good completion is observable only after every owned MonitoredItem is
        // gone.
        if (self.mSubscriptions.empty())
          self.drain_publish_queue(StatusCode{Status::BadNoSubscription});
        self.mSendResponse(std::make_pair(requestId, std::move(response)));
      });
    close_and_remove_subscription(subscriptionId, std::move(closeCompletion));
    mLogger.info("Subscription {} deleted", subscriptionId);
  }
}

// --- SetPublishingMode ---

void SubscriptionsPipeline::handle_set_publishing_mode(
  uint32_t requestId, const SetPublishingModeRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_set_publishing_mode_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_set_publishing_mode_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_set_publishing_mode_on_strand(
  uint32_t requestId, const SetPublishingModeRequest& request)
{
  const auto& ids = request.subscription_ids();

  if (ids.empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Part 4 5.13.4.3 lists BadTooManyOperations for this Service, but Part 5 6.3.11 defines no
  // dedicated OperationLimits property for subscription-id batches. MaxSubscriptionsPerSession is
  // therefore the tightest advertised upper bound: a request larger than the number of subscriptions
  // the Session can own cannot contain any additional valid operation and must not force an unbounded
  // per-call walk.
  if (mCapabilities.maxSubscriptionsPerSession)
  {
    const uint32_t limit = *mCapabilities.maxSubscriptionsPerSession;
    if (limit > 0 && ids.size() > limit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations,
        ErrorDetail::build("SetPublishingModeTooManyOperations",
          "SetPublishingMode request exceeds the subscription operation limit",
          "SubscriptionsPipeline.set_publishing_mode")
          .context(ua::ContextKeys::sizeActual, ids.size())
          .context(ua::ContextKeys::sizeMax, limit)};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  auto response = std::make_shared<SetPublishingModeResponse>();
  stack_utils::prepare_response_header(request.request_header(), response->response_header());

  auto& results = response->results();
  results.resize(ids.size());

  const bool enabled = request.publishing_enabled();

  for (size_t i = 0; i < ids.size(); ++i)
  {
    auto it = mSubscriptions.find(ids[i]);
    if (it == mSubscriptions.end())
    {
      results[i] = StatusCode{Status::BadSubscriptionIdInvalid};
      continue;
    }

    auto& subscription = it->second;
    // Any Service call referencing the SubscriptionId resets its lifetime counter
    // (Part 4 5.13.1.1 h).
    subscription->on_service_call_async();
    subscription->set_publishing_mode_async(enabled);

    results[i] = StatusCode{Status::Good};
  }

  mSendResponse(std::make_pair(requestId, std::move(response)));
}

// --- Publish ---

void SubscriptionsPipeline::handle_publish(uint32_t requestId, const PublishRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_publish_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_publish_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_publish_on_strand(uint32_t requestId, const PublishRequest& request)
{
  // BadNoSubscription when no subscriptions exist and no pending status changes.
  if (mSubscriptions.empty() && mPendingStatusChanges.empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNoSubscription};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Publish queue limit check: expire timed-out requests first, then reject the oldest still-valid
  // request if the queue remains full. A timed-out request must receive Bad_Timeout, never be relabelled
  // as overflow merely because validation was delayed until the next Publish arrived.
  while (mPendingPublishRequests.size() >= mMaxPendingPublishRequests)
  {
    auto oldest = std::move(mPendingPublishRequests.front());
    mPendingPublishRequests.pop_front();
    if (publish_request_timed_out(oldest))
    {
      send_publish_fault(std::move(oldest),
        StatusCode{Status::BadTimeout,
          make_error_detail("PublishRequestTimedOut",
            "Publish request timeoutHint elapsed before response processing",
            "SubscriptionsPipeline")});
      continue;
    }

    send_publish_fault(std::move(oldest),
      StatusCode{Status::BadTooManyPublishRequests,
        make_error_detail("TooManyPublishRequests",
          "Publish request rejected because the Session Publish queue is full",
          "SubscriptionsPipeline")});
    break;
  }

  // Enqueue PendingPublish.
  PendingPublish pending;
  pending.requestId = requestId;
  pending.requestHeader = request.request_header();
  pending.timeoutHint = request.request_header().timeout_hint();
  pending.receivedAt = mMonotonicNow();

  // Copy acknowledgements.
  const auto& acks = request.subscription_acknowledgements();
  pending.acknowledgements.assign(acks.begin(), acks.end());

  mPendingPublishRequests.push_back(std::move(pending));

  // Notify subscriptions that publish requests are available.
  for (auto& [id, sub] : mSubscriptions)
  {
    sub->set_publish_req_queued_async(true);
  }

  // Try immediate dispatch.
  request_dispatch();
}

std::vector<uint32_t> SubscriptionsPipeline::discard_pending_publish_requests()
{
  // The requests arrived on a SecureChannel that has just been lost. The client abandons its outstanding
  // Publish requests when the channel dies and resends fresh ones (with fresh requestIds) on the reconnect
  // channel (Part 4 6.7), so there is nothing to answer here - and answering would be impossible (the
  // channel is gone). Leaving them queued is the bug this fixes: after re-activation on a new channel the
  // stale requests sit at the front of the queue and get dispatched first, so a live subscription's
  // NotificationMessage is sent in reply to a stale requestId the client no longer has outstanding; the
  // client's SecureChannel drops that response and the notification is lost. Drop the stale requests so
  // every post-reconnect NotificationMessage is dispatched against a fresh request the client is awaiting.
  //
  // Report the discarded requestIds: because no response is emitted for them, the session must release the
  // per-request bookkeeping that response_received would otherwise reap (else it orphans across reconnects).
  std::vector<uint32_t> discardedRequestIds;
  discardedRequestIds.reserve(mPendingPublishRequests.size());
  for (const auto& pending : mPendingPublishRequests)
    discardedRequestIds.push_back(pending.requestId);
  mPendingPublishRequests.clear();
  return discardedRequestIds;
}

// --- Republish ---

void SubscriptionsPipeline::handle_republish(uint32_t requestId, const RepublishRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_republish_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_republish_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_republish_on_strand(uint32_t requestId, const RepublishRequest& request)
{
  // Look up subscription.
  auto it = mSubscriptions.find(request.subscription_id());
  if (it == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  it->second->record_republish_request();

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h / state-table rows 20-21) - including a Republish that
  // does not find the requested sequence number (e.g. BadMessageNotAvailable).
  it->second->on_service_call_async();

  // Search retransmission queue.
  const uint32_t targetSeqNum = request.retransmit_sequence_number();
  const IntegerId targetSubId = request.subscription_id();

  for (const auto& entry : mRetransmissionQueue)
  {
    if (entry.subscriptionId == targetSubId && entry.message.sequence_number() == targetSeqNum)
    {
      auto& subscription = it->second;
      // The completion holds the Subscription weakly: a namespace may hold the re-authorization while the
      // Session closes, and keeps nothing of the Session alive (COMP-SVR-NAMESPACE-CALLS-21 rule 1).
      subscription->reauthorize_notification_async(NotificationMessage{entry.message},
        entry.eventProjections,
        entry.dataProjections,
        ua::async::post_borrowing(this,
          mSessionStrand,
          mLogger,
          [requestId,
            requestHeader = request.request_header(),
            subscription = std::weak_ptr<Subscription>{subscription}](
            SubscriptionsPipeline& self, Result<NotificationMessage> result) mutable
          {
            self.on_republish_reauthorized(
              requestId, std::move(requestHeader), std::move(subscription), std::move(result));
          }));
      return;
    }
  }

  // Not found.
  auto fault = std::make_shared<ServiceFault>();
  stack_utils::prepare_response_header(request.request_header(), fault->response_header());
  fault->response_header().service_result() = StatusCode{Status::BadMessageNotAvailable};
  mSendResponse(std::make_pair(requestId, std::move(fault)));
}

void SubscriptionsPipeline::on_republish_reauthorized(uint32_t requestId, RequestHeader requestHeader,
  const std::weak_ptr<Subscription>& subscription, Result<NotificationMessage> result)
{
  // A result that is not Good holds no message: a Bad one answers the Republish with its status, an Uncertain
  // one with Bad_InternalError and it as the cause.
  if (!result.is_good())
  {
    if (const auto& detail = result.shared_detail())
    {
      mLogger.error({{"status", ua::to_string(result.status_code())},
                      {"error_code", detail->code},
                      {"summary", detail->summary}},
        "Republish reauthorization failed");
    }
    else
    {
      mLogger.error({{"status", ua::to_string(result.status_code())}}, "Republish reauthorization failed");
    }

    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(requestHeader, fault->response_header());
    fault->response_header().service_result() = refusal_of(result.status_code(),
      "RepublishAnswerWithoutMessage",
      "The Republish reauthorization answered a status that is neither Good nor Bad, with no message");
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto response = std::make_shared<RepublishResponse>();
  stack_utils::prepare_response_header(requestHeader, response->response_header());
  response->notification_message() = std::move(result).value();

  bool containsDenial = false;
  std::vector<StatusCode> itemStatuses;
  std::vector<uint32_t> itemMasks;
  std::vector<DataChangeNotification*> dataChanges;
  for (auto& notification : response->notification_message().notification_data())
  {
    auto* dataChange = dynamic_cast<DataChangeNotification*>(notification.get());
    if (!dataChange)
      continue;
    dataChanges.push_back(dataChange);
    for (size_t index = 0; index < dataChange->monitored_items().size(); ++index)
    {
      const auto& status = dataChange->monitored_items()[index].value().status();
      if (status && *status == StatusCode{Status::BadUserAccessDenied})
      {
        containsDenial = true;
      }
      itemStatuses.push_back(status.value_or(StatusCode{}));
      uint32_t mask = 0;
      if (index < dataChange->diagnostic_infos().size())
      {
        const auto& original = dataChange->diagnostic_infos()[index];
        if (original.symbolic_id() || original.namespace_uri())
          mask |= diag::operationSymbolicId;
        if (original.locale() || original.localized_text())
          mask |= diag::operationLocalizedText;
        if (original.additional_info())
          mask |= diag::operationAdditionalInfo;
        if (original.inner_status_code())
          mask |= diag::operationInnerStatus;
        if (original.inner_diagnostic_info())
          mask |= diag::operationInnerDiagnostics;
      }
      itemMasks.push_back(mask);
    }
    dataChange->diagnostic_infos().clear();
  }

  // Rebuild all retained item diagnostics in one string-table domain under the current recipient
  // context. Original fields bound the requested mask, so a later grant cannot add diagnostics that
  // the original Publish did not contain. Clearing above also handles zero-mask early returns.
  if (!containsDenial && mDiagnosticSecurityContext)
  {
    Array<DiagnosticInfo> projected;
    DiagnosticCollector collector{
      diag::serviceLevelMask | diag::operationLevelMask, mDiagnosticSecurityContext()};
    collector.apply_to_notification_items(
      response->response_header().string_table(),
      [&itemStatuses](size_t index) { return itemStatuses[index]; },
      [&itemMasks](size_t index) { return itemMasks[index]; },
      itemStatuses.size(),
      projected);
    if (!projected.empty())
    {
      size_t offset = 0;
      for (auto* dataChange : dataChanges)
      {
        for (size_t index = 0; index < dataChange->monitored_items().size(); ++index)
          dataChange->diagnostic_infos().push_back(std::move(projected[offset++]));
      }
    }
  }

  mSendResponse(std::make_pair(requestId, std::move(response)));
  if (const auto republished = subscription.lock())
  {
    republished->record_republish_message();
  }
}

// --- Session lifecycle ---

void SubscriptionsPipeline::close_all()
{
  mClosed = true;

  // 7.3 ergonomic-firing: an in-flight transfer must complete its callback
  // exactly once. Fire a BadSessionClosed ServiceFault before the rest of
  // teardown so the requestor sees the closure rather than a silent drop.
  if (mTransferRunning)
  {
    fail_transfer(StatusCode{Status::BadSessionClosed});
  }

  // Close all subscriptions.
  for (auto& [id, subscription] : mSubscriptions)
  {
    subscription->close_async();
  }

  // Decrement server counters.
  if (mSummaryCounters)
  {
    auto count = numeric_cast<uint32_t>(mSubscriptions.size());
    mSummaryCounters->currentSubscriptionCount.fetch_sub(count, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_sub(count, std::memory_order_relaxed);
  }

  // Reset cross-strand observable gauges.
  mAtomicSubscriptionCount.store(0, std::memory_order_relaxed);
  mAtomicTotalMonitoredItemCount.store(0, std::memory_order_relaxed);

  mSubscriptions.clear();

  // Drain publish queue.
  drain_publish_queue(StatusCode{Status::BadSessionClosed});
}

void SubscriptionsPipeline::orphan_all(SubscriptionTransferContext transferContext)
{
  // No store configured -> fall back to deleting (pre-F34 behaviour). A store that has gone with its server
  // (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01) holds nothing for later either: the Subscriptions are closed.
  auto store = mOrphanedSubscriptionStore.lock();
  if (!store)
  {
    close_all();
    return;
  }

  mClosed = true;

  if (mTransferRunning)
  {
    fail_transfer(StatusCode{Status::BadSessionClosed});
  }

  const auto detachedCount = numeric_cast<uint32_t>(mSubscriptions.size());

  for (auto& [id, subscription] : mSubscriptions)
  {
    // Carry over this subscription's complete retransmission entries, including diagnostic tables.
    std::vector<RetransmissionEntry> retransmissionEntries;
    auto qIt = mRetransmissionQueue.begin();
    while (qIt != mRetransmissionQueue.end())
    {
      if (qIt->subscriptionId == id)
      {
        retransmissionEntries.push_back(std::move(*qIt));
        qIt = mRetransmissionQueue.erase(qIt);
      }
      else
      {
        ++qIt;
      }
    }

    // Rewire callbacks: no owning session to notify of readiness; on lifetime expiry, drop from the
    // store. The removal is posted to the executor so the (possibly final) ~Subscription does not run
    // on the subscription's own strand mid-callback.
    auto weakStore = mOrphanedSubscriptionStore;
    auto executor = mExecutor;
    auto logger = mLogger;
    subscription->rewire_callbacks_async([](IntegerId) {},
      [weakStore, executor, logger](IntegerId expiredId)
      {
        boost::asio::post(executor,
          ua::async::guarded(logger,
            [weakStore, expiredId]
            {
              // The removal can run after the server, and its store, are gone: then nothing holds the
              // Subscription any more.
              if (auto parked = weakStore.lock())
              {
                parked->remove(expiredId);
              }
            }));
      });

    // A parked subscription holds no session; its MonitoredItems must not keep counting against the
    // server-wide MaxMonitoredItems, or a closed session's orphans deny every other client.
    subscription->release_server_monitored_item_slots();

    OrphanedSubscription orphan;
    orphan.subscription = subscription;
    orphan.retransmissionEntries = std::move(retransmissionEntries);
    orphan.transferContext = transferContext;
    store->park(id, std::move(orphan));

    // Drop the router ownership mapping so find_owner() returns null while orphaned (the closing
    // session may briefly outlive this call). The transfer path then routes through the orphan store;
    // attach_transferred_subscription re-registers the new owner.
    if (auto router = mSubscriptionRouter.lock())
    {
      router->unregister_subscription(id);
    }

    mLogger.info("Subscription {} orphaned (session closed with deleteSubscriptions=false)", id);
  }

  // The orphaned subscriptions are no longer owned by any session; attach_transferred_subscription
  // re-increments these when one is transferred (mirrors detach_subscription_for_transfer).
  if (mSummaryCounters)
  {
    mSummaryCounters->currentSubscriptionCount.fetch_sub(detachedCount, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_sub(detachedCount, std::memory_order_relaxed);
  }

  mAtomicSubscriptionCount.store(0, std::memory_order_relaxed);
  mAtomicTotalMonitoredItemCount.store(0, std::memory_order_relaxed);

  mSubscriptions.clear();
  drain_publish_queue(StatusCode{Status::BadSessionClosed});
}

// --- Notification dispatch ---

void SubscriptionsPipeline::on_subscription_ready(IntegerId /*subscriptionId*/)
{
  request_dispatch();
}

void SubscriptionsPipeline::enqueue_pending_status_change(
  IntegerId subscriptionId, NotificationMessage message)
{
  // Memory fail-safe: a client that creates subscriptions and never sends Publish would otherwise grow
  // this backlog without bound - each expiry parks one StatusChangeNotification AND frees its
  // subscription slot, so mMaxSubscriptionsPerSession never trips. At the cap drop the oldest parked
  // notification (the subscription it referred to has already been deleted), mirroring the evict-oldest
  // policy of mPendingPublishRequests / mRetransmissionQueue. A value of 0 leaves it unbounded.
  while (mMaxPendingStatusChanges > 0 && mPendingStatusChanges.size() >= mMaxPendingStatusChanges)
  {
    mPendingStatusChanges.pop_front();
  }
  mPendingStatusChanges.push_back(PendingStatusChange{subscriptionId, std::move(message)});
}

void SubscriptionsPipeline::on_subscription_expired(IntegerId subscriptionId)
{
  // Part 4, Row 27: IssueStatusChangeNotification with BadTimeout before closing.
  auto it = mSubscriptions.find(subscriptionId);
  if (it != mSubscriptions.end())
  {
    auto scnMessage =
      build_status_change_notification(it->second->get_info().peekSequenceNumber, Status::BadTimeout);
    enqueue_pending_status_change(subscriptionId, std::move(scnMessage));
  }

  delete_subscription(subscriptionId);

  // Try to dispatch the StatusChangeNotification if a Publish request is available.
  request_dispatch();

  if (mSubscriptions.empty() && mPendingStatusChanges.empty())
  {
    drain_publish_queue(StatusCode{Status::BadNoSubscription});
  }
}

bool SubscriptionsPipeline::close_and_remove_subscription(
  IntegerId subscriptionId, std::function<void()> closeCompletion)
{
  auto it = mSubscriptions.find(subscriptionId);
  if (it == mSubscriptions.end())
  {
    return false;
  }

  auto subscription = std::move(it->second);
  const auto monitoredItemCount = subscription->get_info().monitoredItemCount;
  mSubscriptions.erase(it);
  mAtomicSubscriptionCount.fetch_sub(1, std::memory_order_relaxed);
  mAtomicTotalMonitoredItemCount.fetch_sub(monitoredItemCount, std::memory_order_relaxed);

  auto queueEntry = mRetransmissionQueue.begin();
  while (queueEntry != mRetransmissionQueue.end())
  {
    if (queueEntry->subscriptionId == subscriptionId)
      queueEntry = mRetransmissionQueue.erase(queueEntry);
    else
      ++queueEntry;
  }

  if (mSummaryCounters)
  {
    mSummaryCounters->currentSubscriptionCount.fetch_sub(1, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_sub(1, std::memory_order_relaxed);
  }

  // Teardown must run on the Subscription strand. The close completion is the bounded final owner:
  // it keeps the weak-borrowing close turn alive, then releases the Subscription immediately after close.
  auto retainedSubscription = subscription;
  subscription->close_async(
    [retainedSubscription = std::move(retainedSubscription),
      closeCompletion = std::move(closeCompletion)]() mutable
    {
      retainedSubscription.reset();
      if (closeCompletion)
        closeCompletion();
    });
  return true;
}

void SubscriptionsPipeline::delete_subscription(IntegerId subscriptionId)
{
  if (close_and_remove_subscription(subscriptionId))
    mLogger.info("Subscription {} expired and deleted", subscriptionId);
}

// --- Publish dispatch (callback-canonical self-tail-call drain) ---

void SubscriptionsPipeline::request_dispatch()
{
  if (mDispatchInFlight)
  {
    mDispatchNeeded = true;
    return;
  }
  mDispatchInFlight = true;
  mDispatchScheduled = true;  // sticky - see header note
  mDispatchNeeded = false;
  dispatch_one_iteration();
}

void SubscriptionsPipeline::dispatch_one_iteration()
{
  if (mClosed)
  {
    mDispatchInFlight = false;
    return;
  }

  // Phase A: dispatch pending StatusChangeNotifications first (e.g., BadTimeout from
  // lifetime expiry) onto any queued PublishRequests.
  while (!mPendingStatusChanges.empty() && !mPendingPublishRequests.empty())
  {
    auto pending = dequeue_valid_publish_request();
    if (!pending)
      break;

    auto scn = std::move(mPendingStatusChanges.front());
    mPendingStatusChanges.pop_front();

    const uint32_t pendingRequestId = pending->requestId;
    auto pendingRequestHeader = std::move(pending->requestHeader);
    auto pendingAcks = std::move(pending->acknowledgements);

    std::vector<StatusCode> ackResults;
    process_acknowledgements(pendingAcks, ackResults);

    add_to_retransmission_queue(scn.subscriptionId, NotificationMessage{scn.message});

    auto response = std::make_shared<PublishResponse>();
    stack_utils::prepare_response_header(pendingRequestHeader, response->response_header());
    response->subscription_id() = scn.subscriptionId;
    response->more_notifications() = false;
    response->notification_message() = std::move(scn.message);
    response->results() = ackResults;
    mSendResponse(std::make_pair(pendingRequestId, std::move(response)));
  }

  // Phase B: if no subscriptions remain after dispatching status changes, drain
  // remaining publishes with BadNoSubscription and finish this iteration.
  if (mSubscriptions.empty() && mPendingStatusChanges.empty())
  {
    drain_publish_queue(StatusCode{Status::BadNoSubscription});
    finish_dispatch_iteration();
    return;
  }

  // Phase C: select a subscription with notifications ready and issue one
  // fulfill_publish_async. The post-await body runs in on_fulfill_complete,
  // which decides whether to loop (moreNotifications) or finish.
  if (mPendingPublishRequests.empty())
  {
    finish_dispatch_iteration();
    return;
  }

  auto subscription = select_subscription_for_publish();
  if (!subscription)
  {
    finish_dispatch_iteration();
    return;
  }

  auto pending = dequeue_valid_publish_request();
  if (!pending)
  {
    finish_dispatch_iteration();
    return;
  }

  const uint32_t pendingRequestId = pending->requestId;
  auto pendingRequestHeader = std::move(pending->requestHeader);
  auto pendingAcks = std::move(pending->acknowledgements);

  std::vector<StatusCode> ackResults;
  process_acknowledgements(pendingAcks, ackResults);

  mLastDispatchedSubscriptionId = subscription->id();

  const bool publishReqQueued = !mPendingPublishRequests.empty();

  // Issue the only async hop. The post-await body (on_fulfill_complete) runs
  // on the session strand after Subscription::fulfill_publish_async fires its
  // callback.
  subscription->fulfill_publish_async(1,
    publishReqQueued,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [subscription,
        pendingRequestId,
        pendingRequestHeader = std::move(pendingRequestHeader),
        ackResults = std::move(ackResults)](
        SubscriptionsPipeline& self, std::vector<Subscription::PublishResult> results) mutable
      {
        self.on_fulfill_complete(std::move(subscription),
          pendingRequestId,
          std::move(pendingRequestHeader),
          std::move(ackResults),
          std::move(results));
      }));
}

void SubscriptionsPipeline::on_fulfill_complete(std::shared_ptr<Subscription> subscription,
  uint32_t pendingRequestId, RequestHeader pendingRequestHeader, std::vector<StatusCode> ackResults,
  std::vector<Subscription::PublishResult> results)
{
  bool moreNotifications = false;

  if (results.empty())
  {
    // No notification available (race). Build keep-alive response.
    auto response = std::make_shared<PublishResponse>();
    stack_utils::prepare_response_header(pendingRequestHeader, response->response_header());
    response->subscription_id() = subscription->id();
    response->more_notifications() = false;
    response->notification_message().sequence_number() = subscription->get_info().peekSequenceNumber;
    response->notification_message().publish_time() = DateTime::now();
    response->results() = ackResults;
    mSendResponse(std::make_pair(pendingRequestId, std::move(response)));
  }
  else
  {
    auto& result = results[0];

    std::shared_ptr<const Array<String>> diagnosticStringTable;
    if (!result.dataChangeDiagnosticMasks.empty() && mDiagnosticSecurityContext)
    {
      auto notification = std::find_if(result.message.notification_data().begin(),
        result.message.notification_data().end(),
        [](auto& candidate) { return dynamic_cast<DataChangeNotification*>(candidate.get()) != nullptr; });
      if (notification != result.message.notification_data().end())
      {
        auto* dataChange = dynamic_cast<DataChangeNotification*>(notification->get());
        auto& monitoredItems = dataChange->monitored_items();
        auto& diagnosticInfos = dataChange->diagnostic_infos();
        Array<String> stringTable;
        DiagnosticCollector collector{
          diag::serviceLevelMask | diag::operationLevelMask, mDiagnosticSecurityContext()};
        collector.apply_to_notification_items(
          stringTable,
          [&monitoredItems](size_t index)
          {
            const auto& status = monitoredItems[index].value().status();
            return status.value_or(StatusCode{});
          },
          [&result](size_t index) { return result.dataChangeDiagnosticMasks[index]; },
          monitoredItems.size(),
          diagnosticInfos);
        if (!stringTable.empty())
        {
          diagnosticStringTable = std::make_shared<const Array<String>>(std::move(stringTable));
        }
      }
    }

    add_to_retransmission_queue(subscription->id(),
      NotificationMessage{result.message},
      diagnosticStringTable,
      std::move(result.eventProjections),
      std::move(result.dataProjections));

    auto response = std::make_shared<PublishResponse>();
    stack_utils::prepare_response_header(pendingRequestHeader, response->response_header());
    if (diagnosticStringTable)
    {
      response->response_header().string_table() = *diagnosticStringTable;
    }
    response->subscription_id() = subscription->id();
    response->more_notifications() = result.moreNotifications;
    response->notification_message() = std::move(result.message);
    response->results() = ackResults;

    Array<Counter> availableSeqNums;
    for (const auto& entry : mRetransmissionQueue)
    {
      if (entry.subscriptionId == subscription->id())
      {
        availableSeqNums.push_back(entry.message.sequence_number());
      }
    }
    // Part 4 7.25: AvailableSequenceNumbers must be returned in ascending numeric order. The
    // retransmission queue is insertion-ordered, which can diverge from sequence order after a
    // transfer re-homes its queued entries - sort so the list is always monotonically increasing.
    std::sort(availableSeqNums.begin(), availableSeqNums.end());
    response->available_sequence_numbers() = std::move(availableSeqNums);

    mSendResponse(std::make_pair(pendingRequestId, std::move(response)));

    moreNotifications = result.moreNotifications;
  }

  if (moreNotifications)
  {
    // Continue the inner publish loop on a fresh strand turn (post, not
    // dispatch - yields the strand per 11.5). The next iteration restarts
    // Phases A + B + C; both A and B are no-ops in the steady state.
    ua::async::post_borrowing(
      this, mSessionStrand, mLogger, [](SubscriptionsPipeline& self) { self.dispatch_one_iteration(); })();
    return;
  }

  finish_dispatch_iteration();
}

void SubscriptionsPipeline::finish_dispatch_iteration()
{
  // Phase D: update publish-req-queued flag on all subscriptions.
  const bool hasQueued = !mPendingPublishRequests.empty();
  for (auto& [id, sub] : mSubscriptions)
  {
    sub->set_publish_req_queued_async(hasQueued);
  }

  if (mDispatchNeeded)
  {
    // Another request arrived mid-iteration; clear the sentinel and self-tail-
    // call via post so the strand turn yields between iterations (11.5).
    mDispatchNeeded = false;
    ua::async::post_borrowing(
      this, mSessionStrand, mLogger, [](SubscriptionsPipeline& self) { self.dispatch_one_iteration(); })();
    return;
  }

  mDispatchInFlight = false;
}

std::shared_ptr<Subscription> SubscriptionsPipeline::select_subscription_for_publish()
{
  // Priority-based: highest priority first. Within same priority: round-robin.
  std::shared_ptr<Subscription> best;
  uint8_t bestPriority = 0;
  bool pastLastDispatched = false;

  for (auto& [id, sub] : mSubscriptions)
  {
    auto info = sub->get_info();
    // Gate on the publishing-timer-granted send slot, not raw data availability:
    // queued samples are delivered on the next publishing-interval tick, never as
    // an out-of-band response to an arriving Publish request (Part 4 5.13.1).
    if (!info.readyToPublish)
      continue;

    if (info.priority > bestPriority)
    {
      bestPriority = info.priority;
      best = sub;
      pastLastDispatched = (id > mLastDispatchedSubscriptionId);
    }
    else if (info.priority == bestPriority)
    {
      // Round-robin: prefer the first subscription after the last dispatched one.
      if (!pastLastDispatched && id > mLastDispatchedSubscriptionId)
      {
        best = sub;
        pastLastDispatched = true;
      }
      else if (!best)
      {
        best = sub;
      }
    }
  }

  return best;
}

bool SubscriptionsPipeline::publish_request_timed_out(const PendingPublish& pending) const
{
  if (pending.timeoutHint == 0)
    return false;
  return mMonotonicNow() - pending.receivedAt >= std::chrono::milliseconds{pending.timeoutHint};
}

void SubscriptionsPipeline::send_publish_fault(PendingPublish&& pending, StatusCode reason)
{
  auto fault = std::make_shared<ServiceFault>();
  stack_utils::prepare_response_header(pending.requestHeader, fault->response_header());
  fault->response_header().service_result() = reason;

  if (reason.shared_detail())
  {
    // Debug: closing a Session faults every queued Publish, which is routine.
    log_exception(mLogger, LogLevel::Debug, "Publish request rejected", reason);
    DiagnosticCollector collector{pending.requestHeader.return_diagnostics(),
      mDiagnosticSecurityContext ? mDiagnosticSecurityContext() : DiagnosticSecurityContext{}};
    collector.set_service_detail(reason);
    collector.apply_to(fault->response_header());
  }

  mSendResponse(std::make_pair(pending.requestId, std::move(fault)));
}

std::optional<SubscriptionsPipeline::PendingPublish> SubscriptionsPipeline::dequeue_valid_publish_request()
{
  while (!mPendingPublishRequests.empty())
  {
    auto pending = std::move(mPendingPublishRequests.front());
    mPendingPublishRequests.pop_front();
    if (!publish_request_timed_out(pending))
      return pending;

    send_publish_fault(std::move(pending),
      StatusCode{Status::BadTimeout,
        make_error_detail("PublishRequestTimedOut",
          "Publish request timeoutHint elapsed before response processing",
          "SubscriptionsPipeline")});
  }
  return std::nullopt;
}

void SubscriptionsPipeline::process_acknowledgements(
  const std::vector<ua::SubscriptionAcknowledgement>& acks, std::vector<StatusCode>& results)
{
  results.reserve(acks.size());

  for (const auto& ack : acks)
  {
    bool found = false;
    for (auto it = mRetransmissionQueue.begin(); it != mRetransmissionQueue.end(); ++it)
    {
      if (it->subscriptionId == ack.subscription_id() &&
          it->message.sequence_number() == ack.sequence_number())
      {
        mRetransmissionQueue.erase(it);
        found = true;
        break;
      }
    }

    if (found)
    {
      results.push_back(StatusCode{Status::Good});
      refresh_unacknowledged(ack.subscription_id());
    }
    else if (mSubscriptions.find(ack.subscription_id()) == mSubscriptions.end())
    {
      results.push_back(StatusCode{Status::BadSubscriptionIdInvalid});
    }
    else
    {
      results.push_back(StatusCode{Status::BadSequenceNumberUnknown});
    }
  }
}

void SubscriptionsPipeline::drain_publish_queue(StatusCode reason)
{
  // Preserve an existing cause; otherwise describe the local reason for draining the queue.
  std::shared_ptr<const ErrorDetail> detail;
  if (!reason.shared_detail() && reason == StatusCode{Status::BadSessionClosed})
  {
    detail = make_error_detail(
      "SessionClosed", "Publish request rejected because session is closing", "SubscriptionsPipeline");
  }
  else if (!reason.shared_detail() && reason == StatusCode{Status::BadNoSubscription})
  {
    detail = make_error_detail(
      "NoSubscription", "Publish request rejected because no subscriptions remain", "SubscriptionsPipeline");
  }

  if (detail)
    reason = StatusCode{reason.value(), std::move(detail)};

  while (auto pending = dequeue_valid_publish_request())
  {
    send_publish_fault(std::move(*pending), reason);
  }
}

void SubscriptionsPipeline::add_to_retransmission_queue(IntegerId subscriptionId,
  NotificationMessage&& message, std::shared_ptr<const Array<String>> diagnosticStringTable,
  std::vector<RetainedEventProjection> eventProjections, std::vector<RetainedDataProjection> dataProjections)
{
  // Keep-alive messages (no notification data) are not retained.
  if (message.notification_data().empty())
  {
    return;
  }

  // Enforce retransmission queue size. An evicted (never-acknowledged) message counts as discarded
  // for the owning subscription's diagnostics.
  while (mRetransmissionQueue.size() >= mMaxRetransmissionQueueSize)
  {
    const IntegerId discardedSub = mRetransmissionQueue.front().subscriptionId;
    mRetransmissionQueue.pop_front();
    if (auto discardedOwner = find_subscription(discardedSub))
      discardedOwner->record_discarded_message();
    refresh_unacknowledged(discardedSub);
  }

  mRetransmissionQueue.push_back(RetransmissionEntry{subscriptionId,
    std::move(message),
    std::move(diagnosticStringTable),
    std::move(eventProjections),
    std::move(dataProjections)});
  refresh_unacknowledged(subscriptionId);
}

void SubscriptionsPipeline::refresh_unacknowledged(IntegerId subscriptionId)
{
  auto subscription = find_subscription(subscriptionId);
  if (!subscription)
    return;
  uint32_t count = 0;
  for (const auto& entry : mRetransmissionQueue)
  {
    if (entry.subscriptionId == subscriptionId)
      ++count;
  }
  subscription->set_unacknowledged_message_count(count);
}

NotificationMessage SubscriptionsPipeline::build_status_change_notification(
  Counter sequenceNumber, Status status)
{
  auto scn = std::make_unique<StatusChangeNotification>();
  scn->status() = StatusCode{status};

  NotificationMessage message;
  message.sequence_number() = sequenceNumber;
  message.publish_time() = DateTime::now();
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(scn);
  message.notification_data().push_back(std::move(ref));
  return message;
}

void SubscriptionsPipeline::handle_create_monitored_items(
  uint32_t requestId, const CreateMonitoredItemsRequest& request, std::vector<LocaleId> locales)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_create_monitored_items_on_strand(requestId, request, std::move(locales));
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request, locales = std::move(locales)](SubscriptionsPipeline& self) mutable
    { self.handle_create_monitored_items_on_strand(requestId, owned, std::move(locales)); })();
}

void SubscriptionsPipeline::handle_create_monitored_items_on_strand(
  uint32_t requestId, const CreateMonitoredItemsRequest& request, std::vector<LocaleId> locales)
{
  auto subIt = mSubscriptions.find(request.subscription_id());
  if (subIt == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  subIt->second->on_service_call_async();

  if (request.items_to_create().empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (request.timestamps_to_return() >= TimestampsToReturn::Invalid)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadTimestampsToReturnInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (mCapabilities.operationLimits.maxMonitoredItemsPerCall)
  {
    auto limit = *mCapabilities.operationLimits.maxMonitoredItemsPerCall;
    if (limit > 0 && request.items_to_create().size() > limit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadInternalError};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto sub = subIt->second;
  const auto& requestHeader = request.request_header();
  auto* atomicMiCount = &mAtomicTotalMonitoredItemCount;

  // Dispatch to subscription strand via async API; callback fires on subscription strand. The
  // post_borrowing handler hops back to the session strand to build and send the response.
  sub->create_monitored_items_async(request,
    *addressSpace,
    mCapabilities,
    mSubscriptionLimits,
    mSecurityContext.lock(),
    mEventBus,
    mSummaryCounters,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [requestHeader, requestId, atomicMiCount](
        SubscriptionsPipeline& self, std::vector<MonitoredItemCreateResult> results) mutable
      {
        // Count successfully created items and update cross-strand gauge.
        uint32_t addedCount = 0;
        for (const auto& r : results)
        {
          if (r.status_code().is_good())
            ++addedCount;
        }
        if (addedCount > 0)
          atomicMiCount->fetch_add(addedCount, std::memory_order_relaxed);

        auto response = std::make_shared<CreateMonitoredItemsResponse>();
        stack_utils::prepare_response_header(requestHeader, response->response_header());
        for (auto& r : results)
        {
          response->results().push_back(std::move(r));
        }

        self.send_after_monitoring_reflected(std::make_pair(requestId, std::move(response)));
      }),
    std::move(locales));
}

void SubscriptionsPipeline::send_after_monitoring_reflected(Response response)
{
  // Deferred only when the diagnostics describing MonitoredItems are maintained; otherwise (and in unit
  // tests) the response goes as before. The reflection completes on another executor, so the send hops
  // back to the session strand.
  auto router = mSubscriptionRouter.lock();
  if (!router || !router->has_monitoring_reflection_callback())
  {
    mSendResponse(std::move(response));
    return;
  }
  router->when_monitoring_reflected(ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [response = std::move(response)](SubscriptionsPipeline& self) mutable
    { self.mSendResponse(std::move(response)); }));
}

void SubscriptionsPipeline::handle_delete_monitored_items(
  uint32_t requestId, const DeleteMonitoredItemsRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_delete_monitored_items_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_delete_monitored_items_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_delete_monitored_items_on_strand(
  uint32_t requestId, const DeleteMonitoredItemsRequest& request)
{
  auto subIt = mSubscriptions.find(request.subscription_id());
  if (subIt == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  subIt->second->on_service_call_async();

  if (request.monitored_item_ids().empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // SVR-BASE-007: MaxMonitoredItemsPerCall bounds DeleteMonitoredItems like the other MonitoredItem
  // services (SVC-13); the guard is the same shape as the create and modify guards.
  if (mCapabilities.operationLimits.maxMonitoredItemsPerCall)
  {
    const auto limit = *mCapabilities.operationLimits.maxMonitoredItemsPerCall;
    if (limit > 0 && request.monitored_item_ids().size() > limit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations,
        ErrorDetail::build("DeleteMonitoredItemsTooManyOperations",
          "monitoredItemIds exceeds the advertised MaxMonitoredItemsPerCall",
          "SubscriptionsPipeline")
          .context(ua::ContextKeys::actual, std::to_string(request.monitored_item_ids().size()))
          .context(ua::ContextKeys::limit, std::to_string(limit))};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadInternalError};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto sub = subIt->second;
  const auto& requestHeader = request.request_header();
  auto* atomicMiCount = &mAtomicTotalMonitoredItemCount;

  // Copy the monitored item IDs.
  std::vector<IntegerId> monitoredItemIds;
  for (auto& id : request.monitored_item_ids())
  {
    monitoredItemIds.push_back(id);
  }

  // Dispatch to subscription strand via async API; callback fires on subscription strand. The
  // post_borrowing handler hops back to the session strand to build and send the response.
  sub->delete_monitored_items_async(std::move(monitoredItemIds),
    *addressSpace,
    mEventBus,
    mSummaryCounters,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [requestHeader, requestId, atomicMiCount](
        SubscriptionsPipeline& self, std::vector<StatusCode> results) mutable
      {
        // Count successfully deleted items and update cross-strand gauge.
        uint32_t deletedCount = 0;
        for (const auto& r : results)
        {
          if (r.is_good())
            ++deletedCount;
        }
        if (deletedCount > 0)
          atomicMiCount->fetch_sub(deletedCount, std::memory_order_relaxed);

        auto response = std::make_shared<DeleteMonitoredItemsResponse>();
        stack_utils::prepare_response_header(requestHeader, response->response_header());
        for (auto& r : results)
        {
          response->results().push_back(r);
        }

        self.send_after_monitoring_reflected(std::make_pair(requestId, std::move(response)));
      }));
}

// --- ModifyMonitoredItems ---

void SubscriptionsPipeline::handle_modify_monitored_items(
  uint32_t requestId, const ModifyMonitoredItemsRequest& request, std::vector<LocaleId> locales)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_modify_monitored_items_on_strand(requestId, request, std::move(locales));
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request, locales = std::move(locales)](SubscriptionsPipeline& self) mutable
    { self.handle_modify_monitored_items_on_strand(requestId, owned, std::move(locales)); })();
}

void SubscriptionsPipeline::handle_modify_monitored_items_on_strand(
  uint32_t requestId, const ModifyMonitoredItemsRequest& request, std::vector<LocaleId> locales)
{
  auto subIt = mSubscriptions.find(request.subscription_id());
  if (subIt == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  subIt->second->on_service_call_async();

  if (request.items_to_modify().empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (request.timestamps_to_return() >= TimestampsToReturn::Invalid)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadTimestampsToReturnInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (mCapabilities.operationLimits.maxMonitoredItemsPerCall)
  {
    const auto limit = *mCapabilities.operationLimits.maxMonitoredItemsPerCall;
    if (limit > 0 && request.items_to_modify().size() > limit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadInternalError};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto sub = subIt->second;
  const auto& requestHeader = request.request_header();

  // Dispatch to subscription strand via async API; callback fires on subscription strand. The
  // post_borrowing handler hops back to the session strand to build and send the response.
  sub->modify_monitored_items_async(request,
    *addressSpace,
    mCapabilities,
    mSubscriptionLimits,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [requestHeader, requestId](
        SubscriptionsPipeline& self, std::vector<MonitoredItemModifyResult> results) mutable
      {
        auto response = std::make_shared<ModifyMonitoredItemsResponse>();
        stack_utils::prepare_response_header(requestHeader, response->response_header());
        for (auto& r : results)
        {
          response->results().push_back(std::move(r));
        }

        self.send_after_monitoring_reflected(std::make_pair(requestId, std::move(response)));
      }),
    std::move(locales));
}

// --- SetMonitoringMode ---

void SubscriptionsPipeline::handle_set_monitoring_mode(
  uint32_t requestId, const SetMonitoringModeRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_set_monitoring_mode_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_set_monitoring_mode_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_set_monitoring_mode_on_strand(
  uint32_t requestId, const SetMonitoringModeRequest& request)
{
  auto subIt = mSubscriptions.find(request.subscription_id());
  if (subIt == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  subIt->second->on_service_call_async();

  if (request.monitored_item_ids().empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (mCapabilities.operationLimits.maxMonitoredItemsPerCall)
  {
    const auto limit = *mCapabilities.operationLimits.maxMonitoredItemsPerCall;
    if (limit > 0 && request.monitored_item_ids().size() > limit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  // Validate monitoring mode enum.
  auto mode = request.monitoring_mode();
  if (mode != MonitoringMode::Disabled && mode != MonitoringMode::Sampling &&
      mode != MonitoringMode::Reporting)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadMonitoringModeInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  auto sub = subIt->second;
  auto sendResponse = mSendResponse;
  const auto& requestHeader = request.request_header();

  // Copy monitored item IDs.
  std::vector<IntegerId> monitoredItemIds;
  for (auto& id : request.monitored_item_ids())
  {
    monitoredItemIds.push_back(id);
  }

  // Dispatch to subscription strand via async API; callback fires on subscription strand. The
  // post_borrowing handler hops back to the session strand to build and send the response.
  sub->set_monitoring_mode_async(std::move(monitoredItemIds),
    mode,
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [sendResponse, requestHeader, requestId](
        SubscriptionsPipeline&, std::vector<StatusCode> results) mutable
      {
        auto response = std::make_shared<SetMonitoringModeResponse>();
        stack_utils::prepare_response_header(requestHeader, response->response_header());
        for (auto& r : results)
        {
          response->results().push_back(r);
        }

        sendResponse(std::make_pair(requestId, std::move(response)));
      }));
}

// --- SetTriggering ---

void SubscriptionsPipeline::handle_set_triggering(uint32_t requestId, const SetTriggeringRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_set_triggering_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_set_triggering_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_set_triggering_on_strand(
  uint32_t requestId, const SetTriggeringRequest& request)
{
  auto subIt = mSubscriptions.find(request.subscription_id());
  if (subIt == mSubscriptions.end())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadSubscriptionIdInvalid};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Any Service call referencing the SubscriptionId resets its lifetime counter
  // (Part 4 5.13.1.1 h).
  subIt->second->on_service_call_async();

  if (request.links_to_add().empty() && request.links_to_remove().empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  if (mCapabilities.operationLimits.maxMonitoredItemsPerCall)
  {
    const size_t operationLimit = *mCapabilities.operationLimits.maxMonitoredItemsPerCall;
    const size_t addCount = request.links_to_add().size();
    const size_t removeCount = request.links_to_remove().size();
    const bool combinedSizeOverflow = addCount > std::numeric_limits<size_t>::max() - removeCount;
    const size_t operationCount =
      combinedSizeOverflow ? std::numeric_limits<size_t>::max() : addCount + removeCount;
    if (operationLimit > 0 && operationCount > operationLimit)
    {
      auto fault = std::make_shared<ServiceFault>();
      stack_utils::prepare_response_header(request.request_header(), fault->response_header());
      fault->response_header().service_result() = StatusCode{Status::BadTooManyOperations,
        ErrorDetail::build("SetTriggeringTooManyOperations",
          "SetTriggering request exceeds the monitored-item operation limit",
          "SubscriptionsPipeline.set_triggering")
          .context(ContextKeys::sizeActual, operationCount)
          .context(ContextKeys::sizeMax, operationLimit)};
      mSendResponse(std::make_pair(requestId, std::move(fault)));
      return;
    }
  }

  auto sub = subIt->second;
  auto sendResponse = mSendResponse;
  const auto& requestHeader = request.request_header();

  // Copy request data.
  const IntegerId triggeringItemId = request.triggering_item_id();
  std::vector<IntegerId> linksToAdd(request.links_to_add().begin(), request.links_to_add().end());
  std::vector<IntegerId> linksToRemove(request.links_to_remove().begin(), request.links_to_remove().end());

  // Dispatch to subscription strand via async API; callback fires on subscription strand. The
  // post_borrowing handler hops back to the session strand to build and send the response.
  sub->set_triggering_async(triggeringItemId,
    std::move(linksToAdd),
    std::move(linksToRemove),
    ua::async::post_borrowing(this,
      mSessionStrand,
      mLogger,
      [sendResponse, requestHeader, requestId](
        SubscriptionsPipeline&, Subscription::SetTriggeringResult triggerResult) mutable
      {
        // Part 4 Table 79: an invalid triggeringItemId is a service-level result.
        if (triggerResult.triggeringItemInvalid)
        {
          auto fault = std::make_shared<ServiceFault>();
          stack_utils::prepare_response_header(requestHeader, fault->response_header());
          fault->response_header().service_result() = StatusCode{Status::BadMonitoredItemIdInvalid};
          sendResponse(std::make_pair(requestId, std::move(fault)));
          return;
        }

        auto response = std::make_shared<SetTriggeringResponse>();
        stack_utils::prepare_response_header(requestHeader, response->response_header());
        for (auto& r : triggerResult.removeResults)
        {
          response->remove_results().push_back(r);
        }
        for (auto& r : triggerResult.addResults)
        {
          response->add_results().push_back(r);
        }

        sendResponse(std::make_pair(requestId, std::move(response)));
      }));
}

// --- TransferSubscriptions ---

std::optional<SubscriptionsPipeline::DetachResult> SubscriptionsPipeline::detach_subscription_for_transfer(
  IntegerId subscriptionId)
{
  auto it = mSubscriptions.find(subscriptionId);
  if (it == mSubscriptions.end())
    return std::nullopt;

  auto subscription = it->second;

  // Build StatusChangeNotification with GoodSubscriptionTransferred.
  // Add to pending status changes so dispatch_one_iteration can deliver it
  // to a waiting Publish request before the queue is drained.
  auto scnMessage = build_status_change_notification(
    subscription->get_info().peekSequenceNumber, Status::GoodSubscriptionTransferred);
  enqueue_pending_status_change(subscriptionId, std::move(scnMessage));

  // Extract retransmission entries belonging to this subscription.
  std::vector<RetransmissionEntry> transferredEntries;
  auto qIt = mRetransmissionQueue.begin();
  while (qIt != mRetransmissionQueue.end())
  {
    if (qIt->subscriptionId == subscriptionId)
    {
      transferredEntries.push_back(std::move(*qIt));
      qIt = mRetransmissionQueue.erase(qIt);
    }
    else
    {
      ++qIt;
    }
  }

  // Remove from subscriptions map (but don't close - it's being transferred).
  auto detachMiCount = subscription->get_info().monitoredItemCount;
  mSubscriptions.erase(it);
  mAtomicSubscriptionCount.fetch_sub(1, std::memory_order_relaxed);
  mAtomicTotalMonitoredItemCount.fetch_sub(detachMiCount, std::memory_order_relaxed);

  // Update server counters (note: attach_transferred_subscription increments on the new session).
  if (mSummaryCounters)
  {
    mSummaryCounters->currentSubscriptionCount.fetch_sub(1, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_sub(1, std::memory_order_relaxed);
  }

  mLogger.info("Subscription {} detached for transfer", subscriptionId);

  // Try to dispatch any pending StatusChangeNotification to a waiting Publish.
  request_dispatch();

  return DetachResult{std::move(subscription), std::move(transferredEntries)};
}

void SubscriptionsPipeline::attach_transferred_subscription(std::shared_ptr<Subscription> subscription,
  std::vector<RetransmissionEntry> retransmissionEntries, bool sendInitialValues)
{
  auto subId = subscription->id();

  // Re-wire callbacks to this session's strand. post_borrowing captures weak_from_this() internally,
  // keeping this manager alive for the duration of the posted task only.
  Subscription::NotifyReady onReady = ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [](SubscriptionsPipeline& self, IntegerId id) { self.on_subscription_ready(id); });
  Subscription::NotifyExpired onExpired = ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [](SubscriptionsPipeline& self, IntegerId id) { self.on_subscription_expired(id); });

  // Add to subscriptions map. An orphan's MonitoredItems were claimed back against the server-wide
  // gauge by try_transfer_from_orphan_store before it left the store; a direct session-to-session
  // transfer never released them.
  auto transferredMiCount = subscription->get_info().monitoredItemCount;
  mSubscriptions.emplace(subId, subscription);
  mAtomicSubscriptionCount.fetch_add(1, std::memory_order_relaxed);
  mAtomicTotalMonitoredItemCount.fetch_add(transferredMiCount, std::memory_order_relaxed);

  // Merge retransmission entries into new session's queue.
  for (auto& entry : retransmissionEntries)
  {
    mRetransmissionQueue.push_back(std::move(entry));
  }

  // Update server counters.
  if (mSummaryCounters)
  {
    mSummaryCounters->currentSubscriptionCount.fetch_add(1, std::memory_order_relaxed);
    mSummaryCounters->publishingIntervalCount.fetch_add(1, std::memory_order_relaxed);
  }

  // Update registry owner synchronously - the registry is thread-safe and this ensures the
  // ownership transfer is visible immediately without waiting for the subscription strand.
  if (auto router = mSubscriptionRouter.lock())
  {
    router->unregister_subscription(subId);
    router->register_subscription(subId, mOwningSession, subscription);
  }

  // Fire-and-forget to subscription strand: rewire callbacks, reset lifetime, resend initial values.
  subscription->configure_access_recheck(
    mAccessRecheckInterval, mSecurityContext.lock(), mAddressSpace, mEventBus);
  subscription->rewire_callbacks_async(std::move(onReady), std::move(onExpired), mMaxResponseMessageSize);
  subscription->on_service_call_async();
  if (sendInitialValues)
  {
    subscription->resend_initial_values_async();
  }

  mLogger.info("Subscription {} attached after transfer", subId);
}

void SubscriptionsPipeline::handle_transfer_subscriptions(
  uint32_t requestId, const TransferSubscriptionsRequest& request)
{
  // Inline on the strand, a copy only when hopping - see handle_create_subscription.
  if (mSessionStrand.running_in_this_thread())
  {
    handle_transfer_subscriptions_on_strand(requestId, request);
    return;
  }
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [requestId, owned = request](SubscriptionsPipeline& self)
    { self.handle_transfer_subscriptions_on_strand(requestId, owned); })();
}

void SubscriptionsPipeline::handle_transfer_subscriptions_on_strand(
  uint32_t requestId, const TransferSubscriptionsRequest& request)
{
  const auto& ids = request.subscription_ids();

  // 5.3 synchronous-completion path: empty subscription-id list yields
  // BadNothingToDo at the service level (no transfer started).
  if (ids.empty())
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadNothingToDo};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Single-flight gate (5.4.1; pin TR-K): a second TransferSubscriptions
  // arriving while one is in flight is rejected with BadInvalidState. Pre-flip
  // code overwrote mActiveTransferTask without rejection - this flip introduces
  // explicit rejection.
  if (mTransferRunning)
  {
    auto fault = std::make_shared<ServiceFault>();
    stack_utils::prepare_response_header(request.request_header(), fault->response_header());
    fault->response_header().service_result() = StatusCode{Status::BadInvalidState};
    mSendResponse(std::make_pair(requestId, std::move(fault)));
    return;
  }

  // Pre-compute user identity and security context (we're on our strand).
  UserIdentity requestingUser;
  EndpointSecurityContext requestingSecurity;
  if (auto securityContext = mSecurityContext.lock())
  {
    if (auto userPtr = securityContext->user_identity())
      requestingUser = *userPtr;
    if (auto secPtr = securityContext->endpoint_security())
      requestingSecurity = *secPtr;
  }

  auto response = std::make_shared<TransferSubscriptionsResponse>();
  stack_utils::prepare_response_header(request.request_header(), response->response_header());
  response->results().resize(ids.size());

  TransferInputs transferInputs{.subIds = std::vector<IntegerId>(ids.begin(), ids.end()),
    .requestingUser = std::move(requestingUser),
    .requestingSecurity = std::move(requestingSecurity),
    .sendInitialValues = request.send_initial_values(),
    .response = std::move(response),
    .requestId = requestId,
    .requestHeader = request.request_header()};

  mTransferRunning = true;
  mTransferRequestId = transferInputs.requestId;
  mTransferRequestHeader = transferInputs.requestHeader;
  try
  {
    start_transfer(std::move(transferInputs));
  }
  catch (...)
  {
    // The body contains itself; what is left out here is the frame allocation, which happens after
    // the transfer has been marked running and would otherwise latch it.
    fail_transfer(ua::exception_to_status_code(std::current_exception()));
  }
}

/// One TransferSubscriptions, in the order the handler chain walked it.
void SubscriptionsPipeline::start_transfer(TransferInputs inputs)
{
  // A task is EAGER, and a transfer whose every id resolves without asking another session - an
  // unknown id, a self-transfer, one taken from the orphan store - finishes without ever suspending,
  // sending its response before this returns. @see Subscription::start_delete
  const uint64_t generation = ++mTransferGeneration;
  auto transfer = run_transfer(std::move(inputs));
  if (mTransferGeneration == generation)
  {
    mTransferTask = std::move(transfer);
  }
}

ua::async::Task<> SubscriptionsPipeline::run_transfer(TransferInputs inputs)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads. The client's TransferSubscriptions would go unanswered - no response, no fault -
  // and `mTransferRunning` would refuse every later transfer on this Session.
  try
  {
    co_await walk_transfer(inputs);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the transfer and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mTransferRunning)
        {
          fail_transfer(ua::exception_to_status_code(std::current_exception()));
        }
      })();
  }
  co_return;
}

ua::async::Task<> SubscriptionsPipeline::walk_transfer(TransferInputs& inputs)
{
  for (size_t cursor = 0; cursor < inputs.subIds.size(); ++cursor)
  {
    if (!mTransferRunning)
    {
      // Something else ended this transfer and answered its caller.
      co_return;
    }

    const auto subId = inputs.subIds[cursor];

    auto router = mSubscriptionRouter.lock();
    if (!router)
    {
      inputs.response->results()[cursor].status_code() = StatusCode{Status::BadSubscriptionIdInvalid};
      continue;
    }

    auto oldSession = router->find_owner(subId);
    if (!oldSession)
    {
      // No live owner - the subscription may have been orphaned by a CloseSession with
      // deleteSubscriptions=false. Attempt to transfer it out of the orphan store (records Good /
      // BadUserAccessDenied inline); only fall through to BadSubscriptionIdInvalid if it is absent.
      if (!try_transfer_from_orphan_store(inputs, cursor, subId))
      {
        inputs.response->results()[cursor].status_code() = StatusCode{Status::BadSubscriptionIdInvalid};
      }
      continue;
    }

    // Scoped, and that is the whole point of the braces. `mOwningSession` is held WEAKLY on purpose:
    // the Session owns this pipeline, so a strong handle to it that outlived this scope would sit in
    // a coroutine frame the pipeline itself owns, and close the cycle Session -> pipeline -> task ->
    // frame -> Session. Nothing would ever free either of them. That is R7, and the chain this
    // replaces never had to say it: it had no frame, and its continuation captured two scalars.
    // Everything the Session is needed for is answered here, before the await.
    bool sameClient = false;
    {
      auto thisSession = mOwningSession.lock();
      if (oldSession == thisSession)
      {
        // Part 4 section 5.13.1.2, Table 85 transition 22: self-transfer stays
        // refused, but naming the Subscription proves the Client is alive and
        // therefore resets that Subscription's lifetime counter.
        if (auto subscription = find_subscription(subId))
        {
          subscription->on_service_call_async();
        }
        inputs.response->results()[cursor].status_code() = StatusCode{Status::BadNothingToDo};
        continue;
      }

      // Same Client (by ApplicationUri) iff source and target sessions carry the same client app URI.
      sameClient =
        thisSession && (oldSession->client_application_uri() == thisSession->client_application_uri());
    }

    // The detach hops to the SOURCE session's strand and its answer hops back to ours, which is what
    // `await_step`'s post does. The answer is a local here, in a translation unit where `Session` is
    // complete, so nothing has to be decomposed to cross a header boundary.
    auto detached = co_await await_step<Result<Session::SubscriptionDetachResult>>(
      [&oldSession, subId, &inputs](auto completion)
      {
        oldSession->detach_subscription_for_transfer(
          subId, inputs.requestingUser, inputs.requestingSecurity, std::move(completion));
      });

    if (!mTransferRunning)
    {
      co_return;
    }

    // A result that is not Good holds no detached Subscription; an Uncertain one is refused as a Bad one is.
    if (!detached.is_good())
    {
      inputs.response->results()[cursor].status_code() = refusal_of(detached.status_code(),
        "TransferAnswerWithoutSubscription",
        "Detaching the Subscription for transfer answered a status that is neither Good nor Bad, with no "
        "Subscription");
      continue;
    }

    {
      auto value = std::move(detached).value();
      if (!value.subscription)
      {
        inputs.response->results()[cursor].status_code() = StatusCode{Status::BadSubscriptionIdInvalid};
        continue;
      }
      // Rewrite retransmission-entry subscriptionId to ours (the entries came
      // from the source session referencing the source's subId, but now belong
      // to our retransmission queue indexed by the same subId since the
      // subscription kept its IntegerId across the transfer).
      std::vector<RetransmissionEntry> retransmitEntries;
      retransmitEntries.reserve(value.retransmissionEntries.size());
      for (auto& entry : value.retransmissionEntries)
      {
        retransmitEntries.push_back(RetransmissionEntry{subId,
          std::move(entry.message),
          std::move(entry.diagnosticStringTable),
          std::move(entry.eventProjections),
          std::move(entry.dataProjections)});
      }

      // Sync attach on our strand (we're already here).
      attach_transferred_subscription(
        std::move(value.subscription), std::move(retransmitEntries), inputs.sendInitialValues);

      inputs.response->results()[cursor].status_code() = StatusCode{Status::Good};

      // Record transfer diagnostics on the now-attached subscription.
      if (auto transferred = find_subscription(subId))
      {
        transferred->record_transfer_request();
        transferred->record_transferred(sameClient);
      }
      refresh_unacknowledged(subId);
      auto& transferAvailable = inputs.response->results()[cursor].available_sequence_numbers();
      for (const auto& entry : mRetransmissionQueue)
      {
        if (entry.subscriptionId == subId)
        {
          transferAvailable.push_back(entry.message.sequence_number());
        }
      }
      // Part 4 7.25: AvailableSequenceNumbers returned in ascending numeric order.
      std::sort(transferAvailable.begin(), transferAvailable.end());
    }
  }

  // A transferred Subscription's MonitoredItems still hold the previous Session's authorization, which
  // the new Session's identity does not match, so until they are re-authorized every sample - and every
  // sample held while the Subscription had no Session - is withheld. The transfer is answered only once
  // that is done, so the new owner's first Publish cannot overtake it. With sendInitialValues the resend
  // re-authorizes first on its own.
  if (!inputs.sendInitialValues)
  {
    for (size_t cursor = 0; cursor < inputs.subIds.size(); ++cursor)
    {
      if (!inputs.response->results()[cursor].status_code().is_good())
        continue;
      auto subscription = find_subscription(inputs.subIds[cursor]);
      if (!subscription)
        continue;
      auto reauthorized = co_await await_step<VoidResult>([&subscription](auto completion)
        { subscription->reauthorize_after_transfer_async(std::move(completion)); });
      if (!mTransferRunning)
        co_return;
      if (reauthorized.is_bad())
      {
        // The items fail closed on their own; the transfer itself has happened and stands.
        mLogger.warning({{"subscription_id", std::to_string(inputs.subIds[cursor])},
                          {"status", ua::to_string(reauthorized.status_code())}},
          "Re-authorizing a transferred Subscription for its new Session failed");
      }
    }
  }

  if (mTransferRunning)
  {
    finish_transfer(inputs);
  }
  co_return;
}

bool SubscriptionsPipeline::try_transfer_from_orphan_store(
  TransferInputs& inputs, size_t cursor, IntegerId subId)
{
  auto store = mOrphanedSubscriptionStore.lock();
  if (!store)
  {
    return false;
  }

  auto taken = store->take(subId);
  if (!taken)
  {
    return false;
  }

  const auto authorization =
    validate_subscription_transfer(taken->transferContext, inputs.requestingUser, inputs.requestingSecurity);
  if (authorization.is_bad())
  {
    // Leave the subscription available for an authorized transfer attempt.
    store->park(subId, std::move(*taken));
    inputs.response->results()[cursor].status_code() = authorization;
    return true;
  }

  // The parked subscription's MonitoredItems count against the server-wide gauge again once a
  // session owns it. Claim them all or nothing, while it is still parked: a transfer that would
  // push the gauge past MaxMonitoredItems is refused and the orphan stays available.
  if (!taken->subscription->reacquire_server_monitored_item_slots(mCapabilities.maxMonitoredItems))
  {
    store->park(subId, std::move(*taken));
    inputs.response->results()[cursor].status_code() = StatusCode{Status::BadTooManyMonitoredItems,
      ErrorDetail::build("TooManyMonitoredItems",
        "Transferring this Subscription would exceed the server-wide monitored-item limit",
        "SubscriptionsPipeline")
        .context(ua::ContextKeys::subscriptionId, std::to_string(subId))};
    return true;
  }

  auto entries = std::move(taken->retransmissionEntries);
  for (auto& entry : entries)
    entry.subscriptionId = subId;

  attach_transferred_subscription(
    std::move(taken->subscription), std::move(entries), inputs.sendInitialValues);

  inputs.response->results()[cursor].status_code() = StatusCode{Status::Good};

  if (auto transferred = find_subscription(subId))
  {
    transferred->record_transfer_request();
    const bool sameClient =
      taken->transferContext.verifiedApplicationUri == inputs.requestingSecurity.clientApplicationUri;
    transferred->record_transferred(sameClient);
  }
  refresh_unacknowledged(subId);

  auto& available = inputs.response->results()[cursor].available_sequence_numbers();
  for (const auto& entry : mRetransmissionQueue)
  {
    if (entry.subscriptionId == subId)
    {
      available.push_back(entry.message.sequence_number());
    }
  }
  // Part 4 7.25: AvailableSequenceNumbers returned in ascending numeric order.
  std::sort(available.begin(), available.end());
  return true;
}

void SubscriptionsPipeline::release_transfer_slot()
{
  // Whoever gets here first ends the transfer and answers it once - the body on its way out, or
  // `close()` answering for a body that can no longer be asked.
  mTransferRunning = false;
  mTransferRequestId = 0;
  mTransferRequestHeader = RequestHeader{};

  // What the slot pins is the root task's inputs - the client's id list, the identity it was
  // authorized against and the response being built - and nothing would release them until the NEXT
  // transfer overwrote the slot. Released on a later turn, because this is reached from inside that
  // very frame, and guarded by the generation because what follows may start the next transfer.
  ua::async::post_borrowing(this,
    mSessionStrand,
    mLogger,
    [generation = mTransferGeneration](SubscriptionsPipeline& self)
    {
      if (self.mTransferGeneration == generation && !self.mTransferRunning)
      {
        self.mTransferTask = {};
      }
    })();
}

void SubscriptionsPipeline::finish_transfer(TransferInputs& inputs)
{
  // For Transfer there is no component-state delta at the end - each attach already happened inline,
  // as its subscription arrived - so this is the response and its audit event, and nothing else.
  auto requestId = inputs.requestId;
  auto response = std::move(inputs.response);
  auto requestHeader = std::move(inputs.requestHeader);
  const bool auditingEnabled = mAuditingEnabled;
  release_transfer_slot();

  // Emit audit event (Part 4, 6.5.10).
  if (auditingEnabled)
  {
    if (auto eventBus = mEventBus.lock(); eventBus && eventBus->has_event_interest())
    {
      bool allGood = true;
      for (const auto& r : response->results())
      {
        if (StatusCode{r.status_code()}.is_bad())
        {
          allGood = false;
          break;
        }
      }

      AuditSessionEventPayload auditEvent;
      // OPC 10000-5 6.4.7: the SourceNode is the SessionDiagnostics Object of the Session the Subscriptions
      // moved to, which is this pipeline's Session. That Object exists only while diagnostics are enabled
      // (6.3.3); without it the Server Object is the SourceNode, and SessionId still names the Session.
      // This runs on the Session strand, where the Session's diagnostics state may be read.
      auto securityContext = mSecurityContext.lock();
      auto diagnosticsObject = mDiagnosticsObject ? mDiagnosticsObject() : std::nullopt;
      auditEvent.sourceNode = diagnosticsObject ? std::move(*diagnosticsObject) : NodeId{ObjectId::Server};
      auditEvent.sourceName = "Session/TransferSubscriptions";
      auditEvent.actionTimeStamp = Variant{DateTime::now()};
      auditEvent.status = allGood;
      auditEvent.serverId = mApplicationUri;
      auditEvent.clientAuditEntryId = requestHeader.audit_entry_id();
      auditEvent.message = LocalizedText{"", "TransferSubscriptions"};
      auditEvent.severity = 1;
      if (securityContext)
      {
        auditEvent.sessionId = securityContext->session_id();
        if (auto user = securityContext->user_identity())
          auditEvent.clientUserId = user->userId;
      }
      eventBus->emit(auditEvent);
    }
  }

  // mSendResponse internally checks Session liveness - safe to call unconditionally.
  mSendResponse(std::make_pair(requestId, std::move(response)));
}

void SubscriptionsPipeline::fail_transfer(StatusCode status)
{
  // Ends the transfer with a fault instead of a response. Read what the fault needs before ending
  // it, because ending it is what releases that along with everything else.
  if (!mTransferRunning)
  {
    return;
  }
  auto requestId = mTransferRequestId;
  auto requestHeader = mTransferRequestHeader;
  release_transfer_slot();

  auto fault = std::make_shared<ServiceFault>();
  stack_utils::prepare_response_header(requestHeader, fault->response_header());
  fault->response_header().service_result() = status;
  mSendResponse(std::make_pair(requestId, std::move(fault)));
}

}  // namespace ua::server
