// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SAMPLE_SINK_IMPL_H
#define UA_SAMPLE_SINK_IMPL_H

#include "ua_logger.h"
#include "ua_sinks.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <mutex>
#include <memory>

namespace ua::server
{

class SessionSecurityContext;
class Subscription;

/// Posts sample batches from any thread to the subscription strand.
/// Holds a weak_ptr to the Subscription - safe if subscription is destroyed.
class SampleSinkImpl : public SampleSink, public std::enable_shared_from_this<SampleSinkImpl>
{
public:
  SampleSinkImpl(
    std::weak_ptr<Subscription> subscription, boost::asio::strand<boost::asio::any_io_executor> strand)
    : mSubscription(std::move(subscription)), mSubscriptionStrand(std::move(strand))
  {}

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override;

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override;

  void mark_semantics_changed(IntegerId monitoredItemId) override;

  void mark_structure_changed(IntegerId monitoredItemId) override;

  void detach() override;

  /// The current caller of the Session whose security context the Subscription was last given (NR-49): asked of
  /// that context each time, so a user change or a Role refresh is seen at once. Null before the Subscription
  /// is given a context, or once that context has gone.
  std::shared_ptr<const CallerInfo> caller() const override;

  /// The security context of the Session that owns the Subscription, replaced when a transfer gives it another
  /// Session. Held weakly: the Session owns its context.
  void set_security_context(std::weak_ptr<SessionSecurityContext> securityContext);

  /// Seeds the logger used to guard the strand posts. Set once by the owning Subscription right after
  /// construction (see Subscription::set_logger), before any sampling happens. A ua::Logger is a value
  /// handle that survives teardown.
  void set_logger(ua::Logger logger)
  {
    mLogger = std::move(logger);
  }

private:
  std::weak_ptr<Subscription> mSubscription;
  boost::asio::strand<boost::asio::any_io_executor> mSubscriptionStrand;
  std::atomic<bool> mDetached{false};
  mutable std::mutex mSecurityContextMutex;
  std::weak_ptr<SessionSecurityContext> mSecurityContext;
  ua::Logger mLogger;
};

}  // namespace ua::server

#endif  // !UA_SAMPLE_SINK_IMPL_H
