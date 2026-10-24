// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the public @ref ua::client::AlarmConditionTracker value handle and the
///        per-condition @ref ua::client::AlarmHandle (client design section 8.8): move-only shared_ptr pimpls
///        forwarding one-hop to the co-owned @ref ua::client::detail::AlarmConditionTrackerImpl.

#include "ua_alarm_condition_tracker.h"

#include "ua_alarm_condition_tracker_impl.h"
#include "ua_sync_wait.h"
#include "ua_error_detail.h"
#include "ua_status.h"

#include <utility>

namespace ua::client
{

namespace
{
/// The tracker's executor, or empty once it has gone (then a blocking wrapper never refuses, and the
/// operation itself reports the closed tracker).
boost::asio::any_io_executor tracker_executor(const std::weak_ptr<detail::AlarmConditionTrackerImpl>& tracker)
{
  const auto locked = tracker.lock();
  return locked ? locked->executor() : boost::asio::any_io_executor{};
}
}  // namespace

namespace
{
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

VoidResult detached_void()
{
  return VoidResult{StatusCode{Status::BadInvalidState},
    ua::make_error_detail("BadInvalidState",
      "AlarmConditionTracker handle is detached (moved-from / null)",
      "client.tier2.alarm_tracker.detached")};
}

VoidResult tracker_gone()
{
  return VoidResult{StatusCode{Status::BadConnectionClosed},
    ua::make_error_detail(
      "BadConnectionClosed", "AlarmHandle: tracker gone", "client.tier2.alarm_tracker.tracker_gone")};
}

ua::StatusCode metrics_tracker_gone()
{
  return StatusCode{Status::BadConnectionClosed,
    ua::make_error_detail(
      "BadConnectionClosed", "AlarmMetricsView: tracker gone", "client.tier2.alarm_metrics.tracker_gone")};
}
}  // namespace

void AlarmMetricsView::read_all_async(std::function<void(ua::Result<AlarmMetricsSnapshot>)> callback) noexcept
{
  if (auto tracker = mTracker.lock())
  {
    tracker->read_alarm_metrics_async(mMetricsObject, std::move(callback));
    return;
  }
  callback(ua::Result<AlarmMetricsSnapshot>{metrics_tracker_gone()});
}

AlarmMetricsSnapshot AlarmMetricsView::read_all_sync()
{
  return ua::detail::good_value(try_read_all_sync());
}

ua::Result<AlarmMetricsSnapshot> AlarmMetricsView::try_read_all_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<AlarmMetricsSnapshot>>(
    tracker_executor(mTracker), [this](auto completion) { read_all_async(std::move(completion)); });
}

void AlarmMetricsView::reset_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (auto tracker = mTracker.lock())
  {
    tracker->reset_alarm_metrics_async(mMetricsObject, std::move(callback));
    return;
  }
  callback(VoidResult{metrics_tracker_gone()});
}

void AlarmMetricsView::reset_sync()
{
  try_reset_sync().value();
}

ua::VoidResult AlarmMetricsView::try_reset_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) { reset_async(std::move(completion)); });
}

// ============ AlarmHandle ============

void AlarmHandle::acknowledge_async(
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->acknowledge_async(mKey, std::nullopt, std::move(comment), std::move(callback));
}

void AlarmHandle::confirm_async(
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->confirm_async(mKey, std::nullopt, std::move(comment), std::move(callback));
}

void AlarmHandle::add_comment_async(ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->add_comment_async(mKey, std::move(eventId), std::move(comment), std::move(callback));
}

void AlarmHandle::enable_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->enable_async(mKey, std::move(callback));
}

void AlarmHandle::disable_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->disable_async(mKey, std::move(callback));
}

void AlarmHandle::silence_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->silence_async(mKey, std::move(callback));
}

void AlarmHandle::suppress_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->suppress_async(mKey, std::move(callback));
}

void AlarmHandle::unsuppress_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->unsuppress_async(mKey, std::move(callback));
}

void AlarmHandle::shelve_async(
  std::optional<ua::Duration> shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  if (shelvingTime.has_value())
  {
    tracker->timed_shelve_async(mKey, *shelvingTime, std::move(callback));
  }
  else
  {
    tracker->one_shot_shelve_async(mKey, std::move(callback));
  }
}

void AlarmHandle::unshelve_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(tracker_gone());
    return;
  }
  tracker->unshelve_async(mKey, std::move(callback));
}

void AlarmHandle::read_property_async(
  ua::QualifiedName property, std::function<void(ua::Result<ua::Variant>)> callback) noexcept
{
  auto tracker = mTracker.lock();
  if (!tracker)
  {
    callback(ua::Result<ua::Variant>{tracker_gone().status_code(), tracker_gone().shared_detail()});
    return;
  }
  tracker->read_property_async(mKey, std::move(property), std::move(callback));
}

ua::Variant AlarmHandle::read_property_sync(ua::QualifiedName property)
{
  return ua::detail::good_value(try_read_property_sync(std::move(property)));
}

ua::Result<ua::Variant> AlarmHandle::try_read_property_sync(ua::QualifiedName property) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::Variant>>(tracker_executor(mTracker),
    [this, property = std::move(property)](auto completion) mutable
    { read_property_async(std::move(property), std::move(completion)); });
}

// ============ AlarmConditionTracker ============

std::shared_ptr<const AlarmConditionTrackerInfo> AlarmConditionTracker::info() const noexcept
{
  return mImpl ? mImpl->info() : nullptr;
}

void AlarmConditionTracker::on_condition_added_async(
  ConditionAddedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->on_condition_added_async(std::move(cb), std::move(callback));
}

void AlarmConditionTracker::on_condition_changed_async(
  ConditionChangedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->on_condition_changed_async(std::move(cb), std::move(callback));
}

void AlarmConditionTracker::on_condition_removed_async(
  ConditionRemovedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->on_condition_removed_async(std::move(cb), std::move(callback));
}

void AlarmConditionTracker::list_conditions_async(
  std::function<void(ua::Result<std::vector<TrackedCondition>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<TrackedCondition>>{StatusCode{Status::BadInvalidState}});
    return;
  }
  mImpl->list_conditions_async(std::move(callback));
}

void AlarmConditionTracker::get_condition_async(
  TrackedKey key, std::function<void(ua::Result<TrackedCondition>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<TrackedCondition>{StatusCode{Status::BadInvalidState}});
    return;
  }
  mImpl->get_condition_async(std::move(key), std::move(callback));
}

AlarmHandle AlarmConditionTracker::handle(TrackedKey key) const noexcept
{
  return AlarmHandle{mImpl, std::move(key)};
}

AlarmMetricsView AlarmConditionTracker::alarm_metrics(ua::NodeId metricsObject) const noexcept
{
  return AlarmMetricsView{mImpl, std::move(metricsObject)};
}

void AlarmConditionTracker::refresh_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->refresh_async(std::move(callback));
}

void AlarmConditionTracker::acknowledge_async(TrackedKey key, std::optional<ua::LocalizedText> comment,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->acknowledge_async(std::move(key), std::nullopt, std::move(comment), std::move(callback));
}

void AlarmConditionTracker::acknowledge_async(TrackedKey key, ua::ByteString eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->acknowledge_async(std::move(key), std::move(eventId), std::move(comment), std::move(callback));
}

void AlarmConditionTracker::confirm_async(TrackedKey key, std::optional<ua::LocalizedText> comment,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->confirm_async(std::move(key), std::nullopt, std::move(comment), std::move(callback));
}

void AlarmConditionTracker::confirm_async(TrackedKey key, ua::ByteString eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->confirm_async(std::move(key), std::move(eventId), std::move(comment), std::move(callback));
}

void AlarmConditionTracker::add_comment_async(TrackedKey key, ua::ByteString eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->add_comment_async(std::move(key), std::move(eventId), std::move(comment), std::move(callback));
}

void AlarmConditionTracker::enable_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->enable_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::disable_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->disable_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::silence_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->silence_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::suppress_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->suppress_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::unsuppress_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->unsuppress_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::timed_shelve_async(
  TrackedKey key, ua::Duration shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->timed_shelve_async(std::move(key), shelvingTime, std::move(callback));
}

void AlarmConditionTracker::one_shot_shelve_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->one_shot_shelve_async(std::move(key), std::move(callback));
}

void AlarmConditionTracker::unshelve_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void());
    return;
  }
  mImpl->unshelve_async(std::move(key), std::move(callback));
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

void AlarmHandle::acknowledge_sync(std::optional<ua::LocalizedText> comment)
{
  try_acknowledge_sync(std::move(comment)).value();
}

ua::VoidResult AlarmHandle::try_acknowledge_sync(std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(tracker_executor(mTracker),
    [this, comment = std::move(comment)](auto completion) mutable
    { acknowledge_async(std::move(comment), std::move(completion)); });
}

void AlarmHandle::confirm_sync(std::optional<ua::LocalizedText> comment)
{
  try_confirm_sync(std::move(comment)).value();
}

ua::VoidResult AlarmHandle::try_confirm_sync(std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(tracker_executor(mTracker),
    [this, comment = std::move(comment)](auto completion) mutable
    { confirm_async(std::move(comment), std::move(completion)); });
}

void AlarmHandle::add_comment_sync(ua::ByteString eventId, std::optional<ua::LocalizedText> comment)
{
  try_add_comment_sync(std::move(eventId), std::move(comment)).value();
}

ua::VoidResult AlarmHandle::try_add_comment_sync(
  ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(tracker_executor(mTracker),
    [this, eventId = std::move(eventId), comment = std::move(comment)](auto completion) mutable
    { add_comment_async(std::move(eventId), std::move(comment), std::move(completion)); });
}

void AlarmHandle::enable_sync()
{
  try_enable_sync().value();
}

ua::VoidResult AlarmHandle::try_enable_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { enable_async(std::move(completion)); });
}

void AlarmHandle::disable_sync()
{
  try_disable_sync().value();
}

ua::VoidResult AlarmHandle::try_disable_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { disable_async(std::move(completion)); });
}

void AlarmHandle::silence_sync()
{
  try_silence_sync().value();
}

ua::VoidResult AlarmHandle::try_silence_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { silence_async(std::move(completion)); });
}

void AlarmHandle::suppress_sync()
{
  try_suppress_sync().value();
}

ua::VoidResult AlarmHandle::try_suppress_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { suppress_async(std::move(completion)); });
}

void AlarmHandle::unsuppress_sync()
{
  try_unsuppress_sync().value();
}

ua::VoidResult AlarmHandle::try_unsuppress_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { unsuppress_async(std::move(completion)); });
}

void AlarmHandle::shelve_sync(std::optional<ua::Duration> shelvingTime)
{
  try_shelve_sync(std::move(shelvingTime)).value();
}

ua::VoidResult AlarmHandle::try_shelve_sync(std::optional<ua::Duration> shelvingTime) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(tracker_executor(mTracker),
    [this, shelvingTime = std::move(shelvingTime)](auto completion) mutable
    { shelve_async(std::move(shelvingTime), std::move(completion)); });
}

void AlarmHandle::unshelve_sync()
{
  try_unshelve_sync().value();
}

ua::VoidResult AlarmHandle::try_unshelve_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    tracker_executor(mTracker), [this](auto completion) mutable { unshelve_async(std::move(completion)); });
}

void AlarmConditionTracker::on_condition_added_sync(ConditionAddedCb cb)
{
  try_on_condition_added_sync(std::move(cb)).value();
}

ua::VoidResult AlarmConditionTracker::try_on_condition_added_sync(ConditionAddedCb cb) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, cb = std::move(cb)](auto completion) mutable
    { on_condition_added_async(std::move(cb), std::move(completion)); });
}

void AlarmConditionTracker::on_condition_changed_sync(ConditionChangedCb cb)
{
  try_on_condition_changed_sync(std::move(cb)).value();
}

ua::VoidResult AlarmConditionTracker::try_on_condition_changed_sync(ConditionChangedCb cb) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, cb = std::move(cb)](auto completion) mutable
    { on_condition_changed_async(std::move(cb), std::move(completion)); });
}

void AlarmConditionTracker::on_condition_removed_sync(ConditionRemovedCb cb)
{
  try_on_condition_removed_sync(std::move(cb)).value();
}

ua::VoidResult AlarmConditionTracker::try_on_condition_removed_sync(ConditionRemovedCb cb) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, cb = std::move(cb)](auto completion) mutable
    { on_condition_removed_async(std::move(cb), std::move(completion)); });
}

std::vector<TrackedCondition> AlarmConditionTracker::list_conditions_sync()
{
  return ua::detail::good_value(try_list_conditions_sync());
}

ua::Result<std::vector<TrackedCondition>> AlarmConditionTracker::try_list_conditions_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<TrackedCondition>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { list_conditions_async(std::move(completion)); });
}

TrackedCondition AlarmConditionTracker::get_condition_sync(TrackedKey key)
{
  return ua::detail::good_value(try_get_condition_sync(std::move(key)));
}

ua::Result<TrackedCondition> AlarmConditionTracker::try_get_condition_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<TrackedCondition>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { get_condition_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::refresh_sync()
{
  try_refresh_sync().value();
}

ua::VoidResult AlarmConditionTracker::try_refresh_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_async(std::move(completion)); });
}

void AlarmConditionTracker::acknowledge_sync(TrackedKey key, std::optional<ua::LocalizedText> comment)
{
  try_acknowledge_sync(std::move(key), std::move(comment)).value();
}

ua::VoidResult AlarmConditionTracker::try_acknowledge_sync(
  TrackedKey key, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), comment = std::move(comment)](auto completion) mutable
    { acknowledge_async(std::move(key), std::move(comment), std::move(completion)); });
}

void AlarmConditionTracker::acknowledge_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment)
{
  try_acknowledge_sync(std::move(key), std::move(eventId), std::move(comment)).value();
}

ua::VoidResult AlarmConditionTracker::try_acknowledge_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
      auto completion) mutable
    { acknowledge_async(std::move(key), std::move(eventId), std::move(comment), std::move(completion)); });
}

void AlarmConditionTracker::confirm_sync(TrackedKey key, std::optional<ua::LocalizedText> comment)
{
  try_confirm_sync(std::move(key), std::move(comment)).value();
}

ua::VoidResult AlarmConditionTracker::try_confirm_sync(
  TrackedKey key, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), comment = std::move(comment)](auto completion) mutable
    { confirm_async(std::move(key), std::move(comment), std::move(completion)); });
}

void AlarmConditionTracker::confirm_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment)
{
  try_confirm_sync(std::move(key), std::move(eventId), std::move(comment)).value();
}

ua::VoidResult AlarmConditionTracker::try_confirm_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
      auto completion) mutable
    { confirm_async(std::move(key), std::move(eventId), std::move(comment), std::move(completion)); });
}

void AlarmConditionTracker::add_comment_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment)
{
  try_add_comment_sync(std::move(key), std::move(eventId), std::move(comment)).value();
}

ua::VoidResult AlarmConditionTracker::try_add_comment_sync(
  TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
      auto completion) mutable
    { add_comment_async(std::move(key), std::move(eventId), std::move(comment), std::move(completion)); });
}

void AlarmConditionTracker::enable_sync(TrackedKey key)
{
  try_enable_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_enable_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { enable_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::disable_sync(TrackedKey key)
{
  try_disable_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_disable_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { disable_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::silence_sync(TrackedKey key)
{
  try_silence_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_silence_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { silence_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::suppress_sync(TrackedKey key)
{
  try_suppress_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_suppress_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { suppress_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::unsuppress_sync(TrackedKey key)
{
  try_unsuppress_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_unsuppress_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { unsuppress_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::timed_shelve_sync(TrackedKey key, ua::Duration shelvingTime)
{
  try_timed_shelve_sync(std::move(key), std::move(shelvingTime)).value();
}

ua::VoidResult AlarmConditionTracker::try_timed_shelve_sync(
  TrackedKey key, ua::Duration shelvingTime) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key), shelvingTime = std::move(shelvingTime)](auto completion) mutable
    { timed_shelve_async(std::move(key), std::move(shelvingTime), std::move(completion)); });
}

void AlarmConditionTracker::one_shot_shelve_sync(TrackedKey key)
{
  try_one_shot_shelve_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_one_shot_shelve_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { one_shot_shelve_async(std::move(key), std::move(completion)); });
}

void AlarmConditionTracker::unshelve_sync(TrackedKey key)
{
  try_unshelve_sync(std::move(key)).value();
}

ua::VoidResult AlarmConditionTracker::try_unshelve_sync(TrackedKey key) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, key = std::move(key)](auto completion) mutable
    { unshelve_async(std::move(key), std::move(completion)); });
}

}  // namespace ua::client
