// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace whose monitoring calls are recorded and scripted.

#ifndef UA_TEST_MONITORING_RECORDING_NAMESPACE_H
#define UA_TEST_MONITORING_RECORDING_NAMESPACE_H

#include "ua_default_namespace.h"
#include "ua_namespace_monitoring.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace ua::test
{

/// A namespace that keeps the default namespace's real node store - so a Subscription can look its Nodes up,
/// authorize them and read their initial values - but answers the monitoring calls itself, as the test
/// scripts, and records them:
///
/// - `create_monitoring_async` issues handles from a counter (or from a list the test gives), and can hold
///   its answer back, answer twice, answer one result short, throw, or answer and then throw. An answer is
///   given on the thread that calls `create_monitoring_async`, or, when held, on the thread that releases it.
/// - `delete_monitoring_async` records the handles of each call and answers Good for each, inline; its
///   answers can be held back, answered with a bad status, or replaced by a throw.
/// - `modify_monitoring_async` answers each item with the sampling interval it was given, inline.
/// - an item of either answer can instead be answered with a status the test gives and no result
///   (@ref answer_next_create_items, @ref answer_next_modify_items).
///
/// - a read of a Variable's Value, as a Subscription makes it for an item's initial value, can be held back
///   (@ref hold_value_reads) and answered later, on the namespace's executor.
///
/// No value is ever sampled: the handles name no real registration.
class MonitoringRecordingNamespace final : public default_ns::Namespace
{
public:
  /// How `create_monitoring_async` answers.
  enum class CreateAnswer
  {
    Issue,  ///< One answer with a handle for every item, on the calling thread.
    Hold,  ///< The same answer, held back until @ref release_create_answers.
    IssueTwice,  ///< Two answers, one after the other, each with a new handle for every item.
    Throw,  ///< Throws `UaException` with the status given to @ref answer_creates, answering nothing.
    IssueThenThrow,  ///< One answer, then throws as for Throw.
    OmitLast,  ///< One answer, without a result for the last item.
  };

  static std::shared_ptr<MonitoringRecordingNamespace> create(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle = 1);

  /// How later `create_monitoring_async` calls answer; @p thrown is the status a throwing mode throws.
  void answer_creates(CreateAnswer how, StatusCode thrown = StatusCode{Status::BadResourceUnavailable});

  /// The handles the next answers issue, in order, before the counter is used again.
  void issue_next(std::vector<MonitoringHandle> handles);

  /// How the next items `create_monitoring_async` answers are answered, in order: an entry holding a status
  /// answers its item with that status and no result, and issues no handle; an empty entry issues a handle.
  void answer_next_create_items(std::vector<std::optional<StatusCode>> results);

  /// How the next items `modify_monitoring_async` answers are answered, in order: an entry holding a status
  /// answers its item with that status and no result; an empty entry answers the sampling interval it was
  /// given.
  void answer_next_modify_items(std::vector<std::optional<StatusCode>> results);

  /// The `create_monitoring_async` calls received so far.
  std::size_t create_calls() const;

  /// The locales of the `RequestInfo` each `create_monitoring_async` call took, one entry per call, in order.
  std::vector<std::vector<LocaleId>> create_locales() const;

  /// The locales of the `RequestInfo` each `modify_monitoring_async` call took, one entry per call, in order.
  std::vector<std::vector<LocaleId>> modify_locales() const;

  /// The `create_monitoring_async` answers held back now.
  std::size_t held_create_answers() const;

  /// Delivers every held `create_monitoring_async` answer on the calling thread, in order.
  void release_create_answers();

  /// Holds back the answers to later `delete_monitoring_async` calls until @ref release_delete_answers.
  void hold_delete_answers();

  /// The `delete_monitoring_async` answers held back now.
  std::size_t held_delete_answers() const;

  /// Delivers every held `delete_monitoring_async` answer on the calling thread.
  void release_delete_answers();

  /// Later `delete_monitoring_async` calls answer @p batchStatus for the whole batch.
  void fail_deletes(StatusCode batchStatus);

  /// Later `delete_monitoring_async` calls throw `UaException` with @p status.
  void throw_from_deletes(StatusCode status);

  /// Every handle an answer issued, in order.
  std::vector<MonitoringHandle> issued_handles() const;

  /// The handles each `delete_monitoring_async` call named, one entry per call, in order.
  std::vector<std::vector<MonitoringHandle>> delete_calls() const;

  /// Every handle named by a `delete_monitoring_async` call, in order.
  std::vector<MonitoringHandle> released_handles() const;

  /// Holds back the answers to the reads of a Value this namespace answers from now on, item by item, until
  /// @ref release_value_reads.
  void hold_value_reads();

  /// The answers to reads of a Value held back now.
  std::size_t held_value_reads() const;

  /// Stops holding reads of a Value and delivers every held answer on the namespace's executor.
  void release_value_reads();

  /// Whether a `delete_monitoring_async` call was entered while one of this namespace's
  /// `create_monitoring_async` calls, or one of its answers, was still on the stack of the same thread.
  bool deleted_inside_a_create_answer() const;

  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override;
  void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override;
  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override;

  /// Reads each Value through the in-memory member, one item at a time, holding back each item's answer
  /// while @ref hold_value_reads is in force.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;

  /// The answers to Value reads held back, shared with the reads in flight.
  struct ValueReadHold;

private:
  using CreateMonitoringCallback = std::function<void(BatchResult<MonitoringCreateItemResult>)>;

  MonitoringRecordingNamespace(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle);

  /// An answer issuing a new handle for each of @p count items. Called with the mutex held.
  BatchResult<MonitoringCreateItemResult> issue_locked(std::size_t count);

  /// Invokes @p callback with @p answer, marking this thread as inside a create answer meanwhile.
  static void deliver_create(
    const CreateMonitoringCallback& callback, BatchResult<MonitoringCreateItemResult> answer);

  mutable std::mutex mMutex;
  CreateAnswer mCreateAnswer{CreateAnswer::Issue};
  StatusCode mThrown{Status::BadResourceUnavailable};
  MonitoringHandle mNextHandle;
  std::deque<MonitoringHandle> mScriptedHandles;
  std::deque<std::optional<StatusCode>> mScriptedCreateItems;
  std::deque<std::optional<StatusCode>> mScriptedModifyItems;
  std::size_t mCreateCalls{0};
  std::vector<std::vector<LocaleId>> mCreateLocales;
  std::vector<std::vector<LocaleId>> mModifyLocales;
  std::vector<std::function<void()>> mHeldCreateAnswers;
  bool mHoldDeleteAnswers{false};
  std::vector<std::function<void()>> mHeldDeleteAnswers;
  std::optional<StatusCode> mDeleteFailure;
  std::optional<StatusCode> mDeleteThrow;
  std::vector<MonitoringHandle> mIssued;
  std::vector<std::vector<MonitoringHandle>> mDeleteCalls;
  bool mDeletedInsideCreateAnswer{false};
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<ValueReadHold> mValueReadHold;
};

}  // namespace ua::test

#endif  // UA_TEST_MONITORING_RECORDING_NAMESPACE_H
