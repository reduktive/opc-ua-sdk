// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Local FakeHistoryDelegate fixture for sub-phase 4.5e (HistoryRead/HistoryUpdate)
// behaviour pins.
//
// Local to tests/behaviour_pins/phase_4_5e_history/ per the runbook section 4.0.1
// "each consumer sub-phase ships its own fake" rule. Mirrors the
// NamespaceHistoryDelegate interface as it exists at HEAD.
//
// The fake supports two completion modes:
//   * Inline mode (default) - *_async fires the callback inline on the calling
//     thread. This is what the in-memory default-namespace history delegate
//     would do.
//   * Deferred mode - *_async parks the callback in a queue. The pin drives
//     completion explicitly (from the dedicated worker thread the fake owns
//     when constructed in deferred mode), so the pin can observe the strand
//     boundary that production code crosses on completion.
//
// Test source files include this header. The pin tests do NOT use *_coro or
// Task<> directly - they drive the public service CompleteCallback shape and
// observe the typed response.

#ifndef TESTS_BEHAVIOUR_PINS_PHASE_4_5E_HISTORY_FAKE_HISTORY_DELEGATE_H
#define TESTS_BEHAVIOUR_PINS_PHASE_4_5E_HISTORY_FAKE_HISTORY_DELEGATE_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <vector>

#include "ua_default_namespace.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_namespace_history_delegate.h"
#include "ua_namespace.h"

namespace ua::test::behaviour_pins::phase_4_5e
{

// Forward-declared completion records. The pin grabs these to verify per-item
// correspondence (originalIndex round-trip) and per-call argument capture.

struct ReadRawCall
{
  std::vector<ua::NamespaceHistoryDelegate::ReadRawItem> items;
  ua::NamespaceHistoryDelegate::ReadContext context;
};

struct UpdateDataCall
{
  std::vector<ua::NamespaceHistoryDelegate::UpdateDataItem> items;
  ua::NamespaceHistoryDelegate::UpdateContext context;
};

struct DeleteRawCall
{
  std::vector<ua::NamespaceHistoryDelegate::DeleteRawItem> items;
  ua::NamespaceHistoryDelegate::UpdateContext context;
};

class FakeHistoryDelegate final : public ua::NamespaceHistoryDelegate
{
public:
  enum class Mode
  {
    Inline,  // *_async fires its callback inline before returning.
    Deferred,  // *_async parks the callback; pin drives completion later.
  };

  explicit FakeHistoryDelegate(Mode mode = Mode::Inline);
  ~FakeHistoryDelegate() override;

  // ----- Configuration -----

  // Stages a successful read_raw response: each input item produces a
  // HistoryReadRawSuccess with `values` carrying a single DataValue whose
  // value() == int32_t(item.index). The original-index round-trip pin reads
  // these back out.
  void stage_read_raw_per_item_success();

  // Stages a batch-level failure for the next read_raw call: the returned
  // BatchResult has batchStatus == status and an empty items vector.
  void stage_read_raw_batch_failure(StatusCode status);

  // Stages a per-item-failure result: the returned BatchResult has good
  // batchStatus and items of the same size as the input list, with statuses
  // taken from `perItemStatuses`. The bad ones receive no detail at this layer.
  void stage_read_raw_per_item_statuses(std::vector<StatusCode> perItemStatuses);

  // Stages a successful update_data response: per-item Good with empty
  // operation_results.
  void stage_update_data_per_item_success();

  // Stages an update_data batch-level failure (batchStatus = status).
  void stage_update_data_batch_failure(StatusCode status);

  // Stages a delete_raw batch-level failure (batchStatus = status).
  void stage_delete_raw_batch_failure(StatusCode status);

  // ----- Mode-only helpers (deferred) -----

  // In deferred mode, drives the next parked callback from the fake's worker
  // thread. Returns false if no callback is parked. The thread on which the
  // callback fires is the fake's worker thread, NOT the test thread and NOT
  // any service-strand pool thread.
  bool drive_next_pending();

  // Number of currently-parked callbacks (deferred mode only).
  size_t pending_call_count();

  // A future the MAIN TEST THREAD can wait on until the next callback is parked (satisfied
  // immediately if one already is). Replaces a busy-spin `while (pending_call_count()==0) yield();`
  // poll, which under high shard load burns a core AND starves the very worker that does the
  // parking - so the poll's deadline tripped (the StrandDispatchPin flake). A blocking future wait
  // does neither, and matches the test rule "use std::promise/std::future on the main thread"
  // ("Never block on a pool thread or strand").
  std::future<void> when_parked();

  // The worker thread id (deferred mode only). Used by strand-dispatch pins
  // to assert "the user CompleteCallback does NOT observe this id" - i.e.
  // production code dispatched back to the service strand.
  std::thread::id worker_thread_id() const;

  // ----- Observation -----

  size_t read_raw_call_count();
  size_t update_data_call_count();
  size_t delete_raw_call_count();
  size_t delete_at_time_call_count();
  size_t delete_events_call_count();

  std::vector<ReadRawCall> read_raw_calls();
  std::vector<UpdateDataCall> update_data_calls();
  std::vector<DeleteRawCall> delete_raw_calls();

  // Returns the cancelled-flag pointer captured from the most recent context
  // passed to *_async, or nullptr if none has been seen.
  std::shared_ptr<std::atomic_bool> last_seen_cancelled_flag();

  // ----- NamespaceHistoryDelegate overrides -----

  void read_raw_async(
    const ReadContext& context, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept override;

  void update_data_async(const UpdateContext& context, std::vector<UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override;

  void delete_raw_async(const UpdateContext& context, std::vector<DeleteRawItem> items,
    DeleteRawCallback callback) noexcept override;

  void delete_at_time_async(const UpdateContext& context, std::vector<DeleteAtTimeItem> items,
    DeleteAtTimeCallback callback) noexcept override;

  void delete_events_async(const UpdateContext& context, std::vector<DeleteEventsItem> items,
    DeleteEventsCallback callback) noexcept override;

private:
  enum class StagedReadRawKind
  {
    PerItemSuccess,
    BatchFailure,
    PerItemStatuses,
  };

  struct StagedReadRaw
  {
    StagedReadRawKind kind{StagedReadRawKind::PerItemSuccess};
    StatusCode status{Status::Good};
    std::vector<StatusCode> perItemStatuses;
  };

  enum class StagedUpdateKind
  {
    PerItemSuccess,
    BatchFailure,
  };

  struct StagedUpdate
  {
    StagedUpdateKind kind{StagedUpdateKind::PerItemSuccess};
    StatusCode status{Status::Good};
  };

  // Parked completion in deferred mode. The lambda owns its callback by value
  // ("Safe lambda use" - fakes that fire callbacks from a worker
  // thread must own everything they touch).
  using PendingFn = std::function<void()>;

  void park_or_run(PendingFn fn);
  void worker_loop();

  Mode mMode;

  std::mutex mMutex;
  std::condition_variable mCv;
  // Deferred callbacks remain parked here until drive_next_pending() explicitly moves one to mReady.
  std::queue<PendingFn> mPending;
  std::queue<PendingFn> mReady;
  // Promises handed out by when_parked(); satisfied (and cleared) by park_or_run when it parks.
  std::vector<std::promise<void>> mParkWaiters;
  bool mShuttingDown{false};

  // Deferred-mode worker.
  std::optional<std::thread> mWorker;
  std::thread::id mWorkerId;

  // Per-method staging.
  std::optional<StagedReadRaw> mStagedReadRaw;
  std::optional<StagedUpdate> mStagedUpdateData;
  std::optional<StagedUpdate> mStagedDeleteRaw;

  // Counters / capture.
  size_t mReadRawCalls{0};
  size_t mUpdateDataCalls{0};
  size_t mDeleteRawCalls{0};
  size_t mDeleteAtTimeCalls{0};
  size_t mDeleteEventsCalls{0};

  std::vector<ReadRawCall> mReadRawCallLog;
  std::vector<UpdateDataCall> mUpdateDataCallLog;
  std::vector<DeleteRawCall> mDeleteRawCallLog;

  std::shared_ptr<std::atomic_bool> mLastCancelled;
};

// Test namespace that hosts the fake. Mirrors the HistoryTestNamespace used in
// existing unit tests at tests/unit/server/services/history_read_service_tests.cpp,
// duplicated here so the pin corpus is self-contained per the runbook section 2 scope.
class HistoryPinNamespace : public ua::default_ns::Namespace,
                            public std::enable_shared_from_this<HistoryPinNamespace>
{
public:
  HistoryPinNamespace(std::string_view uri, boost::asio::any_io_executor executor);

  void set_delegate(std::shared_ptr<FakeHistoryDelegate> delegate);

  std::shared_ptr<ua::NamespaceHistoryDelegate> history_delegate() noexcept override;

private:
  std::shared_ptr<FakeHistoryDelegate> mDelegate;
};

}  // namespace ua::test::behaviour_pins::phase_4_5e

#endif  // TESTS_BEHAVIOUR_PINS_PHASE_4_5E_HISTORY_FAKE_HISTORY_DELEGATE_H
