// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Local fixture for sub-phase 4.5c (RegisterNodesServiceSet) pin tests.
//
// FakeRegisterNodesNamespace is a subclass of default_ns::Namespace that also
// implements NamespaceRegisterNodesDelegate. It lets pin tests stage per-call
// responses (BatchResult<NodeId> for register, VoidResult for unregister) and
// optionally defer their delivery to a dedicated worker thread.
//
// This file is local to phase_4_5c_register_nodes - see runbook section 4.0.1 ("each
// consumer sub-phase ships its own fake"). It must NOT be promoted to
// tests/helpers/ without an explicit Phase 9 cleanup PR.
//
// Lifetime:
//   - In synchronous mode (the default), every register/unregister call fires
//     its callback inline on the calling strand using the staged response.
//   - In deferred mode, every call parks the callback in a queue. Tests drive
//     them by calling complete_pending() (which forwards the call to the
//     dedicated worker thread that owns the parked callbacks) or
//     complete_pending_inline() (which fires synchronously on the test thread).
//   - The destructor signals the worker thread to exit and joins it. The
//     fixture must destroy the namespace BEFORE the boost::asio::thread_pool stops.

#ifndef PHASE_4_5C_FAKE_REGISTER_NODES_DELEGATE_H
#define PHASE_4_5C_FAKE_REGISTER_NODES_DELEGATE_H

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "ua_default_namespace.h"
#include "ua_namespace_service_delegates.h"

namespace ua::test::behaviour_pins::phase_4_5c
{

class FakeRegisterNodesNamespace : public ua::default_ns::Namespace,
                                   public ua::NamespaceRegisterNodesDelegate,
                                   public std::enable_shared_from_this<FakeRegisterNodesNamespace>
{
public:
  /// \param uri  Namespace URI.
  /// \param ex   boost::asio::any_io_executor for the underlying default namespace machinery.
  /// \param deferred  If true, every register/unregister call parks its
  ///                  callback in a queue and fires only when complete_pending()
  ///                  is called. The dedicated worker thread fires the parked
  ///                  callbacks. If false, callbacks fire inline on the calling
  ///                  thread using the staged response.
  static std::shared_ptr<FakeRegisterNodesNamespace> create(
    ua::string_view uri, boost::asio::any_io_executor ex, bool deferred);

  ~FakeRegisterNodesNamespace() override;

  // --- ua::Namespace override ----------------------------------------------

  std::shared_ptr<ua::NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override;

  // --- NamespaceRegisterNodesDelegate overrides ----------------------------

  void register_nodes_async(
    const Context& context, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override;

  void unregister_nodes_async(
    const Context& context, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept override;

  // --- Test-side staging API ------------------------------------------------

  /// Stage the next register-call response. The next register_nodes_async
  /// invocation pops this batch from the front of the queue. If empty, the
  /// fake returns batchStatus = Good with mapped placeholder NodeIds.
  void push_register_response(ua::BatchResult<ua::NodeId> response);

  /// Stage the next unregister-call response.
  void push_unregister_response(ua::VoidResult response);

  /// Number of currently parked (deferred) callbacks. Always 0 in inline mode.
  size_t pending_call_count() const;

  /// Drive every parked callback via the dedicated worker thread. Blocks until
  /// every parked callback at the time of call has been dispatched (the worker
  /// thread executes them in FIFO order).
  void drain_pending_via_worker();

  /// std::thread::id of the dedicated worker thread (deferred mode only).
  /// Returns the default-constructed id if the fake is in inline mode.
  std::thread::id worker_thread_id() const;

  /// Captures every Item.nodeId seen in register_nodes_async, in invocation order.
  std::vector<ua::NodeId> register_call_items() const;

private:
  FakeRegisterNodesNamespace(ua::string_view uri, boost::asio::any_io_executor ex, bool deferred);

  void start_worker();
  void stop_worker();
  void worker_loop();

  const bool mDeferred;

  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::deque<std::function<void()>> mPending;  // parked callbacks (deferred mode only)
  std::deque<ua::BatchResult<ua::NodeId>> mNextRegisterResponses;
  std::deque<ua::VoidResult> mNextUnregisterResponses;
  std::vector<ua::NodeId> mObservedItems;
  bool mShutdown{false};

  std::thread mWorker;
  std::thread::id mWorkerId{};
};

}  // namespace ua::test::behaviour_pins::phase_4_5c

#endif  // PHASE_4_5C_FAKE_REGISTER_NODES_DELEGATE_H
