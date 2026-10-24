// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// FakeAsyncNamespace - per-method opt-in deferring `Namespace` test fake.
//
//
// Behavioural shape (option B per-method opt-in deferral, locked 2026-05-05):
//
//   - Each of the six lookup, creation, deletion and monitoring members
//     (find_nodes_async, create_nodes_async, delete_nodes_async,
//     create_monitoring_async, delete_monitoring_async,
//     modify_monitoring_async) starts in inline mode. The user callback fires
//     on the calling thread carrying the next staged canned result. A lookup,
//     creation or deletion takes one canned result per item.
//
//   - A pin opts an op into deferral via set_<op>_deferred(true). Deferred
//     calls park the user callback on a per-fake queue and the pin must
//     drive complete_pending() to fire it on the dedicated worker thread.
//     A lookup, creation or deletion parks one callback per item; the batch
//     completes once every item has fired.
//
//   - The dedicated worker thread is owned by the fake (started in
//     create(), joined in ~FakeAsyncNamespace). Callbacks fire on this
//     thread when deferred, NEVER on a thread serviced by a production
//     boost::asio::thread_pool. This is required for strand-dispatch pins
//     (SD-B/D/E): with the worker on its own thread, a user callback's
//     std::this_thread::get_id() observation is distinguishable from the
//     calling thread.
//
//   - Canned results are FIFO: each set_next_<op>_result() pushes to the
//     back; each call to <op> pops the front. Calling <op> with an empty
//     canned-result queue fires a BadInternalError result with an
//     ErrorDetail that flags the pin-author bug ("FakeMissingCannedResult").
//     A lookup of a NodeId given to hold() answers the held Node instead.
//
//   - Recorded calls are appended in invocation order and exposed via
//     recorded_calls() for argument-forwarding pins. The recorded
//     metadata is intentionally minimal - pins that need richer recording
//     can extend the fixture or use std::promise to capture the relevant
//     argument inside the canned-result-firing path.
//
//   - The members that act on a Node (read_references_async,
//     read_values_async, write_async, call_async, view_contains_async,
//     add_to_view_async, add_references_async, remove_references_async)
//     always answer inline. Each item takes the next answer staged for its
//     Node with a set_next_*(nodeId, ...) setter and is recorded under that
//     NodeId, for the recorded_*(nodeId) accessors; they are not in
//     recorded_calls(). The Node an item is keyed by: a Reference query's
//     Node, a Value read's or write's Node, a call's Method, a View
//     membership question's or addition's View, a Reference change's source.

#ifndef UA_TEST_BEHAVIOUR_PINS_FAKE_ASYNC_NAMESPACE_H
#define UA_TEST_BEHAVIOUR_PINS_FAKE_ASYNC_NAMESPACE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_duration.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_read_value_id.h"
#include "ua_write_value.h"

namespace ua::test::behaviour_pins
{

class FakeAsyncNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
  }
  enum class Op
  {
    FindNode,
    CreateNode,
    DeleteNode,
    CreateMonitoring,
    DeleteMonitoring,
    ModifyMonitoring,
  };

  /// One recorded invocation. Ordered by call site; one per item for the lookup, creation and deletion.
  struct RecordedCall
  {
    Op op;
    NodeId nodeId;  // find/create/delete; default-constructed otherwise
    NodeClass nodeClass{NodeClass::Unspecified};  // create only
    std::size_t itemCount{0};  // monitoring ops only
  };

  // --- Recorded operations on a Node, per NodeId ---

  /// One Reference half added at the source it is recorded under.
  struct AddReferenceCall
  {
    NodeId type;
    ExpandedNodeId target;
    bool isForward;
  };

  /// One Reference half removed at the source it is recorded under.
  struct RemoveReferenceCall
  {
    NodeId type;
    ExpandedNodeId target;
    bool isForward;
  };

  struct CallCall
  {
    CallMethodRequest methodToCall;
    bool hasContext{false};
  };

  struct ReadValueCall
  {
    Duration maxAge{0};
    bool setSourceTimestamp{false};
    ReadValueId nodeToRead;
  };

  struct WriteValueCall
  {
    WriteValue writeValue;
  };

  /// One membership question asked of the View it is recorded under.
  struct IsNodeInViewCall
  {
    ExpandedNodeId nodeId;  // the candidate
  };

  /// One Node added to the View it is recorded under.
  struct AddNodeToViewCall
  {
    NodeId nodeId;  // the Node added
  };

  /// One Reference query; the whole-set read is a query with maxReferences 0 and no token.
  struct GetReferencesPageCall
  {
    uint32_t maxReferences{0};
    ByteString continuationToken;
  };

  /// Construct + spawn the dedicated worker thread.
  static std::shared_ptr<FakeAsyncNamespace> create(std::string uri);

  ~FakeAsyncNamespace() override;

  FakeAsyncNamespace(const FakeAsyncNamespace&) = delete;
  FakeAsyncNamespace& operator=(const FakeAsyncNamespace&) = delete;

  // --- Deferral controls ---------------------------------------------------

  void set_find_node_deferred(bool deferred);
  void set_create_node_deferred(bool deferred);
  void set_delete_node_deferred(bool deferred);
  void set_create_monitoring_deferred(bool deferred);
  void set_delete_monitoring_deferred(bool deferred);
  void set_modify_monitoring_deferred(bool deferred);

  // --- Per-op canned results (FIFO queues) --------------------------------

  void set_next_find_node_result(NodeResult result);
  void set_next_create_node_result(NodeResult result);
  void set_next_delete_node_result(DeleteNodeResult result);
  void set_next_create_monitoring_result(BatchResult<MonitoringCreateItemResult> result);
  void set_next_delete_monitoring_result(BatchResult<VoidResult> result);
  void set_next_modify_monitoring_result(BatchResult<MonitoringModifyItemResult> result);

  /// Every later lookup of @p nodeId answers @p node, without taking a staged find_node result. The lookup
  /// is still recorded and deferred like any other.
  void hold(const NodeId& nodeId, std::shared_ptr<Node> node);

  // --- Per-NodeId canned answers of the operations on a Node (FIFO queues) ---

  /// The next Reference query of @p nodeId answers @p result, every Reference and no resume token.
  void set_next_get_references(const NodeId& nodeId, NodeAccessor::ReferencesResult result);
  /// The next Reference query of @p nodeId answers the page @p result, with its continuation token.
  void set_next_get_references_page(const NodeId& nodeId, NodeAccessor::ReferencesPageResult result);
  /// The next Reference half added at @p source answers @p result.
  void set_next_add_reference(const NodeId& source, VoidResult result);
  /// The next Reference half removed at @p source answers @p result.
  void set_next_remove_reference(const NodeId& source, VoidResult result);
  /// The next call of the Method @p method answers @p result. A call of a Method with no staged answer is
  /// declined and not recorded.
  void set_next_call(const NodeId& method, CallResult result);
  void set_next_read_value(const NodeId& nodeId, DataValueResult result);
  /// The next write of the Value of @p nodeId answers @p result. A write of any other Attribute answers Good
  /// and is not recorded.
  void set_next_write_value(const NodeId& nodeId, VoidResult result);
  /// The next membership question asked of the View @p view answers @p result.
  void set_next_is_node_in_view(const NodeId& view, BoolResult result);
  /// The next Node added to the View @p view answers @p result.
  void set_next_add_node_to_view(const NodeId& view, VoidResult result);

  // --- Pending-call introspection -----------------------------------------

  /// Number of parked deferred callbacks awaiting complete_pending().
  std::size_t pending_call_count() const;

  /// Spin (with sleep) up to `timeout` waiting for `pending_call_count() >= n`.
  /// Returns true if the condition was met, false on timeout. Use this when
  /// driving multi-step flows where a continuation parks its own callback
  /// asynchronously on the worker thread.
  bool wait_for_pending(std::size_t n, std::chrono::milliseconds timeout = std::chrono::seconds(2)) const;

  /// Release the next parked callback to the worker thread (FIFO). Throws
  /// std::runtime_error if no callback is parked - surfaces pin-author
  /// ordering bugs.
  void complete_pending();

  /// Release every parked callback. Returns the count released.
  std::size_t complete_all_pending();

  /// Block until the worker is idle: no parked callbacks awaiting release and
  /// no fire() in flight (including the post-fire destructor cascade for the
  /// captured callback chain).
  ///
  /// Tests that drive deferred fakes through a multi-step flow MUST call
  /// wait_idle() after the final user callback has fired and before they
  /// allow the test fixture (which owns the AddressSpace) to tear down. The
  /// final fire's captured callback chain may hold the last shared_ptr ref
  /// to AddressSpaceImpl; the cascade releases it on this worker thread.
  /// wait_idle() guarantees the cascade completes before the fixture's
  /// owning ref is dropped, so AddressSpace destruction (and the ensuing
  /// NamespaceArray -> fake destruction) happens on the test thread, not on
  /// the worker. Without this, ~FakeAsyncNamespace runs on its own worker
  /// thread -> mWorker.join() self-EDEADLKs.
  void wait_idle() const;

  std::thread::id worker_thread_id() const noexcept;

  std::vector<RecordedCall> recorded_calls() const;

  // --- Recorded operations on a Node (copies) ------------------------------

  std::size_t recorded_get_references_count(const NodeId& nodeId) const;
  std::vector<GetReferencesPageCall> recorded_get_references_page_calls(const NodeId& nodeId) const;
  std::vector<AddReferenceCall> recorded_add_reference_calls(const NodeId& source) const;
  std::vector<RemoveReferenceCall> recorded_remove_reference_calls(const NodeId& source) const;
  std::vector<CallCall> recorded_call_calls(const NodeId& method) const;
  std::vector<ReadValueCall> recorded_read_value_calls(const NodeId& nodeId) const;
  std::vector<WriteValueCall> recorded_write_value_calls(const NodeId& nodeId) const;
  std::vector<IsNodeInViewCall> recorded_is_node_in_view_calls(const NodeId& view) const;
  std::vector<AddNodeToViewCall> recorded_add_node_to_view_calls(const NodeId& view) const;

  // --- Namespace virtuals -------------------------------------------------

  String uri() const override;

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override;
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override;
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override;
  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override;
  void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override;
  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override;

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override;
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override;
  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override;
  void add_to_view_async(const RequestInfo& request, const NodeId& view, std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

protected:
  explicit FakeAsyncNamespace(std::string uri);

private:
  /// The staged answers and the recorded operations of one Node.
  struct NodeScript
  {
    std::deque<NodeReferencesResult> references;
    std::vector<GetReferencesPageCall> referenceQueries;
    std::deque<VoidResult> addReference;
    std::vector<AddReferenceCall> addReferenceCalls;
    std::deque<VoidResult> removeReference;
    std::vector<RemoveReferenceCall> removeReferenceCalls;
    std::deque<CallResult> call;
    std::vector<CallCall> callCalls;
    std::deque<DataValueResult> readValue;
    std::vector<ReadValueCall> readValueCalls;
    std::deque<VoidResult> writeValue;
    std::vector<WriteValueCall> writeValueCalls;
    std::deque<BoolResult> isNodeInView;
    std::vector<IsNodeInViewCall> isNodeInViewCalls;
    std::deque<VoidResult> addNodeToView;
    std::vector<AddNodeToViewCall> addNodeToViewCalls;
  };

  /// One id's resolution, recorded and possibly parked. The body of @ref find_nodes_async per id.
  void resolve_one(const NodeId& nodeId, std::function<void(NodeResult)> callback);

  /// One creation, recorded and possibly parked. The body of @ref create_nodes_async per item.
  void create_one(const NodeCreation& creation, std::function<void(NodeResult)> callback);

  /// One deletion, recorded and possibly parked. The body of @ref delete_nodes_async per item.
  void delete_one(const NodeId& nodeId, std::function<void(DeleteNodeResult)> callback);

  /// Answers each Reference change at its source from @p staged, recording it in @p recorded.
  template<typename Recorded>
  void change_references(std::span<const ReferenceChange> changes, std::deque<VoidResult> NodeScript::*staged,
    std::vector<Recorded> NodeScript::*recorded, std::string_view opName,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// A copy of a recording of the Node @p nodeId; empty for a NodeId never recorded.
  template<typename Recorded>
  std::vector<Recorded> recorded_of(const NodeId& nodeId, std::vector<Recorded> NodeScript::*recorded) const;

  void worker_loop();
  void park_locked(std::function<void()> fire);

  // Static after construction --------------------------------------------
  std::string mUri;
  std::thread mWorker;
  std::thread::id mWorkerThreadId;

  // Mutex-protected ------------------------------------------------------
  mutable std::mutex mMutex;
  mutable std::condition_variable mCond;
  mutable std::condition_variable mIdleCond;  // notified when worker becomes idle
  bool mShutdown{false};
  bool mWorkerBusy{false};

  // Parked callbacks awaiting release; mReleasedCount tracks how many of
  // them complete_pending() has greenlit. Invariant:
  // mReleasedCount <= mParked.size(). The worker pops mParked.front() each
  // time mReleasedCount > 0.
  std::deque<std::function<void()>> mParked;
  std::size_t mReleasedCount{0};

  bool mFindNodeDeferred{false};
  bool mCreateNodeDeferred{false};
  bool mDeleteNodeDeferred{false};
  bool mCreateMonitoringDeferred{false};
  bool mDeleteMonitoringDeferred{false};
  bool mModifyMonitoringDeferred{false};

  std::deque<NodeResult> mNextFindNodeResults;
  std::deque<NodeResult> mNextCreateNodeResults;
  std::deque<DeleteNodeResult> mNextDeleteNodeResults;
  std::deque<BatchResult<MonitoringCreateItemResult>> mNextCreateMonitoringResults;
  std::deque<BatchResult<VoidResult>> mNextDeleteMonitoringResults;
  std::deque<BatchResult<MonitoringModifyItemResult>> mNextModifyMonitoringResults;
  std::map<NodeId, std::shared_ptr<Node>> mHeld;
  std::map<NodeId, NodeScript> mNodeScripts;

  std::vector<RecordedCall> mRecordedCalls;
};

}  // namespace ua::test::behaviour_pins

#endif  // UA_TEST_BEHAVIOUR_PINS_FAKE_ASYNC_NAMESPACE_H
