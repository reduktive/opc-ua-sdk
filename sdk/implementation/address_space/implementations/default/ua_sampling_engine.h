// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SAMPLING_ENGINE_H
#define UA_SAMPLING_ENGINE_H

#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_duration.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_integer_id.h"
#include "ua_logger.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_node_id.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_value_id.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_timer.h"

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::default_ns
{

/// Sampling mode for a monitored entry.
enum class SamplingKind
{
  Polled,  ///< Engine reads node value on each bucket tick.
  ExceptionLatest,  ///< Write-path stores latest value; tick pushes if changed.
  ExceptionQueued  ///< Write-path queues all values; tick drains and pushes all.
};

/// Sampling engine for the default in-memory namespace.
/// Supports three modes: Polled (reads on timer tick), ExceptionLatest (latest
/// pushed value per tick), and ExceptionQueued (all pushed values).
///
/// Threading model - sync-API mutex-protected helper.
///
/// All public methods are synchronous and return values directly. Mutable
/// state (mEntries, mBuckets, mReportedIndex, counters, mShutdownFlag) is
/// guarded by the single std::mutex `mMutex`. The engine itself has no strand:
/// bucket timer ticks fire directly on the engine's executor and serialise
/// their state access through the mutex. Distinct buckets may tick concurrently
/// on different pool threads; the lock-protected snapshot/writeback phases
/// briefly serialise across them while the lock-free read and sink->push
/// phases parallelise. A tick's read phase runs on a strand made for that tick
/// alone - see BucketTickOperation - which serialises nothing beyond that tick's
/// own state and so leaves this concurrency unchanged.
///
/// Preconditions on collaborators:
///   - The ValueReader MAY complete synchronously or asynchronously, on any
///     thread. The tick (BucketTickOperation) owns itself while a read is
///     outstanding and resumes on its own strand by a post, so a reader that
///     answers inline neither recurses nor holds the tick's thread.
///   - SampleSink::push is documented thread-safe (ua_sample_sink.h).
///
/// The mutex is never held across the reader, Node::attributes(), the narrowing of a value to its
/// registration's IndexRange, or sink->push.
class SamplingEngine : public std::enable_shared_from_this<SamplingEngine>
{
public:
  /// One polled Value to read: the registration's Node and what to read of it.
  struct ValueRead
  {
    std::shared_ptr<Node> node;
    ReadValueId value;
  };

  /// Reads one caller's polled Values for one tick: completes once with one DataValueResult per item, in
  /// order, or with std::nullopt when the registered namespace is gone.
  using ValueReader = std::function<void(std::shared_ptr<const CallerInfo> caller,
    std::vector<ValueRead> items, std::function<void(std::optional<std::vector<DataValueResult>>)> complete)>;

  /// @param executor Where bucket timers fire and ticks run.
  /// @param reader   Reads the polled Values of a Variable at each tick, one call per distinct caller of the
  ///                 tick's entries; every other attribute polled, and a VariableType's Value, is read from
  ///                 the Node's description (`Node::attributes()`).
  /// @param logger   Reports a bucket that cannot keep up with its interval.
  SamplingEngine(boost::asio::any_io_executor executor, ValueReader reader, ua::Logger logger = {});
  ~SamplingEngine();

  SamplingEngine(const SamplingEngine&) = delete;
  SamplingEngine& operator=(const SamplingEngine&) = delete;
  SamplingEngine(SamplingEngine&&) = delete;
  SamplingEngine& operator=(SamplingEngine&&) = delete;

  struct PolledRegistration
  {
    std::shared_ptr<Node> node;
    /// The class of @ref node, which decides how an entry on the Value is read: a Variable's through the
    /// reader, a VariableType's from the Node's description. Not consulted for any other attribute.
    NodeClass nodeClass{NodeClass::Variable};
    NodeId nodeId;
    AttributeId attributeId{AttributeId::Value};
    /// The registration's IndexRange, which each read through the reader carries; empty for the whole value.
    NumericRange indexRange;
    /// @ref indexRange parsed, by the caller: every value the entry reads from the Node's description is
    /// narrowed to it (NR-14 rule 1).
    ParsedNumericRange range;
    IntegerId monitoredItemId{0};
    Duration requestedInterval{0};
    std::shared_ptr<SampleSink> sink;
  };

  struct ExceptionRegistration
  {
    std::shared_ptr<Node> node;
    /// As @ref PolledRegistration::nodeClass: an entry read once after a modify, or polled after one, is
    /// read by it.
    NodeClass nodeClass{NodeClass::Variable};
    NodeId nodeId;
    AttributeId attributeId{AttributeId::Value};
    /// As @ref PolledRegistration::indexRange: an entry read once after a modify, or polled after one, reads
    /// with it.
    NumericRange indexRange;
    /// @ref indexRange parsed, by the caller: every value reported to the entry, and every value it reads
    /// from the Node's description, is narrowed to it before change detection (NR-14 rule 1, NR-48 rule 2).
    ParsedNumericRange range;
    IntegerId monitoredItemId{0};
    Duration requestedInterval{0};
    uint32_t queueSize{1};
    std::shared_ptr<SampleSink> sink;
  };

  struct AddResult
  {
    MonitoringHandle handle{0};
    Duration revisedInterval{0};
  };

  using Delivery = NamespaceMonitoringSupport::Delivery;

  struct ModifyRegistration
  {
    Duration requestedInterval{0};
    uint32_t queueSize{1};
    /// How the entry is fed from now on. Sampled is polled at the requested interval; Reported is fed by
    /// attribute_changed, queued when it is a Value entry at interval 0 and latest-value otherwise.
    Delivery delivery{Delivery::Sampled};
  };

  struct ModifyResult
  {
    Duration revisedInterval{0};
    SamplingKind kind{};
    /// False when the handle names no entry: never added, removed, erased at the tick that found its Node
    /// deleted, or the engine is shut down.
    bool found{false};
  };

  /// A sink and item an entry on a Node's attribute delivers to.
  struct Monitor
  {
    std::shared_ptr<SampleSink> sink;
    IntegerId monitoredItemId{0};
  };

  /// Register a polled monitoring entry. Thread-safe.
  AddResult add_polled(PolledRegistration registration);

  /// Register an ExceptionLatest entry (non-value attributes).
  /// Routed to a normal bucket based on requestedInterval.
  /// Thread-safe.
  AddResult add_exception_latest(ExceptionRegistration registration);

  /// Register an ExceptionQueued entry (value attributes with interval 0).
  /// Routed to an internal 10ms batch bucket. revisedInterval is reported as 0.
  /// Thread-safe.
  AddResult add_exception_queued(ExceptionRegistration registration);

  /// Stores @p value as pending for every exception-mode entry on @p attributeId of @p nodeId whose Node
  /// is not deleted; the entry's next tick delivers it. Looks the entries up in the (NodeId, attribute)
  /// index under the mutex, asks their Nodes deleted() with no lock held, then stores under the mutex; an
  /// entry created in between is not given the value. A polled entry is not in the index and is not
  /// affected. No-op after shutdown. Thread-safe; calls no sink.
  void attribute_changed(const NodeId& nodeId, AttributeId attributeId, const DataValue& value);

  /// The sinks and items of every live entry on @p attributeId of @p nodeId, whatever its kind.
  /// Thread-safe; calls no sink.
  std::vector<Monitor> find_monitors(const NodeId& nodeId, AttributeId attributeId) const;

  /// Modify a previously registered entry: its interval, queue size and kind, which follows from the
  /// delivery as on add. What is pending stays owed: an entry moved between ExceptionQueued and
  /// ExceptionLatest keeps it (the newest queued value as the latest; the latest as the first queued),
  /// and an entry on the Value moved from Polled to an exception mode reads the Node once at its next
  /// tick, unless a value is reported to it first. Thread-safe.
  ModifyResult modify(MonitoringHandle handle, ModifyRegistration registration);

  /// Remove a previously registered entry by handle. Thread-safe.
  void remove(MonitoringHandle handle);

  /// Cancel all timers and clear all registrations. Does not wait for a tick in flight; that tick
  /// pushes nothing once it reaches its write-back.
  void shutdown();

  /// Shuts down as @ref shutdown does, then calls @p done once no tick is in flight: at once, on the
  /// calling thread, when none is, and otherwise on the thread of the last tick to finish, after its
  /// push. No tick starts after this call; a tick in flight that has not stored its values for the push
  /// when shutdown begins pushes nothing and sends no notice. Thread-safe.
  void shutdown_async(std::function<void()> done);

  /// Round a requested interval up to the nearest bucket interval. An interval above the largest bucket,
  /// which a Variable's MinimumSamplingInterval asks for (the Subscription revises a client's request to at
  /// most the largest bucket), is a bucket of its own: the interval rounded up to a whole millisecond, at
  /// most @ref sLongestBucketInterval. 0 and a negative interval get the fastest bucket, NaN the largest.
  Duration round_to_bucket(Duration requested) const;

  /// What one bucket's ticks cost, and what they lose.
  ///
  /// A bucket's ticks do not overlap, so a bucket whose work exceeds its interval cannot keep up however
  /// many cores are idle - and the client is told its requested interval was granted either way. These
  /// are the figures that make that visible.
  struct BucketMetrics
  {
    Duration interval{0};  ///< The bucket's sampling interval, in milliseconds.
    size_t items{0};  ///< Items currently registered in the bucket.
    uint64_t ticksCompleted{0};
    /// Periods that never started because the previous tick had not finalised. Each one is a sample
    /// every item in the bucket did not get, and nothing in the protocol exchange reveals it.
    uint64_t periodsSkipped{0};
    /// Completed ticks whose wall time exceeded the bucket's interval - the condition that causes the
    /// skips above, counted separately because a tick can overrun without the next period arriving.
    uint64_t ticksOverInterval{0};
    double lastTickMilliseconds{0.0};
  };

  /// Snapshot of every bucket's metrics, newest values, ordered by interval.
  /// @return One entry per live bucket; empty after @ref shutdown.
  std::vector<BucketMetrics> metrics() const;

  /// Internal batch interval for ExceptionQueued items (10ms).
  static constexpr Duration exceptionQueuedBatchInterval{10};

  friend struct SamplingEngineTestAccess;

private:
  static constexpr std::array<Duration, 10> sDefaultBuckets{
    50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000, 60000};

  /// The longest period a bucket's timer holds, in milliseconds: half the steady clock's range, so that the
  /// timer's next expiry, its current one plus the period, cannot overflow the clock.
  static constexpr Duration sLongestBucketInterval = static_cast<Duration>(
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max() / 2)
      .count());

  struct Entry
  {
    std::shared_ptr<Node> node;
    /// Set at add when the entry is on a Variable's Value, which the tick reads through the reader; any
    /// other entry the tick reads is read from its Node's description.
    bool readThroughReader{true};
    NodeId nodeId;
    AttributeId attributeId{AttributeId::Value};
    /// The registration's IndexRange, carried by each read through the reader.
    NumericRange indexRange;
    /// The same range, parsed once at add; null when it is empty. Every value the entry delivers that the
    /// reader did not read is narrowed to it, outside the mutex.
    std::shared_ptr<const ParsedNumericRange> range;
    IntegerId monitoredItemId{0};
    std::shared_ptr<SampleSink> sink;
    Duration bucketInterval{0};
    DataValue lastPushedValue;
    SamplingKind kind{SamplingKind::Polled};

    // Pending storage (exception modes only):
    std::optional<DataValue> pendingLatest;  ///< ExceptionLatest: latest value.
    std::vector<DataValue> pendingQueued;  ///< ExceptionQueued: all values.
    uint32_t maxPendingCount{1};  ///< Bounds pendingQueued size.
    /// Set by a modify from Polled to an exception mode on the Value: nothing was pending, and a change
    /// made since the last sample was never reported, so the next tick reads the Node once, as a polled
    /// tick does, unless a value has been reported since.
    bool readOnce{false};
  };

  struct BucketState
  {
    Timer timer;
    // Membership is a set so a single item's removal is O(1) - a vector with
    // linear erase makes bulk teardown of N items in one bucket O(N^2), which
    // dominates DeleteSubscription latency for large monitored-item sets.
    // Order is irrelevant: the tick snapshots every member regardless.
    std::unordered_set<MonitoringHandle> handles;
    // Guards against overlapping read cycles. on_bucket_tick sets this when it
    // hands a snapshot to a BucketTickOperation and finalise_bucket_tick clears it.
    // A namespace whose read completes asynchronously (and slower than
    // the bucket period) would otherwise stack unbounded concurrent ticks; with
    // the guard the engine coalesces - it skips the tick and tries next period.
    bool tickInFlight{false};
    /// Distinguishes this bucket from a later one at the same interval, so that a tick of a bucket that
    /// was emptied and erased cannot clear the guard of the bucket created after it.
    uint64_t generation{0};

    // --- Metrics. Guarded by mMutex like the rest of the bucket's state. ---
    uint64_t ticksCompleted{0};
    uint64_t periodsSkipped{0};
    uint64_t ticksOverInterval{0};
    double lastTickMilliseconds{0.0};
  };

  mutable std::mutex mMutex;
  boost::asio::any_io_executor mExecutor;
  // Logger for ua::async::guarded on the executor-hop posts (records a swallowed exception escaping a
  // continuation). A cheap copyable value handle; default-constructs silent. Set once at construction.
  ua::Logger mLogger;
  /// Reads the polled Values of Variables. Set once at construction; called with no lock held. Shared, so a
  /// tick's read can hold the reader by value across its suspension without holding the engine (R8).
  std::shared_ptr<const ValueReader> mReader;

  std::unordered_map<MonitoringHandle, Entry> mEntries;
  std::map<Duration, BucketState> mBuckets;
  MonitoringHandle mNextHandle{1};
  uint64_t mNextBucketGeneration{1};
  bool mShutdownFlag{false};
  /// Mirrors mShutdownFlag for the tick, which starts no read once shutdown has begun.
  std::atomic<bool> mShuttingDown{false};
  /// Ticks started and not yet finished, and the callers of shutdown_async waiting for them to finish.
  size_t mTicksInFlight{0};
  std::vector<std::function<void()>> mShutdownWaiters;

  /// The (NodeId, attribute) an exception-mode entry is fed by.
  struct NodeAttributeKey
  {
    NodeId nodeId;
    AttributeId attributeId{AttributeId::Value};

    bool operator==(const NodeAttributeKey&) const = default;
  };

  struct NodeAttributeKeyHash
  {
    size_t operator()(const NodeAttributeKey& key) const noexcept
    {
      // The golden-ratio constant of size_t's own width: the 64-bit literal would promote the product and
      // narrow it back on a 32-bit target.
      constexpr size_t goldenRatio =
        sizeof(size_t) >= 8 ? static_cast<size_t>(0x9e3779b97f4a7c15ULL) : static_cast<size_t>(0x9e3779b9U);
      return std::hash<NodeId>{}(key.nodeId) ^ (static_cast<size_t>(key.attributeId) * goldenRatio);
    }
  };

  /// Every exception-mode entry, by the (NodeId, attribute) it is fed by. Polled entries are not in it.
  std::unordered_map<NodeAttributeKey, std::vector<MonitoringHandle>, NodeAttributeKeyHash> mReportedIndex;
  /// Every entry, polled or not, by its (NodeId, attribute): @ref find_monitors answers from it instead of
  /// scanning every entry under the mutex (NR-48).
  std::unordered_map<NodeAttributeKey, std::unordered_set<MonitoringHandle>, NodeAttributeKeyHash>
    mMonitorIndex;

  /// Adds @p handle to, or removes it from, the index slot of @p entry. The caller holds mMutex.
  void index_entry(MonitoringHandle handle, const Entry& entry);
  void unindex_entry(MonitoringHandle handle, const Entry& entry);
  /// Erases @p handle's entry, its index slot and its bucket membership. The caller holds mMutex.
  void erase_entry_locked(std::unordered_map<MonitoringHandle, Entry>::iterator it);

  AddResult add_exception(SamplingKind kind, ExceptionRegistration registration);
  void on_bucket_tick(Duration bucketInterval);
  /// Ends one tick of a bucket: clears its tickInFlight guard (when the bucket is still the one the tick
  /// started on), counts the tick out, and, when it was the last tick in flight after shutdown began,
  /// calls the shutdown_async callers. Takes mMutex; calls the callers with it released.
  void finish_tick(Duration bucketInterval, uint64_t generation);
  void start_bucket_timer(Duration interval);

  /// Per-tick snapshot of one entry - used by BucketTickOperation.
  struct EntrySnapshot
  {
    MonitoringHandle handle{};
    std::shared_ptr<Node> node;
    /// As Entry::readThroughReader.
    bool readThroughReader{true};
    NodeId nodeId;
    AttributeId attributeId{AttributeId::Value};
    /// As Entry::indexRange and Entry::range.
    NumericRange indexRange;
    std::shared_ptr<const ParsedNumericRange> range;
    IntegerId monitoredItemId{};
    std::shared_ptr<SampleSink> sink;
    /// The caller a polled Value item is read for this tick: its sink's `caller()`, asked once per sink per
    /// tick and held until the read answers (NR-49 rules 1 and 4). Null for the server's own read. The
    /// tick makes one reader call per distinct caller.
    std::shared_ptr<const CallerInfo> caller;
    /// Set when the sink's `caller()` failed: the item is answered this status instead of being read.
    std::optional<StatusCode> callerFailure;
    DataValue lastPushedValue;
    SamplingKind kind{SamplingKind::ExceptionLatest};
    /// Set, with no lock held, when the Node reported deleted() before or after the read: the tick sends
    /// Bad_NodeIdUnknown in place of anything it read, after the values it consumed, which were reported
    /// before the deletion.
    bool deleted{false};
    /// The entry's one read after a modify from Polled to an exception mode (Entry::readOnce): this tick
    /// reads the Node as a polled tick does. Never set together with a consumed value.
    bool readOnce{false};

    // Filled in during the read phase (Polled, or readOnce):
    DataValue currentValue;

    // Consumed pending (moved from Entry under lock):
    std::optional<DataValue> consumedLatest;
    std::vector<DataValue> consumedQueued;
  };

  /// What one tick cost, carried from the tick that ran it into @ref finalise_bucket_tick.
  struct TickTiming
  {
    std::chrono::steady_clock::time_point started{};
    /// Items the tick read, through the reader or from a description.
    size_t polledItems{0};
    uint64_t bucketGeneration{0};
  };

  /// What a skipped period looked like, read under the lock and reported outside it.
  struct SkipReport
  {
    uint64_t periodsSkipped{0};
    size_t items{0};
    double lastTickMilliseconds{0.0};
  };

  /// Warns that a bucket is losing periods. Must be called with mMutex released - the Logger's sink is
  /// caller-supplied code.
  void report_skipped_period(Duration bucketInterval, const SkipReport& report);

  /// Records one completed tick against its bucket. Takes mMutex.
  void record_tick(
    Duration bucketInterval, const TickTiming& timing, std::chrono::steady_clock::duration totalPhase);

  /// Gives each snapshot the reader reads this tick its sink's caller: `SampleSink::caller()` is asked once
  /// per sink, with no lock held (it is the sink's code), and a sink whose `caller()` throws has its
  /// snapshots answered `Bad_InternalError` (`SampleSinkCallerThrew`) instead of read (NR-49 rule 1).
  static void assign_callers(std::vector<EntrySnapshot>& snapshots) noexcept;

  /// Called by BucketTickOperation once every read of the tick has completed and the namespace was there.
  /// Checks each snapshot's Node for deletion again (no lock), narrows each value reported to an entry to
  /// the entry's IndexRange and performs change detection (no lock), decides under
  /// mMutex what is still delivered (an entry gone, or shutdown begun, delivers nothing; a deleted Node's
  /// entry is erased and gives one Bad_NodeIdUnknown notice), then pushes and sends the notices with no
  /// lock held. Clears the bucket's tickInFlight guard only after the push, so the next tick's notice
  /// cannot overtake a value this tick read before the deletion.
  void finalise_bucket_tick(Duration bucketInterval, std::vector<EntrySnapshot> snapshots, TickTiming timing);

  // Forward declaration - defined in the .cpp.
  class BucketTickOperation;
};

}  // namespace ua::default_ns

#endif  // !UA_SAMPLING_ENGINE_H
