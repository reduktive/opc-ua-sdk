// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sampling_engine.h"
#include "ua_on_strand.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_monitoring_equality.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_value_id.h"
#include "ua_self_owning_operation.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_utilities.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <string>

namespace ua::default_ns
{

namespace
{

/// A polled attribute read from the Node's description (`Node::attributes()`): any attribute other than a
/// Variable's Value (NR-26 rule 2). A failure is the value's status.
DataValue described_value(const Node& node, AttributeId attributeId)
{
  try
  {
    auto described = node.attributes().attribute(attributeId);
    return described.is_good() ? std::move(described).value() : DataValue{described.status_code()};
  }
  catch (...)
  {
    return DataValue{exception_to_status_code(std::current_exception())};
  }
}

/// Whether an entry is read through the reader: a Variable's Value. Decided once, when the entry is added.
bool read_through_reader(AttributeId attributeId, NodeClass nodeClass)
{
  return attributeId == AttributeId::Value && nodeClass == NodeClass::Variable;
}

/// The range an entry holds: null for an empty one, so that an entry without a range narrows nothing and
/// copies nothing per tick.
std::shared_ptr<const ParsedNumericRange> held_range(ParsedNumericRange range)
{
  if (range.empty())
  {
    return nullptr;
  }
  return std::make_shared<const ParsedNumericRange>(std::move(range));
}

/// Narrows @p value to its registration's @p range (NR-14 rule 1, NR-48 rule 2), as
/// `index_range_utils::apply_to_value` narrows to an unparsed range: no range and a Bad value leave it
/// unchanged; a range that selects nothing sets the failure's status and a null Value. Never throws.
void narrow(DataValue& value, const ParsedNumericRange* range) noexcept
{
  const auto& valueStatus = value.status();
  if (!range || range->empty() || (valueStatus && valueStatus.value().is_bad()))
  {
    return;
  }
  try
  {
    auto sliced = index_range_utils::apply_read(value.value(), *range);
    if (!sliced.is_good())
    {
      value.status() = sliced.status_code();
      value.value() = Variant{};
      return;
    }
    value.value() = std::move(sliced).value();
  }
  catch (...)
  {
    value.status() = exception_to_status_code(std::current_exception());
    value.value() = Variant{};
  }
}

}  // namespace

SamplingEngine::SamplingEngine(boost::asio::any_io_executor executor, ValueReader reader, ua::Logger logger)
  : mExecutor(std::move(executor)), mLogger(std::move(logger)),
    mReader(std::make_shared<const ValueReader>(std::move(reader)))
{}

SamplingEngine::~SamplingEngine()
{
  shutdown();
}

Duration SamplingEngine::round_to_bucket(Duration requested) const
{
  if (requested <= 0)
  {
    return sDefaultBuckets.front();
  }

  for (auto bucket : sDefaultBuckets)
  {
    if (requested <= bucket)
    {
      return bucket;
    }
  }

  if (std::isnan(requested))
  {
    return sDefaultBuckets.back();
  }
  // Above the largest bucket the interval is a Variable's MinimumSamplingInterval, which the revised interval
  // is never below (Part 4 5.12.1.2), so it is kept, rounded up to a whole millisecond for the bucket's
  // timer, up to the longest period that timer can hold.
  return std::min(std::ceil(requested), sLongestBucketInterval);
}

SamplingEngine::AddResult SamplingEngine::add_polled(PolledRegistration registration)
{
  auto interval = round_to_bucket(registration.requestedInterval);
  auto range = held_range(std::move(registration.range));

  const std::lock_guard lock{mMutex};

  if (mShutdownFlag)
  {
    return {0, 0};
  }

  auto handle = mNextHandle++;

  Entry entry;
  entry.node = std::move(registration.node);
  entry.readThroughReader = read_through_reader(registration.attributeId, registration.nodeClass);
  entry.nodeId = std::move(registration.nodeId);
  entry.attributeId = registration.attributeId;
  entry.indexRange = std::move(registration.indexRange);
  entry.range = std::move(range);
  entry.monitoredItemId = registration.monitoredItemId;
  entry.sink = std::move(registration.sink);
  entry.bucketInterval = interval;
  entry.kind = SamplingKind::Polled;

  mMonitorIndex[NodeAttributeKey{entry.nodeId, entry.attributeId}].insert(handle);
  mEntries.emplace(handle, std::move(entry));

  auto& bucket = mBuckets[interval];
  bucket.handles.insert(handle);

  if (bucket.handles.size() == 1)
  {
    start_bucket_timer(interval);
  }

  return {handle, interval};
}

SamplingEngine::AddResult SamplingEngine::add_exception_latest(ExceptionRegistration registration)
{
  return add_exception(SamplingKind::ExceptionLatest, std::move(registration));
}

SamplingEngine::AddResult SamplingEngine::add_exception_queued(ExceptionRegistration registration)
{
  return add_exception(SamplingKind::ExceptionQueued, std::move(registration));
}

SamplingEngine::AddResult SamplingEngine::add_exception(SamplingKind kind, ExceptionRegistration registration)
{
  const Duration interval = (kind == SamplingKind::ExceptionQueued)
                              ? exceptionQueuedBatchInterval
                              : round_to_bucket(registration.requestedInterval);
  auto range = held_range(std::move(registration.range));

  const std::lock_guard lock{mMutex};

  if (mShutdownFlag)
  {
    return {0, 0};
  }

  auto handle = mNextHandle++;

  Entry entry;
  entry.node = std::move(registration.node);
  entry.readThroughReader = read_through_reader(registration.attributeId, registration.nodeClass);
  entry.nodeId = std::move(registration.nodeId);
  entry.attributeId = registration.attributeId;
  entry.indexRange = std::move(registration.indexRange);
  entry.range = std::move(range);
  entry.monitoredItemId = registration.monitoredItemId;
  entry.sink = std::move(registration.sink);
  // An exception-mode value is pushed from the write path, where no reader exists, so it is the same for
  // every caller. A node whose value differs per caller is polled instead, and the poll reads it for the
  // sink's caller of that tick.
  entry.bucketInterval = interval;
  entry.kind = kind;
  // Floor the pending-queue bound to >=1. The service path already revises queueSize to >=1, but the
  // engine must be self-bounding: a 0 here would make the attribute_changed guard (maxPendingCount > 0)
  // treat the queue as unlimited, so an event-driven MI could grow pendingQueued without limit.
  entry.maxPendingCount = std::max<uint32_t>(registration.queueSize, 1u);

  auto emplaced = mEntries.emplace(handle, std::move(entry)).first;
  mMonitorIndex[NodeAttributeKey{emplaced->second.nodeId, emplaced->second.attributeId}].insert(handle);
  index_entry(handle, emplaced->second);

  auto& bucket = mBuckets[interval];
  bucket.handles.insert(handle);

  if (bucket.handles.size() == 1)
  {
    start_bucket_timer(interval);
  }

  // ExceptionQueued reports 0 to clients (the 10ms is an internal detail).
  const Duration revisedInterval = (kind == SamplingKind::ExceptionQueued) ? 0 : interval;
  return {handle, revisedInterval};
}

void SamplingEngine::index_entry(MonitoringHandle handle, const Entry& entry)
{
  if (entry.kind == SamplingKind::Polled)
  {
    return;
  }
  mReportedIndex[NodeAttributeKey{entry.nodeId, entry.attributeId}].push_back(handle);
}

void SamplingEngine::unindex_entry(MonitoringHandle handle, const Entry& entry)
{
  if (entry.kind == SamplingKind::Polled)
  {
    return;
  }
  auto slot = mReportedIndex.find(NodeAttributeKey{entry.nodeId, entry.attributeId});
  if (slot == mReportedIndex.end())
  {
    return;
  }
  std::erase(slot->second, handle);
  if (slot->second.empty())
  {
    mReportedIndex.erase(slot);
  }
}

void SamplingEngine::erase_entry_locked(std::unordered_map<MonitoringHandle, Entry>::iterator it)
{
  const auto handle = it->first;
  const auto interval = it->second.bucketInterval;
  unindex_entry(handle, it->second);
  if (auto slot = mMonitorIndex.find(NodeAttributeKey{it->second.nodeId, it->second.attributeId});
      slot != mMonitorIndex.end())
  {
    slot->second.erase(handle);
    if (slot->second.empty())
    {
      mMonitorIndex.erase(slot);
    }
  }
  mEntries.erase(it);

  auto bucketIt = mBuckets.find(interval);
  if (bucketIt != mBuckets.end())
  {
    auto& handles = bucketIt->second.handles;
    handles.erase(handle);
    if (handles.empty())
    {
      bucketIt->second.timer.cancel();
      mBuckets.erase(bucketIt);
    }
  }
}

void SamplingEngine::attribute_changed(const NodeId& nodeId, AttributeId attributeId, const DataValue& value)
{
  // The Nodes of the entries on (nodeId, attributeId), each paired with whether it is live. A change
  // reported for a Node that is already deleted is not a change of a live Node and is given to no entry,
  // so the deletion's notice follows only what was reported before it (Part 4 5.12.1.6). deleted() is the
  // Node's own code, so it is asked between two passes under the mutex, with no lock held.
  std::vector<std::pair<std::shared_ptr<Node>, bool>> nodes;
  {
    const std::lock_guard lock{mMutex};
    if (mShutdownFlag)
    {
      return;
    }
    auto slot = mReportedIndex.find(NodeAttributeKey{nodeId, attributeId});
    if (slot == mReportedIndex.end())
    {
      return;
    }
    for (const auto handle : slot->second)
    {
      auto entryIt = mEntries.find(handle);
      if (entryIt == mEntries.end() || !entryIt->second.node)
      {
        continue;
      }
      const auto& node = entryIt->second.node;
      if (std::none_of(
            nodes.begin(), nodes.end(), [&node](const auto& known) { return known.first == node; }))
      {
        nodes.emplace_back(node, true);
      }
    }
  }
  for (auto& [node, live] : nodes)
  {
    live = !node->deleted();
  }

  const std::lock_guard lock{mMutex};
  if (mShutdownFlag)
  {
    return;
  }
  auto slot = mReportedIndex.find(NodeAttributeKey{nodeId, attributeId});
  if (slot == mReportedIndex.end())
  {
    return;
  }

  for (const auto handle : slot->second)
  {
    auto entryIt = mEntries.find(handle);
    if (entryIt == mEntries.end())
    {
      continue;
    }
    auto& entry = entryIt->second;
    if (entry.node)
    {
      // An entry created since the first pass was not registered when the change was reported.
      const auto known = std::find_if(
        nodes.begin(), nodes.end(), [&entry](const auto& checked) { return checked.first == entry.node; });
      if (known == nodes.end() || !known->second)
      {
        continue;
      }
    }
    if (entry.kind == SamplingKind::ExceptionLatest)
    {
      entry.pendingLatest = value;
    }
    else if (entry.kind == SamplingKind::ExceptionQueued)
    {
      if (entry.maxPendingCount > 0 && entry.pendingQueued.size() >= entry.maxPendingCount)
      {
        entry.pendingQueued.erase(entry.pendingQueued.begin());  // DiscardOldest
      }
      entry.pendingQueued.push_back(value);
    }
  }
}

std::vector<SamplingEngine::Monitor> SamplingEngine::find_monitors(
  const NodeId& nodeId, AttributeId attributeId) const
{
  std::vector<Monitor> monitors;
  const std::lock_guard lock{mMutex};
  const auto slot = mMonitorIndex.find(NodeAttributeKey{nodeId, attributeId});
  if (slot == mMonitorIndex.end())
  {
    return monitors;
  }
  monitors.reserve(slot->second.size());
  for (const auto handle : slot->second)
  {
    if (const auto it = mEntries.find(handle); it != mEntries.end())
    {
      monitors.push_back({it->second.sink, it->second.monitoredItemId});
    }
  }
  return monitors;
}

SamplingEngine::ModifyResult SamplingEngine::modify(MonitoringHandle handle, ModifyRegistration registration)
{
  const std::lock_guard lock{mMutex};

  if (mShutdownFlag)
  {
    return {};
  }

  auto it = mEntries.find(handle);
  if (it == mEntries.end())
  {
    return {};
  }

  auto& entry = it->second;
  auto oldInterval = entry.bucketInterval;
  auto oldKind = entry.kind;

  // The delivery is the caller's; the kind follows from it, as on add: a Sampled entry is polled, a
  // Reported Value entry at interval 0 is queued, and any other Reported entry keeps the latest value.
  SamplingKind newKind = SamplingKind::Polled;
  if (registration.delivery == Delivery::Reported)
  {
    newKind = (entry.attributeId == AttributeId::Value && registration.requestedInterval == 0)
                ? SamplingKind::ExceptionQueued
                : SamplingKind::ExceptionLatest;
  }

  // Compute new bucket interval.
  const Duration newBucketInterval = (newKind == SamplingKind::ExceptionQueued)
                                       ? exceptionQueuedBatchInterval
                                       : round_to_bucket(registration.requestedInterval);

  // --- Bucket reassignment ---
  if (newBucketInterval != oldInterval)
  {
    // Remove from old bucket.
    auto oldBucketIt = mBuckets.find(oldInterval);
    if (oldBucketIt != mBuckets.end())
    {
      auto& handles = oldBucketIt->second.handles;
      handles.erase(handle);
      if (handles.empty())
      {
        oldBucketIt->second.timer.cancel();
        mBuckets.erase(oldBucketIt);
      }
    }

    // Add to new bucket.
    auto& newBucket = mBuckets[newBucketInterval];
    newBucket.handles.insert(handle);
    if (newBucket.handles.size() == 1)
    {
      start_bucket_timer(newBucketInterval);
    }
  }

  // --- Index and pending changes ---
  if (oldKind == SamplingKind::Polled && newKind != SamplingKind::Polled)
  {
    // Polled -> Exception: the entry is fed by attribute_changed from now on. Nothing is pending, and a
    // change made since the last sample was not reported to it, so its next tick reads the Value once.
    entry.kind = newKind;
    index_entry(handle, entry);
    entry.maxPendingCount = std::max<uint32_t>(registration.queueSize, 1u);  // floor to >=1, see register
    entry.readOnce = entry.attributeId == AttributeId::Value;
  }
  else if (oldKind != SamplingKind::Polled && newKind == SamplingKind::Polled)
  {
    // Exception -> Polled: out of the index, pending storage cleared.
    unindex_entry(handle, entry);
    entry.pendingLatest.reset();
    entry.pendingQueued.clear();
    entry.readOnce = false;
  }
  else if (oldKind != SamplingKind::Polled && newKind != SamplingKind::Polled)
  {
    // Exception -> Exception: update maxPendingCount on the entry directly.
    entry.maxPendingCount = std::max(entry.maxPendingCount, registration.queueSize);

    // What is pending stays owed: from every value to the latest, the newest queued value is the latest;
    // from the latest to every value, the latest is the first queued.
    if (oldKind == SamplingKind::ExceptionQueued && newKind == SamplingKind::ExceptionLatest)
    {
      if (!entry.pendingQueued.empty())
      {
        entry.pendingLatest = std::move(entry.pendingQueued.back());
        entry.pendingQueued.clear();
      }
    }
    else if (oldKind == SamplingKind::ExceptionLatest && newKind == SamplingKind::ExceptionQueued)
    {
      if (entry.pendingLatest.has_value())
      {
        entry.pendingQueued.push_back(std::move(*entry.pendingLatest));
        entry.pendingLatest.reset();
      }
    }

    // Trim pending queued values if they exceed the new max.
    if (newKind == SamplingKind::ExceptionQueued && entry.pendingQueued.size() > entry.maxPendingCount)
    {
      entry.pendingQueued.erase(entry.pendingQueued.begin(),
        entry.pendingQueued.begin() +
          static_cast<std::ptrdiff_t>(entry.pendingQueued.size() - entry.maxPendingCount));
    }
  }

  // Update entry.
  entry.bucketInterval = newBucketInterval;
  entry.kind = newKind;

  const Duration revisedInterval = (newKind == SamplingKind::ExceptionQueued) ? 0 : newBucketInterval;
  return {revisedInterval, newKind, true};
}

void SamplingEngine::remove(MonitoringHandle handle)
{
  const std::lock_guard lock{mMutex};

  auto it = mEntries.find(handle);
  if (it == mEntries.end())
  {
    return;
  }
  erase_entry_locked(it);
}

void SamplingEngine::shutdown()
{
  const std::lock_guard lock{mMutex};
  mShutdownFlag = true;
  mShuttingDown.store(true, std::memory_order_release);

  for (auto& [interval, bucket] : mBuckets)
  {
    bucket.timer.cancel();
  }
  mBuckets.clear();
  mEntries.clear();
  mReportedIndex.clear();
  mMonitorIndex.clear();
}

void SamplingEngine::shutdown_async(std::function<void()> done)
{
  shutdown();
  {
    const std::lock_guard lock{mMutex};
    if (mTicksInFlight != 0)
    {
      // Called by the last tick to finish, in finish_tick.
      mShutdownWaiters.push_back(std::move(done));
      return;
    }
  }
  if (done)
  {
    ua::detail::invoke_user_callback(done);
  }
}

void SamplingEngine::start_bucket_timer(Duration interval)
{
  auto period = std::chrono::milliseconds(numeric_cast<int64_t>(interval));

  auto& bucket = mBuckets[interval];
  bucket.generation = mNextBucketGeneration++;

  bucket.timer = Timer::schedule_every(mExecutor,
    period,
    [weak = weak_from_this(), interval](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      self->on_bucket_tick(interval);
    });
}

/// Drives the read phase of one bucket tick, then hands the filled-in snapshots to
/// SamplingEngine::finalise_bucket_tick for change detection, write-back and push (per 8.2 hazard 3 fix).
///
/// The polled Values of Variables are read through the engine's reader with one call per distinct caller,
/// every call started before any is awaited (NR-49 rule 1). Each answer resumes the tick by a post onto its
/// strand, so a reader that answers inline neither recurses nor holds the thread. Every other polled
/// attribute, and a VariableType's Value, is read from the Node's description (NR-26 rule 2).
///
/// The tick runs on a strand made for it alone, which serialises only the tick's own state - the snapshots
/// it writes the answers into - as await_callback requires of state read and written across a suspension.
/// Distinct buckets still tick concurrently; mMutex remains the only thing that serialises across them.
/// The engine is held weakly: a tick whose engine is gone when it resumes ends.
class SamplingEngine::BucketTickOperation final : public ua::async::SelfOwningOperation<BucketTickOperation>
{
public:
  static void start(const std::shared_ptr<SamplingEngine>& engine, Duration bucketInterval,
    std::vector<EntrySnapshot> snapshots, TickTiming timing)
  {
    auto strand = boost::asio::make_strand(engine->mExecutor);
    auto logger = engine->mLogger;
    launch(std::make_shared<BucketTickOperation>(
      std::move(strand), std::move(logger), engine, bucketInterval, std::move(snapshots), timing));
  }

  BucketTickOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    const std::shared_ptr<SamplingEngine>& engine, Duration bucketInterval,
    std::vector<EntrySnapshot> snapshots, TickTiming timing)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mEngine(engine),
      mBucketInterval(bucketInterval), mSnapshots(std::move(snapshots)), mTiming(timing)
  {}

private:
  friend class ua::async::SelfOwningOperation<BucketTickOperation>;

  using ReadAnswer = std::optional<std::vector<DataValueResult>>;

  /// The snapshots one reader call reads: those whose sinks gave the same caller this tick.
  struct CallerGroup
  {
    std::shared_ptr<const CallerInfo> caller;
    std::vector<size_t> positions;
    std::vector<ValueRead> items;
  };

  ua::async::Task<> run()
  {
    try
    {
      std::vector<CallerGroup> groups;
      std::vector<ua::async::Task<ReadAnswer>> reads;
      std::vector<size_t> described;
      {
        const auto engine = mEngine.lock();
        if (!engine)
        {
          co_return;
        }
        // Nothing this tick reads is pushed once shutdown has begun, so no read is started; finalise drops
        // the tick.
        if (!engine->mShuttingDown.load(std::memory_order_acquire))
        {
          group_reads(groups, described);
          // Every caller's read is started before any is awaited. The engine is held only while they start.
          reads.reserve(groups.size());
          for (auto& group : groups)
          {
            reads.push_back(read(engine->mReader, group.caller, std::move(group.items)));
          }
        }
      }

      for (const size_t index : described)
      {
        auto& snap = mSnapshots[index];
        snap.currentValue = described_value(*snap.node, snap.attributeId);
        narrow(snap.currentValue, snap.range.get());
      }

      bool namespaceGone = false;
      for (size_t group = 0; group < reads.size(); ++group)
      {
        auto answer = co_await std::move(reads[group]);
        if (!answer)
        {
          // The other calls are still awaited, so that none answers into a tick that has ended.
          namespaceGone = true;
          continue;
        }
        assign_answers(groups[group].positions, std::move(*answer));
      }

      const auto engine = mEngine.lock();
      if (!engine)
      {
        co_return;
      }
      if (namespaceGone)
      {
        // The registered namespace is gone: this tick pushes nothing, and the bucket's next tick runs.
        engine->finish_tick(mBucketInterval, mTiming.bucketGeneration);
        co_return;
      }

      // `guarded` because a user-supplied SampleSink::push can throw and nothing awaits
      // this task - an escape would be stored in the coroutine's promise and never read.
      // It is also what keeps the handlers below off the push phase: finalise_bucket_tick
      // has counted the tick out by the time it returns, and a second finish from here
      // would count out a tick that is not this one.
      ua::async::guarded(mLogger,
        [this, &engine] { engine->finalise_bucket_tick(mBucketInterval, std::move(mSnapshots), mTiming); })();
    }
    catch (const ua::async::Abandoned&)
    {
      // Nobody wants this tick's answer any more.
      abandon();
    }
    catch (...)
    {
      // Re-throwing inside `guarded` hands the exception to the logger, which is the only place it can
      // still go. The tick is then abandoned rather than finalised: part of the snapshot holds no answer.
      ua::async::guarded(mLogger, [] { throw; })();
      abandon();
    }
    co_return;
  }

  /// Checks each snapshot's Node for deletion, and sorts the snapshots this tick reads: those on a Variable's
  /// Value into one group per distinct caller, the rest into @p described.
  void group_reads(std::vector<CallerGroup>& groups, std::vector<size_t>& described)
  {
    for (size_t index = 0; index < mSnapshots.size(); ++index)
    {
      auto& snap = mSnapshots[index];
      // Asked with no lock held: deleted() is the Node's own code. A deleted Node is not read; the
      // tick sends its notice in place of a value.
      if (snap.node && snap.node->deleted())
      {
        snap.deleted = true;
        continue;
      }
      if (snap.kind != SamplingKind::Polled && !snap.readOnce)
      {
        continue;
      }
      if (!snap.readThroughReader)
      {
        ++mTiming.polledItems;
        described.push_back(index);
        continue;
      }
      if (snap.callerFailure)
      {
        snap.currentValue = DataValue{*snap.callerFailure};
        continue;
      }
      // Counted where a read is issued: an item answered without one would understate what a read costs.
      ++mTiming.polledItems;

      auto group = std::find_if(groups.begin(),
        groups.end(),
        [&snap](const CallerGroup& candidate) { return candidate.caller == snap.caller; });
      if (group == groups.end())
      {
        group = groups.insert(groups.end(), CallerGroup{snap.caller, {}, {}});
      }
      // The namespace narrows the Value to the registration's range (NR-14 rule 1).
      ReadValueId readId;
      readId.node_id() = snap.nodeId;
      readId.attribute_id() = utils::to_underlying(AttributeId::Value);
      readId.index_range() = snap.indexRange;
      group->positions.push_back(index);
      group->items.push_back(ValueRead{snap.node, std::move(readId)});
    }
  }

  /// One reader call. The reader is called only to start the call, before the first suspension, but the task
  /// is stored and awaited after the engine is released, so it holds @p reader by value (R8) rather than a
  /// reference into the engine.
  ua::async::Task<ReadAnswer> read(std::shared_ptr<const ValueReader> reader,
    std::shared_ptr<const CallerInfo> caller, std::vector<ValueRead> items)
  {
    const size_t count = items.size();
    try
    {
      co_return co_await await_step<ReadAnswer>([&reader, &caller, &items](auto completion)
        { (*reader)(std::move(caller), std::move(items), std::move(completion)); });
    }
    catch (const ua::async::Abandoned&)
    {
      // A withdrawal ends the whole tick, not this one read (R16).
      throw;
    }
    catch (...)
    {
      co_return std::vector<DataValueResult>(
        count, DataValueResult{exception_to_status_code(std::current_exception())});
    }
  }

  /// Puts one reader call's answers into the snapshots it read, in order.
  void assign_answers(const std::vector<size_t>& positions, std::vector<DataValueResult> answer)
  {
    for (size_t item = 0; item < positions.size(); ++item)
    {
      auto& snap = mSnapshots[positions[item]];
      if (item >= answer.size())
      {
        snap.currentValue = DataValue{StatusCode{Status::BadInternalError,
          ErrorDetail::build("ValueReaderItemCountMismatch",
            "The value reader answered fewer items than it was given",
            "SamplingEngine")
            .context(ua::ContextKeys::sizeExpected, std::to_string(positions.size()))
            .context(ua::ContextKeys::sizeActual, std::to_string(answer.size()))}};
        continue;
      }
      auto& result = answer[item];
      if (!result.has_value())
      {
        snap.currentValue = DataValue{result.status_code()};
        continue;
      }
      // The namespace's code on the read and the Value's own status have room for one status in the
      // notification: the one combined_status gives, so a Good subcode or an Uncertain code of the answer
      // reaches the client. A code with a SubCode that is not the one notified is logged instead.
      const StatusCode outer = result.status_code();
      snap.currentValue = std::move(result).value();
      const StatusCode inner = snap.currentValue.status().value_or(StatusCode{Status::Good});
      if (detail::outer_status_answered(outer, inner))
      {
        snap.currentValue.status() = outer;
      }
      else if (detail::has_subcode(outer))
      {
        log_code_not_notified(snap.nodeId, outer, inner);
      }
    }
  }

  /// Logs @p outer, the code with a SubCode the namespace answered the read of @p nodeId with, when the
  /// Value's own status @p inner is the one the notification carries.
  void log_code_not_notified(
    const NodeId& nodeId, const StatusCode& outer, const StatusCode& inner) const noexcept
  {
    try
    {
      if (!mLogger.is_enabled(LogLevel::Warning))
      {
        return;
      }
      const std::string nodeText = to_string(nodeId);
      const std::string outerText = to_string(outer);
      const std::string innerText = to_string(inner);
      mLogger.warning({{"nodeId", std::string_view{nodeText}},
                        {"status", std::string_view{outerText}},
                        {"answered", std::string_view{innerText}}},
        "A sampled Value is notified with its own status; the namespace's code on the read is not notified");
    }
    catch (...)
    {
      detail::ignore_expected_exception();
    }
  }

  /// Ends a tick that holds no answer for part of its snapshot: discarded, and the bucket tries again next
  /// period rather than push values nothing produced.
  void abandon()
  {
    if (const auto engine = mEngine.lock())
    {
      engine->finish_tick(mBucketInterval, mTiming.bucketGeneration);
    }
  }

  /// The tick's frame could not be allocated, so it reads nothing.
  void fail_to_start(StatusCode)
  {
    abandon();
  }

  std::weak_ptr<SamplingEngine> mEngine;
  Duration mBucketInterval;
  std::vector<EntrySnapshot> mSnapshots;
  TickTiming mTiming;
};

void SamplingEngine::finish_tick(Duration bucketInterval, uint64_t generation)
{
  std::vector<std::function<void()>> waiters;
  {
    const std::lock_guard lock{mMutex};
    auto bucketIt = mBuckets.find(bucketInterval);
    if (bucketIt != mBuckets.end() && bucketIt->second.generation == generation)
    {
      bucketIt->second.tickInFlight = false;
    }
    if (mTicksInFlight > 0)
    {
      --mTicksInFlight;
    }
    if (mTicksInFlight == 0 && mShutdownFlag)
    {
      waiters.swap(mShutdownWaiters);
    }
  }
  for (auto& waiter : waiters)
  {
    if (waiter)
    {
      ua::detail::invoke_user_callback(waiter);
    }
  }
}

void SamplingEngine::report_skipped_period(Duration bucketInterval, const SkipReport& report)
{
  // Rate-limited to the first loss and then each doubling. A bucket that cannot keep up loses a period
  // every period, so one line each would bury the log in the symptom; powers of two say it happened,
  // then say it is still happening, at a volume that stays readable for as long as it persists.
  const auto count = report.periodsSkipped;
  if ((count & (count - 1)) != 0)
  {
    return;
  }

  mLogger.warning({{"bucketInterval", bucketInterval},
                    {"periodsSkipped", static_cast<int64_t>(count)},
                    {"items", static_cast<int64_t>(report.items)},
                    {"lastTickMilliseconds", report.lastTickMilliseconds}},
    "Sampling cannot keep up with its interval: a tick is still running when the next period is due, so "
    "that period is skipped and every item in the bucket misses a sample. The clients were granted this "
    "interval and are being served more slowly, with nothing in the protocol exchange to say so. Either "
    "reduce the items on this interval or spread them across several - distinct intervals are sampled "
    "independently.");
}

void SamplingEngine::on_bucket_tick(Duration bucketInterval)
{
  // --- Snapshot phase: copy entry data and consume pending values under lock ---
  std::vector<EntrySnapshot> snapshots;
  std::optional<SkipReport> skipped;
  uint64_t generation = 0;

  {
    const std::lock_guard lock{mMutex};
    if (mShutdownFlag)
    {
      return;
    }

    auto bucketIt = mBuckets.find(bucketInterval);
    if (bucketIt == mBuckets.end())
    {
      return;
    }

    // Coalesce: if the previous cycle for this bucket has not finalised, skip
    // this period rather than stacking a second concurrent read/push cycle.
    // Bounds in-flight work to one cycle per bucket regardless of how slowly a
    // namespace's read completes. Exception-mode pending queues are
    // size-bounded, so skipping loses no committed samples.
    if (bucketIt->second.tickInFlight)
    {
      // Counted, because this is a sample every item in the bucket does not get and the client is
      // never told: it asked for an interval, was granted it, and is being served more slowly.
      // Reported below, outside the lock: a Logger sink is caller-supplied code, and the rule against
      // running caller code while holding the mutex applies to it as much as to a SampleSink.
      skipped = SkipReport{++bucketIt->second.periodsSkipped,
        bucketIt->second.handles.size(),
        bucketIt->second.lastTickMilliseconds};
    }
    else
    {
      bucketIt->second.tickInFlight = true;
      generation = bucketIt->second.generation;
      // Counted from here, so that shutdown_async waits for this tick; finish_tick counts it out.
      ++mTicksInFlight;

      snapshots.reserve(bucketIt->second.handles.size());
      for (auto handle : bucketIt->second.handles)
      {
        auto entryIt = mEntries.find(handle);
        if (entryIt == mEntries.end())
        {
          continue;
        }

        auto& entry = entryIt->second;

        EntrySnapshot snap;
        snap.handle = handle;
        snap.node = entry.node;
        snap.readThroughReader = entry.readThroughReader;
        snap.nodeId = entry.nodeId;
        snap.attributeId = entry.attributeId;
        snap.indexRange = entry.indexRange;
        snap.range = entry.range;
        snap.monitoredItemId = entry.monitoredItemId;
        snap.sink = entry.sink;
        snap.lastPushedValue = entry.lastPushedValue;
        snap.kind = entry.kind;

        if (entry.kind == SamplingKind::ExceptionLatest)
        {
          snap.consumedLatest = std::exchange(entry.pendingLatest, std::nullopt);
        }
        else if (entry.kind == SamplingKind::ExceptionQueued)
        {
          snap.consumedQueued = std::exchange(entry.pendingQueued, {});
        }
        if (std::exchange(entry.readOnce, false))
        {
          // A value reported since the modify is newer than anything the read could add.
          snap.readOnce = !snap.consumedLatest.has_value() && snap.consumedQueued.empty();
        }

        snapshots.push_back(std::move(snap));
      }
    }
  }

  if (skipped.has_value())
  {
    report_skipped_period(bucketInterval, *skipped);
    return;
  }

  if (snapshots.empty())
  {
    // Nothing to do this tick - release the guard so the bucket can run next
    // period (the entries may have been removed between scheduling and firing).
    finish_tick(bucketInterval, generation);
    return;
  }

  assign_callers(snapshots);

  // The tick owns itself while a read is outstanding and holds the snapshots, so a reader that answers
  // later completes against valid state whenever it fires.
  TickTiming timing;
  timing.started = std::chrono::steady_clock::now();
  timing.bucketGeneration = generation;
  BucketTickOperation::start(shared_from_this(), bucketInterval, std::move(snapshots), timing);
}

void SamplingEngine::assign_callers(std::vector<EntrySnapshot>& snapshots) noexcept
{
  try
  {
    struct Asked
    {
      std::shared_ptr<const CallerInfo> caller;
      std::optional<StatusCode> failure;
    };

    std::unordered_map<SampleSink*, Asked> asked;
    for (auto& snap : snapshots)
    {
      if ((snap.kind != SamplingKind::Polled && !snap.readOnce) || !snap.readThroughReader || !snap.sink)
      {
        continue;
      }
      auto [it, first] = asked.try_emplace(snap.sink.get());
      if (first)
      {
        try
        {
          it->second.caller = snap.sink->caller();
        }
        catch (...)
        {
          it->second.failure = StatusCode{Status::BadInternalError,
            ErrorDetail::build("SampleSinkCallerThrew", "The sample sink's caller() threw", "SamplingEngine")
              .cause(exception_to_status_code(std::current_exception()))};
        }
      }
      snap.caller = it->second.caller;
      snap.callerFailure = it->second.failure;
    }
  }
  catch (...)
  {
    // Out of memory while asking: no item is read for a caller it was not given.
    for (auto& snap : snapshots)
    {
      if ((snap.kind == SamplingKind::Polled || snap.readOnce) && snap.readThroughReader && !snap.caller)
      {
        snap.callerFailure = StatusCode{Status::BadOutOfMemory};
      }
    }
  }
}

void SamplingEngine::finalise_bucket_tick(
  Duration bucketInterval, std::vector<EntrySnapshot> snapshots, TickTiming timing)
{
  // --- Deletion, checked again after the reads (no lock: deleted() is the Node's own code) ---
  // A deletion that landed between the tick's check and its read is found here, and the notice
  // replaces what the read answered, so it gives one notice rather than a sample and then a notice.
  for (auto& snap : snapshots)
  {
    if (!snap.deleted && snap.node && snap.node->deleted())
    {
      snap.deleted = true;
    }
  }

  // --- Reported values narrowed per registration (no lock), before change detection ---
  // attribute_changed stores the whole value for every entry on the attribute; each registration's range
  // is applied here, so that change detection compares what its item receives (NR-48 rule 2).
  for (auto& snap : snapshots)
  {
    if (!snap.range)
    {
      continue;
    }
    if (snap.consumedLatest)
    {
      narrow(*snap.consumedLatest, snap.range.get());
    }
    for (auto& queued : snap.consumedQueued)
    {
      narrow(queued, snap.range.get());
    }
  }

  // --- Change detection (no lock) ---
  struct PendingDelivery
  {
    size_t snapshot{0};
    std::vector<DataValue> values;
  };

  std::vector<PendingDelivery> deliveries;
  std::vector<size_t> notices;

  for (size_t index = 0; index < snapshots.size(); ++index)
  {
    auto& snap = snapshots[index];
    if (snap.deleted)
    {
      // What the tick read is dropped; values reported before the deletion are real changes and are
      // delivered below, ahead of the notice (Part 4 5.12.1.5).
      notices.push_back(index);
    }
    if (snap.kind == SamplingKind::Polled || snap.readOnce)
    {
      if (!snap.deleted && !data_values_equal_for_monitoring(snap.currentValue, snap.lastPushedValue))
      {
        deliveries.push_back({index, {std::move(snap.currentValue)}});
      }
    }
    else if (snap.kind == SamplingKind::ExceptionLatest)
    {
      if (snap.consumedLatest.has_value() &&
          !data_values_equal_for_monitoring(*snap.consumedLatest, snap.lastPushedValue))
      {
        deliveries.push_back({index, {std::move(*snap.consumedLatest)}});
      }
    }
    else if (snap.kind == SamplingKind::ExceptionQueued)
    {
      if (!snap.consumedQueued.empty())
      {
        deliveries.push_back({index, std::move(snap.consumedQueued)});
      }
    }
  }

  // --- Write-back phase: what is still delivered is decided here, under the lock ---
  // An entry removed since the snapshot delivers nothing, and once shutdown has begun nothing is
  // delivered at all. The deliveries are decided before the notices, because a deleted Node's entry is
  // erased with its index slot when its notice is decided: so its notice is sent once however many
  // ticks saw the deletion, the Node is no longer held by the entry, and the values reported before the
  // deletion still go out with this tick.
  std::unordered_map<SampleSink*, std::vector<std::pair<IntegerId, DataValue>>> batches;
  std::unordered_map<SampleSink*, std::shared_ptr<SampleSink>> sinkOwners;
  std::vector<std::pair<std::shared_ptr<SampleSink>, IntegerId>> noticesToSend;
  {
    const std::lock_guard lock{mMutex};
    if (!mShutdownFlag)
    {
      for (auto& delivery : deliveries)
      {
        const auto& snap = snapshots[delivery.snapshot];
        auto it = mEntries.find(snap.handle);
        if (it == mEntries.end() || delivery.values.empty())
        {
          continue;
        }
        it->second.lastPushedValue = delivery.values.back();
        auto& batch = batches[snap.sink.get()];
        for (auto& value : delivery.values)
        {
          batch.emplace_back(snap.monitoredItemId, std::move(value));
        }
        sinkOwners.emplace(snap.sink.get(), snap.sink);
      }
      for (const auto index : notices)
      {
        const auto& snap = snapshots[index];
        auto it = mEntries.find(snap.handle);
        if (it == mEntries.end())
        {
          continue;
        }
        erase_entry_locked(it);
        noticesToSend.emplace_back(snap.sink, snap.monitoredItemId);
      }
    }
  }

  // --- Push phase: deliver batches and notices to sinks (no lock) ---
  for (auto& [sinkRaw, batch] : batches)
  {
    auto& sink = sinkOwners[sinkRaw];
    // finalise_bucket_tick runs inside an Asio completion handler - the bucket tick, on its
    // strand. A user-supplied SampleSink::push is not noexcept; a throwing sink would unwind out of
    // io_context::run() -> std::terminate. Contain it here so the boundary holds, mirroring the
    // defensive catch already wrapping the reader's await. No Logger is in scope, so the no-logger
    // invoke_user_callback overload is used.
    ua::detail::invoke_user_callback([&sink, &batch] { sink->push(std::move(batch)); });
  }
  for (auto& [sink, monitoredItemId] : noticesToSend)
  {
    if (sink)
    {
      // Part 4 5.12.1.6: the item reports the deletion with Bad_NodeIdUnknown and is not deleted.
      ua::detail::invoke_user_callback(
        [&sink, id = monitoredItemId] { sink->invalidate(id, StatusCode{Status::BadNodeIdUnknown}); });
    }
  }

  // After the push, because the push is on this tick's strand too: a figure that stopped at the
  // write-back would understate what one interval occupies.
  record_tick(bucketInterval, timing, std::chrono::steady_clock::now() - timing.started);

  // The guard is released only now, after the push: the next tick of this bucket cannot deliver
  // anything - a deletion's notice included - ahead of what this tick delivered (Part 4 5.12.1.5).
  finish_tick(bucketInterval, timing.bucketGeneration);
}

void SamplingEngine::record_tick(
  Duration bucketInterval, const TickTiming& timing, std::chrono::steady_clock::duration totalPhase)
{
  if (timing.polledItems == 0)
  {
    // No read happened, so there is no per-item cost to learn from. A bucket holding only
    // exception-mode items reaches here every tick.
    return;
  }

  const double totalMilliseconds = std::chrono::duration<double, std::milli>(totalPhase).count();

  const std::lock_guard lock{mMutex};
  auto bucketIt = mBuckets.find(bucketInterval);
  if (bucketIt == mBuckets.end())
  {
    return;
  }
  auto& bucket = bucketIt->second;

  ++bucket.ticksCompleted;
  bucket.lastTickMilliseconds = totalMilliseconds;
  if (totalMilliseconds > bucketInterval)
  {
    // The tick did not fit in its period. Whether that costs a sample depends on how far it ran over,
    // which is why this is counted separately from periodsSkipped.
    ++bucket.ticksOverInterval;
  }
}

std::vector<SamplingEngine::BucketMetrics> SamplingEngine::metrics() const
{
  std::vector<BucketMetrics> result;
  const std::lock_guard lock{mMutex};
  result.reserve(mBuckets.size());
  for (const auto& [interval, bucket] : mBuckets)
  {
    BucketMetrics entry;
    entry.interval = interval;
    entry.items = bucket.handles.size();
    entry.ticksCompleted = bucket.ticksCompleted;
    entry.periodsSkipped = bucket.periodsSkipped;
    entry.ticksOverInterval = bucket.ticksOverInterval;
    entry.lastTickMilliseconds = bucket.lastTickMilliseconds;
    result.push_back(entry);
  }
  return result;
}

}  // namespace ua::default_ns
