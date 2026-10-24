// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the event bus asks the namespaces that hold an Event's notifiers: the climb from the SourceNode one
// level at a time, with one lookup and one inverse References read per namespace per level; one View
// membership call per View per Event; a References read that pages without end bounded; a bad answer for
// one Node stopping the climb at that Node only; a null SourceNode not looked up, and a climb lookup,
// References read or check that fails with Bad_NodeIdUnknown logged at Debug while another failure is a
// Warning; and the emit order kept while a level waits on a late answer.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "ua_address_space.h"
#include "ua_base_event.h"
#include "ua_browse_direction.h"
#include "ua_byte_string.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_event_notifier_type.h"
#include "ua_expanded_node_id.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "counting_executor.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;
using Call = BatchRecordingNamespace::Call;
using QueryRecord = BatchRecordingNamespace::ReferenceQueryRecord;

namespace
{

// How long an arm waits for a delivery, and for the executor to have no work left.
constexpr auto deliveryTimeout = 5s;

// The number of answers in a row with a resume token and no References after which a namespace's paging is
// not followed (DL-67 (8), `maxEmptyReferencePages`).
constexpr std::size_t emptyPageBound = 1024;

const NodeId serverObjectId{ObjectId::Server};
const NodeId hasNotifierId{ReferenceTypeId::HasNotifier};
const NodeId hasEventSourceId{ReferenceTypeId::HasEventSource};

/// The Events one item received, in order. Shared with the bus's callback, which may outlive the test body.
class DeliveryTracker
{
public:
  void on_event(std::shared_ptr<const BaseEvent> event)
  {
    const std::lock_guard lock{mMutex};
    mEvents.push_back(std::move(event));
    mArrived.notify_all();
  }

  std::size_t delivery_count() const
  {
    const std::lock_guard lock{mMutex};
    return mEvents.size();
  }

  std::vector<std::shared_ptr<const BaseEvent>> events() const
  {
    const std::lock_guard lock{mMutex};
    return mEvents;
  }

  /// Waits until @p count Events have arrived, or @p limit passes.
  bool wait_for_count(std::size_t count, std::chrono::milliseconds limit)
  {
    std::unique_lock lock{mMutex};
    return mArrived.wait_for(lock, limit, [&] { return mEvents.size() >= count; });
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mArrived;
  std::vector<std::shared_ptr<const BaseEvent>> mEvents;
};

/// Keeps each log entry's level, category, message and structured `status` field, and its text: the message
/// and every string field.
class RecordingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    Entry kept{entry.level, std::string{entry.category}, entry.message, {}, entry.message};
    for (const auto& field : entry.fields)
    {
      if (const auto* value = std::get_if<std::string_view>(&field.value))
      {
        kept.text += " ";
        kept.text += *value;
        if (field.key == "status")
        {
          kept.status = std::string{*value};
        }
      }
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(kept));
  }

  /// How many entries, of any level and category, mention @p text.
  std::size_t count_mentioning(std::string_view text) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry) { return entry.text.find(text) != std::string::npos; }));
  }

  /// How many entries of @p level in @p category have a message that mentions @p site.
  std::size_t count(LogLevel level, std::string_view category, std::string_view site) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry)
      {
        return entry.level == level && entry.category == category &&
               entry.message.find(site) != std::string::npos;
      }));
  }

  /// How many entries of @p level in @p category have a message that mentions @p site and the `status` field
  /// @p status.
  std::size_t count_with_status(
    LogLevel level, std::string_view category, std::string_view site, std::string_view status) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry)
      {
        return entry.level == level && entry.category == category &&
               entry.message.find(site) != std::string::npos && entry.status == status;
      }));
  }

  /// The `status` fields of the entries of @p level in @p category whose message mentions @p site.
  std::string statuses(LogLevel level, std::string_view category, std::string_view site) const
  {
    const std::lock_guard lock{mMutex};
    std::string text;
    for (const auto& entry : mEntries)
    {
      if (entry.level == level && entry.category == category && entry.message.find(site) != std::string::npos)
      {
        text += " " + entry.status;
      }
    }
    return text;
  }

  /// How many entries of @p level or a more severe level, of any category, have been kept.
  std::size_t count_at_or_above(LogLevel level) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(
      mEntries.begin(), mEntries.end(), [&](const Entry& entry) { return entry.level >= level; }));
  }

  /// How many entries of exactly @p level, of any category, have been kept.
  std::size_t count_at_level(LogLevel level) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(
      mEntries.begin(), mEntries.end(), [&](const Entry& entry) { return entry.level == level; }));
  }

  /// How many entries, of any level and category, have a message that mentions @p site.
  std::size_t count_at_site(std::string_view site) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry) { return entry.message.find(site) != std::string::npos; }));
  }

  /// The entries of @p level or a more severe level, one per line: level, category, message and `status`
  /// field.
  std::string describe_at_or_above(LogLevel level) const
  {
    const std::lock_guard lock{mMutex};
    std::string text;
    for (const auto& entry : mEntries)
    {
      if (entry.level >= level)
      {
        text += "\n  " + std::string{to_string(entry.level)} + " [" + entry.category + "] " + entry.message +
                " status " + (entry.status.empty() ? std::string{"(none)"} : entry.status);
      }
    }
    return text.empty() ? std::string{" none"} : text;
  }

  /// Discards the entries kept so far, so that the entries that follow are those of one stimulus.
  void clear()
  {
    const std::lock_guard lock{mMutex};
    mEntries.clear();
  }

private:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::string status;
    std::string text;
  };

  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

std::string describe(const std::vector<NodeId>& nodeIds)
{
  std::string text;
  for (const auto& nodeId : nodeIds)
  {
    text += " " + nodeId.as_definition();
  }
  return text;
}

std::string describe(const std::vector<Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += "\n  call" + describe(call.nodeIds);
    for (const auto& query : call.referenceQueries)
    {
      text += "\n    query " + query.nodeId.as_definition() + " direction " +
              std::to_string(static_cast<int>(query.direction)) + " hint" + describe(query.referenceTypeHint);
    }
  }
  return text;
}

std::vector<NodeId> candidates_of(const Call& call)
{
  std::vector<NodeId> candidates;
  for (const auto& candidate : call.candidates)
  {
    candidates.push_back(candidate.node_id());
  }
  return candidates;
}

std::string describe_membership(const std::vector<Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += "\n  view " + call.view.as_definition() + " candidates" + describe(candidates_of(call));
  }
  return text;
}

std::string text_of(const ByteString& token)
{
  return std::string{reinterpret_cast<const char*>(token.data()), token.size()};
}

/// Whether @p call names @p nodeId anywhere: among its NodeIds, as its View, or among its candidates.
bool names(const Call& call, const NodeId& nodeId)
{
  if (std::find(call.nodeIds.begin(), call.nodeIds.end(), nodeId) != call.nodeIds.end() ||
      call.view == nodeId)
  {
    return true;
  }
  const auto candidates = candidates_of(call);
  return std::find(candidates.begin(), candidates.end(), nodeId) != candidates.end();
}

/// The queries naming @p nodeId among the `read_references_async` calls @p nameSpace recorded, in order.
std::vector<QueryRecord> queries_naming(const BatchRecordingNamespace& nameSpace, const NodeId& nodeId)
{
  std::vector<QueryRecord> queries;
  for (const auto& call : nameSpace.calls(Member::ReadReferences))
  {
    for (const auto& query : call.referenceQueries)
    {
      if (query.nodeId == nodeId)
      {
        queries.push_back(query);
      }
    }
  }
  return queries;
}

/// The Objects S, P1, P2 and R in one recording namespace, each with SubscribeToEvents, and the References
/// P1 HasNotifier S, P2 HasEventSource S, R HasNotifier P1, R HasNotifier P2 and Server Object HasNotifier R.
struct Chain
{
  std::shared_ptr<BatchRecordingNamespace> nameSpace;
  NodeId s;
  NodeId p1;
  NodeId p2;
  NodeId r;
};

/// An address space whose namespace 0 holds only the Server Object, with SubscribeToEvents, an event bus on
/// it, and the recording namespaces a test registers.
class EventFlowTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mIdleCounter = std::make_shared<ua::test_helpers::ExecutorIdleCounter>();
    mAddressSpace = AddressSpace::create("uri:test:event-flow", counting_executor());
    auto server = mAddressSpace->try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
    ASSERT_TRUE(server.is_good()) << to_string(server.status_code());
    server.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  }

  void TearDown() override
  {
    // Nothing a test scripted is left holding or paging, so that every read can finish.
    for (const auto& nameSpace : mNamespaces)
    {
      nameSpace->page_without_end_of({});
      nameSpace->hold_reference_reads_of({});
      nameSpace->release_held_reference_reads();
    }
    mIdleCounter->wait_for_idle(deliveryTimeout);
    mEventBus.reset();
    mAddressSpace.reset();
    mNamespaces.clear();
    mThreadPool.join();
  }

  /// The fixture's executor, counted by the idle counter.
  boost::asio::any_io_executor counting_executor()
  {
    return boost::asio::any_io_executor{
      ua::test_helpers::CountingExecutor{mThreadPool.get_executor(), mIdleCounter}};
  }

  /// Waits until the executor has no work left, or the delivery timeout passes.
  bool settle()
  {
    return mIdleCounter->wait_for_idle(deliveryTimeout);
  }

  /// Registers a recording namespace under @p uri; @p index receives its index.
  std::shared_ptr<BatchRecordingNamespace> add_recording_namespace(const std::string& uri, uint16_t& index)
  {
    auto nameSpace = std::make_shared<BatchRecordingNamespace>(uri, counting_executor());
    const auto added = mAddressSpace->try_add_namespace_sync(nameSpace);
    EXPECT_TRUE(added.is_good()) << to_string(added.status_code());
    index = added.is_good() ? added.value() : uint16_t{0};
    mNamespaces.push_back(nameSpace);
    return nameSpace;
  }

  /// An Object with SubscribeToEvents.
  void make_notifier(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    ASSERT_TRUE(created.is_good()) << nodeId.as_definition() << ": " << to_string(created.status_code());
    created.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  }

  /// A View with SubscribeToEvents.
  void make_view(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_sync<ViewAccessor>(nodeId, NodeClass::View);
    ASSERT_TRUE(created.is_good()) << nodeId.as_definition() << ": " << to_string(created.status_code());
    created.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  }

  /// A ReferenceType Node.
  void make_reference_type(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_sync<ReferenceTypeAccessor>(nodeId, NodeClass::ReferenceType);
    ASSERT_TRUE(created.is_good()) << nodeId.as_definition() << ": " << to_string(created.status_code());
  }

  /// A Reference of @p referenceType from @p source to @p target: the forward half held by the source and
  /// the inverse half held by the target.
  void link(const NodeId& source, const NodeId& referenceType, const NodeId& target)
  {
    auto from = mAddressSpace->try_find_node_sync(source);
    auto to = mAddressSpace->try_find_node_sync(target);
    ASSERT_TRUE(from.is_good()) << source.as_definition();
    ASSERT_TRUE(to.is_good()) << target.as_definition();
    EXPECT_TRUE(from.value().try_add_reference_sync(referenceType, ExpandedNodeId{target}, true).is_good())
      << source.as_definition() << " to " << target.as_definition();
    EXPECT_TRUE(to.value().try_add_reference_sync(referenceType, ExpandedNodeId{source}, false).is_good())
      << target.as_definition() << " from " << source.as_definition();
  }

  /// The chain of @ref Chain in a recording namespace registered under @p uri, which declines its immediate
  /// lookups.
  Chain make_chain(const std::string& uri)
  {
    uint16_t index = 0;
    Chain chain;
    chain.nameSpace = add_recording_namespace(uri, index);
    chain.s = NodeId{index, 1u};
    chain.p1 = NodeId{index, 2u};
    chain.p2 = NodeId{index, 3u};
    chain.r = NodeId{index, 4u};
    for (const auto& nodeId : {chain.s, chain.p1, chain.p2, chain.r})
    {
      make_notifier(nodeId);
    }
    link(chain.p1, hasNotifierId, chain.s);
    link(chain.p2, hasEventSourceId, chain.s);
    link(chain.r, hasNotifierId, chain.p1);
    link(chain.r, hasNotifierId, chain.p2);
    link(serverObjectId, hasNotifierId, chain.r);
    chain.nameSpace->decline_single_lookups();
    return chain;
  }

  /// Registers an event item on @p nodeId whose deliveries @p tracker records.
  EventMonitoringHandle subscribe(
    const NodeId& nodeId, IntegerId monitoredItemId, const std::shared_ptr<DeliveryTracker>& tracker)
  {
    return mEventBus->register_event_item(nodeId,
      monitoredItemId,
      0,
      [tracker](IntegerId, std::shared_ptr<const BaseEvent> event) { tracker->on_event(std::move(event)); });
  }

  static BaseEvent make_event(NodeId sourceNode)
  {
    BaseEvent event;
    event.eventType = NodeId{ObjectTypeId::BaseEventType};
    event.sourceNode = std::move(sourceNode);
    event.sourceName = String{"Test"};
    event.message = LocalizedText{LocaleId{}, String{"Test event"}};
    event.severity = 500;
    return event;
  }

  boost::asio::thread_pool mThreadPool{2};
  std::shared_ptr<ua::test_helpers::ExecutorIdleCounter> mIdleCounter;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<EventBus> mEventBus;
  std::vector<std::shared_ptr<BatchRecordingNamespace>> mNamespaces;
};

class EventClimbFlow : public EventFlowTest
{};

class EventViewFlow : public EventFlowTest
{};

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-THE-CLIMB-MAKES-ONE-LOOKUP-AND-ONE-REFERENCE-READ-PER-LEVEL, scope=function)
TEST_F(EventClimbFlow, OneLookupAndOneReferenceReadPerLevel)
{
  const Chain chain = make_chain("urn:test:event-climb-flow:levels");
  auto atR = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(chain.r, 1, atR);
  subscribe(serverObjectId, 2, atServer);
  chain.nameSpace->reset();

  auto event = make_event(chain.s);
  mEventBus->emit(event);
  atServer->wait_for_count(1, deliveryTimeout);
  settle();

  const std::vector<std::vector<NodeId>> levels{{chain.s}, sorted({chain.p1, chain.p2}), {chain.r}};
  const auto lookups = chain.nameSpace->calls(Member::BatchedLookup);
  EXPECT_EQ(lookups.size(), 3U) << "batched lookups:" << describe(lookups);
  for (std::size_t k = 0; k < lookups.size() && k < levels.size(); ++k)
  {
    EXPECT_EQ(sorted(lookups[k].nodeIds), levels[k])
      << "lookup " << k + 1 << " names" << describe(lookups[k].nodeIds);
  }

  const auto reads = chain.nameSpace->calls(Member::ReadReferences);
  const std::vector<NodeId> eventSourceHint = sorted({hasEventSourceId, hasNotifierId});
  EXPECT_EQ(reads.size(), 3U) << "read_references_async calls:" << describe(reads);
  for (std::size_t k = 0; k < reads.size() && k < levels.size(); ++k)
  {
    EXPECT_EQ(sorted(reads[k].nodeIds), levels[k])
      << "read " << k + 1 << " names" << describe(reads[k].nodeIds);
    for (const auto& query : reads[k].referenceQueries)
    {
      EXPECT_EQ(query.direction, BrowseDirection::Inverse)
        << "read " << k + 1 << ", the query naming " << query.nodeId.as_definition() << " has direction "
        << static_cast<int>(query.direction);
      EXPECT_EQ(sorted(query.referenceTypeHint), eventSourceHint)
        << "read " << k + 1 << ", the query naming " << query.nodeId.as_definition() << " has the hint"
        << describe(query.referenceTypeHint);
    }
  }

  EXPECT_EQ(atR->delivery_count(), 1U) << "R's item";
  EXPECT_EQ(atServer->delivery_count(), 1U) << "the Server Object's item";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-ONE-MEMBERSHIP-CALL-PER-VIEW-PER-EVENT, scope=function)
TEST_F(EventViewFlow, OneMembershipCallPerViewPerEvent)
{
  uint16_t index = 0;
  auto nameSpace = add_recording_namespace("urn:test:event-view-flow:membership", index);
  const NodeId s{index, 1u};
  const NodeId p1{index, 2u};
  const NodeId v{index, 10u};
  make_notifier(s);
  make_notifier(p1);
  link(p1, hasNotifierId, s);
  make_view(v);
  nameSpace->answer_view_membership([p1](const NodeId&, const NodeId& candidate) { return candidate == p1; });
  nameSpace->decline_single_lookups();
  auto atView = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(v, 1, atView);
  subscribe(serverObjectId, 2, atServer);
  nameSpace->reset();

  auto event = make_event(s);
  mEventBus->emit(event);
  atServer->wait_for_count(1, deliveryTimeout);
  settle();

  const auto asked = nameSpace->calls(Member::ViewContains);
  EXPECT_EQ(asked.size(), 1U) << "view_contains_async calls:" << describe_membership(asked);
  for (const auto& call : asked)
  {
    EXPECT_EQ(call.view, v) << "a call names the View " << call.view.as_definition();
    const auto candidates = candidates_of(call);
    EXPECT_EQ(std::count(candidates.begin(), candidates.end(), serverObjectId), 0)
      << "a call names the Server Object among its candidates:" << describe(candidates);
    EXPECT_EQ(std::count(candidates.begin(), candidates.end(), v), 0)
      << "a call names V among its candidates:" << describe(candidates);
  }
  if (asked.size() == 1U)
  {
    EXPECT_EQ(sorted(candidates_of(asked[0])), sorted({s, p1}))
      << "the call's candidates:" << describe(candidates_of(asked[0]));
  }

  EXPECT_EQ(atView->delivery_count(), 1U) << "V's item";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-A-CLIMB-READ-THAT-PAGES-WITHOUT-END-IS-BOUNDED, scope=function)
TEST_F(EventClimbFlow, AReadThatPagesWithoutEndIsBoundedAndTheEventDelivered)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  const Chain chain = make_chain("urn:test:event-climb-flow:paging-without-end");
  auto atR = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(chain.r, 1, atR);
  subscribe(serverObjectId, 2, atServer);
  chain.nameSpace->page_without_end_of({chain.p1});
  chain.nameSpace->reset();

  auto event = make_event(chain.s);
  mEventBus->emit(event);

  // Waits up to 5 s for both deliveries; gives up early once P1 has been read well past the bound, since
  // nothing then stops the paging but the end of the wait.
  const auto until = std::chrono::steady_clock::now() + deliveryTimeout;
  bool delivered = false;
  while (std::chrono::steady_clock::now() < until)
  {
    if (atR->delivery_count() >= 1U && atServer->delivery_count() >= 1U)
    {
      delivered = true;
      break;
    }
    if (queries_naming(*chain.nameSpace, chain.p1).size() > emptyPageBound + 100)
    {
      break;
    }
    std::this_thread::sleep_for(10ms);
  }
  const std::size_t p1QueriesWhenWaitEnded = queries_naming(*chain.nameSpace, chain.p1).size();
  // Stops the answers without end, so that every read can finish.
  chain.nameSpace->page_without_end_of({});
  settle();

  EXPECT_TRUE(delivered)
    << "R's item and the Server Object's item did not both receive the Event within 5 s; "
    << "P1 had been read in " << p1QueriesWhenWaitEnded << " queries when the wait ended";
  EXPECT_EQ(atR->delivery_count(), 1U) << "R's item";
  EXPECT_EQ(atServer->delivery_count(), 1U) << "the Server Object's item";
  EXPECT_EQ(sink->count_mentioning("NamespacePagingDidNotEnd"), 1U)
    << "log entries mentioning NamespacePagingDidNotEnd";

  ByteString lastToken;
  for (const auto& query : queries_naming(*chain.nameSpace, chain.p1))
  {
    if (!query.answeredToken.empty())
    {
      lastToken = query.answeredToken;
    }
  }
  ASSERT_FALSE(lastToken.empty()) << "the namespace answered P1 with no resume token";
  const auto releases = chain.nameSpace->calls(Member::ReleaseResumeToken);
  std::string released;
  for (const auto& release : releases)
  {
    released += " \"" + text_of(release.token) + "\"";
  }
  EXPECT_TRUE(std::any_of(
    releases.begin(), releases.end(), [&](const Call& release) { return release.token == lastToken; }))
    << "P1's last token \"" << text_of(lastToken) << "\" was not released; released:" << released;
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-A-BAD-ANSWER-FOR-ONE-NODE-LEAVES-THE-OTHERS-CLIMBING, scope=function)
TEST_F(EventClimbFlow, ABadAnswerForOneNodeOfALevelLeavesTheOthersClimbing)
{
  struct Case
  {
    const char* name;
    std::string uri;
    bool p1Receives;
    std::function<void(const Chain&)> script;
    // The status P1's References read must have been answered with, for the case to have its fault.
    std::optional<Status> p1ReadAnswer;
  };

  const std::vector<Case> cases{
    {"case 1, P1's References answered Bad_InternalError",
      "urn:test:event-climb-flow:bad-references",
      true,
      [](const Chain& chain)
      {
        chain.nameSpace->answer_reference_query_of(chain.p1,
          1,
          StatusCode{Status::BadInternalError,
            ErrorDetail::build("ScriptedReferencesFailure",
              "The test's namespace cannot read these References",
              "TestNamespace")});
      },
      Status::BadInternalError},
    {"case 2, P1's lookup answered Bad_NodeIdUnknown",
      "urn:test:event-climb-flow:bad-lookup",
      false,
      [](const Chain& chain)
      {
        chain.nameSpace->answer_lookup_of(chain.p1,
          StatusCode{Status::BadNodeIdUnknown,
            ErrorDetail::build(
              "ScriptedLookupFailure", "The test's namespace does not know this Node", "TestNamespace")});
      },
      std::nullopt},
  };

  IntegerId nextItem = 1;
  for (const auto& testCase : cases)
  {
    const Chain chain = make_chain(testCase.uri);
    auto atP1 = std::make_shared<DeliveryTracker>();
    auto atR = std::make_shared<DeliveryTracker>();
    auto atServer = std::make_shared<DeliveryTracker>();
    const std::vector<EventMonitoringHandle> handles{subscribe(chain.p1, nextItem++, atP1),
      subscribe(chain.r, nextItem++, atR),
      subscribe(serverObjectId, nextItem++, atServer)};
    testCase.script(chain);
    chain.nameSpace->reset();

    auto event = make_event(chain.s);
    mEventBus->emit(event);
    atServer->wait_for_count(1, deliveryTimeout);
    settle();

    if (testCase.p1ReadAnswer.has_value())
    {
      const auto ofP1 = queries_naming(*chain.nameSpace, chain.p1);
      EXPECT_TRUE(std::any_of(ofP1.begin(),
        ofP1.end(),
        [&](const QueryRecord& query) {
          return query.answeredStatus.has_value() &&
                 query.answeredStatus->as_status() == *testCase.p1ReadAnswer;
        }))
        << testCase.name << ": no References read of P1 was answered "
        << to_string(StatusCode{*testCase.p1ReadAnswer}) << ", so the stimulus never happened";
    }
    EXPECT_EQ(atR->delivery_count(), 1U) << testCase.name << ": R's item";
    EXPECT_EQ(atServer->delivery_count(), 1U) << testCase.name << ": the Server Object's item";
    EXPECT_EQ(atP1->delivery_count(), testCase.p1Receives ? 1U : 0U) << testCase.name << ": P1's item";

    for (const auto handle : handles)
    {
      mEventBus->deregister_event_item(handle);
    }
    settle();
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-A-SOURCE-THAT-DOES-NOT-RESOLVE-LOGS-NO-WARNING, scope=function)
TEST_F(EventClimbFlow, ASourceThatDoesNotResolveLogsNoWarning)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  const Chain chain = make_chain("urn:test:event-climb-flow:source-that-does-not-resolve");
  // The Events' type, which a Server's namespace 0 holds, so that resolving its hierarchy logs nothing.
  auto baseEventType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(baseEventType.is_good()) << to_string(baseEventType.status_code());
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(serverObjectId, 1, atServer);
  // S's Node, which the namespace answers S's lookup with from Event 4 on: found for Events 4 and 5, and
  // after it has been deleted for Event 6.
  const auto sNode = static_cast<default_ns::Namespace&>(*chain.nameSpace).find_node<Node>(chain.s);
  ASSERT_NE(sNode, nullptr);

  constexpr std::string_view lookupSite{"EventBus.NotifierClimbLookup"};
  constexpr std::string_view referencesSite{"EventBus.NotifierClimbReferences"};
  constexpr std::string_view validationSite{"EventBus.NotifierClimbValidation"};
  const std::string nodeIdUnknown = to_string(StatusCode{Status::BadNodeIdUnknown});
  const std::string internalError = to_string(StatusCode{Status::BadInternalError});
  const auto refusal = [](Status status)
  {
    return StatusCode{status,
      ErrorDetail::build("ScriptedClimbFailure", "The test's namespace refuses this Node", "TestNamespace")};
  };
  // The lookups, in either form, that name S.
  const auto lookupsOfS = [&]
  {
    std::size_t lookups = 0;
    for (const auto member : {Member::BatchedLookup, Member::SingleLookup})
    {
      for (const auto& call : chain.nameSpace->calls(member))
      {
        lookups += names(call, chain.s) ? 1U : 0U;
      }
    }
    return lookups;
  };
  // Emits an Event whose SourceNode is @p sourceNode into a cleared sink, waits until it has been delivered
  // and the executor is idle, and expects the Server Object's item to have received it once.
  const auto emit = [&](const std::string& name, const NodeId& sourceNode)
  {
    sink->clear();
    const std::size_t deliveredBefore = atServer->delivery_count();
    auto event = make_event(sourceNode);
    mEventBus->emit(event);
    const bool arrived = atServer->wait_for_count(deliveredBefore + 1, deliveryTimeout);
    settle();
    EXPECT_TRUE(arrived) << name << ": the Server Object's item did not receive the Event within 5 s";
    const auto received = atServer->events();
    EXPECT_EQ(std::count_if(received.begin(),
                received.end(),
                [&](const std::shared_ptr<const BaseEvent>& delivered)
                { return delivered->eventId == event.eventId; }),
      1)
      << name << ": deliveries of the Event to the Server Object's item";
  };
  // Expects the Event's climb to have logged exactly one entry at @p site, at @p level with @p status.
  const auto expectOneEntry =
    [&](const std::string& name, std::string_view site, LogLevel level, const std::string& status)
  {
    EXPECT_EQ(sink->count_at_site(site), 1U)
      << name << ": entries at " << site << "; every entry:" << sink->describe_at_or_above(LogLevel::Trace);
    EXPECT_EQ(sink->count_with_status(level, "events", site, status), 1U)
      << name << ": entries at " << site << " of level " << to_string(level) << " with status " << status
      << "; every entry:" << sink->describe_at_or_above(LogLevel::Trace);
  };
  const auto expectNoWarning = [&](const std::string& name)
  {
    EXPECT_EQ(sink->count_at_or_above(LogLevel::Warning), 0U)
      << name << ": the entries at Warning or above:" << sink->describe_at_or_above(LogLevel::Warning);
  };
  const auto expectOneWarning = [&](const std::string& name, std::string_view site)
  {
    EXPECT_EQ(sink->count_at_level(LogLevel::Warning), 1U)
      << name
      << ": Warnings; the entries at Warning or above:" << sink->describe_at_or_above(LogLevel::Warning);
    EXPECT_EQ(sink->count_with_status(LogLevel::Warning, "events", site, internalError), 1U)
      << name << ": Warnings at " << site << " with status " << internalError
      << "; the entries at Warning or above:" << sink->describe_at_or_above(LogLevel::Warning);
  };

  {
    const std::string name{"Event 1, a null SourceNode"};
    emit(name, NodeId{});
    EXPECT_EQ(sink->count_at_site(lookupSite), 0U)
      << name << ": entries at " << lookupSite
      << "; every entry:" << sink->describe_at_or_above(LogLevel::Trace);
    expectNoWarning(name);
  }
  {
    const std::string name{"Event 2, S's lookup answered Bad_NodeIdUnknown"};
    chain.nameSpace->answer_lookup_of(chain.s, refusal(Status::BadNodeIdUnknown));
    const std::size_t before = lookupsOfS();
    emit(name, chain.s);
    EXPECT_GT(lookupsOfS(), before) << name << ": no lookup named S, so the stimulus never happened";
    expectOneEntry(name, lookupSite, LogLevel::Debug, nodeIdUnknown);
    expectNoWarning(name);
  }
  {
    const std::string name{"Event 3 (the control for 2), S's lookup answered Bad_InternalError"};
    chain.nameSpace->answer_lookup_of(chain.s, refusal(Status::BadInternalError));
    const std::size_t before = lookupsOfS();
    emit(name, chain.s);
    EXPECT_GT(lookupsOfS(), before) << name << ": no lookup named S, so the stimulus never happened";
    expectOneWarning(name, lookupSite);
  }
  for (const auto status : {Status::BadNodeIdUnknown, Status::BadInternalError})
  {
    const bool unknown = status == Status::BadNodeIdUnknown;
    const std::string name{unknown ? "Event 4, S found and its References read answered Bad_NodeIdUnknown"
                                   : "Event 5 (the control for 4), S found and its References read answered "
                                     "Bad_InternalError"};
    chain.nameSpace->answer_lookup_of(chain.s, sNode);
    // The scripted query is counted over every query naming S since the namespace was made; this test never
    // clears the namespace's record, so the record holds them all.
    const std::size_t queriesBefore = queries_naming(*chain.nameSpace, chain.s).size();
    chain.nameSpace->answer_reference_query_of(chain.s, queriesBefore + 1, refusal(status));
    emit(name, chain.s);
    const auto queries = queries_naming(*chain.nameSpace, chain.s);
    EXPECT_TRUE(queries.size() > queriesBefore && queries[queriesBefore].answeredStatus.has_value() &&
                queries[queriesBefore].answeredStatus->as_status() == status)
      << name << ": S's References read was not answered " << to_string(StatusCode{status})
      << ", so the stimulus never happened";
    if (unknown)
    {
      expectOneEntry(name, referencesSite, LogLevel::Debug, nodeIdUnknown);
      expectNoWarning(name);
    }
    else
    {
      expectOneWarning(name, referencesSite);
    }
  }
  {
    const std::string name{"Event 6, S's lookup answered with S's Node, deleted after it was found"};
    // S's lookup still answers sNode, scripted for Event 5; deleting S leaves that Node deleted.
    ASSERT_TRUE(mAddressSpace->try_delete_node_sync(chain.s, false).is_good());
    settle();
    const std::size_t before = lookupsOfS();
    emit(name, chain.s);
    EXPECT_GT(lookupsOfS(), before) << name << ": no lookup named S, so the stimulus never happened";
    expectOneEntry(name, validationSite, LogLevel::Debug, nodeIdUnknown);
    expectNoWarning(name);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-A-LEVEL-THAT-ANSWERS-LATE-KEEPS-THE-EMIT-ORDER, scope=function)
TEST_F(EventClimbFlow, ALevelThatAnswersLateKeepsTheEmitOrder)
{
  const Chain chain = make_chain("urn:test:event-climb-flow:late-level");
  auto atR = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(chain.r, 1, atR);
  subscribe(serverObjectId, 2, atServer);
  chain.nameSpace->hold_reference_reads_of({chain.p1});
  chain.nameSpace->reset();

  auto first = make_event(chain.s);
  mEventBus->emit(first);
  const bool held = chain.nameSpace->wait_for_held_reference_reads(1, deliveryTimeout);
  auto second = make_event(serverObjectId);
  mEventBus->emit(second);
  // E2 has every chance to overtake E1 while E1's climb waits on P1's read.
  settle();
  chain.nameSpace->hold_reference_reads_of({});
  chain.nameSpace->release_held_reference_reads();
  atServer->wait_for_count(2, deliveryTimeout);
  settle();

  EXPECT_TRUE(held) << "no References read naming P1 was held, so E1's climb never waited on it";
  std::vector<std::string> order;
  for (const auto& event : atServer->events())
  {
    order.push_back(
      event->eventId == first.eventId ? "E1" : (event->eventId == second.eventId ? "E2" : "other"));
  }
  EXPECT_EQ(order, (std::vector<std::string>{"E1", "E2"}))
    << "the Server Object's item received the Events in this order";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-12-A-SUPERTYPE-WALK-THAT-PAGES-WITHOUT-END-IS-BOUNDED, scope=function)
TEST_F(EventClimbFlow, ASupertypeWalkThatPagesWithoutEndIsBoundedAndReleasesItsToken)
{
  uint16_t index = 0;
  auto nameSpace = add_recording_namespace("urn:test:event-climb-flow:supertype-paging-without-end", index);
  const NodeId s{index, 1u};
  const NodeId p{index, 2u};
  const NodeId x{index, 50u};
  make_notifier(s);
  make_notifier(p);
  make_reference_type(x);
  link(p, x, s);
  nameSpace->decline_single_lookups();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(serverObjectId, 1, atServer);
  nameSpace->page_without_end_of({x});
  nameSpace->reset();

  auto event = make_event(s);
  mEventBus->emit(event);

  // Waits up to 5 s for the delivery; gives up early once X has been read well past the bound, since nothing
  // then stops the paging but the end of the wait.
  const auto until = std::chrono::steady_clock::now() + deliveryTimeout;
  bool delivered = false;
  while (std::chrono::steady_clock::now() < until)
  {
    if (atServer->delivery_count() >= 1U)
    {
      delivered = true;
      break;
    }
    if (queries_naming(*nameSpace, x).size() > emptyPageBound + 1 + 100)
    {
      break;
    }
    std::this_thread::sleep_for(10ms);
  }
  const std::size_t xQueriesWhenWaitEnded = queries_naming(*nameSpace, x).size();
  // Stops the answers without end, so that every read can finish.
  nameSpace->page_without_end_of({});
  settle();

  EXPECT_TRUE(delivered)
    << "the Server Object's item did not receive the Event within 5 s; X had been read in "
    << xQueriesWhenWaitEnded << " queries when the wait ended";
  EXPECT_EQ(atServer->delivery_count(), 1U) << "the Server Object's item";
  const auto ofX = queries_naming(*nameSpace, x);
  EXPECT_LE(ofX.size(), emptyPageBound + 1) << "read_references_async queries naming X";

  ByteString lastToken;
  for (const auto& query : ofX)
  {
    if (!query.answeredToken.empty())
    {
      lastToken = query.answeredToken;
    }
  }
  ASSERT_FALSE(lastToken.empty()) << "the namespace gave X no resume token, so the stimulus never happened";
  const auto releases = nameSpace->calls(Member::ReleaseResumeToken);
  std::string released;
  for (const auto& release : releases)
  {
    released += " \"" + text_of(release.token) + "\"";
  }
  EXPECT_TRUE(std::any_of(
    releases.begin(), releases.end(), [&](const Call& release) { return release.token == lastToken; }))
    << "the last token the namespace gave for X, \"" << text_of(lastToken)
    << "\", was not released; released:" << released;
}

// @relation(AC-COMP-SVR-EVENT-CLIMB-REFERENCE-TYPES-02-THE-WARNING-NAMES-THE-LOOKUPS-STATUS, scope=function)
TEST_F(EventClimbFlow, TheWarningForAMissingSupertypeNamesItsStatus)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  uint16_t index = 0;
  add_recording_namespace("urn:test:event-climb-flow:missing-supertype", index);
  const NodeId s{index, 1u};
  const NodeId p{index, 2u};
  const NodeId x{index, 50u};
  const NodeId missingSupertype{index, 99u};
  make_notifier(s);
  make_notifier(p);
  make_reference_type(x);
  {
    auto type = mAddressSpace->try_find_node_sync(x);
    ASSERT_TRUE(type.is_good()) << to_string(type.status_code());
    ASSERT_TRUE(
      type.value()
        .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{missingSupertype}, false)
        .is_good());
  }
  link(p, x, s);
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(serverObjectId, 1, atServer);

  auto event = make_event(s);
  mEventBus->emit(event);
  atServer->wait_for_count(1, deliveryTimeout);
  settle();

  constexpr std::string_view site{"EventBus.EventSourceReferenceType"};
  EXPECT_EQ(sink->count(LogLevel::Warning, "events", site), 1U)
    << "warnings in the category events with the context " << site;
  EXPECT_EQ(sink->count_with_status(
              LogLevel::Warning, "events", site, to_string(StatusCode{Status::BadNodeIdUnknown})),
    1U)
    << "warnings with the context " << site
    << " carrying Bad_NodeIdUnknown; their statuses:" << sink->statuses(LogLevel::Warning, "events", site);
  EXPECT_EQ(atServer->delivery_count(), 1U) << "the Server Object's item";
}

// @relation(AC-COMP-SVR-EVENT-CLIMB-REFERENCE-TYPES-02-A-TYPE-THAT-DOES-NOT-EXIST-IS-LOOKED-UP-ONCE-PER-GENERATION, scope=function)
TEST_F(EventClimbFlow, ATypeThatDoesNotExistIsLookedUpOncePerGeneration)
{
  uint16_t index = 0;
  auto nameSpace = add_recording_namespace("urn:test:event-climb-flow:type-that-does-not-exist", index);
  const NodeId s{index, 1u};
  const NodeId p{index, 2u};
  const NodeId x{index, 50u};
  make_notifier(s);
  make_notifier(p);
  link(p, x, s);
  nameSpace->decline_single_lookups();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(serverObjectId, 1, atServer);
  nameSpace->reset();

  std::vector<ByteString> emitted;
  for (std::size_t k = 1; k <= 3; ++k)
  {
    auto event = make_event(s);
    mEventBus->emit(event);
    emitted.push_back(event.eventId);
    EXPECT_TRUE(atServer->wait_for_count(k, deliveryTimeout)) << "Event " << k << " was not delivered";
    settle();
  }

  // The immediate form is declined, so every lookup reaches the batched member: a lookup is one batched call.
  std::size_t lookupsOfX = 0;
  for (const auto& call : nameSpace->calls(Member::BatchedLookup))
  {
    lookupsOfX += names(call, x) ? 1U : 0U;
  }
  EXPECT_EQ(lookupsOfX, 1U) << "batched lookups naming X:"
                            << describe(nameSpace->calls(Member::BatchedLookup));

  const auto received = atServer->events();
  EXPECT_EQ(received.size(), 3U) << "Events the Server Object's item received";
  for (std::size_t k = 0; k < emitted.size(); ++k)
  {
    EXPECT_EQ(std::count_if(received.begin(),
                received.end(),
                [&](const std::shared_ptr<const BaseEvent>& event) { return event->eventId == emitted[k]; }),
      1)
      << "Event " << k + 1 << " was not received once";
  }
}
