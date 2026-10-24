// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The route of a lookup through the address space to the namespaces that hold its Nodes
/// (COMP-ADDRSP-NAMESPACE-ROUTE-01, -02 and -04).
///
/// Every stub namespace here declines the single-Node fast path, so every lookup takes the batched path
/// (`AddressSpace::find_nodes_async` to `Namespace::find_nodes`), which is the one these criteria are about.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_service_operation_limits.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Forwards to a default namespace and answers each batched lookup in the way the test chooses.
class RouteTestNamespace final : public Namespace
{
public:
  enum class Answer
  {
    AsAnswered,
    Hold,
    Throw,
    FirstItemOnly,
    Twice,
    LookUpFirst,
    SingleNodeForm,
    GuardedCalls,
  };

  explicit RouteTestNamespace(std::shared_ptr<default_ns::Namespace> inner) : mInner(std::move(inner))
  {}

  /// Answers every lookup, value read and Method call it still holds with the batch status
  /// Bad_ResourceUnavailable, outside the lock.
  ~RouteTestNamespace() override
  {
    std::vector<HeldCall> held;
    std::vector<std::function<void(BatchResult<DataValueResult>)>> heldReads;
    std::vector<std::function<void(BatchResult<std::optional<CallResult>>)>> heldMethodCalls;
    {
      const std::lock_guard lock(mMutex);
      held.swap(mHeld);
      heldReads.swap(mHeldReads);
      heldMethodCalls.swap(mHeldMethodCalls);
    }
    const VoidResult unavailable{StatusCode{Status::BadResourceUnavailable}};
    for (auto& call : held)
    {
      BatchResult<NodeResult> answer;
      answer.batchStatus = unavailable;
      call.callback(std::move(answer));
    }
    for (auto& complete : heldReads)
    {
      BatchResult<DataValueResult> answer;
      answer.batchStatus = unavailable;
      complete(std::move(answer));
    }
    for (auto& complete : heldMethodCalls)
    {
      BatchResult<std::optional<CallResult>> answer;
      answer.batchStatus = unavailable;
      complete(std::move(answer));
    }
  }

  RouteTestNamespace(const RouteTestNamespace&) = delete;
  RouteTestNamespace& operator=(const RouteTestNamespace&) = delete;
  RouteTestNamespace(RouteTestNamespace&&) = delete;
  RouteTestNamespace& operator=(RouteTestNamespace&&) = delete;

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  String uri() const override
  {
    return mInner->uri();
  }

  // The member the address space calls to create a Node (NR-70 B7a).
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    const bool guardedOne = answer.load() == Answer::GuardedCalls && nodes.size() == 1;
    if (guardedOne && nodes.front().nodeId == guarded.throwsOnCreate)
    {
      throw std::runtime_error("injected failure in the namespace's create_nodes_async");
    }
    if (guardedOne && nodes.front().nodeId == guarded.completesTwice)
    {
      mInner->create_nodes_async(request,
        nodes,
        [complete = std::move(complete)](BatchResult<NodeResult> created) mutable
        {
          auto first = complete;
          first(std::move(created));
          BatchResult<NodeResult> again;
          again.items.push_back(NodeResult{StatusCode{Status::BadNodeIdExists}});
          complete(std::move(again));
        });
      return;
    }
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> callback) override
  {
    if (answer.load() == Answer::GuardedCalls)
    {
      throw std::runtime_error("injected failure in the namespace's enumerate_nodes_async");
    }
    mInner->enumerate_nodes_async(request, std::move(callback));
  }

  // No synchronous find_node, except in SingleNodeForm: every other lookup takes the batched path.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    if (answer.load() != Answer::SingleNodeForm)
    {
      return std::nullopt;
    }
    if (nodeId == singleNode.throws)
    {
      throw std::runtime_error("injected failure in the namespace's single-Node lookup");
    }
    if (nodeId == singleNode.answersAnother)
    {
      return mInner->find_node(singleNode.answered, maxAge);
    }
    if (nodeId == singleNode.answered)
    {
      return mInner->find_node(nodeId, maxAge);
    }
    return std::nullopt;
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    switch (answer.load())
    {
    case Answer::AsAnswered:
    case Answer::GuardedCalls:
      mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
      return;
    case Answer::Hold:
    {
      {
        const std::lock_guard lock(mMutex);
        mHeld.push_back(HeldCall{std::vector<NodeId>(nodeIds.begin(), nodeIds.end()), std::move(callback)});
      }
      mChanged.notify_all();
      return;
    }
    case Answer::Throw:
      throw std::runtime_error("injected failure in the namespace's lookup member");
    case Answer::FirstItemOnly:
      mInner->find_nodes_async(request,
        nodeIds,
        maxAge,
        [callback = std::move(callback)](BatchResult<NodeResult> result) mutable
        {
          if (result.items.size() > 1)
          {
            result.items.erase(result.items.begin() + 1, result.items.end());
          }
          callback(std::move(result));
        });
      return;
    case Answer::Twice:
      mInner->find_nodes_async(request,
        nodeIds,
        maxAge,
        [callback = std::move(callback), count = nodeIds.size()](BatchResult<NodeResult> result) mutable
        {
          auto first = callback;
          first(std::move(result));
          BatchResult<NodeResult> second;
          for (std::size_t i = 0; i < count; ++i)
          {
            second.items.push_back(NodeResult{StatusCode{Status::BadNodeIdUnknown}});
          }
          callback(std::move(second));
        });
      return;
    case Answer::SingleNodeForm:
      callback(BatchResult<NodeResult>{});  // Good batch status, no items
      return;
    case Answer::LookUpFirst:
    {
      const std::vector<NodeId> target{*lookupTarget};
      auto inner = std::make_shared<std::promise<BatchResult<NodeAccessorResult>>>();
      auto future = inner->get_future();
      addressSpace->find_nodes_async(
        target, [inner](BatchResult<NodeAccessorResult> result) { inner->set_value(std::move(result)); });
      if (future.wait_for(5s) == std::future_status::ready)
      {
        const std::lock_guard lock(mMutex);
        mInnerAnswer = future.get();
      }
      mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
      return;
    }
    }
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  // With holdReadsAndCalls set, holds each value read's and Method call's completion; otherwise answers as a
  // namespace that implements neither.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    if (!holdReadsAndCalls.load())
    {
      mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
      return;
    }
    const std::lock_guard lock(mMutex);
    mHeldReads.push_back(std::move(complete));
  }

  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    if (!holdReadsAndCalls.load())
    {
      Namespace::call_async(request, caller, items, std::move(complete));
      return;
    }
    const std::lock_guard lock(mMutex);
    mHeldMethodCalls.push_back(std::move(complete));
  }

  /// How many value reads and Method calls this namespace holds unanswered.
  std::size_t held_reads_and_calls() const
  {
    const std::lock_guard lock(mMutex);
    return mHeldReads.size() + mHeldMethodCalls.size();
  }

  bool wait_for_held(std::chrono::milliseconds bound)
  {
    std::unique_lock lock(mMutex);
    return mChanged.wait_for(lock, bound, [this] { return !mHeld.empty(); });
  }

  bool has_held_call() const
  {
    const std::lock_guard lock(mMutex);
    return !mHeld.empty();
  }

  /// Answers every held call as the default namespace answers it, outside the lock.
  void release_all()
  {
    std::vector<HeldCall> held;
    {
      const std::lock_guard lock(mMutex);
      held.swap(mHeld);
    }
    for (auto& call : held)
    {
      mInner->find_nodes_async(RequestInfo{}, call.nodeIds, std::nullopt, std::move(call.callback));
    }
  }

  std::optional<BatchResult<NodeAccessorResult>> inner_answer() const
  {
    const std::lock_guard lock(mMutex);
    return mInnerAnswer;
  }

  std::atomic<Answer> answer{Answer::AsAnswered};
  std::atomic<bool> holdReadsAndCalls{false};
  AddressSpace* addressSpace{nullptr};
  std::optional<NodeId> lookupTarget;

  /// SingleNodeForm: find_node throws for `throws`, answers `answersAnother` with the Node of `answered`,
  /// answers `answered` with its own Node, and declines every other NodeId.
  struct
  {
    NodeId throws;
    NodeId answersAnother;
    NodeId answered;
  } singleNode;

  /// GuardedCalls: create_nodes_async throws for `throwsOnCreate` and completes `completesTwice` twice (Good,
  /// then Bad_NodeIdExists); enumerate_nodes throws.
  struct
  {
    NodeId throwsOnCreate;
    NodeId completesTwice;
  } guarded;

private:
  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }

  struct HeldCall
  {
    std::vector<NodeId> nodeIds;
    std::function<void(BatchResult<NodeResult>)> callback;
  };

  std::shared_ptr<default_ns::Namespace> mInner;
  mutable std::mutex mMutex;
  std::condition_variable mChanged;
  std::vector<HeldCall> mHeld;
  std::vector<std::function<void(BatchResult<DataValueResult>)>> mHeldReads;
  std::vector<std::function<void(BatchResult<std::optional<CallResult>>)>> mHeldMethodCalls;
  std::optional<BatchResult<NodeAccessorResult>> mInnerAnswer;
};

struct RegisteredNamespace
{
  std::shared_ptr<RouteTestNamespace> space;
  uint16_t index{0};
};

/// One lookup's completion: how often it ran, and what it answered first. Shared with the callback, so a
/// completion that arrives after the test has stopped waiting touches nothing that has gone.
struct Completion
{
  std::atomic<int> calls{0};
  std::promise<BatchResult<NodeAccessorResult>> first;
  std::future<BatchResult<NodeAccessorResult>> answered{first.get_future()};
};

AddressSpace::FindNodesCompleteCallback record(const std::shared_ptr<Completion>& completion)
{
  return [completion](BatchResult<NodeAccessorResult> result)
  {
    if (completion->calls.fetch_add(1) == 0)
    {
      completion->first.set_value(std::move(result));
    }
  };
}

struct RouteFixture
{
  RouteFixture()
  {
    addressSpace.emplace(AddressSpace::create("urn:test:namespace-route", pool.get_executor()));
  }

  ~RouteFixture()
  {
    stop();
  }

  /// Registers a stub namespace that answers as asked; the test switches its answer afterwards.
  RegisteredNamespace add(const std::string& uri)
  {
    auto space =
      std::make_shared<RouteTestNamespace>(default_ns::Namespace::create(uri, pool.get_executor()));
    space->addressSpace = &*addressSpace;
    const auto index = addressSpace->add_namespace_sync(space);
    return RegisteredNamespace{std::move(space), index};
  }

  /// Creates an Object in the namespace through the address space; nullopt when the creation fails.
  std::optional<NodeId> node(const RegisteredNamespace& registered, uint32_t id)
  {
    const NodeId nodeId{registered.index, id};
    if (addressSpace->try_create_node_sync(nodeId, NodeClass::Object, {}).is_bad())
    {
      return std::nullopt;
    }
    return nodeId;
  }

  /// Ends the address space and runs every queued completion, so a later count is final.
  void stop()
  {
    if (addressSpace)
    {
      addressSpace.reset();
      ::ua::test_utils::drain_with_timeout(pool);
    }
  }

  boost::asio::thread_pool pool{2};
  std::optional<AddressSpace> addressSpace;
};

/// A completion of one call through the address space: how often it ran, and what it answered first.
template<typename T>
struct Counted
{
  std::atomic<int> calls{0};
  std::promise<T> first;
  std::future<T> answered{first.get_future()};
};

template<typename T>
std::function<void(T)> count_calls(const std::shared_ptr<Counted<T>>& counted)
{
  return [counted](T answer)
  {
    if (counted->calls.fetch_add(1) == 0)
    {
      counted->first.set_value(std::move(answer));
    }
  };
}

bool holds_node(const NodeAccessorResult& item, const NodeId& expected)
{
  return item.is_good() && item.value().get_node_id() == expected;
}

}  // namespace

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-01-EVERY-NAMESPACE-IS-CALLED-BEFORE-ANY-ANSWERS, scope=function)
TEST(NamespaceRoute, EveryNamespaceIsCalledBeforeAnyAnswers)
{
  RouteFixture fixture;
  const auto a = fixture.add("urn:test:route-order-a");
  const auto b = fixture.add("urn:test:route-order-b");
  const auto a1 = fixture.node(a, 1);
  const auto a2 = fixture.node(a, 2);
  const auto b1 = fixture.node(b, 1);
  const auto b2 = fixture.node(b, 2);
  ASSERT_TRUE(a1 && a2 && b1 && b2);
  a.space->answer = RouteTestNamespace::Answer::Hold;
  b.space->answer = RouteTestNamespace::Answer::Hold;

  const std::vector<NodeId> asked{*a1, *b1, *a2, *b2};
  auto completion = std::make_shared<Completion>();
  auto& answered = completion->answered;
  fixture.addressSpace->find_nodes_async(asked, record(completion));

  const bool aCalled = a.space->wait_for_held(5s);
  const bool bCalled = b.space->wait_for_held(5s);
  EXPECT_TRUE(aCalled) << "namespace A was not called before any namespace answered";
  EXPECT_TRUE(bCalled) << "namespace B was not called before any namespace answered";

  b.space->release_all();
  EXPECT_EQ(answered.wait_for(100ms), std::future_status::timeout)
    << "the lookup completed while namespace A still held its answer";
  EXPECT_EQ(completion->calls.load(), 0);
  a.space->release_all();
  if (!bCalled && b.space->wait_for_held(5s))
  {
    b.space->release_all();  // called only after A answered: release it so the lookup ends
  }

  ASSERT_EQ(answered.wait_for(5s), std::future_status::ready);
  const auto result = answered.get();
  fixture.stop();
  EXPECT_EQ(completion->calls.load(), 1);
  ASSERT_EQ(result.items.size(), asked.size());
  for (std::size_t i = 0; i < asked.size(); ++i)
  {
    EXPECT_TRUE(holds_node(result.items[i], asked[i])) << "item " << i << " is not the Node asked for there";
  }
}

// A namespace that throws inside its lookup member is run in a child process, because today the throw
// crosses the address space's noexcept lookup and ends the process. The child exits 0 only when the
// lookup answers as the criterion says; any other exit code names the first observation that failed.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-THROWING-NAMESPACE-FAILS-ONLY-ITS-ITEMS, scope=function)
TEST(NamespaceRoute, AThrowingNamespaceFailsOnlyItsItems)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto lookUpThroughAThrowingNamespace = []
  {
    RouteFixture fixture;
    const auto a = fixture.add("urn:test:route-throw-a");
    const auto b = fixture.add("urn:test:route-throw-b");
    const auto a1 = fixture.node(a, 1);
    const auto a2 = fixture.node(a, 2);
    const auto b1 = fixture.node(b, 1);
    if (!a1 || !a2 || !b1)
    {
      std::fprintf(stderr, "setup: a Node could not be created\n");
      std::_Exit(2);
    }
    a.space->answer = RouteTestNamespace::Answer::Throw;

    const std::vector<NodeId> asked{*a1, *b1, *a2};
    auto completion = std::make_shared<Completion>();
    auto& answered = completion->answered;
    fixture.addressSpace->find_nodes_async(asked, record(completion));
    if (answered.wait_for(5s) != std::future_status::ready)
    {
      std::fprintf(stderr, "the lookup did not complete\n");
      std::_Exit(3);
    }
    const auto result = answered.get();
    if (result.items.size() != asked.size())
    {
      std::fprintf(stderr, "the lookup answered %zu items, not 3\n", result.items.size());
      std::_Exit(4);
    }
    for (const std::size_t i : {std::size_t{0}, std::size_t{2}})
    {
      const auto& status = result.items[i].status_code();
      if (status.as_status() != Status::BadInternalError || status.shared_detail() == nullptr ||
          status.shared_detail()->code != "NamespaceCallThrew")
      {
        std::fprintf(
          stderr, "item %zu of the throwing namespace is not Bad_InternalError/NamespaceCallThrew\n", i);
        std::_Exit(5);
      }
    }
    if (!holds_node(result.items[1], *b1))
    {
      std::fprintf(stderr, "the other namespace's item is not its Node\n");
      std::_Exit(6);
    }
    fixture.stop();
    if (completion->calls.load() != 1)
    {
      std::fprintf(stderr, "the lookup completed %d times\n", completion->calls.load());
      std::_Exit(7);
    }
    std::_Exit(0);
  };
  EXPECT_EXIT(lookUpThroughAThrowingNamespace(), ::testing::ExitedWithCode(0), "");
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-SECOND-COMPLETION-IS-IGNORED, scope=function)
TEST(NamespaceRoute, ASecondCompletionIsIgnored)
{
  RouteFixture fixture;
  const auto a = fixture.add("urn:test:route-twice");
  const auto a1 = fixture.node(a, 1);
  const auto a2 = fixture.node(a, 2);
  ASSERT_TRUE(a1 && a2);
  a.space->answer = RouteTestNamespace::Answer::Twice;

  const std::vector<NodeId> asked{*a1, *a2};
  auto completion = std::make_shared<Completion>();
  auto& answered = completion->answered;
  fixture.addressSpace->find_nodes_async(asked, record(completion));

  ASSERT_EQ(answered.wait_for(5s), std::future_status::ready);
  const auto result = answered.get();
  fixture.stop();
  EXPECT_EQ(completion->calls.load(), 1);
  ASSERT_EQ(result.items.size(), asked.size());
  for (std::size_t i = 0; i < asked.size(); ++i)
  {
    EXPECT_EQ(result.items[i].status_code().as_status(), Status::Good) << "item " << i;
    EXPECT_TRUE(holds_node(result.items[i], asked[i])) << "item " << i << " is not the Node asked for there";
  }
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-SHORT-BATCH-FAILS-EVERY-ITEM-OF-ITS-CALL, scope=function)
TEST(NamespaceRoute, AShortBatchFailsEveryItemOfItsCall)
{
  RouteFixture fixture;
  const auto a = fixture.add("urn:test:route-short-a");
  const auto b = fixture.add("urn:test:route-short-b");
  const auto a1 = fixture.node(a, 1);
  const auto a2 = fixture.node(a, 2);
  const auto b1 = fixture.node(b, 1);
  ASSERT_TRUE(a1 && a2 && b1);
  a.space->answer = RouteTestNamespace::Answer::FirstItemOnly;

  const std::vector<NodeId> asked{*a1, *a2, *b1};
  auto completion = std::make_shared<Completion>();
  auto& answered = completion->answered;
  fixture.addressSpace->find_nodes_async(asked, record(completion));

  ASSERT_EQ(answered.wait_for(5s), std::future_status::ready);
  const auto result = answered.get();
  fixture.stop();
  EXPECT_EQ(completion->calls.load(), 1);
  ASSERT_EQ(result.items.size(), asked.size());
  for (const std::size_t i : {std::size_t{0}, std::size_t{1}})
  {
    const auto& status = result.items[i].status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError) << "item " << i << " of the short batch";
    ASSERT_NE(status.shared_detail(), nullptr) << "item " << i;
    EXPECT_EQ(status.shared_detail()->code, "NamespaceItemCountMismatch") << "item " << i;
  }
  EXPECT_TRUE(holds_node(result.items[2], *b1));
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-NAMESPACE-MAY-CALL-THE-ADDRESS-SPACE-FROM-ITS-MEMBER, scope=function)
TEST(NamespaceRoute, ANamespaceMayCallTheAddressSpaceFromItsMember)
{
  RouteFixture fixture;
  const auto a = fixture.add("urn:test:route-reenter-a");
  const auto b = fixture.add("urn:test:route-reenter-b");
  const auto a1 = fixture.node(a, 1);
  const auto b1 = fixture.node(b, 1);
  ASSERT_TRUE(a1 && b1);
  a.space->lookupTarget = *b1;
  a.space->answer = RouteTestNamespace::Answer::LookUpFirst;

  const std::vector<NodeId> asked{*a1};
  auto completion = std::make_shared<Completion>();
  auto& answered = completion->answered;
  fixture.addressSpace->find_nodes_async(asked, record(completion));

  ASSERT_EQ(answered.wait_for(10s), std::future_status::ready);
  const auto result = answered.get();
  const auto inner = a.space->inner_answer();
  ASSERT_TRUE(inner.has_value())
    << "the lookup from inside the namespace's member did not complete within 5 s";
  ASSERT_EQ(inner->items.size(), 1u);
  EXPECT_TRUE(holds_node(inner->items[0], *b1));
  fixture.stop();
  EXPECT_EQ(completion->calls.load(), 1);
  ASSERT_EQ(result.items.size(), 1u);
  EXPECT_TRUE(holds_node(result.items[0], *a1));
}

// The single-Node form is a call to the namespace like a batched one. Run in a child process, because today a
// throw from find_node crosses the address space's noexcept lookup and ends the process. The child exits 0
// only when every observation holds; any other exit code names the first observation that failed.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-THE-SINGLE-NODE-FORM-IS-GUARDED-LIKE-A-CALL, scope=function)
TEST(NamespaceRoute, TheSingleNodeFormIsGuardedLikeACall)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto lookUpThroughTheSingleNodeForm = []
  {
    const auto fail = [](int code, const char* what)
    {
      std::fprintf(stderr, "%s\n", what);
      std::_Exit(code);
    };
    const auto hasCode = [](const StatusCode& status, const char* code)
    {
      return status.as_status() == Status::BadInternalError && status.shared_detail() != nullptr &&
             status.shared_detail()->code == code;
    };
    RouteFixture fixture;
    const auto space = fixture.add("urn:test:route-single-node");
    const auto a = fixture.node(space, 1);
    const auto b = fixture.node(space, 2);
    const auto c = fixture.node(space, 3);
    const auto d = fixture.node(space, 4);
    if (!a || !b || !c || !d)
    {
      fail(2, "setup: a Node could not be created");
    }
    space.space->singleNode.throws = *a;
    space.space->singleNode.answersAnother = *b;
    space.space->singleNode.answered = *c;
    space.space->answer = RouteTestNamespace::Answer::SingleNodeForm;

    const std::vector<NodeId> asked{*a, *b, *c};
    auto completion = std::make_shared<Completion>();
    fixture.addressSpace->find_nodes_async(asked, record(completion));
    if (completion->answered.wait_for(5s) != std::future_status::ready)
    {
      fail(3, "the batched lookup did not complete");
    }
    const auto result = completion->answered.get();
    if (result.items.size() != asked.size())
    {
      fail(4, "the batched lookup did not answer three items");
    }
    if (!hasCode(result.items[0].status_code(), "NamespaceCallThrew"))
    {
      fail(5, "A is not Bad_InternalError/NamespaceCallThrew");
    }
    if (!holds_node(result.items[1], *c))
    {
      fail(6, "B is not Good with C's Node (the alias answer was not passed on)");
    }
    if (!holds_node(result.items[2], *c))
    {
      fail(7, "C is not its Node");
    }

    auto single = std::make_shared<std::promise<NodeAccessorResult>>();
    auto singleCalls = std::make_shared<std::atomic<int>>(0);
    auto singleAnswered = single->get_future();
    fixture.addressSpace->find_node_async(*d,
      [single, singleCalls](NodeAccessorResult item)
      {
        if (singleCalls->fetch_add(1) == 0)
        {
          single->set_value(std::move(item));
        }
      });
    if (singleAnswered.wait_for(5s) != std::future_status::ready)
    {
      fail(8, "the lookup of D did not complete");
    }
    if (!hasCode(singleAnswered.get().status_code(), "NamespaceItemCountMismatch"))
    {
      fail(9, "D is not Bad_InternalError/NamespaceItemCountMismatch");
    }
    fixture.stop();
    if (completion->calls.load() != 1 || singleCalls->load() != 1)
    {
      fail(10, "a lookup completed more than once");
    }
    std::_Exit(0);
  };
  EXPECT_EXIT(lookUpThroughTheSingleNodeForm(), ::testing::ExitedWithCode(0), "");
}

// Every call into a namespace passes the guards, not only the lookup. Run in a child process, because a throw
// from create_nodes_async or enumerate_nodes inside the address space's noexcept members would end the
// process. The child exits 0 only when every observation holds; any other exit code names the first one that
// failed.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-CREATE-AND-ENUMERATE-ARE-GUARDED-LIKE-A-CALL, scope=function)
TEST(NamespaceRoute, CreateAndEnumerateAreGuardedLikeACall)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto callThroughTheGuards = []
  {
    const auto fail = [](int code, const char* what)
    {
      std::fprintf(stderr, "%s\n", what);
      std::_Exit(code);
    };
    const auto threw = [](const StatusCode& status)
    {
      return status.as_status() == Status::BadInternalError && status.shared_detail() != nullptr &&
             status.shared_detail()->code == "NamespaceCallThrew";
    };
    RouteFixture fixture;
    const auto space = fixture.add("urn:test:route-guarded-calls");
    const NodeId a{space.index, uint32_t{1}};
    const NodeId b{space.index, uint32_t{2}};
    space.space->guarded.throwsOnCreate = a;
    space.space->guarded.completesTwice = b;
    space.space->answer = RouteTestNamespace::Answer::GuardedCalls;

    auto createA = std::make_shared<Counted<NodeAccessorResult>>();
    fixture.addressSpace->create_node_async(a, NodeClass::Object, count_calls(createA));
    if (createA->answered.wait_for(5s) != std::future_status::ready)
    {
      fail(2, "the creation of A did not complete");
    }
    if (!threw(createA->answered.get().status_code()))
    {
      fail(3, "the creation of A is not Bad_InternalError/NamespaceCallThrew");
    }

    auto createB = std::make_shared<Counted<NodeAccessorResult>>();
    fixture.addressSpace->create_node_async(b, NodeClass::Object, count_calls(createB));
    if (createB->answered.wait_for(5s) != std::future_status::ready)
    {
      fail(4, "the creation of B did not complete");
    }
    if (!holds_node(createB->answered.get(), b))
    {
      fail(5, "the creation of B is not Good with B's Node");
    }

    auto enumerated = std::make_shared<Counted<Result<std::vector<NodeId>>>>();
    fixture.addressSpace->enumerate_nodes_async(space.index, count_calls(enumerated));
    if (enumerated->answered.wait_for(5s) != std::future_status::ready)
    {
      fail(6, "the enumeration did not complete");
    }
    if (!threw(enumerated->answered.get().status_code()))
    {
      fail(7, "the enumeration is not Bad_InternalError/NamespaceCallThrew");
    }

    fixture.stop();
    if (createA->calls.load() != 1 || createB->calls.load() != 1 || enumerated->calls.load() != 1)
    {
      fail(8, "a completion ran more than once");
    }
    std::_Exit(0);
  };
  EXPECT_EXIT(callThroughTheGuards(), ::testing::ExitedWithCode(0), "");
}

// N's first call holds the lookup's completion; the second item is a second call, since maxNodesPerRead is 1.
// The address space runs on an executor the test runs, and every run is bounded, so a lookup that never
// completes and a namespace that is never released are observed as such rather than as a hang.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-04-A-HELD-COMPLETION-DOES-NOT-KEEP-ITS-NAMESPACE, scope=function)
TEST(NamespaceRouteLifetime, AHeldCompletionDoesNotKeepItsNamespace)
{
  auto completion = std::make_shared<Completion>();
  std::weak_ptr<RouteTestNamespace> released;
  boost::asio::io_context context;
  const auto runUntilNoWork = [&context]
  {
    context.restart();
    context.run_for(5s);
  };
  {
    std::optional<AddressSpace> addressSpace =
      AddressSpace::create("urn:test:namespace-route-lifetime", context.get_executor());
    ServiceOperationLimits limits;
    limits.maxNodesPerRead = 1;
    addressSpace->set_operation_limits(limits);

    auto space = std::make_shared<RouteTestNamespace>(
      default_ns::Namespace::create("urn:test:route-held-completion", context.get_executor()));
    std::optional<Result<uint16_t>> registered;
    addressSpace->add_namespace_async(
      space, [&registered](Result<uint16_t> result) { registered = std::move(result); });
    runUntilNoWork();
    ASSERT_TRUE(registered.has_value()) << "the registration did not complete";
    ASSERT_TRUE(registered->is_good());
    const uint16_t index = registered->value();

    space->answer = RouteTestNamespace::Answer::Hold;
    const std::vector<NodeId> asked{NodeId{index, 1U}, NodeId{index, 2U}};
    addressSpace->find_nodes_async(asked, record(completion));
    runUntilNoWork();
    ASSERT_TRUE(space->has_held_call()) << "N was not called";

    released = space;
    space.reset();
    addressSpace.reset();
    runUntilNoWork();
  }

  EXPECT_TRUE(released.expired()) << "N is kept alive by the lookup completion it holds";
  EXPECT_EQ(completion->calls.load(), 1);
  ASSERT_EQ(completion->answered.wait_for(0s), std::future_status::ready) << "the lookup did not complete";
  const auto result = completion->answered.get();
  ASSERT_EQ(result.items.size(), 2U);
  EXPECT_EQ(result.items[0].status_code(), Status::BadResourceUnavailable);
  EXPECT_EQ(result.items[1].status_code(), Status::BadShutdown);
}

// N answers lookups and creations; once its Nodes exist it holds every value read and Method call. (a) reads
// the Value of N's Variable through the accessor route as the services do (a ValueRead of the accessor the
// address space's lookup returned); (b) calls N's Method on N's Object through the Method's accessor. Every
// run is bounded, as in AHeldCompletionDoesNotKeepItsNamespace.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-04-A-HELD-READ-OR-CALL-DOES-NOT-KEEP-ITS-NAMESPACE, scope=function)
TEST(NamespaceRouteLifetime, AHeldReadOrCallDoesNotKeepItsNamespace)
{
  enum class Asked
  {
    ValueRead,
    MethodCall
  };
  // Each case runs in its own call, so that an assertion that ends one case does not skip the other.
  const auto exercise = [](Asked asked)
  {
    SCOPED_TRACE(asked == Asked::ValueRead ? "a value read" : "a Method call");
    auto read = std::make_shared<Counted<std::vector<DataValueResult>>>();
    auto called = std::make_shared<Counted<CallResult>>();
    std::weak_ptr<RouteTestNamespace> released;
    boost::asio::io_context context;
    const auto runUntilNoWork = [&context]
    {
      context.restart();
      context.run_for(5s);
    };
    {
      std::optional<AddressSpace> addressSpace =
        AddressSpace::create("urn:test:namespace-route-lifetime", context.get_executor());
      auto space = std::make_shared<RouteTestNamespace>(
        default_ns::Namespace::create("urn:test:route-held-read-or-call", context.get_executor()));
      std::optional<Result<uint16_t>> registered;
      addressSpace->add_namespace_async(
        space, [&registered](Result<uint16_t> result) { registered = std::move(result); });
      runUntilNoWork();
      ASSERT_TRUE(registered.has_value()) << "the registration did not complete";
      ASSERT_TRUE(registered->is_good());
      const uint16_t index = registered->value();
      const NodeId variableId{index, 1U};
      const NodeId objectId{index, 2U};
      const NodeId methodId{index, 3U};

      std::vector<NodeAccessorResult> created;
      const auto create = [&](const NodeId& nodeId, NodeClass nodeClass)
      {
        addressSpace->create_node_async(
          nodeId, nodeClass, [&created](NodeAccessorResult result) { created.push_back(std::move(result)); });
      };
      create(variableId, NodeClass::Variable);
      create(objectId, NodeClass::Object);
      create(methodId, NodeClass::Method);
      runUntilNoWork();
      ASSERT_EQ(created.size(), 3U) << "a creation did not complete";
      for (const auto& result : created)
      {
        ASSERT_TRUE(result.is_good());
      }

      const NodeId target = asked == Asked::ValueRead ? variableId : methodId;
      std::optional<BatchResult<NodeAccessorResult>> found;
      addressSpace->find_nodes_async(std::vector<NodeId>{target},
        [&found](BatchResult<NodeAccessorResult> result) { found = std::move(result); });
      runUntilNoWork();
      ASSERT_TRUE(found.has_value()) << "the lookup did not complete";
      ASSERT_EQ(found->items.size(), 1U);
      ASSERT_TRUE(found->items[0].is_good());
      const NodeAccessor accessor = found->items[0].value();

      space->holdReadsAndCalls = true;
      if (asked == Asked::ValueRead)
      {
        ReadValueId value;
        value.node_id() = variableId;
        value.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        std::vector<detail::ValueRead> reads;
        reads.push_back(detail::ValueRead{accessor, value});
        detail::NodeAccessorRoute::read_values(
          RequestInfo{}, nullptr, std::move(reads), Duration{0}, false, count_calls(read));
      }
      else
      {
        const auto method = accessor.as<MethodAccessor>();
        ASSERT_TRUE(method.has_value());
        CallMethodRequest request;
        request.object_id() = objectId;
        request.method_id() = methodId;
        method->call_async(request, nullptr, count_calls(called));
      }
      runUntilNoWork();
      ASSERT_EQ(space->held_reads_and_calls(), 1U) << "N was not asked";

      released = space;
      space.reset();
      addressSpace.reset();
      runUntilNoWork();
    }

    EXPECT_TRUE(released.expired()) << "N is kept alive by the completion it holds";
    if (asked == Asked::ValueRead)
    {
      EXPECT_EQ(read->calls.load(), 1);
      ASSERT_EQ(read->answered.wait_for(0s), std::future_status::ready) << "the value read did not complete";
      const auto answers = read->answered.get();
      ASSERT_EQ(answers.size(), 1U);
      EXPECT_EQ(answers[0].status_code(), Status::BadResourceUnavailable);
    }
    else
    {
      EXPECT_EQ(called->calls.load(), 1);
      ASSERT_EQ(called->answered.wait_for(0s), std::future_status::ready)
        << "the Method call did not complete";
      EXPECT_EQ(called->answered.get().status_code(), Status::BadResourceUnavailable);
    }
  };
  exercise(Asked::ValueRead);
  exercise(Asked::MethodCall);
}
