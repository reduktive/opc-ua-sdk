// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "fake_namespace.h"
#include "namespace_registration_coordinator_test_access.h"
#include "ua_callback_safety.h"
#include "ua_described_nodes.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_namespace_items.h"
#include "ua_node_description.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_sync_wait.h"
#include "ua_weak_address_space.h"

#include <boost/asio/post.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <latch>
#include <mutex>
#include <numeric>
#include <optional>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using namespace ua;
using namespace ua::detail;
using namespace ua::test_helpers;

namespace
{

template<typename Future>
auto get_ready(Future& future)
{
  EXPECT_EQ(future.wait_for(5s), std::future_status::ready);
  return future.get();
}

struct PreparationProbe
{
  std::atomic_size_t commits{0};
  std::atomic_size_t destructions{0};
  std::atomic_bool commitOnExecutor{false};
  boost::asio::any_io_executor executor;
};

class ProbePreparation final : public NamespaceRegistrationPreparation
{
public:
  explicit ProbePreparation(shared_ptr<PreparationProbe> probe) : mProbe(std::move(probe))
  {}

  ~ProbePreparation() override
  {
    ++mProbe->destructions;
  }

  void commit() noexcept override
  {
    ++mProbe->commits;
    if (mProbe->executor)
    {
      mProbe->commitOnExecutor.store(async::detail::on_executor_context(mProbe->executor));
    }
  }

private:
  shared_ptr<PreparationProbe> mProbe;
};

NamespaceRegistrationPreparationResult successful_preparation(const shared_ptr<PreparationProbe>& probe)
{
  return NamespaceRegistrationPreparationResult{std::make_shared<ProbePreparation>(probe)};
}

class DeferredParticipant final : public NamespaceRegistrationParticipant
{
public:
  struct Call
  {
    uint16_t namespaceIndex{0};
    String namespaceUri;
    NamespaceRegistrationPreparationCallback callback;
  };

  explicit DeferredParticipant(shared_ptr<PreparationProbe> probe = std::make_shared<PreparationProbe>())
    : mProbe(std::move(probe))
  {}

  void prepare_async(NamespaceRegistrationCandidate candidate,
    NamespaceRegistrationPreparationCallback callback) noexcept override
  {
    if (mCandidateObserver)
    {
      mCandidateObserver(candidate);
    }
    {
      const std::lock_guard lock(mMutex);
      mCalls.push_back(Call{candidate.namespaceIndex, candidate.namespaceUri, std::move(callback)});
    }
    mChanged.notify_all();
  }

  void observe_candidates(std::function<void(NamespaceRegistrationCandidate&)> observer)
  {
    mCandidateObserver = std::move(observer);
  }

  void wait_for_calls(std::size_t count)
  {
    std::unique_lock lock(mMutex);
    ASSERT_TRUE(mChanged.wait_for(lock, 5s, [&] { return mCalls.size() >= count; }));
  }

  std::size_t call_count() const
  {
    const std::lock_guard lock(mMutex);
    return mCalls.size();
  }

  Call call(std::size_t offset) const
  {
    const std::lock_guard lock(mMutex);
    return mCalls.at(offset);
  }

  void succeed(std::size_t offset, bool duplicate = false)
  {
    auto callback = call(offset).callback;
    callback(successful_preparation(mProbe));
    if (duplicate)
    {
      callback(successful_preparation(mProbe));
    }
  }

  void fail(std::size_t offset, StatusCode failure, bool duplicate = false)
  {
    auto callback = call(offset).callback;
    callback(NamespaceRegistrationPreparationResult{failure});
    if (duplicate)
    {
      callback(NamespaceRegistrationPreparationResult{failure});
    }
  }

  shared_ptr<PreparationProbe> probe() const
  {
    return mProbe;
  }

private:
  shared_ptr<PreparationProbe> mProbe;
  mutable std::mutex mMutex;
  std::condition_variable mChanged;
  std::vector<Call> mCalls;
  std::function<void(NamespaceRegistrationCandidate&)> mCandidateObserver;
};

class ImmediateParticipant final : public NamespaceRegistrationParticipant
{
public:
  explicit ImmediateParticipant(shared_ptr<PreparationProbe> probe = std::make_shared<PreparationProbe>())
    : mProbe(std::move(probe))
  {}

  void prepare_async(
    NamespaceRegistrationCandidate, NamespaceRegistrationPreparationCallback callback) noexcept override
  {
    ++calls;
    callback(successful_preparation(mProbe));
  }

  std::atomic_size_t calls{0};

private:
  shared_ptr<PreparationProbe> mProbe;
};

class DeferredShutdownNamespace final : public Namespace
{
public:
  explicit DeferredShutdownNamespace(String uri) : mUri(std::move(uri))
  {}

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    {
      const std::lock_guard lock(mMutex);
      ++mShutdownCalls;
      mShutdown = std::move(callback);
    }
    mChanged.notify_all();
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    resolve_each(nodeIds,
      std::move(complete),
      [](const NodeId&, std::function<void(NodeResult)> callback)
      { callback(NodeResult{StatusCode{Status::BadNodeIdUnknown}}); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  void wait_for_shutdown()
  {
    std::unique_lock lock(mMutex);
    ASSERT_TRUE(mChanged.wait_for(lock, 5s, [&] { return mShutdownCalls != 0; }));
  }

  void finish_shutdown(VoidResult result = {})
  {
    std::function<void(VoidResult)> callback;
    {
      const std::lock_guard lock(mMutex);
      callback = mShutdown;
    }
    callback(std::move(result));
  }

  std::size_t shutdown_calls() const
  {
    const std::lock_guard lock(mMutex);
    return mShutdownCalls;
  }

private:
  String mUri;
  mutable std::mutex mMutex;
  std::condition_variable mChanged;
  std::size_t mShutdownCalls{0};
  std::function<void(VoidResult)> mShutdown;
};

/// How many times one CountedNamespace was destroyed, held by the test outside the namespace so that it stays
/// readable after the namespace is gone.
struct DestructionProbe
{
  std::atomic_size_t destructions{0};
};

/// A namespace whose destructor counts into the test's probe; its shutdown_async answers Good at once.
class CountedNamespace final : public Namespace
{
public:
  CountedNamespace(String uri, DestructionProbe& probe) : mUri(std::move(uri)), mProbe(probe)
  {}

  ~CountedNamespace() override
  {
    ++mProbe.destructions;
  }

  CountedNamespace(const CountedNamespace&) = delete;
  CountedNamespace& operator=(const CountedNamespace&) = delete;
  CountedNamespace(CountedNamespace&&) = delete;
  CountedNamespace& operator=(CountedNamespace&&) = delete;

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    ++mLookupCalls;
    if (mDeferAfterFirst && mLookupCalls > 1U)
    {
      mDeferredLookup = std::move(complete);
      return;
    }
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      if (mAnswerLookups)
      {
        answer.items.emplace_back(
          mNodes.node_for(NodeDescription::object(nodeId, QualifiedName{nodeId.namespace_index(), "Node"})));
      }
      else
      {
        answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
      }
    }
    complete(std::move(answer));
  }

  void enable_lookups(bool deferAfterFirst = false)
  {
    mAnswerLookups = true;
    mDeferAfterFirst = deferAfterFirst;
  }

  std::function<void(BatchResult<NodeResult>)> deferred_lookup() const
  {
    return mDeferredLookup;
  }

  std::size_t lookup_calls() const
  {
    return mLookupCalls;
  }

  void set_reference_answer(References answer)
  {
    mReferenceAnswer = std::move(answer);
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    for (const auto& query : queries)
    {
      mReferenceNodes.push_back(query.nodeId);
      answer.items.emplace_back(NodeReferences{mReferenceAnswer, {}});
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  std::vector<NodeId> reference_nodes() const
  {
    return mReferenceNodes;
  }

private:
  String mUri;
  DestructionProbe& mProbe;
  DescribedNodes mNodes;
  bool mAnswerLookups{false};
  bool mDeferAfterFirst{false};
  std::size_t mLookupCalls{0};
  std::function<void(BatchResult<NodeResult>)> mDeferredLookup;
  References mReferenceAnswer;
  std::vector<NodeId> mReferenceNodes;
};

Result<uint16_t> add_async_and_wait(AddressSpace& addressSpace, shared_ptr<Namespace> nameSpace)
{
  std::promise<Result<uint16_t>> promise;
  auto future = promise.get_future();
  addressSpace.add_namespace_async(std::move(nameSpace),
    [&promise](Result<uint16_t> result) mutable { promise.set_value(std::move(result)); });
  return get_ready(future);
}

void expect_detail(const StatusCode& status, Status expected, string_view code)
{
  EXPECT_EQ(status, expected);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, code);
}

}  // namespace

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-01-PUBLIC-SURFACES, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, PublicVariantsShareSuccessAndExactErrorSurface)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-public", pool.get_executor());
    EXPECT_EQ(add_async_and_wait(addressSpace, FakeNamespace::create("urn:test:async")).value(), 2);
    EXPECT_EQ(addressSpace.try_add_namespace_sync(FakeNamespace::create("urn:test:try")).value(), 3);
    EXPECT_EQ(addressSpace.add_namespace_sync(FakeNamespace::create("urn:test:throw")), 4);

    const auto before = addressSpace.namespace_array().get_namespace_array();
    const auto asyncDuplicate = add_async_and_wait(addressSpace, FakeNamespace::create("urn:test:async"));
    expect_detail(asyncDuplicate.status_code(), Status::BadAlreadyExists, "DuplicateNamespaceRegistration");
    const auto tryDuplicate = addressSpace.try_add_namespace_sync(FakeNamespace::create("urn:test:try"));
    expect_detail(tryDuplicate.status_code(), Status::BadAlreadyExists, "DuplicateNamespaceRegistration");
    try
    {
      (void)addressSpace.add_namespace_sync(FakeNamespace::create("urn:test:throw"));
      FAIL() << "duplicate throwing wrapper returned";
    }
    catch (const UaException& exception)
    {
      expect_detail(exception.status_code(), Status::BadAlreadyExists, "DuplicateNamespaceRegistration");
    }
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), before);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-01-INPUT-CLASSES, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, InvalidCandidatesLeaveSnapshotAndNextIndexUnchanged)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-inputs", pool.get_executor());
    const auto before = addressSpace.namespace_array().get_namespace_array();

    const auto missing = add_async_and_wait(addressSpace, {});
    expect_detail(missing.status_code(), Status::BadInvalidArgument, "NamespaceMissing");
    const auto empty = add_async_and_wait(addressSpace, FakeNamespace::create(""));
    expect_detail(empty.status_code(), Status::BadInvalidArgument, "NamespaceUriEmpty");
    const auto duplicate =
      add_async_and_wait(addressSpace, FakeNamespace::create("urn:test:registration-inputs"));
    expect_detail(duplicate.status_code(), Status::BadAlreadyExists, "DuplicateNamespaceRegistration");

    NamespaceRegistrationCoordinatorTestAccess::set_maximum_namespaces(addressSpace, 2);
    const auto full = add_async_and_wait(addressSpace, FakeNamespace::create("urn:test:full"));
    expect_detail(full.status_code(), Status::BadInvalidState, "NamespaceTableFull");
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), before);

    NamespaceRegistrationCoordinatorTestAccess::set_maximum_namespaces(addressSpace, 3);
    EXPECT_EQ(addressSpace.add_namespace_sync(FakeNamespace::create("urn:test:valid-after-errors")), 2);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-01-PERMANENT-PREFIX, scope=function)
// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-CONCURRENT, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, SuccessfulAppendsAreDensePermanentAndConcurrent)
{
  boost::asio::thread_pool pool{4};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-concurrent", pool.get_executor());
    constexpr std::size_t count = 24;
    std::vector<shared_ptr<FakeNamespace>> namespaces;
    std::vector<shared_ptr<std::promise<Result<uint16_t>>>> promises;
    std::vector<std::future<Result<uint16_t>>> futures;
    namespaces.reserve(count);
    promises.reserve(count);
    futures.reserve(count);
    for (std::size_t offset = 0; offset < count; ++offset)
    {
      namespaces.push_back(FakeNamespace::create("urn:test:concurrent:" + std::to_string(offset)));
      promises.push_back(std::make_shared<std::promise<Result<uint16_t>>>());
      futures.push_back(promises.back()->get_future());
    }

    std::mutex snapshotsMutex;
    std::vector<Array<String>> snapshots;
    std::atomic_bool stopReader{false};
    std::latch firstSnapshotReady{1};
    std::jthread reader(
      [&]
      {
        while (!stopReader.load(std::memory_order_acquire))
        {
          auto snapshot = addressSpace.namespace_array().get_namespace_array();
          {
            const std::lock_guard lock(snapshotsMutex);
            snapshots.push_back(std::move(snapshot));
            if (snapshots.size() == 1)
            {
              firstSnapshotReady.count_down();
            }
          }
          std::this_thread::yield();
        }
      });
    firstSnapshotReady.wait();

    std::vector<std::jthread> callers;
    callers.reserve(count);
    for (std::size_t offset = 0; offset < count; ++offset)
    {
      callers.emplace_back(
        [addressSpace, nameSpace = namespaces[offset], promise = promises[offset]]() mutable
        {
          addressSpace.add_namespace_async(std::move(nameSpace),
            [promise](Result<uint16_t> result) mutable { promise->set_value(std::move(result)); });
        });
    }
    callers.clear();

    std::vector<uint16_t> indices;
    for (auto& future : futures)
    {
      auto result = get_ready(future);
      ASSERT_TRUE(result) << result.status_code().as_uint32();
      indices.push_back(result.value());
    }
    stopReader.store(true, std::memory_order_release);
    reader.join();
    std::ranges::sort(indices);
    for (std::size_t offset = 0; offset < count; ++offset)
    {
      EXPECT_EQ(indices[offset], offset + 2U);
    }
    const auto committed = addressSpace.namespace_array().get_namespace_array();
    ASSERT_EQ(committed.size(), count + 2U);
    {
      const std::lock_guard lock(snapshotsMutex);
      ASSERT_FALSE(snapshots.empty());
      for (const auto& snapshot : snapshots)
      {
        ASSERT_LE(snapshot.size(), committed.size());
        EXPECT_TRUE(std::equal(snapshot.begin(), snapshot.end(), committed.begin()));
      }
    }
    for (const auto& nameSpace : namespaces)
    {
      const auto index = addressSpace.namespace_array().get_namespace_index(nameSpace->uri());
      EXPECT_EQ(addressSpace.namespace_array().get_namespace(index), nameSpace);
    }
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-02-STATE-TRANSITIONS, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, CandidateIsInvisibleUntilItsSingleTerminalCommit)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-terminal", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);

    std::atomic_size_t failedCalls{0};
    std::promise<Result<uint16_t>> failedPromise;
    auto failedFuture = failedPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:pending-failure"),
      [&](Result<uint16_t> result)
      {
        ++failedCalls;
        failedPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    EXPECT_THROW(
      (void)addressSpace.namespace_array().get_namespace_index("urn:test:pending-failure"), UaException);
    participant->fail(0,
      StatusCode{
        Status::BadConfigurationError, make_error_detail("ParticipantRejected", "injected failure", "test")},
      true);
    EXPECT_TRUE(get_ready(failedFuture).is_bad());
    EXPECT_EQ(failedCalls, 1U);

    std::atomic_size_t successCalls{0};
    std::promise<Result<uint16_t>> successPromise;
    auto successFuture = successPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:pending-success"),
      [&](Result<uint16_t> result)
      {
        ++successCalls;
        successPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(2);
    EXPECT_THROW(
      (void)addressSpace.namespace_array().get_namespace_index("urn:test:pending-success"), UaException);
    participant->succeed(1, true);
    EXPECT_EQ(get_ready(successFuture).value(), 2);
    EXPECT_EQ(successCalls, 1U);
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_index("urn:test:pending-success"), 2);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-02-DEPENDENCY-FAILURE, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, ParticipantFailurePreservesDetailAndRollsBackPreparations)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-rollback", pool.get_executor());
    auto firstProbe = std::make_shared<PreparationProbe>();
    auto first = std::make_shared<ImmediateParticipant>(firstProbe);
    auto second = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, first);
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, second);

    std::promise<Result<uint16_t>> promise;
    auto future = promise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:participant-failure"),
      [&promise](Result<uint16_t> result) mutable { promise.set_value(std::move(result)); });
    second->wait_for_calls(1);
    const StatusCode injectedFailure{Status::BadSecurityChecksFailed,
      make_error_detail("InjectedParticipantFailure", "distinct participant failure", "test")};
    const auto detail = injectedFailure.shared_detail();
    std::thread foreign([second, injectedFailure] { second->fail(0, injectedFailure, true); });
    foreign.join();

    const auto result = get_ready(future);
    EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
    EXPECT_EQ(result.shared_detail(), detail);
    EXPECT_EQ(firstProbe->commits, 0U);
    EXPECT_EQ(firstProbe->destructions, 1U);
    EXPECT_THROW(
      (void)addressSpace.namespace_array().get_namespace_index("urn:test:participant-failure"), UaException);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-02-RESOURCE-ROLLBACK, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, FailureAndCapacityDoNotLeakOrConsumeACommittedSlot)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-capacity", pool.get_executor());
    auto firstProbe = std::make_shared<PreparationProbe>();
    auto first = std::make_shared<ImmediateParticipant>(firstProbe);
    auto second = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, first);
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, second);
    NamespaceRegistrationCoordinatorTestAccess::set_maximum_namespaces(addressSpace, 4);
    auto retriedCandidate = FakeNamespace::create("urn:test:capacity-failed:0");

    for (std::size_t attempt = 0; attempt < 2; ++attempt)
    {
      std::promise<Result<uint16_t>> failedPromise;
      auto failedFuture = failedPromise.get_future();
      auto candidate = attempt == 0 ? retriedCandidate : FakeNamespace::create("urn:test:capacity-failed:1");
      addressSpace.add_namespace_async(std::move(candidate),
        [&failedPromise](Result<uint16_t> result) mutable { failedPromise.set_value(std::move(result)); });
      second->wait_for_calls(attempt + 1U);
      second->fail(attempt, StatusCode{Status::BadConfigurationError});
      EXPECT_TRUE(get_ready(failedFuture).is_bad());
      EXPECT_EQ(firstProbe->destructions, attempt + 1U);
    }

    std::promise<Result<uint16_t>> successPromise;
    auto successFuture = successPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:capacity-success"),
      [&successPromise](Result<uint16_t> result) mutable { successPromise.set_value(std::move(result)); });
    second->wait_for_calls(3);
    second->succeed(2);
    EXPECT_EQ(get_ready(successFuture).value(), 2);

    // AC-COMP-ADDRSP-NAMESPACE-CONTEXT-02-A-FAILED-REGISTRATION-CLOSES-THE-CONTEXT: the failed candidate
    // keeps its closed context, so submitting it again is refused, and a new object takes the free slot.
    auto retryPromise = std::make_shared<std::promise<Result<uint16_t>>>();
    auto retryFuture = retryPromise->get_future();
    addressSpace.add_namespace_async(retriedCandidate,
      [retryPromise](Result<uint16_t> result) mutable { retryPromise->set_value(std::move(result)); });
    if (retryFuture.wait_for(5s) != std::future_status::ready && second->call_count() == 4U)
    {
      second->succeed(3);  // the retry reached a participant: answer it so the test ends rather than hangs
    }
    ASSERT_EQ(get_ready(retryFuture).status_code(), Status::BadInvalidState);

    auto replacement = FakeNamespace::create("urn:test:capacity-failed:0");
    std::promise<Result<uint16_t>> replacementPromise;
    auto replacementFuture = replacementPromise.get_future();
    addressSpace.add_namespace_async(replacement,
      [&replacementPromise](Result<uint16_t> result) mutable
      { replacementPromise.set_value(std::move(result)); });
    second->wait_for_calls(4);
    second->succeed(3);
    EXPECT_EQ(get_ready(replacementFuture).value(), 3);
    EXPECT_EQ(replacement->index(), 3);

    const auto overflow = add_async_and_wait(addressSpace, FakeNamespace::create("urn:test:overflow"));
    expect_detail(overflow.status_code(), Status::BadInvalidState, "NamespaceTableFull");
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_array().size(), 4U);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-CALLBACK-ONCE, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, CallbackCompletesExactlyOnceOnEveryTerminalPath)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-once", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);

    std::atomic_size_t validationCalls{0};
    std::promise<void> validationDone;
    addressSpace.add_namespace_async({},
      [&](Result<uint16_t>)
      {
        ++validationCalls;
        validationDone.set_value();
      });
    auto validationFuture = validationDone.get_future();
    get_ready(validationFuture);
    EXPECT_EQ(validationCalls, 1U);

    std::atomic_size_t participantCalls{0};
    std::promise<void> participantDone;
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:once-failure"),
      [&](Result<uint16_t>)
      {
        ++participantCalls;
        participantDone.set_value();
      });
    participant->wait_for_calls(1);
    participant->fail(0, StatusCode{Status::BadConfigurationError}, true);
    auto participantFuture = participantDone.get_future();
    get_ready(participantFuture);
    EXPECT_EQ(participantCalls, 1U);

    std::atomic_size_t successCalls{0};
    std::promise<Result<uint16_t>> successPromise;
    auto successFuture = successPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:once-success"),
      [&](Result<uint16_t> result)
      {
        ++successCalls;
        successPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(2);
    participant->succeed(1, true);
    EXPECT_TRUE(get_ready(successFuture));
    EXPECT_EQ(successCalls, 1U);

    std::promise<VoidResult> shutdownPromise;
    auto shutdownFuture = shutdownPromise.get_future();
    addressSpace.shutdown_async(
      [&shutdownPromise](VoidResult result) mutable { shutdownPromise.set_value(std::move(result)); });
    EXPECT_TRUE(get_ready(shutdownFuture));
    std::atomic_size_t refusedCalls{0};
    std::promise<Result<uint16_t>> refusedPromise;
    auto refusedFuture = refusedPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:after-stop"),
      [&](Result<uint16_t> result)
      {
        ++refusedCalls;
        refusedPromise.set_value(std::move(result));
      });
    const auto refused = get_ready(refusedFuture);
    EXPECT_EQ(refused.status_code(), Status::BadShutdown);
    EXPECT_EQ(refusedCalls, 1U);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-AFFINITY, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, ForeignCompletionReentersCoordinatorExecutor)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-affinity", pool.get_executor());
    auto probe = std::make_shared<PreparationProbe>();
    probe->executor = pool.get_executor();
    auto participant = std::make_shared<DeferredParticipant>(probe);
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);

    std::promise<bool> callbackPromise;
    auto callbackFuture = callbackPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:foreign-completion"),
      [executor = pool.get_executor(), &callbackPromise](Result<uint16_t> result) mutable
      { callbackPromise.set_value(result.is_good() && async::detail::on_executor_context(executor)); });
    participant->wait_for_calls(1);
    std::thread foreign([participant] { participant->succeed(0); });
    foreign.join();
    EXPECT_TRUE(get_ready(callbackFuture));
    EXPECT_TRUE(probe->commitOnExecutor);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-NONBLOCKING, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, AsyncRegistrationReturnsWhilePreparationIsParked)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-nonblocking", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    std::atomic_bool completed{false};
    std::promise<void> completionPromise;
    auto completionFuture = completionPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:parked"),
      [&](Result<uint16_t>)
      {
        completed = true;
        completionPromise.set_value();
      });
    participant->wait_for_calls(1);
    EXPECT_FALSE(completed);

    std::promise<void> unrelatedPromise;
    auto unrelatedFuture = unrelatedPromise.get_future();
    boost::asio::post(pool, [&unrelatedPromise] { unrelatedPromise.set_value(); });
    get_ready(unrelatedFuture);
    EXPECT_FALSE(completed);
    participant->succeed(0);
    get_ready(completionFuture);
    EXPECT_TRUE(completed);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-REENTRANT, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, CompletionCanReenterRegistrationSafely)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-reentrant", pool.get_executor());
    std::promise<std::pair<Result<uint16_t>, bool>> finalPromise;
    auto finalFuture = finalPromise.get_future();
    std::atomic_bool secondReturned{false};
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:reentrant:first"),
      [&](Result<uint16_t> first)
      {
        if (!first)
        {
          finalPromise.set_value({std::move(first), false});
          return;
        }
        addressSpace.add_namespace_async(FakeNamespace::create("urn:test:reentrant:second"),
          [&](Result<uint16_t> second)
          { finalPromise.set_value({std::move(second), secondReturned.load()}); });
        secondReturned = true;
      });
    auto [result, callbackWasDeferred] = get_ready(finalFuture);
    EXPECT_TRUE(callbackWasDeferred);
    EXPECT_EQ(result.value(), 3);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-03-FIFO, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, DeferredFrontRegistrationCannotBeOvertaken)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-fifo", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    std::mutex orderMutex;
    std::vector<std::string> order;
    std::vector<StatusCode> results;
    std::promise<void> done;
    auto doneFuture = done.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:fifo:a"),
      [&](Result<uint16_t> result)
      {
        const std::lock_guard lock(orderMutex);
        order.push_back("A");
        results.push_back(result.status_code());
      });
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:fifo:b"),
      [&](Result<uint16_t> result)
      {
        {
          const std::lock_guard lock(orderMutex);
          order.push_back("B");
          results.push_back(result.status_code());
        }
        done.set_value();
      });
    participant->wait_for_calls(1);
    EXPECT_EQ(participant->call_count(), 1U);
    participant->succeed(0);
    participant->wait_for_calls(2);
    participant->succeed(1);
    get_ready(doneFuture);
    EXPECT_EQ(order, (std::vector<std::string>{"A", "B"}));
    EXPECT_EQ(results, (std::vector<StatusCode>{Status::Good, Status::Good}));
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_index("urn:test:fifo:a"), 2);
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_index("urn:test:fifo:b"), 3);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-SHUTDOWN-RACE, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, ShutdownRaceCommitsBeforeOrFailsBeforeVisibility)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-shutdown", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    auto first = std::make_shared<DeferredShutdownNamespace>(String{"urn:test:before-shutdown"});

    std::promise<Result<uint16_t>> firstPromise;
    auto firstFuture = firstPromise.get_future();
    addressSpace.add_namespace_async(
      first, [&firstPromise](Result<uint16_t> result) mutable { firstPromise.set_value(std::move(result)); });
    participant->wait_for_calls(1);

    std::promise<VoidResult> shutdownPromise;
    auto shutdownFuture = shutdownPromise.get_future();
    addressSpace.shutdown_async(
      [&shutdownPromise](VoidResult result) mutable { shutdownPromise.set_value(std::move(result)); });
    std::promise<Result<uint16_t>> secondPromise;
    auto secondFuture = secondPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:after-shutdown"),
      [&secondPromise](Result<uint16_t> result) mutable { secondPromise.set_value(std::move(result)); });

    participant->succeed(0, true);
    EXPECT_EQ(get_ready(firstFuture).value(), 2);
    first->wait_for_shutdown();
    EXPECT_EQ(first->shutdown_calls(), 1U);
    first->finish_shutdown();
    EXPECT_TRUE(get_ready(shutdownFuture));
    const auto refused = get_ready(secondFuture);
    expect_detail(refused.status_code(), Status::BadShutdown, "NamespaceRegistrationShuttingDown");
    EXPECT_THROW(
      (void)addressSpace.namespace_array().get_namespace_index("urn:test:after-shutdown"), UaException);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-LATE-COMPLETION, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, LateParticipantCompletionAfterShutdownIsInert)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-late", pool.get_executor());
    auto participant = std::make_shared<DeferredParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    std::promise<Result<uint16_t>> addPromise;
    auto addFuture = addPromise.get_future();
    addressSpace.add_namespace_async(FakeNamespace::create("urn:test:late-completion"),
      [&addPromise](Result<uint16_t> result) mutable { addPromise.set_value(std::move(result)); });
    participant->wait_for_calls(1);
    const auto retained = participant->call(0).callback;
    participant->succeed(0);
    EXPECT_TRUE(get_ready(addFuture));

    std::promise<VoidResult> shutdownPromise;
    auto shutdownFuture = shutdownPromise.get_future();
    addressSpace.shutdown_async(
      [&shutdownPromise](VoidResult result) mutable { shutdownPromise.set_value(std::move(result)); });
    EXPECT_TRUE(get_ready(shutdownFuture));
    const auto commits = participant->probe()->commits.load();
    retained(successful_preparation(participant->probe()));
    std::promise<void> drained;
    auto drainedFuture = drained.get_future();
    boost::asio::post(pool, [&drained] { drained.set_value(); });
    get_ready(drainedFuture);
    EXPECT_EQ(participant->probe()->commits, commits);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-DESTRUCTION, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, DestroyDuringQueuedOrDeferredRegistrationIsSafe)
{
  boost::asio::io_context context;
  {
    std::promise<Result<uint16_t>> queuedPromise;
    auto queuedFuture = queuedPromise.get_future();
    {
      auto addressSpace =
        AddressSpace::create("urn:test:registration-destroy-queued", context.get_executor());
      addressSpace.add_namespace_async(FakeNamespace::create("urn:test:destroy-queued"),
        [&queuedPromise](Result<uint16_t> result) mutable { queuedPromise.set_value(std::move(result)); });
    }
    context.run();
    const auto queuedDestroyed = get_ready(queuedFuture);
    expect_detail(queuedDestroyed.status_code(), Status::BadShutdown, "NamespaceRegistrationOwnerGone");
  }

  boost::asio::thread_pool pool{1};
  {
    auto participant = std::make_shared<DeferredParticipant>();
    std::promise<Result<uint16_t>> promise;
    auto future = promise.get_future();
    {
      auto addressSpace = AddressSpace::create("urn:test:registration-destroy", pool.get_executor());
      NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
      addressSpace.add_namespace_async(FakeNamespace::create("urn:test:destroy-pending"),
        [&promise](Result<uint16_t> result) mutable { promise.set_value(std::move(result)); });
      participant->wait_for_calls(1);
    }
    const auto destroyed = get_ready(future);
    expect_detail(destroyed.status_code(), Status::BadShutdown, "NamespaceRegistrationOwnerGone");
    participant->succeed(0, true);
  }
  pool.join();
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-STAGED-HANDLES-DO-NOT-RETAIN-CANDIDATE, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, StagedHandlesDoNotRetainCandidate)
{
  for (const bool commitOriginal : {false, true})
  {
    SCOPED_TRACE(commitOriginal);
    boost::asio::io_context context;
    DestructionProbe destruction;
    auto participant = std::make_shared<DeferredParticipant>();
    auto stagedObserver = std::make_shared<WeakAddressSpace>();
    auto lookupAnswers = std::make_shared<std::vector<NodeAccessorResult>>();
    auto lateLookupAnswers = std::make_shared<std::vector<NodeAccessorResult>>();
    auto registrations = std::make_shared<std::vector<Result<uint16_t>>>();
    std::optional<AddressSpace> addressSpace =
      AddressSpace::create("urn:test:staged-handle-owner", context.get_executor());
    const WeakAddressSpace ownerObserver{*addressSpace};
    auto candidate =
      std::make_shared<CountedNamespace>(String{"urn:test:staged-handle-candidate"}, destruction);
    const weak_ptr<CountedNamespace> candidateObserver{candidate};
    candidate->enable_lookups(true);
    const Reference originalReference{NodeId{0, 35}, ExpandedNodeId{NodeId{2, 77}}, true};
    candidate->set_reference_answer(References{std::vector<Reference>{originalReference}});

    participant->observe_candidates(
      [stagedObserver, lookupAnswers, lateLookupAnswers](NamespaceRegistrationCandidate& prepared)
      {
        *stagedObserver = WeakAddressSpace{prepared.stagedAddressSpace};
        const NodeId nodeId{prepared.namespaceIndex, 100};
        prepared.stagedAddressSpace.find_node_async(nodeId,
          [stagedObserver, lookupAnswers, lateLookupAnswers, nodeId](NodeAccessorResult result)
          {
            lookupAnswers->push_back(std::move(result));
            if (auto stagedAddressSpace = stagedObserver->lock())
            {
              stagedAddressSpace->find_node_async(nodeId,
                [lateLookupAnswers](NodeAccessorResult lateResult)
                { lateLookupAnswers->push_back(std::move(lateResult)); });
            }
          });
      });
    NamespaceRegistrationCoordinatorTestAccess::install_participant(*addressSpace, participant);
    addressSpace->add_namespace_async(
      candidate, [registrations](Result<uint16_t> result) { registrations->push_back(std::move(result)); });
    context.run();

    ASSERT_EQ(participant->call_count(), 1U);
    ASSERT_EQ(lookupAnswers->size(), 1U);
    ASSERT_TRUE(lookupAnswers->front().is_good()) << describe(lookupAnswers->front().status_code());
    EXPECT_EQ(lookupAnswers->front().value().get_node_id(), (NodeId{2, 100}));
    EXPECT_EQ(candidate->lookup_calls(), 2U);
    EXPECT_TRUE(registrations->empty());
    EXPECT_TRUE(lateLookupAnswers->empty());
    EXPECT_TRUE(stagedObserver->lock().has_value());
    EXPECT_THROW((void)addressSpace->namespace_array().get_namespace_index(candidate->uri()), UaException);
    auto lateLookup = candidate->deferred_lookup();
    ASSERT_TRUE(lateLookup);
    const auto latePreparation = participant->call(0).callback;

    if (commitOriginal)
    {
      participant->succeed(0);
      context.restart();
      context.run();
      ASSERT_EQ(registrations->size(), 1U);
      ASSERT_TRUE(registrations->front().is_good());
      EXPECT_EQ(registrations->front().value(), 2);
      EXPECT_EQ(addressSpace->namespace_array().get_namespace(2), candidate);
      auto references = std::make_shared<std::vector<NodeAccessor::ReferencesResult>>();
      lookupAnswers->front().value().get_references_async(
        [references](NodeAccessor::ReferencesResult result) { references->push_back(std::move(result)); });
      context.restart();
      context.run();
      ASSERT_EQ(references->size(), 1U);
      ASSERT_TRUE(references->front().is_good());
      ASSERT_EQ(references->front().value().size(), 1U);
      EXPECT_EQ(references->front().value().span().front(), originalReference);
      EXPECT_EQ(candidate->reference_nodes(), (std::vector<NodeId>{NodeId{2, 100}}));
    }

    // Only non-owning staged handles, the accessor and copied completions survive these releases.
    addressSpace.reset();
    candidate.reset();
    context.restart();
    context.run();
    EXPECT_FALSE(ownerObserver.lock().has_value());
    EXPECT_FALSE(stagedObserver->lock().has_value());
    EXPECT_TRUE(candidateObserver.expired());
    EXPECT_EQ(destruction.destructions.load(), 1U);
    ASSERT_EQ(registrations->size(), 1U);
    if (!commitOriginal)
    {
      expect_detail(
        registrations->front().status_code(), Status::BadShutdown, "NamespaceRegistrationOwnerGone");
    }

    const StatusCode lateFailure{Status::BadNodeIdUnknown,
      make_error_detail("LateLookupFailure", "The delayed lookup has no Node", "test")};
    BatchResult<NodeResult> lateResult;
    lateResult.items.emplace_back(lateFailure);
    lateLookup(lateResult);
    lateLookup(std::move(lateResult));
    latePreparation(successful_preparation(participant->probe()));
    context.restart();
    context.run();
    ASSERT_EQ(lateLookupAnswers->size(), 1U);
    expect_detail(lateLookupAnswers->front().status_code(), Status::BadNodeIdUnknown, "LateLookupFailure");
    EXPECT_EQ(lateLookupAnswers->front().shared_detail(), lateFailure.shared_detail());
    EXPECT_EQ(registrations->size(), 1U);
    EXPECT_EQ(participant->probe()->commits.load(), std::size_t{commitOriginal});
    EXPECT_FALSE(ownerObserver.lock().has_value());
    EXPECT_FALSE(stagedObserver->lock().has_value());
    EXPECT_TRUE(candidateObserver.expired());
  }
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-EXPIRED-STAGED-ROUTE-DOES-NOT-REBIND, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, ExpiredStagedRouteDoesNotRebind)
{
  for (const bool commitOriginal : {false, true})
  {
    SCOPED_TRACE(commitOriginal);
    boost::asio::io_context context;
    DestructionProbe destruction;
    DestructionProbe replacementDestruction;
    auto addressSpace = AddressSpace::create("urn:test:staged-route-owner", context.get_executor());
    const auto before = addressSpace.namespace_array().get_namespace_array();
    auto participant = std::make_shared<DeferredParticipant>();
    auto stagedObserver = std::make_shared<WeakAddressSpace>();
    auto lookupAnswers = std::make_shared<std::vector<NodeAccessorResult>>();
    auto registrations = std::make_shared<std::vector<Result<uint16_t>>>();
    auto candidate =
      std::make_shared<CountedNamespace>(String{"urn:test:staged-route-original"}, destruction);
    const weak_ptr<CountedNamespace> candidateObserver{candidate};
    candidate->enable_lookups();
    const Reference originalReference{NodeId{0, 35}, ExpandedNodeId{NodeId{2, 77}}, true};
    candidate->set_reference_answer(References{std::vector<Reference>{originalReference}});
    participant->observe_candidates(
      [stagedObserver, lookupAnswers](NamespaceRegistrationCandidate& prepared)
      {
        *stagedObserver = WeakAddressSpace{prepared.stagedAddressSpace};
        prepared.stagedAddressSpace.find_node_async(NodeId{prepared.namespaceIndex, 100},
          [lookupAnswers](NodeAccessorResult result) { lookupAnswers->push_back(std::move(result)); });
      });
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    addressSpace.add_namespace_async(
      candidate, [registrations](Result<uint16_t> result) { registrations->push_back(std::move(result)); });
    context.run();
    ASSERT_EQ(participant->call_count(), 1U);
    ASSERT_EQ(lookupAnswers->size(), 1U);
    ASSERT_TRUE(lookupAnswers->front().is_good()) << describe(lookupAnswers->front().status_code());
    EXPECT_EQ(lookupAnswers->front().value().get_node_id(), (NodeId{2, 100}));
    EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), before);
    EXPECT_EQ(candidate->lookup_calls(), 1U);
    participant->observe_candidates({});

    const StatusCode refusal{Status::BadConfigurationError,
      make_error_detail("StagedCandidateRefused", "The participant refuses the candidate", "test")};
    if (commitOriginal)
    {
      participant->succeed(0, true);
    }
    else
    {
      participant->fail(0, refusal, true);
    }
    context.restart();
    context.run();
    ASSERT_EQ(registrations->size(), 1U);
    if (commitOriginal)
    {
      ASSERT_TRUE(registrations->front().is_good());
      EXPECT_EQ(registrations->front().value(), 2);
    }
    else
    {
      expect_detail(
        registrations->front().status_code(), Status::BadConfigurationError, "StagedCandidateRefused");
      EXPECT_EQ(registrations->front().shared_detail(), refusal.shared_detail());
      EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), before);
    }
    candidate.reset();
    context.restart();
    context.run();

    shared_ptr<CountedNamespace> replacement;
    if (!commitOriginal)
    {
      EXPECT_TRUE(candidateObserver.expired());
      EXPECT_EQ(destruction.destructions.load(), 1U);
      replacement = std::make_shared<CountedNamespace>(
        String{"urn:test:staged-route-replacement"}, replacementDestruction);
      replacement->enable_lookups();
      replacement->set_reference_answer(
        References{std::vector<Reference>{Reference{NodeId{0, 35}, ExpandedNodeId{NodeId{2, 88}}, true}}});
      addressSpace.add_namespace_async(replacement,
        [registrations](Result<uint16_t> result) { registrations->push_back(std::move(result)); });
      context.restart();
      context.run();
      ASSERT_EQ(participant->call_count(), 2U);
      EXPECT_EQ(participant->call(1).namespaceIndex, participant->call(0).namespaceIndex);
      participant->succeed(1, true);
      context.restart();
      context.run();
      ASSERT_EQ(registrations->size(), 2U);
      ASSERT_TRUE(registrations->back().is_good());
      EXPECT_EQ(registrations->back().value(), 2);
      EXPECT_EQ(addressSpace.namespace_array().get_namespace(2), replacement);
    }

    auto routedAnswers = std::make_shared<std::vector<NodeAccessor::ReferencesResult>>();
    lookupAnswers->front().value().get_references_async([routedAnswers](NodeAccessor::ReferencesResult result)
      { routedAnswers->push_back(std::move(result)); });
    context.restart();
    context.run();
    ASSERT_EQ(routedAnswers->size(), 1U);
    if (commitOriginal)
    {
      ASSERT_TRUE(routedAnswers->front().is_good());
      ASSERT_EQ(routedAnswers->front().value().size(), 1U);
      EXPECT_EQ(routedAnswers->front().value().span().front(), originalReference);
      const auto original = candidateObserver.lock();
      ASSERT_NE(original, nullptr);
      EXPECT_EQ(original->reference_nodes(), (std::vector<NodeId>{NodeId{2, 100}}));
      EXPECT_EQ(registrations->size(), 1U);
    }
    else
    {
      expect_detail(routedAnswers->front().status_code(), Status::BadNodeIdUnknown, "NamespaceNotFound");
      EXPECT_TRUE(candidateObserver.expired());
      EXPECT_TRUE(replacement->reference_nodes().empty());
      EXPECT_EQ(replacement->lookup_calls(), 0U);
      EXPECT_EQ(registrations->size(), 2U);
    }
    EXPECT_TRUE(stagedObserver->lock().has_value());
    EXPECT_EQ(lookupAnswers->size(), 1U);
    EXPECT_EQ(participant->probe()->commits.load(), 1U);
  }
}

// Both operations are posted before the executor runs, so the second is queued while the first is current:
// the participant answers each preparation at once, but each answer is a later strand turn than the one that
// queues the second operation. The first operation's completion releases the test's only handle, so the
// address space is gone before the queued operation starts in that same turn, and the queued operation must
// answer Bad_Shutdown with NamespaceRegistrationOwnerGone.
// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-04-WORK-QUEUED-BEHIND-THE-LAST-RELEASE, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, WorkQueuedBehindTheLastReleaseReadsNoDestroyedState)
{
  enum class Queued
  {
    Shutdown,
    Addition
  };
  for (const auto queued : {Queued::Shutdown, Queued::Addition})
  {
    SCOPED_TRACE(queued == Queued::Shutdown ? "a shutdown queued second" : "an addition queued second");
    DestructionProbe first;
    DestructionProbe second;
    DestructionProbe third;
    std::size_t releasingCompletions{0};
    bool aliveAfterRelease{true};
    std::vector<StatusCode> queuedAnswers;
    boost::asio::io_context context;
    {
      std::optional<AddressSpace> addressSpace =
        AddressSpace::create("urn:test:registration-queued-behind-release", context.get_executor());
      const WeakAddressSpace observer{*addressSpace};

      std::vector<Result<uint16_t>> registered;
      const auto record = [&registered](Result<uint16_t> result)
      {
        registered.push_back(std::move(result));
      };
      addressSpace->add_namespace_async(
        std::make_shared<CountedNamespace>(String{"urn:test:queued-behind-first"}, first), record);
      addressSpace->add_namespace_async(
        std::make_shared<CountedNamespace>(String{"urn:test:queued-behind-second"}, second), record);
      context.run();
      ASSERT_EQ(registered.size(), 2U);
      ASSERT_TRUE(registered[0].is_good());
      ASSERT_TRUE(registered[1].is_good());

      NamespaceRegistrationCoordinatorTestAccess::install_participant(
        *addressSpace, std::make_shared<ImmediateParticipant>());
      NamespaceRegistrationCoordinatorTestAccess::prepare_installed_namespaces_async(*addressSpace,
        [&](VoidResult)
        {
          ++releasingCompletions;
          addressSpace.reset();
          aliveAfterRelease = observer.lock().has_value();
        });
      if (queued == Queued::Shutdown)
      {
        addressSpace->shutdown_async(
          [&queuedAnswers](VoidResult result) { queuedAnswers.push_back(result.status_code()); });
      }
      else
      {
        addressSpace->add_namespace_async(
          std::make_shared<CountedNamespace>(String{"urn:test:queued-behind-third"}, third),
          [&queuedAnswers](Result<uint16_t> result) { queuedAnswers.push_back(result.status_code()); });
      }
      context.restart();
      context.run();

      EXPECT_EQ(releasingCompletions, 1U);
      ASSERT_FALSE(aliveAfterRelease)
        << "the test's handle was meant to be the last reference to the address space, released by the first "
           "operation's completion";
      ASSERT_EQ(queuedAnswers.size(), 1U);
      expect_detail(queuedAnswers[0], Status::BadShutdown, "NamespaceRegistrationOwnerGone");
      EXPECT_EQ(first.destructions.load(), 1U);
      EXPECT_EQ(second.destructions.load(), 1U);
      EXPECT_FALSE(addressSpace.has_value()) << "the first operation's completion did not release the handle";
      EXPECT_FALSE(observer.lock().has_value())
        << "something other than the test's handle kept the address space alive";
    }
  }
}

// @relation(AC-COMP-AS-NAMESPACE-REGISTRATION-05-OWN-EXECUTOR, scope=function)
TEST(NamespaceRegistrationCoordinatorTest, SyncWrappersRefuseOwnExecutorBeforeLaunchAndRetry)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:registration-would-block", pool.get_executor());
    auto participant = std::make_shared<ImmediateParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    auto tryCandidate = FakeNamespace::create("urn:test:would-block:try");
    auto throwCandidate = FakeNamespace::create("urn:test:would-block:throw");

    std::promise<Result<uint16_t>> tryPromise;
    auto tryFuture = tryPromise.get_future();
    boost::asio::post(pool,
      [addressSpace, tryCandidate, &tryPromise]() mutable
      { tryPromise.set_value(addressSpace.try_add_namespace_sync(tryCandidate)); });
    const auto tryResult = get_ready(tryFuture);
    EXPECT_EQ(tryResult.status_code(), Status::BadWouldBlock);
    EXPECT_NE(tryResult.shared_detail(), nullptr);

    std::promise<StatusCode> throwPromise;
    auto throwFuture = throwPromise.get_future();
    boost::asio::post(pool,
      [addressSpace, throwCandidate, &throwPromise]() mutable
      {
        try
        {
          (void)addressSpace.add_namespace_sync(throwCandidate);
          throwPromise.set_value(StatusCode{Status::Good});
        }
        catch (const UaException& exception)
        {
          throwPromise.set_value(exception.status_code());
        }
      });
    const auto throwResult = get_ready(throwFuture);
    EXPECT_EQ(throwResult, Status::BadWouldBlock);
    EXPECT_NE(throwResult.shared_detail(), nullptr);
    EXPECT_EQ(participant->calls, 0U);

    EXPECT_EQ(addressSpace.add_namespace_sync(tryCandidate), 2);
    EXPECT_EQ(addressSpace.add_namespace_sync(throwCandidate), 3);
    EXPECT_EQ(participant->calls, 2U);
  }
  pool.join();
}
