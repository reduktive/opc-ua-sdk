// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The address space's public members pass on the code a namespace answers (COMP-SVR-STATUS-ROUTING-04,
// COMP-SVR-STATUS-ROUTING-05), and refuse an Uncertain answer they would act on (COMP-SVR-STATUS-ROUTING-02).
//
// The namespace is a default namespace whose answers a test qualifies: an answer it would give Good is given
// with a Good subcode or an Uncertain code, keeping or dropping its value. Method bindings run against a
// scripted namespace whose Method answers the install of a call handler with the code a test sets.

#include <gtest/gtest.h>

#include "scripted_node.h"
#include "test_utilities.h"

#include "ua_add_method.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_node_utilities.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_quantity.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

constexpr std::string_view uncertainAnswerSummary{
  "The SDK does not act on an answer the namespace is uncertain of"};

/// How an answer the namespace would give Good is given instead: with @ref code, keeping the value when
/// @ref keepValue is true, or with the Uncertain @ref code alone.
struct Qualifier
{
  StatusCode code;
  bool keepValue{true};
};

/// How a Method call the namespace answers Good is answered instead: the Method's statusCode, and the code of
/// the call's answer when one is set.
struct CallQualifier
{
  StatusCode methodStatus;
  std::optional<StatusCode> callCode;
};

/// The answers a @ref QualifyingNamespace changes, shared with the completions it wraps.
struct Qualifications
{
  std::mutex mutex;
  std::map<NodeId, Qualifier> lookups;
  std::map<NodeId, Qualifier> references;
  std::map<NodeId, Qualifier> creates;
  std::map<NodeClass, Qualifier> createsOfClass;
  std::map<NodeId, StatusCode> referenceChanges;
  std::map<NodeId, DataValueResult> reads;
  std::optional<StatusCode> deletes;
  std::optional<CallQualifier> calls;

  /// @p answer as the qualifier @p table holds for @p id gives it; unchanged when there is none or the
  /// answer is not Good.
  template<typename Key, typename T>
  Result<T> apply(const std::map<Key, Qualifier>& table, const Key& id, Result<T> answer)
  {
    std::optional<Qualifier> qualifier;
    {
      const std::lock_guard lock{mutex};
      if (const auto found = table.find(id); found != table.end())
      {
        qualifier = found->second;
      }
    }
    if (!qualifier || !answer.is_good())
    {
      return answer;
    }
    if (qualifier->keepValue)
    {
      return Result<T>{std::move(answer).value(), qualifier->code};
    }
    return Result<T>{qualifier->code};
  }

  std::optional<StatusCode> change_code(const NodeId& source)
  {
    const std::lock_guard lock{mutex};
    if (const auto found = referenceChanges.find(source); found != referenceChanges.end())
    {
      return found->second;
    }
    return std::nullopt;
  }

  std::optional<DataValueResult> read(const NodeId& id)
  {
    const std::lock_guard lock{mutex};
    if (const auto found = reads.find(id); found != reads.end())
    {
      return found->second;
    }
    return std::nullopt;
  }

  std::optional<StatusCode> delete_code()
  {
    const std::lock_guard lock{mutex};
    return deletes;
  }

  std::optional<CallQualifier> call_qualifier()
  {
    const std::lock_guard lock{mutex};
    return calls;
  }
};

/// A default namespace whose Good answers a test qualifies (see @ref Qualifications).
class QualifyingNamespace final : public default_ns::Namespace
{
public:
  QualifyingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  using default_ns::Namespace::find_node;

  /// Answers every later lookup of @p nodeId that would be Good as @p qualifier says.
  void qualify_lookup(const NodeId& nodeId, Qualifier qualifier)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->lookups.insert_or_assign(nodeId, std::move(qualifier));
  }

  /// Answers every later References read of @p nodeId that would be Good as @p qualifier says.
  void qualify_references(const NodeId& nodeId, Qualifier qualifier)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->references.insert_or_assign(nodeId, std::move(qualifier));
  }

  /// Answers the creation of @p nodeId, when it succeeds, as @p qualifier says.
  void qualify_create(const NodeId& nodeId, Qualifier qualifier)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->creates.insert_or_assign(nodeId, std::move(qualifier));
  }

  /// Answers every later creation of a Node of @p nodeClass that succeeds, and whose NodeId has no qualifier
  /// of its own, as @p qualifier says: for a Node whose NodeId the test cannot know in advance.
  void qualify_creates_of(NodeClass nodeClass, Qualifier qualifier)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->createsOfClass.insert_or_assign(nodeClass, std::move(qualifier));
  }

  /// Answers every later add or removal of a Reference half held by @p source that succeeds with @p code.
  void qualify_reference_changes(const NodeId& source, StatusCode code)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->referenceChanges.insert_or_assign(source, std::move(code));
  }

  /// Answers every later Value read of @p nodeId with @p answer.
  void answer_reads(const NodeId& nodeId, DataValueResult answer)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->reads.insert_or_assign(nodeId, std::move(answer));
  }

  /// Answers every later delete that succeeds with @p code.
  void qualify_deletes(StatusCode code)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->deletes = std::move(code);
  }

  /// Answers every later Method call that succeeds as @p qualifier says.
  void qualify_calls(CallQualifier qualifier)
  {
    const std::lock_guard lock{mQualifications->mutex};
    mQualifications->calls = std::move(qualifier);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    default_ns::Namespace::find_nodes_async(request,
      nodeIds,
      maxAge,
      [qualifications = mQualifications,
        ids = std::vector<NodeId>(nodeIds.begin(), nodeIds.end()),
        complete = std::move(complete)](BatchResult<NodeResult> found) mutable
      {
        for (std::size_t i = 0; i < found.items.size() && i < ids.size(); ++i)
        {
          found.items[i] = qualifications->apply(qualifications->lookups, ids[i], std::move(found.items[i]));
        }
        complete(std::move(found));
      });
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    auto found = default_ns::Namespace::find_node(nodeId, maxAge);
    if (found)
    {
      found = mQualifications->apply(mQualifications->lookups, nodeId, std::move(*found));
    }
    return found;
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    std::vector<NodeId> ids;
    ids.reserve(queries.size());
    for (const auto& query : queries)
    {
      ids.push_back(query.nodeId);
    }
    default_ns::Namespace::read_references_async(request,
      queries,
      [qualifications = mQualifications, ids = std::move(ids), complete = std::move(complete)](
        BatchResult<NodeReferencesResult> read) mutable
      {
        for (std::size_t i = 0; i < read.items.size() && i < ids.size(); ++i)
        {
          read.items[i] = qualifications->apply(qualifications->references, ids[i], std::move(read.items[i]));
        }
        complete(std::move(read));
      });
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    std::vector<NodeId> ids;
    ids.reserve(items.size());
    for (const auto& item : items)
    {
      ids.push_back(item.value.node_id());
    }
    default_ns::Namespace::read_values_async(request,
      caller,
      items,
      maxAge,
      setSourceTimestamp,
      [qualifications = mQualifications, ids = std::move(ids), complete = std::move(complete)](
        BatchResult<DataValueResult> read) mutable
      {
        for (std::size_t i = 0; i < read.items.size() && i < ids.size(); ++i)
        {
          if (auto answer = qualifications->read(ids[i]))
          {
            read.items[i] = std::move(*answer);
          }
        }
        complete(std::move(read));
      });
  }

  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    default_ns::Namespace::call_async(request,
      caller,
      items,
      [qualifications = mQualifications, complete = std::move(complete)](
        BatchResult<std::optional<CallResult>> called) mutable
      {
        if (const auto qualifier = qualifications->call_qualifier())
        {
          for (auto& item : called.items)
          {
            if (!item || !item->is_good())
            {
              continue;
            }
            CallMethodResult wire = std::move(*item).value();
            wire.status_code() = qualifier->methodStatus;
            item = qualifier->callCode ? CallResult{std::move(wire), *qualifier->callCode}
                                       : CallResult{std::move(wire)};
          }
        }
        complete(std::move(called));
      });
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    std::vector<NodeId> ids;
    std::vector<NodeClass> classes;
    ids.reserve(nodes.size());
    classes.reserve(nodes.size());
    for (const auto& node : nodes)
    {
      ids.push_back(node.nodeId);
      classes.push_back(node.nodeClass);
    }
    default_ns::Namespace::create_nodes_async(request,
      nodes,
      [qualifications = mQualifications,
        ids = std::move(ids),
        classes = std::move(classes),
        complete = std::move(complete)](BatchResult<NodeResult> created) mutable
      {
        for (std::size_t i = 0; i < created.items.size() && i < ids.size(); ++i)
        {
          created.items[i] =
            qualifications->apply(qualifications->creates, ids[i], std::move(created.items[i]));
          created.items[i] =
            qualifications->apply(qualifications->createsOfClass, classes[i], std::move(created.items[i]));
        }
        complete(std::move(created));
      });
  }

  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    default_ns::Namespace::delete_nodes_async(request,
      nodes,
      halves,
      [qualifications = mQualifications, complete = std::move(complete)](
        BatchResult<DeleteNodeResult> deleted, std::vector<VersionedNode> versioned) mutable
      {
        if (const auto code = qualifications->delete_code())
        {
          for (auto& item : deleted.items)
          {
            if (item.is_good())
            {
              item = DeleteNodeResult{std::move(item).value(), *code};
            }
          }
        }
        complete(std::move(deleted), std::move(versioned));
      });
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    default_ns::Namespace::add_references_async(
      request, changes, qualified_changes(changes, std::move(complete)));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    default_ns::Namespace::remove_references_async(
      request, changes, qualified_changes(changes, std::move(complete)));
  }

private:
  /// @p complete, given each successful change of a source with a qualified code that code instead.
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> qualified_changes(
    std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) const
  {
    std::vector<NodeId> sources;
    sources.reserve(changes.size());
    for (const auto& change : changes)
    {
      sources.push_back(change.source);
    }
    return [qualifications = mQualifications, sources = std::move(sources), complete = std::move(complete)](
             BatchResult<VoidResult> changed, std::vector<VersionedNode> versioned) mutable
    {
      for (std::size_t i = 0; i < changed.items.size() && i < sources.size(); ++i)
      {
        if (!changed.items[i].is_good())
        {
          continue;
        }
        if (const auto code = qualifications->change_code(sources[i]))
        {
          changed.items[i] = VoidResult{*code};
        }
      }
      complete(std::move(changed), std::move(versioned));
    };
  }

  std::shared_ptr<Qualifications> mQualifications = std::make_shared<Qualifications>();
};

/// A scripted Method Node whose MethodCallSource answers the install of a call handler with the code a test
/// sets.
class InstallAnsweringMethod final : public ua::test::ScriptedNode, public MethodCallSource
{
public:
  /// Answers every later install with @p answer.
  void answer_installs(StatusCode answer)
  {
    const std::lock_guard lock{mInstallMutex};
    mAnswer = std::move(answer);
  }

  MethodCallSource* method_call_source() noexcept override
  {
    return this;
  }

  StatusCode set_call_handler(CallHandler handler) override
  {
    const std::lock_guard lock{mInstallMutex};
    mHandler = std::move(handler);
    return mAnswer;
  }

private:
  std::mutex mInstallMutex;
  StatusCode mAnswer{Status::Good};
  CallHandler mHandler;
};

/// Gives @p node the Attributes every reader of it needs.
void describe(
  ua::test::ScriptedNode& node, const NodeId& nodeId, NodeClass nodeClass, const QualifiedName& name)
{
  node.answer_attribute(AttributeId::NodeId, Variant{nodeId});
  node.answer_attribute(AttributeId::NodeClass, Variant{static_cast<int32_t>(nodeClass)});
  node.answer_attribute(AttributeId::BrowseName, Variant{name});
  node.answer_attribute(AttributeId::DisplayName, Variant{LocalizedText{name.name()}});
}

/// Runs @p start with a completion and answers what it completes with first; a completion that has not run
/// within 5 s fails the test.
template<typename R, typename Start>
R awaited(Start&& start, std::string_view what)
{
  auto promise = std::make_shared<std::promise<R>>();
  auto future = promise->get_future();
  auto calls = std::make_shared<std::atomic<int>>(0);
  std::forward<Start>(start)(std::function<void(R)>{[promise, calls](R result)
    {
      if (calls->fetch_add(1) == 0)
      {
        promise->set_value(std::move(result));
      }
    }});
  if (future.wait_for(5s) != std::future_status::ready)
  {
    ADD_FAILURE() << what << ": the completion did not run";
    return R{StatusCode{Status::BadTimeout}};
  }
  return future.get();
}

/// Whether @p status is the refusal of an Uncertain answer the SDK would act on: `Bad_InternalError` with the
/// ErrorDetail @p code, the refusal's summary, and the Uncertain @p cause.
::testing::AssertionResult is_refusal(const StatusCode& status, std::string_view code, Status cause)
{
  if (status.as_status() != Status::BadInternalError)
  {
    return ::testing::AssertionFailure() << "answered " << to_string(status);
  }
  const auto& detail = status.shared_detail();
  if (!detail)
  {
    return ::testing::AssertionFailure() << "Bad_InternalError without an ErrorDetail";
  }
  if (detail->code != code)
  {
    return ::testing::AssertionFailure() << "ErrorDetail " << detail->code << ", not " << code;
  }
  if (detail->summary != uncertainAnswerSummary)
  {
    return ::testing::AssertionFailure() << "summary \"" << detail->summary << "\"";
  }
  if (detail->innerStatus != StatusCode{cause}.value())
  {
    return ::testing::AssertionFailure() << "the cause is " << to_string(StatusCode{detail->innerStatus});
  }
  return ::testing::AssertionSuccess();
}

class StatusRoutingAddressSpace : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mPool.get_executor()));
    mNamespace = std::make_shared<QualifyingNamespace>("urn:test:status-routing", mPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mNsIndex = index.value();
  }

  void TearDown() override
  {
    mScripted.reset();
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeId id(uint32_t identifier) const
  {
    return NodeId{mNsIndex, identifier};
  }

  NodeAccessor object(uint32_t identifier)
  {
    return mAddressSpace->create_node_sync(id(identifier), NodeClass::Object);
  }

  /// Registers a scripted namespace beside the qualifying one and answers its index.
  uint16_t add_scripted_namespace()
  {
    mScripted = std::make_shared<ua::test::ScriptedNamespace>(String{"urn:test:status-routing-scripted"});
    auto index = mAddressSpace->try_add_namespace_sync(mScripted);
    EXPECT_TRUE(index.is_good()) << to_string(index.status_code());
    return index.is_good() ? index.value() : uint16_t{0};
  }

  boost::asio::thread_pool mPool{2};
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<QualifyingNamespace> mNamespace;
  std::shared_ptr<ua::test::ScriptedNamespace> mScripted;
  uint16_t mNsIndex{0};
};

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-LOOKUP-PASSES-THE-NAMESPACES-CODE, scope=function)
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-08-A-THROWING-FORM-GIVES-ONLY-A-GOOD-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, ALookupPassesAGoodSubcodeWithTheNode)
{
  object(1);
  mNamespace->qualify_lookup(id(1), Qualifier{StatusCode{Status::GoodLocalOverride}});

  const auto found = awaited<NodeAccessorResult>(
    [&](auto done) { mAddressSpace->find_node_async(id(1), std::move(done)); }, "find_node_async");
  EXPECT_EQ(found.status_code().as_status(), Status::GoodLocalOverride) << to_string(found.status_code());
  ASSERT_TRUE(found.is_good());
  EXPECT_EQ(found.value().get_node_id(), id(1));

  const auto foundSync = mAddressSpace->try_find_node_sync(id(1));
  EXPECT_EQ(foundSync.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(foundSync.status_code());
  ASSERT_TRUE(foundSync.is_good());
  EXPECT_EQ(foundSync.value().get_node_id(), id(1));

  const auto typed = mAddressSpace->try_find_sync<ObjectAccessor>(id(1));
  EXPECT_EQ(typed.status_code().as_status(), Status::GoodLocalOverride) << to_string(typed.status_code());
  ASSERT_TRUE(typed.is_good());
  EXPECT_EQ(typed.value().get_node_id(), id(1));

  const auto typedAsync = awaited<Result<ObjectAccessor>>(
    [&](auto done) { mAddressSpace->find_async<ObjectAccessor>(id(1), std::move(done)); }, "find_async");
  EXPECT_EQ(typedAsync.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(typedAsync.status_code());
  ASSERT_TRUE(typedAsync.is_good());
  EXPECT_EQ(typedAsync.value().get_node_id(), id(1));

  // The throwing form answers the Node: a Good subcode is Good.
  EXPECT_EQ(mAddressSpace->find_node_sync(id(1)).get_node_id(), id(1));
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-LOOKUP-PASSES-THE-NAMESPACES-CODE, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-08-A-THROWING-FORM-GIVES-ONLY-A-GOOD-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, ALookupPassesAnUncertainCodeWithTheNode)
{
  object(2);
  mNamespace->qualify_lookup(id(2), Qualifier{StatusCode{Status::UncertainLastUsableValue}});

  const auto found = awaited<NodeAccessorResult>(
    [&](auto done) { mAddressSpace->find_node_async(id(2), std::move(done)); }, "find_node_async");
  EXPECT_TRUE(found.is_uncertain());
  EXPECT_EQ(found.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(found.status_code());
  EXPECT_EQ(found.value().get_node_id(), id(2));

  const auto foundSync = mAddressSpace->try_find_node_sync(id(2));
  EXPECT_EQ(foundSync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(foundSync.status_code());
  EXPECT_EQ(foundSync.value().get_node_id(), id(2));

  const auto typed = mAddressSpace->try_find_sync<ObjectAccessor>(id(2));
  EXPECT_EQ(typed.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typed.status_code());
  EXPECT_EQ(typed.value().get_node_id(), id(2));

  const auto typedAsync = awaited<Result<ObjectAccessor>>(
    [&](auto done) { mAddressSpace->find_async<ObjectAccessor>(id(2), std::move(done)); }, "find_async");
  EXPECT_EQ(typedAsync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typedAsync.status_code());
  EXPECT_EQ(typedAsync.value().get_node_id(), id(2));

  EXPECT_THROW((void)mAddressSpace->find_node_sync(id(2)), UaException);
  EXPECT_THROW((void)mAddressSpace->find_sync<ObjectAccessor>(id(2)), UaException);

  mNamespace->qualify_lookup(id(2), Qualifier{StatusCode{Status::UncertainInitialValue}});
  const auto initial = awaited<NodeAccessorResult>(
    [&](auto done) { mAddressSpace->find_node_async(id(2), std::move(done)); }, "find_node_async");
  EXPECT_EQ(initial.status_code().as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(initial.has_value());
  EXPECT_EQ(initial.value().get_node_id(), id(2));

  const auto initialSync = mAddressSpace->try_find_node_sync(id(2));
  EXPECT_EQ(initialSync.status_code().as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(initialSync.has_value());
  EXPECT_EQ(initialSync.value().get_node_id(), id(2));

  const auto initialTyped = mAddressSpace->try_find_sync<ObjectAccessor>(id(2));
  EXPECT_EQ(initialTyped.status_code().as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(initialTyped.has_value());
  EXPECT_EQ(initialTyped.value().get_node_id(), id(2));

  const auto initialTypedAsync = awaited<Result<ObjectAccessor>>(
    [&](auto done) { mAddressSpace->find_async<ObjectAccessor>(id(2), std::move(done)); }, "find_async");
  EXPECT_EQ(initialTypedAsync.status_code().as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(initialTypedAsync.has_value());
  EXPECT_EQ(initialTypedAsync.value().get_node_id(), id(2));
  EXPECT_THROW((void)mAddressSpace->find_node_sync(id(2)), UaException);
  EXPECT_THROW((void)mAddressSpace->find_sync<ObjectAccessor>(id(2)), UaException);
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-LOOKUP-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, ACreationPassesTheNamespacesCode)
{
  mNamespace->qualify_create(id(3), Qualifier{StatusCode{Status::GoodLocalOverride}});
  const auto created = mAddressSpace->try_create_node_sync(id(3), NodeClass::Object);
  EXPECT_EQ(created.status_code().as_status(), Status::GoodLocalOverride) << to_string(created.status_code());
  ASSERT_TRUE(created.is_good());
  EXPECT_EQ(created.value().get_node_id(), id(3));

  mNamespace->qualify_create(id(4), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  const auto createdAsync = awaited<NodeAccessorResult>([&](auto done)
    { mAddressSpace->create_node_async(id(4), NodeClass::Object, std::move(done)); },
    "create_node_async");
  EXPECT_EQ(createdAsync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(createdAsync.status_code());
  EXPECT_EQ(createdAsync.value().get_node_id(), id(4));

  mNamespace->qualify_create(id(5), Qualifier{StatusCode{Status::GoodLocalOverride}});
  const auto typed = mAddressSpace->try_create_sync<ObjectAccessor>(id(5), NodeClass::Object);
  EXPECT_EQ(typed.status_code().as_status(), Status::GoodLocalOverride) << to_string(typed.status_code());
  ASSERT_TRUE(typed.is_good());
  EXPECT_EQ(typed.value().get_node_id(), id(5));

  mNamespace->qualify_create(id(6), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  const auto typedAsync = awaited<Result<ObjectAccessor>>([&](auto done)
    { mAddressSpace->create_async<ObjectAccessor>(id(6), NodeClass::Object, {}, std::move(done)); },
    "create_async");
  EXPECT_EQ(typedAsync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typedAsync.status_code());
  EXPECT_EQ(typedAsync.value().get_node_id(), id(6));

  uint32_t nextId = 7;
  for (const auto code : {Status::GoodLocalOverride, Status::UncertainInitialValue})
  {
    SCOPED_TRACE(to_string(StatusCode{code}));
    const auto synchronousId = id(nextId++);
    mNamespace->qualify_create(synchronousId, Qualifier{StatusCode{code}});
    const auto synchronous = mAddressSpace->try_create_node_sync(synchronousId, NodeClass::Object);
    EXPECT_EQ(synchronous.status_code().as_status(), code);
    ASSERT_TRUE(synchronous.has_value());
    EXPECT_EQ(synchronous.value().get_node_id(), synchronousId);

    const auto asynchronousId = id(nextId++);
    mNamespace->qualify_create(asynchronousId, Qualifier{StatusCode{code}});
    const auto asynchronous = awaited<NodeAccessorResult>([&](auto done)
      { mAddressSpace->create_node_async(asynchronousId, NodeClass::Object, std::move(done)); },
      "create_node_async");
    EXPECT_EQ(asynchronous.status_code().as_status(), code);
    ASSERT_TRUE(asynchronous.has_value());
    EXPECT_EQ(asynchronous.value().get_node_id(), asynchronousId);

    const auto synchronousTypedId = id(nextId++);
    mNamespace->qualify_create(synchronousTypedId, Qualifier{StatusCode{code}});
    const auto synchronousTyped =
      mAddressSpace->try_create_sync<ObjectAccessor>(synchronousTypedId, NodeClass::Object);
    EXPECT_EQ(synchronousTyped.status_code().as_status(), code);
    ASSERT_TRUE(synchronousTyped.has_value());
    EXPECT_EQ(synchronousTyped.value().get_node_id(), synchronousTypedId);

    const auto asynchronousTypedId = id(nextId++);
    mNamespace->qualify_create(asynchronousTypedId, Qualifier{StatusCode{code}});
    const auto asynchronousTyped = awaited<Result<ObjectAccessor>>(
      [&](auto done) {
        mAddressSpace->create_async<ObjectAccessor>(
          asynchronousTypedId, NodeClass::Object, {}, std::move(done));
      },
      "create_async");
    EXPECT_EQ(asynchronousTyped.status_code().as_status(), code);
    ASSERT_TRUE(asynchronousTyped.has_value());
    EXPECT_EQ(asynchronousTyped.value().get_node_id(), asynchronousTypedId);
  }
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-05-AN-UNCERTAIN-ANSWER-WITHOUT-A-VALUE-REACHES-THE-CALLER, scope=function)
TEST_F(StatusRoutingAddressSpace, AnUncertainLookupWithoutANodeReachesTheCaller)
{
  object(7);
  mNamespace->qualify_lookup(id(7), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});

  const auto found = awaited<NodeAccessorResult>(
    [&](auto done) { mAddressSpace->find_node_async(id(7), std::move(done)); }, "find_node_async");
  EXPECT_EQ(found.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(found.status_code());
  EXPECT_THROW((void)found.value(), UaException);

  const auto foundSync = mAddressSpace->try_find_node_sync(id(7));
  EXPECT_EQ(foundSync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(foundSync.status_code());
  EXPECT_THROW((void)foundSync.value(), UaException);

  const auto typed = mAddressSpace->try_find_sync<ObjectAccessor>(id(7));
  EXPECT_EQ(typed.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typed.status_code());

  const auto typedAsync = awaited<Result<ObjectAccessor>>(
    [&](auto done) { mAddressSpace->find_async<ObjectAccessor>(id(7), std::move(done)); }, "find_async");
  EXPECT_EQ(typedAsync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typedAsync.status_code());
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-REFERENCES-READ-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, AReferencesReadPassesTheNamespacesCode)
{
  auto parent = object(10);
  object(11);
  (void)mAddressSpace->create_node_sync(id(12), NodeClass::Variable);
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, id(11));
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id(12));
  ASSERT_TRUE(parent
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  NodeId{ObjectTypeId::BaseObjectType},
                  true,
                  ReferenceHalves::ThisHalfOnly)
                .is_good());

  mNamespace->qualify_references(id(10), Qualifier{StatusCode{Status::GoodLocalOverride}});

  const auto all = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_references_async(std::move(done)); }, "get_references_async");
  EXPECT_EQ(all.status_code().as_status(), Status::GoodLocalOverride) << to_string(all.status_code());
  ASSERT_TRUE(all.is_good());
  EXPECT_EQ(all.value().size(), 3U);

  const auto allSync = parent.try_get_references_sync();
  EXPECT_EQ(allSync.status_code().as_status(), Status::GoodLocalOverride) << to_string(allSync.status_code());

  const auto page = awaited<NodeAccessor::ReferencesPageResult>([&](auto done)
    { parent.get_references_async(0, ByteString{}, std::move(done)); },
    "paged get_references");
  EXPECT_EQ(page.status_code().as_status(), Status::GoodLocalOverride) << to_string(page.status_code());
  ASSERT_TRUE(page.is_good());
  EXPECT_EQ(page.value().references.size(), 3U);

  const auto components = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_components_async(std::move(done)); }, "get_components_async");
  EXPECT_EQ(components.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(components.status_code());
  ASSERT_TRUE(components.is_good());
  EXPECT_EQ(components.value().size(), 1U);
  EXPECT_EQ(parent.try_get_components_sync().status_code().as_status(), Status::GoodLocalOverride);

  const auto properties = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_properties_async(std::move(done)); }, "get_properties_async");
  EXPECT_EQ(properties.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(properties.status_code());
  ASSERT_TRUE(properties.is_good());
  EXPECT_EQ(properties.value().size(), 1U);
  EXPECT_EQ(parent.try_get_properties_sync().status_code().as_status(), Status::GoodLocalOverride);

  const auto typeDefinition = awaited<ExpandedNodeIdResult>([&](auto done)
    { node_utils::get_type_definition_async(parent, std::move(done)); },
    "get_type_definition_async");
  EXPECT_EQ(typeDefinition.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(typeDefinition.status_code());
  ASSERT_TRUE(typeDefinition.is_good());
  EXPECT_EQ(typeDefinition.value(), ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}});

  // The throwing form answers the References: a Good subcode is Good.
  EXPECT_EQ(parent.get_references_sync().size(), 3U);

  mNamespace->qualify_references(id(10), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  const auto uncertain = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_references_async(std::move(done)); }, "get_references_async");
  EXPECT_EQ(uncertain.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(uncertain.status_code());
  EXPECT_EQ(uncertain.value().size(), 3U);
  const auto uncertainComponents = parent.try_get_components_sync();
  EXPECT_EQ(uncertainComponents.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(uncertainComponents.status_code());
  EXPECT_EQ(uncertainComponents.value().size(), 1U);

  const auto uncertainComponentsAsync = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_components_async(std::move(done)); }, "get_components_async");
  EXPECT_EQ(uncertainComponentsAsync.status_code().as_status(), Status::UncertainLastUsableValue);
  ASSERT_TRUE(uncertainComponentsAsync.has_value());
  ASSERT_EQ(uncertainComponentsAsync.value().size(), 1U);
  EXPECT_EQ(uncertainComponentsAsync.value().begin()->target_id(), ExpandedNodeId{id(11)});

  const auto uncertainProperties = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_properties_async(std::move(done)); }, "get_properties_async");
  EXPECT_EQ(uncertainProperties.status_code().as_status(), Status::UncertainLastUsableValue);
  ASSERT_TRUE(uncertainProperties.has_value());
  ASSERT_EQ(uncertainProperties.value().size(), 1U);
  EXPECT_EQ(uncertainProperties.value().begin()->target_id(), ExpandedNodeId{id(12)});

  const auto uncertainTypeDefinition = awaited<ExpandedNodeIdResult>([&](auto done)
    { node_utils::get_type_definition_async(parent, std::move(done)); },
    "get_type_definition_async");
  EXPECT_EQ(uncertainTypeDefinition.status_code().as_status(), Status::UncertainLastUsableValue);
  ASSERT_TRUE(uncertainTypeDefinition.has_value());
  EXPECT_EQ(uncertainTypeDefinition.value(), ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}});
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-05-AN-UNCERTAIN-ANSWER-WITHOUT-A-VALUE-REACHES-THE-CALLER, scope=function)
TEST_F(StatusRoutingAddressSpace, AnUncertainReferencesReadWithoutReferencesReachesTheCaller)
{
  auto parent = object(20);
  mNamespace->qualify_references(id(20), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});

  const auto all = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_references_async(std::move(done)); }, "get_references_async");
  EXPECT_EQ(all.status_code().as_status(), Status::UncertainLastUsableValue) << to_string(all.status_code());
  EXPECT_THROW((void)all.value(), UaException);

  const auto page = awaited<NodeAccessor::ReferencesPageResult>([&](auto done)
    { parent.get_references_async(0, ByteString{}, std::move(done)); },
    "paged get_references");
  EXPECT_EQ(page.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(page.status_code());

  EXPECT_EQ(parent.try_get_references_sync().status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(parent.try_get_components_sync().status_code().as_status(), Status::UncertainLastUsableValue);

  const auto properties = awaited<NodeAccessor::ReferencesResult>(
    [&](auto done) { parent.get_properties_async(std::move(done)); }, "get_properties_async");
  EXPECT_EQ(properties.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(properties.status_code());

  const auto typeDefinition = awaited<ExpandedNodeIdResult>([&](auto done)
    { node_utils::get_type_definition_async(parent, std::move(done)); },
    "get_type_definition_async");
  EXPECT_EQ(typeDefinition.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(typeDefinition.status_code());
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-REFERENCE-CHANGE-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, AReferenceChangePassesTheNamespacesCode)
{
  auto source = object(30);
  object(31);
  object(32);
  object(33);
  object(34);
  mNamespace->qualify_reference_changes(id(30), StatusCode{Status::GoodLocalOverride});
  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  const auto added = source.try_add_reference_sync(hasComponent, id(31));
  EXPECT_EQ(added.status_code().as_status(), Status::GoodLocalOverride) << to_string(added.status_code());

  const auto addedAsync = awaited<VoidResult>(
    [&](auto done)
    {
      source.add_reference_async(NodeId{ReferenceTypeId::Organizes},
        ExpandedNodeId{id(32)},
        true,
        ReferenceHalves::Both,
        std::move(done));
    },
    "add_reference_async");
  EXPECT_EQ(addedAsync.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(addedAsync.status_code());

  const auto removed = source.try_remove_reference_sync(hasComponent, id(31));
  EXPECT_EQ(removed.status_code().as_status(), Status::GoodLocalOverride) << to_string(removed.status_code());

  const auto removedAsync = awaited<VoidResult>(
    [&](auto done)
    {
      source.remove_reference_async(NodeId{ReferenceTypeId::Organizes},
        ExpandedNodeId{id(32)},
        true,
        ReferenceHalves::Both,
        std::move(done));
    },
    "remove_reference_async");
  EXPECT_EQ(removedAsync.status_code().as_status(), Status::GoodLocalOverride);
  EXPECT_EQ(removedAsync.status_code().value(), removed.status_code().value());

  // An add of a Reference that is not present answers the add's code, in the sync and the async form alike.
  const auto addedIfAbsent = source.try_add_reference_if_not_present_sync(hasComponent, id(33));
  EXPECT_EQ(addedIfAbsent.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(addedIfAbsent.status_code());
  const auto addedIfAbsentAsync = awaited<VoidResult>(
    [&](auto done)
    {
      source.add_reference_if_not_present_async(
        hasComponent, id(34), true, ReferenceHalves::Both, std::move(done));
    },
    "add_reference_if_not_present_async");
  EXPECT_EQ(addedIfAbsentAsync.status_code().as_status(), Status::GoodLocalOverride)
    << to_string(addedIfAbsentAsync.status_code());

  // A Reference already present adds nothing: plain Good.
  const auto present = source.try_add_reference_if_not_present_sync(hasComponent, id(33));
  EXPECT_EQ(present.status_code().value(), StatusCode{Status::Good}.value())
    << to_string(present.status_code());

  // A Good subcode on the other half, which the address space adds, reaches the caller too.
  auto other = object(35);
  object(36);
  mNamespace->qualify_reference_changes(id(36), StatusCode{Status::GoodClamped});
  const auto paired = other.try_add_reference_sync(hasComponent, id(36));
  EXPECT_EQ(paired.status_code().as_status(), Status::GoodClamped) << to_string(paired.status_code());

  mNamespace->qualify_reference_changes(id(35), StatusCode{Status::GoodLocalOverride});
  const auto pairedRemoved = awaited<VoidResult>(
    [&](auto done)
    {
      other.remove_reference_async(
        hasComponent, ExpandedNodeId{id(36)}, true, ReferenceHalves::Both, std::move(done));
    },
    "remove_reference_async");
  EXPECT_EQ(pairedRemoved.status_code().as_status(), Status::GoodClamped);
  const auto pairedRestored = other.try_add_reference_sync(hasComponent, id(36));
  EXPECT_EQ(pairedRestored.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(pairedRemoved.status_code().value(), pairedRestored.status_code().value());

  // An Uncertain answer reaches the caller.
  auto uncertainSource = object(37);
  mNamespace->qualify_reference_changes(id(37), StatusCode{Status::UncertainLastUsableValue});
  const auto uncertain = uncertainSource.try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, id(32));
  EXPECT_EQ(uncertain.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(uncertain.status_code());
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, AnAddIfNotPresentRefusesAnUncertainReferencesRead)
{
  auto withReferences = object(40);
  auto target = object(41);
  auto withoutReferences = object(42);
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  mNamespace->qualify_references(id(40), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  mNamespace->qualify_references(id(42), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});

  EXPECT_TRUE(
    is_refusal(withReferences.try_add_reference_if_not_present_sync(hasComponent, id(41)).status_code(),
      "ReferencesAnswerUncertain",
      Status::UncertainLastUsableValue));
  const auto refusedAsync = awaited<VoidResult>(
    [&](auto done)
    {
      withReferences.add_reference_if_not_present_async(
        hasComponent, id(41), true, ReferenceHalves::Both, std::move(done));
    },
    "add_reference_if_not_present_async");
  EXPECT_TRUE(
    is_refusal(refusedAsync.status_code(), "ReferencesAnswerUncertain", Status::UncertainLastUsableValue));
  EXPECT_TRUE(
    is_refusal(withoutReferences.try_add_reference_if_not_present_sync(hasComponent, id(41)).status_code(),
      "ReferencesAnswerUncertain",
      Status::UncertainLastUsableValue));

  // Nothing was added: the target holds no inverse half.
  const auto targetReferences = target.try_get_references_sync();
  ASSERT_TRUE(targetReferences.is_good()) << to_string(targetReferences.status_code());
  EXPECT_TRUE(targetReferences.value().empty());
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-DELETION-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, ADeletionPassesTheNamespacesCode)
{
  object(50);
  object(51);
  mNamespace->qualify_deletes(StatusCode{Status::GoodLocalOverride});

  const auto deleted = mAddressSpace->try_delete_node_sync(id(50), false);
  EXPECT_EQ(deleted.status_code().as_status(), Status::GoodLocalOverride) << to_string(deleted.status_code());
  EXPECT_EQ(mAddressSpace->try_find_node_sync(id(50)).status_code().as_status(), Status::BadNodeIdUnknown);

  const auto subtree = awaited<VoidResult>([&](auto done)
    { mAddressSpace->delete_node_async(id(51), true, ReferenceHalves::Both, std::move(done)); },
    "delete_node_async");
  EXPECT_EQ(subtree.status_code().as_status(), Status::GoodLocalOverride) << to_string(subtree.status_code());
  EXPECT_EQ(mAddressSpace->try_find_node_sync(id(51)).status_code().as_status(), Status::BadNodeIdUnknown);
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, ADeletionRefusesAnUncertainAnswerItWouldActOn)
{
  // The lookup of the subtree's root answered Uncertain with the Node.
  object(60);
  mNamespace->qualify_lookup(id(60), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_TRUE(is_refusal(mAddressSpace->try_delete_node_sync(id(60), true).status_code(),
    "LookupAnswerUncertain",
    Status::UncertainLastUsableValue));
  const auto kept = mAddressSpace->try_find_node_sync(id(60));
  EXPECT_EQ(kept.status_code().as_status(), Status::UncertainLastUsableValue)
    << "the root was deleted: " << to_string(kept.status_code());

  // The References read of the subtree's root answered Uncertain, with its References and without.
  auto withReferences = object(61);
  object(62);
  withReferences.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, id(62));
  mNamespace->qualify_references(id(61), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_TRUE(is_refusal(mAddressSpace->try_delete_node_sync(id(61), true).status_code(),
    "ReferencesAnswerUncertain",
    Status::UncertainLastUsableValue));
  EXPECT_TRUE(mAddressSpace->try_find_node_sync(id(62)).is_good()) << "the child was deleted";

  object(63);
  mNamespace->qualify_references(id(63), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});
  EXPECT_TRUE(is_refusal(mAddressSpace->try_delete_node_sync(id(63), true).status_code(),
    "ReferencesAnswerUncertain",
    Status::UncertainLastUsableValue));
}

// The walk up HasSubtype decides whether a type is compatible, so an Uncertain answer to the lookup or the
// References read of a type on it is refused; a type that is not found still ends the walk as a mismatch.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, TheSubtypeWalkRefusesAnUncertainTypeAnswer)
{
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
  auto base = mAddressSpace->create_node_sync(id(200), NodeClass::ObjectType);
  for (uint32_t i = 1; i <= 3; ++i)
  {
    (void)mAddressSpace->create_node_sync(id(200 + i), NodeClass::ObjectType);
    base.add_reference_sync(hasSubtype, id(200 + i));
    auto instance = object(210 + i);
    ASSERT_TRUE(instance.try_add_reference_sync(hasTypeDefinition, id(200 + i)).is_good());
  }
  const auto attach = [&](uint32_t instance)
  {
    return awaited<VoidResult>([&](auto done)
      { instance_utils::attach_subtype_async(*mAddressSpace, id(instance), id(200), std::move(done)); },
      "attach_subtype_async");
  };

  // Control: the walk reaches the base type.
  const auto compatible = attach(211);
  EXPECT_TRUE(compatible.is_good()) << to_string(compatible.status_code());

  mNamespace->qualify_lookup(id(201), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});
  EXPECT_TRUE(
    is_refusal(attach(211).status_code(), "LookupAnswerUncertain", Status::UncertainLastUsableValue));

  mNamespace->qualify_references(id(202), Qualifier{StatusCode{Status::UncertainLastUsableValue}, false});
  EXPECT_TRUE(
    is_refusal(attach(212).status_code(), "ReferencesAnswerUncertain", Status::UncertainLastUsableValue));

  // Control: a type that is not found ends the walk with Bad_TypeMismatch, as documented.
  mNamespace->qualify_lookup(id(203), Qualifier{StatusCode{Status::BadNodeIdUnknown}, false});
  EXPECT_EQ(attach(213).status_code().as_status(), Status::BadTypeMismatch);
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, AddingAndBindingAMethodRefuseAnUncertainAnswer)
{
  object(70);
  const auto handler = [](const MethodCall&) -> MethodResult<>
  {
    return {};
  };

  // The creation of the Method answered Uncertain with the Node: refused, and the Node is removed again.
  mNamespace->qualify_create(id(71), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  const auto refused = try_add_method_sync(*mAddressSpace,
    id(70),
    QualifiedName{mNsIndex, "Refused"},
    inputs(),
    outputs(),
    handler,
    MethodConfig{.nodeId = id(71)});
  EXPECT_TRUE(is_refusal(refused.status_code(), "LookupAnswerUncertain", Status::UncertainLastUsableValue));
  EXPECT_EQ(mAddressSpace->try_find_node_sync(id(71)).status_code().as_status(), Status::BadNodeIdUnknown)
    << "the Method created is left behind";

  // The lookup of the Method a handler is bound to answered Uncertain with the Node.
  const auto added = try_add_method_sync(*mAddressSpace,
    id(70),
    QualifiedName{mNsIndex, "Bound"},
    inputs(),
    outputs(),
    handler,
    MethodConfig{.nodeId = id(72)});
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  mNamespace->qualify_lookup(id(72), Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_TRUE(
    is_refusal(try_bind_method_sync(*mAddressSpace, id(72), inputs(), outputs(), handler).status_code(),
      "LookupAnswerUncertain",
      Status::UncertainLastUsableValue));
}

// The creation of a Method's argument Property answered Uncertain with the Node: the Method is refused, and
// the Property, which is not yet linked to the Method and so is not removed with it, is removed too.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StatusRoutingAddressSpace, AddingAMethodRemovesAPropertyAnsweredUncertain)
{
  object(80);
  const auto countNodes = [&]
  {
    const auto enumerated = awaited<Result<std::vector<NodeId>>>([&](auto done)
      { mNamespace->enumerate_nodes_async(RequestInfo{}, std::move(done)); },
      "enumerate_nodes_async");
    EXPECT_TRUE(enumerated.is_good()) << to_string(enumerated.status_code());
    return enumerated.is_good() ? enumerated.value().size() : std::size_t{0};
  };
  const std::size_t before = countNodes();

  // The Property's NodeId is a GUID the SDK chooses: every Variable creation is qualified.
  mNamespace->qualify_creates_of(
    NodeClass::Variable, Qualifier{StatusCode{Status::UncertainLastUsableValue}});
  const auto refused = try_add_method_sync(
    *mAddressSpace,
    id(80),
    QualifiedName{mNsIndex, "WithArguments"},
    inputs(arg<double>("Factor")),
    outputs(),
    [](const MethodCall&, double) -> MethodResult<> { return {}; },
    MethodConfig{.nodeId = id(81)});

  EXPECT_TRUE(is_refusal(refused.status_code(), "LookupAnswerUncertain", Status::UncertainLastUsableValue));
  EXPECT_EQ(mAddressSpace->try_find_node_sync(id(81)).status_code().as_status(), Status::BadNodeIdUnknown)
    << "the Method created is left behind";
  EXPECT_EQ(countNodes(), before) << "a Node created by the refused add_method is left behind";
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-04-METHOD-BINDING-PASSES-THE-SETTERS-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, MethodBindingPassesTheSettersCode)
{
  const uint16_t index = add_scripted_namespace();
  ASSERT_NE(index, 0U);
  const NodeId objectId{index, 1};
  const NodeId methodId{index, 2};
  const QualifiedName methodName{index, "Start"};
  auto method = std::make_shared<InstallAnsweringMethod>();
  describe(*method, methodId, NodeClass::Method, methodName);
  auto machine = std::make_shared<ua::test::ScriptedNode>();
  describe(*machine, objectId, NodeClass::Object, QualifiedName{index, "Machine"});
  machine->answer_references(
    {Reference{NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{methodId}, true}});
  mScripted->hold(objectId, machine);
  mScripted->hold(methodId, method);

  const auto handler = [](const MethodCall&) -> MethodResult<>
  {
    return {};
  };
  const MethodCallSource::CallHandler rawHandler =
    [](const CallMethodRequest&, shared_ptr<const MethodCallContext>, std::function<void(CallResult)> done)
  {
    done(CallResult{CallMethodResult{}});
  };
  const StatusCode refusedInstall{Status::BadNotSupported,
    ErrorDetail::build(
      "InstallRefused", "The Method does not take this handler", "StatusRoutingAddressSpace")};

  for (const StatusCode& answer :
    {StatusCode{Status::GoodLocalOverride}, StatusCode{Status::UncertainLastUsableValue}, refusedInstall})
  {
    SCOPED_TRACE(to_string(answer));
    method->answer_installs(answer);

    const auto byNode = try_bind_method_sync(*mAddressSpace, methodId, inputs(), outputs(), handler);
    EXPECT_EQ(byNode.status_code().value(), answer.value()) << to_string(byNode.status_code());

    const auto byName =
      try_bind_method_sync(*mAddressSpace, objectId, methodName, inputs(), outputs(), handler);
    EXPECT_EQ(byName.status_code().value(), answer.value()) << to_string(byName.status_code());

    const auto bound = awaited<VoidResult>([&](auto done)
      { bind_method_async(*mAddressSpace, methodId, inputs(), outputs(), handler, std::move(done)); },
      "bind_method_async");
    EXPECT_EQ(bound.status_code().value(), answer.value()) << to_string(bound.status_code());

    const auto resolved = awaited<VoidResult>(
      [&](auto done)
      {
        instance_utils::resolve_and_set_method_handler_async(
          *mAddressSpace, objectId, methodName, rawHandler, std::move(done));
      },
      "resolve_and_set_method_handler_async");
    EXPECT_EQ(resolved.status_code().value(), answer.value()) << to_string(resolved.status_code());

    if (answer.is_bad())
    {
      const auto detail = byNode.status_code().shared_detail();
      EXPECT_TRUE(detail != nullptr && detail->code == "InstallRefused")
        << "the setter's ErrorDetail is not kept";
    }
  }
}

// The typed call of a Method from the server's own code answers the code its namespace answered the call
// with, combined with the Method's statusCode; a Good subcode is not replaced.
// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-TYPED-CALL-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, ATypedCallPassesTheNamespacesCode)
{
  object(80);
  const auto added = try_add_method_sync(
    *mAddressSpace,
    id(80),
    QualifiedName{mNsIndex, "Run"},
    inputs(),
    outputs(),
    [](const MethodCall&) -> MethodResult<> { return {}; },
    MethodConfig{.nodeId = id(81)});
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  const MethodAccessor& method = added.value();

  mNamespace->qualify_calls(CallQualifier{StatusCode{Status::GoodClamped}, std::nullopt});
  const auto typed = method.try_call_sync<>(id(80));
  EXPECT_EQ(typed.status_code().as_status(), Status::GoodClamped) << to_string(typed.status_code());
  ASSERT_TRUE(typed.has_outputs());
  EXPECT_NO_THROW((void)typed.outputs());

  CallMethodRequest request;
  request.object_id() = id(80);
  request.method_id() = id(81);
  const auto called = awaited<CallResult>(
    [&](auto done) { method.call_async(request, nullptr, std::move(done)); }, "call_async");
  ASSERT_TRUE(called.is_good()) << to_string(called.status_code());
  EXPECT_EQ(called.value().status_code().as_status(), Status::GoodClamped)
    << to_string(called.value().status_code());
  EXPECT_TRUE(called.value().output_arguments().empty());

  mNamespace->qualify_calls(
    CallQualifier{StatusCode{Status::Good}, StatusCode{Status::UncertainLastUsableValue}});
  const auto uncertain = method.try_call_sync<>(id(80));
  EXPECT_EQ(uncertain.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(uncertain.status_code());
  ASSERT_TRUE(uncertain.has_outputs());
  EXPECT_NO_THROW((void)uncertain.outputs());
}

// The typed call of a Method from the server's own code completes with the Good subcode the Method's typed
// handler gave, through with_status or through a Result holding the output, with the outputs and the code's
// own ErrorDetail: only the Call service answers it plain Good, to a client.
// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-TYPED-CALL-PASSES-THE-NAMESPACES-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, ATypedCallPassesTheHandlersGoodSubcode)
{
  object(82);
  const shared_ptr<const ErrorDetail> clampedDetail =
    ErrorDetail::build("PumpRateClamped", "The pump clamped the requested rate", "Pump.Start");
  const StatusCode clamped{Status::GoodClamped, clampedDetail};
  const auto withStatus = try_add_method_sync(
    *mAddressSpace,
    id(82),
    QualifiedName{mNsIndex, "WithStatus"},
    inputs(),
    outputs(arg<double>("Rate")),
    [clamped](const MethodCall&) { return MethodResult<double>::with_status(clamped, 1.5); },
    MethodConfig{.nodeId = id(83)});
  ASSERT_TRUE(withStatus.is_good()) << to_string(withStatus.status_code());
  const auto fromResult = try_add_method_sync(
    *mAddressSpace,
    id(82),
    QualifiedName{mNsIndex, "FromResult"},
    inputs(),
    outputs(arg<double>("Rate")),
    [clamped](const MethodCall&) -> MethodResult<double> { return Result<double>{2.5, clamped}; },
    MethodConfig{.nodeId = id(84)});
  ASSERT_TRUE(fromResult.is_good()) << to_string(fromResult.status_code());

  const std::vector<std::pair<const MethodAccessor*, double>> methods{
    {&withStatus.value(), 1.5}, {&fromResult.value(), 2.5}};
  for (const auto& [method, output] : methods)
  {
    SCOPED_TRACE(to_string(method->get_node_id()));

    const auto typed = method->try_call_sync<double>(id(82));
    EXPECT_EQ(typed.status_code().value(), clamped.value()) << to_string(typed.status_code());
    EXPECT_EQ(typed.status_code().shared_detail(), clampedDetail) << "the handler's ErrorDetail is not kept";
    ASSERT_TRUE(typed.has_outputs()) << "the outputs of a Good subcode were dropped";
    EXPECT_EQ(typed.value(), output);

    EXPECT_EQ(method->call_sync<double>(id(82)), output) << "the throwing form refused a Good subcode";

    CallMethodRequest request;
    request.object_id() = id(82);
    request.method_id() = method->get_node_id();
    const auto called = awaited<CallResult>(
      [&](auto done) { method->call_async(request, nullptr, std::move(done)); }, "call_async");
    ASSERT_TRUE(called.has_value()) << to_string(called.status_code());
    EXPECT_EQ(called.value().status_code().value(), clamped.value())
      << to_string(called.value().status_code());
    ASSERT_EQ(called.value().output_arguments().size(), 1U);
    EXPECT_EQ(called.value().output_arguments()[0].as<double>(), output);
  }
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-05-A-GENERATED-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(StatusRoutingAddressSpace, AGeneratedTypedReadAnswersTheCombinedCode)
{
  auto instance = object(90);
  auto symbol = mAddressSpace->create_node_sync(id(91), NodeClass::Variable);
  symbol.set_browse_name(QualifiedName{0, "Symbol"});
  instance.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id(91));
  ASSERT_TRUE(instance
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  NodeId{ObjectTypeId::QuantityType},
                  true,
                  ReferenceHalves::ThisHalfOnly)
                .is_good());
  const auto attached = Quantity::try_attach_sync(*mAddressSpace, id(90));
  ASSERT_TRUE(attached.is_good()) << to_string(attached.status_code());
  const Quantity& quantity = attached.value();
  const Variant kilograms{LocalizedText{"", "kg"}};

  mNamespace->answer_reads(
    id(91), DataValueResult{DataValue{kilograms}, StatusCode{Status::GoodLocalOverride}});
  const auto subcode = quantity.try_read_symbol_sync();
  EXPECT_EQ(subcode.status_code().as_status(), Status::GoodLocalOverride) << to_string(subcode.status_code());
  ASSERT_TRUE(subcode.is_good());
  EXPECT_EQ(subcode.value().text(), "kg");

  // The Value's own Uncertain status, under a Good subcode on the answer: the worse is answered.
  mNamespace->answer_reads(id(91),
    DataValueResult{DataValue{kilograms, StatusCode{Status::UncertainLastUsableValue}},
      StatusCode{Status::GoodLocalOverride}});
  const auto valueUncertain = quantity.try_read_symbol_sync();
  EXPECT_EQ(valueUncertain.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(valueUncertain.status_code());
  EXPECT_EQ(valueUncertain.value().text(), "kg");

  // An Uncertain answer that holds the Value.
  mNamespace->answer_reads(
    id(91), DataValueResult{DataValue{kilograms}, StatusCode{Status::UncertainLastUsableValue}});
  const auto answerUncertain = awaited<LocalizedTextResult>(
    [&](auto done) { quantity.read_symbol_async(std::move(done)); }, "read_symbol_async");
  EXPECT_EQ(answerUncertain.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(answerUncertain.status_code());
  EXPECT_EQ(answerUncertain.value().text(), "kg");

  mNamespace->answer_reads(id(91),
    DataValueResult{
      DataValue{kilograms, StatusCode{Status::BadSensorFailure}}, StatusCode{Status::GoodLocalOverride}});
  const auto bad = quantity.try_read_symbol_sync();
  EXPECT_EQ(bad.status_code().as_status(), Status::BadSensorFailure);
  EXPECT_FALSE(bad.has_value());
  EXPECT_THROW((void)bad.value(), UaException);

  const auto badAsync = awaited<LocalizedTextResult>(
    [&](auto done) { quantity.read_symbol_async(std::move(done)); }, "read_symbol_async");
  EXPECT_EQ(badAsync.status_code().as_status(), Status::BadSensorFailure);
  EXPECT_FALSE(badAsync.has_value());
  EXPECT_THROW((void)badAsync.value(), UaException);
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-05-AN-UNCERTAIN-ANSWER-WITHOUT-A-VALUE-REACHES-THE-CALLER, scope=function)
TEST_F(StatusRoutingAddressSpace, AGeneratedTypedReadOfAnUncertainAnswerWithoutAValueCompletes)
{
  auto instance = object(95);
  auto symbol = mAddressSpace->create_node_sync(id(96), NodeClass::Variable);
  symbol.set_browse_name(QualifiedName{0, "Symbol"});
  instance.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id(96));
  ASSERT_TRUE(instance
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  NodeId{ObjectTypeId::QuantityType},
                  true,
                  ReferenceHalves::ThisHalfOnly)
                .is_good());
  const auto attached = Quantity::try_attach_sync(*mAddressSpace, id(95));
  ASSERT_TRUE(attached.is_good()) << to_string(attached.status_code());
  const Quantity& quantity = attached.value();

  mNamespace->answer_reads(id(96), DataValueResult{StatusCode{Status::UncertainLastUsableValue}});
  const auto read = awaited<LocalizedTextResult>(
    [&](auto done) { quantity.read_symbol_async(std::move(done)); }, "read_symbol_async");
  EXPECT_EQ(read.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(read.status_code());
  EXPECT_THROW((void)read.value(), UaException);

  const auto readSync = quantity.try_read_symbol_sync();
  EXPECT_EQ(readSync.status_code().as_status(), Status::UncertainLastUsableValue)
    << to_string(readSync.status_code());
  EXPECT_THROW((void)quantity.read_symbol_sync(), UaException);
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-05-A-GENERATED-TYPED-READ-OF-ANOTHER-TYPE-ANSWERS-BAD-TYPE-MISMATCH, scope=function)
TEST_F(StatusRoutingAddressSpace, AGeneratedTypedReadOfAValueOfAnotherTypeAnswersBadTypeMismatch)
{
  auto instance = object(97);
  auto symbol = mAddressSpace->create_node_sync(id(98), NodeClass::Variable);
  symbol.set_browse_name(QualifiedName{0, "Symbol"});
  instance.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id(98));
  ASSERT_TRUE(instance
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  NodeId{ObjectTypeId::QuantityType},
                  true,
                  ReferenceHalves::ThisHalfOnly)
                .is_good());
  const auto attached = Quantity::try_attach_sync(*mAddressSpace, id(97));
  ASSERT_TRUE(attached.is_good()) << to_string(attached.status_code());
  const Quantity& quantity = attached.value();

  // Symbol is a LocalizedText; a String is another type.
  mNamespace->answer_reads(id(98), DataValueResult{DataValue{Variant{String{"kg"}}}});
  const auto mismatch = quantity.try_read_symbol_sync();
  EXPECT_EQ(mismatch.status_code().as_status(), Status::BadTypeMismatch) << to_string(mismatch.status_code());
  ASSERT_NE(mismatch.shared_detail(), nullptr);
  EXPECT_EQ(mismatch.shared_detail()->source, "Quantity::read_symbol_async");
  EXPECT_NE(mismatch.shared_detail()->summary.find("'symbol'"), std::string::npos)
    << mismatch.shared_detail()->summary;

  // Control: the same Property answered with a LocalizedText is read.
  mNamespace->answer_reads(id(98), DataValueResult{DataValue{Variant{LocalizedText{"", "kg"}}}});
  const auto matched = quantity.try_read_symbol_sync();
  ASSERT_TRUE(matched.is_good()) << to_string(matched.status_code());
  EXPECT_EQ(matched.value().text(), "kg");
}

}  // namespace
