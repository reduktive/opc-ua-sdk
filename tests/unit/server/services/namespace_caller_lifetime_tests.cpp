// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "access_control_test_support.h"
#include "batch_recording_namespace.h"
#include "scripted_node.h"
#include "test_log_sink.h"
#include "ua_allow_nulls_batch.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_eu_range_resolver.h"
#include "ua_event_bus.h"
#include "ua_event_bus_test_access.h"
#include "ua_event_notifier_type.h"
#include "ua_event_type_model.h"
#include "ua_logger.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_numeric_data_type_facts.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_service_operation_limits.h"
#include "ua_subscription_test_access.h"
#include "ua_subtype_facts.h"
#include "ua_to_string.h"
#include "ua_write_type_facts.h"

#include "ua_access_control.h"
#include "ua_history_event_field_list.h"
#include "ua_history_event_validation.h"
#include "ua_update_event_details.h"

#include "ua_content_filter.h"
#include "ua_external_guard_linker.h"
#include "ua_simple_attribute_operand.h"
#include "ua_variabletype_id.h"

#include "ua_add_method.h"
#include "ua_alarm_group.h"
#include "ua_analog_item.h"
#include "ua_base_object.h"
#include "ua_data_access_projection.h"
#include "ua_enum_value_type.h"
#include "ua_instance_utils.h"
#include "ua_memory_stream.h"
#include "ua_nodeset_document.h"
#include "ua_nodeset_import.h"
#include "ua_sinks.h"
#include "ua_utilities.h"
#include "ua_state_machine_runtime.h"

#include "ua_access_level_type.h"
#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_application_configuration.h"
#include "ua_continuation_points.h"
#include "ua_data_change_notification.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_diagnostic_policy.h"
#include "ua_history_read_request.h"
#include "ua_history_read_service.h"
#include "ua_namespace_delegates.h"
#include "ua_node_management_service.h"
#include "ua_read_raw_modified_details.h"
#include "ua_retained_notification_authorization.h"
#include "ua_server_configuration.h"
#include "ua_server_session_info.h"
#include "ua_service_fault.h"
#include "ua_session_security.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <gtest/gtest.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

// How long a death-test child may run before SIGALRM ends it, so that a child that hangs fails its test
// rather than holding its shard until the run's own timeout.
constexpr unsigned deathTestChildSeconds = 120;

// The first statement of a death-test child: arms its watchdog.
void start_child()
{
  ::alarm(deathTestChildSeconds);
}

// The last statement of a death-test child. It exits with status 0 when the child's checks passed. Otherwise
// it writes @p scenario and each failed check to stderr, which the parent's EXPECT_EXIT prints, and exits
// with status 1.
[[noreturn]] void finish_child(std::string_view scenario = {})
{
  if (!::testing::Test::HasFailure())
  {
    std::exit(0);
  }
  if (!scenario.empty())
  {
    std::cerr << scenario << '\n';
  }
  const auto* testResult = ::testing::UnitTest::GetInstance()->current_test_info()->result();
  for (int i = 0; i < testResult->total_part_count(); ++i)
  {
    const auto& testPartResult = testResult->GetTestPartResult(i);
    if (!testPartResult.failed())
    {
      continue;
    }
    if (testPartResult.file_name() != nullptr)
    {
      std::cerr << testPartResult.file_name();
    }
    else
    {
      std::cerr << "unknown test source";
    }
    std::cerr << ':' << testPartResult.line_number() << ": " << testPartResult.message() << '\n';
  }
  std::cerr.flush();
  std::exit(1);
}

enum class HeldMember
{
  Lookup,
  References,
  Value,
  Membership,
  Permissions
};

// This state holds callback copies and Nodes, but no address space or namespace handle.
struct HeldObservation : LogSink
{
  std::optional<HeldMember> member;
  NodeId nodeId;
  bool held{false};
  bool copyDelivered{false};
  std::array<std::size_t, 3> calls{};
  std::vector<ua::test::BatchRecordingNamespace::Call> referenceCalls;
  std::vector<NodeId> valueReads;
  std::vector<ByteString> releasedTokens;
  std::function<void()> good;
  std::function<void()> bad;
  std::vector<std::vector<NodeId>> lookupCalls;
  std::vector<ua::test::BatchRecordingNamespace::Call> membershipCalls;
  std::size_t heldAnswerCount{0};
  std::optional<StatusCode> firstHeldRefusal;
  std::size_t dispatchStarts{0};
  std::optional<ByteString> referenceTokenToHold;
  // Calls of `effective_permissions_async`, kept apart from `calls` so that the existing three-member
  // call-count comparisons keep their shape.
  std::size_t permissionCalls{0};

  // Select a later awaited step naming the same Node without retaining either owner.
  std::size_t matchingCallsBeforeHold{0};
  bool holdReferenceAddition{false};
  std::vector<ReferenceChange> referenceAdditions;
  std::optional<ByteString> heldReferenceToken;

  struct Warning
  {
    std::string category;
    std::string message;
    std::map<std::string, std::string> fields;
    bool operator==(const Warning&) const = default;
  };

  void log(const LogEntry& entry) override
  {
    if (entry.level != LogLevel::Warning)
    {
      return;
    }
    Warning warning{std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::ostringstream value;
      std::visit([&value](const auto& scalar) { value << scalar; }, field.value);
      warning.fields.emplace(std::string{field.key}, value.str());
    }
    const std::lock_guard lock{mLogMutex};
    mWarnings.push_back(std::move(warning));
  }

  std::vector<Warning> warnings() const
  {
    const std::lock_guard lock{mLogMutex};
    return mWarnings;
  }

private:
  mutable std::mutex mLogMutex;
  std::vector<Warning> mWarnings;
};

std::size_t member_index(HeldMember member)
{
  return numeric_cast<std::size_t>(utils::to_underlying(member));
}

StatusCode unavailable()
{
  return StatusCode{Status::BadResourceUnavailable,
    ErrorDetail::build(
      "HeldNamespaceRefusal", "The namespace refused its retained operation", "NamespaceCallerLifetime")
      .context(ContextKeys::nodeId, NodeId{2, "held"})};
}

// The in-memory Node behind @p accessor, read and changed directly: no owner lock or namespace call.
std::shared_ptr<default_ns::BaseNode> stored_node(const NodeAccessor& accessor)
{
  return std::dynamic_pointer_cast<default_ns::BaseNode>(ua::detail::NodeAccessorRoute::node_of(accessor));
}

// Extend the recording namespace's real Node store; these tests additionally require externally copied
// completions and destructor delivery, which its ordinary hold/release methods do not provide.
class FakeHoldingNamespace final : public ua::test::BatchRecordingNamespace
{
public:
  FakeHoldingNamespace(boost::asio::any_io_executor executor, std::shared_ptr<HeldObservation> observation,
    StatusCode refusal, string_view namespaceUri = "urn:test:namespace-caller-lifetime")
    : BatchRecordingNamespace(namespaceUri, std::move(executor)), mObservation(std::move(observation)),
      mRefusal(std::move(refusal))
  {}

  ~FakeHoldingNamespace() override
  {
    for (auto& refuse : mRefuse)
    {
      refuse();
    }
  }

  std::map<NodeId, NodeReferencesResult> references;
  std::map<NodeId, DataValueResult> values;
  std::map<NodeId, NodeResult> lookups;
  std::map<NodeId, std::vector<BoolResult>> memberships;

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    ++mObservation->calls[member_index(HeldMember::Lookup)];
    mObservation->lookupCalls.emplace_back(nodeIds.begin(), nodeIds.end());
    const bool hold = should_hold(HeldMember::Lookup, nodeIds);
    // The recorder's lookup of the real Node store, with this namespace's scripted lookups in place of its
    // answers.
    BatchRecordingNamespace::find_nodes_async(request,
      nodeIds,
      maxAge,
      [observation = mObservation,
        refusal = mRefusal,
        hold,
        scripted = lookups,
        requested = std::vector<NodeId>{nodeIds.begin(), nodeIds.end()},
        complete = std::move(complete)](BatchResult<NodeResult> answer)
      {
        for (std::size_t i = 0; i < requested.size() && i < answer.items.size(); ++i)
        {
          if (const auto replacement = scripted.find(requested[i]); replacement != scripted.end())
          {
            answer.items[i] = replacement->second;
          }
        }
        retain_or_deliver(observation, refusal, hold, std::move(answer), complete);
      });
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    ++mObservation->calls[member_index(HeldMember::References)];
    std::vector<NodeId> nodeIds;
    BatchResult<NodeReferencesResult> answer;
    for (const auto& query : queries)
    {
      nodeIds.push_back(query.nodeId);
      if (!query.resumeToken.empty())
      {
        // A forbidden ownerless resume is counted, then answered terminally so the negative stays bounded.
        answer.items.emplace_back(NodeReferences{});
        continue;
      }
      const auto found = references.find(query.nodeId);
      if (found == references.end())
      {
        answer.items.emplace_back(NodeReferences{});
      }
      else
      {
        answer.items.push_back(found->second);
      }
    }
    // This override scripts the answers itself; reuse the base recorder's owned query record shape.
    ua::test::BatchRecordingNamespace::Call recorded;
    recorded.member = ua::test::BatchRecordingNamespace::Member::ReadReferences;
    recorded.nodeIds = nodeIds;
    for (const auto& query : queries)
    {
      recorded.referenceQueries.push_back(
        ua::test::BatchRecordingNamespace::ReferenceQueryRecord{.nodeId = query.nodeId,
          .direction = query.direction,
          .referenceTypeHint = query.referenceTypeHint,
          .maxReferences = query.maxReferences,
          .resumeToken = query.resumeToken,
          .answeredToken = {},
          .answeredStatus = std::nullopt});
    }
    mObservation->referenceCalls.push_back(std::move(recorded));
    bool hold = false;
    if (!mObservation->referenceTokenToHold ||
        std::any_of(queries.begin(),
          queries.end(),
          [observation = mObservation](const auto& query)
          { return query.resumeToken == *observation->referenceTokenToHold; }))
    {
      hold = should_hold(HeldMember::References, nodeIds);
    }
    if (hold && mObservation->heldReferenceToken)
    {
      // The same Node can be read again by a nested child walk. Issue this selected page's token
      // only at the held call, not again for every independent read of that Node's static answer.
      for (std::size_t i = 0; i < nodeIds.size(); ++i)
      {
        if (nodeIds[i] == mObservation->nodeId && answer.items[i].is_good())
        {
          answer.items[i].value().resumeToken = *mObservation->heldReferenceToken;
          mObservation->referenceCalls.back().referenceQueries[i].answeredToken =
            *mObservation->heldReferenceToken;
        }
      }
    }
    retain_or_deliver(mObservation, mRefusal, hold, std::move(answer), complete);
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    ++mObservation->calls[member_index(HeldMember::Value)];
    std::vector<NodeId> nodeIds;
    BatchResult<DataValueResult> answer;
    for (const auto& item : items)
    {
      nodeIds.push_back(item.value.node_id());
      mObservation->valueReads.push_back(item.value.node_id());
      const auto found = values.find(item.value.node_id());
      if (found == values.end())
      {
        answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
      }
      else
      {
        answer.items.push_back(found->second);
      }
    }
    const bool hold = should_hold(HeldMember::Value, nodeIds);
    retain_or_deliver(mObservation, mRefusal, hold, std::move(answer), complete);
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

  void release_resume_token(ByteString token) override
  {
    mObservation->releasedTokens.push_back(std::move(token));
  }

  // The asynchronous permission member, reached once the immediate forms decline. A disengaged @p nodes
  // asks about the namespace itself; it is matched as the null NodeId, so `arm(Permissions, NodeId{})`
  // holds the namespace-subject call. Every subject not held is granted every permission.
  void effective_permissions_async(const RequestInfo&, shared_ptr<const AccessIdentity>,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    ++mObservation->permissionCalls;
    std::vector<NodeId> nodeIds{NodeId{}};
    if (nodes)
    {
      nodeIds = *nodes;
    }
    EffectivePermissionsResult answer;
    for (std::size_t i = 0; i < nodeIds.size(); ++i)
    {
      answer.items.emplace_back(ua::test_helpers::all_permissions());
    }
    const bool hold = should_hold(HeldMember::Permissions, nodeIds);
    retain_or_deliver(mObservation, mRefusal, hold, std::move(answer), std::move(callback));
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override
  {
    if (memberships.empty() && mObservation->member != HeldMember::Membership)
    {
      BatchRecordingNamespace::view_contains_async(request, view, nodes, std::move(complete));
      return;
    }
    ua::test::BatchRecordingNamespace::Call recorded;
    recorded.member = ua::test::BatchRecordingNamespace::Member::ViewContains;
    recorded.view = view;
    recorded.candidates.assign(nodes.begin(), nodes.end());
    mObservation->membershipCalls.push_back(std::move(recorded));
    BatchResult<BoolResult> answer;
    const auto scripted = memberships.find(view);
    for (std::size_t i = 0; i < nodes.size(); ++i)
    {
      if (scripted != memberships.end() && i < scripted->second.size())
      {
        answer.items.push_back(scripted->second[i]);
      }
      else
      {
        answer.items.emplace_back(true);
      }
    }
    const std::array<NodeId, 1> named{view};
    const bool hold = should_hold(HeldMember::Membership, named);
    retain_or_deliver(mObservation, mRefusal, hold, std::move(answer), std::move(complete));
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    std::vector<NodeId> sources;
    for (const auto& change : changes)
    {
      sources.push_back(change.source);
      mObservation->referenceAdditions.push_back(change);
    }
    bool hold{false};
    if (mObservation->holdReferenceAddition && !mObservation->held)
    {
      for (const auto& source : sources)
      {
        if (source != mObservation->nodeId)
        {
          continue;
        }
        if (mObservation->matchingCallsBeforeHold > 0)
        {
          --mObservation->matchingCallsBeforeHold;
          break;
        }
        hold = true;
        mObservation->held = true;
        break;
      }
    }
    // Apply through the existing real Node store before retaining the answer, just as the recording
    // namespace's monitoring-modification hold does. A copied answer never applies the mutation again.
    BatchRecordingNamespace::add_references_async(request,
      changes,
      [observation = mObservation, refusal = mRefusal, hold, complete = std::move(complete)](
        BatchResult<VoidResult> answer, std::vector<VersionedNode> versioned)
      {
        std::function<void(BatchResult<VoidResult>)> deliver = [complete, versioned = std::move(versioned)](
                                                                 BatchResult<VoidResult> result)
        {
          complete(std::move(result), versioned);
        };
        retain_or_deliver(observation, refusal, hold, std::move(answer), std::move(deliver));
      });
    if (hold)
    {
      mRefuse.push_back(mObservation->bad);
    }
  }

private:
  bool should_hold(HeldMember member, std::span<const NodeId> nodeIds)
  {
    if (mObservation->held || mObservation->member != member)
    {
      return false;
    }
    for (const auto& nodeId : nodeIds)
    {
      if (nodeId == mObservation->nodeId)
      {
        if (mObservation->matchingCallsBeforeHold != 0)
        {
          --mObservation->matchingCallsBeforeHold;
          return false;
        }
        mObservation->held = true;
        return true;
      }
    }
    return false;
  }

  template<typename Answer>
  static void retain_or_deliver(const std::shared_ptr<HeldObservation>& observation,
    const StatusCode& refusal, bool hold, BatchResult<Answer> answer,
    std::function<void(BatchResult<Answer>)> complete)
  {
    if (!hold && !observation->copyDelivered)
    {
      complete(std::move(answer));
      return;
    }
    const auto answerCount = answer.items.size();
    if (hold)
    {
      observation->heldAnswerCount = answerCount;
      if (observation->firstHeldRefusal && !answer.items.empty())
      {
        answer.items.front() = Answer{*observation->firstHeldRefusal};
      }
    }
    observation->good = [answer = std::move(answer), complete]
    {
      complete(answer);
    };
    observation->bad = [refusal, complete, answerCount]
    {
      BatchResult<Answer> answer;
      if (refusal.is_uncertain())
      {
        // Uncertain is an item Result without a value, not a whole-batch Bad refusal.
        for (std::size_t i = 0; i < answerCount; ++i)
        {
          answer.items.emplace_back(refusal);
        }
      }
      else
      {
        answer.batchStatus = VoidResult{refusal};
      }
      complete(std::move(answer));
    };
    if (!hold)
    {
      observation->good();
    }
  }

  std::shared_ptr<HeldObservation> mObservation;
  StatusCode mRefusal;
  std::vector<std::function<void()>> mRefuse;
};

template<typename Answer>
struct AnswerObservation
{
  std::size_t count{0};
  std::optional<Answer> answer;
  std::optional<std::size_t> releasedTokensAtCompletion;

  static std::function<void(Answer)> callback(
    std::shared_ptr<AnswerObservation> observation, std::weak_ptr<HeldObservation> held = {})
  {
    return [observation = std::move(observation), held = std::move(held)](Answer answer)
    {
      ++observation->count;
      observation->answer = std::move(answer);
      if (const auto retained = held.lock())
      {
        observation->releasedTokensAtCompletion = retained->releasedTokens.size();
      }
    };
  }
};

struct LifetimeHarness
{
  boost::asio::io_context context;
  StatusCode refusal{unavailable()};
  std::shared_ptr<HeldObservation> held{std::make_shared<HeldObservation>()};
  std::shared_ptr<FakeHoldingNamespace> nameSpace{
    std::make_shared<FakeHoldingNamespace>(context.get_executor(), held, refusal)};
  std::optional<AddressSpace> addressSpace{
    AddressSpace::create("urn:test:namespace-caller-lifetime-owner", context.get_executor())};
  uint16_t index{0};

  explicit LifetimeHarness(StatusCode heldRefusal = unavailable()) : refusal(std::move(heldRefusal))
  {
    const auto registered = std::make_shared<AnswerObservation<Result<uint16_t>>>();
    addressSpace->add_namespace_async(nameSpace, AnswerObservation<Result<uint16_t>>::callback(registered));
    drain();
    EXPECT_EQ(registered->count, 1u);
    if (registered->answer && registered->answer->is_good())
    {
      index = registered->answer->value();
    }
    else
    {
      ADD_FAILURE() << "namespace registration failed";
    }
  }

  ~LifetimeHarness()
  {
    // Release held answers even after a failed owner-expiration assertion so a RED run remains bounded.
    if (held->bad)
    {
      held->bad();
    }
    drain();
    held->good = {};
    held->bad = {};
    nameSpace.reset();
    addressSpace.reset();
    drain();
  }

  void drain()
  {
    context.restart();
    while (context.poll() != 0)
    {
    }
  }

  void drain(std::size_t maximumHandlers)
  {
    context.restart();
    for (std::size_t handled = 0; handled < maximumHandlers; ++handled)
    {
      if (context.poll_one() == 0)
      {
        return;
      }
    }
    const auto extra = context.poll_one();
    EXPECT_EQ(extra, 0u) << "the hierarchy operation exceeded its deterministic handler bound";
    if (extra != 0)
    {
      context.stop();
    }
  }

  std::shared_ptr<EventBus> start_event_hierarchy(const NodeId& eventType,
    const std::shared_ptr<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>& outcome)
  {
    addressSpace->set_logger(
      Logger{held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "hierarchy-test"});
    auto bus = std::make_shared<EventBus>(*addressSpace);
    EventBusTestAccess::post_on_strand(bus,
      [eventType,
        complete = AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>::callback(outcome)](
        auto& guarded) mutable { guarded.resolve_event_type_hierarchy(eventType, std::move(complete)); });
    drain(256);
    return bus;
  }

  NodeAccessor node(string_view identifier, NodeClass nodeClass)
  {
    const NodeId nodeId{index, std::string{identifier}};
    nameSpace->create_node(nodeId, nodeClass);
    const auto found = std::make_shared<AnswerObservation<NodeAccessorResult>>();
    addressSpace->find_node_async(nodeId, AnswerObservation<NodeAccessorResult>::callback(found));
    drain();
    if (!found->answer || !found->answer->is_good())
    {
      throw std::runtime_error("fixture Node lookup failed");
    }
    return found->answer->value();
  }

  void arm(HeldMember member, const NodeId& nodeId)
  {
    held->member = member;
    held->nodeId = nodeId;
    held->calls = {};
    held->referenceCalls.clear();
    held->lookupCalls.clear();
    held->membershipCalls.clear();
    held->heldAnswerCount = 0;
    nameSpace->decline_single_lookups();
  }

  void drop_owners()
  {
    const auto weakSpace = addressSpace->weak();
    const std::weak_ptr<ua::Namespace> weakNamespace{nameSpace};
    addressSpace.reset();
    nameSpace.reset();
    drain();
    EXPECT_FALSE(weakSpace.lock().has_value()) << "held completion retains the AddressSpace";
    EXPECT_TRUE(weakNamespace.expired()) << "held completion retains the namespace";
  }

  void drop_space()
  {
    const auto weakSpace = addressSpace->weak();
    addressSpace.reset();
    drain();
    EXPECT_FALSE(weakSpace.lock().has_value()) << "held completion retains the AddressSpace";
  }
};

NodeReferencesResult reference_to(
  ReferenceTypeId type, const NodeId& target, bool forward, ByteString token = {})
{
  return NodeReferences{
    References{std::vector<Reference>{Reference{NodeId{type}, ExpandedNodeId{target}, forward}}},
    std::move(token)};
}

void expect_refusal(const StatusCode& actual, const StatusCode& expected)
{
  EXPECT_EQ(actual, expected);
  EXPECT_EQ(actual.shared_detail(), expected.shared_detail());
}

// The refusal of an Uncertain @p answer the SDK would act on: `Bad_InternalError` with the ErrorDetail @p
// code, whose inner status is the answer's full value, information bits included, and whose cause is its
// detail.
void expect_uncertain_refused(
  const StatusCode& actual, const StatusCode& answer, std::string_view code = "LookupAnswerUncertain")
{
  EXPECT_EQ(actual, StatusCode{Status::BadInternalError});
  ASSERT_NE(actual.shared_detail(), nullptr);
  EXPECT_EQ(actual.shared_detail()->code, code);
  EXPECT_EQ(actual.shared_detail()->innerStatus, answer.value());
  EXPECT_EQ(actual.shared_detail()->cause, answer.shared_detail());
}

void expect_owner_gone(const StatusCode& actual)
{
  EXPECT_EQ(actual, StatusCode{Status::BadShutdown});
  ASSERT_NE(actual.shared_detail(), nullptr);
  EXPECT_EQ(actual.shared_detail()->code, "AddressSpaceGone");
}

template<typename Answer>
void repeat_and_check(LifetimeHarness& harness, const std::shared_ptr<AnswerObservation<Answer>>& outcome)
{
  const auto calls = harness.held->calls;
  ASSERT_TRUE(harness.held->good);
  harness.held->good();
  harness.held->bad();
  harness.drain();
  EXPECT_EQ(outcome->count, 1u);
  EXPECT_EQ(harness.held->calls, calls);
}

struct PropertyInputs
{
  std::vector<NodeAccessor> variables;
  std::vector<NodeId> properties;
  std::vector<IntegerId> monitoredItems;
};

PropertyInputs properties(LifetimeHarness& harness, string_view browseName, std::size_t count = 1)
{
  PropertyInputs inputs;
  for (std::size_t i = 0; i < count; ++i)
  {
    const auto variable = harness.node("variable" + std::to_string(i), NodeClass::Variable);
    auto property = harness.node("property" + std::to_string(i), NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, std::string{browseName}});
    inputs.variables.push_back(variable);
    inputs.properties.push_back(property.get_node_id());
    harness.nameSpace->references.insert_or_assign(
      variable.get_node_id(), reference_to(ReferenceTypeId::HasProperty, property.get_node_id(), true));
    harness.nameSpace->values.insert_or_assign(property.get_node_id(), DataValue{Variant{true}});
  }
  return inputs;
}

using ReferencesAnswer = std::vector<Result<std::vector<Reference>>>;
using AllowNullsAnswer = std::vector<AllowNullsOutcome>;
using EuRangeAnswer = std::vector<EuRangeProperty>;

void start_references(LifetimeHarness& harness, std::vector<NodeAccessor> nodes,
  const std::shared_ptr<AnswerObservation<ReferencesAnswer>>& outcome,
  std::optional<uint32_t> limit = std::nullopt)
{
  std::vector<namespace_calls::ReferenceRead> reads;
  for (const auto& node : nodes)
  {
    reads.push_back(
      {node, node.get_node_id(), BrowseDirection::Forward, NodeId{ReferenceTypeId::HasProperty}});
  }
  namespace_calls::read_references(*harness.addressSpace,
    RequestInfo{},
    std::move(reads),
    limit,
    AnswerObservation<ReferencesAnswer>::callback(outcome, harness.held));
  harness.drain();
}

enum class TypeOperation
{
  Walk,
  Subtype,
  Declared,
  Encoding,
  Numeric
};

enum class TypeStage
{
  InitialLookup,
  FirstReferences,
  FurtherLookup,
  FurtherReferences
};

struct TypeInputs
{
  NodeAccessor child;
  NodeId childId;
  NodeId parent;
  NodeId target{DataTypeId::Double};
};

TypeInputs type_inputs(LifetimeHarness& harness, TypeOperation operation, string_view suffix = {})
{
  auto child = harness.node("child" + std::string{suffix}, NodeClass::DataType);
  const auto parent = harness.node("parent" + std::string{suffix}, NodeClass::DataType).get_node_id();
  if (operation == TypeOperation::Encoding)
  {
    child = harness.node("encoding" + std::string{suffix}, NodeClass::Object);
    harness.nameSpace->references.insert_or_assign(
      child.get_node_id(), reference_to(ReferenceTypeId::HasEncoding, parent, false));
  }
  else
  {
    harness.nameSpace->references.insert_or_assign(
      child.get_node_id(), reference_to(ReferenceTypeId::HasSubtype, parent, false));
    harness.nameSpace->references.insert_or_assign(
      parent, reference_to(ReferenceTypeId::HasSubtype, NodeId{DataTypeId::Double}, false));
  }
  return {child, child.get_node_id(), parent};
}

void arm_type(LifetimeHarness& harness, const TypeInputs& inputs, TypeStage stage)
{
  if (stage == TypeStage::InitialLookup)
  {
    harness.arm(HeldMember::Lookup, inputs.childId);
  }
  else if (stage == TypeStage::FurtherLookup)
  {
    harness.arm(HeldMember::Lookup, inputs.parent);
  }
  else if (stage == TypeStage::FurtherReferences)
  {
    harness.arm(HeldMember::References, inputs.parent);
  }
  else
  {
    harness.arm(HeldMember::References, inputs.childId);
  }
}

struct TypeAnswer
{
  std::size_t count{0};
  std::vector<SupertypeWalkEnd> walk;
  std::vector<bool> subtype;
  std::map<NodeId, DataTypeFacts> declared;
  std::vector<WriteTypeFacts::EncodingFacts> encoding;
  std::vector<bool> nonNumeric;
  bool throwAfterRecording{false};

  void throw_if_requested() const
  {
    if (throwAfterRecording)
    {
      throw std::runtime_error("facts caller completion refusal");
    }
  }
};

void start_type(LifetimeHarness& harness, TypeOperation operation, std::vector<TypeInputs> inputs,
  const std::shared_ptr<TypeAnswer>& outcome, std::vector<NodeId> knownTypes = {})
{
  std::vector<std::pair<NodeAccessor, NodeId>> starts;
  std::vector<std::pair<NodeId, NodeId>> questions;
  std::vector<NodeId> types{std::move(knownTypes)};
  std::vector<NodeId> targets;
  for (const auto& input : inputs)
  {
    starts.emplace_back(input.child, input.childId);
    questions.emplace_back(input.childId, input.target);
    types.push_back(input.childId);
    targets.push_back(input.target);
  }
  if (operation == TypeOperation::Walk)
  {
    walk_supertypes(
      *harness.addressSpace,
      RequestInfo{},
      std::move(starts),
      8,
      [targets = std::move(targets)](std::size_t chain, const NodeId& type) -> std::optional<int>
      {
        if (type == targets[chain])
        {
          return 7;
        }
        return std::nullopt;
      },
      [outcome](std::vector<SupertypeWalkEnd> answers)
      {
        ++outcome->count;
        outcome->walk = std::move(answers);
      });
  }
  else if (operation == TypeOperation::Subtype)
  {
    SubtypeFacts::resolve_async(*harness.addressSpace,
      RequestInfo{},
      std::move(questions),
      SubtypeFacts::Bounds{8, {}},
      [outcome](std::vector<bool> answers)
      {
        ++outcome->count;
        outcome->subtype = std::move(answers);
        outcome->throw_if_requested();
      });
  }
  else if (operation == TypeOperation::Declared)
  {
    WriteTypeFacts::resolve_declared_async(*harness.addressSpace,
      RequestInfo{},
      std::move(types),
      [outcome](std::map<NodeId, DataTypeFacts> answers)
      {
        ++outcome->count;
        outcome->declared = std::move(answers);
        outcome->throw_if_requested();
      });
  }
  else if (operation == TypeOperation::Encoding)
  {
    WriteTypeFacts::resolve_encodings_async(*harness.addressSpace,
      RequestInfo{},
      std::move(types),
      [outcome](std::vector<WriteTypeFacts::EncodingFacts> answers)
      {
        ++outcome->count;
        outcome->encoding = std::move(answers);
        outcome->throw_if_requested();
      });
  }
  else
  {
    numeric_data_type_facts(*harness.addressSpace,
      RequestInfo{},
      std::move(types),
      [outcome](std::vector<bool> answers)
      {
        ++outcome->count;
        outcome->nonNumeric = std::move(answers);
        outcome->throw_if_requested();
      });
  }
  harness.drain();
}

void expect_type(const TypeAnswer& outcome, TypeOperation operation, TypeStage stage,
  const TypeInputs& inputs, bool success, const StatusCode* failure = nullptr, bool initialFound = false)
{
  EXPECT_EQ(outcome.count, 1u);
  if (operation == TypeOperation::Walk)
  {
    ASSERT_EQ(outcome.walk.size(), 1u);
    if (success)
    {
      EXPECT_EQ(outcome.walk[0].how, SupertypeWalkEnd::How::Decided);
      EXPECT_EQ(outcome.walk[0].value, 7);
    }
    else
    {
      EXPECT_EQ(outcome.walk[0].how, SupertypeWalkEnd::How::Failed);
      if (failure != nullptr)
      {
        expect_refusal(outcome.walk[0].failure, *failure);
      }
      else
      {
        expect_owner_gone(outcome.walk[0].failure);
      }
    }
  }
  else if (operation == TypeOperation::Subtype)
  {
    ASSERT_EQ(outcome.subtype.size(), 1u);
    EXPECT_EQ(outcome.subtype[0], success);
  }
  else if (operation == TypeOperation::Declared)
  {
    const auto found = outcome.declared.find(inputs.childId);
    ASSERT_NE(found, outcome.declared.end());
    const bool expectedFound = success || stage != TypeStage::InitialLookup || initialFound;
    EXPECT_EQ(found->second.found, expectedFound);
    if (expectedFound)
    {
      EXPECT_EQ(found->second.ownId, inputs.childId);
    }
    else
    {
      EXPECT_TRUE(found->second.ownId.is_null());
    }
    if (success)
    {
      EXPECT_EQ(found->second.base, BuiltInTypeId::Double);
    }
    else
    {
      EXPECT_FALSE(found->second.base.has_value());
    }
  }
  else
  {
    ASSERT_EQ(outcome.encoding.size(), 1u);
    EXPECT_EQ(outcome.encoding[0].found, success || stage != TypeStage::InitialLookup || initialFound);
    if (success)
    {
      EXPECT_EQ(outcome.encoding[0].dataType, inputs.parent);
    }
    else
    {
      EXPECT_FALSE(outcome.encoding[0].dataType.has_value());
    }
  }
}

enum class ChunkMode
{
  OwnerlessGood,
  OwnerlessTerminal,
  OwnerlessPage,
  OwnerlessBad,
  BothGone,
  Retained
};

void complete_first_chunk(LifetimeHarness& harness, ChunkMode mode)
{
  const auto calls = harness.held->calls;
  if (mode == ChunkMode::BothGone)
  {
    harness.drop_owners();
  }
  else
  {
    if (mode != ChunkMode::Retained)
    {
      harness.drop_space();
    }
    else
    {
      EXPECT_TRUE(harness.addressSpace->weak().lock().has_value());
    }
    if (mode == ChunkMode::OwnerlessBad)
    {
      harness.held->bad();
    }
    else
    {
      harness.held->good();
    }
    harness.drain();
  }
  if (mode != ChunkMode::Retained)
  {
    EXPECT_EQ(harness.held->calls, calls) << "an unissued chunk or later helper stage was called";
  }
}

void expect_chunk_type(const TypeAnswer& outcome, TypeOperation operation, TypeStage stage,
  const std::vector<TypeInputs>& inputs, ChunkMode mode, const StatusCode& refusal)
{
  EXPECT_EQ(outcome.count, 1u);
  if (operation == TypeOperation::Walk)
  {
    ASSERT_EQ(outcome.walk.size(), inputs.size());
  }
  else if (operation == TypeOperation::Subtype)
  {
    ASSERT_EQ(outcome.subtype.size(), inputs.size());
  }
  else if (operation == TypeOperation::Declared)
  {
    ASSERT_EQ(outcome.declared.size(), inputs.size());
  }
  else
  {
    ASSERT_EQ(outcome.encoding.size(), inputs.size());
  }
  for (std::size_t i = 0; i < inputs.size(); ++i)
  {
    SCOPED_TRACE(i);
    TypeAnswer one;
    one.count = outcome.count;
    if (operation == TypeOperation::Walk)
    {
      one.walk.push_back(outcome.walk[i]);
    }
    else if (operation == TypeOperation::Subtype)
    {
      one.subtype.push_back(outcome.subtype[i]);
    }
    else if (operation == TypeOperation::Declared)
    {
      const auto found = outcome.declared.find(inputs[i].childId);
      ASSERT_NE(found, outcome.declared.end());
      one.declared.insert(*found);
    }
    else
    {
      one.encoding.push_back(outcome.encoding[i]);
    }
    const StatusCode* failure = nullptr;
    if (i == 0 && (mode == ChunkMode::OwnerlessBad || mode == ChunkMode::BothGone))
    {
      failure = &refusal;
    }
    const bool firstLookupAnsweredGood = i == 0 && mode == ChunkMode::OwnerlessGood;
    expect_type(
      one, operation, stage, inputs[i], mode == ChunkMode::Retained, failure, firstLookupAnsweredGood);
  }
}

enum class EventStage
{
  TypeLookup,
  TypeReferences,
  SupertypeLookup,
  SupertypeReferences,
  AggregateLookup,
  AggregateReferences,
  AggregateSupertypeLookup,
  AggregateSupertypeReferences,
  DeclarationLookup,
  DeclarationReferences,
  NestedLookup,
  NestedReferences
};

struct EventInputs
{
  NodeId type;
  NodeId supertype;
  NodeId aggregate;
  NodeId aggregateSupertype;
  NodeId completedType;
  NodeId failedType;
  std::vector<NodeId> declarations;
  std::vector<NodeId> nested;
  std::vector<QualifiedName> names;
  std::map<NodeId, Node*> nodes;
  NodeId source;
  NodeId notifier;
  std::vector<NodeId> notifierParents;
  std::vector<NodeId> views;
  std::vector<NodeId> eventSourceTypes;
  std::map<NodeId, std::shared_ptr<AnswerObservation<std::shared_ptr<const BaseEvent>>>> recipients;
};

EventInputs event_inputs(LifetimeHarness& harness, std::size_t declarationCount = 1)
{
  const auto base = std::make_shared<AnswerObservation<NodeAccessorResult>>();
  harness.addressSpace->create_node_async(NodeId{ObjectTypeId::BaseEventType},
    NodeClass::ObjectType,
    AnswerObservation<NodeAccessorResult>::callback(base));
  harness.drain();
  EXPECT_EQ(base->count, 1u);
  if (!base->answer || !base->answer->is_good())
  {
    throw std::runtime_error("fixture BaseEventType creation failed");
  }

  EventInputs inputs;
  const auto add = [&](string_view identifier, NodeClass nodeClass)
  {
    const auto node = harness.node(identifier, nodeClass);
    const auto nodeId = node.get_node_id();
    inputs.nodes.emplace(nodeId, node.operator->());
    return nodeId;
  };
  inputs.type = add("event-type", NodeClass::ObjectType);
  inputs.supertype = add("event-supertype", NodeClass::ObjectType);
  inputs.aggregate = add("event-aggregate", NodeClass::ReferenceType);
  inputs.aggregateSupertype = add("event-aggregate-supertype", NodeClass::ReferenceType);
  inputs.completedType = add("completed-event-type", NodeClass::ObjectType);
  inputs.failedType = add("failed-event-type", NodeClass::ObjectType);
  for (const auto& type : {inputs.supertype, inputs.completedType, inputs.failedType})
  {
    harness.nameSpace->references.insert_or_assign(
      type, reference_to(ReferenceTypeId::HasSubtype, NodeId{ObjectTypeId::BaseEventType}, false));
  }
  harness.nameSpace->references.insert_or_assign(
    inputs.aggregate, reference_to(ReferenceTypeId::HasSubtype, inputs.aggregateSupertype, false));
  harness.nameSpace->references.insert_or_assign(inputs.aggregateSupertype,
    reference_to(ReferenceTypeId::HasSubtype, NodeId{ReferenceTypeId::Aggregates}, false));

  std::vector<Reference> typeReferences{
    Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{inputs.supertype}, false}};
  for (std::size_t i = 0; i < declarationCount; ++i)
  {
    auto declaration = harness.node("event-branch-" + std::to_string(i), NodeClass::Object);
    const QualifiedName name{harness.index, "Branch" + std::to_string(i)};
    declaration.set_browse_name(name);
    auto nested = harness.node("event-leaf-" + std::to_string(i), NodeClass::Variable);
    nested.set_browse_name(QualifiedName{harness.index, "Leaf"});
    nested.as<VariableAccessor>()->set_data_type(NodeId{DataTypeId::Boolean});
    const auto declarationId = declaration.get_node_id();
    const auto nestedId = nested.get_node_id();
    inputs.declarations.push_back(declarationId);
    inputs.nested.push_back(nestedId);
    inputs.names.push_back(name);
    inputs.nodes.emplace(declarationId, declaration.operator->());
    inputs.nodes.emplace(nestedId, nested.operator->());
    typeReferences.emplace_back(inputs.aggregate, ExpandedNodeId{declarationId}, true);
    harness.nameSpace->references.insert_or_assign(
      declarationId, reference_to(ReferenceTypeId::HasComponent, nestedId, true));
    harness.nameSpace->references.insert_or_assign(nestedId,
      reference_to(ReferenceTypeId::HasModellingRule, NodeId{ObjectId::ModellingRule_Mandatory}, true));
  }
  harness.nameSpace->references.insert_or_assign(
    inputs.type, NodeReferences{References{std::move(typeReferences)}});
  return inputs;
}

std::pair<HeldMember, NodeId> event_stage(const EventInputs& inputs, EventStage stage)
{
  switch (stage)
  {
  case EventStage::TypeLookup:
    return {HeldMember::Lookup, inputs.type};
  case EventStage::TypeReferences:
    return {HeldMember::References, inputs.type};
  case EventStage::SupertypeLookup:
    return {HeldMember::Lookup, inputs.supertype};
  case EventStage::SupertypeReferences:
    return {HeldMember::References, inputs.supertype};
  case EventStage::AggregateLookup:
    return {HeldMember::Lookup, inputs.aggregate};
  case EventStage::AggregateReferences:
    return {HeldMember::References, inputs.aggregate};
  case EventStage::AggregateSupertypeLookup:
    return {HeldMember::Lookup, inputs.aggregateSupertype};
  case EventStage::AggregateSupertypeReferences:
    return {HeldMember::References, inputs.aggregateSupertype};
  case EventStage::DeclarationLookup:
    return {HeldMember::Lookup, inputs.declarations.front()};
  case EventStage::DeclarationReferences:
    return {HeldMember::References, inputs.declarations.front()};
  case EventStage::NestedLookup:
    return {HeldMember::Lookup, inputs.nested.front()};
  case EventStage::NestedReferences:
    return {HeldMember::References, inputs.nested.front()};
  }
  throw std::logic_error("unknown EventType held stage");
}

struct EventAnswer
{
  std::size_t count{0};
  std::optional<event_type_model::DeclarationsResult> declarations;
  std::vector<event_type_model::SelectClauseModelsResult> models;
};

void start_event(LifetimeHarness& harness, const EventInputs& inputs, bool models,
  const std::shared_ptr<EventAnswer>& outcome, const std::vector<NodeId>& types)
{
  if (models)
  {
    std::vector<EventFilter> filters;
    for (const auto& type : types)
    {
      SimpleAttributeOperand clause;
      clause.type_definition_id() = type;
      clause.attribute_id() = utils::to_underlying(AttributeId::Value);
      if (type == inputs.type)
      {
        clause.browse_path() =
          Array<QualifiedName>{inputs.names.front(), QualifiedName{harness.index, "Leaf"}};
      }
      EventFilter filter;
      filter.select_clauses() = Array<SimpleAttributeOperand>{clause};
      filters.push_back(std::move(filter));
    }
    event_type_model::resolve_select_clause_models_async(*harness.addressSpace,
      RequestInfo{},
      std::move(filters),
      [outcome](std::vector<event_type_model::SelectClauseModelsResult> answers)
      {
        ++outcome->count;
        outcome->models = std::move(answers);
      });
  }
  else
  {
    event_type_model::collect_declarations_async(*harness.addressSpace,
      inputs.type,
      [outcome](event_type_model::DeclarationsResult answer)
      {
        ++outcome->count;
        outcome->declarations = std::move(answer);
      });
  }
  harness.drain();
}

void expect_event_failure(const StatusCode& actual, const StatusCode* refusal = nullptr)
{
  if (refusal != nullptr)
  {
    EXPECT_EQ(actual, *refusal);
  }
  else
  {
    EXPECT_EQ(actual, StatusCode{Status::BadShutdown});
  }
  bool found{false};
  for (auto detail = actual.shared_detail(); detail; detail = detail->cause)
  {
    if (refusal != nullptr)
    {
      found = found || detail == refusal->shared_detail();
    }
    else
    {
      found = found || detail->code == "AddressSpaceGone";
    }
  }
  EXPECT_TRUE(found) << "the original refusal or owner-loss detail was not preserved in the cause chain";
}

void expect_event_declarations(
  const EventAnswer& outcome, const EventInputs& inputs, bool success, const StatusCode* refusal = nullptr)
{
  EXPECT_EQ(outcome.count, 1u);
  ASSERT_TRUE(outcome.declarations.has_value());
  if (!success)
  {
    expect_event_failure(outcome.declarations->status_code(), refusal);
    return;
  }
  ASSERT_TRUE(outcome.declarations->is_good());
  const auto& declarations = outcome.declarations->value();
  ASSERT_EQ(declarations.size(), inputs.declarations.size() + inputs.nested.size());
  for (std::size_t i = 0; i < inputs.declarations.size(); ++i)
  {
    const auto& branch = declarations[i];
    EXPECT_EQ(branch.nodeId, inputs.declarations[i]);
    EXPECT_EQ(branch.browsePath, (std::vector<QualifiedName>{inputs.names[i]}));
    EXPECT_EQ(branch.nodeClass, NodeClass::Object);
    EXPECT_FALSE(branch.mandatory);
    ASSERT_TRUE(branch.accessor.has_value());
    EXPECT_EQ(branch.accessor->operator->(), inputs.nodes.at(inputs.declarations[i]));
    const auto& leaf = declarations[inputs.declarations.size() + i];
    EXPECT_EQ(leaf.nodeId, inputs.nested[i]);
    EXPECT_EQ(leaf.browsePath,
      (std::vector<QualifiedName>{
        inputs.names[i], QualifiedName{inputs.names[i].namespace_index(), "Leaf"}}));
    EXPECT_EQ(leaf.nodeClass, NodeClass::Variable);
    EXPECT_TRUE(leaf.mandatory);
    EXPECT_EQ(leaf.dataType, NodeId{DataTypeId::Boolean});
    ASSERT_TRUE(leaf.accessor.has_value());
    EXPECT_EQ(leaf.accessor->operator->(), inputs.nodes.at(inputs.nested[i]));
  }
}

void expect_event_model(const EventAnswer& outcome, const EventInputs& inputs, std::size_t index,
  const NodeId& type, bool success, const StatusCode* refusal = nullptr)
{
  EXPECT_EQ(outcome.count, 1u);
  ASSERT_LT(index, outcome.models.size());
  const auto& answer = outcome.models[index];
  ASSERT_TRUE(answer.is_good()) << "a per-type failure replaced the declared per-clause answer";
  ASSERT_EQ(answer.value().size(), 1u);
  const auto& model = answer.value().front();
  if (success)
  {
    EXPECT_TRUE(model.status.is_good());
    ASSERT_TRUE(model.declarationAccessor.has_value());
    NodeId expected = type;
    if (type == inputs.type)
    {
      expected = inputs.nested.front();
    }
    EXPECT_EQ(model.declarationAccessor->operator->(), inputs.nodes.at(expected));
  }
  else
  {
    expect_event_failure(model.status, refusal);
    EXPECT_FALSE(model.declarationAccessor.has_value());
  }
}

void repeat_event_and_check(LifetimeHarness& harness, const EventAnswer& outcome)
{
  const auto calls = harness.held->calls;
  const auto releasedTokens = harness.held->releasedTokens;
  harness.held->good();
  harness.held->bad();
  harness.drain();
  EXPECT_EQ(outcome.count, 1u);
  EXPECT_EQ(harness.held->calls, calls);
  EXPECT_EQ(harness.held->releasedTokens, releasedTokens);
}

enum class RangeRereadStage
{
  VariableLookup,
  References,
  PropertyLookup,
  Value
};

Range reread_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

std::shared_ptr<Subscription> range_subscription(LifetimeHarness& harness, PropertyInputs& inputs)
{
  auto subscription = Subscription::create(
    1, 1'000'000.0, 100, 3, 0, true, 0, harness.context.get_executor(), [](IntegerId) {}, [](IntegerId) {});
  subscription->set_logger(
    Logger{harness.held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "test"});
  std::vector<NodeId> variables;
  for (std::size_t i = 0; i < inputs.variables.size(); ++i)
  {
    variables.push_back(inputs.variables[i].get_node_id());
    harness.nameSpace->values.insert_or_assign(
      inputs.properties[i], DataValue{Variant{reread_range(-10.0, 20.0 + numeric_cast<double>(i))}});
  }
  const auto ids = std::make_shared<std::vector<IntegerId>>();
  SubscriptionTestAccess::post_on_strand(subscription,
    [variables, weakSpace = harness.addressSpace->weak(), ids](auto& guard)
    {
      for (std::size_t i = 0; i < variables.size(); ++i)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->itemToMonitor.node_id() = variables[i];
        item->itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::Value);
        item->deadbandType = DeadbandType::Percent;
        item->deadbandValue = 10.0;
        item->hasEuRange = true;
        item->euRangeLow = 0.0;
        item->euRangeHigh = 100.0 + numeric_cast<double>(i);
        item->accessAddressSpace = weakSpace;
        // The reread uses the server's RequestInfo, not a Session security context or a create request.
        ids->push_back(guard.add_monitored_item(std::move(item)));
      }
    });
  harness.drain();
  inputs.monitoredItems = std::move(*ids);
  EXPECT_EQ(inputs.monitoredItems.size(), inputs.variables.size());
  return subscription;
}

void arm_range_reread(
  LifetimeHarness& harness, const PropertyInputs& inputs, RangeRereadStage stage, std::size_t index = 0)
{
  switch (stage)
  {
  case RangeRereadStage::VariableLookup:
    harness.arm(HeldMember::Lookup, inputs.variables[index].get_node_id());
    return;
  case RangeRereadStage::References:
    harness.arm(HeldMember::References, inputs.variables[index].get_node_id());
    return;
  case RangeRereadStage::PropertyLookup:
    harness.arm(HeldMember::Lookup, inputs.properties[index]);
    return;
  case RangeRereadStage::Value:
    harness.arm(HeldMember::Value, inputs.properties[index]);
    return;
  }
  throw std::logic_error("unknown Subscription EURange reread stage");
}

void start_range_reread(
  LifetimeHarness& harness, const std::shared_ptr<Subscription>& subscription, const PropertyInputs& inputs)
{
  SubscriptionTestAccess::post_on_strand(subscription,
    [ids = inputs.monitoredItems](auto& guard)
    {
      for (const auto id : ids)
      {
        guard.on_semantics_changed(id);
      }
    });
  harness.drain();
}

void expect_reread_ranges(LifetimeHarness& harness, const std::shared_ptr<Subscription>& subscription,
  const PropertyInputs& inputs, const std::vector<std::optional<Range>>& expected)
{
  ASSERT_EQ(expected.size(), inputs.monitoredItems.size());
  SubscriptionTestAccess::post_on_strand(subscription,
    [ids = inputs.monitoredItems, expected](auto& guard)
    {
      for (std::size_t i = 0; i < ids.size(); ++i)
      {
        SCOPED_TRACE(i);
        const auto* item = guard.find_monitored_item(ids[i]);
        ASSERT_NE(item, nullptr);
        EXPECT_EQ(item->euRangeGeneration, 1u);
        EXPECT_EQ(item->hasEuRange, expected[i].has_value());
        if (expected[i])
        {
          EXPECT_DOUBLE_EQ(item->euRangeLow, expected[i]->low());
          EXPECT_DOUBLE_EQ(item->euRangeHigh, expected[i]->high());
        }
      }
    });
  harness.drain();
}

void expect_reread_warnings(const LifetimeHarness& harness, const PropertyInputs& inputs,
  const std::vector<std::optional<StatusCode>>& failures)
{
  ASSERT_EQ(failures.size(), inputs.monitoredItems.size());
  const auto warnings = harness.held->warnings();
  std::size_t expectedCount{0};
  for (std::size_t i = 0; i < failures.size(); ++i)
  {
    SCOPED_TRACE(i);
    std::vector<HeldObservation::Warning> matched;
    for (const auto& warning : warnings)
    {
      const auto item = warning.fields.find("monitored_item_id");
      if (item != warning.fields.end() && item->second == std::to_string(inputs.monitoredItems[i]))
      {
        matched.push_back(warning);
      }
    }
    if (!failures[i])
    {
      EXPECT_TRUE(matched.empty());
      continue;
    }
    ++expectedCount;
    ASSERT_EQ(matched.size(), 1u);
    const auto& warning = matched.front();
    EXPECT_EQ(warning.category, "subscription");
    ASSERT_TRUE(warning.fields.contains("status"));
    ASSERT_TRUE(warning.fields.contains("error"));
    EXPECT_EQ(warning.fields.at("status"), to_string(*failures[i]));
    const auto& error = warning.fields.at("error");
    if (failures[i]->as_status() == Status::BadNodeIdUnknown)
    {
      EXPECT_EQ(warning.message,
        "A PercentDeadband item's EURange is no longer a usable range; the item reports every change");
      EXPECT_NE(error.find("BadNodeIdUnknown"), std::string::npos);
    }
    else
    {
      EXPECT_EQ(warning.message,
        "A PercentDeadband item's EURange could not be read again; the item keeps the range it holds");
      if (failures[i]->as_status() == Status::BadShutdown)
      {
        EXPECT_NE(error.find("AddressSpaceGone"), std::string::npos);
      }
      else
      {
        ASSERT_NE(failures[i]->shared_detail(), nullptr);
        const auto& detail = *failures[i]->shared_detail();
        EXPECT_NE(error.find(detail.code), std::string::npos);
        EXPECT_NE(error.find(detail.summary), std::string::npos);
        EXPECT_NE(error.find(detail.source), std::string::npos);
        for (const auto& fact : detail.context)
        {
          EXPECT_NE(error.find(fact.key), std::string::npos);
          EXPECT_NE(error.find(fact.value), std::string::npos);
        }
      }
    }
  }
  EXPECT_EQ(warnings.size(), expectedCount);
}

void repeat_reread_and_check(
  LifetimeHarness& harness, const std::shared_ptr<Subscription>& subscription, const PropertyInputs& inputs)
{
  const auto calls = harness.held->calls;
  const auto warnings = harness.held->warnings();
  const auto releasedTokens = harness.held->releasedTokens;
  // A changed cache makes a repeated successful/absent application observable, not just repeated warnings.
  std::vector<std::optional<Range>> markers;
  for (std::size_t i = 0; i < inputs.monitoredItems.size(); ++i)
  {
    markers.emplace_back(reread_range(900.0, 1000.0 + numeric_cast<double>(i)));
  }
  SubscriptionTestAccess::post_on_strand(subscription,
    [ids = inputs.monitoredItems, markers](auto& guard)
    {
      for (std::size_t i = 0; i < ids.size(); ++i)
      {
        auto* item = guard.find_monitored_item(ids[i]);
        ASSERT_NE(item, nullptr);
        item->hasEuRange = true;
        item->euRangeLow = markers[i]->low();
        item->euRangeHigh = markers[i]->high();
      }
    });
  harness.drain();
  harness.held->good();
  harness.held->bad();
  harness.drain();
  EXPECT_EQ(harness.held->calls, calls);
  EXPECT_EQ(harness.held->warnings(), warnings);
  EXPECT_EQ(harness.held->releasedTokens, releasedTokens);
  expect_reread_ranges(harness, subscription, inputs, markers);
  subscription->close_async();
  harness.drain();
}

// How the namespace answers the step a nested supertype walk holds.
enum class SupertypeAnswer
{
  None,
  Remote,
  Local,
  Bad,
  Uncertain
};

std::string_view name(SupertypeAnswer value)
{
  switch (value)
  {
  case SupertypeAnswer::None:
    return "None";
  case SupertypeAnswer::Remote:
    return "Remote";
  case SupertypeAnswer::Local:
    return "Local";
  case SupertypeAnswer::Bad:
    return "Bad";
  case SupertypeAnswer::Uncertain:
    return "Uncertain";
  }
  return "unknown";
}

// How the namespace answers the step a nested reference-type walk holds.
enum class ReferenceTypeAnswer
{
  None,
  Match,
  Next,
  Missing,
  Bad,
  Uncertain
};

std::string_view name(ReferenceTypeAnswer value)
{
  switch (value)
  {
  case ReferenceTypeAnswer::None:
    return "None";
  case ReferenceTypeAnswer::Match:
    return "Match";
  case ReferenceTypeAnswer::Next:
    return "Next";
  case ReferenceTypeAnswer::Missing:
    return "Missing";
  case ReferenceTypeAnswer::Bad:
    return "Bad";
  case ReferenceTypeAnswer::Uncertain:
    return "Uncertain";
  }
  return "unknown";
}

// The Property candidates a Property resolution is given, in order, and how each answers.
enum class CandidateOrder
{
  BadThenMatch,
  MatchThenBad,
  UncertainThenBad,
  ThrowingBrowseNameThenBad,
  UncertainThenBadThenMatch,
  ThrowingBrowseNameThenBadThenMatch
};

std::string_view name(CandidateOrder value)
{
  switch (value)
  {
  case CandidateOrder::BadThenMatch:
    return "BadThenMatch";
  case CandidateOrder::MatchThenBad:
    return "MatchThenBad";
  case CandidateOrder::UncertainThenBad:
    return "UncertainThenBad";
  case CandidateOrder::ThrowingBrowseNameThenBad:
    return "ThrowingBrowseNameThenBad";
  case CandidateOrder::UncertainThenBadThenMatch:
    return "UncertainThenBadThenMatch";
  case CandidateOrder::ThrowingBrowseNameThenBadThenMatch:
    return "ThrowingBrowseNameThenBadThenMatch";
  }
  return "unknown";
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-SUPERTYPE-TERMINAL-ANSWERS-RELEASE-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, NestedSupertypeTerminalAnswersReleaseOwners)
{
  for (const auto stage : {TypeStage::FirstReferences, TypeStage::FurtherLookup})
  {
    for (const auto answer : {SupertypeAnswer::None,
           SupertypeAnswer::Remote,
           SupertypeAnswer::Local,
           SupertypeAnswer::Bad,
           SupertypeAnswer::Uncertain})
    {
      if (stage == TypeStage::FurtherLookup &&
          (answer == SupertypeAnswer::None || answer == SupertypeAnswer::Remote))
      {
        continue;  // These References answers terminate before a local lookup exists.
      }
      for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
      {
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(name(answer));
        SCOPED_TRACE(utils::to_underlying(mode));
        StatusCode refusal{unavailable()};
        if (answer == SupertypeAnswer::Uncertain)
        {
          refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
            ErrorDetail::build("NestedSupertypeUncertain",
              "The namespace has no usable supertype answer",
              "NamespaceCallerLifetime")
              .context(ContextKeys::nodeId, NodeId{2, "uncertain-supertype"})};
        }
        LifetimeHarness harness{refusal};
        const auto inputs = type_inputs(harness, TypeOperation::Walk);
        if (answer == SupertypeAnswer::None)
        {
          harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferences{References{}});
        }
        else if (answer == SupertypeAnswer::Remote)
        {
          harness.nameSpace->references.insert_or_assign(inputs.childId,
            NodeReferences{References{std::vector<Reference>{Reference{
              NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{inputs.parent, uint32_t{1}}, false}}}});
        }
        else if (answer == SupertypeAnswer::Bad || answer == SupertypeAnswer::Uncertain)
        {
          if (stage == TypeStage::FirstReferences)
          {
            harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferencesResult{refusal});
          }
          else
          {
            harness.nameSpace->lookups.insert_or_assign(inputs.parent, NodeResult{refusal});
          }
        }
        arm_type(harness, inputs, stage);
        const auto outcome = std::make_shared<AnswerObservation<node_utils::OptionalNodeAccessorResult>>();
        EXPECT_NO_THROW(node_utils::get_super_type_async(*harness.addressSpace,
          inputs.child,
          AnswerObservation<node_utils::OptionalNodeAccessorResult>::callback(outcome)));
        EXPECT_NO_THROW(harness.drain());
        ASSERT_TRUE(harness.held->held);
        EXPECT_EQ(outcome->count, 0u);
        std::array<std::size_t, 3> expectedCalls{0, 1, 0};
        if (stage == TypeStage::FurtherLookup)
        {
          expectedCalls[member_index(HeldMember::Lookup)] = 1;
        }
        EXPECT_EQ(harness.held->calls, expectedCalls);
        if (mode == ChunkMode::BothGone)
        {
          harness.drop_owners();
          // An unfixed strong capture may prevent destructor refusal. Deliver its same copied answer
          // explicitly so owner-expiry failures do not suppress the remaining bounded evidence.
          EXPECT_NO_THROW(harness.held->bad());
        }
        else
        {
          if (mode == ChunkMode::OwnerlessGood)
          {
            harness.drop_space();
          }
          EXPECT_NO_THROW(harness.held->good());
        }
        EXPECT_NO_THROW(harness.drain());
        if (mode == ChunkMode::Retained && stage == TypeStage::FirstReferences &&
            answer == SupertypeAnswer::Local)
        {
          ++expectedCalls[member_index(HeldMember::Lookup)];
        }
        EXPECT_EQ(harness.held->calls, expectedCalls);
        const auto check = [&]
        {
          EXPECT_EQ(outcome->count, 1u);
          ASSERT_TRUE(outcome->answer.has_value());
          const auto& result = *outcome->answer;
          if (mode == ChunkMode::BothGone || answer == SupertypeAnswer::Bad ||
              answer == SupertypeAnswer::Uncertain)
          {
            expect_refusal(result.status_code(), refusal);
          }
          else if (answer == SupertypeAnswer::None)
          {
            ASSERT_TRUE(result.is_good());
            EXPECT_FALSE(result.value().has_value());
          }
          else if (answer == SupertypeAnswer::Remote)
          {
            EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
            ASSERT_NE(result.shared_detail(), nullptr);
            EXPECT_EQ(result.shared_detail()->code, "InvalidNodeClass");
            ASSERT_EQ(result.shared_detail()->context.size(), 1u);
            EXPECT_EQ(result.shared_detail()->context[0].key, ContextKeys::nodeId.value());
            EXPECT_EQ(result.shared_detail()->context[0].value,
              to_string(ExpandedNodeId{inputs.parent, uint32_t{1}}));
          }
          else if (stage == TypeStage::FirstReferences && mode == ChunkMode::OwnerlessGood)
          {
            expect_owner_gone(result.status_code());
          }
          else
          {
            ASSERT_TRUE(result.is_good());
            ASSERT_TRUE(result.value().has_value());
            EXPECT_EQ(result.value()->get_node_id(), inputs.parent);
            EXPECT_EQ(result.value()->get_node_class(), NodeClass::DataType);
          }
        };
        check();
        repeat_and_check(harness, outcome);
        check();
      }
    }
  }

  for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
  {
    SCOPED_TRACE(utils::to_underlying(mode));
    LifetimeHarness harness;
    const auto instance = harness.node("not-a-type", NodeClass::Object);
    harness.arm(HeldMember::References, instance.get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<node_utils::OptionalNodeAccessorResult>>();
    EXPECT_NO_THROW(node_utils::get_super_type_async(*harness.addressSpace,
      instance,
      AnswerObservation<node_utils::OptionalNodeAccessorResult>::callback(outcome)));
    EXPECT_NO_THROW(harness.drain());
    if (mode == ChunkMode::BothGone)
    {
      harness.drop_owners();
    }
    else if (mode == ChunkMode::OwnerlessGood)
    {
      harness.drop_space();
    }
    EXPECT_FALSE(harness.held->held);
    EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 0, 0}));
    EXPECT_EQ(outcome->count, 1u);
    const auto check = [&]
    {
      ASSERT_TRUE(outcome->answer.has_value());
      ASSERT_TRUE(outcome->answer->is_good());
      EXPECT_FALSE(outcome->answer->value().has_value());
    };
    check();
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-SUPERTYPE-OWNER-LOSS-STOPS-PAGING, scope=function)
TEST(NamespaceCallerLifetime, NestedSupertypeOwnerLossStopsPaging)
{
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    const auto inputs = type_inputs(harness, TypeOperation::Walk);
    const ByteString token{std::vector<uint8_t>{21, 70, 4, 19}};
    harness.nameSpace->references.insert_or_assign(
      inputs.childId, reference_to(ReferenceTypeId::HasSubtype, inputs.parent, false, token));
    arm_type(harness, inputs, TypeStage::FirstReferences);
    const auto outcome = std::make_shared<AnswerObservation<node_utils::OptionalNodeAccessorResult>>();
    EXPECT_NO_THROW(node_utils::get_super_type_async(*harness.addressSpace,
      inputs.child,
      AnswerObservation<node_utils::OptionalNodeAccessorResult>::callback(outcome, harness.held)));
    EXPECT_NO_THROW(harness.drain());
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 1, 0}));
    if (!retainOwners)
    {
      harness.drop_space();
    }
    EXPECT_NO_THROW(harness.held->good());
    EXPECT_NO_THROW(harness.drain());
    const auto check = [&]
    {
      EXPECT_EQ(outcome->count, 1u);
      if (retainOwners)
      {
        EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 2, 0}));
        EXPECT_TRUE(harness.held->releasedTokens.empty());
        EXPECT_EQ(outcome->releasedTokensAtCompletion, 0u);
        ASSERT_EQ(harness.held->referenceCalls.size(), 2u);
        const auto& resumed = harness.held->referenceCalls[1];
        EXPECT_EQ(resumed.nodeIds, (std::vector<NodeId>{inputs.childId}));
        ASSERT_EQ(resumed.referenceQueries.size(), 1u);
        EXPECT_EQ(resumed.referenceQueries[0].resumeToken, token);
      }
      else
      {
        EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 1, 0}));
        EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
        EXPECT_EQ(outcome->releasedTokensAtCompletion, 1u);
        EXPECT_EQ(harness.held->referenceCalls.size(), 1u);
      }
      ASSERT_TRUE(outcome->answer.has_value());
      if (retainOwners)
      {
        ASSERT_TRUE(outcome->answer->is_good());
        ASSERT_TRUE(outcome->answer->value().has_value());
        EXPECT_EQ(outcome->answer->value()->get_node_id(), inputs.parent);
      }
      else
      {
        expect_owner_gone(outcome->answer->status_code());
      }
    };
    check();
    const auto released = harness.held->releasedTokens;
    repeat_and_check(harness, outcome);
    EXPECT_EQ(harness.held->releasedTokens, released);
    check();
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-REFERENCE-TYPE-WALK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, NestedReferenceTypeWalkReleasesOwners)
{
  for (const bool cached : {false, true})
  {
    for (const auto stage : {TypeStage::InitialLookup, TypeStage::FirstReferences, TypeStage::FurtherLookup})
    {
      for (const auto answer : {ReferenceTypeAnswer::None,
             ReferenceTypeAnswer::Match,
             ReferenceTypeAnswer::Next,
             ReferenceTypeAnswer::Missing,
             ReferenceTypeAnswer::Bad,
             ReferenceTypeAnswer::Uncertain})
      {
        if ((stage == TypeStage::InitialLookup &&
              (answer == ReferenceTypeAnswer::None || answer == ReferenceTypeAnswer::Match)) ||
            (stage != TypeStage::InitialLookup && answer == ReferenceTypeAnswer::Missing) ||
            (stage == TypeStage::FurtherLookup && answer == ReferenceTypeAnswer::None))
        {
          continue;  // Each terminal answer is supplied only at a stage that can actually receive it.
        }
        for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
        {
          SCOPED_TRACE(cached);
          SCOPED_TRACE(utils::to_underlying(stage));
          SCOPED_TRACE(name(answer));
          SCOPED_TRACE(utils::to_underlying(mode));
          StatusCode refusal{unavailable()};
          if (answer == ReferenceTypeAnswer::Uncertain)
          {
            refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
              ErrorDetail::build("NestedReferenceTypeUncertain",
                "The namespace has no usable reference-type answer",
                "NamespaceCallerLifetime")
                .context(ContextKeys::nodeId, NodeId{2, "uncertain-reference-type"})};
          }
          LifetimeHarness harness{refusal};
          const auto child = harness.node("reference-child", NodeClass::ReferenceType);
          const auto parent = harness.node("reference-parent", NodeClass::ReferenceType).get_node_id();
          const auto target = harness.node("reference-target", NodeClass::ReferenceType).get_node_id();
          TypeInputs inputs{child, child.get_node_id(), parent, target};
          harness.nameSpace->references.insert_or_assign(
            inputs.childId, reference_to(ReferenceTypeId::HasSubtype, inputs.parent, false));
          harness.nameSpace->references.insert_or_assign(
            inputs.parent, reference_to(ReferenceTypeId::HasSubtype, inputs.target, false));
          if (answer == ReferenceTypeAnswer::None)
          {
            harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferences{References{}});
          }
          else if (answer == ReferenceTypeAnswer::Match)
          {
            inputs.target = inputs.parent;
          }
          else if (answer == ReferenceTypeAnswer::Missing)
          {
            // Never create this node: the base namespace returns genuine initial BadNodeIdUnknown.
            inputs.childId = NodeId{harness.index, "missing-reference-type"};
          }
          else if (answer == ReferenceTypeAnswer::Bad || answer == ReferenceTypeAnswer::Uncertain)
          {
            if (stage == TypeStage::FirstReferences)
            {
              harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferencesResult{refusal});
            }
            else
            {
              NodeId refused = inputs.childId;
              if (stage == TypeStage::FurtherLookup)
              {
                refused = inputs.parent;
              }
              harness.nameSpace->lookups.insert_or_assign(refused, NodeResult{refusal});
            }
          }
          arm_type(harness, inputs, stage);
          const auto cache = std::make_shared<node_utils::RefTypeCache>();
          const auto key = std::make_pair(inputs.childId, inputs.target);
          const auto outcome = std::make_shared<AnswerObservation<BoolResult>>();
          if (cached)
          {
            EXPECT_NO_THROW(node_utils::is_ref_of_type_cached_async(EncodingLimits{},
              *harness.addressSpace,
              true,
              inputs.childId,
              inputs.target,
              cache,
              AnswerObservation<BoolResult>::callback(outcome)));
          }
          else
          {
            EXPECT_NO_THROW(node_utils::is_ref_of_type_async(EncodingLimits{},
              *harness.addressSpace,
              true,
              inputs.childId,
              inputs.target,
              AnswerObservation<BoolResult>::callback(outcome)));
          }
          EXPECT_NO_THROW(harness.drain());
          ASSERT_TRUE(harness.held->held);
          EXPECT_EQ(outcome->count, 0u);
          EXPECT_FALSE(cache->lookup(key).has_value());
          std::array<std::size_t, 3> expectedCalls{1, 0, 0};
          if (stage != TypeStage::InitialLookup)
          {
            expectedCalls[member_index(HeldMember::References)] = 1;
          }
          if (stage == TypeStage::FurtherLookup)
          {
            expectedCalls[member_index(HeldMember::Lookup)] = 2;
          }
          EXPECT_EQ(harness.held->calls, expectedCalls);
          if (mode == ChunkMode::BothGone)
          {
            harness.drop_owners();
            EXPECT_NO_THROW(harness.held->bad());
          }
          else
          {
            if (mode == ChunkMode::OwnerlessGood)
            {
              harness.drop_space();
            }
            EXPECT_NO_THROW(harness.held->good());
          }
          EXPECT_NO_THROW(harness.drain());
          if (mode == ChunkMode::Retained && answer == ReferenceTypeAnswer::Next)
          {
            expectedCalls = {3, 2, 0};
          }
          else if (mode == ChunkMode::Retained && answer == ReferenceTypeAnswer::Match)
          {
            expectedCalls = {2, 1, 0};
          }
          EXPECT_EQ(harness.held->calls, expectedCalls);
          const auto check = [&]
          {
            EXPECT_EQ(outcome->count, 1u);
            ASSERT_TRUE(outcome->answer.has_value());
            const auto& result = *outcome->answer;
            const bool receivedRefusal = mode == ChunkMode::BothGone || answer == ReferenceTypeAnswer::Bad ||
                                         answer == ReferenceTypeAnswer::Uncertain;
            const bool missing = answer == ReferenceTypeAnswer::Missing && mode != ChunkMode::BothGone;
            const bool terminalNone = answer == ReferenceTypeAnswer::None && mode != ChunkMode::BothGone;
            const bool terminalMatch = stage == TypeStage::FurtherLookup &&
                                       answer == ReferenceTypeAnswer::Match && mode != ChunkMode::BothGone;
            const bool retainedSuccess = mode == ChunkMode::Retained && !receivedRefusal;
            if (answer == ReferenceTypeAnswer::Uncertain)
            {
              // The walk decides a rule, so it refuses an Uncertain answer instead of passing it on.
              expect_uncertain_refused(result.status_code(), refusal);
            }
            else if (receivedRefusal)
            {
              EXPECT_EQ(result.status_code(), refusal);
              if (stage == TypeStage::InitialLookup)
              {
                expect_refusal(result.status_code(), refusal);
              }
              else
              {
                ASSERT_NE(result.shared_detail(), nullptr);
                EXPECT_EQ(result.shared_detail()->code, "DanglingHasSubtype");
                EXPECT_EQ(result.shared_detail()->innerStatus, refusal.value());
                EXPECT_EQ(result.shared_detail()->cause, refusal.shared_detail());
              }
            }
            else if (missing || terminalNone || terminalMatch || retainedSuccess)
            {
              ASSERT_TRUE(result.is_good());
              const bool matches = !missing && !terminalNone;
              EXPECT_EQ(result.value(), matches);
            }
            else if (stage != TypeStage::FirstReferences)
            {
              expect_owner_gone(result.status_code());
            }
            else
            {
              EXPECT_EQ(result.status_code(), StatusCode{Status::BadShutdown});
              ASSERT_NE(result.shared_detail(), nullptr);
              EXPECT_EQ(result.shared_detail()->code, "DanglingHasSubtype");
              EXPECT_EQ(result.shared_detail()->innerStatus, utils::to_underlying(Status::BadShutdown));
              ASSERT_NE(result.shared_detail()->cause, nullptr);
              EXPECT_EQ(result.shared_detail()->cause->code, "AddressSpaceGone");
            }
            if (cached && !receivedRefusal && (missing || terminalNone || terminalMatch || retainedSuccess))
            {
              EXPECT_EQ(cache->lookup(key), std::optional<bool>{!missing && !terminalNone});
            }
            else
            {
              EXPECT_FALSE(cache->lookup(key).has_value());
            }
          };
          check();
          repeat_and_check(harness, outcome);
          check();
          if (cached && mode == ChunkMode::Retained && answer != ReferenceTypeAnswer::Bad &&
              answer != ReferenceTypeAnswer::Uncertain)
          {
            const auto calls = harness.held->calls;
            const auto repeated = std::make_shared<AnswerObservation<BoolResult>>();
            EXPECT_NO_THROW(node_utils::is_ref_of_type_cached_async(EncodingLimits{},
              *harness.addressSpace,
              true,
              inputs.childId,
              inputs.target,
              cache,
              AnswerObservation<BoolResult>::callback(repeated)));
            EXPECT_NO_THROW(harness.drain());
            EXPECT_EQ(repeated->count, 1u);
            EXPECT_EQ(harness.held->calls, calls);
            const auto checkRepeated = [&]
            {
              ASSERT_TRUE(repeated->answer.has_value());
              ASSERT_TRUE(repeated->answer->is_good());
              EXPECT_EQ(repeated->answer->value(),
                answer != ReferenceTypeAnswer::Missing && answer != ReferenceTypeAnswer::None);
            };
            checkRepeated();
          }
        }
      }
    }

    for (const bool exactMatch : {false, true})
    {
      for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
      {
        SCOPED_TRACE(cached);
        SCOPED_TRACE(exactMatch);
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        const auto child = harness.node("reference-control", NodeClass::ReferenceType);
        const auto childId = child.get_node_id();
        NodeId target{ReferenceTypeId::Aggregates};
        if (exactMatch)
        {
          target = childId;
        }
        harness.arm(HeldMember::Lookup, childId);
        const auto cache = std::make_shared<node_utils::RefTypeCache>();
        const auto outcome = std::make_shared<AnswerObservation<BoolResult>>();
        if (cached)
        {
          EXPECT_NO_THROW(node_utils::is_ref_of_type_cached_async(EncodingLimits{},
            *harness.addressSpace,
            exactMatch,
            childId,
            target,
            cache,
            AnswerObservation<BoolResult>::callback(outcome)));
        }
        else
        {
          EXPECT_NO_THROW(node_utils::is_ref_of_type_async(EncodingLimits{},
            *harness.addressSpace,
            exactMatch,
            childId,
            target,
            AnswerObservation<BoolResult>::callback(outcome)));
        }
        EXPECT_NO_THROW(harness.drain());
        if (mode == ChunkMode::BothGone)
        {
          harness.drop_owners();
        }
        else if (mode == ChunkMode::OwnerlessGood)
        {
          harness.drop_space();
        }
        EXPECT_FALSE(harness.held->held);
        EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 0, 0}));
        EXPECT_EQ(outcome->count, 1u);
        const auto check = [&]
        {
          ASSERT_TRUE(outcome->answer.has_value());
          ASSERT_TRUE(outcome->answer->is_good());
          EXPECT_EQ(outcome->answer->value(), exactMatch);
        };
        check();
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-PROPERTY-CANDIDATE-PRIORITY-RETAINS-RECEIVED-FAILURES, scope=function)
TEST(NamespaceCallerLifetime, PropertyCandidatePriorityRetainsReceivedFailures)
{
  for (const bool euRange : {false, true})
  {
    for (const auto order : {CandidateOrder::BadThenMatch,
           CandidateOrder::MatchThenBad,
           CandidateOrder::UncertainThenBad,
           CandidateOrder::ThrowingBrowseNameThenBad,
           CandidateOrder::UncertainThenBadThenMatch,
           CandidateOrder::ThrowingBrowseNameThenBadThenMatch})
    {
      SCOPED_TRACE(euRange);
      SCOPED_TRACE(name(order));
      LifetimeHarness harness;
      ua::test::TestLogSink log;
      harness.addressSpace->set_logger(log.logger());
      std::string browseName{"AllowNulls"};
      if (euRange)
      {
        browseName = "EURange";
      }
      const auto inputs = properties(harness, browseName);
      const auto first = harness.node("first-candidate", NodeClass::Variable);
      const auto later = harness.node("later-candidate", NodeClass::Variable);
      const auto firstId = first.get_node_id();
      const auto laterId = later.get_node_id();
      const StatusCode firstBad{Status::BadCommunicationError,
        ErrorDetail::build(
          "FirstPropertyLookupRefusal", "The first candidate lookup was refused", "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, firstId)};
      const StatusCode firstUncertain{Status::UncertainNoCommunicationLastUsableValue,
        ErrorDetail::build("FirstPropertyLookupUncertain",
          "The first candidate lookup carries no Node",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, firstId)};
      const StatusCode firstInspection{Status::BadResourceUnavailable,
        ErrorDetail::build("FirstPropertyBrowseNameRefusal",
          "The first candidate's BrowseName could not be inspected",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, firstId)};
      const StatusCode laterBad{Status::BadUserAccessDenied,
        ErrorDetail::build("LaterPropertyLookupRefusal",
          "A later candidate lookup was refused independently",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, laterId)};
      harness.nameSpace->lookups.insert_or_assign(laterId, NodeResult{laterBad});
      if (order == CandidateOrder::BadThenMatch || order == CandidateOrder::MatchThenBad)
      {
        harness.nameSpace->lookups.insert_or_assign(firstId, NodeResult{firstBad});
      }
      else if (order == CandidateOrder::UncertainThenBad ||
               order == CandidateOrder::UncertainThenBadThenMatch)
      {
        harness.nameSpace->lookups.insert_or_assign(firstId, NodeResult{firstUncertain});
      }
      else
      {
        const auto scripted = std::make_shared<ua::test::ScriptedNode>();
        scripted->answer_attribute(AttributeId::NodeId, Variant{firstId});
        scripted->answer_attribute(
          AttributeId::NodeClass, Variant{numeric_cast<int32_t>(utils::to_underlying(NodeClass::Variable))});
        scripted->refuse_attribute(AttributeId::BrowseName, firstInspection);
        harness.nameSpace->lookups.insert_or_assign(firstId, NodeResult{scripted});
      }
      std::vector<NodeId> candidates;
      if (order == CandidateOrder::BadThenMatch)
      {
        candidates = {firstId, inputs.properties[0]};
      }
      else if (order == CandidateOrder::MatchThenBad)
      {
        candidates = {inputs.properties[0], firstId};
      }
      else
      {
        candidates = {firstId, laterId};
        if (order == CandidateOrder::UncertainThenBadThenMatch ||
            order == CandidateOrder::ThrowingBrowseNameThenBadThenMatch)
        {
          candidates.push_back(inputs.properties[0]);
        }
      }
      std::vector<Reference> references;
      for (const auto& candidate : candidates)
      {
        references.emplace_back(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{candidate}, true);
      }
      harness.nameSpace->references.insert_or_assign(
        inputs.variables[0].get_node_id(), NodeReferences{References{std::move(references)}});
      DataValue expectedValue{Variant{false}};
      if (euRange)
      {
        expectedValue = DataValue{Variant{reread_range(-12.5, 74.25)}};
      }
      harness.nameSpace->values.insert_or_assign(inputs.properties[0], expectedValue);
      harness.arm(HeldMember::Lookup, candidates.front());
      const auto nulls = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
      const auto ranges = std::make_shared<AnswerObservation<EuRangeAnswer>>();
      if (euRange)
      {
        EuRangeResolver::resolve_async(*harness.addressSpace,
          RequestInfo{},
          inputs.variables,
          std::nullopt,
          AnswerObservation<EuRangeAnswer>::callback(ranges));
      }
      else
      {
        AllowNullsBatch::resolve_async(*harness.addressSpace,
          RequestInfo{},
          inputs.variables,
          std::nullopt,
          std::nullopt,
          AnswerObservation<AllowNullsAnswer>::callback(nulls));
      }
      harness.drain();
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(nulls->count + ranges->count, 0u);
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 0}));
      harness.held->good();
      harness.drain();
      const bool matched = order == CandidateOrder::BadThenMatch || order == CandidateOrder::MatchThenBad ||
                           order == CandidateOrder::UncertainThenBadThenMatch ||
                           order == CandidateOrder::ThrowingBrowseNameThenBadThenMatch;
      const auto check = [&]
      {
        EXPECT_EQ(nulls->count + ranges->count, 1u);
        std::array<std::size_t, 3> expectedCalls{1, 1, 0};
        std::vector<NodeId> expectedReads;
        if (matched)
        {
          expectedCalls[member_index(HeldMember::Value)] = 1;
          expectedReads.push_back(inputs.properties[0]);
        }
        EXPECT_EQ(harness.held->calls, expectedCalls);
        EXPECT_EQ(harness.held->valueReads, expectedReads);
        StatusCode actual;
        if (euRange)
        {
          ASSERT_EQ(ranges->count, 1u);
          ASSERT_TRUE(ranges->answer.has_value());
          ASSERT_EQ(ranges->answer->size(), 1u);
          const auto& answer = ranges->answer->front();
          actual = answer.value.status_code();
          if (matched)
          {
            EXPECT_EQ(answer.property, inputs.properties[0]);
            ASSERT_TRUE(answer.value.is_good());
            EXPECT_EQ(answer.value.value(), expectedValue);
          }
          else
          {
            EXPECT_TRUE(answer.property.is_null());
            EXPECT_TRUE(answer.value.is_bad());
          }
        }
        else
        {
          ASSERT_EQ(nulls->count, 1u);
          ASSERT_TRUE(nulls->answer.has_value());
          ASSERT_EQ(nulls->answer->size(), 1u);
          const auto& answer = nulls->answer->front();
          actual = answer.status;
          if (matched)
          {
            EXPECT_EQ(answer.allowed, false);
          }
          else
          {
            EXPECT_FALSE(answer.allowed.has_value());
          }
        }
        if (matched)
        {
          EXPECT_TRUE(actual.is_good());
        }
        else if (order == CandidateOrder::UncertainThenBad)
        {
          EXPECT_EQ(actual, StatusCode{Status::BadInternalError});
          ASSERT_NE(actual.shared_detail(), nullptr);
          const auto& detail = *actual.shared_detail();
          EXPECT_EQ(detail.code, "LookupAnswerUncertain");
          EXPECT_EQ(detail.innerStatus, firstUncertain.value());
          EXPECT_EQ(detail.cause, firstUncertain.shared_detail());
          bool namesTarget{false};
          for (const auto& fact : detail.context)
          {
            if (fact.key == ContextKeys::nodeId.value())
            {
              EXPECT_EQ(fact.value, to_string(firstId));
              namesTarget = true;
            }
          }
          EXPECT_TRUE(namesTarget);
        }
        else
        {
          expect_refusal(actual, firstInspection);
        }
        EXPECT_EQ(log.count(LogLevel::Warning), 0u);
      };
      check();
      if (euRange)
      {
        repeat_and_check(harness, ranges);
      }
      else
      {
        repeat_and_check(harness, nulls);
      }
      check();
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-BROWSE-LIMIT-SNAPSHOT-IS-NONOWNING, scope=function)
TEST(NamespaceCallerLifetime, BrowseLimitSnapshotIsNonowning)
{
  static_assert(noexcept(ua::detail::NodeAccessorRoute::browse_limit(WeakAddressSpace{})));
  {
    LifetimeHarness harness;
    const auto calls = harness.held->calls;
    const auto recordedCalls = harness.nameSpace->calls().size();
    EXPECT_EQ(ua::detail::NodeAccessorRoute::browse_limit(WeakAddressSpace{}), std::nullopt);
    EXPECT_EQ(harness.held->calls, calls);
    EXPECT_EQ(harness.nameSpace->calls().size(), recordedCalls);
  }
  for (std::size_t configuration = 0; configuration < 3; ++configuration)
  {
    SCOPED_TRACE(configuration);
    LifetimeHarness harness;
    std::optional<uint32_t> expected;
    if (configuration != 0)
    {
      ServiceOperationLimits limits;
      limits.maxNodesPerRead = 7;
      limits.maxNodesPerBrowse = std::nullopt;
      if (configuration == 2)
      {
        limits.maxNodesPerBrowse = 1;
        expected = 1;
      }
      harness.addressSpace->set_operation_limits(limits);
    }
    const auto weakSpace = harness.addressSpace->weak();
    const std::weak_ptr<Namespace> weakNamespace{harness.nameSpace};
    const auto calls = harness.held->calls;
    const auto recordedCalls = harness.nameSpace->calls().size();
    const auto snapshot = ua::detail::NodeAccessorRoute::browse_limit(weakSpace);
    EXPECT_EQ(snapshot, expected);
    EXPECT_EQ(harness.held->calls, calls);
    EXPECT_EQ(harness.nameSpace->calls().size(), recordedCalls);
    harness.drop_owners();
    EXPECT_FALSE(weakSpace.lock().has_value());
    EXPECT_TRUE(weakNamespace.expired());
    EXPECT_EQ(snapshot, expected) << "the scalar snapshot remains usable without either owner";
    EXPECT_EQ(ua::detail::NodeAccessorRoute::browse_limit(weakSpace), std::nullopt);
    EXPECT_EQ(harness.held->calls, calls);
    EXPECT_TRUE(harness.held->referenceCalls.empty());
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-SUBSCRIPTION-RANGE-REREAD-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldSubscriptionRangeRereadReleasesOwners)
{
  const StatusCode ownerGone{Status::BadShutdown};
  for (const auto stage : {RangeRereadStage::VariableLookup,
         RangeRereadStage::References,
         RangeRereadStage::PropertyLookup,
         RangeRereadStage::Value})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      auto inputs = properties(harness, "EURange");
      const auto subscription = range_subscription(harness, inputs);
      arm_range_reread(harness, inputs, stage);
      start_range_reread(harness, subscription, inputs);
      ASSERT_TRUE(harness.held->held);
      expect_reread_ranges(harness, subscription, inputs, {reread_range(0.0, 100.0)});
      EXPECT_TRUE(harness.held->warnings().empty());
      complete_first_chunk(harness, mode);
      const bool updated =
        mode == ChunkMode::Retained || (mode == ChunkMode::OwnerlessGood && stage == RangeRereadStage::Value);
      std::optional<Range> expected{reread_range(0.0, 100.0)};
      std::optional<StatusCode> failure{ownerGone};
      if (updated)
      {
        expected = reread_range(-10.0, 20.0);
        failure.reset();
      }
      else if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
      {
        failure = harness.refusal;
      }
      expect_reread_ranges(harness, subscription, inputs, {expected});
      expect_reread_warnings(harness, inputs, {failure});
      repeat_reread_and_check(harness, subscription, inputs);
    }
  }

  // Earlier completed and failed items must not be revisited when a separate pending reread loses AS.
  for (const auto stage : {RangeRereadStage::VariableLookup,
         RangeRereadStage::References,
         RangeRereadStage::PropertyLookup,
         RangeRereadStage::Value})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      auto inputs = properties(harness, "EURange", 3);
      const auto subscription = range_subscription(harness, inputs);
      const StatusCode siblingFailure{Status::BadCommunicationError,
        ErrorDetail::build("EarlierRangeRereadRefusal",
          "An independent item's EURange read was refused",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, inputs.properties[1])};
      harness.nameSpace->values.insert_or_assign(inputs.properties[1], siblingFailure);
      auto previous = inputs;
      previous.variables.erase(previous.variables.begin() + 2, previous.variables.end());
      previous.properties.resize(2);
      previous.monitoredItems.resize(2);
      start_range_reread(harness, subscription, previous);
      expect_reread_ranges(
        harness, subscription, previous, {reread_range(-10.0, 20.0), reread_range(0.0, 101.0)});
      expect_reread_warnings(harness, previous, {std::nullopt, siblingFailure});
      arm_range_reread(harness, inputs, stage, 2);
      PropertyInputs pending;
      pending.monitoredItems = {inputs.monitoredItems[2]};
      start_range_reread(harness, subscription, pending);
      ASSERT_TRUE(harness.held->held);
      complete_first_chunk(harness, mode);
      const bool updated =
        mode == ChunkMode::Retained || (mode == ChunkMode::OwnerlessGood && stage == RangeRereadStage::Value);
      std::optional<Range> expected{reread_range(0.0, 102.0)};
      std::optional<StatusCode> failure{ownerGone};
      if (updated)
      {
        expected = reread_range(-10.0, 22.0);
        failure.reset();
      }
      else if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
      {
        failure = harness.refusal;
      }
      expect_reread_ranges(
        harness, subscription, inputs, {reread_range(-10.0, 20.0), reread_range(0.0, 101.0), expected});
      expect_reread_warnings(harness, inputs, {std::nullopt, siblingFailure, failure});
      repeat_reread_and_check(harness, subscription, inputs);
    }
  }

  // Good and rich-Bad value chunks received in this flush survive the final held chunk's answer.
  for (const auto mode :
    {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
  {
    SCOPED_TRACE(utils::to_underlying(mode));
    LifetimeHarness harness;
    ServiceOperationLimits limits;
    limits.maxNodesPerRead = 1;
    limits.maxNodesPerBrowse = 1;
    harness.addressSpace->set_operation_limits(limits);
    auto inputs = properties(harness, "EURange", 3);
    const auto subscription = range_subscription(harness, inputs);
    const StatusCode siblingFailure{Status::BadCommunicationError,
      ErrorDetail::build(
        "ReceivedRangeChunkRefusal", "A sibling EURange value chunk was refused", "NamespaceCallerLifetime")
        .context(ContextKeys::nodeId, inputs.properties[1])};
    harness.nameSpace->values.insert_or_assign(inputs.properties[1], siblingFailure);
    arm_range_reread(harness, inputs, RangeRereadStage::Value, 2);
    start_range_reread(harness, subscription, inputs);
    ASSERT_TRUE(harness.held->held);
    ASSERT_EQ(harness.held->calls[member_index(HeldMember::Value)], 3u);
    EXPECT_TRUE(harness.held->warnings().empty());
    complete_first_chunk(harness, mode);
    std::optional<Range> expected{reread_range(-10.0, 22.0)};
    std::optional<StatusCode> failure;
    if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
    {
      expected = reread_range(0.0, 102.0);
      failure = harness.refusal;
    }
    expect_reread_ranges(
      harness, subscription, inputs, {reread_range(-10.0, 20.0), reread_range(0.0, 101.0), expected});
    expect_reread_warnings(harness, inputs, {std::nullopt, siblingFailure, failure});
    repeat_reread_and_check(harness, subscription, inputs);
  }

  // An empty References answer and a resolved nonmatching Property establish absence terminally.
  for (const auto stage : {RangeRereadStage::References, RangeRereadStage::PropertyLookup})
  {
    for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      auto inputs = properties(harness, "EURange");
      const auto subscription = range_subscription(harness, inputs);
      if (stage == RangeRereadStage::References)
      {
        harness.nameSpace->references.insert_or_assign(inputs.variables[0].get_node_id(), NodeReferences{});
      }
      else
      {
        const auto found = std::make_shared<AnswerObservation<NodeAccessorResult>>();
        harness.addressSpace->find_node_async(
          inputs.properties[0], AnswerObservation<NodeAccessorResult>::callback(found));
        harness.drain();
        ASSERT_TRUE(found->answer.has_value());
        ASSERT_TRUE(found->answer->is_good());
        found->answer->value().set_browse_name(QualifiedName{0, "OtherProperty"});
      }
      arm_range_reread(harness, inputs, stage);
      start_range_reread(harness, subscription, inputs);
      ASSERT_TRUE(harness.held->held);
      complete_first_chunk(harness, mode);
      expect_reread_ranges(harness, subscription, inputs, {std::nullopt});
      expect_reread_warnings(harness, inputs, {StatusCode{Status::BadNodeIdUnknown}});
      repeat_reread_and_check(harness, subscription, inputs);
    }
  }

  // The first, not last, same-namespace chunk is retained for each of the four reread stages.
  for (const auto stage : {RangeRereadStage::VariableLookup,
         RangeRereadStage::References,
         RangeRereadStage::PropertyLookup,
         RangeRereadStage::Value})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      ServiceOperationLimits limits;
      limits.maxNodesPerRead = 1;
      limits.maxNodesPerBrowse = 1;
      harness.addressSpace->set_operation_limits(limits);
      auto inputs = properties(harness, "EURange", 3);
      const auto subscription = range_subscription(harness, inputs);
      arm_range_reread(harness, inputs, stage);
      start_range_reread(harness, subscription, inputs);
      ASSERT_TRUE(harness.held->held);
      std::size_t expectedLookupCalls{1};
      if (stage == RangeRereadStage::PropertyLookup)
      {
        expectedLookupCalls = 4;  // Three Variable chunks completed before the first Property chunk.
      }
      if (stage == RangeRereadStage::VariableLookup || stage == RangeRereadStage::PropertyLookup)
      {
        ASSERT_EQ(harness.held->calls[member_index(HeldMember::Lookup)], expectedLookupCalls);
      }
      else if (stage == RangeRereadStage::References)
      {
        ASSERT_EQ(harness.held->calls[member_index(HeldMember::References)], 1u);
        ASSERT_EQ(harness.held->referenceCalls.size(), 1u);
        const auto& initial = harness.held->referenceCalls.front();
        EXPECT_EQ(initial.referenceQueries.size(), 1u)
          << "the configured first References chunk issued sibling rereads too";
        EXPECT_EQ(initial.nodeIds, (std::vector<NodeId>{inputs.variables[0].get_node_id()}));
      }
      else
      {
        ASSERT_EQ(harness.held->calls[member_index(HeldMember::Value)], 1u);
      }
      complete_first_chunk(harness, mode);
      std::vector<std::optional<Range>> expected;
      std::vector<std::optional<StatusCode>> failures;
      for (std::size_t i = 0; i < inputs.monitoredItems.size(); ++i)
      {
        const bool updated = mode == ChunkMode::Retained ||
                             (i == 0 && mode == ChunkMode::OwnerlessGood && stage == RangeRereadStage::Value);
        if (updated)
        {
          expected.emplace_back(reread_range(-10.0, 20.0 + numeric_cast<double>(i)));
          failures.emplace_back(std::nullopt);
        }
        else
        {
          expected.emplace_back(reread_range(0.0, 100.0 + numeric_cast<double>(i)));
          if (i == 0 && (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad))
          {
            failures.emplace_back(harness.refusal);
          }
          else
          {
            failures.emplace_back(ownerGone);
          }
        }
      }
      expect_reread_ranges(harness, subscription, inputs, expected);
      expect_reread_warnings(harness, inputs, failures);
      repeat_reread_and_check(harness, subscription, inputs);
    }
  }

  for (const std::size_t count : {1u, 3u})
  {
    SCOPED_TRACE(count);
    LifetimeHarness harness;
    ServiceOperationLimits limits;
    limits.maxNodesPerRead = 1;
    limits.maxNodesPerBrowse = 1;
    harness.addressSpace->set_operation_limits(limits);
    auto inputs = properties(harness, "EURange", count);
    const auto subscription = range_subscription(harness, inputs);
    const ByteString token{std::vector<uint8_t>{11, 12, 13}};
    harness.nameSpace->references.at(inputs.variables[0].get_node_id()).value().resumeToken = token;
    arm_range_reread(harness, inputs, RangeRereadStage::References);
    start_range_reread(harness, subscription, inputs);
    ASSERT_TRUE(harness.held->held);
    complete_first_chunk(harness, ChunkMode::OwnerlessPage);
    std::vector<std::optional<Range>> expected;
    std::vector<std::optional<StatusCode>> failures;
    for (std::size_t i = 0; i < count; ++i)
    {
      expected.emplace_back(reread_range(0.0, 100.0 + numeric_cast<double>(i)));
      failures.emplace_back(ownerGone);
    }
    expect_reread_ranges(harness, subscription, inputs, expected);
    expect_reread_warnings(harness, inputs, failures);
    EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
    repeat_reread_and_check(harness, subscription, inputs);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-EVENT-TYPE-MODEL-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldEventTypeModelReleasesOwners)
{
  for (const bool models : {false, true})
  {
    for (const auto stage : {EventStage::TypeLookup,
           EventStage::TypeReferences,
           EventStage::SupertypeLookup,
           EventStage::SupertypeReferences,
           EventStage::AggregateLookup,
           EventStage::AggregateReferences,
           EventStage::AggregateSupertypeLookup,
           EventStage::AggregateSupertypeReferences,
           EventStage::DeclarationLookup,
           EventStage::DeclarationReferences,
           EventStage::NestedLookup,
           EventStage::NestedReferences})
    {
      for (const auto mode :
        {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
      {
        SCOPED_TRACE(models);
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        const auto inputs = event_inputs(harness);
        const auto [member, nodeId] = event_stage(inputs, stage);
        harness.arm(member, nodeId);
        const auto outcome = std::make_shared<EventAnswer>();
        start_event(harness, inputs, models, outcome, {inputs.type, inputs.type});
        ASSERT_TRUE(harness.held->held);
        EXPECT_EQ(outcome->count, 0u);
        complete_first_chunk(harness, mode);
        const bool success = mode == ChunkMode::Retained ||
                             (mode == ChunkMode::OwnerlessGood && stage == EventStage::NestedReferences);
        const StatusCode* refusal = nullptr;
        if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
        {
          refusal = &harness.refusal;
        }
        if (models)
        {
          ASSERT_EQ(outcome->models.size(), 2u);
          expect_event_model(*outcome, inputs, 0, inputs.type, success, refusal);
          expect_event_model(*outcome, inputs, 1, inputs.type, success, refusal);
        }
        else
        {
          expect_event_declarations(*outcome, inputs, success, refusal);
        }
        EXPECT_TRUE(harness.held->releasedTokens.empty());
        repeat_event_and_check(harness, *outcome);
      }
    }
  }

  // A successful page still requires a new namespace operation; its token remains ours until that call.
  for (const bool models : {false, true})
  {
    for (const auto stage :
      {EventStage::TypeReferences, EventStage::AggregateReferences, EventStage::NestedReferences})
    {
      SCOPED_TRACE(models);
      SCOPED_TRACE(utils::to_underlying(stage));
      LifetimeHarness harness;
      const auto inputs = event_inputs(harness);
      const auto [member, nodeId] = event_stage(inputs, stage);
      const ByteString token{std::vector<uint8_t>{8, 9, 10}};
      harness.nameSpace->references.at(nodeId).value().resumeToken = token;
      harness.arm(member, nodeId);
      const auto outcome = std::make_shared<EventAnswer>();
      start_event(harness, inputs, models, outcome, {inputs.type, inputs.type});
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(outcome->count, 0u);
      complete_first_chunk(harness, ChunkMode::OwnerlessPage);
      if (models)
      {
        ASSERT_EQ(outcome->models.size(), 2u);
        expect_event_model(*outcome, inputs, 0, inputs.type, false);
        expect_event_model(*outcome, inputs, 1, inputs.type, false);
      }
      else
      {
        expect_event_declarations(*outcome, inputs, false);
      }
      EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
      repeat_event_and_check(harness, *outcome);
    }
  }

  // These siblings finish before the pending type reaches either retained declaration stage.
  for (const auto stage : {EventStage::DeclarationLookup, EventStage::NestedReferences})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      const auto inputs = event_inputs(harness);
      const StatusCode failedTypeRefusal{Status::BadUserAccessDenied,
        ErrorDetail::build("CompletedEventTypeRefusal",
          "An independent EventType References read was refused",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, inputs.failedType)};
      harness.nameSpace->references.insert_or_assign(inputs.failedType, failedTypeRefusal);
      const auto [member, nodeId] = event_stage(inputs, stage);
      harness.arm(member, nodeId);
      const auto outcome = std::make_shared<EventAnswer>();
      start_event(
        harness, inputs, true, outcome, {inputs.completedType, inputs.failedType, inputs.type, inputs.type});
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(outcome->count, 0u);
      complete_first_chunk(harness, mode);
      ASSERT_EQ(outcome->models.size(), 4u);
      expect_event_model(*outcome, inputs, 0, inputs.completedType, true);
      expect_event_model(*outcome, inputs, 1, inputs.failedType, false, &failedTypeRefusal);
      const bool success = mode == ChunkMode::Retained ||
                           (mode == ChunkMode::OwnerlessGood && stage == EventStage::NestedReferences);
      const StatusCode* refusal = nullptr;
      if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
      {
        refusal = &harness.refusal;
      }
      expect_event_model(*outcome, inputs, 2, inputs.type, success, refusal);
      expect_event_model(*outcome, inputs, 3, inputs.type, success, refusal);
      repeat_event_and_check(harness, *outcome);
    }
  }

  // Hold the first of three same-namespace type chunks, not a terminal chunk.
  for (const auto stage : {EventStage::TypeLookup, EventStage::TypeReferences})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      ServiceOperationLimits limits;
      limits.maxNodesPerRead = 1;
      limits.maxNodesPerBrowse = 1;
      harness.addressSpace->set_operation_limits(limits);
      const auto inputs = event_inputs(harness);
      const auto [member, nodeId] = event_stage(inputs, stage);
      harness.arm(member, nodeId);
      const auto outcome = std::make_shared<EventAnswer>();
      const std::vector<NodeId> types{inputs.type, inputs.completedType, inputs.failedType};
      start_event(harness, inputs, true, outcome, types);
      ASSERT_TRUE(harness.held->held);
      ASSERT_EQ(harness.held->calls[member_index(member)], 1u);
      EXPECT_EQ(outcome->count, 0u);
      complete_first_chunk(harness, mode);
      ASSERT_EQ(outcome->models.size(), types.size());
      for (std::size_t i = 0; i < types.size(); ++i)
      {
        SCOPED_TRACE(i);
        const StatusCode* refusal = nullptr;
        if (i == 0 && (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad))
        {
          refusal = &harness.refusal;
        }
        expect_event_model(*outcome, inputs, i, types[i], mode == ChunkMode::Retained, refusal);
      }
      repeat_event_and_check(harness, *outcome);
    }
  }

  // Declaration lookup and References chunks are reached by both public interfaces.
  for (const bool models : {false, true})
  {
    for (const auto stage : {EventStage::DeclarationLookup, EventStage::DeclarationReferences})
    {
      for (const auto mode :
        {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
      {
        SCOPED_TRACE(models);
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        ServiceOperationLimits limits;
        limits.maxNodesPerRead = 1;
        limits.maxNodesPerBrowse = 1;
        harness.addressSpace->set_operation_limits(limits);
        const auto inputs = event_inputs(harness, 3);
        const auto [member, nodeId] = event_stage(inputs, stage);
        harness.arm(member, nodeId);
        const auto outcome = std::make_shared<EventAnswer>();
        start_event(harness, inputs, models, outcome, {inputs.type, inputs.type});
        ASSERT_TRUE(harness.held->held);
        EXPECT_EQ(outcome->count, 0u);
        complete_first_chunk(harness, mode);
        const StatusCode* refusal = nullptr;
        if (mode == ChunkMode::BothGone || mode == ChunkMode::OwnerlessBad)
        {
          refusal = &harness.refusal;
        }
        if (models)
        {
          ASSERT_EQ(outcome->models.size(), 2u);
          expect_event_model(*outcome, inputs, 0, inputs.type, mode == ChunkMode::Retained, refusal);
          expect_event_model(*outcome, inputs, 1, inputs.type, mode == ChunkMode::Retained, refusal);
        }
        else
        {
          expect_event_declarations(*outcome, inputs, mode == ChunkMode::Retained, refusal);
        }
        repeat_event_and_check(harness, *outcome);
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-PROPERTY-INSPECTION-FAILURE-IS-ITEM-LOCAL, scope=function)
TEST(NamespaceCallerLifetime, PropertyInspectionFailureIsItemLocal)
{
  for (const bool euRange : {false, true})
  {
    for (const auto inspection : {Status::BadResourceUnavailable, Status::BadNodeIdUnknown, Status::Good})
    {
      SCOPED_TRACE(euRange);
      SCOPED_TRACE(utils::to_underlying(inspection));
      LifetimeHarness harness;
      const std::string browseName = euRange ? "EURange" : "AllowNulls";
      const auto inputs = properties(harness, browseName, 4);
      const StatusCode inspectionFailure{inspection,
        ErrorDetail::build("PropertyClassRefusal",
          "The matching Property's NodeClass could not be read",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, inputs.properties[0])};
      const StatusCode candidateFailure{Status::BadUserAccessDenied,
        ErrorDetail::build("CandidateLookupRefusal",
          "Another Variable's candidate lookup was refused",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, inputs.properties[1])};
      const auto scriptedProperty = std::make_shared<ua::test::ScriptedNode>();
      const auto description = NodeDescription::variable(
        inputs.properties[0], QualifiedName{0, browseName}, NodeId{DataTypeId::Boolean});
      scriptedProperty->answer_attribute(AttributeId::NodeId, Variant{description.node_id()});
      scriptedProperty->answer_attribute(AttributeId::BrowseName, Variant{description.browse_name()});
      scriptedProperty->answer_attribute(AttributeId::NodeClass,
        Variant{numeric_cast<int32_t>(utils::to_underlying(description.node_class()))});
      if (inspection != Status::Good)
      {
        // The read that matches the BrowseName answers; the next one, which inspects the NodeClass, fails.
        scriptedProperty->refuse_attributes_after(1, inspectionFailure);
      }
      harness.nameSpace->lookups.insert_or_assign(inputs.properties[0], NodeResult{scriptedProperty});
      harness.nameSpace->answer_lookup_of(inputs.properties[1], candidateFailure);
      harness.nameSpace->values.insert_or_assign(inputs.properties[2], DataValue{Variant{false}});
      harness.nameSpace->references.insert_or_assign(
        inputs.variables[3].get_node_id(), NodeReferencesResult{NodeReferences{}});
      harness.arm(HeldMember::Lookup, inputs.properties[0]);
      const auto nulls = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
      const auto ranges = std::make_shared<AnswerObservation<EuRangeAnswer>>();
      if (euRange)
      {
        EuRangeResolver::resolve_async(*harness.addressSpace,
          RequestInfo{},
          inputs.variables,
          std::nullopt,
          AnswerObservation<EuRangeAnswer>::callback(ranges));
      }
      else
      {
        AllowNullsBatch::resolve_async(*harness.addressSpace,
          RequestInfo{},
          inputs.variables,
          std::nullopt,
          std::nullopt,
          AnswerObservation<AllowNullsAnswer>::callback(nulls));
      }
      harness.drain();
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 0}));
      EXPECT_EQ(nulls->count + ranges->count, 0u);
      if (inspection == Status::Good)
      {
        const NodeDescription scripted = scriptedProperty->attributes();
        EXPECT_EQ(scripted.browse_name(), description.browse_name());
      }
      harness.held->good();
      harness.drain();
      const auto check = [&]
      {
        EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 1}));
        std::vector<NodeId> expectedValueReads;
        if (inspection == Status::Good)
        {
          expectedValueReads.push_back(inputs.properties[0]);
        }
        expectedValueReads.push_back(inputs.properties[2]);
        EXPECT_EQ(harness.held->valueReads, expectedValueReads);
        if (euRange)
        {
          ASSERT_EQ(ranges->count, 1u);
          ASSERT_TRUE(ranges->answer);
          ASSERT_EQ(ranges->answer->size(), 4u);
          const auto& answers = *ranges->answer;
          EXPECT_EQ(answers[0].property, inputs.properties[0]);
          if (inspection == Status::Good)
          {
            ASSERT_TRUE(answers[0].value.is_good());
            EXPECT_TRUE(answers[0].value.value().value().as<bool>());
          }
          else
          {
            expect_refusal(answers[0].value.status_code(), inspectionFailure);
          }
          expect_refusal(answers[1].value.status_code(), candidateFailure);
          EXPECT_TRUE(answers[1].property.is_null());
          EXPECT_EQ(answers[2].property, inputs.properties[2]);
          ASSERT_TRUE(answers[2].value.is_good());
          EXPECT_FALSE(answers[2].value.value().value().as<bool>());
          EXPECT_TRUE(answers[3].property.is_null());
          EXPECT_EQ(answers[3].value.status_code(), StatusCode{Status::BadNodeIdUnknown});
        }
        else
        {
          ASSERT_EQ(nulls->count, 1u);
          ASSERT_TRUE(nulls->answer);
          ASSERT_EQ(nulls->answer->size(), 4u);
          const auto& answers = *nulls->answer;
          if (inspection == Status::Good)
          {
            EXPECT_TRUE(answers[0].status.is_good());
            EXPECT_EQ(answers[0].allowed, true);
          }
          else if (inspection == Status::BadNodeIdUnknown)
          {
            EXPECT_TRUE(answers[0].status.is_good());
            EXPECT_FALSE(answers[0].allowed.has_value());
          }
          else
          {
            expect_refusal(answers[0].status, inspectionFailure);
            EXPECT_FALSE(answers[0].allowed.has_value());
          }
          expect_refusal(answers[1].status, candidateFailure);
          EXPECT_FALSE(answers[1].allowed.has_value());
          EXPECT_TRUE(answers[2].status.is_good());
          EXPECT_EQ(answers[2].allowed, false);
          EXPECT_TRUE(answers[3].status.is_good());
          EXPECT_FALSE(answers[3].allowed.has_value());
        }
      };
      check();
      if (euRange)
      {
        repeat_and_check(harness, ranges);
      }
      else
      {
        repeat_and_check(harness, nulls);
      }
      check();
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-REFERENCE-READ-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldReferenceReadReleasesOwners)
{
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    const auto variable = harness.node("variable", NodeClass::Variable);
    const NodeId target{harness.index, "property"};
    harness.nameSpace->references.insert_or_assign(
      variable.get_node_id(), reference_to(ReferenceTypeId::HasProperty, target, true));
    harness.arm(HeldMember::References, variable.get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<ReferencesAnswer>>();
    start_references(harness, {variable}, outcome);
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    if (retainOwners)
    {
      harness.held->good();
      harness.drain();
    }
    else
    {
      harness.drop_owners();
    }
    EXPECT_EQ(outcome->count, 1u);
    if (outcome->answer)
    {
      ASSERT_EQ(outcome->answer->size(), 1u);
      const auto& answer = outcome->answer->front();
      if (retainOwners)
      {
        ASSERT_TRUE(answer.is_good());
        ASSERT_EQ(answer.value().size(), 1u);
        EXPECT_EQ(answer.value()[0].target_id().node_id(), target);
      }
      else
      {
        expect_refusal(answer.status_code(), harness.refusal);
      }
    }
    repeat_and_check(harness, outcome);
  }
}

// An identity with no Roles: the holding namespace's immediate permission forms decline, so its asynchronous
// member decides, and no Role can be unknown to the namespace's defaults.
std::shared_ptr<const AccessIdentity> roleless_identity()
{
  auto user = std::make_shared<UserIdentity>();
  user->kind = UserTokenKind::Anonymous;
  user->userId = "lifetime";
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = MessageSecurityMode::None;
  return std::make_shared<AccessIdentity>(AccessIdentityKey{1},
    std::vector<NodeId>{},
    std::move(user),
    std::move(endpoint),
    String{"urn:test:client"});
}

// Whether @p status carries @p refusal's own ErrorDetail, itself or as a cause in its chain.
bool carries_refusal(const StatusCode& status, const StatusCode& refusal)
{
  for (auto detail = status.shared_detail(); detail != nullptr; detail = detail->cause)
  {
    if (detail == refusal.shared_detail())
    {
      return true;
    }
  }
  return false;
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-AUTHORIZATION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldAuthorizationReleasesOwners)
{
  for (const bool namespaceSubject : {false, true})
  {
    for (const bool retainOwners : {false, true})
    {
      SCOPED_TRACE(namespaceSubject);
      SCOPED_TRACE(retainOwners);
      LifetimeHarness harness;
      const auto variable = harness.node("variable", NodeClass::Variable);
      harness.nameSpace->decline_immediate_permissions();
      // The namespace subject is asked with a disengaged NodeId list, which the holding namespace matches
      // as the null NodeId.
      harness.arm(HeldMember::Permissions, namespaceSubject ? NodeId{} : variable.get_node_id());
      EndpointSecurityContext channel;
      channel.messageSecurityMode = MessageSecurityMode::None;
      // Released with the owners, as a service releases its own; one kept is
      // AnAccessControlKeptAcrossAHeldAuthorizationHoldsNoOwner.
      std::optional<AccessControl> accessControl;
      accessControl.emplace(*harness.addressSpace, std::chrono::milliseconds{60000});
      const auto batch = std::make_shared<AnswerObservation<std::vector<AccessControl::Verdict>>>();
      const auto single = std::make_shared<AnswerObservation<AccessControl::Verdict>>();
      if (namespaceSubject)
      {
        accessControl->authorize_namespace_async(RequestInfo{},
          roleless_identity(),
          harness.index,
          channel,
          AnswerObservation<AccessControl::Verdict>::callback(single));
      }
      else
      {
        const std::array items{AccessControl::Item{.node = variable, .operation = AccessOperation::Read}};
        accessControl->authorize_async(RequestInfo{},
          roleless_identity(),
          items,
          channel,
          AnswerObservation<std::vector<AccessControl::Verdict>>::callback(batch));
      }
      harness.drain();
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(batch->count + single->count, 0u);
      if (retainOwners)
      {
        harness.held->good();
        harness.drain();
      }
      else
      {
        accessControl.reset();
        harness.drop_owners();
      }
      std::optional<AccessControl::Verdict> verdict;
      if (namespaceSubject)
      {
        EXPECT_EQ(single->count, 1u);
        verdict = single->answer;
      }
      else
      {
        EXPECT_EQ(batch->count, 1u);
        if (batch->answer)
        {
          ASSERT_EQ(batch->answer->size(), 1u);
          verdict = batch->answer->front();
        }
      }
      if (verdict)
      {
        if (retainOwners)
        {
          EXPECT_TRUE(verdict->permitted);
        }
        else
        {
          EXPECT_FALSE(verdict->permitted);
          EXPECT_TRUE(carries_refusal(verdict->cause, harness.refusal)) << to_string(verdict->cause);
        }
      }
      const auto calls = harness.held->calls;
      const auto permissionCalls = harness.held->permissionCalls;
      harness.held->good();
      harness.held->bad();
      harness.drain();
      EXPECT_EQ(batch->count + single->count, 1u);
      EXPECT_EQ(harness.held->calls, calls);
      EXPECT_EQ(harness.held->permissionCalls, permissionCalls);
    }
  }
}

// An Event insert whose selectClause names every field BaseEventType makes Mandatory and whose one row
// carries a value of each field's declared type, attributing the Event to @p sourceNode.
UpdateEventDetails event_insert_from(const NodeId& sourceNode)
{
  static constexpr std::array<std::string_view, 8> mandatoryFields{
    "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"};
  UpdateEventDetails details;
  details.node_id() = sourceNode;
  details.perform_insert_replace() = PerformUpdateType::Insert;
  for (const auto& name : mandatoryFields)
  {
    SimpleAttributeOperand operand;
    operand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(QualifiedName{uint16_t{0}, std::string{name}});
    operand.attribute_id() = utils::to_underlying(AttributeId::Value);
    details.filter().select_clauses().push_back(std::move(operand));
  }
  const auto when = DateTime::now();
  HistoryEventFieldList record;
  record.event_fields().push_back(Variant{});
  record.event_fields().push_back(Variant{NodeId{ObjectTypeId::BaseEventType}});
  record.event_fields().push_back(Variant{sourceNode});
  record.event_fields().push_back(Variant{String{"namespace caller lifetime"}});
  record.event_fields().push_back(Variant{when});
  record.event_fields().push_back(Variant{when});
  record.event_fields().push_back(Variant{LocalizedText{"", "namespace caller lifetime"}});
  record.event_fields().push_back(Variant{uint16_t{500}});
  details.event_data().push_back(std::move(record));
  return details;
}

// The history-event row validation case of the criterion; the HistoryRead dataEncoding case is not here.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-HISTORY-WALKS-RELEASE-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldHistoryEventSourceNodeReleasesOwners)
{
  using ValidationOutcome = history_event_validation::Outcome;
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    // The harness's namespace 0 has no BaseEventType; it is created without declarations, so every clause
    // field is ignored and the row's success is Good_DataIgnored once its SourceNode resolves.
    const auto base = std::make_shared<AnswerObservation<NodeAccessorResult>>();
    harness.addressSpace->create_node_async(NodeId{ObjectTypeId::BaseEventType},
      NodeClass::ObjectType,
      AnswerObservation<NodeAccessorResult>::callback(base));
    harness.drain();
    ASSERT_TRUE(base->answer && base->answer->is_good());
    const auto source = harness.node("source", NodeClass::Object);
    harness.arm(HeldMember::Lookup, source.get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<ValidationOutcome>>();
    history_event_validation::validate_async(*harness.addressSpace,
      event_insert_from(source.get_node_id()),
      AnswerObservation<ValidationOutcome>::callback(outcome));
    harness.drain();
    ASSERT_TRUE(harness.held->held)
      << "lookups " << harness.held->lookupCalls.size() << ", answers " << outcome->count << ", filter "
      << (outcome->answer ? to_string(outcome->answer->detailStatus) : std::string{"-"}) << ", row "
      << (outcome->answer && !outcome->answer->rowStatus.empty() ? to_string(outcome->answer->rowStatus[0])
                                                                 : std::string{"-"});
    EXPECT_EQ(outcome->count, 0u);
    if (retainOwners)
    {
      harness.held->good();
      harness.drain();
    }
    else
    {
      harness.drop_owners();
    }
    EXPECT_EQ(outcome->count, 1u);
    if (outcome->answer)
    {
      ASSERT_EQ(outcome->answer->rowStatus.size(), 1u);
      const auto& rowStatus = outcome->answer->rowStatus.front();
      if (retainOwners)
      {
        EXPECT_TRUE(rowStatus.is_good()) << to_string(rowStatus);
      }
      else
      {
        EXPECT_TRUE(carries_refusal(rowStatus, harness.refusal)) << to_string(rowStatus);
      }
    }
    repeat_and_check(harness, outcome);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-PROPERTY-RESOLUTION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldPropertyResolutionReleasesOwners)
{
  for (const bool euRange : {false, true})
  {
    for (const auto member : {HeldMember::References, HeldMember::Lookup, HeldMember::Value})
    {
      for (const bool retainOwners : {false, true})
      {
        SCOPED_TRACE(euRange);
        SCOPED_TRACE(member_index(member));
        SCOPED_TRACE(retainOwners);
        LifetimeHarness harness;
        std::string browseName{"AllowNulls"};
        if (euRange)
        {
          browseName = "EURange";
        }
        const auto inputs = properties(harness, browseName);
        NodeId heldId{inputs.properties[0]};
        if (member == HeldMember::References)
        {
          heldId = inputs.variables[0].get_node_id();
        }
        harness.arm(member, heldId);
        const auto nulls = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
        const auto ranges = std::make_shared<AnswerObservation<EuRangeAnswer>>();
        if (euRange)
        {
          EuRangeResolver::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            std::nullopt,
            AnswerObservation<EuRangeAnswer>::callback(ranges));
        }
        else
        {
          AllowNullsBatch::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            std::nullopt,
            std::nullopt,
            AnswerObservation<AllowNullsAnswer>::callback(nulls));
        }
        harness.drain();
        ASSERT_TRUE(harness.held->held);
        if (retainOwners)
        {
          harness.held->good();
          harness.drain();
        }
        else
        {
          harness.drop_owners();
        }
        if (euRange)
        {
          EXPECT_EQ(ranges->count, 1u);
          if (ranges->answer)
          {
            ASSERT_EQ(ranges->answer->size(), 1u);
            const auto& property = ranges->answer->front();
            if (retainOwners)
            {
              EXPECT_EQ(property.property, inputs.properties[0]);
              ASSERT_TRUE(property.value.is_good());
              EXPECT_TRUE(property.value.value().value().as<bool>());
            }
            else
            {
              expect_refusal(property.value.status_code(), harness.refusal);
            }
          }
          repeat_and_check(harness, ranges);
        }
        else
        {
          EXPECT_EQ(nulls->count, 1u);
          if (nulls->answer)
          {
            ASSERT_EQ(nulls->answer->size(), 1u);
            const auto& property = nulls->answer->front();
            if (retainOwners)
            {
              EXPECT_TRUE(property.status.is_good());
              EXPECT_EQ(property.allowed, true);
            }
            else
            {
              expect_refusal(property.status, harness.refusal);
              EXPECT_FALSE(property.allowed.has_value());
            }
          }
          repeat_and_check(harness, nulls);
        }
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-TYPE-RESOLUTION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldTypeResolutionReleasesOwners)
{
  for (const auto operation :
    {TypeOperation::Walk, TypeOperation::Subtype, TypeOperation::Declared, TypeOperation::Encoding})
  {
    for (const auto stage : {TypeStage::InitialLookup,
           TypeStage::FirstReferences,
           TypeStage::FurtherLookup,
           TypeStage::FurtherReferences})
    {
      if ((operation == TypeOperation::Walk && stage == TypeStage::InitialLookup) ||
          (operation == TypeOperation::Encoding &&
            (stage == TypeStage::FurtherLookup || stage == TypeStage::FurtherReferences)))
      {
        continue;  // These interfaces do not perform these operations.
      }
      for (const bool retainOwners : {false, true})
      {
        SCOPED_TRACE(utils::to_underlying(operation));
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(retainOwners);
        LifetimeHarness harness;
        const auto inputs = type_inputs(harness, operation);
        arm_type(harness, inputs, stage);
        const auto outcome = std::make_shared<TypeAnswer>();
        start_type(harness, operation, {inputs}, outcome);
        ASSERT_TRUE(harness.held->held);
        EXPECT_EQ(outcome->count, 0u);
        if (retainOwners)
        {
          harness.held->good();
          harness.drain();
        }
        else
        {
          harness.drop_owners();
        }
        if (outcome->count != 0)
        {
          expect_type(*outcome, operation, stage, inputs, retainOwners, &harness.refusal);
        }
        EXPECT_EQ(outcome->count, 1u);
        const auto calls = harness.held->calls;
        harness.held->good();
        harness.held->bad();
        harness.drain();
        EXPECT_EQ(outcome->count, 1u);
        EXPECT_EQ(harness.held->calls, calls);
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-NUMERIC-TYPE-RESOLUTION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldNumericTypeResolutionReleasesOwners)
{
  const std::vector<NodeId> knownTypes{
    NodeId{DataTypeId::Double}, NodeId{DataTypeId::String}, NodeId{DataTypeId::BaseDataType}, NodeId{}};
  for (const auto stage : {TypeStage::InitialLookup,
         TypeStage::FirstReferences,
         TypeStage::FurtherLookup,
         TypeStage::FurtherReferences})
  {
    for (const auto mode :
      {ChunkMode::BothGone, ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      const auto numeric = type_inputs(harness, TypeOperation::Numeric, "-numeric");
      const auto nonNumeric = type_inputs(harness, TypeOperation::Numeric, "-non-numeric");
      const auto undecided = type_inputs(harness, TypeOperation::Numeric, "-undecided");
      harness.nameSpace->references.insert_or_assign(
        nonNumeric.parent, reference_to(ReferenceTypeId::HasSubtype, NodeId{DataTypeId::String}, false));
      harness.nameSpace->references.insert_or_assign(
        undecided.childId, NodeReferencesResult{NodeReferences{}});
      arm_type(harness, numeric, stage);
      const auto outcome = std::make_shared<TypeAnswer>();
      start_type(harness, TypeOperation::Numeric, {numeric, nonNumeric, undecided}, outcome, knownTypes);
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(outcome->count, 0u);
      complete_first_chunk(harness, mode);
      const auto check = [&]
      {
        ASSERT_EQ(outcome->count, 1u);
        const bool classified = mode == ChunkMode::Retained ||
                                (stage == TypeStage::FurtherReferences && mode == ChunkMode::OwnerlessGood);
        EXPECT_EQ(
          outcome->nonNumeric, (std::vector<bool>{false, true, false, false, false, classified, false}));
        if (mode == ChunkMode::Retained)
        {
          EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{2, 2, 0}));
        }
      };
      check();
      const auto calls = harness.held->calls;
      ASSERT_TRUE(harness.held->good);
      ASSERT_TRUE(harness.held->bad);
      harness.held->good();
      harness.held->bad();
      harness.drain();
      EXPECT_EQ(harness.held->calls, calls);
      check();
    }
  }

  for (const bool nonNumericSupertype : {false, true})
  {
    SCOPED_TRACE(nonNumericSupertype);
    LifetimeHarness harness;
    const auto terminal = type_inputs(harness, TypeOperation::Numeric, "-terminal");
    const auto undecided = type_inputs(harness, TypeOperation::Numeric, "-undecided");
    NodeId target{DataTypeId::Double};
    if (nonNumericSupertype)
    {
      target = NodeId{DataTypeId::String};
    }
    harness.nameSpace->references.insert_or_assign(
      terminal.childId, reference_to(ReferenceTypeId::HasSubtype, target, false));
    harness.nameSpace->references.insert_or_assign(undecided.childId, NodeReferencesResult{NodeReferences{}});
    arm_type(harness, terminal, TypeStage::FirstReferences);
    const auto outcome = std::make_shared<TypeAnswer>();
    start_type(harness, TypeOperation::Numeric, {terminal, undecided}, outcome, knownTypes);
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 0}));
    harness.drop_space();
    const auto calls = harness.held->calls;
    harness.held->good();
    harness.drain();
    const auto check = [&]
    {
      EXPECT_EQ(outcome->count, 1u);
      EXPECT_EQ(
        outcome->nonNumeric, (std::vector<bool>{false, true, false, false, nonNumericSupertype, false}));
      EXPECT_EQ(harness.held->calls, calls);
    };
    check();
    harness.held->good();
    harness.held->bad();
    harness.drain();
    check();
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-LATE-ANSWER-CANNOT-START-OWNERLESS-WORK, scope=function)
TEST(NamespaceCallerLifetime, LateAnswerCannotStartOwnerlessWork)
{
  // The first two namespace items finish before the third is held; only that last item needs paging.
  for (const bool paging : {false, true})
  {
    for (const bool refuse : {false, true})
    {
      SCOPED_TRACE(paging);
      SCOPED_TRACE(refuse);
      LifetimeHarness harness;
      const auto completed = harness.node("completed", NodeClass::Variable);
      const auto failed = harness.node("failed", NodeClass::Variable);
      const auto waiting = harness.node("waiting", NodeClass::Variable);
      const NodeId target{harness.index, "target"};
      const ByteString token{std::vector<uint8_t>{1, 2, 3}};
      harness.nameSpace->references.insert_or_assign(
        completed.get_node_id(), reference_to(ReferenceTypeId::HasProperty, target, true));
      harness.nameSpace->references.insert_or_assign(
        failed.get_node_id(), NodeReferencesResult{harness.refusal});
      ByteString answeredToken;
      if (paging)
      {
        answeredToken = token;
      }
      harness.nameSpace->references.insert_or_assign(
        waiting.get_node_id(), reference_to(ReferenceTypeId::HasProperty, target, true, answeredToken));
      harness.arm(HeldMember::References, waiting.get_node_id());
      const auto outcome = std::make_shared<AnswerObservation<ReferencesAnswer>>();
      start_references(harness, {completed, failed, waiting}, outcome, 1);
      ASSERT_TRUE(harness.held->held);
      ASSERT_EQ(harness.held->calls[member_index(HeldMember::References)], 3u);
      harness.drop_space();
      const auto calls = harness.held->calls;
      if (refuse)
      {
        harness.held->bad();
      }
      else
      {
        harness.held->good();
      }
      harness.drain();
      EXPECT_EQ(harness.held->calls, calls);
      ASSERT_EQ(outcome->count, 1u);
      ASSERT_TRUE(outcome->answer);
      ASSERT_EQ(outcome->answer->size(), 3u);
      ASSERT_TRUE((*outcome->answer)[0].is_good());
      ASSERT_EQ((*outcome->answer)[0].value().size(), 1u);
      EXPECT_EQ((*outcome->answer)[0].value()[0].target_id().node_id(), target);
      expect_refusal((*outcome->answer)[1].status_code(), harness.refusal);
      if (refuse)
      {
        expect_refusal((*outcome->answer)[2].status_code(), harness.refusal);
      }
      else if (paging)
      {
        expect_owner_gone((*outcome->answer)[2].status_code());
      }
      else
      {
        ASSERT_TRUE((*outcome->answer)[2].is_good());
        ASSERT_EQ((*outcome->answer)[2].value().size(), 1u);
        EXPECT_EQ((*outcome->answer)[2].value()[0].target_id().node_id(), target);
      }
      if (paging && !refuse)
      {
        // This observation precedes destruction of either retained callback copy.
        EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
      }
      else
      {
        EXPECT_TRUE(harness.held->releasedTokens.empty());
      }
      repeat_and_check(harness, outcome);
      if (paging && !refuse)
      {
        EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
      }
    }
  }

  for (const bool euRange : {false, true})
  {
    for (const auto member : {HeldMember::References, HeldMember::Lookup, HeldMember::Value})
    {
      for (const bool refuse : {false, true})
      {
        SCOPED_TRACE(euRange);
        SCOPED_TRACE(member_index(member));
        SCOPED_TRACE(refuse);
        LifetimeHarness harness;
        ServiceOperationLimits limits;
        limits.maxNodesPerRead = 1;
        harness.addressSpace->set_operation_limits(limits);
        std::string browseName{"AllowNulls"};
        if (euRange)
        {
          browseName = "EURange";
        }
        const auto inputs = properties(harness, browseName, 3);
        // A completed absent-Property entry and rich failure must survive a later unresolved item.
        if (member == HeldMember::References)
        {
          harness.nameSpace->references.insert_or_assign(
            inputs.variables[0].get_node_id(), NodeReferencesResult{NodeReferences{}});
          harness.nameSpace->references.insert_or_assign(
            inputs.variables[1].get_node_id(), NodeReferencesResult{harness.refusal});
        }
        else if (member == HeldMember::Lookup)
        {
          harness.nameSpace->references.insert_or_assign(
            inputs.variables[0].get_node_id(), NodeReferencesResult{NodeReferences{}});
          harness.nameSpace->answer_lookup_of(inputs.properties[1], harness.refusal);
        }
        else
        {
          harness.nameSpace->values.insert_or_assign(inputs.properties[1], DataValueResult{harness.refusal});
        }
        NodeId heldId{inputs.properties[2]};
        if (member == HeldMember::References)
        {
          heldId = inputs.variables[2].get_node_id();
        }
        harness.arm(member, heldId);
        const auto nulls = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
        const auto ranges = std::make_shared<AnswerObservation<EuRangeAnswer>>();
        if (euRange)
        {
          EuRangeResolver::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            1,
            AnswerObservation<EuRangeAnswer>::callback(ranges));
        }
        else
        {
          AllowNullsBatch::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            1,
            1,
            AnswerObservation<AllowNullsAnswer>::callback(nulls));
        }
        harness.drain();
        ASSERT_TRUE(harness.held->held);
        harness.drop_space();
        const auto calls = harness.held->calls;
        if (refuse)
        {
          harness.held->bad();
        }
        else
        {
          harness.held->good();
        }
        harness.drain();
        EXPECT_EQ(harness.held->calls, calls);
        if (euRange)
        {
          ASSERT_EQ(ranges->count, 1u);
          ASSERT_TRUE(ranges->answer);
          ASSERT_EQ(ranges->answer->size(), 3u);
          if (member == HeldMember::Value)
          {
            ASSERT_TRUE((*ranges->answer)[0].value.is_good());
            EXPECT_TRUE((*ranges->answer)[0].value.value().value().as<bool>());
          }
          else
          {
            EXPECT_EQ((*ranges->answer)[0].value.status_code(), StatusCode{Status::BadNodeIdUnknown});
          }
          expect_refusal((*ranges->answer)[1].value.status_code(), harness.refusal);
          const auto& answer = (*ranges->answer)[2];
          if (refuse)
          {
            expect_refusal(answer.value.status_code(), harness.refusal);
          }
          else if (member == HeldMember::Value)
          {
            EXPECT_EQ(answer.property, inputs.properties[2]);
            ASSERT_TRUE(answer.value.is_good());
            EXPECT_TRUE(answer.value.value().value().as<bool>());
          }
          else
          {
            expect_owner_gone(answer.value.status_code());
          }
          repeat_and_check(harness, ranges);
        }
        else
        {
          ASSERT_EQ(nulls->count, 1u);
          ASSERT_TRUE(nulls->answer);
          ASSERT_EQ(nulls->answer->size(), 3u);
          EXPECT_TRUE((*nulls->answer)[0].status.is_good());
          if (member == HeldMember::Value)
          {
            EXPECT_EQ((*nulls->answer)[0].allowed, true);
          }
          else
          {
            EXPECT_FALSE((*nulls->answer)[0].allowed.has_value());
          }
          expect_refusal((*nulls->answer)[1].status, harness.refusal);
          const auto& answer = (*nulls->answer)[2];
          if (refuse)
          {
            expect_refusal(answer.status, harness.refusal);
            EXPECT_FALSE(answer.allowed.has_value());
          }
          else if (member == HeldMember::Value)
          {
            EXPECT_TRUE(answer.status.is_good());
            EXPECT_EQ(answer.allowed, true);
          }
          else
          {
            expect_owner_gone(answer.status);
            EXPECT_FALSE(answer.allowed.has_value());
          }
          repeat_and_check(harness, nulls);
        }
      }
    }
  }

  for (const auto operation :
    {TypeOperation::Walk, TypeOperation::Subtype, TypeOperation::Declared, TypeOperation::Encoding})
  {
    for (const auto stage : {TypeStage::InitialLookup,
           TypeStage::FirstReferences,
           TypeStage::FurtherLookup,
           TypeStage::FurtherReferences})
    {
      if ((operation == TypeOperation::Walk && stage == TypeStage::InitialLookup) ||
          (operation == TypeOperation::Encoding &&
            (stage == TypeStage::FurtherLookup || stage == TypeStage::FurtherReferences)))
      {
        continue;
      }
      for (const bool refuse : {false, true})
      {
        SCOPED_TRACE(utils::to_underlying(operation));
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(refuse);
        LifetimeHarness harness;
        const auto inputs = type_inputs(harness, operation);
        arm_type(harness, inputs, stage);
        const auto outcome = std::make_shared<TypeAnswer>();
        start_type(harness, operation, {inputs}, outcome);
        ASSERT_TRUE(harness.held->held);
        harness.drop_space();
        const auto calls = harness.held->calls;
        if (refuse)
        {
          harness.held->bad();
        }
        else
        {
          harness.held->good();
        }
        harness.drain();
        EXPECT_EQ(harness.held->calls, calls);
        const bool terminal = stage == TypeStage::FurtherReferences ||
                              (operation == TypeOperation::Encoding && stage == TypeStage::FirstReferences);
        const StatusCode* failure = nullptr;
        if (refuse)
        {
          failure = &harness.refusal;
        }
        expect_type(*outcome, operation, stage, inputs, terminal && !refuse, failure, !refuse);
        harness.held->good();
        harness.held->bad();
        harness.drain();
        EXPECT_EQ(outcome->count, 1u);
        EXPECT_EQ(harness.held->calls, calls);
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-OWNER-LOSS-STOPS-UNISSUED-CHUNKS, scope=function)
TEST(NamespaceCallerLifetime, OwnerLossStopsUnissuedChunks)
{
  for (const auto mode : {ChunkMode::OwnerlessGood,
         ChunkMode::OwnerlessPage,
         ChunkMode::OwnerlessBad,
         ChunkMode::BothGone,
         ChunkMode::Retained})
  {
    SCOPED_TRACE(utils::to_underlying(mode));
    LifetimeHarness harness;
    ServiceOperationLimits limits;
    limits.maxNodesPerBrowse = 1;
    limits.maxNodesPerRead = 1;
    harness.addressSpace->set_operation_limits(limits);
    std::vector<NodeAccessor> variables;
    const NodeId target{harness.index, "reference-target"};
    const ByteString token{std::vector<uint8_t>{7, 8, 9}};
    for (std::size_t i = 0; i < 3; ++i)
    {
      variables.push_back(harness.node("references" + std::to_string(i), NodeClass::Variable));
      ByteString answeredToken;
      if (i == 0 && mode == ChunkMode::OwnerlessPage)
      {
        answeredToken = token;
      }
      harness.nameSpace->references.insert_or_assign(variables.back().get_node_id(),
        reference_to(ReferenceTypeId::HasProperty, target, true, answeredToken));
    }
    harness.arm(HeldMember::References, variables.front().get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<ReferencesAnswer>>();
    start_references(harness, variables, outcome, 1);
    ASSERT_TRUE(harness.held->held);
    ASSERT_EQ(harness.held->calls[member_index(HeldMember::References)], 1u);
    EXPECT_EQ(outcome->count, 0u);
    complete_first_chunk(harness, mode);
    ASSERT_EQ(outcome->count, 1u);
    ASSERT_TRUE(outcome->answer);
    ASSERT_EQ(outcome->answer->size(), 3u);
    for (std::size_t i = 0; i < 3; ++i)
    {
      SCOPED_TRACE(i);
      const auto& answer = (*outcome->answer)[i];
      if (mode == ChunkMode::Retained || (i == 0 && mode == ChunkMode::OwnerlessGood))
      {
        ASSERT_TRUE(answer.is_good());
        ASSERT_EQ(answer.value().size(), 1u);
        EXPECT_EQ(answer.value()[0].target_id().node_id(), target);
      }
      else if (i == 0 && (mode == ChunkMode::OwnerlessBad || mode == ChunkMode::BothGone))
      {
        expect_refusal(answer.status_code(), harness.refusal);
      }
      else
      {
        expect_owner_gone(answer.status_code());
      }
    }
    if (mode == ChunkMode::OwnerlessPage)
    {
      EXPECT_EQ(outcome->releasedTokensAtCompletion, 1u);
      EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
    }
    else
    {
      EXPECT_EQ(outcome->releasedTokensAtCompletion, 0u);
      EXPECT_TRUE(harness.held->releasedTokens.empty());
    }
    if (mode == ChunkMode::Retained)
    {
      EXPECT_EQ(harness.held->calls[member_index(HeldMember::References)], 3u);
    }
    repeat_and_check(harness, outcome);
    if (mode == ChunkMode::OwnerlessPage)
    {
      EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
    }
  }

  for (const bool euRange : {false, true})
  {
    for (const auto member : {HeldMember::References, HeldMember::Lookup, HeldMember::Value})
    {
      for (const auto mode : {ChunkMode::OwnerlessGood,
             ChunkMode::OwnerlessTerminal,
             ChunkMode::OwnerlessPage,
             ChunkMode::OwnerlessBad,
             ChunkMode::BothGone,
             ChunkMode::Retained})
      {
        if ((mode == ChunkMode::OwnerlessPage && member != HeldMember::References) ||
            (mode == ChunkMode::OwnerlessTerminal && member == HeldMember::Value))
        {
          continue;  // Only References page; a successful Value answer is already terminal.
        }
        SCOPED_TRACE(euRange);
        SCOPED_TRACE(member_index(member));
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        ServiceOperationLimits limits;
        limits.maxNodesPerBrowse = 1;
        limits.maxNodesPerRead = 1;
        harness.addressSpace->set_operation_limits(limits);
        std::string browseName{"AllowNulls"};
        if (euRange)
        {
          browseName = "EURange";
        }
        const auto inputs = properties(harness, browseName, 3);
        const ByteString token{std::vector<uint8_t>{4, 5, 6}};
        if (member == HeldMember::References && mode == ChunkMode::OwnerlessTerminal)
        {
          harness.nameSpace->references.insert_or_assign(
            inputs.variables.front().get_node_id(), NodeReferencesResult{NodeReferences{}});
        }
        else if (member == HeldMember::References && mode == ChunkMode::OwnerlessPage)
        {
          harness.nameSpace->references.insert_or_assign(inputs.variables.front().get_node_id(),
            reference_to(ReferenceTypeId::HasProperty, inputs.properties.front(), true, token));
        }
        else if (member == HeldMember::Lookup && mode == ChunkMode::OwnerlessTerminal)
        {
          const auto found = std::make_shared<AnswerObservation<NodeAccessorResult>>();
          harness.addressSpace->find_node_async(
            inputs.properties.front(), AnswerObservation<NodeAccessorResult>::callback(found));
          harness.drain();
          ASSERT_EQ(found->count, 1u);
          ASSERT_TRUE(found->answer && found->answer->is_good());
          found->answer->value().set_browse_name(QualifiedName{0, "OtherProperty"});
        }
        NodeId heldId{inputs.properties.front()};
        if (member == HeldMember::References)
        {
          heldId = inputs.variables.front().get_node_id();
        }
        harness.arm(member, heldId);
        const auto nulls = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
        const auto ranges = std::make_shared<AnswerObservation<EuRangeAnswer>>();
        if (euRange)
        {
          EuRangeResolver::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            1,
            AnswerObservation<EuRangeAnswer>::callback(ranges, harness.held));
        }
        else
        {
          AllowNullsBatch::resolve_async(*harness.addressSpace,
            RequestInfo{},
            inputs.variables,
            1,
            1,
            AnswerObservation<AllowNullsAnswer>::callback(nulls, harness.held));
        }
        harness.drain();
        ASSERT_TRUE(harness.held->held);
        ASSERT_EQ(harness.held->calls[member_index(member)], 1u);
        complete_first_chunk(harness, mode);
        if (euRange)
        {
          ASSERT_EQ(ranges->count, 1u);
          ASSERT_TRUE(ranges->answer);
          ASSERT_EQ(ranges->answer->size(), 3u);
          for (std::size_t i = 0; i < 3; ++i)
          {
            SCOPED_TRACE(i);
            const auto& answer = (*ranges->answer)[i];
            if (member == HeldMember::Value || mode == ChunkMode::Retained)
            {
              EXPECT_EQ(answer.property, inputs.properties[i]);
            }
            if (mode == ChunkMode::Retained ||
                (i == 0 && member == HeldMember::Value && mode == ChunkMode::OwnerlessGood))
            {
              ASSERT_TRUE(answer.value.is_good());
              EXPECT_TRUE(answer.value.value().value().as<bool>());
            }
            else if (i == 0 && mode == ChunkMode::OwnerlessTerminal)
            {
              EXPECT_TRUE(answer.property.is_null());
              EXPECT_EQ(answer.value.status_code(), StatusCode{Status::BadNodeIdUnknown});
            }
            else if (i == 0 && (mode == ChunkMode::OwnerlessBad || mode == ChunkMode::BothGone))
            {
              expect_refusal(answer.value.status_code(), harness.refusal);
            }
            else
            {
              expect_owner_gone(answer.value.status_code());
            }
          }
          if (mode == ChunkMode::OwnerlessPage)
          {
            EXPECT_EQ(ranges->releasedTokensAtCompletion, 1u);
          }
          else
          {
            EXPECT_EQ(ranges->releasedTokensAtCompletion, 0u);
          }
          repeat_and_check(harness, ranges);
        }
        else
        {
          ASSERT_EQ(nulls->count, 1u);
          ASSERT_TRUE(nulls->answer);
          ASSERT_EQ(nulls->answer->size(), 3u);
          for (std::size_t i = 0; i < 3; ++i)
          {
            SCOPED_TRACE(i);
            const auto& answer = (*nulls->answer)[i];
            if (mode == ChunkMode::Retained ||
                (i == 0 && member == HeldMember::Value && mode == ChunkMode::OwnerlessGood))
            {
              EXPECT_TRUE(answer.status.is_good());
              EXPECT_EQ(answer.allowed, true);
            }
            else if (i == 0 && mode == ChunkMode::OwnerlessTerminal)
            {
              EXPECT_TRUE(answer.status.is_good());
              EXPECT_FALSE(answer.allowed.has_value());
            }
            else if (i == 0 && (mode == ChunkMode::OwnerlessBad || mode == ChunkMode::BothGone))
            {
              expect_refusal(answer.status, harness.refusal);
              EXPECT_FALSE(answer.allowed.has_value());
            }
            else
            {
              expect_owner_gone(answer.status);
              EXPECT_FALSE(answer.allowed.has_value());
            }
          }
          if (mode == ChunkMode::OwnerlessPage)
          {
            EXPECT_EQ(nulls->releasedTokensAtCompletion, 1u);
          }
          else
          {
            EXPECT_EQ(nulls->releasedTokensAtCompletion, 0u);
          }
          repeat_and_check(harness, nulls);
        }
        if (mode == ChunkMode::Retained)
        {
          EXPECT_EQ(harness.held->calls[member_index(member)], 3u);
        }
        if (mode == ChunkMode::OwnerlessPage)
        {
          EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
        }
        else
        {
          EXPECT_TRUE(harness.held->releasedTokens.empty());
        }
      }
    }
  }

  for (const auto operation :
    {TypeOperation::Walk, TypeOperation::Subtype, TypeOperation::Declared, TypeOperation::Encoding})
  {
    for (const auto stage : {TypeStage::InitialLookup, TypeStage::FurtherLookup})
    {
      if ((operation == TypeOperation::Walk && stage == TypeStage::InitialLookup) ||
          (operation == TypeOperation::Encoding && stage == TypeStage::FurtherLookup))
      {
        continue;  // Walk starts with accessors; encoding resolution has no further lookup.
      }
      for (const auto mode :
        {ChunkMode::OwnerlessGood, ChunkMode::OwnerlessBad, ChunkMode::BothGone, ChunkMode::Retained})
      {
        SCOPED_TRACE(utils::to_underlying(operation));
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        ServiceOperationLimits limits;
        limits.maxNodesPerRead = 1;
        harness.addressSpace->set_operation_limits(limits);
        std::vector<TypeInputs> inputs;
        for (std::size_t i = 0; i < 3; ++i)
        {
          inputs.push_back(type_inputs(harness, operation, std::to_string(i)));
        }
        arm_type(harness, inputs.front(), stage);
        const auto outcome = std::make_shared<TypeAnswer>();
        start_type(harness, operation, inputs, outcome);
        ASSERT_TRUE(harness.held->held);
        std::size_t expectedLookupCalls{1};
        if (stage == TypeStage::FurtherLookup && operation != TypeOperation::Walk)
        {
          expectedLookupCalls = 4;  // Three completed initial chunks, then the first supertype chunk.
        }
        ASSERT_EQ(harness.held->calls[member_index(HeldMember::Lookup)], expectedLookupCalls);
        EXPECT_EQ(outcome->count, 0u);
        complete_first_chunk(harness, mode);
        expect_chunk_type(*outcome, operation, stage, inputs, mode, harness.refusal);
        if (mode == ChunkMode::Retained)
        {
          std::size_t completedLookupCalls{3};
          if (operation == TypeOperation::Subtype || operation == TypeOperation::Declared)
          {
            completedLookupCalls = 6;
          }
          EXPECT_EQ(harness.held->calls[member_index(HeldMember::Lookup)], completedLookupCalls);
        }
        const auto calls = harness.held->calls;
        harness.held->good();
        harness.held->bad();
        harness.drain();
        EXPECT_EQ(outcome->count, 1u);
        EXPECT_EQ(harness.held->calls, calls);
        EXPECT_TRUE(harness.held->releasedTokens.empty());
      }
    }
  }
}

namespace
{

enum class FactsCompletionPath
{
  Empty,
  BuiltinOnly,
  TerminalLookup,
  DeferredSuccess,
  Ownerless
};

void facts_completion_case(TypeOperation operation, FactsCompletionPath path, bool throwing)
{
  LifetimeHarness harness;
  ua::test::TestLogSink log;
  const auto outcome = std::make_shared<TypeAnswer>();
  outcome->throwAfterRecording = throwing;
  std::vector<NodeId> knownTypes;
  if (operation == TypeOperation::Numeric && path != FactsCompletionPath::Empty)
  {
    knownTypes = {
      NodeId{DataTypeId::Double}, NodeId{DataTypeId::String}, NodeId{DataTypeId::BaseDataType}, NodeId{}};
  }
  if (path == FactsCompletionPath::Empty || path == FactsCompletionPath::BuiltinOnly)
  {
    harness.addressSpace->set_logger(log.logger());
    harness.held->calls = {};
    start_type(harness, operation, {}, outcome, knownTypes);
    EXPECT_EQ(outcome->count, 1u);
    EXPECT_TRUE(outcome->subtype.empty());
    EXPECT_TRUE(outcome->declared.empty());
    EXPECT_TRUE(outcome->encoding.empty());
    if (path == FactsCompletionPath::BuiltinOnly)
    {
      EXPECT_EQ(outcome->nonNumeric, (std::vector<bool>{false, true, false, false}));
    }
    else
    {
      EXPECT_TRUE(outcome->nonNumeric.empty());
    }
    EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 0, 0}));
    EXPECT_EQ(log.count(LogLevel::Warning), throwing ? 1u : 0u);
    return;
  }

  const auto inputs = type_inputs(harness, operation);
  if (operation == TypeOperation::Numeric)
  {
    harness.nameSpace->references.insert_or_assign(
      inputs.parent, reference_to(ReferenceTypeId::HasSubtype, NodeId{DataTypeId::String}, false));
  }
  harness.addressSpace->set_logger(log.logger());
  TypeStage stage{TypeStage::InitialLookup};
  if (path == FactsCompletionPath::DeferredSuccess ||
      (operation == TypeOperation::Numeric && path == FactsCompletionPath::Ownerless))
  {
    stage = TypeStage::FirstReferences;
  }
  if (path == FactsCompletionPath::TerminalLookup)
  {
    // A received rich lookup refusal is terminal, without a References invocation. Keep copies of this
    // inline namespace answer too: duplicate handling must not depend on having deferred the first answer.
    harness.nameSpace->lookups.insert_or_assign(inputs.childId, NodeResult{harness.refusal});
    harness.nameSpace->decline_single_lookups();
    harness.held->calls = {};
    harness.held->copyDelivered = true;
  }
  else
  {
    arm_type(harness, inputs, stage);
  }
  start_type(harness, operation, {inputs}, outcome, knownTypes);
  if (path != FactsCompletionPath::TerminalLookup)
  {
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    EXPECT_EQ(log.count(LogLevel::Warning), 0u);
    if (path == FactsCompletionPath::Ownerless)
    {
      harness.drop_space();
    }
    harness.held->good();
    harness.drain();
  }

  const auto check = [&]
  {
    const bool success = path == FactsCompletionPath::DeferredSuccess;
    const bool initialFound = path == FactsCompletionPath::Ownerless;
    if (operation == TypeOperation::Numeric)
    {
      EXPECT_EQ(outcome->count, 1u);
      EXPECT_EQ(outcome->nonNumeric, (std::vector<bool>{false, true, false, false, success}));
    }
    else
    {
      expect_type(*outcome, operation, stage, inputs, success, nullptr, initialFound);
    }
    EXPECT_EQ(log.count(LogLevel::Warning), throwing ? 1u : 0u);
    if (success && operation != TypeOperation::Encoding)
    {
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{2, 2, 0}));
    }
    else if (success)
    {
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 0}));
    }
    else if (operation == TypeOperation::Numeric && path == FactsCompletionPath::Ownerless)
    {
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 1, 0}));
    }
    else
    {
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{1, 0, 0}));
    }
    if (operation == TypeOperation::Declared)
    {
      const auto found = outcome->declared.find(inputs.childId);
      ASSERT_NE(found, outcome->declared.end());
      EXPECT_EQ(found->second.definition, nullptr);
    }
  };
  check();
  const auto calls = harness.held->calls;
  ASSERT_TRUE(harness.held->good);
  ASSERT_TRUE(harness.held->bad);
  harness.held->good();
  harness.held->bad();
  harness.drain();
  EXPECT_EQ(harness.held->calls, calls);
  check();
}

enum class UncertainControl
{
  OuterUncertain,
  OuterBad,
  EmbeddedUncertain
};

void uncertain_allow_nulls(HeldMember member)
{
  for (const auto control :
    {UncertainControl::OuterUncertain, UncertainControl::OuterBad, UncertainControl::EmbeddedUncertain})
  {
    if (member == HeldMember::References && control == UncertainControl::EmbeddedUncertain)
    {
      continue;  // References have no contained DataValue quality.
    }
    SCOPED_TRACE(utils::to_underlying(control));
    LifetimeHarness harness;
    const auto inputs = properties(harness, "AllowNulls", 2);
    const StatusCode uncertain{
      Status::UncertainNoCommunicationLastUsableValue, harness.refusal.shared_detail()};
    StatusCode injected{uncertain};
    if (control == UncertainControl::OuterBad)
    {
      injected = harness.refusal;
    }
    NodeId heldId{inputs.properties[0]};
    if (member == HeldMember::References)
    {
      heldId = inputs.variables[0].get_node_id();
      harness.nameSpace->references.insert_or_assign(heldId, NodeReferencesResult{injected});
    }
    else if (control == UncertainControl::EmbeddedUncertain)
    {
      harness.nameSpace->values.insert_or_assign(
        heldId, DataValueResult{DataValue{Variant{false}, uncertain}});
    }
    else
    {
      harness.nameSpace->values.insert_or_assign(heldId, DataValueResult{injected});
    }
    harness.arm(member, heldId);
    const auto outcome = std::make_shared<AnswerObservation<AllowNullsAnswer>>();
    AllowNullsBatch::resolve_async(*harness.addressSpace,
      RequestInfo{},
      inputs.variables,
      std::nullopt,
      std::nullopt,
      AnswerObservation<AllowNullsAnswer>::callback(outcome));
    harness.drain();
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    harness.held->good();
    harness.drain();
    ASSERT_EQ(outcome->count, 1u);
    ASSERT_TRUE(outcome->answer);
    ASSERT_EQ(outcome->answer->size(), 2u);
    // A Value whose own status is Uncertain is refused as an Uncertain answer is.
    const auto& refused = (*outcome->answer)[0];
    if (control == UncertainControl::OuterBad)
    {
      expect_refusal(refused.status, harness.refusal);
      EXPECT_FALSE(refused.allowed.has_value());
    }
    else
    {
      EXPECT_EQ(refused.status, StatusCode{Status::BadInternalError});
      EXPECT_FALSE(refused.allowed.has_value());
      ASSERT_NE(refused.status.shared_detail(), nullptr);
      std::string expectedCode{"ReadAnswerUncertain"};
      if (member == HeldMember::References)
      {
        expectedCode = "ReferencesAnswerUncertain";
      }
      EXPECT_EQ(refused.status.shared_detail()->code, expectedCode);
      EXPECT_EQ(refused.status.shared_detail()->innerStatus, uncertain.value());
      EXPECT_EQ(refused.status.shared_detail()->cause, uncertain.shared_detail());
    }
    EXPECT_TRUE((*outcome->answer)[1].status.is_good());
    EXPECT_EQ((*outcome->answer)[1].allowed, true);
    repeat_and_check(harness, outcome);
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-22-UNCERTAIN-PROPERTY-VALUE-IS-REFUSED, scope=function)
TEST(NamespaceCallerLifetimeDeathTest, UncertainAllowNullsValueIsRefused)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_EXIT(
    {
      start_child();
      uncertain_allow_nulls(HeldMember::Value);
      finish_child();
    },
    ::testing::ExitedWithCode(0),
    "");
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-22-UNCERTAIN-REFERENCES-ARE-REFUSED, scope=function)
TEST(NamespaceCallerLifetimeDeathTest, UncertainAllowNullsReferencesAreRefused)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_EXIT(
    {
      start_child();
      uncertain_allow_nulls(HeldMember::References);
      finish_child();
    },
    ::testing::ExitedWithCode(0),
    "");
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-23-THROWING-FACTS-COMPLETION-IS-CONTAINED-ONCE, scope=function)
TEST(NamespaceCallerLifetimeDeathTest, ThrowingFactsCompletionIsContainedOnce)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  for (const auto operation : {TypeOperation::Subtype, TypeOperation::Declared, TypeOperation::Encoding})
  {
    for (const auto path : {FactsCompletionPath::Empty,
           FactsCompletionPath::TerminalLookup,
           FactsCompletionPath::DeferredSuccess,
           FactsCompletionPath::Ownerless})
    {
      for (const bool throwing : {false, true})
      {
        SCOPED_TRACE(utils::to_underlying(operation));
        SCOPED_TRACE(utils::to_underlying(path));
        SCOPED_TRACE(throwing);
        EXPECT_EXIT(
          {
            start_child();
            facts_completion_case(operation, path, throwing);
            finish_child();
          },
          ::testing::ExitedWithCode(0),
          "");
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-23-NUMERIC-COMPLETION-IS-CONTAINED-ONCE, scope=function)
TEST(NamespaceCallerLifetimeDeathTest, NumericCompletionIsContainedOnce)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  for (const auto path : {FactsCompletionPath::Empty,
         FactsCompletionPath::BuiltinOnly,
         FactsCompletionPath::TerminalLookup,
         FactsCompletionPath::DeferredSuccess,
         FactsCompletionPath::Ownerless})
  {
    for (const bool throwing : {false, true})
    {
      SCOPED_TRACE(utils::to_underlying(path));
      SCOPED_TRACE(throwing);
      EXPECT_EXIT(
        {
          start_child();
          facts_completion_case(TypeOperation::Numeric, path, throwing);
          finish_child();
        },
        ::testing::ExitedWithCode(0),
        "");
    }
  }
}

namespace
{

// The step of external guard linking a scenario holds: the lookup, References read, value read or Reference
// addition, and the Node it names.
enum class GuardStage
{
  MachineLookup,
  MachineReferences,
  MachineParentLookup,
  MachineParentReferences,
  ComponentLookup,
  ComponentReferences,
  GuardLookup,
  GuardReferences,
  GuardTypeLookup,
  GuardSupertypeReferences,
  GuardParentLookup,
  GuardParentReferences,
  ExpressionParentLookup,
  ExpressionReferences,
  ExpressionCandidateLookup,
  ExpressionFinalLookup,
  ExpressionValue,
  ForwardLookup,
  ForwardReferences,
  ForwardAddition,
  InverseLookup,
  InverseReferences,
  InverseAddition
};

std::string_view name(GuardStage value)
{
  switch (value)
  {
  case GuardStage::MachineLookup:
    return "MachineLookup";
  case GuardStage::MachineReferences:
    return "MachineReferences";
  case GuardStage::MachineParentLookup:
    return "MachineParentLookup";
  case GuardStage::MachineParentReferences:
    return "MachineParentReferences";
  case GuardStage::ComponentLookup:
    return "ComponentLookup";
  case GuardStage::ComponentReferences:
    return "ComponentReferences";
  case GuardStage::GuardLookup:
    return "GuardLookup";
  case GuardStage::GuardReferences:
    return "GuardReferences";
  case GuardStage::GuardTypeLookup:
    return "GuardTypeLookup";
  case GuardStage::GuardSupertypeReferences:
    return "GuardSupertypeReferences";
  case GuardStage::GuardParentLookup:
    return "GuardParentLookup";
  case GuardStage::GuardParentReferences:
    return "GuardParentReferences";
  case GuardStage::ExpressionParentLookup:
    return "ExpressionParentLookup";
  case GuardStage::ExpressionReferences:
    return "ExpressionReferences";
  case GuardStage::ExpressionCandidateLookup:
    return "ExpressionCandidateLookup";
  case GuardStage::ExpressionFinalLookup:
    return "ExpressionFinalLookup";
  case GuardStage::ExpressionValue:
    return "ExpressionValue";
  case GuardStage::ForwardLookup:
    return "ForwardLookup";
  case GuardStage::ForwardReferences:
    return "ForwardReferences";
  case GuardStage::ForwardAddition:
    return "ForwardAddition";
  case GuardStage::InverseLookup:
    return "InverseLookup";
  case GuardStage::InverseReferences:
    return "InverseReferences";
  case GuardStage::InverseAddition:
    return "InverseAddition";
  }
  return "unknown";
}

// Which owners are released while the step is held: none, the address space, or the address space and the
// namespace.
enum class GuardOwners
{
  Retained,
  SpaceGone,
  BothGone
};

std::string_view name(GuardOwners value)
{
  switch (value)
  {
  case GuardOwners::Retained:
    return "Retained";
  case GuardOwners::SpaceGone:
    return "SpaceGone";
  case GuardOwners::BothGone:
    return "BothGone";
  }
  return "unknown";
}

// How the held step, or the Expression's candidates, are answered.
enum class GuardAnswer
{
  Good,
  Bad,
  Uncertain,
  Terminal,
  Paging,
  CandidateBad,
  CandidateUncertain,
  CandidateBadThenMatch,
  CandidateUncertainThenMatch,
  EmbeddedUncertain
};

std::string_view name(GuardAnswer value)
{
  switch (value)
  {
  case GuardAnswer::Good:
    return "Good";
  case GuardAnswer::Bad:
    return "Bad";
  case GuardAnswer::Uncertain:
    return "Uncertain";
  case GuardAnswer::Terminal:
    return "Terminal";
  case GuardAnswer::Paging:
    return "Paging";
  case GuardAnswer::CandidateBad:
    return "CandidateBad";
  case GuardAnswer::CandidateUncertain:
    return "CandidateUncertain";
  case GuardAnswer::CandidateBadThenMatch:
    return "CandidateBadThenMatch";
  case GuardAnswer::CandidateUncertainThenMatch:
    return "CandidateUncertainThenMatch";
  case GuardAnswer::EmbeddedUncertain:
    return "EmbeddedUncertain";
  }
  return "unknown";
}

// An instantiation context the linking has nothing to do for: one with a Node that is not a guard's, or none.
enum class GuardEmptyControl
{
  NoApplicable,
  NoNodes
};

std::string_view name(GuardEmptyControl value)
{
  switch (value)
  {
  case GuardEmptyControl::NoApplicable:
    return "NoApplicable";
  case GuardEmptyControl::NoNodes:
    return "NoNodes";
  }
  return "unknown";
}

// Whether @p stage is a References read.
bool reads_references(GuardStage stage)
{
  return name(stage).ends_with("References");
}

// Whether @p stage is a Reference addition.
bool adds_reference(GuardStage stage)
{
  return name(stage).ends_with("Addition");
}

// The ErrorDetail code with which the linking refuses an Uncertain answer at @p stage, or nothing when it
// passes the answer on. The linking acts on every lookup, References read and Value read, so an Uncertain
// answer to one is refused; the supertype steps are a References read and a lookup that answer one code,
// refused as a lookup; a Reference addition's own answer is the linking's answer.
std::string_view uncertain_refusal_code(GuardStage stage)
{
  switch (stage)
  {
  case GuardStage::MachineReferences:
  case GuardStage::MachineParentReferences:
  case GuardStage::ComponentReferences:
  case GuardStage::GuardReferences:
  case GuardStage::ExpressionReferences:
  case GuardStage::ForwardReferences:
  case GuardStage::InverseReferences:
    return "ReferencesAnswerUncertain";
  case GuardStage::ExpressionValue:
    return "ReadAnswerUncertain";
  case GuardStage::ForwardAddition:
  case GuardStage::InverseAddition:
    return "AnswerUncertain";
  case GuardStage::MachineLookup:
  case GuardStage::MachineParentLookup:
  case GuardStage::ComponentLookup:
  case GuardStage::GuardLookup:
  case GuardStage::GuardTypeLookup:
  case GuardStage::GuardSupertypeReferences:
  case GuardStage::GuardParentLookup:
  case GuardStage::GuardParentReferences:
  case GuardStage::ExpressionParentLookup:
  case GuardStage::ExpressionCandidateLookup:
  case GuardStage::ExpressionFinalLookup:
  case GuardStage::ForwardLookup:
  case GuardStage::InverseLookup:
    return "LookupAnswerUncertain";
  }
  return "";
}

// Immutable identities and weak-bound accessors only; this model does not retain either owner.
struct ExternalGuardInputs
{
  std::map<GuardStage, NodeId> identities;
  NodeAccessor machine;
  NodeAccessor target;
  std::shared_ptr<const instantiation_detail::InstantiationContext> context;
};

ExternalGuardInputs external_guard_inputs(LifetimeHarness& harness)
{
  const auto base = std::make_shared<AnswerObservation<NodeAccessorResult>>();
  harness.addressSpace->create_node_async(NodeId{VariableTypeId::ExpressionGuardVariableType},
    NodeClass::VariableType,
    AnswerObservation<NodeAccessorResult>::callback(base));
  harness.drain(128);
  EXPECT_EQ(base->count, 1u);
  if (!base->answer || !base->answer->is_good())
  {
    throw std::runtime_error("fixture ExpressionGuardVariableType creation failed");
  }

  const auto owner = harness.node("external-guard-owner", NodeClass::Object).get_node_id();
  const auto ownerType = harness.node("external-guard-owner-type", NodeClass::ObjectType).get_node_id();
  const auto machine = harness.node("external-guard-machine", NodeClass::Object);
  const auto target = harness.node("external-guard-target", NodeClass::Variable);
  const auto machineType = harness.node("external-guard-machine-type", NodeClass::ObjectType).get_node_id();
  const auto machineParent =
    harness.node("external-guard-machine-parent", NodeClass::ObjectType).get_node_id();
  const auto component = harness.node("external-guard-component", NodeClass::Object).get_node_id();
  const auto guard = harness.node("external-guard-variable", NodeClass::Variable).get_node_id();
  const auto guardType = harness.node("external-guard-type", NodeClass::VariableType).get_node_id();
  const auto guardParent = harness.node("external-guard-type-parent", NodeClass::VariableType).get_node_id();
  auto expression = harness.node("external-guard-expression", NodeClass::Variable);
  expression.set_browse_name(QualifiedName{0, "Expression"});
  const auto expressionId = expression.get_node_id();

  harness.nameSpace->references.insert_or_assign(machineType,
    NodeReferences{References{std::vector<Reference>{
      Reference{NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{component}, true},
      Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{machineParent}, false}}}});
  harness.nameSpace->references.insert_or_assign(machineParent, NodeReferences{References{}});
  harness.nameSpace->references.insert_or_assign(
    component, reference_to(ReferenceTypeId::HasGuard, guard, true));
  harness.nameSpace->references.insert_or_assign(guard,
    NodeReferences{References{std::vector<Reference>{
      Reference{NodeId{ReferenceTypeId::HasTypeDefinition}, ExpandedNodeId{guardType}, true},
      Reference{NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{expressionId}, true}}}});
  harness.nameSpace->references.insert_or_assign(
    guardType, reference_to(ReferenceTypeId::HasSubtype, guardParent, false));
  harness.nameSpace->references.insert_or_assign(guardParent,
    reference_to(ReferenceTypeId::HasSubtype, NodeId{VariableTypeId::ExpressionGuardVariableType}, false));
  harness.nameSpace->references.insert_or_assign(machine.get_node_id(), NodeReferences{References{}});
  harness.nameSpace->references.insert_or_assign(target.get_node_id(), NodeReferences{References{}});

  ContentFilter filter;
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::Equals;
  // Two identical operands must still establish each link half only once.
  for (std::size_t operandIndex = 0; operandIndex != 2; ++operandIndex)
  {
    auto operand = std::make_unique<SimpleAttributeOperand>();
    operand->type_definition_id() = ownerType;
    operand->browse_path().push_back(QualifiedName{harness.index, "Threshold"});
    operand->attribute_id() = utils::to_underlying(AttributeId::Value);
    RefStructure<Structure> encoded;
    encoded = std::unique_ptr<Structure>{std::move(operand)};
    element.filter_operands().push_back(std::move(encoded));
  }
  filter.elements().push_back(std::move(element));
  harness.nameSpace->values.insert_or_assign(expressionId, DataValue{Variant{std::move(filter)}});

  auto context = std::make_shared<instantiation_detail::InstantiationContext>();
  context->record_type(ownerType, owner);
  context->record_node(instantiation_detail::InstantiatedNodeBinding{
    .declarationId = NodeId{harness.index, "external-guard-machine-declaration"},
    .instanceId = machine.get_node_id(),
    .parentInstanceId = owner,
    .parentReferenceType = NodeId{ReferenceTypeId::HasComponent},
    .browseName = QualifiedName{harness.index, "Machine"},
    .nodeClass = NodeClass::Object,
    .typeDefinitionId = machineType});
  context->record_node(instantiation_detail::InstantiatedNodeBinding{
    .declarationId = NodeId{harness.index, "external-guard-target-declaration"},
    .instanceId = target.get_node_id(),
    .parentInstanceId = owner,
    .parentReferenceType = NodeId{ReferenceTypeId::HasComponent},
    .browseName = QualifiedName{harness.index, "Threshold"},
    .nodeClass = NodeClass::Variable,
    .typeDefinitionId = std::nullopt});

  return ExternalGuardInputs{{{GuardStage::MachineLookup, machineType},
                               {GuardStage::MachineReferences, machineType},
                               {GuardStage::MachineParentLookup, machineParent},
                               {GuardStage::MachineParentReferences, machineParent},
                               {GuardStage::ComponentLookup, component},
                               {GuardStage::ComponentReferences, component},
                               {GuardStage::GuardLookup, guard},
                               {GuardStage::GuardReferences, guard},
                               {GuardStage::GuardTypeLookup, guardType},
                               {GuardStage::GuardSupertypeReferences, guardType},
                               {GuardStage::GuardParentLookup, guardParent},
                               {GuardStage::GuardParentReferences, guardParent},
                               {GuardStage::ExpressionParentLookup, guard},
                               {GuardStage::ExpressionReferences, guard},
                               {GuardStage::ExpressionCandidateLookup, expressionId},
                               {GuardStage::ExpressionFinalLookup, expressionId},
                               {GuardStage::ExpressionValue, expressionId},
                               {GuardStage::ForwardLookup, machine.get_node_id()},
                               {GuardStage::ForwardReferences, machine.get_node_id()},
                               {GuardStage::ForwardAddition, machine.get_node_id()},
                               {GuardStage::InverseLookup, target.get_node_id()},
                               {GuardStage::InverseReferences, target.get_node_id()},
                               {GuardStage::InverseAddition, target.get_node_id()}},
    machine,
    target,
    std::move(context)};
}

void arm_external_guard(LifetimeHarness& harness, const ExternalGuardInputs& inputs, GuardStage stage)
{
  HeldMember member{HeldMember::Lookup};
  if (reads_references(stage))
  {
    member = HeldMember::References;
  }
  else if (stage == GuardStage::ExpressionValue)
  {
    member = HeldMember::Value;
  }
  harness.arm(member, inputs.identities.at(stage));
  if (stage == GuardStage::ExpressionParentLookup || stage == GuardStage::ExpressionReferences ||
      stage == GuardStage::ExpressionFinalLookup)
  {
    harness.held->matchingCallsBeforeHold = 1;
  }
  if (adds_reference(stage))
  {
    harness.held->member.reset();
    harness.held->holdReferenceAddition = true;
  }
  if (stage == GuardStage::InverseAddition)
  {
    // The address space adds the inverse half itself with the linker's forward add (NR-30 rule 2); the stage
    // holds the linker's own inverse add, the second add on the target.
    harness.held->matchingCallsBeforeHold = 1;
  }
}

void expect_external_guard_links(
  LifetimeHarness& harness, const ExternalGuardInputs& inputs, bool forward, bool inverse)
{
  const std::array<const NodeAccessor*, 2> accessors{&inputs.machine, &inputs.target};
  const std::array<bool, 2> expected{forward, inverse};
  const std::array<NodeId, 2> targets{inputs.target.get_node_id(), inputs.machine.get_node_id()};
  for (std::size_t half = 0; half < accessors.size(); ++half)
  {
    const auto recorded = std::make_shared<AnswerObservation<NodeAccessor::ReferencesResult>>();
    // Inspect the same real Node store directly: no owner lock or namespace call after owner loss.
    const auto stored = stored_node(*accessors[half]);
    ASSERT_NE(stored, nullptr);
    stored->get_references_async(AnswerObservation<NodeAccessor::ReferencesResult>::callback(recorded));
    harness.drain(128);
    ASSERT_EQ(recorded->count, 1u);
    ASSERT_TRUE(recorded->answer && recorded->answer->is_good());
    std::size_t matching{0};
    for (const auto& reference : recorded->answer->value())
    {
      if (reference.type_id() == NodeId{ReferenceTypeId::HasComponent} &&
          reference.target_id() == ExpandedNodeId{targets[half]} && reference.is_forward() == (half == 0))
      {
        ++matching;
      }
    }
    std::size_t expectedCount{0};
    if (expected[half])
    {
      expectedCount = 1;
    }
    EXPECT_EQ(matching, expectedCount);
  }
}

void external_guard_case(GuardStage stage, GuardOwners mode, GuardAnswer answer)
{
  StatusCode refusal{unavailable()};
  if (answer == GuardAnswer::Uncertain || answer == GuardAnswer::EmbeddedUncertain)
  {
    refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
      ErrorDetail::build("ExternalGuardOuterUncertain",
        "The namespace did not supply an external guard operation value",
        "NamespaceCallerLifetime")
        .context(ContextKeys::nodeId, NodeId{2, "external-guard-uncertain"})};
  }
  refusal.semantics_changed(true);
  LifetimeHarness harness{refusal};
  const auto inputs = external_guard_inputs(harness);
  const bool spaceGone = mode == GuardOwners::SpaceGone;
  const bool bothGone = mode == GuardOwners::BothGone;
  const bool terminal = answer == GuardAnswer::Terminal;
  const bool paging = answer == GuardAnswer::Paging;
  const ByteString token{0x45, 0x47, 0x56, 0x31};

  if (terminal)
  {
    if (stage == GuardStage::MachineReferences)
    {
      harness.nameSpace->references.insert_or_assign(
        inputs.identities.at(stage), NodeReferences{References{}});
    }
    else if (stage == GuardStage::MachineParentReferences)
    {
      harness.nameSpace->references.insert_or_assign(inputs.identities.at(GuardStage::MachineReferences),
        reference_to(ReferenceTypeId::HasSubtype, inputs.identities.at(stage), false));
    }
    else if (stage == GuardStage::ComponentReferences)
    {
      harness.nameSpace->references.insert_or_assign(inputs.identities.at(GuardStage::MachineReferences),
        reference_to(ReferenceTypeId::HasComponent, inputs.identities.at(GuardStage::ComponentLookup), true));
      harness.nameSpace->references.insert_or_assign(
        inputs.identities.at(stage), NodeReferences{References{}});
    }
    else if (stage == GuardStage::GuardReferences || stage == GuardStage::GuardSupertypeReferences ||
             stage == GuardStage::GuardParentReferences)
    {
      harness.nameSpace->references.insert_or_assign(
        inputs.identities.at(stage), NodeReferences{References{}});
    }
    else if (stage == GuardStage::ExpressionValue)
    {
      harness.nameSpace->values.insert_or_assign(
        inputs.identities.at(stage), DataValue{Variant{ContentFilter{}}});
    }
  }
  if (paging)
  {
    auto& page = harness.nameSpace->references.at(inputs.identities.at(stage));
    ASSERT_TRUE(page.is_good());
    harness.held->heldReferenceToken = token;
  }
  if (answer == GuardAnswer::EmbeddedUncertain)
  {
    auto& expression = harness.nameSpace->values.at(inputs.identities.at(GuardStage::ExpressionValue));
    ASSERT_TRUE(expression.is_good());
    auto usable = expression.value();
    usable.status() = refusal;
    harness.nameSpace->values.insert_or_assign(
      inputs.identities.at(GuardStage::ExpressionValue), std::move(usable));
  }
  bool provisional{false};
  bool laterMatch{false};
  NodeId failedCandidate;
  if (answer == GuardAnswer::CandidateBad || answer == GuardAnswer::CandidateUncertain ||
      answer == GuardAnswer::CandidateBadThenMatch || answer == GuardAnswer::CandidateUncertainThenMatch)
  {
    provisional = true;
    laterMatch =
      (answer == GuardAnswer::CandidateBadThenMatch || answer == GuardAnswer::CandidateUncertainThenMatch);
    if ((answer == GuardAnswer::CandidateUncertain || answer == GuardAnswer::CandidateUncertainThenMatch))
    {
      refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
        ErrorDetail::build("ExternalGuardCandidateUncertain",
          "The first Expression candidate has no resolved Node",
          "NamespaceCallerLifetime")};
      refusal.semantics_changed(true);
    }
    failedCandidate = harness.node("external-guard-failed-candidate", NodeClass::Variable).get_node_id();
    harness.nameSpace->lookups.insert_or_assign(failedCandidate, NodeResult{refusal});
    std::vector<Reference> properties{
      Reference{NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{failedCandidate}, true}};
    if (laterMatch)
    {
      properties.emplace_back(NodeId{ReferenceTypeId::HasProperty},
        ExpandedNodeId{inputs.identities.at(GuardStage::ExpressionValue)},
        true);
    }
    properties.emplace_back(NodeId{ReferenceTypeId::HasTypeDefinition},
      ExpandedNodeId{inputs.identities.at(GuardStage::GuardTypeLookup)},
      true);
    harness.nameSpace->references.insert_or_assign(
      inputs.identities.at(GuardStage::GuardLookup), NodeReferences{References{std::move(properties)}});
  }

  arm_external_guard(harness, inputs, stage);
  if (provisional)
  {
    harness.held->nodeId = failedCandidate;
  }
  harness.addressSpace->set_logger(
    Logger{harness.held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "external-guard-test"});
  const auto outcome = std::make_shared<AnswerObservation<VoidResult>>();
  EXPECT_NO_THROW(instantiation_detail::wire_external_guard_variables_async(*harness.addressSpace,
    DepthBudget{128},
    inputs.context,
    AnswerObservation<VoidResult>::callback(outcome, harness.held)));
  EXPECT_NO_THROW(harness.drain(512));
  ASSERT_TRUE(harness.held->held) << name(stage);
  EXPECT_EQ(outcome->count, 0u);
  const auto issued = harness.held->calls;
  const auto additions = harness.held->referenceAdditions.size();
  const auto weakSpace = harness.addressSpace->weak();
  const std::weak_ptr<ua::Namespace> weakNamespace{harness.nameSpace};
  const auto good = harness.held->good;
  const auto bad = harness.held->bad;
  ASSERT_TRUE(good);
  ASSERT_TRUE(bad);
  if (bothGone)
  {
    harness.addressSpace.reset();
    harness.nameSpace.reset();
    EXPECT_NO_THROW(harness.drain(512));
    EXPECT_FALSE(weakSpace.lock().has_value());
    EXPECT_TRUE(weakNamespace.expired());
    // An unfixed strong owner suppresses destructor refusal; explicitly drain its copied answer too.
    if (outcome->count == 0)
    {
      EXPECT_NO_THROW(bad());
      EXPECT_NO_THROW(harness.drain(512));
    }
  }
  else
  {
    if (spaceGone)
    {
      harness.addressSpace.reset();
      EXPECT_NO_THROW(harness.drain(512));
      EXPECT_FALSE(weakSpace.lock().has_value());
      EXPECT_FALSE(weakNamespace.expired());
    }
    else
    {
      EXPECT_TRUE(weakSpace.lock().has_value());
      EXPECT_FALSE(weakNamespace.expired());
    }
    if (answer == GuardAnswer::Bad || answer == GuardAnswer::Uncertain)
    {
      EXPECT_NO_THROW(bad());
    }
    else
    {
      EXPECT_NO_THROW(good());
    }
    EXPECT_NO_THROW(harness.drain(512));
  }
  EXPECT_EQ(outcome->count, 1u);
  ASSERT_TRUE(outcome->answer);
  const auto& result = *outcome->answer;
  // An Expression Value whose own status is Uncertain is refused as an Uncertain answer is.
  const bool suppliedRefusal = bothGone || answer == GuardAnswer::Bad || answer == GuardAnswer::Uncertain ||
                               answer == GuardAnswer::EmbeddedUncertain || (provisional && !laterMatch);
  if (suppliedRefusal)
  {
    if ((stage == GuardStage::ExpressionCandidateLookup && answer == GuardAnswer::Uncertain) ||
        (provisional && refusal.is_uncertain()))
    {
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
      ASSERT_NE(result.shared_detail(), nullptr);
      EXPECT_EQ(result.shared_detail()->code, "LookupAnswerUncertain");
      EXPECT_EQ(result.shared_detail()->innerStatus, refusal.value());
      EXPECT_EQ(result.shared_detail()->cause, refusal.shared_detail());
      NodeId unresolved{inputs.identities.at(GuardStage::ExpressionCandidateLookup)};
      if (provisional)
      {
        unresolved = failedCandidate;
      }
      bool recordedIdentity{false};
      for (const auto& fact : result.shared_detail()->context)
      {
        if (fact.key == ContextKeys::nodeId.value() && fact.value == to_string(unresolved))
        {
          recordedIdentity = true;
        }
      }
      EXPECT_TRUE(recordedIdentity);
    }
    else if ((answer == GuardAnswer::Uncertain || answer == GuardAnswer::EmbeddedUncertain) &&
             !uncertain_refusal_code(stage).empty())
    {
      // The linking does not act on an Uncertain answer, so the step's answer is the cause of its refusal.
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError}) << name(stage);
      ASSERT_NE(result.shared_detail(), nullptr) << name(stage);
      EXPECT_EQ(result.shared_detail()->code, uncertain_refusal_code(stage)) << name(stage);
      EXPECT_EQ(
        result.shared_detail()->summary, "The SDK does not act on an answer the namespace is uncertain of")
        << name(stage);
      EXPECT_EQ(result.shared_detail()->innerStatus, refusal.value()) << name(stage);
      EXPECT_EQ(result.shared_detail()->cause, refusal.shared_detail()) << name(stage);
    }
    else
    {
      expect_refusal(result.status_code(), refusal);
      EXPECT_EQ(result.status_code().value(), refusal.value());
      EXPECT_EQ(result.shared_detail(), refusal.shared_detail());
    }
  }
  else if (spaceGone && !terminal && stage != GuardStage::InverseAddition)
  {
    if (stage == GuardStage::ExpressionReferences && !paging)
    {
      // This is the received child utility's own owner-loss answer, passed on unchanged rather than
      // relabelled as a linker initiation failure.
      expect_owner_gone(result.status_code());
      ASSERT_NE(result.shared_detail(), nullptr);
      EXPECT_EQ(result.shared_detail()->source, "find_child_id_by_browse_name_async");
    }
    else
    {
      expect_owner_gone(result.status_code());
    }
  }
  else
  {
    EXPECT_TRUE(result.is_good());
    EXPECT_EQ(result.status_code(), StatusCode{});
  }

  if (spaceGone || bothGone || suppliedRefusal)
  {
    EXPECT_EQ(harness.held->calls, issued) << "a completed/ownerless step issued new namespace work";
    EXPECT_EQ(harness.held->referenceAdditions.size(), additions);
  }
  bool forward{false};
  bool inverse{false};
  if (!terminal && !suppliedRefusal && !spaceGone)
  {
    forward = true;
    inverse = true;
    // Each of the linker's two adds also sends the other half (NR-30 rule 2); this namespace stores no half,
    // so the linker's own inverse add is not found present and is sent too.
    EXPECT_EQ(harness.held->referenceAdditions.size(), 4u);
  }
  else
  {
    // Mutation precedes a held modification answer; later owner loss cannot undo that established half.
    for (std::size_t applied = 0; applied < additions; ++applied)
    {
      const auto& addition = harness.held->referenceAdditions[applied];
      if (addition.source == inputs.machine.get_node_id() && addition.isForward)
      {
        forward = true;
      }
      if (addition.source == inputs.target.get_node_id() && !addition.isForward)
      {
        inverse = true;
      }
    }
  }
  expect_external_guard_links(harness, inputs, forward, inverse);
  if (laterMatch && !spaceGone && !bothGone)
  {
    EXPECT_EQ(
      harness.held->valueReads, (std::vector<NodeId>{inputs.identities.at(GuardStage::ExpressionValue)}));
  }
  if (paging)
  {
    ASSERT_TRUE(outcome->releasedTokensAtCompletion);
    if (spaceGone)
    {
      EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
      EXPECT_EQ(*outcome->releasedTokensAtCompletion, 1u);
    }
    else
    {
      EXPECT_TRUE(harness.held->releasedTokens.empty());
      EXPECT_EQ(*outcome->releasedTokensAtCompletion, 0u);
      if (!bothGone)
      {
        std::size_t consumed{0};
        for (const auto& call : harness.held->referenceCalls)
        {
          for (const auto& query : call.referenceQueries)
          {
            if (query.resumeToken == token)
            {
              ++consumed;
            }
          }
        }
        EXPECT_EQ(consumed, 1u);
      }
    }
  }
  else
  {
    EXPECT_TRUE(harness.held->releasedTokens.empty());
  }
  const auto completedCalls = harness.held->calls;
  const auto completedAdditions = harness.held->referenceAdditions.size();
  const auto completedReleases = harness.held->releasedTokens;
  const auto warnings = harness.held->warnings();
  const auto completedStatus = result.status_code();
  const auto completedDetail = result.shared_detail();
  if (bothGone)
  {
    // Establish the expired issuer before delivering a copied page that must only retire its token.
    EXPECT_FALSE(weakSpace.lock().has_value());
    EXPECT_TRUE(weakNamespace.expired());
  }
  EXPECT_NO_THROW(good());
  EXPECT_NO_THROW(bad());
  EXPECT_NO_THROW(good());
  EXPECT_NO_THROW(harness.drain(512));
  EXPECT_EQ(outcome->count, 1u);
  EXPECT_EQ(outcome->answer->status_code(), completedStatus);
  EXPECT_EQ(outcome->answer->shared_detail(), completedDetail);
  EXPECT_EQ(harness.held->calls, completedCalls);
  EXPECT_EQ(harness.held->referenceAdditions.size(), completedAdditions);
  EXPECT_EQ(harness.held->releasedTokens, completedReleases);
  EXPECT_EQ(harness.held->warnings(), warnings);
  EXPECT_TRUE(warnings.empty());
  expect_external_guard_links(harness, inputs, forward, inverse);
}

void external_guard_empty_case(GuardEmptyControl control)
{
  LifetimeHarness harness;
  auto context = std::make_shared<instantiation_detail::InstantiationContext>();
  if (control == GuardEmptyControl::NoApplicable)
  {
    context->record_node(instantiation_detail::InstantiatedNodeBinding{
      .declarationId = NodeId{harness.index, "nonapplicable-declaration"},
      .instanceId = NodeId{harness.index, "nonapplicable-variable"},
      .parentInstanceId = NodeId{harness.index, "nonapplicable-parent"},
      .parentReferenceType = NodeId{ReferenceTypeId::HasProperty},
      .browseName = QualifiedName{harness.index, "Value"},
      .nodeClass = NodeClass::Variable,
      .typeDefinitionId = NodeId{VariableTypeId::BaseDataVariableType}});
  }
  const auto outcome = std::make_shared<AnswerObservation<VoidResult>>();
  harness.held->calls = {};
  EXPECT_NO_THROW(instantiation_detail::wire_external_guard_variables_async(
    *harness.addressSpace, DepthBudget{128}, context, AnswerObservation<VoidResult>::callback(outcome)));
  EXPECT_NO_THROW(harness.drain(128));
  EXPECT_EQ(outcome->count, 1u);
  ASSERT_TRUE(outcome->answer);
  EXPECT_TRUE(outcome->answer->is_good());
  EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{}));
  EXPECT_TRUE(harness.held->referenceAdditions.empty());
  EXPECT_TRUE(harness.held->releasedTokens.empty());
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EXTERNAL-GUARD-LINKING-RELEASES-OWNERS, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(NamespaceCallerLifetime, ExternalGuardLinkingReleasesOwners)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");

  struct Scenario
  {
    GuardStage stage;
    GuardOwners mode;
    GuardAnswer answer;
  };

  std::vector<Scenario> scenarios;
  for (const auto stage : {GuardStage::MachineLookup,
         GuardStage::MachineReferences,
         GuardStage::MachineParentLookup,
         GuardStage::MachineParentReferences,
         GuardStage::ComponentLookup,
         GuardStage::ComponentReferences,
         GuardStage::GuardLookup,
         GuardStage::GuardReferences,
         GuardStage::GuardTypeLookup,
         GuardStage::GuardSupertypeReferences,
         GuardStage::GuardParentLookup,
         GuardStage::GuardParentReferences,
         GuardStage::ExpressionParentLookup,
         GuardStage::ExpressionReferences,
         GuardStage::ExpressionCandidateLookup,
         GuardStage::ExpressionFinalLookup,
         GuardStage::ExpressionValue,
         GuardStage::ForwardLookup,
         GuardStage::ForwardReferences,
         GuardStage::ForwardAddition,
         GuardStage::InverseLookup,
         GuardStage::InverseReferences,
         GuardStage::InverseAddition})
  {
    for (const auto mode : {GuardOwners::Retained, GuardOwners::SpaceGone})
    {
      for (const auto answer : {GuardAnswer::Good, GuardAnswer::Bad, GuardAnswer::Uncertain})
      {
        scenarios.push_back({stage, mode, answer});
      }
    }
    scenarios.push_back({stage, GuardOwners::BothGone, GuardAnswer::Bad});
  }
  for (const auto stage : {GuardStage::MachineReferences,
         GuardStage::MachineParentReferences,
         GuardStage::ComponentReferences,
         GuardStage::GuardReferences,
         GuardStage::GuardSupertypeReferences,
         GuardStage::GuardParentReferences,
         GuardStage::ExpressionValue})
  {
    scenarios.push_back({stage, GuardOwners::Retained, GuardAnswer::Terminal});
    scenarios.push_back({stage, GuardOwners::SpaceGone, GuardAnswer::Terminal});
  }
  for (const auto stage : {GuardStage::MachineReferences,
         GuardStage::ComponentReferences,
         GuardStage::GuardReferences,
         GuardStage::GuardSupertypeReferences,
         GuardStage::GuardParentReferences,
         GuardStage::ExpressionReferences,
         GuardStage::ForwardReferences,
         GuardStage::InverseReferences})
  {
    for (const auto mode : {GuardOwners::Retained, GuardOwners::SpaceGone, GuardOwners::BothGone})
    {
      scenarios.push_back({stage, mode, GuardAnswer::Paging});
    }
  }
  for (const auto answer : {GuardAnswer::CandidateBad,
         GuardAnswer::CandidateUncertain,
         GuardAnswer::CandidateBadThenMatch,
         GuardAnswer::CandidateUncertainThenMatch})
  {
    scenarios.push_back({GuardStage::ExpressionCandidateLookup, GuardOwners::Retained, answer});
  }
  scenarios.push_back({GuardStage::ExpressionValue, GuardOwners::Retained, GuardAnswer::EmbeddedUncertain});

  for (const auto& scenario : scenarios)
  {
    const std::string described = "external guard scenario " + std::string{name(scenario.stage)} + '/' +
                                  std::string{name(scenario.mode)} + '/' + std::string{name(scenario.answer)};
    SCOPED_TRACE(described);
    EXPECT_EXIT(
      {
        start_child();
        external_guard_case(scenario.stage, scenario.mode, scenario.answer);
        finish_child(described);
      },
      ::testing::ExitedWithCode(0),
      "");
  }
  for (const auto control : {GuardEmptyControl::NoApplicable, GuardEmptyControl::NoNodes})
  {
    const std::string described = "external guard scenario Empty/Retained/" + std::string{name(control)};
    SCOPED_TRACE(described);
    EXPECT_EXIT(
      {
        start_child();
        external_guard_empty_case(control);
        finish_child(described);
      },
      ::testing::ExitedWithCode(0),
      "");
  }
}

namespace
{

// How a reference-type check is decided: at once, from the cache, after reading the subtype chain, from a
// refused lookup, or with its owner gone at one of three steps.
enum class ReferenceTypePath
{
  ExactMatch,
  SubtypesDisabled,
  CacheTrue,
  CacheFalse,
  DeferredTrue,
  DeferredFalse,
  Missing,
  LookupBad,
  LookupUncertain,
  OwnerlessInitial,
  OwnerlessReferences,
  OwnerlessParent
};

std::string_view name(ReferenceTypePath value)
{
  switch (value)
  {
  case ReferenceTypePath::ExactMatch:
    return "ExactMatch";
  case ReferenceTypePath::SubtypesDisabled:
    return "SubtypesDisabled";
  case ReferenceTypePath::CacheTrue:
    return "CacheTrue";
  case ReferenceTypePath::CacheFalse:
    return "CacheFalse";
  case ReferenceTypePath::DeferredTrue:
    return "DeferredTrue";
  case ReferenceTypePath::DeferredFalse:
    return "DeferredFalse";
  case ReferenceTypePath::Missing:
    return "Missing";
  case ReferenceTypePath::LookupBad:
    return "LookupBad";
  case ReferenceTypePath::LookupUncertain:
    return "LookupUncertain";
  case ReferenceTypePath::OwnerlessInitial:
    return "OwnerlessInitial";
  case ReferenceTypePath::OwnerlessReferences:
    return "OwnerlessReferences";
  case ReferenceTypePath::OwnerlessParent:
    return "OwnerlessParent";
  }
  return "unknown";
}

void reference_type_completion_case(bool cached, ReferenceTypePath path, bool throwing)
{
  LifetimeHarness harness;
  const auto child = harness.node("completion-reference-child", NodeClass::ReferenceType);
  const auto parent = harness.node("completion-reference-parent", NodeClass::ReferenceType).get_node_id();
  const auto ancestor = harness.node("completion-reference-ancestor", NodeClass::ReferenceType).get_node_id();
  TypeInputs inputs{child, child.get_node_id(), parent, parent};
  harness.nameSpace->references.insert_or_assign(
    inputs.childId, reference_to(ReferenceTypeId::HasSubtype, inputs.parent, false));
  harness.nameSpace->references.insert_or_assign(
    inputs.parent, reference_to(ReferenceTypeId::HasSubtype, ancestor, false));
  const bool cacheHit = path == ReferenceTypePath::CacheTrue || path == ReferenceTypePath::CacheFalse;
  const bool exactMatch = path == ReferenceTypePath::ExactMatch;
  const bool subtypesDisabled = path == ReferenceTypePath::SubtypesDisabled;
  const bool lookupRefusal =
    path == ReferenceTypePath::LookupBad || path == ReferenceTypePath::LookupUncertain;
  const bool ownerless = path == ReferenceTypePath::OwnerlessInitial ||
                         path == ReferenceTypePath::OwnerlessReferences ||
                         path == ReferenceTypePath::OwnerlessParent;
  const bool expectedValue = path == ReferenceTypePath::ExactMatch || path == ReferenceTypePath::CacheTrue ||
                             path == ReferenceTypePath::DeferredTrue;
  if (exactMatch)
  {
    inputs.target = inputs.childId;
  }
  if (path == ReferenceTypePath::OwnerlessParent)
  {
    inputs.target = ancestor;
  }
  if (path == ReferenceTypePath::CacheFalse || path == ReferenceTypePath::DeferredFalse)
  {
    harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferences{References{}});
  }
  if (path == ReferenceTypePath::Missing)
  {
    // The actual store has no such ReferenceType; this is the documented Good-false terminal lookup.
    inputs.childId = NodeId{harness.index, "missing-completion-reference"};
  }
  StatusCode refusal{harness.refusal};
  if (path == ReferenceTypePath::LookupUncertain)
  {
    refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
      ErrorDetail::build("ReferenceCompletionLookupUncertain",
        "The namespace has no usable reference-type lookup answer",
        "NamespaceCallerLifetime")
        .context(ContextKeys::nodeId, inputs.childId)};
  }
  if (lookupRefusal)
  {
    harness.nameSpace->lookups.insert_or_assign(inputs.childId, NodeResult{refusal});
  }
  const auto cache = std::make_shared<node_utils::RefTypeCache>();
  const auto key = std::make_pair(inputs.childId, inputs.target);
  if (cacheHit)
  {
    cache->store(key, expectedValue);
  }
  harness.addressSpace->set_logger(
    Logger{harness.held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "reference-completion"});
  const bool fast = exactMatch || subtypesDisabled || (cached && cacheHit);
  TypeStage stage{TypeStage::FirstReferences};
  if (lookupRefusal || path == ReferenceTypePath::Missing || path == ReferenceTypePath::OwnerlessInitial)
  {
    stage = TypeStage::InitialLookup;
  }
  else if (path == ReferenceTypePath::OwnerlessParent)
  {
    stage = TypeStage::FurtherLookup;
  }
  if (fast)
  {
    harness.arm(HeldMember::Lookup, inputs.childId);
  }
  else
  {
    arm_type(harness, inputs, stage);
  }
  const auto outcome = std::make_shared<AnswerObservation<BoolResult>>();
  const auto complete = [record = AnswerObservation<BoolResult>::callback(outcome), throwing](
                          BoolResult result)
  {
    record(std::move(result));
    if (throwing)
    {
      throw std::runtime_error("reference-type completion sentinel");
    }
  };
  if (cached)
  {
    EXPECT_NO_THROW(node_utils::is_ref_of_type_cached_async(EncodingLimits{},
      *harness.addressSpace,
      !subtypesDisabled,
      inputs.childId,
      inputs.target,
      cache,
      complete));
  }
  else
  {
    EXPECT_NO_THROW(node_utils::is_ref_of_type_async(
      EncodingLimits{}, *harness.addressSpace, !subtypesDisabled, inputs.childId, inputs.target, complete));
  }
  EXPECT_NO_THROW(harness.drain(128));
  std::array<std::size_t, 3> expectedCalls{};
  if (!fast)
  {
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    EXPECT_TRUE(harness.held->warnings().empty());
    expectedCalls = {1, 0, 0};
    if (stage != TypeStage::InitialLookup)
    {
      expectedCalls[member_index(HeldMember::References)] = 1;
    }
    if (stage == TypeStage::FurtherLookup)
    {
      expectedCalls[member_index(HeldMember::Lookup)] = 2;
    }
    EXPECT_EQ(harness.held->calls, expectedCalls);
    if (ownerless)
    {
      harness.drop_space();
    }
    EXPECT_NO_THROW(harness.held->good());
    EXPECT_NO_THROW(harness.drain(128));
    if (expectedValue)
    {
      expectedCalls = {2, 1, 0};
    }
  }
  else
  {
    EXPECT_FALSE(harness.held->held);
  }
  EXPECT_EQ(harness.held->calls, expectedCalls);
  std::size_t expectedWarnings{0};
  if (throwing)
  {
    expectedWarnings = 1;
  }
  const auto check = [&]
  {
    EXPECT_EQ(outcome->count, 1u);
    const auto checkResult = [&]
    {
      ASSERT_TRUE(outcome->answer.has_value());
      const auto& result = *outcome->answer;
      if (path == ReferenceTypePath::LookupUncertain)
      {
        // The walk decides a rule, so it refuses an Uncertain answer instead of passing it on.
        expect_uncertain_refused(result.status_code(), refusal);
      }
      else if (lookupRefusal)
      {
        expect_refusal(result.status_code(), refusal);
      }
      else if (path == ReferenceTypePath::OwnerlessReferences)
      {
        EXPECT_EQ(result.status_code(), StatusCode{Status::BadShutdown});
        ASSERT_NE(result.shared_detail(), nullptr);
        EXPECT_EQ(result.shared_detail()->code, "DanglingHasSubtype");
        EXPECT_EQ(result.shared_detail()->innerStatus, utils::to_underlying(Status::BadShutdown));
        ASSERT_NE(result.shared_detail()->cause, nullptr);
        EXPECT_EQ(result.shared_detail()->cause->code, "AddressSpaceGone");
      }
      else if (ownerless)
      {
        expect_owner_gone(result.status_code());
      }
      else
      {
        ASSERT_TRUE(result.is_good());
        EXPECT_EQ(result.value(), expectedValue);
      }
    };
    checkResult();
    if (lookupRefusal || ownerless)
    {
      EXPECT_FALSE(cache->lookup(key).has_value());
    }
    else if (cacheHit || (cached && !fast))
    {
      EXPECT_EQ(cache->lookup(key), std::optional<bool>{expectedValue});
    }
    const auto warnings = harness.held->warnings();
    EXPECT_EQ(warnings.size(), expectedWarnings);
    if (throwing && !warnings.empty())
    {
      EXPECT_NE(warnings.front().message.find("User callback threw"), std::string::npos);
      EXPECT_NE(warnings.front().message.find("reference-type completion sentinel"), std::string::npos);
    }
  };
  check();
  if (!fast)
  {
    const auto calls = harness.held->calls;
    const auto warnings = harness.held->warnings();
    EXPECT_NO_THROW(harness.held->good());
    EXPECT_NO_THROW(harness.held->bad());
    EXPECT_NO_THROW(harness.drain(128));
    EXPECT_EQ(harness.held->calls, calls);
    EXPECT_EQ(harness.held->warnings(), warnings);
    check();
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-23-REFERENCE-TYPE-COMPLETION-IS-CONTAINED-ONCE, scope=function)
TEST(NamespaceCallerLifetimeDeathTest, ReferenceTypeCompletionIsContainedOnce)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  for (const bool cached : {false, true})
  {
    for (const auto path : {ReferenceTypePath::ExactMatch,
           ReferenceTypePath::SubtypesDisabled,
           ReferenceTypePath::CacheTrue,
           ReferenceTypePath::CacheFalse,
           ReferenceTypePath::DeferredTrue,
           ReferenceTypePath::DeferredFalse,
           ReferenceTypePath::Missing,
           ReferenceTypePath::LookupBad,
           ReferenceTypePath::LookupUncertain,
           ReferenceTypePath::OwnerlessInitial,
           ReferenceTypePath::OwnerlessReferences,
           ReferenceTypePath::OwnerlessParent})
    {
      for (const bool throwing : {false, true})
      {
        SCOPED_TRACE(cached);
        SCOPED_TRACE(name(path));
        SCOPED_TRACE(throwing);
        EXPECT_EXIT(
          {
            start_child();
            reference_type_completion_case(cached, path, throwing);
            finish_child();
          },
          ::testing::ExitedWithCode(0),
          "");
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-REFERENCE-WALK-PRESERVES-FULL-STATUS, scope=function)
TEST(NamespaceCallerLifetime, NestedReferenceWalkPreservesFullStatus)
{
  for (const bool cached : {false, true})
  {
    for (const auto stage : {TypeStage::InitialLookup, TypeStage::FirstReferences, TypeStage::FurtherLookup})
    {
      for (const bool uncertain : {false, true})
      {
        for (const bool informationBit : {false, true})
        {
          SCOPED_TRACE(cached);
          SCOPED_TRACE(utils::to_underlying(stage));
          SCOPED_TRACE(uncertain);
          SCOPED_TRACE(informationBit);
          LifetimeHarness harness;
          const auto child = harness.node("full-status-reference-child", NodeClass::ReferenceType);
          const auto parent =
            harness.node("full-status-reference-parent", NodeClass::ReferenceType).get_node_id();
          TypeInputs inputs{child, child.get_node_id(), parent, parent};
          harness.nameSpace->references.insert_or_assign(
            inputs.childId, reference_to(ReferenceTypeId::HasSubtype, inputs.parent, false));
          StatusCode refusal{Status::BadResourceUnavailable,
            ErrorDetail::build("ReferenceWalkStatusRefusal",
              "The namespace refused a reference-type answer",
              "NamespaceCallerLifetime")
              .context(ContextKeys::nodeId, inputs.childId)};
          if (uncertain)
          {
            refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
              ErrorDetail::build("ReferenceWalkStatusUncertain",
                "The namespace has no usable reference-type answer",
                "NamespaceCallerLifetime")
                .context(ContextKeys::nodeId, inputs.childId)};
          }
          refusal.semantics_changed(informationBit);
          EXPECT_EQ(refusal.semantics_changed(), informationBit);
          if (stage == TypeStage::FirstReferences)
          {
            harness.nameSpace->references.insert_or_assign(inputs.childId, NodeReferencesResult{refusal});
          }
          else
          {
            NodeId refused = inputs.childId;
            if (stage == TypeStage::FurtherLookup)
            {
              refused = inputs.parent;
            }
            harness.nameSpace->lookups.insert_or_assign(refused, NodeResult{refusal});
          }
          arm_type(harness, inputs, stage);
          const auto cache = std::make_shared<node_utils::RefTypeCache>();
          const auto key = std::make_pair(inputs.childId, inputs.target);
          const auto outcome = std::make_shared<AnswerObservation<BoolResult>>();
          if (cached)
          {
            EXPECT_NO_THROW(node_utils::is_ref_of_type_cached_async(EncodingLimits{},
              *harness.addressSpace,
              true,
              inputs.childId,
              inputs.target,
              cache,
              AnswerObservation<BoolResult>::callback(outcome)));
          }
          else
          {
            EXPECT_NO_THROW(node_utils::is_ref_of_type_async(EncodingLimits{},
              *harness.addressSpace,
              true,
              inputs.childId,
              inputs.target,
              AnswerObservation<BoolResult>::callback(outcome)));
          }
          EXPECT_NO_THROW(harness.drain(128));
          ASSERT_TRUE(harness.held->held);
          EXPECT_EQ(outcome->count, 0u);
          EXPECT_FALSE(cache->lookup(key).has_value());
          std::array<std::size_t, 3> expectedCalls{1, 0, 0};
          if (stage != TypeStage::InitialLookup)
          {
            expectedCalls[member_index(HeldMember::References)] = 1;
          }
          if (stage == TypeStage::FurtherLookup)
          {
            expectedCalls[member_index(HeldMember::Lookup)] = 2;
          }
          EXPECT_EQ(harness.held->calls, expectedCalls);
          EXPECT_NO_THROW(harness.held->good());
          EXPECT_NO_THROW(harness.drain(128));
          const auto check = [&]
          {
            EXPECT_EQ(outcome->count, 1u);
            EXPECT_EQ(harness.held->calls, expectedCalls);
            EXPECT_FALSE(cache->lookup(key).has_value());
            ASSERT_TRUE(outcome->answer.has_value());
            const auto& result = *outcome->answer;
            EXPECT_FALSE(result.is_good());
            if (uncertain)
            {
              // The walk decides a rule, so it refuses an Uncertain answer; its inner status keeps the bit.
              expect_uncertain_refused(result.status_code(), refusal);
            }
            else
            {
              EXPECT_EQ(result.status_code().value(), refusal.value());
              EXPECT_EQ(result.status_code().semantics_changed(), informationBit);
              if (stage == TypeStage::InitialLookup)
              {
                EXPECT_EQ(result.shared_detail(), refusal.shared_detail());
              }
              else
              {
                ASSERT_NE(result.shared_detail(), nullptr);
                EXPECT_EQ(result.shared_detail()->code, "DanglingHasSubtype");
                EXPECT_EQ(result.shared_detail()->innerStatus, refusal.value());
                EXPECT_EQ(result.shared_detail()->cause, refusal.shared_detail());
              }
            }
          };
          check();
          const auto calls = harness.held->calls;
          EXPECT_NO_THROW(harness.held->good());
          EXPECT_NO_THROW(harness.held->bad());
          EXPECT_NO_THROW(harness.drain(128));
          EXPECT_EQ(harness.held->calls, calls);
          check();
        }
      }
    }
  }
}

namespace
{

void complete_hierarchy(
  LifetimeHarness& harness, std::shared_ptr<EventBus>& bus, ChunkMode mode, bool deliverRefusal = false)
{
  const auto calls = harness.held->calls;
  const std::weak_ptr<EventBus> weakBus{bus};
  const auto weakSpace = harness.addressSpace->weak();
  const std::weak_ptr<ua::Namespace> weakNamespace{harness.nameSpace};
  if (mode == ChunkMode::Retained)
  {
    EXPECT_FALSE(weakBus.expired());
    EXPECT_TRUE(weakSpace.lock().has_value());
    EXPECT_FALSE(weakNamespace.expired());
  }
  else
  {
    // An ordinary Bus owns its AddressSpace; release it before testing operation ownership.
    bus.reset();
    harness.drain(256);
    EXPECT_TRUE(weakBus.expired()) << "the held hierarchy completion retains EventBus";
    harness.addressSpace.reset();
    if (mode == ChunkMode::BothGone)
    {
      harness.nameSpace.reset();
    }
    harness.drain(256);
    EXPECT_FALSE(weakSpace.lock().has_value()) << "the held hierarchy completion retains AddressSpace";
    if (mode == ChunkMode::BothGone)
    {
      EXPECT_TRUE(weakNamespace.expired()) << "the held hierarchy completion retains the namespace";
    }
    else
    {
      EXPECT_FALSE(weakNamespace.expired());
    }
  }
  if (mode != ChunkMode::BothGone)
  {
    if (deliverRefusal)
    {
      ASSERT_TRUE(harness.held->bad);
      harness.held->bad();
    }
    else
    {
      ASSERT_TRUE(harness.held->good);
      harness.held->good();
    }
    harness.drain(256);
  }
  if (mode != ChunkMode::Retained)
  {
    EXPECT_EQ(harness.held->calls, calls) << "the ownerless hierarchy issued another namespace operation";
  }
}

void expect_hierarchy_chain(const AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>& outcome,
  const std::vector<NodeId>& expected)
{
  EXPECT_EQ(outcome.count, 1u);
  ASSERT_TRUE(outcome.answer.has_value());
  ASSERT_NE(*outcome.answer, nullptr);
  EXPECT_EQ(**outcome.answer, expected);
}

void expect_hierarchy_warning(
  const LifetimeHarness& harness, const NodeId& eventType, const StatusCode& failure)
{
  const auto warnings = harness.held->warnings();
  ASSERT_EQ(warnings.size(), 1u);
  const auto& warning = warnings.front();
  EXPECT_EQ(warning.category, "events");
  ASSERT_TRUE(warning.fields.contains("status"));
  ASSERT_TRUE(warning.fields.contains("error"));
  EXPECT_EQ(warning.fields.at("status"), to_string(failure));
  std::string diagnostic{warning.message};
  for (const auto& [key, value] : warning.fields)
  {
    diagnostic += '\n';
    diagnostic += key;
    diagnostic += '=';
    diagnostic += value;
  }
  EXPECT_NE(diagnostic.find(to_string(eventType)), std::string::npos);
  const auto& error = warning.fields.at("error");
  if (const auto detail = failure.shared_detail())
  {
    const auto originalHeader = "[" + detail->source + "] " + detail->code + ": " + detail->summary;
    EXPECT_NE(error.find(originalHeader), std::string::npos);
    for (const auto& fact : detail->context)
    {
      EXPECT_NE(error.find(fact.key + " = " + fact.value), std::string::npos);
    }
  }
  else
  {
    EXPECT_EQ(failure, StatusCode{Status::BadShutdown});
    EXPECT_NE(error.find("AddressSpaceGone"), std::string::npos);
  }
}

void repeat_hierarchy_and_check(LifetimeHarness& harness,
  const std::shared_ptr<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>& outcome,
  const std::vector<NodeId>& expected)
{
  const auto calls = harness.held->calls;
  const auto referenceCalls = harness.held->referenceCalls.size();
  const auto warnings = harness.held->warnings();
  const auto releasedTokens = harness.held->releasedTokens;
  const auto completions = outcome->count;
  ASSERT_TRUE(harness.held->good);
  ASSERT_TRUE(harness.held->bad);
  harness.held->good();
  harness.held->bad();
  harness.drain(256);
  EXPECT_EQ(harness.held->calls, calls);
  EXPECT_EQ(harness.held->referenceCalls.size(), referenceCalls);
  EXPECT_EQ(harness.held->warnings(), warnings);
  EXPECT_EQ(harness.held->releasedTokens, releasedTokens);
  EXPECT_EQ(outcome->count, completions);
  expect_hierarchy_chain(*outcome, expected);
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EVENT-HIERARCHY-HELD-STAGES-RELEASE-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, EventHierarchyHeldStagesReleaseOwners)
{
  for (const auto& [stage, terminal] : {std::pair{EventStage::TypeLookup, false},
         std::pair{EventStage::TypeReferences, false},
         std::pair{EventStage::SupertypeLookup, false},
         std::pair{EventStage::TypeReferences, true},
         std::pair{EventStage::SupertypeReferences, true}})
  {
    for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
    {
      SCOPED_TRACE(utils::to_underlying(stage));
      SCOPED_TRACE(terminal);
      SCOPED_TRACE(utils::to_underlying(mode));
      LifetimeHarness harness;
      const auto inputs = event_inputs(harness, 0);
      const auto [member, heldId] = event_stage(inputs, stage);
      if (terminal)
      {
        harness.nameSpace->references.insert_or_assign(heldId, NodeReferences{References{}});
      }
      harness.arm(member, heldId);
      const auto outcome = std::make_shared<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>();
      auto bus = harness.start_event_hierarchy(inputs.type, outcome);
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(outcome->count, 0u);
      EXPECT_TRUE(harness.held->warnings().empty());
      complete_hierarchy(harness, bus, mode);

      std::vector<NodeId> expected{inputs.type};
      if (stage == EventStage::SupertypeReferences ||
          (stage == EventStage::SupertypeLookup && mode != ChunkMode::BothGone))
      {
        expected.push_back(inputs.supertype);
      }
      if (mode == ChunkMode::Retained && !terminal)
      {
        expected = {inputs.type, inputs.supertype, NodeId{ObjectTypeId::BaseEventType}};
      }
      expect_hierarchy_chain(*outcome, expected);
      if (mode == ChunkMode::BothGone)
      {
        expect_hierarchy_warning(harness, inputs.type, harness.refusal);
      }
      else if (mode == ChunkMode::Retained || terminal)
      {
        EXPECT_TRUE(harness.held->warnings().empty());
      }
      else
      {
        expect_hierarchy_warning(harness, inputs.type, StatusCode{Status::BadShutdown});
      }
      repeat_hierarchy_and_check(harness, outcome, expected);
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EVENT-HIERARCHY-FAILURES-REMAIN-OBSERVABLE, scope=function)
TEST(NamespaceCallerLifetime, EventHierarchyFailuresRemainObservable)
{
  for (const auto stage : {EventStage::TypeLookup, EventStage::TypeReferences, EventStage::SupertypeLookup})
  {
    for (const auto status :
      {Status::BadResourceUnavailable, Status::UncertainNoCommunicationLastUsableValue})
    {
      for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessBad, ChunkMode::BothGone})
      {
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(to_string(status));
        SCOPED_TRACE(utils::to_underlying(mode));
        StatusCode refusal{status,
          ErrorDetail::build("EventHierarchyBadRefusal",
            "The namespace refused the event hierarchy operation",
            "NamespaceCallerLifetime.EventHierarchy.Bad")
            .context(ContextKeys::nodeId, NodeId{2, "event-hierarchy-bad-sentinel"})
            .context(ContextKeys::operationIndex, utils::to_underlying(stage))};
        if (status == Status::UncertainNoCommunicationLastUsableValue)
        {
          refusal = StatusCode{status,
            ErrorDetail::build("EventHierarchyUncertainRefusal",
              "The namespace could not establish the event hierarchy answer",
              "NamespaceCallerLifetime.EventHierarchy.Uncertain")
              .context(ContextKeys::nodeId, NodeId{2, "event-hierarchy-uncertain-sentinel"})
              .context(ContextKeys::operationIndex, utils::to_underlying(stage))};
        }
        LifetimeHarness harness{refusal};
        const auto inputs = event_inputs(harness, 0);
        const auto [member, heldId] = event_stage(inputs, stage);
        harness.arm(member, heldId);
        const auto outcome =
          std::make_shared<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>();
        auto bus = harness.start_event_hierarchy(inputs.type, outcome);
        ASSERT_TRUE(harness.held->held);
        EXPECT_EQ(outcome->count, 0u);
        EXPECT_TRUE(harness.held->warnings().empty());
        complete_hierarchy(harness, bus, mode, true);
        const std::vector<NodeId> expected{inputs.type};
        expect_hierarchy_chain(*outcome, expected);
        expect_hierarchy_warning(harness, inputs.type, refusal);
        repeat_hierarchy_and_check(harness, outcome, expected);
      }
    }

    // A successful terminal answer is distinct from a refusal at each held stage.
    LifetimeHarness harness;
    const auto inputs = event_inputs(harness, 0);
    NodeId terminalType{inputs.type};
    std::vector<NodeId> expected{inputs.type};
    if (stage == EventStage::SupertypeLookup)
    {
      terminalType = inputs.supertype;
      expected.push_back(inputs.supertype);
    }
    harness.nameSpace->references.insert_or_assign(terminalType, NodeReferences{References{}});
    const auto [member, heldId] = event_stage(inputs, stage);
    harness.arm(member, heldId);
    const auto outcome = std::make_shared<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>();
    auto bus = harness.start_event_hierarchy(inputs.type, outcome);
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    complete_hierarchy(harness, bus, ChunkMode::Retained);
    expect_hierarchy_chain(*outcome, expected);
    EXPECT_TRUE(harness.held->warnings().empty());
    repeat_hierarchy_and_check(harness, outcome, expected);
  }
}

namespace
{

enum class DispatchStage
{
  ClimbLookup,
  ClimbReferences,
  ClimbPage,
  ReferenceTypeLookup,
  ReferenceTypeReferences,
  ReferenceTypeParentLookup,
  ReferenceTypeParentReferences,
  ViewLookup,
  ViewMembership
};

bool custom_dispatch_stage(DispatchStage stage)
{
  return stage == DispatchStage::ReferenceTypeLookup || stage == DispatchStage::ReferenceTypeReferences ||
         stage == DispatchStage::ReferenceTypeParentLookup ||
         stage == DispatchStage::ReferenceTypeParentReferences;
}

EventInputs dispatch_inputs(LifetimeHarness& harness, DispatchStage stage)
{
  auto inputs = event_inputs(harness, 0);
  const auto makeNotifier = [&harness](string_view name)
  {
    auto node = harness.node(name, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    if (!object)
    {
      throw std::runtime_error("fixture notifier is not an Object");
    }
    object->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    return node.get_node_id();
  };
  inputs.source = makeNotifier("dispatch-source");
  inputs.notifier = makeNotifier("dispatch-reached-notifier");
  harness.nameSpace->references.insert_or_assign(
    inputs.source, reference_to(ReferenceTypeId::HasNotifier, inputs.notifier, false));
  for (std::size_t i = 0; i < 3; ++i)
  {
    inputs.notifierParents.push_back(makeNotifier("dispatch-parent-" + std::to_string(i)));
    auto view = harness.node("dispatch-view-" + std::to_string(i), NodeClass::View);
    auto accessor = view.as<ViewAccessor>();
    if (!accessor)
    {
      throw std::runtime_error("fixture membership node is not a View");
    }
    accessor->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    inputs.views.push_back(view.get_node_id());
    harness.nameSpace->memberships.emplace(view.get_node_id(), std::vector<BoolResult>(6, BoolResult{true}));
  }
  inputs.eventSourceTypes.push_back(inputs.aggregate);
  for (std::size_t i = 1; i < 3; ++i)
  {
    const auto type = harness.node("dispatch-reference-type-" + std::to_string(i), NodeClass::ReferenceType);
    inputs.eventSourceTypes.push_back(type.get_node_id());
    harness.nameSpace->references.insert_or_assign(type.get_node_id(),
      reference_to(ReferenceTypeId::HasSubtype, NodeId{ReferenceTypeId::HasEventSource}, false));
  }
  harness.nameSpace->references.insert_or_assign(
    inputs.aggregate, reference_to(ReferenceTypeId::HasSubtype, inputs.aggregateSupertype, false));
  harness.nameSpace->references.insert_or_assign(inputs.aggregateSupertype,
    reference_to(ReferenceTypeId::HasSubtype, NodeId{ReferenceTypeId::HasEventSource}, false));
  std::vector<Reference> above;
  for (std::size_t i = 0; i < inputs.notifierParents.size(); ++i)
  {
    NodeId type{ReferenceTypeId::HasNotifier};
    if (custom_dispatch_stage(stage))
    {
      type = inputs.eventSourceTypes[i];
    }
    above.emplace_back(type, ExpandedNodeId{inputs.notifierParents[i]}, false);
  }
  harness.nameSpace->references.insert_or_assign(
    inputs.notifier, NodeReferences{References{std::move(above)}});
  for (const auto& parent : inputs.notifierParents)
  {
    harness.nameSpace->references.insert_or_assign(parent, NodeReferences{References{}});
  }
  const auto observe = [&inputs](const NodeId& node)
  {
    inputs.recipients.emplace(node, std::make_shared<AnswerObservation<std::shared_ptr<const BaseEvent>>>());
  };
  observe(NodeId{ObjectId::Server});
  observe(inputs.source);
  observe(inputs.notifier);
  for (const auto& parent : inputs.notifierParents)
  {
    observe(parent);
  }
  for (const auto& view : inputs.views)
  {
    observe(view);
  }
  return inputs;
}

std::pair<HeldMember, NodeId> dispatch_stage(const EventInputs& inputs, DispatchStage stage)
{
  switch (stage)
  {
  case DispatchStage::ClimbLookup:
    return {HeldMember::Lookup, inputs.notifierParents.front()};
  case DispatchStage::ClimbReferences:
  case DispatchStage::ClimbPage:
    return {HeldMember::References, inputs.notifierParents.front()};
  case DispatchStage::ReferenceTypeLookup:
    return {HeldMember::Lookup, inputs.aggregate};
  case DispatchStage::ReferenceTypeReferences:
    return {HeldMember::References, inputs.aggregate};
  case DispatchStage::ReferenceTypeParentLookup:
    return {HeldMember::Lookup, inputs.aggregateSupertype};
  case DispatchStage::ReferenceTypeParentReferences:
    return {HeldMember::References, inputs.aggregateSupertype};
  case DispatchStage::ViewLookup:
    return {HeldMember::Lookup, inputs.views.front()};
  case DispatchStage::ViewMembership:
    return {HeldMember::Membership, inputs.views.front()};
  }
  throw std::logic_error("unknown held dispatch stage");
}

BaseEvent dispatch_event(const EventInputs& inputs, uint16_t severity = 421)
{
  BaseEvent event;
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  event.sourceNode = inputs.source;
  event.sourceName = String{"Held dispatch source"};
  event.severity = severity;
  return event;
}

void expect_dispatch_hold(const LifetimeHarness& harness, const EventInputs& inputs, DispatchStage stage)
{
  ASSERT_TRUE(harness.held->held);
  ASSERT_EQ(harness.held->dispatchStarts, 1u);
  const auto [member, heldId] = dispatch_stage(inputs, stage);
  if (member == HeldMember::References)
  {
    ASSERT_FALSE(harness.held->referenceCalls.empty());
    const auto& queries = harness.held->referenceCalls.back().referenceQueries;
    const auto heldQuery = std::find_if(
      queries.begin(), queries.end(), [heldId](const auto& query) { return query.nodeId == heldId; });
    ASSERT_NE(heldQuery, queries.end());
    if (stage == DispatchStage::ClimbReferences || stage == DispatchStage::ClimbPage)
    {
      EXPECT_EQ(heldQuery->direction, BrowseDirection::Inverse);
      EXPECT_EQ(heldQuery->referenceTypeHint,
        (std::vector<NodeId>{NodeId{ReferenceTypeId::HasEventSource}, NodeId{ReferenceTypeId::HasNotifier}}));
    }
  }
  else if (member == HeldMember::Lookup)
  {
    ASSERT_FALSE(harness.held->lookupCalls.empty());
    const auto& queried = harness.held->lookupCalls.back();
    EXPECT_NE(std::find(queried.begin(), queried.end(), heldId), queried.end());
  }
  else
  {
    ASSERT_EQ(member, HeldMember::Membership);
    ASSERT_EQ(harness.held->membershipCalls.size(), inputs.views.size());
    const auto heldCall = std::find_if(harness.held->membershipCalls.begin(),
      harness.held->membershipCalls.end(),
      [heldId](const auto& call) { return call.view == heldId; });
    ASSERT_NE(heldCall, harness.held->membershipCalls.end());
    std::set<NodeId> subjects{inputs.source, inputs.notifier};
    for (const auto& parent : inputs.notifierParents)
    {
      subjects.emplace(parent);
    }
    std::set<NodeId> queried;
    for (const auto& candidate : heldCall->candidates)
    {
      EXPECT_TRUE(candidate.is_local());
      EXPECT_TRUE(candidate.is_index_based());
      queried.insert(candidate.node_id());
    }
    EXPECT_EQ(queried, subjects);
    EXPECT_EQ(heldCall->candidates.size(), subjects.size());
  }
}

std::shared_ptr<EventBus> start_dispatch(LifetimeHarness& harness, const EventInputs& inputs)
{
  harness.addressSpace->set_logger(
    Logger{harness.held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "dispatch-test"});
  auto bus = std::make_shared<EventBus>(*harness.addressSpace);
  bus->set_event_listener([held = harness.held](const BaseEvent&) { ++held->dispatchStarts; });
  IntegerId identifier{1};
  for (const auto& [node, answer] : inputs.recipients)
  {
    bus->register_event_item(
      node,
      identifier,
      0,
      [identifier,
        complete = AnswerObservation<std::shared_ptr<const BaseEvent>>::callback(answer, harness.held)](
        IntegerId actual,
        std::shared_ptr<const BaseEvent>
          event,
        std::shared_ptr<const event_type_model::DeclarationsResult>
          declarations) mutable
      {
        EXPECT_EQ(actual, identifier);
        EXPECT_EQ(declarations, nullptr);
        complete(std::move(event));
      },
      false);
    ++identifier;
  }
  auto event = dispatch_event(inputs);
  bus->emit(event);
  harness.drain(256);
  return bus;
}

void complete_dispatch(LifetimeHarness& harness, std::shared_ptr<EventBus>& bus, ChunkMode mode)
{
  const auto calls = harness.held->calls;
  const auto memberships = harness.held->membershipCalls.size();
  const std::weak_ptr<EventBus> weakBus{bus};
  const auto weakSpace = harness.addressSpace->weak();
  const std::weak_ptr<ua::Namespace> weakNamespace{harness.nameSpace};
  if (mode != ChunkMode::Retained)
  {
    bus.reset();
    harness.drain(256);
    EXPECT_TRUE(weakBus.expired()) << "started dispatch retains EventBus";
    harness.addressSpace.reset();
    if (mode == ChunkMode::BothGone)
    {
      harness.nameSpace.reset();
    }
    harness.drain(256);
    EXPECT_FALSE(weakSpace.lock().has_value()) << "started dispatch retains AddressSpace";
    if (mode == ChunkMode::BothGone)
    {
      EXPECT_TRUE(weakNamespace.expired()) << "started dispatch retains the namespace";
    }
    else
    {
      EXPECT_FALSE(weakNamespace.expired());
    }
  }
  else
  {
    EXPECT_FALSE(weakBus.expired());
    EXPECT_TRUE(weakSpace.lock().has_value());
    EXPECT_FALSE(weakNamespace.expired());
  }
  if (mode != ChunkMode::BothGone)
  {
    ASSERT_TRUE(harness.held->good);
    harness.held->good();
    harness.drain(256);
  }
  if (mode != ChunkMode::Retained)
  {
    EXPECT_EQ(harness.held->calls, calls) << "ownerless dispatch issued new namespace work";
    EXPECT_EQ(harness.held->membershipCalls.size(), memberships);
  }
}

std::set<NodeId> dispatch_recipients(const EventInputs& inputs, DispatchStage stage, ChunkMode mode,
  bool refused, bool limited = false, std::optional<NodeId> refusedView = std::nullopt)
{
  std::set<NodeId> eligible{NodeId{ObjectId::Server}, inputs.source, inputs.notifier};
  for (std::size_t i = 0; i < inputs.notifierParents.size(); ++i)
  {
    bool earned = mode == ChunkMode::Retained;
    if (stage == DispatchStage::ClimbReferences || stage == DispatchStage::ClimbPage ||
        stage == DispatchStage::ViewLookup || stage == DispatchStage::ViewMembership)
    {
      earned = true;
    }
    else if (stage == DispatchStage::ClimbLookup)
    {
      earned = mode != ChunkMode::BothGone && (!limited || i == 0 || mode == ChunkMode::Retained);
    }
    if (i == 0 && refused && (stage == DispatchStage::ClimbLookup || custom_dispatch_stage(stage)))
    {
      earned = false;
    }
    if (earned)
    {
      eligible.insert(inputs.notifierParents[i]);
    }
  }
  for (const auto& view : inputs.views)
  {
    bool earned = mode == ChunkMode::Retained;
    if (stage == DispatchStage::ViewMembership)
    {
      earned = mode != ChunkMode::BothGone || view != inputs.views.front();
    }
    if (stage == DispatchStage::ViewLookup && refused && refusedView == view)
    {
      earned = false;
    }
    if (earned)
    {
      eligible.insert(view);
    }
  }
  return eligible;
}

void expect_dispatch_deliveries(const EventInputs& inputs, const std::set<NodeId>& eligible,
  std::optional<std::size_t> releasesBeforeDelivery = std::nullopt)
{
  std::shared_ptr<const BaseEvent> sameEvent;
  for (const auto& [node, outcome] : inputs.recipients)
  {
    SCOPED_TRACE(to_string(node));
    if (!eligible.contains(node))
    {
      EXPECT_EQ(outcome->count, 0u);
      EXPECT_FALSE(outcome->answer.has_value());
      continue;
    }
    EXPECT_EQ(outcome->count, 1u);
    if (!outcome->answer || !*outcome->answer)
    {
      ADD_FAILURE() << "an established recipient did not receive the event";
      continue;
    }
    const auto& event = *outcome->answer;
    EXPECT_EQ(event->sourceNode, inputs.source);
    EXPECT_EQ(event->eventType, NodeId{ObjectTypeId::BaseEventType});
    EXPECT_EQ(event->severity, 421u);
    if (sameEvent)
    {
      EXPECT_EQ(event, sameEvent);
    }
    else
    {
      sameEvent = event;
    }
    if (releasesBeforeDelivery)
    {
      EXPECT_EQ(outcome->releasedTokensAtCompletion, releasesBeforeDelivery);
    }
  }
  ASSERT_NE(sameEvent, nullptr);
  ASSERT_NE(sameEvent->eventTypeHierarchy, nullptr);
  EXPECT_EQ(*sameEvent->eventTypeHierarchy, (std::vector<NodeId>{NodeId{ObjectTypeId::BaseEventType}}));
}

void expect_dispatch_refusal(const LifetimeHarness& harness, const StatusCode& failure, std::size_t count)
{
  ASSERT_NE(failure.shared_detail(), nullptr);
  const auto& detail = *failure.shared_detail();
  const auto header = "[" + detail.source + "] " + detail.code + ": " + detail.summary;
  std::size_t observed{0};
  for (const auto& warning : harness.held->warnings())
  {
    const auto error = warning.fields.find("error");
    if (error == warning.fields.end() || error->second.find(header) == std::string::npos)
    {
      continue;
    }
    ++observed;
    EXPECT_EQ(warning.category, "events");
    ASSERT_TRUE(warning.fields.contains("status"));
    // A declared wrapper may carry the original numeric status in its rich cause rather than at top level.
    const auto diagnostic = warning.fields.at("status") + '\n' + error->second;
    EXPECT_NE(diagnostic.find(to_string(failure)), std::string::npos);
    for (const auto& fact : detail.context)
    {
      EXPECT_NE(error->second.find(fact.key + " = " + fact.value), std::string::npos);
    }
  }
  EXPECT_EQ(observed, count);
}

void expect_dispatch_shutdown(const LifetimeHarness& harness, bool required)
{
  std::size_t observed{0};
  for (const auto& warning : harness.held->warnings())
  {
    const auto status = warning.fields.find("status");
    if (status == warning.fields.end() || status->second != to_string(StatusCode{Status::BadShutdown}))
    {
      continue;
    }
    ++observed;
    EXPECT_EQ(warning.category, "events");
    ASSERT_TRUE(warning.fields.contains("error"));
    EXPECT_NE(warning.fields.at("error").find("AddressSpaceGone"), std::string::npos);
  }
  if (required)
  {
    EXPECT_GT(observed, 0u);
  }
  else
  {
    EXPECT_EQ(observed, 0u);
  }
}

void repeat_dispatch_and_check(
  LifetimeHarness& harness, const EventInputs& inputs, const std::shared_ptr<HeldObservation>& held = {})
{
  auto observation = harness.held;
  if (held)
  {
    observation = held;
  }
  const auto calls = harness.held->calls;
  const auto lookups = harness.held->lookupCalls;
  const auto references = harness.held->referenceCalls.size();
  const auto memberships = harness.held->membershipCalls.size();
  const auto releases = harness.held->releasedTokens;
  const auto warnings = harness.held->warnings();
  std::map<NodeId, std::size_t> completions;
  std::map<NodeId, std::optional<std::shared_ptr<const BaseEvent>>> events;
  for (const auto& [node, outcome] : inputs.recipients)
  {
    completions.emplace(node, outcome->count);
    events.emplace(node, outcome->answer);
  }
  ASSERT_TRUE(observation->good);
  ASSERT_TRUE(observation->bad);
  observation->good();
  observation->bad();
  harness.drain(256);
  EXPECT_EQ(harness.held->calls, calls);
  EXPECT_EQ(harness.held->lookupCalls, lookups);
  EXPECT_EQ(harness.held->referenceCalls.size(), references);
  EXPECT_EQ(harness.held->membershipCalls.size(), memberships);
  EXPECT_EQ(harness.held->releasedTokens, releases);
  EXPECT_EQ(harness.held->warnings(), warnings);
  for (const auto& [node, outcome] : inputs.recipients)
  {
    EXPECT_EQ(outcome->count, completions.at(node));
    EXPECT_EQ(outcome->answer, events.at(node));
  }
}

void destroyed_dispatch_token_issuer()
{
  LifetimeHarness harness;
  auto inputs = dispatch_inputs(harness, DispatchStage::ClimbPage);
  const auto otherHeld = std::make_shared<HeldObservation>();
  auto otherNamespace = std::make_shared<FakeHoldingNamespace>(
    harness.context.get_executor(), otherHeld, harness.refusal, "urn:test:dispatch-held-second-namespace");
  const auto registered = std::make_shared<AnswerObservation<Result<uint16_t>>>();
  harness.addressSpace->add_namespace_async(
    otherNamespace, AnswerObservation<Result<uint16_t>>::callback(registered));
  harness.drain(256);
  ASSERT_EQ(registered->count, 1u);
  ASSERT_TRUE(registered->answer);
  ASSERT_TRUE(registered->answer->is_good());
  const NodeId otherParent{registered->answer->value(), "dispatch-other-parent"};
  otherNamespace->create_node(otherParent, NodeClass::Object);
  const auto found = std::make_shared<AnswerObservation<NodeAccessorResult>>();
  harness.addressSpace->find_node_async(otherParent, AnswerObservation<NodeAccessorResult>::callback(found));
  harness.drain(256);
  ASSERT_TRUE(found->answer);
  ASSERT_TRUE(found->answer->is_good());
  auto object = found->answer->value().as<ObjectAccessor>();
  ASSERT_TRUE(object);
  object->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  // An accessor owns its Node, not a namespace; leave only identity observations before owner release.
  object.reset();
  found->answer.reset();
  const auto oldParent = inputs.notifierParents[1];
  inputs.notifierParents[1] = otherParent;
  inputs.recipients.erase(oldParent);
  inputs.recipients.emplace(
    otherParent, std::make_shared<AnswerObservation<std::shared_ptr<const BaseEvent>>>());
  std::vector<Reference> above;
  for (const auto& parent : inputs.notifierParents)
  {
    above.emplace_back(NodeId{ReferenceTypeId::HasNotifier}, ExpandedNodeId{parent}, false);
  }
  harness.nameSpace->references.insert_or_assign(
    inputs.notifier, NodeReferences{References{std::move(above)}});
  const ByteString token{std::vector<uint8_t>{31, 32, 33}};
  harness.nameSpace->references.insert_or_assign(inputs.notifierParents[0],
    reference_to(ReferenceTypeId::HasNotifier, NodeId{ObjectId::Server}, false, token));
  otherHeld->member = HeldMember::References;
  otherHeld->nodeId = otherParent;
  otherNamespace->decline_single_lookups();
  harness.nameSpace->decline_single_lookups();
  auto bus = start_dispatch(harness, inputs);
  ASSERT_TRUE(otherHeld->held);
  ASSERT_EQ(harness.held->dispatchStarts, 1u);
  EXPECT_TRUE(harness.held->releasedTokens.empty());
  const auto calls = harness.held->calls;
  const auto otherCalls = otherHeld->calls;
  const auto weakSpace = harness.addressSpace->weak();
  const std::weak_ptr<EventBus> weakBus{bus};
  const std::weak_ptr<ua::Namespace> weakIssuer{harness.nameSpace};
  const std::weak_ptr<ua::Namespace> weakOther{otherNamespace};
  bus.reset();
  harness.drain(256);
  EXPECT_TRUE(weakBus.expired());
  harness.addressSpace.reset();
  harness.nameSpace.reset();
  otherNamespace.reset();
  harness.drain(256);
  EXPECT_FALSE(weakSpace.lock().has_value());
  EXPECT_TRUE(weakIssuer.expired());
  EXPECT_TRUE(weakOther.expired());
  EXPECT_EQ(harness.held->calls, calls);
  EXPECT_EQ(otherHeld->calls, otherCalls);
  EXPECT_TRUE(harness.held->releasedTokens.empty());
  EXPECT_TRUE(otherHeld->releasedTokens.empty());
  const auto eligible = dispatch_recipients(inputs, DispatchStage::ClimbPage, ChunkMode::BothGone, false);
  expect_dispatch_deliveries(inputs, eligible, 0);
  expect_dispatch_shutdown(harness, true);
  repeat_dispatch_and_check(harness, inputs, otherHeld);
  EXPECT_EQ(otherHeld->calls, otherCalls);
  EXPECT_TRUE(otherHeld->releasedTokens.empty());
}

std::size_t dispatch_lookups_of(const HeldObservation& observation, const NodeId& node)
{
  std::size_t count{0};
  for (const auto& call : observation.lookupCalls)
  {
    count += numeric_cast<std::size_t>(std::count(call.begin(), call.end(), node));
  }
  return count;
}

void dispatch_reference_type_refusal_cache(bool missing)
{
  LifetimeHarness harness;
  auto inputs = dispatch_inputs(harness, DispatchStage::ReferenceTypeLookup);
  const StatusCode refused{Status::BadResourceUnavailable,
    ErrorDetail::build("DispatchCacheRefusal",
      "The namespace could not resolve the application event-source type",
      "NamespaceCallerLifetime.DispatchCache")
      .context(ContextKeys::nodeId, inputs.aggregate)};
  if (missing)
  {
    inputs.aggregate = NodeId{harness.index, "dispatch-genuinely-missing-reference-type"};
    inputs.eventSourceTypes[0] = inputs.aggregate;
    std::vector<Reference> above;
    for (std::size_t i = 0; i < inputs.notifierParents.size(); ++i)
    {
      above.emplace_back(inputs.eventSourceTypes[i], ExpandedNodeId{inputs.notifierParents[i]}, false);
    }
    harness.nameSpace->references.insert_or_assign(
      inputs.notifier, NodeReferences{References{std::move(above)}});
  }
  else
  {
    harness.nameSpace->lookups.insert_or_assign(inputs.aggregate, NodeResult{refused});
  }
  harness.arm(HeldMember::Lookup, inputs.aggregate);
  auto bus = start_dispatch(harness, inputs);
  ASSERT_TRUE(harness.held->held);
  ASSERT_EQ(harness.held->dispatchStarts, 1u);
  complete_dispatch(harness, bus, ChunkMode::Retained);
  const auto firstEligible =
    dispatch_recipients(inputs, DispatchStage::ReferenceTypeLookup, ChunkMode::Retained, true);
  expect_dispatch_deliveries(inputs, firstEligible);
  if (!missing)
  {
    expect_dispatch_refusal(harness, refused, 1);
  }
  const auto warnings = harness.held->warnings();
  ASSERT_EQ(warnings.size(), 1u);
  EXPECT_EQ(warnings.front().category, "events");
  if (missing)
  {
    ASSERT_TRUE(warnings.front().fields.contains("status"));
    EXPECT_EQ(warnings.front().fields.at("status"), to_string(StatusCode{Status::BadNodeIdUnknown}));
  }
  const auto firstCalls = dispatch_lookups_of(*harness.held, inputs.aggregate);
  EXPECT_EQ(firstCalls, 1u);
  repeat_dispatch_and_check(harness, inputs);
  for (const auto& [node, outcome] : inputs.recipients)
  {
    (void)node;
    outcome->count = 0;
    outcome->answer.reset();
  }
  auto repeated = dispatch_event(inputs);
  bus->emit(repeated);
  harness.drain(256);
  expect_dispatch_deliveries(inputs, firstEligible);
  EXPECT_EQ(harness.held->warnings(), warnings) << "a failed custom type logged again in the same generation";
  auto expectedCalls = firstCalls;
  if (!missing)
  {
    ++expectedCalls;
  }
  EXPECT_EQ(dispatch_lookups_of(*harness.held, inputs.aggregate), expectedCalls);
  if (!missing)
  {
    // Change only the dependency's answer, not AddressSpace's model generation or the existing cache.
    harness.nameSpace->lookups.erase(inputs.aggregate);
    for (const auto& [node, outcome] : inputs.recipients)
    {
      (void)node;
      outcome->count = 0;
      outcome->answer.reset();
    }
    auto recovered = dispatch_event(inputs);
    bus->emit(recovered);
    harness.drain(256);
    expect_dispatch_deliveries(
      inputs, dispatch_recipients(inputs, DispatchStage::ReferenceTypeLookup, ChunkMode::Retained, false));
    EXPECT_EQ(dispatch_lookups_of(*harness.held, inputs.aggregate), expectedCalls + 1);
    EXPECT_EQ(harness.held->warnings(), warnings);
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EVENT-DISPATCH-HELD-STAGES-RELEASE-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, EventDispatchHeldStagesReleaseOwners)
{
  for (const auto stage : {DispatchStage::ClimbLookup,
         DispatchStage::ClimbReferences,
         DispatchStage::ClimbPage,
         DispatchStage::ReferenceTypeLookup,
         DispatchStage::ReferenceTypeReferences,
         DispatchStage::ReferenceTypeParentLookup,
         DispatchStage::ReferenceTypeParentReferences,
         DispatchStage::ViewLookup,
         DispatchStage::ViewMembership})
  {
    for (const bool limited : {false, true})
    {
      if (limited && stage != DispatchStage::ClimbLookup && stage != DispatchStage::ClimbReferences)
      {
        continue;
      }
      for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
      {
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(limited);
        SCOPED_TRACE(utils::to_underlying(mode));
        LifetimeHarness harness;
        const auto inputs = dispatch_inputs(harness, stage);
        const auto [member, heldId] = dispatch_stage(inputs, stage);
        const ByteString token{std::vector<uint8_t>{21, 22, 23}};
        if (stage == DispatchStage::ClimbPage)
        {
          harness.nameSpace->references.insert_or_assign(
            heldId, reference_to(ReferenceTypeId::HasNotifier, NodeId{ObjectId::Server}, false, token));
        }
        if (limited)
        {
          ServiceOperationLimits limits;
          if (member == HeldMember::Lookup)
          {
            limits.maxNodesPerRead = 1;
          }
          else
          {
            limits.maxNodesPerBrowse = 1;
          }
          harness.addressSpace->set_operation_limits(limits);
        }
        harness.arm(member, heldId);
        auto bus = start_dispatch(harness, inputs);
        ASSERT_TRUE(harness.held->held);
        ASSERT_EQ(harness.held->dispatchStarts, 1u);
        expect_dispatch_hold(harness, inputs, stage);
        for (const auto& [node, outcome] : inputs.recipients)
        {
          (void)node;
          EXPECT_EQ(outcome->count, 0u);
        }
        if (stage == DispatchStage::ViewMembership)
        {
          ASSERT_EQ(harness.held->membershipCalls.size(), inputs.views.size());
        }
        if (limited)
        {
          EXPECT_EQ(harness.held->heldAnswerCount, 1u);
          for (std::size_t i = 1; i < inputs.notifierParents.size(); ++i)
          {
            const auto& unissued = inputs.notifierParents[i];
            if (member == HeldMember::Lookup)
            {
              EXPECT_EQ(dispatch_lookups_of(*harness.held, unissued), 0u);
            }
            else
            {
              for (const auto& call : harness.held->referenceCalls)
              {
                for (const auto& query : call.referenceQueries)
                {
                  EXPECT_NE(query.nodeId, unissued);
                }
              }
            }
          }
        }
        complete_dispatch(harness, bus, mode);
        const auto eligible = dispatch_recipients(inputs, stage, mode, false, limited);
        std::size_t releases{0};
        if (stage == DispatchStage::ClimbPage && mode == ChunkMode::OwnerlessGood)
        {
          releases = 1;
          EXPECT_EQ(harness.held->releasedTokens, (std::vector<ByteString>{token}));
        }
        else
        {
          EXPECT_TRUE(harness.held->releasedTokens.empty());
        }
        expect_dispatch_deliveries(inputs, eligible, releases);
        if (mode == ChunkMode::Retained)
        {
          EXPECT_TRUE(harness.held->warnings().empty());
        }
        else
        {
          // A terminal refusal of every View lookup leaves no usable View requiring membership.
          expect_dispatch_shutdown(harness,
            stage != DispatchStage::ViewMembership &&
              !(stage == DispatchStage::ViewLookup && mode == ChunkMode::BothGone));
          if (mode == ChunkMode::BothGone)
          {
            expect_dispatch_refusal(harness, harness.refusal, harness.held->heldAnswerCount);
          }
        }
        std::size_t resumes{0};
        for (const auto& call : harness.held->referenceCalls)
        {
          for (const auto& query : call.referenceQueries)
          {
            if (query.resumeToken == token)
            {
              ++resumes;
            }
          }
        }
        std::size_t expectedResumes{0};
        if (stage == DispatchStage::ClimbPage && mode == ChunkMode::Retained)
        {
          expectedResumes = 1;
        }
        EXPECT_EQ(resumes, expectedResumes);
        repeat_dispatch_and_check(harness, inputs);
      }
    }
  }
  destroyed_dispatch_token_issuer();
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EVENT-DISPATCH-REFUSALS-REMAIN-OBSERVABLE, scope=function)
TEST(NamespaceCallerLifetime, EventDispatchRefusalsRemainObservable)
{
  for (const auto stage : {DispatchStage::ClimbLookup,
         DispatchStage::ClimbReferences,
         DispatchStage::ClimbPage,
         DispatchStage::ReferenceTypeLookup,
         DispatchStage::ReferenceTypeReferences,
         DispatchStage::ReferenceTypeParentLookup,
         DispatchStage::ReferenceTypeParentReferences,
         DispatchStage::ViewLookup,
         DispatchStage::ViewMembership})
  {
    for (const auto status :
      {Status::BadResourceUnavailable, Status::UncertainNoCommunicationLastUsableValue})
    {
      for (const auto mode : {ChunkMode::Retained, ChunkMode::OwnerlessGood, ChunkMode::BothGone})
      {
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(to_string(status));
        SCOPED_TRACE(utils::to_underlying(mode));
        StatusCode refusal{status,
          ErrorDetail::build("EventDispatchBadRefusal",
            "The namespace refused a received event dispatch answer",
            "NamespaceCallerLifetime.EventDispatch.Bad")
            .context(ContextKeys::nodeId, NodeId{2, "dispatch-bad-sentinel"})
            .context(ContextKeys::operationIndex, utils::to_underlying(stage))};
        if (status == Status::UncertainNoCommunicationLastUsableValue)
        {
          refusal = StatusCode{status,
            ErrorDetail::build("EventDispatchUncertainRefusal",
              "The namespace could not establish a received event dispatch answer",
              "NamespaceCallerLifetime.EventDispatch.Uncertain")
              .context(ContextKeys::nodeId, NodeId{2, "dispatch-uncertain-sentinel"})
              .context(ContextKeys::operationIndex, utils::to_underlying(stage))};
        }
        LifetimeHarness harness{refusal};
        const auto inputs = dispatch_inputs(harness, stage);
        const auto [member, heldId] = dispatch_stage(inputs, stage);
        harness.arm(member, heldId);
        if (stage == DispatchStage::ClimbPage)
        {
          const ByteString consumed{std::vector<uint8_t>{41, 42, 43}};
          harness.nameSpace->references.insert_or_assign(
            heldId, reference_to(ReferenceTypeId::HasNotifier, NodeId{ObjectId::Server}, false, consumed));
          harness.held->referenceTokenToHold = consumed;
        }
        if (mode != ChunkMode::BothGone)
        {
          harness.held->firstHeldRefusal = refusal;
        }
        auto bus = start_dispatch(harness, inputs);
        ASSERT_TRUE(harness.held->held);
        ASSERT_EQ(harness.held->dispatchStarts, 1u);
        expect_dispatch_hold(harness, inputs, stage);
        if (stage == DispatchStage::ClimbPage)
        {
          ASSERT_FALSE(harness.held->referenceCalls.empty());
          const auto& last = harness.held->referenceCalls.back().referenceQueries;
          ASSERT_EQ(last.size(), 1u);
          EXPECT_EQ(last.front().resumeToken, *harness.held->referenceTokenToHold);
        }
        if (stage == DispatchStage::ViewMembership)
        {
          ASSERT_EQ(harness.held->membershipCalls.size(), inputs.views.size());
          ASSERT_GT(harness.held->heldAnswerCount, 1u);
        }
        std::optional<NodeId> refusedView;
        if (stage == DispatchStage::ViewLookup && mode != ChunkMode::BothGone)
        {
          ASSERT_FALSE(harness.held->lookupCalls.empty());
          ASSERT_FALSE(harness.held->lookupCalls.back().empty());
          refusedView = harness.held->lookupCalls.back().front();
        }
        complete_dispatch(harness, bus, mode);
        const auto eligible = dispatch_recipients(inputs, stage, mode, true, false, refusedView);
        expect_dispatch_deliveries(inputs, eligible, 0);
        std::size_t refusedItems{1};
        if (mode == ChunkMode::BothGone)
        {
          refusedItems = harness.held->heldAnswerCount;
        }
        expect_dispatch_refusal(harness, refusal, refusedItems);
        EXPECT_TRUE(harness.held->releasedTokens.empty());
        repeat_dispatch_and_check(harness, inputs);
      }
    }
    // Each discard boundary has an independent terminal-success control.
    LifetimeHarness harness;
    const auto inputs = dispatch_inputs(harness, stage);
    const auto [member, heldId] = dispatch_stage(inputs, stage);
    harness.arm(member, heldId);
    if (stage == DispatchStage::ClimbPage)
    {
      const ByteString consumed{std::vector<uint8_t>{41, 42, 43}};
      harness.nameSpace->references.insert_or_assign(
        heldId, reference_to(ReferenceTypeId::HasNotifier, NodeId{ObjectId::Server}, false, consumed));
      harness.held->referenceTokenToHold = consumed;
    }
    auto bus = start_dispatch(harness, inputs);
    ASSERT_TRUE(harness.held->held);
    ASSERT_EQ(harness.held->dispatchStarts, 1u);
    expect_dispatch_hold(harness, inputs, stage);
    complete_dispatch(harness, bus, ChunkMode::Retained);
    expect_dispatch_deliveries(inputs, dispatch_recipients(inputs, stage, ChunkMode::Retained, false), 0);
    EXPECT_TRUE(harness.held->warnings().empty());
    repeat_dispatch_and_check(harness, inputs);
  }
  dispatch_reference_type_refusal_cache(false);
  dispatch_reference_type_refusal_cache(true);
}

namespace
{

// What the held References answer says of the Reference to be added: present with the requested type, with a
// subtype or with a conflicting type; absent; or refused Bad or Uncertain.
enum class HeldReferenceFact
{
  Exact,
  Subtype,
  Conflicting,
  Absent,
  Bad,
  Uncertain
};

std::string_view name(HeldReferenceFact value)
{
  switch (value)
  {
  case HeldReferenceFact::Exact:
    return "Exact";
  case HeldReferenceFact::Subtype:
    return "Subtype";
  case HeldReferenceFact::Conflicting:
    return "Conflicting";
  case HeldReferenceFact::Absent:
    return "Absent";
  case HeldReferenceFact::Bad:
    return "Bad";
  case HeldReferenceFact::Uncertain:
    return "Uncertain";
  }
  return "unknown";
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-REFERENCE-ADD-COMPOSITION-PRESERVES-TERMINAL-FACTS, scope=function)
TEST(NamespaceCallerLifetime, ReferenceAddCompositionPreservesTerminalFacts)
{
  for (const auto fact : {HeldReferenceFact::Exact,
         HeldReferenceFact::Subtype,
         HeldReferenceFact::Conflicting,
         HeldReferenceFact::Absent,
         HeldReferenceFact::Bad,
         HeldReferenceFact::Uncertain})
  {
    for (const bool ownerGone : {false, true})
    {
      SCOPED_TRACE(name(fact));
      SCOPED_TRACE(ownerGone);
      LifetimeHarness harness;
      const auto source = harness.node("terminal-add-source", NodeClass::Object);
      const auto sourceId = source.get_node_id();
      const auto targetId = harness.node("terminal-add-target", NodeClass::Object).get_node_id();
      const auto sourceNode = stored_node(source);
      ASSERT_NE(sourceNode, nullptr);
      const auto requiredOwner = harness.addressSpace->weak();
      const std::weak_ptr<ua::Namespace> weakNamespace{harness.nameSpace};
      NodeId requestedType{ReferenceTypeId::HasComponent};
      NodeId heldType{ReferenceTypeId::HasComponent};
      if (fact == HeldReferenceFact::Subtype)
      {
        heldType = NodeId{ReferenceTypeId::HasOrderedComponent};
      }
      else if (fact == HeldReferenceFact::Conflicting)
      {
        requestedType = NodeId{ReferenceTypeId::HasOrderedComponent};
      }
      const bool present = fact == HeldReferenceFact::Exact || fact == HeldReferenceFact::Subtype ||
                           fact == HeldReferenceFact::Conflicting;
      std::vector<Reference> expectedStored;
      if (present)
      {
        expectedStored.emplace_back(heldType, ExpandedNodeId{targetId}, true);
        const auto seeded = std::make_shared<AnswerObservation<VoidResult>>();
        sourceNode->add_reference_async(
          heldType, ExpandedNodeId{targetId}, true, AnswerObservation<VoidResult>::callback(seeded));
        harness.drain(128);
        ASSERT_EQ(seeded->count, 1u);
        ASSERT_TRUE(seeded->answer && seeded->answer->is_good());
      }
      StatusCode refusal{Status::BadResourceUnavailable,
        ErrorDetail::build("ReferenceAddTerminalRefusal",
          "The namespace could not provide the References fact",
          "NamespaceCallerLifetime")
          .context(ContextKeys::nodeId, sourceId)
          .cause(harness.refusal)};
      if (fact == HeldReferenceFact::Uncertain)
      {
        refusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
          ErrorDetail::build("ReferenceAddTerminalUncertain",
            "The namespace supplied no usable References fact",
            "NamespaceCallerLifetime")
            .context(ContextKeys::nodeId, sourceId)
            .cause(harness.refusal)};
      }
      refusal.semantics_changed(true);
      const bool refused = fact == HeldReferenceFact::Bad || fact == HeldReferenceFact::Uncertain;
      if (refused)
      {
        // This is an unsuccessful outer References Result, not an embedded quality on usable data.
        harness.nameSpace->references.insert_or_assign(sourceId, NodeReferencesResult{refusal});
      }
      else
      {
        harness.nameSpace->references.insert_or_assign(sourceId, NodeReferences{References{expectedStored}});
      }
      harness.addressSpace->set_logger(Logger{
        harness.held, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "reference-add-terminal"});
      harness.arm(HeldMember::References, sourceId);
      const auto outcome = std::make_shared<AnswerObservation<VoidResult>>();
      EXPECT_NO_THROW(ua::detail::NodeAccessorRoute::add_reference_if_not_present(source,
        requestedType,
        targetId,
        true,
        AnswerObservation<VoidResult>::callback(outcome),
        requiredOwner));
      EXPECT_NO_THROW(harness.drain(128));
      ASSERT_TRUE(harness.held->held);
      EXPECT_EQ(outcome->count, 0u);
      EXPECT_EQ(harness.held->calls, (std::array<std::size_t, 3>{0, 1, 0}));
      EXPECT_TRUE(harness.held->referenceAdditions.empty());
      const auto issued = harness.held->calls;
      const auto good = harness.held->good;
      const auto bad = harness.held->bad;
      ASSERT_TRUE(good);
      ASSERT_TRUE(bad);
      if (ownerGone)
      {
        harness.addressSpace.reset();
        EXPECT_NO_THROW(harness.drain(128));
        EXPECT_FALSE(requiredOwner.lock().has_value());
      }
      else
      {
        EXPECT_TRUE(requiredOwner.lock().has_value());
      }
      EXPECT_FALSE(weakNamespace.expired());
      EXPECT_NO_THROW(good());
      EXPECT_NO_THROW(harness.drain(128));
      ASSERT_EQ(outcome->count, 1u);
      ASSERT_TRUE(outcome->answer);
      if (fact == HeldReferenceFact::Uncertain)
      {
        // The read decides whether to add, so an Uncertain answer is refused instead of passed on.
        expect_uncertain_refused(outcome->answer->status_code(), refusal, "ReferencesAnswerUncertain");
      }
      else if (refused)
      {
        EXPECT_EQ(outcome->answer->status_code().value(), refusal.value());
        EXPECT_EQ(outcome->answer->shared_detail(), refusal.shared_detail());
      }
      else if (fact == HeldReferenceFact::Conflicting)
      {
        EXPECT_EQ(outcome->answer->status_code(), StatusCode{Status::BadDuplicateReferenceNotAllowed});
        ASSERT_NE(outcome->answer->shared_detail(), nullptr);
        const auto& detail = *outcome->answer->shared_detail();
        EXPECT_EQ(detail.code, "DuplicateReferenceOfAnotherType");
        ASSERT_EQ(detail.context.size(), 3u);
        std::map<std::string, std::string> identities;
        for (const auto& field : detail.context)
        {
          identities.emplace(field.key, field.value);
        }
        EXPECT_EQ(identities.at(std::string{ContextKeys::typeActual.value()}), to_string(heldType));
        EXPECT_EQ(identities.at(std::string{ContextKeys::typeExpected.value()}), to_string(requestedType));
        EXPECT_EQ(identities.at(std::string{ContextKeys::nodeId.value()}), to_string(targetId));
      }
      else if (fact == HeldReferenceFact::Absent && ownerGone)
      {
        expect_owner_gone(outcome->answer->status_code());
      }
      else
      {
        EXPECT_TRUE(outcome->answer->is_good());
        EXPECT_EQ(outcome->answer->status_code(), StatusCode{});
      }
      if (fact == HeldReferenceFact::Absent && !ownerGone)
      {
        // The address space adds the hierarchical Reference's other half in the target's namespace (NR-30
        // rule 2).
        ASSERT_EQ(harness.held->referenceAdditions.size(), 2u);
        const auto& addition = harness.held->referenceAdditions.front();
        EXPECT_EQ(addition.source, sourceId);
        EXPECT_EQ(addition.referenceType, requestedType);
        EXPECT_EQ(addition.target, ExpandedNodeId{targetId});
        EXPECT_TRUE(addition.isForward);
        const auto& other = harness.held->referenceAdditions.back();
        EXPECT_EQ(other.source, targetId);
        EXPECT_EQ(other.referenceType, requestedType);
        EXPECT_EQ(other.target, ExpandedNodeId{sourceId});
        EXPECT_FALSE(other.isForward);
        EXPECT_EQ(harness.held->calls[member_index(HeldMember::References)], 1u);
        EXPECT_EQ(harness.held->calls[member_index(HeldMember::Value)], 0u);
        expectedStored.emplace_back(requestedType, ExpandedNodeId{targetId}, true);
      }
      else
      {
        EXPECT_EQ(harness.held->calls, issued);
        EXPECT_TRUE(harness.held->referenceAdditions.empty());
      }
      // Check the real Node store before and after copied answers, without locking either owner.
      const auto completedCalls = harness.held->calls;
      const auto completedAdditions = harness.held->referenceAdditions.size();
      const auto status = outcome->answer->status_code();
      const auto detail = outcome->answer->shared_detail();
      for (const bool duplicated : {false, true})
      {
        if (duplicated)
        {
          EXPECT_NO_THROW(good());
          EXPECT_NO_THROW(bad());
          EXPECT_NO_THROW(good());
          EXPECT_NO_THROW(harness.drain(128));
        }
        const auto stored = std::make_shared<AnswerObservation<NodeAccessor::ReferencesResult>>();
        sourceNode->get_references_async(AnswerObservation<NodeAccessor::ReferencesResult>::callback(stored));
        harness.drain(128);
        ASSERT_EQ(stored->count, 1u);
        ASSERT_TRUE(stored->answer && stored->answer->is_good());
        const auto actual = stored->answer->value().span();
        ASSERT_EQ(actual.size(), expectedStored.size());
        for (std::size_t i = 0; i < actual.size(); ++i)
        {
          EXPECT_EQ(actual[i].type_id(), expectedStored[i].type_id());
          EXPECT_EQ(actual[i].target_id(), expectedStored[i].target_id());
          EXPECT_EQ(actual[i].is_forward(), expectedStored[i].is_forward());
        }
        EXPECT_EQ(outcome->count, 1u);
        EXPECT_EQ(outcome->answer->status_code(), status);
        EXPECT_EQ(outcome->answer->shared_detail(), detail);
        EXPECT_EQ(harness.held->calls, completedCalls);
        EXPECT_EQ(harness.held->referenceAdditions.size(), completedAdditions);
        EXPECT_TRUE(harness.held->releasedTokens.empty());
        EXPECT_TRUE(harness.held->warnings().empty());
      }
    }
  }
}

namespace
{

// The holding namespace answers a References read only from its scripted map. This enters each
// Reference forward on its source and inverse on its target, so a walk in either direction finds it.
class ScriptedReferences
{
public:
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    mReferences[source].push_back(Reference{NodeId{type}, ExpandedNodeId{target}, true});
    mReferences[target].push_back(Reference{NodeId{type}, ExpandedNodeId{source}, false});
  }

  void apply(FakeHoldingNamespace& nameSpace) const
  {
    for (const auto& [nodeId, references] : mReferences)
    {
      nameSpace.references.insert_or_assign(nodeId, NodeReferences{References{references}, ByteString{}});
    }
  }

private:
  std::map<NodeId, std::vector<Reference>> mReferences;
};

NodeId named(const LifetimeHarness& harness, string_view identifier)
{
  return NodeId{harness.index, std::string{identifier}};
}

// A Node of the holding namespace with the namespace-0 BrowseName and DisplayName @p browseName.
NodeAccessor labelled(
  LifetimeHarness& harness, string_view identifier, NodeClass nodeClass, string_view browseName)
{
  auto node = harness.node(identifier, nodeClass);
  node.set_browse_name(QualifiedName{0, std::string{browseName}});
  node.set_display_name(LocalizedText{"", std::string{browseName}});
  return node;
}

void script_value(LifetimeHarness& harness, const NodeId& nodeId, Variant value)
{
  harness.nameSpace->values.insert_or_assign(nodeId, DataValue{std::move(value)});
}

// EnumValues of a MultiStateValueDiscrete Variable: 1 is "Low", 2 is "High".
Variant enum_values()
{
  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  return Variant{std::move(entries)};
}

// A MultiStateValueDiscrete Variable whose Value is 2, with its EnumValues, EnumDictionaryEntries and
// ValueAsText Properties.
struct MultiStateNodes
{
  NodeAccessor owner;
  NodeAccessor valueAsText;
};

MultiStateNodes multi_state_variable(LifetimeHarness& harness)
{
  auto owner = labelled(harness, "owner", NodeClass::Variable, "State");
  const auto enumValues = labelled(harness, "enumValues", NodeClass::Variable, "EnumValues");
  const auto dictionary = labelled(harness, "dictionary", NodeClass::Variable, "EnumDictionaryEntries");
  auto valueAsText = labelled(harness, "valueAsText", NodeClass::Variable, "ValueAsText");
  ScriptedReferences topology;
  for (const auto& property : {enumValues, dictionary, valueAsText})
  {
    topology.link(owner.get_node_id(), ReferenceTypeId::HasProperty, property.get_node_id());
  }
  topology.apply(*harness.nameSpace);
  script_value(harness, owner.get_node_id(), Variant{int64_t{2}});
  script_value(harness, enumValues.get_node_id(), enum_values());
  script_value(harness,
    dictionary.get_node_id(),
    Variant{Array<NodeId>{Dimensions{2, 1}, {named(harness, "lowEntry"), named(harness, "highEntry")}}});
  return MultiStateNodes{std::move(owner), std::move(valueAsText)};
}

// A FiniteStateMachine "machine" in state "first", whose Method "advance" causes the transition to
// "second", and which is the SubStateMachine of "owningState", the current state of "parentMachine".
struct MachineNodes
{
  NodeAccessor machine;
  NodeAccessor method;
  NodeAccessor currentState;
  NodeAccessor currentStateId;
};

MachineNodes state_machine(LifetimeHarness& harness)
{
  const auto type = labelled(harness, "machineType", NodeClass::ObjectType, "MachineType");
  auto machine = labelled(harness, "machine", NodeClass::Object, "Machine");
  const auto declaredMethod = labelled(harness, "declaredAdvance", NodeClass::Method, "Advance");
  auto method = labelled(harness, "advance", NodeClass::Method, "Advance");
  auto currentState = labelled(harness, "currentState", NodeClass::Variable, "CurrentState");
  auto currentStateId = labelled(harness, "currentStateId", NodeClass::Variable, "Id");
  const auto first = labelled(harness, "first", NodeClass::Object, "First");
  const auto second = labelled(harness, "second", NodeClass::Object, "Second");
  const auto transition = labelled(harness, "firstToSecond", NodeClass::Object, "FirstToSecond");
  const auto firstNumber = labelled(harness, "firstNumber", NodeClass::Variable, "StateNumber");
  const auto secondNumber = labelled(harness, "secondNumber", NodeClass::Variable, "StateNumber");
  const auto parentMachine = labelled(harness, "parentMachine", NodeClass::Object, "ParentMachine");
  const auto owningState = labelled(harness, "owningState", NodeClass::Object, "OwningState");
  const auto parentCurrentState =
    labelled(harness, "parentCurrentState", NodeClass::Variable, "CurrentState");
  const auto parentCurrentStateId = labelled(harness, "parentCurrentStateId", NodeClass::Variable, "Id");

  ScriptedReferences topology;
  topology.link(machine.get_node_id(), ReferenceTypeId::HasTypeDefinition, type.get_node_id());
  topology.link(machine.get_node_id(), ReferenceTypeId::HasComponent, currentState.get_node_id());
  topology.link(machine.get_node_id(), ReferenceTypeId::HasComponent, method.get_node_id());
  topology.link(currentState.get_node_id(), ReferenceTypeId::HasProperty, currentStateId.get_node_id());
  for (const auto& component : {declaredMethod, first, second, transition})
  {
    topology.link(type.get_node_id(), ReferenceTypeId::HasComponent, component.get_node_id());
  }
  topology.link(first.get_node_id(), ReferenceTypeId::HasProperty, firstNumber.get_node_id());
  topology.link(second.get_node_id(), ReferenceTypeId::HasProperty, secondNumber.get_node_id());
  topology.link(transition.get_node_id(), ReferenceTypeId::HasCause, declaredMethod.get_node_id());
  topology.link(transition.get_node_id(), ReferenceTypeId::FromState, first.get_node_id());
  topology.link(transition.get_node_id(), ReferenceTypeId::ToState, second.get_node_id());
  topology.link(owningState.get_node_id(), ReferenceTypeId::HasSubStateMachine, machine.get_node_id());
  topology.link(parentMachine.get_node_id(), ReferenceTypeId::HasComponent, owningState.get_node_id());
  topology.link(parentMachine.get_node_id(), ReferenceTypeId::HasComponent, parentCurrentState.get_node_id());
  topology.link(
    parentCurrentState.get_node_id(), ReferenceTypeId::HasProperty, parentCurrentStateId.get_node_id());
  topology.apply(*harness.nameSpace);

  script_value(harness, currentStateId.get_node_id(), Variant{first.get_node_id()});
  script_value(harness, firstNumber.get_node_id(), Variant{uint32_t{1}});
  script_value(harness, secondNumber.get_node_id(), Variant{uint32_t{2}});
  script_value(harness, parentCurrentStateId.get_node_id(), Variant{owningState.get_node_id()});
  return MachineNodes{
    std::move(machine), std::move(method), std::move(currentState), std::move(currentStateId)};
}

class RecordingEventSink final : public EventSink
{
public:
  void emit(BaseEvent&) override
  {
    ++emitted;
  }

  std::size_t emitted{0};
};

// The answer CALLS-21 allows a caller whose owners were released while a namespace held its stage: the
// namespace's refusal, or Bad_Shutdown with AddressSpaceGone when it needed a further namespace operation.
void expect_refusal_or_owner_gone(const StatusCode& actual, const StatusCode& refusal)
{
  if (actual == StatusCode{Status::BadShutdown})
  {
    expect_owner_gone(actual);
  }
  else
  {
    expect_refusal(actual, refusal);
  }
}

// One entry point of a held-stage criterion. `fixture` builds the Nodes and answers the Node whose
// `member` stage the namespace holds; `start` calls the entry point and answers whatever the caller itself
// still holds of the work (a model, a runtime), which is released with the owners.
template<typename Answer>
struct HeldCase
{
  std::string_view name;
  HeldMember member;
  std::function<NodeAccessor(LifetimeHarness&)> fixture;
  std::function<std::shared_ptr<void>(LifetimeHarness&, const NodeAccessor&, std::function<void(Answer)>)>
    start;
  std::function<void(const Answer&)> expectControl;
  // When set, a further run releases only the address space while the namespace stays alive and answers the
  // held stage Good, and this checks the one answer the caller receives.
  std::function<void(const Answer&)> expectSpaceGone{};
};

// The answer of a composed operation whose next step found the address space gone (CALLS-21 rule 2):
// Bad_Shutdown, AddressSpaceGone, or AccessorWithoutAddressSpace when that step went through an accessor.
void expect_space_gone(const StatusCode& actual)
{
  EXPECT_EQ(actual, StatusCode{Status::BadShutdown}) << to_string(actual);
  ASSERT_NE(actual.shared_detail(), nullptr);
  EXPECT_TRUE(actual.shared_detail()->code == "AddressSpaceGone" ||
              actual.shared_detail()->code == "AccessorWithoutAddressSpace")
    << actual.shared_detail()->code;
}

// The owners are released while the stage is held, and the caller answers once with the refusal or
// AddressSpaceGone; the control keeps the owners, answers the held stage and the caller answers its value.
template<typename Answer>
void run_held_case(const HeldCase<Answer>& heldCase)
{
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(heldCase.name);
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    const auto subject = heldCase.fixture(harness);
    harness.arm(heldCase.member, subject.get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<Answer>>();
    auto callerHandles = heldCase.start(harness, subject, AnswerObservation<Answer>::callback(outcome));
    harness.drain();
    ASSERT_TRUE(harness.held->held);
    EXPECT_EQ(outcome->count, 0u);
    if (retainOwners)
    {
      harness.held->good();
      harness.drain();
    }
    else
    {
      callerHandles.reset();
      harness.drop_owners();
    }
    EXPECT_EQ(outcome->count, 1u);
    if (outcome->answer)
    {
      if (retainOwners)
      {
        heldCase.expectControl(*outcome->answer);
      }
      else
      {
        expect_refusal_or_owner_gone(outcome->answer->status_code(), harness.refusal);
      }
    }
    repeat_and_check(harness, outcome);
  }
  if (!heldCase.expectSpaceGone)
  {
    return;
  }
  SCOPED_TRACE(heldCase.name);
  SCOPED_TRACE("address space released, namespace answers Good");
  LifetimeHarness harness;
  const auto subject = heldCase.fixture(harness);
  harness.arm(heldCase.member, subject.get_node_id());
  const auto outcome = std::make_shared<AnswerObservation<Answer>>();
  auto callerHandles = heldCase.start(harness, subject, AnswerObservation<Answer>::callback(outcome));
  harness.drain();
  ASSERT_TRUE(harness.held->held);
  callerHandles.reset();
  harness.drop_space();
  harness.held->good();
  harness.drain();
  EXPECT_EQ(outcome->count, 1u);
  if (outcome->answer)
  {
    heldCase.expectSpaceGone(*outcome->answer);
  }
}

using ProjectedText = data_access_projection::OptionalLocalizedTextResult;
using ProjectedDictionary = data_access_projection::OptionalDictionarySnapshotResult;

boost::asio::strand<boost::asio::any_io_executor> caller_strand(LifetimeHarness& harness)
{
  return boost::asio::make_strand(boost::asio::any_io_executor{harness.context.get_executor()});
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-VALUE-AS-TEXT-AND-SEMANTICS-WORK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldValueAsTextAndSemanticsWorkReleasesOwners)
{
  run_held_case(HeldCase<DataValueResult>{.name = "project_value_as_text_async, Value read held",
    .member = HeldMember::Value,
    .fixture = [](LifetimeHarness& harness) { return multi_state_variable(harness).owner; },
    .start =
      [](LifetimeHarness& harness, const NodeAccessor& owner, std::function<void(DataValueResult)> complete)
      -> std::shared_ptr<void>
    {
      instance_utils::project_value_as_text_async(
        *harness.addressSpace, owner.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const DataValueResult& answer)
    {
      ASSERT_TRUE(answer.is_good());
      const auto* text = answer.value().value().try_as<LocalizedText>();
      ASSERT_NE(text, nullptr);
      EXPECT_EQ(*text, (LocalizedText{"", "High"}));
    },
    .expectSpaceGone =
      [](const auto& answer)
    {
      expect_space_gone(answer.status_code());
    }});

  run_held_case(HeldCase<VoidResult>{.name = "wire_value_as_text_async, References read held",
    .member = HeldMember::References,
    .fixture = [](LifetimeHarness& harness) { return multi_state_variable(harness).owner; },
    .start = [](LifetimeHarness& harness, const NodeAccessor& owner, std::function<void(VoidResult)> complete)
      -> std::shared_ptr<void>
    {
      instance_utils::wire_value_as_text_async(
        *harness.addressSpace, owner.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl = [](const VoidResult& answer)
    { EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code()); },
    .expectSpaceGone =
      [](const auto& answer)
    {
      expect_space_gone(answer.status_code());
    }});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-DATA-ACCESS-PROJECTION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldDataAccessProjectionReleasesOwners)
{
  run_held_case(HeldCase<ProjectedText>{.name = "value_as_text_async, Property References read held",
    .member = HeldMember::References,
    .fixture = [](LifetimeHarness& harness) { return multi_state_variable(harness).valueAsText; },
    .start =
      [](LifetimeHarness& harness, const NodeAccessor& property, std::function<void(ProjectedText)> complete)
      -> std::shared_ptr<void>
    {
      data_access_projection::value_as_text_async(
        *harness.addressSpace, property, caller_strand(harness), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const ProjectedText& answer)
    {
      ASSERT_TRUE(answer.is_good());
      ASSERT_TRUE(answer.value().has_value());
      EXPECT_EQ(*answer.value(), (LocalizedText{"", "High"}));
    }});

  run_held_case(
    HeldCase<ProjectedDictionary>{.name = "dictionary_snapshot_async, Property References read held",
      .member = HeldMember::References,
      .fixture = [](LifetimeHarness& harness) { return multi_state_variable(harness).valueAsText; },
      .start = [](LifetimeHarness& harness,
                 const NodeAccessor& property,
                 std::function<void(ProjectedDictionary)>
                   complete) -> std::shared_ptr<void>
      {
        data_access_projection::dictionary_snapshot_async(
          *harness.addressSpace, property, caller_strand(harness), std::move(complete));
        return nullptr;
      },
      .expectControl =
        [](const ProjectedDictionary& answer)
      {
        ASSERT_TRUE(answer.is_good());
        ASSERT_TRUE(answer.value().has_value());
        EXPECT_EQ(answer.value()->currentValue, 2);
        ASSERT_EQ(answer.value()->enumValues.size(), 2u);
        EXPECT_EQ(answer.value()->enumValues[1].displayName, (LocalizedText{"", "High"}));
      }});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-STATE-MACHINE-WORK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldStateMachineWorkReleasesOwners)
{
  run_held_case(
    HeldCase<OptionalMethodExecutableResult>{.name = "Method Executable evaluation, Method lookup held",
      .member = HeldMember::Lookup,
      .fixture = [](LifetimeHarness& harness) { return state_machine(harness).method; },
      .start = [](LifetimeHarness& harness,
                 const NodeAccessor& method,
                 std::function<void(OptionalMethodExecutableResult)>
                   complete) -> std::shared_ptr<void>
      {
        evaluate_state_machine_method_executable_async(
          *harness.addressSpace, method.get_node_id(), std::move(complete));
        return nullptr;
      },
      .expectControl =
        [](const OptionalMethodExecutableResult& answer)
      {
        ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
        EXPECT_EQ(answer.value(), std::optional<bool>{true});
      }});

  run_held_case(HeldCase<OptionalStateMachineActiveResult>{
    .name = "state Variable activity evaluation, Variable lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return state_machine(harness).currentState; },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& variable,
               std::function<void(OptionalStateMachineActiveResult)>
                 complete) -> std::shared_ptr<void>
    {
      evaluate_state_machine_variable_active_async(
        *harness.addressSpace, variable.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const OptionalStateMachineActiveResult& answer)
    {
      ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
      EXPECT_EQ(answer.value(), std::optional<bool>{true});
    }});

  run_held_case(HeldCase<StateMachineTransitionResolutionResult>{
    .name = "model transition resolution, machine lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return state_machine(harness).machine; },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& machine,
               std::function<void(StateMachineTransitionResolutionResult)>
                 complete) -> std::shared_ptr<void>
    {
      auto model = make_address_space_state_machine_model(*harness.addressSpace);
      model->resolve_transition_async(machine.get_node_id(), named(harness, "advance"), std::move(complete));
      return model;
    },
    .expectControl =
      [](const StateMachineTransitionResolutionResult& answer)
    {
      ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
      EXPECT_TRUE(answer.value().methodIsCause);
      ASSERT_TRUE(answer.value().enabledTransition.has_value());
      EXPECT_EQ(answer.value().enabledTransition->toState.name, (QualifiedName{0, "Second"}));
    },
    .expectSpaceGone =
      [](const auto& answer)
    {
      expect_space_gone(answer.status_code());
    }});

  // The commit's first lookup is of the CurrentState Id Property it writes first.
  run_held_case(HeldCase<VoidResult>{.name = "model transition commit, CurrentState Id lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return state_machine(harness).currentStateId; },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& currentStateId,
               std::function<void(VoidResult)>
                 complete) -> std::shared_ptr<void>
    {
      StateMachineTransitionDescriptor transition;
      transition.machineId = named(harness, "machine");
      transition.transitionId = named(harness, "firstToSecond");
      transition.transitionName = QualifiedName{0, "FirstToSecond"};
      transition.eventTypes = {NodeId{ObjectTypeId::TransitionEventType}};
      transition.fromState = StateMachineStateDescriptor{.id = named(harness, "first"),
        .name = QualifiedName{0, "First"},
        .number = 1,
        .effectiveDisplayName = LocalizedText{"", "First"}};
      transition.toState = StateMachineStateDescriptor{.id = named(harness, "second"),
        .name = QualifiedName{0, "Second"},
        .number = 2,
        .effectiveDisplayName = LocalizedText{"", "Second"}};
      transition.currentStateVariableId = named(harness, "currentState");
      transition.currentStateIdPropertyId = currentStateId.get_node_id();
      auto model = make_address_space_state_machine_model(*harness.addressSpace);
      model->commit_transition_async(transition, std::move(complete));
      return model;
    },
    .expectControl =
      [](const VoidResult& answer)
    {
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
    }});

  run_held_case(HeldCase<VoidResult>{
    .name = "StateMachineRuntime transition after a Method, machine lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return state_machine(harness).machine; },
    .start =
      [](LifetimeHarness& harness, const NodeAccessor& machine, std::function<void(VoidResult)> complete)
      -> std::shared_ptr<void>
    {
      auto sink = std::make_shared<RecordingEventSink>();
      auto runtime = StateMachineRuntime::create(
        harness.context.get_executor(), make_address_space_state_machine_model(*harness.addressSpace), sink);
      runtime->transition_after_method_async(
        machine.get_node_id(), named(harness, "advance"), std::move(complete));
      return std::make_shared<
        std::pair<std::shared_ptr<RecordingEventSink>, std::shared_ptr<StateMachineRuntime>>>(
        std::move(sink), std::move(runtime));
    },
    .expectControl =
      [](const VoidResult& answer)
    {
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
    }});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-METHOD-AND-FILE-SETUP-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldMethodSetupReleasesOwners)
{
  run_held_case(HeldCase<Result<MethodAccessor>>{.name = "add_method_async, parent lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return harness.node("parent", NodeClass::Object); },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& parent,
               std::function<void(Result<MethodAccessor>)>
                 complete) -> std::shared_ptr<void>
    {
      ua::add_method_async(
        *harness.addressSpace,
        parent.get_node_id(),
        QualifiedName{0, "Added"},
        ua::inputs(),
        ua::outputs(),
        [](const MethodCall&) -> MethodResult<> { return {}; },
        std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const Result<MethodAccessor>& answer)
    {
      ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
      EXPECT_EQ(answer.value().get_browse_name(), (QualifiedName{0, "Added"}));
    }});

  run_held_case(HeldCase<VoidResult>{.name = "bind_method_async, Method lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness)
    { return labelled(harness, "method", NodeClass::Method, "Bound"); },
    .start = [](
               LifetimeHarness& harness, const NodeAccessor& method, std::function<void(VoidResult)> complete)
      -> std::shared_ptr<void>
    {
      ua::bind_method_async(
        *harness.addressSpace,
        method.get_node_id(),
        ua::inputs(),
        ua::outputs(),
        [](const MethodCall&) -> MethodResult<> { return {}; },
        std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const VoidResult& answer)
    {
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
    }});
}

namespace
{

// A Node "instance" of the holding namespace whose HasTypeDefinition is @p typeDefinition, with, when
// @p propertyName is given, a Property "property" of that BrowseName whose type is PropertyType.
NodeAccessor typed_instance(LifetimeHarness& harness, NodeClass nodeClass, const NodeId& typeDefinition,
  std::optional<string_view> propertyName = std::nullopt)
{
  auto instance = labelled(harness, "instance", nodeClass, "Instance");
  ScriptedReferences topology;
  topology.link(instance.get_node_id(), ReferenceTypeId::HasTypeDefinition, typeDefinition);
  if (propertyName)
  {
    const auto property = labelled(harness, "property", NodeClass::Variable, *propertyName);
    topology.link(instance.get_node_id(), ReferenceTypeId::HasProperty, property.get_node_id());
    topology.link(
      property.get_node_id(), ReferenceTypeId::HasTypeDefinition, NodeId{VariableTypeId::PropertyType});
  }
  topology.apply(*harness.nameSpace);
  return instance;
}

template<typename Handle>
void expect_handle_of(const Result<Handle>& answer, string_view identifier)
{
  ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
  EXPECT_EQ(answer.value().node_id().identifier().get_string(), String{std::string{identifier}});
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-TYPED-HANDLE-WORK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldTypedHandleWorkReleasesOwners)
{
  run_held_case(HeldCase<AnalogItemResult>{.name = "AnalogItem::attach_async, instance lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness)
    { return typed_instance(harness, NodeClass::Variable, NodeId{VariableTypeId::AnalogItemType}); },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& instance,
               std::function<void(AnalogItemResult)>
                 complete) -> std::shared_ptr<void>
    {
      AnalogItem::attach_async(*harness.addressSpace, instance.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const AnalogItemResult& answer)
    {
      expect_handle_of(answer, "instance");
    }});

  run_held_case(HeldCase<AlarmGroupResult>{.name = "AlarmGroup::attach_async, instance lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness)
    { return typed_instance(harness, NodeClass::Object, NodeId{ObjectTypeId::AlarmGroupType}); },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& instance,
               std::function<void(AlarmGroupResult)>
                 complete) -> std::shared_ptr<void>
    {
      AlarmGroup::attach_async(*harness.addressSpace, instance.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const AlarmGroupResult& answer)
    {
      expect_handle_of(answer, "instance");
    }});

  // The handle is attached before the stage is armed; the test keeps no copy of it once the accessor is
  // called.
  const auto handle = std::make_shared<std::optional<AnalogItem>>();
  run_held_case(
    HeldCase<PropertyResult>{.name = "AnalogItem::eu_range_property_async, instance References read held",
      .member = HeldMember::References,
      .fixture =
        [handle](LifetimeHarness& harness)
      {
        auto instance =
          typed_instance(harness, NodeClass::Variable, NodeId{VariableTypeId::AnalogItemType}, "EURange");
        const auto attached = std::make_shared<AnswerObservation<AnalogItemResult>>();
        AnalogItem::attach_async(*harness.addressSpace,
          instance.get_node_id(),
          AnswerObservation<AnalogItemResult>::callback(attached));
        harness.drain();
        if (!attached->answer || !attached->answer->is_good())
        {
          throw std::runtime_error("fixture AnalogItem attach failed");
        }
        handle->emplace(std::move(*attached->answer).value());
        return instance;
      },
      .start = [handle](LifetimeHarness& /*harness*/,
                 const NodeAccessor& /*instance*/,
                 std::function<void(PropertyResult)>
                   complete) -> std::shared_ptr<void>
      {
        auto item = std::move(handle->value());
        handle->reset();
        item.eu_range_property_async(std::move(complete));
        return nullptr;
      },
      .expectControl =
        [](const PropertyResult& answer)
      {
        expect_handle_of(answer, "property");
      }});

  run_held_case(HeldCase<BaseObjectResult>{.name = "BaseObject::attach_async, instance lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness)
    { return typed_instance(harness, NodeClass::Object, NodeId{ObjectTypeId::BaseObjectType}); },
    .start = [](LifetimeHarness& harness,
               const NodeAccessor& instance,
               std::function<void(BaseObjectResult)>
                 complete) -> std::shared_ptr<void>
    {
      BaseObject::attach_async(*harness.addressSpace, instance.get_node_id(), std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const BaseObjectResult& answer)
    {
      expect_handle_of(answer, "instance");
    }});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-NODESET-IMPORT-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldNodeSetImportReleasesOwners)
{
  // One Object of the holding namespace, which the import looks up before creating anything.
  static constexpr std::string_view nodeSet = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:namespace-caller-lifetime</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;s=imported" BrowseName="1:Imported"/>
</UANodeSet>)";
  memory_stream_device::ExternalReadOnly device{
    utils::span_of_char_to_span_of_byte(span<const char>{nodeSet.data(), nodeSet.size()})};
  MemoryStream input{device};
  const auto parsed = try_parse_nodeset_sync(input, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << to_string(parsed.status_code());
  const auto document = parsed.value();

  run_held_case(HeldCase<Result<NodeSetImportSummary>>{.name = "import_nodeset_async, Node lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return harness.node("imported", NodeClass::Object); },
    .start = [document](LifetimeHarness& harness,
               const NodeAccessor& /*imported*/,
               std::function<void(Result<NodeSetImportSummary>)>
                 complete) -> std::shared_ptr<void>
    {
      import_nodeset_async(*harness.addressSpace, document, NodeSetImportOptions{}, std::move(complete));
      return nullptr;
    },
    .expectControl =
      [](const Result<NodeSetImportSummary>& answer)
    {
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
    }});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-EVENT-GRAPH-CHECK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldEventGraphCheckReleasesOwners)
{
  run_held_case(HeldCase<VoidResult>{.name = "validate_event_graph_async, Node lookup held",
    .member = HeldMember::Lookup,
    .fixture = [](LifetimeHarness& harness) { return harness.node("graphed", NodeClass::Object); },
    .start =
      [](LifetimeHarness& harness, const NodeAccessor& /*graphed*/, std::function<void(VoidResult)> complete)
      -> std::shared_ptr<void>
    {
      harness.addressSpace->validate_event_graph_async(std::move(complete));
      return nullptr;
    },
    .expectControl = [](const VoidResult& answer)
    { EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code()); },
    .expectSpaceGone =
      [](const VoidResult& answer)
    {
      expect_space_gone(answer.status_code());
    }});
}

namespace
{

// A Session over the harness's address space, for the services: an identity with no Roles on an unsecured
// channel. A service holds its Session weakly, so a test releases it with the owners, as closing it would.
class LifetimeSession final : public SessionInfo, public SessionSecurityContext
{
public:
  explicit LifetimeSession(AddressSpace addressSpace)
    : mAddressSpace(std::move(addressSpace)),
      mApplication(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default()))
  {
    auto user = std::make_shared<UserIdentity>();
    user->kind = UserTokenKind::Anonymous;
    user->userId = "lifetime";
    auto endpoint = std::make_shared<EndpointSecurityContext>();
    endpoint->messageSecurityMode = MessageSecurityMode::None;
    endpoint->securityPolicyId = SecurityPolicyId::None;
    mUser = user;
    mEndpoint = endpoint;
    mIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{1},
      std::vector<NodeId>{},
      std::move(user),
      std::move(endpoint),
      String{"urn:test:client"});
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mApplication;
  }

  const ServerConfig& server_configuration() const override
  {
    return mServer;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(*mEndpoint, *mUser, mServer.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  NodeId session_id() const override
  {
    return NodeId{uint16_t{1}, uint32_t{4242}};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mEndpoint;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mIdentity;
  }

private:
  AddressSpace mAddressSpace;
  std::shared_ptr<const ApplicationConfig> mApplication;
  ServerConfig mServer;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const EndpointSecurityContext> mEndpoint;
  std::shared_ptr<const AccessIdentity> mIdentity;
};

// Accepts every authorized change without making it: the tests observe the checks the service makes before.
class AcceptingNodeManagement final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const Context>, AddressSpace, std::vector<AuthorizedAddNode> items,
    AddNodesCompleteCallback callback) override
  {
    BatchResult<AddNodesItemResult> answer;
    for (const auto& authorized : items)
    {
      AddNodesResult added;
      added.added_node_id() = authorized.item.requested_new_node_id().node_id();
      answer.items.emplace_back(std::move(added));
    }
    callback(std::move(answer));
  }

  void add_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<AddReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    callback(accepted(items.size()));
  }

  void delete_nodes_async(std::shared_ptr<const Context>, AddressSpace, std::vector<DeleteNodesItem> items,
    NodeMgmtCompleteCallback callback) override
  {
    callback(accepted(items.size()));
  }

  void delete_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    callback(accepted(items.size()));
  }

private:
  static BatchResult<VoidResult> accepted(std::size_t count)
  {
    BatchResult<VoidResult> answer;
    answer.items.resize(count);
    return answer;
  }
};

NodeReferencesResult one_reference(const NodeId& type, const NodeId& target, bool forward)
{
  return NodeReferences{
    References{std::vector<Reference>{Reference{type, ExpandedNodeId{target}, forward}}}, {}};
}

// The node-management checks whose walks the tests hold, each reached by the request that makes it.
enum class NodeManagementCheck
{
  InterfaceType,
  HierarchicalSelfReference,
  HasChildClassification,
  HasChildPath,
  BrowseNameCollision
};

// Builds the Nodes and References that lead @p check's walk to a lookup only it makes, starts the request,
// and answers the service; @p heldNodeId receives the NodeId whose lookup the walk makes.
shared_ptr<NodeManagementService> start_node_management(LifetimeHarness& harness, NodeManagementCheck check,
  const std::shared_ptr<LifetimeSession>& session, const std::shared_ptr<NodeManagementDelegate>& delegate,
  NodeId& heldNodeId, std::function<void(Response)> complete)
{
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  const auto referenceItem =
    [](const NodeId& source, const NodeId& type, const NodeId& target, NodeClass targetClass)
  {
    AddReferencesItem item;
    item.source_node_id() = source;
    item.reference_type_id() = type;
    item.is_forward() = true;
    item.target_node_id() = ExpandedNodeId{target};
    item.target_node_class() = targetClass;
    return item;
  };
  AddReferencesRequest references;
  references.request_header().request_handle() = 1;
  switch (check)
  {
  case NodeManagementCheck::InterfaceType:
  {
    // HasTypeDefinition asks whether the target is an Interface: the walk climbs from the type to its
    // supertype.
    const auto instance = harness.node("instance", NodeClass::Object);
    const auto type = harness.node("type", NodeClass::ObjectType);
    const auto supertype = harness.node("supertype", NodeClass::ObjectType);
    harness.nameSpace->references.insert_or_assign(
      type.get_node_id(), one_reference(hasSubtype, supertype.get_node_id(), false));
    heldNodeId = supertype.get_node_id();
    references.references_to_add().push_back(referenceItem(instance.get_node_id(),
      NodeId{ReferenceTypeId::HasTypeDefinition},
      type.get_node_id(),
      NodeClass::ObjectType));
    break;
  }
  case NodeManagementCheck::HierarchicalSelfReference:
  {
    // A self-reference asks whether its ReferenceType is hierarchical.
    const auto source = harness.node("source", NodeClass::Object);
    const auto selfReference = harness.node("selfReference", NodeClass::ReferenceType);
    const auto superReference = harness.node("superReference", NodeClass::ReferenceType);
    harness.nameSpace->references.insert_or_assign(
      selfReference.get_node_id(), one_reference(hasSubtype, superReference.get_node_id(), false));
    heldNodeId = superReference.get_node_id();
    references.references_to_add().push_back(referenceItem(
      source.get_node_id(), selfReference.get_node_id(), source.get_node_id(), NodeClass::Object));
    break;
  }
  case NodeManagementCheck::HasChildClassification:
  {
    // Every Reference is asked whether its ReferenceType is a HasChild.
    const auto source = harness.node("source", NodeClass::Object);
    const auto target = harness.node("target", NodeClass::Object);
    const auto childReference = harness.node("childReference", NodeClass::ReferenceType);
    const auto superReference = harness.node("superReference", NodeClass::ReferenceType);
    harness.nameSpace->references.insert_or_assign(
      childReference.get_node_id(), one_reference(hasSubtype, superReference.get_node_id(), false));
    heldNodeId = superReference.get_node_id();
    references.references_to_add().push_back(referenceItem(
      source.get_node_id(), childReference.get_node_id(), target.get_node_id(), NodeClass::Object));
    break;
  }
  case NodeManagementCheck::HasChildPath:
  {
    // A HasChild asks whether its target already reaches its source through HasChild: the walk follows the
    // target's HasChild to its child.
    const auto source = harness.node("source", NodeClass::Object);
    const auto target = harness.node("target", NodeClass::Object);
    const auto child = harness.node("child", NodeClass::Object);
    const auto componentReference = harness.node("componentReference", NodeClass::ReferenceType);
    harness.nameSpace->references.insert_or_assign(
      componentReference.get_node_id(), one_reference(hasSubtype, NodeId{ReferenceTypeId::HasChild}, false));
    harness.nameSpace->references.insert_or_assign(
      target.get_node_id(), one_reference(componentReference.get_node_id(), child.get_node_id(), true));
    heldNodeId = child.get_node_id();
    references.references_to_add().push_back(referenceItem(
      source.get_node_id(), componentReference.get_node_id(), target.get_node_id(), NodeClass::Object));
    break;
  }
  case NodeManagementCheck::BrowseNameCollision:
  {
    // AddNodes asks whether the parent already has a child of the new Node's BrowseName: the walk looks up
    // the parent's children.
    const auto parent = harness.node("parent", NodeClass::Object);
    const auto type = harness.node("type", NodeClass::ObjectType);
    const auto existing = harness.node("existing", NodeClass::Object);
    const auto organizesReference = harness.node("organizesReference", NodeClass::ReferenceType);
    harness.nameSpace->references.insert_or_assign(organizesReference.get_node_id(),
      one_reference(hasSubtype, NodeId{ReferenceTypeId::HierarchicalReferences}, false));
    harness.nameSpace->references.insert_or_assign(
      parent.get_node_id(), one_reference(organizesReference.get_node_id(), existing.get_node_id(), true));
    heldNodeId = existing.get_node_id();
    AddNodesItem item;
    item.parent_node_id() = ExpandedNodeId{parent.get_node_id()};
    item.reference_type_id() = organizesReference.get_node_id();
    item.requested_new_node_id() = ExpandedNodeId{NodeId{harness.index, std::string{"added"}}};
    item.browse_name() = QualifiedName{harness.index, "Added"};
    item.node_class() = NodeClass::Object;
    item.type_definition() = ExpandedNodeId{type.get_node_id()};
    AddNodesRequest nodes;
    nodes.request_header().request_handle() = 1;
    nodes.nodes_to_add().push_back(std::move(item));
    return NodeManagementService::create(
      session, delegate, 1, std::move(nodes), harness.context.get_executor(), std::move(complete));
  }
  }
  return NodeManagementService::create(
    session, delegate, 1, std::move(references), harness.context.get_executor(), std::move(complete));
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-NODE-MANAGEMENT-CHECKS-RELEASE-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldNodeManagementChecksReleaseOwners)
{
  for (const auto check : {NodeManagementCheck::InterfaceType,
         NodeManagementCheck::HierarchicalSelfReference,
         NodeManagementCheck::HasChildClassification,
         NodeManagementCheck::HasChildPath,
         NodeManagementCheck::BrowseNameCollision})
  {
    for (const bool retainOwners : {false, true})
    {
      SCOPED_TRACE(static_cast<int>(check));
      SCOPED_TRACE(retainOwners);
      LifetimeHarness harness;
      harness.nameSpace->decline_immediate_permissions();
      auto session = std::make_shared<LifetimeSession>(*harness.addressSpace);
      std::shared_ptr<NodeManagementDelegate> delegate = std::make_shared<AcceptingNodeManagement>();
      const auto responses = std::make_shared<std::vector<Response>>();
      NodeId heldNodeId;
      auto service = start_node_management(harness,
        check,
        session,
        delegate,
        heldNodeId,
        [responses](Response response) { responses->push_back(std::move(response)); });
      ASSERT_NE(service, nullptr);
      // Armed after the request is built: the walk's lookup is the first of this Node.
      harness.arm(HeldMember::Lookup, heldNodeId);
      harness.drain();
      ASSERT_TRUE(harness.held->held) << "the request did not reach the walk's lookup of "
                                      << to_string(heldNodeId) << "; answered " << responses->size();
      EXPECT_TRUE(responses->empty());
      if (retainOwners)
      {
        harness.held->good();
        harness.drain();
        ASSERT_EQ(responses->size(), 1u);
        EXPECT_EQ(dynamic_cast<ServiceFault*>(responses->front().second.get()), nullptr);
      }
      else
      {
        // The Session closes: its requests and the Session go, then the server's handles.
        service.reset();
        session.reset();
        delegate.reset();
        harness.drop_owners();
        // The held answer arrives with no one left to take it.
        harness.held->good();
        harness.drain();
        EXPECT_TRUE(responses->empty());
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-HISTORY-READ-DATA-TYPE-WALK-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldHistoryReadDataTypeWalkReleasesOwners)
{
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    harness.nameSpace->decline_immediate_permissions();
    // A dataEncoding asks whether the Variable's DataType is a Structure: the walk climbs from the DataType
    // to its supertype.
    auto variable = harness.node("historized", NodeClass::Variable);
    const auto structure = harness.node("structure", NodeClass::DataType);
    const auto superStructure = harness.node("superStructure", NodeClass::DataType);
    harness.nameSpace->references.insert_or_assign(structure.get_node_id(),
      one_reference(NodeId{ReferenceTypeId::HasSubtype}, superStructure.get_node_id(), false));
    auto accessor = variable.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::HistoryRead);
    accessor->set_access_level(accessLevel);
    accessor->set_data_type(structure.get_node_id());
    harness.drain();

    HistoryReadRequest request;
    request.request_header().request_handle() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    auto details = std::make_unique<ReadRawModifiedDetails>();
    details->start_time() = DateTime{DateTime::min()};
    details->end_time() = DateTime::now();
    details->num_values_per_node() = 10;
    request.history_read_details() = std::move(details);
    request.nodes_to_read().resize(1);
    request.nodes_to_read()[0].node_id() = variable.get_node_id();
    request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

    auto session = std::make_shared<LifetimeSession>(*harness.addressSpace);
    HistoryContinuationPoints continuationPoints;
    const auto responses = std::make_shared<std::size_t>(0);
    harness.arm(HeldMember::Lookup, superStructure.get_node_id());
    auto service = HistoryReadService::create(session,
      {},
      1,
      std::move(request),
      continuationPoints,
      harness.context.get_executor(),
      [responses](HistoryReadService::HistoryReadServiceResponse) { ++*responses; });
    ASSERT_NE(service, nullptr);
    harness.drain();
    ASSERT_TRUE(harness.held->held) << "the request did not reach the DataType walk; answered " << *responses;
    EXPECT_EQ(*responses, 0u);
    if (retainOwners)
    {
      harness.held->good();
      harness.drain();
      EXPECT_EQ(*responses, 1u);
    }
    else
    {
      service.reset();
      session.reset();
      harness.drop_owners();
      harness.held->good();
      harness.drain();
      EXPECT_EQ(*responses, 0u);
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-REPUBLISH-PROJECTION-RELEASES-OWNERS, scope=function)
TEST(NamespaceCallerLifetime, HeldRepublishProjectionReleasesOwners)
{
  for (const bool retainOwners : {false, true})
  {
    SCOPED_TRACE(retainOwners);
    LifetimeHarness harness;
    harness.nameSpace->decline_immediate_permissions();
    const auto variable = harness.node("republished", NodeClass::Variable);
    auto session = std::make_shared<LifetimeSession>(*harness.addressSpace);
    auto subscription = Subscription::create(
      1, 1'000'000.0, 100, 3, 0, true, 0, harness.context.get_executor(), [](IntegerId) {}, [](IntegerId) {});
    subscription->configure_access_recheck(
      std::chrono::milliseconds{0}, session, harness.addressSpace->weak(), {});

    // One retained Value, re-authorized for the Session that asks to have it republished.
    NotificationMessage message;
    message.sequence_number() = 7;
    message.publish_time() = DateTime::now();
    auto dataChange = std::make_unique<DataChangeNotification>();
    MonitoredItemNotification retained;
    retained.client_handle() = 11;
    retained.value() = DataValue{Variant{int32_t{5}}};
    dataChange->monitored_items().push_back(std::move(retained));
    RefStructure<Structure> notification;
    notification.inner_unique_ptr() = std::move(dataChange);
    message.notification_data().push_back(std::move(notification));
    std::vector<RetainedDataProjection> projections{
      RetainedDataProjection{1, variable.get_node_id(), AttributeId::Value, DataValue{Variant{int32_t{5}}}}};

    harness.arm(HeldMember::Lookup, variable.get_node_id());
    const auto outcome = std::make_shared<AnswerObservation<Result<NotificationMessage>>>();
    subscription->reauthorize_notification_async(std::move(message),
      {},
      std::move(projections),
      AnswerObservation<Result<NotificationMessage>>::callback(outcome));
    harness.drain();
    ASSERT_TRUE(harness.held->held) << "the Republish did not reach its lookup; answered " << outcome->count;
    EXPECT_EQ(outcome->count, 0u);
    if (retainOwners)
    {
      harness.held->good();
      harness.drain();
      ASSERT_EQ(outcome->count, 1u);
      ASSERT_TRUE(outcome->answer.has_value());
      EXPECT_TRUE(outcome->answer->is_good()) << to_string(outcome->answer->status_code());
    }
    else
    {
      subscription.reset();
      session.reset();
      harness.drop_owners();
      EXPECT_EQ(outcome->count, 1u);
      if (outcome->answer)
      {
        EXPECT_TRUE(outcome->answer->is_bad());
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-ACCESS-CONTROL-HOLDS-NO-OWNER, scope=function)
TEST(NamespaceCallerLifetime, AnAccessControlKeptAcrossAHeldAuthorizationHoldsNoOwner)
{
  LifetimeHarness harness;
  const auto variable = harness.node("variable", NodeClass::Variable);
  harness.nameSpace->decline_immediate_permissions();
  harness.arm(HeldMember::Permissions, variable.get_node_id());
  EndpointSecurityContext channel;
  channel.messageSecurityMode = MessageSecurityMode::None;
  // Kept, as a Republish keeps the one it re-authorizes with, while the owners are released.
  const AccessControl accessControl{*harness.addressSpace, std::chrono::milliseconds{60000}};
  const auto first = std::make_shared<AnswerObservation<std::vector<AccessControl::Verdict>>>();
  const std::array items{AccessControl::Item{.node = variable, .operation = AccessOperation::Read}};
  accessControl.authorize_async(RequestInfo{},
    roleless_identity(),
    items,
    channel,
    AnswerObservation<std::vector<AccessControl::Verdict>>::callback(first));
  harness.drain();
  ASSERT_TRUE(harness.held->held);
  harness.drop_owners();
  EXPECT_EQ(first->count, 1u);

  // A decision asked of it afterwards is refused for the address space it no longer has (CALLS-21 rule 2).
  const auto later = std::make_shared<AnswerObservation<std::vector<AccessControl::Verdict>>>();
  accessControl.authorize_async(RequestInfo{},
    roleless_identity(),
    items,
    channel,
    AnswerObservation<std::vector<AccessControl::Verdict>>::callback(later));
  harness.drain();
  ASSERT_EQ(later->count, 1u);
  ASSERT_TRUE(later->answer.has_value());
  ASSERT_EQ(later->answer->size(), 1u);
  EXPECT_FALSE(later->answer->front().permitted);
  expect_space_gone(later->answer->front().cause);
}

// @relation(AC-COMP-SVR-EVENTDECL-06-A-HIERARCHY-THAT-FAILED-IS-NOT-KEPT, scope=function)
TEST(NamespaceCallerLifetime, AnEventTypeHierarchyThatFailedIsReadAgain)
{
  LifetimeHarness harness{StatusCode{Status::BadResourceUnavailable}};
  const auto inputs = event_inputs(harness, 0);
  harness.nameSpace->references.insert_or_assign(inputs.supertype, NodeReferences{References{}});
  const auto [member, heldId] = event_stage(inputs, EventStage::SupertypeLookup);
  harness.arm(member, heldId);
  const auto failed = std::make_shared<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>();
  auto bus = harness.start_event_hierarchy(inputs.type, failed);
  ASSERT_TRUE(harness.held->held);
  harness.held->bad();
  harness.drain(256);
  expect_hierarchy_chain(*failed, std::vector<NodeId>{inputs.type});

  // Asked again with the model unchanged, the chain is read again, and the supertype now answers.
  const auto again = std::make_shared<AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>>();
  EventBusTestAccess::post_on_strand(bus,
    [eventType = inputs.type,
      complete = AnswerObservation<std::shared_ptr<const std::vector<NodeId>>>::callback(again)](
      auto& guarded) mutable { guarded.resolve_event_type_hierarchy(eventType, std::move(complete)); });
  harness.drain(256);
  expect_hierarchy_chain(*again, std::vector<NodeId>{inputs.type, inputs.supertype});
}
