// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_conditions.h"

#include "ua_self_owning_operation.h"

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_logic.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_certificate_expiration_alarm_logic.h"
#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_dialog_condition_logic.h"
#include "ua_discrepancy_alarm_logic.h"
#include "ua_discrete_alarm_logic.h"
#include "ua_event_bus.h"
#include "ua_error_detail_keys.h"
#include "ua_instance_utils.h"
#include "ua_callback_safety.h"
#include "ua_limit_alarm_logic.h"
#include "ua_log_exception.h"
#include "ua_method_adapter.h"
#include "ua_method_id.h"
#include "ua_namespace_route.h"
#include "ua_node.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_off_normal_alarm_logic.h"
#include "ua_on_strand.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_refresh_end_event_payload.h"
#include "ua_refresh_start_event_payload.h"
#include "ua_status_routing.h"
#include "ua_system_off_normal_alarm_payload.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include <boost/asio/post.hpp>
#include <atomic>
#include <deque>
#include <future>

namespace ua
{
namespace
{

/// Applies the configured per-condition ConditionBranch retention cap to @p logic when it is acknowledgeable
/// (branches exist only there, and on its subtypes).
///
/// Every path that takes ownership of caller-supplied logic must call this: the cap is a memory fail-safe
/// and a condition whose logic never receives it retains branches to the compiled-in default instead of the
/// configured bound, in both directions.
void apply_branch_cap(ConditionLogic* logic, size_t maxBranchesPerCondition)
{
  if (auto* ackLogic = dynamic_cast<AcknowledgeableConditionLogic*>(logic))
  {
    ackLogic->set_max_branches(maxBranchesPerCondition);
  }
}

bool is_deviation_alarm_type(const NodeId& typeDefinition)
{
  return typeDefinition == NodeId{ObjectTypeId::ExclusiveDeviationAlarmType} ||
         typeDefinition == NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType};
}

bool is_rate_of_change_alarm_type(const NodeId& typeDefinition)
{
  return typeDefinition == NodeId{ObjectTypeId::ExclusiveRateOfChangeAlarmType} ||
         typeDefinition == NodeId{ObjectTypeId::NonExclusiveRateOfChangeAlarmType};
}

void configure_rate_of_change_evaluation(ConditionLogic* logic, const NodeId& typeDefinition)
{
  if (!is_rate_of_change_alarm_type(typeDefinition))
    return;

  if (auto* limitLogic = dynamic_cast<LimitAlarmLogic*>(logic))
  {
    limitLogic->enable_rate_of_change_per_second();
  }
}

VoidResult validate_deviation_limits(const ConditionLogic* logic, const NodeId& typeDefinition)
{
  if (!is_deviation_alarm_type(typeDefinition))
    return {};

  const auto* limitLogic = dynamic_cast<const LimitAlarmLogic*>(logic);
  if (limitLogic == nullptr)
  {
    return VoidResult{Status::BadTypeMismatch,
      ErrorDetail::build(
        "DeviationAlarmLogicTypeInvalid", "a DeviationAlarm requires LimitAlarmLogic", "Conditions")
        .context(ContextKeys::typeId, ua::to_string(typeDefinition))};
  }

  const auto validate = [&typeDefinition](std::string_view name,
                          const std::optional<ConfiguredLimit>& limit,
                          bool positive) -> VoidResult
  {
    if (!limit.has_value() || !limit->is_available())
      return {};

    const auto value = *limit->value();
    if ((positive && value > 0.0) || (!positive && value < 0.0))
      return {};

    return VoidResult{Status::BadOutOfRange,
      ErrorDetail::build("DeviationLimitSignInvalid",
        "a DeviationAlarm limit is zero or lies on the wrong side of the setpoint",
        "Conditions")
        .context(ContextKeys::typeId, ua::to_string(typeDefinition))
        .context(ContextKeys::nodeBrowseName, ua::to_string(QualifiedName{0, name}))
        .context(ContextKeys::actual, std::to_string(value))
        .context(ContextKeys::expected, positive ? "positive" : "negative")};
  };

  const auto& limits = limitLogic->limits();
  for (auto result : {validate("HighHighLimit", limits.highHighLimit, true),
         validate("HighLimit", limits.highLimit, true),
         validate("LowLimit", limits.lowLimit, false),
         validate("LowLowLimit", limits.lowLowLimit, false)})
  {
    if (result.is_bad())
      return result;
  }
  return {};
}

/// OffNormal state machine whose concrete payload identifies SystemOffNormalAlarmType.
class InputCommunicationAlarmLogic final : public OffNormalAlarmLogic
{
public:
  std::unique_ptr<BaseEvent> build_event() const override
  {
    auto event = std::make_unique<SystemOffNormalAlarmPayload>();
    populate_base_fields(*event);
    populate_condition_fields(*event);
    event->ackedState = acked_state();
    event->confirmedState = confirmed_state();
    // Every AlarmConditionType field - ShelvingState, MaxTimeShelved, InputNode and the optional states
    // included - from the one filler the plain alarm uses, so a subtype cannot drift from it.
    populate_alarm_payload_fields(*event);
    event->normalState = normal_state_node();
    return event;
  }
};

}  // namespace

// --- Per-flow state structs -----------------------------------

struct Conditions::SuppressionGroupScan
{
  std::vector<std::shared_ptr<ConditionInstance>> conditions;
  size_t conditionIndex{0};
  std::shared_ptr<ConditionInstance> condition;
  std::vector<NodeId> groups;
  size_t groupIndex{0};
  std::vector<NodeId> members;
  size_t memberIndex{0};
};

namespace
{
// Walk a HasSubtype chain inline and return the supertype (or null NodeId).
// Used inside the discover flow's hierarchy walk and factory lookup.
NodeId pick_supertype(const References& refs)
{
  for (const auto& ref : refs)
  {
    if (!ref.is_forward() && !ref.is_remote() && ref.type_id() == NodeId{ReferenceTypeId::HasSubtype})
    {
      return ref.target_id().node_id();
    }
  }
  return NodeId{};
}

NodeId pick_type_definition(const References& refs)
{
  for (const auto& ref : refs)
  {
    if (ref.is_forward() && !ref.is_remote() && ref.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition})
    {
      return ref.target_id().node_id();
    }
  }
  return NodeId{};
}

NodeId pick_has_condition_source(const References& refs)
{
  for (const auto& ref : refs)
  {
    // HasCondition inverse reference: !forward, type HasCondition, local.
    if (!ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasCondition} && !ref.is_remote())
    {
      return ref.target_id().node_id();
    }
  }
  return NodeId{ObjectId::Server};
}
}  // namespace

Conditions::Conditions(
  ConstructionKey, boost::asio::any_io_executor executor, std::weak_ptr<EventSink> eventSink)
  : mStrand(boost::asio::make_strand(executor)), mEventSink(std::move(eventSink))
{}

Conditions::Conditions(ConstructionKey, boost::asio::any_io_executor executor,
  std::weak_ptr<EventSink> eventSink, AddressSpace addressSpace)
  : mStrand(boost::asio::make_strand(executor)), mEventSink(std::move(eventSink)),
    mAddressSpace(std::move(addressSpace)),
    mLogger(mAddressSpace ? mAddressSpace->logger().with_category("conditions") : ua::Logger{})
{
  // Constructor is called before any shared_ptr<Conditions> is published, so
  // mFactories is not yet reachable from other threads - direct writes are
  // safe and avoid posting to a strand whose owning shared_ptr does not yet
  // exist. This is the one permitted pre-publication registry write
  // (documented exception to Rule 2).
  register_default_factories();
}

ConditionInstance::InputCommunicationObserver Conditions::make_input_communication_observer()
{
  auto weak = weak_from_this();
  return [weak](NodeId conditionId, NodeId inputNode, StatusCode status) mutable
  {
    auto self = weak.lock();
    if (!self)
    {
      return;
    }
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [conditionId = std::move(conditionId), inputNode = std::move(inputNode), status = std::move(status)](
        Conditions& conditions) mutable
      {
        conditions.on_input_communication_status(
          std::move(conditionId), std::move(inputNode), std::move(status));
      })();
  };
}

void Conditions::on_input_communication_status(NodeId conditionId, NodeId inputNode, StatusCode status)
{
  if (mShuttingDown)
  {
    return;
  }

  if (status.is_bad())
  {
    auto& failedConditions = mFailedConditionsByInput[inputNode];
    const bool firstFailureForCondition = failedConditions.insert(std::move(conditionId)).second;
    if (!firstFailureForCondition)
    {
      return;
    }
    if (mInputCommunicationAlarms.contains(inputNode))
    {
      synchronize_input_communication_alarm(inputNode);
    }
    else if (mInputCommunicationAlarmCreates.insert(inputNode).second)
    {
      create_input_communication_alarm(std::move(inputNode));
    }
    return;
  }

  auto failed = mFailedConditionsByInput.find(inputNode);
  if (failed == mFailedConditionsByInput.end())
  {
    return;
  }
  failed->second.erase(conditionId);
  if (!failed->second.empty())
  {
    return;
  }
  mFailedConditionsByInput.erase(failed);
  synchronize_input_communication_alarm(inputNode);
}

void Conditions::create_input_communication_alarm(NodeId inputNode)
{
  auto logic = std::make_unique<InputCommunicationAlarmLogic>();
  logic->set_normal_state(Variant{false});
  logic->set_normal_state_node(inputNode);

  const NodeId conditionId{
    inputNode.namespace_index(), String{fmt::format("CommunicationFailure:{}", ua::to_string(inputNode))}};
  auto weak = weak_from_this();
  create_condition_async(conditionId,
    NodeId{ObjectId::Server},
    String{"CommunicationFailure"},
    std::move(logic),
    NodeId{ObjectTypeId::SystemOffNormalAlarmType},
    [weak, inputNode = std::move(inputNode)](ConditionInstanceResult result) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      self->mInputCommunicationAlarmCreates.erase(inputNode);
      if (!result.is_good())
      {
        log_exception(
          self->mLogger, LogLevel::Error, "Conditions.CreateInputCommunicationAlarm", result.status_code());
        return;
      }

      auto alarm = result.value();
      self->mInputCommunicationAlarms.emplace(inputNode, alarm);
      auto weakForEnable = self->weak_from_this();
      alarm->enable_async(
        [weakForEnable, inputNode = std::move(inputNode)](VoidResult enabled) mutable
        {
          auto owner = weakForEnable.lock();
          if (!owner)
          {
            return;
          }
          if (!enabled.is_good())
          {
            log_exception(owner->mLogger,
              LogLevel::Error,
              "Conditions.EnableInputCommunicationAlarm",
              enabled.status_code());
            return;
          }
          ua::async::post_borrowing(owner.get(),
            owner->mStrand,
            owner->mLogger,
            [inputNode = std::move(inputNode)](Conditions& conditions)
            { conditions.synchronize_input_communication_alarm(inputNode); })();
        });
    });
}

void Conditions::synchronize_input_communication_alarm(const NodeId& inputNode)
{
  const auto alarmEntry = mInputCommunicationAlarms.find(inputNode);
  if (alarmEntry == mInputCommunicationAlarms.end())
  {
    return;
  }

  const auto failed = mFailedConditionsByInput.find(inputNode);
  const bool shouldBeActive = failed != mFailedConditionsByInput.end() && !failed->second.empty();
  const auto alarm = alarmEntry->second;

  auto completion = [logger = mLogger](VoidResult result)
  {
    if (!result.is_good())
    {
      log_exception(
        logger, LogLevel::Error, "Conditions.SynchronizeInputCommunicationAlarm", result.status_code());
    }
  };
  if (shouldBeActive)
  {
    alarm->activate_async(500, std::move(completion));
  }
  else
  {
    alarm->deactivate_async(std::move(completion));
  }
}

void Conditions::ensure_suppression_group_monitoring()
{
  if (!mAddressSpace || mSuppressionGroupTimer || mShuttingDown)
  {
    return;
  }

  auto weak = weak_from_this();
  mSuppressionGroupTimer = Timer::schedule_every(mStrand,
    std::chrono::milliseconds{100},
    [weak](boost::system::error_code error)
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      if (error)
      {
        log_exception(self->mLogger,
          LogLevel::Error,
          "Conditions.AlarmSuppressionGroupTimer",
          StatusCode{Status::BadInternalError,
            ErrorDetail::build("AlarmSuppressionGroupTimerFailure",
              "the periodic suppression-group evaluator failed",
              "Conditions")
              .context(ContextKeys::errorMessage, error.message())});
        return;
      }
      self->begin_suppression_group_scan();
    });
}

void Conditions::begin_suppression_group_scan()
{
  if (mShuttingDown || !mAddressSpace || mSuppressionGroupScan)
  {
    return;
  }

  auto scan = std::make_shared<SuppressionGroupScan>();
  scan->conditions.reserve(mConditions.size());
  for (const auto& [conditionId, condition] : mConditions)
  {
    static_cast<void>(conditionId);
    scan->conditions.push_back(condition);
  }
  mSuppressionGroupScan = std::move(scan);
  suppression_scan_next_condition();
}

void Conditions::suppression_scan_next_condition()
{
  if (mShuttingDown || !mSuppressionGroupScan || !mAddressSpace)
  {
    mSuppressionGroupScan.reset();
    return;
  }
  if (mSuppressionGroupScan->conditionIndex >= mSuppressionGroupScan->conditions.size())
  {
    mSuppressionGroupScan.reset();
    return;
  }

  auto& scan = *mSuppressionGroupScan;
  scan.condition = scan.conditions[scan.conditionIndex];
  scan.groups.clear();
  scan.groupIndex = 0;
  scan.members.clear();
  scan.memberIndex = 0;

  auto weak = weak_from_this();
  mAddressSpace->find_node_async(scan.condition->condition_id(),
    [weak](NodeAccessorResult result) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [result = std::move(result)](Conditions& conditions) mutable
        { conditions.on_suppression_condition_resolved(std::move(result)); })();
    });
}

void Conditions::on_suppression_condition_resolved(NodeAccessorResult result)
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  // The scan decides the SuppressedState, so an answer that is not Good fails it; an Uncertain one, with or
  // without a value, is refused here and at every step below.
  if (!result.is_good())
  {
    fail_suppression_group_scan(::ua::server::detail::not_acted_on(
      ::ua::server::detail::lookupAnswerUncertain, result.status_code(), "Conditions"));
    return;
  }

  auto weak = weak_from_this();
  result.value().get_references_async(
    [weak](Result<References> references) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [references = std::move(references)](Conditions& conditions) mutable
        { conditions.on_suppression_condition_references(std::move(references)); })();
    });
}

void Conditions::on_suppression_condition_references(Result<References> result)
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  if (!result.is_good())
  {
    fail_suppression_group_scan(::ua::server::detail::not_acted_on(
      ::ua::server::detail::referencesAnswerUncertain, result.status_code(), "Conditions"));
    return;
  }

  for (const auto& reference : result.value())
  {
    if (reference.is_forward() && !reference.is_remote() &&
        reference.type_id() == NodeId{ReferenceTypeId::HasAlarmSuppressionGroup})
    {
      mSuppressionGroupScan->groups.push_back(reference.target_id().node_id());
    }
  }

  if (mSuppressionGroupScan->groups.empty())
  {
    apply_suppression_group_state(false, false);
    return;
  }
  suppression_scan_next_group();
}

void Conditions::suppression_scan_next_group()
{
  if (!mSuppressionGroupScan || !mAddressSpace)
  {
    return;
  }
  auto& scan = *mSuppressionGroupScan;
  if (scan.groupIndex >= scan.groups.size())
  {
    apply_suppression_group_state(false, true);
    return;
  }

  auto weak = weak_from_this();
  mAddressSpace->find_node_async(scan.groups[scan.groupIndex],
    [weak](NodeAccessorResult result) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [result = std::move(result)](Conditions& conditions) mutable
        { conditions.on_suppression_group_resolved(std::move(result)); })();
    });
}

void Conditions::on_suppression_group_resolved(NodeAccessorResult result)
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  if (!result.is_good())
  {
    fail_suppression_group_scan(::ua::detail::lookup_failure(
      mSuppressionGroupScan->groups[mSuppressionGroupScan->groupIndex], result.status_code(), "Conditions"));
    return;
  }

  auto weak = weak_from_this();
  result.value().get_references_async(
    [weak](Result<References> references) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [references = std::move(references)](Conditions& conditions) mutable
        { conditions.on_suppression_group_references(std::move(references)); })();
    });
}

void Conditions::on_suppression_group_references(Result<References> result)
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  if (!result.is_good())
  {
    fail_suppression_group_scan(
      ::ua::server::detail::not_acted_on(::ua::server::detail::referencesAnswerUncertain,
        result.status_code(),
        "Conditions",
        mSuppressionGroupScan->groups[mSuppressionGroupScan->groupIndex]));
    return;
  }

  auto& scan = *mSuppressionGroupScan;
  scan.members.clear();
  scan.memberIndex = 0;
  for (const auto& reference : result.value())
  {
    if (reference.is_forward() && !reference.is_remote() &&
        reference.type_id() == NodeId{ReferenceTypeId::AlarmSuppressionGroupMember})
    {
      scan.members.push_back(reference.target_id().node_id());
    }
  }
  if (scan.members.empty())
  {
    fail_suppression_group_scan(StatusCode{Status::BadConfigurationError,
      ErrorDetail::build("AlarmSuppressionGroupEmpty",
        "an AlarmSuppressionGroup must contain at least one member",
        "Conditions")
        .context(ContextKeys::nodeId, ua::to_string(scan.groups[scan.groupIndex]))});
    return;
  }
  suppression_scan_next_member();
}

void Conditions::suppression_scan_next_member()
{
  if (!mSuppressionGroupScan || !mAddressSpace)
  {
    return;
  }
  auto& scan = *mSuppressionGroupScan;
  if (scan.memberIndex >= scan.members.size())
  {
    ++scan.groupIndex;
    suppression_scan_next_group();
    return;
  }

  const NodeId& memberId = scan.members[scan.memberIndex];
  const auto registered = mConditions.find(memberId);
  if (registered != mConditions.end())
  {
    if (registered->second->snapshot()->active())
    {
      apply_suppression_group_state(true, true);
      return;
    }
    ++scan.memberIndex;
    suppression_scan_next_member();
    return;
  }

  auto weak = weak_from_this();
  mAddressSpace->find_node_async(memberId,
    [weak](NodeAccessorResult result) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [result = std::move(result)](Conditions& conditions) mutable
        { conditions.on_suppression_member_resolved(std::move(result)); })();
    });
}

void Conditions::on_suppression_member_resolved(NodeAccessorResult result)
{
  if (!mSuppressionGroupScan || !mAddressSpace)
  {
    return;
  }
  if (!result.is_good())
  {
    fail_suppression_group_scan(
      ::ua::detail::lookup_failure(mSuppressionGroupScan->members[mSuppressionGroupScan->memberIndex],
        result.status_code(),
        "Conditions"));
    return;
  }
  if (!result.value().as<VariableAccessor>())
  {
    const NodeId memberId = mSuppressionGroupScan->members[mSuppressionGroupScan->memberIndex];
    fail_suppression_group_scan(StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("AlarmSuppressionGroupMemberTypeInvalid",
        "a suppression-group member must be a managed Alarm or Boolean Variable",
        "Conditions")
        .context(ContextKeys::nodeId, ua::to_string(memberId))});
    return;
  }

  const NodeId memberId = mSuppressionGroupScan->members[mSuppressionGroupScan->memberIndex];
  auto weak = weak_from_this();
  instance_utils::read_variable_value_async(*mAddressSpace,
    memberId,
    [weak](DataValueResult value) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [value = std::move(value)](Conditions& conditions) mutable
        { conditions.on_suppression_member_value(std::move(value)); })();
    });
}

void Conditions::on_suppression_member_value(DataValueResult result)
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  if (!result.is_good())
  {
    fail_suppression_group_scan(::ua::server::detail::not_acted_on(::ua::server::detail::readAnswerUncertain,
      result.status_code(),
      "Conditions",
      mSuppressionGroupScan->members[mSuppressionGroupScan->memberIndex]));
    return;
  }
  if (const auto& status = result.value().status(); status && status->is_bad())
  {
    fail_suppression_group_scan(*status);
    return;
  }
  const auto* active = result.value().value().try_as<bool>();
  if (!active)
  {
    const NodeId memberId = mSuppressionGroupScan->members[mSuppressionGroupScan->memberIndex];
    fail_suppression_group_scan(StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("AlarmSuppressionGroupMemberValueInvalid",
        "a suppression-group Variable member must provide a Boolean value",
        "Conditions")
        .context(ContextKeys::nodeId, ua::to_string(memberId))});
    return;
  }
  if (*active)
  {
    apply_suppression_group_state(true, true);
    return;
  }
  ++mSuppressionGroupScan->memberIndex;
  suppression_scan_next_member();
}

void Conditions::apply_suppression_group_state(bool active, bool hasReferencedGroups)
{
  if (!mSuppressionGroupScan || !mSuppressionGroupScan->condition)
  {
    return;
  }
  auto condition = mSuppressionGroupScan->condition;
  const NodeId conditionId = condition->condition_id();
  const auto previous = mSuppressionGroupStates.find(conditionId);
  const bool groupWasActive = previous != mSuppressionGroupStates.end() && previous->second;
  if (hasReferencedGroups)
  {
    mSuppressionGroupStates[conditionId] = active;
  }
  else
  {
    mSuppressionGroupStates.erase(conditionId);
  }

  const bool currentlySuppressed = condition->snapshot()->suppressed().value_or(false);
  const bool apply = active ? !currentlySuppressed : groupWasActive && currentlySuppressed;
  if (!apply)
  {
    advance_suppression_group_scan();
    return;
  }

  auto weak = weak_from_this();
  auto completion = [weak](VoidResult result) mutable
  {
    auto self = weak.lock();
    if (!self)
    {
      return;
    }
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [result = std::move(result)](Conditions& conditions) mutable
      { conditions.on_suppression_state_applied(std::move(result)); })();
  };
  if (active)
  {
    condition->suppress_async(std::move(completion));
  }
  else
  {
    condition->unsuppress_async(std::move(completion));
  }
}

void Conditions::on_suppression_state_applied(VoidResult result)
{
  if (result.is_bad())
  {
    log_exception(mLogger, LogLevel::Error, "Conditions.ApplyAlarmSuppressionGroup", result.status_code());
  }
  advance_suppression_group_scan();
}

void Conditions::fail_suppression_group_scan(StatusCode status)
{
  log_exception(mLogger, LogLevel::Warning, "Conditions.EvaluateAlarmSuppressionGroup", status);
  advance_suppression_group_scan();
}

void Conditions::advance_suppression_group_scan()
{
  if (!mSuppressionGroupScan)
  {
    return;
  }
  ++mSuppressionGroupScan->conditionIndex;
  suppression_scan_next_condition();
}

// --- Logic-only creation (no AS integration) ---

void Conditions::create_condition_async(NodeId conditionId, NodeId sourceNode, String sourceName,
  std::unique_ptr<ConditionLogic> logic, CreateConditionCallback completionHandler)
{
  // Build the instance off-strand; it has no AS wiring so construction is
  // pure object setup. Strand entry then registers it via try_emplace
  // arbitration, matching the AS-integrated complete_create path.
  apply_branch_cap(logic.get(), mMaxBranchesPerCondition);
  auto instance = ConditionInstance::create(mStrand.get_inner_executor(),
    std::move(logic),
    conditionId,
    std::move(sourceNode),
    std::move(sourceName),
    mEventSink);

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ConditionInstanceResult{StatusCode{Status::BadShutdown}},
    [id = std::move(conditionId), instance](Conditions& self, CreateConditionCallback callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, ConditionInstanceResult{StatusCode{Status::BadShutdown}});
        return;
      }
      auto [it, inserted] = self.mConditions.try_emplace(std::move(id), instance);
      if (!inserted)
      {
        ua::detail::invoke_user_callback(callback,
          ConditionInstanceResult{StatusCode{Status::BadAlreadyExists},
            ErrorDetail::build("ConditionIdCollision",
              "conditionId collision in create_condition_async (logic-only)",
              "Conditions::create_condition_async")
              .context(ua::ContextKeys::nodeId, ua::to_string(it->first))});
        return;
      }
      self.ensure_suppression_group_monitoring();
      ua::detail::invoke_user_callback(callback, ConditionInstanceResult{std::move(instance)});
    })();
}

ConditionInstanceResult Conditions::try_create_condition_sync(
  NodeId conditionId, NodeId sourceNode, String sourceName, std::unique_ptr<ConditionLogic> logic) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConditionInstanceResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(ConditionInstanceResult)> complete)
      {
        create_condition_async(std::move(conditionId),
          std::move(sourceNode),
          std::move(sourceName),
          std::move(logic),
          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

std::shared_ptr<ConditionInstance> Conditions::create_condition_sync(
  NodeId conditionId, NodeId sourceNode, String sourceName, std::unique_ptr<ConditionLogic> logic)
{
  return try_create_condition_sync(
    std::move(conditionId), std::move(sourceNode), std::move(sourceName), std::move(logic))
    .value();
}

/// Builds one ConditionInstance, wires it into the address space and registers it.
///
/// Three awaits, two of which are the two ways this can lose a race. Losing to shutdown, and losing
/// a conditionId to another creator, both mean tearing our own address-space wiring back down - and
/// that teardown must be awaited rather than done synchronously, because `try_close_sync` on this
/// strand would block it on the instance's strand and deadlock a single-thread pool.
/// @see ua::async::SelfOwningOperation
class CreateConditionOperation final : public ua::async::SelfOwningOperation<CreateConditionOperation>
{
public:
  CreateConditionOperation(Conditions& conditions, NodeId conditionId, NodeId sourceNode, String sourceName,
    std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition, bool resolveConditionName,
    Conditions::CreateConditionCallback callback)
    : ua::async::SelfOwningOperation<CreateConditionOperation>(conditions.mStrand, conditions.mLogger),
      mConditions(conditions.weak_from_this()), mConditionId(std::move(conditionId)),
      mSourceNode(std::move(sourceNode)), mSourceName(std::move(sourceName)), mLogic(std::move(logic)),
      mTypeDefinition(std::move(typeDefinition)), mResolveConditionName(resolveConditionName),
      mCallback(std::move(callback))
  {}

  static void start(Conditions& conditions, NodeId conditionId, NodeId sourceNode, String sourceName,
    std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition, bool resolveConditionName,
    Conditions::CreateConditionCallback callback)
  {
    launch(std::make_shared<CreateConditionOperation>(conditions,
      std::move(conditionId),
      std::move(sourceNode),
      std::move(sourceName),
      std::move(logic),
      std::move(typeDefinition),
      resolveConditionName,
      std::move(callback)));
  }

private:
  friend class ua::async::SelfOwningOperation<CreateConditionOperation>;

  ua::async::Task<> run()
  {
    try
    {
      if (mResolveConditionName)
      {
        // A ConditionPayload that carries no ConditionName takes the type definition's BrowseName.
        // Best-effort, as the chain had it: a type that will not resolve leaves the name alone.
        auto node = co_await await_step<NodeAccessorResult>(
          [this](auto completion)
          {
            auto conditions = mConditions.lock();
            if (!conditions)
            {
              completion(NodeAccessorResult{StatusCode{Status::BadShutdown}});
              return;
            }
            conditions->mAddressSpace->find_node_async(mTypeDefinition, std::move(completion));
          });
        if (node)
        {
          mLogic->set_condition_name(node.value().get_browse_name().name());
        }
      }

      std::shared_ptr<ConditionInstance> instance;
      {
        auto conditions = mConditions.lock();
        if (!conditions)
        {
          complete(ConditionInstanceResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        apply_branch_cap(mLogic.get(), conditions->mMaxBranchesPerCondition);
        instance = ConditionInstance::create(conditions->mStrand.get_inner_executor(),
          std::move(mLogic),
          std::move(mConditionId),
          std::move(mSourceNode),
          std::move(mSourceName),
          conditions->mEventSink,
          conditions->mAddressSpace,
          std::move(mTypeDefinition),
          conditions->make_input_communication_observer());
      }

      auto initialized = co_await await_step<VoidResult>(
        [&instance](auto completion) { instance->initialize_async(std::move(completion)); });

      if (shutting_down())
      {
        // Loser-of-shutdown. Closing the instance is what un-wires it from the address space, and it
        // must be awaited: try_close_sync on this strand would block it on the instance's strand and
        // deadlock a single-thread pool.
        co_await await_step<VoidResult>(
          [&instance](auto completion) { instance->close_async(std::move(completion)); });
        complete(ConditionInstanceResult{StatusCode{Status::BadShutdown}});
        co_return;
      }
      if (initialized.is_bad())
      {
        complete(ConditionInstanceResult{initialized.status_code(), initialized.shared_detail()});
        co_return;
      }

      NodeId actualId;
      bool registered = false;
      {
        auto conditions = mConditions.lock();
        if (!conditions)
        {
          complete(ConditionInstanceResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        // Registration uses the condition's actual NodeId, which may have changed during
        // instantiation.
        actualId = instance->condition_id();
        registered = conditions->mConditions.try_emplace(actualId, instance).second;
        if (registered)
        {
          conditions->ensure_suppression_group_monitoring();
        }
      }

      if (!registered)
      {
        // Loser of a create/discover race: another path already registered an instance for this
        // conditionId. Tear OUR wiring down - awaited, for the same reason as above - and surface
        // BadAlreadyExists once the close completes.
        co_await await_step<VoidResult>(
          [&instance](auto completion) { instance->close_async(std::move(completion)); });
        complete(ConditionInstanceResult{StatusCode{Status::BadAlreadyExists},
          ErrorDetail::build("ConditionIdCollision",
            "conditionId collision during create_condition_async",
            "Conditions::create_condition_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(actualId))});
        co_return;
      }

      complete(ConditionInstanceResult{std::move(instance)});
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      complete(ConditionInstanceResult{ua::exception_to_status_code(std::current_exception())});
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    complete(ConditionInstanceResult{status});
  }

  bool shutting_down() const
  {
    auto conditions = mConditions.lock();
    return !conditions || conditions->mShuttingDown;
  }

  void complete(ConditionInstanceResult result)
  {
    if (auto callback = std::move(mCallback))
    {
      ua::detail::invoke_user_callback(callback, std::move(result));
    }
  }

  std::weak_ptr<Conditions> mConditions;
  NodeId mConditionId;
  NodeId mSourceNode;
  String mSourceName;
  std::unique_ptr<ConditionLogic> mLogic;
  NodeId mTypeDefinition;
  /// True when the logic's payload carries no ConditionName, so the type definition must be read.
  bool mResolveConditionName{false};
  Conditions::CreateConditionCallback mCallback;
};

void Conditions::create_condition_async(NodeId conditionId, NodeId sourceNode, String sourceName,
  std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition, CreateConditionCallback callback)
{
  configure_rate_of_change_evaluation(logic.get(), typeDefinition);
  auto validation = validate_deviation_limits(logic.get(), typeDefinition);
  if (validation.is_bad())
  {
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      ConditionInstanceResult{StatusCode{Status::BadShutdown}},
      [validation = std::move(validation)](Conditions&, CreateConditionCallback completion) mutable
      {
        ua::detail::invoke_user_callback(
          completion, ConditionInstanceResult{validation.status_code(), validation.shared_detail()});
      })();
    return;
  }

  // Asking the logic for its initial event is how the chain decided whether the ConditionName still
  // has to be read off the type definition. It stays here, before anything suspends, because it is
  // the only question that needs the logic before the instance owns it.
  auto initialEvent = logic->build_event();
  auto* conditionEvent = dynamic_cast<ConditionPayload*>(initialEvent.get());
  const bool resolveConditionName = conditionEvent && conditionEvent->conditionName.empty();

  CreateConditionOperation::start(*this,
    std::move(conditionId),
    std::move(sourceNode),
    std::move(sourceName),
    std::move(logic),
    std::move(typeDefinition),
    resolveConditionName,
    std::move(callback));
}

ConditionInstanceResult Conditions::try_create_condition_sync(NodeId conditionId, NodeId sourceNode,
  String sourceName, std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConditionInstanceResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(ConditionInstanceResult)> complete)
      {
        create_condition_async(std::move(conditionId),
          std::move(sourceNode),
          std::move(sourceName),
          std::move(logic),
          std::move(typeDefinition),
          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

std::shared_ptr<ConditionInstance> Conditions::create_condition_sync(NodeId conditionId, NodeId sourceNode,
  String sourceName, std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition)
{
  return try_create_condition_sync(std::move(conditionId),
    std::move(sourceNode),
    std::move(sourceName),
    std::move(logic),
    std::move(typeDefinition))
    .value();
}

// --- Registry operations ---

void Conditions::register_condition_async(
  std::shared_ptr<ConditionInstance> instance, std::function<void(VoidResult)> completionHandler)
{
  auto conditionId = instance->condition_id();
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadShutdown}},
    [id = std::move(conditionId), instance = std::move(instance)](
      Conditions& self, std::function<void(VoidResult)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadShutdown}});
        return;
      }
      auto [it, inserted] = self.mConditions.try_emplace(std::move(id), std::move(instance));
      if (!inserted)
      {
        ua::detail::invoke_user_callback(callback,
          VoidResult{StatusCode{Status::BadAlreadyExists},
            ErrorDetail::build("ConditionIdCollision",
              "conditionId collision in register_condition_async",
              "Conditions::register_condition_async")
              .context(ua::ContextKeys::nodeId, ua::to_string(it->first))});
        return;
      }
      self.ensure_suppression_group_monitoring();
      ua::detail::invoke_user_callback(callback, VoidResult{});
    })();
}

VoidResult Conditions::try_register_condition_sync(std::shared_ptr<ConditionInstance> instance) noexcept
{
  // External-only; never called from inside the SDK.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { register_condition_async(std::move(instance), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::register_condition_sync(std::shared_ptr<ConditionInstance> instance)
{
  try_register_condition_sync(std::move(instance)).value();
}

void Conditions::deregister_condition_async(
  NodeId conditionId, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadShutdown}},
    [id = std::move(conditionId)](Conditions& self, std::function<void(VoidResult)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadShutdown}});
        return;
      }
      self.mConditions.erase(id);
      self.mSuppressionGroupStates.erase(id);
      ua::detail::invoke_user_callback(callback, VoidResult{});
    })();
}

VoidResult Conditions::try_deregister_condition_sync(NodeId conditionId) noexcept
{
  // External-only.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { deregister_condition_async(std::move(conditionId), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::deregister_condition_sync(NodeId conditionId)
{
  try_deregister_condition_sync(std::move(conditionId)).value();
}

void Conditions::find_condition_async(
  NodeId conditionId, std::function<void(Result<std::shared_ptr<ConditionInstance>>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<std::shared_ptr<ConditionInstance>>{StatusCode{Status::BadShutdown}},
    [id = std::move(conditionId)](
      Conditions& self, std::function<void(Result<std::shared_ptr<ConditionInstance>>)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(
          callback, Result<std::shared_ptr<ConditionInstance>>{StatusCode{Status::BadShutdown}});
        return;
      }
      // Good with null payload = "not found"; only Bad{Shutdown} reports an error.
      ua::detail::invoke_user_callback(
        callback, Result<std::shared_ptr<ConditionInstance>>{self.find_condition_on_strand(id)});
    })();
}

Result<std::shared_ptr<ConditionInstance>> Conditions::try_find_condition_sync(NodeId conditionId) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<std::shared_ptr<ConditionInstance>>>(
      boost::asio::any_io_executor{mStrand},
      [&](std::function<void(Result<std::shared_ptr<ConditionInstance>>)> complete)
      { find_condition_async(std::move(conditionId), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

std::shared_ptr<ConditionInstance> Conditions::find_condition_sync(NodeId conditionId)
{
  return ua::detail::good_value(try_find_condition_sync(std::move(conditionId)));
}

std::shared_ptr<ConditionInstance> Conditions::find_condition_on_strand(const NodeId& conditionId) const
{
  // Assumes caller is already on mStrand. Internal hot path for continuations.
  auto it = mConditions.find(conditionId);
  if (it != mConditions.end())
  {
    return it->second;
  }
  return nullptr;
}

// --- ConditionRefresh (callback-canonical, per-instance async chain) ---
//
// Eliminates the legacy std::promise::get_future().get() per-instance block
// (feedback_no_blocking_on_pool). The flow snapshots retained instances on
// the strand, emits RefreshStartEventPayload, drives a per-instance loop that
// resumes back on mStrand via ua::async::post_borrowing (so build_refresh_events
// can complete inline without blowing the stack), then emits RefreshEnd
// and fires the user callback.

/// Replays every retained Condition to a subscriber, bracketed by RefreshStart and RefreshEnd.
///
/// Serves both ConditionRefresh and ConditionRefresh2; the only difference is which instances are
/// snapshotted, so `mMonitoredNode` is empty for the first and set for the second.
///
/// The snapshot, the two bracket events and every replayed event are emitted on the component's
/// strand, in that order. The per-instance loop suspends, so `build_refresh_events_async` may answer
/// inline without growing the stack - which is what the chain's `post_borrowing` hop bought, and
/// what the frame buys now.
/// @see ua::async::SelfOwningOperation
class ConditionRefreshOperation final : public ua::async::SelfOwningOperation<ConditionRefreshOperation>
{
public:
  ConditionRefreshOperation(Conditions& conditions, Conditions::EmitFunction emitter,
    std::optional<NodeId> monitoredNode, std::function<void(VoidResult)> callback)
    : ua::async::SelfOwningOperation<ConditionRefreshOperation>(conditions.mStrand, conditions.mLogger),
      mConditions(conditions.weak_from_this()), mEmitter(std::move(emitter)),
      mMonitoredNode(std::move(monitoredNode)), mCallback(std::move(callback))
  {}

  static void start(Conditions& conditions, Conditions::EmitFunction emitter,
    std::optional<NodeId> monitoredNode, std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<ConditionRefreshOperation>(
      conditions, std::move(emitter), std::move(monitoredNode), std::move(callback)));
  }

private:
  friend class ua::async::SelfOwningOperation<ConditionRefreshOperation>;

  ua::async::Task<> run()
  {
    try
    {
      std::vector<std::shared_ptr<ConditionInstance>> instances;
      {
        auto conditions = mConditions.lock();
        if (!conditions || conditions->mShuttingDown)
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }

        // ConditionRefresh2 is scoped to one MonitoredItem (Part 9 5.5.8): return the retained
        // Conditions whose Event Notifications that MonitoredItem would receive. A MonitoredItem on
        // the Server Object is the top-level event notifier and receives events from every source,
        // so it gets ALL retained Conditions; a MonitoredItem on a specific source gets that
        // source's Conditions. Plain ConditionRefresh is the same question with no scope at all.
        const NodeId serverObjectId{ObjectId::Server};
        const bool everySource = !mMonitoredNode.has_value() || *mMonitoredNode == serverObjectId;
        for (const auto& [id, instance] : conditions->mConditions)
        {
          auto snapshot = instance->snapshot();
          if (snapshot && snapshot->retained() && (everySource || instance->source_node() == *mMonitoredNode))
          {
            instances.push_back(instance);
          }
        }

        RefreshStartEventPayload startEvent;
        startEvent.sourceNode = NodeId{ObjectId::Server};
        ua::detail::invoke_user_callback(mEmitter, startEvent);
      }

      for (const auto& instance : instances)
      {
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }

        auto events = co_await await_step<std::vector<std::unique_ptr<BaseEvent>>>(
          [&instance](auto completion) { instance->build_refresh_events_async(std::move(completion)); });

        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        for (auto& event : events)
        {
          if (event)
          {
            ua::detail::invoke_user_callback(mEmitter, *event);
          }
        }
      }

      if (shutting_down())
      {
        complete(VoidResult{StatusCode{Status::BadShutdown}});
        co_return;
      }
      RefreshEndEventPayload endEvent;
      endEvent.sourceNode = NodeId{ObjectId::Server};
      ua::detail::invoke_user_callback(mEmitter, endEvent);
      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    complete(VoidResult{status});
  }

  /// A component that has gone away counts as shutting down: either way there is nothing left to
  /// replay and the subscriber is owed BadShutdown.
  bool shutting_down() const
  {
    auto conditions = mConditions.lock();
    return !conditions || conditions->mShuttingDown;
  }

  void complete(VoidResult result)
  {
    if (auto callback = std::move(mCallback))
    {
      ua::detail::invoke_user_callback(callback, std::move(result));
    }
  }

  std::weak_ptr<Conditions> mConditions;
  Conditions::EmitFunction mEmitter;
  std::optional<NodeId> mMonitoredNode;  ///< Empty for ConditionRefresh; set for ConditionRefresh2.
  std::function<void(VoidResult)> mCallback;
};

void Conditions::condition_refresh_async(EmitFunction emitter, std::function<void(VoidResult)> callback)
{
  ConditionRefreshOperation::start(*this, std::move(emitter), std::nullopt, std::move(callback));
}

void Conditions::condition_refresh_async(EventSink& sink, std::function<void(VoidResult)> callback)
{
  condition_refresh_async([&sink](BaseEvent& event) { sink.emit(event); }, std::move(callback));
}

VoidResult Conditions::try_condition_refresh_sync(EmitFunction emitter) noexcept
{
  // External-only; never called from inside the SDK.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { condition_refresh_async(std::move(emitter), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

VoidResult Conditions::try_condition_refresh_sync(EventSink& sink) noexcept
{
  return try_condition_refresh_sync(EmitFunction{[&sink](BaseEvent& event)
    {
      sink.emit(event);
    }});
}

void Conditions::condition_refresh_sync(EmitFunction emitter)
{
  try_condition_refresh_sync(std::move(emitter)).value();
}

void Conditions::condition_refresh_sync(EventSink& sink)
{
  try_condition_refresh_sync(sink).value();
}

void Conditions::condition_refresh2_async(
  EmitFunction emitter, NodeId monitoredNode, std::function<void(VoidResult)> callback)
{
  ConditionRefreshOperation::start(*this, std::move(emitter), std::move(monitoredNode), std::move(callback));
}

void Conditions::condition_refresh2_async(
  EventSink& sink, NodeId monitoredNode, std::function<void(VoidResult)> callback)
{
  condition_refresh2_async(
    [&sink](BaseEvent& event) { sink.emit(event); }, std::move(monitoredNode), std::move(callback));
}

VoidResult Conditions::try_condition_refresh2_sync(EmitFunction emitter, NodeId monitoredNode) noexcept
{
  // External-only.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { condition_refresh2_async(std::move(emitter), std::move(monitoredNode), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

VoidResult Conditions::try_condition_refresh2_sync(EventSink& sink, NodeId monitoredNode) noexcept
{
  return try_condition_refresh2_sync(EmitFunction{[&sink](BaseEvent& event)
                                       {
                                         sink.emit(event);
                                       }},
    std::move(monitoredNode));
}

void Conditions::condition_refresh2_sync(EmitFunction emitter, NodeId monitoredNode)
{
  try_condition_refresh2_sync(std::move(emitter), std::move(monitoredNode)).value();
}

void Conditions::condition_refresh2_sync(EventSink& sink, NodeId monitoredNode)
{
  try_condition_refresh2_sync(sink, std::move(monitoredNode)).value();
}

void Conditions::register_factory_async(
  NodeId objectTypeId, ConditionFactory factory, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadShutdown}},
    [id = std::move(objectTypeId), factory = std::move(factory)](
      Conditions& self, std::function<void(VoidResult)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadShutdown}});
        return;
      }
      // Insert-or-assign: existing behaviour overwrites on duplicate (no
      // BadAlreadyExists). Preserve that contract.
      self.mFactories[std::move(id)] = std::move(factory);
      ua::detail::invoke_user_callback(callback, VoidResult{});
    })();
}

VoidResult Conditions::try_register_factory_sync(NodeId objectTypeId, ConditionFactory factory) noexcept
{
  // External-only.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { register_factory_async(std::move(objectTypeId), std::move(factory), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::register_factory_sync(NodeId objectTypeId, ConditionFactory factory)
{
  try_register_factory_sync(std::move(objectTypeId), std::move(factory)).value();
}

void Conditions::find_factory_async(
  NodeId objectTypeId, std::function<void(Result<ConditionFactory>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<ConditionFactory>{StatusCode{Status::BadShutdown}},
    [id = std::move(objectTypeId)](
      Conditions& self, std::function<void(Result<ConditionFactory>)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, Result<ConditionFactory>{StatusCode{Status::BadShutdown}});
        return;
      }
      // Good with null payload = "not registered"; only Bad{Shutdown} is an error.
      ua::detail::invoke_user_callback(callback, Result<ConditionFactory>{self.find_factory_on_strand(id)});
    })();
}

Result<ConditionFactory> Conditions::try_find_factory_sync(NodeId objectTypeId) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<ConditionFactory>>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(Result<ConditionFactory>)> complete)
      { find_factory_async(std::move(objectTypeId), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ConditionFactory Conditions::find_factory_sync(NodeId objectTypeId)
{
  return ua::detail::good_value(try_find_factory_sync(std::move(objectTypeId)));
}

void Conditions::set_max_branches_per_condition(size_t maxBranches)
{
  mMaxBranchesPerCondition = maxBranches < 1 ? 1 : maxBranches;
}

ConditionFactory Conditions::find_factory_on_strand(const NodeId& objectTypeId) const
{
  // Assumes caller is already on mStrand. Internal hot path for continuations.
  auto it = mFactories.find(objectTypeId);
  if (it != mFactories.end())
  {
    return it->second;
  }
  return nullptr;
}

void Conditions::retained_conditions_async(
  std::function<void(Result<std::vector<std::shared_ptr<ConditionInstance>>>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<std::vector<std::shared_ptr<ConditionInstance>>>{StatusCode{Status::BadShutdown}},
    [](Conditions& self,
      std::function<void(Result<std::vector<std::shared_ptr<ConditionInstance>>>)>
        callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(
          callback, Result<std::vector<std::shared_ptr<ConditionInstance>>>{StatusCode{Status::BadShutdown}});
        return;
      }
      std::vector<std::shared_ptr<ConditionInstance>> result;
      for (const auto& [id, instance] : self.mConditions)
      {
        auto snapshot = instance->snapshot();
        if (snapshot && snapshot->retained())
        {
          result.push_back(instance);
        }
      }
      ua::detail::invoke_user_callback(
        callback, Result<std::vector<std::shared_ptr<ConditionInstance>>>{std::move(result)});
    })();
}

Result<std::vector<std::shared_ptr<ConditionInstance>>> Conditions::try_retained_conditions_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<std::vector<std::shared_ptr<ConditionInstance>>>>(
      boost::asio::any_io_executor{mStrand},
      [&](std::function<void(Result<std::vector<std::shared_ptr<ConditionInstance>>>)> complete)
      { retained_conditions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

std::vector<std::shared_ptr<ConditionInstance>> Conditions::retained_conditions_sync()
{
  return ua::detail::good_value(try_retained_conditions_sync());
}

void Conditions::close_async(std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{},
    [](Conditions& self, std::function<void(VoidResult)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        // Idempotent: a second close fires the callback immediately.
        ua::detail::invoke_user_callback(callback, VoidResult{});
        return;
      }
      self.mShuttingDown = true;
      self.mSuppressionGroupTimer.cancel();
      self.mSuppressionGroupScan.reset();
      self.mSuppressionGroupStates.clear();

      // Snapshot + clear under the strand. In-flight discover / has-effect /
      // create flows that re-post will see mShuttingDown=true on resume and
      // bail with BadShutdown, so they cannot re-populate after this point.
      std::vector<std::shared_ptr<ConditionInstance>> instances;
      instances.reserve(self.mConditions.size());
      for (auto& [id, inst] : self.mConditions)
      {
        instances.push_back(inst);
      }
      self.mConditions.clear();

      // Named in the log, because the defect this close exists to prevent presents as a drain
      // that expires with BadTimeout and nothing saying which component still held work.
      self.mLogger.info({{"count", std::to_string(instances.size())}}, "Closing conditions");

      if (instances.empty())
      {
        ua::detail::invoke_user_callback(callback, VoidResult{});
        return;
      }

      // Each instance owns its own strand; close_async runs on that strand.
      // We fan out and wait for all completions before firing our callback.
      auto remaining = std::make_shared<std::atomic<size_t>>(instances.size());
      auto cbShared = std::make_shared<std::function<void(VoidResult)>>(std::move(callback));
      for (auto& inst : instances)
      {
        inst->close_async(
          [remaining, cbShared](VoidResult) mutable
          {
            if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
            {
              ua::detail::invoke_user_callback(*cbShared, VoidResult{});
            }
          });
      }
    })();
}

VoidResult Conditions::try_close_sync() noexcept
{
  // External-only convenience bridge.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete) { close_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::close_sync()
{
  try_close_sync().value();
}

// --- Alarm metrics ---

void Conditions::compute_alarm_metrics_async(
  std::function<void(Result<ConditionAlarmMetrics>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    Result<ConditionAlarmMetrics>{StatusCode{Status::BadShutdown}},
    [](Conditions& self, std::function<void(Result<ConditionAlarmMetrics>)> callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(
          callback, Result<ConditionAlarmMetrics>{StatusCode{Status::BadShutdown}});
        return;
      }
      std::vector<std::shared_ptr<ConditionInstance>> allConditions;
      allConditions.reserve(self.mConditions.size());
      for (const auto& [id, instance] : self.mConditions)
      {
        allConditions.push_back(instance);
      }
      ua::detail::invoke_user_callback(
        callback, Result<ConditionAlarmMetrics>{ConditionAlarmMetrics{allConditions}});
    })();
}

Result<ConditionAlarmMetrics> Conditions::try_compute_alarm_metrics_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<ConditionAlarmMetrics>>(
      boost::asio::any_io_executor{mStrand},
      [&](std::function<void(Result<ConditionAlarmMetrics>)> complete)
      { compute_alarm_metrics_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ConditionAlarmMetrics Conditions::compute_alarm_metrics_sync()
{
  return ua::detail::good_value(try_compute_alarm_metrics_sync());
}

// --- ConditionRefresh method registration ---

void Conditions::register_refresh_methods(std::weak_ptr<server::EventBus> eventBus,
  SubscriptionValidator validator, MonitoredItemNodeResolver itemNodeResolver)
{
  if (!mAddressSpace)
  {
    return;
  }

  using SubscriptionIdArgs = std::tuple<uint32_t>;
  using SubscriptionAndMonitoredItemArgs = std::tuple<uint32_t, uint32_t>;

  // The handlers below are invoked by the address space from arbitrary
  // threads. They MUST be safe under that contract - no raw `this` capture.
  // Every handler:
  //   1. captures weak_from_this() (the AS may outlive Conditions if the
  //      server tears down in an unexpected order),
  //   2. hops onto mStrand via ua::async::post_borrowing to check / set the
  //      per-subscription single-flight guard (COND-136),
  //   3. drives condition_refresh_async whose completion fires the
  //      MethodAdapter complete callback (also hopped through on_strand to
  //      clear the guard).

  // ConditionRefresh (i=3875) - takes 1 argument: SubscriptionId (UInt32)
  {
    auto findResult = mAddressSpace->try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh});
    if (findResult.is_good())
    {
      auto* target = findResult.value()->method_call_source();
      if (target)
      {
        target->set_call_handler(MethodAdapter<SubscriptionIdArgs>{
          [weak = weak_from_this(), eventBus, validator](const NodeId& objectId,
            const SubscriptionIdArgs& args,
            shared_ptr<const MethodCallContext>
              context,
            CallMethodResult result,
            CallMethodCompleteCallback complete)
          {
            // Part 9 5.5.7 makes ConditionRefresh type-scoped rather than instance-addressable:
            // both the MethodId and ObjectId are the well-known ConditionType nodes. Generic Call
            // topology validation admits a Method inherited by an instance, so enforce the narrower
            // ConditionRefresh contract at the handler that owns it.
            if (objectId != NodeId{ObjectTypeId::ConditionType})
            {
              result.status_code() = StatusCode{Status::BadNodeIdInvalid,
                ErrorDetail::build("ConditionRefreshObjectIdInvalid",
                  "ConditionRefresh requires the well-known ConditionType ObjectId",
                  "Conditions::register_refresh_methods")
                  .context(ContextKeys::nodeId, objectId)};
              ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
              return;
            }

            auto lockedSelf = weak.lock();
            if (!lockedSelf)
            {
              result.status_code() = Status::BadShutdown;
              ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
              return;
            }
            auto& [subscriptionId] = args;

            // COND-135: validate subscription / session pairing inline on
            // whatever thread the AS invoked us - no Conditions state is
            // touched here.
            if (context && validator && !validator(subscriptionId, context->sessionId))
            {
              result.status_code() = Status::BadSubscriptionIdInvalid;
              ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
              return;
            }

            auto finish = ua::detail::make_fire_once<StatusCode>(
              [result = std::make_shared<CallMethodResult>(std::move(result)),
                complete = std::move(complete)](StatusCode status) mutable
              {
                result->status_code() = std::move(status);
                ua::detail::invoke_user_callback(complete, CallResult{std::move(*result)});
              });

            // Part 9 5.5.7 distinguishes an owned Subscription that has no event MonitoredItem
            // (BadNothingToDo) from an unknown or foreign Subscription (BadSubscriptionIdInvalid,
            // decided above). EventBus owns the live event-item registry, so query it on its strand
            // before taking the Conditions single-flight guard or starting any refresh work.
            auto bus = eventBus.lock();
            if (!bus)
            {
              finish(StatusCode{Status::BadShutdown});
              return;
            }

            bus->has_event_items_async(subscriptionId,
              [weak, eventBus, subscriptionId, finish = std::move(finish)](Result<bool> hasEventItems) mutable
              {
                auto exceptionFinish = finish;
                try
                {
                  if (!hasEventItems.is_good())
                  {
                    finish(hasEventItems.status_code());
                    return;
                  }
                  if (!hasEventItems.value())
                  {
                    finish(StatusCode{Status::BadNothingToDo,
                      ErrorDetail::build("ConditionRefreshNoEventMonitoredItems",
                        "ConditionRefresh requires at least one event MonitoredItem",
                        "Conditions::register_refresh_methods")
                        .context(ContextKeys::subscriptionId, subscriptionId)});
                    return;
                  }

                  auto owner = weak.lock();
                  if (!owner)
                  {
                    finish(StatusCode{Status::BadShutdown});
                    return;
                  }

                  ua::async::post_borrowing(owner.get(),
                    owner->mStrand,
                    owner->mLogger,
                    std::move(finish),
                    StatusCode{Status::BadShutdown},
                    [eventBus, subscriptionId](
                      Conditions& self, std::function<void(StatusCode)> finishOnStrand) mutable
                    {
                      if (self.mShuttingDown)
                      {
                        finishOnStrand(StatusCode{Status::BadShutdown});
                        return;
                      }
                      if (!self.mRefreshInProgress.insert(subscriptionId).second)
                      {
                        finishOnStrand(StatusCode{Status::BadRefreshInProgress});
                        return;
                      }

                      auto exceptionFinishOnStrand = finishOnStrand;
                      try
                      {
                        self.condition_refresh_async(
                          [eventBus, subscriptionId](BaseEvent& event)
                          {
                            // Lock the bus per emit: the refresh runs on a pool thread and the bus can
                            // be torn down mid-refresh (~ServerImpl). Skip the emit if it is gone (the
                            // refresh still completes for the caller).
                            if (auto liveBus = eventBus.lock())
                              liveBus->emit_to_subscription(subscriptionId, event);
                          },
                          [weakOwner = self.weak_from_this(),
                            subscriptionId,
                            finishOnStrand = std::move(finishOnStrand)](VoidResult refreshResult) mutable
                          {
                            // Best-effort strand-side erase of the single-flight guard; if Conditions
                            // died before this fires, the erase is moot (a fresh Conditions has a fresh
                            // map).
                            if (auto liveOwner = weakOwner.lock())
                            {
                              ua::async::post_borrowing(liveOwner.get(),
                                liveOwner->mStrand,
                                liveOwner->mLogger,
                                [subscriptionId](Conditions& conditions)
                                { conditions.mRefreshInProgress.erase(subscriptionId); })();
                            }
                            finishOnStrand(refreshResult.status_code());
                          });
                      }
                      catch (...)
                      {
                        self.mRefreshInProgress.erase(subscriptionId);
                        exceptionFinishOnStrand(ua::exception_to_status_code(std::current_exception()));
                      }
                    })();
                }
                catch (...)
                {
                  exceptionFinish(ua::exception_to_status_code(std::current_exception()));
                }
              });
          }});
      }
    }
  }

  // ConditionRefresh2 (i=12912) - takes 2 arguments: SubscriptionId, MonitoredItemId (UInt32)
  {
    auto findResult = mAddressSpace->try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh2});
    if (findResult.is_good())
    {
      auto* target = findResult.value()->method_call_source();
      if (target)
      {
        target->set_call_handler(MethodAdapter<SubscriptionAndMonitoredItemArgs>{
          [weak = weak_from_this(), eventBus, validator, itemNodeResolver](const NodeId& /*objectId*/,
            const SubscriptionAndMonitoredItemArgs& args,
            shared_ptr<const MethodCallContext>
              context,
            CallMethodResult result,
            CallMethodCompleteCallback complete)
          {
            auto lockedSelf = weak.lock();
            if (!lockedSelf)
            {
              result.status_code() = Status::BadShutdown;
              ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
              return;
            }
            auto& [subscriptionId, monitoredItemId] = args;

            // COND-135: validate subscription / session pairing inline.
            if (context && validator && !validator(subscriptionId, context->sessionId))
            {
              result.status_code() = Status::BadSubscriptionIdInvalid;
              ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
              return;
            }

            auto resultShared = std::make_shared<CallMethodResult>(std::move(result));
            auto completeShared = std::make_shared<CallMethodCompleteCallback>(std::move(complete));

            // Part 9 5.5.8: ConditionRefresh2 refreshes ONLY the conditions
            // associated with the given MonitoredItem. Resolve the
            // MonitoredItemId to its monitored NodeId; if it cannot be
            // resolved, report Bad_MonitoredItemIdInvalid WITHOUT taking the
            // per-subscription single-flight guard (otherwise a later refresh
            // would wrongly report Bad_RefreshInProgress).
            if (!itemNodeResolver)
            {
              resultShared->status_code() = Status::BadMonitoredItemIdInvalid;
              ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
              return;
            }

            itemNodeResolver(subscriptionId,
              monitoredItemId,
              [weak, eventBus, subscriptionId, monitoredItemId, resultShared, completeShared](
                std::optional<NodeId> monitoredNode) mutable
              {
                if (!monitoredNode)
                {
                  resultShared->status_code() = Status::BadMonitoredItemIdInvalid;
                  ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
                  return;
                }

                auto lockedInstance = weak.lock();
                if (!lockedInstance)
                {
                  resultShared->status_code() = Status::BadShutdown;
                  ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
                  return;
                }

                // Hop onto mStrand to take the single-flight guard and start the
                // scoped refresh.
                ua::async::post_borrowing(
                  lockedInstance.get(),
                  lockedInstance->mStrand,
                  lockedInstance->mLogger,
                  [resultShared, completeShared](StatusCode status) mutable
                  {
                    resultShared->status_code() = status;
                    ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
                  },
                  StatusCode{Status::BadShutdown},
                  [eventBus,
                    subscriptionId,
                    monitoredItemId,
                    node = std::move(*monitoredNode),
                    resultShared,
                    completeShared](Conditions& self, auto&&) mutable
                  {
                    if (self.mShuttingDown)
                    {
                      resultShared->status_code() = Status::BadShutdown;
                      ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
                      return;
                    }
                    if (!self.mRefreshInProgress.insert(subscriptionId).second)
                    {
                      resultShared->status_code() = Status::BadRefreshInProgress;
                      ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(*resultShared)});
                      return;
                    }
                    // Part 9 5.5.8: the retained condition events (and the
                    // RefreshStart/RefreshEnd bookends) are delivered ONLY to
                    // the MonitoredItem that invoked ConditionRefresh2, not to
                    // every event MonitoredItem on the subscription.
                    self.condition_refresh2_async(
                      [eventBus, subscriptionId, monitoredItemId](BaseEvent& event)
                      {
                        // Lock the bus per emit (see ConditionRefresh above): the bus can be torn down
                        // mid-refresh; skip the emit if gone.
                        if (auto bus = eventBus.lock())
                          bus->emit_to_monitored_item(subscriptionId, monitoredItemId, event);
                      },
                      node,
                      [weak = self.weak_from_this(), subscriptionId, resultShared, completeShared](
                        VoidResult) mutable
                      {
                        if (auto s = weak.lock())
                        {
                          ua::async::post_borrowing(s.get(),
                            s->mStrand,
                            s->mLogger,
                            [subscriptionId](Conditions& s2)
                            { s2.mRefreshInProgress.erase(subscriptionId); })();
                        }
                        ua::detail::invoke_user_callback(
                          *completeShared, CallResult{std::move(*resultShared)});
                      });
                  })();
              });
          }});
      }
    }
  }
}

// --- Standard Condition method registration (type method nodes) ------------------------
//
// UACTT (and OPC UA clients generally) invoke the standard Condition methods using the
// TYPE method-node ids with the condition instance as the object:
//   ObjectId = condition instance NodeId, MethodId = i=9027 (Enable) / 9028 (Disable) /
//   9029 (AddComment) / 9111 (Acknowledge) / 9113 (Confirm).
// The per-instance method-node handlers (ConditionInstance::build_register_descriptors)
// do not cover this path, so the type nodes need handlers that resolve the object to its
// registered ConditionInstance and delegate to its call_*_async entry points (the single
// source of truth for the operation + audit emission). Modeled on register_refresh_methods.
//
// Each handler:
//   1. captures weak_from_this() (the AS may outlive Conditions),
//   2. reads ClientUserId from the borrowed context SYNCHRONOUSLY (the context pointer must
//      never be dereferenced after the strand hop - its lifetime ends when the handler
//      returns),
//   3. wraps `complete` in a shared_ptr so it ALWAYS fires (otherwise the client's Call
//      request hangs until session/channel timeout),
//   4. hops onto mStrand, looks up the instance by objectId in mConditions, and delegates
//      to the matching call_*_async; an objectId that is not a live Condition instance reports
//      Bad_NodeIdInvalid inside the CallMethodResult (outer CallResult stays Good).
//
// Status-code rationale (OPC 10000-9 5.7 condition methods, validated against UACTT A&C Comment
// Err_003/Err_004): the Call service's validate_object_id sub-flow runs BEFORE this handler. A
// syntactically-valid-but-nonexistent objectId fails its find_node and the service returns
// Bad_NodeIdUnknown without ever reaching here (Err_004). So any objectId that DOES reach this
// handler is a node that exists and carries the method in its type hierarchy; if it is not a
// registered Condition instance it is a type/non-instance node (Err_003 calls AddComment on
// ConditionType itself) -> Bad_NodeIdInvalid.

void Conditions::register_condition_methods()
{
  if (!mAddressSpace)
  {
    return;
  }

  using NoArgs = std::tuple<>;
  using EventIdCommentArgs = std::tuple<ByteString, LocalizedText>;

  // Install a type-node handler that resolves objectId -> ConditionInstance on mStrand and
  // calls `invoke(instance, userId, args, complete)`. `invoke` runs on mStrand and is
  // responsible for firing the wrapped complete exactly once.
  auto installArgless =
    [this](MethodId methodId,
      std::function<void(
        const std::shared_ptr<ConditionInstance>&, String, std::shared_ptr<CallMethodCompleteCallback>)>
        invoke)
  {
    auto findResult = mAddressSpace->try_find_node_sync(NodeId{methodId});
    if (!findResult.is_good())
    {
      return;
    }
    auto* target = findResult.value()->method_call_source();
    if (!target)
    {
      return;
    }
    target->set_call_handler(MethodAdapter<NoArgs>{
      [weak = weak_from_this(), invoke = std::move(invoke)](const NodeId& objectId,
        const NoArgs& /*args*/,
        shared_ptr<const MethodCallContext>
          context,
        CallMethodResult result,
        CallMethodCompleteCallback complete)
      {
        auto lockedSelf = weak.lock();
        if (!lockedSelf)
        {
          result.status_code() = Status::BadShutdown;
          ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
          return;
        }
        // Read ClientUserId synchronously - context is borrowed for this call only.
        String userId = context ? context->clientUserId : String{};
        auto completeShared = std::make_shared<CallMethodCompleteCallback>(std::move(complete));
        ua::async::post_borrowing(
          lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          [completeShared](CallResult trampolineResult)
          { ua::detail::invoke_user_callback(*completeShared, std::move(trampolineResult)); },
          CallResult{StatusCode{Status::BadShutdown}},
          [objectId, userId = std::move(userId), invoke, completeShared](Conditions& self, auto&&) mutable
          {
            if (self.mShuttingDown)
            {
              ua::detail::invoke_user_callback(*completeShared, CallResult{StatusCode{Status::BadShutdown}});
              return;
            }
            auto it = self.mConditions.find(objectId);
            if (it == self.mConditions.end())
            {
              CallMethodResult notFound;
              notFound.status_code() = Status::BadNodeIdInvalid;
              ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(notFound)});
              return;
            }
            invoke(it->second, std::move(userId), completeShared);
          })();
      }});
  };

  using DurationArgs = std::tuple<double>;

  // The TimedShelve counterpart of installArgless: one Duration input argument, same
  // objectId -> ConditionInstance resolution.
  auto installDuration = [this](MethodId methodId,
                           std::function<void(const std::shared_ptr<ConditionInstance>&,
                             double,
                             String,
                             std::shared_ptr<CallMethodCompleteCallback>)>
                             invoke)
  {
    auto findResult = mAddressSpace->try_find_node_sync(NodeId{methodId});
    if (!findResult.is_good())
    {
      return;
    }
    auto* target = findResult.value()->method_call_source();
    if (!target)
    {
      return;
    }
    target->set_call_handler(MethodAdapter<DurationArgs>{
      [weak = weak_from_this(), invoke = std::move(invoke)](const NodeId& objectId,
        const DurationArgs& args,
        shared_ptr<const MethodCallContext>
          context,
        CallMethodResult result,
        CallMethodCompleteCallback complete)
      {
        auto lockedSelf = weak.lock();
        if (!lockedSelf)
        {
          result.status_code() = Status::BadShutdown;
          ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
          return;
        }
        const auto& [duration] = args;
        String userId = context ? context->clientUserId : String{};
        auto completeShared = std::make_shared<CallMethodCompleteCallback>(std::move(complete));
        ua::async::post_borrowing(
          lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          [completeShared](CallResult trampolineResult)
          { ua::detail::invoke_user_callback(*completeShared, std::move(trampolineResult)); },
          CallResult{StatusCode{Status::BadShutdown}},
          [objectId, duration, userId = std::move(userId), invoke, completeShared](
            Conditions& self, auto&&) mutable
          {
            if (self.mShuttingDown)
            {
              ua::detail::invoke_user_callback(*completeShared, CallResult{StatusCode{Status::BadShutdown}});
              return;
            }
            auto it = self.mConditions.find(objectId);
            if (it == self.mConditions.end())
            {
              CallMethodResult notFound;
              notFound.status_code() = Status::BadNodeIdInvalid;
              ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(notFound)});
              return;
            }
            invoke(it->second, duration, std::move(userId), completeShared);
          })();
      }});
  };

  auto installEventIdComment = [this](MethodId methodId,
                                 std::function<void(const std::shared_ptr<ConditionInstance>&,
                                   ByteString,
                                   LocalizedText,
                                   String,
                                   std::shared_ptr<CallMethodCompleteCallback>)>
                                   invoke)
  {
    auto findResult = mAddressSpace->try_find_node_sync(NodeId{methodId});
    if (!findResult.is_good())
    {
      return;
    }
    auto* target = findResult.value()->method_call_source();
    if (!target)
    {
      return;
    }
    target->set_call_handler(MethodAdapter<EventIdCommentArgs>{
      [weak = weak_from_this(), invoke = std::move(invoke)](const NodeId& objectId,
        const EventIdCommentArgs& args,
        shared_ptr<const MethodCallContext>
          context,
        CallMethodResult result,
        CallMethodCompleteCallback complete)
      {
        auto lockedSelf = weak.lock();
        if (!lockedSelf)
        {
          result.status_code() = Status::BadShutdown;
          ua::detail::invoke_user_callback(complete, CallResult{std::move(result)});
          return;
        }
        const auto& [eventId, comment] = args;
        String userId = context ? context->clientUserId : String{};
        auto completeShared = std::make_shared<CallMethodCompleteCallback>(std::move(complete));
        ua::async::post_borrowing(
          lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          [completeShared](CallResult trampolineResult)
          { ua::detail::invoke_user_callback(*completeShared, std::move(trampolineResult)); },
          CallResult{StatusCode{Status::BadShutdown}},
          // Captures named differently from the `[eventId, comment]` structured binding above:
          // reusing those names shadows the binding, which clang rejects under -Werror=shadow.
          [objectId,
            capturedEventId = eventId,
            capturedComment = comment,
            userId = std::move(userId),
            invoke,
            completeShared](Conditions& self, auto&&) mutable
          {
            if (self.mShuttingDown)
            {
              ua::detail::invoke_user_callback(*completeShared, CallResult{StatusCode{Status::BadShutdown}});
              return;
            }
            auto it = self.mConditions.find(objectId);
            if (it == self.mConditions.end())
            {
              CallMethodResult notFound;
              notFound.status_code() = Status::BadNodeIdInvalid;
              ua::detail::invoke_user_callback(*completeShared, CallResult{std::move(notFound)});
              return;
            }
            // capturedEventId/capturedComment are mutable-lambda captures (non-const lvalues) at
            // their last use; moving avoids a ByteString vector copy and a LocalizedText copy into
            // invoke's by-value sink params.
            invoke(it->second,
              std::move(capturedEventId),
              std::move(capturedComment),
              std::move(userId),
              completeShared);
          })();
      }});
  };

  installArgless(MethodId::ConditionType_Enable,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_enable_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::ConditionType_Disable,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_disable_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installEventIdComment(MethodId::ConditionType_AddComment,
    [](const std::shared_ptr<ConditionInstance>& instance,
      ByteString eventId,
      LocalizedText comment,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_add_comment_async(std::move(eventId),
        std::move(comment),
        std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installEventIdComment(MethodId::AcknowledgeableConditionType_Acknowledge,
    [](const std::shared_ptr<ConditionInstance>& instance,
      ByteString eventId,
      LocalizedText comment,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_acknowledge_async(std::move(eventId),
        std::move(comment),
        std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installEventIdComment(MethodId::AcknowledgeableConditionType_Confirm,
    [](const std::shared_ptr<ConditionInstance>& instance,
      ByteString eventId,
      LocalizedText comment,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_confirm_async(std::move(eventId),
        std::move(comment),
        std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  // The shelving trio, addressed by CONDITION. OPC 10000-9 5.8.17.2/5.8.17.4/5.8.17.6 each require that
  // "all Servers shall also allow Clients to call the ... Method by specifying ConditionId as the
  // ObjectId", because a Server need not expose Condition instances in its AddressSpace and then
  // ConditionId is the only handle a Client is guaranteed to hold. The instance's own ShelvingState
  // child carries its own handlers for the form the spec calls normal; these serve the mandatory one.
  installArgless(MethodId::ShelvedStateMachineType_OneShotShelve,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_one_shot_shelve_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::ShelvedStateMachineType_Unshelve,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_unshelve_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installDuration(MethodId::ShelvedStateMachineType_TimedShelve,
    [](const std::shared_ptr<ConditionInstance>& instance,
      double durationMs,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_timed_shelve_async(durationMs,
        std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  // Suppress / Unsuppress / Silence are Optional on AlarmConditionType (Part 9 Table 42), so a Server
  // owes them nothing by the type model alone - but this Server declares the A & C Suppression
  // Conformance Unit, and the transitions were already implemented on ConditionInstance and reachable
  // only in-process. 5.8.7/5.8.8/5.8.10 each say a Client calls them with ConditionId as the ObjectId.
  installArgless(MethodId::AlarmConditionType_Suppress,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_suppress_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::AlarmConditionType_Unsuppress,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_unsuppress_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::AlarmConditionType_Silence,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_silence_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  // The out-of-service pair and Reset take the ConditionId-addressed form on the same footing as the
  // three above: 5.8.12 and 5.8.14 each state that "Servers shall allow Clients to call the ... Method
  // by specifying ConditionId as the ObjectId", and 5.8.5 says the same of Reset. Only the type Node
  // carries a handler a Client can reach without the instance, so leaving these three out left a
  // Client that cannot see Condition instances able to suppress an alarm but not to take it out of
  // service. An alarm exposing no OutOfServiceState still refuses in the logic - 5.8.12's own rule.
  installArgless(MethodId::AlarmConditionType_RemoveFromService,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_remove_from_service_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::AlarmConditionType_PlaceInService,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_place_in_service_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });

  installArgless(MethodId::AlarmConditionType_Reset,
    [](const std::shared_ptr<ConditionInstance>& instance,
      String userId,
      std::shared_ptr<CallMethodCompleteCallback>
        completeShared)
    {
      instance->call_reset_async(std::move(userId),
        [completeShared](CallResult result)
        { ua::detail::invoke_user_callback(*completeShared, std::move(result)); });
    });
}

// --- HasEffect reference processing (callback-canonical) ---
//
// Error model:
//   - Top-level failures (transition node lookup, get_references) PROPAGATE through
//     complete_has_effect with the original StatusCode + shared_detail().
//   - Per-ref iteration is best-effort: an unresolvable target or a non-applicable
//     ref-type is skipped silently - these are advisory effects on possibly-stale
//     refs. The overall operation reports OK if the top-level lookups succeeded.
//   - Per-instance disable_async / enable_async invocations are intentionally
//     fire-and-forget: the spec's HasEffect semantics are advisory side-effects,
//     not transactional. ErrorDetail from those legs is lost by design and
//     documented at each call site.
//
// Flow:
//   process_has_effect_references_async
//     +- if no AS -> complete inline with VoidResult{} (no error to report)
//     +- kick off mAddressSpace->find_node_async
//     +- on_has_effect_node_resolved
//          +- on bad -> fail through complete_has_effect carrying original status + detail
//          +- kick off node.get_references_async
//                +- on_has_effect_references
//                     +- on bad -> fail through complete_has_effect carrying original status + detail
//                     +- for each ref: fire instance->{disable,enable}_async (advisory)
//                          -> complete_has_effect(VoidResult{})

/// Applies every HasEffect reference on a transition node to the condition it points at.
///
/// Two lookups and a best-effort loop. The error model is the one the chain documented above and is
/// unchanged: the two top-level lookups propagate their status and ErrorDetail, while the per-
/// reference work is advisory - an unresolvable target or an inapplicable reference type is skipped,
/// and the enable/disable calls are fire-and-forget because HasEffect is a side effect, not a
/// transaction.
/// @see ua::async::SelfOwningOperation
class ProcessHasEffectReferencesOperation final
  : public ua::async::SelfOwningOperation<ProcessHasEffectReferencesOperation>
{
public:
  ProcessHasEffectReferencesOperation(
    Conditions& conditions, NodeId transitionNodeId, Conditions::ProcessHasEffectReferencesCallback callback)
    : ua::async::SelfOwningOperation<ProcessHasEffectReferencesOperation>(
        conditions.mStrand, conditions.mLogger),
      mConditions(conditions.weak_from_this()), mTransitionNodeId(std::move(transitionNodeId)),
      mCallback(std::move(callback))
  {}

  static void start(
    Conditions& conditions, NodeId transitionNodeId, Conditions::ProcessHasEffectReferencesCallback callback)
  {
    launch(std::make_shared<ProcessHasEffectReferencesOperation>(
      conditions, std::move(transitionNodeId), std::move(callback)));
  }

private:
  friend class ua::async::SelfOwningOperation<ProcessHasEffectReferencesOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto node = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          auto conditions = mConditions.lock();
          if (!conditions || conditions->mShuttingDown)
          {
            completion(NodeAccessorResult{StatusCode{Status::BadShutdown}});
            return;
          }
          conditions->mAddressSpace->find_node_async(mTransitionNodeId, std::move(completion));
        });

      if (!node.is_good())
      {
        // Top-level failure: the transition node could not be resolved. Surface the original status
        // and ErrorDetail to the caller (10.4); an Uncertain answer, with or without the Node, is refused.
        complete(
          VoidResult{::ua::detail::lookup_failure(mTransitionNodeId, node.status_code(), "Conditions")});
        co_return;
      }
      if (auto conditions = mConditions.lock(); !conditions || conditions->mShuttingDown)
      {
        complete(VoidResult{StatusCode{Status::BadShutdown}});
        co_return;
      }

      auto references = co_await await_step<Result<References>>(
        [&node](auto completion) { node.value().get_references_async(std::move(completion)); });

      if (!references.is_good())
      {
        // Top-level failure: the transition node's references could not be enumerated. Surface the
        // original status and ErrorDetail (10.4); an Uncertain answer is refused.
        complete(
          VoidResult{::ua::server::detail::not_acted_on(::ua::server::detail::referencesAnswerUncertain,
            references.status_code(),
            "Conditions",
            mTransitionNodeId)});
        co_return;
      }

      auto conditions = mConditions.lock();
      if (!conditions || conditions->mShuttingDown)
      {
        complete(VoidResult{StatusCode{Status::BadShutdown}});
        co_return;
      }

      for (const auto& ref : references.value())
      {
        if (!ref.is_forward() || ref.is_remote())
        {
          // Best-effort: HasEffect refs are local-forward by construction; skip others.
          continue;
        }

        const auto& refTypeId = ref.type_id();
        auto instance = conditions->find_condition_on_strand(ref.target_id().node_id());
        if (!instance)
        {
          // Best-effort: target may not be a registered condition, or may have been deregistered
          // between transition emission and effect application. Per-ref miss is non-fatal.
          continue;
        }

        if (refTypeId == NodeId{ReferenceTypeId::HasEffectDisable})
        {
          // Advisory: HasEffect is a side-effect on a possibly-stale target; per-instance failures
          // do not unwind the transition that triggered it. ErrorDetail loss here is by design and
          // documented at the call site (10.4).
          instance->disable_async([](VoidResult) {});
        }
        else if (refTypeId == NodeId{ReferenceTypeId::HasEffectEnable})
        {
          // Advisory: see HasEffectDisable comment above.
          instance->enable_async([](VoidResult) {});
        }
        else if (refTypeId == NodeId{ReferenceTypeId::HasEffectSuppressed} ||
                 refTypeId == NodeId{ReferenceTypeId::HasEffectUnsuppressed})
        {
          // Placeholder: HasEffectSuppressed/Unsuppressed require AlarmConditionLogic
          // suppress/unsuppress integration (a suppress_async/unsuppress_async on ConditionInstance,
          // called through the shell that posts to the strand). Not yet implemented - currently a
          // no-op for both ref types.
        }
      }

      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    complete(VoidResult{status});
  }

  void complete(VoidResult result)
  {
    if (auto callback = std::move(mCallback))
    {
      ua::detail::invoke_user_callback(callback, std::move(result));
    }
  }

  std::weak_ptr<Conditions> mConditions;
  NodeId mTransitionNodeId;
  Conditions::ProcessHasEffectReferencesCallback mCallback;
};

void Conditions::process_has_effect_references_async(
  NodeId transitionNodeId, ProcessHasEffectReferencesCallback callback)
{
  if (!mAddressSpace)
  {
    // No AS configured - there are no nodes to look up, so "no effects" is a
    // legitimate OK outcome, not a swallowed error.
    ua::detail::invoke_user_callback(callback, VoidResult{});
    return;
  }

  ProcessHasEffectReferencesOperation::start(*this, std::move(transitionNodeId), std::move(callback));
}

VoidResult Conditions::try_process_has_effect_references_sync(NodeId transitionNodeId) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { process_has_effect_references_async(std::move(transitionNodeId), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::process_has_effect_references_sync(NodeId transitionNodeId)
{
  try_process_has_effect_references_sync(std::move(transitionNodeId)).value();
}

// --- Default NS0 factory registration ---

void Conditions::register_default_factories()
{
  // Constructor-only entry point. weak_from_this() is empty here, so we must
  // NOT bridge through register_factory_async (its post body would no-op).
  // Write directly into mFactories - pre-publication is the one permitted
  // direct registry write.
  mFactories[NodeId{ObjectTypeId::ConditionType}] = []()
  {
    return std::make_unique<ConditionLogic>();
  };
  mFactories[NodeId{ObjectTypeId::DialogConditionType}] = []()
  {
    return std::make_unique<DialogConditionLogic>();
  };
  mFactories[NodeId{ObjectTypeId::AcknowledgeableConditionType}] = []()
  {
    return std::make_unique<AcknowledgeableConditionLogic>();
  };
  mFactories[NodeId{ObjectTypeId::AlarmConditionType}] = []()
  {
    return std::make_unique<AlarmConditionLogic>();
  };
  mFactories[NodeId{ObjectTypeId::ExclusiveLimitAlarmType}] = []()
  {
    auto logic = std::make_unique<LimitAlarmLogic>();
    logic->set_exclusive(true);
    return logic;
  };
  mFactories[NodeId{ObjectTypeId::NonExclusiveLimitAlarmType}] = []()
  {
    auto logic = std::make_unique<LimitAlarmLogic>();
    logic->set_exclusive(false);
    return logic;
  };
  mFactories[NodeId{ObjectTypeId::DiscreteAlarmType}] = []()
  {
    return std::make_unique<DiscreteAlarmLogic>();
  };
  mFactories[NodeId{ObjectTypeId::OffNormalAlarmType}] = []()
  {
    return std::make_unique<OffNormalAlarmLogic>();
  };
  mFactories[NodeId{ObjectTypeId::DiscrepancyAlarmType}] = []()
  {
    return std::make_unique<DiscrepancyAlarmLogic>();
  };
  mFactories[NodeId{ObjectTypeId::SystemOffNormalAlarmType}] = []()
  {
    return std::make_unique<OffNormalAlarmLogic>();
  };
  mFactories[NodeId{ObjectTypeId::CertificateExpirationAlarmType}] = []()
  {
    return std::make_unique<CertificateExpirationAlarmLogic>();
  };
}

// --- Discover existing conditions (callback-canonical) ---
//
// Error model:
//   - Top-level failure: if mAddressSpace is unset, complete inline with VoidResult{}
//     (nothing to scan is a legitimate OK outcome, not a swallowed error).
//   - Per-parent and per-target lookup failures during the BFS scan are documented
//     best-effort skips: discovery is a scan-and-attach contract that reports OK if
//     the scan ran to completion regardless of per-node failures. Each skip site
//     carries a one-line comment per the 10.4 invariant.
//   - Per-candidate attach failures are similarly best-effort skips.
//   - The overall flow completes with VoidResult{} once both phases have run.
//
// Phase 1 (BFS scan from ObjectsFolder, depth-limited):
//   discover_expand_next
//     +- on_discover_parent_resolved
//     |    +- on_discover_parent_references
//     |         +- discover_process_target          (iterate parent's children)
//     |              +- on_discover_target_resolved
//     |              |    +- on_discover_target_references
//     |              |         +- discover_check_condition_walk   (walk HasSubtype to ConditionType)
//     |              |              +- on_discover_check_step_resolved
//     |              |              +- on_discover_check_step_references
//     |              +- (on best-effort skip -> next ref)
//     +- (when toExpand empty) -> discover_attach_next
//
// Phase 2 (attach each collected candidate):
//   discover_attach_next
//     +- on_discover_candidate_node_resolved
//     |    +- on_discover_candidate_references
//     |         +- discover_factory_walk            (walk HasSubtype until factory hit)
//     |              +- on_discover_factory_step_resolved
//     |              +- on_discover_factory_step_references
//     |                   +- discover_attach_with_factory
//     |                        +- on_discover_attach_complete
//     |                             +- next candidate
//     +- (when candidates exhausted) -> complete_discover(VoidResult{})

/// Scans the address space for Condition objects that nobody created through this component, and
/// attaches one ConditionInstance to each.
///
/// Two phases, and the chain spent sixteen functions saying so. Phase 1 is a depth-limited
/// breadth-first walk from ObjectsFolder: for every Organizes/HasComponent child that is an Object,
/// walk its HasSubtype chain looking for ConditionType. A match is a candidate; anything else is
/// treated as folder-like and pushed back onto the frontier. Phase 2 attaches each candidate,
/// walking HasSubtype again - this time looking for a registered factory.
///
/// The error model is unchanged and is the reason so much of this reads as `continue`: discovery is
/// a scan-and-attach contract that reports OK if the scan ran to completion. Every per-node and
/// per-candidate failure is a documented best-effort skip, and ErrorDetail from those legs is lost
/// by design. Only shutdown ends the scan early.
///
/// Single-flight: `mDiscoverInProgress` is claimed by the entry point before this operation exists,
/// and this operation clears it on every exit - so the claim and the release cannot get out of step
/// with a rejected second caller.
/// @see ua::async::SelfOwningOperation
class DiscoverExistingConditionsOperation final
  : public ua::async::SelfOwningOperation<DiscoverExistingConditionsOperation>
{
public:
  DiscoverExistingConditionsOperation(
    Conditions& conditions, Conditions::DiscoverExistingConditionsCallback callback)
    : ua::async::SelfOwningOperation<DiscoverExistingConditionsOperation>(
        conditions.mStrand, conditions.mLogger),
      mConditions(conditions.weak_from_this()), mCallback(std::move(callback))
  {}

  /// The caller must have claimed `mDiscoverInProgress` already; this operation releases it.
  static void start(Conditions& conditions, Conditions::DiscoverExistingConditionsCallback callback)
  {
    launch(std::make_shared<DiscoverExistingConditionsOperation>(conditions, std::move(callback)));
  }

private:
  friend class ua::async::SelfOwningOperation<DiscoverExistingConditionsOperation>;

  /// One entry on the breadth-first frontier.
  struct PendingNode
  {
    NodeId id;
    int depth;
  };

  static constexpr int sMaxDepth = 20;
  static constexpr int sMaxHopsToConditionType = 30;

  auto find_node(const NodeId& nodeId)
  {
    return await_step<NodeAccessorResult>(
      [this, nodeId](auto completion)
      {
        auto conditions = mConditions.lock();
        if (!conditions || !conditions->mAddressSpace)
        {
          completion(NodeAccessorResult{StatusCode{Status::BadShutdown}});
          return;
        }
        conditions->mAddressSpace->find_node_async(nodeId, std::move(completion));
      });
  }

  auto get_references(const NodeAccessor& node)
  {
    return await_step<Result<References>>(
      [&node](auto completion) { node.get_references_async(std::move(completion)); });
  }

  ua::async::Task<> run()
  {
    try
    {
      std::deque<PendingNode> toExpand;
      toExpand.push_back({NodeId{ObjectId::ObjectsFolder}, 0});
      std::vector<NodeId> candidates;

      // --- Phase 1: depth-limited breadth-first scan from ObjectsFolder -----------------------
      while (!toExpand.empty())
      {
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }

        const auto pending = toExpand.front();
        toExpand.pop_front();
        if (pending.depth >= sMaxDepth)
        {
          // Best-effort: depth limit reached for this branch. Continue scanning others.
          continue;
        }

        if (address_space_gone())
        {
          complete(VoidResult{});
          co_return;
        }
        auto parent = co_await find_node(pending.id);
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        if (!parent.is_good())
        {
          // Best-effort: a parent in the frontier could not be resolved (deleted, remote
          // unreachable, etc.). The scan continues with other parents. Here and below, an Uncertain
          // answer, with or without a value, is not acted on and is skipped as a failed one is.
          continue;
        }

        auto parentRefs = co_await get_references(parent.value());
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        if (!parentRefs.is_good())
        {
          // Best-effort: a parent's references could not be enumerated. Skip this parent.
          continue;
        }

        for (const auto& ref : parentRefs.value().span())
        {
          if (shutting_down())
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }

          // Only follow forward Organizes / HasComponent to local targets.
          if (!ref.is_forward() || ref.is_remote())
          {
            continue;
          }
          const auto& refTypeId = ref.type_id();
          if (refTypeId != NodeId{ReferenceTypeId::Organizes} &&
              refTypeId != NodeId{ReferenceTypeId::HasComponent})
          {
            continue;
          }

          const NodeId targetId = ref.target_id().node_id();

          if (address_space_gone())
          {
            complete(VoidResult{});
            co_return;
          }
          auto target = co_await find_node(targetId);
          if (shutting_down())
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          if (!target.is_good())
          {
            // Best-effort: target ref points at a node we cannot resolve. Skip this ref.
            continue;
          }
          try
          {
            if (target.value().get_node_class() != NodeClass::Object)
            {
              // Only Object nodes can be condition instances. Skip without enqueueing for recursion.
              continue;
            }
          }
          catch (const UaException& error)
          {
            const auto status = error.status_code();
            if (status != StatusCode{Status::BadNodeIdUnknown})
            {
              throw;
            }
            // Lookup and description are separate reads; deletion can occur between them.
            if (auto conditions = mConditions.lock())
            {
              log_exception(conditions->mLogger, LogLevel::Warning, "Conditions.DiscoverTarget", status);
            }
            continue;
          }

          auto targetRefs = co_await get_references(target.value());
          if (shutting_down())
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          if (!targetRefs.is_good())
          {
            // Best-effort: target's references could not be enumerated. Skip this target.
            continue;
          }

          const NodeId typeDefId = pick_type_definition(targetRefs.value());
          if (typeDefId.is_null())
          {
            // No type definition - treat as a possible folder-like container; recurse into it.
            toExpand.push_back({targetId, pending.depth + 1});
            continue;
          }

          // Walk the HasSubtype chain from the type definition looking for ConditionType. Anything
          // that ends the walk without a match means "not a condition, but maybe a container".
          NodeId currentType = typeDefId;
          int hopsRemaining = sMaxHopsToConditionType;
          bool isCondition = false;
          while (true)
          {
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (currentType == NodeId{ObjectTypeId::ConditionType})
            {
              isCondition = true;
              break;
            }
            if (hopsRemaining <= 0)
            {
              // Hop limit reached without finding ConditionType - not a condition.
              break;
            }

            if (address_space_gone())
            {
              complete(VoidResult{});
              co_return;
            }
            --hopsRemaining;
            auto typeNode = co_await find_node(currentType);
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (!typeNode.is_good())
            {
              // Best-effort: a type node in the chain could not be resolved.
              break;
            }

            auto typeRefs = co_await get_references(typeNode.value());
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (!typeRefs.is_good())
            {
              // Best-effort: type node references could not be enumerated. Stop walking.
              break;
            }

            const NodeId supertype = pick_supertype(typeRefs.value());
            if (supertype.is_null())
            {
              // Top of the type hierarchy reached without a ConditionType match.
              break;
            }
            currentType = supertype;
          }

          if (isCondition)
          {
            candidates.push_back(targetId);
          }
          else
          {
            // Treat as folder-like and recurse, to find conditions deeper down.
            toExpand.push_back({targetId, pending.depth + 1});
          }
        }
      }

      // --- Phase 2: attach each collected candidate -------------------------------------------
      for (const auto& candidateId : candidates)
      {
        if (address_space_gone())
        {
          complete(VoidResult{});
          co_return;
        }

        {
          auto conditions = mConditions.lock();
          if (!conditions)
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          if (conditions->find_condition_on_strand(candidateId))
          {
            // Best-effort: candidate already registered (e.g. via create_condition_async). The scan
            // does not duplicate-register.
            continue;
          }
        }

        auto node = co_await find_node(candidateId);
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        if (!node.is_good())
        {
          // Best-effort: candidate node could not be resolved (deleted between the two phases).
          continue;
        }

        auto candidateRefs = co_await get_references(node.value());
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        if (!candidateRefs.is_good())
        {
          // Best-effort: candidate's references unavailable. Try the next candidate.
          continue;
        }

        const NodeId typeDefId = pick_type_definition(candidateRefs.value());
        const NodeId sourceNode = pick_has_condition_source(candidateRefs.value());
        if (typeDefId.is_null())
        {
          // Best-effort: candidate has no HasTypeDefinition - cannot pick a factory.
          continue;
        }

        // The type itself first, then its ancestors: the nearest registered factory wins.
        ConditionFactory factory;
        {
          auto conditions = mConditions.lock();
          if (!conditions)
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          factory = conditions->find_factory_on_strand(typeDefId);
        }

        if (!factory)
        {
          NodeId currentType = typeDefId;
          int hopsRemaining = sMaxHopsToConditionType;
          while (true)
          {
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (hopsRemaining <= 0)
            {
              // Best-effort: hop limit reached without finding a registered factory.
              break;
            }

            if (address_space_gone())
            {
              complete(VoidResult{});
              co_return;
            }
            --hopsRemaining;
            auto typeNode = co_await find_node(currentType);
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (!typeNode.is_good())
            {
              // Best-effort: type node in the chain could not be resolved.
              break;
            }

            auto typeRefs = co_await get_references(typeNode.value());
            if (shutting_down())
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            if (!typeRefs.is_good())
            {
              // Best-effort: type node references unavailable.
              break;
            }

            const NodeId supertype = pick_supertype(typeRefs.value());
            if (supertype.is_null())
            {
              // Best-effort: top of hierarchy reached without finding a factory.
              break;
            }

            auto conditions = mConditions.lock();
            if (!conditions)
            {
              complete(VoidResult{StatusCode{Status::BadShutdown}});
              co_return;
            }
            factory = conditions->find_factory_on_strand(supertype);
            if (factory)
            {
              break;
            }
            currentType = supertype;
          }

          if (!factory)
          {
            continue;
          }
        }

        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }

        std::shared_ptr<ConditionInstance> instance;
        {
          auto conditions = mConditions.lock();
          if (!conditions)
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          auto logic = factory();
          apply_branch_cap(logic.get(), conditions->mMaxBranchesPerCondition);
          instance = ConditionInstance::create(conditions->mStrand.get_inner_executor(),
            std::move(logic),
            candidateId,
            sourceNode,
            String{},
            conditions->mEventSink,
            conditions->mAddressSpace,
            typeDefId,
            conditions->make_input_communication_observer());
        }

        auto attached = co_await await_step<VoidResult>(
          [&instance](auto completion) { instance->attach_async(std::move(completion)); });
        if (shutting_down())
        {
          complete(VoidResult{StatusCode{Status::BadShutdown}});
          co_return;
        }
        if (attached.is_bad())
        {
          // Best-effort: attach failed for this candidate (validation error, AS race, etc.). Drop
          // this candidate's instance and proceed. ErrorDetail is lost here by design - discovery
          // does not unwind on per-item failures.
          continue;
        }

        // Register via try_emplace arbitration: a concurrent create_condition_async may already have
        // registered the same conditionId.
        bool registered = false;
        {
          auto conditions = mConditions.lock();
          if (!conditions)
          {
            complete(VoidResult{StatusCode{Status::BadShutdown}});
            co_return;
          }
          registered = conditions->mConditions.try_emplace(instance->condition_id(), instance).second;
          if (registered)
          {
            conditions->ensure_suppression_group_monitoring();
          }
        }

        if (!registered)
        {
          // We are the loser: tear down our own address-space wiring and continue the scan once the
          // close completes. NEVER try_close_sync on this strand - the instance closes on its own
          // strand over the same executor, so that would deadlock a single-thread pool.
          co_await await_step<VoidResult>(
            [&instance](auto completion) { instance->close_async(std::move(completion)); });
        }
      }

      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    complete(VoidResult{status});
  }

  bool shutting_down() const
  {
    auto conditions = mConditions.lock();
    return !conditions || conditions->mShuttingDown;
  }

  /// The chain re-asked this before every lookup. The entry point will not start a scan without an
  /// address space and nothing clears it mid-scan, so it is a provable-invariant guard rather than a
  /// live branch - but it was a branch, and it ended the scan as OK ("nothing to scan").
  bool address_space_gone() const
  {
    auto conditions = mConditions.lock();
    return !conditions || !conditions->mAddressSpace;
  }

  /// Releases the single-flight claim the entry point took, then answers once.
  void complete(VoidResult result)
  {
    if (auto conditions = mConditions.lock())
    {
      conditions->mDiscoverInProgress = false;
    }
    if (auto callback = std::move(mCallback))
    {
      ua::detail::invoke_user_callback(callback, std::move(result));
    }
  }

  std::weak_ptr<Conditions> mConditions;
  Conditions::DiscoverExistingConditionsCallback mCallback;
};

void Conditions::discover_existing_conditions_async(DiscoverExistingConditionsCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadShutdown}},
    [](Conditions& self, DiscoverExistingConditionsCallback callback) mutable
    {
      if (self.mShuttingDown)
      {
        ua::detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadShutdown}});
        return;
      }
      if (!self.mAddressSpace)
      {
        // No AS configured - nothing to scan. Genuine OK outcome.
        ua::detail::invoke_user_callback(callback, VoidResult{});
        return;
      }
      if (self.mDiscoverInProgress)
      {
        // Single-flight (finding D): a second concurrent discover is rejected.
        ua::detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadInvalidState}});
        return;
      }
      // Claimed HERE, on the strand, so the rejection above and the claim cannot interleave. The
      // operation releases it on every exit.
      self.mDiscoverInProgress = true;

      DiscoverExistingConditionsOperation::start(self, std::move(callback));
    })();
}

VoidResult Conditions::try_discover_existing_conditions_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
      [&](std::function<void(VoidResult)> complete)
      { discover_existing_conditions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Conditions::discover_existing_conditions_sync()
{
  try_discover_existing_conditions_sync().value();
}

}  // namespace ua
