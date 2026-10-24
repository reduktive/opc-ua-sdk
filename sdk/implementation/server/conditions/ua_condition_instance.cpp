// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_instance.h"
#include "ua_whole_value_source.h"
#include "ua_callback_safety.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_payload.h"
#include "ua_alarm_condition_logic.h"
#include "ua_attribute_wire.h"
#include "ua_audit_condition_acknowledge_event_payload.h"
#include "ua_audit_condition_comment_event_payload.h"
#include "ua_audit_condition_confirm_event_payload.h"
#include "ua_audit_condition_enable_event_payload.h"
#include "ua_audit_condition_out_of_service_event_payload.h"
#include "ua_audit_condition_reset_event_payload.h"
#include "ua_audit_condition_respond_event_payload.h"
#include "ua_audit_condition_shelving_event_payload.h"
#include "ua_audit_condition_silence_event_payload.h"
#include "ua_audit_condition_suppression_event_payload.h"
#include "ua_dialog_condition_logic.h"
#include "ua_limit_alarm_logic.h"
#include "ua_log_exception.h"
#include "ua_non_exclusive_limit_alarm_payload.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_weak_address_space.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_event_notifier_type.h"
#include "ua_expanded_node_id.h"
#include "ua_instance_utils.h"
#include "ua_instantiation_options.h"
#include "ua_instantiation_service.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_sync_wait.h"
#include "ua_self_owning_operation.h"
#include "ua_status_routing.h"
#include "ua_referencetype_id.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <chrono>
#include <future>
#include <tuple>
#include <type_traits>

namespace ua
{

namespace detail
{

/// The Initialize and Attach bodies for @ref ConditionInstance.
///
/// This lives here, not on the class, because `ConditionInstance` is a PUBLIC header and no
/// coroutine type has ever appeared in `sdk/interface/`. One forward declaration and one `friend`
/// line cross that boundary; `ua::async::Task` does not.
///
/// The operation holds the instance WEAKLY and re-locks it after every await, because that is what
/// the chain did (`me.lock(); if (!lockedSelf) return;`). An instance destroyed mid-flow therefore
/// drops the remaining work and never answers - the callback lived in the flow state and died with
/// it. Holding it strongly would silently extend a condition's lifetime across its own teardown.
class ConditionLifecycleOperation final : public ua::async::SelfOwningOperation<ConditionLifecycleOperation>
{
public:
  enum class Mode
  {
    Initialize,  ///< instantiate the object, then the shared tail
    Attach  ///< resolve the existing condition and read its state, then the shared tail
  };

  static void start(const std::shared_ptr<ConditionInstance>& owner, Mode mode)
  {
    launch(std::make_shared<ConditionLifecycleOperation>(owner, mode));
  }

  ConditionLifecycleOperation(const std::shared_ptr<ConditionInstance>& owner, Mode mode)
    : SelfOwningOperation(owner->mStrand, owner->mLogger), mOwner(owner), mMode(mode)
  {}

private:
  friend class ua::async::SelfOwningOperation<ConditionLifecycleOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // Each step locks the instance for itself and releases it before awaiting (CALLS-21 rule 1).
      if (mOwner.expired())
        co_return;

      const bool ok =
        (mMode == Mode::Initialize) ? co_await run_initialize_head() : co_await run_attach_head();
      if (!ok)
        co_return;  // the head already answered, or the instance went away

      co_await run_shared_tail();
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger,
        [&]
        {
          if (auto self = mOwner.lock())
          {
            fail(*self, VoidResult{failure, failure.shared_detail()});
          }
        })();
    }
  }

  /// Instantiate the condition object and adopt the subtree it produced.
  /// @return false when the flow has ended (answered, or the instance went away).
  ua::async::Task<bool> run_initialize_head()
  {
    if (mOwner.expired())
      co_return false;

    auto result = co_await await_step<NodeSubtreeResult>(
      [this](auto completion)
      {
        auto owner = mOwner.lock();
        if (!owner)
        {
          return;  // dropped, exactly as the chain's failed weak lock did
        }
        owner->instantiate_condition_object_async(std::move(completion));
      });

    auto self = mOwner.lock();
    if (!self || !self->mInitializeState)
      co_return false;
    if (!result.is_good())
    {
      // The Condition is built on the subtree, so an answer that is not Good fails the initialisation; an
      // Uncertain one, with or without the subtree, is refused (`AnswerUncertain`).
      self->fail_initialize(VoidResult{result.is_bad() ? result.status_code()
                                                       : ::ua::server::detail::uncertain_answer_refused(
                                                           ::ua::server::detail::answerUncertain,
                                                           result.status_code(),
                                                           "ConditionInstance",
                                                           self->mConditionId)});
      co_return false;
    }
    self->mOwnedSubtree.emplace(std::move(result).value());
    self->mConditionId = self->mOwnedSubtree->root();
    co_return true;
  }

  /// Resolve the already-present condition node, then read each initial state bit off it.
  /// @return false when the flow has ended (answered, or the instance went away).
  ua::async::Task<bool> run_attach_head()
  {
    auto self = mOwner.lock();
    if (!self || !self->mAddressSpace)
    {
      if (self)
        self->fail_attach(VoidResult{StatusCode{Status::BadInternalError}});
      co_return false;
    }

    self.reset();
    auto existing = co_await await_step<NodeAccessorResult>(
      [this](auto completion)
      {
        auto owner = mOwner.lock();
        if (!owner || !owner->mAddressSpace)
          return;
        owner->mAddressSpace->find_node_async(owner->mConditionId, std::move(completion));
      });

    self = mOwner.lock();
    if (!self || !self->mAttachState)
      co_return false;
    if (!existing.is_good())
    {
      // The Condition attaches to the Node, so a lookup that is not Good fails the attach; an Uncertain one,
      // with or without the Node, is refused.
      self->fail_attach(VoidResult{
        ::ua::detail::lookup_failure(self->mConditionId, existing.status_code(), "ConditionInstance")});
      co_return false;
    }

    // Every read below is OPTIONAL: a missing parent, a missing child or an unreadable value all
    // apply std::nullopt and leave the bit at its default. Only the instance going away stops the
    // loop. The chain expressed this with three sub-steps and an index; it is three awaits.
    const std::size_t readCount = self->mAttachState->stateBitReads.size();
    for (std::size_t i = 0; i < readCount; ++i)
    {
      self = mOwner.lock();
      if (!self || !self->mAttachState)
        co_return false;
      const auto desc = self->mAttachState->stateBitReads[i];

      NodeId parentId = self->mConditionId;
      NodeId childReferenceType{ReferenceTypeId::HasProperty};

      if (desc.kind == ConditionInstance::AttachState::StateBitReadDescriptor::Kind::BoolChild)
      {
        // Find the parent that holds the bit, then the bit under it.
        self.reset();
        auto parentResult = co_await await_step<NodeIdResult>(
          [this, &desc](auto completion)
          {
            auto owner = mOwner.lock();
            if (!owner || !owner->mAddressSpace)
              return;
            instance_utils::find_child_id_by_browse_name_async(*owner->mAddressSpace,
              owner->mConditionId,
              NodeId{ReferenceTypeId::HasComponent},
              QualifiedName{0, desc.parentBrowseName},
              std::move(completion));
          });
        self = mOwner.lock();
        if (!self || !self->mAttachState)
          co_return false;
        // Non-fatal: the parent state node is optional. A condition that does not carry this
        // sub-state has it recorded as absent rather than failing the whole attach. An Uncertain answer,
        // with or without the Node, is not acted on, so the sub-state is recorded as absent too.
        if (!parentResult.is_good())
        {
          if (desc.applyBool)
            desc.applyBool(*self, std::nullopt);
          continue;
        }
        parentId = parentResult.value();
      }

      self.reset();
      auto childResult = co_await await_step<NodeIdResult>(
        [this, &desc, &parentId, &childReferenceType](auto completion)
        {
          auto owner = mOwner.lock();
          if (!owner || !owner->mAddressSpace)
            return;
          instance_utils::find_child_id_by_browse_name_async(*owner->mAddressSpace,
            parentId,
            childReferenceType,
            QualifiedName{0, desc.childBrowseName},
            std::move(completion));
        });
      self = mOwner.lock();
      if (!self || !self->mAttachState)
        co_return false;
      // Non-fatal, for the same reason as the parent above: the child is optional, and
      // apply_absent records that it is not present instead of failing the attach. An Uncertain answer
      // is not acted on either.
      if (!childResult.is_good())
      {
        apply_absent(*self, desc);
        continue;
      }

      self.reset();
      auto valueResult = co_await await_step<DataValueResult>(
        [this, &childResult](auto completion)
        {
          auto owner = mOwner.lock();
          if (!owner || !owner->mAddressSpace)
            return;
          instance_utils::read_variable_value_async(
            *owner->mAddressSpace, childResult.value(), std::move(completion));
        });
      self = mOwner.lock();
      if (!self || !self->mAttachState)
        co_return false;

      apply_value(*self, desc, valueResult);
    }

    co_return true;
  }

  /// Wire the variables, register the methods, link the source, ensure the notifier hierarchy.
  ///
  /// Both modes run this, and the ONLY difference between the two copies the chain kept is the
  /// `update_snapshot()` below - which attach makes and initialize does not (AF-K: exactly once,
  /// post-register-methods, pre-source-find; matches pre-flip attach_address_space :551). Eleven of
  /// the twelve functions in those two copies were character-identical.
  ua::async::Task<> run_shared_tail()
  {
    const bool attaching = (mMode == Mode::Attach);

    // --- wire the variables -----------------------------------------------------------
    if (auto self = mOwner.lock())
    {
      self->mWiringRefusal.reset();
    }
    for (std::size_t i = 0;; ++i)
    {
      auto self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;
      // A Variable that exists and cannot be wired fails the Condition, as add_method fails without a call
      // source: a Condition whose Variables never change is not silently accepted.
      if (const auto& wiringRefusal = self->mWiringRefusal; wiringRefusal)
      {
        fail(*self, wiringRefusal.value());
        co_return;
      }
      const auto& wires = wire_descriptors(*self);
      if (i >= wires.size())
        break;
      const auto desc = wires[i];

      self.reset();
      co_await await_step<VoidResult>(
        [this, &desc](auto completion)
        {
          auto owner = mOwner.lock();
          if (!owner)
            return;
          owner->dispatch_wire_descriptor(
            desc, [completion = std::move(completion)]() mutable { completion(VoidResult{}); });
        });
    }

    // --- register the methods ---------------------------------------------------------
    for (std::size_t i = 0;; ++i)
    {
      auto self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;
      const auto& registers = register_descriptors(*self);
      if (i >= registers.size())
        break;
      const auto desc = registers[i];

      if (desc.underShelvingState && !self->mResolvedShelvingStateId.has_value())
      {
        self.reset();
        auto idResult = co_await await_step<NodeIdResult>(
          [this](auto completion)
          {
            auto owner = mOwner.lock();
            if (!owner || !owner->mAddressSpace)
              return;
            instance_utils::find_child_id_by_browse_name_async(*owner->mAddressSpace,
              owner->mConditionId,
              NodeId{ReferenceTypeId::HasComponent},
              QualifiedName{0, "ShelvingState"},
              std::move(completion));
          });
        self = mOwner.lock();
        if (!self || !flow_alive(*self))
          co_return;
        self->mResolvedShelvingStateId = idResult.is_good() ? idResult.value() : NodeId{};
      }

      // A descriptor under ShelvingState is skipped entirely when there is no ShelvingState.
      NodeId target;
      if (desc.underShelvingState)
      {
        const auto& shelvingStateId = self->mResolvedShelvingStateId;
        if (!shelvingStateId.has_value() || shelvingStateId.value().is_null())
        {
          continue;
        }
        target = shelvingStateId.value();
      }
      else
      {
        target = self->mConditionId;
      }
      self.reset();
      auto registerResult = co_await await_step<VoidResult>(
        [this, &desc, &target](auto completion)
        {
          auto owner = mOwner.lock();
          if (!owner)
            return;
          owner->dispatch_register_descriptor(desc, target, std::move(completion));
        });
      self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;
      if (registerResult.is_bad() && desc.fatalOnFailure)
      {
        fail(*self, VoidResult{registerResult.status_code(), registerResult.shared_detail()});
        co_return;
      }
      // Optional method registration: failure is best-effort (per pre-flip register_methods
      // `(void)result;` pattern); the flow continues.
    }

    {
      auto self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;
      if (attaching)
      {
        // AF-K: update_snapshot() invoked exactly once, post-register-methods, pre-source-find.
        // Matches pre-flip attach_address_space :551. Initialize does NOT do this.
        self->update_snapshot();
      }
      if (!self->mAddressSpace)
      {
        fail(*self, VoidResult{StatusCode{Status::BadInternalError}});
        co_return;
      }
    }

    // --- find the source and add HasCondition; both are best-effort -------------------
    auto sourceResult = co_await await_step<NodeAccessorResult>(
      [this](auto completion)
      {
        auto owner = mOwner.lock();
        if (!owner || !owner->mAddressSpace)
          return;
        owner->mAddressSpace->find_node_async(owner->mSourceNode, std::move(completion));
      });
    {
      auto self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;

      // Source-find failure is best-effort (pre-flip had no else branch): HasCondition is skipped
      // and the notifier hierarchy is still attempted.
      if (sourceResult.is_good())
      {
        auto& sourceAccessor = source_accessor(*self).emplace(std::move(sourceResult).value());
        // The add-reference result is discarded, exactly as pre-flip discarded it. The lambda locks the
        // instance before it touches the accessor the instance holds.
        self.reset();
        co_await await_step<VoidResult>(
          [this, &sourceAccessor](auto completion)
          {
            auto owner = mOwner.lock();
            if (!owner)
              return;
            sourceAccessor.add_reference_async(NodeId{ReferenceTypeId::HasCondition},
              ExpandedNodeId{owner->mConditionId},
              true,
              ReferenceHalves::Both,
              std::move(completion));
          });
      }
    }

    // --- ensure the notifier hierarchy ------------------------------------------------
    {
      auto self = mOwner.lock();
      if (!self || !flow_alive(*self))
        co_return;
      if (!self->mAddressSpace)
      {
        complete(*self);
        co_return;
      }
    }

    auto notifierSource = co_await await_step<NodeAccessorResult>(
      [this](auto completion)
      {
        auto owner = mOwner.lock();
        if (!owner || !owner->mAddressSpace)
          return;
        owner->mAddressSpace->find_node_async(owner->mSourceNode, std::move(completion));
      });

    auto self = mOwner.lock();
    if (!self || !flow_alive(*self))
      co_return;
    if (!notifierSource.is_good())
    {
      // The source's EventNotifier is written and the notifier References added on it, so a lookup that is
      // not Good fails the flow; an Uncertain one, with or without the Node, is refused.
      fail(*self,
        VoidResult{::ua::detail::lookup_failure(
          self->mSourceNode, notifierSource.status_code(), "ConditionInstance")});
      co_return;
    }

    auto sourceAccessor = std::move(notifierSource).value();
    auto objectAccessor = sourceAccessor.as<ObjectAccessor>();
    notifier_reference_type(*self) = NodeId{ReferenceTypeId::HasEventSource};
    if (objectAccessor)
    {
      auto eventNotifier = objectAccessor->get_event_notifier();
      if (!eventNotifier.test(EventNotifierType::Bit::SubscribeToEvents))
      {
        // The SourceNode is the application's choice and may live in a namespace that answers by posting
        // to this strand, so the EventNotifier is written by an awaited write, never a blocking setter.
        eventNotifier.set(EventNotifierType::Bit::SubscribeToEvents);
        self.reset();
        auto written = co_await await_step<VoidResult>(
          [&sourceAccessor, encoded = attribute_wire::event_notifier(eventNotifier)](auto completion) mutable
          {
            sourceAccessor.write_attribute_async(
              AttributeId::EventNotifier, std::move(encoded), std::move(completion));
          });
        self = mOwner.lock();
        if (!self || !flow_alive(*self))
          co_return;
        if (written.is_bad())
        {
          fail(*self, std::move(written));
          co_return;
        }
      }
      notifier_reference_type(*self) = NodeId{ReferenceTypeId::HasNotifier};
    }

    static const NodeId serverObjectId{ObjectId::Server};
    if (self->mSourceNode == serverObjectId)
    {
      complete(*self);
      co_return;
    }

    // Both halves in one call: the forward half on the Server Object, the inverse on the source.
    // HasNotifier is refused as another type only where a HasEventSource of the same identity is held (Part 3
    // 4.3.4). That Reference already brings the source's events to the Server, which is what the link is for,
    // as does the same Reference already held, so neither refusal fails the flow.
    WeakAddressSpace addressSpace;
    std::shared_ptr<const std::vector<ReferenceChange>> changes;
    {
      const auto& ownerAddressSpace = self->mAddressSpace;
      if (!ownerAddressSpace)
      {
        complete(*self);
        co_return;
      }
      const auto pair =
        ReferenceChange::both_halves(serverObjectId, notifier_reference_type(*self), self->mSourceNode);
      changes = std::make_shared<const std::vector<ReferenceChange>>(pair.begin(), pair.end());
      addressSpace = ownerAddressSpace.value().weak();
    }
    self.reset();
    const auto added = co_await await_step<std::vector<VoidResult>>(
      [&addressSpace, &changes](auto completion)
      {
        ::ua::detail::NodeAccessorRoute::add_references(
          addressSpace, RequestInfo{}, changes, std::move(completion));
      });
    self = mOwner.lock();
    if (!self || !flow_alive(*self))
      co_return;
    for (const auto& half : added)
    {
      if (half.is_bad() && half.status_code().as_status() != Status::BadDuplicateReferenceNotAllowed)
      {
        fail(*self, VoidResult{half.status_code(), half.shared_detail()});
        co_return;
      }
    }

    complete(*self);
  }

  /// The frame could not be allocated. The flow state still holds the caller's callback, so the
  /// failure is reported through it exactly as any other failure is.
  void fail_to_start(StatusCode status)
  {
    if (auto self = mOwner.lock())
    {
      fail(*self, VoidResult{status, status.shared_detail()});
    }
  }

  // --- the two modes differ only in which flow state they read -----------------------
  bool flow_alive(ConditionInstance& self) const
  {
    return (mMode == Mode::Attach) ? static_cast<bool>(self.mAttachState)
                                   : static_cast<bool>(self.mInitializeState);
  }

  std::vector<ConditionInstance::WireDescriptor>& wire_descriptors(ConditionInstance& self) const
  {
    return (mMode == Mode::Attach) ? self.mAttachState->wireDescriptors
                                   : self.mInitializeState->wireDescriptors;
  }

  std::vector<ConditionInstance::RegisterDescriptor>& register_descriptors(ConditionInstance& self) const
  {
    return (mMode == Mode::Attach) ? self.mAttachState->registerDescriptors
                                   : self.mInitializeState->registerDescriptors;
  }

  std::optional<NodeAccessor>& source_accessor(ConditionInstance& self) const
  {
    return (mMode == Mode::Attach) ? self.mAttachState->sourceAccessor
                                   : self.mInitializeState->sourceAccessor;
  }

  NodeId& notifier_reference_type(ConditionInstance& self) const
  {
    return (mMode == Mode::Attach) ? self.mAttachState->notifierReferenceType
                                   : self.mInitializeState->notifierReferenceType;
  }

  void complete(ConditionInstance& self) const
  {
    if (mMode == Mode::Attach)
      self.complete_attach_success();
    else
      self.complete_initialize_success();
  }

  void fail(ConditionInstance& self, VoidResult bad) const
  {
    if (mMode == Mode::Attach)
      self.fail_attach(std::move(bad));
    else
      self.fail_initialize(std::move(bad));
  }

  static void apply_absent(
    ConditionInstance& self, const ConditionInstance::AttachState::StateBitReadDescriptor& desc)
  {
    if (desc.kind == ConditionInstance::AttachState::StateBitReadDescriptor::Kind::BoolChild)
    {
      if (desc.applyBool)
        desc.applyBool(self, std::nullopt);
    }
    else if (desc.applyUint16)
    {
      desc.applyUint16(self, std::nullopt);
    }
  }

  static void apply_value(ConditionInstance& self,
    const ConditionInstance::AttachState::StateBitReadDescriptor& desc, const DataValueResult& result)
  {
    if (desc.kind == ConditionInstance::AttachState::StateBitReadDescriptor::Kind::BoolChild)
    {
      std::optional<bool> applied;
      if (result.is_good())
      {
        if (const auto* val = result.value().value().try_as<bool>())
          applied = *val;
      }
      if (desc.applyBool)
        desc.applyBool(self, applied);
    }
    else
    {
      std::optional<uint16_t> applied;
      if (result.is_good())
      {
        if (const auto* val = result.value().value().try_as<uint16_t>())
          applied = *val;
      }
      if (desc.applyUint16)
        desc.applyUint16(self, applied);
    }
  }

  std::weak_ptr<ConditionInstance> mOwner;
  Mode mMode;
};

}  // namespace detail

namespace
{

/// Convert a StatusCode to a VoidResult.
/// A Good StatusCode is the result as the ConditionLogic gave it, a Good subcode included; any other is the
/// error VoidResult, with the ErrorDetail naming the rejected transition.
///
/// @param status      Outcome the ConditionLogic returned for the transition.
/// @param conditionId Condition the transition was requested on.
/// @param eventId     EventId the caller presented, for the transitions that take one
///                    (Acknowledge / Confirm); nullptr for those that do not.
VoidResult status_to_result(StatusCode status, const NodeId& conditionId, const ByteString* eventId = nullptr)
{
  if (status.is_good())
  {
    return VoidResult{std::move(status)};
  }
  // The leaf status names the rule that failed (BadEventIdUnknown, BadConditionDisabled);
  // the context names the occurrence, which is what a caller needs to act. Acknowledge and
  // Confirm reject a *stale* EventId, so carrying the id the caller presented is what
  // distinguishes "wrong id" from "wrong condition".
  auto builder = ua::ErrorDetail::build("ConditionTransitionRejected",
    "the condition logic rejected the requested transition",
    "ConditionInstance");
  builder.context(ua::ContextKeys::nodeId, conditionId).cause(status);
  if (eventId)
  {
    builder.context(ua::ContextKeys::eventId, ua::to_string(*eventId));
  }
  return VoidResult{status, builder};
}

/// The refusal of a Condition's Variable whose namespace offers no value source: the Condition cannot keep
/// its Value, as `add_method` cannot install a handler without a call source.
VoidResult values_not_supported(const NodeId& variable)
{
  return VoidResult{StatusCode{Status::BadNotSupported,
    ErrorDetail::build("ValueSourcesNotSupported",
      "The namespace's Variables accept no value source, so the Condition cannot keep this Variable's Value",
      "ConditionInstance")
      .context(ua::ContextKeys::nodeId, to_string(variable))}};
}

/// Gives a wired Variable an explicit MinimumSamplingInterval of 0 when it has none. Its Value changes only
/// when the Condition pushes it through `notify_value_changed`, which reports every change, and 0 says so
/// (OPC 10000-4 5.12.1.2): a MonitoredItem at interval 0 is then fed by the pushes rather than sampled. A
/// Variable with its own interval keeps it. A refusal is logged; that Variable's items are sampled, which
/// still reads its Value.
void declare_every_change_reported(NodeAccessor variable, const ua::Logger& logger)
{
  try
  {
    if (variable->attributes().minimum_sampling_interval().has_value())
    {
      return;
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
    return;
  }
  variable.write_attribute_async(AttributeId::MinimumSamplingInterval,
    attribute_wire::minimum_sampling_interval(Duration{0}),
    [logger, nodeId = variable.get_node_id()](VoidResult written)
    {
      if (written.is_bad())
      {
        const std::string idText = to_string(nodeId);
        const std::string causeText = to_string(written.status_code());
        logger.warning({{"node_id", std::string_view{idText}}, {"cause", std::string_view{causeText}}},
          "Condition Variable {} keeps no MinimumSamplingInterval of 0, so its items are sampled: {}",
          idText,
          causeText);
      }
    });
}

/// Ensure a Condition variable read carries timestamps. The Condition value/state readers build a bare
/// DataValue{Variant{...}} with no timestamps; OPC 10000-4 7.7.3 requires a non-null SourceTimestamp when
/// a Client reads with TimestampsToReturn=Both/Source (the UACTT rejects an unset 0001-01-01 timestamp).
/// Fill a server-read SourceTimestamp/ServerTimestamp when the reader supplied none (a reader that has a
/// meaningful change time - e.g. a TwoStateVariable's TransitionTime - may set source_timestamp itself).
DataValue with_read_timestamps(DataValue value)
{
  auto now = DateTime::now();
  // Bind each optional once (shape-1 call-once-and-bind): the accessor returns a reference to the
  // same member, so the .has_value() guard and the ->is_null() deref must share one binding for the
  // checker to prove engagement on the deref. The accessor is a plain member getter (no side
  // effects), so calling once is behaviour-identical.
  auto& sourceTimestamp = value.source_timestamp();
  if (!sourceTimestamp.has_value() || sourceTimestamp->is_null())
  {
    sourceTimestamp = now;
  }
  auto& serverTimestamp = value.server_timestamp();
  if (!serverTimestamp.has_value() || serverTimestamp->is_null())
  {
    serverTimestamp = now;
  }
  return value;
}

StatusCode normalize_input_communication_failure(StatusCode cause)
{
  if (cause.as_status() == Status::BadCommunicationError)
  {
    return cause;
  }
  return StatusCode{Status::BadCommunicationError,
    make_error_detail("ConditionInputCommunicationFailure",
      "The bound Condition input could not be read from its underlying system",
      "ConditionInstance",
      cause)};
}

}  // namespace

// --- Construction ---

ConditionInstance::ConditionInstance(boost::asio::any_io_executor executor,
  std::unique_ptr<ConditionLogic> logic, NodeId conditionId, NodeId sourceNode, String sourceName,
  std::weak_ptr<EventSink> eventSink, std::optional<AddressSpace> addressSpace, NodeId typeDefinition,
  InputCommunicationObserver inputCommunicationObserver)
  : mStrand(boost::asio::make_strand(executor)), mLogic(std::move(logic)),
    mSnapshot(std::make_shared<ConditionStateSnapshot>()), mConditionId(std::move(conditionId)),
    mSourceNode(std::move(sourceNode)), mSourceName(std::move(sourceName)), mEventSink(std::move(eventSink)),
    mAddressSpace(std::move(addressSpace)), mTypeDefinition(std::move(typeDefinition)),
    mLogger(mAddressSpace ? mAddressSpace->logger().with_category("conditions") : ua::Logger{})
{
  mLogic->set_source(mSourceNode, mSourceName);
  mInputCommunicationObserver = std::move(inputCommunicationObserver);
}

std::shared_ptr<ConditionInstance> ConditionInstance::create(boost::asio::any_io_executor executor,
  std::unique_ptr<ConditionLogic> logic, NodeId conditionId, NodeId sourceNode, String sourceName,
  std::weak_ptr<EventSink> eventSink, std::optional<AddressSpace> addressSpace, NodeId typeDefinition,
  InputCommunicationObserver inputCommunicationObserver)
{
  // Cannot use make_shared because the constructor is private.
  return std::shared_ptr<ConditionInstance>(new ConditionInstance(std::move(executor),
    std::move(logic),
    std::move(conditionId),
    std::move(sourceNode),
    std::move(sourceName),
    std::move(eventSink),
    std::move(addressSpace),
    std::move(typeDefinition),
    std::move(inputCommunicationObserver)));
}

// --- Thread-safe accessors ---

std::shared_ptr<const ConditionStateSnapshot> ConditionInstance::snapshot() const
{
  return mSnapshot;
}

const NodeId& ConditionInstance::condition_id() const
{
  return mConditionId;
}

const NodeId& ConditionInstance::source_node() const
{
  return mSourceNode;
}

// --- Internal helpers (called on strand) ---

void ConditionInstance::apply_transition(const ConditionStateTransition& transition)
{
  if (transition.emitEvent)
  {
    emit_condition_event();
  }

  // Emit branch events (new branches, ack/confirm updates, or deletions)
  for (const auto& branchData : transition.branchEvents)
  {
    emit_branch_event(branchData);
  }

  // Update the snapshot to reflect the current logic state
  update_snapshot();

  // Notify wired AS variables that values may have changed
  notify_wired_variables();

  // Execute any timer start/cancel commands from the transition
  process_timer_commands(transition.timerCommands);
}

void ConditionInstance::emit_condition_event()
{
  auto sink = mEventSink.lock();
  if (!sink)
  {
    return;
  }
  auto event = mLogic->build_event();
  // Carry the ConditionId (this condition object's NodeId) so an EventFilter SimpleAttributeOperand
  // with an empty browse path + NodeId attribute resolves to it.
  event->conditionNodeId = mConditionId;
  sink->emit(*event);
  // After emit, EventBus auto-fills EventId - capture it back into logic
  mLogic->set_last_event_id(event->eventId);
  mLastEmittedTime = event->time;
  mLastEmittedReceiveTime = event->receiveTime;
}

void ConditionInstance::emit_branch_event(const BranchEventData& branchData)
{
  auto* ackLogic = dynamic_cast<AcknowledgeableConditionLogic*>(mLogic.get());
  if (!ackLogic)
  {
    return;
  }

  auto event = ackLogic->build_branch_event(branchData.branchId, branchData.retain);
  if (!event)
  {
    return;
  }
  event->conditionNodeId = mConditionId;

  if (auto sink = mEventSink.lock())
  {
    sink->emit(*event);
  }

  if (branchData.retain)
  {
    // Feed back the assigned EventId so future ack/confirm can target this branch
    ackLogic->set_branch_event_id(branchData.branchId, event->eventId);
  }
  else
  {
    // Branch is resolved - remove it from the logic
    ackLogic->remove_branch(branchData.branchId);
  }
}

void ConditionInstance::update_snapshot()
{
  auto event = mLogic->build_event();

  // build_event() leaves EventId empty (the EventBus assigns it at emission, captured back into the
  // logic) and ReceiveTime null. Reflect the last emitted EventId and treat ReceiveTime as the
  // generation Time so the snapshot - and thus the condition's readable EventId/ReceiveTime field
  // nodes - carry valid values rather than reading back as null/BadAttributeIdInvalid.
  event->eventId = mLogic->last_event_id();
  // Time and ReceiveTime describe that same last event: build_event() stamps "now", and a state change
  // that emits no event (a limit alarm's input moving within its current limit band) must not move them
  // away from the EventId they are read with. Before the first event there is none to describe.
  if (mLastEmittedTime)
  {
    event->time = *mLastEmittedTime;
    event->receiveTime = mLastEmittedReceiveTime != DateTime{} ? mLastEmittedReceiveTime : *mLastEmittedTime;
  }
  else
  {
    event->receiveTime = event->time;
  }

  // Try most specific type first, then fall back
  if (auto* alarmEvent = dynamic_cast<AlarmConditionPayload*>(event.get()))
  {
    mSnapshot->update_from(*alarmEvent);
  }
  else if (auto* ackEvent = dynamic_cast<AcknowledgeableConditionPayload*>(event.get()))
  {
    mSnapshot->update_from(*ackEvent);
  }
  else if (const auto* conditionEvent = dynamic_cast<const ConditionPayload*>(event.get()))
  {
    mSnapshot->update_from(*conditionEvent);
  }

  // Limit-alarm sub-state nodes (F66). Non-exclusive: per-limit TwoStateVariables carried by the
  // payload. Exclusive: LimitState.CurrentState derived from the active limit (ExclusiveLimitStateMachine).
  if (auto* nonExclusive = dynamic_cast<NonExclusiveLimitAlarmPayload*>(event.get()))
  {
    mSnapshot->set_non_exclusive_limit_states(nonExclusive->highHighState,
      nonExclusive->highState,
      nonExclusive->lowState,
      nonExclusive->lowLowState);
  }
  else if (const auto* limitLogic = dynamic_cast<const LimitAlarmLogic*>(mLogic.get());
           limitLogic != nullptr && limitLogic->exclusive())
  {
    LocalizedText currentStateName;
    NodeId currentStateId;
    switch (limitLogic->active_limit())
    {
    case ActiveLimit::HighHigh:
      currentStateName = LocalizedText{"", "HighHigh"};
      currentStateId = NodeId{ObjectId::ExclusiveLimitStateMachineType_HighHigh};
      break;
    case ActiveLimit::High:
      currentStateName = LocalizedText{"", "High"};
      currentStateId = NodeId{ObjectId::ExclusiveLimitStateMachineType_High};
      break;
    case ActiveLimit::Low:
      currentStateName = LocalizedText{"", "Low"};
      currentStateId = NodeId{ObjectId::ExclusiveLimitStateMachineType_Low};
      break;
    case ActiveLimit::LowLow:
      currentStateName = LocalizedText{"", "LowLow"};
      currentStateId = NodeId{ObjectId::ExclusiveLimitStateMachineType_LowLow};
      break;
    case ActiveLimit::None:
      break;  // inactive: no current limit state
    }
    mSnapshot->set_exclusive_limit_state(currentStateName, currentStateId);
  }

  // AlarmCondition ShelvingState.CurrentState (a ShelvedStateMachineType). Not carried in any payload,
  // so derive the CurrentState name + state NodeId from the alarm logic - mirrors the exclusive
  // LimitState derivation above. Always set for an alarm (defaults to Unshelved) so the wired
  // ShelvingState/CurrentState node reads a real value with a SourceTimestamp instead of null.
  if (const auto* alarmLogic = dynamic_cast<const AlarmConditionLogic*>(mLogic.get()))
  {
    LocalizedText currentStateName;
    NodeId currentStateId;
    switch (alarmLogic->shelve_state())
    {
    case ShelveState::Unshelved:
      currentStateName = LocalizedText{"", "Unshelved"};
      currentStateId = NodeId{ObjectId::ShelvedStateMachineType_Unshelved};
      break;
    case ShelveState::TimedShelved:
      currentStateName = LocalizedText{"", "TimedShelved"};
      currentStateId = NodeId{ObjectId::ShelvedStateMachineType_TimedShelved};
      break;
    case ShelveState::OneShotShelved:
      currentStateName = LocalizedText{"", "OneShotShelved"};
      currentStateId = NodeId{ObjectId::ShelvedStateMachineType_OneShotShelved};
      break;
    }
    mSnapshot->set_shelve_state(currentStateName, currentStateId);
    mSnapshot->set_unshelve_clock(alarmLogic->unshelve_clock());
  }

  // Publish the current state as an immutable payload. Event-field node value-readers resolve through
  // this payload's resolve_field() - the same resolver the emitted event uses - so a Read of any event
  // field equals the value the event carries, by construction. (Derived non-event state such as
  // ShelvingState/CurrentState and the exclusive LimitState is not carried by any payload and stays
  // sourced from mSnapshot above.)
  mEventState.store(std::shared_ptr<const BaseEvent>{std::move(event)});
}

void ConditionInstance::install_value_read_handler(
  NodeId variableId, std::function<DataValue()> valueReader, std::function<void()> onComplete)
{
  if (!mAddressSpace)
  {
    onComplete();
    return;
  }
  auto me = weak_from_this();
  mAddressSpace->find_node_async(variableId,
    [me, valueReader = std::move(valueReader), onComplete = std::move(onComplete)](
      NodeAccessorResult nodeResult) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
      {
        onComplete();
        return;
      }
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [nodeResult = std::move(nodeResult),
          valueReader = std::move(valueReader),
          onComplete = std::move(onComplete)](ConditionInstance& self) mutable
        {
          // Optional: a Variable that cannot be found, or whose lookup is not Good (an Uncertain answer is
          // not acted on), is not wired.
          if (!nodeResult.is_good())
          {
            onComplete();
            return;
          }
          auto* externalSource = nodeResult.value()->external_value_source();
          if (!externalSource)
          {
            self.refuse_wiring(values_not_supported(nodeResult.value().get_node_id()));
            onComplete();
            return;
          }
          auto setResult = externalSource->set_value_source(detail::whole_value_source(
            [valueReader](
              const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
            { complete(DataValueResult{with_read_timestamps(valueReader())}); }));
          if (setResult.is_bad())
          {
            self.refuse_wiring(std::move(setResult));
            onComplete();
            return;
          }
          declare_every_change_reported(nodeResult.value(), self.mLogger);
          self.mWiredVariables.push_back(VariableWiring{nodeResult.value(), std::move(valueReader)});
          onComplete();
        })();
    });
}

void ConditionInstance::resolve_nested_and_install(std::vector<QualifiedName> path,
  std::vector<NodeId> referenceTypes, std::size_t index, NodeId parent,
  std::function<DataValue()> valueReader, std::function<void()> onComplete)
{
  if (!mAddressSpace || index >= path.size() || path.size() != referenceTypes.size())
  {
    onComplete();
    return;
  }
  auto me = weak_from_this();
  // Read the current segment/refType into locals FIRST: the lambda below moves `path`/`referenceTypes`,
  // and argument evaluation order is unspecified, so indexing them inline could read a moved-from vector.
  const NodeId segmentRefType = referenceTypes[index];
  const QualifiedName segmentName = path[index];
  instance_utils::find_child_id_by_browse_name_async(*mAddressSpace,
    parent,
    segmentRefType,
    segmentName,
    [me,
      path = std::move(path),
      referenceTypes = std::move(referenceTypes),
      index,
      valueReader = std::move(valueReader),
      onComplete = std::move(onComplete)](NodeIdResult childResult) mutable
    {
      auto lockedSelf = me.lock();
      if (!lockedSelf)
      {
        onComplete();
        return;
      }
      ua::async::post_borrowing(lockedSelf.get(),
        lockedSelf->mStrand,
        lockedSelf->mLogger,
        [path = std::move(path),
          referenceTypes = std::move(referenceTypes),
          index,
          valueReader = std::move(valueReader),
          onComplete = std::move(onComplete),
          childResult = std::move(childResult)](ConditionInstance& self) mutable
        {
          // An Uncertain answer, with or without the child, is not acted on: the child is not wired.
          if (!childResult.is_good())
          {
            onComplete();
            return;
          }
          const NodeId childId = childResult.value();
          if (index + 1 == path.size())
          {
            self.install_value_read_handler(childId, std::move(valueReader), std::move(onComplete));
          }
          else
          {
            self.resolve_nested_and_install(std::move(path),
              std::move(referenceTypes),
              index + 1,
              childId,
              std::move(valueReader),
              std::move(onComplete));
          }
        })();
    });
}

void ConditionInstance::notify_wired_variables()
{
  if (!mAddressSpace)
  {
    return;
  }

  for (auto& wiring : mWiredVariables)
  {
    // A Variable deleted since it was bound has nothing more to be told.
    if (!wiring.reader || wiring.node->deleted())
    {
      continue;
    }
    if (auto* source = wiring.node->external_value_source())
    {
      source->notify_value_changed(wiring.reader());
    }
  }
}

void ConditionInstance::emit_audit_event(BaseEvent& auditEvent, std::string_view sourceName)
{
  auto sink = mEventSink.lock();
  if (!sink)
  {
    return;
  }
  // OPC 10000-9 section 5.10: a Condition audit names the ConditionId, not the Server Object. The channel
  // and session audit families do name the Server, and a shared helper that stamped it on every
  // audit got those right and this one wrong while still emitting the correct Event type -- which is
  // why the two are stamped apart rather than together.
  auditEvent.sourceNode = condition_id();
  auditEvent.sourceName = String{sourceName};
  auditEvent.time = DateTime::now();
  auditEvent.severity = 1;
  sink->emit(auditEvent);
}

template<class Op, class MethodCompleteCb>
void ConditionInstance::run_method_on_strand(
  String clientUserId, ByteString eventId, bool hasEventId, Op&& operation, MethodCompleteCb&& callback)
{
  // The completion this post owns is the 2-argument MethodCompleteCallback. post_borrowing's
  // completion-owning overload delivers a single result value, so pair the MethodCompletion kind with
  // the VoidResult outcome: the dead-self path delivers (Threw, BadInternalError) exactly as the
  // pre-flip code did, and the live path delivers the computed (kind, outcome) after the try/catch.
  using MethodOutcome = std::pair<MethodCompletion, VoidResult>;
  auto completionAdapter = [callback = std::forward<MethodCompleteCb>(callback)](
                             MethodOutcome outcome) mutable
  {
    ua::detail::invoke_user_callback(callback, outcome.first, std::move(outcome.second));
  };
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionAdapter),
    MethodOutcome{MethodCompletion::Threw, VoidResult{StatusCode{Status::BadInternalError}}},
    [userId = std::move(clientUserId),
      eventId = std::move(eventId),
      hasEventId,
      op = std::forward<Op>(operation)](ConditionInstance& self, auto completion) mutable
    {
      // Compute the completion kind + result into locals so the completion is fired EXACTLY ONCE,
      // after the try/catch. MethodCompleteCallback is a 2-argument callback (not the single-argument
      // shape make_fire_once supports), so the single-fire discipline is enforced structurally here.
      MethodCompletion kind = MethodCompletion::Returned;
      VoidResult outcome{};
      try
      {
        self.mLogic->set_client_user_id(std::move(userId));
        const bool wasEnabled = self.mSnapshot->enabled();
        auto transition = op(*self.mLogic);
        self.apply_transition(transition);
        if (!wasEnabled && self.mSnapshot->enabled())
          self.evaluate_input_if_bound();
        kind = MethodCompletion::Returned;
        outcome = status_to_result(transition.status, self.mConditionId, hasEventId ? &eventId : nullptr);
      }
      catch (...)
      {
        kind = MethodCompletion::Threw;
        outcome = ua::exception_to_status_code(std::current_exception());
      }
      completion(MethodOutcome{kind, std::move(outcome)});
    })();
}

void ConditionInstance::evaluate_input_if_bound()
{
  // Must be called on the strand.
  if (mInputNode.is_null() || !mAddressSpace)
    return;

  const auto* alarm = dynamic_cast<const AlarmConditionLogic*>(mLogic.get());
  if (!alarm)
    return;

  // Fire-and-forget read+evaluate via the address space's *_async surface.
  // The callback re-locks weak_from_this() and bails on null.
  auto me = weak_from_this();
  instance_utils::read_variable_value_async(*mAddressSpace,
    mInputNode,

    [me](DataValueResult readResult)
    {
      auto self = me.lock();
      if (!self)
        return;
      // Re-dispatch the apply step onto the strand so the logic mutation is
      // strand-serialised regardless of where the AS callback fired.
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [readResult = std::move(readResult)](ConditionInstance& s) mutable
        { s.handle_input_sample(std::move(readResult)); })();
    });
}

void ConditionInstance::handle_input_sample(DataValueResult readResult)
{
  auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(mLogic.get());
  if (!alarmLogic)
  {
    return;
  }

  // The alarm evaluates the input's value, so a read that is not Good is a communication failure: an
  // Uncertain answer, with or without a value, is not evaluated, and is the failure's cause.
  std::optional<StatusCode> communicationFailure;
  if (!readResult.is_good())
  {
    communicationFailure = normalize_input_communication_failure(readResult.status_code());
  }
  else
  {
    const auto& valueStatus = readResult.value().status();
    if (valueStatus.has_value() && valueStatus->is_bad())
    {
      communicationFailure = normalize_input_communication_failure(*valueStatus);
    }
  }

  if (communicationFailure.has_value())
  {
    if (!mInputCommunicationEstablished)
    {
      return;
    }
    mWaitingForInitialInput = false;
    if (!mInputCommunicationFailed)
    {
      mInputCommunicationFailed = true;
      log_exception(
        mLogger, LogLevel::Warning, "ConditionInstance.InputCommunicationFailure", *communicationFailure);
      apply_transition(mLogic->set_quality(*communicationFailure));
      notify_input_communication_state(*communicationFailure);
    }
    return;
  }

  if (mInputCommunicationFailed || mWaitingForInitialInput)
  {
    const bool recovered = mInputCommunicationFailed;
    mInputCommunicationFailed = false;
    mWaitingForInitialInput = false;
    apply_transition(mLogic->set_quality(StatusCode{Status::Good}));
    if (recovered)
    {
      notify_input_communication_state(StatusCode{Status::Good});
    }
  }

  mInputCommunicationEstablished = true;

  auto transition = alarmLogic->evaluate_input(readResult.value().value(), DateTime::now());
  apply_transition(transition);
}

void ConditionInstance::notify_input_communication_state(StatusCode status)
{
  if (mInputCommunicationObserver && !mInputNode.is_null())
  {
    mInputCommunicationObserver(mConditionId, mInputNode, std::move(status));
  }
}

namespace
{

/// A timer command's duration, saturated to what a steady-clock deadline can hold. Durations arrive from
/// Clients (TimedShelve's ShelvingTime is a Duration a Client may set to the largest Double to mean "as
/// long as the Server allows") and from configuration; a Double past the int64 millisecond range, or one
/// that puts now + duration past steady_clock's 64-bit nanosecond range (about 292 years), cannot become
/// a deadline. Ten years is indistinguishable from "until unshelved" for an alarm and keeps the deadline
/// representable. A non-positive or NaN duration fires immediately.
std::chrono::milliseconds timer_duration(double durationMs)
{
  constexpr auto longest =
    std::chrono::milliseconds{static_cast<int64_t>(AlarmConditionLogic::longestShelvingTimeMs)};
  if (!(durationMs > 0.0))
  {
    return std::chrono::milliseconds{0};
  }
  if (durationMs >= static_cast<double>(longest.count()))
  {
    return longest;
  }
  return std::chrono::milliseconds{static_cast<int64_t>(durationMs)};
}

}  // namespace

void ConditionInstance::process_timer_commands(const std::vector<TimerCommand>& commands)
{
  for (const auto& cmd : commands)
  {
    auto duration = timer_duration(cmd.durationMs);

    switch (cmd.kind)
    {
    case TimerCommand::Kind::StartOnDelay:
    {
      mOnDelayTimer.cancel();
      auto me = weak_from_this();
      mOnDelayTimer = Timer::schedule_after(mStrand,
        duration,
        [me](boost::system::error_code ec)
        {
          if (ec)
            return;
          auto self = me.lock();
          if (!self)
            return;
          try
          {
            auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self->mLogic.get());
            if (alarmLogic)
            {
              auto transition = alarmLogic->on_delay_expired();
              self->apply_transition(transition);
            }
          }
          catch (...)
          {
            ua::detail::ignore_expected_exception();
          }
        });
      break;
    }
    case TimerCommand::Kind::CancelOnDelay:
    {
      mOnDelayTimer.cancel();
      break;
    }
    case TimerCommand::Kind::StartOffDelay:
    {
      mOffDelayTimer.cancel();
      auto me = weak_from_this();
      mOffDelayTimer = Timer::schedule_after(mStrand,
        duration,
        [me](boost::system::error_code ec)
        {
          if (ec)
            return;
          auto self = me.lock();
          if (!self)
            return;
          try
          {
            auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self->mLogic.get());
            if (alarmLogic)
            {
              auto transition = alarmLogic->off_delay_expired();
              self->apply_transition(transition);
            }
          }
          catch (...)
          {
            ua::detail::ignore_expected_exception();
          }
        });
      break;
    }
    case TimerCommand::Kind::CancelOffDelay:
    {
      mOffDelayTimer.cancel();
      break;
    }
    case TimerCommand::Kind::StartShelveTimer:
    {
      mShelveTimer.cancel();
      auto me = weak_from_this();
      mShelveTimer = Timer::schedule_after(mStrand,
        duration,
        [me](boost::system::error_code ec)
        {
          if (ec)
            return;
          auto self = me.lock();
          if (!self)
            return;
          try
          {
            auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self->mLogic.get());
            if (alarmLogic)
            {
              auto transition = alarmLogic->on_shelve_timer_expired();
              self->apply_transition(transition);
            }
          }
          catch (...)
          {
            ua::detail::ignore_expected_exception();
          }
        });
      break;
    }
    case TimerCommand::Kind::CancelShelveTimer:
    {
      mShelveTimer.cancel();
      break;
    }
    case TimerCommand::Kind::StartReAlarmTimer:
    {
      mReAlarmTimer.cancel();
      auto me = weak_from_this();
      mReAlarmTimer = Timer::schedule_after(mStrand,
        duration,
        [me](boost::system::error_code ec)
        {
          if (ec)
            return;
          auto self = me.lock();
          if (!self)
            return;
          try
          {
            auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self->mLogic.get());
            if (alarmLogic)
            {
              auto transition = alarmLogic->on_re_alarm_timer_expired();
              self->apply_transition(transition);
            }
          }
          catch (...)
          {
            log_exception(self->mLogger, "ConditionInstance::re_alarm_timer", std::current_exception());
          }
        });
      break;
    }
    case TimerCommand::Kind::CancelReAlarmTimer:
    {
      mReAlarmTimer.cancel();
      break;
    }
    case TimerCommand::Kind::None:
      break;
    }
  }
}

// --- Wire descriptor builder ---

std::vector<ConditionInstance::WireDescriptor> ConditionInstance::build_wire_descriptors() const
{
  // Capture the snapshot by shared_ptr value so the closures keep it alive.
  // update_snapshot() mutates the same snapshot in place; the closures observe
  // the latest values at call time. (Pre-flip behaviour preserved.)
  auto snapshotState = mSnapshot;
  std::vector<WireDescriptor> descriptors;
  descriptors.reserve(35);

  // Mandatory BaseEventType / ConditionType property nodes. A Condition is represented as a NODE whose
  // current state must be READABLE from the address space (Part 9 4.4), not only carried in the event
  // notification. Each reader sources its value and SourceTimestamp from the snapshot's last event, so a
  // client (and the UACTT InstanceCompareInstance) reads a typed value instead of BadAttributeIdInvalid.
  const auto directChildFromSnapshot = [&descriptors, snapshotState](
                                         std::string_view name, std::function<Variant()> read)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, std::string{name}};
    d.valueReader = [snapshotState, read = std::move(read)]()
    {
      DataValue value{read()};
      value.source_timestamp() = snapshotState->time();
      return value;
    };
    descriptors.push_back(std::move(d));
  };
  directChildFromSnapshot("EventId", [snapshotState]() { return Variant{snapshotState->event_id()}; });
  directChildFromSnapshot("EventType", [snapshotState]() { return Variant{snapshotState->event_type()}; });
  directChildFromSnapshot("SourceNode", [snapshotState]() { return Variant{snapshotState->source_node()}; });
  directChildFromSnapshot("SourceName", [snapshotState]() { return Variant{snapshotState->source_name()}; });
  directChildFromSnapshot("Time", [snapshotState]() { return Variant{snapshotState->time()}; });
  directChildFromSnapshot(
    "ReceiveTime", [snapshotState]() { return Variant{snapshotState->receive_time()}; });
  directChildFromSnapshot("Message", [snapshotState]() { return Variant{snapshotState->message()}; });
  directChildFromSnapshot(
    "ConditionClassId", [snapshotState]() { return Variant{snapshotState->condition_class_id()}; });
  directChildFromSnapshot(
    "ConditionClassName", [snapshotState]() { return Variant{snapshotState->condition_class_name()}; });
  directChildFromSnapshot(
    "ConditionName", [snapshotState]() { return Variant{snapshotState->condition_name()}; });
  // BranchId is null for the main/current branch; wiring it returns that typed NodeId with a
  // SourceTimestamp rather than an empty BadAttributeIdInvalid read. ClientUserId carries the identity
  // of the client that last drove a state change (empty until the first user-attributed operation).
  directChildFromSnapshot("BranchId", [snapshotState]() { return Variant{snapshotState->branch_id()}; });
  directChildFromSnapshot(
    "ClientUserId", [snapshotState]() { return Variant{snapshotState->client_user_id()}; });

  // Mandatory event fields that the payload carries but the snapshot does NOT mirror. Resolve them
  // through the payload's resolve_field() - the SAME resolver the emitted event uses - so a Read of the
  // node equals the value carried by the event, by construction, without a bespoke snapshot accessor.
  // (SupportsFilteredRetain: Mandatory on ConditionType in 1.05. NormalState: Mandatory NodeId-typed
  // property on OffNormalAlarmType.) resolve_field returns empty for a field the concrete payload lacks,
  // which matches the event carrying nothing - so wiring these unconditionally is safe for every type.
  const auto directChildResolved = [&descriptors, snapshotState, me = weak_from_this()](std::string_view name)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    const QualifiedName browseName{0, std::string{name}};
    d.browseName = browseName;
    d.valueReader = [snapshotState, me, browseName]()
    {
      DataValue value;
      if (auto self = me.lock())
      {
        if (auto payload = self->mEventState.load())
        {
          const std::array<QualifiedName, 1> path{browseName};
          value = DataValue{payload->resolve_field(path)};
        }
      }
      value.source_timestamp() = snapshotState->time();
      return value;
    };
    descriptors.push_back(std::move(d));
  };
  directChildResolved("SupportsFilteredRetain");
  directChildResolved("NormalState");

  // 1. EnabledState (TwoStateVariable)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "EnabledState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->enabled_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->enabled();
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->enabled_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 2. Quality (ConditionVariable)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::ConditionVariable;
    d.browseName = QualifiedName{0, "Quality"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->quality()}};
    };
    d.timestampReader = [snapshotState]()
    {
      return snapshotState->quality_source_timestamp();
    };
    descriptors.push_back(std::move(d));
  }
  // 3. LastSeverity (ConditionVariable)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::ConditionVariable;
    d.browseName = QualifiedName{0, "LastSeverity"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->last_severity()}};
    };
    d.timestampReader = [snapshotState]()
    {
      return snapshotState->last_severity_source_timestamp();
    };
    descriptors.push_back(std::move(d));
  }
  // 4. Comment (ConditionVariable)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::ConditionVariable;
    d.browseName = QualifiedName{0, "Comment"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->comment()}};
    };
    d.timestampReader = [snapshotState]()
    {
      return snapshotState->comment_source_timestamp();
    };
    descriptors.push_back(std::move(d));
  }
  // 5. Retain (DirectChild)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, "Retain"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->retained()}};
    };
    descriptors.push_back(std::move(d));
  }
  // 6. Severity (DirectChild)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, "Severity"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->severity()}};
    };
    descriptors.push_back(std::move(d));
  }
  // 7. AckedState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "AckedState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->acked_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->acked();
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->acked_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 8. ConfirmedState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "ConfirmedState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->confirmed_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->confirmed();
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->confirmed_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 9. ActiveState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "ActiveState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->active_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->active();
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->active_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 10. InputNode (DirectChild)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, "InputNode"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->input_node()}};
    };
    descriptors.push_back(std::move(d));
  }
  // 11. SuppressedOrShelved (DirectChild)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, "SuppressedOrShelved"};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->suppressed_or_shelved()}};
    };
    descriptors.push_back(std::move(d));
  }
  // 12. SuppressedState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "SuppressedState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->suppressed_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->suppressed().value_or(false);
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->suppressed_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 13. OutOfServiceState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "OutOfServiceState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->out_of_service_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->out_of_service().value_or(false);
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->out_of_service_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 14. SilenceState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "SilenceState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->silenced_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->silenced().value_or(false);
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->silenced_transition_time();
    };
    descriptors.push_back(std::move(d));
  }
  // 15. LatchedState (TwoStateVariable, optional)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, "LatchedState"};
    d.currentStateReader = [snapshotState]()
    {
      return snapshotState->latched_current_state();
    };
    d.idReader = [snapshotState]()
    {
      return snapshotState->latched().value_or(false);
    };
    d.transitionTimeReader = [snapshotState]()
    {
      return snapshotState->latched_transition_time();
    };
    descriptors.push_back(std::move(d));
  }

  // NonExclusiveLimitAlarm per-limit sub-states (TwoStateVariables). Present only on a non-exclusive
  // limit alarm node; on other conditions these browse names don't resolve and the wiring is skipped.
  const auto twoStateFromOptional =
    [&descriptors](std::string_view name, std::function<std::optional<TwoStateVariableState>()> read)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::TwoState;
    d.browseName = QualifiedName{0, std::string{name}};
    d.currentStateReader = [read]()
    {
      auto state = read();
      return state ? state->currentState : LocalizedText{};
    };
    d.idReader = [read]()
    {
      auto state = read();
      return state && state->id;
    };
    d.transitionTimeReader = [read]()
    {
      auto state = read();
      return state ? state->transitionTime : DateTime{};
    };
    descriptors.push_back(std::move(d));
  };
  twoStateFromOptional("HighHighState", [snapshotState]() { return snapshotState->high_high_state(); });
  twoStateFromOptional("HighState", [snapshotState]() { return snapshotState->high_state(); });
  twoStateFromOptional("LowState", [snapshotState]() { return snapshotState->low_state(); });
  twoStateFromOptional("LowLowState", [snapshotState]() { return snapshotState->low_low_state(); });

  // ExclusiveLimitAlarm LimitState (an ExclusiveLimitStateMachine). CurrentState is reached via
  // LimitState/CurrentState (HasComponentx2) and its Id via .../CurrentState/Id (HasProperty). Present
  // only on an exclusive limit alarm node; skipped elsewhere.
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::NestedValue;
    d.browseName = QualifiedName{0, "LimitState"};
    d.nestedPath = {QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}};
    d.nestedReferenceTypes = {NodeId{ReferenceTypeId::HasComponent}, NodeId{ReferenceTypeId::HasComponent}};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->limit_state_name()}};
    };
    descriptors.push_back(std::move(d));
  }
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::NestedValue;
    d.browseName = QualifiedName{0, "LimitState"};
    d.nestedPath = {QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
    d.nestedReferenceTypes = {NodeId{ReferenceTypeId::HasComponent},
      NodeId{ReferenceTypeId::HasComponent},
      NodeId{ReferenceTypeId::HasProperty}};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->limit_state_id()}};
    };
    descriptors.push_back(std::move(d));
  }

  // AlarmCondition ShelvingState (a ShelvedStateMachineType). CurrentState is reached via
  // ShelvingState/CurrentState (HasComponentx2) and its Id via .../CurrentState/Id (HasProperty).
  // Present only on an alarm node; skipped (best-effort) on other conditions.
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::NestedValue;
    d.browseName = QualifiedName{0, "ShelvingState"};
    d.nestedPath = {QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}};
    d.nestedReferenceTypes = {NodeId{ReferenceTypeId::HasComponent}, NodeId{ReferenceTypeId::HasComponent}};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->shelve_state_name()}};
    };
    descriptors.push_back(std::move(d));
  }
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::NestedValue;
    d.browseName = QualifiedName{0, "ShelvingState"};
    d.nestedPath = {
      QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
    d.nestedReferenceTypes = {NodeId{ReferenceTypeId::HasComponent},
      NodeId{ReferenceTypeId::HasComponent},
      NodeId{ReferenceTypeId::HasProperty}};
    d.valueReader = [snapshotState]()
    {
      return DataValue{Variant{snapshotState->shelve_state_id()}};
    };
    descriptors.push_back(std::move(d));
  }
  // ShelvingState.UnshelveTime (Mandatory): evaluated at read time from the alarm's UnshelveClock, so a
  // TimedShelve counts down between events, with the formula the events use.
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::NestedValue;
    d.browseName = QualifiedName{0, "ShelvingState"};
    d.nestedPath = {QualifiedName{0, "ShelvingState"}, QualifiedName{0, "UnshelveTime"}};
    d.nestedReferenceTypes = {NodeId{ReferenceTypeId::HasComponent}, NodeId{ReferenceTypeId::HasProperty}};
    d.valueReader = [snapshotState]()
    {
      const auto now = DateTime::now();
      DataValue dv{Variant{snapshotState->unshelve_clock().remaining_ms(now)}};
      dv.source_timestamp() = now;
      return dv;
    };
    descriptors.push_back(std::move(d));
  }
  // ShelvingState.LastTransition and its Id and TransitionTime: the last shelving transition, recorded by
  // the snapshot when the shelve state changes. Before the first transition they read null values.
  {
    const auto wireLastTransition = [&descriptors, snapshotState](std::vector<QualifiedName> path,
                                      std::vector<NodeId>
                                        referenceTypes,
                                      std::function<Variant(const ConditionStateSnapshot::ShelveTransition&)>
                                        field)
    {
      WireDescriptor d;
      d.kind = WireDescriptor::Kind::NestedValue;
      d.browseName = QualifiedName{0, "ShelvingState"};
      d.nestedPath = std::move(path);
      d.nestedReferenceTypes = std::move(referenceTypes);
      d.valueReader = [snapshotState, field = std::move(field)]()
      {
        const auto transition = snapshotState->last_shelve_transition();
        if (transition.id.is_null())
          return DataValue{};
        return DataValue{field(transition)};
      };
      descriptors.push_back(std::move(d));
    };
    const QualifiedName shelvingState{0, "ShelvingState"};
    const QualifiedName lastTransition{0, "LastTransition"};
    const NodeId hasComponent{ReferenceTypeId::HasComponent};
    const NodeId hasProperty{ReferenceTypeId::HasProperty};
    wireLastTransition({shelvingState, lastTransition},
      {hasComponent, hasComponent},
      [](const ConditionStateSnapshot::ShelveTransition& t) { return Variant{t.name}; });
    wireLastTransition({shelvingState, lastTransition, QualifiedName{0, "Id"}},
      {hasComponent, hasComponent, hasProperty},
      [](const ConditionStateSnapshot::ShelveTransition& t) { return Variant{t.id}; });
    wireLastTransition({shelvingState, lastTransition, QualifiedName{0, "TransitionTime"}},
      {hasComponent, hasComponent, hasProperty},
      [](const ConditionStateSnapshot::ShelveTransition& t) { return Variant{t.time}; });
  }

  // MaxTimeShelved is static configuration too; the Property exists only when one is configured (see the
  // optional-child filter), and reads the same Duration the alarm's events carry.
  if (const auto* alarmLogic = dynamic_cast<const AlarmConditionLogic*>(mLogic.get());
      alarmLogic && alarmLogic->max_time_shelved() > 0.0)
  {
    WireDescriptor d;
    d.kind = WireDescriptor::Kind::DirectChild;
    d.browseName = QualifiedName{0, "MaxTimeShelved"};
    d.valueReader = [value = Variant{alarmLogic->max_time_shelved()}, snapshotState]()
    {
      DataValue dv{value};
      dv.source_timestamp() = snapshotState->time();
      return dv;
    };
    descriptors.push_back(std::move(d));
  }

  // LimitAlarmType threshold / severity / deadband properties. These are STATIC configuration on the
  // alarm's LimitAlarmLogic (set before the instance is created or attached), so the helper wires each
  // node to return its configured value - making a direct Read agree with the value the event carries
  // for every limit alarm, attached or generated. Captured by value: a wire reader runs on the read
  // thread and must not touch the (mutable) logic. One group per configured limit.
  if (const auto* limitLogic = dynamic_cast<const LimitAlarmLogic*>(mLogic.get()))
  {
    const auto& cfg = limitLogic->limits();
    const auto wireStatic = [&descriptors, snapshotState](std::string_view name, Variant value)
    {
      WireDescriptor d;
      d.kind = WireDescriptor::Kind::DirectChild;
      d.browseName = QualifiedName{0, std::string{name}};
      d.valueReader = [value = std::move(value), snapshotState]()
      {
        DataValue dv{value};
        dv.source_timestamp() = snapshotState->time();
        return dv;
      };
      descriptors.push_back(std::move(d));
    };
    if (mTypeDefinition == NodeId{ObjectTypeId::ExclusiveDeviationAlarmType} ||
        mTypeDefinition == NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType})
    {
      // Part 9 sections 5.8.22.2 and 5.8.22.3 require a NULL NodeId when the
      // underlying-system setpoint has no Variable in the AddressSpace. Keep the value typed: an
      // empty Variant cannot be distinguished from an unwired property by a client.
      wireStatic("SetpointNode", Variant{NodeId{}});
    }
    const auto wireLimit = [&descriptors, snapshotState](std::string_view name, const ConfiguredLimit& limit)
    {
      WireDescriptor d;
      d.kind = WireDescriptor::Kind::DirectChild;
      d.browseName = QualifiedName{0, std::string{name}};
      d.readable = limit.is_available();
      if (limit.is_available())
      {
        const Variant value{*limit.value()};
        d.valueReader = [value, snapshotState]()
        {
          DataValue dv{value};
          dv.source_timestamp() = snapshotState->time();
          return dv;
        };
      }
      descriptors.push_back(std::move(d));
    };
    if (cfg.highHighLimit)
    {
      wireLimit("HighHighLimit", *cfg.highHighLimit);
      wireStatic("SeverityHighHigh", Variant{cfg.severityHighHigh});
      wireStatic("HighHighDeadband", Variant{cfg.highHighDeadband});
    }
    if (cfg.highLimit)
    {
      wireLimit("HighLimit", *cfg.highLimit);
      wireStatic("SeverityHigh", Variant{cfg.severityHigh});
      wireStatic("HighDeadband", Variant{cfg.highDeadband});
    }
    if (cfg.lowLimit)
    {
      wireLimit("LowLimit", *cfg.lowLimit);
      wireStatic("SeverityLow", Variant{cfg.severityLow});
      wireStatic("LowDeadband", Variant{cfg.lowDeadband});
    }
    if (cfg.lowLowLimit)
    {
      wireLimit("LowLowLimit", *cfg.lowLowLimit);
      wireStatic("SeverityLowLow", Variant{cfg.severityLowLow});
      wireStatic("LowLowDeadband", Variant{cfg.lowLowDeadband});
    }

    // NonExclusiveLimitAlarmType per-limit state TwoStateVariables. Unlike the thresholds these are
    // DYNAMIC (they flip as the input crosses a limit), so they are sourced from the snapshot - which
    // update_snapshot() already populates from the logic on the strand - exactly like ActiveState.
    if (!limitLogic->exclusive())
    {
      const auto wireLimitState = [&descriptors, snapshotState](std::string_view name, auto stateGetter)
      {
        WireDescriptor d;
        d.kind = WireDescriptor::Kind::TwoState;
        d.browseName = QualifiedName{0, std::string{name}};
        d.currentStateReader = [snapshotState, stateGetter]()
        {
          auto s = stateGetter(*snapshotState);
          return s ? s->currentState : LocalizedText{};
        };
        d.idReader = [snapshotState, stateGetter]()
        {
          auto s = stateGetter(*snapshotState);
          return s ? s->id : false;
        };
        d.transitionTimeReader = [snapshotState, stateGetter]()
        {
          auto s = stateGetter(*snapshotState);
          return s ? s->transitionTime : DateTime{};
        };
        descriptors.push_back(std::move(d));
      };
      if (cfg.highHighLimit)
        wireLimitState("HighHighState", [](const ConditionStateSnapshot& s) { return s.high_high_state(); });
      if (cfg.highLimit)
        wireLimitState("HighState", [](const ConditionStateSnapshot& s) { return s.high_state(); });
      if (cfg.lowLimit)
        wireLimitState("LowState", [](const ConditionStateSnapshot& s) { return s.low_state(); });
      if (cfg.lowLowLimit)
        wireLimitState("LowLowState", [](const ConditionStateSnapshot& s) { return s.low_low_state(); });
    }
  }

  // NOTE: OffNormalAlarmType.NormalState (spec DataType NodeId, 5.8.17) is intentionally not wired
  // here - it is a NodeId pointing at the Variable holding the normal value, but the logic currently
  // models the normal state as a value (set_normal_state) with no public node accessor. Wiring it
  // correctly is a small modeling decision (expose normal_state_node, or set it on the alarm), tracked
  // separately.

  return descriptors;
}

// --- Method-handler closure helpers ---

/// Build the inner CallMethodResult and invoke the method-handler completion.
/// Locks the weak instance first; on null returns BadConditionDisabled.
template<typename Args, typename OperationFn, typename AuditEmitFn>
void ConditionInstance::run_method_handler_inner(std::weak_ptr<ConditionInstance> me,
  const NodeId& /*objectId*/, const Args& args, String userId, CallMethodCompleteCallback complete,
  OperationFn operation, AuditEmitFn auditEmit)
{
  // Guard the user-supplied method-call completion so neither the null-self short-circuit nor the
  // run_method_on_strand completion can ever double-fire it, and route every fire through
  // invoke_user_callback so a throwing completion cannot escape the strand/method-adapter boundary.
  auto guardedComplete = ua::detail::make_fire_once<CallResult>(std::move(complete));
  auto self = me.lock();
  if (!self)
  {
    ua::detail::invoke_user_callback(guardedComplete, CallResult{StatusCode{Status::BadConditionDisabled}});
    return;
  }
  // Acknowledge / Confirm / AddComment take the EventId as their first argument; the rest
  // take none. Lift it where present so a rejected transition names the occurrence on the
  // Method path exactly as it does on the direct *_async API - this is the path a remote
  // client uses, and the one whose rejection reaches the operator only through the log.
  // Nested, not `&&`: tuple_element_t<0, tuple<>> is ill-formed, and a single condition would
  // still have to form that type for the NoArgs instantiations.
  ByteString eventId;
  bool hasEventId = false;
  if constexpr (std::tuple_size_v<Args> > 0)
  {
    if constexpr (std::is_same_v<std::tuple_element_t<0, Args>, ByteString>)
    {
      eventId = std::get<0>(args);
      hasEventId = true;
    }
  }
  // operation captures any per-call args (pre-bound). The lambda below also
  // captures them via the inner `complete-on-result` callback.
  self->run_method_on_strand(std::move(userId),
    std::move(eventId),
    hasEventId,
    operation,
    [me, complete = std::move(guardedComplete), auditEmit = std::move(auditEmit)](
      MethodCompletion kind, VoidResult vr) mutable
    {
      auto lockedSelf = me.lock();
      if (lockedSelf)
      {
        // Audit emission requires a live instance; if the instance died
        // between the run and this completion, emit is silently skipped.
        auditEmit(*lockedSelf, vr.is_good());
      }
      // Exception path: service-internal failure surfaces as a bad outer
      // CallResult so the rich StatusCode (with attached ErrorDetail) is not
      // silently dropped via the Result(T) ctor - the
      // passive-forwarding invariant.
      if (kind == MethodCompletion::Threw)
      {
        ua::detail::invoke_user_callback(complete, CallResult{vr.status_code()});
        return;
      }
      // Per-operation outcome (e.g. BadEventIdUnknown from condition logic):
      // OPC UA Part 4 5.11.2 mandates the wire-level status ride inside
      // CallMethodResult, outer CallResult stays Good. Detail (if any) is
      // carried on the per-result StatusCode and reaches DiagnosticInfo via
      // the service-level walk over Array<CallMethodResult>.
      CallMethodResult r;
      r.status_code() = vr.status_code();
      ua::detail::invoke_user_callback(complete, CallResult{std::move(r)});
    });
  // Remaining args are consumed by the operation closure; only the EventId is lifted above.
}

// --- Client-call entry points (standard Condition methods) -----------------------------
//
// Single source of truth for the standard Condition operations: each runs the logic
// transition AND emits the matching audit event via run_method_handler_inner. Shared by
// the per-instance method-node handlers (build_register_descriptors) and the NS0 type
// method-node handlers (Conditions::register_condition_methods). The operation + audit
// lambdas below are the canonical definitions; build_register_descriptors delegates here.

void ConditionInstance::call_enable_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return logic.enable(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionEnableEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Enable");
    });
}

void ConditionInstance::call_disable_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return logic.disable(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionEnableEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Disable");
    });
}

void ConditionInstance::call_one_shot_shelve_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).one_shot_shelve(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionShelvingEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/OneShotShelve");
    });
}

void ConditionInstance::call_timed_shelve_async(
  double durationMs, String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [durationMs](ConditionLogic& logic)
    { return dynamic_cast<AlarmConditionLogic&>(logic).timed_shelve(durationMs); },
    [durationMs](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionShelvingEventPayload audit;
      audit.status = operationSucceeded;
      audit.shelvingTime = Variant{durationMs};
      self.emit_audit_event(audit, "Method/TimedShelve");
    });
}

void ConditionInstance::call_unshelve_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).unshelve(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionShelvingEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Unshelve");
    });
}

void ConditionInstance::call_suppress_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).suppress(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionSuppressionEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Suppress");
    });
}

void ConditionInstance::call_unsuppress_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).unsuppress(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionSuppressionEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Unsuppress");
    });
}

void ConditionInstance::call_silence_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).silence(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionSilenceEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Silence");
    });
}

void ConditionInstance::call_remove_from_service_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).remove_from_service(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionOutOfServiceEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/RemoveFromService");
    });
}

void ConditionInstance::call_place_in_service_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).place_in_service(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionOutOfServiceEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/PlaceInService");
    });
}

void ConditionInstance::call_reset_async(String userId, CallMethodCompleteCallback complete)
{
  using NoArgs = std::tuple<>;
  run_method_handler_inner<NoArgs>(
    weak_from_this(),
    condition_id(),
    NoArgs{},
    std::move(userId),
    std::move(complete),
    [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).reset(); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionResetEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Reset");
    });
}

void ConditionInstance::call_add_comment_async(
  ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete)
{
  using EventIdCommentArgs = std::tuple<ByteString, LocalizedText>;
  run_method_handler_inner<EventIdCommentArgs>(
    weak_from_this(),
    condition_id(),
    EventIdCommentArgs{eventId, comment},
    std::move(userId),
    std::move(complete),
    [eventId, comment](ConditionLogic& logic) { return logic.add_comment(eventId, comment); },
    [eventId, comment](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionCommentEventPayload audit;
      audit.status = operationSucceeded;
      audit.conditionEventId = eventId;
      audit.comment = comment;
      self.emit_audit_event(audit, "Method/AddComment");
    });
}

void ConditionInstance::call_acknowledge_async(
  ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete)
{
  using EventIdCommentArgs = std::tuple<ByteString, LocalizedText>;
  run_method_handler_inner<EventIdCommentArgs>(
    weak_from_this(),
    condition_id(),
    EventIdCommentArgs{eventId, comment},
    std::move(userId),
    std::move(complete),
    [eventId, comment](ConditionLogic& logic)
    { return dynamic_cast<AcknowledgeableConditionLogic&>(logic).acknowledge(eventId, comment); },
    [eventId, comment](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionAcknowledgeEventPayload audit;
      audit.status = operationSucceeded;
      audit.conditionEventId = eventId;
      audit.comment = comment;
      self.emit_audit_event(audit, "Method/Acknowledge");
    });
}

void ConditionInstance::call_confirm_async(
  ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete)
{
  using EventIdCommentArgs = std::tuple<ByteString, LocalizedText>;
  run_method_handler_inner<EventIdCommentArgs>(
    weak_from_this(),
    condition_id(),
    EventIdCommentArgs{eventId, comment},
    std::move(userId),
    std::move(complete),
    [eventId, comment](ConditionLogic& logic)
    { return dynamic_cast<AcknowledgeableConditionLogic&>(logic).confirm(eventId, comment); },
    [eventId, comment](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionConfirmEventPayload audit;
      audit.status = operationSucceeded;
      audit.conditionEventId = eventId;
      audit.comment = comment;
      self.emit_audit_event(audit, "Method/Confirm");
    });
}

// --- Register-method descriptor builder ---

std::vector<ConditionInstance::RegisterDescriptor> ConditionInstance::build_register_descriptors() const
{
  using NoArgs = std::tuple<>;
  using EventIdCommentArgs = std::tuple<ByteString, LocalizedText>;
  using DurationArgs = std::tuple<double>;
  using RespondArgs = std::tuple<int32_t>;
  using CommentArgs = std::tuple<LocalizedText>;
  using DurationCommentArgs = std::tuple<double, LocalizedText>;

  std::vector<RegisterDescriptor> descriptors;
  descriptors.reserve(24);

  // 1. Enable (fatal)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Enable"};
    d.fatalOnFailure = true;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& /*objectId*/,
                                     const NoArgs& /*args*/,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          // userId is read synchronously here - the borrowed context must not be
          // dereferenced after the strand hop inside call_enable_async.
          String userId = context ? context->clientUserId : String{};
          auto self = me.lock();
          if (!self)
          {
            complete(CallResult{StatusCode{Status::BadConditionDisabled}});
            return;
          }
          self->call_enable_async(std::move(userId), std::move(complete));
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 2. Disable (fatal)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Disable"};
    d.fatalOnFailure = true;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& /*objectId*/,
                                     const NoArgs& /*args*/,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          String userId = context ? context->clientUserId : String{};
          auto self = me.lock();
          if (!self)
          {
            complete(CallResult{StatusCode{Status::BadConditionDisabled}});
            return;
          }
          self->call_disable_async(std::move(userId), std::move(complete));
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 3. AddComment (fatal)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "AddComment"};
    d.fatalOnFailure = true;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<EventIdCommentArgs>{[me](const NodeId& /*objectId*/,
                                                 const EventIdCommentArgs& args,
                                                 shared_ptr<const MethodCallContext>
                                                   context,
                                                 CallMethodResult /*result*/,
                                                 CallMethodCompleteCallback complete)
        {
          auto& [eventId, comment] = args;
          String userId = context ? context->clientUserId : String{};
          auto self = me.lock();
          if (!self)
          {
            complete(CallResult{StatusCode{Status::BadConditionDisabled}});
            return;
          }
          self->call_add_comment_async(eventId, comment, std::move(userId), std::move(complete));
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 4. Acknowledge (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Acknowledge"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<EventIdCommentArgs>{[me](const NodeId& /*objectId*/,
                                                 const EventIdCommentArgs& args,
                                                 shared_ptr<const MethodCallContext>
                                                   context,
                                                 CallMethodResult /*result*/,
                                                 CallMethodCompleteCallback complete)
        {
          auto& [eventId, comment] = args;
          String userId = context ? context->clientUserId : String{};
          auto self = me.lock();
          if (!self)
          {
            complete(CallResult{StatusCode{Status::BadConditionDisabled}});
            return;
          }
          self->call_acknowledge_async(eventId, comment, std::move(userId), std::move(complete));
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 5. Confirm (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Confirm"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<EventIdCommentArgs>{[me](const NodeId& /*objectId*/,
                                                 const EventIdCommentArgs& args,
                                                 shared_ptr<const MethodCallContext>
                                                   context,
                                                 CallMethodResult /*result*/,
                                                 CallMethodCompleteCallback complete)
        {
          auto& [eventId, comment] = args;
          String userId = context ? context->clientUserId : String{};
          auto self = me.lock();
          if (!self)
          {
            complete(CallResult{StatusCode{Status::BadConditionDisabled}});
            return;
          }
          self->call_confirm_async(eventId, comment, std::move(userId), std::move(complete));
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 6. Suppress (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Suppress"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).suppress(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionSuppressionEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/Suppress");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 7. Unsuppress (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Unsuppress"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).unsuppress(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionSuppressionEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/Unsuppress");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 8. RemoveFromService (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "RemoveFromService"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic)
            { return dynamic_cast<AlarmConditionLogic&>(logic).remove_from_service(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionOutOfServiceEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/RemoveFromService");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 9. PlaceInService (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "PlaceInService"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic)
            { return dynamic_cast<AlarmConditionLogic&>(logic).place_in_service(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionOutOfServiceEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/PlaceInService");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 10. Silence (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Silence"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).silence(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionSilenceEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/Silence");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 11. Reset (optional)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Reset"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).reset(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionResetEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/Reset");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 12. TimedShelve (optional, under ShelvingState)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "TimedShelve"};
    d.underShelvingState = true;
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<DurationArgs>{[me](const NodeId& objectId,
                                           const DurationArgs& args,
                                           shared_ptr<const MethodCallContext>
                                             context,
                                           CallMethodResult /*result*/,
                                           CallMethodCompleteCallback complete)
        {
          auto& [duration] = args;
          auto capturedDuration = duration;
          run_method_handler_inner<DurationArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [capturedDuration](ConditionLogic& logic)
            { return dynamic_cast<AlarmConditionLogic&>(logic).timed_shelve(capturedDuration); },
            [capturedDuration](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionShelvingEventPayload audit;
              audit.status = operationSucceeded;
              audit.shelvingTime = Variant{capturedDuration};
              self.emit_audit_event(audit, "Method/TimedShelve");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 13. OneShotShelve (optional, under ShelvingState)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "OneShotShelve"};
    d.underShelvingState = true;
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).one_shot_shelve(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionShelvingEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/OneShotShelve");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 14. Unshelve (optional, under ShelvingState)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Unshelve"};
    d.underShelvingState = true;
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<NoArgs>{[me](const NodeId& objectId,
                                     const NoArgs& args,
                                     shared_ptr<const MethodCallContext>
                                       context,
                                     CallMethodResult /*result*/,
                                     CallMethodCompleteCallback complete)
        {
          run_method_handler_inner<NoArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [](ConditionLogic& logic) { return dynamic_cast<AlarmConditionLogic&>(logic).unshelve(); },
            [](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionShelvingEventPayload audit;
              audit.status = operationSucceeded;
              self.emit_audit_event(audit, "Method/Unshelve");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }
  // 15. Respond (optional, DialogConditionType only)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "Respond"};
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<RespondArgs>{[me](const NodeId& objectId,
                                          const RespondArgs& args,
                                          shared_ptr<const MethodCallContext>
                                            context,
                                          CallMethodResult /*result*/,
                                          CallMethodCompleteCallback complete)
        {
          auto& [selectedResponse] = args;
          auto capturedResponse = selectedResponse;
          run_method_handler_inner<RespondArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [capturedResponse](ConditionLogic& logic)
            { return dynamic_cast<DialogConditionLogic&>(logic).respond(capturedResponse); },
            [capturedResponse](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionRespondEventPayload audit;
              audit.status = operationSucceeded;
              // The Method argument is an Int32 and the audit field a UInt32 (OPC 10000-9 5.6.3, 5.10.5): a
              // negative SelectedResponse, which the logic refuses, is recorded by its bit pattern rather
              // than thrown on, which would leave the Call unanswered.
              audit.selectedResponse = static_cast<uint32_t>(capturedResponse);
              self.emit_audit_event(audit, "Method/Respond");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }

  // 16-22. The comment-bearing `...2` variants (OPC 10000-9 5.8.6, 5.8.9, 5.8.11, 5.8.13, 5.8.15,
  // 5.8.17.3, 5.8.17.7). Each "extends" its base Method "by adding an optional Comment" and is
  // otherwise the base Method: same transition, same refusal codes, same audit Event type. They are
  // built from a factory rather than written out eight times because the only things that differ are
  // the mutation and the audit payload - the dispatch body around them is what a hand-copied variant
  // gets subtly wrong, and getting it wrong here means an operator's comment is silently discarded.
  auto commentVariant = [&descriptors](const char* browseName,
                          bool underShelvingState,
                          std::function<ConditionStateTransition(ConditionLogic&, const LocalizedText&)>
                            mutate,
                          std::function<void(ConditionInstance&, bool)>
                            auditEmit)
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, std::string{browseName}};
    d.underShelvingState = underShelvingState;
    d.fatalOnFailure = false;
    d.handlerFactory = [mutate = std::move(mutate), auditEmit = std::move(auditEmit)](
                         std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<CommentArgs>{[me, mutate, auditEmit](const NodeId& objectId,
                                          const CommentArgs& args,
                                          shared_ptr<const MethodCallContext>
                                            context,
                                          CallMethodResult /*result*/,
                                          CallMethodCompleteCallback complete)
        {
          auto capturedComment = std::get<0>(args);
          run_method_handler_inner<CommentArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [mutate, capturedComment](ConditionLogic& logic) { return mutate(logic, capturedComment); },
            [auditEmit](ConditionInstance& self, bool operationSucceeded)
            { auditEmit(self, operationSucceeded); });
        }};
    };
    descriptors.push_back(std::move(d));
  };

  commentVariant(
    "Suppress2",
    false,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).suppress(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionSuppressionEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Suppress2");
    });

  commentVariant(
    "Unsuppress2",
    false,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).unsuppress(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionSuppressionEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Unsuppress2");
    });

  commentVariant(
    "RemoveFromService2",
    false,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).remove_from_service(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionOutOfServiceEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/RemoveFromService2");
    });

  commentVariant(
    "PlaceInService2",
    false,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).place_in_service(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionOutOfServiceEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/PlaceInService2");
    });

  commentVariant(
    "Reset2",
    false,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).reset(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionResetEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Reset2");
    });

  commentVariant(
    "OneShotShelve2",
    true,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).one_shot_shelve(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionShelvingEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/OneShotShelve2");
    });

  commentVariant(
    "Unshelve2",
    true,
    [](ConditionLogic& logic, const LocalizedText& comment)
    { return dynamic_cast<AlarmConditionLogic&>(logic).unshelve(comment); },
    [](ConditionInstance& self, bool operationSucceeded)
    {
      AuditConditionShelvingEventPayload audit;
      audit.status = operationSucceeded;
      self.emit_audit_event(audit, "Method/Unshelve2");
    });

  // 23. TimedShelve2 (optional, under ShelvingState). Written out rather than taken from the factory
  // above: it is the one `...2` Method with a second argument, and its audit Event carries the
  // ShelvingTime that was asked for (OPC 10000-9 5.8.17.5).
  {
    RegisterDescriptor d;
    d.browseName = QualifiedName{0, "TimedShelve2"};
    d.underShelvingState = true;
    d.fatalOnFailure = false;
    d.handlerFactory = [](std::weak_ptr<ConditionInstance> me) -> MethodCallSource::CallHandler
    {
      return MethodAdapter<DurationCommentArgs>{[me](const NodeId& objectId,
                                                  const DurationCommentArgs& args,
                                                  shared_ptr<const MethodCallContext>
                                                    context,
                                                  CallMethodResult /*result*/,
                                                  CallMethodCompleteCallback complete)
        {
          auto capturedDuration = std::get<0>(args);
          auto capturedComment = std::get<1>(args);
          run_method_handler_inner<DurationCommentArgs>(
            me,
            objectId,
            args,
            (context ? context->clientUserId : String{}),
            std::move(complete),
            [capturedDuration, capturedComment](ConditionLogic& logic) {
              return dynamic_cast<AlarmConditionLogic&>(logic).timed_shelve(
                capturedDuration, capturedComment);
            },
            [capturedDuration](ConditionInstance& self, bool operationSucceeded)
            {
              AuditConditionShelvingEventPayload audit;
              audit.status = operationSucceeded;
              audit.shelvingTime = Variant{capturedDuration};
              self.emit_audit_event(audit, "Method/TimedShelve2");
            });
        }};
    };
    descriptors.push_back(std::move(d));
  }

  return descriptors;
}

namespace
{

/// True for the Variables this Server stops maintaining once a Condition is Disabled, and which
/// OPC 10000-9 5.5.2 therefore requires to answer Bad_ConditionDisabled rather than the value they
/// last held.
///
/// The clause names what stays valid - "EventId, EventType, Source Node, Source Name, Time, and
/// EnabledState" - and then leaves the rest to the Server: other Properties "MAY no longer provide
/// current valid values", and it is the ones "that are no longer provided" that must go Bad. So the
/// set is a statement about this implementation, not a restatement of the spec's list, and it is
/// written positively for that reason.
///
/// What belongs here is the Condition's evaluation output: the state the logic recomputes as the
/// input moves, and stops recomputing the moment the Condition is switched off. What does not is
/// configuration the application supplied - limits, MaxTimeShelved, InputNode, ConditionName,
/// SupportsFilteredRetain - which is as true of a disabled Condition as of a live one, and Retain,
/// which the same clause has the Server set False on entering this state precisely so a Client can
/// read it and see the Condition is not of interest.
bool withdrawn_while_disabled(const QualifiedName& browseName)
{
  const auto& name = browseName.name();
  return name == String{"Severity"} || name == String{"Quality"} || name == String{"LastSeverity"} ||
         name == String{"Comment"} || name == String{"Message"} || name == String{"ActiveState"} ||
         name == String{"AckedState"} || name == String{"ConfirmedState"} ||
         name == String{"SuppressedState"} || name == String{"OutOfServiceState"} ||
         name == String{"SilenceState"} || name == String{"LatchedState"} ||
         name == String{"SuppressedOrShelved"} || name == String{"ShelvingState"} ||
         name == String{"LimitState"};
}

/// Return whether this wired Event field is derived from the sampled underlying-system value.
/// Part 9 section 5.14.2 requires these fields to read NULL with the failure StatusCode while that
/// value is unavailable. Configuration and operator state remain readable through the outage.
bool unavailable_with_input_quality(const QualifiedName& browseName)
{
  const auto& name = browseName.name();
  return name == String{"Severity"} || name == String{"ActiveState"} || name == String{"HighHighState"} ||
         name == String{"HighState"} || name == String{"LowState"} || name == String{"LowLowState"} ||
         name == String{"LimitState"};
}

}  // namespace

// --- Wire-loop dispatcher ---

void ConditionInstance::refuse_wiring(VoidResult refusal)
{
  if (refusal.is_bad() && !mWiringRefusal)
  {
    mWiringRefusal = std::move(refusal);
  }
}

void ConditionInstance::dispatch_wire_descriptor(
  const WireDescriptor& desc, std::function<void()> onStepComplete)
{
  // Each descriptor may issue multiple AS lookups + read/handler-installs. The
  // shared step handler invokes `onStepComplete` when the descriptor's last
  // sub-step returns. A Variable the Condition does not have is skipped; one it has and cannot wire is
  // recorded (refuse_wiring), and the flow fails with it.
  auto me = weak_from_this();

  // OPC 10000-9 5.5.2: for a disabled Condition, the Variables outside the list above "may no longer
  // provide current valid values. All Variables that are no longer provided shall return a status of
  // Bad_ConditionDisabled." This Server stops updating them the moment the Condition is disabled, so
  // they are exactly that - no longer provided - and serving the last live value with a Good status
  // would tell a polling Client that a switched-off Condition is a healthy one. The gate sits here
  // rather than in the readers because every wired Variable, including the Id and TransitionTime
  // sub-properties of a TwoStateVariable, reaches the address space through installReadHandler.
  const bool gateOnDisabled = withdrawn_while_disabled(desc.browseName);
  const bool gateOnInputQuality = unavailable_with_input_quality(desc.browseName);
  auto snapshotState = mSnapshot;

  // Helper: install a read-value handler on a variable node and store the
  // wiring (mirrors pre-flip wire_variable_node).
  auto installReadHandler = [me, gateOnDisabled, gateOnInputQuality, snapshotState](NodeId variableId,
                              std::function<DataValue()>
                                valueReader,
                              std::function<void()>
                                done,
                              bool readable = true)
  {
    if ((gateOnDisabled || gateOnInputQuality) && valueReader)
    {
      valueReader =
        [snapshotState, gateOnDisabled, gateOnInputQuality, inner = std::move(valueReader)]() -> DataValue
      {
        if (snapshotState && gateOnDisabled && !snapshotState->enabled())
        {
          DataValue disabled;
          disabled.status() = StatusCode{Status::BadConditionDisabled};
          return disabled;
        }
        if (snapshotState && gateOnInputQuality && snapshotState->quality().is_bad())
        {
          DataValue unavailable;
          unavailable.status() = snapshotState->quality();
          return unavailable;
        }
        return inner();
      };
    }
    auto lockedSelf = me.lock();
    if (!lockedSelf || !lockedSelf->mAddressSpace)
    {
      done();
      return;
    }
    lockedSelf->mAddressSpace->find_node_async(variableId,

      [me, valueReader = std::move(valueReader), done = std::move(done), readable](
        NodeAccessorResult nodeResult) mutable
      {
        // Re-dispatch the apply step onto the strand so the wiring mutation
        // is strand-serialised.
        auto lockedSelfInner = me.lock();
        if (!lockedSelfInner)
        {
          done();
          return;
        }
        ua::async::post_borrowing(lockedSelfInner.get(),
          lockedSelfInner->mStrand,
          lockedSelfInner->mLogger,
          [nodeResult = std::move(nodeResult),
            valueReader = std::move(valueReader),
            done = std::move(done),
            readable](ConditionInstance& self) mutable
          {
            if (!nodeResult.is_good())
            {
              // Optional wire step: failure is best-effort (per pre-flip
              // wire_variable_node :1075-1078); skip silently and continue. An Uncertain answer, with or
              // without the Node, is not acted on.
              done();
              return;
            }
            if (!readable)
            {
              auto accessor = nodeResult.value();
              if (!accessor.as<VariableAccessor>())
              {
                done();
                return;
              }
              // The Variable's namespace may answer by posting to this strand, so the AccessLevel write
              // is asynchronous and the step completes, back on the strand, when the write has. A refused
              // write would leave the Variable readable, so it fails the Condition's initialisation.
              accessor.write_attribute_async(AttributeId::AccessLevel,
                attribute_wire::access_level(AccessLevelType{}),
                [me = self.weak_from_this(), done = std::move(done)](VoidResult written) mutable
                {
                  auto owner = me.lock();
                  if (!owner)
                  {
                    done();
                    return;
                  }
                  ua::async::post_borrowing(owner.get(),
                    owner->mStrand,
                    owner->mLogger,
                    [done = std::move(done), written = std::move(written)](ConditionInstance& wired) mutable
                    {
                      wired.refuse_wiring(std::move(written));
                      done();
                    })();
                });
              return;
            }
            auto* externalSource = nodeResult.value()->external_value_source();
            if (!externalSource)
            {
              self.refuse_wiring(values_not_supported(nodeResult.value().get_node_id()));
              done();
              return;
            }
            auto setResult = externalSource->set_value_source(detail::whole_value_source(
              [valueReader](
                const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
              { complete(DataValueResult{with_read_timestamps(valueReader())}); }));
            if (setResult.is_bad())
            {
              self.refuse_wiring(std::move(setResult));
              done();
              return;
            }
            declare_every_change_reported(nodeResult.value(), self.mLogger);
            self.mWiredVariables.push_back(VariableWiring{nodeResult.value(), std::move(valueReader)});
            done();
          })();
      });
  };

  // Capture descriptor by value so the closures own their state.
  switch (desc.kind)
  {
  case WireDescriptor::Kind::TwoState:
  {
    // 1) Find the TwoStateVariable child under mConditionId via HasComponent.
    // 2) Install handler on the main variable (current state).
    // 3) Find Id sub-property under variable; install handler if found.
    // 4) Find TransitionTime sub-property under variable; install handler if found.
    auto caseSelf = me.lock();
    if (!caseSelf)
    {
      onStepComplete();
      return;
    }
    // Guard the member optional in its own statement so the .has_value() check and the deref below
    // share one storage location the checker can track (shape-1). Folding it into `!self || ...`
    // above hid the optional's engagement state behind the shared_ptr deref.
    const auto& addressSpaceOpt = caseSelf->mAddressSpace;
    if (!addressSpaceOpt)
    {
      onStepComplete();
      return;
    }
    const auto& addressSpace = *addressSpaceOpt;
    auto browseName = desc.browseName;
    auto currentStateReader = desc.currentStateReader;
    auto idReader = desc.idReader;
    auto transitionTimeReader = desc.transitionTimeReader;
    instance_utils::find_child_id_by_browse_name_async(addressSpace,
      caseSelf->mConditionId,
      NodeId{ReferenceTypeId::HasComponent},
      browseName,

      [me,
        currentStateReader = std::move(currentStateReader),
        idReader = std::move(idReader),
        transitionTimeReader = std::move(transitionTimeReader),
        installReadHandler,
        onStepComplete = std::move(onStepComplete)](NodeIdResult childIdResult) mutable
      {
        auto childCbSelf = me.lock();
        if (!childCbSelf)
        {
          onStepComplete();
          return;
        }
        ua::async::post_borrowing(childCbSelf.get(),
          childCbSelf->mStrand,
          childCbSelf->mLogger,
          [childIdResult = std::move(childIdResult),
            currentStateReader = std::move(currentStateReader),
            idReader = std::move(idReader),
            transitionTimeReader = std::move(transitionTimeReader),
            installReadHandler,
            onStepComplete = std::move(onStepComplete)](ConditionInstance& self) mutable
          {
            if (!self.mAddressSpace)
            {
              onStepComplete();
              return;
            }
            if (!childIdResult.is_good())
            {
              // Optional TwoState child: failure is best-effort (per
              // pre-flip wire_two_state_variable :963-967); skip silently. An Uncertain answer is not acted
              // on.
              onStepComplete();
              return;
            }
            const NodeId variableId = childIdResult.value();
            auto variableMe = self.weak_from_this();
            // Install on the main variable (current state).
            installReadHandler(
              variableId,
              [currentStateReader]()
              { return with_read_timestamps(DataValue{Variant{currentStateReader()}}); },
              [variableMe,
                variableId,
                idReader = std::move(idReader),
                transitionTimeReader = std::move(transitionTimeReader),
                installReadHandler,
                onStepComplete = std::move(onStepComplete)]() mutable
              {
                auto doneCbSelf = variableMe.lock();
                if (!doneCbSelf || !doneCbSelf->mAddressSpace)
                {
                  onStepComplete();
                  return;
                }
                // Find Id sub-property.
                instance_utils::find_child_id_by_browse_name_async(*doneCbSelf->mAddressSpace,
                  variableId,
                  NodeId{ReferenceTypeId::HasProperty},
                  QualifiedName{0, "Id"},

                  [variableMe,
                    variableId,
                    idReader = std::move(idReader),
                    transitionTimeReader = std::move(transitionTimeReader),
                    installReadHandler,
                    onStepComplete = std::move(onStepComplete)](NodeIdResult idChildResult) mutable
                  {
                    auto idCbSelf = variableMe.lock();
                    if (!idCbSelf)
                    {
                      onStepComplete();
                      return;
                    }
                    ua::async::post_borrowing(idCbSelf.get(),
                      idCbSelf->mStrand,
                      idCbSelf->mLogger,
                      [idChildResult = std::move(idChildResult),
                        variableId,
                        idReader = std::move(idReader),
                        transitionTimeReader = std::move(transitionTimeReader),
                        installReadHandler,
                        onStepComplete = std::move(onStepComplete)](ConditionInstance& postSelf) mutable
                      {
                        auto idMe = postSelf.weak_from_this();
                        auto continueWithTransitionTime =
                          [idMe,
                            variableId,
                            transitionTimeReader = std::move(transitionTimeReader),
                            installReadHandler,
                            onStepComplete = std::move(onStepComplete)]() mutable
                        {
                          auto transitionSelf = idMe.lock();
                          if (!transitionSelf || !transitionSelf->mAddressSpace)
                          {
                            onStepComplete();
                            return;
                          }
                          // Find TransitionTime sub-property.
                          instance_utils::find_child_id_by_browse_name_async(*transitionSelf->mAddressSpace,
                            variableId,
                            NodeId{ReferenceTypeId::HasProperty},
                            QualifiedName{0, "TransitionTime"},

                            [idMe,
                              transitionTimeReader = std::move(transitionTimeReader),
                              installReadHandler,
                              onStepComplete = std::move(onStepComplete)](
                              NodeIdResult transitionChildResult) mutable
                            {
                              auto transitionCbSelf = idMe.lock();
                              if (!transitionCbSelf)
                              {
                                onStepComplete();
                                return;
                              }
                              ua::async::post_borrowing(transitionCbSelf.get(),
                                transitionCbSelf->mStrand,
                                transitionCbSelf->mLogger,
                                [transitionChildResult = std::move(transitionChildResult),
                                  transitionTimeReader = std::move(transitionTimeReader),
                                  installReadHandler,
                                  onStepComplete = std::move(onStepComplete)](ConditionInstance&) mutable
                                {
                                  if (transitionChildResult.is_good())
                                  {
                                    installReadHandler(
                                      transitionChildResult.value(),
                                      [transitionTimeReader]() {
                                        return with_read_timestamps(
                                          DataValue{Variant{transitionTimeReader()}});
                                      },
                                      std::move(onStepComplete));
                                  }
                                  else
                                  {
                                    // Optional TransitionTime sub-property:
                                    // failure is best-effort (per pre-flip
                                    // wire_two_state_variable :996-1001);
                                    // skip silently.
                                    onStepComplete();
                                  }
                                })();
                            });
                        };
                        if (idChildResult.is_good())
                        {
                          installReadHandler(
                            idChildResult.value(),
                            [idReader]() { return with_read_timestamps(DataValue{Variant{idReader()}}); },
                            std::move(continueWithTransitionTime));
                        }
                        else
                        {
                          // Optional Id sub-property: failure is best-effort
                          // (per pre-flip wire_two_state_variable :983-987);
                          // skip silently and continue with TransitionTime.
                          continueWithTransitionTime();
                        }
                      })();
                  });
              });
          })();
      });
    break;
  }
  case WireDescriptor::Kind::ConditionVariable:
  {
    auto caseSelf = me.lock();
    if (!caseSelf)
    {
      onStepComplete();
      return;
    }
    // Guard the member optional in its own statement so the .has_value() check and the deref below
    // share one storage location the checker can track (shape-1).
    const auto& addressSpaceOpt = caseSelf->mAddressSpace;
    if (!addressSpaceOpt)
    {
      onStepComplete();
      return;
    }
    const auto& addressSpace = *addressSpaceOpt;
    auto browseName = desc.browseName;
    auto valueReader = desc.valueReader;
    auto timestampReader = desc.timestampReader;
    instance_utils::find_child_id_by_browse_name_async(addressSpace,
      caseSelf->mConditionId,
      NodeId{ReferenceTypeId::HasComponent},
      browseName,

      [me,
        valueReader = std::move(valueReader),
        timestampReader = std::move(timestampReader),
        installReadHandler,
        onStepComplete = std::move(onStepComplete)](NodeIdResult childIdResult) mutable
      {
        auto childCbSelf = me.lock();
        if (!childCbSelf)
        {
          onStepComplete();
          return;
        }
        ua::async::post_borrowing(childCbSelf.get(),
          childCbSelf->mStrand,
          childCbSelf->mLogger,
          [childIdResult = std::move(childIdResult),
            valueReader = std::move(valueReader),
            timestampReader = std::move(timestampReader),
            installReadHandler,
            onStepComplete = std::move(onStepComplete)](ConditionInstance& self) mutable
          {
            if (!self.mAddressSpace)
            {
              onStepComplete();
              return;
            }
            if (!childIdResult.is_good())
            {
              // Optional ConditionVariable child: failure is best-effort
              // (per pre-flip wire_condition_variable :1014-1018); skip silently. An Uncertain answer is not
              // acted on.
              onStepComplete();
              return;
            }
            const NodeId variableId = childIdResult.value();
            auto variableMe = self.weak_from_this();
            // OPC 10000-9: a ConditionVariable's SourceTimestamp is the time its value last CHANGED,
            // not the time a Client happened to read it. The change time is already held -- it is what
            // the separate SourceTimestamp Property beneath this Variable serves -- so the reader
            // stamps it here. `with_read_timestamps` downstream only fills a timestamp that is absent,
            // so this survives; without it the Variable told every Client the Condition had just
            // changed on each poll, and disagreed with its own Property while doing so.
            auto stampedValueReader = [valueReader, timestampReader]()
            {
              DataValue value = valueReader();
              if (timestampReader)
              {
                if (const DateTime changed = timestampReader(); !changed.is_null())
                  value.source_timestamp() = changed;
              }
              return value;
            };
            installReadHandler(variableId,
              std::move(stampedValueReader),
              [variableMe,
                variableId,
                timestampReader = std::move(timestampReader),
                installReadHandler,
                onStepComplete = std::move(onStepComplete)]() mutable
              {
                auto doneCbSelf = variableMe.lock();
                if (!doneCbSelf || !doneCbSelf->mAddressSpace)
                {
                  onStepComplete();
                  return;
                }
                instance_utils::find_child_id_by_browse_name_async(*doneCbSelf->mAddressSpace,
                  variableId,
                  NodeId{ReferenceTypeId::HasProperty},
                  QualifiedName{0, "SourceTimestamp"},

                  [variableMe,
                    timestampReader = std::move(timestampReader),
                    installReadHandler,
                    onStepComplete = std::move(onStepComplete)](NodeIdResult tsChildResult) mutable
                  {
                    auto tsCbSelf = variableMe.lock();
                    if (!tsCbSelf)
                    {
                      onStepComplete();
                      return;
                    }
                    ua::async::post_borrowing(tsCbSelf.get(),
                      tsCbSelf->mStrand,
                      tsCbSelf->mLogger,
                      [tsChildResult = std::move(tsChildResult),
                        timestampReader = std::move(timestampReader),
                        installReadHandler,
                        onStepComplete = std::move(onStepComplete)](ConditionInstance&) mutable
                      {
                        if (tsChildResult.is_good())
                        {
                          installReadHandler(
                            tsChildResult.value(),
                            [timestampReader]()
                            { return with_read_timestamps(DataValue{Variant{timestampReader()}}); },
                            std::move(onStepComplete));
                        }
                        else
                        {
                          // Optional SourceTimestamp sub-property: failure is
                          // best-effort (per pre-flip wire_condition_variable
                          // :1032-1036); skip silently.
                          onStepComplete();
                        }
                      })();
                  });
              });
          })();
      });
    break;
  }
  case WireDescriptor::Kind::DirectChild:
  {
    auto caseSelf = me.lock();
    if (!caseSelf)
    {
      onStepComplete();
      return;
    }
    // Guard the member optional in its own statement so the .has_value() check and the deref below
    // share one storage location the checker can track (shape-1).
    const auto& addressSpaceOpt = caseSelf->mAddressSpace;
    if (!addressSpaceOpt)
    {
      onStepComplete();
      return;
    }
    const auto& addressSpace = *addressSpaceOpt;
    auto browseName = desc.browseName;
    auto valueReader = desc.valueReader;
    const bool readable = desc.readable;
    // Try HasProperty first.
    instance_utils::find_child_id_by_browse_name_async(addressSpace,
      caseSelf->mConditionId,
      NodeId{ReferenceTypeId::HasProperty},
      browseName,

      [me,
        browseName,
        valueReader = std::move(valueReader),
        readable,
        installReadHandler,
        onStepComplete = std::move(onStepComplete)](NodeIdResult firstResult) mutable
      {
        auto childCbSelf = me.lock();
        if (!childCbSelf)
        {
          onStepComplete();
          return;
        }
        ua::async::post_borrowing(childCbSelf.get(),
          childCbSelf->mStrand,
          childCbSelf->mLogger,
          [firstResult = std::move(firstResult),
            browseName,
            valueReader = std::move(valueReader),
            readable,
            installReadHandler,
            onStepComplete = std::move(onStepComplete)](ConditionInstance& self) mutable
          {
            if (!self.mAddressSpace)
            {
              onStepComplete();
              return;
            }
            if (firstResult.is_good())
            {
              installReadHandler(
                firstResult.value(), std::move(valueReader), std::move(onStepComplete), readable);
              return;
            }
            auto variableMe = self.weak_from_this();
            // Try HasComponent as fallback.
            instance_utils::find_child_id_by_browse_name_async(*self.mAddressSpace,
              self.mConditionId,
              NodeId{ReferenceTypeId::HasComponent},
              browseName,

              [variableMe,
                valueReader = std::move(valueReader),
                readable,
                installReadHandler,
                onStepComplete = std::move(onStepComplete)](NodeIdResult secondResult) mutable
              {
                auto secondCbSelf = variableMe.lock();
                if (!secondCbSelf)
                {
                  onStepComplete();
                  return;
                }
                ua::async::post_borrowing(secondCbSelf.get(),
                  secondCbSelf->mStrand,
                  secondCbSelf->mLogger,
                  [secondResult = std::move(secondResult),
                    valueReader = std::move(valueReader),
                    readable,
                    installReadHandler,
                    onStepComplete = std::move(onStepComplete)](ConditionInstance&) mutable
                  {
                    if (secondResult.is_good())
                    {
                      installReadHandler(
                        secondResult.value(), std::move(valueReader), std::move(onStepComplete), readable);
                    }
                    else
                    {
                      // Optional DirectChild: failure is best-effort (per
                      // pre-flip wire_direct_child :1059-1063); skip silently.
                      onStepComplete();
                    }
                  })();
              });
          })();
      });
    break;
  }
  case WireDescriptor::Kind::NestedValue:
  {
    auto self = me.lock();
    if (!self)
    {
      onStepComplete();
      return;
    }
    self->resolve_nested_and_install(desc.nestedPath,
      desc.nestedReferenceTypes,
      0,
      self->mConditionId,
      desc.valueReader,
      std::move(onStepComplete));
    break;
  }
  }
}

// --- Register-loop dispatcher ---

void ConditionInstance::dispatch_register_descriptor(
  const RegisterDescriptor& desc, NodeId parentNode, std::function<void(VoidResult)> completionCallback)
{
  if (!mAddressSpace)
  {
    completionCallback(VoidResult{});
    return;
  }
  auto handler = desc.handlerFactory(weak_from_this());
  auto me = weak_from_this();
  instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
    parentNode,
    desc.browseName,
    std::move(handler),

    [me, completionHandler = std::move(completionCallback)](VoidResult result) mutable
    {
      auto self = me.lock();
      if (!self)
      {
        completionHandler(VoidResult{StatusCode{Status::BadInternalError}});
        return;
      }
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        std::move(completionHandler),
        VoidResult{StatusCode{Status::BadInternalError}},
        [result = std::move(result)](ConditionInstance&, std::function<void(VoidResult)> onComplete) mutable
        { onComplete(std::move(result)); })();
    });
}

// --- Initialization (callback-canonical) ---

void ConditionInstance::initialize_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      // 5.3 synchronous-completion path: logic-only mode short-circuits
      // before any I/O is posted.
      if (!self.mAddressSpace)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{});
        return;
      }
      // 5.4.1 single-flight gate.
      if (self.mInitializeState)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadInvalidState}});
        return;
      }
      self.mInitializeState = std::make_unique<InitializeState>();
      // Publish the logic's initial state into the snapshot and mEventState before wiring, so a Read of
      // a freshly-created (not-yet-transitioned) condition returns real initial values - including the
      // resolve_field-sourced fields (e.g. SupportsFilteredRetain). The attach flow does the same. No
      // event is emitted (emit is separate); this only reads mLogic and updates the in-memory state.
      self.update_snapshot();
      self.mInitializeState->wireDescriptors = self.build_wire_descriptors();
      self.mInitializeState->registerDescriptors = self.build_register_descriptors();
      // Store the fire-once-guarded wrapper so the completion point fire in
      // complete_initialize_success / fail_initialize cannot double-fire the user callback.
      self.mInitializeState->onComplete = std::move(guarded);
      self.mResolvedShelvingStateId.reset();
      detail::ConditionLifecycleOperation::start(
        self.shared_from_this(), detail::ConditionLifecycleOperation::Mode::Initialize);
    })();
}

VoidResult ConditionInstance::try_initialize_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { initialize_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::initialize_sync()
{
  try_initialize_sync().value();
}

void ConditionInstance::instantiate_condition_object_async(std::function<void(NodeSubtreeResult)> completion)
{
  // Step: InstantiatingObject - post the address-space instantiation request.
  if (!mAddressSpace || !mInitializeState)
  {
    completion(NodeSubtreeResult{StatusCode{Status::BadInternalError}});
    return;
  }

  InstantiationService inst{*mAddressSpace};
  InstantiationOptions options;
  // Condition state machines need nested type-level optionals (e.g. TransitionTime on the
  // EnabledState/ActiveState TwoStateVariables) that the type does not redeclare on its instance
  // declaration. The filter below still gates exactly which ones are materialised.
  options.instantiateNestedTypeOptionals = true;

  const auto* ackLogic = dynamic_cast<const AcknowledgeableConditionLogic*>(mLogic.get());
  const bool includeConfirm = ackLogic && ackLogic->supports_confirm();

  const auto* alarmLogic = dynamic_cast<const AlarmConditionLogic*>(mLogic.get());
  const bool includeSuppressed = alarmLogic && alarmLogic->supports_suppressed();
  const bool includeOutOfService = alarmLogic && alarmLogic->supports_out_of_service();
  const bool includeSilence = alarmLogic && alarmLogic->supports_silence();
  const bool includeLatched = alarmLogic && alarmLogic->supports_latched();
  const bool includeMaxTimeShelved = alarmLogic && alarmLogic->max_time_shelved() > 0.0;

  // LimitAlarmType (and its Exclusive/NonExclusive subtypes) carry an optional property group per
  // configured limit - HighHighLimit/SeverityHighHigh/HighHighDeadband etc. - plus, for the
  // NonExclusive subtype, a per-limit state TwoStateVariable. Materialise exactly the limits this
  // alarm actually uses (LimitConfig leaves an unused limit's threshold unset).
  const auto* limitLogic = dynamic_cast<const LimitAlarmLogic*>(mLogic.get());
  const bool nonExclusiveLimits = limitLogic && !limitLogic->exclusive();
  const bool hasHighHigh = limitLogic && limitLogic->limits().highHighLimit.has_value();
  const bool hasHigh = limitLogic && limitLogic->limits().highLimit.has_value();
  const bool hasLow = limitLogic && limitLogic->limits().lowLimit.has_value();
  const bool hasLowLow = limitLogic && limitLogic->limits().lowLowLimit.has_value();

  options.optionalChildFilter = [includeConfirm,
                                  includeMaxTimeShelved,
                                  includeSuppressed,
                                  includeOutOfService,
                                  includeSilence,
                                  includeLatched,
                                  nonExclusiveLimits,
                                  hasHighHigh,
                                  hasHigh,
                                  hasLow,
                                  hasLowLow](const ChildFilterInfo& info) -> bool
  {
    const auto& name = info.browseName.name();
    if (name == String{"TransitionTime"} || name == String{"EffectiveDisplayName"} ||
        name == String{"EffectiveTransitionTime"})
    {
      return true;
    }
    // SupportsFilteredRetain (Optional on ConditionType, OPC 10000-9 5.5.2, added 1.05): a Client
    // checking instance/type-definition compliance (the UACTT "A & C Instances" CU) requires it on
    // every condition instance. It carries no behaviour here, so a default-false Boolean node suffices.
    if (name == String{"SupportsFilteredRetain"})
    {
      return true;
    }
    // When Confirm is supported, materialise BOTH the Confirm Method AND the ConfirmedState
    // TwoStateVariable it operates on (OPC 10000-9 5.7.2): the Method is meaningless without the state,
    // and a Client browsing ConfirmedState/Id (e.g. the UACTT Confirm CU) must find it. ConfirmedState is
    // Optional on AcknowledgeableConditionType, so it is only instantiated via this filter; its Id child is
    // Mandatory on TwoStateVariableType and materialises with it.
    if (includeConfirm && (name == String{"Confirm"} || name == String{"ConfirmedState"}))
    {
      return true;
    }
    // Each Method below is materialised together with its `...2` sibling, the comment-bearing variant
    // OPC 10000-9 added in 1.05 (5.8.9, 5.8.11, 5.8.13, 5.8.15, 5.8.6, 5.8.17.3/.5/.7). The pair is one
    // decision, not two: the newer variant is defined entirely by "extends X by adding an optional
    // Comment", so an instance that offers X and withholds X2 is offering an operator the operation
    // while denying them the only supported way to say why they performed it - and the Shelving2 /
    // Suppression2 Conformance Units are declared on the `...2` node alone. Silence has no such sibling.
    // ShelvingState's LastTransition (Optional, inherited from FiniteStateMachineType) is served from the
    // last shelving transition the Condition made. Only under the shelving state machine: another state
    // machine's LastTransition (an exclusive limit alarm's LimitState) is not tracked.
    if (name == String{"LastTransition"} &&
        info.parentTypeDefinition == NodeId{ObjectTypeId::ShelvedStateMachineType})
    {
      return true;
    }
    if (name == String{"ShelvingState"} || name == String{"TimedShelve"} || name == String{"OneShotShelve"} ||
        name == String{"Unshelve"} || name == String{"TimedShelve2"} || name == String{"OneShotShelve2"} ||
        name == String{"Unshelve2"} || name == String{"InputArguments"})
    {
      return true;
    }
    // MaxTimeShelved is Optional on AlarmConditionType (OPC 10000-9 5.8.2): exposed exactly when the alarm
    // imposes a maximum, so a Read of it agrees with the MaxTimeShelved its events carry.
    if (includeMaxTimeShelved && name == String{"MaxTimeShelved"})
    {
      return true;
    }
    if (includeSuppressed &&
        (name == String{"SuppressedState"} || name == String{"Suppress"} || name == String{"Unsuppress"} ||
          name == String{"Suppress2"} || name == String{"Unsuppress2"}))
    {
      return true;
    }
    if (includeOutOfService && (name == String{"OutOfServiceState"} || name == String{"RemoveFromService"} ||
                                 name == String{"PlaceInService"} || name == String{"RemoveFromService2"} ||
                                 name == String{"PlaceInService2"}))
    {
      return true;
    }
    if (includeSilence && (name == String{"SilenceState"} || name == String{"Silence"}))
    {
      return true;
    }
    if (includeLatched &&
        (name == String{"LatchedState"} || name == String{"Reset"} || name == String{"Reset2"}))
    {
      return true;
    }
    // LimitAlarmType optional limit/severity/deadband property groups - one per configured limit
    // (OPC 10000-9 5.8.20). Required on a limit alarm instance by the UACTT "A & C Instances" CU.
    if (hasHighHigh && (name == String{"HighHighLimit"} || name == String{"SeverityHighHigh"} ||
                         name == String{"HighHighDeadband"}))
    {
      return true;
    }
    if (hasHigh &&
        (name == String{"HighLimit"} || name == String{"SeverityHigh"} || name == String{"HighDeadband"}))
    {
      return true;
    }
    if (hasLow &&
        (name == String{"LowLimit"} || name == String{"SeverityLow"} || name == String{"LowDeadband"}))
    {
      return true;
    }
    if (hasLowLow && (name == String{"LowLowLimit"} || name == String{"SeverityLowLow"} ||
                       name == String{"LowLowDeadband"}))
    {
      return true;
    }
    // NonExclusiveLimitAlarmType per-limit state TwoStateVariables (5.8.21); their Id (Mandatory) and
    // TransitionTime (the TransitionTime clause above + nested-type-optional walk) materialise with them.
    if (nonExclusiveLimits && hasHighHigh && name == String{"HighHighState"})
    {
      return true;
    }
    if (nonExclusiveLimits && hasHigh && name == String{"HighState"})
    {
      return true;
    }
    if (nonExclusiveLimits && hasLow && name == String{"LowState"})
    {
      return true;
    }
    if (nonExclusiveLimits && hasLowLow && name == String{"LowLowState"})
    {
      return true;
    }
    return false;
  };

  auto me = weak_from_this();
  // The body awaits this. await_step posts the answer back onto the strand, so the hand-rolled
  // weak-lock-and-post the chain needed here is gone.
  inst.instantiate_object_async(mSourceNode,
    QualifiedName{mConditionId.namespace_index(), mSourceName},
    mTypeDefinition,
    options,
    std::move(completion));
}

void ConditionInstance::complete_initialize_success()
{
  if (!mInitializeState)
    return;
  // 5.4.5 completion point firing: move-out -> reset -> state -> fire callback.
  auto cb = std::move(mInitializeState->onComplete);
  mInitializeState.reset();
  if (cb)
    ua::detail::invoke_user_callback(cb, VoidResult{});
}

void ConditionInstance::fail_initialize(VoidResult bad)
{
  if (!mInitializeState)
    return;
  // 5.4.5 completion point firing: move-out -> reset -> state -> fire callback.
  auto cb = std::move(mInitializeState->onComplete);
  mInitializeState.reset();
  if (cb)
    ua::detail::invoke_user_callback(cb, std::move(bad));
}

// --- Attach (callback-canonical) ---

void ConditionInstance::attach_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      // 5.3 synchronous-completion path: logic-only mode.
      if (!self.mAddressSpace)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{});
        return;
      }
      // 5.4.1 single-flight gate.
      if (self.mAttachState)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadInvalidState}});
        return;
      }
      self.mAttachState = std::make_unique<AttachState>();
      // Build the read-initial-state descriptor list.
      auto& reads = self.mAttachState->stateBitReads;
      // Always: EnabledState/Id (default true)
      reads.push_back(AttachState::StateBitReadDescriptor{
        AttachState::StateBitReadDescriptor::Kind::BoolChild,
        "EnabledState",
        "Id",
        [](ConditionInstance& s, std::optional<bool> v) { s.mLogic->set_initial_enabled(v.value_or(true)); },
        {}});
      // For AcknowledgeableConditionLogic: AckedState/Id, ConfirmedState/Id
      if (auto* ackLogic = dynamic_cast<AcknowledgeableConditionLogic*>(self.mLogic.get()))
      {
        (void)ackLogic;
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "AckedState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (auto* ack = dynamic_cast<AcknowledgeableConditionLogic*>(s.mLogic.get()))
                ack->set_initial_acked(v.value_or(false));
            },
            {}});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "ConfirmedState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (!v.has_value())
                return;  // optional - skip if not found
              if (auto* ack = dynamic_cast<AcknowledgeableConditionLogic*>(s.mLogic.get()))
                ack->set_initial_confirmed(*v);
            },
            {}});
      }
      // For AlarmConditionLogic: ActiveState/Id + Severity (combined),
      // SuppressedState/Id, OutOfServiceState/Id, SilenceState/Id, LatchedState/Id.
      if (auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get()))
      {
        (void)alarmLogic;
        // ActiveState/Id is read alongside Severity. The pre-flip code reads
        // them in sequence and applies them together via set_initial_active
        // (active ?? false, severity ?? 0). We capture ActiveState/Id first
        // and store it on the alarm logic via a transient buffer in the
        // descriptor; the Severity read then completes the pair.
        // Simpler: emit two descriptors and have ActiveState/Id store its
        // value via an instance scratch member. To avoid adding scratch
        // state, use a shared bool capture inside the descriptor closures.
        auto activeBuffer = std::make_shared<std::optional<bool>>();
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "ActiveState",
            "Id",
            [activeBuffer](ConditionInstance& /*s*/, std::optional<bool> v) { *activeBuffer = v; },
            {}});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::Uint16Property,
            "",
            "Severity",
            {},
            [activeBuffer](ConditionInstance& s, std::optional<uint16_t> v)
            {
              if (auto* alarm = dynamic_cast<AlarmConditionLogic*>(s.mLogic.get()))
                alarm->set_initial_active(activeBuffer->value_or(false), v.value_or(0));
            }});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "SuppressedState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (!v.has_value())
                return;
              if (auto* alarm = dynamic_cast<AlarmConditionLogic*>(s.mLogic.get()))
                alarm->set_initial_suppressed(*v);
            },
            {}});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "OutOfServiceState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (!v.has_value())
                return;
              if (auto* alarm = dynamic_cast<AlarmConditionLogic*>(s.mLogic.get()))
                alarm->set_initial_out_of_service(*v);
            },
            {}});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "SilenceState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (!v.has_value())
                return;
              if (auto* alarm = dynamic_cast<AlarmConditionLogic*>(s.mLogic.get()))
                alarm->set_initial_silenced(*v);
            },
            {}});
        reads.push_back(
          AttachState::StateBitReadDescriptor{AttachState::StateBitReadDescriptor::Kind::BoolChild,
            "LatchedState",
            "Id",
            [](ConditionInstance& s, std::optional<bool> v)
            {
              if (!v.has_value())
                return;
              if (auto* alarm = dynamic_cast<AlarmConditionLogic*>(s.mLogic.get()))
                alarm->set_initial_latched(*v);
            },
            {}});
      }
      self.mAttachState->wireDescriptors = self.build_wire_descriptors();
      self.mAttachState->registerDescriptors = self.build_register_descriptors();
      // Store the fire-once-guarded wrapper so the completion point fire in
      // complete_attach_success / fail_attach cannot double-fire the user callback.
      self.mAttachState->onComplete = std::move(guarded);
      self.mResolvedShelvingStateId.reset();
      detail::ConditionLifecycleOperation::start(
        self.shared_from_this(), detail::ConditionLifecycleOperation::Mode::Attach);
    })();
}

VoidResult ConditionInstance::try_attach_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { attach_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::attach_sync()
{
  try_attach_sync().value();
}

void ConditionInstance::complete_attach_success()
{
  if (!mAttachState)
    return;
  // 5.4.5 completion point firing: move-out -> reset -> state -> fire callback.
  auto cb = std::move(mAttachState->onComplete);
  mAttachState.reset();
  if (cb)
    ua::detail::invoke_user_callback(cb, VoidResult{});
}

void ConditionInstance::fail_attach(VoidResult bad)
{
  if (!mAttachState)
    return;
  // 5.4.5 completion point firing: move-out -> reset -> state -> fire callback.
  auto cb = std::move(mAttachState->onComplete);
  mAttachState.reset();
  if (cb)
    ua::detail::invoke_user_callback(cb, std::move(bad));
}

// --- Enable/Disable ---

void ConditionInstance::enable_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      try
      {
        const bool wasEnabled = self.mSnapshot->enabled();
        auto transition = self.mLogic->enable();
        self.apply_transition(transition);
        if (!wasEnabled && self.mSnapshot->enabled())
          self.evaluate_input_if_bound();
        // OPC 10000-9 section 5.10 obliges the audit Event on the transition, not on the Method: an
        // internally driven Enable is exactly the change a Client cannot see any other way, which is
        // what the audit trail is for. Only the SourceName differs from the Method-driven path, and
        // it has to, because it must not claim a Method drove this.
        if (transition.status.is_good())
        {
          AuditConditionEnableEventPayload audit;
          audit.status = true;
          self.emit_audit_event(audit, "Internal/Enable");
        }
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_enable_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { enable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::enable_sync()
{
  try_enable_sync().value();
}

void ConditionInstance::disable_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      try
      {
        auto transition = self.mLogic->disable();
        self.apply_transition(transition);
        // Audited for the same reason the internal Enable is: the obligation is on the
        // transition, and a Client that did not call the Method has no other record of it.
        if (transition.status.is_good())
        {
          AuditConditionEnableEventPayload audit;
          audit.status = true;
          self.emit_audit_event(audit, "Internal/Disable");
        }
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_disable_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { disable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::disable_sync()
{
  try_disable_sync().value();
}

// --- Activate/Deactivate ---

void ConditionInstance::activate_async(uint16_t severity, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [severity](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded,
          VoidResult{StatusCode{Status::BadNotSupported},
            ua::ErrorDetail::build("LogicTypeMismatch",
              "ConditionInstance::activate requires AlarmConditionLogic; underlying logic does not support "
              "activation",
              "ConditionInstance")
              .context(ua::ContextKeys::nodeId, ua::to_string(self.mConditionId))});
        return;
      }
      try
      {
        auto transition = alarmLogic->activate(severity);
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_activate_sync(uint16_t severity) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete) { activate_async(severity, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::activate_sync(uint16_t severity)
{
  try_activate_sync(severity).value();
}

void ConditionInstance::deactivate_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }
      try
      {
        auto transition = alarmLogic->deactivate();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_deactivate_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { deactivate_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::deactivate_sync()
{
  try_deactivate_sync().value();
}

// --- Acknowledge/Confirm ---

void ConditionInstance::acknowledge_async(
  ByteString eventId, LocalizedText comment, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [eventId = std::move(eventId), comment = std::move(comment)](
      ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      auto* ackLogic = dynamic_cast<AcknowledgeableConditionLogic*>(self.mLogic.get());
      if (!ackLogic)
      {
        ua::detail::invoke_user_callback(guarded,
          VoidResult{StatusCode{Status::BadNotSupported},
            ua::ErrorDetail::build("LogicTypeMismatch",
              "ConditionInstance::acknowledge requires AcknowledgeableConditionLogic; underlying logic does "
              "not support acknowledge",
              "ConditionInstance")
              .context(ua::ContextKeys::nodeId, ua::to_string(self.mConditionId))});
        return;
      }
      try
      {
        auto transition = ackLogic->acknowledge(eventId, comment);
        self.apply_transition(transition);
        // Audited for the same reason the internal Enable is: the obligation is on the
        // transition, and a Client that did not call the Method has no other record of it.
        if (transition.status.is_good())
        {
          AuditConditionAcknowledgeEventPayload audit;
          audit.status = true;
          self.emit_audit_event(audit, "Internal/Acknowledge");
        }
        ua::detail::invoke_user_callback(
          guarded, status_to_result(transition.status, self.mConditionId, &eventId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_acknowledge_sync(ByteString eventId, LocalizedText comment) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete)
      { acknowledge_async(std::move(eventId), std::move(comment), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::acknowledge_sync(ByteString eventId, LocalizedText comment)
{
  try_acknowledge_sync(std::move(eventId), std::move(comment)).value();
}

void ConditionInstance::confirm_async(
  ByteString eventId, LocalizedText comment, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [eventId = std::move(eventId), comment = std::move(comment)](
      ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      auto* ackLogic = dynamic_cast<AcknowledgeableConditionLogic*>(self.mLogic.get());
      if (!ackLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }
      try
      {
        auto transition = ackLogic->confirm(eventId, comment);
        self.apply_transition(transition);
        // Audited for the same reason the internal Enable is: the obligation is on the
        // transition, and a Client that did not call the Method has no other record of it.
        if (transition.status.is_good())
        {
          AuditConditionConfirmEventPayload audit;
          audit.status = true;
          self.emit_audit_event(audit, "Internal/Confirm");
        }
        ua::detail::invoke_user_callback(
          guarded, status_to_result(transition.status, self.mConditionId, &eventId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_confirm_sync(ByteString eventId, LocalizedText comment) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete)
      { confirm_async(std::move(eventId), std::move(comment), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::confirm_sync(ByteString eventId, LocalizedText comment)
{
  try_confirm_sync(std::move(eventId), std::move(comment)).value();
}

// --- Add comment ---

void ConditionInstance::add_comment_async(
  ByteString eventId, LocalizedText comment, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [eventId = std::move(eventId), comment = std::move(comment)](
      ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      try
      {
        auto transition = self.mLogic->add_comment(eventId, comment);
        self.apply_transition(transition);
        // Audited for the same reason the internal Enable is: the obligation is on the
        // transition, and a Client that did not call the Method has no other record of it.
        if (transition.status.is_good())
        {
          AuditConditionCommentEventPayload audit;
          audit.status = true;
          self.emit_audit_event(audit, "Internal/AddComment");
        }
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_add_comment_sync(ByteString eventId, LocalizedText comment) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete)
      { add_comment_async(std::move(eventId), std::move(comment), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::add_comment_sync(ByteString eventId, LocalizedText comment)
{
  try_add_comment_sync(std::move(eventId), std::move(comment)).value();
}

// --- Shelving ---

void ConditionInstance::timed_shelve_async(double durationMs, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [durationMs](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->timed_shelve(durationMs);
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_timed_shelve_sync(double durationMs) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete) { timed_shelve_async(durationMs, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::timed_shelve_sync(double durationMs)
{
  try_timed_shelve_sync(durationMs).value();
}

void ConditionInstance::one_shot_shelve_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->one_shot_shelve();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_one_shot_shelve_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete) { one_shot_shelve_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::one_shot_shelve_sync()
{
  try_one_shot_shelve_sync().value();
}

void ConditionInstance::unshelve_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->unshelve();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_unshelve_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { unshelve_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::unshelve_sync()
{
  try_unshelve_sync().value();
}

// --- Suppress / Out-of-service ---

void ConditionInstance::suppress_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->suppress();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_suppress_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { suppress_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::suppress_sync()
{
  try_suppress_sync().value();
}

void ConditionInstance::unsuppress_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->unsuppress();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_unsuppress_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { unsuppress_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::unsuppress_sync()
{
  try_unsuppress_sync().value();
}

void ConditionInstance::remove_from_service_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->remove_from_service();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_remove_from_service_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete) { remove_from_service_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::remove_from_service_sync()
{
  try_remove_from_service_sync().value();
}

void ConditionInstance::place_in_service_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->place_in_service();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_place_in_service_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete) { place_in_service_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::place_in_service_sync()
{
  try_place_in_service_sync().value();
}

// --- Silence ---

void ConditionInstance::silence_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->silence();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_silence_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { silence_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::silence_sync()
{
  try_silence_sync().value();
}

// --- Reset (latched alarms) ---

void ConditionInstance::reset_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* alarmLogic = dynamic_cast<AlarmConditionLogic*>(self.mLogic.get());
      if (!alarmLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = alarmLogic->reset();
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_reset_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { reset_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::reset_sync()
{
  try_reset_sync().value();
}

// --- Dialog respond ---

void ConditionInstance::respond_async(int32_t selectedResponse, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [selectedResponse](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));

      auto* dialogLogic = dynamic_cast<DialogConditionLogic*>(self.mLogic.get());
      if (!dialogLogic)
      {
        ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
        return;
      }

      try
      {
        auto transition = dialogLogic->respond(selectedResponse);
        self.apply_transition(transition);
        ua::detail::invoke_user_callback(guarded, status_to_result(transition.status, self.mConditionId));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_respond_sync(int32_t selectedResponse) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete)
      { respond_async(selectedResponse, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::respond_sync(int32_t selectedResponse)
{
  try_respond_sync(selectedResponse).value();
}

// --- Input binding ---

void ConditionInstance::bind_input_async(
  NodeId inputNode, double samplingIntervalMs, CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [inputNode = std::move(inputNode), samplingIntervalMs](
      ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      try
      {
        if (!self.mAddressSpace)
        {
          ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
          return;
        }

        const auto* alarmLogic = dynamic_cast<const AlarmConditionLogic*>(self.mLogic.get());
        if (!alarmLogic)
        {
          ua::detail::invoke_user_callback(guarded, VoidResult{StatusCode{Status::BadNotSupported}});
          return;
        }

        // Cancel existing sampling timer
        self.mSamplingTimer.cancel();
        if (self.mInputCommunicationFailed)
        {
          self.notify_input_communication_state(StatusCode{Status::Good});
        }
        self.mInputNode = std::move(inputNode);
        self.mInputCommunicationFailed = false;
        self.mInputCommunicationEstablished = self.mSnapshot->retained();
        self.mWaitingForInitialInput = true;

        // COND-1102: Set quality to Bad_WaitingForInitialData until first sample arrives.
        auto qualityTransition = self.mLogic->set_quality(StatusCode{Status::BadWaitingForInitialData});
        self.apply_transition(qualityTransition);

        // Create a periodic sampling timer
        auto interval = std::chrono::milliseconds(numeric_cast<int64_t>(samplingIntervalMs));
        auto me = self.weak_from_this();
        self.mSamplingTimer = Timer::schedule_every(self.mStrand,
          interval,
          [me](boost::system::error_code ec)
          {
            if (ec)
              return;
            auto lockedSelf = me.lock();
            if (!lockedSelf || !lockedSelf->mAddressSpace)
              return;
            // Fire-and-forget read+evaluate via the address space's *_async surface.
            instance_utils::read_variable_value_async(*lockedSelf->mAddressSpace,
              lockedSelf->mInputNode,

              [me](DataValueResult readResult)
              {
                auto lockedSelfInner = me.lock();
                if (!lockedSelfInner)
                  return;
                ua::async::post_borrowing(lockedSelfInner.get(),
                  lockedSelfInner->mStrand,
                  lockedSelfInner->mLogger,
                  [readResult = std::move(readResult)](ConditionInstance& s) mutable
                  { s.handle_input_sample(std::move(readResult)); })();
              });
          });

        ua::detail::invoke_user_callback(guarded, VoidResult{});
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_bind_input_sync(NodeId inputNode, double samplingIntervalMs) noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(executor,
      [&](std::function<void(VoidResult)> complete)
      { bind_input_async(std::move(inputNode), samplingIntervalMs, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::bind_input_sync(NodeId inputNode, double samplingIntervalMs)
{
  try_bind_input_sync(std::move(inputNode), samplingIntervalMs).value();
}

void ConditionInstance::unbind_input_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{StatusCode{Status::BadInternalError}},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      self.mSamplingTimer.cancel();
      if (self.mInputCommunicationFailed)
      {
        self.notify_input_communication_state(StatusCode{Status::Good});
      }
      self.mInputCommunicationFailed = false;
      self.mInputCommunicationEstablished = false;
      self.mWaitingForInitialInput = false;
      self.mInputNode = NodeId{};
      ua::detail::invoke_user_callback(guarded, VoidResult{});
    })();
}

// --- Refresh event ---

void ConditionInstance::build_refresh_events_async(BuildEventsCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::vector<std::unique_ptr<BaseEvent>>{},
    [](ConditionInstance& self, BuildEventsCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<std::vector<std::unique_ptr<BaseEvent>>>(std::move(callback));
      try
      {
        std::vector<std::unique_ptr<BaseEvent>> events;

        // Trunk event. Carry the ConditionId (this object's NodeId) exactly as the live emit paths do
        // (emit_condition_event / emit_branch_event) so a ConditionRefresh-delivered event resolves the
        // empty-browsePath + NodeId-attribute SimpleAttributeOperand to the ConditionId. Without it a
        // client that discovers conditions via ConditionRefresh cannot extract the ConditionId.
        auto trunkEvent = self.mLogic->build_event();
        trunkEvent->eventId = self.mLogic->last_event_id();
        trunkEvent->conditionNodeId = self.mConditionId;
        // Refresh re-sends the last Event, "the same EventId and Time" (OPC 10000-9 5.5.2), and keeps the
        // ReceiveTime it was given. The replay is built here but sent later, from the Conditions strand, and
        // a live transition can be emitted in between; stamped when sent, the stale replay would look newer
        // to a client than that transition and overwrite it.
        if (self.mLastEmittedTime)
        {
          trunkEvent->time = *self.mLastEmittedTime;
          trunkEvent->receiveTime = self.mLastEmittedReceiveTime != DateTime{} ? self.mLastEmittedReceiveTime
                                                                               : *self.mLastEmittedTime;
        }
        events.push_back(std::move(trunkEvent));

        // Branch events
        const auto* ackLogic = dynamic_cast<const AcknowledgeableConditionLogic*>(self.mLogic.get());
        if (ackLogic)
        {
          for (const auto& branch : ackLogic->branches())
          {
            auto branchEvent = ackLogic->build_branch_event(branch.branchId, /*retain=*/true);
            if (branchEvent)
            {
              branchEvent->eventId = branch.eventId;
              branchEvent->conditionNodeId = self.mConditionId;
              events.push_back(std::move(branchEvent));
            }
          }
        }

        ua::detail::invoke_user_callback(guarded, std::move(events));
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, std::vector<std::unique_ptr<BaseEvent>>{});
      }
    })();
}

// --- Close ---

void ConditionInstance::close_async(CompleteCallback completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{},
    [](ConditionInstance& self, CompleteCallback callback) mutable
    {
      auto guarded = ua::detail::make_fire_once<VoidResult>(std::move(callback));
      try
      {
        // Cancel all pending timers before cleanup
        self.mOnDelayTimer.cancel();
        self.mOffDelayTimer.cancel();
        self.mShelveTimer.cancel();
        self.mReAlarmTimer.cancel();
        self.mSamplingTimer.cancel();

        if (self.mInputCommunicationFailed)
        {
          self.notify_input_communication_state(StatusCode{Status::Good});
        }
        self.mInputCommunicationFailed = false;
        self.mInputCommunicationEstablished = false;
        self.mWaitingForInitialInput = false;

        // Disable the condition if it is enabled, then signal completion
        if (self.mLogic)
        {
          auto transition = self.mLogic->disable();
          self.apply_transition(transition);
        }

        // Clean up address space integration
        self.mWiredVariables.clear();
        if (self.mOwnedSubtree)
        {
          self.mOwnedSubtree->remove_async();
          self.mOwnedSubtree.reset();
        }
        self.mAddressSpace.reset();

        ua::detail::invoke_user_callback(guarded, VoidResult{});
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(guarded, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

VoidResult ConditionInstance::try_close_sync() noexcept
{
  try
  {
    // Refused rather than entered: mStrand is where the answer will be produced, and a thread of it
    // cannot wait for it. Use the *_async overload from inside a handler or callback.
    const boost::asio::any_io_executor executor{mStrand};

    return ua::async::detail::blocking_call<VoidResult>(
      executor, [&](std::function<void(VoidResult)> complete) { close_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ConditionInstance::close_sync()
{
  try_close_sync().value();
}

}  // namespace ua
