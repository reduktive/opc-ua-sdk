// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <functional>
#include <iterator>
#include <ranges>
#include "ua_default_base_node.h"
#include "ua_access_level_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_call_method_result.h"
#include "ua_callback_safety.h"
#include "ua_date_time.h"
#include "ua_default_namespace.h"
#include "ua_reference_identity.h"
#include "ua_error_detail.h"
#include "ua_key_value_pair.h"
#include "ua_namespace.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

namespace ua::default_ns
{

namespace
{

inline void check_deleted(bool deleted)
{
  if (deleted)
  {
    throw UaException{Status::BadNodeIdUnknown,
      make_error_detail("NodeNotFound", "Node has been deleted", "DefaultBaseNode")};
  }
}

// One shared, immutable empty reference vector for every node that has no references yet. Fresh nodes
// (the common case at NodeSet import - thousands of leaf nodes) point at this instead of each
// allocating their own empty vector. The first mutation copies-on-write to an owned vector, so the
// sentinel is never modified.
const base_node_details::SharedReferences& empty_references_sentinel()
{
  static const base_node_details::SharedReferences sentinel =
    std::make_shared<const std::vector<ua::Reference>>();
  return sentinel;
}

// What a Reported registration on @p attributeId observes after a write: the value the description now holds,
// a merged LocalizedText included, stamped with the write's time unless a VariableType's Value carries one.
DataValue reported_value(const NodeDescription& description, AttributeId attributeId)
{
  const auto held = description.attribute(attributeId);
  DataValue value = held.is_good() ? held.value() : DataValue{};
  if (!value.source_timestamp())
  {
    value.source_timestamp() = DateTime::now();
  }
  return value;
}

}  // namespace

BaseNode::BaseNode(const NodeId& nodeId, NodeClass nodeClass)
  : mNodeId{nodeId},
    mDescription{NodeDescription::try_from_attributes(nodeId, nodeClass, InitialAttributes{}).value()},
    mReferences{empty_references_sentinel()}
{}

void BaseNode::call(const CallMethodRequest& methodToCall, shared_ptr<const MethodCallContext> context,
  CallMethodCompleteCallback callback) const
{
  {
    // mDeleted is guarded by mMutex; read it under the shared lock like every other accessor,
    // matching mark_as_deleted()'s WriteLock write (avoids the RacerD read/write race).
    const ReadLock lock{mMutex};
    check_deleted(mDeleted);
  }

  UA_UNUSED(methodToCall);
  UA_UNUSED(context);
  UA_UNUSED(callback);
  throw UaException{Status::BadAttributeIdInvalid,
    ErrorDetail::build("AttributeNotSupported", "Call is not supported on this node class", "DefaultBaseNode")
      .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))};
}

void BaseNode::read_value(Duration maxAge, bool setSourceTimestamp, const ReadValueId& nodeToRead,
  const AccessIdentity* identity, ReadValueCompleteCallback callback) const
{
  UA_UNUSED(identity);  // a base node has no Value; the refusal below is the same for every caller
  {
    const ReadLock lock{mMutex};
    check_deleted(mDeleted);
  }

  UA_UNUSED(maxAge);
  UA_UNUSED(setSourceTimestamp);
  UA_UNUSED(nodeToRead);
  UA_UNUSED(callback);
  throw UaException{Status::BadAttributeIdInvalid,
    ErrorDetail::build(
      "AttributeNotSupported", "Value read is not supported on this node class", "DefaultBaseNode")
      .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))};
}

void BaseNode::write_value_async(
  const ua::WriteValue& nodeToWrite, const AccessIdentity* identity, WriteValueCompleteCallback callback)
{
  UA_UNUSED(nodeToWrite);
  UA_UNUSED(identity);
  VoidResult result = [&]() -> VoidResult
  {
    try
    {
      const ReadLock lock{mMutex};
      check_deleted(mDeleted);
      return VoidResult{Status::BadAttributeIdInvalid,
        ErrorDetail::build(
          "ValueWriteUnsupported", "Value write is not supported on this node class", "DefaultBaseNode")
          .context(ua::ContextKeys::nodeAttribute, ua::to_string(AttributeId::Value))
          .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))};
    }
    catch (...)
    {
      return VoidResult{ua::exception_to_status_code(std::current_exception())};
    }
  }();

  detail::invoke_user_callback(std::move(callback), std::move(result));
}

bool BaseNode::is_attribute_id_valid(AttributeId attributeId) const
{
  check_deleted(mDeleted);

  switch (attributeId)
  {
  case AttributeId::NodeId:
  case AttributeId::NodeClass:
  case AttributeId::BrowseName:
  case AttributeId::DisplayName:
  case AttributeId::Description:
  case AttributeId::WriteMask:
  case AttributeId::RolePermissions:
  case AttributeId::AccessRestrictions:
    return true;

  default:
    return false;
  }
}

void BaseNode::get_references_async(GetReferencesCallback callback) const noexcept
{
  // Capture references under-lock; fire the callback outside the lock -
  // consumer chains may re-enter the node (e.g. add_reference) or hold other
  // locks, and firing in-lock causes deadlock.
  std::optional<Result<ua::References>> result;
  try
  {
    const ReadLock lock{mMutex};
    check_deleted(mDeleted);
    result.emplace(ua::References{mReferences});
  }
  catch (...)
  {
    result.emplace(ua::exception_to_status_code(std::current_exception()));
  }
  callback(std::move(*result));
}

VoidResult BaseNode::change_through_namespace(std::vector<Reference> references, bool add, bool reportMissing)
{
  shared_ptr<NamespaceLink> link;
  {
    const ReadLock lock{mMutex};
    check_deleted(mDeleted);
    link = mNamespaceLink;
  }
  if (!link)
  {
    return VoidResult{Status::BadInvalidState,
      ErrorDetail::build("NamespaceUnavailable", "No namespace created this Node", "DefaultBaseNode")
        .context(ua::ContextKeys::nodeId, mNodeId)};
  }
  return Namespace::change_own_references(
    *link, std::static_pointer_cast<BaseNode>(shared_from_this()), std::move(references), add, reportMissing);
}

NodeId BaseNode::node_id() const
{
  const ReadLock lock{mMutex};
  check_deleted(mDeleted);
  return mNodeId;
}

QualifiedName BaseNode::browse_name() const
{
  const ReadLock lock{mMutex};
  check_deleted(mDeleted);
  return mDescription.browse_name();
}

base_node_details::MutationSnapshot BaseNode::mutation_snapshot() const
{
  const ReadLock lock{mMutex};
  check_deleted(mDeleted);
  return base_node_details::MutationSnapshot{mNodeId, get_node_class(), mReferences};
}

void BaseNode::commit_reference_snapshot(base_node_details::SharedReferences references)
{
  const WriteLock lock{mMutex};
  check_deleted(mDeleted);
  mReferences = std::move(references);
}

void BaseNode::mark_as_deleted()
{
  const WriteLock lock{mMutex};
  mDeleted.store(true, std::memory_order_release);
}

BaseNode::ReferencesOutcome BaseNode::change_references(
  const std::vector<Reference>& references, bool add, bool reportMissing)
{
  const WriteLock lock{mMutex};
  check_deleted(mDeleted);
  std::vector<Reference> finalReferences{mReferences->begin(), mReferences->end()};
  bool changed = false;
  if (add)
  {
    // Part 3 4.3.4: "each Node can reference another Node with the same ReferenceType only once". A batch
    // that repeats a held Reference, or holds one twice, is refused whole (Part 4 Table 27).
    const auto duplicated = reference_identity::held_or_repeated(*mReferences, references);
    if (const auto first = std::ranges::find(duplicated, true); first != duplicated.end())
    {
      const auto position = static_cast<std::size_t>(first - duplicated.begin());
      const Reference& duplicate = references[position];
      // A Reference identified with one of another type that is neither the type asked for nor a subtype of
      // it is not the Reference asked for, which the address space must not take as held.
      const auto identifies = [&duplicate](const Reference& candidate)
      {
        return &candidate != &duplicate && candidate.identifies_same_reference_as(duplicate);
      };
      const auto heldAs = std::ranges::find_if(*mReferences, identifies);
      const auto repeatedAs = std::find_if(
        references.begin(), references.begin() + static_cast<std::ptrdiff_t>(position), identifies);
      const Reference* identified = heldAs != mReferences->end() ? &*heldAs
                                    : repeatedAs != references.begin() + static_cast<std::ptrdiff_t>(position)
                                      ? &*repeatedAs
                                      : nullptr;
      if (identified != nullptr && !reference_identity::held_as_requested(duplicate, *identified))
      {
        return ReferencesOutcome{
          VoidResult{reference_identity::conflicting_type_refusal(duplicate, *identified)}};
      }
      return ReferencesOutcome{VoidResult{Status::BadDuplicateReferenceNotAllowed,
        ErrorDetail::build("DuplicateReference",
          "The Node already holds this Reference, or the request holds it twice",
          "DefaultBaseNode")
          .context(ContextKeys::nodeId, mNodeId)
          .context(ContextKeys::typeActual, duplicate.type_id())
          .context(ContextKeys::actual, duplicate.target_id().node_id())}};
    }
    finalReferences.insert(finalReferences.end(), references.begin(), references.end());
    changed = !references.empty();
  }
  else
  {
    // Part 3 4.3.4: References are identified "in OPC UA Services" with a subtype of a concrete ReferenceType
    // equal to its base concrete type, so a removal naming HasComponent removes a held HasOrderedComponent to
    // the same target, as an add of one is refused where the other is held.
    const auto remove = [&references](const Reference& candidate)
    {
      return std::ranges::any_of(references,
        [&candidate](const Reference& requested)
        { return requested.identifies_same_reference_as(candidate); });
    };
    auto newEnd = std::ranges::remove_if(finalReferences, remove).begin();
    changed = newEnd != finalReferences.end();
    finalReferences.erase(newEnd, finalReferences.end());
  }
  if (changed)
  {
    mReferences = make_shared<const std::vector<Reference>>(std::move(finalReferences));
  }
  if (!add && reportMissing && !changed)
  {
    return ReferencesOutcome{VoidResult{Status::UncertainReferenceNotDeleted}, false};
  }
  return ReferencesOutcome{VoidResult{}, changed};
}

bool BaseNode::remove_references_to(const std::unordered_set<NodeId>& targets)
{
  const auto targetsOne = [&targets](const Reference& reference)
  {
    const ExpandedNodeId& target = reference.target_id();
    return target.is_local() && target.is_index_based() && targets.contains(target.node_id());
  };
  {
    // Most Nodes hold no Reference to a deleted Node: they are passed over under the shared lock.
    const ReadLock lock{mMutex};
    if (mDeleted.load(std::memory_order_relaxed) || std::ranges::none_of(*mReferences, targetsOne))
    {
      return false;
    }
  }
  const WriteLock lock{mMutex};
  if (mDeleted.load(std::memory_order_relaxed))
  {
    return false;
  }
  std::vector<Reference> kept;
  kept.reserve(mReferences->size());
  std::ranges::copy_if(*mReferences, std::back_inserter(kept), std::not_fn(targetsOne));
  if (kept.size() == mReferences->size())
  {
    return false;
  }
  mReferences = make_shared<const std::vector<Reference>>(std::move(kept));
  return true;
}

// --- Async mutations (Node interface) ---

void BaseNode::add_reference_async(
  NodeId type, ExpandedNodeId target, bool isForward, ReferenceModifyCallback callback) noexcept
{
  VoidResult result;
  try
  {
    result = change_through_namespace(
      std::vector<Reference>{Reference{std::move(type), std::move(target), isForward}},
      /*add=*/true,
      /*reportMissing=*/false);
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void BaseNode::add_references_async(
  std::vector<ua::Reference> references, ReferenceModifyCallback callback) noexcept
{
  if (references.empty())
  {
    // Nothing to add - leave mReferences (and the shared empty sentinel) untouched.
    detail::invoke_user_callback(std::move(callback), VoidResult{});
    return;
  }
  VoidResult result;
  try
  {
    result = change_through_namespace(std::move(references), /*add=*/true, /*reportMissing=*/false);
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void BaseNode::remove_reference_async(
  NodeId type, ExpandedNodeId target, bool isForward, ReferenceModifyCallback callback) noexcept
{
  VoidResult result;
  try
  {
    result = change_through_namespace(
      std::vector<Reference>{Reference{std::move(type), std::move(target), isForward}},
      /*add=*/false,
      /*reportMissing=*/true);
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void BaseNode::remove_references_async(
  std::vector<ua::Reference> references, ReferenceModifyCallback callback) noexcept
{
  if (references.empty())
  {
    detail::invoke_user_callback(std::move(callback), VoidResult{});
    return;
  }
  VoidResult result;
  try
  {
    result = change_through_namespace(std::move(references), /*add=*/false, /*reportMissing=*/false);
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void BaseNode::is_node_in_view_async(NodeId nodeId, IsNodeInViewCallback callback) const noexcept
{
  UA_UNUSED(nodeId);
  try
  {
    const ReadLock lock{mMutex};
    check_deleted(mDeleted);
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
    return;
  }
  callback(true);
}

void BaseNode::add_node_to_view_async(NodeId nodeId, ViewModifyCallback callback) noexcept
{
  UA_UNUSED(nodeId);
  callback(VoidResult{Status::BadNotSupported,
    ErrorDetail::build("InvalidNodeClass", "This is not a View Node", "DefaultBaseNode")
      .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))});
}

void BaseNode::raise_reported_registrations(std::weak_ptr<NamespaceMonitoringSupport> helper)
{
  const WriteLock lock{mMutex};
  // The link before the count: a write that sees the count above 0 finds the helper.
  mMonitoringHelper = std::move(helper);
  mReportedRegistrations.fetch_add(1, std::memory_order_acq_rel);
}

void BaseNode::link_monitoring_helper(std::weak_ptr<NamespaceMonitoringSupport> helper)
{
  const WriteLock lock{mMutex};
  mMonitoringHelper = std::move(helper);
}

void BaseNode::lower_reported_registrations() noexcept
{
  auto count = mReportedRegistrations.load(std::memory_order_acquire);
  while (
    count > 0 && !mReportedRegistrations.compare_exchange_weak(count, count - 1, std::memory_order_acq_rel))
  {
  }
}

BaseNode::ChangeObservers BaseNode::change_observers_locked(AttributeId attributeId) const
{
  ChangeObservers observers;
  if (mReportedRegistrations.load(std::memory_order_acquire) > 0)
  {
    observers.helper = mMonitoringHelper.lock();
  }
  if (attributeId == AttributeId::DataType && get_node_class() == NodeClass::Variable)
  {
    observers.structureHelper = mMonitoringHelper.lock();
  }
  return observers;
}

void BaseNode::report_change(
  const ChangeObservers& observers, AttributeId attributeId, const DataValue& value) const
{
  if (observers.helper)
  {
    observers.helper->attribute_changed(mNodeId, attributeId, value);
  }
}

Variant BaseNode::read_attribute(AttributeId attributeId) const
{
  if (is_session_derived_attribute(attributeId))
  {
    throw UaException{Status::BadAttributeIdInvalid,
      ErrorDetail::build("SessionDerivedAttributeNotStored",
        "This Attribute is derived per Session and is never stored on a node",
        "DefaultNode")
        .context(ContextKeys::nodeAttribute, to_string(attributeId))};
  }

  const ReadLock lock{mMutex};

  check_deleted(mDeleted);

  if (!is_attribute_id_valid(attributeId))
  {
    throw UaException{Status::BadAttributeIdInvalid,
      ErrorDetail::build(
        "InvalidAttributeId", "Attribute ID is not valid for this node class", "DefaultBaseNode")
        .context(ua::ContextKeys::nodeAttribute, ua::to_string(attributeId))
        .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))};
  }
  return stored_attribute(attributeId);
}

Variant BaseNode::stored_attribute(AttributeId attributeId) const
{
  const auto held = mDescription.attribute(attributeId);
  if (!held.is_good())
  {
    return Variant{};
  }
  DataValue value = held.value();
  if (attributeId == AttributeId::Value)
  {
    // A VariableType's Value, read back as the DataValue it is held as (DL-20).
    return Variant{std::move(value)};
  }
  return std::move(value.value());
}

NodeDescription BaseNode::written_description(AttributeId attributeId, const Variant& value) const
{
  const auto written = mDescription.try_with_attribute(attributeId, value);
  if (!written.is_good())
  {
    throw UaException{written.status_code()};
  }
  return written.value();
}

bool BaseNode::is_version_name(const QualifiedName& name) noexcept
{
  return name.namespace_index() == 0 && (static_cast<string_view>(name.name()) == "NodeVersion" ||
                                          static_cast<string_view>(name.name()) == "ViewVersion");
}

NodeDescription BaseNode::attributes() const
{
  const ReadLock lock{mMutex};
  return mDescription;
}

void BaseNode::write_attribute_async(
  AttributeId attributeId, Variant attributeValue, WriteAttributeCompleteCallback callback)
{
  ChangeObservers observers;
  std::optional<NodeDescription> written;
  bool dataTypeChanged{false};
  // The in-memory write completes inline. Any failure (deleted node, invalid
  // attribute) is converted to a bad VoidResult and reported via the callback -
  // the *_async surface never throws. The callback is invoked exactly once: in the
  // catch on failure, or once at the end on success (a throwing user callback on
  // the success path propagates rather than re-firing).
  try
  {
    if (is_session_derived_attribute(attributeId))
    {
      // Storing one would let a node disagree with what access control actually enforces. The user
      // view is derived from the source Attribute and the verdict, so there is nothing to keep here.
      throw UaException{Status::BadAttributeIdInvalid,
        ErrorDetail::build("SessionDerivedAttributeNotStorable",
          "This Attribute is derived per Session from its source Attribute and the authorization "
          "verdict; it cannot be stored on a node",
          "DefaultNode")
          .context(ContextKeys::nodeAttribute, to_string(attributeId))};
    }
    const WriteLock lock{mMutex};

    check_deleted(mDeleted);

    if (!is_attribute_id_valid(attributeId))
    {
      throw UaException{Status::BadAttributeIdInvalid,
        ErrorDetail::build(
          "InvalidAttributeId", "Attribute ID is not valid for this node class", "DefaultBaseNode")
          .context(ua::ContextKeys::nodeAttribute, ua::to_string(attributeId))
          .context(ua::ContextKeys::nodeId, ua::to_string(mNodeId))};
    }

    // The new description is built from the held one and stored under this hold (NR-21 rule 5): a
    // LocalizedText merges per locale (OPC 10000-4 5.10.4.1), and a value that does not fit the Attribute is
    // refused with the description's answer and stores nothing.
    written.emplace(written_description(attributeId, attributeValue));
    if (attributeId == AttributeId::DataType)
    {
      const NodeId* before = mDescription.data_type();
      const NodeId* after = written->data_type();
      dataTypeChanged = before == nullptr || after == nullptr || *before != *after;
    }
    if (attributeId == AttributeId::BrowseName && mMayHoldVersions && is_version_name(written->browse_name()))
    {
      mMayHoldVersions->store(true, std::memory_order_release);
    }
    mDescription = *written;
    observers = change_observers_locked(attributeId);
    // Reported under the lock that committed the change, so that two writes are reported in the order they
    // were committed (NR-48 rule 4): the helper takes only its own mutex and calls no sink. Reported from the
    // description stored, so that a Reported registration observes the stored value (SVR-MI-GEN-071): for
    // LocalizedText the merge's result, not the raw client update; for AccessLevel and AccessLevelEx both,
    // since a write changes both. The write is committed whatever the report does, which fails only to
    // allocate.
    if (observers.helper)
    {
      try
      {
        report_change(observers, attributeId, reported_value(*written, attributeId));
        if (attributeId == AttributeId::AccessLevel || attributeId == AttributeId::AccessLevelEx)
        {
          const AttributeId other =
            attributeId == AttributeId::AccessLevel ? AttributeId::AccessLevelEx : AttributeId::AccessLevel;
          report_change(observers, other, reported_value(*written, other));
        }
      }
      catch (...)
      {
        detail::ignore_expected_exception();
      }
    }
  }
  catch (...)
  {
    callback(VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }

  if (dataTypeChanged)
  {
    // A Variable whose DataType changed is serialized with another DataTypeEncoding: one notification of
    // each monitored item on its Value carries StructureChanged (OPC 10000-4 7.39.1 Table 180). A Variable
    // being created has no monitored item, so no helper is linked to it yet and none is told. Told with no
    // lock held; the write is committed whatever the marking does, which fails only to allocate.
    if (observers.structureHelper)
    {
      try
      {
        observers.structureHelper->structure_changed(mNodeId);
      }
      catch (...)
      {
        detail::ignore_expected_exception();
      }
    }
  }

  // The owning namespace advances the NodeVersion of a DataType, ValueRank or ArrayDimensions change made
  // through it (NR-55).
  detail::invoke_user_callback(std::move(callback), VoidResult{});
}

}  // namespace ua::default_ns
