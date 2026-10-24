// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace.h"
#include "ua_namespace_batch_support.h"

#include "ua_data_value.h"
#include "ua_attribute_wire.h"
#include "ua_option_set.h"
#include "ua_option_set_value_merge.h"
#include "ua_to_string.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_context_state.h"
#include "ua_namespace_monitoring_support_access.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_node_utilities.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_value_id.h"
#include "ua_write_value.h"
#include "ua_role_permissions.h"
#include "ua_to_result.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <iterator>
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ua
{

namespace
{

using detail::batch::current_exception_status;
using detail::batch::failed_answer;
using detail::batch::run_once;
using detail::batch::take_once;

// The Nodes a lookup found, one per NodeId asked for: a lookup that failed whole, or answered another
// number of items, fails every NodeId with its status.
std::vector<NodeResult> found_nodes(BatchResult<NodeResult> found, std::size_t asked)
{
  if (found.batchStatus.is_good() && found.items.size() == asked)
  {
    return std::vector<NodeResult>{
      std::make_move_iterator(found.items.begin()), std::make_move_iterator(found.items.end())};
  }
  const StatusCode failure =
    found.batchStatus.is_bad()
      ? found.batchStatus.status_code()
      : StatusCode{Status::BadInternalError,
          ErrorDetail::build("LookupItemCountMismatch",
            "The namespace's lookup answered another number of items than it was asked for",
            "Namespace")
            .context(ContextKeys::sizeExpected, std::to_string(asked))
            .context(ContextKeys::sizeActual, std::to_string(found.items.size()))};
  return std::vector<NodeResult>(asked, NodeResult{failure});
}

// What the immediate effective_permissions answered for one subject, as the asynchronous form answers it.
Result<PermissionType> permissions_answer(const std::optional<PermissionType>& permissions)
{
  if (permissions)
  {
    return *permissions;
  }
  return StatusCode{Status::BadNotSupported,
    ErrorDetail::build("ImmediatePermissionsDeclined",
      "The immediate effective_permissions answered nullopt; a namespace that declines it overrides "
      "effective_permissions_async",
      "Namespace")};
}

// Each of @p count items answered @p status, which keeps its ErrorDetail.
template<typename Item>
BatchResult<Item> each_answered(std::size_t count, const StatusCode& status)
{
  BatchResult<Item> result;
  result.items.reserve(count);
  for (std::size_t i = 0; i < count; ++i)
  {
    result.items.emplace_back(status);
  }
  return result;
}

// What an optional member a namespace does not implement answers for each item.
StatusCode not_supported(std::string code, std::string message)
{
  return StatusCode{
    Status::BadNotSupported, ErrorDetail::build(std::move(code), std::move(message), "Namespace")};
}

}  // namespace

namespace detail::batch
{

namespace
{

// The written DataValue with @p value in place of its own. A merge changes the value only: the written
// StatusCode and both timestamps are the client's ("If the SourceTimestamp or the ServerTimestamp is
// specified, the Server shall use these values", OPC 10000-4 5.10.4.2).
DataValue with_merged_value(const DataValue& written, Variant value)
{
  DataValue merged{std::move(value)};
  merged.status() = written.status();
  merged.source_timestamp() = written.source_timestamp();
  merged.source_pico_seconds() = written.source_pico_seconds();
  merged.server_timestamp() = written.server_timestamp();
  merged.server_pico_seconds() = written.server_pico_seconds();
  return merged;
}

}  // namespace

// A Value read for an item, narrowed to the item's IndexRange, with the read's code (a Good subcode, or an
// Uncertain code with the Value it holds). A range the Value cannot satisfy fails the item with the status
// apply_to_value sets; a Value whose own status is Bad is passed on unchanged.
DataValueResult narrowed(DataValueResult read, const NumericRange& range)
{
  if (!read.has_value())
  {
    return read;
  }
  const StatusCode answered = read.status_code();
  DataValue value = std::move(read).value();
  const auto& priorStatus = value.status();
  const bool badBefore = priorStatus.has_value() && priorStatus.value().is_bad();
  index_range_utils::apply_to_value(value, range);
  const auto& narrowedStatus = value.status();
  if (!badBefore && narrowedStatus.has_value() && narrowedStatus.value().is_bad())
  {
    return DataValueResult{narrowedStatus.value()};
  }
  return DataValueResult{std::move(value), answered};
}

// What is written to a Node as it is given, rather than encoded as a client's write
// (COMP-ADDRSP-ACCESSOR-ROUTE-05 item 2): the forms the accessor's setters write and a client's write cannot
// express. A VariableType's Value is stored as the whole DataValue, a null one clearing it; a null clears an
// optional Attribute (the setters taking std::nullopt); the Attributes the Write service's encoding does not
// handle are written as the setters build them. Nothing for any other value, which is encoded.
std::optional<Variant> written_as_given(AttributeId attributeId, const DataValue& written)
{
  const bool null = written.value().empty();
  switch (attributeId)
  {
  case AttributeId::Value:
    // A VariableType's Value, held in the form it was given: a DataValue with a status or a timestamp as that
    // DataValue, a value alone as its Variant (a null one clears it).
    if (!written.status() && !written.source_timestamp() && !written.server_timestamp())
    {
      return written.value();
    }
    return Variant{written};
  case AttributeId::RolePermissions:
  case AttributeId::AccessRestrictions:
  case AttributeId::AccessLevelEx:
  case AttributeId::DataTypeDefinition:
    return written.value();
  case AttributeId::MinimumSamplingInterval:
  case AttributeId::ArrayDimensions:
    if (null)
    {
      return Variant{};
    }
    return std::nullopt;
  default:
    return std::nullopt;
  }
}

// Whether a Variable's Value write merges into the current Value before it is written: a write with an
// IndexRange (OPC 10000-4 7.27), or an OptionSet carrying ValidBits (OPC 10000-3 8.40).
bool merges(const WriteValue& write)
{
  if (!write.index_range().empty())
  {
    return true;
  }
  const auto* optionSet = write.value().value().try_as<OptionSet>();
  return optionSet != nullptr && !optionSet->valid_bits().empty();
}

// The whole-Value write a merging write (merges) becomes, from the @p current Value read for it: a ranged
// write's partial value applied to the current Value (index_range_utils::apply_write), or an OptionSet's
// written bits merged into the current OptionSet (merge_option_set_value) with its ValidBits cleared. The
// result has no IndexRange. A failed read, a range that does not apply, and a current Value that is not an
// OptionSet fail the item with their status, and a ranged write onto a Value whose status is Bad fails it
// with Bad_IndexRangeNoData; the server's own OptionSet write (@p serversOwn) to a Variable holding none is
// written as given.
Result<WriteValue> merged_value_write(
  const WriteValue& written, const DataValueResult& current, bool serversOwn)
{
  // The write is merged into the current Value, which the SDK acts on: an Uncertain read is refused.
  if (!current.is_good())
  {
    return Result<WriteValue>{::ua::detail::read_failure(current.status_code(), "Namespace")};
  }
  const Variant& currentValue = current.value().value();
  WriteValue merged;
  merged.node_id() = written.node_id();
  merged.attribute_id() = written.attribute_id();
  if (!written.index_range().empty())
  {
    // A Value whose DataValue status is Bad is null (OPC 10000-4 7.11.1, Table 135), so a range has no
    // elements to be applied to; an Uncertain Value is present, and the range is applied to it.
    if (const auto& status = current.value().status(); status.has_value() && status->is_bad())
    {
      return Result<WriteValue>{StatusCode{Status::BadIndexRangeNoData,
        ErrorDetail::build("IndexRangeOntoBadValue",
          "A ranged write has no elements to apply to: the current Value's status is Bad",
          "Namespace")
          .context(ContextKeys::nodeId, to_string(written.node_id()))
          .cause(*status)}};
    }
    auto range = parse_numeric_range(written.index_range());
    if (!range.is_good())
    {
      return Result<WriteValue>{range.status_code()};
    }
    auto applied = index_range_utils::apply_write(currentValue, written.value().value(), range.value());
    if (!applied.is_good())
    {
      return Result<WriteValue>{applied.status_code()};
    }
    merged.value() = with_merged_value(written.value(), std::move(applied).value());
    return merged;
  }
  const auto* writtenSet = written.value().value().try_as<OptionSet>();
  const auto* currentSet = currentValue.try_as<OptionSet>();
  if (writtenSet == nullptr)
  {
    return Result<WriteValue>{StatusCode{Status::BadInternalError}};
  }
  if (currentSet == nullptr)
  {
    // The server's own write (no caller) of an OptionSet to a Variable holding none, as when it gives the
    // Variable its first Value, is stored as given: there is nothing to merge into.
    if (serversOwn)
    {
      return written;
    }
    return Result<WriteValue>{StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("OptionSetMergeCurrentNotOptionSet",
        "Current value of node is not an OptionSet; cannot merge ValidBits",
        "Namespace")
        .context(ContextKeys::nodeId, to_string(written.node_id()))}};
  }
  auto bits = merge_option_set_value(*writtenSet, *currentSet);
  if (!bits.is_good())
  {
    return Result<WriteValue>{bits.status_code()};
  }
  auto structure = currentSet->clone();
  auto* mergedSet = static_cast<OptionSet*>(structure.get());
  mergedSet->value() = std::move(bits).value();
  mergedSet->valid_bits().clear();
  merged.value() = with_merged_value(written.value(), Variant{std::move(structure)});
  return merged;
}

Result<Variant> client_attribute_value(
  NodeClass nodeClass, const NodeId& nodeId, AttributeId attributeId, const Variant& value)
{
  if (attributeId == AttributeId::RolePermissions)
  {
    auto decoded = attribute_wire::decode_role_permissions(value);
    if (!decoded.is_good())
    {
      return Result<Variant>{decoded.status_code()};
    }
    std::optional<std::vector<RolePermissionType>> proposed;
    if (!decoded.value().empty())
    {
      proposed = std::move(decoded).value();
    }
    return attribute_wire::role_permissions(proposed);
  }
  return node_utils::encode_writable_attribute_of_class(nodeClass, nodeId, attributeId, value);
}

}  // namespace detail::batch

namespace
{

// The state of the context a namespace answers before it is attached: index 0, a monitoring helper that
// refuses every create, modify and delete (DL-68 (1)), and refused by attach.
const shared_ptr<const detail::NamespaceContextState>& unattached_state()
{
  static const auto state = std::make_shared<const detail::NamespaceContextState>(
    uint16_t{0}, detail::MonitoringSupportAccess::create_unattached());
  return state;
}

}  // namespace

VoidResult Namespace::attach(NamespaceContext context)
{
  // Only registration creates a context (NR-39). The one context() answers before attach is the namespace's
  // own stand-in, so a namespace cannot use it to give another an index.
  if (context.mState == unattached_state())
  {
    return VoidResult{StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("NamespaceContextNotFromRegistration",
        "The context a namespace answers before it is attached cannot attach a namespace; only registration "
        "creates a context",
        "Namespace")}};
  }
  if (mAttachClaimed.exchange(true, std::memory_order_acq_rel))
  {
    return VoidResult{StatusCode{Status::BadInvalidState,
      ErrorDetail::build("NamespaceAlreadyAttached",
        "This namespace object was attached already; a namespace object accepts one context",
        "Namespace")
        .context(ContextKeys::namespaceIndex, std::to_string(context.index()))}};
  }
  mContext.emplace(std::move(context));
  mAttached.store(true, std::memory_order_release);
  try
  {
    return on_attached(*mContext);
  }
  catch (...)
  {
    return VoidResult{exception_to_status_code(std::current_exception())};
  }
}

const NamespaceContext& Namespace::context() const noexcept
{
  if (mAttached.load(std::memory_order_acquire))
  {
    return *mContext;
  }
  static const NamespaceContext unattached{unattached_state()};
  return unattached;
}

VoidResult Namespace::on_attached(const NamespaceContext& context)
{
  (void)context;
  return {};
}

void Namespace::resolve_each(std::span<const NodeId> nodeIds,
  std::function<void(BatchResult<NodeResult>)> callback,
  const std::function<void(const NodeId&, std::function<void(NodeResult)>)>& resolveOne)
{
  const std::size_t count = nodeIds.size();
  if (count == 0)
  {
    callback(BatchResult<NodeResult>{});
    return;
  }

  // Fan out one resolution per id into ordered slots and complete once every item has reported. The
  // resolver may complete inline or asynchronously: the loop-guard count (N + 1, released after the
  // loop) ensures the final callback never fires mid-loop when completions arrive inline, and the
  // acquire/release on the counter publishes every slot write to the finisher.
  struct Collector
  {
    std::vector<std::optional<NodeResult>> slots;
    std::atomic<std::size_t> remaining;
    std::function<void(BatchResult<NodeResult>)> callback;
  };

  auto collector = std::make_shared<Collector>();
  collector->slots.resize(count);
  collector->remaining.store(count + 1, std::memory_order_relaxed);
  collector->callback = std::move(callback);

  auto finishOne = [collector]()
  {
    if (collector->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1)
    {
      BatchResult<NodeResult> result;
      result.items.reserve(collector->slots.size());
      for (auto& slot : collector->slots)
      {
        result.items.push_back(std::move(*slot));
      }
      collector->callback(std::move(result));
    }
  };

  for (std::size_t i = 0; i < count; ++i)
  {
    resolveOne(nodeIds[i],
      [collector, i, finishOne](NodeResult itemResult)
      {
        collector->slots[i] = std::move(itemResult);
        finishOne();
      });
  }

  finishOne();
}

// --- Batched members: defaults ----------------------------------------------------------------------
//
// None blocks or throws; each completes once, with one result per item in item order. None keeps `this` past
// its return: a completion that arrives later uses only what it captured.

std::optional<NodeResult> Namespace::find_node(const NodeId& nodeId, std::optional<Duration> maxAge)
{
  // Declines: "ask me through find_nodes_async", never "no such node", which is an engaged
  // Bad_NodeIdUnknown.
  (void)nodeId;
  (void)maxAge;
  return std::nullopt;
}

void Namespace::enumerate_nodes_async(
  const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete)
{
  (void)request;
  complete(Result<std::vector<NodeId>>{
    not_supported("EnumerateNotSupported", "This namespace does not support node enumeration")});
}

void Namespace::release_resume_token(ByteString token)
{
  // Final default: a token that holds nothing needs no release.
  (void)token;
}

void Namespace::write_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  (void)caller;
  complete(
    each_answered<VoidResult>(items.size(),
      StatusCode{Status::BadNotWritable,
        ErrorDetail::build("WriteNotSupported", "This namespace does not support writes", "Namespace")}),
    std::vector<VersionedNode>{});
}

void Namespace::call_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  // Every item declined, so the Call service asks the Method's namespace, and answers Bad_NotImplemented
  // for an item both decline.
  (void)request;
  (void)caller;
  BatchResult<std::optional<CallResult>> declined;
  declined.items.reserve(items.size());
  for (std::size_t i = 0; i < items.size(); ++i)
  {
    declined.items.emplace_back(std::nullopt);
  }
  complete(std::move(declined));
}

void Namespace::view_contains_async(const RequestInfo& request, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  // Default (NR-16): a candidate is a member when it is the target, in this server, of one of the View Node's
  // forward References, read in one call with no limit.
  const auto once = take_once(complete);
  if (!once)
  {
    return;
  }
  try
  {
    std::vector<ExpandedNodeId> candidates{nodes.begin(), nodes.end()};
    const NodeId views[]{view};

    // The References are read through this namespace, so only while this member runs: a lookup answered
    // after it returned is refused, because the completion does not hold the namespace. The state settles
    // which came first.
    struct Lookup
    {
      std::optional<NodeResult> viewNode;
      std::atomic<int> state{0};  // 0 waiting, 1 answered before the return, 2 returned first
    };

    auto lookup = std::make_shared<Lookup>();
    find_nodes_async(request,
      views,
      std::nullopt,
      [lookup, once](BatchResult<NodeResult> found)
      {
        try
        {
          lookup->viewNode = std::move(found_nodes(std::move(found), 1).front());
        }
        catch (...)
        {
          lookup->viewNode = NodeResult{current_exception_status()};
        }
        int waiting = 0;
        if (!lookup->state.compare_exchange_strong(waiting, 1, std::memory_order_acq_rel))
        {
          run_once(once,
            failed_answer<BatchResult<BoolResult>>(not_supported("ViewLookupNotImmediate",
              "The namespace answered the View Node's lookup after the member returned; a namespace that "
              "answers later overrides view_contains_async")));
        }
      });
    int waiting = 0;
    if (lookup->state.compare_exchange_strong(waiting, 2, std::memory_order_acq_rel))
    {
      return;
    }
    const std::optional<NodeResult>& viewNode = lookup->viewNode;
    if (!viewNode->is_good())
    {
      run_once(once,
        each_answered<BoolResult>(
          candidates.size(), ::ua::detail::lookup_failure(view, viewNode->status_code(), "Namespace")));
      return;
    }
    const shared_ptr<Node> node = viewNode->value();
    const ReferenceQuery queries[]{ReferenceQuery{*node, view, BrowseDirection::Forward, {}, 0, {}}};
    read_references_async(request,
      queries,
      [once, node, candidates = std::move(candidates)](BatchResult<NodeReferencesResult> read)
      {
        try
        {
          if (read.batchStatus.is_bad() || read.items.size() != 1)
          {
            run_once(once,
              failed_answer<BatchResult<BoolResult>>(read.batchStatus.is_bad()
                                                       ? read.batchStatus.status_code()
                                                       : StatusCode{Status::BadInternalError}));
            return;
          }
          if (!read.items.front().is_good())
          {
            run_once(once,
              each_answered<BoolResult>(candidates.size(),
                ::ua::detail::references_failure(read.items.front().status_code(), "Namespace")));
            return;
          }
          const NodeReferences& references = read.items.front().value();
          if (!references.resumeToken.empty())
          {
            run_once(once,
              failed_answer<BatchResult<BoolResult>>(StatusCode{Status::BadInternalError,
                ErrorDetail::build("ReferencesPagedWithoutLimit",
                  "The namespace paged the View Node's References when asked for all of them",
                  "Namespace")}));
            return;
          }
          BatchResult<BoolResult> contained;
          contained.items.reserve(candidates.size());
          for (const ExpandedNodeId& candidate : candidates)
          {
            bool member = false;
            if (candidate.is_local() && candidate.namespace_uri().empty())
            {
              for (const Reference& reference : references.references)
              {
                const ExpandedNodeId& target = reference.target_id();
                if (reference.is_forward() && target.is_local() && target.namespace_uri().empty() &&
                    target.node_id() == candidate.node_id())
                {
                  member = true;
                  break;
                }
              }
            }
            contained.items.emplace_back(member);
          }
          run_once(once, std::move(contained));
        }
        catch (...)
        {
          run_once(once, failed_answer<BatchResult<BoolResult>>(current_exception_status()));
        }
      });
  }
  catch (...)
  {
    run_once(once, failed_answer<BatchResult<BoolResult>>(current_exception_status()));
  }
}

void Namespace::add_to_view_async(const RequestInfo& request, const NodeId& view,
  std::span<const NodeId> nodes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  (void)view;
  complete(each_answered<VoidResult>(nodes.size(),
             not_supported("AddToViewNotSupported", "This namespace does not support View changes")),
    std::vector<VersionedNode>{});
}

void Namespace::create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
  std::function<void(BatchResult<NodeResult>)> complete)
{
  (void)request;
  complete(each_answered<NodeResult>(
    nodes.size(), not_supported("CreateNodeNotSupported", "This namespace does not support node creation")));
}

void Namespace::delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes,
  ReferenceHalves halves,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  (void)halves;
  complete(each_answered<DeleteNodeResult>(nodes.size(),
             not_supported("DeleteNodeNotSupported", "This namespace does not support node deletion")),
    std::vector<VersionedNode>{});
}

void Namespace::add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  complete(each_answered<VoidResult>(changes.size(),
             not_supported("AddReferenceNotSupported", "This namespace does not support Reference changes")),
    std::vector<VersionedNode>{});
}

void Namespace::remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  complete(
    each_answered<VoidResult>(changes.size(),
      not_supported("RemoveReferenceNotSupported", "This namespace does not support Reference changes")),
    std::vector<VersionedNode>{});
}

namespace
{

using MonitoringHelper = default_ns::NamespaceMonitoringSupport;

}  // namespace

void Namespace::create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> complete)
{
  (void)request;
  (void)caller;
  // Default (NR-47): every item goes to the registration's helper, Sampled, with the Node it carries. Before
  // registration the helper this namespace answers refuses each item Bad_NotSupported
  // (NamespaceNotRegistered) without looking at it; after, it answers an item without a Node
  // Bad_NodeIdUnknown.
  std::vector<MonitoringHelper::ResolvedMonitoringItem> resolved;
  resolved.reserve(items.size());
  for (const auto& item : items)
  {
    resolved.push_back(MonitoringHelper::ResolvedMonitoringItem{item, MonitoringHelper::Delivery::Sampled});
  }
  BatchResult<MonitoringCreateItemResult> batch;
  batch.items.reserve(resolved.size());
  for (auto& created : context().monitoring().create_monitoring(resolved))
  {
    batch.items.push_back(std::move(created.result));
  }
  complete(std::move(batch));
}

void Namespace::modify_monitoring_async(const RequestInfo& request,
  std::span<const MonitoringModifyItem> items,
  std::function<void(BatchResult<MonitoringModifyItemResult>)> complete)
{
  (void)request;
  // Default (NR-47): the registration's helper modifies what it issued, each registration keeping the
  // delivery it has: Sampled for an item this default created, and whatever an override of
  // create_monitoring_async chose for its own. Before registration the helper refuses each item
  // Bad_NotSupported.
  auto& helper = context().monitoring();
  std::vector<MonitoringHelper::ResolvedMonitoringModifyItem> resolved;
  resolved.reserve(items.size());
  for (const auto& item : items)
  {
    const auto registration = detail::MonitoringSupportAccess::registration(helper, item.handle);
    resolved.push_back(MonitoringHelper::ResolvedMonitoringModifyItem{
      item, registration ? registration->delivery : MonitoringHelper::Delivery::Sampled});
  }
  BatchResult<MonitoringModifyItemResult> batch;
  batch.items.reserve(resolved.size());
  for (auto& modified : helper.modify_monitoring(resolved))
  {
    batch.items.push_back(std::move(modified.result));
  }
  complete(std::move(batch));
}

void Namespace::delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
  std::function<void(BatchResult<VoidResult>)> complete)
{
  (void)request;
  // Default (NR-47): the registration's helper releases what it issued. Before registration it refuses each
  // handle Bad_NotSupported.
  auto deleted = context().monitoring().delete_monitoring(handles);
  BatchResult<VoidResult> batch;
  batch.items.assign(std::make_move_iterator(deleted.begin()), std::make_move_iterator(deleted.end()));
  complete(std::move(batch));
}

std::optional<PermissionType> Namespace::effective_permissions(
  const AccessIdentity& identity, const Node* node) const
{
  // The standard Part 3 4.8.3 evaluation, and the reason a namespace on the Role model overrides nothing. It
  // never answers nullopt: the Node's description holds its RolePermissions.
  auto permissions = default_role_permissions();
  if (node != nullptr)
  {
    const NodeDescription nodeDescription = node->attributes();
    permissions = role_permissions::resolve_role_permissions(nodeDescription, permissions);
  }
  if (!permissions)
  {
    // The namespace publishes no default and the node carries no array, which is 5.2.9's "not configured" at
    // both levels. Nothing is granted. A namespace that answers nullopt from default_role_permissions because
    // it decides its own way is required to override this member, so reaching here means the Role model
    // applies and has nothing to say.
    return PermissionType{};
  }
  return role_permissions::merge_permission_bits(*permissions, identity.granted_roles()).permissions;
}

void Namespace::effective_permissions_async(const RequestInfo& request,
  shared_ptr<const AccessIdentity> identity, std::optional<std::vector<NodeId>> nodes,
  EffectivePermissionsCallback callback)
{
  // Default (COMP-ADDRSP-NAMESPACE-INTERFACE-08 item 3): each subject through the immediate form, each Node
  // found through the immediate lookup. A subject the immediate form declines, or whose lookup is declined,
  // is answered Bad_NotSupported: a namespace that declines either overrides this member.
  (void)request;
  EffectivePermissionsResult result;
  try
  {
    if (!identity)
    {
      result.batchStatus = VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("AccessIdentityMissing",
          "An access identity is required to resolve effective permissions",
          "Namespace")}};
    }
    else if (nodes && nodes->empty())
    {
      result.batchStatus = VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("EmptyPermissionSubjectBatch",
          "An engaged effective-permission node batch shall not be empty",
          "Namespace")}};
    }
    else if (!nodes)
    {
      result.items.reserve(1);
      try
      {
        result.items.push_back(
          permissions_answer(effective_permissions(*identity, static_cast<const Node*>(nullptr))));
      }
      catch (...)
      {
        result.items.emplace_back(current_exception_status());
      }
    }
    else
    {
      result.items.reserve(nodes->size());
      for (const auto& nodeId : *nodes)
      {
        // A subject whose lookup or evaluation throws answers that subject alone.
        try
        {
          const std::optional<NodeResult> found = find_node(nodeId, std::nullopt);
          if (!found)
          {
            result.items.emplace_back(StatusCode{Status::BadNotSupported,
              ErrorDetail::build("ImmediateLookupDeclined",
                "The namespace declined the immediate lookup; a namespace that declines it overrides "
                "effective_permissions_async",
                "Namespace")
                .context(ContextKeys::nodeId, nodeId.as_definition())});
          }
          else if (!found->is_good())
          {
            result.items.emplace_back(
              ::ua::detail::lookup_failure(nodeId, found->status_code(), "Namespace"));
          }
          else if (found->value()->deleted())
          {
            result.items.emplace_back(StatusCode{Status::BadNodeIdUnknown,
              ErrorDetail::build("NodeDeleted", "The node has been deleted", "Namespace")
                .context(ContextKeys::nodeId, nodeId.as_definition())});
          }
          else
          {
            result.items.push_back(
              permissions_answer(effective_permissions(*identity, found->value().get())));
          }
        }
        catch (...)
        {
          result.items.emplace_back(current_exception_status());
        }
      }
    }
  }
  catch (...)
  {
    result.items.clear();
    result.batchStatus = VoidResult{current_exception_status()};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void Namespace::validate_role_permissions_updates_async(const RequestInfo& request,
  std::span<const RolePermissionsUpdate> updates, std::function<void(BatchResult<VoidResult>)> complete)
{
  // Final default (NR-24 rule 2): the Role model accepts; a namespace that declares a vendor-specific
  // model by disengaging default_role_permissions() and provides no validator refuses.
  (void)request;
  BatchResult<VoidResult> result;
  try
  {
    const bool roleModel = default_role_permissions().has_value();
    result.items.reserve(updates.size());
    for (const auto& update : updates)
    {
      if (!roleModel)
      {
        result.items.emplace_back(StatusCode{Status::BadNotSupported,
          ErrorDetail::build("RolePermissionsUpdateNotSupported",
            "This namespace declares a vendor-specific permission model and did not provide a "
            "RolePermissions update validator",
            "Namespace")
            .context(ContextKeys::nodeId, update.nodeId.as_definition())});
      }
      else if (update.nodeId.is_null())
      {
        result.items.emplace_back(StatusCode{Status::BadInvalidArgument,
          ErrorDetail::build("RolePermissionsUpdateNodeMissing",
            "A prospective RolePermissions update requires a non-null node identifier",
            "Namespace")});
      }
      else
      {
        result.items.emplace_back();
      }
    }
  }
  catch (...)
  {
    result.items.clear();
    result.batchStatus = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(complete), std::move(result));
}

std::optional<std::vector<RolePermissionType>> Namespace::default_role_permissions() const
{
  // ENGAGED AND EMPTY, written out. `return {};` on an `optional<vector<>>` yields NULLOPT, which is
  // the vendor-model declaration - so the short spelling would have every namespace overriding nothing
  // claim it does not use the Role model while inheriting the evaluation that does.
  return std::optional<std::vector<RolePermissionType>>{std::vector<RolePermissionType>{}};
}

std::optional<AccessRestrictionType> Namespace::default_access_restrictions() const
{
  return std::nullopt;
}

void Namespace::on_identity_released(const AccessIdentityKey&) noexcept
{}

std::optional<NodeId> Namespace::metadata_object() const
{
  return std::nullopt;
}

}  // namespace ua
