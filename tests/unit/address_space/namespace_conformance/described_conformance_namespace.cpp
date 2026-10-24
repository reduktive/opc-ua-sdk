// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "described_conformance_namespace.h"

#include "ua_access_level_ex_type.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_context.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node_class.h"
#include "ua_numeric_range_parser.h"
#include "ua_option_set.h"
#include "ua_option_set_value_merge.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <string>
#include <utility>

namespace ua::test
{

namespace
{

constexpr std::string_view errorSource{"DescribedConformanceNamespace"};
constexpr std::string_view nodeVersionName{"NodeVersion"};
constexpr std::string_view viewVersionName{"ViewVersion"};

StatusCode failure(Status status, std::string code, std::string summary, const NodeId& nodeId)
{
  return StatusCode{status,
    ErrorDetail::build(std::move(code), std::move(summary), std::string{errorSource})
      .context(ContextKeys::nodeId, to_string(nodeId))};
}

StatusCode unknown_node(const NodeId& nodeId)
{
  return failure(
    Status::BadNodeIdUnknown, "NodeNotFound", "This namespace holds no Node for the NodeId", nodeId);
}

StatusCode node_deleted(const NodeId& nodeId)
{
  return failure(Status::BadNodeIdUnknown, "NodeDeleted", "The item's Node has been deleted", nodeId);
}

StatusCode foreign_node(const NodeId& nodeId)
{
  return failure(Status::BadInvalidArgument,
    "ForeignNode",
    "The item carries a Node this namespace did not return for its NodeId",
    nodeId);
}

StatusCode current_exception_status() noexcept
{
  return exception_to_status_code(std::current_exception());
}

template<typename Item>
BatchResult<Item> failed_batch(const StatusCode& status)
{
  BatchResult<Item> batch;
  batch.batchStatus = VoidResult{status};
  return batch;
}

// A resume token: the key of the paged read it continues, as eight bytes.
ByteString token_of(uint64_t key)
{
  std::vector<uint8_t> bytes(sizeof(key));
  for (std::size_t i = 0; i < bytes.size(); ++i)
  {
    bytes[i] = static_cast<uint8_t>(key >> (8 * i));
  }
  return ByteString{std::move(bytes)};
}

std::optional<uint64_t> key_of(const ByteString& token)
{
  if (token.size() != sizeof(uint64_t))
  {
    return std::nullopt;
  }
  uint64_t key = 0;
  for (std::size_t i = 0; i < sizeof(uint64_t); ++i)
  {
    key |= uint64_t{token[i]} << (8 * i);
  }
  return key;
}

// A Variable's Value narrowed to a read's IndexRange (OPC 10000-4 7.27). A range the Value cannot satisfy
// fails the item with the status apply_to_value sets; a Value whose own status is Bad is answered as it is.
DataValueResult narrowed(DataValue value, const NumericRange& range)
{
  const bool badBefore = value.status().has_value() && value.status()->is_bad();
  index_range_utils::apply_to_value(value, range);
  if (!badBefore && value.status().has_value() && value.status()->is_bad())
  {
    return DataValueResult{*value.status()};
  }
  return DataValueResult{std::move(value)};
}

// Whether an Attribute reads the same in two descriptions of one Node.
bool same_attribute(const NodeDescription& before, const NodeDescription& after, AttributeId attributeId)
{
  const DataValueResult was = before.attribute(attributeId);
  const DataValueResult is = after.attribute(attributeId);
  if (was.is_good() != is.is_good())
  {
    return false;
  }
  return !was.is_good() || was.value().value() == is.value().value();
}

// OPC 10000-3 Tables 13 and 14: a change of these Attributes of a Variable or VariableType advances its
// NodeVersion.
bool versioned_attribute(NodeClass nodeClass, AttributeId attributeId)
{
  return (nodeClass == NodeClass::Variable || nodeClass == NodeClass::VariableType) &&
         (attributeId == AttributeId::DataType || attributeId == AttributeId::ValueRank ||
           attributeId == AttributeId::ArrayDimensions);
}

bool is_local_target(const ExpandedNodeId& target)
{
  return target.is_local() && target.is_index_based();
}

// The answers of a batch whose items may answer later, collected in item order; the completion runs once,
// after the last item has answered and the loop that started them has finished.
template<typename Item>
class Join
{
public:
  Join(std::size_t count, std::function<void(BatchResult<Item>)> complete)
    : mAnswers(count), mRemaining(count + 1), mComplete(std::move(complete))
  {}

  // Answers item @p index; a second answer for it is dropped.
  void answer(std::size_t index, Item item)
  {
    {
      const std::lock_guard lock{mMutex};
      if (mAnswers[index].has_value())
      {
        return;
      }
      mAnswers[index].emplace(std::move(item));
    }
    finish_one();
  }

  // Called once the loop has started every item.
  void started()
  {
    finish_one();
  }

private:
  void finish_one()
  {
    BatchResult<Item> batch;
    std::function<void(BatchResult<Item>)> complete;
    {
      const std::lock_guard lock{mMutex};
      if (--mRemaining != 0)
      {
        return;
      }
      batch.items.reserve(mAnswers.size());
      for (auto& answer : mAnswers)
      {
        batch.items.push_back(std::move(*answer));
      }
      complete = std::move(mComplete);
    }
    complete(std::move(batch));
  }

  std::mutex mMutex;
  std::vector<std::optional<Item>> mAnswers;  // guarded by mMutex
  std::size_t mRemaining;  // guarded by mMutex
  std::function<void(BatchResult<Item>)> mComplete;  // guarded by mMutex
};

// The Node's TypeDefinition when it is an Object or Variable, otherwise null (OPC 10000-5 12.16,
// affectedType).
template<typename EntryType>
NodeId affected_type(const EntryType& entry)
{
  const NodeClass nodeClass = entry.description.node_class();
  if (nodeClass != NodeClass::Object && nodeClass != NodeClass::Variable)
  {
    return NodeId{};
  }
  const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
  for (const Reference& reference : *entry.references)
  {
    if (reference.is_forward() && reference.type_id() == hasTypeDefinition &&
        is_local_target(reference.target_id()))
    {
      return reference.target_id().node_id();
    }
  }
  return NodeId{};
}

}  // namespace

DescribedConformanceNamespace::Entry::Entry(NodeDescription described)
  : description{std::move(described)}, references{std::make_shared<const std::vector<Reference>>()}
{}

DescribedConformanceNamespace::DescribedConformanceNamespace(String uri) : mUri{std::move(uri)}
{}

DescribedConformanceNamespace::~DescribedConformanceNamespace() = default;

StatusCode DescribedConformanceNamespace::set_call_handler(
  const NodeId& method, MethodCallSource::CallHandler handler)
{
  auto installed = std::make_shared<const MethodCallSource::CallHandler>(std::move(handler));
  const std::lock_guard lock{mMutex};
  const auto found = mEntries.find(method);
  if (found == mEntries.end())
  {
    return unknown_node(method);
  }
  if (found->second.description.node_class() != NodeClass::Method)
  {
    return failure(
      Status::BadNodeClassInvalid, "NotAMethod", "A call handler is installed on a Method", method);
  }
  found->second.handler = std::move(installed);
  return StatusCode{Status::Good};
}

String DescribedConformanceNamespace::uri() const
{
  return mUri;
}

void DescribedConformanceNamespace::shutdown_async(std::function<void(VoidResult)> callback) noexcept
{
  // Nothing of this namespace runs in the background: its monitored items are sampled by the registration's
  // helper, which the address space shuts down first.
  if (callback)
  {
    callback(VoidResult{});
  }
}

// --- Lookup ---------------------------------------------------------------------------------------------

VoidResult DescribedConformanceNamespace::own(const Node& node, const NodeId& nodeId) const
{
  const shared_ptr<Node> held = mStore.held(nodeId, std::nullopt);
  if (held.get() == &node && !node.deleted())
  {
    return VoidResult{};
  }
  if (node.deleted())
  {
    // The store forgets a Node it deletes, so a deleted Node of this namespace is known by its NodeId.
    const NodeDescription description = node.attributes();
    if (held.get() == &node || description.node_id() == nodeId)
    {
      return VoidResult{node_deleted(nodeId)};
    }
  }
  return VoidResult{foreign_node(nodeId)};
}

NodeResult DescribedConformanceNamespace::resolve_locked(const NodeId& nodeId)
{
  const auto found = mEntries.find(nodeId);
  if (found == mEntries.end())
  {
    return NodeResult{unknown_node(nodeId)};
  }
  // The held Node carries the current description already: every change of it is applied to the Node under
  // mMutex.
  if (auto held = mStore.held(nodeId, std::nullopt))
  {
    return NodeResult{std::move(held)};
  }
  return NodeResult{mStore.node_for(found->second.description)};
}

void DescribedConformanceNamespace::find_nodes_async(const RequestInfo& request,
  std::span<const NodeId> nodeIds, std::optional<Duration> maxAge,
  std::function<void(BatchResult<NodeResult>)> complete)
{
  // This namespace's store is its source, so maxAge asks for nothing older than what it holds.
  (void)request;
  (void)maxAge;
  resolve_each(nodeIds,
    std::move(complete),
    [this](const NodeId& nodeId, std::function<void(NodeResult)> answer)
    {
      NodeResult found = [this, &nodeId]
      {
        const std::lock_guard lock{mMutex};
        return resolve_locked(nodeId);
      }();
      answer(std::move(found));
    });
}

std::optional<NodeResult> DescribedConformanceNamespace::find_node(
  const NodeId& nodeId, std::optional<Duration> maxAge)
{
  (void)maxAge;
  const std::lock_guard lock{mMutex};
  return resolve_locked(nodeId);
}

void DescribedConformanceNamespace::enumerate_nodes_async(
  const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete)
{
  (void)request;
  std::vector<NodeId> nodeIds;
  {
    const std::lock_guard lock{mMutex};
    nodeIds.reserve(mEntries.size());
    for (const auto& [nodeId, entry] : mEntries)
    {
      (void)entry;
      nodeIds.push_back(nodeId);
    }
  }
  complete(Result<std::vector<NodeId>>{std::move(nodeIds)});
}

// --- References -----------------------------------------------------------------------------------------

void DescribedConformanceNamespace::read_references_async(const RequestInfo& request,
  std::span<const ReferenceQuery> queries, std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  // The direction and the ReferenceType hint are not applied: the services filter every answer again. A
  // paged read keeps the rest of its snapshot under its token, so that its pages are those of one read.
  (void)request;
  BatchResult<NodeReferencesResult> result;
  try
  {
    result.items.reserve(queries.size());
    for (const ReferenceQuery& query : queries)
    {
      const std::lock_guard lock{mMutex};
      // A token passed back is consumed whatever the call answers.
      std::optional<PagedRead> resumed;
      bool tokenUnknown = false;
      if (!query.resumeToken.empty())
      {
        const auto key = key_of(query.resumeToken);
        const auto paged = key ? mPagedReads.find(*key) : mPagedReads.end();
        if (paged == mPagedReads.end())
        {
          tokenUnknown = true;
        }
        else
        {
          resumed = std::move(paged->second);
          mPagedReads.erase(paged);
        }
      }
      if (auto checked = own(query.node, query.nodeId); checked.is_bad())
      {
        result.items.emplace_back(checked.status_code());
        continue;
      }
      const auto found = mEntries.find(query.nodeId);
      if (found == mEntries.end())
      {
        result.items.emplace_back(node_deleted(query.nodeId));
        continue;
      }
      if (tokenUnknown || (resumed && resumed->nodeId != query.nodeId))
      {
        result.items.emplace_back(failure(Status::BadContinuationPointInvalid,
          "ResumeTokenUnknown",
          "The resume token was not issued for this Node, or has been consumed or released",
          query.nodeId));
        continue;
      }
      const References all = resumed ? resumed->remaining : References{found->second.references};
      const std::size_t total = all.size();
      const std::size_t count =
        query.maxReferences == 0 ? total : std::min<std::size_t>(query.maxReferences, total);
      NodeReferences page;
      page.references = count == total ? all : all.slice(0, static_cast<uint32_t>(count));
      if (count < total)
      {
        const uint64_t key = mNextToken++;
        mPagedReads.emplace(key,
          PagedRead{
            query.nodeId, all.slice(static_cast<uint32_t>(count), static_cast<uint32_t>(total - count))});
        page.resumeToken = token_of(key);
      }
      result.items.emplace_back(std::move(page));
    }
  }
  catch (...)
  {
    result = failed_batch<NodeReferencesResult>(current_exception_status());
  }
  complete(std::move(result));
}

void DescribedConformanceNamespace::release_resume_token(ByteString token)
{
  const auto key = key_of(token);
  if (!key)
  {
    return;
  }
  const std::lock_guard lock{mMutex};
  mPagedReads.erase(*key);
}

void DescribedConformanceNamespace::add_references_async(const RequestInfo& request,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  change_references(changes, true, std::move(complete));
}

void DescribedConformanceNamespace::remove_references_async(const RequestInfo& request,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  change_references(changes, false, std::move(complete));
}

void DescribedConformanceNamespace::change_references(std::span<const ReferenceChange> changes, bool add,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  BatchResult<VoidResult> result;
  std::vector<VersionedNode> versioned;
  try
  {
    result.items.reserve(changes.size());
    const std::lock_guard lock{mMutex};
    // Each source whose References changed, once, and whether every change made to it here marks it created.
    std::vector<std::pair<NodeId, bool>> touched;
    for (const ReferenceChange& change : changes)
    {
      const auto found = mEntries.find(change.source);
      if (found == mEntries.end())
      {
        result.items.emplace_back(unknown_node(change.source));
        continue;
      }
      Entry& entry = found->second;
      // Only an add keeps a remote target's DisplayName with the Reference.
      const Reference requested =
        add ? Reference{change.referenceType, change.target, change.isForward, change.targetDisplayName}
            : Reference{change.referenceType, change.target, change.isForward};
      // OPC 10000-3 4.3.4: a subtype of a concrete ReferenceType identifies a Reference as its base type
      // does.
      const auto identifies = [&requested](const Reference& held)
      {
        return requested.identifies_same_reference_as(held);
      };
      std::vector<Reference> references(entry.references->begin(), entry.references->end());
      if (add)
      {
        if (std::ranges::any_of(references, identifies))
        {
          result.items.emplace_back(failure(Status::BadDuplicateReferenceNotAllowed,
            "DuplicateReference",
            "The Node already holds this Reference",
            change.source));
          continue;
        }
        references.push_back(requested);
      }
      else if (std::erase_if(references, identifies) == 0)
      {
        result.items.emplace_back(StatusCode{Status::UncertainReferenceNotDeleted});
        continue;
      }
      entry.references = std::make_shared<const std::vector<Reference>>(std::move(references));
      const bool created = add && change.sourceCreated;
      const auto at = std::ranges::find_if(
        touched, [&change](const std::pair<NodeId, bool>& source) { return source.first == change.source; });
      if (at == touched.end())
      {
        touched.emplace_back(change.source, created);
      }
      else
      {
        at->second = at->second && created;
      }
      result.items.emplace_back();
    }
    // A versioned source advances its NodeVersion and is reported; one created in this operation keeps the
    // NodeVersion it was created with and is reported. A NodeVersion that cannot advance leaves the change
    // stored and the source unreported.
    for (const auto& [source, created] : touched)
    {
      Entry& entry = mEntries.at(source);
      Entry* property = version_property_locked(entry, nodeVersionName);
      if (property == nullptr || (!created && advance_node_version_locked(*property).is_bad()))
      {
        continue;
      }
      versioned.push_back(VersionedNode{source, affected_type(entry)});
    }
  }
  catch (...)
  {
    result = failed_batch<VoidResult>(current_exception_status());
    versioned.clear();
  }
  complete(std::move(result), std::move(versioned));
}

// --- Versions -------------------------------------------------------------------------------------------

DescribedConformanceNamespace::Entry* DescribedConformanceNamespace::version_property_locked(
  const Entry& owner, std::string_view name)
{
  const NodeId hasProperty{ReferenceTypeId::HasProperty};
  const NodeId hasModellingRule{ReferenceTypeId::HasModellingRule};
  for (const Reference& reference : *owner.references)
  {
    const ExpandedNodeId& target = reference.target_id();
    if (!reference.is_forward() || reference.type_id() != hasProperty || !is_local_target(target) ||
        target.node_id().namespace_index() != context().index())
    {
      continue;
    }
    const auto found = mEntries.find(target.node_id());
    if (found == mEntries.end() || found->second.description.node_class() != NodeClass::Variable)
    {
      continue;
    }
    const QualifiedName& browseName = found->second.description.browse_name();
    if (browseName.namespace_index() != 0 || static_cast<std::string_view>(browseName.name()) != name)
    {
      continue;
    }
    const bool instanceDeclaration = std::ranges::any_of(*found->second.references,
      [&hasModellingRule](const Reference& held)
      { return held.is_forward() && held.type_id() == hasModellingRule; });
    if (!instanceDeclaration)
    {
      return &found->second;
    }
  }
  return nullptr;
}

VoidResult DescribedConformanceNamespace::advance_node_version_locked(Entry& property)
{
  const Variant current = property.value ? property.value->value() : Variant{};
  const auto* held = current.try_as<String>();
  if (!current.empty() && held == nullptr)
  {
    return VoidResult{failure(Status::BadTypeMismatch,
      "NodeVersionTypeMismatch",
      "The NodeVersion Property does not hold a String",
      property.description.node_id())};
  }
  std::string next = std::to_string(++mNodeVersionCounter);
  if (held != nullptr && static_cast<std::string_view>(*held) == next)
  {
    next = std::to_string(++mNodeVersionCounter);
  }
  property.value = DataValue{Variant{String{next}}, DateTime::now()};
  return VoidResult{};
}

VoidResult DescribedConformanceNamespace::advance_view_version_locked(Entry& property)
{
  const Variant current = property.value ? property.value->value() : Variant{};
  const auto* held = current.try_as<uint32_t>();
  if (!current.empty() && held == nullptr)
  {
    return VoidResult{failure(Status::BadTypeMismatch,
      "ViewVersionTypeMismatch",
      "The ViewVersion Property does not hold a UInt32",
      property.description.node_id())};
  }
  // Greater than 0, and changed.
  uint32_t next = held == nullptr ? 1U : *held + 1U;
  if (next == 0U)
  {
    next = 1U;
  }
  property.value = DataValue{Variant{next}, DateTime::now()};
  return VoidResult{};
}

std::optional<NodeId> DescribedConformanceNamespace::property_owner_locked(const Entry& property) const
{
  const NodeId hasProperty{ReferenceTypeId::HasProperty};
  for (const Reference& reference : *property.references)
  {
    if (!reference.is_forward() && reference.type_id() == hasProperty &&
        is_local_target(reference.target_id()) && mEntries.contains(reference.target_id().node_id()))
    {
      return reference.target_id().node_id();
    }
  }
  return std::nullopt;
}

// --- Values and Attributes ------------------------------------------------------------------------------

void DescribedConformanceNamespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  // The Values are this namespace's own, so every read is of the source, whatever maxAge allows.
  (void)request;
  (void)caller;
  (void)maxAge;
  BatchResult<DataValueResult> result;
  try
  {
    result.items.reserve(items.size());
    for (const ValueReadItem& item : items)
    {
      const NodeId& nodeId = item.value.node_id();
      if (auto checked = own(item.node, nodeId); checked.is_bad())
      {
        result.items.emplace_back(checked.status_code());
        continue;
      }
      std::optional<StatusCode> refused;
      DataValue value;
      {
        const std::lock_guard lock{mMutex};
        const auto found = mEntries.find(nodeId);
        if (found == mEntries.end())
        {
          refused = node_deleted(nodeId);
        }
        else if (found->second.description.node_class() != NodeClass::Variable)
        {
          // A VariableType's Value is a description Attribute; no other NodeClass has a Value.
          refused = failure(
            Status::BadAttributeIdInvalid, "NotAVariable", "Only a Variable's Value is read here", nodeId);
        }
        else if (found->second.value)
        {
          value = *found->second.value;
        }
      }
      if (refused)
      {
        result.items.emplace_back(std::move(*refused));
        continue;
      }
      if (!setSourceTimestamp)
      {
        value.source_timestamp().reset();
      }
      result.items.push_back(narrowed(std::move(value), item.value.index_range()));
    }
  }
  catch (...)
  {
    result = failed_batch<DataValueResult>(current_exception_status());
  }
  complete(std::move(result));
}

VoidResult DescribedConformanceNamespace::write_value_locked(
  Entry& entry, const WriteValue& write, bool serversOwn)
{
  // A merge changes the Value only: the written StatusCode and timestamps are kept (OPC 10000-4 5.10.4.2).
  const DataValue& written = write.value();
  DataValue stored = written;
  const Variant current = entry.value ? entry.value->value() : Variant{};
  if (!write.index_range().empty())
  {
    // OPC 10000-4 7.27: the written part replaces the range of the current Value.
    auto range = parse_numeric_range(write.index_range());
    if (range.is_bad())
    {
      return VoidResult{range.status_code()};
    }
    auto applied = index_range_utils::apply_write(current, written.value(), range.value());
    if (applied.is_bad())
    {
      return VoidResult{applied.status_code()};
    }
    stored.value() = std::move(applied).value();
  }
  else if (const auto* writtenSet = written.value().try_as<OptionSet>();
           writtenSet != nullptr && !writtenSet->valid_bits().empty())
  {
    // OPC 10000-3 8.40: only the bits ValidBits selects change.
    const auto* currentSet = current.try_as<OptionSet>();
    if (currentSet != nullptr)
    {
      auto bits = merge_option_set_value(*writtenSet, *currentSet);
      if (bits.is_bad())
      {
        return VoidResult{bits.status_code()};
      }
      auto merged = currentSet->clone();
      auto& mergedSet = static_cast<OptionSet&>(*merged);
      mergedSet.value() = std::move(bits).value();
      mergedSet.valid_bits().clear();
      stored.value() = Variant{std::move(merged)};
    }
    else if (!serversOwn)
    {
      return VoidResult{failure(Status::BadTypeMismatch,
        "OptionSetMergeCurrentNotOptionSet",
        "The Variable holds no OptionSet to merge the written ValidBits into",
        write.node_id())};
    }
    // The server's own OptionSet write to a Variable holding none, as when it gives the Variable its first
    // Value, is stored as given.
  }
  if (!stored.source_timestamp().has_value())
  {
    stored.source_timestamp() = DateTime::now();
  }
  entry.value = std::move(stored);
  return VoidResult{};
}

void DescribedConformanceNamespace::write_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  const bool serversOwn = caller == nullptr;

  // A Value write of a Property, kept for the semantic-change report once mMutex is released.
  struct PropertyWrite
  {
    std::size_t index;
    NodeId owner;
    NodeId ownerType;
    bool initial;
  };

  BatchResult<VoidResult> result;
  std::vector<VersionedNode> versioned;
  std::vector<NodeId> structureChanged;
  std::vector<PropertyWrite> propertyWrites;
  bool constantChanged = false;
  try
  {
    result.items.reserve(items.size());
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const ValueWriteItem& item = items[index];
      const NodeId& nodeId = item.value.node_id();
      if (auto checked = own(item.node, nodeId); checked.is_bad())
      {
        result.items.emplace_back(checked.status_code());
        continue;
      }
      const auto attributeId = static_cast<AttributeId>(item.value.attribute_id());
      const std::lock_guard lock{mMutex};
      const auto found = mEntries.find(nodeId);
      if (found == mEntries.end())
      {
        result.items.emplace_back(node_deleted(nodeId));
        continue;
      }
      Entry& entry = found->second;
      const NodeClass nodeClass = entry.description.node_class();

      if (attributeId == AttributeId::Value && nodeClass == NodeClass::Variable)
      {
        const bool initial = !entry.value.has_value();
        auto written = write_value_locked(entry, item.value, serversOwn);
        if (written.is_good())
        {
          // OPC 10000-3 8.58: a Value given after the first to a Variable whose AccessLevelEx has Constant
          // changes the namespace's configuration (NR-40).
          const auto levelEx = entry.description.access_level_ex();
          constantChanged =
            constantChanged || (!initial && levelEx && levelEx->test(AccessLevelExType::Bit::Constant));
          if (auto owner = property_owner_locked(entry))
          {
            propertyWrites.push_back(
              PropertyWrite{index, *owner, affected_type(mEntries.at(*owner)), initial});
          }
        }
        result.items.push_back(std::move(written));
        continue;
      }

      // Every other Attribute, a VariableType's Value included, is a description Attribute. The server's own
      // write of a VariableType's Value with a status or a timestamp is held as that DataValue.
      const DataValue& writtenValue = item.value.value();
      const bool wholeDataValue =
        attributeId == AttributeId::Value && serversOwn &&
        (writtenValue.status() || writtenValue.source_timestamp() || writtenValue.server_timestamp());
      const Variant value = wholeDataValue ? Variant{writtenValue} : writtenValue.value();
      auto updated = entry.description.try_with_attribute(attributeId, value);
      if (updated.is_bad())
      {
        result.items.emplace_back(updated.status_code());
        continue;
      }
      const bool changed = versioned_attribute(nodeClass, attributeId) &&
                           !same_attribute(entry.description, updated.value(), attributeId);
      const bool accessLevels =
        attributeId == AttributeId::AccessLevel || attributeId == AttributeId::AccessLevelEx;
      // The description keeps AccessLevel and AccessLevelEx one value; a write of either changes both.
      entry.description = std::move(updated).value();
      if (accessLevels)
      {
        // Both Attributes changed, so the held Node is given the description whole.
        if (mStore.held(nodeId, std::nullopt))
        {
          (void)mStore.node_for(entry.description);
        }
      }
      else if (mStore.record_write(nodeId, attributeId, value).is_bad())
      {
        // The held Node refused a value its description accepted: it is given the description whole.
        (void)mStore.node_for(entry.description);
      }
      VoidResult answer;
      if (changed)
      {
        if (attributeId == AttributeId::DataType && nodeClass == NodeClass::Variable)
        {
          structureChanged.push_back(nodeId);
        }
        if (Entry* property = version_property_locked(entry, nodeVersionName))
        {
          // The Attribute is written; a NodeVersion that cannot advance makes the answer Uncertain.
          auto advanced = advance_node_version_locked(*property);
          if (advanced.is_bad())
          {
            answer = VoidResult{StatusCode{Status::Uncertain, advanced.status_code().shared_detail()}};
          }
          else
          {
            versioned.push_back(VersionedNode{nodeId, affected_type(entry)});
          }
        }
      }
      result.items.push_back(std::move(answer));
    }
  }
  catch (...)
  {
    result = failed_batch<VoidResult>(current_exception_status());
    versioned.clear();
    structureChanged.clear();
    propertyWrites.clear();
    constantChanged = false;
  }

  // The registration's helper and the context are told with mMutex released.
  auto& monitoring = context().monitoring();
  for (const NodeId& variable : structureChanged)
  {
    monitoring.structure_changed(variable);
  }
  std::vector<SemanticChangeReport> semantics;
  for (const PropertyWrite& written : propertyWrites)
  {
    try
    {
      if (monitoring.property_value_changed(written.owner, items[written.index].node, written.initial))
      {
        semantics.push_back(SemanticChangeReport{written.owner, written.ownerType});
      }
    }
    catch (...)
    {
      // It throws only for a Property whose Attributes cannot be read, which a Node of DescribedNodes never
      // is. The Value is stored either way, so the item keeps its answer.
      continue;
    }
  }
  if (!semantics.empty())
  {
    context().semantics_changed(semantics);
  }
  if (constantChanged)
  {
    (void)context().constant_values_changed([](VoidResult) {});
  }
  complete(std::move(result), std::move(versioned));
}

// --- Calls ----------------------------------------------------------------------------------------------

void DescribedConformanceNamespace::call_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  (void)request;
  (void)caller;
  auto join = std::make_shared<Join<std::optional<CallResult>>>(items.size(), std::move(complete));
  for (std::size_t index = 0; index < items.size(); ++index)
  {
    const CallItem& item = items[index];
    const NodeId& methodId = item.request.method_id();
    std::optional<CallResult> immediate;
    std::shared_ptr<const MethodCallSource::CallHandler> handler;
    try
    {
      if (auto checked = own(item.method, methodId); checked.is_bad())
      {
        // A Method of this namespace that has been deleted is answered; any other Method is the namespace's
        // that returned it, so the call is declined.
        if (checked.status_code().as_status() == Status::BadNodeIdUnknown)
        {
          immediate = CallResult{checked.status_code()};
        }
      }
      else
      {
        const std::lock_guard lock{mMutex};
        const auto found = mEntries.find(methodId);
        if (found == mEntries.end())
        {
          immediate = CallResult{node_deleted(methodId)};
        }
        else
        {
          // A Method with no handler is declined, so that the Call service answers Bad_NotImplemented.
          handler = found->second.handler;
        }
      }
    }
    catch (...)
    {
      immediate = CallResult{current_exception_status()};
    }
    if (!handler)
    {
      join->answer(index, std::move(immediate));
      continue;
    }
    // The handler may answer after this returns, when the caller's item has ended: it is given a request of
    // its own.
    auto ownRequest = std::make_shared<const CallMethodRequest>(item.request);
    try
    {
      (*handler)(*ownRequest,
        item.context,
        [join, index, ownRequest](CallResult called)
        { join->answer(index, std::optional<CallResult>{std::move(called)}); });
    }
    catch (...)
    {
      join->answer(index, std::optional<CallResult>{CallResult{current_exception_status()}});
    }
  }
  join->started();
}

// --- Views ----------------------------------------------------------------------------------------------

void DescribedConformanceNamespace::view_contains_async(const RequestInfo& request, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  (void)request;
  BatchResult<BoolResult> result;
  try
  {
    result.items.reserve(nodes.size());
    const std::lock_guard lock{mMutex};
    const auto found = mEntries.find(view);
    std::optional<StatusCode> refused;
    if (found == mEntries.end())
    {
      refused = unknown_node(view);
    }
    else if (found->second.description.node_class() != NodeClass::View)
    {
      refused = failure(Status::BadNodeClassInvalid, "NotAView", "Membership is asked of a View", view);
    }
    for (const ExpandedNodeId& candidate : nodes)
    {
      if (refused)
      {
        result.items.emplace_back(*refused);
        continue;
      }
      // A candidate in another Server is never a member.
      result.items.emplace_back(
        is_local_target(candidate) && found->second.viewMembers.contains(candidate.node_id()));
    }
  }
  catch (...)
  {
    result = failed_batch<BoolResult>(current_exception_status());
  }
  complete(std::move(result));
}

void DescribedConformanceNamespace::add_to_view_async(const RequestInfo& request, const NodeId& view,
  std::span<const NodeId> nodes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  // The View gains members, not References, so its NodeVersion does not change and nothing is reported; its
  // ViewVersion advances once for the call (OPC 10000-3 5.4, Table 10).
  (void)request;
  BatchResult<VoidResult> result;
  try
  {
    result.items.reserve(nodes.size());
    const std::lock_guard lock{mMutex};
    const auto found = mEntries.find(view);
    std::optional<StatusCode> refused;
    if (found == mEntries.end())
    {
      refused = unknown_node(view);
    }
    else if (found->second.description.node_class() != NodeClass::View)
    {
      refused = failure(Status::BadNodeClassInvalid, "NotAView", "Members are added to a View", view);
    }
    if (refused)
    {
      for (std::size_t i = 0; i < nodes.size(); ++i)
      {
        result.items.emplace_back(*refused);
      }
    }
    else
    {
      Entry& entry = found->second;
      std::vector<std::size_t> inserted;
      for (std::size_t i = 0; i < nodes.size(); ++i)
      {
        if (entry.viewMembers.insert(nodes[i]).second)
        {
          inserted.push_back(i);
        }
        result.items.emplace_back();
      }
      Entry* property = inserted.empty() ? nullptr : version_property_locked(entry, viewVersionName);
      if (property != nullptr)
      {
        // A ViewVersion that cannot advance takes the members back out and is the answer of each.
        auto advanced = advance_view_version_locked(*property);
        if (advanced.is_bad())
        {
          for (const std::size_t i : inserted)
          {
            entry.viewMembers.erase(nodes[i]);
            result.items[i] = advanced;
          }
        }
      }
    }
  }
  catch (...)
  {
    result = failed_batch<VoidResult>(current_exception_status());
  }
  complete(std::move(result), std::vector<VersionedNode>{});
}

// --- Creation and deletion ------------------------------------------------------------------------------

void DescribedConformanceNamespace::create_nodes_async(const RequestInfo& request,
  std::span<const NodeCreation> nodes, std::function<void(BatchResult<NodeResult>)> complete)
{
  // A Node is created with the description its Attributes build, in one step; the factory defaults are this
  // namespace's defaults.
  (void)request;
  BatchResult<NodeResult> result;
  try
  {
    result.items.reserve(nodes.size());
    for (const NodeCreation& creation : nodes)
    {
      if (creation.nodeId.namespace_index() != context().index())
      {
        result.items.emplace_back(failure(Status::BadInvalidArgument,
          "NodeIdOfAnotherNamespace",
          "A Node is created in the namespace its NodeId names",
          creation.nodeId));
        continue;
      }
      auto built =
        NodeDescription::try_from_attributes(creation.nodeId, creation.nodeClass, creation.attributes);
      if (built.is_bad())
      {
        result.items.emplace_back(built.status_code());
        continue;
      }
      NodeDescription description = std::move(built).value();
      const std::lock_guard lock{mMutex};
      const auto [entry, inserted] = mEntries.try_emplace(creation.nodeId, std::move(description));
      if (!inserted)
      {
        result.items.emplace_back(failure(Status::BadNodeIdExists,
          "NodeIdExists",
          "This namespace holds a Node for the NodeId",
          creation.nodeId));
        continue;
      }
      result.items.emplace_back(mStore.node_for(entry->second.description));
    }
  }
  catch (...)
  {
    result = failed_batch<NodeResult>(current_exception_status());
  }
  complete(std::move(result));
}

void DescribedConformanceNamespace::delete_nodes_async(const RequestInfo& request,
  std::span<const NodeId> nodes, ReferenceHalves halves,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  (void)request;
  BatchResult<DeleteNodeResult> result;
  std::vector<VersionedNode> versioned;
  try
  {
    result.items.reserve(nodes.size());
    const std::lock_guard lock{mMutex};
    std::unordered_set<NodeId> deleted;
    for (const NodeId& nodeId : nodes)
    {
      const auto found = mEntries.find(nodeId);
      if (found == mEntries.end())
      {
        result.items.emplace_back(unknown_node(nodeId));
        continue;
      }
      const Entry& entry = found->second;
      // A deleted Node that was versioned is reported with the TypeDefinition it had.
      if (version_property_locked(entry, nodeVersionName) != nullptr)
      {
        versioned.push_back(VersionedNode{nodeId, affected_type(entry)});
      }
      // The other half of a Reference to a Node of another namespace is that namespace's: the address space
      // removes it there.
      std::vector<ExternalReference> external;
      for (const Reference& reference : *entry.references)
      {
        const ExpandedNodeId& target = reference.target_id();
        if (is_local_target(target) && target.node_id().namespace_index() != context().index())
        {
          external.push_back(ExternalReference{reference.type_id(), target, reference.is_forward()});
        }
      }
      mEntries.erase(found);
      // Every holder of the Node sees it deleted before the delete completes.
      mStore.remove(nodeId);
      deleted.insert(nodeId);
      result.items.emplace_back(std::move(external));
    }

    // The Views lose their deleted members, and with Both the Nodes left lose their References to a deleted
    // Node; with ThisHalfOnly those are left unresolved.
    std::vector<NodeId> lostReference;
    std::vector<NodeId> lostMember;
    const auto targetsDeleted = [&deleted](const Reference& reference)
    {
      return is_local_target(reference.target_id()) && deleted.contains(reference.target_id().node_id());
    };
    for (auto& [nodeId, entry] : mEntries)
    {
      if (halves == ReferenceHalves::Both && std::ranges::any_of(*entry.references, targetsDeleted))
      {
        std::vector<Reference> kept(entry.references->begin(), entry.references->end());
        std::erase_if(kept, targetsDeleted);
        entry.references = std::make_shared<const std::vector<Reference>>(std::move(kept));
        lostReference.push_back(nodeId);
      }
      if (std::erase_if(
            entry.viewMembers, [&deleted](const NodeId& member) { return deleted.contains(member); }) > 0)
      {
        lostMember.push_back(nodeId);
      }
    }
    // A versioned Node that lost a Reference advances its NodeVersion and is reported; a View that lost a
    // member advances its ViewVersion and is not. A version that cannot advance does not fail the delete.
    for (const NodeId& survivor : lostReference)
    {
      Entry& entry = mEntries.at(survivor);
      Entry* property = version_property_locked(entry, nodeVersionName);
      if (property != nullptr && advance_node_version_locked(*property).is_good())
      {
        versioned.push_back(VersionedNode{survivor, affected_type(entry)});
      }
    }
    for (const NodeId& view : lostMember)
    {
      if (Entry* property = version_property_locked(mEntries.at(view), viewVersionName))
      {
        (void)advance_view_version_locked(*property);
      }
    }
  }
  catch (...)
  {
    result = failed_batch<DeleteNodeResult>(current_exception_status());
    versioned.clear();
  }
  complete(std::move(result), std::move(versioned));
}

// --- Monitoring -----------------------------------------------------------------------------------------

void DescribedConformanceNamespace::create_monitoring_async(const RequestInfo& request,
  const CallerInfo* caller, std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> complete)
{
  // Each item goes to the registration's helper with the Node this namespace hands out for it, and is
  // sampled: the helper reads a Variable's Value through read_values_async and any other Attribute from the
  // Node's description. An item that carries a Node is checked; one that carries none is looked up.
  (void)request;
  (void)caller;
  using Support = default_ns::NamespaceMonitoringSupport;
  BatchResult<MonitoringCreateItemResult> result;
  try
  {
    std::vector<std::optional<MonitoringCreateItemResult>> answers(items.size());
    std::vector<Support::ResolvedMonitoringItem> resolved;
    std::vector<std::size_t> resolvedAt;
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const MonitoringCreateItem& item = items[index];
      Support::ResolvedMonitoringItem entry;
      entry.item = item;
      entry.delivery = Support::Delivery::Sampled;
      if (item.node)
      {
        if (auto checked = own(*item.node, item.nodeId); checked.is_bad())
        {
          answers[index].emplace(checked.status_code());
          continue;
        }
      }
      else
      {
        NodeResult found = [this, &item]
        {
          const std::lock_guard lock{mMutex};
          return resolve_locked(item.nodeId);
        }();
        if (found.is_bad())
        {
          answers[index].emplace(found.status_code());
          continue;
        }
        entry.item.node = std::move(found).value();
      }
      resolved.push_back(std::move(entry));
      resolvedAt.push_back(index);
    }
    auto created = context().monitoring().create_monitoring(resolved);
    for (std::size_t i = 0; i < resolvedAt.size(); ++i)
    {
      answers[resolvedAt[i]].emplace(i < created.size()
                                       ? std::move(created[i].result)
                                       : MonitoringCreateItemResult{StatusCode{Status::BadInternalError}});
    }
    result.items.reserve(answers.size());
    for (auto& answer : answers)
    {
      result.items.push_back(std::move(*answer));
    }
  }
  catch (...)
  {
    result = failed_batch<MonitoringCreateItemResult>(current_exception_status());
  }
  complete(std::move(result));
}

}  // namespace ua::test
