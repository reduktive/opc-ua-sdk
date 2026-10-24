// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_UNIT_ADDRESS_SPACE_SCRIPTED_NODE_H
#define UA_TESTS_UNIT_ADDRESS_SPACE_SCRIPTED_NODE_H

/// @file
/// @brief A `Node` whose Attributes and operations a test scripts, and a namespace that answers each item of
///        its batched members from the script of the item's Node.

#include "per_item_join.h"

#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_role_permission_type.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ua::test
{

/// A Node whose Attributes are the ones a test scripts, and whose operations - References, its Value, writes,
/// Method calls - are scripts a namespace reads (@ref ScriptedNamespace answers each item from them).
///
/// **Attributes.** `attributes()` builds the description with `NodeDescription::try_from_attributes` from
/// every scripted Attribute, NodeId and NodeClass included. A description is read whole, so a refused
/// Attribute (@ref refuse_attribute) refuses every reader: `attributes()` throws the refusal, the first in
/// AttributeId order. A scripted value `try_from_attributes` refuses - a value of the wrong type, an
/// Attribute the NodeClass does not have (a Variable's Value or a Session-derived Attribute among them), a
/// missing or invalid NodeClass - is not dropped: `attributes()` throws the status `try_from_attributes`
/// answered, with its ErrorDetail naming the Attribute. A Node without a scripted NodeId is described with
/// the null NodeId.
class ScriptedNode : public Node
{
public:
  /// One scripted Attribute: a value, or a refusal thrown as `UaException`.
  struct AttributeAnswer
  {
    Variant value;
    std::optional<StatusCode> refusal;
  };

  /// Sets the value of @p attributeId in the description `attributes()` answers.
  void answer_attribute(AttributeId attributeId, Variant value)
  {
    const std::lock_guard lock{mMutex};
    mAttributes[attributeId] = AttributeAnswer{std::move(value), std::nullopt};
  }

  /// Makes `attributes()` throw @p status (see the class documentation).
  void refuse_attribute(AttributeId attributeId, StatusCode status)
  {
    const std::lock_guard lock{mMutex};
    mAttributes[attributeId] = AttributeAnswer{Variant{}, std::move(status)};
  }

  /// Makes `attributes()` answer the next @p reads reads and throw @p status on every read after them: a Node
  /// whose description can be read once and then no longer.
  void refuse_attributes_after(std::size_t reads, StatusCode status)
  {
    const std::lock_guard lock{mMutex};
    mReadsBeforeRefusal = reads;
    mLaterRefusal = std::move(status);
  }

  /// Sets the References @ref references answers.
  void answer_references(std::vector<Reference> references)
  {
    const std::lock_guard lock{mMutex};
    mReferences = std::move(references);
  }

  /// Sets what @ref read_value answers, whatever IndexRange the read names.
  void answer_read_value(DataValueResult answer)
  {
    const std::lock_guard lock{mMutex};
    mReadValue = std::move(answer);
  }

  /// Sets what @ref write_attribute answers.
  void answer_write_attribute(VoidResult answer)
  {
    const std::lock_guard lock{mMutex};
    mWriteAttribute = std::move(answer);
  }

  /// Sets the handler @ref call runs.
  void answer_calls(std::function<CallResult(const CallMethodRequest&)> handler)
  {
    const std::lock_guard lock{mMutex};
    mCallHandler = std::move(handler);
  }

  /// Makes @ref write_value keep its completion until @ref complete_parked_value_write.
  void park_value_writes()
  {
    const std::lock_guard lock{mMutex};
    mParkValueWrites = true;
  }

  /// Makes `deleted()` answer true from now on.
  void mark_deleted() noexcept
  {
    mDeleted.store(true);
  }

  /// The values @ref write_value received, copied when it was called.
  std::vector<Variant> received_value_writes() const
  {
    const std::lock_guard lock{mMutex};
    return mReceivedValueWrites;
  }

  /// How many @ref call invocations ran.
  size_t calls() const
  {
    const std::lock_guard lock{mMutex};
    return mCalls;
  }

  /// Runs the parked completion of @ref write_value with @p result.
  /// @return false when none is parked.
  bool complete_parked_value_write(VoidResult result)
  {
    std::function<void(VoidResult)> parked;
    {
      const std::lock_guard lock{mMutex};
      if (!mParkedValueWrite)
      {
        return false;
      }
      parked = std::move(mParkedValueWrite);
      mParkedValueWrite = nullptr;
    }
    parked(std::move(result));
    return true;
  }

  NodeDescription attributes() const override
  {
    std::map<AttributeId, AttributeAnswer> scripted;
    {
      const std::lock_guard lock{mMutex};
      if (mLaterRefusal)
      {
        if (mReadsBeforeRefusal == 0)
        {
          throw UaException{*mLaterRefusal};
        }
        --mReadsBeforeRefusal;
      }
      scripted = mAttributes;
    }
    for (const auto& entry : scripted)
    {
      if (entry.second.refusal)
      {
        throw UaException{*entry.second.refusal};
      }
    }
    NodeId nodeId;
    NodeClass nodeClass{NodeClass::Unspecified};
    InitialAttributes given;
    given.reserve(scripted.size());
    for (const auto& [attributeId, answer] : scripted)
    {
      if (attributeId == AttributeId::NodeId && answer.value.is_node_id())
      {
        nodeId = answer.value.as<NodeId>();
      }
      if (attributeId == AttributeId::NodeClass && answer.value.is_int32())
      {
        nodeClass = static_cast<NodeClass>(answer.value.as<int32_t>());
      }
      given.emplace_back(attributeId, answer.value);
    }
    // value() throws the refusal, with its ErrorDetail, when try_from_attributes refuses the script.
    return NodeDescription::try_from_attributes(nodeId, nodeClass, given).value();
  }

  bool deleted() const noexcept override
  {
    return mDeleted.load();
  }

  // --- The scripts a namespace reads ------------------------------------------------------------------

  /// The scripted References, in the order given.
  std::vector<Reference> references() const
  {
    const std::lock_guard lock{mMutex};
    return mReferences;
  }

  /// The scripted Value answer; `Bad_InternalError` until one is scripted.
  DataValueResult read_value() const
  {
    const std::lock_guard lock{mMutex};
    return mReadValue;
  }

  /// The scripted answer to a write of a non-Value Attribute. A Good answer applies @p value to the scripted
  /// Attributes before it returns, so that `attributes()` reads the written value.
  VoidResult write_attribute(AttributeId attributeId, const Variant& value) const
  {
    const std::lock_guard lock{mMutex};
    if (mWriteAttribute.is_good())
    {
      mAttributes[attributeId] = AttributeAnswer{value, std::nullopt};
    }
    return mWriteAttribute;
  }

  /// Records the Value @p nodeToWrite carries and answers Good, or parks @p complete while
  /// @ref park_value_writes is in force.
  void write_value(const WriteValue& nodeToWrite, std::function<void(VoidResult)> complete) const
  {
    {
      const std::lock_guard lock{mMutex};
      mReceivedValueWrites.push_back(nodeToWrite.value().value());
      if (mParkValueWrites)
      {
        mParkedValueWrite = std::move(complete);
        return;
      }
    }
    complete(VoidResult{});
  }

  /// Counts the call and runs the scripted handler; `Bad_NotImplemented` when none is scripted.
  CallResult call(const CallMethodRequest& methodToCall) const
  {
    std::function<CallResult(const CallMethodRequest&)> handler;
    {
      const std::lock_guard lock{mMutex};
      ++mCalls;
      handler = mCallHandler;
    }
    return handler ? handler(methodToCall) : CallResult{StatusCode{Status::BadNotImplemented}};
  }

private:
  mutable std::mutex mMutex;
  mutable std::map<AttributeId, AttributeAnswer> mAttributes;
  // Set by refuse_attributes_after: the reads attributes() still answers, then the refusal it throws.
  mutable std::size_t mReadsBeforeRefusal{0};
  std::optional<StatusCode> mLaterRefusal;
  std::vector<Reference> mReferences;
  DataValueResult mReadValue{StatusCode{Status::BadInternalError}};
  VoidResult mWriteAttribute;
  std::function<CallResult(const CallMethodRequest&)> mCallHandler;
  bool mParkValueWrites{false};
  mutable std::function<void(VoidResult)> mParkedValueWrite;
  mutable std::vector<Variant> mReceivedValueWrites;
  mutable size_t mCalls{0};
  std::atomic<bool> mDeleted{false};
};

/// A namespace that holds the Nodes a test gives it by NodeId and answers each item of its batched members
/// from the script of the item's Node:
///
/// - `find_nodes_async` and `find_node(id, maxAge)` answer the Node held for each NodeId, or
///   `Bad_NodeIdUnknown`; `find_node` never declines.
/// - `read_references_async` answers the Node's scripted References, paged by each query's maxReferences with
///   a resume token naming the offset; the direction and the hint are not applied.
/// - `read_values_async` answers the Node's scripted Value.
/// - `write_async` sends a write of the Value to `ScriptedNode::write_value` and any other write to
///   `ScriptedNode::write_attribute`, and reports no versioned Node.
/// - `call_async` answers through the Method Node's script and declines an item whose Method is not a
///   ScriptedNode.
///
/// An item whose Node is not a ScriptedNode fails with `Bad_InvalidArgument` (ErrorDetail
/// `NotAScriptedNode`). Every other member keeps the `Namespace` default: View membership is read from the
/// View Node's scripted References, and Reference changes, View additions, creation and deletion are
/// `Bad_NotSupported`. A test namespace derives from this one to change one member.
class ScriptedNamespace : public Namespace
{
public:
  explicit ScriptedNamespace(String uri = String{"urn:test:scripted"}) : mUri(std::move(uri))
  {}

  using Namespace::find_node;

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});  // nothing armed
    }
  }

  /// Holds @p node, answering lookups of @p nodeId. A Node held earlier under @p nodeId is replaced.
  void hold(const NodeId& nodeId, shared_ptr<Node> node)
  {
    const std::lock_guard lock{mMutex};
    mNodes[nodeId] = std::move(node);
  }

  /// The DefaultRolePermissions this namespace answers; engaged and empty until set.
  void set_default_role_permissions(std::optional<std::vector<RolePermissionType>> permissions)
  {
    const std::lock_guard lock{mMutex};
    mDefaultRolePermissions = std::move(permissions);
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    const std::lock_guard lock{mMutex};
    return mDefaultRolePermissions;
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    resolve_each(nodeIds,
      std::move(complete),
      [this](const NodeId& nodeId, std::function<void(NodeResult)> one) { one(held(nodeId)); });
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration>) override
  {
    return held(nodeId);
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    answer.items.reserve(queries.size());
    for (const auto& query : queries)
    {
      const auto* scripted = dynamic_cast<const ScriptedNode*>(&query.node);
      if (scripted == nullptr)
      {
        answer.items.emplace_back(not_scripted());
        continue;
      }
      const std::vector<Reference> all = scripted->references();
      const auto offset = page_offset(query.resumeToken);
      if (!offset.has_value() || *offset > all.size())
      {
        answer.items.emplace_back(StatusCode{Status::BadContinuationPointInvalid});
        continue;
      }
      const std::size_t end =
        query.maxReferences == 0 ? all.size() : std::min(all.size(), *offset + query.maxReferences);
      std::vector<Reference> page(
        all.begin() + static_cast<std::ptrdiff_t>(*offset), all.begin() + static_cast<std::ptrdiff_t>(end));
      answer.items.emplace_back(
        NodeReferences{References{std::move(page)}, end < all.size() ? page_token(end) : ByteString{}});
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    answer.items.reserve(items.size());
    for (const auto& item : items)
    {
      const auto* scripted = dynamic_cast<const ScriptedNode*>(&item.node);
      answer.items.push_back(scripted != nullptr ? scripted->read_value() : DataValueResult{not_scripted()});
    }
    complete(std::move(answer));
  }

  void write_async(const RequestInfo&, const CallerInfo*, std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    auto join = std::make_shared<PerItemJoin<VoidResult>>(items.size(),
      [complete = std::move(complete)](BatchResult<VoidResult> written)
      { complete(std::move(written), std::vector<VersionedNode>{}); });
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const ValueWriteItem& item = items[index];
      const auto* scripted = dynamic_cast<const ScriptedNode*>(&item.node);
      if (scripted == nullptr)
      {
        join->answer(index, VoidResult{not_scripted()});
        continue;
      }
      const auto attributeId = static_cast<AttributeId>(item.value.attribute_id());
      if (attributeId == AttributeId::Value)
      {
        scripted->write_value(
          item.value, [join, index](VoidResult written) { join->answer(index, std::move(written)); });
        continue;
      }
      join->answer(index, scripted->write_attribute(attributeId, item.value.value().value()));
    }
    join->started();
  }

  void call_async(const RequestInfo&, const CallerInfo*, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    BatchResult<std::optional<CallResult>> answer;
    answer.items.reserve(items.size());
    for (const auto& item : items)
    {
      const auto* method = dynamic_cast<const ScriptedNode*>(&item.method);
      if (method == nullptr)
      {
        answer.items.emplace_back(std::nullopt);
        continue;
      }
      answer.items.emplace_back(method->call(item.request));
    }
    complete(std::move(answer));
  }

protected:
  /// The Node held for @p nodeId, or `Bad_NodeIdUnknown`.
  NodeResult held(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mMutex};
    if (const auto found = mNodes.find(nodeId); found != mNodes.end())
    {
      return NodeResult{found->second};
    }
    return NodeResult{StatusCode{Status::BadNodeIdUnknown}};
  }

  /// The failure of an item whose Node is not a ScriptedNode.
  static StatusCode not_scripted()
  {
    return StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("NotAScriptedNode", "The item's Node is not a ScriptedNode", "ScriptedNamespace")};
  }

private:
  static ByteString page_token(std::size_t offset)
  {
    const std::string text = std::to_string(offset);
    return ByteString{std::vector<uint8_t>(text.begin(), text.end())};
  }

  /// The offset @p token names: 0 for no token, nullopt for a token this namespace did not issue.
  static std::optional<std::size_t> page_offset(const ByteString& token)
  {
    if (token.empty())
    {
      return std::size_t{0};
    }
    const std::string text{reinterpret_cast<const char*>(token.data()), token.size()};
    std::size_t offset = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), offset);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    {
      return std::nullopt;
    }
    return offset;
  }

  String mUri;
  mutable std::mutex mMutex;
  std::map<NodeId, shared_ptr<Node>> mNodes;
  std::optional<std::vector<RolePermissionType>> mDefaultRolePermissions{std::vector<RolePermissionType>{}};
};

}  // namespace ua::test

#endif  // UA_TESTS_UNIT_ADDRESS_SPACE_SCRIPTED_NODE_H
