// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "posting_writes_namespace.h"

#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_write_value.h"

#include <boost/asio/post.hpp>

#include <utility>

namespace ua::test
{

namespace
{

/// A node of a namespace that refuses call handlers or value sources: serves the real node's Attributes and
/// deletion, and hides the probe the namespace refuses, so installing a handler or a source answers
/// Bad_NotSupported. The namespace's batched members unwrap it, since the in-memory members accept only their
/// own nodes.
class HiddenProbesNode final : public Node, public ExternalValueSource
{
public:
  HiddenProbesNode(shared_ptr<Node> inner, bool hideCallSource, bool hideValueSource,
    std::optional<StatusCode> valueSourceRefusal)
    : mInner(std::move(inner)), mHideCallSource(hideCallSource), mHideValueSource(hideValueSource),
      mValueSourceRefusal(std::move(valueSourceRefusal))
  {}

  const Node& inner() const
  {
    return *mInner;
  }

  NodeDescription attributes() const override
  {
    return mInner->attributes();
  }

  bool deleted() const noexcept override
  {
    return mInner->deleted();
  }

  ExternalValueSource* external_value_source() noexcept override
  {
    if (mHideValueSource)
    {
      if (mValueSourceRefusal.has_value())
        return this;
      return nullptr;
    }
    return mInner->external_value_source();
  }

  VoidResult set_value_source(std::shared_ptr<ValueSource> source) override
  {
    if (mValueSourceRefusal.has_value())
      return VoidResult{*mValueSourceRefusal};
    if (auto* inner = mInner->external_value_source())
      return inner->set_value_source(std::move(source));
    return VoidResult{StatusCode{Status::BadNotSupported}};
  }

  void notify_value_changed(DataValue value) override
  {
    if (auto* inner = mInner->external_value_source())
      inner->notify_value_changed(std::move(value));
  }

  MethodCallSource* method_call_source() noexcept override
  {
    return mHideCallSource ? nullptr : mInner->method_call_source();
  }

private:
  shared_ptr<Node> mInner;
  bool mHideCallSource;
  bool mHideValueSource;
  std::optional<StatusCode> mValueSourceRefusal;
};

/// @p node behind a node hiding the probes a namespace refuses, or @p node itself.
shared_ptr<Node> handed_out(shared_ptr<Node> node, bool acceptsCallHandlers, bool acceptsValueSources,
  std::optional<StatusCode> valueSourceRefusal)
{
  if (node == nullptr)
  {
    return node;
  }
  const auto nodeClass = node->attributes().node_class();
  const bool hideCallSource = !acceptsCallHandlers && nodeClass == NodeClass::Method;
  const bool hideValueSource = !acceptsValueSources && nodeClass == NodeClass::Variable;
  if (!hideCallSource && !hideValueSource)
  {
    return node;
  }
  return std::make_shared<HiddenProbesNode>(
    std::move(node), hideCallSource, hideValueSource, std::move(valueSourceRefusal));
}

/// The real node behind @p node: the wrapped node of a refusing namespace, or @p node itself.
const Node& unwrapped(const Node& node)
{
  if (const auto* wrapper = dynamic_cast<const HiddenProbesNode*>(&node))
  {
    return wrapper->inner();
  }
  return node;
}

/// Whether a write of @p attributeId to @p node is a Variable's Value, which is answered inline; every other
/// write is answered by a post. A node whose Attributes cannot be read is not a Variable.
bool variable_value(const Node& node, AttributeId attributeId)
{
  if (attributeId != AttributeId::Value)
  {
    return false;
  }
  try
  {
    return node.attributes().node_class() == NodeClass::Variable;
  }
  catch (...)
  {
    return false;
  }
}

}  // namespace

void PostingWritesNamespace::WriteLog::record(AttributeId attributeId)
{
  const std::lock_guard lock(mutex);
  ++counts[attributeId];
}

std::size_t PostingWritesNamespace::WriteLog::count(AttributeId attributeId) const
{
  const std::lock_guard lock(mutex);
  const auto found = counts.find(attributeId);
  return found == counts.end() ? 0 : found->second;
}

std::optional<StatusCode> PostingWritesNamespace::WriteLog::good_answer_for(const NodeId& nodeId) const
{
  const std::lock_guard lock(mutex);
  for (const auto& [answeredNode, status] : goodAnswers)
  {
    if (answeredNode == nodeId)
    {
      return status;
    }
  }
  return std::nullopt;
}

void PostingWritesNamespace::answer_good_writes_with(const NodeId& nodeId, StatusCode status)
{
  const std::lock_guard lock(mWriteLog->mutex);
  mWriteLog->goodAnswers.emplace_back(nodeId, status);
}

std::shared_ptr<PostingWritesNamespace> PostingWritesNamespace::create(string_view uri,
  boost::asio::any_io_executor executor, CallHandlers callHandlers, ValueSources valueSources,
  std::optional<StatusCode> valueSourceRefusal)
{
  return std::shared_ptr<PostingWritesNamespace>(new PostingWritesNamespace(
    uri, std::move(executor), callHandlers, valueSources, std::move(valueSourceRefusal)));
}

PostingWritesNamespace::PostingWritesNamespace(string_view uri, boost::asio::any_io_executor executor,
  CallHandlers callHandlers, ValueSources valueSources, std::optional<StatusCode> valueSourceRefusal)
  : default_ns::Namespace(uri, executor), mAnswerExecutor(std::move(executor)),
    mAcceptsCallHandlers(callHandlers == CallHandlers::Accepted),
    mAcceptsValueSources(valueSources == ValueSources::Accepted),
    mValueSourceRefusal(std::move(valueSourceRefusal))
{}

std::size_t PostingWritesNamespace::posted_writes(AttributeId attributeId) const
{
  return mWriteLog->count(attributeId);
}

void PostingWritesNamespace::create_nodes_async(const RequestInfo& request,
  std::span<const NodeCreation> nodes, std::function<void(BatchResult<NodeResult>)> complete)
{
  if (mAcceptsCallHandlers && mAcceptsValueSources)
  {
    default_ns::Namespace::create_nodes_async(request, nodes, std::move(complete));
    return;
  }
  default_ns::Namespace::create_nodes_async(request,
    nodes,
    [callHandlers = mAcceptsCallHandlers,
      valueSources = mAcceptsValueSources,
      valueSourceRefusal = mValueSourceRefusal,
      complete = std::move(complete)](BatchResult<NodeResult> created) mutable
    {
      for (auto& item : created.items)
      {
        if (item.is_good())
        {
          item =
            NodeResult{handed_out(std::move(item).value(), callHandlers, valueSources, valueSourceRefusal)};
        }
      }
      complete(std::move(created));
    });
}

void PostingWritesNamespace::write_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  // A write other than a Variable's Value records its Attribute and is answered by a post; a Good answer of
  // any write is replaced by the status set for its node.
  struct Answering
  {
    std::vector<AttributeId> attributes;
    std::vector<NodeId> nodeIds;
    std::vector<bool> posted;
  };

  auto answering = std::make_shared<Answering>();
  std::vector<ValueWriteItem> real;
  real.reserve(items.size());
  for (const auto& item : items)
  {
    const Node& node = unwrapped(item.node);
    const auto attributeId = static_cast<AttributeId>(item.value.attribute_id());
    real.push_back(ValueWriteItem{node, item.value});
    answering->attributes.push_back(attributeId);
    answering->nodeIds.push_back(item.value.node_id());
    answering->posted.push_back(!variable_value(node, attributeId));
  }
  default_ns::Namespace::write_async(request,
    caller,
    real,
    [writeLog = mWriteLog, executor = mAnswerExecutor, answering, complete = std::move(complete)](
      BatchResult<VoidResult> written, std::vector<VersionedNode> versioned) mutable
    {
      bool post = false;
      for (std::size_t index = 0; index < written.items.size() && index < answering->posted.size(); ++index)
      {
        if (answering->posted[index])
        {
          writeLog->record(answering->attributes[index]);
          post = true;
        }
        if (const auto answer = writeLog->good_answer_for(answering->nodeIds[index]);
            answer.has_value() && written.items[index].is_good())
        {
          written.items[index] = VoidResult{*answer};
        }
      }
      if (!post)
      {
        complete(std::move(written), std::move(versioned));
        return;
      }
      boost::asio::post(executor,
        [complete = std::move(complete),
          written = std::move(written),
          versioned = std::move(versioned)]() mutable
        { complete(std::move(written), std::move(versioned)); });
    });
}

void PostingWritesNamespace::read_references_async(const RequestInfo& request,
  std::span<const ReferenceQuery> queries, std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  std::vector<ReferenceQuery> real;
  real.reserve(queries.size());
  for (const auto& query : queries)
  {
    real.push_back(ReferenceQuery{unwrapped(query.node),
      query.nodeId,
      query.direction,
      query.referenceTypeHint,
      query.maxReferences,
      query.resumeToken});
  }
  default_ns::Namespace::read_references_async(request, real, std::move(complete));
}

void PostingWritesNamespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  std::vector<ValueReadItem> real;
  real.reserve(items.size());
  for (const auto& item : items)
  {
    real.push_back(ValueReadItem{unwrapped(item.node), item.value});
  }
  default_ns::Namespace::read_values_async(
    request, caller, real, maxAge, setSourceTimestamp, std::move(complete));
}

void PostingWritesNamespace::call_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  std::vector<CallItem> real;
  real.reserve(items.size());
  for (const auto& item : items)
  {
    real.push_back(CallItem{unwrapped(item.object), unwrapped(item.method), item.request, item.context});
  }
  default_ns::Namespace::call_async(request, caller, real, std::move(complete));
}

NodeResult PostingWritesNamespace::resolve_here(const NodeId& nodeId)
{
  auto resolved = default_ns::Namespace::resolve_here(nodeId);
  if ((mAcceptsCallHandlers && mAcceptsValueSources) || resolved.is_bad())
  {
    return resolved;
  }
  return NodeResult{
    handed_out(std::move(resolved).value(), mAcceptsCallHandlers, mAcceptsValueSources, mValueSourceRefusal)};
}

}  // namespace ua::test
