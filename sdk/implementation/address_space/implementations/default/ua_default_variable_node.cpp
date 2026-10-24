// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_variable_node.h"
#include "ua_default_namespace.h"
#include "ua_namespace_batch_support.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_node_accessor.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_write_value.h"

#include <boost/container/small_vector.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>

namespace ua::default_ns
{

namespace
{

/// The answer of a one-item source call: its item, or the batch's failure.
template<typename T>
T first_answer(BatchResult<T> answered)
{
  if (answered.batchStatus.is_bad())
  {
    return T{answered.batchStatus.status_code(), answered.batchStatus.shared_detail()};
  }
  if (answered.items.size() != 1)
  {
    return T{StatusCode{Status::BadInternalError,
      make_error_detail("ValueSourceAnswerSize",
        "The value source answered another number of items than it was given",
        "VariableNode")}};
  }
  return std::move(answered.items.front());
}

/// A CallerInfo for an identity the caller holds for the length of the call: the pointer is not owned.
CallerInfo caller_of(const AccessIdentity* identity)
{
  CallerInfo caller;
  caller.identity = shared_ptr<const AccessIdentity>(shared_ptr<const AccessIdentity>{}, identity);
  return caller;
}

}  // namespace

VariableNode::VariableNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::Variable)
{}

shared_ptr<VariableNode> VariableNode::create(const NodeId& nodeId)
{
  struct Wrapper : public VariableNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : VariableNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool VariableNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::Value:
  case AttributeId::DataType:
  case AttributeId::ValueRank:
  case AttributeId::ArrayDimensions:
  case AttributeId::AccessLevel:
  case AttributeId::MinimumSamplingInterval:
  case AttributeId::Historizing:
  case AttributeId::AccessLevelEx:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

std::shared_ptr<DefaultValueSource> VariableNode::default_source_for_write_locked()
{
  if (!mSource)
  {
    // The install rule (COMP-DEFAULT-NODE-ATTR-STORAGE-03): a write to a Variable with no source gives it its
    // default source, which then holds the Value.
    auto installed = std::make_shared<DefaultValueSource>();
    mDefaultSource = installed.get();
    mSource = std::move(installed);
  }
  if (mDefaultSource == nullptr)
  {
    return nullptr;
  }
  return std::shared_ptr<DefaultValueSource>(mSource, mDefaultSource);
}

std::shared_ptr<DefaultValueSource> VariableNode::default_source_for_write()
{
  const WriteLock lock(mMutex);
  return default_source_for_write_locked();
}

std::shared_ptr<DefaultValueSource> VariableNode::default_source() const
{
  const ReadLock lock(mMutex);
  if (mDefaultSource == nullptr)
  {
    return nullptr;
  }
  return std::shared_ptr<DefaultValueSource>(mSource, mDefaultSource);
}

DataValue VariableNode::read_default_source(Duration maxAge, bool setSourceTimestamp) const
{
  // OPC 10000-3 5.6.2: Value is a mandatory attribute of every Variable. A Variable never written has no
  // source yet and still has a (null) Value, answered Good.
  if (auto source = default_source())
  {
    return source->read(maxAge, setSourceTimestamp);
  }
  return DataValue{};
}

void VariableNode::read_value(Duration maxAge, bool setSourceTimestamp, const ReadValueId& nodeToRead,
  const AccessIdentity* identity, ReadValueCompleteCallback callback) const
{
  // This member answers the Value whole, as it always has: its callers narrow it to the IndexRange. maxAge
  // belongs to the source, which alone knows what it considers current (Part 4 5.10.2.2), and is passed
  // through.
  auto source = application_source();
  if (!source)
  {
    DataValueResult read{DataValue{}};
    try
    {
      read = DataValueResult{read_default_source(maxAge, setSourceTimestamp)};
    }
    catch (...)
    {
      read = DataValueResult{ua::exception_to_status_code(std::current_exception())};
    }
    detail::invoke_user_callback(std::move(callback), std::move(read));
    return;
  }
  // The source may answer and then throw: the completion is guarded, so it runs once either way.
  auto guarded = detail::make_fire_once<DataValueResult>(std::move(callback));
  try
  {
    ReadValueId whole = nodeToRead;
    whole.index_range() = String{};
    const RequestInfo request;
    const CallerInfo caller = caller_of(identity);
    const ValueSource::ReadContext context{
      request, identity != nullptr ? &caller : nullptr, maxAge, setSourceTimestamp};
    const ValueSource::ReadItem item{*this, whole};
    // The completion holds the source until it answers (NR-13 rule 4): a source replaced while this read is
    // outstanding is not destroyed with the read in it.
    source->read_async(context,
      std::span<const ValueSource::ReadItem>{&item, 1},
      [guarded, held = source](BatchResult<DataValueResult> read)
      { guarded(first_answer(std::move(read))); });
  }
  catch (...)
  {
    guarded(ua::exception_to_status_code(std::current_exception()));
  }
}

void VariableNode::write_value_async(
  const WriteValue& nodeToWrite, const AccessIdentity* identity, WriteValueCompleteCallback callback)
{
  ValueWritten written;
  try
  {
    written = own_change_completion(std::move(callback));
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(callback), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  if (auto source = application_source())
  {
    const RequestInfo request;
    const CallerInfo caller = caller_of(identity);
    write_to_source_async(
      source, request, nodeToWrite, identity != nullptr ? &caller : nullptr, std::move(written));
    return;
  }
  if (nodeToWrite.attribute_id() != utils::to_underlying(AttributeId::Value))
  {
    detail::invoke_user_callback(written, VoidResult{StatusCode{Status::BadAttributeIdInvalid}}, false);
    return;
  }
  if (write_to_default_source_async(nodeToWrite, identity == nullptr, written))
  {
    return;
  }
  // An application source was attached since it was looked for: it is written.
  if (auto source = application_source())
  {
    const RequestInfo request;
    const CallerInfo caller = caller_of(identity);
    write_to_source_async(
      source, request, nodeToWrite, identity != nullptr ? &caller : nullptr, std::move(written));
    return;
  }
  detail::invoke_user_callback(written, VoidResult{StatusCode{Status::BadInternalError}}, false);
}

bool VariableNode::write_to_default_source_async(
  const WriteValue& write, bool serversOwn, ValueWritten& written)
{
  const auto source = default_source_for_write();
  if (!source)
  {
    return false;
  }
  VoidResult result;
  bool initial = false;
  try
  {
    auto stored = commit_to_default_source(*source, write, serversOwn);
    if (!stored.has_value())
    {
      result = VoidResult{stored.status_code(), stored.shared_detail()};
    }
    else
    {
      result = VoidResult{stored.status_code()};
      initial = stored.value().initial;
    }
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  // The callback runs without the source's lock or the commit lock: it may read or write this Variable.
  detail::invoke_user_callback(written, std::move(result), initial);
  return true;
}

Result<DefaultValueSource::Stored> VariableNode::commit_to_default_source(
  DefaultValueSource& source, const WriteValue& write, bool serversOwn) const
{
  const std::lock_guard<std::mutex> commit(mValueCommitMutex);
  auto stored = source.write(write, serversOwn);
  if (stored.is_good())
  {
    // The Value held after a merge is the merged whole: the Reported registrations are told of it as of any
    // other write.
    const auto& merged = stored.value().merged;
    report_commit(merged ? *merged : write.value());
  }
  return stored;
}

void VariableNode::report_commit(const DataValue& value) const noexcept
{
  try
  {
    report_committed_value(value);
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void VariableNode::log_code_not_reported(const StatusCode& outer, const StatusCode& inner) const noexcept
{
  try
  {
    shared_ptr<NamespaceLink> link;
    {
      const ReadLock lock(mMutex);
      link = mNamespaceLink;
    }
    if (!link)
    {
      return;
    }
    const Logger logger = Namespace::logger_of(*link);
    if (!logger.is_enabled(LogLevel::Warning))
    {
      return;
    }
    const std::string nodeText = to_string(node_id());
    const std::string outerText = to_string(outer);
    const std::string innerText = to_string(inner);
    logger.warning({{"nodeId", std::string_view{nodeText}},
                     {"status", std::string_view{outerText}},
                     {"answered", std::string_view{innerText}}},
      "A Value read back after a write is reported with its own status; the value source's code on the read "
      "is not reported");
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void VariableNode::write_to_source_async(const std::shared_ptr<ValueSource>& source,
  const RequestInfo& request, const WriteValue& write, const CallerInfo* caller, ValueWritten written)
{
  ValueWritten committed;
  try
  {
    committed = source_write_completion(source, written);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      written, VoidResult{ua::exception_to_status_code(std::current_exception())}, false);
    return;
  }
  // The source may answer and then throw: the completion is guarded, so it runs once either way.
  auto answered = std::make_shared<std::atomic<bool>>(false);
  auto guarded = [answered, committed = std::move(committed)](VoidResult result, bool initial)
  {
    if (!answered->exchange(true, std::memory_order_acq_rel))
    {
      committed(std::move(result), initial);
    }
  };
  try
  {
    const ValueSource::WriteContext context{request, caller};
    const ValueSource::WriteItem item{*this, write};
    // The completion holds the source until it answers (NR-13 rule 4).
    source->write_async(context,
      std::span<const ValueSource::WriteItem>{&item, 1},
      [guarded, held = source](BatchResult<ValueSource::WriteResult> result)
      {
        auto answer = first_answer(std::move(result));
        if (!answer.has_value())
        {
          guarded(VoidResult{answer.status_code(), answer.shared_detail()}, false);
          return;
        }
        guarded(VoidResult{answer.status_code()}, answer.value().initial);
      });
  }
  catch (...)
  {
    guarded(ua::exception_to_status_code(std::current_exception()), false);
  }
}

VariableNode::ValueWritten VariableNode::source_write_completion(
  const std::shared_ptr<ValueSource>& source, ValueWritten& written)
{
  const weak_ptr<Node> weakSelf = weak_from_this();
  return [weakSelf, source, originalCallback = std::move(written)](VoidResult result, bool initial) mutable
  {
    auto self = std::dynamic_pointer_cast<const VariableNode>(weakSelf.lock());
    if (result.is_bad() || !self || !self->has_reported_registrations())
    {
      // A registration created from here on reads the Value the source holds when it starts.
      const bool committedInitial = result.is_good() && initial;
      detail::invoke_user_callback(originalCallback, std::move(result), committedInitial);
      return;
    }
    // A source may keep another Value than the one written: the Value it then holds is read back and
    // reported, whatever the write was (DL-115 (3)). The answer is given once the report is made.
    std::function<void()> answer;
    try
    {
      answer = [originalCallback, result, initial]() mutable
      {
        detail::invoke_user_callback(originalCallback, std::move(result), initial);
      };
    }
    catch (...)
    {
      // The write was made; the Value cannot be read back to report it.
      detail::invoke_user_callback(originalCallback, std::move(result), initial);
      return;
    }
    const shared_ptr<const VariableNode> variables[]{std::move(self)};
    report_values_held(source, variables, answer);
  };
}

bool VariableNode::has_reported_registrations() const noexcept
{
  return mReportedRegistrations.load(std::memory_order_acquire) > 0;
}

void VariableNode::report_values_held(const std::shared_ptr<ValueSource>& source,
  std::span<const shared_ptr<const VariableNode>> variables, std::function<void()>& then) noexcept
{
  struct ReadBack
  {
    std::atomic<bool> answered{false};
    boost::container::small_vector<shared_ptr<const VariableNode>, 4> variables;
    std::function<void()> then;
  };

  std::shared_ptr<ReadBack> readBack;
  try
  {
    readBack = std::make_shared<ReadBack>();
    readBack->variables.assign(variables.begin(), variables.end());
  }
  catch (...)
  {
    // Nothing is read back: the writes stay committed and are answered unreported.
    detail::invoke_user_callback(then);
    return;
  }
  readBack->then = std::move(then);
  // Runs once, whether the source answers, answers twice, or throws: each Value the read holds, Good or
  // Uncertain, is reported in item order, then the writes are answered.
  const auto finish = [readBack](const BatchResult<DataValueResult>* read) noexcept
  {
    if (readBack->answered.exchange(true, std::memory_order_acq_rel))
    {
      return;
    }
    if (read != nullptr && read->batchStatus.is_good() && read->items.size() == readBack->variables.size())
    {
      for (std::size_t index = 0; index < read->items.size(); ++index)
      {
        const DataValueResult& item = read->items[index];
        if (!item.has_value())
        {
          continue;
        }
        // The source's code on the read and the Value's own status have room for one status: the one
        // combined_status gives, so a Good subcode or an Uncertain code of the answer is reported. A code
        // with a SubCode that is not the one reported is logged instead.
        DataValue reported = item.value();
        const StatusCode& outer = item.status_code();
        const StatusCode inner = reported.status().value_or(StatusCode{Status::Good});
        if (detail::outer_status_answered(outer, inner))
        {
          reported.status() = outer;
        }
        else if (detail::has_subcode(outer))
        {
          readBack->variables[index]->log_code_not_reported(outer, inner);
        }
        readBack->variables[index]->report_commit(reported);
      }
    }
    detail::invoke_user_callback(readBack->then);
  };
  try
  {
    // Built whole before the items refer to them, so that no reference moves.
    boost::container::small_vector<ReadValueId, 4> whole(readBack->variables.size());
    boost::container::small_vector<ValueSource::ReadItem, 4> items;
    for (std::size_t index = 0; index < readBack->variables.size(); ++index)
    {
      whole[index].node_id() = readBack->variables[index]->node_id();
      whole[index].attribute_id() = utils::to_underlying(AttributeId::Value);
      items.push_back(ValueSource::ReadItem{*readBack->variables[index], whole[index]});
    }
    // The server's own read: no caller, and the Value the source holds now.
    const RequestInfo request;
    const ValueSource::ReadContext context{request, nullptr, 0.0, true};
    // The completion holds the source until it answers (NR-13 rule 4).
    source->read_async(
      context, items, [finish, held = source](BatchResult<DataValueResult> read) { finish(&read); });
  }
  catch (...)
  {
    finish(nullptr);
  }
}

VariableNode::ValueWritten VariableNode::own_change_completion(WriteValueCompleteCallback callback)
{
  const weak_ptr<Node> weakSelf = weak_from_this();
  return
    [weakSelf, link = mNamespaceLink, callback = std::move(callback)](VoidResult result, bool initial) mutable
  {
    auto self = std::dynamic_pointer_cast<VariableNode>(weakSelf.lock());
    if (result.is_bad() || !self || !link)
    {
      detail::invoke_user_callback(std::move(callback), std::move(result));
      return;
    }
    Namespace::own_value_committed(*link, std::move(self), initial, std::move(result), std::move(callback));
  };
}

bool VariableNode::update_default_source_async(
  const std::function<Result<Variant>(const Variant& current)>& next, WriteValueCompleteCallback& callback)
{
  const auto source = default_source_for_write();
  if (!source)
  {
    return false;
  }

  VoidResult result;
  try
  {
    // Updated and reported under the commit lock, as a write is (commit_to_default_source).
    const std::lock_guard<std::mutex> commit(mValueCommitMutex);
    auto updated = source->update(next);
    if (!updated.is_good())
    {
      result = VoidResult{updated.status_code(), updated.shared_detail()};
    }
    else
    {
      report_commit(updated.value());
    }
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  // The callback runs without the source's lock or the commit lock: it may read or write this Variable.
  detail::invoke_user_callback(std::move(callback), std::move(result));
  return true;
}

VoidResult VariableNode::set_value_source(std::shared_ptr<ValueSource> source)
{
  std::shared_ptr<ValueSource> replaced;
  {
    const WriteLock lock(mMutex);
    // The detach rule (COMP-DEFAULT-NODE-ATTR-STORAGE-03): a source owns the Value as a whole, so it replaces
    // the default source and the Value that held. Detaching a source leaves none; the next write installs a
    // new default source.
    replaced.swap(mSource);
    mSource = std::move(source);
    mDefaultSource = nullptr;
  }
  // The replaced source is released here, outside the lock.
  return VoidResult{};
}

std::shared_ptr<ValueSource> VariableNode::application_source() const
{
  const ReadLock lock(mMutex);
  return mDefaultSource == nullptr ? mSource : nullptr;
}

void VariableNode::report_committed_value(const DataValue& value) const
{
  ChangeObservers observers;
  {
    const ReadLock lock(mMutex);
    observers = change_observers_locked(AttributeId::Value);
  }
  report_change(observers, AttributeId::Value, value);
}

void VariableNode::notify_value_changed(DataValue newValue)
{
  ChangeObservers observers;
  shared_ptr<NamespaceLink> link;
  {
    const ReadLock lock(mMutex);
    observers = change_observers_locked(AttributeId::Value);
    link = mNamespaceLink;
  }
  report_change(observers, AttributeId::Value, newValue);
  // A change the source made itself is a change, not a first Value (NR-38 rule 1): the namespace's steps run.
  if (link)
  {
    Namespace::own_value_committed(
      *link, std::static_pointer_cast<VariableNode>(shared_from_this()), false, VoidResult{}, nullptr);
  }
}

NodeClass VariableNode::get_node_class() const
{
  return NodeClass::Variable;
}

void VariableNode::write_attribute_async(
  AttributeId attributeId, Variant attributeValue, WriteAttributeCompleteCallback callback)
{
  if (attributeId == AttributeId::Value)
  {
    // A Variable's live value is not a stored attribute; it is written through write_value_async, to its
    // source, never this path.
    callback(VoidResult{Status::BadNotSupported,
      make_error_detail("AttributeNotSupported",
        "Direct write to Value attribute is not supported; write the Value through write_value_async",
        "DefaultVariableNode")});
    return;
  }
  BaseNode::write_attribute_async(attributeId, std::move(attributeValue), std::move(callback));
}

}  // namespace ua::default_ns
