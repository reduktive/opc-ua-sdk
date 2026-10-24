// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_event_validation.h"

#include "ua_callback_safety.h"

#include "ua_content_filter.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_event_type_model.h"
#include "ua_history_event_field_list.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_simple_attribute_operand.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <exception>
#include <memory>
#include <string_view>
#include <utility>

namespace ua::server::history_event_validation
{

namespace
{

void invoke_completion(const AddressSpace& addressSpace, Callback& callback, Outcome outcome) noexcept
{
  try
  {
    const Logger logger = addressSpace.logger();
    ::ua::detail::invoke_user_callback(logger, callback, std::move(outcome));
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(callback, std::move(outcome));
  }
}

void invoke_completion(const Logger& logger, Callback& callback, Outcome outcome) noexcept
{
  ::ua::detail::invoke_user_callback(logger, callback, std::move(outcome));
}

StatusCode source_node_failure(StatusCode cause) noexcept
{
  try
  {
    return StatusCode{Status::BadSourceNodeIdInvalid,
      ErrorDetail::build("HistoryEventSourceNodeInvalid",
        "History Event SourceNode does not refer to a valid node",
        "HistoryEventValidation")
        .cause(std::move(cause))};
  }
  catch (...)
  {
    return StatusCode{Status::BadSourceNodeIdInvalid};
  }
}

std::string to_std(const String& value)
{
  return std::string{static_cast<std::string_view>(value)};
}

/// The key a selectClause entry and an instance declaration are matched on: the browse path
/// joined with '/'. A single-element path (the ordinary case) is just the field's BrowseName;
/// a nested path names a field of a child, and joining keeps the two namespaces of meaning apart
/// without inventing a separate representation.
template<class BrowsePath>
std::string field_key_from_path(const BrowsePath& browsePath)
{
  std::string key;
  for (const auto& element : browsePath)
  {
    if (!key.empty())
      key.push_back('/');
    key += to_std(element.name());
  }
  return key;
}

std::string field_key(const SimpleAttributeOperand& clause)
{
  return field_key_from_path(clause.browse_path());
}

std::string field_key(const std::vector<QualifiedName>& browsePath)
{
  return field_key_from_path(browsePath);
}

/// Whether `value` can be stored in a field whose declared DataType is `dataType`.
///
/// Only a DataType that maps straight onto a built-in type constrains anything checkable here: a
/// subtype such as UtcTime, or an abstract root such as BaseDataType, resolves to no built-in and
/// is treated as "no constraint this check can prove", which keeps a conforming insert from being
/// refused by a validator that knows less than the model does. A null value is always admissible
/// - OPC 10000-11 6.9.4.2 defines a null EventId as the Client asking the Server to generate one,
/// and the same latitude applies to any field the Client leaves for the historian to fill.
bool value_fits_declared_type(const NodeId& dataType, const Variant& value)
{
  if (dataType.is_null() || value.empty())
    return true;
  const BuiltInTypeId declared = DynamicStructureTypeDescriptor::data_type_to_built_in_type(dataType);
  if (declared == BuiltInTypeId::ExtensionObject || declared == BuiltInTypeId::Variant)
    return true;
  try
  {
    return value.get_built_in_type() == declared;
  }
  catch (...)
  {
    return true;
  }
}

// =============================================================================================
// The row-by-row validation itself
// =============================================================================================

/// Everything the check needs, lifted out of the request before the first asynchronous hop.
struct Request
{
  std::vector<std::string> clauseNames;  ///< selectClause field keys, in wire order
  std::vector<std::vector<Variant>> rows;  ///< eventData, one inner vector per row
};

// Reached from the completions the namespaces are given, so it holds the address space weakly.
struct RowWalk : std::enable_shared_from_this<RowWalk>
{
  enum class Step
  {
    ResolvingEventType,
    ResolvingSourceNode,
    Done,
  };

  WeakAddressSpace addressSpace;
  Logger logger;
  CollectDeclarationsHook collectDeclarations;
  FindNodeHook findNode;
  Request request;
  Callback onComplete;

  Step step{Step::ResolvingEventType};
  Outcome outcome;
  size_t row{0};

  RowWalk(const AddressSpace& initialAddressSpace, CollectDeclarationsHook initialCollectDeclarations,
    FindNodeHook initialFindNode, Request initialRequest, Callback initialOnComplete)
    : addressSpace(initialAddressSpace.weak()), logger(initialAddressSpace.logger()),
      collectDeclarations(std::move(initialCollectDeclarations)), findNode(std::move(initialFindNode)),
      request(std::move(initialRequest)), onComplete(std::move(initialOnComplete))
  {}

  /// Index of `name` in the selectClause, or npos when the Client did not name that field.
  [[nodiscard]] size_t clause_index(std::string_view name) const
  {
    const auto found = std::find(request.clauseNames.begin(), request.clauseNames.end(), name);
    return found == request.clauseNames.end()
             ? std::string::npos
             : static_cast<size_t>(std::distance(request.clauseNames.begin(), found));
  }

  void finish()
  {
    if (step == Step::Done)
      return;
    step = Step::Done;
    auto handler = std::move(onComplete);
    onComplete = nullptr;
    invoke_completion(logger, handler, std::move(outcome));
  }

  /// The EventType a row names, or null when the row is short of the EventType field or it is not a
  /// NodeId, so the Event does not say what it is.
  [[nodiscard]] const NodeId* row_event_type(size_t rowIndex) const
  {
    const size_t eventTypeIndex = clause_index("EventType");
    const auto& values = request.rows[rowIndex];
    if (eventTypeIndex >= values.size())
      return nullptr;
    return values[eventTypeIndex].try_as<NodeId>();
  }

  /// The address space is gone when the current row needs it: that row, and every later row that would
  /// need it, is answered `Bad_Shutdown` (`AddressSpaceGone`). A later row refused before any lookup keeps
  /// that refusal, and the rows already answered keep theirs.
  void finish_rows_without_address_space()
  {
    const StatusCode gone = ::ua::detail::address_space_gone("HistoryEventValidation");
    outcome.rowStatus[row] = gone;
    for (++row; row < request.rows.size(); ++row)
    {
      outcome.rowStatus[row] =
        row_event_type(row) != nullptr ? gone : StatusCode{Status::BadTypeDefinitionInvalid};
    }
    finish();
  }

  void finish_row(StatusCode status)
  {
    outcome.rowStatus[row] = status;
    ++row;
    step = Step::ResolvingEventType;
    step_row();
  }

  void step_row()
  {
    if (step == Step::Done)
      return;
    if (row >= request.rows.size() || outcome.detailStatus.is_bad())
    {
      finish();
      return;
    }

    // The clause names EventType (checked before any row was examined); a row short of it, or naming
    // something other than a NodeId, does not say what the Event is.
    const NodeId* eventType = row_event_type(row);
    if (eventType == nullptr)
    {
      finish_row(StatusCode{Status::BadTypeDefinitionInvalid});
      return;
    }

    // Held only for the call below.
    auto owner = addressSpace.lock();
    if (!owner)
    {
      finish_rows_without_address_space();
      return;
    }

    const size_t dependencyRow = row;
    auto self = shared_from_this();
    auto completion = [self, dependencyRow](event_type_model::DeclarationsResult result) mutable
    {
      if (self->row != dependencyRow || self->step != Step::ResolvingEventType)
        return;
      self->on_fields_collected(std::move(result));
    };
    try
    {
      if (collectDeclarations)
        collectDeclarations(*owner, *eventType, std::move(completion));
      else
        event_type_model::collect_declarations_async(*owner, *eventType, std::move(completion));
    }
    catch (...)
    {
      if (row == dependencyRow && step == Step::ResolvingEventType)
        finish_row(::ua::exception_to_status_code(std::current_exception()));
    }
  }

  void on_fields_collected(event_type_model::DeclarationsResult result)
  {
    if (step != Step::ResolvingEventType)
    {
      finish();
      return;
    }
    if (!result.is_good())
    {
      finish_row(result.status_code());
      return;
    }
    const event_type_model::Declarations fields = std::move(result).value();

    // Every field the EventType makes Mandatory has to be named by the selectClause, or the
    // archived Event is missing something every consumer of that type expects to read back. This
    // is a property of the clause rather than of the row, so it stops the whole operation.
    for (const auto& field : fields)
    {
      if (field.mandatory && clause_index(field_key(field.browsePath)) == std::string::npos)
      {
        outcome.detailStatus = StatusCode{Status::BadArgumentsMissing};
        finish();
        return;
      }
    }

    // A value that cannot be processed into the field its clause names is fatal to the whole row:
    // storing the rest would leave an Event that reads back as though the Server had generated it
    // incomplete, with nothing to say a field was dropped.
    const auto& values = request.rows[row];
    std::vector<std::string> ignored;
    std::vector<std::string> invalid;
    for (size_t i = 0; i < request.clauseNames.size(); ++i)
    {
      const auto& name = request.clauseNames[i];
      const auto declared = std::find_if(fields.begin(),
        fields.end(),
        [&name](const event_type_model::Declaration& field) { return field_key(field.browsePath) == name; });
      if (declared == fields.end())
      {
        ignored.push_back(name);
        continue;
      }
      if (i < values.size() && !value_fits_declared_type(declared->dataType, values[i]))
        invalid.push_back(name);
    }
    outcome.ignoredFields[row] = std::move(ignored);
    outcome.invalidFields[row] = std::move(invalid);
    if (!outcome.invalidFields[row].empty())
    {
      finish_row(StatusCode{Status::BadInvalidArgument});
      return;
    }

    // The SourceNode names the Node the Event is attributed to. A NodeId that resolves to nothing
    // leaves the history asserting something the address space contradicts.
    const size_t sourceIndex = clause_index("SourceNode");
    if (sourceIndex >= values.size())
    {
      finish_row(row_success());
      return;
    }
    const NodeId* sourceNode = values[sourceIndex].try_as<NodeId>();
    if (sourceNode == nullptr || sourceNode->is_null())
    {
      finish_row(row_success());
      return;
    }

    // Held only for the call below.
    auto owner = addressSpace.lock();
    if (!owner)
    {
      finish_rows_without_address_space();
      return;
    }

    step = Step::ResolvingSourceNode;
    const size_t dependencyRow = row;
    auto self = shared_from_this();
    auto completion = [self, dependencyRow, sourceNodeId = *sourceNode](NodeAccessorResult found) mutable
    {
      if (self->row != dependencyRow || self->step != Step::ResolvingSourceNode)
        return;
      if (!found.is_good())
      {
        // A Bad answer says the SourceNode is not valid; an Uncertain one, with or without the Node, is
        // refused: the SDK does not accept a SourceNode the namespace is uncertain of.
        self->finish_row(found.is_bad() ? source_node_failure(found.status_code())
                                        : ::ua::detail::lookup_failure(
                                            sourceNodeId, found.status_code(), "HistoryEventValidation"));
        return;
      }
      self->finish_row(self->row_success());
    };
    try
    {
      if (findNode)
        findNode(*owner, *sourceNode, std::move(completion));
      else
        owner->find_node_async(*sourceNode, std::move(completion));
    }
    catch (...)
    {
      if (row == dependencyRow && step == Step::ResolvingSourceNode)
      {
        finish_row(source_node_failure(::ua::exception_to_status_code(std::current_exception())));
      }
    }
  }

  /// Good, or Good_DataIgnored when the historian dropped a field the Client named. Both are
  /// success codes: the Event is archived either way, and only the second says so incompletely.
  [[nodiscard]] StatusCode row_success() const
  {
    return outcome.ignoredFields[row].empty() ? StatusCode{Status::Good}
                                              : StatusCode{Status::GoodDataIgnored};
  }
};

}  // namespace

bool Outcome::has_dispatchable_row() const noexcept
{
  if (detailStatus.is_bad())
    return false;
  return std::any_of(
    rowStatus.begin(), rowStatus.end(), [](const StatusCode& status) { return !status.is_bad(); });
}

void validate_async(AddressSpace addressSpace, const UpdateEventDetails& details, Callback onComplete,
  CollectDeclarationsHook collectDeclarations, FindNodeHook findNode) noexcept
{
  Outcome outcome;
  const auto& filter = details.filter();
  const auto& clauses = filter.select_clauses();

  // An insert is not a filtered query, so a whereClause on one has nothing to select against.
  if (!filter.where_clause().elements().empty())
  {
    outcome.detailStatus = StatusCode{Status::BadEventFilterInvalid};
    invoke_completion(addressSpace, onComplete, std::move(outcome));
    return;
  }

  Request request;
  request.clauseNames.reserve(clauses.size());
  for (const auto& clause : clauses)
  {
    // The operand type is shared with the read path, where an IndexRange selects part of a value.
    // On the insert path there is nothing to select from, and applying it would archive a slice
    // of what the Client sent while reporting the whole value stored.
    if (!clause.index_range().empty())
    {
      outcome.detailStatus = StatusCode{Status::BadIndexRangeInvalid};
      invoke_completion(addressSpace, onComplete, std::move(outcome));
      return;
    }
    request.clauseNames.push_back(field_key(clause));
  }

  // An Event that names neither its type nor its time is filed where no query can find it, so
  // these two are the floor regardless of what the EventType declares.
  const auto names = [&request](std::string_view name)
  {
    return std::find(request.clauseNames.begin(), request.clauseNames.end(), name) !=
           request.clauseNames.end();
  };
  if (!names("EventType") || !names("Time"))
  {
    outcome.detailStatus = StatusCode{Status::BadArgumentsMissing};
    invoke_completion(addressSpace, onComplete, std::move(outcome));
    return;
  }

  request.rows.reserve(details.event_data().size());
  for (const auto& record : details.event_data())
    request.rows.emplace_back(record.event_fields().begin(), record.event_fields().end());

  outcome.rowStatus.assign(request.rows.size(), StatusCode{Status::Good});
  outcome.ignoredFields.resize(request.rows.size());
  outcome.invalidFields.resize(request.rows.size());

  auto walk = std::make_shared<RowWalk>(addressSpace,
    std::move(collectDeclarations),
    std::move(findNode),
    std::move(request),
    std::move(onComplete));
  walk->outcome = std::move(outcome);
  walk->step_row();
}

}  // namespace ua::server::history_event_validation
