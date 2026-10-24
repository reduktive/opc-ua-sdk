// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_data_access_projection.h"

#include "ua_self_owning_operation.h"

#include "ua_on_strand.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_instance_utils.h"
#include "ua_namespace_route.h"
#include "ua_referencetype_id.h"
#include "ua_status_routing.h"
#include "ua_structure.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>

namespace ua::server::data_access_projection
{
std::optional<NodeId> owning_variable_of(const References& references) noexcept
{
  const auto owner = std::find_if(references.begin(),
    references.end(),
    [](const Reference& reference)
    {
      return !reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasProperty} &&
             reference.target_id().is_index_based();
    });
  if (owner == references.end())
  {
    return std::nullopt;
  }
  return owner->target_id().node_id();
}

namespace
{

/// The current value of a MultiStateValueDiscrete Variable as the Int64 its EnumValues entries are keyed by.
///
/// Part 8 section 5.3.3.5 lets the Variable's DataType be any integer Number type, so the value is widened
/// from whichever one it holds; `Variant::to<int64_t>` extracts only an Int64. The same widening
/// instance_utils::project_value_as_text_async applies. A UInt64 above the Int64
/// range, or anything not an integer, has no entry to match.
std::optional<int64_t> enumeration_value(const Variant& value)
{
  if (value.is_int8())
    return value.as<int8_t>();
  if (value.is_uint8())
    return value.as<uint8_t>();
  if (value.is_int16())
    return value.as<int16_t>();
  if (value.is_uint16())
    return value.as<uint16_t>();
  if (value.is_int32())
    return value.as<int32_t>();
  if (value.is_uint32())
    return value.as<uint32_t>();
  if (value.is_int64())
    return value.as<int64_t>();
  if (value.is_uint64() && value.as<uint64_t>() <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
    return static_cast<int64_t>(value.as<uint64_t>());
  return std::nullopt;
}

/// Reads the display text an enumeration's current value maps to, if any: resolves the property's
/// owner, then answers @ref instance_utils::project_value_as_text_async for it.
///
/// A missing or unreadable mapping is `nullopt`, not a failure - the Value the caller asked about
/// simply has no text form. Only a read that actually failed is reported as a failure.
///
/// The strand is the CALLER'S. `AddressSpace` deliberately owns none - it is not a serialised
/// component - and this operation has no shared state of its own to serialise, so minting one would
/// pay an allocation for a guarantee the chain's sequential posts already gave for free. Taking the
/// requesting service's strand instead costs nothing and ties the operation to the request that
/// wants it. @see ua::async::SelfOwningOperation
class ValueAsTextOperation final : public ua::async::SelfOwningOperation<ValueAsTextOperation>
{
public:
  ValueAsTextOperation(AddressSpace addressSpace, NodeAccessor property,
    boost::asio::strand<boost::asio::any_io_executor> strand,
    std::function<void(OptionalLocalizedTextResult)> complete)
    : ua::async::SelfOwningOperation<ValueAsTextOperation>(std::move(strand), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mProperty(std::move(property)), mComplete(std::move(complete))
  {}

  static void run(AddressSpace addressSpace, NodeAccessor property,
    boost::asio::strand<boost::asio::any_io_executor> strand,
    std::function<void(OptionalLocalizedTextResult)> complete)
  {
    launch(std::make_shared<ValueAsTextOperation>(
      std::move(addressSpace), std::move(property), std::move(strand), std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<ValueAsTextOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto references = co_await await_step<NodeAccessor::ReferencesResult>(
        [this](auto completion) { mProperty.get_references_async(std::move(completion)); });
      if (!references.is_good())
      {
        // The projection decides the owner on these References, so an Uncertain answer is not acted on.
        fail(VoidResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
          references.status_code(),
          "DataAccessProjection",
          mProperty.get_node_id())});
        co_return;
      }

      const auto owner = owning_variable_of(references.value());
      if (!owner)
      {
        succeed(std::nullopt);
        co_return;
      }
      const NodeId ownerId = *owner;

      // The same projection a wired ValueAsText Property answers its readers with, so a Read and a
      // MonitoredItem sampling the Property cannot disagree.
      // The address space is locked only inside the step's initiation, so this operation - which the
      // completion it hands out owns - does not keep it alive across the suspension (ua_namespace.h,
      // Ownership).
      auto projected = co_await await_step<DataValueResult>(
        [this, ownerId](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            instance_utils::project_value_as_text_async(
              std::move(*addressSpace), ownerId, std::move(completion));
          }
          else
          {
            completion(DataValueResult{ua::detail::address_space_gone("DataAccessProjection")});
          }
        });
      if (!projected.has_value())
      {
        // No text was projected: the code of the owner's reads is the answer, with its detail.
        fail(VoidResult{projected.status_code(), projected.shared_detail()});
        co_return;
      }
      // The text is the Read's answer, so it carries the code the owner's reads were answered with: a Good
      // subcode, or an Uncertain code with the Value it held, as the Property's wired read handler answers
      // it.
      const auto* text = projected.value().value().try_as<LocalizedText>();
      succeed(text != nullptr ? optional<LocalizedText>{*text} : std::nullopt, projected.status_code());
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      fail(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(VoidResult{status});
  }

  void succeed(optional<LocalizedText> value, StatusCode code = StatusCode{Status::Good})
  {
    if (auto complete = std::move(mComplete))
    {
      complete(OptionalLocalizedTextResult{std::move(value), std::move(code)});
    }
  }

  void fail(const VoidResult& result)
  {
    if (auto complete = std::move(mComplete))
    {
      complete(OptionalLocalizedTextResult{result.status_code(), result.shared_detail()});
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeAccessor mProperty;
  std::function<void(OptionalLocalizedTextResult)> mComplete;
};

/// Reads everything needed to project an enumeration: its owner, its current value, the whole
/// EnumValues table and the EnumDictionaryEntries that go with it.
///
/// Six reads in a row. Unlike @ref ValueAsTextOperation this one reports failures rather than
/// answering `nullopt`, because a caller asking for the snapshot needs the table itself - the only
/// `nullopt` is "this property has no owner to describe".
/// @see ua::async::SelfOwningOperation
class DictionarySnapshotOperation final : public ua::async::SelfOwningOperation<DictionarySnapshotOperation>
{
public:
  DictionarySnapshotOperation(AddressSpace addressSpace, NodeAccessor property,
    boost::asio::strand<boost::asio::any_io_executor> strand,
    std::function<void(OptionalDictionarySnapshotResult)> complete)
    : ua::async::SelfOwningOperation<DictionarySnapshotOperation>(std::move(strand), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mProperty(std::move(property)), mComplete(std::move(complete))
  {}

  static void run(AddressSpace addressSpace, NodeAccessor property,
    boost::asio::strand<boost::asio::any_io_executor> strand,
    std::function<void(OptionalDictionarySnapshotResult)> complete)
  {
    launch(std::make_shared<DictionarySnapshotOperation>(
      std::move(addressSpace), std::move(property), std::move(strand), std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<DictionarySnapshotOperation>;

  // Every step locks the address space only inside its initiation, so this operation - which the
  // completion each step hands out owns - never keeps it alive across a suspension (ua_namespace.h,
  // Ownership).
  auto read_value(const NodeId& nodeId)
  {
    return await_step<DataValueResult>(
      [this, nodeId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::read_variable_data_value_async(
            std::move(*addressSpace), nodeId, std::move(completion));
        }
        else
        {
          completion(DataValueResult{ua::detail::address_space_gone("DataAccessProjection")});
        }
      });
  }

  auto find_property(const NodeId& ownerId, const char* browseName)
  {
    return await_step<VariableAccessorResult>(
      [this, ownerId, browseName](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            ownerId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, browseName},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("DataAccessProjection")});
        }
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      auto references = co_await await_step<NodeAccessor::ReferencesResult>(
        [this](auto completion) { mProperty.get_references_async(std::move(completion)); });
      if (!references.is_good())
      {
        // The projection decides the owner on these References, so an Uncertain answer is not acted on.
        fail(VoidResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
          references.status_code(),
          "DataAccessProjection",
          mProperty.get_node_id())});
        co_return;
      }

      const auto owner = owning_variable_of(references.value());
      if (!owner)
      {
        succeed(std::nullopt);
        co_return;
      }
      const NodeId ownerId = *owner;

      auto ownerNode = co_await await_step<NodeAccessorResult>(
        [this, ownerId](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(ownerId, std::move(completion));
          else
            completion(NodeAccessorResult{ua::detail::address_space_gone("DataAccessProjection")});
        });
      if (!ownerNode.is_good())
      {
        fail(
          VoidResult{::ua::detail::lookup_failure(ownerId, ownerNode.status_code(), "DataAccessProjection")});
        co_return;
      }
      if (ownerNode.value().get_node_class() != NodeClass::Variable)
      {
        // The instance declaration on MultiStateDictionaryEntryDiscreteBaseType: its owner is the
        // VariableType, which holds no current value to project the Property from.
        succeed(std::nullopt);
        co_return;
      }
      DictionarySnapshot snapshot{std::move(ownerNode).value()};

      auto ownerValue = co_await read_value(ownerId);
      if (!ownerValue.has_value())
      {
        fail(VoidResult{ownerValue.status_code(), ownerValue.shared_detail()});
        co_return;
      }
      // The snapshot is what a Read of ValueAsDictionaryEntries answers from, so it carries the codes of the
      // three Value reads it is made from (a Good subcode, or an Uncertain code with the value it held).
      StatusCode answered = ownerValue.status_code();
      const auto numeric = enumeration_value(ownerValue.value().value());
      if (!numeric)
      {
        fail(VoidResult{Status::BadTypeMismatch,
          ErrorDetail::build("EnumerationValueNotInteger",
            "The owning Variable's Value is not an integer an EnumValues entry can be keyed by",
            "DataAccessProjection")});
        co_return;
      }
      snapshot.currentValue = *numeric;

      auto enumValuesProperty = co_await find_property(ownerId, "EnumValues");
      if (!enumValuesProperty.is_good())
      {
        fail(VoidResult{
          ::ua::detail::lookup_failure(ownerId, enumValuesProperty.status_code(), "DataAccessProjection")});
        co_return;
      }

      auto enumValues = co_await read_value(enumValuesProperty.value().get_node_id());
      if (!enumValues.has_value())
      {
        fail(VoidResult{enumValues.status_code(), enumValues.shared_detail()});
        co_return;
      }
      answered =
        combined_read_code(answered, enumValues.status_code(), enumValuesProperty.value().get_node_id());
      auto values = enumValues.value().value().to_vector<RefStructure<Structure>>();
      if (!values.is_good())
      {
        fail(VoidResult{values.status_code(), values.shared_detail()});
        co_return;
      }
      snapshot.enumValues.reserve(values.value().size());
      for (const auto& value : values.value())
      {
        const auto* entry = dynamic_cast<const EnumValueType*>(value.get());
        if (entry == nullptr)
        {
          fail(VoidResult{Status::BadTypeMismatch,
            ErrorDetail::build("EnumValuesEntryTypeMismatch",
              "EnumValues contains an entry that is not EnumValueType",
              "DataAccessProjection")});
          co_return;
        }
        snapshot.enumValues.push_back({entry->value(), entry->display_name()});
      }

      auto dictionaryProperty = co_await find_property(ownerId, "EnumDictionaryEntries");
      if (!dictionaryProperty.is_good())
      {
        fail(VoidResult{
          ::ua::detail::lookup_failure(ownerId, dictionaryProperty.status_code(), "DataAccessProjection")});
        co_return;
      }

      auto entries = co_await read_value(dictionaryProperty.value().get_node_id());
      if (!entries.has_value())
      {
        fail(VoidResult{entries.status_code(), entries.shared_detail()});
        co_return;
      }
      answered =
        combined_read_code(answered, entries.status_code(), dictionaryProperty.value().get_node_id());
      try
      {
        snapshot.dictionaryEntries = entries.value().value().as<Array<NodeId>>();
      }
      catch (...)
      {
        fail(VoidResult{Status::BadTypeMismatch,
          ErrorDetail::build("EnumDictionaryEntriesTypeMismatch",
            "EnumDictionaryEntries does not contain a NodeId array",
            "DataAccessProjection")});
        co_return;
      }
      succeed(std::move(snapshot), std::move(answered));
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      fail(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(VoidResult{status});
  }

  void succeed(optional<DictionarySnapshot> snapshot, StatusCode code = StatusCode{Status::Good})
  {
    if (auto complete = std::move(mComplete))
    {
      complete(OptionalDictionarySnapshotResult{std::move(snapshot), std::move(code)});
    }
  }

  /// The code of the reads so far, @p earlier, and the code @p later of the read of @p nodeId, as the one
  /// code the snapshot carries (`ua::detail::combined_status`). When both carry a SubCode and differ, the
  /// earlier one is not answered and is logged.
  StatusCode combined_read_code(
    const StatusCode& earlier, const StatusCode& later, const NodeId& nodeId) const
  {
    if (earlier == later)
    {
      return later;
    }
    return server::detail::combined_item_status(earlier,
      later,
      mLogger,
      "DataAccessProjection: the code of a Value read the dictionary snapshot is made from was not answered",
      nodeId);
  }

  void fail(const VoidResult& result)
  {
    if (auto complete = std::move(mComplete))
    {
      complete(OptionalDictionarySnapshotResult{result.status_code(), result.shared_detail()});
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeAccessor mProperty;
  std::function<void(OptionalDictionarySnapshotResult)> mComplete;
};

Result<std::pair<size_t, size_t>> dictionary_shape(const DictionarySnapshot& snapshot)
{
  const auto& dimensions = snapshot.dictionaryEntries.dimensions();
  if (!dimensions || dimensions->size() != 2 || (*dimensions)[0] <= 0 || (*dimensions)[1] <= 0)
  {
    return Result<std::pair<size_t, size_t>>{Status::BadTypeMismatch,
      ErrorDetail::build("EnumDictionaryEntriesShapeInvalid",
        "EnumDictionaryEntries must be a non-empty two-dimensional NodeId array",
        "DataAccessProjection")};
  }
  const auto rows = static_cast<size_t>((*dimensions)[0]);
  const auto columns = static_cast<size_t>((*dimensions)[1]);
  if (rows != snapshot.enumValues.size() || rows * columns != snapshot.dictionaryEntries.size())
  {
    return Result<std::pair<size_t, size_t>>{Status::BadOutOfRange,
      ErrorDetail::build("EnumDictionaryEntriesShapeMismatch",
        "EnumDictionaryEntries dimensions do not align with EnumValues and payload size",
        "DataAccessProjection")
        .context(ContextKeys::sizeActual, std::to_string(snapshot.dictionaryEntries.size()))
        .context(ContextKeys::sizeExpected, std::to_string(rows * columns))};
  }
  return std::pair{rows, columns};
}

}  // namespace

void value_as_text_async(AddressSpace addressSpace, NodeAccessor property,
  boost::asio::strand<boost::asio::any_io_executor> strand,
  std::function<void(OptionalLocalizedTextResult)> onComplete) noexcept
{
  try
  {
    // Pass lvalues so allocation/construction failure leaves the caller's completion available for
    // the rich error result below. The flow takes its own value handles once construction succeeds.
    ValueAsTextOperation::run(addressSpace, property, std::move(strand), onComplete);
  }
  catch (...)
  {
    const VoidResult bad = ua::exception_to_status_code(std::current_exception());
    if (onComplete)
      onComplete(OptionalLocalizedTextResult{bad.status_code(), bad.shared_detail()});
  }
}

void dictionary_snapshot_async(AddressSpace addressSpace, NodeAccessor property,
  boost::asio::strand<boost::asio::any_io_executor> strand,
  std::function<void(OptionalDictionarySnapshotResult)> onComplete) noexcept
{
  try
  {
    DictionarySnapshotOperation::run(addressSpace, property, std::move(strand), onComplete);
  }
  catch (...)
  {
    const VoidResult bad = ua::exception_to_status_code(std::current_exception());
    if (onComplete)
      onComplete(OptionalDictionarySnapshotResult{bad.status_code(), bad.shared_detail()});
  }
}

Result<Array<NodeId>> current_dictionary_entries(const DictionarySnapshot& snapshot) noexcept
{
  try
  {
    auto shape = dictionary_shape(snapshot);
    if (!shape.is_good())
      return Result<Array<NodeId>>{shape.status_code(), shape.shared_detail()};
    const auto current = std::find_if(snapshot.enumValues.begin(),
      snapshot.enumValues.end(),
      [&snapshot](const DictionaryEnumEntry& entry) { return entry.value == snapshot.currentValue; });
    if (current == snapshot.enumValues.end())
    {
      return Result<Array<NodeId>>{Status::BadOutOfRange,
        ErrorDetail::build("DictionaryCurrentValueNotEnumerated",
          "the current Variable Value has no EnumValues row",
          "DataAccessProjection")
          .context(ContextKeys::value, std::to_string(snapshot.currentValue))};
    }
    const size_t row = static_cast<size_t>(std::distance(snapshot.enumValues.begin(), current));
    const size_t columns = shape.value().second;
    Array<NodeId> projected;
    projected.reserve(columns);
    for (size_t column = 0; column < columns; ++column)
      projected.push_back(snapshot.dictionaryEntries[(row * columns) + column]);
    return projected;
  }
  catch (...)
  {
    const VoidResult bad = ua::exception_to_status_code(std::current_exception());
    return Result<Array<NodeId>>{bad.status_code(), bad.shared_detail()};
  }
}

Result<DictionaryWriteTarget> dictionary_write_target(
  const DictionarySnapshot& snapshot, DataValue propertyValue) noexcept
{
  try
  {
    auto shape = dictionary_shape(snapshot);
    if (!shape.is_good())
      return Result<DictionaryWriteTarget>{shape.status_code(), shape.shared_detail()};
    auto written = propertyValue.value().to_vector<NodeId>();
    if (!written.is_good() || written.value().size() != 1)
    {
      return Result<DictionaryWriteTarget>{Status::BadTypeMismatch,
        ErrorDetail::build("ValueAsDictionaryEntriesWriteShapeInvalid",
          "ValueAsDictionaryEntries writes must contain exactly one DictionaryEntry NodeId",
          "DataAccessProjection")};
    }
    const auto selected = std::find(
      snapshot.dictionaryEntries.begin(), snapshot.dictionaryEntries.end(), written.value().front());
    if (selected == snapshot.dictionaryEntries.end())
    {
      return Result<DictionaryWriteTarget>{Status::BadOutOfRange,
        ErrorDetail::build("DictionaryEntryNotDefined",
          "the written NodeId is not defined by EnumDictionaryEntries",
          "DataAccessProjection")
          .context(ContextKeys::nodeId, to_string(written.value().front()))};
    }
    const size_t flatIndex = static_cast<size_t>(std::distance(snapshot.dictionaryEntries.begin(), selected));
    const size_t row = flatIndex / shape.value().second;
    propertyValue.value() = Variant{snapshot.enumValues[row].value};
    return DictionaryWriteTarget{snapshot.owner, std::move(propertyValue)};
  }
  catch (...)
  {
    const VoidResult bad = ua::exception_to_status_code(std::current_exception());
    return Result<DictionaryWriteTarget>{bad.status_code(), bad.shared_detail()};
  }
}

}  // namespace ua::server::data_access_projection
