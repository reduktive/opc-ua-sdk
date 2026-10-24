// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_information_model_pairs.h"

#include "ua_array.h"
#include "ua_array_base.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_node_accessor.h"
#include "ua_on_strand.h"
#include "ua_qualified_name.h"
#include "ua_self_owning_operation.h"
#include "ua_status_routing.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/strand.hpp>

#include <cstddef>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ua::server
{

namespace
{

bool is_selection_list_array(const QualifiedName& browseName)
{
  return browseName.namespace_index() == 0 &&
         (browseName.name() == "Selections" || browseName.name() == "SelectionDescriptions");
}

bool is_enum_values_array(const QualifiedName& browseName)
{
  return browseName.namespace_index() == 0 && browseName.name() == "EnumValues";
}

enum class PairedArrayInvariant
{
  SelectionList,
  EnumDictionaryEntries,
};

VoidResult preserve_failure(StatusCode status)
{
  return VoidResult{std::move(status)};
}

/// Validates the paired-array invariants a service Write must not break.
///
/// Two of them: a SelectionList's Selections and SelectionDescriptions must stay the same length as
/// each other, and an EnumValues array must keep the row count of its EnumDictionaryEntries table.
/// Neither is expressible as a type, so a Write that would break one is refused here.
///
/// Its own strand, made over the address space's executor, because the check belongs to no component and
/// @ref ua::async::await_callback keeps the task's generation and suspended handle on whatever it is given.
/// The Write service AWAITS this, so posting costs it nothing.
/// @see ua::async::SelfOwningOperation
class InformationModelWriteOperation final
  : public ua::async::SelfOwningOperation<InformationModelWriteOperation>
{
public:
  using Base = ua::async::SelfOwningOperation<InformationModelWriteOperation>;

  InformationModelWriteOperation(const AddressSpace& addressSpace, NodeAccessor variable,
    std::size_t proposedSize, std::function<void(VoidResult)> complete)
    : Base(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mVariable(std::move(variable)), mNodeId(mVariable.get_node_id()),
      mProposedSize(proposedSize), mComplete(std::move(complete))
  {}

  static void start(const AddressSpace& addressSpace, NodeAccessor variable, std::size_t proposedSize,
    std::function<void(VoidResult)> complete)
  {
    Base::launch(std::make_shared<InformationModelWriteOperation>(
      addressSpace, std::move(variable), proposedSize, std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<InformationModelWriteOperation>;

  /// A shutdown that interrupted validation. Every one of these was its own branch in the flow this
  /// replaced, differing only in which step it names.
  VoidResult shutdown(const char* code, const char* what, const NodeId& nodeId) const
  {
    return preserve_failure(StatusCode{Status::BadShutdown,
      ErrorDetail::build(code, what, "InformationModelPairs")
        .context(ContextKeys::nodeId, ua::to_string(nodeId))});
  }

  ua::async::Task<> run()
  {
    try
    {
      auto addressSpace = mAddressSpace.lock();
      if (!addressSpace)
      {
        finish(shutdown("SelectionListValidationShutdown",
          "address space shut down while validating a SelectionList write",
          mNodeId));
        co_return;
      }

      auto& node = mVariable;
      PairedArrayInvariant invariant{};
      const auto browseName = node.get_browse_name();
      if (is_selection_list_array(browseName))
      {
        invariant = PairedArrayInvariant::SelectionList;
      }
      else if (is_enum_values_array(browseName))
      {
        invariant = PairedArrayInvariant::EnumDictionaryEntries;
      }
      else
      {
        finish({});
        co_return;
      }

      const auto references = co_await await_step<NodeAccessor::ReferencesResult>(
        [&node](auto completion) { node.get_references_async(std::move(completion)); });
      if (!references.is_good())
      {
        // The owner is decided on these References, so an Uncertain answer, with or without them, is refused.
        finish(preserve_failure(server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
          references.status_code(),
          "InformationModelPairs",
          mNodeId)));
        co_return;
      }

      // The owner is found through the Property's inverse HasProperty Reference and nothing else. A
      // namespace that stores only the owner's forward edge gives no owner, and the pair is then not
      // checked: the write takes the normal Write path. The SDK never enumerates a namespace to find an
      // owner (owner decision 14 on the security review's SVC-16). Cost: one reference read per write.
      std::vector<NodeId> possibleOwners;
      for (const auto& reference : references.value().span())
      {
        if (!reference.is_forward() && !reference.is_remote() &&
            reference.type_id() == NodeId{ReferenceTypeId::HasProperty} && reference.target_id().is_local())
        {
          possibleOwners.push_back(reference.target_id().node_id());
        }
      }

      co_await decide_with(std::move(possibleOwners), invariant);
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      finish(preserve_failure(ua::exception_to_status_code(std::current_exception())));
    }
  }

  /// Each candidate owner in turn. Only a type MISMATCH moves on: an owner of the right type decides
  /// the answer, good or bad, and the search stops there. No owner of the right type: not checked.
  ua::async::Task<> decide_with(std::vector<NodeId> owners, PairedArrayInvariant invariant)
  {
    for (const auto& owner : owners)
    {
      const NodeId ownerType{invariant == PairedArrayInvariant::SelectionList
                               ? VariableTypeId::SelectionListType
                               : VariableTypeId::MultiStateDictionaryEntryDiscreteBaseType};

      const auto isOwnerType = co_await await_step<VoidResult>(
        [this, &owner, &ownerType](auto completion)
        {
          auto handle = mAddressSpace.lock();
          if (!handle)
          {
            completion(VoidResult{StatusCode{Status::BadShutdown}});
            return;
          }
          instance_utils::attach_subtype_async(*handle, owner, ownerType, std::move(completion));
        });
      if (!isOwnerType.is_good())
      {
        if (isOwnerType.status_code() != StatusCode{Status::BadTypeMismatch})
        {
          finish(
            preserve_failure(StatusCode{isOwnerType.status_code().value(), isOwnerType.shared_detail()}));
          co_return;
        }
        continue;
      }
      if (invariant == PairedArrayInvariant::EnumDictionaryEntries)
      {
        co_await check_enum_dictionary_entries(owner);
      }
      else
      {
        co_await check_selection_list();
      }
      co_return;
    }

    finish({});
  }

  /// An EnumValues Write must keep the row count of the owner's EnumDictionaryEntries table.
  ua::async::Task<> check_enum_dictionary_entries(const NodeId& owner)
  {
    const auto entriesId = co_await await_step<NodeIdResult>(
      [this, &owner](auto completion)
      {
        auto handle = mAddressSpace.lock();
        if (!handle)
        {
          completion(NodeIdResult{StatusCode{Status::BadShutdown}});
          return;
        }
        instance_utils::find_child_id_by_browse_name_async(*handle,
          owner,
          NodeId{ReferenceTypeId::HasProperty},
          QualifiedName{0, "EnumDictionaryEntries"},
          std::move(completion));
      });
    if (!entriesId.is_good())
    {
      finish(preserve_failure(StatusCode{entriesId.status_code().value(), entriesId.shared_detail()}));
      co_return;
    }

    const NodeId pairedPropertyId = std::move(entriesId).value();
    if (!mAddressSpace.lock())
    {
      finish(shutdown("DictionaryInvariantValidationShutdown",
        "address space shut down while reading EnumDictionaryEntries",
        mNodeId));
      co_return;
    }

    const auto table = co_await await_step<DataValueResult>(
      [this, &pairedPropertyId](auto completion)
      {
        auto handle = mAddressSpace.lock();
        if (!handle)
        {
          completion(DataValueResult{StatusCode{Status::BadShutdown}});
          return;
        }
        instance_utils::read_variable_data_value_async(*handle, pairedPropertyId, std::move(completion));
      });
    if (!table.is_good())
    {
      // The write is decided on the table's row count, which the SDK does not take from a Value the namespace
      // is uncertain of.
      finish(preserve_failure(server::detail::not_acted_on(server::detail::readAnswerUncertain,
        table.status_code(),
        "InformationModelPairs",
        pairedPropertyId)));
      co_return;
    }

    const auto* entries = table.value().value().try_as<Array<NodeId>>();
    const optional<Dimensions>* entryDimensions = nullptr;
    if (entries != nullptr)
    {
      entryDimensions = &entries->dimensions();
    }
    if (entryDimensions == nullptr || !entryDimensions->has_value() || entryDimensions->value().size() != 2U)
    {
      finish(preserve_failure(StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build("EnumDictionaryEntriesShapeInvalid",
          "EnumDictionaryEntries does not contain a two-dimensional NodeId array",
          "InformationModelPairs")
          .context(ContextKeys::nodeId, ua::to_string(pairedPropertyId))}));
      co_return;
    }

    const auto rows = static_cast<std::size_t>(entryDimensions->value()[0]);
    if (rows == mProposedSize)
    {
      finish({});
      co_return;
    }

    finish(preserve_failure(StatusCode{Status::BadOutOfRange,
      ErrorDetail::build("EnumDictionaryEntriesRowCountMismatch",
        "an EnumValues Write would diverge from the EnumDictionaryEntries row count",
        "InformationModelPairs")
        .context(ContextKeys::nodeId, ua::to_string(mNodeId))
        .context(ContextKeys::sizeActual, std::to_string(mProposedSize))
        .context(ContextKeys::sizeExpected, std::to_string(rows))}));
  }

  /// A service Write cannot change the length of a SelectionList array property.
  ua::async::Task<> check_selection_list()
  {
    const auto current = co_await await_step<DataValueResult>(
      [this](auto completion)
      {
        auto handle = mAddressSpace.lock();
        if (!handle)
        {
          completion(DataValueResult{StatusCode{Status::BadShutdown}});
          return;
        }
        instance_utils::read_variable_data_value_async(*handle, mNodeId, std::move(completion));
      });
    if (!current.is_good())
    {
      // The write is decided on the current length, which the SDK does not take from a Value the namespace is
      // uncertain of.
      finish(preserve_failure(server::detail::not_acted_on(
        server::detail::readAnswerUncertain, current.status_code(), "InformationModelPairs", mNodeId)));
      co_return;
    }

    const auto& currentValue = current.value().value();
    if (!currentValue.is_array())
    {
      finish(preserve_failure(StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build("SelectionListPropertyNotArray",
          "SelectionList array property does not currently hold an array",
          "InformationModelPairs")
          .context(ContextKeys::nodeId, ua::to_string(mNodeId))}));
      co_return;
    }

    const auto currentSize = currentValue.get_array_base().size();
    if (currentSize == mProposedSize)
    {
      finish({});
      co_return;
    }

    finish(preserve_failure(StatusCode{Status::BadOutOfRange,
      ErrorDetail::build("SelectionListArraySizeMismatch",
        "a service Write cannot change the length of a SelectionList array property",
        "InformationModelPairs")
        .context(ContextKeys::nodeId, ua::to_string(mNodeId))
        .context(ContextKeys::sizeActual, std::to_string(mProposedSize))
        .context(ContextKeys::sizeExpected, std::to_string(currentSize))}));
  }

  void fail_to_start(StatusCode status)
  {
    finish(preserve_failure(status));
  }

  void finish(VoidResult decision)
  {
    if (auto complete = std::move(mComplete))
    {
      complete(std::move(decision));
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeAccessor mVariable;
  NodeId mNodeId;
  std::size_t mProposedSize{};
  std::function<void(VoidResult)> mComplete;
};

}  // namespace

bool is_information_model_pair(const QualifiedName& browseName)
{
  return is_selection_list_array(browseName) || is_enum_values_array(browseName);
}

void check_information_model_pair_async(AddressSpace addressSpace, NodeAccessor variable,
  std::size_t proposedSize, std::function<void(VoidResult)> done) noexcept
{
  auto guarded = ::ua::detail::make_fire_once<VoidResult>(std::move(done));
  try
  {
    InformationModelWriteOperation::start(addressSpace, std::move(variable), proposedSize, guarded);
  }
  catch (...)
  {
    guarded(preserve_failure(ua::exception_to_status_code(std::current_exception())));
  }
}

}  // namespace ua::server
