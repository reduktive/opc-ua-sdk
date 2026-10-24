// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_data_type_facts.h"

#include "ua_callback_safety.h"
#include "ua_datatype_id.h"
#include "ua_subtype_facts.h"
#include "ua_weak_address_space.h"

#include <memory>
#include <utility>

namespace ua::server
{

std::optional<bool> builtin_numeric_data_type(const NodeId& type) noexcept
{
  try
  {
    if (type.namespace_index() != 0 || !type.is_numeric())
    {
      return std::nullopt;
    }
    switch (static_cast<DataTypeId>(type.identifier().get_numeric()))
    {
    case DataTypeId::SByte:
    case DataTypeId::Byte:
    case DataTypeId::Int16:
    case DataTypeId::UInt16:
    case DataTypeId::Int32:
    case DataTypeId::UInt32:
    case DataTypeId::Int64:
    case DataTypeId::UInt64:
    case DataTypeId::Float:
    case DataTypeId::Double:
    case DataTypeId::Number:
    case DataTypeId::Integer:
    case DataTypeId::UInteger:
      return true;
    case DataTypeId::Boolean:
    case DataTypeId::String:
    case DataTypeId::DateTime:
    case DataTypeId::Guid:
    case DataTypeId::ByteString:
    case DataTypeId::XmlElement:
    case DataTypeId::NodeId:
    case DataTypeId::ExpandedNodeId:
    case DataTypeId::StatusCode:
    case DataTypeId::QualifiedName:
    case DataTypeId::LocalizedText:
    case DataTypeId::Structure:
    case DataTypeId::DataValue:
    case DataTypeId::DiagnosticInfo:
      return false;
    default:
      return std::nullopt;
    }
  }
  catch (...)
  {
    return std::nullopt;
  }
}

namespace
{

// The answer of one call, given once: a walk that throws after it has answered is not answered twice.
struct Answering
{
  Logger logger;
  std::vector<bool> nonNumeric;
  std::function<void(std::vector<bool>)> done;

  void answer() noexcept
  {
    if (auto callback = std::exchange(done, nullptr))
    {
      ua::detail::invoke_user_callback(logger, callback, std::move(nonNumeric));
    }
  }
};

}  // namespace

void numeric_data_type_facts(AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> types,
  std::function<void(std::vector<bool>)> done) noexcept
{
  Logger logger;
  std::shared_ptr<Answering> answering;
  try
  {
    logger = addressSpace.logger();
    answering = std::make_shared<Answering>();
    answering->nonNumeric.assign(types.size(), false);
    answering->done.swap(done);
    answering->logger = logger;

    const NodeId baseDataType{DataTypeId::BaseDataType};
    std::vector<std::size_t> asked;
    std::vector<NodeId> lookups;
    for (std::size_t k = 0; k < types.size(); ++k)
    {
      // A Variable declared BaseDataType, or with no DataType, may hold numbers.
      if (types[k].is_null() || types[k] == baseDataType)
      {
        continue;
      }
      if (const auto builtin = builtin_numeric_data_type(types[k]))
      {
        answering->nonNumeric[k] = !*builtin;
        continue;
      }
      asked.push_back(k);
      lookups.push_back(types[k]);
    }
    if (asked.empty())
    {
      answering->answer();
      return;
    }

    namespace_calls::find_nodes(addressSpace,
      request,
      lookups,
      [addressSpace = addressSpace.weak(), request, answering, asked, lookups](
        std::vector<NodeAccessorResult> found) mutable
      {
        try
        {
          std::vector<std::pair<NodeAccessor, NodeId>> starts;
          std::vector<std::size_t> typeOfChain;
          for (std::size_t c = 0; c < asked.size() && c < found.size(); ++c)
          {
            // A type that is not found, or whose lookup is Uncertain and so holds no Node, is undecided.
            if (found[c].is_good())
            {
              starts.emplace_back(std::move(found[c]).value(), lookups[c]);
              typeOfChain.push_back(asked[c]);
            }
          }
          auto owner = addressSpace.lock();
          if (starts.empty() || !owner)
          {
            answering->answer();
            return;
          }
          walk_supertypes(
            *owner,
            std::move(request),
            std::move(starts),
            maxNumericDataTypeDepth,
            [](std::size_t, const NodeId& type) -> std::optional<int>
            {
              // Reached after at least one step: the starts are never BaseDataType.
              if (type == NodeId{DataTypeId::BaseDataType})
              {
                return 0;
              }
              if (const auto builtin = builtin_numeric_data_type(type))
              {
                return *builtin ? 1 : 0;
              }
              return std::nullopt;
            },
            [answering, typeOfChain](std::vector<SupertypeWalkEnd> ends)
            {
              for (std::size_t c = 0; c < typeOfChain.size() && c < ends.size(); ++c)
              {
                if (ends[c].how == SupertypeWalkEnd::How::Decided && ends[c].value == 0)
                {
                  answering->nonNumeric[typeOfChain[c]] = true;
                }
              }
              answering->answer();
            });
        }
        catch (...)
        {
          // The walk could not start: nothing more is known, and an undecided type is not refused.
          answering->answer();
        }
      });
  }
  catch (...)
  {
    // Before callback transfer, a partially initialized Answering cannot complete the caller.
    if (done)
    {
      try
      {
        ua::detail::invoke_user_callback(logger, done, std::vector<bool>(types.size(), false));
      }
      catch (...)
      {
        // An unresolved answer could not be allocated; no type can be classified from it.
        ua::detail::ignore_expected_exception();
      }
    }
    else if (answering)
    {
      answering->answer();
    }
  }
}

}  // namespace ua::server
