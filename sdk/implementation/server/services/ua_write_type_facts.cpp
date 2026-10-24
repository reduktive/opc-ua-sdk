// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_write_type_facts.h"

#include "ua_callback_safety.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_accessor_route.h"
#include "ua_referencetype_id.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>

namespace ua::server
{

namespace
{

// The built-in base a type's own NodeId gives, if any: Structure for a structured type, the mapped built-in
// type otherwise; nullopt for a type whose base is found further up.
std::optional<BuiltInTypeId> base_of(const NodeId& type)
{
  if (type == NodeId{DataTypeId::Structure})
  {
    return BuiltInTypeId::ExtensionObject;
  }
  const BuiltInTypeId mapped = DynamicStructureTypeDescriptor::data_type_to_built_in_type(type);
  if (mapped != BuiltInTypeId::ExtensionObject)
  {
    return mapped;
  }
  return std::nullopt;
}

}  // namespace

bool WriteTypeFacts::needs_no_lookup(const NodeId& dataType) noexcept
{
  if (dataType.is_null())
  {
    return true;
  }
  if (dataType.namespace_index() != 0 || !dataType.is_numeric())
  {
    return false;
  }
  const auto id = dataType.identifier().get_numeric();
  return id >= 1 && id <= 28;
}

void WriteTypeFacts::resolve_declared_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<NodeId> declared, std::function<void(std::map<NodeId, DataTypeFacts>)> done) noexcept
{
  Logger logger;
  shared_ptr<std::map<NodeId, DataTypeFacts>> facts;
  try
  {
    logger = addressSpace.logger();
    if (declared.empty())
    {
      ua::detail::invoke_user_callback(logger, done, std::map<NodeId, DataTypeFacts>{});
      return;
    }
    facts = std::make_shared<std::map<NodeId, DataTypeFacts>>();
    auto ids = std::make_shared<std::vector<NodeId>>(std::move(declared));
    for (const auto& id : *ids)
    {
      facts->try_emplace(id);
    }
    namespace_calls::find_nodes(addressSpace,
      request,
      *ids,
      [addressSpace = addressSpace.weak(), logger, request, ids, facts, done](
        std::vector<NodeAccessorResult> found) mutable
      {
        try
        {
          // Keep established facts in the final map before allocating continuation storage.
          for (std::size_t k = 0; k < ids->size(); ++k)
          {
            auto& typeFacts = facts->find((*ids)[k])->second;
            if (k < found.size() && found[k].is_good())
            {
              try
              {
                const NodeAccessor node = found[k].value();
                if (const auto dataType = node.as<DataTypeAccessor>())
                {
                  typeFacts.found = true;
                  typeFacts.ownId = dataType->get_node_id();
                  try
                  {
                    typeFacts.definition = dataType->get_data_type_definition();
                  }
                  catch (...)
                  {
                    // A definition that cannot be read gives no member or ValidBits check.
                    typeFacts.definition = nullptr;
                  }
                  if (!needs_no_lookup(typeFacts.ownId))
                  {
                    if (auto base = base_of(typeFacts.ownId))
                    {
                      typeFacts.base = *base;
                    }
                  }
                }
              }
              catch (...)
              {
                // Unresolved facts remain absent; facts obtained before this failure are retained.
                ua::detail::ignore_expected_exception();
              }
            }
          }
          std::vector<std::pair<NodeAccessor, NodeId>> walks;
          std::vector<NodeId> walked;
          walks.reserve(ids->size());
          walked.reserve(ids->size());
          for (std::size_t k = 0; k < ids->size(); ++k)
          {
            const auto& typeFacts = facts->find((*ids)[k])->second;
            if (!typeFacts.found || needs_no_lookup(typeFacts.ownId) || typeFacts.base)
            {
              continue;
            }
            try
            {
              // Complete both fallible identifier copies before extending the paired vectors.
              NodeId ownId{typeFacts.ownId};
              NodeId declaredId{(*ids)[k]};
              walks.emplace_back(found[k].value(), std::move(ownId));
              walked.push_back(std::move(declaredId));
            }
            catch (...)
            {
              // The existing facts-only contract represents an unresolved base as absent.
              ua::detail::ignore_expected_exception();
            }
          }
          auto owner = addressSpace.lock();
          if (walks.empty() || !owner)
          {
            ua::detail::invoke_user_callback(logger, done, std::move(*facts));
            return;
          }
          walk_supertypes(
            *owner,
            std::move(request),
            std::move(walks),
            maxTypeWalkDepth,
            [](std::size_t, const NodeId& type) -> std::optional<int>
            {
              if (auto base = base_of(type))
              {
                return static_cast<int>(*base);
              }
              return std::nullopt;
            },
            [facts, walked = std::move(walked), logger, done](std::vector<SupertypeWalkEnd> ends)
            {
              for (std::size_t k = 0; k < walked.size() && k < ends.size(); ++k)
              {
                if (ends[k].how == SupertypeWalkEnd::How::Decided)
                {
                  facts->find(walked[k])->second.base = static_cast<BuiltInTypeId>(ends[k].value);
                }
              }
              ua::detail::invoke_user_callback(logger, done, std::move(*facts));
            });
        }
        catch (...)
        {
          ua::detail::invoke_user_callback(logger, done, std::move(*facts));
        }
      });
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      logger, done, facts ? std::move(*facts) : std::map<NodeId, DataTypeFacts>{});
  }
}

void WriteTypeFacts::resolve_encodings_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<NodeId> encodings, std::function<void(std::vector<EncodingFacts>)> done) noexcept
{
  Logger logger;
  shared_ptr<std::vector<EncodingFacts>> types;
  try
  {
    logger = addressSpace.logger();
    if (encodings.empty())
    {
      ua::detail::invoke_user_callback(logger, done, std::vector<EncodingFacts>{});
      return;
    }
    const std::size_t count = encodings.size();
    types = std::make_shared<std::vector<EncodingFacts>>(count);
    auto ids = std::make_shared<std::vector<NodeId>>(std::move(encodings));
    namespace_calls::find_nodes(addressSpace,
      request,
      *ids,
      [addressSpace = addressSpace.weak(), logger, request, ids, count, types, done](
        std::vector<NodeAccessorResult> found)
      {
        try
        {
          for (std::size_t k = 0; k < count && k < found.size(); ++k)
          {
            (*types)[k].found = found[k].is_good();
          }
          std::vector<namespace_calls::ReferenceRead> reads;
          std::vector<std::size_t> readOf;
          reads.reserve(count);
          readOf.reserve(count);
          for (std::size_t k = 0; k < count && k < found.size(); ++k)
          {
            if (!found[k].is_good())
            {
              continue;
            }
            try
            {
              reads.push_back(namespace_calls::ReferenceRead{
                found[k].value(), (*ids)[k], BrowseDirection::Inverse, NodeId{ReferenceTypeId::HasEncoding}});
              readOf.push_back(k);
            }
            catch (...)
            {
              // The encoding was found; only its unresolved DataType remains absent.
              ua::detail::ignore_expected_exception();
            }
          }
          auto owner = addressSpace.lock();
          if (reads.empty() || !owner)
          {
            ua::detail::invoke_user_callback(logger, done, std::move(*types));
            return;
          }
          namespace_calls::read_references(*owner,
            request,
            std::move(reads),
            std::nullopt,
            [readOf = std::move(readOf), types, logger, done](
              std::vector<Result<std::vector<Reference>>> references)
            {
              for (std::size_t r = 0; r < readOf.size() && r < references.size(); ++r)
              {
                if (!references[r].is_good())
                {
                  continue;
                }
                try
                {
                  for (const auto& reference : references[r].value())
                  {
                    if (reference.target_id().is_local())
                    {
                      (*types)[readOf[r]].dataType = reference.target_id().node_id();
                      break;
                    }
                  }
                }
                catch (...)
                {
                  // A fallible target copy does not discard other encodings' established facts.
                  ua::detail::ignore_expected_exception();
                }
              }
              ua::detail::invoke_user_callback(logger, done, std::move(*types));
            });
        }
        catch (...)
        {
          ua::detail::invoke_user_callback(logger, done, std::move(*types));
        }
      });
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(logger, done, types ? std::move(*types) : std::vector<EncodingFacts>{});
  }
}

void WriteTypeFacts::resolve_subtypes_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<std::pair<NodeId, NodeId>> questions, std::function<void(std::vector<bool>)> done) noexcept
{
  // The declared type is a structured type below Structure: a chain at Structure or at a type with a
  // built-in mapping has passed it.
  SubtypeFacts::resolve_async(std::move(addressSpace),
    std::move(request),
    std::move(questions),
    SubtypeFacts::Bounds{maxTypeWalkDepth,
      [](const NodeId& type)
      {
        return base_of(type).has_value();
      }},
    std::move(done));
}

}  // namespace ua::server
