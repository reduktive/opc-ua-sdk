// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_address_space_model_access.h"

#include "ua_self_owning_operation.h"

#include <boost/asio/strand.hpp>
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_data_value.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_structure_definition.h"
#include "ua_enum_definition.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_reference.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include "ua_on_strand.h"

#include <cstddef>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ua::dynamic_types
{

namespace
{

using DataValuesResult = ua::Result<std::vector<ua::DataValue>>;
using BrowseResultsResult = ua::Result<std::vector<ua::BrowseResult>>;

/// Reads one attribute of each named node, in order.
///
/// @see ua::async::SelfOwningOperation
class ASReadOperation final : public ua::async::SelfOwningOperation<ASReadOperation>
{
public:
  ASReadOperation(ua::AddressSpace& addressSpace, std::vector<ua::ReadValueId> items,
    TypeModelAccess::ReadCallback complete)
    : ua::async::SelfOwningOperation<ASReadOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mItems(std::move(items)), mUserCallback(std::move(complete))
  {
    mResults.reserve(mItems.size());
  }

  static void run(ua::AddressSpace& addressSpace, std::vector<ua::ReadValueId> items,
    TypeModelAccess::ReadCallback complete)
  {
    launch(std::make_shared<ASReadOperation>(addressSpace, std::move(items), std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<ASReadOperation>;

  ua::async::Task<> run()
  {
    // One lookup of every item and one Value read per namespace, as the server's own calls: the model is
    // the same for every Session, so there is no caller and no permission check.
    std::vector<ua::detail::LookupItem> lookups;
    lookups.reserve(mItems.size());
    for (const auto& item : mItems)
    {
      lookups.push_back(ua::detail::LookupItem{ua::NodeId{item.node_id()}, std::nullopt});
    }
    auto found = co_await await_step<ua::BatchResult<ua::NodeAccessorResult>>(
      [this, &lookups](auto completion)
      {
        ua::detail::NodeAccessorRoute::find_nodes(mAddressSpace, ua::RequestInfo{}, lookups, std::move(completion));
      });

    // Answered by position: the non-Value items now, the Values when their read completes.
    mResults.assign(mItems.size(), ua::DataValue{});
    std::vector<ua::detail::ValueRead> reads;
    std::vector<size_t> readPositions;
    for (size_t i = 0; i < mItems.size(); ++i)
    {
      const auto& item = mItems[i];
      auto& dataValue = mResults[i];
      if (i >= found.items.size() || !found.items[i].is_good())
      {
        dataValue.status() = ua::Status::BadNodeIdUnknown;
        continue;
      }

      const auto& node = found.items[i].value();
      switch (static_cast<ua::AttributeId>(item.attribute_id()))
      {
      case ua::AttributeId::BrowseName:
        dataValue.value() = ua::Variant{node.get_browse_name()};
        break;
      case ua::AttributeId::IsAbstract:
        if (auto dataTypeAccessor = node.as<ua::DataTypeAccessor>())
        {
          dataValue.value() = ua::Variant{dataTypeAccessor->get_is_abstract()};
        }
        else
        {
          dataValue.status() = ua::Status::BadAttributeIdInvalid;
        }
        break;
      case ua::AttributeId::DataTypeDefinition:
        if (auto dataTypeAccessor = node.as<ua::DataTypeAccessor>())
        {
          if (auto stored = dataTypeAccessor->get_data_type_definition())
          {
            dataValue.value() = ua::Variant{stored->clone()};
          }
          // else: no definition - an empty DataValue (null variant), not an error.
        }
        else
        {
          dataValue.status() = ua::Status::BadAttributeIdInvalid;
        }
        break;
      case ua::AttributeId::Value:
        if (!node.as<ua::VariableAccessor>())
        {
          dataValue.status() = ua::Status::BadAttributeIdInvalid;
          break;
        }
        reads.push_back(ua::detail::ValueRead{node, ua::ReadValueId{item}});
        readPositions.push_back(i);
        break;
      default:
        dataValue.status() = ua::Status::BadAttributeIdInvalid;
        break;
      }
    }

    if (!reads.empty())
    {
      auto values = co_await await_step<std::vector<ua::DataValueResult>>(
        [&reads](auto completion)
        {
          ua::detail::NodeAccessorRoute::read_values(
            ua::RequestInfo{}, nullptr, std::move(reads), ua::Duration{0}, false, std::move(completion));
        });
      for (size_t k = 0; k < readPositions.size(); ++k)
      {
        auto& dataValue = mResults[readPositions[k]];
        if (k < values.size() && values[k].is_good())
        {
          dataValue = std::move(values[k]).value();
        }
        else
        {
          dataValue.status() =
            k < values.size() ? values[k].status_code() : ua::StatusCode{ua::Status::BadInternalError};
        }
      }
    }

    complete_success();
  }

  void fail_to_start(ua::StatusCode status)
  {
    auto callback = std::move(mUserCallback);
    if (callback)
    {
      callback(DataValuesResult{status});
    }
  }

  /// The answer is still delivered from a POSTED turn, which is what the chain's own
  /// `post_owning` was for: callers - the hierarchy discovery walk among them - re-enter `read_async`
  /// from this callback, and firing inline let them recurse on one stack and overflow under deep
  /// type hierarchies. `launch` posts the body's start and `await_step` posts every answer, so
  /// every path that reaches here is already off the caller's stack.
  void complete_success()
  {
    auto callback = std::move(mUserCallback);
    if (callback)
    {
      callback(DataValuesResult{std::move(mResults)});
    }
  }

  ua::WeakAddressSpace mAddressSpace;
  std::vector<ua::ReadValueId> mItems;
  TypeModelAccess::ReadCallback mUserCallback;
  std::vector<ua::DataValue> mResults;
};

/// Browses the named nodes' references together, resolving local targets for their browse names.
///
/// @see ua::async::SelfOwningOperation
class ASBrowseOperation final : public ua::async::SelfOwningOperation<ASBrowseOperation>
{
public:
  ASBrowseOperation(ua::AddressSpace& addressSpace, std::vector<ua::BrowseDescription> items,
    TypeModelAccess::BrowseCallback complete)
    : ua::async::SelfOwningOperation<ASBrowseOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mItems(std::move(items)), mUserCallback(std::move(complete))
  {}

  static void run(ua::AddressSpace& addressSpace, std::vector<ua::BrowseDescription> items,
    TypeModelAccess::BrowseCallback complete)
  {
    launch(std::make_shared<ASBrowseOperation>(addressSpace, std::move(items), std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<ASBrowseOperation>;

  ua::async::Task<> run()
  {
    // The server's own calls, as the reads are: the model is the same for every Session, so there is no
    // caller and no permission check (NR-32 rule 2). One lookup per namespace of every source; rounds of one
    // read_references_async per namespace, each for every Reference of a source (maxReferences 0), the next
    // round only for the sources whose namespace answered a resume token; one lookup per namespace of the
    // distinct local targets.
    const ua::WeakAddressSpace weakAddressSpace = mAddressSpace;
    std::vector<ua::detail::LookupItem> lookups;
    lookups.reserve(mItems.size());
    for (const auto& item : mItems)
    {
      lookups.push_back(ua::detail::LookupItem{ua::NodeId{item.node_id()}, std::nullopt});
    }
    auto found = co_await await_step<ua::BatchResult<ua::NodeAccessorResult>>(
      [&weakAddressSpace, &lookups](auto completion)
      {
        ua::detail::NodeAccessorRoute::find_nodes(
          weakAddressSpace, ua::RequestInfo{}, lookups, std::move(completion));
      });

    struct Source
    {
      std::optional<ua::NodeAccessor> node;
      ua::detail::ResumeToken token;
      std::vector<ua::Reference> references;
      /// The answers in a row that held a resume token and no References.
      std::size_t emptyPages{0};
      bool open{false};
    };

    mResults.assign(mItems.size(), ua::BrowseResult{});
    std::vector<Source> sources(mItems.size());
    for (std::size_t i = 0; i < mItems.size(); ++i)
    {
      // A lookup that is not Good is the source's status, its ErrorDetail kept, with no References.
      if (!found.batchStatus.is_good())
      {
        mResults[i].status_code() = found.batchStatus.status_code();
        continue;
      }
      if (i >= found.items.size())
      {
        mResults[i].status_code() = ua::StatusCode{ua::Status::BadInternalError};
        continue;
      }
      if (!found.items[i].is_good())
      {
        mResults[i].status_code() = found.items[i].status_code();
        continue;
      }
      sources[i].node = found.items[i].value();
      // A browseDirection outside the enumeration matches no Reference, so the source is not read.
      const auto direction = mItems[i].browse_direction();
      sources[i].open = (direction == ua::BrowseDirection::Forward) ||
                        (direction == ua::BrowseDirection::Inverse) ||
                        (direction == ua::BrowseDirection::Both);
    }

    for (;;)
    {
      std::vector<std::size_t> reading;
      std::vector<ua::detail::ReferenceRead> reads;
      for (std::size_t i = 0; i < sources.size(); ++i)
      {
        if (!sources[i].open)
        {
          continue;
        }
        std::vector<ua::NodeId> hint;
        if (!mItems[i].reference_type_id().is_null())
        {
          hint.push_back(mItems[i].reference_type_id());
        }
        reads.push_back(ua::detail::ReferenceRead{
          *sources[i].node, mItems[i].browse_direction(), std::move(hint), 0, std::move(sources[i].token)});
        reading.push_back(i);
      }
      if (reads.empty())
      {
        break;
      }
      auto pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
        [&reads](auto completion)
        {
          ua::detail::NodeAccessorRoute::read_references(
            ua::RequestInfo{}, std::move(reads), std::move(completion));
        });
      for (std::size_t r = 0; r < reading.size(); ++r)
      {
        auto& source = sources[reading[r]];
        auto& result = mResults[reading[r]];
        source.open = false;
        if (r >= pages.size())
        {
          result.status_code() = ua::StatusCode{ua::Status::BadOutOfMemory};
          source.references.clear();
          continue;
        }
        auto& page = pages[r];
        // A value is taken only from an answer that holds one: a page answered Bad or Uncertain is the
        // source's status, with no References.
        if (!page.answer.is_good())
        {
          result.status_code() = page.answer.status_code();
          source.references.clear();
          continue;
        }
        for (const auto& reference : page.answer.value().references)
        {
          source.references.push_back(reference);
        }
        source.emptyPages = page.answer.value().references.empty() ? source.emptyPages + 1 : 0;
        source.token = std::move(page.resumeToken);
        if (source.token.empty())
        {
          continue;
        }
        if (source.emptyPages >= ua::detail::maxEmptyReferencePages)
        {
          // The namespace kept answering a token with no References: the source's read fails, and its last
          // token is released.
          source.token.release();
          result.status_code() = ua::StatusCode{ua::Status::BadInternalError,
            ua::ErrorDetail::build("NamespacePagingDidNotEnd",
              "The namespace kept answering resume tokens for the References of a Node",
              "AddressSpaceModelAccess")
              .context(ua::ContextKeys::nodeId, ua::to_string(mItems[reading[r]].node_id()))
              .context(ua::ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))};
          source.references.clear();
          continue;
        }
        source.open = true;
      }
    }

    // The References each source keeps: its direction exactly, its ReferenceType exactly (no subtypes).
    std::vector<std::vector<ua::ReferenceDescription>> matching(mItems.size());
    std::vector<std::vector<std::size_t>> lookupOf(mItems.size());
    std::vector<ua::detail::LookupItem> targetLookups;
    std::unordered_map<ua::NodeId, std::size_t> targetOf;
    for (std::size_t i = 0; i < mItems.size(); ++i)
    {
      const auto& browseDescription = mItems[i];
      for (const auto& reference : sources[i].references)
      {
        bool directionMatch = false;
        switch (browseDescription.browse_direction())
        {
        case ua::BrowseDirection::Forward:
          directionMatch = reference.is_forward();
          break;
        case ua::BrowseDirection::Inverse:
          directionMatch = !reference.is_forward();
          break;
        case ua::BrowseDirection::Both:
          directionMatch = true;
          break;
        default:
          break;
        }
        if (!directionMatch)
        {
          continue;
        }
        if (!browseDescription.reference_type_id().is_null() &&
            reference.type_id() != browseDescription.reference_type_id())
        {
          continue;
        }

        ua::ReferenceDescription referenceDescription;
        referenceDescription.reference_type_id() = reference.type_id();
        referenceDescription.is_forward() = reference.is_forward();
        referenceDescription.node_id() = reference.target_id();
        std::size_t lookup = std::numeric_limits<std::size_t>::max();
        if (!reference.is_remote())
        {
          const ua::NodeId targetId{reference.target_id().node_id()};
          const auto [entry, added] = targetOf.try_emplace(targetId, targetLookups.size());
          if (added)
          {
            targetLookups.push_back(ua::detail::LookupItem{targetId, std::nullopt});
          }
          lookup = entry->second;
        }
        matching[i].push_back(std::move(referenceDescription));
        lookupOf[i].push_back(lookup);
      }
    }

    if (!targetLookups.empty())
    {
      auto targets = co_await await_step<ua::BatchResult<ua::NodeAccessorResult>>(
        [&weakAddressSpace, &targetLookups](auto completion)
        {
          ua::detail::NodeAccessorRoute::find_nodes(
            weakAddressSpace, ua::RequestInfo{}, targetLookups, std::move(completion));
        });
      for (std::size_t i = 0; i < matching.size(); ++i)
      {
        for (std::size_t k = 0; k < matching[i].size(); ++k)
        {
          const std::size_t l = lookupOf[i][k];
          // Per-target lookup failure is best-effort: the partially-populated ReferenceDescription (NodeId
          // only) is still returned, so the caller sees the Reference.
          if ((l < targets.items.size()) && targets.batchStatus.is_good() && targets.items[l].is_good())
          {
            matching[i][k].browse_name() = targets.items[l].value().get_browse_name();
            matching[i][k].node_class() = targets.items[l].value().get_node_class();
          }
        }
      }
    }

    for (std::size_t i = 0; i < mItems.size(); ++i)
    {
      ua::Array<ua::ReferenceDescription> references;
      for (auto& referenceDescription : matching[i])
      {
        references.push_back(std::move(referenceDescription));
      }
      mResults[i].references() = std::move(references);
    }

    complete_success();
  }

  void fail_to_start(ua::StatusCode status)
  {
    auto callback = std::move(mUserCallback);
    if (callback)
    {
      callback(BrowseResultsResult{status});
    }
  }

  /// @see ASReadOperation::complete_success for why this does not need its own post.
  void complete_success()
  {
    auto callback = std::move(mUserCallback);
    if (callback)
    {
      callback(BrowseResultsResult{std::move(mResults)});
    }
  }

  ua::WeakAddressSpace mAddressSpace;
  std::vector<ua::BrowseDescription> mItems;
  TypeModelAccess::BrowseCallback mUserCallback;
  std::vector<ua::BrowseResult> mResults;
};

}  // namespace

AddressSpaceModelAccess::AddressSpaceModelAccess(ua::AddressSpace& addressSpace)
  : mAddressSpace{addressSpace.weak()}
{}

void AddressSpaceModelAccess::read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete)
{
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    complete(DataValuesResult{ua::detail::address_space_gone("AddressSpaceModelAccess")});
    return;
  }
  ASReadOperation::run(*owner, std::move(nodesToRead), std::move(complete));
}

void AddressSpaceModelAccess::browse_async(
  std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete)
{
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    complete(BrowseResultsResult{ua::detail::address_space_gone("AddressSpaceModelAccess")});
    return;
  }
  ASBrowseOperation::run(*owner, std::move(nodesToBrowse), std::move(complete));
}

}  // namespace ua::dynamic_types
