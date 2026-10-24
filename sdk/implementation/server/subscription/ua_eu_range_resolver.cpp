// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_eu_range_resolver.h"

#include "ua_attribute_id.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_routing.h"
#include "ua_subtype_facts.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_utilities.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace ua::server
{

namespace
{

struct Resolving
{
  Resolving(const AddressSpace& space, RequestInfo info)
    : addressSpace(space.weak()), logger(space.logger()), request(std::move(info))
  {}

  WeakAddressSpace addressSpace;
  Logger logger;
  RequestInfo request;
  std::vector<NodeAccessor> variables;
  std::vector<std::optional<EuRangeProperty>> answers;
  std::vector<EuRangeProperty> output;
  std::vector<StatusCode> absent;
  std::vector<NodeId> propertyIds;
  std::vector<bool> decided;
  std::vector<std::optional<StatusCode>> unresolved;
  std::vector<std::optional<StatusCode>> receivedFailures;
  std::vector<std::optional<NodeAccessor>> property;
  std::function<void(std::vector<EuRangeProperty>)> done;
};

void finish(
  const std::shared_ptr<Resolving>& resolving, std::optional<StatusCode> failure = std::nullopt) noexcept
{
  if (!resolving->done)
  {
    return;
  }
  for (std::size_t k = 0; k < resolving->answers.size(); ++k)
  {
    auto& answer = resolving->answers[k];
    const auto& unresolved = resolving->unresolved[k];
    const auto& receivedFailure = resolving->receivedFailures[k];
    if (answer)
    {
      resolving->output[k] = std::move(answer.value());
    }
    else if (!resolving->property[k] && unresolved)
    {
      resolving->output[k] = EuRangeProperty{NodeId{}, DataValueResult{unresolved.value()}};
    }
    else if (!resolving->property[k] && receivedFailure)
    {
      resolving->output[k] = EuRangeProperty{NodeId{}, DataValueResult{receivedFailure.value()}};
    }
    else if (failure)
    {
      resolving->output[k] = EuRangeProperty{std::move(resolving->propertyIds[k]), DataValueResult{*failure}};
    }
  }
  auto done = std::exchange(resolving->done, nullptr);
  ua::detail::invoke_user_callback(resolving->logger, done, std::move(resolving->output));
}

// The Value of each Property found, read without a caller and without an IndexRange: the EURange is a fact of
// the Variable, not of the Session.
void read_properties(const std::shared_ptr<Resolving>& resolving, std::vector<std::size_t> owners,
  std::vector<NodeAccessor> properties)
{
  if (properties.empty())
  {
    finish(resolving);
    return;
  }
  auto addressSpace = resolving->addressSpace.lock();
  if (!addressSpace)
  {
    finish(resolving, ua::detail::address_space_gone("EuRangeResolver"));
    return;
  }
  std::vector<ua::detail::ValueRead> reads;
  reads.reserve(properties.size());
  for (auto& property : properties)
  {
    ReadValueId id;
    id.node_id() = property.get_node_id();
    id.attribute_id() = utils::to_underlying(AttributeId::Value);
    reads.push_back(ua::detail::ValueRead{std::move(property), std::move(id)});
  }
  ua::detail::NodeAccessorRoute::read_values(
    resolving->request,
    nullptr,
    std::move(reads),
    0.0,
    false,
    [resolving, owners](std::vector<DataValueResult> values)
    {
      try
      {
        for (std::size_t k = 0; k < owners.size(); ++k)
        {
          const std::size_t owner = owners[k];
          DataValueResult value =
            k < values.size() ? std::move(values[k]) : DataValueResult{StatusCode{Status::BadInternalError}};
          if (value.is_uncertain())
          {
            // The SDK does not compute a deadband from a range the namespace is uncertain of, whether or not
            // the answer holds a Value.
            value =
              DataValueResult{server::detail::uncertain_answer_refused(server::detail::readAnswerUncertain,
                value.status_code(),
                "EuRangeResolver",
                resolving->propertyIds[owner])};
          }
          resolving->answers[owner] =
            EuRangeProperty{std::move(resolving->propertyIds[owner]), std::move(value)};
        }
        finish(resolving);
      }
      catch (...)
      {
        finish(resolving, exception_to_status_code(std::current_exception()));
      }
    },
    resolving->addressSpace);
}

// The lookup of every candidate decides each Variable's Property, as the browse-name search decides it.
void choose_properties(const std::shared_ptr<Resolving>& resolving,
  const std::vector<std::size_t>& candidateOwner, const std::vector<std::size_t>& candidateSlot,
  const std::vector<NodeId>& distinct, std::vector<NodeAccessorResult> found)
{
  const std::size_t count = resolving->variables.size();
  auto& decided = resolving->decided;
  auto& unresolved = resolving->unresolved;
  auto& property = resolving->property;
  // Retain received failures before any fallible classification. A matching Property still wins.
  for (std::size_t c = 0; c < candidateOwner.size(); ++c)
  {
    const std::size_t k = candidateOwner[c];
    const std::size_t slot = candidateSlot[c];
    if (slot < found.size() && found[slot].is_bad() &&
        found[slot].status_code().as_status() != Status::BadNodeIdUnknown && !resolving->receivedFailures[k])
    {
      resolving->receivedFailures[k] = found[slot].status_code();
    }
  }
  const QualifiedName euRangeName{0, String{"EURange"}};
  for (std::size_t c = 0; c < candidateOwner.size(); ++c)
  {
    const std::size_t k = candidateOwner[c];
    if (decided[k])
    {
      continue;
    }
    const std::size_t slot = candidateSlot[c];
    if (slot >= found.size())
    {
      continue;
    }
    const auto& candidate = found[slot];
    if (candidate.is_good())
    {
      try
      {
        if (candidate.value().get_browse_name() == euRangeName)
        {
          // The NodeId looked up names the Property found, whether or not its description can be read again.
          // It is copied before anything is set, so a Variable whose copy fails has no Property and is
          // answered with the failure.
          NodeId propertyId = distinct[slot];
          property[k] = candidate.value();
          resolving->propertyIds[k] = std::move(propertyId);
          decided[k] = true;
          unresolved[k].reset();
        }
      }
      catch (...)
      {
        if (!unresolved[k])
        {
          unresolved[k] = exception_to_status_code(std::current_exception());
        }
      }
      continue;
    }
    if (unresolved[k] || candidate.status_code().as_status() == Status::BadNodeIdUnknown)
    {
      continue;
    }
    if (candidate.is_bad())
    {
      unresolved[k] = candidate.status_code();
    }
    else
    {
      // The SDK does not take a target the namespace is uncertain of as the Property, whether or not the
      // answer holds its Node, so the target was not resolved.
      unresolved[k] =
        ::ua::detail::lookup_failure(distinct[slot], candidate.status_code(), "EuRangeResolver");
    }
  }

  // Terminal failures and classified absence cannot be replaced by Value-read staging failure.
  for (std::size_t k = 0; k < count; ++k)
  {
    if (!resolving->answers[k] && !property[k])
    {
      StatusCode status = resolving->absent[k];
      const auto& lookupFailure = unresolved[k];
      if (lookupFailure)
      {
        status = lookupFailure.value();
      }
      resolving->answers[k] = EuRangeProperty{NodeId{}, DataValueResult{std::move(status)}};
    }
  }
  std::vector<std::size_t> owners;
  std::vector<NodeAccessor> properties;
  owners.reserve(count);
  properties.reserve(count);
  for (std::size_t k = 0; k < count; ++k)
  {
    if (resolving->answers[k])
    {
      continue;
    }
    try
    {
      if (property[k]->get_node_class() != NodeClass::Variable)
      {
        const StatusCode failure{Status::BadTypeMismatch,
          ErrorDetail::build("BadTypeMismatch", "Node is not a VariableAccessor", "EuRangeResolver")
            .context(ua::ContextKeys::nodeId, ua::to_string(resolving->propertyIds[k]))};
        resolving->answers[k] =
          EuRangeProperty{std::move(resolving->propertyIds[k]), DataValueResult{failure}};
        continue;
      }
      properties.push_back(std::move(*property[k]));
      owners.push_back(k);
    }
    catch (...)
    {
      resolving->answers[k] = EuRangeProperty{std::move(resolving->propertyIds[k]),
        DataValueResult{exception_to_status_code(std::current_exception())}};
    }
  }
  read_properties(resolving, std::move(owners), std::move(properties));
}

}  // namespace

void EuRangeResolver::resolve_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit,
  std::function<void(std::vector<EuRangeProperty>)> done) noexcept
{
  const std::size_t count = variables.size();
  std::shared_ptr<Resolving> resolving;
  try
  {
    resolving = std::make_shared<Resolving>(addressSpace, std::move(request));
    resolving->variables = std::move(variables);
    resolving->answers.resize(resolving->variables.size());
    resolving->output.resize(count,
      EuRangeProperty{NodeId{},
        DataValueResult{StatusCode{Status::BadInternalError,
          ErrorDetail::build(
            "ReadAnswerWithoutValue", "The resolution did not supply an outcome", "EuRangeResolver")}}});
    resolving->absent.resize(count);
    resolving->propertyIds.resize(count);
    resolving->decided.resize(count, false);
    resolving->unresolved.resize(count);
    resolving->receivedFailures.resize(count);
    resolving->property.resize(count);
    resolving->done = std::move(done);

    std::vector<namespace_calls::ReferenceRead> reads;
    std::vector<std::size_t> readOf;
    for (std::size_t k = 0; k < resolving->variables.size(); ++k)
    {
      const NodeAccessor& variable = resolving->variables[k];
      try
      {
        const NodeId parent = variable.get_node_id();
        resolving->absent[k] = StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build(
            "BadNodeIdUnknown", "No child with matching browse name found", "EuRangeResolver")
            .context(ua::ContextKeys::nodeBrowseName, ua::to_string(QualifiedName{0, String{"EURange"}}))
            .context(ua::ContextKeys::nodeId, ua::to_string(parent))};
        // A deleted Variable has no Property; the answer below says so.
        if (variable->deleted())
        {
          resolving->answers[k] = EuRangeProperty{NodeId{}, DataValueResult{resolving->absent[k]}};
          continue;
        }
        reads.push_back(namespace_calls::ReferenceRead{
          variable, variable.get_node_id(), BrowseDirection::Forward, NodeId{ReferenceTypeId::HasProperty}});
        readOf.push_back(k);
      }
      catch (...)
      {
        // The read and the Variable it is for are staged together or not at all, so each answer below is
        // matched to its own Variable.
        if (reads.size() > readOf.size())
        {
          reads.pop_back();
        }
        resolving->answers[k] =
          EuRangeProperty{NodeId{}, DataValueResult{exception_to_status_code(std::current_exception())}};
      }
    }
    if (reads.empty())
    {
      finish(resolving);
      return;
    }

    namespace_calls::read_references(addressSpace,
      resolving->request,
      std::move(reads),
      browseLimit,
      [resolving, readOf](std::vector<Result<std::vector<Reference>>> references)
      {
        try
        {
          // Adopt received failures and filtered absence before copying targets or growing containers.
          for (std::size_t r = 0; r < readOf.size(); ++r)
          {
            const std::size_t k = readOf[r];
            if (r >= references.size())
            {
              resolving->answers[k] =
                EuRangeProperty{NodeId{}, DataValueResult{StatusCode{Status::BadInternalError}}};
            }
            else if (!references[r].is_good())
            {
              // A Bad answer is the Variable's; an Uncertain one, with or without References, is refused.
              resolving->answers[k] = EuRangeProperty{NodeId{},
                DataValueResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
                  references[r].status_code(),
                  "EuRangeResolver",
                  resolving->variables[k].get_node_id())}};
            }
            else if (std::ranges::none_of(references[r].value(),
                       [](const Reference& reference)
                       { return !reference.is_remote() && reference.target_id().is_local(); }))
            {
              resolving->answers[k] = EuRangeProperty{NodeId{}, DataValueResult{resolving->absent[k]}};
            }
          }
          // Every local target of each Variable's HasProperty References, in Reference order; each distinct
          // target looked up once.
          std::vector<std::size_t> candidateOwner;
          std::vector<std::size_t> candidateSlot;
          std::vector<NodeId> distinct;
          std::map<NodeId, std::size_t> slotOf;
          for (std::size_t r = 0; r < readOf.size(); ++r)
          {
            const std::size_t k = readOf[r];
            if (resolving->answers[k])
            {
              continue;
            }
            const std::size_t before = candidateOwner.size();
            for (const auto& reference : references[r].value())
            {
              if (reference.is_remote() || !reference.target_id().is_local())
              {
                continue;
              }
              const NodeId target = reference.target_id().node_id();
              const auto [entry, added] = slotOf.try_emplace(target, distinct.size());
              if (added)
              {
                distinct.push_back(target);
              }
              candidateOwner.push_back(k);
              candidateSlot.push_back(entry->second);
            }
            if (candidateOwner.size() == before)
            {
              resolving->answers[k] = EuRangeProperty{NodeId{}, DataValueResult{resolving->absent[k]}};
            }
          }
          if (distinct.empty())
          {
            finish(resolving);
            return;
          }
          auto owner = resolving->addressSpace.lock();
          if (!owner)
          {
            finish(resolving, ua::detail::address_space_gone("EuRangeResolver"));
            return;
          }
          namespace_calls::find_nodes(*owner,
            resolving->request,
            distinct,
            [resolving, candidateOwner, candidateSlot, distinct](std::vector<NodeAccessorResult> found)
            {
              try
              {
                choose_properties(resolving, candidateOwner, candidateSlot, distinct, std::move(found));
              }
              catch (...)
              {
                finish(resolving, exception_to_status_code(std::current_exception()));
              }
            });
        }
        catch (...)
        {
          finish(resolving, exception_to_status_code(std::current_exception()));
        }
      });
  }
  catch (...)
  {
    if (resolving && resolving->done)
    {
      finish(resolving, exception_to_status_code(std::current_exception()));
    }
    else if (done)
    {
      try
      {
        ua::detail::invoke_user_callback(addressSpace.logger(),
          done,
          std::vector<EuRangeProperty>(count,
            EuRangeProperty{NodeId{}, DataValueResult{exception_to_status_code(std::current_exception())}}));
      }
      catch (...)
      {
        ua::detail::ignore_expected_exception();
      }
    }
  }
}

}  // namespace ua::server
