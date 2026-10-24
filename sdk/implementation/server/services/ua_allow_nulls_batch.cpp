// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_allow_nulls_batch.h"

#include "ua_attribute_id.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_route.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_routing.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_write_type_facts.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace ua::server
{

namespace
{

struct Resolving
{
  Resolving(const AddressSpace& space, RequestInfo info, std::optional<uint32_t> valueReadLimit)
    : addressSpace(space.weak()), logger(space.logger()), request(std::move(info)), readLimit(valueReadLimit)
  {}

  WeakAddressSpace addressSpace;
  Logger logger;
  RequestInfo request;
  std::optional<uint32_t> readLimit;
  std::vector<NodeAccessor> variables;
  std::vector<std::optional<AllowNullsOutcome>> outcomes;
  std::vector<AllowNullsOutcome> answers;
  std::vector<bool> decided;
  std::vector<std::optional<StatusCode>> unresolved;
  std::vector<std::optional<StatusCode>> receivedFailures;
  std::vector<std::optional<NodeAccessor>> property;
  std::function<void(std::vector<AllowNullsOutcome>)> done;
};

void finish(const shared_ptr<Resolving>& resolving, std::optional<StatusCode> failure = std::nullopt) noexcept
{
  if (!resolving->done)
  {
    return;
  }
  for (std::size_t k = 0; k < resolving->outcomes.size(); ++k)
  {
    auto& answer = resolving->answers[k];
    auto& outcome = resolving->outcomes[k];
    const auto& unresolved = resolving->unresolved[k];
    const auto& receivedFailure = resolving->receivedFailures[k];
    if (outcome)
    {
      answer = std::move(outcome.value());
    }
    else if (!resolving->property[k] && unresolved)
    {
      answer = AllowNullsOutcome{unresolved.value(), std::nullopt};
    }
    else if (!resolving->property[k] && receivedFailure)
    {
      answer = AllowNullsOutcome{receivedFailure.value(), std::nullopt};
    }
    else if (failure)
    {
      answer = AllowNullsOutcome{*failure, std::nullopt};
    }
    // A Variable or a Property that does not exist leaves the Server's own null policy in place.
    if (answer.status.as_status() == Status::BadNodeIdUnknown)
    {
      answer = AllowNullsOutcome{StatusCode{Status::Good}, std::nullopt};
    }
  }
  auto done = std::exchange(resolving->done, nullptr);
  ua::detail::invoke_user_callback(resolving->logger, done, std::move(resolving->answers));
}

// The Value of each Property found, read without a caller: AllowNulls is a fact of the type model.
void read_properties(const shared_ptr<Resolving>& resolving, std::vector<std::size_t> owners,
  std::vector<VariableAccessor> properties)
{
  if (properties.empty())
  {
    finish(resolving);
    return;
  }
  auto owner = resolving->addressSpace.lock();
  if (!owner)
  {
    finish(resolving, ua::detail::address_space_gone("AllowNullsBatch"));
    return;
  }

  struct Reading
  {
    std::vector<VariableAccessor> properties;
    std::vector<ReadValueId> ids;
  };

  auto reading = std::make_shared<Reading>();
  std::vector<uint16_t> indexAt;
  for (const auto& property : properties)
  {
    ReadValueId id;
    id.node_id() = property.get_node_id();
    id.attribute_id() = utils::to_underlying(AttributeId::Value);
    indexAt.push_back(id.node_id().namespace_index());
    reading->ids.push_back(std::move(id));
  }
  reading->properties = std::move(properties);
  namespace_calls::by_namespace<DataValueResult>(
    *owner,
    indexAt,
    resolving->readLimit,
    [resolving, reading](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<DataValueResult>)>
        answer)
    {
      std::vector<ValueReadItem> items;
      items.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        items.push_back(ValueReadItem{*reading->properties[position], reading->ids[position]});
      }
      nameSpace.read_values_async(resolving->request, nullptr, items, 0.0, false, std::move(answer));
    },
    [resolving, reading, owners](std::vector<DataValueResult> values)
    {
      try
      {
        // Adopt every received terminal answer before constructing a sibling's fallible refusal.
        for (std::size_t k = 0; k < owners.size() && k < values.size(); ++k)
        {
          auto& outcome = resolving->outcomes[owners[k]];
          auto& read = values[k];
          if (read.is_bad())
          {
            outcome = AllowNullsOutcome{read.status_code(), std::nullopt};
            continue;
          }
          if (!read.is_good())
          {
            // An Uncertain answer is refused below, once every Bad answer has been adopted.
            continue;
          }
          const auto& value = read.value();
          if (value.status() && value.status()->is_bad())
          {
            // Not fatal to the batch: the Value's bad status is this item's outcome, and the others go on.
            outcome = AllowNullsOutcome{*value.status(), std::nullopt};
            continue;
          }
          if (value.status() && !value.status()->is_good())
          {
            // A Value whose own status is Uncertain is refused below, as an Uncertain answer is.
            continue;
          }
          const auto* allowNulls = value.value().try_as<bool>();
          if (allowNulls != nullptr)
          {
            outcome = AllowNullsOutcome{StatusCode{Status::Good}, *allowNulls};
          }
        }
        for (std::size_t k = 0; k < owners.size() && k < values.size(); ++k)
        {
          auto& outcome = resolving->outcomes[owners[k]];
          if (outcome)
          {
            continue;
          }
          auto& read = values[k];
          if (!read.is_good() || (read.value().status() && !read.value().status()->is_good()))
          {
            // The SDK does not decide a write's null policy on a Value the namespace is uncertain of, whether
            // or not the answer holds one, nor on a Value whose own status is Uncertain.
            const StatusCode uncertain = read.is_good() ? *read.value().status() : read.status_code();
            outcome = AllowNullsOutcome{
              server::detail::uncertain_answer_refused(
                server::detail::readAnswerUncertain, uncertain, "AllowNullsBatch", reading->ids[k].node_id()),
              std::nullopt};
          }
          else
          {
            outcome = AllowNullsOutcome{
              StatusCode{Status::BadTypeMismatch,
                ErrorDetail::build(
                  "AllowNullsTypeMismatch", "AllowNulls Property Value is not Boolean", "AttributeServiceSet")
                  .context(ua::ContextKeys::nodeId, to_string(reading->ids[k].node_id()))},
              std::nullopt};
          }
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

}  // namespace

void AllowNullsBatch::resolve_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit, std::optional<uint32_t> readLimit,
  std::function<void(std::vector<AllowNullsOutcome>)> done) noexcept
{
  const std::size_t count = variables.size();
  shared_ptr<Resolving> resolving;
  try
  {
    resolving = std::make_shared<Resolving>(addressSpace, std::move(request), readLimit);
    resolving->variables = std::move(variables);
    resolving->outcomes.resize(resolving->variables.size());
    resolving->decided.resize(count, false);
    resolving->unresolved.resize(count);
    resolving->receivedFailures.resize(count);
    resolving->property.resize(count);
    resolving->answers.resize(count,
      AllowNullsOutcome{
        StatusCode{Status::BadInternalError,
          ErrorDetail::build(
            "ReadAnswerWithoutValue", "The resolution did not supply an outcome", "AllowNullsBatch")},
        std::nullopt});
    resolving->done = std::move(done);

    std::vector<namespace_calls::ReferenceRead> reads;
    std::vector<std::size_t> readOf;
    for (std::size_t k = 0; k < resolving->variables.size(); ++k)
    {
      const NodeAccessor& variable = resolving->variables[k];
      try
      {
        if (variable->deleted())
        {
          resolving->outcomes[k] = AllowNullsOutcome{StatusCode{Status::Good}, std::nullopt};
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
        resolving->outcomes[k] =
          AllowNullsOutcome{exception_to_status_code(std::current_exception()), std::nullopt};
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
          // Adopt received failures and classified absence before allocating candidate storage.
          for (std::size_t r = 0; r < readOf.size(); ++r)
          {
            const std::size_t k = readOf[r];
            if (r >= references.size())
            {
              resolving->outcomes[k] = AllowNullsOutcome{StatusCode{Status::BadInternalError}, std::nullopt};
            }
            else if (references[r].is_bad())
            {
              resolving->outcomes[k] = AllowNullsOutcome{references[r].status_code(), std::nullopt};
            }
            else if (references[r].is_good() &&
                     std::ranges::none_of(references[r].value(),
                       [](const Reference& reference)
                       { return !reference.is_remote() && reference.target_id().is_local(); }))
            {
              resolving->outcomes[k] = AllowNullsOutcome{StatusCode{Status::Good}, std::nullopt};
            }
          }
          // Refuse Uncertain answers, with or without References, before staging any successful sibling's
          // candidates. All received Bad failures were already adopted, even if constructing this refusal
          // fails.
          for (std::size_t r = 0; r < readOf.size() && r < references.size(); ++r)
          {
            const std::size_t k = readOf[r];
            if (!resolving->outcomes[k] && !references[r].is_good())
            {
              resolving->outcomes[k] = AllowNullsOutcome{
                server::detail::uncertain_answer_refused(server::detail::referencesAnswerUncertain,
                  references[r].status_code(),
                  "AllowNullsBatch",
                  resolving->variables[k].get_node_id()),
                std::nullopt};
            }
          }
          // Every local target of each Variable's HasProperty References, in Reference order.
          std::vector<std::size_t> candidateOwner;
          std::vector<NodeId> candidates;
          for (std::size_t r = 0; r < readOf.size(); ++r)
          {
            const std::size_t k = readOf[r];
            if (resolving->outcomes[k])
            {
              continue;
            }
            const std::size_t before = candidates.size();
            for (const auto& reference : references[r].value())
            {
              if (reference.is_remote() || !reference.target_id().is_local())
              {
                continue;
              }
              candidateOwner.push_back(k);
              candidates.push_back(reference.target_id().node_id());
            }
            if (candidates.size() == before)
            {
              resolving->outcomes[k] = AllowNullsOutcome{StatusCode{Status::Good}, std::nullopt};
            }
          }
          if (candidates.empty())
          {
            finish(resolving);
            return;
          }
          auto owner = resolving->addressSpace.lock();
          if (!owner)
          {
            finish(resolving, ua::detail::address_space_gone("AllowNullsBatch"));
            return;
          }
          namespace_calls::find_nodes(*owner,
            resolving->request,
            candidates,
            [resolving, candidateOwner, candidates](std::vector<NodeAccessorResult> found)
            {
              try
              {
                auto& unresolved = resolving->unresolved;
                auto& property = resolving->property;
                auto& decided = resolving->decided;
                // A later successful matching candidate may supersede this provisional failure.
                // Retain its rich status even if earlier successful candidate inspection allocates.
                for (std::size_t c = 0; c < candidates.size() && c < found.size(); ++c)
                {
                  const std::size_t k = candidateOwner[c];
                  if (found[c].is_bad() && found[c].status_code().as_status() != Status::BadNodeIdUnknown &&
                      !resolving->receivedFailures[k])
                  {
                    resolving->receivedFailures[k] = found[c].status_code();
                  }
                }
                const QualifiedName allowNullsName{0, String{"AllowNulls"}};
                for (std::size_t c = 0; c < candidates.size() && c < found.size(); ++c)
                {
                  const std::size_t k = candidateOwner[c];
                  if (decided[k])
                  {
                    continue;
                  }
                  auto& candidate = found[c];
                  if (candidate.is_good())
                  {
                    try
                    {
                      if (candidate.value().get_browse_name() == allowNullsName)
                      {
                        property[k] = candidate.value();
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
                    // The SDK does not take a target the namespace is uncertain of as the Property, whether
                    // or not the answer holds its Node, so the target was not resolved.
                    unresolved[k] =
                      ::ua::detail::lookup_failure(candidates[c], candidate.status_code(), "AllowNullsBatch");
                  }
                }

                // Materialize terminal outcomes for every Variable before allocating Value-read work.
                for (std::size_t k = 0; k < resolving->variables.size(); ++k)
                {
                  if (!resolving->outcomes[k] && !property[k])
                  {
                    StatusCode status{Status::Good};
                    if (unresolved[k])
                    {
                      status = *unresolved[k];
                    }
                    resolving->outcomes[k] = AllowNullsOutcome{std::move(status), std::nullopt};
                  }
                }
                std::vector<std::size_t> owners;
                std::vector<VariableAccessor> properties;
                owners.reserve(resolving->variables.size());
                properties.reserve(resolving->variables.size());
                for (std::size_t k = 0; k < resolving->variables.size(); ++k)
                {
                  if (resolving->outcomes[k])
                  {
                    continue;
                  }
                  try
                  {
                    auto variable = property[k]->as<VariableAccessor>();
                    if (!variable)
                    {
                      resolving->outcomes[k] = AllowNullsOutcome{
                        StatusCode{Status::BadTypeMismatch,
                          ErrorDetail::build("BadTypeMismatch",
                            "Node is not a VariableAccessor",
                            "find_child_variable_accessor_by_browse_name_async")
                            .context(ua::ContextKeys::nodeId, ua::to_string(property[k]->get_node_id()))},
                        std::nullopt};
                      continue;
                    }
                    properties.push_back(std::move(*variable));
                    owners.push_back(k);
                  }
                  catch (...)
                  {
                    resolving->outcomes[k] =
                      AllowNullsOutcome{exception_to_status_code(std::current_exception()), std::nullopt};
                  }
                }
                read_properties(resolving, std::move(owners), std::move(properties));
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
    const StatusCode failure = exception_to_status_code(std::current_exception());
    if (resolving && resolving->done)
    {
      finish(resolving, failure);
    }
    else if (done)
    {
      ua::detail::invoke_user_callback(addressSpace.logger(),
        done,
        std::vector<AllowNullsOutcome>(count, AllowNullsOutcome{failure, std::nullopt}));
    }
  }
}

}  // namespace ua::server
