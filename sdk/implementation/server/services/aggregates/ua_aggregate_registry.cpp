// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_registry.h"

#include "ua_aggregator_factories.h"

namespace ua::server::aggregates
{

AggregatorRegistry::AggregatorRegistry()
{
  register_basic_aggregators(mByNumericId);
  register_variation_aggregators(mByNumericId);
  register_statistical_aggregators(mByNumericId);
  register_bound_aggregators(mByNumericId);
  register_duration_aggregators(mByNumericId);
  register_time_average_aggregators(mByNumericId);
  register_simple_bound_minmax_aggregators(mByNumericId);
  register_counting_aggregators(mByNumericId);
  register_quality_aggregators(mByNumericId);
}

const AggregatorRegistry& AggregatorRegistry::instance()
{
  static const AggregatorRegistry registry;
  return registry;
}

void AggregatorRegistry::add(uint32_t numericId, std::unique_ptr<Aggregator> aggregator)
{
  mByNumericId.emplace(numericId, std::move(aggregator));
}

const Aggregator* AggregatorRegistry::find(const NodeId& aggregateType) const
{
  if (aggregateType.namespace_index() != 0 || !aggregateType.identifier().is_numeric())
    return nullptr;
  const auto it = mByNumericId.find(aggregateType.identifier().get_numeric());
  return it == mByNumericId.end() ? nullptr : it->second.get();
}

std::vector<NodeId> AggregatorRegistry::supported() const
{
  std::vector<NodeId> ids;
  ids.reserve(mByNumericId.size());
  for (const auto& [numericId, aggregator] : mByNumericId)
    ids.emplace_back(numericId);
  return ids;
}

}  // namespace ua::server::aggregates
