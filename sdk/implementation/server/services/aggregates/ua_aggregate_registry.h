// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_REGISTRY_H
#define UA_AGGREGATE_REGISTRY_H

/// Maps an aggregate-function NodeId (NS0 numeric, e.g. AggregateFunction_Average
/// = 2342) to the Aggregator that implements it.

#include "ua_aggregator.h"
#include "ua_node_id.h"

#include <memory>
#include <unordered_map>

namespace ua::server::aggregates
{

class AggregatorRegistry
{
public:
  /// The process-wide registry of all implemented aggregates.
  static const AggregatorRegistry& instance();

  /// The aggregator for `aggregateType`, or nullptr if unsupported.
  const Aggregator* find(const NodeId& aggregateType) const;

  /// NodeIds of every supported aggregate (NS0), for capability advertising.
  std::vector<NodeId> supported() const;

private:
  AggregatorRegistry();
  void add(uint32_t numericId, std::unique_ptr<Aggregator> aggregator);

  std::unordered_map<uint32_t, std::unique_ptr<Aggregator>> mByNumericId;
};

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_REGISTRY_H
