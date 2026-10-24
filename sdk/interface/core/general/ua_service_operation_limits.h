// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The per-service caps on the number of nodes or items in one service request.
/// @ingroup general

#ifndef UA_SERVICE_OPERATION_LIMITS_H
#define UA_SERVICE_OPERATION_LIMITS_H

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace ua
{

/// Per-service caps on the number of nodes or items accepted in a single service request.
///
/// A server advertises them in its OperationLimits Object (OPC 10000-5 6.3.11) and holds every request to them
/// (`ServerConfig::ServerCapabilities::operationLimits`, an alias of this type). The address space uses the same
/// values to bound each call it makes to a namespace: a namespace's part of a batch is sent as consecutive calls of at
/// most the matching limit (@ref AddressSpace::set_operation_limits). `nullopt` leaves the corresponding limit
/// unadvertised and unbounded, and the address space then sends a namespace's part as one call. A limit that is set
/// is greater than zero: "Any operational limits Property that is provided shall have a non zero value" (OPC 10000-5
/// 6.3.11), and both `ServerConfig::validate` and @ref AddressSpace::set_operation_limits refuse a 0.
/// @ingroup general
struct ServiceOperationLimits
{
  /// Value equality across all limits.
  /// @return true when every limit compares equal, otherwise false.
  bool operator==(const ServiceOperationLimits&) const = default;

  std::optional<uint32_t> maxNodesPerRead{1000};  ///< Maximum nodes per Read request.
  std::optional<uint32_t> maxNodesPerHistoryReadData{100};  ///< Maximum nodes per data HistoryRead.
  std::optional<uint32_t> maxNodesPerHistoryReadEvents{100};  ///< Maximum nodes per event HistoryRead.
  std::optional<uint32_t> maxNodesPerWrite{1000};  ///< Maximum nodes per Write request.
  std::optional<uint32_t> maxNodesPerHistoryUpdateData{100};  ///< Maximum nodes per data HistoryUpdate.
  std::optional<uint32_t> maxNodesPerHistoryUpdateEvents{100};  ///< Maximum nodes per event HistoryUpdate.
  std::optional<uint32_t> maxNodesPerMethodCall{100};  ///< Maximum methods per Call request.
  /// Maximum nodes per Browse request. Coupled to `ServerConfig::maxReferencesPerBrowseRequest`:
  /// while that budget is set (it is by default), `validate()` requires this limit to be set and at
  /// most the budget, so every operation keeps a page; run without the budget (nullopt) to leave the
  /// operation count unbounded.
  std::optional<uint32_t> maxNodesPerBrowse{1000};
  std::optional<uint32_t> maxNodesPerRegisterNodes{1000};  ///< Maximum nodes per RegisterNodes request.
  std::optional<uint32_t> maxNodesPerTranslateBrowsePathsToNodeIds{
    1000};  ///< Maximum paths per TranslateBrowsePaths request.
  std::optional<uint32_t> maxNodesPerNodeManagement{100};  ///< Maximum nodes per AddNodes/DeleteNodes request.
  std::optional<uint32_t> maxMonitoredItemsPerCall{
    1000};  ///< Maximum MonitoredItems per Create/Modify/Delete call.

  /// The name of the first limit that is set to 0, which OPC 10000-5 6.3.11 does not allow.
  /// @return The field's name, or an empty view when every limit is unset or greater than zero.
  std::string_view first_zero_limit() const noexcept
  {
    const std::array<std::pair<std::string_view, const std::optional<uint32_t>*>, 12> limits{{
      {"maxNodesPerRead", &maxNodesPerRead},
      {"maxNodesPerHistoryReadData", &maxNodesPerHistoryReadData},
      {"maxNodesPerHistoryReadEvents", &maxNodesPerHistoryReadEvents},
      {"maxNodesPerWrite", &maxNodesPerWrite},
      {"maxNodesPerHistoryUpdateData", &maxNodesPerHistoryUpdateData},
      {"maxNodesPerHistoryUpdateEvents", &maxNodesPerHistoryUpdateEvents},
      {"maxNodesPerMethodCall", &maxNodesPerMethodCall},
      {"maxNodesPerBrowse", &maxNodesPerBrowse},
      {"maxNodesPerRegisterNodes", &maxNodesPerRegisterNodes},
      {"maxNodesPerTranslateBrowsePathsToNodeIds", &maxNodesPerTranslateBrowsePathsToNodeIds},
      {"maxNodesPerNodeManagement", &maxNodesPerNodeManagement},
      {"maxMonitoredItemsPerCall", &maxMonitoredItemsPerCall},
    }};
    for (const auto& [name, limit] : limits)
    {
      if (limit->has_value() && **limit == 0U)
      {
        return name;
      }
    }
    return {};
  }
};

}  // namespace ua

#endif  // UA_SERVICE_OPERATION_LIMITS_H
