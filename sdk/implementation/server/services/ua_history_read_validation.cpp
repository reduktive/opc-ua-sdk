// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_read_validation.h"

#include "ua_access_level_type.h"
#include "ua_event_notifier_type.h"
#include "ua_guid.h"
#include "ua_to_result.h"

#include <algorithm>

namespace ua::server::history_read_validation
{

namespace
{
StatusCode unsupported_event_history()
{
  return StatusCode{Status::BadHistoryOperationUnsupported,
    make_error_detail("HistoricalEventsUnsupported",
      "Node does not support historical Event reads",
      "HistoryReadValidation")};
}

StatusCode unsupported_value_history()
{
  return StatusCode{Status::BadHistoryOperationUnsupported,
    make_error_detail("HistoricalValuesUnsupported",
      "Node does not support historical value reads",
      "HistoryReadValidation")};
}

}  // namespace

StatusCode classify_history_access(const NodeDescription& node, HistoryAccessKind requestedAccess)
{
  const NodeClass nodeClass = node.node_class();
  if (requestedAccess == HistoryAccessKind::Events)
  {
    if (nodeClass == NodeClass::Object)
    {
      return node.event_notifier().value_or(EventNotifierType{}).test(EventNotifierType::Bit::HistoryRead)
               ? StatusCode{Status::Good}
               : unsupported_event_history();
    }
    return nodeClass == NodeClass::Variable ? unsupported_event_history()
                                            : StatusCode{Status::BadHistoryOperationInvalid};
  }
  if (nodeClass == NodeClass::Variable)
  {
    return node.access_level().value_or(AccessLevelType{}).test(AccessLevelType::Bit::HistoryRead)
             ? StatusCode{Status::Good}
             : unsupported_value_history();
  }
  return nodeClass == NodeClass::Object ? unsupported_value_history()
                                        : StatusCode{Status::BadHistoryOperationInvalid};
}

ContinuationLookup lookup_continuation_point(
  const HistoryReadValueId& nodeToRead, std::vector<HistoryContinuationPoint>& available)
{
  if (nodeToRead.continuation_point().empty())
    return {ContinuationKind::Fresh, nullptr};

  Guid guid;
  try
  {
    guid.from_ua_binary(nodeToRead.continuation_point());
  }
  catch (...)
  {
    return {ContinuationKind::Invalid, nullptr};
  }

  auto match = std::ranges::find_if(
    available, [&guid](const HistoryContinuationPoint& entry) { return entry.identifier() == guid; });
  if (match == available.end())
    return {ContinuationKind::Invalid, nullptr};

  return {ContinuationKind::Found, &*match};
}

uint32_t effective_max_values_per_node(uint32_t requested, uint32_t serverLimit)
{
  if (serverLimit == 0)
  {
    return requested;  // no server cap: the client's own request stands, unlimited included
  }
  if (requested == 0)
  {
    return serverLimit;  // client asked for everything; the server's advertised cap is what it gets
  }
  return std::min(requested, serverLimit);
}

}  // namespace ua::server::history_read_validation
