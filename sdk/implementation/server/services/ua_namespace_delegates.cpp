// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_delegates.h"

#include "ua_error_detail.h"
#include "ua_to_result.h"

#include <exception>

namespace ua::server
{

void NodeManagementDelegate::prepare_add_nodes_async(std::shared_ptr<const Context>, AddressSpace,
  std::vector<AddNodesItem> items, PrepareAddNodesCallback callback) noexcept
{
  try
  {
    BatchResult<PrepareAddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (size_t itemIndex = 0; itemIndex < items.size(); ++itemIndex)
    {
      const auto& requestedNodeId = items[itemIndex].requested_new_node_id().node_id();
      if (requestedNodeId.is_null())
      {
        batch.items.emplace_back(StatusCode{Status::BadNotSupported,
          ErrorDetail::build("AddNodesDestinationRoutingUnsupported",
            "The NodeManagementDelegate does not define routing for a null requestedNewNodeId",
            "NodeManagementDelegate")
            .context(ContextKeys::operationIndex, itemIndex)});
        continue;
      }
      batch.items.emplace_back(AddNodeDestination{requestedNodeId.namespace_index()});
    }
    callback(std::move(batch));
  }
  catch (...)
  {
    BatchResult<PrepareAddNodesItemResult> batch;
    const auto status = ua::exception_to_status_code(std::current_exception());
    batch.batchStatus = VoidResult{status, status.shared_detail()};
    callback(std::move(batch));
  }
}

}  // namespace ua::server
