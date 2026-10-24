// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_node_management_delegate.h"

namespace ua::test::behaviour_pins
{

void FakeNodeManagementDelegate::prepare_add_nodes_async(std::shared_ptr<const Context>, ua::AddressSpace,
  std::vector<ua::AddNodesItem> items, PrepareAddNodesCallback callback) noexcept
{
  ua::BatchResult<PrepareAddNodesItemResult> batch;
  batch.items.reserve(items.size());
  for (const auto& item : items)
  {
    const auto& requested = item.requested_new_node_id().node_id();
    const auto destination =
      requested.is_null() ? item.parent_node_id().node_id().namespace_index() : requested.namespace_index();
    batch.items.emplace_back(AddNodeDestination{destination});
  }
  callback(std::move(batch));
}

void FakeNodeManagementDelegate::add_nodes_async(std::shared_ptr<const Context> context,
  ua::AddressSpace /*addressSpace*/, std::vector<AuthorizedAddNode> authorizedItems,
  AddNodesCompleteCallback callback)
{
  std::vector<ua::AddNodesItem> items;
  items.reserve(authorizedItems.size());
  for (const auto& authorized : authorizedItems)
  {
    items.push_back(authorized.item);
  }
  addNodesRecordedContext = context;
  addNodesRecordedItems = items;
  addNodesCalls.fetch_add(1);
  addNodesInvokedThread.store(std::this_thread::get_id());

  ua::BatchResult<AddNodesItemResult> batch;
  if (addNodesFactory)
  {
    batch = addNodesFactory(items);
  }
  else
  {
    batch.items.reserve(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      ua::AddNodesResult r;
      r.status_code() = ua::Status::Good;
      const auto& requested = items[i].requested_new_node_id().node_id();
      r.added_node_id() = requested.is_null() ? ua::NodeId{authorizedItems[i].destination.namespaceIndex,
                                                  static_cast<uint32_t>(60000u + i)}
                                              : requested;
      batch.items.emplace_back(std::move(r));
    }
  }
  callback(std::move(batch));
}

void FakeNodeManagementDelegate::add_references_async(std::shared_ptr<const Context> context,
  ua::AddressSpace /*addressSpace*/, std::vector<ua::AddReferencesItem> items,
  NodeMgmtCompleteCallback callback)
{
  addReferencesRecordedContext = context;
  addReferencesRecordedItems = items;
  addReferencesCalls.fetch_add(1);

  ua::BatchResult<ua::VoidResult> batch;
  if (addReferencesFactory)
  {
    batch = addReferencesFactory(items);
  }
  else
  {
    batch.items.assign(items.size(), ua::VoidResult{});
  }
  callback(std::move(batch));
}

void FakeNodeManagementDelegate::delete_nodes_async(std::shared_ptr<const Context> context,
  ua::AddressSpace /*addressSpace*/, std::vector<ua::DeleteNodesItem> items,
  NodeMgmtCompleteCallback callback)
{
  deleteNodesRecordedContext = context;
  deleteNodesRecordedItems = items;
  deleteNodesCalls.fetch_add(1);

  ua::BatchResult<ua::VoidResult> batch;
  if (deleteNodesFactory)
  {
    batch = deleteNodesFactory(items);
  }
  else
  {
    batch.items.assign(items.size(), ua::VoidResult{});
  }
  callback(std::move(batch));
}

void FakeNodeManagementDelegate::delete_references_async(std::shared_ptr<const Context> context,
  ua::AddressSpace /*addressSpace*/, std::vector<ua::DeleteReferencesItem> items,
  NodeMgmtCompleteCallback callback)
{
  deleteReferencesRecordedContext = context;
  deleteReferencesRecordedItems = items;
  deleteReferencesCalls.fetch_add(1);

  ua::BatchResult<ua::VoidResult> batch;
  if (deleteReferencesFactory)
  {
    batch = deleteReferencesFactory(items);
  }
  else
  {
    batch.items.assign(items.size(), ua::VoidResult{});
  }
  callback(std::move(batch));
}

}  // namespace ua::test::behaviour_pins
