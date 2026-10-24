// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Runs a test NodeManagementDelegate on an application-owned worker thread.

#ifndef UA_TEST_OFFLOADING_NODE_MANAGEMENT_DELEGATE_H
#define UA_TEST_OFFLOADING_NODE_MANAGEMENT_DELEGATE_H

#include "ua_namespace_delegates.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <memory>
#include <utility>
#include <vector>

namespace ua::test
{

/// Forwards every call of a NodeManagementDelegate to @p inner on a worker thread this adapter owns.
///
/// The SDK calls a delegate on a thread of its own executor, where the AddressSpace's blocking
/// primitives (`try_find_node_sync`, `try_create_node_sync`, `try_delete_node_sync`) refuse with
/// Bad_WouldBlock: a namespace may answer them by posting to that very executor. A delegate written
/// with blocking calls - as most test delegates are, for readability - is therefore run where
/// blocking is harmless: on a thread the SDK does not depend on. This is the offload pattern an
/// application uses for the same reason.
///
/// The worker lambdas hold the inner delegate, never this adapter, so the pool is always joined by
/// whichever thread releases the adapter's last owner and never by its own worker.
class OffloadingNodeManagementDelegate final : public server::NodeManagementDelegate
{
public:
  explicit OffloadingNodeManagementDelegate(std::shared_ptr<server::NodeManagementDelegate> inner)
    : mInner(std::move(inner))
  {}

  ~OffloadingNodeManagementDelegate() override
  {
    mWorker.join();
  }

  OffloadingNodeManagementDelegate(const OffloadingNodeManagementDelegate&) = delete;
  OffloadingNodeManagementDelegate& operator=(const OffloadingNodeManagementDelegate&) = delete;

  void prepare_add_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AddNodesItem> items, PrepareAddNodesCallback callback) noexcept override
  {
    boost::asio::post(mWorker,
      [inner = mInner,
        context = std::move(context),
        addressSpace = std::move(addressSpace),
        items = std::move(items),
        callback = std::move(callback)]() mutable
      {
        inner->prepare_add_nodes_async(
          std::move(context), std::move(addressSpace), std::move(items), std::move(callback));
      });
  }

  void add_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AuthorizedAddNode> items, AddNodesCompleteCallback callback) override
  {
    boost::asio::post(mWorker,
      [inner = mInner,
        context = std::move(context),
        addressSpace = std::move(addressSpace),
        items = std::move(items),
        callback = std::move(callback)]() mutable
      {
        inner->add_nodes_async(
          std::move(context), std::move(addressSpace), std::move(items), std::move(callback));
      });
  }

  void add_references_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AddReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    boost::asio::post(mWorker,
      [inner = mInner,
        context = std::move(context),
        addressSpace = std::move(addressSpace),
        items = std::move(items),
        callback = std::move(callback)]() mutable
      {
        inner->add_references_async(
          std::move(context), std::move(addressSpace), std::move(items), std::move(callback));
      });
  }

  void delete_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<DeleteNodesItem> items, NodeMgmtCompleteCallback callback) override
  {
    boost::asio::post(mWorker,
      [inner = mInner,
        context = std::move(context),
        addressSpace = std::move(addressSpace),
        items = std::move(items),
        callback = std::move(callback)]() mutable
      {
        inner->delete_nodes_async(
          std::move(context), std::move(addressSpace), std::move(items), std::move(callback));
      });
  }

  void delete_references_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    boost::asio::post(mWorker,
      [inner = mInner,
        context = std::move(context),
        addressSpace = std::move(addressSpace),
        items = std::move(items),
        callback = std::move(callback)]() mutable
      {
        inner->delete_references_async(
          std::move(context), std::move(addressSpace), std::move(items), std::move(callback));
      });
  }

private:
  std::shared_ptr<server::NodeManagementDelegate> mInner;
  boost::asio::thread_pool mWorker{1};
};

/// Wraps @p inner so it runs on its own worker thread; see OffloadingNodeManagementDelegate.
inline std::shared_ptr<server::NodeManagementDelegate> offloaded(
  std::shared_ptr<server::NodeManagementDelegate> inner)
{
  if (!inner)
    return nullptr;
  return std::make_shared<OffloadingNodeManagementDelegate>(std::move(inner));
}

}  // namespace ua::test

#endif  // UA_TEST_OFFLOADING_NODE_MANAGEMENT_DELEGATE_H
