// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "instantiation/ua_node_subtree.h"

#include "ua_callback_safety.h"
#include "ua_logger.h"
#include <string>
#include "ua_to_string.h"

namespace ua
{

NodeSubtree::NodeSubtree(AddressSpace addressSpace, NodeId rootId, std::vector<NodeId> createdNodes)
  : mAddressSpace(addressSpace.weak()), mRootId(std::move(rootId)), mCreatedNodes(std::move(createdNodes))
{}

NodeSubtree::NodeSubtree(NodeSubtree&& other) noexcept
  : mAddressSpace(std::move(other.mAddressSpace)), mRootId(std::move(other.mRootId)),
    mCreatedNodes(std::move(other.mCreatedNodes)), mReleased(other.mReleased)
{
  other.mReleased = true;
}

NodeSubtree& NodeSubtree::operator=(NodeSubtree&& other) noexcept
{
  if (this == &other)
  {
    return *this;
  }

  remove_async();

  mAddressSpace = std::move(other.mAddressSpace);
  mRootId = std::move(other.mRootId);
  mCreatedNodes = std::move(other.mCreatedNodes);
  mReleased = other.mReleased;

  other.mReleased = true;
  return *this;
}

NodeSubtree::~NodeSubtree()
{
  remove_async();
}

const NodeId& NodeSubtree::root() const
{
  return mRootId;
}

void NodeSubtree::release()
{
  mReleased = true;
}

void NodeSubtree::remove_async()
{
  const bool wasReleased = mReleased;
  mReleased = true;
  if (wasReleased || !mAddressSpace)
  {
    return;
  }
  // Released with the address space: its nodes went with it.
  auto addressSpace = mAddressSpace->lock();
  if (!addressSpace)
  {
    return;
  }

  // Delete exactly the nodes this handle created, in reverse creation order, via the
  // async delete API (fire-and-forget; no synchronous call, so it is safe to run from
  // the destructor on any thread). We delete the explicit recorded set rather than
  // cascading from the root: the handle knows precisely which nodes it created, so the
  // work is bounded and never traverses or over-deletes the surrounding address space
  // (a cascade from a node embedded in a large address space can do exactly that).
  // Single-node deletes still carry cross-namespace reference hygiene, and every
  // intra-subtree reference vanishes as both of its endpoints are deleted. If the
  // address space is torn down first, each delete's weak handle simply fails to lock.
  //
  // Each delete reports its outcome. It used to be discarded, and a discarded outcome here is
  // invisible for ever: the handle that owned the node is already destroyed, so a delete that is
  // REFUSED leaves the node, its attributes and its entries in the namespace's maps behind with
  // nothing to report it. That is a leak whose only symptom is a heap that grows with churn -
  // which is exactly how it presented. Cleanup that cannot fail loudly must at least fail audibly.
  //
  // The completion runs after this destructor has returned, on whatever thread the address space
  // answers on, so it captures only values: the id being deleted and a copy of the logger. No
  // `this`, no members. It is also the last thing standing between a throwing log call and
  // std::terminate inside an Asio handler, hence the catch.
  auto logger = addressSpace->logger();
  for (auto it = mCreatedNodes.rbegin(); it != mCreatedNodes.rend(); ++it)
  {
    addressSpace->delete_node_async(*it,
      /*deleteForwardHierarchicallyReferencedNodes=*/false,
      ReferenceHalves::Both,
      [logger, nodeId = *it](ua::VoidResult result)
      {
        // Uncertain_ReferenceNotDeleted: the node is gone, and the delete has logged the Reference left
        // behind.
        if (!result.is_bad())
        {
          return;
        }
        try
        {
          const std::string nodeText = to_string(nodeId);
          const std::string statusText = to_string(result.status_code());
          logger.with_category("address_space")
            .warning({{"node_id", nodeText}, {"status", statusText}},
              "Owned subtree node could not be removed; it remains in the address space");
        }
        catch (...)
        {
          ua::detail::ignore_expected_exception();
        }
      });
  }
}

void NodeSubtree::add_created_node(NodeId id)
{
  mCreatedNodes.push_back(std::move(id));
}

}  // namespace ua
