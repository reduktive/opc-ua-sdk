// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Local fake for the NodeManagementDelegate, scoped to phase_4_5i pin tests.
//
//
// The fake mirrors the per-method `*_async` shape declared on
// NodeManagementDelegate. Each method:
//   - records the (Context, items) it was invoked with so the test can
//     assert per-item correspondence and forwarding;
//   - fires its callback inline with a configurable BatchResult<>.
//
// Inline-only firing matches the pre-flip production default (in-memory
// delegates resolve synchronously). Async-completing variants (dedicated
// worker thread + parked-callback queue) are an INFRA GAP - see the
// "Infra gaps" line in this PR's summary.

#ifndef UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_FAKE_NODE_MANAGEMENT_DELEGATE_H
#define UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_FAKE_NODE_MANAGEMENT_DELEGATE_H

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include "ua_namespace_delegates.h"

namespace ua::test::behaviour_pins
{

class FakeNodeManagementDelegate final : public ua::server::NodeManagementDelegate
{
public:
  using AddNodesItemResult = ua::server::NodeManagementDelegate::AddNodesItemResult;

  FakeNodeManagementDelegate() = default;
  ~FakeNodeManagementDelegate() override = default;

  // --- add_nodes ------------------------------------------------------------

  void prepare_add_nodes_async(std::shared_ptr<const Context> context, ua::AddressSpace addressSpace,
    std::vector<ua::AddNodesItem> items, PrepareAddNodesCallback callback) noexcept override;

  void add_nodes_async(std::shared_ptr<const Context> context, ua::AddressSpace addressSpace,
    std::vector<AuthorizedAddNode> items, AddNodesCompleteCallback callback) override;

  /// Configure the canned BatchResult that the next add_nodes_async call returns.
  /// If unset, a per-item all-Good batch sized to items.size() is returned.
  std::function<ua::BatchResult<AddNodesItemResult>(const std::vector<ua::AddNodesItem>&)> addNodesFactory;

  std::vector<ua::AddNodesItem> addNodesRecordedItems;
  std::shared_ptr<const Context> addNodesRecordedContext;
  std::atomic<size_t> addNodesCalls{0};
  std::atomic<std::thread::id> addNodesInvokedThread{std::thread::id{}};

  // --- add_references -------------------------------------------------------

  void add_references_async(std::shared_ptr<const Context> context, ua::AddressSpace addressSpace,
    std::vector<ua::AddReferencesItem> items, NodeMgmtCompleteCallback callback) override;

  std::function<ua::BatchResult<ua::VoidResult>(const std::vector<ua::AddReferencesItem>&)>
    addReferencesFactory;
  std::vector<ua::AddReferencesItem> addReferencesRecordedItems;
  std::shared_ptr<const Context> addReferencesRecordedContext;
  std::atomic<size_t> addReferencesCalls{0};

  // --- delete_nodes ---------------------------------------------------------

  void delete_nodes_async(std::shared_ptr<const Context> context, ua::AddressSpace addressSpace,
    std::vector<ua::DeleteNodesItem> items, NodeMgmtCompleteCallback callback) override;

  std::function<ua::BatchResult<ua::VoidResult>(const std::vector<ua::DeleteNodesItem>&)> deleteNodesFactory;
  std::vector<ua::DeleteNodesItem> deleteNodesRecordedItems;
  std::shared_ptr<const Context> deleteNodesRecordedContext;
  std::atomic<size_t> deleteNodesCalls{0};

  // --- delete_references ----------------------------------------------------

  void delete_references_async(std::shared_ptr<const Context> context, ua::AddressSpace addressSpace,
    std::vector<ua::DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override;

  std::function<ua::BatchResult<ua::VoidResult>(const std::vector<ua::DeleteReferencesItem>&)>
    deleteReferencesFactory;
  std::vector<ua::DeleteReferencesItem> deleteReferencesRecordedItems;
  std::shared_ptr<const Context> deleteReferencesRecordedContext;
  std::atomic<size_t> deleteReferencesCalls{0};
};

}  // namespace ua::test::behaviour_pins

#endif  // !UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_FAKE_NODE_MANAGEMENT_DELEGATE_H
