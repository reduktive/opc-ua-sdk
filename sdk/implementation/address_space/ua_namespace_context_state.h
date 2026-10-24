// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_logger.h"
#include "ua_namespace_monitoring_support.h"

#include "ua_result.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace ua
{
class AddressSpaceImpl;
class NamespaceContext;
}  // namespace ua

namespace ua::detail
{

/// What a @ref ua::NamespaceContext and its copies share: the index, the registration's monitoring helper
/// (B3), and the weak link to the address space its reports go to (C2), which closes the context when the
/// registration fails or the address space shuts down (NR-39 rule 4, NR-67).
struct NamespaceContextState
{
  NamespaceContextState(uint16_t namespaceIndex,
    std::shared_ptr<default_ns::NamespaceMonitoringSupport> monitoringHelper,
    std::weak_ptr<AddressSpaceImpl> reportsTo = {}) noexcept
    : index(namespaceIndex), monitoring(std::move(monitoringHelper)), addressSpace(std::move(reportsTo))
  {}

  const uint16_t index;
  /// Never null. The pointer is fixed; the helper it names changes as items are created and deleted.
  const std::shared_ptr<default_ns::NamespaceMonitoringSupport> monitoring;
  /// Where the context's reports go; empty for the context a namespace answers before it is attached.
  const std::weak_ptr<AddressSpaceImpl> addressSpace;
  /// Set when the registration fails or the address space shuts down: the reports do nothing from then on.
  mutable std::atomic<bool> closed{false};

  /// The ConfigurationVersion advances of this namespace (NR-40), run one after another (NR-46 rule 4).
  struct VersionAdvances
  {
    std::mutex mutex;
    /// An advance is queued or running.
    bool running{false};
    /// The completions of the changes reported since the running advance read ConfigurationVersion: the next
    /// advance covers them.
    std::vector<std::function<void(VoidResult)>> waiting;
  };

  /// Never null.
  const std::shared_ptr<VersionAdvances> advances{std::make_shared<VersionAdvances>()};
};

/// What the SDK's own namespaces read from their context and an application's namespace does not.
struct NamespaceContextAccess
{
  /// The logger `AddressSpace::set_logger` last set on the address space @p context reports to; an empty
  /// Logger for a context not attached or whose address space is gone.
  static Logger logger(const NamespaceContext& context);
};

}  // namespace ua::detail
