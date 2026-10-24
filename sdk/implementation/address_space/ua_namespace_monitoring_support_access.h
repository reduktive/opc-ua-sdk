// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_namespace_monitoring_support.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua::detail
{

/// Issues the next monitoring handle from the counter @p next, which it advances past the handle issued. The
/// handle is never 0, which a create answers for no registration, and never one @p inUse answers true for, so
/// a counter that has wrapped does not issue the handle of a registration that still exists.
///
/// @param next  The counter of the next handle to try; advanced past the handle issued.
/// @param inUse Answers whether a handle names a registration that exists. Called under the caller's lock.
/// @return The handle issued.
template<typename InUse>
MonitoringHandle issue_handle(MonitoringHandle& next, const InUse& inUse)
{
  MonitoringHandle handle = next++;
  while (handle == 0 || inUse(handle))
  {
    handle = next++;
  }
  return handle;
}

/// The SDK's own way to the monitoring helper: creating it, shutting it down, and what the in-memory
/// namespace reads of it (a registration). Not public: a namespace reaches its helper through
/// `context().monitoring()` and nothing else.
class MonitoringSupportAccess
{
public:
  using Helper = default_ns::NamespaceMonitoringSupport;

  /// A registration's helper: samples on @p executor (the address space's), logs through @p logger, and
  /// reads its Sampled Values through @p owner, held weakly, each read split by what @p maxNodesPerRead
  /// answers at the tick: the address space's MaxNodesPerRead as it stands then, since namespaces 0 and 1
  /// are registered before the server sets its limits (unset or null: not split).
  static std::shared_ptr<Helper> create(boost::asio::any_io_executor executor, Logger logger,
    std::weak_ptr<Namespace> owner, std::function<std::optional<uint32_t>()> maxNodesPerRead);

  /// The helper the context answers before registration: no engine, no timer, refuses every create,
  /// modify and delete.
  static std::shared_ptr<Helper> create_unattached();

  /// Stops @p helper's timers, refuses later creates and modifies, and calls @p done once no tick is in
  /// flight - inline when none is, otherwise on the thread of the last tick to finish, after its push.
  /// A tick in flight that has not stored its values for the push when this is called pushes nothing
  /// and sends no notice. Safe to call twice.
  static void shutdown_async(Helper& helper, std::function<void()> done) noexcept;

  /// What the in-memory namespace needs of a registration to keep its count of Reported registrations on
  /// the Node the registration was created on (DL-68 (6)).
  struct Registration
  {
    /// The Node the registration was created on; null once that Node is gone.
    std::shared_ptr<Node> node;
    AttributeId attributeId{AttributeId::Value};
    Helper::Delivery delivery{Helper::Delivery::Sampled};
  };

  /// The registration @p handle names, or nullopt for an unknown handle.
  static std::optional<Registration> registration(const Helper& helper, MonitoringHandle handle);
};

}  // namespace ua::detail
