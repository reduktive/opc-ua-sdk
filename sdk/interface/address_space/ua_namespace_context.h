// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_CONTEXT_H
#define UA_NAMESPACE_CONTEXT_H

/// @file
/// @brief What the SDK gives a namespace when the address space registers it.
/// @ingroup address_space

#include "ua_defines.h"
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <span>

namespace ua
{

class Namespace;
struct ModelChangeReport;
struct SemanticChangeReport;

namespace default_ns
{
class NamespaceMonitoringSupport;
}  // namespace default_ns

namespace detail
{
class NamespaceRegistrationCoordinator;
struct NamespaceContextAccess;
struct NamespaceContextState;
}  // namespace detail

/// What the SDK gives a namespace: its index in the server's namespace array, and the monitoring helper of
/// its registration.
///
/// Only the address space creates a context, one per registration, and gives it to the registered object
/// through
/// @ref Namespace::attach, which accepts one context once. A namespace reads its index through
/// `Namespace::context()`; a namespace that forwards to another passes the context it was given on, by
/// calling the other's `attach` from its `on_attached`. Copies share the context.
///
/// When a registration fails, the namespace object keeps its context and cannot be attached again: the
/// application registers a new namespace object.
/// @ingroup address_space
class NamespaceContext
{
public:
  /// The index the namespace was registered at in the server's namespace array.
  ///
  /// May be called from any thread.
  /// @return The namespace index; 0 for the context `Namespace::context()` answers before its namespace is
  /// attached.
  uint16_t index() const noexcept;

  /// The monitoring helper of this registration: the one helper the context and every copy of it answer,
  /// which samples and delivers the namespace's monitored items (see `ua_namespace_monitoring_support.h`).
  ///
  /// The address space creates it with the registration, runs it on the address space's executor, and shuts
  /// it down in `AddressSpace::shutdown_async` before the namespaces. The context `Namespace::context()`
  /// answers before its namespace is attached answers a helper that refuses every create, modify and delete
  /// with `Bad_NotSupported` and the ErrorDetail `NamespaceNotRegistered`; a namespace therefore calls this
  /// each time rather than keeping the reference across its attach.
  ///
  /// May be called from any thread.
  /// @return The registration's helper, valid while this context or a copy of it lives.
  default_ns::NamespaceMonitoringSupport& monitoring() const noexcept;

  /// Reports changes the namespace made to its own Nodes itself, outside the address space's routes (NR-27,
  /// NR-36 rule 3): the model generation advances at once, and one ModelChangeEvent for @p changes is raised
  /// later, on the address space's executor (a GeneralModelChangeEvent listing the Nodes, or a
  /// BaseModelChangeEvent when a ValueRank or ArrayDimensions changed). A ViewContentChanged entry is listed
  /// in no event. The namespace advances each reported Node's NodeVersion before it reports (NR-55). An empty
  /// @p changes reports a change the namespace cannot describe, or one of Nodes that have no NodeVersion: the
  /// model generation advances and no event is raised.
  ///
  /// May be called from any thread, including from inside the namespace's own members while it holds its own
  /// locks: it copies @p changes and calls no namespace before it returns (NR-39 rule 6). Before the
  /// namespace is attached, after its registration failed or the address space shut down, and after the
  /// address space is gone, it does nothing.
  /// @param changes The changes made.
  void model_changed(std::span<const ModelChangeReport> changes) const noexcept;

  /// Reports that Properties with the SemanticChange flag (OPC 10000-3 5.6.2) changed their Value: one
  /// SemanticChangeEvent listing @p changes is raised later, on the address space's executor (NR-38).
  ///
  /// A namespace calls it for each change of such a Property's Value, whether a Write made it or the
  /// namespace itself, except the Value a Property is given first (NR-38 rule 1). With the monitoring helper,
  /// the call to @ref default_ns::NamespaceMonitoringSupport::property_value_changed answers whether an event
  /// is due. The SemanticsChanged bit of the owner's monitored items is set by that call, not by this one.
  ///
  /// May be called from any thread, also while the namespace holds its own locks: it copies @p changes and
  /// calls no namespace before it returns (NR-39 rule 6). Before the namespace is attached, after its
  /// registration failed or the address space shut down, and after the address space is gone, it does
  /// nothing.
  /// @param changes The owners of the changed Properties.
  void semantics_changed(std::span<const SemanticChangeReport> changes) const noexcept;

  /// Reports that this namespace changed the Value of at least one Variable whose AccessLevelEx has the
  /// Constant bit (OPC 10000-3 8.58), through a Write or by itself; the SDK then advances this namespace's
  /// ConfigurationVersion (NR-40). One call may cover any number of such changes, a Write request's, for
  /// example; a Value given when a Variable is created is not a change.
  ///
  /// The SDK finds the namespace's NamespaceMetadata Object as its publication does: the Object
  /// `Namespace::metadata_object()` declares, otherwise the child of Server.Namespaces whose BrowseName is
  /// the namespace's URI in its own index. It then writes the Object's ConfigurationVersion Property, through
  /// the namespace that holds it, to the larger of the current time as a VersionTime and its current Value
  /// plus 1 (OPC 10000-4 7.44). The advances of one namespace run one after another; changes reported while
  /// one runs are covered by the next.
  ///
  /// May be called from any thread, also while the namespace holds its own locks (NR-39 rule 6). The address
  /// space's shutdown waits for the advances it has queued (NR-67).
  /// @param completion Called once, on the address space's executor and never on the calling thread inside
  ///                   this member, so it cannot re-enter a lock the caller holds; after the advance that
  ///                   covers this change: Good, also when the namespace has no
  ///                   ConfigurationVersion; otherwise why ConfigurationVersion could not be advanced.
  /// @return Good when the advance was queued. `Bad_Shutdown` before the namespace is attached, after its
  ///         registration failed or the address space shut down, and after the address space is gone:
  ///         nothing was queued and @p completion is never called.
  [[nodiscard]] VoidResult constant_values_changed(std::function<void(VoidResult)> completion) const noexcept;

private:
  friend class detail::NamespaceRegistrationCoordinator;  // creates the context of each registration
  friend struct detail::NamespaceContextAccess;  // the SDK's namespaces read the address space's logger
  friend class Namespace;  // the context a namespace reads before it is attached

  explicit NamespaceContext(shared_ptr<const detail::NamespaceContextState> state) noexcept;

  shared_ptr<const detail::NamespaceContextState> mState;
};

}  // namespace ua

#endif  // UA_NAMESPACE_CONTEXT_H
