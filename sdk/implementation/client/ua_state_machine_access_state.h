// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_ACCESS_STATE_H
#define UA_STATE_MACHINE_ACCESS_STATE_H

/// @file
/// @brief The strand-free per-handle state the StateMachine typed handles own (client design section 8.18.2),
/// shared
///        between the handle implementation and the @ref ua::client::StateMachineAccessor factory that
///        constructs it. The state hierarchy mirrors the handle hierarchy
///        (`StateMachineHandleState`  to  `FiniteStateMachineHandleState`  to
///        `ProgramStateMachineHandleState`) so the base handle's `shared_ptr<StateMachineHandleState>` can
///        point at the most-derived object and the derived handles reach their extra fields by a checked
///        down-cast.
/// @ingroup client

#include "ua_state_machine_access.h"

#include "ua_logger.h"
#include "ua_node_id.h"

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::client::detail
{

class WireOps;
class SupportOps;

/// The interface refs + resolved child node ids every StateMachine handle carries (client design
/// section 8.18.2). Held by a `std::shared_ptr` so every wire-op completion can weak-capture it and bail
/// cleanly if the handle was dropped mid-flight (section 9.8.3). The ONLY back-references are @ref wireOps /
/// @ref supportOps, `weak_ptr`s to the two narrow upward-interface roles  -  never a
/// `weak_ptr<ConnectionImpl>` (section 8.2A.13)
/// -  so no self-owning cycle can form. The child node ids are resolved once at handle construction (the
/// CurrentState / LastTransition components and their Id / TransitionTime Properties) and are const
/// thereafter.
///
/// Polymorphic (virtual destructor) so the base handle's `shared_ptr<StateMachineHandleState>` can own a
/// derived state object and the derived handles can `dynamic_cast` / `static_cast` down to their level
/// safely.
struct StateMachineHandleState
{
  StateMachineHandleState() = default;
  StateMachineHandleState(const StateMachineHandleState&) = delete;
  StateMachineHandleState& operator=(const StateMachineHandleState&) = delete;
  StateMachineHandleState(StateMachineHandleState&&) = delete;
  StateMachineHandleState& operator=(StateMachineHandleState&&) = delete;
  virtual ~StateMachineHandleState() = default;

  std::weak_ptr<WireOps> wireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<SupportOps> supportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor executor;  ///< where results / boundary failures are delivered
  ua::Logger logger;  ///< logs advisory wire-boundary outcomes (CL-DIAG-002/-015)
  ua::NodeId machineId;  ///< the state-machine Object the handle targets

  ua::NodeId currentStateNodeId;  ///< the CurrentState component (Mandatory, CL-SM-001)
  ua::NodeId currentStateIdNodeId;  ///< the CurrentState.Id Property (Mandatory, CL-SM-003)
  std::optional<ua::NodeId> lastTransitionNodeId;  ///< the LastTransition component (Optional, CL-SM-004)
  std::optional<ua::NodeId> lastTransitionIdNodeId;  ///< the LastTransition.Id Property
  std::optional<ua::NodeId> lastTransitionTimeNodeId;  ///< the LastTransition.TransitionTime Property
};

/// `FiniteStateMachineType` per-handle state (client design section 8.18.2, CL-SM-005). Adds the cached
/// topology plus the `AvailableStates` / `AvailableTransitions` Property node ids used to re-resolve it
/// (`refresh_topology_async`).
///
/// The topology is published as an immutable `shared_ptr<const vector<...>>` held in a
/// `std::atomic<...>` (client design section 8.18.2): a refresh BUILDS a fresh vector and atomically replaces
/// the pointer, and the synchronous accessors atomically LOAD it  -  so a reader never tears against a
/// concurrent refresh under a multi-threaded `io_context`. The atomics are seeded with empty (non-null)
/// shared vectors so every accessor sees a valid snapshot even before the first resolution. `shared_ptr`
/// copies observe the same atomics, so a refresh through one copy is visible to all.
struct FiniteStateMachineHandleState : StateMachineHandleState
{
  std::atomic<std::shared_ptr<const std::vector<AvailableState>>> availableStates{
    std::make_shared<const std::vector<AvailableState>>()};  ///< published topology; atomic-replaced on
                                                             ///< refresh
  std::atomic<std::shared_ptr<const std::vector<AvailableTransition>>> availableTransitions{
    std::make_shared<const std::vector<AvailableTransition>>()};  ///< published; atomic-replaced on refresh
  std::optional<ua::NodeId> availableStatesNodeId;  ///< the AvailableStates Property node (for refresh)
  std::optional<ua::NodeId> availableTransitionsNodeId;  ///< the AvailableTransitions Property node

  /// Where the published snapshot came from, stored through an atomic on the same discipline as the two
  /// vectors above and replaced in the same `publish_topology` call. Seeded non-null so an accessor on an
  /// unresolved handle reads "nothing published, enrichment complete" rather than dereferencing null.
  std::atomic<std::shared_ptr<const TopologyProvenance>> provenance{
    std::make_shared<const TopologyProvenance>()};
};

/// `ProgramStateMachineType` per-handle state (client design section 8.18.2, CL-SM-007..009). Adds the
/// resolved method node ids (keyed by ns0 method BrowseName, e.g. "Start" / "Halt") used by
/// `can_invoke_async` / `invoke_async`.
struct ProgramStateMachineHandleState : FiniteStateMachineHandleState
{
  std::map<std::string, ua::NodeId> methodNodeIds;  ///< resolved method nodes by BrowseName (at construction)
};

}  // namespace ua::client::detail

#endif  // UA_STATE_MACHINE_ACCESS_STATE_H
