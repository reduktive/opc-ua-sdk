// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_ACCESS_TEST_ACCESS_H
#define UA_STATE_MACHINE_ACCESS_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::StateMachineAccessor and the StateMachine typed
/// handles
///        over fake interface roles, for the StateMachine unit suite (see the design specification).
///
/// A friend of the accessor + every typed handle. It adds NO public constructor: it builds each facade /
/// per-handle state directly and hands them to the private constructors, so the whole StateMachine surface
/// can be exercised against a `FakeWireOps` / `FakeSupportOps` with no real `ConnectionImpl`.

#include "ua_state_machine_access.h"
#include "ua_state_machine_access_state.h"

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <utility>

namespace ua::client::detail
{

/// Friend constructor for the StateMachine unit tests.
struct StateMachineClientTestAccess
{
  /// Builds a @ref StateMachineAccessor over @p wireOps / @p supportOps delivering on @p executor.
  static StateMachineAccessor make_accessor(std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger = {})
  {
    return StateMachineAccessor{
      std::move(wireOps), std::move(supportOps), std::move(executor), std::move(logger)};
  }

  /// Builds a base @ref StateMachineHandle directly over a pre-populated state (bypasses the async factory),
  /// so the read paths can be exercised with a known resolution.
  static StateMachineHandle make_handle(std::shared_ptr<StateMachineHandleState> state)
  {
    return StateMachineHandle{std::move(state)};
  }

  /// Builds a @ref FiniteStateMachineHandle directly over a pre-populated state.
  static FiniteStateMachineHandle make_finite_handle(std::shared_ptr<FiniteStateMachineHandleState> state)
  {
    return FiniteStateMachineHandle{std::move(state)};
  }

  /// Builds a @ref ProgramStateMachineHandle directly over a pre-populated state.
  static ProgramStateMachineHandle make_program_handle(
    std::shared_ptr<ProgramStateMachineHandleState> state, bool skipLocalStateCheck = false)
  {
    return ProgramStateMachineHandle{std::move(state), skipLocalStateCheck};
  }
};

}  // namespace ua::client::detail

#endif  // UA_STATE_MACHINE_ACCESS_TEST_ACCESS_H
