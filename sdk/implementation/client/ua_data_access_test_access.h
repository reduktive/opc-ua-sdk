// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_ACCESS_TEST_ACCESS_H
#define UA_DATA_ACCESS_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::DataAccessAccessor, a @ref
/// ua::client::PropertyAccessor,
///        and the DA typed handles over fake interface roles, for the DataAccess unit suite (see
///        the design specification).
///
/// A friend of the accessors + every typed handle. It adds NO public constructor: it builds each facade /
/// per-handle state directly and hands them to the private constructors, so the whole DA surface can be
/// exercised against a `FakeWireOps` / `FakeSupportOps` with no real `ConnectionImpl`.

#include "ua_data_access.h"
#include "ua_data_access_state.h"
#include "ua_property_accessor.h"

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <utility>

namespace ua::client::detail
{

/// Friend constructor for the DataAccess / PropertyAccessor unit tests.
struct DataAccessClientTestAccess
{
  /// Builds a @ref DataAccessAccessor over @p wireOps / @p supportOps delivering on @p executor.
  static DataAccessAccessor make_accessor(std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger = {})
  {
    return DataAccessAccessor{
      std::move(wireOps), std::move(supportOps), std::move(executor), std::move(logger)};
  }

  /// Builds a @ref PropertyAccessor targeting @p nodeId over the fake interface roles.
  static PropertyAccessor make_property_accessor(ua::NodeId nodeId, std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger = {})
  {
    return PropertyAccessor{
      std::move(nodeId), std::move(wireOps), std::move(supportOps), std::move(executor), std::move(logger)};
  }

  /// Builds an @ref AnalogItemHandle directly over a pre-populated state (bypasses the async factory), so the
  /// read / write / filter paths can be exercised with a known Property snapshot.
  static AnalogItemHandle make_analog_handle(std::shared_ptr<AnalogItemState> state)
  {
    return AnalogItemHandle{std::move(state)};
  }

  static TwoStateDiscreteHandle make_two_state_handle(std::shared_ptr<TwoStateDiscreteState> state)
  {
    return TwoStateDiscreteHandle{std::move(state)};
  }

  static MultiStateDiscreteHandle make_multi_state_discrete_handle(
    std::shared_ptr<MultiStateDiscreteState> state)
  {
    return MultiStateDiscreteHandle{std::move(state)};
  }

  static MultiStateValueDiscreteHandle make_multi_state_value_handle(
    std::shared_ptr<MultiStateValueDiscreteState> state)
  {
    return MultiStateValueDiscreteHandle{std::move(state)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_DATA_ACCESS_TEST_ACCESS_H
