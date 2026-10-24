// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_BUS_TEST_ACCESS_H
#define UA_EVENT_BUS_TEST_ACCESS_H

#include "ua_event_bus.h"

#include "strand_test_access_base.h"

namespace ua::server
{

struct EventBusTestAccess : ua::test::StrandTestAccessBase<EventBusTestAccess, EventBus>
{
  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(EventBus& bus, StrandKey)
  {
    return bus.mDispatchStrand;
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  static constexpr auto sPendingDispatches = &EventBus::mPendingDispatches;
  static constexpr auto sEnqueueDispatch = &EventBus::enqueue_dispatch_on_strand;
  static constexpr auto sOnDispatchDropped = &EventBus::mOnDispatchDropped;
  static constexpr auto sResolveEventTypeDeclarations = &EventBus::resolve_event_type_declarations_async;
  static constexpr auto sResolveEventTypeHierarchy = &EventBus::resolve_event_type_hierarchy_async;
  static constexpr auto sDeclarationResolver = &EventBus::mDeclarationResolver;
};

}  // namespace ua::server

template<>
class ua::test::StrandGuard<ua::server::EventBusTestAccess>
{
  using TA = ua::server::EventBusTestAccess;

public:
  STRAND_GUARD_DATA(pending_dispatches, sPendingDispatches)
  STRAND_GUARD_DATA(on_dispatch_dropped, sOnDispatchDropped)
  STRAND_GUARD_METHOD(enqueue_dispatch, sEnqueueDispatch)
  STRAND_GUARD_METHOD(resolve_event_type_declarations, sResolveEventTypeDeclarations)
  STRAND_GUARD_METHOD(resolve_event_type_hierarchy, sResolveEventTypeHierarchy)
  STRAND_GUARD_DATA(declaration_resolver, sDeclarationResolver)

private:
  friend struct ua::test::StrandTestAccessBase<ua::server::EventBusTestAccess, ua::server::EventBus>;

  explicit StrandGuard(ua::server::EventBus& a) : mTarget(a)
  {}

  ua::server::EventBus& mTarget;
};

#endif  // UA_EVENT_BUS_TEST_ACCESS_H
