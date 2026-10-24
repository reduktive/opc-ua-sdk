// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_EVENT_BACKBONE_OPS_H
#define UA_CONNECTION_EVENT_BACKBONE_OPS_H

/// @file
/// @brief The real @ref ua::client::detail::EventBackboneOps (section 8.13) implementation  -  a leaf shim
/// that
///        weak-references @ref ua::client::detail::ConnectionImpl and forwards the three backbone wire
///        operations (create Subscription+event MI, ModifyMonitoredItems filter, delete MI+Subscription) to
///        it. Mirrors @ref ua::client::detail::RealSessionOps / @ref ua_connection_ops.h: the shim only
///        weak-refs `ConnectionImpl`, so no strong cycle forms (ConnectionImpl owns the subscriber Impl,
///        which weak-holds this shim).
/// @ingroup client

#include "ua_event_backbone_ops.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace ua::client::detail
{

class ConnectionImpl;

/// Forwards @ref EventBackboneOps to @ref ConnectionImpl (weak). A gone `ConnectionImpl` completes with
/// `Bad_ConnectionClosed`  -  the subscriber then treats the backbone as un-creatable.
class ConnectionEventBackboneOps final : public EventBackboneOps,
                                         public std::enable_shared_from_this<ConnectionEventBackboneOps>
{
public:
  [[nodiscard]] static std::shared_ptr<ConnectionEventBackboneOps> create(
    std::weak_ptr<ConnectionImpl> connection);

  void create_backbone_async(ua::NodeId notifier, ua::EventFilter filter, std::uint32_t clientHandle,
    std::uint32_t queueSize,
    std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept override;

  void modify_backbone_filter_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::uint32_t clientHandle, ua::EventFilter filter,
    std::function<void(ua::Result<EventFilterDiagnostics>)> callback) noexcept override;

  void delete_backbone_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::function<void(ua::VoidResult)> callback) noexcept override;

  /// Walks the server's `HasSubtype` hierarchy forward from @p roots, one Browse per frontier level, and
  /// returns roots-plus-descendants. Bounded by @ref sMaxSubtypeNodes and @ref sMaxSubtypeDepth so a
  /// pathological (or hostile) hierarchy cannot turn one subscribe into an unbounded browse walk; hitting
  /// either bound is reported as a BAD Result rather than a silently truncated closure, because a partial
  /// closure would drop exactly the events it failed to enumerate.
  void resolve_event_subtypes_async(std::vector<ua::NodeId> roots,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept override;

private:
  /// Ceiling on the total types one closure may contain. The standard event hierarchy is ~60 types; a
  /// server with more than this is either unusual or hostile, and either way the dedicated-backbone
  /// fallback is the safe answer.
  static constexpr std::size_t sMaxSubtypeNodes = 512;
  /// Ceiling on the depth walked below a root (the standard hierarchy is ~6 deep).
  static constexpr std::size_t sMaxSubtypeDepth = 16;

  struct SubtypeWalk;
  static void continue_subtype_walk(
    std::shared_ptr<ConnectionEventBackboneOps> self, std::shared_ptr<SubtypeWalk> walk);

  explicit ConnectionEventBackboneOps(std::weak_ptr<ConnectionImpl> connection);

  std::weak_ptr<ConnectionImpl> mConnection;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_EVENT_BACKBONE_OPS_H
