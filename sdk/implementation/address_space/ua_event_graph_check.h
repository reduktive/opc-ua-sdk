// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#ifndef UA_EVENT_GRAPH_CHECK_H
#define UA_EVENT_GRAPH_CHECK_H

#include "ua_address_space.h"
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <optional>

namespace ua::detail
{

/// The check behind @ref ua::AddressSpace::validate_event_graph_async (NR-54): OPC 10000-3 7.17 and 7.18 over the
/// Nodes of every namespace, read through the namespaces' batched members only.
///
/// 1. Each namespace's NodeIds, one `enumerate_nodes_async` per namespace. A namespace that declines is visited by
///    reachability: from the Server Object and every enumerated Node, along event-family References into it,
///    a round per step.
/// 2. Per round, one lookup per namespace of the Nodes reached, then their References in both directions with
///    HasEventSource and HasNotifier as the hint, every page, split by @p maxNodesPerBrowse.
/// 3. A ReferenceType is event-family when it is HasEventSource or HasNotifier, or its supertypes reach one of
///    them: namespace 0's types from the SDK's model of them, any other by walking its inverse HasSubtype, one
///    round per level.
/// 4. One lookup of the endpoints of event-family References not already looked up, for their NodeClass and
///    EventNotifier; then the endpoint rules and the loop check, in memory.
///
/// @p complete receives Good; the first violation found, `Bad_ReferenceNotAllowed` with its ErrorDetail; or,
/// when none was found but part of the graph was not read (a namespace that declined to enumerate, a lookup,
/// References read or ReferenceType walk that failed), `Uncertain_NotAllNodesAvailable` with the ErrorDetail
/// `EventGraphNotFullyChecked`, naming the namespaces that declined and caused by the first failure. An address
/// space that goes during the check answers `Bad_Shutdown` (`AddressSpaceGone`). @p complete is called once,
/// from the address space's executor, never on the caller's stack; the check holds the address space weakly.
void check_event_graph(const AddressSpace& addressSpace, std::optional<uint32_t> maxNodesPerBrowse,
  std::function<void(VoidResult)> complete) noexcept;

}  // namespace ua::detail

#endif  // !UA_EVENT_GRAPH_CHECK_H
