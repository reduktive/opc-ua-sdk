// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal interface carrying committed address-space semantic/model changes to the server.

#ifndef UA_ADDRESS_SPACE_CHANGE_EVENTS_H
#define UA_ADDRESS_SPACE_CHANGE_EVENTS_H

#include "ua_address_space.h"
#include "ua_node_id.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace ua::detail
{

enum class AddressSpaceChangeKind
{
  /// Properties flagged SemanticChange changed: one SemanticChangeEvent listing the owners in @ref
  /// AddressSpaceChange::changes (their verbs unused).
  Semantic,
  /// The model changes of one operation (NR-36 rule 5): one ModelChangeEvent.
  Model,
};

/// One entry of a GeneralModelChangeEvent (OPC 10000-5 12.16): the Node that changed, its TypeDefinition when
/// it is an Object or Variable, and the verbs (`ModelChangeStructureVerbMask`) of its changes.
struct ModelChangeEntry
{
  NodeId affected;
  NodeId affectedType;
  uint8_t verbs{0};
};

struct AddressSpaceChange
{
  AddressSpaceChangeKind kind{AddressSpaceChangeKind::Model};
  /// The Model kind's changed Nodes, each once; the Semantic kind's owners of the changed Properties.
  std::vector<ModelChangeEntry> changes;
  /// The Model kind holds a change no verb names (a ValueRank or ArrayDimensions change, or a NodeVersion a
  /// client wrote): the event is a BaseModelChangeEvent (OPC 10000-3 9.32.5, 9.32.7).
  bool unspecified{false};
};

/// Installs the server-owned receiver for committed model/semantic changes.
///
/// This is an internal friend interface rather than public AddressSpace API: applications publish their
/// own events through Server::events(), while the SDK server alone owns automatic conformance
/// events produced by mutations of its default namespaces.
class AddressSpaceChangeEvents
{
public:
  using Handler = std::function<void(const AddressSpaceChange&)>;

  static void set_handler(AddressSpace& addressSpace, Handler handler);
};

}  // namespace ua::detail

#endif  // UA_ADDRESS_SPACE_CHANGE_EVENTS_H
