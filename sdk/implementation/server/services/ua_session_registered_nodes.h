// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_REGISTERED_NODES_H
#define UA_SESSION_REGISTERED_NODES_H

#include "ua_address_space.h"
#include "ua_logger.h"
#include "ua_node_id.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::server
{

/// The NodeIds one Session registered, per namespace, as each namespace's RegisterNodes delegate returned
/// them.
///
/// A namespace sees balanced register and unregister calls without tracking Sessions: UnregisterNodes
/// forwards only NodeIds this Session registered, and whatever the Session still holds when it ends is
/// unregistered then, one call per namespace. A RegisterNodes answer that reaches no client, because its
/// request or its Session ended first, is unregistered at once.
///
/// Thread-safe: a namespace answers on whatever thread it chooses, and the answer is recorded there.
class SessionRegisteredNodes
{
public:
  /// @param logger Receives a failed unregistration; nothing else is logged.
  explicit SessionRegisteredNodes(Logger logger);

  /// Records @p nodeIds as registered by this Session in namespace @p namespaceIndex.
  ///
  /// Once the Session has ended nothing is recorded: @p nodeIds are unregistered at once instead.
  ///
  /// @param addressSpace   Where the namespace is looked up for an unregistration at once.
  /// @param namespaceIndex The namespace whose delegate returned @p nodeIds.
  /// @param nodeIds        The NodeIds as the delegate returned them; a NodeId may appear more than once.
  void add(const WeakAddressSpace& addressSpace, uint16_t namespaceIndex, std::span<const NodeId> nodeIds);

  /// Removes, one registration per occurrence, the NodeIds of @p nodeIds that this Session holds in
  /// namespace @p namespaceIndex.
  ///
  /// @param namespaceIndex The namespace the NodeIds belong to.
  /// @param nodeIds        The NodeIds a Client asks to unregister.
  /// @return One entry per element of @p nodeIds: `true` when that NodeId was this Session's and has been
  ///         removed, `false` when the Session did not register it (Part 4 5.8.6.1: such NodeIds are
  ///         ignored).
  std::vector<bool> take(uint16_t namespaceIndex, std::span<const NodeId> nodeIds);

  /// Removes, one registration per occurrence, the NodeIds of @p nodeIds that this Session holds, whichever
  /// namespace registered them: a delegate may answer with a NodeId in another namespace, and its unregister
  /// goes to the namespace that registered it.
  ///
  /// @param nodeIds The NodeIds a Client asks to unregister.
  /// @return One entry per element of @p nodeIds: the index of the namespace that registered that NodeId when
  /// it
  ///         was this Session's and has been removed, empty when the Session did not register it (Part 4
  ///         5.8.6.1: such NodeIds are ignored). A NodeId registered by more than one namespace is taken from
  ///         its own namespace first.
  std::vector<std::optional<uint16_t>> take(std::span<const NodeId> nodeIds);

  /// Removes @p nodeIds from this Session's registrations and unregisters them at once, without awaiting
  /// the namespace; used for a RegisterNodes answer whose request ended before the answer arrived.
  ///
  /// @param addressSpace   Where the namespace is looked up.
  /// @param namespaceIndex The namespace whose delegate returned @p nodeIds.
  /// @param nodeIds        The NodeIds as the delegate returned them.
  void release(
    const WeakAddressSpace& addressSpace, uint16_t namespaceIndex, std::span<const NodeId> nodeIds);

  /// Ends this Session's registrations: everything still recorded is unregistered, one call per
  /// namespace, without awaiting the answers. Later calls to @ref add unregister at once. A second call
  /// does nothing.
  ///
  /// @param addressSpace Where each namespace is looked up; a namespace that is gone is skipped.
  void release_all(const WeakAddressSpace& addressSpace) noexcept;

  /// Asks namespace @p namespaceIndex's delegate to unregister @p nodeIds, posted to the address space's
  /// executor so that a call from inside a delegate's own answer does not call the delegate back from
  /// inside it; a failure is logged. Records nothing.
  void unregister_now(const WeakAddressSpace& addressSpace, uint16_t namespaceIndex,
    std::vector<NodeId> nodeIds) const noexcept;

private:
  Logger mLogger;
  mutable std::mutex mMutex;
  bool mEnded{false};
  std::unordered_map<uint16_t, std::unordered_map<NodeId, size_t>> mRegistered;
};

/// The RegisterNodes answers of one request. Each is recorded in the Session's registrations when its
/// namespace answers, on the namespace's own thread; unless the request's response is sent (@ref keep), all
/// of them are unregistered again when the request ends (@ref discard), however it ends - a failure,
/// a timeout, a cancel - and an answer that arrives after the request ended, with its response or without,
/// is unregistered at once.
class RegisterRequestAnswers
{
public:
  /// @param registry     The Session's registrations; never null.
  /// @param addressSpace Where each namespace is looked up for an unregistration.
  RegisterRequestAnswers(std::shared_ptr<SessionRegisteredNodes> registry, WeakAddressSpace addressSpace);

  /// Takes namespace @p namespaceIndex's answer, as its delegate gave it. Only the first answer of a
  /// namespace is the request's: a Good one is recorded while the request is open, and unregistered at once
  /// after @ref keep or @ref discard, as no response carries it. A later answer of the same namespace is
  /// unregistered at once when Good.
  ///
  /// @param namespaceIndex The namespace that answered.
  /// @param good           Whether the answer's batch status is not Bad, so that @p nodeIds were registered.
  /// @param nodeIds        The NodeIds the delegate returned.
  /// @return `true` for the namespace's first answer, which the request goes on to use.
  bool take_answer(uint16_t namespaceIndex, bool good, std::span<const NodeId> nodeIds);

  /// The request answers namespace @p namespaceIndex's items without its answer (its body failed): what that
  /// answer recorded is unregistered, and a later answer of the namespace is unregistered when it arrives.
  void release(uint16_t namespaceIndex) noexcept;

  /// The response is sent: the Session owns every answer recorded, and @ref discard does nothing.
  void keep() noexcept;

  /// The request ended without its response: every answer recorded is unregistered, and later ones are
  /// unregistered as they arrive. A second call does nothing.
  void discard() noexcept;

private:
  enum class State
  {
    Open,
    Kept,
    Discarded
  };

  std::shared_ptr<SessionRegisteredNodes> mRegistry;
  WeakAddressSpace mAddressSpace;
  std::mutex mMutex;
  State mState{State::Open};
  std::vector<std::pair<uint16_t, std::vector<NodeId>>> mRecorded;
  /// The namespaces that have answered, or whose answer was released.
  std::unordered_set<uint16_t> mAnswered;
};

}  // namespace ua::server

#endif  // !UA_SESSION_REGISTERED_NODES_H
