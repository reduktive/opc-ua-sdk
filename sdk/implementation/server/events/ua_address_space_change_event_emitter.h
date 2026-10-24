// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ADDRESS_SPACE_CHANGE_EVENT_EMITTER_H
#define UA_ADDRESS_SPACE_CHANGE_EVENT_EMITTER_H

#include "ua_address_space_change_events.h"
#include "ua_logger.h"
#include "ua_sinks.h"

#include <cstdint>
#include <memory>
#include <optional>

namespace ua::server
{

/// Translates the address space's changes into OPC UA model and semantic Events, SourceNode the Server
/// Object.
class AddressSpaceChangeEventEmitter final
{
public:
  /// @param maxArrayLength The server's MaxArrayLength, which bounds an Event field (OPC 10000-5 6.3.2); none
  /// for
  ///                       no bound.
  explicit AddressSpaceChangeEventEmitter(std::weak_ptr<EventSink> eventSink, Logger logger = {},
    std::optional<uint32_t> maxArrayLength = std::nullopt);

  /// A Semantic change raises one SemanticChangeEvent. A Model change raises one GeneralModelChangeEvent
  /// listing its changes, or one BaseModelChangeEvent when it holds a change no verb names or more changes
  /// than MaxArrayLength (NR-36 rule 5.2; OPC 10000-3 9.32.7: one event, of one type, for an update).
  void emit(const ::ua::detail::AddressSpaceChange& change) noexcept;

private:
  std::weak_ptr<EventSink> mEventSink;
  Logger mLogger;
  std::optional<uint32_t> mMaxArrayLength;
};

}  // namespace ua::server

#endif  // UA_ADDRESS_SPACE_CHANGE_EVENT_EMITTER_H
