// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_address_space_change_event_emitter.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_base_model_change_event_payload.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_semantic_change_event_payload.h"
#include "ua_semantic_change_structure_data_type.h"

#include <algorithm>

namespace ua::server
{

namespace
{

// The SDK raises its model and semantic change events in the context of the whole AddressSpace: the
// SourceNode is the Server Object and the SourceName is "Server" (Part 5 6.4.31, 6.4.33).
void fill_change_base(BaseEvent& event, string_view message)
{
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Server";
  event.message = LocalizedText{"", message};
  event.severity = 100;
}

}  // namespace

AddressSpaceChangeEventEmitter::AddressSpaceChangeEventEmitter(
  std::weak_ptr<EventSink> eventSink, Logger logger, std::optional<uint32_t> maxArrayLength)
  : mEventSink(std::move(eventSink)), mLogger(std::move(logger)), mMaxArrayLength(maxArrayLength)
{}

void AddressSpaceChangeEventEmitter::emit(const detail::AddressSpaceChange& change) noexcept
{
  try
  {
    auto sink = mEventSink.lock();
    if (!sink)
    {
      throw UaException{Status::BadShutdown,
        ErrorDetail::build("AddressSpaceChangeEventSinkUnavailable",
          "The Event sink is unavailable while reporting an AddressSpace change",
          "AddressSpaceChangeEventEmitter")};
    }

    if (change.kind == detail::AddressSpaceChangeKind::Semantic)
    {
      // An Event field holds at most MaxArrayLength entries: a longer list is raised as several Events.
      const std::size_t perEvent =
        mMaxArrayLength && *mMaxArrayLength != 0 ? std::size_t{*mMaxArrayLength} : change.changes.size();
      for (std::size_t begin = 0; begin < change.changes.size(); begin += perEvent)
      {
        const std::size_t end = std::min(change.changes.size(), begin + perEvent);
        Array<RefStructure<Structure>> changes;
        changes.reserve(end - begin);
        for (std::size_t i = begin; i < end; ++i)
        {
          auto entry = std::make_unique<SemanticChangeStructureDataType>();
          entry->affected() = change.changes[i].affected;
          entry->affected_type() = change.changes[i].affectedType;
          changes.emplace_back(std::move(entry));
        }
        SemanticChangeEventPayload event;
        fill_change_base(event, "AddressSpace semantics changed");
        event.changes = Variant{std::move(changes)};
        sink->emit(event);
      }
      return;
    }

    // Part 3 9.32.5: a BaseModelChangeEvent "does not contain information about the changes but only
    // indicates that changes occurred"; it stands for a change no verb names, and for a list longer than an
    // Event field may be.
    if (change.unspecified || change.changes.empty() ||
        (mMaxArrayLength && *mMaxArrayLength != 0 && change.changes.size() > *mMaxArrayLength))
    {
      BaseModelChangeEventPayload event;
      fill_change_base(event, "The AddressSpace changed");
      sink->emit(event);
      return;
    }
    Array<RefStructure<Structure>> changes;
    changes.reserve(change.changes.size());
    for (const auto& changed : change.changes)
    {
      auto entry = std::make_unique<ModelChangeStructureDataType>();
      entry->affected() = changed.affected;
      entry->affected_type() = changed.affectedType;
      entry->verb() = changed.verbs;
      changes.emplace_back(std::move(entry));
    }
    GeneralModelChangeEventPayload event;
    fill_change_base(event, "The AddressSpace changed");
    event.changes = Variant{std::move(changes)};
    sink->emit(event);
  }
  catch (...)
  {
    async::detail::report_guarded_exception(mLogger, "AddressSpaceChangeEventEmitter::emit");
  }
}

}  // namespace ua::server
