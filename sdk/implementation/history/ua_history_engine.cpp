// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_engine.h"

#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_guid.h"
#include "ua_history_event_field_list.h"
#include "ua_namespace_route.h"
#include "ua_numeric_range_parser.h"
#include "ua_qualified_name.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status.h"
#include "ua_to_result.h"
#include "ua_variant.h"

#include <array>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <string_view>

#include <algorithm>
#include <any>
#include <cstddef>
#include <optional>
#include <type_traits>
#include <utility>

namespace ua::history
{

namespace
{

using ua::DataValue;
using ua::DateTime;
using ua::ModificationInfo;
using ua::StatusCode;

// Opaque field keys for the two BaseEventType fields the store windows and identifies events by.
// StoredEvent::time / ::event_id are derived from these entries (see history_store.h); the engine
// keeps them in StoredEvent::fields too so a read can project a Time/EventId select clause.
constexpr std::string_view timeFieldKey = "Time";
constexpr std::string_view eventIdFieldKey = "EventId";
constexpr ua::StatusCodeValue historianLocationMask = 0x03u;
constexpr ua::StatusCodeValue historianInterpolated = 0x02u;

StatusCode interpolated_status(StatusCode base = StatusCode{ua::Status::Good})
{
  StatusCode status{
    (base.as_uint32() & ~historianLocationMask) | historianInterpolated, base.shared_detail()};
  status.info_type_data_value(true);
  return status;
}

DateTime source_ts(const DataValue& dv)
{
  return dv.source_timestamp().value_or(DateTime{});
}

DataValue bound_placeholder(DateTime when)
{
  // A requested bound with no value present is reported as a Bad_BoundNotFound placeholder at the
  // requested time (OPC 10000-11 section 6.4.3.2). It counts toward numValuesPerNode.
  DataValue dv{StatusCode{ua::Status::BadBoundNotFound}};
  dv.source_timestamp() = when;
  return dv;
}

std::optional<DateTime> opt(bool present, DateTime value)
{
  return present ? std::optional<DateTime>{value} : std::nullopt;
}

// Part 11 6.4: an IndexRange selects the same elements from every historical value. A value with nothing in
// the range - a scalar, a shorter array - is returned with Bad_IndexRangeNoData in its place, and a value
// that already carries a Bad status keeps it. When no value at all has data in the range, the operation
// itself is Bad_IndexRangeNoData.
StatusCode slice_history_values(std::vector<DataValue>& values, const ua::ParsedNumericRange& range)
{
  bool anyData = false;
  for (auto& value : values)
  {
    const auto& valueStatus = value.status();
    if (valueStatus && valueStatus.value().is_bad())
      continue;
    auto sliced = ua::index_range_utils::apply_read(value.value(), range);
    if (!sliced.is_good())
    {
      value.value() = Variant{};
      value.status() = StatusCode{ua::Status::BadIndexRangeNoData};
      continue;
    }
    value.value() = std::move(sliced).value();
    anyData = true;
  }
  return anyData || values.empty() ? StatusCode{ua::Status::Good}
                                   : StatusCode{ua::Status::BadIndexRangeNoData};
}

// The status codes of the store answers one operation, or one entry of an update, has used.
//
// A store may answer a Good subcode or an Uncertain code together with its data (HistoryStore failure
// contract). The engine works with the data and passes the code on, so the Client receives the code the
// store gave and not a plain Good the store did not give. take() returns an answer's data and keeps its
// code; an answer without data throws, as Result::value() does, and the to_result around the operation
// turns the throw into the operation's error result. put_on() answers the kept codes on the operation's
// result and over() on an entry's operationResult. Two kept codes are combined by
// ua::detail::combined_status: the worse severity, else a code with a SubCode, else the later answer.
// A continuation cursor carries code() to the pages resumed from it. A read the engine decides an update or a
// deletion on is not taken when the store answered it Uncertain: uncertain_read_refused() refuses it first.
class StoreAnswers
{
public:
  StoreAnswers() = default;

  // Starts from @p kept, the code a continuation cursor carries from the answers of the earlier pages.
  explicit StoreAnswers(StatusCode kept) : mCode(std::move(kept))
  {}

  // The data of @p answer, whose code is kept. Throws a UaException carrying the answer's status and
  // detail when the answer holds no data.
  template<class T>
    requires(!std::is_void_v<T>)
  [[nodiscard]] T take(ua::Result<T>&& answer)
  {
    if (answer.has_value())
      mCode = ua::detail::combined_status(mCode, answer.status_code());
    return std::move(answer).value();
  }

  // Keeps the code of a write that is Good or Uncertain. A Bad write throws a UaException carrying its
  // status and detail.
  void take(const ua::VoidResult& answer)
  {
    if (answer.is_bad())
      throw ua::UaException{answer.status_code().as_status(), answer.shared_detail()};
    mCode = ua::detail::combined_status(mCode, answer.status_code());
  }

  // The operationResult of an entry the engine settled as @p own (Good_EntryInserted, Good_EntryReplaced,
  // Good): @p own when every kept code is plain Good, otherwise the kept code.
  [[nodiscard]] StatusCode over(const StatusCode& own) const
  {
    return ua::detail::combined_status(own, mCode);
  }

  // The kept code: plain Good when every answer was plain Good.
  [[nodiscard]] const StatusCode& code() const
  {
    return mCode;
  }

  // @p result with the kept code combined into its own when it holds a value and the kept code is not
  // plain Good; otherwise @p result unchanged.
  template<class T>
  [[nodiscard]] ua::Result<T> put_on(ua::Result<T> result) const
  {
    if (!result.has_value() || mCode.as_uint32() == StatusCode{ua::Status::Good}.as_uint32())
      return result;
    StatusCode combinedStatus = ua::detail::combined_status(result.status_code(), mCode);
    return ua::Result<T>{std::move(result).value(), std::move(combinedStatus)};
  }

private:
  StatusCode mCode{ua::Status::Good};
};

// The refusal of a store read the engine would decide an update or a deletion on (whether an entry exists,
// the values a delete removes) when the store answered it Uncertain, with or without data: the engine changes
// nothing on an answer the store is uncertain of. Bad_InternalError (ReadAnswerUncertain) whose cause is the
// store's code with its detail; nullopt for a Good or Bad answer, which take() handles.
template<class T>
std::optional<StatusCode> uncertain_read_refused(const ua::Result<T>& answer)
{
  if (!answer.is_uncertain())
    return std::nullopt;
  return ua::detail::read_failure(answer.status_code(), "HistoryEngine");
}

}  // namespace

namespace
{

// The edge of @p walk a page starts from: the lower bound walking forward, the upper walking back.
std::optional<DateTime>& near_edge(HistoryWindowWalk& walk)
{
  return walk.order == Direction::After ? walk.lower : walk.upper;
}

bool& near_edge_inclusive(HistoryWindowWalk& walk)
{
  return walk.order == Direction::After ? walk.lowerInclusive : walk.upperInclusive;
}

// The next page of the window in walk order, with the walk moved past it. With @p want unset the rest of
// the window is read; otherwise at most @p want rows are returned and @p more says whether the window
// holds more. The store is asked for one row beyond the page, which answers @p more, and, when an earlier
// page ended part-way through the rows at one time, for the rows at that time it already returned, which
// are skipped. A read therefore holds one page, never the window: the window is bounded by the request's
// times, not by the size of the archive.
template<class Row, class ReadWindow, class TimeOf>
std::vector<Row> next_page(
  HistoryWindowWalk& walk, std::optional<uint32_t> want, bool& more, ReadWindow&& readWindow, TimeOf&& timeOf)
{
  const uint64_t skip = walk.returnedAtNearEdge;
  uint32_t limit = 0;
  if (want)
  {
    const uint64_t asked = skip + uint64_t{*want} + 1;
    limit = static_cast<uint32_t>(std::min<uint64_t>(asked, std::numeric_limits<uint32_t>::max()));
  }
  std::vector<Row> rows =
    readWindow(walk.lower, walk.lowerInclusive, walk.upper, walk.upperInclusive, limit, walk.order);
  const size_t first = static_cast<size_t>(std::min<uint64_t>(skip, rows.size()));
  const size_t last = want ? std::min(rows.size(), first + size_t{*want}) : rows.size();
  more = want.has_value() && rows.size() > last;
  std::vector<Row> page(std::make_move_iterator(rows.begin() + static_cast<std::ptrdiff_t>(first)),
    std::make_move_iterator(rows.begin() + static_cast<std::ptrdiff_t>(last)));
  if (!page.empty())
  {
    const DateTime edge = timeOf(page.back());
    auto& nearEdge = near_edge(walk);
    if (!more || !(timeOf(rows[last]) == edge))
    {
      // No row at the page's last time is left: the walk resumes after it.
      nearEdge = edge;
      near_edge_inclusive(walk) = false;
      walk.returnedAtNearEdge = 0;
    }
    else
    {
      // The next row shares the page's last time: the walk resumes at that time and skips the rows at it
      // already returned, those of this page and, when the page holds nothing else, of the pages before.
      uint32_t atEdge = 0;
      for (auto it = page.rbegin(); it != page.rend() && timeOf(*it) == edge; ++it)
        ++atEdge;
      if (atEdge == page.size() && nearEdge && *nearEdge == edge && near_edge_inclusive(walk))
        atEdge += walk.returnedAtNearEdge;
      nearEdge = edge;
      near_edge_inclusive(walk) = true;
      walk.returnedAtNearEdge = atEdge;
    }
  }
  return page;
}

// The window of a raw, modified or event read in the store's terms. Forward [start, end); reverse when
// endTime < startTime, or when only endTime is given: (end, start], or t <= end.
HistoryWindowWalk initial_walk(bool startSpec, DateTime start, bool endSpec, DateTime end)
{
  HistoryWindowWalk walk;
  const bool reverse = (startSpec && endSpec && end < start) || (!startSpec && endSpec);
  if (!reverse)
  {
    walk.lower = opt(startSpec, start);
    walk.lowerInclusive = true;
    walk.upper = opt(endSpec, end);
    walk.upperInclusive = false;
    walk.order = Direction::After;
  }
  else if (startSpec)
  {
    walk.lower = end;
    walk.lowerInclusive = false;
    walk.upper = start;
    walk.upperInclusive = true;
    walk.order = Direction::Before;
  }
  else
  {
    walk.lower = std::nullopt;
    walk.lowerInclusive = true;
    walk.upper = end;
    walk.upperInclusive = true;
    walk.order = Direction::Before;
  }
  return walk;
}

std::optional<uint32_t> page_limit(uint32_t cap)
{
  return cap > 0 ? std::optional<uint32_t>{cap} : std::nullopt;
}

// ExtraData bit: a returned raw value that hides a modification record (i.e. was later modified) carries
// the ExtraData StatusCode info bit so the Client knows it can issue a ReadModified (OPC 10000-11 section
// 3.1 / section 6.4.3.2). Bound placeholders (Bad_BoundNotFound) are not real entries and are skipped.
// Asked for the values of the page only.
void mark_extra_data(
  HistoryStore& store, StoreAnswers& answers, const ua::NodeId& node, std::vector<DataValue>& page)
{
  for (auto& dv : page)
  {
    if (!dv.source_timestamp().has_value())
      continue;
    StatusCode status = dv.status().value_or(StatusCode{});
    if (status.as_uint32() == StatusCode{ua::Status::BadBoundNotFound}.as_uint32())
      continue;
    if (answers.take(store.has_modification_at(node, *dv.source_timestamp())))
    {
      status.extra_data(true);
      dv.status() = status;
    }
  }
}

// The bound returned after the window: the value nearest @p at in @p direction, or a Bad_BoundNotFound
// placeholder at @p at (OPC 10000-11 section 6.4.3.2).
DataValue trailing_bound(
  HistoryStore& store, StoreAnswers& answers, const ua::NodeId& node, DateTime at, Direction direction)
{
  auto bound = answers.take(store.read_nearest_value(node, at, direction, /*inclusive*/ true));
  return bound ? *bound : bound_placeholder(at);
}

}  // namespace

HistoryEngine::ReadRawItemResult HistoryEngine::read_raw(HistoryStore& store, ReadRawItem& item)
{
  // A malformed IndexRange is the operation's Bad_IndexRangeInvalid, before any history is read (Part
  // 4 7.27).
  std::optional<ua::ParsedNumericRange> range;
  if (!item.indexRange.empty())
  {
    auto parsed = ua::parse_numeric_range(item.indexRange);
    if (!parsed.is_good())
      return ReadRawItemResult{parsed.status_code(), parsed.shared_detail()};
    range = std::move(parsed).value();
  }

  ReadRawItemResult raw = [&]
  {
    // Continuation request: the next page of the window the cursor holds the position in.
    if (item.cursor.has_value())
      return resume_raw(store, item);
    // returnBounds is not permitted when reading Modified values (Part 11 section 6.4.3.3).
    if (item.isReadModified && item.returnBounds)
      return ReadRawItemResult{StatusCode{ua::Status::BadInvalidArgument}};
    return item.isReadModified ? read_modified_fresh(store, item) : read_raw_fresh(store, item);
  }();

  if (range && raw.has_value())
  {
    const auto sliced = slice_history_values(raw.value().values, *range);
    if (!sliced.is_good())
      return ReadRawItemResult{sliced};
  }
  return raw;
}

HistoryEngine::ReadRawItemResult HistoryEngine::resume_raw(HistoryStore& store, ReadRawItem& item)
{
  auto* cursor = std::any_cast<RawCursor>(&(*item.cursor));
  // A continuation point resumes the read of the node it was issued for and of no other.
  if (!cursor || !(cursor->node == item.nodeId))
    return ReadRawItemResult{StatusCode{ua::Status::BadContinuationPointInvalid}};

  // Every page of an answer carries the codes the store answered it with, from the first page on.
  StoreAnswers answers{cursor->answerCode};
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadRawSuccess
    {
      const auto& node = cursor->node;
      const uint32_t page = cursor->pageSize;
      ua::NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      bool more = false;
      if (!cursor->windowDone)
      {
        if (cursor->modified)
        {
          auto mods = next_page<ModifiedValue>(
            cursor->walk,
            page_limit(page),
            more,
            [&](auto lower,
              bool lowerInclusive,
              auto upper,
              bool upperInclusive,
              uint32_t limit,
              Direction order)
            {
              return answers.take(
                store.read_modifications(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
            },
            [](const ModifiedValue& mod) { return source_ts(mod.value); });
          success.values.reserve(mods.size());
          success.modificationInfos.reserve(mods.size());
          for (auto& mod : mods)
          {
            success.values.push_back(std::move(mod.value));
            success.modificationInfos.push_back(std::move(mod.info));
          }
        }
        else
        {
          success.values = next_page<DataValue>(
            cursor->walk,
            page_limit(page),
            more,
            [&](auto lower,
              bool lowerInclusive,
              auto upper,
              bool upperInclusive,
              uint32_t limit,
              Direction order) {
              return answers.take(
                store.read_values(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
            },
            source_ts);
        }
      }

      bool trailingPending = false;
      if (!more && cursor->trailingBoundAt)
      {
        if (page == 0 || success.values.size() < page)
          success.values.push_back(
            trailing_bound(store, answers, node, *cursor->trailingBoundAt, cursor->trailingBoundDirection));
        else
          trailingPending = true;
      }
      if (!cursor->modified)
        mark_extra_data(store, answers, node, success.values);

      if (more || trailingPending)
      {
        RawCursor next = *cursor;
        next.windowDone = !more;
        next.answerCode = answers.code();
        success.cursor = Cursor{std::move(next)};
      }
      return success;
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::ReadRawItemResult HistoryEngine::read_raw_fresh(HistoryStore& store, ReadRawItem& item)
{
  // A store answer without data throws from answers.take() below; to_result turns the throw into this
  // item's error Result (StatusCode + ErrorDetail), per the HistoryStore failure contract. The codes of
  // the answers with data go on the item's Result with the values.
  StoreAnswers answers;
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadRawSuccess
    {
      const bool startSpec = !item.startTime.is_null();
      const bool endSpec = !item.endTime.is_null();
      const DateTime start = item.startTime;
      const DateTime end = item.endTime;
      const bool doBounds = item.returnBounds;  // modified+bounds already rejected in read_raw()
      const auto& node = item.nodeId;
      const uint32_t cap = item.maxValuesPerNode;

      ua::NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      std::vector<DataValue> page;

      if (startSpec && endSpec && start == end)
      {
        // Single-timestamp request (Part 11 section 6.4.3.2): time flows forward, "just one value", and
        // never a continuation point.
        if (doBounds)
        {
          auto startBound =
            answers.take(store.read_nearest_value(node, start, Direction::Before, /*inclusive*/ true));
          auto endBound =
            answers.take(store.read_nearest_value(node, start, Direction::After, /*inclusive*/ false));
          page.push_back(startBound ? *startBound : bound_placeholder(start));
          page.push_back(endBound ? *endBound : bound_placeholder(end));
        }
        else if (auto exact = answers.take(store.read_value_at(node, start)))
        {
          page.push_back(*exact);
        }
        if (cap > 0 && page.size() > cap)
          page.resize(cap);
        mark_extra_data(store, answers, node, page);
        success.values = std::move(page);
        return success;
      }

      HistoryWindowWalk walk = initial_walk(startSpec, start, endSpec, end);
      const bool reverse = walk.order == Direction::Before;

      // The leading bound, before the window: forward, the value at/before start unless it is exactly
      // start (then it is the window's first value); reverse, the value at/after start unless it is exactly
      // start. A missing bound is a Bad_BoundNotFound placeholder at start.
      if (doBounds && !reverse)
      {
        auto startBound =
          answers.take(store.read_nearest_value(node, start, Direction::Before, /*inclusive*/ true));
        if (!startBound)
          page.push_back(bound_placeholder(start));
        else if (source_ts(*startBound) < start)
          page.push_back(*startBound);
      }
      else if (doBounds && reverse && startSpec && endSpec)
      {
        auto highBound =
          answers.take(store.read_nearest_value(node, start, Direction::After, /*inclusive*/ true));
        if (!highBound)
          page.push_back(bound_placeholder(start));
        else if (source_ts(*highBound) > start)
          page.push_back(*highBound);
      }

      // The trailing bound, after the window: forward, the first value at/after end; reverse, the value
      // at/before end.
      std::optional<DateTime> trailingAt;
      if (doBounds && endSpec && (!reverse || startSpec))
        trailingAt = end;
      const Direction trailingDirection = reverse ? Direction::Before : Direction::After;

      // numValuesPerNode cap + continuation point. A continuation point is issued only for a bounded
      // multi-value range (startTime AND endTime AND numValuesPerNode, startTime != endTime); an
      // open-ended start+num / end+num request returns up to num values with no continuation (Part 11
      // section 6.4.3.2). Bounds count toward the cap because they are part of the returned sequence.
      const std::optional<uint32_t> want =
        cap > 0 ? std::optional<uint32_t>{cap - static_cast<uint32_t>(std::min<size_t>(cap, page.size()))}
                : std::nullopt;
      bool more = false;
      auto window = next_page<DataValue>(
        walk,
        want,
        more,
        [&](auto lower, bool lowerInclusive, auto upper, bool upperInclusive, uint32_t limit, Direction order)
        {
          return answers.take(
            store.read_values(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
        },
        source_ts);
      page.insert(page.end(), std::make_move_iterator(window.begin()), std::make_move_iterator(window.end()));

      bool trailingPending = false;
      if (!more && trailingAt)
      {
        if (cap == 0 || page.size() < cap)
          page.push_back(trailing_bound(store, answers, node, *trailingAt, trailingDirection));
        else
          trailingPending = true;
      }
      mark_extra_data(store, answers, node, page);
      success.values = std::move(page);

      if ((more || trailingPending) && startSpec && endSpec)
      {
        RawCursor next;
        next.node = node;
        next.walk = walk;
        next.trailingBoundAt = trailingAt;
        next.trailingBoundDirection = trailingDirection;
        next.windowDone = !more;
        next.pageSize = cap;
        next.answerCode = answers.code();
        success.cursor = Cursor{std::move(next)};
      }
      return success;
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::ReadRawItemResult HistoryEngine::read_modified_fresh(HistoryStore& store, ReadRawItem& item)
{
  StoreAnswers answers;
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadRawSuccess
    {
      const bool startSpec = !item.startTime.is_null();
      const bool endSpec = !item.endTime.is_null();
      const auto& node = item.nodeId;
      const uint32_t cap = item.maxValuesPerNode;

      // Modified read has the same direction rules as raw but never returns bounds and always works the
      // modification-record store (Part 11 section 6.4.3.3). All replaced values at a timestamp are returned.
      HistoryWindowWalk walk = initial_walk(startSpec, item.startTime, endSpec, item.endTime);
      bool more = false;
      auto mods = next_page<ModifiedValue>(
        walk,
        page_limit(cap),
        more,
        [&](auto lower, bool lowerInclusive, auto upper, bool upperInclusive, uint32_t limit, Direction order)
        {
          return answers.take(
            store.read_modifications(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
        },
        [](const ModifiedValue& mod) { return source_ts(mod.value); });

      ua::NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      success.values.reserve(mods.size());
      success.modificationInfos.reserve(mods.size());
      for (auto& mod : mods)
      {
        success.values.push_back(std::move(mod.value));
        success.modificationInfos.push_back(std::move(mod.info));
      }
      if (more && startSpec && endSpec)
      {
        RawCursor next;
        next.node = node;
        next.modified = true;
        next.walk = walk;
        next.pageSize = cap;
        next.answerCode = answers.code();
        success.cursor = Cursor{std::move(next)};
      }
      return success;
    });
  return answers.put_on(std::move(result));
}

namespace
{

DataValue no_data_at(DateTime when)
{
  DataValue dv{StatusCode{ua::Status::BadNoData}};
  dv.source_timestamp() = when;
  return dv;
}

// Build a StoredEvent from an event's field-value list and the filter that describes those fields.
// The field key for select clause i is the join of its browse-path names; events[i] is its value.
StoredEvent to_stored_event(const ua::EventFilter& filter, const ua::HistoryEventFieldList& fields)
{
  StoredEvent event;
  const auto& clauses = filter.select_clauses();
  const auto& values = fields.event_fields();
  for (size_t i = 0; i < clauses.size() && i < values.size(); ++i)
    event.fields[HistoryEngine::field_key(clauses[i])] = values[i];

  if (auto it = event.fields.find(std::string{timeFieldKey}); it != event.fields.end())
    if (const auto* time = it->second.try_as<DateTime>())
      event.time = *time;
  if (auto it = event.fields.find(std::string{eventIdFieldKey}); it != event.fields.end())
    if (const auto* id = it->second.try_as<ua::ByteString>())
      event.eventId = *id;
  return event;
}

// Deterministic fallback EventId from the event Time (little-endian ticks). The spec requires the
// server to supply an EventId when the client does not (Part 11 section 6.8.4); a real historian would use
// a globally-unique id  -  the time-derived id is adequate for the reference example.
// The server-supplied EventId when the client provides none (Part 11 section 6.8.4). A fresh random v4 UUID
// guarantees global uniqueness (no collision when two events share a Time), matching how OPC UA
// servers generate EventIds; the 16-byte GUID is carried opaquely in the EventId ByteString.
ua::ByteString generate_event_id()
{
  const std::array<ua::byte, ua::Guid::length> bytes = ua::Guid::create_and_generate().as_ua_binary();
  return ua::ByteString{std::span<const ua::byte>{bytes}};
}

ModificationInfo modification(ua::HistoryUpdateType type, std::string_view userName)
{
  // OPC 10000-11 section 6.5.3: modificationTime and userName are optional. We stamp the time the
  // modification was made and the session user when one is available (empty userName  to  left null,
  // which is permitted, READ-013).
  ModificationInfo info;
  info.update_type() = type;
  info.modification_time() = DateTime::now();
  if (!userName.empty())
    info.user_name() = ua::String{userName};
  return info;
}

}  // namespace

HistoryEngine::ReadAtTimeItemResult HistoryEngine::read_at_time(
  HistoryStore& store, const ReadAtTimeItem& item)
{
  std::optional<ua::ParsedNumericRange> range;
  if (!item.indexRange.empty())
  {
    auto parsed = ua::parse_numeric_range(item.indexRange);
    if (!parsed.is_good())
      return ReadAtTimeItemResult{parsed.status_code(), parsed.shared_detail()};
    range = std::move(parsed).value();
  }

  ReadAtTimeItemResult atTime = [&]() -> ReadAtTimeItemResult
  {
    StoreAnswers answers;
    auto values = ua::detail::to_result(
      [&]() -> ua::NamespaceHistoryDelegate::HistoryReadAtTimeSuccess
      {
        ua::NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
        success.values.reserve(item.timestamps.size());

        for (const DateTime reqTime : item.timestamps)
        {
          // Exact raw value: return as-is.
          if (auto exact = answers.take(store.read_value_at(item.nodeId, reqTime)))
          {
            success.values.push_back(*exact);
            continue;
          }

          auto before = answers.take(
            store.read_nearest_value(item.nodeId, reqTime, Direction::Before, /*inclusive*/ false));
          auto after = answers.take(
            store.read_nearest_value(item.nodeId, reqTime, Direction::After, /*inclusive*/ false));

          if (!before)
          {
            // No value at/before the requested time  to  cannot determine a value (section 6.4.5.2).
            success.values.push_back(no_data_at(reqTime));
            continue;
          }

          const double* beforeNum = before->value().try_as<double>();
          const double* afterNum = after ? after->value().try_as<double>() : nullptr;

          DataValue result;
          if (!item.useSimpleBounds && after && beforeNum && afterNum)
          {
            // Sloped (linear) interpolation between the two bounding values.
            const int64_t t0 =
              before->source_timestamp().value_or(DateTime{}).value().time_since_epoch().count();
            const int64_t t1 =
              after->source_timestamp().value_or(DateTime{}).value().time_since_epoch().count();
            const int64_t t = reqTime.value().time_since_epoch().count();
            const double fraction =
              t1 == t0 ? 0.0 : static_cast<double>(t - t0) / static_cast<double>(t1 - t0);
            const double interpolated = *beforeNum + (*afterNum - *beforeNum) * fraction;
            result = DataValue{ua::Variant{interpolated}, interpolated_status(), reqTime};
          }
          else
          {
            // SimpleBounds, non-numeric, or only the before bound available  to  hold the value at/before.
            result = *before;
            result.source_timestamp() = reqTime;
            result.status() = interpolated_status(result.status().value_or(StatusCode{ua::Status::Good}));
          }
          success.values.push_back(std::move(result));
        }

        return success;
      });
    return answers.put_on(std::move(values));
  }();
  if (range && atTime.has_value())
  {
    const auto sliced = slice_history_values(atTime.value().values, *range);
    if (!sliced.is_good())
      return ReadAtTimeItemResult{sliced};
  }
  return atTime;
}

namespace
{
using Origin = ua::NamespaceHistoryDelegate::HistoryReadEventsSuccess::EventOrigin;

/// The archived event's SourceNode and EventType, when the archive recorded them (the field keys the
/// engine stores them under are the browse names, see field_key). Null when absent or not a NodeId.
Origin origin_of(const StoredEvent& event)
{
  Origin origin;
  const auto nodeField = [&event](const char* key) -> ua::NodeId
  {
    const auto found = event.fields.find(key);
    if (found == event.fields.end() || !found->second.is_node_id())
      return ua::NodeId{};
    return found->second.as<ua::NodeId>();
  };
  origin.sourceNode = nodeField("SourceNode");
  origin.eventType = nodeField("EventType");
  return origin;
}
}  // namespace

std::string HistoryEngine::field_key(const ua::SimpleAttributeOperand& operand)
{
  std::string key;
  for (const auto& name : operand.browse_path())
  {
    if (!key.empty())
      key += '/';
    key.append(std::string_view{name.name()});  // namespace index ignored for the reference
  }
  return key;
}

namespace
{

// One archived event projected onto the select clauses: one Variant per clause, in order. A field the
// event does not hold is Bad_NoData when the EventType model declares it, else null.
ua::HistoryEventFieldList project_event(const StoredEvent& event, const std::vector<std::string>& keys,
  const std::vector<StatusCode>& modelStatuses)
{
  ua::HistoryEventFieldList row;
  for (size_t clauseIndex = 0; clauseIndex < keys.size(); ++clauseIndex)
  {
    auto found = event.fields.find(keys[clauseIndex]);
    if (found != event.fields.end())
      row.event_fields().push_back(found->second);
    else if (clauseIndex < modelStatuses.size() && modelStatuses[clauseIndex].is_good())
      row.event_fields().push_back(ua::Variant{StatusCode{ua::Status::BadNoData}});
    else
      row.event_fields().push_back(ua::Variant{});
  }
  return row;
}

// The next page of events of @p walk, projected, with the walk moved past it. @p more says whether the
// window holds more events.
ua::NamespaceHistoryDelegate::HistoryReadEventsSuccess next_events_page(HistoryStore& store,
  StoreAnswers& answers, const ua::NodeId& node, HistoryWindowWalk& walk, uint32_t cap,
  const std::vector<std::string>& keys, const std::vector<StatusCode>& modelStatuses, bool& more)
{
  auto events = next_page<StoredEvent>(
    walk,
    page_limit(cap),
    more,
    [&](auto lower, bool lowerInclusive, auto upper, bool upperInclusive, uint32_t limit, Direction order) {
      return answers.take(
        store.read_events(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
    },
    [](const StoredEvent& event) { return event.time; });

  ua::NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
  success.events.reserve(events.size());
  success.origins.reserve(events.size());
  for (const auto& event : events)
  {
    success.origins.push_back(origin_of(event));
    success.events.push_back(project_event(event, keys, modelStatuses));
  }
  return success;
}

}  // namespace

HistoryEngine::ReadEventsItemResult HistoryEngine::read_events(HistoryStore& store, ReadEventsItem& item)
{
  if (item.cursor.has_value())
    return resume_events(store, item);

  StoreAnswers answers;
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadEventsSuccess
    {
      std::vector<std::string> keys;
      keys.reserve(item.filter.select_clauses().size());
      for (const auto& clause : item.filter.select_clauses())
        keys.push_back(field_key(clause));

      const bool startSpec = !item.startTime.is_null();
      const bool endSpec = !item.endTime.is_null();
      HistoryWindowWalk walk = initial_walk(startSpec, item.startTime, endSpec, item.endTime);
      bool more = false;
      auto success = next_events_page(
        store, answers, item.nodeId, walk, item.maxValuesPerNode, keys, item.selectClauseModelStatuses, more);
      if (more && startSpec && endSpec)
      {
        EventsCursor next;
        next.node = item.nodeId;
        next.walk = walk;
        next.keys = std::move(keys);
        next.selectClauseModelStatuses = item.selectClauseModelStatuses;
        next.pageSize = item.maxValuesPerNode;
        next.answerCode = answers.code();
        success.cursor = Cursor{std::move(next)};
      }
      return success;
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::ReadEventsItemResult HistoryEngine::resume_events(HistoryStore& store, ReadEventsItem& item)
{
  auto* cursor = std::any_cast<EventsCursor>(&(*item.cursor));
  // A continuation point resumes the read of the node it was issued for and of no other.
  if (!cursor || !(cursor->node == item.nodeId))
    return ReadEventsItemResult{StatusCode{ua::Status::BadContinuationPointInvalid}};
  // ...and with the select clauses it was issued for: the server authorizes the fields of the request
  // in hand, so projecting a page with other clauses would return fields that check never covered.
  // OPC 10000-11 6.3 leaves a changed HistoryReadDetails on a continuation to the Server.
  const auto& clauses = item.filter.select_clauses();
  if (clauses.size() != cursor->keys.size() ||
      !std::ranges::equal(clauses, cursor->keys, {}, [](const auto& clause) { return field_key(clause); }))
    return ReadEventsItemResult{StatusCode{ua::Status::BadContinuationPointInvalid,
      ua::ErrorDetail::build("ContinuationFilterChanged",
        "The continuation's select clauses differ from those its continuation point was issued for",
        "HistoryEngine")}};

  // Every page of an answer carries the codes the store answered it with, from the first page on.
  StoreAnswers answers{cursor->answerCode};
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadEventsSuccess
    {
      bool more = false;
      auto success = next_events_page(store,
        answers,
        cursor->node,
        cursor->walk,
        cursor->pageSize,
        cursor->keys,
        cursor->selectClauseModelStatuses,
        more);
      if (more)
      {
        EventsCursor next = *cursor;
        next.answerCode = answers.code();
        success.cursor = Cursor{std::move(next)};
      }
      return success;
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::UpdateDataItemResult HistoryEngine::update_data(
  HistoryStore& store, const UpdateDataItem& item, std::string_view userName)
{
  return ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      success.operationResults.reserve(item.values.size());

      // A store refusal is that entry's answer, not the item's. Part 11 sections 6.9.2.2 and 6.9.2.4
      // both put Bad_OutOfRange on "the related operationResults entry", so a bulk upload spanning
      // the edge of the archive stores what it can and reports only what it cannot. Calling
      // `.value()` on the store's Result instead threw, and `to_result` turned the throw into a
      // failure of the whole item - the entries either side of the offending one silently unapplied
      // and an empty operationResults array where the per-entry verdicts should have been.
      // A write the store accepts gives the entry the engine's own code (Good_EntryInserted,
      // Good_EntryReplaced) only when the store answered every call for the entry plain Good; a Good
      // subcode or an Uncertain code the store answered for the entry is the entry's answer instead.
      const auto attempt = [](StoreAnswers& entry, const ua::VoidResult& written, const StatusCode& onSuccess)
      {
        if (written.is_bad())
          return written.status_code();
        entry.take(written);
        return entry.over(onSuccess);
      };

      // Replace and an Update of an existing entry record the stored value as replaced, then write the
      // new one. A refused record is the entry's answer, and the new value is not written.
      const auto replace = [&](StoreAnswers& entry, const DataValue& dv, DateTime ts)
      {
        auto stored = store.read_value_at(item.nodeId, ts);
        if (auto refusal = uncertain_read_refused(stored))
          return std::move(*refusal);
        const ua::VoidResult recorded = store.insert_modification(item.nodeId,
          *entry.take(std::move(stored)),
          modification(ua::HistoryUpdateType::Replace, userName));
        if (recorded.is_bad())
          return recorded.status_code();
        entry.take(recorded);
        return attempt(entry, store.insert_value(item.nodeId, dv), StatusCode{ua::Status::GoodEntryReplaced});
      };

      for (const auto& dv : item.values)
      {
        if (!dv.source_timestamp().has_value())
        {
          success.operationResults.push_back(StatusCode{ua::Status::BadInvalidArgument});
          continue;
        }
        const DateTime ts = *dv.source_timestamp();
        StoreAnswers entry;
        auto found = store.read_value_at(item.nodeId, ts);
        if (auto refusal = uncertain_read_refused(found))
        {
          success.operationResults.push_back(std::move(*refusal));
          continue;
        }
        const bool exists = entry.take(std::move(found)).has_value();

        switch (item.performInsertReplace)
        {
        case ua::PerformUpdateType::Insert:
          if (exists)
          {
            success.operationResults.push_back(StatusCode{ua::Status::BadEntryExists});
          }
          else
          {
            // First write of data at this timestamp creates no modification record. Part 11 section
            // 6.8.2.4 permits a modified value on an insert or a replace but does not require one
            // (section 6.4.3.3 says the same for data first added), so this is our choice, not a rule.
            success.operationResults.push_back(
              attempt(entry, store.insert_value(item.nodeId, dv), StatusCode{ua::Status::GoodEntryInserted}));
          }
          break;

        case ua::PerformUpdateType::Replace:
          if (!exists)
          {
            success.operationResults.push_back(StatusCode{ua::Status::BadNoEntryExists});
          }
          else
          {
            success.operationResults.push_back(replace(entry, dv, ts));
          }
          break;

        case ua::PerformUpdateType::Update:
          if (exists)
          {
            success.operationResults.push_back(replace(entry, dv, ts));
          }
          else
          {
            success.operationResults.push_back(
              attempt(entry, store.insert_value(item.nodeId, dv), StatusCode{ua::Status::GoodEntryInserted}));
          }
          break;

        case ua::PerformUpdateType::Remove:
        default:
          // Remove is not valid for UpdateData (it has its own Delete* details).
          success.operationResults.push_back(StatusCode{ua::Status::BadInvalidArgument});
          break;
        }
      }

      return success;
    });
}

HistoryEngine::DeleteItemResult HistoryEngine::delete_raw(
  HistoryStore& store, const DeleteRawItem& item, std::string_view userName)
{
  StoreAnswers answers;
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      // Record each deleted value as a Delete modification before erasing, so ReadModified still sees
      // the history of removals and the Raw read can set the ExtraData bit.
      // An Uncertain answer about what to delete is refused before anything is deleted: the refusal is the
      // operation's error result.
      std::vector<DataValue> deleted;
      if (item.startTime == item.endTime)
      {
        auto exact = store.read_value_at(item.nodeId, item.startTime);
        if (auto refusal = uncertain_read_refused(exact))
          throw ua::UaException{std::move(*refusal)};
        if (auto value = answers.take(std::move(exact)))
          deleted.push_back(std::move(*value));
      }
      else
      {
        auto range = store.read_values(item.nodeId,
          std::optional<DateTime>{item.startTime},
          true,
          std::optional<DateTime>{item.endTime},
          false,
          0,
          Direction::After);
        if (auto refusal = uncertain_read_refused(range))
          throw ua::UaException{std::move(*refusal)};
        deleted = answers.take(std::move(range));
      }
      for (const auto& dv : deleted)
      {
        answers.take(
          store.insert_modification(item.nodeId, dv, modification(ua::HistoryUpdateType::Delete, userName)));
        answers.take(store.delete_value_at(item.nodeId, source_ts(dv)));
      }

      return ua::NamespaceHistoryDelegate::HistoryUpdateSuccess{};
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::DeleteItemResult HistoryEngine::delete_at_time(
  HistoryStore& store, const DeleteAtTimeItem& item, std::string_view userName)
{
  return ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      success.operationResults.reserve(item.timestamps.size());

      // The codes of the store's answers for a timestamp are that entry's answer when not plain Good.
      for (const auto& ts : item.timestamps)
      {
        StoreAnswers entry;
        auto found = store.read_value_at(item.nodeId, ts);
        if (auto refusal = uncertain_read_refused(found))
        {
          success.operationResults.push_back(std::move(*refusal));
          continue;
        }
        auto existing = entry.take(std::move(found));
        if (!existing)
        {
          success.operationResults.push_back(StatusCode{ua::Status::BadNoEntryExists});
          continue;
        }
        entry.take(store.insert_modification(
          item.nodeId, *existing, modification(ua::HistoryUpdateType::Delete, userName)));
        entry.take(store.delete_value_at(item.nodeId, ts));
        success.operationResults.push_back(entry.over(StatusCode{ua::Status::Good}));
      }

      return success;
    });
}

HistoryEngine::UpdateEventsItemResult HistoryEngine::update_events(
  HistoryStore& store, const UpdateEventsItem& item)
{
  return ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      success.operationResults.reserve(item.events.size());

      for (const auto& eventFields : item.events)
      {
        StoredEvent event = to_stored_event(item.filter, eventFields);
        const ua::ByteString suppliedId = event.eventId;
        // The codes of the store's answers for this event are its entry's answer when not plain Good.
        StoreAnswers entry;
        bool exists = false;
        if (!suppliedId.empty())
        {
          auto found = store.read_event(item.nodeId, suppliedId);
          if (auto refusal = uncertain_read_refused(found))
          {
            success.operationResults.push_back(std::move(*refusal));
            continue;
          }
          exists = entry.take(std::move(found)).has_value();
        }

        switch (item.performInsertReplace)
        {
        case ua::PerformUpdateType::Insert:
          if (exists)
          {
            success.operationResults.push_back(StatusCode{ua::Status::BadEntryExists});
            continue;
          }
          break;

        case ua::PerformUpdateType::Replace:
          if (!exists)
          {
            success.operationResults.push_back(StatusCode{ua::Status::BadNoEntryExists});
            continue;
          }
          (void)entry.take(store.delete_event(item.nodeId, suppliedId));
          break;

        case ua::PerformUpdateType::Update:
          if (exists)
            (void)entry.take(store.delete_event(item.nodeId, suppliedId));
          break;

        case ua::PerformUpdateType::Remove:
        default:
          success.operationResults.push_back(StatusCode{ua::Status::BadInvalidArgument});
          continue;
        }

        // Assign a server-generated EventId when the client supplied none, and reflect it back into the
        // stored fields so a subsequent read returns it.
        if (event.eventId.empty())
        {
          event.eventId = generate_event_id();
          event.fields[std::string{eventIdFieldKey}] = ua::Variant{event.eventId};
        }
        entry.take(store.insert_event(item.nodeId, event));
        const ua::Status outcome =
          item.performInsertReplace == ua::PerformUpdateType::Update
            ? (exists ? ua::Status::GoodEntryReplaced : ua::Status::GoodEntryInserted)
            : ua::Status::Good;
        success.operationResults.push_back(entry.over(StatusCode{outcome}));
      }

      return success;
    });
}

HistoryEngine::DeleteItemResult HistoryEngine::delete_events(
  HistoryStore& store, const DeleteEventsItem& item)
{
  return ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      success.operationResults.reserve(item.eventIds.size());

      for (const auto& eventId : item.eventIds)
      {
        StoreAnswers entry;
        const bool deleted = entry.take(store.delete_event(item.nodeId, eventId));
        success.operationResults.push_back(
          deleted ? entry.over(StatusCode{ua::Status::Good}) : StatusCode{ua::Status::BadNoEntryExists});
      }

      return success;
    });
}

HistoryEngine::ReadAnnotationItemResult HistoryEngine::read_annotations(
  HistoryStore& store, const ReadAnnotationItem& item)
{
  StoreAnswers answers;
  auto result = ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryReadAnnotationSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryReadAnnotationSuccess success;
      success.values.reserve(item.reqTimes.size());

      for (const DateTime reqTime : item.reqTimes)
      {
        if (auto annotation = answers.take(store.read_annotation_at(item.nodeId, reqTime)))
          success.values.push_back(std::move(*annotation));
        else
          success.values.push_back(no_data_at(reqTime));
      }

      return success;
    });
  return answers.put_on(std::move(result));
}

HistoryEngine::UpdateStructureDataItemResult HistoryEngine::update_structure_data(
  HistoryStore& store, const UpdateStructureDataItem& item)
{
  return ua::detail::to_result(
    [&]() -> ua::NamespaceHistoryDelegate::HistoryUpdateSuccess
    {
      ua::NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      success.operationResults.reserve(item.values.size());

      for (const auto& entry : item.values)
      {
        if (!entry.source_timestamp().has_value())
        {
          success.operationResults.push_back(StatusCode{ua::Status::BadInvalidArgument});
          continue;
        }
        const DateTime ts = *entry.source_timestamp();
        // The codes of the store's answers for this entry are its answer when not plain Good.
        StoreAnswers answers;
        auto found = store.read_annotation_at(item.nodeId, ts);
        if (auto refusal = uncertain_read_refused(found))
        {
          success.operationResults.push_back(std::move(*refusal));
          continue;
        }
        const bool exists = answers.take(std::move(found)).has_value();

        switch (item.performInsertReplace)
        {
        case ua::PerformUpdateType::Insert:
          if (exists)
            success.operationResults.push_back(StatusCode{ua::Status::BadEntryExists});
          else
          {
            answers.take(store.insert_annotation(item.nodeId, entry));
            success.operationResults.push_back(answers.over(StatusCode{ua::Status::GoodEntryInserted}));
          }
          break;

        case ua::PerformUpdateType::Replace:
          if (!exists)
            success.operationResults.push_back(StatusCode{ua::Status::BadNoEntryExists});
          else
          {
            answers.take(store.insert_annotation(item.nodeId, entry));
            success.operationResults.push_back(answers.over(StatusCode{ua::Status::GoodEntryReplaced}));
          }
          break;

        case ua::PerformUpdateType::Update:
          answers.take(store.insert_annotation(item.nodeId, entry));
          success.operationResults.push_back(
            answers.over(StatusCode{exists ? ua::Status::GoodEntryReplaced : ua::Status::GoodEntryInserted}));
          break;

        case ua::PerformUpdateType::Remove:
          if (!exists)
            success.operationResults.push_back(StatusCode{ua::Status::BadNoEntryExists});
          else
          {
            answers.take(store.delete_annotation_at(item.nodeId, ts));
            success.operationResults.push_back(answers.over(StatusCode{ua::Status::Good}));
          }
          break;

        default:
          success.operationResults.push_back(StatusCode{ua::Status::BadInvalidArgument});
          break;
        }
      }

      return success;
    });
}

}  // namespace ua::history
