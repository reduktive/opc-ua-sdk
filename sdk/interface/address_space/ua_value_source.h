// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The interface through which an application supplies and applies the Values of Variables.
/// @ingroup address_space

#ifndef UA_VALUE_SOURCE_H
#define UA_VALUE_SOURCE_H

#include "ua_data_value.h"
#include "ua_defines.h"
#include "ua_duration.h"
#include "ua_read_value_id.h"
#include "ua_request_info.h"
#include "ua_result.h"
#include "ua_write_value.h"

#include <functional>
#include <memory>
#include <span>

namespace ua
{

class Node;

/// The owner of the Values of one or more Variables: it produces a Value for each read and applies each
/// write.
///
/// Attached to a Variable with `ExternalValueSource::set_value_source`; one source may serve many Variables,
/// and receives each item's Variable so that it can tell them apart. The namespace that holds the Variables
/// calls each source once per request for all of that source's items (`read_async` for a Read or a sampling
/// tick, `write_async` for a Write), in item order.
///
/// **The source applies what a request asks of its data.** A read item's IndexRange selects the elements to
/// return (Part 4 7.27); a write item's IndexRange names the elements its partial Value replaces, and an
/// OptionSet write's ValidBits the bits it replaces (Part 3 OptionSet: "new value = (value & validBits) |
/// (current value & ~validBits)"). The SDK never merges on the source's behalf:
/// `index_range_utils::apply_write` and `merge_option_set_value` are the helpers. Before calling a source,
/// the namespace refuses a ranged access to a Scalar Variable whose DataType can hold neither a String nor a
/// ByteString with Bad_IndexRangeNoData.
///
/// **Lifetime.** The context, the items, every Node and every value they refer to are valid only until the
/// call returns: a source that answers later copies what it needs first. A source calls `complete` exactly
/// once per call, inline or later, with one result per item in item order.
///
/// **Thread safety.** Calls to one source may run concurrently, from any thread of the address space's
/// executor or the caller's.
///
/// **Monitoring.** A MonitoredItem on the Value at sampling interval 0 is fed by the source's reports, not
/// sampled, only when the Variable's MinimumSamplingInterval is 0: an explicit 0 is the source's claim that
/// it reports every change of the Value through `ExternalValueSource::notify_value_changed` (OPC 10000-4
/// 5.12.1.2: interval 0 "indicates that the data item is exception-based"). With the MinimumSamplingInterval
/// absent, or any other figure, the item is sampled through `read_async` at the subscription's tick. A source
/// whose Value differs per caller cannot report it, since a report pushes one Value to every item: its
/// Variable's MinimumSamplingInterval is -1 or the source's own figure, and its items are sampled for each
/// subscription's current caller. How an item is fed is decided when it is created or modified, so a source
/// attached later does not change it. A committed write is reported to items fed by reports with the Value
/// the source then holds, read back whole with no caller, so a source that clamps, rounds or converts what it
/// is given is reported as a Read sees it.
/// @ingroup address_space
class ValueSource
{
public:
  /// Shared by every item of one read call. Valid only until `read_async` returns.
  struct ReadContext
  {
    /// The request the read serves: its deadline, its cancellation and its locales.
    const RequestInfo& request;
    /// The Session on whose behalf the Value is read, or null for the server's own reads. A source whose
    /// Value differs per caller answers from it.
    const CallerInfo* caller;
    /// Part 4 5.10.2.2: 0 asks for the source to be read, the maximum Int32 or more accepts a Value the
    /// source already holds, and anything between a Value no older than that many milliseconds. A source may
    /// always answer freshly.
    Duration maxAge;
    /// Whether the caller wants the SourceTimestamp on the returned Value.
    bool setSourceTimestamp;
  };

  /// One Variable to read. Valid only until `read_async` returns.
  struct ReadItem
  {
    /// The Variable; `attributes()` gives its DataType, ValueRank, BrowseName and the others.
    const Node& node;
    /// Its NodeId, the IndexRange to apply and the DataEncoding the service asked for.
    const ReadValueId& value;
  };

  /// Shared by every item of one write call. Valid only until `write_async` returns.
  struct WriteContext
  {
    /// The request the write serves.
    const RequestInfo& request;
    /// The Session on whose behalf the Value is written, or null for the server's own writes.
    const CallerInfo* caller;
  };

  /// One Variable to write. Valid only until `write_async` returns.
  struct WriteItem
  {
    /// The Variable.
    const Node& node;
    /// Its NodeId, the IndexRange or the ValidBits to apply, and the DataValue.
    const WriteValue& value;
  };

  /// What a source tells about a write it applied.
  struct Written
  {
    /// The write gave the Variable its first Value. A Property's first Value is not a semantic change, and
    /// raises no SemanticChangeEvent; a source that leaves this false has every write counted as a change.
    bool initial{false};
  };

  /// One write item's answer.
  using WriteResult = Result<Written>;

  ValueSource() = default;
  virtual ~ValueSource() = default;
  ValueSource(const ValueSource&) = delete;
  ValueSource& operator=(const ValueSource&) = delete;
  ValueSource(ValueSource&&) = delete;
  ValueSource& operator=(ValueSource&&) = delete;

  /// Produces the Value of each of @p items, then calls @p complete once, with one result per item in item
  /// order.
  ///
  /// A read whose items all have this source is passed to it with the caller's completion unchanged, so that
  /// the namespace allocates nothing, and the namespace holds the source only until this member returns. A
  /// source that answers after returning therefore keeps itself alive until it calls @p complete (for example
  /// by holding a `shared_ptr` to itself in the work it starts), as a Variable given another source drops its
  /// reference to this one. A write is held until it is answered.
  /// @param context Context of the read; borrowed for this invocation.
  /// @param items Values to read, in the order their results are returned.
  /// @param complete Receives one value or rich error result per item.
  virtual void read_async(const ReadContext& context, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) = 0;

  /// Applies each of @p items, then calls @p complete once, with one result per item in item order. The
  /// default answers Bad_NotWritable for every item: a source that does not override it is read-only.
  /// @param context Context of the write; borrowed for this invocation.
  /// @param items Values to write, in the order their results are returned.
  /// @param complete Receives one write result or rich error per item.
  virtual void write_async(const WriteContext& context, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete);

  /// One read of one Variable, for a source written as a function (@ref make_value_source). The arguments are
  /// valid only until it returns; it calls its completion once.
  using ReadValueHandler = std::function<void(
    const ReadContext&, const Node&, const ReadValueId&, std::function<void(DataValueResult)>)>;

  /// One write of one Variable, for a source written as a function (@ref make_value_source). The arguments
  /// are valid only until it returns; it calls its completion once.
  using WriteValueHandler = std::function<void(
    const WriteContext&, const Node&, const WriteValue&, std::function<void(WriteResult)>)>;
};

/// A source that answers each item through @p read or @p write, one item at a time; with no @p write it is
/// read-only, and answers every write Bad_NotWritable. @p read must not be empty.
/// @param read Handler invoked for each value read; must not be empty.
/// @param write Optional handler invoked for each value write; absent means read-only.
/// @return An owned value source that retains the supplied handlers.
/// @throws std::invalid_argument when @p read is empty.
[[nodiscard]] std::shared_ptr<ValueSource> make_value_source(
  ValueSource::ReadValueHandler read, ValueSource::WriteValueHandler write = {});

}  // namespace ua

#endif  // UA_VALUE_SOURCE_H
