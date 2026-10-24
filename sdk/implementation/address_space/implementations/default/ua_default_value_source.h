// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DEFAULT_VALUE_SOURCE_H
#define UA_DEFAULT_VALUE_SOURCE_H

#include "ua_data_value.h"
#include "ua_duration.h"
#include "ua_result.h"
#include "ua_value_source.h"
#include "ua_write_value.h"

#include <functional>
#include <mutex>
#include <optional>

namespace ua::default_ns
{

/// The source a Variable of the in-memory namespace gets when it is written while no source is attached
/// (COMP-DEFAULT-NODE-ATTR-STORAGE-03). It holds that Variable's one Value; the Variable holds no Value
/// itself, only its source (DL-115 (2)), and attaching another source replaces this one as a whole.
///
/// It is an ordinary ValueSource: a read applies the item's IndexRange, and a write applies its IndexRange
/// or ValidBits to the Value held (NR-11 rule 3), atomically under the source's lock (NR-11 rule 4). The
/// in-memory namespace also calls the synchronous members directly, so that reading or writing a Variable on
/// its default source makes no source call and allocates no completion (NR-13a).
class DefaultValueSource final : public ValueSource
{
public:
  /// A write's outcome: for a write that merged, the whole Value it left held (a whole write's is the written
  /// Value, not copied again); and whether the write gave the Variable its first Value (NR-38 rule 1).
  struct Stored
  {
    std::optional<DataValue> merged;
    bool initial{false};
  };

  void read_async(const ReadContext& context, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override;

  /// Each item is applied as @ref write applies it, the server's own write being one with no caller.
  void write_async(const WriteContext& context, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override;

  /// The Value as a read answers it, whole. The ServerTimestamp is the read's time unless the one held is
  /// within @p maxAge (Part 4 5.10.2.2); the SourceTimestamp is dropped unless @p setSourceTimestamp; a
  /// Variable never written answers a null Value, Good (Part 3 5.6.2: every Variable has a Value).
  DataValue read(Duration maxAge, bool setSourceTimestamp) const;

  /// Stores @p write's Value whole, or applies its IndexRange or ValidBits to the Value held
  /// (`detail::batch::merged_value_write`), under the source's lock. A merge that does not apply fails with
  /// its status and stores nothing.
  ///
  /// @param write      The write, possibly with an IndexRange or ValidBits.
  /// @param serversOwn Whether it is the server's own write, which stores an OptionSet with ValidBits
  ///                   as given when the Variable holds no OptionSet yet.
  Result<Stored> write(const WriteValue& write, bool serversOwn);

  /// Stores the Value @p next makes of the one held, under the lock, so that two updates never start from the
  /// same Value; both timestamps are now. A refusal of @p next stores nothing and is the answer.
  Result<DataValue> update(const std::function<Result<Variant>(const Variant& current)>& next);

private:
  mutable std::mutex mMutex;
  std::optional<DataValue> mValue;
};

}  // namespace ua::default_ns

#endif  // UA_DEFAULT_VALUE_SOURCE_H
