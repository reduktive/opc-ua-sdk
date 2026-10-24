// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_ACCESS_PROJECTION_H
#define UA_DATA_ACCESS_PROJECTION_H

#include <boost/asio/strand.hpp>

#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_result.h"

namespace ua::server::data_access_projection
{

using OptionalLocalizedTextResult = Result<optional<LocalizedText>>;

struct DictionaryEnumEntry
{
  int64_t value{0};
  LocalizedText displayName;
};

struct DictionarySnapshot
{
  explicit DictionarySnapshot(NodeAccessor initialOwner) : owner(std::move(initialOwner))
  {}

  NodeAccessor owner;
  int64_t currentValue{0};
  std::vector<DictionaryEnumEntry> enumValues;
  Array<NodeId> dictionaryEntries;
};

using OptionalDictionarySnapshotResult = Result<optional<DictionarySnapshot>>;

struct DictionaryWriteTarget
{
  NodeAccessor owner;
  DataValue value;
};

/// The Variable a Part-19 Property projects: the index-based target of its inverse HasProperty
/// Reference, if any. The one rule both projections and the service's owner authorization apply, so
/// the Node authorized is the Node disclosed.
[[nodiscard]] std::optional<NodeId> owning_variable_of(const References& references) noexcept;

/// Resolves the owning MultiStateValueDiscrete Variable and projects its current numeric Value
/// through EnumValues. A good empty result means the Property is not sufficiently modelled or the
/// current value has no matching enumeration entry; operational failures preserve ErrorDetail. The owner is
/// decided only from a Good References answer: an Uncertain one, with or without References, is refused with
/// `Bad_InternalError` (`ReferencesAnswerUncertain`, its cause the Uncertain code). The text is the Read's
/// answer, so it carries the code of the owner's Value reads (a Good subcode, or an Uncertain code with the
/// value it held, @ref instance_utils::project_value_as_text_async); a read that answered no value answers
/// its code.
/// @param strand The CALLER'S strand. AddressSpace owns none, and this projection has no shared
///               state of its own, so it borrows the strand of the request that wants it rather
///               than minting one per call.
void value_as_text_async(AddressSpace addressSpace, NodeAccessor property,
  boost::asio::strand<boost::asio::any_io_executor> strand,
  std::function<void(OptionalLocalizedTextResult)> onComplete) noexcept;

/// Resolves the owning Variable, its current Value, EnumValues, and the two-dimensional
/// EnumDictionaryEntries table used by ValueAsDictionaryEntries. The owner and its Properties are decided
/// only from Good answers: an Uncertain References read or lookup, with or without a value, is refused with
/// `Bad_InternalError` (`ReferencesAnswerUncertain` or `LookupAnswerUncertain`, its cause the Uncertain
/// code). The snapshot carries the codes of the three Value reads it is made from, combined by
/// `ua::detail::combined_status` (a Good subcode, or an Uncertain code with the value it held); a read that
/// answered no value answers its code. A caller that acts on the snapshot, such as the translation of a
/// write, tests `is_good()`.
/// @param strand The caller's strand. @see value_as_text_async
void dictionary_snapshot_async(AddressSpace addressSpace, NodeAccessor property,
  boost::asio::strand<boost::asio::any_io_executor> strand,
  std::function<void(OptionalDictionarySnapshotResult)> onComplete) noexcept;

/// Selects the current Value's row from a validated dictionary snapshot.
Result<Array<NodeId>> current_dictionary_entries(const DictionarySnapshot& snapshot) noexcept;

/// Maps a ValueAsDictionaryEntries write to the owning Variable's numeric Value write.
Result<DictionaryWriteTarget> dictionary_write_target(
  const DictionarySnapshot& snapshot, DataValue propertyValue) noexcept;

}  // namespace ua::server::data_access_projection

#endif  // UA_DATA_ACCESS_PROJECTION_H
