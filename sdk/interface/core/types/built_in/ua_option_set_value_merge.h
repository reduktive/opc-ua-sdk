// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OPTION_SET_VALUE_MERGE_H
#define UA_OPTION_SET_VALUE_MERGE_H

#include "ua_byte_string.h"
#include "ua_result.h"

namespace ua
{
class OptionSet;

/// Merges a written OptionSet into the current one as OPC 10000-3 8.40 defines a write carrying ValidBits:
/// `(written & validBits) | (current & ~validBits)`, byte by byte over the longer of the two Values, a
/// missing byte counting as zero.
///
/// A namespace or a `ValueSource` that keeps an OptionSet Value applies a write carrying ValidBits with it:
/// the SDK passes such a write on unmerged (NR-11 rule 3).
///
/// @param writtenOptionSet The written OptionSet; its ValidBits are expected to be non-empty.
/// @param currentOptionSet The OptionSet the Variable holds.
/// @return The merged Value, or `Bad_OutOfRange` (`OptionSetValidBitsSizeMismatch`) when the written
///         ValidBits are not as long as the written Value.
ByteStringResult merge_option_set_value(const OptionSet& writtenOptionSet, const OptionSet& currentOptionSet);

}  // namespace ua

#endif  // !UA_OPTION_SET_VALUE_MERGE_H
