// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OPTION_SET_MERGE_H
#define UA_OPTION_SET_MERGE_H

#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_enum_field.h"
#include "ua_option_set_value_merge.h"
#include "ua_result.h"

namespace ua
{
class OptionSet;
}

namespace ua::server
{

/// Build a bitmask from EnumDefinition fields indicating which bit positions the server defines.
/// Each field's mValue is a 0-based bit number. Returns a ByteString of the given length with those
/// bits set.
ByteString build_server_valid_bits_mask(const Array<EnumField>& fields, size_t byteLength);

/// Check that client ValidBits only sets bits the server defines.
/// Returns BadOutOfRange with ErrorDetail if the client sets a ValidBit outside the server mask.
VoidResult validate_client_valid_bits(
  const ByteString& clientValidBits, const ByteString& serverValidBitsMask);

}  // namespace ua::server

#endif  // !UA_OPTION_SET_MERGE_H
