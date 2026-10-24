// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DYNAMIC_FIELD_CODEC_H
#define UA_DYNAMIC_FIELD_CODEC_H

#include "ua_includes.h"
#include "ua_built_in_type_id.h"
#include "ua_variant.h"
#include "ua_resource_budgets.h"

namespace ua
{

class DynamicStructureTypeDescriptor;
class UaBinaryEncoder;
class UaBinaryDecoder;

namespace detail
{

/// Create a default-constructed Variant for the given built-in type and value rank.
/// For scalar fields (valueRank < 0), returns a default scalar.
/// For array fields (valueRank >= 0), returns an empty Variant.
Variant make_default_field_value(BuiltInTypeId builtInType, int32_t valueRank = -1);

/// Encode a single field value to UA Binary based on its built-in type and value rank.
/// For array fields (valueRank >= 0), encodes an Int32 length prefix followed by each element.
void encode_dynamic_field(StackDepth limit, const Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, int32_t valueRank,
  UaBinaryEncoder& encoder);

/// Decode a single field value from UA Binary based on its built-in type and value rank.
/// For array fields (valueRank >= 0), reads an Int32 length followed by each element.
void decode_dynamic_field(StackDepth limit, Variant& fieldValue, BuiltInTypeId builtInType,
  const shared_ptr<const DynamicStructureTypeDescriptor>& nestedDescriptor, int32_t valueRank,
  UaBinaryDecoder& decoder);

}  // namespace detail
}  // namespace ua

#endif  // !UA_DYNAMIC_FIELD_CODEC_H
