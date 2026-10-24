// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ATTRIBUTE_WIRE_H
#define UA_ATTRIBUTE_WIRE_H

/// @file
/// @brief Single-source wire-form encoders for node attributes. Each function
///        returns the OPC UA wire-form `Variant` that the matching
///        `NodeAccessor` setter writes, so setters and bulk builders
///        (create-with-attributes) share one encoding.
///
/// These encoders only translate a typed value into its stored wire form. The one
/// exception is `display_name`, which enforces the OPC 10000-3 DisplayName text-size
/// limit so every write path (the setter and the create-with-attributes builders)
/// shares the same check.

#include "ua_includes.h"
#include "ua_result.h"
#include "ua_variant.h"
#include "ua_qualified_name.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_data_value.h"
#include "ua_value_rank.h"
#include "ua_attribute_write_mask.h"
#include "ua_role_permission_type.h"
#include "ua_access_restriction_type.h"
#include "ua_event_notifier_type.h"
#include "ua_access_level_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_duration.h"
#include "ua_data_type_definition.h"
#include "ua_attribute_id.h"
#include "ua_node_class.h"
#include "ua_node_description.h"

#include <functional>
#include <span>

namespace ua::attribute_wire
{

/// Maximum DisplayName text size in bytes (OPC 10000-3). Single source for the limit enforced by
/// @ref display_name on every write path (the NodeAccessor setter and the create-with-attributes
/// builders).
inline constexpr std::size_t displayNameMaxTextSize{512};

/// Encodes a BrowseName into its wire-form Variant. @see NodeAccessor::set_browse_name
Variant browse_name(const QualifiedName& value);

/// Encodes a DisplayName into its wire-form Variant, enforcing the OPC 10000-3 max text size
/// (`NodeAccessor::sDisplayNameMaxSize`). Throws `UaException{BadInvalidArgument}` when exceeded, so
/// every write path (the setter and the create-with-attributes builders) enforces the same limit.
/// @see NodeAccessor::set_display_name
Variant display_name(const LocalizedText& value);

/// Encodes a Description into its wire-form Variant. @see NodeAccessor::set_description
Variant description(const LocalizedText& value);

/// Encodes a WriteMask into its wire-form Variant; empty optional yields an empty Variant.
/// @see NodeAccessor::set_write_mask
Variant write_mask(const optional<AttributeWriteMask>& value);

/// Encodes RolePermissions into their wire-form Variant; empty optional yields an empty Variant.
/// @see NodeAccessor::set_role_permissions
Variant role_permissions(const optional<std::vector<RolePermissionType>>& value);

/// Encodes RolePermissions that are present into their wire-form Variant.
Variant role_permissions(const std::vector<RolePermissionType>& value);

/// Decodes the RolePermissions a client's Write sends, strictly: a Structure of another type would turn
/// the value into a different, more permissive policy than the one sent, so it is refused rather than
/// dropped.
///
/// @param value The written value: null, or an array of RolePermissionType Structures.
/// @return The entries, empty for a null value or an empty array (OPC 10000-3 5.2.9: clears the Node's
///         own RolePermissions); `Bad_TypeMismatch` for any other value.
Result<std::vector<RolePermissionType>> decode_role_permissions(const Variant& value);

/// Encodes AccessRestrictions into their wire-form Variant; empty optional yields an empty Variant.
/// @see NodeAccessor::set_access_restrictions
Variant access_restrictions(const optional<AccessRestrictionType>& value);

/// Encodes an IsAbstract flag into its wire-form Variant.
Variant is_abstract(bool value);

/// Encodes a Symmetric flag into its wire-form Variant. @see ReferenceTypeAccessor::set_symmetric
Variant symmetric(bool value);

/// Encodes an InverseName into its wire-form Variant. @see ReferenceTypeAccessor::set_inverse_name
Variant inverse_name(const LocalizedText& value);

/// Encodes a DataTypeDefinition into its wire-form Variant; a null definition yields an empty
/// Variant. The stored value is an owning clone. @see DataTypeAccessor::set_data_type_definition
Variant data_type_definition(const shared_ptr<const DataTypeDefinition>& value);

/// Encodes an EventNotifier into its wire-form Variant.
/// @see ObjectAccessor::set_event_notifier, ViewAccessor::set_event_notifier
Variant event_notifier(const EventNotifierType& value);

/// Encodes a VariableType's stored default Value into its wire-form Variant; empty optional
/// yields an empty Variant. @see VariableTypeAccessor::set_value
Variant variable_type_value(const optional<DataValue>& value);

/// Encodes a DataType NodeId into its wire-form Variant.
/// @see VariableAccessor::set_data_type, VariableTypeAccessor::set_data_type
Variant data_type(const NodeId& value);

/// Encodes a ValueRank into its wire-form Variant.
/// @see VariableAccessor::set_value_rank, VariableTypeAccessor::set_value_rank
Variant value_rank(ValueRank value);

/// Encodes ArrayDimensions into their wire-form Variant; empty optional yields an empty Variant.
/// @see VariableAccessor::set_array_dimensions, VariableTypeAccessor::set_array_dimensions
Variant array_dimensions(const optional<std::vector<uint32_t>>& value);

/// Encodes ArrayDimensions that are present into their wire-form Variant.
Variant array_dimensions(const std::vector<uint32_t>& value);

/// Encodes a ContainsNoLoops flag into its wire-form Variant. @see ViewAccessor::set_contains_no_loops
Variant contains_no_loops(bool value);

/// Encodes an AccessLevel into its wire-form Variant. @see VariableAccessor::set_access_level
Variant access_level(const AccessLevelType& value);

/// Encodes an AccessLevelEx into its wire-form Variant; empty optional yields an empty Variant.
/// @see VariableAccessor::set_access_level_ex
Variant access_level_ex(const optional<AccessLevelExType>& value);

/// Encodes a MinimumSamplingInterval into its wire-form Variant; empty optional yields an empty
/// Variant. @see VariableAccessor::set_minimum_sampling_interval
Variant minimum_sampling_interval(const optional<Duration>& value);

/// Encodes a Historizing flag into its wire-form Variant. @see VariableAccessor::set_historizing
Variant historizing(bool value);

/// Encodes an Executable flag into its wire-form Variant. @see MethodAccessor::set_executable
Variant executable(bool value);

}  // namespace ua::attribute_wire

#endif  // UA_ATTRIBUTE_WIRE_H
