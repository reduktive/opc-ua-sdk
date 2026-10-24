// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_TRUST_LIST_MASKS_H
#define UA_DATA_TYPE_TRUST_LIST_MASKS_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA TrustListMasks enumeration data type.
/// @ingroup ua_data_types
enum class TrustListMasks : int32_t
{
  None = 0,  ///< No fields are provided.
  TrustedCertificates = 1,  ///< The TrustedCertificates are provided.
  TrustedCrls = 2,  ///< The TrustedCrls are provided.
  IssuerCertificates = 4,  ///< The IssuerCertificates are provided.
  IssuerCrls = 8,  ///< The IssuerCrls are provided.
  All = 15,  ///< All fields are provided.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(TrustListMasks value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of TrustListMasks.
bool is_valid(TrustListMasks value);

}  // namespace ua

/// The OPC UA DataType of the TrustListMasks enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::TrustListMasks>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::TrustListMasks};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_TRUST_LIST_MASKS_H
