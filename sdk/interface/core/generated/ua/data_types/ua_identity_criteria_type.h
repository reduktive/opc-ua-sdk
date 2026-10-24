// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_IDENTITY_CRITERIA_TYPE_H
#define UA_DATA_TYPE_IDENTITY_CRITERIA_TYPE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA IdentityCriteriaType enumeration data type.
/// @ingroup ua_data_types
enum class IdentityCriteriaType : int32_t
{
  UserName = 1,  ///< The rule specifies a UserName from a UserNameIdentityToken.
  Thumbprint = 2,  ///< The rule specifies the Thumbprint of a user or CA Certificate.
  Role = 3,  ///< The rule is a Role specified in an Access Token.
  GroupId = 4,  ///< The rule is a user group specified in the Access Token.
  Anonymous = 5,  ///< The rule specifies Anonymous UserIdentityToken.
  AuthenticatedUser = 6,  ///< The rule specifies any non Anonymous UserIdentityToken.
  Application =
    7,  ///< The rule specifies the combination of an application identity and an Anonymous UserIdentityToken.
  X509Subject = 8,  ///< The rule specifies the X509 subject name of a user or CA Certificate.
  TrustedApplication = 9,  ///< The rule specifies any trusted application that has been authenticated with a
                           ///< trusted ApplicationInstance Certificate.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(IdentityCriteriaType value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of IdentityCriteriaType.
bool is_valid(IdentityCriteriaType value);

}  // namespace ua

/// The OPC UA DataType of the IdentityCriteriaType enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::IdentityCriteriaType>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::IdentityCriteriaType};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_IDENTITY_CRITERIA_TYPE_H
