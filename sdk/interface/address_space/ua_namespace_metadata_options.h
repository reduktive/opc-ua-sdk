// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_METADATA_OPTIONS_H
#define UA_NAMESPACE_METADATA_OPTIONS_H

/// @file
/// @brief Publication intent and descriptive facts supplied when a namespace is registered.
/// @ingroup address_space

#include "ua_array.h"
#include "ua_date_time.h"
#include "ua_numeric_range.h"
#include "ua_string.h"

#include <cstdint>
#include <optional>

namespace ua
{

/// What the registering caller wants published for this namespace, and the facts to publish.
///
/// Publication intent is stated here rather than inferred from whether the namespace implements
/// @ref Namespace::create_nodes_async, which is a statement about client AddNodes and not about metadata.
/// The registering caller is also the party that knows the descriptive facts: a namespace class
/// written once and instantiated against several data sources does not know its own version, while
/// the application assembling the server does.
struct NamespaceMetadataOptions
{
  /// Whether registration publishes this namespace's metadata Object.
  enum class Publication
  {
    /// Publish a `NamespaceMetadataType` Object. Where the namespace neither declares one nor has
    /// one already reachable under `Server.Namespaces`, it must accept node creation; registration
    /// fails with an actionable cause where it declines. The SDK never answers a request to publish
    /// by publishing nothing.
    Publish,
    /// Publish no Object. Refused for a namespace whose `default_role_permissions()` is engaged,
    /// because that declares the standard Part 3 Role model and Part 3 5.2.9 obliges the server to
    /// publish `DefaultRolePermissions` for it.
    Suppress,
  };

  Publication publication{Publication::Publish};  ///< Metadata publication choice for registration.

  /// Descriptive facts for the Mandatory Properties of Part 5 Table 21. An absent field keeps the
  /// conservative unknown the SDK would otherwise write, and none of these overwrites a value a
  /// NodeSet, store, proxy or application already supplied on a declared Object.
  std::optional<String> namespaceVersion;
  std::optional<DateTime> namespacePublicationDate;  ///< Optional metadata publication date.
  std::optional<bool> isNamespaceSubset;  ///< Whether this server exposes only a namespace subset.
  std::optional<Array<int32_t>> staticNodeIdTypes;  ///< Identifier kinds whose assignments are static.
  std::optional<Array<NumericRange>> staticNumericNodeIdRange;  ///< Static numeric identifier ranges.
  std::optional<String> staticStringNodeIdPattern;  ///< Pattern describing static string identifiers.
};

}  // namespace ua

#endif  // UA_NAMESPACE_METADATA_OPTIONS_H
