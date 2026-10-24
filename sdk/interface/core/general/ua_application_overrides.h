// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_APPLICATION_OVERRIDES_H
#define UA_APPLICATION_OVERRIDES_H

/// @file
/// @brief Optional, per-field overrides layered onto an ApplicationConfig.
/// @ingroup general

#include "ua_application_configuration.h"

#include <optional>
#include <string>
#include <string_view>

namespace ua
{

/// A set of optional overrides layered on top of an existing @ref ApplicationConfig.
///
/// Each member is an `std::optional`: an engaged value replaces the corresponding field in a base
/// configuration, while a disengaged value leaves the base field untouched. This allows a partial
/// configuration (for example loaded from a deployment-specific JSON file) to amend a fully formed
/// base configuration without restating every field. Apply the overrides with @ref apply_overrides.
///
/// JSON keys align with the member names with the leading `m` prefix dropped (for example
/// `defaultLocale` <-> `"DefaultLocale"`).
///
/// @ingroup general
/// @see apply_overrides
struct ApplicationOverrides
{
  /// Override for the application-description part of the configuration, if set.
  std::optional<ApplicationConfig::ApplicationDescriptionPart> applicationDescriptionPart;

  /// Override for the stack/protocol limits and timeouts, if set.
  std::optional<ApplicationConfig::StackLimits> stackLimits;

  /// Override for the file-backed trust-list configuration, if set.
  std::optional<ApplicationConfig::FileTrustListConfig> fileTrustListConfiguration;

  /// Override for the default locale identifier, if set.
  std::optional<LocaleId> defaultLocale;

  /// Override for whether endpoints without security are permitted, if set.
  std::optional<bool> allowInsecureEndpoints;

  /// Override for whether deprecated security policies are permitted, if set.
  std::optional<bool> allowDeprecatedSecurityPolicies;

  /// Override for the maximum node/edge work allowed while decoding, if set.
  std::optional<size_t> decodeWorkLimit;

  /// Override for the maximum live recursion depth allowed while decoding, if set.
  std::optional<size_t> decodeRecursionDepthLimit;

  /// Override for the maximum logical descent allowed while instantiating, if set.
  std::optional<size_t> instantiationDepthLimit;

  /// Override for the maximum iteration count allowed while decoding, if set.
  std::optional<size_t> loopLimit;

  /// Serialises these overrides to a JSON string.
  ///
  /// Only engaged members are meaningful in the result; disengaged optionals are emitted as their
  /// JSON-null / absent form per the serialiser. The output round-trips through
  /// @ref from_json_string.
  ///
  /// @param[in] pretty If `true`, produce human-readable, indented JSON; otherwise produce a
  ///                   compact single-line form.
  /// @return The JSON representation of these overrides.
  /// @see from_json_string
  [[nodiscard]] std::string to_json_string(bool pretty = true) const;

  /// Parses an @ref ApplicationOverrides from a JSON string.
  ///
  /// Keys absent from the JSON leave their corresponding override disengaged. Keys follow the
  /// member-name convention described on @ref ApplicationOverrides.
  ///
  /// @param[in] json JSON text produced by @ref to_json_string, or authored to the same schema.
  /// @return The parsed overrides.
  /// @throws UaException if @p json is not well-formed or does not match the expected schema.
  /// @see to_json_string
  static ApplicationOverrides from_json_string(std::string_view json);
};

/// Returns a copy of @p base with every engaged field of @p overrides applied.
///
/// Each engaged member of @p overrides replaces the matching field of @p base; disengaged members
/// leave the base field unchanged. The resulting configuration is validated before being returned,
/// so an override that produces an inconsistent configuration is rejected here rather than later.
///
/// @param[in] base      The starting configuration. Taken by value and amended in place.
/// @param[in] overrides The fields to apply on top of @p base.
/// @return The merged, validated configuration.
/// @throws UaException if the merged configuration fails validation.
[[nodiscard]] ApplicationConfig apply_overrides(
  ApplicationConfig base, const ApplicationOverrides& overrides);

}  // namespace ua

#endif  // !UA_APPLICATION_OVERRIDES_H
