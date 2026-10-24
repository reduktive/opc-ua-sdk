// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Application identity and configuration for an OPC UA server or client.
/// @ingroup general

#ifndef UA_APPLICATION_CONFIGURATION_H
#define UA_APPLICATION_CONFIGURATION_H

#include "ua_application_description.h"
#include "ua_build_info.h"
#include "ua_crypto.h"
#include "filesystem"
#include "ua_duration.h"
#include "ua_execution_limits.h"

#include <cstddef>

#include <string>
#include <string_view>

#include <ua_connection_protocol_limits.h>

namespace ua
{

class Stream;

/// Static identity an application advertises about itself.
///
/// Holds the fixed, build-time identity (product URI, display name, role, and
/// build metadata) used to populate the @ref ApplicationDescription handed to
/// peers. This is distinct from @ref ApplicationConfig, which carries the
/// deployment-specific instance settings.
/// @ingroup general
struct ApplicationIdentity
{
  String productUri{};  ///< Manufacturer-assigned product URI identifying the software.
  LocalizedText applicationName{};  ///< Human-readable name of the application.
  ApplicationType applicationType{
    ApplicationType::Server};  ///< Role of the application (server, client, ...).
  BuildInfo buildInfo;  ///< Build/version metadata (product, manufacturer, version, build date).

  /// Returns the SDK's built-in default identity (a server identity with the
  /// SDK's product URI and name).
  /// @return The SDK's default application identity.
  static ApplicationIdentity load_default();
};

/// Deployment configuration for an OPC UA application instance.
///
/// Aggregates the tunable settings that govern an application's protocol
/// timeouts, secure-channel and session lifetimes, execution limits, trust-list
/// locations, and security policy. It is JSON-serializable (@ref to_json_string,
/// @ref store) and reloadable (@ref from_json_string, @ref load), so a
/// deployment can persist and restore its configuration.
///
/// The default constructor is deleted: instances are obtained from a factory
/// (@ref load_default, @ref load, @ref from_json_string) so that every
/// configuration starts from a validated baseline.
/// @ingroup general
struct ApplicationConfig
{
  /// Protocol-stack timeouts and lifetime bounds.
  ///
  /// All durations are typed `std::chrono` quantities; the field types carry the
  /// unit (seconds or milliseconds). The minimum/maximum pairs bound what a peer
  /// may negotiate for secure-channel and session lifetimes.
  struct StackLimits
  {
    /// Compares all timeout and lifetime fields for equality (memberwise).
    /// @return `true` if all timeout and lifetime fields are equal.
    bool operator==(const StackLimits&) const = default;

    ua::connection_protocol::Limits
      connectionProtocolLimits;  ///< Message/chunk size and buffer limits for the connection protocol.
    std::chrono::seconds connectionProtocolTimeout{
      10};  ///< Overall connection-protocol handshake timeout. Must be > 0.
    std::chrono::milliseconds connectionProtocolMessageReadTimeout{
      10'000};  ///< Maximum wait for a single inbound message. Must be > 0.
    std::chrono::milliseconds secureChannelMinimumLifetime{
      300'000};  ///< Smallest secure-channel lifetime granted to a peer. Must be > 0.
    std::chrono::milliseconds secureChannelMaximumLifetime{
      3'600'000};  ///< Largest secure-channel lifetime granted to a peer. Must be >= the minimum.
    std::chrono::seconds firstOpnTimeout{
      30};  ///< Time allowed for the first OPN request after the HEL/ACK exchange.
    std::chrono::milliseconds sessionMinimumTimeout{
      60'000};  ///< Smallest session timeout granted to a client. Must be > 0.
    std::chrono::milliseconds sessionMaximumTimeout{
      3'600'000};  ///< Largest session timeout granted to a client. Must be >= the minimum.
  };

  /// Deployment-specific portion of the @ref ApplicationDescription.
  ///
  /// Holds the instance-level fields (currently the application URI) that vary
  /// per deployment, as opposed to the build-time @ref ApplicationIdentity.
  struct ApplicationDescriptionPart
  {
    /// Compares the application-URI field for equality.
    /// @return `true` if the application-URI fields are equal.
    bool operator==(const ApplicationDescriptionPart&) const = default;

    std::string applicationUri{};  ///< Globally unique URI identifying this application instance.
  };

  /// File-backed trust-list (PKI) configuration.
  ///
  /// Locates the on-disk trust lists for the default application and user-token
  /// certificate groups and controls how loaded certificates are validated.
  struct FileTrustListConfig
  {
    /// Compares all trust-list paths, validation options, and refresh settings (memberwise).
    /// @return `true` if all trust-list fields are equal.
    bool operator==(const FileTrustListConfig&) const = default;

    std::filesystem::path
      defaultApplicationGroupTrustListPath;  ///< Path to the application certificate group's trust list.
    /// Validation options for the application group's trust list. Defaults to
    /// CheckRevocationStatusOffline (OPC 10000-12; owner decision 22.1): revocation is checked against
    /// the trust list's CRLs unless an operator clears the bit.
    TrustListValidationOptions defaultApplicationGroupTrustListValidationOptions{
      TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
    /// Path to the user-token certificate group's trust list; unset means the server owns none.
    ///
    /// When set, the server opens this trust list at bring-up and offers it to the authenticator on
    /// every activation (`ua::server::AuthnRequest::userTokenCertificateStore`), so
    /// `X509UserAuthenticator` validates user certificates against it without the host opening a
    /// store itself. It is also the store behind the Part 12 `DefaultUserTokenGroup`, so a remote
    /// administrator can push user-certificate trust changes.
    ///
    /// Leave it unset when no endpoint offers an X.509 user-token policy, or when the host supplies
    /// its own store through `ua::server::ServerComponents::userTokenCertificateStore`: two
    /// `CertificateStore` instances over one directory would each cache, refresh, and write rejected
    /// certificates independently.
    optional<std::filesystem::path> defaultUserTokenGroupTrustListPath;
    /// Validation options for the user-token group's trust list; ignored when the path is unset.
    /// Defaults to CheckRevocationStatusOffline, as for the application group.
    TrustListValidationOptions defaultUserTokenGroupTrustListValidationOptions{
      TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
    optional<std::chrono::seconds> trustListRefreshPeriod;  ///< How often to reload the trust lists from
                                                            ///< disk; unset disables periodic refresh.
    bool storeRejectedCertificates{
      true};  ///< Whether to persist rejected certificates (trust-related rejections only).
    /// Upper bound on the rejected-certificate store (in-memory list + on-disk RejectedCertificates/).
    /// A pre-auth peer can present unlimited distinct certificates during OpenSecureChannel, each with a
    /// unique thumbprint; once this many are held the store evicts oldest-first so it cannot grow without
    /// bound (disk + memory DoS). The rejected list is meant to be a finite, operator-reviewed set
    /// (Part 12 GetRejectedList). 0 disables the bound.
    size_t maxRejectedCertificates{100};
  };

  /// Deleted: configurations are produced by factory functions, never default-constructed.
  ApplicationConfig() = delete;
  /// Copy-constructs an independent configuration with the same settings.
  ApplicationConfig(const ApplicationConfig&) = default;
  /// Move-constructs from @p other, leaving it in a valid but unspecified state.
  /// @param other Configuration to move from.
  ApplicationConfig(ApplicationConfig&& other) noexcept = default;
  /// Copy-assigns the settings of @p other.
  /// @param other Configuration whose settings are copied.
  /// @return Reference to this configuration.
  ApplicationConfig& operator=(const ApplicationConfig& other) = default;
  /// Move-assigns from @p other, leaving it in a valid but unspecified state.
  /// @param other Configuration to move from.
  /// @return Reference to this configuration.
  ApplicationConfig& operator=(ApplicationConfig&& other) noexcept = default;
  /// Destroys the configuration, releasing its owned settings.
  ~ApplicationConfig() = default;

  /// Returns the deployment-specific application-description fields (read-only).
  /// @return A read-only reference to the application-description fields.
  const ApplicationDescriptionPart& application_description_part() const;
  /// Returns the protocol-stack timeouts and lifetime bounds (read-only).
  /// @return A read-only reference to the stack limits.
  const StackLimits& stack_limits() const;
  /// Returns the file-backed trust-list configuration (read-only).
  /// @return A read-only reference to the file trust-list configuration.
  const FileTrustListConfig& file_trust_list_configuration() const;

  /// Returns the deployment-specific application-description fields for mutation.
  /// @return A mutable reference to the application-description fields.
  ApplicationDescriptionPart& application_description_part();
  /// Returns the protocol-stack timeouts and lifetime bounds for mutation.
  /// @return A mutable reference to the stack limits.
  StackLimits& stack_limits();
  /// Returns the file-backed trust-list configuration for mutation.
  /// @return A mutable reference to the file trust-list configuration.
  FileTrustListConfig& file_trust_list_configuration();

  LocaleId defaultLocale{"en"};  ///< Default locale for localized text emitted by the application.
  bool allowInsecureEndpoints{false};  ///< Whether to expose endpoints with security policy None.
  bool allowDeprecatedSecurityPolicies{
    false};  ///< Whether to permit security policies the spec marks deprecated.

  ExecutionLimits
    executionLimits;  ///< Limits guarding recursion depth and loop iterations during request processing.

  /// Returns the execution limits (read-only).
  /// @return A read-only reference to the execution limits.
  const ExecutionLimits& execution_limits() const;
  /// Returns the execution limits for mutation.
  /// @return A mutable reference to the execution limits.
  ExecutionLimits& execution_limits();

  /// Builds the @ref ApplicationDescription advertised to peers.
  ///
  /// Combines this configuration's application URI with the build-time
  /// @p identity and the supplied discovery URLs.
  ///
  /// @param identity      Build-time identity supplying name, type, and product URI.
  /// @param discoveryUrls Discovery endpoint URLs to advertise; copied into the result.
  /// @return The assembled application description.
  ApplicationDescription construct_application_description(
    const ApplicationIdentity& identity, span<std::string_view> discoveryUrls) const;

  /// Serializes this configuration as pretty-printed JSON to a file.
  ///
  /// @param filename Destination path; created or truncated.
  /// @throws UaException if the file cannot be opened for writing.
  /// @see store(Stream&) const, load(const std::filesystem::path&)
  void store(const std::filesystem::path& filename) const;
  /// Loads a configuration from a JSON file.
  ///
  /// @param filename Source path.
  /// @return The deserialized configuration.
  /// @throws UaException if the file cannot be opened for reading or the JSON is invalid.
  /// @see store(const std::filesystem::path&) const, load(const Stream&)
  static ApplicationConfig load(const std::filesystem::path& filename);
  /// Serializes this configuration as pretty-printed JSON to a stream.
  ///
  /// @param stream Sink to which the JSON bytes are written.
  /// @throws UaException if the stream write fails.
  /// @see store(const std::filesystem::path&) const, load(const Stream&)
  void store(Stream& stream) const;
  /// Loads a configuration from a JSON stream.
  ///
  /// Reads the whole stream and parses it as JSON.
  ///
  /// @param stream Source stream.
  /// @return The deserialized configuration.
  /// @throws UaException if the stream read fails or the JSON is invalid.
  /// @see store(Stream&) const, load(const std::filesystem::path&)
  static ApplicationConfig load(const Stream& stream);

  /// Serializes this configuration to a JSON string.
  ///
  /// @param pretty Whether to pretty-print with indentation; otherwise compact.
  /// @return The JSON representation.
  /// @see from_json_string
  [[nodiscard]] std::string to_json_string(bool pretty = true) const;
  /// Deserializes a configuration from a JSON string.
  ///
  /// @param json JSON text to parse.
  /// @return The deserialized configuration.
  /// @throws UaException if @p json is not valid configuration JSON.
  /// @see to_json_string
  static ApplicationConfig from_json_string(std::string_view json);

  /// Returns a validated configuration populated with the SDK's defaults.
  ///
  /// @return A default configuration (default trust-list paths under `./pki`,
  ///         standard timeouts) that has already passed @ref validate.
  static ApplicationConfig load_default();

  /// Returns the conventional configuration file path (`ApplicationConfig.json` in the
  /// current directory).
  /// @return The conventional configuration file path.
  static std::filesystem::path default_config_file();

  /// Validates the configuration's invariants.
  ///
  /// Checks that execution limits are non-zero and that timeouts and lifetimes
  /// are positive with maxima not below their minima.
  ///
  /// @throws UaException with Status::BadConfigurationError if any invariant is violated.
  void validate() const;

private:
  ApplicationConfig(const std::nullptr_t);

  ApplicationDescriptionPart mApplicationDescriptionPart;
  StackLimits mStackLimits;
  FileTrustListConfig mFileTrustListConfiguration;
};
}  // namespace ua

#endif  // !UA_APPLICATION_CONFIGURATION_H
