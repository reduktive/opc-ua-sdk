// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Persisted, JSON-backed process configuration (application defaults plus instances).
/// @ingroup app

#ifndef UA_PROCESS_CONFIGURATION_FILE_H
#define UA_PROCESS_CONFIGURATION_FILE_H

#include "ua_application_configuration.h"
#include "ua_application_overrides.h"
#include "ua_client_configuration.h"
#include "ua_server_configuration.h"

#include <filesystem>
#include <string_view>
#include <string>
#include <vector>

namespace ua
{

class Stream;

/// Persisted configuration for a single process.
///
/// The file schema is a superset that bundles shared application defaults with the
/// per-instance configuration of every server and client the process hosts. It is the
/// in-memory model loaded from, and stored to, the on-disk JSON document.
///
/// Application identity is intentionally not persisted: the durable @ref ApplicationConfig
/// captures only the reusable parts, and a fresh application URI is generated when a default file
/// is created (see @ref load_default).
///
/// JSON object keys mirror the data-member names with the leading `m` prefix dropped (for example
/// `servers` <-> `"Servers"`). All persisting and loading operations validate the configuration and
/// throw @ref UaException on a malformed document or invalid configuration.
/// @ingroup app
struct ProcessConfigurationFile
{
  /// Deleted: an instance always carries application defaults, so there is no empty state. Construct
  /// from application defaults, or via @ref load, @ref from_json_string, or @ref load_default.
  ProcessConfigurationFile() = delete;

  ProcessConfigurationFile(
    const ProcessConfigurationFile&) = default;  ///< Copyable; deep-copies all instances.
  ProcessConfigurationFile(ProcessConfigurationFile&&) noexcept = default;  ///< Movable.
  /// @return A reference to this object.
  ProcessConfigurationFile& operator=(const ProcessConfigurationFile&) = default;  ///< Copy-assignable.
  /// @return A reference to this object.
  ProcessConfigurationFile& operator=(ProcessConfigurationFile&&) noexcept = default;  ///< Move-assignable.
  ~ProcessConfigurationFile() = default;  ///< Destructor; deep-destroys all instances.

  /// Configuration of one named server instance within the process.
  struct ServerInstanceConfig
  {
    std::string name;  ///< Identifier for this server instance, unique within the file.
    ApplicationOverrides
      applicationOverrides;  ///< Per-instance overrides applied over the shared application defaults.
    ::ua::server::ServerConfig server;  ///< Server-specific configuration (endpoints, security, limits).

    /// Validates this server instance's configuration.
    ///
    /// @throws UaException if the instance name or any nested configuration is invalid.
    void validate() const;
  };

  /// Configuration of one named client instance within the process.
  struct ClientInstanceConfig
  {
    std::string name;  ///< Identifier for this client instance, unique within the file.
    ApplicationOverrides
      applicationOverrides;  ///< Per-instance overrides applied over the shared application defaults.
    ::ua::client::ClientConfig client;  ///< Client-specific configuration (session, connection settings).

    /// Validates this client instance's configuration.
    ///
    /// @throws UaException if the instance name or any nested configuration is invalid.
    void validate() const;
  };

  ApplicationConfig application;  ///< Shared application defaults inherited by every instance.
  std::vector<ServerInstanceConfig> servers;  ///< Server instances hosted by the process.
  std::vector<ClientInstanceConfig> clients;  ///< Client instances hosted by the process.

  /// Constructs a process configuration from application defaults and optional instances.
  ///
  /// @param applicationConfig Shared application defaults inherited by every instance.
  /// @param serverInstances     Server instances to host; defaults to none.
  /// @param clientInstances     Client instances to host; defaults to none.
  explicit ProcessConfigurationFile(ApplicationConfig applicationConfig,
    std::vector<ServerInstanceConfig> serverInstances = {},
    std::vector<ClientInstanceConfig> clientInstances = {});

  /// Validates the configuration and writes it as JSON to the file at @p filename.
  ///
  /// Any existing file at @p filename is overwritten.
  ///
  /// @param filename Destination path for the JSON document.
  /// @throws UaException if the configuration is invalid or the file cannot be opened for writing.
  /// @see store(Stream&) const, load
  void store(const std::filesystem::path& filename) const;

  /// Validates the configuration and writes it as JSON to @p stream.
  ///
  /// @param stream Open, writable stream that receives the serialized JSON document. The caller
  ///               retains ownership of the stream.
  /// @throws UaException if the configuration is invalid or the stream write fails.
  /// @see store(const std::filesystem::path&) const, to_json_string
  void store(Stream& stream) const;

  /// Loads and parses a process configuration from the file at @p filename.
  ///
  /// @param filename Path to an existing JSON document.
  /// @return The parsed configuration.
  /// @throws UaException if the file cannot be opened, is malformed, or fails validation.
  /// @see store(const std::filesystem::path&) const
  static ProcessConfigurationFile load(const std::filesystem::path& filename);

  /// Loads and parses a process configuration from @p stream.
  ///
  /// Reads the stream to its end and parses the bytes as a JSON document.
  ///
  /// @param stream Open, readable stream positioned at the start of the JSON document.
  /// @return The parsed configuration.
  /// @throws UaException if the stream content is malformed or fails validation.
  /// @see store(Stream&) const, from_json_string
  static ProcessConfigurationFile load(const Stream& stream);

  /// Validates the configuration and serializes it to a JSON string.
  ///
  /// @param pretty When `true` (the default), emits indented, human-readable JSON; when `false`,
  ///               emits a compact single-line document.
  /// @return The serialized JSON document.
  /// @throws UaException if the configuration is invalid.
  /// @see from_json_string, store(Stream&) const
  [[nodiscard]] std::string to_json_string(bool pretty = true) const;

  /// Parses a process configuration from a JSON string.
  ///
  /// @param json JSON document text, in either the pretty or compact form produced by
  ///             @ref to_json_string.
  /// @return The parsed configuration.
  /// @throws UaException if @p json is malformed or fails validation.
  /// @see to_json_string
  static ProcessConfigurationFile from_json_string(std::string_view json);

  /// Builds the built-in default configuration in memory.
  ///
  /// Produces a single server instance named `"DefaultServer"` with no listeners - the application
  /// must add listeners and endpoints appropriate to its deployment - and an application
  /// configuration whose application URI is freshly generated.
  ///
  /// @return The default configuration; nothing is written to disk.
  /// @throws UaException if the constructed default configuration fails validation.
  /// @see load_or_create_and_store_default, default_config_file
  static ProcessConfigurationFile load_default();

  /// Returns the conventional default configuration-file path.
  ///
  /// @return The relative path `./ProcessConfiguration.json`.
  /// @see load_or_create_and_store_default
  static std::filesystem::path default_config_file();

  /// What @ref load_or_create_and_store_default does with a file it cannot read.
  ///
  /// This governs the UNREADABLE case only -- a file that cannot be opened or does not parse. A file
  /// that loads and then fails validation throws under both values and is never modified: it is
  /// well-formed and wrong, so the operator's intent is legible and worth keeping.
  enum class OnUnreadableFile
  {
    /// Throw, and leave the file exactly as it is. The default, because a configuration file is an
    /// operator's work and a corrupt one is something they need to be told about.
    Fail,
    /// Rename the unreadable file aside, then write and return the default. For an unattended
    /// deployment that must come up rather than sit in a boot loop -- it keeps the evidence, so the
    /// fault can still be diagnosed afterwards. If the rename fails, this throws rather than
    /// overwriting: an explicit override that destroys the file on a full or read-only filesystem would
    /// reintroduce exactly the fault it exists to avoid.
    RecoverAndPreserve
  };

  /// Loads the configuration file, creating and storing the default if it is absent.
  ///
  /// If a file exists at the resolved path it is loaded and strictly validated; an existing file
  /// that loads but fails validation is reported via @ref UaException and is never overwritten. If
  /// no file is present, the built-in default (@ref load_default) is created, written to the
  /// resolved path, and returned.
  ///
  /// @param filename Path to use; when empty, falls back to @ref default_config_file.
  /// @param onUnreadable What to do with a file that is present but cannot be read or parsed.
  /// @return The loaded or newly created configuration.
  /// @throws UaException if an existing file fails validation, if it cannot be read and
  ///         @p onUnreadable is @ref OnUnreadableFile::Fail, if it cannot be renamed aside under
  ///         @ref OnUnreadableFile::RecoverAndPreserve, or if the default cannot be stored.
  /// @see load_default, default_config_file
  static ProcessConfigurationFile load_or_create_and_store_default(
    optional<std::filesystem::path> filename = std::nullopt,
    OnUnreadableFile onUnreadable = OnUnreadableFile::Fail);

  /// Validates the whole configuration, including every server and client instance.
  ///
  /// @throws UaException if the application defaults or any instance configuration is invalid.
  void validate() const;
};

}  // namespace ua

#endif  // !UA_PROCESS_CONFIGURATION_FILE_H
