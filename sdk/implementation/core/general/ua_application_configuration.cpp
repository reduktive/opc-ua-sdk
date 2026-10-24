// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_guid.h"
#include "ua_json_helpers.h"

namespace ua
{

ApplicationConfig::ApplicationConfig(const std::nullptr_t)
{}

const ApplicationConfig::ApplicationDescriptionPart& ApplicationConfig::application_description_part() const
{
  return mApplicationDescriptionPart;
}

const ApplicationConfig::StackLimits& ApplicationConfig::stack_limits() const
{
  return mStackLimits;
}

const ExecutionLimits& ApplicationConfig::execution_limits() const
{
  return executionLimits;
}

const ApplicationConfig::FileTrustListConfig& ApplicationConfig::file_trust_list_configuration() const
{
  return mFileTrustListConfiguration;
}

ApplicationConfig::ApplicationDescriptionPart& ApplicationConfig::application_description_part()
{
  return mApplicationDescriptionPart;
}

ApplicationConfig::StackLimits& ApplicationConfig::stack_limits()
{
  return mStackLimits;
}

ExecutionLimits& ApplicationConfig::execution_limits()
{
  return executionLimits;
}

ApplicationConfig::FileTrustListConfig& ApplicationConfig::file_trust_list_configuration()
{
  return mFileTrustListConfiguration;
}

void ApplicationConfig::validate() const
{
  if (executionLimits.decodeWorkLimit == 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidDecodeWorkLimit", "DecodeWorkLimit must be > 0", "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(executionLimits.decodeWorkLimit))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (executionLimits.decodeRecursionDepthLimit == 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidDecodeRecursionDepthLimit",
        "DecodeRecursionDepthLimit must be > 0",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(executionLimits.decodeRecursionDepthLimit))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (executionLimits.instantiationDepthLimit == 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "InvalidInstantiationDepthLimit", "InstantiationDepthLimit must be > 0", "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(executionLimits.instantiationDepthLimit))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  // The floor is not 1. The server spends this budget importing its own NS0 NodeSet before it serves
  // anything (`is_a_child_of` walks type hierarchies), so a value that is legal-but-tiny aborts startup.
  // Rejecting it here turns a crash into a configuration error naming the field; the import sites are
  // ALSO guarded, so a future NodeSet needing more than this floor still fails cleanly rather than fatally.
  if (executionLimits.loopLimit < ua::ExecutionLimits::minWorkableLoopLimit)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidLoopLimit",
        "LoopLimit is below the minimum the server's own NodeSet import requires",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(executionLimits.loopLimit))
        .context(ua::ContextKeys::min, std::to_string(ua::ExecutionLimits::minWorkableLoopLimit))};
  }

  if (mStackLimits.connectionProtocolTimeout.count() <= 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidConnectionProtocolTimeout",
        "ConnectionProtocolTimeout must be > 0 (milliseconds)",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(mStackLimits.connectionProtocolTimeout.count()))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (mStackLimits.connectionProtocolMessageReadTimeout.count() <= 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidConnectionProtocolMessageReadTimeout",
        "ConnectionProtocolMessageReadTimeout must be > 0 (milliseconds)",
        "ApplicationConfiguration")
        .context(
          ua::ContextKeys::actual, std::to_string(mStackLimits.connectionProtocolMessageReadTimeout.count()))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (mStackLimits.secureChannelMinimumLifetime.count() <= 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidSecureChannelMinimumLifetime",
        "SecureChannelMinimumLifetime must be > 0 (milliseconds)",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(mStackLimits.secureChannelMinimumLifetime.count()))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (mStackLimits.secureChannelMaximumLifetime < mStackLimits.secureChannelMinimumLifetime)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidSecureChannelMaximumLifetime",
        "SecureChannelMaximumLifetime must be >= SecureChannelMinimumLifetime (milliseconds)",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(mStackLimits.secureChannelMaximumLifetime.count()))
        .context(ua::ContextKeys::min, std::to_string(mStackLimits.secureChannelMinimumLifetime.count()))};
  }

  if (mStackLimits.sessionMinimumTimeout.count() <= 0)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidSessionMinimumTimeout",
        "SessionMinimumTimeout must be > 0 (milliseconds)",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(mStackLimits.sessionMinimumTimeout.count()))
        .context(ua::ContextKeys::min, std::to_string(1))};
  }

  if (mStackLimits.sessionMaximumTimeout < mStackLimits.sessionMinimumTimeout)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidSessionMaximumTimeout",
        "SessionMaximumTimeout must be >= SessionMinimumTimeout (milliseconds)",
        "ApplicationConfiguration")
        .context(ua::ContextKeys::actual, std::to_string(mStackLimits.sessionMaximumTimeout.count()))
        .context(ua::ContextKeys::min, std::to_string(mStackLimits.sessionMinimumTimeout.count()))};
  }
}

ApplicationDescription ApplicationConfig::construct_application_description(
  const ApplicationIdentity& identity, span<std::string_view> discoveryUrls) const
{
  ApplicationDescription applicationDescription;
  applicationDescription.application_uri() = mApplicationDescriptionPart.applicationUri;
  applicationDescription.application_name() = identity.applicationName;
  applicationDescription.application_type() = identity.applicationType;
  applicationDescription.product_uri() = identity.productUri;

  auto& urls = applicationDescription.discovery_urls().payload();
  utils::append_span_to_vector(discoveryUrls, urls);
  return applicationDescription;
}

void ApplicationConfig::store(const std::filesystem::path& filename) const
{
  auto name = filename.generic_string();
  FileStream outfile{filename.generic_string()};
  auto status = outfile.open_for_write(true, false);
  if (!status.is_good())
  {
    throw UaException{status.as_status(),
      ErrorDetail::build(
        "ConfigFileWriteError", "Could not open file for writing", "ApplicationConfiguration")
        .context(ua::ContextKeys::filePath, name)};
  }
  store(outfile);
}

void ApplicationConfig::store(Stream& stream) const
{
  const auto json = to_json_string(true);
  const span<const byte> bytes{utils::chars_to_bytes(json.data()), json.size()};
  stream.write_all(bytes);
}

ApplicationConfig ApplicationConfig::load(const std::filesystem::path& filename)
{
  auto name = filename.string();
  FileStream outfile{filename.string()};
  auto status = outfile.open_for_read();
  if (!status.is_good())
  {
    throw UaException{status.as_status(),
      ErrorDetail::build("ConfigFileReadError", "Could not open file for reading", "ApplicationConfiguration")
        .context(ua::ContextKeys::filePath, name)};
  }
  return load(outfile);
}

ApplicationConfig ApplicationConfig::load(const Stream& stream)
{
  std::vector<byte> bytes(stream.get_length());
  stream.read_all(bytes);
  const string_view text{utils::bytes_to_chars(bytes.data()), bytes.size()};

  return from_json_string(text);
}

std::string ApplicationConfig::to_json_string(bool pretty) const
{
  const boost::json::value v = json_helpers::to_json_value(*this);
  return pretty ? json_helpers::pretty_json(v) : boost::json::serialize(v);
}

ApplicationConfig ApplicationConfig::from_json_string(std::string_view json)
{
  const auto jv = json_helpers::parse_json(json);
  return json_helpers::application_configuration_from_json(jv);
}

ApplicationIdentity ApplicationIdentity::load_default()
{
  ApplicationIdentity identity;
  identity.productUri = "http://reduktive.com/OPCUA/SDK/Server";
  identity.applicationName = LocalizedText{"en", "OPC UA SDK Server"};
  identity.applicationType = ApplicationType::Server;
  return identity;
}

ApplicationConfig ApplicationConfig::load_default()
{
  ApplicationConfig config{nullptr};

  auto& trust = config.file_trust_list_configuration();
  trust.defaultApplicationGroupTrustListPath = std::filesystem::path{"./pki/own"};
  trust.defaultApplicationGroupTrustListValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  // The user-token path is deliberately left unset: setting it makes the server open a trust list,
  // arm a refresh timer, and publish a DefaultUserTokenGroup, which only a deployment that offers an
  // X.509 user-token policy wants.
  trust.defaultUserTokenGroupTrustListValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  trust.trustListRefreshPeriod = std::chrono::seconds{5};

  config.validate();
  return config;
}

std::filesystem::path ApplicationConfig::default_config_file()
{
  return std::filesystem::path{"./ApplicationConfiguration.json"};
}

}  // namespace ua
