// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_process_configuration_file.h"

#include "ua_client_configuration.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_to_result.h"
#include "ua_guid.h"
#include "ua_json_helpers.h"
#include "ua_tcp_endpoint.h"
#include "ua_transport_address.h"

#include "fmt/format.h"

#include <boost/asio/ip/host_name.hpp>

#include <cctype>
#include <ranges>
#include <unordered_set>

namespace ua
{

// Forward declarations for Boost.JSON conversions defined in this translation unit.
static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const UserTokenPolicy& p);
static UserTokenPolicy tag_invoke(
  const boost::json::value_to_tag<UserTokenPolicy>&, const boost::json::value& jv);

// ServerConfig::OperationLimits is ua::ServiceOperationLimits, so its conversions belong to namespace ua.
static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServiceOperationLimits& lim);
static ServiceOperationLimits tag_invoke(
  const boost::json::value_to_tag<ServiceOperationLimits>&, const boost::json::value& jv);

namespace server
{
static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ListenOptions& opt);
static ListenOptions tag_invoke(
  const boost::json::value_to_tag<ListenOptions>&, const boost::json::value& jv);

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ServerEndpointConfig& cfg);
static ServerEndpointConfig tag_invoke(
  const boost::json::value_to_tag<ServerEndpointConfig>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ListenerConfig& cfg);
static ServerConfig::ListenerConfig tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ListenerConfig>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ServerCapabilities& caps);
static ServerConfig::ServerCapabilities tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ServerCapabilities>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::HistoryConfig& hist);
static ServerConfig::HistoryConfig tag_invoke(
  const boost::json::value_to_tag<ServerConfig::HistoryConfig>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ConnectionThrottling& t);
static ServerConfig::ConnectionThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ConnectionThrottling>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::IdentityThrottling& t);
static ServerConfig::IdentityThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::IdentityThrottling>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::DiscoveryThrottling& t);
static ServerConfig::DiscoveryThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::DiscoveryThrottling>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ResourceLimits& lim);
static ServerConfig::ResourceLimits tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ResourceLimits>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::SubscriptionLimits& limits);
static ServerConfig::SubscriptionLimits tag_invoke(
  const boost::json::value_to_tag<ServerConfig::SubscriptionLimits>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ReverseConnectTarget& t);
static ServerConfig::ReverseConnectTarget tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ReverseConnectTarget>&, const boost::json::value& jv);

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::LocalDiscoveryServer& lds);
static ServerConfig::LocalDiscoveryServer tag_invoke(
  const boost::json::value_to_tag<ServerConfig::LocalDiscoveryServer>&, const boost::json::value& jv);

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ServerConfig& cfg);
static ServerConfig tag_invoke(const boost::json::value_to_tag<ServerConfig>&, const boost::json::value& jv);
}  // namespace server

namespace client
{
static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ClientConfig& cfg);
static ClientConfig tag_invoke(const boost::json::value_to_tag<ClientConfig>&, const boost::json::value& jv);
}  // namespace client

namespace
{

bool contains_whitespace(std::string_view s)
{
  for (const char ch : s)
  {
    // <cctype> requires an unsigned-char (or EOF) argument; a negative char is UB.
    if (std::isspace(static_cast<unsigned char>(ch)))
    {
      return true;
    }
  }
  return false;
}

std::vector<std::string_view> split_by_colon(std::string_view s)
{
  std::vector<std::string_view> parts;
  while (true)
  {
    const auto pos = s.find(':');
    if (pos == std::string_view::npos)
    {
      parts.emplace_back(s);
      return parts;
    }

    parts.emplace_back(s.substr(0, pos));
    s.remove_prefix(pos + 1);
  }
}

void validate_application_uri(std::string_view applicationUri)
{
  if (applicationUri.empty())
  {
    throw UaException{Status::BadConfigurationError,
      make_error_detail(
        "MissingApplicationUri", "ApplicationUri must not be empty", "ProcessConfigurationFile")};
  }

  if (contains_whitespace(applicationUri))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "InvalidApplicationUri", "ApplicationUri must not contain whitespace", "ProcessConfigurationFile")
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
  }

  // Accept any valid absolute URI, not just our default URN format.
  // Minimal RFC 3986 check:
  //   URI = scheme ":" hier-part / etc.
  //   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  const auto colonPos = applicationUri.find(':');
  if ((colonPos == std::string_view::npos) || (colonPos == 0))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidApplicationUri",
        "ApplicationUri must be an absolute URI of the form <scheme>:<scheme-specific-part>",
        "ProcessConfigurationFile")
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
  }

  const auto scheme = applicationUri.substr(0, colonPos);
  {
    const unsigned char first = numeric_cast<unsigned char>(scheme.front());
    if (!std::isalpha(first))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidApplicationUri",
          "ApplicationUri scheme must start with an alphabetic character",
          "ProcessConfigurationFile")
          .context(ua::ContextKeys::value, std::string{scheme})};
    }
  }
  for (const char ch : scheme)
  {
    // <cctype> requires an unsigned-char (or EOF) argument; a negative char is UB.
    if (!(std::isalnum(static_cast<unsigned char>(ch)) || (ch == '+') || (ch == '-') || (ch == '.')))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidApplicationUri",
          "ApplicationUri scheme contains an invalid character",
          "ProcessConfigurationFile")
          .context(ua::ContextKeys::value, std::string(1, ch))};
    }
  }

  const auto rest = applicationUri.substr(colonPos + 1);
  if (rest.empty())
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidApplicationUri",
        "ApplicationUri must contain a non-empty scheme-specific-part",
        "ProcessConfigurationFile")
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
  }
}

void validate_default_application_uri_urn(std::string_view applicationUri)
{
  validate_application_uri(applicationUri);

  constexpr std::string_view prefix = "urn:";
  if (!applicationUri.starts_with(prefix))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "InvalidApplicationUri", "Default ApplicationUri must start with 'urn:'", "ProcessConfigurationFile")
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
  }

  const auto urnRest = applicationUri.substr(prefix.size());
  const auto parts = split_by_colon(urnRest);

  // urn:reduktive:opcua-sdk:<hostname>:<guid>
  if (parts.size() != 4)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("InvalidApplicationUri",
        "Default ApplicationUri must have 4 non-empty components after 'urn:' "
        "(reduktive:opcua-sdk:<hostname>:<instance-id>)",
        "ProcessConfigurationFile")
        .context(ua::ContextKeys::sizeExpected, "4")
        .context(ua::ContextKeys::sizeActual, std::to_string(parts.size()))
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
  }

  for (const auto& p : parts)
  {
    if (p.empty())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidApplicationUri",
          "Default ApplicationUri urn components must not be empty "
          "(reduktive:opcua-sdk:<hostname>:<instance-id>)",
          "ProcessConfigurationFile")
          .context(ua::ContextKeys::applicationUri, std::string{applicationUri})};
    }
  }
}

std::string generate_default_application_uri()
{
  std::string host = boost::asio::ip::host_name();
  if (host.empty())
  {
    host = "unknown-host";
  }

  auto uri = fmt::format("urn:reduktive:opcua-sdk:{}:{}", host, Guid::create_and_generate().as_string());
  validate_default_application_uri_urn(uri);
  return uri;
}

template<typename Enum>
boost::json::value enum_to_json(Enum e)
{
  using Under = std::underlying_type_t<Enum>;
  return boost::json::value_from(static_cast<Under>(e));
}

template<typename Enum>
Enum enum_from_json(const boost::json::value& jv)
{
  using Under = std::underlying_type_t<Enum>;
  return static_cast<Enum>(boost::json::value_to<Under>(jv));
}

// WellKnownRole <-> stable JSON string (the enumerator name). Stable names keep the config file
// human-readable and resilient to enumerator-value churn, unlike the raw underlying integer.
std::string_view well_known_role_to_string(ua::server::WellKnownRole role)
{
  switch (role)
  {
  case ua::server::WellKnownRole::Anonymous:
    return "Anonymous";
  case ua::server::WellKnownRole::AuthenticatedUser:
    return "AuthenticatedUser";
  case ua::server::WellKnownRole::Observer:
    return "Observer";
  case ua::server::WellKnownRole::Operator:
    return "Operator";
  case ua::server::WellKnownRole::Engineer:
    return "Engineer";
  case ua::server::WellKnownRole::Supervisor:
    return "Supervisor";
  case ua::server::WellKnownRole::ConfigureAdmin:
    return "ConfigureAdmin";
  case ua::server::WellKnownRole::SecurityAdmin:
    return "SecurityAdmin";
  case ua::server::WellKnownRole::TrustedApplication:
    return "TrustedApplication";
  }
  throw UaException{Status::BadConfigurationError,
    make_error_detail("InvalidWellKnownRole", "Unknown WellKnownRole enumerator", "ServerConfiguration")};
}

ua::server::WellKnownRole well_known_role_from_string(std::string_view name)
{
  using ua::server::WellKnownRole;
  if (name == "Anonymous")
    return WellKnownRole::Anonymous;
  if (name == "AuthenticatedUser")
    return WellKnownRole::AuthenticatedUser;
  if (name == "Observer")
    return WellKnownRole::Observer;
  if (name == "Operator")
    return WellKnownRole::Operator;
  if (name == "Engineer")
    return WellKnownRole::Engineer;
  if (name == "Supervisor")
    return WellKnownRole::Supervisor;
  if (name == "ConfigureAdmin")
    return WellKnownRole::ConfigureAdmin;
  if (name == "SecurityAdmin")
    return WellKnownRole::SecurityAdmin;
  if (name == "TrustedApplication")
    return WellKnownRole::TrustedApplication;
  throw UaException{Status::BadConfigurationError,
    ErrorDetail::build("InvalidWellKnownRole", "Unknown WellKnownRole name", "ServerConfiguration")
      .context(ua::ContextKeys::value, std::string{name})};
}

}  // namespace

ProcessConfigurationFile::ProcessConfigurationFile(ApplicationConfig applicationConfig,
  std::vector<ServerInstanceConfig> serverInstances, std::vector<ClientInstanceConfig> clientInstances)
  : application(std::move(applicationConfig)), servers(std::move(serverInstances)),
    clients(std::move(clientInstances))
{}

void ProcessConfigurationFile::ServerInstanceConfig::validate() const
{
  if (name.empty())
  {
    throw UaException{Status::BadConfigurationError,
      make_error_detail(
        "MissingConfigField", "Server instance Name must not be empty", "ProcessConfigurationFile")};
  }

  server.validate();
}

void ProcessConfigurationFile::ClientInstanceConfig::validate() const
{
  if (name.empty())
  {
    throw UaException{Status::BadConfigurationError,
      make_error_detail(
        "MissingConfigField", "Client instance Name must not be empty", "ProcessConfigurationFile")};
  }
}

void ProcessConfigurationFile::validate() const
{
  application.validate();

  {
    std::unordered_set<std::string_view> names;
    for (const auto& s : servers)
    {
      s.validate();

      const auto effectiveApplication = ua::apply_overrides(application, s.applicationOverrides);

      try
      {
        validate_application_uri(effectiveApplication.application_description_part().applicationUri);
      }
      catch (...)
      {
        detail::rethrow_as_ua_exception(Status::BadConfigurationError,
          [&](std::string_view what)
          { return fmt::format("Server instance {}: Invalid ApplicationUri: {}", s.name, what); });
      }

      const bool allowInsecureEndpoints = effectiveApplication.allowInsecureEndpoints;

      if (!allowInsecureEndpoints)
      {
        for (const auto& listener : s.server.listeners())
        {
          for (const auto& endpoint : listener.endpoints)
          {
            const bool endpointIsInsecure = (endpoint.securityPolicyId == SecurityPolicyId::None) ||
                                            (endpoint.messageSecurityMode == MessageSecurityMode::None);

            const bool offersAnonymous = std::ranges::any_of(endpoint.userIdentityTokens,
              [](const UserTokenPolicy& p) { return p.token_type() == UserTokenType::Anonymous; });

            if (offersAnonymous && endpointIsInsecure)
            {
              throw UaException{Status::BadConfigurationError,
                ErrorDetail::build("InsecureEndpointConfig",
                  "Anonymous user token is not allowed on insecure endpoints unless "
                  "AllowInsecureEndpoints is true",
                  "ProcessConfigurationFile")
                  .context(ua::ContextKeys::fieldName, s.name)};
            }
          }
        }
      }

      if (!names.emplace(s.name).second)
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build(
            "DuplicateConfigName", "Duplicate server instance Name", "ProcessConfigurationFile")
            .context(ua::ContextKeys::fieldName, s.name)};
      }
    }
  }

  {
    std::unordered_set<std::string_view> names;
    for (const auto& c : clients)
    {
      c.validate();

      const auto effectiveApplication = ua::apply_overrides(application, c.applicationOverrides);
      try
      {
        validate_application_uri(effectiveApplication.application_description_part().applicationUri);
      }
      catch (...)
      {
        detail::rethrow_as_ua_exception(Status::BadConfigurationError,
          [&](std::string_view what)
          { return fmt::format("Client instance {}: Invalid ApplicationUri: {}", c.name, what); });
      }

      if (!names.emplace(c.name).second)
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build(
            "DuplicateConfigName", "Duplicate client instance Name", "ProcessConfigurationFile")
            .context(ua::ContextKeys::fieldName, c.name)};
      }
    }
  }
}

void ProcessConfigurationFile::store(const std::filesystem::path& filename) const
{
  auto name = filename.generic_string();
  FileStream outfile{filename.generic_string()};
  auto status = outfile.open_for_write(true, false);
  if (!status.is_good())
  {
    throw UaException{status.as_status(),
      ErrorDetail::build(
        "ConfigFileWriteError", "Could not open configuration file for writing", "ProcessConfigurationFile")
        .context(ua::ContextKeys::filePath, name)};
  }
  store(outfile);
}

void ProcessConfigurationFile::store(Stream& stream) const
{
  validate();
  const auto output = to_json_string(true);
  const span<const byte> bytes{utils::chars_to_bytes(output.data()), output.size()};
  stream.write_all(bytes);
}

ProcessConfigurationFile ProcessConfigurationFile::load(const std::filesystem::path& filename)
{
  auto name = filename.string();
  FileStream infile{filename.string()};
  auto status = infile.open_for_read();
  if (!status.is_good())
  {
    throw UaException{status.as_status(),
      ErrorDetail::build(
        "ConfigFileReadError", "Could not open configuration file for reading", "ProcessConfigurationFile")
        .context(ua::ContextKeys::filePath, name)};
  }
  return load(infile);
}

ProcessConfigurationFile ProcessConfigurationFile::load(const Stream& stream)
{
  ByteString bytes;
  bytes.resize(stream.get_length());
  stream.read_all(bytes);
  const string_view text = utils::to_string_view(std::span<const uint8_t>{bytes});

  return from_json_string(text);
}

std::string ProcessConfigurationFile::to_json_string(bool pretty) const
{
  validate();

  boost::json::object obj;
  obj.emplace("Application", ua::json_helpers::to_json_value(application));

  {
    boost::json::array serverArray;
    serverArray.reserve(servers.size());
    for (const auto& s : servers)
    {
      boost::json::object serverObj;
      serverObj.emplace("Name", boost::json::value_from(s.name));
      serverObj.emplace("ApplicationOverrides", ua::json_helpers::to_json_value(s.applicationOverrides));
      serverObj.emplace("Server", boost::json::value_from(s.server));
      serverArray.emplace_back(std::move(serverObj));
    }
    obj.emplace("Servers", std::move(serverArray));
  }

  {
    boost::json::array clientArray;
    clientArray.reserve(clients.size());
    for (const auto& c : clients)
    {
      boost::json::object clientObj;
      clientObj.emplace("Name", boost::json::value_from(c.name));
      clientObj.emplace("ApplicationOverrides", ua::json_helpers::to_json_value(c.applicationOverrides));
      clientObj.emplace("Client", boost::json::value_from(c.client));

      clientArray.emplace_back(std::move(clientObj));
    }
    obj.emplace("Clients", std::move(clientArray));
  }

  // Parenthesised, NOT braced: `value{obj}` selects Boost.JSON's initializer-list constructor, which wraps
  // the object in a one-element array - and `from_json_string` opens with `as_object()`, so every file this
  // function wrote was unloadable.
  const boost::json::value v(std::move(obj));
  return pretty ? ua::json_helpers::pretty_json(v) : boost::json::serialize(v);
}

ProcessConfigurationFile ProcessConfigurationFile::from_json_string(std::string_view json)
{
  try
  {
    const auto jv = ua::json_helpers::parse_json(json);
    if (!jv.is_object())
    {
      // Say WHAT is wrong with the document, not merely that it did not decode. A configuration written by
      // a writer that emitted the wrong shape failed here as a bare Bad_DecodingError, which named neither
      // the shape nor the writer - and every file this SDK stored was such a file until the `value{obj}`
      // brace-initialisation in `to_json_string` was corrected. ErrorDetail propagation is rule #1.
      throw UaException{Status::BadDecodingError,
        ErrorDetail::build("ConfigurationRootIsNotAnObject",
          "the configuration document's root must be a JSON object carrying Application/Servers/Clients",
          "ProcessConfigurationFile")
          .context(ua::ContextKeys::expected, std::string{"object"})
          .context(ua::ContextKeys::actual, std::string{jv.is_array() ? "array" : "scalar"})};
    }
    const auto& obj = jv.as_object();

    auto application = ua::json_helpers::application_configuration_from_json(obj.at("Application"));

    std::vector<ServerInstanceConfig> servers;
    if (const auto it = obj.find("Servers"); it != obj.end())
    {
      const auto& arr = it->value().as_array();
      servers.reserve(arr.size());
      for (const auto& item : arr)
      {
        const auto& so = item.as_object();
        ServerInstanceConfig s;
        s.name = ua::json_helpers::required<std::string>(so, "Name");
        if (const auto ao = so.find("ApplicationOverrides"); ao != so.end())
        {
          s.applicationOverrides = ua::json_helpers::application_overrides_from_json(ao->value());
        }
        s.server = boost::json::value_to<::ua::server::ServerConfig>(so.at("Server"));
        s.validate();
        servers.emplace_back(std::move(s));
      }
    }

    std::vector<ClientInstanceConfig> clients;
    if (const auto it = obj.find("Clients"); it != obj.end())
    {
      const auto& arr = it->value().as_array();
      clients.reserve(arr.size());
      for (const auto& item : arr)
      {
        const auto& co = item.as_object();
        ClientInstanceConfig c;
        c.name = ua::json_helpers::required<std::string>(co, "Name");
        if (const auto ao = co.find("ApplicationOverrides"); ao != co.end())
        {
          c.applicationOverrides = ua::json_helpers::application_overrides_from_json(ao->value());
        }
        if (const auto cj = co.find("Client"); cj != co.end())
        {
          c.client = boost::json::value_to<::ua::client::ClientConfig>(cj->value());
        }
        c.validate();
        clients.emplace_back(std::move(c));
      }
    }

    ProcessConfigurationFile file{std::move(application), std::move(servers), std::move(clients)};
    file.validate();
    return file;
  }
  catch (...)
  {
    detail::rethrow_as_ua_exception(Status::BadDecodingError);
  }
}

ProcessConfigurationFile ProcessConfigurationFile::load_default()
{
  std::vector<ServerInstanceConfig> servers;

  ::ua::server::ServerConfig serverCfg;
  // Default config has no listeners - the application is responsible for adding
  // listeners/endpoints appropriate for its deployment (security policy, user tokens, etc.).

  servers.emplace_back(ServerInstanceConfig{
    .name = "DefaultServer", .applicationOverrides = {}, .server = std::move(serverCfg)});

  auto application = ApplicationConfig::load_default();
  application.application_description_part().applicationUri = generate_default_application_uri();

  ProcessConfigurationFile file{std::move(application), std::move(servers), {}};
  file.validate();
  return file;
}

std::filesystem::path ProcessConfigurationFile::default_config_file()
{
  return std::filesystem::path{"./ProcessConfiguration.json"};
}

ProcessConfigurationFile ProcessConfigurationFile::load_or_create_and_store_default(
  optional<std::filesystem::path> filename, OnUnreadableFile onUnreadable)
{
  const auto configFile = filename.value_or(default_config_file());

  // ONLY an absent file is replaced with the default. This used to wrap the load in a catch-all
  // that wrote the default on ANY failure, so a present-but-corrupt file -- the case an operator
  // most needs to hear about -- was silently overwritten with the listener-less default, destroying
  // both the evidence and their intent. The header has always promised the opposite ("an existing
  // file ... is never overwritten"); this is the code catching up with its own contract.
  std::error_code existsError;
  if (!std::filesystem::exists(configFile, existsError) || existsError)
  {
    auto configuration = load_default();
    configuration.store(configFile);
    return configuration;
  }

  try
  {
    // Strict: an existing file that loads but fails validation throws and is not touched, under
    // either policy. It is well-formed and wrong, so its intent is legible and worth keeping.
    ProcessConfigurationFile loaded = load(configFile);
    loaded.validate();
    return loaded;
  }
  catch (const UaException&)
  {
    if (onUnreadable == OnUnreadableFile::Fail)
    {
      throw;
    }
  }

  // RecoverAndPreserve: keep the unreadable file under a sibling name, then write the default. The
  // rename is what makes this non-destructive, so a rename that fails must NOT fall through to
  // storing over the original.
  auto preserved = configFile;
  preserved += ".unreadable";
  std::error_code renameError;
  std::filesystem::rename(configFile, preserved, renameError);
  if (renameError)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("ConfigFilePreserveFailed",
        "the configuration file could not be read and could not be renamed aside, so it was left "
        "untouched rather than overwritten",
        "ProcessConfigurationFile")
        .context(ua::ContextKeys::filePath, configFile.string())};
  }

  auto configuration = load_default();
  configuration.store(configFile);
  return configuration;
}

// --- JSON conversions for server config types ---

namespace server
{

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ListenOptions& opt)
{
  using namespace boost::json;

  object obj;
  if (opt.timeout)
  {
    obj.emplace("Timeout", value_from(opt.timeout->count()));
  }
  obj.emplace("FailIfAlreadyListening", value_from(opt.failIfAlreadyListening));
  jv = std::move(obj);
}

static ListenOptions tag_invoke(const boost::json::value_to_tag<ListenOptions>&, const boost::json::value& jv)
{
  using namespace boost::json;

  const object& obj = jv.as_object();
  ListenOptions opt;
  if (obj.contains("Timeout"))
  {
    opt.timeout = std::chrono::seconds{value_to<int64_t>(obj.at("Timeout"))};
  }
  if (obj.contains("FailIfAlreadyListening"))
  {
    opt.failIfAlreadyListening = value_to<bool>(obj.at("FailIfAlreadyListening"));
  }
  return opt;
}

}  // namespace server

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const UserTokenPolicy& p)
{
  using namespace boost::json;

  jv = {{"PolicyId", value_from(std::string{p.policy_id()})},
    {"TokenType", enum_to_json(p.token_type())},
    {"IssuedTokenType", value_from(std::string{p.issued_token_type()})},
    {"IssuerEndpointUrl", value_from(std::string{p.issuer_endpoint_url()})},
    {"SecurityPolicyUri", value_from(std::string{p.security_policy_uri()})}};
}

static UserTokenPolicy tag_invoke(
  const boost::json::value_to_tag<UserTokenPolicy>&, const boost::json::value& jv)
{
  using namespace boost::json;

  const object& obj = jv.as_object();
  UserTokenPolicy p;
  p.policy_id() = value_to<std::string>(obj.at("PolicyId"));
  p.token_type() = enum_from_json<UserTokenType>(obj.at("TokenType"));
  if (obj.contains("IssuedTokenType"))
  {
    p.issued_token_type() = value_to<std::string>(obj.at("IssuedTokenType"));
  }
  if (obj.contains("IssuerEndpointUrl"))
  {
    p.issuer_endpoint_url() = value_to<std::string>(obj.at("IssuerEndpointUrl"));
  }
  if (obj.contains("SecurityPolicyUri"))
  {
    p.security_policy_uri() = value_to<std::string>(obj.at("SecurityPolicyUri"));
  }
  return p;
}

namespace server
{

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ServerEndpointConfig& cfg)
{
  using namespace boost::json;

  jv = {{"Name", value_from(cfg.name)},
    {"MessageSecurityMode", enum_to_json(cfg.messageSecurityMode)},
    {"SecurityPolicyId", enum_to_json(cfg.securityPolicyId)},
    {"TransportProfile", enum_to_json(cfg.transportProfile)},
    {"UserIdentityTokens", value_from(cfg.userIdentityTokens)}};
}

static ServerEndpointConfig tag_invoke(
  const boost::json::value_to_tag<ServerEndpointConfig>&, const boost::json::value& jv)
{
  using namespace boost::json;

  const object& obj = jv.as_object();
  ServerEndpointConfig cfg;
  cfg.name = ua::json_helpers::required<std::string>(obj, "Name");
  cfg.messageSecurityMode = enum_from_json<MessageSecurityMode>(obj.at("MessageSecurityMode"));
  cfg.securityPolicyId = enum_from_json<SecurityPolicyId>(obj.at("SecurityPolicyId"));
  cfg.transportProfile = enum_from_json<TransportProfileId>(obj.at("TransportProfile"));
  if (obj.contains("UserIdentityTokens"))
  {
    cfg.userIdentityTokens = value_to<std::vector<UserTokenPolicy>>(obj.at("UserIdentityTokens"));
  }
  return cfg;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ListenerConfig& cfg)
{
  using namespace boost::json;

  jv = {{"Name", value_from(cfg.name)},
    {"Bind",
      {{"TransportProfileId", enum_to_json(cfg.bind.transportProfileId)},
        {"Address", value_from(cfg.bind.address)}}},
    {"ListenOptions", value_from(cfg.listenOptions)},
    {"Endpoints", value_from(cfg.endpoints)}};

  if (cfg.externalUrl)
  {
    jv.as_object()["ExternalUrl"] = value_from(cfg.externalUrl->str());
  }
}

static ServerConfig::ListenerConfig tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ListenerConfig>&, const boost::json::value& jv)
{
  using namespace boost::json;

  const object& obj = jv.as_object();
  ServerConfig::ListenerConfig cfg;
  cfg.name = value_to<std::string>(obj.at("Name"));

  {
    const auto& bindObj = obj.at("Bind").as_object();
    cfg.bind.transportProfileId = enum_from_json<TransportProfileId>(bindObj.at("TransportProfileId"));
    cfg.bind.address = value_to<std::string>(bindObj.at("Address"));
  }

  if (obj.contains("ListenOptions"))
  {
    cfg.listenOptions = value_to<ListenOptions>(obj.at("ListenOptions"));
  }
  if (obj.contains("ExternalUrl"))
  {
    cfg.externalUrl = ua::transport::EndpointUrl{value_to<std::string>(obj.at("ExternalUrl"))};
  }
  if (obj.contains("Endpoints"))
  {
    cfg.endpoints = value_to<std::vector<ServerEndpointConfig>>(obj.at("Endpoints"));
  }
  return cfg;
}

}  // namespace server

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ServiceOperationLimits& lim)
{
  using namespace boost::json;

  object obj;
  if (lim.maxNodesPerRead)
    obj.emplace("MaxNodesPerRead", value_from(*lim.maxNodesPerRead));
  if (lim.maxNodesPerHistoryReadData)
    obj.emplace("MaxNodesPerHistoryReadData", value_from(*lim.maxNodesPerHistoryReadData));
  if (lim.maxNodesPerHistoryReadEvents)
    obj.emplace("MaxNodesPerHistoryReadEvents", value_from(*lim.maxNodesPerHistoryReadEvents));
  if (lim.maxNodesPerWrite)
    obj.emplace("MaxNodesPerWrite", value_from(*lim.maxNodesPerWrite));
  if (lim.maxNodesPerHistoryUpdateData)
    obj.emplace("MaxNodesPerHistoryUpdateData", value_from(*lim.maxNodesPerHistoryUpdateData));
  if (lim.maxNodesPerHistoryUpdateEvents)
    obj.emplace("MaxNodesPerHistoryUpdateEvents", value_from(*lim.maxNodesPerHistoryUpdateEvents));
  if (lim.maxNodesPerMethodCall)
    obj.emplace("MaxNodesPerMethodCall", value_from(*lim.maxNodesPerMethodCall));
  if (lim.maxNodesPerBrowse)
    obj.emplace("MaxNodesPerBrowse", value_from(*lim.maxNodesPerBrowse));
  if (lim.maxNodesPerRegisterNodes)
    obj.emplace("MaxNodesPerRegisterNodes", value_from(*lim.maxNodesPerRegisterNodes));
  if (lim.maxNodesPerTranslateBrowsePathsToNodeIds)
    obj.emplace(
      "MaxNodesPerTranslateBrowsePathsToNodeIds", value_from(*lim.maxNodesPerTranslateBrowsePathsToNodeIds));
  if (lim.maxNodesPerNodeManagement)
    obj.emplace("MaxNodesPerNodeManagement", value_from(*lim.maxNodesPerNodeManagement));
  if (lim.maxMonitoredItemsPerCall)
    obj.emplace("MaxMonitoredItemsPerCall", value_from(*lim.maxMonitoredItemsPerCall));
  jv = std::move(obj);
}

static ServiceOperationLimits tag_invoke(
  const boost::json::value_to_tag<ServiceOperationLimits>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServiceOperationLimits lim;
  if (obj.contains("MaxNodesPerRead"))
    lim.maxNodesPerRead = value_to<uint32_t>(obj.at("MaxNodesPerRead"));
  if (obj.contains("MaxNodesPerHistoryReadData"))
    lim.maxNodesPerHistoryReadData = value_to<uint32_t>(obj.at("MaxNodesPerHistoryReadData"));
  if (obj.contains("MaxNodesPerHistoryReadEvents"))
    lim.maxNodesPerHistoryReadEvents = value_to<uint32_t>(obj.at("MaxNodesPerHistoryReadEvents"));
  if (obj.contains("MaxNodesPerWrite"))
    lim.maxNodesPerWrite = value_to<uint32_t>(obj.at("MaxNodesPerWrite"));
  if (obj.contains("MaxNodesPerHistoryUpdateData"))
    lim.maxNodesPerHistoryUpdateData = value_to<uint32_t>(obj.at("MaxNodesPerHistoryUpdateData"));
  if (obj.contains("MaxNodesPerHistoryUpdateEvents"))
    lim.maxNodesPerHistoryUpdateEvents = value_to<uint32_t>(obj.at("MaxNodesPerHistoryUpdateEvents"));
  if (obj.contains("MaxNodesPerMethodCall"))
    lim.maxNodesPerMethodCall = value_to<uint32_t>(obj.at("MaxNodesPerMethodCall"));
  if (obj.contains("MaxNodesPerBrowse"))
    lim.maxNodesPerBrowse = value_to<uint32_t>(obj.at("MaxNodesPerBrowse"));
  if (obj.contains("MaxNodesPerRegisterNodes"))
    lim.maxNodesPerRegisterNodes = value_to<uint32_t>(obj.at("MaxNodesPerRegisterNodes"));
  if (obj.contains("MaxNodesPerTranslateBrowsePathsToNodeIds"))
    lim.maxNodesPerTranslateBrowsePathsToNodeIds =
      value_to<uint32_t>(obj.at("MaxNodesPerTranslateBrowsePathsToNodeIds"));
  if (obj.contains("MaxNodesPerNodeManagement"))
    lim.maxNodesPerNodeManagement = value_to<uint32_t>(obj.at("MaxNodesPerNodeManagement"));
  if (obj.contains("MaxMonitoredItemsPerCall"))
    lim.maxMonitoredItemsPerCall = value_to<uint32_t>(obj.at("MaxMonitoredItemsPerCall"));
  return lim;
}

namespace server
{

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ServerCapabilities& caps)
{
  using namespace boost::json;
  object obj;
  obj.emplace("MinSupportedSampleRate", value_from(caps.minSupportedSampleRate));
  obj.emplace("MaxBrowseContinuationPoints", value_from(caps.maxBrowseContinuationPoints));
  obj.emplace("MaxQueryContinuationPoints", value_from(caps.maxQueryContinuationPoints));
  obj.emplace("MaxHistoryContinuationPoints", value_from(caps.maxHistoryContinuationPoints));
  if (caps.maxArrayLength)
    obj.emplace("MaxArrayLength", value_from(*caps.maxArrayLength));
  if (caps.maxStringLength)
    obj.emplace("MaxStringLength", value_from(*caps.maxStringLength));
  if (caps.maxByteStringLength)
    obj.emplace("MaxByteStringLength", value_from(*caps.maxByteStringLength));
  obj.emplace("OperationLimits", value_from(caps.operationLimits));
  if (caps.maxSessions)
    obj.emplace("MaxSessions", value_from(*caps.maxSessions));
  if (caps.maxSubscriptions)
    obj.emplace("MaxSubscriptions", value_from(*caps.maxSubscriptions));
  if (caps.maxMonitoredItems)
    obj.emplace("MaxMonitoredItems", value_from(*caps.maxMonitoredItems));
  if (caps.maxSubscriptionsPerSession)
    obj.emplace("MaxSubscriptionsPerSession", value_from(*caps.maxSubscriptionsPerSession));
  if (caps.maxMonitoredItemsPerSubscription)
    obj.emplace("MaxMonitoredItemsPerSubscription", value_from(*caps.maxMonitoredItemsPerSubscription));
  if (caps.maxSelectClauseParameters)
    obj.emplace("MaxSelectClauseParameters", value_from(*caps.maxSelectClauseParameters));
  if (caps.maxWhereClauseParameters)
    obj.emplace("MaxWhereClauseParameters", value_from(*caps.maxWhereClauseParameters));
  if (caps.maxMonitoredItemsQueueSize)
    obj.emplace("MaxMonitoredItemsQueueSize", value_from(*caps.maxMonitoredItemsQueueSize));
  obj.emplace("LocaleIds", value_from(caps.localeIds));
  obj.emplace("ServerProfiles", value_from(caps.serverProfiles));
  jv = std::move(obj);
}

static ServerConfig::ServerCapabilities tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ServerCapabilities>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServerConfig::ServerCapabilities caps;
  caps.minSupportedSampleRate = value_to<Duration>(obj.at("MinSupportedSampleRate"));
  caps.maxBrowseContinuationPoints = value_to<uint16_t>(obj.at("MaxBrowseContinuationPoints"));
  caps.maxQueryContinuationPoints = value_to<uint16_t>(obj.at("MaxQueryContinuationPoints"));
  caps.maxHistoryContinuationPoints = value_to<uint16_t>(obj.at("MaxHistoryContinuationPoints"));
  if (obj.contains("MaxArrayLength"))
    caps.maxArrayLength = value_to<uint32_t>(obj.at("MaxArrayLength"));
  if (obj.contains("MaxStringLength"))
    caps.maxStringLength = value_to<uint32_t>(obj.at("MaxStringLength"));
  if (obj.contains("MaxByteStringLength"))
    caps.maxByteStringLength = value_to<uint32_t>(obj.at("MaxByteStringLength"));
  if (obj.contains("OperationLimits"))
    caps.operationLimits = value_to<ServerConfig::OperationLimits>(obj.at("OperationLimits"));
  if (obj.contains("MaxSessions"))
    caps.maxSessions = value_to<uint32_t>(obj.at("MaxSessions"));
  if (obj.contains("MaxSubscriptions"))
    caps.maxSubscriptions = value_to<uint32_t>(obj.at("MaxSubscriptions"));
  if (obj.contains("MaxMonitoredItems"))
    caps.maxMonitoredItems = value_to<uint32_t>(obj.at("MaxMonitoredItems"));
  if (obj.contains("MaxSubscriptionsPerSession"))
    caps.maxSubscriptionsPerSession = value_to<uint32_t>(obj.at("MaxSubscriptionsPerSession"));
  if (obj.contains("MaxMonitoredItemsPerSubscription"))
    caps.maxMonitoredItemsPerSubscription = value_to<uint32_t>(obj.at("MaxMonitoredItemsPerSubscription"));
  if (obj.contains("MaxSelectClauseParameters"))
    caps.maxSelectClauseParameters = value_to<uint32_t>(obj.at("MaxSelectClauseParameters"));
  if (obj.contains("MaxWhereClauseParameters"))
    caps.maxWhereClauseParameters = value_to<uint32_t>(obj.at("MaxWhereClauseParameters"));
  if (obj.contains("MaxMonitoredItemsQueueSize"))
    caps.maxMonitoredItemsQueueSize = value_to<uint32_t>(obj.at("MaxMonitoredItemsQueueSize"));
  if (obj.contains("LocaleIds"))
    caps.localeIds = value_to<std::vector<std::string>>(obj.at("LocaleIds"));
  if (obj.contains("ServerProfiles"))
    caps.serverProfiles = value_to<std::vector<std::string>>(obj.at("ServerProfiles"));
  return caps;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::SubscriptionLimits& limits)
{
  using namespace boost::json;
  object obj;
  if (limits.minPublishingInterval)
    obj.emplace("MinPublishingInterval", value_from(limits.minPublishingInterval->count()));
  if (limits.maxPublishingInterval)
    obj.emplace("MaxPublishingInterval", value_from(limits.maxPublishingInterval->count()));
  if (limits.maxKeepAliveCount)
    obj.emplace("MaxKeepAliveCount", value_from(*limits.maxKeepAliveCount));
  if (limits.maxLifetimeCount)
    obj.emplace("MaxLifetimeCount", value_from(*limits.maxLifetimeCount));
  if (limits.maxNotificationsPerPublish)
    obj.emplace("MaxNotificationsPerPublish", value_from(*limits.maxNotificationsPerPublish));
  if (limits.maxPublishRequestsPerSession)
    obj.emplace("MaxPublishRequestsPerSession", value_from(*limits.maxPublishRequestsPerSession));
  if (limits.defaultEventQueueSize)
    obj.emplace("DefaultEventQueueSize", value_from(*limits.defaultEventQueueSize));
  if (limits.maxPendingStatusChanges)
    obj.emplace("MaxPendingStatusChanges", value_from(*limits.maxPendingStatusChanges));
  obj.emplace("DurableSubscriptionsEnabled", value_from(limits.durableSubscriptionsEnabled));
  obj.emplace("MaxDurableSubscriptionLifetimeHours", value_from(limits.maxDurableSubscriptionLifetimeHours));
  obj.emplace("MaxDurableMonitoredItemQueueSize", value_from(limits.maxDurableMonitoredItemQueueSize));
  if (limits.maxWhereClauseOperandBytes)
    obj.emplace("MaxWhereClauseOperandBytes", value_from(*limits.maxWhereClauseOperandBytes));
  jv = std::move(obj);
}

static ServerConfig::SubscriptionLimits tag_invoke(
  const boost::json::value_to_tag<ServerConfig::SubscriptionLimits>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServerConfig::SubscriptionLimits limits;
  if (obj.contains("MinPublishingInterval"))
    limits.minPublishingInterval =
      std::chrono::milliseconds{value_to<int64_t>(obj.at("MinPublishingInterval"))};
  if (obj.contains("MaxPublishingInterval"))
    limits.maxPublishingInterval =
      std::chrono::milliseconds{value_to<int64_t>(obj.at("MaxPublishingInterval"))};
  if (obj.contains("MaxKeepAliveCount"))
    limits.maxKeepAliveCount = value_to<uint32_t>(obj.at("MaxKeepAliveCount"));
  if (obj.contains("MaxLifetimeCount"))
    limits.maxLifetimeCount = value_to<uint32_t>(obj.at("MaxLifetimeCount"));
  if (obj.contains("MaxNotificationsPerPublish"))
    limits.maxNotificationsPerPublish = value_to<uint32_t>(obj.at("MaxNotificationsPerPublish"));
  if (obj.contains("MaxPublishRequestsPerSession"))
    limits.maxPublishRequestsPerSession = value_to<uint32_t>(obj.at("MaxPublishRequestsPerSession"));
  if (obj.contains("DefaultEventQueueSize"))
    limits.defaultEventQueueSize = value_to<uint32_t>(obj.at("DefaultEventQueueSize"));
  if (obj.contains("MaxPendingStatusChanges"))
    limits.maxPendingStatusChanges = value_to<uint32_t>(obj.at("MaxPendingStatusChanges"));
  if (obj.contains("DurableSubscriptionsEnabled"))
    limits.durableSubscriptionsEnabled = value_to<bool>(obj.at("DurableSubscriptionsEnabled"));
  if (obj.contains("MaxDurableSubscriptionLifetimeHours"))
    limits.maxDurableSubscriptionLifetimeHours =
      value_to<uint32_t>(obj.at("MaxDurableSubscriptionLifetimeHours"));
  if (obj.contains("MaxDurableMonitoredItemQueueSize"))
    limits.maxDurableMonitoredItemQueueSize = value_to<uint32_t>(obj.at("MaxDurableMonitoredItemQueueSize"));
  if (obj.contains("MaxWhereClauseOperandBytes"))
    limits.maxWhereClauseOperandBytes = value_to<uint32_t>(obj.at("MaxWhereClauseOperandBytes"));
  return limits;
}

namespace
{

std::string diagnostic_level_to_string(ServerConfig::DiagnosticPolicy::Level level)
{
  switch (level)
  {
  case ServerConfig::DiagnosticPolicy::Level::None:
    return "None";
  case ServerConfig::DiagnosticPolicy::Level::Summary:
    return "Summary";
  case ServerConfig::DiagnosticPolicy::Level::Full:
    return "Full";
  default:
    return "None";
  }
}

ServerConfig::DiagnosticPolicy::Level diagnostic_level_from_string(std::string_view str)
{
  if (str == "Summary")
    return ServerConfig::DiagnosticPolicy::Level::Summary;
  if (str == "Full")
    return ServerConfig::DiagnosticPolicy::Level::Full;
  if (str == "None")
    return ServerConfig::DiagnosticPolicy::Level::None;
  throw UaException{Status::BadConfigurationError,
    ErrorDetail::build("InvalidDiagnosticLevel",
      "DiagnosticPolicy level must be 'None', 'Summary', or 'Full'",
      "ServerConfiguration")
      .context(ua::ContextKeys::value, std::string{str})};
}

}  // namespace

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::DiagnosticPolicy& policy)
{
  using namespace boost::json;
  object obj;
  obj.emplace("DefaultLevel", diagnostic_level_to_string(policy.defaultLevel));
  obj.emplace("MaxLevel", diagnostic_level_to_string(policy.maxLevel));
  jv = std::move(obj);
}

static ServerConfig::DiagnosticPolicy tag_invoke(
  const boost::json::value_to_tag<ServerConfig::DiagnosticPolicy>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServerConfig::DiagnosticPolicy policy;
  if (obj.contains("DefaultLevel"))
    policy.defaultLevel = diagnostic_level_from_string(value_to<std::string>(obj.at("DefaultLevel")));
  if (obj.contains("MaxLevel"))
    policy.maxLevel = diagnostic_level_from_string(value_to<std::string>(obj.at("MaxLevel")));
  return policy;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::HistoryConfig& hist)
{
  using namespace boost::json;
  object obj;
  // Always written: an explicit 0 ("unlimited") must survive the file now that the default is finite.
  obj.emplace("MaxReturnDataValues", value_from(hist.maxReturnDataValues));
  obj.emplace("MaxReturnEventValues", value_from(hist.maxReturnEventValues));
  jv = std::move(obj);
}

static ServerConfig::HistoryConfig tag_invoke(
  const boost::json::value_to_tag<ServerConfig::HistoryConfig>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServerConfig::HistoryConfig hist;
  if (obj.contains("MaxReturnDataValues"))
    hist.maxReturnDataValues = value_to<uint32_t>(obj.at("MaxReturnDataValues"));
  if (obj.contains("MaxReturnEventValues"))
    hist.maxReturnEventValues = value_to<uint32_t>(obj.at("MaxReturnEventValues"));
  return hist;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ConnectionThrottling& t)
{
  using namespace boost::json;
  jv = {{"Enabled", value_from(t.enabled)},
    {"MaxConnectionsPerEndpoint", value_from(t.maxConnectionsPerEndpoint)},
    {"MaxConnectionAttemptsPerMinute", value_from(t.maxConnectionAttemptsPerMinute)},
    {"MaxTrackedEndpoints", value_from(t.maxTrackedEndpoints)},
    {"Ipv6PrefixLength", value_from(t.ipv6PrefixLength)}};
}

static ServerConfig::ConnectionThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ConnectionThrottling>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::ConnectionThrottling t;
  if (obj.contains("Enabled"))
    t.enabled = value_to<bool>(obj.at("Enabled"));
  if (obj.contains("MaxConnectionsPerEndpoint"))
    t.maxConnectionsPerEndpoint = value_to<uint32_t>(obj.at("MaxConnectionsPerEndpoint"));
  if (obj.contains("MaxConnectionAttemptsPerMinute"))
    t.maxConnectionAttemptsPerMinute = value_to<uint32_t>(obj.at("MaxConnectionAttemptsPerMinute"));
  if (obj.contains("MaxTrackedEndpoints"))
    t.maxTrackedEndpoints = value_to<uint32_t>(obj.at("MaxTrackedEndpoints"));
  if (obj.contains("Ipv6PrefixLength"))
    t.ipv6PrefixLength = value_to<uint32_t>(obj.at("Ipv6PrefixLength"));
  return t;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::IdentityThrottling& t)
{
  using namespace boost::json;
  jv = {{"Enabled", value_from(t.enabled)},
    {"MaxFailedAttemptsBeforeLockout", value_from(t.maxFailedAttemptsBeforeLockout)},
    {"LockoutDurationSeconds", value_from(t.lockoutDuration.count())},
    {"MaxTrackedIdentities", value_from(t.maxTrackedIdentities)}};
}

static ServerConfig::IdentityThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::IdentityThrottling>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::IdentityThrottling t;
  if (obj.contains("Enabled"))
    t.enabled = value_to<bool>(obj.at("Enabled"));
  if (obj.contains("MaxFailedAttemptsBeforeLockout"))
    t.maxFailedAttemptsBeforeLockout = value_to<uint32_t>(obj.at("MaxFailedAttemptsBeforeLockout"));
  if (obj.contains("LockoutDurationSeconds"))
    t.lockoutDuration = std::chrono::seconds{value_to<int64_t>(obj.at("LockoutDurationSeconds"))};
  if (obj.contains("MaxTrackedIdentities"))
    t.maxTrackedIdentities = value_to<uint32_t>(obj.at("MaxTrackedIdentities"));
  return t;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::DiscoveryThrottling& t)
{
  using namespace boost::json;
  jv = {{"ConcurrencyThreshold", value_from(t.concurrencyThreshold)},
    {"DelayPerRequestMs", value_from(t.delayPerRequest.count())}};
}

static ServerConfig::DiscoveryThrottling tag_invoke(
  const boost::json::value_to_tag<ServerConfig::DiscoveryThrottling>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::DiscoveryThrottling t;
  if (obj.contains("ConcurrencyThreshold"))
    t.concurrencyThreshold = value_to<uint32_t>(obj.at("ConcurrencyThreshold"));
  if (obj.contains("DelayPerRequestMs"))
    t.delayPerRequest = std::chrono::milliseconds{value_to<int64_t>(obj.at("DelayPerRequestMs"))};
  return t;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ResourceLimits& lim)
{
  using namespace boost::json;
  jv = {{"EventDispatchQueueDepth", value_from(lim.eventDispatchQueueDepth)},
    {"ConditionBranchesPerCondition", value_from(lim.conditionBranchesPerCondition)},
    {"OrphanedSubscriptionStore", value_from(lim.orphanedSubscriptionStore)},
    {"BufferedResponsesPerSession", value_from(lim.bufferedResponsesPerSession)},
    {"WriteQueueDepthPerConnection", value_from(lim.writeQueueDepthPerConnection)},
    {"WriteQueueBytesPerConnection", value_from(lim.writeQueueBytesPerConnection)},
    {"IncomingChunkQueueDepth", value_from(lim.incomingChunkQueueDepth)},
    {"OpenFileHandlesPerSession", value_from(lim.openFileHandlesPerSession)},
    {"OpenFileHandles", value_from(lim.openFileHandles)}};
}

static ServerConfig::ResourceLimits tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ResourceLimits>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::ResourceLimits lim;
  if (obj.contains("EventDispatchQueueDepth"))
    lim.eventDispatchQueueDepth = value_to<uint32_t>(obj.at("EventDispatchQueueDepth"));
  if (obj.contains("ConditionBranchesPerCondition"))
    lim.conditionBranchesPerCondition = value_to<uint32_t>(obj.at("ConditionBranchesPerCondition"));
  if (obj.contains("OrphanedSubscriptionStore"))
    lim.orphanedSubscriptionStore = value_to<uint32_t>(obj.at("OrphanedSubscriptionStore"));
  if (obj.contains("BufferedResponsesPerSession"))
    lim.bufferedResponsesPerSession = value_to<uint32_t>(obj.at("BufferedResponsesPerSession"));
  if (obj.contains("WriteQueueDepthPerConnection"))
    lim.writeQueueDepthPerConnection = value_to<uint32_t>(obj.at("WriteQueueDepthPerConnection"));
  if (obj.contains("WriteQueueBytesPerConnection"))
    lim.writeQueueBytesPerConnection = value_to<uint32_t>(obj.at("WriteQueueBytesPerConnection"));
  if (obj.contains("IncomingChunkQueueDepth"))
    lim.incomingChunkQueueDepth = value_to<uint32_t>(obj.at("IncomingChunkQueueDepth"));
  if (obj.contains("OpenFileHandlesPerSession"))
    lim.openFileHandlesPerSession = value_to<uint32_t>(obj.at("OpenFileHandlesPerSession"));
  if (obj.contains("OpenFileHandles"))
    lim.openFileHandles = value_to<uint32_t>(obj.at("OpenFileHandles"));
  return lim;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::ReverseConnectTarget& t)
{
  using namespace boost::json;
  object obj;
  obj.emplace("Name", value_from(t.name));
  obj.emplace("ClientApplicationUri", value_from(t.clientApplicationUri));
  obj.emplace("ClientEndpointUrl", value_from(t.clientEndpointUrl));
  obj.emplace("ServerEndpointUrl", value_from(t.serverEndpointUrl));
  obj.emplace("Endpoints", value_from(t.endpoints));
  obj.emplace("PeriodicConnectIntervalSeconds", value_from(t.periodicConnectInterval.count()));
  obj.emplace("MaxPendingSockets", value_from(t.maxPendingSockets));
  jv = std::move(obj);
}

static ServerConfig::ReverseConnectTarget tag_invoke(
  const boost::json::value_to_tag<ServerConfig::ReverseConnectTarget>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::ReverseConnectTarget t;
  if (obj.contains("Name"))
    t.name = value_to<std::string>(obj.at("Name"));
  if (obj.contains("ClientApplicationUri"))
    t.clientApplicationUri = value_to<std::string>(obj.at("ClientApplicationUri"));
  if (obj.contains("ClientEndpointUrl"))
    t.clientEndpointUrl = value_to<std::string>(obj.at("ClientEndpointUrl"));
  if (obj.contains("ServerEndpointUrl"))
    t.serverEndpointUrl = value_to<std::string>(obj.at("ServerEndpointUrl"));
  if (obj.contains("Endpoints"))
    t.endpoints = value_to<std::vector<ServerEndpointConfig>>(obj.at("Endpoints"));
  if (obj.contains("PeriodicConnectIntervalSeconds"))
    t.periodicConnectInterval =
      std::chrono::seconds{value_to<int64_t>(obj.at("PeriodicConnectIntervalSeconds"))};
  if (obj.contains("MaxPendingSockets"))
    t.maxPendingSockets = value_to<uint32_t>(obj.at("MaxPendingSockets"));
  return t;
}

static void tag_invoke(
  boost::json::value_from_tag, boost::json::value& jv, const ServerConfig::LocalDiscoveryServer& lds)
{
  using namespace boost::json;
  object obj;
  obj.emplace("Enabled", value_from(lds.enabled));
  obj.emplace("RegistrationExpirySeconds", value_from(lds.registrationExpiry.count()));
  if (lds.maxRegistrations)
    obj.emplace("MaxRegistrations", value_from(*lds.maxRegistrations));
  if (lds.semaphoreFileDirectory)
    obj.emplace("SemaphoreFileDirectory", value_from(*lds.semaphoreFileDirectory));
  jv = std::move(obj);
}

static ServerConfig::LocalDiscoveryServer tag_invoke(
  const boost::json::value_to_tag<ServerConfig::LocalDiscoveryServer>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();
  ServerConfig::LocalDiscoveryServer lds;
  if (obj.contains("Enabled"))
    lds.enabled = value_to<bool>(obj.at("Enabled"));
  if (obj.contains("RegistrationExpirySeconds"))
    lds.registrationExpiry = std::chrono::seconds{value_to<int64_t>(obj.at("RegistrationExpirySeconds"))};
  if (obj.contains("MaxRegistrations"))
    lds.maxRegistrations = value_to<uint32_t>(obj.at("MaxRegistrations"));
  if (obj.contains("SemaphoreFileDirectory"))
    lds.semaphoreFileDirectory = value_to<std::string>(obj.at("SemaphoreFileDirectory"));
  return lds;
}

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ServerConfig& cfg)
{
  using namespace boost::json;
  object obj;
  obj.emplace("ServerCapabilities", value_from(cfg.server_capabilities()));
  obj.emplace("Listeners", value_from(cfg.listeners()));
  if (cfg.maxConnections)
    obj.emplace("MaxConnections", value_from(*cfg.maxConnections));
  if (cfg.maxSecureChannels)
    obj.emplace("MaxSecureChannels", value_from(*cfg.maxSecureChannels));
  if (cfg.maxRequestsPerSession)
    obj.emplace("MaxRequestsPerSession", value_from(*cfg.maxRequestsPerSession));
  if (cfg.maxInFlightRequests)
    obj.emplace("MaxInFlightRequests", value_from(*cfg.maxInFlightRequests));
  if (cfg.maxInFlightRequestsPerConnection)
    obj.emplace("MaxInFlightRequestsPerConnection", value_from(*cfg.maxInFlightRequestsPerConnection));
  obj.emplace("ConnectionThrottling", value_from(cfg.connectionThrottling));
  obj.emplace("IdentityThrottling", value_from(cfg.identityThrottling));
  obj.emplace("MaxAccessIdentities", value_from(cfg.maxAccessIdentities));
  obj.emplace("AuthorizationTimeoutMs", value_from(cfg.authzTimeout.count()));
  obj.emplace("AuthenticationTimeoutMs", value_from(cfg.authnTimeout.count()));
  obj.emplace("DiscoveryThrottling", value_from(cfg.discoveryThrottling));
  obj.emplace("ResourceLimits", value_from(cfg.resourceLimits));
  obj.emplace("SubscriptionLimits", value_from(cfg.subscriptionLimits));
  obj.emplace(
    "MonitoredItemAccessRecheckIntervalSeconds", value_from(cfg.monitoredItemAccessRecheckInterval.count()));
  if (cfg.browseContinuationPointTimeout)
    obj.emplace("BrowseContinuationPointTimeout", value_from(cfg.browseContinuationPointTimeout->count()));
  if (cfg.historyContinuationPointTimeout)
    obj.emplace("HistoryContinuationPointTimeout", value_from(cfg.historyContinuationPointTimeout->count()));
  obj.emplace("PartialResultDeadlineFraction", value_from(cfg.partialResultDeadlineFraction));
  if (cfg.maxReferencesPerNode)
    obj.emplace("MaxReferencesPerNode", value_from(*cfg.maxReferencesPerNode));
  // Always written: null carries "disabled" through the file (nullopt is not the default).
  if (cfg.maxReferencesPerBrowseRequest)
    obj.emplace("MaxReferencesPerBrowseRequest", value_from(*cfg.maxReferencesPerBrowseRequest));
  else
    obj.emplace("MaxReferencesPerBrowseRequest", nullptr);
  if (cfg.maxBrowsePathWalkReferences)
    obj.emplace("MaxBrowsePathWalkReferences", value_from(*cfg.maxBrowsePathWalkReferences));
  obj.emplace("DefaultShutdownGracePeriodSeconds", value_from(cfg.defaultShutdownGracePeriodSeconds));
  obj.emplace("RoleManagementEnabled", value_from(cfg.roleManagementEnabled));
  obj.emplace("PushCertificateManagementEnabled", value_from(cfg.pushCertificateManagementEnabled));
  obj.emplace("EnableClaimToRoleMapping", value_from(cfg.enableClaimToRoleMapping));
  if (cfg.wellKnownRoles)
  {
    array roles;
    roles.reserve(cfg.wellKnownRoles->size());
    for (const auto role : *cfg.wellKnownRoles)
      roles.emplace_back(value_from(std::string{well_known_role_to_string(role)}));
    obj.emplace("WellKnownRoles", std::move(roles));
  }
  obj.emplace("ReverseConnectTargets", value_from(cfg.reverseConnectTargets));
  obj.emplace("LocalDiscoveryServer", value_from(cfg.localDiscoveryServer));
  obj.emplace("DiagnosticPolicy", value_from(cfg.diagnosticPolicy));
  // Always written (DEF-6): the defaults are finite, so an explicit 0 ("unlimited") must reach the file.
  obj.emplace("HistoryConfiguration", value_from(cfg.historyConfiguration));
  if (cfg.auditingEnabled)
    obj.emplace("AuditingEnabled", true);
  jv = std::move(obj);
}

static ServerConfig tag_invoke(const boost::json::value_to_tag<ServerConfig>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const object& obj = jv.as_object();

  ServerConfig cfg;
  if (obj.contains("MaxConnections"))
  {
    cfg.maxConnections = value_to<uint32_t>(obj.at("MaxConnections"));
  }
  if (obj.contains("MaxSecureChannels"))
  {
    cfg.maxSecureChannels = value_to<uint32_t>(obj.at("MaxSecureChannels"));
  }
  if (obj.contains("MaxRequestsPerSession"))
  {
    cfg.maxRequestsPerSession = value_to<uint32_t>(obj.at("MaxRequestsPerSession"));
  }
  if (obj.contains("MaxInFlightRequests"))
  {
    cfg.maxInFlightRequests = value_to<uint32_t>(obj.at("MaxInFlightRequests"));
  }
  if (obj.contains("MaxInFlightRequestsPerConnection"))
  {
    cfg.maxInFlightRequestsPerConnection = value_to<uint32_t>(obj.at("MaxInFlightRequestsPerConnection"));
  }
  if (obj.contains("ConnectionThrottling"))
  {
    cfg.connectionThrottling = value_to<ServerConfig::ConnectionThrottling>(obj.at("ConnectionThrottling"));
  }
  if (obj.contains("IdentityThrottling"))
  {
    cfg.identityThrottling = value_to<ServerConfig::IdentityThrottling>(obj.at("IdentityThrottling"));
  }
  if (obj.contains("MaxAccessIdentities"))
  {
    cfg.maxAccessIdentities = value_to<uint32_t>(obj.at("MaxAccessIdentities"));
  }
  if (obj.contains("AuthorizationTimeoutMs"))
  {
    cfg.authzTimeout = std::chrono::milliseconds{value_to<int64_t>(obj.at("AuthorizationTimeoutMs"))};
  }
  if (obj.contains("AuthenticationTimeoutMs"))
  {
    cfg.authnTimeout = std::chrono::milliseconds{value_to<int64_t>(obj.at("AuthenticationTimeoutMs"))};
  }
  if (obj.contains("DiscoveryThrottling"))
  {
    cfg.discoveryThrottling = value_to<ServerConfig::DiscoveryThrottling>(obj.at("DiscoveryThrottling"));
  }
  if (obj.contains("ResourceLimits"))
  {
    cfg.resourceLimits = value_to<ServerConfig::ResourceLimits>(obj.at("ResourceLimits"));
  }
  if (obj.contains("SubscriptionLimits"))
  {
    cfg.subscriptionLimits = value_to<ServerConfig::SubscriptionLimits>(obj.at("SubscriptionLimits"));
  }
  if (obj.contains("MonitoredItemAccessRecheckIntervalSeconds"))
  {
    cfg.monitoredItemAccessRecheckInterval =
      std::chrono::seconds{value_to<int64_t>(obj.at("MonitoredItemAccessRecheckIntervalSeconds"))};
  }
  if (obj.contains("BrowseContinuationPointTimeout"))
  {
    cfg.browseContinuationPointTimeout =
      std::chrono::milliseconds{value_to<int64_t>(obj.at("BrowseContinuationPointTimeout"))};
  }
  if (obj.contains("HistoryContinuationPointTimeout"))
  {
    cfg.historyContinuationPointTimeout =
      std::chrono::milliseconds{value_to<int64_t>(obj.at("HistoryContinuationPointTimeout"))};
  }
  if (obj.contains("PartialResultDeadlineFraction"))
  {
    cfg.partialResultDeadlineFraction = value_to<double>(obj.at("PartialResultDeadlineFraction"));
  }
  if (obj.contains("MaxReferencesPerNode"))
  {
    cfg.maxReferencesPerNode = value_to<uint32_t>(obj.at("MaxReferencesPerNode"));
  }
  if (obj.contains("MaxReferencesPerBrowseRequest"))
  {
    const auto& budget = obj.at("MaxReferencesPerBrowseRequest");
    cfg.maxReferencesPerBrowseRequest =
      budget.is_null() ? std::nullopt : std::optional<uint32_t>{value_to<uint32_t>(budget)};
  }
  if (obj.contains("MaxBrowsePathWalkReferences"))
  {
    cfg.maxBrowsePathWalkReferences = value_to<uint32_t>(obj.at("MaxBrowsePathWalkReferences"));
  }
  if (obj.contains("DefaultShutdownGracePeriodSeconds"))
  {
    cfg.defaultShutdownGracePeriodSeconds = value_to<uint32_t>(obj.at("DefaultShutdownGracePeriodSeconds"));
  }
  if (obj.contains("RoleManagementEnabled"))
  {
    cfg.roleManagementEnabled = value_to<bool>(obj.at("RoleManagementEnabled"));
  }
  if (obj.contains("PushCertificateManagementEnabled"))
  {
    cfg.pushCertificateManagementEnabled = value_to<bool>(obj.at("PushCertificateManagementEnabled"));
  }
  if (obj.contains("EnableClaimToRoleMapping"))
  {
    cfg.enableClaimToRoleMapping = value_to<bool>(obj.at("EnableClaimToRoleMapping"));
  }
  if (obj.contains("WellKnownRoles"))
  {
    std::vector<WellKnownRole> roles;
    const auto& arr = obj.at("WellKnownRoles").as_array();
    roles.reserve(arr.size());
    for (const auto& item : arr)
      roles.push_back(well_known_role_from_string(value_to<std::string>(item)));
    cfg.wellKnownRoles = std::move(roles);
  }
  if (obj.contains("ReverseConnectTargets"))
  {
    cfg.reverseConnectTargets =
      value_to<std::vector<ServerConfig::ReverseConnectTarget>>(obj.at("ReverseConnectTargets"));
  }
  if (obj.contains("LocalDiscoveryServer"))
  {
    cfg.localDiscoveryServer = value_to<ServerConfig::LocalDiscoveryServer>(obj.at("LocalDiscoveryServer"));
  }
  if (obj.contains("ServerCapabilities"))
  {
    cfg.server_capabilities() = value_to<ServerConfig::ServerCapabilities>(obj.at("ServerCapabilities"));
  }
  if (obj.contains("Listeners"))
  {
    cfg.listeners() = value_to<std::vector<ServerConfig::ListenerConfig>>(obj.at("Listeners"));
  }
  if (obj.contains("DiagnosticPolicy"))
  {
    cfg.diagnosticPolicy = value_to<ServerConfig::DiagnosticPolicy>(obj.at("DiagnosticPolicy"));
  }
  if (obj.contains("HistoryConfiguration"))
  {
    cfg.historyConfiguration = value_to<ServerConfig::HistoryConfig>(obj.at("HistoryConfiguration"));
  }
  if (obj.contains("AuditingEnabled"))
  {
    cfg.auditingEnabled = obj.at("AuditingEnabled").as_bool();
  }
  return cfg;
}

}  // namespace server

namespace client
{

static void tag_invoke(boost::json::value_from_tag, boost::json::value& jv, const ClientConfig& cfg)
{
  auto& obj = jv.emplace_object();
  obj.emplace("DefaultServiceTimeoutMs", cfg.defaultServiceTimeout.count());
  obj.emplace("DefaultSessionTimeoutMs", cfg.defaultSessionTimeout.count());
  obj.emplace("DefaultChannelLifetimeMs", cfg.defaultChannelLifetime.count());
  obj.emplace("WriteQueueDepthPerConnection", cfg.writeQueueDepthPerConnection);
  obj.emplace("WriteQueueBytesPerConnection", cfg.writeQueueBytesPerConnection);
}

static ClientConfig tag_invoke(const boost::json::value_to_tag<ClientConfig>&, const boost::json::value& jv)
{
  using namespace boost::json;
  const auto& obj = jv.as_object();

  ClientConfig cfg;
  if (obj.contains("DefaultServiceTimeoutMs"))
  {
    cfg.defaultServiceTimeout =
      std::chrono::milliseconds{obj.at("DefaultServiceTimeoutMs").to_number<int64_t>()};
  }
  if (obj.contains("DefaultSessionTimeoutMs"))
  {
    cfg.defaultSessionTimeout =
      std::chrono::milliseconds{obj.at("DefaultSessionTimeoutMs").to_number<int64_t>()};
  }
  if (obj.contains("DefaultChannelLifetimeMs"))
  {
    cfg.defaultChannelLifetime =
      std::chrono::milliseconds{obj.at("DefaultChannelLifetimeMs").to_number<int64_t>()};
  }
  if (obj.contains("WriteQueueDepthPerConnection"))
  {
    cfg.writeQueueDepthPerConnection = value_to<uint32_t>(obj.at("WriteQueueDepthPerConnection"));
  }
  if (obj.contains("WriteQueueBytesPerConnection"))
  {
    cfg.writeQueueBytesPerConnection = value_to<uint32_t>(obj.at("WriteQueueBytesPerConnection"));
  }
  if (obj.contains("MaxResponseMessageSize"))
  {
    // REMOVED, and rejected rather than ignored. The session-level maxResponseMessageSize is now
    // DERIVED from the transport limit the same configuration already sets
    // (ApplicationConfig::stack_limits().mConnectionProtocolLimits.mMaxMessageSize), so a
    // second settable knob for the same quantity could only ever contradict it. A file carrying the
    // old key was written against a field that never reached the wire; failing here is how its
    // author finds that out.
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("RemovedConfigurationKey",
        "ClientConfiguration.MaxResponseMessageSize has been removed",
        "ProcessConfigurationFile")
        .context(ua::ContextKeys::fieldName, std::string{"MaxResponseMessageSize"})};
  }
  return cfg;
}

}  // namespace client

}  // namespace ua
