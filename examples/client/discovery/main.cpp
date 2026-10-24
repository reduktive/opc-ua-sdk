// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Finding out what a machine offers before committing to a connection.
///
/// It talks to `examples/server/authentication`, which must already be running, because that server
/// advertises three kinds of user credential and so has something interesting to report.
///
/// Discovery answers two different questions. FindServers asks "which applications live behind this
/// address?" and GetEndpoints asks "on what terms will this one talk to me?". Both are answered
/// without a Session, which is what makes them usable before any trust decision has been taken.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_application_description.h"
#include "ua_client.h"
#include "ua_discovery.h"
#include "ua_endpoint_description.h"
#include "ua_exceptions.h"
#include "ua_message_security_mode.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
#include "ua_user_token_policy.h"
#include "ua_utilities.h"

#include <fmt/format.h>

#include <algorithm>
#include <cstddef>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultDiscoveryUrl = "opc.tcp://127.0.0.1:4844";
constexpr auto discoveryTimeout = 10s;

/// Creates the client and hands it to the Runtime to own.
ua::client::Client& create_client(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Client)};

  return runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));
}

/// Asks an address which applications it hosts.
///
/// A plain server answers with itself. A Local Discovery Server answers with every server that has
/// registered with it, which is how one well-known address stands in for a whole machine.
std::vector<ua::ApplicationDescription> find_servers(
  ua::client::Discovery& discovery, std::string_view discoveryUrl)
{
  ua::client::FindServersOptions options;
  options.timeout = discoveryTimeout;
  return discovery.find_servers_sync(std::string{discoveryUrl}, std::move(options));
}

/// Asks one application on what terms it will accept a connection.
///
/// Each EndpointDescription is a complete offer: a URL, a SecurityPolicy, a MessageSecurityMode, the
/// server's certificate, and the user credentials it will accept. A client picks one and connects on
/// exactly those terms.
std::vector<ua::EndpointDescription> get_endpoints(
  ua::client::Discovery& discovery, std::string_view discoveryUrl)
{
  ua::client::GetEndpointsOptions options;
  options.timeout = discoveryTimeout;
  return discovery.get_endpoints_sync(std::string{discoveryUrl}, std::move(options));
}

/// Renders one endpoint's security terms the way a person would compare them.
std::string describe(const ua::EndpointDescription& endpoint)
{
  std::string tokens;
  for (const ua::UserTokenPolicy& token : endpoint.user_identity_tokens())
  {
    tokens += tokens.empty() ? "" : ", ";
    tokens += ua::to_string(token.token_type());
  }
  // The SecurityPolicy travels as a URI whose last segment is the name people use for it.
  const std::string_view policyUri{endpoint.security_policy_uri()};
  const std::size_t lastSegment = policyUri.rfind('#');
  return fmt::format("[securityLevel {}] {} {}, accepts {}",
    endpoint.security_level(),
    lastSegment == std::string_view::npos ? policyUri : policyUri.substr(lastSegment + 1),
    ua::to_string(endpoint.security_mode()),
    tokens);
}

/// The endpoint an unattended client should choose: the highest security level offered.
///
/// `securityLevel` is the server's own ranking of its endpoints, from least to most secure. Trusting
/// it is reasonable once the server's certificate is trusted, and it is what the SDK's own
/// `easy_connect` ranker falls back on to break ties.
const ua::EndpointDescription& strongest(const std::vector<ua::EndpointDescription>& endpoints)
{
  return *std::ranges::max_element(endpoints,
    [](const ua::EndpointDescription& left, const ua::EndpointDescription& right)
    { return left.security_level() < right.security_level(); });
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/discovery", "Ask an address what it is and how it will talk to you.");

    const std::string_view discoveryUrl =
      examples::option_value(argc, argv, "--endpoint", defaultDiscoveryUrl);

    ua::Runtime runtime{{.threads = 2}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
    ua::client::Client& client = create_client(runtime, pki);
    ua::client::Discovery discovery = client.discovery();
    examples::step(1, fmt::format("Client ready, asking {}", discoveryUrl));

    const std::vector<ua::ApplicationDescription> servers = find_servers(discovery, discoveryUrl);
    examples::step(2, fmt::format("FindServers returned {} application(s)", servers.size()));
    for (const ua::ApplicationDescription& server : servers)
    {
      examples::detail(fmt::format("{} [{}]",
        std::string_view{server.application_name().text()},
        std::string_view{server.application_uri()}));
    }

    const std::vector<ua::EndpointDescription> endpoints = get_endpoints(discovery, discoveryUrl);
    examples::step(3, fmt::format("GetEndpoints returned {} endpoint(s)", endpoints.size()));
    for (const ua::EndpointDescription& endpoint : endpoints)
    {
      examples::detail(describe(endpoint));
    }

    examples::step(
      4, fmt::format("Chose the highest securityLevel offered: {}", describe(strongest(endpoints))));
    examples::detail("Connect on exactly those terms, or let easy_connect make the same choice.");

    runtime.shutdown().value();
    examples::step(5, "Stopped the client; no Session was ever opened");

    examples::finished("client/discovery");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/discovery", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/discovery: {}\n", failure.what());
  }
  return 1;
}
