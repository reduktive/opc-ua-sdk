// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief The reference client: a production-shaped OPC UA client application.
///
/// It is the companion to `examples/reference_server`. Where `examples/client/minimal` shows the
/// shortest path to a working client, this one shows what an application that has to be operated
/// looks like: a persistent PKI whose credential comes from the environment, explicit certificate
/// provisioning, a refusal to connect before an operator has established trust, request
/// diagnostics, and a Session closed before the runtime stops.
///
/// The protocol work itself lives in demo.cpp, and the command line in options.cpp, so that this
/// file is about the application's lifecycle and nothing else.

#include "demo.h"
#include "example_support.h"
#include "options.h"
#include "reference_pki.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_log_sink_implementations.h"
#include "ua_runtime.h"

#include <fmt/format.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
namespace reference = reduktive::reference;

// Change these for your application.
constexpr std::string_view applicationUri = "urn:reduktive:reference-client";
constexpr std::string_view keyCredentialEnvironment = "REDUKTIVE_REFERENCE_KEY_PASSWORD";
constexpr std::uint32_t operationDiagnostics = 0x000003FFU;
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

/// The X.509 identity requested when this client provisions its own certificate.
///
/// A client needs a stable application URI but no DNS or IP subject alternative names, because it
/// does not authenticate a listening address.
reference::CertificateProfile certificate_profile()
{
  return {.commonName = "Reduktive Reference Client",
    .applicationUri = std::string{applicationUri},
    .dnsNames = {},
    .ipAddresses = {}};
}

/// The immutable configuration this client is created with.
///
/// Insecure endpoints are prohibited here, before endpoint discovery runs, so no later choice can
/// select one.
ua::client::CreateConfig client_config()
{
  auto identity = ua::ApplicationIdentity::load_default();
  identity.productUri = "https://www.reduktive.com/opcua/sdk";
  identity.applicationName = ua::LocalizedText{"en", "Reduktive SDK Reference Client"};
  identity.applicationType = ua::ApplicationType::Client;

  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri = std::string{applicationUri};
  application.allowInsecureEndpoints = false;

  return {.identity = std::move(identity),
    .application = std::move(application),
    .client = ua::client::ClientConfig{}};
}

/// Performs the operator's provisioning requests: trust a named peer certificate, export this
/// application's own public certificate, or both.
///
/// Naming a file is a deliberate act. The fingerprint is printed so an operator can confirm it
/// over an independent channel before relying on it.
void provision(const reference::Options& options, const reference::ApplicationPki& pki)
{
  if (options.trustCertificate)
  {
    const auto trusted =
      reference::trust_public_certificate(*pki.crypto, *pki.store, *options.trustCertificate);
    examples::detail(fmt::format(
      "Trusted server certificate SHA-256: {}", reference::certificate_sha256(*pki.crypto, *trusted)));
  }
  if (options.exportCertificate)
  {
    reference::export_public_certificate(*pki.applicationCertificate.certificate, *options.exportCertificate);
    examples::detail(fmt::format("Exported client certificate to {}", options.exportCertificate->string()));
  }
  examples::detail(fmt::format("Client certificate SHA-256: {}",
    reference::certificate_sha256(*pki.crypto, *pki.applicationCertificate.certificate)));
}

/// Refuses to connect until an operator has established at least one server trust anchor.
///
/// Without this an accidentally provisioned client would start in a state where it trusts nothing
/// and reports only a handshake failure, which is a much harder thing to diagnose.
void require_a_trust_anchor(ua::CertificateStore& store)
{
  if (store.try_get_trusted_certificates_sync().value().empty())
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceClientTrustListEmpty",
        "Provision the approved server certificate before connecting",
        "reference_client.startup")}};
  }
}

/// Opens the managed Connection.
///
/// EasyConnect discovers the server's endpoints and selects one; `customize` then applies this
/// application's settings to exactly the configuration it selected.
ua::client::Connection connect(ua::client::Client& client, const std::string& endpointUrl)
{
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = endpointUrl;
  policy.timeout = connectTimeout;
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.sessionName = "Reduktive Reference Client";
    config.connectTimeout = connectTimeout;
    // This application makes one deterministic pass and exits, so it does not reconnect. A
    // long-running client sets a ReconnectPolicy and observes connection state instead: see
    // examples/client/reconnect_and_keepalive.
    config.reconnect = std::nullopt;
    // Operation-level diagnostics let a per-Method ErrorDetail travel beside the CallMethodResult.
    // The server decides independently how much it is willing to disclose.
    config.diagnostics.requestedDiagnosticsMask = operationDiagnostics;
  };
  return client.easy_connect_sync(std::move(policy));
}

/// Runs the application: prepare PKI, provision, connect, exercise the demo model, close.
int run(const reference::Options& options)
{
  // The console sink carries SDK diagnostics. It is set to Error so that a successful run shows
  // only what this application prints; raise it to Warning or Info when diagnosing a problem.
  auto logSink = std::make_shared<ua::ConsoleLogSink>();
  auto logLevel = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Error);
  ua::Logger logger{logSink, logLevel, "reference_client"};
  ua::Runtime runtime{{.threads = 2,
    .shutdown = {.reason = ua::LocalizedText{"en", "Reference client stopping"}, .drainBudget = 30s},
    .logger = logger}};

  // The private-key credential comes from the environment and is never a command-line value.
  auto pki = reference::prepare_application_pki(runtime.executor(),
    options.pkiRoot,
    std::string{keyCredentialEnvironment},
    certificate_profile(),
    logger);
  examples::step(1, "Opened the persistent PKI");
  provision(options, pki);

  if (options.provisionOnly)
  {
    // Provision-only never creates a client or touches the network.
    pki.store->shutdown();
    examples::finished("reference_client (provisioning only)");
    return 0;
  }

  require_a_trust_anchor(*pki.store);
  auto& client = runtime.attach(ua::client::Client::create(runtime.executor(),
    client_config(),
    {.crypto = pki.crypto,
      .applicationGroupCertificateStore = pki.store,
      .logSink = logSink,
      .logLevel = ua::LogLevel::Error}));
  ua::client::Connection connection = connect(client, options.endpointUrl);
  examples::step(2, fmt::format("Connected securely to {}", options.endpointUrl));

  const reference::DemoNodes nodes = reference::resolve_demo_nodes(connection);
  examples::step(3, "Resolved the demo model by namespace URI and BrowseName");

  examples::step(4, "Browsed the Demo object");
  reference::list_demo_children(connection, nodes);

  examples::step(5, "Read a Variable");
  reference::read_uptime(connection, nodes);

  examples::step(6, "Wrote a Variable and read it back");
  reference::update_setpoint(connection, nodes);

  examples::step(7, "Subscribed to a Variable");
  reference::watch_setpoint(connection, nodes);

  examples::step(8, "Called a Method");
  reference::call_divide(connection, nodes);

  examples::step(9, "Called a Method the server rejects");
  reference::call_divide_by_zero(connection, nodes);

  connection.close_sync();
  runtime.shutdown().value();
  examples::step(10, "Closed the Session and stopped the client");
  examples::finished("reference_client");
  return 0;
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    const reference::Options options = reference::parse_options(argc, argv);
    if (options.showHelp)
    {
      reference::print_usage();
      return 0;
    }
    examples::banner("reference_client", "A production-shaped OPC UA client application.");
    return run(options);
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("reference_client", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  reference_client: {}\n", failure.what());
  }
  return 1;
}
