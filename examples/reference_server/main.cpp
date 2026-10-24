// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief The reference server: a production-shaped OPC UA server application.
///
/// It is the companion to `examples/reference_client`. Where `examples/server/minimal` shows the
/// shortest path to a working server, this one shows what an application that has to be operated
/// looks like: a persistent PKI whose credential comes from the environment, explicit certificate
/// provisioning, a refusal to start before an operator has established trust, an information model
/// imported from an external NodeSet, namespace-level role permissions, and orderly shutdown.
///
/// The model lives in demo_model.cpp, the network identity in endpoints.cpp, and the command line
/// in options.cpp, so that this file is about the application's lifecycle and nothing else.

#include "demo_model.h"
#include "endpoints.h"
#include "example_support.h"
#include "options.h"
#include "reference_pki.h"

#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_log_sink_implementations.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
namespace reference = reduktive::reference;

// Change these for your application. The application URI is declared in endpoints.h, because the
// certificate and the ApplicationDescription must carry the same one.
constexpr std::string_view keyCredentialEnvironment = "REDUKTIVE_REFERENCE_KEY_PASSWORD";

/// Returns the server components that carry the authentication and authorization policy.
///
/// Anonymous authentication is accepted, and every accepted identity is mapped to the standard
/// Observer role. The namespace-level role permissions in demo_model.cpp then decide what that
/// role may do. A deployment replaces this with its own identities and role mapping. `run()` adds
/// the crypto provider, the certificate store and the log sink.
ua::server::ServerComponents server_components()
{
  ua::server::ServerComponents components;
  components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});
  return components;
}

/// The immutable configuration this server is created with.
///
/// Insecure endpoints are prohibited. Full operation diagnostics are enabled so that a per-Method
/// ErrorDetail can travel back to a client that asks for it; a deployment tunes that against its
/// own disclosure policy.
ua::server::CreateConfig server_config()
{
  auto identity = ua::ApplicationIdentity::load_default();
  identity.productUri = "https://www.reduktive.com/opcua/sdk";
  identity.applicationName = ua::LocalizedText{"en", "Reduktive SDK Reference Server"};
  identity.applicationType = ua::ApplicationType::Server;

  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri = std::string{reference::applicationUri};
  application.allowInsecureEndpoints = false;

  ua::server::ServerConfig server;
  server.diagnosticPolicy.defaultLevel = ua::server::ServerConfig::DiagnosticPolicy::Level::Full;

  return {
    .identity = std::move(identity), .application = std::move(application), .server = std::move(server)};
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
      "Trusted client certificate SHA-256: {}", reference::certificate_sha256(*pki.crypto, *trusted)));
  }
  if (options.exportCertificate)
  {
    reference::export_public_certificate(*pki.applicationCertificate.certificate, *options.exportCertificate);
    examples::detail(fmt::format("Exported server certificate to {}", options.exportCertificate->string()));
  }
  examples::detail(fmt::format("Server certificate SHA-256: {}",
    reference::certificate_sha256(*pki.crypto, *pki.applicationCertificate.certificate)));
}

/// Refuses to expose an endpoint until an operator has approved at least one client.
///
/// Without this, an accidentally provisioned server would start in a state where it can accept no
/// one, and report only a handshake failure to whoever tried.
void require_a_trust_anchor(ua::CertificateStore& store)
{
  if (store.try_get_trusted_certificates_sync().value().empty())
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceServerTrustListEmpty",
        "Provision at least one approved client certificate before starting the server",
        "reference_server.startup")}};
  }
}

/// Runs the application: prepare PKI, provision, bind the model, serve, and shut down on a signal.
int run(const reference::Options& options)
{
  // The console sink carries SDK diagnostics and this application's own model-handler rejections.
  // It is set to Error so a successful run shows only what the application prints; raise it to
  // Warning or Info when diagnosing a problem.
  auto logSink = std::make_shared<ua::ConsoleLogSink>();
  auto logLevel = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Error);
  ua::Logger logger{logSink, logLevel, "reference_server"};
  ua::Runtime runtime{{.threads = 2,
    .shutdown = {.reason = ua::LocalizedText{"en", "Reference server stopping"}, .drainBudget = 30s},
    .logger = logger}};

  // The private-key credential comes from the environment and is never a command-line value.
  auto pki = reference::prepare_application_pki(runtime.executor(),
    options.pkiRoot,
    std::string{keyCredentialEnvironment},
    reference::server_certificate_profile(options.listenAddress),
    logger);
  examples::step(1, "Opened the persistent PKI");
  provision(options, pki);

  if (options.provisionOnly)
  {
    // Provision-only never opens a listener or imports the information model.
    pki.store->shutdown();
    examples::finished("reference_server (provisioning only)");
    return 0;
  }

  if (!options.modelPath)
  {
    throw std::invalid_argument{"--model is required unless --provision-only is used"};
  }
  require_a_trust_anchor(*pki.store);

  ua::server::ServerComponents components = server_components();
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.logSink = logSink;
  components.logLevel = ua::LogLevel::Error;
  auto& server =
    runtime.attach(ua::server::Server::create(runtime.executor(), server_config(), std::move(components)));
  examples::step(2, "Created the server");

  // Import and bind the model before opening the listener, so no client can ever observe a
  // half-built address space.
  reference::try_configure_demo_model(server, *options.modelPath, logger).value();
  examples::step(3, fmt::format("Imported the model from {}", options.modelPath->filename().string()));

  const ua::server::ListenerHandle listener = reference::add_secure_endpoint(server, options.listenAddress);
  server.try_start_sync().value();

  const auto advertised = server.advertised_urls(listener);
  if (advertised.empty())
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadInvalidState,
      ua::ErrorDetail::build("ReferenceServerNoAdvertisedUrl",
        "The listener started without an advertised UA-TCP URL",
        "reference_server.startup")}};
  }
  examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
  examples::detail(advertised.front().str());
  examples::detail(fmt::format("Demo namespace: {}", reference::demoNamespaceUri));
  examples::detail("Nodes: UptimeSeconds, Setpoint, and Divide(numerator, divisor)");
  examples::wait_for_shutdown_signal(runtime.executor(), "Press Ctrl+C to stop.");
  runtime.shutdown().value();
  examples::step(5, "Stopped on Ctrl+C");
  examples::finished("reference_server");
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
    examples::banner("reference_server", "A production-shaped OPC UA server application.");
    return run(options);
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("reference_server", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  reference_server: {}\n", failure.what());
  }
  return 1;
}
