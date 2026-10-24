// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief The smallest complete OPC UA round trip: a secure server and a client, in one process.
///
/// This is the sixty-second proof that the SDK works. It needs no arguments, no configuration
/// file, and no provisioning step, because it creates both halves itself: two certificates in a
/// temporary directory, each half trusting the other, and one Basic256Sha256 SignAndEncrypt
/// endpoint between them. Nothing here is insecure, and nothing here is left running.
///
/// Read examples/server/minimal and examples/client/minimal next: they are the same two halves as
/// separate programs, which is what a real deployment looks like.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_crypto.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_server_state.h"
#include "ua_to_string.h"
#include "ua_utc_time.h"
#include "ua_variable_id.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view serverApplicationUri = "urn:reduktive:opcua-sdk:example:quickstart:server";
constexpr std::string_view clientApplicationUri = "urn:reduktive:opcua-sdk:example:quickstart:client";
constexpr std::string_view bindAddress = "127.0.0.1:0";  // port 0: the operating system picks a free port
constexpr std::uint32_t rsaKeyBits = 2048;
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

/// One half's cryptographic identity: its provider, its file-backed store, and its own certificate.
struct Peer
{
  std::shared_ptr<const ua::Crypto> crypto;
  std::shared_ptr<ua::CertificateStore> store;
  std::shared_ptr<const ua::X509Certificate> certificate;
};

/// Creates a self-signed application instance certificate in its own store beneath @p storeRoot.
///
/// OPC UA identifies an application by the URI in its certificate, so @p applicationUri must match
/// the ApplicationUri the half advertises. A deployment replaces this with certificates issued by
/// its own authority; the shape of what the SDK is handed does not change.
Peer provision_peer(boost::asio::any_io_executor executor, const std::filesystem::path& storeRoot,
  std::string_view commonName, std::string_view applicationUri)
{
  // Not for production: the shared development provider uses a fixed private-key password. A
  // deployment takes the password from a secret provider.
  auto crypto = examples::development_crypto();
  auto store = ua::CertificateStoreFiles::create(std::move(executor), crypto, {.trustListPath = storeRoot});

  ua::Crypto::Name subject;
  subject.commonName = std::string{commonName};
  subject.organization = "Reduktive";

  // The subject alternative names are what a peer checks the endpoint address against, so the
  // certificate must cover every address this half is reached on.
  ua::Crypto::SubjectAlternateName alternateNames;
  alternateNames.uris.emplace_back(applicationUri);
  alternateNames.hostnames.emplace_back("localhost");
  alternateNames.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));

  ua::UtcTime expiry = ua::UtcTime::now();
  expiry.value() += std::chrono::hours{24};

  auto [keys, certificate] =
    crypto->create_self_signed_application_instance_certificate_sync(std::move(subject),
      expiry,
      std::move(alternateNames),
      ua::CertificateType::RsaSha256Application,
      rsaKeyBits);
  store->add_to_application_certificates_sync({.certificateType = ua::CertificateType::RsaSha256Application,
    .certificate = certificate,
    .keys = std::move(keys),
    .issuerCertificates = {}});
  return {std::move(crypto), std::move(store), std::move(certificate)};
}

/// Adds @p peerCertificate to @p store as a trust anchor.
///
/// This is the whole of mutual trust: each half holds the other's public certificate. A deployment
/// performs this deliberately, after checking the certificate's fingerprint over a separate channel.
void trust_peer(ua::CertificateStore& store, std::shared_ptr<const ua::X509Certificate> peerCertificate)
{
  store.try_add_to_trusted_certificates_sync(std::move(peerCertificate)).value();
}

/// Builds the identity and application configuration shared by both halves.
///
/// `allowInsecureEndpoints` stays false, which is the SDK's default: neither half will fall back
/// to an unsecured channel, so this example cannot silently stop being secure.
ua::ApplicationConfig application_configuration(std::string_view applicationUri)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri = std::string{applicationUri};
  application.allowInsecureEndpoints = false;
  return application;
}

/// Opens the listener, advertises one secure endpoint, starts the server, and returns the URL a
/// client should connect to.
///
/// The endpoint pairs a SecurityPolicy (how the channel is protected) with a MessageSecurityMode
/// (how much of each message is protected) and the user identities it will accept. Anonymous is
/// accepted only inside the signed and encrypted channel established by that policy.
std::string start_secure_server(ua::server::Server& server)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  bind.address = std::string{bindAddress};
  const ua::server::ListenerHandle listener = server.listen_sync(std::move(bind), {});

  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256-SignAndEncrypt";
  endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  server.add_endpoint(listener, std::move(endpoint));

  server.start_sync();
  return server.advertised_urls(listener).front().str();
}

/// Creates the server and hands it to the Runtime to own.
///
/// Anonymous authentication is accepted, and every anonymous Session is mapped to the standard
/// Observer role. A deployment replaces both with its own identities and role mapping.
ua::server::Server& create_server(ua::Runtime& runtime, const Peer& pki)
{
  ua::server::ServerComponents components;
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});
  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = application_configuration(serverApplicationUri),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Creates the client and hands it to the Runtime to own.
ua::client::Client& create_client(ua::Runtime& runtime, const Peer& pki)
{
  return runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = application_configuration(clientApplicationUri),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));
}

/// Discovers the server's endpoints, picks the strongest one both halves can speak, and opens a
/// Session on it. EasyConnect performs the whole handshake; @ref ua::client::Connection is the
/// managed result.
ua::client::Connection connect_to(ua::client::Client& client, const std::string& endpointUrl)
{
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = endpointUrl;
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

}  // namespace

int main()
{
  try
  {
    examples::banner("quickstart/roundtrip", "A secure OPC UA server and client in one process.");

    // One Runtime owns the worker threads for both halves and stops what it attached, newest
    // first, when it goes out of scope. The temporary directory holds the throwaway PKI.
    ua::Runtime runtime{{.threads = 4}};
    examples::TemporaryDirectory pkiRoot{"uasdk-quickstart"};

    Peer serverPki = provision_peer(
      runtime.executor(), pkiRoot.path() / "server", "Reduktive Quickstart Server", serverApplicationUri);
    Peer clientPki = provision_peer(
      runtime.executor(), pkiRoot.path() / "client", "Reduktive Quickstart Client", clientApplicationUri);
    examples::step(1, "Created a certificate for each half");

    trust_peer(*serverPki.store, clientPki.certificate);
    trust_peer(*clientPki.store, serverPki.certificate);
    examples::step(2, "Each half now trusts the other's certificate");

    ua::server::Server& server = create_server(runtime, serverPki);
    const std::string endpointUrl = start_secure_server(server);
    examples::step(3, "Server listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);

    ua::client::Client& client = create_client(runtime, clientPki);
    ua::client::Connection connection = connect_to(client, endpointUrl);
    examples::step(4, "Client opened a secure channel and an activated Session");

    // Every server publishes ServerStatus. Reading it needs no address-space code on the server
    // half, which is why it is the first thing worth reading.
    const auto state =
      connection.read_value_sync<std::int32_t>(ua::NodeId{ua::VariableId::Server_ServerStatus_State});
    examples::step(
      5, fmt::format("Read ServerStatus State = {}", ua::to_string(static_cast<ua::ServerState>(state))));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(6, "Closed the Session, then stopped both halves");

    examples::finished("quickstart/roundtrip");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("quickstart/roundtrip", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  quickstart/roundtrip: {}\n", failure.what());
  }
  return 1;
}
