// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief A client that listens for its server to call, and then behaves like any other client.
///
/// It waits for `examples/server/reverse_connect` to dial in. Start either one first: the server
/// retries until this listener exists.
///
/// Reverse Connect changes exactly one thing - who opens the TCP connection. Everything after the
/// ReverseHello is the ordinary client-driven sequence, so this example works at the SDK's tier-0
/// surface, where the SecureChannel and the Session are separate objects. The managed `Connection`
/// facade does not drive reverse connections; that is what `CoreClient` is the explicit override for.
///
/// A client that is dialled cannot run GetEndpoints against the server first, so it has no way to
/// learn the server's certificate at connect time. It must already have it. Here it comes out of the
/// client's own trust list, which is exactly where a provisioned one would be.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_core_client.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reverse_connect_config.h"
#include "ua_runtime.h"
#include "ua_server_state.h"
#include "ua_session_attribute_services.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_variable_id.h"
#include "ua_x509_certificate.h"

#include <fmt/format.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your client.
constexpr std::string_view defaultBindAddress = "127.0.0.1:4870";
// The URL the server advertises for itself in its ReverseHello. Both sides must agree on it. It
// names the server rather than a socket anyone dials, but it is still checked against the server
// certificate's subject alternative names like any other endpoint URL.
constexpr std::string_view serverAdvertisedUrl = "opc.tcp://localhost:4840";
constexpr auto dialTimeout = 30s;
constexpr std::uint32_t maxQueuedConnections = 5;
constexpr auto reverseHelloTimeout = 20s;

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

/// Finds the server's certificate in the trust list, by the ApplicationUri it carries.
///
/// This is what "pre-provisioned" means in practice: an operator put the certificate here after
/// checking its fingerprint, and the client looks it up rather than being handed it by the peer it
/// is about to authenticate.
std::shared_ptr<const ua::X509Certificate> provisioned_server_certificate(
  const examples::DevelopmentPki& pki, std::string_view applicationUri)
{
  const auto trusted = pki.store->get_trusted_certificates_sync();
  const auto match = std::ranges::find_if(trusted,
    [applicationUri](const std::shared_ptr<const ua::X509Certificate>& candidate)
    {
      const auto uris = candidate->san_uris();
      return std::ranges::find(uris, applicationUri) != uris.end();
    });
  if (match == trusted.end())
  {
    // The first thing that goes wrong when this example is pointed at a real server. Saying so
    // here costs one check; leaving it to the handshake produces a channel error that names
    // neither the certificate nor the reason it was missing.
    throw ua::UaException{ua::StatusCode{ua::Status::BadCertificateInvalid,
      ua::ErrorDetail::build("ExampleServerCertificateNotProvisioned",
        "No trusted certificate carries the server's ApplicationUri; provision the server "
        "certificate before listening for it",
        "client.reverse_connect")
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})}};
  }
  return *match;
}

/// Opens the listener the server dials into.
///
/// `expectedServers` is the allow-list, and an empty one accepts nobody. A listening client is
/// reachable from anywhere that can route to it, so naming the servers it will talk to is the
/// difference between a reverse-connect endpoint and an open port.
ua::client::ReverseConnectHandle listen(ua::client::Client& client, std::string_view bindAddress)
{
  ua::client::ReverseConnectListenerConfig config;
  config.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  config.bind.address = std::string{bindAddress};
  config.expectedServers.push_back(ua::client::ExpectedServer{
    .serverUri = std::string{examples::development_application_uri(examples::PkiRole::Server)},
    .endpointUrls = {std::string{serverAdvertisedUrl}}});
  config.maxQueuedConnections = maxQueuedConnections;
  config.initialMessageTimeout = std::chrono::duration_cast<std::chrono::seconds>(reverseHelloTimeout);
  return client.core().start_reverse_connect_sync(std::move(config));
}

/// Waits for the server to dial in, then opens the SecureChannel over the connection it made.
///
/// `ConnectMode::Reverse` is the whole difference: instead of connecting a socket, the channel takes
/// one that the listener has already accepted and validated. The security terms are stated here in
/// full, exactly as they would be for an outbound channel.
ua::client::SecureChannel accept_channel(
  ua::client::Client& client, const std::shared_ptr<const ua::X509Certificate>& serverCertificate)
{
  ua::client::CoreClient::OpenChannelConfig config;
  config.endpointUrl = std::string{serverAdvertisedUrl};
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = serverCertificate;
  config.connectMode = ua::client::ConnectMode::Reverse;
  config.timeout = dialTimeout;
  return client.core().open_channel_sync(std::move(config));
}

/// Names the Session this client asks the server to create.
///
/// The name is what an operator sees in the server's Session diagnostics, so it is worth setting to
/// something that identifies your application rather than leaving the SDK's default.
ua::client::SecureChannel::CreateSessionConfig session_request()
{
  ua::client::SecureChannel::CreateSessionConfig request;
  request.sessionName = "reverse connect example";
  return request;
}

/// Reads one Variable through a tier-0 Session.
///
/// The managed `Connection` facade would make this a one-liner; at tier 0 the service request is
/// built by hand, which is the price of reaching a surface the facade does not cover.
std::int32_t read_server_state(ua::client::Session& session)
{
  ua::ReadValueId what;
  what.node_id() = ua::NodeId{ua::VariableId::Server_ServerStatus_State};
  what.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);

  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(what));
  request.timestamps_to_return() = ua::TimestampsToReturn::Neither;

  const ua::ReadResponse response = session.attributes().read_sync(std::move(request));
  return response.results()[0].value().to<std::int32_t>().value();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/reverse_connect", "Listen for the server to call, then drive as usual.");

    const std::string_view bindAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 2}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
    ua::client::Client& client = create_client(runtime, pki);
    examples::step(1, "Client ready");

    const ua::client::ReverseConnectHandle listener = listen(client, bindAddress);
    examples::step(2, fmt::format("Listening on opc.tcp://{} for one named server", bindAddress));

    ua::client::SecureChannel channel = accept_channel(client,
      provisioned_server_certificate(pki, examples::development_application_uri(examples::PkiRole::Server)));
    examples::step(3, "The server dialled in; opened a Basic256Sha256 SignAndEncrypt channel");

    ua::client::Session session = channel.create_session_sync(session_request());
    session.activate_sync();
    examples::step(4, "Created and activated a Session over that channel");

    examples::step(5,
      fmt::format("Read the server's state: {}",
        ua::to_string(static_cast<ua::ServerState>(read_server_state(session)))));

    session.close_sync();
    channel.close_sync();
    client.core().stop_reverse_connect_sync(listener);
    runtime.shutdown().value();
    examples::step(6, "Closed the Session, the channel, and the listener");

    examples::finished("client/reverse_connect");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/reverse_connect", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/reverse_connect: {}\n", failure.what());
  }
  return 1;
}
