// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Driving a server's certificate management from an administrative client.
///
/// It talks to `examples/server/push_certificates`, which must already be running. Start that first,
/// in another terminal, then run this.
///
/// These operations are ordinary Method calls on the server's `ServerConfiguration` Object, which is
/// why there is no special API for them: everything here is `call_method_sync`. What makes them
/// different is the gate. Every one requires the SecurityAdmin Role, so this example connects twice -
/// once as an operator, to show the refusal, and once as the administrator.
///
/// This example covers the inspection half: what has been rejected, and what is currently trusted.
/// The other half rotates the server's own certificate - CreateSigningRequest, take the request to
/// your certificate authority, then UpdateCertificate and ApplyChanges with what comes back - and no
/// example can supply a CA.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_call_method_result.h"
#include "ua_client.h"
#include "ua_byte_string.h"
#include "ua_file_transfer_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_result.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_user_identity.h"
#include "ua_variant.h"

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fmt/format.h>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4849";
constexpr std::string_view adminUser = "security-admin";
constexpr std::string_view operatorUser = "operator";
// Not for production: password constants compiled into the program. A deployment prompts for the
// credential or reads it from a secret store, and never puts it on a command line or in a log.
constexpr std::string_view adminPassword = "admin-secret";
constexpr std::string_view operatorPassword = "operator-secret";
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

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

/// Opens a Session as the named account.
ua::client::Connection connect_as(
  ua::client::Client& client, std::string_view endpointUrl, std::string_view user, std::string_view password)
{
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.identity =
    ua::client::UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{password}};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Attempts one Method on the server's `ServerConfiguration` Object and reports how it ended.
///
/// The non-throwing form is used here because the refusal is the *expected* outcome, and is what
/// this example is showing. A Call has two result layers and either can carry it: the service may
/// fail outright, or succeed and return a bad per-Method status. Both are reduced to the one status
/// a reader wants, and neither is replaced by a substitute - the ErrorDetail chain the SDK produced
/// is the one that explains the refusal.
ua::StatusCode attempted_call_status(
  ua::client::Connection& connection, ua::MethodId method, std::vector<ua::Variant> arguments)
{
  const ua::Result<ua::CallResult> outcome = connection.typed().try_call_method_sync(
    ua::NodeId{ua::ObjectId::ServerConfiguration}, ua::NodeId{method}, std::move(arguments));
  return outcome.is_good() ? outcome.value().status_code() : outcome.status_code();
}

/// Reads the server's TrustList.
///
/// A TrustList is a FileType node, so it is fetched with exactly the Open/Read/Close that
/// `examples/client/file_transfer` uses on any other file. What comes back is a UA Binary-encoded
/// `TrustListDataType`: the trusted certificates, the issuer certificates, and the revocation lists
/// for each. Reading it is how an administrator answers "what does this server actually trust?"
/// without logging in to the machine.
ua::ByteString read_trust_list(ua::client::Connection& connection)
{
  return connection.files().read_all_sync(
    ua::NodeId{ua::ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
}

/// The number of certificates the server has refused and kept for an operator to look at.
///
/// This is the list an administrator checks first: a client that cannot connect usually appears here,
/// and the answer is either to trust its certificate or to find out who is trying.
///
/// The throwing form, because this Session holds SecurityAdmin: a refusal here is a real failure,
/// and reporting it as a count of zero would hide it behind a plausible number.
std::size_t rejected_count(ua::client::Connection& connection)
{
  const ua::CallResult outcome =
    connection.typed().call_method_sync(ua::NodeId{ua::ObjectId::ServerConfiguration},
      ua::NodeId{ua::MethodId::ServerConfiguration_GetRejectedList},
      {});
  const ua::Array<ua::Variant>& outputs = outcome.value().output_arguments();
  return outputs.empty() ? 0 : outputs[0].to<ua::Array<ua::ByteString>>().value_or({}).size();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/push_certificates", "Manage a server's certificates over OPC UA.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
    ua::client::Client& client = create_client(runtime, pki);
    examples::step(1, fmt::format("Client ready, server at {}", endpointUrl));

    ua::client::Connection asOperator = connect_as(client, endpointUrl, operatorUser, operatorPassword);
    const ua::StatusCode refused =
      attempted_call_status(asOperator, ua::MethodId::ServerConfiguration_GetRejectedList, {});
    examples::step(2, fmt::format("'{}' called GetRejectedList: {}", operatorUser, ua::to_string(refused)));
    examples::detail("Authenticated, and still refused. Certificate management needs SecurityAdmin.");
    asOperator.close_sync();

    ua::client::Connection asAdmin = connect_as(client, endpointUrl, adminUser, adminPassword);
    examples::step(3,
      fmt::format("'{}' called GetRejectedList: {} certificate(s) rejected so far",
        adminUser,
        rejected_count(asAdmin)));

    examples::step(4,
      fmt::format(
        "Read the TrustList as a file: {} bytes of TrustListDataType", read_trust_list(asAdmin).size()));
    examples::detail("Rotating the server's own certificate is the other half: CreateSigningRequest,");
    examples::detail("then UpdateCertificate and ApplyChanges once your CA has signed it.");

    asAdmin.close_sync();
    runtime.shutdown().value();
    examples::step(5, "Closed both Sessions and stopped the client");

    examples::finished("client/push_certificates");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/push_certificates", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/push_certificates: {}\n", failure.what());
  }
  return 1;
}
