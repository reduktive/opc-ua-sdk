// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Which identities a server accepts, and what each of them is then allowed to do.
///
/// Authentication and authorization are two separate decisions, and this server makes both of them
/// visible. It accepts three kinds of user identity - anonymous, username/password, and an X.509
/// user certificate - and maps each to a Role. The Roles, not the identities, decide what a Session
/// may do to the nodes.
///
/// Run `examples/client/authentication` against it to see the same node read successfully by an
/// anonymous Session and refused a write, then written by an authenticated one.
///
/// The server runs until you press Ctrl+C, then shuts down in order.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_identity_facts.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_identity_criteria_type.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_secure_string.h"
#include "ua_server.h"
#include "ua_user_token_type.h"
#include "ua_variabletype_id.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:authentication";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4844";
constexpr std::string_view operatorUser = "operator";
// Not for production: a password constant compiled into the program. A deployment verifies against
// a directory service or a password store, and never holds a plaintext password at all.
constexpr std::string_view operatorPassword = "operator-secret";
constexpr double initialSetpoint = 25.0;

/// Builds the authenticator chain: one delegate per kind of user identity token.
///
/// A CompositeAuthenticator dispatches on the token kind the client presented, so each kind is
/// answered by the code that understands it. An endpoint that advertises a token kind with no
/// delegate behind it rejects every Session that presents one.
std::shared_ptr<ua::server::UserAuthenticator> accepted_identities()
{
  auto composite = std::make_shared<ua::server::CompositeAuthenticator>();
  composite->add(ua::UserTokenKind::Anonymous, std::make_shared<ua::server::AnonymousAuthenticator>());
  composite->add(ua::UserTokenKind::UserName,
    std::make_shared<ua::server::SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        // Not for production: a constant-string comparison. A deployment checks a salted hash, and
        // takes the same time to answer whether or not the account exists.
        return username == operatorUser && std::string_view{password.c_str()} == operatorPassword;
      }));
  // The session checks a user certificate against the server's user-token store before this runs.
  composite->add(ua::UserTokenKind::X509, std::make_shared<ua::server::X509UserAuthenticator>());
  return composite;
}

/// Maps an authenticated identity to the Roles it holds.
///
/// This is the authorization half. `Anonymous` matches a Session that presented no credentials at
/// all; `AuthenticatedUser` matches every Session that presented any accepted credential, whichever
/// kind. A deployment usually names its accounts individually with `UserName` or `Thumbprint`
/// criteria instead of granting a Role to everyone who logged in.
std::shared_ptr<ua::server::RoleConfiguration> identity_role_map()
{
  return ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous},
      {ua::server::WellKnownRole::Operator, ua::IdentityCriteriaType::AuthenticatedUser}});
}

/// Creates the server and hands it to the Runtime to own.
ua::server::Server& create_server(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Server)};

  ua::server::ServerComponents components;
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.userTokenCertificateStore = pki.store;
  components.authenticator = accepted_identities();
  components.roleConfiguration = identity_role_map();

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Registers this server's namespace, granting each Role a different set of permissions.
///
/// This is where authentication finally buys something. Observer may look; Operator may also
/// change. Because the anonymous Session holds only Observer, its Write is refused by the server
/// with `BadUserAccessDenied` - the node is writable, the caller is not.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> byRole{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read}),
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Operator,
      ua::PermissionType{
        ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read, ua::PermissionType::Bit::Write})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, byRole, secureSessionOnly));
}

/// Adds a `Demo` folder holding one `Setpoint` that is readable and writable at the node level.
///
/// The AccessLevel says what the node supports; the Role permissions above say who may use it. Both
/// have to allow an operation before it happens.
void add_demo_folder(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId demoId{namespaceIndex, "Demo"};
  ua::NodeAccessor demo = addressSpace.create_node_sync(demoId, ua::NodeClass::Object);
  demo.set_browse_name(ua::QualifiedName{namespaceIndex, "Demo"});
  demo.set_display_name(ua::LocalizedText{"", "Demo"});
  demo.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, demoId);

  const ua::NodeId setpointId{namespaceIndex, "Demo.Setpoint"};
  ua::VariableAccessor setpoint =
    addressSpace.create_node_sync(setpointId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  setpoint.set_browse_name(ua::QualifiedName{namespaceIndex, "Setpoint"});
  setpoint.set_display_name(ua::LocalizedText{"", "Setpoint"});
  setpoint.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  setpoint.set_access_level(
    ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite});
  setpoint.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  demo.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, setpointId);
  setpoint.write_value_sync(initialSetpoint);
}

/// Opens the listener and advertises one secure endpoint offering all three token kinds.
///
/// A UserTokenPolicy names a kind of credential the endpoint accepts *and* the SecurityPolicy applied
/// to the credential itself, which is a separate decision from the channel's. An anonymous token
/// carries no secret, so `None` is honest there. The other two do: a username policy's algorithm
/// encrypts the password, and a certificate policy's algorithm signs the proof of private-key
/// possession. Naming `None` for either is refused rather than quietly weakened.
std::string start_secure_server(ua::server::Server& server, std::string_view listenAddress)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  bind.address = std::string{listenAddress};
  const ua::server::ListenerHandle listener = server.listen_sync(std::move(bind), {});

  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256-SignAndEncrypt";
  endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::UserName, ua::SecurityPolicyId::Basic256Sha256));
  endpoint.userIdentityTokens.push_back(ua::server::create_user_token_policy(
    ua::UserTokenType::Certificate, ua::SecurityPolicyId::Basic256Sha256));
  server.add_endpoint(listener, std::move(endpoint));

  server.start_sync();
  return server.advertised_urls(listener).front().str();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner(
      "server/authentication", "Accept three kinds of user identity, and give each one different rights.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    examples::step(1, "Opened the development PKI");

    ua::server::Server& server = create_server(runtime, pki);
    examples::step(2, "Accepting anonymous, username/password, and X.509 user identities");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    add_demo_folder(addressSpace, namespaceIndex);
    examples::step(3, "Observer may read Demo/Setpoint; Operator may also write it");

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_authentication in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/authentication");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/authentication", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/authentication: {}\n", failure.what());
  }
  return 1;
}
