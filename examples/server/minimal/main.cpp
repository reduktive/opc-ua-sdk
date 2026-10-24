// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief The smallest standalone OPC UA server: one secure endpoint and one writable value.
///
/// It publishes a namespace of its own containing a `Demo` folder with a `Setpoint` variable, and
/// serves it over a signed and encrypted channel. Run `examples/client/minimal` against it to read
/// and write that value.
///
/// The server runs until you press Ctrl+C, then shuts down in order.

#include "example_pki.h"
#include "example_support.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_permission_type.h"
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
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:minimal";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4840";
constexpr double initialSetpoint = 25.0;

/// Creates the server and hands it to the Runtime to own.
///
/// Anonymous authentication is accepted and mapped to the standard Observer role. A deployment
/// replaces both with its own identities and role mapping.
ua::server::Server& create_server(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Server)};

  ua::server::ServerComponents components;
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Registers this server's own namespace and returns the index it was assigned.
///
/// The URI is the stable identity; the index is assigned at registration and differs between
/// servers. Always address nodes with the returned index, never a literal.
///
/// The permissions granted here are the namespace default, inherited by every node that does not
/// carry its own. Granting nothing means exactly that: a Session would not even be able to browse
/// these nodes. Each node's NodeClass and AccessLevel still decide which of the granted operations
/// actually apply, so Read and Write here do not make a read-only node writable.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{
        ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read, ua::PermissionType::Bit::Write})};

  // Every node in this namespace requires a Session over a signed and encrypted channel.
  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, secureSessionOnly));
}

/// Adds a `Demo` folder beneath `Objects`, containing one readable and writable `Setpoint`.
///
/// A node needs three things to be usable: an incoming hierarchical reference from somewhere a
/// client can reach, a type definition, and - for a Variable - a data type and an access level
/// saying which operations are permitted.
ua::NodeId add_demo_folder(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
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
  // as<T>() narrows a NodeAccessor to the accessor for its NodeClass, which is what adds the
  // Variable-only members used below. It is empty when the node is of another class.
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

  // The address space stores the value, so a client Read and Write need no handler of their own.
  // Bind a read or write handler instead when the value belongs to equipment or another system.
  setpoint.write_value_sync(initialSetpoint);
  return setpointId;
}

/// Opens the listener, advertises one secure endpoint, and starts serving.
///
/// The endpoint pairs a SecurityPolicy with a MessageSecurityMode and the user identities it
/// accepts. Anonymous is accepted only inside the signed and encrypted channel.
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
  server.add_endpoint(listener, std::move(endpoint));

  server.start_sync();
  return server.advertised_urls(listener).front().str();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("server/minimal", "The smallest standalone secure OPC UA server.");

    // A fixed default port, because a server that is reachable at a known address is the whole
    // point; the override is for a machine that already has something listening there.
    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    examples::step(1, "Opened the development PKI");

    ua::server::Server& server = create_server(runtime, pki);
    examples::step(2, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    add_demo_folder(addressSpace, namespaceIndex);
    examples::step(3, fmt::format("Published Demo/Setpoint in namespace {}", namespaceUri));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_minimal in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/minimal");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/minimal", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/minimal: {}\n", failure.what());
  }
  return 1;
}
