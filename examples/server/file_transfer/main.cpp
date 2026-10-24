// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Serving files over OPC UA, so a client can list, read, and create them.
///
/// OPC UA transfers a file through a node, not through a side channel. A `FileType` node offers
/// Open, Read, Write, GetPosition, SetPosition and Close as Methods, and a `FileDirectoryType` node
/// adds CreateFile, CreateDirectory and Delete. Everything travels inside the same Session, under
/// the same security and the same authorization, which is the whole reason to do it this way.
///
/// The SDK supplies the wiring: `ua::FileHelper` and `ua::FileDirectoryHelper` back those nodes with
/// real filesystem I/O, so an application chooses a path and a permission model and nothing else.
///
/// Run `examples/client/file_transfer` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_encoding_limits.h"
#include "ua_exceptions.h"
#include "ua_file_system_helpers.h"
#include "ua_instantiation_options.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:files";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4846";
constexpr std::string_view directoryName = "Documents";
constexpr std::string_view seedFileName = "manual.txt";
constexpr std::string_view seedFileContent = "Reduktive OPC UA SDK\nFile transfer example.\n";

/// Creates the server and hands it to the Runtime to own.
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
    {{ua::server::WellKnownRole::Operator, ua::IdentityCriteriaType::Anonymous}});

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Registers the namespace the file nodes live in.
///
/// Creating a file over OPC UA adds a node, and deleting one removes it, so a client that may do
/// either needs `AddNode` and `DeleteNode` as well as `Call`. Grant a read-only client `Browse`,
/// `Read` and `Call` only: it can then Open and Read a file but not change the directory.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> operatorMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Operator,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Write,
        ua::PermissionType::Bit::Call,
        ua::PermissionType::Bit::AddNode,
        ua::PermissionType::Bit::DeleteNode})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, operatorMay, secureSessionOnly));
}

/// Writes the one file the directory starts out holding.
///
/// Not for production: a deployment serves a directory that already exists and is backed up. This
/// one is created under the system temporary directory and removed when the example exits.
void seed_directory(const std::filesystem::path& directory)
{
  std::filesystem::create_directories(directory);
  std::ofstream seed{directory / seedFileName, std::ios::binary};
  seed << seedFileContent;
}

/// Publishes the directory as a FileDirectoryType node backed by a real filesystem path.
///
/// The helper installs handlers for every Method the type defines and keeps the node's Size and
/// OpenCount Properties answering from live state. Concurrent clients get independent file handles
/// with independent stream positions, so one client reading does not move another client's cursor.
ua::FileDirectoryHelper publish_directory(
  ua::server::Server& server, std::uint16_t namespaceIndex, const std::filesystem::path& directory)
{
  ua::InstantiationOptions options;
  options.parentReferenceType = ua::NodeId{ua::ReferenceTypeId::Organizes};
  options.targetNamespaceIndex = namespaceIndex;

  return ua::FileDirectoryHelper::create_sync(server.address_space(),
    ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::QualifiedName{namespaceIndex, std::string{directoryName}},
    directory,
    options,
    true);
}

/// Publishes one file inside the directory as a FileType node of its own.
///
/// A FileDirectoryType node lists what is on disk beneath it, but a client addresses a file through
/// a node. Adding the node here is what makes the seeded file reachable without the client having to
/// create it first.
ua::FileHelper publish_file(ua::server::Server& server, std::uint16_t namespaceIndex,
  const ua::NodeId& directoryNode, const std::filesystem::path& path)
{
  ua::InstantiationOptions options;
  options.parentReferenceType = ua::NodeId{ua::ReferenceTypeId::Organizes};
  options.targetNamespaceIndex = namespaceIndex;

  return ua::FileHelper::create_sync(server.address_space(),
    directoryNode,
    ua::QualifiedName{namespaceIndex, std::string{seedFileName}},
    path,
    options,
    true);
}

/// Opens the listener, advertises one secure endpoint, and starts serving.
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
    examples::banner("server/file_transfer", "Serve a directory and a file as OPC UA nodes.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    const examples::TemporaryDirectory served{"uasdk-example-files"};
    seed_directory(served.path());
    examples::step(2, fmt::format("Serving a directory holding one file, {}", seedFileName));

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    const ua::FileDirectoryHelper directory = publish_directory(server, namespaceIndex, served.path());
    const ua::FileHelper file =
      publish_file(server, namespaceIndex, directory.node_id(), served.path() / seedFileName);
    examples::step(
      3, fmt::format("Published {} as a FileDirectoryType with one FileType child", directoryName));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_file_transfer in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/file_transfer");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/file_transfer", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/file_transfer: {}\n", failure.what());
  }
  return 1;
}
