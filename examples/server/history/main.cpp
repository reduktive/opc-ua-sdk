// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Serving Historical Access, with the SDK's bundled engine as the historian.
///
/// A base server answers HistoryRead with `BadHistoryOperationUnsupported`: the routes are live, but
/// nothing is behind them. History is a host integration, and something has to actually store the
/// values. This example plugs in the SDK's optional bundled engine over its SQLite store; an
/// application with an existing historian implements `NamespaceHistoryDelegate` against that instead.
///
/// Nothing records a value for you either. Marking a Variable `Historizing` advertises that its
/// history is being kept; feeding the historian is the application's job, and `seed_history` here is
/// standing in for the collector that would normally do it.
///
/// Run `examples/client/history` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_exceptions.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_engine_delegate.h"
#include "ua_history_namespace.h"
#include "ua_history_sqlite_store.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_variabletype_id.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:history";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4847";
constexpr std::string_view variableName = "Temperature";
constexpr std::string_view databaseName = "history.sqlite";
// Fixed timestamps, so a reader can compare their own run against the documented output. A real
// historian's timestamps come from whatever produced the value.
constexpr int seedYear = 2026;
constexpr int seedMonth = 1;
constexpr int seedDay = 1;
constexpr int seedHour = 9;
constexpr int seedSampleCount = 5;
constexpr int seedMinuteStep = 5;
constexpr double seedFirstValue = 20.0;
constexpr double seedValueStep = 0.5;

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

/// Wraps this server's namespace in one that answers history, and registers it.
///
/// `HistoryNamespace` forwards every non-history operation to the namespace it wraps and adds a
/// history delegate. The delegate here is the bundled engine over a SQLite file; replacing it with
/// your own class is the whole of integrating an existing historian.
///
/// `ReadHistory` and `InsertHistory` are separate permissions from `Read` and `Write`: a Role may
/// read live values and be refused the archive, or the reverse.
std::uint16_t add_history_namespace(
  ua::AddressSpace& addressSpace, const std::shared_ptr<ua::history::HistoryEngineDelegate>& historian)
{
  const std::vector<ua::RolePermissionType> operatorMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Operator,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::ReadHistory,
        ua::PermissionType::Bit::InsertHistory,
        ua::PermissionType::Bit::ModifyHistory})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  auto inner = addressSpace.create_namespace(std::string{namespaceUri}, operatorMay, secureSessionOnly);
  return addressSpace.add_namespace_sync(
    std::make_shared<ua::history::HistoryNamespace>(std::move(inner), historian));
}

/// Adds the historised Variable beneath a `Plant` folder.
///
/// Three things mark a node as historised, and all three matter. The AccessLevel must carry
/// `HistoryRead` (and `HistoryWrite` if clients may update the archive), the `Historizing` attribute
/// must be true so a client can see that history is being kept, and the namespace must have a
/// delegate that can answer.
ua::NodeId add_historised_variable(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId plantId{namespaceIndex, "Plant"};
  ua::NodeAccessor plant = addressSpace.create_node_sync(plantId, ua::NodeClass::Object);
  plant.set_browse_name(ua::QualifiedName{namespaceIndex, "Plant"});
  plant.set_display_name(ua::LocalizedText{"", "Plant"});
  plant.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, plantId);

  const ua::NodeId variableId{namespaceIndex, "Plant.Temperature"};
  ua::VariableAccessor temperature =
    addressSpace.create_node_sync(variableId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  temperature.set_browse_name(ua::QualifiedName{namespaceIndex, std::string{variableName}});
  temperature.set_display_name(ua::LocalizedText{"", std::string{variableName}});
  temperature.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  temperature.set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead,
    ua::AccessLevelType::Bit::HistoryRead,
    ua::AccessLevelType::Bit::HistoryWrite});
  temperature.set_historizing(true);
  temperature.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  plant.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, variableId);
  temperature.write_value_sync(seedFirstValue);
  return variableId;
}

/// Puts a known series into the archive, standing in for a collector.
///
/// The SDK does not record a Variable's writes into history by itself, and no OPC UA service asks it
/// to. Whatever produces your values - a scanner, a driver, a message bus - is what calls the
/// historian, on its own schedule, with its own timestamps.
void seed_history(ua::history::HistoryEngineDelegate& historian, const ua::NodeId& node)
{
  ua::NamespaceHistoryDelegate::UpdateDataItem item;
  item.nodeId = node;
  item.performInsertReplace = ua::PerformUpdateType::Insert;
  for (int sample = 0; sample < seedSampleCount; ++sample)
  {
    const ua::DateTime when{seedYear, seedMonth, seedDay, seedHour, sample * seedMinuteStep, 0.0};
    ua::DataValue value;
    value.value() = ua::Variant{seedFirstValue + sample * seedValueStep};
    value.source_timestamp() = when;
    value.server_timestamp() = when;
    value.status() = ua::StatusCode{ua::Status::Good};
    item.values.push_back(std::move(value));
  }

  std::promise<void> stored;
  std::vector<ua::NamespaceHistoryDelegate::UpdateDataItem> items;
  items.push_back(std::move(item));
  historian.update_data_async({}, std::move(items), [&stored](auto) { stored.set_value(); });
  stored.get_future().get();
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
    examples::banner("server/history", "Answer HistoryRead with a real historian behind it.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    const examples::TemporaryDirectory archive{"uasdk-example-history"};
    auto historian =
      std::make_shared<ua::history::HistoryEngineDelegate>(std::make_unique<ua::history::SqliteHistoryStore>(
        (archive.path() / databaseName).string(), server.ua_binary_data_value_codec()));
    examples::step(2, "Opened the bundled SQLite history store");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_history_namespace(addressSpace, historian);
    const ua::NodeId temperature = add_historised_variable(addressSpace, namespaceIndex);
    examples::step(3, fmt::format("Published Plant/{} as a historised Variable", variableName));

    seed_history(*historian, temperature);
    examples::step(4, fmt::format("Seeded {} samples, five minutes apart", seedSampleCount));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(5, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_history in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(6, "Stopped on Ctrl+C");

    examples::finished("server/history");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/history", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/history: {}\n", failure.what());
  }
  return 1;
}
