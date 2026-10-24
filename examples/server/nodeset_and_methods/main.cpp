// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Importing an information model from a NodeSet2 file and binding behaviour to it.
///
/// The model is designed in `model/Pump.NodeSet2.xml` and imported at startup. The application
/// supplies only what a file cannot: the runtime value of a Variable and the body of a Method.
///
/// No code generation is involved. The SDK's type generator produces typed accessors for a model,
/// which is worth having for a large one - `examples/reference_server` uses it - but a NodeSet is
/// perfectly usable without it, and this example shows that path.
///
/// Run `examples/client/browse_and_call` style discovery against it, or any OPC UA client.

#include "example_pki.h"
#include "example_support.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_call_method_result.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_permission_type.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:pump";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4842";
constexpr std::string_view modelFilePath = "model/Pump.NodeSet2.xml";
constexpr double initialSpeed = 1450.0;

// The identifiers the NodeSet assigns within its own namespace. The namespace INDEX is decided at
// import time and is never hard-coded; the identifier inside it is the model's own choice.
constexpr std::uint32_t pumpSpeedIdentifier = 5002;
constexpr std::uint32_t pumpStopIdentifier = 5003;

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
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Registers the model's namespace before importing it, so the file's `ns=1` maps to a real index.
///
/// The permissions granted here are the namespace default, inherited by every imported node. The
/// AccessLevel each node declares in the file still decides which of them apply to it.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Write,
        ua::PermissionType::Bit::Call})};
  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, {}));
}

/// Reads the NodeSet2 file and adds every node it declares to the address space.
void import_model(ua::server::Server& server, const std::filesystem::path& modelFile)
{
  ua::FileStream model{modelFile};
  const ua::StatusCode opened = model.open_for_read();
  if (!opened.is_good())
  {
    // An expected, actionable failure: the file is named by configuration and may be absent.
    throw ua::UaException{opened};
  }
  server.import_nodeset_sync(model);
}

/// Supplies the runtime behaviour the file cannot declare: Speed's starting value, and what Stop
/// actually does.
void bind_behaviour(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId speedId{namespaceIndex, pumpSpeedIdentifier};
  ua::VariableAccessor speed = addressSpace.find_node_sync(speedId).as<ua::VariableAccessor>().value();
  speed.write_value_sync(initialSpeed);

  ua::NodeAccessor stop = addressSpace.find_node_sync(ua::NodeId{namespaceIndex, pumpStopIdentifier});
  auto* callSource = stop->method_call_source();
  if (callSource == nullptr)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadNotSupported}};
  }

  // Stop declares no arguments, so the handler's argument tuple is empty. It still completes the
  // call exactly once, which is the contract for every Method handler.
  using NoArguments = std::tuple<>;
  auto handler = [speed](const ua::NodeId&,
                   const NoArguments&,
                   std::shared_ptr<const ua::MethodCallContext>,
                   ua::CallMethodResult result,
                   ua::CallMethodCompleteCallback complete) mutable
  {
    // On the server's executor the synchronous forms refuse (Bad_WouldBlock), so the write is
    // asynchronous and the call is answered from its completion.
    speed.write_value_async(ua::DataValue{ua::Variant{0.0}},
      [result = std::move(result), complete = std::move(complete)](ua::VoidResult written) mutable
      {
        if (written.is_bad())
        {
          return complete(ua::CallResult{written.status_code(), written.shared_detail()});
        }
        complete(ua::CallResult{std::move(result)});
      });
  };
  const ua::StatusCode installed = callSource->set_call_handler(ua::MethodAdapter<NoArguments>{handler});
  if (!installed.is_good())
  {
    throw ua::UaException{installed};
  }
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
    examples::banner("server/nodeset_and_methods", "Import a model from a file, then give it behaviour.");

    // Found relative to the working directory by default, so the example can be run from its own
    // source directory, and named explicitly otherwise.
    const std::filesystem::path modelFile{examples::option_value(argc, argv, "--model", modelFilePath)};

    // A fixed default port, because a server that is reachable at a known address is the whole
    // point; the override is for a machine that already has something listening there.
    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    import_model(server, modelFile);
    examples::step(
      2, fmt::format("Imported {} into namespace index {}", modelFile.filename().string(), namespaceIndex));

    bind_behaviour(addressSpace, namespaceIndex);
    examples::step(3, fmt::format("Bound Speed = {} and the Stop handler", initialSpeed));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::detail("Model: Pump with Speed (Double, read/write) and Stop().");
    examples::wait_for_shutdown_signal(runtime.executor(), "Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/nodeset_and_methods");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/nodeset_and_methods", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/nodeset_and_methods: {}\n", failure.what());
  }
  return 1;
}
