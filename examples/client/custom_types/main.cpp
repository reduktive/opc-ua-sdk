// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Reading a structure whose type this program was never compiled against.
///
/// It talks to `examples/server/custom_types`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// Nothing here knows what a `PumpReading` is. The Connection resolves the type from the server's
/// own DataType node - the same `StructureDefinition` the server published - and hands back a
/// `DynamicStructure` whose fields can be walked by name. No header is shared between the two
/// programs and nothing was generated from a NodeSet.
///
/// The reify pass that installs the decoder runs on the tier-2 `typed()` read path, so that is the
/// path this example reads through.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_ref_structure.h"
#include "ua_hierarchical_path.h"
#include "ua_runtime.h"
#include "ua_structure_field.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4848";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:types";
constexpr std::string_view folderName = "Pump";
constexpr std::string_view variableName = "Reading";
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

/// Discovers the server's endpoints and opens a Session on the strongest one.
ua::client::Connection connect(ua::Runtime& runtime, std::string_view endpointUrl)
{
  // Identity, client, connection: covered properly by examples/client/minimal, gathered here so
  // main() gets to the subject.
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  ua::client::Client& client = create_client(runtime, pki);
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Resolves `Pump/Reading` to the NodeId this server gave it.
ua::NodeId resolve_reading(ua::client::Connection& connection)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, {std::string{folderName}, std::string{variableName}}));
}

/// The decoded structure, or a clear failure saying the type could not be resolved.
///
/// A value whose type the server did not describe arrives as an opaque structure that preserves its
/// bytes rather than as a decoded one. That is deliberate - an unknown type must not abort the
/// message it arrived in, and its bytes still round-trip if you write them back - but for this
/// example it means the server is not published the way the example assumes.
const ua::DynamicStructure& decoded_or_throw(const ua::Variant& value)
{
  const auto& structure = value.as<ua::RefStructure<ua::Structure>>();
  const auto* reading = dynamic_cast<const ua::DynamicStructure*>(structure.get());
  if (reading == nullptr)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadDataTypeIdUnknown,
      ua::ErrorDetail::build("ExampleTypeNotResolved",
        "the value's type could not be resolved from the server, so it decoded as an opaque structure",
        "client.custom_types")}};
  }
  return *reading;
}

/// The name the server gave the DataType, read from the DataType node itself.
///
/// The `StructureDefinition` describes the *shape*; the node carries the *name*. A client that wants
/// both reads both, which is why this is a second call rather than a field of the descriptor.
std::string type_name(ua::client::Connection& connection, const ua::DynamicStructure& reading)
{
  const ua::DataValue browseName = connection.typed().read_attribute_sync(
    ua::NodeId{reading.descriptor().type_id().node_id()}, ua::AttributeId::BrowseName);
  return std::string{std::string_view{browseName.value().as<ua::QualifiedName>().name()}};
}

/// Renders one field as `name = value`, whatever the field's DataType turned out to be.
///
/// The descriptor supplies the names and the declared types; the instance supplies the values. This
/// is what a generic tool - a browser, a logger, a gateway - does with a type it has never seen.
///
/// An optional field needs the extra question. It is part of the type whether or not this value has
/// it, so a reader that only walks the descriptor would report a field that was never sent; asking
/// the instance is what distinguishes "absent" from "empty".
std::string describe_field(const ua::DynamicStructure& reading, std::size_t index)
{
  const ua::StructureField& field = reading.descriptor().field(index);
  const std::string_view name{field.name()};
  if (field.is_optional() && !reading.has_field(name))
  {
    return fmt::format("{} = absent (optional, not sent by this server)", name);
  }
  return fmt::format(
    "{}{} = {}", name, field.is_optional() ? " (optional)" : "", ua::to_string(reading.field(index)));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/custom_types", "Decode a structure this program was never built for.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    const ua::NodeId reading = resolve_reading(connection);
    examples::step(1, fmt::format("Connected to {} and resolved {}", endpointUrl, variableName));

    // read_values_sync is the tier-2 bulk read, and the one that carries the type-reify pass.
    const std::vector<ua::DataValue> values = connection.typed().read_values_sync({reading});
    const ua::DynamicStructure& decoded = decoded_or_throw(values.front().value());
    examples::step(2, fmt::format("Read the value; its type resolved to {}", type_name(connection, decoded)));

    examples::step(3, fmt::format("It has {} fields, described by the server:", decoded.field_count()));
    for (std::size_t index = 0; index < decoded.field_count(); ++index)
    {
      examples::detail(describe_field(decoded, index));
    }

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(4, "Closed the Session and stopped the client");

    examples::finished("client/custom_types");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/custom_types", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/custom_types: {}\n", failure.what());
  }
  return 1;
}
