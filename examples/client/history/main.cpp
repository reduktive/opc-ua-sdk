// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Reading a Variable's past, and adding to it.
///
/// It talks to `examples/server/history`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// A history read is a cursor, not a single answer: the server returns as many values as it is
/// willing to send and a continuation point for the rest, and the cursor hides that exchange behind
/// `next_sync`. Whether any of this works at all is the server's decision - the services exist on
/// every server, and a server with no historian behind them answers
/// `BadHistoryOperationUnsupported`, which is why the example asks first.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_history_facade.h"
#include "ua_history_read_cursor.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
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
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4847";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:history";
constexpr std::string_view folderName = "Plant";
constexpr std::string_view variableName = "Temperature";
// The window to read. A history read always names one, because "everything" is rarely what anyone
// means and is never what a large archive should be asked for.
constexpr int windowYear = 2026;
constexpr int windowMonth = 1;
constexpr int windowDay = 1;
constexpr int windowStartHour = 8;
constexpr int windowEndHour = 10;
constexpr int insertHour = 9;
constexpr int insertMinute = 25;
constexpr double insertValue = 22.5;
// `2026-01-01T09:05` - an ISO instant cut before the seconds, which is the resolution this archive
// was written at. Presentation only; the DataValue keeps the full instant it carries.
constexpr std::size_t minutePrecision = 16;
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

/// Resolves `Plant/Temperature` to the NodeId this server gave it.
ua::NodeId resolve_temperature(ua::client::Connection& connection)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, {std::string{folderName}, std::string{variableName}}));
}

/// The window every read in this example asks for.
ua::client::TimeRange window()
{
  ua::client::TimeRange range;
  range.startTime = ua::DateTime{windowYear, windowMonth, windowDay, windowStartHour, 0, 0.0};
  range.endTime = ua::DateTime{windowYear, windowMonth, windowDay, windowEndHour, 0, 0.0};
  return range;
}

/// Drains a cursor and returns every value it yields.
///
/// Each `next_sync` is at least one HistoryRead on the wire. A server may return fewer values than
/// asked, even none, with a continuation point to resume from (Part 11 section 6.3), so the loop runs
/// while `has_more` reports a page or a continuation point still held; the cursor asks again itself
/// after an empty page. Draining matters: an abandoned continuation point occupies a slot on the
/// server until it times out.
std::vector<ua::DataValue> drain(ua::client::HistoryReadCursor cursor)
{
  std::vector<ua::DataValue> values;
  while (cursor.has_more())
  {
    const std::vector<ua::DataValue> page = cursor.next_sync();
    values.insert(values.end(), page.begin(), page.end());
  }
  return values;
}

/// Renders one archived sample the way a person reads it, trimmed to the minute.
///
/// A DataValue's timestamps are optional: a server returns the ones the read asked for and no
/// others, so code that assumes both are present fails on a perfectly valid answer.
std::string describe(const ua::DataValue& value)
{
  if (!value.source_timestamp())
  {
    return "no source timestamp";
  }
  const std::string instant = ua::to_string(*value.source_timestamp());
  return fmt::format("{}  {}", instant.substr(0, minutePrecision), value.value().to<double>().value_or(0.0));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/history", "Read a Variable's past, and add to it.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    ua::client::HistoryFacade history = connection.history();
    const ua::NodeId temperature = resolve_temperature(connection);
    examples::step(1, fmt::format("Connected to {} and resolved {}", endpointUrl, variableName));

    examples::step(2,
      fmt::format("Server keeps history for this node: {}",
        history.is_history_capable_sync(temperature) ? "yes" : "no"));

    const std::vector<ua::DataValue> archived = drain(history.read_raw_sync(temperature, window()));
    examples::step(3, fmt::format("HistoryRead Raw returned {} samples", archived.size()));
    for (const ua::DataValue& sample : archived)
    {
      examples::detail(describe(sample));
    }

    ua::DataValue addition;
    addition.value() = ua::Variant{insertValue};
    addition.source_timestamp() =
      ua::DateTime{windowYear, windowMonth, windowDay, insertHour, insertMinute, 0.0};
    addition.status() = ua::StatusCode{ua::Status::Good};
    const ua::client::HistoryUpdateResult inserted =
      history.insert_data_sync(temperature, {std::move(addition)});
    examples::step(4,
      fmt::format(
        "Inserted one sample, server answered {}", ua::to_string(inserted.operationResults.front())));

    const std::vector<ua::DataValue> updated = drain(history.read_raw_sync(temperature, window()));
    examples::step(5, fmt::format("HistoryRead Raw now returns {} samples", updated.size()));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(6, "Closed the Session and stopped the client");

    examples::finished("client/history");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/history", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/history: {}\n", failure.what());
  }
  return 1;
}
