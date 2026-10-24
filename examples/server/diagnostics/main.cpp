// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief What a running server can tell you about itself.
///
/// A server that is otherwise idle has nothing to report, so this one connects a client to itself,
/// does a little work over that Session, and then prints what its observer saw and what its counters
/// hold. Both halves run in one process, so the example needs no second terminal.
///
/// There are two separate mechanisms here, and they answer different questions. A `ServerObserver`
/// is told about each event as it happens, which is what an audit log or an alerting rule needs. The
/// health snapshots are sampled totals, which is what a dashboard needs.
///
/// The server runs until you press Ctrl+C, then shuts down in order.

#include "example_pki.h"
#include "example_queue.h"
#include "example_support.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_object_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_server_health.h"
#include "ua_server_observer.h"
#include "ua_variable_id.h"

#include <fmt/format.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultBindAddress = "127.0.0.1:4845";
constexpr auto eventBudget = 10000ms;
constexpr int connectEventCount = 2;
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

/// Records the Session lifecycle events it is told about, in the order they happened.
///
/// `ServerObserver` also reports SecureChannel and transport activity, rejected certificates, failed
/// authentications, reverse connections and shutdown; every hook has an empty default, so a subclass
/// overrides only the ones it wants. The three overridden here are the ones an audit trail needs.
///
/// The hooks run on one of the server's own threads and must return promptly, so each one appends a
/// line and nothing more. A real implementation appends to an audit log or increments a metric here;
/// anything slower belongs on another thread.
class RecordingObserver : public ua::server::ServerObserver
{
public:
  explicit RecordingObserver(std::shared_ptr<examples::Queue<std::string>> events)
    : mEvents(std::move(events))
  {}

  void on_session_created(const ua::server::SessionEventInfo& info) override
  {
    mEvents->push(fmt::format("Session created, name '{}'", info.sessionName));
  }

  void on_session_activated(const ua::server::SessionEventInfo& info) override
  {
    mEvents->push(fmt::format(
      "Session activated, user '{}'", info.clientUserId.empty() ? "anonymous" : info.clientUserId));
  }

  void on_session_closed(const ua::server::SessionEventInfo&, ua::StatusCode) override
  {
    mEvents->push("Session closed");
  }

private:
  std::shared_ptr<examples::Queue<std::string>> mEvents;
};

/// Creates the server, installs the observer, and hands the server to the Runtime to own.
ua::server::Server& create_server(ua::Runtime& runtime, const examples::DevelopmentPki& pki,
  const std::shared_ptr<ua::server::ServerObserver>& observer)
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

  ua::server::Server& server = runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
  server.set_observer(observer);
  return server;
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

/// Opens a Session against this same server, so that there is something to observe and to count.
///
/// Building a client is `examples/client/minimal`'s subject, not this one's; it is here only to
/// generate traffic. A deployment observes the clients it already has.
ua::client::Connection connect_probe(ua::Runtime& runtime, std::string_view endpointUrl)
{
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Client)};
  ua::client::Client& client = runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));

  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    config.sessionName = "diagnostics probe";
  };
  return client.easy_connect_sync(std::move(policy));
}

/// Prints the Session counters worth watching, from one sampled snapshot.
///
/// `current_*` counters are gauges: they go up and down as clients come and go. `cumulated_*`
/// counters only ever rise, and are what a rate is computed from. The snapshot also carries channel,
/// connection, subscription and rejection counters in the same two shapes. Each field is read from
/// its own atomic, so a snapshot is approximate rather than a coherent instant - which is what OPC UA
/// intends for diagnostics.
void report_server_counters(const ua::server::Server& server, std::string_view when)
{
  const ua::server::ServerHealthSnapshot health = server.health_snapshot();
  examples::detail(fmt::format("{}: {} Sessions now, {} since the server started",
    when,
    health.currentSessionCount,
    health.cumulatedSessionCount));
}

/// Prints what one Session has asked the server to do.
///
/// Per-session counters are how an operator answers "which client is generating this load?", and
/// `unauthorizedRequestCount` is how they answer "which client is asking for things it may not
/// have?" - usually the more interesting question.
void report_session_counters(const ua::server::Server& server)
{
  for (const ua::server::SessionHealthSnapshot& session : server.session_health_snapshots())
  {
    examples::detail(fmt::format("'{}': {} requests, {} reads, {} browses, {} unauthorized",
      session.sessionName,
      session.totalRequests.total,
      session.read.total,
      session.browse.total,
      session.unauthorizedRequestCount));
  }
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("server/diagnostics", "What a running server can tell you about itself.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    auto events = std::make_shared<examples::Queue<std::string>>();
    ua::server::Server& server = create_server(runtime, pki, std::make_shared<RecordingObserver>(events));
    examples::step(1, "Created the server with a ServerObserver installed");

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(2, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    report_server_counters(server, "Before any client");

    ua::client::Connection probe = connect_probe(runtime, endpointUrl);
    probe.read_value_sync<ua::String>(ua::NodeId{ua::VariableId::Server_ServerStatus_BuildInfo_ProductName});
    examples::step(3, "A client connected and read one Variable");
    for (int event = 0; event < connectEventCount; ++event)
    {
      examples::detail(events->take(eventBudget).value_or("no event arrived"));
    }

    examples::step(4, "Sampled the server-wide and per-Session counters");
    report_server_counters(server, "With one client");
    report_session_counters(server);

    probe.close_sync();
    examples::step(5, "The session gauge fell back; the cumulative total did not");
    examples::detail(events->take(eventBudget).value_or("no event arrived"));
    report_server_counters(server, "After the Session closed");

    examples::wait_for_shutdown_signal(runtime.executor(), "Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(6, "Stopped on Ctrl+C");

    examples::finished("server/diagnostics");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/diagnostics", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/diagnostics: {}\n", failure.what());
  }
  return 1;
}
