// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientDiagnostics cluster of the client integration-test matrix (the six `ClientDiagnostics.*`
/// rows,
///        all traced to CL-BASEDIAG-001). DIAGNOSTICS + ERROR-CHAIN SURFACING: the client's outbound
///        `RequestHeader.returnDiagnostics` plumbing and its inbound `DiagnosticInfo -> ErrorDetail`
///        decode/surface path. ErrorDetail propagation is priority #1 here: a server `DiagnosticInfo` that is
///        dropped, delivered as raw stringTable indexes, or crashed on a `-1` index is a first-order defect,
///        so every row asserts the REAL wire-observable behaviour and pins the decoded chain end-to-end.
///
/// Harness: the `client_decode_caps_matrix_tests.cpp` fixture pattern - a real `Client` bound to a
/// `MisbehavingServer`'s crypto + trusted store over ephemeral TCP, an activated Session wrapped into a
/// started `ConnectionImpl`, then into the public tier-2 `ua::client::Connection` (via
/// `ConnectionHandleFactory`) so reads run the genuine managed path (`Connection::try_read_value_sync`).
/// Two MisbehavingServer interfaces drive the rows:
///   - `set_request_observer` captures the OUTBOUND `ReadRequest.request_header().returnDiagnostics()`
///     the client actually put on the wire (mask rows 1-2), and
///   - `set_response_mutator` REPLACES a `ReadResponse` with a crafted `ua::ServiceFault` carrying a
///     `serviceDiagnostics` `DiagnosticInfo` + `stringTable` (rows 3-5). A `ServiceFault` message (Case-1)
///     drives the secure-channel `ServiceFault` decode branch (ua_client_secure_channel_impl.cpp:809/830).
///     A bad `serviceResult` stamped on a NORMAL response header (Case-2) is a DIFFERENT inbound shape: the
///     secure channel delivers it as a transport-good `Result<ReadResponse>`, and the `invoke_wire_op`
///     funnel's `surface_response_diagnostics` decodes it AND (CL-DIAG-005) collapses the Result onto the
///     wire-crossing marker. The `install_case2_read_diagnostics_injector` interface produces Case-2 to
///     exercise that funnel-observer path (the CL-DIAG-012 rows). (Case-2 is synthetic - real servers send
///     ServiceFaults.)
///
/// KEY INVESTIGATION FINDINGS (the required forensic results this file pins):
///   1. THE OUTBOUND RETURN-DIAGNOSTICS MASK IS PLUMBED ONTO THE WIRE. `ClientConfig
///      ::defaultReturnDiagnostics` flows CoreClientImpl::default_return_diagnostics
///      (ua_client_impl.cpp:322)
///      -> session deps -> `typed_request_async` stamps it onto every request whose `returnDiagnostics`
///      is still 0 (ua_session_service_helpers.h:29-31). So a configured 0x000000FF reaches the server's
///      RequestHeader (row 1) and a default 0 stays exactly 0 (row 2). Rows 1-2 pin both directions.
///
///   2. A SERVICEFAULT'S `serviceDiagnostics` IS DECODED INTO THE `ErrorDetail` CHAIN AND SURFACED
///      VERBATIM. The secure channel decodes it (DiagnosticInfoDecoder, wire-crossing marker +
///      `server.symbolic.` prefix) and wraps it under a "ServiceFault" link; the session forwards the
///      bad Result unchanged and the tier-2 read-value facade propagates `shared_detail()` single-wrap
///      (ua_connection.cpp:348). So `Result<T>.status_code().shared_detail()` carries the decoded
///      SymbolicId / localizedText / additionalInfo / innerStatusCode against the resolved stringTable
///      (row 3), the full 3-level nested chain (row 4), and does not crash on `-1` indexes (row 5).
///
///   3. `on_error_chain` FIRES ON THE CASE-2 GENERAL-SURFACE FUNNEL PATH (CL-BASEDIAG-001/CL-DIAG-005/
///      CL-DIAG-012), gated by `ClientDiagnosticPolicy.emitOnErrorChainObserver` (default on). The two
///      `ErrorChainObserver*` rows pin it end-to-end: a Case-2 response (bad `serviceResult` + diagnostics
///      on a normal ReadResponse header) fires `on_error_chain` when the policy enables it, and the gate
///      suppresses it (while the CL-DIAG-005 Result marker still survives) when disabled. It does NOT fire
///      on a Case-1 ServiceFault (the secure channel delivers that as a bad Result before the funnel, so the
///      `result.is_good()`-gated observer path is skipped) -
///      `BadResponseServiceDiagnosticsSurfacedViaErrorChain` pins that 0-fire, and row 6 pins that empty
///      diagnostics fire no observer.
///
/// CALIBRATION (row 5): a DiagnosticInfo string index of `-1` is defensively guarded (resolve_string's
/// `i < 0` branch, ua_diagnostic_to_error_detail.cpp:22) so the client NEVER dereferences the string
/// table out of range - the matrix falsifier ("-1 causes an out-of-range access / crash") is refuted.
/// The REAL decoded text is the placeholder `"<unknown:-1>"`, NOT the empty string the matrix intent
/// describes; this file locks the real behaviour and reports the placeholder-vs-empty divergence as a
/// candidate spec refinement (OPC UA Part 4: index -1 == "field not specified").
///
/// Falsifiability: every row encodes its matrix `[neg: ...]` falsifier and asserts the EXACT observable.
/// No fixed sleeps; the tier-2 sync reads block the test thread on a completion bridged off the executor.

#include "compliance_helpers.h"

#include "misbehaving_server.h"
#include "requests.h"
#include "test_utilities.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_observer_sink.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_client_config_bundle.h"
#include "ua_client_configuration.h"
#include "ua_client_diagnostic_policy.h"
#include "ua_client_observers.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_create_session_request.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_request_header.h"
#include "ua_response_header.h"
#include "ua_server_diagnostics_access.h"
#include "ua_service_fault.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ObserverSlots;

namespace
{

// A standard NS0 Variable present on every server and readable. The rows either read it verbatim (mask +
// empty-diagnostics rows) or replace its ReadResponse with a crafted ServiceFault (diagnostic rows); the
// node's real type is irrelevant.
const NodeId readNode{VariableId::Server_ServerStatus_State};

// Walks an ErrorDetail cause chain (outermost-first) for the first link whose code equals @p code.
const ErrorDetail* find_link_by_code(const ErrorDetail* head, std::string_view code)
{
  for (const ErrorDetail* node = head; node != nullptr; node = node->cause.get())
  {
    if (node->code == code)
    {
      return node;
    }
  }
  return nullptr;
}

// Walks an ErrorDetail cause chain (outermost-first) for the first link whose mSource equals @p source.
const ErrorDetail* find_link_by_source(const ErrorDetail* head, std::string_view source)
{
  for (const ErrorDetail* node = head; node != nullptr; node = node->cause.get())
  {
    if (node->source == source)
    {
      return node;
    }
  }
  return nullptr;
}

// The synthetic wire-crossing marker source the client's DiagnosticInfoDecoder always adds (CL-DIAG-005).
constexpr std::string_view wireMarkerSource = "client.tier0.session.decode_diagnostic";

// Builds a DiagnosticInfo whose string-index fields point at @p symbolicIdx / @p namespaceIdx /
// @p localizedTextIdx in the response stringTable, with optional additionalInfo + innerStatusCode. Passing
// a negative index reproduces the wire "field present but unspecified (-1)" shape row 5 needs.
DiagnosticInfo make_diagnostic(std::optional<int32_t> symbolicIdx, std::optional<int32_t> namespaceIdx,
  std::optional<int32_t> localizedTextIdx, std::optional<std::string> additionalInfo,
  std::optional<StatusCode> innerStatus)
{
  DiagnosticInfo diagnostic;
  if (symbolicIdx)
  {
    diagnostic.symbolic_id() = *symbolicIdx;
  }
  if (namespaceIdx)
  {
    diagnostic.namespace_uri() = *namespaceIdx;
  }
  if (localizedTextIdx)
  {
    diagnostic.localized_text() = *localizedTextIdx;
  }
  if (additionalInfo)
  {
    diagnostic.additional_info() = std::move(*additionalInfo);
  }
  if (innerStatus)
  {
    diagnostic.inner_status_code() = *innerStatus;
  }
  return diagnostic;
}

// Builds a ServiceFault carrying @p serviceResult + @p serviceDiagnostics resolved against @p stringTable.
std::shared_ptr<ua::ServiceFault> make_service_fault(
  StatusCode serviceResult, DiagnosticInfo serviceDiagnostics, const std::vector<std::string>& stringTable)
{
  auto fault = std::make_shared<ua::ServiceFault>();
  fault->response_header().service_result() = serviceResult;
  fault->response_header().service_diagnostics() = std::move(serviceDiagnostics);
  Array<String> table;
  for (const auto& entry : stringTable)
  {
    table.push_back(String{entry});
  }
  fault->response_header().string_table() = std::move(table);
  return fault;
}

// Installs a response mutator that, once @p armed, REPLACES every ReadResponse with a fresh crafted
// ServiceFault. Gating on @p armed keeps the bootstrap (namespace-array read, handshake) untouched.
void install_service_fault_injector(MisbehavingServer& server, std::shared_ptr<std::atomic<bool>> armed,
  std::function<std::shared_ptr<ua::ServiceFault>()> makeFault)
{
  server.set_response_mutator(
    [armed = std::move(armed), makeFault = std::move(makeFault)](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (dynamic_cast<ua::ReadResponse*>(response.second.get()) != nullptr)
      {
        response.second = makeFault();
      }
    });
}

// Installs a response mutator that, once @p armed, mutates every ReadResponse's HEADER to carry @p
// serviceResult (bad) + a crafted serviceDiagnostics, WITHOUT replacing the ReadResponse. This is the Case-2
// shape - a transport-good response whose ResponseHeader.serviceResult is bad - which reaches the
// `invoke_wire_op` funnel and its `surface_response_diagnostics` observer path (unlike a ServiceFault
// message, Case-1, which the secure channel converts to a bad Result before the funnel and so never fires
// that observer). Case-2 is synthetic (real servers send ServiceFaults), so a MisbehavingServer is the only
// way to exercise the funnel observer.
void install_case2_read_diagnostics_injector(MisbehavingServer& server,
  std::shared_ptr<std::atomic<bool>> armed, StatusCode serviceResult,
  std::function<DiagnosticInfo()> makeDiagnostic, std::vector<std::string> stringTable)
{
  server.set_response_mutator(
    [armed = std::move(armed),
      serviceResult,
      makeDiagnostic = std::move(makeDiagnostic),
      stringTable = std::move(stringTable)](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get()))
      {
        read->response_header().service_result() = serviceResult;
        read->response_header().service_diagnostics() = makeDiagnostic();
        Array<String> table;
        for (const auto& entry : stringTable)
        {
          table.push_back(String{entry});
        }
        read->response_header().string_table() = std::move(table);
      }
    });
}

// Installs a request observer that, once @p armed, captures the returnDiagnostics mask of the first
// ReadRequest seen (and records that a Read was observed).
void install_read_mask_capture(MisbehavingServer& server, std::shared_ptr<std::atomic<bool>> armed,
  std::shared_ptr<std::atomic<uint32_t>> captured, std::shared_ptr<std::atomic<bool>> sawRead)
{
  server.set_request_observer(
    [armed = std::move(armed), captured = std::move(captured), sawRead = std::move(sawRead)](
      const ua::Structure& request)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
      {
        captured->store(read->request_header().return_diagnostics(), std::memory_order_release);
        sawRead->store(true, std::memory_order_release);
      }
    });
}

void install_read_mask_sequence(MisbehavingServer& server, std::shared_ptr<std::atomic<bool>> armed,
  std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::vector<uint32_t>> captured)
{
  server.set_request_observer(
    [armed = std::move(armed), mutex = std::move(mutex), captured = std::move(captured)](
      const ua::Structure& request)
    {
      if (!armed->load(std::memory_order_acquire))
      {
        return;
      }
      if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
      {
        std::lock_guard lock(*mutex);
        captured->push_back(read->request_header().return_diagnostics());
      }
    });
}

// A ConnectionObserver that counts the diagnostic-family hooks (on_error_chain / on_advisory_diagnostic)
// plus on_connected (to prove the observer is genuinely wired into the sink, so a "0 fires" assertion is
// not vacuous). Counters are atomic: hooks are delivered on the sink's delivery strand while the test
// thread reads them.
class DiagnosticCountingObserver : public ua::client::ConnectionObserver
{
public:
  void on_connected(const Connection&) override
  {
    mConnectedFires.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_error_chain(
    const Connection&, StatusCode, std::shared_ptr<const ErrorDetail>, std::string_view) override
  {
    mErrorChainFires.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ErrorDetail>) override
  {
    mAdvisoryFires.fetch_add(1, std::memory_order_acq_rel);
  }

  int connected_fires() const
  {
    return mConnectedFires.load(std::memory_order_acquire);
  }

  /// Waits, within the poll budget, for the bootstrap on_connected: the sink delivers it on its strand, which
  /// can run after start has returned.
  void await_connected() const
  {
    const auto deadline = std::chrono::steady_clock::now() + ua::test_utils::default_poll_budget();
    while (connected_fires() < 1 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
  }

  int error_chain_fires() const
  {
    return mErrorChainFires.load(std::memory_order_acquire);
  }

  int advisory_fires() const
  {
    return mAdvisoryFires.load(std::memory_order_acquire);
  }

private:
  std::atomic<int> mConnectedFires{0};
  std::atomic<int> mErrorChainFires{0};
  std::atomic<int> mAdvisoryFires{0};
};

// A managed tier-2 Connection over a MisbehavingServer built with a specific ClientConfig (so the
// outbound returnDiagnostics mask under test is threaded onto the request path) and an optional
// per-Connection observer installed AT CONSTRUCTION (before start) via ConnectionConfig.observers, so the
// observer is genuinely in the sink's slots. Mirrors CapConnection in client_decode_caps_matrix_tests.cpp:
// a real Client + SecureChannel + activated Session wrapped into a started ConnectionImpl then into the
// public Connection handle. No reconnect wiring and no keep-alive poll -> single-shot, so the only inbound
// responses are the ones each row's read provokes.
class DiagConnection
{
public:
  DiagConnection(MisbehavingServer& server, ClientConfig clientConfig, ObserverSlots observers = {},
    ua::client::ClientDiagnosticPolicy diagnostics = {})
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appConfig),
      .client = std::move(clientConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    mChannel.emplace(mClient->core().open_channel_sync(openConfig));
    auto session = mChannel->create_session_sync({.sessionName = "ClientDiagnostics"});
    session.activate_sync();

    ua::client::detail::ConnectionConfig connectionConfig;
    connectionConfig.observers = std::move(observers);
    connectionConfig.diagnostics = std::move(diagnostics);
    auto impl = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), std::move(connectionConfig), Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~DiagConnection()
  {
    if (mConnection)
    {
      (void)mConnection->try_close_sync();
    }
    mConnection.reset();
    mChannel.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  DiagConnection(const DiagConnection&) = delete;
  DiagConnection& operator=(const DiagConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Connection> mConnection;
  VoidResult mStartStatus{};
};

// A direct tier-0 Session over the real client/channel/server stack. Unlike DiagConnection, this deliberately
// does not introduce a managed Connection facade: CL-DIAG-004 governs the raw Session service boundary.
class Tier0DiagSession
{
public:
  Tier0DiagSession(MisbehavingServer& server, bool wrapTier0, ClientConfig clientConfig = {})
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    clientConfig.diagnostics.wrapTier0 = wrapTier0;
    ua::client::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appConfig),
      .client = std::move(clientConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    mChannel.emplace(mClient->core().open_channel_sync(openConfig));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "Tier0Diagnostics"}));
    mSession->activate_sync();
  }

  ~Tier0DiagSession()
  {
    if (mSession)
    {
      (void)mSession->try_close_sync();
    }
    mSession.reset();
    mChannel.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  Tier0DiagSession(const Tier0DiagSession&) = delete;
  Tier0DiagSession& operator=(const Tier0DiagSession&) = delete;

  Session& session()
  {
    return *mSession;
  }

  SecureChannel& channel()
  {
    return *mChannel;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// Two independently configured Connections sharing one Client, used to prove the override does not leak
// through the Client-wide default or across sibling Connection/Session pairs.
class SharedDiagClient
{
public:
  SharedDiagClient(MisbehavingServer& server, uint32_t defaultMask) : mServer(server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ClientConfig clientConfig;
    clientConfig.defaultReturnDiagnostics = defaultMask;
    ua::client::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appConfig),
      .client = std::move(clientConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));
  }

  ~SharedDiagClient()
  {
    for (auto& connection : mConnections)
    {
      (void)connection.try_close_sync();
    }
    mConnections.clear();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  SharedDiagClient(const SharedDiagClient&) = delete;
  SharedDiagClient& operator=(const SharedDiagClient&) = delete;

  void add_connection(std::optional<uint32_t> mask, ua::client::ClientDiagnosticPolicy::WrapLevel wrapLevel =
                                                      ua::client::ClientDiagnosticPolicy::WrapLevel::Standard)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mServer.endpoint_url_none();
    config.reconnect = std::nullopt;
    config.diagnostics.requestedDiagnosticsMask = mask;
    config.diagnostics.wrapLevel = wrapLevel;
    mConnections.push_back(mClient->connect_sync(std::move(config)));
  }

  Connection& connection(std::size_t index)
  {
    return mConnections.at(index);
  }

private:
  MisbehavingServer& mServer;
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::vector<Connection> mConnections;
};

}  // namespace

// @verifies CL-DIAG-004
// @relation(CL-DIAG-004, scope=function)
TEST(ClientDiagnostics, Tier0WrapPolicyIsLosslessAndOptInOverRealServiceFault)
{
  const auto run = [](bool wrapTier0)
  {
    MisbehavingServer server;
    auto armed = std::make_shared<std::atomic<bool>>(false);
    install_service_fault_injector(server,
      armed,
      []
      {
        auto diagnostic = make_diagnostic(
          /*symbolicIdx=*/0, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
        return make_service_fault(
          StatusCode{Status::BadNodeIdUnknown}, std::move(diagnostic), {"UnknownNode"});
      });
    Tier0DiagSession client{server, wrapTier0};
    armed->store(true, std::memory_order_release);
    return client.session().attributes().try_read_sync(
      ReadRequestBuilder().read(readNode).attribute(AttributeId::Value));
  };

  const auto raw = run(false);
  ASSERT_TRUE(raw.is_bad());
  EXPECT_EQ(raw.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(raw.error_detail(), nullptr);
  EXPECT_EQ(raw.error_detail()->code, "ServiceFault")
    << "default tier-0 delivery must expose the raw secure-channel result without a Session wrap";
  EXPECT_NE(find_link_by_source(raw.error_detail(), wireMarkerSource), nullptr)
    << "raw tier-0 delivery must retain the wire marker and decoded server chain";
  EXPECT_EQ(find_link_by_source(raw.error_detail(), "client.tier0.session.service"), nullptr);

  const auto wrapped = run(true);
  ASSERT_TRUE(wrapped.is_bad());
  EXPECT_EQ(wrapped.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(wrapped.error_detail(), nullptr);
  EXPECT_EQ(wrapped.error_detail()->source, "client.tier0.session.service");
  ASSERT_NE(wrapped.error_detail()->cause, nullptr);
  EXPECT_EQ(wrapped.error_detail()->cause->code, "ServiceFault")
    << "the opt-in link must preserve the complete original real-wire failure as its cause";
  EXPECT_NE(find_link_by_source(wrapped.error_detail(), wireMarkerSource), nullptr);
}

// @verifies CL-DIAG-011
// @relation(CL-DIAG-011, scope=function)
TEST(ClientDiagnostics, PerConnectionReturnDiagnosticsOverrideIsWireExactAndIsolated)
{
  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  auto mutex = std::make_shared<std::mutex>();
  auto captured = std::make_shared<std::vector<uint32_t>>();
  install_read_mask_sequence(server, armed, mutex, captured);

  SharedDiagClient client{server, 0x55u};
  client.add_connection(0xFFFFu);
  client.add_connection(0u);
  armed->store(true, std::memory_order_release);

  ASSERT_TRUE(client.connection(0).try_read_value_sync(readNode).is_good());
  ASSERT_TRUE(client.connection(1).try_read_value_sync(readNode).is_good());

  std::lock_guard lock(*mutex);
  ASSERT_EQ(captured->size(), 2u);
  EXPECT_EQ((*captured)[0], 0xFFFFu)
    << "the first Connection override must replace the shared Client default on the wire";
  EXPECT_EQ((*captured)[1], 0u)
    << "an explicit zero override on the sibling Connection must remain isolated and wire-exact";
}

// @verifies CL-DIAG-015
// @relation(CL-DIAG-015, scope=function)
TEST(ClientDiagnostics, WrapLevelsControlRealWireFailureChainAndVerboseNamespaceContext)
{
  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_service_fault_injector(server,
    armed,
    []
    {
      auto diagnostic =
        make_diagnostic(/*symbolicIdx=*/0, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
      return make_service_fault(StatusCode{Status::BadNodeIdUnknown}, std::move(diagnostic), {"UnknownNode"});
    });

  SharedDiagClient client{server, 0x3FFu};
  client.add_connection(std::nullopt, ClientDiagnosticPolicy::WrapLevel::Minimal);
  client.add_connection(std::nullopt, ClientDiagnosticPolicy::WrapLevel::Standard);
  client.add_connection(std::nullopt, ClientDiagnosticPolicy::WrapLevel::Verbose);
  armed->store(true, std::memory_order_release);

  const auto minimal = client.connection(0).try_read_value_sync(readNode);
  ASSERT_TRUE(minimal.is_bad());
  ASSERT_NE(minimal.error_detail(), nullptr);
  EXPECT_EQ(find_link_by_source(minimal.error_detail(), "client.tier1.connection.read"), nullptr);
  EXPECT_EQ(find_link_by_source(minimal.error_detail(), "client.tier2.connection.read_value"), nullptr);
  EXPECT_NE(find_link_by_source(minimal.error_detail(), wireMarkerSource), nullptr);

  const auto standard = client.connection(1).try_read_value_sync(readNode);
  ASSERT_TRUE(standard.is_bad());
  ASSERT_NE(standard.error_detail(), nullptr);
  EXPECT_EQ(standard.error_detail()->source, "client.tier2.connection.read_value");
  ASSERT_NE(standard.error_detail()->cause, nullptr);
  EXPECT_EQ(standard.error_detail()->cause->source, "client.tier1.connection.read");
  EXPECT_NE(find_link_by_source(standard.error_detail(), wireMarkerSource), nullptr);

  const auto verbose = client.connection(2).try_read_value_sync(readNode);
  ASSERT_TRUE(verbose.is_bad());
  ASSERT_NE(verbose.error_detail(), nullptr);
  const auto namespaceUri = std::ranges::find_if(
    verbose.error_detail()->context, [](const NamedValue& fact) { return fact.key == "namespace.uri"; });
  ASSERT_NE(namespaceUri, verbose.error_detail()->context.end());
  EXPECT_EQ(namespaceUri->value, "http://opcfoundation.org/UA/");
}

// =============================================================================================
// ClientDiagnostics.OutboundRequestCarriesConfiguredReturnDiagnosticsMask
// defaultReturnDiagnostics=0x000000FF must reach the server VERBATIM on RequestHeader.returnDiagnostics.
// The client stamps the configured default onto every request whose returnDiagnostics is still 0
// (typed_request_async, ua_session_service_helpers.h:29-31), so a managed Read carries 0x000000FF onto the
// wire. Falsified if the SDK rewrites/zeros the mask or applies a different value.
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, OutboundRequestCarriesConfiguredReturnDiagnosticsMask)
{
  constexpr uint32_t mask = 0x000000FFu;

  ClientConfig config;
  config.defaultReturnDiagnostics = mask;

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  auto captured = std::make_shared<std::atomic<uint32_t>>(0xDEADBEEFu);
  auto sawRead = std::make_shared<std::atomic<bool>>(false);
  install_read_mask_capture(server, armed, captured, sawRead);

  DiagConnection connection{server, config};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed: 0x" << std::hex << connection.start_status().status_code().as_uint32();
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_good()) << "the real server read must succeed, got 0x" << std::hex
                                << result.status_code().as_uint32();

  ASSERT_TRUE(sawRead->load(std::memory_order_acquire))
    << "the ReadRequest must be observable on the wire so its returnDiagnostics can be pinned";
  EXPECT_EQ(captured->load(std::memory_order_acquire), mask)
    << "the configured defaultReturnDiagnostics must be stamped VERBATIM onto the outbound RequestHeader";
}

// =============================================================================================
// ClientDiagnostics.ZeroMaskWhenDiagnosticsDisabled
// Default config (defaultReturnDiagnostics=0): RequestHeader.returnDiagnostics must be EXACTLY 0x00000000.
// The SDK must not 'helpfully' request diagnostics the application did not ask for.
// [neg: disabled mask must be exactly zero]
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, ZeroMaskWhenDiagnosticsDisabled)
{
  ClientConfig config;  // defaultReturnDiagnostics defaults to 0

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  auto captured = std::make_shared<std::atomic<uint32_t>>(0xDEADBEEFu);
  auto sawRead = std::make_shared<std::atomic<bool>>(false);
  install_read_mask_capture(server, armed, captured, sawRead);

  DiagConnection connection{server, config};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_good()) << "the real server read must succeed, got 0x" << std::hex
                                << result.status_code().as_uint32();

  ASSERT_TRUE(sawRead->load(std::memory_order_acquire)) << "the ReadRequest must be observable on the wire";
  EXPECT_EQ(captured->load(std::memory_order_acquire), 0x00000000u)
    << "a disabled diagnostics config must put EXACTLY zero on returnDiagnostics, got 0x" << std::hex
    << captured->load(std::memory_order_acquire);
}

// =============================================================================================
// ClientDiagnostics.BadResponseServiceDiagnosticsSurfacedViaErrorChain
// A ServiceFault with non-empty serviceDiagnostics (symbolicId, namespaceUri, localizedText,
// additionalInfo, innerStatusCode) resolved against a stringTable must surface, through
// Result<T>.status_code().shared_detail(), a decoded ErrorDetail chain with RESOLVED strings - never
// dropped and never delivered as raw stringTable indexes. ErrorDetail propagation is priority #1: this row
// asserts the FULL decoded chain (SymbolicId / localizedText / additionalInfo / innerStatusCode).
// [neg: DiagnosticInfo dropped or delivered as raw stringTable indexes]
//
// DOCUMENTED BUILT-VS-UNBUILT GAP: the matrix oracle also expects `on_error_chain` to fire with the same
// chain. Grep of the implementation shows on_error_chain is wired ONLY on the reconnect-terminal FSM path
// (ua_connection_impl.cpp:2789), NOT on a per-op ServiceFault. This row therefore pins the REAL behaviour:
// the surfaced Result chain IS the delivered diagnostic; no observer fires per-op. Asserting 0 here flips
// the test the moment a future wiring lights the observer up, forcing this gap to be revisited.
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, BadResponseServiceDiagnosticsSurfacedViaErrorChain)
{
  const std::vector<std::string> stringTable = {
    "AccessDeniedByPolicy", "urn:acme:diag", "The write was denied by the server policy"};
  const StatusCode serviceResult{Status::BadUserAccessDenied};
  const StatusCode innerStatus{Status::BadSecurityChecksFailed};
  const std::string additionalInfo = "valve override active";

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_service_fault_injector(server,
    armed,
    [&]
    {
      auto diagnostic = make_diagnostic(/*symbolicIdx=*/0,
        /*namespaceIdx=*/1,
        /*localizedTextIdx=*/2,
        /*additionalInfo=*/additionalInfo,
        /*innerStatus=*/innerStatus);
      return make_service_fault(serviceResult, std::move(diagnostic), stringTable);
    });

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  DiagConnection connection{server, ClientConfig{}, ObserverSlots{.connection = observer}};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "a ServiceFault must surface as a bad Result";
  EXPECT_EQ(result.status_code().as_status(), Status::BadUserAccessDenied)
    << "the terminal status must be the ServiceFault's serviceResult, got 0x" << std::hex
    << result.status_code().as_uint32();

  const ErrorDetail* head = result.error_detail();
  ASSERT_NE(head, nullptr) << "a decoded ServiceFault must carry an ErrorDetail chain";

  // The always-on wire-crossing marker records the terminal service status (CL-DIAG-005).
  const ErrorDetail* marker = find_link_by_source(head, wireMarkerSource);
  ASSERT_NE(marker, nullptr) << "the decoded chain must carry the wire-crossing marker";
  EXPECT_EQ(marker->innerStatus, serviceResult.value())
    << "the marker must record the terminal service status";

  // Priority #1: the decoded server link carries every resolved field, NOT raw indexes.
  const ErrorDetail* serverLink = find_link_by_code(head, "server.symbolic.AccessDeniedByPolicy");
  ASSERT_NE(serverLink, nullptr)
    << "the SymbolicId must be resolved + `server.symbolic.`-prefixed, never a raw index";
  EXPECT_EQ(serverLink->summary, "The write was denied by the server policy")
    << "the localizedText index must be resolved into the summary";
  EXPECT_EQ(serverLink->source, "urn:acme:diag") << "the namespaceUri index must be resolved into the source";
  EXPECT_EQ(serverLink->detail, additionalInfo)
    << "the additionalInfo must be carried through as the extended detail";
  EXPECT_EQ(serverLink->innerStatus, innerStatus.value())
    << "the innerStatusCode must be carried onto the decoded link";

  // DOCUMENTED GAP: on_error_chain is reconnect-terminal-only; it does NOT fire on a per-op ServiceFault.
  EXPECT_EQ(observer->error_chain_fires(), 0)
    << "REAL behaviour: the matrix observer-half is unbuilt for per-op faults; the Result chain is the "
       "delivered diagnostic. A future per-op wiring would flip this and force a revisit";
  EXPECT_EQ(observer->advisory_fires(), 0) << "a hard fault must not surface as an advisory diagnostic";
}

// =============================================================================================
// CL-DIAG-012 - the ClientDiagnosticPolicy.emitOnErrorChainObserver gate, end-to-end over the real funnel.
// A Case-2 response (transport-good ReadResponse with a bad serviceResult + serviceDiagnostics) reaches the
// funnel's surface_response_diagnostics: with emit ENABLED (the default) on_error_chain fires with the
// decoded chain; with emit DISABLED the observer is a strict no-op, yet the always-on CL-DIAG-005 Result
// marker still records the wire boundary (the two are independent). Only a MisbehavingServer can produce
// Case-2 (real servers send ServiceFaults, Case-1, which the secure channel handles before the funnel
// observer).
// =============================================================================================

namespace
{
DiagnosticInfo make_case2_diagnostic()
{
  // symbolicId index 0 -> "AccessDeniedByPolicy"; localizedText index 1 -> the message.
  return make_diagnostic(/*symbolicIdx=*/0,
    /*namespaceIdx=*/std::nullopt,
    /*localizedTextIdx=*/1,
    /*additionalInfo=*/std::nullopt,
    /*innerStatus=*/std::nullopt);
}

const std::vector<std::string> case2StringTable = {"AccessDeniedByPolicy", "denied by server policy"};
}  // namespace

// @verifies CL-DIAG-012
// @relation(CL-DIAG-012, scope=function)
TEST(ClientDiagnostics, ErrorChainObserverFiresOnBadServiceResultWhenPolicyEnabled)
{
  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_case2_read_diagnostics_injector(
    server, armed, StatusCode{Status::BadUserAccessDenied}, make_case2_diagnostic, case2StringTable);

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  ClientConfig clientConfig;
  clientConfig.defaultReturnDiagnostics = 0x3FF;  // request diagnostics so the server (mutator) attaches them
  // Default policy: emitOnErrorChainObserver = true.
  DiagConnection connection{server, clientConfig, ObserverSlots{.connection = observer}};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "the bad serviceResult must collapse the Result (CL-DIAG-005)";

  for (int attempt = 0; attempt < 200 && observer->error_chain_fires() < 1; ++attempt)
  {
    std::this_thread::sleep_for(
      10ms);  // the observer fires on the delivery strand after the sync read returns
  }
  EXPECT_EQ(observer->error_chain_fires(), 1)
    << "emitOnErrorChainObserver=true (default) must fire on_error_chain on the general-surface funnel";
  EXPECT_EQ(observer->advisory_fires(), 0) << "a bad serviceResult is an error chain, not an advisory";
}

// @verifies CL-DIAG-012
// @relation(CL-DIAG-012, scope=function)
TEST(ClientDiagnostics, ErrorChainObserverSuppressedWhenPolicyDisablesEmit)
{
  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_case2_read_diagnostics_injector(
    server, armed, StatusCode{Status::BadUserAccessDenied}, make_case2_diagnostic, case2StringTable);

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  ClientConfig clientConfig;
  clientConfig.defaultReturnDiagnostics = 0x3FF;
  ua::client::ClientDiagnosticPolicy policy;
  policy.emitOnErrorChainObserver = false;  // the gate under test
  DiagConnection connection{server, clientConfig, ObserverSlots{.connection = observer}, policy};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad());

  // The always-on CL-DIAG-005 Result marker is independent of the observer gate - it is STILL attached.
  const ErrorDetail* head = result.error_detail();
  ASSERT_NE(head, nullptr);
  EXPECT_NE(find_link_by_source(head, wireMarkerSource), nullptr)
    << "disabling the observer must NOT suppress the always-on Result marker";

  std::this_thread::sleep_for(100ms);  // give any erroneous observer fire time to reach the delivery strand
  EXPECT_EQ(observer->error_chain_fires(), 0)
    << "emitOnErrorChainObserver=false must suppress on_error_chain end-to-end";
  EXPECT_EQ(observer->advisory_fires(), 0);
}

// @verifies CL-DIAG-007
// End-to-end over the WIRED tier-1 funnel (Case-2: a bad serviceResult on a normal ReadResponse reaches
// invoke_wire_op + surface_response_diagnostics, which now pass the Connection's NamespaceTable snapshot): a
// server DiagnosticInfo carrying a NamespaceURI KNOWN to the client's bootstrapped NamespaceArray decodes to
// source `server.namespace.<uri>`; an UNKNOWN URI decodes to `server.unknown.<uri>` (literal, preserved). A
// broken wiring records the raw URI (no prefix), so a consumer classifying by the prefix misclassifies it.
// @relation(CL-DIAG-007, scope=function)
TEST(ClientDiagnostics, NamespaceUriDecodedToPrefixedSourceOnBadServiceResult)
{
  MisbehavingServer server;
  ClientConfig clientConfig;
  clientConfig.defaultReturnDiagnostics = 0x3FF;  // ask the server (mutator) to attach diagnostics
  DiagConnection connection{server, clientConfig};
  ASSERT_TRUE(connection.start_status().is_good());

  // The known URI must be one the client actually bootstrapped; read it back from the live snapshot.
  auto table = connection->namespace_table();
  ASSERT_NE(table, nullptr) << "the bootstrap must publish a NamespaceTable snapshot";
  const std::string knownUri{*table->lookup_uri(static_cast<ua::client::NamespaceIndex>(table->size() - 1))};
  const std::string unknownUri = "urn:vendor:namespace-absent-from-this-server";

  // Runs one armed Case-2 read whose serviceDiagnostics carries @p namespaceUri, and returns the decoded
  // server link's source (the link just beneath the wire-crossing marker).
  auto sourceFor = [&](const std::string& namespaceUri) -> std::string
  {
    auto armed = std::make_shared<std::atomic<bool>>(false);
    install_case2_read_diagnostics_injector(
      server,
      armed,
      StatusCode{Status::BadUserAccessDenied},
      []
      {
        return make_diagnostic(
          /*symbolicIdx=*/0, /*namespaceIdx=*/1, std::nullopt, std::nullopt, std::nullopt);
      },
      std::vector<std::string>{"AccessDenied", namespaceUri});
    armed->store(true, std::memory_order_release);
    auto result = connection->try_read_value_sync(readNode);
    EXPECT_TRUE(result.is_bad()) << "the bad serviceResult must collapse the Result (CL-DIAG-005)";
    armed->store(false, std::memory_order_release);  // disarm so later reads are unaffected
    const ErrorDetail* head = result.error_detail();
    if (head == nullptr)
      return "<no chain>";
    const ErrorDetail* serverLink = find_link_by_code(head, "server.symbolic.AccessDenied");
    return serverLink != nullptr ? serverLink->source : std::string{"<no server link>"};
  };

  EXPECT_EQ(sourceFor(knownUri), "server.namespace." + knownUri)
    << "a NamespaceURI known to the client's NamespaceArray must be recorded with the server.namespace. "
       "prefix";
  EXPECT_EQ(sourceFor(unknownUri), "server.unknown." + unknownUri)
    << "an unknown NamespaceURI must be recorded literally with the server.unknown. prefix";
}

// =============================================================================================
// ClientDiagnostics.NestedInnerDiagnosticInfoDecodedRecursively
// A ServiceFault whose serviceDiagnostics nests innerDiagnosticInfo 3 levels deep must decode into an
// ErrorDetail.cause() chain mirroring ALL 3 levels - recursion must neither stop early (chain shorter than
// 3) nor overflow (a runaway chain / a spurious CHAIN_TRUNCATED sentinel below the 32-level cap).
// [neg: 3-level nested inner diagnostics]
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, NestedInnerDiagnosticInfoDecodedRecursively)
{
  const std::vector<std::string> stringTable = {"L1", "L2", "L3"};
  const StatusCode l1Status{Status::BadUserAccessDenied};
  const StatusCode l2Status{Status::BadSecurityChecksFailed};
  const StatusCode l3Status{Status::BadNodeIdUnknown};

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_service_fault_injector(server,
    armed,
    [&]
    {
      DiagnosticInfo level1 = make_diagnostic(/*symbolicIdx=*/0,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        /*innerStatus=*/l1Status);
      DiagnosticInfo level2 = make_diagnostic(/*symbolicIdx=*/1,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        /*innerStatus=*/l2Status);
      DiagnosticInfo level3 = make_diagnostic(/*symbolicIdx=*/2,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        /*innerStatus=*/l3Status);
      level2.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>(std::move(level3));
      level1.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>(std::move(level2));
      return make_service_fault(StatusCode{Status::BadInternalError}, std::move(level1), stringTable);
    });

  DiagConnection connection{server, ClientConfig{}};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad());
  const ErrorDetail* head = result.error_detail();
  ASSERT_NE(head, nullptr);

  // Level 1 of the decoded server chain.
  const ErrorDetail* level1 = find_link_by_code(head, "server.symbolic.L1");
  ASSERT_NE(level1, nullptr) << "the outermost server diagnostic (L1) must decode";
  EXPECT_EQ(level1->innerStatus, l1Status.value());

  // Level 2 is L1's cause.
  const ErrorDetail* level2 = level1->cause.get();
  ASSERT_NE(level2, nullptr) << "recursion must not stop early: L2 must hang off L1";
  EXPECT_EQ(level2->code, "server.symbolic.L2");
  EXPECT_EQ(level2->innerStatus, l2Status.value());

  // Level 3 is L2's cause.
  const ErrorDetail* level3 = level2->cause.get();
  ASSERT_NE(level3, nullptr) << "recursion must not stop early: L3 must hang off L2";
  EXPECT_EQ(level3->code, "server.symbolic.L3");
  EXPECT_EQ(level3->innerStatus, l3Status.value());

  // Recursion must terminate exactly at 3 - no 4th server level, no truncation sentinel (depth < cap).
  EXPECT_EQ(level3->cause.get(), nullptr)
    << "the decoded server chain must terminate at exactly 3 levels (no overflow)";
  EXPECT_EQ(find_link_by_code(head, "CHAIN_TRUNCATED"), nullptr)
    << "a 3-level chain is far below the 32-level cap and must NOT be truncated";

  // The whole surfaced chain is finite and small (outer ServiceFault + marker + 3 server levels).
  EXPECT_LE(ErrorChainView{result.status_code()}.depth(), std::size_t{8})
    << "the surfaced chain must be bounded, not a runaway recursion";
}

// =============================================================================================
// ClientDiagnostics.MinusOneStringIndexesHandledDefensively
// A ServiceFault whose serviceDiagnostics sets every string-index field to -1 (present-but-unspecified)
// against an EMPTY stringTable must NOT crash / deref the table out of range, and must still surface a
// bad Result whose non-string fields (innerStatusCode) decode. [neg: -1 (unspecified) string indexes]
//
// CALIBRATION: the matrix intent is "empty string fields". REAL behaviour: resolve_string's `i < 0` guard
// fires (so there is NO out-of-range access - the falsifier is refuted) but returns the placeholder
// "<unknown:-1>" rather than an empty string. This row LOCKS the real placeholder behaviour and reports
// the placeholder-vs-empty divergence as a candidate spec refinement (OPC UA Part 4: -1 == "not specified").
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, MinusOneStringIndexesHandledDefensively)
{
  const std::vector<std::string> emptyStringTable = {};  // no strings -> every index is unresolvable
  const StatusCode innerStatus{Status::BadUserAccessDenied};

  MisbehavingServer server;
  auto armed = std::make_shared<std::atomic<bool>>(false);
  install_service_fault_injector(server,
    armed,
    [&]
    {
      auto diagnostic = make_diagnostic(/*symbolicIdx=*/-1,
        /*namespaceIdx=*/-1,
        /*localizedTextIdx=*/-1,
        /*additionalInfo=*/std::nullopt,
        /*innerStatus=*/innerStatus);
      return make_service_fault(
        StatusCode{Status::BadInternalError}, std::move(diagnostic), emptyStringTable);
    });

  DiagConnection connection{server, ClientConfig{}};
  ASSERT_TRUE(connection.start_status().is_good());
  armed->store(true, std::memory_order_release);

  // Reaching here at all proves the -1 indexes did not crash the client on the stringTable lookup.
  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_bad()) << "the -1-index ServiceFault must surface as a bad Result (no crash)";
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);

  const ErrorDetail* head = result.error_detail();
  ASSERT_NE(head, nullptr);

  // The decode ran (marker present) and the non-string field decoded despite the -1 indexes.
  const ErrorDetail* marker = find_link_by_source(head, wireMarkerSource);
  ASSERT_NE(marker, nullptr);
  const ErrorDetail* serverLink = marker->cause.get();
  ASSERT_NE(serverLink, nullptr) << "the server diagnostic must still decode with -1 string indexes";
  EXPECT_EQ(serverLink->innerStatus, innerStatus.value())
    << "the innerStatusCode must decode even when every string index is -1";

  // CALIBRATION: -1 surfaces as the "<unknown:-1>" placeholder (the `i < 0` guard fired - no OOB deref),
  // NOT the empty string the matrix intent describes. Locking the real behaviour.
  EXPECT_EQ(serverLink->source, "<unknown:-1>")
    << "REAL behaviour: a -1 namespaceUri index resolves to the <unknown:-1> placeholder, proving the "
       "defensive guard fired rather than dereferencing the table";
  EXPECT_EQ(serverLink->code, "server.symbolic.<unknown:-1>")
    << "REAL behaviour: a -1 symbolicId index resolves to the <unknown:-1> placeholder under the prefix";
}

// =============================================================================================
// ClientDiagnostics.EmptyDiagnosticInfoFiresNoObserver
// A GOOD result with empty serviceDiagnostics (a normal server read) must fire NEITHER on_advisory_diagnostic
// NOR on_error_chain. Falsified if an observer spuriously fires on empty diagnostics.
// [neg: empty diagnostics -> no observer]
//
// The observer is installed at construction (ConnectionConfig.observers), so it is genuinely in the sink's
// slots - on_connected firing during bootstrap proves the wiring, making the "0 diagnostic fires" assertion
// non-vacuous.
// =============================================================================================
// @verifies CL-BASEDIAG-001
// @relation(CL-BASEDIAG-001, scope=function)
TEST(ClientDiagnostics, EmptyDiagnosticInfoFiresNoObserver)
{
  MisbehavingServer server;  // no mutator: the server returns good reads with empty diagnostics

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  DiagConnection connection{server, ClientConfig{}, ObserverSlots{.connection = observer}};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->try_read_value_sync(readNode);
  ASSERT_TRUE(result.is_good()) << "a normal read must succeed with empty diagnostics, got 0x" << std::hex
                                << result.status_code().as_uint32();

  // Wiring proof (non-vacuity): the observer received the bootstrap on_connected, so the sink genuinely
  // delivers to it - a spurious diagnostic fire WOULD be caught below.
  observer->await_connected();
  EXPECT_GE(observer->connected_fires(), 1)
    << "the observer must be wired into the sink (on_connected delivered during bootstrap)";

  EXPECT_EQ(observer->error_chain_fires(), 0) << "a good empty-diagnostics read must NOT fire on_error_chain";
  EXPECT_EQ(observer->advisory_fires(), 0)
    << "a good empty-diagnostics read must NOT fire on_advisory_diagnostic";
}

// =============================================================================================
// ClientDiagnostics.OutboundRequestCarriesConfiguredServiceTimeoutAsTimeoutHint
// defaultServiceTimeout must reach the server on RequestHeader.timeoutHint, not just bound the
// request locally. Part 4 7.33 defines the hint as the Client telling the Server how long it will
// wait, and 0 as "no timeout" - so a client that enforces a deadline while sending 0 leaves the
// Server completing work nobody is waiting for.
//
// Two configured values are asserted so the row cannot pass against a hardcoded constant, and the
// per-request override is asserted alongside so the defaulting cannot be an unconditional stamp.
// =============================================================================================
TEST(ClientDiagnostics, OutboundRequestCarriesConfiguredServiceTimeoutAsTimeoutHint)
{
  const auto captureHint = [](std::chrono::milliseconds configured, uint32_t requestOverride)
  {
    ClientConfig config;
    config.defaultServiceTimeout = configured;

    MisbehavingServer server;
    auto armed = std::make_shared<std::atomic<bool>>(false);
    auto captured = std::make_shared<std::atomic<uint32_t>>(0xDEADBEEFu);
    auto sawRead = std::make_shared<std::atomic<bool>>(false);
    server.set_request_observer(
      [armed, captured, sawRead](const ua::Structure& request)
      {
        if (!armed->load(std::memory_order_acquire))
        {
          return;
        }
        if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
        {
          captured->store(read->request_header().timeout_hint(), std::memory_order_release);
          sawRead->store(true, std::memory_order_release);
        }
      });

    Tier0DiagSession client{server, /*wrapTier0=*/false, std::move(config)};
    armed->store(true, std::memory_order_release);

    ua::ReadRequest request = ReadRequestBuilder().read(readNode).attribute(AttributeId::Value);
    request.request_header().timeout_hint() = requestOverride;
    (void)client.session().attributes().try_read_sync(std::move(request));

    EXPECT_TRUE(sawRead->load(std::memory_order_acquire))
      << "the ReadRequest must be observable on the wire so its timeoutHint can be pinned";
    return captured->load(std::memory_order_acquire);
  };

  // Two distinct configured values, so a constant cannot satisfy both.
  EXPECT_EQ(captureHint(std::chrono::seconds{7}, 0), 7000u)
    << "an unset timeoutHint must carry the configured defaultServiceTimeout";
  EXPECT_EQ(captureHint(std::chrono::seconds{23}, 0), 23000u)
    << "the hint must track the configuration, not a compiled-in constant";

  // A caller who set the hint keeps it: the default fills a gap, it does not overwrite intent.
  EXPECT_EQ(captureHint(std::chrono::seconds{7}, 1234u), 1234u)
    << "an explicit per-request timeoutHint must survive the defaulting";
}

// =============================================================================================
// ClientDiagnostics.SessionlessAndLifecycleRequestsAlsoCarryTheConfiguredTimeoutHint
// The session-service path is not the only one that reaches a peer. Session-less services
// (GetEndpoints) have no Session to resolve the hint for them, and the session LIFECYCLE requests
// (CreateSession) are sent before the Session exists. Both resolve it from the channel instead, so
// the rule is uniform: every outbound request carries the deadline that bounds it.
// =============================================================================================
TEST(ClientDiagnostics, SessionlessAndLifecycleRequestsAlsoCarryTheConfiguredTimeoutHint)
{
  constexpr uint32_t configuredMs = 9000u;

  ClientConfig config;
  config.defaultServiceTimeout = std::chrono::milliseconds{configuredMs};

  MisbehavingServer server;
  auto sawGetEndpoints = std::make_shared<std::atomic<uint32_t>>(0xDEADBEEFu);
  auto sawCreateSession = std::make_shared<std::atomic<uint32_t>>(0xDEADBEEFu);
  server.set_request_observer(
    [sawGetEndpoints, sawCreateSession](const ua::Structure& request)
    {
      if (const auto* ep = dynamic_cast<const ua::GetEndpointsRequest*>(&request))
      {
        sawGetEndpoints->store(ep->request_header().timeout_hint(), std::memory_order_release);
      }
      if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
      {
        sawCreateSession->store(create->request_header().timeout_hint(), std::memory_order_release);
      }
    });

  // Opening a channel and creating a session drives both request types.
  Tier0DiagSession client{server, /*wrapTier0=*/false, config};

  ua::GetEndpointsRequest endpointsRequest;
  endpointsRequest.endpoint_url() = server.endpoint_url_none();
  (void)client.channel().try_get_endpoints_sync(std::move(endpointsRequest));

  EXPECT_EQ(sawGetEndpoints->load(std::memory_order_acquire), configuredMs)
    << "a session-less GetEndpoints must carry the configured timeoutHint";
  EXPECT_EQ(sawCreateSession->load(std::memory_order_acquire), configuredMs)
    << "CreateSession is sent before the Session exists, so the channel must resolve its hint";
}

// =============================================================================================
// The EnabledFlag gate over the three diagnostic-array reads (CL-BASEDIAG-003).
// =============================================================================================

namespace
{
// Bridges one async diagnostic-array read onto the test thread. Every call site builds a THROWAWAY
// `connection->server_diagnostics()` accessor, whose EnabledFlag TTL cache starts empty, so each read
// genuinely re-reads the flag from the server rather than reusing an earlier decision.
template<typename ArrayResult, typename Issue>
ArrayResult await_diagnostic_array(Issue issue)
{
  std::promise<ArrayResult> promise;
  auto future = promise.get_future();
  issue([&promise](ArrayResult result) { promise.set_value(std::move(result)); });
  return future.get();
}
}  // namespace

// Part 5 6.3.3: EnabledFlag=false means the diagnostic Variables may hold STALE or zero values, so the three
// array reads (SessionDiagnosticsArray, SubscriptionDiagnosticsArray, SamplingIntervalDiagnosticsArray) must
// still deliver their data AND mark it as not-meaningful via on_advisory_diagnostic; with the flag true they
// read normally and nothing is advised. A plausible implementation reads the arrays unconditionally, so the
// caller reports counters that stopped moving at an unknown time as if they were live - worse than reporting
// nothing, because the values are plausible rather than obviously empty.
//
// MisbehavingServer explicitly maps its anonymous test identity to SecurityAdmin, so the ordinary NS0
// RolePermissions policy permits all three diagnostic-array Reads. Requiring Good in both phases proves that
// the client does not turn EnabledFlag=false into an access refusal or discard the still-readable data.
// Nothing here obliges an array to be non-empty - "read normally" is about the call completing as an ordinary
// read, not about what the server chose to populate.
// @verifies AC-CL-BASEDIAG-003-ENABLEDFLAG
TEST(ClientDiagnostics, DiagnosticArrayReadsHonourTheServerEnabledFlag)
{
  MisbehavingServer server;

  // The antecedent is the SERVER's EnabledFlag value, never a client-side flag set by fiat: each array read
  // batches [array, EnabledFlag] into one Read, so rewriting the SECOND DataValue is exactly "the server
  // reports diagnostics disabled". Matching on the Boolean type pins the flag slot so no other Read is hit,
  // and the rewrite is counted so the disabled antecedent can be proven to have reached the client.
  auto forceDisabled = std::make_shared<std::atomic<bool>>(false);
  auto flagRewrites = std::make_shared<std::atomic<int>>(0);
  server.set_response_mutator(
    [forceDisabled, flagRewrites](ua::Response& response)
    {
      if (!forceDisabled->load(std::memory_order_acquire))
      {
        return;
      }
      auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
      if (read == nullptr || read->results().size() != 2U || !read->results()[1].value().is_boolean())
      {
        return;
      }
      read->results()[1].value() = ua::Variant{false};
      flagRewrites->fetch_add(1, std::memory_order_acq_rel);
    });

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  DiagConnection connection{server, ClientConfig{}, ObserverSlots{.connection = observer}};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed: 0x" << std::hex << connection.start_status().status_code().as_uint32();

  // Wiring proof (non-vacuity): the observer received the bootstrap on_connected, so a missing advisory below
  // is a missing advisory and not a disconnected sink.
  observer->await_connected();
  EXPECT_GE(observer->connected_fires(), 1)
    << "the observer must be wired into the sink (on_connected delivered during bootstrap)";

  // --- EnabledFlag TRUE (the server's own live value): the three arrays read normally. ---
  const auto sessionsEnabled = await_diagnostic_array<SessionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sessions_async(std::move(callback)); });
  ASSERT_TRUE(sessionsEnabled.is_good())
    << "SessionDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << sessionsEnabled.status_code().as_uint32();

  const auto subscriptionsEnabled = await_diagnostic_array<SubscriptionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().subscriptions_async(std::move(callback)); });
  ASSERT_TRUE(subscriptionsEnabled.is_good())
    << "SubscriptionDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << subscriptionsEnabled.status_code().as_uint32();

  const auto samplingEnabled = await_diagnostic_array<SamplingIntervalDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sampling_intervals_async(std::move(callback)); });
  ASSERT_TRUE(samplingEnabled.is_good())
    << "SamplingIntervalDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << samplingEnabled.status_code().as_uint32();

  std::this_thread::sleep_for(100ms);  // let any spurious advisory reach the delivery strand before asserting
  EXPECT_EQ(observer->advisory_fires(), 0)
    << "an enabled server must not mark its diagnostic arrays as possibly stale";

  // --- EnabledFlag FALSE: the data still arrives AND it is marked as not meaningful. ---
  forceDisabled->store(true, std::memory_order_release);

  const auto sessionsDisabled = await_diagnostic_array<SessionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sessions_async(std::move(callback)); });
  EXPECT_TRUE(sessionsDisabled.is_good())
    << "a disabled server still delivers the SessionDiagnosticsArray, got 0x" << std::hex
    << sessionsDisabled.status_code().as_uint32();

  const auto subscriptionsDisabled = await_diagnostic_array<SubscriptionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().subscriptions_async(std::move(callback)); });
  EXPECT_TRUE(subscriptionsDisabled.is_good())
    << "a disabled server still delivers the SubscriptionDiagnosticsArray, got 0x" << std::hex
    << subscriptionsDisabled.status_code().as_uint32();

  const auto samplingDisabled = await_diagnostic_array<SamplingIntervalDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sampling_intervals_async(std::move(callback)); });
  EXPECT_TRUE(samplingDisabled.is_good())
    << "a disabled server still delivers the SamplingIntervalDiagnosticsArray, got 0x" << std::hex
    << samplingDisabled.status_code().as_uint32();

  // Falsifiability: the disabled antecedent must actually have crossed the wire on every one of the three
  // reads, otherwise a zero advisory count below would prove nothing.
  ASSERT_GE(flagRewrites->load(std::memory_order_acquire), 3)
    << "each of the three array reads must batch an EnabledFlag Read that the server answered false";

  for (int attempt = 0; attempt < 200 && observer->advisory_fires() < 1; ++attempt)
  {
    std::this_thread::sleep_for(10ms);  // the advisory is delivered on the sink's delivery strand
  }
  EXPECT_GE(observer->advisory_fires(), 1)
    << "EnabledFlag=false must surface on_advisory_diagnostic so the caller knows the counters may be stale "
       "rather than live";
}

// Part 5 6.3.3 + CL-BASEDIAG-003: `Server.ServerDiagnostics.EnabledFlag` false means the diagnostic
// Variables hold values that stopped moving at an unknown time. The client's contract is therefore a
// CONJUNCTION - the three array reads still complete and hand the caller the data (a disabled server is not a
// blocked call), AND the caller is told the data is no longer meaningful via `on_advisory_diagnostic`. A
// plausible implementation reads the arrays unconditionally, or "helpfully" refuses them; the first reports
// stale counters as live (worse than reporting nothing, because plausible numbers are believed), the second
// throws away data the spec says to deliver.
//
// The antecedent is never asserted by fiat and never manufactured by a mutator: the flag is flipped through
// the PUBLIC client mutator `set_enabled_flag_async`, which drives the server's real EnabledFlag Write
// handler, and both the true and the false state are then READ BACK off the server through the ordinary
// value-read path before the arrays are exercised. Without that read-back the "enabled" half would merely
// assume the server's starting state.
//
// MisbehavingServer explicitly maps this anonymous test identity to SecurityAdmin. Its ordinary NS0
// RolePermissions therefore permit SessionDiagnosticsArray, and Good is pinned in BOTH phases: the test
// proves that EnabledFlag changes only the meaningfulness advisory and never suppresses readable data.
// @verifies AC-CL-BASEDIAG-003-ENABLEDFLAG
TEST(ClientDiagnostics, DisablingServerDiagnosticsStillDeliversTheArraysButMarksThemNotMeaningful)
{
  MisbehavingServer server;  // no response mutator: every value below is the real server's own

  auto observer = std::make_shared<DiagnosticCountingObserver>();
  DiagConnection connection{server, ClientConfig{}, ObserverSlots{.connection = observer}};
  ASSERT_TRUE(connection.start_status().is_good())
    << "bootstrap must succeed: 0x" << std::hex << connection.start_status().status_code().as_uint32();

  // Wiring proof (non-vacuity): the observer received the bootstrap on_connected, so the zero-advisory
  // assertion in the enabled phase is a real observation and not a disconnected sink.
  observer->await_connected();
  EXPECT_GE(observer->connected_fires(), 1)
    << "the observer must be wired into the sink (on_connected delivered during bootstrap)";

  const NodeId enabledFlagNode{VariableId::Server_ServerDiagnostics_EnabledFlag};

  // --- Antecedent 1: the server reports diagnostics ENABLED (read back, not assumed). ---
  const auto flagBefore = connection->try_read_value_sync<bool>(enabledFlagNode);
  ASSERT_TRUE(flagBefore.is_good()) << "EnabledFlag must be readable to establish the antecedent, got 0x"
                                    << std::hex << flagBefore.status_code().as_uint32();
  ASSERT_TRUE(flagBefore.value()) << "this phase only tests the enabled branch if the server reports true";

  const auto sessionsEnabled = await_diagnostic_array<SessionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sessions_async(std::move(callback)); });
  ASSERT_TRUE(sessionsEnabled.is_good())
    << "SessionDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << sessionsEnabled.status_code().as_uint32();

  const auto subscriptionsEnabled = await_diagnostic_array<SubscriptionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().subscriptions_async(std::move(callback)); });
  EXPECT_TRUE(subscriptionsEnabled.is_good())
    << "SubscriptionDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << subscriptionsEnabled.status_code().as_uint32();

  const auto samplingEnabled = await_diagnostic_array<SamplingIntervalDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sampling_intervals_async(std::move(callback)); });
  EXPECT_TRUE(samplingEnabled.is_good())
    << "SamplingIntervalDiagnosticsArray must read normally while diagnostics are enabled, got 0x" << std::hex
    << samplingEnabled.status_code().as_uint32();

  std::this_thread::sleep_for(100ms);  // let any spurious advisory reach the delivery strand before asserting
  EXPECT_EQ(observer->advisory_fires(), 0)
    << "an enabled server must not mark its diagnostic arrays as possibly stale";

  // --- Antecedent 2: disable diagnostics through the real public mutator + the server's Write handler. ---
  const auto write = await_diagnostic_array<ua::VoidResult>([&](auto callback)
    { connection->server_diagnostics().set_enabled_flag_async(false, std::move(callback)); });
  ASSERT_TRUE(write.is_good()) << "the EnabledFlag Write must land on the server so the disabled antecedent "
                                  "is the server's real state, got 0x"
                               << std::hex << write.status_code().as_uint32();

  const auto flagAfter = connection->try_read_value_sync<bool>(enabledFlagNode);
  ASSERT_TRUE(flagAfter.is_good()) << "EnabledFlag must still be readable after the Write, got 0x" << std::hex
                                   << flagAfter.status_code().as_uint32();
  ASSERT_FALSE(flagAfter.value())
    << "the server must actually report diagnostics disabled, otherwise the phase below proves nothing";

  // --- Conjunct 1: the data still arrives. A disabled server is not a blocked call. ---
  const auto sessionsDisabled = await_diagnostic_array<SessionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sessions_async(std::move(callback)); });
  EXPECT_TRUE(sessionsDisabled.is_good())
    << "a disabled server still delivers the SessionDiagnosticsArray, got 0x" << std::hex
    << sessionsDisabled.status_code().as_uint32();

  const auto subscriptionsDisabled = await_diagnostic_array<SubscriptionDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().subscriptions_async(std::move(callback)); });
  EXPECT_TRUE(subscriptionsDisabled.is_good())
    << "a disabled server still delivers the SubscriptionDiagnosticsArray, got 0x" << std::hex
    << subscriptionsDisabled.status_code().as_uint32();

  const auto samplingDisabled = await_diagnostic_array<SamplingIntervalDiagnosticsArrayResult>(
    [&](auto callback) { connection->server_diagnostics().sampling_intervals_async(std::move(callback)); });
  EXPECT_TRUE(samplingDisabled.is_good())
    << "a disabled server still delivers the SamplingIntervalDiagnosticsArray, got 0x" << std::hex
    << samplingDisabled.status_code().as_uint32();

  // --- Conjunct 2: and the caller is told the delivered data is not meaningful. ---
  for (int attempt = 0; attempt < 200 && observer->advisory_fires() < 1; ++attempt)
  {
    std::this_thread::sleep_for(10ms);  // the advisory is delivered on the sink's delivery strand
  }
  EXPECT_GE(observer->advisory_fires(), 1)
    << "EnabledFlag=false must surface on_advisory_diagnostic so the caller learns the counters may have "
       "stopped moving at an unknown time, rather than believing them live";
}
