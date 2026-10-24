// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Complex-value read / encoding-selection / complex-write clusters of the client integration-test
///        matrix (the `ClientReadComplex.*`,
///        `ClientReadEncoding.*` and `ClientWriteComplex.*` rows authored here).
///
/// These are END-TO-END integration tests of the TIER-2 managed accessor (`ua::client::Connection`) over a
/// real in-tree server, built by wrapping a real `ConnectionImpl` over an activated Session (no reconnect
/// wiring -> single-shot, no keep-alive; the same construction the ClientRead/ClientWrite slices use). The
/// adversarial rows stand up their own `MisbehavingServer` and inject malformed / mismatched
/// ExtensionObjects through the response mutator, or capture the outbound request through the request
/// observer.
///
/// STRUCTURAL REALITY (verified before authoring - see the authoring report). The client-observable
/// complex-value behaviour is a MIX of built and unbuilt paths:
///   - The client's `StructureFactory` IS seeded with every NS0 generated type (CoreClientImpl builds it via
///     `register_ua_data_types_with_factory`) and the decode path decodes with `factory.resolver()`, so a
///     NATIVE NS0 structure decodes IN-PLACE, synchronously, with NO Browse. (BUILT - GREEN rows.)
///   - The per-Connection `TypeResolver` (client design section 8.6) is STILL UNWIRED into the decode path
///     (unchanged from the ClientTypeResolver cluster's f2d0f2a8 finding: `type_resolver()` has no
///     functional consumer, `finish_resolution` installs a nullptr decoder, and the codec callsite does not
///     consult the `TypeDeferGate`). A VENDOR structure whose decoder is not pre-registered is therefore
///     NOT lazily resolved via Browse - it surfaces as an opaque `UnknownStructure` (raw bytes preserved).
///     The lazy-resolve / recursive-resolve rows pin that real opaque behaviour and REPORT the gap.
///   - ENCODING SELECTION is UNBUILT: the client never populates `ReadValueId.dataEncoding` (it defaults to
///     a null QualifiedName and relies on the server's session encoding), and it performs no
///     response-encoding validation. The encoding-selection rows pin what actually reaches the wire and
///     REPORT the divergence from the matrix oracle.
///   - A malformed BINARY body of a KNOWN encoding surfaces `Bad_DecodingError` at the wire boundary (the
///     decode throws, the channel fails the request - not a crash, not a silent partial decode). (BUILT.)
///
/// Falsifiability: every test encodes its matrix `[neg: ...]` falsifier. A codec that tolerated a
/// length-mismatched body would fail DecodeErrorsSurfaceBadDecodingError; a decode path that silently
/// discarded an unknown ExtensionObject would fail the vendor rows (they assert the bytes round-trip); a
/// client that fabricated an ExtensionObject tag for a simple type would fail SimpleTypeEncodedAsSuperType.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_browse_request.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_variable_node.h"
#include "ua_duration.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_state.h"
#include "ua_server_status_data_type.h"
#include "ua_status.h"
#include "ua_unknown_structure.h"
#include "ua_value_source.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <condition_variable>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring
// -> single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and
// closes gracefully on destruction. Same interface the ClientRead/ClientWrite slices use.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

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
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// MisbehavingComplexFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection. The
// bootstrap completes against the un-mutated server; the test arms the mutator / observer AFTER
// construction. Mirror of the ClientRead slice's MisbehavingReadFixture.
// ---------------------------------------------------------------------------------------------
class MisbehavingComplexFixture
{
public:
  explicit MisbehavingComplexFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientComplexMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingComplexFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingComplexFixture(const MisbehavingComplexFixture&) = delete;
  MisbehavingComplexFixture& operator=(const MisbehavingComplexFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

class CancelCountAdvisoryObserver final : public ConnectionObserver
{
public:
  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ErrorDetail> detail) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mDetail = std::move(detail);
    }
    mCondition.notify_all();
  }

  std::shared_ptr<const ErrorDetail> wait_for_advisory()
  {
    std::unique_lock<std::mutex> lock(mMutex);
    if (!mCondition.wait_for(lock, 5s, [this] { return mDetail != nullptr; }))
    {
      return {};
    }
    return mDetail;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::shared_ptr<const ErrorDetail> mDetail;
};

// ---------------------------------------------------------------------------------------------
// RequestCapture: mutex-guarded record of what the client actually put on the wire, populated by a
// MisbehavingServer request observer (runs on a server strand while the test thread reads). It records the
// `dataEncoding` QualifiedName of every ReadValueId and counts BrowseRequests (so a test can assert "no
// Browse was issued").
// ---------------------------------------------------------------------------------------------
struct RequestCapture
{
  mutable std::mutex mutex;
  std::vector<QualifiedName> readEncodings;
  uint64_t browseCount{0};

  void observe(const Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* read = dynamic_cast<const ReadRequest*>(&request))
    {
      for (const auto& nodeToRead : read->nodes_to_read())
        readEncodings.push_back(nodeToRead.data_encoding());
    }
    else if (dynamic_cast<const BrowseRequest*>(&request) != nullptr)
    {
      ++browseCount;
    }
  }

  std::vector<QualifiedName> encodings() const
  {
    std::lock_guard lock(mutex);
    return readEncodings;
  }

  uint64_t browses() const
  {
    std::lock_guard lock(mutex);
    return browseCount;
  }
};

// The aggregate ServerStatus Variable, whose Value is a native ServerStatusDataType structure - present on
// every server and decodable in-place by the client's NS0-seeded StructureFactory.
NodeId server_status_node()
{
  return NodeId{VariableId::Server_ServerStatus};
}

// A readable NS0 scalar Int32 node present on every server (the enum-backed ServerStatus State).
NodeId server_state_node()
{
  return NodeId{VariableId::Server_ServerStatus_State};
}

ByteString bytes(std::initializer_list<uint8_t> values)
{
  std::vector<byte> raw;
  raw.reserve(values.size());
  for (uint8_t value : values)
    raw.push_back(static_cast<byte>(value));
  return ByteString{std::move(raw)};
}

}  // namespace

// =============================================================================================
// Fixture: derives from ComplianceWithNodes so the normal-server rows have a populated address space and a
// Double-typed capture node; the MisbehavingServer rows ignore the fixture server and stand up their own.
// Three suite aliases keep the matrix names (ClientReadComplex / ClientReadEncoding / ClientWriteComplex).
// =============================================================================================
class ClientReadWriteComplex : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();

    // A Double-typed Variable used as the SimpleTypeEncodedAsSuperType write target (Duration is a simple
    // type whose super-type is Double). Created in the test namespace so install_write_capture can hook it.
    mDoubleCaptureId = NodeId{mTestNamespaceIndex, uint32_t{8500}};
    auto node = addressSpace.create_node_sync(mDoubleCaptureId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "DoubleCapture"});
    variable->set_display_name(LocalizedText{"", "DoubleCapture"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objects = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objects.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDoubleCaptureId);
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  // Installs a server-side write value handler on @p nodeId that records every decoded WriteValue the
  // client produced (the wire frame after the server decoded it). Mirrors the ClientWrite slice.
  struct WriteCapture
  {
    mutable std::mutex mutex;
    std::vector<DataValue> values;

    std::vector<DataValue> snapshot() const
    {
      std::lock_guard lock(mutex);
      return values;
    }
  };

  std::shared_ptr<WriteCapture> install_write_capture(const NodeId& nodeId)
  {
    auto capture = std::make_shared<WriteCapture>();
    auto node = std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(nodeId));
    EXPECT_NE(node, nullptr) << "capture target must be a default-namespace Variable";
    EXPECT_TRUE(node->external_value_source()
                  ->set_value_source(make_value_source(
                    [capture](const ValueSource::ReadContext& /*context*/,
                      const Node& /*node*/,
                      const ReadValueId& read,
                      std::function<void(DataValueResult)>
                        callback)
                    {
                      DataValue last;
                      {
                        std::lock_guard lock(capture->mutex);
                        if (!capture->values.empty())
                          last = capture->values.back();
                      }
                      index_range_utils::apply_to_value(last, read.index_range());
                      callback(DataValueResult{std::move(last)});
                    },
                    [capture](const ValueSource::WriteContext& /*context*/,
                      const Node& /*node*/,
                      const WriteValue& write,
                      std::function<void(ValueSource::WriteResult)>
                        callback)
                    {
                      {
                        std::lock_guard lock(capture->mutex);
                        capture->values.push_back(write.value());
                      }
                      callback(ValueSource::Written{});
                    }))
                  .is_good());
    return capture;
  }

  NodeId mDoubleCaptureId;
};

using ClientReadComplex = ClientReadWriteComplex;
using ClientReadEncoding = ClientReadWriteComplex;
using ClientWriteComplex = ClientReadWriteComplex;

// =============================================================================================
// ClientReadComplex.DecodeErrorsSurfaceBadDecodingError  (MisbehavingServer) - CL-ATTR-013
// A malformed ExtensionObject body for a REGISTERED (native NS0) Structure encoding must surface
// Bad_DecodingError at the wire boundary - not a silent partial decode, not a crash. The server injects an
// ExtensionObject whose TypeId is the Range Default-Binary encoding but whose binary body length does not
// match the fixed 16-byte Range wire form (a short 4-byte body and an over-long 20-byte body). The client's
// codec resolves Range via the NS0 factory, decodes its two Doubles, and the decoded-length check (or a
// stream underrun) fires Bad_DecodingError. [neg: malformed/mismatched ExtensionObject tolerated as Good]
// =============================================================================================
// @verifies AC-CL-ATTR-013-DECODINGERROR
// @relation(AC-CL-ATTR-013-DECODINGERROR, scope=function)
TEST_F(ClientReadComplex, DecodeErrorsSurfaceBadDecodingError)
{
  const NodeId rangeEncodingId{ObjectId::Range_Encoding_DefaultBinary};
  const NodeId argumentEncodingId{ObjectId::Argument_Encoding_DefaultBinary};

  // Each malformed body gets its OWN server + connection: a decode failure fails the request and closes the
  // channel, so a shared connection could not carry a second case. `encodingId` is the ExtensionObject TypeId
  // (the Default-Binary encoding node) the client resolves to a registered decoder; `body` is the
  // (mismatched) binary payload the server injects for it.
  auto statusFor = [&](const NodeId& encodingId, ByteString body) -> StatusCode
  {
    MisbehavingServer server;
    MisbehavingComplexFixture fixture{server};
    EXPECT_TRUE(fixture.start_status().is_good()) << "bootstrap must succeed against the un-mutated server: "
                                                  << to_string(fixture.start_status().status_code());

    server.set_response_mutator(
      [encodingId, body](Response& response)
      {
        if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
        {
          if (!read->results().empty())
            read->results()[0] =
              DataValue{Variant{UnknownStructure{encodingId, UnknownStructure::BodyEncoding::Binary, body}}};
        }
      });

    return fixture.conn().try_read_value_sync(server_state_node()).status_code();
  };

  // Case A: a body far too short for the 16-byte Range wire form.
  const StatusCode shortCase = statusFor(rangeEncodingId, bytes({0x01, 0x02, 0x03, 0x04}));
  EXPECT_TRUE(shortCase.is_bad()) << "a short ExtensionObject body must not decode as Good";
  EXPECT_EQ(shortCase.as_status(), Status::BadDecodingError)
    << "a malformed body of a registered Structure must surface Bad_DecodingError";

  // Case B: a body longer than the 16-byte Range wire form (length mismatch caught after decode).
  const StatusCode longCase = statusFor(
    rangeEncodingId, bytes({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}));
  EXPECT_TRUE(longCase.is_bad()) << "an over-long ExtensionObject body must not decode as Good";
  EXPECT_EQ(longCase.as_status(), Status::BadDecodingError)
    << "an over-long body of a registered Structure must surface Bad_DecodingError";

  // Case C (CTT/Attr/Read Complex/005 flavour - a DIFFERENT registered structure): the TypeId names the
  // Argument Default-Binary encoding (a multi-field variable-length structure), but the body is far too short
  // to satisfy its wire form. Proves the decode-error path is the GENERAL codec length/structure check, not a
  // Range-specific special case - any registered structure whose body does not match surfaces
  // Bad_DecodingError.
  const StatusCode wrongTypeCase = statusFor(argumentEncodingId, bytes({0x01, 0x02}));
  EXPECT_TRUE(wrongTypeCase.is_bad())
    << "a body too short for the registered Argument structure must not be Good";
  EXPECT_EQ(wrongTypeCase.as_status(), Status::BadDecodingError)
    << "a mismatched body of a DIFFERENT registered Structure must also surface Bad_DecodingError";
}

// @verifies CL-SESS-024 [integration]
// Highest public production tier: a real server mutates an otherwise-Good CancelResponse to report one
// cancellation for a handle with no outstanding request. The managed Connection surfaces that exact count,
// emits the structured advisory, and does not retry Cancel.
// @relation(CL-SESS-024, scope=function)
TEST(ClientSessionCancel, DivergentCancelCountIsSurfacedAndAdvised)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto observer = std::make_shared<CancelCountAdvisoryObserver>();
  fixture.conn().set_connection_observer(observer);

  std::atomic<std::uint32_t> cancelResponses{0};
  server.set_response_mutator(
    [&cancelResponses](Response& response)
    {
      if (auto* cancel = dynamic_cast<CancelResponse*>(response.second.get()))
      {
        ++cancelResponses;
        cancel->cancel_count() = 1;
      }
    });

  CancelRequest request;
  request.request_handle() = 0xCA11u;
  const auto response = fixture.conn().service_requests().cancel_sync(std::move(request));
  EXPECT_EQ(response.cancel_count(), 1u) << "the advisory must not rewrite the server's cancelCount";
  EXPECT_EQ(cancelResponses.load(), 1u) << "a mismatch must not cause an automatic retry";

  const auto detail = observer->wait_for_advisory();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CancelCountMismatch");
  EXPECT_EQ(detail->source, "client.tier1.connection.cancel_count");
}

// =============================================================================================
// ClientReadComplex.CheckedReadValidatesConcreteAgainstAbstractDeclaredDataType (MisbehavingServer) -
// CL-ADDRSP-009
// END-TO-END over a real server + wire: read_value_checked reads a node's Value AND its declared DataType in
// one Read, then validates the value's concrete type against the declared DataType (section 5.8.3). The
// server is mutated to present a Variable declared with the abstract Number DataType: a concrete Int32 value
// is ACCEPTED (Int32 <: Number, from the seeded NS0 hierarchy); a String value - genuinely disjoint from
// Number
// - is REJECTED with Bad_TypeMismatch (not delivered). [neg: a value in a disjoint type branch tolerated]
// =============================================================================================
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ClientReadComplex, CheckedReadValidatesConcreteAgainstAbstractDeclaredDataType)
{
  const NodeId numberDataType{DataTypeId::Number};

  // Presents server_state_node()'s checked Read (Value + DataType) as: results[0] = the given value,
  // results[1] = the abstract Number DataType. Armed AFTER bootstrap so only the checked Read is mutated.
  auto checkedStatusFor = [&](Variant value) -> StatusCode
  {
    MisbehavingServer server;
    MisbehavingComplexFixture fixture{server};
    EXPECT_TRUE(fixture.start_status().is_good()) << to_string(fixture.start_status().status_code());

    server.set_response_mutator(
      [value, numberDataType](Response& response)
      {
        if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
        {
          if (read->results().size() == 2)  // the checked Read: Value + DataType
          {
            read->results()[0] = DataValue{value};
            read->results()[1] = DataValue{Variant{numberDataType}};
          }
        }
      });

    return fixture.conn().try_read_value_checked_sync(server_state_node()).status_code();
  };

  // Concrete Int32 value for an abstract Number declared type -> accepted.
  const StatusCode accepted = checkedStatusFor(Variant{int32_t{7}});
  EXPECT_TRUE(accepted.is_good()) << "Int32 <: Number must be accepted end-to-end: 0x" << std::hex
                                  << accepted.as_uint32();

  // String value for a Number declared type -> a genuinely disjoint mismatch, rejected.
  const StatusCode rejected = checkedStatusFor(Variant{ua::String{"not-a-number"}});
  EXPECT_TRUE(rejected.is_bad()) << "a String is not a subtype of Number";
  EXPECT_EQ(rejected.as_status(), Status::BadTypeMismatch)
    << "a value not a subtype of the declared DataType must be rejected locally";
}

// =============================================================================================
// ClientReadComplex.CheckedWriteRefusesSubtypeToNoSubDataTypesTarget (MisbehavingServer) - CL-ATTR-025
// END-TO-END: write_value_checked pre-flights the target's declared DataType + AccessLevelEx, then refuses a
// strict-subtype write to a Variable whose AccessLevelEx.NoSubDataTypes (bit 11) is set - locally, with
// Bad_TypeMismatch, sparing the round-trip. The server is mutated to present the target as declared Integer
// with NoSubDataTypes; writing an Int32 (a strict subtype of Integer) is refused. A write with the check off
// (plain write_value) would reach the wire. [neg: a NoSubDataTypes subtype write tolerated]
// =============================================================================================
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ClientReadComplex, CheckedWriteRefusesSubtypeToNoSubDataTypesTarget)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  EXPECT_TRUE(fixture.start_status().is_good()) << to_string(fixture.start_status().status_code());

  // Present the checked-write pre-flight (a 2-attribute Read: DataType + AccessLevelEx) as a NoSubDataTypes
  // Integer target. Armed AFTER bootstrap so only the pre-flight Read is mutated.
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (read->results().size() == 2)
        {
          read->results()[0] = DataValue{Variant{NodeId{DataTypeId::Integer}}};  // declared DataType
          read->results()[1] = DataValue{Variant{uint32_t{1u << 11}}};  // AccessLevelEx.NoSubDataTypes
        }
      }
    });

  const auto result = fixture.conn().try_write_value_checked_sync(server_state_node(), Variant{int32_t{7}});
  ASSERT_TRUE(result.is_bad()) << "an Int32 (subtype of Integer) to a NoSubDataTypes target must be refused";
  EXPECT_EQ(result.status_code().as_status(), Status::BadTypeMismatch);
}

// =============================================================================================
// ClientReadComplex.NativeStructureDecodedInPlaceNoBrowse  (MisbehavingServer) - CL-ATTR-012
// Reading a NATIVE UA structure (the aggregate ServerStatus, a ServerStatusDataType) must decode into a
// typed structure using the client's NS0-seeded StructureFactory, with NO additional Browse of
// DataType->HasEncoding (a built-in decoder needs no discovery). The MisbehavingServer request observer
// proves no Browse frame is emitted. [neg: built-in decoder wrongly browses for discovery]
// =============================================================================================
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST_F(ClientReadComplex, NativeStructureDecodedInPlaceNoBrowse)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const Structure& request) { capture->observe(request); });

  auto result = fixture.conn().try_read_value_sync(server_status_node());
  ASSERT_TRUE(result.is_good()) << "the native ServerStatus structure must read Good: "
                                << to_string(result.status_code());
  ASSERT_TRUE(result.value().value().is_structure()) << "the value must be an ExtensionObject structure";
  const auto* status = result.value().value().try_as<ServerStatusDataType>();
  ASSERT_NE(status, nullptr)
    << "a native NS0 structure must decode IN-PLACE to its typed form via the built-in factory";
  EXPECT_EQ(status->state(), ServerState::Running) << "the decoded structure fields must carry real values";

  EXPECT_EQ(capture->browses(), 0u)
    << "a built-in structure decode must issue NO Browse (the generated decoder needs no discovery)";
}

// =============================================================================================
// ClientReadComplex.VendorStructureLazyResolvesViaBrowse  (MisbehavingServer) - CL-ATTR-012
// A 1-level VENDOR structure whose decoder is not pre-registered.
//
// UNBUILT (REPORTED): the matrix oracle expects the Lazy TypeResolver to emit a Browse of
// DataType->HasEncoding, register the structure, and re-decode so the caller receives a typed value. The
// per-Connection TypeResolver is NOT wired into the decode path (unchanged from the ClientTypeResolver
// cluster's f2d0f2a8 finding), so the vendor ExtensionObject is preserved as an opaque UnknownStructure
// (raw bytes round-trip) and NO Browse is issued. This pins the real opaque behaviour + the no-Browse fact
// and reports the lazy-resolve gap. [neg: if discovery were built, a Browse would appear and the value
// would be typed]
// =============================================================================================
// @verifies AC-CL-ATTR-012-HASENCODING
// @relation(AC-CL-ATTR-012-HASENCODING, scope=function)
TEST_F(ClientReadComplex, VendorStructureLazyResolvesViaBrowse)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const Structure& request) { capture->observe(request); });

  const NodeId vendorEncodingId{5, uint32_t{77001}};  // unknown to built-in / dictionary / user layers
  const ByteString vendorBody = bytes({0x2A, 0x00, 0x00, 0x00});  // opaque vendor payload
  server.set_response_mutator(
    [vendorEncodingId, vendorBody](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{
            Variant{UnknownStructure{vendorEncodingId, UnknownStructure::BodyEncoding::Binary, vendorBody}}};
      }
    });

  auto result = fixture.conn().try_read_value_sync(server_state_node());
  ASSERT_TRUE(result.is_good()) << "an unknown vendor ExtensionObject must NOT hard-fail the Read: "
                                << to_string(result.status_code());
  const auto* opaque = result.value().value().try_as<UnknownStructure>();
  ASSERT_NE(opaque, nullptr)
    << "an unresolved vendor structure is surfaced as an opaque UnknownStructure (lazy resolve UNBUILT)";
  EXPECT_EQ(opaque->encoding_id(), vendorEncodingId) << "the unresolved encoding NodeId must be retained";
  EXPECT_EQ(opaque->encoded_data(), vendorBody) << "the raw vendor body must round-trip losslessly";
  EXPECT_EQ(capture->browses(), 0u) << "the TypeResolver is not wired into the decode path: NO lazy Browse "
                                       "of DataType->HasEncoding is issued";
}

// =============================================================================================
// ClientReadComplex.NestedVendorStructureResolvesRecursively  (MisbehavingServer) - CL-ATTR-012
// A vendor Structure whose body itself carries a nested vendor ExtensionObject.
//
// UNBUILT (REPORTED): the matrix oracle expects each nested type to be resolved before the top-level decode
// completes (all leaf fields typed). With the TypeResolver unwired, the OUTER vendor ExtensionObject is
// preserved opaquely with its ENTIRE nested body bytes retained verbatim - no level is resolved, no Browse
// is issued. This pins that the outer opaque body round-trips the full nested payload (so a later resolver
// could reify it) and reports that recursive resolution is unbuilt. [neg: if recursion were built, the
// inner leaf would surface typed]
// =============================================================================================
// @verifies AC-CL-ATTR-012-HASENCODING
// @relation(AC-CL-ATTR-012-HASENCODING, scope=function)
TEST_F(ClientReadComplex, NestedVendorStructureResolvesRecursively)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const Structure& request) { capture->observe(request); });

  const NodeId outerEncodingId{5, uint32_t{77010}};
  // A body that itself embeds the wire form of a nested vendor ExtensionObject (2-byte NodeId + body-enc
  // byte + length + payload). The client cannot see the nesting: the outer is opaque bytes end-to-end.
  const ByteString nestedBody = bytes({0x01, 0x77, 0x01, 0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF});
  server.set_response_mutator(
    [outerEncodingId, nestedBody](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{
            Variant{UnknownStructure{outerEncodingId, UnknownStructure::BodyEncoding::Binary, nestedBody}}};
      }
    });

  auto result = fixture.conn().try_read_value_sync(server_state_node());
  ASSERT_TRUE(result.is_good()) << "a nested vendor ExtensionObject must NOT hard-fail the Read: "
                                << to_string(result.status_code());
  const auto* opaque = result.value().value().try_as<UnknownStructure>();
  ASSERT_NE(opaque, nullptr)
    << "the outer vendor structure is opaque - no level is resolved (recursive resolve UNBUILT)";
  EXPECT_EQ(opaque->encoded_data(), nestedBody)
    << "the outer opaque body must retain the ENTIRE nested payload verbatim (nothing decoded away)";
  EXPECT_EQ(capture->browses(), 0u) << "no Browse is issued for any nesting level (resolver unwired)";
}

// =============================================================================================
// ClientReadComplex.DefaultBinaryChosenMatchingSessionEncoding  (MisbehavingServer) - CL-ATTR-012
// The matrix oracle expects the client to advertise a `Default Binary` dataEncoding matching the UA-Binary
// session when reading a structured value.
//
// UNBUILT (REPORTED): the client does NOT implement dataEncoding selection - it leaves
// ReadValueId.dataEncoding NULL and relies on the server's session encoding. The captured outbound request
// therefore carries a null dataEncoding (not the `Default Binary` BrowseName). This pins the real wire
// behaviour and reports the divergence. [neg: if selection were built, the BrowseName would be 'Default
// Binary']
// =============================================================================================
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST_F(ClientReadComplex, DefaultBinaryChosenMatchingSessionEncoding)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const Structure& request) { capture->observe(request); });

  auto result = fixture.conn().try_read_value_sync(server_status_node());
  ASSERT_TRUE(result.is_good()) << "the structured value must read Good: " << to_string(result.status_code());

  const auto encodings = capture->encodings();
  ASSERT_FALSE(encodings.empty()) << "the outbound ReadValueId must have been observed";
  EXPECT_TRUE(encodings.front().is_null())
    << "the client does not implement dataEncoding selection: it leaves dataEncoding NULL and relies on "
       "the session encoding (matrix oracle 'Default Binary' is UNBUILT - reported)";
}

// =============================================================================================
// ClientReadEncoding.EncodingOmittedForNonStructureAndNonValue  (MisbehavingServer) - CL-ATTR-014
// The client must omit dataEncoding for a non-structure Value read (scalar Int32) and a non-Value attribute
// read (DisplayName): the captured outbound ReadValueId.dataEncoding is null for both. A tier-1 forced
// `Default Binary` on the same scalar is forwarded verbatim (case C), proving the null is a genuine default
// rather than the client dropping the field.
//
// NOTE (REPORTED): the client omits dataEncoding UNCONDITIONALLY (it never sets it for any read); the null
// on cases A/B is therefore correct but not the product of structure-aware selection. [neg: encoding sent
// on a non-Structure / non-Value read]
// =============================================================================================
// @verifies CL-ATTR-014
// @relation(CL-ATTR-014, scope=function)
TEST_F(ClientReadEncoding, EncodingOmittedForNonStructureAndNonValue)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const Structure& request) { capture->observe(request); });

  // Case A: a scalar Int32 Value read.
  ASSERT_TRUE(fixture.conn().try_read_value_sync(server_state_node()).is_good());
  // Case B: a DisplayName (non-Value) attribute read.
  ASSERT_TRUE(
    fixture.conn().typed().try_read_attribute_sync(server_state_node(), AttributeId::DisplayName).is_good());
  // Case C: a tier-1 read that explicitly forces the `Default Binary` dataEncoding.
  ASSERT_TRUE(fixture.conn()
                .service_requests()
                .try_read_sync(ReadRequestBuilder()
                                 .read(server_state_node())
                                 .attribute(AttributeId::Value)
                                 .data_encoding(QualifiedName{0, "Default Binary"}))
                .is_good());

  const auto encodings = capture->encodings();
  ASSERT_EQ(encodings.size(), 3u) << "three single-node reads must be observed in order";
  EXPECT_TRUE(encodings[0].is_null()) << "a scalar Int32 Value read must omit dataEncoding";
  EXPECT_TRUE(encodings[1].is_null()) << "a DisplayName (non-Value) read must omit dataEncoding";
  EXPECT_EQ(std::string{encodings[2].name()}, "Default Binary")
    << "an explicitly forced dataEncoding must be forwarded verbatim (proving A/B's null is a real default)";
}

// =============================================================================================
// ClientReadEncoding.NullEncodingDefaultsToSessionEncoding  (normal server) - CL-ATTR-015
// With a UA-Binary Session and a null dataEncoding, a structured value (native ServerStatus) decodes
// correctly against the session's binary encoding. [neg: the client cannot handle the server's chosen
// encoding -> decode fails or wrong fields]
// =============================================================================================
// @verifies CL-ATTR-015
// @relation(CL-ATTR-015, scope=function)
TEST_F(ClientReadEncoding, NullEncodingDefaultsToSessionEncoding)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("NullEnc")};
  ASSERT_TRUE(connection.start_status().is_good());

  // read_value_sync leaves dataEncoding null; the UA-Binary session decodes the structure correctly.
  auto result = connection->try_read_value_sync(server_status_node());
  ASSERT_TRUE(result.is_good()) << "a null dataEncoding must default to the binary session encoding: "
                                << to_string(result.status_code());
  const auto* status = result.value().value().try_as<ServerStatusDataType>();
  ASSERT_NE(status, nullptr) << "the structure must decode against the session's binary encoding";
  EXPECT_EQ(status->state(), ServerState::Running) << "the decoded fields must be correct, not garbage";
}

// =============================================================================================
// ClientReadEncoding.MismatchedEncodingResponseRejected  (MisbehavingServer) - CL-ATTR-016
// The client requests `Default Binary` but the server returns an XML-encoded body (ExtensionObject body
// byte 2) for a registered encoding.
//
// The public typed read-with-encoding API validates the decoded ExtensionObject body kind before exposing
// the value. The codec preserves an XML body as UnknownStructure tagged Xml, giving the facade authoritative
// evidence that the response does not match the requested Default Binary encoding. [neg: response encoding
// != requested]
// =============================================================================================
// @verifies AC-CL-ATTR-016-ENCODING-MISMATCH
// @relation(AC-CL-ATTR-016-ENCODING-MISMATCH, scope=function)
TEST_F(ClientReadEncoding, MismatchedEncodingResponseRejected)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId rangeEncodingId{ObjectId::Range_Encoding_DefaultBinary};
  const ByteString xmlBody = bytes({'<', 'R', '>', '<', '/', 'R', '>'});
  server.set_response_mutator(
    [rangeEncodingId, xmlBody](Response& response)
    {
      if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!read->results().empty())
          read->results()[0] = DataValue{
            Variant{UnknownStructure{rangeEncodingId, UnknownStructure::BodyEncoding::Xml, xmlBody}}};
      }
    });

  // Request Default Binary explicitly; the server answers with an XML-bodied ExtensionObject.
  auto result = fixture.conn().typed().try_read_value_with_encoding_sync(
    server_state_node(), QualifiedName{0, "Default Binary"});

  ASSERT_TRUE(result.is_bad()) << "an XML response to a Default Binary read must be rejected";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr) << "the encoding mismatch must retain diagnostic detail";
  EXPECT_EQ(result.shared_detail()->code, "DataEncodingMismatch");
}

// =============================================================================================
// ClientWriteComplex.SimpleTypeEncodedAsSuperType  (normal server, server-side capture) - CL-ATTR-026
// Writing a Duration value to a Double-typed Variable must place a plain Double scalar on the wire (Duration
// is a simple DataType whose super-type is Double) - the client must NOT fabricate a synthetic simple-type
// ExtensionObject tag. A server-side value handler captures the decoded wire Variant. [neg: simple DataType
// wire equivalence - a synthetic tag would differ from a plain Double]
// =============================================================================================
// @verifies CL-ATTR-026
// @relation(CL-ATTR-026, scope=function)
TEST_F(ClientWriteComplex, SimpleTypeEncodedAsSuperType)
{
  auto capture = install_write_capture(mDoubleCaptureId);

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("SimpleSuper")};
  ASSERT_TRUE(connection.start_status().is_good());

  const Duration duration = 2.5;  // Duration is a simple type aliasing Double
  ASSERT_TRUE(connection->try_write_value_sync(mDoubleCaptureId, Variant{duration}).is_good())
    << "a Duration write to a Double Variable must be accepted";

  auto captured = capture->snapshot();
  ASSERT_EQ(captured.size(), 1u) << "the write must reach the server-side handler";
  EXPECT_FALSE(captured[0].value().is_structure())
    << "a simple DataType must NOT be wrapped in a synthetic ExtensionObject tag";
  const double* asDouble = captured[0].value().try_as<double>();
  ASSERT_NE(asDouble, nullptr) << "the wire Variant must be a plain Double (the super-type)";
  EXPECT_DOUBLE_EQ(*asDouble, 2.5) << "the Duration value must survive as a plain Double";
}

// @relation(AC-SVR-ATTR-WRITE-026-TYPEMISMATCH, scope=function)

// =============================================================================================
// ClientWriteComplex.SubtypeAcceptedSiblingRejected  (normal server) - CL-ATTR-025
// Case A: a subtype Variant (Int32) written to a parent-DataType (Number) Variable is accepted (Good). Case
// B: a sibling/unrelated type (String) is rejected with the server's Bad_TypeMismatch, and the tier-2
// verdict equals the raw tier-0 per-operation status (the client forwards, never fabricates). [neg: sibling
// type rejected]
//
// NOTE (REPORTED): the matrix's case C (a subtype write locally rejected when the cache shows
// AccessLevelEx.NoSubDataTypes=1) needs a client-side attribute cache + subtype check that is UNBUILT (the
// tier-2 write takes only (NodeId, Variant), with no cached DataType), so it is reported, not asserted.
// =============================================================================================
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ClientWriteComplex, SubtypeAcceptedSiblingRejected)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("Subtype")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case A: Int32 is a concrete subtype of the abstract Number DataType -> accepted.
  auto subtype = connection->try_write_value_sync(mNumberVariableId, Variant{int32_t{7}});
  EXPECT_TRUE(subtype.is_good()) << "a subtype value written to a parent-DataType Variable must be accepted: "
                                 << to_string(subtype.status_code());

  // Case B: String is not a subtype of Number -> the server rejects it; the client forwards that verdict.
  auto tier2 = connection->try_write_value_sync(mNumberVariableId, Variant{String{"not-a-number"}});
  auto tier1 = connection->service_requests().try_write_sync(
    WriteRequestBuilder().write(mNumberVariableId, Variant{String{"not-a-number"}}));
  ASSERT_TRUE(tier1.is_good()) << "the Write service itself completes; any failure is per-operation";
  ASSERT_EQ(tier1.value().results().size(), 1u);
  const StatusCode rawPerOp = tier1.value().results()[0];

  EXPECT_TRUE(tier2.is_bad()) << "a sibling/unrelated type must be rejected, not accepted";
  const StatusCode tier2Status = tier2.is_bad() ? tier2.status_code() : StatusCode{Status::Good};
  EXPECT_EQ(tier2Status.value(), rawPerOp.value())
    << "tier-2 must surface the server's exact per-operation verdict, never fabricate one";
  EXPECT_EQ(rawPerOp.as_status(), Status::BadTypeMismatch)
    << "the server rejects a sibling type with Bad_TypeMismatch";
}

namespace
{

// ---------------------------------------------------------------------------------------------
// WriteWireCapture: mutex-guarded record of the DataValues the client actually put on the wire in every
// WriteRequest, populated by a MisbehavingServer request observer (runs on a server strand while the test
// thread reads). It is the request-side counterpart of RequestCapture for writes: it lets a test assert
// what the client SENT, independently of what the server did with it.
// ---------------------------------------------------------------------------------------------
struct WriteWireCapture
{
  mutable std::mutex mutex;
  std::vector<DataValue> writtenValues;
  uint64_t writeRequests{0};

  void observe(const Structure& request)
  {
    if (const auto* write = dynamic_cast<const WriteRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      ++writeRequests;
      for (const auto& nodeToWrite : write->nodes_to_write())
        writtenValues.push_back(nodeToWrite.value());
    }
  }

  std::vector<DataValue> snapshot() const
  {
    std::lock_guard lock(mutex);
    return writtenValues;
  }

  uint64_t writes() const
  {
    std::lock_guard lock(mutex);
    return writeRequests;
  }
};

}  // namespace

// =============================================================================================
// ClientWriteComplex.MisalignedWriteResultsAreRejectedWithNoPerNodeOutcome
// Part 4 section 5.10.4.2: the Write `results[]` size and order match `nodesToWrite`. A client that trusts
// positional alignment without checking the length is the plausible implementation, and for Write it is
// the worst place to be wrong: the caller is told which of its writes succeeded, so a short list either
// hides an outcome or slides a status onto the wrong Node - the application then rewrites a Node that
// already took the value, or fails to retry one that silently did not. A three-Node Write answered with
// two results must therefore be rejected outright, with NO per-Node outcome handed back at all.
// [neg: two results for three nodesToWrite reported as two (or three) per-Node verdicts]
// =============================================================================================
// @verifies AC-CL-ATTR-017-WRITE-ALIGNMENT
TEST_F(ClientWriteComplex, MisalignedWriteResultsAreRejectedWithNoPerNodeOutcome)
{
  MisbehavingServer server;
  MisbehavingComplexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Drop the LAST result of the three-result Write response: three Nodes requested, two answered. Counted
  // so the test can prove the misaligned response really reached the client (a bad verdict for any other
  // reason would be a vacuous pass).
  auto shortenedWrites = std::make_shared<std::atomic<uint64_t>>(0);
  server.set_response_mutator(
    [shortenedWrites](Response& response)
    {
      auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
      if (!writeResponse || writeResponse->results().size() != 3)
        return;
      Array<StatusCode> shortened;
      shortened.push_back(writeResponse->results()[0]);
      shortened.push_back(writeResponse->results()[1]);
      writeResponse->results() = std::move(shortened);
      shortenedWrites->fetch_add(1);
    });

  std::vector<std::pair<NodeId, Variant>> pairs;
  pairs.emplace_back(server_state_node(), Variant{int32_t{1}});
  pairs.emplace_back(NodeId{VariableId::Server_ServerStatus_CurrentTime}, Variant{int32_t{2}});
  pairs.emplace_back(NodeId{VariableId::Server_ServerStatus_StartTime}, Variant{int32_t{3}});

  auto result = fixture.conn().typed().try_write_values_sync(pairs);

  ASSERT_EQ(shortenedWrites->load(), 1u)
    << "the three-Node Write must have been answered with a two-entry results list (otherwise this test "
       "proves nothing about alignment)";
  EXPECT_TRUE(result.is_bad()) << "a two-result answer to a three-Node Write must be rejected";
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadUnexpectedError}.value())
    << "a misaligned Write results list must surface as Bad_UnexpectedError";
  // value_or hands back the fallback when the Result holds nothing, so an empty list here is the
  // caller being given no per-Node outcome at all rather than a truncated one.
  EXPECT_TRUE(result.value_or({}).empty())
    << "no per-Node outcome may be handed to the caller from a misaligned results list";
  ASSERT_NE(result.shared_detail(), nullptr) << "the rejection must carry diagnostic detail";
  EXPECT_THAT(result.shared_detail()->code, ::testing::HasSubstr("ResultCountMismatch"))
    << "the rejection must name the result-count mismatch, not some unrelated failure";
}

// =============================================================================================
// ClientWriteComplex.ExplicitTimestampsReachTheWireAndRefusalIsSurfaced
// Part 4 section 5.10.4.2: "If the SourceTimestamp or the ServerTimestamp is specified, the Server shall use
// these values. The Server returns Bad_WriteNotSupported if it does not support writing of timestamps."
// The client-side obligation is first an API-shape one - a tier-2 path that takes only a Variant cannot
// express the write at all, so the obligation fails by silent absence - and then a fidelity one: the
// supplied instants must reach the wire unaltered (a historian replaying data needs the original
// instants, not the moment of upload), and a server that refuses the combination must have its exact
// code surfaced rather than swallowed or "recovered" by a quiet second attempt with the timestamps
// stripped, which would write the value under a fabricated receipt time.
// [neg: timestamps dropped/regenerated on the wire, refusal swallowed, or a stripped retry emitted]
// =============================================================================================
// @verifies AC-CL-ATTR-027-CLIENT-TIMESTAMPS
TEST_F(ClientWriteComplex, ExplicitTimestampsReachTheWireAndRefusalIsSurfaced)
{
  const DateTime sourceTs{2021, 3, 4, 5, 6, 7.0};
  const DateTime serverTs{2022, 8, 9, 10, 11, 12.0};

  DataValue timestamped{Variant{int32_t{4242}}};
  timestamped.source_timestamp() = sourceTs;
  timestamped.server_timestamp() = serverTs;

  // Arm 1 - a server that honours them: the fixture's real server, writing to the Variable whose
  // AccessLevel carries TimestampWrite. A server-side value handler captures the decoded WriteValue, so
  // the assertion is on what the client put on the wire, not on anything the test fabricated.
  {
    auto capture = install_write_capture(mFullAccessVariableId);

    StartedConnection connection{mClientThreadPool.executor(), open_activated_session("WriteTimestamps")};
    ASSERT_TRUE(connection.start_status().is_good());

    auto honoured =
      connection->typed().try_write_attribute_sync(mFullAccessVariableId, AttributeId::Value, timestamped);
    EXPECT_TRUE(honoured.is_good()) << "a timestamped write to a TimestampWrite Variable must be accepted: "
                                    << to_string(honoured.status_code());

    auto captured = capture->snapshot();
    ASSERT_EQ(captured.size(), 1u) << "the timestamped write must reach the server-side handler";
    ASSERT_TRUE(captured[0].source_timestamp().has_value()) << "the SourceTimestamp must reach the wire";
    EXPECT_EQ(*captured[0].source_timestamp(), sourceTs)
      << "the supplied SourceTimestamp must carry verbatim";
    ASSERT_TRUE(captured[0].server_timestamp().has_value()) << "the ServerTimestamp must reach the wire";
    EXPECT_EQ(*captured[0].server_timestamp(), serverTs)
      << "the supplied ServerTimestamp must carry verbatim";
  }

  // Arm 2 - a server that answers Bad_WriteNotSupported. The request observer records every WriteRequest
  // the client emitted, so "no retry without the timestamps" is falsifiable: a stripped second attempt
  // would show up as a second Write whose DataValue has no timestamps.
  {
    MisbehavingServer server;
    MisbehavingComplexFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    auto wire = std::make_shared<WriteWireCapture>();
    server.set_request_observer([wire](const Structure& request) { wire->observe(request); });
    server.set_response_mutator(
      [](Response& response)
      {
        if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        {
          if (!writeResponse->results().empty())
            writeResponse->results()[0] = StatusCode{Status::BadWriteNotSupported};
        }
      });

    auto refused =
      fixture.conn().typed().try_write_attribute_sync(server_state_node(), AttributeId::Value, timestamped);

    EXPECT_TRUE(refused.is_bad()) << "a refused timestamp write must not be reported as written";
    EXPECT_EQ(refused.status_code().value(), StatusCode{Status::BadWriteNotSupported}.value())
      << "the server's exact Bad_WriteNotSupported must be surfaced, not swallowed or rewritten";

    EXPECT_EQ(wire->writes(), 1u)
      << "the refusal must not trigger a second attempt: exactly one Write round-trip";
    auto sent = wire->snapshot();
    ASSERT_EQ(sent.size(), 1u) << "exactly one WriteValue must have been observed on the wire";
    ASSERT_TRUE(sent[0].source_timestamp().has_value())
      << "the single attempt must be the timestamped one - no retry stripped of the SourceTimestamp";
    EXPECT_EQ(*sent[0].source_timestamp(), sourceTs);
    ASSERT_TRUE(sent[0].server_timestamp().has_value())
      << "the single attempt must be the timestamped one - no retry stripped of the ServerTimestamp";
    EXPECT_EQ(*sent[0].server_timestamp(), serverTs);
  }
}

// =============================================================================================
// ClientWriteComplex.WriteNotSupportedCommitsNothingAndIsReportedToTheCaller
// Part 4 section 5.10.4.4: for Bad_WriteNotSupported "the Server shall not perform any write on this Node and
// shall return this StatusCode for this Node". This code is atomic where the other per-operation write
// failures are not, so an implementation that treats it as an ordinary per-operation error - reporting
// the code but assuming the supported part (the value) went in, or retrying the value alone - is correct
// for every other code and wrong for this one. The read-back is the only way to tell the two apart, so
// the Node's stored value, status and timestamp are all re-read after the refusal.
// [neg: the value alone committed while Bad_WriteNotSupported is reported]
// =============================================================================================
// @verifies AC-CL-ATTR-028-WRITENOTSUPPORTED-ATOMIC
TEST_F(ClientWriteComplex, WriteNotSupportedCommitsNothingAndIsReportedToTheCaller)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("WriteNotSupported")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Establish a known value so "the Node is unchanged" is falsifiable.
  ASSERT_TRUE(connection->try_write_value_sync(mWritableVariableId, Variant{int32_t{4242}}).is_good())
    << "the setup write to the writable Variable must succeed";

  // mWritableVariableId advertises CurrentRead + CurrentWrite only: it supports the value and neither the
  // status nor the timestamp, so value+status+timestamp together is an unsupported combination. The
  // refusal is the server's, decided from the Node's own AccessLevel - nothing here fabricates it.
  const DateTime attemptedTs{2021, 1, 2, 3, 4, 0.0};
  DataValue combination{Variant{int32_t{909}}, StatusCode{Status::UncertainLastUsableValue}};
  combination.source_timestamp() = attemptedTs;

  auto refused =
    connection->typed().try_write_attribute_sync(mWritableVariableId, AttributeId::Value, combination);
  ASSERT_TRUE(refused.is_bad()) << "an unsupported value/status/timestamp combination must not be reported "
                                   "as written";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadWriteNotSupported)
    << "the caller must see the exact Bad_WriteNotSupported the server returned";

  auto readBack = connection->try_read_value_sync(mWritableVariableId);
  ASSERT_TRUE(readBack.is_good()) << "the read-back must succeed: " << to_string(readBack.status_code());
  const int32_t* stored = readBack.value().value().try_as<int32_t>();
  ASSERT_NE(stored, nullptr) << "the Node must still hold its Int32 value";
  EXPECT_EQ(*stored, 4242) << "the value must NOT have been written on its own - the refusal is atomic";
  if (readBack.value().status().has_value())
  {
    EXPECT_NE(readBack.value().status()->as_status(), Status::UncertainLastUsableValue)
      << "the attempted StatusCode must not have been committed";
  }
  if (readBack.value().source_timestamp().has_value())
  {
    EXPECT_NE(*readBack.value().source_timestamp(), attemptedTs)
      << "the attempted SourceTimestamp must not have been committed";
  }
}

// =============================================================================================
// ClientWriteComplex.SuppliedTimestampsAreUsedByTheServerAndTheirRefusalReachesTheCaller
// Part 4 section 5.10.4.2: "If the SourceTimestamp or the ServerTimestamp is specified, the Server shall use
// these values. The Server returns a Bad_WriteNotSupported error if it does not support writing of
// timestamps." A plausible implementation gets this wrong at both ends. Outbound, it treats a
// DataValue write as a Variant write and lets the instants be regenerated (or dropped) at send time,
// which destroys the only reason to send them at all - a historian replaying data needs the original
// instants, not the moment of upload - and the loss is silent, because the write still returns Good.
// Inbound, it reads Bad_WriteNotSupported as an ordinary transient failure and "recovers" by quietly
// re-sending the value alone, so the caller is told the write succeeded and the Node ends up holding a
// fabricated receipt time.
//
// The honouring arm inspects the DataValue the SERVER ACTUALLY STORED, through the address space
// rather than through a Read service call: the Read service re-stamps ServerTimestamp with the receipt
// time by policy, so the value store is the only place where BOTH supplied instants are still
// observable, and no stub handler stands between the wire and the assertion. The refusing arm counts
// the WriteRequests that reached a server answering Bad_WriteNotSupported, so a stripped second
// attempt would be visible rather than inferred.
// [neg: instants regenerated or dropped on the wire, the refusal swallowed, or a stripped retry sent]
// =============================================================================================
// @verifies AC-CL-ATTR-027-CLIENT-TIMESTAMPS
TEST_F(ClientWriteComplex, SuppliedTimestampsAreUsedByTheServerAndTheirRefusalReachesTheCaller)
{
  // Fixed instants far in the past: neither can coincide with a receipt time, so an implementation
  // that regenerated either stamp cannot accidentally satisfy the equality assertions below.
  const DateTime suppliedSource{2019, 5, 6, 7, 8, 9.0};
  const DateTime suppliedServer{2020, 10, 11, 12, 13, 14.0};

  DataValue supplied{Variant{int32_t{5150}}};
  supplied.source_timestamp() = suppliedSource;
  supplied.server_timestamp() = suppliedServer;

  // Arm 1 - a server that honours them. mFullAccessVariableId carries TimestampWrite and keeps its
  // default value store: nothing in this test intercepts the write, so what the store holds afterwards
  // is what the client put on the wire and the server chose to use.
  {
    StartedConnection connection{mClientThreadPool.executor(), open_activated_session("HonouredStamps")};
    ASSERT_TRUE(connection.start_status().is_good());

    auto honoured =
      connection->typed().try_write_attribute_sync(mFullAccessVariableId, AttributeId::Value, supplied);
    ASSERT_TRUE(honoured.is_good()) << "a full DataValue carrying both timestamps must be writable to a "
                                       "TimestampWrite Variable: "
                                    << to_string(honoured.status_code());

    auto addressSpace = mServer.server().address_space();
    auto storedNode = addressSpace.find_node_sync(mFullAccessVariableId);
    auto storedVariable = storedNode.as<VariableAccessor>();
    ASSERT_TRUE(storedVariable.has_value()) << "the write target must still be a Variable";
    // maxAge Int32 max is the cached-value read (Part 4 5.10.2.2): it returns the ServerTimestamp the
    // store holds. A maxAge 0 read would be entitled to a fresh one.
    ReadValueId storedValueId;
    storedValueId.node_id() = mFullAccessVariableId;
    storedValueId.attribute_id() = utils::to_underlying(AttributeId::Value);
    std::promise<DataValueResult> storedRead;
    storedVariable->read_value_async(static_cast<Duration>(std::numeric_limits<int32_t>::max()),
      true,
      storedValueId,
      nullptr,
      [&storedRead](DataValueResult result) { storedRead.set_value(std::move(result)); });
    auto stored = storedRead.get_future().get();
    ASSERT_TRUE(stored.is_good()) << "the stored DataValue must be readable: "
                                  << to_string(stored.status_code());

    const int32_t* storedValue = stored.value().value().try_as<int32_t>();
    ASSERT_NE(storedValue, nullptr) << "the write must have reached the Variable's value store";
    EXPECT_EQ(*storedValue, 5150) << "the stored value must be the one written";
    ASSERT_TRUE(stored.value().source_timestamp().has_value())
      << "the supplied SourceTimestamp must have crossed the wire, not been dropped";
    EXPECT_EQ(*stored.value().source_timestamp(), suppliedSource)
      << "the server must use the supplied SourceTimestamp, not the moment of receipt";
    ASSERT_TRUE(stored.value().server_timestamp().has_value())
      << "the supplied ServerTimestamp must have crossed the wire, not been dropped";
    EXPECT_EQ(*stored.value().server_timestamp(), suppliedServer)
      << "the server must use the supplied ServerTimestamp, not the moment of receipt";
  }

  // Arm 2 - a server that answers Bad_WriteNotSupported. The refusal is what the criterion posits, so
  // it is imposed on the response; the artefact under test is the CLIENT's handling of it. The request
  // observer records every WriteRequest the client emitted, which is what makes "no retry without the
  // timestamps" falsifiable rather than assumed.
  {
    MisbehavingServer server;
    MisbehavingComplexFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    auto wire = std::make_shared<WriteWireCapture>();
    server.set_request_observer([wire](const Structure& request) { wire->observe(request); });

    auto refusals = std::make_shared<std::atomic<uint64_t>>(0);
    server.set_response_mutator(
      [refusals](Response& response)
      {
        if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        {
          if (!writeResponse->results().empty())
          {
            writeResponse->results()[0] = StatusCode{Status::BadWriteNotSupported};
            refusals->fetch_add(1);
          }
        }
      });

    auto refused =
      fixture.conn().typed().try_write_attribute_sync(server_state_node(), AttributeId::Value, supplied);

    ASSERT_EQ(refusals->load(), 1u) << "exactly one Write must have been answered Bad_WriteNotSupported "
                                       "(otherwise this arm proves nothing about the refusal)";
    ASSERT_TRUE(refused.is_bad()) << "a refused timestamp write must not be reported as written";
    EXPECT_EQ(refused.status_code().value(), StatusCode{Status::BadWriteNotSupported}.value())
      << "the server's exact code must reach the caller, neither swallowed nor rewritten";
    ASSERT_NE(refused.shared_detail(), nullptr) << "the refusal must carry diagnostic detail";
    EXPECT_THAT(refused.shared_detail()->code, ::testing::HasSubstr("CombinationUnsupported"))
      << "the refusal must be reported as the Value/Status/timestamp combination being unsupported";

    EXPECT_EQ(wire->writes(), 1u) << "the refusal must not provoke a second, quietly stripped attempt";
    auto sent = wire->snapshot();
    ASSERT_EQ(sent.size(), 1u) << "exactly one WriteValue must have reached the wire";
    ASSERT_TRUE(sent[0].source_timestamp().has_value())
      << "the single attempt must be the timestamped one - no retry stripped of the SourceTimestamp";
    EXPECT_EQ(*sent[0].source_timestamp(), suppliedSource)
      << "the SourceTimestamp on the wire must be the one supplied, verbatim";
    ASSERT_TRUE(sent[0].server_timestamp().has_value())
      << "the single attempt must be the timestamped one - no retry stripped of the ServerTimestamp";
    EXPECT_EQ(*sent[0].server_timestamp(), suppliedServer)
      << "the ServerTimestamp on the wire must be the one supplied, verbatim";
  }
}
