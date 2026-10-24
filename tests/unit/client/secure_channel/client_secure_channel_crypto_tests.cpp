// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "integration/helpers/sanitizer_budget.h"

#include "ua_application_configuration.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "ua_data_type_registration.h"
#include "ua_connection_protocol.h"
#include "ua_crypto.h"
#include "ua_reverse_hello.h"
#include "ua_memory_stream.h"
#include "ua_security_policy.h"
#include "ua_stack_utilities.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_async_crypto.h"
#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"

// Test-only access to client secure channel internals.
#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"

#include <condition_variable>
#include <cstring>
#include <future>
#include <optional>
#include <mutex>
#include <thread>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace ua::stack_utils;
using namespace std::chrono_literals;

using STA = SecureChannelTestAccess;

namespace
{

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

static std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() -> ua::SecureString { return ua::SecureString{"password"}; });
}

static ByteString make_nonce(const Crypto& crypto, size_t size)
{
  ByteString nonce;
  nonce.resize(size);
  auto entropy = crypto.get_entropy_sync(size);
  std::memcpy(nonce.data(), entropy.data(), size);
  return nonce;
}

static EncodingLimits test_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

// ---------------------------------------------------------------------------
// TestCertificateStore - returns pre-configured client certificate
// ---------------------------------------------------------------------------

class TestCertificateStore : public CertificateStore
{
public:
  TestCertificateStore(ApplicationCertificate clientCert, std::shared_ptr<const X509Certificate> serverCert)
    : mClientCert(std::move(clientCert)), mServerCert(std::move(serverCert))
  {}

  void add_to_application_certificates_async(
    ApplicationCertificate /*certificate*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  /// Test hook: when set to a bad status, get_application_certificate_async reports that the store
  /// has no own Application Instance Certificate to provide (models CL-SECADMIN-007's absent-own-cert
  /// precondition). A Good status (the default) returns the configured client certificate.
  /// Test hook (decision 24): the own certificate's issuer chain the store hands out with the leaf. Set
  /// before the channel opens.
  void set_own_issuer_certificates(std::vector<std::shared_ptr<const X509Certificate>> issuers)
  {
    mClientCert.issuerCertificates = std::move(issuers);
  }

  void set_own_certificate_status(StatusCode status) noexcept
  {
    mOwnCertStatus.store(status.as_uint32(), std::memory_order_relaxed);
  }

  /// Test hook: the CertificateType the client last requested its own Application Instance Certificate
  /// with. The client selects by mSecurityPolicy->certificate_type(), which is curve-distinguishing for
  /// ECC policies (CL-ECC-001). -1 until the first request.
  std::optional<CertificateType> requested_certificate_type() const noexcept
  {
    const auto raw = mRequestedCertType.load(std::memory_order_relaxed);
    if (raw < 0)
      return std::nullopt;
    return static_cast<CertificateType>(raw);
  }

  void get_application_certificate_async(
    CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept override
  {
    mRequestedCertType.store(static_cast<int>(certificateType), std::memory_order_relaxed);
    const auto raw = mOwnCertStatus.load(std::memory_order_relaxed);
    if (raw != 0)
    {
      callback(ApplicationCertificateResult{StatusCode{static_cast<Status>(raw)}});
      return;
    }
    callback(ApplicationCertificateResult{mClientCert});
  }

  void get_application_certificates_async(GetApplicationCertificatesCallback callback) const noexcept override
  {
    callback(ApplicationCertificateListResult{ApplicationCertificateList{mClientCert}});
  }

  void add_to_trusted_certificates_async(
    shared_ptr<const X509Certificate> /*certificate*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_trusted_certificates_async(std::vector<shared_ptr<const X509Certificate>> /*certificates*/,
    CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    if (mServerCert)
    {
      callback(CertificateListResult{CertificateList{mServerCert}});
    }
    else
    {
      callback(CertificateListResult{CertificateList{}});
    }
  }

  void add_to_issuer_certificates_async(
    shared_ptr<const X509Certificate> /*certificate*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_issuer_certificates_async(std::vector<shared_ptr<const X509Certificate>> /*certificates*/,
    CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(CertificateListResult{CertificateList{}});
  }

  void add_to_rejected_certificates_async(
    shared_ptr<const X509Certificate> /*certificate*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(CertificateListResult{CertificateList{}});
  }

  void add_to_trusted_crls_async(
    shared_ptr<const X509Crl> /*crl*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<shared_ptr<const X509Crl>> /*crls*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(CrlListResult{CrlList{}});
  }

  void add_to_issuer_crls_async(
    shared_ptr<const X509Crl> /*crl*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_issuer_crls_async(
    std::vector<shared_ptr<const X509Crl>> /*crls*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(CrlListResult{CrlList{}});
  }

  void replace_trusted_certificates_async(
    CertificateList /*certificates*/, CrlList /*crls*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void replace_issuer_certificates_async(
    CertificateList /*certificates*/, CrlList /*crls*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void remove_from_trusted_certificates_async(
    const std::string& /*thumbprint*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void remove_from_issuer_certificates_async(
    const std::string& /*thumbprint*/, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void set_validation_options(TrustListValidationOptions /*validationOptions*/) override
  {}

  TrustListValidationOptions validation_options() const override
  {
    return {};
  }

  void refresh_cache(CompleteCallback callback) override
  {
    callback(VoidResult{});
  }

  /// Test hook: scripts the outcome of the next (and every subsequent) validate_certificate_async.
  /// A Good status (the default) accepts; any bad status makes the store reject, modelling an
  /// untrusted / invalid server certificate. Stored as an atomic because the test thread sets it and
  /// the crypto pool thread reads it inside validate_certificate_async.
  void set_validate_status(StatusCode status) noexcept
  {
    mValidateStatus.store(status.as_uint32(), std::memory_order_relaxed);
  }

  /// The request the most recent validate_certificate_async carried (empty before the first).
  optional<CertificateValidationRequest> last_request() const
  {
    std::lock_guard<std::mutex> lock(mRequestMutex);
    return mLastRequest;
  }

  /// Number of times validate_certificate_async has been invoked (for asserting re-validation).
  std::size_t validate_call_count() const noexcept
  {
    return mValidateCalls.load(std::memory_order_relaxed);
  }

  void validate_certificate_async(CertificateValidationRequest request,
    Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    {
      std::lock_guard<std::mutex> lock(mRequestMutex);
      mLastRequest = std::move(request);
    }
    mValidateCalls.fetch_add(1, std::memory_order_relaxed);
    const auto raw = mValidateStatus.load(std::memory_order_relaxed);
    if (raw != 0)
    {
      std::unique_ptr<ua::ErrorDetail> detail = ua::ErrorDetail::build("UntrustedServerCertificate",
        "Server certificate is not trusted by the configured certificate store",
        "TestCertificateStore");
      callback(VoidResult{StatusCode{static_cast<Status>(raw)}, std::move(detail)});
      return;
    }
    callback(VoidResult{});
  }

private:
  ApplicationCertificate mClientCert;
  std::shared_ptr<const X509Certificate> mServerCert;
  // 0 == Status::Good == accept (default). Non-zero == the bad status the store rejects with.
  std::atomic<uint32_t> mValidateStatus{0};
  // 0 == Status::Good == own cert present (default). Non-zero == the store has no own cert to give.
  std::atomic<uint32_t> mOwnCertStatus{0};
  // Count of validate_certificate_async invocations (proves re-validation on renewal).
  std::atomic<std::size_t> mValidateCalls{0};
  // The request of the most recent validation, so a wiring test asserts what the client's OPN path built.
  mutable std::mutex mRequestMutex;
  optional<CertificateValidationRequest> mLastRequest;
  // The CertificateType the client last requested its own cert with (-1 = none yet). mutable: the
  // getter is const but must record the observed request for CL-ECC-001.
  mutable std::atomic<int> mRequestedCertType{-1};
};

// ---------------------------------------------------------------------------
// CryptoSecureChannelDeps - provides real crypto and cert store
// ---------------------------------------------------------------------------

class CryptoSecureChannelDeps : public SecureChannelDependencies
{
public:
  CryptoSecureChannelDeps(boost::asio::any_io_executor ex, std::shared_ptr<const Crypto> crypto,
    std::shared_ptr<CertificateStore> certStore)
    : mExecutor(ex), mAppCfg(ApplicationConfig::load_default()), mCrypto(std::move(crypto)),
      mCertStore(std::move(certStore))
  {
    // Populate the factory exactly as the real client does, so inbound responses (e.g. a forged
    // ReadResponse) can be created and decoded by receive_response_message.
    const ua::CodecNamespaceContext nsConfig{};
    ua::register_ua_data_types_with_factory(nsConfig, &mFactory, nullptr);
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return mCrypto;
  }

  shared_ptr<CertificateStore> certificate_store() override
  {
    return mCertStore;
  }

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  Logger logger() override
  {
    return mLogger;
  }

  /// Injects a logger so a test can capture what the client logs (default: a null, no-op logger,
  /// so existing tests are unaffected). Read lazily by the impl, so it may be set after create().
  void set_logger(Logger logger)
  {
    mLogger = std::move(logger);
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<CertificateStore> mCertStore;
  Logger mLogger;
};

// ---------------------------------------------------------------------------
// Synchronization state for callbacks
// ---------------------------------------------------------------------------

struct CryptoCallbackSync
{
  std::mutex mx;
  std::condition_variable cv;

  bool opened{false};
  StatusCode openedStatus{Status::Good};
  bool errorOccurred{false};
  StatusCode errorStatus{Status::Good};

  bool wait_opened(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return opened; });
  }

  bool wait_error(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return errorOccurred; });
  }
};

// ---------------------------------------------------------------------------
// ConnectionProtocol handshake sync
// ---------------------------------------------------------------------------

struct ConnHandshakeSync
{
  std::mutex mx;
  std::condition_variable cv;

  bool complete{false};
  StatusCode completeStatus{Status::Good};
  connection_protocol::NegotiatedLimits negotiatedLimits;
  std::shared_ptr<ConnectionProtocol> completedCp;

  bool errorOccurred{false};
  StatusCode errorStatus{Status::Good};

  bool wait_complete(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return complete; });
  }
};

// ---------------------------------------------------------------------------
// Build ACK frame
// ---------------------------------------------------------------------------

static std::vector<byte> build_ack(
  uint32_t protocolVersion, uint32_t recvBuf, uint32_t sendBuf, uint32_t maxMsg, uint32_t maxChunks)
{
  memory_stream_device::Dynamic streamDevice{connection_protocol::acknowledgeSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'A'});
  enc.encode(limit, uint8_t{'C'});
  enc.encode(limit, uint8_t{'K'});
  enc.encode(limit, uint8_t{'F'});
  enc.encode(limit, uint32_t{connection_protocol::acknowledgeSize});
  enc.encode(limit, protocolVersion);
  enc.encode(limit, recvBuf);
  enc.encode(limit, sendBuf);
  enc.encode(limit, maxMsg);
  enc.encode(limit, maxChunks);

  auto out = streamDevice.move_storage_out();
  out.resize(connection_protocol::acknowledgeSize);
  return out;
}

// ---------------------------------------------------------------------------
// WiredSecureChannelSetup - full wired setup with real crypto
// ---------------------------------------------------------------------------

struct WiredSecureChannelSetup
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const AsymmetricKeyPair> clientKeys;
  std::shared_ptr<const X509Certificate> clientCert;
  std::shared_ptr<const AsymmetricKeyPair> serverKeys;
  std::shared_ptr<const X509Certificate> serverCert;

  std::shared_ptr<CryptoSecureChannelDeps> deps;
  std::shared_ptr<TestCertificateStore> certStore;
  std::shared_ptr<FakeTransportConnection> transport;
  std::shared_ptr<FakeConnectionProtocolDeps> cpDeps;
  std::shared_ptr<ConnectionProtocol> connection;
  std::shared_ptr<ConnHandshakeSync> connSync;
  std::shared_ptr<CryptoCallbackSync> scSync;
  std::shared_ptr<SecureChannelImpl> impl;

  /// Create a wired setup with Basic256Sha256 SignAndEncrypt by default.
  static WiredSecureChannelSetup create(boost::asio::any_io_executor ex,
    MessageSecurityMode securityMode = MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId policyId = SecurityPolicyId::Basic256Sha256,
    const std::function<void(TestCertificateStore&)>& configureStore = {},
    CertificateKeyAlgorithm keyAlg = CertificateKeyAlgorithm::Rsa,
    CertificateSignatureAlgorithm sigAlg = CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateType certType = CertificateType::RsaSha256Application,
    std::shared_ptr<CertificateStore> trustStoreOverride = nullptr)
  {
    WiredSecureChannelSetup setup;

    // Create real crypto and PKI.
    setup.crypto = create_crypto();
    TestPki pki{setup.crypto};

    // A self-signed Application Instance Certificate for the given key/signature algorithm, with the
    // keyUsage OPC 10000-6 Table 43 requires of one: digitalSignature for every key, and for RSA also
    // nonRepudiation, keyEncipherment, dataEncipherment and the serverAuth/clientAuth purposes. A CA
    // certificate would not do: the peer's certificate is refused for its use when it falls short.
    auto makeCert = [&](const std::shared_ptr<const AsymmetricKeyPair>& keys,
                      std::string_view cn,
                      std::string_view serial) -> std::shared_ptr<const X509Certificate>
    {
      Crypto::CreateCertificateConfig params;
      params.subjectKeys = keys;
      params.issuerKeys = keys;
      params.subject.commonName = std::string{cn};
      params.serialNumber = std::string{serial};
      params.basicConstraint.cA = false;
      params.keyUsage.digitalSignature = true;
      if (keyAlg == CertificateKeyAlgorithm::Rsa)
      {
        params.keyUsage.nonRepudiation = true;
        params.keyUsage.keyEncipherment = true;
        params.keyUsage.dataEncipherment = true;
        params.keyUsage.serverAuth = true;
        params.keyUsage.clientAuth = true;
      }
      params.certificateSignatureAlgorithm = sigAlg;
      params.from = DateTime::now();
      params.to = DateTime{params.from.value() + std::chrono::days{365}};
      return pki.create_cert(params);
    };

    const auto keyBits =
      keyAlg == CertificateKeyAlgorithm::Rsa ? std::optional<std::size_t>{2048} : std::nullopt;
    setup.clientKeys = setup.crypto->create_asymmetric_key_pair_sync(keyAlg, keyBits);
    setup.clientCert = makeCert(setup.clientKeys, "TestClient", "200");

    setup.serverKeys = setup.crypto->create_asymmetric_key_pair_sync(keyAlg, keyBits);
    setup.serverCert = makeCert(setup.serverKeys, "TestServer", "201");

    // Create cert store with client cert.
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = certType;
    appCert.certificate = setup.clientCert;
    appCert.keys = setup.clientKeys;

    auto certStore = std::make_shared<TestCertificateStore>(std::move(appCert), setup.serverCert);
    setup.certStore = certStore;

    // Let the caller script the store (e.g. mark the own cert absent) BEFORE the channel open starts.
    if (configureStore)
    {
      configureStore(*certStore);
    }

    // Create deps with real crypto.
    setup.deps = std::make_shared<CryptoSecureChannelDeps>(ex, setup.crypto, certStore);

    // Create FakeTransportConnection + ConnectionProtocol (client role).
    setup.transport = std::make_shared<FakeTransportConnection>();
    setup.cpDeps = std::make_shared<FakeConnectionProtocolDeps>(ex);

    // Queue ACK so the HEL/ACK handshake completes.
    setup.transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

    setup.connSync = std::make_shared<ConnHandshakeSync>();

    auto syncPtr = setup.connSync;
    setup.connection = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      setup.cpDeps,
      setup.transport,
      false,
      60s,
      [syncPtr](StatusCode st,
        shared_ptr<ConnectionProtocol>
          cp,
        connection_protocol::NegotiatedLimits negotiated,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
          syncPtr->negotiatedLimits = negotiated;
          syncPtr->completedCp = std::move(cp);
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](StatusCode st, string_view /*reason*/, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
        }
        syncPtr->cv.notify_one();
      },
      "opc.tcp://localhost:4840");

    // Wait for HEL/ACK handshake to complete.
    EXPECT_TRUE(syncPtr->wait_complete(2s))
      << "ConnectionProtocol HEL/ACK handshake did not complete in time";
    EXPECT_TRUE(syncPtr->completeStatus.is_good())
      << "ConnectionProtocol handshake failed: " << syncPtr->completeStatus.as_uint32();

    // Now set message callbacks on the completed CP so SecureChannelImpl can use it.
    // SecureChannelImpl::initialise() calls set_callbacks on the CP, so we don't need
    // to register callbacks here - the SecureChannelImpl will do it.

    // Create the SecureChannelImpl.
    setup.scSync = std::make_shared<CryptoCallbackSync>();
    auto scSyncPtr = setup.scSync;

    SecureChannelImpl::Config config;
    config.securityMode = securityMode;
    config.securityPolicyId = policyId;
    config.endpointUrl = "opc.tcp://localhost:4840";
    config.serverCertificate = setup.serverCert;
    // W6b-1 (CL-PULLCRT-001): a per-open trust-store override. `nullptr` (the default) keeps the
    // deps runtime store as the server-cert validation store; a non-null store overrides it.
    config.trustStoreOverride = std::move(trustStoreOverride);

    setup.impl = SecureChannelImpl::create(
      setup.deps,
      setup.connection,
      syncPtr->negotiatedLimits,
      config,
      [scSyncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(scSyncPtr->mx);
          scSyncPtr->opened = true;
          scSyncPtr->openedStatus = result.status_code();
        }
        scSyncPtr->cv.notify_one();
      },
      [scSyncPtr](VoidResult result)
      {
        {
          std::lock_guard<std::mutex> lk(scSyncPtr->mx);
          scSyncPtr->errorOccurred = true;
          scSyncPtr->errorStatus = result.status_code();
        }
        scSyncPtr->cv.notify_one();
      });

    return setup;
  }
};

// ---------------------------------------------------------------------------
// Parse AsymmetricSecurityHeader from an OPN chunk
// ---------------------------------------------------------------------------

struct ParsedOpnChunk
{
  UaScMessageHeader header;
  AsymmetricSecurityHeader securityHeader;
  SequenceHeader sequenceHeader;
  size_t bodyOffset{0};
  size_t totalSize{0};
};

static ParsedOpnChunk parse_opn_chunk(span<const byte> chunk, const Crypto& crypto)
{
  memory_stream_device::ExternalReadOnly streamDevice{chunk};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  ParsedOpnChunk parsed;
  parsed.totalSize = chunk.size();

  parsed.header.decode(limits, dec);
  parsed.securityHeader.decode(limits, dec, crypto);
  // Note: sequence header and body may be encrypted, so we record position after security header.
  parsed.bodyOffset = stream.get_position();

  return parsed;
}

}  // namespace

// ---------------------------------------------------------------------------
// Test: OPN request is signed when using an authenticated security policy
// CL-SC-001 #30
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, OpnRequestHasSignatureStructure)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  // Wait for the OPN chunk to be written.
  // Write[0] = HEL (from ConnectionProtocol), Write[1] = OPN chunk (from SecureChannelImpl).
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s))
    << "Expected at least 2 writes (HEL + OPN) on the transport";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  // The OPN chunk is the second write.
  auto& opnChunk = writes[1];

  // An OPN chunk with SignAndEncrypt should be significantly larger than just the header
  // because it includes the asymmetric security header, encrypted body, padding, and signature.
  // The minimum size for the header alone (message header + asym header with cert + sequence header)
  // is several hundred bytes. With encryption and signature, the total should be well over 512 bytes.
  EXPECT_GT(opnChunk.size(), 512u) << "OPN chunk is too small to contain signature and encryption";

  // Parse the header and asymmetric security header (these are NOT encrypted in OPN).
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // Verify it is an OPN message.
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Open);
  EXPECT_EQ(parsed.header.isFinal, UaScMessageHeader::IsFinal::Final);

  // Verify the security policy URI is Basic256Sha256.
  EXPECT_NE(parsed.securityHeader.securityPolicyUri.find("Basic256Sha256"), std::string::npos)
    << "Expected Basic256Sha256 policy URI, got: " << parsed.securityHeader.securityPolicyUri;

  // Verify sender certificate is present (the client cert).
  EXPECT_NE(parsed.securityHeader.senderCertificate, nullptr)
    << "OPN chunk must contain the sender (client) certificate";

  // Verify receiver certificate thumbprint is present.
  EXPECT_FALSE(parsed.securityHeader.receiverCertificateThumbprint.empty())
    << "OPN chunk must contain the receiver (server) certificate thumbprint";

  // Verify the thumbprint matches the server cert.
  auto expectedThumbprint = setup.serverCert->thumbprint();
  EXPECT_EQ(parsed.securityHeader.receiverCertificateThumbprint, expectedThumbprint)
    << "Receiver thumbprint should match the server certificate";

  // The chunk size should be larger than the plaintext body would be, indicating
  // that a signature (and encryption) was applied. The RSA signature for 2048-bit keys
  // is 256 bytes. Check that the chunk has enough room after the body offset.
  size_t afterBodyBytes = parsed.totalSize - parsed.bodyOffset;
  EXPECT_GT(afterBodyBytes, 256u)
    << "After the body offset, there should be enough bytes for encrypted body + signature";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test: OPN request body is encrypted when using SignAndEncrypt mode
// CL-SC-002 #32
// ---------------------------------------------------------------------------

// @verifies CL-SC-002 [PARTIAL] Verified: the OPN request body is encrypted (not shipped as
// plaintext) for a policy != None channel - the OpenSecureChannelRequest type-id bytes
// 01 00 BE 01 are absent from the region after the (plaintext) AsymmetricSecurityHeader, and
// that region is not all-zero; exercised at Basic256Sha256 / SignAndEncrypt over the real
// SecureChannelImpl -> SecurityPolicy::encode_message -> ConnectionProtocol send path.
// Deferred: the "always encrypted" clause under Sign-only message security mode
// (OpnRequestHasSignatureStructureInSignOnlyMode asserts only chunk size, not plaintext-absence),
// and affirmative round-trip proof that the receiver's public key was the encryption key.
// @relation(CL-SC-002, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnRequestBodyNotPlaintextWhenPolicyNotNone)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s))
    << "Expected at least 2 writes (HEL + OPN) on the transport";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // In an encrypted OPN chunk, the body portion (after the asymmetric security header
  // and sequence header) is encrypted with the server's public key. We verify encryption
  // by checking that the body bytes do NOT contain the plaintext OPN request type ID.
  //
  // The OpenSecureChannelRequest type ID (in UA Binary) is encoded as an ExpandedNodeId.
  // The numeric ID is 446 for the OPN request encoding. If we can find this ID in the
  // body, the body is NOT encrypted.

  // The body starts at parsed.bodyOffset. For encrypted content, we should not be able
  // to find recognizable patterns. Check that no 4-byte window in the encrypted body
  // matches the OPN request encoding type id (446 = 0x01BE, encoded as a 4-byte node id).
  //
  // OPN request encoding ID 446 would appear as: 01 00 BE 01 (NodeId encoding for numeric ns=0).
  std::array<byte, 4> opnTypeId = {byte{0x01}, byte{0x00}, byte{0xBE}, byte{0x01}};

  span<const byte> bodySpan{opnChunk.data() + parsed.bodyOffset, opnChunk.size() - parsed.bodyOffset};

  bool foundPlaintext = false;
  if (bodySpan.size() >= 4)
  {
    for (size_t i = 0; i <= bodySpan.size() - 4; ++i)
    {
      if (bodySpan[i] == opnTypeId[0] && bodySpan[i + 1] == opnTypeId[1] && bodySpan[i + 2] == opnTypeId[2] &&
          bodySpan[i + 3] == opnTypeId[3])
      {
        foundPlaintext = true;
        break;
      }
    }
  }

  EXPECT_FALSE(foundPlaintext)
    << "OPN request body appears to contain plaintext type ID - encryption may not be applied";

  // Additionally verify the body is not all zeros (would indicate a bug).
  bool allZeros = true;
  for (size_t i = parsed.bodyOffset; i < opnChunk.size(); ++i)
  {
    if (opnChunk[i] != byte{0x00})
    {
      allZeros = false;
      break;
    }
  }
  EXPECT_FALSE(allZeros) << "Encrypted body should not be all zeros";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control arm of AC-CL-SC-002. Its sibling proves encryption by the ABSENCE of a byte pattern, and an
// absence oracle is worth only as much as the demonstration that the same scan finds the pattern when the
// body really is plaintext. This run differs from it in exactly one variable - the SecurityPolicy - and
// applies the identical scan over the identical region, asserting the pattern IS there.
// @verifies CL-SC-002
// @relation(CL-SC-002, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnRequestBodyIsPlaintextWhenPolicyNone)
{
  boost::asio::thread_pool tp;
  auto setup =
    WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::None, SecurityPolicyId::None);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // The same four bytes the encrypted arm searches for: the OpenSecureChannelRequest binary encoding id
  // 446, as a numeric four-byte NodeId in namespace 0.
  const std::array<byte, 4> opnTypeId = {byte{0x01}, byte{0x00}, byte{0xBE}, byte{0x01}};
  span<const byte> bodySpan{opnChunk.data() + parsed.bodyOffset, opnChunk.size() - parsed.bodyOffset};

  bool foundPlaintext = false;
  if (bodySpan.size() >= 4)
  {
    for (size_t i = 0; i <= bodySpan.size() - 4; ++i)
    {
      if (bodySpan[i] == opnTypeId[0] && bodySpan[i + 1] == opnTypeId[1] && bodySpan[i + 2] == opnTypeId[2] &&
          bodySpan[i + 3] == opnTypeId[3])
      {
        foundPlaintext = true;
        break;
      }
    }
  }

  EXPECT_TRUE(foundPlaintext)
    << "under SecurityPolicy None the OPN body is plaintext, so the scan its encrypted pair relies on must "
       "find the request type id here - otherwise that pair's absence oracle proves nothing";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test: Client nonce length matches policy (32 bytes for Basic256Sha256)
// CL-SC-005 #38
// ---------------------------------------------------------------------------

// @verifies CL-SC-005 [PARTIAL] Verified: under Basic256Sha256 the client-emitted clientNonce is
// exactly 32 bytes (that policy's SecureChannelNonceLength), non-zero, produced through the real
// mSecurityPolicy->nonce_length() -> mNonceLength -> get_entropy_async -> mLastClientNonce path
// (mLastClientNonce is the identical ByteString sent on the wire). Deferred: (a) other policies'
// nonce lengths (e.g. None=0, ECC variants); (b) that the length is genuinely DERIVED from the
// policy rather than the hardcoded `mNonceLength > 0 ? mNonceLength : 32` fallback (which equals
// 32, so a policy-length-mis-read-as-0 bug would still PASS this test).
// @relation(CL-SC-005, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientNonceLengthMatchesPolicyBasic256Sha256)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  // Wait for the OPN chunk to be sent (which means setup_and_open has completed
  // and stored the nonce in mLastClientNonce).
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s))
    << "Expected at least 2 writes (HEL + OPN) on the transport";

  // Access the last client nonce via test access.
  auto nonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });

  // Basic256Sha256 nonce_length is 32.
  EXPECT_EQ(nonce.size(), 32u) << "Client nonce for Basic256Sha256 should be exactly 32 bytes";

  // Verify nonce is not all zeros (real entropy was used).
  bool allZeros = true;
  for (size_t i = 0; i < nonce.size(); ++i)
  {
    if (nonce.data()[i] != 0)
    {
      allZeros = false;
      break;
    }
  }
  EXPECT_FALSE(allZeros) << "Client nonce should contain real entropy, not all zeros";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test: No certificate verification required when policy is None
// CL-SC-013
// ---------------------------------------------------------------------------

// @verifies CL-SC-013 [PARTIAL] Falsifiably covers the "certificates are not provided under
// SecurityPolicy None" clause: the real OPN produced by SecureChannelImpl (encoded by the None
// SecurityPolicy via drain_outgoing -> encode_message_async) carries no SenderCertificate and no
// ReceiverCertificateThumbprint. DEFERRED: the "shall not be verified" clause is only covered
// indirectly (a null certificate_store() plus a successful OPN send); no inbound OPN response is
// delivered, so the server-certificate verification path is never exercised and the test would
// still pass if the client wrongly verified a peer certificate under None.
// @relation(CL-SC-013, scope=function)
TEST(ClientSecureChannelCryptoTests, NoCertVerificationWhenPolicyNone)
{
  boost::asio::thread_pool tp;
  // Create a setup with SecurityPolicy None and no server certificate.
  // This should not require any certificate at all.
  auto crypto = create_crypto();

  auto deps = std::make_shared<CryptoSecureChannelDeps>(tp.get_executor(), crypto, nullptr);

  auto transport = std::make_shared<FakeTransportConnection>();
  auto cpDeps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());

  // Queue ACK for handshake.
  transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

  auto connSync = std::make_shared<ConnHandshakeSync>();
  auto connSyncPtr = connSync;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    cpDeps,
    transport,
    false,
    60s,
    [connSyncPtr](StatusCode st,
      shared_ptr<ConnectionProtocol>
        completedCp,
      connection_protocol::NegotiatedLimits negotiated,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->complete = true;
        connSyncPtr->completeStatus = st;
        connSyncPtr->negotiatedLimits = negotiated;
        connSyncPtr->completedCp = std::move(completedCp);
      }
      connSyncPtr->cv.notify_one();
    },
    [connSyncPtr](StatusCode st, string_view /*reason*/, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->errorOccurred = true;
        connSyncPtr->errorStatus = st;
      }
      connSyncPtr->cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  ASSERT_TRUE(connSync->wait_complete(2s)) << "ConnectionProtocol handshake did not complete";

  auto scSync = std::make_shared<CryptoCallbackSync>();
  auto scSyncPtr = scSync;

  SecureChannelImpl::Config config;
  config.securityMode = MessageSecurityMode::None;
  config.securityPolicyId = SecurityPolicyId::None;
  config.endpointUrl = "opc.tcp://localhost:4840";
  // No server certificate needed for None policy.

  auto impl = SecureChannelImpl::create(
    deps,
    cp,
    connSync->negotiatedLimits,
    config,
    [scSyncPtr](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(scSyncPtr->mx);
        scSyncPtr->opened = true;
        scSyncPtr->openedStatus = result.status_code();
      }
      scSyncPtr->cv.notify_one();
    },
    [scSyncPtr](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(scSyncPtr->mx);
        scSyncPtr->errorOccurred = true;
        scSyncPtr->errorStatus = result.status_code();
      }
      scSyncPtr->cv.notify_one();
    });

  // Wait for OPN to be sent (write[1] after HEL).
  ASSERT_TRUE(transport->wait_for_write_count(2, 3s))
    << "Expected OPN to be sent without certificate verification";

  auto writes = transport->writes();
  ASSERT_GE(writes.size(), 2u);

  // Parse the OPN chunk to verify it has policy None.
  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *crypto);

  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Open);

  // Security policy URI should contain "None".
  EXPECT_NE(parsed.securityHeader.securityPolicyUri.find("None"), std::string::npos)
    << "Expected None policy URI, got: " << parsed.securityHeader.securityPolicyUri;

  // No sender certificate for None policy.
  EXPECT_EQ(parsed.securityHeader.senderCertificate, nullptr)
    << "None policy should not include a sender certificate";

  // No receiver thumbprint for None policy.
  EXPECT_TRUE(parsed.securityHeader.receiverCertificateThumbprint.empty())
    << "None policy should not include a receiver thumbprint";

  // Channel should be in Opening state (waiting for OPN response).
  auto state = STA::on_strand(*impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Opening);
  impl.reset();
  cp.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test: OPN request with Sign mode has signature but body may be readable
// CL-SC-001 #30 (Sign mode variant)
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, OpnRequestHasSignatureStructureInSignOnlyMode)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::Sign);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s))
    << "Expected at least 2 writes (HEL + OPN) on the transport";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // Verify OPN message type.
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Open);

  // Verify sender cert and receiver thumbprint are present.
  EXPECT_NE(parsed.securityHeader.senderCertificate, nullptr)
    << "Sign mode OPN must include sender certificate";
  EXPECT_FALSE(parsed.securityHeader.receiverCertificateThumbprint.empty())
    << "Sign mode OPN must include receiver thumbprint";

  // For OPN messages, the body is ALWAYS encrypted with the server's public key
  // regardless of Sign vs SignAndEncrypt mode (per OPC UA spec Part 6).
  // So we verify the chunk is large enough to include signature.
  // RSA-2048 signature is 256 bytes.
  EXPECT_GT(opnChunk.size(), parsed.bodyOffset + 256u)
    << "OPN chunk should be large enough to include body + RSA signature";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Test: Authenticated channel sets is_authenticated flag and nonce length
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, AuthenticatedChannelSetsSecurityConfig)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  // Wait for OPN to be sent.
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  // Verify is_authenticated is set.
  EXPECT_TRUE(STA::on_strand(*setup.impl, [](auto& g) { return g.is_authenticated(); }))
    << "Channel with Basic256Sha256 should be marked as authenticated";

  // Verify nonce_length matches security policy.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.nonce_length(); }), 32u)
    << "Nonce length should be 32 for Basic256Sha256";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-006 #40: SecureChannelId zero for new channel creation
// (verified on the wire with real crypto)
// ---------------------------------------------------------------------------

// @verifies CL-SC-006
// @relation(CL-SC-006, scope=function)
TEST(ClientSecureChannelCryptoTests, IssueRequestHasSecureChannelIdZeroOnWire)
{
  // Spec: Part 4, 5.5.2 - SecureChannelId shall be null (0) when creating new channel.
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // The SecureChannelId in the message header should be 0 for an Issue request.
  EXPECT_EQ(parsed.header.secureChannelId, 0u) << "New channel OPN Issue must have SecureChannelId = 0";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-002 #55: SecurityPolicyUri length <= 255 bytes (on wire)
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, SecurityPolicyUriWithinLimitOnWire)
{
  // Spec: Part 6, 6.7.2 - SecurityPolicyUri shall not exceed 255 bytes.
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  EXPECT_LE(parsed.securityHeader.securityPolicyUri.size(), 255u)
    << "SecurityPolicyUri on wire must be <= 255 bytes, got: "
    << parsed.securityHeader.securityPolicyUri.size();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-003 #56: SenderCertificate fits in single chunk
// ---------------------------------------------------------------------------

// @verifies CL-UASC-003 (PARTIAL): drives the real client OPN encoder (SecureChannelImpl ->
// SecurityPolicy::encode_asymmetric, ua_security_policy.cpp) and falsifiably asserts ONLY that a
// normal single self-signed cert is emitted as a single Final MessageChunk (IsFinal==Final)
// carrying a non-null SenderCertificate. NOT verified here: the "leave room for at least one byte
// of BODY" clause (totalSize > bodyOffset+1 is tautological for an authenticated OPN - the region
// after the AsymmetricSecurityHeader is always the encrypted SequenceHeader+padding+signature,
// non-empty regardless of body) and the "(incl. chains)" clause (no chain sent, empty
// mIssuerCertificates). The size/room-for-body enforcement (the requirement's normative "shall be
// small enough") and the oversized-cert boundary are covered on the receiver decode path by
// UascSecurityPolicyTests.AsymmetricSenderCertificateMustLeaveRoomForBody
// (ua_security_policy.cpp:977-990, BadDecodingError on a bloated cert), not by this test.
// @relation(CL-UASC-003, scope=function)
TEST(ClientSecureChannelCryptoTests, SenderCertFitsInSingleChunk)
{
  // Spec: Part 6, 6.7.2 - SenderCertificate shall be small enough to fit in single chunk.
  // Our test uses a standard RSA-2048 cert which is well within limits.
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // The OPN was sent as a single chunk (IsFinal = Final).
  EXPECT_EQ(parsed.header.isFinal, UaScMessageHeader::IsFinal::Final)
    << "OPN with cert should fit in a single chunk";

  // Verify the sender certificate is present and valid.
  EXPECT_NE(parsed.securityHeader.senderCertificate, nullptr);

  // Verify there's at least 1 byte of body after the security header.
  EXPECT_GT(parsed.totalSize, parsed.bodyOffset + 1)
    << "There must be room for at least 1 byte of body after the security header";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-008 #64: ReceiverCertificateThumbprint matches client cert
// (verification that server's OPN response thumbprint would match our cert)
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, ReceiverThumbprintMatchesServerCert)
{
  // Spec: Part 6, 6.7.6 - ReceiverCertificateThumbprint must match server cert.
  // For client-side OPN *requests*, the receiver is the server.
  // Verify the thumbprint in our outgoing OPN matches the server cert we configured.
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  auto expectedThumbprint = setup.serverCert->thumbprint();
  EXPECT_EQ(parsed.securityHeader.receiverCertificateThumbprint, expectedThumbprint)
    << "Receiver thumbprint in OPN request must match the configured server certificate";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-007 #62: SecurityPolicy in OPN matches configured policy
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, OpnPolicyMatchesConfiguredPolicy)
{
  // Spec: Part 6, 6.7.6 - SecurityPolicy in OPN must match the configured policy.
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(
    tp.get_executor(), MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  EXPECT_EQ(
    parsed.securityHeader.securityPolicyUri, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
    << "OPN SecurityPolicyUri must match the configured policy";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-015 #76: Client nonce is cryptographic random (with real crypto)
// ---------------------------------------------------------------------------

// @verifies CL-UASC-015 (PARTIAL): drives the real client OPN nonce path
// (SecureChannelImpl::start_open sets mNonceLength = mSecurityPolicy->nonce_length(),
// then generate_nonce_async -> Crypto::get_entropy_async produces mLastClientNonce) and
// asserts the client nonce is exactly 32 bytes (Basic256Sha256 SecureChannelNonceLength)
// and that two independently generated nonces differ (cryptographic-random proxy over the
// real entropy source).
// DEFERRED: the length is only checked for Basic256Sha256, so with the hardcoded-32
// fallback (nonceLen = mNonceLength > 0 ? mNonceLength : 32) the test would still pass even
// if the policy-derivation broke - it does not prove the length tracks other policies'
// SecureChannelNonceLength; and "cryptographic random" is a two-sample difference proxy,
// not statistical-quality verification.
// @relation(CL-UASC-015, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientNonceIsCryptographicRandomWithRealCrypto)
{
  // Spec: Part 6, 6.7.4 - Nonces shall be cryptographic random.
  // Generate two channels and verify their nonces differ (with very high probability).
  boost::asio::thread_pool tp;
  auto setup1 = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup1.transport->wait_for_write_count(2, 3s));

  auto setup2 = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup2.transport->wait_for_write_count(2, 3s));

  auto nonce1 = STA::on_strand(*setup1.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  auto nonce2 = STA::on_strand(*setup2.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });

  ASSERT_EQ(nonce1.size(), 32u);
  ASSERT_EQ(nonce2.size(), 32u);

  // Two independently generated 32-byte nonces should differ.
  EXPECT_NE(nonce1, nonce2) << "Two independently generated nonces should differ";
  setup1.impl.reset();
  setup1.connection.reset();
  setup2.impl.reset();
  setup2.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-004 #36: Client nonce different on Issue and Renew (with real crypto)
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, ClientNonceLengthZeroForPolicyNoneOnWire)
{
  // Spec: Part 4, 5.5.2 - For SecurityPolicy None, clientNonce should be empty.
  boost::asio::thread_pool tp;
  // Create with None policy.
  auto crypto = create_crypto();
  auto deps = std::make_shared<CryptoSecureChannelDeps>(tp.get_executor(), crypto, nullptr);

  auto transport = std::make_shared<FakeTransportConnection>();
  auto cpDeps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

  auto connSync = std::make_shared<ConnHandshakeSync>();
  auto connSyncPtr = connSync;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    cpDeps,
    transport,
    false,
    60s,
    [connSyncPtr](StatusCode st,
      shared_ptr<ConnectionProtocol>
        completedCp,
      connection_protocol::NegotiatedLimits negotiated,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->complete = true;
        connSyncPtr->completeStatus = st;
        connSyncPtr->negotiatedLimits = negotiated;
        connSyncPtr->completedCp = std::move(completedCp);
      }
      connSyncPtr->cv.notify_one();
    },
    [connSyncPtr](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->errorOccurred = true;
        connSyncPtr->errorStatus = st;
      }
      connSyncPtr->cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  ASSERT_TRUE(connSync->wait_complete(2s));

  SecureChannelImpl::Config config;
  config.securityMode = MessageSecurityMode::None;
  config.securityPolicyId = SecurityPolicyId::None;
  config.endpointUrl = "opc.tcp://localhost:4840";

  auto impl = SecureChannelImpl::create(
    deps, cp, connSync->negotiatedLimits, config, [](VoidResult) {}, [](VoidResult) {});

  ASSERT_TRUE(transport->wait_for_write_count(2, 3s));

  // For None policy, client nonce should be empty.
  auto nonce = STA::on_strand(*impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  EXPECT_TRUE(nonce.empty()) << "Client nonce for SecurityPolicy None should be empty";

  // Verify unauthenticated flag.
  EXPECT_FALSE(STA::on_strand(*impl, [](auto& g) { return g.is_authenticated(); }))
    << "None policy should not be authenticated";
  impl.reset();
  cp.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-001 #31: OPN request not signed when policy is None (on wire)
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelCryptoTests, OpnRequestNotSignedWhenPolicyNone)
{
  // Spec: Part 4, 5.5.2 - OPN with SecurityPolicy None should not have signature.
  boost::asio::thread_pool tp;
  auto crypto = create_crypto();
  auto deps = std::make_shared<CryptoSecureChannelDeps>(tp.get_executor(), crypto, nullptr);

  auto transport = std::make_shared<FakeTransportConnection>();
  auto cpDeps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

  auto connSync = std::make_shared<ConnHandshakeSync>();
  auto connSyncPtr = connSync;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    cpDeps,
    transport,
    false,
    60s,
    [connSyncPtr](StatusCode st,
      shared_ptr<ConnectionProtocol>
        completedCp,
      connection_protocol::NegotiatedLimits negotiated,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->complete = true;
        connSyncPtr->completeStatus = st;
        connSyncPtr->negotiatedLimits = negotiated;
        connSyncPtr->completedCp = std::move(completedCp);
      }
      connSyncPtr->cv.notify_one();
    },
    [connSyncPtr](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(connSyncPtr->mx);
        connSyncPtr->errorOccurred = true;
        connSyncPtr->errorStatus = st;
      }
      connSyncPtr->cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  ASSERT_TRUE(connSync->wait_complete(2s));

  SecureChannelImpl::Config config;
  config.securityMode = MessageSecurityMode::None;
  config.securityPolicyId = SecurityPolicyId::None;
  config.endpointUrl = "opc.tcp://localhost:4840";

  auto impl = SecureChannelImpl::create(
    deps, cp, connSync->negotiatedLimits, config, [](VoidResult) {}, [](VoidResult) {});

  ASSERT_TRUE(transport->wait_for_write_count(2, 3s));

  auto writes = transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *crypto);

  // For None policy: no sender cert, no thumbprint.
  EXPECT_EQ(parsed.securityHeader.senderCertificate, nullptr);
  EXPECT_TRUE(parsed.securityHeader.receiverCertificateThumbprint.empty());

  // The None-policy OPN body is not encrypted and not signed.
  // The body should be small - just the OPN request with no padding/signature overhead.
  // For a None policy OPN, the total chunk size should be relatively small
  // (no RSA signature = no 256 bytes overhead).
  size_t afterBody = parsed.totalSize - parsed.bodyOffset;
  EXPECT_LT(afterBody, 200u)
    << "None-policy OPN should not have RSA signature overhead (body after header should be < 200 bytes)";
  impl.reset();
  cp.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ===========================================================================
// Additional wire-level requirement coverage (appended).
//
// These tests reuse the existing WiredSecureChannelSetup (real Crypto + TestPki +
// FakeTransportConnection + real ConnectionProtocol + SecureChannelImpl), parse_opn_chunk,
// make_nonce, test_limits, and SecureChannelTestAccess helpers defined above.
// ===========================================================================

#include "run_async_sync.h"
#include "server_chunk_forge.h"

#include "ua_close_secure_channel_request.h"
#include "ua_expanded_node_id.h"
#include "ua_open_secure_channel_request.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_secure_channel_context.h"

namespace
{

/// Plaintext framing of a symmetric (established-channel) chunk. The message header and symmetric
/// security header (carrying the token id) are always plaintext; the sequence header read here is
/// only meaningful when the chunk itself is unencrypted (SecurityPolicy None).
struct DecodedSymmetricChunkHeader
{
  UaScMessageHeader header;
  SymmetricSecurityHeader securityHeader;
  SequenceHeader sequenceHeader;
};

static DecodedSymmetricChunkHeader parse_symmetric_chunk_header(span<const byte> chunk)
{
  memory_stream_device::ExternalReadOnly streamDevice{chunk};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  DecodedSymmetricChunkHeader out;
  out.header.decode(limits, dec);
  out.securityHeader.decode(limits, dec);
  out.sequenceHeader.decode(limits, dec);
  return out;
}

/// Decode a plaintext (SecurityPolicy None) OpenSecureChannelRequest body from an OPN chunk. Only
/// valid for the None policy, where the OPN body is not encrypted.
static OpenSecureChannelRequest decode_plaintext_opn_request(span<const byte> chunk, const Crypto& crypto)
{
  memory_stream_device::ExternalReadOnly streamDevice{chunk};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  UaScMessageHeader header;
  header.decode(limits, dec);
  AsymmetricSecurityHeader securityHeader;
  securityHeader.decode(limits, dec, crypto);
  SequenceHeader sequenceHeader;
  sequenceHeader.decode(limits, dec);

  auto depth = limits.stack_depth();
  ExpandedNodeId typeId;
  dec.decode(depth, typeId);
  OpenSecureChannelRequest request;
  dec.decode(depth, request);
  return request;
}

/// Drive a valid OPN response onto an authenticated channel that has already sent its OPN-Issue,
/// deriving real symmetric keys and opening the channel. Returns once the opened callback fires.
static void open_authenticated_channel(WiredSecureChannelSetup& setup, uint32_t secureChannelId,
  uint32_t tokenId, std::chrono::milliseconds revisedLifetime, ByteString serverNonce)
{
  STA::on_strand(*setup.impl,
    [&](auto& g)
    {
      g.handle_opn_response(
        StatusCode{Status::Good}, secureChannelId, tokenId, revisedLifetime, serverNonce, nullptr);
    });
}

}  // namespace

// ---------------------------------------------------------------------------
// CL-UASC-001: SequenceNumber is incremented by exactly one per chunk sent.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-001
// @relation(CL-UASC-001, scope=function)
TEST(ClientSecureChannelCryptoTests, SequenceNumberIncrementsByOnePerChunk)
{
  // Use SecurityPolicy None so the sequence header of each established-channel chunk is plaintext
  // and can be read directly from the wire.
  boost::asio::thread_pool tp;
  auto setup =
    WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::None, SecurityPolicyId::None);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Open the channel (None policy: empty server nonce is accepted, no key derivation).
  open_authenticated_channel(setup, /*secureChannelId*/ 5, /*tokenId*/ 1, 600000ms, ByteString{});
  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "None-policy channel should open on a good OPN response";

  // Send two service requests; each is a single established-channel chunk.
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), [](auto) {});
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), [](auto) {});

  ASSERT_TRUE(setup.transport->wait_for_write_count(4, 3s))
    << "Expected HEL + OPN + two service-request chunks";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 4u);

  const auto firstSeq =
    parse_symmetric_chunk_header(span<const byte>{writes[2]}).sequenceHeader.sequenceNumber;
  const auto secondSeq =
    parse_symmetric_chunk_header(span<const byte>{writes[3]}).sequenceHeader.sequenceNumber;

  EXPECT_EQ(secondSeq, firstSeq + 1)
    << "SequenceNumber must be incremented by exactly one for each MessageChunk sent";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-013: ClientProtocolVersion in the OPN request is 0 (matches Hello).
// ---------------------------------------------------------------------------

// @verifies CL-UASC-013
// @relation(CL-UASC-013, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnClientProtocolVersionIsZeroOnWire)
{
  // SecurityPolicy None keeps the OPN body plaintext so the request can be decoded directly.
  boost::asio::thread_pool tp;
  auto setup =
    WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::None, SecurityPolicyId::None);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto request = decode_plaintext_opn_request(span<const byte>{writes[1]}, *setup.crypto);

  // The obligation is a *relation* between two frames, so read the Hello rather than a literal: writes[0]
  // is the HELF, whose ProtocolVersion is the four little-endian bytes following the 8-byte message header.
  // Asserting against a constant would fail on a conforming client that raised both, and pass on a divergent
  // one that raised only the Hello.
  ASSERT_GE(writes[0].size(), 12u);
  ASSERT_EQ(static_cast<char>(writes[0][0]), 'H');
  const auto helloProtocolVersion =
    static_cast<uint32_t>(writes[0][8]) | (static_cast<uint32_t>(writes[0][9]) << 8) |
    (static_cast<uint32_t>(writes[0][10]) << 16) | (static_cast<uint32_t>(writes[0][11]) << 24);

  EXPECT_EQ(request.client_protocol_version(), helloProtocolVersion)
    << "OPN ClientProtocolVersion must equal the ProtocolVersion the Hello put on the wire";
  EXPECT_EQ(helloProtocolVersion, 0u) << "this version of the standard negotiates ProtocolVersion 0";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-014: AuthenticationToken in the OPN RequestHeader is null.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-014
// @relation(CL-UASC-014, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnRequestAuthenticationTokenIsNull)
{
  boost::asio::thread_pool tp;
  auto setup =
    WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::None, SecurityPolicyId::None);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto request = decode_plaintext_opn_request(span<const byte>{writes[1]}, *setup.crypto);

  EXPECT_TRUE(request.request_header().authentication_token().is_null())
    << "OPN RequestHeader.AuthenticationToken must be set to null";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-009: The current tokenId is carried with each secured (symmetric) message.
// ---------------------------------------------------------------------------

// @verifies CL-SC-009
// @relation(CL-SC-009, scope=function)
TEST(ClientSecureChannelCryptoTests, SymmetricMessageCarriesCurrentTokenId)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  // Open with a real 32-byte server nonce so symmetric session keys derive and the channel opens.
  const uint32_t issuedTokenId = 4242;
  open_authenticated_channel(
    setup, /*secureChannelId*/ 88, issuedTokenId, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "Authenticated channel should open on a good OPN response";

  // The stored token id should be the one from the OPN response.
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), issuedTokenId);

  // Send a service request; its symmetric security header must carry the current token id.
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), [](auto) {});
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s));

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 3u);

  auto parsed = parse_symmetric_chunk_header(span<const byte>{writes[2]});
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Message);
  EXPECT_EQ(parsed.securityHeader.tokenId, issuedTokenId)
    << "Each secured message must carry the active SecurityToken id";
  EXPECT_EQ(
    parsed.securityHeader.tokenId, STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }));
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-004: A fresh clientNonce is generated for each SecureChannel renewal.
// ---------------------------------------------------------------------------

// @verifies CL-SC-004
// @relation(CL-SC-004, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientNonceDiffersBetweenIssueAndRenew)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  // Open the channel so a renewal can be driven on it.
  open_authenticated_channel(
    setup, /*secureChannelId*/ 42, /*tokenId*/ 7, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  auto nonceIssue = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(nonceIssue.size(), 32u);

  // Drive a renewal on the SAME channel: a new clientNonce must be generated and an OPN-Renew sent.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s)) << "Renewal should emit an OPN-Renew chunk";

  auto nonceRenew = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(nonceRenew.size(), 32u);

  EXPECT_NE(nonceIssue, nonceRenew) << "A new clientNonce must be generated for each SecureChannel renewal";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-008: Renewal uses the SecureChannelId assigned in the Issue response.
// ---------------------------------------------------------------------------

// @verifies CL-SC-008
// @relation(CL-SC-008, scope=function)
TEST(ClientSecureChannelCryptoTests, RenewUsesChannelIdFromIssueResponse)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t issuedChannelId = 90210;
  open_authenticated_channel(setup, issuedChannelId, /*tokenId*/ 7, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  // Drive a renewal; capture the OPN-Renew chunk.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s));

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 3u);

  // The OPN message header (plaintext) of the renewal must carry the issued SecureChannelId.
  auto parsed = parse_opn_chunk(span<const byte>{writes[2]}, *setup.crypto);
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Open);
  EXPECT_EQ(parsed.header.secureChannelId, issuedChannelId)
    << "OPN-Renew must reuse the SecureChannelId assigned in the Issue response";
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-005: The SDK sends the certificate provided by the certificate store.
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-005
// @relation(CL-SECADMIN-005, scope=function)
TEST(ClientSecureChannelCryptoTests, SenderCertificateMatchesStoreProvidedCertificate)
{
  boost::asio::thread_pool tp;

  // Each WiredSecureChannelSetup builds its own client Application Instance Certificate and injects
  // it via the certificate store. Two setups therefore present two different certificates.
  auto setupA = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setupA.transport->wait_for_write_count(2, 3s));
  auto writesA = setupA.transport->writes();
  ASSERT_GE(writesA.size(), 2u);
  auto parsedA = parse_opn_chunk(span<const byte>{writesA[1]}, *setupA.crypto);

  auto setupB = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setupB.transport->wait_for_write_count(2, 3s));
  auto writesB = setupB.transport->writes();
  ASSERT_GE(writesB.size(), 2u);
  auto parsedB = parse_opn_chunk(span<const byte>{writesB[1]}, *setupB.crypto);

  ASSERT_NE(parsedA.securityHeader.senderCertificate, nullptr);
  ASSERT_NE(parsedB.securityHeader.senderCertificate, nullptr);

  // Each OPN carries the certificate that its own store provided...
  EXPECT_EQ(parsedA.securityHeader.senderCertificate->thumbprint(), setupA.clientCert->thumbprint())
    << "OPN SenderCertificate must be the store-provided Application Instance Certificate (A)";
  EXPECT_EQ(parsedB.securityHeader.senderCertificate->thumbprint(), setupB.clientCert->thumbprint())
    << "OPN SenderCertificate must be the store-provided Application Instance Certificate (B)";

  // ...and the two distinct stores yield two distinct on-wire certificates (no hard-coded cert).
  EXPECT_NE(parsedA.securityHeader.senderCertificate->thumbprint(),
    parsedB.securityHeader.senderCertificate->thumbprint());
  setupA.impl.reset();
  setupA.connection.reset();
  setupB.impl.reset();
  setupB.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-009: The client supports BOTH mandated policies - Aes128Sha256RsaOaep AND
// Basic256Sha256 (the requirement is conjunctive). This test opens a channel under each and asserts
// the negotiated OPN carries the corresponding policy URI, so dropping either policy fails it.
// (The reject-unknown-policy-URI negative sits at the ConnectionConfig/URI layer, not the
// SecureChannelImpl enum-typed harness, and is therefore not falsifiable in this fixture.)
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-009
// @relation(CL-SECADMIN-009, scope=function)
TEST(ClientSecureChannelCryptoTests, SupportsAes128Sha256RsaOaepPolicy)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(
    tp.get_executor(), MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes128Sha256RsaOaep);

  // A sent OPN proves the SDK built and negotiated the Aes128Sha256RsaOaep channel.
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s))
    << "Aes128Sha256RsaOaep OPN should be sent on the transport";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto parsed = parse_opn_chunk(span<const byte>{writes[1]}, *setup.crypto);
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Open);
  EXPECT_NE(parsed.securityHeader.securityPolicyUri.find("Aes128"), std::string::npos)
    << "OPN SecurityPolicyUri must name the Aes128Sha256RsaOaep policy, got: "
    << parsed.securityHeader.securityPolicyUri;

  // Authenticated-channel invariants still hold for this policy.
  EXPECT_NE(parsed.securityHeader.senderCertificate, nullptr);
  EXPECT_EQ(parsed.securityHeader.receiverCertificateThumbprint, setup.serverCert->thumbprint());

  // Conjunct 2: the client must ALSO support Basic256Sha256. Open a second channel under it and
  // assert its OPN URI names Basic256Sha256 - so a client that dropped Basic256Sha256 fails here.
  auto basicSetup = WiredSecureChannelSetup::create(
    tp.get_executor(), MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(basicSetup.transport->wait_for_write_count(2, 3s))
    << "Basic256Sha256 OPN should be sent on the transport";
  auto basicWrites = basicSetup.transport->writes();
  ASSERT_GE(basicWrites.size(), 2u);
  auto basicParsed = parse_opn_chunk(span<const byte>{basicWrites[1]}, *basicSetup.crypto);
  EXPECT_NE(basicParsed.securityHeader.securityPolicyUri.find("Basic256Sha256"), std::string::npos)
    << "OPN SecurityPolicyUri must name the Basic256Sha256 policy, got: "
    << basicParsed.securityHeader.securityPolicyUri;
  basicSetup.impl.reset();
  basicSetup.connection.reset();

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-001: The OPN request is signed with the client's private key.
// The signature is located inside the (server-key-encrypted) region, decrypted with the server's
// private key, then verified against the CLIENT's public key over the signed region. A negative
// cross-check confirms a different key does NOT verify, proving the client key is required.
// ---------------------------------------------------------------------------

// @verifies CL-SC-001
// @relation(CL-SC-001, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnRequestSignatureVerifiesWithClientPublicKey)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // A server-side decrypt context: the server certificate/key pair decrypt the encrypted region.
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = setup.crypto;
  context->securityPolicy = policy;
  context->localCertificate = setup.serverCert;
  context->localKeyPair = setup.serverKeys;
  context->encodingLimits = test_limits();

  // Decrypt the encrypted region (everything from the sequence-header offset onward). The returned
  // buffer is: [plaintext headers][SequenceHeader | Body | Padding | Signature].
  auto decrypted = ua::test_helpers::run_async_callback_sync<ByteStringResult>(
    [&](auto cb) {
      policy->asymmetric_decrypt_async(
        *context, span<const byte>{opnChunk}, parsed.bodyOffset, std::move(cb));
    }).value();

  const size_t signatureSize = policy->asymmetric_signature_size(setup.clientCert.get());
  ASSERT_GT(decrypted.size(), signatureSize);

  span<const byte> decryptedBytes = decrypted;
  span<const byte> signedRegion = decryptedBytes.subspan(0, decrypted.size() - signatureSize);
  span<const byte> signature = decryptedBytes.subspan(decrypted.size() - signatureSize, signatureSize);

  auto clientPublicKey = setup.clientCert->public_key();
  auto serverPublicKey = setup.serverCert->public_key();
  auto algorithm = policy->asymmetric_signature_algorithm();

  // The client's public key verifies the signature: the OPN was signed with the client private key.
  EXPECT_NO_THROW(setup.crypto->asymmetric_verify_sync(algorithm, clientPublicKey, signedRegion, signature));
  // A different key (the server's) must NOT verify, proving the client key is the signer.
  EXPECT_ANY_THROW(setup.crypto->asymmetric_verify_sync(algorithm, serverPublicKey, signedRegion, signature));
  context.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CLO token-binding: the CloseSecureChannel request is framed with the CURRENT SecurityToken id.
// NOTE: this does NOT verify CL-SC-014, whose obligation is that the CLO be SIGNED with the current
// token's key - the MAC is produced from the internal derived session key and is not externally
// re-derivable in this harness, so the signing obligation is untestable here. CL-SC-014 therefore
// remains uncovered (needs a signature-verification interface or a MisbehavingServer integration row).
// This test verifies only the externally observable token-id binding of the CLO chunk.
// ---------------------------------------------------------------------------
TEST(ClientSecureChannelCryptoTests, CloseRequestCarriesCurrentTokenId)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t issuedTokenId = 555;
  open_authenticated_channel(
    setup, /*secureChannelId*/ 88, issuedTokenId, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  // Request a channel close; the client must emit a CLO chunk secured with the current token.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_close_requested(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s)) << "close should emit a CLO chunk";

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 3u);

  auto parsed = parse_symmetric_chunk_header(span<const byte>{writes[2]});
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Close)
    << "The close chunk must be framed as a CLO message";
  EXPECT_EQ(parsed.securityHeader.tokenId, issuedTokenId)
    << "CLO must be secured with the current SecurityToken id";
  EXPECT_EQ(
    parsed.securityHeader.tokenId, STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }));
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-ECC-001 (Part 6 section 6.8.2): the client selects its own ApplicationInstance Certificate by the
// SecurityPolicy's curve-distinguishing certificate_type(). Over an ECC nistP256 channel it requests
// EccNistP256Application; over Basic256Sha256 it requests RsaSha256Application. Drives the real
// client cert-selection path (SecureChannelImpl -> certStore->get_application_certificate_async(
// mSecurityPolicy->certificate_type()), ua_client_secure_channel_impl.cpp:316); the observing
// TestCertificateStore records the requested type. Falsifiable: a client that ignored the policy curve
// (requested a generic/RSA type on the ECC channel) fails the EccNistP256Application assertion; the RSA
// contrast fails if the type were hard-coded.
// ---------------------------------------------------------------------------

// @verifies CL-ECC-001
// @relation(CL-ECC-001, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientSelectsOwnCertByPolicyCurveSpecificType)
{
  auto observeRequestedType = [](WiredSecureChannelSetup& setup)
  {
    for (int i = 0; i < 400 && !setup.certStore->requested_certificate_type().has_value(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    return setup.certStore->requested_certificate_type();
  };

  // ECC nistP256 channel: the client must request the curve-specific ECC application cert type.
  {
    boost::asio::thread_pool tp;
    auto ecc = WiredSecureChannelSetup::create(tp.get_executor(),
      MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::EccNistP256AesGcm,
      {},
      CertificateKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      CertificateType::EccNistP256Application);
    auto eccType = observeRequestedType(ecc);
    ASSERT_TRUE(eccType.has_value()) << "the client must request its own certificate during open";
    EXPECT_EQ(*eccType, CertificateType::EccNistP256Application)
      << "an ECC nistP256 channel must select the curve-specific EccNistP256Application cert type";
    ecc.impl.reset();
    ecc.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }

  // Contrast: a Basic256Sha256 (RSA) channel selects the RSA application cert type.
  {
    boost::asio::thread_pool tp;
    auto rsa = WiredSecureChannelSetup::create(
      tp.get_executor(), MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    auto rsaType = observeRequestedType(rsa);
    ASSERT_TRUE(rsaType.has_value());
    EXPECT_EQ(*rsaType, CertificateType::RsaSha256Application)
      << "a Basic256Sha256 channel must select the RSA application cert type (curve-distinguishing)";
    rsa.impl.reset();
    rsa.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// ---------------------------------------------------------------------------
// CL-ECC-002 (Part 6 section 6.8.3): "The EphemeralKeys may be used for exactly one key negotiation. After
// that they are discarded." For an ECC channel the client's OPN nonce IS a freshly generated ephemeral
// public key (is_ecc() -> create_ephemeral_keys_async, ua_client_secure_channel_impl.cpp:1609;
// mLastClientNonce = ephemeral public key). Two independent ECC opens must carry DISTINCT ephemerals
// (a fresh key per negotiation), and the nonce is an ECC public key (not a 32-byte random nonce).
// Falsifiable: a client reusing a fixed/cached ephemeral yields identical nonces; a client emitting a
// plain 32-byte nonce fails the size check.
// @verifies CL-ECC-002 (PARTIAL): proves a fresh ECC ephemeral public key is generated per OPN. The
// same-channel renewal-discards-old-key facet (a Renew OPN allocates a new ephemeral) needs a completed ECC
// handshake + renewal and is deferred.
// ---------------------------------------------------------------------------

// @verifies CL-ECC-002
// @relation(CL-ECC-002, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientGeneratesFreshEccEphemeralPerOpn)
{
  auto eccEphemeral = [](boost::asio::thread_pool& tp) -> ByteString
  {
    auto setup = WiredSecureChannelSetup::create(tp.get_executor(),
      MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::EccNistP256AesGcm,
      {},
      CertificateKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      CertificateType::EccNistP256Application);
    ByteString nonce;
    for (int i = 0; i < 400; ++i)
    {
      nonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
      if (!nonce.empty())
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    setup.impl.reset();
    setup.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
    return nonce;
  };

  boost::asio::thread_pool tp1;
  boost::asio::thread_pool tp2;
  auto e1 = eccEphemeral(tp1);
  auto e2 = eccEphemeral(tp2);

  ASSERT_FALSE(e1.empty()) << "the client must generate an ECC ephemeral for the OPN nonce";
  ASSERT_FALSE(e2.empty());
  EXPECT_NE(e1, e2) << "each OPN must use a freshly generated ECC ephemeral (not a fixed/reused key)";
  EXPECT_GT(e1.size(), 32u)
    << "the ECC OPN nonce is an ephemeral public key, not a 32-byte random nonce (size " << e1.size() << ")";
}

// ---------------------------------------------------------------------------
// CL-TCP-012 (Part 6, 7.1.2.4): an outgoing request that cannot be sent within the negotiated
// MaxChunkCount / send-buffer must be rejected up-front with BadResponseTooLarge - NOT a generic
// BadUnexpectedError. Two cases, both driven through the real client send/encode path
// (send_request -> encode_symmetric_message_async):
//   (1) tiny send buffer (underflow range): maxChunkBodySize wrapped/zeroed and bypassed the chunk-count
//       check, so the emit threw StreamCapacityExceeded (BadUnexpectedError). The guard now surfaces
//       BadResponseTooLarge. RED before the fix.
//   (2) realistic buffer + sendMaxChunkCount=1 + a genuinely multi-chunk request: the chunk-count check
//       fires and surfaces BadResponseTooLarge (already correct; guards against a regression).
// ---------------------------------------------------------------------------

namespace
{
// Forces the negotiated send limits on the open channel's context and sends one ReadRequest, returning
// the callback status.
ua::StatusCode send_read_with_send_limits(
  WiredSecureChannelSetup& setup, uint32_t sendBufferSize, uint32_t maxSendChunks, std::size_t readValueIds)
{
  STA::on_strand(*setup.impl,
    [&](auto& g)
    {
      g.context()->negotiatedLimits.sendBufferSize = sendBufferSize;
      g.context()->negotiatedLimits.sendMaxChunkCount = maxSendChunks;
    });
  auto request = std::make_shared<ua::ReadRequest>();
  request->nodes_to_read().payload().resize(readValueIds);
  for (std::size_t i = 0; i < readValueIds; ++i)
  {
    request->nodes_to_read().payload()[i].node_id() =
      ua::NodeId{uint16_t{0}, static_cast<uint32_t>(1000 + i)};
    request->nodes_to_read().payload()[i].attribute_id() = 13;  // Value
  }
  auto promise = std::make_shared<std::promise<ua::StatusCode>>();
  auto future = promise->get_future();
  setup.impl->send_request(request, [promise](auto result) { promise->set_value(result.status_code()); });
  if (future.wait_for(3s) != std::future_status::ready)
  {
    return ua::StatusCode{Status::BadTimeout};
  }
  return future.get();
}
}  // namespace

// Opens a Basic256Sha256 SignAndEncrypt channel and returns the callback status of one ReadRequest sent
// under the given forced send limits, tearing the setup down before returning.
ua::StatusCode open_and_send_with_send_limits(
  boost::asio::thread_pool& tp, uint32_t sendBufferSize, uint32_t maxSendChunks, std::size_t readValueIds)
{
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, /*channelId=*/88, /*tokenId=*/4242, 600000ms, serverNonce);
  EXPECT_TRUE(setup.scSync->wait_opened(2s));

  auto status = send_read_with_send_limits(setup, sendBufferSize, maxSendChunks, readValueIds);

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return status;
}

// @verifies CL-TCP-012 [PARTIAL] - covers only the small-send-buffer cause: a buffer too small to hold even
// one chunk made the per-branch maxChunkBodySize wrap (or zero, for None) and bypass the chunk-count
// check, so the emit threw StreamCapacityExceeded (BadUnexpectedError) and, for None, risked a
// divide-by-zero. The guard in encode_symmetric_message_async rejects up-front with BadResponseTooLarge.
// The deeper cause - a whole-message encode buffer that collapsed to a single send buffer when the peer
// advertised MaxMessageSize=0 (unlimited), so every multi-chunk message failed to serialize - is now fixed
// in encode_unknown_message_async and covered by the three tests immediately below.
// @relation(CL-TCP-012, scope=function)
TEST(ClientSecureChannelCryptoTests, OversizeRequestTinyBufferSurfacesBadRequestTooLarge)
{
  boost::asio::thread_pool tp;
  auto status = open_and_send_with_send_limits(tp, /*sendBufferSize=*/64, /*maxSendChunks=*/1, /*ids=*/1);
  EXPECT_EQ(status, ua::StatusCode{Status::BadRequestTooLarge})
    << "a REQUEST that cannot fit the negotiated send buffer must surface BadRequestTooLarge (client "
       "direction, OPC 10000-4 section 5.3); BadResponseTooLarge means the channel role is not consulted, "
       "got 0x"
    << std::hex << status.as_uint32();
}

// ---------------------------------------------------------------------------
// CL-TCP-012 (Part 6, 6.7.2 / 7.1.2.4): the whole-message encode buffer must hold a multi-chunk message.
// The previous sizing, max(sendBufferSize, sendMaxMessageSize, 1024), collapsed to a single send buffer
// (one chunk) whenever the peer advertised sendMaxMessageSize=0 ("no limit" - what most servers send), so
// any message larger than one send buffer failed to serialize with BadUnexpectedError before the size
// checks in encode_symmetric_message_async could run. The fix sizes the buffer to the whole message
// (peer MaxMessageSize -> local self-protection cap recvMaxMessageSize -> 16 MB default, plus one send
// buffer of headroom) and adds an explicit self-protection ceiling check for the unlimited-peer case.
//
// A successful multi-chunk send is observed on the WIRE: the fake server sends no response, so the request
// callback never fires; success shows up as >=2 chunk writes on the transport. A rejection fires the
// callback (with BadResponseTooLarge / BadUnexpectedError) before any chunk is written.
// ---------------------------------------------------------------------------

namespace
{
// Outcome of driving one request through the real client send/encode path under fully-forced send limits.
struct ForcedLimitSendOutcome
{
  std::size_t newWrites{0};  // chunks this send placed on the transport
  ua::StatusCode callbackStatus{Status::Good};
  bool callbackFired{false};
};

// A ReadRequest whose serialized body is approximately `approxBodyBytes` (one ReadValueId carrying a
// DataEncoding name of that many bytes). Used to place the body precisely within a size window without a
// per-ReadValueId byte estimate. The large name is a size-control device, not a semantic requirement.
std::shared_ptr<ua::ReadRequest> make_read_request_of_size(std::size_t approxBodyBytes)
{
  auto request = std::make_shared<ua::ReadRequest>();
  request->nodes_to_read().payload().resize(1);
  auto& readValue = request->nodes_to_read().payload()[0];
  readValue.node_id() = ua::NodeId{uint16_t{0}, uint32_t{85}};  // Objects folder
  readValue.attribute_id() = 13;  // Value
  readValue.data_encoding().name() = ua::String{std::string(approxBodyBytes, 'a')};
  return request;
}

// Forces all four negotiated send-direction limits on the open channel's context, sends `request` through
// the real send/encode path, and reports whether it was chunked onto the wire or rejected up-front.
ForcedLimitSendOutcome send_request_observing_outcome(WiredSecureChannelSetup& setup, uint32_t sendBufferSize,
  uint32_t sendMaxMessageSize, uint32_t sendMaxChunkCount, uint32_t recvMaxMessageSize,
  const std::shared_ptr<ua::ReadRequest>& request)
{
  STA::on_strand(*setup.impl,
    [&](auto& g)
    {
      g.context()->negotiatedLimits.sendBufferSize = sendBufferSize;
      g.context()->negotiatedLimits.sendMaxMessageSize = sendMaxMessageSize;
      g.context()->negotiatedLimits.sendMaxChunkCount = sendMaxChunkCount;
      g.context()->negotiatedLimits.recvMaxMessageSize = recvMaxMessageSize;
    });

  const std::size_t baseline = setup.transport->writes().size();
  auto promise = std::make_shared<std::promise<ua::StatusCode>>();
  setup.impl->send_request(request, [promise](auto result) { promise->set_value(result.status_code()); });
  auto future = promise->get_future();

  ForcedLimitSendOutcome outcome;
  // future::wait_for returns the instant the callback fires, so a rejection is observed promptly; only a
  // success (whose callback never fires) pays the timeout before we confirm the chunks on the wire.
  if (future.wait_for(1s) == std::future_status::ready)
  {
    outcome.callbackFired = true;
    outcome.callbackStatus = future.get();
  }
  else
  {
    setup.transport->wait_for_write_count(baseline + 2, 2s);
  }
  outcome.newWrites = setup.transport->writes().size() - baseline;
  return outcome;
}
}  // namespace

// Opens a Basic256Sha256 SignAndEncrypt channel, sends `request` under the given forced send limits, and
// reports the outcome, tearing the setup down before returning.
ForcedLimitSendOutcome open_and_observe_send(boost::asio::thread_pool& tp, uint32_t sendBufferSize,
  uint32_t sendMaxMessageSize, uint32_t sendMaxChunkCount, uint32_t recvMaxMessageSize,
  const std::shared_ptr<ua::ReadRequest>& request)
{
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  open_authenticated_channel(
    setup, /*channelId=*/88, /*tokenId=*/4242, 600000ms, make_nonce(*setup.crypto, 32));
  EXPECT_TRUE(setup.scSync->wait_opened(2s));

  auto outcome = send_request_observing_outcome(
    setup, sendBufferSize, sendMaxMessageSize, sendMaxChunkCount, recvMaxMessageSize, request);

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return outcome;
}

// @verifies CL-TCP-012 - with the peer advertising MaxMessageSize=0 (unlimited - what most servers send),
// a legitimate multi-chunk request (serialized body larger than one send buffer) is split into chunks and
// placed on the wire, instead of failing with BadUnexpectedError because the pre-chunk encode buffer had
// collapsed to a single send buffer. This is the core CL-TCP-012 defect.
// @relation(CL-TCP-012, scope=function)
TEST(ClientSecureChannelCryptoTests, UnlimitedMaxMessageSizeMultiChunkRequestIsChunkedAndSent)
{
  boost::asio::thread_pool tp;
  // Peer: unlimited MaxMessageSize + unlimited MaxChunkCount; local self-protection cap 16 MB; ~200 KB body
  // over a 64 KB send buffer -> several chunks.
  auto outcome = open_and_observe_send(tp,
    /*sendBufferSize=*/65536,
    /*sendMaxMessageSize=*/0,
    /*sendMaxChunkCount=*/0,
    /*recvMaxMessageSize=*/16u * 1024 * 1024,
    make_read_request_of_size(200000));
  EXPECT_GE(outcome.newWrites, 2u)
    << "an unlimited-MaxMessageSize multi-chunk request must be split into >=2 chunks and sent; got "
    << outcome.newWrites << " chunk writes; callbackFired=" << outcome.callbackFired << " status 0x"
    << std::hex << outcome.callbackStatus.as_uint32();
  EXPECT_FALSE(outcome.callbackFired)
    << "a successful multi-chunk send must not fail the request; got status 0x" << std::hex
    << outcome.callbackStatus.as_uint32();
}

// @verifies CL-TCP-012 - for an unlimited peer (MaxMessageSize=0), encode_symmetric_message_async's
// message-size check is disabled, so the local self-protection ceiling (recvMaxMessageSize, else the
// 16 MB default) is the only outgoing bound. A request exceeding it must be rejected with the meaningful
// BadResponseTooLarge, NOT the generic BadUnexpectedError from an encode-buffer overflow.
// @relation(CL-TCP-012, scope=function)
TEST(ClientSecureChannelCryptoTests, UnlimitedPeerRequestOverLocalSelfProtectionCapRejectedCleanly)
{
  boost::asio::thread_pool tp;
  // Peer unlimited; local cap forced to 20000 with a 64 KB send buffer of headroom, so the ~50 KB body
  // serializes fully (fits ceiling+headroom = 85536) and is rejected by the explicit ceiling check rather
  // than overflowing the buffer.
  auto outcome = open_and_observe_send(tp,
    /*sendBufferSize=*/65536,
    /*sendMaxMessageSize=*/0,
    /*sendMaxChunkCount=*/0,
    /*recvMaxMessageSize=*/20000,
    make_read_request_of_size(50000));
  EXPECT_TRUE(outcome.callbackFired) << "an over-cap request must be rejected, not sent";
  EXPECT_EQ(outcome.callbackStatus, ua::StatusCode{Status::BadRequestTooLarge})
    << "over-self-protection-cap REQUEST must surface BadRequestTooLarge (client direction), got 0x"
    << std::hex << outcome.callbackStatus.as_uint32();
  EXPECT_EQ(outcome.newWrites, 0u) << "a rejected request must not place any chunk on the wire";
}

// @verifies CL-TCP-012 - when the peer DID set a MaxMessageSize larger than one send buffer, a request just
// over that limit must serialize (thanks to the encode-buffer headroom) and be rejected by
// encode_symmetric_message_async with BadResponseTooLarge. Previously the encode buffer was sized to
// max(sendBuffer, MaxMessageSize) == MaxMessageSize, so an over-limit request overflowed it and surfaced
// BadUnexpectedError before the size check could run.
// @relation(CL-TCP-012, scope=function)
TEST(ClientSecureChannelCryptoTests, PeerMaxMessageSizeOverLimitRequestRejectedCleanly)
{
  boost::asio::thread_pool tp;
  // Peer MaxMessageSize 600000 (> the 512 KB send buffer); ~800 KB body -> over the limit but within
  // ceiling+headroom (1124288), so it serializes and is rejected cleanly rather than overflowing.
  auto outcome = open_and_observe_send(tp,
    /*sendBufferSize=*/524288,
    /*sendMaxMessageSize=*/600000,
    /*sendMaxChunkCount=*/0,
    /*recvMaxMessageSize=*/16u * 1024 * 1024,
    make_read_request_of_size(800000));
  EXPECT_TRUE(outcome.callbackFired) << "an over-MaxMessageSize request must be rejected, not sent";
  EXPECT_EQ(outcome.callbackStatus, ua::StatusCode{Status::BadRequestTooLarge})
    << "over-MaxMessageSize REQUEST must surface BadRequestTooLarge (client direction), got 0x" << std::hex
    << outcome.callbackStatus.as_uint32();
  EXPECT_EQ(outcome.newWrites, 0u) << "a rejected request must not place any chunk on the wire";
}

// ===========================================================================
// Inbound-decode tests driven by the ServerChunkForge test interface.
//
// The forge synthesises a server->client wire chunk against a server-role SecureChannelContext
// (deriving the MIRROR symmetric token) and the chunk is fed into the REAL client
// SecureChannelImpl decode path via the receive_message_chunk strand interface. See
// tests/helpers/server_chunk_forge.h.
// ===========================================================================

namespace
{

// Waits (bounded) for a captured value to become present, driven by a strand-serialized callback.
struct ServiceResponseSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  StatusCode status{Status::Good};
  std::shared_ptr<ua::Structure> message;

  void set(SecureChannelImpl::ServiceResponseResult result)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      fired = true;
      status = result.status_code();
      if (result.is_good())
      {
        message = std::move(result).value();
      }
    }
    cv.notify_one();
  }

  bool wait(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this] { return fired; });
  }
};

// Feeds a forged chunk into the client decode path via the receive_message_chunk strand interface.
void feed_chunk(SecureChannelImpl& impl, std::vector<byte> chunk)
{
  STA::on_strand(impl,
    [bytes = std::move(chunk)](auto& g) mutable
    { g.receive_message_chunk(StatusCode{Status::Good}, std::move(bytes)); });
}

// Reads the single pending request id off the client (the ReadRequest just submitted).
uint32_t single_pending_request_id(SecureChannelImpl& impl)
{
  return STA::on_strand(impl,
    [](auto& g) -> uint32_t
    {
      const auto& pending = g.pending_requests();
      return pending.empty() ? 0u : pending.begin()->first;
    });
}

}  // namespace

// ---------------------------------------------------------------------------
// CL-UASC-006: A symmetric chunk carrying the wrong SecureChannelId is rejected (before crypto)
// with BadSecureChannelIdInvalid; a validly-signed chunk with the correct id is delivered.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-006
// @relation(CL-UASC-006, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, WrongSecureChannelIdSymmetricChunkIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Open the authenticated channel via the existing post-decode interface (no forged OPN).
  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "Authenticated channel should open on a good OPN response";

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  // Forge configured with the SAME peer material, deriving the mirror token. Held in an optional so
  // it can be destroyed (cancelling the security token's expiry timer) before the pool is drained.
  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  // Submit a service request so there is a pending callback to observe.
  auto sync = std::make_shared<ServiceResponseSync>();
  setup.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [sync](auto result) { sync->set(std::move(result)); });
  auto requestId = single_pending_request_id(*setup.impl);
  ASSERT_NE(requestId, 0u) << "The ReadRequest should be registered as a pending request";

  // A validly-signed symmetric chunk stamped with the WRONG SecureChannelId.
  ua::test_helpers::ServerChunkForge::SymMsgParams params;
  params.secureChannelId = channelId + 1;  // wrong
  params.tokenId = tokenId;
  params.requestId = requestId;
  params.sequenceNumber = 1;
  auto chunk = forge->build_symmetric_msg(params);

  feed_chunk(*setup.impl, std::move(chunk));

  ASSERT_TRUE(sync->wait(2s)) << "The pending request must be failed when the channel is torn down";
  EXPECT_TRUE(sync->status.is_bad())
    << "A chunk with the wrong SecureChannelId must not deliver a response; got status "
    << sync->status.as_uint32();
  EXPECT_EQ(sync->message, nullptr) << "No decoded response must be delivered for a rejected chunk";

  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed)
    << "A wrong-SecureChannelId chunk must close the channel";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-UASC-006
// @relation(CL-UASC-006, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, CorrectSecureChannelIdSymmetricChunkIsDelivered)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  auto sync = std::make_shared<ServiceResponseSync>();
  setup.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [sync](auto result) { sync->set(std::move(result)); });
  auto requestId = single_pending_request_id(*setup.impl);
  ASSERT_NE(requestId, 0u);

  // A validly-signed symmetric chunk stamped with the CORRECT SecureChannelId.
  ua::test_helpers::ServerChunkForge::SymMsgParams params;
  params.secureChannelId = channelId;  // correct
  params.tokenId = tokenId;
  params.requestId = requestId;
  params.sequenceNumber = 1;
  auto chunk = forge->build_symmetric_msg(params);

  feed_chunk(*setup.impl, std::move(chunk));

  ASSERT_TRUE(sync->wait(2s)) << "The correlated ReadResponse should be delivered to the pending request";
  EXPECT_TRUE(sync->status.is_good())
    << "A validly-signed chunk with the correct id must deliver Good; got " << sync->status.as_uint32();
  ASSERT_NE(sync->message, nullptr) << "The decoded ReadResponse must be delivered";
  EXPECT_NE(dynamic_cast<ua::ReadResponse*>(sync->message.get()), nullptr)
    << "The delivered response must be a ReadResponse";

  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Open) << "The channel must stay open after a good chunk";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A server may answer and then close (ApplyChanges, OPC 10000-12 7.10.6): its response reaches the client,
// and the transport fails while that response is still being decrypted. The response is delivered to its
// caller and the channel then closes. Both ways the failure arrives are driven: a transport error, and a read
// that completes with a bad status. The chunk and the failure are handed over in one strand turn, as a read
// of the response followed at once by the peer's close is. Falsifiable: reporting the failure at once fails
// the pending request although its response was received (found end to end by GdsPushScenarios).
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, AResponseReceivedBeforeTheTransportFailsIsDelivered)
{
  for (const bool asReadFailure : {false, true})
  {
    SCOPED_TRACE(asReadFailure ? "a read completing with a bad status" : "a transport error");
    boost::asio::thread_pool tp;
    auto ex = tp.get_executor();
    auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
    ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
    const uint32_t channelId = 88;
    const uint32_t tokenId = 4242;
    auto serverNonce = make_nonce(*setup.crypto, 32);
    open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
    ASSERT_TRUE(setup.scSync->wait_opened(2s));
    auto clientNonce =
      STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
    std::optional<ua::test_helpers::ServerChunkForge> forge;
    forge.emplace(ex,
      setup.crypto,
      setup.serverCert,
      setup.serverKeys,
      setup.clientCert,
      MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::Basic256Sha256);
    forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

    auto sync = std::make_shared<ServiceResponseSync>();
    setup.impl->send_request(
      std::make_shared<ua::ReadRequest>(), [sync](auto result) { sync->set(std::move(result)); });
    auto requestId = single_pending_request_id(*setup.impl);
    ASSERT_NE(requestId, 0u);
    ua::test_helpers::ServerChunkForge::SymMsgParams params;
    params.secureChannelId = channelId;
    params.tokenId = tokenId;
    params.requestId = requestId;
    params.sequenceNumber = 1;
    auto chunk = forge->build_symmetric_msg(params);

    STA::on_strand(*setup.impl,
      [bytes = std::move(chunk), asReadFailure](auto& g) mutable
      {
        g.receive_message_chunk(StatusCode{Status::Good}, std::move(bytes));  // decryption starts
        if (asReadFailure)
          g.receive_message_chunk(StatusCode{Status::BadConnectionClosed}, std::vector<byte>{});
        else
          g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{});
      });

    ASSERT_TRUE(sync->wait(2s));
    EXPECT_TRUE(sync->status.is_good())
      << "the received response is delivered; got " << sync->status.as_uint32();
    EXPECT_NE(dynamic_cast<ua::ReadResponse*>(sync->message.get()), nullptr);
    auto state = SecureChannelImpl::ChannelState::Open;
    for (int i = 0; i < 100 && state != SecureChannelImpl::ChannelState::Closed; ++i)
    {
      std::this_thread::sleep_for(10ms);
      state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
    }
    EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed) << "the failure is then delivered";

    forge.reset();
    setup.impl.reset();
    setup.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// ---------------------------------------------------------------------------
// CL-UASC-010: The client verifies the RequestId of an inbound response. A validly-signed,
// correctly-sequenced symmetric chunk whose RequestId matches NO pending request must be dropped:
// it must not be misrouted to an unrelated pending request, and must not tear down the channel. A
// subsequent chunk carrying the CORRECT RequestId is still delivered (positive control) - proving
// the drop is specifically due to RequestId non-correlation and not a dead forge/harness.
// (Confirm-implemented: the drop path is SecureChannelImpl::on_chunk_decoded's
// mPendingRequests.find(requestId) miss, ua_client_secure_channel_impl.cpp:833; falsifiable - a
// misrouting client would fire the pending callback on the stray chunk and fail EXPECT_FALSE.)
// ---------------------------------------------------------------------------

// @verifies CL-UASC-010
// @relation(CL-UASC-010, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, UnknownRequestIdResponseIsDroppedWithoutDisturbingPending)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  auto sync = std::make_shared<ServiceResponseSync>();
  setup.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [sync](auto result) { sync->set(std::move(result)); });
  auto requestId = single_pending_request_id(*setup.impl);
  ASSERT_NE(requestId, 0u) << "The ReadRequest should be registered as a pending request";

  // A validly-signed, correctly-sequenced chunk whose RequestId matches NO pending request.
  ua::test_helpers::ServerChunkForge::SymMsgParams strayParams;
  strayParams.secureChannelId = channelId;
  strayParams.tokenId = tokenId;
  strayParams.requestId = requestId + 1000;  // not a live request id
  strayParams.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(strayParams));

  // The pending request must NOT be disturbed by the uncorrelated response (bounded negative wait).
  EXPECT_FALSE(sync->wait(500ms))
    << "A response with an unknown RequestId must not be misrouted to the pending request";
  EXPECT_EQ(single_pending_request_id(*setup.impl), requestId)
    << "The original request must remain pending after an uncorrelated response is dropped";
  auto stateAfterStray = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(stateAfterStray, SecureChannelImpl::ChannelState::Open)
    << "A valid but uncorrelated response must not tear down the channel";

  // Positive control: the SAME forge/token delivers a response correlated to the real request id.
  ua::test_helpers::ServerChunkForge::SymMsgParams matchParams;
  matchParams.secureChannelId = channelId;
  matchParams.tokenId = tokenId;
  matchParams.requestId = requestId;  // correct
  matchParams.sequenceNumber = 2;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(matchParams));

  ASSERT_TRUE(sync->wait(2s)) << "The correctly-correlated ReadResponse should be delivered";
  EXPECT_TRUE(sync->status.is_good()) << "Correlated delivery must be Good; got " << sync->status.as_uint32();
  EXPECT_NE(dynamic_cast<ua::ReadResponse*>(sync->message.get()), nullptr)
    << "The delivered response must be a ReadResponse";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Shared helpers for the sequence-number / token-rotation / logging tests below.
// ---------------------------------------------------------------------------

namespace
{

// A LogSink that records every entry so a test can assert the client logged a discard.
class CapturingLogSink : public ua::LogSink
{
public:
  struct Entry
  {
    ua::LogLevel level;
    std::string category;
    std::string message;
  };

  void log(const ua::LogEntry& entry) override
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mEntries.push_back(Entry{entry.level, std::string{entry.category}, entry.message});
  }

  size_t error_count() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return std::count_if(
      mEntries.begin(), mEntries.end(), [](const Entry& e) { return e.level == ua::LogLevel::Error; });
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

// Opens a None-policy channel via the post-decode handle_opn_response interface (empty nonces, no crypto).
void open_none_channel(WiredSecureChannelSetup& setup, uint32_t channelId, uint32_t tokenId)
{
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, ByteString{});
}

// Submits a ReadRequest and returns (sync, requestId). Waits until the request is registered.
std::pair<std::shared_ptr<ServiceResponseSync>, uint32_t> submit_read_request(SecureChannelImpl& impl)
{
  auto sync = std::make_shared<ServiceResponseSync>();
  impl.send_request(
    std::make_shared<ua::ReadRequest>(), [sync](auto result) { sync->set(std::move(result)); });
  auto requestId = single_pending_request_id(impl);
  return {sync, requestId};
}

}  // namespace

// ---------------------------------------------------------------------------
// CL-UASC-011: The client accepts strictly-incrementing inbound sequence numbers and rejects a gap.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-011
// @relation(CL-UASC-011, scope=function)
// @relation(AC-SVR-SCE-005-SEQUENCE-FROM-ZERO, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, GappedInboundSequenceNumberIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t channelId = 7;
  const uint32_t tokenId = 3;
  open_none_channel(setup, channelId, tokenId);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::None,
    SecurityPolicyId::None);
  forge->set_token_from_nonces(ByteString{}, ByteString{}, tokenId, 600000ms);

  // seq 1 (the first valid inbound number: the client seeds lastRxSequenceNumber = 0) is accepted.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams p1;
  p1.secureChannelId = channelId;
  p1.tokenId = tokenId;
  p1.requestId = req1;
  p1.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(p1));
  ASSERT_TRUE(sync1->wait(2s));
  EXPECT_TRUE(sync1->status.is_good()) << "seq 1 must be accepted; got " << sync1->status.as_uint32();

  // seq 3 (a gap: 2 is skipped) is rejected and tears the channel down.
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams p2;
  p2.secureChannelId = channelId;
  p2.tokenId = tokenId;
  p2.requestId = req2;
  p2.sequenceNumber = 3;  // gap
  feed_chunk(*setup.impl, forge->build_symmetric_msg(p2));

  ASSERT_TRUE(sync2->wait(2s)) << "The pending request must fail when the gapped chunk closes the channel";
  EXPECT_EQ(sync2->status.as_status(), Status::BadSequenceNumberInvalid)
    << "A gapped inbound sequence number must be rejected with BadSequenceNumberInvalid; got "
    << sync2->status.as_uint32();
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-UASC-011
// @relation(CL-UASC-011, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, ReplayedInboundSequenceNumberIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t channelId = 7;
  const uint32_t tokenId = 3;
  open_none_channel(setup, channelId, tokenId);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::None,
    SecurityPolicyId::None);
  forge->set_token_from_nonces(ByteString{}, ByteString{}, tokenId, 600000ms);

  // seq 1 is accepted.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams p1;
  p1.secureChannelId = channelId;
  p1.tokenId = tokenId;
  p1.requestId = req1;
  p1.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(p1));
  ASSERT_TRUE(sync1->wait(2s));
  EXPECT_TRUE(sync1->status.is_good());

  // Re-feeding seq 1 (a replay) is rejected: the next expected number is 2.
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams p2;
  p2.secureChannelId = channelId;
  p2.tokenId = tokenId;
  p2.requestId = req2;
  p2.sequenceNumber = 1;  // replay
  feed_chunk(*setup.impl, forge->build_symmetric_msg(p2));

  ASSERT_TRUE(sync2->wait(2s));
  EXPECT_EQ(sync2->status.as_status(), Status::BadSequenceNumberInvalid)
    << "A replayed inbound sequence number must be rejected with BadSequenceNumberInvalid; got "
    << sync2->status.as_uint32();
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-010: A chunk stamped with the OLD token id is accepted while renewal is in flight, but is
// rejected with BadSecureChannelTokenUnknown once the channel has rotated to the new token.
// ---------------------------------------------------------------------------

// @verifies CL-SC-010
// @relation(CL-SC-010, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, OldTokenAcceptedDuringRenewalThenRejectedAfterRotation)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t channelId = 9;
  const uint32_t oldTokenId = 100;
  const uint32_t newTokenId = 200;
  open_none_channel(setup, channelId, oldTokenId);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::None,
    SecurityPolicyId::None);
  forge->set_token_from_nonces(ByteString{}, ByteString{}, oldTokenId, 600000ms);
  forge->set_pending_token(ByteString{}, ByteString{}, newTokenId, 600000ms);

  // Drive the client into Renewing: the active token is still the OLD token; no renewal has completed.
  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_renewing(); });

  // (1) A chunk stamped with the OLD token id is accepted while renewal is in flight.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams pOld1;
  pOld1.secureChannelId = channelId;
  pOld1.tokenId = oldTokenId;
  pOld1.requestId = req1;
  pOld1.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(pOld1));
  ASSERT_TRUE(sync1->wait(2s));
  EXPECT_TRUE(sync1->status.is_good())
    << "The old token must still be accepted during renewal; got " << sync1->status.as_uint32();

  // Complete the renewal on the client: the new token becomes the one it sends under, and the old one is kept
  // for receiving only.
  STA::on_strand(*setup.impl,
    [&](auto& g) {
      g.handle_opn_response(StatusCode{Status::Good}, channelId, newTokenId, 600000ms, ByteString{}, nullptr);
    });

  // (2) A chunk stamped with the NEW token id is accepted and ends the acceptance of the old token.
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams pNew;
  pNew.secureChannelId = channelId;
  pNew.tokenId = newTokenId;
  pNew.requestId = req2;
  pNew.sequenceNumber = 2;
  pNew.usePendingToken = true;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(pNew));
  ASSERT_TRUE(sync2->wait(2s));
  EXPECT_TRUE(sync2->status.is_good())
    << "The new token must be accepted after renewal; got " << sync2->status.as_uint32();

  // (3) After rotation the OLD token is unknown and its chunk is rejected.
  auto [sync3, req3] = submit_read_request(*setup.impl);
  ASSERT_NE(req3, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams pOld2;
  pOld2.secureChannelId = channelId;
  pOld2.tokenId = oldTokenId;
  pOld2.requestId = req3;
  pOld2.sequenceNumber = 3;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(pOld2));
  ASSERT_TRUE(sync3->wait(2s));
  EXPECT_EQ(sync3->status.as_status(), Status::BadSecureChannelTokenUnknown)
    << "After rotation the old token must be rejected with BadSecureChannelTokenUnknown; got "
    << sync3->status.as_uint32();
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SC-009 / CL-SC-010 (OPC 10000-6 6.7.4; interoperability finding 014): when the renew response arrives
// the client secures what it SENDS with the new token at once, and keeps accepting the old token "until it
// expires or it receives a Message from the Server secured with the new SecurityToken" (1.05.06).
// ---------------------------------------------------------------------------

// The request sent right after the renew response carries the NEW token id - nothing from the server under
// the new token comes first. Falsifiable: the former client kept sending under the old token until it
// RECEIVED a new-token message, so with a server that also waits, neither side ever rotated.
// @relation(AC-CL-SC-009-02, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, TokenIdUpdatedAfterRenewal)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  const uint32_t channelId = 9;
  const uint32_t oldTokenId = 100;
  const uint32_t newTokenId = 200;
  open_none_channel(setup, channelId, oldTokenId);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_renewing(); });
  STA::on_strand(*setup.impl,
    [&](auto& g) {
      g.handle_opn_response(StatusCode{Status::Good}, channelId, newTokenId, 600000ms, ByteString{}, nullptr);
    });

  const auto writesBefore = setup.transport->writes().size();
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), [](auto) {});
  ASSERT_TRUE(setup.transport->wait_for_write_count(writesBefore + 1, 3s));
  const auto writes = setup.transport->writes();
  const auto parsed = parse_symmetric_chunk_header(span<const byte>{writes.back()});
  EXPECT_EQ(parsed.header.messageType, UaScMessageHeader::MessageType::Message);
  EXPECT_EQ(parsed.securityHeader.tokenId, newTokenId)
    << "the request after the renew response uses the new token";

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Server answers under the old token until it receives a message under the new one, so the answer to a
// request in flight across the renewal arrives under the old token AFTER the renew response: it is accepted.
// Once a chunk under the new token has been accepted, the old token is refused. Falsifiable: the former
// client (BR-11) refused the first old-token chunk; a client that never retired the old token accepts the
// third.
// @relation(AC-CL-SC-010-02, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, OldTokenAcceptedAfterTheRenewResponseUntilANewTokenMessage)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  const uint32_t channelId = 9;
  const uint32_t oldTokenId = 100;
  const uint32_t newTokenId = 200;
  open_none_channel(setup, channelId, oldTokenId);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));
  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::None,
    SecurityPolicyId::None);
  forge->set_token_from_nonces(ByteString{}, ByteString{}, oldTokenId, 600000ms);
  forge->set_pending_token(ByteString{}, ByteString{}, newTokenId, 600000ms);

  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_renewing(); });
  STA::on_strand(*setup.impl,
    [&](auto& g) {
      g.handle_opn_response(StatusCode{Status::Good}, channelId, newTokenId, 600000ms, ByteString{}, nullptr);
    });

  // (1) The old token, after the renew response and before any new-token message: accepted.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams old1;
  old1.secureChannelId = channelId;
  old1.tokenId = oldTokenId;
  old1.requestId = req1;
  old1.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(old1));
  ASSERT_TRUE(sync1->wait(2s));
  EXPECT_TRUE(sync1->status.is_good())
    << "an answer under the old token after the renew response must be accepted; got "
    << sync1->status.as_uint32();

  // (2) The first chunk under the new token: accepted, and it retires the old token.
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams fresh;
  fresh.secureChannelId = channelId;
  fresh.tokenId = newTokenId;
  fresh.requestId = req2;
  fresh.sequenceNumber = 2;
  fresh.usePendingToken = true;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(fresh));
  ASSERT_TRUE(sync2->wait(2s));
  EXPECT_TRUE(sync2->status.is_good()) << "the new token must be accepted; got " << sync2->status.as_uint32();

  // (3) The old token after a new-token message: refused.
  auto [sync3, req3] = submit_read_request(*setup.impl);
  ASSERT_NE(req3, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams old2;
  old2.secureChannelId = channelId;
  old2.tokenId = oldTokenId;
  old2.requestId = req3;
  old2.sequenceNumber = 3;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(old2));
  ASSERT_TRUE(sync3->wait(2s));
  EXPECT_EQ(sync3->status.as_status(), Status::BadSecureChannelTokenUnknown)
    << "after a message under the new token the old token must be refused; got " << sync3->status.as_uint32();

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The same rule on an authenticated RSA channel, through the production renewal: the client renews (a new
// clientNonce, an OPN-Renew on the wire), takes the renew response, and then receives a chunk signed and
// encrypted with the OLD token's keys. Only this arm reaches the RSA decoder's token lookup by id: at
// SecurityPolicy None no keys are selected. Falsifiable: a decoder that finds only the active and pending
// tokens refuses the first chunk as a retired token; one that never drops it accepts the third.
// @relation(AC-CL-SC-010-02, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, OldTokenKeysOpenAnAuthenticatedAnswerAfterTheRenewResponse)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(
    ex, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  const uint32_t channelId = 88;
  const uint32_t oldTokenId = 100;
  const uint32_t newTokenId = 200;
  const auto issueServerNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, oldTokenId, 600000ms, issueServerNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));
  const auto issueClientNonce =
    STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(issueClientNonce, issueServerNonce, oldTokenId, 600000ms);

  // The production renewal: a fresh clientNonce and an OPN-Renew, then the renew response.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s)) << "the renewal must send an OPN-Renew";
  const auto renewClientNonce =
    STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  const auto renewServerNonce = make_nonce(*setup.crypto, 32);
  forge->set_pending_token(renewClientNonce, renewServerNonce, newTokenId, 600000ms);
  open_authenticated_channel(setup, channelId, newTokenId, 600000ms, renewServerNonce);

  // (1) An answer under the old token's keys, after the renew response: accepted.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams old1;
  old1.secureChannelId = channelId;
  old1.tokenId = oldTokenId;
  old1.requestId = req1;
  old1.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(old1));
  ASSERT_TRUE(sync1->wait(2s));
  EXPECT_TRUE(sync1->status.is_good())
    << "an answer under the old token's keys must be accepted after the renew response; got "
    << sync1->status.as_uint32();

  // (2) The first chunk under the new token's keys: accepted.
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams fresh;
  fresh.secureChannelId = channelId;
  fresh.tokenId = newTokenId;
  fresh.requestId = req2;
  fresh.sequenceNumber = 2;
  fresh.usePendingToken = true;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(fresh));
  ASSERT_TRUE(sync2->wait(2s));
  EXPECT_TRUE(sync2->status.is_good()) << "the new token must be accepted; got " << sync2->status.as_uint32();

  // (3) The old token after a new-token message: refused.
  auto [sync3, req3] = submit_read_request(*setup.impl);
  ASSERT_NE(req3, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams old2;
  old2.secureChannelId = channelId;
  old2.tokenId = oldTokenId;
  old2.requestId = req3;
  old2.sequenceNumber = 3;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(old2));
  ASSERT_TRUE(sync3->wait(2s));
  EXPECT_EQ(sync3->status.as_status(), Status::BadSecureChannelTokenUnknown)
    << "after a message under the new token the old token must be refused; got " << sync3->status.as_uint32();

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The old token is accepted after the renew response only until its revised lifetime elapses ("until it
// expires"), even when no message under the new token arrives. The same chunk shape before and after the
// expiry: only the elapsed lifetime differs. Falsifiable: a client that kept the old token until a new-token
// message alone accepts the second chunk; the former client (BR-11) refused the first.
// @relation(AC-CL-SC-010-03, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, OldTokenRejectedOnceItsLifetimeHasElapsed)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  const uint32_t channelId = 9;
  const uint32_t oldTokenId = 100;
  const uint32_t newTokenId = 200;
  // The old token lives 1500 ms; the renew response re-arms the renewal timer from the new token's lifetime,
  // so the client starts no renewal of its own within the test.
  constexpr auto oldLifetime = 1500ms;
  // Taken before the token exists, so the guard below never under-states the token's age.
  const auto opened = std::chrono::steady_clock::now();
  open_authenticated_channel(setup, channelId, oldTokenId, oldLifetime, ByteString{});
  ASSERT_TRUE(setup.scSync->wait_opened(2s));
  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::None,
    SecurityPolicyId::None);
  forge->set_token_from_nonces(ByteString{}, ByteString{}, oldTokenId, 600000ms);

  STA::on_strand(*setup.impl, [](auto& g) { g.set_channel_renewing(); });
  STA::on_strand(*setup.impl,
    [&](auto& g) {
      g.handle_opn_response(StatusCode{Status::Good}, channelId, newTokenId, 600000ms, ByteString{}, nullptr);
    });

  // Before the expiry: accepted.
  auto [sync1, req1] = submit_read_request(*setup.impl);
  ASSERT_NE(req1, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams before;
  before.secureChannelId = channelId;
  before.tokenId = oldTokenId;
  before.requestId = req1;
  before.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(before));
  ASSERT_TRUE(sync1->wait(2s));
  ASSERT_LT(std::chrono::steady_clock::now() - opened, oldLifetime)
    << "the first chunk was not delivered within the old token's lifetime; the arm proves nothing";
  EXPECT_TRUE(sync1->status.is_good())
    << "the old token must be accepted before it expires; got " << sync1->status.as_uint32();

  // After the expiry: refused.
  std::this_thread::sleep_until(opened + oldLifetime + 200ms);
  auto [sync2, req2] = submit_read_request(*setup.impl);
  ASSERT_NE(req2, 0u);
  ua::test_helpers::ServerChunkForge::SymMsgParams after;
  after.secureChannelId = channelId;
  after.tokenId = oldTokenId;
  after.requestId = req2;
  after.sequenceNumber = 2;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(after));
  ASSERT_TRUE(sync2->wait(2s));
  EXPECT_EQ(sync2->status.as_status(), Status::BadSecureChannelTokenUnknown)
    << "the old token must be refused once it has expired; got " << sync2->status.as_uint32();

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-012: A rejected inbound chunk is logged (an error entry is emitted before the discard).
// ---------------------------------------------------------------------------

// @verifies CL-UASC-012
// @relation(CL-UASC-012, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, RejectedInboundChunkIsLogged)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  // Install a capturing sink AFTER open, so only the reject's log entries are observed.
  auto sink = std::make_shared<CapturingLogSink>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  setup.deps->set_logger(ua::Logger{sink, level, "client"});

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  auto [sync, requestId] = submit_read_request(*setup.impl);
  ASSERT_NE(requestId, 0u);

  // Trigger a reject (wrong SecureChannelId).
  ua::test_helpers::ServerChunkForge::SymMsgParams params;
  params.secureChannelId = channelId + 1;
  params.tokenId = tokenId;
  params.requestId = requestId;
  params.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(params));

  ASSERT_TRUE(sync->wait(2s));
  ASSERT_TRUE(sync->status.is_bad()) << "the reject must fail the pending request";

  // Drain any posted logging continuations, then assert the discard was logged at Error.
  STA::strand_barrier(*setup.impl);
  EXPECT_GE(sink->error_count(), 1u)
    << "A rejected inbound chunk must be logged at Error before it is discarded";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control arm of AC-CL-UASC-012. RejectedInboundChunkIsLogged asserts an Error entry appears while a
// chunk is discarded; on its own it cannot tell that entry apart from one this fixture would have produced
// anyway. This run differs from it in exactly one variable - the SecureChannelId stamped on the fed chunk -
// and asserts the sink stays clean, so the Error the sibling counts is attributable to the discard.
// @verifies CL-UASC-012
// @relation(CL-UASC-012, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, AcceptedInboundChunkLogsNoError)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  // Install the capturing sink AFTER open, exactly as the rejecting sibling does.
  auto sink = std::make_shared<CapturingLogSink>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  setup.deps->set_logger(ua::Logger{sink, level, "client"});

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  auto [sync, requestId] = submit_read_request(*setup.impl);
  ASSERT_NE(requestId, 0u);

  ua::test_helpers::ServerChunkForge::SymMsgParams params;
  params.secureChannelId = channelId;  // correct - the one variable that differs from the sibling
  params.tokenId = tokenId;
  params.requestId = requestId;
  params.sequenceNumber = 1;
  feed_chunk(*setup.impl, forge->build_symmetric_msg(params));

  ASSERT_TRUE(sync->wait(2s));
  ASSERT_TRUE(sync->status.is_good()) << "the correctly-stamped chunk must be delivered, not discarded";

  STA::strand_barrier(*setup.impl);
  EXPECT_EQ(sink->error_count(), 0u)
    << "a chunk that is accepted must produce no Error entry, so the sibling's Error belongs to the discard";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SESS-023: a cancelled outstanding request's callback receives Bad_RequestCancelledByClient. The
// server answers the outstanding request with a ServiceFault (service_result =
// Bad_RequestCancelledByClient); the client's generic pending-request map must route that fault status
// to the originating request's callback, WITHOUT closing the channel (a per-request fault is not a
// channel error).
// ---------------------------------------------------------------------------

// @verifies CL-SESS-023
// @relation(CL-SESS-023, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, CancelledOutstandingRequestReceivesRequestCancelledByClient)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, channelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "Authenticated channel should open on a good OPN response";

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  // Submit a service request that stays outstanding, then deliver a ServiceFault for its request id.
  auto [sync, requestId] = submit_read_request(*setup.impl);
  ASSERT_NE(requestId, 0u) << "the ReadRequest should be registered as a pending request";

  ua::test_helpers::ServerChunkForge::SymMsgParams params;
  params.secureChannelId = channelId;
  params.tokenId = tokenId;
  params.requestId = requestId;
  params.sequenceNumber = 1;
  feed_chunk(*setup.impl,
    forge->build_symmetric_service_fault(params, StatusCode{Status::BadRequestCancelledByClient}));

  ASSERT_TRUE(sync->wait(2s)) << "the outstanding request's callback must fire";
  EXPECT_EQ(sync->status, StatusCode{Status::BadRequestCancelledByClient})
    << "the cancelled outstanding request's callback must receive Bad_RequestCancelledByClient";
  EXPECT_EQ(sync->message, nullptr) << "a ServiceFault delivers no decoded response body";

  // A per-request fault must not tear down the channel.
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Open)
    << "delivering a ServiceFault for one request must leave the channel open";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ===========================================================================
// Inbound OpenSecureChannel-response decode tests (build_opn_response forge interface).
//
// Unlike the symmetric tests above (which open the channel via the post-decode handle_opn_response
// interface and then inject established-channel chunks), these feed a forged *OPN response* chunk into the
// client's receive_message_chunk interface so the REAL asymmetric decode path runs end to end:
//   receive_message_chunk -> decode_asymmetric (cert-match, key-length, validate_certificate_async)
//   -> on_chunk_decoded -> receive_response_message -> handle_opn_response_async.
// This is what lets the client-side inbound-OPN security obligations be unit-tested against the real
// code path rather than a post-decode injection.
// ===========================================================================

// ---------------------------------------------------------------------------
// Positive control for the build_opn_response forge: a valid forged OPN response, decoded through the
// real asymmetric path (with a Good-returning cert store), opens the channel and adopts its token.
// ---------------------------------------------------------------------------

TEST(ClientSecureChannelInboundOpnDecodeTests, ForgedValidOpnResponseOpensChannel)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  const uint32_t channelId = 77;
  const uint32_t tokenId = 909;
  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = channelId;
  params.tokenId = tokenId;
  params.requestId = 1;
  params.sequenceNumber = 1;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  params.revisedLifetimeMs = 600000;

  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ASSERT_TRUE(setup.scSync->wait_opened(2s))
    << "A valid forged OPN response, decoded through the real asymmetric path, must open the channel";
  EXPECT_TRUE(setup.scSync->openedStatus.is_good())
    << "channel open status: " << setup.scSync->openedStatus.as_uint32();

  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Open)
    << "a validly-decoded OPN response must drive the channel to Open";
  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), tokenId)
    << "the token id carried in the forged OPN response body must be adopted by the client";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 6.7.4: the ServerProtocolVersion of the OpenSecureChannel response shall be the ProtocolVersion of
// the Acknowledge (0), and the receiver closes the channel and reports Bad_ProtocolVersionUnsupported on a
// mismatch. The forged response differs from ForgedValidOpnResponseOpensChannel (the control) only in
// that version.
// @verifies AC-CL-UASC-022-01
TEST(ClientSecureChannelInboundOpnDecodeTests, AnOpnResponseNamingAnotherProtocolVersionIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 77;
  params.tokenId = 909;
  params.requestId = 1;
  params.sequenceNumber = 1;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  params.revisedLifetimeMs = 600000;
  params.serverProtocolVersion = 1;

  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open must complete, refused";
  EXPECT_EQ(setup.scSync->openedStatus.as_status(), Status::BadProtocolVersionUnsupported);
  EXPECT_NE(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Open)
    << "the channel is not opened on a mismatched ServerProtocolVersion";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Owner decision 11: under Basic128Rsa15 the server nonce is exactly 16 bytes (OPC 10000-7; Part 4
// 5.5.2.2), as the OPC Foundation .NET stack sends and requires. A 16-byte server nonce opens the
// channel; a 32-byte one, which the SDK itself used to require for this policy, is refused.
// @verifies AC-CL-SC-015-BASIC128RSA15-NONCE-IS-16
TEST(ClientSecureChannelInboundOpnDecodeTests, ABasic128Rsa15ServerNonceIsSixteenBytes)
{
  for (const size_t length : {size_t{16}, size_t{32}})
  {
    SCOPED_TRACE(length);
    boost::asio::thread_pool tp;
    auto ex = tp.get_executor();
    auto setup = WiredSecureChannelSetup::create(
      ex, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic128Rsa15);
    ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

    std::optional<ua::test_helpers::ServerChunkForge> forge;
    forge.emplace(ex,
      setup.crypto,
      setup.serverCert,
      setup.serverKeys,
      setup.clientCert,
      MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::Basic128Rsa15);

    ua::test_helpers::ServerChunkForge::OpnRespParams params;
    params.secureChannelId = 77;
    params.tokenId = 909;
    params.requestId = 1;
    params.sequenceNumber = 1;
    params.serverNonce = make_nonce(*setup.crypto, length);
    params.revisedLifetimeMs = 600000;

    feed_chunk(*setup.impl, forge->build_opn_response(params));

    ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open must complete";
    if (length == 16)
    {
      EXPECT_TRUE(setup.scSync->openedStatus.is_good())
        << "channel open status: " << setup.scSync->openedStatus.as_uint32();
      EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.last_client_nonce().size(); }), 16u)
        << "the client's own clientNonce is Basic128Rsa15's 16 bytes";
    }
    else
    {
      EXPECT_EQ(setup.scSync->openedStatus.as_status(), Status::BadNonceInvalid);
    }

    forge.reset();
    setup.impl.reset();
    setup.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-001 (administrator-supplied trust list is authoritative) /
// CL-UASC-009 (server-certificate trust validation): the client drives the OPN decode-asymmetric
// path, which invokes the injected CertificateStore's validate_certificate_async. A rejection there
// (an untrusted server certificate) must fail the channel open and close the channel; a Good result
// (a trusted certificate) must open it. Two-sided so the reject branch is provably non-vacuous.
//
// SCOPE: this verifies the CLIENT-side obligation - that the client consults the store on the real
// decode path and honours (surfaces + closes on) its verdict. The chain-validation / trust-list-
// authority mechanics of CL-SECADMIN-001 are the CertificateStore's job (tier-0 store tests +
// real-store integration); they are out of scope for this client-plumbing unit test.
// STATUS NOTE: CL-UASC-009's text says "return Bad_SecurityChecksFailed on error"; the client
// surfaces the store's verdict verbatim (it does not normalise it), and CL-SECADMIN-001's own test
// oracle explicitly ratifies "Bad_SecurityChecksFailed (or equivalent BadCertificateUntrusted)" for
// exactly this scenario. The store is scripted to reject with BadCertificateUntrusted below.
// ---------------------------------------------------------------------------

namespace
{
// Drives a WiredSecureChannelSetup to receive one valid forged OPN response and returns the resulting
// open status. The cert store is scripted before the chunk is fed, so the store's validate outcome
// governs whether the real decode path opens or rejects the channel.
StatusCode drive_opn_with_store_validation(
  boost::asio::thread_pool& tp, StatusCode validateOutcome, SecureChannelImpl::ChannelState& stateOut)
{
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Script the trust decision the client's decode path will observe when it validates the server cert.
  setup.certStore->set_validate_status(validateOutcome);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 55;
  params.tokenId = 321;
  params.requestId = 1;
  params.sequenceNumber = 1;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  params.revisedLifetimeMs = 600000;

  feed_chunk(*setup.impl, forge->build_opn_response(params));

  EXPECT_TRUE(setup.scSync->wait_opened(2s))
    << "the open callback must resolve (success or failure) once the OPN response is decoded";
  StatusCode openStatus = setup.scSync->openedStatus;
  stateOut = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return openStatus;
}
}  // namespace

// @verifies CL-SECADMIN-001
// @verifies CL-UASC-009
// @relation(CL-SECADMIN-001, CL-UASC-009, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, UntrustedServerCertificateRejectsChannelOpen)
{
  // Positive control: a trusted server cert (store returns Good) opens the channel through the real
  // validate path. Without this, the negative branch below could pass vacuously (e.g. if the chunk
  // never reached validation at all).
  {
    boost::asio::thread_pool tp;
    SecureChannelImpl::ChannelState state{};
    auto status = drive_opn_with_store_validation(tp, StatusCode{Status::Good}, state);
    EXPECT_TRUE(status.is_good()) << "a trusted server certificate must open the channel; got "
                                  << status.as_uint32();
    EXPECT_EQ(state, SecureChannelImpl::ChannelState::Open);
  }

  // Negative: the store rejects the server cert as untrusted. The client must surface the rejection
  // and close the channel rather than proceed.
  {
    boost::asio::thread_pool tp;
    SecureChannelImpl::ChannelState state{};
    auto status = drive_opn_with_store_validation(tp, StatusCode{Status::BadCertificateUntrusted}, state);
    EXPECT_TRUE(status.is_bad()) << "an untrusted server certificate must fail the channel open, not proceed";
    EXPECT_EQ(status, StatusCode{Status::BadCertificateUntrusted})
      << "the client must surface the certificate-store rejection status to the opener";
    EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed)
      << "a rejected server certificate must close the channel";
  }
}

// ---------------------------------------------------------------------------
// CL-PULLCRT-001 (W6b-1): the bootstrap-trust OPN overlay. A per-open trust-store override
// (SecureChannelImpl::Config::trustStoreOverride) makes the OPN server-certificate validation consult
// an admin-supplied store DISTINCT from the deps runtime store. The three tests below prove the
// override store - not the runtime store - governs the OPN trust decision (and that a null override
// falls back to the runtime store, i.e. no behaviour change).
// ---------------------------------------------------------------------------

namespace
{
// Outcome of the override probe: the open status/state plus which store the real OPN decode path
// actually invoked (validate_call_count per store).
struct OverrideProbe
{
  StatusCode openStatus;
  SecureChannelImpl::ChannelState state{};
  std::size_t runtimeValidateCalls{0};
  std::size_t overrideValidateCalls{0};
};

// Drives a WiredSecureChannelSetup to receive one valid forged OPN response. The deps (runtime)
// store's validate verdict is scripted to `runtimeOutcome`. When `overrideOutcome` is set, a SEPARATE
// TestCertificateStore (scripted to that verdict) is installed as the per-open trust-store override;
// when nullopt no override is installed, so the runtime store must be used. Records which store the
// real asymmetric OPN decode path actually consulted.
OverrideProbe drive_opn_with_override(
  boost::asio::thread_pool& tp, StatusCode runtimeOutcome, std::optional<StatusCode> overrideOutcome)
{
  auto ex = tp.get_executor();

  std::shared_ptr<TestCertificateStore> overrideStore;
  if (overrideOutcome)
  {
    // The override store only answers server-cert validation (context.mCertStore); it never provides
    // the client's own application certificate (that comes from the deps store), so a default
    // ApplicationCertificate / null server cert is sufficient here.
    overrideStore =
      std::make_shared<TestCertificateStore>(CertificateStore::ApplicationCertificate{}, nullptr);
    overrideStore->set_validate_status(*overrideOutcome);
  }

  auto setup = WiredSecureChannelSetup::create(
    ex,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    [runtimeOutcome](TestCertificateStore& runtimeStore)
    { runtimeStore.set_validate_status(runtimeOutcome); },
    CertificateKeyAlgorithm::Rsa,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateType::RsaSha256Application,
    overrideStore);
  EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 55;
  params.tokenId = 321;
  params.requestId = 1;
  params.sequenceNumber = 1;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  params.revisedLifetimeMs = 600000;

  feed_chunk(*setup.impl, forge->build_opn_response(params));

  EXPECT_TRUE(setup.scSync->wait_opened(2s))
    << "the open callback must resolve (success or failure) once the OPN response is decoded";

  OverrideProbe probe;
  probe.openStatus = setup.scSync->openedStatus;
  probe.state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  probe.runtimeValidateCalls = setup.certStore->validate_call_count();
  probe.overrideValidateCalls = overrideStore ? overrideStore->validate_call_count() : 0;

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return probe;
}
}  // namespace

// @verifies CL-PULLCRT-001
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, TrustStoreOverrideIsConsultedForServerCertValidation)
{
  // The override store TRUSTS the server cert while the runtime (deps) store REJECTS it. If the
  // override is honoured the OPN opens the channel; if the runtime store were (wrongly) used the open
  // would fail. This is the RED->GREEN behaviour: without the Config store-selection the runtime store
  // is consulted (reject) and this fails.
  boost::asio::thread_pool tp;
  auto probe = drive_opn_with_override(tp,
    /*runtimeOutcome=*/StatusCode{Status::BadCertificateUntrusted},
    /*overrideOutcome=*/StatusCode{Status::Good});

  EXPECT_TRUE(probe.openStatus.is_good())
    << "the OVERRIDE store trusts the server cert, so the OPN must open the channel; got "
    << probe.openStatus.as_uint32();
  EXPECT_EQ(probe.state, SecureChannelImpl::ChannelState::Open);
  EXPECT_EQ(probe.overrideValidateCalls, 1u)
    << "the override store must be the store consulted for server-cert validation";
  EXPECT_EQ(probe.runtimeValidateCalls, 0u)
    << "the runtime (deps) store must NOT be consulted when an override is set";
}

// @verifies CL-PULLCRT-001
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, TrustStoreOverrideIsAuthoritativeOverRuntimeStore)
{
  // Inverse: the override REJECTS while the runtime store TRUSTS. The override must be authoritative,
  // so the open fails Bad_CertificateUntrusted and the channel closes - proving it is the override,
  // not the runtime store, that governs the OPN trust decision.
  boost::asio::thread_pool tp;
  auto probe = drive_opn_with_override(tp,
    /*runtimeOutcome=*/StatusCode{Status::Good},
    /*overrideOutcome=*/StatusCode{Status::BadCertificateUntrusted});

  EXPECT_TRUE(probe.openStatus.is_bad())
    << "the OVERRIDE store rejects the server cert, so the OPN must fail even though the runtime "
       "store trusts it";
  EXPECT_EQ(probe.openStatus, StatusCode{Status::BadCertificateUntrusted})
    << "the client must surface the override store's rejection status to the opener";
  EXPECT_EQ(probe.state, SecureChannelImpl::ChannelState::Closed)
    << "a rejected server certificate must close the channel";
  EXPECT_EQ(probe.overrideValidateCalls, 1u)
    << "the override store must be the store consulted for server-cert validation";
  EXPECT_EQ(probe.runtimeValidateCalls, 0u)
    << "the runtime (deps) store must NOT be consulted when an override is set";
}

// @verifies CL-PULLCRT-001
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, NullTrustStoreOverrideFallsBackToRuntimeStore)
{
  // A null override must not change behaviour: the runtime (deps) store governs. Two-sided so the
  // fallback is provably non-vacuous.
  {
    boost::asio::thread_pool tp;
    auto probe = drive_opn_with_override(tp,
      /*runtimeOutcome=*/StatusCode{Status::Good},
      /*overrideOutcome=*/std::nullopt);
    EXPECT_TRUE(probe.openStatus.is_good())
      << "with no override, a runtime-trusted server cert must open the channel";
    EXPECT_EQ(probe.state, SecureChannelImpl::ChannelState::Open);
    EXPECT_EQ(probe.runtimeValidateCalls, 1u)
      << "the runtime store must be consulted when no override is set";
  }
  {
    boost::asio::thread_pool tp;
    auto probe = drive_opn_with_override(tp,
      /*runtimeOutcome=*/StatusCode{Status::BadCertificateUntrusted},
      /*overrideOutcome=*/std::nullopt);
    EXPECT_TRUE(probe.openStatus.is_bad())
      << "with no override, a runtime-untrusted server cert must fail the open";
    EXPECT_EQ(probe.openStatus, StatusCode{Status::BadCertificateUntrusted});
    EXPECT_EQ(probe.state, SecureChannelImpl::ChannelState::Closed);
    EXPECT_EQ(probe.runtimeValidateCalls, 1u)
      << "the runtime store must be consulted when no override is set";
  }
}

// ---------------------------------------------------------------------------
// CL-UASC-007: the client verifies the RESPONSE's SecurityPolicyUri. An OPN response whose asymmetric
// security header carries a policy URI different from the configured one is rejected before any
// decrypt, and the channel closes. (Positive control: ForgedValidOpnResponseOpensChannel above, whose
// forge policy matches, opens the channel.)
// ---------------------------------------------------------------------------

// @verifies CL-UASC-007
// @relation(CL-UASC-007, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, MismatchedResponseSecurityPolicyRejectsChannel)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  // Client channel negotiated Basic256Sha256.
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Forge the OPN response under a DIFFERENT (valid) policy, so its plaintext security-header
  // SecurityPolicyUri does not match the client's configured Basic256Sha256.
  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Aes128Sha256RsaOaep);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 61;
  params.tokenId = 71;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve";
  EXPECT_EQ(setup.scSync->openedStatus, StatusCode{Status::BadSecurityPolicyRejected})
    << "a response whose SecurityPolicyUri does not match the configured policy must be rejected";
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-008: the client verifies the ReceiverCertificateThumbprint in the OPN response's asymmetric
// security header equals its OWN certificate's thumbprint. A response addressed to a different
// receiver certificate is rejected with Bad_CertificateInvalid and the channel closes.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-008
// @relation(CL-UASC-008, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, WrongReceiverThumbprintRejectsChannel)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Forge with the matching policy (so the policy-URI check passes) but a DECOY receiver certificate
  // (the server cert), so the header's ReceiverCertificateThumbprint is that of the decoy, not the
  // client's own cert. The thumbprint check runs before any decrypt, so the wrong-recipient
  // encryption is never reached.
  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    /*clientCert(receiver)=*/setup.serverCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 62;
  params.tokenId = 72;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve";
  EXPECT_EQ(setup.scSync->openedStatus, StatusCode{Status::BadCertificateInvalid})
    << "a response whose ReceiverCertificateThumbprint is not the client's own cert must be rejected";
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-004: the client closes the channel when an inbound chunk fails to decode. Here the OPN
// response's asymmetric security-header SecurityPolicyUri length prefix is corrupted so the header
// decode overruns; the client must surface a decode failure and close the channel rather than
// proceed. (The SecurityPolicyUri length is one of the header's length fields; the requirement's
// canonical example corrupts SenderCertificateLength - an equivalent security-header length field.
// Positive control: the same forge, unpatched, opens the channel above.)
// ---------------------------------------------------------------------------

// @verifies CL-UASC-004
// @relation(CL-UASC-004, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, InvalidSecurityHeaderLengthClosesChannel)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 63;
  params.tokenId = 73;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  auto chunk = forge->build_opn_response(params);

  // The asymmetric security header begins immediately after the fixed-size message header, with the
  // SecurityPolicyUri int32 length prefix. Overwrite it with a value that overruns the chunk.
  const size_t policyUriLenOffset = UaScMessageHeader::sizeInBytes;
  ASSERT_GT(chunk.size(), policyUriLenOffset + sizeof(uint32_t));
  const uint32_t bogusLength = 0x7FFFFFFFu;
  for (size_t i = 0; i < sizeof(uint32_t); ++i)
  {
    chunk[policyUriLenOffset + i] = static_cast<byte>((bogusLength >> (8 * i)) & 0xFFu);
  }

  feed_chunk(*setup.impl, std::move(chunk));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve";
  EXPECT_TRUE(setup.scSync->openedStatus.is_bad())
    << "a chunk with an invalid security-header length must fail to decode, not open the channel";
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed)
    << "a chunk decode failure must close the channel";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-005: "The contents of the MessageChunk shall not be interpreted until the Message is
// decrypted AND the signature ... verified." Two halves, one requirement, two tests:
//   (a) a chunk that fails to DECRYPT must not have its body interpreted (this test); and
//   (b) a chunk that decrypts but whose SIGNATURE is invalid must not have its body interpreted
//       (WrongSignatureOpnResponseIsRejectedBeforeBodyInterpretation below).
// Both prove the body is never reached: the channel does not open and the forged token is never
// adopted. (Positive control: ForgedValidOpnResponseOpensChannel opens and adopts the token when the
// chunk is intact.)
// ---------------------------------------------------------------------------

// @verifies CL-UASC-005
// @relation(CL-UASC-005, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, CorruptedCiphertextLeavesOpnBodyUninterpreted)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  const uint32_t forgedToken = 74;
  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 64;
  params.tokenId = forgedToken;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  auto chunk = forge->build_opn_response(params);

  // Corrupt the last byte of the chunk: it lies inside the RSA-OAEP-encrypted region, so the
  // asymmetric DECRYPT step fails its OAEP integrity check (decrypt runs before body interpretation).
  // The sibling test below covers the signature-verify half.
  ASSERT_FALSE(chunk.empty());
  chunk.back() = static_cast<byte>(static_cast<uint8_t>(chunk.back()) ^ 0xFFu);

  feed_chunk(*setup.impl, std::move(chunk));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve";
  EXPECT_TRUE(setup.scSync->openedStatus.is_bad())
    << "a chunk that fails to decrypt must not open the channel";
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed)
    << "a decrypt failure must close the channel; the body is never interpreted";
  EXPECT_NE(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), forgedToken)
    << "the forged token from the (never-interpreted) body must not have been adopted";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-UASC-005
// @relation(CL-UASC-005, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, WrongSignatureOpnResponseIsRejectedBeforeBodyInterpretation)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  // Sign the forged OPN response with a key pair that does NOT match the sender certificate, while
  // keeping the real server cert as the header SenderCertificate (so the client's cert-match passes)
  // and encrypting to the real client cert (so decrypt SUCCEEDS). The signature is therefore verified
  // against the server cert's public key and fails - this exercises the verify branch specifically,
  // which a decrypt-corruption cannot reach.
  auto wrongSigningKeys = setup.crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    /*serverKeys(signing)=*/wrongSigningKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  const uint32_t forgedToken = 75;
  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 65;
  params.tokenId = forgedToken;
  params.serverNonce = make_nonce(*setup.crypto, 32);
  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve";
  EXPECT_EQ(setup.scSync->openedStatus, StatusCode{Status::BadApplicationSignatureInvalid})
    << "a decryptable chunk whose signature does not verify must be rejected at the verify step";
  auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed)
    << "a signature-verification failure must close the channel; the body is never interpreted";
  EXPECT_NE(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_token_id(); }), forgedToken)
    << "the forged token from the (never-interpreted) body must not have been adopted";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-004 (Part 4 6.1.7): the server certificate must be re-validated every time the
// SecurityToken is renewed. The client re-runs the OPN decode path (including
// validate_certificate_async) on the OPN-RENEW response, so a cert that becomes untrusted between
// open and renewal is caught at renewal and the channel is torn down.
// SCOPE: covers "re-validates on renew" + "disconnects on renewal-validation-failure". The
// "picks up a refreshed CRL at renewal" sub-obligation (CRL revocation between open and renewal) needs
// CRL manipulation in the store and is deferred.
// ---------------------------------------------------------------------------

namespace
{
// Feeds a forged Issue OPN response (token 1) and waits for the channel to open.
void open_via_forged_issue(
  WiredSecureChannelSetup& setup, ua::test_helpers::ServerChunkForge& forge, uint32_t channelId)
{
  ua::test_helpers::ServerChunkForge::OpnRespParams issue;
  issue.secureChannelId = channelId;
  issue.tokenId = 1;
  issue.serverNonce = make_nonce(*setup.crypto, 32);
  feed_chunk(*setup.impl, forge.build_opn_response(issue));
  ASSERT_TRUE(setup.scSync->wait_opened(5s)) << "the initial forged Issue OPN must open the channel";
}

// Triggers a token renewal (a real OPN-RENEW request is sent) and feeds a forged RENEW OPN response
// (token 2). The forged RENEW drives the client's decode - including the mandatory re-validation - but
// is not a full renewal completion, so callers assert only the re-validation (and, on rejection, the
// close), never a completed-renewal state.
void renew_via_forge(
  WiredSecureChannelSetup& setup, ua::test_helpers::ServerChunkForge& forge, uint32_t channelId)
{
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_token_renewal(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 5s)) << "renewal must send an OPN-RENEW request";
  ua::test_helpers::ServerChunkForge::OpnRespParams renew;
  renew.secureChannelId = channelId;
  renew.tokenId = 2;
  renew.serverNonce = make_nonce(*setup.crypto, 32);
  feed_chunk(*setup.impl, forge.build_opn_response(renew));
}

// Polls (bounded) until the store's validate-call count reaches @p n.
bool wait_for_validate_count(WiredSecureChannelSetup& setup, std::size_t n)
{
  auto deadline = std::chrono::steady_clock::now() + 5s;
  while (setup.certStore->validate_call_count() < n && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  return setup.certStore->validate_call_count() >= n;
}
}  // namespace

// @verifies CL-SECADMIN-004
// @relation(CL-SECADMIN-004, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, ServerCertificateRevalidatedOnTokenRenewal)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  open_via_forged_issue(setup, *forge, /*channelId*/ 90);
  // The initial open validates the server certificate exactly once.
  EXPECT_TRUE(wait_for_validate_count(setup, 1));
  EXPECT_EQ(setup.certStore->validate_call_count(), 1u)
    << "the initial channel open validates the server certificate exactly once";

  renew_via_forge(setup, *forge, /*channelId*/ 90);
  // The renewal must RE-VALIDATE, taking the total to two. This is the required obligation; it is
  // deterministic (validation runs synchronously inside the OPN-RENEW decode flow).
  EXPECT_TRUE(wait_for_validate_count(setup, 2))
    << "the SecurityToken renewal must re-validate the server certificate";
  EXPECT_EQ(setup.certStore->validate_call_count(), 2u)
    << "the SecurityToken renewal re-validates the server certificate (open=1, renew=2)";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SECADMIN-004
// @relation(CL-SECADMIN-004, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, RenewalServerCertValidationFailureClosesChannel)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    setup.serverCert,
    setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);

  open_via_forged_issue(setup, *forge, /*channelId*/ 91);
  ASSERT_TRUE(wait_for_validate_count(setup, 1));

  // Between open and renewal the server certificate becomes untrusted.
  setup.certStore->set_validate_status(StatusCode{Status::BadCertificateUntrusted});
  renew_via_forge(setup, *forge, /*channelId*/ 91);

  // The renewal re-validation rejects the now-untrusted cert, failing the OPN-RENEW decode and closing
  // the channel. This close is immediate (synchronous in the decode flow the moment the forged RENEW is
  // fed), so it is attributable to the rejection, not to any later renewal-deadline timeout. Requiring
  // that validation actually re-ran (count == 2) pins the close to the re-validation step specifically.
  EXPECT_TRUE(wait_for_validate_count(setup, 2))
    << "the renewal must re-run validation (open=1, renew=2) before rejecting";
  auto deadline = std::chrono::steady_clock::now() + 5s;
  auto channelClosed = [&]
  {
    return STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }) ==
           SecureChannelImpl::ChannelState::Closed;
  };
  while (!channelClosed() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  EXPECT_TRUE(channelClosed())
    << "a server certificate that fails re-validation at renewal must close the channel";

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-007: an ApplicationInstanceCertificate must be present for an authenticated channel.
// When the certificate store has no own certificate to provide, the client must NOT proceed with the
// OpenSecureChannel handshake; the open fails and no OPN is emitted on the wire.
//
// SCOPE (partial tag): the spec frames this as a CoreClient::create precondition; the implementation
// enforces it at channel-open (connect) time, which this test verifies. This discharges the
// required behaviour - the client refuses to proceed (emits no OPN) with no own cert. It does
// NOT cover the create-time timing, the BadConfigurationError status class, the "ErrorDetail names
// the missing cert" clause, or the None-mode exemption; those are recorded for the maintainer
// (CL-SECADMIN-007).
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-007
// @relation(CL-SECADMIN-007, scope=function)
TEST(ClientSecureChannelCryptoTests, AbsentOwnCertificateFailsAuthenticatedChannelOpen)
{
  // Positive control: with an own cert present, the authenticated open proceeds far enough to emit
  // the OPN request on the wire (HEL + OPN = 2 writes).
  {
    boost::asio::thread_pool tp;
    auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
    EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s))
      << "with an own cert present the client must send its OPN request";
    setup.impl.reset();
    setup.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }

  // Negative: the store reports no own cert. The client must fail the open before sending any OPN.
  {
    boost::asio::thread_pool tp;
    // BadNotFound matches what the real file-backed store returns when no own cert is present
    // (ua_certificate_store_files.cpp); the client surfaces the store's status verbatim.
    auto setup = WiredSecureChannelSetup::create(tp.get_executor(),
      MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::Basic256Sha256,
      [](TestCertificateStore& store) { store.set_own_certificate_status(StatusCode{Status::BadNotFound}); });

    ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open callback must resolve (as a failure)";
    EXPECT_TRUE(setup.scSync->openedStatus.is_bad())
      << "an authenticated open with no own certificate must fail, not proceed";

    // The decisive check: the client must not have emitted an OPN request. Only the HEL write
    // (from the transport handshake) may be present; a second write would mean an OPN was sent.
    STA::strand_barrier(*setup.impl);
    EXPECT_LT(setup.transport->writes().size(), 2u)
      << "no OpenSecureChannel request may be emitted when the client has no own certificate";

    auto state = STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); });
    EXPECT_EQ(state, SecureChannelImpl::ChannelState::Closed);

    setup.impl.reset();
    setup.connection.reset();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// ===========================================================================
// Appended coverage: CL-DISC-001, CL-SC-014, CL-UASC-021, CL-SECADMIN-006.
//
// All reuse the file-scope harness above (WiredSecureChannelSetup, parse_opn_chunk,
// decode_plaintext_opn_request, open_authenticated_channel, parse_symmetric_chunk_header,
// ServerChunkForge / feed_chunk / single_pending_request_id / ServiceResponseSync, and the
// SecureChannelTestAccess accessors). Two small NEW test-double helpers are added below
// (build_impl_on_store, RotatableCertificateStore) rather than editing the existing
// WiredSecureChannelSetup::create, to keep the change append-only.
// ===========================================================================

// ---------------------------------------------------------------------------
// CL-DISC-001: the client populates the OpenSecureChannel purely from the security parameters it was
// given DIRECTLY (endpoint URL + SecurityPolicy + MessageSecurityMode + server certificate), with no
// GetEndpoints/discovery step preceding the open. Here the harness hands the client its policy
// (Basic256Sha256) and mode (SignAndEncrypt) directly and sets up NO discovery round-trip; the OPN the
// client emits must carry exactly those supplied values. The plaintext AsymmetricSecurityHeader must
// name the supplied policy, and the encrypted body's OpenSecureChannelRequest.SecurityMode (recovered
// by decrypting with the server key) must equal the supplied mode.
//
// A distinct oracle from CL-UASC-007's OpnPolicyMatchesConfiguredPolicy: this frames the assertion as
// "the params supplied directly on the discovery-disabled path are the ones on the wire" and also pins
// the SecurityMode (not just the policy URI). Falsified by any client that ignores/renegotiates the
// supplied policy/mode or that would need a GetEndpoints response to populate the OPN.
//
// SCOPE (deferred, not unit-testable here): (a) the OpenChannelConfig->SecureChannelImpl::Config field
// forward at ua_client_impl.cpp:594-604, and (b) the whole-flow "zero GetEndpoints observed on the
// wire" assertion both need CoreClientImpl::open_channel_async driven end to end (a connector-injection
// interface that does not exist today). Both are assigned to the integration MisbehavingServer
// message-type-recorder row (ClientConfigureEndpoint.ExactUrlConnectsWithoutGetEndpoints); the "no
// GetEndpoints" half is additionally structurally guaranteed (open_channel_async has no discovery
// branch).
// ---------------------------------------------------------------------------

// NOT a CL-DISC-001 verifier (tag removed after adversarial review): at the SecureChannelImpl layer
// there is no discovery/ExactUrl/GetEndpoints-skip branch, so "without discovery" is a tautology here.
// This is a supplementary pin that the OPN reflects the directly-configured policy AND SecurityMode
// (a strict superset of CL-UASC-007's policy-only pin). CL-DISC-001 proper (the discovery-disabled
// connect path that skips GetEndpoints and fails closed on a missing policy) is owed a CoreClientImpl-layer
// test with a connector-capture interface - left uncovered (residual/maintainer flag).
TEST(ClientSecureChannelCryptoTests, SuppliedSecurityParamsPopulateOpnWithoutDiscovery)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Directly supply endpoint + policy + mode + server cert; NO discovery step is configured.
  auto setup = WiredSecureChannelSetup::create(
    ex, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 2u);

  auto& opnChunk = writes[1];
  auto parsed = parse_opn_chunk(span<const byte>{opnChunk}, *setup.crypto);

  // Load-bearing oracle: the OPN's plaintext SecurityPolicyUri equals the directly-supplied policy.
  EXPECT_EQ(
    parsed.securityHeader.securityPolicyUri, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
    << "the OPN SecurityPolicyUri must be the directly-supplied policy (no discovery output consulted)";

  // Strengthening: recover the encrypted OpenSecureChannelRequest.SecurityMode by decrypting the body
  // with the server key pair; it must equal the directly-supplied SignAndEncrypt. This proves the
  // supplied MODE (not just the policy URI) drove the OPN body.
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = setup.crypto;
  context->securityPolicy = policy;
  context->localCertificate = setup.serverCert;
  context->localKeyPair = setup.serverKeys;
  context->encodingLimits = test_limits();

  auto decrypted = ua::test_helpers::run_async_callback_sync<ByteStringResult>(
    [&](auto cb) {
      policy->asymmetric_decrypt_async(
        *context, span<const byte>{opnChunk}, parsed.bodyOffset, std::move(cb));
    }).value();

  auto request = decode_plaintext_opn_request(span<const byte>{decrypted}, *setup.crypto);
  EXPECT_EQ(request.security_mode(), MessageSecurityMode::SignAndEncrypt)
    << "the OPN body SecurityMode must be the directly-supplied mode, got: "
    << static_cast<int>(request.security_mode());

  context.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// New test-double helpers for CL-UASC-021 / CL-SECADMIN-006 (append-only additions; the existing
// WiredSecureChannelSetup::create is not modified).
// ---------------------------------------------------------------------------

namespace
{

// Bounded sync for the persistent post-open channel-error observer (Config::onChannelError).
struct ChannelErrorSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool fired{false};
  StatusCode status{Status::Good};

  void fire(StatusCode s)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      fired = true;
      status = s;
    }
    cv.notify_one();
  }

  bool wait(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this] { return fired; });
  }
};

// A SecureChannelImpl wired on an externally-supplied deps (so several impls can share one certificate
// store / crypto), with an optional Config hook (used to wire Config::onChannelError, which
// WiredSecureChannelSetup::create leaves empty). Mirrors create()'s transport + HEL/ACK + impl wiring.
struct ImplOnStore
{
  std::shared_ptr<FakeTransportConnection> transport;
  std::shared_ptr<FakeConnectionProtocolDeps> cpDeps;
  std::shared_ptr<ConnectionProtocol> connection;
  std::shared_ptr<CryptoCallbackSync> scSync;
  std::shared_ptr<SecureChannelImpl> impl;
};

ImplOnStore build_impl_on_store(boost::asio::any_io_executor ex,
  std::shared_ptr<CryptoSecureChannelDeps> deps, MessageSecurityMode securityMode, SecurityPolicyId policyId,
  std::shared_ptr<const X509Certificate> serverCert,
  const std::function<void(SecureChannelImpl::Config&)>& configHook = {},
  std::chrono::milliseconds fatalCloseTimeout = ConnectionProtocol::defaultFatalCloseTimeout)
{
  ImplOnStore out;
  out.transport = std::make_shared<FakeTransportConnection>();
  out.cpDeps = std::make_shared<FakeConnectionProtocolDeps>(ex);
  out.transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

  auto connSync = std::make_shared<ConnHandshakeSync>();
  out.connection = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    out.cpDeps,
    out.transport,
    false,
    60s,
    [connSync](StatusCode st,
      shared_ptr<ConnectionProtocol>
        cp,
      connection_protocol::NegotiatedLimits negotiated,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(connSync->mx);
        connSync->complete = true;
        connSync->completeStatus = st;
        connSync->negotiatedLimits = negotiated;
        connSync->completedCp = std::move(cp);
      }
      connSync->cv.notify_one();
    },
    [connSync](StatusCode st, string_view /*reason*/, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(connSync->mx);
        connSync->errorOccurred = true;
        connSync->errorStatus = st;
      }
      connSync->cv.notify_one();
    },
    "opc.tcp://localhost:4840",
    /*endpointUrlValidator=*/{},
    /*messageReadTimeout=*/std::chrono::milliseconds{10'000},
    /*serverUri=*/{},
    /*reverseHelloValidator=*/{},
    /*closeObserver=*/{},
    fatalCloseTimeout);

  EXPECT_TRUE(connSync->wait_complete(2s)) << "HEL/ACK handshake did not complete for build_impl_on_store";

  out.scSync = std::make_shared<CryptoCallbackSync>();
  auto scSync = out.scSync;

  SecureChannelImpl::Config config;
  config.securityMode = securityMode;
  config.securityPolicyId = policyId;
  config.endpointUrl = "opc.tcp://localhost:4840";
  config.serverCertificate = std::move(serverCert);
  if (configHook)
  {
    configHook(config);
  }

  out.impl = SecureChannelImpl::create(
    deps,
    out.connection,
    connSync->negotiatedLimits,
    config,
    [scSync](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(scSync->mx);
        scSync->opened = true;
        scSync->openedStatus = result.status_code();
      }
      scSync->cv.notify_one();
    },
    [scSync](VoidResult result)
    {
      {
        std::lock_guard<std::mutex> lk(scSync->mx);
        scSync->errorOccurred = true;
        scSync->errorStatus = result.status_code();
      }
      scSync->cv.notify_one();
    });

  return out;
}

// A certificate store whose own ApplicationInstanceCertificate can be ROTATED at runtime (models an
// administrator swapping the client key/cert with no SDK restart). It extends the file's
// TestCertificateStore and overrides only the own-certificate accessor to return whatever is currently
// installed under a mutex; all other behaviour (trust, validate, ...) is inherited unchanged.
class RotatableCertificateStore : public TestCertificateStore
{
public:
  RotatableCertificateStore(
    CertificateStore::ApplicationCertificate initial, std::shared_ptr<const X509Certificate> serverCert)
    : TestCertificateStore(initial, std::move(serverCert)), mCurrent(std::move(initial))
  {}

  void rotate_application_certificate(CertificateStore::ApplicationCertificate next)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mCurrent = std::move(next);
  }

  void get_application_certificate_async(
    CertificateType /*certificateType*/, GetApplicationCertificateCallback callback) const noexcept override
  {
    CertificateStore::ApplicationCertificate cert;
    {
      std::lock_guard<std::mutex> lk(mMutex);
      cert = mCurrent;
    }
    callback(ApplicationCertificateResult{std::move(cert)});
  }

private:
  mutable std::mutex mMutex;
  CertificateStore::ApplicationCertificate mCurrent;
};

// Decrypts an OPN chunk with the server key pair, isolates the trailing asymmetric signature (its size
// determined by @p signerCert), and returns whether it verifies against @p candidateCert's public key -
// i.e. whether that key signed the OPN. Reuses the decrypt/verify pattern of
// OpnRequestSignatureVerifiesWithClientPublicKey.
bool opn_signature_verifies_with(boost::asio::any_io_executor ex, const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const X509Certificate>& serverCert,
  const std::shared_ptr<const AsymmetricKeyPair>& serverKeys, const X509Certificate& signerCert,
  span<const byte> opnChunk, const X509Certificate& candidateCert)
{
  auto parsed = parse_opn_chunk(opnChunk, *crypto);
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = crypto;
  context->securityPolicy = policy;
  context->localCertificate = serverCert;
  context->localKeyPair = serverKeys;
  context->encodingLimits = test_limits();

  auto decrypted = ua::test_helpers::run_async_callback_sync<ByteStringResult>(
    [&](auto cb) {
      policy->asymmetric_decrypt_async(*context, opnChunk, parsed.bodyOffset, std::move(cb));
    }).value();

  const size_t signatureSize = policy->asymmetric_signature_size(&signerCert);
  if (decrypted.size() <= signatureSize)
  {
    return false;
  }

  span<const byte> decryptedBytes = decrypted;
  span<const byte> signedRegion = decryptedBytes.subspan(0, decrypted.size() - signatureSize);
  span<const byte> signature = decryptedBytes.subspan(decrypted.size() - signatureSize, signatureSize);

  auto candidatePublicKey = candidateCert.public_key();
  try
  {
    crypto->asymmetric_verify_sync(
      policy->asymmetric_signature_algorithm(), candidatePublicKey, signedRegion, signature);
    return true;
  }
  catch (...)
  {
    return false;
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// CL-SC-014: a secured (symmetric) request is SIGNED with the key associated with the CURRENT
// SecurityToken. The existing SymmetricMessageCarriesCurrentTokenId (CL-SC-009) only checks the header
// TokenId; this test additionally proves the trailing HMAC verifies under the signing key independently
// re-derived (ChannelRole::Client) from the channel's OWN negotiated nonces (the client nonce it
// actually used + the test's server nonce) - i.e. the current token's local key. Sign-only mode keeps
// the HMAC in the plaintext chunk tail so no decrypt is needed.
//
// Falsifiable: a client that skips signing, signs with the peer/remote key, or with a stale/wrong
// token's key makes symmetric_verify_sync throw. The negative cross-check (the REMOTE derived key must
// NOT verify) proves the local current-token key is required, which the TokenId-only test cannot.
// ---------------------------------------------------------------------------

// @verifies CL-SC-014
// @relation(CL-SC-014, scope=function)
TEST(ClientSecureChannelCryptoTests, SymmetricRequestSignedWithCurrentTokenKey)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  // Sign-only so the symmetric signature sits in the plaintext chunk tail (no decrypt required).
  auto setup =
    WiredSecureChannelSetup::create(ex, MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, /*secureChannelId*/ 88, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the Sign-mode channel should open on a good OPN response";

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  // STIMULUS: drive the real send path -> symmetric encode -> sign with the active token's local key.
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), [](auto) {});
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 3u);
  const auto& chunk = writes[2];

  // ORACLE: independently re-derive the client's LOCAL signing key (ChannelRole::Client, local=client
  // nonce, remote=server nonce) and verify the trailing HMAC over the rest of the chunk.
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = setup.crypto;
  context->securityPolicy = policy;
  context->encodingLimits = test_limits();

  auto derived = ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [&](auto cb)
    {
      policy->derive_symmetric_keys_async(
        context, clientNonce, serverNonce, ChannelRole::Client, std::move(cb));
    }).value();

  const auto& localSigningKey = derived.first.signingKey;  // local = client's own keys
  const auto& remoteSigningKey = derived.second.signingKey;  // remote = peer keys (must NOT verify)
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(chunk.size(), signatureSize);

  span<const byte> chunkBytes{chunk};
  span<const byte> signedRegion = chunkBytes.subspan(0, chunk.size() - signatureSize);
  span<const byte> actualSig = chunkBytes.subspan(chunk.size() - signatureSize, signatureSize);
  const auto algorithm = policy->symmetric_signature_algorithm();

  // The request is signed with the CURRENT token's local signing key.
  EXPECT_NO_THROW(setup.crypto->symmetric_verify_sync(
    algorithm, span<const byte>{localSigningKey}, signedRegion, actualSig))
    << "the symmetric request must be signed with the current token's local signing key";
  // The peer/remote key must NOT verify - the local current-token key is required.
  EXPECT_ANY_THROW(setup.crypto->symmetric_verify_sync(
    algorithm, span<const byte>{remoteSigningKey}, signedRegion, actualSig))
    << "the request must not verify under the remote (peer) key";
  // Bind the verified signature to the current token id.
  EXPECT_EQ(parse_symmetric_chunk_header(chunkBytes).securityHeader.tokenId, tokenId);

  context.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-014
// The CloseSecureChannel (CLO) request is likewise signed with the current token's local key. This ties
// to the start_close/CLO disposition note: the existing CloseRequestCarriesCurrentTokenId only checks
// the CLO's header TokenId; here the CLO's trailing HMAC must verify under the independently re-derived
// current-token local signing key (and must NOT verify under the remote key).
// @relation(CL-SC-014, scope=function)
TEST(ClientSecureChannelCryptoTests, CloseRequestSignedWithCurrentTokenKey)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup =
    WiredSecureChannelSetup::create(ex, MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t tokenId = 555;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, /*secureChannelId*/ 88, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  // STIMULUS: request a channel close; the client emits a CLO chunk secured with the current token.
  STA::on_strand(*setup.impl, [](auto& g) { g.handle_close_requested(); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s)) << "close should emit a CLO chunk";
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 3u);
  const auto& chunk = writes[2];

  auto parsedHeader = parse_symmetric_chunk_header(span<const byte>{chunk});
  ASSERT_EQ(parsedHeader.header.messageType, UaScMessageHeader::MessageType::Close)
    << "the close chunk must be framed as a CLO message";

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = setup.crypto;
  context->securityPolicy = policy;
  context->encodingLimits = test_limits();

  auto derived = ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [&](auto cb)
    {
      policy->derive_symmetric_keys_async(
        context, clientNonce, serverNonce, ChannelRole::Client, std::move(cb));
    }).value();

  const auto& localSigningKey = derived.first.signingKey;
  const auto& remoteSigningKey = derived.second.signingKey;
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(chunk.size(), signatureSize);

  span<const byte> chunkBytes{chunk};
  span<const byte> signedRegion = chunkBytes.subspan(0, chunk.size() - signatureSize);
  span<const byte> actualSig = chunkBytes.subspan(chunk.size() - signatureSize, signatureSize);
  const auto algorithm = policy->symmetric_signature_algorithm();

  EXPECT_NO_THROW(setup.crypto->symmetric_verify_sync(
    algorithm, span<const byte>{localSigningKey}, signedRegion, actualSig))
    << "the CLO request must be signed with the current token's local signing key";
  EXPECT_ANY_THROW(setup.crypto->symmetric_verify_sync(
    algorithm, span<const byte>{remoteSigningKey}, signedRegion, actualSig))
    << "the CLO request must not verify under the remote (peer) key";
  EXPECT_EQ(parsedHeader.securityHeader.tokenId, tokenId);

  context.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-TCP-014 (Part 6 7.1.5): a client that encounters a fatal error reports it and sends a
// CloseSecureChannel. The CLO is a secured UASC message (6.7.2.2-6.7.2.4: SecureChannelId, TokenId,
// sequence header) signed with the current token's key (Part 4 5.5.3.1), so the SecureChannel builds it
// through its normal encode pipeline once the ConnectionProtocol reports a fatal error that left the
// socket writable. The stimulus is an invalid message type after the channel opened.
// ---------------------------------------------------------------------------

namespace
{

/// A connection-protocol header whose message type is no UA message type: a fatal error after which the
/// socket is still writable (Part 6 7.1.2.2).
std::vector<byte> invalid_message_type_header()
{
  return std::vector<byte>{static_cast<byte>('X'),
    static_cast<byte>('Y'),
    static_cast<byte>('Z'),
    static_cast<byte>('F'),
    static_cast<byte>(16),
    static_cast<byte>(0),
    static_cast<byte>(0),
    static_cast<byte>(0)};
}

/// Counts the completions of one service request and keeps the last status.
struct RequestOutcome
{
  std::mutex mx;
  std::condition_variable cv;
  int count{0};
  StatusCode status{Status::Good};

  SecureChannelImpl::ServiceResponseCallback callback()
  {
    return [this](SecureChannelImpl::ServiceResponseResult result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        ++count;
        status = result.status_code();
      }
      cv.notify_all();
    };
  }

  bool wait(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return count > 0; });
  }
};

}  // namespace

// Sign mode keeps the sequence header and the signature in plaintext, so the whole CLO is checkable:
// its header names the opened SecureChannelId, its TokenId is the current token, its sequence number
// follows the request sent before it, and its signature verifies under the client's current-token
// signing key (the pattern of CloseRequestSignedWithCurrentTokenKey). The pending request is failed with
// the fatal status (the report to the application) before the socket closes, and the socket closes only
// after the CLO. Falsifiable: the former bare 8-byte "CLOF" frame fails every framing assertion, and a
// client that closed without a CLO leaves three writes.
// @verifies AC-CL-TCP-014-01
// @relation(AC-CL-TCP-014-01, scope=function)
TEST(ClientSecureChannelCryptoTests, FatalErrorOnOpenChannelSendsCloSignedWithCurrentToken)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto setup =
    WiredSecureChannelSetup::create(ex, MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t secureChannelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*setup.crypto, 32);
  open_authenticated_channel(setup, secureChannelId, tokenId, 600000ms, serverNonce);
  ASSERT_TRUE(setup.scSync->wait_opened(2s));
  auto clientNonce = STA::on_strand(*setup.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  // A request in flight when the fatal error arrives: its MSG is the message the CLO follows.
  RequestOutcome outcome;
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), outcome.callback());
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s));

  // STIMULUS: a fatal error after which the socket is still writable.
  setup.transport->enqueue_read_exact(invalid_message_type_header());

  ASSERT_TRUE(outcome.wait()) << "the fatal error must be reported (the pending request fails)";
  EXPECT_EQ(outcome.status, Status::BadTcpMessageTypeInvalid);
  ASSERT_TRUE(setup.transport->wait_for_write_count(4, 3s)) << "a CloseSecureChannel must be written";
  ASSERT_TRUE(setup.transport->wait_for_close(3s)) << "the socket closes after the CLO";
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{4u})
    << "the CLO is written before the socket closes";

  auto writes = setup.transport->writes();
  ASSERT_EQ(writes.size(), 4u);
  const auto request = parse_symmetric_chunk_header(span<const byte>{writes[2]});
  const auto& chunk = writes[3];
  const auto closeChunk = parse_symmetric_chunk_header(span<const byte>{chunk});
  EXPECT_EQ(closeChunk.header.messageType, UaScMessageHeader::MessageType::Close);
  EXPECT_EQ(closeChunk.header.secureChannelId, secureChannelId);
  EXPECT_EQ(closeChunk.securityHeader.tokenId, tokenId);
  EXPECT_EQ(closeChunk.sequenceHeader.sequenceNumber, request.sequenceHeader.sequenceNumber + 1)
    << "the CLO's sequence number follows the previous message's";

  // ORACLE: re-derive the client's local signing key for the current token and verify the CLO's HMAC.
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(ex);
  context->crypto = setup.crypto;
  context->securityPolicy = policy;
  context->encodingLimits = test_limits();
  auto derived = ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [&](auto cb)
    {
      policy->derive_symmetric_keys_async(
        context, clientNonce, serverNonce, ChannelRole::Client, std::move(cb));
    }).value();
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(chunk.size(), signatureSize);
  span<const byte> chunkBytes{chunk};
  span<const byte> signedRegion = chunkBytes.subspan(0, chunk.size() - signatureSize);
  span<const byte> actualSig = chunkBytes.subspan(chunk.size() - signatureSize, signatureSize);
  EXPECT_NO_THROW(setup.crypto->symmetric_verify_sync(policy->symmetric_signature_algorithm(),
    span<const byte>{derived.first.signingKey},
    signedRegion,
    actualSig))
    << "the CLO must be signed with the current token's local signing key";

  EXPECT_EQ(STA::on_strand(*setup.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  EXPECT_EQ(outcome.count, 1) << "the request is failed exactly once";

  context.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// SignAndEncrypt: the CLO's header and security header stay plaintext, so its type, SecureChannelId and
// TokenId are checked on the wire; the rest is encrypted under the current token.
// @verifies AC-CL-TCP-014-01
// @relation(AC-CL-TCP-014-01, scope=function)
TEST(ClientSecureChannelCryptoTests, FatalErrorOnOpenEncryptedChannelSendsCloUnderCurrentToken)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));

  const uint32_t secureChannelId = 91;
  const uint32_t tokenId = 555;
  open_authenticated_channel(setup, secureChannelId, tokenId, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  setup.transport->enqueue_read_exact(invalid_message_type_header());

  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s)) << "a CloseSecureChannel must be written";
  ASSERT_TRUE(setup.transport->wait_for_close(3s));
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{3u});

  auto writes = setup.transport->writes();
  ASSERT_EQ(writes.size(), 3u);
  const auto closeChunk = parse_symmetric_chunk_header(span<const byte>{writes[2]});
  EXPECT_EQ(closeChunk.header.messageType, UaScMessageHeader::MessageType::Close);
  EXPECT_EQ(closeChunk.header.secureChannelId, secureChannelId);
  EXPECT_EQ(closeChunk.securityHeader.tokenId, tokenId);
  EXPECT_GT(writes[2].size(), ua::connection_protocol::headerSize) << "not the bare 8-byte CLOF frame";

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A dead socket (a read error after the channel opened) cannot carry a CLO: the pending request is failed
// once with the transport's status, the socket is closed and nothing is written after the request.
// Falsifiable: a channel that tried its CLO on a dead socket leaves a fourth write.
// @verifies AC-CL-TCP-014-02
// @relation(AC-CL-TCP-014-02, scope=function)
TEST(ClientSecureChannelCryptoTests, ReadErrorOnOpenChannelSendsNoClo)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  open_authenticated_channel(setup, 88, 4242, 600000ms, make_nonce(*setup.crypto, 32));
  ASSERT_TRUE(setup.scSync->wait_opened(2s));

  RequestOutcome outcome;
  setup.impl->send_request(std::make_shared<ua::ReadRequest>(), outcome.callback());
  ASSERT_TRUE(setup.transport->wait_for_write_count(3, 3s));

  setup.transport->enqueue_read_error(Status::BadCommunicationError, "connection reset");

  ASSERT_TRUE(outcome.wait());
  EXPECT_EQ(outcome.status, Status::BadCommunicationError);
  ASSERT_TRUE(setup.transport->wait_for_close(3s));
  EXPECT_FALSE(setup.transport->wait_for_write_count(4, 300ms)) << "no CLO may follow a dead socket";
  EXPECT_EQ(setup.transport->writes().size(), 3u);
  EXPECT_EQ(outcome.count, 1) << "the error is reported once";

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Before the OpenSecureChannel response there is no SecureChannelId or token, so no CLO exists: a fatal
// error that left the socket writable fails the open and closes the socket with nothing written after
// the OPN. Falsifiable: a channel that sent a CLO in Opening leaves a third write.
// @verifies AC-CL-TCP-014-02
// @relation(AC-CL-TCP-014-02, scope=function)
TEST(ClientSecureChannelCryptoTests, FatalErrorBeforeOpenSendsNoClo)
{
  boost::asio::thread_pool tp;
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(), MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  setup.transport->enqueue_read_exact(invalid_message_type_header());

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open must complete, failed";
  EXPECT_EQ(setup.scSync->openedStatus.as_status(), Status::BadTcpMessageTypeInvalid);
  ASSERT_TRUE(setup.transport->wait_for_close(3s));
  EXPECT_FALSE(setup.transport->wait_for_write_count(3, 300ms)) << "no CLO exists before the open";
  EXPECT_EQ(setup.transport->writes().size(), 2u);

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-021: when an inbound secured chunk fails cryptographic verification AFTER the channel is
// open, the client must close the channel AND fire the persistent post-open observer
// (Config::onChannelError) - the reconnect / re-open trigger. Here a validly-framed symmetric chunk
// (correct SecureChannelId + token id + request id) is corrupted in its crypto-protected tail so the
// symmetric verify fails; the observer must fire once with a bad status.
//
// A positive phase first delivers an INTACT chunk (same headers), which is delivered Good, keeps the
// channel open, and leaves the observer SILENT - proving the subsequent close+observer-fire is caused
// specifically by the CRYPTO verification failure (distinguishing this from CL-UASC-006's pre-crypto
// SecureChannelId rejection). The observer-fired assertion is required: without it the test would
// only prove "closes on bad verify", not the re-open obligation.
//
// The channel-under-test is built via build_impl_on_store so Config::onChannelError can be wired (the
// existing WiredSecureChannelSetup::create leaves it empty); all crypto/cert material is reused from a
// WiredSecureChannelSetup::create for the forge.
// ---------------------------------------------------------------------------

// @verifies CL-UASC-021 [PARTIAL] - covers the SecureChannelImpl half: a post-open verification error
// closes the channel and FIRES the persistent mOnChannelError observer (the reconnect trigger). The
// requirement's re-open obligation (the client then attempts to send a fresh OpenSecureChannel) is owned
// by the reconnection FSM and is NOT asserted here (its companion ClientReconnectionTests.
// ReconnectCreatesNewChannelAndActivatesSession is a state!=Closed stub) - deferred/residual.
// @relation(CL-UASC-021, scope=function)
TEST(ClientSecureChannelInboundDecodeTests, PostOpenVerifyFailureFiresChannelErrorObserver)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Material provider (crypto, client/server keys+certs, cert store, deps). Its own impl is unused.
  auto seed = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(seed.transport->wait_for_write_count(2, 3s));

  // Channel under test: a second impl on the SAME store/deps, with the post-open error observer wired.
  auto errorSync = std::make_shared<ChannelErrorSync>();
  auto handle = build_impl_on_store(ex,
    seed.deps,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    seed.serverCert,
    [errorSync](SecureChannelImpl::Config& config)
    {
      config.onChannelError = [errorSync](VoidResult result)
      {
        errorSync->fire(result.status_code());
      };
    });
  ASSERT_TRUE(handle.transport->wait_for_write_count(2, 3s)) << "the channel-under-test must send its OPN";

  const uint32_t channelId = 88;
  const uint32_t tokenId = 4242;
  auto serverNonce = make_nonce(*seed.crypto, 32);
  STA::on_strand(*handle.impl,
    [&](auto& g)
    { g.handle_opn_response(StatusCode{Status::Good}, channelId, tokenId, 600000ms, serverNonce, nullptr); });
  ASSERT_TRUE(handle.scSync->wait_opened(2s)) << "the channel-under-test must open (mOnChannelError armed)";

  auto clientNonce =
    STA::on_strand(*handle.impl, [](auto& g) -> ByteString { return g.last_client_nonce(); });
  ASSERT_EQ(clientNonce.size(), 32u);

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    seed.crypto,
    seed.serverCert,
    seed.serverKeys,
    seed.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256);
  forge->set_token_from_nonces(clientNonce, serverNonce, tokenId, 600000ms);

  // Positive phase: an INTACT chunk (correct headers) is delivered Good, keeps the channel open, and
  // leaves the observer silent.
  auto goodSync = std::make_shared<ServiceResponseSync>();
  handle.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [goodSync](auto result) { goodSync->set(std::move(result)); });
  auto goodRequestId = single_pending_request_id(*handle.impl);
  ASSERT_NE(goodRequestId, 0u);

  ua::test_helpers::ServerChunkForge::SymMsgParams goodParams;
  goodParams.secureChannelId = channelId;
  goodParams.tokenId = tokenId;
  goodParams.requestId = goodRequestId;
  goodParams.sequenceNumber = 1;
  feed_chunk(*handle.impl, forge->build_symmetric_msg(goodParams));

  ASSERT_TRUE(goodSync->wait(2s)) << "the intact chunk should be delivered";
  EXPECT_TRUE(goodSync->status.is_good());
  EXPECT_FALSE(errorSync->fired) << "an intact chunk must not fire the channel-error observer";
  EXPECT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Open);

  // Negative phase: the same headers, but the crypto-protected tail is corrupted so symmetric verify
  // fails. This must close the channel and fire the post-open observer.
  auto badSync = std::make_shared<ServiceResponseSync>();
  handle.impl->send_request(
    std::make_shared<ua::ReadRequest>(), [badSync](auto result) { badSync->set(std::move(result)); });
  auto badRequestId = single_pending_request_id(*handle.impl);
  ASSERT_NE(badRequestId, 0u);

  ua::test_helpers::ServerChunkForge::SymMsgParams badParams;
  badParams.secureChannelId = channelId;
  badParams.tokenId = tokenId;
  badParams.requestId = badRequestId;
  badParams.sequenceNumber = 2;
  auto badChunk = forge->build_symmetric_msg(badParams);
  ASSERT_FALSE(badChunk.empty());
  // Flip the last byte - well past the plaintext message + symmetric-security header, inside the
  // encrypted body/signature - so decode_message_chunk_async's symmetric verify fails.
  badChunk.back() = static_cast<byte>(static_cast<uint8_t>(badChunk.back()) ^ 0xFFu);
  feed_chunk(*handle.impl, std::move(badChunk));

  // Load-bearing CL-UASC-021 oracle: the persistent post-open observer (the reconnect trigger) fires
  // exactly once with a bad status.
  ASSERT_TRUE(errorSync->wait(2s))
    << "a post-open verification failure must fire the persistent mOnChannelError observer";
  EXPECT_TRUE(errorSync->status.is_bad()) << "the channel-error observer must report a bad status";

  // Secondary: the channel closes and the pending request fails.
  ASSERT_TRUE(badSync->wait(2s)) << "the pending request must fail when the channel is torn down";
  EXPECT_TRUE(badSync->status.is_bad());
  EXPECT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);

  forge.reset();
  handle.impl.reset();
  handle.connection.reset();
  seed.impl.reset();
  seed.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-SECADMIN-006: rotating the client's ApplicationInstanceCertificate/key in the certificate store
// takes effect without an SDK restart. start_open re-consults the store on every new channel open
// (ua_client_secure_channel_impl.cpp:316), so a certificate rotated between two opens is picked up on
// the second open. Two SecureChannelImpls are built on the SAME store: the first opens with key A, the
// store is then rotated to key B, and the second impl opens - its OPN must be signed with key B.
//
// Load-bearing oracle: OPN #1 verifies against key A's public key and NOT B; OPN #2 verifies against
// key B's public key and NOT A. If the SDK cached the private key from the first open / at injection
// (the rotation-immutability bug this requirement guards against), OPN #2 would still be signed with
// key A - verifying under A and failing under B, tripping the assertion.
//
// SCOPE: the two sibling sub-obligations are NOT client-testable and belong elsewhere:
// (b) self-signed-cert-signature-matches-embedded-public-key is a Crypto/X509 property (SHARED_LAYER);
// (c) the enforced 0600 private-key file mode belongs to the file-backed CertificateStore backend
// (SHARED_LAYER) and is covered by the focused lifecycle integration matrix, not this client unit.
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-006 [PARTIAL] - covers obligation (a): the client re-loads its own cert+key
// from the store on every channel open, so key rotation via store swap works WITHOUT an SDK restart
// (OPN #2 is signed with the rotated key, not a cached one). Obligations (b) self-signed-cert signature
// matches the embedded public key and (c) 0600 private-key file-mode are NOT covered here (shared
// crypto/X509 + file-backend layers) and are covered by focused lifecycle integration rows.
// @relation(CL-SECADMIN-006, scope=function)
TEST(ClientSecureChannelCryptoTests, ClientKeyRotationDoesNotRequireSdkRestart)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Reuse a WiredSecureChannelSetup only for its crypto + server material + initial client key/cert A.
  auto seed = WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(seed.transport->wait_for_write_count(2, 3s));

  auto crypto = seed.crypto;
  const auto certType = CertificateType::RsaSha256Application;

  // Key/cert A (the initially-installed own certificate).
  auto clientKeysA = seed.clientKeys;
  auto clientCertA = seed.clientCert;

  // Key/cert B (the rotated-in own certificate) - a fresh self-signed RSA cert via the same crypto.
  TestPki pki{crypto};
  auto clientKeysB = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCertB = pki.create_root_ca(clientKeysB, "TestClientB", "202");

  // A rotatable store starting with cert A, shared across both channel opens (models one live SDK).
  CertificateStore::ApplicationCertificate appA;
  appA.certificateType = certType;
  appA.certificate = clientCertA;
  appA.keys = clientKeysA;
  auto store = std::make_shared<RotatableCertificateStore>(appA, seed.serverCert);
  auto deps = std::make_shared<CryptoSecureChannelDeps>(ex, crypto, store);

  // Open #1: the store currently holds key A; OPN #1 must be signed with key A.
  auto handle1 = build_impl_on_store(
    ex, deps, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, seed.serverCert);
  ASSERT_TRUE(handle1.transport->wait_for_write_count(2, 3s)) << "OPN #1 must be sent";
  auto opnChunk1 = handle1.transport->writes()[1];

  // Rotate the store to key/cert B (administrator swap, no SDK restart).
  CertificateStore::ApplicationCertificate appB;
  appB.certificateType = certType;
  appB.certificate = clientCertB;
  appB.keys = clientKeysB;
  store->rotate_application_certificate(appB);

  // Open #2: a NEW impl on the SAME store now holding key B; OPN #2 must be signed with key B.
  auto handle2 = build_impl_on_store(
    ex, deps, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, seed.serverCert);
  ASSERT_TRUE(handle2.transport->wait_for_write_count(2, 3s)) << "OPN #2 must be sent";
  auto opnChunk2 = handle2.transport->writes()[1];

  // OPN #1 is signed with key A (not B).
  EXPECT_TRUE(opn_signature_verifies_with(
    ex, crypto, seed.serverCert, seed.serverKeys, *clientCertA, span<const byte>{opnChunk1}, *clientCertA))
    << "OPN #1 must be signed with the initially-installed key A";
  EXPECT_FALSE(opn_signature_verifies_with(
    ex, crypto, seed.serverCert, seed.serverKeys, *clientCertA, span<const byte>{opnChunk1}, *clientCertB))
    << "OPN #1 must not verify under the rotated-in key B";

  // Load-bearing: OPN #2 is signed with the rotated key B (not the cached key A).
  EXPECT_TRUE(opn_signature_verifies_with(
    ex, crypto, seed.serverCert, seed.serverKeys, *clientCertB, span<const byte>{opnChunk2}, *clientCertB))
    << "OPN #2 must be signed with the rotated key B (store re-consulted, no SDK restart)";
  EXPECT_FALSE(opn_signature_verifies_with(
    ex, crypto, seed.serverCert, seed.serverKeys, *clientCertB, span<const byte>{opnChunk2}, *clientCertA))
    << "OPN #2 must not still be signed with the cached key A (the rotation-immutability bug)";

  handle1.impl.reset();
  handle1.connection.reset();
  handle2.impl.reset();
  handle2.connection.reset();
  seed.impl.reset();
  seed.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-TCP-014: an error the SecureChannel detects itself (here a MSG chunk naming another SecureChannelId,
// rejected by the decode before any crypto runs) closes an open channel with a CloseSecureChannel. If the
// CloseSecureChannel encode never completes - a crypto provider that never answers the symmetric sign -
// the protocol's fallback timer (the create() argument fatalCloseTimeout) still closes the
// transport. The chunk arrives through the transport, the path a real server's bytes take.
// ---------------------------------------------------------------------------

namespace
{

/// A symmetric MSG chunk for @p secureChannelId, split into the 8-byte header and the remainder, the two
/// reads the client ConnectionProtocol makes. The body after the SecureChannelId is filler: the decode
/// rejects a chunk for another channel before it reads further.
std::pair<std::vector<byte>, std::vector<byte>> msg_chunk_for_channel(uint32_t secureChannelId)
{
  constexpr uint32_t chunkSize = 32;
  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'M'});
  enc.encode(limit, uint8_t{'S'});
  enc.encode(limit, uint8_t{'G'});
  enc.encode(limit, uint8_t{'F'});
  enc.encode(limit, chunkSize);
  enc.encode(limit, secureChannelId);
  enc.encode(limit, uint32_t{1});  // TokenId
  enc.encode(limit, uint32_t{1});  // SequenceNumber
  enc.encode(limit, uint32_t{1});  // RequestId
  enc.encode(limit, uint32_t{0});  // filler
  enc.encode(limit, uint32_t{0});  // filler

  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  std::vector<byte> header(out.begin(), out.begin() + ua::connection_protocol::headerSize);
  std::vector<byte> body(out.begin() + ua::connection_protocol::headerSize, out.end());
  return {std::move(header), std::move(body)};
}

// Short enough that a small multiple of it is well under the 3 s default, so the configured timer (not
// some other path) is what closes the transport; long enough for an answering provider to sign the
// CloseSecureChannel first.
constexpr auto channelDetectedFatalCloseTimeout = 400ms;
constexpr auto channelDetectedCloseBound = channelDetectedFatalCloseTimeout * 5;

struct ChannelDetectedErrorOutcome
{
  bool closedWithinBound{false};
  std::size_t parkedSigns{0};
  std::optional<std::size_t> writesAtFirstClose;
  std::vector<std::vector<byte>> writes;
  SecureChannelImpl::ChannelState state{SecureChannelImpl::ChannelState::Open};
};

/// Opens a Sign-mode Basic256Sha256 channel on a FakeAsyncCrypto, then delivers a chunk for another
/// SecureChannelId through the transport. The one variable: @p hangTheCloseEncode parks every crypto
/// operation after the open, so the CloseSecureChannel's symmetric sign never completes.
ChannelDetectedErrorOutcome run_channel_detected_error(boost::asio::thread_pool& tp, bool hangTheCloseEncode)
{
  ChannelDetectedErrorOutcome outcome;
  auto ex = tp.get_executor();

  // Material provider (keys, certificates, certificate store). Its own channel is unused.
  auto seed = WiredSecureChannelSetup::create(ex, MessageSecurityMode::Sign);
  EXPECT_TRUE(seed.transport->wait_for_write_count(2, 3s));

  // Channel under test: the same store, a crypto provider that can be made to stop answering.
  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  auto deps = std::make_shared<CryptoSecureChannelDeps>(ex, crypto, seed.certStore);
  auto handle = build_impl_on_store(ex,
    deps,
    MessageSecurityMode::Sign,
    SecurityPolicyId::Basic256Sha256,
    seed.serverCert,
    {},
    channelDetectedFatalCloseTimeout);
  EXPECT_TRUE(handle.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const uint32_t channelId = 88;
  STA::on_strand(*handle.impl,
    [&](auto& g)
    {
      g.handle_opn_response(
        StatusCode{Status::Good}, channelId, 4242, 600000ms, make_nonce(*seed.crypto, 32), nullptr);
    });
  EXPECT_TRUE(handle.scSync->wait_opened(2s));
  EXPECT_TRUE(handle.scSync->openedStatus.is_good());

  if (hangTheCloseEncode)
  {
    crypto->set_park_async(true);
  }

  // STIMULUS: a chunk for another SecureChannelId, which the channel itself rejects.
  auto [header, body] = msg_chunk_for_channel(channelId + 1);
  handle.transport->enqueue_read_exact(std::move(header));
  handle.transport->enqueue_read_exact(std::move(body));

  outcome.closedWithinBound = handle.transport->wait_for_close(channelDetectedCloseBound);
  outcome.parkedSigns = crypto->pending_symmetric_sign_count();
  outcome.writesAtFirstClose = handle.transport->writes_at_first_close();
  outcome.writes = handle.transport->writes();
  outcome.state = STA::on_strand(*handle.impl, [](auto& g) { return g.channel_state(); });

  // Release any parked sign so the encode unwinds before teardown.
  crypto->set_park_async(false);
  while (crypto->pending_symmetric_sign_count() > 0)
  {
    crypto->complete_pending_symmetric_sign(0, ByteStringResult{StatusCode{Status::BadInternalError}});
  }

  handle.impl.reset();
  handle.connection.reset();
  seed.impl.reset();
  seed.connection.reset();
  return outcome;
}

}  // namespace

// A close that wins the race against an open's key derivation. release_security_state runs as its own strand
// turn and drops the context, and the derivation answers after it: the channel takes that answer as moot
// instead of opening a context it no longer holds. Falsifiable: on_security_token_created_for_open
// dereferenced the released context, a null dereference that ends the process.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-IN-FLIGHT-AT-CLOSE, scope=function)
TEST(ClientSecureChannelCryptoTests, KeysDerivedAfterACloseReleasedTheChannelAreDropped)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto seed = WiredSecureChannelSetup::create(ex, MessageSecurityMode::Sign);
  ASSERT_TRUE(seed.transport->wait_for_write_count(2, 3s));

  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  auto deps = std::make_shared<CryptoSecureChannelDeps>(ex, crypto, seed.certStore);
  auto handle = build_impl_on_store(ex,
    deps,
    MessageSecurityMode::Sign,
    SecurityPolicyId::Basic256Sha256,
    seed.serverCert,
    {},
    channelDetectedFatalCloseTimeout);
  ASSERT_TRUE(handle.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  const auto waitForDerive = [&]
  {
    const auto deadline = std::chrono::steady_clock::now() + test_utils::scaled(2000ms);
    while (crypto->pending_derive_symmetric_keys_count() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    return crypto->pending_derive_symmetric_keys_count() == 1;
  };

  // The open's response arrives and its key derivation is held.
  crypto->set_park_async(true);
  STA::on_strand(*handle.impl,
    [&](auto& g)
    {
      g.handle_opn_response(
        StatusCode{Status::Good}, 88, 4242, 600000ms, make_nonce(*seed.crypto, 32), nullptr);
    });
  ASSERT_TRUE(waitForDerive()) << "the open's key derivation was never requested";

  // The transport fails; the close releases the security state in a turn of its own.
  STA::on_strand(*handle.impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });
  STA::strand_barrier(*handle.impl);
  ASSERT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.context(); }), nullptr)
    << "the close did not release the security state";

  // The derivation answers now, successfully: both directions' key material.
  const auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const size_t keyMaterial = policy->symmetric_signature_key_size() +
                             policy->symmetric_encryption_key_size() + policy->symmetric_iv_size();
  crypto->complete_pending_derive_symmetric_keys(0, ByteStringResult{ByteString(keyMaterial, uint8_t{0x21})});
  ASSERT_TRUE(waitForDerive()) << "the second derivation was never requested";
  crypto->complete_pending_derive_symmetric_keys(0, ByteStringResult{ByteString(keyMaterial, uint8_t{0x22})});
  crypto->set_park_async(false);
  STA::strand_barrier(*handle.impl);
  STA::strand_barrier(*handle.impl);

  EXPECT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);

  handle.impl.reset();
  handle.connection.reset();
  seed.impl.reset();
  seed.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The same race at the start of an ECC open: the close releases the security state while the ephemeral key
// pair for the nonce is generated, and the key pair arrives after it. The channel drops it instead of storing
// its private key in a context it no longer holds. Falsifiable: the key-pair callback dereferenced the
// released context.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-IN-FLIGHT-AT-CLOSE, scope=function)
TEST(ClientSecureChannelCryptoTests, AnEphemeralKeyPairGeneratedAfterACloseReleasedTheChannelIsDropped)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto seed = WiredSecureChannelSetup::create(ex,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::EccNistP256AesGcm,
    {},
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256,
    CertificateType::EccNistP256Application);
  ASSERT_TRUE(seed.transport->wait_for_write_count(2, 3s));

  // Every crypto operation of the channel under test is held from the start: the open's key pair first.
  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  crypto->set_park_async(true);
  auto deps = std::make_shared<CryptoSecureChannelDeps>(ex, crypto, seed.certStore);
  auto handle = build_impl_on_store(ex,
    deps,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::EccNistP256AesGcm,
    seed.serverCert,
    {},
    channelDetectedFatalCloseTimeout);
  const auto deadline = std::chrono::steady_clock::now() + test_utils::scaled(2000ms);
  while (crypto->pending_create_ephemeral_keys_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(crypto->pending_create_ephemeral_keys_count(), 1u) << "the open never asked for its key pair";

  STA::on_strand(*handle.impl,
    [](auto& g) { g.receive_transport_error(StatusCode{Status::BadConnectionClosed}, std::string_view{}); });
  STA::strand_barrier(*handle.impl);
  ASSERT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.context(); }), nullptr)
    << "the close did not release the security state";

  crypto->set_park_async(false);
  crypto->complete_pending_create_ephemeral_keys(0,
    Crypto::EphemeralKeyPairResult{
      seed.crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256)});
  STA::strand_barrier(*handle.impl);
  STA::strand_barrier(*handle.impl);

  EXPECT_EQ(STA::on_strand(*handle.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);
  EXPECT_EQ(handle.transport->writes().size(), 1u) << "no OpenSecureChannel follows the Hello";

  handle.impl.reset();
  handle.connection.reset();
  seed.impl.reset();
  seed.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Negative arm: the CloseSecureChannel encode hangs, and the fallback timer closes the transport anyway.
// Falsifiable: without SecureChannelImpl::close_with_close_secure_channel's
// begin_close_after_channel_error no timer is armed, and the transport stays open and reading for as long
// as the sign is parked.
// @verifies AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED
// @relation(AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED, scope=function)
TEST(ClientSecureChannelCryptoTests, AChannelDetectedErrorWithAHungCloseEncodeIsBoundedByTheFallbackTimer)
{
  boost::asio::thread_pool tp;
  auto outcome = run_channel_detected_error(tp, /*hangTheCloseEncode*/ true);

  EXPECT_TRUE(outcome.closedWithinBound)
    << "the fallback timer must close the transport while the CloseSecureChannel encode is hung";
  EXPECT_EQ(outcome.parkedSigns, 1u)
    << "the CloseSecureChannel's sign was still parked when the transport closed";
  EXPECT_EQ(outcome.writesAtFirstClose, std::optional<std::size_t>{2u})
    << "nothing follows the OPN: the hung CloseSecureChannel was never written";
  EXPECT_EQ(outcome.state, SecureChannelImpl::ChannelState::Closed);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Control arm: the same channel and stimulus with a provider that answers. The CloseSecureChannel is
// signed and written, and the transport closes after it - the timer bounds the hung case only.
// @verifies AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED
// @relation(AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED, scope=function)
TEST(ClientSecureChannelCryptoTests, AChannelDetectedErrorWithAnAnsweringProviderWritesTheCloseFirst)
{
  boost::asio::thread_pool tp;
  auto outcome = run_channel_detected_error(tp, /*hangTheCloseEncode*/ false);

  EXPECT_TRUE(outcome.closedWithinBound);
  EXPECT_EQ(outcome.parkedSigns, 0u);
  EXPECT_EQ(outcome.writesAtFirstClose, std::optional<std::size_t>{3u})
    << "the CloseSecureChannel is written before the transport closes";
  ASSERT_EQ(outcome.writes.size(), 3u);
  EXPECT_EQ(parse_symmetric_chunk_header(span<const byte>{outcome.writes[2]}).header.messageType,
    UaScMessageHeader::MessageType::Close);
  EXPECT_EQ(outcome.state, SecureChannelImpl::ChannelState::Closed);

  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Completeness review C2 (decision 24): the client OPN carries the own issuer chain after the leaf
// (AsymmetricSecurityHeader SenderCertificate, OPC 10000-6 6.7.2.3 / 6.2.6), and an own chain too large for
// one chunk closes the channel with an error instead of sending a truncated or oversized header.
// ---------------------------------------------------------------------------

namespace
{

std::vector<std::shared_ptr<const X509Certificate>> make_own_issuers(
  const std::shared_ptr<const Crypto>& crypto)
{
  TestPki pki{crypto};
  return {pki.create_root_ca(
            ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 80), "Own IA", "8001"),
    pki.create_root_ca(
      ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 81), "Own Root", "8002")};
}

}  // namespace

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-81-SEND-OWN-CHAIN, scope=function)
TEST(ClientSecureChannelCryptoTests, OpnSenderCertificateIsTheLeafThenTheOwnIssuers)
{
  boost::asio::thread_pool tp;
  const auto issuers = make_own_issuers(create_crypto());
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(),
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    [&issuers](TestCertificateStore& store) { store.set_own_issuer_certificates(issuers); });
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 3s));
  const auto writes = setup.transport->writes();
  const auto parsed = parse_opn_chunk(span<const byte>{writes[1]}, *setup.crypto);
  ASSERT_NE(parsed.securityHeader.senderCertificate, nullptr);
  EXPECT_EQ(parsed.securityHeader.senderCertificate->thumbprint(), setup.clientCert->thumbprint());
  ASSERT_EQ(parsed.securityHeader.issuerCertificates.size(), 2u);
  EXPECT_EQ(parsed.securityHeader.issuerCertificates[0]->thumbprint(), issuers[0]->thumbprint());
  EXPECT_EQ(parsed.securityHeader.issuerCertificates[1]->thumbprint(), issuers[1]->thumbprint());
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The own chain repeated until it exceeds the 65536-byte chunk the server's ACK allows: Part 6 6.7.2.3
// requires the SenderCertificate with its chain to fit one chunk. SDK decision (the specification names no
// code): the open fails with Bad_EncodingLimitsExceeded and nothing oversized is written.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-83-OWN-CHAIN-TOO-LARGE, scope=function)
TEST(ClientSecureChannelCryptoTests, AnOwnChainLargerThanAChunkClosesTheChannelWithAnError)
{
  boost::asio::thread_pool tp;
  const auto issuers = make_own_issuers(create_crypto());
  std::vector<std::shared_ptr<const X509Certificate>> oversized;
  for (int i = 0; i < 100; ++i)
  {
    oversized.push_back(issuers[0]);
  }
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(),
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    [&oversized](TestCertificateStore& store) { store.set_own_issuer_certificates(oversized); });
  // A failed open is reported through the open callback, as for every other open refusal.
  ASSERT_TRUE(setup.scSync->wait_opened(3s)) << "the open must fail, not hang";
  EXPECT_EQ(setup.scSync->openedStatus, StatusCode{Status::BadEncodingLimitsExceeded});
  for (const auto& write : setup.transport->writes())
  {
    EXPECT_LE(write.size(), 65536u) << "no chunk larger than the negotiated buffer is written";
  }
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Found by the integration matrix (2026-10-02): the client fixes the server certificate from GetEndpoints
// before it opens, so the OPN response's sender certificate is ALREADY known when it is decoded. The
// issuer chain the server presented after that certificate (OPC 10000-6 6.2.6, 6.7.2.3) must still reach
// the validation as the presented issuers; it was dropped, and a server whose intermediate the client
// does not hold was refused as Bad_CertificateChainIncomplete. For ECC the known certificate must also be
// the one that signed the response (Part 6 6.7.4), as on the RSA path.
// ---------------------------------------------------------------------------

namespace
{

struct ForgedOpnResponseOutcome
{
  std::size_t validateCalls{0};
  optional<CertificateValidationRequest> request;
  bool opened{false};
  StatusCode openStatus;
};

// Two CA certificates standing in for the chain a server presents after its leaf. Only their identity in
// the validation request is observed; the scripted store does not build the chain.
std::vector<std::shared_ptr<const X509Certificate>> make_presented_issuers(
  const std::shared_ptr<const Crypto>& crypto)
{
  TestPki pki{crypto};
  return {pki.create_root_ca(
            ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 82), "Server IA", "8201"),
    pki.create_root_ca(
      ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 83), "Server Root", "8202")};
}

// The client opens against setup.serverCert (its known peer). The forged OPN response is signed by
// `signerCert`/`signerKeys` (nullptr = the known server certificate) and presents `issuers` after it.
ForgedOpnResponseOutcome feed_forged_opn_response(boost::asio::thread_pool& tp, SecurityPolicyId policyId,
  const std::vector<std::shared_ptr<const X509Certificate>>& issuers,
  std::shared_ptr<const X509Certificate> signerCert = nullptr,
  std::shared_ptr<const AsymmetricKeyPair> signerKeys = nullptr)
{
  auto ex = tp.get_executor();
  const bool ecc = policyId == SecurityPolicyId::EccNistP256AesGcm;
  auto setup = ecc ? WiredSecureChannelSetup::create(ex,
                       MessageSecurityMode::SignAndEncrypt,
                       policyId,
                       {},
                       CertificateKeyAlgorithm::EccNistP256,
                       CertificateSignatureAlgorithm::EcDsaSha2256,
                       CertificateType::EccNistP256Application)
                   : WiredSecureChannelSetup::create(ex, MessageSecurityMode::SignAndEncrypt, policyId);
  EXPECT_TRUE(setup.transport->wait_for_write_count(2, 3s)) << "Expected HEL + OPN on the transport";

  std::optional<ua::test_helpers::ServerChunkForge> forge;
  forge.emplace(ex,
    setup.crypto,
    signerCert ? signerCert : setup.serverCert,
    signerKeys ? signerKeys : setup.serverKeys,
    setup.clientCert,
    MessageSecurityMode::SignAndEncrypt,
    policyId);
  forge->set_local_issuer_certificates(issuers);
  // The server's first response covers the Signature of the client's request (writes: HEL, OPN).
  forge->record_open_secure_channel_request(span<const byte>{setup.transport->writes().at(1)});

  ua::test_helpers::ServerChunkForge::OpnRespParams params;
  params.secureChannelId = 61;
  params.tokenId = 62;
  params.requestId = 1;
  params.sequenceNumber = 1;
  params.serverNonce =
    ecc ? ByteString{setup.crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256).publicKey}
        : make_nonce(*setup.crypto, 32);
  params.revisedLifetimeMs = 600000;

  feed_chunk(*setup.impl, forge->build_opn_response(params));

  ForgedOpnResponseOutcome outcome;
  outcome.opened = setup.scSync->wait_opened(3s);
  outcome.openStatus = setup.scSync->openedStatus;
  outcome.validateCalls = setup.certStore->validate_call_count();
  outcome.request = setup.certStore->last_request();

  forge.reset();
  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return outcome;
}

void expect_presented_issuers(
  const ForgedOpnResponseOutcome& outcome, const std::vector<std::shared_ptr<const X509Certificate>>& issuers)
{
  ASSERT_GE(outcome.validateCalls, 1u) << "the server certificate was never validated";
  ASSERT_TRUE(outcome.request.has_value());
  ASSERT_EQ(outcome.request->presentedIssuers.size(), issuers.size())
    << "the issuer chain of the OPN response must reach the validation as the presented issuers";
  for (std::size_t i = 0; i < issuers.size(); ++i)
  {
    EXPECT_EQ(outcome.request->presentedIssuers[i]->thumbprint(), issuers[i]->thumbprint()) << "issuer " << i;
  }
}

}  // namespace

// Negative arm: the known server certificate signs an OPN response that presents its issuer chain. Before
// the fix the chain was dropped because the certificate was already known, and the validation saw none.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-139-KNOWN-PEER-KEEPS-PRESENTED-CHAIN, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, TheChainOfAnOpnResponseFromTheKnownServerIsValidated)
{
  boost::asio::thread_pool tp;
  const auto issuers = make_presented_issuers(create_crypto());
  const auto outcome = feed_forged_opn_response(tp, SecurityPolicyId::Basic256Sha256, issuers);
  expect_presented_issuers(outcome, issuers);
  EXPECT_TRUE(outcome.opened);
  EXPECT_EQ(outcome.openStatus, StatusCode{Status::Good});
}

// Control arm: the same response without a chain. Differs in the presented chain alone, and the
// validation then sees no presented issuers - the issuers above came from the OPN response's header.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-139-KNOWN-PEER-KEEPS-PRESENTED-CHAIN, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, AnOpnResponseWithoutAChainPresentsNoIssuers)
{
  boost::asio::thread_pool tp;
  const auto outcome = feed_forged_opn_response(tp, SecurityPolicyId::Basic256Sha256, {});
  ASSERT_GE(outcome.validateCalls, 1u);
  ASSERT_TRUE(outcome.request.has_value());
  EXPECT_TRUE(outcome.request->presentedIssuers.empty());
  EXPECT_EQ(outcome.openStatus, StatusCode{Status::Good});
}

// ECC: the same obligation on the ECC decode path, which carries its own copy of the adoption logic.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-139-KNOWN-PEER-KEEPS-PRESENTED-CHAIN, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-140-ECC-KNOWN-PEER-SIGNS-THE-RESPONSE, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, TheChainOfAnEccOpnResponseFromTheKnownServerIsValidated)
{
  boost::asio::thread_pool tp;
  const auto issuers = make_presented_issuers(create_crypto());
  const auto outcome = feed_forged_opn_response(tp, SecurityPolicyId::EccNistP256AesGcm, issuers);
  expect_presented_issuers(outcome, issuers);
  EXPECT_NE(outcome.openStatus, StatusCode{Status::BadCertificateInvalid})
    << "the known server certificate signed the response";
}

// Negative arm (Part 6 6.7.4): the client fixed certificate A from GetEndpoints; the ECC OPN response is
// signed by certificate B. Before the fix the ECC path adopted B because the channel was still
// Uninitialised. Control: TheChainOfAnEccOpnResponseFromTheKnownServerIsValidated, signed by A.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-140-ECC-KNOWN-PEER-SIGNS-THE-RESPONSE, scope=function)
TEST(ClientSecureChannelInboundOpnDecodeTests, AnEccOpnResponseSignedByAnotherCertificateIsInvalid)
{
  boost::asio::thread_pool tp;
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto otherKeys =
    crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = otherKeys;
  certParams.issuerKeys = otherKeys;
  certParams.subject.commonName = "ImposterServer";
  certParams.serialNumber = "8203";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto otherCert = pki.create_cert(certParams);

  const auto outcome =
    feed_forged_opn_response(tp, SecurityPolicyId::EccNistP256AesGcm, {}, otherCert, otherKeys);
  ASSERT_TRUE(outcome.opened) << "the open must complete, refused";
  EXPECT_EQ(outcome.openStatus, StatusCode{Status::BadCertificateInvalid});
  EXPECT_EQ(outcome.validateCalls, 0u)
    << "a response signed by another certificate is refused before validation";
}

// ---------------------------------------------------------------------------
// An Uncertain answer from the application's CertificateStore or Crypto provider is not acted on: the
// channel refuses it with Bad_InternalError and an ErrorDetail coded CertificateStoreAnswerUncertain or
// CryptoAnswerUncertain, whose inner status is the Uncertain code.
// ---------------------------------------------------------------------------

namespace
{

/// A channel under test whose crypto provider is a FakeAsyncCrypto, parked when @p park is set so the test
/// answers the provider itself. Certificates and keys come from a seed setup on real crypto; the seed's own
/// channel is not used. The channel error observer is wired.
struct ProviderAnsweredChannel
{
  WiredSecureChannelSetup seed;
  std::shared_ptr<FakeAsyncCrypto> crypto;
  /// The channel holds its dependencies weakly; this keeps them alive for the test.
  std::shared_ptr<CryptoSecureChannelDeps> deps;
  ImplOnStore handle;
  std::shared_ptr<ChannelErrorSync> channelError;

  void release()
  {
    handle.impl.reset();
    handle.connection.reset();
    deps.reset();
    seed.impl.reset();
    seed.connection.reset();
  }
};

ProviderAnsweredChannel channel_on_fake_crypto(boost::asio::any_io_executor ex, bool park,
  SecurityPolicyId policyId = SecurityPolicyId::Basic256Sha256,
  CertificateKeyAlgorithm keyAlg = CertificateKeyAlgorithm::Rsa,
  CertificateSignatureAlgorithm sigAlg = CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
  CertificateType certType = CertificateType::RsaSha256Application,
  const std::function<void(FakeAsyncCrypto&)>& configure = {})
{
  ProviderAnsweredChannel out;
  out.seed = WiredSecureChannelSetup::create(
    ex, MessageSecurityMode::SignAndEncrypt, policyId, {}, keyAlg, sigAlg, certType);
  out.crypto = FakeAsyncCrypto::create();
  out.crypto->set_park_async(park);
  if (configure)
  {
    configure(*out.crypto);
  }

  CertificateStore::ApplicationCertificate own;
  own.certificateType = certType;
  own.certificate = out.seed.clientCert;
  own.keys = out.seed.clientKeys;
  auto store = std::make_shared<TestCertificateStore>(std::move(own), out.seed.serverCert);
  out.deps = std::make_shared<CryptoSecureChannelDeps>(ex, out.crypto, std::move(store));

  out.channelError = std::make_shared<ChannelErrorSync>();
  out.handle = build_impl_on_store(ex,
    out.deps,
    MessageSecurityMode::SignAndEncrypt,
    policyId,
    out.seed.serverCert,
    [channelError = out.channelError](SecureChannelImpl::Config& config)
    {
      config.onChannelError = [channelError](VoidResult result)
      {
        channelError->fire(result.status_code());
      };
    });
  return out;
}

/// Polls @p count until it reaches @p expected or 5 s pass.
bool wait_for_count(const std::function<std::size_t()>& count, std::size_t expected)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (count() < expected && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(5ms);
  }
  return count() >= expected;
}

/// Checks the refusal shape: Bad_InternalError, @p code, the Uncertain code as the inner status.
void expect_refusal(const StatusCode& status, std::string_view code, const StatusCode& uncertain)
{
  EXPECT_EQ(status.as_status(), Status::BadInternalError);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, code);
  EXPECT_EQ(status.shared_detail()->innerStatus, uncertain.value());
}

}  // namespace

// The own certificate answered Uncertain: the open fails with the CertificateStoreAnswerUncertain refusal
// and no OpenSecureChannel request is sent.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSecureChannelCryptoTests, AnUncertainOwnCertificateAnswerIsRefusedBeforeTheOpn)
{
  boost::asio::thread_pool tp;
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  auto setup = WiredSecureChannelSetup::create(tp.get_executor(),
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    [uncertain](TestCertificateStore& store) { store.set_own_certificate_status(uncertain); });

  ASSERT_TRUE(setup.scSync->wait_opened(2s)) << "the open must complete, refused";
  expect_refusal(setup.scSync->openedStatus, "CertificateStoreAnswerUncertain", uncertain);
  STA::strand_barrier(*setup.impl);
  EXPECT_LT(setup.transport->writes().size(), 2u) << "only the Hello is written";

  setup.impl.reset();
  setup.connection.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The RSA nonce answered Uncertain, holding entropy: the open fails with the CryptoAnswerUncertain refusal
// and no OpenSecureChannel request is sent.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSecureChannelCryptoTests, AnUncertainOpenNonceIsRefusedBeforeTheOpn)
{
  boost::asio::thread_pool tp;
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  auto channel = channel_on_fake_crypto(tp.get_executor(),
    /*park=*/false,
    SecurityPolicyId::Basic256Sha256,
    CertificateKeyAlgorithm::Rsa,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateType::RsaSha256Application,
    [uncertain](FakeAsyncCrypto& crypto) { crypto.set_entropy_answer(uncertain, /*holdingBytes=*/true); });

  ASSERT_TRUE(channel.handle.scSync->wait_opened(5s)) << "the open must complete, refused";
  expect_refusal(channel.handle.scSync->openedStatus, "CryptoAnswerUncertain", uncertain);
  STA::strand_barrier(*channel.handle.impl);
  EXPECT_LT(channel.handle.transport->writes().size(), 2u) << "only the Hello is written";

  channel.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ECC ephemeral key answered Uncertain without a key: the open fails with the CryptoAnswerUncertain
// refusal and no OpenSecureChannel request is sent.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSecureChannelCryptoTests, AnUncertainEccEphemeralKeyIsRefusedBeforeTheOpn)
{
  boost::asio::thread_pool tp;
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  auto channel = channel_on_fake_crypto(tp.get_executor(),
    /*park=*/false,
    SecurityPolicyId::EccNistP256AesGcm,
    CertificateKeyAlgorithm::EccNistP256,
    CertificateSignatureAlgorithm::EcDsaSha2256,
    CertificateType::EccNistP256Application,
    [uncertain](FakeAsyncCrypto& crypto) { crypto.set_ephemeral_keys_answer(uncertain); });

  ASSERT_TRUE(channel.handle.scSync->wait_opened(2s)) << "the open must complete, refused";
  expect_refusal(channel.handle.scSync->openedStatus, "CryptoAnswerUncertain", uncertain);
  STA::strand_barrier(*channel.handle.impl);
  EXPECT_LT(channel.handle.transport->writes().size(), 2u) << "only the Hello is written";

  channel.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The renewal nonce answered Uncertain: the channel closes with the CryptoAnswerUncertain refusal and the
// channel error observer, which starts a reconnect, receives it.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientSecureChannelCryptoTests, AnUncertainRenewalNonceClosesTheChannelAndReachesTheErrorObserver)
{
  boost::asio::thread_pool tp;
  auto channel = channel_on_fake_crypto(tp.get_executor(), /*park=*/false);
  ASSERT_TRUE(channel.handle.transport->wait_for_write_count(2, 3s)) << "the channel must send its OPN";
  auto serverNonce = make_nonce(*channel.seed.crypto, 32);
  STA::on_strand(*channel.handle.impl,
    [&](auto& g)
    { g.handle_opn_response(StatusCode{Status::Good}, 88u, 4242u, 600000ms, serverNonce, nullptr); });
  ASSERT_TRUE(channel.handle.scSync->wait_opened(2s));
  ASSERT_TRUE(channel.handle.scSync->openedStatus.is_good());

  channel.crypto->set_park_async(true);
  STA::on_strand(*channel.handle.impl, [](auto& g) { g.handle_token_renewal(); });
  ASSERT_TRUE(wait_for_count([&] { return channel.crypto->pending_get_entropy_count(); }, 1));
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  channel.crypto->complete_pending_get_entropy(0, ByteStringResult{uncertain});

  ASSERT_TRUE(channel.channelError->wait(2s)) << "the channel error observer must learn of the close";
  expect_refusal(channel.channelError->status, "CryptoAnswerUncertain", uncertain);
  EXPECT_EQ(STA::on_strand(*channel.handle.impl, [](auto& g) { return g.channel_state(); }),
    SecureChannelImpl::ChannelState::Closed);

  channel.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
