// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "run_async_sync.h"
#include <boost/asio/strand.hpp>

#include "ua_crypto.h"
#include "ua_security_policy.h"
#include "ua_secure_channel_context.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_null_stream.h"
#include "ua_structure_factory.h"

#include "fake_certificate_store.h"
#include "test_pki_helpers.h"
#include "ua_open_secure_channel_request.h"

#include <mutex>
#include <optional>
#include <vector>

using namespace ua;
using namespace ua::stack_utils;
using namespace std::chrono_literals;

namespace
{

static std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() -> ua::SecureString { return ua::SecureString{"password"}; });
}

static EncodingLimits test_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

static void expect_runtime_exception_status(const std::function<void()>& fn, Status expected)
{
  try
  {
    fn();
    FAIL() << "Expected UaException";
  }
  catch (const UaException& e)
  {
    EXPECT_EQ(e.status(), expected);
  }
}

static ByteString build_opn_chunk(uint32_t secureChannelId, std::string securityPolicyUri,
  shared_ptr<const X509Certificate> senderCert, std::vector<shared_ptr<const X509Certificate>> issuerCerts,
  ByteString receiverThumbprint, uint32_t sequenceNumber, uint32_t requestId, span<const byte> body)
{
  // Build chunk: UaScMessageHeader + AsymmetricSecurityHeader + SequenceHeader + body.
  AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = std::move(securityPolicyUri);
  sh.senderCertificate = std::move(senderCert);
  sh.issuerCertificates = std::move(issuerCerts);
  sh.receiverCertificateThumbprint = std::move(receiverThumbprint);

  size_t securityHeaderSize = 0;
  {
    NullStream ns;
    UaBinaryEncoder enc(CodecNamespaceContext{}, ns);
    sh.encode(test_limits(), enc);
    securityHeaderSize = enc.stream().get_position();
  }

  const uint32_t chunkSize = static_cast<uint32_t>(
    UaScMessageHeader::sizeInBytes + securityHeaderSize + SequenceHeader::sizeInBytes + body.size());

  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  auto limits = test_limits();

  UaScMessageHeader header;
  header.messageType = UaScMessageHeader::MessageType::Open;
  header.isFinal = UaScMessageHeader::IsFinal::Final;
  header.messageChunkSize = chunkSize;
  header.secureChannelId = secureChannelId;
  header.encode(limits, enc);

  sh.encode(limits, enc);

  SequenceHeader seq;
  seq.sequenceNumber = sequenceNumber;
  seq.requestId = requestId;
  seq.encode(limits, enc);

  enc.stream().write_all(body);

  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  return ByteString{span<const byte>{out}};
}

static shared_ptr<SecureChannelContext> make_authenticated_context_uninitialised(
  boost::asio::any_io_executor ex, boost::asio::strand<boost::asio::any_io_executor> strand,
  std::shared_ptr<const Crypto> crypto, shared_ptr<const X509Certificate> localCertificate)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = test_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = std::move(crypto);
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = std::move(localCertificate);
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;
  (void)ex;
  return ctx;
}

static shared_ptr<SecureChannelContext> make_authenticated_context_open_with_remote_cert(
  boost::asio::any_io_executor ex, boost::asio::strand<boost::asio::any_io_executor> strand,
  std::shared_ptr<const Crypto> crypto, uint32_t secureChannelId,
  shared_ptr<const X509Certificate> localCertificate, shared_ptr<const X509Certificate> remoteCertificate)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->encodingLimits = test_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = std::move(crypto);
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = std::move(localCertificate);
  ctx->remoteCertificate = std::move(remoteCertificate);
  ctx->secureChannelId = secureChannelId;
  ctx->lastRxSequenceNumber = std::nullopt;
  (void)ex;
  return ctx;
}

}  // namespace

// @relation(AC-SVR-UASC-032-POLICYCONTINUITY, SVR-UASC-061, scope=function)
TEST(UascAuthenticatedOpnTests, SecurityPolicyUriMismatchIsRejected)
{
  // Requirement: P6-67-0032 (verify supported SecurityPolicy)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Server", "10");

  auto ctx = make_authenticated_context_uninitialised(ex, strand, crypto, localCert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#None",
    /*senderCert*/ nullptr,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ {},
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadSecurityPolicyRejected);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-028, SVR-UASC-061, scope=function)
TEST(UascAuthenticatedOpnTests, MissingSenderCertificateIsRejected)
{
  // Requirement: P6-67-0028 (mode != None requires sender cert + receiver thumbprint)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Server", "11");

  auto ctx = make_authenticated_context_uninitialised(ex, strand, crypto, localCert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ nullptr,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadCertificateInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-028-BOTHPRESENT, scope=function)
TEST(UascAuthenticatedOpnTests, MissingReceiverThumbprintIsRejected)
{
  // Requirement: P6-67-0028 (mode != None requires sender cert + receiver thumbprint)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Server", "12");

  auto clientKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert = pki.create_root_ca(clientKeys, "Client", "120");

  auto ctx = make_authenticated_context_uninitialised(ex, strand, crypto, localCert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ clientCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ {},
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadCertificateInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-033-THUMBMATCH, SVR-UASC-061, scope=function)
TEST(UascAuthenticatedOpnTests, ReceiverThumbprintMismatchIsRejected)
{
  // Requirement: P6-67-0033 (thumbprint recognition)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Server", "13");

  auto clientKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert = pki.create_root_ca(clientKeys, "Client", "130");

  auto ctx = make_authenticated_context_uninitialised(ex, strand, crypto, localCert);

  ByteString wrongThumbprint = localCert->thumbprint();
  wrongThumbprint[0] = static_cast<uint8_t>(~wrongThumbprint[0]);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ clientCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ wrongThumbprint,
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadCertificateInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-023, SVR-UASC-031, SVR-UASC-061, scope=function)
TEST(UascAuthenticatedOpnTests, SenderCertificateChangeAcrossOpnIsRejected)
{
  // Requirements: P6-67-0023, P6-67-0031 (cert continuity)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Server", "14");

  auto clientKeys1 = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert1 = pki.create_root_ca(clientKeys1, "Client1", "140");
  auto clientKeys2 = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert2 = pki.create_root_ca(clientKeys2, "Client2", "141");

  auto ctx = make_authenticated_context_open_with_remote_cert(
    ex, strand, crypto, /*secureChannelId*/ 1, localCert, clientCert1);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 1,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ clientCert2,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadCertificateInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-SC-011
// Part 6 6.7.4 lines 3815-3817: "The Client shall abandon the SecureChannel if the Certificate used to sign
// the response is not the same as the Certificate used to encrypt the request." On the FIRST
// OpenSecureChannel the client has already fixed the server certificate (it encrypted its request to it), so
// a response signed by a DIFFERENT certificate must be rejected - the client must NOT silently adopt the
// response signer just because the channel is not yet Open. The context here is Uninitialised (first OPN) but
// carries the pre-configured server certificate (as the client sets it from GetEndpoints before opening).
// Falsifiable: a client that adopted the first-OPN sender certificate unconditionally (gating on channel
// state rather than on whether a certificate is already known) would not raise BadCertificateInvalid.
// @relation(CL-SC-011, scope=function)
TEST(UascAuthenticatedOpnTests, FirstOpnSenderCertMismatchWithConfiguredServerCertIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto localKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(localKeys, "Client", "15");  // the client's own (receiver) certificate

  auto configuredServerKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto configuredServerCert = pki.create_root_ca(configuredServerKeys, "ConfiguredServer", "150");  // cert A
  auto imposterServerKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto imposterServerCert = pki.create_root_ca(imposterServerKeys, "ImposterServer", "151");  // cert B != A

  // First-OPN client context: state Uninitialised, but the server certificate is ALREADY fixed (the client
  // encrypted its OPN request to configuredServerCert).
  auto ctx = make_authenticated_context_uninitialised(ex, strand, crypto, localCert);
  ctx->remoteCertificate = configuredServerCert;

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ imposterServerCert,  // response signed by a certificate that is NOT the configured one
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  expect_runtime_exception_status(
    [&]()
    {
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
        .value();
    },
    Status::BadCertificateInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------------------------------
// Server role: a renew is compared by its leaf (OPC 10000-6 6.7.4, owner decision 26).
//
// "The Server shall reject renew requests if the SenderCertificate is not the same as the one used to
// create the SecureChannel." The SenderCertificate is the leaf; the issuer chain that accompanies it
// (6.2.6) may differ from one OPN to the next. Each test runs the production encoder on a client-role
// context and the production decoder on a server-role context, so every OPN chunk is a real one,
// encrypted and signed by the client's private key: Issue with leaf A, then a Renew that differs in
// exactly one thing. The negative presents another leaf certified on the SAME key - its signature
// verifies, so only a comparison of the leaf itself can refuse it. The control presents leaf A with
// another issuer chain, which must be accepted and its chain adopted. Both run on the RSA decoder and on
// the ECC decoder, which carry separate copies of the check.
// ---------------------------------------------------------------------------------------------------

namespace
{

struct RenewLeafParams
{
  SecurityPolicyId policy;
  CertificateKeyAlgorithm keyAlgorithm;
  CertificateSignatureAlgorithm signatureAlgorithm;
  std::string_view name;
};

class ServerRoleRenewLeaf : public ::testing::TestWithParam<RenewLeafParams>
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPki.emplace(mCrypto);
    mServerKeys = make_keys();
    mServerCertificate = make_certificate(mServerKeys, mServerKeys, nullptr, "Server", "401", /*ca*/ false);
    mCaKeys = make_keys();
    mCa = make_certificate(mCaKeys, mCaKeys, nullptr, "Renew CA", "402", /*ca*/ true);
    // The same CA subject and key in another certificate: a second, equally valid chain for leaf A.
    mCaReissued = make_certificate(mCaKeys, mCaKeys, nullptr, "Renew CA", "403", /*ca*/ true);
    mClientKeys = make_keys();
    mLeafA = make_certificate(mClientKeys, mCaKeys, mCa, "Client", "410", /*ca*/ false);
    // Another leaf on the SAME key: a renew it signs verifies, so only a leaf comparison refuses it.
    mLeafB = make_certificate(mClientKeys, mCaKeys, mCa, "Client", "411", /*ca*/ false);
    mStore = test_helpers::FakeCertificateStore::create();

    mServerContext = make_context(ChannelRole::Server);
    mServerContext->localCertificate = mServerCertificate;
    mServerContext->localKeyPair = mServerKeys;
    mServerContext->certStore = mStore;

    mClientContext = make_context(ChannelRole::Client);
    mClientContext->localCertificate = mLeafA;
    mClientContext->localKeyPair = mClientKeys;
    mClientContext->localIssuerCertificates = {mCa};
    mClientContext->remoteCertificate = mServerCertificate;
  }

  void TearDown() override
  {
    mServerContext.reset();
    mClientContext.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  shared_ptr<const AsymmetricKeyPair> make_keys() const
  {
    if (GetParam().keyAlgorithm == CertificateKeyAlgorithm::Rsa)
    {
      return mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    }
    return mCrypto->create_asymmetric_key_pair_sync(GetParam().keyAlgorithm, std::nullopt);
  }

  shared_ptr<const X509Certificate> make_certificate(shared_ptr<const AsymmetricKeyPair> subjectKeys,
    shared_ptr<const AsymmetricKeyPair> issuerKeys, shared_ptr<const X509Certificate> issuer,
    const std::string& name, const std::string& serial, bool ca)
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = std::move(subjectKeys);
    p.issuerKeys = std::move(issuerKeys);
    p.issuer = std::move(issuer);
    p.subject.commonName = name;
    p.serialNumber = serial;
    p.basicConstraint.cA = ca;
    p.keyUsage.keyCertSign = ca;
    p.keyUsage.crlSign = ca;
    p.keyUsage.digitalSignature = !ca;
    p.keyUsage.nonRepudiation = !ca;
    const bool rsa = GetParam().keyAlgorithm == CertificateKeyAlgorithm::Rsa;
    p.keyUsage.keyEncipherment = !ca && rsa;
    p.keyUsage.dataEncipherment = !ca && rsa;
    p.keyUsage.serverAuth = !ca;
    p.keyUsage.clientAuth = !ca;
    p.certificateSignatureAlgorithm = GetParam().signatureAlgorithm;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    return mPki->create_cert(p);
  }

  shared_ptr<SecureChannelContext> make_context(ChannelRole role)
  {
    auto ctx = std::make_shared<SecureChannelContext>();
    ctx->boundStrand = boost::asio::make_strand(mPool.get_executor());
    ctx->role = role;
    ctx->state = SecureChannelContext::State::Uninitialised;
    ctx->crypto = mCrypto;
    // One policy instance per side, as in production.
    ctx->securityPolicy = SecurityPolicy::create(GetParam().policy);
    ctx->messageSecurityMode = MessageSecurityMode::Sign;
    ctx->secureChannelId = 0;
    ctx->lastRxSequenceNumber = std::nullopt;
    ctx->encodingLimits = test_limits();
    ctx->negotiatedLimits = {.sendBufferSize = 65536,
      .receiveBufferSize = 65536,
      .sendMaxMessageSize = 1u << 20,
      .sendMaxChunkCount = 100,
      .recvMaxMessageSize = 1u << 20,
      .recvMaxChunkCount = 100};
    ctx->namespaceIndexCallback = [](string_view)
    {
      return uint16_t{0};
    };
    return ctx;
  }

  /// The client frames an OpenSecureChannel request of @p type through the production encoder; the
  /// server decodes the one chunk it produces through the production decoder.
  DecodedMessageChunkResult send_opn(SecurityTokenRequestType type, uint32_t requestId)
  {
    auto request = std::make_shared<OpenSecureChannelRequest>();
    request->client_protocol_version() = 0;
    request->request_type() = type;
    request->security_mode() = MessageSecurityMode::Sign;
    request->client_nonce() = mCrypto->get_entropy_sync(32);
    request->requested_lifetime() = 60000;

    std::mutex chunkMutex;
    std::vector<ByteString> chunks;
    SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
    {
      const std::lock_guard<std::mutex> lock(chunkMutex);
      chunks.push_back(std::move(chunk));
    };
    auto clientPolicy = mClientContext->securityPolicy;
    auto encoded = ua::test_helpers::run_async_callback_sync<VoidResult>([&](auto cb)
      { clientPolicy->encode_message_async(mClientContext, requestId, request, sink, std::move(cb)); });
    EXPECT_TRUE(encoded.is_good()) << "the client could not frame the OPN: 0x" << std::hex
                                   << encoded.status_code().as_uint32();
    if (encoded.is_bad() || chunks.size() != 1)
    {
      ADD_FAILURE() << "an OPN request must frame into exactly one chunk, got " << chunks.size();
      return DecodedMessageChunkResult{StatusCode{Status::BadInternalError}};
    }

    auto serverPolicy = mServerContext->securityPolicy;
    return ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) {
        serverPolicy->decode_message_chunk_async(mServerContext, std::move(chunks.front()), std::move(cb));
      });
  }

  /// Issue with leaf A and its chain {CA}, then open both ends the way a completed Issue does.
  void issue_with_leaf_a()
  {
    auto issued = send_opn(SecurityTokenRequestType::Issue, 1);
    ASSERT_TRUE(issued.is_good()) << "the Issue signed by leaf A must decode: 0x" << std::hex
                                  << issued.status_code().as_uint32();
    ASSERT_NE(mServerContext->remoteCertificate, nullptr);
    ASSERT_EQ(mServerContext->remoteCertificate->thumbprint(), mLeafA->thumbprint())
      << "the Issue fixes leaf A as the certificate that created the channel";
    ASSERT_EQ(mServerContext->remoteIssuerCertificates.size(), 1u);
    ASSERT_EQ(mServerContext->remoteIssuerCertificates.front()->thumbprint(), mCa->thumbprint());

    constexpr uint32_t channelId = 5;
    mServerContext->state = SecureChannelContext::State::Open;
    mServerContext->secureChannelId = channelId;
    mClientContext->state = SecureChannelContext::State::Open;
    mClientContext->secureChannelId = channelId;
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<const Crypto> mCrypto;
  std::optional<TestPki> mPki;
  shared_ptr<const AsymmetricKeyPair> mServerKeys;
  shared_ptr<const X509Certificate> mServerCertificate;
  shared_ptr<const AsymmetricKeyPair> mCaKeys;
  shared_ptr<const X509Certificate> mCa;
  shared_ptr<const X509Certificate> mCaReissued;
  shared_ptr<const AsymmetricKeyPair> mClientKeys;
  shared_ptr<const X509Certificate> mLeafA;
  shared_ptr<const X509Certificate> mLeafB;
  std::shared_ptr<test_helpers::FakeCertificateStore> mStore;
  shared_ptr<SecureChannelContext> mServerContext;
  shared_ptr<SecureChannelContext> mClientContext;
};

}  // namespace

// Negative arm: the renew is signed by leaf B, certified on leaf A's own key and chained to the same CA.
// A comparison by key (or by issuer) would accept it; the leaf comparison refuses it with
// Bad_CertificateInvalid and leaves the channel's certificate as the Issue fixed it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-124-RENEW-SAME-LEAF, scope=function)
TEST_P(ServerRoleRenewLeaf, ARenewSignedByAnotherLeafOnTheSameKeyIsRefused)
{
  ASSERT_NO_FATAL_FAILURE(issue_with_leaf_a());
  ASSERT_NE(mLeafB->thumbprint(), mLeafA->thumbprint()) << "precondition: leaf B is another certificate";

  mClientContext->localCertificate = mLeafB;  // the one variable changed from the control
  auto renewed = send_opn(SecurityTokenRequestType::Renew, 2);

  ASSERT_TRUE(renewed.is_bad()) << "a renew signed by another leaf must be refused";
  EXPECT_EQ(renewed.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(mServerContext->remoteCertificate, nullptr);
  EXPECT_EQ(mServerContext->remoteCertificate->thumbprint(), mLeafA->thumbprint())
    << "a refused renew must not replace the certificate that created the channel";
}

// Control arm: the renew is signed by leaf A again but presents another issuer chain (the CA reissued).
// The leaf is the same, so the renew is accepted, and the newly presented chain replaces the old one.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-124-RENEW-SAME-LEAF, scope=function)
TEST_P(ServerRoleRenewLeaf, ARenewWithTheSameLeafAndAnotherChainIsAcceptedAndItsChainAdopted)
{
  ASSERT_NO_FATAL_FAILURE(issue_with_leaf_a());
  ASSERT_NE(mCaReissued->thumbprint(), mCa->thumbprint()) << "precondition: the chain really differs";

  mClientContext->localIssuerCertificates = {mCaReissued};  // the one variable changed from the negative
  auto renewed = send_opn(SecurityTokenRequestType::Renew, 2);

  ASSERT_TRUE(renewed.is_good()) << "a renew signed by the same leaf must be accepted: 0x" << std::hex
                                 << renewed.status_code().as_uint32();
  ASSERT_TRUE(renewed.value().has_value()) << "the Final OPN chunk completes the request";
  ASSERT_NE(mServerContext->remoteCertificate, nullptr);
  EXPECT_EQ(mServerContext->remoteCertificate->thumbprint(), mLeafA->thumbprint());
  ASSERT_EQ(mServerContext->remoteIssuerCertificates.size(), 1u);
  EXPECT_EQ(mServerContext->remoteIssuerCertificates.front()->thumbprint(), mCaReissued->thumbprint())
    << "the chain presented with the renew is adopted";
}

INSTANTIATE_TEST_SUITE_P(Policies, ServerRoleRenewLeaf,
  ::testing::Values(RenewLeafParams{SecurityPolicyId::Basic256Sha256,
                      CertificateKeyAlgorithm::Rsa,
                      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
                      "Basic256Sha256"},
    RenewLeafParams{SecurityPolicyId::EccNistP256AesGcm,
      CertificateKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      "EccNistP256"}),
  [](const ::testing::TestParamInfo<RenewLeafParams>& info) { return std::string{info.param.name}; });
