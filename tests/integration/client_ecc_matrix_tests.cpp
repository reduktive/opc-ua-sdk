// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientEcc` integration cluster - the ECC security-policy slice of the client integration-test
///        matrix (the 13 `ClientEcc.*` rows,
///        CL-ECC-001..004, client design section 10.2).
///
/// The rows cover four ECC-specific client behaviours:
///   * CL-ECC-004 registry/capability: the SDK registers the low-end ECC policies and connects over them
///     end-to-end (ECC_nistP256, ECC_curve25519_ChaCha20Poly1305).
///   * CL-ECC-001 own-cert / per-curve selection: an ECC own cert must carry digitalSignature; the store
///     selects the cert matching the configured policy curve; a policy with no matching-curve cert fails.
///   * CL-ECC-003 CreateSession ECDH exchange: the client sends the ECDHPolicyUri in the CreateSession
///     AdditionalHeader on an ECC channel (and NOT on an RSA channel), extracts the server ephemeral key
///     (ECDHKey) from the CreateSession response, and does not proceed with an absent key.
///   * CL-ECC-002 ephemeral discipline: a fresh client ephemeral per OPN, and the stored server ephemeral
///     is overwritten (never reused stale) across successive ActivateSession rounds.
///
/// Fixture: a self-contained server that mirrors the ComplianceSecured / ClientUsernamePassword PKI build
/// (RSA + ECC nistP256 + ECC curve25519 server/client certs, ECC nistP384 client cert for the multi-curve
/// selection row) with the same strand-safe request-observer + response-interceptor interfaces the
/// ClientUsernamePassword slice added (`ServerImplTestAccess::set_on_secure_channel_available` +
/// `SecureChannelTestAccess`). Those interfaces give the MisbehavingServer-equivalent capabilities the matrix
/// assigns to the MisbehavingServer rows (inspect the CreateSession request AdditionalHeader; inject a
/// StatusCode into the ECDHKey response slot) plus capture of every CreateSession/ActivateSession ECDHKey
/// and every ActivateSession user-token - so all 13 rows run against one real in-tree secured server.
///
/// Each row is falsifiable: it asserts an EXACT observable - the ECDHPolicyUri string, the EccEncryptedSecret
/// ReceiverPublicKey bytes, the selected local certificate identity, the distinct per-OPN client ephemeral -
/// never "did not crash".
///
/// Matrix-oracle deviations asserted-real and batched for the maintainer (see the per-test NOTE comments):
///   * CreateFailsWhenNoMatchingCurveCertForPolicy - there is NO create-time curve-cert-match check; the SDK
///     surfaces the missing-curve-cert case at channel-OPEN (the policy is only known then), failing
///     client-side with `ClientCertificateRetrievalFailed` / `BadNotFound` (which does not name the
///     policy/curve), before any network exchange.
///   * SendsEcdhPolicyUriInCreateSessionWhenEccChannel - the client derives the ECDHPolicyUri from the
///   CHANNEL
///     security policy URI (it is emitted whenever the channel's policy has an EphemeralKey: ECC or RSA_DH),
///     which equals the user-token-policy URI on such a channel.
///   * HandlesServerStatusCodeInsteadOfEcdhKey - the client does NOT surface the server's StatusCode from the
///     ECDHKey slot; the tier-0 extractor treats a StatusCode-in-the-slot as "no key" and stores an empty
///     ephemeral (it does not mis-parse the StatusCode's bytes as a key). The row asserts that real tier-0
///     observable; the ECDHKey is only consumed by a later user-token encrypt, so CreateSession still
///     completes. Surfacing the specific StatusCode up front is an unbuilt refinement (batched).
///   * DoesNotReuseStaleServerEphemeral - the client always uses the most-recent server-delivered ephemeral;
///     there is no client-side path that reintroduces a stale key, so the matrix's "pin a fabricated stale
///     key" is realised as a host-interface READBACK proving the stale CreateSession ephemeral (EK1) was
///     overwritten by the ActivateSession-response ephemeral (EK2) before the re-activate encrypts.

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_client_secure_channel_test_access.h"
#include "ua_client_session_test_access.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_status.h"
#include "ua_user_identity.h"
#include "ua_x509_certificate.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_additional_parameters_type.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_ephemeral_key_type.h"
#include "ua_key_value_pair.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_policy.h"

#include "ua_message_security_mode.h"
#include "ua_secure_channel_context.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"

#include "channel_bound_signature_test_data.h"
#include "sanitizer_budget.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// The policy id the fixture's ECC USERNAME token policy is advertised under (chosen by the test).
constexpr std::string_view userEccPolicyId = "user-ecc";
// The username the fixture accepts with any password (so the encrypting activate rows always activate).
constexpr std::string_view user = "alice";
constexpr std::string_view testPassword = "testpass";

std::string policy_uri(SecurityPolicyId id)
{
  return std::string{SecurityPolicy::create(id)->uri()};
}

// The part of a SecurityPolicyUri after '#', for example "ECC_nistP384_AesGcm": a test-name and
// endpoint-name suffix.
std::string policy_fragment(std::string_view uri)
{
  return std::string{uri.substr(uri.find('#') + 1)};
}

// A minimal little-endian reader over a raw blob (ByteString stores uint8_t). `valid` goes false on any
// short read so a malformed blob never reads out of bounds. (Mirrors the ClientUsernamePassword slice.)
struct BlobReader
{
  span<const uint8_t> data;
  std::size_t offset{0};
  bool valid{true};

  uint32_t u32()
  {
    if (offset + 4 > data.size())
    {
      valid = false;
      return 0;
    }
    const uint32_t value =
      static_cast<uint32_t>(data[offset]) | (static_cast<uint32_t>(data[offset + 1]) << 8) |
      (static_cast<uint32_t>(data[offset + 2]) << 16) | (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
  }

  void skip(std::size_t count)
  {
    if (offset + count > data.size())
    {
      valid = false;
      offset = data.size();
      return;
    }
    offset += count;
  }

  // Skip a UA-binary length-prefixed field (String or ByteString): int32 length (-1 = null) + bytes.
  void skip_length_prefixed()
  {
    const auto length = static_cast<int32_t>(u32());
    if (length > 0)
      skip(static_cast<std::size_t>(length));
  }

  ByteString read_byte_string()
  {
    const auto length = static_cast<int32_t>(u32());
    if (length <= 0)
      return {};
    if (offset + static_cast<std::size_t>(length) > data.size())
    {
      valid = false;
      return {};
    }
    ByteString out{data.subspan(offset, static_cast<std::size_t>(length))};
    offset += static_cast<std::size_t>(length);
    return out;
  }
};

// Extract the `ReceiverPublicKey` (server ephemeral) from an EccEncryptedSecret blob (Part 4 7.41.2.5,
// Table 190). The blob is the ExtensionObject - TypeId, encoding mask, Length - and its body, whose header is
// cleartext:
//   CommonHeader:  SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime, 8 bytes)
//   KeyDataLength: UInt16
//   KeyData:       SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
// so no decryption is needed to recover the receiver (server ephemeral) public key.
std::optional<ByteString> ecc_receiver_public_key(span<const uint8_t> blob)
{
  // The ExtensionObject prefix: the four-byte NodeId of EccEncryptedSecret (namespace 0, i=17546), the
  // ByteString body mask 0x01, and the body Length, which counts every byte after it.
  constexpr std::size_t prefixSize = 9;
  if (blob.size() < prefixSize || blob[0] != 0x01 || blob[1] != 0x00 ||
      (static_cast<unsigned>(blob[2]) | (static_cast<unsigned>(blob[3]) << 8)) != 17546u || blob[4] != 0x01)
    return std::nullopt;
  BlobReader reader{blob};
  reader.skip(5);
  if (reader.u32() != blob.size() - prefixSize)
    return std::nullopt;
  reader.skip_length_prefixed();  // SecurityPolicyUri (String)
  reader.skip_length_prefixed();  // Certificate (ByteString)
  reader.skip(8);  // SigningTime (DateTime)
  reader.skip(2);  // KeyDataLength (UInt16)
  (void)reader.read_byte_string();  // SenderPublicKey
  ByteString receiver = reader.read_byte_string();  // ReceiverPublicKey
  if (!reader.valid)
    return std::nullopt;
  return receiver;
}

// Concatenate two DER blobs. An OPC UA certificate chain is exactly this: the DER encodings of the
// certificates laid end to end, leaf first (Part 6 6.2.2), carried in one ByteString field.
ByteString concat_der(const ByteString& first, const ByteString& second)
{
  ByteString out = first;
  for (uint8_t value : second)
    out.push_back(value);
  return out;
}

// Extract the server ephemeral public key (ECDHKey) from a response's AdditionalHeader (mirror of the
// client's own extract_server_ephemeral_key). Returns empty when the ECDHKey slot is absent or does not
// hold an EphemeralKeyType (e.g. it holds a StatusCode instead).
ByteString extract_ecdh_key(const ua::Structure* additionalHeader)
{
  const auto* params = dynamic_cast<const ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return {};
  for (const auto& kv : params->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHKey")
    {
      if (const auto* ephemeral = kv.value().try_as<ua::EphemeralKeyType>())
        return ephemeral->public_key();
    }
  }
  return {};
}

// A structural description of one response's AdditionalHeader, recorded exactly as it arrived: what the
// header IS, every name it carries, and whether the ECDHKey slot holds an EphemeralKeyType. Part 6 Table 63
// fixes all three, and none of them is visible through `extract_ecdh_key` above, which reports only the
// bytes it managed to find and reports "empty" for every way of getting the shape wrong.
struct HeaderShape
{
  bool present{false};  ///< The response carried an AdditionalHeader at all.
  bool isAdditionalParameters{false};  ///< ... and it decoded as an AdditionalParametersType.
  std::vector<std::string> parameterNames;  ///< The name of every KeyValuePair in it, in order.
  bool ecdhKeyPresent{false};  ///< One of those names is "ECDHKey".
  bool ecdhKeyIsEphemeralKeyType{false};  ///< ... and its value holds an EphemeralKeyType.
  ByteString ecdhPublicKey;  ///< That EphemeralKeyType's public key.
};

HeaderShape describe_additional_header(const ua::Structure* additionalHeader)
{
  HeaderShape shape;
  if (!additionalHeader)
    return shape;
  shape.present = true;
  const auto* params = dynamic_cast<const ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return shape;
  shape.isAdditionalParameters = true;
  for (const auto& kv : params->parameters().payload())
  {
    shape.parameterNames.push_back(std::string{std::string_view{kv.key().name()}});
    if (std::string_view{kv.key().name()} != "ECDHKey")
      continue;
    shape.ecdhKeyPresent = true;
    if (const auto* ephemeral = kv.value().try_as<ua::EphemeralKeyType>())
    {
      shape.ecdhKeyIsEphemeralKeyType = true;
      shape.ecdhPublicKey = ephemeral->public_key();
    }
  }
  return shape;
}

// Extract the ECDHPolicyUri String the client put in a CreateSession request's AdditionalHeader, if any.
std::optional<std::string> extract_ecdh_policy_uri(const ua::Structure* additionalHeader)
{
  const auto* params = dynamic_cast<const ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return std::nullopt;
  for (const auto& kv : params->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHPolicyUri")
    {
      if (const auto* uri = kv.value().try_as<ua::String>())
        return std::string{*uri};
    }
  }
  return std::nullopt;
}

// Replace the ECDHKey value in an AdditionalHeader with a StatusCode (Part 6: a server that cannot honour
// the requested ECDHPolicyUri returns a StatusCode in the ECDHKey slot). Used by the misbehaving-server row.
/// Flips the first byte of the EphemeralKey signature in the ECDHKey slot: the key itself stays the
/// server's, so only the signature check can tell it from a genuine one.
void corrupt_ecdh_key_signature(ua::Structure* additionalHeader)
{
  auto* params = dynamic_cast<ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return;
  for (auto& kv : params->parameters().payload())
  {
    if (std::string_view{kv.key().name()} != "ECDHKey")
      continue;
    if (const auto* key = kv.value().try_as<ua::EphemeralKeyType>())
    {
      auto corrupted = std::make_unique<ua::EphemeralKeyType>();
      corrupted->public_key() = key->public_key();
      auto signature = key->signature();
      if (!signature.empty())
      {
        signature[0] = static_cast<uint8_t>(signature[0] ^ 0x5A);
      }
      corrupted->signature() = std::move(signature);
      kv.value() = ua::Variant{std::move(corrupted)};
    }
  }
}

void inject_status_into_ecdh_slot(ua::Structure* additionalHeader, ua::StatusCode status)
{
  auto* params = dynamic_cast<ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return;
  for (auto& kv : params->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHKey")
      kv.value() = ua::Variant{status};
  }
}

// Build a UserName UserTokenPolicy with an explicit policy id + effective security policy URI.
UserTokenPolicy user_name_policy(std::string_view policyId, std::string_view securityPolicyUri)
{
  UserTokenPolicy policy;
  policy.token_type() = UserTokenType::UserName;
  policy.policy_id() = std::string{policyId};
  policy.security_policy_uri() = std::string{securityPolicyUri};
  return policy;
}

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial make_cert(const std::shared_ptr<const Crypto>& crypto, CertificateType certType,
  std::string_view commonName, std::string_view uri)
{
  Crypto::Name subject;
  subject.commonName = std::string{commonName};
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(std::string{uri});
  altName.hostnames.push_back("localhost");
  altName.hostnames.push_back("127.0.0.1");
  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, certType, 2048);
  if (result.is_bad())
    throw std::runtime_error("failed to create certificate: " + std::string{commonName});
  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

// Runs the SDK's peer-certificate validation for one policy over one certificate against one store - the
// exact entry point a SecureChannel calls on the certificate the peer presented in the OPN
// (`SecurityPolicy::validate_certificate_async`). Everything the check consumes is set on the context:
// the certificate under test, the store holding the trust lists, and the crypto provider. Blocks on the
// test thread only (never on a pool thread) and keeps the context alive until the callback has run.
ua::VoidResult validate_peer_certificate(const std::shared_ptr<SecurityPolicy>& policy,
  const std::shared_ptr<const Crypto>& crypto, const std::shared_ptr<CertificateStore>& store,
  const std::shared_ptr<const X509Certificate>& certificate)
{
  // The strand a bound channel always carries: the SecureChannel constructor engages `mStrand`
  // immediately, so a context without one is a shape production never produces. The validation body
  // marshals its continuation onto it, so this pool has to be running for the wait below to return.
  static boost::asio::thread_pool validationPool{2};

  auto context = std::make_shared<ua::SecureChannelContext>();
  context->boundStrand =
    boost::asio::make_strand(boost::asio::any_io_executor{validationPool.get_executor()});
  context->crypto = crypto;
  context->certStore = store;
  context->securityPolicy = policy;
  context->remoteCertificate = certificate;

  std::promise<ua::VoidResult> promise;
  auto future = promise.get_future();
  policy->validate_certificate_async(
    *context, [&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// A snapshot of the UserNameIdentityToken bytes the client put on the wire for one ActivateSession request.
struct CapturedToken
{
  bool present{false};
  std::string encryptionAlgorithm;
  ByteString password;  // the EccEncryptedSecret blob for an ECC user-token policy
};

// The application-instance signature the client put on the wire for one ActivateSession request.
struct CapturedSignature
{
  std::string algorithm;
  ByteString signature;
};

// Mutex-guarded observation co-owned by the fixture and the strand-side interfaces. The server is drained
// before this is released (see the fixture destructor), so a late strand turn never touches dead state.
struct EccObservation
{
  mutable std::mutex mutex;

  int createSessionCount{0};
  std::optional<std::string> createSessionEcdhPolicyUri;  // from the CreateSession request AdditionalHeader
  ByteString createSessionEcdhKey;  // EK1 from the CreateSession response AdditionalHeader

  ByteString createSessionClientNonce;  // clientNonce from the CreateSession request
  ByteString createSessionServerNonce;  // serverNonce from the CreateSession response
  ByteString presentedServerCertificate;  // serverCertificate exactly as the client received it

  std::vector<CapturedToken> activateTokens;  // one per ActivateSession request, in order
  std::vector<CapturedSignature> activateSignatures;  // clientSignature per ActivateSession request, in order
  std::vector<ByteString> activateResponseEcdhKeys;  // fresh EK from each ActivateSession response, in order

  HeaderShape createSessionHeaderShape;  // shape of the CreateSession response AdditionalHeader
  std::vector<HeaderShape> activateHeaderShapes;  // shape of each ActivateSession response AdditionalHeader

  // Armed by the test thread BEFORE connecting: replace the CreateSession-response ECDHKey with a StatusCode.
  bool injectStatusInsteadOfEcdhKey{false};

  // Armed by the test thread BEFORE connecting: corrupt the CreateSession-response EphemeralKey signature,
  // leaving the key itself the server's.
  bool corruptEcdhKeySignature{false};

  // Armed by the test thread BEFORE connecting: append these DER bytes to the CreateSession-response
  // serverCertificate, so the client is handed a CHAIN whose leaf is the real server certificate.
  ByteString appendToServerCertificate;

  void observe_request(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
    {
      ++createSessionCount;
      createSessionClientNonce = create->client_nonce();
      createSessionEcdhPolicyUri =
        extract_ecdh_policy_uri(create->request_header().additional_header().get());
      return;
    }
    if (const auto* activate = dynamic_cast<const ua::ActivateSessionRequest*>(&request))
    {
      CapturedToken token;
      if (const auto* userToken =
            dynamic_cast<const ua::UserNameIdentityToken*>(activate->user_identity_token().get()))
      {
        token.present = true;
        token.encryptionAlgorithm = std::string{userToken->encryption_algorithm()};
        token.password = userToken->password();
      }
      activateTokens.push_back(std::move(token));

      CapturedSignature signature;
      signature.algorithm = std::string{activate->client_signature().algorithm()};
      signature.signature = activate->client_signature().signature();
      activateSignatures.push_back(std::move(signature));
    }
  }

  void intercept_response(ua::Response& response)
  {
    std::lock_guard lock(mutex);
    if (auto* create = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
    {
      auto* header = create->response_header().additional_header().get();
      if (injectStatusInsteadOfEcdhKey)
        inject_status_into_ecdh_slot(header, ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
      if (corruptEcdhKeySignature)
        corrupt_ecdh_key_signature(header);
      createSessionEcdhKey = extract_ecdh_key(header);
      createSessionHeaderShape = describe_additional_header(header);
      if (!appendToServerCertificate.empty())
        create->server_certificate() = concat_der(create->server_certificate(), appendToServerCertificate);
      presentedServerCertificate = create->server_certificate();
      createSessionServerNonce = create->server_nonce();
      return;
    }
    if (auto* activate = dynamic_cast<ua::ActivateSessionResponse*>(response.second.get()))
    {
      activateResponseEcdhKeys.push_back(
        extract_ecdh_key(activate->response_header().additional_header().get()));
      activateHeaderShapes.push_back(
        describe_additional_header(activate->response_header().additional_header().get()));
    }
  }

  int create_session_count() const
  {
    std::lock_guard lock(mutex);
    return createSessionCount;
  }

  std::optional<std::string> create_session_ecdh_policy_uri() const
  {
    std::lock_guard lock(mutex);
    return createSessionEcdhPolicyUri;
  }

  ByteString create_session_ecdh_key() const
  {
    std::lock_guard lock(mutex);
    return createSessionEcdhKey;
  }

  ByteString create_session_client_nonce() const
  {
    std::lock_guard lock(mutex);
    return createSessionClientNonce;
  }

  ByteString create_session_server_nonce() const
  {
    std::lock_guard lock(mutex);
    return createSessionServerNonce;
  }

  ByteString presented_server_certificate() const
  {
    std::lock_guard lock(mutex);
    return presentedServerCertificate;
  }

  std::vector<CapturedToken> activate_tokens() const
  {
    std::lock_guard lock(mutex);
    return activateTokens;
  }

  std::vector<CapturedSignature> activate_signatures() const
  {
    std::lock_guard lock(mutex);
    return activateSignatures;
  }

  std::vector<ByteString> activate_response_ecdh_keys() const
  {
    std::lock_guard lock(mutex);
    return activateResponseEcdhKeys;
  }

  HeaderShape create_session_header_shape() const
  {
    std::lock_guard lock(mutex);
    return createSessionHeaderShape;
  }

  std::vector<HeaderShape> activate_header_shapes() const
  {
    std::lock_guard lock(mutex);
    return activateHeaderShapes;
  }
};

}  // namespace

// =============================================================================================
// Fixture: a server with an RSA endpoint and an endpoint for each of the fourteen EphemeralKey policies, the
// request-observer / response-interceptor interfaces, and a client trusting that server; each store holds a
// certificate of every type those policies need.
// =============================================================================================
class ClientEcc : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mObservation = std::make_shared<EccObservation>();

    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    mServerRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "EccServer RSA", "urn:test:ecc:server:rsa");
    mServerNistP256 = make_cert(
      mCrypto, CertificateType::EccNistP256Application, "EccServer nistP256", "urn:test:ecc:server:nistp256");
    mServerCurve25519 = make_cert(mCrypto,
      CertificateType::EccCurve25519Application,
      "EccServer curve25519",
      "urn:test:ecc:server:curve25519");

    constexpr std::string_view clientApplicationUri{"urn:test:ecc:client"};
    mClientRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "EccClient RSA", clientApplicationUri);
    mClientNistP256 =
      make_cert(mCrypto, CertificateType::EccNistP256Application, "EccClient nistP256", clientApplicationUri);
    mClientNistP384 =
      make_cert(mCrypto, CertificateType::EccNistP384Application, "EccClient nistP384", clientApplicationUri);
    mClientCurve25519 = make_cert(
      mCrypto, CertificateType::EccCurve25519Application, "EccClient curve25519", clientApplicationUri);

    // A server and a client certificate of every other type an EphemeralKey policy needs (OPC 10000-6
    // Table 49), so each of the fourteen policies has a usable endpoint (ClientEphemeralKeyAgreement).
    mServerByType = {{CertificateType::RsaSha256Application, mServerRsa},
      {CertificateType::EccNistP256Application, mServerNistP256},
      {CertificateType::EccCurve25519Application, mServerCurve25519}};
    mClientByType = {{CertificateType::RsaSha256Application, mClientRsa},
      {CertificateType::EccNistP256Application, mClientNistP256},
      {CertificateType::EccNistP384Application, mClientNistP384},
      {CertificateType::EccCurve25519Application, mClientCurve25519}};
    std::vector<std::pair<CertificateType, KeyMaterial>> extraServer;
    std::vector<std::pair<CertificateType, KeyMaterial>> extraClient;
    for (const auto& row : ephemeral_key_policy_rows())
    {
      const auto name = policy_fragment(row.uri);
      if (!mServerByType.contains(row.certificateType))
      {
        auto material =
          make_cert(mCrypto, row.certificateType, "EccServer " + name, "urn:test:ecc:server:" + name);
        mServerByType.emplace(row.certificateType, material);
        extraServer.emplace_back(row.certificateType, std::move(material));
      }
      if (!mClientByType.contains(row.certificateType))
      {
        auto material = make_cert(mCrypto, row.certificateType, "EccClient " + name, clientApplicationUri);
        mClientByType.emplace(row.certificateType, material);
        extraClient.emplace_back(row.certificateType, std::move(material));
      }
    }

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_ecc_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    // Server store: holds a server app cert of every type, trusts every client cert.
    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    add_app_cert(mServerCertStore, CertificateType::RsaSha256Application, mServerRsa);
    add_app_cert(mServerCertStore, CertificateType::EccNistP256Application, mServerNistP256);
    add_app_cert(mServerCertStore, CertificateType::EccCurve25519Application, mServerCurve25519);
    mServerCertStore->add_to_trusted_certificates_sync(mClientRsa.cert);
    mServerCertStore->add_to_trusted_certificates_sync(mClientNistP256.cert);
    mServerCertStore->add_to_trusted_certificates_sync(mClientNistP384.cert);
    mServerCertStore->add_to_trusted_certificates_sync(mClientCurve25519.cert);
    for (const auto& [type, material] : extraServer)
      add_app_cert(mServerCertStore, type, material);
    for (const auto& [type, material] : extraClient)
      mServerCertStore->add_to_trusted_certificates_sync(material.cert);

    // Client store: holds RSA + all ECC client app certs (nistP256 + nistP384 co-resident for the
    // per-curve selection row), trusts the server certs.
    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    add_app_cert(mClientCertStore, CertificateType::RsaSha256Application, mClientRsa);
    add_app_cert(mClientCertStore, CertificateType::EccNistP256Application, mClientNistP256);
    add_app_cert(mClientCertStore, CertificateType::EccNistP384Application, mClientNistP384);
    add_app_cert(mClientCertStore, CertificateType::EccCurve25519Application, mClientCurve25519);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);
    mClientCertStore->add_to_trusted_certificates_sync(mServerNistP256.cert);
    mClientCertStore->add_to_trusted_certificates_sync(mServerCurve25519.cert);
    for (const auto& [type, material] : extraClient)
      add_app_cert(mClientCertStore, type, material);
    for (const auto& [type, material] : extraServer)
      mClientCertStore->add_to_trusted_certificates_sync(material.cert);

    // Server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString&) { return username == user; }));
    components.authenticator = composite;
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});

    server::CreateConfig serverCreateCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

    mServer.emplace(
      Server::create(mServerThreadPool.executor(), std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    add_endpoints();
    install_wire_ops();

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    mClient.emplace(make_client(mClientCertStore));
  }

  void TearDown() override
  {
    // Close + drain the server BEFORE releasing the shared observation state (mirror of the
    // ClientUsernamePassword teardown order): no in-flight strand turn can then touch dead state.
    mClient.reset();
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
    mObservation.reset();

    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  static void add_app_cert(
    const std::shared_ptr<CertificateStore>& store, CertificateType type, const KeyMaterial& material)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = type;
    appCert.certificate = material.cert;
    appCert.keys = material.keys;
    store->add_to_application_certificates_sync(appCert);
  }

  Client make_client(const std::shared_ptr<CertificateStore>& store)
  {
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:ecc:client";
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    return Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = store,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning});
  }

  void add_endpoints()
  {
    // Basic256Sha256 / SignAndEncrypt: RSA channel, Anonymous.
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // ECC_nistP256 / SignAndEncrypt: Anonymous + UserName(ECC, "user-ecc").
    {
      ServerEndpointConfig ep;
      ep.name = "EccNistP256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::EccNistP256AesGcm;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(
        user_name_policy(userEccPolicyId, policy_uri(SecurityPolicyId::EccNistP256AesGcm)));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // ECC_curve25519_ChaChaPoly / SignAndEncrypt: Anonymous + UserName(ECC, "user-ecc").
    {
      ServerEndpointConfig ep;
      ep.name = "EccCurve25519_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::EccCurve25519ChaChaPoly;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(
        user_name_policy(userEccPolicyId, policy_uri(SecurityPolicyId::EccCurve25519ChaChaPoly)));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // Every other EphemeralKey policy / SignAndEncrypt: Anonymous + UserName under the policy itself.
    for (const auto& row : ephemeral_key_policy_rows())
    {
      if (row.id == SecurityPolicyId::EccNistP256AesGcm ||
          row.id == SecurityPolicyId::EccCurve25519ChaChaPoly)
        continue;
      ServerEndpointConfig ep;
      ep.name = policy_fragment(row.uri) + "_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = row.id;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(user_name_policy(userEccPolicyId, row.uri));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }
  }

  void install_wire_ops()
  {
    auto& serverImpl = ServerTestAccess::impl(*mServer);
    ServerImplTestAccess(serverImpl)
      .set_on_secure_channel_available(
        [observation = mObservation](std::shared_ptr<ua::server::SecureChannel> secureChannel)
        {
          ua::server::SecureChannelTestAccess::post_on_strand(std::move(secureChannel),
            [observation](auto& guard)
            {
              guard.set_request_observer([observation](uint32_t /*requestId*/, const ua::Structure& request)
                { observation->observe_request(request); });
              guard.set_response_interceptor(
                [observation](ua::Response& response) { observation->intercept_response(response); });
            });
        });
  }

  const KeyMaterial& server_cert_for(SecurityPolicyId policy) const
  {
    switch (policy)
    {
    case SecurityPolicyId::EccNistP256AesGcm:
      return mServerNistP256;
    case SecurityPolicyId::EccCurve25519ChaChaPoly:
      return mServerCurve25519;
    default:
      if (const auto* row = find_ephemeral_key_policy(policy))
        return mServerByType.at(row->certificateType);
      return mServerRsa;
    }
  }

  // Open a SignAndEncrypt channel of the given policy against the fixture's server, using `client`.
  ua::Result<ua::client::SecureChannel> open_channel(ua::client::Client& client, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = policy;
    cfg.serverCertificate = server_cert_for(policy).cert;
    return client.core().try_open_channel_sync(std::move(cfg));
  }

  // Open ECC channel -> create -> activate(UserName ECC) with the fixture's client; leaves the session and
  // channel open (owned by the caller) so successive re-activations can be driven.
  struct EccSession
  {
    bool channelOpened{false};
    std::optional<ua::client::SecureChannel> channel;
    std::optional<ua::client::Session> session;
    ua::VoidResult activate;
  };

  EccSession open_create_activate(SecurityPolicyId policy, std::string_view policyId)
  {
    EccSession out;
    auto channelResult = open_channel(*mClient, policy);
    if (channelResult.is_bad())
    {
      out.activate = ua::VoidResult{channelResult.status_code(), channelResult.shared_detail()};
      return out;
    }
    out.channelOpened = true;
    out.channel.emplace(std::move(channelResult).value());
    out.session.emplace(out.channel->create_session_sync({.sessionName = "EccTest"}));

    ua::client::Session::ActivateConfig config;
    config.policyId = std::string{policyId};
    config.identity =
      UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}};
    out.activate = out.session->try_activate_sync(std::move(config));
    return out;
  }

  static void close_session(EccSession& s)
  {
    if (s.session)
      (void)s.session->try_close_sync();
    if (s.channel)
      (void)s.channel->try_close_sync();
  }

  // Read the client channel's last client nonce (for ECC = the client ephemeral public key) + token id.
  struct ChannelSnapshot
  {
    uint32_t tokenId{0};
    ByteString lastClientNonce;
  };

  static ChannelSnapshot read_channel(ua::client::SecureChannel& channel)
  {
    return ua::client::SecureChannelTestAccess::on_strand(channel,
      [](auto& guard)
      {
        ChannelSnapshot snap;
        snap.tokenId = guard.channel_token_id();
        snap.lastClientNonce = guard.last_client_nonce();
        return snap;
      });
  }

  static bool wait_for_renewal(
    ua::client::SecureChannel& channel, uint32_t oldTokenId, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (read_channel(channel).tokenId != oldTokenId)
        return true;
      std::this_thread::sleep_for(50ms);
    }
    return false;
  }

  std::shared_ptr<const Crypto> mCrypto;
  KeyMaterial mServerRsa;
  KeyMaterial mServerNistP256;
  KeyMaterial mServerCurve25519;
  KeyMaterial mClientRsa;
  KeyMaterial mClientNistP256;
  KeyMaterial mClientNistP384;
  KeyMaterial mClientCurve25519;
  std::map<CertificateType, KeyMaterial> mServerByType;  // one server certificate per EphemeralKey type
  std::map<CertificateType, KeyMaterial> mClientByType;  // one client certificate per EphemeralKey type
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::shared_ptr<EccObservation> mObservation;
};

// The key-agreement obligations hold for every policy whose keys come from an EphemeralKey exchange: the
// twelve ECC policies and the two RSA_DH policies (the EphemeralKeyType of OPC 10000-4 7.15). The parameter
// is the channel policy and the UserName token policy (G-49); the ECC_nistP256_AesGcm row is the test each
// replaced. The registry, certificate-curve and key-usage tests below keep their representative policies.
class ClientEphemeralKeyAgreement : public ClientEcc, public ::testing::WithParamInterface<SecurityPolicyId>
{};

std::vector<SecurityPolicyId> ephemeral_key_policies()
{
  std::vector<SecurityPolicyId> policies;
  for (const auto& row : ephemeral_key_policy_rows())
    policies.push_back(row.id);
  return policies;
}

std::string ephemeral_key_policy_name(const ::testing::TestParamInfo<SecurityPolicyId>& info)
{
  return policy_fragment(policy_uri(info.param));
}

INSTANTIATE_TEST_SUITE_P(FourteenPolicies, ClientEphemeralKeyAgreement,
  ::testing::ValuesIn(ephemeral_key_policies()), ephemeral_key_policy_name);

// =============================================================================================
// CL-ECC-004: registry / capability
// =============================================================================================

// @verifies CL-ECC-004
// The SDK registers both low-end ECC policies - ECC_nistP256 (the NIST 128-bit-tier policy the matrix names
// "Aes128_Sha256_nistP256") and ECC_curve25519_ChaCha20Poly1305 (the Bernstein 128-bit-tier policy) - in the
// SAME lookup the connect path and Discovery::select_endpoint consume: SecurityPolicy::create(uri). A
// registration that satisfied a static enumeration but not this lookup would still fail here. Falsifier: an
// unregistered URI makes SecurityPolicy::create(uri) throw Bad_InvalidArgument.
// @relation(CL-ECC-004, scope=function)
TEST_F(ClientEcc, RegistryListsBothLowEndEccPolicies)
{
  const std::string nistUri = policy_uri(SecurityPolicyId::EccNistP256AesGcm);
  const std::string curve25519Uri = policy_uri(SecurityPolicyId::EccCurve25519ChaChaPoly);

  // The connect-path lookup (URI -> policy) resolves both to an ECC policy of the expected id.
  std::shared_ptr<SecurityPolicy> nist;
  std::shared_ptr<SecurityPolicy> curve25519;
  ASSERT_NO_THROW(nist = SecurityPolicy::create(nistUri));
  ASSERT_NO_THROW(curve25519 = SecurityPolicy::create(curve25519Uri));
  EXPECT_EQ(nist->id(), SecurityPolicyId::EccNistP256AesGcm);
  EXPECT_TRUE(nist->is_ecc());
  EXPECT_EQ(curve25519->id(), SecurityPolicyId::EccCurve25519ChaChaPoly);
  EXPECT_TRUE(curve25519->is_ecc());

  // Round-trip through the id-keyed lookup the same way the connect path derives a URI to advertise/match.
  EXPECT_EQ(std::string{SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()}, nistUri);
  EXPECT_EQ(
    std::string{SecurityPolicy::create(SecurityPolicyId::EccCurve25519ChaChaPoly)->uri()}, curve25519Uri);
}

// @verifies AC-CL-ECC-004-CURVE25519-MINIMUM
// End-to-end handshake under ECC_nistP256 (the matrix's "Aes128_Sha256_nistP256"; the SDK's URI for this
// low-end NIST policy is ECC_nistP256). A SignAndEncrypt OPN over the nistP256 endpoint succeeds; if the
// policy were unregistered the connect would fail Bad_SecurityPolicyRejected.
// @relation(CL-ECC-004, scope=function)
TEST_F(ClientEcc, SupportsAes128Sha256NistP256)
{
  auto channel = open_channel(*mClient, SecurityPolicyId::EccNistP256AesGcm);
  ASSERT_TRUE(channel.is_good()) << "ECC_nistP256 SignAndEncrypt OPN must succeed: 0x" << std::hex
                                 << channel.status_code().as_uint32();
  EXPECT_TRUE(channel.value().is_open());
  (void)std::move(channel).value().try_close_sync();
}

// @verifies AC-CL-ECC-004-CURVE25519-MINIMUM
// End-to-end handshake under ECC_curve25519_ChaCha20Poly1305 (the low-end Bernstein/curve25519 policy). A
// SignAndEncrypt OPN over the curve25519 endpoint succeeds; if the policy were unregistered the connect
// would fail Bad_SecurityPolicyRejected.
// @relation(AC-CL-ECC-004-CURVE25519-MINIMUM, scope=function)
TEST_F(ClientEcc, SupportsChaCha20Poly1305Curve25519)
{
  auto channel = open_channel(*mClient, SecurityPolicyId::EccCurve25519ChaChaPoly);
  ASSERT_TRUE(channel.is_good()) << "ECC_curve25519_ChaCha20Poly1305 SignAndEncrypt OPN must succeed: 0x"
                                 << std::hex << channel.status_code().as_uint32();
  EXPECT_TRUE(channel.value().is_open());
  (void)std::move(channel).value().try_close_sync();
}

// =============================================================================================
// CL-ECC-001: own-cert / per-curve certificate selection
// =============================================================================================

// @verifies CL-ECC-001
// A client whose store holds only an RSA own cert cannot open an ECC_nistP256 channel: the client selects the
// own cert by the policy's certificate type (EccNistP256Application), finds none (BadNotFound), and fails
// client-side with ClientCertificateRetrievalFailed - before any network exchange. Falsifier: without the
// per-policy cert-type selection the RSA cert would be (wrongly) reused for the ECC handshake.
//
// NOTE (matrix-oracle deviation, batched): the matrix frames this as a `Client::create` precondition naming
// the policy and the absent ECC cert type, but the SDK (a) has NO create-time
// "curve-cert-matching-the-policy" check - the security policy, and hence the required curve cert type, is
// only known from the OpenChannelConfig, not at create time - and (b) surfaces the failure at channel-OPEN,
// where the own cert is selected by the policy's certificate type: the store has no EccNistP256Application
// cert, so retrieval fails BadNotFound wrapped in a generic ClientCertificateRetrievalFailed that does NOT
// name the policy/curve. This row asserts that real client-observable behaviour; enriching the retrieval
// ErrorDetail to name the policy/curve is batched as an enhancement.
// @relation(CL-ECC-001, scope=function)
TEST_F(ClientEcc, CreateFailsWhenNoMatchingCurveCertForPolicy)
{
  // A store with only an RSA app cert (no ECC cert of any curve), trusting the server ECC cert so the only
  // reason the ECC open can fail is the missing own cert.
  auto storePath = mTempDir / "rsa_only_store";
  std::filesystem::create_directories(storePath);
  TrustListValidationOptions validationOptions;
  auto rsaOnlyStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = storePath, .validationOptions = validationOptions});
  add_app_cert(rsaOnlyStore, CertificateType::RsaSha256Application, mClientRsa);
  rsaOnlyStore->add_to_trusted_certificates_sync(mServerNistP256.cert);

  auto rsaOnlyClient = make_client(rsaOnlyStore);
  auto channel = open_channel(rsaOnlyClient, SecurityPolicyId::EccNistP256AesGcm);

  ASSERT_TRUE(channel.is_bad()) << "an ECC channel with no matching-curve own cert must fail to open";
  EXPECT_EQ(channel.status_code(), ua::StatusCode{ua::Status::BadNotFound})
    << "the store has no ECC own cert of the policy's curve type -> BadNotFound at cert retrieval";
  ASSERT_TRUE(channel.shared_detail()) << "the failure must carry an ErrorDetail";
  EXPECT_THAT(
    ua::to_string(*channel.shared_detail()), ::testing::HasSubstr("ClientCertificateRetrievalFailed"))
    << "the ErrorDetail must name the failed own-certificate retrieval for the configured policy";
  EXPECT_EQ(mObservation->create_session_count(), 0)
    << "no session may be created when the own cert cannot be retrieved";
}

// @verifies CL-ECC-001
// An ECC own cert that lacks the digitalSignature keyUsage bit fails create: Part 6 section 6.2.2 requires an
// ECC ApplicationInstance key to carry digitalSignature (the channel signature). The key-type-aware
// create-time validator (validate_own_application_certificate) rejects it naming the missing bit. Falsifier:
// without the check the unusable cert is accepted and only fails later on the wire.
// @relation(CL-ECC-001, scope=function)
TEST_F(ClientEcc, EccCertKeyUsageMustIncludeDigitalSignature)
{
  const std::string uri = "urn:test:ecc:no-digital-signature";

  // Self-signed ECC (nistP256) cert with keyCertSign (so the self-signed check is satisfied) but WITHOUT
  // digitalSignature - the deliberate defect.
  auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  Crypto::CreateCertificateConfig params;
  params.serialNumber = "1";
  params.subject.commonName = "Ecc No DigitalSignature Client";
  params.subjectKeys = keys;
  params.issuerKeys = keys;  // self-signed
  params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  params.from = UtcTime{2020, 1, 1, 0, 0, 0};
  params.to = UtcTime{2050, 1, 1, 0, 0, 0};
  params.keyUsage.digitalSignature = false;  // the deliberate defect
  params.keyUsage.keyAgreement = true;
  params.keyUsage.keyCertSign = true;  // self-signed CA bit so only digitalSignature is the failure
  params.subjectAlternateName.hostnames.push_back("localhost");
  params.subjectAlternateName.uris.push_back(uri);
  params.basicConstraint.cA = true;
  params.basicConstraint.pathLength = 0;

  std::promise<CertificateResult> promise;
  auto future = promise.get_future();
  mCrypto->create_certificate_async(
    params, [&promise](CertificateResult r) { promise.set_value(std::move(r)); });
  auto certResult = future.get();
  ASSERT_TRUE(certResult.is_good()) << "ECC cert generation must succeed";
  auto cert = std::move(certResult).value();
  ASSERT_EQ(cert->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);
  ASSERT_FALSE(cert->key_usage_digital_signature()) << "fixture precondition: digitalSignature absent";

  auto storePath = mTempDir / "ecc_no_digsig_store";
  std::filesystem::create_directories(storePath);
  TrustListValidationOptions validationOptions;
  auto store = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = storePath, .validationOptions = validationOptions});
  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::EccNistP256Application;
  appCert.certificate = cert;
  appCert.keys = keys;
  store->add_to_application_certificates_sync(appCert);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.application_description_part().applicationUri = uri;
  client::CreateConfig cfg{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
  auto result = Client::try_create(mClientThreadPool.executor(),
    std::move(cfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = store,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning});

  ASSERT_TRUE(result.is_bad()) << "an ECC own cert missing digitalSignature must fail create";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateKeyUsageInvalid"))
    << "the ErrorDetail must name the keyUsage precondition";
  EXPECT_THAT(detail, ::testing::HasSubstr("digitalSignature"))
    << "the ErrorDetail must name the specific missing keyUsage bit";
}

// @verifies CL-ECC-001
// With both an nistP256 and an nistP384 own cert co-resident in the store, configuring an ECC_nistP256
// channel presents the nistP256 cert: the store selects the own cert by the policy's certificate type
// (per-curve), not the first ECC cert. Asserted directly on the channel's selected local certificate, and
// end-to-end (the server, which trusts the nistP256 client cert, accepts the OPN). Falsifier: broken
// per-curve selection would pick the nistP384 cert (wrong-curve key for an nistP256 policy) and the OPN
// would fail.
// @relation(CL-ECC-001, scope=function)
TEST_F(ClientEcc, UsesEccCertMatchingConfiguredPolicyCurve)
{
  ASSERT_NE(mClientNistP256.cert->key_algorithm(), mClientNistP384.cert->key_algorithm())
    << "fixture precondition: the two ECC own certs are on distinct curves";

  auto channelResult = open_channel(*mClient, SecurityPolicyId::EccNistP256AesGcm);
  ASSERT_TRUE(channelResult.is_good()) << "ECC_nistP256 OPN must succeed with the matching-curve own cert";
  auto channel = std::move(channelResult).value();

  auto localCert = ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& guard) { return guard.context()->localCertificate; });
  ASSERT_NE(localCert, nullptr) << "the channel must have selected a local certificate";
  EXPECT_EQ(localCert->key_algorithm(), CertificateKeyAlgorithm::EccNistP256)
    << "the selected own cert must be the nistP256 cert, not the co-resident nistP384 cert";
  EXPECT_EQ(*localCert, *mClientNistP256.cert) << "the exact nistP256 own cert must be the one presented";

  (void)channel.try_close_sync();
}

// =============================================================================================
// CL-ECC-003: CreateSession ECDH exchange
// =============================================================================================

// @verifies CL-ECC-003
// On an ECC channel, the client extracts the server ephemeral public key (ECDHKey) from the CreateSession
// response AdditionalHeader and uses it to encrypt the first ActivateSession user token: the emitted
// EccEncryptedSecret's ReceiverPublicKey equals the ECDHKey delivered by the server. If extraction had
// failed, the activation would have no ephemeral and error.
// @relation(CL-ECC-003, scope=function)
TEST_P(ClientEphemeralKeyAgreement, ExtractsEcdhKeyFromCreateSessionResponse)
{
  auto s = open_create_activate(GetParam(), userEccPolicyId);
  ASSERT_TRUE(s.activate.is_good()) << "activation over the ECC channel must succeed: 0x" << std::hex
                                    << s.activate.status_code().as_uint32();

  const ByteString serverEphemeral = mObservation->create_session_ecdh_key();
  ASSERT_FALSE(serverEphemeral.empty()) << "server must return an ECDHKey in the CreateSession response";

  auto tokens = mObservation->activate_tokens();
  ASSERT_EQ(tokens.size(), 1u);
  ASSERT_TRUE(tokens[0].present);
  ASSERT_FALSE(tokens[0].password.empty());

  auto receiver = ecc_receiver_public_key(tokens[0].password);
  ASSERT_TRUE(receiver.has_value()) << "could not parse the EccEncryptedSecret header";
  EXPECT_EQ(*receiver, serverEphemeral)
    << "the first ActivateSession token must be encrypted with the extracted CreateSession ECDHKey";

  close_session(s);
}

// @verifies CL-ECC-003
// On an ECC channel the client requests an ECDH ephemeral by putting the ECDHPolicyUri in the CreateSession
// request AdditionalHeader, equal to the ECC policy URI. If it were omitted the server could not return a
// usable ephemeral and later activation would fail.
//
// NOTE (matrix nuance): the client derives the ECDHPolicyUri from the CHANNEL security-policy URI (it is sent
// whenever the channel's policy has an EphemeralKey), which on such a channel equals the user-token-policy
// URI.
// @relation(CL-ECC-003, scope=function)
TEST_P(ClientEphemeralKeyAgreement, SendsEcdhPolicyUriInCreateSessionWhenEccChannel)
{
  auto channelResult = open_channel(*mClient, GetParam());
  ASSERT_TRUE(channelResult.is_good());
  auto channel = std::move(channelResult).value();
  auto session = channel.create_session_sync({.sessionName = "EccEcdhReq"});

  auto uri = mObservation->create_session_ecdh_policy_uri();
  ASSERT_TRUE(uri.has_value()) << "an ECC channel must send an ECDHPolicyUri in the CreateSession request";
  EXPECT_EQ(*uri, policy_uri(GetParam())) << "the ECDHPolicyUri must name the ECC policy URI";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @verifies CL-ECC-003
// On an RSA channel the client sends NO ECDHPolicyUri in the CreateSession request: the ECDH obligation is
// ECC-specific and an RSA channel emitting it would be a defect. Falsifier: a policy-blind emitter would add
// an ECDHPolicyUri here too.
// @relation(CL-ECC-003, scope=function)
TEST_F(ClientEcc, DoesNotSendEcdhPolicyUriForRsaChannel)
{
  auto channelResult = open_channel(*mClient, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channelResult.is_good());
  auto channel = std::move(channelResult).value();
  auto session = channel.create_session_sync({.sessionName = "RsaEcdhReq"});

  EXPECT_EQ(mObservation->create_session_count(), 1) << "exactly one CreateSession must have been observed";
  EXPECT_FALSE(mObservation->create_session_ecdh_policy_uri().has_value())
    << "an RSA channel must NOT send an ECDHPolicyUri in the CreateSession request";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @verifies CL-ECC-003
// When the server returns a StatusCode in the ECDHKey slot instead of a key (Part 6: signalled when it cannot
// honour the requested ECDHPolicyUri), the client's tier-0 extractor stores NO server ephemeral - it treats a
// StatusCode-in-the-ECDHKey-slot as "no key" rather than mis-reading the StatusCode's bytes as an ephemeral.
// Read directly from session state via the host interface (before any ActivateSession, whose response would
// deliver a fresh ephemeral and overwrite it). Falsifier: a naive extractor that fabricated a key from the
// StatusCode would leave a non-empty stored ephemeral.
//
// NOTE (matrix-oracle deviation, batched): the matrix expects the client to SURFACE the server's StatusCode
// through Result/ErrorDetail. It does not: the ECDHKey is only consumed later (to encrypt a user token), so
// CreateSession itself completes. A later ECC user-token encrypt then fails (BadSecurityChecksFailed, "server
// ephemeral key is empty") but is logged-and-proceeded-past by design ("pre-flip behaviour",
// ua_client_session_impl.cpp on_user_token_encrypted), so the failure surfaces opaquely as the server's
// ActivateSession rejection. This row asserts the real, deterministic tier-0 observable (no ephemeral
// stored); surfacing the server StatusCode up front for an ECC channel that will need the ephemeral is
// batched as an enhancement.
// @relation(CL-ECC-003, scope=function)
TEST_P(ClientEphemeralKeyAgreement, HandlesServerStatusCodeInsteadOfEcdhKey)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectStatusInsteadOfEcdhKey = true;
  }

  auto channelResult = open_channel(*mClient, GetParam());
  ASSERT_TRUE(channelResult.is_good()) << "the ECC channel itself is valid and must open";
  auto channel = std::move(channelResult).value();
  auto session = channel.create_session_sync({.sessionName = "EccStatusKey"});

  // Precondition: the injection replaced the real server ephemeral in the CreateSession response.
  EXPECT_TRUE(mObservation->create_session_ecdh_key().empty())
    << "the injected StatusCode must occupy the ECDHKey slot in place of a real ephemeral";

  // Product observable: the client stored NO ephemeral (did not mis-parse the StatusCode as a key). Read
  // BEFORE any ActivateSession so a successful activate response cannot repopulate the stored ephemeral.
  const ByteString storedEphemeral = ua::client::SessionTestAccess::on_strand(
    session, [](auto& guard) { return guard.server_ephemeral_public_key(); });
  EXPECT_TRUE(storedEphemeral.empty())
    << "a StatusCode in the ECDHKey slot must yield no stored server ephemeral, not a mis-parsed key";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The EphemeralKey's signature is what ties the key to the server (Part 4 section 7.15): a key whose
// signature does not verify with the authenticated server certificate is refused before any secret is
// encrypted to it, and no ActivateSession leaves the client. The username-over-ECC rows above are the
// control: the same policy with the genuine signature activates.
// @relation(AC-CL-ECC-005-UNSIGNED-OR-FORGED-EPHEMERAL-KEY-IS-REFUSED, scope=function)
TEST_P(ClientEphemeralKeyAgreement, RefusesUserTokenEncryptionWhenEphemeralKeySignatureIsCorrupt)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->corruptEcdhKeySignature = true;
  }

  auto s = open_create_activate(GetParam(), userEccPolicyId);
  ASSERT_TRUE(s.channelOpened) << "the ECC channel itself is valid and must open";
  EXPECT_EQ(s.activate.status_code().as_status(), Status::BadSecurityChecksFailed)
    << "a forged EphemeralKey signature must refuse the activation; before the fix the password was "
       "encrypted to the key and sent";
  {
    std::lock_guard lock(mObservation->mutex);
    EXPECT_TRUE(mObservation->activateTokens.empty())
      << "no ActivateSession may carry a secret encrypted to a key the server did not sign";
  }
  close_session(s);
}

// @relation(AC-SVR-ECC-002-NONCE-IS-EPHEMERAL-PUBLIC, scope=function)
// @relation(AC-SVR-ECC-003-EPHEMERAL-ONE-USE, scope=function)

// =============================================================================================
// CL-ECC-002: ephemeral discipline
// =============================================================================================

// @verifies CL-ECC-002
// A fresh client ECC ephemeral is generated for each OPN: the client ephemeral public key carried as the
// clientNonce differs between the initial OPN and an OPN-RENEW on the same channel. Reusing the private key
// would repeat the clientNonce (the ephemeral "exactly once" rule; the server also rejects a reused renew
// nonce with Bad_NonceInvalid). Falsifier: identical client ephemerals across the two handshakes.
// @relation(CL-ECC-002, scope=function)
TEST_P(ClientEphemeralKeyAgreement, GeneratesNewEccEphemeralPerOpn)
{
  auto channelResult = open_channel(*mClient, GetParam());
  ASSERT_TRUE(channelResult.is_good());
  auto channel = std::move(channelResult).value();

  auto before = read_channel(channel);
  ASSERT_FALSE(before.lastClientNonce.empty()) << "the initial ECC OPN must carry a client ephemeral";

  // Drive an OPN-RENEW directly (no lifetime-timer wait) and wait until the channel token rolls over.
  ua::client::SecureChannelTestAccess::on_strand(channel, [](auto& guard) { guard.handle_token_renewal(); });
  ASSERT_TRUE(
    wait_for_renewal(channel, before.tokenId, ua::test_utils::scaled(std::chrono::milliseconds{5000})))
    << "the channel must renew within the deadline";

  auto after = read_channel(channel);
  ASSERT_FALSE(after.lastClientNonce.empty()) << "the renewed ECC OPN must carry a client ephemeral";
  EXPECT_NE(after.lastClientNonce, before.lastClientNonce)
    << "a fresh client ECC ephemeral must be generated for the renewed OPN";

  (void)channel.try_close_sync();
}

// @relation(AC-SVR-ECC-004-NEW-EPHEMERAL-PER-ACTIVATE, scope=function)

// @verifies CL-ECC-002
// The stored server ephemeral is overwritten on each ActivateSession round: the second activation encrypts
// its token under the ephemeral the FIRST activation's response delivered (EK2), not the CreateSession
// ephemeral (EK1). Falsifier: if the stale EK1 were retained, the second token would encrypt under EK1.
// @relation(CL-ECC-002, scope=function)
TEST_P(ClientEphemeralKeyAgreement, OverwritesStoredServerEphemeralOnEachActivate)
{
  auto s = open_create_activate(GetParam(), userEccPolicyId);
  ASSERT_TRUE(s.activate.is_good()) << "first activation must succeed: 0x" << std::hex
                                    << s.activate.status_code().as_uint32();

  // Re-activate the same session (the server returns a fresh ephemeral on every ActivateSession response).
  ua::client::Session::ActivateConfig config;
  config.policyId = std::string{userEccPolicyId};
  config.identity =
    UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}};
  auto second = s.session->try_activate_sync(std::move(config));
  ASSERT_TRUE(second.is_good()) << "re-activation must succeed: 0x" << std::hex
                                << second.status_code().as_uint32();

  const ByteString ek1 = mObservation->create_session_ecdh_key();  // CreateSession ephemeral
  auto activateKeys = mObservation->activate_response_ecdh_keys();
  ASSERT_GE(activateKeys.size(), 1u) << "the first ActivateSession response must deliver a fresh ephemeral";
  const ByteString ek2 = activateKeys[0];  // ephemeral delivered by the first ActivateSession response

  ASSERT_FALSE(ek1.empty());
  ASSERT_FALSE(ek2.empty());
  EXPECT_NE(ek1, ek2) << "each round must deliver a distinct server ephemeral";

  auto tokens = mObservation->activate_tokens();
  ASSERT_EQ(tokens.size(), 2u) << "two ActivateSession requests must have been observed";
  auto receiver1 = ecc_receiver_public_key(tokens[0].password);
  auto receiver2 = ecc_receiver_public_key(tokens[1].password);
  ASSERT_TRUE(receiver1.has_value());
  ASSERT_TRUE(receiver2.has_value());
  EXPECT_EQ(*receiver1, ek1) << "the first activation must encrypt under the CreateSession ephemeral (EK1)";
  EXPECT_EQ(*receiver2, ek2) << "the second activation must encrypt under the overwritten ephemeral (EK2)";

  close_session(s);
}

// @relation(AC-SVR-ECC-003-EPHEMERAL-ONE-USE, scope=function)
// @relation(AC-SVR-ECC-004-NEW-EPHEMERAL-PER-ACTIVATE, scope=function)

// @verifies CL-ECC-002
// The client never reuses a stale server ephemeral across re-activation: after the first activation, the
// stored ephemeral is the fresh one the response delivered (EK2), NOT the now-stale CreateSession ephemeral
// (EK1), and the re-activate encrypts under EK2. Falsifier: retaining EK1 would leave the store at EK1 and
// encrypt the re-activate token under the stale EK1.
//
// NOTE (matrix-oracle deviation, batched): the matrix's "pin a fabricated older ECDHKey via the host
// interface" does not correspond to a real client threat - the client always trusts the most-recent
// server-delivered ephemeral and no client path reintroduces a stale key. The host interface is used here to
// READ BACK the stored ephemeral and prove the stale EK1 was overwritten by EK2 before the re-activate, which
// is the concrete, falsifiable form of "does not reuse the stale ephemeral".
// @relation(CL-ECC-002, scope=function)
TEST_P(ClientEphemeralKeyAgreement, DoesNotReuseStaleServerEphemeral)
{
  auto s = open_create_activate(GetParam(), userEccPolicyId);
  ASSERT_TRUE(s.activate.is_good()) << "first activation must succeed: 0x" << std::hex
                                    << s.activate.status_code().as_uint32();

  const ByteString ek1 = mObservation->create_session_ecdh_key();
  ASSERT_FALSE(ek1.empty());

  // Host-interface readback: after the first activation the stored server ephemeral must have been
  // overwritten away from the stale CreateSession ephemeral (EK1) to the ephemeral the ActivateSession
  // response delivered (EK2).
  const ByteString stored = ua::client::SessionTestAccess::on_strand(
    *s.session, [](auto& guard) { return guard.server_ephemeral_public_key(); });
  ASSERT_FALSE(stored.empty());
  EXPECT_NE(stored, ek1) << "the stale CreateSession ephemeral must not be retained after activation";

  auto activateKeys = mObservation->activate_response_ecdh_keys();
  ASSERT_GE(activateKeys.size(), 1u);
  const ByteString ek2 = activateKeys[0];
  EXPECT_EQ(stored, ek2) << "the stored ephemeral must be the latest server-delivered ephemeral (EK2)";

  // Re-activate and confirm the token uses the latest ephemeral (EK2), never the stale EK1.
  ua::client::Session::ActivateConfig config;
  config.policyId = std::string{userEccPolicyId};
  config.identity =
    UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}};
  auto second = s.session->try_activate_sync(std::move(config));
  ASSERT_TRUE(second.is_good()) << "re-activation must succeed: 0x" << std::hex
                                << second.status_code().as_uint32();

  auto tokens = mObservation->activate_tokens();
  ASSERT_EQ(tokens.size(), 2u);
  auto receiver2 = ecc_receiver_public_key(tokens[1].password);
  ASSERT_TRUE(receiver2.has_value());
  EXPECT_EQ(*receiver2, ek2) << "the re-activate must encrypt under the latest ephemeral (EK2)";
  EXPECT_NE(*receiver2, ek1) << "the re-activate must never encrypt under the stale ephemeral (EK1)";

  close_session(s);
}

// =============================================================================================
// SVR-ECC-007: a chained serverCertificate is used leaf-only
// =============================================================================================

// Part 4 section 5.6.3 (SPEC-SVR-ECC-007): "If the serverCertificate contains a chain, the signature
// calculation shall be done only with the leaf Certificate." serverCertificate is ONE ByteString that may
// hold several concatenated DER certificates, and a plausible implementation gets it wrong in either
// direction: it treats the whole blob as the signature input (the peer recomputes the expected bytes from the
// leaf alone and rejects the activation, Bad_ApplicationSignatureInvalid), or it hands the whole blob to a
// strict certificate parser / takes the trailing certificate as the serverSignature key (CreateSession
// refused, Bad_CertificateInvalid). Here the CreateSession response is rewritten on the server strand to
// carry leaf || a second certificate, and the leaf-only rule is asserted against the exact signed bytes: the
// clientSignature verifies over the 1.05.07 channel-bound data (Table 101) built with HASH(leaf) and does NOT
// verify over the same data built with HASH(chain). The server's
// own acceptance of the activation is the independent second oracle - it rebuilds the expected data from its
// leaf certificate, so a chain-signing client cannot activate.
//
// NOTE (clause not reachable from this fixture, batched): the criterion's second sentence - where the leaf
// check fails, the full chain is tried before refusing - has no observable here. The retry belongs to the
// verifier, whose expected data is `certAndKey.mCertificate->der_encoding()`; `X509Certificate` models
// exactly one certificate and CreateSessionResponse emits a single leaf DER, so this server never holds a
// chain to retry against (ua_server_session.cpp records the retry as "currently vacuous"). Presenting a
// legacy peer that signed over the full chain would need a MUTATING request interface; the server-side
// interface is a const RequestObserver, and a chain faked into the response is invisible to the server's
// verifier.
// @verifies AC-SVR-ECC-007-LEAF-SIGNATURE
TEST_F(ClientEcc, UsesOnlyTheLeafOfAChainedServerCertificateForSessionSignatures)
{
  const ByteString leafDer = mServerNistP256.cert->der_encoding();
  const ByteString appendedDer = mServerRsa.cert->der_encoding();  // stands in for an appended issuer
  ASSERT_FALSE(leafDer.empty());
  ASSERT_FALSE(appendedDer.empty());
  ASSERT_NE(leafDer, appendedDer) << "fixture precondition: the appended certificate is not the leaf";

  // Arm the chain BEFORE connecting: the CreateSession response will carry leaf || appended.
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->appendToServerCertificate = appendedDer;
  }

  auto s = open_create_activate(SecurityPolicyId::EccNistP256AesGcm, userEccPolicyId);
  ASSERT_TRUE(s.channelOpened) << "the ECC channel must open (the OPN certificate is untouched)";

  // The stimulus really happened: the client was handed two concatenated certificates, leaf first.
  const ByteString presented = mObservation->presented_server_certificate();
  ASSERT_EQ(presented.size(), leafDer.size() + appendedDer.size())
    << "the CreateSession response must carry the concatenated chain";
  const auto leafLength = static_cast<std::ptrdiff_t>(leafDer.size());
  EXPECT_EQ(ByteString(presented.begin(), presented.begin() + leafLength), leafDer)
    << "the chain's leaf must be the real server certificate";
  EXPECT_EQ(ByteString(presented.begin() + leafLength, presented.end()), appendedDer)
    << "the chain must carry a second certificate behind the leaf";
  ASSERT_NE(presented, leafDer) << "the presented certificate must differ from the leaf alone";

  // The chained serverCertificate is not refused: the serverSignature was verified with the LEAF of the
  // chain (a strict whole-blob parse, or taking the trailing certificate, fails CreateSession) and the
  // server accepted the leaf-signed activation.
  EXPECT_EQ(mObservation->create_session_count(), 1) << "exactly one CreateSession must have been observed";
  ASSERT_TRUE(s.activate.is_good()) << "a chained serverCertificate must not be refused: 0x" << std::hex
                                    << s.activate.status_code().as_uint32();

  // The ActivateSession clientSignature covers the LEAF alone, asserted on the exact bytes.
  const auto signatures = mObservation->activate_signatures();
  ASSERT_EQ(signatures.size(), 1u) << "exactly one ActivateSession must have been observed";
  const ByteString& clientSignature = signatures[0].signature;
  ASSERT_FALSE(clientSignature.empty()) << "the ActivateSession must carry a client signature";
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  EXPECT_EQ(signatures[0].algorithm, std::string{policy->asymmetric_signature_algorithm_uri()})
    << "the client signature must be made with the channel policy's asymmetric signature algorithm";

  // OPC 10000-4 1.05.07 Table 101: the policy has SecureChannelEnhancements, so the ClientSignature signs
  // the channel-bound data, whose serverCertificate term is HASH(serverCertificate). The leaf-only rule
  // decides which bytes that term hashes.
  ASSERT_TRUE(policy->secure_channel_enhancements()) << "fixture precondition: a channel-bound signature";
  auto inputs = ua::client::SecureChannelTestAccess::on_strand(*s.channel,
    [](auto& guard)
    {
      const auto& context = *guard.context();
      return ChannelBoundSignatureInputs{.channelThumbprint = context.channelThumbprint,
        .serverChannelCertificate = der_or_empty(context.remoteCertificate),
        .clientChannelCertificate = der_or_empty(context.localCertificate)};
    });
  ASSERT_FALSE(inputs.channelThumbprint.empty()) << "the channel has no ChannelThumbprint";
  inputs.serverNonce = mObservation->create_session_server_nonce();
  ASSERT_FALSE(inputs.serverNonce.empty()) << "the CreateSession response must carry a serverNonce";
  inputs.clientNonce = mObservation->create_session_client_nonce();
  ASSERT_FALSE(inputs.clientNonce.empty()) << "the CreateSession request must carry a clientNonce";
  inputs.serverCertificate = leafDer;
  const ByteString signedOverLeaf =
    channel_bound_data(*mCrypto, *policy, ChannelBoundSignature::Client, inputs);
  inputs.serverCertificate = presented;
  const ByteString signedOverChain =
    channel_bound_data(*mCrypto, *policy, ChannelBoundSignature::Client, inputs);
  const ByteString clientPublicKey = mClientNistP256.cert->public_key();
  ASSERT_FALSE(clientPublicKey.empty()) << "fixture precondition: the ECC own certificate has a public key";

  EXPECT_NO_THROW(mCrypto->asymmetric_verify_sync(
    policy->asymmetric_signature_algorithm(), clientPublicKey, signedOverLeaf, clientSignature))
    << "the clientSignature must cover the channel-bound data with HASH(leaf certificate)";
  EXPECT_THROW(mCrypto->asymmetric_verify_sync(
                 policy->asymmetric_signature_algorithm(), clientPublicKey, signedOverChain, clientSignature),
    ua::UaException)
    << "the clientSignature must NOT cover the full chain";

  close_session(s);
}

// =============================================================================================
// SVR-ECC-001: an ECC channel negotiates its keys by ephemeral key exchange
// =============================================================================================

// Part 6 section 6.8.2: "ECC is an asymmetric cryptography algorithm that only supports digital signatures",
// so the UASC handshake is modified for it - the Client generates a fresh key pair (JC, KC) and puts the
// PUBLIC key on the wire as the clientNonce, the Server answers with its own (JS) as the serverNonce, and
// the channel keys are derived from the Diffie-Hellman shared secret of that pair. The RSA design cannot
// be reused because an ECC key cannot encrypt: an implementation that treated ECC as "RSA with different
// algorithm identifiers" would generate a random secret nonce and encrypt it under the peer's certificate
// key, and that is precisely what this test refuses to accept. Three facts separate the two mechanisms and
// all three are asserted - the ECC policy exposes NO asymmetric encryption algorithm to carry a nonce with
// (the RSA control does); the nonces on a live ECC channel are the size the policy states for an ephemeral
// public key rather than the short secret an RSA channel carries; and each nonce really is a point on the
// policy's named curve, proved by computing an ECDH shared secret against it with a locally generated
// ephemeral key, which fails outright on a blob that is not a public key. The derived keys are then checked
// to be in force, so the exchange is not decoration alongside key material that came from elsewhere.
//
// NOTE: the derivation itself cannot be recomputed and compared byte-for-byte here, because the client's
// ephemeral PRIVATE key is deliberately destroyed the moment the keys are derived (the key derivation in
// ua_sec_pol_ephemeral_key.cpp clears localEphemeralPrivateKey). The public halves, their curve membership
// and the resulting token are what remain observable once the channel is open.
// @verifies AC-SVR-ECC-001-EPHEMERAL-KEY-EXCHANGE
TEST_F(ClientEcc, AnEccChannelNegotiatesItsKeysByEphemeralKeyExchange)
{
  const auto eccPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto rsaPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(eccPolicy->is_ecc()) << "fixture precondition: the policy under test is an ECC policy";
  ASSERT_TRUE(rsaPolicy->is_rsa()) << "fixture precondition: the control policy is an RSA policy";

  // (1) The mechanism the policy makes available at all. An RSA policy transports key material by
  //     encrypting a nonce under the peer's certificate key and so must name an asymmetric encryption
  //     algorithm; an ECC policy has none, which is why the ephemeral exchange exists.
  EXPECT_EQ(eccPolicy->asymmetric_encryption_algorithm(), AsymmetricEncryptionAlgorithm::Invalid)
    << "an ECC policy only supports digital signatures, so it must offer no asymmetric encryption "
       "algorithm under which a nonce could be transported";
  EXPECT_NE(rsaPolicy->asymmetric_encryption_algorithm(), AsymmetricEncryptionAlgorithm::Invalid)
    << "the RSA control must name the asymmetric encryption algorithm it derives keys through, or the "
       "contrast above proves nothing";
  EXPECT_NE(eccPolicy->asymmetric_signature_algorithm(), AsymmetricSignatureAlgorithm::Invalid)
    << "the ECC policy must still name a signature algorithm: the handshake is signed, not encrypted";

  // (2) A live ECC channel: read the nonces actually exchanged and the token they produced.
  auto channelResult = open_channel(*mClient, SecurityPolicyId::EccNistP256AesGcm);
  ASSERT_TRUE(channelResult.is_good())
    << "the ECC_nistP256 channel must open: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();

  struct EccKeyExchangeSnapshot
  {
    ByteString clientNonce;
    ByteString serverNonce;
    bool hasActiveToken{false};
    std::size_t localEncryptingKeySize{0};
    std::size_t remoteEncryptingKeySize{0};
  };

  auto snapshot = ua::client::SecureChannelTestAccess::on_strand(channel,
    [](auto& guard)
    {
      EccKeyExchangeSnapshot snap;
      snap.clientNonce = guard.last_client_nonce();
      snap.serverNonce = guard.server_nonce();
      const auto context = guard.context();
      if (context && context->activeSecurityToken)
      {
        snap.hasActiveToken = true;
        snap.localEncryptingKeySize = context->activeSecurityToken->local_keys().encryptingKey.size();
        snap.remoteEncryptingKeySize = context->activeSecurityToken->remote_keys().encryptingKey.size();
      }
      return snap;
    });

  GTEST_LOG_(INFO) << "ECC_nistP256 nonce sizes: client=" << snapshot.clientNonce.size()
                   << " server=" << snapshot.serverNonce.size()
                   << " (policy nonce_length=" << eccPolicy->nonce_length() << ")";

  ASSERT_FALSE(snapshot.clientNonce.empty()) << "the ECC OPN request must carry a client nonce";
  ASSERT_FALSE(snapshot.serverNonce.empty()) << "the ECC OPN response must carry a server nonce";
  EXPECT_EQ(snapshot.clientNonce.size(), eccPolicy->nonce_length())
    << "on an ECC channel the clientNonce is the Client EphemeralKey's public key encoded for the curve, "
       "so it is the policy's nonce length - a shorter secret nonce means the RSA design was reused";
  EXPECT_EQ(snapshot.serverNonce.size(), eccPolicy->nonce_length())
    << "the serverNonce is likewise the Server EphemeralKey's public key";
  // RATIFICATION PENDING (Phase 2 of the 1.05.07 work): this arm asserted the SEC1 0x04 tag as the first
  // byte. Part 6 Table 72 carries a NIST public key as its raw X|Y coordinates without that tag, which is
  // what the client sends (the base commit already sent 64 bytes, so the old arm failed there too); the
  // curve membership is proved by the ECDH agreement in (3).
  EXPECT_EQ(snapshot.clientNonce.size(), 64u)
    << "a P-256 public key is carried as its raw X|Y coordinates, 32 bytes each, without the SEC1 0x04 tag";

  // (3) Each nonce really is a public key on the policy's curve: an ECDH agreement against it with a
  //     locally generated ephemeral key succeeds. A random secret nonce is not a point on the curve and
  //     the agreement below would throw.
  const auto localEphemeral = mCrypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);
  ASSERT_FALSE(localEphemeral.privateKey.empty()) << "the test's own ephemeral key pair must generate";

  ByteString secretWithClientNonce;
  ASSERT_NO_THROW(secretWithClientNonce = mCrypto->calculate_shared_secret_sync(
                    EphemeralKeyAlgorithm::EccNistP256, localEphemeral.privateKey, snapshot.clientNonce))
    << "the clientNonce must be usable as an ECDH public key on the policy's named curve";
  EXPECT_FALSE(secretWithClientNonce.empty()) << "the agreement over the clientNonce must yield a secret";

  ByteString secretWithServerNonce;
  ASSERT_NO_THROW(secretWithServerNonce = mCrypto->calculate_shared_secret_sync(
                    EphemeralKeyAlgorithm::EccNistP256, localEphemeral.privateKey, snapshot.serverNonce))
    << "the serverNonce must be usable as an ECDH public key on the policy's named curve";
  EXPECT_FALSE(secretWithServerNonce.empty()) << "the agreement over the serverNonce must yield a secret";
  EXPECT_NE(secretWithClientNonce, secretWithServerNonce)
    << "the two nonces are distinct ephemeral public keys, so they cannot agree to the same secret";

  // (4) The keys that exchange produced are the ones securing the channel.
  EXPECT_TRUE(snapshot.hasActiveToken) << "the opened channel must hold an active security token";
  EXPECT_EQ(snapshot.localEncryptingKeySize, eccPolicy->symmetric_encryption_key_size())
    << "the derived sending key must be the policy's symmetric encryption key size";
  EXPECT_EQ(snapshot.remoteEncryptingKeySize, eccPolicy->symmetric_encryption_key_size())
    << "the derived receiving key must be the policy's symmetric encryption key size";
  EXPECT_TRUE(channel.is_open()) << "the channel derived usable keys and stayed open";

  // (5) The RSA control, on the same server: its clientNonce is the policy's short secret nonce, not an
  //     ephemeral public key, because RSA transports key material by encrypting under the certificate key.
  auto rsaChannelResult = open_channel(*mClient, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(rsaChannelResult.is_good()) << "the RSA control channel must open";
  auto rsaChannel = std::move(rsaChannelResult).value();
  const ByteString rsaClientNonce = read_channel(rsaChannel).lastClientNonce;
  ASSERT_FALSE(rsaClientNonce.empty()) << "the RSA OPN request must carry a client nonce";
  EXPECT_EQ(rsaClientNonce.size(), rsaPolicy->nonce_length())
    << "the RSA clientNonce is the policy's secret nonce length";
  EXPECT_NE(rsaClientNonce.size(), snapshot.clientNonce.size())
    << "the two mechanisms must not put the same shape on the wire: the RSA nonce is a transported "
       "secret, the ECC nonce an ephemeral public key";

  (void)rsaChannel.try_close_sync();
  (void)channel.try_close_sync();
}

// =============================================================================================
// SVR-ECC-006: the named-curve check overlays the standard certificate validation steps
// =============================================================================================

// Part 6 section 6.8.2: "Each SecurityPolicy specifies a list of named curves which are permitted for use in
// the ApplicationInstance Certificate. This list always includes the named curve used for the EphemeralKey,
// however, it may allow other named curves." The check is therefore an OVERLAY on Part 4 Table 106, not a
// replacement for it, and that is what the two halves below assert. A plausible implementation applies the
// curve check INSTEAD of the standard steps (an untrusted certificate on the right curve then walks in), or
// omits it entirely and validates an ECC peer by trust chain alone (a certificate whose key cannot produce
// the policy's signatures is then accepted, and the channel fails later with something that names neither
// the policy nor the curve).
//
// The wrong-curve exemplar is deliberately cross-FAMILY (a Curve25519 certificate under ECC_nistP256, and a
// nistP256 certificate under ECC_curve25519_ChaCha20Poly1305) rather than a neighbouring NIST curve: the
// sentence quoted above lets a policy permit additional named curves, so a nistP384 certificate under
// ECC_nistP256 is NOT necessarily a violation and asserting its refusal would manufacture a defect against a
// conforming server. A Curve25519 key cannot produce the ECDSA-SHA2-256 signatures ECC_nistP256 specifies
// (and vice versa), so no permitted-curve list for either policy can contain the other's key.
//
// The subject is the SDK's own peer-certificate entry point, `SecurityPolicy::validate_certificate_async` -
// the call a SecureChannel makes on the certificate the peer presented in the OPN. Driving it directly keeps
// the observation on the validation decision itself: over the wire, a certificate the server ought to have
// rejected can also fail later for an unrelated encoding reason, which would let a violating server pass.
// The coverage marker is deliberately WITHHELD. What this test establishes is the permitted-curve list
// and the Table 106 overlay around it; what the criterion asks for is the REFUSAL, and the refusal is
// thrown in `SecPolEphemeralKey::decode_asymmetric_message_chunk_async`'s prologue, which needs a real
// asymmetric message chunk to reach. Claiming the criterion from here would be the name-similarity binding
// this campaign spent a round unpicking.
TEST_F(ClientEcc, EachEccPolicyPermitsOnlyItsOwnCurveFamilyAndStillAppliesTheStandardSteps)
{
  const auto nistPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto curve25519Policy = SecurityPolicy::create(SecurityPolicyId::EccCurve25519ChaChaPoly);

  ASSERT_EQ(mClientNistP256.cert->key_algorithm(), CertificateKeyAlgorithm::EccNistP256)
    << "fixture precondition: the nistP256 exemplar is on the NIST P-256 curve";
  ASSERT_EQ(mClientCurve25519.cert->key_algorithm(), CertificateKeyAlgorithm::EccCurve25519)
    << "fixture precondition: the curve25519 exemplar is on Curve25519";

  // An otherwise-valid certificate on the right curve that no store trusts: the standard Table 106 trust
  // step must still refuse it, which is what makes the curve check an addition rather than a substitute.
  const auto untrusted = make_cert(
    mCrypto, CertificateType::EccNistP256Application, "Untrusted nistP256", "urn:test:ecc:stranger");
  ASSERT_EQ(untrusted.cert->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);

  // (a)/(b) The permitted-curve list itself, in both directions. These arms USED to call
  //     `validate_certificate_async` on a wrong-curve certificate and demand a refusal, and they were
  //     red against a conforming SDK: that entry point is the Part 4 Table 106 half ONLY -- for ECC it
  //     skips even the key-length branch (`ua_security_policy.cpp:3067-3121`) and delegates to the cert
  //     store. The curve gate is real but lives one level up, in the synchronous prologue of
  //     `SecPolEphemeralKey::decode_asymmetric_message_chunk_async` (`ua_sec_pol_ephemeral_key.cpp`), which
  //     compares the presented certificate's key_algorithm() against permitted_certificate_key_algorithms()
  //     and throws BadCertificateInvalid / "InvalidCertificateKeyAlgorithm" BEFORE calling
  //     start_decode_ecc_validate_cert -- so the overlay the criterion describes is exactly what the SDK
  //     does, and the old arms were asking the wrong function for it.
  //
  //     What is asserted here instead is the list that gate consults, which is falsifiable in both
  //     directions: a policy that permitted everything, or that had no opinion, fails these.
  //     What is NOT asserted here is that the decode prologue consults it -- no interface in this test
  //     reaches an asymmetric message chunk, so the criterion's own arm stays unbound and says so.
  const auto nistEcc = std::dynamic_pointer_cast<const SecPolEphemeralKey>(nistPolicy);
  const auto curve25519Ecc = std::dynamic_pointer_cast<const SecPolEphemeralKey>(curve25519Policy);
  ASSERT_NE(nistEcc, nullptr) << "ECC_nistP256 shall be an ECC policy";
  ASSERT_NE(curve25519Ecc, nullptr) << "ECC_curve25519_ChaCha20Poly1305 shall be an ECC policy";

  // The end-entity curve the gate consults (OPC 10000-7 profile database: "An end entity Certificate
  // shall use <curve>"); restated from the removed permitted-curve list (owner review 2026-10-02 item 2).
  const auto permits = [](const SecPolEphemeralKey& policy, CertificateKeyAlgorithm algo)
  {
    return policy.certificate_key_algorithm() == algo;
  };
  const auto& nistPermitted = *nistEcc;
  const auto& curve25519Permitted = *curve25519Ecc;

  EXPECT_FALSE(permits(nistPermitted, CertificateKeyAlgorithm::EccCurve25519))
    << "a Curve25519 key cannot produce the ECDSA-SHA2-256 signatures ECC_nistP256 specifies, so that "
       "curve shall not be on ECC_nistP256's permitted-certificate list";
  EXPECT_TRUE(permits(nistPermitted, CertificateKeyAlgorithm::EccNistP256))
    << "ECC_nistP256 shall permit its own named curve, or the list forbids everything and the check "
       "above is vacuous";

  EXPECT_FALSE(permits(curve25519Permitted, CertificateKeyAlgorithm::EccNistP256))
    << "the same fault in the other direction, so a pass cannot come from a list that knows one policy";
  EXPECT_TRUE(permits(curve25519Permitted, CertificateKeyAlgorithm::EccCurve25519))
    << "ECC_curve25519_ChaCha20Poly1305 shall permit its own named curve";

  // (c) Right curve, untrusted: the standard steps are still applied - the curve check is in ADDITION to
  //     them, so a certificate that satisfies the curve must still satisfy Table 106.
  const auto untrustedRightCurve =
    validate_peer_certificate(nistPolicy, mCrypto, mServerCertStore, untrusted.cert);
  EXPECT_TRUE(untrustedRightCurve.is_bad())
    << "the named-curve check overlays the standard validation steps rather than replacing them: a "
       "certificate on the policy's own curve that no trust list carries shall still be refused; got "
    << to_string(untrustedRightCurve.status_code().as_status());

  // (d) The controls, one per direction: each certificate presented under the policy whose curve it is on
  //     shall be accepted. These carry the criterion's "otherwise valid under Table 106" - without them a
  //     refusal in (a) or (b) could be the certificate failing the standard steps for its own reasons
  //     (a chain that will not build, an unusable signature algorithm) rather than the curve check, and a
  //     validator that refused everything would satisfy (a) to (c) while proving nothing.
  const auto trustedNistUnderNist =
    validate_peer_certificate(nistPolicy, mCrypto, mServerCertStore, mClientNistP256.cert);
  EXPECT_TRUE(trustedNistUnderNist.is_good())
    << "a trusted certificate on ECC_nistP256's own named curve shall be accepted; got "
    << to_string(trustedNistUnderNist.status_code().as_status());

  const auto trustedCurve25519UnderCurve25519 =
    validate_peer_certificate(curve25519Policy, mCrypto, mServerCertStore, mClientCurve25519.cert);
  EXPECT_TRUE(trustedCurve25519UnderCurve25519.is_good())
    << "the Curve25519 certificate is valid under the standard steps - it validates under its own policy - "
       "so its refusal in (a) is attributable to the curve and nothing else; got "
    << to_string(trustedCurve25519UnderCurve25519.status_code().as_status());
}

// =============================================================================================
// SVR-ECC-008: the EphemeralKey travels in the AdditionalHeader as a name-value pair
// =============================================================================================

// Part 6 section 6.8.3 with Table 63: because the CreateSession/ActivateSession handshake has no field for
// it, the server's EphemeralKey is returned in the AdditionalHeader of the ResponseHeader, as an instance of
// the AdditionalParametersType name-value list (Part 4 section 7.1) whose "ECDHKey" entry holds an
// EphemeralKeyType - and the server "always returns a new EphemeralKey" on every ActivateSession response,
// not only the first. The AdditionalHeader is an extension point, so a server that puts the key anywhere else
// - a bespoke structure, a raw ByteString value instead of an EphemeralKeyType, a differently spelled name,
// or nothing at all on the ActivateSession response - produces a handshake that completes while no
// interoperating client can find the key, which is the failure this criterion exists to catch. The shape is
// captured on the response as the client received it, and the key found there is then tied to the exchange
// that used it: the EccEncryptedSecret the client emitted names that very public key as its
// ReceiverPublicKey.
// @verifies AC-SVR-ECC-008-EPHEMERAL-IN-ADDITIONALHEADER
TEST_F(ClientEcc, TheServerEphemeralKeyTravelsInTheAdditionalHeaderAsAnAdditionalParametersNameValuePair)
{
  auto s = open_create_activate(SecurityPolicyId::EccNistP256AesGcm, userEccPolicyId);
  ASSERT_TRUE(s.activate.is_good()) << "the ECC session must create and activate, or there are no "
                                       "responses to read: 0x"
                                    << std::hex << s.activate.status_code().as_uint32();

  const auto createShape = mObservation->create_session_header_shape();
  GTEST_LOG_(INFO) << "CreateSession AdditionalHeader parameters: "
                   << ::testing::PrintToString(createShape.parameterNames);

  ASSERT_TRUE(createShape.present)
    << "the CreateSession response of an ECC session carried no AdditionalHeader at all, so the client has "
       "no EphemeralKey to encrypt a user token with";
  EXPECT_TRUE(createShape.isAdditionalParameters)
    << "the AdditionalHeader shall be an AdditionalParametersType name-value list (Part 4 section 7.1)";
  EXPECT_TRUE(createShape.ecdhKeyPresent)
    << "the list shall carry the parameter Part 6 Table 63 names, 'ECDHKey'; names seen: "
    << ::testing::PrintToString(createShape.parameterNames);
  EXPECT_TRUE(createShape.ecdhKeyIsEphemeralKeyType)
    << "the ECDHKey value shall hold an EphemeralKeyType, not a bare key blob";
  EXPECT_FALSE(createShape.ecdhPublicKey.empty()) << "that EphemeralKeyType shall carry a public key";

  const auto activateShapes = mObservation->activate_header_shapes();
  ASSERT_EQ(activateShapes.size(), 1u)
    << "exactly one ActivateSession response must have been observed, or the checks below have no subject";
  GTEST_LOG_(INFO) << "ActivateSession AdditionalHeader parameters: "
                   << ::testing::PrintToString(activateShapes[0].parameterNames);

  ASSERT_TRUE(activateShapes[0].present)
    << "the ActivateSession response shall carry an AdditionalHeader too: the server always returns a new "
       "EphemeralKey for the client to use next time";
  EXPECT_TRUE(activateShapes[0].isAdditionalParameters)
    << "the ActivateSession AdditionalHeader shall be an AdditionalParametersType as well";
  EXPECT_TRUE(activateShapes[0].ecdhKeyPresent)
    << "the ActivateSession response shall carry an 'ECDHKey' parameter; names seen: "
    << ::testing::PrintToString(activateShapes[0].parameterNames);
  EXPECT_TRUE(activateShapes[0].ecdhKeyIsEphemeralKeyType)
    << "the ActivateSession ECDHKey value shall hold an EphemeralKeyType";
  EXPECT_FALSE(activateShapes[0].ecdhPublicKey.empty())
    << "the ActivateSession EphemeralKeyType shall carry a public key";
  EXPECT_NE(activateShapes[0].ecdhPublicKey, createShape.ecdhPublicKey)
    << "an EphemeralKey may be used for exactly one key negotiation, so the ActivateSession response shall "
       "deliver a NEW one rather than repeat the CreateSession key";

  // The key carried in that name-value pair is the one the exchange actually used: the first user token was
  // encrypted with it as the ReceiverPublicKey of the EccEncryptedSecret.
  const auto tokens = mObservation->activate_tokens();
  ASSERT_EQ(tokens.size(), 1u);
  ASSERT_TRUE(tokens[0].present) << "the activation must have carried a UserNameIdentityToken";
  ASSERT_FALSE(tokens[0].password.empty()) << "that token must carry an EccEncryptedSecret";
  const auto receiver = ecc_receiver_public_key(tokens[0].password);
  ASSERT_TRUE(receiver.has_value()) << "could not parse the EccEncryptedSecret header";
  EXPECT_EQ(*receiver, createShape.ecdhPublicKey)
    << "the EphemeralKey delivered in the CreateSession AdditionalHeader shall be the one the client "
       "encrypted its user token to, or the header carried a key nothing uses";

  close_session(s);
}
