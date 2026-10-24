// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The fourteen SecurityPolicies of OPC UA 1.05.07 end to end: a real server and a real client at the
///        highest public tier (Client::try_connect_sync), each end with a certificate of the family its
///        policy names. All fourteen have SecureChannelEnhancements (OPC 10000-6 6.7.5, 6.8.1).
///
/// TIER: EnhancedSessionActivation moves a Session to a channel of another policy or mode, which only the
/// tier-1 Session can steer (Session::try_activate_sync(SecureChannel)); a move to a channel of the same
/// policy and mode is the Connection's reconnect. A stimulus the SDK client never sends - a ClientSignature
/// or UserTokenSignature over the wrong data - is delivered into the server side of a channel the SDK client
/// opened, through the server's own decoded-request path.

#include "access_control_test_support.h"
#include "certificate_validation_integration_fixture.h"
#include "channel_bound_signature_test_data.h"
#include "misbehaving_server.h"
#include "requests.h"
#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_client_session_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_additional_parameters_type.h"
#include "ua_anonymous_identity_token.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_default_namespace.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_chain.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_security_policy.h"
#include "ua_server_observer.h"
#include "ua_service_fault.h"
#include "ua_session_attribute_services.h"
#include "ua_variable_id.h"
#include "ua_x509_identity_token.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace ua::test_helpers::certificate_validation;
using namespace std::chrono_literals;

namespace
{

/// What a server answered a raw peer whose OpenSecureChannel named a given policy URI.
struct RawOpnAnswer
{
  std::string type;  ///< The answer's message type ("ERR", "OPN", ...), or "" when nothing came.
  std::uint32_t error{};  ///< The ERR's Error field.
  bool closed{};  ///< The server closed the connection after answering.
};

/// HEL, then an OpenSecureChannel naming @p policyUri, from a raw TCP peer (Part 6 7.1.2.3, 6.7.2.3).
/// Hand-rolled because the SDK client refuses a removed URI before it would send one; the server refuses the
/// policy on its URI alone, so the rest of the request is a minimal None-shaped body. Every read is bounded
/// by @p limit.
RawOpnAnswer raw_open_secure_channel(
  const std::string& endpointUrl, std::string_view policyUri, std::chrono::milliseconds limit = 5000ms)
{
  const auto u32 = [](std::vector<std::uint8_t>& out, std::uint32_t value)
  {
    for (int shift = 0; shift < 32; shift += 8)
      out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
  };
  const auto text = [&u32](std::vector<std::uint8_t>& out, std::string_view value)
  {
    u32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
  };
  const auto frame = [&u32](std::string_view type, const std::vector<std::uint8_t>& body)
  {
    std::vector<std::uint8_t> out{type.begin(), type.end()};
    u32(out, static_cast<std::uint32_t>(8 + body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
  };

  std::vector<std::uint8_t> hello;
  for (const std::uint32_t field : {0u, 65536u, 65536u, 16777216u, 0u})
    u32(hello, field);  // version, receive and send buffers, max message size, max chunk count
  text(hello, endpointUrl);

  std::vector<std::uint8_t> open;
  u32(open, 0);  // SecureChannelId
  text(open, policyUri);
  u32(open, 0xFFFFFFFF);  // SenderCertificate: null
  u32(open, 0xFFFFFFFF);  // ReceiverCertificateThumbprint: null
  u32(open, 1);  // SequenceNumber
  u32(open, 1);  // RequestId
  open.insert(open.end(), {0x01, 0x00, 0xBE, 0x01});  // OpenSecureChannelRequest_Encoding_DefaultBinary
  open.insert(open.end(), 30, 0x00);  // a zeroed RequestHeader and request body

  const auto authority = endpointUrl.substr(endpointUrl.find("://") + 3);
  const auto hostPort = authority.substr(0, authority.find('/'));
  const auto colon = hostPort.rfind(':');
  boost::asio::io_context io;
  boost::asio::ip::tcp::socket socket{io};
  boost::asio::connect(socket,
    boost::asio::ip::tcp::resolver{io}.resolve(hostPort.substr(0, colon), hostPort.substr(colon + 1)));
  socket.non_blocking(true);
  const auto deadline = std::chrono::steady_clock::now() + limit;
  // Reads exactly @p size bytes, or fewer when the peer closes or the deadline passes.
  const auto read = [&](std::size_t size)
  {
    std::vector<std::uint8_t> bytes(size);
    std::size_t done = 0;
    while (done < size && std::chrono::steady_clock::now() < deadline)
    {
      boost::system::error_code ec;
      const auto n = socket.read_some(boost::asio::buffer(bytes.data() + done, size - done), ec);
      if (ec == boost::asio::error::would_block)
      {
        std::this_thread::sleep_for(5ms);
        continue;
      }
      if (ec)
        break;
      done += n;
    }
    bytes.resize(done);
    return bytes;
  };
  const auto readMessage = [&]() -> std::pair<std::string, std::vector<std::uint8_t>>
  {
    auto header = read(8);
    if (header.size() < 8)
      return {};
    const auto size = static_cast<std::uint32_t>(header[4]) | (static_cast<std::uint32_t>(header[5]) << 8) |
                      (static_cast<std::uint32_t>(header[6]) << 16) |
                      (static_cast<std::uint32_t>(header[7]) << 24);
    auto body = (size >= 8 && size <= 65536) ? read(size - 8) : std::vector<std::uint8_t>{};
    return {std::string{header.begin(), header.begin() + 3}, std::move(body)};
  };

  boost::asio::write(socket, boost::asio::buffer(frame("HELF", hello)));
  RawOpnAnswer answer;
  if (readMessage().first != "ACK")
    return answer;
  boost::asio::write(socket, boost::asio::buffer(frame("OPNF", open)));
  auto [type, body] = readMessage();
  answer.type = type;
  if (type == "ERR" && body.size() >= 4)
    answer.error = static_cast<std::uint32_t>(body[0]) | (static_cast<std::uint32_t>(body[1]) << 8) |
                   (static_cast<std::uint32_t>(body[2]) << 16) | (static_cast<std::uint32_t>(body[3]) << 24);
  // After its answer the server hangs up: a read then ends at the peer's FIN, not at the deadline.
  std::uint8_t probe = 0;
  while (std::chrono::steady_clock::now() < deadline)
  {
    boost::system::error_code ec;
    socket.read_some(boost::asio::buffer(&probe, 1), ec);
    if (ec == boost::asio::error::would_block)
    {
      std::this_thread::sleep_for(5ms);
      continue;
    }
    answer.closed = static_cast<bool>(ec);
    break;
  }
  return answer;
}

/// The fourteen policies, in the order of OPC 10000-7 Table 49 (profile ids 2324 to 2291).
const std::vector<SecurityPolicyId>& enhanced_policies()
{
  static const std::vector<SecurityPolicyId> policies{SecurityPolicyId::EccNistP256AesGcm,
    SecurityPolicyId::EccNistP256ChaChaPoly,
    SecurityPolicyId::EccNistP384AesGcm,
    SecurityPolicyId::EccNistP384ChaChaPoly,
    SecurityPolicyId::EccBrainpoolP256r1AesGcm,
    SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    SecurityPolicyId::EccBrainpoolP384r1AesGcm,
    SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    SecurityPolicyId::EccCurve25519AesGcm,
    SecurityPolicyId::EccCurve25519ChaChaPoly,
    SecurityPolicyId::EccCurve448AesGcm,
    SecurityPolicyId::EccCurve448ChaChaPoly,
    SecurityPolicyId::RsaDhAesGcm,
    SecurityPolicyId::RsaDhChaChaPoly};
  return policies;
}

std::string enhanced_policy_name(const ::testing::TestParamInfo<SecurityPolicyId>& info)
{
  return policy_name(info.param);
}

/// Counts the token renewals the server reports for channels of one policy, and the renewals that failed.
class RenewalCounter final : public server::ServerObserver
{
public:
  explicit RenewalCounter(std::string policyUri) : mPolicyUri(std::move(policyUri))
  {}

  void on_secure_channel_renewed(const server::SecureChannelEventInfo& info) override
  {
    if (info.securityPolicyUri == mPolicyUri)
      ++mRenewed;
  }

  void on_secure_channel_renew_failed(const server::SecureChannelEventInfo& info, StatusCode) override
  {
    if (info.securityPolicyUri == mPolicyUri)
      ++mFailed;
  }

  int renewed() const
  {
    return mRenewed.load();
  }

  int failed() const
  {
    return mFailed.load();
  }

private:
  std::string mPolicyUri;
  std::atomic<int> mRenewed{0};
  std::atomic<int> mFailed{0};
};

/// Whether the detail chain of @p status names @p code at any depth.
bool chain_names(const StatusCode& status, std::string_view code)
{
  for (const auto& link : ErrorChainView{status})
    if (link.code == code)
      return true;
  return false;
}

/// The SecurityPolicy and SecurityMode of the SecureChannel of every Session activation, as the server
/// reports them.
class ActivationRecorder final : public server::ServerObserver
{
public:
  using ChannelSecurity = std::pair<std::string, MessageSecurityMode>;

  void on_secure_channel_opened(const server::SecureChannelEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    mChannels[info.secureChannelId] = ChannelSecurity{info.securityPolicyUri, info.messageSecurityMode};
  }

  void on_session_activated(const server::SessionEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    const auto channel = mChannels.find(info.secureChannelId);
    mActivations.push_back(channel != mChannels.end() ? channel->second : ChannelSecurity{});
    mSessionChannels.emplace_back(info.sessionId, info.secureChannelId);
  }

  std::vector<ChannelSecurity> activations() const
  {
    const std::lock_guard lock{mMutex};
    return mActivations;
  }

  /// The Session and the SecureChannelId of every activation.
  std::vector<std::pair<NodeId, uint32_t>> session_channels() const
  {
    const std::lock_guard lock{mMutex};
    return mSessionChannels;
  }

private:
  mutable std::mutex mMutex;
  std::map<uint32_t, ChannelSecurity> mChannels;
  std::vector<ChannelSecurity> mActivations;
  std::vector<std::pair<NodeId, uint32_t>> mSessionChannels;
};

/// A server of its own on the parameter's policy (SignAndEncrypt, or Sign and SignAndEncrypt) with the
/// family's valid server certificate, and the cached client of the family. The server is not the matrix
/// cache's: this one gets its own observer.
class EnhancedSecurityPolicies : public ::testing::TestWithParam<SecurityPolicyId>
{
protected:
  void TearDown() override
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    mServer.reset();
    mServerStore.reset();
  }

  /// With @p userNameAuthenticator the endpoint also offers a UserName token policy of the parameter's
  /// policy, which that authenticator decides.
  void start_server(std::shared_ptr<server::ServerObserver> observer,
    MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt,
    std::shared_ptr<server::UserAuthenticator> userNameAuthenticator = nullptr)
  {
    const auto policy = GetParam();
    auto& pki = shared_pki();
    auto& cache = MatrixCache::instance();
    mServerStore = make_store(cache.new_directory("enhanced_server"),
      cache.server_pool().executor(),
      pki.crypto(),
      validation_options_for(CertificateCase::Valid),
      pki.trust_material(family_of(policy)),
      &pki.leaf(policy, CertificateCase::Valid, Role::Server),
      application_certificate_type(policy));
    mServer = std::make_unique<MatrixServer>(cache.server_pool(),
      pki.crypto(),
      MatrixServer::Options{.policy = policy,
        .mode = mode,
        .applicationStore = mServerStore,
        .userTokenStore = nullptr,
        .x509Authenticator = nullptr,
        .auditing = false,
        .userTokenSecurityPolicy = std::nullopt,
        .localDiscoveryServer = false,
        .userNameAuthenticator = std::move(userNameAuthenticator),
        .userNameSecurityPolicy = policy});
    if (observer)
      mServer->server().set_observer(std::move(observer));
    const auto started = mServer->start();
    ASSERT_TRUE(started.is_good()) << ua::format(started.status_code());
  }

  client::Client& client(MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt)
  {
    return *MatrixCache::instance()
              .client_for(GetParam(), mode, validation_options_for(CertificateCase::Valid))
              .client;
  }

  std::shared_ptr<CertificateStore> mServerStore;
  std::unique_ptr<MatrixServer> mServer;
  std::optional<client::Connection> mConnection;
};

/// Whether @p request asks for an EphemeralKey: an ECDHPolicyUri in its RequestHeader AdditionalHeader.
bool asks_for_ephemeral_key(const CreateSessionRequest& request)
{
  const auto* additional =
    dynamic_cast<const AdditionalParametersType*>(request.request_header().additional_header().get());
  return additional && std::ranges::any_of(additional->parameters().payload(),
                         [](const auto& kv) { return std::string_view{kv.key().name()} == "ECDHPolicyUri"; });
}

/// A MisbehavingServer on the parameter's policy (SignAndEncrypt) presenting the family's valid server
/// certificate, and a client of its own trusting the family PKI, whose self-signed certificate the server
/// trusts.
class EnhancedChannelMisbehavingServer : public ::testing::TestWithParam<SecurityPolicyId>
{
protected:
  void TearDown() override
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    mClient.reset();
    mServer.reset();
    mClientStore.reset();
  }

  void start(bool unbindIssueResponse)
  {
    const auto policy = GetParam();
    auto& pki = shared_pki();
    auto& cache = MatrixCache::instance();
    const auto& serverLeaf = pki.leaf(policy, CertificateCase::Valid, Role::Server);
    const auto& clientLeaf = pki.leaf(policy, CertificateCase::Untrusted, Role::Client);
    mServer = std::make_unique<MisbehavingServer>(
      MisbehavingServer::Config{.secureChannelMinimumLifetime = std::chrono::milliseconds{2000},
        .certificateScenario = MisbehavingServer::CertificateScenario{.certificate = serverLeaf.certificate,
          .keys = serverLeaf.keys,
          .issuerCertificates = serverLeaf.presentedIssuers,
          .certificateType = application_certificate_type(policy),
          .securedPolicy = policy,
          .securedMode = MessageSecurityMode::SignAndEncrypt,
          .trustedCertificates = {clientLeaf.certificate},
          .applicationUri = serverUri}});
    if (unbindIssueResponse)
      mServer->sign_issue_response_without_request_signature();
    mClientStore = make_store(cache.new_directory("enhanced_misbehaving_client"),
      cache.client_pool().executor(),
      pki.crypto(),
      validation_options_for(CertificateCase::Valid),
      pki.trust_material(family_of(policy)),
      &clientLeaf,
      application_certificate_type(policy));
    mClient.emplace(make_matrix_client(cache.client_pool(), pki.crypto(), mClientStore));
  }

  /// The fixture advertises 127.0.0.1; the certificates name "localhost" (host-name check, Table 106 step 8).
  static std::string on_localhost(std::string url)
  {
    const auto loopback = url.find("127.0.0.1");
    if (loopback != std::string::npos)
      url.replace(loopback, std::string_view{"127.0.0.1"}.size(), "localhost");
    return url;
  }

  ConnectResult connect()
  {
    auto result = reported(mClient->try_connect_sync(matrix_connection_config(
      on_localhost(mServer->endpoint_url_sign_encrypt()), GetParam(), MessageSecurityMode::SignAndEncrypt)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  /// Client::try_easy_connect_sync to the server, accepting its certificate for this session if asked,
  /// without reconnect. It discovers the endpoints and pins the strongest, the secured endpoint.
  ConnectResult easy_connect()
  {
    client::EasyConnectConfig policy;
    policy.endpointUrl = on_localhost(mServer->endpoint_url_sign_encrypt());
    policy.trustPrompt = [](const X509Certificate& /*certificate*/, StatusCode /*reason*/)
    {
      return client::TrustDecision::AcceptForThisSession;
    };
    policy.customize = [](client::ConnectionConfig& config)
    {
      config.endpointUrl = on_localhost(config.endpointUrl);
      config.reconnect = std::nullopt;
    };
    auto result = reported(mClient->try_easy_connect_sync(std::move(policy)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  /// What the server saw of the CreateSession requests: how many, and how many asked for an EphemeralKey.
  struct CreateSessionRequests
  {
    std::atomic<int> total{0};
    std::atomic<int> askedForEphemeralKey{0};
  };

  /// Makes the server answer as Eclipse Milo 1.2.0-RC1 does when its endpoint offers no UserName policy: a
  /// CreateSession that asks for an EphemeralKey fails with Bad_SecurityPolicyRejected (interoperability
  /// finding 021), where OPC 10000-6 Table 70 puts that StatusCode in the ECDHKey slot of a successful
  /// response. The secured endpoint offers Anonymous only. Returns what the server records of the requests.
  std::shared_ptr<CreateSessionRequests> fault_ephemeral_key_requests()
  {
    auto requests = std::make_shared<CreateSessionRequests>();
    mServer->set_request_observer(
      [requests](const Structure& request)
      {
        if (const auto* create = dynamic_cast<const CreateSessionRequest*>(&request))
        {
          ++requests->total;
          if (asks_for_ephemeral_key(*create))
            ++requests->askedForEphemeralKey;
        }
      });
    mServer->set_response_mutator(
      [requests](Response& response)
      {
        if (auto* created = dynamic_cast<CreateSessionResponse*>(response.second.get());
            created && requests->askedForEphemeralKey.load() > 0)
          created->response_header().service_result() = StatusCode{Status::BadSecurityPolicyRejected};
      });
    return requests;
  }

  std::unique_ptr<MisbehavingServer> mServer;
  std::shared_ptr<CertificateStore> mClientStore;
  std::optional<client::Client> mClient;
  std::optional<client::Connection> mConnection;
};

/// The first request id a test delivers into a server SecureChannel. The SDK client numbers its own requests
/// from 1, so the two never meet within a test.
constexpr uint32_t firstDeliveredRequestId = 0x7C000001u;

/// The ServiceResult of @p response, or Bad_Timeout when none arrived.
StatusCode service_result(const std::shared_ptr<const Structure>& response)
{
  if (!response)
    return StatusCode{Status::BadTimeout};
  if (const auto* fault = dynamic_cast<const ServiceFault*>(response.get()))
    return fault->response_header().service_result();
  if (const auto* created = dynamic_cast<const CreateSessionResponse*>(response.get()))
    return created->response_header().service_result();
  if (const auto* activated = dynamic_cast<const ActivateSessionResponse*>(response.get()))
    return activated->response_header().service_result();
  if (const auto* read = dynamic_cast<const ReadResponse*>(response.get()))
    return read->response_header().service_result();
  return StatusCode{Status::BadUnexpectedError};
}

/// The server side of every SecureChannel a server opens, the signature algorithms its Session requests and
/// responses carry, and the responses to the requests a test delivers into a channel. A delivered request
/// goes through the server's own decoded-request path - as in the certificate continuity test of
/// ComplianceSecureChannel - and carries a stimulus the SDK client never sends. Its response also reaches the
/// client, which ignores a response to a request it did not send.
class ServerChannels
{
public:
  /// Installs the hooks on every SecureChannel @p server opens from now on.
  explicit ServerChannels(server::Server& server) : mState(std::make_shared<State>())
  {
    ServerImplTestAccess(ServerTestAccess::impl(server))
      .set_on_secure_channel_available(
        [weak = std::weak_ptr<State>{mState}](std::shared_ptr<server::SecureChannel> channel)
        {
          auto state = weak.lock();
          if (!state)
            return;
          {
            const std::lock_guard lock{state->mutex};
            state->channels.push_back(channel);
          }
          server::SecureChannelTestAccess::post_on_strand(std::move(channel),
            [weak](auto& guard)
            {
              guard.set_request_observer(
                [weak](uint32_t /*requestId*/, const Structure& request)
                {
                  const auto* activate = dynamic_cast<const ActivateSessionRequest*>(&request);
                  auto state = weak.lock();
                  if (!activate || !state)
                    return;
                  const std::lock_guard lock{state->mutex};
                  state->clientSignatureAlgorithms.emplace_back(activate->client_signature().algorithm());
                });
              guard.set_response_interceptor(
                [weak](Response& response)
                {
                  auto state = weak.lock();
                  if (!state)
                    return;
                  const std::lock_guard lock{state->mutex};
                  if (const auto* created = dynamic_cast<const CreateSessionResponse*>(response.second.get()))
                    state->serverSignatureAlgorithms.emplace_back(created->server_signature().algorithm());
                  if (response.first >= firstDeliveredRequestId)
                    state->responses[response.first] = response.second;
                });
            });
        });
  }

  /// The server side of the SecureChannel @p secureChannelId, or null.
  std::shared_ptr<server::SecureChannel> channel(uint32_t secureChannelId) const
  {
    std::vector<std::shared_ptr<server::SecureChannel>> channels;
    {
      const std::lock_guard lock{mState->mutex};
      channels = mState->channels;
    }
    for (const auto& channel : channels)
    {
      const auto id = server::SecureChannelTestAccess::on_strand(
        *channel, [](auto& guard) { return guard.context() ? guard.context()->secureChannelId : 0u; });
      if (id == secureChannelId)
        return channel;
    }
    return nullptr;
  }

  /// Delivers @p request into @p channel for the Session of @p authenticationToken; its response, or null
  /// when none arrives.
  std::shared_ptr<const Structure> deliver(server::SecureChannel& channel, std::shared_ptr<Structure> request,
    const NodeId& authenticationToken = {})
  {
    const auto requestId = mNextRequestId++;
    server::SecureChannelTestAccess::on_strand(channel,
      [&](auto& guard) { guard.inject_decoded_request(requestId, std::move(request), authenticationToken); });
    std::shared_ptr<const Structure> response;
    (void)eventually(
      [&]
      {
        const std::lock_guard lock{mState->mutex};
        const auto found = mState->responses.find(requestId);
        if (found == mState->responses.end())
          return false;
        response = found->second;
        return true;
      });
    return response;
  }

  std::vector<std::string> client_signature_algorithms() const
  {
    const std::lock_guard lock{mState->mutex};
    return mState->clientSignatureAlgorithms;
  }

  std::vector<std::string> server_signature_algorithms() const
  {
    const std::lock_guard lock{mState->mutex};
    return mState->serverSignatureAlgorithms;
  }

private:
  struct State
  {
    std::mutex mutex;
    std::vector<std::shared_ptr<server::SecureChannel>> channels;
    std::map<uint32_t, std::shared_ptr<const Structure>> responses;
    std::vector<std::string> clientSignatureAlgorithms;
    std::vector<std::string> serverSignatureAlgorithms;
  };

  std::shared_ptr<State> mState;
  uint32_t mNextRequestId{firstDeliveredRequestId};
};

/// A server of its own whose first endpoint is one policy in one mode (Sign also offers SignAndEncrypt), with
/// the family's valid server certificate and further endpoints of that family, and the cached client of the
/// family. The Session rules of OPC 10000-4 5.7.3 and 6.1.8 are driven through the SDK client where it can
/// send the stimulus, and delivered into the server side of the channel where it never would.
class EnhancedSessionActivation : public ::testing::Test
{
protected:
  struct Endpoint
  {
    SecurityPolicyId policy;
    MessageSecurityMode mode;
  };

  /// A Session the SDK client created and activated (Anonymous) over a channel the test keeps.
  struct BoundSession
  {
    client::SecureChannel* channel{nullptr};
    client::Session* session{nullptr};
    NodeId authenticationToken;
  };

  /// A Session created by a CreateSession delivered into the server side of a channel.
  struct RawSession
  {
    std::shared_ptr<server::SecureChannel> serverChannel;
    NodeId authenticationToken;
    ByteString clientNonce;
    ByteString serverNonce;
    ByteString serverCertificate;  ///< As the CreateSession response carries it.
    ChannelBoundSignatureInputs inputs;  ///< Table 101's values for this Session and channel.
  };

  void TearDown() override
  {
    reset();
  }

  void reset()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    for (auto& session : mSessions)
      (void)session.try_close_sync();
    mSessions.clear();
    for (auto& channel : mChannels)
      (void)channel.try_close_sync();
    mChannels.clear();
    mTraffic.reset();
    mServer.reset();
    mServerStore.reset();
    mUserStore.reset();
    mX509Authenticator.reset();
  }

  /// With @p x509 the first endpoint also offers an X509 token policy ("x509") of its own policy, which a
  /// CountingX509Authenticator decides against the family's user PKI.
  void start(SecurityPolicyId policy, MessageSecurityMode mode, std::vector<Endpoint> extraEndpoints = {},
    bool x509 = false, std::vector<UserTokenPolicy> extraTokenPolicies = {})
  {
    mPolicy = policy;
    auto& pki = shared_pki();
    auto& cache = MatrixCache::instance();
    mServerStore = make_store(cache.new_directory("activation_server"),
      cache.server_pool().executor(),
      pki.crypto(),
      validation_options_for(CertificateCase::Valid),
      pki.trust_material(family_of(policy)),
      &pki.leaf(policy, CertificateCase::Valid, Role::Server),
      application_certificate_type(policy));
    if (x509)
    {
      mUserStore = make_store(cache.new_directory("activation_user"),
        cache.server_pool().executor(),
        pki.crypto(),
        validation_options_for(CertificateCase::Valid),
        pki.trust_material(family_of(policy)),
        nullptr,
        CertificateType::Invalid);
      mX509Authenticator = std::make_shared<CountingX509Authenticator>();
    }
    mServer = std::make_unique<MatrixServer>(cache.server_pool(),
      pki.crypto(),
      MatrixServer::Options{.policy = policy,
        .mode = mode,
        .applicationStore = mServerStore,
        .userTokenStore = mUserStore,
        .x509Authenticator = mX509Authenticator,
        .auditing = false,
        .userTokenSecurityPolicy = std::nullopt,
        .localDiscoveryServer = false,
        .userNameAuthenticator = nullptr,
        .userNameSecurityPolicy = std::nullopt,
        .extraTokenPolicies = std::move(extraTokenPolicies)});
    for (const auto& extra : extraEndpoints)
    {
      server::ServerEndpointConfig endpoint;
      endpoint.name = policy_name(extra.policy) + "_" + mode_name(extra.mode);
      endpoint.messageSecurityMode = extra.mode;
      endpoint.securityPolicyId = extra.policy;
      UserTokenPolicy anonymous;
      anonymous.policy_id() = "anonymous";
      anonymous.token_type() = UserTokenType::Anonymous;
      endpoint.userIdentityTokens.push_back(std::move(anonymous));
      mServer->server().add_endpoint(mServer->listener(), std::move(endpoint));
    }
    mTraffic = std::make_unique<ServerChannels>(mServer->server());
    if (mObserver)
      mServer->server().set_observer(mObserver);
    const auto started = mServer->start();
    ASSERT_TRUE(started.is_good()) << ua::format(started.status_code());
  }

  /// The family's client: it holds the family's valid client certificate, which serves every policy of the
  /// family, so one Session can be moved between them.
  client::Client& client()
  {
    return *MatrixCache::instance()
              .client_for(
                mPolicy, MessageSecurityMode::SignAndEncrypt, validation_options_for(CertificateCase::Valid))
              .client;
  }

  const LeafMaterial& leaf(Role role) const
  {
    return shared_pki().leaf(mPolicy, CertificateCase::Valid, role);
  }

  /// A new channel of @p policy in @p mode to the server, or nothing.
  std::optional<client::SecureChannel> open(SecurityPolicyId policy, MessageSecurityMode mode)
  {
    client::CoreClient::OpenChannelConfig config;
    config.endpointUrl = mServer->endpoint_url();
    config.securityMode = mode;
    config.securityPolicyId = policy;
    config.serverCertificate = leaf(Role::Server).certificate;
    auto opened = client().core().try_open_channel_sync(std::move(config));
    EXPECT_TRUE(opened.is_good()) << "a " << mode_name(mode) << " channel of " << policy_name(policy)
                                  << " did not open: " << ua::format(opened.status_code());
    if (opened.is_bad())
      return std::nullopt;
    return std::move(opened).value();
  }

  /// A Session the SDK client creates and activates (Anonymous) over a new channel of @p policy in @p mode.
  BoundSession bound_session(SecurityPolicyId policy, MessageSecurityMode mode)
  {
    auto opened = open(policy, mode);
    if (!opened)
      return {};
    auto& channel = mChannels.emplace_back(std::move(*opened));
    auto& session =
      mSessions.emplace_back(channel.create_session_sync({.sessionName = "EnhancedSessionActivation"}));
    const auto activated = session.try_activate_sync();
    EXPECT_TRUE(activated.is_good()) << ua::format(activated.status_code());
    if (activated.is_bad())
      return {};
    return BoundSession{.channel = &channel,
      .session = &session,
      .authenticationToken = client::SessionTestAccess::on_strand(
        session, [](auto& guard) { return guard.authentication_token(); })};
  }

  /// Reads the Server's CurrentTime for the Session of @p authenticationToken through the server side of
  /// @p channel: whether that channel still serves the Session.
  StatusCode read_over(server::SecureChannel& channel, const NodeId& authenticationToken)
  {
    auto request = std::make_shared<ReadRequest>(ReadRequestBuilder()
                                                   .read(NodeId{VariableId::Server_ServerStatus_CurrentTime})
                                                   .attribute(AttributeId::Value)
                                                   .build());
    const auto response = mTraffic->deliver(channel, std::move(request), authenticationToken);
    const auto* read = dynamic_cast<const ReadResponse*>(response.get());
    if (!read || read->response_header().service_result().is_bad())
      return service_result(response);
    if (read->results().empty())
      return StatusCode{Status::BadUnexpectedError};
    return read->results()[0].status().value_or(StatusCode{Status::Good});
  }

  StatusCode read_over(const client::SecureChannel& channel, const NodeId& authenticationToken)
  {
    const auto serverChannel = mTraffic->channel(channel.secure_channel_id());
    if (!serverChannel)
      return StatusCode{Status::BadSecureChannelIdInvalid};
    return read_over(*serverChannel, authenticationToken);
  }

  /// A CreateSession, as the SDK client sends it, delivered into the server side of a new channel of the
  /// first endpoint; the channel is kept.
  std::optional<RawSession> raw_session()
  {
    auto opened = open(mPolicy, MessageSecurityMode::SignAndEncrypt);
    if (!opened)
      return std::nullopt;
    const auto& channel = mChannels.emplace_back(std::move(*opened));
    RawSession raw;
    raw.serverChannel = mTraffic->channel(channel.secure_channel_id());
    if (!raw.serverChannel)
    {
      ADD_FAILURE() << "the server side of the channel was not found";
      return std::nullopt;
    }
    raw.clientNonce = shared_pki().crypto()->get_entropy_sync(32);
    auto request = std::make_shared<CreateSessionRequest>();
    request->client_description().application_uri() = clientUri;
    request->endpoint_url() = mServer->endpoint_url();
    request->session_name() = "EnhancedSessionActivation";
    request->client_nonce() = raw.clientNonce;
    request->client_certificate() = leaf(Role::Client).certificate->der_encoding();
    request->requested_session_timeout() = 60000.0;
    const auto response = mTraffic->deliver(*raw.serverChannel, std::move(request));
    const auto* created = dynamic_cast<const CreateSessionResponse*>(response.get());
    if (!created || created->response_header().service_result().is_bad())
    {
      ADD_FAILURE() << "the delivered CreateSession failed: " << ua::format(service_result(response));
      return std::nullopt;
    }
    raw.authenticationToken = created->authentication_token();
    raw.serverNonce = created->server_nonce();
    raw.serverCertificate = created->server_certificate();
    raw.inputs = server::SecureChannelTestAccess::on_strand(*raw.serverChannel,
      [](auto& guard)
      {
        const auto& context = *guard.context();
        return ChannelBoundSignatureInputs{.channelThumbprint = context.channelThumbprint,
          .serverChannelCertificate = der_or_empty(context.localCertificate),
          .clientChannelCertificate = der_or_empty(context.remoteCertificate)};
      });
    raw.inputs.clientNonce = raw.clientNonce;
    raw.inputs.serverNonce = raw.serverNonce;
    raw.inputs.serverCertificate = leaf(Role::Server).certificate->der_encoding();
    raw.inputs.clientCertificate = leaf(Role::Client).certificate->der_encoding();
    EXPECT_FALSE(raw.inputs.channelThumbprint.empty()) << "the channel has no ChannelThumbprint";
    return raw;
  }

  /// @p data signed with @p keys under @p policy's asymmetric signature algorithm, with @p algorithm.
  static SignatureData sign(const SecurityPolicy& policy,
    const std::shared_ptr<const AsymmetricKeyPair>& keys, const ByteString& data,
    std::string_view algorithm = {})
  {
    SignatureData signature;
    signature.signature() =
      shared_pki().crypto()->asymmetric_sign_sync(policy.asymmetric_signature_algorithm(), keys, data);
    signature.algorithm() = String{algorithm};
    return signature;
  }

  /// The legacy data a session signature signs: a certificate followed by a nonce (OPC 10000-4 5.7.2).
  static ByteString legacy_data(const ByteString& certificate, const ByteString& nonce)
  {
    ByteString data = certificate;
    std::ranges::copy(nonce, std::back_inserter(data));
    return data;
  }

  /// An Anonymous ActivateSession for @p raw whose ClientSignature signs @p clientSignatureData.
  std::shared_ptr<ActivateSessionRequest> activate_request(
    const ByteString& clientSignatureData, std::string_view algorithm = {})
  {
    auto request = std::make_shared<ActivateSessionRequest>();
    request->client_signature() =
      sign(*SecurityPolicy::create(mPolicy), leaf(Role::Client).keys, clientSignatureData, algorithm);
    auto token = std::make_unique<AnonymousIdentityToken>();
    token->policy_id() = "anonymous";
    request->user_identity_token() = std::move(token);
    return request;
  }

  /// The Table 101 ClientSignature data of @p raw.
  ByteString client_data(const RawSession& raw) const
  {
    return channel_bound_data(
      *shared_pki().crypto(), *SecurityPolicy::create(mPolicy), ChannelBoundSignature::Client, raw.inputs);
  }

  SecurityPolicyId mPolicy{SecurityPolicyId::Invalid};
  std::shared_ptr<server::ServerObserver> mObserver;  ///< Installed by start() when set.
  std::shared_ptr<CertificateStore> mServerStore;
  std::shared_ptr<CertificateStore> mUserStore;
  std::shared_ptr<CountingX509Authenticator> mX509Authenticator;
  std::unique_ptr<MatrixServer> mServer;
  std::unique_ptr<ServerChannels> mTraffic;
  std::list<client::SecureChannel> mChannels;
  std::list<client::Session> mSessions;
  std::optional<client::Connection> mConnection;
};

/// The outcome of Server::create for a configuration that declares one endpoint on a listener.
struct CreateOutcome
{
  std::optional<Status> refusal;  ///< The refusal's status; empty when the server was created.
  std::shared_ptr<const ErrorDetail> detail;
};

CreateOutcome create_with_endpoint(server::ServerEndpointConfig endpoint)
{
  auto application = ua::test_utils::create_test_config();
  application.allowInsecureEndpoints = true;
  application.allowDeprecatedSecurityPolicies = true;
  server::ServerConfig configuration;
  server::ServerConfig::ListenerConfig listener;
  listener.name = "declared";
  listener.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  listener.bind.address = "127.0.0.1:0";
  listener.endpoints.push_back(std::move(endpoint));
  configuration.listeners().push_back(std::move(listener));
  try
  {
    auto created = server::Server::create(MatrixCache::instance().server_pool().executor(),
      server::CreateConfig{.identity = ApplicationIdentity::load_default(),
        .application = std::move(application),
        .server = std::move(configuration)},
      server::ServerComponents{.crypto = shared_pki().crypto()});
    (void)created.try_shutdown_sync({.grace = std::chrono::seconds{0}});
    return {};
  }
  catch (const UaException& refused)
  {
    return CreateOutcome{.refusal = refused.status(),
      .detail = refused.detail() ? std::make_shared<const ErrorDetail>(*refused.detail()) : nullptr};
  }
}

/// An endpoint of @p policy in @p mode offering one token policy ("refused") of @p type naming @p
/// tokenPolicy.
server::ServerEndpointConfig endpoint_offering(
  SecurityPolicyId policy, MessageSecurityMode mode, UserTokenType type, SecurityPolicyId tokenPolicy)
{
  server::ServerEndpointConfig endpoint;
  endpoint.name = "unusable";
  endpoint.securityPolicyId = policy;
  endpoint.messageSecurityMode = mode;
  UserTokenPolicy token;
  token.policy_id() = "refused";
  token.token_type() = type;
  token.security_policy_uri() = ua::utils::get_security_policy_uri(tokenPolicy);
  endpoint.userIdentityTokens.push_back(std::move(token));
  return endpoint;
}

/// The value of @p key in @p detail's context, or nothing.
std::optional<std::string> context_value(const ErrorDetail& detail, std::string_view key)
{
  for (const auto& item : detail.context)
    if (item.key == key)
      return item.value;
  return std::nullopt;
}

/// The X509 token policy "x509-legacy" naming Basic256Sha256, which has no SecureChannelEnhancements, for an
/// RSA_DH endpoint, which has them. Part 4 7.41 lets an X509 token policy name any SecurityPolicy; the SDK
/// keeps it to the endpoint's certificate family (guess G-33).
std::vector<UserTokenPolicy> legacy_x509_token_policy()
{
  UserTokenPolicy legacy;
  legacy.policy_id() = "x509-legacy";
  legacy.token_type() = UserTokenType::Certificate;
  legacy.security_policy_uri() = ua::utils::get_security_policy_uri(SecurityPolicyId::Basic256Sha256);
  return {legacy};
}

}  // namespace

// The four NIST/Brainpool policies OPC UA 1.05.07 removed, named in an OpenSecureChannel sent to a server
// whose endpoint offers the parameter's policy: each is refused with Bad_SecurityPolicyRejected in an ERR and
// the connection is closed. The removed Edwards URIs and any unknown string take the same path (the unit
// arm).
// @relation(AC-SVR-SCE-001-REMOVED-URI-REFUSED, scope=function)
TEST_P(EnhancedSecurityPolicies, ARemovedEccPolicyUriIsRejected)
{
  ASSERT_NO_FATAL_FAILURE(start_server(nullptr));
  for (const std::string_view uri : {"http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1"})
  {
    SCOPED_TRACE(std::string{uri});
    const auto answer = raw_open_secure_channel(mServer->endpoint_url(), uri, ua::test_utils::scaled(5000ms));
    ASSERT_EQ(answer.type, "ERR") << "the OpenSecureChannel was not answered with an ERR";
    EXPECT_EQ(answer.error, StatusCode{Status::BadSecurityPolicyRejected}.as_uint32());
    EXPECT_TRUE(answer.closed) << "the server kept the connection open after refusing the policy";
  }
}

// AC-SVR-SCE-004-CHAINED-RENEW end to end: both ends chain every renewal's key material from the token before
// it (OPC 10000-6 6.8.1 Step 2), so traffic continues across renewals. The server grants the 1 s lifetime the
// client asks for, and the client renews at 75 % of it. A Read is sent every 100 ms, and every Read must
// succeed. The server reports a renewal before its response reaches the client, so a Read counts as one after
// renewal n only when it starts 300 ms after the server reported n - by then the client sends under the new
// token. The test ends when there has been such a Read after each of three renewals. An end that derived a
// renewal's keys from anything else - the new secret alone, or a token other than the latest - would fail the
// first Read under that token (the tag does not verify), and the channel would close.
// @relation(AC-SVR-SCE-004-CHAINED-RENEW, scope=function)
TEST_P(EnhancedSecurityPolicies, ReadsSucceedAcrossRepeatedRenewals)
{
  const auto policy = GetParam();
  auto renewals = std::make_shared<RenewalCounter>(std::string{SecurityPolicy::create(policy)->uri()});
  ASSERT_NO_FATAL_FAILURE(start_server(renewals));

  auto config =
    matrix_connection_config(mServer->endpoint_url(), policy, MessageSecurityMode::SignAndEncrypt);
  config.channelLifetime = ua::test_utils::scaled(1000ms);
  auto connected = reported(client().try_connect_sync(std::move(config)));
  ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
  mConnection.emplace(std::move(connected).value());

  constexpr size_t renewalsToCross = 3;
  const auto settle = ua::test_utils::scaled(300ms);
  std::vector<std::optional<std::chrono::steady_clock::time_point>> reportedAt(renewalsToCross + 1);
  std::vector<bool> readAfterRenewal(renewalsToCross + 1, false);
  const auto deadline =
    std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{15000});
  while (!readAfterRenewal[renewalsToCross] && std::chrono::steady_clock::now() < deadline)
  {
    const auto renewed = std::min(static_cast<size_t>(renewals->renewed()), renewalsToCross);
    const auto now = std::chrono::steady_clock::now();
    if (!reportedAt[renewed])
      reportedAt[renewed] = now;
    const auto value = mConnection->try_read_value_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
    ASSERT_TRUE(value.is_good()) << "a Read after " << renewed
                                 << " renewals failed: " << ua::format(value.status_code());
    if (renewed > 0 && now - *reportedAt[renewed] >= settle)
      readAfterRenewal[renewed] = true;
    std::this_thread::sleep_for(100ms);
  }
  for (size_t n = 1; n <= renewalsToCross; ++n)
    EXPECT_TRUE(readAfterRenewal[n]) << "no Read was sent under the token of renewal " << n;
  EXPECT_EQ(renewals->failed(), 0);
}

// AC-SVR-SCE-001 end to end: under each policy a Session opens over a Sign and over a SignAndEncrypt
// channel - CreateSession and ActivateSession each prove the channel bound signature data (OPC 10000-4 6.1.8)
// both ends build - and the server reports each activation on a channel of that policy and mode.
// @relation(AC-SVR-SCE-001-SESSION-PER-POLICY, scope=function)
TEST_P(EnhancedSecurityPolicies, EverySessionOpensUnderItsPolicy)
{
  const auto policy = GetParam();
  const std::string uri{SecurityPolicy::create(policy)->uri()};
  auto recorder = std::make_shared<ActivationRecorder>();
  ASSERT_NO_FATAL_FAILURE(start_server(recorder, MessageSecurityMode::Sign));

  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    SCOPED_TRACE(mode_name(mode));
    auto connected = reported(
      client(mode).try_connect_sync(matrix_connection_config(mServer->endpoint_url(), policy, mode)));
    ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
    auto connection = std::move(connected).value();
    const auto value = connection.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
    EXPECT_TRUE(value.is_good()) << ua::format(value.status_code());
    EXPECT_TRUE(eventually(
      [&]
      {
        const auto activations = recorder->activations();
        return !activations.empty() && activations.back() == ActivationRecorder::ChannelSecurity{uri, mode};
      }))
      << "the server did not report the activation on a " << mode_name(mode) << " channel of " << uri;
    (void)connection.try_close_sync();
  }
}

// AC-SVR-SCE-009-SECRET-ROUND-TRIP end to end: a UserName token policy of the parameter's policy - the
// password travels as an EccEncryptedSecret (OPC 10000-4 7.41.2.5) under it. The right password activates the
// Session; a wrong one is refused with Bad_UserAccessDenied, which shows the server decrypted the secret it
// compared.
// @relation(AC-SVR-SCE-009-SECRET-ROUND-TRIP, scope=function)
TEST_P(EnhancedSecurityPolicies, AUserNameSecretRoundTripsUnderItsPolicy)
{
  const auto policy = GetParam();
  auto authenticator = std::make_shared<server::SimpleUserPasswordAuthenticator>(
    [](std::string_view userName, const ua::SecureString& password)
    { return userName == "test-user" && password.view() == "right-password"; });
  ASSERT_NO_FATAL_FAILURE(start_server(nullptr, MessageSecurityMode::SignAndEncrypt, authenticator));

  const auto connectWith = [&](std::string password)
  {
    auto config =
      matrix_connection_config(mServer->endpoint_url(), policy, MessageSecurityMode::SignAndEncrypt);
    config.identity =
      client::UsernamePasswordIdentity{.username = "test-user", .password = std::move(password)};
    config.userTokenPolicyId = "username-secret";
    return reported(client().try_connect_sync(std::move(config)));
  };

  auto accepted = connectWith("right-password");
  ASSERT_TRUE(accepted.is_good()) << ua::format(accepted.status_code());
  mConnection.emplace(std::move(accepted).value());

  const auto refused = connectWith("wrong-password");
  ASSERT_TRUE(refused.is_bad()) << "a wrong password activated the Session";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadUserAccessDenied)
    << ua::format(refused.status_code());
}

// AC-SVR-SCE-002-MULTI-CHUNK end to end: under each policy, over a Sign and over a SignAndEncrypt channel, a
// ByteString larger than four chunks is written to a Variable and read back. Each chunk carries its own tag
// (SVR-SCE-002) and an IV built from the TokenId and the previous sequence number (SVR-SCE-003), so the Write
// request and the Read response each cross the channel as more than four separately protected chunks. No
// chunk is larger than the negotiated buffer, which is at most the buffer the server proposes, so a value of
// four times that buffer cannot fit in four. The bytes cycle through 251 values, so a chunk that is
// reordered, repeated or dropped does not leave an equal value.
// @relation(AC-SVR-SCE-002-MULTI-CHUNK, scope=function)
TEST_P(EnhancedSecurityPolicies, ALargeValueCrossesManyChunks)
{
  const auto policy = GetParam();
  ASSERT_NO_FATAL_FAILURE(start_server(nullptr, MessageSecurityMode::Sign));

  auto addressSpace = mServer->server().address_space();
  auto largeNamespace =
    default_ns::Namespace::create("urn:test:enhanced:many-chunks", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(largeNamespace);
  grant_namespace_to_test_client(addressSpace, namespaceIndex);
  const NodeId variableId{namespaceIndex, std::uint32_t{1}};
  auto node = addressSpace.create_node_sync(variableId, NodeClass::Variable);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_browse_name(QualifiedName{namespaceIndex, "LargeValue"});
  variable->set_display_name(LocalizedText{"", "LargeValue"});
  variable->set_data_type(NodeId{DataTypeId::ByteString});
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, variableId);

  const size_t bufferSize =
    ua::test_utils::create_test_config().stack_limits().connectionProtocolLimits.maxBufferSize;
  std::vector<uint8_t> bytes(4 * bufferSize + 1);
  for (size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<uint8_t>(i % 251);
  const ByteString written{bytes};

  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    SCOPED_TRACE(mode_name(mode));
    auto connected = reported(
      client(mode).try_connect_sync(matrix_connection_config(mServer->endpoint_url(), policy, mode)));
    ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
    auto connection = std::move(connected).value();
    const auto write = connection.try_write_value_sync(variableId, Variant{written});
    ASSERT_TRUE(write.is_good()) << "the Write of " << written.size()
                                 << " bytes failed: " << ua::format(write.status_code());
    const auto read = connection.try_read_value_sync(variableId);
    ASSERT_TRUE(read.is_good()) << "the Read back failed: " << ua::format(read.status_code());
    const auto* back = read.value().value().try_as<ByteString>();
    ASSERT_NE(back, nullptr) << "the value read back is not a ByteString";
    EXPECT_EQ(back->size(), written.size());
    EXPECT_TRUE(*back == written) << "the value read back differs from the value written";
    (void)connection.try_close_sync();
  }
}

INSTANTIATE_TEST_SUITE_P(
  FourteenPolicies, EnhancedSecurityPolicies, ::testing::ValuesIn(enhanced_policies()), enhanced_policy_name);

// AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED end to end, control: the same MisbehavingServer, signing its first
// response over the response and the request's Signature as OPC 10000-6 6.7.5 requires, is accepted.
// @relation(AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED, scope=function)
TEST_P(EnhancedChannelMisbehavingServer, AFirstResponseBoundToTheRequestIsAccepted)
{
  ASSERT_NO_FATAL_FAILURE(start(false));
  const auto connected = connect();
  EXPECT_TRUE(connected.is_good()) << ua::format(connected.status_code());
}

// AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED end to end: a server that signs its first OpenSecureChannel response
// over the response alone, as it signs a renewal's, has not bound it to the client's request, and the client
// refuses it with Bad_SecurityChecksFailed (OPC 10000-6 6.7.6) before it opens a Session.
// @relation(AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED, scope=function)
TEST_P(EnhancedChannelMisbehavingServer, AFirstResponseNotBoundToTheRequestIsRefused)
{
  ASSERT_NO_FATAL_FAILURE(start(true));
  const auto connected = connect();
  ASSERT_TRUE(connected.is_bad());
  EXPECT_EQ(connected.status_code().as_status(), Status::BadSecurityChecksFailed)
    << ua::format(connected.status_code());
  EXPECT_TRUE(chain_names(connected.status_code(), "FirstResponseSignatureInvalid"))
    << "the refusal is not the first response's signature check";
}

// AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY end to end: the MisbehavingServer's secured
// endpoint offers Anonymous only and faults a CreateSession that asks for an EphemeralKey, as Eclipse
// Milo 1.2.0-RC1 does. The managed connect, selecting from discovery, asks for none there, so it connects.
// Falsifiable: the former client asked on every key-agreement channel, and its connect failed.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_P(EnhancedChannelMisbehavingServer, AnAnonymousOnlyEndpointIsAskedForNoEphemeralKey)
{
  ASSERT_NO_FATAL_FAILURE(start(false));
  const auto requests = fault_ephemeral_key_requests();

  const auto connected = connect();
  EXPECT_EQ(requests->total.load(), 1) << "the connect did not reach CreateSession exactly once";
  EXPECT_EQ(requests->askedForEphemeralKey.load(), 0)
    << "the client asked an endpoint offering no UserName or IssuedToken policy for an EphemeralKey";
  EXPECT_TRUE(connected.is_good()) << ua::format(connected.status_code());
}

// The same through Client::try_easy_connect_sync, which pins the endpoint it discovered and connects ExactUrl
// with the discovery result. Falsifiable: an ExactUrl plan that ignores its discovery result asks, and fails.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_P(EnhancedChannelMisbehavingServer, EasyConnectAsksAnAnonymousOnlyEndpointForNoEphemeralKey)
{
  ASSERT_NO_FATAL_FAILURE(start(false));
  const auto requests = fault_ephemeral_key_requests();

  const auto connected = easy_connect();
  EXPECT_EQ(requests->total.load(), 1) << "easy_connect did not reach CreateSession exactly once";
  EXPECT_EQ(requests->askedForEphemeralKey.load(), 0)
    << "easy_connect asked an endpoint offering no UserName or IssuedToken policy for an EphemeralKey";
  EXPECT_TRUE(connected.is_good()) << ua::format(connected.status_code());
}

INSTANTIATE_TEST_SUITE_P(FourteenPolicies, EnhancedChannelMisbehavingServer,
  ::testing::ValuesIn(enhanced_policies()), enhanced_policy_name);

// =============================================================================================
// EnhancedSessionActivation: the channel bound Session signatures (OPC 10000-4 6.1.8) and the rules for
// moving a Session to another SecureChannel (5.7.3), end to end.
// =============================================================================================

// AC-SVR-SCE-010-LEGACY-SIGNATURE-REFUSED end to end: over an enhanced channel, a ClientSignature over the
// legacy data (ServerCertificate | ServerNonce) is refused with Bad_ApplicationSignatureInvalid and leaves
// the Session unactivated; the Table 101 ClientSignature then activates it. Whether the refusal activated the
// Session is read from the activations the server reports, since any other request to a Session that is not
// activated closes it.
// @relation(AC-SVR-SCE-010-LEGACY-SIGNATURE-REFUSED, scope=function)
TEST_F(EnhancedSessionActivation, ALegacyClientSignatureIsRefused)
{
  auto recorder = std::make_shared<ActivationRecorder>();
  mObserver = recorder;
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::SignAndEncrypt));
  const auto raw = raw_session();
  ASSERT_TRUE(raw.has_value());

  const auto legacy = mTraffic->deliver(*raw->serverChannel,
    activate_request(legacy_data(raw->serverCertificate, raw->serverNonce)),
    raw->authenticationToken);
  EXPECT_EQ(service_result(legacy).as_status(), Status::BadApplicationSignatureInvalid)
    << ua::format(service_result(legacy));

  const auto bound =
    mTraffic->deliver(*raw->serverChannel, activate_request(client_data(*raw)), raw->authenticationToken);
  EXPECT_TRUE(service_result(bound).is_good()) << "control: " << ua::format(service_result(bound));
  // Reported in order, so a refused ActivateSession that activated the Session shows before the control.
  ASSERT_TRUE(eventually([&] { return !recorder->activations().empty(); }));
  EXPECT_EQ(recorder->activations().size(), 1u) << "the refused ActivateSession activated the Session";
  EXPECT_TRUE(read_over(*raw->serverChannel, raw->authenticationToken).is_good());
}

// AC-SVR-SCE-010-X509-TOKEN end to end, control: the SDK client activates with an X509 user token under the
// enhanced token policy and under the legacy one over the same RSA_DH channel - the token policy, not the
// channel, decides which data the UserTokenSignature signs (SD-P4-001).
// @relation(AC-SVR-SCE-010-X509-TOKEN, scope=function)
TEST_F(EnhancedSessionActivation, AnX509TokenSignsTheLayoutOfItsTokenPolicy)
{
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::RsaDhAesGcm,
    MessageSecurityMode::SignAndEncrypt,
    {},
    true,
    legacy_x509_token_policy()));
  const auto& user = leaf(Role::User);
  for (const std::string policyId : {"x509", "x509-legacy"})
  {
    SCOPED_TRACE(policyId);
    auto config =
      matrix_connection_config(mServer->endpoint_url(), mPolicy, MessageSecurityMode::SignAndEncrypt);
    client::X509Identity identity;
    identity.certificate = user.certificate;
    identity.keyPair = user.keys;
    identity.issuerCertificates = user.presentedIssuers;
    config.identity = std::move(identity);
    config.userTokenPolicyId = policyId;
    auto connected = reported(client().try_connect_sync(std::move(config)));
    ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
    auto connection = std::move(connected).value();
    const auto value = connection.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
    EXPECT_TRUE(value.is_good()) << ua::format(value.status_code());
    (void)connection.try_close_sync();
  }
  EXPECT_EQ(mX509Authenticator->calls(), 2);
}

// AC-SVR-SCE-010-X509-TOKEN end to end: a UserTokenSignature over the data of the other layout - the legacy
// data under the enhanced token policy, the Table 101 data under the legacy one - is refused with
// Bad_UserSignatureInvalid before the authenticator, and the Session stays unactivated.
// @relation(AC-SVR-SCE-010-X509-TOKEN, scope=function)
TEST_F(EnhancedSessionActivation, AUserTokenSignatureOverTheWrongLayoutIsRefused)
{
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::RsaDhAesGcm,
    MessageSecurityMode::SignAndEncrypt,
    {},
    true,
    legacy_x509_token_policy()));
  const auto& user = leaf(Role::User);
  const auto channelPolicy = SecurityPolicy::create(mPolicy);
  for (const auto& [policyId, tokenPolicy] : {std::pair{std::string{"x509"}, mPolicy},
         std::pair{std::string{"x509-legacy"}, SecurityPolicyId::Basic256Sha256}})
  {
    SCOPED_TRACE(policyId);
    const auto raw = raw_session();
    ASSERT_TRUE(raw.has_value());
    const auto tokenSecurityPolicy = SecurityPolicy::create(tokenPolicy);
    // The other layout: an enhanced token policy signs Table 101, a legacy one ServerCertificate |
    // ServerNonce.
    const auto wrongData =
      tokenSecurityPolicy->secure_channel_enhancements()
        ? legacy_data(raw->serverCertificate, raw->serverNonce)
        : channel_bound_data(
            *shared_pki().crypto(), *channelPolicy, ChannelBoundSignature::UserToken, raw->inputs);
    auto request = activate_request(client_data(*raw));
    auto token = std::make_unique<X509IdentityToken>();
    token->policy_id() = policyId;
    token->certificate_data() = user.certificate->der_encoding();
    request->user_identity_token() = std::move(token);
    request->user_token_signature() = sign(*tokenSecurityPolicy,
      user.keys,
      wrongData,
      tokenSecurityPolicy->secure_channel_enhancements()
        ? std::string_view{}
        : std::string_view{tokenSecurityPolicy->asymmetric_signature_algorithm_uri()});

    const auto refused = mTraffic->deliver(*raw->serverChannel, std::move(request), raw->authenticationToken);
    EXPECT_EQ(service_result(refused).as_status(), Status::BadUserSignatureInvalid)
      << ua::format(service_result(refused));
    EXPECT_EQ(
      read_over(*raw->serverChannel, raw->authenticationToken).as_status(), Status::BadSessionNotActivated);
  }
  EXPECT_EQ(mX509Authenticator->calls(), 0) << "a refused UserTokenSignature reached the authenticator";
}

// AC-SVR-SCE-011-ALGORITHM-EMPTY-AND-IGNORED end to end: under an enhanced policy the ServerSignature and the
// ClientSignature the SDK sends carry no algorithm, and a correct ClientSignature naming an unrelated
// algorithm URI still activates the Session - the receiver ignores the field (OPC 10000-4 Table 174).
// @relation(AC-SVR-SCE-011-ALGORITHM-EMPTY-AND-IGNORED, scope=function)
TEST_F(EnhancedSessionActivation, AReceivedSignatureAlgorithmIsIgnored)
{
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::SignAndEncrypt));
  const auto bound = bound_session(mPolicy, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(bound.session, nullptr);
  const auto serverAlgorithms = mTraffic->server_signature_algorithms();
  const auto clientAlgorithms = mTraffic->client_signature_algorithms();
  ASSERT_EQ(serverAlgorithms.size(), 1u);
  ASSERT_EQ(clientAlgorithms.size(), 1u);
  EXPECT_EQ(serverAlgorithms.front(), "") << "the ServerSignature names an algorithm";
  EXPECT_EQ(clientAlgorithms.front(), "") << "the ClientSignature names an algorithm";

  const auto raw = raw_session();
  ASSERT_TRUE(raw.has_value());
  const auto activated = mTraffic->deliver(*raw->serverChannel,
    activate_request(client_data(*raw), "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
    raw->authenticationToken);
  EXPECT_TRUE(service_result(activated).is_good()) << ua::format(service_result(activated));
}

// AC-SVR-SCE-012-POLICY-OR-MODE-CHANGE-REFUSED end to end: a Session activated over a SignAndEncrypt channel
// is moved by the SDK client to a new channel with the same client certificate under another policy, and
// under the same policy in Sign: both are refused with Bad_SecurityPolicyRejected and the Session keeps
// serving its original channel. Under the same policy and mode the move succeeds. The rule holds for every
// SecurityPolicy (D-6), so an RSA pair repeats the first arm.
// @relation(AC-SVR-SCE-012-POLICY-OR-MODE-CHANGE-REFUSED, scope=function)
TEST_F(EnhancedSessionActivation, MovingToAnotherPolicyOrModeIsRefused)
{
  const auto expectRefusedMove = [this](SecurityPolicyId policy, MessageSecurityMode mode)
  {
    SCOPED_TRACE(policy_name(policy) + "_" + mode_name(mode));
    const auto bound = bound_session(mPolicy, MessageSecurityMode::SignAndEncrypt);
    ASSERT_NE(bound.session, nullptr);
    auto target = open(policy, mode);
    ASSERT_TRUE(target.has_value());
    const auto moved = bound.session->try_activate_sync(std::move(*target));
    EXPECT_EQ(moved.status_code().as_status(), Status::BadSecurityPolicyRejected)
      << ua::format(moved.status_code());
    EXPECT_TRUE(read_over(*bound.channel, bound.authenticationToken).is_good())
      << "the Session no longer serves its original channel";
  };

  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::EccNistP256AesGcm,
    MessageSecurityMode::SignAndEncrypt,
    {{SecurityPolicyId::EccNistP256ChaChaPoly, MessageSecurityMode::SignAndEncrypt},
      {SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::Sign}}));
  expectRefusedMove(SecurityPolicyId::EccNistP256ChaChaPoly, MessageSecurityMode::SignAndEncrypt);
  expectRefusedMove(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::Sign);
  {
    const auto bound = bound_session(mPolicy, MessageSecurityMode::SignAndEncrypt);
    ASSERT_NE(bound.session, nullptr);
    auto target = open(mPolicy, MessageSecurityMode::SignAndEncrypt);
    ASSERT_TRUE(target.has_value());
    const auto moved = bound.session->try_activate_sync(std::move(*target));
    EXPECT_TRUE(moved.is_good()) << "control: " << ua::format(moved.status_code());
  }

  reset();
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::Basic256Sha256,
    MessageSecurityMode::SignAndEncrypt,
    {{SecurityPolicyId::Aes128Sha256RsaOaep, MessageSecurityMode::SignAndEncrypt}}));
  expectRefusedMove(SecurityPolicyId::Aes128Sha256RsaOaep, MessageSecurityMode::SignAndEncrypt);
}

// AC-SVR-SCE-012-ANONYMOUS-OVER-SIGN-REFUSED end to end: an Anonymous Session moved to a new Sign channel of
// its policy is refused with Bad_IdentityTokenRejected - nothing would bind it to the client that activated
// it - and keeps serving its original channel; between SignAndEncrypt channels the same move succeeds.
// @relation(AC-SVR-SCE-012-ANONYMOUS-OVER-SIGN-REFUSED, scope=function)
TEST_F(EnhancedSessionActivation, AnAnonymousMoveOverSignIsRefused)
{
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::Sign));
  {
    const auto bound = bound_session(mPolicy, MessageSecurityMode::Sign);
    ASSERT_NE(bound.session, nullptr);
    auto target = open(mPolicy, MessageSecurityMode::Sign);
    ASSERT_TRUE(target.has_value());
    const auto moved = bound.session->try_activate_sync(std::move(*target));
    EXPECT_EQ(moved.status_code().as_status(), Status::BadIdentityTokenRejected)
      << ua::format(moved.status_code());
    EXPECT_TRUE(read_over(*bound.channel, bound.authenticationToken).is_good())
      << "the Session no longer serves its original channel";
  }
  {
    const auto bound = bound_session(mPolicy, MessageSecurityMode::SignAndEncrypt);
    ASSERT_NE(bound.session, nullptr);
    auto target = open(mPolicy, MessageSecurityMode::SignAndEncrypt);
    ASSERT_TRUE(target.has_value());
    const auto moved = bound.session->try_activate_sync(std::move(*target));
    EXPECT_TRUE(moved.is_good()) << "control: " << ua::format(moved.status_code());
  }
}

// AC-CL-SCE-010-REBIND-SIGNS-FOR-THE-NEW-CHANNEL end to end, at the highest tier: the server closes the
// connection under a Connection, which reconnects over a new channel of the same policy and mode and
// re-activates its Session there. The ClientSignature is bound to the new channel, so the server accepts it:
// it reports the same Session activated on a second channel, and a Read succeeds.
// @relation(AC-CL-SCE-010-REBIND-SIGNS-FOR-THE-NEW-CHANNEL, scope=function)
TEST_F(EnhancedSessionActivation, ASessionReactivatesOnANewChannel)
{
  auto recorder = std::make_shared<ActivationRecorder>();
  mObserver = recorder;
  ASSERT_NO_FATAL_FAILURE(start(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::SignAndEncrypt));
  auto config =
    matrix_connection_config(mServer->endpoint_url(), mPolicy, MessageSecurityMode::SignAndEncrypt);
  client::ReconnectPolicy reconnect;
  reconnect.backoff.base = 100ms;
  reconnect.backoff.jitterPct = 0.0;
  config.reconnect = reconnect;
  // A lost channel is noticed by the keep-alive poll; the default (three 5 s polls) outlasts the Session.
  config.keepAlive.interval = 200ms;
  config.keepAlive.missedBeforeReconnect = 1;
  auto connected = reported(client().try_connect_sync(std::move(config)));
  ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
  mConnection.emplace(std::move(connected).value());
  ASSERT_TRUE(eventually([&] { return recorder->session_channels().size() == 1; }));
  const auto first = recorder->session_channels().front();
  const auto serverChannel = mTraffic->channel(first.second);
  ASSERT_NE(serverChannel, nullptr);

  serverChannel->close();
  ASSERT_TRUE(eventually([&] { return recorder->session_channels().size() >= 2; }, 15000ms))
    << "the Connection did not re-activate its Session";
  const auto second = recorder->session_channels()[1];
  EXPECT_EQ(second.first, first.first) << "the reconnect created a Session instead of re-activating its own";
  EXPECT_NE(second.second, first.second) << "the Session was re-activated on its old channel";
  const auto value = mConnection->try_read_value_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
  EXPECT_TRUE(value.is_good()) << ua::format(value.status_code());
}

// =============================================================================================
// EnhancedTokenPolicies: decision D-16 - a token policy the server could only refuse is not offered.
// =============================================================================================

// AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES: Server::create refuses, with Bad_SecurityPolicyRejected, a None
// endpoint whose UserName token policy names an ECC policy (OPC 10000-4 7.41), a Basic256Sha256 endpoint
// whose UserName token policy does (no EphemeralKey to encrypt with), and a Basic256Sha256 endpoint whose
// X509 token policy names an enhanced policy (no ChannelThumbprint to sign). The ErrorDetail names the
// endpoint; its cause names the token policy and the rule.
// @relation(AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES, scope=function)
TEST(EnhancedTokenPolicies, AServerWithAnUnusableTokenPolicyDoesNotStart)
{
  struct Arm
  {
    SecurityPolicyId endpointPolicy;
    MessageSecurityMode mode;
    UserTokenType tokenType;
    const char* rule;
  };

  for (const auto& arm : {Arm{SecurityPolicyId::None,
                            MessageSecurityMode::None,
                            UserTokenType::UserName,
                            "EphemeralKeySecretOverNoneChannel"},
         Arm{SecurityPolicyId::Basic256Sha256,
           MessageSecurityMode::SignAndEncrypt,
           UserTokenType::UserName,
           "EphemeralKeySecretWithoutKeyAgreement"},
         Arm{SecurityPolicyId::Basic256Sha256,
           MessageSecurityMode::SignAndEncrypt,
           UserTokenType::Certificate,
           "EnhancedTokenPolicyOverLegacyChannel"}})
  {
    SCOPED_TRACE(arm.rule);
    const auto outcome = create_with_endpoint(
      endpoint_offering(arm.endpointPolicy, arm.mode, arm.tokenType, SecurityPolicyId::EccNistP256AesGcm));
    // Every arm runs: a failing one does not hide the others.
    if (!outcome.refusal.has_value())
    {
      ADD_FAILURE() << "the server was created";
      continue;
    }
    EXPECT_EQ(*outcome.refusal, Status::BadSecurityPolicyRejected);
    if (outcome.detail == nullptr || outcome.detail->cause == nullptr)
    {
      ADD_FAILURE() << "the refusal carries no ErrorDetail with a cause";
      continue;
    }
    EXPECT_EQ(context_value(*outcome.detail, ContextKeys::endpointName.value()), "unusable");
    EXPECT_EQ(outcome.detail->cause->code, arm.rule);
    EXPECT_EQ(context_value(*outcome.detail->cause, ContextKeys::tokenPolicyId.value()), "refused");
  }
}

// AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES, control: an RSA_DH endpoint offering a UserName token policy of its
// own policy and an X509 token policy naming Basic256Sha256 (same certificate family, no
// SecureChannelEnhancements) starts, and GetEndpoints lists both token policies on it.
// @relation(AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES, scope=function)
TEST(EnhancedTokenPolicies, AUsableTokenPolicyIsOffered)
{
  constexpr auto policy = SecurityPolicyId::RsaDhAesGcm;
  auto& pki = shared_pki();
  auto& cache = MatrixCache::instance();
  auto store = make_store(cache.new_directory("usable_token_policy"),
    cache.server_pool().executor(),
    pki.crypto(),
    validation_options_for(CertificateCase::Valid),
    pki.trust_material(family_of(policy)),
    &pki.leaf(policy, CertificateCase::Valid, Role::Server),
    application_certificate_type(policy));
  MatrixServer server(cache.server_pool(),
    pki.crypto(),
    MatrixServer::Options{.policy = policy,
      .mode = MessageSecurityMode::SignAndEncrypt,
      .applicationStore = store,
      .userTokenStore = nullptr,
      .x509Authenticator = nullptr,
      .auditing = false,
      .userTokenSecurityPolicy = std::nullopt,
      .localDiscoveryServer = false,
      .userNameAuthenticator = std::make_shared<server::SimpleUserPasswordAuthenticator>(
        [](std::string_view, const ua::SecureString&) { return false; }),
      .userNameSecurityPolicy = policy,
      .extraTokenPolicies = legacy_x509_token_policy()});
  const auto started = server.start();
  ASSERT_TRUE(started.is_good()) << ua::format(started.status_code());

  auto& client =
    *cache
       .client_for(
         policy, MessageSecurityMode::SignAndEncrypt, validation_options_for(CertificateCase::Valid))
       .client;
  const auto endpoints = client.discovery().try_get_endpoints_sync(server.endpoint_url(), {});
  ASSERT_TRUE(endpoints.is_good()) << ua::format(endpoints.status_code());
  const std::string uri{SecurityPolicy::create(policy)->uri()};
  const auto found = std::ranges::find_if(endpoints.value(),
    [&](const EndpointDescription& endpoint)
    {
      return std::string{endpoint.security_policy_uri()} == uri &&
             endpoint.security_mode() == MessageSecurityMode::SignAndEncrypt;
    });
  ASSERT_NE(found, endpoints.value().end()) << "the RSA_DH endpoint is not listed";
  const auto offers = [&](std::string_view policyId, UserTokenType type, SecurityPolicyId tokenPolicy)
  {
    return std::ranges::any_of(found->user_identity_tokens(),
      [&](const UserTokenPolicy& token)
      {
        return std::string{token.policy_id()} == policyId && token.token_type() == type &&
               token.security_policy_uri() == ua::utils::get_security_policy_uri(tokenPolicy);
      });
  };
  EXPECT_TRUE(offers("username-secret", UserTokenType::UserName, policy));
  EXPECT_TRUE(offers("x509-legacy", UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256));
}

// AC-CL-IDENT-005-LEGACY-SECRET-SPANS-RSA-BLOCKS end to end: over an RSA_DH channel the Session nonce is 128
// bytes, so a 64-byte password under an Aes256Sha256RsaPss UserName token policy (RSA-OAEP-SHA256, 190
// plaintext bytes per block of the 2048-bit server key) is a two-block legacy secret (OPC 10000-4 7.40.2.2,
// 7.40.4). The client encrypts it block by block and the server decrypts it: the Session activates with the
// right password and a wrong one is refused with Bad_UserAccessDenied.
// @relation(AC-CL-IDENT-005-LEGACY-SECRET-SPANS-RSA-BLOCKS, scope=function)
TEST(EnhancedTokenPolicies, ALegacySecretOfTwoRsaBlocksActivatesOverRsaDh)
{
  constexpr auto policy = SecurityPolicyId::RsaDhAesGcm;
  const std::string rightPassword(64, 'p');
  auto& pki = shared_pki();
  auto& cache = MatrixCache::instance();
  const auto* serverCertificate = pki.leaf(policy, CertificateCase::Valid, Role::Server).certificate.get();
  ASSERT_LT(SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss)
              ->asymmetric_plaintext_block_size(serverCertificate),
    4u + 64u + 128u)
    << "the precondition: the legacy secret of a 64-byte password and a 128-byte nonce is more than one "
       "block";
  auto store = make_store(cache.new_directory("legacy_secret_blocks"),
    cache.server_pool().executor(),
    pki.crypto(),
    validation_options_for(CertificateCase::Valid),
    pki.trust_material(family_of(policy)),
    &pki.leaf(policy, CertificateCase::Valid, Role::Server),
    application_certificate_type(policy));
  MatrixServer server(cache.server_pool(),
    pki.crypto(),
    MatrixServer::Options{.policy = policy,
      .mode = MessageSecurityMode::SignAndEncrypt,
      .applicationStore = store,
      .userTokenStore = nullptr,
      .x509Authenticator = nullptr,
      .auditing = false,
      .userTokenSecurityPolicy = std::nullopt,
      .localDiscoveryServer = false,
      .userNameAuthenticator = std::make_shared<server::SimpleUserPasswordAuthenticator>(
        [&rightPassword](std::string_view userName, const ua::SecureString& password)
        { return userName == "test-user" && password.view() == rightPassword; }),
      .userNameSecurityPolicy = SecurityPolicyId::Aes256Sha256RsaPss});
  const auto started = server.start();
  ASSERT_TRUE(started.is_good()) << ua::format(started.status_code());

  auto& client =
    *cache
       .client_for(
         policy, MessageSecurityMode::SignAndEncrypt, validation_options_for(CertificateCase::Valid))
       .client;
  const auto connectWith = [&](std::string password)
  {
    auto config =
      matrix_connection_config(server.endpoint_url(), policy, MessageSecurityMode::SignAndEncrypt);
    config.identity =
      client::UsernamePasswordIdentity{.username = "test-user", .password = std::move(password)};
    config.userTokenPolicyId = "username-secret";
    return reported(client.try_connect_sync(std::move(config)));
  };

  auto accepted = connectWith(rightPassword);
  ASSERT_TRUE(accepted.is_good()) << ua::format(accepted.status_code());
  (void)accepted.value().try_close_sync();

  const auto refused = connectWith(std::string(64, 'q'));
  ASSERT_TRUE(refused.is_bad()) << "a wrong password activated the Session";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadUserAccessDenied)
    << ua::format(refused.status_code());
}
