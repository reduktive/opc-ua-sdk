// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Tests for the concrete tier-1 host shim ua::client::detail::PullCertificateManagerClientHost (client
// design section 8.1A, Slice W6-wire) and the CoreClientImpl start_pull_cert_management wiring + CL-MULTI-001
// latch. The shim IMPLEMENTS the narrow PullCertificateManagerHost interface the own-strand
// PullCertificateManagerImpl consumes, by weak-referencing a real CoreClientImpl: it rehydrates the in-memory
// persisted-request store, the atomic cert/trust-list staging (with the H4(b) cert<=>key/issuer binding
// validation via CoreClientImpl::crypto()), the server-cert revalidation broadcast
// (CoreClientImpl::revalidate_connections_async, W5), the Client-scoped observer fan-out (ClientObserverSink,
// J58/W1), and the Rule-4 cross-strand snapshot.
//
// The GDS transport (open/close + the TrustList / cert-request RPCs) is the deferred W6b wiring: open_gds is
// a source-tagged Bad_NotImplemented DEFER-STUB, so in production mGdsConnection stays null and the RPC
// primitives null-guard it (a source-tagged Bad, never a fake Good). set_gds_connection_for_test injects a
// Connection so the present-branch (W6b-deferred) is exercised too.
//
// A single-thread pool runs the async work (the same substrate as the W5 registry-revalidate + J58 sink
// tests): Client::create binds a periodic trust-list-refresh timer to the executor, so a hand-pumped
// io_context would never drain. Completions / observer fan-out land on a pool worker thread, so the fakes are
// thread-safe and delivery is awaited with a bounded future / poll (a hard FAIL on timeout, never an
// unbounded wait). Every test is falsifiable: it asserts the concrete observable (the exact source tag, the
// staged cert, the round-tripped persisted requests, the delivered observer hook), not merely "did not
// crash".

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen (../connection, via CMake)
#include "stub_x509_certificate.h"  // ua::testing::StubX509Certificate / make_stub_certificate
#include "test_key_cache.h"

#include "ua_application_configuration.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_certificate_store.h"
#include "ua_client.h"
#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_client_test_hooks.h"
#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_translated_node_id.h"
#include "ua_connection_impl_test_access.h"
#include "ua_crypto.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_observer_sink.h"
#include "ua_pull_certificate_manager.h"
#include "ua_pull_certificate_manager_client_host.h"
#include "ua_reconnect_policy.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_trust_list_data_type.h"
#include "ua_x509_certificate.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>
#include <optional>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_components.h"

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::Status;
using ua::VoidResult;
using ua::client::Client;
using ua::client::CoreClientImpl;
using ua::client::CoreClientTestAccess;
using ua::client::PullCertLifecycleEvent;
using ua::client::SecurityObserver;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::PersistedRequest;
using ua::client::detail::PullCertificateManagerClientHost;
using ua::client::detail::ServerCertValidator;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using Host = PullCertificateManagerClientHost;

ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// A ServerCertValidator that counts its invocations then fires Good inline (mirrors the W5 interface).
ServerCertValidator counting_wire_ops(std::shared_ptr<std::atomic<int>> count)
{
  return [count = std::move(count)](std::function<void(VoidResult)> verdict) mutable
  {
    count->fetch_add(1, std::memory_order_relaxed);
    verdict(VoidResult{});
  };
}

// --- A CertificateStore that RECORDS the staging calls the shim's apply_cert_update_async issues. ---
/// A held application certificate that answers only its public key.
class HeldStubCertificate final : public ua::testing::StubX509Certificate
{
public:
  explicit HeldStubCertificate(ua::ByteString publicKey) : mPublicKey(std::move(publicKey))
  {}

  ua::ByteString public_key() const override
  {
    return mPublicKey;
  }

private:
  ua::ByteString mPublicKey;
};

/// The fixture client's configuration: the default with a distinctive ApplicationUri, so an arm can
/// tell "this client's URI" from an empty string.
inline ua::ApplicationConfig client_application_configuration()
{
  auto configuration = ua::ApplicationConfig::load_default();
  configuration.application_description_part().applicationUri = "urn:test:client";
  return configuration;
}

class CapturingCertStore final : public ua::CertificateStore
{
public:
  static std::shared_ptr<CapturingCertStore> create()
  {
    return std::shared_ptr<CapturingCertStore>(new CapturingCertStore());
  }

  std::atomic<int> appCertAdds{0};
  std::atomic<int> trustedReplaces{0};
  std::atomic<int> issuerAdds{0};
  std::atomic<int> issuerReplaces{0};
  // When set, replace_trusted_certificates_async fails - a mid-sequence store step failure the H2 atomicity
  // test uses to prove the own-cert swap (staged LAST) never happens on a trust-list-step failure.
  std::atomic<bool> failReplaceTrusted{false};
  mutable std::mutex mutex;
  std::shared_ptr<const ua::X509Certificate> lastAppCert;  // guarded by mutex
  ua::CertificateType lastAppType{ua::CertificateType::Invalid};  // guarded by mutex
  // The MODELLED issuer set: add appends, replace overwrites - so a test can assert the FINAL issuer contents
  // (H1: a UNION that survives, not an add wiped by a subsequent replace). Guarded by mutex.
  ua::CertificateList issuerSet;
  std::shared_ptr<const ua::AsymmetricKeyPair> lastAppKeys;  // guarded by mutex
  ua::CertificateStore::ApplicationCertificateList heldAppCerts;  // guarded by mutex; what the client holds
  // When set, get_application_certificates_async answers this code without a value. Guarded by mutex.
  std::optional<ua::StatusCode> heldAppCertsAnswer;
  std::atomic<int> validateCalls{0};
  ua::StatusCode validateStatus{ua::Status::Good};
  std::optional<std::string> lastValidatedApplicationUri;  // guarded by mutex
  std::optional<ua::CertificateUse> lastValidatedUse;  // guarded by mutex
  std::shared_ptr<const ua::X509Certificate> lastValidatedCertificate;  // guarded by mutex
  ua::CertificateList lastValidatedAdditionalTrusted;  // guarded by mutex
  ua::CertificateList lastValidatedAdditionalIssuers;  // guarded by mutex

  /// Holds @p publicKey's key pair as an application certificate the client already has, so a
  /// signing-request renewal finds its key.
  void hold_stored_key_pair(ua::ByteString publicKey, std::shared_ptr<const ua::AsymmetricKeyPair> keys,
    ua::CertificateType type = ua::CertificateType::RsaSha256Application)
  {
    ApplicationCertificate entry;
    entry.certificateType = type;
    entry.certificate = std::make_shared<HeldStubCertificate>(std::move(publicKey));
    entry.keys = std::move(keys);
    const std::lock_guard<std::mutex> lock(mutex);
    heldAppCerts.push_back(std::move(entry));
  }

  void add_to_application_certificates_async(
    ApplicationCertificate certificate, CompleteCallback callback) noexcept override
  {
    {
      const std::lock_guard<std::mutex> lock(mutex);
      lastAppCert = certificate.certificate;
      lastAppKeys = certificate.keys;
      lastAppType = certificate.certificateType;
    }
    appCertAdds.fetch_add(1, std::memory_order_release);
    callback(VoidResult{});
  }

  void add_to_issuer_certificates_async(std::vector<std::shared_ptr<const ua::X509Certificate>> certificates,
    CompleteCallback callback) noexcept override
  {
    {
      const std::lock_guard<std::mutex> lock(mutex);
      for (auto& certificate : certificates)
      {
        issuerSet.push_back(certificate);
      }
    }
    issuerAdds.fetch_add(1, std::memory_order_release);
    callback(VoidResult{});
  }

  void replace_trusted_certificates_async(
    ua::CertificateList, ua::CrlList, CompleteCallback callback) noexcept override
  {
    if (failReplaceTrusted.load(std::memory_order_acquire))
    {
      callback(VoidResult{ua::StatusCode{ua::Status::BadInternalError},
        ua::make_error_detail("StoreReplaceTrustedFailed", "injected trusted-replace failure", "test")});
      return;
    }
    trustedReplaces.fetch_add(1, std::memory_order_release);
    callback(VoidResult{});
  }

  void replace_issuer_certificates_async(
    ua::CertificateList certificates, ua::CrlList, CompleteCallback callback) noexcept override
  {
    {
      const std::lock_guard<std::mutex> lock(mutex);
      issuerSet = std::move(certificates);
    }
    issuerReplaces.fetch_add(1, std::memory_order_release);
    callback(VoidResult{});
  }

  // Whether the final modelled issuer set contains @p certificate (by pointer identity).
  bool issuer_set_contains(const std::shared_ptr<const ua::X509Certificate>& certificate)
  {
    const std::lock_guard<std::mutex> lock(mutex);
    for (const auto& held : issuerSet)
    {
      if (held.get() == certificate.get())
      {
        return true;
      }
    }
    return false;
  }

  // ---- remaining surface: inert success (unused by these tests) ----
  void get_application_certificate_async(
    ua::CertificateType, GetApplicationCertificateCallback callback) const noexcept override
  {
    callback(ApplicationCertificateResult{ApplicationCertificate{}});
  }

  void get_application_certificates_async(GetApplicationCertificatesCallback callback) const noexcept override
  {
    ApplicationCertificateList held;
    std::optional<ua::StatusCode> answer;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      held = heldAppCerts;
      answer = heldAppCertsAnswer;
    }
    if (answer)
    {
      callback(ApplicationCertificateListResult{*answer});
      return;
    }
    callback(ApplicationCertificateListResult{std::move(held)});
  }

  void add_to_trusted_certificates_async(
    std::shared_ptr<const ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_trusted_certificates_async(
    std::vector<std::shared_ptr<const ua::X509Certificate>>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(ua::CertificateListResult{ua::CertificateList{}});
  }

  void add_to_issuer_certificates_async(
    std::shared_ptr<const ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(ua::CertificateListResult{ua::CertificateList{}});
  }

  void add_to_rejected_certificates_async(
    std::shared_ptr<const ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(ua::CertificateListResult{ua::CertificateList{}});
  }

  void add_to_trusted_crls_async(
    std::shared_ptr<const ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<std::shared_ptr<const ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(ua::CrlListResult{ua::CrlList{}});
  }

  void add_to_issuer_crls_async(
    std::shared_ptr<const ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void add_to_issuer_crls_async(
    std::vector<std::shared_ptr<const ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(ua::CrlListResult{ua::CrlList{}});
  }

  void remove_from_trusted_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void remove_from_issuer_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }

  void set_validation_options(ua::TrustListValidationOptions) override
  {}

  ua::TrustListValidationOptions validation_options() const override
  {
    return {};
  }

  void refresh_cache(CompleteCallback callback) override
  {
    callback(VoidResult{});
  }

  void validate_certificate_async(ua::CertificateValidationRequest request,
    ua::Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    {
      const std::lock_guard<std::mutex> lock(mutex);
      if (!request.trustedForThisConnection.empty())
        lastValidatedAdditionalTrusted = request.trustedForThisConnection;
      if (!request.presentedIssuers.empty())
        lastValidatedAdditionalIssuers = request.presentedIssuers;
      lastValidatedApplicationUri = request.applicationUri;
      lastValidatedUse = request.use;
      lastValidatedCertificate = request.certificate;
    }
    validateCalls.fetch_add(1, std::memory_order_release);
    if (validateStatus.is_bad())
    {
      callback(VoidResult{validateStatus});
      return;
    }
    callback(VoidResult{});
  }

private:
  CapturingCertStore() = default;
};

// --- A stub cert whose H4(b) binding-relevant accessors (issued_by / public_key / thumbprint / DER) are
//     configurable, so a test can build a matched or a mismatched cert<=>issuer binding with no real crypto.
//     ---
class BindingStubCertificate : public ua::testing::StubX509Certificate
{
public:
  ua::ByteString publicKeyBytes;
  ua::ByteString thumbprintBytes;
  ua::ByteString derBytes{0x30, 0x82, 0x02};
  bool issuedByResult = false;
  // Self-anchored by default (matches StubX509Certificate) so an empty-chain cert passes the H4b
  // self-anchor check; a test sets this false to exercise the unanchored-leaf rejection.
  bool selfSignedResult = true;

  ua::ByteString public_key() const override
  {
    return publicKeyBytes;
  }

  ua::ByteString thumbprint() const override
  {
    return thumbprintBytes;
  }

  ua::ByteString der_encoding() const override
  {
    return derBytes;
  }

  bool issued_by(const ua::X509Certificate&) const override
  {
    return issuedByResult;
  }

  bool self_signed() const override
  {
    return selfSignedResult;
  }

  ua::CertificateKeyAlgorithm keyAlgorithm = ua::CertificateKeyAlgorithm::Rsa;

  ua::CertificateKeyAlgorithm key_algorithm() const override
  {
    return keyAlgorithm;
  }
};

// A thread-safe Client-level SecurityObserver capturing the Client-scoped pull-cert hooks (mirrors J58).
class FakeSecurityObserver : public SecurityObserver
{
public:
  std::atomic<int> certRotated{0};
  std::atomic<int> pullCert{0};
  PullCertLifecycleEvent pullCertEvent{};

  void on_certificate_rotated(const ua::X509Certificate& newCert) override
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mLastRotatedDer = newCert.der_encoding();
    }
    certRotated.fetch_add(1, std::memory_order_release);
  }

  void on_pull_cert_management_lifecycle(const ua::client::Connection*, PullCertLifecycleEvent event,
    std::shared_ptr<const ua::ErrorDetail>) override
  {
    pullCertEvent = event;
    pullCert.fetch_add(1, std::memory_order_release);
  }

  ua::ByteString last_rotated_der()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastRotatedDer;
  }

private:
  std::mutex mMutex;
  ua::ByteString mLastRotatedDer;
};

class PullCertClientHostTest : public ::testing::Test
{
protected:
  boost::asio::thread_pool mPool{1};
  std::shared_ptr<CapturingCertStore> mStore = CapturingCertStore::create();
  // A credential callback so a generated private key can be exported to PEM and re-imported by the shim's H4b
  // key-binding check (both use this same Client crypto, so the credential round-trips).
  std::shared_ptr<const ua::Crypto> mCrypto =
    ua::create_default_crypto([]() { return ua::SecureString{"testpw"}; });
  Client mClient =
    Client::create(mPool.get_executor(), ua::client::CreateConfig{{}, client_application_configuration(), {}},
      ua::client::ClientComponents{.crypto = mCrypto, .applicationGroupCertificateStore = mStore});
  std::shared_ptr<CoreClientImpl> mClientImpl = CoreClientTestAccess::impl(mClient.core());

  std::shared_ptr<Host> make_host(std::shared_ptr<const ua::X509Certificate> ownCert = nullptr)
  {
    return std::make_shared<Host>(std::weak_ptr<CoreClientImpl>(mClientImpl),
      mPool.get_executor(),
      mClientImpl->client_observer_sink(),
      std::move(ownCert),
      Logger{});
  }

  // A host whose weak CoreClientImpl is already expired (a default-constructed weak_ptr never locks), so the
  // client-reaching primitives (apply / revalidate) hit their *ClientGone guard.
  std::shared_ptr<Host> make_host_client_gone()
  {
    return std::make_shared<Host>(std::weak_ptr<CoreClientImpl>{},
      mPool.get_executor(),
      mClientImpl->client_observer_sink(),
      /*ownCert=*/nullptr,
      Logger{});
  }

  /// Awaits an async shim primitive's Result on the pool. A hang FAILs promptly (bounded), never an unbounded
  /// wait.
  template<typename R, typename Invoke>
  R await(Invoke&& invoke)
  {
    std::promise<R> promise;
    auto future = promise.get_future();
    std::function<void(R)> callback = [&promise](R result)
    {
      promise.set_value(std::move(result));
    };
    invoke(callback);
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the shim primitive never completed within 5s";
      return R{ua::StatusCode{ua::Status::BadTimeout},
        ua::make_error_detail("AwaitTimeout", "the shim primitive never completed", "test")};
    }
    return future.get();
  }

  static void wait_for_count(std::atomic<int>& counter, int expected)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (counter.load(std::memory_order_acquire) < expected && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    ASSERT_GE(counter.load(std::memory_order_acquire), expected);
  }

  void TearDown() override
  {
    if (const auto manager = CoreClientTestAccess::pull_cert_manager(*mClientImpl))
    {
      const auto stopped = await<VoidResult>(
        [&manager](std::function<void(VoidResult)> callback) { manager->stop_async(std::move(callback)); });
      EXPECT_TRUE(stopped.is_good()) << "the pull-certificate manager must stop while its pool is alive";
    }

    const auto shutDown = mClient.try_shutdown_sync();
    EXPECT_TRUE(shutDown.is_good()) << "the fixture client must shut down while its pool is alive";
    mClientImpl.reset();
    mPool.join();
  }

  std::shared_ptr<ConnectionImpl> make_connection(const std::shared_ptr<FakeSessionOps>& session,
    const std::shared_ptr<FakeReopen>& reopen, ServerCertValidator validator = {})
  {
    return ConnectionImplTestAccess::create_with_ops(mPool.get_executor(),
      session,
      ConnectionConfig{},
      Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      KeepAlivePolicy{0ms},
      /*clientObserverDefaults=*/{},
      /*enableRedundancy=*/false,
      /*redundancyPolicy=*/{},
      /*redundancyDiscovery=*/{},
      std::move(validator));
  }
};

ua::NodeId default_group_id()
{
  return ua::NodeId{ua::ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup};
}

// ============================================================================
// GDS bootstrap (CL-PULLCRT-001 / CL-PULLCRT-002)
// ============================================================================

// open_gds now drives a REAL Client::connect_async (was a DEFER-STUB). Unit-level: the guard + the fact a
// real connect is attempted. The SignAndEncrypt+Anonymous connect succeeding end-to-end is integration-tested
// against the reference server.

// A destroyed Client short-circuits with a source-tagged client_gone (never a crash / a fake Good).
TEST_F(PullCertClientHostTest, OpenGdsWhenClientExpiredIsSourceTaggedClientGone)
{
  auto host = make_host_client_gone();
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->open_gds_connection_async(Host::GdsConnectionRequest{}, std::move(cb)); });

  EXPECT_TRUE(result.is_bad());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.open_gds.client_gone");
}

// With a live Client, open_gds threads the request into a real connect: an empty endpoint URL is rejected by
// the connect plan (proving a live connect is attempted, not a stubbed Bad_NotImplemented). Falsifiable: the
// old stub returned Bad_NotImplemented with the open_gds.not_implemented source regardless of the request.
TEST_F(PullCertClientHostTest, OpenGdsDrivesARealConnectAndPropagatesItsError)
{
  auto host = make_host();
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->open_gds_connection_async(Host::GdsConnectionRequest{/*endpointUrl=*/}, std::move(cb)); });

  EXPECT_TRUE(result.is_bad());
  ASSERT_NE(result.shared_detail(), nullptr);
  // The connect-plan's empty-URL rejection - NOT the old open_gds DEFER-STUB tag.
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.connect.endpoint_url.empty")
    << "open_gds must drive the real connect path (the connect-plan validation surfaces), not a stub";
}

TEST_F(PullCertClientHostTest, CloseGdsCompletesGood)
{
  auto host = make_host();
  const auto result = await<VoidResult>(
    [&](std::function<void(VoidResult)> cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "close is best-effort Good (nothing to close in production)";
}

// ============================================================================
// Own-cert thumbprint snapshot (CL-PULLCRT-004)
// ============================================================================

// @verifies CL-PULLCRT-004
// @relation(CL-PULLCRT-004, scope=function)
TEST_F(PullCertClientHostTest, ThumbprintIsHexOfOwnCertThumbprint)
{
  auto cert = std::make_shared<BindingStubCertificate>();
  cert->thumbprintBytes = ua::ByteString{0xDE, 0xAD, 0xBE, 0xEF};
  auto host = make_host(cert);
  EXPECT_EQ(host->current_own_cert_thumbprint_sha1(), "deadbeef");
}

TEST_F(PullCertClientHostTest, ThumbprintIsEmptyWithoutOwnCert)
{
  auto host = make_host();
  EXPECT_TRUE(host->current_own_cert_thumbprint_sha1().empty());
}

// ============================================================================
// TrustList / cert-request RPC - null-guarded (production) + present-branch DEFER (W6b)
// ============================================================================

TEST_F(PullCertClientHostTest, ReadTrustListWithoutGdsConnectionIsSourceTaggedBad)
{
  auto host = make_host();
  const auto result =
    await<ua::Result<ua::TrustListDataType>>([&](std::function<void(ua::Result<ua::TrustListDataType>)> cb)
      { host->read_trust_list_async(ua::NodeId{2, 7U}, default_group_id(), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNotConnected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.trust_list.gds_not_open");
}

// GetCertificateStatus without a GDS connection is a source-tagged Bad, never read as "no update required".
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST_F(PullCertClientHostTest, GetCertificateStatusWithoutGdsConnectionIsSourceTaggedBad)
{
  auto host = make_host();
  const auto result = await<ua::Result<bool>>(
    [&](std::function<void(ua::Result<bool>)> cb) {
      host->get_certificate_status_async(ua::NodeId{2, 7U}, default_group_id(), ua::NodeId{}, std::move(cb));
    });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNotConnected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.get_certificate_status");
}

TEST_F(PullCertClientHostTest, ReadLastUpdateTimeWithoutGdsConnectionIsSourceTaggedBad)
{
  auto host = make_host();
  const auto result = await<ua::Result<std::optional<ua::DateTime>>>(
    [&](std::function<void(ua::Result<std::optional<ua::DateTime>>)> cb)
    { host->read_trust_list_last_update_time_async(ua::NodeId{2, 7U}, default_group_id(), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNotConnected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.trust_list_last_update.gds_not_open");
}

TEST_F(PullCertClientHostTest, StartCertificateRequestWithoutGdsConnectionIsSourceTaggedBad)
{
  auto host = make_host();
  const auto result = await<ua::Result<ua::NodeId>>([&](std::function<void(ua::Result<ua::NodeId>)> cb)
    { host->start_certificate_request_async(Host::CertRequestParams{}, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNotConnected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.start_request.gds_not_open");
}

TEST_F(PullCertClientHostTest, FinishCertificateRequestWithoutGdsConnectionIsSourceTaggedBad)
{
  auto host = make_host();
  const auto result = await<ua::Result<Host::FinishCertificateResult>>(
    [&](std::function<void(ua::Result<Host::FinishCertificateResult>)> cb)
    { host->finish_certificate_request_async(default_group_id(), ua::NodeId{2, 0xA1U}, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNotConnected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.finish_request.gds_not_open");
}

TEST_F(PullCertClientHostTest, StartCertificateRequestRejectsConnectionWithoutGdsNamespace)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));
  auto host = make_host();
  host->set_gds_connection_for_test(connection);
  Host::CertRequestParams params;
  params.newKeyPair = true;

  const auto result = await<ua::Result<ua::NodeId>>([&](std::function<void(ua::Result<ua::NodeId>)> callback)
    { host->start_certificate_request_async(std::move(params), std::move(callback)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.start_request.gds_namespace_missing");
}

// @verifies CL-PULLCRT-003
// @relation(CL-PULLCRT-003, scope=function)
TEST_F(PullCertClientHostTest, FinishCertificateRequestRejectsConnectionWithoutGdsNamespace)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));
  auto host = make_host();
  host->set_gds_connection_for_test(connection);

  const auto result = await<ua::Result<Host::FinishCertificateResult>>(
    [&](std::function<void(ua::Result<Host::FinishCertificateResult>)> callback)
    { host->finish_certificate_request_async(ua::NodeId{2, 1U}, ua::NodeId{2, 2U}, std::move(callback)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.finish_request.gds_namespace_missing");
}

// An injected Connection without the standard GDS namespace cannot resolve CertificateDirectory.GetTrustList.
TEST_F(PullCertClientHostTest, ReadTrustListWithoutGdsNamespaceIsSourceTaggedBad)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));

  auto host = make_host();
  host->set_gds_connection_for_test(connection);

  const auto result =
    await<ua::Result<ua::TrustListDataType>>([&](std::function<void(ua::Result<ua::TrustListDataType>)> cb)
      { host->read_trust_list_async(ua::NodeId{2, 7U}, ua::NodeId{ua::ObjectId::Server}, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.trust_list.group_unresolved");
}

TEST_F(PullCertClientHostTest, ReadLastUpdateTimeWithoutGdsNamespaceIsSourceTaggedBad)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));

  auto host = make_host();
  host->set_gds_connection_for_test(connection);

  const auto result = await<ua::Result<std::optional<ua::DateTime>>>(
    [&](std::function<void(ua::Result<std::optional<ua::DateTime>>)> cb)
    {
      host->read_trust_list_last_update_time_async(
        ua::NodeId{2, 7U}, ua::NodeId{ua::ObjectId::Server}, std::move(cb));
    });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.trust_list_last_update.group_unresolved");
}

// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST_F(PullCertClientHostTest, GetCertificateStatusWithoutGdsNamespaceIsSourceTaggedBad)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));

  auto host = make_host();
  host->set_gds_connection_for_test(connection);

  const auto result = await<ua::Result<bool>>(
    [&](std::function<void(ua::Result<bool>)> cb)
    {
      host->get_certificate_status_async(
        ua::NodeId{2, 7U}, ua::NodeId{ua::ObjectId::Server}, ua::NodeId{}, std::move(cb));
    });

  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.get_certificate_status");
}

// A String Directory id is the case a moved-from NodeId loses: the Method lookup must start at the
// Directory the server returned, and the Call must target it, whichever order the compiler builds the
// lookup's arguments in.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST_F(PullCertClientHostTest, GetCertificateStatusCallsTheMethodOnAStringDirectoryId)
{
  constexpr std::uint16_t gdsNamespace = 2;
  const ua::NodeId directoryId{gdsNamespace, ua::String{"Directory"}};
  const ua::NodeId methodId{gdsNamespace, ua::String{"Directory.GetCertificateStatus"}};
  auto session = std::make_shared<FakeSessionOps>();
  session->translateBrowsePaths.set_result_fn(
    [directoryId, methodId](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
      -> ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>
    {
      ua::TranslateBrowsePathsToNodeIdsResponse response;
      for (const auto& path : request.browse_paths())
      {
        ua::BrowsePathResult result;
        ua::BrowsePathTarget target;
        target.target_id() = ua::ExpandedNodeId{
          path.starting_node() == ua::NodeId{ua::ObjectId::ObjectsFolder} ? directoryId : methodId};
        target.remaining_path_index() = ua::client::TranslatedNodeId::fullyResolved;
        result.targets().push_back(std::move(target));
        response.results().push_back(std::move(result));
      }
      return ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)};
    });
  session->read.set_result(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
    {"http://opcfoundation.org/UA/", "urn:test:connection", "http://opcfoundation.org/UA/GDS/"})});
  auto reopen = std::make_shared<FakeReopen>();
  auto connectionImpl = make_connection(session, reopen);
  const auto started = await<VoidResult>(
    [&](std::function<void(VoidResult)> cb) { connectionImpl->start_async(std::move(cb)); });
  ASSERT_TRUE(started.is_good());
  auto connection =
    std::make_shared<ua::client::Connection>(ConnectionHandleFactory::make_connection(connectionImpl));

  auto host = make_host();
  host->set_gds_connection_for_test(connection);

  (void)await<ua::Result<bool>>(
    [&](std::function<void(ua::Result<bool>)> cb)
    {
      host->get_certificate_status_async(
        ua::NodeId{2, 7U}, ua::NodeId{ua::ObjectId::Server}, ua::NodeId{}, std::move(cb));
    });

  const auto translates = session->translateBrowsePaths.requests();
  ASSERT_EQ(translates.size(), 2U);
  ASSERT_EQ(translates[1].browse_paths().size(), 1U);
  EXPECT_EQ(translates[1].browse_paths()[0].starting_node(), directoryId)
    << "the Method lookup must start at the Directory the first lookup returned";
  const auto calls = session->call.requests();
  ASSERT_EQ(calls.size(), 1U);
  ASSERT_EQ(calls[0].methods_to_call().size(), 1U);
  EXPECT_EQ(calls[0].methods_to_call()[0].object_id(), directoryId);
  EXPECT_EQ(calls[0].methods_to_call()[0].method_id(), methodId);
}

// ============================================================================
// Persisted-request IO - in-memory round-trip (CL-PULLCRT-003 / CL-PULLCRT-005, J59)
// ============================================================================

// In-memory round-trip only - this is NOT restart survival, so it does not verify CL-PULLCRT-005 (which
// requires persistence across an SDK restart PLUS atomic apply). The atomic-apply clause is covered by the
// ApplyOwnCertStagedLast... atomicity test; the file-backed persist that survives a restart is a follow-up
// (J59 flags the in-memory default).
TEST_F(PullCertClientHostTest, PersistedRequestsRoundTripThroughInMemoryStore)
{
  auto host = make_host();

  PersistedRequest request;
  request.certificateGroupId = default_group_id();
  request.requestId = ua::NodeId{2, 0xA1B2U};
  request.certThumbprintSha1 = "thumb-A";
  request.persistedAt = ua::DateTime::now();

  const auto write = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->write_persisted_requests_async({request}, std::move(cb)); });
  EXPECT_TRUE(write.is_good());

  const auto read = await<ua::Result<std::vector<PersistedRequest>>>(
    [&](std::function<void(ua::Result<std::vector<PersistedRequest>>)> cb)
    { host->read_persisted_requests_async(std::move(cb)); });
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().size(), 1u);
  EXPECT_EQ(read.value()[0].certThumbprintSha1, "thumb-A");
  EXPECT_EQ(read.value()[0].requestId, request.requestId);
}

TEST_F(PullCertClientHostTest, ReadPersistedRequestsIsEmptyBeforeAnyWrite)
{
  auto host = make_host();
  const auto read = await<ua::Result<std::vector<PersistedRequest>>>(
    [&](std::function<void(ua::Result<std::vector<PersistedRequest>>)> cb)
    { host->read_persisted_requests_async(std::move(cb)); });
  ASSERT_TRUE(read.is_good());
  EXPECT_TRUE(read.value().empty());
}

// ============================================================================
// apply_cert_update - H4(b) binding validation + CertificateStore staging (CL-PULLCRT-005)
// ============================================================================

// A renewed cert whose delivered issuer chain does NOT sign it is rejected (H4b binding) with a source-tagged
// Bad, and the runtime store is NOT touched.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyRejectsUnboundIssuerChainAndDoesNotStage)
{
  auto host = make_host();

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = false;  // the delivered issuer does NOT sign the leaf
  auto issuer = std::make_shared<BindingStubCertificate>();

  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newIssuerChain = {issuer};

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.issuer_unbound");
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "a rejected cert must never be staged";
  EXPECT_EQ(mStore->trustedReplaces.load(), 0);
}

// A renewed cert whose public key does NOT match the delivered private key is rejected (H4b key binding,
// real crypto: the PEM is parsed and its SubjectPublicKeyInfo compared to the cert's public key). Not staged.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyRejectsMismatchedKeyBindingAndDoesNotStage)
{
  auto host = make_host();

  // A real RSA key pair; its DER public key will NOT equal the stub cert's (bogus) public_key() bytes.
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;  // issuer binding passes, so the KEY binding is the check under test
  cert->publicKeyBytes = ua::ByteString{0x01, 0x02, 0x03};  // deliberately not the key's public_key_der()

  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newPrivateKey = keys->private_key_pem();

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.key_mismatch");
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "a key-unbound cert must never be staged";
}

// A validly-bound cert (issuer signs the leaf) + a TrustList commit is staged: the own cert lands in the
// application certificates and the trusted list is replaced.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-004, CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyStagesBoundCertAndTrustList)
{
  // RATIFIED TEST ADAPTATION (group J, B3-5): a renewal without a delivered private key is staged with
  // the key pair the store holds; the store holds one for this (stub) public key.
  auto host = make_host();
  mStore->hold_stored_key_pair(
    {}, mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048));

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;  // the delivered issuer signs the leaf (H4b OK)
  cert->thumbprintBytes = ua::ByteString{0xAB, 0xCD};
  auto issuer = std::make_shared<BindingStubCertificate>();

  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newIssuerChain = {issuer};
  update.newTrustList = ua::TrustListDataType{};  // empty lists - no DER decode needed

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a validly-bound cert + trust list stages successfully";
  EXPECT_EQ(mStore->appCertAdds.load(), 1)
    << "the renewed own cert is staged to the application certificates";
  EXPECT_EQ(mStore->trustedReplaces.load(), 1) << "the pulled trust list replaces the trusted set";
  const std::lock_guard<std::mutex> lock(mStore->mutex);
  EXPECT_EQ(mStore->lastAppCert.get(), cert.get()) << "the exact renewed cert is staged";
  // @verifies CL-PULLCRT-004
  EXPECT_EQ(host->current_own_cert_thumbprint_sha1(), "abcd")
    << "the binding snapshot advances only after the application-certificate store step succeeds";
}

TEST_F(PullCertClientHostTest, ApplyTrustListOnlyStagesTrustedSetWithoutCert)
{
  auto host = make_host();

  Host::CertUpdate update;
  update.newTrustList = ua::TrustListDataType{};  // trust-list-only commit, no cert change

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "no cert change -> no application-cert staging";
  EXPECT_EQ(mStore->trustedReplaces.load(), 1);
}

// H1: a combined update {renewed cert + newIssuerChain=[CA] + newTrustList with EMPTY issuers} must leave the
// CA in the runtime issuer set. The old add-then-replace wiped the just-added chain via the trust-list's
// (empty) issuer replace. The fix composes ONE issuer set = trust-list issuers UNION the chain and does a
// SINGLE replace, so the CA survives.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyUnionsIssuerChainWithTrustListIssuersSoChainSurvives)
{
  auto host = make_host();
  mStore->hold_stored_key_pair({},
    mCrypto->create_asymmetric_key_pair_sync(
      ua::CertificateKeyAlgorithm::Rsa, 2048));  // RATIFIED TEST ADAPTATION (group J, B3-5)

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;  // the delivered issuer signs the leaf (H4b OK)
  auto ca = std::make_shared<BindingStubCertificate>();  // the issuer CA delivered alongside the leaf

  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newIssuerChain = {ca};
  update.newTrustList = ua::TrustListDataType{};  // EMPTY issuer set in the pulled trust list

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(mStore->issuer_set_contains(ca))
    << "the delivered issuer CA must survive in the runtime issuer set - the trust-list issuer replace must "
       "not wipe it (H1: union, not add-then-replace)";
  EXPECT_EQ(mStore->issuerAdds.load(), 0) << "no separate add_to_issuer - the union is one replace";
  EXPECT_EQ(mStore->issuerReplaces.load(), 1) << "the composed issuer set is replaced exactly once";
}

// H2: with the own-cert swap staged LAST, a mid-sequence trust-list step failure leaves the own cert
// UNCHANGED (not swapped), the callback is Bad, and a subsequent retry converges. The old order swapped the
// own cert FIRST, so a later trust-list failure left a half-applied store.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyOwnCertStagedLastSoTrustListFailureLeavesOwnCertUnchanged)
{
  auto host = make_host();
  mStore->hold_stored_key_pair({},
    mCrypto->create_asymmetric_key_pair_sync(
      ua::CertificateKeyAlgorithm::Rsa, 2048));  // RATIFIED TEST ADAPTATION (group J, B3-5)

  auto makeUpdate = []
  {
    auto cert = std::make_shared<BindingStubCertificate>();
    cert->issuedByResult = true;
    auto ca = std::make_shared<BindingStubCertificate>();
    Host::CertUpdate update;
    update.newOwnCert = cert;
    update.newIssuerChain = {ca};
    update.newTrustList = ua::TrustListDataType{};
    return update;
  };

  mStore->failReplaceTrusted.store(true, std::memory_order_release);
  const auto failed = await<VoidResult>(
    [&](std::function<void(VoidResult)> cb) { host->apply_cert_update_async(makeUpdate(), std::move(cb)); });

  EXPECT_TRUE(failed.is_bad()) << "a trust-list step failure fails the apply";
  EXPECT_EQ(mStore->appCertAdds.load(), 0)
    << "the own-cert swap is staged LAST, so a trust-list-step failure never swaps the own cert (H2)";

  // The retry re-converges once the store recovers (idempotent replaces + own-cert-last).
  mStore->failReplaceTrusted.store(false, std::memory_order_release);
  const auto retried = await<VoidResult>(
    [&](std::function<void(VoidResult)> cb) { host->apply_cert_update_async(makeUpdate(), std::move(cb)); });

  ASSERT_TRUE(retried.is_good()) << "a retry after the store recovers converges";
  EXPECT_EQ(mStore->appCertAdds.load(), 1) << "the own cert is now staged (convergence)";
}

// H4b: a renewed leaf that is NOT self-anchored and carries NO issuer chain cannot be bound to a trust
// anchor - it must be rejected (source-tagged), never silently accepted.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplyRejectsUnanchoredLeafWithoutIssuerChain)
{
  auto host = make_host();

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->selfSignedResult = false;  // not self-anchored
  // newIssuerChain intentionally empty

  Host::CertUpdate update;
  update.newOwnCert = cert;

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.issuer_unanchored");
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "an unanchored leaf must never be staged";
}

// H4b: a self-anchored (self-signed) leaf with no issuer chain is self-anchored - it stages.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplySelfSignedLeafWithoutIssuerChainStages)
{
  auto host = make_host();
  mStore->hold_stored_key_pair({},
    mCrypto->create_asymmetric_key_pair_sync(
      ua::CertificateKeyAlgorithm::Rsa, 2048));  // RATIFIED TEST ADAPTATION (group J, B3-5)

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->selfSignedResult = true;  // self-anchored - no chain needed

  Host::CertUpdate update;
  update.newOwnCert = cert;

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a self-anchored leaf stages without an issuer chain";
  EXPECT_EQ(mStore->appCertAdds.load(), 1);
}

// H4b (StartSigningRequest key binding): the client keeps its EXISTING key, so the renewed leaf's public key
// must match the CURRENT own-cert's public key. A mismatch is rejected (source-tagged), not staged.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplySigningRequestRejectsKeyNotMatchingCurrentOwnCert)
{
  auto current = std::make_shared<BindingStubCertificate>();
  current->publicKeyBytes = ua::ByteString{0xAA, 0xBB};
  auto host = make_host(current);  // the on-channel current own cert (StartSigningRequest key source)

  auto renewed = std::make_shared<BindingStubCertificate>();
  renewed->selfSignedResult = true;  // isolate the KEY check (issuer binding trivially passes)
  renewed->publicKeyBytes = ua::ByteString{0xCC, 0xDD};  // a DIFFERENT key than the current own cert

  Host::CertUpdate update;
  update.newOwnCert = renewed;
  // no newPrivateKey -> StartSigningRequest (the client retains its current key)

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.signing_key_mismatch");
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "a signing-request cert with a foreign key must not be staged";
}

// H4b (StartSigningRequest key binding): a renewed leaf carrying the SAME public key as the current own cert
// binds to the retained key and stages.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
TEST_F(PullCertClientHostTest, ApplySigningRequestAcceptsKeyMatchingCurrentOwnCert)
{
  auto current = std::make_shared<BindingStubCertificate>();
  current->publicKeyBytes = ua::ByteString{0xAA, 0xBB};
  auto host = make_host(current);
  mStore->hold_stored_key_pair(ua::ByteString{0xAA, 0xBB},
    mCrypto->create_asymmetric_key_pair_sync(
      ua::CertificateKeyAlgorithm::Rsa, 2048));  // RATIFIED TEST ADAPTATION (group J, B3-5)

  auto renewed = std::make_shared<BindingStubCertificate>();
  renewed->selfSignedResult = true;
  renewed->publicKeyBytes = ua::ByteString{0xAA, 0xBB};  // SAME key as the current own cert

  Host::CertUpdate update;
  update.newOwnCert = renewed;

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a signing-request cert with the retained key stages";
  EXPECT_EQ(mStore->appCertAdds.load(), 1);
}

// A host whose CoreClientImpl has expired rejects apply with the source-tagged *ClientGone (never a silent
// drop).
TEST_F(PullCertClientHostTest, ApplyWhenClientExpiredIsSourceTaggedClientGone)
{
  auto host = make_host_client_gone();

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->selfSignedResult = true;
  Host::CertUpdate update;
  update.newOwnCert = cert;

  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidState);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.client_gone");
}

// ============================================================================
// Revalidation broadcast - forwards to CoreClientImpl::revalidate_connections_async (CL-PULLCRT-006)
// ============================================================================

// @verifies CL-PULLCRT-006
// @relation(CL-PULLCRT-006, scope=function)
TEST_F(PullCertClientHostTest, RevalidateForwardsToClientImplWalk)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls));
  mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));

  auto host = make_host();
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->revalidate_connections_async(false, true, std::move(cb)); });

  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(wireOpCalls->load(), 1) << "the shim's revalidate walks the Client's Connection registry (W5)";
}

// A host whose CoreClientImpl has expired rejects revalidate with the source-tagged *ClientGone.
TEST_F(PullCertClientHostTest, RevalidateWhenClientExpiredIsSourceTaggedClientGone)
{
  auto host = make_host_client_gone();
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->revalidate_connections_async(false, true, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidState);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.revalidate.client_gone");
}

// ============================================================================
// Observer fan-out - routed to the Client-scoped ClientObserverSink (CL-RECONN-006 / section 8.1A.1)
// ============================================================================

TEST_F(PullCertClientHostTest, CertificateRotatedFiresClientSecurityObserver)
{
  auto observer = std::make_shared<FakeSecurityObserver>();
  mClient.set_security_observer(observer);

  auto host = make_host();
  const auto cert = ua::testing::make_stub_certificate();
  host->fire_observer_certificate_rotated(cert);

  wait_for_count(observer->certRotated, 1);
  EXPECT_EQ(observer->last_rotated_der(), cert->der_encoding())
    << "the rotated cert is delivered intact to the Client-level SecurityObserver";
}

TEST_F(PullCertClientHostTest, PullCertLifecycleFiresClientSecurityObserver)
{
  auto observer = std::make_shared<FakeSecurityObserver>();
  mClient.set_security_observer(observer);

  auto host = make_host();
  host->fire_observer_pull_cert_lifecycle(PullCertLifecycleEvent::CertificateCommitted, nullptr);

  wait_for_count(observer->pullCert, 1);
  EXPECT_EQ(observer->pullCertEvent, PullCertLifecycleEvent::CertificateCommitted);
}

// ============================================================================
// Rule-4 cross-strand snapshot
// ============================================================================

TEST_F(PullCertClientHostTest, PublishInfoSnapshotIsReadableBack)
{
  auto host = make_host();
  auto info = std::make_shared<ua::client::PullCertManagementInfo>();
  info->state = ua::client::PullCertManagementState::Idle;
  info->failureCount = 7;
  host->publish_info_snapshot(info);

  const auto snapshot = host->info_snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->failureCount, 7u);
  EXPECT_EQ(snapshot.get(), info.get()) << "the published pointer is stored verbatim (lock-free load)";
}

// ============================================================================
// CoreClientImpl start_pull_cert_management + CL-MULTI-001
// ============================================================================

ua::client::PullCertManagementConfig pull_config(std::shared_ptr<ua::CertificateStore> store)
{
  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = "opc.tcp://gds";
  config.bootstrapTrustStore = store;
  config.runtimeCertStore = std::move(store);
  return config;
}

CoreClientImpl::PullCertManagementResult start_once(
  CoreClientImpl& impl, const ua::client::PullCertManagementConfig& config)
{
  std::promise<CoreClientImpl::PullCertManagementResult> promise;
  auto future = promise.get_future();
  impl.start_pull_cert_management_async(config,
    [&promise](CoreClientImpl::PullCertManagementResult started) { promise.set_value(std::move(started)); });
  EXPECT_EQ(future.wait_for(5s), std::future_status::ready);
  return future.get();
}

// @verifies CL-PULLCRT-001
// @relation(CL-PULLCRT-001, scope=function)
TEST_F(PullCertClientHostTest, StartPullCertManagementConstructsManagerOnce)
{
  const auto result = start_once(*mClientImpl, pull_config(mStore));

  ASSERT_TRUE(result.is_good()) << "the first start constructs the manager";
  EXPECT_NE(result.value(), nullptr);
  EXPECT_EQ(CoreClientTestAccess::pull_cert_manager(*mClientImpl).get(), result.value().get())
    << "ClientImpl holds the write-once manager it handed back";
  EXPECT_NE(CoreClientTestAccess::pull_cert_host(*mClientImpl), nullptr) << "the shim is owned by ClientImpl";
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST_F(PullCertClientHostTest, SecondStartReturnsBadAlreadyExists)
{
  const auto config = pull_config(mStore);

  const auto first = start_once(*mClientImpl, config);
  ASSERT_TRUE(first.is_good());

  const auto second = start_once(*mClientImpl, config);
  EXPECT_EQ(second.status_code().as_status(), Status::BadAlreadyExists)
    << "a second live start is rejected (CL-MULTI-001)";
  ASSERT_NE(second.shared_detail(), nullptr);
  EXPECT_EQ(second.shared_detail()->source, "client.tier1.pull_cert.start.already_exists");
}

// The public Client::start_pull_cert_management_sync facade forwards to CoreClientImpl and hands back the
// manager handle; a second start is rejected (CL-MULTI-001), surfaced through try_*_sync as a bad Result.
// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST_F(PullCertClientHostTest, StartPullCertManagementFacadeForwardsAndRejectsSecondStart)
{
  const auto config = pull_config(mStore);

  const auto first = mClient.try_start_pull_cert_management_sync(config);
  ASSERT_TRUE(first.is_good()) << "the facade forwards the first start to ClientImpl";
  EXPECT_NE(first.value(), nullptr) << "the facade hands back the manager handle";
  EXPECT_EQ(CoreClientTestAccess::pull_cert_manager(*mClientImpl).get(), first.value().get())
    << "the handle the facade returns is the write-once ClientImpl manager";

  const auto second = mClient.try_start_pull_cert_management_sync(config);
  EXPECT_EQ(second.status_code().as_status(), Status::BadAlreadyExists)
    << "a second live start through the facade is rejected (CL-MULTI-001)";
}

}  // namespace

// The renewed certificate is validated through the store with the delivered chain and THIS client's
// ApplicationUri before anything is staged; the issuer binding alone verifies no signature and no
// identity (security review B3-5).
// @verifies AC-CL-PULLCRT-005-A-RENEWED-CERTIFICATE-IS-VALIDATED-BEFORE-IT-IS-STAGED
TEST_F(PullCertClientHostTest, ApplyValidatesTheRenewedCertificateWithTheClientsApplicationUri)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;
  cert->publicKeyBytes = keys->public_key_der();
  auto issuer = std::make_shared<BindingStubCertificate>();
  auto host = make_host();
  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newPrivateKey = keys->private_key_pem();
  update.newIssuerChain = {issuer};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  EXPECT_EQ(mStore->validateCalls.load(), 1);
  const std::lock_guard<std::mutex> lock(mStore->mutex);
  ASSERT_TRUE(mStore->lastValidatedApplicationUri.has_value());
  EXPECT_EQ(*mStore->lastValidatedApplicationUri, "urn:test:client");
  EXPECT_EQ(mStore->lastValidatedUse, ua::CertificateUse::ClientApplicationInstance)
    << "the renewed certificate is this client's own, so it must carry clientAuth";
  ASSERT_EQ(mStore->lastValidatedAdditionalIssuers.size(), 1u)
    << "the delivered chain is the additional issuer";
  EXPECT_EQ(mStore->lastValidatedAdditionalIssuers.front().get(), issuer.get());
  EXPECT_EQ(mStore->lastValidatedCertificate.get(), cert.get());
}

// The GDS delivers the key unprotected, because the manager requests it without a password (OPC 10000-12
// 7.9.5). The host reads it with the application's own Crypto and stages it with the certificate.
// @relation(AC-CL-PULLCRT-005-A-GDS-GENERATED-KEY-IS-REQUESTED-UNPROTECTED-AND-HELD-UNDER-THE-APPLICATION-CREDENTIAL, scope=function)
TEST_F(PullCertClientHostTest, ApplyStagesAnUnprotectedDeliveredKey)
{
  const std::string& unprotected = ua::test_keys::private_key_pem(ua::test_keys::KeyType::P256, 0);
  const ua::ByteString pem{std::vector<ua::byte>(reinterpret_cast<const ua::byte*>(unprotected.data()),
    reinterpret_cast<const ua::byte*>(unprotected.data()) + unprotected.size())};
  std::vector<ua::byte> copy(pem.size());
  std::memcpy(copy.data(), pem.data(), pem.size());
  const auto keys =
    mCrypto->get_private_key_from_pem(ua::CertificateKeyAlgorithm::EccNistP256, ua::span<ua::byte>{copy});
  ASSERT_NE(keys, nullptr);

  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;
  cert->keyAlgorithm = ua::CertificateKeyAlgorithm::EccNistP256;
  cert->publicKeyBytes = keys->public_key_der();
  auto host = make_host();
  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newPrivateKey = pem;
  update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  EXPECT_EQ(mStore->appCertAdds.load(), 1);
  const std::lock_guard<std::mutex> lock(mStore->mutex);
  ASSERT_NE(mStore->lastAppKeys, nullptr);
  EXPECT_EQ(mStore->lastAppKeys->public_key_der(), keys->public_key_der()) << "the delivered key is staged";
}

// A GDS-issued ECC certificate is staged under its curve's type: the store keeps one certificate per curve
// and has no slot for the generic EccApplication type, so a commit under it fails (found end to end by
// GdsPullProvisioning.RsaAndEccCertificatesOfOneGroupAreObtainedInOneCycle). A key the store cannot hold is
// refused before anything is staged.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST_F(PullCertClientHostTest, AnEccCertificateIsStagedUnderItsCurvesType)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::EccNistP256, 256);
  ASSERT_NE(keys, nullptr);
  auto host = make_host();
  const auto apply = [&](ua::CertificateKeyAlgorithm algorithm)
  {
    auto cert = std::make_shared<BindingStubCertificate>();
    cert->issuedByResult = true;
    cert->keyAlgorithm = algorithm;
    cert->publicKeyBytes = keys->public_key_der();
    Host::CertUpdate update;
    update.newOwnCert = cert;
    update.newPrivateKey = keys->private_key_pem();
    update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
    return await<VoidResult>([&](std::function<void(VoidResult)> cb)
      { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  };

  const auto staged = apply(ua::CertificateKeyAlgorithm::EccNistP256);
  ASSERT_TRUE(staged.is_good()) << to_string(staged.status_code());
  {
    const std::lock_guard<std::mutex> lock(mStore->mutex);
    EXPECT_EQ(mStore->lastAppType, ua::CertificateType::EccNistP256Application);
  }

  const auto refused = apply(ua::CertificateKeyAlgorithm::EccNistP521);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->source, "client.tier1.pull_cert.apply.type_unsupported");
  EXPECT_EQ(mStore->appCertAdds.load(), 1) << "the unsupported key is never staged";
}

// A renewed certificate the store refuses is not staged, and the refusal carries the cause.
// @verifies AC-CL-PULLCRT-005-A-RENEWED-CERTIFICATE-IS-VALIDATED-BEFORE-IT-IS-STAGED
TEST_F(PullCertClientHostTest, ApplyRejectsARenewedCertificateTheStoreDoesNotValidate)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto cert = std::make_shared<BindingStubCertificate>();
  cert->issuedByResult = true;
  cert->publicKeyBytes = keys->public_key_der();
  auto host = make_host();
  mStore->validateStatus = ua::StatusCode{ua::Status::BadCertificateUriInvalid};
  Host::CertUpdate update;
  update.newOwnCert = cert;
  update.newPrivateKey = keys->private_key_pem();
  update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.validation_failed");
  EXPECT_EQ(
    result.shared_detail()->innerStatus, ua::utils::to_underlying(ua::Status::BadCertificateUriInvalid))
    << "the store's refusal is carried as the cause";
  EXPECT_EQ(mStore->appCertAdds.load(), 0) << "a certificate the store refuses is never staged";
}

// StartSigningRequest renewal: the client kept its key pair, so the renewed certificate is staged with
// the key pair the store holds for that public key (before, a null key pair reached the store and
// crashed the client after the certificate file had been overwritten).
// @verifies AC-CL-PULLCRT-005-A-SIGNING-REQUEST-RENEWAL-IS-STAGED-WITH-THE-EXISTING-KEY-PAIR
TEST_F(PullCertClientHostTest, ApplyStagesASigningRequestRenewalWithTheStoredKeyPair)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto current = std::make_shared<BindingStubCertificate>();
  current->publicKeyBytes = keys->public_key_der();
  mStore->hold_stored_key_pair(keys->public_key_der(), keys, ua::CertificateType::RsaMinApplication);
  auto renewed = std::make_shared<BindingStubCertificate>();
  renewed->issuedByResult = true;
  renewed->publicKeyBytes = keys->public_key_der();  // the same key, as a signing-request renewal has
  auto host = make_host(current);
  Host::CertUpdate update;
  update.newOwnCert = renewed;  // no newPrivateKey: the signing-request branch
  update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  EXPECT_EQ(mStore->appCertAdds.load(), 1);
  const std::lock_guard<std::mutex> lock(mStore->mutex);
  EXPECT_EQ(mStore->lastAppCert.get(), renewed.get());
  EXPECT_EQ(mStore->lastAppKeys.get(), keys.get()) << "staged with the stored key pair, never a null one";
  EXPECT_EQ(mStore->lastAppType, ua::CertificateType::RsaMinApplication)
    << "staged under the stored certificate's type";
}

// When the store holds no key pair for the renewed certificate's public key, the certificate is not
// staged at all (rather than staged without its key).
// @verifies AC-CL-PULLCRT-005-A-SIGNING-REQUEST-RENEWAL-IS-STAGED-WITH-THE-EXISTING-KEY-PAIR
TEST_F(PullCertClientHostTest, ApplyRefusesASigningRequestRenewalWhoseKeyPairTheStoreDoesNotHold)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto current = std::make_shared<BindingStubCertificate>();
  current->publicKeyBytes = keys->public_key_der();
  auto renewed = std::make_shared<BindingStubCertificate>();
  renewed->issuedByResult = true;
  renewed->publicKeyBytes = keys->public_key_der();
  auto host = make_host(current);
  Host::CertUpdate update;
  update.newOwnCert = renewed;
  update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.existing_key_absent");
  EXPECT_EQ(mStore->appCertAdds.load(), 0);
  EXPECT_EQ(mStore->issuerAdds.load(), 0) << "nothing is staged: the lookup runs before the issuer step";
  EXPECT_EQ(mStore->issuerReplaces.load(), 0);
}

// A signing-request renewal whose held-key-pair lookup the store answers Uncertain: the answer is not used,
// the update fails with Bad_InternalError and the CertificateStoreAnswerUncertain detail whose cause is the
// store's code, and nothing is staged.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(PullCertClientHostTest, ApplyRefusesAnUncertainHeldKeyPairAnswer)
{
  const auto keys = mCrypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto current = std::make_shared<BindingStubCertificate>();
  current->publicKeyBytes = keys->public_key_der();
  mStore->hold_stored_key_pair(keys->public_key_der(), keys, ua::CertificateType::RsaMinApplication);
  const ua::StatusCode uncertain{ua::Status::UncertainLastUsableValue};
  {
    const std::lock_guard<std::mutex> lock(mStore->mutex);
    mStore->heldAppCertsAnswer = uncertain;
  }
  auto renewed = std::make_shared<BindingStubCertificate>();
  renewed->issuedByResult = true;
  renewed->publicKeyBytes = keys->public_key_der();
  auto host = make_host(current);
  Host::CertUpdate update;
  update.newOwnCert = renewed;  // no newPrivateKey: the signing-request branch looks the key pair up
  update.newIssuerChain = {std::make_shared<BindingStubCertificate>()};
  const auto result = await<VoidResult>([&](std::function<void(VoidResult)> cb)
    { host->apply_cert_update_async(std::move(update), std::move(cb)); });
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateStoreAnswerUncertain");
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.apply.existing_key_absent");
  EXPECT_EQ(result.shared_detail()->innerStatus, uncertain.value()) << "the store's code is the cause";
  EXPECT_EQ(mStore->appCertAdds.load(), 0);
  EXPECT_EQ(mStore->issuerAdds.load(), 0) << "nothing is staged: the lookup runs before the issuer step";
  EXPECT_EQ(mStore->issuerReplaces.load(), 0);
}
