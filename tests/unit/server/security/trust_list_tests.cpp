// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for TrustListManager - strand-serialized component managing TrustListType FileType protocol.

#include <gtest/gtest.h>
#include "fmt/ranges.h"
#include "fmt/format.h"

#include <fstream>
#include <sstream>
#include <limits>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "test_key_cache.h"
#include "test_utilities.h"
#include <boost/asio/strand.hpp>

#include "ua_trust_list_manager.h"
#include "ua_trust_list_manager_test_access.h"
#include "ua_certificate_push_service.h"
#include "ua_error_chain.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "fake_certificate_store.h"
#include "fake_async_crypto.h"

#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_encoding_limits.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_objecttype_id.h"
#include "ua_server_observer.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_trust_list_data_type.h"
#include "ua_error_detail_keys.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"
#include "test_pki_helpers.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "ua_fmt.h"

#include <fmt/format.h>
#include <fmt/ranges.h>

#include "ua_byte_format.h"

// Renders a status's ErrorDetail chain, so a failing assertion names the step that gave up rather
// than only the code. CreateSigningRequest is a fourteen-step flow whose abandon sites all answer
// Bad_InternalError; without this the failure is unattributable.
std::string describe_chain(const ua::StatusCode& status)
{
  std::string out;
  for (const auto& link : ua::ErrorChainView{status})
  {
    out += "[" + link.source + " " + link.code + ": " + link.summary;
    if (!link.detail.empty())
      out += " | " + link.detail;
    for (const auto& kv : link.context)
      out += " | " + kv.key + "=" + kv.value;
    out += "] ";
  }
  return out.empty() ? std::string{"<no ErrorDetail>"} : out;
}

using namespace ua;
using namespace std::chrono_literals;

// The value an ErrorDetail's context holds under @p key, or empty.
std::string context_value(const ua::ErrorDetail& detail, std::string_view key)
{
  for (const auto& entry : detail.context)
    if (entry.key == key)
      return entry.value;
  return {};
}

namespace
{

// Checks that @p status refuses an answer given as Uncertain_LastUsableValue: Bad_InternalError whose
// ErrorDetail is @p code, with the Uncertain code as its inner status.
void expect_uncertain_answer_refusal(const ua::StatusCode& status, std::string_view code)
{
  EXPECT_EQ(status.as_status(), ua::Status::BadInternalError) << describe_chain(status);
  ASSERT_NE(status.shared_detail(), nullptr) << describe_chain(status);
  EXPECT_EQ(status.shared_detail()->code, code);
  EXPECT_EQ(
    status.shared_detail()->innerStatus, ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
}

}  // namespace

namespace ua
{
std::ostream& operator<<(std::ostream& os, const StatusCode& sc)
{
  return os << fmt::format("{}", sc);
}
}  // namespace ua

namespace
{

using InMemoryFakeCertificateStore = ua::test_helpers::InMemoryFakeCertificateStore;
using FakeAsyncCrypto = ua::test_helpers::FakeAsyncCrypto;

shared_ptr<const X509Crl> make_u5_out_of_date_crl(const Crypto& crypto, TestPki& pki,
  const shared_ptr<const X509Certificate>& issuer, const shared_ptr<const AsymmetricKeyPair>& issuerKeys);

/// Buffers every message a logger emits, so a test can assert what was (or was not) logged.
class RecordingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    const std::lock_guard lock(mMutex);
    mMessages.emplace_back(entry.message);
  }

  [[nodiscard]] bool saw(std::string_view fragment) const
  {
    const std::lock_guard lock(mMutex);
    return std::any_of(mMessages.begin(),
      mMessages.end(),
      [fragment](const std::string& message) { return message.find(fragment) != std::string::npos; });
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mMessages;
};

// ============================================================================
// Test fixture
// ============================================================================

class TrustListTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    mPki = std::make_unique<TestPki>(mCrypto);

    // Generate a CA key pair and root CA cert
    mCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mCaCert = mPki->create_root_ca(mCaKeys);

    // Generate a leaf key pair and cert
    mLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    auto now = DateTime::now();
    mLeafCert = mPki->create_leaf_cert(
      mLeafKeys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{30}}, {}, {}, "LeafCert");

    // Generate a second leaf cert for multi-cert tests
    mLeaf2Keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mLeaf2Cert = mPki->create_leaf_cert(
      mLeaf2Keys, mCaKeys, mCaCert, now, DateTime{now.value() + std::chrono::days{30}}, {}, {}, "LeafCert2");

    // Create a CRL
    mCrl = mPki->create_crl(mCaCert, mCaKeys, {});

    // Set up fake store with trusted cert and issuer cert
    mFakeStore = std::make_shared<InMemoryFakeCertificateStore>();
    mFakeStore->trustedCerts.push_back(mLeafCert);
    mFakeStore->issuerCerts.push_back(mCaCert);
    mFakeStore->trustedCrls.push_back(mCrl);
  }

  void TearDown() override
  {
    if (mManager)
    {
      mManager->shutdown();
    }
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// Create the TrustListManager with default dependencies.
  /// Call after SetUp() when you may want to customize mFakeStore first.
  std::shared_ptr<TrustListManager> create_manager(
    uint32_t maxSize = 65535, std::chrono::milliseconds activityTimeout = 60000ms)
  {
    TrustListManager::Dependencies deps{
      .strand = boost::asio::make_strand(mPool.get_executor()),
      .certificateStore = mFakeStore,
      .crypto = mCrypto,
      .executor = mPool.get_executor(),
      .maxTrustListSize = maxSize,
      .activityTimeout = activityTimeout,
      .logger = mManagerLogger,
      .modificationClaim = make_modification_claim(),
      .openedForWrite = mOpenedForWrite,
      .stageUntilApply = mStageUntilApply,
      .resetWaitLimit = mResetWaitLimit,
    };
    // The manager reads the group's options from the store when each validation starts.
    mFakeStore->set_validation_options(mValidationOptions);

    mManager = TrustListManager::create(std::move(deps), mModifiedCallback);
    return mManager;
  }

  // --- Helper: synchronous wrappers using promise/future on main test thread ---

  Result<uint32_t> open_sync(const NodeId& sessionId, uint8_t mode)
  {
    std::promise<Result<uint32_t>> p;
    mManager->open_async(sessionId,
      mode,
      [this, &p](Result<uint32_t> r)
      {
        ++mOpenCompletionCount;
        p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  Result<uint32_t> open_with_masks_sync(const NodeId& sessionId, uint32_t masks)
  {
    std::promise<Result<uint32_t>> p;
    mManager->open_with_masks_async(sessionId,
      masks,
      [this, &p](Result<uint32_t> r)
      {
        ++mOpenWithMasksCompletionCount;
        p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  VoidResult close_sync(const NodeId& sessionId, uint32_t handle)
  {
    std::promise<VoidResult> p;
    mManager->close_async(sessionId, handle, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  Result<ByteString> read_sync(const NodeId& sessionId, uint32_t handle, int32_t length)
  {
    std::promise<Result<ByteString>> p;
    mManager->read_async(
      sessionId, handle, length, [&p](Result<ByteString> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  VoidResult write_sync(const NodeId& sessionId, uint32_t handle, ByteString data)
  {
    std::promise<VoidResult> p;
    mManager->write_async(
      sessionId, handle, std::move(data), [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  Result<uint64_t> get_position_sync(const NodeId& sessionId, uint32_t handle)
  {
    std::promise<Result<uint64_t>> p;
    mManager->get_position_async(sessionId, handle, [&p](Result<uint64_t> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  VoidResult set_position_sync(const NodeId& sessionId, uint32_t handle, uint64_t position)
  {
    std::promise<VoidResult> p;
    mManager->set_position_async(
      sessionId, handle, position, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  Result<bool> close_and_update_sync(const NodeId& sessionId, uint32_t handle)
  {
    std::promise<Result<bool>> p;
    mManager->close_and_update_async(sessionId,
      handle,
      [this, &p](Result<bool> r)
      {
        ++mCloseAndUpdateCompletionCount;
        p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  VoidResult add_certificate_sync(const NodeId& sessionId, ByteString cert, bool isTrusted)
  {
    std::promise<VoidResult> p;
    mManager->add_certificate_async(sessionId,
      std::move(cert),
      isTrusted,
      [this, &p](VoidResult r)
      {
        ++mAddCertificateCompletionCount;
        p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  VoidResult remove_certificate_sync(const NodeId& sessionId, std::string thumbprint, bool isTrusted)
  {
    std::promise<VoidResult> p;
    mManager->remove_certificate_async(sessionId,
      std::move(thumbprint),
      isTrusted,
      [this, &p](VoidResult r)
      {
        ++mRemoveCertificateCompletionCount;
        p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  Result<bool> is_write_open_sync()
  {
    std::promise<Result<bool>> p;
    mManager->is_write_open_async([&p](Result<bool> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  /// Encode a TrustListDataType to UA Binary for use in write tests.
  ByteString encode_trust_list(const TrustListDataType& trustList)
  {
    memory_stream_device::Dynamic encDevice(65535, true);
    MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
    UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
    encoder.encode(EncodingLimits{}.stack_depth(), trustList);
    auto data = encDevice.get_data();
    return ByteString{data};
  }

  /// Get thumbprint as hex string (matching CertificateStoreFiles format).
  std::string thumbprint_hex(const shared_ptr<const X509Certificate>& cert)
  {
    return fmt::format("{:02X}", fmt::join(cert->thumbprint(), ""));
  }

  // Fixtures
  boost::asio::thread_pool mPool{1};
  std::shared_ptr<const Crypto> mCrypto;
  std::unique_ptr<TestPki> mPki;

  shared_ptr<const AsymmetricKeyPair> mCaKeys;
  shared_ptr<const X509Certificate> mCaCert;
  shared_ptr<const AsymmetricKeyPair> mLeafKeys;
  shared_ptr<const X509Certificate> mLeafCert;
  shared_ptr<const AsymmetricKeyPair> mLeaf2Keys;
  shared_ptr<const X509Certificate> mLeaf2Cert;
  shared_ptr<const X509Crl> mCrl;

  std::shared_ptr<InMemoryFakeCertificateStore> mFakeStore;
  std::shared_ptr<TrustListManager> mManager;
  /// The certificate group's validation options a test sets before create_manager() (default: none).
  TrustListValidationOptions mValidationOptions{};
  /// The server's wiring: a CloseAndUpdate is staged until ApplyChanges (set before create_manager()).
  bool mStageUntilApply{false};
  /// The Open-for-write notification (null: none wired).
  std::function<void(NodeId, std::shared_ptr<TrustListModificationClaim>)> mOpenedForWrite;
  Logger mManagerLogger{};  // the manager's logger (set before create_manager())
  // Long, so a test's "not answered yet" window never meets it; the wait-limit test shortens it.
  std::chrono::milliseconds mResetWaitLimit{30000};

  VoidResult apply_staged_sync()
  {
    std::promise<VoidResult> p;
    mManager->apply_staged_async([&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  std::optional<ua::detail::TrustListContent> staged_lists_sync()
  {
    std::promise<std::optional<ua::detail::TrustListContent>> p;
    mManager->staged_lists_async(
      [&p](std::optional<ua::detail::TrustListContent> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  /// Open(Write|EraseExisting) -> Write(@p trustList) -> CloseAndUpdate, as session A.
  Result<bool> update_trust_list_sync(const TrustListDataType& trustList)
  {
    auto opened = open_sync(mSessionA, 0x06);
    if (opened.is_bad())
      return opened.status_code();
    auto written = write_sync(mSessionA, opened.value(), encode_trust_list(trustList));
    if (written.is_bad())
      return written.status_code();
    return close_and_update_sync(mSessionA, opened.value());
  }

  /// The TrustList as a Read of it returns it, decoded.
  TrustListDataType read_trust_list_sync()
  {
    auto opened = open_sync(mSessionA, 0x01);
    EXPECT_TRUE(opened.is_good());
    auto data = read_sync(mSessionA, opened.value(), 65535);
    EXPECT_TRUE(data.is_good());
    (void)close_sync(mSessionA, opened.value());
    auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.value().data()), data.value().size()};
    memory_stream_device::ExternalReadOnly readDevice(dataSpan);
    MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
    UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});
    TrustListDataType trustList;
    decoder.decode(EncodingLimits{}.stack_depth(), trustList);
    return trustList;
  }

  /// The push transaction gate a test installs before create_manager() (null: every change allowed).
  std::function<StatusCode(const NodeId&)> mModificationGate;
  std::vector<NodeId> mAbandonedSessionIds;  // guarded by mModifiedMutex

  /// The claim source create_manager() wires: refused where mModificationGate refuses, otherwise a
  /// claim whose release is recorded in mAbandonedSessionIds (no gate: claims that record nothing).
  std::function<Result<std::shared_ptr<TrustListModificationClaim>>(const NodeId&)> make_modification_claim()
  {
    if (!mModificationGate)
      return nullptr;
    return [this, gate = mModificationGate](
             const NodeId& session) -> Result<std::shared_ptr<TrustListModificationClaim>>
    {
      if (auto status = gate(session); status.is_bad())
        return status;
      return std::make_shared<TrustListModificationClaim>(
        [this, session]()
        {
          std::lock_guard lock(mModifiedMutex);
          mAbandonedSessionIds.push_back(session);
        },
        mClaimGeneration.load());
    };
  }

  /// The push transaction the claims name (TrustListModificationClaim::transaction_generation).
  std::atomic<uint64_t> mClaimGeneration{0};

  size_t abandoned_count()
  {
    std::lock_guard lock(mModifiedMutex);
    return mAbandonedSessionIds.size();
  }

  std::atomic<size_t> mOpenCompletionCount{0};
  std::atomic<size_t> mOpenWithMasksCompletionCount{0};
  std::atomic<size_t> mCloseAndUpdateCompletionCount{0};
  std::atomic<size_t> mAddCertificateCompletionCount{0};
  std::atomic<size_t> mRemoveCertificateCompletionCount{0};

  // Track modification callbacks via promise/future.
  // Each test that expects a callback installs a fresh promise via reset_modified_promise().
  std::mutex mModifiedMutex;
  std::vector<NodeId> mModifiedSessionIds;
  std::shared_ptr<std::promise<NodeId>> mModifiedPromise;
  // The claims applied modifications handed over: kept, as the push transaction keeps them.
  std::vector<std::shared_ptr<TrustListModificationClaim>> mCommittedClaims;  // guarded by mModifiedMutex

  TrustListManager::TrustListModifiedCallback mModifiedCallback =
    [this](NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
  {
    std::shared_ptr<std::promise<NodeId>> p;
    {
      std::lock_guard lock(mModifiedMutex);
      mModifiedSessionIds.push_back(sessionId);
      mCommittedClaims.push_back(std::move(claim));
      p = mModifiedPromise;
    }
    if (p)
      p->set_value(std::move(sessionId));
  };

  /// Install a fresh promise; return the future. Call before the operation that triggers modification.
  std::future<NodeId> expect_modified()
  {
    std::lock_guard lock(mModifiedMutex);
    mModifiedPromise = std::make_shared<std::promise<NodeId>>();
    return mModifiedPromise->get_future();
  }

  // Common session IDs
  NodeId mSessionA{1, 1};
  NodeId mSessionB{1, 2};
};

// ============================================================================
// FileType: Open
// ============================================================================

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-01-OPEN, scope=function)
TEST_F(TrustListTest, OpenRead_ReturnsHandle)
{
  create_manager();

  auto result = open_sync(mSessionA, 0x01);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_GT(result.value(), 0u);
  EXPECT_EQ(mFakeStore->trustedCertificateCallCount, 1u);
  EXPECT_EQ(mOpenCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-01-OPEN, scope=function)
TEST_F(TrustListTest, OpenReadStoreFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadCommunicationError,
    make_error_detail(
      "TrustListReadUnavailable", "Trusted certificate list is unavailable", "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->trustedCertificateResults.emplace_back(upstream);

  create_manager();

  auto result = open_sync(mSessionA, 0x01);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->trustedCertificateCallCount, 1u);
  EXPECT_EQ(mOpenCompletionCount.load(), 1u);
  EXPECT_EQ(mManager->open_count(), 0u);
}

TEST_F(TrustListTest, OpenWrite_ReturnsHandle)
{
  create_manager();

  auto result = open_sync(mSessionA, 0x06);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_GT(result.value(), 0u);
}

TEST_F(TrustListTest, OpenInvalidMode_Fails)
{
  create_manager();

  auto result = open_sync(mSessionA, 0x02);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, OpenWhenAlreadyOpen_Fails)
{
  create_manager();

  auto first = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(first.is_good());

  auto second = open_sync(mSessionA, 0x06);

  ASSERT_TRUE(second.is_bad());
  EXPECT_EQ(second.status_code(), StatusCode{Status::BadNotWritable});
}

// ============================================================================
// FileType: Close
// ============================================================================

TEST_F(TrustListTest, Close_ClosesHandle)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto closeResult = close_sync(mSessionA, handle);
  ASSERT_TRUE(closeResult.is_good());

  // Should be able to reopen
  auto reopen = open_sync(mSessionA, 0x06);
  EXPECT_TRUE(reopen.is_good());
}

TEST_F(TrustListTest, Close_WrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto closeResult = close_sync(mSessionB, handle);

  ASSERT_TRUE(closeResult.is_bad());
  EXPECT_EQ(closeResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, Close_WrongHandle_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto closeResult = close_sync(mSessionA, handle + 999);

  ASSERT_TRUE(closeResult.is_bad());
  EXPECT_EQ(closeResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

// ============================================================================
// FileType: Read/Write
// ============================================================================

TEST_F(TrustListTest, ReadAfterOpenRead_ReturnsTrustListData)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Read a large chunk to get all data
  auto readResult = read_sync(mSessionA, handle, 65535);
  ASSERT_TRUE(readResult.is_good());

  auto& data = readResult.value();
  EXPECT_GT(data.size(), 0u);

  // Decode the trust list and verify it contains our data
  auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.data()), data.size()};
  memory_stream_device::ExternalReadOnly readDevice(dataSpan);
  MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
  UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});

  TrustListDataType trustList;
  decoder.decode(EncodingLimits{}.stack_depth(), trustList);

  EXPECT_EQ(trustList.trusted_certificates().size(), 1u);
  EXPECT_EQ(trustList.issuer_certificates().size(), 1u);
  EXPECT_EQ(trustList.trusted_crls().size(), 1u);
}

TEST_F(TrustListTest, WriteToReadHandle_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  ByteString someData{0x01, 0x02, 0x03};
  auto writeResult = write_sync(mSessionA, handle, std::move(someData));

  ASSERT_TRUE(writeResult.is_bad());
  EXPECT_EQ(writeResult.status_code(), StatusCode{Status::BadInvalidState});
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-03-CLOSE-AND-UPDATE, scope=function)
TEST_F(TrustListTest, WriteAndCloseAndUpdate_ReplacesTrustList)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Build a trust list with our leaf2 cert as trusted
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // TrustedCertificates only
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());

  auto encoded = encode_trust_list(trustList);
  auto writeResult = write_sync(mSessionA, handle, std::move(encoded));
  ASSERT_TRUE(writeResult.is_good());

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  EXPECT_TRUE(updateResult.value());

  // Verify the store was updated: trusted certs replaced
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mCloseAndUpdateCompletionCount.load(), 1u);
}

// ============================================================================
// FileType: GetPosition / SetPosition
// ============================================================================

TEST_F(TrustListTest, GetPosition_ReturnsCurrentPosition)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Initial position should be 0
  auto posResult = get_position_sync(mSessionA, handle);
  ASSERT_TRUE(posResult.is_good());
  EXPECT_EQ(posResult.value(), 0u);

  // Read some bytes
  read_sync(mSessionA, handle, 10);

  // Position should have advanced
  auto posResult2 = get_position_sync(mSessionA, handle);
  ASSERT_TRUE(posResult2.is_good());
  EXPECT_EQ(posResult2.value(), 10u);
}

TEST_F(TrustListTest, SetPosition_SeeksToPosition)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Read some bytes first
  auto readResult1 = read_sync(mSessionA, handle, 10);
  ASSERT_TRUE(readResult1.is_good());
  auto firstBytes = readResult1.value();

  // Seek back to start
  auto seekResult = set_position_sync(mSessionA, handle, 0);
  ASSERT_TRUE(seekResult.is_good());

  // Read again - should get the same bytes
  auto readResult2 = read_sync(mSessionA, handle, 10);
  ASSERT_TRUE(readResult2.is_good());
  EXPECT_EQ(readResult2.value(), firstBytes);
}

// ============================================================================
// OpenWithMasks
// ============================================================================

TEST_F(TrustListTest, OpenWithMasks_TrustedOnly)
{
  create_manager();

  // Mask 0x01 = TrustedCertificates only
  auto openResult = open_with_masks_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto readResult = read_sync(mSessionA, handle, 65535);
  ASSERT_TRUE(readResult.is_good());

  auto& data = readResult.value();
  auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.data()), data.size()};
  memory_stream_device::ExternalReadOnly readDevice(dataSpan);
  MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
  UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});

  TrustListDataType trustList;
  decoder.decode(EncodingLimits{}.stack_depth(), trustList);

  EXPECT_EQ(trustList.specified_lists(), 0x01u);
  EXPECT_EQ(trustList.trusted_certificates().size(), 1u);
  // Other lists should be empty since they were not requested
  EXPECT_EQ(trustList.issuer_certificates().size(), 0u);
  EXPECT_EQ(trustList.trusted_crls().size(), 0u);
  EXPECT_EQ(trustList.issuer_crls().size(), 0u);
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-02-OPEN-WITH-MASKS, scope=function)
TEST_F(TrustListTest, OpenWithMasks_AllMasks)
{
  create_manager();

  auto openResult = open_with_masks_sync(mSessionA, 0x0F);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto readResult = read_sync(mSessionA, handle, 65535);
  ASSERT_TRUE(readResult.is_good());

  auto& data = readResult.value();
  auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.data()), data.size()};
  memory_stream_device::ExternalReadOnly readDevice(dataSpan);
  MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
  UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});

  TrustListDataType trustList;
  decoder.decode(EncodingLimits{}.stack_depth(), trustList);

  EXPECT_EQ(trustList.specified_lists(), 0x0Fu);
  EXPECT_EQ(trustList.trusted_certificates().size(), 1u);
  EXPECT_EQ(trustList.issuer_certificates().size(), 1u);
  EXPECT_EQ(trustList.trusted_crls().size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCertificateCallCount, 1u);
  EXPECT_EQ(mOpenWithMasksCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-02-OPEN-WITH-MASKS, scope=function)
TEST_F(TrustListTest, OpenWithMasksStoreFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("MaskedTrustListReadUnavailable",
      "Masked trusted certificate list is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->trustedCertificateResults.emplace_back(upstream);

  create_manager();

  auto result = open_with_masks_sync(mSessionA, 0x01);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->trustedCertificateCallCount, 1u);
  EXPECT_EQ(mOpenWithMasksCompletionCount.load(), 1u);
  EXPECT_EQ(mManager->open_count(), 0u);
}

TEST_F(TrustListTest, OpenWithMasks_ZeroMaskFetchesAll)
{
  create_manager();

  auto openResult = open_with_masks_sync(mSessionA, 0);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto readResult = read_sync(mSessionA, handle, 65535);
  ASSERT_TRUE(readResult.is_good());

  auto& data = readResult.value();
  auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.data()), data.size()};
  memory_stream_device::ExternalReadOnly readDevice(dataSpan);
  MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
  UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});

  TrustListDataType trustList;
  decoder.decode(EncodingLimits{}.stack_depth(), trustList);

  // masks=0 should be treated as kMaskAll (0x0F)
  EXPECT_EQ(trustList.specified_lists(), 0x0Fu);
  EXPECT_EQ(trustList.trusted_certificates().size(), 1u);
  EXPECT_EQ(trustList.issuer_certificates().size(), 1u);
  EXPECT_EQ(trustList.trusted_crls().size(), 1u);
}

// ============================================================================
// CloseAndUpdate
// ============================================================================

TEST_F(TrustListTest, CloseAndUpdate_WriteModeOnly)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto updateResult = close_and_update_sync(mSessionA, handle);

  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidState});
}

TEST_F(TrustListTest, CloseAndUpdate_NotifiesCallback)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Write an empty trust list
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  auto encoded = encode_trust_list(trustList);
  write_sync(mSessionA, handle, std::move(encoded));

  auto modifiedFuture = expect_modified();

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  auto modifiedSession = modifiedFuture.get();
  EXPECT_EQ(modifiedSession, mSessionA);
}

TEST_F(TrustListTest, CloseAndUpdate_UpdatesLastUpdateTime)
{
  create_manager();

  auto timeBefore = mManager->last_update_time();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Write a trust list to trigger update
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  auto encoded = encode_trust_list(trustList);
  write_sync(mSessionA, handle, std::move(encoded));

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  auto timeAfter = mManager->last_update_time();
  EXPECT_NE(timeAfter, timeBefore);
}

TEST_F(TrustListTest, CloseAndUpdate_EmptyWrite_Succeeds)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Don't write anything - just CloseAndUpdate on empty buffer
  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  EXPECT_TRUE(updateResult.value());
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-03-CLOSE-AND-UPDATE, scope=function)
TEST_F(TrustListTest, CloseAndUpdateStoreFailurePreservesExactRichResult)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());

  auto encoded = encode_trust_list(trustList);
  auto writeResult = write_sync(mSessionA, handle, std::move(encoded));
  ASSERT_TRUE(writeResult.is_good());

  const StatusCode upstream{Status::BadSecurityChecksFailed,
    make_error_detail("TrustListReplaceUnavailable",
      "Trusted certificate replacement is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->replaceTrustedCertificateResults.emplace_back(upstream);

  auto result = close_and_update_sync(mSessionA, handle);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mCloseAndUpdateCompletionCount.load(), 1u);
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.front()->der_encoding(), mLeafCert->der_encoding());
  EXPECT_EQ(mManager->open_count(), 0u);
}

// ApplyChanges' write of the staged lists: a store failure reaches the caller as the store gave it (same
// code, same ErrorDetail object), and the store keeps its lists. Control: ApplyStagedWritesTheStore.
// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-06-APPLY-STAGED, scope=function)
TEST_F(TrustListTest, ApplyStagedStoreFailurePreservesExactRichResult)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());

  const StatusCode upstream{Status::BadSecurityChecksFailed,
    make_error_detail("TrustListReplaceUnavailable",
      "Trusted certificate replacement is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->replaceTrustedCertificateResults.emplace_back(upstream);

  const auto result = apply_staged_sync();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.front()->der_encoding(), mLeafCert->der_encoding());
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-06-APPLY-STAGED, scope=function)
TEST_F(TrustListTest, ApplyStagedWritesTheStore)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.front()->der_encoding(), mLeafCert->der_encoding()) << "staged only";

  const auto result = apply_staged_sync();
  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.front()->der_encoding(), mLeaf2Cert->der_encoding());
  EXPECT_FALSE(staged_lists_sync().has_value());
}

// The reset's clear: a store failure reaches the caller as the store gave it (same code, same ErrorDetail
// object). Control: TheResetDropsTheStagedLists clears successfully.
// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-07-CLEAR-LISTS, scope=function)
TEST_F(TrustListTest, ClearListsStoreFailurePreservesExactRichResult)
{
  create_manager();
  const StatusCode upstream{Status::BadSecurityChecksFailed,
    make_error_detail("TrustListReplaceUnavailable",
      "Trusted certificate replacement is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->replaceTrustedCertificateResults.emplace_back(upstream);

  std::promise<VoidResult> cleared;
  mManager->clear_lists_async([&cleared](VoidResult r) { cleared.set_value(std::move(r)); });
  auto clearedFuture = cleared.get_future();
  ASSERT_EQ(clearedFuture.wait_for(5s), std::future_status::ready);
  const auto result = clearedFuture.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
}

// ============================================================================
// AddCertificate
// ============================================================================

// @relation(SVR-SECADMIN-009, scope=function)
// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-04-ADD, scope=function)
TEST_F(TrustListTest, AddCertificate_TrustedAddsToTrustedStore)
{
  create_manager();

  auto before = mFakeStore->trustedCerts.size();

  auto result = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), /*isTrusted=*/true);
  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());

  EXPECT_EQ(mFakeStore->trustedCerts.size(), before + 1);
  EXPECT_EQ(mFakeStore->addToTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mAddCertificateCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-04-ADD, scope=function)
TEST_F(TrustListTest, AddCertificateStoreFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("TrustListAddUnavailable",
      "Trusted certificate addition is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->addToTrustedCertificateResults.emplace_back(upstream);

  create_manager();
  const auto before = mFakeStore->trustedCerts.size();

  auto result = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->addToTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mAddCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), before);
}

// RATIFIED (owner report 2026-10-03, BR-13; OPC 10000-12 7.8.2.4): AddCertificate is not part of a
// transaction - it has no applyChangesRequired output, changes the TrustList at once and opens no transaction
// (formerly AddCertificate_NotifiesModifiedCallback, which asserted it joined one). Its claim is released
// when it completes. Falsifiable: the former code handed the claim to the modified callback (a transaction).
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(TrustListTest, AddCertificateAppliesAtOnceAndOpensNoTransaction)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  create_manager();

  auto result = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_TRUE(is_write_open_sync().is_good());  // a strand barrier behind the completion

  EXPECT_EQ(mFakeStore->trustedCerts.size(), 2u) << "written to the store at once";
  EXPECT_FALSE(staged_lists_sync().has_value()) << "nothing is staged";
  std::lock_guard lock(mModifiedMutex);
  EXPECT_TRUE(mModifiedSessionIds.empty()) << "no transaction is opened";
  EXPECT_EQ(mAbandonedSessionIds.size(), 1u) << "the claim is released";
}

// ============================================================================
// RemoveCertificate
// ============================================================================

// Covers SVR-SECADMIN-016 (coverage-audit retag).
// @relation(SVR-ECC-010, SVR-SECADMIN-016, scope=function)
// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-05-REMOVE, scope=function)
TEST_F(TrustListTest, RemoveCertificate_RemovesFromTrusted)
{
  create_manager();

  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);

  auto tp = thumbprint_hex(mLeafCert);
  auto result = remove_certificate_sync(mSessionA, tp, /*isTrusted=*/true);
  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());

  EXPECT_EQ(mFakeStore->trustedCerts.size(), 0u);
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mRemoveCertificateCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-TRUST-LIST-MANAGER-PROPAGATION-05-REMOVE, scope=function)
TEST_F(TrustListTest, RemoveCertificateStoreFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadCommunicationError,
    make_error_detail("TrustListRemoveUnavailable",
      "Trusted certificate removal is unavailable",
      "InMemoryFakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->removeFromTrustedCertificateResults.emplace_back(upstream);

  create_manager();
  const auto before = mFakeStore->trustedCerts.size();
  const auto thumbprint = thumbprint_hex(mLeafCert);

  auto result = remove_certificate_sync(mSessionA, thumbprint, true);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mRemoveCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), before);
}

// A TrustList Method reads nothing from a list the store answered Uncertain: Open answers Bad_InternalError
// with the CertificateStoreAnswerUncertain refusal carrying the store's code, and opens no handle.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TrustListTest, OpenRefusesAnUncertainStoreAnswer)
{
  mFakeStore->trustedCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});
  create_manager();

  auto result = open_sync(mSessionA, 0x01);

  expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
  EXPECT_EQ(mOpenCompletionCount.load(), 1u);
  EXPECT_EQ(mManager->open_count(), 0u);
}

// AddCertificate validates against the store's lists only when the store answered them Good: an Uncertain
// answer is refused (Bad_InternalError, CertificateStoreAnswerUncertain) and nothing is added.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TrustListTest, AddCertificateRefusesAnUncertainStoreAnswer)
{
  mFakeStore->trustedCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});
  create_manager();
  const auto before = mFakeStore->trustedCerts.size();

  auto result = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);

  expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
  EXPECT_EQ(mFakeStore->addToTrustedCertificateCallCount, 0u);
  EXPECT_EQ(mAddCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), before);
}

// RemoveCertificate looks the thumbprint up only in a list the store answered Good: an Uncertain answer is
// refused (Bad_InternalError, CertificateStoreAnswerUncertain) and nothing is removed.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TrustListTest, RemoveCertificateRefusesAnUncertainStoreAnswer)
{
  mFakeStore->trustedCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});
  create_manager();
  const auto before = mFakeStore->trustedCerts.size();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), true);

  expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u);
  EXPECT_EQ(mRemoveCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), before);
}

// CloseAndUpdate keeps an unmasked list as the store has it only when the store answered it Good. Here the
// update names the trusted CRLs alone, so the merge reads the trusted certificates; answered Uncertain, the
// update is refused (Bad_InternalError, CertificateStoreAnswerUncertain) and the store is not replaced.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAnUncertainStoreAnswerForAnUnmaskedList)
{
  create_manager();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good()) << describe_chain(opened.status_code());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x02;
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(trustList)).is_good());
  mFakeStore->trustedCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});

  auto result = close_and_update_sync(mSessionA, opened.value());

  expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
  EXPECT_EQ(mCloseAndUpdateCompletionCount.load(), 1u);
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts.front()->der_encoding(), mLeafCert->der_encoding());
}

// Part 12 7.8.2.5: "It returns Bad_InvalidArgument if the thumbprint does not match a Certificate in the
// Trust List". RATIFIED (owner decision 2026-10-03, conformance gap (a)): this test expected the store's
// Bad_NotFound for a malformed "DEADBEEF"; it now names a well-formed thumbprint of no listed certificate and
// expects the spec's code, with the refusal naming the thumbprint and the store untouched.
// @verifies AC-SVR-PULLCRT-038-A-UNKNOWN-THUMBPRINT-IS-INVALID-ARGUMENT
TEST_F(TrustListTest, RemoveCertificate_UnknownThumbprint_ReturnsBadInvalidArgument)
{
  create_manager();
  const auto unknown = thumbprint_hex(mLeaf2Cert);  // well-formed, and not in the trusted list

  auto result = remove_certificate_sync(mSessionA, unknown, /*isTrusted=*/true);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "TrustListCertificateNotFound");
  EXPECT_EQ(context_value(*result.shared_detail(), ua::ContextKeys::certificateThumbprint.value()), unknown);
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u) << "the store is not asked";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mLeafCert);
}

// The store's own Bad_NotFound (the list changed between the read and the removal) is answered with the
// spec's code too.
// @verifies AC-SVR-PULLCRT-038-A-UNKNOWN-THUMBPRINT-IS-INVALID-ARGUMENT
TEST_F(TrustListTest, RemoveCertificate_StoreNotFoundIsAnsweredAsInvalidArgument)
{
  mFakeStore->removeFromTrustedCertificateResults.emplace_back(StatusCode{Status::BadNotFound});
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "TrustListCertificateNotFound");
  EXPECT_EQ(result.shared_detail()->innerStatus, StatusCode{Status::BadNotFound}.value())
    << "the store's cause";
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 1u);
}

// Part 12 7.8.2.5: "If the Certificate is a CA Certificate that has CRLs then all CRLs for that CA are
// removed as well" (Mantis 6796: only that CA's). Falsifiable: the former manager removed the certificate
// alone.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, RemovingACaAlsoRemovesTheCrlsItIssued)
{
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Other CA", "200");
  auto otherCrl = mPki->create_crl(otherCa, otherKeys, {});
  auto caCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  auto caCrlRevoking = mPki->create_crl(mCaCert, mCaKeys, {"1234"});
  mFakeStore->issuerCerts = {mCaCert, otherCa};
  mFakeStore->issuerCrls = {caCrl, otherCrl, caCrlRevoking};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCerts[0], otherCa);
  ASSERT_EQ(mFakeStore->issuerCrls.size(), 1u) << "both of the CA's CRLs leave with it";
  EXPECT_EQ(mFakeStore->issuerCrls[0], otherCrl) << "another CA's CRL stays";
  EXPECT_EQ(mFakeStore->replaceIssuerCertificateCallCount.load(), 1u)
    << "the CA and its CRLs leave in one store update";
  // Only the list the CA is removed from: the fixture's trusted CRL (also issued by the CA) stays.
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0], mCrl);
}

// A CRL is the CA's when the CA's key verifies it, not merely when it names the CA: a different CA with the
// same subject name keeps its CRL. Falsifiable: a name-only match removes both.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, ACaSharingTheSubjectNameKeepsItsCrl)
{
  auto twinKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto twinCa = mPki->create_root_ca(twinKeys, "Root CA", "201");  // the fixture CA's subject name
  ASSERT_EQ(twinCa->subject_distinguished_name(), mCaCert->subject_distinguished_name());
  auto caCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  auto twinCrl = mPki->create_crl(twinCa, twinKeys, {});
  mFakeStore->issuerCerts = {mCaCert, twinCa};
  mFakeStore->issuerCrls = {caCrl, twinCrl};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCerts[0], twinCa);
  ASSERT_EQ(mFakeStore->issuerCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCrls[0], twinCrl) << "the twin CA's CRL is not the removed CA's";
}

// A renewed CA (same subject, same key) that stays in the list also issued the removed CA's CRLs, so they
// stay: Mantis 6796, only the removed CA's CRLs go. Falsifiable: without the second check the CRL goes.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, ACrlThatARenewedCaStillNeedsStays)
{
  auto renewed = mPki->create_root_ca(mCaKeys, "Root CA", "101");  // same subject and key, new serial
  auto caCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  mFakeStore->issuerCerts = {mCaCert, renewed};
  mFakeStore->issuerCrls = {caCrl};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCerts[0], renewed);
  ASSERT_EQ(mFakeStore->issuerCrls.size(), 1u) << "the renewed CA verifies the CRL too";
  EXPECT_EQ(mFakeStore->issuerCrls[0], caCrl);
}

// An expired CRL the CA issued leaves with it: ownership does not depend on the CRL's validity window.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, AnExpiredCrlOfTheCaLeavesWithIt)
{
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Other CA", "200");
  auto expired = make_u5_out_of_date_crl(*mCrypto, *mPki, mCaCert, mCaKeys);
  auto otherCrl = mPki->create_crl(otherCa, otherKeys, {});
  mFakeStore->issuerCerts = {mCaCert, otherCa};
  mFakeStore->issuerCrls = {expired, otherCrl};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->issuerCrls.size(), 1u) << "the CA's expired CRL left with it";
  EXPECT_EQ(mFakeStore->issuerCrls[0], otherCrl);
}

// The contract with Crypto behind the test above: the ownership check asks with
// SuppressRevocationStatusUnknown, the documented way (Crypto::validate_crl_async) to have a CRL outside its
// window still match. The OpenSSL backend also skips the window when no revocation checking is requested, so
// only this check keeps another backend from leaving an expired CRL behind.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, TheCrlOwnershipCheckAsksCryptoToIgnoreTheValidityWindow)
{
  auto crypto = FakeAsyncCrypto::create();
  mCrypto = crypto;
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {})};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  const auto options = crypto->crl_validation_options();
  ASSERT_FALSE(options.empty());
  for (const auto& o : options)
    EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown));
  EXPECT_TRUE(mFakeStore->issuerCrls.empty());
}

// A crypto that answers a CRL check twice advances the scan once: the removal still answers once, with the
// first (real) verdict.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, ACrlCheckAnsweredTwiceCountsOnce)
{
  auto crypto = FakeAsyncCrypto::create();
  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Twice);
  mCrypto = crypto;
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Other CA", "200");
  auto caCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  auto otherCrl = mPki->create_crl(otherCa, otherKeys, {});
  mFakeStore->issuerCerts = {mCaCert, otherCa};
  mFakeStore->issuerCrls = {caCrl, otherCrl};
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);
  // A second answer that advanced the scan again would end in a second replace; wait a bounded time for one,
  // expecting none.
  const auto deadline = std::chrono::steady_clock::now() + 1s;
  while (
    mFakeStore->replaceIssuerCertificateCallCount.load() < 2 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(5ms);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  EXPECT_EQ(mRemoveCertificateCompletionCount.load(), 1u);
  ASSERT_EQ(mFakeStore->issuerCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCrls[0], otherCrl);
  EXPECT_EQ(mFakeStore->replaceIssuerCertificateCallCount.load(), 1u);
}

// A CRL check whose answer is dropped loses that removal (the caller is not answered, as with any store or
// crypto that drops a callback) but does not leave the TrustList refusing every later change.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, ADroppedCrlCheckDoesNotLeaveTheTrustListLocked)
{
  auto crypto = FakeAsyncCrypto::create();
  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Drop);
  mCrypto = crypto;
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {})};
  create_manager();

  std::atomic<bool> removeAnswered{false};
  mManager->remove_certificate_async(mSessionA,
    thumbprint_hex(mCaCert),
    /*isTrustedCertificate=*/false,
    [&](VoidResult) { removeAnswered = true; });
  auto added = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), /*isTrusted=*/true);

  EXPECT_TRUE(added.is_good()) << describe_chain(added.status_code());
  EXPECT_FALSE(removeAnswered.load());
  EXPECT_EQ(mFakeStore->issuerCerts.size(), 1u) << "the dropped removal changed nothing";
}

// While a removal is checking CRLs (held here), a CloseAndUpdate and a second RemoveCertificate are refused
// with Bad_InvalidState: each would otherwise write lists the removal is about to replace. Once it completes,
// changes are accepted again.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, CloseAndUpdateAndRemoveAreRefusedWhileARemovalChecksCrls)
{
  auto crypto = FakeAsyncCrypto::create();
  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Hold);
  mCrypto = crypto;
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {})};
  create_manager();

  std::promise<VoidResult> removed;
  mManager->remove_certificate_async(mSessionA,
    thumbprint_hex(mCaCert),
    /*isTrustedCertificate=*/false,
    [&removed](VoidResult r) { removed.set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (crypto->held_crl_validation_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(crypto->held_crl_validation_count(), 1u) << "the removal is checking the CA's CRL";

  // Bounded waits: without the refusal either call would block on the held CRL check, and the test must fail,
  // not hang. The promises are shared, so an answer arriving after a timeout lands safely.
  auto second = std::make_shared<std::promise<VoidResult>>();
  mManager->remove_certificate_async(mSessionA,
    thumbprint_hex(mLeafCert),
    /*isTrustedCertificate=*/true,
    [second](VoidResult r) { second->set_value(std::move(r)); });
  auto secondFuture = second->get_future();
  ASSERT_EQ(secondFuture.wait_for(5s), std::future_status::ready) << "a second removal is answered at once";
  EXPECT_EQ(secondFuture.get().status_code(), StatusCode{Status::BadInvalidState});
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(trustList)).is_good());
  auto update = std::make_shared<std::promise<Result<bool>>>();
  mManager->close_and_update_async(
    mSessionA, opened.value(), [update](Result<bool> r) { update->set_value(std::move(r)); });
  auto updateFuture = update->get_future();
  ASSERT_EQ(updateFuture.wait_for(5s), std::future_status::ready) << "the CloseAndUpdate is answered at once";
  EXPECT_EQ(updateFuture.get().status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "neither change was written";

  // A refused CloseAndUpdate leaves the TrustList open for write (the client may retry or Close); Close it.
  ASSERT_TRUE(close_sync(mSessionA, opened.value()).is_good());

  crypto->release_held_crl_validations();
  auto removedFuture = removed.get_future();
  ASSERT_EQ(removedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(removedFuture.get().is_good());
  EXPECT_TRUE(remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true).is_good())
    << "accepted again once the removal completed";
}

// Part 12 Figure 22 (7.8.2.1): Open with the write bit claims the push transaction - refused with
// Bad_TransactionPending while another Session holds it - and hands the claim to the push service, which
// opens or joins the Session's transaction, before the Open is answered. Anyone may read.
// Falsifiable: the former manager opened for write without claiming, and started no transaction.
// @verifies AC-SVR-PULLCRT-039-OPEN-FOR-WRITE-IS-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(TrustListTest, OpenForWriteClaimsTheTransactionAndHandsItOverBeforeAnswering)
{
  mModificationGate = [this](const NodeId& session)
  {
    return session == mSessionA ? StatusCode{Status::Good} : StatusCode{Status::BadTransactionPending};
  };
  std::mutex openedMutex;
  std::vector<std::pair<NodeId, std::shared_ptr<TrustListModificationClaim>>> opened;
  mOpenedForWrite = [&](NodeId session, std::shared_ptr<TrustListModificationClaim> claim)
  {
    const std::lock_guard lock(openedMutex);
    opened.emplace_back(std::move(session), std::move(claim));
  };
  create_manager();

  auto refused = open_sync(mSessionB, 0x06);
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadTransactionPending});
  auto read = open_sync(mSessionB, 0x01);
  ASSERT_TRUE(read.is_good()) << "reading is not refused";
  ASSERT_TRUE(close_sync(mSessionB, read.value()).is_good());
  {
    const std::lock_guard lock(openedMutex);
    EXPECT_TRUE(opened.empty()) << "a refused Open and a read hand over no claim";
  }

  auto owner = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(owner.is_good());
  {
    const std::lock_guard lock(openedMutex);
    ASSERT_EQ(opened.size(), 1u) << "handed over before the Open was answered";
    EXPECT_EQ(opened[0].first, mSessionA);
    EXPECT_NE(opened[0].second, nullptr);
  }
  EXPECT_EQ(abandoned_count(), 0u) << "the claim is the push service's to release";
  {
    const std::lock_guard lock(openedMutex);
    opened.clear();
  }
  EXPECT_EQ(abandoned_count(), 1u) << "released when the push service drops it";
}

// Owner decision Q2: lists staged in a push transaction that has ended (its discard not here yet) are not the
// TrustList of the Session's next transaction. A CloseAndUpdate in the new transaction keeps the unmasked
// lists as the store has them, and the ended transaction's discard leaves the new one's lists alone.
// Falsifiable: the former manager merged onto whatever was staged, so a cancelled change came back in the
// next transaction.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(TrustListTest, AChangeInANewTransactionDoesNotBuildOnListsStagedInAnEndedOne)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  mClaimGeneration = 1;
  create_manager();

  TrustListDataType emptied;
  emptied.specified_lists() = 0x01;  // transaction 1: no trusted certificates
  ASSERT_TRUE(update_trust_list_sync(emptied).is_good());
  ASSERT_TRUE(staged_lists_sync().has_value());
  ASSERT_TRUE(staged_lists_sync()->trustedCerts.empty());

  mClaimGeneration = 2;  // transaction 1 ended; the Session's transaction 2 changes only the issuers
  TrustListDataType issuers;
  issuers.specified_lists() = 0x04;
  issuers.issuer_certificates().push_back(mCaCert->der_encoding());
  const auto updated = update_trust_list_sync(issuers);
  ASSERT_TRUE(updated.is_good()) << describe_chain(updated.status_code());

  auto staged = staged_lists_sync();
  ASSERT_TRUE(staged.has_value());
  EXPECT_EQ(staged->trustedCerts.size(), 1u)
    << "the trusted certificates are the store's, not transaction 1's";

  mManager->discard_staged_async(mSessionA, uint64_t{1});
  EXPECT_TRUE(staged_lists_sync().has_value()) << "transaction 1's discard keeps transaction 2's lists";
  mManager->discard_staged_async(mSessionA, uint64_t{2});
  EXPECT_FALSE(staged_lists_sync().has_value()) << "transaction 2's discard drops them";
}

// Owner decision Q2: data uploaded on a handle opened in a transaction that has since ended (CancelChanges)
// is not carried into a new one: the CloseAndUpdate is refused with Bad_InvalidState
// (TrustListTransactionEnded), the handle is closed and nothing is staged. Falsifiable: the former manager
// staged it under the next transaction's claim.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(TrustListTest, AnUploadFromAnEndedTransactionIsRefusedAtCloseAndUpdate)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  mClaimGeneration = 1;
  create_manager();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(trustList)).is_good());

  mClaimGeneration = 2;  // transaction 1 was cancelled; a claim now names the next one
  const auto refused = close_and_update_sync(mSessionA, opened.value());
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "TrustListTransactionEnded");
  EXPECT_FALSE(staged_lists_sync().has_value());
  EXPECT_EQ(mManager->open_count(), 0u) << "the handle is closed";
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// Work queued behind the list writes (a reset waiting for one) blocks new list changes even when no write is
// held
// - the state a reset passes through between two strand turns - so a stream of changes cannot starve it.
// Every change is refused with Bad_InvalidState, ApplyChanges writes nothing and the write state reports
// busy, until the work has run. Falsifiable: a list_writes_blocked that looks only at the writes in flight
// lets them in.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, WorkQueuedBehindTheListWritesRefusesNewChangesUntilItRuns)
{
  create_manager();
  std::atomic<bool> ran{false};
  std::promise<void> queued;
  TrustListManagerTestAccess::queue_after_list_write(
    *mManager, [&ran](TrustListManager&) { ran = true; }, [&queued]() { queued.set_value(); });
  queued.get_future().get();

  // No handle is open and no write is held: only the queued work refuses these.
  EXPECT_EQ(add_certificate_sync(mSessionB, mLeaf2Cert->der_encoding(), true).status_code(),
    StatusCode{Status::BadInvalidState});
  EXPECT_EQ(remove_certificate_sync(mSessionB, thumbprint_hex(mLeafCert), true).status_code(),
    StatusCode{Status::BadInvalidState});
  const auto apply = apply_staged_sync();
  ASSERT_NE(apply.shared_detail(), nullptr);
  EXPECT_EQ(apply.shared_detail()->code, "TrustListWriteInProgress");
  const auto busy = is_write_open_sync();
  ASSERT_TRUE(busy.is_good());
  EXPECT_TRUE(busy.value());
  // A CloseAndUpdate is refused too (an open write handle does not refuse it by itself).
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(trustList)).is_good());
  EXPECT_EQ(
    close_and_update_sync(mSessionA, opened.value()).status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_TRUE(close_sync(mSessionA, opened.value()).is_good());
  EXPECT_FALSE(ran.load());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "nothing was written";

  std::promise<void> ranQueued;
  TrustListManagerTestAccess::run_after_list_write(*mManager, [&ranQueued]() { ranQueued.set_value(); });
  ranQueued.get_future().get();
  EXPECT_TRUE(ran.load());
  EXPECT_TRUE(add_certificate_sync(mSessionB, mLeaf2Cert->der_encoding(), true).is_good())
    << "accepted again";
}

// One list write at a time: while an AddCertificate's store write is in flight (parked here), a
// RemoveCertificate is refused with Bad_InvalidState, so the manager never depends on the order in which the
// store applies the two. Once the write lands the removal is accepted.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, AnAddCertificateWriteInFlightRefusesARemovalUntilItLands)
{
  mFakeStore->parkAddToTrusted = true;
  create_manager();
  auto added = std::make_shared<std::promise<VoidResult>>();
  mManager->add_certificate_async(mSessionA,
    mLeaf2Cert->der_encoding(),
    /*isTrustedCertificate=*/true,
    [added](VoidResult r) { added->set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!mFakeStore->addToTrustedIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_TRUE(mFakeStore->addToTrustedIsParked.load()) << "the AddCertificate reached the store";

  auto during = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true);
  EXPECT_EQ(during.status_code(), StatusCode{Status::BadInvalidState});
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u);

  mFakeStore->release_parked_add_to_trusted();
  auto addedFuture = added->get_future();
  ASSERT_EQ(addedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(addedFuture.get().is_good());
  EXPECT_TRUE(remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true).is_good())
    << "accepted once the write landed";
}

// Part 12 7.10.10 ("All TrustLists are cleared") gives the reset no way to refuse: a clear that arrives
// during a list write waits for it, then clears - so the certificate that write added is cleared too.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, TheResetClearsAfterTheWriteInProgress)
{
  mFakeStore->parkAddToTrusted = true;
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {})};
  create_manager();
  auto added = std::make_shared<std::promise<VoidResult>>();
  mManager->add_certificate_async(mSessionA,
    mLeaf2Cert->der_encoding(),
    /*isTrustedCertificate=*/true,
    [added](VoidResult r) { added->set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!mFakeStore->addToTrustedIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_TRUE(mFakeStore->addToTrustedIsParked.load());

  auto cleared = std::make_shared<std::promise<VoidResult>>();
  mManager->clear_lists_async([cleared](VoidResult r) { cleared->set_value(std::move(r)); });
  auto clearedFuture = cleared->get_future();
  EXPECT_EQ(clearedFuture.wait_for(200ms), std::future_status::timeout) << "the clear waits for the write";
  EXPECT_FALSE(mFakeStore->trustedCerts.empty()) << "nothing cleared yet";

  mFakeStore->release_parked_add_to_trusted();
  ASSERT_EQ(clearedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(clearedFuture.get().is_good());
  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "the certificate the write added is cleared too";
  EXPECT_TRUE(mFakeStore->trustedCrls.empty());
  EXPECT_TRUE(mFakeStore->issuerCerts.empty());
  EXPECT_TRUE(mFakeStore->issuerCrls.empty());
}

// The reset also drops the lists a transaction staged, so a later ApplyChanges writes nothing back.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, TheResetDropsTheStagedLists)
{
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());

  auto cleared = std::make_shared<std::promise<VoidResult>>();
  mManager->clear_lists_async([cleared](VoidResult r) { cleared->set_value(std::move(r)); });
  auto clearedFuture = cleared->get_future();
  ASSERT_EQ(clearedFuture.wait_for(5s), std::future_status::ready);
  ASSERT_TRUE(clearedFuture.get().is_good());

  auto applied = std::make_shared<std::promise<VoidResult>>();
  mManager->apply_staged_async([applied](VoidResult r) { applied->set_value(std::move(r)); });
  auto appliedFuture = applied->get_future();
  ASSERT_EQ(appliedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(appliedFuture.get().is_good()) << "nothing staged: nothing to write";
  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "the staged list was not written back";
}

// ApplyChanges that reaches the manager while a CloseAndUpdate of the same transaction is still merging (its
// CRL check held here) is refused with Bad_InvalidState and writes nothing: the lists it verified are not the
// ones the merge is about to stage. Internal observable: in production the ApplyChanges preflight refuses
// earlier (the TrustList is still open for write, is_write_open_async); this is the gap after it.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, ApplyChangesIsRefusedWhileACloseAndUpdateIsMerging)
{
  auto crypto = FakeAsyncCrypto::create();
  mCrypto = crypto;
  mStageUntilApply = true;
  create_manager();
  TrustListDataType first;
  first.specified_lists() = 0x01;
  first.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(first).is_good());

  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Hold);
  TrustListDataType second;
  second.specified_lists() = 0x03;  // trusted certificates and trusted CRLs
  second.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  second.trusted_crls().push_back(mCrl->der_encoding());
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(second)).is_good());
  auto updated = std::make_shared<std::promise<Result<bool>>>();
  mManager->close_and_update_async(
    mSessionA, opened.value(), [updated](Result<bool> r) { updated->set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (crypto->held_crl_validation_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(crypto->held_crl_validation_count(), 1u) << "the second CloseAndUpdate is checking its CRL";

  auto applied = std::make_shared<std::promise<VoidResult>>();
  mManager->apply_staged_async([applied](VoidResult r) { applied->set_value(std::move(r)); });
  auto appliedFuture = applied->get_future();
  ASSERT_EQ(appliedFuture.wait_for(5s), std::future_status::ready) << "refused at once, not waited for";
  const auto appliedResult = appliedFuture.get();
  EXPECT_EQ(appliedResult.status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_NE(appliedResult.shared_detail(), nullptr);
  EXPECT_EQ(appliedResult.shared_detail()->code, "TrustListWriteInProgress");

  crypto->release_held_crl_validations();
  auto updatedFuture = updated->get_future();
  ASSERT_EQ(updatedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(updatedFuture.get().is_good());
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "the refused apply wrote nothing";
}

// A reset waits for a list write in progress, but not forever: a write that never completes (a CRL check held
// here) does not hold back the shutdown Part 12 7.10.10 requires - after the wait limit the reset clears
// anyway. Meanwhile no new change starts, so the reset is not starved.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, AResetClearsAfterItsWaitLimitWhenAWriteNeverCompletes)
{
  mResetWaitLimit = 300ms;
  auto sink = std::make_shared<RecordingLogSink>();
  mManagerLogger = Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "TrustListTest"};
  auto crypto = FakeAsyncCrypto::create();
  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Hold);
  mCrypto = crypto;
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Other CA", "200");
  mFakeStore->issuerCerts = {mCaCert, otherCa};
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {}), mPki->create_crl(otherCa, otherKeys, {})};
  create_manager();
  auto removed = std::make_shared<std::promise<VoidResult>>();
  mManager->remove_certificate_async(mSessionA,
    thumbprint_hex(mCaCert),
    /*isTrustedCertificate=*/false,
    [removed](VoidResult r) { removed->set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (crypto->held_crl_validation_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(crypto->held_crl_validation_count(), 1u) << "the removal's write is in progress";

  auto cleared = std::make_shared<std::promise<VoidResult>>();
  mManager->clear_lists_async([cleared](VoidResult r) { cleared->set_value(std::move(r)); });
  auto clearedFuture = cleared->get_future();
  EXPECT_EQ(clearedFuture.wait_for(50ms), std::future_status::timeout)
    << "the reset waits for the write first";
  auto during = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), /*isTrusted=*/true);
  EXPECT_EQ(during.status_code(), StatusCode{Status::BadInvalidState}) << "no new change while a reset waits";

  ASSERT_EQ(clearedFuture.wait_for(mResetWaitLimit + 5s), std::future_status::ready)
    << "cleared at the wait limit";
  const auto forced = clearedFuture.get();
  EXPECT_EQ(forced.status_code(), StatusCode{Status::BadTimeout})
    << "not Good: the write still in flight may land over the cleared lists";
  ASSERT_NE(forced.shared_detail(), nullptr);
  EXPECT_EQ(forced.shared_detail()->code, "TrustListWriteOutlastedTheReset");
  EXPECT_TRUE(mFakeStore->trustedCerts.empty());
  EXPECT_TRUE(mFakeStore->issuerCerts.empty());

  // The late removal writes the issuer list it read before the reset ({Other CA}) over the cleared lists; the
  // follow-up clear, run when that write has ended, empties them again.
  crypto->release_held_crl_validations();
  auto removedFuture = removed->get_future();
  ASSERT_EQ(removedFuture.wait_for(5s), std::future_status::ready);
  // Wait, through the manager's strand, until no list write is in progress or queued (the follow-up clear is
  // done); the store is read only after that round trip.
  const auto settle = std::chrono::steady_clock::now() + 5s;
  for (bool busy = true; busy && std::chrono::steady_clock::now() < settle;)
  {
    std::promise<Result<bool>> state;
    mManager->is_write_open_async([&state](Result<bool> r) { state.set_value(std::move(r)); });
    const auto answer = state.get_future().get();
    busy = answer.is_bad() || answer.value();
    if (busy)
      std::this_thread::sleep_for(5ms);
  }
  EXPECT_TRUE(mFakeStore->issuerCerts.empty()) << "the late write did not undo the reset";
  EXPECT_TRUE(mFakeStore->issuerCrls.empty());
  EXPECT_FALSE(sink->saw("the reset is incomplete"))
    << "the follow-up clear succeeded: no failure is reported";
}

// A CloseAndUpdate's list write ends with its answer, whoever still holds the update's state: here the store
// keeps a copy of a list-read callback (which holds the update) after answering it. Falsifiable: a token tied
// to that state's lifetime refuses the next change with Bad_InvalidState.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, ACloseAndUpdatesWriteEndsWithItsAnswer)
{
  mFakeStore->keepIssuerCrlsCallback = true;  // the merge reads the unmasked issuer CRLs through it
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // trusted certificates only: the other lists are read from the store
  trustList.trusted_certificates().push_back(mLeafCert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());
  ASSERT_FALSE(mFakeStore->keptIssuerCrlsCallbacks.empty()) << "the store kept the merge's read callback";

  auto removed = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true);
  EXPECT_TRUE(removed.is_good()) << describe_chain(removed.status_code());
  mFakeStore->keptIssuerCrlsCallbacks.clear();
}

// A reset still waiting when the manager goes is answered (Bad_InternalError), so the push service still
// reaches the shutdown Part 12 7.10.10 requires. Falsifiable: a dropped request is never answered.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, AResetWaitingWhenTheManagerGoesIsStillAnswered)
{
  auto crypto = FakeAsyncCrypto::create();
  crypto->set_crl_answer(FakeAsyncCrypto::CrlAnswer::Hold);
  mCrypto = crypto;
  mFakeStore->issuerCrls = {mPki->create_crl(mCaCert, mCaKeys, {})};
  create_manager();
  mManager->remove_certificate_async(
    mSessionA, thumbprint_hex(mCaCert), /*isTrustedCertificate=*/false, [](VoidResult) {});
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (crypto->held_crl_validation_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(crypto->held_crl_validation_count(), 1u);
  auto cleared = std::make_shared<std::promise<VoidResult>>();
  mManager->clear_lists_async([cleared](VoidResult r) { cleared->set_value(std::move(r)); });
  auto clearedFuture = cleared->get_future();
  ASSERT_EQ(clearedFuture.wait_for(200ms), std::future_status::timeout) << "the reset is waiting";

  mManager->shutdown();
  mManager.reset();

  ASSERT_EQ(clearedFuture.wait_for(5s), std::future_status::ready) << "answered although its manager went";
  EXPECT_EQ(clearedFuture.get().status_code(), StatusCode{Status::BadInternalError});
  crypto->release_held_crl_validations();
}

// A handle open for write when the reset arrives is closed by it, so it cannot CloseAndUpdate the old lists
// back.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(TrustListTest, TheResetClosesAHandleOpenForWrite)
{
  create_manager();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());

  auto cleared = std::make_shared<std::promise<VoidResult>>();
  mManager->clear_lists_async([cleared](VoidResult r) { cleared->set_value(std::move(r)); });
  auto clearedFuture = cleared->get_future();
  ASSERT_EQ(clearedFuture.wait_for(5s), std::future_status::ready);
  ASSERT_TRUE(clearedFuture.get().is_good());

  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeafCert->der_encoding());
  EXPECT_TRUE(write_sync(mSessionA, opened.value(), encode_trust_list(trustList)).is_bad())
    << "the handle was closed by the reset";
  EXPECT_TRUE(mFakeStore->trustedCerts.empty());
}

// Decision 28: a thumbprint that is not 40 hexadecimal digits is Bad_InvalidArgument (ThumbprintMalformed),
// refused before the store is asked.
// @verifies AC-SVR-PULLCRT-038-A-UNKNOWN-THUMBPRINT-IS-INVALID-ARGUMENT
TEST_F(TrustListTest, RemoveCertificate_MalformedThumbprint_ReturnsBadInvalidArgument)
{
  create_manager();

  auto result = remove_certificate_sync(mSessionA, "DEADBEEF", /*isTrusted=*/true);

  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ThumbprintMalformed");
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u);
}

// A certificate that is not a CA leaves the CRLs alone and is removed by the single-certificate call.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, RemovingALeafKeepsTheCrlsAndUsesTheSingleRemoval)
{
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), /*isTrusted=*/true);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  EXPECT_TRUE(mFakeStore->trustedCerts.empty());
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0], mCrl);
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
}

// A CA that issued none of the list's CRLs is removed by the single-certificate call; the CRLs stay.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, RemovingACaWithoutCrlsKeepsTheOtherCrls)
{
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Other CA", "200");
  mFakeStore->trustedCerts.push_back(otherCa);
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(otherCa), /*isTrusted=*/true);

  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mLeafCert);
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u) << "the CA issued none of them";
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
}

// The removal reads the list and then rewrites it; an AddCertificate arriving in between would be lost by the
// rewrite, so it is refused (Bad_InvalidState, as during a CloseAndUpdate). The hook queues the Add on the
// strand while the removal is reading, so it runs before the removal completes.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(TrustListTest, AnAddCertificateDuringARemovalRewriteIsRefused)
{
  auto caCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  mFakeStore->issuerCrls = {caCrl};
  std::promise<VoidResult> added;
  mFakeStore->beforeIssuerCrlsAnswer = [&]
  {
    mFakeStore->beforeIssuerCrlsAnswer = nullptr;  // once
    mManager->add_certificate_async(mSessionA,
      mLeaf2Cert->der_encoding(),
      /*isTrustedCertificate=*/true,
      [&added](VoidResult r) { added.set_value(std::move(r)); });
  };
  create_manager();

  auto removed = remove_certificate_sync(mSessionA, thumbprint_hex(mCaCert), /*isTrusted=*/false);
  auto addFuture = added.get_future();
  ASSERT_EQ(addFuture.wait_for(5s), std::future_status::ready);
  const auto addResult = addFuture.get();

  ASSERT_TRUE(removed.is_good()) << describe_chain(removed.status_code());
  EXPECT_EQ(addResult.status_code(), StatusCode{Status::BadInvalidState});
  EXPECT_TRUE(mFakeStore->issuerCerts.empty());
  EXPECT_TRUE(mFakeStore->issuerCrls.empty());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "the refused Add wrote nothing";
}

// Part 12 7.10.6: "If a Session is closed or abandoned then the transaction is closed and all pending changes
// are discarded" - including a CloseAndUpdate that staged before its transaction was recorded (review BR-13:
// otherwise the lists stayed staged with no transaction to apply or cancel them, and the next transaction
// built on them). Lists another Session staged are kept.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(TrustListTest, TheStagingSessionClosingDiscardsItsStagedLists)
{
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());

  mManager->on_session_closed_async(mSessionB);
  mManager->discard_staged_async(mSessionB);
  EXPECT_TRUE(staged_lists_sync().has_value()) << "another Session's close or discard keeps them";

  mManager->on_session_closed_async(mSessionA);
  EXPECT_FALSE(staged_lists_sync().has_value());
  ASSERT_TRUE(apply_staged_sync().is_good());
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
}

// 7.8.2.4 / 7.8.2.5: a staged CloseAndUpdate is a transaction in progress even before the push service has
// recorded it, so AddCertificate and RemoveCertificate are refused - also from the Session that staged it -
// rather than writing the store under lists ApplyChanges would write over (review BR-13).
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(TrustListTest, AddAndRemoveAreRefusedWhileAChangeIsStaged)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x04;  // IssuerCertificates only
  trustList.issuer_certificates().push_back(mCaCert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());

  EXPECT_EQ(add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true).status_code(),
    StatusCode{Status::BadTransactionPending});
  EXPECT_EQ(remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), true).status_code(),
    StatusCode{Status::BadTransactionPending});
  EXPECT_EQ(mFakeStore->addToTrustedCertificateCallCount, 0u);
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u);
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// ============================================================================
// Session binding
// ============================================================================

TEST_F(TrustListTest, ReadFromWrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto readResult = read_sync(mSessionB, handle, 100);

  ASSERT_TRUE(readResult.is_bad());
  EXPECT_EQ(readResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, OnSessionClosed_ClosesHandle)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  EXPECT_EQ(mManager->open_count(), 1u);

  // Fire session closed notification
  mManager->on_session_closed_async(mSessionA);

  // Wait for the strand to process
  std::promise<void> drain;
  auto drainFuture = drain.get_future();
  // Open attempt will fail or succeed; either way it drains the strand
  std::promise<Result<uint32_t>> p;
  mManager->open_async(mSessionA, 0x06, [&p](Result<uint32_t> r) { p.set_value(std::move(r)); });
  auto reopenResult = p.get_future().get();

  // After session close, the handle should have been closed, so reopen should succeed
  EXPECT_TRUE(reopenResult.is_good());
}

// ============================================================================
// IsWriteOpen query
// ============================================================================

TEST_F(TrustListTest, IsWriteOpen_WhenWriteOpen_ReturnsTrue)
{
  create_manager();

  open_sync(mSessionA, 0x06);

  auto result = is_write_open_sync();
  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value());
}

TEST_F(TrustListTest, IsWriteOpen_WhenReadOpen_ReturnsFalse)
{
  create_manager();

  open_sync(mSessionA, 0x01);

  auto result = is_write_open_sync();
  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value());
}

TEST_F(TrustListTest, IsWriteOpen_WhenNoHandle_ReturnsFalse)
{
  create_manager();

  auto result = is_write_open_sync();
  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value());
}

// ============================================================================
// OpenCount property
// ============================================================================

TEST_F(TrustListTest, OpenCount_WhenOpen_ReturnsOne)
{
  create_manager();

  open_sync(mSessionA, 0x06);

  EXPECT_EQ(mManager->open_count(), 1u);
}

TEST_F(TrustListTest, OpenCount_WhenClosed_ReturnsZero)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  close_sync(mSessionA, openResult.value());

  EXPECT_EQ(mManager->open_count(), 0u);
}

// ============================================================================
// Activity timeout
// ============================================================================

TEST_F(TrustListTest, ActivityTimeout_ClosesStaleHandle)
{
  // Use a very short timeout
  create_manager(65535, 100ms);

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  EXPECT_EQ(mManager->open_count(), 1u);

  // Wait for timeout to fire
  std::this_thread::sleep_for(300ms);

  // The handle should have been auto-closed
  EXPECT_EQ(mManager->open_count(), 0u);
}

// ============================================================================
// Size enforcement
// ============================================================================

TEST_F(TrustListTest, WriteAndCloseAndUpdate_WithAllLists_UpdatesBothStores)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  // Build a trust list with both trusted and issuer certificates
  TrustListDataType trustList;
  trustList.specified_lists() = 0x0F;  // All lists
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  trustList.issuer_certificates().push_back(mCaCert->der_encoding());
  trustList.trusted_crls().push_back(mCrl->der_encoding());

  auto encoded = encode_trust_list(trustList);
  write_sync(mSessionA, handle, std::move(encoded));

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  // Both stores should have been replaced
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());

  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCerts[0]->der_encoding(), mCaCert->der_encoding());

  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
}

TEST_F(TrustListTest, OpenReadOnlyMode_AllowsSecondOpenAfterClose)
{
  create_manager();

  auto open1 = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(open1.is_good());
  auto handle1 = open1.value();

  close_sync(mSessionA, handle1);

  auto open2 = open_sync(mSessionB, 0x01);
  EXPECT_TRUE(open2.is_good());
}

TEST_F(TrustListTest, OpenReadThenOpenWrite_FailsWhileReadOpen)
{
  create_manager();

  auto openRead = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openRead.is_good());

  auto openWrite = open_sync(mSessionB, 0x06);
  EXPECT_TRUE(openWrite.is_bad());
  EXPECT_EQ(openWrite.status_code(), StatusCode{Status::BadNotWritable});
}

// RATIFIED (owner report 2026-10-03, BR-13; OPC 10000-12 7.8.2.5): RemoveCertificate is not part of a
// transaction - it changes the TrustList at once and opens none (formerly
// RemoveCertificate_NotifiesModifiedCallback, which asserted it joined one). Its claim is released when it
// completes.
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(TrustListTest, RemoveCertificateAppliesAtOnceAndOpensNoTransaction)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  mStageUntilApply = true;
  create_manager();

  auto result = remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), true);
  ASSERT_TRUE(result.is_good()) << describe_chain(result.status_code());
  ASSERT_TRUE(is_write_open_sync().is_good());  // a strand barrier behind the completion

  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "removed from the store at once";
  EXPECT_FALSE(staged_lists_sync().has_value());
  std::lock_guard lock(mModifiedMutex);
  EXPECT_TRUE(mModifiedSessionIds.empty()) << "no transaction is opened";
  EXPECT_EQ(mAbandonedSessionIds.size(), 1u) << "the claim is released";
}

// OPC 10000-12 7.8.2.4 / 7.8.2.5: AddCertificate and RemoveCertificate "return Bad_TransactionPending if a
// transaction is in progress" - the caller's own included - and change nothing. The manager asks the
// immediate gate (the push service answers it, CertificatePushServiceTest covers that answer).
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(TrustListTest, AddAndRemoveAreRefusedWhileATransactionIsInProgress)
{
  TrustListManager::Dependencies deps{
    .strand = boost::asio::make_strand(mPool.get_executor()),
    .certificateStore = mFakeStore,
    .crypto = mCrypto,
    .executor = mPool.get_executor(),
    .logger = Logger{},
    .modificationClaim = [](const NodeId&) -> Result<std::shared_ptr<TrustListModificationClaim>>
    { return std::make_shared<TrustListModificationClaim>(nullptr); },
    .immediateModificationClaim = [](const NodeId&) -> Result<std::shared_ptr<TrustListModificationClaim>>
    { return StatusCode{Status::BadTransactionPending}; },
    .stageUntilApply = true,
  };
  mManager = TrustListManager::create(std::move(deps), mModifiedCallback);

  EXPECT_EQ(add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true).status_code(),
    StatusCode{Status::BadTransactionPending});
  EXPECT_EQ(remove_certificate_sync(mSessionA, thumbprint_hex(mLeafCert), true).status_code(),
    StatusCode{Status::BadTransactionPending});
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mLeafCert);
  EXPECT_EQ(mFakeStore->addToTrustedCertificateCallCount, 0u);
  EXPECT_EQ(mFakeStore->removeFromTrustedCertificateCallCount, 0u);

  // CloseAndUpdate asks the transaction gate, which joins the transaction.
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  auto updated = update_trust_list_sync(trustList);
  ASSERT_TRUE(updated.is_good()) << describe_chain(updated.status_code());
  EXPECT_TRUE(updated.value());
}

// ============================================================================
// CloseAndUpdate inside a push transaction (OPC 10000-12 7.8.2.3, 7.10.1)
// ============================================================================

// "If a transaction exists, the Server does not update the TrustList until ApplyChanges ... is called. Any
// Clients that read the TrustList before ApplyChanges is called will receive the existing TrustList before
// the transaction started." Falsifiable: the former manager wrote the store at CloseAndUpdate.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(TrustListTest, CloseAndUpdateInATransactionIsStagedUntilApplyChanges)
{
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());

  auto modified = expect_modified();
  auto updated = update_trust_list_sync(trustList);
  ASSERT_TRUE(updated.is_good()) << describe_chain(updated.status_code());
  EXPECT_TRUE(updated.value()) << "applyChangesRequired";
  EXPECT_EQ(modified.get(), mSessionA) << "the change joins the session's transaction";

  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "the store is untouched";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mLeafCert);
  const auto read = read_trust_list_sync();
  ASSERT_EQ(read.trusted_certificates().size(), 1u);
  EXPECT_EQ(read.trusted_certificates()[0], mLeafCert->der_encoding()) << "reads return the list before";
  const auto staged = staged_lists_sync();
  ASSERT_TRUE(staged.has_value());
  ASSERT_EQ(staged->trustedCerts.size(), 1u);
  EXPECT_EQ(staged->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());
  ASSERT_EQ(staged->issuerCerts.size(), 1u) << "the unmasked lists are staged as they are";
  EXPECT_EQ(staged->trustedCrls.size(), 1u);

  ASSERT_TRUE(apply_staged_sync().is_good());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());
  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->issuerCerts[0], mCaCert);
  EXPECT_FALSE(staged_lists_sync().has_value()) << "applied lists are no longer staged";
  EXPECT_NE(mManager->last_update_time(), UtcTime{}) << "LastUpdateTime reflects the applied change";
}

// 7.10.1: "a Server shall queue the changes in the order that they were requested": a second CloseAndUpdate
// builds on the first, so a list it does not mask keeps the staged value, not the store's.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(TrustListTest, ASecondUpdateInTheTransactionBuildsOnTheStagedLists)
{
  mStageUntilApply = true;
  create_manager();
  TrustListDataType first;
  first.specified_lists() = 0x01;
  first.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(update_trust_list_sync(first).is_good());

  TrustListDataType second;
  second.specified_lists() = 0x02;  // TrustedCrls only: the trusted certificates are the staged ones
  ASSERT_TRUE(update_trust_list_sync(second).is_good());

  const auto staged = staged_lists_sync();
  ASSERT_TRUE(staged.has_value());
  ASSERT_EQ(staged->trustedCerts.size(), 1u);
  EXPECT_EQ(staged->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());
  EXPECT_TRUE(staged->trustedCrls.empty());
  ASSERT_TRUE(apply_staged_sync().is_good());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeaf2Cert->der_encoding());
  EXPECT_TRUE(mFakeStore->trustedCrls.empty());
}

// 7.10.8 / 7.10.6: CancelChanges and the owner's Session closing discard the staged changes; the store keeps
// its lists.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(TrustListTest, DiscardingTheStagedListsLeavesTheStoreAsItWas)
{
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());
  ASSERT_TRUE(staged_lists_sync().has_value());

  mManager->discard_staged_async();
  EXPECT_FALSE(staged_lists_sync().has_value());
  ASSERT_TRUE(apply_staged_sync().is_good()) << "nothing staged: nothing to write";
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mLeafCert);
}

// A store that refuses the write fails ApplyChanges with its own result, once.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(TrustListTest, ApplyingTheStagedListsReportsTheStoresFailure)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("TrustListReplaceUnavailable", "Trusted list replacement is unavailable", "Test")};
  mFakeStore->replaceTrustedCertificateResults.emplace_back(upstream);
  mStageUntilApply = true;
  create_manager();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(update_trust_list_sync(trustList).is_good());

  size_t completions{0};
  std::promise<VoidResult> p;
  mManager->apply_staged_async(
    [&](VoidResult r)
    {
      ++completions;
      p.set_value(std::move(r));
    });
  const auto result = p.get_future().get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstream.shared_detail().get());
  ASSERT_TRUE(is_write_open_sync().is_good());
  EXPECT_EQ(completions, 1u);
}

TEST_F(TrustListTest, WriteFromWrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  ByteString someData{0x01, 0x02};
  auto writeResult = write_sync(mSessionB, handle, std::move(someData));

  ASSERT_TRUE(writeResult.is_bad());
  EXPECT_EQ(writeResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, GetPositionFromWrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto posResult = get_position_sync(mSessionB, handle);
  ASSERT_TRUE(posResult.is_bad());
  EXPECT_EQ(posResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, SetPositionFromWrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto seekResult = set_position_sync(mSessionB, handle, 0);
  ASSERT_TRUE(seekResult.is_bad());
  EXPECT_EQ(seekResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, CloseAndUpdate_WrongSession_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  auto handle = openResult.value();

  auto updateResult = close_and_update_sync(mSessionB, handle);
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, ReadNoHandle_Fails)
{
  create_manager();

  auto readResult = read_sync(mSessionA, 1, 100);
  ASSERT_TRUE(readResult.is_bad());
  EXPECT_EQ(readResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, CloseNoHandle_Fails)
{
  create_manager();

  auto closeResult = close_sync(mSessionA, 1);
  ASSERT_TRUE(closeResult.is_bad());
  EXPECT_EQ(closeResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, WriteNoHandle_Fails)
{
  create_manager();

  ByteString data{0x01};
  auto writeResult = write_sync(mSessionA, 1, std::move(data));
  ASSERT_TRUE(writeResult.is_bad());
  EXPECT_EQ(writeResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, GetPositionNoHandle_Fails)
{
  create_manager();

  auto posResult = get_position_sync(mSessionA, 1);
  ASSERT_TRUE(posResult.is_bad());
  EXPECT_EQ(posResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, SetPositionNoHandle_Fails)
{
  create_manager();

  auto seekResult = set_position_sync(mSessionA, 1, 0);
  ASSERT_TRUE(seekResult.is_bad());
  EXPECT_EQ(seekResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, CloseAndUpdateNoHandle_Fails)
{
  create_manager();

  auto updateResult = close_and_update_sync(mSessionA, 1);
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidArgument});
}

TEST_F(TrustListTest, OnSessionClosed_DifferentSession_DoesNotCloseHandle)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  // Close a different session - should have no effect
  mManager->on_session_closed_async(mSessionB);

  // Drain the strand
  auto isOpen = is_write_open_sync();
  ASSERT_TRUE(isOpen.is_good());
  EXPECT_TRUE(isOpen.value());
  EXPECT_EQ(mManager->open_count(), 1u);
}

TEST_F(TrustListTest, OpenWithMasks_WhenAlreadyOpen_Fails)
{
  create_manager();

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  auto masksResult = open_with_masks_sync(mSessionB, 0x0F);
  ASSERT_TRUE(masksResult.is_bad());
  EXPECT_EQ(masksResult.status_code(), StatusCode{Status::BadNotWritable});
}

// ============================================================================
// CertificatePushService tests
// ============================================================================

class CertificatePushServiceTest : public ::testing::Test
{
protected:
  virtual CertificatePushService::Dependencies::DependencyFailureDetailBuilder
    dependency_failure_detail_builder()
  {
    return {};
  }

  virtual CertificatePushService::Dependencies::ApplyWriteStateCheck apply_write_state_check()
  {
    return {};
  }

  virtual CertificatePushService::Dependencies::CertificateDerEncoder certificate_der_encoder()
  {
    return {};
  }

  // The server's Session lookup: a Session is gone once mark_session_gone named it (the server
  // removes a Session before its close event is delivered).
  void mark_session_gone(const NodeId& sessionId)
  {
    const std::lock_guard<std::mutex> lock(mGoneSessionsMutex);
    mGoneSessions.push_back(sessionId);
  }

  std::mutex mGoneSessionsMutex;
  std::vector<NodeId> mGoneSessions;
  /// The production wiring stages a CloseAndUpdate until ApplyChanges (Part 12 7.8.2.3); a fixture
  /// that drives that path sets this before SetUp.
  bool mStageTrustListUntilApply{false};
  /// Runs inside the re-evaluation hook, i.e. while ApplyChanges is still in progress.
  std::function<void()> mDuringReevaluation;
  /// The push service's crypto is a FakeAsyncCrypto (mFakeCrypto) forwarding to a real one (set before
  /// SetUp).
  bool mUseFakeAsyncCrypto{false};
  std::shared_ptr<FakeAsyncCrypto> mFakeCrypto;
  /// ResetToServerDefaults' deadline (set before SetUp); long, so only a test that shortens it meets it.
  std::chrono::milliseconds mResetDeadline{30000};
  std::atomic<int> mShutdownRequestCount{0};  // the requestShutdown hook's calls

  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    if (mUseFakeAsyncCrypto)
    {
      mFakeCrypto = FakeAsyncCrypto::create();
      mCrypto = mFakeCrypto;
    }
    mPki = std::make_unique<TestPki>(mCrypto);

    // Generate a CA key pair and root CA cert
    mCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mCaCert = mPki->create_root_ca(mCaKeys);

    // Generate a leaf key pair and cert (serves as existing application certificate)
    mLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    auto now = DateTime::now();
    mLeafCert = mPki->create_leaf_cert(mLeafKeys,
      mCaKeys,
      mCaCert,
      now,
      DateTime{now.value() + std::chrono::days{30}},
      {"urn:test:server"},
      {"localhost"},
      "TestServer");

    // Set up fake store with an existing application certificate
    mFakeStore = std::make_shared<InMemoryFakeCertificateStore>();
    mFakeStore->trustedCerts.push_back(mCaCert);

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = mLeafCert;
    appCert.keys = mLeafKeys;
    mFakeStore->appCerts.push_back(appCert);

    // Create TrustListManager (needed by CertificatePushService)
    TrustListManager::Dependencies tlmDeps{
      .strand = boost::asio::make_strand(mPool.get_executor()),
      .certificateStore = mFakeStore,
      .crypto = mCrypto,
      .executor = mPool.get_executor(),
      .maxTrustListSize = 65535,
      .activityTimeout = 60000ms,
      .logger = Logger{},
      .stageUntilApply = mStageTrustListUntilApply,
    };
    mTrustList = TrustListManager::create(std::move(tlmDeps), mTrustListModifiedCallback);

    // Create CertificatePushService
    CertificatePushService::Dependencies deps{
      .strand = boost::asio::make_strand(mPool.get_executor()),
      .crypto = mCrypto,
      .certificateStore = mFakeStore,
      .trustList = mTrustList,
      .executor = mPool.get_executor(),
      .logger = Logger{},
      .applicationUri = "urn:test:server",
      .hostnames = {"localhost"},
      .closeAllChannels =
        [this](const NodeId&,
          server::MethodResponseCorrelation correlation,
          std::function<void(VoidResult)>
            callback)
      {
        ++mChannelCloseHookCount;
        mChannelCloseCorrelation = correlation;
        mEffectOrder.emplace_back("close");
        if (mChannelCloseHookThrows)
          throw std::runtime_error{"injected channel-close hook failure"};
        if (mChannelCloseHookResult)
        {
          callback(*mChannelCloseHookResult);
          return;
        }
        mChannelsClosed = true;
        callback(VoidResult{});
      },
      .reevaluateCertificates =
        [this](const NodeId& originSessionId,
          server::MethodResponseCorrelation correlation,
          std::function<void(VoidResult)>
            callback)
      {
        ++mReevaluationHookCount;
        mReevaluationCorrelation = correlation;
        mEffectOrder.emplace_back("reevaluate");
        if (mDuringReevaluation)
          mDuringReevaluation();
        if (mReevaluationHookThrows)
          throw std::runtime_error{"injected certificate re-evaluation hook failure"};
        if (mReevaluationHookResult)
        {
          callback(*mReevaluationHookResult);
          return;
        }
        mReevaluationOriginSessionId = originSessionId;
        mReevaluationServerRequestId = correlation.requestId;
        ++mReevaluationCount;
        callback(VoidResult{});
      },
      .requestShutdown = [this]() { ++mShutdownRequestCount; },
      .publishTransactionDiagnostics = [this](TransactionDiagnosticsRecord record)
      { mTransactionDiagnostics.emplace_back(std::move(record)); },
      .dependencyFailureDetailBuilder = dependency_failure_detail_builder(),
      .applyWriteStateCheck = apply_write_state_check(),
      .certificateDerEncoder = certificate_der_encoder(),
      .sessionExists =
        [this](const NodeId& sessionId)
      {
        const std::lock_guard<std::mutex> lock(mGoneSessionsMutex);
        return std::find(mGoneSessions.begin(), mGoneSessions.end(), sessionId) == mGoneSessions.end();
      },
      .resetDeadline = mResetDeadline,
    };
    mPushService = CertificatePushService::create(std::move(deps));
  }

  void TearDown() override
  {
    if (mPushService)
    {
      mPushService->shutdown();
    }
    if (mTrustList)
    {
      mTrustList->shutdown();
    }
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  // --- Sync wrappers ---

  Result<ByteString> create_signing_request_sync(const NodeId& sessionId, const NodeId& groupId,
    const NodeId& typeId, const String& subjectName, bool regeneratePrivateKey, const ByteString& nonce)
  {
    std::promise<Result<ByteString>> p;
    mCreateSigningRequestCompletionCount.store(0);
    mPushService->create_signing_request_async(sessionId,
      groupId,
      typeId,
      subjectName,
      regeneratePrivateKey,
      nonce,
      [this, &p](Result<ByteString> r)
      {
        if (mCreateSigningRequestCompletionCount.fetch_add(1) == 0)
          p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  Result<bool> update_certificate_sync(const NodeId& sessionId, const NodeId& groupId, const NodeId& typeId,
    ByteString certificate, std::vector<ByteString> issuerCertificates, String privateKeyFormat,
    ByteString privateKey)
  {
    std::promise<Result<bool>> p;
    mUpdateCertificateCompletionCount.store(0);
    mPushService->update_certificate_async(sessionId,
      groupId,
      typeId,
      std::move(certificate),
      std::move(issuerCertificates),
      std::move(privateKeyFormat),
      std::move(privateKey),
      [this, &p](Result<bool> r)
      {
        if (mUpdateCertificateCompletionCount.fetch_add(1) == 0)
          p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  struct PendingUpdateResult
  {
    std::shared_ptr<std::atomic_size_t> completionCount;
    std::future<Result<bool>> result;
  };

  PendingUpdateResult start_update_certificate(const NodeId& sessionId, ByteString certificate)
  {
    auto completionCount = std::make_shared<std::atomic_size_t>(0);
    auto promise = std::make_shared<std::promise<Result<bool>>>();
    auto future = promise->get_future();
    mPushService->update_certificate_async(sessionId,
      mNullGroupId,
      mRsaSha256TypeId,
      std::move(certificate),
      std::vector<ByteString>{mCaCert->der_encoding()},
      String{},
      ByteString{},
      [completionCount, promise](Result<bool> result)
      {
        if (completionCount->fetch_add(1) == 0)
          promise->set_value(std::move(result));
      });
    return PendingUpdateResult{std::move(completionCount), std::move(future)};
  }

  VoidResult apply_changes_sync(const NodeId& sessionId, uint32_t serverRequestId = 1)
  {
    return apply_changes_with_correlation_sync(
      sessionId, server::MethodResponseCorrelation{1, serverRequestId});
  }

  VoidResult apply_changes_with_correlation_sync(
    const NodeId& sessionId, server::MethodResponseCorrelation correlation)
  {
    std::promise<VoidResult> p;
    mApplyCompletionCount.store(0);
    mPushService->apply_changes_async(sessionId,
      correlation,
      [this, &p](VoidResult r)
      {
        if (mApplyCompletionCount.fetch_add(1) == 0)
          p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  VoidResult cancel_changes_sync(const NodeId& sessionId)
  {
    std::promise<VoidResult> p;
    mPushService->cancel_changes_async(sessionId, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  Result<std::vector<ByteString>> get_rejected_list_sync()
  {
    std::promise<Result<std::vector<ByteString>>> p;
    mGetRejectedListCompletionCount.store(0);
    mPushService->get_rejected_list_async(
      [this, &p](Result<std::vector<ByteString>> r)
      {
        if (mGetRejectedListCompletionCount.fetch_add(1) == 0)
          p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>> get_certificates_sync(const NodeId& groupId)
  {
    std::promise<Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>> p;
    mGetCertificatesCompletionCount.store(0);
    mPushService->get_certificates_async(groupId,
      [this, &p](Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>> r)
      {
        if (mGetCertificatesCompletionCount.fetch_add(1) == 0)
          p.set_value(std::move(r));
      });
    return p.get_future().get();
  }

  /// Helper: create a valid leaf certificate signed by our CA, using the given key pair.
  std::shared_ptr<const X509Certificate> create_valid_leaf(
    std::shared_ptr<const AsymmetricKeyPair> subjectKeys)
  {
    auto now = DateTime::now();
    return mPki->create_leaf_cert(subjectKeys,
      mCaKeys,
      mCaCert,
      now,
      DateTime{now.value() + std::chrono::days{30}},
      {"urn:test:server"},
      {"localhost"},
      "TestServer");
  }

  // Fixtures
  boost::asio::thread_pool mPool{1};
  std::shared_ptr<const Crypto> mCrypto;
  std::unique_ptr<TestPki> mPki;

  shared_ptr<const AsymmetricKeyPair> mCaKeys;
  shared_ptr<const X509Certificate> mCaCert;
  shared_ptr<const AsymmetricKeyPair> mLeafKeys;
  shared_ptr<const X509Certificate> mLeafCert;

  std::shared_ptr<InMemoryFakeCertificateStore> mFakeStore;
  std::shared_ptr<TrustListManager> mTrustList;
  std::shared_ptr<CertificatePushService> mPushService;

  std::atomic<bool> mChannelsClosed{false};
  std::atomic_size_t mCreateSigningRequestCompletionCount{0};
  std::atomic_size_t mUpdateCertificateCompletionCount{0};
  std::atomic_size_t mApplyCompletionCount{0};
  std::atomic_size_t mGetRejectedListCompletionCount{0};
  std::atomic_size_t mGetCertificatesCompletionCount{0};
  size_t mChannelCloseHookCount{0};
  optional<server::MethodResponseCorrelation> mChannelCloseCorrelation;
  bool mChannelCloseHookThrows{false};
  optional<VoidResult> mChannelCloseHookResult;
  size_t mReevaluationCount{0};
  size_t mReevaluationHookCount{0};
  optional<server::MethodResponseCorrelation> mReevaluationCorrelation;
  bool mReevaluationHookThrows{false};
  optional<VoidResult> mReevaluationHookResult;
  NodeId mReevaluationOriginSessionId;
  uint32_t mReevaluationServerRequestId{0};
  std::vector<std::string> mEffectOrder;
  std::vector<TransactionDiagnosticsRecord> mTransactionDiagnostics;

  // Common IDs
  NodeId mSessionA{1, 100u};
  NodeId mSessionB{1, 200u};
  NodeId mNullGroupId{};
  NodeId mRsaSha256TypeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)};

  // TrustListManager modified callback (required but not primary focus)
  TrustListManager::TrustListModifiedCallback mTrustListModifiedCallback =
    [](NodeId, std::shared_ptr<TrustListModificationClaim>) {
    };
};

class CertificatePushServiceMappingThrowTest : public CertificatePushServiceTest
{
protected:
  CertificatePushService::Dependencies::DependencyFailureDetailBuilder
    dependency_failure_detail_builder() override
  {
    return [this](StatusCode) -> std::shared_ptr<const ErrorDetail>
    {
      throw UaException{mMappingFailure};
    };
  }

  StatusCode mMappingFailure{Status::BadResourceUnavailable,
    make_error_detail("DiagnosticBuilderUnavailable", "Injected diagnostic builder failure",
      "CertificatePushServiceMappingThrowTest")};
};

class CertificatePushServiceApplyPreflightTest : public CertificatePushServiceTest
{
protected:
  CertificatePushService::Dependencies::ApplyWriteStateCheck apply_write_state_check() override
  {
    return [this](std::function<void(Result<bool>)> callback)
    {
      ++mApplyWriteStateCheckCount;
      mApplyWriteStateCallback = std::move(callback);
    };
  }

  void complete_apply_write_state_check(Result<bool> result)
  {
    ASSERT_TRUE(mApplyWriteStateCallback.has_value());
    auto callback = std::move(*mApplyWriteStateCallback);
    mApplyWriteStateCallback.reset();
    callback(std::move(result));
  }

  std::optional<std::function<void(Result<bool>)>> mApplyWriteStateCallback;
  size_t mApplyWriteStateCheckCount{0};
};

class CertificatePushServiceMaterializationThrowTest : public CertificatePushServiceTest
{
protected:
  CertificatePushService::Dependencies::CertificateDerEncoder certificate_der_encoder() override
  {
    return [this](const std::shared_ptr<const X509Certificate>&) -> ByteString
    {
      throw UaException{mMaterializationFailure};
    };
  }

  StatusCode mMaterializationFailure{Status::BadEncodingError,
    make_error_detail("CertificateDerEncodingFailed", "Injected DER encoding failure",
      "CertificatePushServiceMaterializationThrowTest")};
};

// ============================================================================
// CreateSigningRequest
// ============================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-011, scope=function)
// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-01-CSR-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_ValidParams_ReturnsCsr)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{"Test"}, true, nonce);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_FALSE(result.value().empty());
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mCreateSigningRequestCompletionCount.load(), 1u);
}

// The CSR must carry BOTH of its extensions, under exactly ONE extReq attribute.
//
// X509_REQ_add_extensions does not append to a list - it adds the whole list as the request's extReq
// ATTRIBUTE. The builder called it once per extension, so the second call asked for a second extReq and
// OpenSSL 3 refused it with "duplicate attribute". Every SDK CSR needs at least keyUsage and
// subjectAltName, so CreateSigningRequest could not produce a request at all.
//
// `is_good()` alone would not have caught the regression this pins: a fix that attached only the first
// extension, or silently dropped them, also returns a well-formed signed CSR. So this parses the DER the
// service actually returned and asserts the attribute count as well as the two extensions.
TEST_F(CertificatePushServiceTest, CreateSigningRequest_CarriesEveryExtensionUnderOneAttribute)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{"Test"}, true, nonce);
  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());

  const auto der = result.value();
  ASSERT_FALSE(der.empty());
  const unsigned char* cursor = reinterpret_cast<const unsigned char*>(der.data());
  X509_REQ* raw = d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der.size()));
  ASSERT_NE(raw, nullptr) << "the service returned bytes that are not a DER-encoded CSR";
  const std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{raw, &X509_REQ_free};

  // Exactly one extReq attribute: the defect was a second one.
  int extReqAttributes = 0;
  for (int i = 0; i < X509_REQ_get_attr_count(req.get()); ++i)
  {
    const X509_ATTRIBUTE* attribute = X509_REQ_get_attr(req.get(), i);
    if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(const_cast<X509_ATTRIBUTE*>(attribute))) == NID_ext_req)
      ++extReqAttributes;
  }
  EXPECT_EQ(extReqAttributes, 1) << "extensions belong to ONE extReq attribute; a second is the defect "
                                    "OpenSSL rejects as a duplicate";

  STACK_OF(X509_EXTENSION)* extensions = X509_REQ_get_extensions(req.get());
  ASSERT_NE(extensions, nullptr) << "the CSR carries no extensions at all";
  bool haveKeyUsage = false;
  bool haveSubjectAltName = false;
  for (int i = 0; i < sk_X509_EXTENSION_num(extensions); ++i)
  {
    const int nid = OBJ_obj2nid(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(extensions, i)));
    haveKeyUsage = haveKeyUsage || nid == NID_key_usage;
    haveSubjectAltName = haveSubjectAltName || nid == NID_subject_alt_name;
  }
  sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

  EXPECT_TRUE(haveKeyUsage) << "the requested key usage must reach the CSR";
  EXPECT_TRUE(haveSubjectAltName)
    << "the ApplicationUri travels in subjectAltName - a CSR without it cannot yield a usable "
       "application instance certificate";
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-01-CSR-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_CertificateTypeListFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("CertificateCatalogueUnavailable",
      "Application certificate catalogue is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->applicationCertificateListResults.emplace_back(upstream);

  auto result = create_signing_request_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    String{"Test"},
    true,
    ByteString(std::vector<byte>(32, byte{0xAB})));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mCreateSigningRequestCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-01-CSR-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_SubjectCertificateFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadCommunicationError,
    make_error_detail("CurrentCertificateUnavailable",
      "Current application certificate is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->applicationCertificateResults.emplace_back(mFakeStore->appCerts.front());
  mFakeStore->applicationCertificateResults.emplace_back(upstream);

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{}, false, ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 2u);
  EXPECT_EQ(mCreateSigningRequestCompletionCount.load(), 1u);
}

TEST_F(CertificatePushServiceTest, CreateSigningRequest_NonceTooShort_Fails)
{
  ByteString shortNonce(std::vector<byte>(16, byte{0xAB}));

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{"Test"}, true, shortNonce);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-01-CSR-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest,
  CreateSigningRequest_UnsupportedCertificateTypeAfterSuccessfulListReturnsBadInvalidArgument)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  const NodeId invalidType{0, static_cast<uint32_t>(ObjectTypeId::EccNistP256ApplicationCertificateType)};

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, invalidType, String{"Test"}, true, nonce);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mCreateSigningRequestCompletionCount.load(), 1u);
}

TEST_F(CertificatePushServiceTest, CreateSigningRequest_UseExistingKey)
{
  auto result = create_signing_request_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, String{"Test"}, false, ByteString{});

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_FALSE(result.value().empty());
}

// The CertificateType is checked only against a list the store answered Good. An Uncertain answer is refused
// (Bad_InternalError, CertificateStoreAnswerUncertain carrying the store's code) and is not taken for a
// supported type: the request goes no further than the check. UpdateCertificate makes the same check.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_AnUncertainCertificateTypeListIsRefused)
{
  mFakeStore->applicationCertificateListResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});

  auto result =
    create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{}, false, ByteString{});

  expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u) << "the request went on past the type check";
  EXPECT_EQ(mCreateSigningRequestCompletionCount.load(), 1u);
}

// The existing keys and the subject of a CSR are taken only from a Good store answer. An Uncertain answer to
// either read is refused (Bad_InternalError, CertificateStoreAnswerUncertain carrying the store's code) and
// no CSR is returned.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_AnUncertainKeysOrSubjectAnswerIsRefused)
{
  {
    SCOPED_TRACE("the existing keys");
    mFakeStore->applicationCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});
    auto result = create_signing_request_sync(
      mSessionA, mNullGroupId, mRsaSha256TypeId, String{"Test"}, false, ByteString{});
    expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
    EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 1u);
  }
  {
    SCOPED_TRACE("the subject");
    mFakeStore->applicationCertificateResults.emplace_back(mFakeStore->appCerts.front());
    mFakeStore->applicationCertificateResults.emplace_back(StatusCode{Status::UncertainLastUsableValue});
    auto result =
      create_signing_request_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, String{}, false, ByteString{});
    expect_uncertain_answer_refusal(result.status_code(), "CertificateStoreAnswerUncertain");
    EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 3u);
  }
}

class CertificatePushServiceCsrCryptoAnswerTest : public CertificatePushServiceTest
{
public:
  CertificatePushServiceCsrCryptoAnswerTest()
  {
    mUseFakeAsyncCrypto = true;
  }

protected:
  /// Starts a CreateSigningRequest that regenerates its key, with the crypto parked.
  std::future<Result<ByteString>> start_parked_signing_request()
  {
    auto answered = std::make_shared<std::promise<Result<ByteString>>>();
    auto future = answered->get_future();
    mFakeCrypto->set_park_async(true);
    mPushService->create_signing_request_async(mSessionA,
      mNullGroupId,
      mRsaSha256TypeId,
      String{"Test"},
      true,
      ByteString(std::vector<byte>(32, byte{0xAB})),
      [answered](Result<ByteString> result) { answered->set_value(std::move(result)); });
    return future;
  }

  /// Waits until @p pending answers more than zero.
  static bool wait_until_parked(const std::function<size_t()>& pending)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (pending() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(1ms);
    return pending() > 0;
  }
};

// A CSR's key pair is used, and the CSR returned, only on a Good crypto answer. An Uncertain answer to the
// key generation, or to the CSR itself, is refused (Bad_InternalError, CryptoAnswerUncertain carrying the
// provider's code) and no CSR is returned.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(CertificatePushServiceCsrCryptoAnswerTest, AnUncertainKeyPairOrCsrAnswerIsRefused)
{
  {
    SCOPED_TRACE("the key pair");
    auto answered = start_parked_signing_request();
    ASSERT_TRUE(
      wait_until_parked([this] { return mFakeCrypto->pending_create_asymmetric_key_pair_count(); }));
    mFakeCrypto->set_park_async(false);
    mFakeCrypto->complete_pending_create_asymmetric_key_pair(
      0, KeyPairResult{StatusCode{Status::UncertainLastUsableValue}});
    ASSERT_EQ(answered.wait_for(5s), std::future_status::ready);
    expect_uncertain_answer_refusal(answered.get().status_code(), "CryptoAnswerUncertain");
  }
  {
    SCOPED_TRACE("the CSR");
    auto answered = start_parked_signing_request();
    ASSERT_TRUE(
      wait_until_parked([this] { return mFakeCrypto->pending_create_asymmetric_key_pair_count(); }));
    mFakeCrypto->complete_pending_create_asymmetric_key_pair(0, KeyPairResult{mLeafKeys});
    ASSERT_TRUE(
      wait_until_parked([this] { return mFakeCrypto->pending_create_certificate_signing_request_count(); }));
    mFakeCrypto->set_park_async(false);
    mFakeCrypto->complete_pending_create_certificate_signing_request(
      0, ByteStringResult{StatusCode{Status::UncertainLastUsableValue}});
    ASSERT_EQ(answered.wait_for(5s), std::future_status::ready);
    expect_uncertain_answer_refusal(answered.get().status_code(), "CryptoAnswerUncertain");
  }
}

// ============================================================================
// UpdateCertificate
// ============================================================================

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-02-UPDATE-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_WithExistingKey_Succeeds)
{
  // Create a new cert using the existing leaf key pair (same public key)
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  auto result = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_TRUE(result.value());  // applyChangesRequired
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 1u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-02-UPDATE-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_CertificateTypeListFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("CertificateCatalogueUnavailable",
      "Application certificate catalogue is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->applicationCertificateListResults.emplace_back(upstream);
  auto newCert = create_valid_leaf(mLeafKeys);

  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 0u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-02-UPDATE-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_ValidationFailureWrapsExactRichCause)
{
  const StatusCode upstream{Status::BadCertificateUntrusted,
    make_error_detail(
      "InjectedValidationFailure", "Injected certificate validation failure", "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->validateCertificateStatus = upstream;
  auto newCert = create_valid_leaf(mLeafKeys);

  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadSecurityChecksFailed}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateIntegrityValidationFailed");
  EXPECT_EQ(result.shared_detail()->innerStatus, upstream.value());
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause.get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-02-UPDATE-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_ExistingKeyFailureWrapsExactRichCause)
{
  const StatusCode upstream{Status::BadCommunicationError,
    make_error_detail("ExistingCertificateUnavailable",
      "Existing application certificate is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->applicationCertificateResults.emplace_back(upstream);
  auto newCert = create_valid_leaf(mLeafKeys);

  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadSecurityChecksFailed}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ExistingCertificateResolutionFailed");
  EXPECT_EQ(result.shared_detail()->innerStatus, upstream.value());
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause.get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 1u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-04-MAPPING-CONSTRUCTION-FAILURE, scope=function)
TEST_F(CertificatePushServiceMappingThrowTest,
  UpdateCertificate_ValidationMappingThrowCompletesOnceWithExactRichResult)
{
  mFakeStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};
  auto newCert = create_valid_leaf(mLeafKeys);

  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), mMappingFailure.value());
  EXPECT_EQ(result.shared_detail().get(), mMappingFailure.shared_detail().get());
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-04-MAPPING-CONSTRUCTION-FAILURE, scope=function)
TEST_F(CertificatePushServiceMappingThrowTest,
  UpdateCertificate_ExistingKeyMappingThrowCompletesOnceWithExactRichResult)
{
  mFakeStore->applicationCertificateResults.emplace_back(StatusCode{Status::BadCommunicationError});
  auto newCert = create_valid_leaf(mLeafKeys);

  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), mMappingFailure.value());
  EXPECT_EQ(result.shared_detail().get(), mMappingFailure.shared_detail().get());
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 1u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 1u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-CROSS-SESSION-RESERVATION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_InFlightFirstSessionRejectsSecondBeforePrerequisites)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  const auto certificate = create_valid_leaf(mLeafKeys)->der_encoding();

  auto first = start_update_certificate(mSessionA, certificate);
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mFakeStore->deferred_application_certificate_list_count(), 1u);

  auto second = start_update_certificate(mSessionB, certificate);
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(second.result.wait_for(std::chrono::milliseconds{0}), std::future_status::ready);
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);

  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());
  while (mFakeStore->complete_next_application_certificate_list())
  {
  }

  const auto firstResult = first.result.get();
  const auto secondResult = second.result.get();
  ASSERT_TRUE(firstResult.is_good()) << firstResult.status_code();
  ASSERT_TRUE(secondResult.is_bad());
  EXPECT_EQ(secondResult.status_code(), StatusCode{Status::BadTransactionPending});
  EXPECT_EQ(first.completionCount->load(), 1u);
  EXPECT_EQ(second.completionCount->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-LATE-COMPLETION-INVALIDATION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_LateCompletionAfterCancelCannotRecreateTransaction)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  auto pending = start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mFakeStore->deferred_application_certificate_list_count(), 1u);

  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good());
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());

  const auto result = pending.result.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "UpdateTransactionInvalidated");
  EXPECT_EQ(pending.completionCount->load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-LATE-COMPLETION-INVALIDATION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_LateCompletionAfterSessionCloseCannotRecreateTransaction)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  auto pending = start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mFakeStore->deferred_application_certificate_list_count(), 1u);

  mPushService->on_session_closed_async(mSessionA);
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());

  const auto result = pending.result.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "UpdateTransactionInvalidated");
  EXPECT_EQ(pending.completionCount->load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-FAILURE-ROLLBACK, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_FailedNewReservationRollsBackEmptyTransaction)
{
  auto result = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    ByteString(std::vector<byte>{byte{0x01}, byte{0x02}}),
    {},
    String{},
    ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateInvalid});
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-FAILURE-ROLLBACK, scope=function)
// @relation(AC-SVR-PULLCRT-028-FAILURE-PRESERVES-TRANSACTION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_FailedFlowPreservesPopulatedSameSessionTransaction)
{
  const auto originalCertificateCount = mFakeStore->appCerts.size();
  const auto certificate = create_valid_leaf(mLeafKeys)->der_encoding();
  ASSERT_TRUE(start_update_certificate(mSessionA, certificate).result.get().is_good());

  auto failed = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    ByteString(std::vector<byte>{byte{0x01}, byte{0x02}}),
    {},
    String{},
    ByteString{});
  ASSERT_TRUE(failed.is_bad());
  EXPECT_EQ(failed.status_code(), StatusCode{Status::BadCertificateInvalid});

  EXPECT_TRUE(apply_changes_sync(mSessionA).is_good());
  EXPECT_EQ(mFakeStore->appCerts.size(), originalCertificateCount + 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-FAILURE-ROLLBACK, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_FailedCreatorPreservesConcurrentSameSessionReservation)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("CertificateCatalogueUnavailable",
      "Application certificate catalogue is unavailable",
      "FakeCertificateStore")};
  mFakeStore->applicationCertificateListResults.emplace_back(upstream);
  mFakeStore->applicationCertificateListResults.emplace_back(mFakeStore->appCerts);
  mFakeStore->deferApplicationCertificateListResults = true;
  const auto certificate = create_valid_leaf(mLeafKeys)->der_encoding();

  auto creator = start_update_certificate(mSessionA, certificate);
  auto concurrent = start_update_certificate(mSessionA, certificate);
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mFakeStore->deferred_application_certificate_list_count(), 2u);
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());

  EXPECT_TRUE(creator.result.get().is_bad());
  EXPECT_TRUE(concurrent.result.get().is_good());
  EXPECT_EQ(creator.completionCount->load(), 1u);
  EXPECT_EQ(concurrent.completionCount->load(), 1u);
  EXPECT_TRUE(apply_changes_sync(mSessionA).is_good());
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-02-UPDATE-RICH-FAILURES, scope=function)
TEST_F(CertificatePushServiceTest,
  UpdateCertificate_UnsupportedCertificateTypeAfterSuccessfulListReturnsBadInvalidArgument)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  const NodeId invalidType{0, static_cast<uint32_t>(ObjectTypeId::EccNistP256ApplicationCertificateType)};

  auto result =
    update_certificate_sync(mSessionA, mNullGroupId, invalidType, certDer, {}, String{}, ByteString{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mFakeStore->validateCertificateCallCount, 0u);
  EXPECT_EQ(mFakeStore->applicationCertificateCallCount, 0u);
  EXPECT_EQ(mUpdateCertificateCompletionCount.load(), 1u);
}

TEST_F(CertificatePushServiceTest, UpdateCertificate_CreatesTransaction)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  // Transaction exists - CancelChanges should succeed
  auto cancelResult = cancel_changes_sync(mSessionA);
  EXPECT_TRUE(cancelResult.is_good()) << cancelResult.status_code();
}

// ============================================================================
// Transaction
// ============================================================================

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-03-CROSS-SESSION-RESERVATION, scope=function)
TEST_F(CertificatePushServiceTest, Transaction_DifferentSession_Fails)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  // Session A creates transaction
  auto resultA = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(resultA.is_good()) << resultA.status_code();

  // Session B attempts to create transaction - should fail
  auto resultB = update_certificate_sync(
    mSessionB, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(resultB.is_bad());
  EXPECT_EQ(resultB.status_code(), StatusCode{Status::BadTransactionPending});
}

TEST_F(CertificatePushServiceTest, CancelChanges_DiscardsTransaction)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  auto cancelResult = cancel_changes_sync(mSessionA);
  ASSERT_TRUE(cancelResult.is_good()) << cancelResult.status_code();

  // No transaction - ApplyChanges should fail with BadNothingToDo
  auto applyResult = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

TEST_F(CertificatePushServiceTest, CancelChanges_NoTransaction_Fails)
{
  auto result = cancel_changes_sync(mSessionA);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
}

// ============================================================================
// ApplyChanges
// ============================================================================

TEST_F(CertificatePushServiceTest, ApplyChanges_NoTransaction_Fails)
{
  auto result = apply_changes_sync(mSessionA);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
}

TEST_F(CertificatePushServiceTest, ApplyChanges_WrongSession_Fails)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  // Session A owns the transaction
  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  // Session B tries to apply - should fail
  auto applyResult = apply_changes_sync(mSessionB);
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadUserAccessDenied});
}

TEST_F(CertificatePushServiceTest, ApplyChanges_CommitsCertificate)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  size_t appCertsBefore = mFakeStore->appCerts.size();

  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  auto applyResult = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applyResult.is_good()) << applyResult.status_code();

  // A new ApplicationCertificate should have been added to the store
  EXPECT_GT(mFakeStore->appCerts.size(), appCertsBefore);
}

TEST_F(CertificatePushServiceTest, ApplyChanges_TriggersChannelClose)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  auto applyResult = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applyResult.is_good()) << applyResult.status_code();

  // The channel close is posted to the executor - drain by posting a sentinel after it.
  std::promise<void> drain;
  boost::asio::post(mPool.get_executor(), [&drain]() { drain.set_value(); });
  drain.get_future().get();

  EXPECT_TRUE(mChannelsClosed.load());
}

// The re-evaluation hook's failure reaches the AddCertificate or RemoveCertificate caller as the hook gave it
// (same code, same ErrorDetail object). Control: ReevaluateCertificatesForwardsTheCallerAndItsCorrelation.
// @relation(AC-SVR-PULLCRT-016-B-A-REEVALUATION-FAILURE-REACHES-THE-CALLER-UNCHANGED, scope=function)
TEST_F(CertificatePushServiceTest, ReevaluateCertificatesHookFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("ReevaluationUnavailable", "the re-evaluation could not run", "TestHook")};
  const auto upstreamDetail = upstream.shared_detail();
  mReevaluationHookResult = VoidResult{upstream};

  std::promise<VoidResult> done;
  mPushService->reevaluate_certificates_async(mSessionA,
    server::MethodResponseCorrelation{3, 9},
    [&done](VoidResult r) { done.set_value(std::move(r)); });
  const auto result = done.get_future().get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
}

// AddCertificate / RemoveCertificate re-evaluation (7.8.2.3) goes through the same hook as ApplyChanges: with
// the caller's response correlation the caller is deferred to its response; without one, nobody is.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
// @relation(AC-SVR-PULLCRT-016-B-A-REEVALUATION-FAILURE-REACHES-THE-CALLER-UNCHANGED, scope=function)
TEST_F(CertificatePushServiceTest, ReevaluateCertificatesForwardsTheCallerAndItsCorrelation)
{
  std::promise<VoidResult> first;
  mPushService->reevaluate_certificates_async(mSessionA,
    server::MethodResponseCorrelation{3, 9},
    [&first](VoidResult r) { first.set_value(std::move(r)); });
  ASSERT_TRUE(first.get_future().get().is_good());
  EXPECT_EQ(mReevaluationCount, 1u);
  EXPECT_EQ(mReevaluationOriginSessionId, mSessionA);
  ASSERT_TRUE(mReevaluationCorrelation.has_value());
  EXPECT_EQ(*mReevaluationCorrelation, (server::MethodResponseCorrelation{3, 9}));

  std::promise<VoidResult> second;
  mPushService->reevaluate_certificates_async(
    mSessionA, std::nullopt, [&second](VoidResult r) { second.set_value(std::move(r)); });
  ASSERT_TRUE(second.get_future().get().is_good());
  EXPECT_EQ(mReevaluationCount, 2u);
  EXPECT_EQ(mReevaluationOriginSessionId, NodeId{}) << "no caller to defer";
}

// OPC 10000-12 7.8.2.4 / 7.8.2.5: AddCertificate and RemoveCertificate "return Bad_TransactionPending if a
// transaction is in progress" - the caller's own included, unlike CloseAndUpdate, which continues it. The
// claim they take says so; once the transaction ends they are allowed again.
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(CertificatePushServiceTest, TheImmediateClaimIsRefusedWhileTheCallersOwnTransactionIsHeld)
{
  ASSERT_TRUE(mPushService->claim_immediate_trust_list_modification(mSessionA).is_good()) << "no transaction";
  mPushService->on_trust_list_modified(
    mSessionA, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
  (void)get_rejected_list_sync();  // a barrier on the service strand

  const auto refused = mPushService->claim_immediate_trust_list_modification(mSessionA);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadTransactionPending});
  EXPECT_TRUE(mPushService->claim_trust_list_modification(mSessionA).is_good())
    << "CloseAndUpdate continues the caller's transaction";

  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good());
  EXPECT_TRUE(mPushService->claim_immediate_trust_list_modification(mSessionA).is_good());
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_UserTokenOnlyForwardsExactOriginAndRequestId)
{
  constexpr uint32_t serverRequestId = 41;
  const NodeId userTokenTrustList{
    0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);

  auto result = apply_changes_sync(mSessionA, serverRequestId);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_EQ(mReevaluationCount, 1u);
  EXPECT_EQ(mReevaluationOriginSessionId, mSessionA);
  EXPECT_EQ(mReevaluationServerRequestId, serverRequestId);
  ASSERT_TRUE(mReevaluationCorrelation.has_value());
  EXPECT_EQ(*mReevaluationCorrelation, (server::MethodResponseCorrelation{1, serverRequestId}));
  EXPECT_FALSE(mChannelsClosed.load());
  EXPECT_EQ(mFakeStore->refreshCacheCallCount, 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
// RATIFIED (owner decision 2026-10-03, BR-13 part 2): a TrustList change no longer closes every channel, so
// the close is driven by what still does - a new Server Certificate (Part 12 7.10.6).
TEST_F(CertificatePushServiceTest, ApplyChanges_CombinedEffectsShareCorrelationAndRunCloseFirst)
{
  const NodeId userTokenTrustList{
    ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList};
  auto newCert = create_valid_leaf(mLeafKeys);
  ASSERT_TRUE(update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{})
                .is_good());
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);
  const server::MethodResponseCorrelation correlation{17, 41};

  auto result = apply_changes_with_correlation_sync(mSessionA, correlation);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  EXPECT_EQ(mChannelCloseHookCount, 1u);
  EXPECT_EQ(mReevaluationHookCount, 1u);
  ASSERT_TRUE(mChannelCloseCorrelation.has_value());
  ASSERT_TRUE(mReevaluationCorrelation.has_value());
  EXPECT_EQ(*mChannelCloseCorrelation, correlation);
  EXPECT_EQ(*mReevaluationCorrelation, correlation);
  EXPECT_EQ(mEffectOrder, (std::vector<std::string>{"close", "reevaluate"}));
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
  EXPECT_TRUE(mChannelsClosed.load());
  EXPECT_EQ(mReevaluationCount, 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_RefreshFailurePreservesDetailAndSuppressesEffects)
{
  const NodeId userTokenTrustList{
    0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);
  mFakeStore->refreshCacheStatus = StatusCode{Status::BadCertificateInvalid,
    make_error_detail("CacheRefreshFailed", "Certificate cache refresh failed", "FakeCertificateStore")};

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CacheRefreshFailed");
  EXPECT_EQ(mReevaluationCount, 0u);
  EXPECT_FALSE(mChannelsClosed.load());
  EXPECT_EQ(mFakeStore->refreshCacheCallCount, 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_RefreshThrowPreservesRichDetailAndCompletesOnce)
{
  const NodeId userTokenTrustList{
    0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);
  mFakeStore->refreshCacheThrows = true;

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "StdException");
  ASSERT_EQ(result.shared_detail()->context.size(), 1u);
  EXPECT_EQ(result.shared_detail()->context.front().key, ContextKeys::errorMessage.value());
  EXPECT_EQ(result.shared_detail()->context.front().value, "injected cache refresh failure");
  EXPECT_EQ(mReevaluationHookCount, 0u);
  EXPECT_EQ(mChannelCloseHookCount, 0u);
  EXPECT_FALSE(mChannelsClosed.load());
  EXPECT_EQ(mFakeStore->refreshCacheCallCount, 1u);
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_ValidationFailureWrapsAndPreservesInjectedCause)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto updateResult = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  mFakeStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted,
    make_error_detail(
      "CertificateChainValidationFailed", "Injected certificate-chain failure", "FakeCertificateStore")};

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ApplyValidationFailed");
  EXPECT_EQ(result.shared_detail()->innerStatus, StatusCode{Status::BadCertificateUntrusted}.value());
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->code, "CertificateChainValidationFailed");
  EXPECT_FALSE(mChannelsClosed.load());
  EXPECT_EQ(mReevaluationHookCount, 0u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
// RATIFIED (owner decision 2026-10-03, BR-13 part 2): the channel close is driven by a new Server
// Certificate, the change that still closes every channel (Part 12 7.10.6).
TEST_F(CertificatePushServiceTest, ApplyChanges_ChannelCloseBadResultPreservesDetailAndCompletesOnce)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  ASSERT_TRUE(update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{})
                .is_good());
  mChannelCloseHookResult = VoidResult{Status::BadInternalError,
    make_error_detail("InjectedChannelCloseFailure", "Injected channel-close failure", "Test")};

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "InjectedChannelCloseFailure");
  EXPECT_EQ(mChannelCloseHookCount, 1u);
  EXPECT_EQ(mReevaluationHookCount, 0u);
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
// RATIFIED (owner decision 2026-10-03, BR-13 part 2): the channel close is driven by a new Server
// Certificate, the change that still closes every channel (Part 12 7.10.6).
TEST_F(CertificatePushServiceTest, ApplyChanges_ChannelCloseThrowBecomesRichFailureAndCompletesOnce)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  ASSERT_TRUE(update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{})
                .is_good());
  mChannelCloseHookThrows = true;

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ChannelCloseHookFailed");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(mChannelCloseHookCount, 1u);
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_ReevaluationBadResultPreservesDetailAndCompletesOnce)
{
  const NodeId userTokenTrustList{
    0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);
  mReevaluationHookResult = VoidResult{Status::BadInternalError,
    make_error_detail("InjectedReevaluationFailure", "Injected reevaluation failure", "Test")};

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "InjectedReevaluationFailure");
  EXPECT_EQ(mReevaluationHookCount, 1u);
  EXPECT_EQ(mChannelCloseHookCount, 0u);
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_ReevaluationThrowBecomesRichFailureAndCompletesOnce)
{
  const NodeId userTokenTrustList{
    0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};
  mPushService->on_trust_list_modified(mSessionA, userTokenTrustList);
  mReevaluationHookThrows = true;

  auto result = apply_changes_sync(mSessionA, 41);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  // RATIFIED (owner decision 2026-10-03, BR-13 part 2): the hook re-evaluates every certificate, not
  // only user identities, and its failure is coded for that.
  EXPECT_EQ(result.shared_detail()->code, "CertificateReevaluationHookFailed");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(mReevaluationHookCount, 1u);
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);
}

// Part 12 7.10.10: a reset that arrives while ApplyChanges is still in its preflight (the transaction in the
// Applying phase, not yet taken) ends the transaction too: the preflight cannot restore it, and nothing it
// held is applied in the shutdown window. Falsifiable: a reset that ended only an Open-phase transaction
// left it to be restored and applied by a second ApplyChanges.
// @verifies AC-SVR-PULLCRT-040-B-THE-RESET-ALWAYS-SHUTS-DOWN-AND-ANSWERS-WHETHER-IT-CLEARED
TEST_F(CertificatePushServiceApplyPreflightTest, AResetDuringTheApplyPreflightEndsTheTransaction)
{
  ASSERT_TRUE(
    start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding()).result.get().is_good());
  const auto certificatesBefore = mFakeStore->appCerts.size();
  auto applyPromise = std::make_shared<std::promise<VoidResult>>();
  auto applyResult = applyPromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [applyPromise](VoidResult result) { applyPromise->set_value(std::move(result)); });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_TRUE(mApplyWriteStateCallback.has_value()) << "the preflight is in flight";

  std::promise<VoidResult> reset;
  mPushService->reset_to_server_defaults_async(
    mSessionA, [&reset](VoidResult r) { reset.set_value(std::move(r)); });
  auto resetFuture = reset.get_future();
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);

  complete_apply_write_state_check(false);  // nothing open for write: the apply would go ahead
  ASSERT_EQ(applyResult.wait_for(5s), std::future_status::ready);
  const auto applied = applyResult.get();
  EXPECT_EQ(applied.status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_NE(applied.shared_detail(), nullptr);
  EXPECT_EQ(applied.shared_detail()->code, "ApplyTransactionInvalidated");
  EXPECT_EQ(apply_changes_sync(mSessionA, 2).status_code(), StatusCode{Status::BadNothingToDo})
    << "no transaction is left to apply";
  EXPECT_EQ(mFakeStore->appCerts.size(), certificatesBefore);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-05-APPLY-GENERATION-PHASE, scope=function)
TEST_F(CertificatePushServiceApplyPreflightTest,
  UpdateCertificate_WhileApplyPreflightInFlightReturnsBadInvalidStateBeforePrerequisite)
{
  ASSERT_TRUE(
    start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding()).result.get().is_good());

  auto applyPromise = std::make_shared<std::promise<VoidResult>>();
  auto applyResult = applyPromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [applyPromise](VoidResult result) { applyPromise->set_value(std::move(result)); });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mApplyWriteStateCheckCount, 1u);
  ASSERT_TRUE(mApplyWriteStateCallback.has_value());
  const auto listCallsBeforeUpdate = mFakeStore->applicationCertificateListCallCount;

  auto updateResult = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    create_valid_leaf(mLeafKeys)->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});

  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(updateResult.shared_detail(), nullptr);
  EXPECT_EQ(updateResult.shared_detail()->code, "UpdateRejectedWhileApplying");
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, listCallsBeforeUpdate);

  complete_apply_write_state_check(false);
  EXPECT_TRUE(applyResult.get().is_good());
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-05-APPLY-GENERATION-PHASE, scope=function)
TEST_F(CertificatePushServiceApplyPreflightTest,
  ApplyChanges_LatePreflightAfterCancelAndRecreateCannotConsumeNewGeneration)
{
  const auto certificate = create_valid_leaf(mLeafKeys)->der_encoding();
  ASSERT_TRUE(start_update_certificate(mSessionA, certificate).result.get().is_good());

  auto stalePromise = std::make_shared<std::promise<VoidResult>>();
  auto staleResult = stalePromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [stalePromise](VoidResult result) { stalePromise->set_value(std::move(result)); });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mApplyWriteStateCheckCount, 1u);
  ASSERT_TRUE(mApplyWriteStateCallback.has_value());

  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good());
  ASSERT_TRUE(start_update_certificate(mSessionA, certificate).result.get().is_good());

  complete_apply_write_state_check(false);
  const auto stale = staleResult.get();
  ASSERT_TRUE(stale.is_bad());
  EXPECT_EQ(stale.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(stale.shared_detail(), nullptr);
  EXPECT_EQ(stale.shared_detail()->code, "ApplyTransactionInvalidated");

  auto currentPromise = std::make_shared<std::promise<VoidResult>>();
  auto currentResult = currentPromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 2},
    [currentPromise](VoidResult result) { currentPromise->set_value(std::move(result)); });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  if (mApplyWriteStateCallback)
    complete_apply_write_state_check(false);
  EXPECT_TRUE(currentResult.get().is_good());
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-05-APPLY-GENERATION-PHASE, scope=function)
TEST_F(CertificatePushServiceApplyPreflightTest,
  ApplyChanges_LatePreflightAfterSessionCloseAndRecreateCannotConsumeNewGeneration)
{
  const auto certificate = create_valid_leaf(mLeafKeys)->der_encoding();
  ASSERT_TRUE(start_update_certificate(mSessionA, certificate).result.get().is_good());

  auto staleCompletionCount = std::make_shared<std::atomic_size_t>(0);
  auto stalePromise = std::make_shared<std::promise<VoidResult>>();
  auto staleResult = stalePromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [staleCompletionCount, stalePromise](VoidResult result)
    {
      if (staleCompletionCount->fetch_add(1) == 0)
        stalePromise->set_value(std::move(result));
    });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mApplyWriteStateCheckCount, 1u);
  ASSERT_TRUE(mApplyWriteStateCallback.has_value());

  mPushService->on_session_closed_async(mSessionA);
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_TRUE(mTransactionDiagnostics.empty());
  ASSERT_TRUE(start_update_certificate(mSessionA, certificate).result.get().is_good());

  complete_apply_write_state_check(false);
  const auto stale = staleResult.get();
  ASSERT_TRUE(stale.is_bad());
  EXPECT_EQ(stale.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(stale.shared_detail(), nullptr);
  EXPECT_EQ(stale.shared_detail()->code, "ApplyTransactionInvalidated");
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(staleCompletionCount->load(), 1u);
  EXPECT_TRUE(mTransactionDiagnostics.empty());

  auto currentPromise = std::make_shared<std::promise<VoidResult>>();
  auto currentResult = currentPromise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 2},
    [currentPromise](VoidResult result) { currentPromise->set_value(std::move(result)); });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  if (mApplyWriteStateCallback)
    complete_apply_write_state_check(false);
  EXPECT_TRUE(currentResult.get().is_good());
  ASSERT_EQ(mTransactionDiagnostics.size(), 1u);
  EXPECT_TRUE(mTransactionDiagnostics.front().result.is_good());
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-05-APPLY-GENERATION-PHASE, scope=function)
TEST_F(
  CertificatePushServiceTest, ApplyChanges_InFlightUpdateReservationReturnsBadInvalidStateWithoutPreflight)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  auto pending = start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_EQ(mFakeStore->deferred_application_certificate_list_count(), 1u);

  auto result = apply_changes_sync(mSessionA);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadInvalidState}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ApplyUpdatePrerequisitePending");
  EXPECT_EQ(mApplyCompletionCount.load(), 1u);

  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());
  EXPECT_TRUE(pending.result.get().is_good());
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_InlineFailureThrowingCompletionInvokedOnce)
{
  auto count = std::make_shared<std::atomic_size_t>(0);
  mPushService->create_signing_request_async(mSessionA,
    NodeId{1, 999u},
    mRsaSha256TypeId,
    String{},
    false,
    ByteString{},
    [count](Result<ByteString>)
    {
      ++*count;
      throw std::runtime_error{"injected completion failure"};
    });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_AsyncCompletionThrowingCompletionInvokedOnce)
{
  auto count = std::make_shared<std::atomic_size_t>(0);
  auto promise = std::make_shared<std::promise<void>>();
  auto completed = promise->get_future();
  mPushService->create_signing_request_async(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    String{"Test"},
    false,
    ByteString{},
    [count, promise](Result<ByteString>)
    {
      if (count->fetch_add(1) == 0)
        promise->set_value();
      throw std::runtime_error{"injected completion failure"};
    });
  completed.get();
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_InlineFailureThrowingCompletionInvokedOnce)
{
  auto count = std::make_shared<std::atomic_size_t>(0);
  mPushService->update_certificate_async(mSessionA,
    NodeId{1, 999u},
    mRsaSha256TypeId,
    ByteString{},
    {},
    String{},
    ByteString{},
    [count](Result<bool>)
    {
      ++*count;
      throw std::runtime_error{"injected completion failure"};
    });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_AsyncCompletionThrowingCompletionInvokedOnce)
{
  auto count = std::make_shared<std::atomic_size_t>(0);
  auto promise = std::make_shared<std::promise<void>>();
  auto completed = promise->get_future();
  mPushService->update_certificate_async(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    create_valid_leaf(mLeafKeys)->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{},
    [count, promise](Result<bool>)
    {
      if (count->fetch_add(1) == 0)
        promise->set_value();
      throw std::runtime_error{"injected completion failure"};
    });
  completed.get();
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_InlineFailureThrowingCompletionInvokedOnce)
{
  auto count = std::make_shared<std::atomic_size_t>(0);
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [count](VoidResult)
    {
      ++*count;
      throw std::runtime_error{"injected completion failure"};
    });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-07-THROWING-PUBLIC-COMPLETION, scope=function)
TEST_F(CertificatePushServiceTest, ApplyChanges_AsyncCompletionThrowingCompletionInvokedOnce)
{
  ASSERT_TRUE(
    start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding()).result.get().is_good());
  auto count = std::make_shared<std::atomic_size_t>(0);
  auto promise = std::make_shared<std::promise<void>>();
  auto completed = promise->get_future();
  mPushService->apply_changes_async(mSessionA,
    server::MethodResponseCorrelation{1, 1},
    [count, promise](VoidResult)
    {
      if (count->fetch_add(1) == 0)
        promise->set_value();
      throw std::runtime_error{"injected completion failure"};
    });
  completed.get();
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(count->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-06-DUPLICATE-COLLABORATORS, scope=function)
TEST_F(CertificatePushServiceTest, CreateSigningRequest_DuplicateTypeListAfterSuccessIsIgnored)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  auto completionCount = std::make_shared<std::atomic_size_t>(0);
  auto promise = std::make_shared<std::promise<Result<ByteString>>>();
  auto result = promise->get_future();
  mPushService->create_signing_request_async(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    String{"Test"},
    false,
    ByteString{},
    [completionCount, promise](Result<ByteString> completionResult)
    {
      if (completionCount->fetch_add(1) == 0)
        promise->set_value(std::move(completionResult));
    });
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());
  ASSERT_TRUE(result.get().is_good());

  ASSERT_TRUE(mFakeStore->repeat_last_application_certificate_list());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(completionCount->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-06-DUPLICATE-COLLABORATORS, scope=function)
TEST_F(CertificatePushServiceTest, UpdateCertificate_DuplicateTypeListAfterCancelIsIgnored)
{
  mFakeStore->deferApplicationCertificateListResults = true;
  auto pending = start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good());
  ASSERT_TRUE(mFakeStore->complete_next_application_certificate_list());
  EXPECT_TRUE(pending.result.get().is_bad());

  ASSERT_TRUE(mFakeStore->repeat_last_application_certificate_list());
  ASSERT_TRUE(get_rejected_list_sync().is_good());
  EXPECT_EQ(pending.completionCount->load(), 1u);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-08-GETTER-MATERIALIZATION, scope=function)
TEST_F(CertificatePushServiceMaterializationThrowTest,
  GetRejectedList_EncodingThrowCompletesOnceWithExactRichResult)
{
  mFakeStore->rejectedCerts.push_back(mLeafCert);
  auto completionCount = std::make_shared<std::atomic_size_t>(0);
  auto promise = std::make_shared<std::promise<Result<std::vector<ByteString>>>>();
  auto result = promise->get_future();
  const auto expectedDetail = mMaterializationFailure.shared_detail();
  mPushService->get_rejected_list_async(
    [completionCount, promise](Result<std::vector<ByteString>> completionResult)
    {
      if (completionCount->fetch_add(1) == 0)
        promise->set_value(std::move(completionResult));
    });

  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
  ASSERT_EQ(result.wait_for(std::chrono::milliseconds{0}), std::future_status::ready);
  const auto completionResult = result.get();
  ASSERT_TRUE(completionResult.is_bad());
  EXPECT_EQ(completionResult.status_code().value(), mMaterializationFailure.value());
  EXPECT_EQ(completionResult.shared_detail().get(), expectedDetail.get());
  EXPECT_EQ(completionCount->load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-PREREQUISITES-08-GETTER-MATERIALIZATION, scope=function)
TEST_F(CertificatePushServiceMaterializationThrowTest,
  GetCertificates_EncodingThrowCompletesOnceWithExactRichResult)
{
  auto completionCount = std::make_shared<std::atomic_size_t>(0);
  using CertificatesResult = Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>;
  auto promise = std::make_shared<std::promise<CertificatesResult>>();
  auto result = promise->get_future();
  const auto expectedDetail = mMaterializationFailure.shared_detail();
  mPushService->get_certificates_async(mNullGroupId,
    [completionCount, promise](CertificatesResult completionResult)
    {
      if (completionCount->fetch_add(1) == 0)
        promise->set_value(std::move(completionResult));
    });

  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
  ASSERT_EQ(result.wait_for(std::chrono::milliseconds{0}), std::future_status::ready);
  const auto completionResult = result.get();
  ASSERT_TRUE(completionResult.is_bad());
  EXPECT_EQ(completionResult.status_code().value(), mMaterializationFailure.value());
  EXPECT_EQ(completionResult.shared_detail().get(), expectedDetail.get());
  EXPECT_EQ(completionCount->load(), 1u);
}

// ============================================================================
// GetRejectedList
// ============================================================================

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-GETTERS-02-REJECTED-LIST-FAILURE, scope=function)
TEST_F(CertificatePushServiceTest, GetRejectedList_ReturnsRejectedCerts)
{
  // Pre-populate store with a rejected cert
  mFakeStore->rejectedCerts.push_back(mLeafCert);

  auto result = get_rejected_list_sync();

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(result.value()[0], mLeafCert->der_encoding());
  EXPECT_EQ(mFakeStore->rejectedCertificateCallCount, 1u);
  EXPECT_EQ(mGetRejectedListCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-GETTERS-02-REJECTED-LIST-FAILURE, scope=function)
TEST_F(CertificatePushServiceTest, GetRejectedList_StoreFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadCommunicationError,
    make_error_detail("RejectedCertificateListUnavailable",
      "Rejected certificate list is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->rejectedCertificateResults.emplace_back(upstream);

  auto result = get_rejected_list_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->rejectedCertificateCallCount, 1u);
  EXPECT_EQ(mGetRejectedListCompletionCount.load(), 1u);
}

// ============================================================================
// GetCertificates
// ============================================================================

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-GETTERS-01-APPLICATION-LIST-FAILURE, scope=function)
TEST_F(CertificatePushServiceTest, GetCertificates_ReturnsAppCerts)
{
  auto result = get_certificates_sync(mNullGroupId);

  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  auto& [typeIds, certs] = result.value();
  ASSERT_EQ(typeIds.size(), 1u);
  ASSERT_EQ(certs.size(), 1u);
  EXPECT_EQ(typeIds[0], mRsaSha256TypeId);
  EXPECT_EQ(certs[0], mLeafCert->der_encoding());
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mGetCertificatesCompletionCount.load(), 1u);
}

// @relation(AC-COMP-SVR-CERTIFICATE-PUSH-GETTERS-01-APPLICATION-LIST-FAILURE, scope=function)
TEST_F(CertificatePushServiceTest, GetCertificates_ApplicationListFailurePreservesExactRichResult)
{
  const StatusCode upstream{Status::BadResourceUnavailable,
    make_error_detail("ApplicationCertificateListUnavailable",
      "Application certificate list is unavailable",
      "FakeCertificateStore")};
  const auto upstreamDetail = upstream.shared_detail();
  mFakeStore->applicationCertificateListResults.emplace_back(upstream);

  auto result = get_certificates_sync(mNullGroupId);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), upstream.value());
  EXPECT_EQ(result.shared_detail().get(), upstreamDetail.get());
  EXPECT_EQ(mFakeStore->applicationCertificateListCallCount, 1u);
  EXPECT_EQ(mGetCertificatesCompletionCount.load(), 1u);
}

// Part 12 7.10: DefaultApplicationGroup (i=14156) is mandatory; DefaultHttpsGroup and
// DefaultUserTokenGroup are optional and must be absent - not present-but-empty - where the
// deployment does not implement them, because a client browses the group set to learn what it may
// push. A plausible implementation answers for every group NodeId the standard NodeSet defines,
// which advertises the HTTPS group the SDK does not ship and a user-token group with no store
// behind it. GetCertificates (7.10.5) is where the service states its own group set: it reserves
// Bad_InvalidArgument for "a NodeId that is not a CertificateGroup of this Server", and returns
// Good with an empty certificateTypeIds for a group that exists but carries no CertificateTypes -
// so Good-versus-Bad here is exactly the present-versus-absent distinction the obligation makes.
// @verifies AC-SVR-PULLCRT-003-CERTIFICATE-GROUPS
TEST_F(CertificatePushServiceTest, CertificateGroupsAreOnlyThoseTheDeploymentImplements)
{
  auto getCertificatesFrom = [](const std::shared_ptr<CertificatePushService>& service, const NodeId& groupId)
  {
    std::promise<Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>> p;
    service->get_certificates_async(groupId,
      [&p](Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  };

  const NodeId applicationGroupId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup};
  const NodeId httpsGroupId{ObjectId::ServerConfiguration_CertificateGroups_DefaultHttpsGroup};
  const NodeId userTokenGroupId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup};

  // Conjunct 1: DefaultApplicationGroup is present, and backed by the application certificate.
  auto applicationGroup = getCertificatesFrom(mPushService, applicationGroupId);
  ASSERT_TRUE(applicationGroup.is_good()) << applicationGroup.status_code();
  auto& [applicationTypeIds, applicationCerts] = applicationGroup.value();
  ASSERT_FALSE(applicationCerts.empty());
  ASSERT_EQ(applicationTypeIds.size(), applicationCerts.size());
  EXPECT_EQ(applicationTypeIds[0], mRsaSha256TypeId);
  EXPECT_EQ(applicationCerts[0], mLeafCert->der_encoding());

  // Conjunct 2: the HTTPS group is a planned extension, so it is not a group of this server.
  auto httpsGroup = getCertificatesFrom(mPushService, httpsGroupId);
  ASSERT_TRUE(httpsGroup.is_bad());
  EXPECT_EQ(httpsGroup.status_code(), StatusCode{Status::BadInvalidArgument});

  // Conjunct 3: this fixture configures no user-token trust list, so that group is absent too -
  // it must not be answered as a valid group that merely has nothing in it.
  auto userTokenGroup = getCertificatesFrom(mPushService, userTokenGroupId);
  ASSERT_TRUE(userTokenGroup.is_bad());
  EXPECT_EQ(userTokenGroup.status_code(), StatusCode{Status::BadInvalidArgument});

  // Conjunct 4: "only where the server implements them" cuts both ways - a deployment that does
  // configure a user-token trust list publishes that group, and the same call is then accepted.
  TrustListManager::Dependencies userTokenTlmDeps{
    .strand = boost::asio::make_strand(mPool.get_executor()),
    .certificateStore = mFakeStore,
    .crypto = mCrypto,
    .executor = mPool.get_executor(),
    .maxTrustListSize = 65535,
    .activityTimeout = 60000ms,
    .logger = Logger{},
  };
  auto userTokenTrustList = TrustListManager::create(std::move(userTokenTlmDeps), mTrustListModifiedCallback);

  CertificatePushService::Dependencies configuredDeps{
    .strand = boost::asio::make_strand(mPool.get_executor()),
    .crypto = mCrypto,
    .certificateStore = mFakeStore,
    .trustList = mTrustList,
    .userTokenTrustList = userTokenTrustList,
    .executor = mPool.get_executor(),
    .logger = Logger{},
    .applicationUri = "urn:test:server",
    .hostnames = {"localhost"},
    .closeAllChannels =
      [](const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)> callback)
    { callback(VoidResult{}); },
    .dependencyFailureDetailBuilder = {},
    .applyWriteStateCheck = {},
    .certificateDerEncoder = {},
  };
  auto configuredService = CertificatePushService::create(std::move(configuredDeps));

  auto configuredUserTokenGroup = getCertificatesFrom(configuredService, userTokenGroupId);
  EXPECT_TRUE(configuredUserTokenGroup.is_good()) << configuredUserTokenGroup.status_code();

  // ...and the HTTPS group stays absent even on that deployment.
  auto configuredHttpsGroup = getCertificatesFrom(configuredService, httpsGroupId);
  ASSERT_TRUE(configuredHttpsGroup.is_bad());
  EXPECT_EQ(configuredHttpsGroup.status_code(), StatusCode{Status::BadInvalidArgument});

  configuredService->shutdown();
  userTokenTrustList->shutdown();
}

// ============================================================================
// Session Close
// ============================================================================

TEST_F(CertificatePushServiceTest, OnSessionClosed_CancelsTransaction)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  // Create a transaction for session A
  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  // Fire session closed notification - posts to strand, drained by the next sync call (FIFO).
  mPushService->on_session_closed_async(mSessionA);

  // Transaction should be cancelled - ApplyChanges fails
  auto applyResult = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

// ============================================================================
// TrustListModified
// ============================================================================

TEST_F(CertificatePushServiceTest, OnTrustListModified_CreatesTransaction)
{
  // Fire trust list modified - posts to strand, drained by the next sync call (FIFO).
  mPushService->on_trust_list_modified(
    mSessionA, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});

  // ApplyChanges should succeed (trust list modified flag set)
  auto applyResult = apply_changes_sync(mSessionA);
  EXPECT_TRUE(applyResult.is_good()) << applyResult.status_code();
}

// ============================================================================
// Observer
// ============================================================================

TEST_F(CertificatePushServiceTest, Observer_ForwardsSessionClose)
{
  auto newCert = create_valid_leaf(mLeafKeys);
  auto certDer = newCert->der_encoding();
  auto caDer = mCaCert->der_encoding();

  // Create a transaction for session A
  auto updateResult = update_certificate_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, certDer, {caDer}, String{}, ByteString{});
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  // Create observer and fire session close through it
  auto observer = make_push_certificate_observer(mPushService, mTrustList);

  server::SessionEventInfo info;
  info.sessionId = mSessionA;
  observer->on_session_closed(info, StatusCode{Status::Good});

  // Transaction should be cancelled - the observer posts to strand, drained by sync call (FIFO).
  auto applyResult = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

}  // namespace

// The arm reads VmHWM from /proc/self/status, so it exists on Linux only.
#if defined(__linux__)
namespace
{
/// Peak resident set size of this process in bytes (VmHWM from /proc/self/status), or 0 when it
/// cannot be read. A high-water mark: a 2 GiB buffer that came and went still shows.
size_t peak_resident_bytes()
{
  std::ifstream status{"/proc/self/status"};
  std::string line;
  while (std::getline(status, line))
  {
    if (line.rfind("VmHWM:", 0) == 0)
    {
      size_t kib = 0;
      std::istringstream fields{line.substr(6)};
      fields >> kib;
      return kib * 1024;
    }
  }
  return 0;
}
}  // namespace

// TrustList Read allocates min(length, remaining), not the caller's length: a Read asking for
// INT32_MAX returns the encoded trust list (a few KiB) without a 2 GiB zero-filled buffer coming into
// being, which the process's resident size would show.
// @verifies AC-SVR-SECADMIN-009-TRUSTLIST-READ-ALLOCATES-THE-REMAINDER-NOT-THE-REQUEST
TEST_F(TrustListTest, ReadOfTheMaximumLengthCostsTheRemainderNotTwoGigabytes)
{
  create_manager();
  auto openResult = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();

  {
    // Reset the high-water mark, so an earlier test's peak cannot hide this read's.
    std::ofstream clearRefs{"/proc/self/clear_refs"};
    clearRefs << "5";
  }
  const auto before = peak_resident_bytes();
  ASSERT_NE(before, 0u) << "VmHWM is read from /proc/self/status";
  auto readResult = read_sync(mSessionA, handle, std::numeric_limits<int32_t>::max());
  ASSERT_TRUE(readResult.is_good());
  const auto after = peak_resident_bytes();
  EXPECT_LT(after, before + (64u << 20))
    << "the read must not have touched a caller-sized buffer (the peak resident size grew by "
    << (after - before) << " bytes)";

  // The data is the whole trust list, byte for byte what a bounded read from the start returns.
  ASSERT_TRUE(close_sync(mSessionA, handle).is_good());
  auto reopen = open_sync(mSessionA, 0x01);
  ASSERT_TRUE(reopen.is_good());
  auto bounded = read_sync(mSessionA, reopen.value(), 65535);
  ASSERT_TRUE(bounded.is_good());
  EXPECT_EQ(readResult.value(), bounded.value());
}
#endif

// The CSR subject is built from the current certificate's name components. subject() is the raw DER
// of the whole Name; handed over as a distinguished-name string it became one dnQualifier holding DER
// bytes, so a CA signing the request issued a certificate with no CommonName. Observed through the
// issued certificate: the CA signs the CSR and the leaf's CommonName is the current certificate's.
// @verifies AC-SVR-PULLCRT-035-CREATESIGNINGREQUEST-SUBJECT-IS-THE-CURRENT-NAME
TEST_F(CertificatePushServiceTest, CreateSigningRequestCarriesTheCurrentCertificatesNameComponents)
{
  auto result = create_signing_request_sync(
    mSessionA, mNullGroupId, mRsaSha256TypeId, String{}, /*regeneratePrivateKey*/ false, ByteString{});
  ASSERT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
  ASSERT_FALSE(result.value().empty());

  auto issued = mPki->sign_csr(result.value(), mCaKeys, mCaCert);
  ASSERT_NE(issued, nullptr);
  EXPECT_EQ(issued->subject_common_name(), mLeafCert->subject_common_name())
    << "the CSR names the current certificate's CommonName as a CommonName";
  EXPECT_FALSE(issued->subject_common_name().empty());
}

// ============================================================================
// Group J (security review B3-3/B3-4): CloseAndUpdate masks, validation, the transaction gate,
// AddCertificate / RemoveCertificate gates
// ============================================================================

// Part 12 7.8.2.3: "If a bit is not set then the associated field is not changed". A CRL-only
// upload replaces the trusted CRLs and leaves the trusted certificates as they are; before, it
// wiped every trusted certificate and locked every client out.
// @verifies AC-SVR-SECADMIN-009-CLOSEANDUPDATE-LEAVES-UNMASKED-LISTS-UNCHANGED
TEST_F(TrustListTest, CloseAndUpdateWithOnlyTheCrlMaskKeepsTheTrustedCertificates)
{
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();

  // A CRL that differs from the one the store holds (it revokes a serial), so "replaced" and "kept"
  // are distinguishable.
  auto replacementCrl = mPki->create_crl(mCaCert, mCaKeys, {"1234"});
  ASSERT_NE(replacementCrl->der_encoding(), mCrl->der_encoding());
  const auto issuerCrlsBefore = mFakeStore->issuerCrls.size();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x02;  // TrustedCrls only
  trustList.trusted_crls().push_back(replacementCrl->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, handle, encode_trust_list(trustList)).is_good());

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();

  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "the unmasked trusted certificates are kept";
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding());
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), replacementCrl->der_encoding()) << "replaced";
  ASSERT_EQ(mFakeStore->issuerCerts.size(), 1u) << "the issuer lists were not touched";
  EXPECT_EQ(mFakeStore->issuerCrls.size(), issuerCrlsBefore);
}

// Part 12 7.8.2.3: every uploaded certificate is verified before anything is replaced; an expired
// one refuses the whole update with Bad_CertificateInvalid and the store is untouched.
// @verifies AC-SVR-SECADMIN-009-CLOSEANDUPDATE-VALIDATES-EVERY-UPLOADED-CERTIFICATE
TEST_F(TrustListTest, CloseAndUpdateRefusesAnExpiredCertificateAndReplacesNothing)
{
  create_manager();
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "Expired");

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  trustList.trusted_certificates().push_back(expired->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, handle, encode_trust_list(trustList)).is_good());

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_FALSE(updateResult.is_good());
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "nothing was replaced";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding());
}

// A CA-issued certificate whose issuer is in neither the uploaded nor the kept lists cannot be
// verified and refuses the update the same way.
// @verifies AC-SVR-SECADMIN-009-CLOSEANDUPDATE-VALIDATES-EVERY-UPLOADED-CERTIFICATE
TEST_F(TrustListTest, CloseAndUpdateRefusesACertificateWhoseIssuerIsInNeitherList)
{
  create_manager();
  auto otherCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherCaKeys);
  auto strangerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto now = DateTime::now();
  auto stranger = mPki->create_leaf_cert(strangerKeys,
    otherCaKeys,
    otherCa,
    now,
    DateTime{now.value() + std::chrono::days{30}},
    {},
    {},
    "Stranger");

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(stranger->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, handle, encode_trust_list(trustList)).is_good());

  auto updateResult = close_and_update_sync(mSessionA, handle);
  ASSERT_FALSE(updateResult.is_good());
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
}

// Part 12 7.8.2.3: while another session owns the push transaction, a modification is refused
// BEFORE it is applied (Bad_TransactionPending), instead of applied and left out of the
// re-evaluation. The gate is what the push service answers; here it is a stand-in that names the
// owner. RATIFIED (owner decision Q1, 2026-10-04, Part 12 Figure 22): the other session's Open for write is
// itself refused with Bad_TransactionPending; its CloseAndUpdate is refused when the transaction started
// after it opened (the gate names the owner only from then on).
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(TrustListTest, ModificationsAreRefusedWhileAnotherSessionOwnsTheTransaction)
{
  std::atomic<bool> ownedByA{false};
  mModificationGate = [this, &ownedByA](const NodeId& session)
  {
    return !ownedByA.load() || session == mSessionA ? StatusCode{Status::Good}
                                                    : StatusCode{Status::BadTransactionPending};
  };
  create_manager();

  // CloseAndUpdate by the other session, opened before A's transaction started.
  auto openResult = open_sync(mSessionB, 0x06);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();
  ownedByA = true;
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(write_sync(mSessionB, handle, encode_trust_list(trustList)).is_good());
  auto updateResult = close_and_update_sync(mSessionB, handle);
  ASSERT_FALSE(updateResult.is_good());
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadTransactionPending);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "refused before it was applied";
  EXPECT_EQ(open_sync(mSessionB, 0x06).status_code(), StatusCode{Status::BadTransactionPending})
    << "and a new Open for write is refused";

  // AddCertificate and RemoveCertificate by the other session.
  auto addResult = add_certificate_sync(mSessionB, mLeaf2Cert->der_encoding(), true);
  EXPECT_EQ(addResult.status_code().as_status(), Status::BadTransactionPending);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
  auto removeResult =
    remove_certificate_sync(mSessionB, fmt::format("{:02X}", fmt::join(mLeafCert->thumbprint(), "")), true);
  EXPECT_EQ(removeResult.status_code().as_status(), Status::BadTransactionPending);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);

  // Control: the owner's modification goes through.
  auto ownerAdd = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_TRUE(ownerAdd.is_good()) << ownerAdd.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 2u);
}

// Part 12 7.8.2.4: AddCertificate with isTrustedCertificate FALSE returns Bad_CertificateInvalid;
// before, the certificate was added to the issuer list instead.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-VALIDATES-AND-REFUSES-WHAT-THE-SPEC-REFUSES
TEST_F(TrustListTest, AddCertificateWithIsTrustedFalseIsRefusedAndAddsNothing)
{
  create_manager();
  const auto issuersBefore = mFakeStore->issuerCerts.size();
  auto result = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), false);
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid);
  EXPECT_EQ(mFakeStore->issuerCerts.size(), issuersBefore) << "nothing was added as an issuer";
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// Part 12 7.8.2.4: AddCertificate cannot be called while the TrustList is open for write.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-VALIDATES-AND-REFUSES-WHAT-THE-SPEC-REFUSES
TEST_F(TrustListTest, AddAndRemoveCertificateAreRefusedWhileTheTrustListIsOpenForWrite)
{
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  auto addResult = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_EQ(addResult.status_code().as_status(), Status::BadInvalidState);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
  auto removeResult =
    remove_certificate_sync(mSessionA, fmt::format("{:02X}", fmt::join(mLeafCert->thumbprint(), "")), true);
  EXPECT_EQ(removeResult.status_code().as_status(), Status::BadInvalidState);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);

  ASSERT_TRUE(close_sync(mSessionA, openResult.value()).is_good());
  auto afterClose = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_TRUE(afterClose.is_good()) << "control: allowed once the handle is closed";
}

// Part 12 7.8.2.4: the certificate is verified before it is stored; an expired one is refused.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-VALIDATES-AND-REFUSES-WHAT-THE-SPEC-REFUSES
TEST_F(TrustListTest, AddCertificateRefusesAnExpiredCertificate)
{
  create_manager();
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "Expired");
  auto result = add_certificate_sync(mSessionA, expired->der_encoding(), true);
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid);
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// ============================================================================
// Part 12 7.8.2.3 / 7.8.2.4 with Part 4 6.1.3: every certificate of the resulting trust list passes the
// Part 4 validation, with that list as its anchors and its CRLs, under the group's validation options
// ============================================================================

namespace
{
// An ApplicationInstance-shaped certificate with an explicit issuer, serial and validity, for the arms
// that need a self-signed certificate, a known serial (to revoke) or an intermediate CA.
std::shared_ptr<const X509Certificate> make_trust_list_cert(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& subjectKeys,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
  const std::shared_ptr<const X509Certificate>& issuerCert, const std::string& name,
  const std::string& serial, bool isCa, DateTime from, DateTime to)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = subjectKeys;
  p.issuerKeys = issuerKeys;
  p.issuer = issuerCert;
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = isCa;
  if (isCa)
  {
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
  }
  else
  {
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
  }
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = from;
  p.to = to;
  return pki.create_cert(p);
}

}  // namespace

// Controls: a trusted self-signed certificate is its own root, so it is valid with no issuer (Part 4
// 6.1.3 Build Certificate Chain); nothing about the upload has to be trusted by the list it replaces.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateAcceptsASelfSignedTrustedCertificate)
{
  create_manager();
  const auto now = DateTime::now();
  auto selfKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto selfSigned = make_trust_list_cert(*mPki,
    selfKeys,
    selfKeys,
    nullptr,
    "SelfSigned",
    "7001",
    false,
    now,
    DateTime{now.value() + std::chrono::days{30}});

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(selfSigned->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());

  auto updateResult = close_and_update_sync(mSessionA, openResult.value());
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), selfSigned->der_encoding());
}

// Control: a CA-issued leaf whose chain - an intermediate CA and its self-signed root - arrives in the
// new issuer list is valid against the new list, although the store held none of them.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateAcceptsALeafWhoseCaChainIsInTheNewIssuerList)
{
  // The fixture's trusted CRL is issued by the fixture CA, which this update drops from the issuer
  // list; every CRL of the new list is validated too (Part 12 7.8.2.1), so it would refuse the update
  // for a reason this test is not about.
  mFakeStore->trustedCrls.clear();
  create_manager();
  const auto now = DateTime::now();
  const DateTime until{now.value() + std::chrono::days{30}};
  auto rootKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto root = make_trust_list_cert(*mPki, rootKeys, rootKeys, nullptr, "NewRoot", "7101", true, now, until);
  auto intermediateKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto intermediate = make_trust_list_cert(
    *mPki, intermediateKeys, rootKeys, root, "NewIntermediate", "7102", true, now, until);
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = make_trust_list_cert(
    *mPki, leafKeys, intermediateKeys, intermediate, "NewLeaf", "7103", false, now, until);

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x05;  // TrustedCertificates | IssuerCertificates
  trustList.trusted_certificates().push_back(leaf->der_encoding());
  trustList.issuer_certificates().push_back(root->der_encoding());
  trustList.issuer_certificates().push_back(intermediate->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());

  auto updateResult = close_and_update_sync(mSessionA, openResult.value());
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), leaf->der_encoding());
  EXPECT_EQ(mFakeStore->issuerCerts.size(), 2u);
}

// The suppression the group is configured with applies to an upload as to a peer certificate: with
// SuppressCertificateExpired the expired certificate is accepted (control), without it the update is
// refused with Bad_CertificateInvalid carrying Bad_CertificateTimeInvalid and naming the certificate,
// and the list is left as it was.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateHonoursTheConfiguredExpirySuppressionAndNamesTheCause)
{
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "Expired");
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(expired->der_encoding());
  const auto upload = encode_trust_list(trustList);

  // refused: no suppression configured.
  create_manager();
  {
    auto openResult = open_sync(mSessionA, 0x06);
    ASSERT_TRUE(openResult.is_good());
    ASSERT_TRUE(write_sync(mSessionA, openResult.value(), upload).is_good());
    auto updateResult = close_and_update_sync(mSessionA, openResult.value());
    ASSERT_TRUE(updateResult.is_bad());
    EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid);
    const auto detail = updateResult.shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "TrustListCertificateInvalid");
    EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadCertificateTimeInvalid}.value())
      << "the Part 4 error is the cause";
    EXPECT_EQ(context_value(*detail, ua::ContextKeys::certificateThumbprint.value()),
      utils::bytes_to_hex_string(span<const byte>{expired->thumbprint()}))
      << "the refusal names the certificate";
    // Owner decision D-b: a Summary-level DiagnosticInfo carries the summary but not the context, so the
    // summary names the certificate too (OPC 10000-12 7.8.2.3).
    EXPECT_NE(detail->summary.find("'Expired'"), std::string::npos) << detail->summary;
    EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
    ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
    EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding());
  }
  mManager->shutdown();

  // control: the same upload under SuppressCertificateExpired.
  mValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressCertificateExpired};
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), upload).is_good());
  auto updateResult = close_and_update_sync(mSessionA, openResult.value());
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), expired->der_encoding());
}

// The anchors are the NEW list, not the store's: a leaf whose CA the store holds is refused when the
// same update empties the issuer list, and nothing is replaced. The control keeps the issuer list.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesALeafWhoseCaIsAbsentFromTheNewList)
{
  create_manager();
  {
    auto openResult = open_sync(mSessionA, 0x06);
    ASSERT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x05;  // TrustedCertificates | IssuerCertificates (now empty)
    trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
    ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    auto updateResult = close_and_update_sync(mSessionA, openResult.value());
    ASSERT_TRUE(updateResult.is_bad());
    EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid);
    const auto detail = updateResult.shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "TrustListCertificateInvalid");
    EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadCertificateChainIncomplete}.value())
      << "Part 4 Table 106: an issuer in neither list leaves the chain incomplete";
    EXPECT_EQ(context_value(*detail, ua::ContextKeys::certificateThumbprint.value()),
      utils::bytes_to_hex_string(span<const byte>{mLeaf2Cert->thumbprint()}))
      << "the refusal names the certificate";
    EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
    ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
    EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding());
    EXPECT_EQ(mFakeStore->issuerCerts.size(), 1u) << "the issuer list is not emptied either";
  }

  // control: the same leaf with the issuer list left as it is.
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
  auto updateResult = close_and_update_sync(mSessionA, openResult.value());
  ASSERT_TRUE(updateResult.is_good()) << updateResult.status_code();
}

// With offline revocation checking configured, a certificate revoked by a CRL that arrives in the same
// update is refused with Bad_CertificateInvalid carrying Bad_CertificateRevoked and the list is kept;
// the control's CRL revokes another serial and the update goes through.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesACertificateRevokedByACrlInTheNewList)
{
  mValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline,
      TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown,
      TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown};
  create_manager();
  const auto now = DateTime::now();
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = make_trust_list_cert(*mPki,
    leafKeys,
    mCaKeys,
    mCaCert,
    "RevocableLeaf",
    "4242",
    false,
    now,
    DateTime{now.value() + std::chrono::days{30}});
  auto unrelatedCrl = mPki->create_crl(mCaCert, mCaKeys, {"1"});
  auto revokingCrl = mPki->create_crl(mCaCert, mCaKeys, {"4242"});

  const auto update = [&](const shared_ptr<const X509Crl>& crl)
  {
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x03;  // TrustedCertificates | TrustedCrls
    trustList.trusted_certificates().push_back(leaf->der_encoding());
    trustList.trusted_crls().push_back(crl->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  // control: the CRL revokes another serial.
  auto accepted = update(unrelatedCrl);
  ASSERT_TRUE(accepted.is_good()) << accepted.status_code();
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), unrelatedCrl->der_encoding());

  auto refused = update(revokingCrl);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateRevoked}.value());
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{leaf->thumbprint()}))
    << "the refusal names the revoked certificate";
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), unrelatedCrl->der_encoding()) << "the list is kept";
}

// Part 12 7.8.2.4: AddCertificate "will return a validation error if the Certificate is issued by a CA
// and the Certificate for the issuer is not in the Trust List"; a self-signed certificate needs none,
// and a leaf whose CA the list holds is added (controls). Each refusal leaves the list unchanged.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, AddCertificateRefusesALeafWhoseCaIsNotInTheTrustList)
{
  create_manager();
  const auto now = DateTime::now();
  const DateTime until{now.value() + std::chrono::days{30}};
  auto otherCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherCaKeys, "Other CA", "7201");
  auto strangerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto stranger = mPki->create_leaf_cert(strangerKeys, otherCaKeys, otherCa, now, until, {}, {}, "Stranger");

  auto refused = add_certificate_sync(mSessionA, stranger->der_encoding(), true);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "TrustListCertificateInvalid");
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateChainIncomplete}.value())
    << "Part 4 Table 106: an issuer that is not in the Trust List leaves the chain incomplete";
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{stranger->thumbprint()}))
    << "the refusal names the certificate";
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u) << "nothing was added";

  auto selfKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto selfSigned =
    make_trust_list_cert(*mPki, selfKeys, selfKeys, nullptr, "SelfSigned", "7202", false, now, until);
  auto selfResult = add_certificate_sync(mSessionA, selfSigned->der_encoding(), true);
  EXPECT_TRUE(selfResult.is_good()) << selfResult.status_code();
  auto issuedResult = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_TRUE(issuedResult.is_good()) << issuedResult.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 3u);
}

// OPC 10000-6 Table 43: a self-signed ApplicationInstance Certificate "should" have cA FALSE, "however, TRUE
// shall be accepted to ensure backward interoperability" (owner decision 2026-10-03: keep accepting it). Such
// a legacy certificate is a trusted peer, not an issuer, so AddCertificate adds it; a self-signed root CA is
// still refused as an issuer (7.8.2.4): an RSA root with no application key usages, an ECC root with no
// application URI, and an ECC root whose pathLength is above 0 (refused by the ApplicationInstance usage
// rules).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-21-TRUST-LIST-ADD-PLACEMENT, scope=function)
TEST_F(TrustListTest, AddCertificateAddsASelfSignedApplicationCertificateMarkedCa)
{
  create_manager();
  // A third-party (legacy) self-signed ApplicationInstance Certificate that carries cA TRUE, pathLength 0 and
  // keyCertSign beside the application key usages and an application URI.
  auto peerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig legacy;
  legacy.subjectKeys = legacy.issuerKeys = peerKeys;
  legacy.subject.commonName = "Legacy self-signed peer";
  legacy.serialNumber = "7206";
  legacy.basicConstraint.cA = true;
  legacy.basicConstraint.pathLength = 0;
  legacy.keyUsage.keyCertSign = true;
  legacy.keyUsage.digitalSignature = true;
  legacy.keyUsage.nonRepudiation = true;
  legacy.keyUsage.keyEncipherment = true;
  legacy.keyUsage.dataEncipherment = true;
  legacy.keyUsage.serverAuth = true;
  legacy.keyUsage.clientAuth = true;
  legacy.subjectAlternateName.uris.push_back("urn:test:legacy:peer");
  legacy.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  legacy.from = DateTime::now();
  legacy.to = DateTime{legacy.from.value() + std::chrono::days{365}};
  const auto peer = mPki->create_cert(legacy);
  ASSERT_TRUE(peer->basic_constraints_ca());
  const auto trustedBefore = mFakeStore->trustedCerts.size();

  auto added = add_certificate_sync(mSessionA, peer->der_encoding(), true);
  EXPECT_TRUE(added.is_good()) << added.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore + 1);

  // Control: the SDK's own self-signed certificate (cA FALSE, owner decision 2026-10-03) is added as any
  // leaf.
  Crypto::SubjectAlternateName sdkNames;
  sdkNames.uris.push_back("urn:test:sdk:peer");
  auto identity = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "SDK self-signed peer"},
    DateTime{2050, 1, 1, 0, 0, 0},
    sdkNames,
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_TRUE(identity.is_good());
  auto sdkAdded = add_certificate_sync(mSessionA, identity.value().second->der_encoding(), true);
  EXPECT_TRUE(sdkAdded.is_good()) << sdkAdded.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore + 2);

  auto rootKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto root = mPki->create_root_ca(rootKeys, "Self-signed root", "7203");
  auto refused = add_certificate_sync(mSessionA, root->der_encoding(), true);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "AddCertificateCannotAddACaCertificate");
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore + 2) << "the root was not added";

  // A common ECC root CA profile passes the ECC ApplicationInstance key-usage rule (digitalSignature with
  // keyCertSign). Each arm fails exactly one of the other clauses, so each clause is shown to hold on its
  // own: an ECC root with pathLength 0 but no application URI, and one with a URI but pathLength 1.
  const auto eccRoot = [&](const std::string& serial, std::optional<std::string> uri, uint32_t pathLength)
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = "ECC root " + serial;
    p.serialNumber = serial;
    p.basicConstraint.cA = true;
    p.basicConstraint.pathLength = pathLength;
    p.keyUsage.digitalSignature = true;
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    if (uri)
      p.subjectAlternateName.uris.push_back(*uri);
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    return mPki->create_cert(p);
  };
  for (const auto& root :
    {eccRoot("7204", std::nullopt, 0), eccRoot("7205", std::string{"urn:test:ecc:root"}, 1)})
  {
    auto eccRefused = add_certificate_sync(mSessionA, root->der_encoding(), true);
    EXPECT_EQ(eccRefused.status_code().as_status(), Status::BadCertificateInvalid)
      << root->subject_common_name();
    ASSERT_NE(eccRefused.shared_detail(), nullptr);
    EXPECT_EQ(eccRefused.shared_detail()->code, "AddCertificateCannotAddACaCertificate");
  }
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore + 2) << "no ECC root was added";
}

// AddCertificate validates under the group's options too: an expired certificate is refused with
// Bad_CertificateTimeInvalid as the cause, and added once SuppressCertificateExpired is configured.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, AddCertificateHonoursTheConfiguredExpirySuppression)
{
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "Expired");

  create_manager();
  auto refused = add_certificate_sync(mSessionA, expired->der_encoding(), true);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateTimeInvalid}.value());
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
  mManager->shutdown();

  mValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressCertificateExpired};
  create_manager();
  auto accepted = add_certificate_sync(mSessionA, expired->der_encoding(), true);
  EXPECT_TRUE(accepted.is_good()) << accepted.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 2u);
}

// Part 4 Table 106 Certificate Usage / Part 6 Table 45: an issuer-list entry is validated as a CA
// certificate, so one without basicConstraints cA TRUE is refused with Bad_CertificateIssuerUseNotAllowed
// as the cause and named; the control puts a self-signed root in the same place and is accepted.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAnIssuerCertificateWithoutTheCaFlag)
{
  create_manager();
  const auto now = DateTime::now();
  const DateTime until{now.value() + std::chrono::days{30}};
  auto endEntityKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto endEntity =
    make_trust_list_cert(*mPki, endEntityKeys, endEntityKeys, nullptr, "NotACa", "7301", false, now, until);
  auto rootKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto root =
    make_trust_list_cert(*mPki, rootKeys, rootKeys, nullptr, "AnotherRoot", "7302", true, now, until);

  const auto update = [&](const shared_ptr<const X509Certificate>& issuer)
  {
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x04;  // IssuerCertificates; the fixture CA stays for its CRL
    trustList.issuer_certificates().push_back(mCaCert->der_encoding());
    trustList.issuer_certificates().push_back(issuer->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  auto refused = update(endEntity);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateUseNotAllowed}.value());
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{endEntity->thumbprint()}));
  EXPECT_EQ(mFakeStore->issuerCerts.size(), 1u) << "the issuer list is unchanged";

  auto accepted = update(root);
  ASSERT_TRUE(accepted.is_good()) << accepted.status_code();
  EXPECT_EQ(mFakeStore->issuerCerts.size(), 2u);
}

// The CA rule for an issuer-list entry runs after its validity check, not instead of it: an expired
// intermediate CA in the new issuer list is refused with Bad_CertificateTimeInvalid as the cause.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAnExpiredIntermediateInTheIssuerList)
{
  create_manager();
  const auto now = DateTime::now();
  auto intermediateKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expiredIntermediate = make_trust_list_cert(*mPki,
    intermediateKeys,
    mCaKeys,
    mCaCert,
    "ExpiredIntermediate",
    "7501",
    true,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}});

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x04;  // IssuerCertificates
  trustList.issuer_certificates().push_back(mCaCert->der_encoding());
  trustList.issuer_certificates().push_back(expiredIntermediate->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
  auto refused = close_and_update_sync(mSessionA, openResult.value());
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateTimeInvalid}.value());
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{expiredIntermediate->thumbprint()}));
  EXPECT_EQ(mFakeStore->issuerCerts.size(), 1u) << "the issuer list is unchanged";
}

// Owner decision (2026-10-01): every certificate of the NEW list is validated, kept ones included. A
// trusted certificate the store already holds that has since expired refuses an update that keeps it,
// naming it, until SuppressCertificateExpired is configured.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-ENTRIES-PASS-PART4-VALIDATION-AGAINST-THE-NEW-LIST, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAKeptCertificateThatHasExpired)
{
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "KeptExpired");
  mFakeStore->trustedCerts.push_back(expired);
  create_manager();

  const auto crlOnlyUpdate = [&]
  {
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x02;  // TrustedCrls only: the trusted certificates are kept
    trustList.trusted_crls().push_back(mCrl->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  auto refused = crlOnlyUpdate();
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateTimeInvalid}.value());
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{expired->thumbprint()}))
    << "the refusal names the kept certificate";
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);

  mFakeStore->set_validation_options(
    TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressCertificateExpired});
  auto accepted = crlOnlyUpdate();
  ASSERT_TRUE(accepted.is_good()) << accepted.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 2u) << "the kept certificates are kept";
}

// Part 12 7.8.2.1: the Server "will validate all new Certificates and CRLs". A CRL carrying the fixture
// CA's name but signed by an unrelated key, and a CRL whose issuer is in neither list, each refuse the
// update with Bad_CertificateInvalid, the cause and the CRL's issuer; the list is unchanged. The
// control's CRL is signed by the fixture CA and is installed.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CRLS-ARE-VALIDATED-BEFORE-THEY-ARE-INSTALLED
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-CRLS-ARE-VALIDATED-BEFORE-THEY-ARE-INSTALLED, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesACrlThatItsIssuerDidNotSign)
{
  create_manager();
  auto otherKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto otherCa = mPki->create_root_ca(otherKeys, "Unlisted CRL Issuer", "7401");

  const auto update = [&](const shared_ptr<const X509Crl>& crl)
  {
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x02;  // TrustedCrls
    trustList.trusted_crls().push_back(crl->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  auto forged = update(mPki->create_crl(mCaCert, otherKeys, {"77"}));
  ASSERT_TRUE(forged.is_bad());
  EXPECT_EQ(forged.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(forged.shared_detail(), nullptr);
  EXPECT_EQ(forged.shared_detail()->code, "TrustListCrlInvalid");
  EXPECT_EQ(forged.shared_detail()->innerStatus, StatusCode{Status::BadSecurityChecksFailed}.value());
  EXPECT_NE(context_value(*forged.shared_detail(), ua::ContextKeys::crlIssuer.value()).find("Root CA"),
    std::string::npos)
    << "the refusal names the CRL's issuer";

  auto orphan = update(mPki->create_crl(otherCa, otherKeys, {"77"}));
  ASSERT_TRUE(orphan.is_bad());
  EXPECT_EQ(orphan.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(orphan.shared_detail(), nullptr);
  EXPECT_EQ(orphan.shared_detail()->innerStatus, StatusCode{Status::BadCertificateChainIncomplete}.value());
  EXPECT_NE(
    context_value(*orphan.shared_detail(), ua::ContextKeys::crlIssuer.value()).find("Unlisted CRL Issuer"),
    std::string::npos);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), mCrl->der_encoding()) << "the list is unchanged";

  auto validCrl = mPki->create_crl(mCaCert, mCaKeys, {"77"});
  auto accepted = update(validCrl);
  ASSERT_TRUE(accepted.is_good()) << accepted.status_code();
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), validCrl->der_encoding());
}

// The manager reads the group's options from the store when each validation starts: an expired
// certificate refused under the options the manager was created with is added once the store's options
// change, with no new manager.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-VALIDATION-FOLLOWS-THE-STORES-CURRENT-OPTIONS
// @relation(AC-SVR-SECADMIN-009-TRUST-LIST-VALIDATION-FOLLOWS-THE-STORES-CURRENT-OPTIONS, scope=function)
TEST_F(TrustListTest, TrustListValidationFollowsTheStoresCurrentOptions)
{
  create_manager();
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "ExpiredForOptions");

  auto refused = add_certificate_sync(mSessionA, expired->der_encoding(), true);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);

  mFakeStore->set_validation_options(
    TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressCertificateExpired});
  auto accepted = add_certificate_sync(mSessionA, expired->der_encoding(), true);
  EXPECT_TRUE(accepted.is_good()) << accepted.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 2u);
}

// An AddCertificate validates against the lists it read; a change the manager applied in between (here a
// RemoveCertificate issued while the lists were being read) makes that verdict stale, and the commit
// refuses with Bad_InvalidState (TrustListChangedDuringValidation). The control repeats the add with
// nothing in between and it goes through.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-REFUSES-WHEN-THE-LIST-CHANGED-DURING-VALIDATION
// @relation(AC-SVR-SECADMIN-009-ADDCERTIFICATE-REFUSES-WHEN-THE-LIST-CHANGED-DURING-VALIDATION, scope=function)
TEST_F(TrustListTest, AddCertificateIsRefusedWhenTheListChangesDuringItsValidation)
{
  create_manager();
  auto removed = std::make_shared<std::promise<VoidResult>>();
  const auto leafThumbprint = thumbprint_hex(mLeafCert);
  mFakeStore->beforeIssuerCrlsAnswer = [this, removed, leafThumbprint, fired = false]() mutable
  {
    if (std::exchange(fired, true))
      return;
    mManager->remove_certificate_async(
      mSessionA, leafThumbprint, true, [removed](VoidResult r) { removed->set_value(std::move(r)); });
  };

  auto refused = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadInvalidState);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "TrustListChangedDuringValidation");
  ASSERT_TRUE(removed->get_future().get().is_good());
  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "the removal went through and the addition did not";

  mFakeStore->beforeIssuerCrlsAnswer = nullptr;
  auto accepted = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_TRUE(accepted.is_good()) << accepted.status_code();
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// Part 12 7.8.2.4: isTrustedCertificate FALSE is Bad_CertificateInvalid whatever else holds - also while
// the TrustList is open for write, which otherwise answers Bad_InvalidState.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-REFUSES-AN-UNTRUSTED-CERTIFICATE-FIRST
// @relation(AC-SVR-SECADMIN-009-ADDCERTIFICATE-REFUSES-AN-UNTRUSTED-CERTIFICATE-FIRST, scope=function)
TEST_F(TrustListTest, AddCertificateWithIsTrustedFalseIsCertificateInvalidEvenWhileOpenForWrite)
{
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());

  auto untrusted = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), false);
  EXPECT_EQ(untrusted.status_code().as_status(), Status::BadCertificateInvalid);
  auto trusted = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_EQ(trusted.status_code().as_status(), Status::BadInvalidState)
    << "control: the write handle refuses";
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// The push service's answer to the gate: the transaction owner may modify, another session may
// not, and nobody is refused once the transaction is gone.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, TrustListModificationIsAllowedForTheTransactionOwnerOnly)
{
  EXPECT_TRUE(mPushService->trust_list_modification_allowed(mSessionB).is_good()) << "no transaction yet";

  mPushService->on_trust_list_modified(mSessionA, NodeId{0, uint32_t{12345}});
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (mPushService->trust_list_modification_allowed(mSessionB).is_good() &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  EXPECT_EQ(
    mPushService->trust_list_modification_allowed(mSessionB).as_status(), Status::BadTransactionPending);
  EXPECT_TRUE(mPushService->trust_list_modification_allowed(mSessionA).is_good()) << "the owner may";

  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good());
  EXPECT_TRUE(mPushService->trust_list_modification_allowed(mSessionB).is_good()) << "gone with it";
}

// Part 12 Figure 22: a TrustList opened for write creates the Session's transaction - empty until a change is
// made, and ended by CancelChanges like any other - or continues the one it holds; another Session is refused
// meanwhile. Falsifiable: the former service started a transaction only at CloseAndUpdate.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, OpeningForWriteOpensOrContinuesTheSessionsTransaction)
{
  auto claimed = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(claimed.is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, claimed.value());
  claimed = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();  // a barrier on the service strand

  EXPECT_EQ(mPushService->claim_trust_list_modification(mSessionB).status_code(),
    StatusCode{Status::BadTransactionPending})
    << "another Session is refused while the transaction is held";
  auto again = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(again.is_good()) << "the owner continues its transaction";
  mPushService->on_trust_list_opened_for_write(mSessionA, again.value());
  again = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good()) << "the Open opened a transaction to cancel";
  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo})
    << "one transaction, not one per Open";
  EXPECT_TRUE(mPushService->claim_trust_list_modification(mSessionB).is_good()) << "free once it ended";
}

// An AddCertificate or RemoveCertificate in flight does not keep an empty transaction alive: its change never
// lands in one. Falsifiable: counting its claim kept the empty transaction a failed UpdateCertificate opened,
// refusing every other Session until the owner applied or cancelled it.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, AnAddCertificateInFlightDoesNotKeepAnEmptyTransaction)
{
  const ByteString malformed(std::vector<byte>{byte{0x01}, byte{0x02}});
  auto adding = mPushService->claim_immediate_trust_list_modification(mSessionA);
  ASSERT_TRUE(adding.is_good());
  ASSERT_TRUE(
    update_certificate_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, malformed, {}, String{}, ByteString{})
      .is_bad());
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo})
    << "the failed UpdateCertificate's empty transaction was rolled back";
  adding = std::shared_ptr<TrustListModificationClaim>{};
}

// The transaction-claim count cannot outlive the claims it is part of: a Session closing zeroes the counts
// while one of its claims is still alive, a later claim of the same Session joins a transaction, and the
// older one is withdrawn first. Afterwards an empty transaction another Session's failed UpdateCertificate
// opens is rolled back as usual. Falsifiable: the count stuck at 1 kept every later empty transaction alive.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, TheTransactionClaimCountDoesNotOutliveAClosedSessionsClaims)
{
  auto older =
    mPushService->claim_immediate_trust_list_modification(mSessionA);  // an AddCertificate in flight
  ASSERT_TRUE(older.is_good());
  mPushService->on_session_closed_async(mSessionA);
  (void)get_rejected_list_sync();  // the close ran: counts zeroed, owner released
  auto later = mPushService->claim_trust_list_modification(mSessionA);  // a CloseAndUpdate's claim
  ASSERT_TRUE(later.is_good());
  older = std::shared_ptr<TrustListModificationClaim>{};  // withdrawn first
  later = std::shared_ptr<TrustListModificationClaim>{};

  const ByteString malformed(std::vector<byte>{byte{0x01}, byte{0x02}});
  ASSERT_TRUE(
    update_certificate_sync(mSessionB, mNullGroupId, mRsaSha256TypeId, malformed, {}, String{}, ByteString{})
      .is_bad());
  EXPECT_EQ(apply_changes_sync(mSessionB).status_code(), StatusCode{Status::BadNothingToDo})
    << "the failed UpdateCertificate's empty transaction was rolled back";
}

// A failed UpdateCertificate rolls back only a transaction that holds nothing: not one a TrustList Open
// opened (Figure 22: ApplyChanges, CancelChanges or the Session closing end it), and not while a TrustList
// change of the owner is in flight (it names that transaction and would be dropped). Falsifiable: the former
// rollback ended both, losing a CloseAndUpdate already answered Good.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, AFailedUpdateCertificateKeepsTheTransactionATrustListOpened)
{
  const ByteString malformed(std::vector<byte>{byte{0x01}, byte{0x02}});
  auto opened = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(opened.is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, opened.value());
  opened = std::shared_ptr<TrustListModificationClaim>{};
  ASSERT_TRUE(
    update_certificate_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, malformed, {}, String{}, ByteString{})
      .is_bad());
  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good()) << "the Open's transaction survived the failure";

  // A change in flight (claimed, not yet landed) when an UpdateCertificate opens the transaction and fails.
  auto inFlight = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(inFlight.is_good());
  ASSERT_TRUE(
    update_certificate_sync(mSessionA, mNullGroupId, mRsaSha256TypeId, malformed, {}, String{}, ByteString{})
      .is_bad());
  mPushService->on_trust_list_modified(mSessionA,
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList},
    inFlight.value());
  inFlight = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();
  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good()) << "the change landed in a transaction";
}

// Part 12 7.10.10: the reset ends the push transaction, so nothing staged before it can be applied in the
// shutdown window. Falsifiable: the former reset left it open for an ApplyChanges.
// @verifies AC-SVR-PULLCRT-040-B-THE-RESET-ALWAYS-SHUTS-DOWN-AND-ANSWERS-WHETHER-IT-CLEARED
TEST_F(CertificatePushServiceTest, TheResetEndsThePushTransaction)
{
  auto opened = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(opened.is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, opened.value());
  opened = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  std::promise<VoidResult> reset;
  mPushService->reset_to_server_defaults_async(
    mSessionA, [&reset](VoidResult r) { reset.set_value(std::move(r)); });
  auto resetFuture = reset.get_future();
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
}

// An Open whose transaction ends before the service hears of it (CancelChanges in between) opens no new one:
// the claim names the transaction it was taken in (Part 12 7.10.8, owner decision Q2).
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, AnOpenWhoseTransactionEndedOpensNone)
{
  auto first = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(first.is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, first.value());
  first = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  auto late = mPushService->claim_trust_list_modification(mSessionA);  // taken in that transaction
  ASSERT_TRUE(late.is_good());
  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, late.value());
  late = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo})
    << "the cancelled transaction is not reopened";
}

// Part 12 7.10.8 (owner decision Q2): CancelChanges is never refused, also while a CloseAndUpdate of the
// transaction is still merging; the change, landing after the cancel, opens no new transaction - it was
// cancelled. Falsifiable: the former service opened a new transaction for it, so the cancelled change
// resurrected.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(CertificatePushServiceTest, AChangeWhoseTransactionWasCancelledWhileItRanOpensNone)
{
  auto opened = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(opened.is_good());
  mPushService->on_trust_list_opened_for_write(mSessionA, opened.value());
  opened = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  auto merging = mPushService->claim_trust_list_modification(mSessionA);  // a CloseAndUpdate in flight
  ASSERT_TRUE(merging.is_good());
  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good()) << "CancelChanges is not refused";
  mPushService->on_trust_list_modified(mSessionA,
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList},
    merging.value());
  merging = std::shared_ptr<TrustListModificationClaim>{};
  (void)get_rejected_list_sync();

  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo})
    << "no transaction carries the cancelled change";
  EXPECT_TRUE(mPushService->claim_trust_list_modification(mSessionB).is_good()) << "and nothing is held";
}

// The push service's claim: the first session claims, another is refused while the claim stands, a
// withdrawn claim frees it, and a transaction opened by the claimant keeps the refusal.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, ATrustListClaimHoldsTheTransactionUntilItIsWithdrawnOrOpened)
{
  // A claim is withdrawn by dropping it.
  const auto withdrawn = std::shared_ptr<TrustListModificationClaim>{};
  auto firstA = mPushService->claim_trust_list_modification(mSessionA);
  EXPECT_TRUE(firstA.is_good());
  EXPECT_EQ(mPushService->claim_trust_list_modification(mSessionB).status_code().as_status(),
    Status::BadTransactionPending);
  auto secondA = mPushService->claim_trust_list_modification(mSessionA);
  EXPECT_TRUE(secondA.is_good()) << "the claimant may again";
  firstA = withdrawn;
  EXPECT_EQ(mPushService->claim_trust_list_modification(mSessionB).status_code().as_status(),
    Status::BadTransactionPending)
    << "claims are counted: one of A's two is still in flight";
  secondA = withdrawn;
  auto claimB = mPushService->claim_trust_list_modification(mSessionB);
  EXPECT_TRUE(claimB.is_good()) << "freed by the withdrawal";
  claimB = withdrawn;

  // The claimant's modification turns the claim into the transaction; the refusal outlives the claim.
  auto claimed = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(claimed.is_good());
  mPushService->on_trust_list_modified(mSessionA, NodeId{0, uint32_t{12345}}, claimed.value());
  (void)cancel_changes_sync(mSessionB);  // queued behind on_trust_list_modified: a strand barrier
  claimed = withdrawn;  // the claim's last holder lets go after the transaction opened: it holds
  EXPECT_EQ(mPushService->claim_trust_list_modification(mSessionB).status_code().as_status(),
    Status::BadTransactionPending);
  EXPECT_TRUE(cancel_changes_sync(mSessionA).is_good());
  claimB = mPushService->claim_trust_list_modification(mSessionB);
  EXPECT_TRUE(claimB.is_good());
  claimB = withdrawn;
}

// Every modification whose claim was granted but which did not go through releases the claim: an
// expired certificate, malformed DER, a refused CloseAndUpdate. A successful one does not (its
// transaction takes the ownership over). Before, these paths kept the claim for good and every other
// session was refused until restart (round-2 panel). RATIFIED (owner decision Q1, 2026-10-04): an Open for
// write takes a claim too and hands it to the push service, which keeps it for the transaction; the fixture's
// Open notification keeps it likewise, so the counts are the modifications' claims alone.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(TrustListTest, AModificationThatDoesNotGoThroughReleasesItsClaim)
{
  mModificationGate = [](const NodeId&)
  {
    return StatusCode{Status::Good};
  };
  std::vector<std::shared_ptr<TrustListModificationClaim>> openClaims;  // read only after the strand turns
  std::mutex openClaimsMutex;
  mOpenedForWrite = [&](NodeId, std::shared_ptr<TrustListModificationClaim> claim)
  {
    const std::lock_guard lock(openClaimsMutex);
    openClaims.push_back(std::move(claim));
  };
  create_manager();
  const auto now = DateTime::now();
  auto expiredKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expired = mPki->create_leaf_cert(expiredKeys,
    mCaKeys,
    mCaCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {},
    "Expired");

  EXPECT_FALSE(add_certificate_sync(mSessionA, expired->der_encoding(), true).is_good());
  EXPECT_EQ(abandoned_count(), 1u) << "the expired certificate released its claim";
  EXPECT_FALSE(add_certificate_sync(mSessionA, ByteString{0x30, 0x03, 0x01}, true).is_good());
  EXPECT_EQ(abandoned_count(), 2u) << "malformed DER released its claim";

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(expired->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
  EXPECT_FALSE(close_and_update_sync(mSessionA, openResult.value()).is_good());
  EXPECT_EQ(abandoned_count(), 3u) << "the refused CloseAndUpdate released its claim";

  // Control: a modification that goes through keeps its claim for the transaction. RATIFIED (owner report
  // 2026-10-03, BR-13): the control is a CloseAndUpdate - an AddCertificate, which it was, opens no
  // transaction (OPC 10000-12 7.8.2.4) and releases its claim
  // (AddCertificateAppliesAtOnceAndOpensNoTransaction).
  auto reopened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(reopened.is_good());
  TrustListDataType valid;
  valid.specified_lists() = 0x01;
  valid.trusted_certificates().push_back(mLeaf2Cert->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, reopened.value(), encode_trust_list(valid)).is_good());
  EXPECT_TRUE(close_and_update_sync(mSessionA, reopened.value()).is_good());
  EXPECT_EQ(abandoned_count(), 3u);
}

// A session that closes while its modification is in flight keeps no claim, and the modification's
// late completion opens no transaction for it: another session may modify afterwards. The server
// removes a Session before its close event is delivered, and the push service asks the server whether
// the Session still exists, so a late claim and a late UpdateCertificate are refused as well.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(CertificatePushServiceTest, AClosedSessionsLateModificationOpensNoTransaction)
{
  const auto claim = mPushService->claim_trust_list_modification(mSessionA);
  ASSERT_TRUE(claim.is_good());
  mark_session_gone(mSessionA);
  mPushService->on_session_closed_async(mSessionA);
  mPushService->on_trust_list_modified(mSessionA, NodeId{0, uint32_t{12345}});
  (void)cancel_changes_sync(mSessionB);  // a strand barrier behind both posts
  EXPECT_TRUE(mPushService->trust_list_modification_allowed(mSessionB).is_good())
    << "no claim and no transaction survive the closed session";
  EXPECT_EQ(cancel_changes_sync(mSessionA).status_code().as_status(), Status::BadNothingToDo)
    << "no transaction was opened";

  EXPECT_EQ(mPushService->claim_trust_list_modification(mSessionA).status_code().as_status(),
    Status::BadSessionIdInvalid)
    << "a closed session takes no claim";
  const auto lateUpdate =
    start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding()).result.get();
  ASSERT_TRUE(lateUpdate.is_bad());
  EXPECT_EQ(lateUpdate.status_code().as_status(), Status::BadSessionIdInvalid)
    << "a late UpdateCertificate opens no transaction for the closed session";
  EXPECT_TRUE(mPushService->trust_list_modification_allowed(mSessionB).is_good());
}

namespace
{
/// Starts a CloseAndUpdate whose merge parks on the store's trusted-certificates read (the upload
/// masks the CRLs only, so the merge fetches the kept certificates), and returns its future.
std::future<Result<bool>> start_parked_update(TrustListManager& manager, InMemoryFakeCertificateStore& store,
  const NodeId& session, uint32_t handle, std::shared_ptr<std::promise<Result<bool>>> promise)
{
  (void)store;
  manager.close_and_update_async(
    session, handle, [promise](Result<bool> result) { promise->set_value(std::move(result)); });
  return promise->get_future();
}
}  // namespace

// While a CloseAndUpdate waits on the store, a second CloseAndUpdate on the handle is refused before its
// data is decoded, and once the session has closed its handle an AddCertificate and a RemoveCertificate are
// refused too: the update would overwrite them with the lists it fetched. The parked update then abandons
// (its handle is gone) and nothing is replaced.
// @verifies AC-SVR-SECADMIN-009-NO-TRUST-LIST-CHANGE-WHILE-AN-UPDATE-IS-IN-FLIGHT
TEST_F(TrustListTest, ChangesAreRefusedWhileAnUpdateWaitsOnTheStore)
{
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  const auto handle = openResult.value();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x02;
  trustList.trusted_crls().push_back(mCrl->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, handle, encode_trust_list(trustList)).is_good());

  mFakeStore->parkTrustedRead = true;
  auto promise = std::make_shared<std::promise<Result<bool>>>();
  auto parked = start_parked_update(*mManager, *mFakeStore, mSessionA, handle, promise);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!mFakeStore->trustedReadIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  ASSERT_TRUE(mFakeStore->trustedReadIsParked.load()) << "the merge is waiting on the store";

  auto second = close_and_update_sync(mSessionA, handle);
  EXPECT_EQ(second.status_code().as_status(), Status::BadInvalidState) << "one update at a time";

  ASSERT_TRUE(close_sync(mSessionA, handle).is_good());
  auto add = add_certificate_sync(mSessionA, mLeaf2Cert->der_encoding(), true);
  EXPECT_EQ(add.status_code().as_status(), Status::BadInvalidState)
    << "no change while an update is in flight";
  auto remove =
    remove_certificate_sync(mSessionA, fmt::format("{:02X}", fmt::join(mLeafCert->thumbprint(), "")), true);
  EXPECT_EQ(remove.status_code().as_status(), Status::BadInvalidState)
    << "no removal while an update is in flight";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding())
    << "unchanged, not just same size";

  mFakeStore->release_parked_trusted_read();
  const auto result = parked.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidState) << "the update's handle is gone";
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u);
}

// A session that closes its handle and opens another while its update waits on the store: the update
// sees a different handle, abandons, and leaves the NEW handle open (closing only its own).
// @verifies AC-SVR-SECADMIN-009-NO-TRUST-LIST-CHANGE-WHILE-AN-UPDATE-IS-IN-FLIGHT
TEST_F(TrustListTest, AnUpdateWhoseHandleWasReplacedAbandonsAndLeavesTheNewHandleOpen)
{
  create_manager();
  auto first = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(first.is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x02;
  trustList.trusted_crls().push_back(mCrl->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, first.value(), encode_trust_list(trustList)).is_good());

  mFakeStore->parkTrustedRead = true;
  auto promise = std::make_shared<std::promise<Result<bool>>>();
  auto parked = start_parked_update(*mManager, *mFakeStore, mSessionA, first.value(), promise);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!mFakeStore->trustedReadIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  ASSERT_TRUE(mFakeStore->trustedReadIsParked.load());

  ASSERT_TRUE(close_sync(mSessionA, first.value()).is_good());
  auto second = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(second.is_good());
  ASSERT_NE(second.value(), first.value());

  mFakeStore->release_parked_trusted_read();
  EXPECT_EQ(parked.get().status_code().as_status(), Status::BadInvalidState);
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "no stale list was written back";
  EXPECT_TRUE(write_sync(mSessionA, second.value(), encode_trust_list(trustList)).is_good())
    << "the new handle is still open";
}

// ============================================================================
// U5 (certificate-validation test plan): the U1 placements, U2 faults and CRL faults as trust-list
// contents (OPC 10000-12 section 7.8.2), and the channel close an applied change triggers.
// Every expected status comes from an oracle below written from the specification.
// ============================================================================

namespace
{

std::shared_ptr<const Crypto> make_u5_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

ByteString encode_u5_trust_list(const TrustListDataType& trustList)
{
  memory_stream_device::Dynamic encDevice(65535, true);
  MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
  encoder.encode(EncodingLimits{}.stack_depth(), trustList);
  auto data = encDevice.get_data();
  return ByteString{data};
}

/// One byte of the signature value flipped (the last byte of the DER), the TBSCertificate untouched.
ByteString with_broken_signature(const shared_ptr<const X509Certificate>& certificate)
{
  const auto der = certificate->der_encoding();
  std::vector<uint8_t> bytes(der.begin(), der.end());
  bytes.back() = static_cast<uint8_t>(bytes.back() ^ 0x5A);
  return ByteString{std::move(bytes)};
}

/// A CRL signed by its issuer whose nextUpdate is a day in the past.
shared_ptr<const X509Crl> make_u5_out_of_date_crl(const Crypto& crypto, TestPki& pki,
  const shared_ptr<const X509Certificate>& issuer, const shared_ptr<const AsymmetricKeyPair>& issuerKeys)
{
  const auto current = pki.create_crl(issuer, issuerKeys, {"1"});
  const auto der = current->der_encoding();
  std::vector<unsigned char> raw(der.begin(), der.end());
  const unsigned char* in = raw.data();
  std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl{
    d2i_X509_CRL(nullptr, &in, static_cast<long>(raw.size())), &X509_CRL_free};
  if (!crl)
    throw std::runtime_error{"d2i_X509_CRL failed"};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> thisUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> nextUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  X509_gmtime_adj(thisUpdate.get(), -2L * 24 * 60 * 60);
  X509_gmtime_adj(nextUpdate.get(), -1L * 24 * 60 * 60);
  X509_CRL_set1_lastUpdate(crl.get(), thisUpdate.get());
  X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get());
  const auto pem = issuerKeys->private_key_pem();
  std::unique_ptr<BIO, decltype(&BIO_free)> bio{
    BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
  char passphrase[] = "password";
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
    PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, passphrase), &EVP_PKEY_free};
  if (!key || X509_CRL_sign(crl.get(), key.get(), EVP_sha256()) <= 0)
    throw std::runtime_error{"re-signing the out-of-date CRL failed"};
  unsigned char* out = nullptr;
  const int length = i2d_X509_CRL(crl.get(), &out);
  if (length <= 0)
    throw std::runtime_error{"i2d_X509_CRL failed"};
  std::vector<ua::byte> bytes(
    reinterpret_cast<const ua::byte*>(out), reinterpret_cast<const ua::byte*>(out) + length);
  OPENSSL_free(out);
  return crypto.read_crl_from_der(span<const ua::byte>{bytes});
}

/// leaf <- intermediate <- root and, per position, fault variants sharing the valid twin's name and key.
struct U5Pki
{
  std::shared_ptr<const Crypto> crypto;
  shared_ptr<const AsymmetricKeyPair> rootKeys;
  shared_ptr<const AsymmetricKeyPair> intermediateKeys;
  shared_ptr<const X509Certificate> root;
  shared_ptr<const X509Certificate> intermediate;
  shared_ptr<const X509Certificate> leaf;
  // [position] = leaf, intermediate, root.
  std::array<shared_ptr<const X509Certificate>, 3> expired;
  std::array<shared_ptr<const X509Certificate>, 3> notYetValid;
  std::array<shared_ptr<const X509Certificate>, 3> wrongCa;
  shared_ptr<const X509Crl> rootCrl;
  shared_ptr<const X509Crl> intermediateCrl;
  shared_ptr<const X509Crl> rootCrlRevokingIntermediate;
  shared_ptr<const X509Crl> intermediateCrlRevokingLeaf;
  shared_ptr<const X509Crl> rootCrlOutOfDate;
};

std::unique_ptr<U5Pki> build_u5_pki()
{
  auto pki = std::make_unique<U5Pki>();
  pki->crypto = make_u5_crypto();
  TestPki helper{pki->crypto};
  const auto now = DateTime::now();
  const DateTime inAYear{now.value() + std::chrono::days{365}};
  const DateTime monthAgo{now.value() - std::chrono::days{30}};
  const DateTime yesterday{now.value() - std::chrono::days{1}};
  const DateTime inTenDays{now.value() + std::chrono::days{10}};
  const DateTime inFortyDays{now.value() + std::chrono::days{40}};
  // Keys from the shared test key cache, a slot per key.
  pki->rootKeys = test_keys::key_pair(*pki->crypto, test_keys::KeyType::Rsa2048, 0);
  pki->intermediateKeys = test_keys::key_pair(*pki->crypto, test_keys::KeyType::Rsa2048, 1);
  const auto leafKeys = test_keys::key_pair(*pki->crypto, test_keys::KeyType::Rsa2048, 2);
  const auto& rk = pki->rootKeys;
  const auto& ik = pki->intermediateKeys;

  pki->root = make_trust_list_cert(helper, rk, rk, nullptr, "U5 Root", "5100", true, now, inAYear);
  pki->intermediate =
    make_trust_list_cert(helper, ik, rk, pki->root, "U5 Intermediate", "5200", true, now, inAYear);
  pki->leaf =
    make_trust_list_cert(helper, leafKeys, ik, pki->intermediate, "U5 Leaf", "5300", false, now, inAYear);

  pki->expired = {make_trust_list_cert(
                    helper, leafKeys, ik, pki->intermediate, "U5 Leaf", "5301", false, monthAgo, yesterday),
    make_trust_list_cert(helper, ik, rk, pki->root, "U5 Intermediate", "5201", true, monthAgo, yesterday),
    make_trust_list_cert(helper, rk, rk, nullptr, "U5 Root", "5101", true, monthAgo, yesterday)};
  pki->notYetValid = {
    make_trust_list_cert(
      helper, leafKeys, ik, pki->intermediate, "U5 Leaf", "5302", false, inTenDays, inFortyDays),
    make_trust_list_cert(helper, ik, rk, pki->root, "U5 Intermediate", "5202", true, inTenDays, inFortyDays),
    make_trust_list_cert(helper, rk, rk, nullptr, "U5 Root", "5102", true, inTenDays, inFortyDays)};
  pki->wrongCa = {
    make_trust_list_cert(helper, leafKeys, ik, pki->intermediate, "U5 Leaf", "5303", true, now, inAYear),
    make_trust_list_cert(helper, ik, rk, pki->root, "U5 Intermediate", "5203", false, now, inAYear),
    make_trust_list_cert(helper, rk, rk, nullptr, "U5 Root", "5103", false, now, inAYear)};

  pki->rootCrl = helper.create_crl(pki->root, rk, {});
  pki->intermediateCrl = helper.create_crl(pki->intermediate, ik, {});
  pki->rootCrlRevokingIntermediate = helper.create_crl(pki->root, rk, {"5200"});
  pki->intermediateCrlRevokingLeaf = helper.create_crl(pki->intermediate, ik, {"5300"});
  pki->rootCrlOutOfDate = make_u5_out_of_date_crl(*pki->crypto, helper, pki->root, rk);
  return pki;
}

/// Where a certificate is relative to a CloseAndUpdate.
enum class ListPlacement
{
  NewTrusted,  ///< In the uploaded TrustedCertificates.
  NewIssuer,  ///< In the uploaded IssuerCertificates.
  OldOnly,  ///< Only in the list the upload replaces.
  Absent,  ///< Nowhere.
};

const char* list_placement_name(ListPlacement placement)
{
  switch (placement)
  {
  case ListPlacement::NewTrusted:
    return "NewTrusted";
  case ListPlacement::NewIssuer:
    return "NewIssuer";
  case ListPlacement::OldOnly:
    return "OldOnly";
  case ListPlacement::Absent:
    return "Absent";
  }
  return "Unknown";
}

/// OPC 10000-12 section 7.8.2.3 with OPC 10000-4 Table 106: every certificate of the NEW list is validated
/// with the new list as its only chain material. A listed certificate whose issuer is not listed cannot be
/// built into a chain (step 2). The issuer list is validated for the CA use, so a leaf there is
/// Bad_CertificateUseNotAllowed (step 9, decision 22.4). The positions are leaf, intermediate, root.
Status list_placement_oracle(const std::array<ListPlacement, 3>& placements)
{
  const auto listed = [&](std::size_t i)
  {
    return placements[i] == ListPlacement::NewTrusted || placements[i] == ListPlacement::NewIssuer;
  };
  for (std::size_t i = 0; i < placements.size(); ++i)
  {
    if (!listed(i))
      continue;
    for (std::size_t above = i + 1; above < placements.size(); ++above)
      if (!listed(above))
        return Status::BadCertificateChainIncomplete;
  }
  if (placements[0] == ListPlacement::NewIssuer)
    return Status::BadCertificateUseNotAllowed;
  return Status::Good;
}

std::vector<std::array<ListPlacement, 3>> all_list_placements()
{
  constexpr ListPlacement all[] = {
    ListPlacement::NewTrusted, ListPlacement::NewIssuer, ListPlacement::OldOnly, ListPlacement::Absent};
  std::vector<std::array<ListPlacement, 3>> cases;
  for (const auto leaf : all)
    for (const auto intermediate : all)
      for (const auto root : all)
        cases.push_back({leaf, intermediate, root});
  return cases;
}

class TrustListPlacementMatrix : public TrustListTest,
                                 public ::testing::WithParamInterface<std::array<ListPlacement, 3>>
{
public:
  static void SetUpTestSuite()
  {
    sU5 = build_u5_pki();
  }

  static void TearDownTestSuite()
  {
    sU5.reset();
  }

protected:
  static std::unique_ptr<U5Pki> sU5;
};

std::unique_ptr<U5Pki> TrustListPlacementMatrix::sU5;

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-20-TRUST-LIST-PLACEMENT, scope=function)
TEST_P(TrustListPlacementMatrix, CloseAndUpdateReturnsTheSpecifiedStatus)
{
  const auto& placements = GetParam();
  const std::array<shared_ptr<const X509Certificate>, 3> chain{sU5->leaf, sU5->intermediate, sU5->root};
  mFakeStore->trustedCerts.clear();
  mFakeStore->issuerCerts.clear();
  mFakeStore->trustedCrls.clear();
  TrustListDataType trustList;
  trustList.specified_lists() = 0x05;  // TrustedCertificates | IssuerCertificates
  std::size_t trustedCount = 0;
  std::size_t issuerCount = 0;
  for (std::size_t i = 0; i < chain.size(); ++i)
  {
    switch (placements[i])
    {
    case ListPlacement::NewTrusted:
      trustList.trusted_certificates().push_back(chain[i]->der_encoding());
      ++trustedCount;
      break;
    case ListPlacement::NewIssuer:
      trustList.issuer_certificates().push_back(chain[i]->der_encoding());
      ++issuerCount;
      break;
    case ListPlacement::OldOnly:
      mFakeStore->issuerCerts.push_back(chain[i]);
      break;
    case ListPlacement::Absent:
      break;
    }
  }
  create_manager();
  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
  auto updateResult = close_and_update_sync(mSessionA, openResult.value());

  const auto expected = list_placement_oracle(placements);
  if (expected == Status::Good)
  {
    ASSERT_TRUE(updateResult.is_good())
      << updateResult.status_code() << " " << describe_chain(updateResult.status_code());
    EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedCount);
    EXPECT_EQ(mFakeStore->issuerCerts.size(), issuerCount);
    return;
  }
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(updateResult.shared_detail(), nullptr);
  EXPECT_EQ(updateResult.shared_detail()->innerStatus, StatusCode{expected}.value())
    << "expected cause " << StatusCode{expected} << ": " << describe_chain(updateResult.status_code());
  EXPECT_EQ(mFakeStore->replaceTrustedCertificateCallCount, 0u) << "a refused update replaces nothing";
}

INSTANTIATE_TEST_SUITE_P(EveryPlacement, TrustListPlacementMatrix, ::testing::ValuesIn(all_list_placements()),
  [](const ::testing::TestParamInfo<std::array<ListPlacement, 3>>& info)
  {
    return std::string{"Leaf_"} + list_placement_name(info.param[0]) + "_I_" +
           list_placement_name(info.param[1]) + "_R_" + list_placement_name(info.param[2]);
  });

/// Where an issuer is in the current list when AddCertificate runs.
enum class StorePlacement
{
  Trusted,
  Issuer,
  Absent,
};

struct AddPlacementCase
{
  bool addIntermediate = false;  ///< Add the intermediate (its issuer: the root) instead of the leaf.
  std::vector<StorePlacement> issuers;  ///< From the added certificate's issuer up to the root.
};

class TrustListAddPlacementMatrix : public TrustListTest,
                                    public ::testing::WithParamInterface<AddPlacementCase>
{
public:
  static void SetUpTestSuite()
  {
    sU5 = build_u5_pki();
  }

  static void TearDownTestSuite()
  {
    sU5.reset();
  }

protected:
  static std::unique_ptr<U5Pki> sU5;
};

std::unique_ptr<U5Pki> TrustListAddPlacementMatrix::sU5;

std::vector<AddPlacementCase> all_add_placements()
{
  constexpr StorePlacement all[] = {StorePlacement::Trusted, StorePlacement::Issuer, StorePlacement::Absent};
  std::vector<AddPlacementCase> cases;
  for (const auto intermediate : all)
    for (const auto root : all)
      cases.push_back({false, {intermediate, root}});
  for (const auto root : all)
    cases.push_back({true, {root}});
  return cases;
}

// OPC 10000-12 section 7.8.2.4: AddCertificate refuses a certificate whose issuer is not in the Trust List,
// and refuses a CA certificate outright (CA certificates and their CRLs are managed with the Write Method).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-21-TRUST-LIST-ADD-PLACEMENT, scope=function)
TEST_P(TrustListAddPlacementMatrix, AddCertificateReturnsTheSpecifiedStatus)
{
  const auto& c = GetParam();
  mFakeStore->trustedCerts.clear();
  mFakeStore->issuerCerts.clear();
  mFakeStore->trustedCrls.clear();
  const std::vector<shared_ptr<const X509Certificate>> issuers =
    c.addIntermediate ? std::vector<shared_ptr<const X509Certificate>>{sU5->root}
                      : std::vector<shared_ptr<const X509Certificate>>{sU5->intermediate, sU5->root};
  bool chainComplete = true;
  for (std::size_t i = 0; i < issuers.size(); ++i)
  {
    if (c.issuers[i] == StorePlacement::Trusted)
      mFakeStore->trustedCerts.push_back(issuers[i]);
    else if (c.issuers[i] == StorePlacement::Issuer)
      mFakeStore->issuerCerts.push_back(issuers[i]);
    else
      chainComplete = false;
  }
  const auto trustedBefore = mFakeStore->trustedCerts.size();
  create_manager();
  const auto& added = c.addIntermediate ? sU5->intermediate : sU5->leaf;
  auto result = add_certificate_sync(mSessionA, added->der_encoding(), true);
  if (c.addIntermediate)
  {
    // OPC 10000-12 7.8.2.4: "This Method cannot provide CRLs so issuer Certificates cannot be added with this
    // Method. Instead, CA Certificates and their CRLs shall be managed with the Write Method" - a CA
    // certificate is refused whatever its chain, and nothing is added.
    EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "AddCertificateCannotAddACaCertificate");
    EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore) << "nothing was added";
    return;
  }
  if (chainComplete)
  {
    EXPECT_TRUE(result.is_good()) << result.status_code() << " " << describe_chain(result.status_code());
    EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore + 1);
    return;
  }
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->innerStatus, StatusCode{Status::BadCertificateChainIncomplete}.value());
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore) << "nothing was added";
}

INSTANTIATE_TEST_SUITE_P(EveryPlacement, TrustListAddPlacementMatrix,
  ::testing::ValuesIn(all_add_placements()),
  [](const ::testing::TestParamInfo<AddPlacementCase>& info)
  {
    const auto name = [](StorePlacement p)
    {
      return p == StorePlacement::Trusted ? "Trusted" : p == StorePlacement::Issuer ? "Issuer" : "Absent";
    };
    std::string out = info.param.addIntermediate ? "AddIntermediate" : "AddLeaf";
    for (const auto p : info.param.issuers)
      out += std::string{"_"} + name(p);
    return out;
  });

enum class EntryFault
{
  Expired,
  NotYetValid,
  Revoked,
  WrongCa,
  BrokenSignature,
};

struct EntryFaultCase
{
  EntryFault fault = EntryFault::Expired;
  std::size_t position = 0;  ///< 0 leaf (trusted list), 1 intermediate (issuer list), 2 root (trusted list).
  bool suppressed = false;  ///< All five suppression bits set.
};

/// The causes the specification allows. Across certificates the order is not defined (decision 22.3), so a
/// fault on an issuer may surface as its own (leaf-variant) code or as the issuer variant.
std::vector<Status> entry_fault_oracle(const EntryFaultCase& c)
{
  switch (c.fault)
  {
  case EntryFault::Expired:
  case EntryFault::NotYetValid:
    if (c.suppressed)
      return {Status::Good};
    return c.position == 0 ? std::vector<Status>{Status::BadCertificateTimeInvalid}
                           : std::vector<Status>{
                               Status::BadCertificateTimeInvalid, Status::BadCertificateIssuerTimeInvalid};
  case EntryFault::Revoked:
    return c.position == 0
             ? std::vector<Status>{Status::BadCertificateRevoked}
             : std::vector<Status>{Status::BadCertificateRevoked, Status::BadCertificateIssuerRevoked};
  case EntryFault::WrongCa:
    // At the leaf the "wrong" certificate is a CA-issued certificate declaring cA TRUE with keyCertSign: in
    // the trusted list that is a legitimate intermediate CA, validated for the CA use by its own cA flag
    // (decision 21.1; Part 4 6.1.3: the trusted list "may be a Certificate belonging to a CA"), so it is
    // Good. On a CA position the fault is a CA without cA TRUE: refused for the CA use.
    if (c.position == 0)
      return {Status::Good};
    return {Status::BadCertificateUseNotAllowed, Status::BadCertificateIssuerUseNotAllowed};
  case EntryFault::BrokenSignature:
    return {Status::BadCertificateInvalid};
  }
  return {};
}

std::vector<EntryFaultCase> all_entry_faults()
{
  std::vector<EntryFaultCase> cases;
  for (const auto fault : {EntryFault::Expired,
         EntryFault::NotYetValid,
         EntryFault::Revoked,
         EntryFault::WrongCa,
         EntryFault::BrokenSignature})
    for (std::size_t position = 0; position < 3; ++position)
    {
      if (fault == EntryFault::Revoked && position == 2)
        continue;  // A self-signed root is revoked by no CRL in its own chain.
      for (const bool suppressed : {false, true})
        cases.push_back({fault, position, suppressed});
    }
  return cases;
}

class TrustListEntryFaultMatrix : public TrustListTest, public ::testing::WithParamInterface<EntryFaultCase>
{
public:
  static void SetUpTestSuite()
  {
    sU5 = build_u5_pki();
  }

  static void TearDownTestSuite()
  {
    sU5.reset();
  }

protected:
  static std::unique_ptr<U5Pki> sU5;
};

std::unique_ptr<U5Pki> TrustListEntryFaultMatrix::sU5;

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-22-TRUST-LIST-ENTRY-FAULT, scope=function)
TEST_P(TrustListEntryFaultMatrix, CloseAndUpdateReturnsTheSpecifiedStatus)
{
  using Bit = TrustListValidationOptions::Bit;
  const auto& c = GetParam();
  mValidationOptions = c.suppressed ? TrustListValidationOptions{Bit::CheckRevocationStatusOffline,
                                        Bit::SuppressCertificateExpired,
                                        Bit::SuppressHostNameInvalid,
                                        Bit::SuppressRevocationStatusUnknown,
                                        Bit::SuppressIssuerCertificateExpired,
                                        Bit::SuppressIssuerRevocationStatusUnknown}
                                    : TrustListValidationOptions{Bit::CheckRevocationStatusOffline};
  mFakeStore->trustedCerts.clear();
  mFakeStore->issuerCerts.clear();
  mFakeStore->trustedCrls.clear();
  mFakeStore->trustedCerts.push_back(mLeafCert);
  create_manager();

  std::array<ByteString, 3> der{
    sU5->leaf->der_encoding(), sU5->intermediate->der_encoding(), sU5->root->der_encoding()};
  auto rootCrl = sU5->rootCrl;
  auto intermediateCrl = sU5->intermediateCrl;
  switch (c.fault)
  {
  case EntryFault::Expired:
    der[c.position] = sU5->expired[c.position]->der_encoding();
    break;
  case EntryFault::NotYetValid:
    der[c.position] = sU5->notYetValid[c.position]->der_encoding();
    break;
  case EntryFault::WrongCa:
    der[c.position] = sU5->wrongCa[c.position]->der_encoding();
    break;
  case EntryFault::BrokenSignature:
    der[c.position] = with_broken_signature(c.position == 0   ? sU5->leaf
                                            : c.position == 1 ? sU5->intermediate
                                                              : sU5->root);
    break;
  case EntryFault::Revoked:
    if (c.position == 0)
      intermediateCrl = sU5->intermediateCrlRevokingLeaf;
    else
      rootCrl = sU5->rootCrlRevokingIntermediate;
    break;
  }

  TrustListDataType trustList;
  trustList.specified_lists() = 0x0F;  // every list
  trustList.trusted_certificates().push_back(der[0]);
  trustList.trusted_certificates().push_back(der[2]);
  trustList.issuer_certificates().push_back(der[1]);
  trustList.trusted_crls().push_back(rootCrl->der_encoding());
  trustList.issuer_crls().push_back(intermediateCrl->der_encoding());

  auto openResult = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(openResult.is_good());
  ASSERT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
  auto updateResult = close_and_update_sync(mSessionA, openResult.value());

  const auto allowed = entry_fault_oracle(c);
  if (allowed == std::vector<Status>{Status::Good})
  {
    EXPECT_TRUE(updateResult.is_good())
      << updateResult.status_code() << " " << describe_chain(updateResult.status_code());
    return;
  }
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadCertificateInvalid)
    << describe_chain(updateResult.status_code());
  if (c.fault != EntryFault::BrokenSignature || updateResult.shared_detail() != nullptr)
  {
    ASSERT_NE(updateResult.shared_detail(), nullptr);
    const auto inner = updateResult.shared_detail()->innerStatus;
    EXPECT_TRUE(std::any_of(
      allowed.begin(), allowed.end(), [inner](Status s) { return StatusCode{s}.value() == inner; }))
      << "the cause " << describe_chain(updateResult.status_code()) << " is not one the specification allows";
  }
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "the list is unchanged";
  EXPECT_EQ(mFakeStore->trustedCerts[0]->der_encoding(), mLeafCert->der_encoding());
}

std::string entry_fault_case_name(const ::testing::TestParamInfo<EntryFaultCase>& info)
{
  constexpr const char* faults[] = {"Expired", "NotYetValid", "Revoked", "WrongCa", "BrokenSignature"};
  constexpr const char* positions[] = {"Leaf", "Intermediate", "Root"};
  return std::string{faults[static_cast<int>(info.param.fault)]} + "_" + positions[info.param.position] +
         (info.param.suppressed ? "_AllSuppressed" : "_NotSuppressed");
}

INSTANTIATE_TEST_SUITE_P(
  EveryFault, TrustListEntryFaultMatrix, ::testing::ValuesIn(all_entry_faults()), entry_fault_case_name);

}  // namespace

// Decision 21.9: a CRL of the new list is validated like a certificate. An out-of-date CRL is
// revocation-unknown (the plan's labelled interpretation), so it refuses the update only while offline
// revocation checking is on and unsuppressed; a current CRL is the control.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-23-TRUST-LIST-CRL-FAULT, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAnOutOfDateCrlOnlyWhileRevocationCheckingIsOnAndUnsuppressed)
{
  using Bit = TrustListValidationOptions::Bit;
  const auto staleCrl = make_u5_out_of_date_crl(*mCrypto, *mPki, mCaCert, mCaKeys);
  mFakeStore->trustedCerts.clear();
  mFakeStore->issuerCerts.clear();
  mFakeStore->trustedCrls.clear();
  mFakeStore->trustedCerts.push_back(mCaCert);

  const auto update = [&](TrustListValidationOptions options, const shared_ptr<const X509Crl>& crl)
  {
    if (mManager)
      mManager->shutdown();
    mValidationOptions = options;
    create_manager();
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x02;  // TrustedCrls
    trustList.trusted_crls().push_back(crl->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  auto refused = update(TrustListValidationOptions{Bit::CheckRevocationStatusOffline}, staleCrl);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid)
    << describe_chain(refused.status_code());
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_NE(context_value(*refused.shared_detail(), ua::ContextKeys::crlIssuer.value()).find("Root CA"),
    std::string::npos)
    << "the refusal names the CRL's issuer";
  EXPECT_TRUE(mFakeStore->trustedCrls.empty()) << "the list is unchanged";

  auto off = update(TrustListValidationOptions{}, staleCrl);
  EXPECT_TRUE(off.is_good()) << describe_chain(off.status_code());
  auto suppressed = update(TrustListValidationOptions{Bit::CheckRevocationStatusOffline,
                             Bit::SuppressRevocationStatusUnknown,
                             Bit::SuppressIssuerRevocationStatusUnknown},
    staleCrl);
  EXPECT_TRUE(suppressed.is_good()) << describe_chain(suppressed.status_code());
  auto current = update(
    TrustListValidationOptions{Bit::CheckRevocationStatusOffline}, mPki->create_crl(mCaCert, mCaKeys, {}));
  EXPECT_TRUE(current.is_good()) << describe_chain(current.status_code());
}

// Decision 21.8: an entry the update keeps is validated too. The update specifies only the CRLs, and the
// new CRL revokes the leaf the trusted list keeps.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-24-TRUST-LIST-KEPT-ENTRY, scope=function)
TEST_F(TrustListTest, CloseAndUpdateRefusesAKeptCertificateThatTheNewCrlRevokes)
{
  mValidationOptions =
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  mFakeStore->trustedCrls.clear();
  create_manager();
  const auto update = [&](const shared_ptr<const X509Crl>& crl)
  {
    auto openResult = open_sync(mSessionA, 0x06);
    EXPECT_TRUE(openResult.is_good());
    TrustListDataType trustList;
    trustList.specified_lists() = 0x02;  // TrustedCrls only: the certificates are kept
    trustList.trusted_crls().push_back(crl->der_encoding());
    EXPECT_TRUE(write_sync(mSessionA, openResult.value(), encode_trust_list(trustList)).is_good());
    return close_and_update_sync(mSessionA, openResult.value());
  };

  const auto control = mPki->create_crl(mCaCert, mCaKeys, {"1"});
  auto accepted = update(control);
  ASSERT_TRUE(accepted.is_good()) << describe_chain(accepted.status_code());

  auto refused = update(mPki->create_crl(mCaCert, mCaKeys, {mLeafCert->serial_number()}));
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::BadCertificateRevoked}.value())
    << describe_chain(refused.status_code());
  EXPECT_EQ(context_value(*refused.shared_detail(), ua::ContextKeys::certificateThumbprint.value()),
    utils::bytes_to_hex_string(span<const byte>{mLeafCert->thumbprint()}))
    << "the refusal names the kept certificate";
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCrls[0]->der_encoding(), control->der_encoding()) << "the list is kept";
}

namespace
{
// The production modification path: the TrustListManager's modified callback hands the change to the push
// service, as ua_push_management_wiring.cpp wires it.
class CertificatePushServiceTrustListEffectTest : public CertificatePushServiceTest
{
public:
  /// Open(Write|EraseExisting) -> Write(@p trustList) -> CloseAndUpdate on the application TrustList, as
  /// session A.
  Result<bool> stage_trust_list(const TrustListDataType& trustList)
  {
    std::promise<Result<uint32_t>> opened;
    mTrustList->open_async(
      mSessionA, 0x06, [&opened](Result<uint32_t> r) { opened.set_value(std::move(r)); });
    const auto handle = opened.get_future().get();
    if (handle.is_bad())
      return handle.status_code();
    std::promise<VoidResult> written;
    mTrustList->write_async(mSessionA,
      handle.value(),
      encode_u5_trust_list(trustList),
      [&written](VoidResult r) { written.set_value(std::move(r)); });
    if (auto w = written.get_future().get(); w.is_bad())
      return w.status_code();
    std::promise<Result<bool>> updated;
    mTrustList->close_and_update_async(
      mSessionA, handle.value(), [&updated](Result<bool> r) { updated.set_value(std::move(r)); });
    return updated.get_future().get();
  }

  std::optional<ua::detail::TrustListContent> staged_application_lists()
  {
    std::promise<std::optional<ua::detail::TrustListContent>> p;
    mTrustList->staged_lists_async(
      [&p](std::optional<ua::detail::TrustListContent> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  CertificatePushServiceTrustListEffectTest()
  {
    mStageTrustListUntilApply = true;
    mTrustListModifiedCallback = [this](NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
    {
      if (mPushService)
        mPushService->on_trust_list_modified(std::move(sessionId),
          NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList},
          std::move(claim));
    };
  }
};
}  // namespace

// OPC 10000-12 sections 7.8.2.3 and 7.10.6: an applied update that drops a trusted certificate has every open
// channel and session re-evaluate, so none authenticated by a certificate that is no longer trusted survives
// it. RATIFIED (owner decision 2026-10-03, BR-13): the update is staged until ApplyChanges, and re-evaluation
// (which closes only the affected channels) replaces closing every channel.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-25-TRUST-LIST-CLOSES-CHANNELS, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, ApplyingAnUpdateThatRemovesTrustClosesTheChannels)
{
  std::promise<Result<uint32_t>> opened;
  mTrustList->open_async(mSessionA, 0x06, [&opened](Result<uint32_t> r) { opened.set_value(std::move(r)); });
  const auto handle = opened.get_future().get();
  ASSERT_TRUE(handle.is_good());

  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // TrustedCertificates, now empty: the CA is no longer trusted
  std::promise<VoidResult> written;
  mTrustList->write_async(mSessionA,
    handle.value(),
    encode_u5_trust_list(trustList),
    [&written](VoidResult r) { written.set_value(std::move(r)); });
  ASSERT_TRUE(written.get_future().get().is_good());

  std::promise<Result<bool>> updated;
  mTrustList->close_and_update_async(
    mSessionA, handle.value(), [&updated](Result<bool> r) { updated.set_value(std::move(r)); });
  const auto update = updated.get_future().get();
  ASSERT_TRUE(update.is_good()) << describe_chain(update.status_code());
  EXPECT_TRUE(update.value()) << "applyChangesRequired: the change takes effect at ApplyChanges";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u) << "staged: the store keeps the CA until ApplyChanges";
  EXPECT_EQ(mReevaluationHookCount, 0u);

  const auto applied = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applied.is_good()) << describe_chain(applied.status_code());
  std::promise<void> drain;
  boost::asio::post(mPool.get_executor(), [&drain]() { drain.set_value(); });
  drain.get_future().get();
  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "ApplyChanges writes the staged list";
  EXPECT_EQ(mReevaluationHookCount, 1u)
    << "the applied trust-list change re-evaluates every channel and session";
  EXPECT_EQ(mChannelCloseHookCount, 0u) << "no new Server Certificate: channels still trusted stay open";
}

// OPC 10000-12 7.10.8 / 7.10.1: CancelChanges discards the staged TrustList; the store keeps its lists.
// Falsifiable: the former server wrote the store at CloseAndUpdate, so a cancel left the change in force.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, CancelChangesDiscardsTheStagedTrustList)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // the CA is no longer trusted
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  ASSERT_TRUE(staged_application_lists().has_value());

  ASSERT_TRUE(cancel_changes_sync(mSessionA).is_good());

  EXPECT_FALSE(staged_application_lists().has_value());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mCaCert);
  EXPECT_EQ(apply_changes_sync(mSessionA).status_code(), StatusCode{Status::BadNothingToDo});
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mReevaluationHookCount, 0u);
}

// A CloseAndUpdate whose transaction cannot be recorded (its Session is gone by the time the push service
// hears of it) is discarded: nothing would ever apply or cancel it (review BR-13).
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, AStagedChangeNoTransactionTakesOverIsDiscarded)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  ASSERT_TRUE(staged_application_lists().has_value());

  mark_session_gone(mSessionB);
  mPushService->on_trust_list_modified(
    mSessionB, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
  (void)get_rejected_list_sync();  // a barrier on the service strand, which posted the discard
  EXPECT_TRUE(staged_application_lists().has_value()) << "another Session's lists are not touched";

  mark_session_gone(mSessionA);
  mPushService->on_trust_list_modified(
    mSessionA, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
  (void)get_rejected_list_sync();
  EXPECT_FALSE(staged_application_lists().has_value());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
}

// While ApplyChanges writes the TrustLists its transaction staged, no TrustList modification may stage over
// them or write the store under them - not another Session's CloseAndUpdate, not an AddCertificate (review
// BR-13: the former frame released the gate before writing, so such a change was written by, or lost to,
// this ApplyChanges). Observed inside the re-evaluation hook, which runs before ApplyChanges completes.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, TheTrustListGateIsClosedUntilApplyChangesCompletes)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  std::optional<StatusCode> otherSession;
  std::optional<StatusCode> immediate;
  mDuringReevaluation = [&]
  {
    otherSession = mPushService->claim_trust_list_modification(mSessionB).status_code();
    immediate = mPushService->claim_immediate_trust_list_modification(mSessionA).status_code();
  };

  ASSERT_TRUE(apply_changes_sync(mSessionA).is_good());

  ASSERT_TRUE(otherSession.has_value());
  EXPECT_EQ(*otherSession, StatusCode{Status::BadTransactionPending});
  ASSERT_TRUE(immediate.has_value());
  EXPECT_EQ(*immediate, StatusCode{Status::BadTransactionPending});
  EXPECT_TRUE(mPushService->claim_trust_list_modification(mSessionB).is_good()) << "open again once applied";
  EXPECT_TRUE(mPushService->claim_immediate_trust_list_modification(mSessionA).is_good());
}

// ResetToServerDefaults clears through the TrustListManager, the only writer of its lists: the lists a
// transaction staged are dropped too, so nothing is written back after the reset. Falsifiable: a reset that
// writes the store directly leaves them staged.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(CertificatePushServiceTrustListEffectTest, TheResetClearsThroughTheTrustListAndDropsTheStagedLists)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  ASSERT_TRUE(staged_application_lists().has_value());

  std::promise<VoidResult> reset;
  mPushService->reset_to_server_defaults_async(
    mSessionA, [&reset](VoidResult r) { reset.set_value(std::move(r)); });
  auto resetFuture = reset.get_future();
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(resetFuture.get().is_good());

  EXPECT_FALSE(staged_application_lists().has_value()) << "the staged lists went with the reset";
  EXPECT_TRUE(mFakeStore->trustedCerts.empty());
  EXPECT_TRUE(mFakeStore->issuerCerts.empty());
  EXPECT_EQ(mShutdownRequestCount.load(), 1);
}

// Part 12 7.10.10: a TrustList clear that fails does not prevent the shutdown, and the answer says it failed
// instead of Good (owner decision Q4). Falsifiable: the former reset answered Good whatever the clear did.
// @verifies AC-SVR-PULLCRT-040-B-THE-RESET-ALWAYS-SHUTS-DOWN-AND-ANSWERS-WHETHER-IT-CLEARED
TEST_F(CertificatePushServiceTrustListEffectTest, AResetWhoseClearFailsAnswersTheFailureAndStillShutsDown)
{
  const StatusCode refused{Status::BadResourceUnavailable};
  mFakeStore->replaceTrustedCertificateResults.push_back(VoidResult{refused});

  std::promise<VoidResult> reset;
  mPushService->reset_to_server_defaults_async(
    mSessionA, [&reset](VoidResult r) { reset.set_value(std::move(r)); });
  auto resetFuture = reset.get_future();
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(resetFuture.get().status_code(), refused);
  EXPECT_EQ(mShutdownRequestCount.load(), 1) << "the shutdown is requested anyway";
}

class CertificatePushServiceLostValidationTest : public CertificatePushServiceTrustListEffectTest
{
public:
  CertificatePushServiceLostValidationTest()
  {
    mUseFakeAsyncCrypto = true;
  }
};

// An ApplyChanges that took its transaction and then never completes (a certificate validation lost here)
// still drops the lists the transaction staged: nothing else would, and they would refuse AddCertificate and
// RemoveCertificate with Bad_TransactionPending meanwhile. Falsifiable: the former frame dropped them only on
// the outcomes it handled.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(CertificatePushServiceLostValidationTest, AnApplyChangesThatIsLostAfterTheTakeDropsItsStagedLists)
{
  ASSERT_TRUE(
    start_update_certificate(mSessionA, create_valid_leaf(mLeafKeys)->der_encoding()).result.get().is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  trustList.trusted_certificates().push_back(mCaCert->der_encoding());
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  ASSERT_TRUE(staged_application_lists().has_value());

  mFakeCrypto->set_park_async(true);
  mPushService->apply_changes_async(mSessionA, server::MethodResponseCorrelation{1, 7}, [](VoidResult) {});
  const auto parked = std::chrono::steady_clock::now() + 5s;
  while (mFakeCrypto->pending_validate_certificate_count() == 0 && std::chrono::steady_clock::now() < parked)
    std::this_thread::sleep_for(1ms);
  ASSERT_EQ(mFakeCrypto->pending_validate_certificate_count(), 1u) << "ApplyChanges took the transaction";
  mFakeCrypto->set_park_async(false);
  mFakeCrypto->drop_pending_validate_certificate();

  const auto dropped = std::chrono::steady_clock::now() + 5s;
  while (staged_application_lists().has_value() && std::chrono::steady_clock::now() < dropped)
    std::this_thread::sleep_for(1ms);
  EXPECT_FALSE(staged_application_lists().has_value());
}

class CertificatePushServiceResetDeadlineTest : public CertificatePushServiceTrustListEffectTest
{
public:
  CertificatePushServiceResetDeadlineTest()
  {
    mResetDeadline = 300ms;
  }
};

// Part 12 7.10.10: a clear that does not end by the reset deadline (its store write parked here) does not
// hold back the shutdown: at the deadline the shutdown is requested and the reset answers Bad_Timeout. The
// clear ending later neither answers again nor requests a second shutdown. Falsifiable: the former reset
// waited for the clear without limit, so neither happened.
// @verifies AC-SVR-PULLCRT-040-B-THE-RESET-ALWAYS-SHUTS-DOWN-AND-ANSWERS-WHETHER-IT-CLEARED
TEST_F(CertificatePushServiceResetDeadlineTest, AResetWhoseClearDoesNotEndAnswersBadTimeoutAndShutsDown)
{
  mFakeStore->parkReplaceTrusted = true;
  std::atomic<int> answers{0};
  auto reset = std::make_shared<std::promise<VoidResult>>();
  mPushService->reset_to_server_defaults_async(mSessionA,
    [reset, &answers](VoidResult r)
    {
      if (answers.fetch_add(1) == 0)
        reset->set_value(std::move(r));
    });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!mFakeStore->replaceTrustedIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_TRUE(mFakeStore->replaceTrustedIsParked.load()) << "the clear is writing the store";

  auto resetFuture = reset->get_future();
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);
  const auto answer = resetFuture.get();
  EXPECT_EQ(answer.status_code(), StatusCode{Status::BadTimeout});
  ASSERT_NE(answer.shared_detail(), nullptr);
  EXPECT_EQ(answer.shared_detail()->code, "ResetToServerDefaultsTimedOut");
  EXPECT_EQ(mShutdownRequestCount.load(), 1);

  mFakeStore->release_parked_replace_trusted();
  (void)staged_application_lists();  // a barrier on the manager's strand, where the clear ends
  (void)get_rejected_list_sync();  // and on the service strand, where a late finish would run
  (void)get_rejected_list_sync();
  EXPECT_EQ(answers.load(), 1) << "answered once (by construction: the answer is fire-once)";
  EXPECT_EQ(mShutdownRequestCount.load(), 1) << "one shutdown request";
}

// A CloseAndUpdate of the transaction still in flight when ApplyChanges takes the transaction (it began after
// the write-state preflight) would stage lists the apply does not verify: ApplyChanges is refused with
// Bad_InvalidState before anything is committed, and the transaction is kept. Falsifiable: the former apply
// went ahead and could install unverified lists.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(CertificatePushServiceTrustListEffectTest, ApplyChangesIsRefusedWhileATrustListModificationIsInFlight)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  auto inFlight = mPushService->claim_trust_list_modification(mSessionA);  // the owner's next CloseAndUpdate
  ASSERT_TRUE(inFlight.is_good());

  const auto refused = apply_changes_sync(mSessionA);

  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "TrustListModificationInProgress");
  EXPECT_TRUE(staged_application_lists().has_value()) << "the transaction is kept";
  inFlight = std::shared_ptr<TrustListModificationClaim>{};  // the modification ends
  const auto applied = apply_changes_sync(mSessionA, 2);
  EXPECT_TRUE(applied.is_good()) << "applied once the modification has ended: "
                                 << describe_chain(applied.status_code());
}

// A TrustList the store refuses to write fails ApplyChanges, but what reached the store before is in force,
// so the open channels and Sessions are still re-evaluated, and nothing stays staged (review BR-13).
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, AStoreRefusingTheWriteStillReevaluatesAndDiscards)
{
  const StatusCode refused{Status::BadResourceUnavailable,
    make_error_detail("TrustListWriteRefused", "The store refused the write", "Test")};
  mFakeStore->replaceTrustedCertificateResults.emplace_back(refused);
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());

  const auto applied = apply_changes_sync(mSessionA);

  ASSERT_TRUE(applied.is_bad());
  EXPECT_EQ(applied.status_code().value(), refused.value());
  EXPECT_EQ(mReevaluationHookCount, 1u) << "the change that may have reached the store is re-evaluated";
  EXPECT_FALSE(staged_application_lists().has_value());
  EXPECT_TRUE(mPushService->claim_trust_list_modification(mSessionB).is_good()) << "the gate is open again";
}

// 7.10.6: "If a Session is closed or abandoned then the transaction is closed and all pending changes are
// discarded."
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, TheOwnersSessionClosingDiscardsTheStagedTrustList)
{
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  ASSERT_TRUE(staged_application_lists().has_value());

  mPushService->on_session_closed_async(mSessionA);
  (void)cancel_changes_sync(mSessionB);  // queued behind the close on the service strand: a barrier

  EXPECT_FALSE(staged_application_lists().has_value());
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mCaCert);
}

// 7.10.1: ApplyChanges "verifies that all the changes are consistent". A Server Certificate pushed in the
// same transaction as a TrustList that adds its CA is validated against the TrustList the transaction
// installs - at UpdateCertificate and at ApplyChanges (the order is not specified; owner report 2026-10-03,
// BR-13). Falsifiable: validated against the store, which does not trust the CA, both calls fail.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, APushedCertificateMayChainToACaStagedInTheSameTransaction)
{
  mFakeStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};  // the store's verdict
  const auto newCert = create_valid_leaf(mLeafKeys);
  ASSERT_TRUE(update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{})
                .is_bad())
    << "control: against the store the CA is not trusted";

  TrustListDataType trustList;
  trustList.specified_lists() = 0x03;  // the CA and its CRL are trusted
  trustList.trusted_certificates().push_back(mCaCert->der_encoding());
  trustList.trusted_crls().push_back(mPki->create_crl(mCaCert, mCaKeys, {})->der_encoding());
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  const auto updated = update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{});
  ASSERT_TRUE(updated.is_good()) << describe_chain(updated.status_code());
  const auto appCertsBefore = mFakeStore->appCerts.size();

  const auto applied = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applied.is_good()) << describe_chain(applied.status_code());
  EXPECT_GT(mFakeStore->appCerts.size(), appCertsBefore) << "the certificate is installed";
  ASSERT_EQ(mFakeStore->trustedCrls.size(), 1u) << "and the TrustList written";
}

// 7.10.1: "If any errors are found then all changes are discarded": a pushed certificate the staged TrustList
// no longer trusts fails ApplyChanges, and the TrustList is not written either.
// @relation(AC-SVR-PULLCRT-037-A-CLOSEANDUPDATE-IS-STAGED-UNTIL-APPLYCHANGES, scope=function)
TEST_F(CertificatePushServiceTrustListEffectTest, AnApplyThatFailsVerificationDiscardsTheStagedTrustList)
{
  const auto newCert = create_valid_leaf(mLeafKeys);
  ASSERT_TRUE(update_certificate_sync(mSessionA,
    mNullGroupId,
    mRsaSha256TypeId,
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{},
    ByteString{})
                .is_good());
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // the CA is no longer trusted
  ASSERT_TRUE(stage_trust_list(trustList).is_good());
  const auto appCertsBefore = mFakeStore->appCerts.size();

  const auto applied = apply_changes_sync(mSessionA);
  ASSERT_TRUE(applied.is_bad());
  EXPECT_EQ(applied.status_code().as_status(), Status::BadSecurityChecksFailed);
  EXPECT_FALSE(staged_application_lists().has_value()) << "the staged TrustList is discarded";
  ASSERT_EQ(mFakeStore->trustedCerts.size(), 1u);
  EXPECT_EQ(mFakeStore->trustedCerts[0], mCaCert);
  EXPECT_EQ(mFakeStore->appCerts.size(), appCertsBefore);
  EXPECT_EQ(mReevaluationHookCount, 0u);
}
