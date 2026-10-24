// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_channel_bound_signature_data.h"
#include "ua_crypto.h"
#include "ua_to_string.h"

#include "fake_async_crypto.h"
#include "run_async_sync.h"
#include "integration/helpers/sanitizer_budget.h"
#include "unit/security/sce_vector_helpers.h"
#include "unit/security/sce_vectors.h"

#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>

namespace
{

using namespace ua;
namespace sd = ua::test::sce_vectors::signature_data;
using ua::test::sce_vectors::hex_bytes;

ChannelBoundSignatureInputs vector_inputs()
{
  return ChannelBoundSignatureInputs{.channelThumbprint = hex_bytes(sd::thumbprint),
    .clientNonce = hex_bytes(sd::clientNonce),
    .serverNonce = hex_bytes(sd::serverNonce),
    .serverCertificate = hex_bytes(sd::serverCert),
    .serverChannelCertificate = hex_bytes(sd::serverChannelCert),
    .clientCertificate = hex_bytes(sd::clientCert),
    .clientChannelCertificate = hex_bytes(sd::clientChannelCert)};
}

class ChannelBoundSignatureData : public ::testing::Test
{
protected:
  ByteStringResult build(ChannelBoundSignature signature, HashAlgorithm hash,
    ChannelBoundSignatureInputs inputs, shared_ptr<const Crypto> crypto = nullptr)
  {
    if (!crypto)
      crypto = create_default_crypto([]() { return ua::SecureString{""}; });
    return ua::test_helpers::run_async_function_sync<ByteStringResult>(
      [&](auto callback)
      {
        build_channel_bound_signature_data_async(signature,
          hash,
          std::move(crypto),
          boost::asio::make_strand(mPool.get_executor()),
          ua::Logger{},
          std::move(inputs),
          std::move(callback));
      });
  }

  boost::asio::thread_pool mPool{1};
};

// Each Table 101 row, for a SHA-256 and a SHA-384 CertificateThumbprintAlgorithm, matches the vector computed
// outside the SDK (with Python `cryptography`). The server application and channel
// certificates differ, so a row that hashed one for the other would not match; HASH covers the bytes as
// given.
// @relation(AC-SVR-SCE-010-SIGNATURE-DATA, scope=function)
// @relation(AC-COMP-ECC-CHANNEL-BOUND-DATA-ANSWERS-ONCE, scope=function)
TEST_F(ChannelBoundSignatureData, EveryLayoutMatchesTable101)
{
  struct Row
  {
    ChannelBoundSignature signature;
    HashAlgorithm hash;
    std::string_view expected;
    const char* name;
  };

  const std::vector<Row> rows{
    {ChannelBoundSignature::Server, HashAlgorithm::Sha2256, sd::sha256ServerSignature, "Sha256 Server"},
    {ChannelBoundSignature::Client, HashAlgorithm::Sha2256, sd::sha256ClientSignature, "Sha256 Client"},
    {ChannelBoundSignature::UserToken,
      HashAlgorithm::Sha2256,
      sd::sha256UserTokenSignature,
      "Sha256 UserToken"},
    {ChannelBoundSignature::UserTokenOverNone,
      HashAlgorithm::Sha2256,
      sd::sha256UserTokenSignatureNone,
      "Sha256 UserTokenOverNone"},
    {ChannelBoundSignature::Server, HashAlgorithm::Sha2384, sd::sha384ServerSignature, "Sha384 Server"},
    {ChannelBoundSignature::Client, HashAlgorithm::Sha2384, sd::sha384ClientSignature, "Sha384 Client"},
    {ChannelBoundSignature::UserToken,
      HashAlgorithm::Sha2384,
      sd::sha384UserTokenSignature,
      "Sha384 UserToken"},
    {ChannelBoundSignature::UserTokenOverNone,
      HashAlgorithm::Sha2384,
      sd::sha384UserTokenSignatureNone,
      "Sha384 UserTokenOverNone"},
  };
  for (const auto& row : rows)
  {
    SCOPED_TRACE(row.name);
    const auto data = build(row.signature, row.hash, vector_inputs());
    ASSERT_TRUE(data.is_good()) << to_string(data.status_code().as_status());
    EXPECT_EQ(data.value(), hex_bytes(row.expected));
  }
}

// "If the Certificate argument is null or empty, function returns a OctetString with 0 length": an empty
// client channel certificate contributes nothing, and the fields either side of it are unchanged.
// @relation(AC-SVR-SCE-010-SIGNATURE-DATA, scope=function)
TEST_F(ChannelBoundSignatureData, AnEmptyCertificateHashesToNothing)
{
  auto inputs = vector_inputs();
  inputs.clientChannelCertificate = ByteString{};
  const auto data = build(ChannelBoundSignature::Client, HashAlgorithm::Sha2256, std::move(inputs));
  ASSERT_TRUE(data.is_good()) << to_string(data.status_code().as_status());
  EXPECT_EQ(data.value(), hex_bytes(sd::sha256ClientSignatureWithEmptyClientChannelCert));
}

// A digest the Crypto provider fails ends the build with that status, answered once; no partial data is
// answered and no further digest is asked for.
// @relation(AC-COMP-ECC-CHANNEL-BOUND-DATA-ANSWERS-ONCE, scope=function)
TEST_F(ChannelBoundSignatureData, AFailedCertificateHashAnswersItsStatus)
{
  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  crypto->set_park_async(true);
  std::optional<ByteStringResult> answered;
  int answers = 0;
  std::mutex mutex;
  build_channel_bound_signature_data_async(ChannelBoundSignature::Server,
    HashAlgorithm::Sha2256,
    crypto,
    boost::asio::make_strand(mPool.get_executor()),
    ua::Logger{},
    vector_inputs(),
    [&](ByteStringResult result)
    {
      const std::lock_guard lock{mutex};
      ++answers;
      answered = std::move(result);
    });
  const auto deadline =
    std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{2000});
  while (crypto->pending_calculate_digest_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(crypto->pending_calculate_digest_count(), 1u) << "the server channel certificate was not hashed";
  crypto->complete_pending_calculate_digest(0,
    Crypto::CalculateDigestOutputResult{
      StatusCode{Status::BadNotSupported}, make_error_detail("Test", "digest refused", "Test")});
  while (std::chrono::steady_clock::now() < deadline)
  {
    {
      const std::lock_guard lock{mutex};
      if (answered)
        break;
    }
    std::this_thread::yield();
  }
  // Long enough for a second answer or a further digest request to show.
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  const std::lock_guard lock{mutex};
  ASSERT_TRUE(answered.has_value()) << "the build never answered";
  EXPECT_EQ(answers, 1);
  EXPECT_EQ(answered->status_code().as_status(), Status::BadNotSupported);
  EXPECT_EQ(crypto->pending_calculate_digest_count(), 0u) << "the build went on after the failed digest";
}

// A digest the Crypto provider answers Uncertain is not used, with or without a digest: the build answers
// Bad_InternalError with the CryptoAnswerUncertain ErrorDetail whose inner status is the Uncertain code,
// once, and asks for no further digest.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(ChannelBoundSignatureData, AnUncertainCertificateHashIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const Crypto::CalculateDigestOutput digest{ByteString{}, ByteString(32, 0x5A)};
  for (const bool withDigest : {false, true})
  {
    SCOPED_TRACE(withDigest ? "the answer holds a digest" : "the answer holds no digest");
    auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
    crypto->set_park_async(true);
    std::optional<ByteStringResult> answered;
    int answers = 0;
    std::mutex mutex;
    build_channel_bound_signature_data_async(ChannelBoundSignature::Server,
      HashAlgorithm::Sha2256,
      crypto,
      boost::asio::make_strand(mPool.get_executor()),
      ua::Logger{},
      vector_inputs(),
      [&](ByteStringResult result)
      {
        const std::lock_guard lock{mutex};
        ++answers;
        answered = std::move(result);
      });
    const auto deadline =
      std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{2000});
    while (crypto->pending_calculate_digest_count() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    ASSERT_EQ(crypto->pending_calculate_digest_count(), 1u)
      << "the server channel certificate was not hashed";
    crypto->complete_pending_calculate_digest(0,
      withDigest ? Crypto::CalculateDigestOutputResult{digest, uncertain}
                 : Crypto::CalculateDigestOutputResult{uncertain});
    while (std::chrono::steady_clock::now() < deadline)
    {
      {
        const std::lock_guard lock{mutex};
        if (answered)
          break;
      }
      std::this_thread::yield();
    }
    // Long enough for a second answer or a further digest request to show.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    const std::lock_guard lock{mutex};
    ASSERT_TRUE(answered.has_value()) << "the build never answered";
    EXPECT_EQ(answers, 1);
    EXPECT_EQ(answered->status_code().as_status(), Status::BadInternalError)
      << to_string(answered->status_code().as_status());
    ASSERT_NE(answered->shared_detail(), nullptr);
    EXPECT_EQ(answered->shared_detail()->code, "CryptoAnswerUncertain");
    EXPECT_EQ(answered->shared_detail()->innerStatus, uncertain.value());
    EXPECT_EQ(crypto->pending_calculate_digest_count(), 0u) << "the build went on after the Uncertain digest";
  }
}

// A callback that throws is not answered again: the exception ends the build, and the failure it is turned
// into finds the callback already answered - both when the build runs and when it is refused before it starts
// (no Crypto provider).
// @relation(AC-COMP-ECC-CHANNEL-BOUND-DATA-ANSWERS-ONCE, scope=function)
TEST_F(ChannelBoundSignatureData, ACallbackThatThrowsIsNotAnsweredAgain)
{
  for (const bool withCrypto : {true, false})
  {
    SCOPED_TRACE(withCrypto ? "the build runs" : "the build is refused before it starts");
    auto answers = std::make_shared<std::atomic<int>>(0);
    try
    {
      build_channel_bound_signature_data_async(ChannelBoundSignature::Server,
        HashAlgorithm::Sha2256,
        withCrypto ? create_default_crypto([]() { return ua::SecureString{""}; }) : nullptr,
        boost::asio::make_strand(mPool.get_executor()),
        ua::Logger{},
        vector_inputs(),
        [answers](ByteStringResult)
        {
          if (answers->fetch_add(1) == 0)
            throw std::runtime_error{"the caller's continuation failed"};
        });
    }
    catch (...)
    {
      ADD_FAILURE() << "the callback's exception escaped the builder";
    }
    const auto deadline =
      std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{2000});
    while (answers->load() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    // Long enough for a second answer to show.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_EQ(answers->load(), 1);
  }
}

}  // namespace
