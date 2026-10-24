// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_user_token_encryption.h"
#include "ua_security_policy_internal.h"
#include "ua_secure_memory.h"

#include "ua_crypto.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_ecc_encrypted_secret_encoder.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_issued_identity_token.h"
#include "ua_rsa_encrypted_secret_encoder.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_security_policy.h"
#include "ua_security_policy_compatibility.h"
#include "ua_to_result.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstring>

namespace ua
{

namespace
{

// RSA path: encrypt the Legacy UserIdentityToken secret (Part 4 7.41.2.2, Table 186):
// `Length(4 LE) || tokenData || serverNonce`, built by build_legacy_encrypted_token_plaintext,
// with the server's public key. The server-side decoder
// (`ua_server_session.cpp::parse_identity_token_async` via parse_legacy_encrypted_token_secret)
// recovers the password from this format.
class EncryptRsaUserTokenOperation final : public ua::async::SelfOwningOperation<EncryptRsaUserTokenOperation>
{
public:
  EncryptRsaUserTokenOperation(const EncryptRsaUserTokenOperation&) = delete;
  EncryptRsaUserTokenOperation& operator=(const EncryptRsaUserTokenOperation&) = delete;
  EncryptRsaUserTokenOperation(EncryptRsaUserTokenOperation&&) = delete;
  EncryptRsaUserTokenOperation& operator=(EncryptRsaUserTokenOperation&&) = delete;

  /// DEF-4: the decrypted and derived secret bytes are scrubbed when the flow ends, whichever way.
  ~EncryptRsaUserTokenOperation()
  {
    ua::security::secure_clear(mPlainText);
  }

  /// Builds the operation and starts it on @p strand. The plaintext and the sized cipher buffer are
  /// built by the caller, which is also where the server nonce is consumed - it is part of the
  /// plaintext (Part 4 7.41.2.2) and nothing after that point needs it.
  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<UserNameIdentityToken> token, shared_ptr<const X509Certificate> serverCertificate,
    ByteString plainText, ByteString cipherText, size_t plainTextBlockSize, size_t cipherTextBlockSize,
    std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncryptRsaUserTokenOperation>(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(token),
      std::move(serverCertificate),
      std::move(plainText),
      std::move(cipherText),
      plainTextBlockSize,
      cipherTextBlockSize,
      std::move(callback)));
  }

  EncryptRsaUserTokenOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<UserNameIdentityToken> token, shared_ptr<const X509Certificate> serverCertificate,
    ByteString plainText, ByteString cipherText, size_t plainTextBlockSize, size_t cipherTextBlockSize,
    std::function<void(VoidResult)> callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mPolicy(std::move(policy)),
      mCrypto(std::move(crypto)), mToken(std::move(token)), mServerCertificate(std::move(serverCertificate)),
      mPlainText(std::move(plainText)), mCipherText(std::move(cipherText)),
      mPlainTextBlockSize(plainTextBlockSize), mCipherTextBlockSize(cipherTextBlockSize),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncryptRsaUserTokenOperation>;

  /// One asymmetric encryption per PlainTextBlockSize block of the plaintext (OPC 10000-6 6.7.2), then the
  /// token carries the ciphertext. A 64-byte password with a 128-byte serverNonce is 196 bytes, more than
  /// one RSA-OAEP-SHA256 block of a 2048-bit key. `await_step` hands the collaborator a fire-once
  /// completion, so a second delivery of a block's result is ignored structurally.
  ua::async::Task<> run()
  {
    try
    {
      const span<const byte> plainText{mPlainText};
      const span<byte> cipherText{mCipherText};
      // The caller refuses a zero PlainTextBlockSize and sized the ciphertext for this many blocks.
      const size_t blocks = (plainText.size() + mPlainTextBlockSize - 1) / mPlainTextBlockSize;
      for (size_t block = 0; block < blocks; ++block)
      {
        const size_t offset = block * mPlainTextBlockSize;
        auto result = co_await await_step<VoidResult>(
          [&](auto completion)
          {
            mCrypto->asymmetric_encrypt_async(nullptr,
              mPolicy->asymmetric_encryption_algorithm(),
              mServerCertificate->public_key(),
              plainText.subspan(offset, std::min(mPlainTextBlockSize, plainText.size() - offset)),
              cipherText.subspan(block * mCipherTextBlockSize, mCipherTextBlockSize),
              std::move(completion));
          });
        if (!result.is_good())
        {
          answer(VoidResult{ua::security_internal::not_good_answer(
            result.status_code(), Status::BadInternalError, "encrypt_rsa_user_token")});
          co_return;
        }
      }

      mToken->password() = std::move(mCipherText);
      mToken->encryption_algorithm() =
        asymmetric_encryption_algorithm_uri(mPolicy->asymmetric_encryption_algorithm());
      answer(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      // A root task: nobody awaits this, so an escaping exception would be stored in a promise
      // nobody reads and the caller would wait for an answer that never came.
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(VoidResult{failure, failure.shared_detail()}); })();
    }
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(VoidResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<UserNameIdentityToken> mToken;
  shared_ptr<const X509Certificate> mServerCertificate;
  ByteString mPlainText;
  ByteString mCipherText;
  size_t mPlainTextBlockSize;
  size_t mCipherTextBlockSize;
  std::function<void(VoidResult)> mCallback;
};

// OPC 10000-4 7.40.4: a password in the legacy format "shall not exceed 64 bytes".
constexpr size_t maximumLegacyPasswordSize = 64;

// The longest legacy plaintext: Length(4) || password(64) || serverNonce(128, OPC 10000-4 1.05.07 5.7.2).
// It bounds the number of blocks a receiver decrypts, so a secret of many valid blocks costs one size check
// rather than one private-key operation per block.
constexpr size_t maximumLegacySecretPlainTextSize =
  4 + maximumLegacyPasswordSize + stack_utils::maximumSessionNonceLength;

// The decrypt twin of EncryptRsaUserTokenOperation: one asymmetric decryption per ciphertext block, the
// recovered blocks appended in order.
class DecryptLegacyTokenSecretOperation final
  : public ua::async::SelfOwningOperation<DecryptLegacyTokenSecretOperation>
{
public:
  using Callback = std::function<void(Result<span<const byte>>)>;

  /// Builds the operation and starts it on @p strand. The caller keeps @p cipherText and @p plainText
  /// alive until the callback.
  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const AsymmetricKeyPair> keys, size_t cipherTextBlockSize, span<const byte> cipherText,
    span<byte> plainText, Callback callback)
  {
    launch(std::make_shared<DecryptLegacyTokenSecretOperation>(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(keys),
      cipherTextBlockSize,
      cipherText,
      plainText,
      std::move(callback)));
  }

  DecryptLegacyTokenSecretOperation(boost::asio::strand<boost::asio::any_io_executor> strand,
    ua::Logger logger, shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const AsymmetricKeyPair> keys, size_t cipherTextBlockSize, span<const byte> cipherText,
    span<byte> plainText, Callback callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mPolicy(std::move(policy)),
      mCrypto(std::move(crypto)), mKeys(std::move(keys)), mCipherTextBlockSize(cipherTextBlockSize),
      mCipherText(cipherText), mPlainText(plainText), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecryptLegacyTokenSecretOperation>;

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(Result<span<const byte>>{status, status.shared_detail()});
  }

  ua::async::Task<> run()
  {
    try
    {
      size_t recovered = 0;
      const size_t blocks = mCipherText.size() / mCipherTextBlockSize;
      for (size_t block = 0; block < blocks; ++block)
      {
        auto result = co_await await_step<Crypto::ByteSpanResult>(
          [&](auto completion)
          {
            mCrypto->asymmetric_decrypt_async(nullptr,
              mPolicy->asymmetric_encryption_algorithm(),
              mKeys,
              mCipherText.subspan(block * mCipherTextBlockSize, mCipherTextBlockSize),
              mPlainText.subspan(recovered),
              std::move(completion));
          });
        if (!result.is_good())
        {
          // The blocks already recovered hold the start of the password.
          ua::security::secure_zero(mPlainText.data(), recovered);
          answer(Result<span<const byte>>{ua::security_internal::not_good_answer(
            result.status_code(), Status::BadInternalError, "decrypt_legacy_token_secret")});
          co_return;
        }
        recovered += result.value().size();
      }
      answer(Result<span<const byte>>{span<const byte>{mPlainText.first(recovered)}});
    }
    catch (const ua::async::Abandoned&)
    {
      // A root task that was withdrawn does nothing (ua_coro.h); nothing in this file withdraws it.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(
        mLogger, [&] { answer(Result<span<const byte>>{failure, failure.shared_detail()}); })();
    }
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(Result<span<const byte>> result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<const AsymmetricKeyPair> mKeys;
  size_t mCipherTextBlockSize;
  span<const byte> mCipherText;
  span<byte> mPlainText;
  Callback mCallback;
};

// encrypt_rsa_user_token: build the plaintext (Length || password || serverNonce) and size the cipher
// buffer here, one ciphertext block per plaintext block, then hand both to the body that encrypts them.
void encrypt_rsa_user_token_async(shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
  boost::asio::strand<boost::asio::any_io_executor> strand, shared_ptr<UserNameIdentityToken> token,
  ByteString serverNonce, shared_ptr<const X509Certificate> serverCertificate, ua::Logger logger,
  std::function<void(VoidResult)> callback)
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    if (!serverCertificate)
    {
      callback(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
        make_error_detail(
          "BadSecurityChecksFailed", "Server certificate is null", "encrypt_rsa_user_token")});
      return;
    }

    auto& password = token->password();

    ByteString plainText =
      build_legacy_encrypted_token_plaintext(span<const byte>{password}, span<const byte>{serverNonce});

    auto cipherTextBlockSize = policy->asymmetric_ciphertext_block_size(serverCertificate.get());
    auto plainTextBlockSize = policy->asymmetric_plaintext_block_size(serverCertificate.get());

    if (plainTextBlockSize == 0)
    {
      callback(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
        ErrorDetail::build(
          "BadSecurityChecksFailed", "Plaintext block size is zero", "encrypt_rsa_user_token")
          .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
      return;
    }

    auto numBlocks = (plainText.size() + plainTextBlockSize - 1) / plainTextBlockSize;
    ByteString cipherText;
    cipherText.resize(numBlocks * cipherTextBlockSize);

    started = true;
    EncryptRsaUserTokenOperation::start(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(token),
      std::move(serverCertificate),
      std::move(plainText),
      std::move(cipherText),
      plainTextBlockSize,
      cipherTextBlockSize,
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    if (!started && callback)
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

}  // namespace

void decrypt_legacy_token_secret_async(shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const AsymmetricKeyPair> keys, size_t plainTextBlockSize, size_t cipherTextBlockSize,
  span<const byte> cipherText, span<byte> plainText, ua::Logger logger,
  std::function<void(Result<span<const byte>>)> callback)
{
  const bool wholeBlocks = plainTextBlockSize != 0 && cipherTextBlockSize != 0 && !cipherText.empty() &&
                           cipherText.size() % cipherTextBlockSize == 0 &&
                           plainText.size() >= cipherText.size();
  const size_t maximumBlocks =
    plainTextBlockSize == 0
      ? 0
      : (maximumLegacySecretPlainTextSize + plainTextBlockSize - 1) / plainTextBlockSize;
  if (!wholeBlocks || cipherText.size() / cipherTextBlockSize > maximumBlocks)
  {
    callback(Result<span<const byte>>{StatusCode{Status::BadDecodingError},
      ErrorDetail::build("LegacySecretBlocksInvalid",
        "The legacy encrypted secret is not a whole number of ciphertext blocks, or has more blocks than the "
        "longest legacy secret needs",
        "decrypt_legacy_token_secret")
        .context(ua::ContextKeys::sizeActual, std::to_string(cipherText.size()))
        .context(ua::ContextKeys::sizeBlock, std::to_string(cipherTextBlockSize))
        .context(ua::ContextKeys::sizeMax, std::to_string(maximumBlocks * cipherTextBlockSize))});
    return;
  }
  DecryptLegacyTokenSecretOperation::start(std::move(strand),
    std::move(logger),
    std::move(policy),
    std::move(crypto),
    std::move(keys),
    cipherTextBlockSize,
    cipherText,
    plainText,
    std::move(callback));
}

// encrypt_user_token flow (top-level dispatcher):
//   encrypt_user_token_async
//     -> [empty password? -> complete with VoidResult{}]
//     -> [ECC?]  -> encrypt_ecc_encrypted_secret_async
//                  -> on_user_token_ecc_complete  -> update token + complete | fail
//     -> [RSA?]  -> encrypt_rsa_user_token_async
//                  -> on_user_token_rsa_complete  -> complete | fail
//     -> [other policy] -> complete with VoidResult{}
void encrypt_user_token_async(shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
  boost::asio::strand<boost::asio::any_io_executor> strand, shared_ptr<UserNameIdentityToken> token,
  ByteString serverNonce, shared_ptr<const X509Certificate> serverCertificate,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ua::Logger logger,
  std::function<void(VoidResult)> callback)
{
  try
  {
    if (!policy || !crypto || !token)
    {
      callback(VoidResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("MissingDependency",
          "Null policy, crypto, or token passed to encrypt_user_token_async",
          "encrypt_user_token")});
      return;
    }

    if (token->password().empty())
    {
      callback(VoidResult{});
      return;
    }

    // Key agreement (ECC and RSA_DH): the secret is an EccEncryptedSecret (Part 4 section 7.40.2.3).
    if (policy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid)
    {
      auto eccPolicy = std::dynamic_pointer_cast<const SecPolEphemeralKey>(policy);
      if (!eccPolicy || serverEphemeralPublicKey.empty())
      {
        callback(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build("BadSecurityChecksFailed",
            "Ephemeral-key policy cast failed or server ephemeral key is empty",
            "encrypt_user_token")
            .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
        return;
      }

      auto policyUri = policy->uri();
      // Capture the password copy before moving token into the completion lambda - C++ does not
      // sequence sibling function-argument evaluations, so reading through `token` after a
      // `std::move(token)` argument is UB.
      ByteString passwordCopy{token->password()};

      encrypt_ecc_encrypted_secret_async(std::move(eccPolicy),
        std::move(crypto),
        std::move(strand),
        std::move(serverEphemeralPublicKey),
        std::move(clientCertificate),
        std::move(clientKeyPair),
        std::move(serverNonce),
        std::move(passwordCopy),
        logger,
        [token = std::move(token), policyUri = std::move(policyUri), callback = std::move(callback)](
          ByteStringResult result) mutable
        {
          if (!result.is_good())
          {
            callback(VoidResult{ua::security_internal::not_good_answer(
              result.status_code(), Status::BadInternalError, "encrypt_user_token")});
            return;
          }
          token->password() = std::move(result).value();
          token->encryption_algorithm() = std::move(policyUri);
          callback(VoidResult{});
        });
      return;
    }

    if (policy->is_rsa())
    {
      if (token->password().size() <= 64)
      {
        // Part 4 v1.05.07 section 7.40.4: RSA passwords of at most 64 UTF-8 bytes use
        // the legacy encrypted-secret form, independently of policy deprecation.
        encrypt_rsa_user_token_async(std::move(policy),
          std::move(crypto),
          std::move(strand),
          std::move(token),
          std::move(serverNonce),
          std::move(serverCertificate),
          std::move(logger),
          std::move(callback));
        return;
      }

      // Part 4 v1.05.07 section 7.40.4: longer RSA passwords use RsaEncryptedSecret.
      if (!serverCertificate)
      {
        callback(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("BadSecurityChecksFailed",
            "Server certificate is null for RsaEncryptedSecret user-token encryption",
            "encrypt_user_token")});
        return;
      }

      auto algorithmUri =
        std::string{asymmetric_encryption_algorithm_uri(policy->asymmetric_encryption_algorithm())};
      // Capture the password copy before moving token into the completion lambda - sibling
      // function-argument evaluations are unsequenced, so reading through `token` after a
      // std::move(token) argument would be UB (same guard as the ECC branch).
      ByteString passwordCopy{token->password()};

      encrypt_rsa_encrypted_secret_async(std::move(policy),
        std::move(crypto),
        std::move(strand),
        std::move(serverCertificate),
        std::move(serverNonce),
        std::move(passwordCopy),
        logger,
        [token = std::move(token), algorithmUri = std::move(algorithmUri), callback = std::move(callback)](
          ByteStringResult result) mutable
        {
          if (!result.is_good())
          {
            callback(VoidResult{ua::security_internal::not_good_answer(
              result.status_code(), Status::BadInternalError, "encrypt_user_token")});
            return;
          }
          token->password() = std::move(result).value();
          token->encryption_algorithm() = std::move(algorithmUri);
          callback(VoidResult{});
        });
      return;
    }

    callback(VoidResult{});
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(VoidResult{er, er.shared_detail()});
  }
}

void encrypt_issued_token_async(shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
  boost::asio::strand<boost::asio::any_io_executor> strand, shared_ptr<IssuedIdentityToken> token,
  ByteString serverNonce, shared_ptr<const X509Certificate> serverCertificate,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ua::Logger logger,
  std::function<void(VoidResult)> callback)
{
  auto complete = detail::make_fire_once<VoidResult>(std::move(callback));
  try
  {
    if (!policy || !crypto || !token)
    {
      complete(VoidResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("MissingDependency",
          "Null policy, crypto, or token passed to encrypt_issued_token_async",
          "encrypt_issued_token")});
      return;
    }

    if (token->token_data().empty())
    {
      token->encryption_algorithm().clear();
      complete(VoidResult{});
      return;
    }

    ByteString tokenData{token->token_data()};
    token->encryption_algorithm().clear();

    if (policy->ephemeral_key_algorithm() != EphemeralKeyAlgorithm::Invalid)
    {
      auto eccPolicy = std::dynamic_pointer_cast<const SecPolEphemeralKey>(policy);
      if (!eccPolicy || serverEphemeralPublicKey.empty())
      {
        complete(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build("IssuedTokenEccEncryptionUnavailable",
            "Ephemeral-key policy or server ephemeral key is unavailable for issued-token encryption",
            "encrypt_issued_token")
            .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
        return;
      }

      encrypt_ecc_encrypted_secret_async(std::move(eccPolicy),
        std::move(crypto),
        std::move(strand),
        std::move(serverEphemeralPublicKey),
        std::move(clientCertificate),
        std::move(clientKeyPair),
        std::move(serverNonce),
        std::move(tokenData),
        logger,
        [token = std::move(token), complete](ByteStringResult result) mutable
        {
          if (!result.is_good())
          {
            complete(VoidResult{ua::security_internal::not_good_answer(
              result.status_code(), Status::BadInternalError, "encrypt_issued_token")});
            return;
          }
          token->token_data() = std::move(result).value();
          token->encryption_algorithm().clear();
          complete(VoidResult{});
        });
      return;
    }

    if (policy->is_rsa())
    {
      if (!serverCertificate)
      {
        complete(VoidResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("IssuedTokenServerCertificateMissing",
            "Server certificate is null for issued-token RsaEncryptedSecret encryption",
            "encrypt_issued_token")});
        return;
      }

      encrypt_rsa_encrypted_secret_async(std::move(policy),
        std::move(crypto),
        std::move(strand),
        std::move(serverCertificate),
        std::move(serverNonce),
        std::move(tokenData),
        logger,
        [token = std::move(token), complete](ByteStringResult result) mutable
        {
          if (!result.is_good())
          {
            complete(VoidResult{ua::security_internal::not_good_answer(
              result.status_code(), Status::BadInternalError, "encrypt_issued_token")});
            return;
          }
          token->token_data() = std::move(result).value();
          token->encryption_algorithm().clear();
          complete(VoidResult{});
        });
      return;
    }

    complete(VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
      ErrorDetail::build("IssuedTokenEncryptionPolicyUnsupported",
        "The resolved user-token policy cannot encrypt an IssuedIdentityToken",
        "encrypt_issued_token")
        .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})});
  }
  catch (...)
  {
    auto error = ua::exception_to_status_code(std::current_exception());
    complete(VoidResult{error, error.shared_detail()});
  }
}

ByteString build_legacy_encrypted_token_plaintext(span<const byte> tokenData, span<const byte> serverNonce)
{
  // Part 4 7.41.2.2, Table 186: Length counts the token data plus the server nonce.
  const uint32_t declaredLength = static_cast<uint32_t>(tokenData.size() + serverNonce.size());

  // Sized once and filled in place, rather than reserve() plus push_back(). Both are correct and
  // allocate exactly once; GCC 14 cannot see that through the inlined reserve() and reports the
  // vector's own deallocation as a delete on an offset pointer (-Werror=free-nonheap-object), which
  // fails the Release build. Writing the length the same way it is read also keeps the four header
  // bytes next to the field they encode.
  std::vector<uint8_t> plain(4 + tokenData.size() + serverNonce.size());
  plain[0] = static_cast<uint8_t>(declaredLength & 0xFF);
  plain[1] = static_cast<uint8_t>((declaredLength >> 8) & 0xFF);
  plain[2] = static_cast<uint8_t>((declaredLength >> 16) & 0xFF);
  plain[3] = static_cast<uint8_t>((declaredLength >> 24) & 0xFF);
  const auto toByte = [](byte b)
  {
    return static_cast<uint8_t>(b);
  };
  const auto afterToken = std::transform(tokenData.begin(), tokenData.end(), plain.begin() + 4, toByte);
  std::transform(serverNonce.begin(), serverNonce.end(), afterToken, toByte);
  return ByteString{std::move(plain)};
}

ByteStringResult parse_legacy_encrypted_token_secret(span<const byte> decrypted, span<const byte> serverNonce)
{
  const size_t nonceSize = serverNonce.size();

  const auto validateSecretSize = [=](size_t secretSize) -> VoidResult
  {
    if (secretSize <= maximumLegacyPasswordSize)
      return {};
    return StatusCode{Status::BadIdentityTokenInvalid,
      ErrorDetail::build("LegacyTokenSecretTooLong",
        "Legacy encrypted UserIdentityToken secret exceeds the permitted size",
        "parse_legacy_encrypted_token_secret")
        .context(ua::ContextKeys::sizeActual, secretSize)
        .context(ua::ContextKeys::sizeMax, maximumLegacyPasswordSize)};
  };

  // Spec format (Part 4 7.41.2.2, Table 186): Length(4 LE) || tokenData || serverNonce, with
  // optional trailing zero padding. Read the length prefix and accept this interpretation only if
  // it is self-consistent (fits the buffer, leaves room for the nonce) AND the declared trailing
  // bytes equal the expected server nonce - otherwise fall back to the historical prefix-less form.
  if (decrypted.size() >= 4)
  {
    const uint32_t declaredLength =
      static_cast<uint32_t>(decrypted[0]) | (static_cast<uint32_t>(decrypted[1]) << 8) |
      (static_cast<uint32_t>(decrypted[2]) << 16) | (static_cast<uint32_t>(decrypted[3]) << 24);

    if (declaredLength >= nonceSize && static_cast<size_t>(declaredLength) + 4 <= decrypted.size())
    {
      auto payload = decrypted.subspan(4, declaredLength);
      auto padding = decrypted.subspan(static_cast<size_t>(declaredLength) + 4);
      auto noncePart = payload.subspan(declaredLength - nonceSize, nonceSize);

      if (std::ranges::equal(noncePart, serverNonce))
      {
        if (!std::ranges::all_of(padding, [](byte value) { return value == byte{0}; }))
        {
          return ByteStringResult{StatusCode{Status::BadIdentityTokenRejected},
            ErrorDetail::build("BadIdentityTokenRejected",
              "Encrypted UserIdentityToken secret has non-zero padding after the declared length",
              "parse_legacy_encrypted_token_secret")
              .context(ua::ContextKeys::length, std::to_string(declaredLength))
              .context(ua::ContextKeys::sizeActual, std::to_string(decrypted.size()))};
        }
        const size_t secretSize = declaredLength - nonceSize;
        if (auto sizeResult = validateSecretSize(secretSize); sizeResult.is_bad())
          return ByteStringResult{sizeResult.status_code()};
        return ByteStringResult{ByteString{payload.subspan(0, secretSize)}};
      }
      // Length prefix was plausible but the nonce did not match at the declared offset;
      // fall through to the legacy interpretation below.
    }
  }

  // Legacy format: tokenData || serverNonce (no length prefix). The asymmetric padding scheme
  // strips its own padding, so the nonce sits exactly at the tail.
  if (decrypted.size() < nonceSize)
  {
    return ByteStringResult{StatusCode{Status::BadIdentityTokenInvalid},
      ErrorDetail::build("BadIdentityTokenInvalid",
        "Decrypted password payload is shorter than server nonce",
        "parse_legacy_encrypted_token_secret")
        .context(ua::ContextKeys::sizeActual, std::to_string(decrypted.size()))
        .context(ua::ContextKeys::sizeMin, std::to_string(nonceSize))};
  }

  const size_t nonceOffset = decrypted.size() - nonceSize;
  if (!std::ranges::equal(decrypted.subspan(nonceOffset, nonceSize), serverNonce))
  {
    return ByteStringResult{StatusCode{Status::BadIdentityTokenInvalid},
      make_error_detail("BadIdentityTokenInvalid",
        "Decrypted nonce does not match server nonce",
        "parse_legacy_encrypted_token_secret")};
  }

  if (auto sizeResult = validateSecretSize(nonceOffset); sizeResult.is_bad())
    return ByteStringResult{sizeResult.status_code()};

  return ByteStringResult{ByteString{decrypted.subspan(0, nonceOffset)}};
}

}  // namespace ua
