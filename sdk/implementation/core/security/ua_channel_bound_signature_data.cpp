// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_channel_bound_signature_data.h"

#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_security_policy_internal.h"

#include <array>
#include <iterator>
#include <utility>

namespace ua
{

namespace
{

// The fields of one Table 101 row, in order. A certificate field is appended as its hash.
enum class Field
{
  ChannelThumbprint,
  ClientNonce,
  ServerNonce,
  ServerCertificate,
  ServerChannelCertificate,
  ClientCertificate,
  ClientChannelCertificate,
};

span<const Field> table_101_row(ChannelBoundSignature signature)
{
  using F = Field;
  static constexpr std::array serverRow{F::ChannelThumbprint,
    F::ClientNonce,
    F::ServerChannelCertificate,
    F::ClientChannelCertificate,
    F::ServerNonce};
  static constexpr std::array clientRow{F::ChannelThumbprint,
    F::ServerNonce,
    F::ServerCertificate,
    F::ServerChannelCertificate,
    F::ClientChannelCertificate,
    F::ClientNonce};
  static constexpr std::array userTokenRow{F::ChannelThumbprint,
    F::ServerNonce,
    F::ServerCertificate,
    F::ServerChannelCertificate,
    F::ClientCertificate,
    F::ClientChannelCertificate,
    F::ClientNonce};
  static constexpr std::array userTokenOverNoneRow{F::ServerNonce, F::ServerCertificate, F::ClientNonce};
  switch (signature)
  {
  case ChannelBoundSignature::Server:
    return serverRow;
  case ChannelBoundSignature::Client:
    return clientRow;
  case ChannelBoundSignature::UserToken:
    return userTokenRow;
  case ChannelBoundSignature::UserTokenOverNone:
    return userTokenOverNoneRow;
  }
  return {};
}

const ByteString& field_value(const ChannelBoundSignatureInputs& inputs, Field field)
{
  switch (field)
  {
  case Field::ChannelThumbprint:
    return inputs.channelThumbprint;
  case Field::ClientNonce:
    return inputs.clientNonce;
  case Field::ServerNonce:
    return inputs.serverNonce;
  case Field::ServerCertificate:
    return inputs.serverCertificate;
  case Field::ServerChannelCertificate:
    return inputs.serverChannelCertificate;
  case Field::ClientCertificate:
    return inputs.clientCertificate;
  case Field::ClientChannelCertificate:
    return inputs.clientChannelCertificate;
  }
  return inputs.channelThumbprint;
}

bool is_certificate(Field field)
{
  return field == Field::ServerCertificate || field == Field::ServerChannelCertificate ||
         field == Field::ClientCertificate || field == Field::ClientChannelCertificate;
}

// Appends one Table 101 row. Each certificate is hashed through the Crypto provider as it is reached, so the
// data grows in table order and no hash is computed for a row that does not use the certificate.
class BuildChannelBoundSignatureDataOperation final
  : public ua::async::SelfOwningOperation<BuildChannelBoundSignatureDataOperation>
{
public:
  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    ChannelBoundSignature signature, HashAlgorithm hash, shared_ptr<const Crypto> crypto,
    ChannelBoundSignatureInputs inputs, std::function<void(ByteStringResult)>& callback)
  {
    launch(std::make_shared<BuildChannelBoundSignatureDataOperation>(
      std::move(strand), std::move(logger), signature, hash, std::move(crypto), std::move(inputs), callback));
  }

  BuildChannelBoundSignatureDataOperation(boost::asio::strand<boost::asio::any_io_executor> strand,
    ua::Logger logger, ChannelBoundSignature signature, HashAlgorithm hash, shared_ptr<const Crypto> crypto,
    ChannelBoundSignatureInputs inputs, std::function<void(ByteStringResult)>& callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mSignature(signature), mHash(hash),
      mCrypto(std::move(crypto)), mInputs(std::move(inputs)), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<BuildChannelBoundSignatureDataOperation>;

  ua::async::Task<> run()
  {
    try
    {
      for (const Field field : table_101_row(mSignature))
      {
        const ByteString& value = field_value(mInputs, field);
        if (!is_certificate(field))
        {
          std::ranges::copy(value, std::back_inserter(mData));
          continue;
        }
        // "If the Certificate argument is null or empty, function returns a OctetString with 0 length."
        if (value.empty())
        {
          continue;
        }
        auto digestResult = co_await await_step<Crypto::CalculateDigestOutputResult>(
          [this, &value](auto completion)
          {
            ByteString certificate{value};
            const span<const byte> input{certificate};
            mCrypto->calculate_digest_async(mHash, std::move(certificate), input, std::move(completion));
          },
          [](BuildChannelBoundSignatureDataOperation& self, StatusCode status)
          { self.fail_to_start(std::move(status)); });
        if (digestResult.is_uncertain())
        {
          answer(ByteStringResult{StatusCode{Status::BadInternalError,
            ua::security_internal::uncertain_answer_detail(
              digestResult.status_code(), "build_channel_bound_signature_data")}});
          co_return;
        }
        if (!digestResult.is_good())
        {
          answer(ByteStringResult{digestResult.status_code(),
            ErrorDetail::build("CertificateHashFailed",
              "Could not hash a certificate of the channel bound signature data",
              "build_channel_bound_signature_data")
              .cause(digestResult.status_code())});
          co_return;
        }
        std::ranges::copy(digestResult.value().digest, std::back_inserter(mData));
      }
      answer(ByteStringResult{std::move(mData)});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      answer(ByteStringResult{failure, failure.shared_detail()});
    }
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(ByteStringResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(ByteStringResult result) noexcept
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      ::ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
    }
  }

  ChannelBoundSignature mSignature;
  HashAlgorithm mHash;
  shared_ptr<const Crypto> mCrypto;
  ChannelBoundSignatureInputs mInputs;
  ByteString mData;
  std::function<void(ByteStringResult)> mCallback;
};

}  // namespace

void build_channel_bound_signature_data_async(ChannelBoundSignature signature, HashAlgorithm hash,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ua::Logger logger, ChannelBoundSignatureInputs inputs, std::function<void(ByteStringResult)> callback)
{
  // Construction borrows the callback until its final, non-throwing member initialization.
  try
  {
    if (!crypto)
    {
      ::ua::detail::invoke_user_callback(logger,
        callback,
        ByteStringResult{StatusCode{Status::BadInvalidArgument},
          make_error_detail("MissingDependency",
            "Null crypto passed to build_channel_bound_signature_data_async",
            "build_channel_bound_signature_data")});
      return;
    }
    BuildChannelBoundSignatureDataOperation::start(
      std::move(strand), logger, signature, hash, std::move(crypto), std::move(inputs), callback);
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      logger, callback, ByteStringResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua
