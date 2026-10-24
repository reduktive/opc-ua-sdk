// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_crypto.h"
#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_security_policy_internal.h"
#include "ua_string.h"
#include "ua_to_result.h"

#include "fmt/format.h"

#include <algorithm>
#include <cctype>
#include <future>

namespace
{

bool has_local_top_level_domain(std::string_view hostname)
{
  if (!hostname.empty() && hostname.back() == '.')
  {
    hostname.remove_suffix(1);
  }

  constexpr std::string_view localSuffix{".local"};
  if (hostname.size() <= localSuffix.size())
  {
    return false;
  }

  const auto suffix = hostname.substr(hostname.size() - localSuffix.size());
  return std::equal(suffix.begin(),
    suffix.end(),
    localSuffix.begin(),
    [](char actual, char expected)
    {
      return std::tolower(static_cast<unsigned char>(actual)) ==
             std::tolower(static_cast<unsigned char>(expected));
    });
}

void normalize_application_certificate_hostnames(ua::Crypto::SubjectAlternateName& subjectAlternateName)
{
  std::vector<std::string> normalizedHostnames;
  normalizedHostnames.reserve(subjectAlternateName.hostnames.size());

  for (auto hostname : subjectAlternateName.hostnames)
  {
    if (has_local_top_level_domain(hostname))
    {
      const std::size_t suffixSize = hostname.back() == '.' ? 7U : 6U;
      hostname.erase(hostname.size() - suffixSize);
    }

    if (!hostname.empty() && std::find(normalizedHostnames.begin(), normalizedHostnames.end(), hostname) ==
                               normalizedHostnames.end())
    {
      normalizedHostnames.push_back(std::move(hostname));
    }
  }

  subjectAlternateName.hostnames = std::move(normalizedHostnames);
}

}  // namespace

namespace ua
{

void ua::Crypto::create_self_signed_application_instance_certificate_async(Name subject, UtcTime expiry,
  SubjectAlternateName subjectAlternateName, CertificateType certificateType,
  optional<size_t> keyLengthInBits,
  CreateSelfSignedApplicationInstanceCertificateCompleteCallback callback) const
{
  CertificateKeyAlgorithm keyAlgorithm = CertificateKeyAlgorithm::Invalid;
  CertificateSignatureAlgorithm sigAlgorithm = CertificateSignatureAlgorithm::Invalid;

  try
  {
    normalize_application_certificate_hostnames(subjectAlternateName);

    switch (certificateType)
    {
    case CertificateType::RsaMinApplication:
      keyAlgorithm = CertificateKeyAlgorithm::Rsa;
      sigAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha1;
      if (!keyLengthInBits.has_value() || (keyLengthInBits.value() < 1024) ||
          (keyLengthInBits.value() > 2048))
      {
        throw UaException{Status::BadInvalidArgument,
          ErrorDetail::build("InvalidKeyLength",
            "RSA key length is outside the valid range for an RsaMinApplication certificate.",
            "Crypto")
            .context(ua::ContextKeys::length, std::to_string(keyLengthInBits.value_or(0)))
            .context(ua::ContextKeys::min, std::to_string(1024))
            .context(ua::ContextKeys::max, std::to_string(2048))};
      }
      break;

    case CertificateType::Application:
    case CertificateType::RsaSha256Application:
      keyAlgorithm = CertificateKeyAlgorithm::Rsa;
      sigAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
      if (!keyLengthInBits.has_value() || (keyLengthInBits.value() < 2048) ||
          (keyLengthInBits.value() > 4096))
      {
        throw UaException{Status::BadInvalidArgument,
          ErrorDetail::build("InvalidKeyLength",
            "RSA key length is outside the valid range for an RsaSha256Application certificate.",
            "Crypto")
            .context(ua::ContextKeys::length, std::to_string(keyLengthInBits.value_or(0)))
            .context(ua::ContextKeys::min, std::to_string(2048))
            .context(ua::ContextKeys::max, std::to_string(4096))};
      }
      break;

    case CertificateType::EccNistP256Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccNistP256;
      sigAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
      break;

    case CertificateType::EccNistP384Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccNistP384;
      sigAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2384;
      break;

    case CertificateType::EccBrainpoolP256r1Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccBrainpoolP256r1;
      sigAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
      break;

    case CertificateType::EccBrainpoolP384r1Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccBrainpoolP384r1;
      sigAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2384;
      break;

    case CertificateType::EccCurve448Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccCurve448;
      sigAlgorithm = CertificateSignatureAlgorithm::PureEdDsa448;
      break;

    case CertificateType::EccApplication:
    case CertificateType::EccCurve25519Application:
      keyAlgorithm = CertificateKeyAlgorithm::EccCurve25519;
      sigAlgorithm = CertificateSignatureAlgorithm::PureEdDsa25519;
      break;

    case CertificateType::Https:
    case CertificateType::Invalid:
    default:
      throw UaException{Status::BadInvalidArgument,
        make_error_detail("UnsupportedCertificateType",
          "Certificate type is invalid or unsupported (Https/Invalid)",
          "Crypto")};
      break;
    }
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
    return;
  }

  auto me = shared_from_this();

  create_asymmetric_key_pair_async(keyAlgorithm,
    keyLengthInBits,
    [me,
      sigAlgorithm,
      sub = std::move(subject),
      expiry,
      altName = std::move(subjectAlternateName),
      cb = std::move(callback)](Result<shared_ptr<const AsymmetricKeyPair>> keyPairResult)
    {
      if (!keyPairResult.is_good())
      {
        // The certificate is built only on a Good key pair: an Uncertain answer, holding a key pair or
        // not, is refused with Bad_InternalError and its code as the cause.
        cb(security_internal::not_good_answer(
          keyPairResult.status_code(), Status::BadInternalError, "Crypto"));
      }
      else
      {
        auto keyPair = std::move(keyPairResult).value();
        check(keyPair);
        CreateCertificateConfig parameters;
        parameters.serialNumber = "1";
        parameters.subject = sub;
        parameters.issuerKeys = parameters.subjectKeys = keyPair;
        parameters.certificateSignatureAlgorithm = sigAlgorithm;
        parameters.from = DateTime::now();
        parameters.to = expiry;
        parameters.subjectAlternateName = altName;
        parameters.keyUsage.digitalSignature = parameters.keyUsage.nonRepudiation =
          parameters.keyUsage.keyEncipherment = parameters.keyUsage.dataEncipherment =
            parameters.keyUsage.serverAuth = parameters.keyUsage.clientAuth = true;
        // Part 6 section 6.2.2 Table 43 requires keyCertSign for a self-signed application certificate.
        // This does not make it a CA: retain cA FALSE and omit pathLength.
        parameters.keyUsage.keyCertSign = true;
        parameters.basicConstraint.cA = false;

        me->create_certificate_async(parameters,
          [keyPair, cb1 = cb](Result<shared_ptr<const X509Certificate>> certResult)
          {
            if (!certResult.has_value())
            {
              cb1(certResult.status_code());
            }
            else
            {
              // The answer keeps the code the certificate was created with: a Good subcode or an
              // Uncertain code is passed on with the key pair and certificate.
              const StatusCode code = certResult.status_code();
              cb1(ua::detail::held(std::make_pair(keyPair, std::move(certResult).value()), code));
            }
          });
      }
    });
}

SelfSignedCertResult ua::Crypto::try_create_self_signed_application_instance_certificate_sync(Name subject,
  UtcTime expiry, SubjectAlternateName subjectAlternateName, CertificateType certificateType,
  optional<size_t> keyLengthInBits) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SelfSignedCertResult>(boost::asio::any_io_executor{},
      [&](std::function<void(SelfSignedCertResult)> complete)
      {
        create_self_signed_application_instance_certificate_async(std::move(subject),
          expiry,
          std::move(subjectAlternateName),
          certificateType,
          keyLengthInBits,
          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

std::pair<shared_ptr<const AsymmetricKeyPair>, shared_ptr<const X509Certificate>>
  ua::Crypto::create_self_signed_application_instance_certificate_sync(Name subject, UtcTime expiry,
    SubjectAlternateName subjectAlternateName, CertificateType certificateType,
    optional<size_t> keyLengthInBits) const
{
  return ua::detail::good_value(try_create_self_signed_application_instance_certificate_sync(
    std::move(subject), expiry, std::move(subjectAlternateName), certificateType, keyLengthInBits));
}

shared_ptr<const X509Certificate> ua::Crypto::sign_certificate_request_sync(
  const SignCsrConfig& parameters) const
{
  return ua::detail::good_value(try_sign_certificate_request_sync(parameters));
}

CertificateResult ua::Crypto::try_sign_certificate_request_sync(
  const SignCsrConfig& parameters) const noexcept
{
  // Crypto has no executor: its operations compute on the calling thread, so there is none to refuse.
  return ua::async::detail::blocking_call<CertificateResult>(boost::asio::any_io_executor{},
    [&](std::function<void(CertificateResult)> complete)
    { sign_certificate_request_async(parameters, std::move(complete)); });
}

shared_ptr<const X509Crl> ua::Crypto::create_crl_sync(shared_ptr<const X509Certificate> issuer,
  shared_ptr<const AsymmetricKeyPair> issuerKeys, const std::vector<std::string>& revokedSerialNumbers) const
{
  return ua::detail::good_value(
    try_create_crl_sync(std::move(issuer), std::move(issuerKeys), revokedSerialNumbers));
}

CrlResult ua::Crypto::try_create_crl_sync(shared_ptr<const X509Certificate> issuer,
  shared_ptr<const AsymmetricKeyPair> issuerKeys,
  const std::vector<std::string>& revokedSerialNumbers) const noexcept
{
  // Crypto has no executor: its operations compute on the calling thread, so there is none to refuse.
  return ua::async::detail::blocking_call<CrlResult>(boost::asio::any_io_executor{},
    [&](std::function<void(CrlResult)> complete)
    {
      create_crl_async(std::move(issuer),
        std::move(issuerKeys),
        std::vector<std::string>(revokedSerialNumbers),
        std::move(complete));
    });
}

}  // namespace ua
