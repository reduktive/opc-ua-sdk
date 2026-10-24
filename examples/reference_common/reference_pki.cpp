// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "reference_pki.h"

#include "ua_certificate_store_files.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_trust_list_validation_options.h"
#include "ua_utc_time.h"
#include "ua_x509_certificate.h"

#include <fmt/format.h>
#include <fmt/ranges.h>

#include "ua_byte_format.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <ranges>
#include <string_view>
#include <utility>

namespace reduktive::reference
{
namespace
{
constexpr std::uintmax_t maximumCertificateBytes = 1024U * 1024U;
constexpr std::uint32_t rsaKeyBits = 2048;

ua::SecureString credential_from_environment(const std::string& variableName)
{
  // getenv is the narrow C boundary. Copy immediately into a SecureString, which wipes its bytes when it
  // goes, and never expose the value in an error or log entry.
  const auto environmentValue = std::getenv(variableName.c_str());
  if (environmentValue == nullptr || environmentValue[0] == '\0')
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceKeyCredentialMissing",
        fmt::format("Set {} before provisioning or starting the reference application", variableName),
        "reference.pki.credential")}};
  }

  return ua::SecureString{environmentValue};
}

bool contains_all(const std::vector<std::string>& available, const std::vector<std::string>& required)
{
  return std::ranges::all_of(required,
    [&available](const std::string& value)
    { return std::ranges::find(available, value) != available.end(); });
}

bool contains_all(const std::vector<boost::asio::ip::address>& available,
  const std::vector<boost::asio::ip::address>& required)
{
  return std::ranges::all_of(required,
    [&available](const boost::asio::ip::address& value)
    { return std::ranges::find(available, value) != available.end(); });
}

bool certificate_matches(const ua::X509Certificate& certificate, const CertificateProfile& profile)
{
  const auto uris = certificate.san_uris();
  return std::ranges::find(uris, profile.applicationUri) != uris.end() &&
         contains_all(certificate.san_hostnames(), profile.dnsNames) &&
         contains_all(certificate.san_ip_addresses(), profile.ipAddresses) &&
         certificate.validity_to() > ua::UtcTime::now();
}

ua::UtcTime certificate_expiry()
{
  ua::UtcTime expiry = ua::UtcTime::now();
  expiry.value() += std::chrono::hours{24 * 365 * 5};
  return expiry;
}

ua::ByteString read_certificate_file(const std::filesystem::path& source)
{
  std::error_code sizeError;
  const std::uintmax_t size = std::filesystem::file_size(source, sizeError);
  if (sizeError)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceCertificateFileUnreadable",
        "The peer certificate file could not be inspected",
        "reference.pki.import")
        .context(ua::ContextKeys::filePath, source.string())
        .context(ua::ContextKeys::fileErrorCode, sizeError.value())}};
  }
  if (size == 0 || size > maximumCertificateBytes)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadEncodingLimitsExceeded,
      ua::ErrorDetail::build("ReferenceCertificateFileSizeInvalid",
        "The peer certificate must be a non-empty DER file no larger than 1 MiB",
        "reference.pki.import")
        .context(ua::ContextKeys::filePath, source.string())
        .context(ua::ContextKeys::sizeActual, size)
        .context(ua::ContextKeys::sizeMax, maximumCertificateBytes)}};
  }

  ua::ByteString contents(static_cast<std::size_t>(size), std::uint8_t{0});
  std::ifstream input{source, std::ios::binary};
  input.read(reinterpret_cast<char*>(contents.data()), static_cast<std::streamsize>(contents.size()));
  if (!input)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceCertificateFileReadFailed",
        "The peer certificate file could not be read completely",
        "reference.pki.import")
        .context(ua::ContextKeys::filePath, source.string())}};
  }
  return contents;
}
}  // namespace

ApplicationPki prepare_application_pki(boost::asio::any_io_executor executor, std::filesystem::path pkiRoot,
  std::string credentialEnvironmentVariable, CertificateProfile profile, ua::Logger logger)
{
  auto credential = credential_from_environment(credentialEnvironmentVariable);
  auto crypto = ua::create_default_crypto([credential = std::move(credential)] { return credential; });
  auto store = ua::CertificateStoreFiles::create(
    std::move(executor), crypto, {.trustListPath = std::move(pkiRoot), .logger = std::move(logger)});

  auto existing = store->try_get_application_certificate_sync(ua::CertificateType::RsaSha256Application);
  if (existing.is_good() && existing.value().certificate && existing.value().keys &&
      certificate_matches(*existing.value().certificate, profile))
  {
    return {std::move(crypto), std::move(store), std::move(existing).value()};
  }
  if (existing.is_bad() && existing.status_code().as_status() != ua::Status::BadNotFound)
  {
    throw ua::UaException{existing.status_code()};
  }

  ua::Crypto::Name subject;
  subject.commonName = std::move(profile.commonName);
  subject.organization = "Reduktive";

  ua::Crypto::SubjectAlternateName alternateNames;
  alternateNames.uris.push_back(std::move(profile.applicationUri));
  alternateNames.hostnames = std::move(profile.dnsNames);
  alternateNames.ipAddresses = std::move(profile.ipAddresses);

  auto [keys, certificate] =
    crypto->create_self_signed_application_instance_certificate_sync(std::move(subject),
      certificate_expiry(),
      std::move(alternateNames),
      ua::CertificateType::RsaSha256Application,
      rsaKeyBits);

  ua::CertificateStore::ApplicationCertificate generated{
    .certificateType = ua::CertificateType::RsaSha256Application,
    .certificate = std::move(certificate),
    .keys = std::move(keys)};
  store->try_add_to_application_certificates_sync(generated).value();
  return {std::move(crypto), std::move(store), std::move(generated)};
}

void export_public_certificate(
  const ua::X509Certificate& certificate, const std::filesystem::path& destination)
{
  if (!destination.parent_path().empty())
  {
    std::filesystem::create_directories(destination.parent_path());
  }
  const ua::ByteString der = certificate.der_encoding();
  std::ofstream output{destination, std::ios::binary | std::ios::trunc};
  output.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
  if (!output)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("ReferenceCertificateExportFailed",
        "The public application certificate could not be exported",
        "reference.pki.export")
        .context(ua::ContextKeys::filePath, destination.string())}};
  }
}

std::shared_ptr<const ua::X509Certificate> trust_public_certificate(
  const ua::Crypto& crypto, ua::CertificateStore& store, const std::filesystem::path& source)
{
  auto certificate = crypto.read_certificate_from_der(read_certificate_file(source));
  store.try_add_to_trusted_certificates_sync(certificate).value();
  return certificate;
}

std::string certificate_sha256(const ua::Crypto& crypto, const ua::X509Certificate& certificate)
{
  const ua::ByteString der = certificate.der_encoding();
  const ua::ByteString digest = crypto.calculate_digest_sync(ua::HashAlgorithm::Sha2256, der);
  return fmt::format("{:02X}", fmt::join(digest, ""));
}

}  // namespace reduktive::reference
