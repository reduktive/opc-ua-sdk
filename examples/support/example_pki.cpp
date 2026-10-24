// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "example_pki.h"

#include "ua_certificate_store_files.h"
#include "ua_trust_list_validation_options.h"
#include "ua_utc_time.h"
#include "ua_x509_certificate.h"

#include <boost/asio/ip/address.hpp>

#include <array>
#include <cerrno>
#include <stdexcept>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace examples
{
namespace
{
constexpr std::string_view serverApplicationUri = "urn:reduktive:opcua-sdk:example:server";
constexpr std::string_view clientApplicationUri = "urn:reduktive:opcua-sdk:example:client";
constexpr std::uint32_t rsaKeyBits = 2048;

std::filesystem::path pki_root()
{
  auto root = development_pki_root();
  prepare_development_pki_root(root);
  return root;
}

std::string_view role_directory(PkiRole role) noexcept
{
  return role == PkiRole::Server ? "server" : "client";
}

/// Loads @p role's own certificate, creating a self-signed one on first use.
std::shared_ptr<const ua::X509Certificate> own_certificate(
  const ua::Crypto& crypto, ua::CertificateStore& store, PkiRole role)
{
  auto existing = store.try_get_application_certificate_sync(ua::CertificateType::RsaSha256Application);
  if (existing.is_good() && existing.value().certificate && existing.value().keys)
  {
    return existing.value().certificate;
  }

  ua::Crypto::Name subject;
  subject.commonName = role == PkiRole::Server ? "Reduktive Example Server" : "Reduktive Example Client";
  subject.organization = "Reduktive";

  // A server is reached at an address, so its certificate must cover that address. A client is
  // not, so it needs only its ApplicationUri.
  ua::Crypto::SubjectAlternateName alternateNames;
  alternateNames.uris.emplace_back(development_application_uri(role));
  if (role == PkiRole::Server)
  {
    alternateNames.hostnames.emplace_back("localhost");
    alternateNames.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
  }

  ua::UtcTime expiry = ua::UtcTime::now();
  expiry.value() += std::chrono::hours{24 * 30};

  auto [keys, certificate] =
    crypto.create_self_signed_application_instance_certificate_sync(std::move(subject),
      expiry,
      std::move(alternateNames),
      ua::CertificateType::RsaSha256Application,
      rsaKeyBits);
  store
    .try_add_to_application_certificates_sync({.certificateType = ua::CertificateType::RsaSha256Application,
      .certificate = certificate,
      .keys = std::move(keys)})
    .value();
  return certificate;
}

}  // namespace

std::shared_ptr<const ua::Crypto> development_crypto()
{
  // Not for production: a constant private-key password. A deployment reads it from a secret
  // provider, and never from source, a command line, or a log.
  return ua::create_default_crypto([]() { return ua::SecureString{"uasdk-examples"}; });
}

std::string_view development_application_uri(PkiRole role) noexcept
{
  return role == PkiRole::Server ? serverApplicationUri : clientApplicationUri;
}

DevelopmentPki open_development_pki(boost::asio::any_io_executor executor, PkiRole role)
{
  // Both halves are prepared on whichever call comes first, so an example server and an example
  // client can each be started with no arguments and in either order.
  constexpr std::array<PkiRole, 2> roles{PkiRole::Server, PkiRole::Client};
  std::array<DevelopmentPki, 2> halves;
  for (std::size_t index = 0; index < roles.size(); ++index)
  {
    auto crypto = development_crypto();
    auto store = ua::CertificateStoreFiles::create(
      executor, crypto, {.trustListPath = pki_root() / role_directory(roles[index])});
    auto certificate = own_certificate(*crypto, *store, roles[index]);
    halves[index] = {std::move(crypto), std::move(store), std::move(certificate)};
  }

  // Not for production: each half is given the other's certificate without anyone checking it.
  halves[0].store->try_add_to_trusted_certificates_sync(halves[1].certificate).value();
  halves[1].store->try_add_to_trusted_certificates_sync(halves[0].certificate).value();

  return role == PkiRole::Server ? std::move(halves[0]) : std::move(halves[1]);
}

std::filesystem::path development_pki_root()
{
#ifdef _WIN32
  return std::filesystem::temp_directory_path() / "uasdk-examples-pki";
#else
  return std::filesystem::temp_directory_path() / ("uasdk-examples-pki-" + std::to_string(::geteuid()));
#endif
}

void prepare_development_pki_root(const std::filesystem::path& root)
{
  std::error_code error;
  const auto status = std::filesystem::symlink_status(root, error);
  if (error || !std::filesystem::exists(status))
  {
    // DEF-8: create it owner-only from the start (mkdir 0700 on POSIX), so no window exists in which
    // another user can enter it.
#ifdef _WIN32
    std::filesystem::create_directories(root);
#else
    if (::mkdir(root.c_str(), 0700) != 0 && errno != EEXIST)
      throw std::runtime_error("cannot create the development PKI directory " + root.string());
    // A concurrent creator won the race: verify what is there like an existing directory.
    return prepare_development_pki_root(root);
#endif
    return;
  }
  if (std::filesystem::is_symlink(status) || !std::filesystem::is_directory(status))
    throw std::runtime_error("the development PKI path is not a directory: " + root.string());
#ifndef _WIN32
  struct stat info
  {};

  if (::lstat(root.c_str(), &info) != 0)
    throw std::runtime_error("cannot inspect the development PKI directory " + root.string());
  if (info.st_uid != ::geteuid())
    throw std::runtime_error("the development PKI directory is owned by another user: " + root.string());
  if ((info.st_mode & 077) != 0)
    throw std::runtime_error(
      "the development PKI directory is accessible to other users (mode must be 0700): " + root.string());
#endif
}

}  // namespace examples
