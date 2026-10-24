// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_STORE_TEST_BACKENDS_H
#define UA_CERTIFICATE_STORE_TEST_BACKENDS_H

#include <memory>
#include <filesystem>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <gtest/gtest.h>
#include "ua_crypto.h"
#include "ua_certificate_store.h"
#include "ua_certificate_store_files.h"

namespace ua
{

struct BackendOpenSslFiles
{
  static constexpr std::string_view name = "openssl_files";
  static constexpr bool supportsFilesystem = true;
  static constexpr bool supportsPersistence = true;
  static constexpr bool supportsHotReload = true;
  static constexpr bool supportsCrlGeneration = true;

  static std::shared_ptr<const ua::Crypto> create_crypto()
  {
    return ua::create_default_crypto([]() { return ua::SecureString{"password"}; });
  }

  static std::shared_ptr<ua::CertificateStore> create_store(const std::filesystem::path& root,
    boost::asio::any_io_executor executor, std::shared_ptr<const ua::Crypto> crypto,
    ua::TrustListValidationOptions defaultOptions)
  {
    return ua::CertificateStoreFiles::create(executor,
      crypto,
      {.trustListPath = root, .validationOptions = defaultOptions, .storeRejectedCertificates = false});
  }
};

/// Every certificate-store backend under test. A typed suite whose tests apply to only some backends
/// is instantiated for the matching subset below, never skipped at run time.
using AllBackends = std::tuple<BackendOpenSslFiles>;

namespace detail
{

template<typename Tuple>
struct AsGtestTypes;

template<typename... Ts>
struct AsGtestTypes<std::tuple<Ts...>>
{
  using type = ::testing::Types<Ts...>;
};

/// The backends in @p List for which @p Keep holds, as a ::testing::Types list. An empty subset does not
/// compile: a suite with no applicable backend must not exist.
template<template<typename> class Keep, typename List>
struct BackendsWhere;

template<template<typename> class Keep, typename... Ts>
struct BackendsWhere<Keep, std::tuple<Ts...>>
{
  using type = typename AsGtestTypes<decltype(std::tuple_cat(
    std::declval<std::conditional_t<Keep<Ts>::value, std::tuple<Ts>, std::tuple<>>>()...))>::type;
};

template<typename TBackend>
struct KeepEveryBackend : std::true_type
{};

template<typename TBackend>
struct GeneratesCrls : std::bool_constant<TBackend::supportsCrlGeneration>
{};

template<typename TBackend>
struct PersistsToFilesystem : std::bool_constant<TBackend::supportsFilesystem>
{};

}  // namespace detail

using Backends = detail::BackendsWhere<detail::KeepEveryBackend, AllBackends>::type;

/// The backends that can generate CRLs, for tests that revoke through a CRL.
using CrlGeneratingBackends = detail::BackendsWhere<detail::GeneratesCrls, AllBackends>::type;

/// The backends that persist to the filesystem, for tests that break or inspect the on-disk store.
using FilesystemBackends = detail::BackendsWhere<detail::PersistsToFilesystem, AllBackends>::type;

}  // namespace ua

#endif  // UA_CERTIFICATE_STORE_TEST_BACKENDS_H
