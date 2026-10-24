// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <optional>
#include <algorithm>
#include <map>
#include <fstream>
#include <iterator>
#include "ua_certificate_store_files.h"
#include "ua_certificate_store_files_impl.h"
#include "ua_certificate_store_files_detail.h"
#include "ua_certificate_thumbprint.h"
#include "ua_to_string.h"
#include "ua_guid.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_file_stream.h"
#include "ua_callback_safety.h"
#include "ua_on_strand.h"
#include "ua_owner_only_directory.h"
#include "ua_to_result.h"

#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"

using namespace std::filesystem;

namespace ua
{

namespace certificate_store_files_detail
{

void recover_list_directories(const std::vector<std::filesystem::path>& directories)
{
  std::error_code ignored;
  const auto freshOf = [](const path& directory)
  {
    return path{directory.string() + ".new"};
  };
  const auto retiredOf = [](const path& directory)
  {
    return path{directory.string() + ".old"};
  };
  const bool unfinished = std::any_of(directories.begin(),
    directories.end(),
    [&](const path& directory) { return exists(freshOf(directory), ignored); });
  for (const auto& directory : directories)
  {
    if (unfinished && exists(retiredOf(directory), ignored))
    {
      remove_all(directory, ignored);  // a new list renamed in before the crash: rolled back
      rename(retiredOf(directory), directory);
    }
    remove_all(freshOf(directory), ignored);
    remove_all(retiredOf(directory), ignored);
  }
}

void replace_list_directories(const std::vector<ListReplacement>& replacements)
{
  std::error_code ignored;
  const auto freshOf = [](const path& directory)
  {
    return path{directory.string() + ".new"};
  };
  const auto retiredOf = [](const path& directory)
  {
    return path{directory.string() + ".old"};
  };

  // 1. Every new list is written into a fresh sibling; nothing current is touched yet.
  {
    std::vector<path> directories;
    for (const auto& replacement : replacements)
      directories.push_back(replacement.directory);
    recover_list_directories(directories);
  }
  for (const auto& replacement : replacements)
  {
    create_directory(freshOf(replacement.directory));
  }
  try
  {
    for (const auto& replacement : replacements)
    {
      replacement.writeNewContent(freshOf(replacement.directory));
    }
  }
  catch (...)
  {
    for (const auto& replacement : replacements)
      remove_all(freshOf(replacement.directory), ignored);
    throw;
  }

  // 2. Each directory is swapped by two renames. Each rename is atomic, and between them the list
  // exists under exactly one name (`.old`), which recover_list_directories restores after a crash.
  // A failure restores what was already swapped.
  std::size_t swapped = 0;
  bool failingListRestored = true;
  try
  {
    for (; swapped < replacements.size(); ++swapped)
    {
      const auto& directory = replacements[swapped].directory;
      rename(directory, retiredOf(directory));
      if (replacements[swapped].afterRenamedAsideForTests)
        replacements[swapped].afterRenamedAsideForTests(directory);
      try
      {
        rename(freshOf(directory), directory);
      }
      catch (...)
      {
        std::error_code restoreError;
        rename(retiredOf(directory), directory, restoreError);
        failingListRestored = !restoreError;
        throw;
      }
    }
  }
  catch (...)
  {
    bool restored = failingListRestored;
    for (std::size_t i = 0; i < swapped; ++i)
    {
      const auto& directory = replacements[i].directory;
      remove_all(directory, ignored);
      std::error_code renameError;
      rename(retiredOf(directory), directory, renameError);
      restored = restored && !renameError;
    }
    // Only a complete restore may clear the fresh siblings: while one stays, the next recovery rolls
    // the pair back from its ".old" lists instead of taking them for a finished swap's leftovers.
    for (const auto& replacement : replacements)
    {
      if (restored)
        remove_all(freshOf(replacement.directory), ignored);
      else
        create_directory(freshOf(replacement.directory), ignored);
    }
    throw;
  }
  for (const auto& replacement : replacements)
    remove_all(retiredOf(replacement.directory), ignored);
}

}  // namespace certificate_store_files_detail

namespace
{
// Downcast-and-lock helper: the non-strand-post continuations that survive in this file (the
// Crypto-validation `completed` chain and the background refresh Timer) capture `weak_from_this()`
// (which is `weak_ptr<CertificateStore>` because CertificateStore owns the `enable_shared_from_this`)
// and downcast the locked shared_ptr to `CertificateStoreFilesImpl` so they can reach the file-backed
// internals. The strand-post call sites use the @ref ua::async post helpers + @ref as_files instead.
inline shared_ptr<CertificateStoreFilesImpl> lock_self(const weak_ptr<CertificateStore>& weak)
{
  return std::static_pointer_cast<CertificateStoreFilesImpl>(weak.lock());
}

// Reference downcasts mirroring lock_self for the post-helper handlers. The `enable_shared_from_this`
// lives on the base `CertificateStore`, so `post_borrowing` / `post_owning` deduce `Self =
// CertificateStore` (the post helpers static_assert that `Self` derives from
// `enable_shared_from_this<Self>`, which only the base satisfies) and hand the handler a live
// `CertificateStore&`. These overloads recover the file-backed `CertificateStoreFilesImpl&` so the handler
// can reach the store's internals, in the const and non-const member paths.
inline CertificateStoreFilesImpl& as_files(CertificateStore& base)
{
  return static_cast<CertificateStoreFilesImpl&>(base);
}

inline const CertificateStoreFilesImpl& as_files(const CertificateStore& base)
{
  return static_cast<const CertificateStoreFilesImpl&>(base);
}

// Path names
const string_view rootPath{"TrustList"};
const string_view applicationCertPath{"ApplicationCertificates"};
const string_view applicationKeyPath{"ApplicationKeys"};
const string_view trustedCertPath{"TrustedCertificates"};
const string_view trustedCrlPath{"TrustedCrls"};
const string_view issuerCertPath{"IssuerCertificates"};
const string_view issuerCrlPath{"IssuerCrls"};
const string_view rejectedCertPath{"RejectedCertificates"};

// Application certificate and key file names
static std::map<CertificateType, std::pair<std::string, CertificateKeyAlgorithm>> gCertTypes{
  {CertificateType::RsaMinApplication, std::make_pair("RsaMin", CertificateKeyAlgorithm::Rsa)},
  {CertificateType::RsaSha256Application, std::make_pair("RsaSha256", CertificateKeyAlgorithm::Rsa)},
  {CertificateType::EccNistP256Application,
    std::make_pair("EccNistP256", CertificateKeyAlgorithm::EccNistP256)},
  {CertificateType::EccNistP384Application,
    std::make_pair("EccNistP384", CertificateKeyAlgorithm::EccNistP384)},
  {CertificateType::EccBrainpoolP256r1Application,
    std::make_pair("EccBrainpoolP256r1", CertificateKeyAlgorithm::EccBrainpoolP256r1)},
  {CertificateType::EccBrainpoolP384r1Application,
    std::make_pair("EccBrainpoolP384r1", CertificateKeyAlgorithm::EccBrainpoolP384r1)},
  {CertificateType::EccCurve25519Application,
    std::make_pair("EccCurve25519", CertificateKeyAlgorithm::EccCurve25519)},
  {CertificateType::EccCurve448Application,
    std::make_pair("EccCurve448", CertificateKeyAlgorithm::EccCurve448)}};
}  // namespace

CertificateStoreFilesImpl::~CertificateStoreFilesImpl()
{
  // Safety net: cancel the refresh timer so it does not fire after destruction.
  mRefreshTimer.cancel();
}

void CertificateStoreFilesImpl::shutdown()
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    [](auto& base) { as_files(base).mRefreshTimer.cancel(); })();
}

void CertificateStoreFilesImpl::add_to_application_certificates_async(
  CertificateStore::ApplicationCertificate certificate, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [certificate](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_application_certificates_internal(certificate, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_application_certificate_async(
  CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    ApplicationCertificateResult{Status::BadInternalError},
    [certificateType](auto& base, GetApplicationCertificateCallback done) mutable
    { as_files(base).get_application_certificate_internal(certificateType, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_application_certificates_async(
  CertificateStore::GetApplicationCertificatesCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    ApplicationCertificateListResult{Status::BadInternalError},
    [](auto& base, GetApplicationCertificatesCallback done) mutable
    { as_files(base).get_application_certificates_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::add_to_trusted_certificates_async(
  shared_ptr<const X509Certificate> certificate, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    std::vector<shared_ptr<const X509Certificate>> certificates;
    certificates.push_back(certificate);

    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [cs = std::move(certificates)](auto& base, CompleteCallback done) mutable
      { as_files(base).add_to_trusted_certificates_internal(cs, std::move(done)); })();
  }
  catch (...)
  {
    // The 1-element vector build or the post-helper construction failed (e.g. bad_alloc) before the
    // work was queued; report synchronously via the surviving callback copy so the error is never
    // silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

void CertificateStoreFilesImpl::add_to_trusted_certificates_async(
  std::vector<shared_ptr<const X509Certificate>> certificates,
  CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [cs = std::move(certificates)](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_trusted_certificates_internal(cs, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_trusted_certificates_async(
  CertificateStore::GetCertificatesCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    CertificateListResult{Status::BadInternalError},
    [](auto& base, GetCertificatesCallback done) mutable
    { as_files(base).get_trusted_certificates_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::add_to_issuer_certificates_async(
  shared_ptr<const X509Certificate> certificate, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    std::vector<shared_ptr<const X509Certificate>> certificates;
    certificates.push_back(certificate);

    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [cs = std::move(certificates)](auto& base, CompleteCallback done) mutable
      { as_files(base).add_to_issuer_certificates_internal(cs, std::move(done)); })();
  }
  catch (...)
  {
    // The 1-element vector build or the post-helper construction failed (e.g. bad_alloc) before the
    // work was queued; report synchronously via the surviving callback copy so the error is never
    // silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

void CertificateStoreFilesImpl::add_to_issuer_certificates_async(
  std::vector<shared_ptr<const X509Certificate>> certificates,
  CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [cs = std::move(certificates)](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_issuer_certificates_internal(cs, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_issuer_certificates_async(
  CertificateStore::GetCertificatesCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    CertificateListResult{Status::BadInternalError},
    [](auto& base, GetCertificatesCallback done) mutable
    { as_files(base).get_issuer_certificates_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::add_to_rejected_certificates_async(
  shared_ptr<const X509Certificate> certificate, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [certificate](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_rejected_certificates_internal(certificate, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_rejected_certificates_async(
  CertificateStore::GetCertificatesCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    CertificateListResult{Status::BadInternalError},
    [](auto& base, GetCertificatesCallback done) mutable
    { as_files(base).get_rejected_certificates_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::add_to_trusted_crls_async(
  shared_ptr<const X509Crl> crl, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    std::vector<shared_ptr<const X509Crl>> crls;
    crls.push_back(crl);

    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [cs = std::move(crls)](auto& base, CompleteCallback done) mutable
      { as_files(base).add_to_trusted_crls_internal(cs, std::move(done)); })();
  }
  catch (...)
  {
    // The 1-element vector build or the post-helper construction failed (e.g. bad_alloc) before the
    // work was queued; report synchronously via the surviving callback copy so the error is never
    // silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

void CertificateStoreFilesImpl::add_to_trusted_crls_async(
  std::vector<shared_ptr<const X509Crl>> crls, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [cs = std::move(crls)](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_trusted_crls_internal(cs, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_trusted_crls_async(
  CertificateStore::GetCrlsCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    CrlListResult{Status::BadInternalError},
    [](auto& base, GetCrlsCallback done) mutable
    { as_files(base).get_trusted_crls_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::add_to_issuer_crls_async(
  shared_ptr<const X509Crl> crl, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    std::vector<shared_ptr<const X509Crl>> crls;
    crls.push_back(crl);

    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [cs = std::move(crls)](auto& base, CompleteCallback done) mutable
      { as_files(base).add_to_issuer_crls_internal(cs, std::move(done)); })();
  }
  catch (...)
  {
    // The 1-element vector build or the post-helper construction failed (e.g. bad_alloc) before the
    // work was queued; report synchronously via the surviving callback copy so the error is never
    // silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

void CertificateStoreFilesImpl::add_to_issuer_crls_async(
  std::vector<shared_ptr<const X509Crl>> crls, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [cs = std::move(crls)](auto& base, CompleteCallback done) mutable
    { as_files(base).add_to_issuer_crls_internal(cs, std::move(done)); })();
}

void CertificateStoreFilesImpl::get_issuer_crls_async(
  CertificateStore::GetCrlsCallback callback) const noexcept
{
  ua::async::post_borrowing(static_cast<const CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    CrlListResult{Status::BadInternalError},
    [](auto& base, GetCrlsCallback done) mutable
    { as_files(base).get_issuer_crls_internal(std::move(done)); })();
}

void CertificateStoreFilesImpl::replace_trusted_certificates_async(
  CertificateList certificates, CrlList crls, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [certificates = std::move(certificates), crls = std::move(crls)](
      auto& base, CompleteCallback done) mutable
    {
      as_files(base).replace_trusted_certificates_internal(
        std::move(certificates), std::move(crls), std::move(done));
    })();
}

void CertificateStoreFilesImpl::replace_issuer_certificates_async(
  CertificateList certificates, CrlList crls, CertificateStore::CompleteCallback callback) noexcept
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [certificates = std::move(certificates), crls = std::move(crls)](
      auto& base, CompleteCallback done) mutable
    {
      as_files(base).replace_issuer_certificates_internal(
        std::move(certificates), std::move(crls), std::move(done));
    })();
}

void CertificateStoreFilesImpl::remove_from_trusted_certificates_async(
  const std::string& thumbprint, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [tp = thumbprint](auto& base, CompleteCallback done) mutable
      { as_files(base).remove_from_trusted_certificates_internal(tp, std::move(done)); })();
  }
  catch (...)
  {
    // The thumbprint copy into the handler or the post-helper construction failed (e.g. bad_alloc)
    // before the work was queued; report synchronously via the surviving callback copy so the error
    // is never silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

void CertificateStoreFilesImpl::remove_from_issuer_certificates_async(
  const std::string& thumbprint, CertificateStore::CompleteCallback callback) noexcept
{
  try
  {
    ua::async::post_borrowing(static_cast<CertificateStore*>(this),
      mStrand,
      mLogger,
      callback,
      VoidResult{Status::BadInternalError},
      [tp = thumbprint](auto& base, CompleteCallback done) mutable
      { as_files(base).remove_from_issuer_certificates_internal(tp, std::move(done)); })();
  }
  catch (...)
  {
    // The thumbprint copy into the handler or the post-helper construction failed (e.g. bad_alloc)
    // before the work was queued; report synchronously via the surviving callback copy so the error
    // is never silently dropped (never discard an error at a boundary).
    ua::detail::invoke_user_callback(mLogger, callback, VoidResult{Status::BadOutOfMemory});
  }
}

TrustListValidationOptions CertificateStoreFilesImpl::validation_options() const
{
  return TrustListValidationOptions{mPublishedValidationOptions.load()};
}

void CertificateStoreFilesImpl::set_validation_options(TrustListValidationOptions validationOptions)
{
  mPublishedValidationOptions.store(validationOptions.as_underlying_type());
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    [validationOptions](auto& base) { as_files(base).set_validation_options_internal(validationOptions); })();
}

shared_ptr<CertificateStore> CertificateStoreFiles::create(
  boost::asio::any_io_executor executor, shared_ptr<const Crypto> crypto, CertificateStoreFilesConfig config)
{
  return CertificateStoreFilesImpl::create(std::move(executor), std::move(crypto), std::move(config));
}

shared_ptr<CertificateStore> CertificateStoreFilesImpl::create(
  boost::asio::any_io_executor executor, shared_ptr<const Crypto> crypto, CertificateStoreFilesConfig config)
{
  auto path = absolute(config.trustListPath);
  const TrustListValidationOptions validationOptions = config.validationOptions;
  const optional<std::chrono::seconds> refreshPeriod = config.refreshPeriod;
  const bool storeRejectedCertificates = config.storeRejectedCertificates;
  Logger logger = std::move(config.logger);
  const size_t maxRejectedCertificates = config.maxRejectedCertificates;
  const CertificateUse use = config.use;

  struct Wrapper : public CertificateStoreFilesImpl
  {
  public:
    Wrapper(std::filesystem::path trustListPath, boost::asio::any_io_executor executor,
      shared_ptr<const Crypto> crypto, TrustListValidationOptions validationOptions,
      bool storeRejectedCertificates, Logger logger, size_t maxRejectedCertificates, CertificateUse use)
      : CertificateStoreFilesImpl(trustListPath, executor, crypto, validationOptions,
          storeRejectedCertificates, std::move(logger), maxRejectedCertificates, use)
    {}
  };

  auto store = make_shared<Wrapper>(path,
    executor,
    crypto,
    validationOptions,
    storeRejectedCertificates,
    std::move(logger),
    maxRejectedCertificates,
    use);

  // Initial load runs synchronously - the store is not yet shared, so no strand serialization needed.
  // This lets construction failures propagate to the caller.
  store->refresh_cache_internal();

  ua::async::post_borrowing(static_cast<CertificateStore*>(store.get()),
    store->mStrand,
    store->mLogger,
    [refreshPeriod](auto& base) { as_files(base).initialise_file_system_monitoring(refreshPeriod); })();
  return store;
}

CertificateStoreFilesImpl::CertificateStoreFilesImpl(std::filesystem::path trustListPath,
  boost::asio::any_io_executor executor, shared_ptr<const Crypto> crypto,
  TrustListValidationOptions validationOptions, bool storeRejectedCertificates, Logger logger,
  size_t maxRejectedCertificates, CertificateUse use)
  : mTrustListPath(trustListPath), mCrypto(crypto), mExecutor(executor),
    mStrand(boost::asio::make_strand(executor)), mValidationOptions(validationOptions),
    mPublishedValidationOptions(validationOptions.as_underlying_type()),
    mStoreRejectedCertificates(storeRejectedCertificates), mMaxRejectedCertificates(maxRejectedCertificates),
    mUse(use), mLogger(std::move(logger))
{
  if (trustListPath.empty())
  {
    throw UaException{Status::BadInvalidArgument,
      make_error_detail("CertificateStorePath", "Trust list path must be provided", "CertificateStore")};
  }

  create_missing_directories();
}

void CertificateStoreFilesImpl::create_missing_directories()
{
  try
  {
    create_directories(mTrustListPath);
    auto trustListFolder = mTrustListPath / rootPath;
    create_directory(trustListFolder);
    create_directory(trustListFolder / applicationCertPath);
    // DEF-5: create_directory applies the process umask, which leaves the private-key directory
    // listable (022) or even writable (002) by other accounts. The directory is owner-only from the
    // moment this store creates it; one that already exists is the operator's and is left alone
    // (write_key refuses it if other users can write to it).
    {
      std::error_code keysDirectoryError;
      security::create_directories_owner_only(trustListFolder / applicationKeyPath, keysDirectoryError);
      if (keysDirectoryError)
        throw filesystem_error{"cannot create the private key directory",
          trustListFolder / applicationKeyPath,
          keysDirectoryError};
    }
    // A crash mid-replacement leaves a list under `<dir>.old` or `<dir>.new` (see
    // replace_list_directories): put it back before an empty directory is created in its place.
    certificate_store_files_detail::recover_list_directories(
      {trustListFolder / trustedCertPath, trustListFolder / trustedCrlPath});
    certificate_store_files_detail::recover_list_directories(
      {trustListFolder / issuerCertPath, trustListFolder / issuerCrlPath});
    create_directory(trustListFolder / trustedCertPath);
    create_directory(trustListFolder / trustedCrlPath);
    create_directory(trustListFolder / issuerCertPath);
    create_directory(trustListFolder / issuerCrlPath);
    create_directory(trustListFolder / rejectedCertPath);
  }
  catch (...)
  {
    detail::rethrow_as_ua_exception();
  }
}

void CertificateStoreFilesImpl::add_to_application_certificates_internal(
  CertificateStore::ApplicationCertificate certificate, CertificateStore::CompleteCallback callback)
{
  try
  {
    write_cert(
      *certificate.certificate, application_certs_path() / cert_filename(certificate.certificateType));
    // The issuer chain is stored next to the leaf as consecutive DER certificates, leaf's issuer
    // first (decision 24); an empty chain removes a chain file left by a previous certificate.
    const auto chainPath = application_certs_path() / chain_filename(certificate.certificateType);
    if (certificate.issuerCertificates.empty())
    {
      std::error_code removeError;
      std::filesystem::remove(chainPath, removeError);
    }
    else
    {
      ByteString chain;
      for (const auto& issuer : certificate.issuerCertificates)
      {
        if (!issuer)
        {
          throw UaException{Status::BadInvalidArgument,
            make_error_detail("ApplicationCertificateChainInvalid",
              "the issuer chain of an application certificate holds a null certificate",
              "CertificateStore")};
        }
        const auto der = issuer->der_encoding();
        chain.payload().insert(chain.payload().end(), der.begin(), der.end());
      }
      write_file(std::move(chain), chainPath);
    }
    write_key(certificate.certificateType, *certificate.keys);
    // On disk the store keeps exactly one certificate + key file per CertificateType, and the writes
    // above overwrite them. Mirror that in memory: replace any existing entry of the same type rather
    // than appending. Otherwise a rotated own certificate/key would be shadowed by the stale first
    // entry (get_application_certificate() returns the first match by type), so the disk and in-memory
    // views would diverge and a live rotation would never take effect.
    std::erase_if(mApplicationCertificates,
      [&certificate](const CertificateStore::ApplicationCertificate& existing)
      { return existing.certificateType == certificate.certificateType; });
    mApplicationCertificates.push_back(certificate);
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_application_certificate_internal(
  CertificateType certificateType, GetApplicationCertificateCallback callback) const
{
  for (const auto& appCert : mApplicationCertificates)
  {
    if (appCert.certificateType == certificateType)
    {
      detail::invoke_user_callback(mLogger, callback, appCert);
      return;
    }
  }
  detail::invoke_user_callback(mLogger, callback, StatusCode{Status::BadNotFound});
}

void CertificateStoreFilesImpl::get_application_certificates_internal(
  CertificateStore::GetApplicationCertificatesCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mApplicationCertificates);
}

void CertificateStoreFilesImpl::add_to_trusted_certificates_internal(
  std::vector<shared_ptr<const X509Certificate>> certificates, CertificateStore::CompleteCallback callback)
{
  try
  {
    for (auto& cert : certificates)
    {
      if (!exists(*cert, mTrustedCertificates))
      {
        mTrustedCertificates.push_back(cert);
        write_cert(*cert, trusted_certs_path() / cert_filename(*cert));
      }
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_trusted_certificates_internal(
  CertificateStore::GetCertificatesCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mTrustedCertificates);
}

void CertificateStoreFilesImpl::add_to_issuer_certificates_internal(
  std::vector<shared_ptr<const X509Certificate>> certificates, CertificateStore::CompleteCallback callback)
{
  try
  {
    for (auto& cert : certificates)
    {
      if (!exists(*cert, mIssuerCertificates))
      {
        mIssuerCertificates.push_back(cert);
        write_cert(*cert, issuer_certs_path() / cert_filename(*cert));
      }
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_issuer_certificates_internal(
  CertificateStore::GetCertificatesCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mIssuerCertificates);
}

void CertificateStoreFilesImpl::add_to_rejected_certificates_internal(
  shared_ptr<const X509Certificate> certificate, CertificateStore::CompleteCallback callback)
{
  try
  {
    if (!exists(*certificate, mRejectedCertificates))
    {
      // Bound the rejected store (anti pre-auth cert-flood DoS): an unauthenticated peer can present
      // unlimited distinct (fresh self-signed) certificates during OpenSecureChannel, each with a
      // unique thumbprint that never matches the exists() dedup. Without a cap, mRejectedCertificates
      // and the on-disk RejectedCertificates/ directory grow without bound. The rejected list is meant
      // to be a finite, operator-reviewed set (Part 12 GetRejectedList), so evict oldest-first once the
      // cap is reached (mMaxRejectedCertificates == 0 disables the bound). File removal is best-effort:
      // the in-memory cap is enforced regardless so memory cannot grow even if a file delete fails.
      while (mMaxRejectedCertificates > 0 && mRejectedCertificates.size() >= mMaxRejectedCertificates &&
             !mRejectedCertificates.empty())
      {
        const auto& oldest = mRejectedCertificates.front();
        try
        {
          remove_cert_file(rejected_certs_path(), *oldest);
        }
        catch (const std::filesystem::filesystem_error&)
        {
          // Best-effort, as above: the in-memory cap holds even when the file stays.
          detail::ignore_expected_exception();
        }
        mRejectedCertificates.erase(mRejectedCertificates.begin());
      }
      mRejectedCertificates.push_back(certificate);
      write_cert(*certificate, rejected_certs_path() / cert_filename(*certificate));
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_rejected_certificates_internal(
  CertificateStore::GetCertificatesCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mRejectedCertificates);
}

void CertificateStoreFilesImpl::add_to_trusted_crls_internal(
  std::vector<shared_ptr<const X509Crl>> crls, CertificateStore::CompleteCallback callback)
{
  try
  {
    for (auto& crl : crls)
    {
      if (!exists(*crl, mTrustedCrls))
      {
        mTrustedCrls.push_back(crl);
        write_crl(*crl, trusted_crls_path() / crl_filename(*crl));
      }
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_trusted_crls_internal(CertificateStore::GetCrlsCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mTrustedCrls);
}

void CertificateStoreFilesImpl::add_to_issuer_crls_internal(
  std::vector<shared_ptr<const X509Crl>> crls, CertificateStore::CompleteCallback callback)
{
  try
  {
    for (auto& crl : crls)
    {
      if (!exists(*crl, mIssuerCrls))
      {
        mIssuerCrls.push_back(crl);
        write_crl(*crl, issuer_crls_path() / crl_filename(*crl));
      }
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::get_issuer_crls_internal(CertificateStore::GetCrlsCallback callback) const
{
  detail::invoke_user_callback(mLogger, callback, mIssuerCrls);
}

void CertificateStoreFilesImpl::replace_trusted_certificates_internal(
  CertificateList certificates, CrlList crls, CertificateStore::CompleteCallback callback)
{
  try
  {
    // The new lists are written beside the current ones and swapped into place together (security
    // review B3-3): a write failure part-way, or a crash, leaves the current lists intact instead
    // of deleted-then-half-written ones, and the cache follows the files.
    certificate_store_files_detail::replace_list_directories({
      {trusted_certs_path(),
        [&](const path& into)
        {
          for (const auto& cert : certificates)
            write_cert(*cert, into / cert_filename(*cert));
        },
        {}},
      {trusted_crls_path(),
        [&](const path& into)
        {
          for (const auto& crl : crls)
            write_crl(*crl, into / crl_filename(*crl));
        },
        {}},
    });
    mTrustedCertificates = std::move(certificates);
    mTrustedCrls = std::move(crls);
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::replace_issuer_certificates_internal(
  CertificateList certificates, CrlList crls, CertificateStore::CompleteCallback callback)
{
  try
  {
    // Same atomic swap as the trusted lists (see replace_trusted_certificates_internal).
    certificate_store_files_detail::replace_list_directories({
      {issuer_certs_path(),
        [&](const path& into)
        {
          for (const auto& cert : certificates)
            write_cert(*cert, into / cert_filename(*cert));
        },
        {}},
      {issuer_crls_path(),
        [&](const path& into)
        {
          for (const auto& crl : crls)
            write_crl(*crl, into / crl_filename(*crl));
        },
        {}},
    });
    mIssuerCertificates = std::move(certificates);
    mIssuerCrls = std::move(crls);
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

namespace
{

VoidResult malformed_thumbprint()
{
  return VoidResult{StatusCode{Status::BadInvalidArgument,
    make_error_detail("ThumbprintMalformed",
      "The thumbprint is not 40 hexadecimal digits (a SHA-1 thumbprint)",
      "CertificateStoreFiles")}};
}

}  // namespace

void CertificateStoreFilesImpl::remove_from_trusted_certificates_internal(
  const std::string& thumbprint, CertificateStore::CompleteCallback callback)
{
  try
  {
    // Decision 28: decoded to bytes and compared as bytes (either case; no lost zero padding).
    const auto wanted = detail::decode_thumbprint(thumbprint);
    if (!wanted)
    {
      detail::invoke_user_callback(mLogger, callback, malformed_thumbprint());
      return;
    }
    auto it = std::find_if(mTrustedCertificates.begin(),
      mTrustedCertificates.end(),
      [&](const shared_ptr<const X509Certificate>& cert)
      { return detail::thumbprint_matches(*cert, *wanted); });

    if (it != mTrustedCertificates.end())
    {
      remove_cert_file(trusted_certs_path(), **it);
      mTrustedCertificates.erase(it);
    }
    else
    {
      detail::invoke_user_callback(mLogger, callback, VoidResult{StatusCode{Status::BadNotFound}});
      return;
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::remove_from_issuer_certificates_internal(
  const std::string& thumbprint, CertificateStore::CompleteCallback callback)
{
  try
  {
    // Decision 28: decoded to bytes and compared as bytes (either case; no lost zero padding).
    const auto wanted = detail::decode_thumbprint(thumbprint);
    if (!wanted)
    {
      detail::invoke_user_callback(mLogger, callback, malformed_thumbprint());
      return;
    }
    auto it = std::find_if(mIssuerCertificates.begin(),
      mIssuerCertificates.end(),
      [&](const shared_ptr<const X509Certificate>& cert)
      { return detail::thumbprint_matches(*cert, *wanted); });

    if (it != mIssuerCertificates.end())
    {
      remove_cert_file(issuer_certs_path(), **it);
      mIssuerCertificates.erase(it);
    }
    else
    {
      detail::invoke_user_callback(mLogger, callback, VoidResult{StatusCode{Status::BadNotFound}});
      return;
    }
  }
  catch (...)
  {
    detail::invoke_user_callback(mLogger, callback, ua::exception_to_status_code(std::current_exception()));
    return;
  }
  detail::invoke_user_callback(mLogger, callback, VoidResult{});
}

void CertificateStoreFilesImpl::set_validation_options_internal(
  const TrustListValidationOptions& validationOptions)
{
  mValidationOptions = validationOptions;
}

void CertificateStoreFilesImpl::refresh_cache_internal()
{
  mTrustedCertificates.clear();
  mTrustedCrls.clear();
  mIssuerCertificates.clear();
  mIssuerCrls.clear();
  mApplicationCertificates.clear();
  mRejectedCertificates.clear();

  std::exception_ptr unreadableCrl;
  read_trusted_certs();
  read_trusted_crls(unreadableCrl);
  read_issuer_certs();
  read_issuer_crls(unreadableCrl);
  read_application_certs();
  read_rejected_certs();
  if (unreadableCrl)
  {
    // Revocation cannot be checked against a CRL the store cannot read, and an older CRL of the same
    // issuer may have loaded in its place: no certificate is trusted until a refresh reads them all.
    mTrustedCertificates.clear();
    mTrustedCrls.clear();
    mIssuerCertificates.clear();
    mIssuerCrls.clear();
    std::rethrow_exception(unreadableCrl);
  }
}

void CertificateStoreFilesImpl::read_certs(auto& list, const path& folder)
{
  for (const auto& dirEntry : directory_iterator{folder})
  {
    if (dirEntry.is_regular_file())
    {
      auto cert = read_cert(dirEntry.path());
      if (cert)
      {
        list.push_back(cert);
      }
    }
  }
}

void CertificateStoreFilesImpl::read_crls(auto& list, const path& folder, std::exception_ptr& unreadable)
{
  for (const auto& dirEntry : directory_iterator{folder})
  {
    if (dirEntry.is_regular_file())
    {
      try
      {
        auto crl = read_crl(dirEntry.path());
        if (crl)
        {
          list.push_back(crl);
        }
      }
      catch (...)
      {
        if (!unreadable)
          unreadable = std::current_exception();
      }
    }
  }
}

void CertificateStoreFilesImpl::read_application_certs()
{
  auto certFolder = application_certs_path();

  for (const auto& entry : gCertTypes)
  {
    auto filepath = certFolder / cert_filename(entry.first);
    auto cert = read_cert(filepath);
    if (!cert)
    {
      continue;
    }
    auto key = read_key(entry.first);
    if (!key)
    {
      continue;
    }

    ApplicationCertificate applicationCertificate;
    applicationCertificate.certificateType = entry.first;
    applicationCertificate.certificate = cert;
    applicationCertificate.keys = key;
    // The issuer chain stored next to the leaf (absent for a self-signed certificate).
    try
    {
      if (auto chain = read_file(certFolder / chain_filename(entry.first)); !chain.empty())
      {
        applicationCertificate.issuerCertificates = mCrypto->read_certificates_from_der(chain);
      }
    }
    catch (...)
    {
      // The leaf is still usable; a peer that needs the chain fails validation and says so.
      report_unreadable_file(certFolder / chain_filename(entry.first), std::current_exception());
    }
    mApplicationCertificates.push_back(applicationCertificate);
  }
}

void CertificateStoreFilesImpl::read_trusted_certs()
{
  read_certs(mTrustedCertificates, trusted_certs_path());
}

void CertificateStoreFilesImpl::read_trusted_crls(std::exception_ptr& unreadable)
{
  read_crls(mTrustedCrls, trusted_crls_path(), unreadable);
}

void CertificateStoreFilesImpl::read_issuer_certs()
{
  read_certs(mIssuerCertificates, issuer_certs_path());
}

void CertificateStoreFilesImpl::read_issuer_crls(std::exception_ptr& unreadable)
{
  read_crls(mIssuerCrls, issuer_crls_path(), unreadable);
}

void CertificateStoreFilesImpl::read_rejected_certs()
{
  read_certs(mRejectedCertificates, rejected_certs_path());
}

// A certificate file that cannot be read or parsed is left out of its list and reported, so one bad file (a
// PEM file, a file still being copied) does not stop the rest of the trust list loading. Leaving it out
// cannot widen trust: an unread certificate is not trusted.
shared_ptr<const X509Certificate> CertificateStoreFilesImpl::read_cert(const path& filepath) const
{
  try
  {
    auto bytes = read_file(filepath);
    if (bytes.empty())
    {
      return {};
    }
    return mCrypto->read_certificate_from_der(bytes);
  }
  catch (...)
  {
    report_unreadable_file(filepath, std::current_exception());
    return {};
  }
}

shared_ptr<const X509Crl> CertificateStoreFilesImpl::read_crl(const path& filepath) const
{
  try
  {
    auto bytes = read_file(filepath);
    if (bytes.empty())
    {
      return {};
    }
    return mCrypto->read_crl_from_der(bytes);
  }
  catch (...)
  {
    // Not left out like a certificate: an older CRL of the same issuer may still load, and checking
    // revocation against it would accept a certificate the unread CRL revokes (refresh_cache_internal).
    report_unreadable_file(filepath, std::current_exception());
    throw;
  }
}

void CertificateStoreFilesImpl::report_unreadable_file(const path& filepath, std::exception_ptr error) const
{
  const auto status = ua::exception_to_status_code(error);
  mLogger.error({{"file_path", std::string_view{filepath.string()}}},
    "Certificate store file left out: it cannot be read or parsed ({} {})",
    to_string(status.as_status()),
    status.shared_detail() ? status.shared_detail()->summary : "");
}

shared_ptr<const AsymmetricKeyPair> CertificateStoreFilesImpl::read_key(CertificateType type) const
{
  auto filepath = application_keys_path() / key_filename(type);
  if (auto search = gCertTypes.find(type); search != gCertTypes.end())
  {
    auto bytes = read_file(filepath);
    if (bytes.empty())
    {
      return {};
    }
    try
    {
      return mCrypto->get_private_key_from_pem(search->second.second, bytes);
    }
    catch (const std::exception& ex)
    {
      mLogger.info("Failed to load private key from {}: {}", filepath.string(), ex.what());
      return {};
    }
    catch (...)
    {
      mLogger.info("Failed to load private key from {}", filepath.string());
      return {};
    }
  }
  else
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("CertificateNotFound", "Unknown certificate type for key lookup", "CertificateStore")
        .context(ua::ContextKeys::typeId, std::to_string(static_cast<int>(type)))};
  }
}

// A file is named by its SHA-1 thumbprint as 40 hexadecimal digits, two per byte. Earlier releases wrote
// each byte without its leading zero, which made two different thumbprints able to share one file name;
// legacy_cert_filename is that name, still removed when a certificate is (see remove_cert_file).
std::string CertificateStoreFilesImpl::cert_filename(const X509Certificate& certificate) const
{
  return fmt::format("{:02X}", fmt::join(certificate.thumbprint(), "")) + ".der";
}

std::string CertificateStoreFilesImpl::crl_filename(const X509Crl& crl) const
{
  return fmt::format("{:02X}", fmt::join(crl.thumbprint(), "")) + ".crl";
}

std::string CertificateStoreFilesImpl::legacy_cert_filename(const X509Certificate& certificate) const
{
  return fmt::format("{:X}", fmt::join(certificate.thumbprint(), "")) + ".der";
}

void CertificateStoreFilesImpl::remove_cert_file(
  const std::filesystem::path& directory, const X509Certificate& certificate) const
{
  // Throws when a file exists and cannot be removed, so the caller reports the failure.
  if (!std::filesystem::remove(directory / cert_filename(certificate)))
  {
    // A store written by an earlier release names the file without zero padding. Removed only when that
    // file holds this certificate, because such a name can also belong to another one.
    const auto legacy = directory / legacy_cert_filename(certificate);
    std::ifstream in{legacy, std::ios::binary};
    const std::vector<char> bytes{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    const auto der = certificate.der_encoding();
    in.close();
    if (!bytes.empty() && bytes.size() == der.size() &&
        std::equal(bytes.begin(),
          bytes.end(),
          der.begin(),
          [](char a, auto b) { return static_cast<unsigned char>(a) == static_cast<unsigned char>(b); }))
    {
      std::filesystem::remove(legacy);
    }
  }
}

std::string CertificateStoreFilesImpl::cert_filename(CertificateType certificateType) const
{
  if (auto search = gCertTypes.find(certificateType); search != gCertTypes.end())
  {
    return "ApplicationCert" + search->second.first + ".der";
  }
  else
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateNotFound", "Unknown certificate type for cert filename lookup", "CertificateStore")
        .context(ua::ContextKeys::typeId, std::to_string(static_cast<int>(certificateType)))};
  }
}

std::string CertificateStoreFilesImpl::chain_filename(CertificateType certificateType) const
{
  if (auto search = gCertTypes.find(certificateType); search != gCertTypes.end())
  {
    return "ApplicationCertChain" + search->second.first + ".der";
  }
  throw UaException{Status::BadInvalidArgument,
    ErrorDetail::build(
      "CertificateNotFound", "Unknown certificate type for chain filename lookup", "CertificateStore")
      .context(ua::ContextKeys::typeId, std::to_string(static_cast<int>(certificateType)))};
}

std::string CertificateStoreFilesImpl::key_filename(CertificateType certificateType) const
{
  if (auto search = gCertTypes.find(certificateType); search != gCertTypes.end())
  {
    return "ApplicationPrivateKey" + search->second.first + ".pem";
  }
  else
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateNotFound", "Unknown certificate type for key filename lookup", "CertificateStore")
        .context(ua::ContextKeys::typeId, std::to_string(static_cast<int>(certificateType)))};
  }
}

void CertificateStoreFilesImpl::write_file(ByteString content, const path& filepath)
{
  FileStream fs{filepath.string()};
  auto status = fs.open_for_write(true, false);
  if (status.is_bad())
  {
    throw UaException{status.as_status(),
      ErrorDetail::build("CertificateLoadFailed", "Could not open file for write", "CertificateStore")
        .context(ua::ContextKeys::filePath, filepath.string())};
  }
  fs.write_all(content);
}

ByteString CertificateStoreFilesImpl::read_file(const path& filepath) const
{
  ByteString result;
  FileStream fs{filepath.string()};
  auto status = fs.open_for_read();
  if (status.is_good())
  {
    result.resize(fs.get_length());
    fs.read_all(result);
  }
  return result;
}

void CertificateStoreFilesImpl::write_cert(const X509Certificate& certificate, const path& filepath)
{
  write_file(certificate.der_encoding(), filepath);
}

void CertificateStoreFilesImpl::write_crl(const X509Crl& crl, const path& filepath)
{
  write_file(crl.der_encoding(), filepath);
}

void CertificateStoreFilesImpl::write_key(CertificateType type, const AsymmetricKeyPair& keyPair)
{
  // DEF-5: a private key on disk is a secret. The old path created the file through fopen() (which
  // honours the umask and follows a planted symlink) and chmod-ed it afterwards, logging a failure at
  // info level. The key is now written to a fresh, exclusively created, owner-only temporary file
  // beside its target and renamed over it: rename replaces a planted symlink instead of following
  // it, no reader ever sees a world-readable or partial key, and every failure is an error.
  const auto keysDirectory = application_keys_path();
  const auto filepath = keysDirectory / key_filename(type);
  std::error_code error;
  const bool createdDirectory = security::create_directories_owner_only(keysDirectory, error);
  const auto temporary =
    keysDirectory / (key_filename(type) + ".tmp." + ua::to_string(Guid::create_and_generate()));
  const auto fail = [&](std::string_view what, StatusCode cause)
  {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("PrivateKeyWriteFailed", std::string{what}, "CertificateStore")
        .context(ua::ContextKeys::filePath, filepath.string())
        .cause(std::move(cause))};
  };
  if (createdDirectory && error)
    fail("Could not make the private key directory owner-only", StatusCode{Status::BadUnknownResponse});
#ifndef _WIN32
  // A pre-existing directory is the operator's, but a key must not land where another account can
  // unlink or replace it after the rename.
  {
    const auto directoryStatus = std::filesystem::status(keysDirectory, error);
    const auto perms = directoryStatus.permissions();
    if (!error && ((perms & std::filesystem::perms::group_write) != std::filesystem::perms::none ||
                    (perms & std::filesystem::perms::others_write) != std::filesystem::perms::none))
      fail(
        "The private key directory is writable by other users", StatusCode{Status::BadSecurityChecksFailed});
  }
#endif
  {
    FileStream stream{temporary.string()};
    const auto opened = stream.open_for_exclusive_write();
    if (opened.is_bad())
      fail("Could not create the private key file exclusively", opened);
    try
    {
      stream.write_all(keyPair.private_key_pem());
      stream.close();
    }
    catch (...)
    {
      fail("Could not write the private key file", ua::exception_to_status_code(std::current_exception()));
    }
  }
#ifdef _WIN32
  // CREATE_NEW gives no owner-only mode on Windows; the nearest equivalent is applied afterwards.
  std::filesystem::permissions(temporary,
    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
    std::filesystem::perm_options::replace,
    error);
  if (error)
    fail("Could not restrict the private key file's permissions", StatusCode{Status::BadUnknownResponse});
#endif
  std::filesystem::rename(temporary, filepath, error);
  if (error)
    fail("Could not move the private key file into place", StatusCode{Status::BadUnknownResponse});
}

std::filesystem::path CertificateStoreFilesImpl::trusted_certs_path() const
{
  return mTrustListPath / rootPath / trustedCertPath;
}

std::filesystem::path CertificateStoreFilesImpl::trusted_crls_path() const
{
  return mTrustListPath / rootPath / trustedCrlPath;
}

std::filesystem::path CertificateStoreFilesImpl::issuer_certs_path() const
{
  return mTrustListPath / rootPath / issuerCertPath;
}

std::filesystem::path CertificateStoreFilesImpl::issuer_crls_path() const
{
  return mTrustListPath / rootPath / issuerCrlPath;
}

std::filesystem::path CertificateStoreFilesImpl::rejected_certs_path() const
{
  return mTrustListPath / rootPath / rejectedCertPath;
}

std::filesystem::path CertificateStoreFilesImpl::application_certs_path() const
{
  return mTrustListPath / rootPath / applicationCertPath;
}

std::filesystem::path CertificateStoreFilesImpl::application_keys_path() const
{
  return mTrustListPath / rootPath / applicationKeyPath;
}

bool CertificateStoreFilesImpl::store_to_rejected(Status status, const TrustListValidationOptions& options)
{
  using Bit = TrustListValidationOptions::Bit;
  // A certificate goes to the rejected store when trusting it is the administrator's decision to
  // make: it is untrusted/URI-invalid outright, or its failure is one the caller opted to suppress
  // (treating it as a soft, recordable rejection). A certificate whose issuer is unknown
  // (Bad_CertificateChainIncomplete) is the administrator's to review and trust exactly as an
  // untrusted one is. An expired, revoked or policy-violating certificate is not filed: trusting it
  // would not make it acceptable.
  return status == Status::BadCertificateUntrusted || status == Status::BadCertificateChainIncomplete ||
         status == Status::BadCertificateUriInvalid ||
         (status == Status::BadCertificateHostNameInvalid && options.test(Bit::SuppressHostNameInvalid)) ||
         (status == Status::BadCertificateRevocationUnknown &&
           options.test(Bit::SuppressRevocationStatusUnknown)) ||
         (status == Status::BadCertificateIssuerRevocationUnknown &&
           options.test(Bit::SuppressIssuerRevocationStatusUnknown));
}

void CertificateStoreFilesImpl::validate_certificate_async(
  CertificateValidationRequest request, Crypto::CertificateValidationCompleteCallback callback) noexcept
{
  // The validation verdict (Result<void>) flows back through `completed`, which re-posts onto the
  // store's strand so the RejectedCertificates persist side effect runs serialized before the verdict
  // is delivered. post_borrowing owns the user callback and delivers BadInternalError on the can't-run
  // paths (the store is gone, or a post cannot be queued).
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [request = std::move(request)](auto& base, Crypto::CertificateValidationCompleteCallback done) mutable
    {
      auto& self = as_files(base);
      auto weak = self.weak_from_this();

      // The store fills what the request leaves open: its options and the use it was created for.
      if (!request.options)
      {
        request.options = self.mValidationOptions;
      }
      if (!request.use)
      {
        request.use = self.mUse;
      }

      // CL-SECADMIN-003: a per-connection trust decision widens the trust list for this validation only and
      // changes nothing else the validator checks (owner decision 22.5): the accepted certificate is one
      // more trusted certificate, and its chain must still reach a self-signed root through the trusted
      // list, the issuer list or the presented certificates, whose CRLs are consulted as configured.
      CertificateValidationMaterial material;
      material.trusted.reserve(self.mTrustedCertificates.size() + request.trustedForThisConnection.size());
      material.trusted.insert(
        material.trusted.end(), self.mTrustedCertificates.begin(), self.mTrustedCertificates.end());
      material.trusted.insert(material.trusted.end(),
        request.trustedForThisConnection.begin(),
        request.trustedForThisConnection.end());
      material.issuers = self.mIssuerCertificates;
      material.trustedCrls = self.mTrustedCrls;
      material.issuerCrls = self.mIssuerCrls;
      material.options = *request.options;

      const auto certificate = request.certificate;
      const auto options = *request.options;
      auto completed = [weak, certificate, options, done = std::move(done)](Result<void> result) mutable
      {
        auto me = lock_self(weak);
        if (!me)
        {
          ua::detail::invoke_user_callback(done, VoidResult{Status::BadInternalError});
          return;
        }
        // Re-post onto the store's own strand so the rejected-cert persistence runs serialized before
        // the verdict is delivered; post_borrowing keeps ownership of the user callback. Only the leaf
        // is filed: the presented issuers are the peer's chain material, not the refused certificate.
        ua::async::post_borrowing(static_cast<CertificateStore*>(me.get()),
          me->mStrand,
          me->mLogger,
          std::move(done),
          VoidResult{Status::BadInternalError},
          [certificate, options, result = std::move(result)](
            auto& innerBase, Crypto::CertificateValidationCompleteCallback innerDone) mutable
          {
            auto& innerSelf = as_files(innerBase);
            if (innerSelf.mStoreRejectedCertificates &&
                store_to_rejected(result.status_code().as_status(), options))
            {
              auto persistWeak = innerSelf.weak_from_this();
              innerSelf.add_to_rejected_certificates_async(certificate,
                [persistWeak, done = std::move(innerDone), result](VoidResult persistResult) mutable
                {
                  // Persisting to the RejectedCertificates store is a best-effort,
                  // server-side bookkeeping side effect; the validation verdict is already
                  // decided and must not change (OPC 10000-4 certificate handling). A persist
                  // failure (e.g. filesystem error) is therefore non-fatal to the verdict, but
                  // must be logged so operators retain visibility - never silently discarded.
                  if (persistResult.is_bad())
                  {
                    if (auto persistSelf = lock_self(persistWeak))
                    {
                      const auto persistStatus = persistResult.status_code();
                      persistSelf->mLogger.error(
                        "Failed to persist rejected certificate to RejectedCertificates store: {} {}",
                        to_string(persistStatus.as_status()),
                        persistStatus.shared_detail() ? persistStatus.shared_detail()->summary : "");
                    }
                  }
                  ua::detail::invoke_user_callback(done, result);
                });
            }
            else
            {
              ua::detail::invoke_user_callback(innerDone, result);
            }
          })();
      };

      self.mCrypto->validate_certificate_async(request, std::move(material), std::move(completed));
    })();
}

void CertificateStoreFilesImpl::initialise_file_system_monitoring(
  optional<std::chrono::seconds> refreshPeriod)
{
  if (!refreshPeriod.has_value())
  {
    return;
  }

  auto weak = weak_from_this();

  mRefreshTimer = Timer::schedule_every(mStrand,
    refreshPeriod.value(),
    [weak](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      if (auto self = lock_self(weak))
      {
        self->test_filesystem_for_changes();
      }
    });
}

void CertificateStoreFilesImpl::test_filesystem_for_changes()
{
  try
  {
    auto trustListFolder = mTrustListPath / rootPath;
    std::multimap<std::string, std::filesystem::file_time_type> filesystemStatus;

    for (const auto& dirEntry : recursive_directory_iterator{trustListFolder})
    {
      if (dirEntry.is_regular_file())
      {
        filesystemStatus.insert(std::pair{dirEntry.path().filename().string(), dirEntry.last_write_time()});
      }
    }

    if (filesystemStatus != mLastFilesystemStatus)
    {
      mLastFilesystemStatus = std::move(filesystemStatus);
      refresh_cache_internal();
    }
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    mLogger.error("Failed to refresh certificate store: {} {}",
      to_string(er.as_status()),
      er.shared_detail() ? er.shared_detail()->summary : "");
  }
}

void CertificateStoreFilesImpl::refresh_cache(CompleteCallback callback)
{
  ua::async::post_borrowing(static_cast<CertificateStore*>(this),
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{Status::BadInternalError},
    [](auto& base, CompleteCallback done) mutable
    {
      auto& self = as_files(base);
      try
      {
        self.refresh_cache_internal();
      }
      catch (...)
      {
        done(ua::exception_to_status_code(std::current_exception()));
        return;
      }
      done(VoidResult{});
    })();
}

template<typename T>
bool CertificateStoreFilesImpl::exists(
  const T& item, const std::vector<shared_ptr<const T>>& collection) const
{
  for (const auto& entry : collection)
  {
    if (item == *entry)
    {
      return true;
    }
  }
  return false;
}
}  // namespace ua
