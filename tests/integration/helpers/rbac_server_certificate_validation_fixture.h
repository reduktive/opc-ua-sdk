// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#pragma once

/// @file
/// @brief The `RbacServerCertificateValidation` fixture, shared by the certificate-validation
///        tests and by the certificate-structure vector tests that are withheld from the public
///        snapshot. It lives in a header so that withholding those vectors costs only the two
///        tests that need them, rather than every test built on this fixture.

#include "role_based_security_fixture.h"

#include "ua_date_time.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"

#include <deque>
#include <future>
#include <memory>
#include <string>

/// The RBAC server plus the machinery to allocate shaped certificates through the production `Crypto`
/// and present them to it as a client application instance certificate.
///
/// Every extra client gets its own file-backed store (the concrete `CertificateStoreFiles` the SDK
/// ships) holding the shaped certificate as its application certificate and the fixture's server
/// certificate as trusted - so a refused channel is always the SERVER's verdict on the client
/// certificate and never the client's verdict on the server.
class RbacServerCertificateValidation : public ComplianceRoleBasedSecurity
{
protected:
  void TearDown() override
  {
    // The extra Clients must be destroyed while their executor is still running; the base TearDown
    // stops the pools.
    mExtraClients.clear();
    ComplianceRoleBasedSecurity::TearDown();
  }

  std::shared_ptr<const AsymmetricKeyPair> new_rsa_keys(size_t bits)
  {
    return mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, bits);
  }

  /// Issue a certificate through the production `Crypto`. Records a non-fatal failure and returns
  /// null when issuance itself fails, so a allocating problem can never be mistaken for a validation
  /// verdict.
  std::shared_ptr<const X509Certificate> allocate(
    const Crypto::CreateCertificateConfig& params, const char* what)
  {
    std::promise<CertificateResult> promise;
    mCrypto->create_certificate_async(
      params, [&promise](CertificateResult result) { promise.set_value(std::move(result)); });
    auto result = promise.get_future().get();
    if (result.is_bad())
    {
      ADD_FAILURE() << "could not allocate " << what << ": " << result.status_code().value();
      return {};
    }
    return std::move(result).value();
  }

  /// Parameters for a self-signed root CA: cA=TRUE, keyCertSign + cRLSign, in date.
  Crypto::CreateCertificateConfig root_ca_params(const std::shared_ptr<const AsymmetricKeyPair>& keys,
    const std::string& serialNumber, const std::string& commonName,
    CertificateSignatureAlgorithm algorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256)
  {
    Crypto::CreateCertificateConfig params;
    params.serialNumber = serialNumber;
    params.subject.commonName = commonName;
    params.subjectKeys = keys;
    params.issuerKeys = keys;
    params.certificateSignatureAlgorithm = algorithm;
    params.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
    params.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
    params.basicConstraint.cA = true;
    params.keyUsage.digitalSignature = true;
    params.keyUsage.keyCertSign = true;
    params.keyUsage.crlSign = true;
    return params;
  }

  /// The ApplicationUri a shaped identity uses, both in its certificate SAN and in the
  /// ApplicationDescription of the Client that presents it, so the two always agree.
  static std::string identity_uri(const std::string& label)
  {
    return "urn:test:secadmin:" + label;
  }

  /// Parameters for a CA-issued application instance certificate that satisfies Part 6 section 6.2.2
  /// Table 43 in full: all four RSA keyUsage bits, clientAuth extendedKeyUsage, cA=FALSE, and the
  /// SAN shape the fixture's own (accepted) client certificate carries. Each test then breaks
  /// exactly one field of this, so a refusal is attributable to that field alone.
  Crypto::CreateCertificateConfig conformant_leaf_params(const std::shared_ptr<const X509Certificate>& issuer,
    const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
    const std::shared_ptr<const AsymmetricKeyPair>& subjectKeys, const std::string& serialNumber,
    const std::string& commonName, const std::string& label)
  {
    const std::string applicationUri = identity_uri(label);
    Crypto::CreateCertificateConfig params;
    params.serialNumber = serialNumber;
    params.subject.commonName = commonName;
    params.subjectKeys = subjectKeys;
    params.issuer = issuer;
    params.issuerKeys = issuerKeys;
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    params.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
    params.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
    params.keyUsage.digitalSignature = true;
    params.keyUsage.nonRepudiation = true;
    params.keyUsage.keyEncipherment = true;
    params.keyUsage.dataEncipherment = true;
    params.keyUsage.clientAuth = true;
    params.basicConstraint.cA = false;
    params.subjectAlternateName.uris.push_back(applicationUri);
    params.subjectAlternateName.hostnames.push_back("localhost");
    return params;
  }

  /// Present `certificate` to the fixture's running server as the client application instance
  /// certificate, over a fresh channel in `mode`. Returns the whole result so a caller can keep the
  /// channel; the Client is retained by the fixture for the test's lifetime.
  ///
  /// `mode` defaults to SignAndEncrypt / Basic256Sha256 - the secured endpoint, where the server
  /// evaluates the certificate. Passing None selects the fixture's None / None endpoint, which is
  /// what `AC-SVR-SECADMIN-015` needs: the same identity presented to an endpoint that must not
  /// evaluate it. As in `ComplianceRoleBasedSecurity::open_channel`, no expected server certificate
  /// is configured for None, since none is exchanged.
  ua::client::CoreClient::SecureChannelResult open_channel_as(
    const std::shared_ptr<const X509Certificate>& certificate,
    const std::shared_ptr<const AsymmetricKeyPair>& keys, const std::string& label,
    MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt)
  {
    // `label` also names this client's store directory, so a test that presents ONE certificate over
    // TWO channels has to give it two labels - and deriving the applicationUri from the label then
    // makes the ApplicationDescription claim an identity the presented certificate does not carry.
    // `Client::create` rejects that itself, before any wire traffic, with BadCertificateUriInvalid:
    // Part 6 section 6.2.2 Table 43 requires the subjectAltName to include a uniformResourceIdentifier
    // equal to the applicationUri. Take the URI from the certificate's own SAN and leave `label`
    // naming only the store.
    const auto sanUris = certificate->san_uris();
    const std::string applicationUri = sanUris.empty() ? identity_uri(label) : sanUris.front();
    const auto storePath = mTempDir / ("secadmin_store_" + label);
    std::filesystem::create_directories(storePath);
    auto store =
      CertificateStoreFiles::create(mClientThreadPool.executor(), mCrypto, {.trustListPath = storePath});

    ua::CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = certificate;
    appCert.keys = keys;
    store->add_to_application_certificates_sync(appCert);
    store->add_to_trusted_certificates_sync(mServerCert);

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = applicationUri;
    ua::client::CreateConfig createConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    mExtraClients.push_back(ua::client::Client::create(mClientThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = store,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug}));

    ua::client::CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = mEndpointUrl;
    channelConfig.securityMode = mode;
    channelConfig.securityPolicyId =
      (mode == MessageSecurityMode::None) ? SecurityPolicyId::None : SecurityPolicyId::Basic256Sha256;
    if (mode != MessageSecurityMode::None)
    {
      channelConfig.serverCertificate = mServerCert;
    }
    return mExtraClients.back().core().try_open_channel_sync(std::move(channelConfig));
  }

  /// `open_channel_as` reduced to the StatusCode the CLIENT is told, closing any channel that did
  /// open so the server is not left holding it.
  StatusCode channel_status_as(const std::shared_ptr<const X509Certificate>& certificate,
    const std::shared_ptr<const AsymmetricKeyPair>& keys, const std::string& label,
    MessageSecurityMode mode = MessageSecurityMode::SignAndEncrypt)
  {
    auto result = open_channel_as(certificate, keys, label, mode);
    const StatusCode status = result.status_code();
    if (result.is_good())
    {
      auto channel = std::move(result).value();
      (void)channel.try_close_sync();
    }
    return status;
  }

  // A deque, not a vector: an open SecureChannel outlives the call that created its Client, and a
  // reallocation would move the Client out from under it.
  std::deque<ua::client::Client> mExtraClients;
};
