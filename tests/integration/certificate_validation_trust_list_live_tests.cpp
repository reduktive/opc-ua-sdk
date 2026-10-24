// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief I3: certificate validation on LIVE connections and on the remaining real server paths, over all 11
///        SecurityPolicies x {Sign, SignAndEncrypt} (certificate coverage review "Integration scope").
///
///   - TrustList CloseAndUpdate removing the client's trust closes its channel and a reconnect is refused
///     (Part 12 7.8.2: an update closes sessions holding a certificate no longer trusted); adding trust makes
///     the reconnect succeed; a pushed CRL revoking the client's certificate refuses it.
///   - UpdateCertificate through the push service refuses a certificate violating the endpoint policy it
///     serves (approved G), with a compliant certificate as the control.
///   - Server startup refusal: Bad_ConfigurationError naming the endpoint for a non-compliant own certificate
///     (approved F), with a compliant certificate as the control.
///   - ActivateSession with an X509 user token carrying a chain is accepted; a faulty one is
///     Bad_IdentityTokenRejected and the authenticator is never called (approved item 8).
///   - Completeness review 2026-10-02 (C3, C8-C10, C12, C13 and decision 24 server side): the presented chain
///     kept across renewals and pushes; renew with the same leaf (decision 26); the user-token group live; a
///     secured token policy on a None channel; rotation with a chain; UpdateCertificate issuer checks; issuer
///     CRL, AddCertificate and RemoveCertificate live; CloseAndUpdate DiagnosticInfo; GetRejectedList over
///     the wire; suppressed errors per path; the X509 Table 106 cause; LDS registration with chains; the
///     server sending its own chain (OPN, GetEndpoints, an oversized chain). Rows whose variable is not the
///     server reuse a cached server (MatrixCache).
///
/// REUSE: PKI once per binary, keys from the test key cache, the shared pools of MatrixCache. Each row here
/// starts its own server: the TrustList and UpdateCertificate rows change the server's trust or certificate
/// state, and the startup rows test the start itself, so a reused server would carry one row's state into the
/// next; the X509 rows need a user-token store the cached servers do not have.
/// TIER: tier 2 throughout. The TrustList and UpdateCertificate methods are called through
/// Connection::service_requests().try_call_sync, the tier-2 surface for Call (no typed push facade exists).
/// UpdateCertificate requires an encrypted channel (Part 12 7.10.4), so its rows run on SignAndEncrypt only.
///
/// Assumed API beyond the approved proposal (owner decision needed):
/// `client::X509Identity::issuerCertificates` (the issuer chain sent in the X509IdentityToken's
/// certificateData, OPC 10000-4 7.41.5), in addition to
/// `CertificateStore::ApplicationCertificate::issuerCertificates` (see the fixture header).

#include <iostream>
#include "ua_to_string.h"
#include "certificate_validation_integration_fixture.h"
#include "ua_client_own_cert_validation_test_access.h"

#include "ua_binary_codec.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_trust_list_data_type.h"
#include "ua_client_observers.h"
#include "ua_core_client.h"
#include "ua_discovery_registration.h"
#include "ua_lds_registrar.h"
#include "ua_registered_server.h"
#include "ua_user_identity.h"
#include "sanitizer_budget.h"

#include <concepts>
#include <future>
#include <type_traits>

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::test_helpers::certificate_validation;

namespace
{

class DisconnectRecorder : public client::ConnectionObserver
{
public:
  void on_disconnected(const client::Connection& /*connection*/, StatusCode reason,
    std::shared_ptr<const ErrorDetail> /*detail*/) override
  {
    std::lock_guard lock(mMutex);
    mReasons.push_back(reason);
  }

  bool any() const
  {
    std::lock_guard lock(mMutex);
    return !mReasons.empty();
  }

private:
  mutable std::mutex mMutex;
  std::vector<StatusCode> mReasons;
};

ByteString der_of(const X509Certificate& certificate)
{
  return certificate.der_encoding();
}

ByteString der_of(const X509Crl& crl)
{
  return crl.der_encoding();
}

/// The TrustList Method thumbprint argument: the SHA-1 thumbprint as upper-case hexadecimal.
std::string hex_upper(const ByteString& bytes)
{
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string text;
  for (const uint8_t value : bytes)
  {
    text.push_back(digits[value >> 4]);
    text.push_back(digits[value & 0x0F]);
  }
  return text;
}

/// The input arguments of a Method call, built element by element (as push_certificate_management_tests.cpp
/// builds them).
template<typename... Values>
  requires(std::same_as<std::remove_cvref_t<Values>, Variant> && ...)
Array<Variant> arguments(Values&&... values)
{
  Array<Variant> array;
  (array.push_back(std::forward<Values>(values)), ...);
  return array;
}

/// Whether any DiagnosticInfo of @p response (or an inner one) names @p text, in AdditionalInfo or in a
/// string-table entry it indexes (OPC 10000-4 7.12).
bool diagnostics_name(const CallResponse& response, const std::string& text)
{
  const auto& table = response.response_header().string_table();
  const auto indexed = [&](const std::optional<int32_t>& index)
  {
    return index.has_value() && *index >= 0 && static_cast<size_t>(*index) < table.size() &&
           std::string{static_cast<std::string_view>(table[static_cast<size_t>(*index)])}.find(text) !=
             std::string::npos;
  };
  for (const auto& info : response.diagnostic_infos())
  {
    for (const DiagnosticInfo* link = &info; link != nullptr; link = link->inner_diagnostic_info().get())
    {
      if (link->additional_info().has_value() && link->additional_info()->find(text) != std::string::npos)
        return true;
      if (indexed(link->localized_text()) || indexed(link->symbolic_id()))
        return true;
    }
  }
  return false;
}

NodeId certificate_type_id(SecurityPolicyId policy)
{
  switch (application_certificate_type(policy))
  {
  case CertificateType::RsaMinApplication:
    return NodeId{ObjectTypeId::RsaMinApplicationCertificateType};
  case CertificateType::EccNistP256Application:
    return NodeId{ObjectTypeId::EccNistP256ApplicationCertificateType};
  case CertificateType::EccNistP384Application:
    return NodeId{ObjectTypeId::EccNistP384ApplicationCertificateType};
  case CertificateType::EccBrainpoolP256r1Application:
    return NodeId{ObjectTypeId::EccBrainpoolP256r1ApplicationCertificateType};
  case CertificateType::EccBrainpoolP384r1Application:
    return NodeId{ObjectTypeId::EccBrainpoolP384r1ApplicationCertificateType};
  case CertificateType::EccCurve25519Application:
    return NodeId{ObjectTypeId::EccCurve25519ApplicationCertificateType};
  case CertificateType::EccCurve448Application:
    return NodeId{ObjectTypeId::EccCurve448ApplicationCertificateType};
  default:
    return NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType};
  }
}

std::vector<MatrixParam> sign_and_encrypt_params()
{
  std::vector<MatrixParam> params;
  for (const auto& param : channel_params())
  {
    if (param.mode == MessageSecurityMode::SignAndEncrypt)
      params.push_back(param);
  }
  return params;
}

class CertificateValidationLive : public ::testing::TestWithParam<MatrixParam>
{
protected:
  static MatrixPki& pki()
  {
    return shared_pki();
  }

  void SetUp() override
  {
    mDirectory = MatrixCache::instance().new_directory("i3_");
  }

  void TearDown() override
  {
    mCachedServer = nullptr;
    for (auto& connection : mConnections)
      (void)connection.try_close_sync();
    mConnections.clear();
    mClients.clear();
    mServer.reset();
    mServerStore.reset();
    mUserStore.reset();
    mClientStores.clear();
  }

  Family family() const
  {
    return family_of(GetParam().policy);
  }

  /// The administrator's own certificate: self-signed, trusted by the server explicitly, so a TrustList
  /// update that drops the family root does not lock the administrator out.
  const LeafMaterial& admin_leaf() const
  {
    return pki().leaf(GetParam().policy, CertificateCase::Untrusted, Role::Client);
  }

  /// The subject client's own certificate: issued by the family root.
  const LeafMaterial& subject_leaf() const
  {
    return pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Client);
  }

  /// Builds the server (not started) with @p serverOwn and @p trust (+ the administrator's certificate).
  void build_server(const LeafMaterial& serverOwn, TrustMaterial trust, bool withUserTokens = false)
  {
    trust.trusted.push_back(admin_leaf().certificate);
    mServerStore = make_store(mDirectory / "server",
      MatrixCache::instance().server_pool().executor(),
      pki().crypto(),
      mServerOptions,
      trust,
      &serverOwn,
      server_certificate_type());
    if (withUserTokens)
    {
      mUserStore = make_store(mDirectory / "user",
        MatrixCache::instance().server_pool().executor(),
        pki().crypto(),
        mUserOptions,
        pki().trust_material(family()),
        nullptr,
        CertificateType::Invalid);
      mAuthenticator = std::make_shared<CountingX509Authenticator>();
    }
    mServer = std::make_unique<MatrixServer>(MatrixCache::instance().server_pool(),
      pki().crypto(),
      MatrixServer::Options{.policy = endpoint_policy(),
        .mode = endpoint_mode(),
        .applicationStore = mServerStore,
        .userTokenStore = mUserStore,
        .x509Authenticator = mAuthenticator,
        .auditing = true,
        .userTokenSecurityPolicy = mUserTokenPolicy,
        .localDiscoveryServer = mLocalDiscoveryServer,
        .extraTokenPolicies = mExtraTokenPolicies});
  }

  void start_server(const LeafMaterial& serverOwn, TrustMaterial trust, bool withUserTokens = false)
  {
    build_server(serverOwn, std::move(trust), withUserTokens);
    const auto started = mServer->start();
    ASSERT_TRUE(started.is_good()) << "fixture: the server must start: "
                                   << ua::describe(started.status_code());
  }

  /// Connects a new client presenting @p own; on success the connection is kept and returned.
  ConnectResult connect_as(const LeafMaterial& own,
    client::UserIdentity identity = client::AnonymousIdentity{}, std::string userTokenPolicyId = {})
  {
    mClientStores.push_back(make_store(mDirectory / ("client" + std::to_string(mClientStores.size())),
      MatrixCache::instance().client_pool().executor(),
      pki().crypto(),
      validation_options_for(CertificateCase::Valid),
      mClientTrust.value_or(pki().trust_material(family())),
      &own,
      application_certificate_type(GetParam().policy)));
    mClients.push_back(make_matrix_client(MatrixCache::instance().client_pool(),
      pki().crypto(),
      mClientStores.back(),
      nullptr,
      endpoint_policy() == SecurityPolicyId::None));
    // The administrator changes the TrustList, which needs an encrypted channel (OPC 10000-12 7.8.2); the
    // server offers SignAndEncrypt beside a Sign endpoint for it.
    const bool administrator = own.certificate == admin_leaf().certificate;
    const auto mode = administrator && endpoint_mode() == MessageSecurityMode::Sign
                        ? MessageSecurityMode::SignAndEncrypt
                        : endpoint_mode();
    auto config = matrix_connection_config(target().endpoint_url(), endpoint_policy(), mode);
    config.channelLifetime = mChannelLifetime;
    config.identity = std::move(identity);
    config.userTokenPolicyId = std::move(userTokenPolicyId);
    auto result = reported(mClients.back().try_connect_sync(std::move(config)));
    if (result.is_good())
      mConnections.push_back(std::move(result).value());
    return result;
  }

  static Result<CallMethodResult> call(
    client::Connection& connection, const NodeId& objectId, const NodeId& methodId, Array<Variant> arguments)
  {
    CallMethodRequest method;
    method.object_id() = objectId;
    method.method_id() = methodId;
    method.input_arguments() = std::move(arguments);
    CallRequest request;
    request.methods_to_call().push_back(std::move(method));
    auto response = connection.service_requests().try_call_sync(std::move(request));
    if (response.is_bad())
      return Result<CallMethodResult>{response.status_code(), response.shared_detail()};
    if (response.value().results().empty())
      return Result<CallMethodResult>{StatusCode{Status::BadUnexpectedError}};
    return std::move(response.value().results()[0]);
  }

  enum class Group
  {
    Application,  ///< DefaultApplicationGroup.
    UserToken  ///< DefaultUserTokenGroup.
  };

  struct TrustListIds
  {
    NodeId object;
    NodeId open;
    NodeId write;
    NodeId closeAndUpdate;
    NodeId addCertificate;
    NodeId removeCertificate;
  };

  static TrustListIds trust_list_ids(Group group)
  {
    if (group == Group::UserToken)
    {
      return TrustListIds{
        .object = NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList},
        .open = NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Open},
        .write =
          NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Write},
        .closeAndUpdate =
          NodeId{
            MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate},
        .addCertificate =
          NodeId{
            MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate},
        .removeCertificate = NodeId{
          MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate}};
    }
    return TrustListIds{
      .object = NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList},
      .open = NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
      .write =
        NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Write},
      .closeAndUpdate =
        NodeId{
          MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate},
      .addCertificate =
        NodeId{
          MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate},
      .removeCertificate = NodeId{
        MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate}};
  }

  /// Open(Write|EraseExisting) -> Write -> CloseAndUpdate of @p group's TrustList. The CloseAndUpdate is sent
  /// asking for every DiagnosticInfo field (returnDiagnostics 0x3FF, OPC 10000-4 7.32) and its response is
  /// kept in mLastCloseAndUpdate.
  StatusCode push_trust_list(
    client::Connection& admin, const TrustListDataType& list, Group group = Group::Application)
  {
    const auto ids = trust_list_ids(group);
    memory_stream_device::Dynamic device(65535, /*reserve=*/true);
    MemoryStream<memory_stream_device::Dynamic> stream(device);
    UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
    encoder.encode(EncodingLimits{}.stack_depth(), list);

    auto opened = call(admin, ids.object, ids.open, arguments(Variant{uint8_t{0x06}}));
    if (opened.is_bad() || opened.value().status_code().is_bad() || opened.value().output_arguments().empty())
      return opened.is_bad() ? opened.status_code() : opened.value().status_code();
    const auto handle = opened.value().output_arguments()[0].as<uint32_t>();

    auto written =
      call(admin, ids.object, ids.write, arguments(Variant{handle}, Variant{ByteString{device.get_data()}}));
    if (written.is_bad() || written.value().status_code().is_bad())
      return written.is_bad() ? written.status_code() : written.value().status_code();

    CallMethodRequest method;
    method.object_id() = ids.object;
    method.method_id() = ids.closeAndUpdate;
    method.input_arguments() = arguments(Variant{handle});
    CallRequest request;
    request.request_header().return_diagnostics() = 0x3FF;
    request.methods_to_call().push_back(std::move(method));
    auto response = admin.service_requests().try_call_sync(std::move(request));
    if (response.is_bad())
      return response.status_code();
    mLastCloseAndUpdate = response.value();
    if (response.value().results().empty())
      return StatusCode{Status::BadUnexpectedError};
    const auto status = response.value().results()[0].status_code();
    // OPC 10000-12 7.8.2.3: applyChangesRequired TRUE means the new TrustList is used after ApplyChanges
    // (7.10.6), which is also what closes the channels and sessions the change affects.
    const auto& outputs = response.value().results()[0].output_arguments();
    if (status.is_good() && !outputs.empty() && outputs[0].as<bool>())
    {
      const auto applied = call(admin,
        NodeId{ObjectId::ServerConfiguration},
        NodeId{MethodId::ServerConfiguration_ApplyChanges},
        arguments());
      if (applied.is_bad() || applied.value().status_code().is_bad())
        return applied.is_bad() ? applied.status_code() : applied.value().status_code();
    }
    if (status.is_bad())
    {
      // The server's diagnostics name the certificate or CRL that failed (Part 12 7.8.2.3).
      std::cout << "[CloseAndUpdate refused] " << ua::describe(status);
      for (const auto& info : response.value().diagnostic_infos())
        std::cout << "\n  diagnostic: " << ua::to_string(info);
      std::cout << std::endl;
    }
    return status;
  }

  /// AddCertificate(certificate, isTrustedCertificate = TRUE) on @p group's TrustList (OPC 10000-12 7.8.2.4).
  StatusCode add_certificate(
    client::Connection& admin, const X509Certificate& certificate, Group group = Group::Application)
  {
    const auto ids = trust_list_ids(group);
    return method_status(
      call(admin, ids.object, ids.addCertificate, arguments(Variant{der_of(certificate)}, Variant{true})));
  }

  /// RemoveCertificate(thumbprint, isTrustedCertificate = TRUE) on @p group's TrustList (OPC
  /// 10000-12 7.8.2.5).
  StatusCode remove_certificate(
    client::Connection& admin, const X509Certificate& certificate, Group group = Group::Application)
  {
    const auto ids = trust_list_ids(group);
    return method_status(call(admin,
      ids.object,
      ids.removeCertificate,
      arguments(Variant{String{hex_upper(certificate.thumbprint())}}, Variant{true})));
  }

  /// A full TrustList (all four masks): @p trusted plus the administrator, the family root as an ISSUER (so
  /// the subject's chain still builds), and @p trustedCrls plus every family CRL needed for revocation.
  TrustListDataType trust_list(std::vector<CertificatePointer> trusted, std::vector<CrlPointer> trustedCrls,
    bool withIntermediate = true)
  {
    TrustListDataType list;
    list.specified_lists() = 0x0F;
    trusted.push_back(admin_leaf().certificate);
    for (const auto& certificate : trusted)
      list.trusted_certificates().push_back(der_of(*certificate));
    for (const auto& crl : trustedCrls)
      list.trusted_crls().push_back(der_of(*crl));
    // A valid new TrustList (OPC 10000-12 7.8.2.3: every certificate and CRL of it is validated): the
    // family root and intermediate are issuers, so every chain still builds and each CRL's issuer is present;
    // only the trusted list decides what is trusted.
    list.issuer_certificates().push_back(der_of(*pki().root(family())));
    if (!withIntermediate)
    {
      // Without the intermediate (a TrustList may not hold a revoked certificate, 7.8.2.3): its CRLs go too,
      // and the root's CRL is the caller's (trustedCrls), so no second root CRL competes with it.
      return list;
    }
    list.issuer_certificates().push_back(der_of(*pki().intermediate(family())));
    for (const auto& crl : pki().trust_material(family()).issuerCrls)
      list.issuer_crls().push_back(der_of(*crl));
    list.issuer_crls().push_back(der_of(*pki().root_crl(family())));
    return list;
  }

  /// The type the server's own certificate is registered under. On a secured endpoint it is the endpoint
  /// policy's type; on a None endpoint with a secured user-token policy the server selects one certificate
  /// per family, and every RSA token policy uses an RsaSha256Application certificate (the SDK rule pinned by
  /// ResolveCertificateTypeForEndpoint.NoneChannelMixedRsaPoliciesReturnsRsaSha256).
  CertificateType server_certificate_type() const
  {
    const auto type = application_certificate_type(GetParam().policy);
    if (endpoint_policy() == SecurityPolicyId::None && type == CertificateType::RsaMinApplication)
      return CertificateType::RsaSha256Application;
    return type;
  }

  SecurityPolicyId endpoint_policy() const
  {
    return mEndpoint ? mEndpoint->first : GetParam().policy;
  }

  MessageSecurityMode endpoint_mode() const
  {
    return mEndpoint ? mEndpoint->second : GetParam().mode;
  }

  /// The server connect_as dials: a cached server when the row's variable is not the server (mCachedServer),
  /// else the server this test built.
  MatrixServer& target()
  {
    return mCachedServer != nullptr ? *mCachedServer : *mServer;
  }

  /// UpdateCertificate on the DefaultApplicationGroup with @p certificate and @p issuers.
  Result<CallMethodResult> update_certificate(
    client::Connection& admin, const ByteString& certificate, Array<ByteString> issuers)
  {
    return call(admin,
      NodeId{ObjectId::ServerConfiguration},
      NodeId{MethodId::ServerConfiguration_UpdateCertificate},
      arguments(Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}},
        Variant{certificate_type_id(GetParam().policy)},
        Variant{certificate},
        Variant{std::move(issuers)},
        Variant{String{}},
        Variant{ByteString{}}));
  }

  /// The Method status of a successful Call, or the Call's own failure.
  static StatusCode method_status(const Result<CallMethodResult>& result)
  {
    return result.is_bad() ? result.status_code() : result.value().status_code();
  }

  // Per-test configuration read by build_server / connect_as; set before calling them.
  std::optional<std::pair<SecurityPolicyId, MessageSecurityMode>> mEndpoint;  ///< Default: the parameter's.
  std::optional<SecurityPolicyId> mUserTokenPolicy;  ///< The X509 UserTokenPolicy's own SecurityPolicy.
  std::vector<UserTokenPolicy> mExtraTokenPolicies;  ///< Offered after the fixture's own token policies.
  bool mLocalDiscoveryServer{false};
  TrustListValidationOptions mServerOptions{validation_options_for(CertificateCase::Valid)};
  TrustListValidationOptions mUserOptions{validation_options_for(CertificateCase::Valid)};
  std::optional<TrustMaterial> mClientTrust;  ///< Default: the family trust.
  std::optional<std::chrono::milliseconds> mChannelLifetime;
  MatrixServer* mCachedServer{nullptr};
  std::optional<CallResponse> mLastCloseAndUpdate;

  std::filesystem::path mDirectory;
  std::shared_ptr<CertificateStore> mServerStore;
  std::shared_ptr<CertificateStore> mUserStore;
  std::shared_ptr<CountingX509Authenticator> mAuthenticator;
  std::vector<std::shared_ptr<CertificateStore>> mClientStores;
  std::unique_ptr<MatrixServer> mServer;
  std::vector<client::Client> mClients;
  std::vector<client::Connection> mConnections;
};

class CertificateValidationTrustListLive : public CertificateValidationLive
{};

class CertificateValidationUpdateCertificate : public CertificateValidationLive
{};

class CertificateValidationStartupRefusal : public CertificateValidationLive
{};

class CertificateValidationStartupAcceptance : public CertificateValidationLive
{};

class CertificateValidationX509UserToken : public CertificateValidationLive
{};

// A pushed TrustList that no longer trusts the client's root closes the client's channel, and a reconnect is
// refused: Bad_SecurityChecksFailed on the wire, Bad_CertificateUntrusted to the observer (the root is still
// an issuer, so the chain builds and the Trust List step is the one that fails).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-58-TRUST-LIST-LIVE, scope=function)
TEST_P(CertificateValidationTrustListLive, RemovingTheClientsTrustClosesItsChannelAndRefusesTheReconnect)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(subject_leaf()).is_good()) << "fixture: the subject client starts trusted";
  auto disconnects = std::make_shared<DisconnectRecorder>();
  mConnections.back().set_connection_observer(disconnects);
  ASSERT_TRUE(connect_as(admin_leaf()).is_good()) << "fixture: the administrator connects";

  const auto pushed = push_trust_list(mConnections.back(), trust_list({}, {}));
  ASSERT_EQ(pushed, StatusCode{Status::Good}) << "the TrustList update itself must succeed";

  EXPECT_TRUE(eventually([&] { return disconnects->any(); }))
    << "a TrustList update must close the channel of a client no longer trusted";
  auto reconnect = connect_as(subject_leaf());
  ASSERT_TRUE(reconnect.is_bad()) << "the reconnect of a client no longer trusted must be refused";
  EXPECT_EQ(reconnect.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  const auto rejected = mServer->hooks().rejected();
  EXPECT_NE(
    std::find(rejected.begin(), rejected.end(), StatusCode{Status::BadCertificateUntrusted}), rejected.end());
}

// Control: a pushed TrustList that adds the root makes the previously refused client connect.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-58-TRUST-LIST-LIVE, scope=function)
TEST_P(CertificateValidationTrustListLive, AddingTheClientsTrustAcceptsTheReconnect)
{
  auto trust = pki().trust_material(family());
  trust.trusted.clear();
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), trust);
  mServerStore->add_to_issuer_certificates_sync(pki().root(family()));
  mServerStore->add_to_issuer_crls_sync(pki().root_crl(family()));
  const auto refused = connect_as(subject_leaf());
  ASSERT_TRUE(refused.is_bad()) << "fixture: the subject client starts untrusted";
  ASSERT_TRUE(connect_as(admin_leaf()).is_good()) << "fixture: the administrator connects";

  const auto pushed =
    push_trust_list(mConnections.back(), trust_list({pki().root(family())}, {pki().root_crl(family())}));
  ASSERT_EQ(pushed, StatusCode{Status::Good});

  auto reconnect = connect_as(subject_leaf());
  EXPECT_TRUE(reconnect.is_good()) << "after the root is trusted the client must connect: 0x" << std::hex
                                   << reconnect.status_code().as_uint32();
}

// A pushed CRL revoking the client's certificate closes its channel and refuses the reconnect with
// Bad_CertificateRevoked reported to the observer.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-58-TRUST-LIST-LIVE, scope=function)
TEST_P(CertificateValidationTrustListLive, ARevokingCrlPushRefusesTheClient)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(subject_leaf()).is_good());
  auto disconnects = std::make_shared<DisconnectRecorder>();
  mConnections.back().set_connection_observer(disconnects);
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());

  const auto revoking = pki().root_crl_revoking(family(), *subject_leaf().certificate);
  const auto pushed = push_trust_list(mConnections.back(), trust_list({pki().root(family())}, {revoking}));
  ASSERT_EQ(pushed, StatusCode{Status::Good});

  EXPECT_TRUE(eventually([&] { return disconnects->any(); })) << "a revoked client's channel must be closed";
  auto reconnect = connect_as(subject_leaf());
  ASSERT_TRUE(reconnect.is_bad());
  EXPECT_EQ(reconnect.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  const auto rejected = mServer->hooks().rejected();
  EXPECT_NE(
    std::find(rejected.begin(), rejected.end(), StatusCode{Status::BadCertificateRevoked}), rejected.end());
}

// UpdateCertificate refuses a certificate whose signature violates the policy of the endpoint it would serve
// (approved G; same key as the installed certificate, so only the policy differs from the control) with
// Bad_SecurityChecksFailed (oracle review 2026-10-02, Part 12 7.10.4; Part 12 lists no
// Bad_CertificatePolicyCheckFailed for UpdateCertificate).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-59-UPDATE-CERTIFICATE, scope=function)
TEST_P(CertificateValidationUpdateCertificate, RefusesACertificateViolatingTheEndpointPolicy)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());
  // Basic128Rsa15 and Basic256 permit every PKCS#1 v1.5 signature and the SDK creates no RSA-PSS certificate
  // (see matrix_params), so for them the violation is the key length; it has another key as well.
  const auto violation = is_rsa_min_policy(GetParam().policy) ? CertificateCase::PolicyKeyLength
                                                              : CertificateCase::PolicySignature;
  const auto& violating = pki().leaf(GetParam().policy, violation, Role::Server);

  auto result = call(mConnections.back(),
    NodeId{ObjectId::ServerConfiguration},
    NodeId{MethodId::ServerConfiguration_UpdateCertificate},
    arguments(Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}},
      Variant{certificate_type_id(GetParam().policy)},
      Variant{der_of(*violating.certificate)},
      Variant{Array<ByteString>{}},
      Variant{String{}},
      Variant{ByteString{}}));
  ASSERT_TRUE(result.is_good()) << "the Call service itself must succeed";
  // OPC 10000-12 7.10.4: "The Server shall do all normal integrity checks on the Certificate and all of the
  // issuer Certificates. If errors occur the Bad_SecurityChecksFailed error is returned." The Security Policy
  // Check (Part 4 Table 106 step 4) is one of those checks. RATIFIED (owner decision 2026-10-03, D-e): for
  // the RsaMin policies the only violation is the key length, which is RsaMinApplicationCertificateType's
  // key-shape rule (7.8.4.4) and is refused first as Bad_InvalidArgument (SVR-PULLCRT-026).
  const auto expected = is_rsa_min_policy(GetParam().policy) ? StatusCode{Status::BadInvalidArgument}
                                                             : StatusCode{Status::BadSecurityChecksFailed};
  EXPECT_EQ(result.value().status_code(), expected);
}

// Control: a compliant certificate with the same key is accepted by UpdateCertificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-59-UPDATE-CERTIFICATE, scope=function)
TEST_P(CertificateValidationUpdateCertificate, AcceptsACompliantCertificate)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());
  const auto compliant = pki().issue_leaf(family(), "UpdateCertificate compliant", serverUri);

  auto result = call(mConnections.back(),
    NodeId{ObjectId::ServerConfiguration},
    NodeId{MethodId::ServerConfiguration_UpdateCertificate},
    arguments(Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}},
      Variant{certificate_type_id(GetParam().policy)},
      Variant{der_of(*compliant.certificate)},
      Variant{Array<ByteString>{}},
      Variant{String{}},
      Variant{ByteString{}}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::Good});
}

// A server whose own certificate violates the policy of an endpoint it serves refuses to start with
// Bad_ConfigurationError naming the endpoint (approved F).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-60-STARTUP-REFUSAL, scope=function)
TEST_P(CertificateValidationStartupRefusal, RefusesToStartWithANonCompliantOwnCertificate)
{
  build_server(
    pki().leaf(GetParam().policy, GetParam().certificateCase, Role::Server), pki().trust_material(family()));
  const auto started = mServer->start();

  ASSERT_TRUE(started.is_bad()) << "a non-compliant own certificate must stop the server starting";
  EXPECT_EQ(started.status_code(), StatusCode{Status::BadConfigurationError});
  const auto endpointName = policy_name(GetParam().policy) + "_" + mode_name(GetParam().mode);
  EXPECT_TRUE(detail_chain_has(started.shared_detail(), std::nullopt, endpointName))
    << "the refusal must name the endpoint " << endpointName;
}

// Control: the compliant own certificate starts.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-60-STARTUP-REFUSAL, scope=function)
TEST_P(CertificateValidationStartupAcceptance, StartsWithACompliantOwnCertificate)
{
  build_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  const auto started = mServer->start();
  EXPECT_TRUE(started.is_good()) << "0x" << std::hex << started.status_code().as_uint32();
}

// An X509 user token carrying its chain (leaf issued by the intermediate, intermediate sent with it) is
// accepted and reaches the authenticator.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-61-X509-USER-TOKEN, scope=function)
TEST_P(CertificateValidationX509UserToken, AChainCarryingUserTokenIsAccepted)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
    pki().trust_material(family()),
    true);
  const auto& user = pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::User);
  client::X509Identity identity;
  identity.certificate = user.certificate;
  identity.keyPair = user.keys;
  identity.issuerCertificates = user.presentedIssuers;  // ASSUMED API (see file comment).

  auto result = connect_as(subject_leaf(), identity, "x509");
  EXPECT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(mAuthenticator->calls(), 1)
    << "an accepted certificate is mapped to an identity by the authenticator";
}

// The same user certificate WITHOUT its intermediate is refused by the session before the authenticator:
// Bad_IdentityTokenRejected, authenticator never called.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-61-X509-USER-TOKEN, scope=function)
TEST_P(CertificateValidationX509UserToken, AFaultyUserTokenIsRejectedBeforeTheAuthenticator)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
    pki().trust_material(family()),
    true);
  const auto& user = pki().leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::User);
  client::X509Identity identity;
  identity.certificate = user.certificate;
  identity.keyPair = user.keys;
  identity.issuerCertificates = user.presentedIssuers;  // ASSUMED API: empty here.

  auto result = connect_as(subject_leaf(), identity, "x509");
  ASSERT_TRUE(result.is_bad()) << "a user certificate whose chain cannot be built must be refused";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  EXPECT_EQ(mAuthenticator->calls(), 0) << "the authenticator must not be called for a refused certificate";
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificateChainIncomplete}, *user.certificate);
    }))
    << "the Table 106 cause (Bad_CertificateChainIncomplete) must be reported for the USER certificate";
}

INSTANTIATE_TEST_SUITE_P(
  AllChannels, CertificateValidationTrustListLive, ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(EncryptedChannels, CertificateValidationUpdateCertificate,
  ::testing::ValuesIn(sign_and_encrypt_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(PolicyViolations, CertificateValidationStartupRefusal,
  ::testing::ValuesIn(matrix_params({CertificateCase::PolicyKeyLength, CertificateCase::PolicySignature})),
  matrix_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationStartupAcceptance,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(
  AllChannels, CertificateValidationX509UserToken, ::testing::ValuesIn(channel_params()), channel_param_name);

// ====================== Completeness review (2026-10-02): C3, C8-C10, C12, C13, decision 24
// ======================

/// Long enough for at least two OPN renewals of a channel with @p lifetime (a client renews at 75 %).
void wait_for_renewals(std::chrono::milliseconds lifetime)
{
  std::this_thread::sleep_for(ua::test_utils::scaled(lifetime * 3));
}

client::X509Identity x509_identity(const LeafMaterial& user)
{
  client::X509Identity identity;
  identity.certificate = user.certificate;
  identity.keyPair = user.keys;
  identity.issuerCertificates = user.presentedIssuers;
  return identity;
}

/// The two LDS configurations (one RSA, one ECC policy).
std::vector<MatrixParam> lds_params()
{
  return {MatrixParam{.policy = SecurityPolicyId::Basic256Sha256,
            .mode = MessageSecurityMode::SignAndEncrypt,
            .certificateCase = CertificateCase::Valid},
    MatrixParam{.policy = SecurityPolicyId::EccNistP256AesGcm,
      .mode = MessageSecurityMode::SignAndEncrypt,
      .certificateCase = CertificateCase::Valid}};
}

/// C8 rows: the parameter's policy is the USER TOKEN policy; the channel is None.
std::string token_policy_param_name(const ::testing::TestParamInfo<MatrixParam>& info)
{
  return policy_name(info.param.policy);
}

class CertificateValidationPresentedChainKept : public CertificateValidationLive
{
protected:
  static constexpr std::chrono::milliseconds sLifetime{1000};

  /// The server trusts the family root and holds NO intermediate; the subject presents its intermediate on a
  /// channel renewed every sLifetime; then the administrator connects.
  void connect_chain_presenting_subject()
  {
    mChannelLifetime = sLifetime;
    start_server(
      pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
    ASSERT_TRUE(connect_as(chained_subject()).is_good()) << "fixture: the chain-presenting subject connects";
    mDisconnects = std::make_shared<DisconnectRecorder>();
    mConnections.back().set_connection_observer(mDisconnects);
    ASSERT_TRUE(connect_as(admin_leaf()).is_good()) << "fixture: the administrator connects";
  }

  const LeafMaterial& chained_subject() const
  {
    return pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Client);
  }

  /// Replaces the subject's own certificate entry (its store is the first client store).
  void replace_subject_certificate(
    const CertificatePointer& certificate, std::vector<CertificatePointer> issuers)
  {
    mClientStores.front()->add_to_application_certificates_sync(CertificateStore::ApplicationCertificate{
      .certificateType = application_certificate_type(GetParam().policy),
      .certificate = certificate,
      .keys = chained_subject().keys,
      .issuerCertificates = std::move(issuers)});
  }

  std::shared_ptr<DisconnectRecorder> mDisconnects;
};

// C3 (control): two renewals and a TrustList push that changes something unrelated each re-validate the
// channel; the intermediate is in no server list, so each must use the chain the subject PRESENTED, kept with
// the channel.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-123-PRESENTED-CHAIN-KEPT, scope=function)
TEST_P(CertificateValidationPresentedChainKept, RenewalsAndAnUnrelatedPushKeepTheChannel)
{
  ASSERT_NO_FATAL_FAILURE(connect_chain_presenting_subject());
  wait_for_renewals(sLifetime);
  EXPECT_FALSE(mDisconnects->any()) << "renewals must re-validate with the presented chain";

  const auto unrelated = pki().issue_self_signed(
    family(), "Unrelated " + policy_name(GetParam().policy), "urn:test:certificate-validation:unrelated");
  ASSERT_EQ(push_trust_list(mConnections.back(),
              trust_list({pki().root(family()), unrelated.certificate}, {pki().root_crl(family())})),
    StatusCode{Status::Good});
  wait_for_renewals(sLifetime);
  EXPECT_FALSE(mDisconnects->any())
    << "re-evaluation after an unrelated TrustList change must use the presented chain kept with the channel";
  EXPECT_TRUE(mServer->hooks().rejected().empty());
}

// C3 (negative): once the root is no longer trusted, the chain-presenting channel is closed and the refusal
// names the presented leaf with Bad_CertificateUntrusted (the root stays an issuer, so the chain still
// builds).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-123-PRESENTED-CHAIN-KEPT, scope=function)
TEST_P(CertificateValidationPresentedChainKept, RemovingTheRootClosesTheChainPresentingChannel)
{
  ASSERT_NO_FATAL_FAILURE(connect_chain_presenting_subject());
  ASSERT_EQ(push_trust_list(mConnections.back(), trust_list({}, {})), StatusCode{Status::Good});
  EXPECT_TRUE(eventually([&] { return mDisconnects->any(); })) << "the channel must be closed";
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificateUntrusted}, *chained_subject().certificate);
    }));
}

class CertificateValidationUserTokenGroupLive : public CertificateValidationLive
{
protected:
  /// The subject activates with an X509 user certificate @p user; then the administrator connects.
  void connect_x509_subject(const LeafMaterial& user)
  {
    start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
      pki().trust_material(family()),
      true);
    ASSERT_TRUE(connect_as(subject_leaf(), x509_identity(user), "x509").is_good())
      << "fixture: the X509 subject activates";
    mDisconnects = std::make_shared<DisconnectRecorder>();
    mConnections.back().set_connection_observer(mDisconnects);
    ASSERT_TRUE(connect_as(admin_leaf()).is_good()) << "fixture: the administrator connects";
  }

  const LeafMaterial& chained_user() const
  {
    return pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::User);
  }

  /// Whether the X509 subject's Session still serves a request. A Session closed by the server (OPC 10000-12
  /// 7.10.6 closes the Session, not the channel) sends nothing; the client learns it on its next request.
  bool subject_session_usable()
  {
    return mConnections.front().try_read_value_sync(NodeId{VariableId::Server_ServerStatus_State}).is_good();
  }

  std::shared_ptr<DisconnectRecorder> mDisconnects;
};

// C3 (control): an unrelated push to the user-token group re-evaluates the X509 session with the chain the
// user token PRESENTED; the session survives.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-125-USER-TOKEN-GROUP-LIVE, scope=function)
TEST_P(CertificateValidationUserTokenGroupLive, AnUnrelatedUserTokenPushKeepsTheX509Session)
{
  ASSERT_NO_FATAL_FAILURE(connect_x509_subject(chained_user()));
  const auto unrelated = pki().issue_self_signed(family(),
    "Unrelated User " + policy_name(GetParam().policy),
    "urn:test:certificate-validation:unrelated");
  ASSERT_EQ(push_trust_list(mConnections.back(),
              trust_list({pki().root(family()), unrelated.certificate}, {pki().root_crl(family())}),
              Group::UserToken),
    StatusCode{Status::Good});
  std::this_thread::sleep_for(ua::test_utils::scaled(std::chrono::milliseconds{2000}));
  // RATIFIED (owner decision 2026-10-03, D-c): the Session is probed - a client disconnect never follows a
  // Session close, so the former disconnect check could not fail.
  EXPECT_TRUE(subject_session_usable())
    << "the X509 session must survive an unrelated user-token TrustList change";
  EXPECT_TRUE(mServer->hooks().rejected().empty());
}

// C3 / C10 (negative): the user-token group no longer trusts the root -> the X509 session is closed and the
// refusal names the USER certificate with Bad_CertificateUntrusted.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-125-USER-TOKEN-GROUP-LIVE, scope=function)
TEST_P(CertificateValidationUserTokenGroupLive, RemovingTheRootFromTheUserTokenGroupClosesTheX509Session)
{
  ASSERT_NO_FATAL_FAILURE(connect_x509_subject(chained_user()));
  ASSERT_EQ(
    push_trust_list(mConnections.back(), trust_list({}, {}), Group::UserToken), StatusCode{Status::Good});
  // RATIFIED (owner decision 2026-10-03, D-c): the Session is probed; its close sends nothing to the client.
  EXPECT_TRUE(eventually([&] { return !subject_session_usable(); })) << "the X509 session must be closed";
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificateUntrusted}, *chained_user().certificate);
    }));
}

// C10 (negative): a CRL pushed to the user-token group revoking the user certificate closes the X509 session.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-125-USER-TOKEN-GROUP-LIVE, scope=function)
TEST_P(CertificateValidationUserTokenGroupLive, ARevokingCrlOnTheUserTokenGroupClosesTheX509Session)
{
  const auto& user = pki().leaf(GetParam().policy, CertificateCase::Valid, Role::User);
  ASSERT_NO_FATAL_FAILURE(connect_x509_subject(user));
  const auto revoking = pki().root_crl_revoking(family(), *user.certificate);
  ASSERT_EQ(
    push_trust_list(mConnections.back(), trust_list({pki().root(family())}, {revoking}), Group::UserToken),
    StatusCode{Status::Good});
  // RATIFIED (owner decision 2026-10-03, D-c): the Session is probed; its close sends nothing to the client.
  EXPECT_TRUE(eventually([&] { return !subject_session_usable(); }))
    << "the revoked user's session must be closed";
  EXPECT_TRUE(eventually(
    [&] {
      return mServer->hooks().rejected_with(StatusCode{Status::BadCertificateRevoked}, *user.certificate);
    }));
}

class CertificateValidationSecuredTokenOnNoneChannel : public CertificateValidationLive
{
protected:
  void SetUp() override
  {
    CertificateValidationLive::SetUp();
    mEndpoint = std::make_pair(SecurityPolicyId::None, MessageSecurityMode::None);
    mUserTokenPolicy = GetParam().policy;
  }
};

// C8 (negative, client side): on a None channel the client validates the server certificate under the token
// policy BEFORE it encrypts the UserName token's secret with it; an untrusted one is refused and the token
// never reaches the server. Under an ECC or RSA_DH policy there is no such secret: OPC 10000-4 7.41 (1.05.07)
// does not allow these policies to encrypt one on a None endpoint (decision D-16), so the endpoint offering
// that UserName token is refused when it is added and no client is asked to encrypt under it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-126-SECURED-TOKEN-ON-NONE, scope=function)
// @relation(AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES, scope=function)
TEST_P(CertificateValidationSecuredTokenOnNoneChannel, TheClientRefusesAnUntrustedServerCertificate)
{
  if (!secret_token_allowed_on_none_endpoint(GetParam().policy))
  {
    UserTokenPolicy userName;
    userName.policy_id() = "username";
    userName.token_type() = UserTokenType::UserName;
    userName.security_policy_uri() = ua::utils::get_security_policy_uri(GetParam().policy);
    mExtraTokenPolicies.push_back(std::move(userName));
    try
    {
      build_server(pki().leaf(GetParam().policy, CertificateCase::Untrusted, Role::Server),
        pki().trust_material(family()),
        true);
      ADD_FAILURE() << "a None endpoint offering a UserName token under this policy was added";
    }
    catch (const UaException& refused)
    {
      EXPECT_EQ(refused.status(), Status::BadSecurityPolicyRejected);
      ASSERT_NE(refused.detail(), nullptr);
      EXPECT_EQ(refused.detail()->code, "EphemeralKeySecretOverNoneChannel");
    }
    return;
  }
  start_server(pki().leaf(GetParam().policy, CertificateCase::Untrusted, Role::Server),
    pki().trust_material(family()),
    true);
  auto result = connect_as(subject_leaf(),
    client::UsernamePasswordIdentity{.username = "operator", .password = "secret"},
    "username");
  ASSERT_TRUE(result.is_bad()) << "an untrusted server certificate must not be used for the user token";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUntrusted})
    << "got 0x" << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(mAuthenticator->calls(), 0) << "the token must never reach the server";
}

// C8 (control): the same channel with a trusted server certificate activates the X509 session.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-126-SECURED-TOKEN-ON-NONE, scope=function)
TEST_P(CertificateValidationSecuredTokenOnNoneChannel, ATrustedServerCertificateActivatesTheX509Session)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
    pki().trust_material(family()),
    true);
  auto result = connect_as(subject_leaf(),
    x509_identity(pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::User)),
    "x509");
  EXPECT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(mAuthenticator->calls(), 1);
}

// C8 (negative, server side): the server validates the X509 user certificate under the TOKEN policy (the
// channel is None, so no channel policy applies): a key violating the token policy is
// Bad_IdentityTokenRejected with Bad_CertificatePolicyCheckFailed as the cause.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-126-SECURED-TOKEN-ON-NONE, scope=function)
TEST_P(
  CertificateValidationSecuredTokenOnNoneChannel, TheServerRefusesAUserCertificateViolatingTheTokenPolicy)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
    pki().trust_material(family()),
    true);
  const auto& user = pki().leaf(GetParam().policy, CertificateCase::PolicyKeyLength, Role::User);
  auto result = connect_as(subject_leaf(), x509_identity(user), "x509");
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificatePolicyCheckFailed}, *user.certificate);
    }));
  EXPECT_EQ(mAuthenticator->calls(), 0);
}

class CertificateValidationRotation : public CertificateValidationLive
{
protected:
  /// The new server certificate: issued by the intermediate, the same key as the installed one.
  const LeafMaterial& rotated() const
  {
    return pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Server);
  }

  /// The subject (trusting the root only, so the new intermediate must come from the server) and the
  /// administrator connect; UpdateCertificate installs rotated() with its intermediate; ApplyChanges applies
  /// it.
  void rotate()
  {
    start_server(
      pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
    ASSERT_TRUE(connect_as(subject_leaf()).is_good());
    ASSERT_TRUE(connect_as(admin_leaf()).is_good());
    Array<ByteString> issuers;
    issuers.push_back(der_of(*pki().intermediate(family())));
    ASSERT_EQ(method_status(
                update_certificate(mConnections.back(), der_of(*rotated().certificate), std::move(issuers))),
      StatusCode{Status::Good});
    ASSERT_EQ(method_status(call(mConnections.back(),
                NodeId{ObjectId::ServerConfiguration},
                NodeId{MethodId::ServerConfiguration_ApplyChanges},
                arguments())),
      StatusCode{Status::Good});
  }

  ConnectResult reconnect_subject(std::shared_ptr<const X509Certificate> serverCertificate = nullptr)
  {
    auto config = matrix_connection_config(mServer->endpoint_url(), GetParam().policy, GetParam().mode);
    config.serverCertificate = std::move(serverCertificate);
    return reported(mClients.front().try_connect_sync(std::move(config)));
  }
};

// C9 (control): after UpdateCertificate with a chain + ApplyChanges the existing client reconnects,
// validating the new leaf with the intermediate only the server sends, and GetEndpoints serves leaf + chain.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-127-ROTATION, scope=function)
TEST_P(CertificateValidationRotation, AnExistingClientReconnectsAndGetEndpointsServesTheNewChain)
{
  ASSERT_NO_FATAL_FAILURE(rotate());
  auto reconnect = reconnect_subject();
  ASSERT_TRUE(reconnect.is_good()) << "the rotated certificate and its chain must validate: 0x" << std::hex
                                   << reconnect.status_code().as_uint32();
  mConnections.push_back(std::move(reconnect).value());
  auto endpoints = mClients.front().discovery().try_get_endpoints_sync(
    mServer->endpoint_url(), client::GetEndpointsOptions{});
  ASSERT_TRUE(endpoints.is_good());
  ASSERT_FALSE(endpoints.value().empty());
  for (const auto& endpoint : endpoints.value())
    EXPECT_EQ(endpoint.server_certificate(), chain_der(rotated())) << "GetEndpoints must serve leaf + chain";
}

// C9 (negative): a client still using the old server certificate sends a stale ReceiverCertificateThumbprint
// and is refused with Bad_CertificateInvalid (OPC 10000-6 6.7.2.3).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-127-ROTATION, scope=function)
TEST_P(CertificateValidationRotation, AClientUsingTheStaleCertificateIsRefusedWithCertificateInvalid)
{
  ASSERT_NO_FATAL_FAILURE(rotate());
  auto stale =
    reconnect_subject(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server).certificate);
  ASSERT_TRUE(stale.is_bad());
  EXPECT_EQ(stale.status_code(), StatusCode{Status::BadCertificateInvalid})
    << "got 0x" << std::hex << stale.status_code().as_uint32();
}

// C9 (negative): UpdateCertificate refuses every faulty issuer chain with Bad_SecurityChecksFailed (OPC
// 10000-12 7.10.4); one server per channel configuration, the five faults in turn (a refusal changes no
// server state). The control is the valid chain installed by rotate() in the rows above.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-128-UPDATE-CERTIFICATE-ISSUERS, scope=function)
TEST_P(CertificateValidationRotation, UpdateCertificateRefusesEveryFaultyIssuerChain)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());
  for (auto fault : {IssuerFault::Expired,
         IssuerFault::NotTheSigner,
         IssuerFault::NotCa,
         IssuerFault::PolicyViolation,
         IssuerFault::TrailingBytes})
  {
    SCOPED_TRACE("IssuerFault " + std::to_string(static_cast<int>(fault)));
    const auto material = pki().leaf_with_faulty_issuer(GetParam().policy, fault);
    Array<ByteString> issuers;
    for (const auto& issuer : material.presentedIssuers)
    {
      const auto der = der_of(*issuer);
      std::vector<uint8_t> bytes(der.begin(), der.end());
      if (fault == IssuerFault::TrailingBytes)
        bytes.insert(bytes.end(), {0x00, 0x00});
      issuers.push_back(ByteString{std::move(bytes)});
    }
    EXPECT_EQ(method_status(
                update_certificate(mConnections.back(), der_of(*material.certificate), std::move(issuers))),
      StatusCode{Status::BadSecurityChecksFailed});
  }
}

// C10 (negative): a pushed CRL revoking the INTERMEDIATE closes the channel of a client whose chain runs
// through it; the reconnect is refused and reported Bad_CertificateIssuerRevoked for the presented leaf.
// RATIFIED (owner decision 2026-10-03, D-a): the pushed TrustList leaves the intermediate out - OPC 10000-12
// 7.8.2.3 refuses a TrustList holding a certificate that is not valid (decision H), and a revoked
// intermediate is not. The client presents the intermediate in its own chain, which is what the revocation
// reaches. Without the intermediate its CRL cannot be installed (7.8.2.1 validates each CRL against the new
// list), so the leaf's revocation status is unknown; the group suppresses that one status (OPC 10000-12
// TrustListValidationOptions, SuppressRevocationStatusUnknown) so only the intermediate's revocation can
// close the channel.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-129-TRUST-LIST-LIVE-COMPLETENESS, scope=function)
TEST_P(CertificateValidationTrustListLive, ACrlRevokingTheIntermediateClosesTheChannelWithIssuerRevoked)
{
  mServerOptions.set(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown);
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  const auto& subject = pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Client);
  ASSERT_TRUE(connect_as(subject).is_good());
  auto disconnects = std::make_shared<DisconnectRecorder>();
  mConnections.back().set_connection_observer(disconnects);
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());

  const auto revoking = pki().root_crl_revoking(family(), *pki().intermediate(family()));
  ASSERT_EQ(push_trust_list(mConnections.back(),
              trust_list({pki().root(family())}, {revoking}, /*withIntermediate=*/false)),
    StatusCode{Status::Good});
  EXPECT_TRUE(eventually([&] { return disconnects->any(); }));
  auto reconnect = connect_as(subject);
  ASSERT_TRUE(reconnect.is_bad());
  EXPECT_EQ(reconnect.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificateIssuerRevoked}, *subject.certificate);
    }));
}

// C10 (negative): RemoveCertificate of a trusted self-signed client certificate closes that client's channel
// and refuses its reconnect as untrusted.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-129-TRUST-LIST-LIVE-COMPLETENESS, scope=function)
TEST_P(CertificateValidationTrustListLive, RemoveCertificateClosesTheRemovedCertificatesChannel)
{
  const auto removable =
    pki().issue_self_signed(family(), "Removable " + policy_name(GetParam().policy), clientUri);
  auto trust = pki().trust_material(family());
  trust.trusted.push_back(removable.certificate);
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), trust);
  ASSERT_TRUE(connect_as(removable).is_good());
  auto disconnects = std::make_shared<DisconnectRecorder>();
  mConnections.back().set_connection_observer(disconnects);
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());

  ASSERT_EQ(remove_certificate(mConnections.back(), *removable.certificate), StatusCode{Status::Good});
  EXPECT_TRUE(eventually([&] { return disconnects->any(); }))
    << "the removed certificate's channel must close";
  auto reconnect = connect_as(removable);
  ASSERT_TRUE(reconnect.is_bad());
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().rejected_with(
        StatusCode{Status::BadCertificateUntrusted}, *removable.certificate);
    }));
}

// C10 (control): AddCertificate of a refused self-signed client certificate makes its reconnect succeed.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-129-TRUST-LIST-LIVE-COMPLETENESS, scope=function)
TEST_P(CertificateValidationTrustListLive, AddCertificateAcceptsTheAddedCertificateOnReconnect)
{
  const auto addable =
    pki().issue_self_signed(family(), "Addable " + policy_name(GetParam().policy), clientUri);
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(addable).is_bad()) << "fixture: the self-signed client starts untrusted";
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());
  ASSERT_EQ(add_certificate(mConnections.back(), *addable.certificate), StatusCode{Status::Good});
  auto reconnect = connect_as(addable);
  EXPECT_TRUE(reconnect.is_good()) << "0x" << std::hex << reconnect.status_code().as_uint32();
}

// C10 (negative): a CloseAndUpdate refused because a trusted certificate is expired returns
// Bad_CertificateInvalid and its DiagnosticInfo names the certificate (OPC 10000-12 7.8.2.3, decision 21.8).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-129-TRUST-LIST-LIVE-COMPLETENESS, scope=function)
TEST_P(CertificateValidationTrustListLive, ARefusedCloseAndUpdateNamesTheCertificateInItsDiagnostics)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());
  const auto& expired = pki().leaf(GetParam().policy, CertificateCase::Expired, Role::Client);
  const auto status = push_trust_list(
    mConnections.back(), trust_list({pki().root(family()), expired.certificate}, {pki().root_crl(family())}));
  EXPECT_EQ(status, StatusCode{Status::BadCertificateInvalid});
  ASSERT_TRUE(mLastCloseAndUpdate.has_value());
  EXPECT_TRUE(diagnostics_name(*mLastCloseAndUpdate, policy_name(GetParam().policy) + " Expired"))
    << "the CloseAndUpdate DiagnosticInfo must name the refused certificate";
}

class CertificateValidationRejectedListLive : public CertificateValidationLive
{};

// C12: GetRejectedList over the wire returns the refused UNTRUSTED leaf only; expired, revoked and
// policy-violating refusals are not filed (each refused in the same run, on the same server).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-130-REJECTED-LIST-OVER-THE-WIRE, scope=function)
TEST_P(CertificateValidationRejectedListLive, GetRejectedListReturnsTheUntrustedLeafOnly)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  const auto untrusted =
    pki().issue_self_signed(family(), "RejectedUntrusted " + policy_name(GetParam().policy), clientUri);
  {
    // The policy-violating certificate is one the SDK client itself refuses to present; the test needs the
    // server to receive it (owner decision 2026-10-03, BR-17), so the client's own check is skipped here.
    const ua::client::detail::SkipOwnCertificatePolicyChecksForTests presentAnyCertificate;
    for (const LeafMaterial* refused : {&untrusted,
           &pki().leaf(GetParam().policy, CertificateCase::Expired, Role::Client),
           &pki().leaf(GetParam().policy, CertificateCase::Revoked, Role::Client),
           &pki().leaf(GetParam().policy, CertificateCase::PolicyKeyLength, Role::Client)})
      ASSERT_TRUE(connect_as(*refused).is_bad()) << "fixture: each certificate is refused";
  }
  ASSERT_TRUE(connect_as(admin_leaf()).is_good());

  auto listed = call(mConnections.back(),
    NodeId{ObjectId::ServerConfiguration},
    NodeId{MethodId::ServerConfiguration_GetRejectedList},
    arguments());
  ASSERT_EQ(method_status(listed), StatusCode{Status::Good});
  ASSERT_FALSE(listed.value().output_arguments().empty());
  const auto rejected = listed.value().output_arguments()[0].as<Array<ByteString>>();
  ASSERT_EQ(rejected.size(), 1u) << "only the untrusted leaf is filed";
  EXPECT_EQ(rejected[0], der_of(*untrusted.certificate));
}

class CertificateValidationSuppressedPaths : public CertificateValidationLive
{};

// C13 (server): a suppressed client-certificate expiry is reported for the one validation of the client
// certificate, the SecureChannel's (decision 22.6), naming the presented certificate. CreateSession does not
// validate it again: OPC 10000-4 5.6.2 has the Server "verify that this Certificate is the same as the one it
// used to create the SecureChannel". Cached server of the configuration. The negative arm is the unsuppressed
// Expired row of CertificateValidationServerRefusal.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-133-SUPPRESSED-PATHS, scope=function)
TEST_P(CertificateValidationSuppressedPaths, AClientExpiryIsReportedOnceForTheChannel)
{
  mCachedServer =
    MatrixCache::instance()
      .server_for(
        GetParam().policy, GetParam().mode, validation_options_for(CertificateCase::ExpiredSuppressed))
      .server.get();
  mCachedServer->reset_observations();
  const auto& expired = pki().leaf(GetParam().policy, CertificateCase::ExpiredSuppressed, Role::Client);
  ASSERT_TRUE(connect_as(expired).is_good());
  const StatusCode timeInvalid{Status::BadCertificateTimeInvalid};
  EXPECT_TRUE(eventually(
    [&] { return mCachedServer->hooks().suppressed_count(timeInvalid, *expired.certificate) >= 1; }));
  EXPECT_EQ(mCachedServer->hooks().suppressed_count(timeInvalid, *expired.certificate), 1u)
    << "one report, for the SecureChannel's validation; CreateSession compares, it does not re-validate";
}

// C13 (server): a suppressed USER-certificate expiry on the user-token group is reported for the user token
// and the session activates. The negative arm is the Expired row of CertificateValidationX509UserTokenCause.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-133-SUPPRESSED-PATHS, scope=function)
TEST_P(CertificateValidationSuppressedPaths, AUserCertificateExpiryIsReportedForTheUserToken)
{
  mUserOptions = validation_options_for(CertificateCase::ExpiredSuppressed);
  start_server(pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server),
    pki().trust_material(family()),
    true);
  const auto& user = pki().leaf(GetParam().policy, CertificateCase::ExpiredSuppressed, Role::User);
  auto result = connect_as(subject_leaf(), x509_identity(user), "x509");
  ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  EXPECT_TRUE(eventually(
    [&]
    {
      return mServer->hooks().suppressed_count(
               StatusCode{Status::BadCertificateTimeInvalid}, *user.certificate) == 1;
    }));
  EXPECT_EQ(mAuthenticator->calls(), 1);
}

class CertificateValidationX509UserTokenCause : public CertificateValidationLive
{};

// Ledger correction: an X509 user token refused by Table 106 is Bad_IdentityTokenRejected on the wire, and
// the server reports the exact Table 106 cause for the USER certificate and audits it; the authenticator is
// not called. One cached user-token server per configuration (the user certificate is the variable). The
// control is CertificateValidationX509UserToken.AChainCarryingUserTokenIsAccepted.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-135-X509-TABLE-106-CAUSE, scope=function)
TEST_P(CertificateValidationX509UserTokenCause, TheRefusedUserCertificateIsReportedWithItsTable106Cause)
{
  auto& entry = MatrixCache::instance().user_token_server_for(GetParam().policy, GetParam().mode);
  mCachedServer = entry.server.get();
  mCachedServer->reset_observations();
  const int callsBefore = entry.authenticator->calls();
  const auto expected = expected_outcome(GetParam().certificateCase);
  const auto& user = pki().leaf(GetParam().policy, GetParam().certificateCase, Role::User);

  auto result = connect_as(subject_leaf(), x509_identity(user), "x509");
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  EXPECT_TRUE(
    eventually([&] { return mCachedServer->hooks().rejected_with(expected.table106, *user.certificate); }))
    << "the Table 106 cause 0x" << std::hex << expected.table106.as_uint32()
    << " must name the user certificate";
  ASSERT_TRUE(expected.auditEventType.has_value());
  EXPECT_TRUE(eventually([&]
    { return mCachedServer->events().saw_certificate_event(*expected.auditEventType, *user.certificate); }));
  EXPECT_EQ(entry.authenticator->calls(), callsBefore) << "the authenticator must not be called";
}

/// Records the registration outcomes of a DiscoveryRegistration driver.
class RegistrationRecorder : public app::DiscoveryRegistrationObserver
{
public:
  void on_registration_established(const app::DiscoveryRegistrationInfo& /*info*/) override
  {
    mEstablished.fetch_add(1);
  }

  void on_registration_failed(const app::DiscoveryRegistrationInfo& /*info*/, StatusCode status,
    std::shared_ptr<const ErrorDetail> /*detail*/, std::chrono::steady_clock::time_point /*retryAt*/) override
  {
    std::lock_guard lock(mMutex);
    mFailures.push_back(status);
  }

  void on_registration_deregistered(const app::DiscoveryRegistrationInfo& /*info*/) override
  {}

  int established() const
  {
    return mEstablished.load();
  }

  bool failed_with(StatusCode status) const
  {
    std::lock_guard lock(mMutex);
    return std::find(mFailures.begin(), mFailures.end(), status) != mFailures.end();
  }

private:
  mutable std::mutex mMutex;
  std::atomic<int> mEstablished{0};
  std::vector<StatusCode> mFailures;
};

class CertificateValidationLdsRegistration : public CertificateValidationLive
{
protected:
  void SetUp() override
  {
    CertificateValidationLive::SetUp();
    mLocalDiscoveryServer = true;
  }

  void TearDown() override
  {
    if (mDriver)
    {
      auto done = std::make_shared<std::promise<void>>();
      mDriver->stop_async([done](VoidResult) { done->set_value(); });
      done->get_future().wait_for(ua::test_utils::scaled(std::chrono::milliseconds{8000}));
      mDriver.reset();
    }
    if (mRegistrarClient)
    {
      auto done = std::make_shared<std::promise<void>>();
      mRegistrarClient->shutdown_async([done](VoidResult) { done->set_value(); });
      done->get_future().wait_for(ua::test_utils::scaled(std::chrono::milliseconds{5000}));
      mRegistrarClient.reset();
    }
    CertificateValidationLive::TearDown();
  }

  /// A registering server presenting @p own (ApplicationUri clientUri) registers with the LDS (mServer)
  /// through the production driver (DiscoveryRegistration over ClientLdsRegistrar).
  void register_with_lds(const LeafMaterial& own)
  {
    mRegistrarStore = make_store(mDirectory / "registrar",
      MatrixCache::instance().client_pool().executor(),
      pki().crypto(),
      validation_options_for(CertificateCase::Valid),
      pki().trust_material(family()),
      &own,
      application_certificate_type(GetParam().policy));
    auto applicationConfiguration = ua::test_utils::create_test_config();
    applicationConfiguration.application_description_part().applicationUri = clientUri;
    applicationConfiguration.allowDeprecatedSecurityPolicies = true;
    client::CreateConfig createConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(applicationConfiguration)};
    mRegistrarClient = std::make_shared<client::CoreClient>(
      client::CoreClient::create(MatrixCache::instance().client_pool().executor(),
        std::move(createConfig),
        client::ClientComponents{.crypto = pki().crypto(),
          .applicationGroupCertificateStore = mRegistrarStore,
          .logSink = ua::test_helpers::test_log_sink(),
          .logLevel = LogLevel::Warning}));

    RegisteredServer identity;
    identity.server_uri() = String{clientUri};
    identity.product_uri() = String{"urn:test:certificate-validation:product"};
    identity.server_type() = ApplicationType::Server;
    identity.server_names().payload().push_back(LocalizedText{String{"en"}, String{"Registering server"}});
    identity.discovery_urls().payload().push_back(String{"opc.tcp://registering-server:4840"});
    identity.is_online() = true;

    app::DiscoveryRegistrationConfig config;
    config.targets = {app::DiscoveryTarget{.discoveryUrl = mServer->endpoint_url(),
      .messageSecurityMode = GetParam().mode,
      .securityPolicyId = GetParam().policy}};
    config.cadence = std::chrono::seconds{1};
    config.backoffInitial = std::chrono::seconds{1};
    config.backoffCap = std::chrono::seconds{4};
    config.shutdownDeregisterTimeout = std::chrono::seconds{3};
    mDriver = app::DiscoveryRegistration::create(MatrixCache::instance().client_pool().executor(),
      std::make_shared<app::ClientLdsRegistrar>(mRegistrarClient),
      std::move(identity),
      std::move(config));
    mDriver->set_observer(mRecorder);
    auto started = std::make_shared<std::promise<void>>();
    mDriver->start_async([started](VoidResult) { started->set_value(); });
    started->get_future().wait_for(ua::test_utils::scaled(std::chrono::milliseconds{2000}));
  }

  std::shared_ptr<RegistrationRecorder> mRecorder{std::make_shared<RegistrationRecorder>()};
  std::shared_ptr<CertificateStore> mRegistrarStore;
  std::shared_ptr<client::CoreClient> mRegistrarClient;
  std::shared_ptr<app::DiscoveryRegistration> mDriver;
};

// C13 LDS (control): a registering server presenting its intermediate registers with an LDS trusting the root
// only (the LDS completes the chain from what the server sent).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-134-LDS-CHAIN, scope=function)
TEST_P(CertificateValidationLdsRegistration, AChainPresentingServerRegisters)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  register_with_lds(pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Client));
  EXPECT_TRUE(eventually([&] { return mRecorder->established() >= 1; }, std::chrono::milliseconds{8000}));
}

// C13 LDS (negative, LDS side): the same leaf WITHOUT its intermediate is refused by the LDS.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-134-LDS-CHAIN, scope=function)
TEST_P(CertificateValidationLdsRegistration, TheLdsRefusesARegisteringServerWithoutItsChain)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server), pki().trust_material(family()));
  const auto& own = pki().leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::Client);
  register_with_lds(own);
  EXPECT_TRUE(eventually([&] { return mRecorder->failed_with(StatusCode{Status::BadSecurityChecksFailed}); },
    std::chrono::milliseconds{8000}));
  EXPECT_TRUE(
    mServer->hooks().rejected_with(StatusCode{Status::BadCertificateChainIncomplete}, *own.certificate));
  EXPECT_EQ(mRecorder->established(), 0);
}

// C13 LDS (negative, registering side): the registering server validates the LDS certificate and refuses an
// untrusted one with Bad_CertificateUntrusted.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-134-LDS-CHAIN, scope=function)
TEST_P(CertificateValidationLdsRegistration, TheRegisteringServerRefusesAnUntrustedLds)
{
  start_server(
    pki().leaf(GetParam().policy, CertificateCase::Untrusted, Role::Server), pki().trust_material(family()));
  register_with_lds(pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Client));
  EXPECT_TRUE(eventually([&] { return mRecorder->failed_with(StatusCode{Status::BadCertificateUntrusted}); },
    std::chrono::milliseconds{8000}));
  EXPECT_EQ(mRecorder->established(), 0);
}

class CertificateValidationServerSendsChain : public CertificateValidationLive
{};

// Decision 24 (a, control): the server sends leaf + its issuer chain in the OPN SenderCertificate. The client
// holds the root, the root CRL and the intermediate CRL but NOT the intermediate, so the connect can only
// succeed with the intermediate from the server's header.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-136-SERVER-SENDS-CHAIN, scope=function)
TEST_P(CertificateValidationServerSendsChain, TheClientCompletesTheChainFromTheServersHeader)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Server),
    pki().trust_material(family()));
  auto result = connect_as(subject_leaf());
  EXPECT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
}

// Decision 24 (a, negative): the same leaf with no chain configured is Bad_CertificateChainIncomplete at the
// client, so the row above is discriminating.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-136-SERVER-SENDS-CHAIN, scope=function)
TEST_P(CertificateValidationServerSendsChain, WithoutItsChainTheSameLeafIsChainIncomplete)
{
  start_server(pki().leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::Server),
    pki().trust_material(family()));
  auto result = connect_as(subject_leaf());
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateChainIncomplete});
}

// Decision 24 (b): every endpoint GetEndpoints returns carries serverCertificate = leaf + chain in order.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-136-SERVER-SENDS-CHAIN, scope=function)
TEST_P(CertificateValidationServerSendsChain, GetEndpointsServesTheLeafFollowedByItsChain)
{
  const auto& own = pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Server);
  start_server(own, pki().trust_material(family()));
  ASSERT_TRUE(connect_as(subject_leaf()).is_good());
  auto endpoints = mClients.front().discovery().try_get_endpoints_sync(
    mServer->endpoint_url(), client::GetEndpointsOptions{});
  ASSERT_TRUE(endpoints.is_good());
  ASSERT_FALSE(endpoints.value().empty());
  for (const auto& endpoint : endpoints.value())
    EXPECT_EQ(endpoint.server_certificate(), chain_der(own));
}

// Decision 24 (c, negative): an own chain larger than the peer's MaxSenderCertificateSize fails the open with
// Bad_EncodingLimitsExceeded (the SDK's chosen status; OPC 10000-6 6.7.2.3 names none) instead of sending an
// oversized chunk (which the client would refuse with a transport error instead). 200 CAs exceed any chunk.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-136-SERVER-SENDS-CHAIN, scope=function)
TEST_P(CertificateValidationServerSendsChain, AnOwnChainLargerThanTheSenderCertificateLimitFailsTheOpen)
{
  start_server(pki().deep_chain_leaf(GetParam().policy, 200), pki().trust_material(family()));
  auto result = connect_as(subject_leaf());
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadEncodingLimitsExceeded})
    << "got 0x" << std::hex << result.status_code().as_uint32();
}

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationPresentedChainKept,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationUserTokenGroupLive,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(TokenPolicies, CertificateValidationSecuredTokenOnNoneChannel,
  ::testing::ValuesIn(sign_and_encrypt_params()), token_policy_param_name);

INSTANTIATE_TEST_SUITE_P(EncryptedChannels, CertificateValidationRotation,
  ::testing::ValuesIn(sign_and_encrypt_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationRejectedListLive,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationSuppressedPaths,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(Refused, CertificateValidationX509UserTokenCause,
  ::testing::ValuesIn(matrix_params({CertificateCase::Untrusted,
    CertificateCase::Expired,
    CertificateCase::Revoked,
    CertificateCase::ChainIncomplete})),
  matrix_param_name);

INSTANTIATE_TEST_SUITE_P(LdsConfigurations, CertificateValidationLdsRegistration,
  ::testing::ValuesIn(lds_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationServerSendsChain,
  ::testing::ValuesIn(channel_params()), channel_param_name);

}  // namespace
