// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Self-tests of the GDS emulator (tests/integration/helpers/gds_emulator.h): they prove the test
///        infrastructure itself, through real SDK client sessions, before scenario tests rely on it. They
///        verify no SDK obligation, so each is marked as characterising the gds_emulator component.

#include "gds_emulator.h"

#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_crypto.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_guid.h"
#include "ua_object_id.h"
#include "ua_pull_cert_trust_list_codec.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_trust_list_data_type.h"

#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using namespace ua;
using ua::test::GdsApplicationRecord;
using ua::test::GdsApproval;
using ua::test::GdsEmulator;
using ua::test::GdsMethod;

/// One OPC UA application talking to the emulator: its own certificate, store and Client.
struct TestApplication
{
  std::string uri;
  std::shared_ptr<const X509Certificate> certificate;
  std::shared_ptr<CertificateStore> store;
  std::optional<client::Client> client;
  std::vector<std::shared_ptr<client::Connection>> connections;
};

class GdsEmulatorSelfTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // The file stores write private keys encrypted with the Crypto credential, so it must be non-empty.
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_gds_emulator_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);
    auto created = GdsEmulator::create(
      {.executor = mServerPool.executor(), .crypto = mCrypto, .workDirectory = mTempDir / "gds"});
    ASSERT_TRUE(created.is_good()) << "emulator: " << ua::format(created.status_code()) << " "
                                   << (created.shared_detail() ? ua::to_string(*created.shared_detail())
                                                               : std::string{});
    mEmulator = std::move(created).value();
    make_application(mApplicationA, "a");
    make_application(mApplicationB, "b");
  }

  void TearDown() override
  {
    for (auto* application : {&mApplicationA, &mApplicationB})
    {
      for (auto& connection : application->connections)
      {
        (void)connection->try_close_sync();
      }
      application->connections.clear();
    }
    if (mEmulator)
    {
      mEmulator->shutdown();
    }
    mApplicationA.client.reset();
    mApplicationB.client.reset();
    mEmulator.reset();
    ua::test_utils::stop_pool_in_teardown(mClientPool, "client");
    ua::test_utils::stop_pool_in_teardown(mServerPool, "server");
    std::error_code error;
    std::filesystem::remove_all(mTempDir, error);
  }

  void make_application(TestApplication& application, const std::string& label)
  {
    application.uri = "urn:test:gds:application:" + label;
    Crypto::Name subject;
    subject.commonName = "GDS emulator test application " + label;
    subject.organization = "Test";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back(application.uri);
    alternateName.hostnames.push_back("localhost");
    auto identity = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, DateTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(identity.is_good());
    auto [keys, certificate] = std::move(identity).value();
    application.certificate = certificate;
    const auto storePath = mTempDir / ("client_" + label);
    std::filesystem::create_directories(storePath);
    application.store =
      CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = storePath});
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = certificate;
    own.keys = std::move(keys);
    application.store->add_to_application_certificates_sync(own);
    application.store->add_to_trusted_certificates_sync(mEmulator->server_certificate());
    mEmulator->trust_client_certificate(certificate);

    auto configuration = ua::test_utils::create_test_config();
    configuration.application_description_part().applicationUri = application.uri;
    auto createConfig = (client::CreateConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(configuration)});
    application.client.emplace(client::Client::create(mClientPool.executor(),
      std::move(createConfig),
      client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = application.store,
        .logSink = ua::test_helpers::test_log_sink(),
        .logLevel = LogLevel::Debug}));
  }

  std::shared_ptr<client::Connection> connect(TestApplication& application, MessageSecurityMode mode)
  {
    client::ConnectionConfig config;
    config.endpointUrl = mEmulator->endpoint_url();
    config.securityMode = mode;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mEmulator->server_certificate();
    config.reconnect = std::nullopt;
    auto connected = application.client->try_connect_sync(std::move(config));
    EXPECT_TRUE(connected.is_good()) << "connect: " << ua::format(connected.status_code());
    if (connected.is_bad())
    {
      return nullptr;
    }
    auto connection = std::make_shared<client::Connection>(std::move(connected).value());
    application.connections.push_back(connection);
    return connection;
  }

  CallResult call(client::Connection& connection, GdsMethod method, std::vector<Variant> arguments)
  {
    auto called = connection.typed().try_call_method_sync(
      mEmulator->directory_id(), mEmulator->method_id(method), std::move(arguments));
    if (called.is_bad())
    {
      return CallResult{called.status_code(), called.shared_detail()};
    }
    return std::move(called).value();
  }

  NodeId register_application(client::Connection& connection, const TestApplication& application)
  {
    GdsApplicationRecord record;
    record.applicationUri = application.uri;
    record.applicationType = ApplicationType::Client;
    record.applicationNames.push_back(LocalizedText{"en", "Test application"});
    record.productUri = "urn:test:gds:product";
    auto registered =
      call(connection, GdsMethod::RegisterApplication, {mEmulator->encode_application_record(record)});
    EXPECT_TRUE(registered.is_good()) << "RegisterApplication: " << ua::format(registered.status_code());
    if (registered.is_bad() || registered.value().output_arguments().size() != 1)
    {
      return {};
    }
    const auto* applicationId = registered.value().output_arguments()[0].try_as<NodeId>();
    return applicationId ? *applicationId : NodeId{};
  }

  /// A DER PKCS #10 request for a fresh RSA key carrying @p uri; @p keys receives the key.
  ByteString make_csr(const std::string& uri, std::shared_ptr<const AsymmetricKeyPair>& keys)
  {
    keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    Crypto::CreateCsrConfig parameters;
    parameters.subject.commonName = "CSR subject";
    parameters.subject.organization = "Test";
    parameters.subjectKeys = keys;
    parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    parameters.keyUsage.digitalSignature = true;
    parameters.keyUsage.keyEncipherment = true;
    parameters.subjectAlternateName.uris.push_back(uri);
    parameters.subjectAlternateName.hostnames.push_back("localhost");
    std::promise<ByteStringResult> promise;
    mCrypto->create_certificate_signing_request_async(
      parameters, [&promise](ByteStringResult result) { promise.set_value(std::move(result)); });
    auto csr = promise.get_future().get();
    EXPECT_TRUE(csr.is_good());
    return csr.is_good() ? csr.value() : ByteString{};
  }

  NodeId start_signing(client::Connection& connection, const NodeId& applicationId, const ByteString& csr)
  {
    auto started = call(connection,
      GdsMethod::StartSigningRequest,
      {Variant{applicationId}, Variant{NodeId{}}, Variant{NodeId{}}, Variant{csr}});
    EXPECT_TRUE(started.is_good()) << "StartSigningRequest: " << ua::format(started.status_code());
    if (started.is_bad() || started.value().output_arguments().size() != 1)
    {
      return {};
    }
    const auto* requestId = started.value().output_arguments()[0].try_as<NodeId>();
    return requestId ? *requestId : NodeId{};
  }

  CallResult finish(client::Connection& connection, const NodeId& applicationId, const NodeId& requestId)
  {
    return call(connection, GdsMethod::FinishRequest, {Variant{applicationId}, Variant{requestId}});
  }

  static RelativePath one_step(ReferenceTypeId reference, QualifiedName name)
  {
    RelativePathElement element;
    element.reference_type_id() = NodeId{reference};
    element.include_subtypes() = true;
    element.target_name() = std::move(name);
    RelativePath path;
    path.elements().push_back(std::move(element));
    return path;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::filesystem::path mTempDir;
  boost::asio::thread_pool mServerPool;
  boost::asio::thread_pool mClientPool;
  std::shared_ptr<GdsEmulator> mEmulator;
  TestApplication mApplicationA;
  TestApplication mApplicationB;
};

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, ImportedDirectoryAndMethodsResolveByStandardBrowsePath)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto gds = mEmulator->gds_namespace_index();
  ASSERT_NE(gds, 0);

  auto directory = connection->typed().try_resolve_path_sync(
    NodeId{ObjectId::ObjectsFolder}, one_step(ReferenceTypeId::Organizes, QualifiedName{gds, "Directory"}));
  ASSERT_TRUE(directory.is_good()) << to_string(directory.status_code());
  EXPECT_EQ(directory.value(), mEmulator->directory_id());

  for (auto [method, name] : {std::pair{GdsMethod::FindApplications, "FindApplications"},
         std::pair{GdsMethod::RegisterApplication, "RegisterApplication"},
         std::pair{GdsMethod::UnregisterApplication, "UnregisterApplication"},
         std::pair{GdsMethod::GetApplication, "GetApplication"},
         std::pair{GdsMethod::StartSigningRequest, "StartSigningRequest"},
         std::pair{GdsMethod::StartNewKeyPairRequest, "StartNewKeyPairRequest"},
         std::pair{GdsMethod::FinishRequest, "FinishRequest"},
         std::pair{GdsMethod::GetCertificateGroups, "GetCertificateGroups"},
         std::pair{GdsMethod::GetTrustList, "GetTrustList"},
         std::pair{GdsMethod::GetCertificateStatus, "GetCertificateStatus"}})
  {
    auto resolved = connection->typed().try_resolve_path_sync(
      mEmulator->directory_id(), one_step(ReferenceTypeId::HasComponent, QualifiedName{gds, name}));
    ASSERT_TRUE(resolved.is_good()) << name << ": " << to_string(resolved.status_code());
    EXPECT_EQ(resolved.value(), mEmulator->method_id(method)) << name;
  }
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, SigningRequestIssuesCaSignedCertificateForTheCsrKey)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto applicationId = register_application(*connection, mApplicationA);
  ASSERT_FALSE(applicationId.is_null());

  // FindApplications returns exactly the registered record (Part 12 6.6.4).
  auto found = call(*connection, GdsMethod::FindApplications, {Variant{String{mApplicationA.uri}}});
  ASSERT_TRUE(found.is_good());
  ASSERT_EQ(found.value().output_arguments().size(), 1u);
  const auto& records = found.value().output_arguments()[0].as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(records.size(), 1u);
  auto record = mEmulator->decode_application_record(Variant{records.payload()[0].get()->clone()});
  ASSERT_TRUE(record.is_good());
  EXPECT_EQ(record.value().applicationId, applicationId);
  EXPECT_EQ(record.value().applicationUri, mApplicationA.uri);

  std::shared_ptr<const AsymmetricKeyPair> keys;
  const auto csr = make_csr(mApplicationA.uri, keys);
  const auto requestId = start_signing(*connection, applicationId, csr);
  ASSERT_FALSE(requestId.is_null());

  auto finished = finish(*connection, applicationId, requestId);
  ASSERT_TRUE(finished.is_good()) << ua::format(finished.status_code());
  const auto& outputs = finished.value().output_arguments();
  ASSERT_EQ(outputs.size(), 3u);
  const auto* certificateDer = outputs[0].try_as<ByteString>();
  ASSERT_NE(certificateDer, nullptr);
  const auto certificate = mCrypto->read_certificate_from_der(span<const byte>{*certificateDer});
  EXPECT_TRUE(certificate->issued_by(*mEmulator->ca_certificate()));
  EXPECT_EQ(certificate->public_key(), keys->public_key_der());
  const auto uris = certificate->san_uris();
  EXPECT_NE(std::find(uris.begin(), uris.end(), mApplicationA.uri), uris.end());
  const auto* privateKey = outputs[1].try_as<ByteString>();
  EXPECT_TRUE(outputs[1].empty() || (privateKey && privateKey->empty()));
  auto issuers = outputs[2].to_vector<ByteString>();
  ASSERT_TRUE(issuers.is_good());
  ASSERT_EQ(issuers.value().size(), 1u);
  EXPECT_EQ(issuers.value()[0], mEmulator->ca_certificate()->der_encoding());
  ASSERT_EQ(mEmulator->issued_certificates(applicationId).size(), 1u);
  EXPECT_EQ(mEmulator->call_count(GdsMethod::StartSigningRequest), 1u);
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, PendingApprovalAnswersNothingToDoUntilApproved)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto applicationId = register_application(*connection, mApplicationA);
  ASSERT_FALSE(applicationId.is_null());
  mEmulator->set_next_approval(GdsApproval::pending_for(2));
  std::shared_ptr<const AsymmetricKeyPair> keys;
  const auto requestId = start_signing(*connection, applicationId, make_csr(mApplicationA.uri, keys));
  ASSERT_FALSE(requestId.is_null());

  EXPECT_EQ(finish(*connection, applicationId, requestId).status_code().as_status(), Status::BadNothingToDo);
  EXPECT_EQ(finish(*connection, applicationId, requestId).status_code().as_status(), Status::BadNothingToDo);
  auto approved = finish(*connection, applicationId, requestId);
  EXPECT_TRUE(approved.is_good()) << ua::format(approved.status_code());
  EXPECT_EQ(mEmulator->call_count(GdsMethod::FinishRequest), 3u);
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, TrustListDownloadMatchesConfigurationAndLastUpdateTimeMoves)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto applicationId = register_application(*connection, mApplicationA);
  ASSERT_FALSE(applicationId.is_null());

  auto trustList = call(*connection, GdsMethod::GetTrustList, {Variant{applicationId}, Variant{NodeId{}}});
  ASSERT_TRUE(trustList.is_good()) << ua::format(trustList.status_code());
  const auto* trustListId = trustList.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(trustListId, nullptr);
  EXPECT_EQ(*trustListId, mEmulator->default_application_trust_list_id());

  auto readLastUpdate = [&]
  {
    auto value =
      connection->try_read_value_sync(mEmulator->default_application_trust_list_last_update_time_id());
    EXPECT_TRUE(value.is_good());
    const auto* time = value.is_good() ? value.value().value().try_as<DateTime>() : nullptr;
    return time ? *time : DateTime{};
  };
  auto download = [&]
  {
    auto body = connection->files().try_read_all_sync(*trustListId);
    EXPECT_TRUE(body.is_good()) << ua::format(body.status_code());
    auto decoded = client::detail::decode_trust_list_body(body.is_good() ? body.value() : ByteString{});
    EXPECT_TRUE(decoded.is_good());
    return decoded.is_good() ? decoded.value() : TrustListDataType{};
  };
  auto holds = [](const auto& list, const ByteString& der)
  {
    return std::find(list.begin(), list.end(), der) != list.end();
  };

  const auto before = readLastUpdate();
  EXPECT_FALSE(before.is_null());
  const auto initial = download();
  EXPECT_TRUE(holds(initial.trusted_certificates(), mEmulator->ca_certificate()->der_encoding()));
  EXPECT_TRUE(holds(initial.trusted_crls(), mEmulator->ca_crl()->der_encoding()));

  Crypto::Name subject;
  subject.commonName = "Another CA";
  subject.organization = "Test";
  auto anotherCa = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    subject, DateTime{2050, 1, 1, 0, 0, 0}, {}, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(anotherCa.is_good());
  const auto added = anotherCa.value().second;
  EXPECT_FALSE(holds(initial.trusted_certificates(), added->der_encoding()));
  mEmulator->add_trusted_certificate(mEmulator->default_application_group_id(), added);

  EXPECT_GT(readLastUpdate(), before);
  const auto updated = download();
  EXPECT_TRUE(holds(updated.trusted_certificates(), added->der_encoding()));
  EXPECT_TRUE(holds(updated.trusted_certificates(), mEmulator->ca_certificate()->der_encoding()));
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, SigningRequestOnSignOnlyChannelIsRefused)
{
  auto signOnly = connect(mApplicationA, MessageSecurityMode::Sign);
  ASSERT_NE(signOnly, nullptr);
  const auto applicationId = register_application(*signOnly, mApplicationA);  // authenticated suffices
  ASSERT_FALSE(applicationId.is_null());
  std::shared_ptr<const AsymmetricKeyPair> keys;
  const auto csr = make_csr(mApplicationA.uri, keys);

  auto refused = call(*signOnly,
    GdsMethod::StartSigningRequest,
    {Variant{applicationId}, Variant{NodeId{}}, Variant{NodeId{}}, Variant{csr}});
  EXPECT_EQ(refused.status_code().as_status(), Status::BadUserAccessDenied);

  // Control: the same request over SignAndEncrypt is accepted.
  auto encrypted = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(encrypted, nullptr);
  EXPECT_FALSE(start_signing(*encrypted, applicationId, csr).is_null());
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, FinishRequestFromAnotherApplicationIsRefused)
{
  auto connectionA = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  auto connectionB = connect(mApplicationB, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connectionA, nullptr);
  ASSERT_NE(connectionB, nullptr);
  const auto applicationA = register_application(*connectionA, mApplicationA);
  const auto applicationB = register_application(*connectionB, mApplicationB);
  ASSERT_FALSE(applicationA.is_null());
  ASSERT_FALSE(applicationB.is_null());
  ASSERT_NE(applicationA, applicationB);
  std::shared_ptr<const AsymmetricKeyPair> keys;
  const auto requestA = start_signing(*connectionA, applicationA, make_csr(mApplicationA.uri, keys));
  ASSERT_FALSE(requestA.is_null());

  // B presenting A's ApplicationId lacks ApplicationSelfAdmin for A (Part 12 7.2).
  EXPECT_EQ(
    finish(*connectionB, applicationA, requestA).status_code().as_status(), Status::BadUserAccessDenied);
  // B presenting its own ApplicationId: the requestId is not a request of that Application (7.9.5).
  EXPECT_EQ(
    finish(*connectionB, applicationB, requestA).status_code().as_status(), Status::BadInvalidArgument);
  // Control: A finishes its own request.
  EXPECT_TRUE(finish(*connectionA, applicationA, requestA).is_good());
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, CertificateGroupOutsideTheDirectoryIsRefused)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto applicationId = register_application(*connection, mApplicationA);
  ASSERT_FALSE(applicationId.is_null());
  std::shared_ptr<const AsymmetricKeyPair> keys;
  const auto csr = make_csr(mApplicationA.uri, keys);

  // The server's own ns=0 ServerConfig group is not one of the CertificateManager's groups.
  auto refused = call(*connection,
    GdsMethod::StartSigningRequest,
    {Variant{applicationId},
      Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}},
      Variant{NodeId{}},
      Variant{csr}});
  EXPECT_EQ(refused.status_code().as_status(), Status::BadInvalidArgument);
  // Control: the Directory's own DefaultApplicationGroup is accepted.
  auto accepted = call(*connection,
    GdsMethod::StartSigningRequest,
    {Variant{applicationId},
      Variant{mEmulator->default_application_group_id()},
      Variant{NodeId{}},
      Variant{csr}});
  EXPECT_TRUE(accepted.is_good()) << ua::format(accepted.status_code());
}

// @characterises(gds_emulator)
// Without a password the key comes back unprotected (OPC 10000-12 7.9.5), so any Crypto reads it.
TEST_F(GdsEmulatorSelfTest, UnprotectedKeyHelperWritesAPemAnyCryptoReads)
{
  for (const auto algorithm : {CertificateKeyAlgorithm::Rsa, CertificateKeyAlgorithm::EccNistP256})
  {
    auto pem = ua::test::unprotected_private_key_pem(algorithm);
    ASSERT_TRUE(pem.is_good());
    const std::string text(reinterpret_cast<const char*>(pem.value().data()), pem.value().size());
    EXPECT_NE(text.find("-----BEGIN PRIVATE KEY-----"), std::string::npos) << "PKCS #8, not encrypted";
    auto other = create_default_crypto([]() { return ua::SecureString{"z"}; });
    std::vector<byte> copy(pem.value().size());
    std::memcpy(copy.data(), pem.value().data(), copy.size());
    EXPECT_NE(other->get_private_key_from_pem(algorithm, span<byte>{copy}), nullptr);
  }
}

// @characterises(gds_emulator)
TEST_F(GdsEmulatorSelfTest, NewKeyPairRequestReturnsPasswordProtectedKeyForTheCertificate)
{
  auto connection = connect(mApplicationA, MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(connection, nullptr);
  const auto applicationId = register_application(*connection, mApplicationA);
  ASSERT_FALSE(applicationId.is_null());
  auto newKeyPair = [&](std::string format)
  {
    return call(*connection,
      GdsMethod::StartNewKeyPairRequest,
      {Variant{applicationId},
        Variant{NodeId{}},
        Variant{NodeId{}},
        Variant{String{"CN=Key pair test/O=Test"}},
        Variant{Array<String>{}},
        Variant{String{std::move(format)}},
        Variant{String{"secret"}}});
  };

  // PFX is not produced: the Crypto interface has no PKCS #12 export.
  EXPECT_EQ(newKeyPair("PFX").status_code().as_status(), Status::BadNotSupported);

  auto started = newKeyPair("PEM");
  ASSERT_TRUE(started.is_good()) << ua::format(started.status_code());
  const auto* requestId = started.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(requestId, nullptr);
  auto finished = finish(*connection, applicationId, *requestId);
  ASSERT_TRUE(finished.is_good()) << ua::format(finished.status_code());
  const auto& outputs = finished.value().output_arguments();
  ASSERT_EQ(outputs.size(), 3u);
  const auto certificate = mCrypto->read_certificate_from_der(span<const byte>{outputs[0].as<ByteString>()});
  EXPECT_TRUE(certificate->issued_by(*mEmulator->ca_certificate()));
  auto pem = outputs[1].as<ByteString>();
  ASSERT_FALSE(pem.empty());
  const auto secretCrypto = create_default_crypto([]() { return ua::SecureString{"secret"}; });
  std::vector<byte> pemBytes(span<const byte>{pem}.begin(), span<const byte>{pem}.end());
  const auto keys =
    secretCrypto->get_private_key_from_pem(certificate->key_algorithm(), span<byte>{pemBytes});
  EXPECT_EQ(keys->public_key_der(), certificate->public_key());
}

}  // namespace
