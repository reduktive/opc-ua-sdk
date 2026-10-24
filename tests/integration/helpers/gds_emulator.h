// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A Global Discovery Server / CertificateManager emulator for integration tests (Part 12 sections
///        6.6 and 7.9): an SDK Server that imports the official `Opc.Ua.Gds.NodeSet2.xml`, serves the
///        standard `Objects/Directory` Methods (application directory and pull certificate management) with
///        a real test CA, and serves the DefaultApplicationGroup TrustList through the SDK's own
///        TrustListManager. Test infrastructure, not product code: the fixture drives it through the plain
///        C++ control interface below (approval policy, update flags, TrustList contents, revocation) and
///        reads its oracles (call counts, last arguments, issued certificates).

#ifndef UA_TEST_GDS_EMULATOR_H
#define UA_TEST_GDS_EMULATOR_H

#include "ua_application_type.h"
#include "ua_byte_string.h"
#include "ua_crypto.h"
#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_variant.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::test
{

/// The Directory Methods the emulator serves, used to index the call-count and last-argument oracles.
enum class GdsMethod : std::uint8_t
{
  FindApplications,
  RegisterApplication,
  UnregisterApplication,
  GetApplication,
  StartSigningRequest,
  StartNewKeyPairRequest,
  FinishRequest,
  GetCertificateGroups,
  GetTrustList,
  GetCertificateStatus,
};

/// How the emulator answers FinishRequest for the next certificate request it accepts.
struct GdsApproval
{
  enum class Kind : std::uint8_t
  {
    Immediate,  ///< The first FinishRequest succeeds.
    Pending,  ///< FinishRequest answers Bad_NothingToDo for `pendingPolls` calls, then succeeds.
    Reject,  ///< FinishRequest answers `rejection` (Part 12 7.9.5: Bad_RequestNotAllowed by default).
  };

  Kind kind{Kind::Immediate};
  std::size_t pendingPolls{0};
  StatusCode rejection{Status::BadRequestNotAllowed};

  static GdsApproval immediate()
  {
    return {};
  }

  static GdsApproval pending_for(std::size_t polls)
  {
    return {Kind::Pending, polls, StatusCode{Status::BadRequestNotAllowed}};
  }

  static GdsApproval reject(StatusCode status = StatusCode{Status::BadRequestNotAllowed})
  {
    return {Kind::Reject, 0, status};
  }
};

/// The fields of the Part 12 6.6.5 ApplicationRecordDataType (Table 7), in wire order.
struct GdsApplicationRecord
{
  NodeId applicationId;
  std::string applicationUri;
  ApplicationType applicationType{ApplicationType::Client};
  std::vector<LocalizedText> applicationNames;
  std::string productUri;
  std::vector<std::string> discoveryUrls;
  std::vector<std::string> serverCapabilities;
};

/// What the emulator recorded about one issued certificate.
struct GdsIssuedCertificate
{
  NodeId applicationId;
  NodeId requestId;
  NodeId certificateGroupId;
  NodeId certificateTypeId;
  std::shared_ptr<const X509Certificate> certificate;
  bool newKeyPair{false};
};

/// Construction parameters.
struct GdsEmulatorOptions
{
  /// Executor of a thread pool the fixture owns (and stops after @ref GdsEmulator::shutdown).
  boost::asio::any_io_executor executor;
  std::shared_ptr<const Crypto> crypto;
  /// Scratch directory for the emulator's certificate stores; created if absent, never removed.
  std::filesystem::path workDirectory;
  /// Path of the GDS NodeSet (copied next to integration_tests by tests/CMakeLists.txt).
  std::filesystem::path nodeSetPath{"Opc.Ua.Gds.NodeSet2.xml"};
  /// ApplicationUri of the emulator server (its certificate SAN URI).
  std::string applicationUri{"urn:test:gds:emulator"};
};

/// A new private key for @p algorithm (Rsa: 2048 bits; otherwise NIST P-256) as an UNPROTECTED PKCS #8 PEM:
/// what a CertificateManager returns from FinishRequest for a StartNewKeyPairRequest that named no password
/// (OPC 10000-12 7.9.5). The SDK Crypto cannot write one, so test GDS stand-ins use this.
Result<ByteString> unprotected_private_key_pem(CertificateKeyAlgorithm algorithm);

/// The GDS emulator. Create on the test thread, call @ref shutdown from TearDown before stopping the pool.
/// Every member is thread-safe; the Method handlers run on the server's threads.
class GdsEmulator
{
public:
  /// Builds the server, imports the GDS NodeSet, installs the handlers and starts listening. Blocking: call
  /// from the test thread only. A failure names what was missing (NodeSet file, Directory instance, a
  /// Method) in its ErrorDetail.
  static Result<std::shared_ptr<GdsEmulator>> create(GdsEmulatorOptions options);

  GdsEmulator(const GdsEmulator&) = delete;
  GdsEmulator& operator=(const GdsEmulator&) = delete;
  GdsEmulator(GdsEmulator&&) = delete;
  GdsEmulator& operator=(GdsEmulator&&) = delete;
  /// Does not block and does not stop the server; call @ref shutdown first.
  ~GdsEmulator();

  /// Stops the TrustList service and shuts the server down. Blocking; idempotent; test thread only.
  void shutdown();

  // ---- Connection facts ----
  [[nodiscard]] const std::string& endpoint_url() const;
  [[nodiscard]] std::shared_ptr<const X509Certificate> server_certificate() const;
  [[nodiscard]] std::uint16_t gds_namespace_index() const;
  [[nodiscard]] NodeId directory_id() const;
  [[nodiscard]] NodeId method_id(GdsMethod method) const;
  [[nodiscard]] NodeId default_application_group_id() const;
  [[nodiscard]] NodeId default_application_trust_list_id() const;
  [[nodiscard]] NodeId default_application_trust_list_last_update_time_id() const;

  /// Lets @p certificate open a SecureChannel to the emulator (the GDS server's own channel trust).
  void trust_client_certificate(std::shared_ptr<const X509Certificate> certificate);
  /// Grants the ApplicationAdmin Privilege (Part 12 6.2 Table 2, 7.2 Table 20) to the application whose
  /// SecureChannel certificate is @p certificate: it may register and manage any application.
  void grant_application_admin(std::shared_ptr<const X509Certificate> certificate);

  // ---- Controls ----
  /// Queues the approval policy for the next accepted StartSigningRequest / StartNewKeyPairRequest. With
  /// an empty queue a request is approved immediately.
  void set_next_approval(GdsApproval approval);
  /// Sets what GetCertificateStatus answers for (application, group, type). A null group or type means the
  /// default, as the Method itself resolves them (Part 12 7.9.10).
  void set_update_required(const NodeId& applicationId, const NodeId& certificateGroupId,
    const NodeId& certificateTypeId, bool updateRequired);
  /// TrustList edits of a CertificateGroup (Part 12 7.8.2); each bumps the group's LastUpdateTime.
  void add_trusted_certificate(
    const NodeId& certificateGroupId, std::shared_ptr<const X509Certificate> certificate);
  void remove_trusted_certificate(const NodeId& certificateGroupId, const X509Certificate& certificate);
  void add_issuer_certificate(
    const NodeId& certificateGroupId, std::shared_ptr<const X509Certificate> certificate);
  void remove_issuer_certificate(const NodeId& certificateGroupId, const X509Certificate& certificate);
  void add_trusted_crl(const NodeId& certificateGroupId, std::shared_ptr<const X509Crl> crl);
  void add_issuer_crl(const NodeId& certificateGroupId, std::shared_ptr<const X509Crl> crl);
  /// Revokes @p certificate: its serial joins the CA CRL (republished in every TrustList that carries it)
  /// and the certificate is removed from every TrustList.
  void revoke_certificate(const X509Certificate& certificate);
  /// Issues a certificate for @p subjectKeys signed by the emulator's CA, with the parameters FinishRequest
  /// certificates carry, outside any request: a peer of the application under test (a plant server) holds
  /// it, so revoking it is a revocation the application learns from the GDS. Blocking; test thread only.
  [[nodiscard]] std::shared_ptr<const X509Certificate> issue_certificate(
    std::shared_ptr<const AsymmetricKeyPair> subjectKeys, Crypto::Name subject,
    Crypto::SubjectAlternateName alternateName);

  // ---- Oracles ----
  [[nodiscard]] std::shared_ptr<const X509Certificate> ca_certificate() const;
  [[nodiscard]] std::shared_ptr<const X509Crl> ca_crl() const;
  [[nodiscard]] std::size_t call_count(GdsMethod method) const;
  [[nodiscard]] std::vector<Variant> last_arguments(GdsMethod method) const;
  [[nodiscard]] std::vector<GdsIssuedCertificate> issued_certificates(const NodeId& applicationId) const;
  [[nodiscard]] std::optional<GdsApplicationRecord> application(const NodeId& applicationId) const;
  [[nodiscard]] DateTime trust_list_last_update_time(const NodeId& certificateGroupId) const;

  // ---- ApplicationRecordDataType codec for test clients ----
  /// Encodes @p record as the ExtensionObject a client passes to RegisterApplication (binary encoding
  /// ns=GDS;i=134, Part 12 6.6.5). The value reports its DataType, so a tier-2 client accepts it as a
  /// structured Method argument without resolving the GDS types. The emulator's namespace index is the
  /// client's, as the client uses the server's namespace table.
  [[nodiscard]] Variant encode_application_record(const GdsApplicationRecord& record) const;
  /// The ApplicationRecordDataType DataType NodeId (ns=GDS;i=1).
  [[nodiscard]] NodeId application_record_data_type_id() const;
  /// Decodes one ApplicationRecordDataType ExtensionObject (FindApplications / GetApplication output).
  [[nodiscard]] Result<GdsApplicationRecord> decode_application_record(const Variant& value) const;

  struct State;

private:
  GdsEmulator() = default;

  std::shared_ptr<State> mState;
};

}  // namespace ua::test

#endif  // UA_TEST_GDS_EMULATOR_H
