// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "gds_emulator.h"

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_binary_codec.h"
#include "ua_built_in_authenticators.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_certificate_store.h"
#include "ua_certificate_store_files.h"
#include "ua_codec_namespace_context.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_guid.h"
#include "ua_memory_stream.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_value_source.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_server.h"
#include "ua_server_components.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_observer.h"
#include "ua_structure_factory.h"
#include "ua_transport_address.h"
#include "ua_trust_list_manager.h"
#include "ua_unknown_structure.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/strand.hpp>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <utility>

namespace ua::test
{

using namespace ::ua::server;

namespace
{

/// A new private key for @p algorithm as an UNPROTECTED PKCS #8 PEM (OPC 10000-12 7.9.5, no password).
Result<ByteString> generate_unprotected_pem(CertificateKeyAlgorithm algorithm)
{
  // The EVP_PKEY_CTX calls, not OpenSSL 3's EVP_PKEY_Q_keygen, so the helper also builds against 1.1.1.
  const bool rsa = algorithm == CertificateKeyAlgorithm::Rsa;
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(rsa ? EVP_PKEY_RSA : EVP_PKEY_EC, nullptr);
  EVP_PKEY* key = nullptr;
  if (context == nullptr || EVP_PKEY_keygen_init(context) <= 0 ||
      (rsa ? EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048)
           : EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1)) <= 0 ||
      EVP_PKEY_keygen(context, &key) <= 0)
  {
    EVP_PKEY_free(key);
    key = nullptr;
  }
  EVP_PKEY_CTX_free(context);
  if (key == nullptr)
    return StatusCode{Status::BadInternalError,
      make_error_detail("GdsKeyGenerationFailed", "OpenSSL key generation failed", "GdsEmulator")};
  BIO* bio = BIO_new(BIO_s_mem());
  const bool written =
    bio != nullptr && PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
  ByteString pem;
  if (written)
  {
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    pem = ByteString{
      std::vector<byte>(reinterpret_cast<const byte*>(data), reinterpret_cast<const byte*>(data) + length)};
  }
  BIO_free(bio);
  EVP_PKEY_free(key);
  if (!written)
    return StatusCode{Status::BadInternalError,
      make_error_detail("GdsKeyExportFailed", "OpenSSL could not write the key", "GdsEmulator")};
  return pem;
}

constexpr std::string_view gdsNamespaceUri{"http://opcfoundation.org/UA/GDS/"};
constexpr std::string_view errorSource{"integration.gds_emulator"};
/// ApplicationRecordDataType DefaultBinary encoding, ns=GDS;i=134 in Opc.Ua.Gds.NodeSet2.xml (Part 12 6.6.5).
constexpr std::uint32_t applicationRecordBinaryEncodingId = 134;
/// ApplicationRecordDataType DataType, ns=GDS;i=1 in Opc.Ua.Gds.NodeSet2.xml.
constexpr std::uint32_t applicationRecordDataTypeId = 1;
constexpr std::size_t methodCount = 10;

std::size_t index_of(GdsMethod method)
{
  return static_cast<std::size_t>(method);
}

std::string_view browse_name_of(GdsMethod method)
{
  switch (method)
  {
  case GdsMethod::FindApplications:
    return "FindApplications";
  case GdsMethod::RegisterApplication:
    return "RegisterApplication";
  case GdsMethod::UnregisterApplication:
    return "UnregisterApplication";
  case GdsMethod::GetApplication:
    return "GetApplication";
  case GdsMethod::StartSigningRequest:
    return "StartSigningRequest";
  case GdsMethod::StartNewKeyPairRequest:
    return "StartNewKeyPairRequest";
  case GdsMethod::FinishRequest:
    return "FinishRequest";
  case GdsMethod::GetCertificateGroups:
    return "GetCertificateGroups";
  case GdsMethod::GetTrustList:
    return "GetTrustList";
  case GdsMethod::GetCertificateStatus:
    return "GetCertificateStatus";
  }
  return {};
}

CallResult bad(Status status, std::string code, std::string text)
{
  return CallResult{
    StatusCode{status}, make_error_detail(std::move(code), std::move(text), std::string{errorSource})};
}

CallResult good(std::vector<Variant> outputs)
{
  CallMethodResult result;
  for (auto& output : outputs)
  {
    result.output_arguments().push_back(std::move(output));
  }
  return CallResult{std::move(result)};
}

/// A NodeId input argument; an empty Variant is a null NodeId. nullopt = wrong type.
std::optional<NodeId> node_id_argument(const CallMethodRequest& request, std::size_t index)
{
  const auto& arguments = request.input_arguments();
  if (index >= arguments.size() || arguments[index].empty())
  {
    return NodeId{};
  }
  if (const auto* nodeId = arguments[index].try_as<NodeId>())
  {
    return *nodeId;
  }
  return std::nullopt;
}

std::optional<std::string> string_argument(const CallMethodRequest& request, std::size_t index)
{
  const auto& arguments = request.input_arguments();
  if (index >= arguments.size() || arguments[index].empty())
  {
    return std::string{};
  }
  if (const auto* text = arguments[index].try_as<String>())
  {
    return std::string{*text};
  }
  return std::nullopt;
}

std::optional<std::vector<std::string>> string_array_argument(
  const CallMethodRequest& request, std::size_t index)
{
  const auto& arguments = request.input_arguments();
  if (index >= arguments.size() || arguments[index].empty())
  {
    return std::vector<std::string>{};
  }
  auto values = arguments[index].to_vector<String>();
  if (values.is_bad())
  {
    return std::nullopt;
  }
  std::vector<std::string> out;
  for (const auto& value : values.value())
  {
    out.emplace_back(value);
  }
  return out;
}

std::optional<ByteString> byte_string_argument(const CallMethodRequest& request, std::size_t index)
{
  const auto& arguments = request.input_arguments();
  if (index >= arguments.size() || arguments[index].empty())
  {
    return ByteString{};
  }
  if (const auto* bytes = arguments[index].try_as<ByteString>())
  {
    return *bytes;
  }
  return std::nullopt;
}

std::string lowercase(std::string text)
{
  std::transform(text.begin(),
    text.end(),
    text.begin(),
    [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return text;
}

/// The SubjectAlternativeName of a DER PKCS #10 request. The Crypto interface signs a request but exposes
/// no reader for it, and Part 12 7.9.3 needs the request's ApplicationUri (Bad_CertificateUriInvalid) and
/// copies its subjectAltName into the certificate, so the emulator reads the extension with OpenSSL.
std::optional<Crypto::SubjectAlternateName> read_request_subject_alt_name(const ByteString& requestDer)
{
  const span<const byte> view{requestDer};
  const auto* cursor = reinterpret_cast<const unsigned char*>(view.data());
  X509_REQ* request = d2i_X509_REQ(nullptr, &cursor, static_cast<long>(view.size()));
  if (!request)
  {
    return std::nullopt;
  }
  Crypto::SubjectAlternateName alternateName;
  STACK_OF(X509_EXTENSION)* extensions = X509_REQ_get_extensions(request);
  if (extensions)
  {
    auto* names =
      static_cast<GENERAL_NAMES*>(X509V3_get_d2i(extensions, NID_subject_alt_name, nullptr, nullptr));
    if (names)
    {
      for (int position = 0; position < sk_GENERAL_NAME_num(names); ++position)
      {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, position);
        auto text = [](const ASN1_STRING* value)
        {
          return std::string{reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
        };
        if (name->type == GEN_URI)
        {
          alternateName.uris.push_back(text(name->d.uniformResourceIdentifier));
        }
        else if (name->type == GEN_DNS)
        {
          alternateName.hostnames.push_back(text(name->d.dNSName));
        }
        else if (name->type == GEN_IPADD)
        {
          const auto* data = ASN1_STRING_get0_data(name->d.iPAddress);
          const auto length = ASN1_STRING_length(name->d.iPAddress);
          if (length == 4)
          {
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::copy(data, data + 4, bytes.begin());
            alternateName.ipAddresses.emplace_back(boost::asio::ip::address_v4{bytes});
          }
          else if (length == 16)
          {
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::copy(data, data + 16, bytes.begin());
            alternateName.ipAddresses.emplace_back(boost::asio::ip::address_v6{bytes});
          }
        }
      }
      GENERAL_NAMES_free(names);
    }
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
  }
  X509_REQ_free(request);
  return alternateName;
}

/// Parses the Part 12 7.9.4 subjectName syntax: `/`-separated `name=value` pairs, name one of CN, O, OU,
/// DC, L, S, C, a value containing `/` or `=` in double quotes. nullopt = not valid.
std::optional<Crypto::Name> parse_subject_name(std::string_view subject)
{
  Crypto::Name name;
  std::size_t position = 0;
  while (position < subject.size())
  {
    const auto equals = subject.find('=', position);
    if (equals == std::string_view::npos)
    {
      return std::nullopt;
    }
    const std::string key{subject.substr(position, equals - position)};
    std::string value;
    position = equals + 1;
    if (position < subject.size() && subject[position] == '"')
    {
      const auto close = subject.find('"', position + 1);
      if (close == std::string_view::npos)
      {
        return std::nullopt;
      }
      value = std::string{subject.substr(position + 1, close - position - 1)};
      position = close + 1;
      if (position < subject.size() && subject[position] != '/')
      {
        return std::nullopt;
      }
    }
    else
    {
      const auto slash = subject.find('/', position);
      const auto end = slash == std::string_view::npos ? subject.size() : slash;
      value = std::string{subject.substr(position, end - position)};
      if (value.find('=') != std::string::npos)
      {
        return std::nullopt;
      }
      position = end;
    }
    if (position < subject.size())
    {
      ++position;  // the '/' separator
    }
    if (key == "CN")
      name.commonName = value;
    else if (key == "O")
      name.organization = value;
    else if (key == "OU")
      name.organizationUnit = value;
    else if (key == "L")
      name.locality = value;
    else if (key == "S")
      name.state = value;
    else if (key == "C")
      name.country = value;
    else if (key == "DC")
    {
      // Crypto::Name has no domainComponent field; the requested subject may be ignored (7.9.4).
    }
    else
    {
      return std::nullopt;
    }
  }
  return name;
}

/// The host of an `opc.tcp://host:port/path` style URL; empty when there is none.
std::string host_of(std::string_view url)
{
  const auto scheme = url.find("://");
  if (scheme == std::string_view::npos)
  {
    return {};
  }
  auto rest = url.substr(scheme + 3);
  if (!rest.empty() && rest.front() == '[')
  {
    const auto close = rest.find(']');
    return close == std::string_view::npos ? std::string{} : std::string{rest.substr(1, close - 1)};
  }
  const auto end = rest.find_first_of(":/");
  return std::string{rest.substr(0, end)};
}

template<typename Value>
Result<Value> wait_for(std::function<void(std::function<void(Result<Value>)>)> start)
{
  auto promise = std::make_shared<std::promise<Result<Value>>>();
  auto future = promise->get_future();
  start([promise](Result<Value> result) { promise->set_value(std::move(result)); });
  if (future.wait_for(std::chrono::seconds{60}) != std::future_status::ready)
  {
    return {StatusCode{Status::BadTimeout},
      make_error_detail(
        "GdsEmulatorWaitTimedOut", "an emulator operation did not complete", std::string{errorSource})};
  }
  return future.get();
}

VoidResult wait_void(std::function<void(std::function<void(VoidResult)>)> start)
{
  auto promise = std::make_shared<std::promise<VoidResult>>();
  auto future = promise->get_future();
  start([promise](VoidResult result) { promise->set_value(std::move(result)); });
  if (future.wait_for(std::chrono::seconds{60}) != std::future_status::ready)
  {
    return VoidResult{StatusCode{Status::BadTimeout},
      make_error_detail(
        "GdsEmulatorWaitTimedOut", "an emulator operation did not complete", std::string{errorSource})};
  }
  return future.get();
}

/// An ApplicationRecordDataType value as a test client sends it. The body is the Table 7 field sequence,
/// encoded by the emulator; the value reports its DataType so a tier-2 client can check the argument against
/// the Method's InputArguments without resolving the GDS types first.
class ApplicationRecordStructure final : public Structure
{
public:
  ApplicationRecordStructure(NodeId dataTypeId, NodeId encodingId, ByteString body)
    : mDataTypeId(std::move(dataTypeId)), mEncodingId(std::move(encodingId)), mBody(std::move(body))
  {}

  NodeId type_id(const CodecNamespaceContext&) const override
  {
    return mDataTypeId;
  }

  ExpandedNodeId type_id() const override
  {
    return ExpandedNodeId{mDataTypeId};
  }

  String type_name() const override
  {
    return String{"ApplicationRecordDataType"};
  }

  void encode_id(StackDepth limit, const CodecNamespaceContext&, Encoder& encoder) const override
  {
    encoder.get_ua_binary()->encode(limit, mEncodingId);
  }

  void encode(StackDepth, Encoder& encoder) const override
  {
    encoder.get_ua_binary()->stream().write_all(span<const byte>{mBody});
  }

  unique_ptr<Structure> clone() const override
  {
    return std::make_unique<ApplicationRecordStructure>(mDataTypeId, mEncodingId, mBody);
  }

  std::string to_string(int) const override
  {
    return "ApplicationRecordDataType";
  }

  const ByteString& body() const
  {
    return mBody;
  }

private:
  NodeId mDataTypeId;
  NodeId mEncodingId;
  ByteString mBody;
};

std::vector<RolePermissionType> call_grants()
{
  std::vector<RolePermissionType> grants;
  for (auto role : {ObjectId::WellKnownRole_Anonymous,
         ObjectId::WellKnownRole_AuthenticatedUser,
         ObjectId::WellKnownRole_SecurityAdmin})
  {
    RolePermissionType grant;
    grant.role_id() = NodeId{role};
    grant.permissions() = ua::test_helpers::all_permissions();
    grants.push_back(std::move(grant));
  }
  return grants;
}

}  // namespace

// ---------------------------------------------------------------------------------------------------------
// State shared by the handlers, the observer and the control interface. Handlers capture it weakly.
// ---------------------------------------------------------------------------------------------------------

struct GdsEmulator::State : std::enable_shared_from_this<GdsEmulator::State>
{
  enum class ChannelRequirement
  {
    Any,
    Authenticated,
    Encrypted,
  };

  struct Caller
  {
    MessageSecurityMode mode{MessageSecurityMode::Invalid};
    std::shared_ptr<const X509Certificate> certificate;
    std::string applicationUri;
    bool applicationAdmin{false};
  };

  struct Group
  {
    NodeId id;
    NodeId trustListId;
    NodeId lastUpdateTimeId;
    std::vector<NodeId> certificateTypes;
    CertificateList trusted;
    CrlList trustedCrls;
    CertificateList issuers;
    CrlList issuerCrls;
    DateTime lastUpdateTime;
    std::shared_ptr<CertificateStore> store;
    std::shared_ptr<TrustListManager> trustList;
  };

  struct Request
  {
    NodeId requestId;
    NodeId applicationId;
    NodeId groupId;
    NodeId typeId;
    ByteString callerThumbprint;
    bool newKeyPair{false};
    GdsApproval approval;
    std::size_t pollsRemaining{0};
    std::shared_ptr<const X509Certificate> certificate;
    ByteString privateKey;
    bool delivered{false};
  };

  boost::asio::any_io_executor executor;
  std::shared_ptr<const Crypto> crypto;
  std::filesystem::path workDirectory;
  std::string applicationUri;

  std::optional<Server> server;
  std::shared_ptr<CertificateStore> serverStore;
  std::shared_ptr<const X509Certificate> serverCertificate;
  std::string endpointUrl;
  std::uint16_t gdsNamespaceIndex{0};
  NodeId directoryId;
  std::array<NodeId, methodCount> methodIds;
  bool shutDown{false};

  mutable std::mutex mutex;
  std::shared_ptr<const X509Certificate> caCertificate;
  std::shared_ptr<const AsymmetricKeyPair> caKeys;
  std::shared_ptr<const X509Crl> caCrl;
  std::vector<std::string> revokedSerials;
  std::uint64_t nextSerial{1000};
  std::map<NodeId, GdsApplicationRecord> applications;
  std::map<NodeId, Request> requests;
  std::vector<GdsIssuedCertificate> issued;
  std::vector<Group> groups;
  std::vector<GdsApproval> approvals;
  std::map<std::tuple<NodeId, NodeId, NodeId>, bool> updateRequired;
  std::set<std::string> adminThumbprints;
  std::array<std::size_t, methodCount> callCounts{};
  std::array<std::vector<Variant>, methodCount> lastArguments;
  std::map<std::uint32_t, ByteString> channelCertificates;
  std::map<NodeId, std::uint32_t> sessionChannels;

  // ---- Lookups (mutex held) ----

  Group* find_group(const NodeId& groupId)
  {
    const NodeId& wanted = groupId.is_null() ? groups.front().id : groupId;
    for (auto& group : groups)
    {
      if (group.id == wanted)
      {
        return &group;
      }
    }
    return nullptr;
  }

  void bump(Group& group)
  {
    auto now = DateTime::now();
    if (now <= group.lastUpdateTime)
    {
      now.value() = group.lastUpdateTime.value() + datetime::OneHundredNanoSeconds{1};
    }
    group.lastUpdateTime = now;
  }

  std::string next_serial()
  {
    return std::to_string(nextSerial++);
  }

  // ---- Caller identity (Part 12 7.2: the SecureChannel certificate identifies the application) ----

  Caller resolve_caller(const std::shared_ptr<const MethodCallContext>& context)
  {
    Caller caller;
    if (!context)
    {
      return caller;
    }
    caller.mode = context->channelSecurityMode;
    ByteString der;
    {
      const std::lock_guard lock(mutex);
      const auto session = sessionChannels.find(context->sessionId);
      if (session != sessionChannels.end())
      {
        const auto channel = channelCertificates.find(session->second);
        if (channel != channelCertificates.end())
        {
          der = channel->second;
        }
      }
    }
    if (der.empty())
    {
      return caller;
    }
    try
    {
      caller.certificate = crypto->read_certificate_from_der(span<const byte>{der});
    }
    catch (...)
    {
      return caller;
    }
    const auto uris = caller.certificate->san_uris();
    if (!uris.empty())
    {
      caller.applicationUri = uris.front();
    }
    const std::lock_guard lock(mutex);
    caller.applicationAdmin = adminThumbprints.contains(ua::to_string(caller.certificate->thumbprint()));
    return caller;
  }

  static std::optional<CallResult> check_channel(const Caller& caller, ChannelRequirement requirement)
  {
    // Part 12 7.9.3/7.9.4/7.9.5 name an encrypted SecureChannel, 6.6.6/6.6.8/7.9.7/7.9.9/7.9.10 an
    // authenticated one; the Method tables name Bad_UserAccessDenied for a caller without the right.
    if (requirement == ChannelRequirement::Encrypted && caller.mode != MessageSecurityMode::SignAndEncrypt)
    {
      return bad(Status::BadUserAccessDenied,
        "GdsEncryptedChannelRequired",
        "this Method shall be called from an encrypted SecureChannel (Part 12 7.9)");
    }
    if (requirement == ChannelRequirement::Authenticated && caller.mode != MessageSecurityMode::Sign &&
        caller.mode != MessageSecurityMode::SignAndEncrypt)
    {
      return bad(Status::BadUserAccessDenied,
        "GdsAuthenticatedChannelRequired",
        "this Method shall be called from an authenticated SecureChannel (Part 12 6.6, 7.9)");
    }
    if (requirement != ChannelRequirement::Any && !caller.certificate)
    {
      return bad(Status::BadUserAccessDenied,
        "GdsCallerCertificateUnknown",
        "the SecureChannel certificate that identifies the application is not known");
    }
    return std::nullopt;
  }

  /// Bad_NotFound for an unknown application, Bad_UserAccessDenied unless the caller holds
  /// ApplicationSelfAdmin for it (its channel certificate carries the record's ApplicationUri) or
  /// ApplicationAdmin (Part 12 7.2 Table 20).
  std::optional<CallResult> authorize_application(
    const Caller& caller, const NodeId& applicationId, GdsApplicationRecord* record)
  {
    const std::lock_guard lock(mutex);
    const auto found = applications.find(applicationId);
    if (found == applications.end())
    {
      return bad(Status::BadNotFound,
        "GdsApplicationNotFound",
        "the applicationId does not refer to a registered Application");
    }
    if (!caller.applicationAdmin && caller.applicationUri != found->second.applicationUri)
    {
      return bad(Status::BadUserAccessDenied,
        "GdsApplicationSelfAdminDenied",
        "the SecureChannel certificate does not identify this Application (ApplicationSelfAdmin, Part 12 "
        "7.2)");
    }
    if (record)
    {
      *record = found->second;
    }
    return std::nullopt;
  }

  /// Resolves a (group, type) pair; Bad_InvalidArgument names which argument is not valid.
  std::optional<CallResult> resolve_group_and_type(NodeId& groupId, NodeId& typeId)
  {
    const std::lock_guard lock(mutex);
    auto* group = find_group(groupId);
    if (!group)
    {
      return bad(Status::BadInvalidArgument,
        "GdsCertificateGroupInvalid",
        "certificateGroupId does not name a CertificateGroup of this CertificateManager");
    }
    groupId = group->id;
    if (typeId.is_null())
    {
      typeId = group->certificateTypes.front();
      return std::nullopt;
    }
    if (std::find(group->certificateTypes.begin(), group->certificateTypes.end(), typeId) ==
        group->certificateTypes.end())
    {
      return bad(Status::BadInvalidArgument,
        "GdsCertificateTypeInvalid",
        "certificateTypeId is not in the CertificateTypes of the CertificateGroup");
    }
    return std::nullopt;
  }

  // ---- ApplicationRecordDataType body (Part 12 6.6.5 Table 7) ----

  Variant encode_record(const GdsApplicationRecord& record) const
  {
    memory_stream_device::Dynamic device(1024, /*reserve=*/true);
    MemoryStream<memory_stream_device::Dynamic> stream(device);
    UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
    const auto depth = EncodingLimits{}.stack_depth();
    encoder.encode(depth, record.applicationId);
    encoder.encode(depth, string_view{record.applicationUri});
    encoder.encode(depth, static_cast<std::int32_t>(record.applicationType));
    Array<LocalizedText> names;
    for (const auto& name : record.applicationNames)
    {
      names.push_back(name);
    }
    encoder.encode(depth, names);
    encoder.encode(depth, string_view{record.productUri});
    Array<String> discoveryUrls;
    for (const auto& url : record.discoveryUrls)
    {
      discoveryUrls.push_back(String{url});
    }
    encoder.encode(depth, discoveryUrls);
    Array<String> capabilities;
    for (const auto& capability : record.serverCapabilities)
    {
      capabilities.push_back(String{capability});
    }
    encoder.encode(depth, capabilities);
    return Variant{
      std::make_unique<ApplicationRecordStructure>(NodeId{gdsNamespaceIndex, applicationRecordDataTypeId},
        NodeId{gdsNamespaceIndex, applicationRecordBinaryEncodingId},
        ByteString{device.get_data()})};
  }

  Result<GdsApplicationRecord> decode_record(const Structure& structure) const
  {
    // The server registers no GDS types, so a request argument arrives verbatim (UnknownStructure). A client
    // that resolved the type from the server's DataTypeDefinition holds a typed structure instead: its body
    // is re-encoded and decoded the same way.
    ByteString body;
    if (const auto* opaque = dynamic_cast<const UnknownStructure*>(&structure))
    {
      if (opaque->body_encoding() != UnknownStructure::BodyEncoding::Binary ||
          opaque->encoding_id() != NodeId{gdsNamespaceIndex, applicationRecordBinaryEncodingId})
      {
        return {StatusCode{Status::BadInvalidArgument},
          make_error_detail("GdsApplicationRecordTypeInvalid",
            "the value is not a binary-encoded ApplicationRecordDataType",
            std::string{errorSource})};
      }
      body = opaque->encoded_data();
    }
    else if (const auto* record = dynamic_cast<const ApplicationRecordStructure*>(&structure))
    {
      body = record->body();
    }
    else
    {
      if (std::string{structure.type_name()}.find("ApplicationRecordDataType") == std::string::npos)
      {
        return {StatusCode{Status::BadInvalidArgument},
          make_error_detail("GdsApplicationRecordTypeInvalid",
            "the value is not an ApplicationRecordDataType",
            std::string{errorSource})};
      }
      memory_stream_device::Dynamic device(1024, /*reserve=*/true);
      MemoryStream<memory_stream_device::Dynamic> stream(device);
      UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
      encoder.encode(EncodingLimits{}.stack_depth(), structure);
      body = ByteString{device.get_data()};
    }
    try
    {
      memory_stream_device::ExternalReadOnly device{span<const byte>{body}};
      MemoryStream<memory_stream_device::ExternalReadOnly> stream{device};
      UaBinaryDecoder decoder{StructureResolver{}, stream, EncodingLimits{}};
      const auto depth = EncodingLimits{}.stack_depth();
      GdsApplicationRecord record;
      decoder.decode(depth, record.applicationId);
      decoder.decode(depth, record.applicationUri);
      std::int32_t type = 0;
      decoder.decode(depth, type);
      record.applicationType = static_cast<ApplicationType>(type);
      Array<LocalizedText> names;
      decoder.decode(depth, names);
      for (const auto& name : names.payload())
      {
        record.applicationNames.push_back(name);
      }
      decoder.decode(depth, record.productUri);
      Array<String> discoveryUrls;
      decoder.decode(depth, discoveryUrls);
      for (const auto& url : discoveryUrls.payload())
      {
        record.discoveryUrls.emplace_back(url);
      }
      Array<String> capabilities;
      decoder.decode(depth, capabilities);
      for (const auto& capability : capabilities.payload())
      {
        record.serverCapabilities.emplace_back(capability);
      }
      return {std::move(record)};
    }
    catch (...)
    {
      return {StatusCode{Status::BadInvalidArgument},
        make_error_detail("GdsApplicationRecordDecodeFailed",
          "the ApplicationRecordDataType body is invalid",
          std::string{errorSource})};
    }
  }

  // ---- TrustList publication (the group's CertificateStore backs the TrustListManager) ----

  void publish_group_async(NodeId groupId, std::function<void(VoidResult)> callback)
  {
    std::shared_ptr<CertificateStore> store;
    CertificateList trusted;
    CrlList trustedCrls;
    CertificateList issuers;
    CrlList issuerCrls;
    {
      const std::lock_guard lock(mutex);
      auto* group = find_group(groupId);
      if (!group)
      {
        callback(VoidResult{StatusCode{Status::BadInvalidArgument}});
        return;
      }
      store = group->store;
      trusted = group->trusted;
      trustedCrls = group->trustedCrls;
      issuers = group->issuers;
      issuerCrls = group->issuerCrls;
    }
    store->replace_trusted_certificates_async(std::move(trusted),
      std::move(trustedCrls),
      [store,
        issuers = std::move(issuers),
        issuerCrls = std::move(issuerCrls),
        callback = std::move(callback)](VoidResult trustedResult) mutable
      {
        if (trustedResult.is_bad())
        {
          callback(std::move(trustedResult));
          return;
        }
        store->replace_issuer_certificates_async(
          std::move(issuers), std::move(issuerCrls), std::move(callback));
      });
  }

  void publish_all_async(std::function<void(VoidResult)> callback)
  {
    std::vector<NodeId> groupIds;
    {
      const std::lock_guard lock(mutex);
      for (const auto& group : groups)
      {
        groupIds.push_back(group.id);
      }
    }
    auto self = shared_from_this();
    auto remaining = std::make_shared<std::atomic<std::size_t>>(groupIds.size());
    auto firstFailure = std::make_shared<std::optional<VoidResult>>();
    auto failureMutex = std::make_shared<std::mutex>();
    auto shared = std::make_shared<std::function<void(VoidResult)>>(std::move(callback));
    for (const auto& groupId : groupIds)
    {
      publish_group_async(groupId,
        [remaining, firstFailure, failureMutex, shared](VoidResult result)
        {
          if (result.is_bad())
          {
            const std::lock_guard lock(*failureMutex);
            if (!*firstFailure)
            {
              *firstFailure = std::move(result);
            }
          }
          if (remaining->fetch_sub(1) == 1)
          {
            (*shared)(*firstFailure ? **firstFailure : VoidResult{});
          }
        });
    }
  }

  /// Adds @p serials to the CA CRL, republishes it wherever the old CRL was, removes @p certificates from
  /// every TrustList and bumps the LastUpdateTime of every changed group.
  void revoke_async(std::vector<std::shared_ptr<const X509Certificate>> certificates,
    std::function<void(VoidResult)> callback)
  {
    std::vector<std::string> serials;
    {
      const std::lock_guard lock(mutex);
      for (const auto& certificate : certificates)
      {
        revokedSerials.push_back(certificate->serial_number());
      }
      serials = revokedSerials;
    }
    auto self = shared_from_this();
    crypto->create_crl_async(caCertificate,
      caKeys,
      std::move(serials),
      [self, certificates = std::move(certificates), callback = std::move(callback)](CrlResult crl) mutable
      {
        if (crl.is_bad())
        {
          callback(VoidResult{crl.status_code(), crl.shared_detail()});
          return;
        }
        {
          const std::lock_guard lock(self->mutex);
          const auto oldCrl = self->caCrl;
          self->caCrl = crl.value();
          for (auto& group : self->groups)
          {
            for (auto* list : {&group.trustedCrls, &group.issuerCrls})
            {
              for (auto& entry : *list)
              {
                if (oldCrl && entry && *entry == *oldCrl)
                {
                  entry = crl.value();
                }
              }
            }
            for (auto* list : {&group.trusted, &group.issuers})
            {
              std::erase_if(*list,
                [&certificates](const auto& held)
                {
                  return std::any_of(certificates.begin(),
                    certificates.end(),
                    [&held](const auto& revoked) { return held->der_encoding() == revoked->der_encoding(); });
                });
            }
            self->bump(group);
          }
        }
        self->publish_all_async(std::move(callback));
      });
  }

  // ---- Oracle recording ----

  void record_call(GdsMethod method, const CallMethodRequest& request)
  {
    const std::lock_guard lock(mutex);
    ++callCounts[index_of(method)];
    lastArguments[index_of(method)].assign(
      request.input_arguments().begin(), request.input_arguments().end());
  }

  // ---- Directory Methods (Part 12 6.6) ----

  void find_applications(const CallMethodRequest& request, std::shared_ptr<const MethodCallContext>,
    std::function<void(CallResult)> callback)
  {
    // Part 12 6.6.4: zero or one record for the ApplicationUri.
    const auto uri = string_argument(request, 0);
    if (!uri)
    {
      callback(bad(Status::BadInvalidArgument, "GdsApplicationUriInvalid", "applicationUri is not a String"));
      return;
    }
    Array<RefStructure<Structure>> records;
    {
      const std::lock_guard lock(mutex);
      for (const auto& [id, record] : applications)
      {
        if (record.applicationUri == *uri)
        {
          RefStructure<Structure> entry;
          entry = encode_record(record).as<Structure>().clone();
          records.push_back(std::move(entry));
        }
      }
    }
    callback(good({Variant{std::move(records)}}));
  }

  void register_application(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Authenticated))
    {
      callback(std::move(*refused));
      return;
    }
    const auto& arguments = request.input_arguments();
    if (arguments.empty() || !arguments[0].is_structure())
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsApplicationRecordMissing", "application is not a Structure"));
      return;
    }
    auto decoded = decode_record(arguments[0].as<Structure>());
    if (decoded.is_bad())
    {
      callback(CallResult{decoded.status_code(), decoded.shared_detail()});
      return;
    }
    auto record = std::move(decoded).value();
    if (record.applicationUri.empty())
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsApplicationUriEmpty", "applicationUri shall not be empty"));
      return;
    }
    if (record.applicationNames.empty())
    {
      callback(bad(
        Status::BadInvalidArgument, "GdsApplicationNamesEmpty", "applicationNames needs one or more names"));
      return;
    }
    if (!is_valid(record.applicationType))
    {
      callback(bad(Status::BadInvalidArgument, "GdsApplicationTypeInvalid", "applicationType is not valid"));
      return;
    }
    // Part 12 6.6.6 names the DiscoveryAdmin Role or the ApplicationAdmin Privilege. The emulator also
    // accepts an application registering its own ApplicationUri (6.5 Table 3 lets a GDS provide its own
    // acceptance mechanism).
    if (!caller.applicationAdmin && caller.applicationUri != record.applicationUri)
    {
      callback(bad(Status::BadUserAccessDenied,
        "GdsRegistrationDenied",
        "the caller is neither an ApplicationAdmin nor the application being registered"));
      return;
    }
    NodeId applicationId;
    {
      const std::lock_guard lock(mutex);
      // 6.6.6: RegisterApplication shall not create duplicate records if the ApplicationUri already exists.
      for (const auto& [id, existing] : applications)
      {
        if (existing.applicationUri == record.applicationUri)
        {
          applicationId = id;
        }
      }
      if (applicationId.is_null())
      {
        applicationId = NodeId{gdsNamespaceIndex, "app:" + Guid::create_and_generate().as_string()};
        record.applicationId = applicationId;
        applications.emplace(applicationId, std::move(record));
      }
    }
    callback(good({Variant{applicationId}}));
  }

  void unregister_application(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Authenticated))
    {
      callback(std::move(*refused));
      return;
    }
    const auto applicationId = node_id_argument(request, 0);
    if (!applicationId)
    {
      callback(bad(Status::BadInvalidArgument, "GdsApplicationIdInvalid", "applicationId is not a NodeId"));
      return;
    }
    if (auto refused = authorize_application(caller, *applicationId, nullptr))
    {
      callback(std::move(*refused));
      return;
    }
    std::vector<std::shared_ptr<const X509Certificate>> toRevoke;
    {
      const std::lock_guard lock(mutex);
      applications.erase(*applicationId);
      std::erase_if(
        requests, [&](const auto& entry) { return entry.second.applicationId == *applicationId; });
      for (const auto& certificate : issued)
      {
        if (certificate.applicationId == *applicationId)
        {
          toRevoke.push_back(certificate.certificate);
        }
      }
    }
    if (toRevoke.empty())
    {
      callback(good({}));
      return;
    }
    // 6.6.8: certificates issued to an unregistered application shall be revoked.
    revoke_async(std::move(toRevoke),
      [callback = std::move(callback)](VoidResult revoked)
      {
        if (revoked.is_bad())
        {
          callback(CallResult{revoked.status_code(), revoked.shared_detail()});
          return;
        }
        callback(good({}));
      });
  }

  void get_application(const CallMethodRequest& request, std::shared_ptr<const MethodCallContext> context,
    std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    const auto applicationId = node_id_argument(request, 0);
    if (!applicationId)
    {
      callback(bad(Status::BadInvalidArgument, "GdsApplicationIdInvalid", "applicationId is not a NodeId"));
      return;
    }
    GdsApplicationRecord record;
    if (auto refused = authorize_application(caller, *applicationId, &record))
    {
      callback(std::move(*refused));
      return;
    }
    callback(good({encode_record(record)}));
  }

  // ---- CertificateManager Methods (Part 12 7.9) ----

  /// Queues an accepted request and returns its requestId; the next approval policy applies.
  NodeId accept_request(Request request)
  {
    const std::lock_guard lock(mutex);
    GdsApproval approval;
    if (!approvals.empty())
    {
      approval = approvals.front();
      approvals.erase(approvals.begin());
    }
    request.requestId = NodeId{gdsNamespaceIndex, "request:" + Guid::create_and_generate().as_string()};
    request.approval = approval;
    request.pollsRemaining = approval.kind == GdsApproval::Kind::Pending ? approval.pendingPolls : 0;
    auto requestId = request.requestId;
    requests.emplace(requestId, std::move(request));
    return requestId;
  }

  void start_signing_request(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Encrypted))
    {
      callback(std::move(*refused));
      return;
    }
    auto applicationId = node_id_argument(request, 0);
    auto groupId = node_id_argument(request, 1);
    auto typeId = node_id_argument(request, 2);
    const auto csr = byte_string_argument(request, 3);
    if (!applicationId || !groupId || !typeId || !csr)
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsArgumentTypeInvalid", "an input argument has the wrong type"));
      return;
    }
    GdsApplicationRecord record;
    if (auto refused = authorize_application(caller, *applicationId, &record))
    {
      callback(std::move(*refused));
      return;
    }
    if (auto refused = resolve_group_and_type(*groupId, *typeId))
    {
      callback(std::move(*refused));
      return;
    }
    if (csr->empty())
    {
      callback(bad(Status::BadInvalidArgument, "GdsCertificateRequestEmpty", "certificateRequest is empty"));
      return;
    }
    const auto alternateName = read_request_subject_alt_name(*csr);
    if (!alternateName)
    {
      callback(bad(Status::BadInvalidArgument,
        "GdsCertificateRequestInvalid",
        "certificateRequest is not a DER PKCS #10 request"));
      return;
    }
    // 7.9.3: the ApplicationUri shall be in the CSR and match the Application record.
    if (alternateName->uris.empty() ||
        std::find(alternateName->uris.begin(), alternateName->uris.end(), record.applicationUri) ==
          alternateName->uris.end())
    {
      callback(bad(Status::BadCertificateUriInvalid,
        "GdsCertificateRequestUriMismatch",
        "the CSR does not carry the ApplicationUri of the Application record"));
      return;
    }
    Crypto::SignCsrConfig parameters;
    parameters.csrDer = *csr;
    {
      const std::lock_guard lock(mutex);
      parameters.issuer = caCertificate;
      parameters.issuerKeys = caKeys;
    }
    parameters.signatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
    parameters.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
    parameters.subjectAlternateName = *alternateName;  // 7.9.3: subjectAltName copied from the CSR

    Request pending;
    pending.applicationId = *applicationId;
    pending.groupId = *groupId;
    pending.typeId = *typeId;
    pending.callerThumbprint = caller.certificate->thumbprint();
    std::weak_ptr<State> weakSelf = shared_from_this();
    crypto->sign_certificate_request_async(parameters,
      [weakSelf, pending = std::move(pending), callback = std::move(callback)](
        CertificateResult signedResult) mutable
      {
        const auto self = weakSelf.lock();
        if (!self)
        {
          callback(bad(Status::BadShutdown, "GdsEmulatorGone", "the emulator was destroyed"));
          return;
        }
        if (signedResult.is_bad())
        {
          // A CSR whose self-signature does not verify does not prove possession of the key (7.9.3).
          callback(CallResult{StatusCode{Status::BadInvalidArgument},
            ErrorDetail::build("GdsCertificateRequestRejected",
              "certificateRequest could not be signed (proof of possession failed)",
              std::string{errorSource})
              .cause(signedResult.status_code())});
          return;
        }
        pending.certificate = signedResult.value();
        callback(good({Variant{self->accept_request(std::move(pending))}}));
      });
  }

  void start_new_key_pair_request(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Encrypted))
    {
      callback(std::move(*refused));
      return;
    }
    auto applicationId = node_id_argument(request, 0);
    auto groupId = node_id_argument(request, 1);
    auto typeId = node_id_argument(request, 2);
    const auto subjectName = string_argument(request, 3);
    const auto domainNames = string_array_argument(request, 4);
    const auto privateKeyFormat = string_argument(request, 5);
    const auto privateKeyPassword = string_argument(request, 6);
    if (!applicationId || !groupId || !typeId || !subjectName || !domainNames || !privateKeyFormat ||
        !privateKeyPassword)
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsArgumentTypeInvalid", "an input argument has the wrong type"));
      return;
    }
    GdsApplicationRecord record;
    if (auto refused = authorize_application(caller, *applicationId, &record))
    {
      callback(std::move(*refused));
      return;
    }
    if (auto refused = resolve_group_and_type(*groupId, *typeId))
    {
      callback(std::move(*refused));
      return;
    }
    const auto format = lowercase(*privateKeyFormat);
    if (format == "pfx")
    {
      // 7.9.4 requires PEM and PFX; the Crypto interface has no PKCS #12 export, so the emulator cannot.
      callback(bad(Status::BadNotSupported,
        "GdsPfxNotSupported",
        "the emulator cannot produce PKCS #12: the Crypto interface exports PEM only"));
      return;
    }
    if (format != "pem")
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsPrivateKeyFormatInvalid", "privateKeyFormat is not PEM or PFX"));
      return;
    }
    Crypto::Name subject;
    if (!subjectName->empty())
    {
      auto parsed = parse_subject_name(*subjectName);
      if (!parsed)
      {
        callback(
          bad(Status::BadInvalidArgument, "GdsSubjectNameInvalid", "subjectName is not valid (7.9.4)"));
        return;
      }
      subject = std::move(*parsed);
    }
    if (subject.commonName.empty())
    {
      subject.commonName = record.applicationNames.empty()
                             ? record.applicationUri
                             : std::string{record.applicationNames.front().text()};
    }
    if (subject.organization.empty())
    {
      subject.organization = "GDS Emulator";  // 7.9.4: an ApplicationCertificateType subject needs O= or DC=
    }
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back(record.applicationUri);
    std::vector<std::string> domains = *domainNames;
    if (domains.empty() && record.applicationType != ApplicationType::Client)
    {
      // 7.9.4: when domainNames is empty the DiscoveryUrls of a Server are used; for a Client they are
      // omitted.
      for (const auto& url : record.discoveryUrls)
      {
        if (auto host = host_of(url); !host.empty())
        {
          domains.push_back(std::move(host));
        }
      }
    }
    for (const auto& domain : domains)
    {
      boost::system::error_code error;
      const auto address = boost::asio::ip::make_address(domain, error);
      if (error)
        alternateName.hostnames.push_back(domain);
      else
        alternateName.ipAddresses.push_back(address);
    }
    const auto keyAlgorithm = *typeId == NodeId{ObjectTypeId::EccNistP256ApplicationCertificateType}
                                ? CertificateKeyAlgorithm::EccNistP256
                                : CertificateKeyAlgorithm::Rsa;

    Request pending;
    pending.applicationId = *applicationId;
    pending.groupId = *groupId;
    pending.typeId = *typeId;
    pending.callerThumbprint = caller.certificate->thumbprint();
    pending.newKeyPair = true;
    // 7.9.5: "If a password was supplied the blob is protected with it." With a password, the key is
    // generated by a Crypto whose credential is that password (the SDK Crypto writes every PEM key encrypted
    // with its credential). Without one the key is returned unprotected, as a GDS returns it: the SDK Crypto
    // cannot export an unprotected PEM, so the emulator writes one with OpenSSL and loads it to sign the
    // certificate.
    std::optional<ByteString> unprotectedPem;
    if (privateKeyPassword->empty())
    {
      auto generated = generate_unprotected_pem(keyAlgorithm);
      if (generated.is_bad())
      {
        callback(CallResult{generated.status_code(), generated.shared_detail()});
        return;
      }
      unprotectedPem = std::move(generated).value();
    }
    auto keyCrypto = crypto;
    if (!privateKeyPassword->empty())
    {
      keyCrypto = create_default_crypto(
        [password = *privateKeyPassword] { return ua::SecureString{password.data(), password.size()}; });
    }
    std::weak_ptr<State> weakSelf = shared_from_this();
    auto onKeys = [weakSelf,
                    unprotectedPem,
                    subject = std::move(subject),
                    alternateName = std::move(alternateName),
                    pending = std::move(pending),
                    callback = std::move(callback)](KeyPairResult keys) mutable
    {
      const auto self = weakSelf.lock();
      if (!self)
      {
        callback(bad(Status::BadShutdown, "GdsEmulatorGone", "the emulator was destroyed"));
        return;
      }
      if (keys.is_bad())
      {
        callback(CallResult{keys.status_code(), keys.shared_detail()});
        return;
      }
      Crypto::CreateCertificateConfig parameters;
      {
        const std::lock_guard lock(self->mutex);
        parameters.serialNumber = self->next_serial();
        parameters.issuer = self->caCertificate;
        parameters.issuerKeys = self->caKeys;
      }
      parameters.subject = std::move(subject);
      parameters.subjectKeys = keys.value();
      parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
      parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
      parameters.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
      parameters.keyUsage.digitalSignature = true;
      parameters.keyUsage.nonRepudiation = true;
      parameters.keyUsage.keyEncipherment = true;
      parameters.keyUsage.dataEncipherment = true;
      parameters.keyUsage.clientAuth = true;
      parameters.keyUsage.serverAuth = true;
      parameters.basicConstraint.cA = false;
      parameters.subjectAlternateName = std::move(alternateName);
      auto subjectKeys = keys.value();
      self->crypto->create_certificate_async(parameters,
        [weakSelf, subjectKeys, unprotectedPem, pending = std::move(pending), callback = std::move(callback)](
          CertificateResult certificate) mutable
        {
          const auto self = weakSelf.lock();
          if (!self)
          {
            callback(bad(Status::BadShutdown, "GdsEmulatorGone", "the emulator was destroyed"));
            return;
          }
          if (certificate.is_bad())
          {
            callback(CallResult{certificate.status_code(), certificate.shared_detail()});
            return;
          }
          try
          {
            pending.privateKey = unprotectedPem ? *unprotectedPem : subjectKeys->private_key_pem();
          }
          catch (...)
          {
            callback(bad(
              Status::BadInternalError, "GdsPrivateKeyExportFailed", "the new key could not be exported"));
            return;
          }
          pending.certificate = certificate.value();
          callback(good({Variant{self->accept_request(std::move(pending))}}));
        });
    };
    if (unprotectedPem)
    {
      KeyPairResult loaded{StatusCode{Status::BadInternalError}};
      try
      {
        std::vector<byte> copy(unprotectedPem->size());
        std::memcpy(copy.data(), unprotectedPem->data(), copy.size());
        loaded = KeyPairResult{crypto->get_private_key_from_pem(keyAlgorithm, span<byte>{copy})};
      }
      catch (const UaException& exception)
      {
        loaded = KeyPairResult{exception.status_code()};
      }
      catch (...)
      {
        loaded = KeyPairResult{StatusCode{Status::BadInternalError}};
      }
      onKeys(std::move(loaded));
      return;
    }
    keyCrypto->create_asymmetric_key_pair_async(keyAlgorithm,
      keyAlgorithm == CertificateKeyAlgorithm::Rsa ? std::optional<std::size_t>{2048} : std::nullopt,
      std::move(onKeys));
  }

  void finish_request(const CallMethodRequest& request, std::shared_ptr<const MethodCallContext> context,
    std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Encrypted))
    {
      callback(std::move(*refused));
      return;
    }
    const auto applicationId = node_id_argument(request, 0);
    const auto requestId = node_id_argument(request, 1);
    if (!applicationId || !requestId)
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsArgumentTypeInvalid", "an input argument has the wrong type"));
      return;
    }
    if (auto refused = authorize_application(caller, *applicationId, nullptr))
    {
      callback(std::move(*refused));
      return;
    }
    std::vector<Variant> outputs;
    {
      const std::lock_guard lock(mutex);
      const auto found = requests.find(*requestId);
      if (found == requests.end() || found->second.applicationId != *applicationId)
      {
        callback(bad(Status::BadInvalidArgument,
          "GdsRequestIdInvalid",
          "requestId does not reference a valid request for the Application (7.9.5)"));
        return;
      }
      auto& pending = found->second;
      // 7.9.5: the Client Certificate shall be the same as the one used to start the request.
      if (pending.callerThumbprint != caller.certificate->thumbprint())
      {
        callback(bad(Status::BadUserAccessDenied,
          "GdsRequestCallerCertificateMismatch",
          "FinishRequest was not called with the certificate that started the request (7.9.5)"));
        return;
      }
      if (pending.approval.kind == GdsApproval::Kind::Reject)
      {
        callback(CallResult{pending.approval.rejection,
          make_error_detail(
            "GdsRequestRejected", "the CertificateManager rejected the request", std::string{errorSource})});
        return;
      }
      if (pending.pollsRemaining > 0)
      {
        --pending.pollsRemaining;
        callback(bad(Status::BadNothingToDo, "GdsRequestPending", "the request has not yet been approved"));
        return;
      }
      if (!pending.delivered)
      {
        pending.delivered = true;
        issued.push_back(GdsIssuedCertificate{pending.applicationId,
          pending.requestId,
          pending.groupId,
          pending.typeId,
          pending.certificate,
          pending.newKeyPair});
        updateRequired[{pending.applicationId, pending.groupId, pending.typeId}] = false;
      }
      Array<ByteString> issuers;
      issuers.push_back(caCertificate->der_encoding());
      outputs.emplace_back(pending.certificate->der_encoding());
      outputs.emplace_back(pending.newKeyPair ? pending.privateKey : ByteString{});
      outputs.emplace_back(std::move(issuers));
    }
    callback(good(std::move(outputs)));
  }

  void get_certificate_groups(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Authenticated))
    {
      callback(std::move(*refused));
      return;
    }
    const auto applicationId = node_id_argument(request, 0);
    if (!applicationId)
    {
      callback(bad(Status::BadInvalidArgument, "GdsApplicationIdInvalid", "applicationId is not a NodeId"));
      return;
    }
    if (auto refused = authorize_application(caller, *applicationId, nullptr))
    {
      callback(std::move(*refused));
      return;
    }
    Array<NodeId> groupIds;
    {
      const std::lock_guard lock(mutex);
      for (const auto& group : groups)
      {
        groupIds.push_back(group.id);
      }
    }
    callback(good({Variant{std::move(groupIds)}}));
  }

  void get_trust_list(const CallMethodRequest& request, std::shared_ptr<const MethodCallContext> context,
    std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Authenticated))
    {
      callback(std::move(*refused));
      return;
    }
    const auto applicationId = node_id_argument(request, 0);
    const auto groupId = node_id_argument(request, 1);
    if (!applicationId || !groupId)
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsArgumentTypeInvalid", "an input argument has the wrong type"));
      return;
    }
    if (auto refused = authorize_application(caller, *applicationId, nullptr))
    {
      callback(std::move(*refused));
      return;
    }
    NodeId trustListId;
    {
      const std::lock_guard lock(mutex);
      auto* group = find_group(*groupId);  // 7.9.9: null selects a suitable default group
      if (!group)
      {
        callback(bad(Status::BadInvalidArgument,
          "GdsCertificateGroupInvalid",
          "certificateGroupId does not name a CertificateGroup of this CertificateManager"));
        return;
      }
      trustListId = group->trustListId;
    }
    callback(good({Variant{trustListId}}));
  }

  void get_certificate_status(const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    const auto caller = resolve_caller(context);
    if (auto refused = check_channel(caller, ChannelRequirement::Authenticated))
    {
      callback(std::move(*refused));
      return;
    }
    auto applicationId = node_id_argument(request, 0);
    auto groupId = node_id_argument(request, 1);
    auto typeId = node_id_argument(request, 2);
    if (!applicationId || !groupId || !typeId)
    {
      callback(
        bad(Status::BadInvalidArgument, "GdsArgumentTypeInvalid", "an input argument has the wrong type"));
      return;
    }
    if (auto refused = authorize_application(caller, *applicationId, nullptr))
    {
      callback(std::move(*refused));
      return;
    }
    if (auto refused = resolve_group_and_type(*groupId, *typeId))
    {
      callback(std::move(*refused));
      return;
    }
    bool required = false;
    {
      const std::lock_guard lock(mutex);
      const auto found = updateRequired.find({*applicationId, *groupId, *typeId});
      if (found != updateRequired.end())
      {
        required = found->second;
      }
      else
      {
        // Nothing set for this combination: an application holding no certificate this GDS issued for it
        // needs one (7.9.10 "TRUE if the Application needs to request a new Certificate").
        required = std::none_of(issued.begin(),
          issued.end(),
          [&](const GdsIssuedCertificate& certificate)
          {
            return certificate.applicationId == *applicationId &&
                   certificate.certificateGroupId == *groupId && certificate.certificateTypeId == *typeId;
          });
      }
    }
    callback(good({Variant{required}}));
  }

  void dispatch(GdsMethod method, const CallMethodRequest& request,
    std::shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)
  {
    record_call(method, request);
    switch (method)
    {
    case GdsMethod::FindApplications:
      return find_applications(request, std::move(context), std::move(callback));
    case GdsMethod::RegisterApplication:
      return register_application(request, std::move(context), std::move(callback));
    case GdsMethod::UnregisterApplication:
      return unregister_application(request, std::move(context), std::move(callback));
    case GdsMethod::GetApplication:
      return get_application(request, std::move(context), std::move(callback));
    case GdsMethod::StartSigningRequest:
      return start_signing_request(request, std::move(context), std::move(callback));
    case GdsMethod::StartNewKeyPairRequest:
      return start_new_key_pair_request(request, std::move(context), std::move(callback));
    case GdsMethod::FinishRequest:
      return finish_request(request, std::move(context), std::move(callback));
    case GdsMethod::GetCertificateGroups:
      return get_certificate_groups(request, std::move(context), std::move(callback));
    case GdsMethod::GetTrustList:
      return get_trust_list(request, std::move(context), std::move(callback));
    case GdsMethod::GetCertificateStatus:
      return get_certificate_status(request, std::move(context), std::move(callback));
    }
  }
};

namespace
{

using State = GdsEmulator::State;

/// Tracks which SecureChannel certificate each Session uses (Part 12 7.2: the certificate used to create
/// the SecureChannel identifies the application). The server raises these events synchronously, before the
/// response that lets the client send its next request.
class CallerIdentityObserver final : public ServerObserver
{
public:
  explicit CallerIdentityObserver(std::weak_ptr<State> state) : mState(std::move(state))
  {}

  void on_secure_channel_opened(const SecureChannelEventInfo& info) override
  {
    remember_channel(info);
  }

  void on_secure_channel_renewed(const SecureChannelEventInfo& info) override
  {
    remember_channel(info);
  }

  void on_secure_channel_closed(const SecureChannelEventInfo& info, StatusCode) override
  {
    if (auto state = mState.lock())
    {
      const std::lock_guard lock(state->mutex);
      state->channelCertificates.erase(info.secureChannelId);
    }
  }

  void on_session_created(const SessionEventInfo& info) override
  {
    remember_session(info);
  }

  void on_session_activated(const SessionEventInfo& info) override
  {
    remember_session(info);
  }

  void on_session_closed(const SessionEventInfo& info, StatusCode) override
  {
    forget_session(info);
  }

  void on_session_timed_out(const SessionEventInfo& info) override
  {
    forget_session(info);
  }

private:
  void remember_channel(const SecureChannelEventInfo& info)
  {
    if (auto state = mState.lock())
    {
      const std::lock_guard lock(state->mutex);
      state->channelCertificates[info.secureChannelId] = info.clientCertificate;
    }
  }

  void remember_session(const SessionEventInfo& info)
  {
    if (auto state = mState.lock())
    {
      const std::lock_guard lock(state->mutex);
      state->sessionChannels[info.sessionId] = info.secureChannelId;
    }
  }

  void forget_session(const SessionEventInfo& info)
  {
    std::vector<std::shared_ptr<TrustListManager>> trustLists;
    if (auto state = mState.lock())
    {
      const std::lock_guard lock(state->mutex);
      state->sessionChannels.erase(info.sessionId);
      for (const auto& group : state->groups)
      {
        trustLists.push_back(group.trustList);
      }
    }
    for (const auto& trustList : trustLists)
    {
      if (trustList)
      {
        trustList->on_session_closed_async(info.sessionId);  // releases a handle the Session left open
      }
    }
  }

  std::weak_ptr<State> mState;
};

Result<NodeId> find_forward_child(AddressSpace& addressSpace, const NodeId& parent, const QualifiedName& name)
{
  auto parentNode = addressSpace.try_find_node_sync(parent);
  if (parentNode.is_bad())
  {
    return {parentNode.status_code(), parentNode.shared_detail()};
  }
  auto references = parentNode.value().try_get_references_sync();
  if (references.is_bad())
  {
    return {references.status_code(), references.shared_detail()};
  }
  for (const auto& reference : references.value())
  {
    if (!reference.is_forward() || reference.is_remote())
    {
      continue;
    }
    const auto& target = reference.target_id().node_id();
    auto targetNode = addressSpace.try_find_node_sync(target);
    if (targetNode.is_good() && targetNode.value().get_browse_name() == name)
    {
      return {target};
    }
  }
  return {StatusCode{Status::BadNotFound},
    make_error_detail("GdsNodeSetNodeMissing",
      "the GDS NodeSet does not provide the node '" + std::string{name.name()} + "'",
      std::string{errorSource})};
}

/// The handlers for the TrustList FileType Methods, bound to the SDK TrustListManager of a group. The
/// emulator's TrustList is read-only for applications (Part 12 7.8.2.1): write modes are refused.
VoidResult wire_trust_list(
  AddressSpace& addressSpace, const NodeId& trustListId, std::weak_ptr<TrustListManager> manager)
{
  using Handler = std::function<void(
    const CallMethodRequest&, std::shared_ptr<const MethodCallContext>, std::function<void(CallResult)>)>;
  auto require = [](const std::shared_ptr<const MethodCallContext>& context) -> std::optional<CallResult>
  {
    if (!context || (context->channelSecurityMode != MessageSecurityMode::Sign &&
                      context->channelSecurityMode != MessageSecurityMode::SignAndEncrypt))
    {
      return bad(Status::BadUserAccessDenied,
        "GdsTrustListAuthenticatedChannelRequired",
        "the TrustList is readable over an authenticated SecureChannel only");
    }
    return std::nullopt;
  };
  auto locked = [manager](std::function<void(CallResult)>& callback) -> std::shared_ptr<TrustListManager>
  {
    auto held = manager.lock();
    if (!held)
    {
      callback(bad(Status::BadShutdown, "GdsTrustListGone", "the TrustList service has stopped"));
    }
    return held;
  };
  auto uint32Argument = [](
                          const CallMethodRequest& request, std::size_t index) -> std::optional<std::uint32_t>
  {
    const auto& arguments = request.input_arguments();
    if (index < arguments.size())
    {
      if (const auto* value = arguments[index].try_as<std::uint32_t>())
      {
        return *value;
      }
    }
    return std::nullopt;
  };

  std::vector<std::pair<std::string_view, Handler>> handlers;
  handlers.emplace_back("Open",
    [require, locked](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto& arguments = request.input_arguments();
      const auto* mode = arguments.empty() ? nullptr : arguments[0].try_as<std::uint8_t>();
      if (!mode)
        return callback(bad(Status::BadInvalidArgument, "GdsTrustListModeInvalid", "mode is not a Byte"));
      if (*mode != 0x01)
        return callback(
          bad(Status::BadNotWritable, "GdsTrustListReadOnly", "the TrustList opens for reading only"));
      auto held = locked(callback);
      if (!held)
        return;
      held->open_async(context->sessionId,
        *mode,
        [callback = std::move(callback)](Result<std::uint32_t> handle) mutable
        {
          if (handle.is_bad())
            return callback(CallResult{handle.status_code(), handle.shared_detail()});
          callback(good({Variant{handle.value()}}));
        });
    });
  handlers.emplace_back("OpenWithMasks",
    [require, locked, uint32Argument](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto masks = uint32Argument(request, 0);
      if (!masks)
        return callback(bad(Status::BadInvalidArgument, "GdsTrustListMasksInvalid", "masks is not a UInt32"));
      auto held = locked(callback);
      if (!held)
        return;
      held->open_with_masks_async(context->sessionId,
        *masks,
        [callback = std::move(callback)](Result<std::uint32_t> handle) mutable
        {
          if (handle.is_bad())
            return callback(CallResult{handle.status_code(), handle.shared_detail()});
          callback(good({Variant{handle.value()}}));
        });
    });
  handlers.emplace_back("Read",
    [require, locked, uint32Argument](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto handle = uint32Argument(request, 0);
      const auto& arguments = request.input_arguments();
      const auto* length = arguments.size() > 1 ? arguments[1].try_as<std::int32_t>() : nullptr;
      if (!handle || !length)
        return callback(bad(Status::BadInvalidArgument, "GdsTrustListReadInvalid", "Read arguments invalid"));
      auto held = locked(callback);
      if (!held)
        return;
      held->read_async(context->sessionId,
        *handle,
        *length,
        [callback = std::move(callback)](Result<ByteString> data) mutable
        {
          if (data.is_bad())
            return callback(CallResult{data.status_code(), data.shared_detail()});
          callback(good({Variant{std::move(data).value()}}));
        });
    });
  handlers.emplace_back("Close",
    [require, locked, uint32Argument](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto handle = uint32Argument(request, 0);
      if (!handle)
        return callback(bad(Status::BadInvalidArgument, "GdsTrustListHandleInvalid", "fileHandle invalid"));
      auto held = locked(callback);
      if (!held)
        return;
      held->close_async(context->sessionId,
        *handle,
        [callback = std::move(callback)](VoidResult closed) mutable
        {
          if (closed.is_bad())
            return callback(CallResult{closed.status_code(), closed.shared_detail()});
          callback(good({}));
        });
    });
  handlers.emplace_back("GetPosition",
    [require, locked, uint32Argument](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto handle = uint32Argument(request, 0);
      if (!handle)
        return callback(bad(Status::BadInvalidArgument, "GdsTrustListHandleInvalid", "fileHandle invalid"));
      auto held = locked(callback);
      if (!held)
        return;
      held->get_position_async(context->sessionId,
        *handle,
        [callback = std::move(callback)](Result<std::uint64_t> position) mutable
        {
          if (position.is_bad())
            return callback(CallResult{position.status_code(), position.shared_detail()});
          callback(good({Variant{position.value()}}));
        });
    });
  handlers.emplace_back("SetPosition",
    [require, locked, uint32Argument](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>
        context,
      std::function<void(CallResult)>
        callback)
    {
      if (auto refused = require(context))
        return callback(std::move(*refused));
      const auto handle = uint32Argument(request, 0);
      const auto& arguments = request.input_arguments();
      const auto* position = arguments.size() > 1 ? arguments[1].try_as<std::uint64_t>() : nullptr;
      if (!handle || !position)
        return callback(
          bad(Status::BadInvalidArgument, "GdsTrustListSetPositionInvalid", "arguments invalid"));
      auto held = locked(callback);
      if (!held)
        return;
      held->set_position_async(context->sessionId,
        *handle,
        *position,
        [callback = std::move(callback)](VoidResult moved) mutable
        {
          if (moved.is_bad())
            return callback(CallResult{moved.status_code(), moved.shared_detail()});
          callback(good({}));
        });
    });

  const auto grants = call_grants();
  for (auto& [name, handler] : handlers)
  {
    auto methodId = find_forward_child(addressSpace, trustListId, QualifiedName{0, name});
    if (methodId.is_bad())
    {
      return VoidResult{methodId.status_code(), methodId.shared_detail()};
    }
    auto node = addressSpace.find_node_sync(methodId.value());
    node.set_role_permissions(grants);
    auto* source = node->method_call_source();
    if (!source)
    {
      return VoidResult{StatusCode{Status::BadNotSupported},
        make_error_detail("GdsTrustListMethodNotCallable",
          "a TrustList Method has no call source",
          std::string{errorSource})};
    }
    source->set_call_handler(std::move(handler));
  }
  return VoidResult{};
}

Result<std::shared_ptr<const X509Certificate>> create_ca(const Crypto& crypto,
  const std::shared_ptr<const AsymmetricKeyPair>& keys, const std::string& commonName,
  const std::string& serial)
{
  Crypto::CreateCertificateConfig parameters;
  parameters.serialNumber = serial;
  parameters.subject.commonName = commonName;
  parameters.subject.organization = "GDS Emulator";
  parameters.subjectKeys = keys;
  parameters.issuerKeys = keys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  parameters.to = DateTime{DateTime::now().value() + std::chrono::days{3650}};
  parameters.basicConstraint.cA = true;
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.keyCertSign = true;
  parameters.keyUsage.crlSign = true;
  return wait_for<std::shared_ptr<const X509Certificate>>(
    [&crypto, parameters](auto done) { crypto.create_certificate_async(parameters, std::move(done)); });
}

}  // namespace

// ---------------------------------------------------------------------------------------------------------
// GdsEmulator
// ---------------------------------------------------------------------------------------------------------

Result<std::shared_ptr<GdsEmulator>> GdsEmulator::create(GdsEmulatorOptions options)
{
  auto fail = [](std::string code, std::string text) -> Result<std::shared_ptr<GdsEmulator>>
  {
    return {StatusCode{Status::BadConfigurationError},
      make_error_detail(std::move(code), std::move(text), std::string{errorSource})};
  };

  if (!std::filesystem::exists(options.nodeSetPath))
  {
    return fail("GdsNodeSetMissing", "the GDS NodeSet file is missing: " + options.nodeSetPath.string());
  }
  std::filesystem::create_directories(options.workDirectory);

  auto emulator = std::shared_ptr<GdsEmulator>(new GdsEmulator());
  auto state = std::make_shared<State>();
  emulator->mState = state;
  state->executor = options.executor;
  state->crypto = options.crypto;
  state->workDirectory = options.workDirectory;
  state->applicationUri = options.applicationUri;
  const auto& crypto = *state->crypto;

  // ---- The CA ----
  auto caKeys = wait_for<std::shared_ptr<const AsymmetricKeyPair>>(
    [&crypto](auto done)
    {
      crypto.create_asymmetric_key_pair_async(
        CertificateKeyAlgorithm::Rsa, std::size_t{2048}, std::move(done));
    });
  if (caKeys.is_bad())
  {
    return {caKeys.status_code(), caKeys.shared_detail()};
  }
  state->caKeys = caKeys.value();
  auto ca = create_ca(crypto, state->caKeys, "GDS Emulator CA", "1");
  if (ca.is_bad())
  {
    return {ca.status_code(), ca.shared_detail()};
  }
  state->caCertificate = ca.value();
  auto crl = wait_for<std::shared_ptr<const X509Crl>>([&crypto, state](auto done)
    { crypto.create_crl_async(state->caCertificate, state->caKeys, {}, std::move(done)); });
  if (crl.is_bad())
  {
    return {crl.status_code(), crl.shared_detail()};
  }
  state->caCrl = crl.value();

  // ---- The server's own certificate and channel trust ----
  Crypto::Name subject;
  subject.commonName = "GDS Emulator";
  subject.organization = "GDS Emulator";
  Crypto::SubjectAlternateName alternateName;
  alternateName.uris.push_back(options.applicationUri);
  alternateName.hostnames.push_back("localhost");
  alternateName.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
  auto serverIdentity = crypto.try_create_self_signed_application_instance_certificate_sync(
    subject, DateTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
  if (serverIdentity.is_bad())
  {
    return {serverIdentity.status_code(), serverIdentity.shared_detail()};
  }
  auto [serverKeys, serverCertificate] = std::move(serverIdentity).value();
  state->serverCertificate = serverCertificate;
  std::filesystem::create_directories(options.workDirectory / "server");
  state->serverStore = CertificateStoreFiles::create(
    options.executor, state->crypto, {.trustListPath = options.workDirectory / "server"});
  {
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = serverCertificate;
    own.keys = std::move(serverKeys);
    if (auto added = state->serverStore->try_add_to_application_certificates_sync(own); added.is_bad())
    {
      return {added.status_code(), added.shared_detail()};
    }
  }
  // The GDS accepts channels from applications holding a certificate its own CA issued.
  if (auto added = state->serverStore->try_add_to_trusted_certificates_sync(state->caCertificate);
      added.is_bad())
  {
    return {added.status_code(), added.shared_detail()};
  }
  if (auto added = state->serverStore->try_add_to_trusted_crls_sync(state->caCrl); added.is_bad())
  {
    return {added.status_code(), added.shared_detail()};
  }

  // ---- The server ----
  auto application = ua::test_utils::create_test_config();
  application.allowInsecureEndpoints = true;
  application.application_description_part().applicationUri = options.applicationUri;
  ServerComponents components{.crypto = state->crypto,
    .applicationGroupCertificateStore = state->serverStore,
    .authenticator = std::make_shared<AnonymousAuthenticator>(),
    .roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}})};
  CreateConfig createConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(application)};
  try
  {
    state->server.emplace(Server::create(options.executor, std::move(createConfig), std::move(components)));
  }
  catch (const UaException& exception)
  {
    return {exception.status_code(),
      ErrorDetail::build(
        "GdsServerCreateFailed", "the emulator server could not be created", std::string{errorSource})
        .cause(exception.status_code())};
  }
  auto& server = *state->server;
  server.set_observer(std::make_shared<CallerIdentityObserver>(state));

  // ---- Import the official GDS model (Part 12 Annex / Opc.Ua.Gds.NodeSet2.xml) ----
  FileStream nodeSet{options.nodeSetPath};
  nodeSet.open_for_read();
  NodeSetImportOptions importOptions;
  importOptions.namespaceFactory = [executor = options.executor](
                                     string_view uri) -> std::shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
  auto imported = server.try_import_nodeset_sync(nodeSet, std::move(importOptions));
  if (imported.is_bad())
  {
    return {imported.status_code(), imported.shared_detail()};
  }
  auto addressSpace = server.address_space();
  state->gdsNamespaceIndex = addressSpace.namespace_array().get_namespace_index(gdsNamespaceUri);
  if (state->gdsNamespaceIndex == 0)
  {
    return fail("GdsNamespaceMissing", "the import did not register http://opcfoundation.org/UA/GDS/");
  }
  // The imported namespace declares no defaults and would hide its undecorated nodes; the Methods below
  // carry NodeSet RolePermissions that grant Call to CertificateAuthorityAdmin only. A pull client is an
  // Anonymous Session authorised by the ApplicationSelfAdmin Privilege (Part 12 7.2, Table 21 Connect) -
  // not a Role - so Call is opened here and the handlers enforce the Privilege themselves.
  ua::test_helpers::grant_namespace_to_test_client(addressSpace, state->gdsNamespaceIndex);
  const auto gds = state->gdsNamespaceIndex;

  auto directory =
    find_forward_child(addressSpace, NodeId{ObjectId::ObjectsFolder}, QualifiedName{gds, "Directory"});
  if (directory.is_bad())
  {
    return {directory.status_code(), directory.shared_detail()};
  }
  state->directoryId = directory.value();
  const auto grants = call_grants();
  std::weak_ptr<State> weakState = state;
  for (std::size_t index = 0; index < methodCount; ++index)
  {
    const auto method = static_cast<GdsMethod>(index);
    auto methodId =
      find_forward_child(addressSpace, state->directoryId, QualifiedName{gds, browse_name_of(method)});
    if (methodId.is_bad())
    {
      return {methodId.status_code(), methodId.shared_detail()};
    }
    state->methodIds[index] = methodId.value();
    auto node = addressSpace.find_node_sync(methodId.value());
    node.set_role_permissions(grants);
    for (const auto& property : node.get_properties_sync())
    {
      addressSpace.find_node_sync(property.target_id().node_id()).set_role_permissions(grants);
    }
    auto* source = node->method_call_source();
    if (!source)
    {
      return fail("GdsMethodNotCallable", "the Directory Method has no call source");
    }
    source->set_call_handler(
      [weakState, method](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext>
          context,
        std::function<void(CallResult)>
          callback)
      {
        auto held = weakState.lock();
        if (!held)
        {
          callback(bad(Status::BadShutdown, "GdsEmulatorGone", "the emulator was destroyed"));
          return;
        }
        held->dispatch(method, request, std::move(context), std::move(callback));
      });
  }

  // ---- DefaultApplicationGroup and its TrustList (Part 12 7.9.2: shall be supported) ----
  auto groups = find_forward_child(addressSpace, state->directoryId, QualifiedName{gds, "CertificateGroups"});
  if (groups.is_bad())
  {
    return {groups.status_code(), groups.shared_detail()};
  }
  auto defaultGroup =
    find_forward_child(addressSpace, groups.value(), QualifiedName{0, "DefaultApplicationGroup"});
  if (defaultGroup.is_bad())
  {
    return {defaultGroup.status_code(), defaultGroup.shared_detail()};
  }
  auto trustList = find_forward_child(addressSpace, defaultGroup.value(), QualifiedName{0, "TrustList"});
  if (trustList.is_bad())
  {
    return {trustList.status_code(), trustList.shared_detail()};
  }
  auto lastUpdateTime =
    find_forward_child(addressSpace, trustList.value(), QualifiedName{0, "LastUpdateTime"});
  if (lastUpdateTime.is_bad())
  {
    return {lastUpdateTime.status_code(), lastUpdateTime.shared_detail()};
  }

  State::Group group;
  group.id = defaultGroup.value();
  group.trustListId = trustList.value();
  group.lastUpdateTimeId = lastUpdateTime.value();
  group.certificateTypes = {NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType},
    NodeId{ObjectTypeId::EccNistP256ApplicationCertificateType}};
  group.trusted = {state->caCertificate};
  group.trustedCrls = {state->caCrl};
  group.lastUpdateTime = DateTime::now();
  std::filesystem::create_directories(options.workDirectory / "default_application_group");
  group.store = CertificateStoreFiles::create(
    options.executor, state->crypto, {.trustListPath = options.workDirectory / "default_application_group"});
  group.trustList = TrustListManager::create(
    TrustListManager::Dependencies{.strand = boost::asio::make_strand(options.executor),
      .certificateStore = group.store,
      .crypto = state->crypto,
      .executor = options.executor},
    [](NodeId, std::shared_ptr<TrustListModificationClaim>) {});
  if (auto wired = wire_trust_list(addressSpace, group.trustListId, group.trustList); wired.is_bad())
  {
    return {wired.status_code(), wired.shared_detail()};
  }
  {
    auto node = addressSpace.find_node_sync(group.lastUpdateTimeId);
    node.set_role_permissions(grants);
    auto* values = node->external_value_source();
    if (!values)
    {
      return fail("GdsLastUpdateTimeNotReadable", "TrustList LastUpdateTime has no external value source");
    }
    const auto groupId = group.id;
    (void)values->set_value_source(make_value_source(
      [weakState, groupId](const ValueSource::ReadContext&,
        const Node&,
        const ReadValueId& read,
        std::function<void(DataValueResult)>
          complete)
      {
        DataValue value;
        if (auto held = weakState.lock())
        {
          const std::lock_guard lock(held->mutex);
          if (auto* found = held->find_group(groupId))
          {
            value.value() = Variant{found->lastUpdateTime};
          }
        }
        value.server_timestamp() = DateTime::now();
        value.source_timestamp() = DateTime::now();
        index_range_utils::apply_to_value(value, read.index_range());
        complete(DataValueResult{std::move(value)});
      }));
  }
  const auto groupId = group.id;
  state->groups.push_back(std::move(group));
  if (auto published =
        wait_void([state, groupId](auto done) { state->publish_group_async(groupId, std::move(done)); });
      published.is_bad())
  {
    return {published.status_code(), published.shared_detail()};
  }

  // ---- Endpoints and start ----
  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  ListenerHandle listener{0};
  try
  {
    listener = server.listen_sync(std::move(bind), {});
    for (auto [name, mode, policy] : {std::tuple{"None", MessageSecurityMode::None, SecurityPolicyId::None},
           std::tuple{"Basic256Sha256_Sign", MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256},
           std::tuple{"Basic256Sha256_SignAndEncrypt",
             MessageSecurityMode::SignAndEncrypt,
             SecurityPolicyId::Basic256Sha256}})
    {
      ServerEndpointConfig endpoint;
      endpoint.name = name;
      endpoint.messageSecurityMode = mode;
      endpoint.securityPolicyId = policy;
      endpoint.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      server.add_endpoint(listener, std::move(endpoint));
    }
    server.start_sync();
  }
  catch (const UaException& exception)
  {
    return {exception.status_code(),
      ErrorDetail::build(
        "GdsServerStartFailed", "the emulator server could not start", std::string{errorSource})
        .cause(exception.status_code())};
  }
  const auto urls = server.advertised_urls(listener);
  if (urls.empty())
  {
    return fail("GdsEndpointMissing", "the emulator server advertises no URL");
  }
  state->endpointUrl = urls.front().str();
  return {std::move(emulator)};
}

GdsEmulator::~GdsEmulator() = default;

void GdsEmulator::shutdown()
{
  if (!mState || mState->shutDown)
  {
    return;
  }
  mState->shutDown = true;
  for (auto& group : mState->groups)
  {
    if (group.trustList)
    {
      group.trustList->shutdown();
    }
  }
  if (mState->server)
  {
    (void)mState->server->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  }
}

const std::string& GdsEmulator::endpoint_url() const
{
  return mState->endpointUrl;
}

std::shared_ptr<const X509Certificate> GdsEmulator::server_certificate() const
{
  return mState->serverCertificate;
}

std::uint16_t GdsEmulator::gds_namespace_index() const
{
  return mState->gdsNamespaceIndex;
}

NodeId GdsEmulator::directory_id() const
{
  return mState->directoryId;
}

NodeId GdsEmulator::method_id(GdsMethod method) const
{
  return mState->methodIds[index_of(method)];
}

NodeId GdsEmulator::default_application_group_id() const
{
  return mState->groups.front().id;
}

NodeId GdsEmulator::default_application_trust_list_id() const
{
  return mState->groups.front().trustListId;
}

NodeId GdsEmulator::default_application_trust_list_last_update_time_id() const
{
  return mState->groups.front().lastUpdateTimeId;
}

void GdsEmulator::trust_client_certificate(std::shared_ptr<const X509Certificate> certificate)
{
  mState->serverStore->add_to_trusted_certificates_sync(std::move(certificate));
}

void GdsEmulator::grant_application_admin(std::shared_ptr<const X509Certificate> certificate)
{
  const std::lock_guard lock(mState->mutex);
  mState->adminThumbprints.insert(ua::to_string(certificate->thumbprint()));
}

void GdsEmulator::set_next_approval(GdsApproval approval)
{
  const std::lock_guard lock(mState->mutex);
  mState->approvals.push_back(approval);
}

void GdsEmulator::set_update_required(const NodeId& applicationId, const NodeId& certificateGroupId,
  const NodeId& certificateTypeId, bool updateRequired)
{
  const std::lock_guard lock(mState->mutex);
  auto* group = mState->find_group(certificateGroupId);
  if (!group)
  {
    throw UaException{Status::BadInvalidArgument};
  }
  const NodeId typeId = certificateTypeId.is_null() ? group->certificateTypes.front() : certificateTypeId;
  mState->updateRequired[{applicationId, group->id, typeId}] = updateRequired;
}

namespace
{

template<typename Edit>
void edit_group(const std::shared_ptr<State>& state, const NodeId& groupId, Edit edit)
{
  {
    const std::lock_guard lock(state->mutex);
    auto* group = state->find_group(groupId);
    if (!group)
    {
      throw UaException{Status::BadInvalidArgument};
    }
    edit(*group);
    state->bump(*group);
  }
  auto published =
    wait_void([state, groupId](auto done) { state->publish_group_async(groupId, std::move(done)); });
  if (published.is_bad())
  {
    throw UaException{published.status_code().as_status(), published.shared_detail()};
  }
}

}  // namespace

void GdsEmulator::add_trusted_certificate(
  const NodeId& certificateGroupId, std::shared_ptr<const X509Certificate> certificate)
{
  edit_group(mState,
    certificateGroupId,
    [&](State::Group& group) { group.trusted.push_back(std::move(certificate)); });
}

void GdsEmulator::remove_trusted_certificate(
  const NodeId& certificateGroupId, const X509Certificate& certificate)
{
  edit_group(mState,
    certificateGroupId,
    [&](State::Group& group)
    {
      std::erase_if(
        group.trusted, [&](const auto& held) { return held->der_encoding() == certificate.der_encoding(); });
    });
}

void GdsEmulator::add_issuer_certificate(
  const NodeId& certificateGroupId, std::shared_ptr<const X509Certificate> certificate)
{
  edit_group(mState,
    certificateGroupId,
    [&](State::Group& group) { group.issuers.push_back(std::move(certificate)); });
}

void GdsEmulator::remove_issuer_certificate(
  const NodeId& certificateGroupId, const X509Certificate& certificate)
{
  edit_group(mState,
    certificateGroupId,
    [&](State::Group& group)
    {
      std::erase_if(
        group.issuers, [&](const auto& held) { return held->der_encoding() == certificate.der_encoding(); });
    });
}

void GdsEmulator::add_trusted_crl(const NodeId& certificateGroupId, std::shared_ptr<const X509Crl> crl)
{
  edit_group(
    mState, certificateGroupId, [&](State::Group& group) { group.trustedCrls.push_back(std::move(crl)); });
}

void GdsEmulator::add_issuer_crl(const NodeId& certificateGroupId, std::shared_ptr<const X509Crl> crl)
{
  edit_group(
    mState, certificateGroupId, [&](State::Group& group) { group.issuerCrls.push_back(std::move(crl)); });
}

void GdsEmulator::revoke_certificate(const X509Certificate& certificate)
{
  auto copy = mState->crypto->read_certificate_from_der(span<const byte>{certificate.der_encoding()});
  auto state = mState;
  auto revoked = wait_void([state, copy](auto done) { state->revoke_async({copy}, std::move(done)); });
  if (revoked.is_bad())
  {
    throw UaException{revoked.status_code().as_status(), revoked.shared_detail()};
  }
}

std::shared_ptr<const X509Certificate> GdsEmulator::issue_certificate(
  std::shared_ptr<const AsymmetricKeyPair> subjectKeys, Crypto::Name subject,
  Crypto::SubjectAlternateName alternateName)
{
  Crypto::CreateCertificateConfig parameters;
  {
    const std::lock_guard lock(mState->mutex);
    parameters.serialNumber = mState->next_serial();
    parameters.issuer = mState->caCertificate;
    parameters.issuerKeys = mState->caKeys;
  }
  parameters.subject = std::move(subject);
  parameters.subjectKeys = std::move(subjectKeys);
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  parameters.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.nonRepudiation = true;
  parameters.keyUsage.keyEncipherment = true;
  parameters.keyUsage.dataEncipherment = true;
  parameters.keyUsage.clientAuth = true;
  parameters.keyUsage.serverAuth = true;
  parameters.basicConstraint.cA = false;
  parameters.subjectAlternateName = std::move(alternateName);
  std::promise<CertificateResult> promise;
  mState->crypto->create_certificate_async(
    parameters, [&promise](CertificateResult result) { promise.set_value(std::move(result)); });
  auto issued = promise.get_future().get();
  if (issued.is_bad())
  {
    throw UaException{issued.status_code().as_status(), issued.shared_detail()};
  }
  return issued.value();
}

std::shared_ptr<const X509Certificate> GdsEmulator::ca_certificate() const
{
  const std::lock_guard lock(mState->mutex);
  return mState->caCertificate;
}

std::shared_ptr<const X509Crl> GdsEmulator::ca_crl() const
{
  const std::lock_guard lock(mState->mutex);
  return mState->caCrl;
}

std::size_t GdsEmulator::call_count(GdsMethod method) const
{
  const std::lock_guard lock(mState->mutex);
  return mState->callCounts[index_of(method)];
}

std::vector<Variant> GdsEmulator::last_arguments(GdsMethod method) const
{
  const std::lock_guard lock(mState->mutex);
  return mState->lastArguments[index_of(method)];
}

std::vector<GdsIssuedCertificate> GdsEmulator::issued_certificates(const NodeId& applicationId) const
{
  const std::lock_guard lock(mState->mutex);
  std::vector<GdsIssuedCertificate> out;
  for (const auto& certificate : mState->issued)
  {
    if (certificate.applicationId == applicationId)
    {
      out.push_back(certificate);
    }
  }
  return out;
}

std::optional<GdsApplicationRecord> GdsEmulator::application(const NodeId& applicationId) const
{
  const std::lock_guard lock(mState->mutex);
  const auto found = mState->applications.find(applicationId);
  if (found == mState->applications.end())
  {
    return std::nullopt;
  }
  return found->second;
}

DateTime GdsEmulator::trust_list_last_update_time(const NodeId& certificateGroupId) const
{
  const std::lock_guard lock(mState->mutex);
  auto* group = mState->find_group(certificateGroupId);
  return group ? group->lastUpdateTime : DateTime{};
}

NodeId GdsEmulator::application_record_data_type_id() const
{
  return NodeId{mState->gdsNamespaceIndex, applicationRecordDataTypeId};
}

Variant GdsEmulator::encode_application_record(const GdsApplicationRecord& record) const
{
  return mState->encode_record(record);
}

Result<GdsApplicationRecord> GdsEmulator::decode_application_record(const Variant& value) const
{
  if (!value.is_structure())
  {
    return {StatusCode{Status::BadTypeMismatch},
      make_error_detail(
        "GdsApplicationRecordNotStructure", "the value is not a Structure", std::string{errorSource})};
  }
  return mState->decode_record(value.as<Structure>());
}

Result<ByteString> unprotected_private_key_pem(CertificateKeyAlgorithm algorithm)
{
  return generate_unprotected_pem(algorithm);
}

}  // namespace ua::test
