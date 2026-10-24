// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_configuration.h"
#include "ua_identity_thumbprint.h"

#include "ua_claim_keys.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_message_security_mode.h"
#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_well_known_role_permissions.h"
#include "ua_to_result.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <exception>
#include <mutex>
#include <string>
#include <string_view>

namespace ua::server
{

namespace
{

// ============================================================================
// Format discipline helpers - Part 18 4.4.3
// ============================================================================

const std::string roleConfigurationSource{"RoleConfiguration"};

/// Part 18 4.4.3 Table 8 - RDN attribute order for X509Subject criteria.
/// Lower index = higher priority in the canonical ordering. The names are
/// matched case-sensitively per X.500 / RFC 4514 convention.
constexpr std::array<std::string_view, 9> x509SubjectTable8{
  "CN", "O", "OU", "DC", "L", "S", "C", "dnQualifier", "serialNumber"};

std::optional<size_t> table8_order(std::string_view name) noexcept
{
  for (size_t i = 0; i < x509SubjectTable8.size(); ++i)
  {
    if (x509SubjectTable8[i] == name)
    {
      return i;
    }
  }
  return std::nullopt;
}

/// Canonicalise an X509Subject criteria string per Part 18 4.4.3 L793-808 +
/// Table 8. Input format: `Name1="Value1"/Name2="Value2"/...` with the names
/// drawn from Table 8. Output is the same syntax with
/// the tokens reordered by Table-8 column (lowest first), preserving the
/// input order for repeated names. Part 18 section 4.4.3 requires every name
/// in the criteria string to be a Table-8 entry; its rule that other names are
/// ignored applies to attributes in the Certificate being matched.
///
/// Rejects values that contain a `"` character (spec: "The value may be any
/// printable character except for '\"'.") - detected by scanning whether the
/// character following the closing quote is `/` or end-of-input.
Result<std::string> canonicalise_x509_subject(std::string_view input)
{
  auto reject = [&input](std::string summary)
  {
    return Result<std::string>{StatusCode{Status::BadInvalidArgument},
      ErrorDetail::build("IdentityRuleSubjectMalformed",
        "Malformed X509Subject criteria",
        "server.tier1.authz.rbac.identity_rule.x509_subject.malformed")
        .context(ua::ContextKeys::errorMessage, std::move(summary))
        .context(ua::ContextKeys::actual, std::string(input))};
  };

  struct Token
  {
    size_t orderKey;  // Table-8 index; std::stable_sort preserves input order on equal keys.
    std::string_view name;
    std::string value;
  };

  std::vector<Token> tokens;
  size_t cursor = 0;
  while (cursor < input.size())
  {
    // Skip the separator if not at start.
    if (cursor != 0)
    {
      if (input[cursor] != '/')
      {
        return reject(
          "X509Subject criteria must separate Name=\"Value\" tokens with '/' per Part 18 4.4.3 L795.");
      }
      ++cursor;
    }
    const size_t eq = input.find('=', cursor);
    if (eq == std::string_view::npos)
    {
      return reject("X509Subject criteria token is missing '=' per Part 18 4.4.3 L795-796.");
    }
    const std::string_view name = input.substr(cursor, eq - cursor);
    if (name.empty())
    {
      return reject("X509Subject criteria token has empty attribute name.");
    }
    if (eq + 1 >= input.size() || input[eq + 1] != '"')
    {
      return reject("X509Subject criteria value must be enclosed in double quotes per Part 18 4.4.3 L796.");
    }
    const size_t valueStart = eq + 2;
    const size_t closingQuote = input.find('"', valueStart);
    if (closingQuote == std::string_view::npos)
    {
      return reject("X509Subject criteria value has no closing double quote.");
    }
    cursor = closingQuote + 1;
    // After the closing `"`, only `/` (token separator) or end-of-input is
    // valid. Anything else means the value contained a `"` character -
    // Part 18 4.4.3 L801 forbids that ("any printable character except
    // for '\"'.").
    if (cursor < input.size() && input[cursor] != '/')
    {
      return reject(
        "X509Subject criteria value must not contain a '\"' character "
        "(Part 18 4.4.3 L801).");
    }
    std::string value{input.substr(valueStart, closingQuote - valueStart)};

    const auto order = table8_order(name);
    if (!order.has_value())
    {
      return reject("X509Subject criteria attribute '" + std::string{name} +
                    "' is not listed in Part 18 section 4.4.3 Table 8.");
    }
    tokens.push_back(Token{*order, name, std::move(value)});
  }

  // std::stable_sort preserves the relative order of equal-key tokens, so
  // repeated attribute names retain their input order per Part 18 4.4.3
  // L805-807 ("entries with the same name are entered in the order they
  // appear in the Certificate").
  std::stable_sort(tokens.begin(),
    tokens.end(),
    [](const Token& a, const Token& b) noexcept { return a.orderKey < b.orderKey; });

  std::string out;
  for (size_t i = 0; i < tokens.size(); ++i)
  {
    if (i != 0)
    {
      out.push_back('/');
    }
    out.append(tokens[i].name);
    out.append("=\"");
    out.append(tokens[i].value);
    out.push_back('"');
  }
  return Result<std::string>{std::move(out)};
}

/// Apply Part 18 4.4.3 format discipline to a single identity rule in
/// place. Used by every API that lands a rule in `RoleConfiguration`
/// (`add_role`, `add_custom_role`, `add_identity_rule`) so the stored
/// criteria is always canonical regardless of the entry path.
VoidResult canonicalise_in_place(IdentityMappingRuleType& rule)
{
  const bool criteriaRequired = rule.criteria_type() == IdentityCriteriaType::UserName ||
                                rule.criteria_type() == IdentityCriteriaType::Thumbprint ||
                                rule.criteria_type() == IdentityCriteriaType::Role ||
                                rule.criteria_type() == IdentityCriteriaType::GroupId ||
                                rule.criteria_type() == IdentityCriteriaType::Application ||
                                rule.criteria_type() == IdentityCriteriaType::X509Subject;
  if (criteriaRequired && rule.criteria().empty())
  {
    return VoidResult{StatusCode{Status::BadInvalidArgument},
      ErrorDetail::build("IdentityRuleCriteriaEmpty",
        "Identity rules that compare a configured value require non-empty criteria.",
        roleConfigurationSource)};
  }

  switch (rule.criteria_type())
  {
  case IdentityCriteriaType::Thumbprint:
  {
    auto normalised = normalise_identity_thumbprint(rule.criteria());
    if (!normalised.is_good())
    {
      return VoidResult{normalised.status_code()};
    }
    rule.criteria() = String{std::move(normalised).value()};
    return VoidResult{};
  }
  case IdentityCriteriaType::X509Subject:
  {
    auto canonical = canonicalise_x509_subject(rule.criteria());
    if (!canonical.is_good())
    {
      return VoidResult{canonical.status_code()};
    }
    rule.criteria() = String{std::move(canonical).value()};
    return VoidResult{};
  }
  default:
    return VoidResult{};
  }
}

String calling_application_uri(const UserIdentity&, const EndpointSecurityContext& security) noexcept
{
  // This is the URI verified against the authenticated client certificate during CreateSession.
  // Never fall back to an authenticator claim: claims are application supplied and cannot bind the
  // SecureChannel's ApplicationInstanceCertificate to the CreateSession ApplicationDescription.
  return security.clientApplicationUri;
}

/// The two application-authentication gates shared by the `Application` and
/// `TrustedApplication` identity criteria (Part 18 4.4.3 L785-788): the
/// Client's ApplicationInstanceCertificate shall be trusted by the Server AND
/// the Session shall use at least a signed communication channel.
///
/// Trust is surfaced to `RoleConfiguration` via the `client_cert_trusted=true`
/// claim populated by the session-side producer when the client cert validates
/// against the trust list (the P1 trusted-cert mechanism). A failed gate
/// suppresses the rule match (rather than denying the request outright) so the
/// absence of a gate signal is visible as "role not granted", consistent with
/// the other criteria types.
bool client_application_trusted(const UserIdentity& user, const EndpointSecurityContext& security) noexcept
{
  if (security.messageSecurityMode != MessageSecurityMode::Sign &&
      security.messageSecurityMode != MessageSecurityMode::SignAndEncrypt)
  {
    return false;
  }
  auto trustClaim = user.claims.find(ClaimKeys::clientCertificateTrusted);
  return trustClaim != user.claims.end() && trustClaim->second == "true";
}

bool rule_matches(
  const IdentityMappingRuleType& rule, const UserIdentity& user, const EndpointSecurityContext& security)
{
  const std::string criteria{static_cast<std::string>(rule.criteria())};
  switch (rule.criteria_type())
  {
  case IdentityCriteriaType::Anonymous:
    return user.kind == UserTokenKind::Anonymous;
  case IdentityCriteriaType::AuthenticatedUser:
    return user.kind != UserTokenKind::Anonymous;
  case IdentityCriteriaType::UserName:
    // Part 18 section 4.4.4 Table 10: the criterion names a UserName from a UserNameIdentityToken.
    // An X.509 or issued identity whose user id happens to equal the name is a different principal.
    return user.kind == UserTokenKind::UserName && user.userId == criteria;
  case IdentityCriteriaType::Thumbprint:
  {
    auto it = user.claims.find(ClaimKeys::thumbprint);
    if (it == user.claims.end())
    {
      return false;
    }
    // Normalise the user-side claim to the same upper-case-no-spaces shape
    // used at config time so a mixed-case / dashed PEM thumbprint still
    // matches the canonical stored form.
    auto normalised = normalise_identity_thumbprint(it->second);
    return normalised.is_good() && normalised.value() == criteria;
  }
  case IdentityCriteriaType::Role:
  {
    auto it = user.claims.find(ClaimKeys::role);
    return it != user.claims.end() && it->second == criteria;
  }
  case IdentityCriteriaType::GroupId:
  {
    auto it = user.claims.find(ClaimKeys::group);
    return it != user.claims.end() && it->second == criteria;
  }
  case IdentityCriteriaType::Application:
  {
    // Part 18 4.4.3 L785-786: `criteria` is the ApplicationUri taken from the
    // Client Certificate; it must equal the calling application's URI. The
    // trusted-cert + signed-channel gates then apply (shared with
    // TrustedApplication).
    const String callingApp = calling_application_uri(user, security);
    if (callingApp.empty() || static_cast<std::string_view>(callingApp) != criteria)
    {
      return false;
    }
    return client_application_trusted(user, security);
  }
  case IdentityCriteriaType::TrustedApplication:
    // Part 18 4.4.3 (1.05.04+): like Application, but matches ANY Session
    // whose ApplicationInstanceCertificate is trusted - the `criteria` field
    // is not used (no specific ApplicationUri is compared). Only the shared
    // trusted-cert + signed-channel gates apply.
    return client_application_trusted(user, security);
  case IdentityCriteriaType::X509Subject:
  {
    auto it = user.claims.find(ClaimKeys::x509Subject);
    if (it == user.claims.end())
    {
      return false;
    }
    auto canonical = canonicalise_x509_subject(it->second);
    return canonical.is_good() && canonical.value() == criteria;
  }
  }
  return false;
}

bool application_filter_passes(const RoleConfiguration::RoleDefinition& role, const UserIdentity& user,
  const EndpointSecurityContext& security) noexcept
{
  if (role.applications.empty())
  {
    return true;
  }
  // Part 18 4.4.1 L665-671: a Role with a non-empty Applications property
  // is the explicit application-authentication path; the session must be at
  // least signed (Sign or SignAndEncrypt). Plain `None` channels cannot
  // satisfy an Applications-filtered Role regardless of include/exclude mode.
  if (security.messageSecurityMode != MessageSecurityMode::Sign &&
      security.messageSecurityMode != MessageSecurityMode::SignAndEncrypt)
  {
    return false;
  }
  const String callingApp = calling_application_uri(user, security);
  if (callingApp.empty())
  {
    // No app URI presented: include-list rejects, exclude-list accepts.
    return role.applicationsExclude;
  }
  const bool listed = std::any_of(role.applications.begin(),
    role.applications.end(),
    [&](const String& candidate) noexcept { return candidate == callingApp; });
  return role.applicationsExclude ? !listed : listed;
}

bool endpoint_entry_matches(const EndpointType& entry, const EndpointSecurityContext& security) noexcept
{
  // Per Part 18 4.4.2: non-default fields narrow the match; default-valued
  // fields ("ignored for comparison") match anything. SecurityMode default is
  // `Invalid`; URL/policyUri/TransportProfileUri defaults are empty/null.
  if (!entry.endpoint_url().empty() && static_cast<std::string_view>(entry.endpoint_url()) !=
                                         static_cast<std::string_view>(security.endpointUrl))
  {
    return false;
  }
  if (entry.security_mode() != MessageSecurityMode::Invalid &&
      entry.security_mode() != security.messageSecurityMode)
  {
    return false;
  }
  if (!entry.security_policy_uri().empty())
  {
    const String actualPolicyUri = utils::get_security_policy_uri(security.securityPolicyId);
    if (static_cast<std::string_view>(entry.security_policy_uri()) !=
        static_cast<std::string_view>(actualPolicyUri))
    {
      return false;
    }
  }
  if (!entry.transport_profile_uri().empty() &&
      static_cast<std::string_view>(entry.transport_profile_uri()) !=
        static_cast<std::string_view>(security.transportProfileUri))
  {
    return false;
  }
  return true;
}

bool endpoint_filter_passes(
  const RoleConfiguration::RoleDefinition& role, const EndpointSecurityContext& security) noexcept
{
  if (role.endpoints.empty())
  {
    return true;
  }
  const bool listed = std::any_of(role.endpoints.begin(),
    role.endpoints.end(),
    [&](const EndpointType& entry) noexcept { return endpoint_entry_matches(entry, security); });
  return role.endpointsExclude ? !listed : listed;
}

}  // namespace

/// Upper-case-hex-no-spaces normalisation per Part 18 4.4.3 L766-769:
///   "the thumbprint shall be encoded as a hexadecimal string with upper case
///    characters and without spaces."
///
/// Accepts any mixed-case hex string with arbitrary internal whitespace and
/// canonicalises to the spec-prescribed shape. Rejects non-hex characters.
Result<std::string> normalise_identity_thumbprint(std::string_view input)
{
  std::string out;
  out.reserve(input.size());
  for (const char c : input)
  {
    // Tolerate common separator characters (spaces, colons, dashes) that
    // appear in cert-tool output ("AB:CD:..." / "AB-CD-..." / "AB CD ...") -
    // the spec only constrains the canonical *stored* form, not the input.
    if (std::isspace(numeric_cast<unsigned char>(c)) || c == ':' || c == '-')
    {
      continue;
    }
    if (!std::isxdigit(numeric_cast<unsigned char>(c)))
    {
      return Result<std::string>{StatusCode{Status::BadInvalidArgument},
        ErrorDetail::build("IdentityRuleThumbprintMalformed",
          "Thumbprint criteria must be a hexadecimal string per Part 18 4.4.3 L766-769; "
          "non-hex character encountered.",
          "server.tier1.authz.rbac.identity_rule.thumbprint.malformed")
          .context(ua::ContextKeys::value, std::string(1, c))};
    }
    out.push_back(static_cast<char>(std::toupper(numeric_cast<unsigned char>(c))));
  }
  return Result<std::string>{std::move(out)};
}

namespace
{

void add_well_known_grant(
  RoleConfiguration& configuration, const RoleConfiguration::WellKnownRoleGrant& grant, size_t grantIndex)
{
  const auto roleBit = well_known_role_bit(grant.role);
  if (!roleBit.has_value())
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("WellKnownRoleGrantInvalidRole",
        "Declarative Role grant names an invalid well-known Role",
        "RoleConfiguration")
        .context(ContextKeys::operationIndex, grantIndex)
        .context(ContextKeys::actual, utils::to_underlying(grant.role))};
  }

  const NodeId roleId = well_known_role_node_id(grant.role);
  const auto configuredBit = configuration.role_bit(roleId);
  if (!configuredBit.has_value())
  {
    RoleConfiguration::RoleDefinition definition;
    definition.roleId = roleId;
    definition.roleBit = *roleBit;
    if (!configuration.add_role(std::move(definition)))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("WellKnownRoleGrantRoleCollision",
          "Declarative Role grant could not register its derived Role definition",
          "RoleConfiguration")
          .context(ContextKeys::operationIndex, grantIndex)
          .context(ContextKeys::nodeId, roleId.as_definition())};
    }
  }
  else if (*configuredBit != *roleBit)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("WellKnownRoleGrantBitMismatch",
        "Declarative Role grant found a mismatched internal Role slot",
        "RoleConfiguration")
        .context(ContextKeys::operationIndex, grantIndex)
        .context(ContextKeys::nodeId, roleId.as_definition())};
  }

  IdentityMappingRuleType rule;
  rule.criteria_type() = grant.criteriaType;
  rule.criteria() = grant.criteria;
  auto result = configuration.add_identity_rule(roleId, std::move(rule));
  if (result.is_bad())
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("WellKnownRoleGrantInvalidRule",
        "Declarative Role grant contains an invalid identity rule",
        "RoleConfiguration")
        .context(ContextKeys::operationIndex, grantIndex)
        .context(ContextKeys::nodeId, roleId.as_definition())
        .cause(result.status_code())};
  }
}

}  // namespace

std::shared_ptr<RoleConfiguration> RoleConfiguration::from_well_known_grants(
  std::initializer_list<WellKnownRoleGrant> grants)
{
  auto configuration = std::make_shared<RoleConfiguration>();
  size_t grantIndex = 0;
  for (const auto& grant : grants)
  {
    add_well_known_grant(*configuration, grant, grantIndex);
    ++grantIndex;
  }
  return configuration;
}

std::shared_ptr<RoleConfiguration> RoleConfiguration::from_well_known_grants(
  std::span<const WellKnownRole> roles, IdentityCriteriaType criteriaType, String criteria)
{
  auto configuration = std::make_shared<RoleConfiguration>();
  for (size_t grantIndex = 0; grantIndex < roles.size(); ++grantIndex)
  {
    add_well_known_grant(
      *configuration, WellKnownRoleGrant{roles[grantIndex], criteriaType, criteria}, grantIndex);
  }
  return configuration;
}

VoidResult RoleConfiguration::grant_role_management_access(std::vector<NodeId> roleIds) noexcept
{
  try
  {
    const std::unique_lock lock(mMutex);
    if (mRoleManagementAccessSealed)
    {
      return VoidResult{StatusCode{Status::BadInvalidState,
        ErrorDetail::build("RoleManagementAccessAlreadyConsumed",
          "Role-management access policy cannot be changed after a Server has consumed this "
          "RoleConfiguration",
          "RoleConfiguration")}};
    }
    if (roleIds.empty())
    {
      return VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("RoleManagementAccessEmpty",
          "At least one registered Role is required when granting Role-management access",
          "RoleConfiguration")}};
    }

    for (size_t index = 0; index < roleIds.size(); ++index)
    {
      const auto& roleId = roleIds[index];
      if (roleId.is_null())
      {
        return VoidResult{StatusCode{Status::BadInvalidArgument,
          ErrorDetail::build("RoleManagementAccessRoleNull",
            "A null NodeId cannot identify a Role granted Role-management access",
            "RoleConfiguration")
            .context(ContextKeys::index, index)}};
      }
      const auto registered = std::find_if(mRoles.begin(),
        mRoles.end(),
        [&roleId](const RoleDefinition& role) { return role.roleId == roleId; });
      if (registered == mRoles.end())
      {
        return VoidResult{StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("RoleManagementAccessRoleUnknown",
            "Role-management access can be granted only to a Role registered in this configuration",
            "RoleConfiguration")
            .context(ContextKeys::index, index)
            .context(ContextKeys::nodeId, roleId.as_definition())}};
      }
    }

    for (auto& roleId : roleIds)
    {
      if (std::find(mRoleManagementAccessRoles.begin(), mRoleManagementAccessRoles.end(), roleId) ==
          mRoleManagementAccessRoles.end())
      {
        mRoleManagementAccessRoles.push_back(std::move(roleId));
      }
    }
    return VoidResult{};
  }
  catch (...)
  {
    return VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

std::vector<NodeId> RoleConfiguration::consume_role_management_access_roles()
{
  const std::unique_lock lock(mMutex);
  mRoleManagementAccessSealed = true;
  return mRoleManagementAccessRoles;
}

bool RoleConfiguration::add_role(RoleDefinition definition)
{
  if (definition.roleBit >= 64)
  {
    return false;
  }
  // Apply Part 18 4.4.3 format discipline to every rule before storage so
  // the stored criteria is canonical regardless of which API the caller
  // used. If any rule fails to canonicalise, reject the whole definition
  // - partial mutation is worse than rejection here.
  for (auto& rule : definition.identities)
  {
    if (canonicalise_in_place(rule).is_bad())
    {
      return false;
    }
  }
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  for (const auto& existing : mRoles)
  {
    if (existing.roleId == definition.roleId)
    {
      continue;  // overwriting same id is allowed
    }
    if (existing.roleBit == definition.roleBit)
    {
      return false;  // bit collision with a different role
    }
  }
  auto found = std::find_if(mRoles.begin(),
    mRoles.end(),
    [&](const RoleDefinition& r) noexcept { return r.roleId == definition.roleId; });
  if (found != mRoles.end())
  {
    *found = std::move(definition);
  }
  else
  {
    mRoles.push_back(std::move(definition));
  }
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::remove_role(const NodeId& roleId) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto it = std::find_if(
    mRoles.begin(), mRoles.end(), [&](const RoleDefinition& r) noexcept { return r.roleId == roleId; });
  if (it == mRoles.end())
  {
    return false;
  }
  mRoles.erase(it);
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

void RoleConfiguration::add_well_known_defaults()
{
  RoleDefinition anonymous;
  anonymous.roleId = NodeId{0, utils::to_underlying(ObjectId::WellKnownRole_Anonymous)};
  anonymous.roleBit = 0;
  {
    // Mirror runtime seeding (`seed_well_known_roles` in
    // `ua_server_impl.cpp`): Anonymous ships with both the `Anonymous`
    // AND the `AuthenticatedUser` default rules per Part 18 4.3 L408-414.
    IdentityMappingRuleType anonRule;
    anonRule.criteria_type() = IdentityCriteriaType::Anonymous;
    anonymous.identities.push_back(std::move(anonRule));
    IdentityMappingRuleType authRule;
    authRule.criteria_type() = IdentityCriteriaType::AuthenticatedUser;
    anonymous.identities.push_back(std::move(authRule));
  }
  if (!add_role(std::move(anonymous)))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("WellKnownRoleDefaultCollision",
        "The Anonymous Role could not be registered because its bit slot collides",
        roleConfigurationSource)
        .context(ContextKeys::nodeId, well_known_role_node_id(WellKnownRole::Anonymous).as_definition())};
  }

  RoleDefinition authenticated;
  authenticated.roleId = NodeId{0, utils::to_underlying(ObjectId::WellKnownRole_AuthenticatedUser)};
  authenticated.roleBit = 1;
  {
    IdentityMappingRuleType rule;
    rule.criteria_type() = IdentityCriteriaType::AuthenticatedUser;
    authenticated.identities.push_back(std::move(rule));
  }
  if (!add_role(std::move(authenticated)))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("WellKnownRoleDefaultCollision",
        "The AuthenticatedUser Role could not be registered because its bit slot collides",
        roleConfigurationSource)
        .context(
          ContextKeys::nodeId, well_known_role_node_id(WellKnownRole::AuthenticatedUser).as_definition())};
  }
}

uint64_t RoleConfiguration::evaluate_roles(
  const UserIdentity& user, const EndpointSecurityContext& security) const
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  uint64_t mask{0};
  for (const auto& role : mRoles)
  {
    if (!application_filter_passes(role, user, security))
    {
      continue;
    }
    if (!endpoint_filter_passes(role, security))
    {
      continue;
    }
    for (const auto& rule : role.identities)
    {
      if (rule_matches(rule, user, security))
      {
        mask |= (uint64_t{1} << role.roleBit);
        break;
      }
    }
  }
  return mask;
}

std::vector<NodeId> RoleConfiguration::evaluate_role_ids(
  const UserIdentity& user, const EndpointSecurityContext& security) const
{
  return evaluate_access_identity(user, security).grantedRoles;
}

RoleConfiguration::AccessEvaluation RoleConfiguration::evaluate_access_identity(
  const UserIdentity& user, const EndpointSecurityContext& security) const
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  AccessEvaluation evaluation;
  evaluation.grantedRoles.reserve(mRoles.size());
  evaluation.registeredRoles.reserve(mRoles.size());
  for (const auto& role : mRoles)
  {
    evaluation.registeredRoles.push_back(role.roleId);
    if (!application_filter_passes(role, user, security) || !endpoint_filter_passes(role, security))
    {
      continue;
    }
    if (std::any_of(role.identities.begin(),
          role.identities.end(),
          [&](const IdentityMappingRuleType& rule) { return rule_matches(rule, user, security); }))
    {
      evaluation.grantedRoles.push_back(role.roleId);
    }
  }
  evaluation.configurationEpoch = mEpoch.load(std::memory_order_acquire);
  return evaluation;
}

std::vector<NodeId> RoleConfiguration::role_ids() const
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  std::vector<NodeId> registered;
  registered.reserve(mRoles.size());
  for (const auto& role : mRoles)
  {
    registered.push_back(role.roleId);
  }
  return registered;
}

std::optional<uint8_t> RoleConfiguration::role_bit(const NodeId& roleId) const noexcept
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  for (const auto& role : mRoles)
  {
    if (role.roleId == roleId)
    {
      return role.roleBit;
    }
  }
  return std::nullopt;
}

size_t RoleConfiguration::role_count() const noexcept
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  return mRoles.size();
}

std::optional<RoleConfiguration::RoleDefinition> RoleConfiguration::get_role(
  const NodeId& roleId) const noexcept
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  for (const auto& role : mRoles)
  {
    if (role.roleId == roleId)
    {
      return role;
    }
  }
  return std::nullopt;
}

std::vector<RoleConfiguration::RoleDefinition> RoleConfiguration::roles() const
{
  const std::shared_lock<std::shared_mutex> lock(mMutex);
  return mRoles;
}

namespace
{

/// Find a free bit slot in `[0, 63]` not used by any existing role. Caller
/// holds the unique lock -- which the `_locked` suffix states, so the name carries the precondition
/// its sibling `find_role_locked` already did. `callback-under-unique-lock` reads that suffix: a
/// helper that requires the lock is the opposite of a user callback that must not see it.
std::optional<uint8_t> find_free_bit_slot_locked(
  const std::vector<RoleConfiguration::RoleDefinition>& roles) noexcept
{
  uint64_t used{0};
  for (const auto& role : roles)
  {
    if (role.roleBit < 64)
    {
      used |= (uint64_t{1} << role.roleBit);
    }
  }
  for (uint8_t bit = 0; bit < 64; ++bit)
  {
    if ((used & (uint64_t{1} << bit)) == 0)
    {
      return bit;
    }
  }
  return std::nullopt;
}

RoleConfiguration::RoleDefinition* find_role_locked(
  std::vector<RoleConfiguration::RoleDefinition>& roles, const NodeId& roleId) noexcept
{
  auto it = std::find_if(roles.begin(),
    roles.end(),
    [&](const RoleConfiguration::RoleDefinition& r) noexcept { return r.roleId == roleId; });
  return it == roles.end() ? nullptr : &*it;
}

bool identity_rule_equal(const IdentityMappingRuleType& a, const IdentityMappingRuleType& b) noexcept
{
  return a.criteria_type() == b.criteria_type() &&
         static_cast<std::string_view>(a.criteria()) == static_cast<std::string_view>(b.criteria());
}

}  // namespace

std::optional<uint8_t> RoleConfiguration::add_custom_role(RoleDefinition definition)
{
  // Format-discipline pass before acquiring the lock so the unlocked
  // canonicaliser allocations don't block other readers.
  for (auto& rule : definition.identities)
  {
    if (canonicalise_in_place(rule).is_bad())
    {
      return std::nullopt;
    }
  }
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  if (find_role_locked(mRoles, definition.roleId))
  {
    return std::nullopt;  // already registered
  }
  auto bit = find_free_bit_slot_locked(mRoles);
  if (!bit)
  {
    return std::nullopt;  // no free slot
  }
  definition.roleBit = *bit;
  mRoles.push_back(std::move(definition));
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return bit;
}

VoidResult RoleConfiguration::add_identity_rule(const NodeId& roleId, IdentityMappingRuleType rule)
{
  // Format-discipline pass (Part 18 4.4.3 L766-769 + L793-808) - done
  // outside the lock since it depends only on the rule, and so the
  // allocating canonicaliser doesn't run under a unique-lock writer
  // contention window.
  if (auto canon = canonicalise_in_place(rule); canon.is_bad())
  {
    return canon;
  }

  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return VoidResult{StatusCode{Status::BadNotFound},
      ErrorDetail::build("IdentityRuleRoleNotFound",
        "Cannot add identity rule: role is not registered in RoleConfiguration.",
        "server.tier1.authz.rbac.identity_rule.role_not_found")
        .context(ua::ContextKeys::nodeId, roleId.as_definition())};
  }
  for (const auto& existing : role->identities)
  {
    if (identity_rule_equal(existing, rule))
    {
      return VoidResult{StatusCode{Status::BadEntryExists},
        ErrorDetail::build("IdentityRuleDuplicate",
          "Identity rule with the same criteria_type + criteria is already registered on this role.",
          "server.tier1.authz.rbac.identity_rule.duplicate")
          .context(ua::ContextKeys::nodeId, roleId.as_definition())
          .context(ua::ContextKeys::typeName, to_string(rule.criteria_type()))
          .context(ua::ContextKeys::actual, std::string(rule.criteria()))};
    }
  }
  role->identities.push_back(std::move(rule));
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return VoidResult{};
}

bool RoleConfiguration::remove_identity_rule(
  const NodeId& roleId, const IdentityMappingRuleType& rule) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  auto it = std::find_if(role->identities.begin(),
    role->identities.end(),
    [&](const IdentityMappingRuleType& existing) noexcept { return identity_rule_equal(existing, rule); });
  if (it == role->identities.end())
  {
    return false;
  }
  role->identities.erase(it);
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::add_application(const NodeId& roleId, String applicationUri) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  for (const auto& existing : role->applications)
  {
    if (existing == applicationUri)
    {
      return false;
    }
  }
  role->applications.push_back(std::move(applicationUri));
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::remove_application(const NodeId& roleId, const String& applicationUri) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  auto it = std::find(role->applications.begin(), role->applications.end(), applicationUri);
  if (it == role->applications.end())
  {
    return false;
  }
  role->applications.erase(it);
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::add_endpoint(const NodeId& roleId, EndpointType endpoint) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  for (const auto& existing : role->endpoints)
  {
    if (existing == endpoint)
    {
      return false;
    }
  }
  role->endpoints.push_back(std::move(endpoint));
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::remove_endpoint(const NodeId& roleId, const EndpointType& endpoint) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  auto it = std::find(role->endpoints.begin(), role->endpoints.end(), endpoint);
  if (it == role->endpoints.end())
  {
    return false;
  }
  role->endpoints.erase(it);
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::set_applications_exclude(const NodeId& roleId, bool exclude) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  if (role->applicationsExclude == exclude)
  {
    return true;  // no-op write - still a successful Write per spec
  }
  role->applicationsExclude = exclude;
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

bool RoleConfiguration::set_endpoints_exclude(const NodeId& roleId, bool exclude) noexcept
{
  const std::unique_lock<std::shared_mutex> lock(mMutex);
  auto* role = find_role_locked(mRoles, roleId);
  if (!role)
  {
    return false;
  }
  if (role->endpointsExclude == exclude)
  {
    return true;
  }
  role->endpointsExclude = exclude;
  mEpoch.fetch_add(1, std::memory_order_acq_rel);
  return true;
}

}  // namespace ua::server
