// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_audit_event_emitter.h"

#include "ua_credential_redaction.h"

#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_audit_activate_session_event_payload.h"
#include "ua_audit_certificate_data_mismatch_event_payload.h"
#include "ua_audit_certificate_event_payload.h"
#include "ua_audit_certificate_expired_event_payload.h"
#include "ua_audit_certificate_invalid_event_payload.h"
#include "ua_audit_certificate_mismatch_event_payload.h"
#include "ua_audit_certificate_revoked_event_payload.h"
#include "ua_audit_certificate_untrusted_event_payload.h"
#include "ua_audit_channel_event_payload.h"
#include "ua_audit_create_session_event_payload.h"
#include "ua_audit_open_secure_channel_event_payload.h"
#include "ua_audit_session_event_payload.h"
#include "ua_audit_url_mismatch_event_payload.h"
#include "ua_date_time.h"
#include "ua_exceptions.h"
#include "ua_issued_identity_token.h"
#include "ua_message_security_mode.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_certificate.h"

#include "fmt/format.h"

#include <cstring>
#include <random>
#include <string_view>

namespace ua::server
{

namespace
{

const NodeId serverObjectId{ObjectId::Server};

/// Pending certificate EventIds kept for the Service audit event to name. A peer whose failed Service
/// never raises a Service audit event leaves an entry behind; the map is cleared when it reaches this
/// size, so a flood of refused peers costs bounded memory (O(1) amortised per event).
constexpr std::size_t maxPendingCertificateEvents = 1024;

std::uint64_t random_event_id_salt()
{
  std::random_device device;
  return (static_cast<std::uint64_t>(device()) << 32U) ^ static_cast<std::uint64_t>(device());
}

const std::string* find_error_context(const std::shared_ptr<const ErrorDetail>& detail, const ContextKey& key)
{
  for (const ErrorDetail* layer = detail.get(); layer != nullptr; layer = layer->cause.get())
  {
    for (const auto& fact : layer->context)
    {
      if (fact.key == key.value())
        return &fact.value;
    }
  }
  return nullptr;
}

std::string_view certificate_rejection_message(const StatusCode& reason)
{
  const auto status = reason.as_status();
  const auto* cryptoError = find_error_context(reason.shared_detail(), ContextKeys::cryptoError);
  if (status == Status::BadCertificateTimeInvalid || status == Status::BadCertificateIssuerTimeInvalid)
  {
    const bool issuer = status == Status::BadCertificateIssuerTimeInvalid;
    if (cryptoError != nullptr && (cryptoError->find("not yet valid") != std::string::npos ||
                                    cryptoError->find("notBefore") != std::string::npos))
      return issuer ? "Issuer certificate validity period has not begun"
                    : "Certificate validity period has not begun";
    if (cryptoError != nullptr && (cryptoError->find("has expired") != std::string::npos ||
                                    cryptoError->find("notAfter") != std::string::npos))
      return issuer ? "Issuer certificate validity period has ended"
                    : "Certificate validity period has ended";
  }

  switch (status)
  {
  case Status::BadCertificateTimeInvalid:
    return "Certificate validity period does not include the current time";
  case Status::BadCertificateIssuerTimeInvalid:
    return "Issuer certificate validity period does not include the current time";
  case Status::BadCertificateInvalid:
    return "Certificate is malformed or invalid";
  case Status::BadCertificateChainIncomplete:
    return "Certificate chain is incomplete";
  case Status::BadCertificateUntrusted:
    return "Certificate is not trusted";
  case Status::BadCertificateUseNotAllowed:
    return "Certificate use is not allowed";
  case Status::BadCertificateIssuerUseNotAllowed:
    return "Issuer certificate use is not allowed";
  case Status::BadCertificatePolicyCheckFailed:
    return "Certificate does not meet the SecurityPolicy requirements";
  case Status::BadCertificateRevocationUnknown:
    return "Certificate revocation status is unknown";
  case Status::BadCertificateIssuerRevocationUnknown:
    return "Issuer certificate revocation status is unknown";
  case Status::BadCertificateRevoked:
    return "Certificate has been revoked";
  case Status::BadCertificateIssuerRevoked:
    return "Issuer certificate has been revoked";
  case Status::BadCertificateHostNameInvalid:
    return "Certificate host name does not match";
  case Status::BadCertificateUriInvalid:
    return "Certificate application URI does not match";
  default:
    return "Certificate rejected";
  }
}

/// Fill the common AuditEventPayload base fields.
void fill_audit_base(
  AuditEventPayload& event, const std::string& serverId, bool success, const std::string& auditEntryId = {})
{
  event.sourceNode = serverObjectId;
  event.actionTimeStamp = Variant{DateTime::now()};
  event.status = success;
  event.serverId = serverId;
  event.clientAuditEntryId = auditEntryId;
}

}  // namespace

AuditEventEmitter::AuditEventEmitter(std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger)
  : mEventSink(std::move(eventSink)), mServerId(std::move(serverId)), mLogger(std::move(logger)),
    mEventIdSalt(random_event_id_salt())
{}

std::string AuditEventEmitter::take_certificate_event_reference(const std::string& remoteAddress)
{
  ByteString eventId;
  {
    const std::lock_guard lock{mPendingMutex};
    const auto found = mPendingCertificateEvents.find(remoteAddress);
    if (found == mPendingCertificateEvents.end())
      return {};
    eventId = std::move(found->second);
    mPendingCertificateEvents.erase(found);
  }
  // OPC 10000-4 section 6.1.3: the Service audit event's Message names the EventId of the certificate
  // audit event raised for the same invocation; written as hexadecimal octets.
  std::string text{" (certificate audit EventId "};
  for (const auto octet : eventId)
    text += fmt::format("{:02x}", static_cast<unsigned>(octet));
  text += ")";
  return text;
}

void AuditEventEmitter::emit_audit_event(BaseEvent& event) noexcept
{
  try
  {
    auto sink = mEventSink.lock();
    if (!sink)
    {
      throw UaException{Status::BadShutdown,
        ErrorDetail::build("AuditEventSinkUnavailable",
          "Audit event sink is unavailable",
          "AuditEventEmitter::emit_audit_event")};
    }
    sink->emit(event);
  }
  catch (...)
  {
    async::detail::report_guarded_exception(mLogger, "AuditEventEmitter::emit_audit_event");
  }
}

// --- Secure Channel ---

void AuditEventEmitter::on_secure_channel_opened(const SecureChannelEventInfo& info)
{
  // Part 4, 6.5.5: OpenSecureChannel (Issue) success -> AuditOpenSecureChannelEventType
  AuditOpenSecureChannelEventPayload event;
  fill_audit_base(event, mServerId, true, info.auditEntryId);
  event.sourceName = "SecureChannel/OpenSecureChannel";
  event.message =
    LocalizedText{"", "Secure channel opened" + take_certificate_event_reference(info.remoteAddress)};
  event.severity = 1;  // Low severity - successful operation

  event.secureChannelId = fmt::format("{}", info.secureChannelId);
  event.securityPolicyUri = info.securityPolicyUri;
  event.securityMode = Variant{utils::to_underlying(info.messageSecurityMode)};
  event.requestType = Variant{int32_t{0}};  // Issue = 0
  event.clientCertificate = info.clientCertificate;
  event.clientCertificateThumbprint = info.clientCertificateThumbprint;
  event.requestedLifetime = Variant{static_cast<double>(info.requestedLifetime)};

  emit_audit_event(event);
}

void AuditEventEmitter::on_secure_channel_closed(const SecureChannelEventInfo& info, StatusCode /*reason*/)
{
  // Part 4, 6.5.5: CloseSecureChannel -> AuditChannelEventType
  AuditChannelEventPayload event;
  fill_audit_base(event, mServerId, true, info.auditEntryId);
  event.sourceName = "SecureChannel/CloseSecureChannel";
  event.message = LocalizedText{"", "Secure channel closed"};
  event.severity = 1;

  event.secureChannelId = fmt::format("{}", info.secureChannelId);
  // Part 5, 6.4.5: ClientUserId = "System/CloseSecureChannel" if not available
  event.clientUserId = "System/CloseSecureChannel";

  emit_audit_event(event);
}

void AuditEventEmitter::on_secure_channel_renewed(const SecureChannelEventInfo& info)
{
  // Part 4, 6.5.5: Renew success is not required (only failure).
  // But we emit a channel event for observability - low severity, success.
  AuditChannelEventPayload event;
  fill_audit_base(event, mServerId, true, info.auditEntryId);
  event.sourceName = "SecureChannel/RenewSecureChannel";
  event.message = LocalizedText{"", "Secure channel renewed"};
  event.severity = 1;

  event.secureChannelId = fmt::format("{}", info.secureChannelId);

  emit_audit_event(event);
}

void AuditEventEmitter::on_secure_channel_open_failed(const SecureChannelEventInfo& info, StatusCode reason)
{
  // Part 4, 6.5.5: OPN validation failure -> AuditOpenSecureChannelEventType with status=false
  AuditOpenSecureChannelEventPayload event;
  fill_audit_base(event, mServerId, false, info.auditEntryId);
  event.sourceName = "SecureChannel/OpenSecureChannel";
  event.message =
    LocalizedText{"", "OpenSecureChannel failed" + take_certificate_event_reference(info.remoteAddress)};
  event.severity = 800;  // High severity - security event

  event.secureChannelId = fmt::format("{}", info.secureChannelId);
  event.securityPolicyUri = info.securityPolicyUri;
  event.securityMode = Variant{utils::to_underlying(info.messageSecurityMode)};
  event.requestType = Variant{int32_t{0}};  // Issue = 0
  event.statusCodeId = reason;

  emit_audit_event(event);
}

void AuditEventEmitter::on_secure_channel_renew_failed(const SecureChannelEventInfo& info, StatusCode reason)
{
  // Part 4, 6.5.5: Renew validation failure -> AuditChannelEventType with status=false
  AuditChannelEventPayload event;
  fill_audit_base(event, mServerId, false, info.auditEntryId);
  event.sourceName = "SecureChannel/RenewSecureChannel";
  event.message = LocalizedText{"", "Secure channel renew failed"};
  event.severity = 800;  // High severity - security event

  event.secureChannelId = fmt::format("{}", info.secureChannelId);
  event.statusCodeId = reason;

  emit_audit_event(event);
}

// --- Session ---

void AuditEventEmitter::on_session_created(const SessionEventInfo& info)
{
  // Part 4, 6.5.6: CreateSession -> AuditCreateSessionEventType
  const auto fillCreated = [&](AuditCreateSessionEventPayload& event)
  {
    fill_audit_base(event, mServerId, true, info.auditEntryId);
    event.sourceName = "Session/CreateSession";
    event.message = LocalizedText{"", fmt::format("Session '{}' created", info.sessionName)};
    event.severity = 1;
    event.sessionId = info.sessionId;
    event.secureChannelId = fmt::format("{}", info.secureChannelId);
    event.clientCertificate = info.clientCertificate;
    event.clientCertificateThumbprint = info.clientCertificateThumbprint;
    if (info.revisedSessionTimeout > 0.0)
      event.revisedSessionTimeout = Variant{info.revisedSessionTimeout};
  };

  // Part 4 section 5.6.2.2 makes this Event independent of whether CreateSession is accepted. A
  // successful mismatch therefore emits the subtype in addition to the ordinary success audit.
  if (info.endpointUrlMismatch && !info.endpointUrl.empty())
  {
    AuditUrlMismatchEventPayload mismatch;
    fillCreated(mismatch);
    mismatch.endpointUrl = info.endpointUrl;
    emit_audit_event(mismatch);
  }

  AuditCreateSessionEventPayload event;
  fillCreated(event);
  emit_audit_event(event);
}

void AuditEventEmitter::on_session_create_failed(const SessionEventInfo& info, StatusCode reason)
{
  const std::string certificateReference = take_certificate_event_reference(info.remoteAddress);
  const auto fillFailure = [&](AuditCreateSessionEventPayload& event)
  {
    fill_audit_base(event, mServerId, false, info.auditEntryId);
    event.sourceName = "Session/CreateSession";
    const auto detail = reason.shared_detail();
    event.message = LocalizedText{"",
      (detail && !detail->summary.empty()
          ? fmt::format("CreateSession failed: {}", detail->summary)
          : fmt::format("CreateSession failed with StatusCode 0x{:08x}", reason.as_uint32())) +
        certificateReference};
    event.severity = 800;
    event.sessionId = info.sessionId;
    event.secureChannelId = fmt::format("{}", info.secureChannelId);
    event.clientCertificate = info.clientCertificate;
    event.clientCertificateThumbprint = info.clientCertificateThumbprint;
    if (info.revisedSessionTimeout > 0.0)
      event.revisedSessionTimeout = Variant{info.revisedSessionTimeout};
  };

  if (reason.as_status() == Status::BadTcpEndpointUrlInvalid && !info.endpointUrl.empty())
  {
    AuditUrlMismatchEventPayload event;
    fillFailure(event);
    event.endpointUrl = info.endpointUrl;
    emit_audit_event(event);
    return;
  }

  AuditCreateSessionEventPayload event;
  fillFailure(event);
  emit_audit_event(event);
}

void AuditEventEmitter::on_session_activated(const SessionEventInfo& info)
{
  // Part 4, 6.5.6: ActivateSession -> AuditActivateSessionEventType
  AuditActivateSessionEventPayload event;
  fill_audit_base(event, mServerId, true, info.auditEntryId);
  event.sourceName = "Session/ActivateSession";
  event.message = LocalizedText{"",
    fmt::format("Session '{}' activated", info.sessionName) +
      take_certificate_event_reference(info.remoteAddress)};
  event.severity = 1;
  event.clientUserId = info.clientUserId;

  event.sessionId = info.sessionId;
  event.secureChannelId = fmt::format("{}", info.secureChannelId);
  if (info.userIdentityToken)
    event.userIdentityToken = Variant{redact_credentials(*info.userIdentityToken)};

  emit_audit_event(event);
}

void AuditEventEmitter::on_session_closed(const SessionEventInfo& info, StatusCode /*reason*/)
{
  // Part 4, 6.5.6: CloseSession -> AuditSessionEventType
  // SourceName = "Session/CloseSession"
  AuditSessionEventPayload event;
  fill_audit_base(event, mServerId, true, info.auditEntryId);
  event.sourceName = "Session/CloseSession";
  event.message = LocalizedText{"", fmt::format("Session '{}' closed", info.sessionName)};
  event.severity = 1;
  event.clientUserId = info.clientUserId;

  event.sessionId = info.sessionId;

  emit_audit_event(event);
}

void AuditEventEmitter::on_session_timed_out(const SessionEventInfo& info)
{
  // Part 4, 6.5.6: Session timeout -> AuditSessionEventType
  // SourceName = "Session/Timeout"
  AuditSessionEventPayload event;
  fill_audit_base(event, mServerId, true);
  event.sourceName = "Session/Timeout";
  event.message = LocalizedText{"", fmt::format("Session '{}' timed out", info.sessionName)};
  event.severity = 500;  // Medium severity - unexpected termination
  event.clientUserId = info.clientUserId;

  event.sessionId = info.sessionId;

  emit_audit_event(event);
}

// --- Security ---

std::unique_ptr<AuditCertificateEventPayload> AuditEventEmitter::make_certificate_event(
  const CertificateEventInfo& info, bool suppressed)
{
  const StatusCode& reason = info.status;
  // OPC 10000-4 Table 106 (audit column), one event type per validation step.
  std::unique_ptr<AuditCertificateEventPayload> event;
  switch (reason.as_status())
  {
  case Status::BadCertificateTimeInvalid:
  case Status::BadCertificateIssuerTimeInvalid:
    event = std::make_unique<AuditCertificateExpiredEventPayload>();
    break;
  case Status::BadCertificateUntrusted:
    event = std::make_unique<AuditCertificateUntrustedEventPayload>();
    break;
  case Status::BadCertificateUseNotAllowed:
  case Status::BadCertificateIssuerUseNotAllowed:
    event = std::make_unique<AuditCertificateMismatchEventPayload>();
    break;
  case Status::BadCertificateRevoked:
  case Status::BadCertificateIssuerRevoked:
  case Status::BadCertificateRevocationUnknown:
  case Status::BadCertificateIssuerRevocationUnknown:
    event = std::make_unique<AuditCertificateRevokedEventPayload>();
    break;
  case Status::BadCertificateInvalid:
  case Status::BadCertificateChainIncomplete:
  case Status::BadCertificatePolicyCheckFailed:
  case Status::BadSecurityChecksFailed:
    event = std::make_unique<AuditCertificateInvalidEventPayload>();
    break;
  case Status::BadCertificateHostNameInvalid:
  case Status::BadCertificateUriInvalid:
  {
    // OPC 10000-5 section 6.4.13: the host name or URI that did not match.
    auto mismatch = std::make_unique<AuditCertificateDataMismatchEventPayload>();
    if (info.invalidHostname)
      mismatch->invalidHostname = *info.invalidHostname;
    if (info.invalidUri)
      mismatch->invalidUri = *info.invalidUri;
    event = std::move(mismatch);
    break;
  }
  default:
    // A status outside Table 106: the generic certificate event.
    event = std::make_unique<AuditCertificateEventPayload>();
    break;
  }

  // A suppressed error was accepted (the action succeeded); a rejection refused it.
  fill_audit_base(*event, mServerId, suppressed);
  // OPC 10000-5 section 6.4.12 fixes the SourceName for AuditCertificateEventType at
  // "Security/Certificate", and section 6.4.13-section 6.4.18 repeat it verbatim for every subtype -- so
  // one constant governs the family, and it is not the Service that happened to present the certificate.
  // Naming OpenSecureChannel here put the certificate record outside the SourceName filter a compliant
  // Client subscribes with, and merged it with the OPN audit, which is a separate Event.
  event->sourceName = "Security/Certificate";
  const std::string_view text = certificate_rejection_message(reason);
  event->message = LocalizedText{"",
    suppressed ? fmt::format("Certificate error suppressed by the validation options: {}", text)
               : std::string{text}};
  event->severity = suppressed ? 500 : 800;
  event->statusCodeId = reason;
  // OPC 10000-5 section 6.4.12: Certificate is Mandatory - the certificate that caused the event.
  if (info.certificate)
    event->certificate = info.certificate->der_encoding();

  // The EventId is stamped here (the EventBus keeps a non-empty one) so the Service audit event of the
  // same invocation can name it.
  const std::uint64_t parts[2]{mEventIdSalt, mNextEventId.fetch_add(1, std::memory_order_relaxed)};
  event->eventId.resize(sizeof(parts));
  std::memcpy(event->eventId.data(), parts, sizeof(parts));
  {
    const std::lock_guard lock{mPendingMutex};
    if (mPendingCertificateEvents.size() >= maxPendingCertificateEvents)
      mPendingCertificateEvents.clear();
    mPendingCertificateEvents.insert_or_assign(info.remoteAddress, event->eventId);
  }
  return event;
}

void AuditEventEmitter::on_certificate_rejected(const CertificateEventInfo& info)
{
  // Part 4, 6.5.5 and Table 106: certificate validation error -> the step's event subtype.
  const auto payload = make_certificate_event(info, false);
  auto& event = *payload;
  emit_audit_event(event);
}

void AuditEventEmitter::on_certificate_error_suppressed(const CertificateEventInfo& info)
{
  // Part 4 section 6.1.3: a suppressed error is "always reported via auditing" - the same Table 106 type.
  const auto payload = make_certificate_event(info, true);
  auto& event = *payload;
  emit_audit_event(event);
}

void AuditEventEmitter::on_authentication_failed(const SessionEventInfo& info, StatusCode reason)
{
  // Part 4, 6.5.6: Authentication failure -> AuditSessionEventType with status=false
  AuditSessionEventPayload event;
  fill_audit_base(event, mServerId, false, info.auditEntryId);
  event.sourceName = "Session/ActivateSession";
  event.message =
    LocalizedText{"", "Authentication failed" + take_certificate_event_reference(info.remoteAddress)};
  event.severity = 800;  // High severity - security event
  event.clientUserId = info.clientUserId;

  event.sessionId = info.sessionId;
  event.statusCodeId = reason;

  emit_audit_event(event);
}

}  // namespace ua::server
