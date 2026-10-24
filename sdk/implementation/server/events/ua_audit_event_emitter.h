// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AUDIT_EVENT_EMITTER_H
#define UA_AUDIT_EVENT_EMITTER_H

#include "ua_audit_certificate_event_payload.h"
#include "ua_byte_string.h"
#include "ua_logger.h"
#include "ua_sinks.h"
#include "ua_server_observer.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace ua::server
{

/// Translates ServerObserver lifecycle callbacks into typed OPC UA audit events
/// and emits them via the EventSink (EventBus).
///
/// Created only when auditing is enabled (ServerConfig.auditingEnabled).
/// Registered as an internal ServerObserver alongside any user-set observer.
///
/// Holds the EventSink via weak_ptr - observers handed out by the server (e.g.
/// to SecureChannel destructors) may outlive the EventSink during teardown.
/// Missing sinks and sink exceptions are contained and reported through the
/// ErrorDetail-aware logger; the emitter does not extend the sink's lifetime.
class AuditEventEmitter final : public ServerObserver
{
public:
  /// @param eventSink The event sink to emit audit events through. Stored as
  ///   weak_ptr; missing-sink and emission failures are logged and contained.
  /// @param serverId The ServerUri used as the ServerId audit field.
  /// @param logger ErrorDetail-aware diagnostic destination for emission failures.
  AuditEventEmitter(std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger = {});

  // Secure channel lifecycle
  void on_secure_channel_opened(const SecureChannelEventInfo& info) override;
  void on_secure_channel_closed(const SecureChannelEventInfo& info, StatusCode reason) override;
  void on_secure_channel_renewed(const SecureChannelEventInfo& info) override;
  void on_secure_channel_open_failed(const SecureChannelEventInfo& info, StatusCode reason) override;
  void on_secure_channel_renew_failed(const SecureChannelEventInfo& info, StatusCode reason) override;

  // Session lifecycle
  void on_session_created(const SessionEventInfo& info) override;
  void on_session_create_failed(const SessionEventInfo& info, StatusCode reason) override;
  void on_session_activated(const SessionEventInfo& info) override;
  void on_session_closed(const SessionEventInfo& info, StatusCode reason) override;
  void on_session_timed_out(const SessionEventInfo& info) override;

  // Security
  void on_certificate_rejected(const CertificateEventInfo& info) override;
  void on_certificate_error_suppressed(const CertificateEventInfo& info) override;
  void on_authentication_failed(const SessionEventInfo& info, StatusCode reason) override;

private:
  void emit_audit_event(BaseEvent& event) noexcept;

  /// Builds the Table 106 certificate audit event for @p info (OPC 10000-4 Table 106, OPC 10000-5
  /// section 6.4.12-6.4.18), stamps its EventId and records that id against the peer address so the
  /// Service audit event of the same invocation can name it (OPC 10000-4 section 6.1.3).
  [[nodiscard]] std::unique_ptr<AuditCertificateEventPayload> make_certificate_event(
    const CertificateEventInfo& info, bool suppressed);

  /// The " (certificate audit EventId <hex>)" suffix for the Service audit event of @p remoteAddress,
  /// consuming the recorded id; empty when no certificate event was raised for that peer.
  [[nodiscard]] std::string take_certificate_event_reference(const std::string& remoteAddress);

  std::weak_ptr<EventSink> mEventSink;
  std::string mServerId;
  Logger mLogger;
  /// EventId = mEventIdSalt (8 bytes, random per emitter) || mNextEventId (8 bytes). 16 bytes, so it
  /// cannot equal an EventBus-stamped id (8 bytes).
  std::uint64_t mEventIdSalt;
  std::atomic<std::uint64_t> mNextEventId{1};
  /// Peer address -> EventId of the last certificate audit event raised for it and not yet named by a
  /// Service audit event. Bounded by maxPendingCertificateEvents (cleared when full).
  std::mutex mPendingMutex;
  std::unordered_map<std::string, ByteString> mPendingCertificateEvents;
};

}  // namespace ua::server

#endif  // !UA_AUDIT_EVENT_EMITTER_H
