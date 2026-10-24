// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <cstddef>
#include <regex>

#include "stub_x509_certificate.h"
#include "stubs.h"
#include "test_utilities.h"

#include "ua_access_level_type.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_address_space.h"
#include "ua_alarm_condition_logic.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_attribute_service_set.h"
#include "ua_audit_activate_session_event_payload.h"
#include "ua_audit_history_update_event_payload.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_audit_certificate_data_mismatch_event_payload.h"
#include "ua_audit_certificate_event_payload.h"
#include "ua_audit_certificate_expired_event_payload.h"
#include "ua_audit_certificate_invalid_event_payload.h"
#include "ua_audit_certificate_mismatch_event_payload.h"
#include "ua_audit_certificate_revoked_event_payload.h"
#include "ua_audit_certificate_untrusted_event_payload.h"
#include "ua_audit_channel_event_payload.h"
#include "ua_audit_create_session_event_payload.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_event_emitter.h"
#include "ua_audit_node_management_event_payload.h"
#include "ua_audit_update_event_payload.h"
#include "ua_audit_open_secure_channel_event_payload.h"
#include "ua_audit_session_event_payload.h"
#include "ua_audit_url_mismatch_event_payload.h"
#include "ua_audit_update_method_event_payload.h"
#include "ua_base_event.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_codec_namespace_context.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_condition_state_snapshot.h"
#include "ua_create_session_request.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_type_registration.h"
// ua_default_namespace.h only forward-declares BaseNode, so a TU that instantiates
// Namespace::find_node<Node>() cannot see that BaseNode derives from Node and the shared_ptr conversion
// in its body fails. The definition has to be visible here.
#include "ua_default_base_node.h"
#include "ua_default_namespace.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_event_notifier_type.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_namespace_history_delegate.h"
#include "ua_issued_identity_token.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_service.h"
#include "ua_method_service_set.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_logger.h"
#include "ua_log_sink.h"
#include "ua_namespace_array.h"
#include "ua_namespace_delegates.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_management_service.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_perform_update_type.h"
#include "ua_permission_type.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_security_policy.h"
#include "ua_server.h"
#include "ua_server_observer.h"
#include "ua_service_fault.h"
#include "ua_session_security.h"
#include "ua_structure_factory.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_subscriptions_pipeline.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_to_string.h"
#include "ua_update_data_details.h"
#include "ua_user_name_identity_token.h"
#include "ua_array.h"
#include "ua_datatype_id.h"
#include "ua_value_rank.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include "security/ua_server_authentication.h"
#include "ua_server_components.h"

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::server;

namespace
{

struct alignas(std::max_align_t) SessionRegistryOwnerToken
{};

std::shared_ptr<Session> make_session_registry_placeholder()
{
  auto owner = std::make_shared<SessionRegistryOwnerToken>();
  auto* identity = reinterpret_cast<Session*>(owner.get());
  return std::shared_ptr<Session>{std::move(owner), identity};
}

const NodeId serverObjectId{ObjectId::Server};
const std::string testServerId = "urn:test:server";

StatusCode certificate_time_status(std::string cryptoError)
{
  std::shared_ptr<const ErrorDetail> detail = ErrorDetail::build(
    "CertificateTimeInvalid", "Certificate chain validation failed: time invalid", "CertificateValidation")
                                                .context(ContextKeys::cryptoError, std::move(cryptoError));
  return StatusCode{Status::BadCertificateTimeInvalid, std::move(detail)};
}

/// Collects emitted events for inspection.
///
/// THREAD-SAFE, and it has to be. An audit event is emitted wherever the work that raised it
/// happened: a Call audits on the pool thread running the method, a session activation audits on the
/// session's strand, and the test thread is meanwhile waiting on a condition variable and then
/// reading what arrived. Two of those can push into the vector at once.
///
/// Without the lock that is a data race on a `std::vector`, and its symptom is not a failed
/// assertion - it is a corrupted heap, surfacing at whatever allocates next. That is what
/// `malloc(): unaligned tcache chunk detected`, `corrupted double-linked list` and `malloc():
/// unsorted double linked list corrupted` were: all three were observed from this file, and they
/// killed whole test shards elsewhere in the suite because heap corruption does not stay where it is
/// made. Reproduced on demand with
/// `MALLOC_CHECK_=3 MALLOC_PERTURB_=165 ./tests --gtest_filter='*Audit*' --gtest_repeat=5`.
///
/// This is the same defect, in the same area, that `tests/helpers` hit before: a fake EventSink that
/// needed thread-safety because a static pool cannot be drained mid-suite.
class EventCollector
{
public:
  void on_event(const BaseEvent& event)
  {
    // Cloned OUTSIDE the lock: cloning allocates and runs a dynamic_cast ladder, and the lock only
    // has to cover the vector.
    auto cloned = clone(event);
    const std::lock_guard lock{mMutex};
    mEvents.push_back(std::move(cloned));
  }

  size_t count() const
  {
    const std::lock_guard lock{mMutex};
    return mEvents.size();
  }

  const BaseEvent& at(size_t index) const
  {
    const std::lock_guard lock{mMutex};
    return *mEvents.at(index);
  }

  template<typename T>
  const T& get(size_t index) const
  {
    const std::lock_guard lock{mMutex};
    auto* ptr = dynamic_cast<const T*>(mEvents.at(index).get());
    if (!ptr)
      throw std::runtime_error("Event at index is not the expected type");
    return *ptr;
  }

  void clear()
  {
    const std::lock_guard lock{mMutex};
    mEvents.clear();
  }

private:
  static std::unique_ptr<BaseEvent> clone(const BaseEvent& event)
  {
    // Try each concrete type in order of specificity
    if (auto* e = dynamic_cast<const AuditOpenSecureChannelEventPayload*>(&event))
      return std::make_unique<AuditOpenSecureChannelEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditUrlMismatchEventPayload*>(&event))
      return std::make_unique<AuditUrlMismatchEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCreateSessionEventPayload*>(&event))
      return std::make_unique<AuditCreateSessionEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditActivateSessionEventPayload*>(&event))
      return std::make_unique<AuditActivateSessionEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateExpiredEventPayload*>(&event))
      return std::make_unique<AuditCertificateExpiredEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateUntrustedEventPayload*>(&event))
      return std::make_unique<AuditCertificateUntrustedEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateInvalidEventPayload*>(&event))
      return std::make_unique<AuditCertificateInvalidEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateRevokedEventPayload*>(&event))
      return std::make_unique<AuditCertificateRevokedEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateDataMismatchEventPayload*>(&event))
      return std::make_unique<AuditCertificateDataMismatchEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateMismatchEventPayload*>(&event))
      return std::make_unique<AuditCertificateMismatchEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditCertificateEventPayload*>(&event))
      return std::make_unique<AuditCertificateEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditChannelEventPayload*>(&event))
      return std::make_unique<AuditChannelEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditSessionEventPayload*>(&event))
      return std::make_unique<AuditSessionEventPayload>(*e);
    if (auto* e = dynamic_cast<const AuditEventPayload*>(&event))
      return std::make_unique<AuditEventPayload>(*e);
    return std::make_unique<BaseEvent>(event);
  }

  mutable std::mutex mMutex;
  std::vector<std::unique_ptr<BaseEvent>> mEvents;
};

/// Minimal EventSink that just calls through to a collector.
class TestEventSink : public EventSink
{
public:
  explicit TestEventSink(EventCollector& collector) : mCollector(collector)
  {}

  void emit(BaseEvent& event) override
  {
    mCollector.on_event(event);
  }

private:
  EventCollector& mCollector;
};

class ThrowingEventSink final : public EventSink
{
public:
  explicit ThrowingEventSink(StatusCode failure) : mFailure(std::move(failure))
  {}

  void emit(BaseEvent&) override
  {
    ++mCalls;
    throw UaException{mFailure};
  }

  size_t calls() const noexcept
  {
    return mCalls;
  }

private:
  StatusCode mFailure;
  size_t mCalls{0};
};

struct RecordedLogEntry
{
  LogLevel level;
  std::string category;
  std::string message;
  std::map<std::string, std::string> fields;
};

class RecordingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    RecordedLogEntry copy{entry.level, std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      if (const auto* value = std::get_if<std::string_view>(&field.value))
        copy.fields.emplace(field.key, *value);
    }
    mEntries.push_back(std::move(copy));
  }

  const std::vector<RecordedLogEntry>& entries() const noexcept
  {
    return mEntries;
  }

private:
  std::vector<RecordedLogEntry> mEntries;
};

SecureChannelEventInfo make_channel_info(
  uint32_t channelId = 1, std::string policyUri = "http://opcfoundation.org/UA/SecurityPolicy#None")
{
  SecureChannelEventInfo info;
  info.secureChannelId = channelId;
  info.securityPolicyUri = std::move(policyUri);
  info.messageSecurityMode = MessageSecurityMode::None;
  info.remoteAddress = "192.168.1.100:4840";
  return info;
}

SessionEventInfo make_session_info(std::string name = "TestSession", uint32_t channelId = 1)
{
  SessionEventInfo info;
  info.sessionId = NodeId{1, 100u};
  info.sessionName = std::move(name);
  info.secureChannelId = channelId;
  info.remoteAddress = "192.168.1.100:4840";
  return info;
}

/// The certificate a peer presented, as the server's certificate paths hand it to the observer (owner
/// decision 27: the hook carries the certificate, Part 5 6.4.12 makes the Certificate property Mandatory).
std::shared_ptr<const X509Certificate> presented_certificate()
{
  static const std::shared_ptr<const X509Certificate> certificate =
    std::make_shared<ua::testing::StubX509Certificate>();
  return certificate;
}

/// The decision-27 form of a certificate rejection: the remote address, the presented certificate and the
/// Table 106 status; no host name or URI unless the caller sets them.
CertificateEventInfo certificate_event(std::string remoteAddress, StatusCode status)
{
  CertificateEventInfo info;
  info.remoteAddress = std::move(remoteAddress);
  info.certificate = presented_certificate();
  info.status = status;
  info.invalidHostname = std::nullopt;
  info.invalidUri = std::nullopt;
  return info;
}

class AuditEventEmitterTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mSink = std::make_shared<TestEventSink>(mCollector);
    mEmitter = std::make_unique<AuditEventEmitter>(mSink, testServerId);
  }

  EventCollector mCollector;
  std::shared_ptr<TestEventSink> mSink;
  std::unique_ptr<AuditEventEmitter> mEmitter;
};

}  // namespace

// --- SecureChannel audit events ---

// Covers SVR-AUDIT-013, SVR-AUDIT-024 (coverage-audit retag).
// @relation(SVR-EVT-AUD-003, SVR-EVT-AUD-004, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SecureChannelOpened_EmitsAuditOpenSecureChannelEvent)
{
  auto info = make_channel_info();
  mEmitter->on_secure_channel_opened(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditOpenSecureChannelEventPayload>(0);

  EXPECT_EQ(event.sourceNode, serverObjectId);
  EXPECT_EQ(event.sourceName, "SecureChannel/OpenSecureChannel");
  EXPECT_EQ(event.serverId, testServerId);
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.secureChannelId, "1");
  EXPECT_EQ(event.securityPolicyUri, info.securityPolicyUri);
  EXPECT_EQ(event.severity, 1);
}

// @relation(AC-SVR-DIAG-013-AUDIT-EMITTER-DETAIL, scope=function)
TEST_F(AuditEventEmitterTest, SinkFailureIsContainedAndLoggedWithItsRichCause)
{
  EXPECT_NO_THROW(mEmitter->on_secure_channel_opened(make_channel_info()));
  EXPECT_EQ(mCollector.count(), 1u);

  std::shared_ptr<const ErrorDetail> root =
    ErrorDetail::build("AuditSinkRoot", "Injected audit sink root failure", "ThrowingEventSink");
  std::shared_ptr<const ErrorDetail> outer =
    ErrorDetail::build("AuditSinkFailure", "Audit sink rejected event", "ThrowingEventSink")
      .cause(StatusCode{Status::BadCertificateUntrusted, root});
  const StatusCode injected{Status::BadInternalError, outer};

  auto logs = std::make_shared<RecordingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  Logger logger{logs, level, "audit"};
  auto throwingSink = std::make_shared<ThrowingEventSink>(injected);
  AuditEventEmitter throwingEmitter{throwingSink, testServerId, logger};

  EXPECT_NO_THROW(throwingEmitter.on_secure_channel_opened(make_channel_info()));
  EXPECT_EQ(throwingSink->calls(), 1u);
  ASSERT_EQ(logs->entries().size(), 1u);
  EXPECT_EQ(logs->entries()[0].level, LogLevel::Error);
  EXPECT_EQ(logs->entries()[0].category, "audit");
  EXPECT_EQ(logs->entries()[0].message, "AuditEventEmitter::emit_audit_event");
  EXPECT_EQ(logs->entries()[0].fields.at("status"), to_string(injected));
  EXPECT_EQ(logs->entries()[0].fields.at("error"), to_string(*outer));

  EventCollector collector;
  auto expiredSink = std::make_shared<TestEventSink>(collector);
  AuditEventEmitter expiredEmitter{expiredSink, testServerId, logger};
  expiredSink.reset();
  EXPECT_NO_THROW(expiredEmitter.on_secure_channel_opened(make_channel_info()));
  EXPECT_EQ(collector.count(), 0u);
  ASSERT_EQ(logs->entries().size(), 2u);
  EXPECT_EQ(logs->entries()[1].fields.at("status"), to_string(StatusCode{Status::BadShutdown}));
  const std::unique_ptr<ua::ErrorDetail> unavailable = ErrorDetail::build(
    "AuditEventSinkUnavailable", "Audit event sink is unavailable", "AuditEventEmitter::emit_audit_event");
  EXPECT_EQ(logs->entries()[1].fields.at("error"), to_string(*unavailable));
}

// Covers SVR-AUDIT-021 (coverage-audit retag).
// @relation(SVR-EVT-AUD-003, SVR-EVT-AUD-005, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SecureChannelClosed_EmitsAuditChannelEvent)
{
  auto info = make_channel_info(42);
  mEmitter->on_secure_channel_closed(info, StatusCode{Status::Good});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditChannelEventPayload>(0);

  EXPECT_EQ(event.sourceNode, serverObjectId);
  EXPECT_EQ(event.sourceName, "SecureChannel/CloseSecureChannel");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.secureChannelId, "42");
  EXPECT_EQ(event.clientUserId, "System/CloseSecureChannel");
}

TEST_F(AuditEventEmitterTest, SecureChannelRenewed_EmitsAuditChannelEvent)
{
  auto info = make_channel_info(7);
  mEmitter->on_secure_channel_renewed(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditChannelEventPayload>(0);

  EXPECT_EQ(event.sourceName, "SecureChannel/RenewSecureChannel");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.secureChannelId, "7");
}

// --- Session audit events ---

// Covers SVR-SESS-007, SVR-AUDIT-016 (coverage-audit retag).
// @relation(SVR-EVT-AUD-007, SVR-EVT-AUD-008, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SessionCreated_EmitsAuditCreateSessionEvent)
{
  auto info = make_session_info("MySession", 5);
  mEmitter->on_session_created(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCreateSessionEventPayload>(0);

  EXPECT_EQ(event.sourceNode, serverObjectId);
  EXPECT_EQ(event.sourceName, "Session/CreateSession");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.sessionId, info.sessionId);
  EXPECT_EQ(event.secureChannelId, "5");
  EXPECT_EQ(event.serverId, testServerId);
}

// @relation(AC-SVR-EVT-AUD-008-CREATESESSION-AUDIT, scope=function)
TEST_F(AuditEventEmitterTest, SessionCreateFailureEmitsCreateSessionAuditFromRichStatus)
{
  auto info = make_session_info("RefusedSession", 17);
  info.auditEntryId = "audit-17";
  shared_ptr<const ErrorDetail> detail =
    ErrorDetail::build("ClientNonceTooShort", "Client nonce shorter than the required minimum", "Session");

  mEmitter->on_session_create_failed(info, StatusCode{Status::BadNonceInvalid, detail});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCreateSessionEventPayload>(0);
  EXPECT_EQ(event.sourceNode, serverObjectId);
  EXPECT_EQ(event.sourceName, "Session/CreateSession");
  EXPECT_FALSE(event.status);
  EXPECT_EQ(event.sessionId, info.sessionId);
  EXPECT_EQ(event.secureChannelId, "17");
  EXPECT_EQ(event.clientAuditEntryId, "audit-17");
  const std::string message{event.message.text()};
  EXPECT_NE(message.find("Client nonce shorter"), std::string::npos);
}

// @relation(AC-SVR-EVT-AUD-008-CREATESESSION-AUDIT, scope=function)
TEST_F(AuditEventEmitterTest, EndpointUrlFailureEmitsUrlMismatchSubtype)
{
  auto info = make_session_info("UrlMismatch", 18);
  info.endpointUrl = "opc.tcp://wrong.example:4840";

  mEmitter->on_session_create_failed(info, StatusCode{Status::BadTcpEndpointUrlInvalid});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditUrlMismatchEventPayload>(0);
  EXPECT_FALSE(event.status);
  EXPECT_EQ(event.sourceName, "Session/CreateSession");
  EXPECT_EQ(event.endpointUrl, info.endpointUrl);
}

// Part 4 section 5.6.2.2 requires the AuditUrlMismatchEventType even when the Server accepts the
// endpointUrl and creates the Session. The ordinary CreateSession audit is an independent SHALL, so
// the successful mismatch produces both Events rather than replacing one with the other.
// @relation(AC-SVR-SESS-008-URLMISMATCH-EVENT, scope=function)
TEST_F(AuditEventEmitterTest, SuccessfulSessionWithUrlMismatchEmitsMismatchAndCreateEvents)
{
  auto info = make_session_info("SuccessfulUrlMismatch", 19);
  info.endpointUrl = "opc.tcp://not-declared.invalid:4840";
  info.endpointUrlMismatch = true;

  mEmitter->on_session_created(info);

  ASSERT_EQ(mCollector.count(), 2u);
  const auto& mismatch = mCollector.get<AuditUrlMismatchEventPayload>(0);
  EXPECT_TRUE(mismatch.status);
  EXPECT_EQ(mismatch.endpointUrl, info.endpointUrl);
  const auto& created = mCollector.get<AuditCreateSessionEventPayload>(1);
  EXPECT_TRUE(created.status);
  EXPECT_EQ(created.sessionId, info.sessionId);
}

// @relation(SVR-EVT-AUD-007, SVR-EVT-AUD-009, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SessionActivated_EmitsAuditActivateSessionEvent)
{
  auto info = make_session_info("MySession", 5);
  mEmitter->on_session_activated(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditActivateSessionEventPayload>(0);

  EXPECT_EQ(event.sourceName, "Session/ActivateSession");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.sessionId, info.sessionId);
  EXPECT_EQ(event.secureChannelId, "5");
}

// @relation(SVR-EVT-AUD-007, SVR-EVT-AUD-011, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SessionClosed_EmitsAuditSessionEvent)
{
  auto info = make_session_info("ClosedSession");
  mEmitter->on_session_closed(info, StatusCode{Status::Good});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);

  EXPECT_EQ(event.sourceName, "Session/CloseSession");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.sessionId, info.sessionId);
}

// @relation(SVR-EVT-AUD-011, scope=function)
TEST_F(AuditEventEmitterTest, SessionTimedOut_EmitsAuditSessionEvent)
{
  auto info = make_session_info("TimedOutSession");
  mEmitter->on_session_timed_out(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);

  EXPECT_EQ(event.sourceName, "Session/Timeout");
  EXPECT_TRUE(event.status);
  EXPECT_EQ(event.sessionId, info.sessionId);
  EXPECT_GE(event.severity, 500);  // Medium severity for timeout
}

// --- Security audit events ---

// @relation(AC-SVR-EVT-AUD-006-CERT-ERROR-DETAIL, SVR-EVT-AUD-013, scope=function)
TEST_F(AuditEventEmitterTest, CertificateRejected_EmitsAuditCertificateEvent)
{
  mEmitter->on_certificate_rejected(
    certificate_event("192.168.1.100:4840", StatusCode{Status::BadCertificateUntrusted}));

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCertificateEventPayload>(0);

  EXPECT_EQ(event.sourceNode, serverObjectId);
  // Part 5 section 6.4.12 fixes the certificate family's SourceName at "Security/Certificate", and
  // section 6.4.13-section 6.4.18 repeat it for every subtype. Naming the Service that presented the
  // certificate - what the emitter used to stamp, and what this assertion used to pin - puts the record
  // outside the SourceName filter a compliant Client subscribes with and merges it with the OPN audit, which
  // is a separate Event.
  EXPECT_EQ(event.sourceName, "Security/Certificate");
  EXPECT_FALSE(event.status);
  EXPECT_GE(event.severity, 800);
  ASSERT_TRUE(event.statusCodeId.has_value());
  EXPECT_EQ(*event.statusCodeId, StatusCode(Status::BadCertificateUntrusted));
}

// Covers SVR-IDENT-006 (coverage-audit retag).
// @relation(AC-SVR-EVT-AUD-007-SESSION-SERVICES-AUDIT, SVR-EVT-AUD-009, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, AuthenticationFailed_EmitsAuditSessionEvent)
{
  auto info = make_session_info("FailedAuth");
  mEmitter->on_authentication_failed(info, StatusCode{Status::BadIdentityTokenRejected});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);

  EXPECT_EQ(event.sourceName, "Session/ActivateSession");
  EXPECT_FALSE(event.status);
  EXPECT_GE(event.severity, 800);
  ASSERT_TRUE(event.statusCodeId.has_value());
  EXPECT_EQ(*event.statusCodeId, StatusCode(Status::BadIdentityTokenRejected));
}

// --- Common field checks ---

// Covers SVR-AUDIT-002 (coverage-audit retag).
// @relation(AC-SVR-AUDIT-002-MANDATORY-FIELDS, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, AllEvents_HaveServerIdSet)
{
  mEmitter->on_secure_channel_opened(make_channel_info());
  mEmitter->on_session_created(make_session_info());
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateInvalid}));

  for (size_t i = 0; i < mCollector.count(); ++i)
  {
    const auto& event = mCollector.get<AuditEventPayload>(i);
    EXPECT_EQ(event.serverId, testServerId) << "Event index " << i;
  }
}

// @relation(AC-SVR-AUDIT-002-MANDATORY-FIELDS, scope=function)
TEST_F(AuditEventEmitterTest, AllEvents_HaveActionTimeStampSet)
{
  mEmitter->on_secure_channel_opened(make_channel_info());

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditEventPayload>(0);
  EXPECT_FALSE(event.actionTimeStamp.empty());
}

// Covers SVR-AUDIT-012 (coverage-audit retag).
// @relation(SVR-AUDIT-002, scope=function)
TEST_F(AuditEventEmitterTest, AllEvents_HaveSourceNodeAsServerObject)
{
  mEmitter->on_secure_channel_opened(make_channel_info());
  mEmitter->on_session_created(make_session_info());
  mEmitter->on_session_closed(make_session_info(), StatusCode{Status::Good});

  for (size_t i = 0; i < mCollector.count(); ++i)
  {
    EXPECT_EQ(mCollector.at(i).sourceNode, serverObjectId) << "Event index " << i;
  }
}

// @relation(AC-SVR-AUDIT-003-AUDITENTRYID-PROPAGATED, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, AuditEntryId_PropagatedFromChannelInfo)
{
  auto info = make_channel_info();
  info.auditEntryId = "client-audit-123";
  mEmitter->on_secure_channel_opened(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditEventPayload>(0);
  EXPECT_EQ(event.clientAuditEntryId, "client-audit-123");
}

// @relation(AC-SVR-AUDIT-003-AUDITENTRYID-PROPAGATED, scope=function)
TEST_F(AuditEventEmitterTest, AuditEntryId_PropagatedFromSessionInfo)
{
  auto info = make_session_info();
  info.auditEntryId = "session-audit-456";
  mEmitter->on_session_created(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditEventPayload>(0);
  EXPECT_EQ(event.clientAuditEntryId, "session-audit-456");
}

// @relation(AC-SVR-AUDIT-003-AUDITENTRYID-PROPAGATED, scope=function)
TEST_F(AuditEventEmitterTest, AuditEntryId_EmptyWhenNotProvided)
{
  mEmitter->on_secure_channel_opened(make_channel_info());

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditEventPayload>(0);
  EXPECT_TRUE(event.clientAuditEntryId.empty());
}

// --- ClientUserId propagation (G4) ---

// @relation(SVR-AUDIT-004, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, SessionActivated_PropagatesClientUserId)
{
  auto info = make_session_info();
  info.clientUserId = "admin@example.com";
  mEmitter->on_session_activated(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditActivateSessionEventPayload>(0);
  EXPECT_EQ(event.clientUserId, "admin@example.com");
}

// @relation(SVR-AUDIT-004, scope=function)
TEST_F(AuditEventEmitterTest, SessionClosed_PropagatesClientUserId)
{
  auto info = make_session_info();
  info.clientUserId = "user1";
  mEmitter->on_session_closed(info, StatusCode{Status::Good});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);
  EXPECT_EQ(event.clientUserId, "user1");
}

// @relation(SVR-AUDIT-004, scope=function)
TEST_F(AuditEventEmitterTest, SessionTimedOut_PropagatesClientUserId)
{
  auto info = make_session_info();
  info.clientUserId = "timedout-user";
  mEmitter->on_session_timed_out(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);
  EXPECT_EQ(event.clientUserId, "timedout-user");
}

// @relation(SVR-AUDIT-004, scope=function)
TEST_F(AuditEventEmitterTest, SessionCreated_ClientUserIdEmpty)
{
  // Pre-authentication: no user identity known yet
  auto info = make_session_info();
  mEmitter->on_session_created(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCreateSessionEventPayload>(0);
  EXPECT_TRUE(event.clientUserId.empty());
}

// @relation(AC-SVR-AUDIT-004-CLIENTUSERID, scope=function)
TEST_F(AuditEventEmitterTest, AuthenticationFailed_PropagatesClientUserId)
{
  auto info = make_session_info();
  info.clientUserId = "rejected-user";
  mEmitter->on_authentication_failed(info, StatusCode{Status::BadIdentityTokenRejected});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditSessionEventPayload>(0);
  EXPECT_EQ(event.clientUserId, "rejected-user");
}

// @relation(AC-SVR-SECADMIN-005-VALIDATION-AUDIT-PER-STEP, scope=function)

// --- Certificate rejection subtypes (G6) ---

// Covers SVR-SECADMIN-005 (coverage-audit retag).
// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, CertificateTimeInvalid_EmitsExpiredSubtype)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateTimeInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateExpiredEventPayload>(0));
}

// @relation(SVR-AUDIT-007, scope=function)
TEST_F(AuditEventEmitterTest, CertificateIssuerTimeInvalid_EmitsExpiredSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateIssuerTimeInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateExpiredEventPayload>(0));
}

// @relation(AC-SVR-SECADMIN-005-VALIDATION-AUDIT-PER-STEP, scope=function)
// @relation(AC-SVR-SECADMIN-018-UNTRUSTED-AUDIT, scope=function)

// Covers SVR-SECADMIN-018 (coverage-audit retag).
// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, CertificateUntrusted_EmitsUntrustedSubtype)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateUntrusted}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateUntrustedEventPayload>(0));
}

// @relation(SVR-AUDIT-007, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, CertificateInvalid_EmitsInvalidSubtype)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateInvalidEventPayload>(0));
}

// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, scope=function)
TEST_F(AuditEventEmitterTest, CertificateChainIncomplete_EmitsInvalidSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateChainIncomplete}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateInvalidEventPayload>(0));
}

// @relation(AC-SVR-SECADMIN-005-VALIDATION-AUDIT-PER-STEP, scope=function)

// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, scope=function)
TEST_F(AuditEventEmitterTest, CertificateRevoked_EmitsRevokedSubtype)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateRevoked}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateRevokedEventPayload>(0));
}

// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, SVR-AUDIT-026, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, CertificateHostNameInvalid_EmitsDataMismatchSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateHostNameInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateDataMismatchEventPayload>(0));
}

// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, SVR-AUDIT-026, scope=function)
TEST_F(AuditEventEmitterTest, CertificateUriInvalid_EmitsDataMismatchSubtype)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateUriInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NO_THROW(mCollector.get<AuditCertificateDataMismatchEventPayload>(0));
}

// @relation(AC-SVR-AUDIT-007-CERT-SUBTYPE, scope=function)
TEST_F(AuditEventEmitterTest, CertificateUnknownStatus_EmitsGenericCertificateEvent)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadSecurityChecksFailed}));
  ASSERT_EQ(mCollector.count(), 1u);
  // Should be base AuditCertificateEventPayload, not a subtype
  const auto& event = mCollector.get<AuditCertificateEventPayload>(0);
  EXPECT_FALSE(event.status);
  EXPECT_GE(event.severity, 800);
}

// @relation(SVR-EVT-AUD-006, scope=function)
TEST_F(AuditEventEmitterTest, CertificateSubtype_StillHasCommonFields)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateRevoked}));
  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCertificateEventPayload>(0);  // polymorphic access
  // Part 5 section 6.4.12 fixes this at "Security/Certificate" for AuditCertificateEventType and repeats
  // it for every subtype (section 6.4.13-section 6.4.18). The assertion previously named the Service that
  // presented the certificate, which is what the emitter used to stamp; that put the record
  // outside the SourceName filter a compliant Client subscribes with.
  EXPECT_EQ(event.sourceName, "Security/Certificate");
  EXPECT_FALSE(event.status);
  EXPECT_EQ(event.serverId, testServerId);
  EXPECT_GE(event.severity, 800);
  ASSERT_TRUE(event.statusCodeId.has_value());
  EXPECT_EQ(*event.statusCodeId, StatusCode(Status::BadCertificateRevoked));
}

// --- Certificate audit content (completeness review C5; owner decision 27) ---

namespace
{

/// The EventId as hexadecimal text, lower and upper case, the two forms a message can carry it in.
std::pair<std::string, std::string> event_id_hex(const ByteString& eventId)
{
  static constexpr char lowerHexDigits[] = "0123456789abcdef";
  static constexpr char upperHexDigits[] = "0123456789ABCDEF";
  std::string lower;
  std::string upper;
  for (const auto octet : eventId)
  {
    const auto value = static_cast<unsigned>(octet);
    lower.push_back(lowerHexDigits[(value >> 4U) & 0xFU]);
    lower.push_back(lowerHexDigits[value & 0xFU]);
    upper.push_back(upperHexDigits[(value >> 4U) & 0xFU]);
    upper.push_back(upperHexDigits[value & 0xFU]);
  }
  return {lower, upper};
}

bool message_names_event_id(const BaseEvent& serviceEvent, const ByteString& eventId)
{
  const std::string text{static_cast<std::string_view>(serviceEvent.message.text())};
  const auto [lower, upper] = event_id_hex(eventId);
  return !lower.empty() && (text.find(lower) != std::string::npos || text.find(upper) != std::string::npos);
}

}  // namespace

// Part 5 6.4.12: the Certificate property of AuditCertificateEventType is Mandatory and is the certificate
// that caused the Event. Every subtype the emitter raises carries the presented certificate's DER.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, EveryCertificateAuditEventCarriesThePresentedCertificate)
{
  const Status reasons[]{Status::BadCertificateInvalid,
    Status::BadCertificateChainIncomplete,
    Status::BadCertificatePolicyCheckFailed,
    Status::BadCertificateUntrusted,
    Status::BadCertificateTimeInvalid,
    Status::BadCertificateIssuerTimeInvalid,
    Status::BadCertificateHostNameInvalid,
    Status::BadCertificateUriInvalid,
    Status::BadCertificateUseNotAllowed,
    Status::BadCertificateIssuerUseNotAllowed,
    Status::BadCertificateRevocationUnknown,
    Status::BadCertificateIssuerRevocationUnknown,
    Status::BadCertificateRevoked,
    Status::BadCertificateIssuerRevoked};
  for (const auto reason : reasons)
  {
    mCollector.clear();
    mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{reason}));
    ASSERT_EQ(mCollector.count(), 1u) << to_string(StatusCode{reason});
    const auto& event = mCollector.get<AuditCertificateEventPayload>(0);
    EXPECT_EQ(event.certificate, presented_certificate()->der_encoding())
      << to_string(StatusCode{reason}) << ": the Certificate property must be the presented certificate";
  }
}

// Table 106: the Certificate Usage step (UseNotAllowed, IssuerUseNotAllowed) is audited as
// AuditCertificateMismatchEventType (Part 5 6.4.18).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificateUseNotAllowed_EmitsMismatchSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateUseNotAllowed}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NE(dynamic_cast<const AuditCertificateMismatchEventPayload*>(&mCollector.at(0)), nullptr);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificateIssuerUseNotAllowed_EmitsMismatchSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateIssuerUseNotAllowed}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NE(dynamic_cast<const AuditCertificateMismatchEventPayload*>(&mCollector.at(0)), nullptr);
}

// Table 106: the Revocation Check step audits an issuer's revocation as AuditCertificateRevokedEventType.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificateIssuerRevoked_EmitsRevokedSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateIssuerRevoked}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NE(dynamic_cast<const AuditCertificateRevokedEventPayload*>(&mCollector.at(0)), nullptr);
}

// Table 106: the Security Policy Check step audits as AuditCertificateInvalidEventType.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificatePolicyCheckFailed_EmitsInvalidSubtype)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificatePolicyCheckFailed}));
  ASSERT_EQ(mCollector.count(), 1u);
  EXPECT_NE(dynamic_cast<const AuditCertificateInvalidEventPayload*>(&mCollector.at(0)), nullptr);
}

// Part 5 6.4.13: a host-name mismatch fills InvalidHostname with the host name that did not match, and leaves
// InvalidUri empty.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificateHostNameInvalid_SetsInvalidHostname)
{
  auto info = certificate_event("addr", StatusCode{Status::BadCertificateHostNameInvalid});
  info.invalidHostname = std::string{"other.example"};
  mEmitter->on_certificate_rejected(info);
  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCertificateDataMismatchEventPayload>(0);
  EXPECT_EQ(std::string{static_cast<std::string_view>(event.invalidHostname)}, "other.example");
  EXPECT_TRUE(std::string{static_cast<std::string_view>(event.invalidUri)}.empty());
}

// Part 5 6.4.13: a URI mismatch fills InvalidUri with the ApplicationUri that did not match.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, CertificateUriInvalid_SetsInvalidUri)
{
  auto info = certificate_event("addr", StatusCode{Status::BadCertificateUriInvalid});
  info.invalidUri = std::string{"urn:other:application"};
  mEmitter->on_certificate_rejected(info);
  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCertificateDataMismatchEventPayload>(0);
  EXPECT_EQ(std::string{static_cast<std::string_view>(event.invalidUri)}, "urn:other:application");
  EXPECT_TRUE(std::string{static_cast<std::string_view>(event.invalidHostname)}.empty());
}

// Decision 22.2 + 27: a suppressed error raises its Table 106 event, carrying the certificate, exactly as a
// rejection does.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-85-AUDIT-CERTIFICATE-CONTENT, scope=function)
TEST_F(AuditEventEmitterTest, SuppressedCertificateErrorCarriesThePresentedCertificate)
{
  mEmitter->on_certificate_error_suppressed(
    certificate_event("addr", StatusCode{Status::BadCertificateTimeInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditCertificateExpiredEventPayload>(0);
  EXPECT_EQ(event.certificate, presented_certificate()->der_encoding());
}

// Part 4 6.1.3: when a certificate fails validation the Service audit Event (AuditOpenSecureChannelEventType)
// carries in its Message the EventId of the AuditCertificateEventType raised for it. Control: a certificate
// event for ANOTHER peer is not named.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-86-AUDIT-SERVICE-EVENT-ID, scope=function)
TEST_F(AuditEventEmitterTest, OpenSecureChannelAuditMessageNamesTheCertificateAuditEventId)
{
  const auto channel = make_channel_info();
  mEmitter->on_certificate_rejected(
    certificate_event(channel.remoteAddress, StatusCode{Status::BadCertificateUntrusted}));
  mEmitter->on_secure_channel_open_failed(channel, StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_EQ(mCollector.count(), 2u);
  const auto certificateEventId = mCollector.get<AuditCertificateEventPayload>(0).eventId;
  const auto& service = mCollector.get<AuditOpenSecureChannelEventPayload>(1);
  EXPECT_TRUE(message_names_event_id(service, certificateEventId))
    << "message: " << std::string{static_cast<std::string_view>(service.message.text())};
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-86-AUDIT-SERVICE-EVENT-ID, scope=function)
TEST_F(AuditEventEmitterTest, OpenSecureChannelAuditMessageDoesNotNameAnotherPeersCertificateEvent)
{
  const auto channel = make_channel_info();
  mEmitter->on_certificate_rejected(
    certificate_event("10.9.9.9:4840", StatusCode{Status::BadCertificateUntrusted}));
  mEmitter->on_secure_channel_open_failed(channel, StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_EQ(mCollector.count(), 2u);
  const auto certificateEventId = mCollector.get<AuditCertificateEventPayload>(0).eventId;
  EXPECT_FALSE(
    message_names_event_id(mCollector.get<AuditOpenSecureChannelEventPayload>(1), certificateEventId));
}

// Part 4 6.1.3, ActivateSession: an X509 user token refused by validation raises the certificate event
// (decision 27 form) and the ActivateSession audit Event names its EventId.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-86-AUDIT-SERVICE-EVENT-ID, scope=function)
TEST_F(AuditEventEmitterTest, ActivateSessionAuditMessageNamesTheUserCertificateAuditEventId)
{
  const auto session = make_session_info();
  mEmitter->on_certificate_rejected(
    certificate_event(session.remoteAddress, StatusCode{Status::BadCertificateUntrusted}));
  mEmitter->on_authentication_failed(session, StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_EQ(mCollector.count(), 2u);
  const auto certificateEventId = mCollector.get<AuditCertificateEventPayload>(0).eventId;
  const auto& service = mCollector.get<AuditSessionEventPayload>(1);
  EXPECT_EQ(service.sourceName, "Session/ActivateSession");
  EXPECT_TRUE(message_names_event_id(service, certificateEventId))
    << "message: " << std::string{static_cast<std::string_view>(service.message.text())};
}

// --- OPN/Renew failure events (G1, G2) ---

// @relation(AC-SVR-EVT-AUD-003-CHANNEL-SERVICES-AUDIT, SVR-AUDIT-029, scope=function)
// @verifies AC-SVR-AUDIT-013-OPN-SOURCENAME
TEST_F(AuditEventEmitterTest, OpenSecureChannelFailed_EmitsAuditOpenSecureChannelEvent)
{
  auto info = make_channel_info();
  mEmitter->on_secure_channel_open_failed(info, StatusCode{Status::BadSecurityModeRejected});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditOpenSecureChannelEventPayload>(0);
  EXPECT_EQ(event.sourceName, "SecureChannel/OpenSecureChannel");
  EXPECT_FALSE(event.status);
  EXPECT_GE(event.severity, 800);
  EXPECT_EQ(event.serverId, testServerId);
  ASSERT_TRUE(event.statusCodeId.has_value());
  EXPECT_EQ(*event.statusCodeId, StatusCode(Status::BadSecurityModeRejected));
}

// @relation(SVR-EVT-AUD-003, SVR-AUDIT-011, SVR-AUDIT-029, scope=function)
TEST_F(AuditEventEmitterTest, RenewSecureChannelFailed_EmitsAuditChannelEvent)
{
  auto info = make_channel_info(42);
  mEmitter->on_secure_channel_renew_failed(info, StatusCode{Status::BadNonceInvalid});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditChannelEventPayload>(0);
  EXPECT_EQ(event.sourceName, "SecureChannel/RenewSecureChannel");
  EXPECT_FALSE(event.status);
  EXPECT_GE(event.severity, 800);
  EXPECT_EQ(event.secureChannelId, "42");
  ASSERT_TRUE(event.statusCodeId.has_value());
  EXPECT_EQ(*event.statusCodeId, StatusCode(Status::BadNonceInvalid));
}

// --- EventBus integration: local listener ---

// @relation(SVR-AUDIT-008, SVR-AUDIT-029, scope=function)
TEST(EventBusLocalListenerTest, SetEventListener_ReceivesEvents)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  // Create minimal Server Object for EventBus
  auto serverResult = addressSpace.try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
  ASSERT_TRUE(serverResult.is_good());
  serverResult.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  // EventBus inherits enable_shared_from_this; posted strand work requires
  // shared ownership for weak_from_this() to resolve.
  auto bus = std::make_shared<EventBus>(addressSpace);

  std::mutex receivedMutex;
  std::vector<NodeId> receivedEventTypes;
  bus->set_event_listener(
    [&](const BaseEvent& event)
    {
      std::lock_guard lk(receivedMutex);
      receivedEventTypes.push_back(event.eventType);
    });

  EXPECT_TRUE(bus->has_event_interest());

  BaseEvent event;
  event.eventType = NodeId{0, 1000u};
  event.sourceNode = serverObjectId;
  event.sourceName = "Test";
  event.message = LocalizedText{"", "Test event"};
  event.severity = 100;
  bus->emit(event);

  // Listener fires on the bus strand; drain before asserting.
  ::ua::test_utils::drain_with_timeout(tp);

  std::lock_guard lk(receivedMutex);
  ASSERT_EQ(receivedEventTypes.size(), 1u);
  EXPECT_EQ(receivedEventTypes[0], NodeId(0, 1000u));
}

// @relation(SVR-AUDIT-008, scope=function)
TEST(EventBusLocalListenerTest, ClearListener_StopsReceiving)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  auto serverResult = addressSpace.try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
  ASSERT_TRUE(serverResult.is_good());
  serverResult.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  auto bus = std::make_shared<EventBus>(addressSpace);

  std::atomic<int> callCount{0};
  bus->set_event_listener([&](const BaseEvent&) { ++callCount; });
  EXPECT_TRUE(bus->has_event_interest());

  bus->set_event_listener(nullptr);
  // The "false" gate flip is strand-reconciled; drain before observing.
  ::ua::test_utils::drain_with_timeout(tp);
  EXPECT_FALSE(bus->has_event_interest());

  BaseEvent event;
  event.eventType = NodeId{0, 1000u};
  event.sourceNode = serverObjectId;
  event.sourceName = "Test";
  event.message = LocalizedText{"", "Test event"};
  event.severity = 100;
  bus->emit(event);

  ::ua::test_utils::drain_with_timeout(tp);
  EXPECT_EQ(callCount.load(), 0);
}

// @relation(SVR-AUDIT-009, SVR-AUDIT-029, scope=function)
TEST(EventBusLocalListenerTest, HasEventInterest_TrueWhenMonitoredItemRegistered)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  auto serverResult = addressSpace.try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
  ASSERT_TRUE(serverResult.is_good());
  serverResult.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  auto bus = std::make_shared<EventBus>(addressSpace);
  EXPECT_FALSE(bus->has_event_interest());

  auto handle =
    bus->register_event_item(serverObjectId, 1, 0, [](IntegerId, std::shared_ptr<const BaseEvent>) {});
  EXPECT_TRUE(bus->has_event_interest());

  bus->deregister_event_item(handle);
  // Strand-reconciled flip; drain before observing.
  ::ua::test_utils::drain_with_timeout(tp);
  EXPECT_FALSE(bus->has_event_interest());
}

// --- Condition audit events (AuditConditionEventType and its subtypes) ---
//
// These are not emitted by AuditEventEmitter: the channel/session/certificate audits above come
// from the ServerObserver callbacks, while the condition audits come from ConditionInstance's
// client-Method entry points and its internal transitions. Both land on the same EventSink, and
// the SourceNode/SourceName conventions differ between the two families, which is exactly what
// the criteria below pin.

namespace
{

const NodeId auditConditionId{1, 5000u};
const NodeId auditConditionSource{1, 500u};

/// Records the identifying fields of every emitted event.
///
/// A condition Method emits the condition event first and the audit event second, so a test must
/// select the audit record by its EventType rather than taking the last one; the collector above
/// slices unknown payload types, which would lose that identity. Also stamps an EventId the way
/// the real EventBus does - ConditionInstance reads it back into the logic, and without it there
/// is no EventId for a later Acknowledge or AddComment to quote.
class ConditionAuditRecorder : public EventSink
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    String sourceName;
  };

  /// THREAD-SAFE for the same reason @ref EventCollector is: a condition raises its audit wherever
  /// the work that raised it happened - a shelving timer, a re-alarm, the registry's own strand -
  /// while the test thread reads what arrived. An unguarded `push_back` from two threads corrupts
  /// the heap rather than failing an assertion, and the damage surfaces in whatever allocates next,
  /// which is usually a different test.
  void emit(BaseEvent& event) override
  {
    const std::lock_guard lock{mMutex};
    if (event.eventId.empty())
      event.eventId = ByteString{std::vector<uint8_t>{static_cast<uint8_t>(mRecords.size() + 1u)}};
    mRecords.push_back(Record{event.eventType, event.sourceNode, event.sourceName});
  }

  std::vector<Record> of_type(ObjectTypeId type) const
  {
    const std::lock_guard lock{mMutex};
    std::vector<Record> matches;
    for (const auto& record : mRecords)
    {
      if (record.eventType == NodeId{type})
        matches.push_back(record);
    }
    return matches;
  }

  size_t count() const
  {
    const std::lock_guard lock{mMutex};
    return mRecords.size();
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

class ConditionAuditEventTest : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// Logic-only alarm instance: AlarmConditionLogic derives from AcknowledgeableConditionLogic, so
  /// Enable, AddComment and Acknowledge are all reachable on it.
  std::shared_ptr<ConditionInstance> make_alarm_instance()
  {
    return ConditionInstance::create(mPool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      auditConditionId,
      auditConditionSource,
      String{"AuditSource"},
      mRecorder);
  }

  /// Drive one client-Method entry point to completion. Returns false (having reported the reason)
  /// when the Method itself was rejected: the per-operation status rides inside the
  /// CallMethodResult while the outer CallResult stays Good, so both have to be unpacked. The
  /// audit obligations only bite on a Method that actually ran, so a caller asserts on this before
  /// asserting on the recorded events.
  ///
  /// Waits on the Method's own completion rather than draining the pool. `drain_with_timeout` joins
  /// the pool, which makes it a one-shot: every call after the first posts to a pool that will never
  /// run it again, and the Method appears to hang. Two of these tests drive several Methods in
  /// sequence - which is the point of them, since SourceName is what tells the Methods apart - so
  /// the helper has to leave the pool alive.
  template<typename Invoke>
  bool run_method(Invoke&& invoke, const char* what)
  {
    std::promise<StatusCode> settled;
    auto outcome = settled.get_future();
    invoke(CallMethodCompleteCallback{[&settled](CallResult result) mutable
      {
        settled.set_value(result.is_good() ? result.value().status_code() : result.status_code());
      }});

    if (outcome.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
    {
      ADD_FAILURE() << what << " did not complete";
      return false;
    }
    const StatusCode inner = outcome.get();
    EXPECT_TRUE(inner.is_good()) << what << " was rejected by the condition logic";
    return inner.is_good();
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<ConditionAuditRecorder> mRecorder = std::make_shared<ConditionAuditRecorder>();
};

}  // namespace

// Part 9 5.10: the audit records the state change, not the call, so a Condition enabled by a
// server-internal action must raise the same AuditConditionEnableEventType a client Enable raises.
// A plausible implementation hangs audit emission off the Method dispatch only - which is where the
// ClientUserId and the Method name are to hand - and leaves every internally driven change, an HMI
// enable or a start-up rule, with no audit trail at all.
// @verifies AC-SVR-AC-062-AUDIT-ON-INTERNAL-ACTION
TEST_F(ConditionAuditEventTest, InternalEnableStillRaisesTheConditionAuditEvent)
{
  auto instance = make_alarm_instance();

  // enable_sync() is the server-internal transition; it is not the client Enable Method.
  instance->enable_sync();
  ::ua::test_utils::drain_with_timeout(mPool);

  ASSERT_GT(mRecorder->count(), 0u) << "the internal transition emitted no events at all";
  const auto audits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  EXPECT_FALSE(audits.empty()) << "an internally driven Enable raised no AuditConditionEnableEventType";
}

// Part 9 5.10 line 5054: AuditConditionEventType inherits SourceNode, and unlike the channel and
// session audits above - which name the Server Object - a condition audit must name the
// ConditionId. A shared emit helper that stamps the Server Object on every audit event gets the
// channel family right and this one wrong, while still emitting the correct event type.
// @verifies AC-SVR-AC-063-AUDIT-SOURCENODE-CONDITIONID
TEST_F(ConditionAuditEventTest, ConditionAuditEventSourceNodeIsTheConditionId)
{
  auto instance = make_alarm_instance();

  ASSERT_TRUE(run_method([&](CallMethodCompleteCallback complete)
    { instance->call_enable_async(String{"operator"}, std::move(complete)); },
    "Enable"));

  const auto audits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  ASSERT_FALSE(audits.empty()) << "the Enable Method raised no AuditConditionEnableEventType";
  EXPECT_EQ(audits.front().sourceNode, auditConditionId);
  EXPECT_NE(audits.front().sourceNode, serverObjectId);
}

// Part 9 5.10 lines 5055-5056: SourceName on a condition audit event must be "Method/" followed by
// the name of the Method that drove it - it is the field an auditor filters on. An implementation
// that leaves SourceName at the Condition's own source name, or sets one constant string for the
// whole family, emits the right event types and is caught only by reading the field per Method.
// @verifies AC-SVR-AC-064-AUDIT-SOURCENAME-METHOD
TEST_F(ConditionAuditEventTest, ConditionAuditEventSourceNameNamesTheMethodThatDroveIt)
{
  auto instance = make_alarm_instance();

  ASSERT_TRUE(run_method([&](CallMethodCompleteCallback complete)
    { instance->call_enable_async(String{"operator"}, std::move(complete)); },
    "Enable"));

  const ByteString trunkEventId = instance->snapshot()->event_id();
  ASSERT_FALSE(trunkEventId.empty()) << "no EventId for AddComment to quote";
  ASSERT_TRUE(run_method(
    [&](CallMethodCompleteCallback complete)
    {
      instance->call_add_comment_async(
        trunkEventId, LocalizedText{"", "Operator note"}, String{"operator"}, std::move(complete));
    },
    "AddComment"));

  const ByteString commentedEventId = instance->snapshot()->event_id();
  ASSERT_FALSE(commentedEventId.empty()) << "no EventId for Acknowledge to quote";
  ASSERT_TRUE(run_method(
    [&](CallMethodCompleteCallback complete)
    {
      instance->call_acknowledge_async(
        commentedEventId, LocalizedText{"", "Acknowledged"}, String{"operator"}, std::move(complete));
    },
    "Acknowledge"));

  const auto enableAudits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  const auto commentAudits = mRecorder->of_type(ObjectTypeId::AuditConditionCommentEventType);
  const auto acknowledgeAudits = mRecorder->of_type(ObjectTypeId::AuditConditionAcknowledgeEventType);
  ASSERT_FALSE(enableAudits.empty()) << "the Enable Method raised no AuditConditionEnableEventType";
  ASSERT_FALSE(commentAudits.empty()) << "the AddComment Method raised no AuditConditionCommentEventType";
  ASSERT_FALSE(acknowledgeAudits.empty())
    << "the Acknowledge Method raised no AuditConditionAcknowledgeEventType";

  EXPECT_EQ(enableAudits.front().sourceName, "Method/Enable");
  EXPECT_EQ(commentAudits.front().sourceName, "Method/AddComment");
  EXPECT_EQ(acknowledgeAudits.front().sourceName, "Method/Acknowledge");
}

// Part 9 5.10 lines 5074-5077: AuditConditionEnableEventType is shared by Enable and Disable, so
// SourceName is the only field that says which of the two happened - "Method/Enable",
// "Method/Disable", and for a server-internal transition a non-Method description such as
// "Internal/Enable". An implementation that emits one audit event per transition with a single
// constant SourceName satisfies the event-type obligation and loses the direction entirely, which
// is the whole point of auditing an enable.
// @verifies AC-SVR-AC-065-ENABLE-AUDIT-SOURCENAME
TEST_F(ConditionAuditEventTest, EnableAuditSourceNameDistinguishesEnableDisableAndInternalChanges)
{
  auto methodDriven = make_alarm_instance();

  ASSERT_TRUE(run_method([&](CallMethodCompleteCallback complete)
    { methodDriven->call_enable_async(String{"operator"}, std::move(complete)); },
    "Enable"));
  ASSERT_TRUE(run_method([&](CallMethodCompleteCallback complete)
    { methodDriven->call_disable_async(String{"operator"}, std::move(complete)); },
    "Disable"));

  const auto methodAudits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  ASSERT_EQ(methodAudits.size(), 2u)
    << "Enable and Disable must each raise exactly one AuditConditionEnableEventType";
  EXPECT_EQ(methodAudits[0].sourceName, "Method/Enable");
  EXPECT_EQ(methodAudits[1].sourceName, "Method/Disable");

  // A second Condition enabled internally shares the event type but must not claim a Method drove
  // it. Same recorder, so the internal record is the one past the two Method-driven records.
  auto internallyDriven = make_alarm_instance();
  internallyDriven->enable_sync();
  ::ua::test_utils::drain_with_timeout(mPool);

  const auto allAudits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  ASSERT_GT(allAudits.size(), methodAudits.size())
    << "an internally driven Enable raised no AuditConditionEnableEventType";
  const auto& internalAudit = allAudits[methodAudits.size()];
  EXPECT_FALSE(internalAudit.sourceName.empty()) << "the internal Enable left SourceName unset";
  EXPECT_NE(internalAudit.sourceName, "Method/Enable");
  EXPECT_NE(internalAudit.sourceName, "Method/Disable");
}

// --- Latched-alarm Reset audit events (AuditConditionResetEventType) ---
//
// Reset and Reset2 are Optional members of AlarmConditionType and the audit hook hangs off the
// address-space Method dispatch, not off the internal reset transition, so neither is reachable
// from the logic-only fixture above: a ConditionInstance has no call_reset_async, and reset_sync()
// is the internal transition. These tests therefore stand up a real NS0-backed address space,
// materialise the Methods by declaring latching support, and invoke them the way a Client does.

namespace
{

class ConditionResetAuditTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);

    sAddressSpace.emplace(AddressSpace::create("uri:test:reset-audit", sPool.get_executor()));

    StructureFactory structureFactory;
    auto lookupFn = namespace_array_utils::get_index_lookup_function(as());
    const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
    register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

    FileStream inputStream{"NodeSet2.xml"};
    inputStream.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(sLimits,
      inputStream,
      structureFactory,
      as().namespace_array(),
      as().server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});

    auto importer = xml::nodeset::ImportEngine::create(sLimits, as(), nodeSets, {});
    importer->import_all_sync({}, {});
  }

  static void TearDownTestSuite()
  {
    // Release the imported NS0 graph before LeakSanitizer runs, as the other NS0-backed suites in
    // this binary do. Do not join the static pool: a joined thread_pool cannot be revived.
    sAddressSpace.reset();
  }

  static AddressSpace& as()
  {
    return *sAddressSpace;
  }

  /// A latching alarm, integrated with the address space, left enabled, inactive and acknowledged.
  ///
  /// That is exactly the state `AlarmConditionLogic::reset()` demands, so a Reset call reaches the
  /// Method's success path instead of being turned away with BadInvalidState before any audit
  /// decision is made. Latching support is also what materialises the Optional Reset Method node.
  std::shared_ptr<ConditionInstance> make_reset_ready_alarm()
  {
    const auto id = sNextId++;
    auto logic = std::make_unique<AlarmConditionLogic>();
    logic->set_supports_latched(true);

    auto instance = ConditionInstance::create(sPool.get_executor(),
      std::move(logic),
      NodeId{1, id},
      NodeId{ObjectId::ObjectsFolder},
      String{"ResetAuditCond_" + std::to_string(id)},
      mRecorder,
      as(),
      NodeId{ObjectTypeId::AlarmConditionType});
    EXPECT_TRUE(instance->try_initialize_sync().is_good()) << "address-space integration failed";

    instance->enable_sync();
    instance->activate_sync(500);
    instance->deactivate_sync();

    const ByteString eventId = instance->snapshot()->event_id();
    EXPECT_FALSE(eventId.empty()) << "no EventId for Acknowledge to quote";
    EXPECT_TRUE(instance->try_acknowledge_sync(eventId, LocalizedText{"", "ack"}).is_good());
    return instance;
  }

  /// Find a forward HasComponent child of @p parent with the given browse name.
  NodeId find_component(const NodeId& parent, const std::string& browseName)
  {
    auto nodeResult = as().try_find_node_sync(parent);
    if (nodeResult.is_bad())
    {
      return NodeId{};
    }
    auto refs = nodeResult.value().get_references_sync();
    for (const auto& ref : refs)
    {
      if (!ref.is_forward() || ref.is_remote() || ref.type_id() != NodeId{ReferenceTypeId::HasComponent})
      {
        continue;
      }
      auto childResult = as().try_find_node_sync(ref.target_id().node_id());
      if (childResult.is_good() && std::string{childResult.value().get_browse_name().name()} == browseName)
      {
        return ref.target_id().node_id();
      }
    }
    return NodeId{};
  }

  /// Invoke a Method node the way a Client does and return the per-operation status. The outer
  /// CallResult stays Good for a rejected operation, so both layers have to be unpacked.
  StatusCode call_method(const NodeId& objectId, const NodeId& methodId, Array<Variant> inputs = {})
  {
    auto methodResult = as().try_find_sync<MethodAccessor>(methodId);
    if (methodResult.is_bad())
    {
      return methodResult.status_code();
    }

    CallMethodRequest request;
    request.object_id() = objectId;
    request.method_id() = methodId;
    request.input_arguments() = std::move(inputs);

    auto callResult = methodResult.value().try_call_sync(request);
    if (callResult.is_bad())
    {
      return callResult.status_code();
    }
    return callResult.value().status_code();
  }

  static boost::asio::thread_pool sPool;
  static std::optional<AddressSpace> sAddressSpace;
  static EncodingLimits sLimits;
  static uint32_t sNextId;

  std::shared_ptr<ConditionAuditRecorder> mRecorder = std::make_shared<ConditionAuditRecorder>();
};

boost::asio::thread_pool ConditionResetAuditTest::sPool{2};
std::optional<AddressSpace> ConditionResetAuditTest::sAddressSpace{};
EncodingLimits ConditionResetAuditTest::sLimits{};
uint32_t ConditionResetAuditTest::sNextId{7100};

}  // namespace

// Part 9 5.8.5 lines 2972-2973: if Auditing is supported, Reset shall generate an
// AuditConditionResetEventType for all invocations. Reset clears the latch, which is the last
// remaining record that the alarm ever occurred, so the audit event is all that survives it. A
// plausible implementation audits the Methods every condition has - Enable, AddComment,
// Acknowledge - and leaves the Optional latched Methods unaudited; the ordinary condition event
// Reset emits looks identical either way, so only the audit event type separates the two.
// @verifies AC-SVR-AC-124-RESET-AUDIT
TEST_F(ConditionResetAuditTest, ResetMethodRaisesTheConditionResetAuditEvent)
{
  auto instance = make_reset_ready_alarm();
  ASSERT_TRUE(instance->snapshot()->enabled());
  ASSERT_FALSE(instance->snapshot()->active());
  ASSERT_TRUE(instance->snapshot()->acked()) << "Reset is refused unless the alarm is acknowledged";

  const NodeId resetMethodId = find_component(instance->condition_id(), "Reset");
  ASSERT_FALSE(resetMethodId.is_null()) << "the latching alarm exposes no Reset Method node to call";

  const StatusCode callStatus = call_method(instance->condition_id(), resetMethodId);
  ASSERT_TRUE(callStatus.is_good()) << "Reset was refused: " << callStatus.as_uint32();

  const auto audits = mRecorder->of_type(ObjectTypeId::AuditConditionResetEventType);
  EXPECT_FALSE(audits.empty()) << "the Reset Method raised no AuditConditionResetEventType";
}

// The Reset2 audit row was retired here on 2026-08-10 into
// WV-A-C-RESET2-METHOD-NOT-MATERIALISED: Part 9 Table 47 marks Reset2 an Optional member of
// AlarmConditionType and this SDK does not materialise it, so the audit-on-invocation obligation
// has no invocations to bind. Reset itself is materialised and its audit stays verified above.

// Part 9 5.10: the audit records the state change, not the call, and the criterion names two
// internally driven changes - an enable and an acknowledgement. Acknowledge is the harder half: it
// carries an EventId and a comment, so an implementation that does route internal transitions
// through the audit path often still hangs the Acknowledge audit off the Method adapter, which is
// the only place those two arguments are unpacked. An alarm acknowledged at a local HMI panel then
// leaves no audit record at all while an internally enabled one does.
// @verifies AC-SVR-AC-062-AUDIT-ON-INTERNAL-ACTION
TEST_F(ConditionAuditEventTest, InternalAcknowledgeStillRaisesTheConditionAuditEvent)
{
  auto instance = make_alarm_instance();

  // enable_sync()/activate_sync() are the server-internal transitions; they are not client Methods.
  // Activating leaves the trunk unacknowledged, which is what makes the Acknowledge below succeed.
  // Each blocks until the strand handler has applied the transition and emitted, so nothing is left
  // in flight to drain - and draining here would join the pool, leaving no thread to run the
  // acknowledgement posted below. TearDown does the one drain this fixture needs.
  instance->enable_sync();
  instance->activate_sync(500);

  const ByteString trunkEventId = instance->snapshot()->event_id();
  ASSERT_FALSE(trunkEventId.empty()) << "no EventId for the internal Acknowledge to quote";
  ASSERT_FALSE(instance->snapshot()->acked()) << "the alarm was already acknowledged before the test acted";

  // try_acknowledge_sync() is the server-internal acknowledgement - the local-HMI path - as opposed
  // to call_acknowledge_async(), which is the client Acknowledge Method.
  ASSERT_TRUE(
    instance->try_acknowledge_sync(trunkEventId, LocalizedText{"", "acknowledged at the panel"}).is_good());

  ASSERT_TRUE(instance->snapshot()->acked()) << "the internal Acknowledge did not take effect";
  ASSERT_GT(mRecorder->count(), 0u) << "the internal transition emitted no events at all";
  const auto audits = mRecorder->of_type(ObjectTypeId::AuditConditionAcknowledgeEventType);
  EXPECT_FALSE(audits.empty())
    << "an internally driven Acknowledge raised no AuditConditionAcknowledgeEventType";
}

// Part 9 5.10 lines 5074-5077: for a non-Method transition SourceName must describe the internal
// mechanism - `Internal/Enable`, `Startup/Enable`, `Remote/Enable` - and must NOT claim a Method
// drove it, because a client filtering on the `Method/` prefix uses that prefix to decide whether a
// Method call is what it is looking at. An implementation that reaches for the nearest existing
// string and stamps `Method/Enable`, or one that keeps the `Method/` prefix and only varies the
// suffix, still names the right direction and is caught only by testing the prefix and the suffix
// as separate conjuncts.
// @verifies AC-SVR-AC-065-ENABLE-AUDIT-SOURCENAME
TEST_F(ConditionAuditEventTest, InternalEnableAuditSourceNameDescribesTheMechanismNotAMethod)
{
  auto instance = make_alarm_instance();

  instance->enable_sync();
  ::ua::test_utils::drain_with_timeout(mPool);

  const auto audits = mRecorder->of_type(ObjectTypeId::AuditConditionEnableEventType);
  ASSERT_FALSE(audits.empty()) << "an internally driven Enable raised no AuditConditionEnableEventType";

  const std::string sourceName{audits.front().sourceName};
  ASSERT_FALSE(sourceName.empty()) << "the internal Enable left SourceName unset";
  EXPECT_NE(sourceName.rfind("Method/", 0), 0u)
    << "the internal Enable claimed a Method drove it: SourceName was '" << sourceName << "'";
  EXPECT_NE(sourceName.find("Enable"), std::string::npos)
    << "SourceName does not name the Enable direction: '" << sourceName << "'";
}

// --- ActivateSession audit: user identity token redaction ---

// Part 5 section 6.4.10 (line 2413) / Part 4 section 6.5: the AuditActivateSessionEvent carries the
// UserIdentityToken the client presented, and for a UserName token "the password shall not be
// included". Audit events are the most widely readable data a server produces - subscribed to,
// historised, exported - so a password copied into one is a credential written to every archive the
// audit trail reaches. Copying the token wholesale is the natural implementation and keeps the user
// name correct, so only reading the password field separates a redacted token from a leaked one.
// @verifies AC-SVR-AUDIT-023-NO-PASSWORD-IN-AUDIT
TEST_F(AuditEventEmitterTest, ActivateSessionAuditNeverCarriesTheUserNamePassword)
{
  auto info = make_session_info("PasswordSession");
  info.clientUserId = "operator1";

  // The token as the ActivateSession request delivered it: a user name and its password.
  auto token = std::make_shared<UserNameIdentityToken>();
  token->user_name() = String{"operator1"};
  token->password() = ByteString{std::vector<uint8_t>{0x73, 0x65, 0x63, 0x72, 0x65, 0x74}};
  info.userIdentityToken = token;

  mEmitter->on_session_activated(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditActivateSessionEventPayload>(0);

  const auto* audited = event.userIdentityToken.try_as<UserNameIdentityToken>();
  ASSERT_NE(audited, nullptr) << "the audit event carries no UserName UserIdentityToken to inspect";
  EXPECT_EQ(audited->user_name(), "operator1") << "the audited token does not identify the user";
  EXPECT_TRUE(audited->password().empty())
    << "the audited UserIdentityToken carries the password - a credential written to every "
       "subscriber, historian and export the audit trail reaches";
}

// --- Local listener + subscriber-interest gate ---
//
// Both tests below drive a real audit producer into a real EventBus. The listener test uses
// AuditEventEmitter (the ServerObserver that turns channel/session lifecycle into audit events); the
// interest-gate test uses MethodServiceSet's post-response audit, which is the gated high-frequency
// producer named by the requirement (CU-AUDITING-METHOD). Neither test creates a Session,
// Subscription or MonitoredItem except where the criterion asks for one.

namespace
{

const NodeId gateObjectId{0, 4242u};
const NodeId gateMethodId{0, 4243u};
constexpr IntegerId gateMonitoredItemId{1};
constexpr uint32_t gateSubscriptionId{0};

/// An EventBus that records every event handed to it and then runs the real dispatch path.
///
/// The record is taken in `emit`, which is the only thing an audit producer does with an event it
/// has built: at every audit site in the server the construction and the emit sit inside the same
/// `if`, so "nothing arrived here" is the observable form of "no Event was constructed". Forwarding
/// to `EventBus::emit` keeps subscriber delivery real, which is the other half of the gate.
class RecordingEventBus : public EventBus
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    String sourceName;
    NodeId methodId;
    bool isUpdateMethodAudit{false};
  };

  explicit RecordingEventBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    {
      std::lock_guard lock(mMutex);
      Record record;
      record.eventType = event.eventType;
      record.sourceNode = event.sourceNode;
      record.sourceName = event.sourceName;
      if (const auto* methodAudit = dynamic_cast<const AuditUpdateMethodEventPayload*>(&event))
      {
        record.isUpdateMethodAudit = true;
        record.methodId = methodAudit->methodId;
      }
      mRecords.push_back(std::move(record));
    }
    EventBus::emit(event);
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

/// Drive one Call request through the real MethodServiceSet and wait for its response.
///
/// Returns false (having reported it) when no CallResponse came back - a service-level fault never
/// reaches the per-operation audit site, so a caller asserts on this before asserting on events.
bool run_call_service(
  const std::shared_ptr<SessionInfo>& sessionInfo, CallRequest request, boost::asio::any_io_executor executor)
{
  std::condition_variable cv;
  std::mutex mtx;
  bool completed = false;

  auto service = MethodServiceSet::create(sessionInfo,
    std::vector<LocaleId>{LocaleId{"en"}},
    0,
    std::move(request),
    executor,
    [&cv, &mtx, &completed](Response response)
    {
      auto* callResponse = dynamic_cast<CallResponse*>(std::get<shared_ptr<Structure>>(response).get());
      std::lock_guard lock(mtx);
      completed = callResponse != nullptr;
      cv.notify_all();
    });

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, std::chrono::seconds{2}, [&completed] { return completed; });
  return completed;
}

/// One Call of a method that does not resolve. The Call still runs to a per-operation result, and
/// the audit site sits on that result path, so this provokes an auditable action without needing a
/// method node - and it keeps the called Object distinct from the Server Object.
CallRequest make_gate_call_request()
{
  CallRequest request;
  request.methods_to_call().resize(1);
  request.methods_to_call()[0].object_id() = gateObjectId;
  request.methods_to_call()[0].method_id() = gateMethodId;
  return request;
}

}  // namespace

// SVR-AUDIT-008 (design extension, `audit_event_design.md` "Local Event Listener"): the hosting
// application is not a client, so requiring it to subscribe to itself would put its own audit trail
// behind the session machinery it is hosting. An implementation that hangs audit delivery off the
// subscriber fan-out - the obvious place, since every other event consumer lives there - leaves a
// host with no Session, Subscription or MonitoredItem seeing nothing at all, and one that special-
// cases audit types onto the listener fails the other half: the listener takes every event.
// @verifies AC-SVR-AUDIT-008-LOCAL-LISTENER
TEST(EventBusLocalListenerTest, LocalListenerReceivesAuditAndNonAuditEventsWithNoSubscription)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  auto serverResult = addressSpace.try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
  ASSERT_TRUE(serverResult.is_good());
  serverResult.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  auto bus = std::make_shared<EventBus>(addressSpace);

  // No Session, Subscription or MonitoredItem is created anywhere in this test, and the bus confirms
  // it has no other source of interest before the local listener is installed.
  EXPECT_FALSE(bus->has_event_interest());

  struct Seen
  {
    NodeId eventType;
    String sourceName;
    String serverId;
    String secureChannelId;
    bool isAudit{false};
    bool isOpenSecureChannelAudit{false};
  };

  std::mutex seenMutex;
  std::vector<Seen> seen;
  bus->set_event_listener(
    [&](const BaseEvent& event)
    {
      Seen record;
      record.eventType = event.eventType;
      record.sourceName = event.sourceName;
      if (const auto* audit = dynamic_cast<const AuditEventPayload*>(&event))
      {
        record.isAudit = true;
        record.serverId = audit->serverId;
      }
      if (const auto* opened = dynamic_cast<const AuditOpenSecureChannelEventPayload*>(&event))
      {
        record.isOpenSecureChannelAudit = true;
        record.secureChannelId = opened->secureChannelId;
      }
      std::lock_guard lk(seenMutex);
      seen.push_back(std::move(record));
    });
  EXPECT_TRUE(bus->has_event_interest());

  // The audit event comes from the real emitter, through the real bus - not from the test.
  AuditEventEmitter emitter(bus, testServerId);
  emitter.on_secure_channel_opened(make_channel_info(11));

  // ... and a non-audit event, which the same listener must also receive.
  BaseEvent plain;
  plain.eventType = NodeId{0, 1000u};
  plain.sourceNode = serverObjectId;
  plain.sourceName = "Test";
  plain.message = LocalizedText{"", "Test event"};
  plain.severity = 100;
  bus->emit(plain);

  // The listener fires on the bus strand; drain before asserting.
  ::ua::test_utils::drain_with_timeout(tp);

  std::lock_guard lk(seenMutex);
  ASSERT_EQ(seen.size(), 2u) << "the local listener did not receive both events";
  EXPECT_TRUE(seen[0].isAudit) << "the audit event never reached the local listener";
  EXPECT_TRUE(seen[0].isOpenSecureChannelAudit) << "the audit event reached the listener sliced";
  EXPECT_EQ(seen[0].sourceName, "SecureChannel/OpenSecureChannel");
  EXPECT_EQ(seen[0].serverId, testServerId);
  EXPECT_EQ(seen[0].secureChannelId, "11");
  EXPECT_FALSE(seen[1].isAudit) << "the second event should be the plain non-audit event";
  EXPECT_EQ(seen[1].eventType, NodeId(0, 1000u)) << "a non-audit event did not reach the listener";
}

// SVR-AUDIT-009 (design invariant, `audit_event_design.md` "Two-Level Gate"): building an audit
// Event costs work per auditable action, so Write/Call audits are skipped when no MonitoredItem and
// no local listener exist. The gate is a performance obligation with a correctness edge, and the
// edge is the expensive half: an implementation that caches the "nobody is listening" answer, or
// that never re-reads it, keeps the saving and silently swallows the audit trail of a subscriber
// that arrived afterwards. Both halves are driven through MethodServiceSet's real audit site.
// @verifies AC-SVR-AUDIT-009-SUBSCRIBER-INTEREST-GATE
TEST(EventInterestGateTest, AuditEventsAreBuiltOnlyWhenSubscribedAndAreStillDeliveredWhenTheyAre)
{
  boost::asio::thread_pool pool;

  std::mutex deliveryMutex;
  std::condition_variable deliveryCv;
  std::vector<NodeId> deliveredEventTypes;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto bus = std::make_shared<RecordingEventBus>(addressSpace);
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();

  // Case 1 - nothing subscribed: no MonitoredItem, no local listener.
  ASSERT_FALSE(bus->has_event_interest());
  ASSERT_TRUE(run_call_service(sessionInfo, make_gate_call_request(), pool.get_executor()))
    << "the first Call never produced a response, so it never reached the audit site";
  // The audit decision is made on the service strand before the response is handed back, so by the
  // time the Call has completed the count is settled.
  EXPECT_TRUE(bus->records().empty()) << "an audit Event was built for a Call nobody was listening to";

  // Case 2 - one event MonitoredItem, registered the way a Subscription registers one.
  auto handle = bus->register_event_item(serverObjectId,
    gateMonitoredItemId,
    gateSubscriptionId,
    [&](IntegerId, std::shared_ptr<const BaseEvent> event)
    {
      std::lock_guard lock(deliveryMutex);
      deliveredEventTypes.push_back(event->eventType);
      deliveryCv.notify_all();
    });
  EXPECT_NE(handle, 0u);
  EXPECT_TRUE(bus->has_event_interest());

  // The registry insert is posted to the bus strand; this strand-ordered read lands after it, so the
  // second Call cannot race the registration.
  std::promise<bool> registered;
  bus->resolve_event_item_node_async(gateSubscriptionId,
    gateMonitoredItemId,
    [&registered](std::optional<NodeId> node) { registered.set_value(node.has_value()); });
  auto registeredFuture = registered.get_future();
  ASSERT_EQ(registeredFuture.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "the bus never answered the registration probe";
  ASSERT_TRUE(registeredFuture.get()) << "the event MonitoredItem never became visible to the bus";

  ASSERT_TRUE(run_call_service(sessionInfo, make_gate_call_request(), pool.get_executor()))
    << "the second Call never produced a response, so it never reached the audit site";

  auto records = bus->records();
  ASSERT_EQ(records.size(), 1u) << "the subscribed Call did not build exactly one audit Event";
  EXPECT_TRUE(records.front().isUpdateMethodAudit) << "the Call's audit Event is not a method audit";

  // ... and the event is delivered normally, not swallowed by the optimisation.
  const AuditUpdateMethodEventPayload expectedType;
  std::unique_lock<std::mutex> deliveryLock(deliveryMutex);
  EXPECT_TRUE(deliveryCv.wait_for(
    deliveryLock, std::chrono::seconds{2}, [&deliveredEventTypes] { return !deliveredEventTypes.empty(); }))
    << "the audit Event was built but never delivered to the subscribed MonitoredItem";
  ASSERT_FALSE(deliveredEventTypes.empty());
  EXPECT_EQ(deliveredEventTypes.front(), expectedType.eventType);
  deliveryLock.unlock();

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 5 section 6.4.27 (lines 2837-2839): "The SourceNode Property for Events of this type shall be
// assigned to the NodeId of the Object that the Method resides on. The SourceName for Events of this
// type shall be 'Attribute/Call'." This is the fourth SourceNode convention in the audit corpus, and
// SourceName is the field an auditor filters a service on - a name invented from the service set
// ("Method/Call") reads plausibly and matches nothing a compliant client looks for, while a shared
// helper that stamps the Server Object on every audit event gets the channel family right and loses
// which Object was called. Both fields are read per Call for that reason.
// @verifies AC-SVR-AUDIT-020-UPDATEMETHOD-SOURCE
// @relation(AC-SVR-SM-046-AUDITUPDATEMETHOD-SOURCENAME, scope=function)
TEST(MethodCallAuditTest, MethodCallAuditNamesTheObjectCalledAndTheMethod)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto bus = std::make_shared<RecordingEventBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();

  ASSERT_TRUE(run_call_service(sessionInfo, make_gate_call_request(), pool.get_executor()))
    << "the Call never produced a response, so it never reached the audit site";

  auto records = bus->records();
  ASSERT_FALSE(records.empty()) << "the Call raised no audit Event at all";
  const auto& audit = records.front();
  ASSERT_TRUE(audit.isUpdateMethodAudit) << "the Call's audit Event is not an AuditUpdateMethodEvent";
  EXPECT_EQ(audit.sourceNode, gateObjectId) << "the method audit does not name the Object called";
  EXPECT_NE(audit.sourceNode, serverObjectId) << "the method audit named the Server Object";
  EXPECT_EQ(audit.methodId, gateMethodId);
  EXPECT_EQ(audit.sourceName, "Attribute/Call") << "SourceName must be exactly 'Attribute/Call'";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

namespace
{

/// An EventBus that records which Method an audit Event names AND how the invocation ended, then
/// runs the real dispatch path.
///
/// The two recorders above capture one half each - `RecordingEventBus` the MethodId,
/// `AuditOutcomeRecordingBus` the Status - and the both-outcomes obligation needs both at once:
/// which Method was audited, and with what outcome. Recording in `emit` is what makes "nothing
/// arrived here" the observable form of "no Event was constructed".
class MethodAuditRecordingBus : public EventBus
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    NodeId methodId;
    bool isUpdateMethodAudit{false};
    bool status{false};
  };

  explicit MethodAuditRecordingBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    {
      std::lock_guard lock(mMutex);
      Record record;
      record.eventType = event.eventType;
      record.sourceNode = event.sourceNode;
      if (const auto* audit = dynamic_cast<const AuditEventPayload*>(&event))
        record.status = audit->status;
      if (const auto* methodAudit = dynamic_cast<const AuditUpdateMethodEventPayload*>(&event))
      {
        record.isUpdateMethodAudit = true;
        record.methodId = methodAudit->methodId;
      }
      mRecords.push_back(std::move(record));
    }
    EventBus::emit(event);
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

}  // namespace

// Part 4 section 6.5.9: a Call shall raise an `AuditUpdateMethodEventType` Event for both successful and
// failed invocations "if the invocation modifies the AddressSpace, writes a value or modifies the
// state of the system". The failure half is the one an implementation loses - the emission naturally
// sits on the success branch, and a refused Call that changed nothing leaves no other trace, so the
// attempt an auditor is hunting for disappears entirely. One Method that writes a Variable through
// the address space is therefore invoked twice, once accepted and once refused, so the pair differs
// only in outcome; each invocation's own per-operation status is asserted before its audit is looked
// for, so "no audit" can never be a Call that never ran.
//
// The criterion's read-only half is deliberately NOT asserted. The same clause ends "Methods that do
// not modify the AddressSpace, write values or modify the state of the system may generate events"
// (SPEC-SVR-EVT-AUD-020, an explicit MAY), so a server that audits every Call - including this SDK,
// whose Call audit site is unconditional - is conforming. Demanding silence for a read-only Method
// would manufacture a defect against permitted behaviour.
// @verifies AC-SVR-EVT-AUD-019-METHOD-AUDIT
TEST(MethodCallAuditTest, AStateChangingMethodCallIsAuditedWhetherItSucceedsOrIsRefused)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto methodNamespace =
    default_ns::Namespace::create("uri:test:audit-method-classification", pool.get_executor());
  addressSpace.add_namespace_sync(methodNamespace);
  const uint16_t nsIndex =
    addressSpace.namespace_array().get_namespace_index("uri:test:audit-method-classification");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the Method-bearing namespace was not registered";

  auto bus = std::make_shared<MethodAuditRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  // The Variable the state-changing Method writes: the modification the obligation is conditional on.
  const NodeId writtenNode{nsIndex, 9500u};
  auto writtenResult = addressSpace.try_create_sync<VariableAccessor>(writtenNode, NodeClass::Variable);
  ASSERT_TRUE(writtenResult.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    writtenResult.value().set_access_level(accessLevel);
  }
  const VariableAccessor writtenVariable = writtenResult.value();

  auto objectsFolder = addressSpace.try_find_node_sync(NodeId{ObjectId::ObjectsFolder});
  ASSERT_TRUE(objectsFolder.is_good()) << "the address space has no Objects folder to hang a Method on";

  // An Object owning one Method, with the handler the Call dispatch reaches.
  auto makeMethod = [&](uint32_t objectIdentifier,
                      uint32_t methodIdentifier,
                      const char* browseName,
                      MethodCallSource::CallHandler handler)
  {
    const NodeId objectId{nsIndex, objectIdentifier};
    const NodeId methodId{nsIndex, methodIdentifier};

    auto objectResult = addressSpace.try_create_sync<ObjectAccessor>(objectId, NodeClass::Object);
    EXPECT_TRUE(objectResult.is_good());
    objectResult.value().set_browse_name(QualifiedName{nsIndex, browseName});
    objectResult.value().set_display_name(LocalizedText{"", browseName});
    EXPECT_TRUE(
      objectsFolder.value().try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, objectId).is_good());

    auto methodResult = addressSpace.try_create_sync<MethodAccessor>(methodId, NodeClass::Method);
    EXPECT_TRUE(methodResult.is_good());
    methodResult.value().set_browse_name(QualifiedName{nsIndex, browseName});
    methodResult.value().set_display_name(LocalizedText{"", browseName});
    methodResult.value().set_executable(true);
    EXPECT_TRUE(
      objectResult.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId).is_good());

    auto methodNode = methodNamespace->find_node<Node>(methodId);
    EXPECT_NE(methodNode, nullptr) << "the Method node was not created in the test namespace";
    auto* callSource = methodNode ? methodNode->method_call_source() : nullptr;
    EXPECT_NE(callSource, nullptr) << "the Method node exposes no call-handler interface";
    if (callSource != nullptr)
      callSource->set_call_handler(std::move(handler));
    return std::make_pair(objectId, methodId);
  };

  // One Method that modifies the AddressSpace. Its first invocation writes; its second is refused,
  // so the pair differs only in outcome - the same Method, the same classification.
  auto invocationCount = std::make_shared<std::atomic<int>>(0);
  const auto stateChanging = makeMethod(9510u,
    9511u,
    "StateChangingMethod",
    [writtenVariable, invocationCount](const CallMethodRequest&,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        callback)
    {
      CallMethodResult result;
      if (invocationCount->fetch_add(1) == 0)
      {
        VariableAccessor variable = writtenVariable;
        variable.write_value_async(DataValue{Variant{int32_t{42}}}, [](VoidResult) {});
        result.status_code() = Status::Good;
      }
      else
      {
        result.status_code() = Status::BadUserAccessDenied;
      }
      callback(CallResult{std::move(result)});
    });

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();

  // Drive one Call through the real MethodServiceSet and return its per-operation status. The outer
  // response stays Good for a refused operation, so both layers have to be unpacked.
  auto callOne = [&](const NodeId& objectId, const NodeId& methodId) -> StatusCode
  {
    std::mutex mutex;
    std::condition_variable cv;
    bool completed = false;
    StatusCode operationStatus{Status::BadInternalError};

    CallRequest request;
    request.methods_to_call().resize(1);
    request.methods_to_call()[0].object_id() = objectId;
    request.methods_to_call()[0].method_id() = methodId;

    auto service = MethodServiceSet::create(sessionInfo,
      std::vector<LocaleId>{LocaleId{"en"}},
      0,
      std::move(request),
      pool.get_executor(),
      [&cv, &mutex, &completed, &operationStatus](Response response)
      {
        auto* callResponse = dynamic_cast<CallResponse*>(std::get<shared_ptr<Structure>>(response).get());
        std::lock_guard lock(mutex);
        if (callResponse != nullptr && callResponse->results().size() == 1u)
          operationStatus = StatusCode{callResponse->results()[0].status_code()};
        completed = callResponse != nullptr;
        cv.notify_all();
      });

    std::unique_lock<std::mutex> lock(mutex);
    EXPECT_TRUE(cv.wait_for(lock, std::chrono::seconds{3}, [&completed] { return completed; }))
      << "the Call never produced a response, so it never reached the audit site";
    return operationStatus;
  };

  const StatusCode acceptedStatus = callOne(stateChanging.first, stateChanging.second);
  ASSERT_TRUE(acceptedStatus.is_good())
    << "the state-changing Method's first invocation was refused (" << acceptedStatus.as_uint32()
    << "), so nothing was modified and the obligation never bit";

  const StatusCode refusedStatus = callOne(stateChanging.first, stateChanging.second);
  ASSERT_TRUE(refusedStatus.is_bad())
    << "the state-changing Method's second invocation succeeded - the failure stimulus never happened";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);

  const auto records = bus->records();
  size_t methodAudits = 0;
  size_t stateChangingSuccessAudits = 0;
  size_t stateChangingFailureAudits = 0;
  for (const auto& record : records)
  {
    if (!record.isUpdateMethodAudit)
      continue;
    ++methodAudits;
    if (record.methodId != stateChanging.second)
      continue;
    if (record.status)
      ++stateChangingSuccessAudits;
    else
      ++stateChangingFailureAudits;
  }

  EXPECT_GT(stateChangingSuccessAudits, 0u)
    << "the successful state-changing Call raised no AuditUpdateMethodEventType; " << methodAudits
    << " method audits were raised in all";
  EXPECT_GT(stateChangingFailureAudits, 0u)
    << "the refused state-changing Call raised no AuditUpdateMethodEventType carrying Status false - "
       "the attempt to change state left no trace at all; "
    << methodAudits << " method audits were raised in all";
}

// --- HasEventSource / EventNotifier agreement ---

// Part 3 section 7: a HasEventSource reference may only originate from an Object whose EventNotifier has
// the SubscribeToEvents bit set, because the notifier hierarchy a client walks is only navigable
// through Nodes it can actually subscribe to. A mutator that treats HasEventSource as just another
// reference type materialises links out of Objects nothing can subscribe to and every traversal that
// follows one ends at a dead end. The audit runs over the references that were actually
// materialised, and is asserted non-empty first so a mutator that refuses everything cannot pass it.
// @verifies AC-SVR-EVT-ATTR-002-HASEVENTSOURCE-NOTIFIER-BIT
TEST(EventSourceReferenceInvariantTest, HasEventSourceOriginatesOnlyFromObjectsThatCanBeSubscribedTo)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  auto makeObject = [&addressSpace](uint32_t identifier, EventNotifierType notifier)
  {
    const NodeId nodeId{0, identifier};
    auto result = addressSpace.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(result.is_good());
    result.value().set_event_notifier(notifier);
    return nodeId;
  };

  const NodeId subscribable = makeObject(8100u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId notSubscribable = makeObject(8101u, EventNotifierType{});
  const NodeId eventSource = makeObject(8102u, EventNotifierType{});

  auto subscribableNode = addressSpace.try_find_node_sync(subscribable);
  ASSERT_TRUE(subscribableNode.is_good());
  auto notSubscribableNode = addressSpace.try_find_node_sync(notSubscribable);
  ASSERT_TRUE(notSubscribableNode.is_good());

  // An Object that can be subscribed to may own an event source.
  EXPECT_TRUE(subscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());

  // An Object that cannot be subscribed to must not. The mutation commits - the event-graph check is not
  // on the mutation path, because Part 3 7.17 binds the address space a server presents and the
  // implementer discharges it by calling AddressSpace::validate_event_graph_async once a build is finished.
  ASSERT_TRUE(notSubscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());
  const auto verdict = addressSpace.try_validate_event_graph_sync();
  EXPECT_EQ(verdict.status_code(), Status::BadReferenceNotAllowed)
    << "a HasEventSource reference from an Object whose EventNotifier lacks SubscribeToEvents went "
       "unreported";
  ASSERT_NE(verdict.status_code().shared_detail(), nullptr);
  EXPECT_EQ(verdict.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");

  // Removed again, so the audit below reads a graph the check accepts. The audit then remains a second,
  // independent statement of the same rule, made over what the store actually holds.
  notSubscribableNode.value().remove_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource);
  EXPECT_TRUE(addressSpace.try_validate_event_graph_sync().is_good());

  // Read the source Object's EventNotifier for every HasEventSource reference that now exists.
  const NodeId candidates[] = {subscribable, notSubscribable, eventSource};
  size_t hasEventSourceReferences = 0;
  for (const auto& candidate : candidates)
  {
    auto nodeResult = addressSpace.try_find_node_sync(candidate);
    ASSERT_TRUE(nodeResult.is_good());
    auto object = nodeResult.value().as<ObjectAccessor>();
    ASSERT_TRUE(object);

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;

      ++hasEventSourceReferences;
      EXPECT_TRUE(object->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        << "a HasEventSource reference originates from an Object that cannot be subscribed to";
    }
  }

  ASSERT_GT(hasEventSourceReferences, 0u)
    << "no HasEventSource reference was materialised at all - the bit audit would be vacuous";

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.5.1 Table 11: a HasNotifier reference may only be used from an Object whose EventNotifier
// carries the SubscribeToEvents bit. It is the symmetric half of the HasEventSource rule above, and a
// mutator that guards one and not the other is the realistic failure: HasNotifier is the reference the
// event pipeline itself walks, so a link sourced from an Object nothing can subscribe to builds a
// notifier hierarchy whose intermediate node can never carry a MonitoredItem. The audit over the
// references that were actually materialised is asserted non-empty first, so a mutator that refuses
// everything cannot pass it.
// @verifies AC-SVR-EVT-ATTR-003-HASNOTIFIER-NOTIFIER-BIT
TEST(EventNotifierReferenceInvariantTest, HasNotifierOriginatesOnlyFromObjectsThatCanBeSubscribedTo)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  auto makeObject = [&addressSpace](uint32_t identifier, EventNotifierType notifier)
  {
    const NodeId nodeId{0, identifier};
    auto result = addressSpace.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(result.is_good());
    result.value().set_event_notifier(notifier);
    return nodeId;
  };

  const NodeId subscribable = makeObject(8200u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId notSubscribable = makeObject(8201u, EventNotifierType{});
  const NodeId notifierTarget =
    makeObject(8202u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  auto subscribableNode = addressSpace.try_find_node_sync(subscribable);
  ASSERT_TRUE(subscribableNode.is_good());
  auto notSubscribableNode = addressSpace.try_find_node_sync(notSubscribable);
  ASSERT_TRUE(notSubscribableNode.is_good());

  // An Object that can be subscribed to may point at a notifier.
  EXPECT_TRUE(subscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, notifierTarget)
                .is_good());

  // An Object that cannot be subscribed to must not. The mutation commits - the event-graph check is not
  // on the mutation path, because Part 3 7.17 binds the address space a server presents and the
  // implementer discharges it by calling AddressSpace::validate_event_graph_async once a build is finished.
  ASSERT_TRUE(notSubscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, notifierTarget)
                .is_good());
  const auto rejected = addressSpace.try_validate_event_graph_sync();
  EXPECT_TRUE(rejected.is_bad())
    << "a HasNotifier reference from an Object whose EventNotifier lacks SubscribeToEvents went "
       "unreported";
  EXPECT_EQ(rejected.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejected.status_code().shared_detail(), nullptr);
  EXPECT_EQ(rejected.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");

  // Removed again, so the audit below reads a graph the check accepts, and remains a second independent
  // statement of the same rule over what the store actually holds.
  notSubscribableNode.value().remove_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, notifierTarget);
  EXPECT_TRUE(addressSpace.try_validate_event_graph_sync().is_good());

  // Read the source Object's EventNotifier for every HasNotifier reference that now exists.
  const NodeId candidates[] = {subscribable, notSubscribable, notifierTarget};
  size_t hasNotifierReferences = 0;
  for (const auto& candidate : candidates)
  {
    auto nodeResult = addressSpace.try_find_node_sync(candidate);
    ASSERT_TRUE(nodeResult.is_good());
    auto object = nodeResult.value().as<ObjectAccessor>();
    ASSERT_TRUE(object);

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasNotifier})
        continue;

      ++hasNotifierReferences;
      EXPECT_TRUE(object->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        << "a HasNotifier reference originates from an Object that cannot be subscribed to";
    }
  }

  ASSERT_GT(hasNotifierReferences, 0u)
    << "no HasNotifier reference was materialised at all - the bit audit would be vacuous";

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 7.18: every HasNotifier target shall be a subscribable Object, in either storage direction.
// @relation(AC-SVR-ADDRSP-173-HASNOTIFIER-TARGET-SUBSCRIBABLE, scope=function)
TEST(EventNotifierReferenceInvariantTest, HasNotifierTargetsAreSubscribableObjectsWhicheverEndAddsThem)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  auto targetNamespace = default_ns::Namespace::create("uri:target", threadPool.get_executor());
  const uint16_t targetNamespaceIndex = addressSpace.add_namespace_sync(std::move(targetNamespace));

  auto makeObject = [&addressSpace](uint32_t identifier, EventNotifierType notifier)
  {
    const NodeId nodeId{0, identifier};
    auto result = addressSpace.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(result.is_good());
    result.value().set_event_notifier(notifier);
    return nodeId;
  };

  const auto subscribable = EventNotifierType{EventNotifierType::Bit::SubscribeToEvents};
  const NodeId source = makeObject(8210u, subscribable);
  const NodeId validTarget{targetNamespaceIndex, uint32_t{8211}};
  const NodeId nonSubscribableTarget{targetNamespaceIndex, uint32_t{8212}};
  const NodeId variableTarget{targetNamespaceIndex, uint32_t{8213}};
  ASSERT_TRUE(addressSpace.try_create_sync<ObjectAccessor>(validTarget, NodeClass::Object).is_good());
  ASSERT_TRUE(
    addressSpace.try_create_sync<ObjectAccessor>(nonSubscribableTarget, NodeClass::Object).is_good());
  ASSERT_TRUE(addressSpace.try_create_sync<VariableAccessor>(variableTarget, NodeClass::Variable).is_good());

  addressSpace.find_node_sync(validTarget)
    .as<ObjectAccessor>()
    ->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  addressSpace.find_node_sync(nonSubscribableTarget)
    .as<ObjectAccessor>()
    ->set_event_notifier(EventNotifierType{});

  auto sourceNode = addressSpace.try_find_node_sync(source);
  auto validTargetNode = addressSpace.try_find_node_sync(validTarget);
  auto nonSubscribableTargetNode = addressSpace.try_find_node_sync(nonSubscribableTarget);
  ASSERT_TRUE(sourceNode.is_good());
  ASSERT_TRUE(validTargetNode.is_good());
  ASSERT_TRUE(nonSubscribableTargetNode.is_good());

  EXPECT_TRUE(
    sourceNode.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, validTarget).is_good());
  EXPECT_TRUE(validTargetNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, source, /*isForward=*/false)
                .is_good());

  // Each illegal target is added, reported by the explicit check, then removed so the next case is judged
  // on its own graph rather than on the previous one's violation. The mutation itself no longer refuses:
  // Part 3 7.17 binds the address space a server presents, and the implementer discharges it by calling
  // AddressSpace::validate_event_graph_async once a build is finished.
  const auto expectTargetViolation =
    [&addressSpace](NodeAccessor& holder, const NodeId& target, bool isForward, string_view what)
  {
    ASSERT_TRUE(
      holder.try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, target, isForward).is_good())
      << what;
    const auto verdict = addressSpace.try_validate_event_graph_sync();
    EXPECT_EQ(verdict.status_code(), Status::BadReferenceNotAllowed) << what;
    ASSERT_NE(verdict.status_code().shared_detail(), nullptr) << what;
    EXPECT_EQ(verdict.status_code().shared_detail()->code, "EventReferenceTargetNotSubscribable") << what;
    holder.remove_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, target, isForward);
    EXPECT_TRUE(addressSpace.try_validate_event_graph_sync().is_good())
      << "removing the offending reference should leave a graph the check accepts: " << what;
  };

  expectTargetViolation(sourceNode.value(), nonSubscribableTarget, true, "forward, unsubscribable target");
  expectTargetViolation(sourceNode.value(), variableTarget, true, "forward, target is not an Object");
  expectTargetViolation(
    nonSubscribableTargetNode.value(), source, false, "inverse, added from the target end");

  // A batch commits as one overlay, so both its references land and the check judges the result. That the
  // batch is all-or-nothing is still the subject; that it is refused up front no longer is.
  const auto referencesBeforeBatch = sourceNode.value().get_references_sync();
  std::vector<Reference> batch;
  batch.emplace_back(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{validTarget}, true);
  batch.emplace_back(NodeId{ReferenceTypeId::HasNotifier}, ExpandedNodeId{nonSubscribableTarget}, true);
  ASSERT_TRUE(sourceNode.value().try_add_references_sync(std::move(batch)).is_good());
  EXPECT_EQ(sourceNode.value().get_references_sync().size(), referencesBeforeBatch.size() + 2)
    << "a batch must commit whole or not at all; a partial prefix would be the defect";
  const auto batchVerdict = addressSpace.try_validate_event_graph_sync();
  EXPECT_EQ(batchVerdict.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(batchVerdict.status_code().shared_detail(), nullptr);
  EXPECT_EQ(batchVerdict.status_code().shared_detail()->code, "EventReferenceTargetNotSubscribable");

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// --- View event aggregation ---

// Part 3 section 5.4: "A View that supports Events shall provide all Events that occur in any Object used as
// EventNotifier that is part of the content of the View." A plausible implementation resolves an
// event's notifier set by walking HasNotifier upward from the SourceNode only, so a View that merely
// CONTAINS its notifiers aggregates nothing: the MonitoredItem on the View is accepted and then never
// receives anything, and the client has no way to learn the View was incomplete. The Server-Object
// consumer is the control - it proves both events really entered the routing pipeline, so a failure on
// the View consumer cannot be blamed on the stimulus. Both contained notifiers are asserted separately
// because "all Events" is the obligation and delivering one of two would otherwise read as a pass.
// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
// @relation(AC-SVR-ADDRSP-077-VIEW-SURFACES-CONTAINED-EVENTS, scope=function)
TEST(ViewEventAggregationTest, ViewSupportingEventsDeliversTheEventsOfEveryNotifierItContains)
{
  boost::asio::thread_pool tp;
  auto addressSpace = AddressSpace::create("uri:test", tp.get_executor());

  const EventNotifierType subscribable{EventNotifierType::Bit::SubscribeToEvents};

  auto serverResult = addressSpace.try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
  ASSERT_TRUE(serverResult.is_good());
  serverResult.value().set_event_notifier(subscribable);

  const NodeId notifierA{0, 8300u};
  const NodeId notifierB{0, 8301u};
  auto notifierAResult = addressSpace.try_create_sync<ObjectAccessor>(notifierA, NodeClass::Object);
  ASSERT_TRUE(notifierAResult.is_good());
  notifierAResult.value().set_event_notifier(subscribable);
  auto notifierBResult = addressSpace.try_create_sync<ObjectAccessor>(notifierB, NodeClass::Object);
  ASSERT_TRUE(notifierBResult.is_good());
  notifierBResult.value().set_event_notifier(subscribable);

  // A View that supports Events, whose content is exactly those two notifier Objects.
  const NodeId viewId{0, 8302u};
  auto viewResult = addressSpace.try_create_sync<ViewAccessor>(viewId, NodeClass::View);
  ASSERT_TRUE(viewResult.is_good());
  viewResult.value().set_event_notifier(subscribable);

  auto viewNode = addressSpace.try_find_node_sync(viewId);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(
    viewNode.value().try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, notifierA).is_good());
  ASSERT_TRUE(
    viewNode.value().try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, notifierB).is_good());
  // The content of a View is its membership (NR-16, NR-28 rule 1): the two notifiers are members.
  ASSERT_TRUE(viewResult.value().try_add_node_to_view_sync(notifierA).is_good());
  ASSERT_TRUE(viewResult.value().try_add_node_to_view_sync(notifierB).is_good());

  auto bus = std::make_shared<EventBus>(addressSpace);

  std::mutex deliveryMutex;
  std::condition_variable deliveryCv;
  std::vector<NodeId> viewSources;
  std::vector<NodeId> serverSources;

  constexpr IntegerId viewItemId{1};
  constexpr IntegerId serverItemId{2};
  constexpr uint32_t subscriptionId{0};

  auto viewHandle = bus->register_event_item(viewId,
    viewItemId,
    subscriptionId,
    [&](IntegerId, std::shared_ptr<const BaseEvent> event)
    {
      std::lock_guard lock(deliveryMutex);
      viewSources.push_back(event->sourceNode);
      deliveryCv.notify_all();
    });
  auto serverHandle = bus->register_event_item(serverObjectId,
    serverItemId,
    subscriptionId,
    [&](IntegerId, std::shared_ptr<const BaseEvent> event)
    {
      std::lock_guard lock(deliveryMutex);
      serverSources.push_back(event->sourceNode);
      deliveryCv.notify_all();
    });
  EXPECT_NE(viewHandle, 0u);
  EXPECT_NE(serverHandle, 0u);
  EXPECT_TRUE(bus->has_event_interest());

  // The registry inserts are posted to the bus strand; this strand-ordered read lands after both, so
  // the emits below cannot race the registrations.
  std::promise<bool> registered;
  bus->resolve_event_item_node_async(subscriptionId,
    serverItemId,
    [&registered](std::optional<NodeId> node) { registered.set_value(node.has_value()); });
  auto registeredFuture = registered.get_future();
  ASSERT_EQ(registeredFuture.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "the bus never answered the registration probe";
  ASSERT_TRUE(registeredFuture.get()) << "the event MonitoredItems never became visible to the bus";

  // Raise one event on EACH notifier Object inside the View.
  BaseEvent eventA;
  eventA.eventType = NodeId{ObjectTypeId::BaseEventType};
  eventA.sourceNode = notifierA;
  eventA.sourceName = "ViewNotifierA";
  eventA.message = LocalizedText{"", "event raised on the first notifier in the View"};
  eventA.severity = 100;
  bus->emit(eventA);

  BaseEvent eventB;
  eventB.eventType = NodeId{ObjectTypeId::BaseEventType};
  eventB.sourceNode = notifierB;
  eventB.sourceName = "ViewNotifierB";
  eventB.message = LocalizedText{"", "event raised on the second notifier in the View"};
  eventB.severity = 100;
  bus->emit(eventB);

  auto contains = [](const std::vector<NodeId>& seen, const NodeId& source)
  {
    return std::find(seen.begin(), seen.end(), source) != seen.end();
  };

  {
    // Control: both events reached the routing pipeline at all (the Server Object is the root
    // notifier). Without this the View assertions below could not distinguish a lost stimulus from a
    // View that aggregates nothing.
    std::unique_lock<std::mutex> lock(deliveryMutex);
    ASSERT_TRUE(deliveryCv.wait_for(lock,
      std::chrono::seconds{2},
      [&] { return contains(serverSources, notifierA) && contains(serverSources, notifierB); }))
      << "the raised events never reached the Server Object notifier - the stimulus never happened";
  }

  {
    std::unique_lock<std::mutex> lock(deliveryMutex);
    deliveryCv.wait_for(lock,
      std::chrono::seconds{2},
      [&] { return contains(viewSources, notifierA) && contains(viewSources, notifierB); });

    ASSERT_FALSE(serverSources.empty());
    EXPECT_TRUE(contains(viewSources, notifierA))
      << "the View did not provide the Events of the first notifier Object in its content";
    EXPECT_TRUE(contains(viewSources, notifierB))
      << "the View did not provide the Events of the second notifier Object in its content";
  }

  bus->deregister_event_item(viewHandle);
  bus->deregister_event_item(serverHandle);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Update audit source taxonomy (Write / HistoryUpdate) ---

namespace
{

/// Minimal history delegate that accepts a value-history update batch.
///
/// The audit obligation only bites on an update that actually ran, so the delegate answers Good per
/// value rather than leaning on the base class's `BadHistoryOperationUnsupported` default.
class UpdateSourceHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  void update_data_async(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      for (size_t valueIndex = 0; valueIndex < item.values.size(); ++valueIndex)
        success.operationResults.push_back(Status::Good);
      batch.items.emplace_back(std::move(success));
    }
    callback(std::move(batch));
  }
};

/// A namespace that offers history, so a HistoryUpdate reaches the per-item audit site at all.
class UpdateSourceNamespace : public default_ns::Namespace,
                              public std::enable_shared_from_this<UpdateSourceNamespace>
{
public:
  UpdateSourceNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<UpdateSourceHistoryDelegate> mDelegate = std::make_shared<UpdateSourceHistoryDelegate>();
};

/// A test-local namespace where a request alias resolves to a Node whose own NodeId is canonical.
/// This isolates AttributeServiceSet's audit choice from RegisterNodesService; the focused integration
/// arm supplies the complete RegisterNodes -> Write -> Audit path.
class AliasResolvingNamespace : public default_ns::Namespace
{
public:
  AliasResolvingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  NodeId add_alias(const NodeId& canonical)
  {
    NodeId alias{canonical.namespace_index(), mNextAlias++};
    std::lock_guard lock(mMutex);
    mAliasToCanonical.emplace(to_string(alias), canonical);
    return alias;
  }

  /// What resolution MEANS for this namespace: an alias resolves to its canonical node.
  ///
  /// Overridden here rather than in `find_nodes` so that BOTH routes obey it - the synchronous fast
  /// lane the AddressSpace asks first, and the batch it falls back to. Putting it in `find_nodes`
  /// compiled and passed nothing: the fast lane answered straight past the alias map and the write
  /// came back BadNodeIdInvalid from a namespace that had the node.
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    NodeId resolved = nodeId;
    {
      std::lock_guard lock(mMutex);
      if (const auto alias = mAliasToCanonical.find(to_string(nodeId)); alias != mAliasToCanonical.end())
        resolved = alias->second;
    }
    return default_ns::Namespace::resolve_here(resolved);
  }

private:
  mutable std::mutex mMutex;
  std::map<std::string, NodeId> mAliasToCanonical;
  uint32_t mNextAlias{990000};
};

/// An EventBus that records the identity of every event handed to it and then runs the real dispatch.
///
/// The services under test cast their EventSink to `EventBus*` before consulting the interest gate, so
/// the recorder has to BE an EventBus rather than merely implement EventSink.
class UpdateAuditRecordingBus : public EventBus
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    String sourceName;
    bool isWriteUpdateAudit{false};
    bool isHistoryUpdateAudit{false};
  };

  explicit UpdateAuditRecordingBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    {
      std::lock_guard lock(mMutex);
      Record record;
      record.eventType = event.eventType;
      record.sourceNode = event.sourceNode;
      record.sourceName = event.sourceName;
      record.isWriteUpdateAudit = dynamic_cast<const AuditWriteUpdateEventPayload*>(&event) != nullptr;
      record.isHistoryUpdateAudit = dynamic_cast<const AuditHistoryUpdateEventPayload*>(&event) != nullptr;
      mRecords.push_back(std::move(record));
    }
    EventBus::emit(event);
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

}  // namespace

// Part 5 section 6.4.24 lines 2749-2752 and section 6.4.25 lines 2774-2775: "The SourceNode Property for
// Events of this type shall be assigned to the NodeId that was changed. The SourceName ... shall be
// 'Attribute/' and the Service that generated the event." This is the exception to the channel/session rule
// the rest of this file pins, where SourceNode is the Server Object - an auditor asking what changed a
// particular Variable filters on exactly this field. A shared emit helper that stamps the Server
// Object on every audit event gets the channel family right and both update families wrong while
// still emitting the correct event types, so SourceNode is read per service and compared against the
// Server Object as well as against the changed Node.
// @verifies AC-SVR-AUDIT-019-UPDATE-SOURCE
TEST(AuditUpdateSourceTest, UpdateAuditNamesTheChangedNodeAndTheServiceThatChangedIt)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto historyNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-update-source", pool.get_executor());
  addressSpace.add_namespace_sync(historyNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-update-source");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the history-bearing namespace was not registered";

  auto bus = std::make_shared<UpdateAuditRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId writtenNode{nsIndex, 9400u};
  auto writtenResult = nodes.try_create_sync<VariableAccessor>(writtenNode, NodeClass::Variable);
  ASSERT_TRUE(writtenResult.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    writtenResult.value().set_access_level(accessLevel);
  }

  const NodeId historisedNode{nsIndex, 9401u};
  auto historisedResult = nodes.try_create_sync<VariableAccessor>(historisedNode, NodeClass::Variable);
  ASSERT_TRUE(historisedResult.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::HistoryRead);
    accessLevel.set(AccessLevelType::Bit::HistoryWrite);
    historisedResult.value().set_access_level(accessLevel);
  }

  // --- Write ---
  WriteRequest writeRequest;
  writeRequest.request_header().request_handle() = 1;
  WriteValue writeValue;
  writeValue.node_id() = writtenNode;
  writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeValue.value().value() = Variant{int32_t{42}};
  writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));

  std::promise<Response> writeDone;
  auto writeFuture = writeDone.get_future();
  auto writeService = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    pool.get_executor(),
    [&writeDone](Response response) { writeDone.set_value(std::move(response)); });
  (void)writeService;
  ASSERT_EQ(writeFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the Write service never completed, so it never reached the audit site";
  auto writeResponseHolder = writeFuture.get();
  auto* writeResponse =
    dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(writeResponseHolder).get());
  ASSERT_NE(writeResponse, nullptr) << "the Write faulted at service level and never changed a Node";
  ASSERT_EQ(writeResponse->results().size(), 1u);
  ASSERT_TRUE(writeResponse->results()[0].is_good())
    << "the Write was refused, so no Node changed and the audit obligation never bit";

  // --- HistoryUpdate ---
  HistoryUpdateRequest historyRequest;
  historyRequest.request_header().request_handle() = 2;
  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = historisedNode;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  DataValue historisedValue;
  historisedValue.value() = 42;
  updateDetails->update_values().resize(1);
  updateDetails->update_values()[0] = std::move(historisedValue);
  historyRequest.history_update_details().resize(1);
  historyRequest.history_update_details()[0] = std::move(updateDetails);

  std::promise<Response> historyDone;
  auto historyFuture = historyDone.get_future();
  auto historyService = HistoryUpdateService::create(sessionInfo,
    2,
    std::move(historyRequest),
    pool.get_executor(),
    [&historyDone](Response response) { historyDone.set_value(std::move(response)); });
  (void)historyService;
  ASSERT_EQ(historyFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the HistoryUpdate service never completed, so it never reached the audit site";
  auto historyResponseHolder = historyFuture.get();
  auto* historyResponse =
    dynamic_cast<HistoryUpdateResponse*>(std::get<shared_ptr<Structure>>(historyResponseHolder).get());
  ASSERT_NE(historyResponse, nullptr)
    << "the HistoryUpdate faulted at service level and never reached the per-item audit site";
  ASSERT_EQ(historyResponse->results().size(), 1u);
  ASSERT_TRUE(historyResponse->results()[0].status_code().is_good())
    << "the HistoryUpdate was refused, so no Node's history changed";

  const auto records = bus->records();
  ASSERT_FALSE(records.empty()) << "neither the Write nor the HistoryUpdate raised any audit Event";

  const UpdateAuditRecordingBus::Record* writeAudit = nullptr;
  const UpdateAuditRecordingBus::Record* historyAudit = nullptr;
  for (const auto& record : records)
  {
    if (record.isWriteUpdateAudit && writeAudit == nullptr)
      writeAudit = &record;
    if (record.isHistoryUpdateAudit && historyAudit == nullptr)
      historyAudit = &record;
  }

  ASSERT_NE(writeAudit, nullptr) << "the Write raised no AuditWriteUpdateEvent";
  EXPECT_EQ(writeAudit->sourceNode, writtenNode) << "the Write audit does not name the Node that changed";
  EXPECT_NE(writeAudit->sourceNode, serverObjectId) << "the Write audit named the Server Object";
  EXPECT_EQ(writeAudit->sourceName, "Attribute/Write") << "SourceName must be exactly 'Attribute/Write'";

  ASSERT_NE(historyAudit, nullptr) << "the HistoryUpdate raised no AuditHistoryUpdateEvent";
  EXPECT_EQ(historyAudit->sourceNode, historisedNode)
    << "the HistoryUpdate audit does not name the Node whose history changed";
  EXPECT_NE(historyAudit->sourceNode, serverObjectId) << "the HistoryUpdate audit named the Server Object";
  EXPECT_EQ(historyAudit->sourceName, "Attribute/HistoryUpdate")
    << "SourceName must be exactly 'Attribute/HistoryUpdate'";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 5.8.5.1: audit records use the canonical NodeId Attribute value, never a registered
// Session-scoped alias. The alias resolves through the real AddressSpace lookup to the same
// NodeAccessor, so this unit arm distinguishes the request identity from the resolved Node identity
// at AttributeServiceSet's audit site. The focused integration control proves RegisterNodes supplies
// the alias in production.
// @verifies AC-SVR-VIEW-REG-003-AUDIT-CANONICAL-ID
TEST(AuditUpdateSourceTest, WriteThroughAnAliasAuditsTheResolvedCanonicalNodeId)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto aliasingNamespace =
    std::make_shared<AliasResolvingNamespace>("uri:test:audit-write-alias", pool.get_executor());
  addressSpace.add_namespace_sync(aliasingNamespace);
  const auto namespaceIndex =
    addressSpace.namespace_array().get_namespace_index("uri:test:audit-write-alias");
  ASSERT_NE(namespaceIndex, uint16_t{0});

  const NodeId canonicalNodeId{namespaceIndex, 9500u};
  auto variableResult = addressSpace.try_create_sync<VariableAccessor>(canonicalNodeId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  AccessLevelType accessLevel;
  accessLevel.set(AccessLevelType::Bit::CurrentRead);
  accessLevel.set(AccessLevelType::Bit::CurrentWrite);
  variableResult.value().set_access_level(accessLevel);
  const NodeId aliasNodeId = aliasingNamespace->add_alias(canonicalNodeId);
  ASSERT_NE(aliasNodeId, canonicalNodeId);

  auto bus = std::make_shared<UpdateAuditRecordingBus>(addressSpace);
  bus->set_event_listener([](const BaseEvent&) {});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();

  WriteRequest writeRequest;
  writeRequest.request_header().request_handle() = 1;
  WriteValue writeValue;
  writeValue.node_id() = aliasNodeId;
  writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeValue.value().value() = Variant{int32_t{42}};
  writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));

  std::promise<Response> writeDone;
  auto writeFuture = writeDone.get_future();
  auto writeService = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    pool.get_executor(),
    [&writeDone](Response response) { writeDone.set_value(std::move(response)); });
  (void)writeService;
  ASSERT_EQ(writeFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready);
  auto responseHolder = writeFuture.get();
  auto* response = dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(responseHolder).get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto writeStatus = response->results()[0];
  ASSERT_TRUE(writeStatus.is_good()) << "Write status: " << writeStatus.as_uint32();

  const auto records = bus->records();
  const auto audit = std::ranges::find_if(
    records, [](const UpdateAuditRecordingBus::Record& record) { return record.isWriteUpdateAudit; });
  ASSERT_NE(audit, records.end());
  EXPECT_EQ(audit->sourceNode, canonicalNodeId);
  EXPECT_NE(audit->sourceNode, aliasNodeId);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// --- TransferSubscriptions audit ---

namespace
{

/// Minimal SessionSecurityContext for the transfer pipelines: the identity is swappable so the same
/// target session can be refused a Subscription and then granted one.
class TransferAuditSecurityContext : public SessionSecurityContext
{
public:
  ua::NodeId session_id() const override
  {
    return sessionId;
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return endpointSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return userIdentity;
  }

  ua::NodeId sessionId;
  std::shared_ptr<const EndpointSecurityContext> endpointSecurity{
    std::make_shared<EndpointSecurityContext>()};
  std::shared_ptr<const UserIdentity> userIdentity{std::make_shared<UserIdentity>()};
};

}  // namespace

// Part 4 section 6.5.10: a TransferSubscriptions call shall raise an AuditSessionEventType Event or a
// subtype, for the attempt that fails as much as for the one that succeeds. A transfer moves a Subscription
// between Sessions - it moves data between identities - which is why the refused attempt, a client
// reaching for a Subscription owned by another user, is the security-relevant record and exactly the
// one a plausible implementation loses by hanging the emit off the success branch. The event type is
// read as well as the source name, because an implementation that reports the transfer as a plain
// BaseEvent or as a non-session audit subtype leaves the record outside every AuditSessionEventType
// filter an auditor subscribes with.
// @verifies AC-SVR-AUDIT-010-TRANSFER-AUDIT
TEST(TransferSubscriptionsAuditTest, TransferSubscriptionsAuditsBothOutcomesAsSessionAuditEvents)
{
  boost::asio::thread_pool pool;
  SubscriptionIdAllocator idAllocator;
  SubscriptionRouter router;
  OrphanedSubscriptionStore orphanStore;
  auto counters = std::make_shared<ServerSummaryCounters>();

  // Session placeholders used only for registry ownership - never dereferenced.
  auto sessionA = make_session_registry_placeholder();
  auto sessionB = make_session_registry_placeholder();

  auto secCtxA = std::make_shared<TransferAuditSecurityContext>();
  auto secCtxB = std::make_shared<TransferAuditSecurityContext>();
  secCtxA->userIdentity =
    std::make_shared<const UserIdentity>(UserIdentity{.userId = "testUser", .kind = UserTokenKind::UserName});
  secCtxB->userIdentity =
    std::make_shared<const UserIdentity>(UserIdentity{.userId = "testUser", .kind = UserTokenKind::UserName});

  std::mutex mutexA;
  std::condition_variable cvA;
  std::vector<Response> responsesA;
  std::mutex mutexB;
  std::condition_variable cvB;
  std::vector<Response> responsesB;

  auto addressSpace = AddressSpace::create("urn:test:transfer-audit", pool.get_executor());
  auto bus = std::make_shared<EventBus>(addressSpace);

  // Owned by the listener so a late dispatch cannot reference dead test locals.
  struct TransferAuditSink
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<bool> statuses;
    std::vector<bool> isSessionAudit;
    std::vector<NodeId> eventTypes;
  };

  auto sink = std::make_shared<TransferAuditSink>();

  // Selected by SourceName alone, so whether the record is an AuditSessionEventType at all stays an
  // observation rather than a precondition of the filter.
  bus->set_event_listener(
    [sink](const BaseEvent& event)
    {
      if (event.sourceName != "Session/TransferSubscriptions")
        return;
      {
        std::lock_guard lk(sink->mutex);
        const auto* audit = dynamic_cast<const AuditSessionEventPayload*>(&event);
        sink->isSessionAudit.push_back(audit != nullptr);
        sink->statuses.push_back(audit != nullptr && audit->status);
        sink->eventTypes.push_back(event.eventType);
      }
      sink->cv.notify_all();
    });
  ASSERT_TRUE(bus->has_event_interest());

  auto executor = pool.get_executor();
  auto mgrA = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = executor,
    .sessionStrand = boost::asio::make_strand(executor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = counters,
    .sendResponse =
      [&mutexA, &cvA, &responsesA](Response r)
    {
      std::lock_guard lk(mutexA);
      responsesA.push_back(std::move(r));
      cvA.notify_all();
    },
    .subscriptionRouter = router.weak(),
    .orphanedSubscriptionStore = orphanStore.weak(),
    .owningSession = sessionA,
    .securityContext = secCtxA,
  });

  auto mgrB = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = executor,
    .sessionStrand = boost::asio::make_strand(executor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = counters,
    .sendResponse =
      [&mutexB, &cvB, &responsesB](Response r)
    {
      std::lock_guard lk(mutexB);
      responsesB.push_back(std::move(r));
      cvB.notify_all();
    },
    .subscriptionRouter = router.weak(),
    .orphanedSubscriptionStore = orphanStore.weak(),
    .owningSession = sessionB,
    .securityContext = secCtxB,
    .eventBus = bus,
    .auditingEnabled = true,
    .applicationUri = "urn:test:transfer-audit",
  });

  auto createSubscriptionOnA = [&]() -> IntegerId
  {
    size_t base = 0;
    {
      std::lock_guard lk(mutexA);
      base = responsesA.size();
    }
    CreateSubscriptionRequest request;
    request.requested_publishing_interval() = 1000;
    request.requested_lifetime_count() = 30;
    request.requested_max_keep_alive_count() = 10;
    request.max_notifications_per_publish() = 0;
    request.publishing_enabled() = true;
    request.priority() = 0;
    mgrA->handle_create_subscription(1, request);

    std::unique_lock<std::mutex> lk(mutexA);
    EXPECT_TRUE(cvA.wait_for(lk, std::chrono::seconds{2}, [&] { return responsesA.size() > base; }))
      << "CreateSubscription produced no response";
    if (responsesA.size() <= base)
      return IntegerId{0};
    auto* response =
      dynamic_cast<CreateSubscriptionResponse*>(std::get<shared_ptr<Structure>>(responsesA.back()).get());
    EXPECT_NE(response, nullptr) << "CreateSubscription faulted";
    return response != nullptr ? response->subscription_id() : IntegerId{0};
  };

  const IntegerId refusedId = createSubscriptionOnA();
  const IntegerId grantedId = createSubscriptionOnA();
  ASSERT_NE(refusedId, IntegerId{0});
  ASSERT_NE(grantedId, IntegerId{0});

  // Both Subscriptions belong to "otherUser"; session B authenticates as "testUser" for now.
  const UserIdentity owner{.userId = "otherUser", .kind = UserTokenKind::UserName};
  mgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});
  ASSERT_TRUE(orphanStore.contains(refusedId));
  ASSERT_TRUE(orphanStore.contains(grantedId));

  auto waitForAudits = [&sink](size_t count)
  {
    std::unique_lock<std::mutex> lk(sink->mutex);
    return sink->cv.wait_for(
      lk, std::chrono::seconds{2}, [&sink, count] { return sink->statuses.size() >= count; });
  };

  auto runTransfer = [&](uint32_t requestId, IntegerId subscriptionId) -> StatusCode
  {
    size_t base = 0;
    {
      std::lock_guard lk(mutexB);
      base = responsesB.size();
    }
    TransferSubscriptionsRequest request;
    request.subscription_ids().push_back(subscriptionId);
    mgrB->handle_transfer_subscriptions(requestId, request);

    std::unique_lock<std::mutex> lk(mutexB);
    EXPECT_TRUE(cvB.wait_for(lk, std::chrono::seconds{2}, [&] { return responsesB.size() > base; }))
      << "TransferSubscriptions produced no response";
    if (responsesB.size() <= base)
      return StatusCode{Status::BadInternalError};
    auto* response =
      dynamic_cast<TransferSubscriptionsResponse*>(std::get<shared_ptr<Structure>>(responsesB.back()).get());
    EXPECT_NE(response, nullptr) << "TransferSubscriptions faulted at service level";
    if (response == nullptr || response->results().size() != 1u)
      return StatusCode{Status::BadInternalError};
    return StatusCode{response->results()[0].status_code()};
  };

  // 1. Refused: claiming another user's Subscription. The refusal comes from the transfer
  //    authorization inside the pipeline, not from the fixture.
  ASSERT_EQ(runTransfer(1, refusedId), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(waitForAudits(1)) << "a refused TransferSubscriptions raised no audit Event";

  // 2. Accepted: the owning user asks for the other Subscription.
  secCtxB->userIdentity = std::make_shared<const UserIdentity>(
    UserIdentity{.userId = "otherUser", .kind = UserTokenKind::UserName});
  ASSERT_EQ(runTransfer(2, grantedId), StatusCode{Status::Good});
  ASSERT_TRUE(mgrB->has_subscription(grantedId));
  EXPECT_TRUE(waitForAudits(2)) << "a successful TransferSubscriptions raised no audit Event";

  {
    std::lock_guard lk(sink->mutex);
    ASSERT_EQ(sink->statuses.size(), 2u) << "both outcomes must be audited";
    ASSERT_EQ(sink->isSessionAudit.size(), 2u);
    ASSERT_EQ(sink->eventTypes.size(), 2u);
    EXPECT_TRUE(sink->isSessionAudit[0])
      << "the refused transfer's audit record is not an AuditSessionEventType or a subtype";
    EXPECT_TRUE(sink->isSessionAudit[1])
      << "the successful transfer's audit record is not an AuditSessionEventType or a subtype";
    EXPECT_FALSE(sink->eventTypes[0].is_null()) << "the refused transfer's audit carries no EventType";
    EXPECT_FALSE(sink->eventTypes[1].is_null()) << "the successful transfer's audit carries no EventType";
    EXPECT_FALSE(sink->statuses[0]) << "the refused transfer must be audited as a failure";
    EXPECT_TRUE(sink->statuses[1]) << "the successful transfer must be audited as a success";
  }

  mgrA.reset();
  mgrB.reset();
  sessionA.reset();
  sessionB.reset();
  orphanStore.clear();
  ::ua::test_utils::drain_with_timeout(pool);
}

// --- Session-termination SourceName taxonomy ---

// Part 5 section 6.4.7: a session-termination audit Event's SourceName names how the Session ended -
// `Session/CloseSession` for a client that said goodbye, `Session/Timeout` for one that stopped
// answering. Both terminations produce an AuditSessionEventType carrying the same SessionId, so
// SourceName is the only field that separates a tidy client from an abandoned one; a shared close
// helper that stamps one generic string satisfies every other session-audit obligation in this file
// and erases that distinction, which is why the two names are also compared against each other.
// @verifies AC-SVR-EVT-AUD-012-SESSION-SOURCENAMES
TEST_F(AuditEventEmitterTest, SessionTerminationAuditNamesTheCauseInSourceName)
{
  mEmitter->on_session_closed(make_session_info("TidyClient"), StatusCode{Status::Good});
  mEmitter->on_session_timed_out(make_session_info("AbandonedClient"));

  ASSERT_EQ(mCollector.count(), 2u);
  const auto& closed = mCollector.get<AuditSessionEventPayload>(0);
  const auto& timedOut = mCollector.get<AuditSessionEventPayload>(1);

  EXPECT_EQ(closed.sourceName, "Session/CloseSession");
  EXPECT_EQ(timedOut.sourceName, "Session/Timeout");
  EXPECT_NE(closed.sourceName, timedOut.sourceName)
    << "both terminations were audited under a single generic SourceName";
}

// --- Session lifecycle audits driven through the real Session shell ---
//
// The AuditEventEmitter tests above call the ServerObserver hooks directly, which pins the mapping
// from a hook to an audit Event but cannot say whether the server ever calls the hook. The two
// obligations below are about exactly that - a Session that ended without a client asking, and a
// CreateSession the server refused - so both drive a real `Session` over a real `SecureChannel` with
// the production `AuditEventEmitter` registered as the server's observer. The dependency doubles are
// the ones the Session constructor consumes, mirroring the recipe already exercised in
// tests/unit/server/core/server_event_handler_tests.cpp.

namespace
{

/// Thread-safe audit sink: the session shell emits from its own strand and from a destructor.
class SessionAuditRecorder : public EventSink
{
public:
  struct Record
  {
    NodeId eventType;
    String sourceName;
    bool isSessionAudit{false};
    bool isCreateSessionAudit{false};
    bool isActivateSessionAudit{false};
    bool status{false};
  };

  void emit(BaseEvent& event) override
  {
    Record record;
    record.eventType = event.eventType;
    record.sourceName = event.sourceName;
    if (const auto* audit = dynamic_cast<const AuditEventPayload*>(&event))
      record.status = audit->status;
    record.isSessionAudit = dynamic_cast<const AuditSessionEventPayload*>(&event) != nullptr;
    record.isCreateSessionAudit = dynamic_cast<const AuditCreateSessionEventPayload*>(&event) != nullptr;
    record.isActivateSessionAudit = dynamic_cast<const AuditActivateSessionEventPayload*>(&event) != nullptr;
    {
      std::lock_guard lock(mMutex);
      mRecords.push_back(std::move(record));
    }
    mCv.notify_all();
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

  /// Waits until at least one recorded Event satisfies @p predicate.
  bool wait_for_audit(const std::function<bool(const Record&)>& predicate) const
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCv.wait_for(lock,
      std::chrono::seconds{2},
      [this, &predicate] { return std::any_of(mRecords.begin(), mRecords.end(), predicate); });
  }

  /// How many Events have been recorded so far - the index a later wait is told to start from.
  size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mRecords.size();
  }

  /// Waits until at least one Event recorded at or after index @p from satisfies @p predicate.
  ///
  /// The index is what attributes an Event to the stimulus that followed it: everything the earlier
  /// phases of a test raised sits below @p from and cannot answer for what came after.
  bool wait_for_audit_from(size_t from, const std::function<bool(const Record&)>& predicate) const
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCv.wait_for(lock,
      std::chrono::seconds{2},
      [this, from, &predicate]
      {
        if (from >= mRecords.size())
          return false;
        using Difference = std::vector<Record>::difference_type;
        return std::any_of(mRecords.begin() + static_cast<Difference>(from), mRecords.end(), predicate);
      });
  }

  /// The evidence a failure message carries: how many Events arrived, and what the first one named.
  std::string summary() const
  {
    std::lock_guard lock(mMutex);
    std::string text = std::to_string(mRecords.size()) + " Events reached the audit sink";
    if (!mRecords.empty())
      text += ", the first named '" + std::string{mRecords.front().sourceName} + "'";
    return text;
  }

private:
  mutable std::mutex mMutex;
  mutable std::condition_variable mCv;
  std::vector<Record> mRecords;
};

/// Accepts every identity, so an ActivateSession reaches its success path.
class LifecycleAuditAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    completion(
      make_authn_success(UserIdentity{.userId = "anonymous", .displayName = "Anonymous", .claims = {}}));
  }
};

/// SecureChannel dependencies carrying the observer under test; everything else is unused here.
class LifecycleAuditChannelDeps final : public SecureChannelDependencies
{
public:
  LifecycleAuditChannelDeps(boost::asio::any_io_executor executor, std::shared_ptr<ServerObserver> observer)
    : mExecutor(std::move(executor)), mAppCfg(::ua::ApplicationConfig::load_default()),
      mObserver(std::move(observer))
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  void create_session(SecureChannelInfo, uint32_t, CreateSessionRequest&&) override
  {}

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
  {
    return {};
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  uint32_t get_next_secure_channel_id() override
  {
    return 1;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return mObserver;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  void remove_secure_channel(const shared_ptr<SecureChannel>&) override
  {}

private:
  boost::asio::any_io_executor mExecutor;
  ::ua::ApplicationConfig mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  std::shared_ptr<ServerObserver> mObserver;
};

/// Session dependencies carrying the observer under test; everything else is unused here.
class LifecycleAuditSessionDeps final : public SessionDependencies
{
public:
  LifecycleAuditSessionDeps(boost::asio::any_io_executor executor, ServerComponents hooks,
    std::shared_ptr<ServerObserver> observer, shared_ptr<const Crypto> crypto)
    : mExecutor(std::move(executor)),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto)), mObserver(std::move(observer))
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return mCrypto;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return *mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const shared_ptr<Session>&) override
  {}

  const ::ua::server::ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return mObserver;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<RequestLatencyTracker> latency_tracker() override
  {
    return nullptr;
  }

  std::shared_ptr<ServerSummaryCounters> summary_counters() override
  {
    return nullptr;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return nullptr;
  }

  SubscriptionIdAllocator& subscription_id_allocator() override
  {
    return mSubscriptionIdAllocator;
  }

  SubscriptionRouter& subscription_router() override
  {
    return mSubscriptionRouter;
  }

  OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    return mOrphanedSubscriptionStore;
  }

  EventBus& event_bus() override
  {
    return mEventBus;
  }

  std::shared_ptr<::ua::server::EventBus> event_bus_shared() override
  {
    return {};
  }

  std::shared_ptr<NodeManagementDelegate> node_management_delegate() override
  {
    return nullptr;
  }

  optional<StatusCode> begin_identity_attempt(const ::ua::server::ClientId&, std::string_view) override
  {
    return std::nullopt;
  }

  void finish_identity_attempt(
    const ::ua::server::ClientId&, std::string_view, IdentityAttemptOutcome) override
  {}

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<ServerObserver> mObserver;
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
};

/// One live Session on one live SecureChannel, plus the responses the channel sent back.
struct SessionAuditHarness
{
  boost::asio::thread_pool threadPool;
  std::shared_ptr<LifecycleAuditChannelDeps> scDeps;
  std::shared_ptr<LifecycleAuditSessionDeps> sessDeps;
  std::shared_ptr<SecureChannel> sc;
  std::shared_ptr<Session> session;

  std::mutex mutex;
  std::condition_variable cv;
  std::optional<Response> lastResponse;

  ~SessionAuditHarness()
  {
    // Release the strand/executor-pinned members before draining: any_io_executor is work-tracking,
    // so while an impl still holds one the pool's outstanding-work count never reaches zero.
    session.reset();
    sc.reset();
    sessDeps.reset();
    scDeps.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  bool wait_for_response()
  {
    std::unique_lock<std::mutex> lock(mutex);
    return cv.wait_for(lock, std::chrono::seconds{2}, [this] { return lastResponse.has_value(); });
  }

  void clear_response()
  {
    std::lock_guard lock(mutex);
    lastResponse.reset();
  }

  std::shared_ptr<Structure> last_response_body()
  {
    std::lock_guard lock(mutex);
    return lastResponse.has_value() ? lastResponse->second : nullptr;
  }

  /// Drain the session strand so an in-flight close lambda releases its shared_ptr<Session>.
  void drain_session_strand()
  {
    if (session)
      SessionTestAccess::strand_barrier(*session);
  }
};

/// Stands up a Session whose server observer is @p observer, over a channel on @p policyId.
///
/// @p authenticator replaces the accept-everything default when a test needs the authenticated
/// identity to vary between activations; null keeps the default.
std::unique_ptr<SessionAuditHarness> make_session_audit_harness(std::shared_ptr<ServerObserver> observer,
  SecurityPolicyId policyId = SecurityPolicyId::None, ByteString clientNonce = ByteString{},
  std::shared_ptr<UserAuthenticator> authenticator = nullptr)
{
  const char* const endpointPolicyId = policyId == SecurityPolicyId::None ? "L/None" : "L/Ep";

  auto harness = std::make_unique<SessionAuditHarness>();
  auto executor = harness->threadPool.get_executor();

  harness->scDeps = std::make_shared<LifecycleAuditChannelDeps>(executor, observer);
  harness->sc = SecureChannel::create(
    harness->scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*harness->sc,
    [&](auto& g)
    {
      if (policyId == SecurityPolicyId::None)
        g.set_minimal_context_none(executor, endpointPolicyId);
      else
        g.set_minimal_context_authenticated(executor, endpointPolicyId, policyId, MessageSecurityMode::None);
    });

  SecureChannelTestAccess::on_strand(*harness->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mutex = harness->mutex, &cv = harness->cv, &last = harness->lastResponse](const Response& response)
        {
          {
            std::lock_guard lock(mutex);
            last = response;
          }
          cv.notify_all();
        });
    });

  ServerComponents hooks;
  hooks.authenticator = authenticator ? std::move(authenticator)
                                      : std::static_pointer_cast<UserAuthenticator>(
                                          std::make_shared<LifecycleAuditAuthenticator>());
  const auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  shared_ptr<const X509Certificate> clientCertificate;
  if (policyId != SecurityPolicyId::None)
  {
    Crypto::Name subject;
    subject.commonName = "Audit Client";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back("urn:test:audit-client");
    auto certificateResult = crypto->try_create_self_signed_application_instance_certificate_sync(
      subject, UtcTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    clientCertificate = std::move(certificateResult).value().second;
  }
  harness->sessDeps = std::make_shared<LifecycleAuditSessionDeps>(executor, hooks, observer, crypto);

  const auto& userTokens = SecureChannelTestAccess::on_strand(
    *harness->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); });
  SecureChannelInfo channelInfo(harness->sc->weak_from_this(),
    SecurityPolicy::create(policyId),
    MessageSecurityMode::None,
    endpointPolicyId,
    userTokens,
    clientCertificate);

  CreateSessionRequest createRequest;
  createRequest.client_nonce() = std::move(clientNonce);
  if (clientCertificate)
  {
    createRequest.client_description().application_uri() = "urn:test:audit-client";
    createRequest.client_certificate() = clientCertificate->der_encoding();
  }
  harness->session = Session::create(harness->sessDeps, channelInfo, 1, std::move(createRequest));

  // Let the create flow settle on the session strand before the caller acts on the Session.
  SessionTestAccess::strand_barrier(*harness->session);
  return harness;
}

}  // namespace

// Part 4 section 6.5.6: CloseSession shall generate an `AuditSessionEventType` Event or a subtype, and "it
// shall always be generated if a Session is terminated like Session timeout expiration or Server
// shutdown". "Always" is the hard half: the two endings no client asked for are the ones the emission
// code does not naturally sit on - a timeout fires inside a timer and a shutdown runs during
// teardown, when raising Events is the last thing an implementation is thinking about. An audit trail
// that records only orderly closes cannot tell a client that disconnected from one that was dropped,
// so all three endings are driven through the real session shell, each on its own recorder so an
// audit Event cannot be credited to the wrong ending.
//
// Attribution needs two guards, because every one of these Sessions is activated first and
// `AuditActivateSessionEventType` is itself an `AuditSessionEventType`: a bare "an AuditSessionEvent
// arrived" check would already be satisfied by the activation, and would pass on a server that
// audits no termination at all. So the Event looked for must be an `AuditSessionEventType` that is
// neither of the two subtypes the other Session services raise, AND must have been recorded after
// the activation settled.
// @verifies AC-SVR-EVT-AUD-011-CLOSESESSION-AUDIT
TEST(SessionLifecycleAuditTest, EverySessionTerminationRaisesASessionAuditEventHoweverTheSessionEnded)
{
  const auto isTerminationAudit = [](const SessionAuditRecorder::Record& record)
  {
    return record.isSessionAudit && !record.isCreateSessionAudit && !record.isActivateSessionAudit;
  };

  // Leave each Session activated, so what the terminations below end is a live Session. The response
  // slot is cleared first: the create flow may already have answered into it.
  const auto activate = [](SessionAuditHarness& harness)
  {
    harness.clear_response();
    ActivateSessionRequest activateRequest;
    activateRequest.request_header().request_handle() = 42;
    harness.session->activate(2, std::move(activateRequest), {});
    const bool answered = harness.wait_for_response();
    EXPECT_TRUE(answered) << "the Session never answered ActivateSession, so no live Session was created";
    harness.drain_session_strand();
    harness.clear_response();
    return answered;
  };

  // 1. The Session a client closed.
  {
    auto recorder = std::make_shared<SessionAuditRecorder>();
    auto emitter = std::make_shared<AuditEventEmitter>(recorder, testServerId);
    auto harness = make_session_audit_harness(emitter);
    ASSERT_NE(harness->session, nullptr) << "no Session was created to close";
    ASSERT_TRUE(activate(*harness));
    // The activation has settled on the session strand, so everything it raised is already below
    // this index and cannot be mistaken for the close audit.
    const size_t beforeTermination = recorder->count();

    CloseSessionRequest closeRequest;
    closeRequest.request_header().request_handle() = 43;
    harness->session->close(3, std::move(closeRequest));
    ASSERT_TRUE(harness->wait_for_response()) << "CloseSession produced no response";
    ASSERT_NE(dynamic_cast<CloseSessionResponse*>(harness->last_response_body().get()), nullptr)
      << "CloseSession faulted, so the Session never ended this way";

    harness->drain_session_strand();
    harness.reset();  // the server drops the closed Session, as it does in production

    EXPECT_TRUE(recorder->wait_for_audit_from(beforeTermination, isTerminationAudit))
      << "a Session closed by an explicit CloseSession raised no AuditSessionEventType: "
      << recorder->summary();
  }

  // 2. The Session that stopped answering and timed out.
  {
    auto recorder = std::make_shared<SessionAuditRecorder>();
    auto emitter = std::make_shared<AuditEventEmitter>(recorder, testServerId);
    auto harness = make_session_audit_harness(emitter);
    ASSERT_NE(harness->session, nullptr) << "no Session was created to time out";
    ASSERT_TRUE(activate(*harness));
    const size_t beforeTermination = recorder->count();

    // The inactivity deadline expiring inside the server - nobody asked for this termination.
    SessionTestAccess::on_strand(*harness->session, [](auto& g) { g.timeout(); });

    EXPECT_TRUE(recorder->wait_for_audit_from(beforeTermination, isTerminationAudit))
      << "a Session terminated by timeout expiry raised no AuditSessionEventType: " << recorder->summary();
    harness->drain_session_strand();
  }

  // 3. The Session the server terminated on its way down.
  {
    auto recorder = std::make_shared<SessionAuditRecorder>();
    auto emitter = std::make_shared<AuditEventEmitter>(recorder, testServerId);
    auto harness = make_session_audit_harness(emitter);
    ASSERT_NE(harness->session, nullptr) << "no Session was created to terminate";
    ASSERT_TRUE(activate(*harness));
    const size_t beforeTermination = recorder->count();

    // The shutdown path: every live Session is terminated and then dropped.
    harness->session->terminate_for_shutdown();
    harness->drain_session_strand();
    harness.reset();

    EXPECT_TRUE(recorder->wait_for_audit_from(beforeTermination, isTerminationAudit))
      << "a Session terminated by Server shutdown raised no AuditSessionEventType: " << recorder->summary();
  }
}

// Part 4 section 6.5.6: "The CreateSession service shall generate AuditCreateSessionEventType events or
// subtypes of it", and Part 4 section 6.5 binds that to failed Service invocations as much as successful
// ones. A refused CreateSession is a connection attempt that reached the session layer and was turned
// away - an unactivated or blocked connection is precisely what an auditor is hunting for - and it is
// the invocation an implementation drops, because the emission naturally sits where the Session
// becomes real. The control is an accepted, activated Session on the same emitter and the same
// recorder, so a missing CreateSession audit below cannot be dead wiring, and the refusal itself is
// asserted from the ServiceFault before any audit claim is made.
// @verifies AC-SVR-EVT-AUD-008-CREATESESSION-AUDIT
TEST(SessionLifecycleAuditTest, ARefusedCreateSessionRaisesTheCreateSessionAuditEvent)
{
  auto recorder = std::make_shared<SessionAuditRecorder>();
  auto emitter = std::make_shared<AuditEventEmitter>(recorder, testServerId);

  // Control: this emitter, wired this way, does reach the recorder from inside the session shell.
  {
    auto accepted = make_session_audit_harness(emitter);
    ASSERT_NE(accepted->session, nullptr) << "the control Session was never created";
    ActivateSessionRequest activateRequest;
    activateRequest.request_header().request_handle() = 42;
    accepted->session->activate(2, std::move(activateRequest), {});
    ASSERT_TRUE(recorder->wait_for_audit(
      [](const SessionAuditRecorder::Record& record) { return record.isActivateSessionAudit; }))
      << "no audit Event reached the recorder from an accepted Session - the wiring is dead, so "
         "nothing below could be observed: "
      << recorder->summary();
    accepted->drain_session_strand();
  }

  // The refused CreateSession: a 31-byte ClientNonce on an authenticated policy.
  ByteString shortNonce(31, uint8_t{0xBB});
  auto refused = make_session_audit_harness(emitter, SecurityPolicyId::Basic256Sha256, std::move(shortNonce));
  ASSERT_TRUE(refused->wait_for_response()) << "the refused CreateSession produced no response at all";
  auto* fault = dynamic_cast<ServiceFault*>(refused->last_response_body().get());
  ASSERT_NE(fault, nullptr) << "the CreateSession was accepted - the failure stimulus never happened";
  EXPECT_EQ(fault->response_header().service_result(), Status::BadNonceInvalid);
  refused->drain_session_strand();
  refused.reset();

  const auto records = recorder->records();
  size_t createSessionAudits = 0;
  size_t refusedCreateSessionAudits = 0;
  for (const auto& record : records)
  {
    if (!record.isCreateSessionAudit)
      continue;
    ++createSessionAudits;
    if (!record.status)
      ++refusedCreateSessionAudits;
  }

  EXPECT_GT(createSessionAudits, 0u) << "no CreateSession raised an AuditCreateSessionEventType at all; "
                                     << recorder->summary();
  EXPECT_GT(refusedCreateSessionAudits, 0u)
    << "a refused CreateSession raised no AuditCreateSessionEventType carrying Status false - the "
       "attempt left no trace at all; "
    << recorder->summary();
}

// --- NodeManagement / update-service audit outcomes ---

namespace
{

/// An EventBus that records the identity AND the outcome of every event handed to it, then runs the
/// real dispatch path.
///
/// The record is taken in `emit`, which is the only thing an audit producer does with an event it has
/// built, so "nothing arrived here" is the observable form of "no Event was constructed". The
/// services under test cast their EventSink to `EventBus*` before consulting the interest gate, so
/// the recorder has to BE an EventBus rather than merely implement EventSink.
class AuditOutcomeRecordingBus : public EventBus
{
public:
  struct Record
  {
    NodeId eventType;
    NodeId sourceNode;
    String sourceName;
    bool isAudit{false};
    bool status{false};
    bool isNodeManagementAudit{false};
    bool isWriteUpdateAudit{false};
    bool isHistoryUpdateAudit{false};
    Variant oldValue;
    Variant newValue;
    Variant indexRange;
  };

  explicit AuditOutcomeRecordingBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    {
      std::lock_guard lock(mMutex);
      Record record;
      record.eventType = event.eventType;
      record.sourceNode = event.sourceNode;
      record.sourceName = event.sourceName;
      if (const auto* audit = dynamic_cast<const AuditEventPayload*>(&event))
      {
        record.isAudit = true;
        record.status = audit->status;
      }
      record.isNodeManagementAudit = dynamic_cast<const AuditNodeManagementEventPayload*>(&event) != nullptr;
      if (const auto* writeAudit = dynamic_cast<const AuditWriteUpdateEventPayload*>(&event))
      {
        record.isWriteUpdateAudit = true;
        record.oldValue = writeAudit->oldValue;
        record.newValue = writeAudit->newValue;
        record.indexRange = writeAudit->indexRange;
      }
      record.isHistoryUpdateAudit = dynamic_cast<const AuditHistoryUpdateEventPayload*>(&event) != nullptr;
      mRecords.push_back(std::move(record));
    }
    EventBus::emit(event);
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

/// A node-management delegate that accepts every item the service hands it.
///
/// The audit obligation bites on the outcome the SERVICE computes, so the delegate must never be the
/// thing that fails an item: every refused invocation below is refused by the service itself, on a
/// NodeId that was never created, before the delegate is consulted at all.
class NodeManagementAuditDelegate : public NodeManagementDelegate
{
public:
  void prepare_add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddNodesItem> items,
    NodeManagementDelegate::PrepareAddNodesCallback callback) noexcept override
  {
    BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      const auto& requested = item.requested_new_node_id().node_id();
      const uint16_t destination =
        requested.is_null() ? item.parent_node_id().node_id().namespace_index() : requested.namespace_index();
      batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{destination});
    }
    callback(std::move(batch));
  }

  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    for (size_t i = 0; i < items.size(); ++i)
    {
      AddNodesResult result;
      result.status_code() = Status::Good;
      const auto& requested = items[i].item.requested_new_node_id().node_id();
      result.added_node_id() = requested.is_null() ? NodeId{items[i].destination.namespaceIndex,
                                                       static_cast<std::uint32_t>(60000u + i)}
                                                   : requested;
      batch.items.emplace_back(std::move(result));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddReferencesItem> items, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteNodesItem> items, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }
};

}  // namespace

// Part 4 section 6.5.7: AddNodes, AddReferences, DeleteNodes and DeleteReferences each raise an
// AuditNodeManagementEventType Event (or a subtype) for a successful AND for a failed invocation.
// Address-space modification is the change class with no other record - a written value can be read
// back, a deleted Node cannot - so an unaudited refusal leaves no evidence the attempt was ever made.
// The emit naturally sits on the success branch, and with four services it is enough for one of the
// eight to be wired to the wrong branch, which is why all eight are driven and counted. Every refusal
// here is the service's own (a NodeId that was never created), never the delegate's.
// @verifies AC-SVR-EVT-AUD-014-NODEMANAGEMENT-AUDIT
TEST(NodeManagementAuditTest, EveryNodeManagementServiceAuditsSuccessAndFailure)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  // A writable namespace to own the test Nodes; its history delegate is irrelevant here.
  auto writableNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-node-mgmt", pool.get_executor());
  addressSpace.add_namespace_sync(writableNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-node-mgmt");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the test namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId existingA{nsIndex, 9600u};
  const NodeId existingB{nsIndex, 9601u};
  const NodeId neverCreated{nsIndex, 9699u};
  ASSERT_TRUE(nodes.try_create_sync<ObjectAccessor>(existingA, NodeClass::Object).is_good());
  ASSERT_TRUE(nodes.try_create_sync<ObjectAccessor>(existingB, NodeClass::Object).is_good());

  auto handler = std::make_shared<NodeManagementAuditDelegate>();

  auto run = [&](auto&& request) -> std::shared_ptr<Structure>
  {
    std::promise<Response> done;
    auto future = done.get_future();
    auto service = NodeManagementService::create(sessionInfo,
      handler,
      1,
      std::move(request),
      pool.get_executor(),
      [&done](Response response) { done.set_value(std::move(response)); });
    (void)service;
    if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
      return nullptr;
    return std::get<shared_ptr<Structure>>(future.get());
  };

  auto makeAddNodes = [](const NodeId& parent)
  {
    AddNodesRequest request;
    request.request_header().request_handle() = 1;
    AddNodesItem item;
    item.parent_node_id().node_id() = parent;
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.browse_name() = QualifiedName{parent.namespace_index(), "AuditedObject"};
    item.node_class() = NodeClass::Object;
    item.type_definition().node_id() = NodeId{ObjectTypeId::BaseObjectType};
    request.nodes_to_add().payload().push_back(std::move(item));
    return request;
  };
  auto makeAddReferences = [](const NodeId& source)
  {
    AddReferencesRequest request;
    request.request_header().request_handle() = 1;
    AddReferencesItem item;
    item.source_node_id() = source;
    // A conforming item: AddReferences screens targetNodeId, targetNodeClass and targetServerUri
    // (OPC 10000-4 5.7.3.2) before an item is dispatched, so a bare one is refused for its
    // parameters and never reaches the audit path this test is about.
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.is_forward() = true;
    item.target_node_id().node_id() = NodeId{ObjectId::Server};
    item.target_node_class() = NodeClass::Object;
    request.references_to_add().payload().push_back(std::move(item));
    return request;
  };
  auto makeDeleteNodes = [](const NodeId& node)
  {
    DeleteNodesRequest request;
    request.request_header().request_handle() = 1;
    DeleteNodesItem item;
    item.node_id() = node;
    request.nodes_to_delete().payload().push_back(std::move(item));
    return request;
  };
  auto makeDeleteReferences = [](const NodeId& source, const NodeId& target)
  {
    DeleteReferencesRequest request;
    request.request_header().request_handle() = 1;
    DeleteReferencesItem item;
    item.source_node_id() = source;
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.target_node_id() = ExpandedNodeId{target};
    request.references_to_delete().payload().push_back(std::move(item));
    return request;
  };

  // --- AddNodes: accepted, then refused ---
  auto addNodesGood = run(makeAddNodes(existingA));
  auto* addNodesGoodResponse = dynamic_cast<AddNodesResponse*>(addNodesGood.get());
  ASSERT_NE(addNodesGoodResponse, nullptr) << "AddNodes faulted at service level";
  ASSERT_EQ(addNodesGoodResponse->results().size(), 1u);
  ASSERT_TRUE(addNodesGoodResponse->results()[0].status_code().is_good());

  auto addNodesBad = run(makeAddNodes(neverCreated));
  auto* addNodesBadResponse = dynamic_cast<AddNodesResponse*>(addNodesBad.get());
  ASSERT_NE(addNodesBadResponse, nullptr) << "the refused AddNodes faulted at service level";
  ASSERT_EQ(addNodesBadResponse->results().size(), 1u);
  ASSERT_TRUE(addNodesBadResponse->results()[0].status_code().is_bad())
    << "the AddNodes meant to fail was accepted - the failure stimulus never happened";

  // --- AddReferences: accepted, then refused ---
  auto addRefsGood = run(makeAddReferences(existingA));
  auto* addRefsGoodResponse = dynamic_cast<AddReferencesResponse*>(addRefsGood.get());
  ASSERT_NE(addRefsGoodResponse, nullptr) << "AddReferences faulted at service level";
  ASSERT_EQ(addRefsGoodResponse->results().size(), 1u);
  ASSERT_TRUE(addRefsGoodResponse->results()[0].is_good());

  auto addRefsBad = run(makeAddReferences(neverCreated));
  auto* addRefsBadResponse = dynamic_cast<AddReferencesResponse*>(addRefsBad.get());
  ASSERT_NE(addRefsBadResponse, nullptr) << "the refused AddReferences faulted at service level";
  ASSERT_EQ(addRefsBadResponse->results().size(), 1u);
  ASSERT_TRUE(addRefsBadResponse->results()[0].is_bad())
    << "the AddReferences meant to fail was accepted - the failure stimulus never happened";

  // --- DeleteNodes: accepted, then refused ---
  auto deleteNodesGood = run(makeDeleteNodes(existingA));
  auto* deleteNodesGoodResponse = dynamic_cast<DeleteNodesResponse*>(deleteNodesGood.get());
  ASSERT_NE(deleteNodesGoodResponse, nullptr) << "DeleteNodes faulted at service level";
  ASSERT_EQ(deleteNodesGoodResponse->results().size(), 1u);
  ASSERT_TRUE(deleteNodesGoodResponse->results()[0].is_good());

  auto deleteNodesBad = run(makeDeleteNodes(neverCreated));
  auto* deleteNodesBadResponse = dynamic_cast<DeleteNodesResponse*>(deleteNodesBad.get());
  ASSERT_NE(deleteNodesBadResponse, nullptr) << "the refused DeleteNodes faulted at service level";
  ASSERT_EQ(deleteNodesBadResponse->results().size(), 1u);
  ASSERT_TRUE(deleteNodesBadResponse->results()[0].is_bad())
    << "the DeleteNodes meant to fail was accepted - the failure stimulus never happened";

  // --- DeleteReferences: accepted, then refused ---
  auto deleteRefsGood = run(makeDeleteReferences(existingA, existingB));
  auto* deleteRefsGoodResponse = dynamic_cast<DeleteReferencesResponse*>(deleteRefsGood.get());
  ASSERT_NE(deleteRefsGoodResponse, nullptr) << "DeleteReferences faulted at service level";
  ASSERT_EQ(deleteRefsGoodResponse->results().size(), 1u);
  ASSERT_TRUE(deleteRefsGoodResponse->results()[0].is_good());

  auto deleteRefsBad = run(makeDeleteReferences(neverCreated, existingB));
  auto* deleteRefsBadResponse = dynamic_cast<DeleteReferencesResponse*>(deleteRefsBad.get());
  ASSERT_NE(deleteRefsBadResponse, nullptr) << "the refused DeleteReferences faulted at service level";
  ASSERT_EQ(deleteRefsBadResponse->results().size(), 1u);
  ASSERT_TRUE(deleteRefsBadResponse->results()[0].is_bad())
    << "the DeleteReferences meant to fail was accepted - the failure stimulus never happened";

  // Each service emits its audit Event before it hands the response back, and every call above was
  // awaited, so the record is settled and in invocation order.
  const auto records = bus->records();
  ASSERT_EQ(records.size(), 8u) << "the eight NodeManagement invocations did not raise eight audit Events";

  const char* const expectedSourceNames[] = {"NodeManagement/AddNodes",
    "NodeManagement/AddNodes",
    "NodeManagement/AddReferences",
    "NodeManagement/AddReferences",
    "NodeManagement/DeleteNodes",
    "NodeManagement/DeleteNodes",
    "NodeManagement/DeleteReferences",
    "NodeManagement/DeleteReferences"};

  for (size_t i = 0; i < records.size(); ++i)
  {
    EXPECT_TRUE(records[i].isNodeManagementAudit)
      << "audit Event " << i << " is not an AuditNodeManagementEventType or a subtype";
    EXPECT_EQ(records[i].sourceName, expectedSourceNames[i]) << "audit Event " << i;
    // Even indices are the accepted invocations, odd indices the refused ones.
    EXPECT_EQ(records[i].status, (i % 2u) == 0u) << "audit Event " << i << " records the wrong outcome";
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 6.5: audit Events are raised "for both successful and failed Service invocations". The
// failed ones are what an auditor is looking for and the ones an implementation drops, because the
// emit naturally sits where the change is applied: a Write or a HistoryUpdate refused for want of the
// permission bit is exactly the attempt that should be investigated, and unlike a successful one it
// leaves no other trace behind. Both services are driven through the same refusal shape - a Node that
// resolves and is authorized but does not carry the write permission - so the two halves are directly
// comparable, and each failure record is read for Status false as well as for existence.
// @verifies AC-SVR-EVT-AUD-015-WRITE-AUDIT-BOTH
TEST(UpdateServiceAuditTest, WriteAndHistoryUpdateAuditRefusedInvocationsAsWellAsSuccessful)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto historyNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-update-outcomes", pool.get_executor());
  addressSpace.add_namespace_sync(historyNamespace);
  const uint16_t nsIndex =
    addressSpace.namespace_array().get_namespace_index("uri:test:audit-update-outcomes");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the history-bearing namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  auto makeVariable = [&nodes](
                        const NodeId& nodeId, const AccessLevelType& accessLevel, bool historizing = false)
  {
    auto result = nodes.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(result.is_good());
    if (result.is_good())
    {
      result.value().set_access_level(accessLevel);
      result.value().set_historizing(historizing);
    }
  };

  AccessLevelType writable;
  writable.set(AccessLevelType::Bit::CurrentRead);
  writable.set(AccessLevelType::Bit::CurrentWrite);

  AccessLevelType readOnly;
  readOnly.set(AccessLevelType::Bit::CurrentRead);

  AccessLevelType historyWritable;
  historyWritable.set(AccessLevelType::Bit::CurrentRead);
  historyWritable.set(AccessLevelType::Bit::HistoryRead);
  historyWritable.set(AccessLevelType::Bit::HistoryWrite);

  // A HistoricalNode in Part 11 section 4's own terms - Historizing set and the HistoryRead bit present -
  // with HistoryWrite deliberately withheld. That makes the refusal at ua_history_update_service.cpp:462 the
  // only thing under test: the node is unarguably one the HistoryUpdate audit obligation binds.
  AccessLevelType historyReadOnly;
  historyReadOnly.set(AccessLevelType::Bit::CurrentRead);
  historyReadOnly.set(AccessLevelType::Bit::HistoryRead);

  const NodeId writtenNode{nsIndex, 9700u};
  const NodeId refusedWriteNode{nsIndex, 9701u};
  const NodeId historisedNode{nsIndex, 9702u};
  const NodeId refusedHistoryNode{nsIndex, 9703u};
  makeVariable(writtenNode, writable);
  makeVariable(refusedWriteNode, readOnly);
  makeVariable(historisedNode, historyWritable, /*historizing=*/true);
  makeVariable(refusedHistoryNode, historyReadOnly, /*historizing=*/true);

  // --- Write: one accepted operation and one refused, in the same request ---
  WriteRequest writeRequest;
  writeRequest.request_header().request_handle() = 1;
  for (const auto& target : {writtenNode, refusedWriteNode})
  {
    WriteValue writeValue;
    writeValue.node_id() = target;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value().value() = Variant{int32_t{42}};
    writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));
  }

  std::promise<Response> writeDone;
  auto writeFuture = writeDone.get_future();
  auto writeService = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    pool.get_executor(),
    [&writeDone](Response response) { writeDone.set_value(std::move(response)); });
  (void)writeService;
  ASSERT_EQ(writeFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the Write service never completed, so it never reached the audit site";
  auto writeResponseHolder = writeFuture.get();
  auto* writeResponse =
    dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(writeResponseHolder).get());
  ASSERT_NE(writeResponse, nullptr) << "the Write faulted at service level";
  ASSERT_EQ(writeResponse->results().size(), 2u);
  ASSERT_TRUE(writeResponse->results()[0].is_good()) << "the Write meant to succeed was refused";
  ASSERT_TRUE(writeResponse->results()[1].is_bad())
    << "the Write meant to be refused was accepted - the failure stimulus never happened";

  // --- HistoryUpdate: one accepted operation and one refused, in the same request ---
  HistoryUpdateRequest historyRequest;
  historyRequest.request_header().request_handle() = 2;
  historyRequest.history_update_details().resize(2);
  {
    size_t detailIndex = 0;
    for (const auto& target : {historisedNode, refusedHistoryNode})
    {
      auto updateDetails = std::make_unique<UpdateDataDetails>();
      updateDetails->node_id() = target;
      updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
      DataValue historisedValue;
      historisedValue.value() = 42;
      updateDetails->update_values().resize(1);
      updateDetails->update_values()[0] = std::move(historisedValue);
      historyRequest.history_update_details()[detailIndex] = std::move(updateDetails);
      ++detailIndex;
    }
  }

  std::promise<Response> historyDone;
  auto historyFuture = historyDone.get_future();
  auto historyService = HistoryUpdateService::create(sessionInfo,
    2,
    std::move(historyRequest),
    pool.get_executor(),
    [&historyDone](Response response) { historyDone.set_value(std::move(response)); });
  (void)historyService;
  ASSERT_EQ(historyFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the HistoryUpdate service never completed, so it never reached the audit site";
  auto historyResponseHolder = historyFuture.get();
  auto* historyResponse =
    dynamic_cast<HistoryUpdateResponse*>(std::get<shared_ptr<Structure>>(historyResponseHolder).get());
  ASSERT_NE(historyResponse, nullptr) << "the HistoryUpdate faulted at service level";
  ASSERT_EQ(historyResponse->results().size(), 2u);
  ASSERT_TRUE(historyResponse->results()[0].status_code().is_good())
    << "the HistoryUpdate meant to succeed was refused";
  ASSERT_TRUE(historyResponse->results()[1].status_code().is_bad())
    << "the HistoryUpdate meant to be refused was accepted - the failure stimulus never happened";

  const auto records = bus->records();
  ASSERT_FALSE(records.empty()) << "neither the Write nor the HistoryUpdate raised any audit Event";

  const AuditOutcomeRecordingBus::Record* writeSuccessAudit = nullptr;
  const AuditOutcomeRecordingBus::Record* writeFailureAudit = nullptr;
  const AuditOutcomeRecordingBus::Record* historySuccessAudit = nullptr;
  const AuditOutcomeRecordingBus::Record* historyFailureAudit = nullptr;
  for (const auto& record : records)
  {
    if (record.isWriteUpdateAudit && record.sourceNode == writtenNode && writeSuccessAudit == nullptr)
      writeSuccessAudit = &record;
    if (record.isWriteUpdateAudit && record.sourceNode == refusedWriteNode && writeFailureAudit == nullptr)
      writeFailureAudit = &record;
    if (record.isHistoryUpdateAudit && record.sourceNode == historisedNode && historySuccessAudit == nullptr)
      historySuccessAudit = &record;
    if (record.isHistoryUpdateAudit && record.sourceNode == refusedHistoryNode &&
        historyFailureAudit == nullptr)
      historyFailureAudit = &record;
  }

  EXPECT_NE(writeSuccessAudit, nullptr) << "a successful Write raised no audit Event";
  EXPECT_NE(writeFailureAudit, nullptr)
    << "a refused Write raised no audit Event - the attempt left no trace at all";
  EXPECT_NE(historySuccessAudit, nullptr) << "a successful HistoryUpdate raised no audit Event";
  EXPECT_NE(historyFailureAudit, nullptr)
    << "a refused HistoryUpdate raised no audit Event - the attempt left no trace at all";

  if (writeSuccessAudit != nullptr)
    EXPECT_TRUE(writeSuccessAudit->status) << "the successful Write was audited as a failure";
  if (writeFailureAudit != nullptr)
    EXPECT_FALSE(writeFailureAudit->status) << "the refused Write was audited as a success";
  if (historySuccessAudit != nullptr)
    EXPECT_TRUE(historySuccessAudit->status) << "the successful HistoryUpdate was audited as a failure";
  if (historyFailureAudit != nullptr)
    EXPECT_FALSE(historyFailureAudit->status) << "the refused HistoryUpdate was audited as a success";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 6.5.9 / Part 5 section 6.4.25: a Write raises `AuditWriteUpdateEventType` specifically, not
// the generic `AuditUpdateEventType` parent. The subtype is what carries OldValue and NewValue, so a server
// that emits the parent produces a record that says a Node was updated and cannot say to what
// - and because the parent satisfies every "an audit Event was raised" check, the omission is only
// visible by reading the EventType a subscriber would filter on. Both the concrete payload type and
// the EventType NodeId are read, and the EventType is compared against the parent as well.
// @verifies AC-SVR-EVT-AUD-016-WRITE-SUBTYPE
TEST(UpdateServiceAuditTest, WriteRaisesTheWriteUpdateSubtypeNotTheGenericUpdateEvent)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto writableNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-write-subtype", pool.get_executor());
  addressSpace.add_namespace_sync(writableNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-write-subtype");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the test namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId writtenNode{nsIndex, 9800u};
  auto writtenResult = nodes.try_create_sync<VariableAccessor>(writtenNode, NodeClass::Variable);
  ASSERT_TRUE(writtenResult.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    writtenResult.value().set_access_level(accessLevel);
  }

  WriteRequest writeRequest;
  writeRequest.request_header().request_handle() = 1;
  WriteValue writeValue;
  writeValue.node_id() = writtenNode;
  writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeValue.value().value() = Variant{int32_t{7}};
  writeRequest.nodes_to_write().payload().push_back(std::move(writeValue));

  std::promise<Response> writeDone;
  auto writeFuture = writeDone.get_future();
  auto writeService = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    pool.get_executor(),
    [&writeDone](Response response) { writeDone.set_value(std::move(response)); });
  (void)writeService;
  ASSERT_EQ(writeFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the Write service never completed, so it never reached the audit site";
  auto writeResponseHolder = writeFuture.get();
  auto* writeResponse =
    dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(writeResponseHolder).get());
  ASSERT_NE(writeResponse, nullptr) << "the Write faulted at service level and never changed a Node";
  ASSERT_EQ(writeResponse->results().size(), 1u);
  ASSERT_TRUE(writeResponse->results()[0].is_good())
    << "the Write was refused, so no Node changed and the audit obligation never bit";

  const auto records = bus->records();
  ASSERT_FALSE(records.empty()) << "the Write raised no audit Event at all";

  const AuditOutcomeRecordingBus::Record* writeAudit = nullptr;
  for (const auto& record : records)
  {
    if (record.sourceNode == writtenNode && writeAudit == nullptr)
      writeAudit = &record;
  }
  ASSERT_NE(writeAudit, nullptr) << "no audit Event names the Node the Write changed";
  EXPECT_TRUE(writeAudit->isWriteUpdateAudit)
    << "the Write's audit Event is not an AuditWriteUpdateEventType payload";
  EXPECT_EQ(writeAudit->eventType, NodeId(ObjectTypeId::AuditWriteUpdateEventType))
    << "the Write's audit Event does not declare the AuditWriteUpdateEventType EventType";
  EXPECT_NE(writeAudit->eventType, NodeId(ObjectTypeId::AuditUpdateEventType))
    << "the Write was audited as the generic AuditUpdateEventType parent, losing OldValue/NewValue";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 6.5.9: the special RolePermissions write path mutates through Namespace policy,
// before the ordinary Attribute Write path would read the old Attribute value. Its audit record
// still has to carry the exact permission arrays from before and after that mutation; otherwise a
// successful revocation records what was installed but not what access was removed.
// @relation(AC-SVR-EVT-AUD-022-ROLEPERMISSIONS-WRITE-AUDIT, scope=function)
TEST(UpdateServiceAuditTest, RolePermissionsWriteAuditCarriesTheExactOldAndNewPermissionSets)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  bus->set_event_listener([](const BaseEvent&) {});
  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  sessionInfo->set_access_identity_for_test(std::make_shared<AccessIdentity>(AccessIdentityKey{99},
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_SecurityAdmin}},
    sessionInfo->user_identity(),
    sessionInfo->endpoint_security(),
    String{"urn:test:audit-role-permissions"}));

  const auto makePermission = [](ObjectId role, std::initializer_list<PermissionType::Bit> bits)
  {
    RolePermissionType permission;
    permission.role_id() = NodeId{role};
    permission.permissions() = PermissionType{bits};
    return permission;
  };
  const auto encodePermissions = [](const std::vector<RolePermissionType>& permissions)
  {
    Array<RefStructure<Structure>> encoded;
    encoded.payload().reserve(permissions.size());
    for (const auto& permission : permissions)
    {
      RefStructure<Structure> item;
      item = std::unique_ptr<Structure>{std::make_unique<RolePermissionType>(permission).release()};
      encoded.payload().push_back(std::move(item));
    }
    return Variant{std::move(encoded)};
  };
  const auto decodePermissions = [](const Variant& value)
  {
    std::vector<RolePermissionType> decoded;
    if (!value.is_array_of_structure())
      return decoded;
    for (const auto& item : value.as<Array<RefStructure<Structure>>>().payload())
    {
      if (const auto* permission = dynamic_cast<const RolePermissionType*>(item.get()))
        decoded.push_back(*permission);
    }
    return decoded;
  };
  const auto expectPermissionsEqual =
    [](const std::vector<RolePermissionType>& actual, const std::vector<RolePermissionType>& expected)
  {
    ASSERT_EQ(actual.size(), expected.size());
    for (size_t index = 0; index < expected.size(); ++index)
    {
      EXPECT_EQ(actual[index].role_id(), expected[index].role_id()) << "permission index " << index;
      EXPECT_EQ(actual[index].permissions(), expected[index].permissions()) << "permission index " << index;
    }
  };

  const std::vector<RolePermissionType> before{makePermission(ObjectId::WellKnownRole_Anonymous,
                                                 {PermissionType::Bit::Browse, PermissionType::Bit::Read}),
    makePermission(ObjectId::WellKnownRole_SecurityAdmin,
      {PermissionType::Bit::Read, PermissionType::Bit::WriteRolePermissions})};
  const std::vector<RolePermissionType> after{
    makePermission(ObjectId::WellKnownRole_Anonymous, {PermissionType::Bit::Browse}),
    makePermission(ObjectId::WellKnownRole_SecurityAdmin,
      {PermissionType::Bit::Read, PermissionType::Bit::WriteRolePermissions})};

  const NodeId writtenNode{1, 9801u};
  auto created = addressSpace.try_create_node_sync(writtenNode, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_role_permissions(before);
  AttributeWriteMask writeMask;
  writeMask.set(AttributeWriteMask::Bit::RolePermissions);
  created.value().set_write_mask(writeMask);

  WriteRequest request;
  request.request_header().request_handle() = 1;
  WriteValue writeValue;
  writeValue.node_id() = writtenNode;
  writeValue.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  writeValue.value().value() = encodePermissions(after);
  request.nodes_to_write().payload().push_back(std::move(writeValue));

  std::promise<Response> done;
  auto future = done.get_future();
  auto service = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(request),
    pool.get_executor(),
    [&done](Response response) { done.set_value(std::move(response)); });
  (void)service;
  ASSERT_EQ(future.wait_for(std::chrono::seconds{3}), std::future_status::ready);
  auto responseHolder = future.get();
  auto* response = dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(responseHolder).get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto rolePermissionsWriteStatus = response->results()[0];
  ASSERT_TRUE(rolePermissionsWriteStatus.is_good())
    << "RolePermissions write status: " << rolePermissionsWriteStatus.as_uint32();

  const auto records = bus->records();
  const auto audit = std::ranges::find_if(records,
    [&writtenNode](const AuditOutcomeRecordingBus::Record& record)
    { return record.isWriteUpdateAudit && record.sourceNode == writtenNode; });
  ASSERT_NE(audit, records.end());
  ASSERT_TRUE(audit->oldValue.is_array()) << "OldValue must identify the permissions replaced";
  ASSERT_TRUE(audit->newValue.is_array()) << "NewValue must identify the permissions installed";
  expectPermissionsEqual(decodePermissions(audit->oldValue), before);
  expectPermissionsEqual(decodePermissions(audit->newValue), after);

  const auto applied = created.value().get_role_permissions();
  ASSERT_TRUE(applied.has_value());
  expectPermissionsEqual(*applied, after);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 5 section 6.4.25: "OldValue identifies the value that the Attribute contained before the write. If
// the IndexRange is provided, only the value of that range is shown." A Write of a range is audited with the
// old value of that range, and an unranged Write with the whole old value; the record each Write raises is
// read for OldValue, NewValue and IndexRange.
// @relation(AC-SVR-EVT-AUD-016-RANGED-WRITE-OLDVALUE-NARROWED, scope=function)
TEST(WriteAuditOldValue, IsNarrowedToTheWritesRange)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto writableNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-ranged-write", pool.get_executor());
  addressSpace.add_namespace_sync(writableNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-ranged-write");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the test namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId arrayNode{nsIndex, 9810u};
  auto created = nodes.try_create_sync<VariableAccessor>(arrayNode, NodeClass::Variable);
  ASSERT_TRUE(created.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    created.value().set_access_level(accessLevel);
    created.value().set_data_type(NodeId{DataTypeId::Int32});
    created.value().set_value_rank(ValueRank{1});
    created.value().write_value_sync(Array<int32_t>{1, 2, 3, 4});
  }

  const auto writeOnce = [&](Variant value, String indexRange, uint32_t handle)
  {
    WriteRequest request;
    request.request_header().request_handle() = handle;
    WriteValue writeValue;
    writeValue.node_id() = arrayNode;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.index_range() = std::move(indexRange);
    writeValue.value().value() = std::move(value);
    request.nodes_to_write().payload().push_back(std::move(writeValue));

    auto done = std::make_shared<std::promise<Response>>();
    auto future = done->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      handle,
      std::move(request),
      pool.get_executor(),
      [done](Response response) { done->set_value(std::move(response)); });
    (void)service;
    if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the Write with request handle " << handle << " did not answer within three seconds";
      return StatusCode{Status::BadTimeout};
    }
    auto holder = future.get();
    auto* response = dynamic_cast<WriteResponse*>(std::get<shared_ptr<Structure>>(holder).get());
    EXPECT_NE(response, nullptr);
    return response == nullptr || response->results().empty() ? StatusCode{Status::BadUnexpectedError}
                                                              : response->results()[0];
  };

  ASSERT_EQ(writeOnce(Variant{Array<int32_t>{20, 30}}, String{"1:2"}, 1).as_status(), Status::Good)
    << "the ranged Write was refused, so no audit of it can be read";
  ASSERT_EQ(writeOnce(Variant{Array<int32_t>{5, 6, 7, 8}}, String{}, 2).as_status(), Status::Good)
    << "the unranged Write was refused, so no audit of it can be read";

  std::vector<AuditOutcomeRecordingBus::Record> writeAudits;
  for (const auto& record : bus->records())
    if (record.isWriteUpdateAudit && record.sourceNode == arrayNode)
      writeAudits.push_back(record);
  ASSERT_EQ(writeAudits.size(), 2u) << "each Write must raise one AuditWriteUpdateEventType Event";

  const auto& ranged = writeAudits[0];
  EXPECT_EQ(ranged.oldValue, (Variant{Array<int32_t>{2, 3}}))
    << "the ranged Write's OldValue is not the old value of the range it wrote: "
    << to_string(ranged.oldValue);
  EXPECT_EQ(ranged.newValue, (Variant{Array<int32_t>{20, 30}})) << to_string(ranged.newValue);
  EXPECT_EQ(ranged.indexRange, Variant{String{"1:2"}}) << to_string(ranged.indexRange);

  const auto& whole = writeAudits[1];
  EXPECT_EQ(whole.oldValue, (Variant{Array<int32_t>{1, 20, 30, 4}}))
    << "the unranged Write's OldValue is not the whole value before it: " << to_string(whole.oldValue);
  EXPECT_TRUE(whole.indexRange.empty())
    << "an unranged Write's IndexRange must be null, and an empty String is not: "
    << to_string(whole.indexRange);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 4 section 7.11, Table 135, DataValue value: "If the StatusCode indicates an error then the value is to
// be ignored and the Server shall set it to null." Part 5 section 6.4.25 lets a Server that does not have the
// old value report null. A value whose status is Bad is one the Server ignores, so the audit of a Write over
// it records a null OldValue, with and without an IndexRange. The Bad DataValue is stored again before the
// second Write, because the ranged Write leaves a Good value.
// @relation(AC-SVR-EVT-AUD-016-BAD-OLDVALUE-AUDITED-AS-NULL, scope=function)
TEST(WriteAuditOldValue, ABadOldValueIsAuditedAsNull)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto writableNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-bad-old-value", pool.get_executor());
  addressSpace.add_namespace_sync(writableNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-bad-old-value");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the test namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId arrayNode{nsIndex, 9820u};
  auto created = nodes.try_create_sync<VariableAccessor>(arrayNode, NodeClass::Variable);
  ASSERT_TRUE(created.is_good());
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    created.value().set_access_level(accessLevel);
    created.value().set_data_type(NodeId{DataTypeId::Int32});
    created.value().set_value_rank(ValueRank{1});
  }
  const auto storeBadValue = [&created]
  {
    DataValue bad{Variant{Array<int32_t>{1, 2, 3, 4}}};
    bad.status() = StatusCode{Status::BadNoCommunication};
    const auto stored = created.value().try_write_value_sync(std::move(bad));
    ASSERT_TRUE(stored.is_good()) << "the Bad DataValue was not stored: " << to_string(stored.status_code());
  };

  // The old value is read before the Write is made, so what each audit records does not depend on whether the
  // Write is accepted; only that it answers.
  const auto writeOnce = [&](Variant value, String indexRange, uint32_t handle)
  {
    WriteRequest request;
    request.request_header().request_handle() = handle;
    WriteValue writeValue;
    writeValue.node_id() = arrayNode;
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.index_range() = std::move(indexRange);
    writeValue.value().value() = std::move(value);
    request.nodes_to_write().payload().push_back(std::move(writeValue));

    auto done = std::make_shared<std::promise<Response>>();
    auto future = done->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      handle,
      std::move(request),
      pool.get_executor(),
      [done](Response response) { done->set_value(std::move(response)); });
    (void)service;
    if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
      ADD_FAILURE() << "the Write with request handle " << handle << " did not answer within three seconds";
  };

  storeBadValue();
  writeOnce(Variant{Array<int32_t>{20, 30}}, String{"1:2"}, 1);
  storeBadValue();
  writeOnce(Variant{Array<int32_t>{5, 6, 7, 8}}, String{}, 2);

  std::vector<AuditOutcomeRecordingBus::Record> writeAudits;
  for (const auto& record : bus->records())
    if (record.isWriteUpdateAudit && record.sourceNode == arrayNode)
      writeAudits.push_back(record);
  ASSERT_EQ(writeAudits.size(), 2u) << "each Write must raise one AuditWriteUpdateEventType Event";

  const auto& ranged = writeAudits[0];
  EXPECT_TRUE(ranged.oldValue.empty())
    << "the ranged Write over a Bad value was audited with an OldValue: " << to_string(ranged.oldValue);
  EXPECT_EQ(ranged.newValue, (Variant{Array<int32_t>{20, 30}})) << to_string(ranged.newValue);
  EXPECT_EQ(ranged.indexRange, Variant{String{"1:2"}}) << to_string(ranged.indexRange);

  const auto& whole = writeAudits[1];
  EXPECT_TRUE(whole.oldValue.empty())
    << "the unranged Write over a Bad value was audited with an OldValue: " << to_string(whole.oldValue);
  EXPECT_EQ(whole.newValue, (Variant{Array<int32_t>{5, 6, 7, 8}})) << to_string(whole.newValue);
  EXPECT_TRUE(whole.indexRange.empty())
    << "an unranged Write's IndexRange must be null: " << to_string(whole.indexRange);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

namespace
{

/// History delegate that accepts a value-history update batch AND a raw-history delete batch.
///
/// The base class answers `BadHistoryOperationUnsupported` by default, which would turn the delete
/// below into a refusal and rob the criterion of its third stimulus, so both entry points answer Good.
class HistoryKindAuditDelegate : public NamespaceHistoryDelegate
{
public:
  void update_data_async(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      for (size_t valueIndex = 0; valueIndex < item.values.size(); ++valueIndex)
        success.operationResults.push_back(Status::Good);
      batch.items.emplace_back(std::move(success));
    }
    callback(std::move(batch));
  }

  void delete_raw_async(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::DeleteRawItem> items, DeleteRawCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
    for (size_t itemIndex = 0; itemIndex < items.size(); ++itemIndex)
    {
      NamespaceHistoryDelegate::HistoryUpdateSuccess success;
      batch.items.emplace_back(std::move(success));
    }
    callback(std::move(batch));
  }
};

/// A namespace whose history delegate serves both the update and the delete kinds.
class HistoryKindNamespace : public default_ns::Namespace,
                             public std::enable_shared_from_this<HistoryKindNamespace>
{
public:
  HistoryKindNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<HistoryKindAuditDelegate> mDelegate = std::make_shared<HistoryKindAuditDelegate>();
};

}  // namespace

// Part 4 section 6.5 / Part 11: every HistoryUpdate modification kind raises an `AuditHistoryUpdateEventType`
// Event or a subtype. A history update rewrites the record of what happened, so an unaudited one
// leaves no way to tell an edited history from an original - and the kinds do not share an emit site:
// insert and replace flow through the value-update path while a delete flows through a separate
// delete path, which is where a server that audits "history writes" typically stops. Each kind is
// therefore driven on its own Node so an audit Event can be attributed to it rather than counted.
// @verifies AC-SVR-EVT-AUD-017-HISTORYUPDATE-AUDIT
TEST(UpdateServiceAuditTest, HistoryInsertReplaceAndDeleteEachRaiseAHistoryUpdateAudit)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto historyNamespace =
    std::make_shared<HistoryKindNamespace>("uri:test:audit-history-kinds", pool.get_executor());
  addressSpace.add_namespace_sync(historyNamespace);
  const uint16_t nsIndex = addressSpace.namespace_array().get_namespace_index("uri:test:audit-history-kinds");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the history-bearing namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId insertedNode{nsIndex, 9900u};
  const NodeId replacedNode{nsIndex, 9901u};
  const NodeId deletedNode{nsIndex, 9902u};
  for (const auto& target : {insertedNode, replacedNode, deletedNode})
  {
    auto result = nodes.try_create_sync<VariableAccessor>(target, NodeClass::Variable);
    ASSERT_TRUE(result.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::HistoryRead);
    accessLevel.set(AccessLevelType::Bit::HistoryWrite);
    result.value().set_access_level(accessLevel);
  }

  auto makeValueUpdate = [](const NodeId& target, PerformUpdateType kind)
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = target;
    details->perform_insert_replace() = kind;
    DataValue historisedValue;
    historisedValue.value() = 42;
    details->update_values().resize(1);
    details->update_values()[0] = std::move(historisedValue);
    return details;
  };

  HistoryUpdateRequest historyRequest;
  historyRequest.request_header().request_handle() = 1;
  historyRequest.history_update_details().resize(3);
  historyRequest.history_update_details()[0] = makeValueUpdate(insertedNode, PerformUpdateType::Insert);
  historyRequest.history_update_details()[1] = makeValueUpdate(replacedNode, PerformUpdateType::Replace);
  {
    auto deleteDetails = std::make_unique<DeleteRawModifiedDetails>();
    deleteDetails->node_id() = deletedNode;
    deleteDetails->is_delete_modified() = false;
    const DateTime deleteEndTime = DateTime::now();
    deleteDetails->start_time() = DateTime{deleteEndTime.value() - std::chrono::hours{1}};
    deleteDetails->end_time() = deleteEndTime;
    historyRequest.history_update_details()[2] = std::move(deleteDetails);
  }

  std::promise<Response> historyDone;
  auto historyFuture = historyDone.get_future();
  auto historyService = HistoryUpdateService::create(sessionInfo,
    1,
    std::move(historyRequest),
    pool.get_executor(),
    [&historyDone](Response response) { historyDone.set_value(std::move(response)); });
  (void)historyService;
  ASSERT_EQ(historyFuture.wait_for(std::chrono::seconds{3}), std::future_status::ready)
    << "the HistoryUpdate service never completed, so it never reached the per-item audit site";
  auto historyResponseHolder = historyFuture.get();
  auto* historyResponse =
    dynamic_cast<HistoryUpdateResponse*>(std::get<shared_ptr<Structure>>(historyResponseHolder).get());
  ASSERT_NE(historyResponse, nullptr) << "the HistoryUpdate faulted at service level";
  ASSERT_EQ(historyResponse->results().size(), 3u);
  ASSERT_TRUE(historyResponse->results()[0].status_code().is_good()) << "the history insert was refused";
  ASSERT_TRUE(historyResponse->results()[1].status_code().is_good()) << "the history replace was refused";
  ASSERT_TRUE(historyResponse->results()[2].status_code().is_good()) << "the history delete was refused";

  const auto records = bus->records();
  ASSERT_FALSE(records.empty()) << "no HistoryUpdate modification kind raised any audit Event";

  auto audited = [&records](const NodeId& target)
  {
    for (const auto& record : records)
    {
      if (record.isHistoryUpdateAudit && record.sourceNode == target)
        return true;
    }
    return false;
  };

  EXPECT_TRUE(audited(insertedNode)) << "the history insert raised no AuditHistoryUpdateEventType";
  EXPECT_TRUE(audited(replacedNode)) << "the history replace raised no AuditHistoryUpdateEventType";
  EXPECT_TRUE(audited(deletedNode)) << "the history delete raised no AuditHistoryUpdateEventType";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// --- Audit field taxonomy: SessionId, SourceNode/SourceName, ClientUserId, SecureChannelId ---
//
// The tests below read the audit FIELDS rather than the event types the sections above pin. Every
// one of them is a field an auditor filters or joins on, and each family follows a different rule -
// which is why a shared emit helper that fills them uniformly satisfies every "an audit Event was
// raised" check in this file and still produces a record nothing can be reconstructed from.

namespace
{

/// Lower-cases @p text so a Message assertion can look for a word without pinning its casing.
std::string to_lower_copy(const std::string& text)
{
  std::string lowered = text;
  std::transform(lowered.begin(),
    lowered.end(),
    lowered.begin(),
    [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return lowered;
}

}  // namespace

// Part 5 6.4.7 (lines 2337-2340): "The SessionId shall contain the SessionId of the session that the
// Service call was issued on[.] In the CreateSession Service this shall be set to the newly created
// SessionId." CreateSession is the exception and it is the one that matters: the call has no session
// to be issued on, so a uniform implementation either leaves the field null or carries whichever
// session the emitter last saw - and either way the link between a client's first audit record and
// every record that follows it is gone. Both arms run on one emitter so a carried-over id cannot
// hide behind a fresh fixture.
// @verifies AC-SVR-AUDIT-015-SESSIONID-SEMANTICS
TEST_F(AuditEventEmitterTest, SessionAuditSessionIdNamesTheSessionTheCallWasIssuedOn)
{
  const NodeId establishedSessionId{1, 700u};
  const NodeId newlyCreatedSessionId{1, 701u};

  // An ordinary session service, issued on a session that already exists.
  auto established = make_session_info("EstablishedSession", 5);
  established.sessionId = establishedSessionId;
  mEmitter->on_session_activated(established);

  // CreateSession itself: the session named here did not exist a moment ago.
  auto created = make_session_info("NewSession", 5);
  created.sessionId = newlyCreatedSessionId;
  mEmitter->on_session_created(created);

  ASSERT_EQ(mCollector.count(), 2u);
  const auto& issuedOn = mCollector.get<AuditActivateSessionEventPayload>(0);
  const auto& create = mCollector.get<AuditCreateSessionEventPayload>(1);

  EXPECT_EQ(issuedOn.sessionId, establishedSessionId)
    << "the audit Event does not name the session the call was issued on";

  EXPECT_FALSE(create.sessionId.is_null())
    << "the CreateSession audit carries no SessionId at all, so the audit trail's first record for "
       "this client cannot be joined to anything that follows it";
  EXPECT_EQ(create.sessionId, newlyCreatedSessionId)
    << "the CreateSession audit does not name the newly created session";
  EXPECT_NE(create.sessionId, establishedSessionId)
    << "the CreateSession audit names a session that existed before the call";
}

// Part 5 6.3 / 6.4: a client subscribes for audit Events by creating an event MonitoredItem on the
// Server Object, which is only possible when that Object's EventNotifier carries the
// SubscribeToEvents bit. The bit lives in NS0 (i=2253 EventNotifier="1"), so the plausible failure
// is an address-space load that drops the attribute, or a router that does not treat the Server
// Object as the notifier audit Events are reported on - in both cases the item is accepted and then
// receives nothing, which no client can distinguish from a quiet server. The item is therefore
// proved by function: a real AuditEventEmitter emits through a real EventBus and the item must
// receive the Event.
// @verifies AC-SVR-AUDIT-006-SERVER-NOTIFIER-BIT
TEST(ServerObjectAuditNotifierTest, ServerObjectEventNotifierPermitsSubscribingForAuditEvents)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();
  // Owns the Server for the test and shuts it down on reset - the idiom the Server-backed tests
  // above use so the pool can be drained.
  auto serverOwner = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());

  auto serverNodeResult = addressSpace.try_find_node_sync(serverObjectId);
  ASSERT_TRUE(serverNodeResult.is_good()) << "the server's address space has no Server Object";
  auto serverObject = serverNodeResult.value().as<ObjectAccessor>();
  ASSERT_TRUE(serverObject) << "the Server Object is not an Object";

  EXPECT_TRUE(serverObject->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
    << "the Server Object's EventNotifier does not permit subscribing for Events, so no client can "
       "reach the audit trail at all";

  auto bus = std::make_shared<EventBus>(addressSpace);

  constexpr IntegerId auditItemId{1};
  constexpr uint32_t auditSubscriptionId{0};
  std::mutex deliveryMutex;
  std::condition_variable deliveryCv;
  std::vector<NodeId> deliveredEventTypes;

  auto handle = bus->register_event_item(serverObjectId,
    auditItemId,
    auditSubscriptionId,
    [&](IntegerId, std::shared_ptr<const BaseEvent> event)
    {
      std::lock_guard lock(deliveryMutex);
      deliveredEventTypes.push_back(event->eventType);
      deliveryCv.notify_all();
    });
  ASSERT_NE(handle, 0u) << "no event MonitoredItem could be created on the Server Object";

  // The registry insert is posted to the bus strand; this strand-ordered read lands after it, so the
  // emit below cannot race the registration.
  std::promise<bool> registered;
  bus->resolve_event_item_node_async(auditSubscriptionId,
    auditItemId,
    [&registered](std::optional<NodeId> node) { registered.set_value(node.has_value()); });
  auto registeredFuture = registered.get_future();
  ASSERT_EQ(registeredFuture.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "the bus never answered the registration probe";
  ASSERT_TRUE(registeredFuture.get()) << "the event MonitoredItem never became visible to the bus";

  // The audit Event comes from the real emitter, through the real bus - not from the test.
  AuditEventEmitter emitter(bus, testServerId);
  emitter.on_secure_channel_opened(make_channel_info(11));

  const AuditOpenSecureChannelEventPayload expectedType;
  {
    std::unique_lock<std::mutex> lock(deliveryMutex);
    EXPECT_TRUE(deliveryCv.wait_for(
      lock, std::chrono::seconds{2}, [&deliveredEventTypes] { return !deliveredEventTypes.empty(); }))
      << "an event MonitoredItem on the Server Object received no audit Event";
    ASSERT_FALSE(deliveredEventTypes.empty());
    EXPECT_EQ(deliveredEventTypes.front(), expectedType.eventType);
  }

  bus->deregister_event_item(handle);
  serverOwner.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 5 6.4.7 (lines 2331-2336): "If the Event is generated by a TransferSubscriptions Service call,
// the SourceNode Property shall be assigned to the SessionDiagnostics Object that represents the
// session[.] Otherwise, the SourceNode Property for Events of this type shall be assigned to the
// Server Object." TransferSubscriptions is the exception within the exception - it names a Session's
// diagnostics rather than the Server - and a shared emit helper that stamps the Server Object on
// every audit Event gets the whole rest of the session family right while erasing which session's
// data moved. Both arms are read: the transfer through the real subscription pipeline, the ordinary
// session services through the real AuditEventEmitter.
//
// The pipeline runs without a live Session, so the transfer arm gives the receiving pipeline the Session's
// answer for its SessionDiagnostics Object, once a NodeId and once none (NR-70 DL-89: the Server Object
// then).
// @verifies AC-SVR-AUDIT-014-SESSION-SOURCENODE
// @relation(AC-SVR-AUDIT-010-THE-TRANSFER-AUDIT-NAMES-THE-RECEIVING-SESSIONS-DIAGNOSTICS-OBJECT, scope=function)
TEST(TransferSubscriptionsAuditTest, SessionAuditSourceNodeFollowsTheServiceThatRaisedIt)
{
  // --- Arm 1: the ordinary session services, which name the Server Object ---
  {
    EventCollector collector;
    auto sink = std::make_shared<TestEventSink>(collector);
    AuditEventEmitter emitter(sink, testServerId);

    emitter.on_session_created(make_session_info("Ordinary", 5));
    emitter.on_session_activated(make_session_info("Ordinary", 5));
    emitter.on_session_closed(make_session_info("Ordinary", 5), StatusCode{Status::Good});

    ASSERT_EQ(collector.count(), 3u) << "the ordinary session services raised no audit Events";
    GTEST_LOG_(INFO) << "ordinary session audit Events scanned: " << collector.count();
    for (size_t i = 0; i < collector.count(); ++i)
    {
      EXPECT_EQ(collector.at(i).sourceNode, serverObjectId)
        << "ordinary session audit Event " << i << " does not name the Server Object";
    }
  }

  // --- Arm 2: TransferSubscriptions, which names the session rather than the Server ---
  boost::asio::thread_pool pool;
  SubscriptionIdAllocator idAllocator;
  SubscriptionRouter router;
  OrphanedSubscriptionStore orphanStore;
  auto counters = std::make_shared<ServerSummaryCounters>();

  // Session placeholders used only for registry ownership - never dereferenced.
  auto sessionA = make_session_registry_placeholder();
  auto sessionB = make_session_registry_placeholder();

  auto secCtxA = std::make_shared<TransferAuditSecurityContext>();
  auto secCtxB = std::make_shared<TransferAuditSecurityContext>();
  // A session id the transfer audit could name, so "not the Server Object" is reachable for a
  // conforming implementation rather than impossible by construction.
  secCtxB->sessionId = NodeId{1, 4242u};
  const UserIdentity owner{.userId = "transferUser", .kind = UserTokenKind::UserName};
  secCtxA->userIdentity = std::make_shared<const UserIdentity>(owner);
  secCtxB->userIdentity = std::make_shared<const UserIdentity>(owner);

  std::mutex mutexA;
  std::condition_variable cvA;
  std::vector<Response> responsesA;
  std::mutex mutexB;
  std::condition_variable cvB;
  std::vector<Response> responsesB;

  auto addressSpace = AddressSpace::create("urn:test:transfer-source-node", pool.get_executor());
  auto bus = std::make_shared<EventBus>(addressSpace);

  struct TransferSourceSink
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<NodeId> sourceNodes;
    std::vector<NodeId> eventTypes;
    bool complete{false};
  };

  auto sink = std::make_shared<TransferSourceSink>();

  // Select by SourceName so SourceNode and EventType remain observations.
  bus->set_event_listener(
    [sink](const BaseEvent& event)
    {
      if (event.sourceName != "Session/TransferSubscriptions" && event.sourceName != "TransferAuditComplete")
        return;
      {
        std::lock_guard lock(sink->mutex);
        if (event.sourceName == "TransferAuditComplete")
        {
          sink->complete = true;
        }
        else
        {
          sink->sourceNodes.push_back(event.sourceNode);
          sink->eventTypes.push_back(event.eventType);
        }
      }
      sink->cv.notify_all();
    });
  ASSERT_TRUE(bus->has_event_interest());

  auto executor = pool.get_executor();
  // One transfer from a pipeline of Session A to one of Session B, whose Session answers @p diagnosticsObject
  // for its SessionDiagnostics Object; @p observed receives the transfer audit's SourceNode.
  const auto transferAudit =
    [&](std::function<std::optional<NodeId>()> diagnosticsObject, std::optional<NodeId>& observed)
  {
    {
      std::lock_guard lock(sink->mutex);
      sink->sourceNodes.clear();
      sink->eventTypes.clear();
      sink->complete = false;
    }
    responsesA.clear();
    responsesB.clear();
    auto mgrA = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = executor,
      .sessionStrand = boost::asio::make_strand(executor),
      .logger = Logger{},
      .idAllocator = idAllocator,
      .summaryCounters = counters,
      .sendResponse =
        [&mutexA, &cvA, &responsesA](Response r)
      {
        std::lock_guard lk(mutexA);
        responsesA.push_back(std::move(r));
        cvA.notify_all();
      },
      .subscriptionRouter = router.weak(),
      .orphanedSubscriptionStore = orphanStore.weak(),
      .owningSession = sessionA,
      .securityContext = secCtxA,
    });

    auto mgrB = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = executor,
      .sessionStrand = boost::asio::make_strand(executor),
      .logger = Logger{},
      .idAllocator = idAllocator,
      .summaryCounters = counters,
      .sendResponse =
        [&mutexB, &cvB, &responsesB](Response r)
      {
        std::lock_guard lk(mutexB);
        responsesB.push_back(std::move(r));
        cvB.notify_all();
      },
      .subscriptionRouter = router.weak(),
      .orphanedSubscriptionStore = orphanStore.weak(),
      .owningSession = sessionB,
      .securityContext = secCtxB,
      .diagnosticsObject = std::move(diagnosticsObject),
      .eventBus = bus,
      .auditingEnabled = true,
      .applicationUri = "urn:test:transfer-source-node",
    });

    CreateSubscriptionRequest createRequest;
    createRequest.requested_publishing_interval() = 1000;
    createRequest.requested_lifetime_count() = 30;
    createRequest.requested_max_keep_alive_count() = 10;
    createRequest.max_notifications_per_publish() = 0;
    createRequest.publishing_enabled() = true;
    createRequest.priority() = 0;
    mgrA->handle_create_subscription(1, createRequest);

    IntegerId subscriptionId{0};
    {
      std::unique_lock<std::mutex> lk(mutexA);
      ASSERT_TRUE(cvA.wait_for(lk, std::chrono::seconds{2}, [&] { return !responsesA.empty(); }))
        << "CreateSubscription produced no response";
      auto* response =
        dynamic_cast<CreateSubscriptionResponse*>(std::get<shared_ptr<Structure>>(responsesA.back()).get());
      ASSERT_NE(response, nullptr) << "CreateSubscription faulted";
      subscriptionId = response->subscription_id();
    }
    ASSERT_NE(subscriptionId, IntegerId{0});

    mgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});
    ASSERT_TRUE(orphanStore.contains(subscriptionId));

    TransferSubscriptionsRequest transferRequest;
    transferRequest.subscription_ids().push_back(subscriptionId);
    mgrB->handle_transfer_subscriptions(1, transferRequest);
    {
      std::unique_lock<std::mutex> lk(mutexB);
      ASSERT_TRUE(cvB.wait_for(lk, std::chrono::seconds{2}, [&] { return !responsesB.empty(); }))
        << "TransferSubscriptions produced no response";
      auto* response = dynamic_cast<TransferSubscriptionsResponse*>(
        std::get<shared_ptr<Structure>>(responsesB.back()).get());
      ASSERT_NE(response, nullptr) << "TransferSubscriptions faulted at service level";
      ASSERT_EQ(response->results().size(), 1u);
      ASSERT_TRUE(StatusCode{response->results()[0].status_code()}.is_good())
        << "the transfer was refused, so the service never reached its audit site";
    }

    // Transfer audit emission precedes its response. The bus delivers this later marker
    // after every preceding audit, including a duplicate emitted for the same transfer.
    BaseEvent complete;
    complete.sourceName = "TransferAuditComplete";
    bus->emit(complete);
    {
      std::unique_lock<std::mutex> lock(sink->mutex);
      ASSERT_TRUE(sink->cv.wait_for(lock, std::chrono::seconds{2}, [&sink] { return sink->complete; }))
        << "the transfer audit observation did not finish";
      ASSERT_EQ(sink->sourceNodes.size(), 1u) << "each transfer must raise exactly one matching audit Event";
      ASSERT_EQ(sink->eventTypes.size(), 1u);
      EXPECT_EQ(sink->eventTypes.front(), NodeId{ObjectTypeId::AuditSessionEventType})
        << "the transfer audit must be AuditSessionEventType";
      observed = sink->sourceNodes.front();
    }
    orphanStore.clear();
  };

  // The receiving Session answers its SessionDiagnostics Object, so the audit names it (Part 5 6.4.7).
  const NodeId diagnosticsObjectB{1, 4243u};
  std::optional<NodeId> withObject;
  transferAudit([diagnosticsObjectB] { return std::optional<NodeId>{diagnosticsObjectB}; }, withObject);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(withObject, std::optional<NodeId>{diagnosticsObjectB})
    << "the TransferSubscriptions audit does not name the SessionDiagnostics Object of the Session the "
       "Subscriptions moved to";
  // The receiving Session has no such Object (diagnostics off, or the Object still being created), so the
  // audit names the Server Object (NR-70 DL-89); its SessionId still names the Session.
  std::optional<NodeId> withoutObject;
  transferAudit([] { return std::optional<NodeId>{}; }, withoutObject);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(withoutObject, std::optional<NodeId>{serverObjectId})
    << "without a SessionDiagnostics Object the TransferSubscriptions audit does not name the Server Object";

  sessionA.reset();
  sessionB.reset();
  orphanStore.clear();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 5 6.4.7 (lines 2335-2336): the SourceName of a session audit Event "shall be 'Session/' and
// the Service or cause that generates the Event", with the per-subtype clauses fixing the exact
// strings ("Session/CreateSession" in 6.4.8, "Session/ActivateSession" in 6.4.10). SourceName is the
// field an auditor filters a service on, so a shared session-audit helper that stamps one string -
// or that names the service set rather than the service - satisfies every event-type obligation in
// this file and collapses the whole family into one indistinguishable bucket. Every subtype the
// emitter can raise is provoked, because a subset would pass on exactly that implementation.
// @verifies AC-SVR-AUDIT-016-SESSION-SUBTYPE-SOURCENAMES
TEST_F(AuditEventEmitterTest, EachSessionAuditSubtypeCarriesItsOwnExactSourceName)
{
  mEmitter->on_session_created(make_session_info("SubtypeScan", 1));
  mEmitter->on_session_activated(make_session_info("SubtypeScan", 1));
  mEmitter->on_session_closed(make_session_info("SubtypeScan", 1), StatusCode{Status::Good});
  mEmitter->on_session_timed_out(make_session_info("SubtypeScan", 1));
  mEmitter->on_authentication_failed(
    make_session_info("SubtypeScan", 1), StatusCode{Status::BadIdentityTokenRejected});

  const std::vector<std::string> expectedSourceNames{"Session/CreateSession",
    "Session/ActivateSession",
    "Session/CloseSession",
    "Session/Timeout",
    "Session/ActivateSession"};

  ASSERT_EQ(mCollector.count(), expectedSourceNames.size())
    << "not every session audit subtype was provoked, so the family scan would be partial";
  GTEST_LOG_(INFO) << "session audit subtypes scanned: " << mCollector.count()
                   << " (CreateSession, ActivateSession, CloseSession, Timeout, failed ActivateSession)";

  std::vector<std::string> observed;
  for (size_t i = 0; i < mCollector.count(); ++i)
  {
    const auto& event = mCollector.get<AuditSessionEventPayload>(i);
    const std::string sourceName{event.sourceName};
    EXPECT_EQ(sourceName, expectedSourceNames[i]) << "session audit subtype " << i;
    EXPECT_EQ(sourceName.rfind("Session/", 0), 0u)
      << "session audit subtype " << i << " does not carry the 'Session/' prefix: '" << sourceName << "'";
    observed.push_back(sourceName);
  }

  std::sort(observed.begin(), observed.end());
  observed.erase(std::unique(observed.begin(), observed.end()), observed.end());
  EXPECT_GE(observed.size(), 4u)
    << "the session audit family was raised under " << observed.size()
    << " distinct SourceNames - a generic string cannot say which Service or cause raised the Event";
}

// Part 5 6.4.12 (line 2463) and every certificate subtype clause after it (6.4.13-6.4.18 repeat the
// sentence verbatim): "The SourceName for Events of this type shall be 'Security/Certificate'." One
// string across the whole family, unlike the session and channel families where SourceName names the
// Service - here the subtype carries the distinction instead. Naming the Service that happened to
// present the certificate ("SecureChannel/OpenSecureChannel") follows the pattern used everywhere
// else in this file and is non-conformant: it puts the certificate record outside the SourceName
// filter a compliant client subscribes with, and merges it with the OPN audit that is a separate
// Event. Every subtype the emitter can produce is provoked, so a fix applied to one branch cannot
// read as a fix to the family.
// @verifies AC-SVR-AUDIT-017-CERTIFICATE-SOURCENAME
TEST_F(AuditEventEmitterTest, EveryCertificateAuditSubtypeCarriesTheSecurityCertificateSourceName)
{
  const std::vector<Status> rejectionReasons{Status::BadCertificateTimeInvalid,
    Status::BadCertificateUntrusted,
    Status::BadCertificateInvalid,
    Status::BadCertificateRevoked,
    Status::BadCertificateHostNameInvalid,
    Status::BadSecurityChecksFailed};

  for (const auto reason : rejectionReasons)
    mEmitter->on_certificate_rejected(certificate_event("192.168.1.100:4840", StatusCode{reason}));

  ASSERT_EQ(mCollector.count(), rejectionReasons.size())
    << "not every certificate rejection raised an audit Event, so the family scan would be partial";
  GTEST_LOG_(INFO) << "certificate audit subtypes scanned: " << mCollector.count();

  for (size_t i = 0; i < mCollector.count(); ++i)
  {
    const auto& event = mCollector.get<AuditCertificateEventPayload>(i);
    EXPECT_EQ(event.sourceName, "Security/Certificate")
      << "certificate audit Event " << i << " does not carry the SourceName the clause fixes for the "
      << "whole AuditCertificateEventType family";
  }
}

// Part 5 6.4.19 (lines 2620-2624): "The SourceNode Property for Events of this type shall be assigned
// to the Server Object. The SourceName for Events of this type shall be 'NodeManagement/' and the
// Service that generates the Event." The Server Object here is the opposite of the update family's
// rule (6.4.24/6.4.25 name the changed Node), and the reason is structural: a deleted Node cannot be
// a SourceNode. An implementation that reuses the update helper - the natural one to reach for,
// since both families are about a Node changing - names a Node that may no longer exist, and the
// record is unresolvable. All four services are driven so one mis-wired branch cannot hide behind
// three correct ones.
// @verifies AC-SVR-AUDIT-018-NODEMANAGEMENT-SOURCE
TEST(NodeManagementAuditTest, NodeManagementAuditNamesTheServerObjectAndTheService)
{
  boost::asio::thread_pool pool;

  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto addressSpace = server.address_space();

  auto writableNamespace =
    std::make_shared<UpdateSourceNamespace>("uri:test:audit-node-mgmt-source", pool.get_executor());
  addressSpace.add_namespace_sync(writableNamespace);
  const uint16_t nsIndex =
    addressSpace.namespace_array().get_namespace_index("uri:test:audit-node-mgmt-source");
  ASSERT_NE(nsIndex, uint16_t{0}) << "the test namespace was not registered";

  auto bus = std::make_shared<AuditOutcomeRecordingBus>(addressSpace);
  // A local listener opens the two-level gate without introducing a Subscription.
  bus->set_event_listener([](const BaseEvent&) {});

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), pool.get_executor());
  sessionInfo->eventSink = bus.get();
  auto nodes = sessionInfo->address_space();

  const NodeId existingA{nsIndex, 9620u};
  const NodeId existingB{nsIndex, 9621u};
  ASSERT_TRUE(nodes.try_create_sync<ObjectAccessor>(existingA, NodeClass::Object).is_good());
  ASSERT_TRUE(nodes.try_create_sync<ObjectAccessor>(existingB, NodeClass::Object).is_good());

  auto handler = std::make_shared<NodeManagementAuditDelegate>();

  auto run = [&](auto&& request) -> std::shared_ptr<Structure>
  {
    std::promise<Response> done;
    auto future = done.get_future();
    auto service = NodeManagementService::create(sessionInfo,
      handler,
      1,
      std::move(request),
      pool.get_executor(),
      [&done](Response response) { done.set_value(std::move(response)); });
    (void)service;
    if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
      return nullptr;
    return std::get<shared_ptr<Structure>>(future.get());
  };

  AddNodesRequest addNodesRequest;
  addNodesRequest.request_header().request_handle() = 1;
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = existingA;
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.browse_name() = QualifiedName{nsIndex, "AuditedObject"};
    item.node_class() = NodeClass::Object;
    item.type_definition().node_id() = NodeId{ObjectTypeId::BaseObjectType};
    addNodesRequest.nodes_to_add().payload().push_back(std::move(item));
  }
  auto addNodesHolder = run(std::move(addNodesRequest));
  auto* addNodesResponse = dynamic_cast<AddNodesResponse*>(addNodesHolder.get());
  ASSERT_NE(addNodesResponse, nullptr) << "AddNodes faulted at service level";
  ASSERT_EQ(addNodesResponse->results().size(), 1u);
  ASSERT_TRUE(addNodesResponse->results()[0].status_code().is_good()) << "the AddNodes never ran";

  AddReferencesRequest addReferencesRequest;
  addReferencesRequest.request_header().request_handle() = 1;
  {
    AddReferencesItem item;
    item.source_node_id() = existingA;
    // See the note on make_add_references above: the item has to satisfy the Part 4 5.7.3.2
    // parameter screen to reach the audit path.
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.is_forward() = true;
    item.target_node_id().node_id() = NodeId{ObjectId::Server};
    item.target_node_class() = NodeClass::Object;
    addReferencesRequest.references_to_add().payload().push_back(std::move(item));
  }
  auto addReferencesHolder = run(std::move(addReferencesRequest));
  auto* addReferencesResponse = dynamic_cast<AddReferencesResponse*>(addReferencesHolder.get());
  ASSERT_NE(addReferencesResponse, nullptr) << "AddReferences faulted at service level";
  ASSERT_EQ(addReferencesResponse->results().size(), 1u);
  ASSERT_TRUE(addReferencesResponse->results()[0].is_good()) << "the AddReferences never ran";

  DeleteNodesRequest deleteNodesRequest;
  deleteNodesRequest.request_header().request_handle() = 1;
  {
    DeleteNodesItem item;
    item.node_id() = existingA;
    deleteNodesRequest.nodes_to_delete().payload().push_back(std::move(item));
  }
  auto deleteNodesHolder = run(std::move(deleteNodesRequest));
  auto* deleteNodesResponse = dynamic_cast<DeleteNodesResponse*>(deleteNodesHolder.get());
  ASSERT_NE(deleteNodesResponse, nullptr) << "DeleteNodes faulted at service level";
  ASSERT_EQ(deleteNodesResponse->results().size(), 1u);
  ASSERT_TRUE(deleteNodesResponse->results()[0].is_good()) << "the DeleteNodes never ran";

  DeleteReferencesRequest deleteReferencesRequest;
  deleteReferencesRequest.request_header().request_handle() = 1;
  {
    DeleteReferencesItem item;
    item.source_node_id() = existingA;
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.target_node_id() = ExpandedNodeId{existingB};
    deleteReferencesRequest.references_to_delete().payload().push_back(std::move(item));
  }
  auto deleteReferencesHolder = run(std::move(deleteReferencesRequest));
  auto* deleteReferencesResponse = dynamic_cast<DeleteReferencesResponse*>(deleteReferencesHolder.get());
  ASSERT_NE(deleteReferencesResponse, nullptr) << "DeleteReferences faulted at service level";
  ASSERT_EQ(deleteReferencesResponse->results().size(), 1u);
  ASSERT_TRUE(deleteReferencesResponse->results()[0].is_good()) << "the DeleteReferences never ran";

  // Each service emits its audit Event before it hands the response back, and every call above was
  // awaited, so the record is settled and in invocation order.
  const auto records = bus->records();
  ASSERT_EQ(records.size(), 4u)
    << "the four NodeManagement invocations did not raise four audit Events, so the SourceNode scan "
       "would run over a partial family";
  GTEST_LOG_(INFO) << "node-management audit Events scanned: " << records.size();

  const char* const expectedSourceNames[] = {"NodeManagement/AddNodes",
    "NodeManagement/AddReferences",
    "NodeManagement/DeleteNodes",
    "NodeManagement/DeleteReferences"};

  for (size_t i = 0; i < records.size(); ++i)
  {
    EXPECT_TRUE(records[i].isNodeManagementAudit)
      << "audit Event " << i << " is not an AuditNodeManagementEventType or a subtype";
    EXPECT_EQ(records[i].sourceNode, serverObjectId)
      << "node-management audit Event " << i << " does not name the Server Object";
    EXPECT_EQ(records[i].sourceName, expectedSourceNames[i]) << "node-management audit Event " << i;
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// Part 5 6.4.5 (lines 2230-2232): "If the ClientUserId is not available for a CloseSecureChannel
// call, then this parameter shall be set to 'System/CloseSecureChannel'." This is the one place a
// substitute is REQUIRED where 6.4.3 requires an empty ClientUserId for an anonymous user - and the
// two must not read alike, because anonymous means a user chose not to identify while "no user at
// all" means the action had no session behind it. An implementation that fills ClientUserId from the
// session and leaves it empty when there is no session satisfies every other ClientUserId obligation
// in this file and turns a server-driven channel teardown into what looks like an anonymous client's
// action.
// @verifies AC-SVR-AUDIT-021-CLIENTUSERID-SYSTEM-FALLBACK
TEST_F(AuditEventEmitterTest, ClientUserIdFallsBackToSystemServiceWhenNoUserIsAvailable)
{
  // A CloseSecureChannel: a channel-level action with no session, and so no user, behind it.
  mEmitter->on_secure_channel_closed(make_channel_info(9), StatusCode{Status::Good});

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditChannelEventPayload>(0);
  const std::string clientUserId{event.clientUserId};

  EXPECT_FALSE(clientUserId.empty())
    << "the CloseSecureChannel audit left ClientUserId empty, which 6.4.3 reserves for an "
       "authenticated-but-anonymous user - the record cannot tell the two apart";
  EXPECT_EQ(clientUserId.rfind("System/", 0), 0u)
    << "ClientUserId does not carry the 'System/' prefix: '" << clientUserId << "'";
  EXPECT_EQ(clientUserId, "System/CloseSecureChannel");
}

// Part 5 6.4.3 (lines 2179-2185): "If the UserIdentityToken is an IssuedIdentityToken then the
// ClientUserId shall be a string that represents the owner of the token." The token itself is opaque
// to the audit trail, so recording it would write a live credential into every archive the trail
// reaches while identifying nobody. The realistic failure is a derivation that switches on the token
// type, handles UserName and X509 - the two whose subject is a field of the token - and falls
// through for an issued token, leaving ClientUserId empty on exactly the sessions whose identity came
// from an external authority.
//
// The criterion's second stimulus, a SessionlessInvoke, has no subject in this SDK: no sessionless
// Service dispatch exists (only the generated SessionlessInvoke request/response types), so there is
// no invocation to raise an audit Event from and nothing is asserted about it here.
// @verifies AC-SVR-AUDIT-022-ISSUEDTOKEN-CLIENTUSERID
TEST_F(AuditEventEmitterTest, IssuedIdentityTokenAuditIdentifiesTheTokenSubjectNotTheToken)
{
  const std::string opaqueTokenBlob = "opaque-issued-token-blob";
  const std::string tokenSubject = "jwt-subject@example.com";

  auto info = make_session_info("IssuedTokenSession", 3);
  info.clientUserId = tokenSubject;
  auto token = std::make_shared<IssuedIdentityToken>();
  token->token_data() = ByteString{std::vector<uint8_t>{opaqueTokenBlob.begin(), opaqueTokenBlob.end()}};
  info.userIdentityToken = token;

  mEmitter->on_session_activated(info);

  ASSERT_EQ(mCollector.count(), 1u);
  const auto& event = mCollector.get<AuditActivateSessionEventPayload>(0);
  const std::string clientUserId{event.clientUserId};

  ASSERT_NE(event.userIdentityToken.try_as<IssuedIdentityToken>(), nullptr)
    << "the audit Event carries no IssuedIdentityToken, so this is not the session the obligation "
       "binds";
  EXPECT_FALSE(clientUserId.empty())
    << "a session authenticated by an IssuedIdentityToken was audited with no ClientUserId at all";
  EXPECT_EQ(clientUserId, tokenSubject) << "ClientUserId does not identify the token's subject";
  EXPECT_EQ(clientUserId.find(opaqueTokenBlob), std::string::npos)
    << "ClientUserId carries the opaque token rather than its subject - a credential that identifies "
       "nobody";
}

// Part 5 6.4.5 (lines 2234-2235): "The SecureChannelId shall uniquely identify the SecureChannel."
// It is the audit-trail consequence of the channel-id allocator's uniqueness: a colliding value
// merges two clients' activity into one apparent conversation in the record, and an auditor grouping
// on it cannot tell that it happened. The plausible failure is not a constant - it is a lossy
// rendering, a channel id narrowed to 16 bits or to a signed type on its way into the String field,
// which collides only for the values a long-lived server eventually reaches. The channels below are
// chosen so exactly that mistake collides: 0xFFFFFFFF truncated to 16 bits is 65535.
// @verifies AC-SVR-AUDIT-024-SECURECHANNELID-UNIQUE
TEST_F(AuditEventEmitterTest, AuditSecureChannelIdUniquelyIdentifiesItsOwnChannel)
{
  const std::vector<uint32_t> channelIds{1u, 65535u, 4294967295u};
  for (const auto channelId : channelIds)
    mEmitter->on_secure_channel_opened(make_channel_info(channelId));
  // The same channels again, so "the same channel renders the same way" is observable alongside
  // "different channels render differently" - a per-emission counter satisfies only the second.
  for (const auto channelId : channelIds)
    mEmitter->on_secure_channel_renewed(make_channel_info(channelId));

  ASSERT_EQ(mCollector.count(), channelIds.size() * 2u);
  GTEST_LOG_(INFO) << "concurrent channels compared: " << channelIds.size() << " over " << mCollector.count()
                   << " audit Events";

  std::vector<std::string> firstPass;
  for (size_t i = 0; i < channelIds.size(); ++i)
  {
    const auto& opened = mCollector.get<AuditOpenSecureChannelEventPayload>(i);
    const std::string secureChannelId{opened.secureChannelId};
    EXPECT_FALSE(secureChannelId.empty()) << "audit Event " << i << " carries no SecureChannelId";
    firstPass.push_back(secureChannelId);
  }

  for (size_t i = 0; i < channelIds.size(); ++i)
  {
    const auto& renewed = mCollector.get<AuditChannelEventPayload>(channelIds.size() + i);
    EXPECT_EQ(std::string{renewed.secureChannelId}, firstPass[i])
      << "channel " << channelIds[i] << " was identified differently in two of its own audit Events";
  }

  std::vector<std::string> distinct = firstPass;
  std::sort(distinct.begin(), distinct.end());
  distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
  EXPECT_EQ(distinct.size(), channelIds.size())
    << "two concurrent channels were given the same SecureChannelId, merging their activity into one "
       "apparent client in the audit record";
}

// Part 5 6.4.5 (lines 2234-2237) and 6.4.8/6.4.10 repeat it: "The application shall use the same
// identifier in all AuditEvents related to the Session Service Set (AuditCreateSessionEventType,
// AuditActivateSessionEventType and their subtypes) and the SecureChannel Service Set
// (AuditChannelEventType and its subtypes)." Consistency is what makes the field a join key - an
// auditor reconstructs one client's activity by grouping on it - so a server that formats it per
// family, or regenerates it per service, scatters a single session across the record while every
// individual Event still looks well-formed.
//
// The population is the Events that carry the Property: the plain AuditSessionEventType raised by
// CloseSession has no SecureChannelId in Table 28, so a session close cannot be compared and is not
// asserted here.
// @verifies AC-SVR-AUDIT-025-SECURECHANNELID-CONSISTENT
TEST_F(AuditEventEmitterTest, TheSameSecureChannelIdAppearsInEveryAuditEventForASessionsServices)
{
  constexpr uint32_t channelId = 77u;

  mEmitter->on_secure_channel_opened(make_channel_info(channelId));
  mEmitter->on_session_created(make_session_info("JoinKeySession", channelId));
  mEmitter->on_session_activated(make_session_info("JoinKeySession", channelId));
  mEmitter->on_secure_channel_closed(make_channel_info(channelId), StatusCode{Status::Good});

  ASSERT_EQ(mCollector.count(), 4u);
  GTEST_LOG_(INFO) << "audit Events carrying SecureChannelId compared: 4 (OpenSecureChannel, "
                      "CreateSession, ActivateSession, CloseSecureChannel)";

  const std::string opened{mCollector.get<AuditOpenSecureChannelEventPayload>(0).secureChannelId};
  const std::string created{mCollector.get<AuditCreateSessionEventPayload>(1).secureChannelId};
  const std::string activated{mCollector.get<AuditActivateSessionEventPayload>(2).secureChannelId};
  const std::string closed{mCollector.get<AuditChannelEventPayload>(3).secureChannelId};

  ASSERT_FALSE(opened.empty()) << "the channel audit carries no SecureChannelId to join on";
  EXPECT_EQ(created, opened)
    << "the CreateSession audit identifies the channel differently from the channel's own audit";
  EXPECT_EQ(activated, opened)
    << "the ActivateSession audit identifies the channel differently from the channel's own audit";
  EXPECT_EQ(closed, opened)
    << "the CloseSecureChannel audit identifies the channel differently from the OpenSecureChannel "
       "audit for the same channel";
}

// Part 5 6.4.14 (lines 2515-2518): "The Message Variable shall include a description of why the
// certificate was expired (i.e. time before start or time after end)." Not-yet-valid usually means a
// clock problem and expired usually means a rotation lapse - opposite remedies - and the subtype
// alone does not distinguish them, which is why the clause puts the distinction in the Message. A
// server that fills Message with one constant for every certificate rejection produces a record that
// says only what the EventType already said. The untrusted rejection below is the control: a Message
// identical to it cannot be a description of why THIS certificate's validity period failed.
//
// Both time bounds have the same numeric Bad_CertificateTimeInvalid code. Their distinction is the
// validator's structured crypto.error fact attached to that rich StatusCode, so this drives both
// details through the same observer API and requires the audit Message to preserve them.
// @verifies AC-SVR-AUDIT-027-EXPIRED-MESSAGE
TEST_F(AuditEventEmitterTest, ExpiredCertificateAuditMessageNamesTheTimeBoundThatFailed)
{
  mEmitter->on_certificate_rejected(
    certificate_event("addr", certificate_time_status("certificate is not yet valid")));
  mEmitter->on_certificate_rejected(
    certificate_event("addr", certificate_time_status("certificate has expired")));
  // Control: a rejection for a wholly different reason. A family-wide constant Message is identical
  // to this one.
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateUntrusted}));

  ASSERT_EQ(mCollector.count(), 3u);
  ASSERT_NO_THROW(mCollector.get<AuditCertificateExpiredEventPayload>(0))
    << "a not-yet-valid certificate did not raise the expired subtype";
  ASSERT_NO_THROW(mCollector.get<AuditCertificateExpiredEventPayload>(1))
    << "an expired certificate did not raise the expired subtype";

  const std::string notYetValidMessage{mCollector.get<AuditCertificateEventPayload>(0).message.text()};
  const std::string expiredMessage{mCollector.get<AuditCertificateEventPayload>(1).message.text()};
  const std::string untrustedMessage{mCollector.get<AuditCertificateEventPayload>(2).message.text()};

  ASSERT_FALSE(notYetValidMessage.empty()) << "the not-yet-valid certificate audit carries no Message";
  ASSERT_FALSE(expiredMessage.empty()) << "the expired-certificate audit carries no Message at all";
  EXPECT_NE(expiredMessage, untrustedMessage)
    << "the expired-certificate audit carries the same Message as an untrusted-certificate audit - one "
       "constant for the whole family describes nothing";

  EXPECT_NE(notYetValidMessage.find("not begun"), std::string::npos)
    << "the Message does not identify the not-before bound: '" << notYetValidMessage << "'";
  EXPECT_NE(expiredMessage.find("ended"), std::string::npos)
    << "the Message does not identify the not-after bound: '" << expiredMessage << "'";
  EXPECT_NE(notYetValidMessage, expiredMessage) << "opposite validity-bound failures need distinct Messages";
}

// Part 5 6.4.15 (lines 2535-2537): "The Message shall include a description of why the certificate is
// invalid." One subtype covers every structural defect, so the Message is the only field that says
// which one occurred; a malformed certificate and an unresolvable trust chain are different
// operational faults with different fixes, and both arrive here as
// AuditCertificateInvalidEventType. A server that writes one sentence for every rejection produces a
// Message that only restates the subtype - it passes any "the Event carries a Message" check and
// tells an operator nothing the EventType did not.
// @verifies AC-SVR-AUDIT-028-INVALID-MESSAGE
TEST_F(AuditEventEmitterTest, InvalidCertificateAuditMessageDescribesTheSpecificDefect)
{
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateInvalid}));
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateChainIncomplete}));

  ASSERT_EQ(mCollector.count(), 2u);
  ASSERT_NO_THROW(mCollector.get<AuditCertificateInvalidEventPayload>(0));
  ASSERT_NO_THROW(mCollector.get<AuditCertificateInvalidEventPayload>(1));
  GTEST_LOG_(INFO) << "invalid-certificate reasons compared: 2 (malformed certificate, incomplete chain)";

  const std::string malformedMessage{mCollector.get<AuditCertificateEventPayload>(0).message.text()};
  const std::string chainMessage{mCollector.get<AuditCertificateEventPayload>(1).message.text()};

  ASSERT_FALSE(malformedMessage.empty()) << "the invalid-certificate audit carries no Message at all";
  ASSERT_FALSE(chainMessage.empty()) << "the incomplete-chain audit carries no Message at all";

  EXPECT_NE(malformedMessage, chainMessage)
    << "two different certificate defects were reported under one identical Message, which describes "
       "neither of them";

  for (const auto& message : {malformedMessage, chainMessage})
  {
    const std::string lowered = to_lower_copy(message);
    EXPECT_NE(lowered, "certificate invalid")
      << "the Message only restates the subtype's name: '" << message << "'";
    EXPECT_EQ(lowered.find("auditcertificateinvalideventtype"), std::string::npos)
      << "the Message only restates the subtype's name: '" << message << "'";
  }
}

namespace
{

/// Records the activation audits a Session raises, with the identity each one names.
class IdentityChangeAuditRecorder : public EventSink
{
public:
  struct Record
  {
    bool isActivateSessionAudit{false};
    String clientUserId;
  };

  void emit(BaseEvent& event) override
  {
    Record record;
    record.isActivateSessionAudit = dynamic_cast<const AuditActivateSessionEventPayload*>(&event) != nullptr;
    if (const auto* audit = dynamic_cast<const AuditEventPayload*>(&event))
      record.clientUserId = audit->clientUserId;
    {
      std::lock_guard lock(mMutex);
      mRecords.push_back(std::move(record));
    }
    mCv.notify_all();
  }

  std::vector<Record> records() const
  {
    std::lock_guard lock(mMutex);
    return mRecords;
  }

  size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mRecords.size();
  }

  /// Waits until at least @p count Events have been recorded.
  bool wait_for_count(size_t count) const
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCv.wait_for(lock, std::chrono::seconds{2}, [this, count] { return mRecords.size() >= count; });
  }

private:
  mutable std::mutex mMutex;
  mutable std::condition_variable mCv;
  std::vector<Record> mRecords;
};

/// Answers a different user identity on each activation - the identity change the criterion drives.
class IdentityChangeAuthenticator final : public UserAuthenticator
{
public:
  static constexpr const char* firstUser = "operator-one";
  static constexpr const char* secondUser = "operator-two";

  void authenticate_async(AuthnRequest, AuthnComplete completion) noexcept override
  {
    const std::string userId = mCallCount.fetch_add(1) == 0 ? firstUser : secondUser;
    completion(make_authn_success(
      UserIdentity{.userId = userId, .displayName = userId, .kind = UserTokenKind::Anonymous}));
  }

private:
  std::atomic<int> mCallCount{0};
};

}  // namespace

// Part 4 6.5 / 6.5.6: ActivateSession raises an AuditActivateSessionEventType for every invocation,
// and Part 4 5.6.3 makes calling it again on a live Session the way a client changes the user the
// Session acts as. That second call is the audit case an implementation misses: the Session already
// exists and was already audited at creation and first activation, so emission hung off "a Session
// became usable" fires once and every action the second identity takes is attributed, in the record,
// to the first. The identity really changes here - the authenticator answers a different principal
// on each activation - and the audit raised after the change is required to name the new one.
// @verifies AC-SVR-EVT-AUD-010-CHANGE-IDENTITY-AUDIT
TEST(SessionLifecycleAuditTest, ChangingTheUserIdentityOnALiveSessionRaisesAnActivateSessionAudit)
{
  auto recorder = std::make_shared<IdentityChangeAuditRecorder>();
  auto emitter = std::make_shared<AuditEventEmitter>(recorder, testServerId);
  auto harness = make_session_audit_harness(
    emitter, SecurityPolicyId::None, ByteString{}, std::make_shared<IdentityChangeAuthenticator>());
  ASSERT_NE(harness->session, nullptr) << "no Session was created to activate";

  // First activation: the Session becomes live under the first identity.
  harness->clear_response();
  ActivateSessionRequest firstActivate;
  firstActivate.request_header().request_handle() = 42;
  harness->session->activate(2, std::move(firstActivate), {});
  ASSERT_TRUE(harness->wait_for_response()) << "the Session never answered the first ActivateSession";
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(harness->last_response_body().get()), nullptr)
    << "the first ActivateSession faulted, so no live Session was ever established";
  harness->drain_session_strand();
  ASSERT_TRUE(recorder->wait_for_count(1))
    << "the first activation raised no audit Event - the wiring is dead, so nothing below could be "
       "observed";
  // Everything the first activation raised sits below this index and cannot be mistaken for the
  // audit of the identity change.
  const size_t beforeIdentityChange = recorder->count();

  // Second activation on the same live Session, under a different user identity.
  harness->clear_response();
  ActivateSessionRequest secondActivate;
  secondActivate.request_header().request_handle() = 43;
  harness->session->activate(3, std::move(secondActivate), {});
  ASSERT_TRUE(harness->wait_for_response()) << "the Session never answered the second ActivateSession";
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(harness->last_response_body().get()), nullptr)
    << "the identity change was refused, so the stimulus never happened";
  harness->drain_session_strand();
  static_cast<void>(recorder->wait_for_count(beforeIdentityChange + 1));

  const auto records = recorder->records();
  ASSERT_GT(records.size(), beforeIdentityChange)
    << "changing the user identity on a live Session raised no audit Event at all";

  const IdentityChangeAuditRecorder::Record* changeAudit = nullptr;
  for (size_t i = beforeIdentityChange; i < records.size(); ++i)
  {
    if (records[i].isActivateSessionAudit)
    {
      changeAudit = &records[i];
      break;
    }
  }

  ASSERT_NE(changeAudit, nullptr)
    << "changing the user identity on a live Session raised no AuditActivateSessionEventType";
  EXPECT_EQ(changeAudit->clientUserId, IdentityChangeAuthenticator::secondUser)
    << "the identity-change audit names the user the Session activated with the first time, so every "
       "action the new identity takes is attributed to the old one";

  harness.reset();
}

// =============================================================================================
// What a certificate audit Event SAYS, as distinct from which subtype it is
//
// The subtype tests above establish that a rejection reason selects the right EventType. These three
// establish the two fields a human or a SIEM actually reads, and both are wrong in the same way: the
// emitter fills them from one `fillCommon` lambda that closes over nothing about the reason
// (`ua_audit_event_emitter.cpp:213-223`), so every certificate Event carries the same SourceName and
// the same Message whichever branch below it fires. A test that only checks the subtype passes on a
// server whose Events are otherwise indistinguishable from each other.
// =============================================================================================

// Part 5 section 6.4.13-section 6.4.18 give every certificate audit subtype the same sentence: "The
// SourceName for Events of this type shall be 'Security/Certificate'." One SourceName across the whole
// family, with the subtype carrying the distinction - which is the opposite convention from the session and
// channel families, where the SourceName names the service.
//
// The emitter assigns "SecureChannel/OpenSecureChannel" to all of them. That is not merely the wrong
// string: it is a *service* name on an Event whose whole family is defined not to carry one, so a
// consumer filtering audit Events by SourceName finds certificate rejections filed under the channel
// service and cannot separate them from an ordinary channel audit.
//
// Asserted across every subtype rather than one, because the obligation is that the string does not
// vary - a single-subtype check would pass on a server that had fixed one branch of the six.
// @verifies AC-SVR-AUDIT-017-CERTIFICATE-SOURCENAME
TEST_F(AuditEventEmitterTest, EveryCertificateAuditSubtypeCarriesTheSourceNameSecurityCertificate)
{
  const std::pair<Status, const char*> rejections[]{
    {Status::BadCertificateTimeInvalid, "time invalid -> Expired"},
    {Status::BadCertificateUntrusted, "untrusted -> Untrusted"},
    {Status::BadCertificateInvalid, "invalid -> Invalid"},
    {Status::BadCertificateRevoked, "revoked -> Revoked"},
    {Status::BadCertificateHostNameInvalid, "hostname -> DataMismatch"},
  };

  for (const auto& [reason, label] : rejections)
  {
    mCollector.clear();
    mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{reason}));
    ASSERT_EQ(mCollector.count(), 1u) << label << ": no audit Event was emitted at all";
    const auto& event = mCollector.get<AuditCertificateEventPayload>(0);
    const std::string sourceName{static_cast<std::string_view>(event.sourceName)};
    EXPECT_EQ(sourceName, "Security/Certificate")
      << label << ": SourceName is '" << sourceName
      << "'. Part 5 section 6.4.13-section 6.4.18 give every certificate audit subtype the same SourceName, "
         "'Security/Certificate'; a service name here files a certificate rejection under the "
         "channel service, where no consumer looking for certificate audits will find it";
  }
}

// Part 5 section 6.4.14 (AuditCertificateExpiredEventType) covers two opposite conditions with one subtype:
// a certificate whose validity has not begun and one whose validity has ended. They usually have
// opposite causes - a clock skew on the presenting peer versus a rotation nobody performed - and
// opposite remedies, so the Event's Message is the only place the distinction can survive.
//
// Both failures carry Bad_CertificateTimeInvalid numerically. The control variable is solely the
// structured OpenSSL reason attached to the StatusCode, proving the emitter consumes that detail
// rather than branching on a different status or certificate-chain depth.
// @verifies AC-SVR-AUDIT-027-EXPIRED-MESSAGE
TEST_F(AuditEventEmitterTest, TheTwoExpiryBoundsProduceDifferentAuditMessages)
{
  mCollector.clear();
  mEmitter->on_certificate_rejected(
    certificate_event("addr", certificate_time_status("certificate is not yet valid")));
  ASSERT_EQ(mCollector.count(), 1u);
  const std::string beforeStart{
    static_cast<std::string_view>(mCollector.get<AuditCertificateExpiredEventPayload>(0).message.text())};

  mCollector.clear();
  mEmitter->on_certificate_rejected(
    certificate_event("addr", certificate_time_status("certificate has expired")));
  ASSERT_EQ(mCollector.count(), 1u);
  const std::string afterEnd{
    static_cast<std::string_view>(mCollector.get<AuditCertificateExpiredEventPayload>(0).message.text())};

  EXPECT_NE(beforeStart, afterEnd) << "not-yet-valid and expired certificates both produced the Message '"
                                   << beforeStart << "'";
  EXPECT_NE(beforeStart.find("not begun"), std::string::npos);
  EXPECT_NE(afterEnd.find("ended"), std::string::npos);
}

// Part 5 section 6.4.15 (AuditCertificateInvalidEventType) is the subtype for a certificate that is
// malformed or unusable, which covers several unrelated defects - a structurally invalid certificate
// and an incomplete chain among them. The subtype says only "invalid"; the Message is where the
// defect is named.
//
// As above, the assertion is the weakest one that can fail: the Messages of two distinct invalid
// reasons must differ from each other. The emitter's constant makes them identical.
// @verifies AC-SVR-AUDIT-028-INVALID-MESSAGE
TEST_F(AuditEventEmitterTest, TwoDistinctInvalidCertificateReasonsProduceDifferentAuditMessages)
{
  mCollector.clear();
  mEmitter->on_certificate_rejected(certificate_event("addr", StatusCode{Status::BadCertificateInvalid}));
  ASSERT_EQ(mCollector.count(), 1u);
  const std::string malformed{
    static_cast<std::string_view>(mCollector.get<AuditCertificateInvalidEventPayload>(0).message.text())};

  mCollector.clear();
  mEmitter->on_certificate_rejected(
    certificate_event("addr", StatusCode{Status::BadCertificateChainIncomplete}));
  ASSERT_EQ(mCollector.count(), 1u);
  const std::string incompleteChain{
    static_cast<std::string_view>(mCollector.get<AuditCertificateInvalidEventPayload>(0).message.text())};

  EXPECT_NE(malformed, incompleteChain)
    << "a malformed certificate and an incomplete chain both produced the Message '" << malformed
    << "'. They are different defects with different remedies - one is the peer's certificate, the "
       "other is the issuers it failed to send - and repeating a constant leaves an operator with "
       "the subtype's name and nothing else";
}

namespace
{

std::filesystem::path audit_repository_root()
{
  // UASDK_TEST_SOURCE_DIR (absolute; see tests/CMakeLists.txt), not __FILE__, anchors the walk.
  auto candidate = std::filesystem::path{UASDK_TEST_SOURCE_DIR};
  // parent_path() of the filesystem root is the root itself, so an empty-path test never fires. If the
  // marker cannot be found the walk spins on "/" at full CPU and hangs the whole test binary rather than
  // failing it. Stop when the walk stops moving and let the caller's assertion report the absence.
  while (!std::filesystem::exists(candidate / "internal" / "requirements" / "grammar.sgra"))
  {
    auto parent = candidate.parent_path();
    if (parent == candidate)
      return {};
    candidate = std::move(parent);
  }
  return candidate;
}

// Every audit-observer hook routes through one failure-contained emission interface. The runtime unit
// injects the rich failure; this source-level durability check prevents a later hook from bypassing
// that interface. It is intentionally unit/tooling evidence, not an integration test.
// @relation(AC-SVR-DIAG-013-AUDIT-EMITTER-DETAIL, scope=function)
TEST(AuditEventEmitterStructureTest, EveryObserverHookUsesTheFailureContainedEmissionInterface)
{
  const auto root = audit_repository_root();
  // This test reads the SDK's own sources to check a structural property, and finds them by walking
  // up to a marker that exists only in the full development checkout. Without that checkout it fails
  // and names what is missing; a tree that cannot carry the sources leaves this test out of its run
  // through tests/development_only_tests.txt, not by a skip.
  ASSERT_FALSE(root.empty()) << "missing the full development checkout: no repository-root marker "
                                "above UASDK_TEST_SOURCE_DIR (" UASDK_TEST_SOURCE_DIR
                                "), so the audited SDK sources are absent";
  const auto emitter = root / "sdk" / "implementation" / "server" / "events" / "ua_audit_event_emitter.cpp";
  const auto emitterHeader =
    root / "sdk" / "implementation" / "server" / "events" / "ua_audit_event_emitter.h";
  ASSERT_TRUE(std::filesystem::exists(emitter));
  ASSERT_TRUE(std::filesystem::exists(emitterHeader));

  std::ifstream sourceStream{emitter};
  ASSERT_TRUE(sourceStream.is_open());
  const std::string source{std::istreambuf_iterator<char>{sourceStream}, std::istreambuf_iterator<char>{}};
  std::ifstream headerStream{emitterHeader};
  ASSERT_TRUE(headerStream.is_open());
  const std::string header{std::istreambuf_iterator<char>{headerStream}, std::istreambuf_iterator<char>{}};

  const auto countOccurrences = [&source](std::string_view token)
  {
    size_t count = 0;
    for (auto at = source.find(token); at != std::string::npos; at = source.find(token, at + token.size()))
      ++count;
    return count;
  };
  EXPECT_EQ(countOccurrences("mEventSink.lock()"), 1u);
  EXPECT_EQ(countOccurrences("sink->emit(event);"), 1u);
  EXPECT_NE(
    source.find("void AuditEventEmitter::emit_audit_event(BaseEvent& event) noexcept"), std::string::npos);
  EXPECT_NE(source.find("report_guarded_exception(mLogger"), std::string::npos);

  const std::regex hookPattern{R"(void\s+(on_[a-z_]+)\([^;]*\)\s+override;)"};
  std::vector<std::string> hooks;
  for (std::sregex_iterator match{header.begin(), header.end(), hookPattern}, end; match != end; ++match)
    hooks.push_back((*match)[1].str());
  ASSERT_FALSE(hooks.empty());

  for (const auto& hook : hooks)
  {
    const auto begin = source.find("AuditEventEmitter::" + hook + "(");
    ASSERT_NE(begin, std::string::npos) << hook;
    const auto end = source.find("\nvoid AuditEventEmitter::", begin + 1);
    const auto body = source.substr(begin, end - begin);
    EXPECT_NE(body.find("emit_audit_event(event);"), std::string::npos) << hook;
  }
}

// OPC 10000-4 section 6.1.3: suppressed errors "are always reported via auditing" (owner decision 22.6,
// certificate-validation test plan U9). For each suppressible fault the emitter raises the event type the
// Table 106 audit column names for that step - validity: AuditCertificateExpiredEventType; host name:
// AuditCertificateDataMismatchEventType; revocation unknown: AuditCertificateRevokedEventType - with the
// fault as its StatusCodeId. The validation paths (SecureChannel, CreateSession, user tokens) call this once
// per ErrorDetail entry of a Good result.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-28-SUPPRESSED-AUDIT-EVENT, scope=function)
TEST_F(AuditEventEmitterTest, SuppressedCertificateFaultRaisesItsTable106AuditEventType)
{
  enum class Expected
  {
    Expired,
    DataMismatch,
    Revoked,
  };
  const std::vector<std::pair<Status, Expected>> table{
    {Status::BadCertificateTimeInvalid, Expected::Expired},
    {Status::BadCertificateIssuerTimeInvalid, Expected::Expired},
    {Status::BadCertificateHostNameInvalid, Expected::DataMismatch},
    {Status::BadCertificateRevocationUnknown, Expected::Revoked},
    {Status::BadCertificateIssuerRevocationUnknown, Expected::Revoked},
  };
  for (std::size_t i = 0; i < table.size(); ++i)
  {
    const auto [fault, expected] = table[i];
    mEmitter->on_certificate_error_suppressed(certificate_event("addr", StatusCode{fault}));
    ASSERT_EQ(mCollector.count(), i + 1) << "exactly one event per suppressed fault";
    switch (expected)
    {
    case Expected::Expired:
    {
      const auto& event = mCollector.get<AuditCertificateExpiredEventPayload>(i);
      ASSERT_TRUE(event.statusCodeId.has_value());
      EXPECT_EQ(*event.statusCodeId, StatusCode{fault});
      break;
    }
    case Expected::DataMismatch:
    {
      const auto& event = mCollector.get<AuditCertificateDataMismatchEventPayload>(i);
      ASSERT_TRUE(event.statusCodeId.has_value());
      EXPECT_EQ(*event.statusCodeId, StatusCode{fault});
      break;
    }
    case Expected::Revoked:
    {
      const auto& event = mCollector.get<AuditCertificateRevokedEventPayload>(i);
      ASSERT_TRUE(event.statusCodeId.has_value());
      EXPECT_EQ(*event.statusCodeId, StatusCode{fault});
      break;
    }
    }
  }
}

}  // namespace
