// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief State machine for the OPC UA CertificateExpirationAlarmType.
/// @ingroup address_space

#ifndef UA_CERTIFICATE_EXPIRATION_ALARM_LOGIC_H
#define UA_CERTIFICATE_EXPIRATION_ALARM_LOGIC_H

#include "ua_off_normal_alarm_logic.h"
#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_node_id.h"

#include <optional>

namespace ua
{

namespace test
{
class CertificateExpirationAlarmLogicTestAccess;
}  // namespace test

/// State machine for the OPC UA CertificateExpirationAlarmType (Part 9, 5.8.24.7).
///
/// Monitors a certificate's expiration. The alarm activates once the current
/// time plus the configured expiration limit reaches or passes the certificate's
/// expiration date, signalling that the certificate is due for renewal before it
/// expires. Extends @ref OffNormalAlarmLogic.
///
/// This is a synchronous in-memory state machine: callers drive it from the
/// owning condition's serialization context and inspect the returned
/// @ref ConditionStateTransition to decide what events and timer commands to
/// run. It performs no I/O and never blocks.
/// @ingroup address_space
class CertificateExpirationAlarmLogic : public OffNormalAlarmLogic
{
public:
  ~CertificateExpirationAlarmLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  CertificateExpirationAlarmLogic(const CertificateExpirationAlarmLogic&) = delete;
  CertificateExpirationAlarmLogic& operator=(const CertificateExpirationAlarmLogic&) = delete;
  CertificateExpirationAlarmLogic(CertificateExpirationAlarmLogic&&) = delete;
  CertificateExpirationAlarmLogic& operator=(CertificateExpirationAlarmLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  CertificateExpirationAlarmLogic() = default;
  // --- Configuration ---

  /// Sets the certificate's expiration date used by @ref evaluate_expiration.
  ///
  /// @param expirationDate Absolute time at which the monitored certificate expires.
  void set_expiration_date(DateTime expirationDate);

  /// Sets how far before expiry the alarm activates.
  ///
  /// @param ms Lead time before the expiration date, in milliseconds. Defaults to
  ///           two weeks (1209600000 ms) until overridden.
  void set_expiration_limit(double ms);

  /// Sets the NodeId of the certificate type this alarm reports.
  ///
  /// @param certType NodeId identifying the certificate's type (e.g. application
  ///                 instance certificate). Surfaced on the emitted event.
  void set_certificate_type(NodeId certType);

  /// Sets the DER-encoded certificate this alarm reports.
  ///
  /// @param cert The monitored certificate as a DER byte string. Surfaced on the
  ///             emitted event.
  void set_certificate(ByteString cert);

  // --- Evaluation ---

  /// Evaluates whether the certificate is within its expiration limit.
  ///
  /// Activates the alarm when `now + expiration_limit >= expiration_date`, and
  /// otherwise deactivates it. Intended to be called periodically (e.g. on a
  /// poll timer) since expiry is time-driven rather than input-driven.
  ///
  /// @param now The current time to evaluate against.
  /// @return The resulting @ref ConditionStateTransition. The shell inspects it to
  ///         decide whether to emit an event and which timer commands to run.
  ConditionStateTransition evaluate_expiration(DateTime now);

  // --- Event building ---

  /// Builds the event for the current alarm state.
  ///
  /// Overrides @ref OffNormalAlarmLogic::build_event to populate the
  /// CertificateExpirationAlarmType-specific fields (certificate type and
  /// certificate) in addition to the inherited alarm fields.
  ///
  /// @return A newly constructed event describing the current state. Ownership
  ///         transfers to the caller.
  std::unique_ptr<BaseEvent> build_event() const override;

protected:
  /// Returns the configured certificate expiration date.
  ///
  /// Extension point for derived state machines; reflects the last value passed
  /// to @ref set_expiration_date.
  ///
  /// @return Reference to the stored expiration date, valid for the lifetime of
  ///         this object.
  const DateTime& expiration_date() const;

  /// Returns the configured expiration limit in milliseconds.
  ///
  /// Extension point for derived state machines; reflects the last value passed
  /// to @ref set_expiration_limit.
  ///
  /// @return The lead time before expiry, in milliseconds.
  double expiration_limit_ms() const;

private:
  friend class test::CertificateExpirationAlarmLogicTestAccess;

  DateTime mExpirationDate{};
  double mExpirationLimitMs{1209600000.0};  // Default: 2 weeks in ms
  NodeId mCertificateType{};
  ByteString mCertificate{};
};

}  // namespace ua

#endif  // !UA_CERTIFICATE_EXPIRATION_ALARM_LOGIC_H
