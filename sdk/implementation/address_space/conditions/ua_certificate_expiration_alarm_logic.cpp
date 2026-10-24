// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_expiration_alarm_logic.h"

#include "ua_certificate_expiration_alarm_payload.h"
#include "ua_data_value.h"

#include <chrono>

namespace ua
{

// --- Configuration ---

void CertificateExpirationAlarmLogic::set_expiration_date(DateTime expirationDate)
{
  mExpirationDate = expirationDate;
}

void CertificateExpirationAlarmLogic::set_expiration_limit(double ms)
{
  mExpirationLimitMs = ms;
}

void CertificateExpirationAlarmLogic::set_certificate_type(NodeId certType)
{
  mCertificateType = std::move(certType);
}

void CertificateExpirationAlarmLogic::set_certificate(ByteString cert)
{
  mCertificate = std::move(cert);
}

// --- Evaluation ---

ConditionStateTransition CertificateExpirationAlarmLogic::evaluate_expiration(DateTime now)
{
  if (mExpirationDate.is_null())
  {
    // No expiration date configured
    return {};
  }

  // Convert expiration limit from milliseconds to the DateTime tick unit (100ns intervals)
  auto limitDuration = std::chrono::duration_cast<datetime::OneHundredNanoSeconds>(
    std::chrono::duration<double, std::milli>(mExpirationLimitMs));

  // Check: now + expiration_limit >= expiration_date
  auto threshold = now.value() + limitDuration;
  const bool expiring = threshold >= mExpirationDate.value();

  if (expiring && !active())
  {
    return activate(severity() > 0 ? severity() : 800);
  }
  else if (!expiring && active())
  {
    return deactivate();
  }

  return {};
}

// --- Event building ---

std::unique_ptr<BaseEvent> CertificateExpirationAlarmLogic::build_event() const
{
  auto event = std::make_unique<CertificateExpirationAlarmPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields: every one - ShelvingState, MaxTimeShelved, InputNode and the optional
  // states included - from the filler the plain alarm uses, so a subtype cannot drift from it.
  populate_alarm_payload_fields(*event);

  // OffNormalAlarmPayload fields
  event->normalState = normal_state_node();

  // CertificateExpirationAlarmPayload fields
  event->expirationDate = mExpirationDate;
  if (mExpirationLimitMs != 1209600000.0)
  {
    event->expirationLimit = Variant{mExpirationLimitMs};
  }
  event->certificateType = mCertificateType;
  event->certificate = mCertificate;

  return event;
}

// --- Protected accessors ---

const DateTime& CertificateExpirationAlarmLogic::expiration_date() const
{
  return mExpirationDate;
}

double CertificateExpirationAlarmLogic::expiration_limit_ms() const
{
  return mExpirationLimitMs;
}

}  // namespace ua
