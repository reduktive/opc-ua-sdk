// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_expiration_alarm_logic.h"

#include "ua_certificate_expiration_alarm_payload.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <chrono>

#include <gtest/gtest.h>

namespace ua::test
{

namespace
{

DateTime offset_ms(const DateTime& base, int64_t ms)
{
  auto tp =
    base.value() + std::chrono::duration_cast<datetime::OneHundredNanoSeconds>(std::chrono::milliseconds{ms});
  return DateTime{tp};
}

}  // namespace

/// Test-access helper for CertificateExpirationAlarmLogic.
class CertificateExpirationAlarmLogicTestAccess
{
public:
  explicit CertificateExpirationAlarmLogicTestAccess(CertificateExpirationAlarmLogic& logic) : mLogic(logic)
  {}

  bool enabled() const
  {
    return mLogic.enabled();
  }

  bool retained() const
  {
    return mLogic.retained();
  }

  bool active() const
  {
    return mLogic.active();
  }

  bool acknowledged() const
  {
    return mLogic.acknowledged();
  }

  const TwoStateVariableState& active_state() const
  {
    return mLogic.active_state();
  }

  const DateTime& expiration_date() const
  {
    return mLogic.expiration_date();
  }

  double expiration_limit_ms() const
  {
    return mLogic.expiration_limit_ms();
  }

private:
  CertificateExpirationAlarmLogic& mLogic;
};

class CertificateExpirationAlarmLogicTest : public ::testing::Test
{
protected:
  CertificateExpirationAlarmLogic mLogic;
  CertificateExpirationAlarmLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }
};

// =============================================================================
// Configuration
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, ConfigurationRoundTrip)
{
  auto date = DateTime::now();
  mLogic.set_expiration_date(date);
  EXPECT_EQ(mAccess.expiration_date(), date);

  mLogic.set_expiration_limit(3600000.0);
  EXPECT_DOUBLE_EQ(mAccess.expiration_limit_ms(), 3600000.0);
}

TEST_F(CertificateExpirationAlarmLogicTest, DefaultExpirationLimitIsTwoWeeks)
{
  // 2 weeks = 14 * 24 * 60 * 60 * 1000 = 1209600000 ms
  EXPECT_DOUBLE_EQ(mAccess.expiration_limit_ms(), 1209600000.0);
}

// =============================================================================
// evaluate_expiration: activation
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, ActivatesWhenExpirationApproaching)
{
  mLogic.enable();

  auto now = DateTime::now();
  // Certificate expires in 1 hour, limit is 2 hours
  auto expirationDate = offset_ms(now, 3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(7200000.0);  // 2 hours

  // now + 2h >= expiration (now + 1h) -> should activate
  auto transition = mLogic.evaluate_expiration(now);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

TEST_F(CertificateExpirationAlarmLogicTest, DoesNotActivateWhenExpirationFarAway)
{
  mLogic.enable();

  auto now = DateTime::now();
  // Certificate expires in 1 week, limit is 1 day
  auto expirationDate = offset_ms(now, 604800000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(86400000.0);  // 1 day

  // now + 1 day < expiration (now + 7 days) -> should not activate
  auto transition = mLogic.evaluate_expiration(now);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(CertificateExpirationAlarmLogicTest, ActivatesWhenAlreadyExpired)
{
  mLogic.enable();

  auto now = DateTime::now();
  // Certificate already expired 1 hour ago
  auto expirationDate = offset_ms(now, -3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(86400000.0);

  auto transition = mLogic.evaluate_expiration(now);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// evaluate_expiration: deactivation
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, DeactivatesWhenCertificateRenewed)
{
  mLogic.enable();

  auto now = DateTime::now();
  // Initially expiring soon
  auto expirationDate = offset_ms(now, 3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(7200000.0);

  mLogic.evaluate_expiration(now);
  ASSERT_TRUE(mAccess.active());

  // Certificate renewed - new expiration is 1 year away
  auto newExpirationDate = offset_ms(now, 31536000000LL);
  mLogic.set_expiration_date(newExpirationDate);

  auto transition = mLogic.evaluate_expiration(now);
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// evaluate_expiration: no-op when no expiration date
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, DoesNothingWhenNoExpirationDateSet)
{
  mLogic.enable();

  auto transition = mLogic.evaluate_expiration(DateTime::now());
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// evaluate_expiration: idempotent
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, DoesNotReActivateWhenAlreadyActive)
{
  mLogic.enable();

  auto now = DateTime::now();
  auto expirationDate = offset_ms(now, 3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(7200000.0);

  mLogic.evaluate_expiration(now);
  ASSERT_TRUE(mAccess.active());

  // Re-evaluate - should not produce a new transition
  auto transition = mLogic.evaluate_expiration(now);
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(CertificateExpirationAlarmLogicTest, BuildEventReturnsCertificateExpirationAlarmType)
{
  mLogic.enable();

  auto now = DateTime::now();
  auto expirationDate = offset_ms(now, 3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_certificate_type(NodeId{0, 12345});
  mLogic.set_certificate(ByteString{std::vector<uint8_t>{0x01, 0x02, 0x03}});

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* certAlarm = dynamic_cast<CertificateExpirationAlarmPayload*>(event.get());
  ASSERT_NE(certAlarm, nullptr);

  EXPECT_EQ(certAlarm->expirationDate, expirationDate);
  EXPECT_EQ(certAlarm->certificateType, (NodeId{0, 12345}));
  EXPECT_EQ(certAlarm->certificate, (ByteString{std::vector<uint8_t>{0x01, 0x02, 0x03}}));
}

TEST_F(CertificateExpirationAlarmLogicTest, BuildEventCapturesActiveState)
{
  mLogic.enable();

  auto now = DateTime::now();
  auto expirationDate = offset_ms(now, 3600000);
  mLogic.set_expiration_date(expirationDate);
  mLogic.set_expiration_limit(7200000.0);
  mLogic.evaluate_expiration(now);
  ASSERT_TRUE(mAccess.active());

  auto event = mLogic.build_event();
  auto* certAlarm = dynamic_cast<CertificateExpirationAlarmPayload*>(event.get());
  ASSERT_NE(certAlarm, nullptr);
  EXPECT_TRUE(certAlarm->activeState.id);
}

}  // namespace ua::test
