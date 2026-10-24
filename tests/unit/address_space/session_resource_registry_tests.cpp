// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_error_detail.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_session_resource_registry.h"
#include "ua_status.h"
#include "ua_exceptions.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace
{

class RecordingSink final : public ua::LogSink
{
public:
  struct Record
  {
    ua::LogLevel level;
    std::string message;
    std::vector<std::string> keys;
    std::vector<std::string> stringValues;
  };

  void log(const ua::LogEntry& entry) override
  {
    Record record{entry.level, entry.message, {}, {}};
    for (const auto& field : entry.fields)
    {
      record.keys.emplace_back(field.key);
      if (const auto* value = std::get_if<std::string_view>(&field.value))
        record.stringValues.emplace_back(*value);
    }
    const std::lock_guard lock{mMutex};
    mRecords.push_back(std::move(record));
  }

  std::vector<Record> records() const
  {
    const std::lock_guard lock{mMutex};
    return mRecords;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

ua::Logger recording_logger(const std::shared_ptr<RecordingSink>& sink)
{
  return ua::Logger{sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
}

}  // namespace

// @relation(AC-COMP-ADDRSP-SESSION-RESOURCE-REGISTRY-01-SESSION-ISOLATION, scope=function)
TEST(SessionResourceRegistryTest, ReleaseSessionInvokesOnlyLiveRegistrationsWithExactIdentity)
{
  auto registry = std::make_shared<ua::detail::SessionResourceRegistry>();
  const ua::NodeId sessionA{1, 101u};
  const ua::NodeId sessionB{1, 202u};

  std::vector<ua::NodeId> observed;
  auto live =
    registry->register_cleanup([&observed](const ua::NodeId& sessionId) { observed.push_back(sessionId); });

  size_t releasedCalls = 0;
  auto released = registry->register_cleanup([&releasedCalls](const ua::NodeId&) { ++releasedCalls; });
  released.reset();

  registry->release_session(sessionA);
  registry->release_session(sessionB);

  EXPECT_EQ(observed, (std::vector<ua::NodeId>{sessionA, sessionB}));
  EXPECT_EQ(releasedCalls, 0u);

  std::weak_ptr<int> owner;
  {
    auto state = std::make_shared<int>(42);
    owner = state;
    auto weakState = std::weak_ptr<int>{state};
    auto registration =
      registry->register_cleanup([weakState](const ua::NodeId&) { EXPECT_NE(weakState.lock(), nullptr); });
    state.reset();
    EXPECT_TRUE(owner.expired()) << "the registry retained the helper state instead of only its registration";
  }
}

// @relation(AC-COMP-ADDRSP-SESSION-RESOURCE-REGISTRY-02-CALLBACK-SAFETY, scope=function)
TEST(SessionResourceRegistryTest, ThrowingReentrantCallbackIsContainedLoggedAndDoesNotSuppressLaterCleanup)
{
  auto registry = std::make_shared<ua::detail::SessionResourceRegistry>();
  auto sink = std::make_shared<RecordingSink>();
  registry->set_logger(recording_logger(sink));
  const ua::NodeId sessionId{1, 303u};

  std::shared_ptr<ua::detail::SessionResourceRegistry::Registration> first;
  first = registry->register_cleanup(
    [&first](const ua::NodeId&)
    {
      first.reset();
      throw ua::UaException{ua::Status::BadInternalError,
        ua::make_error_detail("SentinelCleanupFailure", "Sentinel cleanup failed", "RegistryTest")};
    });

  size_t laterCalls = 0;
  ua::NodeId laterSession;
  auto later = registry->register_cleanup(
    [&laterCalls, &laterSession](const ua::NodeId& observed)
    {
      ++laterCalls;
      laterSession = observed;
    });

  EXPECT_NO_THROW(registry->release_session(sessionId));
  EXPECT_EQ(laterCalls, 1u);
  EXPECT_EQ(laterSession, sessionId);

  const auto records = sink->records();
  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].level, ua::LogLevel::Error);
  EXPECT_EQ(records[0].message, "SessionResourceRegistry cleanup callback");
  EXPECT_NE(std::find(records[0].keys.begin(), records[0].keys.end(), "error"), records[0].keys.end());
  EXPECT_TRUE(std::any_of(records[0].stringValues.begin(),
    records[0].stringValues.end(),
    [](const std::string& value) { return value.find("SentinelCleanupFailure") != std::string::npos; }));
}
