// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// SessionRegisteredNodes: the NodeIds a Session registered, per namespace, and their unregistration when no
// Client can unregister them any more (NR-4 release rule 2; NR-70 F20). The namespaces are
// RegisterNodesRecordingNamespaces, which record every unregistration they are asked for. This file is listed
// in CMake when F20 is applied: SessionRegisteredNodes is F20's.

#include <gtest/gtest.h>

#include "register_nodes_harness.h"

#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_session_registered_nodes.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace ua;
using namespace ua::test::register_nodes;

namespace
{

/// Records what is logged, its structured fields rendered as text.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::vector<std::string> fieldValues;
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::visit(
        [&copy](const auto& value)
        {
          std::ostringstream rendered;
          rendered << value;
          copy.fieldValues.push_back(rendered.str());
        },
        field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  std::vector<Entry> entries() const
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

const std::string unregisterFailedWarning =
  "Could not unregister NodeIds that a Session registered and no Client can unregister any more";

Logger logger_for(const std::shared_ptr<RecordingLogSink>& sink)
{
  return Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
}

/// The stimulus both arms of AC-COMP-SVR-SESSION-REGISTERED-NODES-01-RECORD-TAKE-RELEASE share, up to the
/// take.
std::vector<bool> add_x_x_z_then_take_x_y(
  RegisterNodesHarness& harness, server::SessionRegisteredNodes& registry)
{
  const NodeId x{harness.firstIndex, "N1"};
  const NodeId y{harness.firstIndex, "N2"};
  const NodeId z{harness.firstIndex, "N3"};
  const std::vector<NodeId> added{x, x, z};
  registry.add(harness.address_space().weak(), harness.firstIndex, added);
  const std::vector<NodeId> taken{x, y};
  return registry.take(harness.firstIndex, taken);
}

}  // namespace

// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-01-RECORD-TAKE-RELEASE, scope=function)
// @relation(AC-SVR-VIEW-REG-002-SESSION-CLOSE-UNREGISTERS, scope=function)
TEST(SessionRegisteredNodes, ReleaseAllUnregistersWhatTheSessionHolds)
{
  RegisterNodesHarness harness;
  server::SessionRegisteredNodes registry{Logger{}};
  add_x_x_z_then_take_x_y(harness, registry);
  const auto weak = harness.address_space().weak();

  registry.release_all(weak);
  ASSERT_TRUE(wait_until([&harness] { return harness.first->unregister_calls().size() == 1u; }))
    << "release_all made " << harness.first->unregister_calls().size() << " calls";
  auto first = harness.first->unregister_calls().front();
  std::sort(first.begin(), first.end());
  std::vector<NodeId> expected{NodeId{harness.firstIndex, "N1"}, NodeId{harness.firstIndex, "N3"}};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(first, expected) << "the first release_all unregistered " << text(first);

  const std::vector<NodeId> later{NodeId{harness.firstIndex, "N4"}};
  registry.add(weak, harness.firstIndex, later);
  ASSERT_TRUE(wait_until([&harness] { return harness.first->unregister_calls().size() == 2u; }))
    << "an add after the end was not unregistered at once";
  EXPECT_EQ(harness.first->unregister_calls()[1], later);

  registry.release_all(weak);
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(harness.first->unregister_calls().size(), 2u) << "the second release_all made a call";
}

// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-01-RECORD-TAKE-RELEASE, scope=function)
// @relation(AC-SVR-VIEW-URG-001-FORWARDS-ONLY-THE-SESSIONS-IDS, scope=function)
TEST(SessionRegisteredNodes, TakeReturnsOnlyTheSessionsIds)
{
  RegisterNodesHarness harness;
  server::SessionRegisteredNodes registry{Logger{}};
  EXPECT_EQ(add_x_x_z_then_take_x_y(harness, registry), (std::vector<bool>{true, false}));
}

// A namespace that is gone is an index with no namespace when the release runs. A delegate's
// unregister_nodes_async is noexcept, so the throwing namespace of the criterion cannot be built.
// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-01-FAILED-UNREGISTER-LOGGED, scope=function)
TEST(SessionRegisteredNodes, AFailedUnregistrationIsLoggedAndAGoneNamespaceIsSkipped)
{
  RegisterNodesHarness harness;
  auto sink = std::make_shared<RecordingLogSink>();
  server::SessionRegisteredNodes registry{logger_for(sink)};
  const auto weak = harness.address_space().weak();
  constexpr uint16_t goneIndex = 60;
  const std::vector<NodeId> inFirst{NodeId{harness.firstIndex, "N1"}};
  const std::vector<NodeId> inSecond{NodeId{harness.secondIndex, "N1"}};
  const std::vector<NodeId> inGone{NodeId{goneIndex, "N1"}};
  registry.add(weak, harness.firstIndex, inFirst);
  registry.add(weak, harness.secondIndex, inSecond);
  registry.add(weak, goneIndex, inGone);
  harness.first->answer_unregisters(StatusCode{Status::BadInternalError});

  EXPECT_NO_THROW(registry.release_all(weak));
  ASSERT_TRUE(wait_until(
    [&harness]
    {
      return harness.first->unregister_calls().size() == 1u &&
             harness.second->unregister_calls().size() == 1u;
    }))
    << "the namespaces were not each called once";

  ASSERT_TRUE(wait_until(
    [&sink]
    {
      for (const auto& entry : sink->entries())
      {
        if (entry.level == LogLevel::Warning && entry.category == "service" &&
            entry.message == unregisterFailedWarning)
        {
          return true;
        }
      }
      return false;
    }))
    << "no warning in the category service that an unregistration failed";
  std::size_t failures = 0;
  for (const auto& entry : sink->entries())
  {
    if (entry.level != LogLevel::Warning || entry.category != "service" ||
        entry.message != unregisterFailedWarning)
    {
      continue;
    }
    ++failures;
    for (const auto& value : entry.fieldValues)
    {
      EXPECT_EQ(value.find(std::to_string(goneIndex)), std::string::npos)
        << "a warning names the gone namespace";
    }
  }
  EXPECT_EQ(failures, 1u) << "only the first namespace's unregistration failed";
}
