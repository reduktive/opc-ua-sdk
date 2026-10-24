// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The two parts of the monitoring release a Subscription goes through (NR-4 release rule 1; delivery decision
// DL-13): `release_monitoring_handles`, which sends each namespace one delete_monitoring for its handles, all
// at once; and `UnclaimedMonitoringHandles`, which holds the handles of a create_monitoring answer until its
// create takes them, and releases those of any answer the create will not take.
//
// The namespaces are MonitoringRecordingNamespaces at indexes 2 and 3 (monitoring_release_fixture.h): they
// record every delete_monitoring call and can hold back, fail or throw from it.

#include <gtest/gtest.h>

#include "monitoring_release_fixture.h"

#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_monitoring_release.h"

#include <atomic>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using ua::test::monitoring_release::MonitoringRelease;
using ua::test::monitoring_release::sorted;
using ua::test::monitoring_release::text;
using ua::test::monitoring_release::wait_until;
using namespace std::chrono_literals;

namespace
{

/// Records what is logged, its structured fields rendered as text.
class RecordingLogSink final : public ua::LogSink
{
public:
  struct Entry
  {
    ua::LogLevel level;
    std::string category;
    std::string message;
    std::vector<std::string> fieldValues;
  };

  void log(const ua::LogEntry& entry) override
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

const std::string releaseFailedWarning =
  "A namespace did not release monitoring handles the server no longer uses";

/// Whether @p entry names the namespace at @p index (a field that is the index, or that holds @p uri).
bool names_namespace(const RecordingLogSink::Entry& entry, uint16_t index, const std::string& uri)
{
  for (const auto& value : entry.fieldValues)
  {
    if (value == std::to_string(index) || value.find(uri) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

std::vector<ua::server::IssuedMonitoringHandle> handles(
  std::initializer_list<std::pair<uint16_t, ua::MonitoringHandle>> list)
{
  std::vector<ua::server::IssuedMonitoringHandle> out;
  for (const auto& [index, handle] : list)
  {
    out.push_back(ua::server::IssuedMonitoringHandle{index, handle});
  }
  return out;
}

std::vector<ua::MonitoringHandle> handle_values(const std::vector<ua::server::IssuedMonitoringHandle>& issued)
{
  std::vector<ua::MonitoringHandle> out;
  for (const auto& handle : issued)
  {
    out.push_back(handle.handle);
  }
  return out;
}

class UnclaimedMonitoringHandles : public MonitoringRelease
{
protected:
  ua::Logger logger() const
  {
    return ua::Logger{mLog, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
  }

  /// Waits until every handler posted to the address space's executor before this call has run.
  void let_the_executor_run()
  {
    std::this_thread::sleep_for(50ms);
  }

  std::shared_ptr<RecordingLogSink> mLog = std::make_shared<RecordingLogSink>();
};

}  // namespace

// @relation(AC-COMP-SVR-MONITORING-RELEASE-01-ONE-CALL-PER-NAMESPACE, scope=function)
TEST_F(MonitoringRelease, HandlesAreGroupedByNamespaceAndReleasedAllAtOnce)
{
  mNs2->hold_delete_answers();
  mNs3->hold_delete_answers();

  ua::server::release_monitoring_handles(
    mAddressSpace->weak(), handles({{2, 5}, {3, 7}, {2, 6}, {2, 0}}), ua::Logger{});

  // The release has returned, and both answers are still held.
  ASSERT_EQ(mNs2->held_delete_answers(), 1u);
  ASSERT_EQ(mNs3->held_delete_answers(), 1u);
  const auto calls2 = mNs2->delete_calls();
  const auto calls3 = mNs3->delete_calls();
  ASSERT_EQ(calls2.size(), 1u) << "namespace 2 received " << calls2.size() << " calls";
  EXPECT_EQ(sorted(calls2.front()), (std::vector<ua::MonitoringHandle>{5, 6})) << text(calls2.front());
  ASSERT_EQ(calls3.size(), 1u) << "namespace 3 received " << calls3.size() << " calls";
  EXPECT_EQ(calls3.front(), (std::vector<ua::MonitoringHandle>{7})) << text(calls3.front());
  mNs2->release_delete_answers();
  mNs3->release_delete_answers();
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-01-FAILED-RELEASE-LOGGED, scope=function)
TEST_F(MonitoringRelease, AFailedReleaseIsLoggedAndAGoneNamespaceIsSkipped)
{
  auto log = std::make_shared<RecordingLogSink>();
  const ua::Logger logger{log, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
  mNs2->fail_deletes(ua::StatusCode{ua::Status::BadInternalError});
  mNs3->throw_from_deletes(ua::StatusCode{ua::Status::BadResourceUnavailable});

  EXPECT_NO_THROW(
    ua::server::release_monitoring_handles(mAddressSpace->weak(), handles({{2, 5}, {3, 7}, {4, 9}}), logger));
  EXPECT_NO_THROW(ua::server::release_monitoring_handles(mAddressSpace->weak(), handles({{2, 6}}), logger));

  EXPECT_EQ(mNs2->delete_calls(), (std::vector<std::vector<ua::MonitoringHandle>>{{5}, {6}}));
  EXPECT_EQ(mNs3->delete_calls(), (std::vector<std::vector<ua::MonitoringHandle>>{{7}}));

  size_t for2 = 0;
  size_t for3 = 0;
  for (const auto& entry : log->entries())
  {
    if (entry.level != ua::LogLevel::Warning || entry.category != "subscription" ||
        entry.message != releaseFailedWarning)
    {
      continue;
    }
    for2 += names_namespace(entry, 2, "urn:test:monitoring-release:2") ? 1u : 0u;
    for3 += names_namespace(entry, 3, "urn:test:monitoring-release:3") ? 1u : 0u;
    EXPECT_FALSE(names_namespace(entry, 4, "urn:test:monitoring-release:4")) << "a warning names index 4";
  }
  EXPECT_EQ(for2, 2u) << "namespace 2's two failed answers were not each logged";
  EXPECT_EQ(for3, 1u) << "namespace 3's throw was not logged";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-TWO-ANSWERS-UNDER-ONE-TICKET, scope=function)
TEST_F(UnclaimedMonitoringHandles, TheFirstAnswerIsUsedAndALaterOneIsReleased)
{
  const auto weak = mAddressSpace->weak();

  // A second answer before the claim.
  ua::server::UnclaimedMonitoringHandles first{logger()};
  const auto t1 = first.open_ticket();
  EXPECT_TRUE(first.hold(t1, weak, handles({{2, 5}})));
  EXPECT_FALSE(first.hold(t1, weak, handles({{2, 6}})));
  const auto claimed = first.claim(t1);
  ASSERT_TRUE(claimed.has_value());
  EXPECT_EQ(handle_values(*claimed), (std::vector<ua::MonitoringHandle>{5}));
  EXPECT_TRUE(wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{6}; }))
    << "released: " << text(mNs2->released_handles());

  // A second answer after the claim.
  ua::server::UnclaimedMonitoringHandles second{logger()};
  const auto t2 = second.open_ticket();
  EXPECT_TRUE(second.hold(t2, weak, handles({{2, 7}})));
  const auto claimedSecond = second.claim(t2);
  ASSERT_TRUE(claimedSecond.has_value());
  EXPECT_EQ(handle_values(*claimedSecond), (std::vector<ua::MonitoringHandle>{7}));
  EXPECT_FALSE(second.hold(t2, weak, handles({{2, 8}})));
  EXPECT_TRUE(
    wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{6, 8}; }))
    << "released: " << text(mNs2->released_handles());

  // An answer held when the end comes.
  ua::server::UnclaimedMonitoringHandles third{logger()};
  const auto t3 = third.open_ticket();
  EXPECT_TRUE(third.hold(t3, weak, handles({{2, 9}})));
  third.end();
  EXPECT_TRUE(
    wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{6, 8, 9}; }))
    << "released: " << text(mNs2->released_handles());
  EXPECT_FALSE(third.claim(t3).has_value()) << "a claim after the end returned the released handles";
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-ONLY-THE-FIRST-OF-TWO-CONCURRENT-ANSWERS-IS-DELIVERED, scope=function)
TEST_F(UnclaimedMonitoringHandles, OnlyTheFirstOfTwoAnswersIsDelivered)
{
  constexpr int rounds = 1000;
  const auto weak = mAddressSpace->weak();
  ua::server::UnclaimedMonitoringHandles unclaimed{logger()};
  std::set<ua::MonitoringHandle> claimedHandles;
  int roundsWithOneFirst = 0;
  for (int round = 0; round < rounds; ++round)
  {
    const auto ticket = unclaimed.open_ticket();
    const ua::MonitoringHandle a = 1000u + 2u * static_cast<ua::MonitoringHandle>(round);
    const ua::MonitoringHandle b = a + 1u;
    std::latch start{2};
    bool firstA = false;
    bool firstB = false;
    std::thread holderA{[&]
      {
        start.arrive_and_wait();
        firstA = unclaimed.hold(ticket, weak, handles({{2, a}}));
      }};
    std::thread holderB{[&]
      {
        start.arrive_and_wait();
        firstB = unclaimed.hold(ticket, weak, handles({{2, b}}));
      }};
    holderA.join();
    holderB.join();
    const auto claimed = unclaimed.claim(ticket);
    if (firstA != firstB && claimed.has_value() && claimed->size() == 1u &&
        claimed->front().handle == (firstA ? a : b))
    {
      ++roundsWithOneFirst;
      claimedHandles.insert(claimed->front().handle);
    }
    else
    {
      ADD_FAILURE() << "round " << round << ": hold answered " << firstA << " and " << firstB
                    << "; the claim returned "
                    << (claimed ? text(handle_values(*claimed)) : std::string{"no value"});
      break;
    }
  }
  EXPECT_EQ(roundsWithOneFirst, rounds);

  ASSERT_TRUE(
    wait_until([this] { return mNs2->released_handles().size() >= static_cast<size_t>(rounds); }, 10s))
    << "only " << mNs2->released_handles().size() << " handles were released";
  let_the_executor_run();
  const auto released = mNs2->released_handles();
  EXPECT_EQ(released.size(), static_cast<size_t>(rounds));
  const std::set<ua::MonitoringHandle> distinct(released.begin(), released.end());
  EXPECT_EQ(distinct.size(), released.size()) << "a handle was released twice";
  for (const auto handle : claimedHandles)
  {
    if (distinct.contains(handle))
    {
      ADD_FAILURE() << "the claimed handle " << handle << " was released";
      break;
    }
  }
}

// @relation(AC-COMP-SVR-MONITORING-RELEASE-02-AN-ABANDONED-TICKET-RELEASES-ITS-ANSWERS, scope=function)
TEST_F(UnclaimedMonitoringHandles, AnAbandonedTicketReleasesWhatItHoldsAndLaterAnswers)
{
  const auto weak = mAddressSpace->weak();
  ua::server::UnclaimedMonitoringHandles unclaimed{logger()};

  const auto t1 = unclaimed.open_ticket();
  EXPECT_TRUE(unclaimed.hold(t1, weak, handles({{2, 5}})));
  unclaimed.abandon(t1);
  EXPECT_TRUE(wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{5}; }))
    << "after the abandon, released: " << text(mNs2->released_handles());
  EXPECT_FALSE(unclaimed.hold(t1, weak, handles({{2, 6}})))
    << "a later answer to an abandoned ticket was taken";
  EXPECT_TRUE(
    wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{5, 6}; }))
    << "after the later hold, released: " << text(mNs2->released_handles());
  EXPECT_FALSE(unclaimed.claim(t1).has_value()) << "an abandoned ticket was claimed";

  const auto t2 = unclaimed.open_ticket();
  unclaimed.abandon(t2);
  EXPECT_FALSE(unclaimed.hold(t2, weak, handles({{2, 7}}))) << "an answer to an abandoned ticket was taken";
  EXPECT_TRUE(
    wait_until([this] { return mNs2->released_handles() == std::vector<ua::MonitoringHandle>{5, 6, 7}; }))
    << "after the hold under T2, released: " << text(mNs2->released_handles());
  let_the_executor_run();
  EXPECT_EQ(mNs2->released_handles(), (std::vector<ua::MonitoringHandle>{5, 6, 7}))
    << "a handle was released twice";
}
