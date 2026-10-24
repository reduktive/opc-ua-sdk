// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "allocation_controller.h"
#include "batch_recording_namespace.h"
#include "fake_async_crypto.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_callback_safety.h"
#include "ua_channel_bound_signature_data.h"
#include "ua_crypto.h"
#include "ua_defines.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_ecc_encrypted_secret_encoder.h"
#include "ua_on_strand.h"
#include "ua_monitoring_entry.h"
#include "ua_reconnect_fsm_logic.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_to_result.h"

#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace ua;

// The private allocation executable is Linux-only. Run registered C++ static destructors in a child
// to exercise reporting after the emergency storage's enclosing union has been destroyed.
extern "C" void __cxa_finalize(void*);

namespace
{

class FakeInlineMonitoringNamespace final : public test::BatchRecordingNamespace
{
public:
  FakeInlineMonitoringNamespace(boost::asio::any_io_executor executor, unsigned& completions,
    bool injectAllocationFailure, bool throwAfterAnswer, std::size_t itemCount)
    : BatchRecordingNamespace("urn:test:inline-monitoring-allocation", std::move(executor)),
      mCompletions(completions), mInjectAllocationFailure(injectAllocationFailure),
      mThrowAfterAnswer(throwAfterAnswer), mItemCount(itemCount),
      mException(std::make_exception_ptr(UaException{namespaceFailure}))
  {}

  void create_monitoring_async(const RequestInfo&, const CallerInfo*, std::span<const MonitoringCreateItem>,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override
  {
    BatchResult<MonitoringCreateItemResult> result;
    for (std::size_t index = 0; index < mItemCount; ++index)
      result.items.emplace_back(MonitoringCreateSuccess{
        .handle = numeric_cast<MonitoringHandle>(5 + index), .revisedSamplingInterval = 250});
    answer(std::move(result), std::move(complete));
  }

  void modify_monitoring_async(const RequestInfo&, std::span<const MonitoringModifyItem>,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override
  {
    BatchResult<MonitoringModifyItemResult> result;
    for (std::size_t index = 0; index < mItemCount; ++index)
      result.items.emplace_back(MonitoringModifySuccess{.revisedSamplingInterval = 250});
    answer(std::move(result), std::move(complete));
  }

  void delete_monitoring_async(const RequestInfo&, std::span<const MonitoringHandle>,
    std::function<void(BatchResult<VoidResult>)> complete) override
  {
    BatchResult<VoidResult> result;
    for (std::size_t index = 0; index < mItemCount; ++index)
      result.items.emplace_back();
    answer(std::move(result), std::move(complete));
  }

  const StatusCode namespaceFailure{Status::BadResourceUnavailable,
    make_error_detail(
      "InlineMonitoringThrow", "Namespace completed inline and then threw", "MonitoringTest")};
  unsigned completionsBeforeReturn{0};
  std::size_t holdingInjections{0};
  bool armedDuringAnswer{false};

private:
  template<typename Item>
  void answer(BatchResult<Item> result, std::function<void(BatchResult<Item>)> complete)
  {
    // Preparation, type erasure and the one-item answer precede interception. The SDK's hold is next.
    if (mInjectAllocationFailure)
      test::allocation::fail_all();
    else
      test::allocation::record();
    armedDuringAnswer = test::allocation::armed();
    try
    {
      complete(std::move(result));
    }
    catch (...)
    {
      test::allocation::disarm();
      throw;
    }
    completionsBeforeReturn = mCompletions;
    holdingInjections = test::allocation::injections();
    test::allocation::disarm();
    if (mThrowAfterAnswer)
      std::rethrow_exception(mException);
  }

  unsigned& mCompletions;
  bool mInjectAllocationFailure;
  bool mThrowAfterAnswer;
  std::size_t mItemCount;
  std::exception_ptr mException;
};

TEST(MonitoringEntryAllocation, InlineCompletionWaitsForReturnAndPreservesThrowUnderAllocationFailure)
{
  for (const std::size_t itemCount : {1U, 6U})
    for (const unsigned operation : {0U, 1U, 2U})
      for (const bool injectAllocationFailure : {false, true})
        for (const bool throwAfterAnswer : {false, true})
        {
          SCOPED_TRACE(::testing::Message{} << "items=" << itemCount << " operation=" << operation
                                            << " inject=" << injectAllocationFailure
                                            << " throw=" << throwAfterAnswer);
          boost::asio::io_context context;
          unsigned completions = 0;
          auto nameSpace = std::make_shared<FakeInlineMonitoringNamespace>(
            context.get_executor(), completions, injectAllocationFailure, throwAfterAnswer, itemCount);
          StatusCode observed{Status::BadUnexpectedError};
          std::size_t resultCount = 0;
          Duration revisedInterval = 0;
          MonitoringHandle createdHandle = 0;
          std::array<MonitoringHandle, 6> released{};
          std::size_t releaseCount = 0;
          const auto complete = [&](auto result)
          {
            ++completions;
            observed = result.batchStatus.status_code();
            resultCount = result.items.size();
            if constexpr (requires { result.items[0].value().revisedSamplingInterval; })
            {
              if (resultCount != 0 && result.items[0].is_good())
                revisedInterval = result.items[0].value().revisedSamplingInterval;
            }
            if constexpr (requires { result.items[0].value().handle; })
            {
              if (resultCount != 0 && result.items[0].is_good())
                createdHandle = result.items[0].value().handle;
            }
          };
          const RequestInfo request{};
          if (operation == 0)
          {
            const std::array<MonitoringCreateItem, 6> items{};
            detail::MonitoringEntry::create(nameSpace,
              request,
              nullptr,
              std::span{items}.first(itemCount),
              complete,
              [&](BatchResult<MonitoringCreateItemResult> result)
              {
                for (const auto& item : result.items)
                  if (item.is_good() && releaseCount < released.size())
                    released[releaseCount++] = item.value().handle;
              });
          }
          else if (operation == 1)
          {
            const std::array<MonitoringModifyItem, 6> items{};
            detail::MonitoringEntry::modify(nameSpace, request, std::span{items}.first(itemCount), complete);
          }
          else
          {
            const std::array<MonitoringHandle, 6> handles{5, 6, 7, 8, 9, 10};
            detail::MonitoringEntry::remove(
              nameSpace, request, std::span{handles}.first(itemCount), complete);
          }
          EXPECT_FALSE(test::allocation::armed());
          EXPECT_TRUE(nameSpace->armedDuringAnswer);
          if (!injectAllocationFailure)
          {
            const auto allocations = test::allocation::recorded_sdk_allocations();
            for (const auto& allocation : allocations)
            {
              EXPECT_TRUE(allocation.nearestSdkFrame.file.ends_with("/ua_monitoring_entry.h"))
                << test::allocation::describe(allocation);
              EXPECT_NE(allocation.nearestSdkFrame.statement.find("held.push_back"), std::string::npos)
                << test::allocation::describe(allocation);
              RecordProperty("holding_allocation_" + std::to_string(itemCount) + "_" +
                               std::to_string(operation) + "_" + std::to_string(throwAfterAnswer),
                test::allocation::describe(allocation));
            }
            EXPECT_TRUE(allocations.empty()) << "An inline answer needs no holding allocation";
          }
          EXPECT_EQ(nameSpace->holdingInjections, 0U) << "An inline answer needs no holding allocation";
          EXPECT_EQ(nameSpace->completionsBeforeReturn, 0U);
          EXPECT_EQ(completions, 1U);
          if (throwAfterAnswer)
          {
            EXPECT_EQ(observed, StatusCode{Status::BadInternalError});
            EXPECT_EQ(resultCount, 0U);
            const auto* diagnostic = observed.detail();
            EXPECT_NE(diagnostic, nullptr);
            if (diagnostic)
            {
              EXPECT_EQ(diagnostic->code, "NamespaceCallThrew");
              EXPECT_EQ(diagnostic->innerStatus, nameSpace->namespaceFailure.value());
              EXPECT_EQ(diagnostic->cause, nameSpace->namespaceFailure.shared_detail());
            }
            EXPECT_EQ(releaseCount, operation == 0 ? itemCount : 0U);
            for (std::size_t index = 0; index < releaseCount; ++index)
              EXPECT_EQ(released[index], 5U + index);
          }
          else
          {
            EXPECT_TRUE(observed.is_good());
            EXPECT_EQ(resultCount, itemCount);
            EXPECT_EQ(releaseCount, 0U);
            if (operation != 2)
              EXPECT_EQ(revisedInterval, 250);
            if (operation == 0)
              EXPECT_EQ(createdHandle, 5U);
          }
        }
}

struct AllocationBorrowedOwner : std::enable_shared_from_this<AllocationBorrowedOwner>
{};

class CountingLogSink final : public LogSink
{
public:
  void log(const LogEntry&) override
  {
    ++entries;
  }

  unsigned entries{0};
};

using Tracker = client::detail::AlarmConditionTrackerImpl;
using TrackerStatusSink = std::function<void(StatusCode)>;

struct TrackerEntry
{
  std::string_view name;
  std::function<void()> (*prepare)(const std::shared_ptr<Tracker>&, TrackerStatusSink);
};

// All type erasure and argument copies happen here, before the allocation controller is armed.
// Invocation only locks weak ownership and moves the prepared callback and tuple into the real API.
template<typename ResultType, typename Method, typename... Arguments>
std::function<void()> prepare_tracker_entry(
  const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink, Method method, Arguments... arguments)
{
  std::function<void(ResultType)> callback;
  if (sink)
  {
    callback = [sink = std::move(sink)](ResultType result) mutable
    {
      sink(result.status_code());
    };
  }
  return [weak = std::weak_ptr<Tracker>{tracker},
           method,
           callback = std::move(callback),
           inputs = std::make_tuple(std::move(arguments)...)]() mutable
  {
    if (auto owner = weak.lock())
    {
      std::apply([&owner, &callback, method](auto&&... values)
        { std::invoke(method, *owner, std::move(values)..., std::move(callback)); },
        std::move(inputs));
    }
  };
}

const client::TrackedKey trackerEntryKey{NodeId{2, std::string(128, 'c')}, NodeId{2, std::string(128, 'b')}};

const std::array<TrackerEntry, 21> trackerEntries{{
  {"Start",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker, std::move(sink), &Tracker::start_async);
    }},
  {"ConditionAdded",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::on_condition_added_async,
        client::ConditionAddedCb{[](const client::TrackedCondition&) {
        }});
    }},
  {"ConditionChanged",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::on_condition_changed_async,
        client::ConditionChangedCb{[](const client::TrackedCondition&) {
        }});
    }},
  {"ConditionRemoved",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::on_condition_removed_async,
        client::ConditionRemovedCb{[](client::TrackedKey) {
        }});
    }},
  {"List",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<Result<std::vector<client::TrackedCondition>>>(
        tracker, std::move(sink), &Tracker::list_conditions_async);
    }},
  {"Get",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<Result<client::TrackedCondition>>(
        tracker, std::move(sink), &Tracker::get_condition_async, trackerEntryKey);
    }},
  {"Refresh",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker, std::move(sink), &Tracker::refresh_async);
    }},
  {"ReadAlarmMetrics",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<Result<client::AlarmMetricsSnapshot>>(
        tracker, std::move(sink), &Tracker::read_alarm_metrics_async, NodeId{2, std::string(128, 'm')});
    }},
  {"ReadProperty",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<Result<Variant>>(tracker,
        std::move(sink),
        &Tracker::read_property_async,
        trackerEntryKey,
        QualifiedName{2, std::string(128, 'p')});
    }},
  {"ResetAlarmMetrics",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::reset_alarm_metrics_async, NodeId{2, std::string(128, 'm')});
    }},
  {"Acknowledge",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::acknowledge_async,
        trackerEntryKey,
        std::optional<ByteString>{ByteString(128, 42)},
        std::optional<LocalizedText>{LocalizedText{std::string(128, 'a')}});
    }},
  {"Confirm",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::confirm_async,
        trackerEntryKey,
        std::optional<ByteString>{ByteString(128, 42)},
        std::optional<LocalizedText>{LocalizedText{std::string(128, 'c')}});
    }},
  {"AddComment",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(tracker,
        std::move(sink),
        &Tracker::add_comment_async,
        trackerEntryKey,
        ByteString(128, 42),
        std::optional<LocalizedText>{LocalizedText{std::string(128, 'a')}});
    }},
  {"Enable",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::enable_async, trackerEntryKey);
    }},
  {"Disable",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::disable_async, trackerEntryKey);
    }},
  {"Silence",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::silence_async, trackerEntryKey);
    }},
  {"Suppress",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::suppress_async, trackerEntryKey);
    }},
  {"Unsuppress",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::unsuppress_async, trackerEntryKey);
    }},
  {"TimedShelve",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::timed_shelve_async, trackerEntryKey, Duration{1000.0});
    }},
  {"OneShotShelve",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::one_shot_shelve_async, trackerEntryKey);
    }},
  {"Unshelve",
    [](const std::shared_ptr<Tracker>& tracker, TrackerStatusSink sink)
    {
      return prepare_tracker_entry<VoidResult>(
        tracker, std::move(sink), &Tracker::unshelve_async, trackerEntryKey);
    }},
}};

std::shared_ptr<Tracker> create_entry_tracker(boost::asio::io_context& context)
{
  auto sink = std::make_shared<CountingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  return Tracker::create(boost::asio::make_strand(context),
    context.get_executor(),
    {},
    {},
    Logger{sink, level, std::string(128, 't')},
    {});
}

void require_tracker_entry(
  bool condition, std::string_view name, std::size_t prefix, std::string_view message)
{
  test::allocation::disarm();
  if (!condition)
  {
    std::fprintf(stderr,
      "%.*s prefix=%zu: %.*s\n",
      numeric_cast<int>(name.size()),
      name.data(),
      prefix,
      numeric_cast<int>(message.size()),
      message.data());
    std::_Exit(EXIT_FAILURE);
  }
}

bool same_tracker_diagnostic(const ErrorDetail* actual, const ErrorDetail* expected)
{
  while (actual && expected)
  {
    if (actual->code != expected->code || actual->summary != expected->summary ||
        actual->detail != expected->detail || actual->source != expected->source ||
        actual->innerStatus != expected->innerStatus || actual->context.size() != expected->context.size())
    {
      return false;
    }
    for (std::size_t index = 0; index < actual->context.size(); ++index)
    {
      if (actual->context[index].key != expected->context[index].key ||
          actual->context[index].value != expected->context[index].value)
      {
        return false;
      }
    }
    actual = actual->cause.get();
    expected = expected->cause.get();
  }
  return actual == expected;
}

void check_tracker_entry_failure_matrix(const TrackerEntry& entry, bool completionThrows)
{
  test::allocation::disarm();
  StatusCode baseline;
  {
    boost::asio::io_context context;
    auto tracker = create_entry_tracker(context);
    unsigned completions = 0;
    auto invoke = entry.prepare(tracker,
      [&](StatusCode result)
      {
        ++completions;
        baseline = std::move(result);
      });
    invoke();
    context.run();
    require_tracker_entry(completions == 1, entry.name, 0, "baseline did not complete exactly once");
  }

  unsigned injectedPrefixes = 0;
  for (std::size_t prefix = 0; prefix <= 64; ++prefix)
  {
    boost::asio::io_context context;
    auto tracker = create_entry_tracker(context);
    unsigned completions = 0;
    std::size_t deliveryInjections = 0;
    StatusCode observed;
    auto invoke = entry.prepare(tracker,
      [&](StatusCode result)
      {
        ++completions;
        observed = std::move(result);
        deliveryInjections = test::allocation::injections();
        if (completionThrows)
        {
          throw 42;
        }
      });
    std::fprintf(
      stderr, "%.*s prefix=%zu\n", numeric_cast<int>(entry.name.size()), entry.name.data(), prefix);
    test::allocation::fail_all(prefix);
    invoke();
    context.run();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    require_tracker_entry(completions == 1, entry.name, prefix, "completion count was not one");
    if (deliveryInjections != 0)
    {
      require_tracker_entry(observed == StatusCode{Status::BadOutOfMemory} && observed.detail() &&
                              !observed.detail()->code.empty() && !observed.detail()->summary.empty(),
        entry.name,
        prefix,
        "pre-delivery injection did not produce rich BadOutOfMemory");
    }
    else
    {
      require_tracker_entry(
        observed == baseline && same_tracker_diagnostic(observed.detail(), baseline.detail()),
        entry.name,
        prefix,
        "uninjected delivery changed the baseline status or diagnostic");
    }
    if (injections == 0)
    {
      require_tracker_entry(injectedPrefixes >= 3, entry.name, prefix, "fewer than three injected prefixes");
      std::_Exit(EXIT_SUCCESS);
    }
    ++injectedPrefixes;
  }
  require_tracker_entry(
    false, entry.name, 64, "no complete injection-free iteration within the prefix bound");
}

void check_tracker_entry_empty_completion(const TrackerEntry& entry)
{
  test::allocation::disarm();
  for (std::size_t prefix = 0; prefix <= 64; ++prefix)
  {
    boost::asio::io_context context;
    auto tracker = create_entry_tracker(context);
    auto invoke = entry.prepare(tracker, {});
    std::fprintf(stderr,
      "%.*s empty completion prefix=%zu\n",
      numeric_cast<int>(entry.name.size()),
      entry.name.data(),
      prefix);
    test::allocation::fail_all(prefix);
    invoke();
    context.run();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    if (injections == 0)
    {
      std::_Exit(EXIT_SUCCESS);
    }
  }
  require_tracker_entry(false, entry.name, 64, "empty completion never reached an injection-free iteration");
}

void check_tracker_redundancy_notification_failures()
{
  test::allocation::disarm();
  unsigned injectedPrefixes = 0;
  for (std::size_t prefix = 0; prefix <= 64; ++prefix)
  {
    boost::asio::io_context context;
    auto tracker = create_entry_tracker(context);
    std::fprintf(stderr, "RedundancyNotification prefix=%zu\n", prefix);
    test::allocation::fail_all(prefix);
    tracker->on_redundancy_switch_recovered_async(RedundancySupport::Cold);
    context.run();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    if (injections == 0)
    {
      require_tracker_entry(
        injectedPrefixes >= 3, "RedundancyNotification", prefix, "fewer than three injected prefixes");
      std::_Exit(EXIT_SUCCESS);
    }
    ++injectedPrefixes;
  }
  require_tracker_entry(
    false, "RedundancyNotification", 64, "no complete injection-free notification within the prefix bound");
}

class AlarmConditionTrackerEntryAllocation : public testing::TestWithParam<TrackerEntry>
{};

void check_tracker_close_failure_matrix(bool completionThrows)
{
  unsigned failedAttempts = 0;
  bool reachedSuccess = false;
  for (std::size_t successfulAllocations = 0; successfulAllocations < 32; ++successfulAllocations)
  {
    boost::asio::io_context context;
    auto sink = std::make_shared<CountingLogSink>();
    auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
    const Logger logger{sink, level, std::string(128, 'c')};
    auto tracker = client::detail::AlarmConditionTrackerImpl::create(
      boost::asio::make_strand(context), context.get_executor(), {}, {}, logger, {});
    unsigned completions = 0;
    StatusCode observed;
    std::function<void(VoidResult)> completion = [&](VoidResult result)
    {
      ++completions;
      observed = result.status_code();
      if (completionThrows)
      {
        throw 42;
      }
    };
    test::allocation::fail_all(successfulAllocations);
    tracker->close_async(std::move(completion));
    context.run();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    const bool richFailure = injections != 0 && observed == StatusCode{Status::BadOutOfMemory} &&
                             observed.detail() && !observed.detail()->code.empty();
    const bool deliveredSuccess = observed.is_good() && (injections == 0 || completionThrows);
    if (completions != 1 || (!richFailure && !deliveredSuccess))
    {
      std::_Exit(EXIT_FAILURE);
    }
    if (observed.is_good())
    {
      reachedSuccess = true;
      break;
    }
    ++failedAttempts;
  }
  std::_Exit(failedAttempts >= 3 && reachedSuccess ? EXIT_SUCCESS : EXIT_FAILURE);
}

// Forked checks distinguish a contained allocation failure from std::terminate without terminating
// the remaining unit tests. All assertions and parent-side reporting run with interception disarmed.
void check_translation(std::exception_ptr exception, Status expected, bool throughResult)
{
  test::allocation::fail_all();
  const StatusCode status =
    throughResult ? detail::to_result([&]() -> int { std::rethrow_exception(exception); }).status_code()
                  : exception_to_status_code(exception);
  const auto failures = test::allocation::injections();
  const bool stayedArmed = test::allocation::armed();
  test::allocation::disarm();
  if (!stayedArmed || failures == 0 || status != StatusCode{expected} || !status.detail() ||
      status.detail()->code.empty() || status.detail()->summary.empty())
  {
    std::_Exit(EXIT_FAILURE);
  }
  std::_Exit(EXIT_SUCCESS);
}

void check_ua_exception(bool throughResult)
{
  const std::shared_ptr<const ErrorDetail> originalDetail =
    make_error_detail("ExistingFailure", "Original diagnostic", "UnitTest");
  const StatusCode original{utils::to_underlying(Status::BadNodeIdUnknown) | 0x80U, originalDetail};
  const auto exception = std::make_exception_ptr(UaException{original});
  test::allocation::fail_all();
  const StatusCode translated =
    throughResult ? detail::to_result([&]() -> int { std::rethrow_exception(exception); }).status_code()
                  : exception_to_status_code(exception);
  const auto failures = test::allocation::injections();
  test::allocation::disarm();
  if (translated.value() != original.value() || translated.shared_detail() != original.shared_detail() ||
      failures != 0)
  {
    std::_Exit(EXIT_FAILURE);
  }
  std::_Exit(EXIT_SUCCESS);
}

void check_callback_reporting(std::exception_ptr exception)
{
  auto sink = std::make_shared<CountingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  const Logger logger{sink, level, "AllocationFailureCallbackReporting"};
  unsigned callbacks = 0;
  test::allocation::fail_all();
  detail::invoke_user_callback(logger,
    [&]
    {
      ++callbacks;
      std::rethrow_exception(exception);
    });
  const auto failures = test::allocation::injections();
  test::allocation::disarm();
  if (callbacks != 1 || failures == 0 || sink->entries != 0)
  {
    std::_Exit(EXIT_FAILURE);
  }
  std::_Exit(EXIT_SUCCESS);
}

void check_valueless_cause(bool (*check)(const client::ReconnectCause&))
{
  client::RedundancySwitchInfo switchInfo;
  switchInfo.fromUri = std::string(128, 'a');
  client::ReconnectCause cause{client::TransportDropped{}};
  bool allocationFailed = false;
  test::allocation::fail_all();
  try
  {
    cause.emplace<client::RedundancySwitchInfo>(switchInfo);
  }
  catch (const std::bad_alloc&)
  {
    allocationFailed = true;
  }
  const auto failures = test::allocation::injections();
  test::allocation::disarm();
  if (!allocationFailed || failures == 0 || !cause.valueless_by_exception())
  {
    std::_Exit(EXIT_FAILURE);
  }
  std::_Exit(check(cause) ? EXIT_SUCCESS : EXIT_FAILURE);
}

}  // namespace

TEST(ExceptionBoundaryAllocation, ControllerKeepsFailingUntilDisarmed)
{
  unsigned failures = 0;
  test::allocation::fail_all();
  for (unsigned attempt = 0; attempt < 2; ++attempt)
  {
    try
    {
      void* allocation = ::operator new(64);
      ::operator delete(allocation);
    }
    catch (const std::bad_alloc&)
    {
      ++failures;
    }
  }
  const auto injections = test::allocation::injections();
  const bool stayedArmed = test::allocation::armed();
  test::allocation::disarm();
  EXPECT_EQ(failures, 2U);
  EXPECT_EQ(injections, 2U);
  EXPECT_TRUE(stayedArmed);
}

TEST(ExceptionBoundaryAllocation, ToResultBadAllocRetainsDiagnostic)
{
  EXPECT_EXIT(check_translation(std::make_exception_ptr(std::bad_alloc{}), Status::BadOutOfMemory, true),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ToResultStdExceptionRetainsDiagnostic)
{
  EXPECT_EXIT(
    check_translation(
      std::make_exception_ptr(std::runtime_error{"Original failure"}), Status::BadInternalError, true),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ToResultUnknownExceptionRetainsDiagnostic)
{
  EXPECT_EXIT(check_translation(std::make_exception_ptr(42), Status::BadInternalError, true),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ExceptionToStatusBadAllocRetainsDiagnostic)
{
  EXPECT_EXIT(check_translation(std::make_exception_ptr(std::bad_alloc{}), Status::BadOutOfMemory, false),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ExceptionToStatusStdExceptionRetainsDiagnostic)
{
  EXPECT_EXIT(
    check_translation(
      std::make_exception_ptr(std::runtime_error{"Original failure"}), Status::BadInternalError, false),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ExceptionToStatusUnknownExceptionRetainsDiagnostic)
{
  EXPECT_EXIT(check_translation(std::make_exception_ptr(42), Status::BadInternalError, false),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ToResultUaExceptionPreservesDetailIdentity)
{
  EXPECT_EXIT(check_ua_exception(true), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST(ExceptionBoundaryAllocation, ExceptionToStatusUaExceptionPreservesDetailIdentity)
{
  EXPECT_EXIT(check_ua_exception(false), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST(ExceptionBoundaryAllocation, EmergencyDiagnosticRemainsAvailableAfterStaticDestruction)
{
  EXPECT_EXIT((
                []
                {
                  const auto exception = std::make_exception_ptr(std::bad_alloc{});
                  __cxa_finalize(nullptr);
                  check_translation(exception, Status::BadOutOfMemory, false);
                })(),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, StdCallbackExceptionCannotEscapeFailedLogging)
{
  EXPECT_EXIT(check_callback_reporting(std::make_exception_ptr(std::runtime_error{"Callback failed"})),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, UnknownCallbackExceptionCannotEscapeFailedLogging)
{
  EXPECT_EXIT(
    check_callback_reporting(std::make_exception_ptr(42)), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST(ExceptionBoundaryAllocation, ValuelessReconnectCauseHasLowerPriorityThanValidCauses)
{
  EXPECT_EXIT(check_valueless_cause([](const client::ReconnectCause& cause)
                { return client::detail::reconnect_cause_priority(cause) == -1; }),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ValuelessReconnectCauseHasAnUnknownName)
{
  EXPECT_EXIT(check_valueless_cause([](const client::ReconnectCause& cause)
                { return client::detail::reconnect_cause_name(cause) == "Unknown"; }),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(ExceptionBoundaryAllocation, ValidReconnectCauseReplacesValuelessCauseOnly)
{
  EXPECT_EXIT(check_valueless_cause(
                [](const client::ReconnectCause& cause)
                {
                  const client::ReconnectCause valid{client::TransportDropped{}};
                  return client::detail::reconnect_cause_upgrades(cause, valid) &&
                         !client::detail::reconnect_cause_upgrades(valid, cause) &&
                         !client::detail::reconnect_cause_upgrades(cause, cause);
                }),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(PostBorrowingAllocation, FailedEnqueueCompletesOnceWithRichOutOfMemory)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  unsigned completions = 0;
  StatusCode observed;
  auto post = async::post_borrowing(
    owner.get(),
    context.get_executor(),
    Logger{},
    [&](VoidResult result)
    {
      ++completions;
      observed = result.status_code();
    },
    VoidResult{Status::BadShutdown},
    [](AllocationBorrowedOwner&, auto completion) { completion(VoidResult{}); });
  // Every allocation fails, so the first to fail is now the helper's own state, made when it is invoked;
  // EveryInvocationAllocationFailureAnswersOnce fails the later ones, the enqueue among them. The private
  // executable also intercepts the aligned_alloc used by Asio's default queue allocator.
  test::allocation::fail_all();
  post();
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_GT(injections, 0U);
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
  ASSERT_NE(observed.detail(), nullptr);
  EXPECT_FALSE(observed.detail()->code.empty());
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingAllocation, FailedEnqueuePreservesTheMoveOnlyFallback)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  auto fallback = std::make_unique<int>(42);
  const int* expected = fallback.get();
  unsigned completions = 0;
  std::unique_ptr<int> observed;
  auto post = async::post_borrowing(
    owner.get(),
    context.get_executor(),
    Logger{},
    [&](std::unique_ptr<int> result)
    {
      ++completions;
      observed = std::move(result);
    },
    std::move(fallback),
    [](AllocationBorrowedOwner&, auto completion) { completion(std::make_unique<int>(0)); });
  test::allocation::fail_all();
  post();
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_GT(injections, 0U);
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed.get(), expected);
  ASSERT_NE(observed, nullptr);
  EXPECT_EQ(*observed, 42);
}

// A noexcept service entry point builds the helper with no try around it, so building it must not allocate:
// with every allocation failing, construction from owned inputs completes, and the callable still delivers
// its result once afterwards.
// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-ALLOCATES-NOTHING, scope=function)
TEST(PostBorrowingAllocation, ConstructionFromOwnedInputsAllocatesNothing)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  unsigned completions = 0;
  StatusCode observed{Status::BadInternalError};
  Logger logger;
  VoidResult fallback{Status::BadShutdown};
  const auto make = [&]
  {
    return async::post_borrowing(
      owner.get(),
      context.get_executor(),
      std::move(logger),
      [&](VoidResult result)
      {
        ++completions;
        observed = result.status_code();
      },
      std::move(fallback),
      [](AllocationBorrowedOwner&, auto completion) { completion(VoidResult{}); });
  };
  std::optional<decltype(make())> post;
  bool constructionThrew = false;
  test::allocation::fail_all();
  try
  {
    post.emplace(make());
  }
  catch (const std::bad_alloc&)
  {
    constructionThrew = true;
  }
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_FALSE(constructionThrew) << "building the helper threw bad_alloc";
  EXPECT_EQ(injections, 0U) << "building the helper allocated";
  ASSERT_TRUE(post.has_value());
  (*post)();
  context.run();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(observed.is_good()) << to_string(observed);
}

// Every allocation the helper makes happens when it is invoked, inside its exception boundary: failing each
// in turn, from the first, still delivers exactly one answer, BadOutOfMemory until the sweep reaches an
// invocation that needs no more allocations than it was allowed.
// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-ALLOCATES-NOTHING, scope=function)
TEST(PostBorrowingAllocation, EveryInvocationAllocationFailureAnswersOnce)
{
  bool reachedSuccess = false;
  unsigned failures = 0;
  for (std::size_t allowed = 0; allowed < 64 && !reachedSuccess; ++allowed)
  {
    boost::asio::io_context context;
    const auto owner = std::make_shared<AllocationBorrowedOwner>();
    unsigned completions = 0;
    StatusCode observed{Status::BadInternalError};
    auto post = async::post_borrowing(
      owner.get(),
      context.get_executor(),
      Logger{},
      [&](VoidResult result)
      {
        ++completions;
        observed = result.status_code();
      },
      VoidResult{Status::BadShutdown},
      [](AllocationBorrowedOwner&, auto completion) { completion(VoidResult{}); });
    test::allocation::fail_all(allowed);
    post();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    context.run();
    EXPECT_EQ(completions, 1U) << "allowed allocations: " << allowed;
    if (injections == 0)
    {
      reachedSuccess = true;
      EXPECT_TRUE(observed.is_good()) << to_string(observed);
    }
    else
    {
      ++failures;
      EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory}) << "allowed allocations: " << allowed;
    }
  }
  EXPECT_GT(failures, 0U);
  RecordProperty("invocation_allocation_failure_points", failures);
  EXPECT_TRUE(reachedSuccess);
}

// The same sweep with a move-only payload, which has no rich status to carry: each failed invocation
// answers once with the caller's own fallback, whichever allocation failed.
// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-ALLOCATES-NOTHING, scope=function)
TEST(PostBorrowingAllocation, EveryInvocationAllocationFailurePreservesTheMoveOnlyFallback)
{
  bool reachedSuccess = false;
  unsigned failures = 0;
  for (std::size_t allowed = 0; allowed < 64 && !reachedSuccess; ++allowed)
  {
    boost::asio::io_context context;
    const auto owner = std::make_shared<AllocationBorrowedOwner>();
    auto fallback = std::make_unique<int>(42);
    const int* expectedFallback = fallback.get();
    unsigned completions = 0;
    std::unique_ptr<int> observed;
    auto post = async::post_borrowing(
      owner.get(),
      context.get_executor(),
      Logger{},
      [&](std::unique_ptr<int> result)
      {
        ++completions;
        observed = std::move(result);
      },
      std::move(fallback),
      [](AllocationBorrowedOwner&, auto completion) { completion(std::unique_ptr<int>{}); });
    test::allocation::fail_all(allowed);
    post();
    const auto injections = test::allocation::injections();
    test::allocation::disarm();
    context.run();
    EXPECT_EQ(completions, 1U) << "allowed allocations: " << allowed;
    if (injections == 0)
    {
      reachedSuccess = true;
      EXPECT_EQ(observed, nullptr) << "the handler's own answer";
    }
    else
    {
      ++failures;
      EXPECT_EQ(observed.get(), expectedFallback) << "allowed allocations: " << allowed;
    }
  }
  EXPECT_GT(failures, 0U);
  RecordProperty("invocation_allocation_failure_points_move_only", failures);
  EXPECT_TRUE(reachedSuccess);
}

// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-PREPARATION-FAILURE, scope=function)
TEST(PostBorrowingAllocation, FailedLoggerCopyLeavesTheCallerCompletionUsable)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  auto sink = std::make_shared<CountingLogSink>();
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  const Logger logger{sink, level, std::string(128, 'c')};
  unsigned completions = 0;
  std::function<void(VoidResult)> completion = [&](VoidResult)
  {
    ++completions;
  };
  bool setupFailed = false;
  test::allocation::fail_all();
  try
  {
    auto post = async::post_borrowing(owner.get(),
      context.get_executor(),
      logger,
      std::move(completion),
      VoidResult{Status::BadShutdown},
      [](AllocationBorrowedOwner&, auto callback) { callback(VoidResult{}); });
    test::allocation::disarm();
    post();
  }
  catch (const std::bad_alloc&)
  {
    setupFailed = true;
  }
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_TRUE(setupFailed);
  EXPECT_GT(injections, 0U);
  ASSERT_TRUE(completion);
  completion(VoidResult{Status::BadOutOfMemory});
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingAllocation, SustainedFailureInsideTheHandlerStillCompletes)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  unsigned completions = 0;
  StatusCode observed;
  async::post_borrowing(
    owner.get(),
    context.get_executor(),
    Logger{},
    [&](VoidResult result)
    {
      ++completions;
      observed = result.status_code();
    },
    VoidResult{Status::BadShutdown},
    [](AllocationBorrowedOwner&, auto)
    {
      test::allocation::fail_all();
      void* allocation = ::operator new(64);
      ::operator delete(allocation);
    })();
  context.run();
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_GT(injections, 0U);
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
  ASSERT_NE(observed.detail(), nullptr);
  EXPECT_FALSE(observed.detail()->code.empty());
}

// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-PREPARATION-FAILURE, scope=function)
TEST(PostBorrowingAllocation, FailedCompletionCopiesRetainTheRvalueFallback)
{
  bool reachedSuccess = false;
  unsigned failures = 0;
  for (std::size_t allowed = 0; allowed < 32 && !reachedSuccess; ++allowed)
  {
    boost::asio::io_context context;
    const auto owner = std::make_shared<AllocationBorrowedOwner>();
    auto fallback = std::make_unique<int>(42);
    const int* expectedFallback = fallback.get();
    unsigned completions = 0;
    std::function<void(std::unique_ptr<int>)> completion = [text = std::string(128, 'a'), &completions](
                                                             std::unique_ptr<int>)
    {
      EXPECT_EQ(text.back(), 'a');
      ++completions;
    };
    test::allocation::fail_all(allowed);
    try
    {
      auto post = async::post_borrowing(owner.get(),
        context.get_executor(),
        Logger{},
        completion,
        std::move(fallback),
        [](AllocationBorrowedOwner&, auto callback) { callback(std::make_unique<int>(0)); });
      test::allocation::disarm();
      reachedSuccess = true;
      EXPECT_TRUE(completion);
      post();
      context.run();
      EXPECT_EQ(completions, 1U);
    }
    catch (const std::bad_alloc&)
    {
      const auto injections = test::allocation::injections();
      test::allocation::disarm();
      ++failures;
      EXPECT_GT(injections, 0U);
      ASSERT_TRUE(completion);
      EXPECT_EQ(fallback.get(), expectedFallback);
      completion(std::move(fallback));
      EXPECT_EQ(completions, 1U);
    }
    test::allocation::disarm();
  }
  EXPECT_GT(failures, 0U);
  RecordProperty("completion_copy_allocation_failure_points", failures);
  EXPECT_TRUE(reachedSuccess);
}

// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-PREPARATION-FAILURE, scope=function)
TEST(PostBorrowingAllocation, FailedFallbackCopiesRetainTheMoveOnlyCompletion)
{
  bool reachedSuccess = false;
  unsigned failures = 0;
  for (std::size_t allowed = 0; allowed < 32 && !reachedSuccess; ++allowed)
  {
    boost::asio::io_context context;
    const auto owner = std::make_shared<AllocationBorrowedOwner>();
    const std::vector<std::string> fallback{std::string(128, 'a')};
    unsigned completions = 0;
    bool retainedMarker = false;
    auto completion = [marker = std::make_unique<int>(42), &completions, &retainedMarker](
                        std::vector<std::string>)
    {
      ++completions;
      retainedMarker = marker && *marker == 42;
    };
    test::allocation::fail_all(allowed);
    try
    {
      auto post = async::post_borrowing(owner.get(),
        context.get_executor(),
        Logger{},
        std::move(completion),
        fallback,
        [](AllocationBorrowedOwner&, auto callback) { callback(std::vector<std::string>{}); });
      test::allocation::disarm();
      reachedSuccess = true;
      post();
      context.run();
      EXPECT_EQ(completions, 1U);
      EXPECT_TRUE(retainedMarker);
    }
    catch (const std::bad_alloc&)
    {
      const auto injections = test::allocation::injections();
      test::allocation::disarm();
      ++failures;
      EXPECT_GT(injections, 0U);
      ASSERT_EQ(fallback.size(), 1U);
      EXPECT_EQ(fallback.front(), std::string(128, 'a'));
      completion({});
      EXPECT_EQ(completions, 1U);
      EXPECT_TRUE(retainedMarker);
    }
    test::allocation::disarm();
  }
  EXPECT_GT(failures, 0U);
  RecordProperty("fallback_copy_allocation_failure_points", failures);
  EXPECT_TRUE(reachedSuccess);
}

TEST(AlarmConditionTrackerCloseAllocation, EverySetupAndBodyFailureCompletesWithRichOutOfMemory)
{
  EXPECT_EXIT(check_tracker_close_failure_matrix(false), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST(AlarmConditionTrackerCloseAllocation, AThrowingCompletionIsContainedAtEveryFailurePoint)
{
  EXPECT_EXIT(check_tracker_close_failure_matrix(true), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST(AllocationFailureController, AlignedAllocationsUseTheExistingSustainedFailureCounter)
{
  test::allocation::fail_all(1);
  void* first = std::aligned_alloc(64, 128);
  void* second = std::aligned_alloc(64, 128);
  void* third = std::aligned_alloc(64, 128);
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_NE(first, nullptr);
  EXPECT_EQ(second, nullptr);
  EXPECT_EQ(third, nullptr);
  EXPECT_EQ(injections, 2U);
  std::free(first);
  std::free(second);
  std::free(third);
  void* recovered = std::aligned_alloc(64, 128);
  EXPECT_NE(recovered, nullptr);
  std::free(recovered);
}

TEST(PostBorrowingAllocation, FailedProducerArgumentCopyCompletesWithRichOutOfMemory)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  const std::string argument(128, 'p');
  unsigned completions = 0;
  unsigned handlers = 0;
  StatusCode observed;
  auto post = async::post_borrowing(
    owner.get(),
    context.get_executor(),
    Logger{},
    [&](VoidResult result)
    {
      ++completions;
      observed = result.status_code();
    },
    VoidResult{Status::BadShutdown},
    [&](AllocationBorrowedOwner&, auto completion, std::string)
    {
      ++handlers;
      completion(VoidResult{});
    });
  test::allocation::fail_all();
  post(argument);
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_GT(injections, 0U);
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
  ASSERT_NE(observed.detail(), nullptr);
  EXPECT_FALSE(observed.detail()->code.empty());
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingAllocation, FailedProducerCallbackConversionCompletesBeforeNoexceptProducerEntry)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<AllocationBorrowedOwner>();
  unsigned completions = 0;
  bool producerEntered = false;
  StatusCode observed;
  async::post_borrowing(
    owner.get(),
    context.get_executor(),
    Logger{},
    [&](VoidResult result)
    {
      ++completions;
      observed = result.status_code();
    },
    VoidResult{Status::BadShutdown},
    [&](AllocationBorrowedOwner& actualOwner, std::function<void(VoidResult)> completion)
    {
      auto producer = [&](std::function<void(VoidResult)>) noexcept
      {
        producerEntered = true;
      };
      auto response = async::post_borrowing(&actualOwner,
        context.get_executor(),
        Logger{},
        std::move(completion),
        VoidResult{Status::BadShutdown},
        [](AllocationBorrowedOwner&, auto finish, VoidResult result) { finish(std::move(result)); });
      test::allocation::fail_all();
      producer(std::move(response));
    })();
  context.run();
  const auto injections = test::allocation::injections();
  test::allocation::disarm();
  EXPECT_GT(injections, 0U);
  EXPECT_FALSE(producerEntered);
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
  ASSERT_NE(observed.detail(), nullptr);
  EXPECT_FALSE(observed.detail()->code.empty());
}

TEST_P(AlarmConditionTrackerEntryAllocation, OwnerDestructionStillCompletesExactlyOnce)
{
  const auto& entry = GetParam();
  SCOPED_TRACE(entry.name);
  boost::asio::io_context context;
  auto tracker = create_entry_tracker(context);
  const std::weak_ptr<Tracker> weak = tracker;
  unsigned completions = 0;
  StatusCode observed;
  auto invoke = entry.prepare(tracker,
    [&](StatusCode result)
    {
      ++completions;
      observed = std::move(result);
    });
  invoke();
  tracker.reset();
  EXPECT_TRUE(weak.expired());
  context.run();
  EXPECT_TRUE(weak.expired());
  ASSERT_EQ(completions, 1U);
  EXPECT_EQ(observed, StatusCode{Status::BadConnectionClosed});
}

TEST_P(AlarmConditionTrackerEntryAllocation, EverySetupAndWorkFailureCompletesWithRichOutOfMemory)
{
  EXPECT_EXIT(
    check_tracker_entry_failure_matrix(GetParam(), false), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST_P(AlarmConditionTrackerEntryAllocation, AThrowingCompletionIsContainedAtEveryFailurePoint)
{
  EXPECT_EXIT(
    check_tracker_entry_failure_matrix(GetParam(), true), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

TEST_P(AlarmConditionTrackerEntryAllocation, AnActuallyEmptyCompletionCannotTerminate)
{
  EXPECT_EXIT(check_tracker_entry_empty_completion(GetParam()), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

INSTANTIATE_TEST_SUITE_P(AllEntryPoints, AlarmConditionTrackerEntryAllocation,
  testing::ValuesIn(trackerEntries),
  [](const testing::TestParamInfo<TrackerEntry>& info) { return std::string{info.param.name}; });

TEST(AlarmConditionTrackerNotificationAllocation, SustainedFailureCannotTerminateRedundancyRecovery)
{
  EXPECT_EXIT(check_tracker_redundancy_notification_failures(), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

// @relation(AC-COMP-ECC-CHANNEL-BOUND-DATA-ALLOCATION-FAILURE-ANSWERS-ONCE, scope=function)
TEST(ChannelBoundSignatureAllocation, EveryAllocationFailureStillAnswersOnce)
{
  for (const bool withCrypto : {true, false})
  {
    for (const bool completionThrows : {false, true})
    {
      unsigned injectedPrefixes = 0;
      bool reachedSuccess = false;
      for (std::size_t prefix = 0; prefix <= 64; ++prefix)
      {
        SCOPED_TRACE(::testing::Message() << "withCrypto=" << withCrypto << " completionThrows="
                                          << completionThrows << " prefix=" << prefix);
        boost::asio::io_context context;
        const auto strand = boost::asio::make_strand(context);
        std::shared_ptr<const Crypto> crypto;
        if (withCrypto)
        {
          crypto = create_default_crypto([] { return SecureString{""}; });
        }
        ChannelBoundSignatureInputs inputs;
        inputs.serverNonce = ByteString{0x12};
        inputs.serverCertificate = ByteString{0x56};
        inputs.clientNonce = ByteString{0x34};
        ByteString expected{0x12};
        if (withCrypto)
        {
          const auto digest = crypto->calculate_digest_sync(HashAlgorithm::Sha2256, inputs.serverCertificate);
          for (const auto value : digest)
          {
            expected.push_back(value);
          }
        }
        expected.push_back(0x34);
        auto sink = std::make_shared<CountingLogSink>();
        auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
        Logger logger{sink, level, std::string(128, 'c')};
        unsigned completions = 0;
        std::size_t failuresAtDelivery = 0;
        StatusCode observed;
        ByteString data;
        std::function<void(ByteStringResult)> callback = [&](ByteStringResult result)
        {
          ++completions;
          observed = result.status_code();
          failuresAtDelivery = test::allocation::injections();
          if (result.is_good())
          {
            data = std::move(result.value());
          }
          if (completionThrows)
          {
            throw 42;
          }
        };
        std::exception_ptr escaped;
        test::allocation::fail_all(prefix);
        try
        {
          build_channel_bound_signature_data_async(ChannelBoundSignature::UserTokenOverNone,
            HashAlgorithm::Sha2256,
            std::move(crypto),
            strand,
            std::move(logger),
            std::move(inputs),
            std::move(callback));
          context.run();
        }
        catch (...)
        {
          escaped = std::current_exception();
        }
        const auto injections = test::allocation::injections();
        test::allocation::disarm();
        ASSERT_FALSE(escaped) << "an allocation or completion exception escaped the asynchronous boundary";
        ASSERT_EQ(completions, 1U);
        if (failuresAtDelivery != 0)
        {
          EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
          ASSERT_NE(observed.detail(), nullptr);
          EXPECT_FALSE(observed.detail()->code.empty());
          EXPECT_FALSE(observed.detail()->summary.empty());
          EXPECT_FALSE(observed.detail()->source.empty());
        }
        else if (withCrypto)
        {
          EXPECT_EQ(observed, StatusCode{Status::Good});
          EXPECT_EQ(data, expected);
        }
        else
        {
          EXPECT_EQ(observed, StatusCode{Status::BadInvalidArgument});
          ASSERT_NE(observed.detail(), nullptr);
          EXPECT_EQ(observed.detail()->code, "MissingDependency");
        }
        if (injections == 0)
        {
          EXPECT_GE(injectedPrefixes, 3U);
          reachedSuccess = true;
          break;
        }
        ++injectedPrefixes;
      }
      EXPECT_TRUE(reachedSuccess) << "the allocation sweep did not reach its injection-free control";
    }
  }
}

// @relation(AC-COMP-ECC-CHANNEL-BOUND-DATA-ALLOCATION-FAILURE-ANSWERS-ONCE, scope=function)
TEST(ChannelBoundSignatureAllocation, DeferredDigestAllocationStillAnswersOnce)
{
  for (const bool completionThrows : {false, true})
  {
    unsigned injectedPrefixes = 0;
    bool reachedSuccess = false;
    for (std::size_t prefix = 0; prefix <= 64; ++prefix)
    {
      SCOPED_TRACE(::testing::Message() << "completionThrows=" << completionThrows << " prefix=" << prefix);
      boost::asio::io_context context;
      auto crypto = test_helpers::FakeAsyncCrypto::create();
      crypto->set_park_async(true);
      auto sink = std::make_shared<CountingLogSink>();
      auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
      Logger logger{sink, level, std::string(128, 'c')};
      ChannelBoundSignatureInputs inputs;
      inputs.serverNonce = ByteString{0x12};
      inputs.serverCertificate = ByteString{0x56};
      inputs.clientNonce = ByteString{0x34};
      Crypto::CalculateDigestOutputResult digest{Crypto::CalculateDigestOutput{{}, ByteString{0x78}}};
      unsigned completions = 0;
      std::size_t failuresAtDelivery = 0;
      StatusCode observed;
      ByteString data;
      build_channel_bound_signature_data_async(ChannelBoundSignature::UserTokenOverNone,
        HashAlgorithm::Sha2256,
        crypto,
        boost::asio::make_strand(context),
        std::move(logger),
        std::move(inputs),
        [&](ByteStringResult result)
        {
          ++completions;
          observed = result.status_code();
          failuresAtDelivery = test::allocation::injections();
          if (result.is_good())
          {
            data = std::move(result.value());
          }
          if (completionThrows)
          {
            throw 42;
          }
        });
      context.run();
      ASSERT_EQ(crypto->pending_calculate_digest_count(), 1U);
      ASSERT_EQ(completions, 0U);
      context.restart();
      std::exception_ptr escaped;
      test::allocation::fail_all(prefix);
      try
      {
        crypto->complete_pending_calculate_digest(0, std::move(digest));
        context.run();
      }
      catch (...)
      {
        escaped = std::current_exception();
      }
      const auto injections = test::allocation::injections();
      test::allocation::disarm();
      EXPECT_FALSE(escaped) << "a deferred digest or completion exception escaped";
      ASSERT_EQ(completions, 1U);
      EXPECT_EQ(crypto->pending_calculate_digest_count(), 0U);
      if (failuresAtDelivery != 0)
      {
        EXPECT_EQ(observed, StatusCode{Status::BadOutOfMemory});
        ASSERT_NE(observed.detail(), nullptr);
        EXPECT_FALSE(observed.detail()->code.empty());
        EXPECT_FALSE(observed.detail()->summary.empty());
        EXPECT_FALSE(observed.detail()->source.empty());
      }
      else
      {
        EXPECT_EQ(observed, StatusCode{Status::Good});
        EXPECT_EQ(data, (ByteString{0x12, 0x78, 0x34}));
      }
      if (injections == 0)
      {
        EXPECT_GE(injectedPrefixes, 3U);
        reachedSuccess = true;
        break;
      }
      ++injectedPrefixes;
    }
    EXPECT_TRUE(reachedSuccess) << "the deferred allocation sweep did not reach its injection-free control";
  }
}

// @relation(AC-COMP-ECC-SECRET-CODERS-ALLOCATION-FAILURE-ANSWERS-ONCE, scope=function)
TEST(EccEncryptedSecretAllocation, EveryAllocationFailureStillAnswersOnce)
{
  const auto crypto = create_default_crypto([] { return SecureString{"password"}; });
  const auto policy =
    std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
  const auto clientKey = test_keys::key_pair(*crypto, test_keys::KeyType::P256, 0);
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig certificateConfig;
  certificateConfig.subjectKeys = clientKey;
  certificateConfig.issuerKeys = clientKey;
  certificateConfig.subject.commonName = "AllocationTestClient";
  certificateConfig.serialNumber = "1";
  certificateConfig.basicConstraint.cA = false;
  certificateConfig.keyUsage.digitalSignature = true;
  certificateConfig.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  certificateConfig.from = DateTime::now();
  certificateConfig.to = DateTime{certificateConfig.from.value() + std::chrono::days{365}};
  const auto certificate = pki.create_cert(certificateConfig);
  const auto serverEphemeral = crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);
  const ByteString nonce(32, 0x42);
  const ByteString secret{1, 2, 3};

  boost::asio::io_context fixtureContext;
  auto fixture = std::make_shared<std::optional<ByteStringResult>>();
  encrypt_ecc_encrypted_secret_async(policy,
    crypto,
    boost::asio::make_strand(fixtureContext),
    serverEphemeral.publicKey,
    certificate,
    clientKey,
    nonce,
    secret,
    {},
    [weak = std::weak_ptr{fixture}](ByteStringResult result)
    {
      if (auto output = weak.lock())
      {
        output->emplace(std::move(result));
      }
    });
  fixtureContext.run();
  ASSERT_TRUE(fixture->has_value());
  ASSERT_TRUE(fixture->value().is_good());
  const auto envelope = fixture->value().value();

  // Owned observations let stored callbacks report without borrowing the test's stack.
  struct Observation
  {
    unsigned completions{0};
    std::size_t failuresAtDelivery{0};
    StatusCode status;
    ByteString encoded;
    std::optional<EccEncryptedSecretFields> decoded;
  };

  for (const bool encode : {true, false})
  {
    for (const bool withCrypto : {true, false})
    {
      for (const bool completionThrows : {false, true})
      {
        unsigned injectedPrefixes = 0;
        bool reachedControl = false;
        for (std::size_t prefix = 0; prefix <= 256; ++prefix)
        {
          SCOPED_TRACE(::testing::Message()
                       << "encode=" << encode << " withCrypto=" << withCrypto
                       << " completionThrows=" << completionThrows << " prefix=" << prefix);
          boost::asio::io_context context;
          const auto strand = boost::asio::make_strand(context);
          auto sink = std::make_shared<CountingLogSink>();
          auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
          Logger logger{sink, level, std::string(128, 'e')};
          std::shared_ptr<const Crypto> selectedCrypto = withCrypto ? crypto : nullptr;
          auto publicKey = serverEphemeral.publicKey;
          auto privateKey = serverEphemeral.privateKey;
          auto preparedNonce = nonce;
          auto preparedSecret = secret;
          auto preparedEnvelope = envelope;
          auto observed = std::make_shared<Observation>();
          std::function<void(ByteStringResult)> encodeCallback =
            [weak = std::weak_ptr{observed}, completionThrows](ByteStringResult result)
          {
            if (auto output = weak.lock())
            {
              ++output->completions;
              output->failuresAtDelivery = test::allocation::injections();
              output->status = result.status_code();
              if (result.is_good())
              {
                output->encoded = std::move(result).value();
              }
              if (completionThrows)
              {
                throw 42;
              }
            }
          };
          std::function<void(EccEncryptedSecretFieldsResult)> decodeCallback =
            [weak = std::weak_ptr{observed}, completionThrows](EccEncryptedSecretFieldsResult result)
          {
            if (auto output = weak.lock())
            {
              ++output->completions;
              output->failuresAtDelivery = test::allocation::injections();
              output->status = result.status_code();
              if (result.is_good())
              {
                output->decoded.emplace(std::move(result).value());
              }
              if (completionThrows)
              {
                throw 42;
              }
            }
          };
          std::exception_ptr escaped;
          test::allocation::fail_all(prefix);
          try
          {
            if (encode)
            {
              encrypt_ecc_encrypted_secret_async(policy,
                std::move(selectedCrypto),
                strand,
                std::move(publicKey),
                certificate,
                clientKey,
                std::move(preparedNonce),
                std::move(preparedSecret),
                std::move(logger),
                std::move(encodeCallback));
            }
            else
            {
              decrypt_ecc_encrypted_secret_async(std::move(preparedEnvelope),
                policy,
                std::move(selectedCrypto),
                strand,
                std::move(privateKey),
                std::move(publicKey),
                certificate,
                std::move(logger),
                std::move(decodeCallback));
            }
            context.run();
          }
          catch (...)
          {
            escaped = std::current_exception();
          }
          const auto injections = test::allocation::injections();
          test::allocation::disarm();
          EXPECT_FALSE(escaped) << "an allocation or completion exception escaped the coder";
          EXPECT_EQ(observed->completions, 1U);
          if (escaped || observed->completions != 1U)
          {
            break;
          }
          if (observed->failuresAtDelivery != 0)
          {
            EXPECT_TRUE(observed->status.is_bad());
            if (withCrypto && prefix == 0)
            {
              EXPECT_EQ(observed->status, StatusCode{Status::BadOutOfMemory});
            }
            ASSERT_NE(observed->status.detail(), nullptr);
            EXPECT_FALSE(observed->status.detail()->code.empty());
            EXPECT_FALSE(observed->status.detail()->summary.empty());
            EXPECT_FALSE(observed->status.detail()->source.empty());
          }
          else if (!withCrypto)
          {
            EXPECT_EQ(observed->status, StatusCode{Status::BadInvalidArgument});
            ASSERT_NE(observed->status.detail(), nullptr);
            EXPECT_EQ(observed->status.detail()->code, "MissingDependency");
          }
          else
          {
            ASSERT_EQ(observed->status, StatusCode{Status::Good});
            if (encode)
            {
              boost::asio::io_context controlContext;
              auto decoded = std::make_shared<std::optional<EccEncryptedSecretFieldsResult>>();
              decrypt_ecc_encrypted_secret_async(std::move(observed->encoded),
                policy,
                crypto,
                boost::asio::make_strand(controlContext),
                serverEphemeral.privateKey,
                serverEphemeral.publicKey,
                certificate,
                {},
                [weak = std::weak_ptr{decoded}](EccEncryptedSecretFieldsResult result)
                {
                  if (auto output = weak.lock())
                  {
                    output->emplace(std::move(result));
                  }
                });
              controlContext.run();
              ASSERT_TRUE(decoded->has_value());
              ASSERT_TRUE(decoded->value().is_good());
              EXPECT_EQ(decoded->value().value().nonce, nonce);
              EXPECT_EQ(decoded->value().value().secret, secret);
            }
            else
            {
              ASSERT_TRUE(observed->decoded.has_value());
              EXPECT_EQ(observed->decoded->nonce, nonce);
              EXPECT_EQ(observed->decoded->secret, secret);
            }
          }
          if (injections == 0)
          {
            EXPECT_GE(injectedPrefixes, 3U);
            reachedControl = true;
            break;
          }
          ++injectedPrefixes;
        }
        EXPECT_TRUE(reachedControl) << "the allocation sweep did not reach its injection-free control";
      }
    }
  }
}
