// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A sink that records what reaches a monitored item, and a monitored item created on it as a
///        Subscription creates one.

#ifndef UA_TEST_MONITORED_ITEM_PROBE_H
#define UA_TEST_MONITORED_ITEM_PROBE_H

#include "ua_address_space.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_monitoring.h"
#include "ua_sinks.h"
#include "ua_status_code.h"

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <utility>
#include <vector>

namespace ua::test
{

/// A SampleSink that records every sample and notice it is given, and can be waited on.
class RecordingSampleSink final : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
        mSamples.push_back(std::move(sample));
    }
    mCv.notify_all();
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    {
      const std::lock_guard lock{mMutex};
      mNotices.emplace_back(monitoredItemId, reason);
    }
    mCv.notify_all();
  }

  void detach() override
  {}

  /// Waits until @p count samples arrived, or @p timeout passes; returns whether they did.
  bool wait_for_samples(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mSamples.size() >= count; });
  }

  std::vector<std::pair<IntegerId, DataValue>> samples() const
  {
    const std::lock_guard lock{mMutex};
    return mSamples;
  }

  std::vector<std::pair<IntegerId, StatusCode>> notices() const
  {
    const std::lock_guard lock{mMutex};
    return mNotices;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
  std::vector<std::pair<IntegerId, StatusCode>> mNotices;
};

/// Asks the namespace that holds @p item's Node to create the monitored item, as a Subscription does, and
/// returns its answer; Bad_Timeout when no answer arrives within 2 s.
inline MonitoringCreateItemResult monitor(const AddressSpace& addressSpace, MonitoringCreateItem item)
{
  auto ns = addressSpace.namespace_array().get_namespace(item.nodeId.namespace_index());
  if (!ns)
    return MonitoringCreateItemResult{StatusCode{Status::BadNodeIdUnknown}};
  auto answer = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>();
  auto answered = answer->get_future();
  const MonitoringCreateItem items[] = {std::move(item)};
  ns->create_monitoring_async(RequestInfo{},
    nullptr,
    std::span<const MonitoringCreateItem>{items},
    [answer](BatchResult<MonitoringCreateItemResult> result) { answer->set_value(std::move(result)); });
  if (answered.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    return MonitoringCreateItemResult{StatusCode{Status::BadTimeout}};
  auto result = answered.get();
  if (result.batchStatus.is_bad())
    return MonitoringCreateItemResult{result.batchStatus.status_code()};
  if (result.items.size() != 1u)
    return MonitoringCreateItemResult{StatusCode{Status::BadInternalError}};
  return std::move(result.items.front());
}

/// Asks the namespace at @p namespaceIndex to delete the monitored item @p handle, and returns its answer.
inline VoidResult unmonitor(
  const AddressSpace& addressSpace, uint16_t namespaceIndex, MonitoringHandle handle)
{
  auto ns = addressSpace.namespace_array().get_namespace(namespaceIndex);
  if (!ns)
    return VoidResult{StatusCode{Status::BadNodeIdUnknown}};
  auto answer = std::make_shared<std::promise<BatchResult<VoidResult>>>();
  auto answered = answer->get_future();
  const MonitoringHandle handles[] = {handle};
  ns->delete_monitoring_async(RequestInfo{},
    std::span<const MonitoringHandle>{handles},
    [answer](BatchResult<VoidResult> result) { answer->set_value(std::move(result)); });
  if (answered.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    return VoidResult{StatusCode{Status::BadTimeout}};
  auto result = answered.get();
  if (result.batchStatus.is_bad())
    return result.batchStatus;
  if (result.items.size() != 1u)
    return VoidResult{StatusCode{Status::BadInternalError}};
  return std::move(result.items.front());
}

}  // namespace ua::test

#endif  // UA_TEST_MONITORED_ITEM_PROBE_H
