// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_namespace.h"

#include "per_item_join.h"

#include "ua_error_detail.h"

#include <memory>
#include <stdexcept>
#include <utility>

namespace ua::test_helpers
{

namespace
{

/// The answer to an operation on a Node: the fake holds no Nodes of its own.
ua::StatusCode holds_no_nodes()
{
  return ua::StatusCode{ua::Status::BadNotSupported,
    ua::ErrorDetail::build("FakeNamespaceHoldsNoNodes",
      "FakeNamespace holds no Nodes, so it has no References or Values to read",
      "FakeNamespace")};
}

}  // namespace

std::shared_ptr<FakeNamespace> FakeNamespace::create(std::string_view uri)
{
  return std::shared_ptr<FakeNamespace>(new FakeNamespace(uri));
}

FakeNamespace::FakeNamespace(std::string_view uri) : mUri(uri)
{}

ua::String FakeNamespace::uri() const
{
  return mUri;
}

void FakeNamespace::shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (callback)
  {
    callback(ua::VoidResult{});  // nothing armed
  }
}

std::uint16_t FakeNamespace::index() const
{
  return context().index();
}

void FakeNamespace::find_nodes_async(const ua::RequestInfo& /*request*/, std::span<const ua::NodeId> nodeIds,
  std::optional<ua::Duration> /*maxAge*/, std::function<void(ua::BatchResult<ua::NodeResult>)> complete)
{
  // Parks each id separately: resolve_each completes the batch once every parked entry has been answered,
  // so a test can drive them one at a time.
  resolve_each(nodeIds,
    std::move(complete),
    [this](const ua::NodeId& nodeId, FindNodeCallback done)
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mFinds.push_back(FindEntry{FindNodeRecord{nodeId}, std::move(done)});
    });
}

void FakeNamespace::create_nodes_async(const ua::RequestInfo& /*request*/,
  std::span<const ua::NodeCreation> nodes, std::function<void(ua::BatchResult<ua::NodeResult>)> complete)
{
  auto join = std::make_shared<ua::test::PerItemJoin<ua::NodeResult>>(nodes.size(), std::move(complete));
  for (std::size_t index = 0; index < nodes.size(); ++index)
  {
    const ua::NodeCreation& creation = nodes[index];
    CreateNodeCallback done = [join, index](ua::NodeResult created)
    {
      join->answer(index, std::move(created));
    };
    bool unsupported = false;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      unsupported = mCreateNodesUnsupported;
      if (!unsupported)
      {
        mCreates.push_back(CreateEntry{
          CreateNodeRecord{creation.nodeId, creation.nodeClass, creation.attributes}, std::move(done)});
      }
    }
    if (unsupported)
    {
      done(ua::NodeResult{ua::StatusCode{ua::Status::BadNotSupported}});
    }
  }
  join->started();
}

void FakeNamespace::delete_nodes_async(const ua::RequestInfo& /*request*/, std::span<const ua::NodeId> nodes,
  ua::ReferenceHalves /*halves*/,
  std::function<void(ua::BatchResult<ua::DeleteNodeResult>, std::vector<ua::VersionedNode>)> complete)
{
  auto join = std::make_shared<ua::test::PerItemJoin<ua::DeleteNodeResult>>(nodes.size(),
    [complete = std::move(complete)](ua::BatchResult<ua::DeleteNodeResult> deleted)
    { complete(std::move(deleted), std::vector<ua::VersionedNode>{}); });
  {
    std::lock_guard<std::mutex> lock(mMutex);
    for (std::size_t index = 0; index < nodes.size(); ++index)
    {
      mDeletes.push_back(DeleteEntry{DeleteNodeRecord{nodes[index]},
        [join, index](ua::DeleteNodeResult deleted)
        {
          join->answer(index, std::move(deleted));
        }});
    }
  }
  join->started();
}

void FakeNamespace::create_monitoring_async(const ua::RequestInfo& /*request*/,
  const ua::CallerInfo* /*caller*/, std::span<const ua::MonitoringCreateItem> items,
  CreateMonitoringCallback complete)
{
  CreateMonitoringRecord record;
  record.items.assign(items.begin(), items.end());
  std::lock_guard<std::mutex> lock(mMutex);
  mCreateMons.push_back(CreateMonEntry{std::move(record), std::move(complete)});
}

void FakeNamespace::delete_monitoring_async(const ua::RequestInfo& /*request*/,
  std::span<const ua::MonitoringHandle> handles, DeleteMonitoringCallback complete)
{
  DeleteMonitoringRecord record;
  record.handles.assign(handles.begin(), handles.end());
  std::lock_guard<std::mutex> lock(mMutex);
  mDeleteMons.push_back(DeleteMonEntry{std::move(record), std::move(complete)});
}

void FakeNamespace::modify_monitoring_async(const ua::RequestInfo& /*request*/,
  std::span<const ua::MonitoringModifyItem> items, ModifyMonitoringCallback complete)
{
  ModifyMonitoringRecord record;
  record.items.assign(items.begin(), items.end());
  std::exception_ptr exception;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    exception = mModifyMonitoringException;
    if (!exception)
      mModifyMons.push_back(ModifyMonEntry{std::move(record), std::move(complete)});
  }
  if (exception)
    std::rethrow_exception(exception);
}

void FakeNamespace::read_references_async(const ua::RequestInfo& /*request*/,
  std::span<const ua::ReferenceQuery> queries,
  std::function<void(ua::BatchResult<ua::NodeReferencesResult>)> complete)
{
  ua::BatchResult<ua::NodeReferencesResult> answer;
  answer.items.assign(queries.size(), ua::NodeReferencesResult{holds_no_nodes()});
  complete(std::move(answer));
}

void FakeNamespace::read_values_async(const ua::RequestInfo& /*request*/, const ua::CallerInfo* /*caller*/,
  std::span<const ua::ValueReadItem> items, ua::Duration /*maxAge*/, bool /*setSourceTimestamp*/,
  std::function<void(ua::BatchResult<ua::DataValueResult>)> complete)
{
  ua::BatchResult<ua::DataValueResult> answer;
  answer.items.assign(items.size(), ua::DataValueResult{holds_no_nodes()});
  complete(std::move(answer));
}

namespace
{

template<typename Vec>
std::size_t count_under_lock(std::mutex& mutex, const Vec& vec)
{
  std::lock_guard<std::mutex> lock(mutex);
  return vec.size();
}

template<typename Vec>
auto record_at_under_lock(std::mutex& mutex, const Vec& vec, std::size_t idx)
{
  std::lock_guard<std::mutex> lock(mutex);
  if (idx >= vec.size())
    throw std::out_of_range("FakeNamespace: pending index out of range");
  return vec[idx].args;
}

template<typename Vec, typename Result>
void complete_at(std::mutex& mutex, Vec& vec, std::size_t idx, Result result)
{
  std::unique_lock<std::mutex> lock(mutex);
  if (idx >= vec.size())
    throw std::out_of_range("FakeNamespace: pending index out of range");
  auto cb = std::move(vec[idx].callback);
  vec.erase(vec.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  // Fire the callback after releasing the lock - never invoke user callbacks
  // while holding a mutex (callback-safety golden rule).
  cb(std::move(result));
}

}  // namespace

std::size_t FakeNamespace::pending_find_node_count() const
{
  return count_under_lock(mMutex, mFinds);
}

std::size_t FakeNamespace::pending_create_node_count() const
{
  return count_under_lock(mMutex, mCreates);
}

std::size_t FakeNamespace::pending_delete_node_count() const
{
  return count_under_lock(mMutex, mDeletes);
}

std::size_t FakeNamespace::pending_create_monitoring_count() const
{
  return count_under_lock(mMutex, mCreateMons);
}

std::size_t FakeNamespace::pending_delete_monitoring_count() const
{
  return count_under_lock(mMutex, mDeleteMons);
}

std::size_t FakeNamespace::pending_modify_monitoring_count() const
{
  return count_under_lock(mMutex, mModifyMons);
}

FakeNamespace::FindNodeRecord FakeNamespace::pending_find_node_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mFinds, idx);
}

FakeNamespace::CreateNodeRecord FakeNamespace::pending_create_node_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mCreates, idx);
}

FakeNamespace::DeleteNodeRecord FakeNamespace::pending_delete_node_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mDeletes, idx);
}

FakeNamespace::CreateMonitoringRecord FakeNamespace::pending_create_monitoring_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mCreateMons, idx);
}

FakeNamespace::DeleteMonitoringRecord FakeNamespace::pending_delete_monitoring_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mDeleteMons, idx);
}

FakeNamespace::ModifyMonitoringRecord FakeNamespace::pending_modify_monitoring_at(std::size_t idx) const
{
  return record_at_under_lock(mMutex, mModifyMons, idx);
}

void FakeNamespace::complete_pending_find_node(std::size_t idx, ua::NodeResult result)
{
  complete_at(mMutex, mFinds, idx, std::move(result));
}

void FakeNamespace::complete_pending_create_node(std::size_t idx, ua::NodeResult result)
{
  complete_at(mMutex, mCreates, idx, std::move(result));
}

void FakeNamespace::complete_pending_delete_node(std::size_t idx, ua::DeleteNodeResult result)
{
  complete_at(mMutex, mDeletes, idx, std::move(result));
}

void FakeNamespace::complete_pending_create_monitoring(
  std::size_t idx, ua::BatchResult<ua::MonitoringCreateItemResult> result)
{
  complete_at(mMutex, mCreateMons, idx, std::move(result));
}

void FakeNamespace::complete_pending_delete_monitoring(
  std::size_t idx, ua::BatchResult<ua::VoidResult> result)
{
  complete_at(mMutex, mDeleteMons, idx, std::move(result));
}

void FakeNamespace::complete_pending_modify_monitoring(
  std::size_t idx, ua::BatchResult<ua::MonitoringModifyItemResult> result)
{
  complete_at(mMutex, mModifyMons, idx, std::move(result));
}

void FakeNamespace::set_modify_monitoring_exception(std::exception_ptr exception)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mModifyMonitoringException = std::move(exception);
}

FakeNamespace::ModifyMonitoringCallback FakeNamespace::take_pending_modify_monitoring_callback(
  std::size_t idx)
{
  std::lock_guard<std::mutex> lock(mMutex);
  if (idx >= mModifyMons.size())
    throw std::out_of_range("FakeNamespace: pending index out of range");
  auto callback = std::move(mModifyMons[idx].callback);
  mModifyMons.erase(mModifyMons.begin() + static_cast<std::ptrdiff_t>(idx));
  return callback;
}

void FakeNamespace::decline_create_nodes_as_unsupported()
{
  std::lock_guard<std::mutex> lock(mMutex);
  mCreateNodesUnsupported = true;
}

ua::AddressSpace make_address_space_with_fake_namespace(
  boost::asio::any_io_executor executor, std::shared_ptr<FakeNamespace> fakeNamespace)
{
  auto addressSpace = ua::AddressSpace::create(ua::String{"urn:test:fake-fixture"}, executor);
  addressSpace.add_namespace_sync(fakeNamespace);
  return addressSpace;
}

}  // namespace ua::test_helpers
