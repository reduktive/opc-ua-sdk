// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "deferred_namespace.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"

#include <stdexcept>
#include <utility>

namespace ua::test
{

std::shared_ptr<DeferredNamespace> DeferredNamespace::create(
  string_view uri, boost::asio::any_io_executor executor)
{
  auto result = std::shared_ptr<DeferredNamespace>(new DeferredNamespace(uri, std::move(executor)));
  result->start_worker();
  return result;
}

DeferredNamespace::DeferredNamespace(string_view uri, boost::asio::any_io_executor executor)
  : default_ns::Namespace(uri, std::move(executor))
{}

DeferredNamespace::~DeferredNamespace()
{
  {
    const std::lock_guard lock(mWorkerMutex);
    mStopping = true;
    mParked.clear();
    mReleased = 0;
  }
  mWorkerCondition.notify_all();
  if (mWorker.joinable())
  {
    if (std::this_thread::get_id() == mWorkerThreadId)
    {
      std::terminate();
    }
    mWorker.join();
  }
}

size_t DeferredNamespace::PairHash::operator()(const Pair& pair) const noexcept
{
  const size_t identityHash = std::hash<AccessIdentityKey>{}(pair.identity);
  const size_t nodeHash = std::hash<NodeId>{}(pair.node);
  return identityHash ^ (nodeHash + size_t{0x9e3779b9} + (identityHash << 6U) + (identityHash >> 2U));
}

void DeferredNamespace::grant(
  const AccessIdentityKey& identity, const NodeId& node, PermissionType permissions)
{
  const std::lock_guard lock(mAccessMutex);
  mAnswers.insert_or_assign(Pair{identity, node}, permissions);
}

void DeferredNamespace::set_async_permissions(
  const AccessIdentityKey& identity, const NodeId& node, PermissionType permissions)
{
  const std::lock_guard lock(mAccessMutex);
  mAsyncAnswers.insert_or_assign(Pair{identity, node}, permissions);
}

void DeferredNamespace::set_async_namespace_permissions(PermissionType permissions)
{
  const std::lock_guard lock(mAccessMutex);
  mAsyncNamespacePermissions = permissions;
  mNamespacePermissionsRequireAsync = true;
}

void DeferredNamespace::deny(const AccessIdentityKey& identity, const NodeId& node)
{
  grant(identity, node, PermissionType{});
}

void DeferredNamespace::forget(const AccessIdentityKey& identity, const NodeId& node)
{
  const std::lock_guard lock(mAccessMutex);
  mAnswers.erase(Pair{identity, node});
}

void DeferredNamespace::set_resolution_mode(ResolutionMode mode)
{
  const std::lock_guard lock(mAccessMutex);
  mResolutionMode = mode;
}

void DeferredNamespace::set_duplicate_completion(bool enabled)
{
  const std::lock_guard lock(mAccessMutex);
  mDuplicateCompletion = enabled;
}

void DeferredNamespace::set_default_access_restrictions(std::optional<AccessRestrictionType> restrictions)
{
  const std::lock_guard lock(mAccessMutex);
  mDefaultAccessRestrictions = restrictions;
}

void DeferredNamespace::set_default_role_permissions(
  std::optional<std::vector<RolePermissionType>> permissions)
{
  const std::lock_guard lock(mAccessMutex);
  mDefaultRolePermissions = std::move(permissions);
}

std::optional<PermissionType> DeferredNamespace::effective_permissions(
  const AccessIdentity& identity, const Node* node) const
{
  mPermissionQuestions.fetch_add(1, std::memory_order_relaxed);
  if (node == nullptr)
  {
    {
      const std::lock_guard lock(mAccessMutex);
      if (mNamespacePermissionsRequireAsync)
      {
        return std::nullopt;
      }
    }
    return default_ns::Namespace::effective_permissions(identity, nullptr);
  }
  const NodeDescription described = node->attributes();
  const std::lock_guard lock(mAccessMutex);
  const auto found = mAnswers.find(Pair{identity.key(), described.node_id()});
  if (found == mAnswers.end())
    return std::nullopt;
  return found->second;
}

void DeferredNamespace::effective_permissions_async(const RequestInfo& request,
  std::shared_ptr<const AccessIdentity> identity, std::optional<std::vector<NodeId>> nodes,
  EffectivePermissionsCallback callback)
{
  (void)request;
  ResolutionMode mode;
  bool duplicateCompletion;
  {
    const std::lock_guard lock(mAccessMutex);
    mode = mResolutionMode;
    duplicateCompletion = mDuplicateCompletion;
    mEffectivePermissionsCalls.push_back(EffectivePermissionsCall{identity->key(), nodes});
  }

  if (mode == ResolutionMode::Failing)
  {
    EffectivePermissionsResult result;
    result.batchStatus = VoidResult{StatusCode{Status::BadCommunicationError,
      ErrorDetail::build("DeferredNamespaceResolutionFailed",
        "The test namespace injected an asynchronous permission failure",
        "DeferredNamespace")}};
    callback(std::move(result));
    return;
  }
  if (mode == ResolutionMode::NeverCompletes)
  {
    return;
  }

  auto completion = [this,
                      identity = std::move(identity),
                      nodes = std::move(nodes),
                      callback = std::move(callback),
                      duplicateCompletion]() mutable
  {
    EffectivePermissionsResult result;
    if (!nodes)
    {
      std::optional<PermissionType> configured;
      {
        const std::lock_guard lock(mAccessMutex);
        configured = mAsyncNamespacePermissions;
      }
      if (configured)
      {
        result.items.emplace_back(*configured);
        if (duplicateCompletion)
          callback(result);
        callback(std::move(result));
        return;
      }
      const auto permissions = default_ns::Namespace::effective_permissions(*identity, nullptr);
      if (permissions)
      {
        result.items.emplace_back(*permissions);
      }
      else
      {
        result.items.emplace_back(StatusCode{Status::BadUserAccessDenied,
          ErrorDetail::build("DeferredNamespacePermissionUnavailable",
            "No asynchronous namespace permission answer was configured",
            "DeferredNamespace")});
      }
      if (duplicateCompletion)
        callback(result);
      callback(std::move(result));
      return;
    }

    result.items.reserve(nodes->size());
    {
      const std::lock_guard lock(mAccessMutex);
      for (const auto& nodeId : *nodes)
      {
        const Pair subject{identity->key(), nodeId};
        const auto asynchronous = mAsyncAnswers.find(subject);
        if (asynchronous != mAsyncAnswers.end())
        {
          result.items.emplace_back(asynchronous->second);
          continue;
        }
        const auto immediate = mAnswers.find(subject);
        if (immediate != mAnswers.end())
        {
          result.items.emplace_back(immediate->second);
          continue;
        }
        result.items.emplace_back(StatusCode{Status::BadUserAccessDenied,
          ErrorDetail::build("DeferredNamespacePermissionUnavailable",
            "No asynchronous permission answer was configured",
            "DeferredNamespace")
            .context(ContextKeys::nodeId, nodeId.as_definition())});
      }
    }
    if (duplicateCompletion)
      callback(result);
    callback(std::move(result));
  };

  if (mode == ResolutionMode::Inline)
  {
    completion();
    return;
  }
  {
    const std::lock_guard lock(mWorkerMutex);
    mParked.push_back(std::move(completion));
  }
  mWorkerCondition.notify_all();
}

std::optional<std::vector<RolePermissionType>> DeferredNamespace::default_role_permissions() const
{
  const std::lock_guard lock(mAccessMutex);
  return mDefaultRolePermissions;
}

std::optional<AccessRestrictionType> DeferredNamespace::default_access_restrictions() const
{
  const std::lock_guard lock(mAccessMutex);
  return mDefaultAccessRestrictions;
}

void DeferredNamespace::complete_pending_resolutions()
{
  {
    const std::lock_guard lock(mWorkerMutex);
    const size_t waiting = mParked.size() - mReleased;
    if (waiting == 0)
    {
      throw std::runtime_error("DeferredNamespace has no pending permission resolution");
    }
    mReleased = mParked.size();
  }
  mWorkerCondition.notify_all();
}

void DeferredNamespace::complete_next_pending_resolution()
{
  {
    const std::lock_guard lock(mWorkerMutex);
    if (mParked.size() == mReleased)
    {
      throw std::runtime_error("DeferredNamespace has no pending permission resolution");
    }
    ++mReleased;
  }
  mWorkerCondition.notify_all();
}

bool DeferredNamespace::wait_for_pending_resolutions(size_t count, std::chrono::milliseconds timeout) const
{
  std::unique_lock lock(mWorkerMutex);
  return mWorkerCondition.wait_for(lock, timeout, [&] { return mParked.size() - mReleased >= count; });
}

void DeferredNamespace::wait_released_resolutions_idle() const
{
  std::unique_lock lock(mWorkerMutex);
  mIdleCondition.wait(lock, [&] { return !mWorkerBusy && mReleased == 0; });
}

void DeferredNamespace::wait_idle() const
{
  std::unique_lock lock(mWorkerMutex);
  mIdleCondition.wait(lock, [&] { return !mWorkerBusy && mParked.empty() && mReleased == 0; });
}

std::vector<DeferredNamespace::EffectivePermissionsCall>
  DeferredNamespace::effective_permissions_calls() const
{
  const std::lock_guard lock(mAccessMutex);
  return mEffectivePermissionsCalls;
}

size_t DeferredNamespace::permission_questions() const noexcept
{
  return mPermissionQuestions.load(std::memory_order_relaxed);
}

std::thread::id DeferredNamespace::worker_thread_id() const noexcept
{
  return mWorkerThreadId;
}

void DeferredNamespace::start_worker()
{
  mWorker = std::thread(&DeferredNamespace::worker_loop, this);
  mWorkerThreadId = mWorker.get_id();
}

void DeferredNamespace::worker_loop()
{
  while (true)
  {
    std::function<void()> completion;
    {
      std::unique_lock lock(mWorkerMutex);
      mWorkerCondition.wait(lock, [&] { return mStopping || mReleased != 0; });
      if (mStopping)
      {
        return;
      }
      completion = std::move(mParked.front());
      mParked.pop_front();
      --mReleased;
      mWorkerBusy = true;
    }

    try
    {
      completion();
    }
    catch (...)
    {}
    completion = nullptr;

    {
      const std::lock_guard lock(mWorkerMutex);
      mWorkerBusy = false;
    }
    mIdleCondition.notify_all();
  }
}

}  // namespace ua::test
