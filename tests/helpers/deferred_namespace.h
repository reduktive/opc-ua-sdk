// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace with deterministic asynchronous permission deferral.

#ifndef UA_TEST_DEFERRED_NAMESPACE_H
#define UA_TEST_DEFERRED_NAMESPACE_H

#include "ua_default_namespace.h"
#include "ua_namespace_authorization.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ua::test
{

/// A namespace whose immediate permission knowledge and asynchronous resolution are controlled
/// by a test. Unlike a mock-only namespace it retains the default namespace's real node surface, so the
/// same fixture can drive both direct unit tests and public service integration tests.
class DeferredNamespace final : public default_ns::Namespace
{
public:
  enum class ResolutionMode
  {
    Inline,
    Deferred,
    Failing,
    NeverCompletes
  };

  struct EffectivePermissionsCall
  {
    AccessIdentityKey identity;
    std::optional<std::vector<NodeId>> nodes;
  };

  static std::shared_ptr<DeferredNamespace> create(string_view uri, boost::asio::any_io_executor executor);

  ~DeferredNamespace() override;

  DeferredNamespace(const DeferredNamespace&) = delete;
  DeferredNamespace& operator=(const DeferredNamespace&) = delete;

  void grant(const AccessIdentityKey& identity, const NodeId& node, PermissionType permissions);
  void set_async_permissions(
    const AccessIdentityKey& identity, const NodeId& node, PermissionType permissions);
  void set_async_namespace_permissions(PermissionType permissions);
  void deny(const AccessIdentityKey& identity, const NodeId& node);
  void forget(const AccessIdentityKey& identity, const NodeId& node);
  void set_resolution_mode(ResolutionMode mode);
  void set_duplicate_completion(bool enabled);
  void set_default_access_restrictions(std::optional<AccessRestrictionType> restrictions);
  void set_default_role_permissions(std::optional<std::vector<RolePermissionType>> permissions);

  void complete_pending_resolutions();
  void complete_next_pending_resolution();
  bool wait_for_pending_resolutions(
    size_t count = 1, std::chrono::milliseconds timeout = std::chrono::seconds(2)) const;
  void wait_released_resolutions_idle() const;
  void wait_idle() const;

  std::vector<EffectivePermissionsCall> effective_permissions_calls() const;
  size_t permission_questions() const noexcept;
  std::thread::id worker_thread_id() const noexcept;

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override;
  void effective_permissions_async(const RequestInfo& request, std::shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override;
  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override;
  std::optional<AccessRestrictionType> default_access_restrictions() const override;

private:
  struct Pair
  {
    AccessIdentityKey identity;
    NodeId node;

    friend bool operator==(const Pair&, const Pair&) = default;
  };

  struct PairHash
  {
    size_t operator()(const Pair& pair) const noexcept;
  };

  DeferredNamespace(string_view uri, boost::asio::any_io_executor executor);
  void start_worker();
  void worker_loop();

  mutable std::mutex mAccessMutex;
  std::unordered_map<Pair, PermissionType, PairHash> mAnswers;
  std::unordered_map<Pair, PermissionType, PairHash> mAsyncAnswers;
  std::optional<PermissionType> mAsyncNamespacePermissions;
  bool mNamespacePermissionsRequireAsync{false};
  std::vector<EffectivePermissionsCall> mEffectivePermissionsCalls;
  ResolutionMode mResolutionMode{ResolutionMode::Inline};
  bool mDuplicateCompletion{false};
  std::optional<std::vector<RolePermissionType>> mDefaultRolePermissions{std::vector<RolePermissionType>{}};
  std::optional<AccessRestrictionType> mDefaultAccessRestrictions;
  mutable std::atomic<size_t> mPermissionQuestions{0};

  mutable std::mutex mWorkerMutex;
  mutable std::condition_variable mWorkerCondition;
  mutable std::condition_variable mIdleCondition;
  std::deque<std::function<void()>> mParked;
  size_t mReleased{};
  bool mWorkerBusy{false};
  bool mStopping{false};
  std::thread mWorker;
  std::thread::id mWorkerThreadId;
};

}  // namespace ua::test

#endif  // UA_TEST_DEFERRED_NAMESPACE_H
