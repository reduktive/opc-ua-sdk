// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_FAKE_NAMESPACE_H
#define UA_TEST_HELPERS_FAKE_NAMESPACE_H

#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "ua_address_space.h"
#include "ua_result.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_string.h"

namespace ua::test_helpers
{

class FakeNamespace : public ua::Namespace
{
public:
  static std::shared_ptr<FakeNamespace> create(std::string_view uri);

  ua::String uri() const override;
  std::uint16_t index() const;

  /// This fake arms no timers, so stopping is immediate and says so explicitly.
  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept override;

  using FindNodeCallback = std::function<void(ua::NodeResult)>;
  using CreateNodeCallback = std::function<void(ua::NodeResult)>;
  using DeleteNodeCallback = std::function<void(ua::DeleteNodeResult)>;
  using CreateMonitoringCallback = std::function<void(ua::BatchResult<ua::MonitoringCreateItemResult>)>;
  using DeleteMonitoringCallback = std::function<void(ua::BatchResult<ua::VoidResult>)>;
  using ModifyMonitoringCallback = std::function<void(ua::BatchResult<ua::MonitoringModifyItemResult>)>;

  /// Parks each NodeId separately; the batch completes once every parked lookup has been completed.
  void find_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodeIds,
    std::optional<ua::Duration> maxAge,
    std::function<void(ua::BatchResult<ua::NodeResult>)> complete) override;
  /// Parks each creation separately, unless creations are declined.
  void create_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeCreation> nodes,
    std::function<void(ua::BatchResult<ua::NodeResult>)> complete) override;
  /// Parks each deletion separately; the batch reports no versioned Node.
  void delete_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodes,
    ua::ReferenceHalves halves,
    std::function<void(ua::BatchResult<ua::DeleteNodeResult>, std::vector<ua::VersionedNode>)> complete)
    override;

  void create_monitoring_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::MonitoringCreateItem> items, CreateMonitoringCallback complete) override;
  void delete_monitoring_async(const ua::RequestInfo& request, std::span<const ua::MonitoringHandle> handles,
    DeleteMonitoringCallback complete) override;
  void modify_monitoring_async(const ua::RequestInfo& request,
    std::span<const ua::MonitoringModifyItem> items, ModifyMonitoringCallback complete) override;

  /// The fake holds no Nodes of its own: every Reference query is answered `Bad_NotSupported`.
  void read_references_async(const ua::RequestInfo& request, std::span<const ua::ReferenceQuery> queries,
    std::function<void(ua::BatchResult<ua::NodeReferencesResult>)> complete) override;
  /// The fake holds no Nodes of its own: every Value read is answered `Bad_NotSupported`.
  void read_values_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::ValueReadItem> items, ua::Duration maxAge, bool setSourceTimestamp,
    std::function<void(ua::BatchResult<ua::DataValueResult>)> complete) override;

  struct FindNodeRecord
  {
    ua::NodeId nodeId;
  };

  struct CreateNodeRecord
  {
    ua::NodeId nodeId;
    ua::NodeClass nodeClass;
    ua::InitialAttributes initialAttributes;
  };

  struct DeleteNodeRecord
  {
    ua::NodeId nodeId;
  };

  struct CreateMonitoringRecord
  {
    std::vector<ua::MonitoringCreateItem> items;
  };

  struct DeleteMonitoringRecord
  {
    std::vector<ua::MonitoringHandle> handles;
  };

  struct ModifyMonitoringRecord
  {
    std::vector<ua::MonitoringModifyItem> items;
  };

  std::size_t pending_find_node_count() const;
  std::size_t pending_create_node_count() const;
  std::size_t pending_delete_node_count() const;
  std::size_t pending_create_monitoring_count() const;
  std::size_t pending_delete_monitoring_count() const;
  std::size_t pending_modify_monitoring_count() const;

  FindNodeRecord pending_find_node_at(std::size_t idx) const;
  CreateNodeRecord pending_create_node_at(std::size_t idx) const;
  DeleteNodeRecord pending_delete_node_at(std::size_t idx) const;
  CreateMonitoringRecord pending_create_monitoring_at(std::size_t idx) const;
  DeleteMonitoringRecord pending_delete_monitoring_at(std::size_t idx) const;
  ModifyMonitoringRecord pending_modify_monitoring_at(std::size_t idx) const;

  void complete_pending_find_node(std::size_t idx, ua::NodeResult result);
  void complete_pending_create_node(std::size_t idx, ua::NodeResult result);
  void complete_pending_delete_node(std::size_t idx, ua::DeleteNodeResult result);
  void complete_pending_create_monitoring(
    std::size_t idx, ua::BatchResult<ua::MonitoringCreateItemResult> result);
  void complete_pending_delete_monitoring(std::size_t idx, ua::BatchResult<ua::VoidResult> result);
  void complete_pending_modify_monitoring(
    std::size_t idx, ua::BatchResult<ua::MonitoringModifyItemResult> result);
  void set_modify_monitoring_exception(std::exception_ptr exception);
  ModifyMonitoringCallback take_pending_modify_monitoring_callback(std::size_t idx);

  /// Makes future creations complete immediately with BadNotSupported.
  ///
  /// Use this for fakes that exercise another namespace operation but are registered through a
  /// Server. Transactional registration first offers NamespaceMetadata materialisation to the
  /// represented namespace; declining it lets the lifecycle participant use its NS1 fallback
  /// without consuming or weakening the operation the test intends to park.
  void decline_create_nodes_as_unsupported();

private:
  explicit FakeNamespace(std::string_view uri);

  template<typename Args, typename Callback>
  struct PendingEntry
  {
    Args args;
    Callback callback;
  };

  using FindEntry = PendingEntry<FindNodeRecord, FindNodeCallback>;
  using CreateEntry = PendingEntry<CreateNodeRecord, CreateNodeCallback>;
  using DeleteEntry = PendingEntry<DeleteNodeRecord, DeleteNodeCallback>;
  using CreateMonEntry = PendingEntry<CreateMonitoringRecord, CreateMonitoringCallback>;
  using DeleteMonEntry = PendingEntry<DeleteMonitoringRecord, DeleteMonitoringCallback>;
  using ModifyMonEntry = PendingEntry<ModifyMonitoringRecord, ModifyMonitoringCallback>;

  mutable std::mutex mMutex;
  ua::String mUri;

  std::vector<FindEntry> mFinds;
  std::vector<CreateEntry> mCreates;
  std::vector<DeleteEntry> mDeletes;
  std::vector<CreateMonEntry> mCreateMons;
  std::vector<DeleteMonEntry> mDeleteMons;
  std::vector<ModifyMonEntry> mModifyMons;
  std::exception_ptr mModifyMonitoringException;
  bool mCreateNodesUnsupported{false};
};

ua::AddressSpace make_address_space_with_fake_namespace(
  boost::asio::any_io_executor executor, std::shared_ptr<FakeNamespace> fakeNamespace);

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_FAKE_NAMESPACE_H
