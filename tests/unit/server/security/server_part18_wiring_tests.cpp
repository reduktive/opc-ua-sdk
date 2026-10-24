// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for `ServerImpl::create` Part-18 RoleSet wiring.
///
/// Pins:
///   * No `mRoleConfiguration` -> no RoleSet configuration wiring and fail-closed namespace defaults.
///   * `mRoleConfiguration` supplied -> SDK seeds well-known defaults,
///     and reuses the supplied `RoleConfiguration` verbatim (no SDK-side copy).

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_access_control.h"
#include "ua_application_configuration.h"
#include "ua_default_namespace.h"
#include "ua_data_value.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_type.h"
#include "ua_server_impl.h"
#include "ua_sync_wait.h"

#include "namespace_registration_coordinator_test_access.h"
#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "test_utilities.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

::ua::server::CombinedConfig make_frozen_config(
  std::optional<std::vector<WellKnownRole>> wellKnownRoles = std::nullopt, bool pushManagement = true)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  appCfg.file_trust_list_configuration().defaultUserTokenGroupTrustListPath = std::nullopt;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  sc.wellKnownRoles = std::move(wellKnownRoles);
  sc.pushCertificateManagementEnabled = pushManagement;
  frozen.server = std::move(sc);
  return frozen;
}

shared_ptr<ServerImpl> create_server(boost::asio::any_io_executor ex,
  std::shared_ptr<RoleConfiguration> roleConfig = nullptr,
  std::optional<std::vector<WellKnownRole>> wellKnownRoles = std::nullopt, bool pushManagement = true)
{
  auto frozen = make_frozen_config(std::move(wellKnownRoles), pushManagement);
  ::ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::move(roleConfig);
  return ServerImpl::create(ex, std::move(frozen), std::move(components));
}

Server create_server_handle(boost::asio::any_io_executor executor,
  std::shared_ptr<RoleConfiguration> roleConfiguration = nullptr,
  std::optional<std::vector<WellKnownRole>> wellKnownRoles = std::nullopt)
{
  auto application = ua::test_utils::create_test_config();
  application.allowInsecureEndpoints = true;
  application.file_trust_list_configuration().defaultUserTokenGroupTrustListPath = std::nullopt;
  ServerConfig serverConfiguration;
  serverConfiguration.wellKnownRoles = std::move(wellKnownRoles);
  ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::move(roleConfiguration);
  return Server::create(executor,
    CreateConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = std::move(serverConfiguration)},
    std::move(components));
}

RolePermissionType permission(NodeId roleId, PermissionType permissions)
{
  RolePermissionType result;
  result.role_id() = std::move(roleId);
  result.permissions() = permissions;
  return result;
}

std::vector<NodeId> matching_children(AddressSpace& addressSpace, const NodeId& parent,
  const NodeId& referenceType, const QualifiedName& browseName)
{
  std::vector<NodeId> matches;
  auto parentAccessor = addressSpace.try_find_node_sync(parent);
  if (parentAccessor.is_bad())
  {
    return matches;
  }
  for (const auto& reference : parentAccessor.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.is_remote() || reference.type_id() != referenceType ||
        !reference.target_id().is_local())
    {
      continue;
    }
    const auto childId = reference.target_id().node_id();
    auto child = addressSpace.try_find_node_sync(childId);
    if (child.is_good() && child.value().get_browse_name() == browseName)
    {
      matches.push_back(childId);
    }
  }
  return matches;
}

NodeId metadata_node(AddressSpace& addressSpace, uint16_t namespaceIndex, string_view namespaceUri)
{
  const auto matches = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, namespaceUri});
  if (matches.size() != 1)
  {
    return {};
  }
  return matches.front();
}

DataValueResult metadata_property(AddressSpace& addressSpace, const NodeId& metadata, string_view name)
{
  const auto matches =
    matching_children(addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, name});
  if (matches.size() != 1)
  {
    return StatusCode{Status::BadNodeIdUnknown};
  }
  auto property = addressSpace.try_find_sync<VariableAccessor>(matches.front());
  if (property.is_bad())
  {
    return DataValueResult{property.status_code()};
  }
  return property.value().try_read_value_sync();
}

std::vector<RolePermissionType> role_permissions(const DataValue& value)
{
  std::vector<RolePermissionType> result;
  if (!value.value().is_array_of_structure())
  {
    return result;
  }
  for (const auto& encoded : value.value().as<Array<RefStructure<Structure>>>())
  {
    if (const auto* entry = dynamic_cast<const RolePermissionType*>(encoded.get()))
    {
      result.push_back(*entry);
    }
  }
  return result;
}

ListenerHandle configure_ephemeral_listener(Server& server)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  const auto listener = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  server.add_endpoint(listener, std::move(endpoint));
  return listener;
}

ListenerHandle configure_listener(Server& server, std::string address, std::string name)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = std::move(address);
  const auto listener = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig endpoint;
  endpoint.name = std::move(name);
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  server.add_endpoint(listener, std::move(endpoint));
  return listener;
}

VoidResult start_async_wait(Server& server)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  server.start_async([&promise](VoidResult result) mutable { promise.set_value(std::move(result)); });
  if (future.wait_for(std::chrono::seconds{10}) != std::future_status::ready)
  {
    throw std::runtime_error{"start_async did not complete"};
  }
  return future.get();
}

class NoCreateNamespace : public Namespace
{
public:
  explicit NoCreateNamespace(String uri) : mUri(std::move(uri))
  {}

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    resolve_each(nodeIds,
      std::move(batchCallback),
      [](const NodeId&, std::function<void(NodeResult)> callback)
      { callback(NodeResult{StatusCode{Status::BadNodeIdUnknown}}); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

private:
  String mUri;
};

class GovernedNoCreateNamespace final : public NoCreateNamespace
{
public:
  GovernedNoCreateNamespace(String uri, std::vector<RolePermissionType> defaults)
    : NoCreateNamespace(std::move(uri)), mDefaults(std::move(defaults))
  {}

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return mDefaults;
  }

private:
  std::vector<RolePermissionType> mDefaults;
};

struct StartupProbe
{
  std::atomic_size_t commits{0};
  std::atomic_bool commitsOnExecutor{true};
  boost::asio::any_io_executor executor;
};

class StartupPreparation final : public detail::NamespaceRegistrationPreparation
{
public:
  explicit StartupPreparation(shared_ptr<StartupProbe> probe) : mProbe(std::move(probe))
  {}

  void commit() noexcept override
  {
    mProbe->commits.fetch_add(1, std::memory_order_relaxed);
    if (mProbe->executor && !async::detail::on_executor_context(mProbe->executor))
    {
      mProbe->commitsOnExecutor.store(false, std::memory_order_relaxed);
    }
  }

private:
  shared_ptr<StartupProbe> mProbe;
};

class StartupParticipant final : public detail::NamespaceRegistrationParticipant
{
public:
  enum class Mode
  {
    Immediate,
    Deferred,
  };

  explicit StartupParticipant(Mode mode, boost::asio::any_io_executor executor)
    : mMode(mode), mProbe(std::make_shared<StartupProbe>())
  {
    mProbe->executor = std::move(executor);
  }

  void prepare_async(detail::NamespaceRegistrationCandidate,
    detail::NamespaceRegistrationPreparationCallback callback) noexcept override
  {
    bool completeInline = false;
    bool duplicateInline = false;
    {
      const std::lock_guard lock(mMutex);
      ++mCalls;
      if (mMode == Mode::Deferred)
      {
        mPending.push_back(callback);
      }
      else
      {
        completeInline = true;
        duplicateInline = mDuplicateImmediate;
      }
    }
    mChanged.notify_all();
    if (completeInline)
    {
      callback(success());
      if (duplicateInline)
      {
        callback(success());
      }
    }
  }

  void wait_for_calls(std::size_t count)
  {
    std::unique_lock lock(mMutex);
    if (!mChanged.wait_for(lock, std::chrono::seconds{10}, [&] { return mCalls >= count; }))
    {
      throw std::runtime_error{"startup participant was not called"};
    }
  }

  void release_success(bool duplicate = false)
  {
    release(success(), duplicate);
  }

  void release_failure(StatusCode failure, bool duplicate = false)
  {
    release(detail::NamespaceRegistrationPreparationResult{std::move(failure)}, duplicate);
  }

  void repeat_last_success()
  {
    detail::NamespaceRegistrationPreparationCallback callback;
    {
      const std::lock_guard lock(mMutex);
      callback = mLastReleased;
    }
    if (callback)
    {
      callback(success());
    }
  }

  void duplicate_immediate_completions(bool enabled)
  {
    const std::lock_guard lock(mMutex);
    mDuplicateImmediate = enabled;
  }

  std::size_t call_count() const
  {
    const std::lock_guard lock(mMutex);
    return mCalls;
  }

  shared_ptr<StartupProbe> probe() const
  {
    return mProbe;
  }

private:
  detail::NamespaceRegistrationPreparationResult success() const
  {
    return detail::NamespaceRegistrationPreparationResult{std::make_shared<StartupPreparation>(mProbe)};
  }

  void release(detail::NamespaceRegistrationPreparationResult result, bool duplicate)
  {
    detail::NamespaceRegistrationPreparationCallback callback;
    {
      const std::lock_guard lock(mMutex);
      if (mPending.empty())
      {
        throw std::logic_error{"no deferred startup preparation is pending"};
      }
      callback = mPending.front();
      mPending.erase(mPending.begin());
      mLastReleased = callback;
      mMode = Mode::Immediate;
    }
    callback(result);
    if (duplicate)
    {
      callback(std::move(result));
    }
  }

  mutable std::mutex mMutex;
  std::condition_variable mChanged;
  Mode mMode;
  std::size_t mCalls{0};
  bool mDuplicateImmediate{false};
  std::vector<detail::NamespaceRegistrationPreparationCallback> mPending;
  detail::NamespaceRegistrationPreparationCallback mLastReleased;
  shared_ptr<StartupProbe> mProbe;
};

void install_startup_participant(Server& server, const shared_ptr<StartupParticipant>& participant)
{
  auto addressSpace = server.address_space();
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
}

void expect_start_error(const VoidResult& result, Status expected, string_view code)
{
  EXPECT_EQ(result.status_code(), expected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, code);
}

}  // namespace

// @relation(AC-SVR-ADDRSP-056-NAMESPACE-EXPOSES-DEFAULT, scope=function)
// @relation(AC-SVR-ADDRSP-064-VENDOR-MODEL-OMITS-STANDARD-PROPERTIES, scope=function)
// @relation(AC-SVR-AUTHZ-026-EVERY-NAMESPACE-IS-REACHABLE, scope=function)
// @relation(AC-SVR-AUTHZ-026-ADOPTED-OBJECT-IS-NOT-DUPLICATED, scope=function)
// @relation(AC-SVR-AUTHZ-026-PLACEMENT-FOLLOWS-NODE-CREATION, scope=function)
// @relation(AC-SVR-AUTHZ-027-SUPPLIED-VALUES-SURVIVE, scope=function)
// @relation(AC-SVR-AUTHZ-028-UNCONFIGURED-PUBLISHES-EMPTY-AND-HIDES, scope=function)
// @relation(AC-SVR-AUTHZ-029-OVERRIDING-NOTHING-IS-CONFORMANT, scope=function)
TEST(ServerPart18WiringTest, StartSnapshotsStandardVendorAndUnspecifiedNamespaceModels)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    auto addressSpace = server.address_space();
    const std::vector<RolePermissionType> defaults{permission(NodeId{ObjectId::WellKnownRole_Observer},
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read})};

    auto standard = default_ns::Namespace::create("urn:startup:standard", pool.get_executor());
    standard->set_namespace_defaults(defaults, std::nullopt);
    const auto standardIndex = addressSpace.add_namespace_sync(standard);

    auto vendor = default_ns::Namespace::create("urn:startup:vendor", pool.get_executor());
    vendor->set_namespace_defaults(std::nullopt, std::nullopt);
    const auto vendorIndex = addressSpace.add_namespace_sync(vendor);

    auto unspecified = default_ns::Namespace::create("urn:startup:unspecified", pool.get_executor());
    const auto unspecifiedIndex = addressSpace.add_namespace_sync(unspecified);

    auto noCreate = std::make_shared<NoCreateNamespace>(String{"urn:startup:no-create"});
    const auto noCreateIndex = addressSpace.add_namespace_sync(noCreate);

    auto governedNoCreate =
      std::make_shared<GovernedNoCreateNamespace>(String{"urn:startup:governed-no-create"}, defaults);
    const auto governedNoCreateIndex = addressSpace.add_namespace_sync(governedNoCreate);

    const auto started = server.try_start_sync();
    ASSERT_TRUE(started) << started.status_code().as_uint32();

    const auto standardMetadata = metadata_node(addressSpace, standardIndex, "urn:startup:standard");
    ASSERT_FALSE(standardMetadata.is_null());
    // Created by the SDK, so it lives in namespace 1 whatever it describes. What ties it to the
    // namespace it represents is its BrowseName and NamespaceUri, not its NodeId - and the
    // authorization below proves the represented namespace's policy still governs reading it,
    // because that policy is stamped on the node rather than inherited from namespace 1.
    EXPECT_EQ(standardMetadata.namespace_index(), 1u);
    const auto defaultPermissions =
      metadata_property(addressSpace, standardMetadata, "DefaultRolePermissions");
    const auto userPermissions =
      metadata_property(addressSpace, standardMetadata, "DefaultUserRolePermissions");
    ASSERT_TRUE(defaultPermissions);
    ASSERT_TRUE(userPermissions);
    EXPECT_EQ(role_permissions(defaultPermissions.value()), defaults);
    // DefaultUserRolePermissions is the current Session's view of the array above (Part 3 5.2.9), and
    // this read presents no Session, so no Role is assigned and the published array is empty. The
    // per-Session projection itself is covered in default_role_permissions_property_tests.cpp; what
    // matters here is that startup published the Property at all, in namespace 1, governed by the
    // namespace it describes.
    EXPECT_TRUE(role_permissions(userPermissions.value()).empty());

    const auto vendorMetadata = metadata_node(addressSpace, vendorIndex, "urn:startup:vendor");
    ASSERT_FALSE(vendorMetadata.is_null());
    EXPECT_TRUE(metadata_property(addressSpace, vendorMetadata, "DefaultRolePermissions").is_bad());
    EXPECT_TRUE(metadata_property(addressSpace, vendorMetadata, "DefaultUserRolePermissions").is_bad());

    const auto unspecifiedMetadata = metadata_node(addressSpace, unspecifiedIndex, "urn:startup:unspecified");
    ASSERT_FALSE(unspecifiedMetadata.is_null());
    const auto unspecifiedDefaults =
      metadata_property(addressSpace, unspecifiedMetadata, "DefaultRolePermissions");
    const auto unspecifiedUserDefaults =
      metadata_property(addressSpace, unspecifiedMetadata, "DefaultUserRolePermissions");
    ASSERT_TRUE(unspecifiedDefaults);
    ASSERT_TRUE(unspecifiedUserDefaults);
    EXPECT_TRUE(role_permissions(unspecifiedDefaults.value()).empty());
    EXPECT_TRUE(role_permissions(unspecifiedUserDefaults.value()).empty());

    const auto noCreateMetadata = metadata_node(addressSpace, noCreateIndex, "urn:startup:no-create");
    ASSERT_FALSE(noCreateMetadata.is_null());
    EXPECT_EQ(noCreateMetadata.namespace_index(), 1u);
    for (const auto mandatoryProperty : std::array<string_view, 7>{"NamespaceUri",
           "NamespaceVersion",
           "NamespacePublicationDate",
           "IsNamespaceSubset",
           "StaticNodeIdTypes",
           "StaticNumericNodeIdRange",
           "StaticStringNodeIdPattern"})
    {
      EXPECT_TRUE(metadata_property(addressSpace, noCreateMetadata, mandatoryProperty)) << mandatoryProperty;
    }
    EXPECT_TRUE(metadata_property(addressSpace, noCreateMetadata, "DefaultAccessRestrictions"));

    const auto governedNoCreateMetadata =
      metadata_node(addressSpace, governedNoCreateIndex, "urn:startup:governed-no-create");
    ASSERT_FALSE(governedNoCreateMetadata.is_null());
    ASSERT_EQ(governedNoCreateMetadata.namespace_index(), 1u);
    auto endpoint = std::make_shared<EndpointSecurityContext>();
    endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    auto observer = std::make_shared<AccessIdentity>(AccessIdentityKey{301},
      std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_Observer}},
      std::make_shared<UserIdentity>(),
      endpoint,
      String{"urn:test:metadata-governance"});
    AccessControl accessControl{addressSpace, std::chrono::milliseconds{100}};
    const auto isPermitted = [&](const NodeAccessor& subject, AccessOperation operation)
    {
      std::promise<std::vector<AccessControl::Verdict>> promise;
      auto future = promise.get_future();
      const std::array items{AccessControl::Item{subject, operation}};
      accessControl.authorize_async(ua::RequestInfo{},
        observer,
        items,
        *endpoint,
        [&promise](std::vector<AccessControl::Verdict> verdicts) { promise.set_value(std::move(verdicts)); });
      auto verdicts = future.get();
      return verdicts.size() == 1 && verdicts[0].permitted;
    };
    auto governedObject = addressSpace.find_node_sync(governedNoCreateMetadata);
    EXPECT_TRUE(isPermitted(governedObject, AccessOperation::Browse));
    const auto namespaceUriChildren = matching_children(addressSpace,
      governedNoCreateMetadata,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, "NamespaceUri"});
    ASSERT_EQ(namespaceUriChildren.size(), 1u);
    auto governedProperty = addressSpace.find_node_sync(namespaceUriChildren.front());
    EXPECT_TRUE(isPermitted(governedProperty, AccessOperation::Read));

    const auto namespaceUris = addressSpace.namespace_array().get_namespace_array();
    for (size_t offset = 0; offset < namespaceUris.size(); ++offset)
    {
      const auto namespaceIndex = numeric_cast<uint16_t>(offset);
      const auto published = metadata_node(addressSpace, namespaceIndex, namespaceUris[offset]);
      EXPECT_FALSE(published.is_null()) << offset;
    }
    EXPECT_EQ(metadata_node(addressSpace, 0, namespaceUris[0]), NodeId{ObjectId::OPCUANamespaceMetadata});

    const auto ns0Uri =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "NamespaceUri");
    ASSERT_TRUE(ns0Uri);
    ASSERT_TRUE(ns0Uri.value().value().is_string());
    EXPECT_EQ(ns0Uri.value().value().as<String>(), String{"http://opcfoundation.org/UA/"});
    const auto ns0Version =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "NamespaceVersion");
    ASSERT_TRUE(ns0Version);
    ASSERT_TRUE(ns0Version.value().value().is_string());
    EXPECT_EQ(ns0Version.value().value().as<String>(), String{"1.05.06"});
    const auto ns0PublicationDate =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "NamespacePublicationDate");
    ASSERT_TRUE(ns0PublicationDate);
    ASSERT_TRUE(ns0PublicationDate.value().value().is_date_time());
    EXPECT_EQ(ns0PublicationDate.value().value().as<DateTime>(), DateTime::parse("2025-11-08T00:00:00Z"));
    const auto ns0Subset =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "IsNamespaceSubset");
    ASSERT_TRUE(ns0Subset);
    ASSERT_TRUE(ns0Subset.value().value().is_boolean());
    EXPECT_FALSE(ns0Subset.value().value().as<bool>());
    const auto ns0StaticTypes =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "StaticNodeIdTypes");
    ASSERT_TRUE(ns0StaticTypes);
    ASSERT_TRUE(ns0StaticTypes.value().value().is_array_of_int32());
    const auto& staticTypes = ns0StaticTypes.value().value().as<Array<int32_t>>();
    ASSERT_EQ(staticTypes.size(), 1u);
    EXPECT_EQ(staticTypes[0], 0);
    const auto ns0StaticRanges =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "StaticNumericNodeIdRange");
    ASSERT_TRUE(ns0StaticRanges);
    ASSERT_TRUE(ns0StaticRanges.value().value().is_array_of_string());
    const auto& staticRanges = ns0StaticRanges.value().value().as<Array<String>>();
    ASSERT_EQ(staticRanges.size(), 37u);
    EXPECT_EQ(staticRanges[0], String{"1:2252"});
    EXPECT_EQ(staticRanges[36], String{"31917:2147483647"});
    const auto ns0StaticPattern =
      metadata_property(addressSpace, NodeId{ObjectId::OPCUANamespaceMetadata}, "StaticStringNodeIdPattern");
    ASSERT_TRUE(ns0StaticPattern);
    ASSERT_TRUE(ns0StaticPattern.value().value().is_string());
    EXPECT_TRUE(ns0StaticPattern.value().value().as<String>().empty());

    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-SVR-DIAG-001-NAMESPACE-METADATA-PREPARATION, scope=function)
TEST(ServerPart18WiringTest, StartFailurePreservesMissingNamespacesParentAndActivatesNoListener)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    auto addressSpace = server.address_space();
    ASSERT_TRUE(addressSpace.try_delete_node_sync(NodeId{ObjectId::Server_Namespaces}, true));

    const auto started = server.try_start_sync();
    ASSERT_TRUE(started.is_bad());
    EXPECT_EQ(started.status_code(), Status::BadNodeIdUnknown);
    ASSERT_NE(started.shared_detail(), nullptr);
    EXPECT_EQ(started.shared_detail()->code, "NamespaceMetadataParentUnavailable");
    ASSERT_NE(started.shared_detail()->cause, nullptr);
    EXPECT_EQ(StatusCode{started.shared_detail()->innerStatus}, Status::BadNodeIdUnknown);
    EXPECT_TRUE(server.advertised_urls(listener).empty());
    EXPECT_TRUE(server.discovery_urls().empty());
  }
  pool.join();
}

// @relation(AC-SVR-ADDRSP-056-NAMESPACE-METADATA-START-WOULD-BLOCK, scope=function)
TEST(ServerPart18WiringTest, StartOnOwnExecutorFailsBeforeLaunchAndCanBeRetried)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = std::make_shared<Server>(create_server_handle(pool.get_executor()));
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Immediate, pool.get_executor());
    install_startup_participant(*server, participant);
    const auto listener = configure_ephemeral_listener(*server);
    auto addressSpace = server->address_space();
    auto applicationNamespace = default_ns::Namespace::create("urn:startup:would-block", pool.get_executor());
    applicationNamespace->set_namespace_defaults(
      std::vector<RolePermissionType>{
        permission(NodeId{ObjectId::WellKnownRole_Observer}, PermissionType{PermissionType::Bit::Browse})},
      std::nullopt);
    const auto namespaceIndex = addressSpace.add_namespace_sync(applicationNamespace);
    const auto callsBeforeExecutorWrappers = participant->call_count();

    auto promise = std::make_shared<std::promise<VoidResult>>();
    auto future = promise->get_future();
    boost::asio::post(pool, [server, promise] { promise->set_value(server->try_start_sync()); });
    const auto refused = future.get();
    ASSERT_TRUE(refused.is_bad());
    EXPECT_EQ(refused.status_code(), Status::BadWouldBlock);
    EXPECT_NE(refused.shared_detail(), nullptr);
    EXPECT_TRUE(server->advertised_urls(listener).empty());
    EXPECT_EQ(participant->call_count(), callsBeforeExecutorWrappers);

    auto throwingPromise = std::make_shared<std::promise<StatusCode>>();
    auto throwingFuture = throwingPromise->get_future();
    boost::asio::post(pool,
      [server, throwingPromise]
      {
        try
        {
          server->start_sync();
          throwingPromise->set_value(StatusCode{Status::Good});
        }
        catch (const UaException& exception)
        {
          throwingPromise->set_value(exception.status_code());
        }
      });
    const auto throwingRefused = throwingFuture.get();
    EXPECT_EQ(throwingRefused, Status::BadWouldBlock);
    EXPECT_NE(throwingRefused.shared_detail(), nullptr);
    EXPECT_EQ(participant->call_count(), callsBeforeExecutorWrappers);
    const auto committedMetadata = metadata_node(addressSpace, namespaceIndex, "urn:startup:would-block");
    EXPECT_FALSE(committedMetadata.is_null());

    const auto started = server->try_start_sync();
    ASSERT_TRUE(started) << started.status_code().as_uint32() << " "
                         << (started.shared_detail() ? to_string(*started.shared_detail()) : std::string{});
    EXPECT_FALSE(server->advertised_urls(listener).empty());
    EXPECT_GT(participant->call_count(), callsBeforeExecutorWrappers);
    EXPECT_EQ(metadata_node(addressSpace, namespaceIndex, "urn:startup:would-block"), committedMetadata);
    EXPECT_TRUE(server->try_shutdown_sync({.grace = std::chrono::seconds{0}}));
    server.reset();
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-01-PUBLIC-SURFACE, scope=function)
TEST(ServerPart18WiringTest, StartVariantsShareSuccessAndExactStateError)
{
  boost::asio::thread_pool pool{2};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    ASSERT_TRUE(start_async_wait(server));
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    expect_start_error(start_async_wait(server), Status::BadInvalidState, "ServerStartNotIdle");
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    ASSERT_TRUE(server.try_start_sync());
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    expect_start_error(server.try_start_sync(), Status::BadInvalidState, "ServerStartNotIdle");
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    server.start_sync();
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    try
    {
      server.start_sync();
      FAIL() << "a second throwing start returned";
    }
    catch (const UaException& exception)
    {
      EXPECT_EQ(exception.status(), Status::BadInvalidState);
      ASSERT_NE(exception.detail(), nullptr);
      EXPECT_EQ(exception.detail()->code, "ServerStartNotIdle");
    }
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-01-STATE, scope=function)
// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-01-METADATA-FAILURE, scope=function)
TEST(ServerPart18WiringTest, StartMetadataFailurePreservesDetailAndCanBeRetried)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_size_t activationCalls{0};
    ServerImplTestAccess{ServerTestAccess::impl(server)}.set_on_network_activation(
      [&] { activationCalls.fetch_add(1, std::memory_order_relaxed); });
    const auto prefix = server.address_space().namespace_array().get_namespace_array();

    std::atomic_size_t callbackCalls{0};
    std::promise<VoidResult> firstPromise;
    auto firstFuture = firstPromise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        callbackCalls.fetch_add(1, std::memory_order_relaxed);
        firstPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);

    expect_start_error(start_async_wait(server), Status::BadInvalidState, "ServerStartNotIdle");
    const StatusCode injectedFailure{Status::BadSecurityChecksFailed,
      ErrorDetail::build("InjectedStartupMetadataFailure",
        "The test lifecycle participant rejected initial namespace preparation",
        "StartupParticipant")};
    const auto injectedDetail = injectedFailure.shared_detail();
    participant->release_failure(injectedFailure, true);
    const auto first = firstFuture.get();
    EXPECT_EQ(first.status_code(), Status::BadSecurityChecksFailed);
    EXPECT_EQ(first.shared_detail(), injectedDetail);
    EXPECT_EQ(callbackCalls, 1U);
    EXPECT_EQ(activationCalls, 0U);
    EXPECT_TRUE(server.advertised_urls(listener).empty());
    EXPECT_EQ(server.address_space().namespace_array().get_namespace_array(), prefix);

    ASSERT_TRUE(start_async_wait(server));
    EXPECT_EQ(activationCalls, 1U);
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    EXPECT_EQ(server.address_space().namespace_array().get_namespace_array(), prefix);
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-01-NETWORK-ROLLBACK, scope=function)
TEST(ServerPart18WiringTest, StartNetworkFailurePreservesDetailAndCanBeRetried)
{
  boost::asio::io_context blockerContext;
  boost::asio::ip::tcp::acceptor blocker{blockerContext};
  blocker.open(boost::asio::ip::tcp::v4());
  blocker.bind({boost::asio::ip::address_v4::loopback(), 0});
  blocker.listen();
  const auto blockedPort = blocker.local_endpoint().port();

  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto first = configure_listener(server, "127.0.0.1:0", "First");
    const auto second = configure_listener(server, "127.0.0.1:" + std::to_string(blockedPort), "Conflicting");

    const auto failed = start_async_wait(server);
    expect_start_error(failed, Status::BadResourceUnavailable, "ListenerBindFailed");
    EXPECT_TRUE(server.advertised_urls(first).empty());
    EXPECT_TRUE(server.advertised_urls(second).empty());
    EXPECT_TRUE(server.discovery_urls().empty());

    boost::system::error_code closeError;
    blocker.close(closeError);
    ASSERT_FALSE(closeError);
    ASSERT_TRUE(start_async_wait(server));
    EXPECT_EQ(server.advertised_urls(first).size(), 1U);
    EXPECT_EQ(server.advertised_urls(second).size(), 1U);
    EXPECT_EQ(server.discovery_urls().size(), 2U);
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-CALLBACK-ONCE, scope=function)
TEST(ServerPart18WiringTest, StartAsyncCompletesExactlyOnceAcrossEveryTerminalPath)
{
  boost::asio::thread_pool pool{2};
  {
    auto server = create_server_handle(pool.get_executor());
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_size_t calls{0};
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        calls.fetch_add(1, std::memory_order_relaxed);
        promise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    participant->release_success(true);
    EXPECT_TRUE(future.get());
    participant->repeat_last_success();
    std::promise<void> barrier;
    auto barrierFuture = barrier.get_future();
    boost::asio::post(pool, [&] { barrier.set_value(); });
    barrierFuture.get();
    EXPECT_EQ(calls, 1U);
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  {
    auto server = create_server_handle(pool.get_executor());
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_size_t calls{0};
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        calls.fetch_add(1, std::memory_order_relaxed);
        promise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    participant->release_failure(StatusCode{Status::BadConfigurationError}, true);
    EXPECT_EQ(future.get().status_code(), Status::BadConfigurationError);
    participant->repeat_last_success();
    EXPECT_EQ(calls, 1U);
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  {
    auto server = create_server_handle(pool.get_executor());
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Immediate, pool.get_executor());
    participant->duplicate_immediate_completions(true);
    install_startup_participant(server, participant);
    ServerImplTestAccess{ServerTestAccess::impl(server)}.set_on_network_activation(
      []
      {
        throw UaException{Status::BadResourceUnavailable,
          ErrorDetail::build("InjectedNetworkActivationFailure",
            "The test activation interface rejected startup",
            "ServerPart18WiringTest")};
      });
    std::atomic_size_t calls{0};
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        calls.fetch_add(1, std::memory_order_relaxed);
        promise.set_value(std::move(result));
      });
    expect_start_error(future.get(), Status::BadResourceUnavailable, "InjectedNetworkActivationFailure");
    EXPECT_EQ(calls, 1U);
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  {
    auto server = create_server_handle(pool.get_executor());
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_size_t calls{0};
    std::promise<VoidResult> startPromise;
    auto startFuture = startPromise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        calls.fetch_add(1, std::memory_order_relaxed);
        startPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    std::promise<VoidResult> shutdownPromise;
    auto shutdownFuture = shutdownPromise.get_future();
    server.shutdown_async({.grace = std::chrono::seconds{0}},
      [&](VoidResult result) { shutdownPromise.set_value(std::move(result)); });
    EXPECT_EQ(startFuture.get().status_code(), Status::BadShutdown);
    participant->release_success(true);
    EXPECT_TRUE(shutdownFuture.get());
    participant->repeat_last_success();
    EXPECT_EQ(calls, 1U);
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-AFFINITY, scope=function)
TEST(ServerPart18WiringTest, ForeignMetadataCompletionReentersBeforeNetworkActivation)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_bool activationOnExecutor{false};
    std::atomic_bool callbackOnExecutor{false};
    std::thread::id activationThread;
    std::thread::id callbackThread;
    ServerImplTestAccess{ServerTestAccess::impl(server)}.set_on_network_activation(
      [&]
      {
        activationOnExecutor.store(
          async::detail::on_executor_context(pool.get_executor()), std::memory_order_relaxed);
        activationThread = std::this_thread::get_id();
      });

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        callbackOnExecutor.store(
          async::detail::on_executor_context(pool.get_executor()), std::memory_order_relaxed);
        callbackThread = std::this_thread::get_id();
        promise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    std::thread::id foreignThread;
    std::thread foreign(
      [&]
      {
        foreignThread = std::this_thread::get_id();
        participant->release_success();
      });
    foreign.join();
    EXPECT_TRUE(future.get());
    EXPECT_TRUE(activationOnExecutor);
    EXPECT_TRUE(callbackOnExecutor);
    EXPECT_TRUE(participant->probe()->commitsOnExecutor);
    EXPECT_NE(activationThread, foreignThread);
    EXPECT_NE(callbackThread, foreignThread);
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-NONBLOCKING, scope=function)
TEST(ServerPart18WiringTest, StartAsyncReturnsWhileMetadataPreparationIsParked)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::promise<VoidResult> startPromise;
    auto startFuture = startPromise.get_future();
    server.start_async([&](VoidResult result) { startPromise.set_value(std::move(result)); });
    participant->wait_for_calls(1);
    EXPECT_EQ(startFuture.wait_for(std::chrono::milliseconds{0}), std::future_status::timeout);
    EXPECT_TRUE(server.advertised_urls(listener).empty());

    std::promise<void> unrelated;
    auto unrelatedFuture = unrelated.get_future();
    boost::asio::post(pool, [&] { unrelated.set_value(); });
    EXPECT_EQ(unrelatedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    EXPECT_EQ(startFuture.wait_for(std::chrono::milliseconds{0}), std::future_status::timeout);
    participant->release_success();
    EXPECT_TRUE(startFuture.get());
    EXPECT_FALSE(server.advertised_urls(listener).empty());
    EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-SHUTDOWN, scope=function)
TEST(ServerPart18WiringTest, ShutdownDuringStartPreventsLateNetworkActivation)
{
  boost::asio::thread_pool pool{1};
  {
    auto server = create_server_handle(pool.get_executor());
    const auto listener = configure_ephemeral_listener(server);
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(server, participant);
    std::atomic_size_t startCalls{0};
    std::promise<VoidResult> startPromise;
    auto startFuture = startPromise.get_future();
    server.start_async(
      [&](VoidResult result)
      {
        startCalls.fetch_add(1, std::memory_order_relaxed);
        startPromise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);

    std::atomic_size_t shutdownCalls{0};
    std::promise<VoidResult> shutdownPromise;
    auto shutdownFuture = shutdownPromise.get_future();
    server.shutdown_async({.grace = std::chrono::seconds{0}},
      [&](VoidResult result)
      {
        shutdownCalls.fetch_add(1, std::memory_order_relaxed);
        shutdownPromise.set_value(std::move(result));
      });
    expect_start_error(startFuture.get(), Status::BadShutdown, "ServerShutdownDuringStart");
    EXPECT_TRUE(server.advertised_urls(listener).empty());
    participant->release_success(true);
    EXPECT_TRUE(shutdownFuture.get());
    participant->repeat_last_success();
    std::promise<void> barrier;
    auto barrierFuture = barrier.get_future();
    boost::asio::post(pool, [&] { barrier.set_value(); });
    barrierFuture.get();
    EXPECT_EQ(startCalls, 1U);
    EXPECT_EQ(shutdownCalls, 1U);
    EXPECT_TRUE(server.advertised_urls(listener).empty());
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-LIFETIME, scope=function)
TEST(ServerPart18WiringTest, DestroyWhileStartEntryIsQueuedCompletesCaller)
{
  boost::asio::io_context context;
  auto constructionGuard = boost::asio::make_work_guard(context);
  std::jthread runner([&] { context.run(); });
  std::optional<Server> server{create_server_handle(context.get_executor())};
  context.stop();
  runner.join();
  constructionGuard.reset();
  context.restart();
  auto participant =
    std::make_shared<StartupParticipant>(StartupParticipant::Mode::Immediate, context.get_executor());
  install_startup_participant(*server, participant);
  std::weak_ptr<ServerImpl> implementation = ServerTestAccess::impl_ptr(*server);
  std::atomic_size_t calls{0};
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  server->start_async(
    [&](VoidResult result)
    {
      calls.fetch_add(1, std::memory_order_relaxed);
      promise.set_value(std::move(result));
    });
  server.reset();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  expect_start_error(future.get(), Status::BadShutdown, "ServerDestroyedDuringStart");
  EXPECT_TRUE(implementation.expired());
  context.poll();
  EXPECT_EQ(calls, 1U);
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-LATE, scope=function)
// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-LIFETIME, scope=function)
TEST(ServerPart18WiringTest, DestroyDuringStartMakesLateCompletionInert)
{
  boost::asio::thread_pool pool{1};
  auto participant =
    std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
  std::atomic_size_t calls{0};
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  std::weak_ptr<ServerImpl> implementation;
  {
    std::optional<Server> server{create_server_handle(pool.get_executor())};
    install_startup_participant(*server, participant);
    auto retainedAddressSpace = server->address_space();
    implementation = ServerTestAccess::impl_ptr(*server);
    server->start_async(
      [&](VoidResult result)
      {
        calls.fetch_add(1, std::memory_order_relaxed);
        promise.set_value(std::move(result));
      });
    participant->wait_for_calls(1);
    server.reset();
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    expect_start_error(future.get(), Status::BadShutdown, "ServerDestroyedDuringStart");
    EXPECT_TRUE(implementation.expired());
    participant->release_success(true);
    participant->repeat_last_success();
    std::promise<void> barrier;
    auto barrierFuture = barrier.get_future();
    boost::asio::post(pool, [&] { barrier.set_value(); });
    barrierFuture.get();
    EXPECT_EQ(calls, 1U);
  }
  pool.join();
}

// @relation(AC-COMP-SVR-STARTUP-LIFECYCLE-02-CONCURRENT, scope=function)
TEST(ServerPart18WiringTest, ConcurrentStartCallsCreateOneAttemptAndOneListenerSet)
{
  boost::asio::thread_pool pool{2};
  {
    auto server = std::make_shared<Server>(create_server_handle(pool.get_executor()));
    const auto listener = configure_ephemeral_listener(*server);
    auto participant =
      std::make_shared<StartupParticipant>(StartupParticipant::Mode::Deferred, pool.get_executor());
    install_startup_participant(*server, participant);
    std::atomic_size_t activationCalls{0};
    ServerImplTestAccess{ServerTestAccess::impl(*server)}.set_on_network_activation(
      [&] { activationCalls.fetch_add(1, std::memory_order_relaxed); });

    constexpr std::size_t callCount = 12;
    std::mutex resultsMutex;
    std::condition_variable resultsChanged;
    std::vector<VoidResult> results;
    std::vector<std::jthread> callers;
    callers.reserve(callCount);
    for (std::size_t index = 0; index < callCount; ++index)
    {
      callers.emplace_back(
        [&, server]
        {
          server->start_async(
            [&](VoidResult result)
            {
              // Notified under the lock: the test returns, destroying resultsChanged, as soon as it sees the
              // last result.
              const std::lock_guard lock(resultsMutex);
              results.push_back(std::move(result));
              resultsChanged.notify_all();
            });
        });
    }
    callers.clear();
    participant->wait_for_calls(1);
    {
      std::unique_lock lock(resultsMutex);
      ASSERT_TRUE(resultsChanged.wait_for(
        lock, std::chrono::seconds{10}, [&] { return results.size() == callCount - 1U; }));
    }
    participant->release_success();
    {
      std::unique_lock lock(resultsMutex);
      ASSERT_TRUE(
        resultsChanged.wait_for(lock, std::chrono::seconds{10}, [&] { return results.size() == callCount; }));
    }

    const auto successes =
      std::ranges::count_if(results, [](const VoidResult& result) { return result.is_good(); });
    EXPECT_EQ(successes, 1);
    for (const auto& result : results)
    {
      if (result.is_good())
      {
        continue;
      }
      expect_start_error(result, Status::BadInvalidState, "ServerStartNotIdle");
    }
    EXPECT_EQ(activationCalls, 1U);
    EXPECT_FALSE(server->advertised_urls(listener).empty());
    EXPECT_TRUE(server->try_shutdown_sync({.grace = std::chrono::seconds{0}}));
  }
  pool.join();
}

// ============================================================================
// No `mRoleConfiguration` -> no Part-18 wiring
// ============================================================================

TEST(ServerPart18WiringTest, NoRoleConfigurationKeepsFailClosedNamespaceDefaults)
{
  // Default `ServerComponents` carries no `mRoleConfiguration`. The
  // SDK does not synthesise one - host must opt in explicitly.
  boost::asio::thread_pool tp;
  auto server = create_server(tp.get_executor());
  ServerImplTestAccess access{*server};
  EXPECT_EQ(access.role_configuration(), nullptr);
  auto ns0 = access.address_space().namespace_array().get_namespace(static_cast<uint16_t>(0));
  ASSERT_NE(ns0, nullptr);
  ASSERT_TRUE(ns0->default_role_permissions().has_value());
  EXPECT_TRUE(ns0->default_role_permissions()->empty());
}

// @relation(AC-SVR-PULLCRT-003-CERTIFICATE-GROUPS, scope=function)
TEST(ServerPart18WiringTest, PublishesOnlyImplementedCertificateGroups)
{
  boost::asio::thread_pool threadPool;
  auto server = create_server(threadPool.get_executor());
  ServerImplTestAccess access{*server};

  EXPECT_TRUE(access.address_space().try_find_node_sync(
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}));
  EXPECT_FALSE(access.address_space().try_find_node_sync(
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultHttpsGroup}));
  EXPECT_FALSE(access.address_space().try_find_node_sync(
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup}));
}

// Owner decision Q3: with push management off the server publishes no Part 12 ServerConfiguration model at
// all - the Object and everything under it are gone - and wires no push service, so nothing can change its
// certificates or trust lists through the server. With it on (the default) both are there. Falsifiable: the
// former server always published and wired them.
// @verifies AC-SVR-PULLCRT-042-PUSH-MANAGEMENT-OFF-PUBLISHES-NO-SERVER-CONFIGURATION
TEST(ServerPart18WiringTest, PushManagementOffPublishesNoServerConfigurationAndWiresNoPushService)
{
  boost::asio::thread_pool threadPool;
  auto off = create_server(threadPool.get_executor(), nullptr, std::nullopt, /*pushManagement=*/false);
  ServerImplTestAccess offAccess{*off};
  auto& offSpace = offAccess.address_space();
  EXPECT_TRUE(offSpace.try_find_node_sync(NodeId{ObjectId::Server})) << "the Server Object stays";
  EXPECT_FALSE(offSpace.try_find_node_sync(NodeId{ObjectId::ServerConfiguration}));
  EXPECT_FALSE(offSpace.try_find_node_sync(NodeId{MethodId::ServerConfiguration_ApplyChanges}));
  EXPECT_FALSE(offSpace.try_find_node_sync(NodeId{MethodId::ServerConfiguration_UpdateCertificate}));
  EXPECT_FALSE(offSpace.try_find_node_sync(
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList}));
  EXPECT_FALSE(offSpace.try_find_node_sync(
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open}));
  EXPECT_EQ(offAccess.certificate_push_service(), nullptr);

  auto on = create_server(threadPool.get_executor());
  ServerImplTestAccess onAccess{*on};
  EXPECT_TRUE(onAccess.address_space().try_find_node_sync(NodeId{ObjectId::ServerConfiguration}));
  EXPECT_TRUE(
    onAccess.address_space().try_find_node_sync(NodeId{MethodId::ServerConfiguration_ApplyChanges}));
  EXPECT_NE(onAccess.certificate_push_service(), nullptr);
}

// ============================================================================
// `mRoleConfiguration` -> Part-18 wiring runs
// ============================================================================

// @relation(AC-SVR-AUTHZ-028-NO-ROLE-MATERIALISED-PUBLISHES-EMPTY, scope=function)
TEST(ServerPart18WiringTest, RoleConfigurationDrivesPart18WiringAndSeedsWellKnownDefaults)
{
  // Host supplies an empty `RoleConfiguration`. The SDK seeds the nine well-known roles.
  auto config = std::make_shared<RoleConfiguration>();
  boost::asio::thread_pool tp;
  auto server = create_server(tp.get_executor(), config);
  ServerImplTestAccess access{*server};
  ASSERT_NE(access.role_configuration(), nullptr);
  // Same shared_ptr - SDK reuses the host's `RoleConfiguration` so
  // RoleSet mutations and authorization decisions share state.
  EXPECT_EQ(access.role_configuration().get(), config.get());

  // Well-known defaults seeded by `seed_well_known_roles`.
  EXPECT_EQ(access.role_configuration()
              ->role_bit(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)})
              .value_or(0xff),
    0);
  EXPECT_EQ(access.role_configuration()
              ->role_bit(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_AuthenticatedUser)})
              .value_or(0xff),
    1);
  EXPECT_TRUE(access.role_configuration()
                ->role_bit(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)})
                .has_value());
  EXPECT_TRUE(access.role_configuration()
                ->role_bit(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)})
                .has_value());
  // TrustedApplication (NodeId 18625, UA-1.05.04) seeded at bit 8.
  EXPECT_EQ(access.role_configuration()
              ->role_bit(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_TrustedApplication)})
              .value_or(0xff),
    8);

  // NS0 and NS1 enforce the same exact materialised-role defaults that publication reports.
  auto ns0 = access.address_space().namespace_array().get_namespace(static_cast<uint16_t>(0));
  auto ns1 = access.address_space().namespace_array().get_namespace(static_cast<uint16_t>(1));
  ASSERT_NE(ns0, nullptr);
  ASSERT_NE(ns1, nullptr);
  const auto ns0Defaults = ns0->default_role_permissions();
  const auto ns1Defaults = ns1->default_role_permissions();
  ASSERT_TRUE(ns0Defaults.has_value());
  ASSERT_TRUE(ns1Defaults.has_value());
  EXPECT_EQ(ns0Defaults->size(), 9u);
  EXPECT_EQ(*ns1Defaults, *ns0Defaults);
  for (const auto& entry : *ns0Defaults)
  {
    EXPECT_TRUE(access.role_configuration()->role_bit(entry.role_id()).has_value());
  }
}

// @relation(AC-SVR-AUTHZ-028-NO-ROLE-MATERIALISED-PUBLISHES-EMPTY, scope=function)
TEST(ServerPart18WiringTest, EmptyRoleSelectionInstallsEngagedEmptyDefaultsInNs0AndNs1)
{
  auto config = std::make_shared<RoleConfiguration>();
  boost::asio::thread_pool pool{1};
  auto server = create_server_handle(pool.get_executor(), config, std::vector<WellKnownRole>{});
  auto addressSpace = server.address_space();

  EXPECT_TRUE(config->roles().empty());
  for (const uint16_t namespaceIndex : std::array<uint16_t, 2>{0, 1})
  {
    const auto nameSpace = addressSpace.namespace_array().get_namespace(namespaceIndex);
    ASSERT_NE(nameSpace, nullptr);
    const auto defaults = nameSpace->default_role_permissions();
    ASSERT_TRUE(defaults.has_value());
    EXPECT_TRUE(defaults->empty());
  }

  const auto started = server.try_start_sync();
  ASSERT_TRUE(started) << started.status_code().as_uint32();
  const auto namespaceUris = addressSpace.namespace_array().get_namespace_array();
  ASSERT_GE(namespaceUris.size(), 2u);
  const auto applicationMetadata = metadata_node(addressSpace, 1, namespaceUris[1]);
  ASSERT_FALSE(applicationMetadata.is_null());
  const auto publishedDefaults =
    metadata_property(addressSpace, applicationMetadata, "DefaultRolePermissions");
  ASSERT_TRUE(publishedDefaults);
  EXPECT_TRUE(role_permissions(publishedDefaults.value()).empty());
  EXPECT_TRUE(metadata_property(addressSpace, applicationMetadata, "DefaultAccessRestrictions"));

  for (const auto roleName : std::array<string_view, 9>{"Anonymous",
         "AuthenticatedUser",
         "Observer",
         "Operator",
         "Engineer",
         "Supervisor",
         "ConfigureAdmin",
         "SecurityAdmin",
         "TrustedApplication"})
  {
    EXPECT_TRUE(matching_children(addressSpace,
      NodeId{ObjectId::Server_ServerCapabilities_RoleSet},
      NodeId{ReferenceTypeId::HasComponent},
      QualifiedName{0, roleName})
                  .empty())
      << roleName;
  }
  EXPECT_TRUE(server.try_shutdown_sync({.grace = std::chrono::seconds{0}}));
}

TEST(ServerPart18WiringTest, HostPrePopulatedRolesAreRetained)
{
  // Host pre-populates a custom role. `seed_well_known_roles` must skip
  // it (the role bit is already in use) and the custom role survives.
  auto config = std::make_shared<RoleConfiguration>();
  RoleConfiguration::RoleDefinition custom;
  custom.roleId = NodeId{1, 9001};
  custom.roleBit = 9;
  ASSERT_TRUE(config->add_role(std::move(custom)));

  boost::asio::thread_pool tp;
  auto server = create_server(tp.get_executor(), config);
  ServerImplTestAccess access{*server};
  ASSERT_NE(access.role_configuration(), nullptr);
  EXPECT_EQ(access.role_configuration().get(), config.get());
  EXPECT_EQ(access.role_configuration()->role_bit(NodeId{1, 9001}).value_or(0xff), 9);
}

TEST(ServerPart18WiringTest, HostRoleBitCollisionRefusesStartupWithDetail)
{
  auto config = std::make_shared<RoleConfiguration>();
  RoleConfiguration::RoleDefinition custom;
  custom.roleId = NodeId{1, 9002};
  custom.roleBit = 8;
  ASSERT_TRUE(config->add_role(std::move(custom)));

  boost::asio::thread_pool tp;
  try
  {
    (void)create_server(tp.get_executor(), config);
    FAIL() << "TrustedApplication's canonical bit collision was accepted";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadConfigurationError);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "WellKnownRoleSeedCollision");
    ASSERT_NE(std::find_if(exception.detail()->context.begin(),
                exception.detail()->context.end(),
                [](const NamedValue& value) { return value.key == ContextKeys::nodeId.value(); }),
      exception.detail()->context.end());
  }
}
