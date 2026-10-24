// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Public-tier integration evidence for the one-shot GDS QueryServers facade
///        (CL-DISC-013 / CL-DISC-016).

#include "compliance_helpers.h"

#include "ua_application_description.h"
#include "ua_array.h"
#include "ua_discovery.h"
#include "ua_ref_structure.h"
#include "ua_server_on_network.h"

#include <mutex>
#include <string_view>
#include <vector>

namespace
{

class ClientDiscoveryGds : public ComplianceBase
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mGdsNamespace =
      default_ns::Namespace::create("http://opcfoundation.org/UA/GDS/", mServer.thread_pool().executor());
    mGdsNamespaceIndex = addressSpace.add_namespace_sync(mGdsNamespace);

    mDirectoryId = NodeId{mGdsNamespaceIndex, std::uint32_t{5000}};
    auto directoryNode = addressSpace.create_node_sync(mDirectoryId, NodeClass::Object);
    auto directory = directoryNode.as<ObjectAccessor>();
    ASSERT_TRUE(directory);
    directory->set_browse_name(QualifiedName{mGdsNamespaceIndex, "Directory"});
    directory->set_display_name(LocalizedText{"", "Directory"});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDirectoryId);

    mQueryServersId = NodeId{mGdsNamespaceIndex, std::uint32_t{5001}};
    auto methodNode = addressSpace.create_node_sync(mQueryServersId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method);
    method->set_browse_name(QualifiedName{mGdsNamespaceIndex, "QueryServers"});
    method->set_display_name(LocalizedText{"", "QueryServers"});
    method->set_executable(true);
    directoryNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mQueryServersId);

    auto* callSource = mGdsNamespace->find_node<Node>(mQueryServersId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [this](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext>
          context,
        std::function<void(CallResult)>
          callback)
      {
        {
          std::lock_guard lock(mCallMutex);
          if (context)
          {
            mCallingSessions.push_back(context->sessionId);
          }
          mLastArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
        }

        auto server = std::make_unique<ServerOnNetwork>();
        server->record_id() = 77;
        server->server_name() = "Integration GDS Server";
        server->discovery_url() = "opc.tcp://returned.example:4840";
        server->server_capabilities().push_back("DA");
        std::unique_ptr<Structure> structure = std::move(server);
        RefStructure<Structure> reference;
        reference = std::move(structure);
        Array<RefStructure<Structure>> servers;
        servers.push_back(std::move(reference));

        CallMethodResult result;
        result.output_arguments().push_back(Variant{UtcTime{2026, 7, 24, 12, 0, 0}});
        result.output_arguments().push_back(Variant{std::move(servers)});
        callback(CallResult{std::move(result)});
      });

    mQueryApplicationsId = NodeId{mGdsNamespaceIndex, std::uint32_t{5002}};
    auto applicationsMethodNode = addressSpace.create_node_sync(mQueryApplicationsId, NodeClass::Method);
    auto applicationsMethod = applicationsMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(applicationsMethod);
    applicationsMethod->set_browse_name(QualifiedName{mGdsNamespaceIndex, "QueryApplications"});
    applicationsMethod->set_display_name(LocalizedText{"", "QueryApplications"});
    applicationsMethod->set_executable(true);
    directoryNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mQueryApplicationsId);
    auto* applicationsCallSource = mGdsNamespace->find_node<Node>(mQueryApplicationsId)->method_call_source();
    ASSERT_NE(applicationsCallSource, nullptr);
    applicationsCallSource->set_call_handler(
      [this](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext>
          context,
        std::function<void(CallResult)>
          callback)
      {
        {
          std::lock_guard lock(mCallMutex);
          if (context)
            mCallingSessions.push_back(context->sessionId);
          mLastArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
        }
        Array<RefStructure<Structure>> applications;
        for (const std::string_view uri : {"urn:integration:application:a", "urn:integration:application:b"})
        {
          auto application = std::make_unique<ApplicationDescription>();
          application->application_uri() = uri;
          std::unique_ptr<Structure> structure = std::move(application);
          RefStructure<Structure> reference;
          reference = std::move(structure);
          applications.push_back(std::move(reference));
        }
        CallMethodResult result;
        result.output_arguments().push_back(Variant{UtcTime{2026, 7, 24, 13, 0, 0}});
        result.output_arguments().push_back(Variant{std::uint32_t{0}});
        result.output_arguments().push_back(Variant{std::move(applications)});
        callback(CallResult{std::move(result)});
      });
  }

  ConnectionConfig connection_config() const
  {
    ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.securityMode = MessageSecurityMode::None;
    config.securityPolicyId = SecurityPolicyId::None;
    config.identity = AnonymousIdentity{};
    return config;
  }

  std::shared_ptr<default_ns::Namespace> mGdsNamespace;
  std::uint16_t mGdsNamespaceIndex{0};
  NodeId mDirectoryId;
  NodeId mQueryServersId;
  NodeId mQueryApplicationsId;
  std::mutex mCallMutex;
  std::vector<NodeId> mCallingSessions;
  std::vector<Variant> mLastArguments;
};

// Highest public production tier: Client::discovery() -> Discovery::gds_query_servers_sync.
// @verifies CL-DISC-013
// @verifies CL-DISC-016
// @relation(CL-DISC-013, CL-DISC-016, scope=function)
TEST_F(ClientDiscoveryGds, QueryServersReturnsRecordsAndClosesSessionAfterCall)
{
  const auto baseline = mServer.server().health_snapshot();
  GdsServerFilter filter;
  filter.startingRecordId = 12;
  filter.maxRecordsToReturn = 4;
  filter.applicationName = "Integration%";
  filter.serverCapabilities = {"DA"};

  const auto reply = mClient->discovery().gds_query_servers_sync(connection_config(), std::move(filter));

  EXPECT_EQ(reply.lastCounterResetTime, (UtcTime{2026, 7, 24, 12, 0, 0}))
    << "QueryServers must surface the GDS counter-reset timestamp to the pagination owner";
  ASSERT_EQ(reply.servers.size(), 1u);
  EXPECT_EQ(reply.servers[0].record_id(), 77u);
  EXPECT_EQ(std::string{reply.servers[0].discovery_url()}, "opc.tcp://returned.example:4840");
  {
    std::lock_guard lock(mCallMutex);
    ASSERT_EQ(mLastArguments.size(), 6u);
    EXPECT_EQ(mLastArguments[0].as<std::uint32_t>(), 12u);
    EXPECT_EQ(mLastArguments[1].as<std::uint32_t>(), 4u);
    EXPECT_EQ(std::string{mLastArguments[2].as<String>()}, "Integration%");
  }
  const auto after = mServer.server().health_snapshot();
  EXPECT_EQ(after.currentSessionCount, baseline.currentSessionCount)
    << "the GDS Session must be closed before the one-shot facade returns";
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST_F(ClientDiscoveryGds, QueryServersDoesNotPoolConnection)
{
  const auto baseline = mServer.server().health_snapshot();

  const auto first = mClient->discovery().gds_query_servers_sync(connection_config(), GdsServerFilter{});
  const auto second = mClient->discovery().gds_query_servers_sync(connection_config(), GdsServerFilter{});

  ASSERT_EQ(first.servers.size(), 1u);
  ASSERT_EQ(second.servers.size(), 1u);
  {
    std::lock_guard lock(mCallMutex);
    ASSERT_EQ(mCallingSessions.size(), 2u);
    EXPECT_NE(mCallingSessions[0], mCallingSessions[1])
      << "each GDS action sequence must use a fresh Session";
  }
  const auto after = mServer.server().health_snapshot();
  EXPECT_EQ(after.currentSessionCount, baseline.currentSessionCount);
  EXPECT_EQ(after.cumulatedSessionCount - baseline.cumulatedSessionCount, 2u);
}

// @verifies CL-DISC-018 [integration]
// @relation(CL-DISC-018, scope=function)
TEST_F(ClientDiscoveryGds, QueryApplicationsThreadsFiltersVerbatim)
{
  GdsApplicationFilter filter;
  filter.startingRecordId = 19;
  filter.maxRecordsToReturn = 7;
  filter.applicationName = "MyApp";
  filter.applicationUri = "urn:my:%";
  filter.applicationType = 0x2;
  filter.productUri = "urn:product:%";
  filter.capabilities = {"LDS", "DA"};

  const auto reply = mClient->discovery().gds_query_applications_sync(connection_config(), std::move(filter));

  ASSERT_EQ(reply.applications.size(), 2u);
  {
    std::lock_guard lock(mCallMutex);
    ASSERT_EQ(mLastArguments.size(), 7u);
    EXPECT_EQ(mLastArguments[0].as<std::uint32_t>(), 19u);
    EXPECT_EQ(mLastArguments[1].as<std::uint32_t>(), 7u);
    EXPECT_EQ(std::string{mLastArguments[2].as<String>()}, "MyApp");
    EXPECT_EQ(std::string{mLastArguments[3].as<String>()}, "urn:my:%");
    EXPECT_EQ(mLastArguments[4].as<std::uint32_t>(), 0x2u);
    EXPECT_EQ(std::string{mLastArguments[5].as<String>()}, "urn:product:%");
    const auto& capabilities = mLastArguments[6].as<Array<String>>();
    ASSERT_EQ(capabilities.size(), 2u);
    EXPECT_EQ(std::string{capabilities[0]}, "LDS");
    EXPECT_EQ(std::string{capabilities[1]}, "DA");
  }
}

// @verifies CL-DISC-018 [integration]
// @relation(CL-DISC-018, scope=function)
TEST_F(ClientDiscoveryGds, QueryApplicationsEmptyFilterReturnsAll)
{
  const auto reply =
    mClient->discovery().gds_query_applications_sync(connection_config(), GdsApplicationFilter{});

  ASSERT_EQ(reply.applications.size(), 2u);
  std::lock_guard lock(mCallMutex);
  ASSERT_EQ(mLastArguments.size(), 7u);
  EXPECT_TRUE(mLastArguments[2].as<String>().empty());
  EXPECT_TRUE(mLastArguments[3].as<String>().empty());
  EXPECT_EQ(mLastArguments[4].as<std::uint32_t>(), 0u);
  EXPECT_TRUE(mLastArguments[5].as<String>().empty());
  EXPECT_TRUE(mLastArguments[6].as<Array<String>>().empty());
}

}  // namespace
