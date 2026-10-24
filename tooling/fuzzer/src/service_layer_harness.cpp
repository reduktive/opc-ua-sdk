// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "service_layer_harness.h"
#include "fuzz_client.h"

#include "input_generators.h"
#include "liveness_watchdog.h"

#include "ua_logger.h"

#include "ua_add_nodes_request.h"
#include "ua_add_references_request.h"
#include "ua_application_configuration.h"
#include "ua_browse_request.h"
#include "ua_call_request.h"
#include "ua_client.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_subscription_request.h"
#include "ua_crypto_types.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_references_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_message_security_mode.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_subscription_request.h"
#include "ua_publish_request.h"
#include "ua_read_request.h"
#include "ua_register_nodes_request.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_publishing_mode_request.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_transport_address.h"
#include "ua_unregister_nodes_request.h"
#include "ua_write_request.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <thread>

namespace fuzz
{

namespace
{

struct ServerFixture
{
  // serverThreads == 0 -> hardware concurrency (default); 1 -> single-threaded server, which
  // surfaces synchronous blocking that a multi-threaded pool would mask (another thread keeps
  // servicing work). The client pool stays default-threaded.
  explicit ServerFixture(std::size_t serverThreads = 0)
    : serverPool(
        serverThreads > 0 ? serverThreads : std::max<std::size_t>(1, std::thread::hardware_concurrency()))
  {}

  boost::asio::thread_pool serverPool;
  boost::asio::thread_pool clientPool;
  std::optional<ua::server::Server> server;
  std::string endpointUrl;
  ua::server::ListenerHandle listener{0};

  void start()
  {
    auto appCfg = ua::ApplicationConfig::load_default();
    appCfg.allowInsecureEndpoints = true;
    // Required: published as Server.ServerArray[0] and as the URI of the server's own namespace.
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:service-layer";

    ua::server::CreateConfig createCfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = ua::server::ServerConfig{}};

    ua::server::ServerComponents components;
    components.crypto = ua::create_default_crypto();
    components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();

    server.emplace(
      ua::server::Server::create(serverPool.get_executor(), std::move(createCfg), std::move(components)));

    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
    endpoint.securityPolicyId = ua::SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));

    ua::transport::BindAddress bind;
    bind.address = "127.0.0.1:0";

    listener = server->listen_sync(std::move(bind), {});
    server->add_endpoint(listener, endpoint);
    server->start_sync();

    auto urls = server->advertised_urls(listener);
    endpointUrl = urls.front().str();
  }

  void stop()
  {
    server.reset();
    clientPool.join();
    serverPool.join();
  }
};

/// Tracks subscription and monitored item state so that fuzz operations on dependent
/// services (e.g. DeleteSubscriptions, ModifyMonitoredItems) can reference real IDs
/// mixed with random/invalid ones.
struct FuzzSessionState
{
  struct SubscriptionState
  {
    uint32_t subscriptionId{0};
    std::vector<uint32_t> monitoredItemIds;
    uint32_t nextClientHandle{0};
  };

  std::map<uint32_t, SubscriptionState> subscriptions;
  std::vector<ua::NodeId> registeredNodes;

  bool has_subscriptions() const
  {
    return !subscriptions.empty();
  }

  uint32_t random_subscription_id(std::mt19937_64& rng) const
  {
    if (subscriptions.empty())
      return 0;
    auto it = subscriptions.begin();
    std::advance(it, std::uniform_int_distribution<size_t>(0, subscriptions.size() - 1)(rng));
    return it->first;
  }

  std::vector<uint32_t> all_subscription_ids() const
  {
    std::vector<uint32_t> ids;
    ids.reserve(subscriptions.size());
    for (const auto& [id, _] : subscriptions)
    {
      ids.push_back(id);
    }
    return ids;
  }

  bool has_monitored_items(uint32_t subId) const
  {
    auto it = subscriptions.find(subId);
    return it != subscriptions.end() && !it->second.monitoredItemIds.empty();
  }

  std::vector<uint32_t> random_monitored_item_ids(uint32_t subId, std::mt19937_64& rng, int count) const
  {
    std::vector<uint32_t> result;
    auto it = subscriptions.find(subId);
    if (it == subscriptions.end() || it->second.monitoredItemIds.empty())
      return result;

    const auto& items = it->second.monitoredItemIds;
    for (int i = 0; i < count && !items.empty(); ++i)
    {
      result.push_back(items[std::uniform_int_distribution<size_t>(0, items.size() - 1)(rng)]);
    }
    return result;
  }
};

Monitor::CaseOutcome make_outcome(uint64_t caseNum, FuzzService service)
{
  Monitor::CaseOutcome outcome;
  outcome.caseNumber = caseNum;
  outcome.layer = FuzzLayer::Service;
  outcome.service = service;
  return outcome;
}

void record_exception(Monitor::CaseOutcome& outcome)
{
  outcome.exceptionThrown = true;
  try
  {
    throw;
  }
  catch (const std::exception& e)
  {
    outcome.exceptionMessage = e.what();
  }
  catch (...)
  {
    outcome.exceptionMessage = "unknown exception";
  }
}

void finish_case(Monitor::CaseOutcome& outcome, std::chrono::steady_clock::time_point start, Monitor& monitor,
  Reporter& reporter)
{
  outcome.latency =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
  if (auto finding = monitor.record(outcome))
  {
    reporter.report_finding(*finding);
  }
}

// --- Individual service case runners ---

void run_read_case(ua::client::Session& session, ReadRequestGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::ReadRequest req;
  auto numNodes = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numNodes; ++i)
  {
    req.nodes_to_read().push_back(gen.generate_read_value_id());
  }
  req.timestamps_to_return() = gen.generate_timestamps_to_return();
  req.max_age() = static_cast<double>(gen.generate_max_age());

  auto outcome = make_outcome(caseNum, FuzzService::Read);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.attributes().try_read_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_browse_case(ua::client::Session& session, BrowseRequestGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::BrowseRequest req;
  auto numNodes = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numNodes; ++i)
  {
    req.nodes_to_browse().push_back(gen.generate_browse_description());
  }
  req.requested_max_references_per_node() = gen.generate_requested_max_references_per_node();

  auto outcome = make_outcome(caseNum, FuzzService::Browse);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.view().try_browse_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_write_case(ua::client::Session& session, WriteRequestGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::WriteRequest req;
  auto numNodes = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numNodes; ++i)
  {
    req.nodes_to_write().push_back(gen.generate_write_value());
  }

  auto outcome = make_outcome(caseNum, FuzzService::Write);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.attributes().try_write_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_call_case(ua::client::Session& session, CallRequestGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::CallRequest req;
  auto numMethods = std::uniform_int_distribution<int>(1, 3)(rng);
  for (int i = 0; i < numMethods; ++i)
  {
    req.methods_to_call().push_back(gen.generate_call_method_request());
  }

  auto outcome = make_outcome(caseNum, FuzzService::Call);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.methods().try_call_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_translate_browse_paths_case(ua::client::Session& session, TranslateBrowsePathsGenerator& gen,
  std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::TranslateBrowsePathsToNodeIdsRequest req;
  auto numPaths = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numPaths; ++i)
  {
    req.browse_paths().push_back(gen.generate_browse_path());
  }

  auto outcome = make_outcome(caseNum, FuzzService::TranslateBrowsePaths);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.view().try_translate_browse_paths_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_register_nodes_case(ua::client::Session& session, RegisterNodesGenerator& gen,
  FuzzSessionState& state, std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::RegisterNodesRequest req;
  auto numNodes = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numNodes; ++i)
  {
    req.nodes_to_register().push_back(gen.generate_node_to_register());
  }

  auto outcome = make_outcome(caseNum, FuzzService::RegisterNodes);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.view().try_register_nodes_sync(std::move(req));
    if (resp.is_good())
    {
      for (auto& nodeId : resp.value().registered_node_ids())
      {
        state.registeredNodes.push_back(std::move(nodeId));
      }
    }
    else
    {
      outcome.statusCode = resp.status_code().as_uint32();
    }
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_unregister_nodes_case(ua::client::Session& session, FuzzSessionState& state, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::UnregisterNodesRequest req;
  if (!state.registeredNodes.empty())
  {
    auto count = std::min(
      static_cast<size_t>(std::uniform_int_distribution<int>(1, 3)(rng)), state.registeredNodes.size());
    for (size_t i = 0; i < count; ++i)
    {
      req.nodes_to_unregister().push_back(state.registeredNodes.back());
      state.registeredNodes.pop_back();
    }
  }
  else
  {
    // Unregister random nodes (should get BadNodeIdUnknown or similar).
    NodeIdGenerator nodeGen(rng);
    req.nodes_to_unregister().push_back(nodeGen.generate());
  }

  auto outcome = make_outcome(caseNum, FuzzService::UnregisterNodes);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.view().try_unregister_nodes_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_create_subscription_case(ua::client::Session& session, SubscriptionParamsGenerator& gen,
  FuzzSessionState& state, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  auto req = gen.generate_create_subscription_request();

  auto outcome = make_outcome(caseNum, FuzzService::CreateSubscription);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.subscriptions().try_create_subscription_sync(std::move(req));
    if (resp.is_good())
    {
      auto subId = resp.value().subscription_id();
      state.subscriptions[subId] = FuzzSessionState::SubscriptionState{.subscriptionId = subId};
    }
    else
    {
      outcome.statusCode = resp.status_code().as_uint32();
    }
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_modify_subscription_case(ua::client::Session& session, SubscriptionParamsGenerator& gen,
  FuzzSessionState& state, std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  uint32_t subId = state.has_subscriptions() ? state.random_subscription_id(rng)
                                             : std::uniform_int_distribution<uint32_t>(0, 1000)(rng);

  auto req = gen.generate_modify_subscription_request(subId);

  auto outcome = make_outcome(caseNum, FuzzService::ModifySubscription);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.subscriptions().try_modify_subscription_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_delete_subscriptions_case(ua::client::Session& session, FuzzSessionState& state,
  std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::DeleteSubscriptionsRequest req;

  if (state.has_subscriptions())
  {
    // Delete 1-3 subscriptions: mix of real and sometimes bogus IDs.
    auto count = std::uniform_int_distribution<int>(1, 3)(rng);
    for (int i = 0; i < count; ++i)
    {
      if (state.has_subscriptions() && std::uniform_int_distribution<int>(0, 3)(rng) != 0)
      {
        req.subscription_ids().push_back(state.random_subscription_id(rng));
      }
      else
      {
        req.subscription_ids().push_back(std::uniform_int_distribution<uint32_t>(0, 10000)(rng));
      }
    }
  }
  else
  {
    req.subscription_ids().push_back(std::uniform_int_distribution<uint32_t>(0, 10000)(rng));
  }

  // Track which real subs we're deleting.
  std::vector<uint32_t> deletedIds;
  for (auto id : req.subscription_ids())
  {
    if (state.subscriptions.count(id))
      deletedIds.push_back(id);
  }

  auto outcome = make_outcome(caseNum, FuzzService::DeleteSubscriptions);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.subscriptions().try_delete_subscriptions_sync(std::move(req));
    if (resp.is_good())
    {
      for (auto id : deletedIds)
      {
        state.subscriptions.erase(id);
      }
    }
    else
    {
      outcome.statusCode = resp.status_code().as_uint32();
    }
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_set_publishing_mode_case(ua::client::Session& session, SubscriptionParamsGenerator& gen,
  FuzzSessionState& state, std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  auto ids = state.has_subscriptions()
               ? state.all_subscription_ids()
               : std::vector<uint32_t>{std::uniform_int_distribution<uint32_t>(0, 1000)(rng)};

  auto req = gen.generate_set_publishing_mode_request(std::move(ids));

  auto outcome = make_outcome(caseNum, FuzzService::SetPublishingMode);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.subscriptions().try_set_publishing_mode_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_create_monitored_items_case(ua::client::Session& session, MonitoredItemParamsGenerator& gen,
  FuzzSessionState& state, std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  uint32_t subId = state.has_subscriptions() ? state.random_subscription_id(rng)
                                             : std::uniform_int_distribution<uint32_t>(0, 1000)(rng);

  ua::CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = ua::TimestampsToReturn::Both;

  auto& subState = state.subscriptions[subId];
  auto numItems = std::uniform_int_distribution<int>(1, 5)(rng);
  for (int i = 0; i < numItems; ++i)
  {
    req.items_to_create().push_back(gen.generate_monitored_item_create_request(subState.nextClientHandle++));
  }

  auto outcome = make_outcome(caseNum, FuzzService::CreateMonitoredItems);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.monitored_items().try_create_monitored_items_sync(std::move(req));
    if (resp.is_good() && state.subscriptions.count(subId))
    {
      for (const auto& result : resp.value().results())
      {
        if (result.status_code().is_good())
        {
          state.subscriptions[subId].monitoredItemIds.push_back(result.monitored_item_id());
        }
      }
    }
    else if (!resp.is_good())
    {
      outcome.statusCode = resp.status_code().as_uint32();
    }
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_modify_monitored_items_case(ua::client::Session& session, MonitoredItemParamsGenerator& gen,
  FuzzSessionState& state, std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  uint32_t subId = state.has_subscriptions() ? state.random_subscription_id(rng)
                                             : std::uniform_int_distribution<uint32_t>(0, 1000)(rng);

  ua::ModifyMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = ua::TimestampsToReturn::Both;

  if (state.has_monitored_items(subId))
  {
    auto ids = state.random_monitored_item_ids(subId, rng, std::uniform_int_distribution<int>(1, 3)(rng));
    for (auto id : ids)
    {
      req.items_to_modify().push_back(gen.generate_monitored_item_modify_request(id));
    }
  }
  else
  {
    req.items_to_modify().push_back(
      gen.generate_monitored_item_modify_request(std::uniform_int_distribution<uint32_t>(0, 1000)(rng)));
  }

  auto outcome = make_outcome(caseNum, FuzzService::ModifyMonitoredItems);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.monitored_items().try_modify_monitored_items_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_delete_monitored_items_case(ua::client::Session& session, FuzzSessionState& state,
  std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  uint32_t subId = state.has_subscriptions() ? state.random_subscription_id(rng)
                                             : std::uniform_int_distribution<uint32_t>(0, 1000)(rng);

  ua::DeleteMonitoredItemsRequest req;
  req.subscription_id() = subId;

  std::vector<uint32_t> deletingIds;
  if (state.has_monitored_items(subId))
  {
    deletingIds = state.random_monitored_item_ids(subId, rng, std::uniform_int_distribution<int>(1, 3)(rng));
    for (auto id : deletingIds)
    {
      req.monitored_item_ids().push_back(id);
    }
  }
  else
  {
    req.monitored_item_ids().push_back(std::uniform_int_distribution<uint32_t>(0, 1000)(rng));
  }

  auto outcome = make_outcome(caseNum, FuzzService::DeleteMonitoredItems);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.monitored_items().try_delete_monitored_items_sync(std::move(req));
    if (resp.is_good() && state.subscriptions.count(subId))
    {
      auto& items = state.subscriptions[subId].monitoredItemIds;
      for (auto delId : deletingIds)
      {
        std::erase(items, delId);
      }
    }
    else if (!resp.is_good())
    {
      outcome.statusCode = resp.status_code().as_uint32();
    }
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_set_monitoring_mode_case(ua::client::Session& session, FuzzSessionState& state, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  uint32_t subId = state.has_subscriptions() ? state.random_subscription_id(rng)
                                             : std::uniform_int_distribution<uint32_t>(0, 1000)(rng);

  ua::SetMonitoringModeRequest req;
  req.subscription_id() = subId;
  req.monitoring_mode() = static_cast<ua::MonitoringMode>(std::uniform_int_distribution<int>(0, 3)(rng));

  if (state.has_monitored_items(subId))
  {
    auto ids = state.random_monitored_item_ids(subId, rng, std::uniform_int_distribution<int>(1, 3)(rng));
    for (auto id : ids)
    {
      req.monitored_item_ids().push_back(id);
    }
  }
  else
  {
    req.monitored_item_ids().push_back(std::uniform_int_distribution<uint32_t>(0, 1000)(rng));
  }

  auto outcome = make_outcome(caseNum, FuzzService::SetMonitoringMode);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.monitored_items().try_set_monitoring_mode_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_publish_case(ua::client::Session& session, PublishParamsGenerator& gen, FuzzSessionState& state,
  std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::PublishRequest req;

  // Short timeout so publish doesn't block the fuzz loop waiting for notifications.
  req.request_header().timeout_hint() = 200;

  // Occasionally include fuzzed subscription acknowledgements.
  if (state.has_subscriptions() && std::uniform_int_distribution<int>(0, 2)(rng) != 0)
  {
    auto ackCount = std::uniform_int_distribution<int>(1, 3)(rng);
    for (int i = 0; i < ackCount; ++i)
    {
      req.subscription_acknowledgements().push_back(
        gen.generate_subscription_acknowledgement(state.random_subscription_id(rng)));
    }
  }

  auto outcome = make_outcome(caseNum, FuzzService::CreateSubscription);
  outcome.service = FuzzService::SetPublishingMode;  // closest enum; Publish isn't in the enum
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.subscriptions().try_publish_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_add_nodes_case(ua::client::Session& session, NodeManagementGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::AddNodesRequest req;
  auto count = std::uniform_int_distribution<int>(1, 3)(rng);
  for (int i = 0; i < count; ++i)
  {
    req.nodes_to_add().push_back(gen.generate_add_nodes_item());
  }

  auto outcome = make_outcome(caseNum, FuzzService::AddNodes);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.node_management().try_add_nodes_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_delete_nodes_case(ua::client::Session& session, NodeManagementGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::DeleteNodesRequest req;
  auto count = std::uniform_int_distribution<int>(1, 3)(rng);
  for (int i = 0; i < count; ++i)
  {
    req.nodes_to_delete().push_back(gen.generate_delete_nodes_item());
  }

  auto outcome = make_outcome(caseNum, FuzzService::DeleteNodes);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.node_management().try_delete_nodes_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_add_references_case(ua::client::Session& session, NodeManagementGenerator& gen, std::mt19937_64& rng,
  Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::AddReferencesRequest req;
  auto count = std::uniform_int_distribution<int>(1, 3)(rng);
  for (int i = 0; i < count; ++i)
  {
    req.references_to_add().push_back(gen.generate_add_references_item());
  }

  auto outcome = make_outcome(caseNum, FuzzService::AddReferences);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.node_management().try_add_references_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

void run_delete_references_case(ua::client::Session& session, NodeManagementGenerator& gen,
  std::mt19937_64& rng, Monitor& monitor, Reporter& reporter, uint64_t caseNum)
{
  ua::DeleteReferencesRequest req;
  auto count = std::uniform_int_distribution<int>(1, 3)(rng);
  for (int i = 0; i < count; ++i)
  {
    req.references_to_delete().push_back(gen.generate_delete_references_item());
  }

  auto outcome = make_outcome(caseNum, FuzzService::DeleteReferences);
  auto start = std::chrono::steady_clock::now();
  try
  {
    auto resp = session.node_management().try_delete_references_sync(std::move(req));
    if (!resp.is_good())
      outcome.statusCode = resp.status_code().as_uint32();
  }
  catch (...)
  {
    record_exception(outcome);
  }
  finish_case(outcome, start, monitor, reporter);
}

/// Service weights for random selection. Subscription-related services get lower base weight
/// because they need active subscriptions to be meaningful; the dispatcher boosts them when
/// subscriptions exist.
struct ServiceWeight
{
  FuzzService service;
  int baseWeight;
  bool needsSubscription;
  bool needsMonitoredItems;
};

// clang-format off
static constexpr ServiceWeight serviceWeights[] = {
  {FuzzService::Read,                  10, false, false},
  {FuzzService::Browse,                10, false, false},
  {FuzzService::Write,                  8, false, false},
  {FuzzService::Call,                   5, false, false},
  {FuzzService::TranslateBrowsePaths,   5, false, false},
  {FuzzService::RegisterNodes,          3, false, false},
  {FuzzService::UnregisterNodes,        3, false, false},
  {FuzzService::CreateSubscription,     8, false, false},
  {FuzzService::ModifySubscription,     4, true,  false},
  {FuzzService::DeleteSubscriptions,    3, true,  false},
  {FuzzService::SetPublishingMode,      3, true,  false},
  {FuzzService::CreateMonitoredItems,   6, true,  false},
  {FuzzService::ModifyMonitoredItems,   3, true,  true},
  {FuzzService::DeleteMonitoredItems,   3, true,  true},
  {FuzzService::SetMonitoringMode,      3, true,  true},
  {FuzzService::AddNodes,               3, false, false},
  {FuzzService::AddReferences,          3, false, false},
  {FuzzService::DeleteNodes,            3, false, false},
  {FuzzService::DeleteReferences,       3, false, false},
};
// clang-format on

FuzzService select_service(const FuzzSessionState& state, std::mt19937_64& rng)
{
  // Compute effective weights. Subscription- and monitored-item-dependent services are floored to
  // 1 (not zeroed) when no subscription / monitored item exists, so they're still occasionally
  // picked to fuzz error paths with bogus IDs. CreateSubscription is untouched here; demoting the
  // dependents just leaves it relatively more likely, so a subscription tends to appear first.
  int totalWeight = 0;
  std::vector<std::pair<FuzzService, int>> weighted;

  for (const auto& sw : serviceWeights)
  {
    int w = sw.baseWeight;

    if (sw.needsSubscription && !state.has_subscriptions())
    {
      // Floor to 1 (instead of dropping to 0) so this service is still selected occasionally with
      // a non-existent subscription id -- exercises the server's error path.
      w = 1;
    }
    if (sw.needsMonitoredItems)
    {
      bool hasAny = false;
      for (const auto& [subId, sub] : state.subscriptions)
      {
        if (!sub.monitoredItemIds.empty())
        {
          hasAny = true;
          break;
        }
      }
      if (!hasAny)
        w = 1;
    }

    weighted.push_back({sw.service, w});
    totalWeight += w;
  }

  auto pick = std::uniform_int_distribution<int>(0, totalWeight - 1)(rng);
  int cumulative = 0;
  for (const auto& [service, weight] : weighted)
  {
    cumulative += weight;
    if (pick < cumulative)
      return service;
  }

  return FuzzService::Read;
}

}  // namespace

void run_service_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  auto log = logger.with_category("service");
  log.info("Starting in-process server");

  const std::size_t serverThreads =
    config.syncBlock.serverThreads > 0 ? static_cast<std::size_t>(config.syncBlock.serverThreads) : 0;
  ServerFixture fixture(serverThreads);
  fixture.start();

  if (config.syncBlock.serverThreads == 1)
  {
    log.info("Server running SINGLE-THREADED (sync-block detection {})",
      config.syncBlock.detectSyncBlock ? "ON" : "off");
  }

  // Watch the server executor for synchronous blocking: if a handler wedges the single server
  // thread, the heartbeat stops being serviced and we abort (capturing the stuck backtrace).
  std::optional<LivenessWatchdog> syncBlockWatchdog;
  if (config.syncBlock.detectSyncBlock)
  {
    syncBlockWatchdog.emplace(fixture.serverPool.get_executor(),
      std::chrono::milliseconds(config.syncBlock.livenessDeadlineMs),
      std::chrono::milliseconds(config.syncBlock.heartbeatIntervalMs),
      []
      {
        std::cerr << "\n===== SYNC-BLOCK STALL DETECTED =====\n"
                  << "The server executor did not service a liveness heartbeat within the deadline: "
                  << "a handler is blocking the (single) server thread synchronously, which the "
                  << "callback-canonical SDK must never do. Aborting to capture the wedged thread's "
                  << "backtrace.\n"
                  << std::flush;
        std::abort();
      });
  }

  log.info("Server listening on {}", fixture.endpointUrl);
  log.info("Connecting client");

  // Scope the client-side objects (client, channel, session) so they are destroyed
  // BEFORE fixture.stop() joins clientPool. A live client keeps a pending socket
  // read (and channel timers) outstanding on that pool; calling thread_pool::join()
  // while that work is outstanding blocks forever (the teardown-hang this fixes).
  {
    auto client = ua::client::Client::create(fixture.clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()});

    ua::client::CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = fixture.endpointUrl;
    channelConfig.securityMode = ua::MessageSecurityMode::None;
    channelConfig.securityPolicyId = ua::SecurityPolicyId::None;

    auto channel = client.core().open_channel_sync(channelConfig);
    auto session = channel.create_session_sync({});
    session.activate_sync();

    log.info("Session active, starting fuzz loop");

    // Set up RNG and generators.
    std::mt19937_64 rng(config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}());

    ReadRequestGenerator readGen(rng, config.limits);
    BrowseRequestGenerator browseGen(rng, config.limits);
    WriteRequestGenerator writeGen(rng, config.limits);
    CallRequestGenerator callGen(rng, config.limits);
    TranslateBrowsePathsGenerator translateGen(rng, config.limits);
    RegisterNodesGenerator registerGen(rng, config.limits);
    SubscriptionParamsGenerator subGen(rng, config.limits);
    MonitoredItemParamsGenerator monGen(rng, config.limits);
    PublishParamsGenerator pubGen(rng, config.limits);
    NodeManagementGenerator nodeMgmtGen(rng, config.limits);

    FuzzSessionState state;

    auto maxCases = config.campaign.maxCases;
    auto startTime = std::chrono::steady_clock::now();

    for (uint64_t caseNum = 1; maxCases == 0 || caseNum <= maxCases; ++caseNum)
    {
      auto service = select_service(state, rng);

      switch (service)
      {
      case FuzzService::Read:
        run_read_case(session, readGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::Browse:
        run_browse_case(session, browseGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::Write:
        run_write_case(session, writeGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::Call:
        run_call_case(session, callGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::TranslateBrowsePaths:
        run_translate_browse_paths_case(session, translateGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::RegisterNodes:
        run_register_nodes_case(session, registerGen, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::UnregisterNodes:
        run_unregister_nodes_case(session, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::CreateSubscription:
        run_create_subscription_case(session, subGen, state, monitor, reporter, caseNum);
        break;
      case FuzzService::ModifySubscription:
        run_modify_subscription_case(session, subGen, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::DeleteSubscriptions:
        run_delete_subscriptions_case(session, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::SetPublishingMode:
        run_set_publishing_mode_case(session, subGen, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::CreateMonitoredItems:
        run_create_monitored_items_case(session, monGen, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::ModifyMonitoredItems:
        run_modify_monitored_items_case(session, monGen, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::DeleteMonitoredItems:
        run_delete_monitored_items_case(session, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::SetMonitoringMode:
        run_set_monitoring_mode_case(session, state, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::AddNodes:
        run_add_nodes_case(session, nodeMgmtGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::DeleteNodes:
        run_delete_nodes_case(session, nodeMgmtGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::AddReferences:
        run_add_references_case(session, nodeMgmtGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::DeleteReferences:
        run_delete_references_case(session, nodeMgmtGen, rng, monitor, reporter, caseNum);
        break;
      case FuzzService::BrowseNext:
      case FuzzService::FindServers:
      case FuzzService::GetEndpoints:
        // BrowseNext requires continuation points from a prior Browse; skip for now.
        // FindServers/GetEndpoints are discovery services, not session-level.
        run_read_case(session, readGen, rng, monitor, reporter, caseNum);
        break;
      }

      // Update status periodically.
      auto elapsed = std::chrono::steady_clock::now() - startTime;
      auto elapsedSec = std::chrono::duration<double>(elapsed).count();
      auto rate = elapsedSec > 0 ? static_cast<double>(caseNum) / elapsedSec : 0.0;
      reporter.update_status(caseNum, rate, FuzzLayer::Service, monitor.server_alive());

      // If server died, try to reconnect.
      if (!monitor.server_alive())
      {
        log.warning("Server connection lost, attempting reconnect");
        try
        {
          channel = client.core().open_channel_sync(channelConfig);
          session = channel.create_session_sync({});
          session.activate_sync();
          monitor.set_server_alive(true);
          state = FuzzSessionState{};  // Reset state after reconnect.
          log.info("Reconnected");
        }
        catch (const std::exception& e)
        {
          log.error("Reconnect failed: {}", e.what());
          break;
        }
      }
    }

    auto totalElapsed = std::chrono::steady_clock::now() - startTime;
    auto totalSec = std::chrono::duration<double>(totalElapsed).count();

    log.info("Fuzz loop complete");

    FuzzResult result;
    result.totalCases = maxCases;
    result.acceptedMutations = monitor.accepted_mutations();
    result.rejectedMutations = monitor.rejected_mutations();
    result.elapsedSeconds = totalSec;
    result.casesPerSecond = maxCases > 0 ? static_cast<double>(maxCases) / totalSec : 0.0;
    result.findingsDir = config.reporting.outputDir;

    auto findings = reporter.findings();
    for (const auto& f : findings)
    {
      switch (f.findingClass)
      {
      case FindingClass::SecurityCrash:
      case FindingClass::SecurityAsanViolation:
        ++result.crashes;
        break;
      case FindingClass::SecurityAuthBypass:
      case FindingClass::SecurityPrivEscalation:
      case FindingClass::SecurityHang:
      case FindingClass::SecurityUnexpectedDisconnect:
      case FindingClass::SecurityDosDegradation:
      case FindingClass::SecurityStateMachineViolation:
      case FindingClass::SecurityReplayAccepted:
        ++result.securityFindings;
        break;
      case FindingClass::MemoryLeak:
      case FindingClass::MemoryLeakSlow:
        ++result.memoryLeaks;
        break;
      case FindingClass::ResourceLeakSession:
      case FindingClass::ResourceLeakChannel:
      case FindingClass::ResourceLeakSubscription:
      case FindingClass::ResourceLeakFd:
        ++result.resourceLeaks;
        break;
      case FindingClass::PerfLatencySpike:
      case FindingClass::PerfLatencyDrift:
      case FindingClass::PerfThroughputDegradation:
      case FindingClass::PerfSlowHandshake:
        ++result.perfFindings;
        break;
      default:
        ++result.criticalBehaviour;
        break;
      }
    }

    reporter.write_summary(result);

    try
    {
      session.close_sync();
      channel.close_sync();
    }
    catch (...)
    {}
  }  // client/channel/session destroyed here, releasing all clientPool work

  // Stop the watchdog (joins its thread; no more heartbeats posted) BEFORE the pools join.
  syncBlockWatchdog.reset();
  fixture.stop();
}

}  // namespace fuzz
