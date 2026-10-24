// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A Server with RegisterNodes-recording test namespaces and a Session (SessionInfoStub) through which the
// RegisterNodes service is run as the Session runs it: RegisterNodesServiceSet::create on the request.

#ifndef UA_TEST_REGISTER_NODES_HARNESS_H
#define UA_TEST_REGISTER_NODES_HARNESS_H

#include <gtest/gtest.h>

#include "register_nodes_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

#include "ua_register_nodes_service.h"
#include "ua_server.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace ua::test::register_nodes
{

using namespace std::chrono_literals;

inline bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 3s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(2ms);
  }
  return true;
}

inline std::string text(const std::vector<NodeId>& nodeIds)
{
  std::string out = "{";
  for (const auto& nodeId : nodeIds)
  {
    out += (out.size() > 1 ? ", " : "") + ua::to_string(nodeId);
  }
  return out + "}";
}

/// One RegisterNodes or UnregisterNodes request in flight.
struct PendingRequest
{
  std::shared_ptr<server::RegisterNodesServiceSet> service;
  std::shared_ptr<std::promise<server::RegisterNodesServiceSet::ResponseOrServiceFault>> promise;
  std::future<server::RegisterNodesServiceSet::ResponseOrServiceFault> future;

  /// The answer, or nullopt when none came within 5 s.
  std::optional<server::RegisterNodesServiceSet::ResponseOrServiceFault> wait()
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      return std::nullopt;
    }
    return future.get();
  }
};

/// A Server with two RegisterNodes-recording namespaces, each holding Objects "N1".."N4", and a Session.
class RegisterNodesHarness
{
public:
  /// @param stubsOtherConstructor Builds the Session through SessionInfoStub's other constructor.
  explicit RegisterNodesHarness(bool stubsOtherConstructor = false)
  {
    server::CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = server::ServerConfig{}};
    auto created = server::Server::create(mThreadPool.get_executor(),
      std::move(cfg),
      server::ServerComponents{.crypto = test_helpers::test_crypto()});
    mAddressSpace.emplace(created.address_space());
    first =
      RegisterNodesRecordingNamespace::create("urn:test:register-nodes:first", mThreadPool.get_executor());
    second =
      RegisterNodesRecordingNamespace::create("urn:test:register-nodes:second", mThreadPool.get_executor());
    firstIndex = mAddressSpace->add_namespace_sync(first);
    secondIndex = mAddressSpace->add_namespace_sync(second);
    for (const auto index : {firstIndex, secondIndex})
    {
      for (const char* name : {"N1", "N2", "N3", "N4"})
      {
        auto node = mAddressSpace->try_create_node_sync(NodeId{index, name}, NodeClass::Object, {});
        EXPECT_TRUE(node.is_good()) << ua::to_string(node.status_code());
      }
    }
    sessionInfo = stubsOtherConstructor
                    ? std::make_shared<SessionInfoStub>(
                        std::move(created), mThreadPool.get_executor(), nullptr, /*noAccessIdentity=*/false)
                    : std::make_shared<SessionInfoStub>(std::move(created), mThreadPool.get_executor());
  }

  ~RegisterNodesHarness()
  {
    first->release_register_answers();
    second->release_register_answers();
    sessionInfo.reset();
    test_utils::drain_with_timeout(mThreadPool);
  }

  RegisterNodesHarness(const RegisterNodesHarness&) = delete;
  RegisterNodesHarness& operator=(const RegisterNodesHarness&) = delete;

  AddressSpace address_space() const
  {
    return *mAddressSpace;
  }

  PendingRequest start_register(std::vector<NodeId> nodeIds, uint32_t timeoutHint = 0)
  {
    RegisterNodesRequest request;
    request.request_header().timeout_hint() = timeoutHint;
    for (auto& nodeId : nodeIds)
    {
      request.nodes_to_register().push_back(std::move(nodeId));
    }
    return start(std::move(request));
  }

  PendingRequest start_unregister(std::vector<NodeId> nodeIds)
  {
    UnregisterNodesRequest request;
    for (auto& nodeId : nodeIds)
    {
      request.nodes_to_unregister().push_back(std::move(nodeId));
    }
    return start(std::move(request));
  }

  /// Runs a RegisterNodes and answers the NodeIds its response carries (empty when it carries none).
  std::vector<NodeId> register_nodes(std::vector<NodeId> nodeIds)
  {
    auto pending = start_register(std::move(nodeIds));
    auto answer = pending.wait();
    EXPECT_TRUE(answer.has_value()) << "the RegisterNodes did not answer";
    std::vector<NodeId> registered;
    if (answer)
    {
      if (const auto* response = std::get_if<RegisterNodesResponse>(&*answer))
      {
        for (const auto& nodeId : response->registered_node_ids())
        {
          registered.push_back(nodeId);
        }
      }
    }
    return registered;
  }

  /// Runs an UnregisterNodes and answers its service result.
  StatusCode unregister_nodes(std::vector<NodeId> nodeIds)
  {
    auto pending = start_unregister(std::move(nodeIds));
    auto answer = pending.wait();
    if (!answer)
    {
      ADD_FAILURE() << "the UnregisterNodes did not answer";
      return StatusCode{Status::BadTimeout};
    }
    if (const auto* fault = std::get_if<ServiceFault>(&*answer))
    {
      return fault->response_header().service_result();
    }
    if (const auto* response = std::get_if<UnregisterNodesResponse>(&*answer))
    {
      return response->response_header().service_result();
    }
    return StatusCode{Status::BadUnexpectedError};
  }

  std::shared_ptr<RegisterNodesRecordingNamespace> first;
  std::shared_ptr<RegisterNodesRecordingNamespace> second;
  uint16_t firstIndex = 0;
  uint16_t secondIndex = 0;
  std::shared_ptr<SessionInfoStub> sessionInfo;

private:
  template<typename Request>
  PendingRequest start(Request request)
  {
    PendingRequest pending;
    pending.promise =
      std::make_shared<std::promise<server::RegisterNodesServiceSet::ResponseOrServiceFault>>();
    pending.future = pending.promise->get_future();
    pending.service = server::RegisterNodesServiceSet::create(sessionInfo,
      std::move(request),
      mThreadPool.get_executor(),
      [promise = pending.promise](server::RegisterNodesServiceSet::ResponseOrServiceFault response)
      { promise->set_value(std::move(response)); });
    return pending;
  }

  boost::asio::thread_pool mThreadPool{4};
  std::optional<AddressSpace> mAddressSpace;
};

}  // namespace ua::test::register_nodes

#endif  // UA_TEST_REGISTER_NODES_HARNESS_H
