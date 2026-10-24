// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Registered NodeIds are valid only within the Session that registered them (Part 4 5.8.5.1), and
// UnregisterNodes unregisters only NodeIds known as registered (5.8.6.1): a namespace sees, per Session, one
// unregistration for every registration, at the Client's UnregisterNodes or at the Session's end (NR-4
// release rule 2). A test namespace is its own RegisterNodes delegate and records every unregistration it is
// asked for; the Sessions are Clients over the wire.

#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "register_nodes_recording_namespace.h"

#include "ua_register_nodes_request.h"
#include "ua_to_string.h"
#include "ua_unregister_nodes_request.h"

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;
using ua::test::RegisterNodesRecordingNamespace;

namespace
{

bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 5s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(5ms);
  }
  return true;
}

std::string text(const std::vector<NodeId>& nodeIds)
{
  std::string out = "{";
  for (const auto& nodeId : nodeIds)
  {
    out += (out.size() > 1 ? ", " : "") + to_string(nodeId);
  }
  return out + "}";
}

class RegisterNodesOwnership : public ComplianceSecuredWithSession
{
protected:
  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();
    auto addressSpace = mServer->address_space();
    mNamespace = RegisterNodesRecordingNamespace::create(
      "urn:test:register-nodes-ownership", mServerThreadPool.get_executor());
    mIndex = addressSpace.add_namespace_sync(mNamespace);
    for (const char* name : {"X", "Y", "Z", "W"})
    {
      auto node = addressSpace.create_node_sync(NodeId{mIndex, name}, NodeClass::Object);
      node.set_browse_name(QualifiedName{mIndex, name});
      node.set_display_name(LocalizedText{"", name});
    }
    grant_fixture_namespace_permissions(addressSpace);
  }

  NodeId id(const char* name) const
  {
    return NodeId{mIndex, name};
  }

  client::Session open_second_session(const std::string& name)
  {
    auto session = mChannel->create_session_sync({.sessionName = name});
    session.activate_sync();
    return session;
  }

  static std::vector<NodeId> register_nodes(client::Session& session, const std::vector<NodeId>& nodeIds)
  {
    RegisterNodesRequest request;
    for (const auto& nodeId : nodeIds)
    {
      request.nodes_to_register().push_back(nodeId);
    }
    const auto response = session.view().register_nodes_sync(std::move(request));
    std::vector<NodeId> registered;
    for (const auto& nodeId : response.registered_node_ids())
    {
      registered.push_back(nodeId);
    }
    return registered;
  }

  static StatusCode unregister_nodes(client::Session& session, const std::vector<NodeId>& nodeIds)
  {
    UnregisterNodesRequest request;
    for (const auto& nodeId : nodeIds)
    {
      request.nodes_to_unregister().push_back(nodeId);
    }
    const auto response = session.view().unregister_nodes_sync(std::move(request));
    return response.response_header().service_result();
  }

  std::shared_ptr<RegisterNodesRecordingNamespace> mNamespace;
  uint16_t mIndex = 0;
};

}  // namespace

// @relation(AC-SVR-VIEW-URG-001-FORWARDS-ONLY-THE-SESSIONS-IDS, scope=function)
TEST_F(RegisterNodesOwnership, UnregisterForwardsOnlyTheSessionsIds)
{
  // Session A is the fixture's Session; Session B a second one on the same channel.
  ASSERT_EQ(register_nodes(*mSession, {id("X")}), (std::vector<NodeId>{id("X")}));
  auto sessionB = open_second_session("RegisterNodesOwnershipB");
  ASSERT_EQ(register_nodes(sessionB, {id("Z")}), (std::vector<NodeId>{id("Z")}));

  const auto status = unregister_nodes(sessionB, {id("X"), id("Z"), id("Y")});
  EXPECT_EQ(status.as_status(), Status::Good) << to_string(status);
  EXPECT_EQ(mNamespace->unregistered(), (std::vector<NodeId>{id("Z")}))
    << "Session B's UnregisterNodes forwarded " << text(mNamespace->unregistered()) << ", not Z only";
  sessionB.close_sync();

  mSession->close_sync();
  EXPECT_TRUE(wait_until([this] { return mNamespace->unregistered_count(id("X")) == 1u; }))
    << "Session A's close did not unregister X; unregistered: " << text(mNamespace->unregistered());
}

// @relation(AC-SVR-VIEW-REG-002-SESSION-CLOSE-UNREGISTERS, scope=function)
TEST_F(RegisterNodesOwnership, SessionCloseUnregistersTheSessionsNodes)
{
  ASSERT_EQ(
    register_nodes(*mSession, {id("X"), id("Y"), id("Z")}), (std::vector<NodeId>{id("X"), id("Y"), id("Z")}));
  EXPECT_EQ(unregister_nodes(*mSession, {id("Y")}).as_status(), Status::Good);

  mSession->close_sync();
  EXPECT_TRUE(wait_until(
    [this] {
      return mNamespace->unregistered_count(id("X")) == 1u && mNamespace->unregistered_count(id("Z")) == 1u;
    }))
    << "after the Session closed the namespace had been asked to unregister "
    << text(mNamespace->unregistered());
  std::this_thread::sleep_for(100ms);
  for (const char* name : {"X", "Y", "Z"})
  {
    EXPECT_EQ(mNamespace->unregistered_count(id(name)), 1u) << name << " was not unregistered exactly once";
  }
}
