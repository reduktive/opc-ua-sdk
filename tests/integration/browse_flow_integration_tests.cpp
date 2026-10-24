// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A Browse continuation point that is discarded releases the resume token it holds, over the wire.
///
/// A recording namespace that pages each answer at the query's maxReferences, with a resume token while
/// References remain, is mounted in a real server; an SDK client Browses one of its Nodes with
/// requestedMaxReferencesPerNode 2, so the Session stores a continuation point holding the namespace's token.
/// The point is then released by BrowseNext, discarded with its Session, freed for a new request, or expired,
/// and the namespace is watched for `release_resume_token`. These need the Session's own store of
/// continuation points, which only a real Session has.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "batch_recording_namespace.h"
#include "compliance_helpers.h"
#include "requests.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_byte_string.h"
#include "ua_referencetype_id.h"
#include "ua_session_view_services.h"
#include "ua_to_string.h"

using namespace ua;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

std::string text_of(const ByteString& token)
{
  return std::string{reinterpret_cast<const char*>(token.data()), token.size()};
}

/// A server with a recording namespace A holding S and S', each with five forward HasComponent References,
/// and a Session on it. The Session's continuation-point limits are set per test, before the server is built.
class BrowseFlow : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    ComplianceWithSession::configure_server_config(serverCfg);
    const std::string_view name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
    if (name == "AContinuationPointFreedForANewRequestReleasesItsResumeToken")
    {
      serverCfg.server_capabilities().maxBrowseContinuationPoints = 1;
    }
    if (name == "AnExpiredContinuationPointReleasesItsResumeToken")
    {
      serverCfg.browseContinuationPointTimeout = 200ms;
    }
  }

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mA = std::make_shared<BatchRecordingNamespace>(
      "urn:test:browse-flow:release", mServer.thread_pool().executor());
    const uint16_t index = addressSpace.add_namespace_sync(mA);
    mS = NodeId{index, uint32_t{100}};
    mOther = NodeId{index, uint32_t{200}};
    for (const uint32_t base : {uint32_t{100}, uint32_t{200}})
    {
      const NodeId source{index, base};
      auto sourceNode = addressSpace.create_node_sync(source, NodeClass::Object);
      for (uint32_t i = 1; i <= 5; ++i)
      {
        const NodeId target{index, base + i};
        auto targetNode = addressSpace.create_node_sync(target, NodeClass::Object);
        sourceNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{target}, true);
        targetNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{source}, false);
      }
    }
    mA->page_references_by_max_references();
  }

  static BrowseRequest browse_of(const NodeId& source)
  {
    return BrowseRequestBuilder()
      .browse(source)
      .direction(BrowseDirection::Forward)
      .reference_type(NodeId{})
      .include_subtypes(true)
      .max_references_per_node(2)
      .build();
  }

  /// Browses S, so the response carries a continuation point P holding A's token; @return P, and A's token in
  /// @p token.
  ByteString browse_s(ByteString& token)
  {
    mA->reset();
    auto response = mSession->view().browse_sync(browse_of(mS));
    EXPECT_EQ(response.results().size(), 1U);
    if (response.results().size() != 1U)
    {
      return {};
    }
    EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good);
    EXPECT_EQ(response.results()[0].references().size(), 2U);
    const auto point = response.results()[0].continuation_point();
    EXPECT_FALSE(point.empty()) << "S's Browse handed out no continuation point";
    for (const auto& call : mA->calls(Member::ReadReferences))
    {
      for (const auto& query : call.referenceQueries)
      {
        if (query.nodeId == mS && !query.answeredToken.empty())
        {
          token = query.answeredToken;
        }
      }
    }
    EXPECT_FALSE(token.empty()) << "A answered S with no resume token";
    mSequenceAfterBrowse = latest_sequence();
    return point;
  }

  std::size_t latest_sequence() const
  {
    std::size_t latest = 0;
    for (const auto& call : mA->calls())
    {
      latest = std::max(latest, call.sequence);
    }
    return latest;
  }

  /// Waits up to 2 s for A to release @p token, then a little longer for a second release.
  /// @return How many times A released @p token.
  std::size_t releases_of(const ByteString& token) const
  {
    const auto count = [this, &token]
    {
      std::size_t released = 0;
      for (const auto& call : mA->calls(Member::ReleaseResumeToken))
      {
        if (call.token == token)
        {
          ++released;
        }
      }
      return released;
    };
    const auto until = std::chrono::steady_clock::now() + 2s;
    while (count() == 0 && std::chrono::steady_clock::now() < until)
    {
      std::this_thread::sleep_for(10ms);
    }
    std::this_thread::sleep_for(100ms);
    return count();
  }

  /// No read_references_async query A received after S's Browse carries @p token.
  void expect_no_later_query_carries(const ByteString& token) const
  {
    for (const auto& call : mA->calls(Member::ReadReferences))
    {
      if (call.sequence <= mSequenceAfterBrowse)
      {
        continue;
      }
      for (const auto& query : call.referenceQueries)
      {
        EXPECT_NE(query.resumeToken, token) << "a later query naming " << query.nodeId.as_definition()
                                            << " carried P's token \"" << text_of(token) << "\"";
      }
    }
  }

  /// Browses S' in a new request; it answers Good with two References and a continuation point.
  void expect_other_browsed()
  {
    auto response = mSession->view().browse_sync(browse_of(mOther));
    ASSERT_EQ(response.results().size(), 1U);
    EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good)
      << to_string(response.results()[0].status_code());
    EXPECT_EQ(response.results()[0].references().size(), 2U);
    EXPECT_FALSE(response.results()[0].continuation_point().empty()) << "S' handed out no continuation point";
  }

  shared_ptr<BatchRecordingNamespace> mA;
  NodeId mS;
  NodeId mOther;
  std::size_t mSequenceAfterBrowse{0};
};

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-A-DISCARDED-CONTINUATION-POINT-RELEASES-ITS-RESUME-TOKEN, scope=function)
TEST_F(BrowseFlow, AContinuationPointReleasedByBrowseNextReleasesItsResumeToken)
{
  ByteString token;
  const auto point = browse_s(token);
  ASSERT_FALSE(point.empty());
  ASSERT_FALSE(token.empty());

  auto released = mSession->view().browse_next_sync(browse_next(point, /*release=*/true));

  EXPECT_TRUE(released.results().empty()) << released.results().size() << " results";
  EXPECT_EQ(releases_of(token), 1U) << "release_resume_token calls with P's token \"" << text_of(token)
                                    << "\"";
  expect_no_later_query_carries(token);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-A-DISCARDED-CONTINUATION-POINT-RELEASES-ITS-RESUME-TOKEN, scope=function)
TEST_F(BrowseFlow, AContinuationPointDiscardedWithItsSessionReleasesItsResumeToken)
{
  ByteString token;
  const auto point = browse_s(token);
  ASSERT_FALSE(point.empty());
  ASSERT_FALSE(token.empty());

  ASSERT_TRUE(mSession->try_close_sync().is_good());
  mSession.reset();

  EXPECT_EQ(releases_of(token), 1U) << "release_resume_token calls with P's token \"" << text_of(token)
                                    << "\"";
  expect_no_later_query_carries(token);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-A-DISCARDED-CONTINUATION-POINT-RELEASES-ITS-RESUME-TOKEN, scope=function)
TEST_F(BrowseFlow, AContinuationPointFreedForANewRequestReleasesItsResumeToken)
{
  ByteString token;
  const auto point = browse_s(token);
  ASSERT_FALSE(point.empty());
  ASSERT_FALSE(token.empty());

  expect_other_browsed();

  EXPECT_EQ(releases_of(token), 1U) << "release_resume_token calls with P's token \"" << text_of(token)
                                    << "\"";
  expect_no_later_query_carries(token);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-A-DISCARDED-CONTINUATION-POINT-RELEASES-ITS-RESUME-TOKEN, scope=function)
TEST_F(BrowseFlow, AnExpiredContinuationPointReleasesItsResumeToken)
{
  ByteString token;
  const auto point = browse_s(token);
  ASSERT_FALSE(point.empty());
  ASSERT_FALSE(token.empty());

  std::this_thread::sleep_for(400ms);
  expect_other_browsed();

  EXPECT_EQ(releases_of(token), 1U) << "release_resume_token calls with P's token \"" << text_of(token)
                                    << "\"";
  expect_no_later_query_carries(token);
}
