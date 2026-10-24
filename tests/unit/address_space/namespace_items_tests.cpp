// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-NAMESPACE-INTERFACE-04 (ReferenceChange::both_halves) and -09 item 1 (the default
// RequestInfo's cancellation flag).

#include <gtest/gtest.h>

#include "ua_expanded_node_id.h"
#include "ua_namespace_items.h"
#include "ua_node_id.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"

#include <atomic>
#include <cstdint>
#include <string_view>
#include <thread>

using namespace ua;

// NR-30 rule 3 and NR-63: the two halves of one Reference, forward on the source and inverse on the
// target, each with sourceCreated false; a ReferenceChange given only three fields is a forward half
// whose source was not created in the operation. Two namespaces and identifier forms show that each half
// is addressed to its own Node.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-04-BOTH-HALVES-FORWARD-AND-INVERSE, scope=function)
TEST(ReferenceChangePairs, BothHalvesNamesForwardAndInverse)
{
  const NodeId source{2, uint32_t{1}};
  const NodeId target{3, std::string_view{"Motor"}};
  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  const auto halves = ReferenceChange::both_halves(source, hasComponent, target);

  EXPECT_EQ(halves[0].source, source);
  EXPECT_EQ(halves[0].referenceType, hasComponent);
  EXPECT_EQ(halves[0].target, ExpandedNodeId{target});
  EXPECT_TRUE(halves[0].isForward);
  EXPECT_FALSE(halves[0].sourceCreated);

  EXPECT_EQ(halves[1].source, target);
  EXPECT_EQ(halves[1].referenceType, hasComponent);
  EXPECT_EQ(halves[1].target, ExpandedNodeId{source});
  EXPECT_FALSE(halves[1].isForward);
  EXPECT_FALSE(halves[1].sourceCreated);

  const ReferenceChange threeFields{source, hasComponent, ExpandedNodeId{target}};
  EXPECT_TRUE(threeFields.isForward);
  EXPECT_FALSE(threeFields.sourceCreated);
}

// The A1 header review's ruling of 2026-10-09 and NR-8: every default-constructed RequestInfo holds the
// same flag, not null and not set. The second thread is the control that the flag is one static object,
// and the copy that copying keeps it.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-09-DEFAULT-REQUEST-IS-NEVER-CANCELLED, scope=function)
TEST(RequestInfoDefault, IsOneSharedFlagThatIsNeverSet)
{
  const RequestInfo first;
  const RequestInfo copy = first;
  const std::atomic_bool* otherThreads = nullptr;
  bool otherThreadsSet = true;
  std::thread other{[&]
    {
      const RequestInfo onAnotherThread;
      otherThreads = onAnotherThread.cancelled.get();
      otherThreadsSet = onAnotherThread.cancelled && onAnotherThread.cancelled->load();
    }};
  other.join();

  ASSERT_NE(first.cancelled, nullptr);
  ASSERT_NE(copy.cancelled, nullptr);
  ASSERT_NE(otherThreads, nullptr);
  EXPECT_FALSE(first.cancelled->load());
  EXPECT_FALSE(copy.cancelled->load());
  EXPECT_FALSE(otherThreadsSet);
  EXPECT_EQ(first.cancelled.get(), copy.cancelled.get());
  EXPECT_EQ(first.cancelled.get(), otherThreads);
}
