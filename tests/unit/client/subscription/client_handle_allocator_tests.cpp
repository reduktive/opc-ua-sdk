// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ClientHandleAllocator (CL-MI-003) - unique per-Connection monitored
// item handles: monotonic, never 0, wraps past the max to 1.
//
// Falsifiability: a stub returning 0 / not advancing fails every case.
//
// @verifies CL-MI-003
// @relation(CL-MI-003, scope=file)

#include "ua_client_handle_allocator.h"

#include <gtest/gtest.h>

#include <set>

namespace
{

using ua::client::detail::ClientHandleAllocator;

TEST(ClientHandleAllocator, FirstHandleIsOne)
{
  ClientHandleAllocator alloc;
  EXPECT_EQ(alloc.allocate(), 1u);
}

TEST(ClientHandleAllocator, IncreasesMonotonically)
{
  ClientHandleAllocator alloc;
  EXPECT_EQ(alloc.allocate(), 1u);
  EXPECT_EQ(alloc.allocate(), 2u);
  EXPECT_EQ(alloc.allocate(), 3u);
}

TEST(ClientHandleAllocator, HandlesAreUniqueAndNeverZero)
{
  ClientHandleAllocator alloc;
  std::set<std::uint32_t> seen;
  for (int i = 0; i < 1000; ++i)
  {
    const auto handle = alloc.allocate();
    EXPECT_NE(handle, 0u);
    EXPECT_TRUE(seen.insert(handle).second) << "handle " << handle << " was issued twice";
  }
}

TEST(ClientHandleAllocator, WrapsPastMaxToOneNotZero)
{
  ClientHandleAllocator alloc{ClientHandleAllocator::maxHandle};
  EXPECT_EQ(alloc.allocate(), ClientHandleAllocator::maxHandle);
  EXPECT_EQ(alloc.allocate(), 1u) << "the successor of the max handle is 1, not 0";
}

TEST(ClientHandleAllocator, ZeroFirstHandleTreatedAsOne)
{
  ClientHandleAllocator alloc{0};
  EXPECT_EQ(alloc.allocate(), 1u);
}

}  // namespace
