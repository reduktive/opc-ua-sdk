// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the immutable, Session-scoped ua::client::ServerTable (CL-BASE-002).

#include "ua_server_table.h"

#include "ua_error_detail.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <string>

namespace
{

using ua::ExpandedNodeId;
using ua::NodeId;
using ua::client::ServerTable;

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST(ServerTable, ResolvesExpandedNodeIdServerIndexFromCachedArray)
{
  const auto created = ServerTable::create({"urn:local", "urn:remote:a", "urn:remote:b"}, 7);
  ASSERT_TRUE(created.is_good());
  const auto table = created.value();

  EXPECT_EQ(table->size(), 3u);
  EXPECT_EQ(table->generation(), 7u);
  EXPECT_EQ(table->lookup_index("urn:remote:a"), 1u);
  const auto resolved = table->resolve_server_uri(ExpandedNodeId{NodeId{2, 42}, std::uint32_t{2}});
  ASSERT_TRUE(resolved.is_good());
  EXPECT_EQ(resolved.value(), "urn:remote:b");
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST(ServerTable, InvalidServerIndexRetainsIndexAndBoundsInErrorDetail)
{
  const auto table = ServerTable::create({"urn:local"}, 0).value();

  const auto result = table->resolve_server_uri(ExpandedNodeId{NodeId{1, 42}, std::uint32_t{9}});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadServerIndexInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ServerIndexOutOfRange");
  EXPECT_EQ(result.shared_detail()->source, "client.server_table");
  ASSERT_EQ(result.shared_detail()->context.size(), 2u);
  EXPECT_EQ(result.shared_detail()->context[0].value, "9");
  EXPECT_EQ(result.shared_detail()->context[1].value, "1");
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST(ServerTable, RejectsMissingLocalServerUri)
{
  for (const auto& uris : {std::vector<std::string>{}, std::vector<std::string>{""}})
  {
    const auto result = ServerTable::create(uris, 0);
    ASSERT_TRUE(result.is_bad());
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "LocalServerUriMissing");
  }
}

// @verifies CL-BASE-002
// @relation(CL-BASE-002, scope=function)
TEST(ServerTable, DuplicateUriResolvesToStableLowestIndex)
{
  const auto table = ServerTable::create({"urn:local", "urn:remote", "urn:remote"}, 0).value();
  EXPECT_EQ(table->lookup_index("urn:remote"), 1u);
}

}  // namespace
