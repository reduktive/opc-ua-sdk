// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Compile-level check that the server name of the Data Access write policy stays.

#include <gtest/gtest.h>

#include <type_traits>

#include "ua_data_access_utils.h"
#include "ua_server_configuration.h"

// ua::server::DataAccessOutOfRangePolicy names the type that ua::DataAccessOutOfRangePolicy moved to, so
// existing callers compile unchanged. The control is the enumerator both names reach: a value of one converts
// to the other.
// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-SERVER-POLICY-ALIAS, scope=function)
TEST(DataAccessPolicyAlias, ServerNameIsTheCoreType)
{
  static_assert(std::is_same_v<ua::server::DataAccessOutOfRangePolicy, ua::DataAccessOutOfRangePolicy>);
  const ua::server::DataAccessOutOfRangePolicy serverName = ua::server::DataAccessOutOfRangePolicy::Clamp;
  const ua::DataAccessOutOfRangePolicy coreName = serverName;
  EXPECT_EQ(coreName, ua::DataAccessOutOfRangePolicy::Clamp);
}
