// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_zero_tables.h"

#include <array>

namespace ua::namespace_zero_tables
{

std::span<const ReferenceTypeRow> reference_types() noexcept
{
  static constexpr std::array<ReferenceTypeRow, 80> rows{{
    {31U, 0U, true},
    {32U, 31U, true},
    {33U, 31U, true},
    {34U, 33U, true},
    {35U, 33U, false},
    {36U, 33U, false},
    {37U, 32U, false},
    {38U, 32U, false},
    {39U, 32U, false},
    {40U, 32U, false},
    {41U, 32U, false},
    {44U, 34U, true},
    {45U, 34U, false},
    {46U, 44U, false},
    {47U, 44U, false},
    {48U, 36U, false},
    {49U, 47U, false},
    {51U, 32U, false},
    {52U, 32U, false},
    {53U, 32U, false},
    {54U, 32U, false},
    {56U, 44U, false},
    {117U, 32U, false},
    {129U, 47U, false},
    {131U, 129U, false},
    {3065U, 41U, false},
    {9004U, 32U, false},
    {9005U, 32U, false},
    {9006U, 32U, false},
    {14476U, 47U, false},
    {14936U, 33U, false},
    {15112U, 47U, false},
    {15296U, 47U, false},
    {15297U, 47U, false},
    {16361U, 47U, false},
    {16362U, 35U, false},
    {17276U, 54U, false},
    {17597U, 32U, false},
    {17603U, 32U, false},
    {17604U, 47U, false},
    {17983U, 54U, false},
    {17984U, 54U, false},
    {17985U, 54U, false},
    {18804U, 47U, false},
    {18805U, 47U, false},
    {19814U, 32U, false},
    {19815U, 33U, false},
    {19816U, 19815U, false},
    {19817U, 19815U, false},
    {19818U, 32U, false},
    {19819U, 33U, false},
    {19845U, 33U, false},
    {19846U, 34U, false},
    {23469U, 32U, false},
    {23562U, 32U, false},
    {24136U, 47U, false},
    {24137U, 32U, false},
    {25237U, 32U, false},
    {25238U, 33U, false},
    {25253U, 32U, false},
    {25254U, 33U, false},
    {25255U, 32U, false},
    {25256U, 33U, false},
    {25257U, 32U, false},
    {25258U, 32U, false},
    {25259U, 25258U, false},
    {25260U, 25258U, false},
    {25261U, 25255U, false},
    {25262U, 47U, false},
    {25263U, 25262U, false},
    {25264U, 25262U, false},
    {25265U, 25255U, false},
    {25345U, 33U, false},
    {32059U, 16362U, false},
    {32407U, 32U, false},
    {32558U, 32U, false},
    {32559U, 32U, false},
    {32633U, 32U, false},
    {32634U, 32U, false},
    {32679U, 34U, false},
  }};
  return rows;
}

std::span<const DataAccessTypeRow> data_access_variable_types() noexcept
{
  static constexpr std::array<DataAccessTypeRow, 14> rows{{
    {2368U, DataAccessKind::Analog},
    {2376U, DataAccessKind::MultiStateDiscrete},
    {11238U, DataAccessKind::MultiStateValueDiscrete},
    {12021U, DataAccessKind::Analog},
    {12029U, DataAccessKind::Analog},
    {12038U, DataAccessKind::Analog},
    {12047U, DataAccessKind::Analog},
    {12057U, DataAccessKind::Analog},
    {12068U, DataAccessKind::Analog},
    {15318U, DataAccessKind::Analog},
    {17497U, DataAccessKind::Analog},
    {17570U, DataAccessKind::Analog},
    {19077U, DataAccessKind::MultiStateValueDiscrete},
    {19084U, DataAccessKind::MultiStateValueDiscrete},
  }};
  return rows;
}

}  // namespace ua::namespace_zero_tables
