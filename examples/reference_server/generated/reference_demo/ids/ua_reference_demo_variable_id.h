// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_DEMO_VARIABLE_IDENTIFIERS_H
#define UA_REFERENCE_DEMO_VARIABLE_IDENTIFIERS_H

#include "ua_includes.h"

namespace ua::reference_demo
{

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
enum class VariableId : uint32_t
{
  DemoType_UptimeSeconds = 1002U,
  DemoType_Setpoint = 1003U,
  DemoType_Divide_InputArguments = 1005U,
  DemoType_Divide_OutputArguments = 1006U,
  Demo_UptimeSeconds = 2002U,
  Demo_Setpoint = 2003U,
  Demo_Divide_InputArguments = 2005U,
  Demo_Divide_OutputArguments = 2006U
};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace ua::reference_demo

#endif  // UA_REFERENCE_DEMO_VARIABLE_IDENTIFIERS_H
