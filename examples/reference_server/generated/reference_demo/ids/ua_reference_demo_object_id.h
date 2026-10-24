// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_DEMO_OBJECT_IDENTIFIERS_H
#define UA_REFERENCE_DEMO_OBJECT_IDENTIFIERS_H

#include "ua_includes.h"

namespace ua::reference_demo
{

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
enum class ObjectId : uint32_t
{
  Demo = 2001U
};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace ua::reference_demo

#endif  // UA_REFERENCE_DEMO_OBJECT_IDENTIFIERS_H
