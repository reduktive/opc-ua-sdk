// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_DEMO_DATA_TYPE_REGISTRATION_H
#define UA_REFERENCE_DEMO_DATA_TYPE_REGISTRATION_H

#include "ua_structure.h"
#include "ua_reference_demo_aliases.h"

namespace ua::reference_demo
{

void register_ua_reference_demo_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);

}  // namespace ua::reference_demo

#endif  // !UA_REFERENCE_DEMO_DATA_TYPE_REGISTRATION_H
