// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_REGISTRATION_H
#define UA_DATA_TYPE_REGISTRATION_H

#include "ua_structure.h"

namespace ua
{

class StructureFactory;

void register_ua_core_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_data_access_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_auditing_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_certificates_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_network_mgmt_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_diagnostics_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);
void register_ua_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);

}  // namespace ua

#endif  // !UA_DATA_TYPE_REGISTRATION_H
