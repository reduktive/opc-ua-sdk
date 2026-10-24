// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_union.h"

#include "ua_datatype_id.h"
#include "ua_node_id.h"

namespace ua
{

BuiltInTypeId Union::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool Union::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  return (dataTypeId == NodeId{DataTypeId::Union}) || Structure::is_of_type(ns, dataTypeId);
}

}  // namespace ua
