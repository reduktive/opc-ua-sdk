// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_structure.h"
#include "ua_expanded_node_id.h"
#include "ua_codec.h"

namespace ua
{

BuiltInTypeId Structure::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool Structure::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  UA_UNUSED(ns);

  // Every structured DataType is a subtype of Structure (i=22), and every DataType of BaseDataType.
  // StructureType (i=98) is the Enumeration of structure kinds, not a supertype.
  return (dataTypeId == NodeId{DataTypeId::Structure}) || (dataTypeId == NodeId{DataTypeId::BaseDataType});
}

void Structure::encode(StackDepth limit, Encoder& encoder) const
{
  // Each structure encode represents visiting one node in the encoded graph.
  limit.consume_node();
  UA_UNUSED(encoder);
}

void Structure::decode(StackDepth limit, Decoder& decoder)
{
  // Each structure decode represents visiting one node in the decoded graph.
  limit.consume_node();
  UA_UNUSED(decoder);
}

void Structure::resolve(span<const LocaleId> locales)
{
  UA_UNUSED(locales);
}

void Structure::append_fields(std::string& output, int /*indent*/) const
{
  UA_UNUSED(output);
}

}  // namespace ua
