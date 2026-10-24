// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_codec_namespace_context.h"

#include "ua_data_value.h"

namespace ua
{

CodecNamespaceContext::CodecNamespaceContext(NamespaceIndexResolver namespaceIndexResolver,
  NodeIdTranslator nodeIdTranslator, QualifiedNameTranslator qualifiedNameTranslator,
  ExpandedNodeIdTranslator expandedNodeIdTranslator)
  : getNamespaceIndex(std::move(namespaceIndexResolver)), translateNodeId(std::move(nodeIdTranslator)),
    translateQualifiedName(std::move(qualifiedNameTranslator)),
    translateExpandedNodeId(std::move(expandedNodeIdTranslator))
{}

CodecNamespaceContext CodecNamespaceContext::with_translators(NodeIdTranslator translateNodeId,
  QualifiedNameTranslator translateQualifiedName, ExpandedNodeIdTranslator translateExpandedNodeId)
{
  return CodecNamespaceContext{
    {}, std::move(translateNodeId), std::move(translateQualifiedName), std::move(translateExpandedNodeId)};
}

}  // namespace ua
