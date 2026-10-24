// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_zero.h"
#include "ua_data_value.h"
#include "ua_node.h"
#include "ua_add_references_item.h"
#include "ua_add_nodes_item.h"
#include "ua_memory_stream.h"
#include "ua_nodeset_parser.h"
#include "nodeset_ns0.h"
#include "ua_structure_factory.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_default_reference_type_node.h"

namespace ua::default_ns
{

VoidResult NamespaceZero::on_attached(const NamespaceContext& context)
{
  if (context.index() != 0)
  {
    return VoidResult{StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build(
        "NamespaceIndexOutOfRange", "NamespaceZero must have a namespace index of zero", "NamespaceZero")
        .context(ua::ContextKeys::namespaceIndex, std::to_string(context.index()))
        .context(ua::ContextKeys::expected, std::to_string(0))}};
  }
  return {};
}

std::optional<NodeId> NamespaceZero::metadata_object() const
{
  return NodeId{ObjectId::OPCUANamespaceMetadata};
}

shared_ptr<NamespaceZero> NamespaceZero::create(boost::asio::any_io_executor executor)
{
  struct Wrapper : public NamespaceZero
  {
  public:
    explicit Wrapper(boost::asio::any_io_executor executor) : NamespaceZero(std::move(executor))
    {}
  };

  return make_shared<Wrapper>(std::move(executor));
}

NamespaceZero::NamespaceZero(boost::asio::any_io_executor executor)
  : default_ns::Namespace{"http://opcfoundation.org/UA/", std::move(executor)}
{}

}  // namespace ua::default_ns
