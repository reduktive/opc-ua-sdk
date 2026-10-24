// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_ZERO_H
#define UA_NAMESPACE_ZERO_H

#include "ua_default_namespace.h"
#include "ua_string.h"
#include "ua_node_id.h"
#include "ua_nodeset_parser.h"

namespace ua::default_ns
{

class NamespaceZero : public default_ns::Namespace
{
public:
  NamespaceZero(const NamespaceZero&) = delete;
  NamespaceZero(NamespaceZero&&) noexcept = delete;
  NamespaceZero& operator=(const NamespaceZero&) = delete;
  NamespaceZero& operator=(NamespaceZero&&) noexcept = delete;
  ~NamespaceZero() override = default;

  std::optional<NodeId> metadata_object() const override;

  static shared_ptr<NamespaceZero> create(boost::asio::any_io_executor executor);

private:
  explicit NamespaceZero(boost::asio::any_io_executor executor);

  /// Refuses any index but 0 with `Bad_InvalidArgument`: namespace 0 is the OPC UA namespace.
  VoidResult on_attached(const NamespaceContext& context) override;
};

}  // namespace ua::default_ns

#endif  // UA_NAMESPACE_ZERO_H
