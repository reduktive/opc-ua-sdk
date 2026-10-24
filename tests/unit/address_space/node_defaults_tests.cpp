// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-NAMESPACE-INTERFACE-02 item 3: Node::deleted()'s default.

#include <gtest/gtest.h>

#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"

#include <cstdint>
#include <memory>
#include <utility>

using namespace ua;

namespace
{

// A Node that describes itself and overrides nothing else: it never deletes.
class DescribedOnlyNode final : public Node
{
public:
  NodeDescription attributes() const override
  {
    return NodeDescription::object(NodeId{2, uint32_t{60}}, QualifiedName{2, "Never deleted"});
  }
};

}  // namespace

// NR-44: deleted() defaults to false, so a namespace that never deletes Nodes implements nothing; it is
// noexcept.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-02-DELETED-DEFAULT-FALSE, scope=function)
TEST(NodeDeletedDefault, ANodeThatNeverDeletesAnswersFalse)
{
  const auto node = std::make_shared<DescribedOnlyNode>();
  static_assert(noexcept(std::declval<const Node&>().deleted()), "Node::deleted() must be noexcept");
  EXPECT_FALSE(node->deleted());
}
