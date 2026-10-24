// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_node.h"

namespace ua::test::behaviour_pins
{

FakeNode::FakeNode(NodeId nodeId, NodeClass nodeClass)
  : mDescription(NodeDescription::try_from_attributes(nodeId, nodeClass, InitialAttributes{}).value())
{}

NodeDescription FakeNode::attributes() const
{
  return mDescription;
}

}  // namespace ua::test::behaviour_pins
