// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// FakeNode - a Node of a given NodeId and NodeClass for the behaviour pins.
//
// Its description carries those two Attributes and the defaults
// NodeDescription::try_from_attributes gives every other one. The operations
// on a Node - References, Values, writes, calls, Views - are its namespace's
// batched members: FakeAsyncNamespace stages their answers and records their
// calls per NodeId.

#ifndef UA_TEST_BEHAVIOUR_PINS_FAKE_NODE_H
#define UA_TEST_BEHAVIOUR_PINS_FAKE_NODE_H

#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"

namespace ua::test::behaviour_pins
{

class FakeNode : public Node
{
public:
  /// @throws UaException when @p nodeClass is not one of the eight NodeClasses.
  FakeNode(NodeId nodeId, NodeClass nodeClass);

  FakeNode(const FakeNode&) = delete;
  FakeNode& operator=(const FakeNode&) = delete;

  NodeDescription attributes() const override;

private:
  NodeDescription mDescription;
};

}  // namespace ua::test::behaviour_pins

#endif  // UA_TEST_BEHAVIOUR_PINS_FAKE_NODE_H
