// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A concrete ConditionType for tests that want a plain Condition.

#ifndef UA_TEST_HELPERS_CONCRETE_CONDITION_TYPE_H
#define UA_TEST_HELPERS_CONCRETE_CONDITION_TYPE_H

#include "ua_address_space.h"
#include "ua_expanded_node_id.h"
#include "ua_node_accessor.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

#include <cstdint>

namespace ua::test_helpers
{

/// A concrete ObjectType derived from ConditionType that declares no members of its own, so its instances
/// have exactly the members a ConditionType instance has. ConditionType is abstract, and an abstract type
/// has no instances of its own (OPC 10000-3 section 5.5.2; address_space_1_0.md D-25, P8E). Created once
/// per address space, with both halves of its HasSubtype so a subtype test from either side finds it.
///
/// @param addressSpace   Address space holding NS0's ConditionType.
/// @param namespaceIndex Namespace the type is created in; it must exist.
/// @return The type's NodeId.
inline NodeId concrete_condition_type(AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const NodeId typeId{namespaceIndex, std::string_view{"TestConcreteConditionType"}};
  if (addressSpace.try_find_node_sync(typeId).is_good())
  {
    return typeId;
  }
  auto type = addressSpace.create_node_sync(typeId, NodeClass::ObjectType);
  type.set_browse_name(QualifiedName{namespaceIndex, "TestConcreteConditionType"});
  type.set_display_name(LocalizedText{"", String{"TestConcreteConditionType"}});
  // The address space adds the inverse half on the new type (NR-70 B8).
  addressSpace.find_node_sync(NodeId{ObjectTypeId::ConditionType})
    .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{typeId});
  return typeId;
}

}  // namespace ua::test_helpers

#endif  // UA_TEST_HELPERS_CONCRETE_CONDITION_TYPE_H
