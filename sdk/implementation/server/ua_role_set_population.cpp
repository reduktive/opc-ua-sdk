// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_set_population.h"

#include "ua_access_restriction_type.h"
#include "ua_array.h"
#include "ua_attribute_wire.h"
#include "ua_endpoint_type.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_type.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <array>
#include <string>
#include <string_view>

namespace ua::server
{

namespace
{

constexpr uint32_t roleTypeId = 15620;

struct WellKnownRoleNodes
{
  WellKnownRole role;
  uint32_t roleObjectId;
};

constexpr std::array<WellKnownRoleNodes, 9> wellKnownRoles{{
  {WellKnownRole::Anonymous, utils::to_underlying(ObjectId::WellKnownRole_Anonymous)},
  {WellKnownRole::AuthenticatedUser, utils::to_underlying(ObjectId::WellKnownRole_AuthenticatedUser)},
  {WellKnownRole::Observer, utils::to_underlying(ObjectId::WellKnownRole_Observer)},
  {WellKnownRole::Operator, utils::to_underlying(ObjectId::WellKnownRole_Operator)},
  {WellKnownRole::Engineer, utils::to_underlying(ObjectId::WellKnownRole_Engineer)},
  {WellKnownRole::Supervisor, utils::to_underlying(ObjectId::WellKnownRole_Supervisor)},
  {WellKnownRole::ConfigureAdmin, utils::to_underlying(ObjectId::WellKnownRole_ConfigureAdmin)},
  {WellKnownRole::SecurityAdmin, utils::to_underlying(ObjectId::WellKnownRole_SecurityAdmin)},
  {WellKnownRole::TrustedApplication, utils::to_underlying(ObjectId::WellKnownRole_TrustedApplication)},
}};

void merge_encrypted_browse_requirement(NodeAccessor& node)
{
  auto restrictions = node.get_access_restrictions().value_or(AccessRestrictionType{});
  restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
  restrictions.set(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  node.set_access_restrictions(restrictions);
}

template<typename Apply>
void apply_to_role_surface(AddressSpace& addressSpace, NodeAccessor& roleNode, Apply apply)
{
  apply(roleNode);
  auto references = roleNode.try_get_references_sync();
  if (!references)
  {
    return;
  }
  for (const auto& reference : references.value())
  {
    if (!reference.is_forward() || reference.is_remote() || !reference.type_id().is_numeric())
    {
      continue;
    }
    const auto referenceType = reference.type_id().identifier().get_numeric();
    if (referenceType != utils::to_underlying(ReferenceTypeId::HasProperty) &&
        referenceType != utils::to_underlying(ReferenceTypeId::HasComponent))
    {
      continue;
    }
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child)
    {
      apply(child.value());
    }
  }
}

void merge_encrypted_browse_requirement_with_children(AddressSpace& addressSpace, NodeAccessor& roleNode)
{
  apply_to_role_surface(
    addressSpace, roleNode, [](NodeAccessor& node) { merge_encrypted_browse_requirement(node); });
}

/// Look up a child node by browse name under `parent` via HasProperty refs.
/// Returns the child's `NodeAccessor` or empty on miss.
optional<NodeAccessor> find_property_child(
  AddressSpace& addressSpace, const NodeAccessor& parent, std::string_view browseName)
{
  auto references = parent.try_get_references_sync();
  if (!references)
  {
    return std::nullopt;
  }
  for (const auto& ref : references.value())
  {
    if (!ref.is_forward() || ref.is_remote())
    {
      continue;
    }
    if (!ref.type_id().is_numeric() ||
        ref.type_id().identifier().get_numeric() != utils::to_underlying(ReferenceTypeId::HasProperty))
    {
      continue;
    }
    auto childResult = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (!childResult)
    {
      continue;
    }
    if (static_cast<std::string_view>(childResult.value().get_browse_name().name()) == browseName)
    {
      return childResult.value();
    }
  }
  return std::nullopt;
}

void write_variable(NodeAccessor& node, Variant value)
{
  auto var = node.as<VariableAccessor>();
  if (!var)
  {
    return;
  }
  DataValue dv;
  dv.value() = std::move(value);
  dv.server_timestamp() = DateTime::now();
  (void)var->try_write_value_sync(std::move(dv));
}

void write_property_value(
  AddressSpace& addressSpace, const NodeAccessor& roleObject, std::string_view browseName, Variant value)
{
  auto child = find_property_child(addressSpace, roleObject, browseName);
  if (!child)
  {
    return;
  }
  write_variable(*child, std::move(value));
}

Array<String> to_string_array(const std::vector<String>& apps)
{
  Array<String> out;
  out.payload().reserve(apps.size());
  for (const auto& a : apps)
  {
    out.payload().push_back(a);
  }
  return out;
}

template<typename T>
Array<RefStructure<Structure>> to_structure_array(const std::vector<T>& items)
{
  Array<RefStructure<Structure>> out;
  out.payload().reserve(items.size());
  for (const auto& item : items)
  {
    RefStructure<Structure> ref;
    ref = std::unique_ptr<Structure>{std::make_unique<T>(item).release()};
    out.payload().push_back(std::move(ref));
  }
  return out;
}

/// Mirror the live `RoleConfiguration` content into the role Object's per-role
/// Variables (Identities / Applications / Endpoints + the *Exclude flags).
///
/// The static access-control attributes (RolePermissions / AccessRestrictions)
/// are NOT set here: from UA-1.05.06 the standard NodeSet ships them on the
/// well-known role Objects, their child Variables, and their Methods, and the
/// NodeSet importer applies them. The SDK only synthesised them under 1.05.02
/// because that NodeSet was incomplete; overwriting the imported values now
/// would discard the spec-prescribed grants (e.g. the `Anonymous: Browse`
/// permission on each role Object).
void populate_role_instance(
  AddressSpace& addressSpace, const NodeAccessor& roleObject, const RoleConfiguration::RoleDefinition& def)
{
  write_property_value(addressSpace,
    roleObject,
    "Identities",
    Variant{to_structure_array<IdentityMappingRuleType>(def.identities)});
  write_property_value(addressSpace, roleObject, "Applications", Variant{to_string_array(def.applications)});
  write_property_value(addressSpace, roleObject, "ApplicationsExclude", Variant{def.applicationsExclude});
  write_property_value(
    addressSpace, roleObject, "Endpoints", Variant{to_structure_array<EndpointType>(def.endpoints)});
  write_property_value(addressSpace, roleObject, "EndpointsExclude", Variant{def.endpointsExclude});
  write_property_value(addressSpace, roleObject, "CustomConfiguration", Variant{def.customConfiguration});
}

bool is_role_object(AddressSpace& addressSpace, const NodeId& nodeId)
{
  // A Node or References the namespace is uncertain of do not make a Role object.
  auto node = addressSpace.try_find_node_sync(nodeId);
  if (!node.is_good())
  {
    return false;
  }
  auto references = node.value().try_get_references_sync();
  if (!references.is_good())
  {
    return false;
  }
  for (const auto& reference : references.value())
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition} &&
        reference.target_id().is_local() && reference.target_id().node_id() == NodeId{0, roleTypeId})
    {
      return true;
    }
  }
  return false;
}

void prune_unconfigured_role_membership(
  AddressSpace& addressSpace, NodeAccessor& roleSet, const RoleConfiguration& roleConfig)
{
  // Pruning acts on the RoleSet's References, so only a Good answer is used; any other throws.
  const auto roleSetReferences = ua::detail::good_value(roleSet.try_get_references_sync());
  for (const auto& reference : roleSetReferences)
  {
    if (!reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasComponent} ||
        !reference.target_id().is_local())
    {
      continue;
    }
    const auto roleId = reference.target_id().node_id();
    if (roleConfig.get_role(roleId).has_value() || !is_role_object(addressSpace, roleId))
    {
      continue;
    }
    roleSet.try_remove_reference_sync(reference).value();
  }
}

/// The child of @p roleSet, through a forward local HasComponent Reference, whose BrowseName has the name of
/// @p browseName, whatever its namespace, as AddRole compares them; null when no child has it. A Reference
/// whose target does not resolve names no child.
NodeId role_set_child_named(
  AddressSpace& addressSpace, const NodeAccessor& roleSet, const QualifiedName& browseName)
{
  auto references = roleSet.try_get_references_sync();
  if (!references)
  {
    return NodeId{};
  }
  for (const auto& reference : references.value())
  {
    if (!reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasComponent} ||
        !reference.target_id().is_local())
    {
      continue;
    }
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child && child.value().get_browse_name().name() == browseName.name())
    {
      return reference.target_id().node_id();
    }
  }
  return NodeId{};
}

/// The BrowseName and DisplayName of a configured Role's Object: the definition's BrowseName and its
/// name with no locale.
InitialAttributes role_object_attributes(const QualifiedName& browseName)
{
  InitialAttributes attributes;
  attributes.emplace_back(AttributeId::BrowseName, attribute_wire::browse_name(browseName));
  attributes.emplace_back(
    AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{browseName.name()}));
  return attributes;
}

}  // namespace

void populate_role_set(AddressSpace addressSpace, const RoleConfiguration& roleConfig,
  const std::optional<std::vector<WellKnownRole>>& selection)
{
  // NS0 import preserves the published RolePermissions and merges the Part 18 channel requirements
  // through author_role_management_baseline. That includes EncryptionRequired for AddRole and
  // RemoveRole (sections 4.2.2 and 4.2.3), regardless of their published SigningRequired bit.
  // author_role_management_access extends permissions for deployment-designated administrators.
  // Preserve those grants here; this pass adds the section 4.4.1 encrypted Browse requirement to the
  // Role surface and populates RoleConfiguration values.

  if (auto roleType = addressSpace.try_find_node_sync(NodeId{0, roleTypeId}))
  {
    auto node = roleType.value();
    merge_encrypted_browse_requirement_with_children(addressSpace, node);
  }

  const NodeId roleSetId{ObjectId::Server_ServerCapabilities_RoleSet};
  auto roleSet = addressSpace.try_find_node_sync(roleSetId);
  for (const auto& spec : wellKnownRoles)
  {
    const NodeId roleId{0, spec.roleObjectId};
    auto roleObjectResult = addressSpace.try_find_node_sync(roleId);
    if (!roleObjectResult)
    {
      continue;
    }
    auto roleObject = roleObjectResult.value();
    // Part 18 section 4.4.1 applies the encrypted-channel condition to Browse as well as ordinary
    // access. Preserve every NodeSet-provided permission/restriction bit and add that condition to
    // the Role Object and its Properties/Methods, including roles omitted by the host selection.
    merge_encrypted_browse_requirement_with_children(addressSpace, roleObject);
    if (selection.has_value() &&
        std::find(selection->begin(), selection->end(), spec.role) == selection->end())
    {
      continue;
    }
    auto def = roleConfig.get_role(roleId);
    const RoleConfiguration::RoleDefinition empty;
    populate_role_instance(addressSpace, roleObject, def.value_or(empty));
  }

  for (const auto& def : roleConfig.roles())
  {
    if (def.roleId.namespace_index() == 0)
    {
      continue;
    }
    auto roleObject = addressSpace.try_find_node_sync(def.roleId);
    if (!roleObject)
    {
      // An Object this pass creates is named by the definition (OPC 10000-3 5.2.1: BrowseName and
      // DisplayName are Mandatory). A Role that cannot be named, or whose name another child of RoleSet
      // has (OPC 10000-18 4.2.2), is reported and left out of RoleSet; its permissions still apply.
      if (def.browseName.is_null() || static_cast<std::string_view>(def.browseName.name()).empty())
      {
        const std::string roleText = to_string(def.roleId);
        addressSpace.logger().with_category("server").warning({{"role_id", std::string_view{roleText}}},
          "Configured Role {} is not created under RoleSet: its RoleDefinition has no browseName",
          roleText);
        continue;
      }
      if (roleSet)
      {
        const NodeId holder = role_set_child_named(addressSpace, roleSet.value(), def.browseName);
        if (!holder.is_null())
        {
          const std::string roleText = to_string(def.roleId);
          const std::string nameText = to_string(def.browseName);
          const std::string holderText = to_string(holder);
          addressSpace.logger().with_category("server").warning(
            {{"role_id", std::string_view{roleText}},
              {"browse_name", std::string_view{nameText}},
              {"holder_id", std::string_view{holderText}}},
            "Configured Role {} is not created under RoleSet: its BrowseName {} is already the BrowseName "
            "of {}",
            roleText,
            nameText,
            holderText);
          continue;
        }
      }
      roleObject = addressSpace.try_create_node_sync(
        def.roleId, NodeClass::Object, role_object_attributes(def.browseName));
    }
    if (!roleObject)
    {
      // The Role is configured but cannot be in the address space, typically because its namespace is
      // not registered at start-up. Said, not skipped: an administrator otherwise cannot tell why it is
      // missing from RoleSet.
      const std::string roleText = to_string(def.roleId);
      const std::string causeText = to_string(roleObject.status_code());
      addressSpace.logger().with_category("server").warning(
        {{"role_id", std::string_view{roleText}},
          {"namespace_index", uint64_t{def.roleId.namespace_index()}},
          {"cause", std::string_view{causeText}}},
        "Configured Role {} is not created under RoleSet (namespace index {}): {}",
        roleText,
        def.roleId.namespace_index(),
        causeText);
      continue;
    }
    auto object = roleObject.value();
    (void)object.try_add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{0, roleTypeId}, true);
    if (roleSet)
    {
      (void)roleSet.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, def.roleId, true);
    }
    merge_encrypted_browse_requirement_with_children(addressSpace, object);
    populate_role_instance(addressSpace, object, def);
  }
  if (roleSet)
  {
    auto roleSetNode = roleSet.value();
    prune_unconfigured_role_membership(addressSpace, roleSetNode, roleConfig);
  }
}

}  // namespace ua::server
