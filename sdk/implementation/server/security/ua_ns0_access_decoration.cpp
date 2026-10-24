// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_ns0_access_decoration.h"

#include "ua_access_restriction_type.h"
#include "ua_datatype_id.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"
#include "ua_well_known_role_permissions.h"

#include <algorithm>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::server
{

namespace
{

using xml::nodeset::ImportEngine;
using xml::nodeset::Node;
using xml::nodeset::NodeSet;

using RoleArray = std::vector<RolePermissionType>;
using NodeIdSet = std::unordered_set<NodeId>;

/// The AuditEventType subtypes the NodeSet leaves without RolePermissions, the only undecorated types in NS0
/// whose supertype carries an array. A subtype inherits its supertype's Attribute values unless it overrides
/// them (Part 3 6.3.2), so each takes the array AuditEventType and the other 48 of its 58 subtypes carry:
/// Anonymous Browse and Read, and every permission for SecurityAdmin. A Client receives an Event only if
/// ReceiveEvents is set on its EventType and on its SourceNode (Part 3 Table 37 bit 11), so only
/// SecurityAdmin receives these. OPC 10000-12 8.5.8 also requires that for the three KeyCredential types.
constexpr std::array<ObjectTypeId, 10> undecoratedAuditEventTypes{
  ObjectTypeId::ProgramTransitionAuditEventType,
  ObjectTypeId::TrustListUpdatedAuditEventType,
  ObjectTypeId::CertificateUpdatedAuditEventType,
  ObjectTypeId::ConfigurationUpdatedAuditEventType,
  ObjectTypeId::RoleMappingRuleChangedAuditEventType,
  ObjectTypeId::KeyCredentialAuditEventType,
  ObjectTypeId::KeyCredentialUpdatedAuditEventType,
  ObjectTypeId::KeyCredentialDeletedAuditEventType,
  ObjectTypeId::TrustListUpdateRequestedAuditEventType,
  ObjectTypeId::CertificateUpdateRequestedAuditEventType};

/// The two folders under ServerConfiguration the NodeSet leaves without RolePermissions. Every other Node of
/// the push-management surface carries its own array; these take the one the NodeSet gives
/// ServerConfiguration.
constexpr std::array<ObjectId, 2> undecoratedServerConfigurationFolders{
  ObjectId::AuthorizationServices, ObjectId::KeyCredentialConfiguration};

/// The Nodes a client reads to bootstrap a Session. Kept readable by every well-known Role whatever
/// the NodeSet publishes for them, so no permission configuration can stop a Session activating.
constexpr std::array<VariableId, 3> bootstrapVariables{
  VariableId::Server_ServerArray, VariableId::Server_NamespaceArray, VariableId::Server_ServerStatus};
constexpr std::array<ObjectId, 1> bootstrapObjects{ObjectId::Server};

/// The relation indices the rules walk, built in one pass so no rule re-reads the XML. Both reference
/// directions are indexed: the parser mirrors each parsed reference onto its target, so either end may
/// be the one the NodeSet wrote.
struct Relations
{
  std::unordered_map<NodeId, std::vector<NodeId>> subtypes;  ///< a type -> the types deriving from it
  std::unordered_map<NodeId, std::vector<NodeId>> instances;  ///< a type -> its instances
  std::unordered_map<NodeId, std::vector<NodeId>> children;  ///< a Node -> its hierarchical children
};

bool is_hierarchical(const NodeId& referenceType)
{
  return referenceType == NodeId{ReferenceTypeId::HasComponent} ||
         referenceType == NodeId{ReferenceTypeId::HasProperty} ||
         referenceType == NodeId{ReferenceTypeId::HasOrderedComponent};
}

Relations index_relations(const NodeSet& ns0)
{
  Relations relations;
  for (const auto& [nodeId, node] : ns0.nodes())
  {
    if (!node)
    {
      continue;
    }
    for (const auto& reference : node->references())
    {
      // Normalise to the forward direction so both ends of a mirrored reference index identically.
      NodeId source = reference.targetId;
      NodeId target = nodeId;
      if (reference.isForward)
      {
        source = nodeId;
        target = reference.targetId;
      }
      if (reference.typeId == NodeId{ReferenceTypeId::HasSubtype})
      {
        relations.subtypes[source].push_back(target);
      }
      else if (reference.typeId == NodeId{ReferenceTypeId::HasTypeDefinition})
      {
        relations.instances[target].push_back(source);
      }
      else if (is_hierarchical(reference.typeId))
      {
        relations.children[source].push_back(target);
      }
    }
  }
  return relations;
}

/// Every Node reachable from `seeds` by descending subtypes, crossing from a type to its instances, and
/// descending hierarchical children.
///
/// Never climbs to a supertype or a parent - climbing from any seed would eventually absorb all of NS0.
/// Does not follow `HasEncoding` or `HasDescription`: those reach a DataType's schema metadata, which a
/// client legitimately reads to decode values.
NodeIdSet reachable_surface(const NodeSet& ns0, const Relations& relations, std::span<const NodeId> seeds)
{
  NodeIdSet members{seeds.begin(), seeds.end()};
  std::vector<NodeId> frontier{seeds.begin(), seeds.end()};
  while (!frontier.empty())
  {
    const NodeId current = frontier.back();
    frontier.pop_back();
    for (const auto* edges : {&relations.subtypes, &relations.instances, &relations.children})
    {
      const auto found = edges->find(current);
      if (found == edges->end())
      {
        continue;
      }
      for (const auto& next : found->second)
      {
        if (ns0.nodes().count(next) != 0 && members.insert(next).second)
        {
          frontier.push_back(next);
        }
      }
    }
  }
  return members;
}

/// The RoleType declaration and every Property/Method declaration below it. Unlike
/// `reachable_surface`, this does not cross into RoleType instances: those carry their own published
/// policies and must not be overwritten by the SDK's abstract-type baseline.
NodeIdSet role_type_declaration_surface(const NodeSet& ns0, const Relations& relations)
{
  const NodeId roleType{ObjectTypeId::RoleType};
  NodeIdSet members{roleType};
  std::vector<NodeId> frontier{roleType};
  while (!frontier.empty())
  {
    const NodeId current = frontier.back();
    frontier.pop_back();
    const auto children = relations.children.find(current);
    if (children == relations.children.end())
    {
      continue;
    }
    for (const auto& child : children->second)
    {
      if (ns0.nodes().contains(child) && members.insert(child).second)
      {
        frontier.push_back(child);
      }
    }
  }
  return members;
}

/// The arrays the NodeSet declares, read once. `HasNoPermissions` counts as decorated: it declares an
/// explicit empty set, which is a statement and not an absence.
struct DeclaredDecoration
{
  std::unordered_map<NodeId, RoleArray> arrays;
  NodeIdSet decorated;
  /// The AccessRestrictions the NodeSet declares, by Node. Read once for the same reason as the arrays.
  std::unordered_map<NodeId, AccessRestrictionType> restrictions;
};

DeclaredDecoration read_declared_decoration(const NodeSet& ns0)
{
  DeclaredDecoration declared;
  for (const auto& [nodeId, node] : ns0.nodes())
  {
    if (!node)
    {
      continue;
    }
    if (const auto restrictions = node->access_restrictions())
    {
      declared.restrictions.emplace(nodeId, *restrictions);
    }
    auto array = node->role_permissions();
    if (!array.empty())
    {
      declared.decorated.insert(nodeId);
      declared.arrays.emplace(nodeId, std::move(array));
    }
    else if (node->has_no_permissions())
    {
      declared.decorated.insert(nodeId);
    }
  }
  return declared;
}

std::optional<RoleArray> effective_role_permissions(const NodeId& nodeId, const DeclaredDecoration& declared,
  const ImportEngine::AccessDecorationMap& decoration)
{
  const auto authored = decoration.find(nodeId);
  if (authored != decoration.end())
  {
    const auto& rolePermissions = authored->second.rolePermissions;
    if (rolePermissions)
    {
      return rolePermissions.value();
    }
  }
  const auto published = declared.arrays.find(nodeId);
  if (published != declared.arrays.end())
  {
    return published->second;
  }
  if (declared.decorated.contains(nodeId))
  {
    return RoleArray{};  // HasNoPermissions is an explicit deny-all policy, not an absent Attribute.
  }
  return std::nullopt;
}

PermissionType all_permissions()
{
  return PermissionType{PermissionType::Bit::Browse,
    PermissionType::Bit::ReadRolePermissions,
    PermissionType::Bit::WriteAttribute,
    PermissionType::Bit::WriteRolePermissions,
    PermissionType::Bit::WriteHistorizing,
    PermissionType::Bit::Read,
    PermissionType::Bit::Write,
    PermissionType::Bit::ReadHistory,
    PermissionType::Bit::InsertHistory,
    PermissionType::Bit::ModifyHistory,
    PermissionType::Bit::DeleteHistory,
    PermissionType::Bit::ReceiveEvents,
    PermissionType::Bit::Call,
    PermissionType::Bit::AddReference,
    PermissionType::Bit::RemoveReference,
    PermissionType::Bit::DeleteNode,
    PermissionType::Bit::AddNode};
}

/// A declared array with Browse ORed into every well-known Role, and nothing else widened. Used for an
/// InstanceDeclaration of a restricted surface: generic Clients must be able to resolve the type's
/// members (Part 3 4.5.1, "the TypeDefinitionNodes shall be provided for generic Clients"), while the
/// instances created from the declaration - which inherit its RolePermissions - still refuse Read to
/// every Role the declared array does not grant it.
RoleArray browse_widened_array(const RoleArray& declared)
{
  RoleArray array = declared;
  for (const auto role : well_known_roles())
  {
    const NodeId roleId = well_known_role_node_id(role);
    const auto found = std::find_if(array.begin(),
      array.end(),
      [&roleId](const RolePermissionType& entry) { return entry.role_id() == roleId; });
    if (found != array.end())
    {
      found->permissions().set(PermissionType::Bit::Browse);
      continue;
    }
    RolePermissionType entry;
    entry.role_id() = roleId;
    entry.permissions() = PermissionType{PermissionType::Bit::Browse};
    array.push_back(std::move(entry));
  }
  return array;
}

/// Where a Node of a restricted surface sits in the type model.
enum class SurfacePlace
{
  TypeDefinition,  ///< an ObjectType, VariableType, DataType or ReferenceType
  InstanceDeclaration,  ///< a member of a type, identified by its forward HasModellingRule
  Instance,  ///< everything else: a Node carrying live data
};

SurfacePlace surface_place(const NodeSet& ns0, const NodeId& nodeId)
{
  const auto found = ns0.nodes().find(nodeId);
  if (found == ns0.nodes().end() || !found->second)
  {
    return SurfacePlace::Instance;
  }
  switch (found->second->node_class())
  {
  case NodeClass::ObjectType:
  case NodeClass::VariableType:
  case NodeClass::DataType:
  case NodeClass::ReferenceType:
    return SurfacePlace::TypeDefinition;
  default:
    break;
  }
  const NodeId hasModellingRule{ReferenceTypeId::HasModellingRule};
  for (const auto& reference : found->second->references())
  {
    if (reference.isForward && reference.typeId == hasModellingRule)
    {
      return SurfacePlace::InstanceDeclaration;
    }
  }
  return SurfacePlace::Instance;
}

RoleArray role_management_admin_permissions()
{
  // Part 3 Table 2 / Part 18: Role membership and RolePermissions are security settings, so the full
  // set (Call on AddIdentity/RemoveIdentity, WriteRolePermissions, ...) belongs to SecurityAdmin
  // alone, exactly as the NodeSet grants it on the well-known Roles. ConfigureAdmin may browse and
  // read the Role objects (its own configuration surface) but may not change who holds a Role.
  // AddRole copies this policy onto every Role it creates.
  RoleArray permissions;
  permissions.reserve(2);
  RolePermissionType securityAdmin;
  securityAdmin.role_id() = well_known_role_node_id(WellKnownRole::SecurityAdmin);
  securityAdmin.permissions() = all_permissions();
  permissions.push_back(std::move(securityAdmin));
  RolePermissionType configureAdmin;
  configureAdmin.role_id() = well_known_role_node_id(WellKnownRole::ConfigureAdmin);
  configureAdmin.permissions() = PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  permissions.push_back(std::move(configureAdmin));
  return permissions;
}

/// Supplies the Part-18 RoleType administrative baseline and RoleSet Method encryption requirements.
/// Authoring the policy before import makes it atomic with node creation and lets custom instances
/// inherit the ordinary Attributes.
void author_role_management_baseline(
  const NodeSet& ns0, const Relations& relations, ImportEngine::AccessDecorationMap& decoration)
{
  const NodeId roleType{ObjectTypeId::RoleType};
  if (!ns0.nodes().contains(roleType))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("RoleTypeMissing",
        "The standard NodeSet does not contain the required RoleType declaration",
        "Ns0AccessDecoration")
        .context(ContextKeys::nodeId, roleType.as_definition())};
  }

  const auto permissions = role_management_admin_permissions();
  for (const auto& nodeId : role_type_declaration_surface(ns0, relations))
  {
    const auto found = ns0.nodes().find(nodeId);
    if (found == ns0.nodes().end() || !found->second)
    {
      continue;
    }
    decoration[nodeId].rolePermissions = permissions;
    auto restrictions = found->second->access_restrictions().value_or(AccessRestrictionType{});
    restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
    decoration[nodeId].accessRestrictions = restrictions;
  }

  // Part 18 sections 4.2.2 and 4.2.3 require encrypted invocation. Preserve the published permissions
  // and restriction bits on both declarations and standard instances. Part 3 section 8.56 makes
  // ApplyRestrictionsToBrowse independent; these invocation clauses do not require adding it.
  for (const auto method : {MethodId::RoleSetType_AddRole,
         MethodId::RoleSetType_RemoveRole,
         MethodId::Server_ServerCapabilities_RoleSet_AddRole,
         MethodId::Server_ServerCapabilities_RoleSet_RemoveRole})
  {
    const NodeId methodId{method};
    const auto found = ns0.nodes().find(methodId);
    if (found == ns0.nodes().end() || !found->second)
    {
      continue;
    }
    auto restrictions = found->second->access_restrictions().value_or(AccessRestrictionType{});
    restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
    decoration[methodId].accessRestrictions = restrictions;
  }
}

/// Closes any remaining silence on the standard Role-management surface without replacing policy the
/// NodeSet did publish. In particular the RoleSetType placeholder is a RoleType instance but carries no
/// access Attributes of its own; leaving it to the namespace default would make the abstract management
/// surface broader than its concrete Role Objects.
void author_missing_role_management_policy(const NodeSet& ns0, const Relations& relations,
  const DeclaredDecoration& declared, ImportEngine::AccessDecorationMap& decoration)
{
  const std::array<NodeId, 2> roots{
    NodeId{ObjectTypeId::RoleType}, NodeId{ObjectId::Server_ServerCapabilities_RoleSet}};
  const auto permissions = role_management_admin_permissions();
  for (const auto& nodeId : reachable_surface(ns0, relations, roots))
  {
    if (effective_role_permissions(nodeId, declared, decoration).has_value())
    {
      continue;
    }
    const auto found = ns0.nodes().find(nodeId);
    if (found == ns0.nodes().end() || !found->second)
    {
      continue;
    }
    // An undecorated InstanceDeclaration here is the RoleSetType `<RoleName>` placeholder and its
    // members. Generic Clients resolve a type's members by browse path (Part 3 6.4.2; CTT Base Info
    // Base Types 003), so every Role may Browse it; nothing else is widened. Role Objects are
    // instantiated from RoleType, whose declarations keep the administrative baseline, never from
    // this placeholder.
    decoration[nodeId].rolePermissions = surface_place(ns0, nodeId) == SurfacePlace::InstanceDeclaration
                                           ? browse_widened_array(permissions)
                                           : permissions;
    auto restrictions = found->second->access_restrictions().value_or(AccessRestrictionType{});
    restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
    decoration[nodeId].accessRestrictions = restrictions;
  }
}

/// Extends the complete Part-18 Role-management surface before import. This is configuration-time
/// authoring only: the resulting ordinary RolePermissions are the sole runtime authority.
void author_role_management_access(const NodeSet& ns0, const Relations& relations,
  const DeclaredDecoration& declared, std::span<const NodeId> roleIds,
  ImportEngine::AccessDecorationMap& decoration)
{
  if (roleIds.empty())
  {
    return;
  }

  const std::array<NodeId, 2> roots{
    NodeId{ObjectTypeId::RoleType}, NodeId{ObjectId::Server_ServerCapabilities_RoleSet}};
  for (const auto& root : roots)
  {
    if (!ns0.nodes().contains(root))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("RoleManagementSurfaceRootMissing",
          "A required Role-management surface root is absent from the standard NodeSet",
          "Ns0AccessDecoration")
          .context(ContextKeys::nodeId, root.as_definition())};
    }
  }

  const auto members = reachable_surface(ns0, relations, roots);
  std::vector<NodeId> orderedMembers{members.begin(), members.end()};
  std::sort(orderedMembers.begin(), orderedMembers.end());

  struct Stage
  {
    NodeId nodeId;
    RoleArray permissions;
  };

  std::vector<Stage> stages;
  stages.reserve(orderedMembers.size());
  const NodeId securityAdminRole{ObjectId::WellKnownRole_SecurityAdmin};
  for (const auto& nodeId : orderedMembers)
  {
    auto permissions = effective_role_permissions(nodeId, declared, decoration);
    if (!permissions)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("RoleManagementSurfacePolicyMissing",
          "A Role-management node has no RolePermissions policy to extend",
          "Ns0AccessDecoration")
          .context(ContextKeys::nodeId, nodeId.as_definition())};
    }
    const auto baseline = std::find_if(permissions->begin(),
      permissions->end(),
      [&securityAdminRole](const RolePermissionType& entry) { return entry.role_id() == securityAdminRole; });
    if (baseline == permissions->end())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("RoleManagementSurfaceBaselineMissing",
          "A Role-management node has no SecurityAdmin policy from which to derive its exact grant",
          "Ns0AccessDecoration")
          .context(ContextKeys::nodeId, nodeId.as_definition())};
    }

    const auto baselinePermissions = baseline->permissions();
    const auto baselineBits = baselinePermissions.as_underlying_type();
    for (const auto& roleId : roleIds)
    {
      const auto existing = std::find_if(permissions->begin(),
        permissions->end(),
        [&roleId](const RolePermissionType& entry) { return entry.role_id() == roleId; });
      if (existing == permissions->end())
      {
        RolePermissionType grant;
        grant.role_id() = roleId;
        grant.permissions() = baselinePermissions;
        permissions->push_back(std::move(grant));
      }
      else
      {
        existing->permissions().from_underlying_type(
          existing->permissions().as_underlying_type() | baselineBits);
      }
    }
    stages.push_back(Stage{nodeId, std::move(*permissions)});
  }

  for (auto& stage : stages)
  {
    decoration[stage.nodeId].rolePermissions = std::move(stage.permissions);
  }
}

/// What the NodeSet publishes for a bootstrap Node, with Browse and Read ORed into every well-known
/// Role - the ones it names as well as the ones it omits. A named Role can lack Read (`i=2253` grants
/// Anonymous Browse, ReceiveEvents and Call), so skipping named Roles would leave the lockout in place.
RoleArray bootstrap_array(const RoleArray& declared)
{
  RoleArray array = declared;
  for (const auto role : well_known_roles())
  {
    const NodeId roleId = well_known_role_node_id(role);
    const auto found = std::find_if(array.begin(),
      array.end(),
      [&roleId](const RolePermissionType& entry) { return entry.role_id() == roleId; });
    if (found != array.end())
    {
      found->permissions().set(PermissionType::Bit::Browse);
      found->permissions().set(PermissionType::Bit::Read);
      continue;
    }
    RolePermissionType entry;
    entry.role_id() = roleId;
    entry.permissions() = PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read};
    array.push_back(std::move(entry));
  }
  return array;
}

/// SecurityAdmin's general mask, widened by the two read bits. The array used wherever a `shall`
/// restricts a Node to administrators.
RoleArray administrators_only_array()
{
  RolePermissionType entry;
  entry.role_id() = well_known_role_node_id(WellKnownRole::SecurityAdmin);
  entry.permissions() = well_known_role_permissions(WellKnownRole::SecurityAdmin);
  entry.permissions().set(PermissionType::Bit::Read);
  entry.permissions().set(PermissionType::Bit::ReadRolePermissions);
  return RoleArray{std::move(entry)};
}

RolePermissionType role_entry(WellKnownRole role, PermissionType permissions)
{
  RolePermissionType entry;
  entry.role_id() = well_known_role_node_id(role);
  entry.permissions() = permissions;
  return entry;
}

/// The array the NodeSet gives SessionSecurityDiagnosticsArray under the Server Object, the one Node of the
/// security-diagnostics surface it decorates: SecurityAdmin alone, with every permission except
/// ReceiveEvents, Call and AddNode.
RoleArray security_diagnostics_array()
{
  using Bit = PermissionType::Bit;
  return RoleArray{role_entry(WellKnownRole::SecurityAdmin,
    PermissionType{Bit::Browse,
      Bit::ReadRolePermissions,
      Bit::WriteAttribute,
      Bit::WriteRolePermissions,
      Bit::WriteHistorizing,
      Bit::Read,
      Bit::Write,
      Bit::ReadHistory,
      Bit::InsertHistory,
      Bit::ModifyHistory,
      Bit::DeleteHistory,
      Bit::AddReference,
      Bit::RemoveReference,
      Bit::DeleteNode})};
}

/// The AccessRestrictions the NodeSet gives the same Node: signing and encryption required.
AccessRestrictionType security_diagnostics_restrictions()
{
  AccessRestrictionType restrictions;
  restrictions.set(AccessRestrictionType::Bit::SigningRequired);
  restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
  return restrictions;
}

/// The array the NodeSet gives AuditEventType and 48 of its 58 subtypes.
RoleArray audit_event_type_array()
{
  using Bit = PermissionType::Bit;
  return RoleArray{role_entry(WellKnownRole::Anonymous, PermissionType{Bit::Browse, Bit::Read}),
    role_entry(WellKnownRole::SecurityAdmin, all_permissions())};
}

/// The array the NodeSet gives ServerConfiguration: Anonymous may Browse, and ConfigureAdmin and
/// SecurityAdmin have every permission except WriteHistorizing, Read, Write and AddNode.
RoleArray server_configuration_array()
{
  using Bit = PermissionType::Bit;
  const PermissionType administrator{Bit::Browse,
    Bit::ReadRolePermissions,
    Bit::WriteAttribute,
    Bit::WriteRolePermissions,
    Bit::ReadHistory,
    Bit::InsertHistory,
    Bit::ModifyHistory,
    Bit::DeleteHistory,
    Bit::ReceiveEvents,
    Bit::Call,
    Bit::AddReference,
    Bit::RemoveReference,
    Bit::DeleteNode};
  return RoleArray{role_entry(WellKnownRole::Anonymous, PermissionType{Bit::Browse}),
    role_entry(WellKnownRole::ConfigureAdmin, administrator),
    role_entry(WellKnownRole::SecurityAdmin, administrator)};
}

}  // namespace

ImportEngine::AccessDecorationMap compute_ns0_access_decoration(
  const NodeSet& ns0, std::span<const NodeId> roleManagementAccessRoles)
{
  const Relations relations = index_relations(ns0);
  const DeclaredDecoration declared = read_declared_decoration(ns0);

  ImportEngine::AccessDecorationMap decoration;

  const auto stamp = [&decoration](const NodeId& nodeId, RoleArray array)
  {
    decoration[nodeId].rolePermissions = std::move(array);
  };

  // When a request is checked, a Node without RolePermissions falls back only to its namespace's
  // DefaultRolePermissions (Part 3 5.2.9 and 4.8.3), never to a parent Node or a supertype. Each rule below
  // names the Nodes it covers and writes out the array it gives them; a Node the NodeSet decorates keeps its
  // own array.

  // Security diagnostics "shall be restricted to authorized users, such as users who have the SecurityAdmin
  // role" (OPC 10000-5 7.16) and "shall only be accessible by authorised users" (12.12). The NodeSet
  // decorates one Node of that surface, SessionSecurityDiagnosticsArray under the Server Object. The rest are
  // members of the same types, and each Session's own diagnostics are instantiated from those members, which
  // takes their RolePermissions and AccessRestrictions as initial values (Part 3 6.4.2). The restriction is
  // on the information, so the array depends on where a Node sits:
  // - an Instance carries live data and takes the restricted array;
  // - an InstanceDeclaration holds no data but is what each Session's instance copies, so it keeps the array
  //   and gains only Browse: generic Clients resolve a type's Mandatory members by browse path (Part 3 6.4.2;
  //   Part 5 Tables 12 and 13), and every instance still refuses Read;
  // - a TypeDefinition holds no data and is never copied from, so it takes the namespace default.
  const std::array<NodeId, 3> securitySeeds{NodeId{VariableTypeId::SessionSecurityDiagnosticsArrayType},
    NodeId{VariableTypeId::SessionSecurityDiagnosticsType},
    NodeId{DataTypeId::SessionSecurityDiagnosticsDataType}};
  const auto securitySurface = reachable_surface(ns0, relations, securitySeeds);
  const RoleArray securityArray = security_diagnostics_array();
  const RoleArray securityDeclarationArray = browse_widened_array(securityArray);
  for (const auto& nodeId : securitySurface)
  {
    if (declared.decorated.count(nodeId) != 0)
    {
      continue;
    }
    switch (surface_place(ns0, nodeId))
    {
    case SurfacePlace::TypeDefinition:
      break;
    case SurfacePlace::InstanceDeclaration:
      stamp(nodeId, securityDeclarationArray);
      break;
    case SurfacePlace::Instance:
      stamp(nodeId, securityArray);
      break;
    }
  }
  // The same Node declares AccessRestrictions (SigningRequired | EncryptionRequired): security diagnostics
  // carry client identities and must not cross an unencrypted channel. The Variable and Object Nodes of the
  // surface (the instance declarations, hence every per-session instance created from them) take them when
  // they declare none. The VariableTypes and the DataType are left alone: type discovery and
  // DataTypeDefinition reads disclose no session data and must keep working on any channel.
  const AccessRestrictionType securityRestrictions = security_diagnostics_restrictions();
  for (const auto& nodeId : securitySurface)
  {
    const auto found = ns0.nodes().find(nodeId);
    if (found == ns0.nodes().end() || !found->second)
    {
      continue;
    }
    const auto nodeClass = found->second->node_class();
    if (nodeClass != NodeClass::Variable && nodeClass != NodeClass::Object)
    {
      continue;
    }
    if (declared.restrictions.contains(nodeId))
    {
      continue;
    }
    decoration[nodeId].accessRestrictions = securityRestrictions;
  }

  // Part 3 5.2.9 restricts DefaultRolePermissions to administrators; the NodeSet decorates it with
  // nothing, so the restriction has to be stamped on.
  stamp(NodeId{VariableId::OPCUANamespaceMetadata_DefaultRolePermissions}, administrators_only_array());

  // Two security surfaces where the NodeSet leaves named Nodes undecorated: the audit EventTypes and the
  // ServerConfiguration folders.
  const auto stampUndecorated = [&](const NodeId& nodeId, const RoleArray& array)
  {
    if (ns0.nodes().contains(nodeId) && declared.decorated.count(nodeId) == 0)
    {
      stamp(nodeId, array);
    }
  };
  const RoleArray auditArray = audit_event_type_array();
  for (const auto type : undecoratedAuditEventTypes)
  {
    stampUndecorated(NodeId{type}, auditArray);
  }
  const RoleArray serverConfigurationArray = server_configuration_array();
  for (const auto folder : undecoratedServerConfigurationFolders)
  {
    stampUndecorated(NodeId{folder}, serverConfigurationArray);
  }

  // Applied last: a floor rather than a posture, so no earlier rule may narrow it.
  const auto bootstrapFloor = [&](const NodeId& nodeId)
  {
    const auto array = declared.arrays.find(nodeId);
    RoleArray declaredArray;
    if (array != declared.arrays.end())
      declaredArray = array->second;
    stamp(nodeId, bootstrap_array(declaredArray));
  };
  for (const auto variable : bootstrapVariables)
  {
    bootstrapFloor(NodeId{variable});
  }
  for (const auto object : bootstrapObjects)
  {
    bootstrapFloor(NodeId{object});
  }

  author_role_management_baseline(ns0, relations, decoration);
  author_missing_role_management_policy(ns0, relations, declared, decoration);
  author_role_management_access(ns0, relations, declared, roleManagementAccessRoles, decoration);

  return decoration;
}

}  // namespace ua::server
