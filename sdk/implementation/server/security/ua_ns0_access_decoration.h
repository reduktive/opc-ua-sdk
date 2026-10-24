// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NS0_ACCESS_DECORATION_H
#define UA_NS0_ACCESS_DECORATION_H

#include "ua_nodeset_import_engine.h"

#include <span>

namespace ua::xml::nodeset
{
class NodeSet;
}

namespace ua::server
{

/// The access-control decoration this SDK applies to the shipped OPC UA NodeSet, keyed by NodeId and
/// applied by the import that creates NS0.
///
/// The NodeSet decorates a tenth of its Nodes and no DataType, ReferenceType or VariableType at all, so
/// a server enforcing it as published needs a namespace default to be usable - and supplying one then
/// creates two problems the NodeSet cannot solve for itself. It cannot reach a Value, because Part 3
/// Table 37 bit 0 covers every Attribute except the Value, so the metadata a client decodes the model
/// with stays unreadable. And because a non-empty array replaces the default for every Role rather than
/// merging with it (Part 3 5.2.9), an undecorated Node beside a decorated one takes the wider default -
/// which opens the Part 18 4.4.1 Role surface and the Part 5 12.12 security diagnostics.
///
/// The returned map is the difference: what the import shall write instead of what the NodeSet declares.
/// A third group of stamps is policy rather than conformance - the Nodes a client reads to bootstrap
/// are kept readable by every well-known Role, because a server in which six of the nine cannot
/// activate a Session is not usable. The per-Role masks are defined by the SDK's well-known-role
/// permission policy.
///
/// Pure: it reads the parsed NodeSet and touches no address space.
///
/// @param ns0 The parsed OPC UA NodeSet, after `Parser::parse` has mirrored its references.
/// @param roleManagementAccessRoles Registered Roles whose ordinary policy shall mirror each
///                                  Role-management node's SecurityAdmin grant. Empty leaves the
///                                  shipped surface unchanged.
/// @return One entry per Node whose decoration the import shall override. Nodes absent from the map are
///         imported exactly as the NodeSet declares them.
xml::nodeset::ImportEngine::AccessDecorationMap compute_ns0_access_decoration(
  const xml::nodeset::NodeSet& ns0, std::span<const NodeId> roleManagementAccessRoles = {});

}  // namespace ua::server

#endif  // UA_NS0_ACCESS_DECORATION_H
