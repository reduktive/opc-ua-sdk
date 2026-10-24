// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_WRITE_TYPE_FACTS_H
#define UA_WRITE_TYPE_FACTS_H

#include "ua_address_space.h"
#include "ua_browse_direction.h"
#include "ua_built_in_type_id.h"
#include "ua_data_type_definition.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_subtype_facts.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace ua::server
{

/// What the Write service's type checks need of a declared DataType D (SVR-ATTR-WRITE-008, -025).
struct DataTypeFacts
{
  /// D was found as a DataType Node. When false, no enum, lexical-form or built-in base check applies.
  bool found{false};

  /// The Node's own NodeId, which may differ from D when D is an alias.
  NodeId ownId;

  /// The Node's DataTypeDefinition; null when it has none or it cannot be read.
  shared_ptr<const DataTypeDefinition> definition;

  /// The built-in base of D: the first type of its supertype chain with a built-in mapping (Structure for an
  /// ExtensionObject). `nullopt` when the chain has none, the walk failed, or D is a namespace 0 type up to
  /// 28, whose check needs no walk.
  std::optional<BuiltInTypeId> base;
};

/// The DataType facts of a Write request (NR-24 5a), with one namespace call per namespace per round: one
/// lookup of the declared types, then per level of their hierarchies one `read_references_async` of the
/// inverse HasSubtype References and one lookup of the supertypes that are not built-in. Nothing is cached
/// past the request.
class WriteTypeFacts
{
public:
  /// Whether the Write service needs no facts of @p dataType: null, or a namespace 0 numeric id from 1 to 28
  /// (the built-in types and Number, Integer, UInteger), which the service checks by its id alone.
  static bool needs_no_lookup(const NodeId& dataType) noexcept;

  /// The facts of each type of @p declared, keyed by the type.
  static void resolve_declared_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<NodeId> declared, std::function<void(std::map<NodeId, DataTypeFacts>)> done) noexcept;

  /// What an encoding Node says of the DataType it encodes.
  struct EncodingFacts
  {
    /// The encoding Node was found.
    bool found{false};
    /// The local target of its inverse HasEncoding Reference; `nullopt` when it has none.
    std::optional<NodeId> dataType;
  };

  /// The facts of each encoding Node of @p encodings.
  static void resolve_encodings_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<NodeId> encodings, std::function<void(std::vector<EncodingFacts>)> done) noexcept;

  /// For each (written W, declared D) of @p questions, whether W is a subtype of D: D is in W's supertype
  /// chain (@ref SubtypeFacts::resolve_async). A lookup or a read of References that fails, a remote
  /// supertype, a chain that reaches Structure or a type with a built-in mapping, and a chain deeper than 32
  /// are `false`.
  static void resolve_subtypes_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<std::pair<NodeId, NodeId>> questions, std::function<void(std::vector<bool>)> done) noexcept;
};

}  // namespace ua::server

#endif  // !UA_WRITE_TYPE_FACTS_H
