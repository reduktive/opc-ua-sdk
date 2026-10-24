// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBTYPE_FACTS_H
#define UA_SUBTYPE_FACTS_H

#include "ua_address_space.h"
#include "ua_browse_direction.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_reference.h"
#include "ua_request_info.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace ua
{

/// The deepest DataType hierarchy a walk of supertypes climbs: the Write service's checks (NR-24 5a) and the
/// address space's check of a HasSubtype between VariableTypes (NR-52).
inline constexpr std::size_t maxTypeWalkDepth = 32;

/// The batched namespace calls the services make for a request (NR-23): each a call of a namespace's batched
/// member per namespace, through @ref ua::detail::NamespaceRoute and so with its guards (a throw, a second
/// completion or an answer of another size answer the call's items `Bad_InternalError`). Each completion is
/// called once, with one answer per item in item order, and must not throw.
namespace namespace_calls
{

/// Calls a batched member for items split by namespace: item `k` belongs to namespace `indexAt[k]` of
/// @p addressSpace, and @p invoke is called per namespace with the positions of its items, at most @p limit
/// at a time. An item of an unregistered namespace is `Bad_NodeIdUnknown`. A supplied
/// @p requiredAddressSpace is checked before each unissued chunk; omitted, default route diagnostics apply.
template<typename Answer>
void by_namespace(const AddressSpace& addressSpace, std::span<const uint16_t> indexAt,
  std::optional<uint32_t> limit, typename ua::detail::NamespaceRoute<Answer>::Invoke invoke,
  std::function<void(std::vector<Answer>)> done,
  std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept
{
  try
  {
    const auto& namespaces = addressSpace.namespace_array();
    auto split = ua::detail::split_by_namespace<Answer>(
      indexAt, [&namespaces](uint16_t index) { return namespaces.get_namespace(index); });
    ua::detail::NamespaceRoute<Answer>::run(std::move(split.answers),
      std::move(split.parts),
      limit,
      std::move(invoke),
      std::move(done),
      std::move(requiredAddressSpace));
  }
  catch (...)
  {
    std::vector<Answer> failed(indexAt.size(), Answer{exception_to_status_code(std::current_exception())});
    done(std::move(failed));
  }
}

/// Looks up @p nodeIds for @p request: one lookup per namespace
/// (`ua::detail::NodeAccessorRoute::find_nodes`).
void find_nodes(const AddressSpace& addressSpace, const RequestInfo& request, std::vector<NodeId> nodeIds,
  std::function<void(std::vector<NodeAccessorResult>)> done) noexcept;

/// One Node's References of one type, or of several, and one direction, as @ref read_references reads them.
struct ReferenceRead
{
  NodeAccessor node;
  NodeId nodeId;
  BrowseDirection direction{BrowseDirection::Both};
  NodeId referenceType;
  /// Further ReferenceTypes read in the same query, each hinted and kept as @ref referenceType is.
  std::vector<NodeId> otherTypes{};
  /// Whether a Reference whose type may be a subtype of a type read is kept too: one of a namespace-0 type
  /// that `reference_type_may_match_hint` places under a type read, and one of any type that function cannot
  /// place, which the caller decides. Off by default: only References of exactly the types read are kept.
  bool subtypes{false};
};

/// Every Reference of each Node of @p reads: one `read_references_async` per namespace per round, a round for
/// each resume token a namespace answers. The types and direction are passed as the hint and applied to the
/// answer, which keeps only References of exactly those types (or, with `subtypes`, of a type that may be a
/// subtype of one) and in that direction, in the order given. Each
/// token answered is held with the namespace that issued it and released through it if the reading stops
/// before passing it back. A read whose namespace answers `ua::detail::maxEmptyReferencePages` pages in a row
/// with a token and no References fails `Bad_InternalError` (`NamespacePagingDidNotEnd`), its last token
/// released; an answer that holds a Reference starts the count again (DL-67 (8)).
void read_references(const AddressSpace& addressSpace, const RequestInfo& request,
  std::vector<ReferenceRead> reads, std::optional<uint32_t> limit,
  std::function<void(std::vector<Result<std::vector<Reference>>>)> done) noexcept;

}  // namespace namespace_calls

/// How a supertype walk ended for one chain: decided by the check (with its value), at a type without a
/// supertype, or failed (a read or a lookup failed, a remote supertype, the depth bound reached).
struct SupertypeWalkEnd
{
  enum class How
  {
    Decided,
    NoSuper,
    Failed
  } how{How::Failed};
  int value{0};
  /// Why a `Failed` chain failed, with its ErrorDetail: the status the lookup or the read of References
  /// answered (`Bad_NodeIdUnknown` for a supertype that does not exist), or the bound or remote supertype
  /// that stopped it. Good for the other ends.
  StatusCode failure;
};

/// Decides a chain at a type it reached, or `nullopt` to continue to the type's supertype.
using SupertypeWalkCheck = std::function<std::optional<int>(std::size_t chain, const NodeId& type)>;

/// Walks the supertype chains starting at @p starts (each a Node and its NodeId) together, a level per round:
/// per level one `read_references_async` per namespace of the inverse HasSubtype References of the chains not
/// yet decided, and one lookup per namespace of their supertypes (DL-62 (9)). Each chain is decided by
/// @p check at each type it reaches, the start included; a chain that reaches a type that is not a type Node,
/// or one without a supertype, ends `NoSuper`; one that has climbed @p maxDepth levels without being decided
/// ends `Failed`. @p done receives one end per start, in start order, once.
void walk_supertypes(AddressSpace addressSpace, RequestInfo request,
  std::vector<std::pair<NodeAccessor, NodeId>> starts, std::size_t maxDepth, SupertypeWalkCheck check,
  std::function<void(std::vector<SupertypeWalkEnd>)> done);

/// Whether types are subtypes of others, for one request (NR-24 5a, DL-66 (6)): the Write service's DataType
/// checks and TranslateBrowsePaths' ReferenceType checks ask it, many questions at once.
class SubtypeFacts
{
public:
  /// Where a walk stops without an answer of true.
  struct Bounds
  {
    /// The most supertype levels a chain climbs; a chain deeper than this answers false.
    std::size_t maxDepth{0};
    /// Whether a chain at a type has passed every type it could be asked about, answering false there
    /// rather than climbing on; null when no type does.
    std::function<bool(const NodeId& type)> passed;
  };

  /// For each (W, D) of @p questions, whether W is D or a subtype of D: D is in W's supertype chain. The
  /// written types are looked up with one call per namespace, then their chains walked together
  /// (@ref walk_supertypes). A lookup or a read of References that fails, a remote supertype, a chain that
  /// reaches a type @p bounds says has passed, and one deeper than its bound are `false`. @p done receives
  /// one answer per question, in question order, once; an empty vector when the walk could not start.
  static void resolve_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<std::pair<NodeId, NodeId>> questions, Bounds bounds,
    std::function<void(std::vector<bool>)> done) noexcept;

  /// As @ref resolve_async, but a question the walk could not decide answers why: a W that does not exist, a
  /// remote supertype, a chain past @p bounds and one deeper than its bound are still `false`, and any other
  /// failed lookup or read of References, or an address space gone, answers its failure (an Uncertain answer
  /// as `ua::detail::lookup_failure` gives it). @p done receives one answer per question, in question order,
  /// once; an empty vector when the walk could not start.
  static void decide_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<std::pair<NodeId, NodeId>> questions, Bounds bounds,
    std::function<void(std::vector<BoolResult>)> done) noexcept;
};

}  // namespace ua

#endif  // !UA_SUBTYPE_FACTS_H
