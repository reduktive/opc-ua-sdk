// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_type_loader.h"
#include "ua_self_owning_operation.h"
#include "ua_type_model_access.h"
#include "ua_resource_budgets.h"
#include "ua_dynamic_type_registry.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_browse_result_mask.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_enum_definition.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_expanded_node_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_browse_description.h"
#include "ua_browse_result.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_structure_definition.h"
#include "ua_to_result.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <fmt/format.h>

#include <future>
#include <string>
#include <string_view>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace ua::dynamic_types
{

namespace
{

// Upper bound on the type hierarchy discovered from a (remote, untrusted) server during a dynamic
// type load. The BFS over HasSubtype builds its node list entirely from server-returned references,
// so a malicious/buggy server - or a cyclic HasSubtype graph - could inflate it without limit, which
// then drives O(N) read/browse batch allocations in read_all_type_info. Real type hierarchies are at
// most a few thousand nodes (NS0 plus companion specs), so this cap is generous headroom while still
// bounding the allocation against attacker input. Exceeding it fails the load (BadEncodingLimitsExceeded).
constexpr size_t maxDiscoveredTypes = 100000;

/// The status the loader refuses a model answer with that is not Good. The loader acts on every answer it
/// receives (the walk decides which types exist and what is registered), so an Uncertain answer, with or
/// without data, becomes `Bad_InternalError` with an ErrorDetail coded @p code whose cause is the Uncertain
/// code with its own detail. A Bad answer is passed on as it is.
///
/// @param answer The answer's status; not Good.
/// @param code   `ReadAnswerUncertain` or `ReferencesAnswerUncertain`.
/// @return The status the load completes with.
StatusCode answer_refused(const StatusCode& answer, std::string_view code)
{
  if (!answer.is_uncertain())
  {
    return answer;
  }
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build(
      std::string{code}, "The SDK does not act on an answer the type model is uncertain of", "TypeLoader")
      .cause(answer)};
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct DataTypeInfo
{
  NodeId nodeId;
  String browseName;
  bool isAbstract{false};
  NodeId parentTypeId;

  std::optional<StructureDefinition> structureDefinition;
  std::optional<EnumDefinition> enumDefinition;

  // Encodings: { {"Default Binary", NodeId{...}}, {"Default JSON", NodeId{...}} }
  std::vector<std::pair<String, NodeId>> encodings;
};

struct RegistrationContext
{
  const std::unordered_map<NodeId, DataTypeInfo>& typeMap;
  const NamespaceUriLookup& nsLookup;
  DynamicTypeRegistry& registry;
  LoaderRegistrationStats& stats;
  WorkBudget& budget;

  std::unordered_set<NodeId> registered;
  std::unordered_set<NodeId> failed;
  std::unordered_set<NodeId> selectedTypes;
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

bool is_ns0_builtin(const NodeId& typeId)
{
  return typeId.namespace_index() == 0;
}

bool is_uint_type(const NodeId& typeId)
{
  if (typeId.namespace_index() != 0 || !typeId.is_numeric())
  {
    return false;
  }
  auto numId = typeId.identifier().get_numeric();
  return numId == utils::to_underlying(DataTypeId::UInt16) ||
         numId == utils::to_underlying(DataTypeId::UInt32) ||
         numId == utils::to_underlying(DataTypeId::UInt64) ||
         numId == utils::to_underlying(DataTypeId::UInteger);
}

/// Whether @p typeId is an OptionSet: a supertype on its HasSubtype parent chain is OptionSet or an unsigned
/// integer type before Enumeration is reached.
///
/// The parent of each type is the first inverse HasSubtype target the server returned, so the chain is
/// server input: a type can name itself or a type further down its own chain. The walk records every type
/// it has stepped through and answers "not an OptionSet" when a parent repeats, so a cyclic chain ends the
/// walk instead of looping forever.
bool is_option_set(const std::unordered_map<NodeId, DataTypeInfo>& typeMap, const NodeId& typeId)
{
  auto it = typeMap.find(typeId);
  if (it == typeMap.end())
  {
    return false;
  }

  std::unordered_set<NodeId> visited{typeId};
  NodeId parentId = it->second.parentTypeId;

  while (!parentId.is_null())
  {
    if (!visited.insert(parentId).second)
    {
      return false;  // cyclic HasSubtype parent chain
    }
    if (parentId == NodeId{DataTypeId::Enumeration})
    {
      return false;  // plain enum
    }
    if (parentId.namespace_index() == 0 && parentId.is_numeric() &&
        parentId.identifier().get_numeric() == 12755U)
    {
      return true;  // OptionSet base type
    }
    if (is_uint_type(parentId))
    {
      return true;  // UInteger subtype -> option set
    }

    auto parentIt = typeMap.find(parentId);
    if (parentIt == typeMap.end())
    {
      break;  // reached NS0 or unknown
    }
    parentId = parentIt->second.parentTypeId;
  }
  return false;
}

std::optional<NodeId> find_binary_encoding(const std::vector<std::pair<String, NodeId>>& encodings)
{
  for (const auto& [name, nodeId] : encodings)
  {
    if (static_cast<string_view>(name) == "Default Binary")
    {
      return nodeId;
    }
  }
  return std::nullopt;
}

NamespaceUriLookup make_ns_lookup(const std::vector<String>& nsUris)
{
  return [nsUris](uint16_t nsIndex) -> String
  {
    if (nsIndex < nsUris.size())
    {
      return nsUris[nsIndex];
    }
    return {};
  };
}

/// Build an ExpandedNodeId from a NodeId by looking up its namespace URI.
ExpandedNodeId make_expanded(const NodeId& nodeId, const NamespaceUriLookup& nsLookup)
{
  if (nodeId.namespace_index() == 0)
  {
    return ExpandedNodeId{nodeId};
  }
  auto nsUri = nsLookup(nodeId.namespace_index());
  NodeId idPart = nodeId;
  idPart.namespace_index() = 0;
  return ExpandedNodeId{std::move(idPart), static_cast<string_view>(nsUri)};
}

std::shared_ptr<const ErrorDetail> make_failure_detail(
  StatusCode status, std::string summary, std::shared_ptr<const ErrorDetail> cause = {})
{
  auto detail = std::make_unique<ErrorDetail>();
  detail->summary = std::move(summary);
  detail->source = "TypeLoader";
  detail->innerStatus = status.value();
  if (cause)
  {
    detail->cause = std::move(cause);
  }
  return detail;
}

// ---------------------------------------------------------------------------
// register_with_deps
// ---------------------------------------------------------------------------

std::shared_ptr<const ErrorDetail> register_with_deps(RegistrationContext& ctx, const NodeId& typeId)
{
  if (ctx.registered.contains(typeId))
  {
    return nullptr;
  }
  if (ctx.failed.contains(typeId))
  {
    // Chain the type's own recorded failure, so that a dependent's cause chain reaches the root cause
    // whichever of the two was visited first: the visiting order is a hash order, and differs between
    // platforms. Only the failure path searches, and the work budget bounds the failures.
    std::shared_ptr<const ErrorDetail> cause;
    for (const auto& failure : ctx.stats.failures)
    {
      if (failure.typeId == typeId)
      {
        cause = failure.detail;
        break;
      }
    }
    return make_failure_detail(
      StatusCode{Status::BadDataTypeIdUnknown}, "type previously failed to register", std::move(cause));
  }
  if (is_ns0_builtin(typeId))
  {
    return nullptr;
  }

  // Work budget protection - each type is a node in the dependency graph
  try
  {
    ctx.budget.consume_node();
  }
  catch (const UaException& ex)
  {
    auto detail = make_failure_detail(
      ex.status(), fmt::format("work budget exceeded registering type {}", typeId.as_definition()));
    ctx.failed.insert(typeId);
    ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, String{}, detail});
    return detail;
  }

  auto it = ctx.typeMap.find(typeId);
  if (it == ctx.typeMap.end())
  {
    auto detail = make_failure_detail(StatusCode{Status::BadNodeIdUnknown},
      fmt::format("type {} not found in discovered hierarchy", typeId.as_definition()));
    ctx.failed.insert(typeId);
    ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, String{}, detail});
    return detail;
  }
  const auto& info = it->second;

  if (info.isAbstract)
  {
    ++ctx.stats.skippedAbstract;
    return nullptr;
  }

  // Enum / option set - no field dependencies, register directly
  if (info.enumDefinition)
  {
    const bool optionSet = is_option_set(ctx.typeMap, typeId);
    auto expandedId = make_expanded(typeId, ctx.nsLookup);
    auto result = ctx.registry.register_type(*info.enumDefinition,
      std::move(expandedId),
      String{static_cast<string_view>(info.browseName)},
      optionSet);
    if (result.is_good())
    {
      ++ctx.stats.enumCount;
      if (!ctx.selectedTypes.contains(typeId))
      {
        ++ctx.stats.dependencyCount;
      }
      ctx.registered.insert(typeId);
    }
    else
    {
      auto detail = make_failure_detail(result.status_code(),
        fmt::format("{}: enum registration failed", static_cast<string_view>(info.browseName)));
      ctx.failed.insert(typeId);
      ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
      return detail;
    }
    return nullptr;
  }

  if (!info.structureDefinition)
  {
    auto detail = make_failure_detail(StatusCode{Status::BadDataTypeIdUnknown},
      fmt::format("{}: no StructureDefinition attribute", static_cast<string_view>(info.browseName)));
    ctx.failed.insert(typeId);
    ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
    return detail;
  }

  // Find binary encoding
  auto encodingId = find_binary_encoding(info.encodings);
  if (!encodingId)
  {
    auto detail = make_failure_detail(StatusCode{Status::BadDataTypeIdUnknown},
      fmt::format("{}: no Default Binary encoding", static_cast<string_view>(info.browseName)));
    ctx.failed.insert(typeId);
    ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
    return detail;
  }

  // Recurse into field dependencies - topological order emerges naturally.
  // Each field traversal is an edge in the dependency graph.
  for (size_t i = 0; i < info.structureDefinition->fields().size(); ++i)
  {
    const auto& field = info.structureDefinition->fields()[i];
    try
    {
      ctx.budget.consume_edge();
    }
    catch (const UaException& ex)
    {
      auto detail = make_failure_detail(ex.status(),
        fmt::format("{}: edge budget exceeded at field '{}'",
          static_cast<string_view>(info.browseName),
          static_cast<string_view>(field.name())));
      ctx.failed.insert(typeId);
      ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
      return detail;
    }
    if (auto cause = register_with_deps(ctx, field.data_type()))
    {
      auto detail = make_failure_detail(StatusCode{Status::BadDataTypeIdUnknown},
        fmt::format("{}: field '{}' dependency failed",
          static_cast<string_view>(info.browseName),
          static_cast<string_view>(field.name())),
        cause);
      ctx.failed.insert(typeId);
      ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
      return detail;
    }
  }

  // Register the structure
  auto expandedTypeId = make_expanded(typeId, ctx.nsLookup);
  auto expandedEncodingId = make_expanded(*encodingId, ctx.nsLookup);

  auto result = ctx.registry.register_type(*info.structureDefinition,
    std::move(expandedTypeId),
    std::move(expandedEncodingId),
    String{static_cast<string_view>(info.browseName)},
    ctx.nsLookup);

  if (result.is_good())
  {
    ++ctx.stats.structureCount;
    if (!ctx.selectedTypes.contains(typeId))
    {
      ++ctx.stats.dependencyCount;
    }
    ctx.registered.insert(typeId);
  }
  else
  {
    auto detail = make_failure_detail(result.status_code(),
      fmt::format("{}: structure registration failed", static_cast<string_view>(info.browseName)));
    ctx.failed.insert(typeId);
    ctx.stats.failures.push_back(TypeRegistrationFailure{typeId, info.browseName, detail});
    return detail;
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Async helpers (callback-canonical)
// ---------------------------------------------------------------------------

using NamespaceArrayResult = Result<std::vector<String>>;
using NodeIdListResult = Result<std::vector<NodeId>>;
using TypeMapResult = Result<std::unordered_map<NodeId, DataTypeInfo>>;

// ---------------------------------------------------------------------------
// Non-coroutine registration helpers
// ---------------------------------------------------------------------------

LoaderRegistrationStatsResult register_single_type(const std::unordered_map<NodeId, DataTypeInfo>& typeMap,
  const NamespaceUriLookup& nsLookup, DynamicTypeRegistry& registry, const NodeId& dataTypeId)
{
  LoaderRegistrationStats stats;
  WorkBudget budget{1000, 1000000};
  RegistrationContext ctx{
    .typeMap = typeMap,
    .nsLookup = nsLookup,
    .registry = registry,
    .stats = stats,
    .budget = budget,
    .registered = {},
    .failed = {},
    .selectedTypes = {dataTypeId},
  };

  if (auto detail = register_with_deps(ctx, dataTypeId))
  {
    return LoaderRegistrationStatsResult{StatusCode{detail->innerStatus}, detail};
  }
  return stats;
}

/// Which types named by structure fields of what we already hold are still unfetched.
///
/// Pure, and deliberately NOT inside the coroutine: the scan snapshot and the field walk would
/// otherwise be locals of the coroutine frame, and gcc 14 ICEs building that frame's destructor
/// (build_special_member_call, cp/call.cc) once it holds this much. Smaller frame, same answer.
std::vector<NodeId> collect_missing_dependencies(const std::unordered_map<NodeId, DataTypeInfo>& typeMap,
  std::unordered_set<NodeId>& needed, const std::unordered_set<NodeId>& fetched)
{
  // Snapshot before mutating `needed`: inserting into an unordered_set mid-iteration can rehash and
  // invalidate iterators.
  const std::vector<NodeId> toScan(needed.begin(), needed.end());
  std::vector<NodeId> toFetch;
  for (const auto& id : toScan)
  {
    const auto it = typeMap.find(id);
    if (it == typeMap.end())
    {
      continue;
    }
    const auto& structureDefinitionValue = it->second.structureDefinition;
    if (!structureDefinitionValue)
    {
      continue;
    }
    const auto& structureDefinition = structureDefinitionValue.value();
    for (size_t i = 0; i < structureDefinition.fields().size(); ++i)
    {
      auto fieldTypeId = structureDefinition.fields()[i].data_type();
      if (fieldTypeId.namespace_index() == 0 || needed.contains(fieldTypeId) || fetched.contains(fieldTypeId))
      {
        continue;
      }
      needed.insert(fieldTypeId);
      toFetch.push_back(std::move(fieldTypeId));
    }
  }
  return toFetch;
}

// ---------------------------------------------------------------------------
// Top-level callback-canonical flows
// ---------------------------------------------------------------------------

/// Loads DataType definitions from a model - the whole hierarchy, or one type and its dependencies.
///
/// The strand is handed IN rather than made here. This has no executor to make one from: its
/// collaborator is the abstract @ref TypeModelAccess, which exposes `read_async` and `browse_async`
/// and deliberately says nothing about where the data comes from - a local address space on the
/// server, a network Session on the client. @ref ua::async::await_callback keeps the task's own
/// state on whatever executor it is given, so one has to arrive from outside.
/// @see ua::async::SelfOwningOperation
class TypeLoadOperation final : public ua::async::SelfOwningOperation<TypeLoadOperation>
{
public:
  using Base = ua::async::SelfOwningOperation<TypeLoadOperation>;
  using Complete = std::function<void(LoaderRegistrationStatsResult)>;

  TypeLoadOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    TypeModelAccess& access, DynamicTypeRegistry& registry, TypeFilter filter,
    std::optional<NodeId> singleType, Complete complete)
    : Base(std::move(strand), std::move(logger)), mAccess(access), mRegistry(registry),
      mFilter(std::move(filter)), mSingleType(std::move(singleType)), mComplete(std::move(complete))
  {}

  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    TypeModelAccess& access, DynamicTypeRegistry& registry, TypeFilter filter,
    std::optional<NodeId> singleType, Complete complete)
  {
    Base::launch(std::make_shared<TypeLoadOperation>(std::move(strand),
      std::move(logger),
      access,
      registry,
      std::move(filter),
      std::move(singleType),
      std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<TypeLoadOperation>;

  /// The model's Read answer; one that is not Good is refused (@ref answer_refused).
  ua::async::Task<Result<std::vector<DataValue>>> read(std::vector<ReadValueId> reads)
  {
    auto answer = co_await await_step<Result<std::vector<DataValue>>>(
      [this, reads = std::move(reads)](auto completion) mutable
      { mAccess.read_async(std::move(reads), std::move(completion)); });
    if (answer.is_good())
    {
      co_return answer;
    }
    co_return Result<std::vector<DataValue>>{answer_refused(answer.status_code(), "ReadAnswerUncertain")};
  }

  /// The model's Browse answer as given, Uncertain included.
  ua::async::Task<Result<std::vector<BrowseResult>>> browse_answer(
    std::vector<BrowseDescription> descriptions)
  {
    co_return co_await await_step<Result<std::vector<BrowseResult>>>(
      [this, descriptions = std::move(descriptions)](auto completion) mutable
      { mAccess.browse_async(std::move(descriptions), std::move(completion)); });
  }

  /// The model's Browse answer; one that is not Good is refused (@ref answer_refused).
  ua::async::Task<Result<std::vector<BrowseResult>>> browse(std::vector<BrowseDescription> descriptions)
  {
    auto answer = co_await browse_answer(std::move(descriptions));
    if (answer.is_good())
    {
      co_return answer;
    }
    co_return Result<std::vector<BrowseResult>>{
      answer_refused(answer.status_code(), "ReferencesAnswerUncertain")};
  }

  /// Reads Server_NamespaceArray (i=2255).
  ua::async::Task<NamespaceArrayResult> read_namespace_array()
  {
    std::vector<ReadValueId> reads;
    ReadValueId rv;
    rv.node_id() = NodeId{VariableId::Server_NamespaceArray};
    rv.attribute_id() = static_cast<IntegerId>(AttributeId::Value);
    reads.push_back(std::move(rv));

    const auto result = co_await read(std::move(reads));
    if (!result.is_good())
    {
      co_return NamespaceArrayResult{result.status_code(), result.shared_detail()};
    }

    const auto& dataValues = result.value();
    if (dataValues.empty())
    {
      co_return NamespaceArrayResult{StatusCode{Status::BadUnexpectedError},
        make_failure_detail(StatusCode{Status::BadUnexpectedError}, "empty read result for NamespaceArray")};
    }

    const auto& dv = dataValues[0];
    const auto& status = dv.status();
    if (status.has_value() && !status->is_good())
    {
      co_return NamespaceArrayResult{*status, make_failure_detail(*status, "failed to read NamespaceArray")};
    }
    if (!dv.value().is_array_of_string())
    {
      co_return NamespaceArrayResult{StatusCode{Status::BadTypeMismatch},
        make_failure_detail(
          StatusCode{Status::BadTypeMismatch}, "NamespaceArray value is not an Array<String>")};
    }

    const auto& stringArray = dv.value().as<Array<String>>();
    std::vector<String> nsUris;
    nsUris.reserve(stringArray.size());
    for (size_t i = 0; i < stringArray.size(); ++i)
    {
      nsUris.push_back(stringArray[i]);
    }
    co_return NamespaceArrayResult{std::move(nsUris)};
  }

  /// Breadth-first over HasSubtype from @p rootTypeId, one browse per level.
  ///
  /// A LOOP, not one frame per level: the depth is the server's type hierarchy, and R4 costs about
  /// 430 bytes of stack per level of coroutine nesting. The root itself is not collected - only its
  /// subtypes - which is what the flow this replaced did.
  ua::async::Task<NodeIdListResult> discover_hierarchy(NodeId rootTypeId)
  {
    std::vector<NodeId> currentLevel{std::move(rootTypeId)};
    std::vector<NodeId> allTypeIds;

    while (!currentLevel.empty())
    {
      std::vector<BrowseDescription> browseDescs;
      browseDescs.reserve(currentLevel.size());
      for (const auto& nodeId : currentLevel)
      {
        BrowseDescription bd;
        bd.node_id() = nodeId;
        bd.browse_direction() = BrowseDirection::Forward;
        bd.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
        bd.include_subtypes() = false;
        bd.node_class_mask() = 0;
        bd.result_mask() = utils::to_underlying(BrowseResultMask::BrowseName);
        browseDescs.push_back(std::move(bd));
      }

      auto result = co_await browse_answer(std::move(browseDescs));
      if (result.is_uncertain())
      {
        // The walk decides which types are loaded, so a page the model is uncertain of is refused at
        // any level rather than ending the walk early with a partial hierarchy.
        co_return NodeIdListResult{answer_refused(result.status_code(), "ReferencesAnswerUncertain")};
      }
      if (!result.is_good())
      {
        // 10.4: top-level/primary failures must propagate. If nothing has been collected yet, the
        // very first browse (root -> BaseDataType) failed, so the operation cannot even begin.
        if (allTypeIds.empty())
        {
          co_return NodeIdListResult{result.status_code(), result.shared_detail()};
        }
        // Mid-walk best-effort for a Bad page: terminate the BFS and return whatever was collected so far.
        co_return NodeIdListResult{std::move(allTypeIds)};
      }

      std::vector<NodeId> nextLevel;
      for (const auto& br : result.value())
      {
        for (size_t i = 0; i < br.references().size(); ++i)
        {
          nextLevel.push_back(NodeId{br.references()[i].node_id()});
        }
      }

      // Bound the server-driven hierarchy size (anti unbounded-allocation DoS; also terminates a
      // cyclic HasSubtype graph). Fail rather than allocate against attacker-controlled input.
      if (nextLevel.size() > maxDiscoveredTypes - allTypeIds.size())
      {
        co_return NodeIdListResult{StatusCode{Status::BadEncodingLimitsExceeded},
          ErrorDetail::build("TypeHierarchyTooLarge",
            "Discovered type hierarchy exceeds the maximum supported size",
            "TypeLoader")
            .context(ua::ContextKeys::max, std::to_string(maxDiscoveredTypes))};
      }

      allTypeIds.insert(allTypeIds.end(), nextLevel.begin(), nextLevel.end());
      currentLevel = std::move(nextLevel);
    }
    co_return NodeIdListResult{std::move(allTypeIds)};
  }

  /// BrowseName / IsAbstract / DataTypeDefinition per type, plus inverse-HasSubtype (parent) and
  /// forward-HasEncoding per type.
  ua::async::Task<TypeMapResult> read_all_type_info(std::vector<NodeId> typeIds)
  {
    if (typeIds.empty())
    {
      co_return TypeMapResult{std::unordered_map<NodeId, DataTypeInfo>{}};
    }

    std::vector<ReadValueId> reads;
    reads.reserve(typeIds.size() * 3);
    for (const auto& id : typeIds)
    {
      for (const auto attribute :
        {AttributeId::BrowseName, AttributeId::IsAbstract, AttributeId::DataTypeDefinition})
      {
        ReadValueId rv;
        rv.node_id() = id;
        rv.attribute_id() = static_cast<IntegerId>(attribute);
        reads.push_back(std::move(rv));
      }
    }

    std::vector<BrowseDescription> browses;
    browses.reserve(typeIds.size() * 2);
    for (const auto& id : typeIds)
    {
      BrowseDescription parentBrowse;
      parentBrowse.node_id() = id;
      parentBrowse.browse_direction() = BrowseDirection::Inverse;
      parentBrowse.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
      parentBrowse.include_subtypes() = false;
      parentBrowse.node_class_mask() = 0;
      parentBrowse.result_mask() = utils::to_underlying(BrowseResultMask::BrowseName);
      browses.push_back(std::move(parentBrowse));

      BrowseDescription encodingBrowse;
      encodingBrowse.node_id() = id;
      encodingBrowse.browse_direction() = BrowseDirection::Forward;
      encodingBrowse.reference_type_id() = NodeId{ReferenceTypeId::HasEncoding};
      encodingBrowse.include_subtypes() = false;
      encodingBrowse.node_class_mask() = 0;
      encodingBrowse.result_mask() = utils::to_underlying(BrowseResultMask::BrowseName);
      browses.push_back(std::move(encodingBrowse));
    }

    // BOTH IN FLIGHT before either is awaited. A Task starts eagerly, so these two run together
    // exactly as the two independent callbacks did, and the co_awaits below are the join - not a
    // sequence of one request after the other.
    auto readTask = read(std::move(reads));
    auto browseTask = browse(std::move(browses));
    // `std::move`: Task's operator co_await is rvalue-qualified, which is what stops a task being
    // awaited twice.
    auto readResult = co_await std::move(readTask);
    auto browseResult = co_await std::move(browseTask);

    if (!readResult.is_good())
    {
      co_return TypeMapResult{readResult.status_code(), readResult.shared_detail()};
    }
    if (!browseResult.is_good())
    {
      co_return TypeMapResult{browseResult.status_code(), browseResult.shared_detail()};
    }

    const auto& readValues = readResult.value();
    const auto& browseValues = browseResult.value();

    std::unordered_map<NodeId, DataTypeInfo> typeMap;
    for (size_t i = 0; i < typeIds.size(); ++i)
    {
      DataTypeInfo info;
      info.nodeId = typeIds[i];

      const auto readIdx = i * 3;
      if (readIdx < readValues.size() && readValues[readIdx].value().is_qualified_name())
      {
        info.browseName = readValues[readIdx].value().as<QualifiedName>().name();
      }
      if (readIdx + 1 < readValues.size() && readValues[readIdx + 1].value().is_boolean())
      {
        info.isAbstract = readValues[readIdx + 1].value().as<bool>();
      }
      if (readIdx + 2 < readValues.size())
      {
        const auto& defVariant = readValues[readIdx + 2].value();
        if (defVariant.is_structure())
        {
          if (const auto* structDef = defVariant.try_as<StructureDefinition>())
          {
            info.structureDefinition = *structDef;
          }
          else if (const auto* enumDef = defVariant.try_as<EnumDefinition>())
          {
            info.enumDefinition = *enumDef;
          }
        }
      }

      const auto browseIdx = i * 2;
      if (browseIdx < browseValues.size() && browseValues[browseIdx].references().size() > 0)
      {
        info.parentTypeId = NodeId{browseValues[browseIdx].references()[0].node_id()};
      }
      if (browseIdx + 1 < browseValues.size())
      {
        for (size_t j = 0; j < browseValues[browseIdx + 1].references().size(); ++j)
        {
          const auto& ref = browseValues[browseIdx + 1].references()[j];
          info.encodings.emplace_back(ref.browse_name().name(), NodeId{ref.node_id()});
        }
      }

      typeMap[info.nodeId] = std::move(info);
    }
    co_return TypeMapResult{std::move(typeMap)};
  }

  ua::async::Task<> run()
  {
    try
    {
      auto namespaceArray = co_await read_namespace_array();
      if (!namespaceArray.is_good())
      {
        fire(LoaderRegistrationStatsResult{namespaceArray.status_code(), namespaceArray.shared_detail()});
        co_return;
      }
      // A MEMBER, not a parameter: R8 - a reference parameter held across a co_await is a
      // dangling read waiting to happen, and the frame outlives nothing here anyway.
      mNsLookup = make_ns_lookup(namespaceArray.value());

      if (mSingleType)
      {
        co_await load_one();
      }
      else
      {
        co_await load_all();
      }
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      fire(ua::exception_to_status_code(std::current_exception()));
    }
    co_return;
  }

  /// The whole DataType hierarchy, filtered, then registered.
  ua::async::Task<> load_all()
  {
    auto hierarchy = co_await discover_hierarchy(NodeId{DataTypeId::BaseDataType});
    if (!hierarchy.is_good())
    {
      fire(LoaderRegistrationStatsResult{hierarchy.status_code(), hierarchy.shared_detail()});
      co_return;
    }

    // Hoisted for the same reason as in load_one.
    std::vector<NodeId> discoveredTypeIds = std::move(hierarchy).value();
    auto typeInfo = co_await read_all_type_info(std::move(discoveredTypeIds));
    if (!typeInfo.is_good())
    {
      fire(LoaderRegistrationStatsResult{typeInfo.status_code(), typeInfo.shared_detail()});
      co_return;
    }
    auto typeMap = std::move(typeInfo).value();

    std::unordered_set<NodeId> selectedTypes;
    // Explicit iteration, not a structured binding - see load_one.
    for (auto entry = typeMap.begin(); entry != typeMap.end(); ++entry)
    {
      const auto& nodeId = entry->first;
      const auto& info = entry->second;
      if (nodeId.namespace_index() == 0)
      {
        continue;
      }
      const auto kind = info.enumDefinition        ? DiscoveredTypeKind::Enumeration
                        : info.structureDefinition ? DiscoveredTypeKind::Structure
                                                   : DiscoveredTypeKind::Other;
      DiscoveredType discovered{nodeId, info.browseName, info.isAbstract, info.parentTypeId, kind};
      if (!mFilter || mFilter(discovered))
      {
        selectedTypes.insert(nodeId);
      }
    }

    LoaderRegistrationStats stats;
    WorkBudget budget{1000, 1000000};
    RegistrationContext ctx{
      .typeMap = typeMap,
      .nsLookup = mNsLookup,
      .registry = mRegistry,
      .stats = stats,
      .budget = budget,
      .registered = {},
      .failed = {},
      .selectedTypes = std::move(selectedTypes),
    };

    for (const auto& nodeId : ctx.selectedTypes)
    {
      register_with_deps(ctx, nodeId);
      // failures recorded in stats - continue with next type
    }
    fire(LoaderRegistrationStatsResult{std::move(stats)});
  }

  /// One type, chasing structure-field dependencies until nothing new is needed.
  ua::async::Task<> load_one()
  {
    NodeId dataTypeId = *mSingleType;
    std::unordered_set<NodeId> needed{dataTypeId};
    std::unordered_set<NodeId> fetched{dataTypeId};

    // The argument is built into a NAMED local first, deliberately. Constructing a temporary
    // from a coroutine-frame local inside the co_await operand ICEs gcc 14 while it builds the
    // frame's destructor (build_special_member_call, cp/call.cc:11096). Bisected to exactly
    // that: the same call with an empty vector, or with the vector hoisted, compiles.
    std::vector<NodeId> seed;
    seed.push_back(dataTypeId);
    auto initial = co_await read_all_type_info(std::move(seed));
    if (!initial.is_good())
    {
      fire(LoaderRegistrationStatsResult{initial.status_code(), initial.shared_detail()});
      co_return;
    }
    auto typeMap = std::move(initial).value();

    // Iterative, not recursive: the chase depth is the model's, not the SDK's. R4.
    while (true)
    {
      auto toFetch = collect_missing_dependencies(typeMap, needed, fetched);
      if (toFetch.empty())
      {
        break;
      }

      auto dependencies = co_await read_all_type_info(std::move(toFetch));
      if (!dependencies.is_good())
      {
        fire(LoaderRegistrationStatsResult{dependencies.status_code(), dependencies.shared_detail()});
        co_return;
      }
      // Explicit iteration, not a structured binding: a structured binding over a coroutine-frame
      // local ICEs gcc 14 here (build_special_member_call, cp/call.cc).
      auto& fetchedTypes = dependencies.value();
      for (auto entry = fetchedTypes.begin(); entry != fetchedTypes.end(); ++entry)
      {
        fetched.insert(entry->first);
        typeMap[entry->first] = std::move(entry->second);
      }
    }

    fire(register_single_type(typeMap, mNsLookup, mRegistry, dataTypeId));
  }

  void fail_to_start(StatusCode status)
  {
    fire(LoaderRegistrationStatsResult{status, status.shared_detail()});
  }

  void fire(LoaderRegistrationStatsResult result)
  {
    if (auto callback = std::move(mComplete))
    {
      callback(std::move(result));
    }
  }

  TypeModelAccess& mAccess;
  DynamicTypeRegistry& mRegistry;
  NamespaceUriLookup mNsLookup;
  TypeFilter mFilter;
  /// Engaged for load_type, empty for load_types.
  std::optional<NodeId> mSingleType;
  Complete mComplete;
};

}  // anonymous namespace

namespace
{

/// Runs an async load to completion on an io_context this function owns and DRIVES.
///
/// The callers of the `*_sync` entry points have no executor to lend - the unit tests deliberately
/// have none - and a `boost::asio::thread_pool` could not be driven from outside even if they did:
/// it has no `poll()`, and `attach()` blocks until the pool stops rather than until one answer
/// arrives. An `io_context` can be driven, so the wrapper makes one, runs the load on a strand over
/// it, and turns the wheel itself. That is what keeps these signatures free of an executor
/// parameter, and what makes them unable to deadlock against the caller's.
template<typename Launch>
LoaderRegistrationStatsResult drive_to_completion(Launch&& launch)
{
  boost::asio::io_context io;
  auto work = boost::asio::make_work_guard(io);
  std::optional<LoaderRegistrationStatsResult> answer;

  launch(boost::asio::make_strand(boost::asio::any_io_executor{io.get_executor()}),
    ua::Logger{},
    [&answer, &work](LoaderRegistrationStatsResult result) mutable
    {
      answer = std::move(result);
      // Releasing the guard is what lets run() return: the load is the only work this context has.
      work.reset();
    });

  io.run();

  if (!answer)
  {
    return LoaderRegistrationStatsResult{StatusCode{Status::BadInternalError},
      make_failure_detail(
        StatusCode{Status::BadInternalError}, "type load ended without delivering an answer")};
  }
  return std::move(*answer);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API: load_types
// ---------------------------------------------------------------------------

void load_types_async(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
  TypeModelAccess& access, DynamicTypeRegistry& registry, TypeFilter filter,
  std::function<void(LoaderRegistrationStatsResult)> callback)
{
  TypeLoadOperation::start(std::move(strand),
    std::move(logger),
    access,
    registry,
    std::move(filter),
    std::nullopt,
    std::move(callback));
}

LoaderRegistrationStatsResult try_load_types_sync(
  TypeModelAccess& access, DynamicTypeRegistry& registry, TypeFilter filter) noexcept
{
  try
  {
    return drive_to_completion(
      [&access, &registry, &filter](auto strand, auto logger, auto completion)
      {
        load_types_async(
          std::move(strand), std::move(logger), access, registry, std::move(filter), std::move(completion));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

LoaderRegistrationStats load_types_sync(
  TypeModelAccess& access, DynamicTypeRegistry& registry, TypeFilter filter)
{
  return ua::detail::good_value(try_load_types_sync(access, registry, std::move(filter)));
}

// ---------------------------------------------------------------------------
// Public API: load_type
// ---------------------------------------------------------------------------

void load_type_async(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
  TypeModelAccess& access, DynamicTypeRegistry& registry, const NodeId& dataTypeId,
  std::function<void(LoaderRegistrationStatsResult)> callback)
{
  TypeLoadOperation::start(
    std::move(strand), std::move(logger), access, registry, TypeFilter{}, dataTypeId, std::move(callback));
}

LoaderRegistrationStatsResult try_load_type_sync(
  TypeModelAccess& access, DynamicTypeRegistry& registry, const NodeId& dataTypeId) noexcept
{
  try
  {
    return drive_to_completion(
      [&access, &registry, &dataTypeId](auto strand, auto logger, auto completion)
      {
        load_type_async(
          std::move(strand), std::move(logger), access, registry, dataTypeId, std::move(completion));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

LoaderRegistrationStats load_type_sync(
  TypeModelAccess& access, DynamicTypeRegistry& registry, const NodeId& dataTypeId)
{
  return ua::detail::good_value(try_load_type_sync(access, registry, dataTypeId));
}

}  // namespace ua::dynamic_types
