// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_accessor_route.h"

#include "ua_address_space_impl.h"
#include "ua_call_method_request.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_log_exception.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace_items.h"
#include "ua_namespace_route.h"
#include "ua_namespace_zero_tables.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_subtype_facts.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_value_range_check.h"
#include "ua_write_value.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <iterator>
#include <numeric>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ua::detail
{

struct NodeAccessorRoute::Bound
{
  shared_ptr<Node> node;
  shared_ptr<AddressSpaceImpl> addressSpace;
  shared_ptr<const NamespaceRegistrationRoute> registrationRoute;
  shared_ptr<Namespace> nameSpace;
  std::optional<StatusCode> failure;
};

namespace
{

// Puts item `position` into the part of `nameSpace`, adding the part when it is the namespace's first item.
// The part and its index are recorded together or not at all, so a failed allocation leaves no index past
// the parts' end for a later item of the same namespace to write through.
template<typename Part>
void add_to_part(std::vector<Part>& parts, std::unordered_map<const Namespace*, std::size_t>& partOf,
  shared_ptr<Namespace> nameSpace, std::size_t position)
{
  const Namespace* key = nameSpace.get();
  if (const auto found = partOf.find(key); found != partOf.end())
  {
    parts[found->second].positions.push_back(position);
    return;
  }
  parts.push_back(Part{std::move(nameSpace), {position}});
  try
  {
    partOf.emplace(key, parts.size() - 1);
  }
  catch (...)
  {
    parts.pop_back();
    throw;
  }
}

// Calls one namespace's member once for `count` items and hands on its answers in item order, through the
// route and its guards. Throws only before the call is made.
template<typename Answer>
void call_namespace(shared_ptr<Namespace> nameSpace, std::size_t count,
  std::function<void(Namespace&, std::function<void(BatchResult<Answer>)>)> invoke,
  std::function<void(std::vector<Answer>)> done)
{
  using Route = NamespaceRoute<Answer>;
  typename Route::Part part{std::move(nameSpace), {}};
  part.positions.reserve(count);
  for (std::size_t position = 0; position < count; ++position)
  {
    part.positions.push_back(position);
  }
  std::vector<typename Route::Part> parts;
  parts.push_back(std::move(part));
  std::vector<std::optional<Answer>> answers(count);
  Route::run(
    std::move(answers),
    std::move(parts),
    std::nullopt,
    [invoke = std::move(invoke)](
      Namespace& member, std::span<const std::size_t>, std::function<void(BatchResult<Answer>)> answer)
    { invoke(member, std::move(answer)); },
    std::move(done));
}

uint8_t verb(ModelChangeStructureVerbMask mask) noexcept
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

// The step an operation's calls record into: @p given, the step of the operation the call is part of;
// otherwise one of the call's own, which is closed, and its event raised, before @p callback runs (NR-36 rule
// 4).
template<typename Answer>
shared_ptr<ModelChangeStep> operation_step(const weak_ptr<AddressSpaceImpl>& addressSpace,
  shared_ptr<ModelChangeStep> given, std::function<void(Answer)>& callback)
{
  if (given)
  {
    return given;
  }
  auto step = ModelChangeStep::create(addressSpace);
  callback = [step, inner = std::move(callback)](Answer answer) mutable
  {
    step->close([inner = std::move(inner), answer = std::move(answer)]() mutable
      { invoke_user_callback(inner, std::move(answer)); });
  };
  return step;
}

// The completion of an add_references_async or remove_references_async call of @p items: each reported Node
// holds a half that was added (ReferenceAdded, and NodeAdded for a source created in this operation) or
// removed (ReferenceDeleted). A HasTypeDefinition sent for a created source gives its entry an affectedType
// (NR-63 rule 3).
std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> recording_changes(
  std::function<void(BatchResult<VoidResult>)> answer, ModelChangeStep& step,
  std::span<const ReferenceChange> items, bool add)
{
  std::unordered_set<NodeId> created;
  if (add)
  {
    const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
    for (const ReferenceChange& item : items)
    {
      if (!item.sourceCreated)
      {
        continue;
      }
      created.insert(item.source);
      if (item.referenceType == hasTypeDefinition && item.isForward && item.target.is_local())
      {
        step.type_definition_sent(item.source, item.target.node_id());
      }
    }
  }
  const uint8_t changed = add ? verb(ModelChangeStructureVerbMask::ReferenceAdded)
                              : verb(ModelChangeStructureVerbMask::ReferenceDeleted);
  return recording_versions<VoidResult>(std::move(answer),
    step,
    [created = std::move(created), changed](const NodeId& node)
    {
      return created.contains(node)
               ? static_cast<uint8_t>(changed | verb(ModelChangeStructureVerbMask::NodeAdded))
               : changed;
    });
}

// The completion of a write_async call of @p items. The output does not say which Attribute changed: a
// reported Node the call wrote only the DataType of is DataTypeChanged; one it also wrote another Attribute
// of (a ValueRank or ArrayDimensions) has no verb, and makes the event a BaseModelChangeEvent, which tells
// the clients that any Node may have changed (Part 3 9.32.5).
std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> record_writes(
  std::function<void(BatchResult<VoidResult>)> answer, ModelChangeStep& step,
  std::span<const ValueWriteItem> items)
{
  // Per written Node: whether every item of the call that writes it writes its DataType.
  std::unordered_map<NodeId, bool> onlyDataType;
  for (const ValueWriteItem& item : items)
  {
    const bool dataType = static_cast<AttributeId>(item.value.attribute_id()) == AttributeId::DataType;
    auto [entry, added] = onlyDataType.try_emplace(item.value.node_id(), dataType);
    if (!added)
    {
      entry->second = entry->second && dataType;
    }
  }
  return recording_versions<VoidResult>(std::move(answer),
    step,
    [onlyDataType = std::move(onlyDataType)](const NodeId& node)
    {
      const auto written = onlyDataType.find(node);
      return written != onlyDataType.end() && written->second
               ? verb(ModelChangeStructureVerbMask::DataTypeChanged)
               : uint8_t{0};
    });
}

// Whether a write of @p write changes the model the generation counts: a BrowseName or a DataType (NR-68 item
// 1).
bool changes_the_model(const WriteValue& write) noexcept
{
  const auto attribute = static_cast<AttributeId>(write.attribute_id());
  return attribute == AttributeId::BrowseName || attribute == AttributeId::DataType;
}

// NR-36 rule 6: a Value written to a 0:NodeVersion Property outside the address space's own advance is a
// model change no verb names (OPC 10000-3 9.32.2), raised as a BaseModelChangeEvent.
bool writes_a_node_version(const Node& node, const WriteValue& written) noexcept
{
  try
  {
    if (static_cast<AttributeId>(written.attribute_id()) != AttributeId::Value)
    {
      return false;
    }
    const auto nodeDescription = node.attributes();
    return nodeDescription.browse_name() == QualifiedName{0, "NodeVersion"};
  }
  catch (...)
  {
    return false;
  }
}

// The answer of a change made of several: the first Bad answer, else the first Uncertain one (a remove of a
// Reference not held), else the Good code the answers combine to by combined_status, so a namespace's Good
// subcode is answered rather than plain Good (for one answer, its own code).
VoidResult first_failure(std::vector<VoidResult> answers)
{
  VoidResult uncertain;
  StatusCode good{Status::Good};
  for (auto& answer : answers)
  {
    if (answer.is_bad())
    {
      return std::move(answer);
    }
    if (!answer.is_good())
    {
      if (uncertain.is_good())
      {
        uncertain = std::move(answer);
      }
      continue;
    }
    good = combined_status(good, answer.status_code());
  }
  if (!uncertain.is_good())
  {
    return uncertain;
  }
  return VoidResult{good};
}

// What the route does with the other half of a Reference of a type (NR-30 rule 2, revised by NR-50, NR-68
// item 7 and DL-115 (4), (5)): it adds or removes it in the target's namespace, except for a remote target.
enum class OtherHalf : std::uint8_t
{
  // The caller names every half.
  None,
  // The hierarchical types and GeneratesEvent with their subtypes, which OPC 10000-3 recommends bidirectional
  // (5.3.2, 5.6.5): a failed other half is logged and the change keeps its own answer.
  Recommended,
  // HasSubtype and its subtypes: the subtype's inverse half is required (OPC 10000-3 5.5.2), the supertype's
  // forward half recommended.
  InverseRequired,
  // HasEncoding and its subtypes, bidirectional (OPC 10000-3 5.8.4): a failed other half is reported on the
  // change.
  Required,
};

// The rule for namespace 0's ReferenceType @p type, from the table generated from its NodeSet, with no
// lookup; a subtype takes the rule of its nearest supertype that has one. Nullopt for a type of another
// namespace.
std::optional<OtherHalf> namespace_zero_other_half(const NodeId& type) noexcept
{
  if (type.namespace_index() != 0)
  {
    return std::nullopt;
  }
  if (!type.is_numeric())
  {
    return OtherHalf::None;
  }
  const auto rows = namespace_zero_tables::reference_types();
  uint32_t id = type.identifier().get_numeric();
  for (std::size_t depth = 0; depth <= rows.size(); ++depth)
  {
    switch (static_cast<ReferenceTypeId>(id))
    {
    case ReferenceTypeId::HasSubtype:
      return OtherHalf::InverseRequired;
    case ReferenceTypeId::HasEncoding:
      return OtherHalf::Required;
    case ReferenceTypeId::HierarchicalReferences:
    case ReferenceTypeId::GeneratesEvent:
      return OtherHalf::Recommended;
    default:
      break;
    }
    const auto row = std::lower_bound(rows.begin(),
      rows.end(),
      id,
      [](const namespace_zero_tables::ReferenceTypeRow& candidate, uint32_t wanted)
      { return candidate.id < wanted; });
    if (row == rows.end() || row->id != id || row->supertype == 0)
    {
      return OtherHalf::None;
    }
    id = row->supertype;
  }
  return OtherHalf::None;
}

// Whether a Reference of @p referenceType may have an other half the route adds or removes: namespace 0's
// rule, and true for a type of another namespace, which only a lookup decides.
bool may_be_paired(const NodeId& referenceType) noexcept
{
  const auto zero = namespace_zero_other_half(referenceType);
  return !zero || *zero != OtherHalf::None;
}

// Whether a Reference of @p referenceType may be HasEncoding or HasSubtype, or a subtype of one, whose other
// half OPC 10000-3 requires: namespace 0's rule, and true for a type of another namespace, which only a
// lookup decides.
bool may_require_its_other_half(const NodeId& referenceType) noexcept
{
  const auto zero = namespace_zero_other_half(referenceType);
  return !zero || *zero == OtherHalf::Required || *zero == OtherHalf::InverseRequired;
}

// Whether @p change, sent without its other half, would leave a Node without a half OPC 10000-3 requires:
// either half of HasEncoding (5.8.4), or the subtype's inverse half of HasSubtype, which the supertype's
// forward half needs while the forward half is optional (5.3.3.3). So an add of the forward half alone and a
// removal of the inverse half alone are refused. A target in another Server keeps its half whatever is asked,
// so a change naming one is not refused.
bool leaves_a_required_half_alone(const ReferenceChange& change, OtherHalf rule, bool add) noexcept
{
  return change.target.is_local() &&
         (rule == OtherHalf::Required ||
           (rule == OtherHalf::InverseRequired && (add ? change.isForward : !change.isForward)));
}

// The answer of a change @ref leaves_a_required_half_alone refuses: nothing of it is sent.
VoidResult required_half_refusal(const ReferenceChange& change, OtherHalf rule, bool add)
{
  const char* const message =
    rule == OtherHalf::Required
      ? (add
            ? "OPC 10000-3 5.8.4 requires both halves of a HasEncoding Reference; one half alone is not added"
            : "OPC 10000-3 5.8.4 requires both halves of a HasEncoding Reference; one half alone is not "
              "removed")
      : (add ? "OPC 10000-3 5.3.3.3 requires a subtype to hold the inverse HasSubtype to its supertype; the "
               "supertype's forward half alone is not added"
             : "OPC 10000-3 5.3.3.3 requires a subtype to hold the inverse HasSubtype to its supertype; the "
               "subtype's inverse half alone is not removed");
  return VoidResult{StatusCode{Status::BadNotSupported,
    ErrorDetail::build("RequiredOtherHalfLeftAlone", message, "NodeAccessorRoute")
      .context(ContextKeys::nodeId, to_string(change.source))
      .context(ContextKeys::typeId, to_string(change.referenceType))}};
}

// The rule for each ReferenceType of one call.
using OtherHalves = std::unordered_map<NodeId, OtherHalf>;

OtherHalf other_half_of(const OtherHalves& halves, const NodeId& referenceType) noexcept
{
  const auto found = halves.find(referenceType);
  return found == halves.end() ? OtherHalf::None : found->second;
}

// Logs a ReferenceType whose rule the walk of its supertypes could not decide; its References are not paired.
void log_undecided_type(const Logger& logger, const NodeId& referenceType, const StatusCode& status) noexcept
{
  try
  {
    logger.with_category("address_space")
      .warning({{"reference_type", to_string(referenceType)},
                 {"status", to_string(status)},
                 {"error", status.shared_detail() ? to_string(*status.shared_detail()) : std::string{}}},
        "Could not decide whether the address space pairs references of this type; their other halves are "
        "not added or removed");
  }
  catch (...)
  {
    ignore_expected_exception();
  }
}

// The rule for each ReferenceType of @p changes: namespace 0's from its table; another namespace's from the
// first namespace-0 type its supertype chain reaches, walked once per type in the call (walk_supertypes). The
// answers are not kept after the call, so a namespace that changes its type hierarchy is read again at the
// next one. A type that does not exist, or whose chain ends outside namespace 0, is None; one whose walk
// fails is None, and logged. @p done is called once.
void classify_other_halves(const WeakAddressSpace& addressSpace, const shared_ptr<const RequestInfo>& request,
  const std::vector<ReferenceChange>& changes,
  std::function<void(Result<shared_ptr<const OtherHalves>>)> done) noexcept
{
  try
  {
    auto halves = std::make_shared<OtherHalves>();
    std::vector<NodeId> walked;
    for (const auto& change : changes)
    {
      if (halves->contains(change.referenceType) ||
          std::find(walked.begin(), walked.end(), change.referenceType) != walked.end())
      {
        continue;
      }
      if (const auto zero = namespace_zero_other_half(change.referenceType))
      {
        halves->emplace(change.referenceType, *zero);
      }
      else
      {
        walked.push_back(change.referenceType);
      }
    }
    if (walked.empty())
    {
      invoke_user_callback(done, Result<shared_ptr<const OtherHalves>>{std::move(halves)});
      return;
    }
    auto owner = addressSpace.lock();
    if (!owner)
    {
      invoke_user_callback(
        done, Result<shared_ptr<const OtherHalves>>{address_space_gone("NodeAccessorRoute")});
      return;
    }
    Logger logger = owner->logger();
    const AddressSpace space = *owner;
    ::ua::namespace_calls::find_nodes(space,
      *request,
      walked,
      [space, request, halves, walked, logger, done = std::move(done)](
        std::vector<NodeAccessorResult> found) mutable
      {
        try
        {
          std::vector<std::pair<NodeAccessor, NodeId>> starts;
          std::vector<std::size_t> startOf;
          for (std::size_t t = 0; t < walked.size(); ++t)
          {
            if (t < found.size() && found[t].is_good())
            {
              starts.emplace_back(found[t].value(), walked[t]);
              startOf.push_back(t);
              continue;
            }
            const StatusCode why =
              t < found.size() ? found[t].status_code() : StatusCode{Status::BadInternalError};
            if (why != Status::BadNodeIdUnknown)
            {
              log_undecided_type(logger, walked[t], lookup_failure(walked[t], why, "NodeAccessorRoute"));
            }
            halves->emplace(walked[t], OtherHalf::None);
          }
          if (starts.empty())
          {
            invoke_user_callback(done, Result<shared_ptr<const OtherHalves>>{std::move(halves)});
            return;
          }
          ::ua::walk_supertypes(
            space,
            *request,
            std::move(starts),
            ::ua::maxTypeWalkDepth,
            [](std::size_t, const NodeId& type) -> std::optional<int>
            {
              const auto zero = namespace_zero_other_half(type);
              return zero ? std::optional<int>{static_cast<int>(*zero)} : std::nullopt;
            },
            [halves,
              walked = std::move(walked),
              startOf = std::move(startOf),
              logger,
              done = std::move(done)](std::vector<::ua::SupertypeWalkEnd> ends) mutable
            {
              try
              {
                for (std::size_t s = 0; s < startOf.size(); ++s)
                {
                  const NodeId& type = walked[startOf[s]];
                  OtherHalf decided = OtherHalf::None;
                  if (s >= ends.size())
                  {
                    log_undecided_type(logger, type, StatusCode{Status::BadInternalError});
                  }
                  else if (ends[s].how == ::ua::SupertypeWalkEnd::How::Decided)
                  {
                    decided = static_cast<OtherHalf>(ends[s].value);
                  }
                  else if (ends[s].how == ::ua::SupertypeWalkEnd::How::Failed)
                  {
                    log_undecided_type(logger, type, ends[s].failure);
                  }
                  halves->emplace(type, decided);
                }
                invoke_user_callback(done, Result<shared_ptr<const OtherHalves>>{std::move(halves)});
              }
              catch (...)
              {
                invoke_user_callback(done,
                  Result<shared_ptr<const OtherHalves>>{exception_to_status_code(std::current_exception())});
              }
            });
        }
        catch (...)
        {
          invoke_user_callback(
            done, Result<shared_ptr<const OtherHalves>>{exception_to_status_code(std::current_exception())});
        }
      });
  }
  catch (...)
  {
    invoke_user_callback(
      done, Result<shared_ptr<const OtherHalves>>{exception_to_status_code(std::current_exception())});
  }
}

// @p changes with each local target given by namespace URI written in its index form, so that its other half
// and the NR-52 check reach the target's namespace, as Browse reads such a target. A URI the server does not
// hold is kept as given: no Node of this server is its target. The same pointer when no target is given by
// URI.
shared_ptr<const std::vector<ReferenceChange>> with_index_targets(
  const shared_ptr<AddressSpaceImpl>& impl, shared_ptr<const std::vector<ReferenceChange>> changes)
{
  if (!changes || std::none_of(changes->begin(),
                    changes->end(),
                    [](const ReferenceChange& change)
                    { return change.target.is_local() && change.target.is_not_index_based(); }))
  {
    return changes;
  }
  if (!impl)
  {
    return changes;
  }
  auto resolved = std::make_shared<std::vector<ReferenceChange>>(*changes);
  for (auto& change : *resolved)
  {
    if (!change.target.is_local() || !change.target.is_not_index_based())
    {
      continue;
    }
    try
    {
      const uint16_t index = impl->namespace_array().get_namespace_index(change.target.namespace_uri());
      change.target.namespace_uri().clear();
      change.target.node_id().namespace_index() = index;
    }
    catch (const UaException& exception)
    {
      if (exception.status() != Status::BadOutOfRange)
      {
        throw;
      }
      // An unregistered namespace URI remains in URI form; it does not identify a local target.
      ignore_expected_exception();
    }
  }
  return resolved;
}

// One half of a Reference, as a batch holds each once.
struct HalfKey
{
  NodeId source;
  NodeId referenceType;
  NodeId target;
  bool isForward{true};

  bool operator==(const HalfKey& other) const = default;
};

struct HalfKeyHash
{
  std::size_t operator()(const HalfKey& key) const noexcept
  {
    std::size_t hash = std::hash<NodeId>{}(key.source);
    hash = hash * 31 + std::hash<NodeId>{}(key.referenceType);
    hash = hash * 31 + std::hash<NodeId>{}(key.target);
    return hash * 2 + (key.isForward ? 1 : 0);
  }
};

// Removes from @p others (and @p otherFor) each half @p requested holds itself, as a both_halves item does:
// the batch is one pair, and its halves were sent once. On an add only the paired types have other halves; on
// a removal every type has.
void drop_requested_halves(const std::vector<ReferenceChange>& requested, const OtherHalves& halves, bool add,
  std::vector<ReferenceChange>& others, std::vector<std::size_t>& otherFor,
  std::vector<OtherHalf>& otherRules)
{
  std::unordered_set<HalfKey, HalfKeyHash> uniqueChanges;
  for (const auto& change : requested)
  {
    if (change.target.is_local() && (!add || other_half_of(halves, change.referenceType) != OtherHalf::None))
    {
      uniqueChanges.insert(
        HalfKey{change.source, change.referenceType, change.target.node_id(), change.isForward});
    }
  }
  std::size_t kept = 0;
  for (std::size_t k = 0; k < others.size(); ++k)
  {
    const auto& other = others[k];
    if (uniqueChanges.contains(
          HalfKey{other.source, other.referenceType, other.target.node_id(), other.isForward}))
    {
      continue;
    }
    if (kept != k)
    {
      others[kept] = std::move(others[k]);
      otherFor[kept] = otherFor[k];
      otherRules[kept] = otherRules[k];
    }
    ++kept;
  }
  others.resize(kept);
  otherFor.resize(kept);
  otherRules.resize(kept);
}

// Logs the other half of a Reference that could not be added or removed.
void log_other_half(
  const Logger& logger, const ReferenceChange& other, const StatusCode& status, bool add) noexcept
{
  try
  {
    const std::string sourceText = to_string(other.source);
    const std::string typeText = to_string(other.referenceType);
    const std::string targetText = to_string(other.target);
    const std::string statusText = to_string(status);
    const std::string errorText = status.shared_detail() ? to_string(*status.shared_detail()) : std::string{};
    // Two calls: the message is a fmt format string, which must be a literal checked when compiled.
    if (add)
    {
      logger.with_category("address_space")
        .warning({{"source", sourceText},
                   {"reference_type", typeText},
                   {"target", targetText},
                   {"status", statusText},
                   {"error", errorText}},
          "Could not add the other half of a reference whose type the address space pairs; the requested "
          "half "
          "was added");
    }
    else
    {
      logger.with_category("address_space")
        .warning({{"source", sourceText},
                   {"reference_type", typeText},
                   {"target", targetText},
                   {"status", statusText},
                   {"error", errorText}},
          "Could not remove the other half of a reference; the requested half was removed");
    }
  }
  catch (...)
  {
    ignore_expected_exception();
  }
}

// Whether @p answer says the Node holds the half asked for already: Bad_DuplicateReferenceNotAllowed without
// the ErrorDetail `DuplicateReferenceOfAnotherType`, which a namespace gives when it holds the Reference with
// a type that is neither the one asked for nor a subtype of it (`Namespace::add_references_async`).
bool holds_the_half_asked_for(const VoidResult& answer) noexcept
{
  if (answer.status_code().as_status() != Status::BadDuplicateReferenceNotAllowed)
  {
    return false;
  }
  const auto& detail = answer.shared_detail();
  return !detail || detail->code != "DuplicateReferenceOfAnotherType";
}

// The answer of a change whose other half the route sent: its own, combined by combined_status with the other
// half's when that is Good, so that a Good subcode on either reaches the caller, unless the other half
// failed. A half that is already held (on an add) or not held (on a removal), and a target Node that does not
// exist, are not failures. A failed other half is logged; it is answered with its StatusCode and an
// ErrorDetail naming it only where @p rule requires that half (see OtherHalf), and the change's own half was
// not already held and answered so.
VoidResult paired_answer(VoidResult own, const ReferenceChange& other, const VoidResult& otherAnswer,
  bool add, OtherHalf rule, const Logger& logger)
{
  if (otherAnswer.is_good())
  {
    return own.is_bad() ? std::move(own)
                        : VoidResult{combined_status(own.status_code(), otherAnswer.status_code())};
  }
  const Status status = otherAnswer.status_code().as_status();
  if (status == Status::BadNodeIdUnknown ||
      (add ? holds_the_half_asked_for(otherAnswer) : status == Status::UncertainReferenceNotDeleted))
  {
    return own;
  }
  log_other_half(logger, other, otherAnswer.status_code(), add);
  const bool required =
    rule == OtherHalf::Required || (rule == OtherHalf::InverseRequired && !other.isForward);
  if (own.is_bad() || !required)
  {
    return own;
  }
  return VoidResult{otherAnswer.status_code(),
    ErrorDetail::build(add ? "OtherHalfNotAdded" : "OtherHalfNotRemoved",
      add ? "The requested half of this reference was added; the other half, which the type requires, was not"
          : "The requested half of this reference was removed; the other half, which the type requires, was "
            "not",
      "NodeAccessorRoute")
      .context(ContextKeys::nodeId, to_string(other.source))
      .context(ContextKeys::namespaceIndex, std::to_string(other.source.namespace_index()))
      .context(ContextKeys::typeId, to_string(other.referenceType))
      .cause(otherAnswer.status_code())};
}

/// Whether a subtype's ValueRank @p restated keeps to its supertype's @p inherited (Part 3 6.2.7 b): Any may
/// become any value, ScalarOrOneDimension Scalar or one dimension, OneOrMoreDimensions a number of
/// dimensions; every other value stays as it is.
bool value_rank_kept(int32_t inherited, int32_t restated)
{
  if (restated == inherited)
  {
    return true;
  }
  switch (inherited)
  {
  case ValueRank::any:
    return true;
  case ValueRank::scalarOrOneDimension:
    return restated == ValueRank::scalar || restated == 1;
  case ValueRank::oneOrMore:
    return restated > 0;
  default:
    return false;
  }
}

/// The refusal of a HasSubtype from the VariableType @p super to the VariableType @p sub under Part 3 6.2.7 b
/// and c, read from their descriptions, or nullopt. An Attribute either type does not state is not compared.
std::optional<VoidResult> rank_or_dimensions_refusal(
  const NodeDescription& super, const NodeDescription& sub, const NodeId& subId)
{
  const auto inheritedRank = super.value_rank();
  const auto restatedRank = sub.value_rank();
  if (inheritedRank && restatedRank && !value_rank_kept(inheritedRank->as_int32(), restatedRank->as_int32()))
  {
    return VoidResult{Status::BadReferenceNotAllowed,
      ErrorDetail::build("SubtypeValueRankNotRestricted",
        "A VariableType subtype's ValueRank is neither its supertype's nor a restriction of it",
        "NodeAccessorRoute")
        .context(ContextKeys::nodeId, to_string(subId))
        .context(ContextKeys::expected, std::to_string(inheritedRank->as_int32()))
        .context(ContextKeys::actual, std::to_string(restatedRank->as_int32()))};
  }
  const auto* inherited = super.array_dimensions();
  const auto* restated = sub.array_dimensions();
  if (inherited == nullptr || restated == nullptr || inherited->empty() || restated->empty())
  {
    return std::nullopt;
  }
  if (inherited->size() != restated->size())
  {
    return VoidResult{Status::BadReferenceNotAllowed,
      ErrorDetail::build("SubtypeArrayDimensionsSizeMismatch",
        "A VariableType subtype changes the number of dimensions fixed by its supertype",
        "NodeAccessorRoute")
        .context(ContextKeys::nodeId, to_string(subId))
        .context(ContextKeys::expected, std::to_string(inherited->size()))
        .context(ContextKeys::actual, std::to_string(restated->size()))};
  }
  for (std::size_t dimension = 0; dimension < inherited->size(); ++dimension)
  {
    if ((*inherited)[dimension] != 0U && (*inherited)[dimension] != (*restated)[dimension])
    {
      return VoidResult{Status::BadReferenceNotAllowed,
        ErrorDetail::build("SubtypeArrayDimensionChanged",
          "A VariableType subtype changes an ArrayDimensions entry fixed by its supertype",
          "NodeAccessorRoute")
          .context(ContextKeys::nodeId, to_string(subId))
          .context(ContextKeys::index, std::to_string(dimension))
          .context(ContextKeys::expected, std::to_string((*inherited)[dimension]))
          .context(ContextKeys::actual, std::to_string((*restated)[dimension]))};
    }
  }
  return std::nullopt;
}

/// What the lookup of a call's HasSubtype changes found, per change (NR-52): whether both ends are
/// VariableTypes, the refusal rules b and c give, and the DataTypes rule a must compare, as (the subtype's,
/// the supertype's).
struct SubtypeChecks
{
  std::vector<bool> betweenVariableTypes;
  std::vector<std::optional<VoidResult>> refusals;
  std::vector<std::optional<std::pair<NodeId, NodeId>>> dataTypes;
  std::vector<NodeId> subtypes;
};

/// Looks up both ends of @p changes, each a HasSubtype with a local target, in one lookup, and where both are
/// VariableTypes applies Part 3 6.2.7 b and c from their descriptions and records the DataTypes for rule a.
/// An end that is not found or not a VariableType leaves the change unchecked. @p done is called once.
void look_up_subtypes(const WeakAddressSpace& addressSpace, const shared_ptr<const RequestInfo>& request,
  const shared_ptr<const std::vector<ReferenceChange>>& changes,
  std::function<void(Result<SubtypeChecks>)> done) noexcept
{
  try
  {
    std::vector<LookupItem> lookups;
    lookups.reserve(2 * changes->size());
    for (const auto& change : *changes)
    {
      lookups.push_back(LookupItem{change.source, std::nullopt});
      lookups.push_back(LookupItem{change.target.node_id(), std::nullopt});
    }
    NodeAccessorRoute::find_nodes(addressSpace,
      *request,
      lookups,
      [changes, done](BatchResult<NodeAccessorResult> found) mutable
      {
        Result<SubtypeChecks> checks{SubtypeChecks{}};
        try
        {
          auto& checked = checks.value();
          const std::size_t count = changes->size();
          checked.betweenVariableTypes.assign(count, false);
          checked.refusals.resize(count);
          checked.dataTypes.resize(count);
          checked.subtypes.resize(count);
          // A lookup that fails leaves the check undecided, and the change is refused with the failure rather
          // than added unchecked (NR-52).
          const auto refuse = [&checked](std::size_t i, VoidResult failure)
          {
            checked.betweenVariableTypes[i] = true;
            checked.refusals[i] = std::move(failure);
          };
          for (std::size_t i = 0; i < count; ++i)
          {
            if (!found.batchStatus.is_good())
            {
              refuse(i, found.batchStatus);
              continue;
            }
            if (2 * i + 1 >= found.items.size())
            {
              refuse(i, VoidResult{StatusCode{Status::BadInternalError}});
              continue;
            }
            // Not fatal: the add itself answers a source that is not found, and a target that is not found
            // gets no half (NR-30); neither is a VariableType this check could compare.
            const auto& sourceFound = found.items[2 * i];
            const auto& targetFound = found.items[2 * i + 1];
            if (sourceFound.status_code().as_status() == Status::BadNodeIdUnknown ||
                targetFound.status_code().as_status() == Status::BadNodeIdUnknown)
            {
              continue;
            }
            if (!sourceFound.is_good() || !targetFound.is_good())
            {
              const bool sourceFailed = !sourceFound.is_good();
              const auto& change = (*changes)[i];
              refuse(i,
                VoidResult{lookup_failure(sourceFailed ? change.source : change.target.node_id(),
                  (sourceFailed ? sourceFound : targetFound).status_code(),
                  "NodeAccessorRoute")});
              continue;
            }
            const auto source = NodeAccessorRoute::attributes(found.items[2 * i].value());
            const auto target = NodeAccessorRoute::attributes(found.items[2 * i + 1].value());
            // Not fatal: 6.2.7 constrains only a HasSubtype between VariableTypes, and any other is added
            // unchecked.
            if (!source.is_good() || !target.is_good() ||
                source.value().node_class() != NodeClass::VariableType ||
                target.value().node_class() != NodeClass::VariableType)
            {
              continue;
            }
            const auto& change = (*changes)[i];
            const auto& super = change.isForward ? source.value() : target.value();
            const auto& sub = change.isForward ? target.value() : source.value();
            checked.betweenVariableTypes[i] = true;
            checked.subtypes[i] = change.isForward ? change.target.node_id() : change.source;
            checked.refusals[i] = rank_or_dimensions_refusal(super, sub, checked.subtypes[i]);
            const NodeId* inheritedType = super.data_type();
            const NodeId* restatedType = sub.data_type();
            if (!checked.refusals[i] && inheritedType != nullptr && restatedType != nullptr &&
                *inheritedType != *restatedType)
            {
              checked.dataTypes[i] = std::pair{*restatedType, *inheritedType};
            }
          }
        }
        catch (...)
        {
          checks = Result<SubtypeChecks>{exception_to_status_code(std::current_exception())};
        }
        invoke_user_callback(done, std::move(checks));
      });
  }
  catch (...)
  {
    invoke_user_callback(done, Result<SubtypeChecks>{exception_to_status_code(std::current_exception())});
  }
}

/// Part 3 6.2.7 a on the changes @p checks records DataTypes for: whether the subtype's DataType is the
/// supertype's or a subtype of it, by walking its supertypes (@ref ua::SubtypeFacts::decide_async). A
/// DataType that does not exist, a remote supertype or a chain past the walk bound is not a subtype; a walk
/// that fails otherwise refuses the change with its failure. @p done receives @p checks with those refusals
/// added, once.
void check_data_types(const WeakAddressSpace& addressSpace, const shared_ptr<const RequestInfo>& request,
  SubtypeChecks checks, std::function<void(SubtypeChecks)> done) noexcept
{
  std::vector<std::pair<NodeId, NodeId>> questions;
  std::vector<std::size_t> askedFor;
  try
  {
    for (std::size_t i = 0; i < checks.dataTypes.size(); ++i)
    {
      const auto& dataType = checks.dataTypes[i];
      if (dataType)
      {
        questions.push_back(dataType.value());
        askedFor.push_back(i);
      }
    }
  }
  catch (...)
  {
    for (std::size_t i = 0; i < checks.dataTypes.size(); ++i)
    {
      if (checks.dataTypes[i])
      {
        checks.refusals[i] = VoidResult{exception_to_status_code(std::current_exception())};
      }
    }
    invoke_user_callback(done, std::move(checks));
    return;
  }
  if (questions.empty())
  {
    invoke_user_callback(done, std::move(checks));
    return;
  }
  auto owner = addressSpace.lock();
  if (!owner)
  {
    for (const std::size_t i : askedFor)
    {
      checks.refusals[i] = VoidResult{address_space_gone("NodeAccessorRoute")};
    }
    invoke_user_callback(done, std::move(checks));
    return;
  }
  ::ua::SubtypeFacts::decide_async(*owner,
    *request,
    std::move(questions),
    ::ua::SubtypeFacts::Bounds{::ua::maxTypeWalkDepth, nullptr},
    [checks = std::move(checks), askedFor = std::move(askedFor), done = std::move(done)](
      std::vector<BoolResult> answers) mutable
    {
      try
      {
        for (std::size_t k = 0; k < askedFor.size(); ++k)
        {
          if (k < answers.size() && answers[k].is_good() && answers[k].value())
          {
            continue;
          }
          const std::size_t i = askedFor[k];
          if (k < answers.size() && !answers[k].is_good())
          {
            checks.refusals[i] = VoidResult{answers[k].status_code(), answers[k].shared_detail()};
            continue;
          }
          const auto& [restated, inherited] = *checks.dataTypes[i];
          checks.refusals[i] =
            answers.empty()
              ? VoidResult{Status::BadInternalError,
                  ErrorDetail::build("SubtypeCheckNotRun",
                    "The walk of the subtype's DataType could not start",
                    "NodeAccessorRoute")
                    .context(ContextKeys::nodeId, to_string(checks.subtypes[i]))}
              : VoidResult{Status::BadReferenceNotAllowed,
                  ErrorDetail::build("SubtypeDataTypeNotASubtype",
                    "A VariableType subtype's DataType is neither its supertype's nor a subtype of it",
                    "NodeAccessorRoute")
                    .context(ContextKeys::nodeId, to_string(checks.subtypes[i]))
                    .context(ContextKeys::expected, to_string(inherited))
                    .context(ContextKeys::actual, to_string(restated))};
        }
      }
      catch (...)
      {
        for (const std::size_t i : askedFor)
        {
          checks.refusals[i] = VoidResult{exception_to_status_code(std::current_exception())};
        }
      }
      invoke_user_callback(done, std::move(checks));
    });
}

}  // namespace

ResumeToken::ResumeToken(ByteString token, weak_ptr<Namespace> issuer, Logger logger) noexcept
  : mToken(std::move(token)), mIssuer(std::move(issuer)), mLogger(std::move(logger))
{}

ResumeToken::ResumeToken(ResumeToken&& other) noexcept
  : mToken(other.take()), mIssuer(std::move(other.mIssuer)), mLogger(std::move(other.mLogger))
{}

ResumeToken& ResumeToken::operator=(ResumeToken&& other) noexcept
{
  if (this != &other)
  {
    release();
    mToken = other.take();
    mIssuer = std::move(other.mIssuer);
    mLogger = std::move(other.mLogger);
  }
  return *this;
}

ResumeToken::~ResumeToken()
{
  release();
}

bool ResumeToken::empty() const noexcept
{
  return mToken.empty();
}

ByteString ResumeToken::take() noexcept
{
  ByteString token = std::move(mToken);
  mToken = ByteString{};
  return token;
}

void ResumeToken::release() noexcept
{
  if (mToken.empty())
  {
    return;
  }
  ByteString token = take();
  try
  {
    if (auto issuer = mIssuer.lock())
    {
      issuer->release_resume_token(std::move(token));
    }
  }
  catch (...)
  {
    try
    {
      log_exception(mLogger.with_category("address_space"),
        LogLevel::Warning,
        "Namespace::release_resume_token",
        std::current_exception());
    }
    catch (...)
    {
      ignore_expected_exception();
    }
  }
}

NodeAccessorRoute::Bound NodeAccessorRoute::bound_of(const NodeAccessor& accessor, const NodeId& nodeId)
{
  Bound nodeBinding;
  nodeBinding.node = accessor.mNode;
  nodeBinding.registrationRoute = accessor.mAddressSpace.mRegistrationRoute;
  nodeBinding.addressSpace = accessor.mAddressSpace.mImpl.lock();
  if (!nodeBinding.addressSpace)
  {
    nodeBinding.failure = StatusCode{Status::BadShutdown,
      ErrorDetail::build(
        "AccessorWithoutAddressSpace", "The accessor's address space no longer exists", "NodeAccessor")
        .context(ContextKeys::nodeId, to_string(nodeId))};
    return nodeBinding;
  }
  nodeBinding.nameSpace =
    nodeBinding.addressSpace->resolve_namespace(nodeId.namespace_index(), nodeBinding.registrationRoute);
  if (!nodeBinding.nameSpace)
  {
    nodeBinding.failure = StatusCode{Status::BadNodeIdUnknown,
      ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "NodeAccessor")
        .context(ContextKeys::namespaceIndex, std::to_string(nodeId.namespace_index()))};
  }
  return nodeBinding;
}

void NodeAccessorRoute::find_nodes(const WeakAddressSpace& addressSpace, const RequestInfo& request,
  std::span<const LookupItem> items, AddressSpace::FindNodesCompleteCallback callback,
  std::optional<WeakAddressSpace> requiredAddressSpace) noexcept
{
  auto impl = addressSpace.mImpl.lock();
  if (impl)
  {
    impl->find_nodes_async(
      request, items, std::move(callback), addressSpace.mRegistrationRoute, std::move(requiredAddressSpace));
    return;
  }
  BatchResult<NodeAccessorResult> result;
  try
  {
    result.items.reserve(items.size());
    for (const auto& item : items)
    {
      result.items.emplace_back(StatusCode{Status::BadShutdown,
        ErrorDetail::build("AddressSpaceGone", "The address space no longer exists", "NodeAccessorRoute")
          .context(ContextKeys::nodeId, to_string(item.nodeId))});
    }
  }
  catch (...)
  {
    result.items.clear();
    result.batchStatus = VoidResult{exception_to_status_code(std::current_exception())};
  }
  invoke_user_callback(callback, std::move(result));
}

void NodeAccessorRoute::create_nodes(const WeakAddressSpace& addressSpace, const RequestInfo& request,
  shared_ptr<const std::vector<NodeCreation>> creations,
  std::function<void(std::vector<NodeAccessorResult>)> callback) noexcept
{
  auto impl = addressSpace.mImpl.lock();
  if (impl)
  {
    impl->create_nodes_async(
      request, std::move(creations), std::move(callback), addressSpace.mRegistrationRoute);
    return;
  }
  std::vector<NodeAccessorResult> answers;
  try
  {
    answers.assign(
      creations ? creations->size() : 0, NodeAccessorResult{address_space_gone("NodeAccessorRoute")});
  }
  catch (...)
  {
    answers.clear();
  }
  invoke_user_callback(callback, std::move(answers));
}

void NodeAccessorRoute::add_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
  shared_ptr<const std::vector<ReferenceChange>> changes,
  std::function<void(std::vector<VoidResult>)> callback, bool addRequiredPairs,
  shared_ptr<ModelChangeStep> step) noexcept
{
  try
  {
    step = operation_step(addressSpace.mImpl, std::move(step), callback);
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(
        changes ? changes->size() : 0, VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(callback, std::move(all));
    return;
  }
  // The add itself: with the other halves the address space adds, or only the halves given when the caller
  // sends both itself.
  const auto add = [addRequiredPairs, step](const WeakAddressSpace& space,
                     const shared_ptr<const RequestInfo>& info,
                     shared_ptr<const std::vector<ReferenceChange>>
                       sent,
                     std::function<void(std::vector<VoidResult>)>
                       answer)
  {
    if (addRequiredPairs)
    {
      change_references(space, *info, std::move(sent), /*add=*/true, std::move(answer), step);
      return;
    }
    send_changes(space, info, std::move(sent), /*add=*/true, std::move(answer), step);
  };
  const auto answerAll =
    [](std::size_t count, const StatusCode& status, std::function<void(std::vector<VoidResult>)>& to)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(count, VoidResult{status});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(to, std::move(all));
  };

  try
  {
    changes = with_index_targets(addressSpace.mImpl.lock(), std::move(changes));
  }
  catch (...)
  {
    answerAll(changes ? changes->size() : 0, exception_to_status_code(std::current_exception()), callback);
    return;
  }

  // The HasSubtype changes with a local target are looked up first. Those between VariableTypes are checked
  // against Part 3 6.2.7 (NR-52) and added after the call's other changes are held, so that the walk of rule
  // a sees a DataType's HasSubtype added in the same call.
  shared_ptr<const RequestInfo> heldRequest;
  std::vector<std::size_t> candidates;
  shared_ptr<const std::vector<ReferenceChange>> candidateChanges;
  try
  {
    heldRequest = std::make_shared<const RequestInfo>(request);
    const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
    std::vector<ReferenceChange> looked;
    for (std::size_t i = 0; changes && i < changes->size(); ++i)
    {
      if ((*changes)[i].referenceType == hasSubtype && (*changes)[i].target.is_local())
      {
        candidates.push_back(i);
        looked.push_back((*changes)[i]);
      }
    }
    if (!candidates.empty())
    {
      candidateChanges = std::make_shared<const std::vector<ReferenceChange>>(std::move(looked));
    }
  }
  catch (...)
  {
    answerAll(changes ? changes->size() : 0, exception_to_status_code(std::current_exception()), callback);
    return;
  }
  if (candidates.empty())
  {
    add(addressSpace, heldRequest, std::move(changes), std::move(callback));
    return;
  }

  look_up_subtypes(addressSpace,
    heldRequest,
    candidateChanges,
    [add,
      answerAll,
      addressSpace,
      heldRequest,
      changes,
      candidates = std::move(candidates),
      candidateChanges,
      callback = std::move(callback)](Result<SubtypeChecks> looked) mutable
    {
      if (!looked.is_good())
      {
        answerAll(changes->size(), looked.status_code(), callback);
        return;
      }
      // What the call answers, the checked changes' positions in it and in the lookup, and the checks.
      struct Checking
      {
        std::vector<VoidResult> answers;
        std::vector<std::size_t> checkedAt;
        std::vector<std::size_t> checkedK;
        SubtypeChecks checks;
        std::function<void(std::vector<VoidResult>)> callback;
      };
      shared_ptr<Checking> checking;
      shared_ptr<const std::vector<ReferenceChange>> rest;
      std::vector<std::size_t> restAt;
      try
      {
        checking = std::make_shared<Checking>();
        checking->answers.resize(changes->size());
        checking->checks = std::move(looked).value();
        std::vector<bool> isChecked(changes->size(), false);
        for (std::size_t k = 0; k < candidates.size(); ++k)
        {
          if (checking->checks.betweenVariableTypes[k])
          {
            isChecked[candidates[k]] = true;
            checking->checkedAt.push_back(candidates[k]);
            checking->checkedK.push_back(k);
          }
        }
        std::vector<ReferenceChange> restChanges;
        for (std::size_t i = 0; i < changes->size(); ++i)
        {
          if (!isChecked[i])
          {
            restAt.push_back(i);
            restChanges.push_back((*changes)[i]);
          }
        }
        rest = std::make_shared<const std::vector<ReferenceChange>>(std::move(restChanges));
        checking->callback = std::move(callback);
      }
      catch (...)
      {
        answerAll(changes->size(),
          exception_to_status_code(std::current_exception()),
          checking && checking->callback ? checking->callback : callback);
        return;
      }

      // The changes between VariableTypes: rule a decided, the refused answered, the rest added.
      auto checkAndAdd = [add, addressSpace, heldRequest, candidateChanges, checking]()
      {
        check_data_types(addressSpace,
          heldRequest,
          std::move(checking->checks),
          [add, addressSpace, heldRequest, candidateChanges, checking](SubtypeChecks checks)
          {
            std::vector<std::size_t> passedAt;
            shared_ptr<const std::vector<ReferenceChange>> passed;
            try
            {
              std::vector<ReferenceChange> passing;
              for (std::size_t j = 0; j < checking->checkedAt.size(); ++j)
              {
                const std::size_t k = checking->checkedK[j];
                if (checks.refusals[k])
                {
                  checking->answers[checking->checkedAt[j]] = std::move(*checks.refusals[k]);
                  continue;
                }
                passedAt.push_back(checking->checkedAt[j]);
                passing.push_back((*candidateChanges)[k]);
              }
              passed = std::make_shared<const std::vector<ReferenceChange>>(std::move(passing));
            }
            catch (...)
            {
              checking->answers.assign(
                checking->answers.size(), VoidResult{exception_to_status_code(std::current_exception())});
              invoke_user_callback(checking->callback, std::move(checking->answers));
              return;
            }
            if (passed->empty())
            {
              invoke_user_callback(checking->callback, std::move(checking->answers));
              return;
            }
            add(addressSpace,
              heldRequest,
              std::move(passed),
              [checking, passedAt = std::move(passedAt)](std::vector<VoidResult> added)
              {
                for (std::size_t j = 0; j < passedAt.size() && j < added.size(); ++j)
                {
                  checking->answers[passedAt[j]] = std::move(added[j]);
                }
                invoke_user_callback(checking->callback, std::move(checking->answers));
              });
          });
      };
      if (checking->checkedAt.empty() || rest->empty())
      {
        if (checking->checkedAt.empty())
        {
          // Nothing between VariableTypes: the call as given.
          add(addressSpace, heldRequest, changes, std::move(checking->callback));
          return;
        }
        checkAndAdd();
        return;
      }
      add(addressSpace,
        heldRequest,
        std::move(rest),
        [checking, restAt = std::move(restAt), checkAndAdd](std::vector<VoidResult> added)
        {
          for (std::size_t k = 0; k < restAt.size() && k < added.size(); ++k)
          {
            checking->answers[restAt[k]] = std::move(added[k]);
          }
          checkAndAdd();
        });
    });
}

void NodeAccessorRoute::remove_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
  shared_ptr<const std::vector<ReferenceChange>> changes,
  std::function<void(std::vector<VoidResult>)> callback, bool removeOtherHalves,
  shared_ptr<ModelChangeStep> step) noexcept
{
  try
  {
    step = operation_step(addressSpace.mImpl, std::move(step), callback);
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(
        changes ? changes->size() : 0, VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(callback, std::move(all));
    return;
  }
  try
  {
    changes = with_index_targets(addressSpace.mImpl.lock(), std::move(changes));
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(
        changes ? changes->size() : 0, VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(callback, std::move(all));
    return;
  }
  if (removeOtherHalves)
  {
    change_references(
      addressSpace, request, std::move(changes), /*add=*/false, std::move(callback), std::move(step));
    return;
  }
  // Only the halves given, as the caller names them.
  shared_ptr<const RequestInfo> heldRequest;
  try
  {
    heldRequest = std::make_shared<const RequestInfo>(request);
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(
        changes ? changes->size() : 0, VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(callback, std::move(all));
    return;
  }
  send_changes(addressSpace,
    std::move(heldRequest),
    std::move(changes),
    /*add=*/false,
    std::move(callback),
    std::move(step));
}

void NodeAccessorRoute::change_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
  shared_ptr<const std::vector<ReferenceChange>> requested, bool add,
  std::function<void(std::vector<VoidResult>)> callback, shared_ptr<ModelChangeStep> step) noexcept
{
  shared_ptr<std::function<void(std::vector<VoidResult>)>> complete;
  shared_ptr<const RequestInfo> heldRequest;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<VoidResult>)>>(std::move(callback));
    heldRequest = std::make_shared<const RequestInfo>(request);
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(
        requested ? requested->size() : 0, VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }
  // The rule of each type first; then the requested halves; then the other half of each change whose own half
  // is held now (added or present on an add, removed or absent on a removal), so that a refused change leaves
  // no half of its Reference behind. An add sends the other half of a paired type; a removal that of every
  // type (OPC 10000-4 5.7.5.1), whose rule decides only whether its failure answers the change.
  classify_other_halves(addressSpace,
    heldRequest,
    *requested,
    [addressSpace, heldRequest, requested, add, complete, step](
      Result<shared_ptr<const OtherHalves>> classified) mutable
    {
      if (!classified.is_good())
      {
        std::vector<VoidResult> all;
        try
        {
          all.assign(requested->size(), VoidResult{classified.status_code(), classified.shared_detail()});
        }
        catch (...)
        {
          all.clear();
        }
        invoke_user_callback(*complete, std::move(all));
        return;
      }
      send_changes(
        addressSpace,
        heldRequest,
        requested,
        add,
        [addressSpace, heldRequest, requested, add, halves = std::move(classified).value(), complete, step](
          std::vector<VoidResult> answers)
        {
          std::vector<ReferenceChange> others;
          std::vector<std::size_t> otherFor;
          std::vector<OtherHalf> otherRules;
          Logger logger;
          try
          {
            for (std::size_t i = 0; i < answers.size() && i < requested->size(); ++i)
            {
              const auto& change = (*requested)[i];
              const Status status = answers[i].status_code().as_status();
              const bool held =
                answers[i].is_good() ||
                (add ? holds_the_half_asked_for(answers[i]) : status == Status::UncertainReferenceNotDeleted);
              const OtherHalf rule = other_half_of(*halves, change.referenceType);
              if (!held || (add && rule == OtherHalf::None))
              {
                continue;
              }
              // The address space adds these halves itself, so a caller adding one it holds already is not
              // refused (NR-30 rule 4); one held with another type is refused as the namespace answered.
              if (add && holds_the_half_asked_for(answers[i]))
              {
                answers[i] = VoidResult{};
              }
              if (!change.target.is_local())
              {
                continue;
              }
              others.push_back(ReferenceChange{change.target.node_id(),
                change.referenceType,
                ExpandedNodeId{change.source},
                !change.isForward,
                false});
              otherFor.push_back(i);
              otherRules.push_back(rule);
            }
            drop_requested_halves(*requested, *halves, add, others, otherFor, otherRules);
            if (auto impl = addressSpace.mImpl.lock())
            {
              logger = impl->logger();
            }
          }
          catch (...)
          {
            answers.assign(requested->size(), VoidResult{exception_to_status_code(std::current_exception())});
            invoke_user_callback(*complete, std::move(answers));
            return;
          }
          if (others.empty())
          {
            invoke_user_callback(*complete, std::move(answers));
            return;
          }
          auto sent = std::make_shared<const std::vector<ReferenceChange>>(std::move(others));
          send_changes(
            addressSpace,
            heldRequest,
            sent,
            add,
            [answers = std::move(answers),
              sent,
              otherFor = std::move(otherFor),
              otherRules = std::move(otherRules),
              add,
              logger = std::move(logger),
              complete](std::vector<VoidResult> otherAnswers) mutable
            {
              try
              {
                for (std::size_t k = 0; k < otherFor.size() && k < otherAnswers.size(); ++k)
                {
                  answers[otherFor[k]] = paired_answer(
                    std::move(answers[otherFor[k]]), (*sent)[k], otherAnswers[k], add, otherRules[k], logger);
                }
              }
              catch (...)
              {
                answers.assign(
                  answers.size(), VoidResult{exception_to_status_code(std::current_exception())});
              }
              invoke_user_callback(*complete, std::move(answers));
            },
            step);
        },
        step);
    });
}

void NodeAccessorRoute::send_changes(const WeakAddressSpace& addressSpace,
  shared_ptr<const RequestInfo> request, shared_ptr<const std::vector<ReferenceChange>> changes, bool add,
  std::function<void(std::vector<VoidResult>)> callback, shared_ptr<ModelChangeStep> step) noexcept
{
  using Route = NamespaceRoute<VoidResult>;
  shared_ptr<std::function<void(std::vector<VoidResult>)>> complete;
  std::vector<std::optional<VoidResult>> answers;
  std::vector<Route::Part> parts;
  std::optional<uint32_t> limit;
  weak_ptr<AddressSpaceImpl> space;
  const std::size_t count = changes ? changes->size() : 0;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<VoidResult>)>>(std::move(callback));
    auto impl = addressSpace.mImpl.lock();
    space = impl;
    if (!impl)
    {
      std::vector<VoidResult> gone(count, VoidResult{address_space_gone("NodeAccessorRoute")});
      invoke_user_callback(*complete, std::move(gone));
      return;
    }
    if (count == 0)
    {
      invoke_user_callback(*complete, std::vector<VoidResult>{});
      return;
    }
    const auto& operationLimits = impl->mOperationLimits;
    limit = operationLimits ? operationLimits.value().maxNodesPerNodeManagement : std::nullopt;
    answers.resize(count);
    // The part of each namespace, in the order the namespaces first appear.
    std::unordered_map<const Namespace*, std::size_t> partOf;
    for (std::size_t i = 0; i < count; ++i)
    {
      const uint16_t namespaceIndex = (*changes)[i].source.namespace_index();
      auto nameSpace = impl->resolve_namespace(namespaceIndex, addressSpace.mRegistrationRoute);
      if (!nameSpace)
      {
        answers[i] = VoidResult{StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "NodeAccessorRoute")
            .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex))}};
        continue;
      }
      add_to_part(parts, partOf, std::move(nameSpace), i);
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::vector<VoidResult> all;
    try
    {
      all.assign(count, VoidResult{failed});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }
  Route::run(
    std::move(answers),
    std::move(parts),
    limit,
    [changes, request, add, step](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<VoidResult>)>
        answer)
    {
      auto send = [&nameSpace, &request, add, &answer, &step](std::span<const ReferenceChange> items)
      {
        if (add)
        {
          nameSpace.add_references_async(
            *request, items, recording_changes(std::move(answer), *step, items, add));
        }
        else
        {
          nameSpace.remove_references_async(
            *request, items, recording_changes(std::move(answer), *step, items, add));
        }
      };
      // A namespace's chunk is consecutive changes when it is the only namespace: sent without copying.
      if (positions.back() - positions.front() + 1 == positions.size())
      {
        send(std::span<const ReferenceChange>{changes->data() + positions.front(), positions.size()});
        return;
      }
      std::vector<ReferenceChange> items;
      items.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        items.push_back((*changes)[position]);
      }
      send(items);
    },
    [changes, complete, space](std::vector<VoidResult> answered)
    {
      if (const auto owner = space.lock())
      {
        owner->model_changed_if_any(answered);
      }
      invoke_user_callback(*complete, std::move(answered));
    });
}

shared_ptr<ModelChangeStep> NodeAccessorRoute::model_change_step(const WeakAddressSpace& addressSpace)
{
  return ModelChangeStep::create(addressSpace.mImpl);
}

std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> NodeAccessorRoute::recording_writes(
  std::function<void(BatchResult<VoidResult>)> answer, ModelChangeStep& step,
  std::span<const ValueWriteItem> items)
{
  return record_writes(std::move(answer), step, items);
}

void NodeAccessorRoute::model_written(const WeakAddressSpace& addressSpace,
  std::span<const WriteValue> writes, std::span<const VoidResult> answers) noexcept
{
  for (std::size_t i = 0; i < writes.size() && i < answers.size(); ++i)
  {
    if (changes_the_model(writes[i]) && !answers[i].is_bad())
    {
      if (const auto owner = addressSpace.mImpl.lock())
      {
        owner->model_changed();
      }
      return;
    }
  }
}

std::optional<ServiceOperationLimits> NodeAccessorRoute::operation_limits(
  const WeakAddressSpace& addressSpace) noexcept
{
  const auto owner = addressSpace.mImpl.lock();
  if (!owner)
  {
    return std::nullopt;
  }
  return owner->mOperationLimits;
}

boost::asio::any_io_executor NodeAccessorRoute::executor(const NodeAccessor& accessor) noexcept
{
  const auto addressSpace = accessor.mAddressSpace.mImpl.lock();
  return addressSpace ? addressSpace->executor() : boost::asio::any_io_executor{};
}

shared_ptr<Node> NodeAccessorRoute::node_of(const NodeAccessor& accessor) noexcept
{
  return accessor.get_node_ptr();
}

std::optional<uint32_t> NodeAccessorRoute::browse_limit(const WeakAddressSpace& addressSpace) noexcept
{
  const auto owner = addressSpace.mImpl.lock();
  if (!owner)
  {
    return std::nullopt;
  }
  const auto& operationLimits = owner->mOperationLimits;
  if (!operationLimits)
  {
    return std::nullopt;
  }
  return operationLimits.value().maxNodesPerBrowse;
}

NodeAccessor NodeAccessorRoute::bound(shared_ptr<Node> node, weak_ptr<AddressSpaceImpl> addressSpace,
  shared_ptr<const NamespaceRegistrationRoute> registrationRoute)
{
  return NodeAccessor{
    std::move(node), WeakAddressSpace{std::move(addressSpace), std::move(registrationRoute)}};
}

void NodeAccessorRoute::read_references(const RequestInfo& request, std::vector<ReferenceRead> reads,
  std::function<void(std::vector<ReferencePage>)> callback,
  std::optional<WeakAddressSpace> requiredAddressSpace) noexcept
{
  using Route = NamespaceRoute<NodeReferencesResult>;

  // What the calls refer to, held until every namespace has answered: the reads with their Nodes and owning
  // namespaces, and a copy of the request, which is valid only until this call returns.
  struct State
  {
    std::vector<ReferenceRead> reads;
    std::vector<shared_ptr<Node>> nodes;
    std::vector<NodeId> nodeIds;
    std::vector<weak_ptr<Namespace>> owners;
    RequestInfo request;
    Logger logger;
  };

  shared_ptr<std::function<void(std::vector<ReferencePage>)>> complete;
  std::vector<std::optional<NodeReferencesResult>> answers;
  std::vector<Route::Part> parts;
  std::optional<uint32_t> limit;
  shared_ptr<State> state;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<ReferencePage>)>>(std::move(callback));
    state = std::make_shared<State>();
    state->reads = std::move(reads);
    state->request = request;
    const std::size_t count = state->reads.size();
    state->nodes.resize(count);
    state->nodeIds.resize(count);
    state->owners.resize(count);
    answers.resize(count);
    // The part of each namespace, in the order the namespaces first appear.
    std::unordered_map<const Namespace*, std::size_t> partOf;
    bool limitRead = false;
    for (std::size_t i = 0; i < count; ++i)
    {
      try
      {
        const ReferenceRead& read = state->reads[i];
        NodeId nodeId = read.node.get_node_id();
        Bound nodeBinding = bound_of(read.node, nodeId);
        if (nodeBinding.failure)
        {
          answers[i] = NodeReferencesResult{*nodeBinding.failure};
          continue;
        }
        if (!limitRead)
        {
          limitRead = true;
          const auto& operationLimits = nodeBinding.addressSpace->mOperationLimits;
          limit = operationLimits ? operationLimits.value().maxNodesPerBrowse : std::nullopt;
          state->logger = nodeBinding.addressSpace->logger();
        }
        state->nodes[i] = std::move(nodeBinding.node);
        state->nodeIds[i] = std::move(nodeId);
        state->owners[i] = nodeBinding.nameSpace;
        add_to_part(parts, partOf, std::move(nodeBinding.nameSpace), i);
      }
      catch (...)
      {
        answers[i] = NodeReferencesResult{exception_to_status_code(std::current_exception())};
      }
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::span<ReferenceRead> unissued = reads;
    if (state)
    {
      unissued = state->reads;
    }
    for (auto& read : unissued)
    {
      if (auto* token = std::get_if<ResumeToken>(&read.resumeToken))
      {
        token->release();
      }
    }
    std::vector<ReferencePage> all;
    try
    {
      const std::size_t count = state ? state->reads.size() : reads.size();
      all.reserve(count);
      for (std::size_t i = 0; i < count; ++i)
      {
        all.push_back(ReferencePage{NodeReferencesResult{failed}, {}});
      }
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }

  Route::run(
    std::move(answers),
    std::move(parts),
    limit,
    [state](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<NodeReferencesResult>)>
        answer)
    {
      std::vector<ReferenceQuery> queries;
      queries.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        const ReferenceRead& read = state->reads[position];
        queries.push_back(ReferenceQuery{*state->nodes[position],
          state->nodeIds[position],
          read.direction,
          read.hint,
          read.maxReferences,
          {}});
      }
      for (std::size_t query = 0; query < positions.size(); ++query)
      {
        auto& resumeToken = state->reads[positions[query]].resumeToken;
        if (auto* token = std::get_if<ResumeToken>(&resumeToken))
        {
          queries[query].resumeToken = token->take();
        }
        else
        {
          queries[query].resumeToken = std::move(std::get<ByteString>(resumeToken));
        }
      }
      nameSpace.read_references_async(state->request, queries, std::move(answer));
    },
    [state, complete](std::vector<NodeReferencesResult> found)
    {
      for (auto& read : state->reads)
      {
        if (auto* token = std::get_if<ResumeToken>(&read.resumeToken))
        {
          token->release();
        }
      }
      // Each answered token goes into its page's holder, which releases it if the page is dropped.
      std::vector<ReferencePage> pages;
      std::size_t built = 0;
      try
      {
        pages.reserve(found.size());
        for (; built < found.size(); ++built)
        {
          NodeReferencesResult& answer = found[built];
          ResumeToken token;
          if (answer.has_value() && !answer.value().resumeToken.empty())
          {
            token = ResumeToken{
              std::exchange(answer.value().resumeToken, ByteString{}), state->owners[built], state->logger};
          }
          pages.push_back(ReferencePage{std::move(answer), std::move(token)});
        }
      }
      catch (...)
      {
        // The pages built release their tokens as they go; the answers not yet built release theirs here.
        pages.clear();
        for (; built < found.size(); ++built)
        {
          NodeReferencesResult& answer = found[built];
          if (answer.has_value())
          {
            ResumeToken{
              std::exchange(answer.value().resumeToken, ByteString{}), state->owners[built], Logger{}}
              .release();
          }
        }
      }
      invoke_user_callback(*complete, std::move(pages));
    },
    std::move(requiredAddressSpace));
}

void NodeAccessorRoute::read_references(const NodeAccessor& accessor, uint32_t maxReferences,
  ByteString resumeToken, NodeAccessor::GetReferencesPageCallback callback) noexcept
{
  shared_ptr<NodeAccessor::GetReferencesPageCallback> complete;
  try
  {
    complete = std::make_shared<NodeAccessor::GetReferencesPageCallback>(std::move(callback));
    std::vector<ReferenceRead> reads;
    reads.push_back(
      ReferenceRead{accessor, BrowseDirection::Both, {}, maxReferences, std::move(resumeToken)});
    read_references(RequestInfo{},
      std::move(reads),
      [complete](std::vector<ReferencePage> pages)
      {
        try
        {
          if (pages.size() != 1)
          {
            invoke_user_callback(
              *complete, NodeAccessor::ReferencesPageResult{StatusCode{Status::BadOutOfMemory}});
            return;
          }
          // The page carries the namespace's code: a Good subcode, or an Uncertain code with the References
          // it holds.
          NodeReferencesResult& answer = pages.front().answer;
          if (!answer.has_value())
          {
            invoke_user_callback(*complete, NodeAccessor::ReferencesPageResult{answer.status_code()});
            return;
          }
          const StatusCode answered = answer.status_code();
          NodeReferences& page = answer.value();
          invoke_user_callback(*complete,
            NodeAccessor::ReferencesPageResult{
              NodeAccessor::ReferencePage{std::move(page.references), pages.front().resumeToken.take()},
              answered});
        }
        catch (...)
        {
          invoke_user_callback(*complete,
            NodeAccessor::ReferencesPageResult{exception_to_status_code(std::current_exception())});
        }
      });
  }
  catch (...)
  {
    invoke_user_callback(complete ? *complete : callback,
      NodeAccessor::ReferencesPageResult{exception_to_status_code(std::current_exception())});
  }
}

void NodeAccessorRoute::read_all_references(const NodeAccessor& accessor,
  NodeAccessor::GetReferencesCallback callback, std::optional<WeakAddressSpace> requiredAddressSpace) noexcept
{
  struct Pages
  {
    explicit Pages(NodeAccessor of) : accessor(std::move(of))
    {}

    NodeAccessor accessor;
    std::optional<WeakAddressSpace> requiredAddressSpace;
    std::vector<Reference> collected;
    // The code the pages read so far combine to: the answer carries a page's Good subcode or Uncertain code.
    StatusCode answered{Status::Good};
    NodeAccessor::GetReferencesCallback complete;
    std::function<void(ResumeToken)> next;
  };

  shared_ptr<Pages> pages;
  try
  {
    pages = std::make_shared<Pages>(accessor);
    pages->requiredAddressSpace = std::move(requiredAddressSpace);
    pages->complete = std::move(callback);
    // Each page asks for the next until no token is left. `next` holds the pages weakly; the read in flight
    // holds them.
    pages->next = [weakPages = weak_ptr<Pages>{pages}](ResumeToken token)
    {
      auto held = weakPages.lock();
      if (!held)
      {
        return;
      }
      std::vector<ReferenceRead> reads;
      try
      {
        std::optional<AddressSpace> requiredOwner;
        if (held->requiredAddressSpace)
        {
          requiredOwner = held->requiredAddressSpace->lock();
          if (!requiredOwner)
          {
            token.release();
            invoke_user_callback(std::exchange(held->complete, nullptr),
              NodeAccessor::ReferencesResult{address_space_gone("NodeAccessorRoute")});
            return;
          }
        }
        reads.push_back(ReferenceRead{held->accessor, BrowseDirection::Both, {}, 0, std::move(token)});
        read_references(
          RequestInfo{},
          std::move(reads),
          [held](std::vector<ReferencePage> receivedPages)
          {
            try
            {
              if (receivedPages.size() != 1)
              {
                for (auto& page : receivedPages)
                  page.resumeToken.release();
                invoke_user_callback(std::exchange(held->complete, nullptr),
                  NodeAccessor::ReferencesResult{StatusCode{Status::BadOutOfMemory}});
                return;
              }
              auto& page = receivedPages.front();
              if (!page.answer.has_value())
              {
                page.resumeToken.release();
                invoke_user_callback(std::exchange(held->complete, nullptr),
                  NodeAccessor::ReferencesResult{page.answer.status_code()});
                return;
              }
              held->answered = combined_status(held->answered, page.answer.status_code());
              NodeReferences& read = page.answer.value();
              const bool last = page.resumeToken.empty();
              if (last && held->collected.empty())
              {
                // A terminal single page is already the complete answer, even without its owner.
                invoke_user_callback(std::exchange(held->complete, nullptr),
                  NodeAccessor::ReferencesResult{std::move(read.references), held->answered});
                return;
              }
              held->collected.insert(held->collected.end(), read.references.begin(), read.references.end());
              if (last)
              {
                invoke_user_callback(std::exchange(held->complete, nullptr),
                  NodeAccessor::ReferencesResult{References{std::move(held->collected)}, held->answered});
                return;
              }
              held->next(std::move(page.resumeToken));
            }
            catch (...)
            {
              const auto failure = exception_to_status_code(std::current_exception());
              for (auto& page : receivedPages)
                page.resumeToken.release();
              invoke_user_callback(
                std::exchange(held->complete, nullptr), NodeAccessor::ReferencesResult{failure});
            }
          },
          held->requiredAddressSpace);
      }
      catch (...)
      {
        const auto failure = exception_to_status_code(std::current_exception());
        token.release();
        for (auto& read : reads)
        {
          if (auto holder = std::get_if<ResumeToken>(&read.resumeToken))
            holder->release();
        }
        invoke_user_callback(std::exchange(held->complete, nullptr), NodeAccessor::ReferencesResult{failure});
      }
    };
    pages->next(ResumeToken{});
  }
  catch (...)
  {
    invoke_user_callback(pages ? pages->complete : callback,
      NodeAccessor::ReferencesResult{exception_to_status_code(std::current_exception())});
  }
}

namespace
{

// An accessor's ReferenceHalves::ThisHalfOnly changes of @p changes: each type classified, a change that
// would leave a required half alone answered `Bad_NotSupported` and not sent, and the rest sent as given,
// through @ref NodeAccessorRoute::add_references or @ref NodeAccessorRoute::remove_references with no other
// half (which still resolve a target given by namespace URI, and check a HasSubtype between VariableTypes on
// an add). @p callback receives one answer per change, in change order, once.
void change_this_half_only(const WeakAddressSpace& addressSpace,
  shared_ptr<const std::vector<ReferenceChange>> changes, bool add,
  std::function<void(std::vector<VoidResult>)> callback) noexcept
{
  shared_ptr<std::function<void(std::vector<VoidResult>)>> complete;
  shared_ptr<const RequestInfo> request;
  const auto answerAll = [&changes](const shared_ptr<std::function<void(std::vector<VoidResult>)>>& to,
                           std::function<void(std::vector<VoidResult>)>& fallback,
                           const StatusCode& status)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(changes ? changes->size() : 0, VoidResult{status});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(to ? *to : fallback, std::move(all));
  };
  try
  {
    complete = std::make_shared<std::function<void(std::vector<VoidResult>)>>(std::move(callback));
    request = std::make_shared<const RequestInfo>();
  }
  catch (...)
  {
    answerAll(complete, callback, exception_to_status_code(std::current_exception()));
    return;
  }
  classify_other_halves(addressSpace,
    request,
    *changes,
    [addressSpace, changes, add, complete](Result<shared_ptr<const OtherHalves>> classified) mutable
    {
      std::vector<VoidResult> answers;
      std::vector<std::size_t> sentAt;
      shared_ptr<const std::vector<ReferenceChange>> sent;
      try
      {
        if (!classified.is_good())
        {
          answers.assign(changes->size(), VoidResult{classified.status_code(), classified.shared_detail()});
          invoke_user_callback(*complete, std::move(answers));
          return;
        }
        const auto& halves = *classified.value();
        // A change sent is answered by the namespace; until then it is a failure, so that an answer that
        // never arrives is not Good.
        answers.assign(changes->size(), VoidResult{StatusCode{Status::BadInternalError}});
        std::vector<ReferenceChange> sending;
        for (std::size_t i = 0; i < changes->size(); ++i)
        {
          const auto& change = (*changes)[i];
          const OtherHalf rule = other_half_of(halves, change.referenceType);
          if (leaves_a_required_half_alone(change, rule, add))
          {
            answers[i] = required_half_refusal(change, rule, add);
            continue;
          }
          sentAt.push_back(i);
          sending.push_back(change);
        }
        if (sending.empty())
        {
          invoke_user_callback(*complete, std::move(answers));
          return;
        }
        sent = std::make_shared<const std::vector<ReferenceChange>>(std::move(sending));
      }
      catch (...)
      {
        try
        {
          answers.assign(changes->size(), VoidResult{exception_to_status_code(std::current_exception())});
        }
        catch (...)
        {
          answers.clear();
        }
        invoke_user_callback(*complete, std::move(answers));
        return;
      }
      auto merge = [answers = std::move(answers), sentAt = std::move(sentAt), complete](
                     std::vector<VoidResult> answered) mutable
      {
        for (std::size_t k = 0; k < sentAt.size() && k < answered.size(); ++k)
        {
          answers[sentAt[k]] = std::move(answered[k]);
        }
        invoke_user_callback(*complete, std::move(answers));
      };
      if (add)
      {
        NodeAccessorRoute::add_references(
          addressSpace, RequestInfo{}, std::move(sent), std::move(merge), /*addRequiredPairs=*/false);
      }
      else
      {
        NodeAccessorRoute::remove_references(
          addressSpace, RequestInfo{}, std::move(sent), std::move(merge), /*removeOtherHalves=*/false);
      }
    });
}

}  // namespace

void NodeAccessorRoute::change_references(const NodeAccessor& accessor, std::vector<Reference> references,
  bool add, ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  shared_ptr<NodeAccessor::ReferenceModifyCallback> complete;
  try
  {
    complete = std::make_shared<NodeAccessor::ReferenceModifyCallback>(std::move(callback));
    const NodeId nodeId = accessor.get_node_id();
    Bound nodeBinding = bound_of(accessor, nodeId);
    if (nodeBinding.failure)
    {
      invoke_user_callback(*complete, VoidResult{*nodeBinding.failure});
      return;
    }
    if (references.empty())
    {
      invoke_user_callback(*complete, VoidResult{});
      return;
    }
    auto changes = std::make_shared<std::vector<ReferenceChange>>();
    changes->reserve(references.size());
    for (const auto& reference : references)
    {
      changes->push_back(ReferenceChange{nodeId,
        reference.type_id(),
        reference.target_id(),
        reference.is_forward(),
        false,
        reference.target_display_name()});
    }
    // A change with a local target goes through the batched entries when its own half alone is not the whole
    // change: with Both, an add whose type may be paired and every removal, whose other half is added or
    // removed; with ThisHalfOnly, a type that may require its other half, which may be refused. A HasSubtype
    // is then checked between VariableTypes (NR-52), and a target given by namespace URI is resolved.
    const bool both = halves == ReferenceHalves::Both;
    if (std::any_of(changes->begin(),
          changes->end(),
          [add, both](const ReferenceChange& change)
          {
            if (!change.target.is_local())
            {
              return false;
            }
            if (change.target.is_not_index_based())
            {
              return true;
            }
            return both ? (!add || may_be_paired(change.referenceType))
                        : may_require_its_other_half(change.referenceType);
          }))
    {
      auto answer = [complete](std::vector<VoidResult> answers)
      {
        invoke_user_callback(*complete, first_failure(std::move(answers)));
      };
      if (!both)
      {
        change_this_half_only(accessor.mAddressSpace, std::move(changes), add, std::move(answer));
      }
      else if (add)
      {
        add_references(accessor.mAddressSpace, RequestInfo{}, std::move(changes), std::move(answer));
      }
      else
      {
        remove_references(accessor.mAddressSpace, RequestInfo{}, std::move(changes), std::move(answer));
      }
      return;
    }
    const std::size_t count = changes->size();
    auto step = ModelChangeStep::create(nodeBinding.addressSpace);
    call_namespace<VoidResult>(
      std::move(nodeBinding.nameSpace),
      count,
      [changes, add, step](Namespace& nameSpace, std::function<void(BatchResult<VoidResult>)> answer)
      {
        if (add)
        {
          nameSpace.add_references_async(
            RequestInfo{}, *changes, recording_changes(std::move(answer), *step, *changes, add));
        }
        else
        {
          nameSpace.remove_references_async(
            RequestInfo{}, *changes, recording_changes(std::move(answer), *step, *changes, add));
        }
      },
      [changes, complete, step, space = weak_ptr<AddressSpaceImpl>{nodeBinding.addressSpace}](
        std::vector<VoidResult> answers)
      {
        if (const auto owner = space.lock())
        {
          owner->model_changed_if_any(answers);
        }
        step->close([complete, answer = first_failure(std::move(answers))]() mutable
          { invoke_user_callback(*complete, std::move(answer)); });
      });
  }
  catch (...)
  {
    invoke_user_callback(
      complete ? *complete : callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void NodeAccessorRoute::read_values(const RequestInfo& request, const CallerInfo* caller,
  std::vector<ValueRead> reads, Duration maxAge, bool setSourceTimestamp,
  std::function<void(std::vector<DataValueResult>)> callback,
  std::optional<WeakAddressSpace> requiredAddressSpace) noexcept
{
  using Route = NamespaceRoute<DataValueResult>;

  // What the calls refer to, held until every namespace has answered: the reads with their Nodes, parsed
  // IndexRanges and owning namespaces, and copies of the request and the caller, which are valid only until
  // this call returns. The namespaces are held weakly, since the completions the route gives them hold this.
  struct State
  {
    std::vector<ValueRead> reads;
    std::vector<shared_ptr<Node>> nodes;
    std::vector<ParsedNumericRange> ranges;
    std::vector<weak_ptr<Namespace>> owners;
    RequestInfo request;
    std::optional<CallerInfo> caller;
    Duration maxAge{0};
    bool setSourceTimestamp{false};
  };

  shared_ptr<std::function<void(std::vector<DataValueResult>)>> complete;
  std::vector<std::optional<DataValueResult>> answers;
  std::vector<Route::Part> parts;
  std::optional<uint32_t> limit;
  shared_ptr<State> state;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<DataValueResult>)>>(std::move(callback));
    state = std::make_shared<State>();
    state->reads = std::move(reads);
    state->request = request;
    if (caller != nullptr)
    {
      state->caller = *caller;
    }
    state->maxAge = maxAge;
    state->setSourceTimestamp = setSourceTimestamp;
    const std::size_t count = state->reads.size();
    state->nodes.resize(count);
    state->ranges.resize(count);
    state->owners.resize(count);
    answers.resize(count);
    // The part of each namespace, in the order the namespaces first appear.
    std::unordered_map<const Namespace*, std::size_t> partOf;
    bool limitRead = false;
    for (std::size_t i = 0; i < count; ++i)
    {
      try
      {
        const ValueRead& read = state->reads[i];
        auto parsed = parse_numeric_range(read.value.index_range());
        if (!parsed.is_good())
        {
          answers[i] = DataValueResult{parsed.status_code()};
          continue;
        }
        Bound nodeBinding = bound_of(read.variable, read.variable.get_node_id());
        if (nodeBinding.failure)
        {
          answers[i] = DataValueResult{*nodeBinding.failure};
          continue;
        }
        if (!limitRead)
        {
          limitRead = true;
          const auto& operationLimits = nodeBinding.addressSpace->mOperationLimits;
          limit = operationLimits ? operationLimits.value().maxNodesPerRead : std::nullopt;
        }
        state->nodes[i] = std::move(nodeBinding.node);
        state->ranges[i] = std::move(parsed).value();
        state->owners[i] = nodeBinding.nameSpace;
        add_to_part(parts, partOf, std::move(nodeBinding.nameSpace), i);
      }
      catch (...)
      {
        answers[i] = DataValueResult{exception_to_status_code(std::current_exception())};
      }
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::vector<DataValueResult> all;
    try
    {
      const std::size_t count = state ? state->reads.size() : reads.size();
      all.assign(count, DataValueResult{failed});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }

  Route::run(
    std::move(answers),
    std::move(parts),
    limit,
    [state](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<DataValueResult>)>
        answer)
    {
      std::vector<ValueReadItem> items;
      items.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        items.push_back(ValueReadItem{*state->nodes[position], state->reads[position].value});
      }
      nameSpace.read_values_async(state->request,
        state->caller ? &*state->caller : nullptr,
        items,
        state->maxAge,
        state->setSourceTimestamp,
        std::move(answer));
    },
    [state, complete](std::vector<DataValueResult> found)
    {
      for (std::size_t i = 0; i < found.size(); ++i)
      {
        DataValueResult& answer = found[i];
        // Only a routed item can hold a value: every other item was answered with its failure before routing
        // and keeps it, so skipping it here is not fatal. An Uncertain value is checked as a Good one is.
        if (!state->nodes[i] || !answer.has_value())
        {
          continue;
        }
        const DataValue& value = answer.value();
        if (value.status().has_value() && value.status()->is_bad())
        {
          continue;
        }
        try
        {
          if (const auto excess = first_dimension_beyond(value.value(), state->ranges[i]))
          {
            const auto owner = state->owners[i].lock();
            answer = DataValueResult{value_exceeds_range(state->reads[i].variable.get_node_id(),
              *excess,
              "NodeAccessorRoute",
              owner ? std::optional<std::string>{std::string{owner->uri()}} : std::nullopt)};
          }
        }
        catch (...)
        {
          answer = DataValueResult{exception_to_status_code(std::current_exception())};
        }
      }
      invoke_user_callback(*complete, std::move(found));
    },
    std::move(requiredAddressSpace));
}

namespace
{

// The only item of a one-item call's answer, with the guards the route gives a call (NR-23 rule 4): a Bad
// batch status answers the item with it, and an answer with another number of items answers Bad_InternalError
// (`NamespaceItemCountMismatch`), the detail the route builds.
template<typename Answer>
Answer only_item(BatchResult<Answer> batch) noexcept
{
  try
  {
    if (batch.batchStatus.is_bad())
    {
      return Answer{batch.batchStatus.status_code()};
    }
    if (batch.items.size() != 1U)
    {
      return Answer{StatusCode{Status::BadInternalError,
        ErrorDetail::build("NamespaceItemCountMismatch",
          "The namespace answered another number of items than the call had",
          "NamespaceRoute")
          .context(ContextKeys::sizeExpected, std::to_string(std::size_t{1}))
          .context(ContextKeys::sizeActual, std::to_string(batch.items.size()))}};
    }
    return std::move(batch.items.front());
  }
  catch (...)
  {
    return Answer{exception_to_status_code(std::current_exception())};
  }
}

// What a one-item call answers when the namespace's member throws (NR-23 rule 4), the detail the route
// builds.
StatusCode one_item_call_threw(std::exception_ptr thrown) noexcept
{
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build("NamespaceCallThrew", "The namespace's member threw", "NamespaceRoute")
        .cause(exception_to_status_code(std::move(thrown)))};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

// The one completion state of an accessor's Value read (NR-2 rule 4), held by the completion the namespace is
// given: the Node until the call completes, the namespace only weakly.
struct OneValueRead
{
  NodeAccessor::ReadValueCompleteCallback callback;
  shared_ptr<Node> node;
  // The NodeId the item names, for the detail of an answer larger than its range.
  NodeId nodeId;
  ParsedNumericRange range;
  weak_ptr<Namespace> owner;
  std::atomic<bool> answered{false};
};

// Answers the read's caller once: a second completion, or the failure of a throw after the namespace has
// answered, is ignored. As on the batched path, an answer holding more than the range selects is refused
// (CALLS-25 rule 2).
void answer_value_read(OneValueRead& read, BatchResult<DataValueResult> batch) noexcept
{
  if (read.answered.exchange(true, std::memory_order_acq_rel))
  {
    return;
  }
  DataValueResult answer = only_item(std::move(batch));
  if (answer.has_value())
  {
    const auto& valueStatus = answer.value().status();
    if (!(valueStatus.has_value() && valueStatus.value().is_bad()))
    {
      try
      {
        if (const auto excess = first_dimension_beyond(answer.value().value(), read.range))
        {
          const auto owner = read.owner.lock();
          answer = DataValueResult{value_exceeds_range(read.nodeId,
            *excess,
            "NodeAccessorRoute",
            owner ? std::optional<std::string>{std::string{owner->uri()}} : std::nullopt)};
        }
      }
      catch (...)
      {
        answer = DataValueResult{exception_to_status_code(std::current_exception())};
      }
    }
  }
  auto callback = std::move(read.callback);
  invoke_user_callback(callback, std::move(answer));
}

}  // namespace

// A one-item read adds no batch state (NR-2 rule 4): the item is on this stack, which it may be since it is
// valid until the member returns, and the call's only allocation is its completion state.
void NodeAccessorRoute::read_value(const NodeAccessor& accessor, Duration maxAge, bool setSourceTimestamp,
  const ReadValueId& nodeToRead, const CallerInfo* caller,
  NodeAccessor::ReadValueCompleteCallback callback) noexcept
{
  shared_ptr<OneValueRead> read;
  try
  {
    read = std::make_shared<OneValueRead>();
    read->callback = std::move(callback);
    // As the batched path: a range that does not parse is answered without calling the namespace.
    auto parsed = parse_numeric_range(nodeToRead.index_range());
    if (!parsed.is_good())
    {
      invoke_user_callback(read->callback, DataValueResult{parsed.status_code()});
      return;
    }
    Bound nodeBinding = bound_of(accessor, accessor.get_node_id());
    if (nodeBinding.failure)
    {
      invoke_user_callback(read->callback, DataValueResult{*nodeBinding.failure});
      return;
    }
    read->node = std::move(nodeBinding.node);
    read->range = std::move(parsed).value();
    read->owner = nodeBinding.nameSpace;
    // The item names the Node it carries (ValueReadItem::value); a ReadValueId given without a NodeId names
    // this accessor's Variable.
    std::optional<ReadValueId> named;
    if (nodeToRead.node_id().is_null())
    {
      named.emplace(nodeToRead);
      const NodeDescription nodeDescription = read->node->attributes();
      named->node_id() = nodeDescription.node_id();
    }
    const ReadValueId& value = named ? *named : nodeToRead;
    read->nodeId = value.node_id();
    const ValueReadItem item{*read->node, value};
    std::function<void(BatchResult<DataValueResult>)> complete = [read](BatchResult<DataValueResult> batch)
    {
      answer_value_read(*read, std::move(batch));
    };
    // The namespace is held only while its member runs.
    shared_ptr<Namespace> nameSpace = std::move(nodeBinding.nameSpace);
    std::optional<StatusCode> threw;
    try
    {
      nameSpace->read_values_async(RequestInfo{},
        caller,
        std::span<const ValueReadItem>{&item, 1},
        maxAge,
        setSourceTimestamp,
        std::move(complete));
    }
    catch (...)
    {
      threw = one_item_call_threw(std::current_exception());
    }
    nameSpace.reset();
    if (threw)
    {
      BatchResult<DataValueResult> failed;
      failed.batchStatus = VoidResult{std::move(*threw)};
      answer_value_read(*read, std::move(failed));
    }
  }
  catch (...)
  {
    const DataValueResult failed{exception_to_status_code(std::current_exception())};
    if (!read)
    {
      invoke_user_callback(callback, failed);
    }
    else if (!read->answered.exchange(true, std::memory_order_acq_rel))
    {
      auto answer = std::move(read->callback);
      invoke_user_callback(answer, failed);
    }
  }
}

Result<NodeDescription> NodeAccessorRoute::attributes(const NodeAccessor& accessor) noexcept
{
  try
  {
    if (!accessor.mNode)
    {
      return Result<NodeDescription>{StatusCode{Status::BadNodeIdUnknown,
        ErrorDetail::build("AccessorWithoutNode", "The accessor holds no Node", "NodeAccessorRoute")}};
    }
    // A deleted Node keeps its last Attributes, which its getters no longer answer: `node_id()` throws, so
    // the NodeId the detail names is the one its last description holds. A Node that cannot describe itself
    // either is named by none.
    if (accessor.mNode->deleted())
    {
      auto builder =
        ErrorDetail::build("NodeDeleted", "The accessor's Node has been deleted", "NodeAccessorRoute");
      try
      {
        const NodeDescription last = accessor.mNode->attributes();
        if (!last.node_id().is_null())
        {
          builder.context(ContextKeys::nodeId, to_string(last.node_id()));
        }
      }
      catch (...)
      {
        ignore_expected_exception();
      }
      std::unique_ptr<ErrorDetail> detail = builder;
      return Result<NodeDescription>{StatusCode{Status::BadNodeIdUnknown, std::move(detail)}};
    }
    return Result<NodeDescription>{accessor.mNode->attributes()};
  }
  catch (...)
  {
    return Result<NodeDescription>{exception_to_status_code(std::current_exception())};
  }
}

namespace
{

// The one completion state of an accessor's write (NR-2 rule 4), held by the completion the namespace is
// given: the Node until the call completes, neither the namespace nor the address space.
struct OneWrite
{
  std::function<void(VoidResult)> callback;
  shared_ptr<Node> node;
  weak_ptr<AddressSpaceImpl> addressSpace;
  // The NodeId a DataType write names: a versioned Node reported with it changed its DataType.
  std::optional<NodeId> dataTypeWritten;
  bool changesModel{false};
  bool writesNodeVersion{false};
  // Whether the caller has been answered, and whether the namespace has completed the call.
  std::atomic<bool> answered{false};
  std::atomic<bool> completed{false};
};

// The step of a write that changed versioned Nodes or wrote a NodeVersion: each reported Node with the verbs
// `record_writes` gives it (DataTypeChanged for the Node a DataType write names, none for another), and a
// NodeVersion written as a change no verb names (NR-36 rule 6).
shared_ptr<ModelChangeStep> write_step(
  const OneWrite& write, std::span<const VersionedNode> versioned, bool nodeVersion)
{
  auto step = ModelChangeStep::create(write.addressSpace);
  const std::function<uint8_t(const NodeId&)> verbsOf = [&write](const NodeId& node)
  {
    return write.dataTypeWritten && *write.dataTypeWritten == node
             ? verb(ModelChangeStructureVerbMask::DataTypeChanged)
             : uint8_t{0};
  };
  step->record(versioned, verbsOf);
  if (nodeVersion)
  {
    step->record_unspecified();
  }
  return step;
}

// Answers the write's caller: after the model generation has advanced for a write that changes the model, and
// after the event of a write that changed versioned Nodes or wrote a NodeVersion has been raised (NR-36 rule
// 4). Only such a write creates a step. A step that cannot be created answers the caller with that failure.
void finish_write(OneWrite& write, VoidResult answer, std::span<const VersionedNode> versioned) noexcept
{
  auto callback = std::move(write.callback);
  if (write.changesModel && !answer.is_bad())
  {
    if (const auto owner = write.addressSpace.lock())
    {
      owner->model_changed();
    }
  }
  const bool nodeVersion = write.writesNodeVersion && !answer.is_bad();
  if (versioned.empty() && !nodeVersion)
  {
    invoke_user_callback(callback, std::move(answer));
    return;
  }
  try
  {
    auto step = write_step(write, versioned, nodeVersion);
    std::function<void()> done = [callback, answer]() mutable
    {
      invoke_user_callback(callback, std::move(answer));
    };
    step->close(std::move(done));
  }
  catch (...)
  {
    invoke_user_callback(callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

// The completion the namespace is given: its first completion only. When the caller was already answered with
// the member's throw, the versioned Nodes it reports are still raised.
void complete_write(
  OneWrite& write, BatchResult<VoidResult> batch, std::vector<VersionedNode> versioned) noexcept
{
  if (write.completed.exchange(true, std::memory_order_acq_rel))
  {
    return;
  }
  if (write.answered.exchange(true, std::memory_order_acq_rel))
  {
    if (!versioned.empty())
    {
      try
      {
        write_step(write, versioned, false)->close(nullptr);
      }
      catch (...)
      {
        ignore_expected_exception();
      }
    }
    return;
  }
  finish_write(write, only_item(std::move(batch)), versioned);
}

}  // namespace

// A one-item write adds no batch state (NR-2 rule 4): the item is on this stack, which it may be since it is
// valid until the member returns, and the call's only allocation is its completion state, with a model change
// step only for a write that needs one.
void NodeAccessorRoute::write(const NodeAccessor& accessor, const WriteValue& nodeToWrite,
  const CallerInfo* caller, std::function<void(VoidResult)> callback) noexcept
{
  shared_ptr<OneWrite> write;
  try
  {
    write = std::make_shared<OneWrite>();
    write->callback = std::move(callback);
    Bound nodeBinding = bound_of(accessor, accessor.get_node_id());
    if (nodeBinding.failure)
    {
      invoke_user_callback(write->callback, VoidResult{*nodeBinding.failure});
      return;
    }
    write->node = std::move(nodeBinding.node);
    write->addressSpace = nodeBinding.addressSpace;
    write->changesModel = changes_the_model(nodeToWrite);
    write->writesNodeVersion = writes_a_node_version(*write->node, nodeToWrite);
    if (static_cast<AttributeId>(nodeToWrite.attribute_id()) == AttributeId::DataType)
    {
      write->dataTypeWritten = nodeToWrite.node_id();
    }
    const ValueWriteItem item{*write->node, nodeToWrite};
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete =
      [write](BatchResult<VoidResult> batch, std::vector<VersionedNode> versioned)
    {
      complete_write(*write, std::move(batch), std::move(versioned));
    };
    // The namespace is held only while its member runs.
    shared_ptr<Namespace> nameSpace = std::move(nodeBinding.nameSpace);
    std::optional<StatusCode> threw;
    try
    {
      nameSpace->write_async(
        RequestInfo{}, caller, std::span<const ValueWriteItem>{&item, 1}, std::move(complete));
    }
    catch (...)
    {
      threw = one_item_call_threw(std::current_exception());
    }
    nameSpace.reset();
    if (threw && !write->answered.exchange(true, std::memory_order_acq_rel))
    {
      finish_write(*write, VoidResult{std::move(*threw)}, {});
    }
  }
  catch (...)
  {
    const VoidResult failed{exception_to_status_code(std::current_exception())};
    if (!write)
    {
      invoke_user_callback(callback, failed);
    }
    else if (!write->answered.exchange(true, std::memory_order_acq_rel))
    {
      auto answer = std::move(write->callback);
      invoke_user_callback(answer, failed);
    }
  }
}

void NodeAccessorRoute::write_values(const RequestInfo& request, const CallerInfo* caller,
  std::vector<ValueWrite> writes, std::function<void(std::vector<VoidResult>)> callback,
  shared_ptr<ModelChangeStep> step) noexcept
{
  using Route = NamespaceRoute<VoidResult>;

  // What the calls refer to, held until every namespace has answered: the writes with their Nodes, and copies
  // of the request and the caller, which are valid only until this call returns.
  struct State
  {
    std::vector<ValueWrite> writes;
    std::vector<shared_ptr<Node>> nodes;
    RequestInfo request;
    std::optional<CallerInfo> caller;
  };

  shared_ptr<std::function<void(std::vector<VoidResult>)>> complete;
  std::vector<std::optional<VoidResult>> answers;
  std::vector<Route::Part> parts;
  std::optional<uint32_t> limit;
  shared_ptr<State> state;
  weak_ptr<AddressSpaceImpl> space;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<VoidResult>)>>(std::move(callback));
    state = std::make_shared<State>();
    state->writes = std::move(writes);
    state->request = request;
    if (caller != nullptr)
    {
      state->caller = *caller;
    }
    const std::size_t count = state->writes.size();
    state->nodes.resize(count);
    answers.resize(count);
    // The part of each namespace, in the order the namespaces first appear.
    std::unordered_map<const Namespace*, std::size_t> partOf;
    bool limitRead = false;
    for (std::size_t i = 0; i < count; ++i)
    {
      try
      {
        const ValueWrite& valueWrite = state->writes[i];
        Bound nodeBinding = bound_of(valueWrite.variable, valueWrite.variable.get_node_id());
        if (nodeBinding.failure)
        {
          answers[i] = VoidResult{*nodeBinding.failure};
          continue;
        }
        if (!limitRead)
        {
          limitRead = true;
          const auto& operationLimits = nodeBinding.addressSpace->mOperationLimits;
          limit = operationLimits ? operationLimits.value().maxNodesPerWrite : std::nullopt;
          space = nodeBinding.addressSpace;
        }
        state->nodes[i] = std::move(nodeBinding.node);
        add_to_part(parts, partOf, std::move(nodeBinding.nameSpace), i);
      }
      catch (...)
      {
        answers[i] = VoidResult{exception_to_status_code(std::current_exception())};
      }
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::vector<VoidResult> all;
    try
    {
      all.assign(state ? state->writes.size() : writes.size(), VoidResult{failed});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }
  // A step the caller gives is an operation that writes the first Values of Nodes it created, which change no
  // version (NR-63); a NodeVersion written without one raises the event of NR-36 rule 6.
  const bool ownStep = !step;
  try
  {
    step = operation_step(space, std::move(step), *complete);
  }
  catch (...)
  {
    std::vector<VoidResult> all;
    try
    {
      all.assign(state->writes.size(), VoidResult{exception_to_status_code(std::current_exception())});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(*complete, std::move(all));
    return;
  }

  Route::run(
    std::move(answers),
    std::move(parts),
    limit,
    [state, step](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<VoidResult>)>
        answer)
    {
      std::vector<ValueWriteItem> items;
      items.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        items.push_back(ValueWriteItem{*state->nodes[position], state->writes[position].value});
      }
      nameSpace.write_async(state->request,
        state->caller ? &*state->caller : nullptr,
        items,
        record_writes(std::move(answer), *step, items));
    },
    [state, complete, space, step, ownStep](std::vector<VoidResult> written)
    {
      for (std::size_t i = 0; i < written.size() && i < state->writes.size(); ++i)
      {
        if (changes_the_model(state->writes[i].value) && !written[i].is_bad())
        {
          if (const auto owner = space.lock())
          {
            owner->model_changed();
          }
          break;
        }
      }
      for (std::size_t i = 0; ownStep && i < written.size() && i < state->writes.size(); ++i)
      {
        if (!written[i].is_bad() && state->nodes[i] &&
            writes_a_node_version(*state->nodes[i], state->writes[i].value))
        {
          step->record_unspecified();
          break;
        }
      }
      invoke_user_callback(*complete, std::move(written));
    });
}

namespace
{

// One request's Method calls on their way through the namespaces (NR-15 rules 2 to 4): the route's own copies
// of what each namespace is given, held until the last namespace has answered.
struct MethodCallRun
{
  RequestInfo request;
  shared_ptr<const CallerInfo> caller;
  shared_ptr<std::vector<MethodCallItem>> items;
  // Per item: the Nodes of its Object and its Method, and its Method's namespace when that is not the
  // Object's, held weakly, since the completions the route gives the namespaces hold this run.
  std::vector<shared_ptr<Node>> objects;
  std::vector<shared_ptr<Node>> methods;
  std::vector<std::optional<weak_ptr<Namespace>>> methodNamespaces;
  std::optional<uint32_t> limit;
  std::function<void(MethodCallAnswers)> answered;
};

// The answer for an item that neither the Object's namespace nor the Method's took.
StatusCode call_declined(const NodeId& methodId)
{
  return StatusCode{Status::BadNotImplemented,
    ErrorDetail::build("CallDeclined",
      "Neither the Object's namespace nor the Method's namespace took the call",
      "NodeAccessor")
      .context(ContextKeys::nodeId, to_string(methodId))};
}

// The answer for a Node deleted since it was looked up, as the route's lookup would answer it.
StatusCode node_deleted(const NodeId& nodeId)
{
  return StatusCode{Status::BadNodeIdUnknown,
    ErrorDetail::build("NodeDeleted", "The accessor's Node has been deleted", "NodeAccessorRoute")
      .context(ContextKeys::nodeId, to_string(nodeId))};
}

// Hands answered items to the caller; nothing when there are none.
void report(
  const MethodCallRun& run, std::vector<std::size_t> positions, std::vector<CallResult> results) noexcept
{
  if (positions.empty())
  {
    return;
  }
  MethodCallAnswers answers;
  answers.positions = std::move(positions);
  answers.results = std::move(results);
  answers.items = run.items;
  invoke_user_callback(run.answered, std::move(answers));
}

// Answers every item at @p positions with @p status.
void fail_items(
  const MethodCallRun& run, const std::vector<std::size_t>& positions, const StatusCode& status) noexcept
{
  try
  {
    report(run,
      std::vector<std::size_t>(positions),
      std::vector<CallResult>(positions.size(), CallResult{status}));
  }
  catch (...)
  {
    // Nothing is left to answer with; the caller's own deadline answers these items.
    ignore_expected_exception();
  }
}

void offer_calls(const shared_ptr<MethodCallRun>& run, shared_ptr<Namespace> nameSpace,
  const std::vector<std::size_t>& positions, bool offerMethods);

// Takes one namespace's answers for the items at @p offered: the items it took, and with @p offerMethods
// false the items it declined, are reported at once; with @p offerMethods true the items it declined then go
// to their Methods' namespaces, one call per namespace, or are declined by both when the Method's namespace
// is the one that declined.
void take_answers(const shared_ptr<MethodCallRun>& run, const std::vector<std::size_t>& offered,
  std::vector<std::optional<CallResult>> answers, bool offerMethods) noexcept
{
  std::vector<std::size_t> positions;
  std::vector<CallResult> results;
  // The declined items of each Method namespace, in the order the namespaces first appear.
  std::vector<std::pair<shared_ptr<Namespace>, std::vector<std::size_t>>> declined;
  try
  {
    positions.reserve(offered.size());
    results.reserve(offered.size());
    for (std::size_t slot = 0; slot < offered.size() && slot < answers.size(); ++slot)
    {
      const std::size_t position = offered[slot];
      std::optional<CallResult>& answer = answers[slot];
      if (answer)
      {
        positions.push_back(position);
        results.push_back(std::move(*answer));
        continue;
      }
      const auto& methodNamespace = run->methodNamespaces[position];
      if (!offerMethods || !methodNamespace)
      {
        positions.push_back(position);
        results.emplace_back(call_declined((*run->items)[position].request.method_id()));
        continue;
      }
      shared_ptr<Namespace> next = methodNamespace->lock();
      if (!next)
      {
        positions.push_back(position);
        results.emplace_back(namespace_released());
        continue;
      }
      auto group = std::find_if(
        declined.begin(), declined.end(), [&next](const auto& entry) { return entry.first == next; });
      if (group == declined.end())
      {
        declined.emplace_back(std::move(next), std::vector<std::size_t>{});
        group = std::prev(declined.end());
      }
      group->second.push_back(position);
    }
  }
  catch (...)
  {
    declined.clear();
    positions.clear();
    results.clear();
    fail_items(*run, offered, exception_to_status_code(std::current_exception()));
    return;
  }
  report(*run, std::move(positions), std::move(results));
  for (auto& [nameSpace, group] : declined)
  {
    try
    {
      offer_calls(run, std::move(nameSpace), group, false);
    }
    catch (...)
    {
      fail_items(*run, group, exception_to_status_code(std::current_exception()));
    }
  }
}

// Offers the items at @p positions to @p nameSpace in one `call_async`, split by the limit, and takes its
// answers when it has answered. Throws only before the call is made.
void offer_calls(const shared_ptr<MethodCallRun>& run, shared_ptr<Namespace> nameSpace,
  const std::vector<std::size_t>& positions, bool offerMethods)
{
  using Route = NamespaceRoute<std::optional<CallResult>>;
  auto offered = std::make_shared<const std::vector<std::size_t>>(positions);
  Route::Part part{std::move(nameSpace), {}};
  part.positions.resize(offered->size());
  std::iota(part.positions.begin(), part.positions.end(), std::size_t{0});
  std::vector<Route::Part> parts;
  parts.push_back(std::move(part));
  std::vector<std::optional<std::optional<CallResult>>> answers(offered->size());
  Route::run(
    std::move(answers),
    std::move(parts),
    run->limit,
    [run, offered](Namespace& member,
      std::span<const std::size_t>
        slots,
      std::function<void(BatchResult<std::optional<CallResult>>)>
        answer)
    {
      std::vector<CallItem> items;
      items.reserve(slots.size());
      for (const std::size_t slot : slots)
      {
        const std::size_t position = (*offered)[slot];
        const MethodCallItem& item = (*run->items)[position];
        items.push_back(
          CallItem{*run->objects[position], *run->methods[position], item.request, item.context});
      }
      member.call_async(run->request, run->caller.get(), items, std::move(answer));
    },
    [run, offered, offerMethods](std::vector<std::optional<CallResult>> found)
    { take_answers(run, *offered, std::move(found), offerMethods); });
}

}  // namespace

void NodeAccessorRoute::call_items(const RequestInfo& request, shared_ptr<const CallerInfo> caller,
  std::vector<MethodCallItem> items, std::function<void(MethodCallAnswers)> answered) noexcept
{
  shared_ptr<MethodCallRun> run;
  // The Objects' namespaces in the order they first appear, each with the positions of its items in item
  // order.
  std::vector<std::pair<shared_ptr<Namespace>, std::vector<std::size_t>>> parts;
  std::vector<std::size_t> failedPositions;
  std::vector<CallResult> failedResults;
  try
  {
    run = std::make_shared<MethodCallRun>();
    run->answered = std::move(answered);
    run->request = request;
    run->caller = std::move(caller);
    run->items = std::make_shared<std::vector<MethodCallItem>>(std::move(items));
    const std::size_t count = run->items->size();
    run->objects.resize(count);
    run->methods.resize(count);
    run->methodNamespaces.resize(count);
    failedPositions.reserve(count);
    failedResults.reserve(count);
    bool limitRead = false;
    for (std::size_t position = 0; position < count; ++position)
    {
      const MethodCallItem& item = (*run->items)[position];
      std::optional<StatusCode> failure;
      try
      {
        // The Method and the Object were looked up by the caller, and either may have been deleted since:
        // such a Node is not called, and is answered as a lookup would answer it. Checked before the Method's
        // NodeId is read, which a deleted Node no longer answers.
        if (item.method.mNode && item.method.mNode->deleted())
        {
          failure = node_deleted(item.request.method_id());
        }
        else if (item.object.mNode && item.object.mNode->deleted())
        {
          failure = node_deleted(item.request.object_id());
        }
        else if (Bound nodeBinding = bound_of(item.method, item.method.get_node_id()); nodeBinding.failure)
        {
          failure = *nodeBinding.failure;
        }
        else if (auto objectNamespace = nodeBinding.addressSpace->resolve_namespace(
                   item.request.object_id().namespace_index(), nodeBinding.registrationRoute);
                 !objectNamespace || !item.object.mNode)
        {
          failure = StatusCode{Status::BadNodeIdUnknown};
        }
        else
        {
          if (!limitRead)
          {
            limitRead = true;
            const auto& operationLimits = nodeBinding.addressSpace->mOperationLimits;
            run->limit = operationLimits ? operationLimits.value().maxNodesPerMethodCall : std::nullopt;
          }
          auto part = std::find_if(parts.begin(),
            parts.end(),
            [&objectNamespace](const auto& entry) { return entry.first == objectNamespace; });
          if (part == parts.end())
          {
            parts.emplace_back(objectNamespace, std::vector<std::size_t>{});
            part = std::prev(parts.end());
          }
          part->second.push_back(position);
          run->objects[position] = item.object.mNode;
          run->methods[position] = std::move(nodeBinding.node);
          if (objectNamespace != nodeBinding.nameSpace)
          {
            run->methodNamespaces[position] = weak_ptr<Namespace>{nodeBinding.nameSpace};
          }
        }
      }
      catch (...)
      {
        failure = exception_to_status_code(std::current_exception());
      }
      if (failure)
      {
        failedPositions.push_back(position);
        failedResults.emplace_back(std::move(*failure));
      }
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    try
    {
      MethodCallAnswers all;
      const std::size_t count = run && run->items ? run->items->size() : items.size();
      all.positions.resize(count);
      std::iota(all.positions.begin(), all.positions.end(), std::size_t{0});
      all.results.assign(count, CallResult{failed});
      all.items = run ? run->items : nullptr;
      invoke_user_callback(run ? run->answered : answered, std::move(all));
    }
    catch (...)
    {
      // Nothing is left to answer with; the caller's own deadline answers these items.
      ignore_expected_exception();
    }
    return;
  }

  report(*run, std::move(failedPositions), std::move(failedResults));
  for (const auto& [nameSpace, positions] : parts)
  {
    try
    {
      offer_calls(run, nameSpace, positions, true);
    }
    catch (...)
    {
      fail_items(*run, positions, exception_to_status_code(std::current_exception()));
    }
  }
}

void NodeAccessorRoute::call(const NodeAccessor& method, const CallMethodRequest& request,
  shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback) noexcept
{
  shared_ptr<CallMethodCompleteCallback> complete;
  try
  {
    complete = std::make_shared<CallMethodCompleteCallback>(std::move(callback));
    Bound nodeBinding = bound_of(method, method.get_node_id());
    if (nodeBinding.failure)
    {
      invoke_user_callback(*complete, CallResult{*nodeBinding.failure});
      return;
    }
    // The Object's Node comes from the address space's lookup, which answers an unknown Object or namespace.
    nodeBinding.addressSpace->find_node_async(
      request.object_id(),
      [method, request, context = std::move(context), complete](NodeAccessorResult found) mutable
      {
        // The Method is called on the Object found, so an Uncertain lookup is not acted on.
        if (!found.is_good())
        {
          invoke_user_callback(*complete,
            CallResult{lookup_failure(request.object_id(), found.status_code(), "NodeAccessorRoute")});
          return;
        }
        NodeAccessorRoute::call(method, found.value(), request, std::move(context), std::move(*complete));
      },
      nodeBinding.registrationRoute);
  }
  catch (...)
  {
    invoke_user_callback(
      complete ? *complete : callback, CallResult{exception_to_status_code(std::current_exception())});
  }
}

void NodeAccessorRoute::call(const NodeAccessor& method, const NodeAccessor& object,
  const CallMethodRequest& request, shared_ptr<const MethodCallContext> context,
  CallMethodCompleteCallback callback) noexcept
{
  shared_ptr<CallMethodCompleteCallback> complete;
  try
  {
    complete = std::make_shared<CallMethodCompleteCallback>(std::move(callback));
    std::vector<MethodCallItem> items;
    items.push_back(MethodCallItem{method, object, request, std::move(context)});
    // The server's own call (NR-46 rule 2): no request of a client and no caller. One item is answered once.
    call_items(RequestInfo{},
      nullptr,
      std::move(items),
      [complete](MethodCallAnswers answers)
      {
        if (!answers.results.empty())
        {
          invoke_user_callback(*complete, std::move(answers.results.front()));
        }
      });
  }
  catch (...)
  {
    invoke_user_callback(
      complete ? *complete : callback, CallResult{exception_to_status_code(std::current_exception())});
  }
}

void NodeAccessorRoute::view_contains(const RequestInfo& request, const NodeAccessor& view,
  std::vector<ExpandedNodeId> candidates, std::function<void(std::vector<BoolResult>)> callback) noexcept
{
  // What the call refers to, held until the namespace has answered: the View, the distinct candidates it is
  // asked about, the asked candidate each candidate maps to, and a copy of the request.
  struct Ask
  {
    shared_ptr<Node> view;
    NodeId viewId;
    std::vector<ExpandedNodeId> asked;
    std::vector<std::optional<std::size_t>> askedAt;
    std::vector<std::optional<BoolResult>> answers;
    RequestInfo request;
  };

  shared_ptr<std::function<void(std::vector<BoolResult>)>> complete;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<BoolResult>)>>(std::move(callback));
    const std::size_t count = candidates.size();
    const NodeId viewId = view.get_node_id();
    Bound nodeBinding = bound_of(view, viewId);
    if (nodeBinding.failure)
    {
      invoke_user_callback(*complete, std::vector<BoolResult>(count, BoolResult{*nodeBinding.failure}));
      return;
    }

    auto ask = std::make_shared<Ask>();
    ask->view = std::move(nodeBinding.node);
    ask->viewId = viewId;
    ask->request = request;
    ask->askedAt.resize(count);
    ask->answers.resize(count);
    const NodeId serverObject{ObjectId::Server};
    std::unordered_map<ExpandedNodeId, std::size_t> distinct;
    for (std::size_t i = 0; i < count; ++i)
    {
      ExpandedNodeId& candidate = candidates[i];
      const bool local = candidate.is_local() && candidate.is_index_based();
      // The View Node is a member of its own View (NR-16 rule 6); the Server Object is a member of no View
      // (OPC 10000-3 5.4, NR-41). Neither is asked, whatever the namespace would answer.
      if (local && candidate.node_id() == viewId)
      {
        ask->answers[i] = BoolResult{true};
        continue;
      }
      if (local && candidate.node_id() == serverObject)
      {
        ask->answers[i] = BoolResult{false};
        continue;
      }
      const auto [entry, added] = distinct.try_emplace(candidate, ask->asked.size());
      if (added)
      {
        ask->asked.push_back(std::move(candidate));
      }
      ask->askedAt[i] = entry->second;
    }

    auto deliver = [ask, complete](std::vector<BoolResult> asked)
    {
      std::vector<BoolResult> result;
      try
      {
        result.reserve(ask->answers.size());
        for (std::size_t i = 0; i < ask->answers.size(); ++i)
        {
          result.push_back(ask->answers[i] ? std::move(*ask->answers[i]) : asked[*ask->askedAt[i]]);
        }
      }
      catch (...)
      {
        result.clear();
      }
      invoke_user_callback(*complete, std::move(result));
    };

    if (ask->asked.empty())
    {
      deliver({});
      return;
    }
    // At most maxNodesPerBrowse candidates per call (NR-31 rule 5), each call after the previous has
    // answered.
    using Route = NamespaceRoute<BoolResult>;
    const std::size_t askedCount = ask->asked.size();
    typename Route::Part part{std::move(nodeBinding.nameSpace), {}};
    part.positions.resize(askedCount);
    std::iota(part.positions.begin(), part.positions.end(), std::size_t{0});
    std::vector<typename Route::Part> parts;
    parts.push_back(std::move(part));
    const auto& operationLimits = nodeBinding.addressSpace->mOperationLimits;
    const std::optional<uint32_t> limit =
      operationLimits ? operationLimits.value().maxNodesPerBrowse : std::nullopt;
    Route::run(
      std::vector<std::optional<BoolResult>>(askedCount),
      std::move(parts),
      limit,
      [ask](Namespace& nameSpace,
        std::span<const std::size_t>
          positions,
        std::function<void(BatchResult<BoolResult>)>
          answer)
      {
        if (positions.size() == ask->asked.size())
        {
          nameSpace.view_contains_async(ask->request, ask->viewId, ask->asked, std::move(answer));
          return;
        }
        std::vector<ExpandedNodeId> slice;
        slice.reserve(positions.size());
        for (const std::size_t position : positions)
        {
          slice.push_back(ask->asked[position]);
        }
        nameSpace.view_contains_async(ask->request, ask->viewId, slice, std::move(answer));
      },
      std::move(deliver));
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::vector<BoolResult> all;
    try
    {
      all.assign(candidates.size(), BoolResult{failed});
    }
    catch (...)
    {
      all.clear();
    }
    invoke_user_callback(complete ? *complete : callback, std::move(all));
  }
}

void NodeAccessorRoute::view_contains(
  const NodeAccessor& view, NodeId member, NodeAccessor::IsNodeInViewCallback callback) noexcept
{
  shared_ptr<NodeAccessor::IsNodeInViewCallback> complete;
  try
  {
    complete = std::make_shared<NodeAccessor::IsNodeInViewCallback>(std::move(callback));
    std::vector<ExpandedNodeId> candidates;
    candidates.emplace_back(std::move(member));
    view_contains(RequestInfo{},
      view,
      std::move(candidates),
      [complete](std::vector<BoolResult> answers)
      {
        if (answers.size() != 1)
        {
          invoke_user_callback(*complete, BoolResult{StatusCode{Status::BadOutOfMemory}});
          return;
        }
        invoke_user_callback(*complete, std::move(answers.front()));
      });
  }
  catch (...)
  {
    invoke_user_callback(
      complete ? *complete : callback, BoolResult{exception_to_status_code(std::current_exception())});
  }
}

void NodeAccessorRoute::add_to_view(
  const NodeAccessor& view, NodeId member, NodeAccessor::ViewModifyCallback callback) noexcept
{
  shared_ptr<NodeAccessor::ViewModifyCallback> complete;
  try
  {
    complete = std::make_shared<NodeAccessor::ViewModifyCallback>(std::move(callback));
    // The Server Object is a member of no View (OPC 10000-3 5.4, NR-41), whatever the View's namespace
    // would accept.
    if (member == NodeId{ObjectId::Server})
    {
      invoke_user_callback(*complete,
        VoidResult{StatusCode{Status::BadReferenceNotAllowed,
          ErrorDetail::build(
            "ServerObjectInView", "The Server Object cannot be part of a View", "AddressSpace")
            .context(ContextKeys::actual, to_string(member))}});
      return;
    }
    const NodeId viewId = view.get_node_id();
    Bound nodeBinding = bound_of(view, viewId);
    if (nodeBinding.failure)
    {
      invoke_user_callback(*complete, VoidResult{*nodeBinding.failure});
      return;
    }

    struct Add
    {
      shared_ptr<Node> view;
      NodeId viewId;
      std::vector<NodeId> members;
    };

    auto add = std::make_shared<Add>();
    add->view = std::move(nodeBinding.node);
    add->viewId = viewId;
    add->members.push_back(std::move(member));
    // A View is reported only when it gained a Reference; its content change is its ViewVersion's (OPC
    // 10000-3 5.4).
    auto step = ModelChangeStep::create(nodeBinding.addressSpace);
    call_namespace<VoidResult>(
      std::move(nodeBinding.nameSpace),
      1,
      [add, step](Namespace& nameSpace, std::function<void(BatchResult<VoidResult>)> answer)
      {
        nameSpace.add_to_view_async(RequestInfo{},
          add->viewId,
          add->members,
          recording_versions<VoidResult>(std::move(answer),
            *step,
            [](const NodeId&) { return verb(ModelChangeStructureVerbMask::ReferenceAdded); }));
      },
      [add, complete, step](std::vector<VoidResult> answers)
      {
        step->close([complete, answer = std::move(answers.front())]() mutable
          { invoke_user_callback(*complete, std::move(answer)); });
      });
  }
  catch (...)
  {
    invoke_user_callback(
      complete ? *complete : callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua::detail
