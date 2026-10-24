// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_nodeset_import_engine.h"
#include "ua_callback_safety.h"

#include "ua_access_level_ex_type.h"
#include "ua_array.h"
#include "ua_attribute_wire.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_resource_budgets.h"
#include "ua_key_value_pair.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_node_utilities.h"
#include "ua_objecttype_id.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_ref_structure.h"
#include "ua_reference.h"
#include "ua_reference_identity.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_structure.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_unknown_structure.h"
#include "ua_utilities.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/strand.hpp>

#include <boost/asio/post.hpp>

#include <algorithm>
#include <future>
#include <iterator>
#include <limits>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ua::xml::nodeset
{

namespace
{

// True if a decoded value holds an opaque (unresolved) ExtensionObject - as a scalar or as an
// element of a structure array. Used to enforce the unknown-structure import policy.
bool variant_contains_unknown_structure(const Variant& value)
{
  if (value.is_structure())
  {
    return dynamic_cast<const UnknownStructure*>(&value.as<Structure>()) != nullptr;
  }
  if (value.is_array_of_structure())
  {
    for (const auto& reference : value.as<Array<RefStructure<Structure>>>().payload())
    {
      if (dynamic_cast<const UnknownStructure*>(&(*reference)) != nullptr)
      {
        return true;
      }
    }
  }
  return false;
}

// Fold a parsed XML candidate list into a rich LocalizedText (mirrors the retired importer).
LocalizedText fold_candidates(const std::vector<LocalizedText>& values)
{
  std::vector<LocalizedText::Scalar> translations;
  translations.reserve(values.size());
  for (const auto& value : values)
  {
    translations.emplace_back(value.locale(), value.text());
  }
  return LocalizedText::from_translations(std::move(translations));
}

// Augment a bad StatusCode with the offending node's source `line:col`, unless the position is
// unknown or a deeper frame already recorded one (guard mirrors the retired importer's
// catch-augment). Chains the original status as the cause so nothing is dropped.
StatusCode augment_with_location(StatusCode sc, const Node* xmlNode)
{
  if (xmlNode == nullptr)
  {
    return sc;
  }
  const auto location = xmlNode->source_location();
  const ErrorDetail* original = sc.detail();
  // A deeper frame already recorded a source position if its context carries the
  // source.location key (positions now live in context, not in mDetail).
  bool alreadyLocated = false;
  if (original != nullptr)
  {
    for (const auto& fact : original->context)
    {
      if (fact.key == ua::ContextKeys::sourceLocation.value())
      {
        alreadyLocated = true;
        break;
      }
    }
  }
  if (!location.valid || alreadyLocated)
  {
    return sc;  // cannot locate, or a deeper frame already recorded a source position
  }
  return StatusCode{sc.as_status(),
    ErrorDetail::build("NodesetImportFailed", "NodeSet import failed", "NodesetImport")
      .context(ua::ContextKeys::sourceLocation, location.to_string())
      .cause(sc)};
}

/// Undoes a partial import by deleting what it created, newest first.
///
/// Its own strand, made over the address space's executor, because this has no component to borrow
/// one from: @ref ua::async::await_callback keeps the task's generation and suspended handle on
/// whatever it is given, and the address space is deliberately an executor rather than a strand.
/// @see ua::async::SelfOwningOperation
class ImportedMetadataRollbackOperation final
  : public ua::async::SelfOwningOperation<ImportedMetadataRollbackOperation>
{
public:
  using Base = ua::async::SelfOwningOperation<ImportedMetadataRollbackOperation>;

  ImportedMetadataRollbackOperation(
    AddressSpace addressSpace, std::vector<NodeId> createdNodes, std::function<void(VoidResult)> completion)
    : Base(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mCreatedNodes(std::move(createdNodes)),
      mCompletion(std::move(completion))
  {}

  static void start(
    AddressSpace addressSpace, std::vector<NodeId> createdNodes, std::function<void(VoidResult)> completion)
  {
    Base::launch(std::make_shared<ImportedMetadataRollbackOperation>(
      std::move(addressSpace), std::move(createdNodes), std::move(completion)));
  }

private:
  friend class ua::async::SelfOwningOperation<ImportedMetadataRollbackOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // Newest first, so a node is never deleted while something it created still refers to it.
      //
      // A LOOP, not the recursion this replaced: the old `drive()` called itself from the deletion's
      // own callback, so an address space answering on the calling stack grew the stack once per
      // created node - a depth the imported file chooses. R4.
      for (auto node = mCreatedNodes.rbegin(); node != mCreatedNodes.rend(); ++node)
      {
        const auto result = co_await await_step<VoidResult>(
          [this, nodeId = *node](auto completion)
          {
            auto owner = mAddressSpace.lock();
            if (!owner)
            {
              completion(VoidResult{::ua::detail::address_space_gone("NodeSetImport")});
              return;
            }
            owner->delete_node_async(nodeId, false, ReferenceHalves::Both, std::move(completion));
          });

        // The FIRST failure is the answer; the rest of the rollback still runs, because a node left
        // behind is worse than a status already decided.
        if (result.is_bad() && mFirstFailure.is_good())
        {
          mFirstFailure = VoidResult{result.status_code(), result.shared_detail()};
        }
      }
      complete(std::move(mFirstFailure));
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    complete(VoidResult{status, status.shared_detail()});
  }

  void complete(VoidResult result)
  {
    if (auto completion = std::move(mCompletion))
    {
      completion(std::move(result));
    }
  }

  /// Held weakly (CALLS-21 rule 1): the created nodes go with their address space, so a rollback that finds
  /// it gone has nothing left to undo, and answers AddressSpaceGone for each node it could not delete.
  WeakAddressSpace mAddressSpace;
  std::vector<NodeId> mCreatedNodes;
  std::function<void(VoidResult)> mCompletion;
  VoidResult mFirstFailure;
};

class ImportedMetadataPreparation final : public ::ua::detail::NamespaceRegistrationPreparation
{
public:
  ImportedMetadataPreparation(const ImportedMetadataPreparation&) = delete;
  ImportedMetadataPreparation& operator=(const ImportedMetadataPreparation&) = delete;
  ImportedMetadataPreparation(ImportedMetadataPreparation&&) = delete;
  ImportedMetadataPreparation& operator=(ImportedMetadataPreparation&&) = delete;

  ImportedMetadataPreparation(WeakAddressSpace addressSpace, std::vector<NodeId> createdNodes)
    : mAddressSpace(std::move(addressSpace)), mCreatedNodes(std::move(createdNodes))
  {}

  ~ImportedMetadataPreparation() override
  {
    if (mFinalized)
    {
      return;
    }
    mFinalized = true;
    // The created nodes went with their address space when it is gone.
    auto owner = mAddressSpace.lock();
    if (!owner)
    {
      return;
    }
    for (auto it = mCreatedNodes.rbegin(); it != mCreatedNodes.rend(); ++it)
    {
      owner->delete_node_async(*it, false, ReferenceHalves::Both, {});
    }
  }

  void commit() noexcept override
  {
    mFinalized = true;
    mCreatedNodes.clear();
  }

  void rollback_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (mFinalized)
    {
      callback(VoidResult{});
      return;
    }
    mFinalized = true;
    auto owner = mAddressSpace.lock();
    if (!owner)
    {
      callback(VoidResult{::ua::detail::address_space_gone("NodeSetImport")});
      return;
    }
    ImportedMetadataRollbackOperation::start(*owner, std::move(mCreatedNodes), std::move(callback));
  }

private:
  WeakAddressSpace mAddressSpace;
  std::vector<NodeId> mCreatedNodes;
  bool mFinalized{false};
};

}  // namespace

// Per-node import context, one per node visited (including forward-reference descendants).
struct ImportEngine::Operation
{
  enum class Step
  {
    Start,
    LookingUp,
    Creating,
    AddingReferences,
    WritingValues,
    Done
  };

  // One Node of the operation: where the files hold it, its NodeId in the address space, and what the
  // operation found or did with it.
  struct Item
  {
    const NodeSet* nodeSet{nullptr};
    Node* xmlNode{nullptr};
    NodeId translatedId;
    // The earlier item with the same NodeId in the address space: this one is neither looked up nor created,
    // and only its References are added.
    optional<std::size_t> sameAs;
    bool created{false};
    optional<NodeAccessor> accessor;
  };

  // Whose Reference a half of the Reference phase is, and whether it is the half the item holds, whose
  // failure fails the import, or the other half, held by the target (NR-31 rule 2).
  struct HalfOrigin
  {
    std::size_t item{0};
    bool own{true};
  };

  Step step{Step::Start};

  // What the operation imports: Nodes given by their NodeIds in the files, and Nodes already resolved.
  std::vector<NodeId> seedIds;
  std::vector<std::pair<const NodeSet*, Node*>> seedNodes;
  // Whether the forward References of each Node created are followed, charging `budget`.
  bool followForwardReferences{false};
  shared_ptr<WorkBudget> budget;
  optional<ImportNodePredicate> nodePred;
  optional<ImportReferencePredicate> refPred;
  Completion completion;

  // Registration metadata staging imports through the coordinator's private AddressSpace route before the
  // global namespace maps are committed. Held weakly, as the engine's own handle is: a namespace holding one
  // of the staging's calls keeps no address space (COMP-SVR-NAMESPACE-CALLS-21 rule 1).
  std::optional<WeakAddressSpace> stagedAddressSpace;
  shared_ptr<std::vector<NodeId>> stagedCreatedNodes;
  bool namespaceMapsReady{false};
  bool countReferences{true};
  bool translateReferencesInSourceFrame{false};

  // The chunk size of each phase (NR-31 rule 5): the address space's operation limit, or no limit.
  std::size_t readLimit{std::numeric_limits<std::size_t>::max()};
  std::size_t managementLimit{std::numeric_limits<std::size_t>::max()};
  std::size_t writeLimit{std::numeric_limits<std::size_t>::max()};

  std::vector<Item> items;
  std::unordered_set<const Node*> visited;
  std::unordered_map<NodeId, std::size_t> itemOf;
  // The first item of the level being looked up and created; every item is in the one level unless the
  // forward References are followed.
  std::size_t levelBegin{0};
  // The items the current phase sends, and how many of them (or of `changes`, or of `items`) it has sent.
  std::vector<std::size_t> pending;
  std::size_t cursor{0};
  std::vector<ReferenceChange> changes;
  std::vector<HalfOrigin> origins;
  // The operation's model changes, raised once when it finishes (NR-36 rule 4); made by the first phase that
  // changes a Node.
  shared_ptr<::ua::detail::ModelChangeStep> modelStep;
};

struct ImportEngine::NamespaceMapFrame
{
  enum class Step
  {
    Selecting,
    Registering,
    Done,
  };

  Step step{Step::Selecting};
  std::size_t nodeSetOffset{0};
  bool nodeSetStarted{false};
  std::vector<String> currentUris;
  std::size_t uriOffset{0};
  std::vector<uint16_t> currentMap;
  std::unordered_map<const NodeSet*, std::vector<uint16_t>> maps;
  optional<ImportNodePredicate> nodePred;
  optional<ImportReferencePredicate> refPred;
  std::unordered_set<std::string> preparedMetadataUris;
  shared_ptr<RegistrationMetadataSource> currentMetadataSource;
  ::ua::detail::NamespaceRegistrationInitializer currentInitializer;
  Completion completion;
};

struct ImportEngine::RegistrationMetadataSource
{
  NodeSet* nodeSet{nullptr};
  Node* metadataObject{nullptr};
  std::vector<Node*> nodes;
};

struct ImportEngine::RegistrationMetadataFrame
{
  explicit RegistrationMetadataFrame(const AddressSpace& staged)
    : stagedAddressSpace(staged.weak()), logger(staged.logger())
  {}

  WeakAddressSpace stagedAddressSpace;
  Logger logger;
  String namespaceUri;
  uint16_t namespaceIndex{0};
  shared_ptr<RegistrationMetadataSource> source;
  optional<ImportReferencePredicate> refPred;
  shared_ptr<std::vector<NodeId>> createdNodes{make_shared<std::vector<NodeId>>()};
  ::ua::detail::NamespaceRegistrationInitializationCallback completion;
  bool done{false};
};

ImportEngine::ImportEngine(EncodingLimits limits, AddressSpace addressSpace,
  std::vector<shared_ptr<NodeSet>> nodeSets, NamespaceAllocator namespaceAllocator)
  : mLimits(limits), mAddressSpace(addressSpace.weak()), mNodeSets(std::move(nodeSets)),
    mNamespaceAllocator(std::move(namespaceAllocator))
{
  build_state_machine_reference_closure();
}

shared_ptr<ImportEngine> ImportEngine::create(EncodingLimits limits, AddressSpace addressSpace,
  std::vector<shared_ptr<NodeSet>> nodeSets, NamespaceAllocator namespaceAllocator)
{
  class Wrapper : public ImportEngine
  {
  public:
    Wrapper(EncodingLimits limits, AddressSpace addressSpace, std::vector<shared_ptr<NodeSet>> nodeSets,
      NamespaceAllocator namespaceAllocator)
      : ImportEngine{limits, std::move(addressSpace), std::move(nodeSets), std::move(namespaceAllocator)}
    {}
  };

  return make_shared<Wrapper>(
    limits, std::move(addressSpace), std::move(nodeSets), std::move(namespaceAllocator));
}

// =================================================================================================
// Synchronous helpers (namespace translation against the prebuilt maps + attribute copying).
// =================================================================================================

std::pair<const NodeSet*, Node*> ImportEngine::find_node_with_nodeset(const NodeId& nodeId) const
{
  for (const auto& nodeSet : mNodeSets)
  {
    if (!nodeSet)
    {
      continue;
    }
    if (auto* node = nodeSet->find_node(nodeId))
    {
      return {nodeSet.get(), node};
    }
  }
  return {nullptr, nullptr};
}

void ImportEngine::build_state_machine_reference_closure()
{
  const auto nodeSets = node_sets();
  const auto isTypeOrSubtype = [this, nodeSets](const Node& node, const NodeId& baseType)
  {
    return node.node_id() == baseType || utilities::is_a_child_of(mLimits, nodeSets, node, baseType);
  };
  const auto hasReference = [](const auto& references, const Node::Reference& sought)
  {
    return std::ranges::any_of(references,
      [&sought](const Node::Reference& candidate)
      {
        return candidate.typeId == sought.typeId && candidate.targetId == sought.targetId &&
               candidate.isForward == sought.isForward;
      });
  };
  const auto addDerived = [this, &hasReference](const Node& source, Node::Reference reference)
  {
    if (hasReference(source.references(), reference))
      return;
    auto& derived = mDerivedReferences[&source];
    if (!hasReference(derived, reference))
      derived.push_back(std::move(reference));
  };

  for (const auto& nodeSet : mNodeSets)
  {
    if (!nodeSet)
      continue;
    for (const auto& nodeEntry : nodeSet->nodes())
    {
      const auto& node = nodeEntry.second;
      const auto* machineType = dynamic_cast<const ObjectType*>(node.get());
      if (machineType == nullptr ||
          !isTypeOrSubtype(*machineType, NodeId{ObjectTypeId::FiniteStateMachineType}))
      {
        continue;
      }

      for (const auto& componentReference : machineType->references())
      {
        if (!componentReference.isForward ||
            componentReference.typeId != NodeId{ReferenceTypeId::HasComponent})
        {
          continue;
        }
        const auto* transition = utilities::find_node(nodeSets, componentReference.targetId);
        if (transition == nullptr)
          continue;
        const auto* transitionType =
          utilities::get_target(nodeSets, *transition, NodeId{ReferenceTypeId::HasTypeDefinition}, true);
        if (transitionType == nullptr ||
            !isTypeOrSubtype(*transitionType, NodeId{ObjectTypeId::TransitionType}))
        {
          continue;
        }

        for (const auto& effectReference : transition->references())
        {
          if (!effectReference.isForward || effectReference.typeId != NodeId{ReferenceTypeId::HasEffect})
          {
            continue;
          }
          const auto* eventType = utilities::find_node(nodeSets, effectReference.targetId);
          if (eventType == nullptr || eventType->node_class() != NodeClass::ObjectType ||
              !isTypeOrSubtype(*eventType, NodeId{ObjectTypeId::BaseEventType}))
          {
            continue;
          }

          addDerived(*machineType,
            Node::Reference{NodeId{ReferenceTypeId::GeneratesEvent}, effectReference.targetId, true});
          addDerived(*eventType,
            Node::Reference{NodeId{ReferenceTypeId::GeneratesEvent}, machineType->node_id(), false});
        }
      }
    }
  }
}

NodeIdResult ImportEngine::translated_node_id(const NodeId& documentNodeId) const noexcept
{
  try
  {
    const auto [nodeSet, node] = find_node_with_nodeset(documentNodeId);
    if (!nodeSet || !node)
    {
      return StatusCode{Status::BadNodeIdUnknown};
    }
    return translate_node_id(*nodeSet, documentNodeId);
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ImportEngine::build_namespace_maps_async(
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred, Completion completion)
{
  if (!completion)
  {
    return;
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    completion(VoidResult{Status::BadShutdown,
      ErrorDetail::build("NodesetAddressSpaceGone",
        "The address space was destroyed before namespace mapping could begin",
        "NodesetImport")});
    return;
  }

  auto self = shared_from_this();
  auto executor = addressSpace->executor();
  ua::async::post_owning(self.get(),
    executor,
    addressSpace->logger(),
    [nodePred = std::move(nodePred), refPred = std::move(refPred), completion = std::move(completion)](
      ImportEngine& engine) mutable
    {
      if (engine.mNamespaceMapsBuilt)
      {
        completion(VoidResult{});
        return;
      }

      auto frame = make_shared<NamespaceMapFrame>();
      frame->nodePred = std::move(nodePred);
      frame->refPred = std::move(refPred);
      frame->completion = std::move(completion);
      engine.drive_namespace_maps(std::move(frame));
    })();
}

void ImportEngine::drive_namespace_maps(shared_ptr<NamespaceMapFrame> frame)
{
  if (frame->step != NamespaceMapFrame::Step::Selecting)
  {
    return;
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    finish_namespace_maps(std::move(frame),
      VoidResult{Status::BadShutdown,
        ErrorDetail::build("NodesetAddressSpaceGone",
          "The address space was destroyed while namespace mapping was in progress",
          "NodesetImport")});
    return;
  }

  try
  {
    while (frame->nodeSetOffset < mNodeSets.size())
    {
      const auto& nodeSet = mNodeSets[frame->nodeSetOffset];
      if (!nodeSet)
      {
        ++frame->nodeSetOffset;
        continue;
      }

      if (!frame->nodeSetStarted)
      {
        frame->nodeSetStarted = true;
        frame->currentMap = {0};  // document ns=0 is always the UA namespace
        frame->currentUris.clear();
        frame->uriOffset = 0;
        if (const auto& namespaceUris = nodeSet->namespace_uris())
        {
          const auto uris = namespaceUris->uris();
          frame->currentUris.assign(uris.begin(), uris.end());
          frame->currentMap.reserve(1 + frame->currentUris.size());
        }
      }

      if (frame->uriOffset == frame->currentUris.size())
      {
        frame->maps.insert_or_assign(nodeSet.get(), std::move(frame->currentMap));
        frame->nodeSetStarted = false;
        ++frame->nodeSetOffset;
        continue;
      }

      const auto requestedUri = frame->currentUris[frame->uriOffset];
      std::optional<uint16_t> existingIndex;
      try
      {
        existingIndex = addressSpace->namespace_array().get_namespace_index(requestedUri);
      }
      catch (const UaException& ex)
      {
        if (ex.status() != Status::BadOutOfRange)
        {
          throw;
        }
        ua::detail::ignore_expected_exception();
      }

      frame->currentMetadataSource.reset();
      frame->currentInitializer = {};
      if (!frame->preparedMetadataUris.contains(std::string{requestedUri}))
      {
        frame->currentMetadataSource =
          find_registration_metadata_source(requestedUri, frame->nodePred, frame->refPred);
        if (frame->currentMetadataSource)
        {
          frame->currentInitializer =
            make_metadata_initializer(requestedUri, frame->currentMetadataSource, frame->refPred);
        }
      }

      if (existingIndex)
      {
        if (!frame->currentMetadataSource)
        {
          frame->currentMap.push_back(*existingIndex);
          ++frame->uriOffset;
          continue;
        }
        frame->step = NamespaceMapFrame::Step::Registering;
        prepare_existing_imported_metadata(std::move(frame), std::move(requestedUri), *existingIndex);
        return;
      }

      if (!mNamespaceAllocator)
      {
        throw UaException{Status::BadInvalidState,
          ErrorDetail::build("NodesetImportFailed",
            "Importing a NodeSet with an unknown namespace URI requires a namespace_factory",
            "NodesetImport")
            .context(ua::ContextKeys::namespaceUri, std::string(requestedUri))};
      }

      auto nameSpace = mNamespaceAllocator(requestedUri);
      if (!nameSpace)
      {
        throw UaException{Status::BadInvalidArgument,
          ErrorDetail::build("InvalidNamespaceIndex",
            "namespace_factory returned a null Namespace for the requested URI",
            "NodesetImport")
            .context(ua::ContextKeys::namespaceUri, std::string(requestedUri))};
      }
      if (string_view{nameSpace->uri()} != string_view{requestedUri})
      {
        throw UaException{Status::BadInvalidArgument,
          ErrorDetail::build("DuplicateNamespaceRegistration",
            "namespace_factory returned a Namespace whose URI does not match the requested URI",
            "NodesetImport")
            .context(ua::ContextKeys::namespaceUri, std::string(requestedUri))
            .context(ua::ContextKeys::actual, std::string(nameSpace->uri()))};
      }

      frame->step = NamespaceMapFrame::Step::Registering;
      auto self = shared_from_this();
      auto executor = addressSpace->executor();
      auto continuation = ua::async::post_owning(self.get(),
        executor,
        addressSpace->logger(),
        [frame, requestedUri](ImportEngine& engine, UInt16Result result) mutable
        { engine.on_namespace_registered(std::move(frame), std::move(requestedUri), std::move(result)); });
      if (frame->currentMetadataSource)
      {
        ::ua::detail::AddressSpaceNamespaceLifecycle::add_imported_namespace_async(
          *addressSpace, std::move(nameSpace), frame->currentInitializer, std::move(continuation));
      }
      else
      {
        addressSpace->add_namespace_async(std::move(nameSpace), std::move(continuation));
      }
      return;
    }

    mNodeSetNsIndexMaps = std::move(frame->maps);
    mNamespaceMapsBuilt = true;
    finish_namespace_maps(std::move(frame), VoidResult{});
  }
  catch (...)
  {
    finish_namespace_maps(
      std::move(frame), VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void ImportEngine::on_namespace_registered(
  shared_ptr<NamespaceMapFrame> frame, String requestedUri, UInt16Result result)
{
  if (frame->step != NamespaceMapFrame::Step::Registering)
  {
    return;
  }

  if (!result.is_good())
  {
    if (result.status_code().as_status() != Status::BadAlreadyExists)
    {
      finish_namespace_maps(std::move(frame), VoidResult{result.status_code(), result.shared_detail()});
      return;
    }

    auto addressSpace = mAddressSpace.lock();
    if (!addressSpace)
    {
      finish_namespace_maps(std::move(frame),
        VoidResult{Status::BadShutdown,
          ErrorDetail::build("NodesetAddressSpaceGone",
            "The address space was destroyed while resolving a namespace registration race",
            "NodesetImport")
            .cause(result.status_code())});
      return;
    }
    try
    {
      result = UInt16Result{addressSpace->namespace_array().get_namespace_index(requestedUri)};
    }
    catch (...)
    {
      const auto lookupFailure = ua::exception_to_status_code(std::current_exception());
      finish_namespace_maps(std::move(frame),
        VoidResult{lookupFailure.as_status(),
          ErrorDetail::build("NamespaceRegistrationRaceUnresolved",
            "A concurrent registration reported the URI as present but it could not be resolved",
            "NodesetImport")
            .context(ua::ContextKeys::namespaceUri, std::string(requestedUri))
            .cause(lookupFailure)});
      return;
    }
    if (frame->currentMetadataSource)
    {
      prepare_existing_imported_metadata(std::move(frame), std::move(requestedUri), result.value());
      return;
    }
  }

  if (frame->currentMetadataSource)
  {
    frame->preparedMetadataUris.insert(std::string{requestedUri});
  }
  frame->currentMetadataSource.reset();
  frame->currentInitializer = {};
  frame->currentMap.push_back(result.value());
  ++frame->uriOffset;
  frame->step = NamespaceMapFrame::Step::Selecting;
  drive_namespace_maps(std::move(frame));
}

void ImportEngine::prepare_existing_imported_metadata(
  shared_ptr<NamespaceMapFrame> frame, String requestedUri, uint16_t namespaceIndex)
{
  try
  {
    auto addressSpace = mAddressSpace.lock();
    if (!addressSpace)
    {
      finish_namespace_maps(std::move(frame),
        VoidResult{Status::BadShutdown,
          ErrorDetail::build("NodesetAddressSpaceGone",
            "The address space was destroyed while preparing imported namespace metadata",
            "NodesetImport")});
      return;
    }
    if (!frame->currentMetadataSource || !frame->currentInitializer)
    {
      finish_namespace_maps(std::move(frame),
        VoidResult{Status::BadInternalError,
          ErrorDetail::build("NamespaceMetadataInitializerMissing",
            "The imported metadata declaration lost its staging initializer",
            "NodesetImport")
            .context(ContextKeys::namespaceUri, std::string{requestedUri})});
      return;
    }

    mNodeSetNsIndexMaps.insert_or_assign(frame->currentMetadataSource->nodeSet,
      registration_namespace_map(*frame->currentMetadataSource->nodeSet, requestedUri, namespaceIndex));
    const auto metadataObject = translate_node_id(
      *frame->currentMetadataSource->nodeSet, frame->currentMetadataSource->metadataObject->node_id());
    auto self = shared_from_this();
    auto continuation = ua::async::post_owning(self.get(),
      addressSpace->executor(),
      addressSpace->logger(),
      [frame, requestedUri, namespaceIndex](ImportEngine& engine, VoidResult result) mutable
      {
        engine.on_existing_imported_metadata_prepared(
          std::move(frame), std::move(requestedUri), namespaceIndex, std::move(result));
      });
    ::ua::detail::AddressSpaceNamespaceLifecycle::prepare_imported_metadata_async(
      *addressSpace, namespaceIndex, metadataObject, frame->currentInitializer, std::move(continuation));
  }
  catch (...)
  {
    finish_namespace_maps(
      std::move(frame), VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void ImportEngine::on_existing_imported_metadata_prepared(
  shared_ptr<NamespaceMapFrame> frame, String requestedUri, uint16_t namespaceIndex, VoidResult result)
{
  if (frame->step != NamespaceMapFrame::Step::Registering)
  {
    return;
  }
  if (result.is_bad())
  {
    finish_namespace_maps(std::move(frame), VoidResult{result.status_code(), result.shared_detail()});
    return;
  }

  frame->preparedMetadataUris.insert(std::string{requestedUri});
  frame->currentMetadataSource.reset();
  frame->currentInitializer = {};
  frame->currentMap.push_back(namespaceIndex);
  ++frame->uriOffset;
  frame->step = NamespaceMapFrame::Step::Selecting;
  drive_namespace_maps(std::move(frame));
}

void ImportEngine::finish_namespace_maps(shared_ptr<NamespaceMapFrame> frame, VoidResult result)
{
  if (frame->step == NamespaceMapFrame::Step::Done)
  {
    return;
  }
  frame->step = NamespaceMapFrame::Step::Done;
  auto completion = std::move(frame->completion);
  completion(std::move(result));
}

shared_ptr<ImportEngine::RegistrationMetadataSource> ImportEngine::find_registration_metadata_source(
  string_view namespaceUri, const optional<ImportNodePredicate>& nodePred,
  const optional<ImportReferencePredicate>& refPred) const
{
  shared_ptr<RegistrationMetadataSource> found;
  for (const auto& nodeSet : mNodeSets)
  {
    if (!nodeSet || !nodeSet->namespace_uris())
    {
      continue;
    }
    const auto uris = nodeSet->namespace_uris()->uris();
    for (const auto& [nodeId, ownedNode] : nodeSet->nodes())
    {
      Node* node = ownedNode.get();
      if (!node || node->node_class() != NodeClass::Object || nodeId.namespace_index() == 0 ||
          nodeId.namespace_index() > uris.size() ||
          string_view{uris[nodeId.namespace_index() - 1U]} != namespaceUri)
      {
        continue;
      }
      const auto releaseStatus = node->release_status();
      if ((!mIncludeNonReleased && releaseStatus && *releaseStatus != Node::ReleaseStatus::Released) ||
          (nodePred && !(*nodePred)(*node)))
      {
        continue;
      }

      bool isAcceptedMetadataObject = false;
      for (const auto& reference : node->references())
      {
        if (reference.isForward && reference.typeId == NodeId{ReferenceTypeId::HasTypeDefinition} &&
            reference.targetId == NodeId{ObjectTypeId::NamespaceMetadataType} &&
            (!refPred || (*refPred)(*node, reference)))
        {
          isAcceptedMetadataObject = true;
          break;
        }
      }
      if (!isAcceptedMetadataObject)
      {
        continue;
      }

      if (found && found->metadataObject->node_id() != node->node_id())
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("DuplicateNamespaceMetadataDeclaration",
            "A NodeSet import declares more than one metadata Object for one namespace",
            "NodesetImport")
            .context(ContextKeys::namespaceUri, std::string{namespaceUri})
            .context(ContextKeys::expected, to_string(found->metadataObject->node_id()))
            .context(ContextKeys::actual, to_string(node->node_id()))};
      }
      if (found)
      {
        continue;
      }

      found = make_shared<RegistrationMetadataSource>();
      found->nodeSet = nodeSet.get();
      found->metadataObject = node;
      found->nodes.push_back(node);
      std::unordered_set<NodeId> selected{node->node_id()};
      for (const auto& reference : node->references())
      {
        if (!reference.isForward || reference.typeId != NodeId{ReferenceTypeId::HasProperty} ||
            (refPred && !(*refPred)(*node, reference)))
        {
          continue;
        }
        auto* child = nodeSet->find_node(reference.targetId);
        if (!child || (nodePred && !(*nodePred)(*child)))
        {
          continue;
        }
        const auto childReleaseStatus = child->release_status();
        if (!mIncludeNonReleased && childReleaseStatus &&
            *childReleaseStatus != Node::ReleaseStatus::Released)
        {
          continue;
        }
        if (selected.insert(child->node_id()).second)
        {
          found->nodes.push_back(child);
        }
      }
    }
  }
  return found;
}

::ua::detail::NamespaceRegistrationInitializer ImportEngine::make_metadata_initializer(String namespaceUri,
  shared_ptr<RegistrationMetadataSource> source, optional<ImportReferencePredicate> refPred)
{
  auto self = shared_from_this();
  return
    [self, namespaceUri = std::move(namespaceUri), source = std::move(source), refPred = std::move(refPred)](
      ::ua::detail::NamespaceRegistrationCandidate candidate,
      ::ua::detail::NamespaceRegistrationInitializationCallback completion) mutable
  {
    if (candidate.namespaceUri != namespaceUri)
    {
      completion(::ua::detail::NamespaceRegistrationInitializationResult{Status::BadConfigurationError,
        ErrorDetail::build("NamespaceMetadataInitializerUriMismatch",
          "The namespace coordinator invoked a NodeSet initializer for a different URI",
          "NodesetImport")
          .context(ContextKeys::expected, std::string{namespaceUri})
          .context(ContextKeys::actual, std::string{candidate.namespaceUri})});
      return;
    }
    self->stage_registration_metadata_async(std::move(candidate.stagedAddressSpace),
      candidate.namespaceIndex,
      namespaceUri,
      source,
      refPred,
      std::move(completion));
  };
}

std::vector<uint16_t> ImportEngine::registration_namespace_map(
  const NodeSet& nodeSet, string_view candidateUri, uint16_t candidateIndex) const
{
  std::vector<uint16_t> mapping{0};
  const auto& namespaceUris = nodeSet.namespace_uris();
  if (!namespaceUris)
  {
    return mapping;
  }
  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    throw UaException{Status::BadShutdown,
      ErrorDetail::build("NodesetAddressSpaceGone",
        "The address space was destroyed while staging imported namespace metadata",
        "NodesetImport")};
  }

  for (const auto& uri : namespaceUris.value().uris())
  {
    if (string_view{uri} == candidateUri)
    {
      mapping.push_back(candidateIndex);
      continue;
    }
    try
    {
      mapping.push_back(addressSpace->namespace_array().get_namespace_index(uri));
    }
    catch (const UaException& ex)
    {
      if (ex.status() != Status::BadOutOfRange)
      {
        throw;
      }
      ua::detail::ignore_expected_exception();
      break;
    }
  }
  return mapping;
}

void ImportEngine::stage_registration_metadata_async(AddressSpace stagedAddressSpace, uint16_t namespaceIndex,
  String namespaceUri, shared_ptr<RegistrationMetadataSource> source,
  optional<ImportReferencePredicate> refPred,
  ::ua::detail::NamespaceRegistrationInitializationCallback completion)
{
  // A caller that passes no callback still has the metadata staged; a failure is logged instead.
  completion = ::ua::detail::completion_or_log(
    std::move(completion), stagedAddressSpace.logger(), "ImportEngine::stage_registration_metadata_async");
  auto fallbackCompletion = completion;
  try
  {
    mNodeSetNsIndexMaps.insert_or_assign(
      source->nodeSet, registration_namespace_map(*source->nodeSet, namespaceUri, namespaceIndex));
    auto frame = make_shared<RegistrationMetadataFrame>(std::move(stagedAddressSpace));
    frame->namespaceUri = std::move(namespaceUri);
    frame->namespaceIndex = namespaceIndex;
    frame->source = std::move(source);
    frame->refPred = std::move(refPred);
    frame->completion = std::move(completion);
    drive_registration_metadata(std::move(frame));
  }
  catch (...)
  {
    fallbackCompletion(::ua::detail::NamespaceRegistrationInitializationResult{
      ua::exception_to_status_code(std::current_exception())});
  }
}

void ImportEngine::drive_registration_metadata(shared_ptr<RegistrationMetadataFrame> frame)
{
  if (frame->done)
  {
    return;
  }

  try
  {
    const auto& mapping = ns_index_map(*frame->source->nodeSet);
    auto availableReference = [mapSize = mapping.size(), callerFilter = frame->refPred](
                                const Node& source, const Node::Reference& reference)
    {
      if (callerFilter && !(*callerFilter)(source, reference))
      {
        return false;
      }
      return reference.typeId.namespace_index() < mapSize && reference.targetId.namespace_index() < mapSize;
    };

    auto operation = make_shared<Operation>();
    for (Node* sourceNode : frame->source->nodes)
    {
      operation->seedNodes.emplace_back(frame->source->nodeSet, sourceNode);
    }
    operation->refPred = ImportReferencePredicate{std::move(availableReference)};
    operation->stagedAddressSpace = frame->stagedAddressSpace;
    operation->stagedCreatedNodes = frame->createdNodes;
    operation->namespaceMapsReady = true;
    operation->countReferences = false;
    operation->translateReferencesInSourceFrame = true;
    auto self = shared_from_this();
    operation->completion = [self, frame](VoidResult result) mutable
    {
      self->finish_registration_metadata(std::move(frame),
        result.is_bad() ? VoidResult{result.status_code(), result.shared_detail()} : VoidResult{});
    };
    start_operation(std::move(operation));
  }
  catch (...)
  {
    finish_registration_metadata(
      std::move(frame), VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void ImportEngine::finish_registration_metadata(
  shared_ptr<RegistrationMetadataFrame> frame, VoidResult result)
{
  if (frame->done)
  {
    return;
  }
  frame->done = true;
  auto completion = std::move(frame->completion);

  NodeId metadataObject;
  try
  {
    metadataObject = translate_node_id(*frame->source->nodeSet, frame->source->metadataObject->node_id());
  }
  catch (...)
  {
    if (result.is_good())
    {
      result = VoidResult{ua::exception_to_status_code(std::current_exception())};
    }
  }

  auto preparation =
    make_shared<ImportedMetadataPreparation>(frame->stagedAddressSpace, std::move(*frame->createdNodes));
  if (result.is_bad())
  {
    auto logger = frame->logger;
    preparation->rollback_async(
      [preparation,
        logger = std::move(logger),
        result = std::move(result),
        completion = std::move(completion)](VoidResult cleanup) mutable
      {
        if (cleanup.is_bad())
        {
          logger.error({{"status", to_string(cleanup.status_code())}},
            "Failed to roll back staged NodeSet metadata after an import failure");
        }
        completion(::ua::detail::NamespaceRegistrationInitializationResult{
          result.status_code(), result.shared_detail()});
      });
    return;
  }

  ::ua::detail::NamespaceRegistrationInitialization initialized;
  initialized.metadataObject = metadataObject;
  initialized.preparation = std::move(preparation);
  completion(::ua::detail::NamespaceRegistrationInitializationResult{std::move(initialized)});
}

const std::vector<uint16_t>& ImportEngine::ns_index_map(const NodeSet& nodeSet) const
{
  auto it = mNodeSetNsIndexMaps.find(&nodeSet);
  // Maps are built eagerly for all node sets before any node is processed.
  return it->second;
}

NodeId ImportEngine::translate_node_id(const NodeSet& nodeSet, const NodeId& nodeId) const
{
  auto ns = nodeId.namespace_index();
  if (ns == 0)
  {
    return nodeId;
  }
  const auto& map = ns_index_map(nodeSet);
  if (ns >= map.size())
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("InvalidNodesetXml",
        "NodeId namespace index is out of range for the NodeSet namespace map",
        "NodesetImport")
        .context(ua::ContextKeys::namespaceIndex, std::to_string(ns))
        .context(ua::ContextKeys::sizeMax, std::to_string(map.size()))};
  }
  auto translated = nodeId;
  translated.namespace_index() = map[ns];
  return translated;
}

QualifiedName ImportEngine::translate_qualified_name(
  const NodeSet& nodeSet, const QualifiedName& browseName) const
{
  auto ns = browseName.namespace_index();
  if (ns == 0)
  {
    return browseName;
  }
  const auto& map = ns_index_map(nodeSet);
  if (ns >= map.size())
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("InvalidNodesetXml",
        "QualifiedName namespace index is out of range for the NodeSet namespace map",
        "NodesetImport")
        .context(ua::ContextKeys::namespaceIndex, std::to_string(ns))
        .context(ua::ContextKeys::sizeMax, std::to_string(map.size()))};
  }
  auto translated = browseName;
  translated.namespace_index() = map[ns];
  return translated;
}

CodecNamespaceContext ImportEngine::make_translation_config(const NodeSet& nodeSet) const
{
  // The hooks fire as each value is decoded, reaching embedded ids wherever they appear (scalars,
  // arrays, structure/union fields, the ExtensionObject TypeId). Consumed synchronously within
  // `value(config)`; the prebuilt maps mean no AddressSpace is needed here. `translateExpandedNodeId`
  // is deliberately left unset (D-P): the decoder routes an ExpandedNodeId's inner NodeId through
  // decode(NodeId&), so translateNodeId already translates it exactly once.
  CodecNamespaceContext config;
  config.translateNodeId = [this, &nodeSet](NodeId& id)
  {
    id = translate_node_id(nodeSet, id);
  };
  config.translateQualifiedName = [this, &nodeSet](QualifiedName& name)
  {
    name = translate_qualified_name(nodeSet, name);
  };
  return config;
}

const StructureResolver& ImportEngine::resolver_for(const NodeSet& nodeSet) const
{
  // D-H 6: realize values into the target frame with the import's resolver when one was supplied;
  // otherwise fall back to the NodeSet's own parse-time resolver (NS0 + standard-struct values).
  return mStructureResolverOverride ? mStructureResolverOverride : nodeSet.structure_resolver();
}

void ImportEngine::copy_base_attributes(
  const Node& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(AttributeId::BrowseName,
    attribute_wire::browse_name(translate_qualified_name(nodeSet, source.browse_name())));
  // A creation Attribute is held as given, so a Node's translations are given as one LocalizedText.
  if (const auto displayNames = source.display_name(); !displayNames.empty())
  {
    // Each translation is held to DisplayName's size limit, which the folded value checks only for its first.
    for (const auto& displayName : displayNames)
    {
      static_cast<void>(attribute_wire::display_name(displayName));
    }
    attributes.emplace_back(
      AttributeId::DisplayName, attribute_wire::display_name(fold_candidates(displayNames)));
  }
  if (const auto descriptions = source.description(); !descriptions.empty())
  {
    attributes.emplace_back(
      AttributeId::Description, attribute_wire::description(fold_candidates(descriptions)));
  }
  attributes.emplace_back(AttributeId::WriteMask, attribute_wire::write_mask(source.write_mask()));

  // Consulted before either access-control Attribute is read, so a stamped node takes the stamp whether
  // or not the NodeSet declares one for it.
  const AccessDecoration* decoration{nullptr};
  if (!mAccessDecoration.empty())
  {
    const auto entry = mAccessDecoration.find(source.node_id());
    if (entry != mAccessDecoration.end())
    {
      decoration = &entry->second;
    }
  }

  bool decorated{false};
  std::vector<RolePermissionType> rolePermissions;
  if (decoration)
  {
    const auto& authoredPermissions = decoration->rolePermissions;
    if (authoredPermissions.has_value())
    {
      rolePermissions = authoredPermissions.value();
      decorated = true;
    }
  }
  if (!decorated)
  {
    rolePermissions = source.role_permissions();
  }
  if (!rolePermissions.empty())
  {
    // Role ids are structural ids (used for server-side authorization lookups), so they must be
    // translated from the NodeSet-local namespace to the server namespace at this write boundary.
    for (auto& rolePermission : rolePermissions)
    {
      rolePermission.role_id() = translate_node_id(nodeSet, rolePermission.role_id());
    }
    attributes.emplace_back(AttributeId::RolePermissions,
      attribute_wire::role_permissions(optional<std::vector<RolePermissionType>>{rolePermissions}));
  }
  else if (decorated || source.has_no_permissions())
  {
    // An engaged-but-empty decoration says what `HasNoPermissions` says, and must not fall through.
    //
    // D-L: <HasNoPermissions>true</HasNoPermissions> declares an *explicit empty* permission set,
    // which is authorization-significant (no role may access the node) and distinct from "no
    // RolePermissions specified" (left as the node's default). Apply the explicit empty set - the
    // encoder must produce the array form (not an empty Variant), so the optional is engaged with
    // an empty vector, matching the setter, which always wrote the array when called.
    attributes.emplace_back(AttributeId::RolePermissions,
      attribute_wire::role_permissions(
        optional<std::vector<RolePermissionType>>{std::vector<RolePermissionType>{}}));
  }

  auto accessRestrictions = decoration && decoration->accessRestrictions ? decoration->accessRestrictions
                                                                         : source.access_restrictions();
  if (accessRestrictions)
  {
    attributes.emplace_back(
      AttributeId::AccessRestrictions, attribute_wire::access_restrictions(accessRestrictions));
  }
}

void ImportEngine::copy_attributes(const ReferenceType& source, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(AttributeId::IsAbstract, attribute_wire::is_abstract(source.is_abstract()));
  attributes.emplace_back(AttributeId::Symmetric, attribute_wire::symmetric(source.symmetric()));
  for (const auto& inverseName : source.inverse_name())
  {
    attributes.emplace_back(AttributeId::InverseName, attribute_wire::inverse_name(inverseName));
  }
}

void ImportEngine::copy_attributes(
  const DataType& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(AttributeId::IsAbstract, attribute_wire::is_abstract(source.is_abstract()));

  auto sourceDefinition = source.definition();
  if (!sourceDefinition.has_value())
  {
    return;
  }

  auto aggregateFields = utilities::aggregate_fields(node_sets(), source);

  if (utilities::is_a_structure(mLimits, node_sets(), source))
  {
    auto structureDefinition = make_shared<StructureDefinition>();
    structureDefinition->default_encoding_id() = default_binary_encoding_id(source, nodeSet);

    auto parent = utilities::get_parent(node_sets(), source);
    if (parent)
    {
      auto [parentNodeSet, parentNode] = find_node_with_nodeset(parent->node_id());
      if (!parentNodeSet)
      {
        throw UaException{Status::BadInvalidState,
          ErrorDetail::build("NodesetImportFailed",
            "Could not determine the NodeSet for the DataType parent of the node",
            "NodesetImport")
            .context(ua::ContextKeys::nodeId, to_string(source.node_id()))};
      }
      structureDefinition->base_data_type() = translate_node_id(*parentNodeSet, parent->node_id());
    }

    auto hasOptionalFields = has_optional_fields(aggregateFields);
    auto allowsSubTypes = allows_sub_types(aggregateFields);

    auto structureType = StructureType::Structure;
    if (hasOptionalFields && !allowsSubTypes)
    {
      structureType = StructureType::StructureWithOptionalFields;
    }
    else if (sourceDefinition->is_union() && !allowsSubTypes)
    {
      structureType = StructureType::Union;
    }
    else if (!hasOptionalFields && allowsSubTypes)
    {
      structureType = StructureType::StructureWithSubtypedValues;
    }
    else if (sourceDefinition->is_union() && allowsSubTypes)
    {
      structureType = StructureType::UnionWithSubtypedValues;
    }
    structureDefinition->structure_type() = structureType;

    Array<StructureField> fields;
    fields.reserve(aggregateFields.size());
    for (const auto& field : aggregateFields)
    {
      StructureField structureField;
      structureField.name() = field.name();
      if (!field.description().empty())
      {
        structureField.description() = fold_candidates(field.description());
      }
      structureField.data_type() = translate_node_id(nodeSet, field.data_type());
      structureField.value_rank() = field.value_rank();
      structureField.array_dimensions() = utils::span_of_int32_to_uint32(field.array_dimensions());
      // OPC 10000-3 section 8.51: for valueRank >= 1 the arrayDimensions element count "shall be equal to
      // the value of the valueRank field", and the clause supplies its own encoding for "no bound to
      // declare" -- the element value 0. Unlike the Variable ArrayDimensions *Attribute*, which Part 3
      // Table 13 marks Optional, this field is not optional for an array, so a NodeSet that omits it
      // leaves a definition a Client cannot read the rank off. Filling the omission with zeroes is
      // the clause's own answer and is not an invention.
      if (structureField.value_rank() >= 1 &&
          structureField.array_dimensions().size() != static_cast<size_t>(structureField.value_rank()))
      {
        structureField.array_dimensions().payload().assign(
          static_cast<size_t>(structureField.value_rank()), uint32_t{0});
      }
      structureField.max_string_length() = field.max_string_length();

      if (hasOptionalFields)
      {
        structureField.is_optional() = field.is_optional();
      }
      else if (allowsSubTypes)
      {
        structureField.is_optional() = field.allow_sub_types();
      }
      fields.push_back(std::move(structureField));
    }
    structureDefinition->fields() = std::move(fields);
    attributes.emplace_back(
      AttributeId::DataTypeDefinition, attribute_wire::data_type_definition(structureDefinition));
  }
  else if (utilities::is_an_enumeration(mLimits, node_sets(), source) || sourceDefinition->is_option_set())
  {
    auto enumDefinition = make_shared<EnumDefinition>();
    Array<EnumField> fields;
    fields.reserve(aggregateFields.size());
    for (const auto& field : aggregateFields)
    {
      EnumField enumField;
      enumField.name() = field.name();
      if (!field.display_name().empty())
      {
        enumField.display_name() = fold_candidates(field.display_name());
      }
      if (!field.description().empty())
      {
        enumField.description() = fold_candidates(field.description());
      }
      const auto fieldValue = field.value();
      if (fieldValue.has_value())
      {
        enumField.value() = *fieldValue;
      }
      fields.push_back(std::move(enumField));
    }
    enumDefinition->fields() = std::move(fields);
    attributes.emplace_back(
      AttributeId::DataTypeDefinition, attribute_wire::data_type_definition(enumDefinition));
  }
}

void ImportEngine::copy_attributes(const Object& source, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(
    AttributeId::EventNotifier, attribute_wire::event_notifier(source.event_notifier()));
}

void ImportEngine::copy_attributes(
  const VariableType& source, const NodeSet& nodeSet, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(AttributeId::IsAbstract, attribute_wire::is_abstract(source.is_abstract()));

  auto value = source.value(resolver_for(nodeSet), make_translation_config(nodeSet));
  if (!value.empty())
  {
    if (mFailOnUnknownStructure && variant_contains_unknown_structure(value))
    {
      throw UaException(Status::BadNotSupported,
        ErrorDetail::build("UnresolvedStructureValue",
          "NodeSet value contains an ExtensionObject of an unresolved type; supply a structure_resolver "
          "or set on_unknown_structure = ImportOpaque",
          "NodesetImport")
          .context(ua::ContextKeys::nodeId, to_string(source.node_id())));
    }
    optional<DataValue> dataValue{DataValue{}};
    dataValue->value() = std::move(value);
    attributes.emplace_back(AttributeId::Value, attribute_wire::variable_type_value(dataValue));
  }

  attributes.emplace_back(
    AttributeId::DataType, attribute_wire::data_type(translate_node_id(nodeSet, source.data_type())));
  attributes.emplace_back(AttributeId::ValueRank, attribute_wire::value_rank(ValueRank{source.value_rank()}));
  attributes.emplace_back(AttributeId::ArrayDimensions,
    attribute_wire::array_dimensions(utils::span_of_int32_to_uint32(source.array_dimensions())));
}

void ImportEngine::copy_attributes(const Method& source, ua::InitialAttributes& attributes)
{
  UA_UNUSED(source);
  attributes.emplace_back(AttributeId::Executable, attribute_wire::executable(true));
}

void ImportEngine::copy_attributes(const ObjectType& source, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(AttributeId::IsAbstract, attribute_wire::is_abstract(source.is_abstract()));
}

void ImportEngine::copy_attributes(const View& source, ua::InitialAttributes& attributes)
{
  attributes.emplace_back(
    AttributeId::ContainsNoLoops, attribute_wire::contains_no_loops(source.contains_no_loops()));
  attributes.emplace_back(
    AttributeId::EventNotifier, attribute_wire::event_notifier(source.event_notifier()));
}

ua::InitialAttributes ImportEngine::build_initial_attributes(const Node& source, const NodeSet& nodeSet)
{
  ua::InitialAttributes attributes;
  copy_base_attributes(source, nodeSet, attributes);

  switch (source.node_class())
  {
  case NodeClass::ReferenceType:
    copy_attributes(dynamic_cast<const ReferenceType&>(source), attributes);
    break;
  case NodeClass::Object:
    copy_attributes(dynamic_cast<const Object&>(source), attributes);
    break;
  case NodeClass::DataType:
    copy_attributes(dynamic_cast<const DataType&>(source), nodeSet, attributes);
    break;
  case NodeClass::ObjectType:
    copy_attributes(dynamic_cast<const ObjectType&>(source), attributes);
    break;
  case NodeClass::VariableType:
    copy_attributes(dynamic_cast<const VariableType&>(source), nodeSet, attributes);
    break;
  case NodeClass::Method:
    copy_attributes(dynamic_cast<const Method&>(source), attributes);
    break;
  case NodeClass::View:
    copy_attributes(dynamic_cast<const View&>(source), attributes);
    break;
  case NodeClass::Variable:
  {
    // A Variable instance's non-Value attributes are creation attributes (folded here); only its
    // live Value stays on the async value path (write_value_async in copy_class_attributes).
    const auto& variableSource = dynamic_cast<const Variable&>(source);
    attributes.emplace_back(AttributeId::DataType,
      attribute_wire::data_type(translate_node_id(nodeSet, variableSource.data_type())));
    attributes.emplace_back(
      AttributeId::ValueRank, attribute_wire::value_rank(ValueRank{variableSource.value_rank()}));
    attributes.emplace_back(AttributeId::ArrayDimensions,
      attribute_wire::array_dimensions(utils::span_of_int32_to_uint32(variableSource.array_dimensions())));
    attributes.emplace_back(AttributeId::AccessLevelEx,
      attribute_wire::access_level_ex(optional<AccessLevelExType>{variableSource.access_level()}));
    attributes.emplace_back(AttributeId::MinimumSamplingInterval,
      attribute_wire::minimum_sampling_interval(variableSource.minimum_sampling_interval()));
    attributes.emplace_back(
      AttributeId::Historizing, attribute_wire::historizing(variableSource.historizing()));
    break;
  }
  default:
    break;
  }

  return attributes;
}

bool ImportEngine::has_optional_fields(span<const DataTypeField> fields)
{
  for (auto& field : fields)
  {
    if (field.is_optional())
    {
      return true;
    }
  }
  return false;
}

bool ImportEngine::allows_sub_types(span<const DataTypeField> fields)
{
  for (auto& field : fields)
  {
    if (field.allow_sub_types())
    {
      return true;
    }
  }
  return false;
}

NodeId ImportEngine::default_binary_encoding_id(const Node& dataType, const NodeSet& nodeSet)
{
  UA_UNUSED(nodeSet);
  for (const auto& reference : dataType.raw_references())
  {
    if ((reference.type_id() == NodeId{ReferenceTypeId::HasEncoding}) && reference.is_forward())
    {
      const Node* node = utilities::find_node(node_sets(), reference.target_id());
      if (node && (node->browse_name() == QualifiedName{"Default Binary"}))
      {
        auto [encodingNodeSet, encodingNode] = find_node_with_nodeset(node->node_id());
        if (!encodingNodeSet)
        {
          throw UaException{Status::BadInvalidState,
            ErrorDetail::build(
              "NodesetImportFailed", "Could not determine the NodeSet for the encoding node", "NodesetImport")
              .context(ua::ContextKeys::nodeId, to_string(node->node_id()))};
        }
        return translate_node_id(*encodingNodeSet, node->node_id());
      }
    }
  }
  return {};
}

bool ImportEngine::is_data_type_encoding(const Node& node)
{
  if (node.node_class() != NodeClass::Object)
  {
    return false;
  }
  for (const auto& reference : node.raw_references())
  {
    if ((reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition}) && reference.is_forward() &&
        (reference.target_id() == NodeId{ObjectTypeId::DataTypeEncodingType}))
    {
      return true;
    }
  }
  return false;
}

// =================================================================================================
// Operation entry points.
// =================================================================================================

void ImportEngine::import_all_async(
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred, Completion completion)
{
  shared_ptr<Operation> operation;
  try
  {
    operation = make_shared<Operation>();
    for (const auto& nodeSet : mNodeSets)
    {
      if (!nodeSet)
      {
        continue;
      }
      for (const auto& [id, node] : nodeSet->nodes())
      {
        if (!nodePred || (*nodePred)(*node))
        {
          operation->seedNodes.emplace_back(nodeSet.get(), node.get());
        }
      }
    }
  }
  catch (...)
  {
    completion(VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  operation->nodePred = std::move(nodePred);
  operation->refPred = std::move(refPred);
  operation->completion = std::move(completion);
  start_operation(std::move(operation));
}

void ImportEngine::import_type_definitions_only_async(std::string excludedCategorySubstring,
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred, Completion completion)
{
  auto self = shared_from_this();
  auto excluded = std::make_shared<std::string>(std::move(excludedCategorySubstring));

  auto categoryExcluded = [excluded](const Node& node) -> bool
  {
    if (excluded->empty())
    {
      return false;
    }
    const auto category = node.category();
    if (!category)
    {
      return false;
    }
    return string_view{*category}.find(*excluded) != string_view::npos;
  };

  // Mirrors Importer::import_type_definitions_only::should_import_node.
  auto shouldImport = [self, categoryExcluded, callerNodePred = nodePred](const Node& node) -> bool
  {
    if (categoryExcluded(node))
    {
      return false;
    }
    if (callerNodePred && !(*callerNodePred)(node))
    {
      return false;
    }
    switch (node.node_class())
    {
    case NodeClass::ReferenceType:
    case NodeClass::ObjectType:
    case NodeClass::VariableType:
      return true;
    case NodeClass::DataType:
    {
      const auto& dataType = dynamic_cast<const DataType&>(node);
      return dataType.purpose() == DataType::DataTypePurpose::Normal;
    }
    case NodeClass::Object:
    case NodeClass::Variable:
    case NodeClass::Method:
    {
      // DataType encoding objects (Default Binary / Default XML) have no ParentNodeId - the parent
      // walk below can't reach them. Recognise them directly so structure DataTypes import with the
      // encoding objects clients need to (de)serialise the type (e.g. ServerStatusDataType's
      // Default Binary, the HasEncoding target the address model otherwise lacks).
      if (is_data_type_encoding(node))
      {
        return true;
      }

      LoopLimit parentBudget{self->mLimits.execution.loopLimit};
      const Node* current = &node;
      while (true)
      {
        parentBudget.consume_iteration();
        const auto& instance = dynamic_cast<const Instance&>(*current);
        const auto parentId = instance.parent_node_id();
        const auto* parent = utilities::find_node(self->node_sets(), parentId);
        if (!parent)
        {
          return false;
        }
        if (categoryExcluded(*parent))
        {
          return false;
        }
        switch (parent->node_class())
        {
        case NodeClass::ObjectType:
        case NodeClass::VariableType:
        case NodeClass::DataType:
          // A DataType's Property children (EnumStrings / EnumValues / OptionSetValues) are part of
          // its type definition - they carry the enumeration/option-set metadata clients read to
          // interpret the type. Import them with the type, exactly like ObjectType/VariableType
          // components. Without this the enum DataTypes import without their value Property and the
          // address model is incomplete (e.g. ServerState has no EnumStrings).
          return true;
        case NodeClass::Object:
        case NodeClass::Variable:
        case NodeClass::Method:
          current = parent;
          continue;
        default:
          return false;
        }
      }
    }
    default:
      return false;
    }
  };

  ImportNodePredicate nodePredicate = [shouldImport](const Node& node)
  {
    return shouldImport(node);
  };

  ImportReferencePredicate refPredicate = [self, shouldImport, callerRefPred = refPred](
                                            const Node& node, const Node::Reference& reference)
  {
    // Honour a caller-supplied reference filter first.
    if (callerRefPred && !(*callerRefPred)(node, reference))
    {
      return false;
    }
    // Always keep structural metadata references to well-known singletons.
    if (reference.typeId == NodeId{ReferenceTypeId::HasModellingRule} ||
        reference.typeId == NodeId{ReferenceTypeId::HasTypeDefinition})
    {
      return true;
    }
    const auto* target = utilities::find_node(self->node_sets(), reference.targetId);
    if (!target)
    {
      return true;  // target imported elsewhere or absent - keep the reference
    }
    // A target this filter would skip may already be in the address space - the Types folders the
    // server imports first, for one. Keep that reference: dropping it loses the inverse half of a
    // hierarchical reference (VariableTypes -Organizes-> BaseVariableType), so an inverse browse from
    // a type never reaches Root through Types (Part 3 5.3.2).
    return self->mNodesInAddressSpace.contains(target) || shouldImport(*target);
  };

  import_all_async(std::move(nodePredicate), std::move(refPredicate), std::move(completion));
}

void ImportEngine::import_node_async(
  NodeId nodeId, optional<ImportReferencePredicate> refPred, Completion completion)
{
  auto operation = make_shared<Operation>();
  operation->seedIds.push_back(std::move(nodeId));
  operation->refPred = std::move(refPred);
  operation->completion = std::move(completion);
  start_operation(std::move(operation));
}

void ImportEngine::import_node_and_forward_refs_async(NodeId nodeId, optional<ImportNodePredicate> nodePred,
  optional<ImportReferencePredicate> refPred, Completion completion)
{
  auto operation = make_shared<Operation>();
  operation->seedIds.push_back(std::move(nodeId));
  operation->followForwardReferences = true;
  operation->budget = make_shared<WorkBudget>(mLimits.work_budget());
  operation->nodePred = std::move(nodePred);
  operation->refPred = std::move(refPred);
  operation->completion = std::move(completion);
  start_operation(std::move(operation));
}

// =================================================================================================
// Synchronous convenience wrappers (two-variant pattern). See the header for the blocking contract:
// the caller's thread must not be an AS-executor thread.
// =================================================================================================

VoidResult ImportEngine::drive_sync(const std::function<void(Completion)>& start)
{
  // External/startup-thread convenience: refused on an AS-executor thread, otherwise blocks the caller.
  // `start` launches the async op synchronously (moving its predicates into the engine's chain) before
  // returning, so the caller's locals stay valid for the launch. With the address space already gone
  // there is no executor to refuse; the operation itself reports Bad_Shutdown.
  const auto addressSpace = mAddressSpace.lock();
  return ua::async::detail::blocking_call<VoidResult>(
    addressSpace ? addressSpace->executor() : boost::asio::any_io_executor{},
    [&start](std::function<void(VoidResult)> complete) { start(std::move(complete)); });
}

VoidResult ImportEngine::try_import_all_sync(
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  return drive_sync([&](Completion completion)
    { import_all_async(std::move(nodePred), std::move(refPred), std::move(completion)); });
}

void ImportEngine::import_all_sync(
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  auto result = try_import_all_sync(std::move(nodePred), std::move(refPred));
  if (result.is_bad())
  {
    throw UaException(result.status_code());
  }
}

VoidResult ImportEngine::try_import_type_definitions_only_sync(std::string excludedCategorySubstring,
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  return drive_sync(
    [&](Completion completion)
    {
      import_type_definitions_only_async(
        std::move(excludedCategorySubstring), std::move(nodePred), std::move(refPred), std::move(completion));
    });
}

void ImportEngine::import_type_definitions_only_sync(std::string excludedCategorySubstring,
  optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  auto result = try_import_type_definitions_only_sync(
    std::move(excludedCategorySubstring), std::move(nodePred), std::move(refPred));
  if (result.is_bad())
  {
    throw UaException(result.status_code());
  }
}

VoidResult ImportEngine::try_import_node_sync(NodeId nodeId, optional<ImportReferencePredicate> refPred)
{
  return drive_sync([&](Completion completion)
    { import_node_async(std::move(nodeId), std::move(refPred), std::move(completion)); });
}

void ImportEngine::import_node_sync(NodeId nodeId, optional<ImportReferencePredicate> refPred)
{
  auto result = try_import_node_sync(std::move(nodeId), std::move(refPred));
  if (result.is_bad())
  {
    throw UaException(result.status_code());
  }
}

VoidResult ImportEngine::try_import_node_and_forward_refs_sync(
  NodeId nodeId, optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  return drive_sync(
    [&](Completion completion)
    {
      import_node_and_forward_refs_async(
        std::move(nodeId), std::move(nodePred), std::move(refPred), std::move(completion));
    });
}

void ImportEngine::import_node_and_forward_refs_sync(
  NodeId nodeId, optional<ImportNodePredicate> nodePred, optional<ImportReferencePredicate> refPred)
{
  auto result =
    try_import_node_and_forward_refs_sync(std::move(nodeId), std::move(nodePred), std::move(refPred));
  if (result.is_bad())
  {
    throw UaException(result.status_code());
  }
}

// =================================================================================================
// Sequential operation driver (import_all / import_type_definitions_only).
// =================================================================================================

// =================================================================================================
// Operations (NR-31): the Nodes an operation reaches are looked up, the missing ones created, then every
// Reference of them added, then the created Variables' Values written. Each phase is sent in chunks of the
// operation limit that bounds it, each chunk after the previous one has answered, and each answer is handled
// on a fresh stack.
// =================================================================================================

namespace
{

// A phase's chunk size: the operation limit, or no limit when it is unset or zero.
std::size_t chunk_size(const std::optional<uint32_t>& limit)
{
  return limit && *limit > 0 ? static_cast<std::size_t>(*limit) : std::numeric_limits<std::size_t>::max();
}

// The two ReferenceTypes the files' References are sent as written; every other as both halves (NR-31).
bool sent_as_written(const NodeId& referenceType)
{
  return referenceType == NodeId{ReferenceTypeId::HasTypeDefinition} ||
         referenceType == NodeId{ReferenceTypeId::HasModellingRule};
}

// One half of a Reference, as the Reference phase sends each once.
struct HalfKey
{
  NodeId source;
  NodeId referenceType;
  NodeId target;
  bool isForward{true};

  bool operator==(const HalfKey& other) const
  {
    return isForward == other.isForward && source == other.source && referenceType == other.referenceType &&
           target == other.target;
  }
};

struct HalfKeyHash
{
  std::size_t operator()(const HalfKey& key) const noexcept
  {
    // The golden-ratio constant of size_t's own width: the 64-bit literal narrows on a 32-bit target.
    constexpr std::size_t goldenRatio = sizeof(std::size_t) >= 8
                                          ? static_cast<std::size_t>(0x9e3779b97f4a7c15ULL)
                                          : static_cast<std::size_t>(0x9e3779b9U);
    std::size_t hash = std::hash<NodeId>{}(key.source);
    for (const NodeId* part : {&key.referenceType, &key.target})
    {
      hash ^= std::hash<NodeId>{}(*part) + goldenRatio + (hash << 6U) + (hash >> 2U);
    }
    return hash ^ static_cast<std::size_t>(key.isForward);
  }
};

}  // namespace

WeakAddressSpace ImportEngine::handle_of(const Operation& operation) const
{
  return operation.stagedAddressSpace ? *operation.stagedAddressSpace : mAddressSpace;
}

template<class Fn>
void ImportEngine::post_next(shared_ptr<Operation> operation, Fn&& fn)
{
  const auto& stagedAddressSpace = operation->stagedAddressSpace;
  auto addressSpace = stagedAddressSpace ? stagedAddressSpace.value().lock() : mAddressSpace.lock();
  if (!addressSpace)
  {
    finish(std::move(operation), VoidResult{::ua::detail::address_space_gone("NodesetImport")});
    return;
  }
  auto self = shared_from_this();
  auto executor = addressSpace->executor();
  ua::async::post_owning(self.get(),
    executor,
    addressSpace->logger(),
    [operation = std::move(operation), fn = std::forward<Fn>(fn)](ImportEngine& engine) mutable
    { fn(engine, std::move(operation)); })();
}

void ImportEngine::start_operation(shared_ptr<Operation> operation)
{
  // Namespace registration is part of the canonical async import flow. It may drive a live Server
  // lifecycle participant, so internal import code never reaches for the blocking wrapper.
  if (!mNamespaceMapsBuilt && !operation->namespaceMapsReady)
  {
    auto addressSpace = mAddressSpace.lock();
    if (!addressSpace)
    {
      finish(std::move(operation),
        VoidResult{Status::BadShutdown,
          ErrorDetail::build("NodesetAddressSpaceGone",
            "The address space was destroyed before namespace mapping completed",
            "NodesetImport")});
      return;
    }

    auto self = shared_from_this();
    auto executor = addressSpace->executor();
    auto nodePred = operation->nodePred;
    auto refPred = operation->refPred;
    auto continuation = ua::async::post_owning(self.get(),
      executor,
      addressSpace->logger(),
      [operation = std::move(operation)](ImportEngine& engine, VoidResult result) mutable
      {
        if (result.is_bad())
        {
          engine.finish(std::move(operation), VoidResult{result.status_code(), result.shared_detail()});
          return;
        }
        engine.start_operation(std::move(operation));
      });
    build_namespace_maps_async(std::move(nodePred), std::move(refPred), std::move(continuation));
    return;
  }

  operation->step = Operation::Step::LookingUp;
  if (const auto limits = ::ua::detail::NodeAccessorRoute::operation_limits(handle_of(*operation)))
  {
    operation->readLimit = chunk_size(limits->maxNodesPerRead);
    operation->managementLimit = chunk_size(limits->maxNodesPerNodeManagement);
    operation->writeLimit = chunk_size(limits->maxNodesPerWrite);
  }
  for (const auto& [nodeSet, xmlNode] : operation->seedNodes)
  {
    if (auto failed = add_item(*operation, nodeSet, xmlNode))
    {
      finish(std::move(operation), VoidResult{*failed});
      return;
    }
  }
  for (const auto& nodeId : operation->seedIds)
  {
    if (auto failed = add_item(*operation, nodeId))
    {
      finish(std::move(operation), VoidResult{*failed});
      return;
    }
  }
  look_up_level(std::move(operation));
}

void ImportEngine::charge_node(Operation& operation) const
{
  if (operation.followForwardReferences)
  {
    operation.budget->consume_node();
    return;
  }
  // Outside the forward walk each Node is charged to a budget of its own, as the per-node flow did.
  WorkBudget budget = mLimits.work_budget();
  budget.consume_node();
}

optional<StatusCode> ImportEngine::add_item(Operation& operation, const NodeId& fileLocalId) noexcept
{
  try
  {
    auto [nodeSet, xmlNode] = find_node_with_nodeset(fileLocalId);
    if (xmlNode && operation.visited.contains(xmlNode))
    {
      return std::nullopt;
    }
    charge_node(operation);
    if (!xmlNode)
    {
      return std::nullopt;  // a NodeId the files do not hold is skipped
    }
    return add_resolved_item(operation, nodeSet, xmlNode);
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

optional<StatusCode> ImportEngine::add_item(
  Operation& operation, const NodeSet* nodeSet, Node* xmlNode) noexcept
{
  try
  {
    if (operation.visited.contains(xmlNode))
    {
      return std::nullopt;
    }
    charge_node(operation);
    return add_resolved_item(operation, nodeSet, xmlNode);
  }
  catch (...)
  {
    return augment_with_location(ua::exception_to_status_code(std::current_exception()), xmlNode);
  }
}

optional<StatusCode> ImportEngine::add_resolved_item(
  Operation& operation, const NodeSet* nodeSet, Node* xmlNode) noexcept
{
  try
  {
    operation.visited.insert(xmlNode);
    const auto releaseStatus = xmlNode->release_status();
    if (!mIncludeNonReleased && releaseStatus.has_value() &&
        (*releaseStatus != Node::ReleaseStatus::Released))
    {
      return std::nullopt;  // Draft / Deprecated are skipped (D-Q)
    }
    Operation::Item item;
    item.nodeSet = nodeSet;
    item.xmlNode = xmlNode;
    item.translatedId = translate_node_id(*nodeSet, xmlNode->node_id());
    const auto [entry, added] = operation.itemOf.try_emplace(item.translatedId, operation.items.size());
    if (!added)
    {
      item.sameAs = entry->second;
    }
    operation.items.push_back(std::move(item));
    return std::nullopt;
  }
  catch (...)
  {
    return augment_with_location(ua::exception_to_status_code(std::current_exception()), xmlNode);
  }
}

void ImportEngine::look_up_level(shared_ptr<Operation> operation)
{
  try
  {
    operation->step = Operation::Step::LookingUp;
    operation->pending.clear();
    for (std::size_t i = operation->levelBegin; i < operation->items.size(); ++i)
    {
      if (!operation->items[i].sameAs)
      {
        operation->pending.push_back(i);
      }
    }
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  operation->cursor = 0;
  look_up_next(std::move(operation));
}

void ImportEngine::look_up_next(shared_ptr<Operation> operation)
{
  if (operation->cursor == operation->pending.size())
  {
    create_level(std::move(operation));
    return;
  }
  const std::size_t begin = operation->cursor;
  const std::size_t end = begin + std::min(operation->readLimit, operation->pending.size() - begin);
  operation->cursor = end;
  shared_ptr<std::vector<::ua::detail::LookupItem>> lookups;
  try
  {
    lookups = make_shared<std::vector<::ua::detail::LookupItem>>();
    lookups->reserve(end - begin);
    for (std::size_t k = begin; k < end; ++k)
    {
      lookups->push_back(
        ::ua::detail::LookupItem{operation->items[operation->pending[k]].translatedId, std::nullopt});
    }
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  auto self = shared_from_this();
  const auto handle = handle_of(*operation);
  ::ua::detail::NodeAccessorRoute::find_nodes(handle,
    RequestInfo{},
    *lookups,
    [self, operation, lookups, begin](BatchResult<NodeAccessorResult> found) mutable
    {
      self->post_next(std::move(operation),
        [begin, found = std::move(found)](ImportEngine& engine, shared_ptr<Operation> next) mutable
        { engine.on_looked_up(std::move(next), begin, std::move(found)); });
    });
}

void ImportEngine::on_looked_up(
  shared_ptr<Operation> operation, std::size_t begin, BatchResult<NodeAccessorResult> found)
{
  if (operation->step != Operation::Step::LookingUp)
  {
    return;
  }
  if (found.batchStatus.is_bad())
  {
    finish(std::move(operation), std::move(found.batchStatus));
    return;
  }
  try
  {
    const std::size_t count = std::min(found.items.size(), operation->cursor - begin);
    for (std::size_t k = 0; k < count; ++k)
    {
      // A Node found is not created: only its References are added. An Uncertain answer is not acted on, so
      // the import is refused; any other answer takes the create path, as the per-node flow did.
      auto& item = operation->items[operation->pending[begin + k]];
      if (found.items[k].is_uncertain())
      {
        finish(std::move(operation),
          VoidResult{augment_with_location(
            ::ua::detail::lookup_failure(item.translatedId, found.items[k].status_code(), "NodesetImport"),
            item.xmlNode)});
        return;
      }
      if (found.items[k].is_good())
      {
        item.accessor = found.items[k].value();
        mNodesInAddressSpace.insert(item.xmlNode);
      }
    }
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  look_up_next(std::move(operation));
}

void ImportEngine::create_level(shared_ptr<Operation> operation)
{
  try
  {
    operation->step = Operation::Step::Creating;
    operation->pending.clear();
    for (std::size_t i = operation->levelBegin; i < operation->items.size(); ++i)
    {
      const auto& item = operation->items[i];
      if (!item.sameAs && !item.accessor)
      {
        operation->pending.push_back(i);
      }
    }
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  operation->cursor = 0;
  create_next(std::move(operation));
}

void ImportEngine::create_next(shared_ptr<Operation> operation)
{
  if (operation->cursor == operation->pending.size())
  {
    next_level(std::move(operation));
    return;
  }
  const std::size_t begin = operation->cursor;
  const std::size_t end = begin + std::min(operation->managementLimit, operation->pending.size() - begin);
  operation->cursor = end;
  shared_ptr<std::vector<NodeCreation>> creations;
  const Node* located = nullptr;
  try
  {
    creations = make_shared<std::vector<NodeCreation>>();
    creations->reserve(end - begin);
    for (std::size_t k = begin; k < end; ++k)
    {
      const auto& item = operation->items[operation->pending[k]];
      located = item.xmlNode;
      // build_initial_attributes may throw (an unresolved structure, or a bad DataType parent).
      creations->push_back(NodeCreation{item.translatedId,
        item.xmlNode->node_class(),
        build_initial_attributes(*item.xmlNode, *item.nodeSet)});
    }
  }
  catch (...)
  {
    finish(std::move(operation),
      VoidResult{augment_with_location(ua::exception_to_status_code(std::current_exception()), located)});
    return;
  }
  auto self = shared_from_this();
  const auto handle = handle_of(*operation);
  ::ua::detail::NodeAccessorRoute::create_nodes(handle,
    RequestInfo{},
    std::move(creations),
    [self, operation, begin, end](std::vector<NodeAccessorResult> created) mutable
    {
      self->post_next(std::move(operation),
        [begin, end, created = std::move(created)](ImportEngine& engine, shared_ptr<Operation> next) mutable
        { engine.on_created(std::move(next), begin, end, std::move(created)); });
    });
}

void ImportEngine::on_created(shared_ptr<Operation> operation, std::size_t begin, std::size_t end,
  std::vector<NodeAccessorResult> created)
{
  if (operation->step != Operation::Step::Creating)
  {
    return;
  }
  optional<StatusCode> failure;
  // The Nodes the namespace holds from a create the import refused.
  std::vector<NodeId> refusedHeld;
  try
  {
    for (std::size_t k = begin; k < end; ++k)
    {
      auto& item = operation->items[operation->pending[k]];
      const std::size_t answer = k - begin;
      NodeAccessorResult result = answer < created.size()
                                    ? std::move(created[answer])
                                    : NodeAccessorResult{StatusCode{Status::BadInternalError}};
      if (!result.is_good())
      {
        // A create answered Uncertain may hold the Node it made. The import does not act on that Node, and
        // does not leave it behind either: a staged import's rollback deletes it with the Nodes the staging
        // created, and any other import deletes it before it answers.
        if (result.has_value())
        {
          if (operation->stagedCreatedNodes)
          {
            operation->stagedCreatedNodes->push_back(item.translatedId);
          }
          else
          {
            refusedHeld.push_back(item.translatedId);
          }
        }
        if (!failure)
        {
          // The import acts on the Node it creates, so an Uncertain answer is refused as a lookup's is.
          const StatusCode refused =
            ::ua::detail::lookup_failure(item.translatedId, result.status_code(), "NodesetImport");
          failure = augment_with_location(
            StatusCode{refused.as_status(),
              ErrorDetail::build(
                "NodesetImportFailed", "Failed to create node in the address space", "NodesetImport")
                .context(ua::ContextKeys::nodeId, to_string(item.translatedId))
                .cause(refused)},
            item.xmlNode);
        }
        continue;
      }
      item.accessor = result.value();
      item.created = true;
      mNodesInAddressSpace.insert(item.xmlNode);
      if (operation->stagedCreatedNodes)
      {
        operation->stagedCreatedNodes->push_back(item.translatedId);
      }
      ++mNodesImported;
    }
  }
  catch (...)
  {
    failure = ua::exception_to_status_code(std::current_exception());
  }
  if (failure)
  {
    if (!refusedHeld.empty())
    {
      remove_refused_then_finish(std::move(operation), std::move(refusedHeld), *failure);
      return;
    }
    finish(std::move(operation), VoidResult{*failure});
    return;
  }
  create_next(std::move(operation));
}

void ImportEngine::remove_refused_then_finish(
  shared_ptr<Operation> operation, std::vector<NodeId> refusedHeld, StatusCode failure)
{
  try
  {
    auto owner = handle_of(*operation).lock();
    if (!owner)
    {
      // The Nodes went with their address space.
      finish(std::move(operation), VoidResult{failure});
      return;
    }
    auto logger = owner->logger();
    // The deletion answers on an executor thread; finish touches only the operation, which nothing else
    // advances while the deletion runs, so it is answered there.
    ImportedMetadataRollbackOperation::start(*owner,
      std::move(refusedHeld),
      [self = shared_from_this(), operation, failure, logger](VoidResult removed) mutable
      {
        if (removed.is_bad())
        {
          logger.warning({{"status", to_string(removed.status_code())}},
            "A Node the NodeSet import refused could not be removed");
        }
        self->finish(std::move(operation), VoidResult{failure});
      });
  }
  catch (...)
  {
    // The Nodes could not be removed: the import still answers its failure.
    finish(std::move(operation), VoidResult{failure});
  }
}

void ImportEngine::next_level(shared_ptr<Operation> operation)
{
  if (!operation->followForwardReferences)
  {
    add_references(std::move(operation));
    return;
  }
  // The forward References of each Node this level created reach the next level; a Node found is not
  // followed, as the per-node flow did.
  const std::size_t levelEnd = operation->items.size();
  for (std::size_t i = operation->levelBegin; i < levelEnd; ++i)
  {
    if (!operation->items[i].created)
    {
      continue;
    }
    Node* xmlNode = operation->items[i].xmlNode;
    for (const auto& reference : xmlNode->references())
    {
      if (!reference.isForward)
      {
        continue;
      }
      try
      {
        operation->budget->consume_edge();
      }
      catch (...)
      {
        finish(std::move(operation),
          VoidResult{augment_with_location(ua::exception_to_status_code(std::current_exception()), xmlNode)});
        return;
      }
      if (auto failed = add_item(*operation, reference.targetId))
      {
        finish(std::move(operation), VoidResult{*failed});
        return;
      }
    }
  }
  operation->levelBegin = levelEnd;
  if (levelEnd == operation->items.size())
  {
    add_references(std::move(operation));
    return;
  }
  look_up_level(std::move(operation));
}

void ImportEngine::add_references(shared_ptr<Operation> operation)
{
  operation->step = Operation::Step::AddingReferences;
  const Node* located = nullptr;
  try
  {
    std::unordered_map<HalfKey, std::size_t, HalfKeyHash> sent;
    // Each half once. The half an item holds stays its own when another item's Reference also gives it.
    auto addHalf = [&operation, &sent](std::size_t item, bool own, ReferenceChange change)
    {
      HalfKey key{change.source, change.referenceType, change.target.node_id(), change.isForward};
      const auto [entry, added] = sent.try_emplace(std::move(key), operation->changes.size());
      if (!added)
      {
        if (own && !operation->origins[entry->second].own)
        {
          operation->origins[entry->second] = Operation::HalfOrigin{item, true};
        }
        return;
      }
      operation->changes.push_back(std::move(change));
      operation->origins.push_back(Operation::HalfOrigin{item, own});
    };
    auto created = [&operation](std::size_t index)
    {
      const auto& item = operation->items[index];
      return item.sameAs ? operation->items[*item.sameAs].created : item.created;
    };
    // The other half is added only when the caller's filter keeps the Reference as the target holds it, as it
    // decided each Node's own References in the per-node flow: the server's NS0 import drops the Server's
    // HasComponent to the PubSub model's PublishSubscribe, so PublishSubscribe's inverse half does not put it
    // back. A target outside the files has no References to ask about, and gets its half.
    auto targetKeeps = [this, &operation](const Operation::Item& item,
                         const Node::Reference& reference,
                         const NodeSet& targetNodeSet,
                         const NodeId& type,
                         const NodeId& target)
    {
      if (!operation->refPred)
      {
        return true;
      }
      const NodeSet* holderNodeSet = &targetNodeSet;
      const Node* holder = nullptr;
      if (const auto targetItem = operation->itemOf.find(target); targetItem != operation->itemOf.end())
      {
        holderNodeSet = operation->items[targetItem->second].nodeSet;
        holder = operation->items[targetItem->second].xmlNode;
      }
      else
      {
        for (const auto& nodeSet : mNodeSets)
        {
          if (nodeSet.get() == &targetNodeSet)
          {
            holder = nodeSet->find_node(reference.targetId);
            break;
          }
        }
        if (!holder && reference.targetId.namespace_index() == 0)
        {
          std::tie(holderNodeSet, holder) = find_node_with_nodeset(reference.targetId);
        }
      }
      const bool sameFrame = holderNodeSet == item.nodeSet;
      // A NodeSet the import built no namespace map for cannot be compared in the address space's frame.
      if (!holder || !holderNodeSet || (!sameFrame && !mNodeSetNsIndexMaps.contains(holderNodeSet)))
      {
        return true;
      }
      for (const auto& held : holder->references())
      {
        if (held.isForward == reference.isForward)
        {
          continue;
        }
        const bool mirrors = sameFrame
                               ? held.typeId == reference.typeId && held.targetId == item.xmlNode->node_id()
                               : translate_node_id(*holderNodeSet, held.typeId) == type &&
                                   translate_node_id(*holderNodeSet, held.targetId) == item.translatedId;
        if (mirrors)
        {
          return (*operation->refPred)(*holder, held);
        }
      }
      return true;
    };

    std::vector<Node::Reference> references;
    for (std::size_t i = 0; i < operation->items.size(); ++i)
    {
      const auto& item = operation->items[i];
      located = item.xmlNode;
      references.clear();
      for (const auto& reference : item.xmlNode->references())
      {
        const auto& referencePredicate = operation->refPred;
        if (!referencePredicate || (referencePredicate.value())(*item.xmlNode, reference))
        {
          references.push_back(reference);
        }
      }
      if (const auto derived = mDerivedReferences.find(item.xmlNode); derived != mDerivedReferences.end())
      {
        for (const auto& reference : derived->second)
        {
          const auto& referencePredicate = operation->refPred;
          if (!referencePredicate || (referencePredicate.value())(*item.xmlNode, reference))
          {
            references.push_back(reference);
          }
        }
      }
      if (operation->countReferences)
      {
        mReferencesImported += references.size();
      }
      for (const auto& reference : references)
      {
        NodeId type = translate_node_id(*item.nodeSet, reference.typeId);
        // The target may live in a different NodeSet: translated against its own.
        const NodeSet* targetNodeSet = item.nodeSet;
        if (!operation->translateReferencesInSourceFrame && reference.targetId.namespace_index() != 0)
        {
          auto [foundNodeSet, foundNode] = find_node_with_nodeset(reference.targetId);
          if (foundNodeSet)
          {
            targetNodeSet = foundNodeSet;
          }
        }
        NodeId target = translate_node_id(*targetNodeSet, reference.targetId);
        const bool bothHalves =
          !sent_as_written(type) && targetKeeps(item, reference, *targetNodeSet, type, target);
        if (bothHalves)
        {
          const auto targetItem = operation->itemOf.find(target);
          const bool targetCreated = targetItem != operation->itemOf.end() && created(targetItem->second);
          addHalf(i,
            false,
            ReferenceChange{
              target, type, ExpandedNodeId{item.translatedId}, !reference.isForward, targetCreated});
        }
        addHalf(i,
          true,
          ReferenceChange{item.translatedId,
            std::move(type),
            ExpandedNodeId{std::move(target)},
            reference.isForward,
            created(i)});
      }
    }

    located = nullptr;
    if (auto refused = keep_one_half_per_reference(*operation))
    {
      finish(std::move(operation), VoidResult{*refused});
      return;
    }

    // The HasSubtype References of VariableTypes go last, in file order: the address space checks them
    // against Part 3 6.2.7 (NR-52), which walks their DataTypes' supertypes, and those DataTypes' own
    // HasSubtype References may come from the same files.
    std::vector<ReferenceChange> laterChanges;
    std::vector<Operation::HalfOrigin> laterOrigins;
    std::size_t kept = 0;
    for (std::size_t c = 0; c < operation->changes.size(); ++c)
    {
      const Node* holder = operation->items[operation->origins[c].item].xmlNode;
      if (operation->changes[c].referenceType == NodeId{ReferenceTypeId::HasSubtype} && holder != nullptr &&
          holder->node_class() == NodeClass::VariableType)
      {
        laterChanges.push_back(std::move(operation->changes[c]));
        laterOrigins.push_back(operation->origins[c]);
        continue;
      }
      if (kept != c)
      {
        operation->changes[kept] = std::move(operation->changes[c]);
        operation->origins[kept] = operation->origins[c];
      }
      ++kept;
    }
    operation->changes.resize(kept);
    operation->origins.resize(kept);
    std::ranges::move(laterChanges, std::back_inserter(operation->changes));
    operation->origins.insert(operation->origins.end(), laterOrigins.begin(), laterOrigins.end());
  }
  catch (...)
  {
    finish(std::move(operation),
      VoidResult{augment_with_location(ua::exception_to_status_code(std::current_exception()), located)});
    return;
  }
  operation->cursor = 0;
  add_next_references(std::move(operation));
}

optional<StatusCode> ImportEngine::keep_one_half_per_reference(Operation& operation) const
{
  // DL-11: the halves one source is sent that OPC 10000-3 section 4.3.4 identifies as one Reference, a type
  // and its subtype, are decided together, so the result does not depend on the order the files are read in:
  // the half whose type is each other's type or a subtype of it is sent, and the others are not. Halves whose
  // types are not one line of subtypes fail the import.
  std::unordered_map<NodeId, std::vector<std::size_t>> bySource;
  for (std::size_t c = 0; c < operation.changes.size(); ++c)
  {
    bySource[operation.changes[c].source].push_back(c);
  }
  std::vector<bool> keep(operation.changes.size(), true);
  std::vector<Reference> asked;
  for (const auto& [source, members] : bySource)
  {
    if (members.size() < 2)
    {
      continue;
    }
    asked.clear();
    for (const std::size_t c : members)
    {
      const auto& change = operation.changes[c];
      asked.emplace_back(change.referenceType, change.target, change.isForward);
    }
    auto decided = ::ua::reference_identity::references_to_add(std::span<const Reference>{}, asked);
    if (!decided.is_good())
    {
      return augment_with_location(
        decided.status_code(), operation.items[operation.origins[members.front()].item].xmlNode);
    }
    if (decided.value().size() == members.size())
    {
      continue;
    }
    std::unordered_set<HalfKey, HalfKeyHash> chosen;
    for (const auto& reference : decided.value())
    {
      chosen.insert(
        HalfKey{source, reference.type_id(), reference.target_id().node_id(), reference.is_forward()});
    }
    for (std::size_t m = 0; m < members.size(); ++m)
    {
      const auto& change = operation.changes[members[m]];
      if (chosen.contains(HalfKey{source, change.referenceType, change.target.node_id(), change.isForward}))
      {
        continue;
      }
      keep[members[m]] = false;
      // The half sent in its place is the same Reference: it is the Node's own when this one was.
      if (!operation.origins[members[m]].own)
      {
        continue;
      }
      for (std::size_t k = 0; k < members.size(); ++k)
      {
        const auto& kept = operation.changes[members[k]];
        if (chosen.contains(HalfKey{source, kept.referenceType, kept.target.node_id(), kept.isForward}) &&
            asked[k].identifies_same_reference_as(asked[m]))
        {
          operation.origins[members[k]] = operation.origins[members[m]];
        }
      }
    }
  }
  std::size_t next = 0;
  for (std::size_t c = 0; c < operation.changes.size(); ++c)
  {
    if (!keep[c])
    {
      continue;
    }
    if (next != c)
    {
      operation.changes[next] = std::move(operation.changes[c]);
      operation.origins[next] = operation.origins[c];
    }
    ++next;
  }
  operation.changes.resize(next);
  operation.origins.resize(next);
  return std::nullopt;
}

void ImportEngine::add_next_references(shared_ptr<Operation> operation)
{
  if (operation->cursor == operation->changes.size())
  {
    operation->step = Operation::Step::WritingValues;
    operation->cursor = 0;
    write_next_values(std::move(operation));
    return;
  }
  const std::size_t begin = operation->cursor;
  const std::size_t end = begin + std::min(operation->managementLimit, operation->changes.size() - begin);
  operation->cursor = end;
  shared_ptr<const std::vector<ReferenceChange>> chunk;
  try
  {
    const auto first = operation->changes.begin() + static_cast<std::ptrdiff_t>(begin);
    chunk = make_shared<const std::vector<ReferenceChange>>(
      first, first + static_cast<std::ptrdiff_t>(end - begin));
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  auto self = shared_from_this();
  const auto handle = handle_of(*operation);
  try
  {
    if (!operation->modelStep)
    {
      operation->modelStep = ::ua::detail::NodeAccessorRoute::model_change_step(handle);
    }
  }
  catch (...)
  {
    finish(std::move(operation), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  auto step = operation->modelStep;
  // The import sends both halves of each Reference itself, as the caller's filter keeps them on each side:
  // the route does not add a half the filter dropped.
  ::ua::detail::NodeAccessorRoute::add_references(
    handle,
    RequestInfo{},
    std::move(chunk),
    [self, operation, begin](std::vector<VoidResult> added) mutable
    {
      self->post_next(std::move(operation),
        [begin, added = std::move(added)](ImportEngine& engine, shared_ptr<Operation> next) mutable
        { engine.on_references_added(std::move(next), begin, std::move(added)); });
    },
    /*addRequiredPairs=*/false,
    std::move(step));
}

void ImportEngine::on_references_added(
  shared_ptr<Operation> operation, std::size_t begin, std::vector<VoidResult> added)
{
  if (operation->step != Operation::Step::AddingReferences)
  {
    return;
  }
  optional<StatusCode> failure;
  try
  {
    const std::size_t count = std::min(added.size(), operation->cursor - begin);
    if (count < operation->cursor - begin)
    {
      failure = StatusCode{Status::BadInternalError};
    }
    for (std::size_t k = 0; k < count; ++k)
    {
      const StatusCode& status = added[k].status_code();
      // A half the address space already holds is not added again (NR-30 rule 4; NR-68 item 8).
      if (added[k].is_good() || status.as_status() == Status::BadDuplicateReferenceNotAllowed)
      {
        continue;
      }
      const auto& origin = operation->origins[begin + k];
      if (origin.own)
      {
        if (!failure)
        {
          failure = augment_with_location(status, operation->items[origin.item].xmlNode);
        }
        continue;
      }
      // The other half's target is neither among the Nodes imported nor in the address space.
      if (status.as_status() == Status::BadNodeIdUnknown)
      {
        continue;
      }
      // NR-31 rule 2: a refused other half is logged and the import continues.
      const auto& change = operation->changes[begin + k];
      const auto& stagedAddressSpace = operation->stagedAddressSpace;
      if (auto addressSpace = stagedAddressSpace ? stagedAddressSpace.value().lock() : mAddressSpace.lock())
      {
        addressSpace->logger().warning({{"nodeId", to_string(change.source)},
                                         {"referenceType", to_string(change.referenceType)},
                                         {"target", to_string(change.target)},
                                         {"status", to_string(status)}},
          "NodeSet import could not add the other half of a Reference; the import continues");
      }
    }
  }
  catch (...)
  {
    failure = ua::exception_to_status_code(std::current_exception());
  }
  if (failure)
  {
    finish(std::move(operation), VoidResult{*failure});
    return;
  }
  add_next_references(std::move(operation));
}

void ImportEngine::write_next_values(shared_ptr<Operation> operation)
{
  // A created Variable's Value is not a creation attribute: it is written once every Reference is added.
  std::vector<::ua::detail::ValueWrite> writes;
  std::vector<std::size_t> written;
  const Node* located = nullptr;
  try
  {
    while (operation->cursor < operation->items.size() && writes.size() < operation->writeLimit)
    {
      const std::size_t i = operation->cursor++;
      const auto& item = operation->items[i];
      if (!item.created || !item.accessor || item.xmlNode->node_class() != NodeClass::Variable)
      {
        continue;
      }
      located = item.xmlNode;
      auto variable = item.accessor->as<VariableAccessor>();
      if (!variable)
      {
        continue;
      }
      const auto& variableSource = dynamic_cast<const Variable&>(*item.xmlNode);
      auto value = variableSource.value(resolver_for(*item.nodeSet), make_translation_config(*item.nodeSet));
      if (value.empty())
      {
        continue;
      }
      if (mFailOnUnknownStructure && variant_contains_unknown_structure(value))
      {
        throw UaException(Status::BadNotSupported,
          ErrorDetail::build("UnresolvedStructureValue",
            "NodeSet value contains an ExtensionObject of an unresolved type; supply a "
            "structure_resolver or set on_unknown_structure = ImportOpaque",
            "NodesetImport")
            .context(ua::ContextKeys::nodeId, to_string(variableSource.node_id())));
      }
      WriteValue writeValue;
      writeValue.node_id() = variable->get_node_id();
      writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
      writeValue.value().value() = std::move(value);
      writeValue.value().server_timestamp() = DateTime::now();
      writes.push_back(::ua::detail::ValueWrite{*item.accessor, std::move(writeValue)});
      written.push_back(i);
    }
  }
  catch (...)
  {
    finish(std::move(operation),
      VoidResult{augment_with_location(ua::exception_to_status_code(std::current_exception()), located)});
    return;
  }
  if (writes.empty())
  {
    finish(std::move(operation), VoidResult{});
    return;
  }
  auto self = shared_from_this();
  auto step = operation->modelStep;
  ::ua::detail::NodeAccessorRoute::write_values(
    RequestInfo{},
    nullptr,
    std::move(writes),
    [self, operation, written = std::move(written)](std::vector<VoidResult> results) mutable
    {
      self->post_next(std::move(operation),
        [written = std::move(written), results = std::move(results)](
          ImportEngine& engine, shared_ptr<Operation> next) mutable
        { engine.on_values_written(std::move(next), std::move(written), std::move(results)); });
    },
    std::move(step));
}

void ImportEngine::on_values_written(
  shared_ptr<Operation> operation, std::vector<std::size_t> written, std::vector<VoidResult> results)
{
  if (operation->step != Operation::Step::WritingValues)
  {
    return;
  }
  for (std::size_t k = 0; k < written.size(); ++k)
  {
    if (k >= results.size())
    {
      finish(std::move(operation), VoidResult{StatusCode{Status::BadInternalError}});
      return;
    }
    if (results[k].is_bad())
    {
      // Built before the call: an argument that reads operation is unsequenced with the one that moves it.
      VoidResult failure{
        augment_with_location(results[k].status_code(), operation->items[written[k]].xmlNode)};
      finish(std::move(operation), std::move(failure));
      return;
    }
  }
  write_next_values(std::move(operation));
}

void ImportEngine::finish(shared_ptr<Operation> operation, VoidResult result)
{
  if (operation->step == Operation::Step::Done)
  {
    return;  // completion already called
  }
  operation->step = Operation::Step::Done;

  Completion completion = std::move(operation->completion);
  operation->completion = {};
  // The operation's event is raised before its caller is answered (NR-46); a failed import's rollback, which
  // its caller makes, raises its own.
  if (auto step = std::move(operation->modelStep))
  {
    step->close(
      [completion = std::move(completion), result = std::move(result)]() mutable
      {
        if (completion)
        {
          completion(std::move(result));
        }
      });
    return;
  }
  if (completion)
  {
    completion(std::move(result));
  }
}

}  // namespace ua::xml::nodeset
