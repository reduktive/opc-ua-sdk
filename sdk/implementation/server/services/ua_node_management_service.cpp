// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_management_service.h"
#include "ua_reference_type_model.h"
#include "ua_verdict_rules.h"
#include "ua_on_strand.h"

#include "security/ua_access_control.h"
#include "ua_address_space.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_audit_add_nodes_event_payload.h"
#include "ua_audit_add_references_event_payload.h"
#include "ua_audit_delete_nodes_event_payload.h"
#include "ua_audit_delete_references_event_payload.h"
#include "ua_diagnostic_collector.h"
#include "ua_data_type_attributes.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_log_exception.h"
#include "ua_method_attributes.h"
#include "ua_namespace_delegates.h"
#include "ua_namespace_array.h"
#include "ua_object_id.h"
#include "ua_object_attributes.h"
#include "ua_object_type_attributes.h"
#include "ua_objecttype_id.h"
#include "ua_reference_type_attributes.h"
#include "ua_server_session_info.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variable_attributes.h"
#include "ua_variable_type_attributes.h"
#include "ua_view_attributes.h"

#include "ua_session_security.h"

#include "fmt/format.h"

#include <algorithm>
#include <array>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::server
{

// =============================================================================================
// Per-flow state - single-instance per service per kind. Each flow's unique_ptr lives on the
// service and is reset() at completion / cancel / timeout.
// =============================================================================================

struct AddNodesState
{
  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<AddNodesResponse> response;
  DiagnosticCollector collector;
  std::vector<bool> eligible;
  std::vector<bool> authorized;  // per-item flag
  std::vector<std::optional<NodeManagementDelegate::AddNodeDestination>> destinations;
  std::vector<size_t> preparationIndices;
  /// The items behind @ref preparationIndices, handed to the delegate to choose destinations for.
  std::vector<AddNodesItem> preparationItems;
  std::vector<std::optional<NodeAccessor>> resolvedParents;
  std::vector<size_t> authorizedIndices;  // built after Authorizing completes
  std::vector<NodeManagementDelegate::AuthorizedAddNode> authorizedItems;  // populated for handler call
  std::shared_ptr<NodeManagementDelegate::Context> handlerContext;

  AddNodesState(AddressSpace initialAddressSpace, shared_ptr<AddNodesResponse> initialResponse,
    DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      collector(std::move(initialCollector))
  {}
};

struct AddReferencesState
{
  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<AddReferencesResponse> response;
  DiagnosticCollector collector;
  std::vector<bool> authorized;
  std::vector<std::optional<NodeAccessor>> resolvedSources;

  // Per-item verdict on the declared `targetNodeClass` against the NodeClass the resolved target
  // actually has (OPC 10000-4 5.7.3.2). Held rather than applied on the spot so it lands *after* the
  // data-model checks a ReferenceType carries: a Method offered as the HasProperty of a
  // ReferenceType is refused for being a Method, which is what Part 3 5.3 is about, and reporting
  // Bad_NodeClassInvalid there would answer the smaller of the two things wrong with it.
  std::vector<StatusCode> declaredClassVerdict;

  /// The items that survived the item-alone screen, and so became units.
  std::vector<size_t> toResolve;

  std::vector<size_t> authorizedIndices;
  std::vector<AddReferencesItem> authorizedItems;
  std::shared_ptr<NodeManagementDelegate::Context> handlerContext;

  AddReferencesState(AddressSpace initialAddressSpace, shared_ptr<AddReferencesResponse> initialResponse,
    DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      collector(std::move(initialCollector))
  {}
};

struct DeleteNodesState
{
  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<DeleteNodesResponse> response;
  DiagnosticCollector collector;
  std::vector<bool> authorized;
  std::vector<size_t> authorizedIndices;
  std::vector<DeleteNodesItem> authorizedItems;
  std::shared_ptr<NodeManagementDelegate::Context> handlerContext;

  DeleteNodesState(AddressSpace initialAddressSpace, shared_ptr<DeleteNodesResponse> initialResponse,
    DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      collector(std::move(initialCollector))
  {}
};

struct DeleteReferencesState
{
  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<DeleteReferencesResponse> response;
  DiagnosticCollector collector;
  std::vector<bool> authorized;
  std::vector<size_t> authorizedIndices;
  std::vector<DeleteReferencesItem> authorizedItems;
  std::shared_ptr<NodeManagementDelegate::Context> handlerContext;

  DeleteReferencesState(AddressSpace initialAddressSpace,
    shared_ptr<DeleteReferencesResponse> initialResponse, DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      collector(std::move(initialCollector))
  {}
};

namespace
{

bool node_attributes_match_class(const AddNodesItem& item)
{
  const Structure* attributes = item.node_attributes().get();
  if (!attributes)
    return true;

  switch (item.node_class())
  {
  case NodeClass::Object:
    return dynamic_cast<const ObjectAttributes*>(attributes) != nullptr;
  case NodeClass::Variable:
    return dynamic_cast<const VariableAttributes*>(attributes) != nullptr;
  case NodeClass::Method:
    return dynamic_cast<const MethodAttributes*>(attributes) != nullptr;
  case NodeClass::ObjectType:
    return dynamic_cast<const ObjectTypeAttributes*>(attributes) != nullptr;
  case NodeClass::VariableType:
    return dynamic_cast<const VariableTypeAttributes*>(attributes) != nullptr;
  case NodeClass::ReferenceType:
    return dynamic_cast<const ReferenceTypeAttributes*>(attributes) != nullptr;
  case NodeClass::DataType:
    return dynamic_cast<const DataTypeAttributes*>(attributes) != nullptr;
  case NodeClass::View:
    return dynamic_cast<const ViewAttributes*>(attributes) != nullptr;
  case NodeClass::Unspecified:
    return false;
  }
  return false;
}

bool is_type_node_class(NodeClass nodeClass)
{
  return nodeClass == NodeClass::ObjectType || nodeClass == NodeClass::VariableType ||
         nodeClass == NodeClass::ReferenceType || nodeClass == NodeClass::DataType;
}

const NodeId serverObjectNodeId{ObjectId::Server};

void fill_node_mgmt_audit_base(AuditEventPayload& event, const SessionInfo& sessionInfo,
  const std::string& sourceName, bool success, const std::string& auditEntryId = {})
{
  event.sourceNode = serverObjectNodeId;
  event.sourceName = sourceName;
  event.actionTimeStamp = Variant{DateTime::now()};
  event.status = success;
  event.serverId = sessionInfo.configuration().application_description_part().applicationUri;
  event.message = LocalizedText{"", sourceName};
  event.severity = 1;
  event.clientAuditEntryId = auditEntryId;

  if (auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto user = sec->user_identity())
      event.clientUserId = user->userId;
  }
}

template<typename EventT>
void emit_node_mgmt_audit(const shared_ptr<ua::server::SessionInfo>& sessionInfo, EventT& event)
{
  if (!sessionInfo->server_configuration().auditingEnabled)
    return;

  const auto sink = sessionInfo->event_sink();
  if (!sink || !static_cast<EventBus*>(sink.get())->has_event_interest())
    return;

  sink->emit(event);
}

}  // namespace

// --- Constructors -----------------------------------------------------------

NodeManagementService::NodeManagementService(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddNodesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mRequestId(requestId), mHandler(std::move(handler)), mAddNodesRequest(std::move(request)),
    mServiceCallCompleteCallback(std::move(callback)), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

NodeManagementService::NodeManagementService(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddReferencesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mRequestId(requestId), mHandler(std::move(handler)), mAddReferencesRequest(std::move(request)),
    mServiceCallCompleteCallback(std::move(callback)), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

NodeManagementService::NodeManagementService(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteNodesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mRequestId(requestId), mHandler(std::move(handler)), mDeleteNodesRequest(std::move(request)),
    mServiceCallCompleteCallback(std::move(callback)), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

NodeManagementService::NodeManagementService(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteReferencesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mRequestId(requestId), mHandler(std::move(handler)), mDeleteReferencesRequest(std::move(request)),
    mServiceCallCompleteCallback(std::move(callback)), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

NodeManagementService::~NodeManagementService() = default;

// --- Factory methods --------------------------------------------------------

shared_ptr<NodeManagementService> NodeManagementService::create(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddNodesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public NodeManagementService
  {
    Wrapper(weak_ptr<SessionInfo> si, std::shared_ptr<NodeManagementDelegate> h, uint32_t rid,
      AddNodesRequest&& req, boost::asio::any_io_executor ex, ServiceCallComplete cb)
      : NodeManagementService(std::move(si), std::move(h), rid, std::move(req), std::move(ex), std::move(cb))
    {}
  };

  auto service = std::make_shared<Wrapper>(std::move(sessionInfo),
    std::move(handler),
    requestId,
    std::move(request),
    std::move(executor),
    std::move(callback));
  service->start();
  return service;
}

shared_ptr<NodeManagementService> NodeManagementService::create(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddReferencesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public NodeManagementService
  {
    Wrapper(weak_ptr<SessionInfo> si, std::shared_ptr<NodeManagementDelegate> h, uint32_t rid,
      AddReferencesRequest&& req, boost::asio::any_io_executor ex, ServiceCallComplete cb)
      : NodeManagementService(std::move(si), std::move(h), rid, std::move(req), std::move(ex), std::move(cb))
    {}
  };

  auto service = std::make_shared<Wrapper>(std::move(sessionInfo),
    std::move(handler),
    requestId,
    std::move(request),
    std::move(executor),
    std::move(callback));
  service->start();
  return service;
}

shared_ptr<NodeManagementService> NodeManagementService::create(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteNodesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public NodeManagementService
  {
    Wrapper(weak_ptr<SessionInfo> si, std::shared_ptr<NodeManagementDelegate> h, uint32_t rid,
      DeleteNodesRequest&& req, boost::asio::any_io_executor ex, ServiceCallComplete cb)
      : NodeManagementService(std::move(si), std::move(h), rid, std::move(req), std::move(ex), std::move(cb))
    {}
  };

  auto service = std::make_shared<Wrapper>(std::move(sessionInfo),
    std::move(handler),
    requestId,
    std::move(request),
    std::move(executor),
    std::move(callback));
  service->start();
  return service;
}

shared_ptr<NodeManagementService> NodeManagementService::create(weak_ptr<SessionInfo> sessionInfo,
  std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteReferencesRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public NodeManagementService
  {
    Wrapper(weak_ptr<SessionInfo> si, std::shared_ptr<NodeManagementDelegate> h, uint32_t rid,
      DeleteReferencesRequest&& req, boost::asio::any_io_executor ex, ServiceCallComplete cb)
      : NodeManagementService(std::move(si), std::move(h), rid, std::move(req), std::move(ex), std::move(cb))
    {}
  };

  auto service = std::make_shared<Wrapper>(std::move(sessionInfo),
    std::move(handler),
    requestId,
    std::move(request),
    std::move(executor),
    std::move(callback));
  service->start();
  return service;
}

// --- Process dispatch -------------------------------------------------------
void NodeManagementService::begin_processing()
{
  if (mAddNodesRequest)
    start_add_nodes();
  else if (mAddReferencesRequest)
    start_add_references();
  else if (mDeleteNodesRequest)
    start_delete_nodes();
  else if (mDeleteReferencesRequest)
    start_delete_references();
}

// =============================================================================================
// Helper: build an AuthzRequest snapshot per-item
// =============================================================================================

namespace
{

// The composition ReferenceTypes. OPC 10000-3 4.5.2: "A TypeDefinitionNode and its
// InstanceDeclarations shall always reside in the same Server", and the same clause is explicit that
// a *HasTypeDefinition* Reference may cross Servers - so it is what a type is built out of that is
// local, not what a type is. A cross-Server Reference of one of these is the case Part 4's
// Bad_ReferenceLocalOnly reports.
bool is_composition_reference_type(const NodeId& referenceTypeId)
{
  return referenceTypeId == NodeId{ReferenceTypeId::HasComponent} ||
         referenceTypeId == NodeId{ReferenceTypeId::HasProperty} ||
         referenceTypeId == NodeId{ReferenceTypeId::HasOrderedComponent} ||
         referenceTypeId == NodeId{ReferenceTypeId::HasSubtype};
}

/// The Part 4 5.7.3.4 checks that need nothing but the item itself.
///
/// Returns Good when the item is worth resolving. Each refusal is a code the Server could not
/// otherwise reach: a `targetServerUri` naming a Server this one cannot resolve leaves a Reference
/// whose ExpandedNodeId no Client can follow, a structurally unusable `targetNodeId` names nothing
/// whatever the address space holds, and a composition Reference to another Server asserts a
/// composition the model forbids.
///
/// A well-formed id that merely names an absent Node is deliberately NOT refused: OPC 10000-3 4.3.4
/// says "OPC UA does not require that the TargetNode exists, thus References may point to a Node that
/// does not exist", so a dangling Reference is a state the model sanctions and only an unusable id is
/// invalid.
StatusCode screen_add_references_item(const AddReferencesItem& item, const String& ownApplicationUri)
{
  const auto& serverUri = item.target_server_uri();
  if (!serverUri.empty() && serverUri != ownApplicationUri)
  {
    // This Server hosts no remote address spaces and keeps no registry of peers it could resolve a
    // URI against, so the only URI it can honour is its own - which names a local Reference spelled
    // the long way round. Anything else is a target no Client could follow.
    return StatusCode{Status::BadServerUriInvalid};
  }
  if (item.target_node_id().node_id().is_null())
  {
    return StatusCode{Status::BadTargetNodeIdInvalid};
  }
  if (item.target_node_id().server_index() != 0 && is_composition_reference_type(item.reference_type_id()))
  {
    return StatusCode{Status::BadReferenceLocalOnly};
  }
  if (item.target_node_class() == NodeClass::Unspecified)
  {
    // OPC 10000-4 section 5.7.3.2: "the Client shall specify the targetNodeClass since the TargetNode might
    // not be accessible directly by the Server." The parameter is required rather than advisory for
    // exactly the case the Server cannot check it in -- a target on another Server -- so inferring it
    // locally and ignoring it remotely would accept a Reference the Server cannot describe.
    return StatusCode{Status::BadNodeClassInvalid};
  }
  return StatusCode{Status::Good};
}

/// Looks @p nodeId up in the address space @p addressSpace names, or answers @p complete with
/// `AddressSpaceGone` when it is gone. The walks below hold the address space weakly: the completion each
/// gives a namespace owns the walk, so a strong handle would let a namespace that keeps it keep the address
/// space (CALLS-21 rules 1 and 2).
void find_node_weakly(const WeakAddressSpace& addressSpace, const NodeId& nodeId,
  std::function<void(NodeAccessorResult)> complete)
{
  if (auto owner = addressSpace.lock())
  {
    owner->find_node_async(nodeId, std::move(complete));
    return;
  }
  complete(NodeAccessorResult{ua::detail::address_space_gone("NodeManagementService")});
}

/// Answer whether `referenceTypeId` is `HierarchicalReferences` or descends from it.
///
/// Walks the inverse HasSubtype chain rather than matching a list of NS0 ids, so a ReferenceType a
/// server author declares under Organizes is judged by the same rule as Organizes itself. A chain
/// deeper than the bound is a cycle rather than a model, and answers false: refusing an item on the
/// strength of a broken type hierarchy would turn a modelling error into a rejected request.
void is_hierarchical_reference_type_async(
  AddressSpace addressSpace, NodeId referenceTypeId, std::function<void(bool)> onComplete)
{
  constexpr int maxSupertypeDepth = 32;

  struct Walk
  {
    WeakAddressSpace addressSpace;
    std::function<void(bool)> onComplete;
    int depth{0};

    void step(NodeId typeId, std::shared_ptr<Walk> self)
    {
      if (typeId == NodeId{ReferenceTypeId::HierarchicalReferences})
      {
        self->onComplete(true);
        return;
      }
      if (++depth > maxSupertypeDepth)
      {
        self->onComplete(false);
        return;
      }
      find_node_weakly(addressSpace,
        typeId,
        [self](NodeAccessorResult found) mutable
        {
          // Not Good, an Uncertain answer included: the type is not known to be hierarchical.
          if (!found.is_good())
          {
            self->onComplete(false);
            return;
          }
          found.value().get_references_async(
            [self](Result<References> references) mutable
            {
              if (!references.is_good())
              {
                self->onComplete(false);
                return;
              }
              for (const auto& reference : references.value())
              {
                if (reference.is_forward() || reference.is_remote())
                  continue;
                if (reference.type_id() != NodeId{ReferenceTypeId::HasSubtype})
                  continue;
                if (!reference.target_id().is_local())
                  continue;
                self->step(reference.target_id().node_id(), self);
                return;
              }
              self->onComplete(false);
            });
        });
    }
  };

  auto walk = std::make_shared<Walk>(Walk{addressSpace.weak(), std::move(onComplete), 0});
  walk->step(referenceTypeId, walk);
}

/// Determines whether a local ObjectType is BaseInterfaceType or one of its descendants.
///
/// The walk owns itself through its callback chain. Every collaborator completion is posted onto the
/// address-space executor before the next step, so in-memory namespaces may complete inline without
/// growing the stack. A failed lookup or reference read remains a bad BoolResult with its rich
/// StatusCode; the AddNodes flow wraps that cause as BadTypeDefinitionInvalid for the affected item.
class InterfaceTypeWalk final : public std::enable_shared_from_this<InterfaceTypeWalk>
{
public:
  InterfaceTypeWalk(AddressSpace addressSpace, NodeId candidate, std::function<void(BoolResult)> onComplete)
    : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
      mCandidate(std::move(candidate)), mOnComplete(std::move(onComplete))
  {}

  void start()
  {
    find_candidate();
  }

private:
  enum class Step
  {
    FindingCandidate,
    ReadingReferences,
    Done,
  };

  static constexpr size_t sMaxHierarchyDepth = 64;

  static const NodeId& base_interface_type()
  {
    static const NodeId id{ObjectTypeId::BaseInterfaceType};
    return id;
  }

  void find_candidate()
  {
    if (mStep == Step::Done)
      return;
    if (mCandidate == base_interface_type())
    {
      complete(BoolResult{true});
      return;
    }
    if (++mDepth > sMaxHierarchyDepth)
    {
      complete(BoolResult{StatusCode{Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("InterfaceHierarchyTooDeep",
          "Type hierarchy exceeded the bounded walk depth",
          "NodeManagementService")
          .context(ContextKeys::max, sMaxHierarchyDepth)
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }

    mStep = Step::FindingCandidate;
    find_node_weakly(mAddressSpace,
      mCandidate,
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](InterfaceTypeWalk& self, NodeAccessorResult result) mutable
        { self.on_candidate_found(std::move(result)); }));
  }

  void on_candidate_found(NodeAccessorResult result)
  {
    if (mStep != Step::FindingCandidate)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("InterfaceWalkStepMismatch",
          "Interface hierarchy walk reached an unexpected step",
          "NodeManagementService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(
        BoolResult{::ua::detail::lookup_failure(mCandidate, result.status_code(), "NodeManagementService")});
      return;
    }

    mStep = Step::ReadingReferences;
    result.value().get_references_async(ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](InterfaceTypeWalk& self, Result<References> references) mutable
      { self.on_references_read(std::move(references)); }));
  }

  void on_references_read(Result<References> result)
  {
    if (mStep != Step::ReadingReferences)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("InterfaceWalkStepMismatch",
          "Interface hierarchy walk reached an unexpected step",
          "NodeManagementService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
        result.status_code(),
        "NodeManagementService",
        mCandidate)});
      return;
    }

    for (const auto& reference : result.value())
    {
      if (reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasSubtype})
        continue;
      if (!reference.target_id().is_local())
      {
        complete(BoolResult{StatusCode{Status::BadTypeDefinitionInvalid,
          ErrorDetail::build("RemoteInterfaceSupertype",
            "Interface hierarchy contains a remote supertype that cannot be validated locally",
            "NodeManagementService")
            .context(ContextKeys::nodeId, reference.target_id())}});
        return;
      }
      mCandidate = reference.target_id().node_id();
      find_candidate();
      return;
    }

    complete(BoolResult{false});
  }

  void complete(BoolResult result)
  {
    if (mStep == Step::Done)
      return;
    mStep = Step::Done;
    auto onComplete = std::move(mOnComplete);
    onComplete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeId mCandidate;
  std::function<void(BoolResult)> mOnComplete;
  size_t mDepth{0};
  Step mStep{Step::FindingCandidate};
};

void is_interface_type_async(
  AddressSpace addressSpace, NodeId candidate, std::function<void(BoolResult)> onComplete)
{
  auto walk =
    std::make_shared<InterfaceTypeWalk>(std::move(addressSpace), std::move(candidate), std::move(onComplete));
  walk->start();
}

/// Core Part 3 ReferenceTypes in the HasChild family. These identities are intrinsic to the standard
/// hierarchy and remain classifiable in deliberately minimal address spaces that do not materialize
/// NS0 ReferenceType Nodes. User-defined and later standard subtypes still use the hierarchy walk.
std::optional<bool> classify_core_reference_type_as_has_child(const NodeId& candidate)
{
  if (candidate == NodeId{ReferenceTypeId::HasChild} ||
      candidate == NodeId{ReferenceTypeId::HasEventSource} ||
      candidate == NodeId{ReferenceTypeId::HasNotifier} || candidate == NodeId{ReferenceTypeId::Aggregates} ||
      candidate == NodeId{ReferenceTypeId::HasSubtype} || candidate == NodeId{ReferenceTypeId::HasProperty} ||
      candidate == NodeId{ReferenceTypeId::HasComponent} ||
      candidate == NodeId{ReferenceTypeId::HasOrderedComponent})
  {
    return true;
  }

  if (candidate == NodeId{ReferenceTypeId::References} ||
      candidate == NodeId{ReferenceTypeId::NonHierarchicalReferences} ||
      candidate == NodeId{ReferenceTypeId::HierarchicalReferences} ||
      candidate == NodeId{ReferenceTypeId::Organizes} ||
      candidate == NodeId{ReferenceTypeId::HasModellingRule} ||
      candidate == NodeId{ReferenceTypeId::HasEncoding} ||
      candidate == NodeId{ReferenceTypeId::HasDescription} ||
      candidate == NodeId{ReferenceTypeId::HasTypeDefinition} ||
      candidate == NodeId{ReferenceTypeId::GeneratesEvent} ||
      candidate == NodeId{ReferenceTypeId::AlwaysGeneratesEvent} ||
      candidate == NodeId{ReferenceTypeId::HasInterface})
  {
    return false;
  }

  return std::nullopt;
}

std::optional<bool> classify_core_reference_type_as_hierarchical(const NodeId& candidate)
{
  if (candidate == NodeId{ReferenceTypeId::HierarchicalReferences} ||
      candidate == NodeId{ReferenceTypeId::Organizes})
  {
    return true;
  }

  if (const auto hasChild = classify_core_reference_type_as_has_child(candidate); hasChild && *hasChild)
    return true;

  if (candidate == NodeId{ReferenceTypeId::References} ||
      candidate == NodeId{ReferenceTypeId::NonHierarchicalReferences} ||
      candidate == NodeId{ReferenceTypeId::HasModellingRule} ||
      candidate == NodeId{ReferenceTypeId::HasEncoding} ||
      candidate == NodeId{ReferenceTypeId::HasDescription} ||
      candidate == NodeId{ReferenceTypeId::HasTypeDefinition} ||
      candidate == NodeId{ReferenceTypeId::GeneratesEvent} ||
      candidate == NodeId{ReferenceTypeId::AlwaysGeneratesEvent} ||
      candidate == NodeId{ReferenceTypeId::HasInterface})
  {
    return false;
  }

  return std::nullopt;
}

/// Determines whether a ReferenceType is the named ancestor or one of its descendants.
///
/// Like InterfaceTypeWalk, this is a bounded, self-owning asynchronous walk. Failures retain the
/// address-space StatusCode so callers can wrap the exact lookup/read cause at their service interface.
class ReferenceTypeSubtypeWalk final : public std::enable_shared_from_this<ReferenceTypeSubtypeWalk>
{
public:
  ReferenceTypeSubtypeWalk(
    AddressSpace addressSpace, NodeId candidate, NodeId ancestor, std::function<void(BoolResult)> onComplete)
    : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
      mCandidate(std::move(candidate)), mAncestor(std::move(ancestor)), mOnComplete(std::move(onComplete))
  {}

  void start()
  {
    find_candidate();
  }

private:
  enum class Step
  {
    FindingCandidate,
    ReadingReferences,
    Done,
  };

  static constexpr size_t sMaxHierarchyDepth = 64;

  void find_candidate()
  {
    if (mStep == Step::Done)
      return;
    if (mCandidate == mAncestor)
    {
      complete(BoolResult{true});
      return;
    }
    if (mAncestor == NodeId{ReferenceTypeId::HasChild})
    {
      const auto coreClassification = classify_core_reference_type_as_has_child(mCandidate);
      if (coreClassification)
      {
        complete(BoolResult{*coreClassification});
        return;
      }
    }
    if (mAncestor == NodeId{ReferenceTypeId::HierarchicalReferences})
    {
      const auto coreClassification = classify_core_reference_type_as_hierarchical(mCandidate);
      if (coreClassification)
      {
        complete(BoolResult{*coreClassification});
        return;
      }
    }
    if (std::find(mVisited.begin(), mVisited.end(), mCandidate) != mVisited.end())
    {
      complete(BoolResult{StatusCode{Status::BadReferenceTypeIdInvalid,
        ErrorDetail::build(
          "ReferenceTypeHierarchyCycle", "ReferenceType hierarchy contains a cycle", "NodeManagementService")
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }
    mVisited.push_back(mCandidate);
    if (mVisited.size() > sMaxHierarchyDepth)
    {
      complete(BoolResult{StatusCode{Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("ReferenceTypeHierarchyTooDeep",
          "ReferenceType hierarchy exceeded the bounded walk depth",
          "NodeManagementService")
          .context(ContextKeys::max, sMaxHierarchyDepth)
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }

    mStep = Step::FindingCandidate;
    find_node_weakly(mAddressSpace,
      mCandidate,
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](ReferenceTypeSubtypeWalk& self, NodeAccessorResult result) mutable
        { self.on_candidate_found(std::move(result)); }));
  }

  void on_candidate_found(NodeAccessorResult result)
  {
    if (mStep != Step::FindingCandidate)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("ReferenceTypeWalkStepMismatch",
          "ReferenceType hierarchy walk reached an unexpected step",
          "NodeManagementService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(
        BoolResult{::ua::detail::lookup_failure(mCandidate, result.status_code(), "NodeManagementService")});
      return;
    }
    if (result.value().get_node_class() != NodeClass::ReferenceType)
    {
      complete(BoolResult{StatusCode{Status::BadReferenceTypeIdInvalid,
        ErrorDetail::build("HierarchyNodeNotReferenceType",
          "ReferenceType hierarchy walk resolved a non-ReferenceType Node",
          "NodeManagementService")
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }

    mStep = Step::ReadingReferences;
    result.value().get_references_async(ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](ReferenceTypeSubtypeWalk& self, Result<References> references) mutable
      { self.on_references_read(std::move(references)); }));
  }

  void on_references_read(Result<References> result)
  {
    if (mStep != Step::ReadingReferences)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("ReferenceTypeWalkStepMismatch",
          "ReferenceType hierarchy walk reached an unexpected step",
          "NodeManagementService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
        result.status_code(),
        "NodeManagementService",
        mCandidate)});
      return;
    }

    for (const auto& reference : result.value())
    {
      if (reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasSubtype})
        continue;
      if (!reference.target_id().is_local())
      {
        complete(BoolResult{StatusCode{Status::BadReferenceTypeIdInvalid,
          ErrorDetail::build("RemoteReferenceTypeSupertype",
            "ReferenceType hierarchy contains a remote supertype that cannot be validated locally",
            "NodeManagementService")
            .context(ContextKeys::nodeId, reference.target_id())}});
        return;
      }
      mCandidate = reference.target_id().node_id();
      find_candidate();
      return;
    }

    complete(BoolResult{false});
  }

  void complete(BoolResult result)
  {
    if (mStep == Step::Done)
      return;
    mStep = Step::Done;
    auto onComplete = std::move(mOnComplete);
    onComplete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeId mCandidate;
  NodeId mAncestor;
  std::function<void(BoolResult)> mOnComplete;
  std::vector<NodeId> mVisited;
  Step mStep{Step::FindingCandidate};
};

void is_reference_type_or_subtype_async(
  AddressSpace addressSpace, NodeId candidate, NodeId ancestor, std::function<void(BoolResult)> onComplete)
{
  auto walk = std::make_shared<ReferenceTypeSubtypeWalk>(
    std::move(addressSpace), std::move(candidate), std::move(ancestor), std::move(onComplete));
  walk->start();
}

class BrowseNameCollisionWalk final : public std::enable_shared_from_this<BrowseNameCollisionWalk>
{
public:
  BrowseNameCollisionWalk(AddressSpace addressSpace, NodeAccessor parent, NodeId referenceTypeId,
    QualifiedName browseName, std::function<void(BoolResult)> onComplete)
    : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
      mParent(std::move(parent)), mReferenceTypeId(std::move(referenceTypeId)),
      mBrowseName(std::move(browseName)), mOnComplete(std::move(onComplete))
  {}

  void start()
  {
    mStep = Step::ReadingReferences;
    mParent.get_references_async(ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](BrowseNameCollisionWalk& self, Result<References> result) mutable
      { self.on_references_read(std::move(result)); }));
  }

private:
  enum class Step
  {
    ReadingReferences,
    FindingCandidate,
    Done,
  };

  void on_references_read(Result<References> result)
  {
    if (mStep != Step::ReadingReferences)
    {
      complete(step_mismatch());
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
        result.status_code(),
        "NodeManagementService",
        mParent.get_node_id())});
      return;
    }

    for (const auto& reference : result.value())
    {
      if (reference.is_forward() && reference.type_id() == mReferenceTypeId &&
          reference.target_id().is_local())
      {
        mCandidates.push_back(reference.target_id().node_id());
      }
    }
    find_next_candidate();
  }

  void find_next_candidate()
  {
    if (mStep == Step::Done)
      return;
    if (mCandidateIndex >= mCandidates.size())
    {
      complete(BoolResult{false});
      return;
    }

    mStep = Step::FindingCandidate;
    find_node_weakly(mAddressSpace,
      mCandidates[mCandidateIndex],
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](BrowseNameCollisionWalk& self, NodeAccessorResult result) mutable
        { self.on_candidate_found(std::move(result)); }));
  }

  void on_candidate_found(NodeAccessorResult result)
  {
    if (mStep != Step::FindingCandidate)
    {
      complete(step_mismatch());
      return;
    }
    if (!result.is_good())
    {
      if (result.status_code().as_status() != Status::BadNodeIdUnknown)
      {
        complete(BoolResult{::ua::detail::lookup_failure(
          mCandidates[mCandidateIndex], result.status_code(), "NodeManagementService")});
        return;
      }
    }
    else if (result.value().get_browse_name() == mBrowseName)
    {
      complete(BoolResult{true});
      return;
    }

    ++mCandidateIndex;
    find_next_candidate();
  }

  BoolResult step_mismatch() const
  {
    return BoolResult{StatusCode{Status::BadInternalError,
      make_error_detail("BrowseNameCollisionWalkStepMismatch",
        "BrowseName collision validation reached an unexpected step",
        "NodeManagementService")}};
  }

  void complete(BoolResult result)
  {
    if (mStep == Step::Done)
      return;
    mStep = Step::Done;
    auto onComplete = std::move(mOnComplete);
    onComplete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeAccessor mParent;
  NodeId mReferenceTypeId;
  QualifiedName mBrowseName;
  std::function<void(BoolResult)> mOnComplete;
  std::vector<NodeId> mCandidates;
  size_t mCandidateIndex{0};
  Step mStep{Step::ReadingReferences};
};

void has_browse_name_collision_async(AddressSpace addressSpace, NodeAccessor parent, NodeId referenceTypeId,
  QualifiedName browseName, std::function<void(BoolResult)> onComplete)
{
  auto walk = std::make_shared<BrowseNameCollisionWalk>(std::move(addressSpace),
    std::move(parent),
    std::move(referenceTypeId),
    std::move(browseName),
    std::move(onComplete));
  walk->start();
}

/// Answers whether `goal` is reachable from `start` by following forward, local References whose
/// ReferenceType is HasChild or any subtype. Part 3 section 7.5 defines one shared non-looping hierarchy over
/// all HasChild subtypes, so the walk deliberately does not require each edge to use the same exact
/// ReferenceType. The graph and every type-hierarchy lookup are bounded.
class HasChildReachabilityWalk final : public std::enable_shared_from_this<HasChildReachabilityWalk>
{
public:
  HasChildReachabilityWalk(
    AddressSpace addressSpace, NodeId start, NodeId goal, std::function<void(BoolResult)> onComplete)
    : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
      mGoal(std::move(goal)), mOnComplete(std::move(onComplete))
  {
    mPendingNodes.push_back(std::move(start));
  }

  void start()
  {
    process_next_node();
  }

private:
  enum class Step
  {
    FindingNode,
    ReadingReferences,
    ClassifyingReference,
    Done,
  };

  static constexpr size_t sMaxVisitedNodes = 256;
  static constexpr size_t sMaxExaminedReferences = 2048;

  void process_next_node()
  {
    if (mStep == Step::Done)
      return;
    if (mNextNode >= mPendingNodes.size())
    {
      complete(BoolResult{false});
      return;
    }

    mCurrentNode = mPendingNodes[mNextNode++];
    if (mCurrentNode == mGoal)
    {
      complete(BoolResult{true});
      return;
    }
    if (std::find(mVisited.begin(), mVisited.end(), mCurrentNode) != mVisited.end())
    {
      process_next_node();
      return;
    }
    mVisited.push_back(mCurrentNode);
    if (mVisited.size() > sMaxVisitedNodes)
    {
      complete(BoolResult{StatusCode{Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("NoLoopNodeLimitExceeded",
          "HasChild reachability walk exceeded its Node bound",
          "NodeManagementService")
          .context(ContextKeys::max, sMaxVisitedNodes)}});
      return;
    }

    mStep = Step::FindingNode;
    find_node_weakly(mAddressSpace,
      mCurrentNode,
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](HasChildReachabilityWalk& self, NodeAccessorResult result) mutable
        { self.on_node_found(std::move(result)); }));
  }

  void on_node_found(NodeAccessorResult result)
  {
    if (mStep != Step::FindingNode)
    {
      complete(step_mismatch());
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{
        ::ua::detail::lookup_failure(mCurrentNode, result.status_code(), "NodeManagementService")});
      return;
    }

    mStep = Step::ReadingReferences;
    result.value().get_references_async(ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](HasChildReachabilityWalk& self, Result<References> references) mutable
      { self.on_references_read(std::move(references)); }));
  }

  void on_references_read(Result<References> result)
  {
    if (mStep != Step::ReadingReferences)
    {
      complete(step_mismatch());
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
        result.status_code(),
        "NodeManagementService",
        mCurrentNode)});
      return;
    }

    mReferences = std::move(result).value();
    mReferenceIndex = 0;
    classify_next_reference();
  }

  void classify_next_reference()
  {
    if (mStep == Step::Done)
      return;
    while (mReferenceIndex < mReferences.size())
    {
      const auto& reference = mReferences.span()[mReferenceIndex];
      if (!reference.is_forward() || !reference.target_id().is_local())
      {
        ++mReferenceIndex;
        continue;
      }
      if (++mExaminedReferences > sMaxExaminedReferences)
      {
        complete(BoolResult{StatusCode{Status::BadEncodingLimitsExceeded,
          ErrorDetail::build("NoLoopReferenceLimitExceeded",
            "HasChild reachability walk exceeded its Reference bound",
            "NodeManagementService")
            .context(ContextKeys::max, sMaxExaminedReferences)}});
        return;
      }

      auto cached = std::find_if(mTypeCache.begin(),
        mTypeCache.end(),
        [&reference](const auto& entry) { return entry.first == reference.type_id(); });
      if (cached != mTypeCache.end())
      {
        accept_classification(cached->second);
        continue;
      }

      mStep = Step::ClassifyingReference;
      auto addressSpace = mAddressSpace.lock();
      if (!addressSpace)
      {
        complete(BoolResult{ua::detail::address_space_gone("NodeManagementService")});
        return;
      }
      is_reference_type_or_subtype_async(std::move(*addressSpace),
        reference.type_id(),
        NodeId{ReferenceTypeId::HasChild},
        ua::async::post_owning(this,
          mExecutor,
          mLogger,
          [](HasChildReachabilityWalk& self, BoolResult isHasChild) mutable
          { self.on_reference_classified(std::move(isHasChild)); }));
      return;
    }

    process_next_node();
  }

  void on_reference_classified(BoolResult result)
  {
    if (mStep != Step::ClassifyingReference)
    {
      complete(step_mismatch());
      return;
    }
    if (!result.is_good())
    {
      complete(std::move(result));
      return;
    }
    const auto& reference = mReferences.span()[mReferenceIndex];
    mTypeCache.emplace_back(reference.type_id(), result.value());
    accept_classification(result.value());
    classify_next_reference();
  }

  void accept_classification(bool isHasChild)
  {
    const auto& reference = mReferences.span()[mReferenceIndex++];
    if (!isHasChild)
      return;

    const NodeId next = reference.target_id().node_id();
    if (next == mGoal)
    {
      complete(BoolResult{true});
      return;
    }
    const bool known = std::find(mVisited.begin(), mVisited.end(), next) != mVisited.end() ||
                       std::find(mPendingNodes.begin(), mPendingNodes.end(), next) != mPendingNodes.end();
    if (!known)
      mPendingNodes.push_back(next);
  }

  BoolResult step_mismatch() const
  {
    return BoolResult{StatusCode{Status::BadInternalError,
      make_error_detail("NoLoopWalkStepMismatch",
        "HasChild reachability walk reached an unexpected step",
        "NodeManagementService")}};
  }

  void complete(BoolResult result)
  {
    if (mStep == Step::Done)
      return;
    mStep = Step::Done;
    auto onComplete = std::move(mOnComplete);
    onComplete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeId mGoal;
  std::function<void(BoolResult)> mOnComplete;
  std::vector<NodeId> mPendingNodes;
  std::vector<NodeId> mVisited;
  std::vector<std::pair<NodeId, bool>> mTypeCache;
  size_t mNextNode{0};
  size_t mExaminedReferences{0};
  NodeId mCurrentNode;
  References mReferences;
  size_t mReferenceIndex{0};
  Step mStep{Step::FindingNode};
};

void has_child_path_async(
  AddressSpace addressSpace, NodeId start, NodeId goal, std::function<void(BoolResult)> onComplete)
{
  auto walk = std::make_shared<HasChildReachabilityWalk>(
    std::move(addressSpace), std::move(start), std::move(goal), std::move(onComplete));
  walk->start();
}

template<typename ItemT>
NodeId item_authz_node(const ItemT& item, AccessOperation op);

template<>
NodeId item_authz_node<AddReferencesItem>(const AddReferencesItem& item, AccessOperation /*op*/)
{
  return item.source_node_id();
}

template<>
NodeId item_authz_node<DeleteNodesItem>(const DeleteNodesItem& item, AccessOperation /*op*/)
{
  return item.node_id();
}

template<>
NodeId item_authz_node<DeleteReferencesItem>(const DeleteReferencesItem& item, AccessOperation /*op*/)
{
  return item.source_node_id();
}

}  // namespace

// =============================================================================================
// AddNodes flow
// =============================================================================================
//
// ASCII flow:
//   start_add_nodes                                       (entry from begin_processing, on mStrand)
//     [validate session / Empty / TooMany]                rejects -> service fault inline
//     [fail-closed: no committed AccessIdentity]         mark all denied; -> CallingHandler
//     [screen item shape]
//     [required TypeDefinition] -> resolve and verify ObjectType/VariableType for the NodeClass
//     -> on_add_nodes_type_definition_resolved(itemIndex, NodeAccessorResult)
//          [missing/wrong class] write BadTypeDefinitionInvalid + detail; --counter
//          [VariableType] mark eligible; --counter
//          [ObjectType] -> InterfaceTypeWalk on address-space executor
//     -> on_add_nodes_type_definition_checked(itemIndex, BoolResult)
//          [walk bad] wrap rich cause as BadTypeDefinitionInvalid; --counter
//          [Interface] write BadTypeDefinitionInvalid + detail; --counter
//          [concrete type] mark eligible; --counter
//          if counter == 0 -> start_add_nodes_authorization
//     -> start_add_nodes_authorization
//          [eligible item] per-item parent find_node fan-out
//     -> on_add_nodes_item_node_resolved(itemIndex, NodeAccessorResult)
//          [find_node bad]  write findResult status + shared_detail; --counter
//          [find_node good] retain parent; validate BrowseName/reference invariants; --counter
//          if counter == 0 -> start_add_nodes_handler_call
//     -> start_add_nodes_handler_call
//          [no authorized items] complete_add_nodes (no handler call)
//          else add_nodes_async -> on_add_nodes_handler_complete
//     -> on_add_nodes_handler_complete(BatchResult<...>)
//          [batchStatus.is_bad()] log + per-item batchStatus + collector detail
//          [success]              per-item map result + AddNodesResult
//          complete_add_nodes
//     -> complete_add_nodes | fail_add_nodes

void NodeManagementService::start_add_nodes()
{
  // Engaged by the AddNodes constructor; begin_processing only dispatches here when it is set.
  if (!mAddNodesRequest)
    return;
  auto& request = *mAddNodesRequest;
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{request.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw_null_pointer_check(Status::BadInvalidArgument);
    }
    set_timeout();

    auto& items = request.nodes_to_add();
    const size_t count = items.size();

    if (count == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail(
          "EmptyAddNodesRequest", "AddNodes request contains no items", "NodeManagementService")};
    }

    auto& limit =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerNodeManagement;
    if (limit && count > limit.value())
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyNodesToAdd",
          "Requested item count exceeds the server operation limit",
          "NodeManagementService")
          .context(ua::ContextKeys::sizeActual, std::to_string(count))
          .context(ua::ContextKeys::sizeMax, std::to_string(limit.value()))};
    }

    const auto* sec = dynamic_cast<const SessionSecurityContext*>(sessionInfo.get());
    auto addressSpace = sessionInfo->address_space();

    auto response = std::make_shared<AddNodesResponse>();
    response->results().resize(count);

    mAddNodesState = std::make_unique<AddNodesState>(std::move(addressSpace), response, std::move(collector));
    mAddNodesState->accessControl = SessionAccessControl::create(*sessionInfo);
    mAddNodesState->eligible.assign(count, false);
    mAddNodesState->authorized.assign(count, false);
    mAddNodesState->destinations.resize(count);
    mAddNodesState->resolvedParents.resize(count);

    auto handlerContext = std::make_shared<NodeManagementDelegate::Context>();
    if (sec)
    {
      handlerContext->userIdentity = sec->user_identity();
      handlerContext->endpointSecurity = sec->endpoint_security();
    }
    handlerContext->cancelled = mCancelled;
    mAddNodesState->handlerContext = std::move(handlerContext);

    if (!mAddNodesState->accessControl)
    {
      for (size_t i = 0; i < count; ++i)
      {
        StatusCode status{Status::BadUserAccessDenied,
          ErrorDetail::build("AuthorizationUnavailable",
            "AddNodes denied because no committed access identity is available",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, i)};
        mAddNodesState->response->results()[i].status_code() = status;
        mAddNodesState->collector.add_item_detail(i, status.shared_detail());
      }
      // Nothing to prepare, so the body goes straight to the delegate with nothing.
      mAddNodesTask = run_add_nodes();
      return;
    }

    std::vector<AddNodesItem> preparationItems;
    preparationItems.reserve(count);
    mAddNodesState->preparationIndices.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      const auto& requestedNewNodeId = items[i].requested_new_node_id();
      if (requestedNewNodeId.server_index() != 0)
      {
        std::shared_ptr<const ErrorDetail> detail =
          ErrorDetail::build("AddNodesRequestedNodeIdServerIndexInvalid",
            "AddNodes requestedNewNodeId must identify this server",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, i)
            .context(ContextKeys::serverIndex, requestedNewNodeId.server_index())
            .context(ContextKeys::nodeId, requestedNewNodeId.node_id());
        mAddNodesState->response->results()[i].status_code() = StatusCode{Status::BadNodeIdRejected, detail};
        mAddNodesState->collector.add_item_detail(i, detail);
        continue;
      }

      const NodeId& requestedNodeId = requestedNewNodeId.node_id();
      if (!requestedNodeId.is_null() &&
          !mAddNodesState->addressSpace.namespace_array().get_namespace(requestedNodeId.namespace_index()))
      {
        std::shared_ptr<const ErrorDetail> detail =
          ErrorDetail::build("AddNodesRequestedNodeIdNamespaceUnknown",
            "AddNodes requestedNewNodeId uses an unknown namespace index",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, i)
            .context(ContextKeys::nodeId, requestedNodeId)
            .context(ContextKeys::namespaceIndex, requestedNodeId.namespace_index());
        mAddNodesState->response->results()[i].status_code() = StatusCode{Status::BadNodeIdRejected, detail};
        mAddNodesState->collector.add_item_detail(i, detail);
        continue;
      }

      mAddNodesState->preparationIndices.push_back(i);
      preparationItems.push_back(items[i]);
    }

    mAddNodesState->preparationItems = std::move(preparationItems);
    mAddNodesTask = run_add_nodes();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "NodeManagementService", er);
    }
    if (mAddNodesState)
    {
      fail_add_nodes(VoidResult{er, er.shared_detail()});
    }
    else
    {
      send_service_fault(request.request_header(), er);
    }
  }
}

ua::async::Task<> NodeManagementService::run_add_nodes()
{
  try
  {
    auto& state = *mAddNodesState;

    // --- destinations: one batch call, then one authorization per destination namespace --------
    if (!state.preparationIndices.empty())
    {
      auto batch = co_await await_step<BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult>>(
        [this](auto completion)
        {
          auto& pending = *mAddNodesState;
          mHandler->prepare_add_nodes_async(pending.handlerContext,
            pending.addressSpace,
            std::move(pending.preparationItems),
            std::move(completion));
        });

      auto itemsByDestination = accept_prepared_destinations(std::move(batch));

      if (!itemsByDestination.empty())
      {
        std::vector<ua::async::Task<>> units;
        units.reserve(itemsByDestination.size());
        for (auto& [namespaceIndex, itemIndices] : itemsByDestination)
        {
          units.push_back(authorize_destination_unit(namespaceIndex, std::move(itemIndices)));
        }
        for (auto& unit : units)
        {
          co_await std::move(unit);
        }

        // --- per-item validation, for whatever survived the destination decision --------------
        {
          std::vector<ua::async::Task<>> validations;
          const auto& items = mAddNodesRequest->nodes_to_add();
          validations.reserve(items.size());
          for (size_t i = 0; i < items.size(); ++i)
          {
            if (!state.eligible[i])
            {
              continue;
            }
            if (!screen_add_nodes_item(i))
            {
              continue;
            }
            validations.push_back(validate_add_nodes_unit(i));
          }
          for (auto& unit : validations)
          {
            co_await std::move(unit);
          }
        }

        // --- the parent each surviving item wants to hang from --------------------------------
        {
          std::vector<ua::async::Task<>> parents;
          const auto& items = mAddNodesRequest->nodes_to_add();
          parents.reserve(items.size());
          for (size_t i = 0; i < items.size(); ++i)
          {
            if (state.eligible[i])
            {
              parents.push_back(add_nodes_parent_unit(i));
            }
          }
          for (auto& unit : parents)
          {
            co_await std::move(unit);
          }
        }
      }
    }

    co_await call_add_nodes_delegate();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    const auto er = ua::exception_to_status_code(std::current_exception());
    if (mAddNodesState)
    {
      fail_add_nodes(VoidResult{er, er.shared_detail()});
    }
  }
  co_return;
}

std::unordered_map<uint16_t, std::vector<size_t>> NodeManagementService::accept_prepared_destinations(
  BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch)
{
  auto& state = *mAddNodesState;
  const auto& items = mAddNodesRequest->nodes_to_add();
  const auto failItem = [&state](size_t itemIndex, StatusCode status)
  {
    state.response->results()[itemIndex].status_code() = status;
    if (status.shared_detail())
    {
      state.collector.add_item_detail(itemIndex, status.shared_detail());
    }
  };

  if (batch.batchStatus.is_bad())
  {
    const auto status = batch.batchStatus.status_code();
    for (const auto itemIndex : state.preparationIndices)
    {
      failItem(itemIndex, status);
    }
    return {};
  }

  if (batch.items.size() != state.preparationIndices.size())
  {
    const StatusCode status{Status::BadInternalError,
      ErrorDetail::build("AddNodesPreparationCardinalityMismatch",
        "NodeManagementDelegate returned the wrong number of prepared destinations",
        "NodeManagementService")
        .context(ContextKeys::sizeExpected, state.preparationIndices.size())
        .context(ContextKeys::sizeActual, batch.items.size())};
    for (const auto itemIndex : state.preparationIndices)
    {
      failItem(itemIndex, status);
    }
    return {};
  }

  std::unordered_map<uint16_t, std::vector<size_t>> itemsByDestination;
  for (size_t preparedIndex = 0; preparedIndex < batch.items.size(); ++preparedIndex)
  {
    const size_t itemIndex = state.preparationIndices[preparedIndex];
    auto& prepared = batch.items[preparedIndex];
    if (!prepared.is_good())
    {
      failItem(itemIndex,
        server::detail::not_acted_on(server::detail::answerUncertain,
          prepared.status_code(),
          "NodeManagementService",
          items[itemIndex].requested_new_node_id().node_id()));
      continue;
    }

    const auto destination = prepared.value();
    const auto& requestedNodeId = items[itemIndex].requested_new_node_id().node_id();
    if (!requestedNodeId.is_null() && destination.namespaceIndex != requestedNodeId.namespace_index())
    {
      failItem(itemIndex,
        StatusCode{Status::BadInternalError,
          ErrorDetail::build("AddNodesExplicitDestinationRedirected",
            "NodeManagementDelegate redirected an explicit requestedNewNodeId",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)
            .context(ContextKeys::nodeId, requestedNodeId)
            .context(ContextKeys::namespaceIndex, destination.namespaceIndex)});
      continue;
    }
    if (!state.addressSpace.namespace_array().get_namespace(destination.namespaceIndex))
    {
      failItem(itemIndex,
        StatusCode{Status::BadInternalError,
          ErrorDetail::build("AddNodesDestinationNamespaceUnknown",
            "NodeManagementDelegate selected an unregistered destination namespace",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)
            .context(ContextKeys::namespaceIndex, destination.namespaceIndex)});
      continue;
    }

    state.destinations[itemIndex] = destination;
    itemsByDestination[destination.namespaceIndex].push_back(itemIndex);
  }
  return itemsByDestination;
}

ua::async::Task<> NodeManagementService::authorize_destination_unit(
  uint16_t namespaceIndex, std::vector<size_t> itemIndices)
{
  auto verdict = co_await await_step<AccessControl::Verdict>(
    [this, namespaceIndex](auto completion)
    {
      mAddNodesState->accessControl->authorize_namespace_async(
        RequestInfo{}, namespaceIndex, std::move(completion));
    });

  auto& state = *mAddNodesState;
  for (const auto itemIndex : itemIndices)
  {
    if (verdict.permitted)
    {
      state.eligible[itemIndex] = true;
      continue;
    }
    state.response->results()[itemIndex].status_code() = verdict.cause;
    if (verdict.cause.shared_detail())
    {
      state.collector.add_item_detail(itemIndex, verdict.cause.shared_detail());
    }
  }
}

bool NodeManagementService::screen_add_nodes_item(size_t itemIndex)
{
  auto& state = *mAddNodesState;
  const auto& item = mAddNodesRequest->nodes_to_add()[itemIndex];

  const auto refuse = [&state, itemIndex](StatusCode status)
  {
    state.response->results()[itemIndex].status_code() = status;
    state.collector.add_item_detail(itemIndex, status.shared_detail());
    state.eligible[itemIndex] = false;
    return false;
  };

  const auto& browseName = item.browse_name();
  if (browseName.name().empty())
  {
    return refuse(StatusCode{Status::BadBrowseNameInvalid,
      ErrorDetail::build(
        "EmptyBrowseName", "AddNodes browse name must contain a name", "NodeManagementService")
        .context(ContextKeys::namespaceIndex, browseName.namespace_index())});
  }
  if (!state.addressSpace.namespace_array().get_namespace(browseName.namespace_index()))
  {
    return refuse(StatusCode{Status::BadBrowseNameInvalid,
      ErrorDetail::build("BrowseNameNamespaceUnknown",
        "AddNodes browse name uses an unknown namespace index",
        "NodeManagementService")
        .context(ContextKeys::nodeBrowseName, browseName)
        .context(ContextKeys::namespaceIndex, browseName.namespace_index())});
  }
  if (item.node_class() == NodeClass::Unspecified || !is_valid(item.node_class()))
  {
    return refuse(StatusCode{Status::BadNodeClassInvalid,
      ErrorDetail::build("InvalidNodeClass",
        "AddNodes NodeClass is not one of the eight defined NodeClasses",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)});
  }
  if (!node_attributes_match_class(item))
  {
    return refuse(StatusCode{Status::BadNodeAttributesInvalid,
      ErrorDetail::build("AddNodesNodeAttributesInvalid",
        "AddNodes nodeAttributes do not match the requested NodeClass",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::typeActual, item.node_attributes()->type_name())
        .context(ContextKeys::typeExpected, to_string(item.node_class()))});
  }

  const auto& expandedTypeDefinition = item.type_definition();
  const NodeId typeDefinition = expandedTypeDefinition.node_id();
  const bool requiresTypeDefinition =
    item.node_class() == NodeClass::Object || item.node_class() == NodeClass::Variable;
  const bool hasTypeDefinition = !typeDefinition.is_null();
  if (requiresTypeDefinition != hasTypeDefinition ||
      (hasTypeDefinition && !expandedTypeDefinition.is_local()))
  {
    return refuse(StatusCode{Status::BadTypeDefinitionInvalid,
      ErrorDetail::build("AddNodesTypeDefinitionScopeInvalid",
        "AddNodes typeDefinition is required exactly for Object and Variable Nodes",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::typeName, to_string(item.node_class()))
        .context(ContextKeys::nodeId, typeDefinition)});
  }
  return true;
}

ua::async::Task<> NodeManagementService::validate_add_nodes_unit(size_t itemIndex)
{
  auto& state = *mAddNodesState;
  const auto& item = mAddNodesRequest->nodes_to_add()[itemIndex];

  // The chain started these two checks together and let whichever answered last write the item's
  // result. Run in the order it started them, which is the order they landed whenever the address
  // space answered inline - so the ReferenceType verdict still has the last word.
  if (!item.type_definition().node_id().is_null())
  {
    auto typeNode = co_await await_step<NodeAccessorResult>(
      [this, itemIndex](auto completion)
      {
        mAddNodesState->addressSpace.find_node_async(
          mAddNodesRequest->nodes_to_add()[itemIndex].type_definition().node_id(), std::move(completion));
      });

    if (!typeNode.is_good() && !typeNode.is_bad())
    {
      const StatusCode refused = ::ua::detail::lookup_failure(
        item.type_definition().node_id(), typeNode.status_code(), "NodeManagementService");
      state.response->results()[itemIndex].status_code() = refused;
      state.collector.add_item_detail(itemIndex, refused.shared_detail());
      state.eligible[itemIndex] = false;
    }
    else if (typeNode.is_bad())
    {
      std::shared_ptr<const ErrorDetail> detail =
        ErrorDetail::build("TypeDefinitionHierarchyUnavailable",
          "AddNodes could not validate the TypeDefinition hierarchy",
          "NodeManagementService")
          .context(ContextKeys::operationIndex, itemIndex)
          .context(ContextKeys::nodeId, item.type_definition().node_id())
          .cause(typeNode.status_code());
      state.response->results()[itemIndex].status_code() =
        StatusCode{Status::BadTypeDefinitionInvalid, detail};
      state.collector.add_item_detail(itemIndex, detail);
      state.eligible[itemIndex] = false;
    }
    else
    {
      const NodeClass requiredTypeClass =
        item.node_class() == NodeClass::Object ? NodeClass::ObjectType : NodeClass::VariableType;
      const NodeClass actualTypeClass = typeNode.value().get_node_class();
      if (actualTypeClass != requiredTypeClass)
      {
        std::shared_ptr<const ErrorDetail> detail =
          ErrorDetail::build("AddNodesTypeDefinitionInvalid",
            "AddNodes typeDefinition does not identify the type class required by the NodeClass",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)
            .context(ContextKeys::nodeId, item.type_definition().node_id())
            .context(ContextKeys::typeActual, to_string(actualTypeClass))
            .context(ContextKeys::typeExpected, to_string(requiredTypeClass));
        state.response->results()[itemIndex].status_code() =
          StatusCode{Status::BadTypeDefinitionInvalid, detail};
        state.collector.add_item_detail(itemIndex, detail);
        state.eligible[itemIndex] = false;
      }
      else if (requiredTypeClass == NodeClass::ObjectType)
      {
        auto isInterface = co_await await_step<BoolResult>(
          [this, itemIndex](auto completion)
          {
            is_interface_type_async(mAddNodesState->addressSpace,
              mAddNodesRequest->nodes_to_add()[itemIndex].type_definition().node_id(),
              std::move(completion));
          });

        if (!isInterface.is_good())
        {
          StatusCode status{Status::BadTypeDefinitionInvalid,
            make_error_detail("TypeDefinitionHierarchyUnavailable",
              "AddNodes could not validate the TypeDefinition hierarchy",
              "NodeManagementService",
              isInterface.status_code())};
          state.response->results()[itemIndex].status_code() = status;
          state.collector.add_item_detail(itemIndex, status.shared_detail());
          state.eligible[itemIndex] = false;
        }
        else if (isInterface.value())
        {
          StatusCode status{Status::BadTypeDefinitionInvalid,
            ErrorDetail::build("InterfaceAsTypeDefinition",
              "An Interface cannot be used as an instance TypeDefinition",
              "NodeManagementService")
              .context(ContextKeys::operationIndex, itemIndex)};
          state.response->results()[itemIndex].status_code() = status;
          state.collector.add_item_detail(itemIndex, status.shared_detail());
          state.eligible[itemIndex] = false;
        }
      }
      // A successful VariableType validation leaves the tentative eligibility unchanged while the
      // ReferenceType check below runs.
    }
  }

  auto hierarchical = co_await await_step<BoolResult>(
    [this, itemIndex](auto completion)
    {
      is_reference_type_or_subtype_async(mAddNodesState->addressSpace,
        mAddNodesRequest->nodes_to_add()[itemIndex].reference_type_id(),
        NodeId{ReferenceTypeId::HierarchicalReferences},
        std::move(completion));
    });

  if (!hierarchical.is_good())
  {
    const StatusCode cause = hierarchical.status_code();
    if (cause.as_status() == Status::BadNodeIdUnknown ||
        cause.as_status() == Status::BadReferenceTypeIdInvalid)
    {
      std::shared_ptr<const ErrorDetail> detail = ErrorDetail::build("AddNodesReferenceTypeInvalid",
        "AddNodes referenceTypeId does not resolve to a ReferenceType Node",
        "NodeManagementService")
                                                    .context(ContextKeys::operationIndex, itemIndex)
                                                    .context(ContextKeys::nodeId, item.reference_type_id())
                                                    .cause(cause);
      state.response->results()[itemIndex].status_code() =
        StatusCode{Status::BadReferenceTypeIdInvalid, detail};
      state.collector.add_item_detail(itemIndex, detail);
    }
    else
    {
      state.response->results()[itemIndex].status_code() = cause;
      if (cause.shared_detail())
        state.collector.add_item_detail(itemIndex, cause.shared_detail());
    }
    state.eligible[itemIndex] = false;
  }
  else if (!hierarchical.value())
  {
    StatusCode status{Status::BadReferenceNotAllowed,
      ErrorDetail::build("AddNodesReferenceNotHierarchical",
        "AddNodes requires a hierarchical attaching ReferenceType",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::nodeId, item.reference_type_id())};
    state.response->results()[itemIndex].status_code() = status;
    state.collector.add_item_detail(itemIndex, status.shared_detail());
    state.eligible[itemIndex] = false;
  }
  co_return;
}

ua::async::Task<> NodeManagementService::add_nodes_parent_unit(size_t itemIndex)
{
  auto& state = *mAddNodesState;
  const auto& item = mAddNodesRequest->nodes_to_add()[itemIndex];

  auto parent = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      mAddNodesState->addressSpace.find_node_async(
        mAddNodesRequest->nodes_to_add()[itemIndex].parent_node_id().node_id(), std::move(completion));
    });

  const auto refuse = [&state, itemIndex](StatusCode status)
  {
    state.response->results()[itemIndex].status_code() = status;
    if (status.shared_detail())
      state.collector.add_item_detail(itemIndex, status.shared_detail());
    state.authorized[itemIndex] = false;
  };

  if (!parent.is_good())
  {
    // Spec: a missing parent for AddNodes returns BadParentNodeIdInvalid, not the generic
    // BadNodeIdUnknown surfaced by the address-space lookup (Part 4 5.7.2). An Uncertain answer, with or
    // without the parent, is refused.
    auto status = ::ua::detail::lookup_failure(
      item.parent_node_id().node_id(), parent.status_code(), "NodeManagementService");
    if (status.as_status() == Status::BadNodeIdUnknown)
    {
      status = StatusCode{Status::BadParentNodeIdInvalid,
        make_error_detail("AddNodesParentNotFound",
          "AddNodes parent node could not be resolved",
          "NodeManagementService",
          parent.status_code())};
    }
    refuse(status);
    co_return;
  }

  const NodeClass parentNodeClass = parent.value().get_node_class();
  if (item.reference_type_id() == NodeId{ReferenceTypeId::HasSubtype} &&
      (!is_type_node_class(parentNodeClass) || !is_type_node_class(item.node_class()) ||
        parentNodeClass != item.node_class()))
  {
    refuse(StatusCode{Status::BadReferenceNotAllowed,
      ErrorDetail::build("AddNodesHasSubtypeNodeClassInvalid",
        "AddNodes HasSubtype attachment requires matching type NodeClasses",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::typeActual, to_string(item.node_class()))
        .context(ContextKeys::typeExpected, to_string(parentNodeClass))});
    co_return;
  }
  if (parentNodeClass == NodeClass::ReferenceType &&
      item.reference_type_id() == NodeId{ReferenceTypeId::HasProperty} &&
      item.node_class() != NodeClass::Variable)
  {
    refuse(StatusCode{Status::BadNodeClassInvalid,
      ErrorDetail::build("ReferenceTypePropertyNotVariable",
        "A ReferenceType Property created by AddNodes must be a Variable",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)});
    co_return;
  }
  if (item.reference_type_id() == NodeId{ReferenceTypeId::HasProperty} &&
      item.node_class() != NodeClass::Variable)
  {
    refuse(StatusCode{Status::BadReferenceNotAllowed,
      ErrorDetail::build("AddNodesPropertyNotVariable",
        "AddNodes HasProperty attachment requires a Variable target",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::typeActual, to_string(item.node_class()))
        .context(ContextKeys::typeExpected, to_string(NodeClass::Variable))});
    co_return;
  }

  state.resolvedParents[itemIndex] = parent.value();

  auto collision = co_await await_step<BoolResult>(
    [this, itemIndex](auto completion)
    {
      const auto& pending = *mAddNodesState;
      const auto& pendingItem = mAddNodesRequest->nodes_to_add()[itemIndex];
      has_browse_name_collision_async(pending.addressSpace,
        *pending.resolvedParents[itemIndex],
        pendingItem.reference_type_id(),
        pendingItem.browse_name(),
        std::move(completion));
    });

  if (!collision.is_good())
  {
    const StatusCode status = collision.status_code();
    state.response->results()[itemIndex].status_code() = status;
    if (status.shared_detail())
      state.collector.add_item_detail(itemIndex, status.shared_detail());
  }
  else if (collision.value())
  {
    StatusCode status{Status::BadBrowseNameDuplicated,
      ErrorDetail::build("AddNodesBrowseNameDuplicated",
        "AddNodes BrowseName is already used under the same parent relationship",
        "NodeManagementService")
        .context(ContextKeys::operationIndex, itemIndex)
        .context(ContextKeys::nodeBrowseName, item.browse_name())
        .context(ContextKeys::nodeId, item.parent_node_id())};
    state.response->results()[itemIndex].status_code() = status;
    state.collector.add_item_detail(itemIndex, status.shared_detail());
  }
  else
  {
    state.authorized[itemIndex] = true;
  }
  co_return;
}

ua::async::Task<> NodeManagementService::call_add_nodes_delegate()
{
  auto& state = *mAddNodesState;
  auto& items = mAddNodesRequest->nodes_to_add();

  // A request may collide with itself: two items asking for the same BrowseName under the same
  // parent relationship cannot both be added, and only the request can see that.
  for (size_t itemIndex = 0; itemIndex < items.size(); ++itemIndex)
  {
    if (!state.authorized[itemIndex])
      continue;
    for (size_t priorIndex = 0; priorIndex < itemIndex; ++priorIndex)
    {
      if (!state.authorized[priorIndex] ||
          items[itemIndex].parent_node_id() != items[priorIndex].parent_node_id() ||
          items[itemIndex].reference_type_id() != items[priorIndex].reference_type_id() ||
          items[itemIndex].browse_name() != items[priorIndex].browse_name())
      {
        continue;
      }

      StatusCode status{Status::BadBrowseNameDuplicated,
        ErrorDetail::build("AddNodesBrowseNameDuplicatedInRequest",
          "AddNodes request repeats a BrowseName under the same parent relationship",
          "NodeManagementService")
          .context(ContextKeys::operationIndex, itemIndex)
          .context(ContextKeys::nodeBrowseName, items[itemIndex].browse_name())
          .context(ContextKeys::nodeId, items[itemIndex].parent_node_id())};
      state.response->results()[itemIndex].status_code() = status;
      state.collector.add_item_detail(itemIndex, status.shared_detail());
      state.authorized[itemIndex] = false;
      break;
    }
  }

  for (size_t i = 0; i < state.authorized.size(); ++i)
  {
    if (state.authorized[i])
    {
      const auto& destination = state.destinations[i];
      if (!destination)
      {
        fail_add_nodes(VoidResult{StatusCode{Status::BadInternalError,
          ErrorDetail::build("AddNodesDestinationMissing",
            "An authorized AddNodes item has no prepared destination",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, i)}});
        co_return;
      }
      state.authorizedItems.push_back(
        NodeManagementDelegate::AuthorizedAddNode{items[i], destination.value()});
      state.authorizedIndices.push_back(i);
    }
  }

  if (state.authorizedItems.empty())
  {
    complete_add_nodes();
    co_return;
  }

  auto batch = co_await await_step<BatchResult<NodeManagementDelegate::AddNodesItemResult>>(
    [this](auto completion)
    {
      auto& pending = *mAddNodesState;
      mHandler->add_nodes_async(pending.handlerContext,
        pending.addressSpace,
        std::move(pending.authorizedItems),
        std::move(completion));
    });

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "NodeManagement/AddNodes: delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (auto idx : state.authorizedIndices)
    {
      state.response->results()[idx].status_code() = batchStatus;
      if (batchDetail)
      {
        state.collector.add_item_detail(idx, batchDetail);
      }
    }
  }
  else
  {
    auto& handlerResults = batch.items;
    if (handlerResults.size() != state.authorizedIndices.size())
    {
      const StatusCode status{Status::BadInternalError,
        ErrorDetail::build("AddNodesMutationCardinalityMismatch",
          "NodeManagementDelegate returned the wrong number of AddNodes mutation results",
          "NodeManagementService")
          .context(ContextKeys::sizeExpected, state.authorizedIndices.size())
          .context(ContextKeys::sizeActual, handlerResults.size())};
      for (const auto itemIndex : state.authorizedIndices)
      {
        state.response->results()[itemIndex].status_code() = status;
        state.collector.add_item_detail(itemIndex, status.shared_detail());
      }
    }
    else
    {
      for (size_t i = 0; i < state.authorizedIndices.size(); ++i)
      {
        const size_t itemIndex = state.authorizedIndices[i];
        if (!handlerResults[i].has_value())
        {
          state.response->results()[itemIndex].status_code() = handlerResults[i].status_code();
          if (handlerResults[i].shared_detail())
          {
            state.collector.add_item_detail(itemIndex, handlerResults[i].shared_detail());
          }
          continue;
        }

        const StatusCode answered = handlerResults[i].status_code();
        auto result = std::move(handlerResults[i]).value();
        if (result.status_code().is_good())
        {
          const auto& addedNodeId = result.added_node_id();
          const auto destination = state.destinations[itemIndex];
          if (!destination || addedNodeId.is_null() ||
              addedNodeId.namespace_index() != destination->namespaceIndex)
          {
            StatusCode contractFailure{Status::BadInternalError,
              ErrorDetail::build("AddNodesMutationDestinationMismatch",
                "NodeManagementDelegate reported success outside the prepared destination",
                "NodeManagementService")
                .context(ContextKeys::operationIndex, itemIndex)
                .context(ContextKeys::nodeId, addedNodeId)
                .context(
                  ContextKeys::namespaceIndex, destination ? destination->namespaceIndex : uint16_t{})};
            state.response->results()[itemIndex].status_code() = contractFailure;
            state.collector.add_item_detail(itemIndex, contractFailure.shared_detail());
            continue;
          }
        }
        // The delegate's code on its answer and the AddNodesResult's statusCode share the item's one status.
        result.status_code() = server::detail::combined_item_status(answered,
          result.status_code(),
          mLogger,
          "NodeManagementService: an AddNodes answer code was not answered",
          result.added_node_id());
        const StatusCode itemStatus = result.status_code();
        state.response->results()[itemIndex] = std::move(result);
        if (itemStatus.shared_detail())
        {
          state.collector.add_item_detail(itemIndex, itemStatus.shared_detail());
        }
      }
    }
  }

  complete_add_nodes();
}

void NodeManagementService::complete_add_nodes()
{
  if (!try_finish())
  {
    mAddNodesState.reset();
    return;
  }
  if (!mAddNodesRequest)
    return;
  auto& request = *mAddNodesRequest;
  auto& state = *mAddNodesState;
  const size_t count = request.nodes_to_add().size();
  auto sessionInfo = mSessionInfo.lock();
  if (sessionInfo)
  {
    const bool allGood = std::ranges::all_of(
      state.response->results(), [](const auto& r) { return StatusCode{r.status_code()}.is_good(); });
    AuditAddNodesEventPayload auditEvent;
    fill_node_mgmt_audit_base(auditEvent,
      *sessionInfo,
      "NodeManagement/AddNodes",
      allGood,
      request.request_header().audit_entry_id());
    auditEvent.nodesToAdd = Variant{array_utils::copy_to_array_of_references(request.nodes_to_add())};
    emit_node_mgmt_audit(sessionInfo, auditEvent);
  }
  stack_utils::prepare_response_header(request.request_header(), state.response->response_header());
  state.collector.apply_to(state.response->response_header(), state.response->diagnostic_infos(), count);
  auto response = state.response;
  mAddNodesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, response));
}

void NodeManagementService::fail_add_nodes(VoidResult error)
{
  if (!try_finish())
  {
    mAddNodesState.reset();
    return;
  }
  if (!mAddNodesRequest)
    return;
  auto& request = *mAddNodesRequest;
  auto& state = *mAddNodesState;
  state.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&request.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  state.collector.apply_to(serviceFault->response_header(), unused, 0);
  mAddNodesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
}

// =============================================================================================
// AddReferences flow
// =============================================================================================

void NodeManagementService::start_add_references()
{
  // Engaged by the AddReferences constructor; begin_processing only dispatches here when it is set.
  if (!mAddReferencesRequest)
    return;
  auto& request = *mAddReferencesRequest;
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{request.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw_null_pointer_check(Status::BadInvalidArgument);
    }
    set_timeout();

    auto& items = request.references_to_add();
    const size_t count = items.size();

    if (count == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail(
          "EmptyAddReferencesRequest", "AddReferences request contains no items", "NodeManagementService")};
    }

    auto& limit =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerNodeManagement;
    if (limit && count > limit.value())
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyReferencesToAdd",
          "Requested item count exceeds the server operation limit",
          "NodeManagementService")
          .context(ua::ContextKeys::sizeActual, std::to_string(count))
          .context(ua::ContextKeys::sizeMax, std::to_string(limit.value()))};
    }

    const auto* sec = dynamic_cast<const SessionSecurityContext*>(sessionInfo.get());
    auto addressSpace = sessionInfo->address_space();

    auto response = std::make_shared<AddReferencesResponse>();
    response->results().resize(count);

    mAddReferencesState =
      std::make_unique<AddReferencesState>(std::move(addressSpace), response, std::move(collector));
    mAddReferencesState->accessControl = SessionAccessControl::create(*sessionInfo);
    mAddReferencesState->authorized.assign(count, false);
    mAddReferencesState->resolvedSources.resize(count);
    mAddReferencesState->declaredClassVerdict.assign(count, StatusCode{Status::Good});

    auto handlerContext = std::make_shared<NodeManagementDelegate::Context>();
    if (sec)
    {
      handlerContext->userIdentity = sec->user_identity();
      handlerContext->endpointSecurity = sec->endpoint_security();
    }
    handlerContext->cancelled = mCancelled;
    mAddReferencesState->handlerContext = std::move(handlerContext);

    if (!mAddReferencesState->accessControl)
    {
      for (size_t i = 0; i < count; ++i)
      {
        mAddReferencesState->response->results()[i] = Status::BadUserAccessDenied;
      }
      // No units, so the join below is empty and the delegate is called with nothing - the same
      // shape every other answer takes.
      mAddReferencesTask = run_add_references();
      return;
    }

    // Part 4 5.7.3.4 Table 27 gives AddReferences ten operation-level codes, and three of them are
    // decidable from the item alone - no Node has to be resolved and no delegate consulted. They are
    // screened here, in the same place and for the same reason DeleteReferences screens its own target
    // parameters before dispatch: an item that cannot mean anything is refused before the Server spends
    // an address-space lookup deciding whether the caller may perform it.
    const String ownApplicationUri =
      sessionInfo->configuration().application_description_part().applicationUri;
    std::vector<size_t> toResolve;
    toResolve.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      const StatusCode screen = screen_add_references_item(items[i], ownApplicationUri);
      if (screen.is_good())
      {
        toResolve.push_back(i);
        continue;
      }
      // The refusal is the item's answer, not a dropped item: it lands in the operation's own results
      // slot and reaches the caller whether or not anything else in this request succeeds.
      mAddReferencesState->response->results()[i] = screen;
      mAddReferencesState->authorized[i] = false;
    }

    mAddReferencesState->toResolve = std::move(toResolve);
    mAddReferencesTask = run_add_references();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "NodeManagementService", er);
    }
    if (mAddReferencesState)
    {
      fail_add_references(VoidResult{er, er.shared_detail()});
    }
    else
    {
      send_service_fault(request.request_header(), er);
    }
  }
}

ua::async::Task<> NodeManagementService::run_add_references()
{
  try
  {
    const auto& state = *mAddReferencesState;

    // Only the items that survived the item-alone screen become units; the rest already have their
    // answer. The units are spawned eagerly into a vector local to THIS frame, so awaiting them is
    // the barrier the chain spelled out with a countdown.
    std::vector<ua::async::Task<>> units;
    units.reserve(state.toResolve.size());
    for (size_t i : state.toResolve)
    {
      units.push_back(add_references_unit(i));
    }
    for (auto& unit : units)
    {
      co_await std::move(unit);
    }

    co_await call_add_references_delegate();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    const auto er = ua::exception_to_status_code(std::current_exception());
    if (mAddReferencesState)
    {
      fail_add_references(VoidResult{er, er.shared_detail()});
    }
  }
  co_return;
}

ua::async::Task<> NodeManagementService::add_references_unit(size_t itemIndex)
{
  auto& state = *mAddReferencesState;
  const auto& item = mAddReferencesRequest->references_to_add()[itemIndex];

  // --- the source node, and whether this session may add a Reference to it --------------------
  auto sourceNode = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      auto authzNodeId = item_authz_node(
        mAddReferencesRequest->references_to_add()[itemIndex], AccessOperation::AddReferences);
      mAddReferencesState->addressSpace.find_node_async(authzNodeId, std::move(completion));
    });

  if (!sourceNode.is_good())
  {
    // Spec: a missing source for AddReferences returns BadSourceNodeIdInvalid, not the generic
    // BadNodeIdUnknown surfaced by the address-space lookup (Part 4 5.7.3). Answered directly rather
    // than through the verdict helper: there is no data-model check left for it to lose to. An Uncertain
    // answer, with or without the source, is refused.
    auto status =
      ::ua::detail::lookup_failure(item.source_node_id(), sourceNode.status_code(), "NodeManagementService");
    // The lookup's detail (or the refusal's) stays in the operation's diagnostics when the code is replaced.
    const auto detail = status.shared_detail();
    if (status.as_status() == Status::BadNodeIdUnknown)
    {
      status = StatusCode{Status::BadSourceNodeIdInvalid};
    }
    state.response->results()[itemIndex] = status;
    if (detail)
    {
      state.collector.add_item_detail(itemIndex, detail);
    }
    state.authorized[itemIndex] = false;
    co_return;
  }

  state.resolvedSources[itemIndex] = sourceNode.value();
  // SVR-AUTHZ-007 (SVC-6): an inverse Reference changes the TARGET's forward set, so a local target
  // needs AddReference too. Both Nodes are decided in one authorization (two items at most). An absent
  // target (Bad_NodeIdUnknown) has no forward set to grow and is left to the target validation that
  // follows, which answers by ReferenceType; any other lookup failure fails the item (fail closed).
  std::vector<AccessControl::Item> items;
  items.push_back(
    AccessControl::Item{.node = sourceNode.value(), .operation = AccessOperation::AddReferences});
  if (!item.is_forward() && item.target_node_id().server_index() == 0)
  {
    auto targetNode = co_await await_step<NodeAccessorResult>(
      [this, itemIndex](auto completion)
      {
        mAddReferencesState->addressSpace.find_node_async(
          mAddReferencesRequest->references_to_add()[itemIndex].target_node_id().node_id(),
          std::move(completion));
      });
    if (targetNode.is_good())
    {
      items.push_back(
        AccessControl::Item{.node = targetNode.value(), .operation = AccessOperation::AddReferences});
    }
    else if (targetNode.status_code().as_status() != Status::BadNodeIdUnknown)
    {
      // An absent target has no forward set to grow and is left to the target validation below; any
      // other lookup failure, an Uncertain answer included, fails the item rather than skipping the
      // target's check (fail closed).
      const StatusCode failed = ::ua::detail::lookup_failure(
        item.target_node_id().node_id(), targetNode.status_code(), "NodeManagementService");
      state.response->results()[itemIndex] = failed;
      if (failed.shared_detail())
      {
        state.collector.add_item_detail(itemIndex, failed.shared_detail());
      }
      state.authorized[itemIndex] = false;
      co_return;
    }
  }
  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &items](auto completion)
    { mAddReferencesState->accessControl->authorize_async(RequestInfo{}, items, std::move(completion)); });
  if (const auto denial = detail::first_denial(verdicts, items.size()))
  {
    state.response->results()[itemIndex] = *denial;
    if (auto detail = denial->shared_detail())
    {
      state.collector.add_item_detail(itemIndex, std::move(detail));
    }
    co_return;
  }

  // --- what the source already carries ---------------------------------------------------------
  auto sourceRefs = co_await await_step<Result<References>>([this, itemIndex](auto completion)
    { mAddReferencesState->resolvedSources[itemIndex]->get_references_async(std::move(completion)); });

  if (!sourceRefs.is_good())
  {
    finish_add_references_item_validation(itemIndex,
      sourceRefs.is_bad()
        ? StatusCode{Status::BadReferenceNotAllowed}
        : server::detail::uncertain_answer_refused(server::detail::referencesAnswerUncertain,
            sourceRefs.status_code(),
            "NodeManagementService",
            item.source_node_id()));
    co_return;
  }

  // Part 4 5.7.3.4: Bad_DuplicateReferenceNotAllowed. A Reference is identified by the triple
  // (ReferenceType, direction, target), a subtype of a concrete ReferenceType counting as its base concrete
  // type (Part 3 4.3.4), so an item repeating one the source already carries asks for something the address
  // space cannot represent twice. Reporting Good and silently doing nothing tells the caller a second
  // Reference exists.
  const NodeId requestedIdentity = reference_identity_type(item.reference_type_id());
  for (const auto& reference : sourceRefs.value())
  {
    if (reference.is_forward() == item.is_forward() &&
        reference.target_id().node_id() == item.target_node_id().node_id() &&
        reference.target_id().server_index() == item.target_node_id().server_index() &&
        reference_identity_type(reference.type_id()) == requestedIdentity)
    {
      finish_add_references_item_validation(itemIndex, Status::BadDuplicateReferenceNotAllowed);
      co_return;
    }
  }

  // --- the three ReferenceTypes with rules of their own about their own ends -------------------
  if (item.reference_type_id() == NodeId{ReferenceTypeId::HasInterface})
  {
    // Normalize the resulting edge, not the request spelling: for an inverse declaration the item
    // target becomes the HasInterface source.
    const NodeId resultingSource =
      item.is_forward() ? item.source_node_id() : item.target_node_id().node_id();
    auto isInterface = co_await await_step<BoolResult>(
      [this, resultingSource](auto completion) {
        is_interface_type_async(mAddReferencesState->addressSpace, resultingSource, std::move(completion));
      });
    if (!isInterface.is_good())
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          make_error_detail("HasInterfaceSourceHierarchyUnavailable",
            "AddReferences could not validate the HasInterface source hierarchy",
            "NodeManagementService",
            isInterface.status_code())});
      co_return;
    }
    if (isInterface.value())
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          ErrorDetail::build("InterfaceAsHasInterfaceSource",
            "An Interface cannot be the source of a HasInterface reference",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)});
      co_return;
    }
  }
  else if (item.reference_type_id() == NodeId{ReferenceTypeId::HasTypeDefinition})
  {
    // HasTypeDefinition always points instance -> type. In an inverse declaration the item's source
    // is therefore the TypeDefinition that must be checked.
    const NodeId resultingTypeDefinition =
      item.is_forward() ? item.target_node_id().node_id() : item.source_node_id();
    auto isInterface = co_await await_step<BoolResult>(
      [this, resultingTypeDefinition](auto completion)
      {
        is_interface_type_async(
          mAddReferencesState->addressSpace, resultingTypeDefinition, std::move(completion));
      });
    if (!isInterface.is_good())
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          make_error_detail("TypeDefinitionHierarchyUnavailable",
            "AddReferences could not validate the TypeDefinition hierarchy",
            "NodeManagementService",
            isInterface.status_code())});
      co_return;
    }
    if (isInterface.value())
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          ErrorDetail::build("InterfaceAsTypeDefinition",
            "An Interface cannot be the target of a HasTypeDefinition reference",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)});
      co_return;
    }
  }
  else if (item.target_node_id().server_index() == 0 &&
           item.target_node_id().node_id() == item.source_node_id())
  {
    // OPC 10000-3 7.3: "it is not allowed to have self-references using HierarchicalReferences." The
    // prohibition is on the ReferenceType's ancestry rather than on a fixed list of NS0 ids, so a
    // user-defined subtype of Organizes is caught by the same rule - which is why the ancestry is
    // walked rather than matched. The walk only happens for an item that is a self-reference at all,
    // which is rare enough that its cost never falls on ordinary AddReferences traffic.
    auto hierarchical = co_await await_step<bool>(
      [this, itemIndex](auto completion)
      {
        is_hierarchical_reference_type_async(mAddReferencesState->addressSpace,
          mAddReferencesRequest->references_to_add()[itemIndex].reference_type_id(),
          std::move(completion));
      });
    if (hierarchical)
    {
      finish_add_references_item_validation(itemIndex, Status::BadInvalidSelfReference);
      co_return;
    }
  }

  // --- the target, and the class the client declared for it ------------------------------------
  // Every local target is resolved now, not only the targets of the three ReferenceTypes whose own
  // rules constrain them: the declared `targetNodeClass` has to be compared against the Node the
  // Server can actually see, and that comparison applies to a plain Organizes item as much as to a
  // HasProperty one. A remote target is not resolvable here, which is precisely why OPC 10000-4
  // section 5.7.3.2 makes the Client state the class in the first place.
  if (item.target_node_id().server_index() != 0)
  {
    finish_add_references_item_validation(itemIndex);
    co_return;
  }

  auto targetNode = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      mAddReferencesState->addressSpace.find_node_async(
        mAddReferencesRequest->references_to_add()[itemIndex].target_node_id().node_id(),
        std::move(completion));
    });

  if (!targetNode.is_good() && !targetNode.is_bad())
  {
    // An Uncertain answer, with or without the target, is refused: the rules below would rest on it.
    finish_add_references_item_validation(itemIndex,
      ::ua::detail::lookup_failure(
        item.target_node_id().node_id(), targetNode.status_code(), "NodeManagementService"));
    co_return;
  }
  if (targetNode.is_bad())
  {
    // The three ReferenceTypes below have rules *about* the target, so an unresolvable one leaves
    // those rules unenforceable and the item is refused. For every other ReferenceType an absent
    // target is not an error at all: OPC 10000-3 section 4.3.4 says References may point to a Node
    // that does not exist, so refusing here would invent a constraint the model does not impose.
    const bool targetIsConstrained = item.reference_type_id() == NodeId{ReferenceTypeId::HasSubtype} ||
                                     item.reference_type_id() == NodeId{ReferenceTypeId::HasComponent} ||
                                     item.reference_type_id() == NodeId{ReferenceTypeId::HasProperty};
    finish_add_references_item_validation(
      itemIndex, targetIsConstrained ? StatusCode{Status::BadReferenceNotAllowed} : StatusCode{});
    co_return;
  }

  // OPC 10000-4 section 5.7.3.2: the supplied targetNodeClass shall match the TargetNode, and
  // section 5.7.3.4 assigns Bad_NodeClassInvalid to the mismatch. Accepting a declaration the Server
  // can see is false leaves a Reference whose Browse result reports a NodeClass its target does not
  // have, which every client downstream reads as fact. Recorded here and applied at the end, so a
  // ReferenceType's own data-model rule answers first where it has one.
  if (item.target_node_class() != targetNode.value().get_node_class())
  {
    state.declaredClassVerdict[itemIndex] = StatusCode{Status::BadNodeClassInvalid};
  }

  if (item.reference_type_id() == NodeId{ReferenceTypeId::HasProperty})
  {
    const auto& property =
      item.is_forward() ? std::optional<NodeAccessor>{targetNode.value()} : state.resolvedSources[itemIndex];
    if (!property || property->get_node_class() != NodeClass::Variable)
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          ErrorDetail::build("ReferenceTypePropertyNotVariable",
            "The target of a HasProperty reference must be a Variable",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)});
      co_return;
    }
  }
  else if (item.reference_type_id() == NodeId{ReferenceTypeId::HasSubtype})
  {
    const auto& resolvedSource = state.resolvedSources[itemIndex];
    const auto sourceClass = resolvedSource ? resolvedSource->get_node_class() : NodeClass::Unspecified;
    const auto targetClass = targetNode.value().get_node_class();
    if (!is_type_node_class(sourceClass) || !is_type_node_class(targetClass) || sourceClass != targetClass)
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceNotAllowed,
          ErrorDetail::build("HasSubtypeNodeClassInvalid",
            "HasSubtype requires source and target Nodes of the same type NodeClass",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)
            .context(ContextKeys::typeActual, to_string(targetClass))
            .context(ContextKeys::typeExpected, to_string(sourceClass))});
      co_return;
    }
    const auto sourceType = resolvedSource ? resolvedSource->as<ReferenceTypeAccessor>() : std::nullopt;
    const auto targetType = targetNode.value().as<ReferenceTypeAccessor>();
    if (sourceType && targetType)
    {
      if (sourceType->get_symmetric() != targetType->get_symmetric())
      {
        finish_add_references_item_validation(itemIndex,
          StatusCode{Status::BadReferenceNotAllowed,
            ErrorDetail::build("ReferenceTypeSymmetryMismatch",
              "A ReferenceType subtype cannot change its supertype's Symmetric attribute",
              "NodeManagementService")
              .context(ContextKeys::operationIndex, itemIndex)});
        co_return;
      }

      const auto& subtype = item.is_forward() ? targetNode.value() : *resolvedSource;
      auto subtypeRefs = co_await await_step<Result<References>>(
        [&subtype](auto completion) { subtype.get_references_async(std::move(completion)); });

      if (!subtypeRefs.is_good())
      {
        finish_add_references_item_validation(itemIndex,
          StatusCode{Status::BadReferenceNotAllowed,
            make_error_detail("SubtypeReferencesUnavailable",
              "AddReferences could not inspect the candidate ReferenceType subtype",
              "NodeManagementService",
              server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
                subtypeRefs.status_code(),
                "NodeManagementService",
                subtype.get_node_id()))});
        co_return;
      }
      for (const auto& reference : subtypeRefs.value())
      {
        if (!reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasSubtype})
        {
          finish_add_references_item_validation(itemIndex,
            StatusCode{Status::BadReferenceNotAllowed,
              ErrorDetail::build("ReferenceTypeSecondSupertype",
                "A ReferenceType shall have exactly one supertype",
                "NodeManagementService")
                .context(ContextKeys::operationIndex, itemIndex)});
          co_return;
        }
      }
    }
  }

  // --- No Loops: a HasChild-derived Reference must not close a cycle ---------------------------
  auto isHasChild = co_await await_step<BoolResult>(
    [this, itemIndex](auto completion)
    {
      is_reference_type_or_subtype_async(mAddReferencesState->addressSpace,
        mAddReferencesRequest->references_to_add()[itemIndex].reference_type_id(),
        NodeId{ReferenceTypeId::HasChild},
        std::move(completion));
    });

  if (!isHasChild.is_good())
  {
    const StatusCode cause = isHasChild.status_code();
    if (cause.as_status() == Status::BadNodeIdUnknown ||
        cause.as_status() == Status::BadReferenceTypeIdInvalid)
    {
      finish_add_references_item_validation(itemIndex,
        StatusCode{Status::BadReferenceTypeIdInvalid,
          ErrorDetail::build("AddReferencesReferenceTypeInvalid",
            "The AddReferences referenceTypeId does not resolve to a ReferenceType Node",
            "NodeManagementService")
            .context(ContextKeys::operationIndex, itemIndex)
            .context(ContextKeys::nodeId, item.reference_type_id())
            .cause(cause)});
      co_return;
    }
    finish_add_references_item_validation(itemIndex,
      StatusCode{Status::BadReferenceNotAllowed,
        make_error_detail("NoLoopReferenceTypeHierarchyUnavailable",
          "AddReferences could not validate the ReferenceType's No Loops constraint",
          "NodeManagementService",
          cause)});
    co_return;
  }
  if (!isHasChild.value())
  {
    finish_add_references_item_validation(itemIndex);
    co_return;
  }

  const NodeId resultingSource = item.is_forward() ? item.source_node_id() : item.target_node_id().node_id();
  const NodeId resultingTarget = item.is_forward() ? item.target_node_id().node_id() : item.source_node_id();
  auto pathExists = co_await await_step<BoolResult>(
    [this, resultingSource, resultingTarget](auto completion)
    {
      has_child_path_async(
        mAddReferencesState->addressSpace, resultingTarget, resultingSource, std::move(completion));
    });

  if (!pathExists.is_good())
  {
    finish_add_references_item_validation(itemIndex,
      StatusCode{Status::BadReferenceNotAllowed,
        make_error_detail("NoLoopReachabilityUnavailable",
          "AddReferences could not validate the HasChild graph for a loop",
          "NodeManagementService",
          pathExists.status_code())});
    co_return;
  }
  if (pathExists.value())
  {
    finish_add_references_item_validation(itemIndex,
      StatusCode{Status::BadReferenceNotAllowed,
        ErrorDetail::build("ReferenceWouldCreateLoop",
          "The requested Reference would create a loop in the HasChild hierarchy",
          "NodeManagementService")
          .context(ContextKeys::operationIndex, itemIndex)});
    co_return;
  }
  finish_add_references_item_validation(itemIndex);
}

void NodeManagementService::finish_add_references_item_validation(size_t itemIndex, StatusCode status)
{
  if (!mAddReferencesState || itemIndex >= mAddReferencesState->authorized.size())
    return;
  auto& state = *mAddReferencesState;
  // An item the data-model checks passed still has to survive the declared-class comparison; one
  // they refused keeps their verdict, which is the more specific of the two.
  if (status.is_good() && itemIndex < state.declaredClassVerdict.size())
    status = state.declaredClassVerdict[itemIndex];
  state.authorized[itemIndex] = status.is_good();
  if (status.is_bad())
  {
    state.response->results()[itemIndex] = status;
    if (status.shared_detail())
      state.collector.add_item_detail(itemIndex, status.shared_detail());
  }
}

ua::async::Task<> NodeManagementService::call_add_references_delegate()
{
  auto& state = *mAddReferencesState;
  auto& items = mAddReferencesRequest->references_to_add();
  for (size_t i = 0; i < state.authorized.size(); ++i)
  {
    if (state.authorized[i])
    {
      state.authorizedItems.push_back(items[i]);
      state.authorizedIndices.push_back(i);
    }
  }

  if (state.authorizedItems.empty())
  {
    complete_add_references();
    co_return;
  }

  auto batch = co_await await_step<BatchResult<VoidResult>>(
    [this](auto completion)
    {
      auto& pending = *mAddReferencesState;
      mHandler->add_references_async(pending.handlerContext,
        pending.addressSpace,
        std::move(pending.authorizedItems),
        std::move(completion));
    });

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "NodeManagement/AddReferences: delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (auto idx : state.authorizedIndices)
    {
      state.response->results()[idx] = batchStatus;
      if (batchDetail)
      {
        state.collector.add_item_detail(idx, batchDetail);
      }
    }
  }
  else
  {
    auto& handlerResults = batch.items;
    for (size_t i = 0; i < state.authorizedIndices.size() && i < handlerResults.size(); ++i)
    {
      state.response->results()[state.authorizedIndices[i]] = handlerResults[i].status_code();
      if (handlerResults[i].is_bad() && handlerResults[i].error_detail())
      {
        state.collector.add_item_detail(state.authorizedIndices[i], handlerResults[i].shared_detail());
      }
    }
  }

  complete_add_references();
}

void NodeManagementService::complete_add_references()
{
  if (!try_finish())
  {
    mAddReferencesState.reset();
    return;
  }
  if (!mAddReferencesRequest)
    return;
  auto& request = *mAddReferencesRequest;
  auto& state = *mAddReferencesState;
  const size_t count = request.references_to_add().size();
  auto sessionInfo = mSessionInfo.lock();
  if (sessionInfo)
  {
    const bool allGood =
      std::ranges::all_of(state.response->results(), [](const auto& r) { return StatusCode{r}.is_good(); });
    AuditAddReferencesEventPayload auditEvent;
    fill_node_mgmt_audit_base(auditEvent,
      *sessionInfo,
      "NodeManagement/AddReferences",
      allGood,
      request.request_header().audit_entry_id());
    auditEvent.referencesToAdd =
      Variant{array_utils::copy_to_array_of_references(request.references_to_add())};
    emit_node_mgmt_audit(sessionInfo, auditEvent);
  }
  stack_utils::prepare_response_header(request.request_header(), state.response->response_header());
  state.collector.apply_to(state.response->response_header(), state.response->diagnostic_infos(), count);
  auto response = state.response;
  mAddReferencesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, response));
}

void NodeManagementService::fail_add_references(VoidResult error)
{
  if (!try_finish())
  {
    mAddReferencesState.reset();
    return;
  }
  if (!mAddReferencesRequest)
    return;
  auto& request = *mAddReferencesRequest;
  auto& state = *mAddReferencesState;
  state.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&request.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  state.collector.apply_to(serviceFault->response_header(), unused, 0);
  mAddReferencesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
}

// =============================================================================================
// DeleteNodes flow
// =============================================================================================

void NodeManagementService::start_delete_nodes()
{
  // Engaged by the DeleteNodes constructor; begin_processing only dispatches here when it is set.
  if (!mDeleteNodesRequest)
    return;
  auto& request = *mDeleteNodesRequest;
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{request.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw_null_pointer_check(Status::BadInvalidArgument);
    }
    set_timeout();

    auto& items = request.nodes_to_delete();
    const size_t count = items.size();

    if (count == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail(
          "EmptyDeleteNodesRequest", "DeleteNodes request contains no items", "NodeManagementService")};
    }

    auto& limit =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerNodeManagement;
    if (limit && count > limit.value())
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyNodesToDelete",
          "Requested item count exceeds the server operation limit",
          "NodeManagementService")
          .context(ua::ContextKeys::sizeActual, std::to_string(count))
          .context(ua::ContextKeys::sizeMax, std::to_string(limit.value()))};
    }

    const auto* sec = dynamic_cast<const SessionSecurityContext*>(sessionInfo.get());
    auto addressSpace = sessionInfo->address_space();

    auto response = std::make_shared<DeleteNodesResponse>();
    response->results().resize(count);

    mDeleteNodesState =
      std::make_unique<DeleteNodesState>(std::move(addressSpace), response, std::move(collector));
    mDeleteNodesState->accessControl = SessionAccessControl::create(*sessionInfo);
    mDeleteNodesState->authorized.assign(count, false);

    auto handlerContext = std::make_shared<NodeManagementDelegate::Context>();
    if (sec)
    {
      handlerContext->userIdentity = sec->user_identity();
      handlerContext->endpointSecurity = sec->endpoint_security();
    }
    handlerContext->cancelled = mCancelled;
    mDeleteNodesState->handlerContext = std::move(handlerContext);

    mDeleteNodesTask = run_delete_nodes();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "NodeManagementService", er);
    }
    if (mDeleteNodesState)
    {
      fail_delete_nodes(VoidResult{er, er.shared_detail()});
    }
    else
    {
      send_service_fault(request.request_header(), er);
    }
  }
}

ua::async::Task<> NodeManagementService::run_delete_nodes()
{
  try
  {
    auto& state = *mDeleteNodesState;

    if (!state.accessControl)
    {
      // No access control means no session to ask, so nothing is deletable. The delegate is still
      // called - with nothing - so the answer takes the same shape as every other.
      for (auto& result : state.response->results())
      {
        result = Status::BadUserAccessDenied;
      }
    }
    else
    {
      // Every item is decided independently. The units are spawned eagerly - a Task starts on
      // construction - into a vector local to THIS frame, so awaiting them is the barrier: nothing
      // has to count anything down, and nothing outlives the request that owns the vector.
      std::vector<ua::async::Task<>> units;
      units.reserve(state.authorized.size());
      for (size_t i = 0; i < state.authorized.size(); ++i)
      {
        units.push_back(delete_nodes_unit(i));
      }
      for (auto& unit : units)
      {
        co_await std::move(unit);
      }
    }

    co_await call_delete_nodes_delegate();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    const auto er = ua::exception_to_status_code(std::current_exception());
    if (mDeleteNodesState)
    {
      fail_delete_nodes(VoidResult{er, er.shared_detail()});
    }
  }
  co_return;
}

ua::async::Task<> NodeManagementService::delete_nodes_unit(size_t itemIndex)
{
  auto& state = *mDeleteNodesState;

  auto findResult = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      auto authzNodeId =
        item_authz_node(mDeleteNodesRequest->nodes_to_delete()[itemIndex], AccessOperation::DeleteNodes);
      mDeleteNodesState->addressSpace.find_node_async(authzNodeId, std::move(completion));
    });

  if (!findResult.is_good() && !findResult.is_bad())
  {
    // An Uncertain answer, with or without the Node, is refused: the SDK does not delete a Node the namespace
    // is uncertain of.
    const StatusCode refused = ::ua::detail::lookup_failure(
      item_authz_node(mDeleteNodesRequest->nodes_to_delete()[itemIndex], AccessOperation::DeleteNodes),
      findResult.status_code(),
      "NodeManagementService");
    state.response->results()[itemIndex] = refused;
    state.collector.add_item_detail(itemIndex, refused.shared_detail());
    state.authorized[itemIndex] = false;
    co_return;
  }
  if (findResult.is_bad())
  {
    // Spec: a null NodeId on DeleteNodes returns BadNodeIdInvalid (structurally invalid);
    // a non-null NodeId that does not resolve keeps BadNodeIdUnknown (Part 4 5.7.4).
    auto status = findResult.status_code();
    if (mDeleteNodesRequest->nodes_to_delete()[itemIndex].node_id().is_null())
    {
      status = StatusCode{Status::BadNodeIdInvalid};
    }
    state.response->results()[itemIndex] = status;
    if (findResult.shared_detail())
    {
      state.collector.add_item_detail(itemIndex, findResult.shared_detail());
    }
    state.authorized[itemIndex] = false;
    co_return;
  }

  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
    [this, node = findResult.value()](auto completion) mutable
    {
      const std::array items{AccessControl::Item{.node = node, .operation = AccessOperation::DeleteNodes}};
      mDeleteNodesState->accessControl->authorize_async(RequestInfo{}, items, std::move(completion));
    });

  // SVR-AUTHZ-015: one verdict per item, decided by the shared rule like the other three services.
  const auto denial = detail::first_denial(verdicts, 1);
  state.authorized[itemIndex] = !denial.has_value();
  if (denial)
  {
    state.response->results()[itemIndex] = *denial;
    if (auto detail = denial->shared_detail())
    {
      state.collector.add_item_detail(itemIndex, std::move(detail));
    }
  }
  co_return;
}

ua::async::Task<> NodeManagementService::call_delete_nodes_delegate()
{
  auto& state = *mDeleteNodesState;
  auto& items = mDeleteNodesRequest->nodes_to_delete();
  for (size_t i = 0; i < state.authorized.size(); ++i)
  {
    if (state.authorized[i])
    {
      state.authorizedItems.push_back(items[i]);
      state.authorizedIndices.push_back(i);
    }
  }

  if (state.authorizedItems.empty())
  {
    complete_delete_nodes();
    co_return;
  }

  auto batch = co_await await_step<BatchResult<VoidResult>>(
    [this](auto completion)
    {
      auto& pending = *mDeleteNodesState;
      mHandler->delete_nodes_async(pending.handlerContext,
        pending.addressSpace,
        std::move(pending.authorizedItems),
        std::move(completion));
    });

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "NodeManagement/DeleteNodes: delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (auto idx : state.authorizedIndices)
    {
      state.response->results()[idx] = batchStatus;
      if (batchDetail)
      {
        state.collector.add_item_detail(idx, batchDetail);
      }
    }
  }
  else
  {
    auto& handlerResults = batch.items;
    for (size_t i = 0; i < state.authorizedIndices.size() && i < handlerResults.size(); ++i)
    {
      state.response->results()[state.authorizedIndices[i]] = handlerResults[i].status_code();
      if (handlerResults[i].is_bad() && handlerResults[i].error_detail())
      {
        state.collector.add_item_detail(state.authorizedIndices[i], handlerResults[i].shared_detail());
      }
    }
  }

  complete_delete_nodes();
}

void NodeManagementService::complete_delete_nodes()
{
  if (!try_finish())
  {
    mDeleteNodesState.reset();
    return;
  }
  if (!mDeleteNodesRequest)
    return;
  auto& request = *mDeleteNodesRequest;
  auto& state = *mDeleteNodesState;
  const size_t count = request.nodes_to_delete().size();
  auto sessionInfo = mSessionInfo.lock();
  if (sessionInfo)
  {
    // Part 5 6.4.3: whether the action could be performed. An item answered Uncertain_ReferenceNotDeleted
    // deleted its Node; only a Bad item was not performed.
    const bool performed =
      std::ranges::none_of(state.response->results(), [](const auto& r) { return StatusCode{r}.is_bad(); });
    AuditDeleteNodesEventPayload auditEvent;
    fill_node_mgmt_audit_base(auditEvent,
      *sessionInfo,
      "NodeManagement/DeleteNodes",
      performed,
      request.request_header().audit_entry_id());
    auditEvent.nodesToDelete = Variant{array_utils::copy_to_array_of_references(request.nodes_to_delete())};
    emit_node_mgmt_audit(sessionInfo, auditEvent);
  }
  stack_utils::prepare_response_header(request.request_header(), state.response->response_header());
  state.collector.apply_to(state.response->response_header(), state.response->diagnostic_infos(), count);
  auto response = state.response;
  mDeleteNodesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, response));
}

void NodeManagementService::fail_delete_nodes(VoidResult error)
{
  if (!try_finish())
  {
    mDeleteNodesState.reset();
    return;
  }
  if (!mDeleteNodesRequest)
    return;
  auto& request = *mDeleteNodesRequest;
  auto& state = *mDeleteNodesState;
  state.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&request.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  state.collector.apply_to(serviceFault->response_header(), unused, 0);
  mDeleteNodesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
}

// =============================================================================================
// DeleteReferences flow
// =============================================================================================

void NodeManagementService::start_delete_references()
{
  // Engaged by the DeleteReferences constructor; begin_processing only dispatches here when it is set.
  if (!mDeleteReferencesRequest)
    return;
  auto& request = *mDeleteReferencesRequest;
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{request.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw_null_pointer_check(Status::BadInvalidArgument);
    }
    set_timeout();

    auto& items = request.references_to_delete();
    const size_t count = items.size();

    if (count == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail("EmptyDeleteReferencesRequest",
          "DeleteReferences request contains no items",
          "NodeManagementService")};
    }

    auto& limit =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerNodeManagement;
    if (limit && count > limit.value())
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyReferencesToDelete",
          "Requested item count exceeds the server operation limit",
          "NodeManagementService")
          .context(ua::ContextKeys::sizeActual, std::to_string(count))
          .context(ua::ContextKeys::sizeMax, std::to_string(limit.value()))};
    }

    const auto* sec = dynamic_cast<const SessionSecurityContext*>(sessionInfo.get());
    auto addressSpace = sessionInfo->address_space();

    auto response = std::make_shared<DeleteReferencesResponse>();
    response->results().resize(count);

    mDeleteReferencesState =
      std::make_unique<DeleteReferencesState>(std::move(addressSpace), response, std::move(collector));
    mDeleteReferencesState->accessControl = SessionAccessControl::create(*sessionInfo);
    mDeleteReferencesState->authorized.assign(count, false);

    auto handlerContext = std::make_shared<NodeManagementDelegate::Context>();
    if (sec)
    {
      handlerContext->userIdentity = sec->user_identity();
      handlerContext->endpointSecurity = sec->endpoint_security();
    }
    handlerContext->cancelled = mCancelled;
    mDeleteReferencesState->handlerContext = std::move(handlerContext);

    mDeleteReferencesTask = run_delete_references();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "NodeManagementService", er);
    }
    if (mDeleteReferencesState)
    {
      fail_delete_references(VoidResult{er, er.shared_detail()});
    }
    else
    {
      send_service_fault(request.request_header(), er);
    }
  }
}

ua::async::Task<> NodeManagementService::run_delete_references()
{
  try
  {
    auto& state = *mDeleteReferencesState;
    auto& items = mDeleteReferencesRequest->references_to_delete();

    if (!state.accessControl)
    {
      for (auto& result : state.response->results())
      {
        result = Status::BadUserAccessDenied;
      }
    }
    else
    {
      // The two structural screens are decided here, without asking the address space anything: an
      // item that names another server, or no target at all, is answered on the spot and never
      // becomes a unit. The chain did the same, and counted only the survivors.
      std::vector<ua::async::Task<>> units;
      units.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        const auto& target = items[i].target_node_id();
        if (target.server_index() != 0)
        {
          std::shared_ptr<const ErrorDetail> detail =
            ErrorDetail::build("DeleteReferencesServerIndexInvalid",
              "DeleteReferences target names a server index this server cannot resolve",
              "NodeManagementService")
              .context(ua::ContextKeys::operationIndex, std::to_string(i))
              .context(ua::ContextKeys::index, std::to_string(target.server_index()));
          state.response->results()[i] = StatusCode{Status::BadServerIndexInvalid, detail};
          state.collector.add_item_detail(i, detail);
          continue;
        }
        if (target.node_id().is_null())
        {
          std::shared_ptr<const ErrorDetail> detail =
            ErrorDetail::build("DeleteReferencesTargetNodeIdInvalid",
              "DeleteReferences target NodeId is null",
              "NodeManagementService")
              .context(ua::ContextKeys::operationIndex, std::to_string(i));
          state.response->results()[i] = StatusCode{Status::BadTargetNodeIdInvalid, detail};
          state.collector.add_item_detail(i, detail);
          continue;
        }
        units.push_back(delete_references_unit(i));
      }
      for (auto& unit : units)
      {
        co_await std::move(unit);
      }
    }

    co_await call_delete_references_delegate();
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    const auto er = ua::exception_to_status_code(std::current_exception());
    if (mDeleteReferencesState)
    {
      fail_delete_references(VoidResult{er, er.shared_detail()});
    }
  }
  co_return;
}

ua::async::Task<> NodeManagementService::delete_references_unit(size_t itemIndex)
{
  auto& state = *mDeleteReferencesState;
  const auto& item = mDeleteReferencesRequest->references_to_delete()[itemIndex];

  auto refTypeNode = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      mDeleteReferencesState->addressSpace.find_node_async(
        mDeleteReferencesRequest->references_to_delete()[itemIndex].reference_type_id(),
        std::move(completion));
    });

  if (!refTypeNode.is_good() && refTypeNode.status_code().as_status() != Status::BadNodeIdUnknown)
  {
    // A Bad answer is the item's; an Uncertain one, with or without the Node, is refused.
    const StatusCode failed = ::ua::detail::lookup_failure(
      item.reference_type_id(), refTypeNode.status_code(), "NodeManagementService");
    state.response->results()[itemIndex] = failed;
    if (failed.shared_detail())
    {
      state.collector.add_item_detail(itemIndex, failed.shared_detail());
    }
    co_return;
  }

  if (refTypeNode.is_bad() || refTypeNode.value().get_node_class() != NodeClass::ReferenceType)
  {
    std::shared_ptr<const ErrorDetail> detail;
    if (refTypeNode.is_bad())
    {
      detail = ErrorDetail::build("DeleteReferencesReferenceTypeInvalid",
        "DeleteReferences referenceTypeId does not identify a ReferenceType Node",
        "NodeManagementService")
                 .context(ua::ContextKeys::operationIndex, itemIndex)
                 .context(ua::ContextKeys::nodeId, item.reference_type_id())
                 .cause(refTypeNode.status_code());
    }
    else
    {
      detail = ErrorDetail::build("DeleteReferencesReferenceTypeInvalid",
        "DeleteReferences referenceTypeId does not identify a ReferenceType Node",
        "NodeManagementService")
                 .context(ua::ContextKeys::operationIndex, itemIndex)
                 .context(ua::ContextKeys::nodeId, item.reference_type_id());
    }
    state.response->results()[itemIndex] = StatusCode{Status::BadReferenceTypeIdInvalid, detail};
    state.collector.add_item_detail(itemIndex, detail);
    co_return;
  }

  auto targetNode = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      mDeleteReferencesState->addressSpace.find_node_async(
        mDeleteReferencesRequest->references_to_delete()[itemIndex].target_node_id().node_id(),
        std::move(completion));
    });

  if (!targetNode.is_good() && !targetNode.is_bad())
  {
    // An Uncertain answer, with or without the target, is refused.
    const StatusCode refused = ::ua::detail::lookup_failure(
      item.target_node_id().node_id(), targetNode.status_code(), "NodeManagementService");
    state.response->results()[itemIndex] = refused;
    state.collector.add_item_detail(itemIndex, refused.shared_detail());
    co_return;
  }
  if (targetNode.is_bad())
  {
    std::shared_ptr<const ErrorDetail> detail =
      ErrorDetail::build("DeleteReferencesTargetNodeIdInvalid",
        "DeleteReferences target NodeId does not identify a local node",
        "NodeManagementService")
        .context(ua::ContextKeys::operationIndex, std::to_string(itemIndex))
        .context(ua::ContextKeys::nodeId, ua::to_string(item.target_node_id().node_id()))
        .cause(targetNode.status_code());
    state.response->results()[itemIndex] = StatusCode{Status::BadTargetNodeIdInvalid, detail};
    state.collector.add_item_detail(itemIndex, detail);
    co_return;
  }

  auto sourceNode = co_await await_step<NodeAccessorResult>(
    [this, itemIndex](auto completion)
    {
      const auto sourceNodeId = item_authz_node(
        mDeleteReferencesRequest->references_to_delete()[itemIndex], AccessOperation::DeleteReferences);
      mDeleteReferencesState->addressSpace.find_node_async(sourceNodeId, std::move(completion));
    });

  if (!sourceNode.is_good())
  {
    // Spec: a missing source for DeleteReferences returns BadSourceNodeIdInvalid, not the generic
    // BadNodeIdUnknown surfaced by the address-space lookup (Part 4 5.7.5). An Uncertain answer, with or
    // without the source, is refused.
    auto status = ::ua::detail::lookup_failure(item_authz_node(item, AccessOperation::DeleteReferences),
      sourceNode.status_code(),
      "NodeManagementService");
    // The lookup's detail (or the refusal's) stays in the operation's diagnostics when the code is replaced.
    const auto detail = status.shared_detail();
    if (status.as_status() == Status::BadNodeIdUnknown)
    {
      status = StatusCode{Status::BadSourceNodeIdInvalid};
    }
    state.response->results()[itemIndex] = status;
    if (detail)
    {
      state.collector.add_item_detail(itemIndex, detail);
    }
    state.authorized[itemIndex] = false;
    co_return;
  }

  // SVR-AUTHZ-007 (SVC-6): a bidirectional delete removes the inverse Reference from the target, and an
  // inverse item removes the target's forward Reference, so the (local, already resolved) target needs
  // RemoveReference too. Both Nodes are decided in one authorization (two items at most).
  std::vector<AccessControl::Item> items;
  items.push_back(
    AccessControl::Item{.node = sourceNode.value(), .operation = AccessOperation::DeleteReferences});
  if (item.delete_bidirectional() || !item.is_forward())
  {
    items.push_back(
      AccessControl::Item{.node = targetNode.value(), .operation = AccessOperation::DeleteReferences});
  }
  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &items](auto completion)
    { mDeleteReferencesState->accessControl->authorize_async(RequestInfo{}, items, std::move(completion)); });
  const auto denial = detail::first_denial(verdicts, items.size());
  state.authorized[itemIndex] = !denial.has_value();
  if (denial)
  {
    state.response->results()[itemIndex] = *denial;
    if (auto detail = denial->shared_detail())
    {
      state.collector.add_item_detail(itemIndex, std::move(detail));
    }
  }
  co_return;
}

ua::async::Task<> NodeManagementService::call_delete_references_delegate()
{
  auto& state = *mDeleteReferencesState;
  auto& items = mDeleteReferencesRequest->references_to_delete();
  for (size_t i = 0; i < state.authorized.size(); ++i)
  {
    if (state.authorized[i])
    {
      state.authorizedItems.push_back(items[i]);
      state.authorizedIndices.push_back(i);
    }
  }

  if (state.authorizedItems.empty())
  {
    complete_delete_references();
    co_return;
  }

  auto batch = co_await await_step<BatchResult<VoidResult>>(
    [this](auto completion)
    {
      auto& pending = *mDeleteReferencesState;
      mHandler->delete_references_async(pending.handlerContext,
        pending.addressSpace,
        std::move(pending.authorizedItems),
        std::move(completion));
    });

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "NodeManagement/DeleteReferences: delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (auto idx : state.authorizedIndices)
    {
      state.response->results()[idx] = batchStatus;
      if (batchDetail)
      {
        state.collector.add_item_detail(idx, batchDetail);
      }
    }
  }
  else
  {
    auto& handlerResults = batch.items;
    for (size_t i = 0; i < state.authorizedIndices.size() && i < handlerResults.size(); ++i)
    {
      state.response->results()[state.authorizedIndices[i]] = handlerResults[i].status_code();
      if (handlerResults[i].is_bad() && handlerResults[i].error_detail())
      {
        state.collector.add_item_detail(state.authorizedIndices[i], handlerResults[i].shared_detail());
      }
    }
  }

  complete_delete_references();
}

void NodeManagementService::complete_delete_references()
{
  if (!try_finish())
  {
    mDeleteReferencesState.reset();
    return;
  }
  if (!mDeleteReferencesRequest)
    return;
  auto& request = *mDeleteReferencesRequest;
  auto& state = *mDeleteReferencesState;
  const size_t count = request.references_to_delete().size();
  auto sessionInfo = mSessionInfo.lock();
  if (sessionInfo)
  {
    const bool allGood =
      std::ranges::all_of(state.response->results(), [](const auto& r) { return StatusCode{r}.is_good(); });
    AuditDeleteReferencesEventPayload auditEvent;
    fill_node_mgmt_audit_base(auditEvent,
      *sessionInfo,
      "NodeManagement/DeleteReferences",
      allGood,
      request.request_header().audit_entry_id());
    auditEvent.referencesToDelete =
      Variant{array_utils::copy_to_array_of_references(request.references_to_delete())};
    emit_node_mgmt_audit(sessionInfo, auditEvent);
  }
  stack_utils::prepare_response_header(request.request_header(), state.response->response_header());
  state.collector.apply_to(state.response->response_header(), state.response->diagnostic_infos(), count);
  auto response = state.response;
  mDeleteReferencesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, response));
}

void NodeManagementService::fail_delete_references(VoidResult error)
{
  if (!try_finish())
  {
    mDeleteReferencesState.reset();
    return;
  }
  if (!mDeleteReferencesRequest)
    return;
  auto& request = *mDeleteReferencesRequest;
  auto& state = *mDeleteReferencesState;
  state.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&request.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  state.collector.apply_to(serviceFault->response_header(), unused, 0);
  mDeleteReferencesState.reset();
  mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
}

// --- Common -----------------------------------------------------------------

void NodeManagementService::cancel()
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [](NodeManagementService& self)
    {
      self.mCancelled->store(true);
      // Pre-flip behaviour: just signal cancellation; the running operation completes normally.
      // We do not reset any flow here.
    })();
}

void NodeManagementService::abort(StatusCode reason)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](NodeManagementService& self) mutable
    {
      self.mCancelled->store(true);
      // Unlike a Cancel, which lets the operation answer with what it changed, the call answers now; the
      // operation's later answer is dropped by try_finish.
      const RequestHeader* header = nullptr;
      if (self.mAddNodesRequest)
        header = &self.mAddNodesRequest->request_header();
      else if (self.mAddReferencesRequest)
        header = &self.mAddReferencesRequest->request_header();
      else if (self.mDeleteNodesRequest)
        header = &self.mDeleteNodesRequest->request_header();
      else if (self.mDeleteReferencesRequest)
        header = &self.mDeleteReferencesRequest->request_header();
      if (header)
        self.send_service_fault(*header, reason);
    })();
}

void NodeManagementService::set_timeout()
{
  if (mAddNodesRequest)
    ServiceBase::set_timeout(mAddNodesRequest->request_header().timeout_hint());
  else if (mAddReferencesRequest)
    ServiceBase::set_timeout(mAddReferencesRequest->request_header().timeout_hint());
  else if (mDeleteNodesRequest)
    ServiceBase::set_timeout(mDeleteNodesRequest->request_header().timeout_hint());
  else if (mDeleteReferencesRequest)
    ServiceBase::set_timeout(mDeleteReferencesRequest->request_header().timeout_hint());
}

void NodeManagementService::timeout()
{
  ServiceFault serviceFault;
  serviceFault.response_header().service_result() = Status::BadTimeout;
  finish(std::make_pair(mRequestId, std::make_shared<ServiceFault>(std::move(serviceFault))));
}

void NodeManagementService::finish(Response response)
{
  if (!try_finish())
    return;

  mServiceCallCompleteCallback(std::move(response));
}

void NodeManagementService::send_service_fault(const RequestHeader& requestHeader, StatusCode status)
{
  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  finish(std::make_pair(mRequestId, serviceFault));
}

}  // namespace ua::server
