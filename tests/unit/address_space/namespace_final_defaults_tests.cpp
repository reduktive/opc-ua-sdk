// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-NAMESPACE-INTERFACE-08: the defaults of the Namespace members a namespace need not override,
// observed on stub namespaces that override only the required members.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_namespace_authorization.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_role_permission_type.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

using namespace ua;

namespace
{

// Counts a completion's invocations and keeps the arguments of the first.
template<typename... Args>
class Completion
{
public:
  std::function<void(Args...)> callback()
  {
    return [state = mState](Args... args)
    {
      const std::lock_guard lock{state->mutex};
      ++state->count;
      if (!state->first)
      {
        state->first.emplace(std::move(args)...);
      }
      state->ready.notify_all();
    };
  }

  bool wait()
  {
    std::unique_lock lock{mState->mutex};
    return mState->ready.wait_for(
      lock, ::ua::test_utils::default_poll_budget(), [this] { return mState->count > 0; });
  }

  int count() const
  {
    const std::lock_guard lock{mState->mutex};
    return mState->count;
  }

  template<size_t Index>
  auto& get()
  {
    return std::get<Index>(*mState->first);
  }

private:
  struct State
  {
    std::mutex mutex;
    std::condition_variable ready;
    int count{0};
    std::optional<std::tuple<std::decay_t<Args>...>> first;
  };

  std::shared_ptr<State> mState = std::make_shared<State>();
};

// A Node that serves one description.
class DescribedNode final : public Node
{
public:
  explicit DescribedNode(NodeDescription description) : mDescription(std::move(description))
  {}

  NodeDescription attributes() const override
  {
    return mDescription;
  }

private:
  NodeDescription mDescription;
};

// A namespace that overrides only the required members: it holds Nodes and their References in maps, and
// every other member answers through its default.
class RequiredMembersNamespace : public Namespace
{
public:
  String uri() const override
  {
    return String{"urn:test:required-members"};
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      answer.items.push_back(held(nodeId));
    }
    complete(std::move(answer));
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    const std::lock_guard lock{mMutex};
    for (const auto& query : queries)
    {
      const auto found = mReferences.find(query.nodeId);
      answer.items.emplace_back(NodeReferences{
        References{found == mReferences.end() ? std::vector<Reference>{} : found->second}, ByteString{}});
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answer.items.emplace_back(StatusCode{Status::BadNotReadable});
    }
    complete(std::move(answer));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return mDefaultRolePermissions;
  }

  shared_ptr<Node> hold(NodeDescription description)
  {
    auto node = std::make_shared<DescribedNode>(description);
    const std::lock_guard lock{mMutex};
    mNodes[description.node_id()] = node;
    return node;
  }

  void hold_references(const NodeId& nodeId, std::vector<Reference> references)
  {
    const std::lock_guard lock{mMutex};
    mReferences[nodeId] = std::move(references);
  }

  void set_default_role_permissions(std::optional<std::vector<RolePermissionType>> permissions)
  {
    mDefaultRolePermissions = std::move(permissions);
  }

protected:
  NodeResult held(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mMutex};
    if (const auto found = mNodes.find(nodeId); found != mNodes.end())
    {
      return NodeResult{found->second};
    }
    return NodeResult{StatusCode{Status::BadNodeIdUnknown}};
  }

private:
  mutable std::mutex mMutex;
  std::map<NodeId, shared_ptr<Node>> mNodes;
  std::map<NodeId, std::vector<Reference>> mReferences;
  std::optional<std::vector<RolePermissionType>> mDefaultRolePermissions{std::vector<RolePermissionType>{}};
};

// The same namespace answering the immediate lookup as well, which effective_permissions_async's default
// looks each Node subject up with.
class ImmediateLookupNamespace : public RequiredMembersNamespace
{
public:
  using Namespace::find_node;

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration>) override
  {
    return held(nodeId);
  }
};

bool is_node(const Node& node, const NodeId& nodeId)
{
  const NodeDescription description = node.attributes();
  return description.node_id() == nodeId;
}

// Declines the immediate effective_permissions for one Node, and evaluates the Role model for every other
// subject.
class DecliningPermissionsNamespace final : public ImmediateLookupNamespace
{
public:
  using ImmediateLookupNamespace::effective_permissions;

  explicit DecliningPermissionsNamespace(NodeId declinedFor) : mDeclinedFor{std::move(declinedFor)}
  {}

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override
  {
    if (node != nullptr && is_node(*node, mDeclinedFor))
    {
      return std::nullopt;
    }
    return ImmediateLookupNamespace::effective_permissions(identity, node);
  }

private:
  NodeId mDeclinedFor;
};

// Throws from the immediate effective_permissions for one Node, and evaluates the Role model for every other
// subject.
class ThrowingPermissionsNamespace final : public ImmediateLookupNamespace
{
public:
  using ImmediateLookupNamespace::effective_permissions;

  explicit ThrowingPermissionsNamespace(NodeId throwsFor) : mThrowsFor{std::move(throwsFor)}
  {}

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override
  {
    if (node != nullptr && is_node(*node, mThrowsFor))
    {
      throw UaException{StatusCode{Status::BadResourceUnavailable,
        ErrorDetail::build("ScriptedPermissionsThrew", "The stub's evaluation throws", "Test")}};
    }
    return ImmediateLookupNamespace::effective_permissions(identity, node);
  }

private:
  NodeId mThrowsFor;
};

NodeDescription object_named(const NodeId& nodeId)
{
  return NodeDescription::object(nodeId, QualifiedName{nodeId.namespace_index(), "Object"});
}

NodeDescription variable_named(const NodeId& nodeId)
{
  return NodeDescription::variable(
    nodeId, QualifiedName{nodeId.namespace_index(), "Variable"}, NodeId{0, uint32_t{6}});
}

RolePermissionType grant_of(const NodeId& role, std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType grant;
  grant.role_id() = role;
  grant.permissions() = PermissionType{bits};
  return grant;
}

WriteValue display_name_write(const NodeId& nodeId, const char* text)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  write.value() = DataValue{Variant{LocalizedText{LocaleId{"en"}, String{text}}}};
  return write;
}

CallMethodRequest call_of(const NodeId& objectId, const NodeId& methodId)
{
  CallMethodRequest request;
  request.object_id() = objectId;
  request.method_id() = methodId;
  return request;
}

}  // namespace

// NR-24 rule 2 and NR-68 item 5: the final default accepts every update for the Role model and answers
// Bad_NotSupported, with an ErrorDetail, for each update when default_role_permissions() is disengaged.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-ROLE-PERMISSIONS-VALIDATION-DEFAULT, scope=function)
TEST(NamespaceDefaults, RolePermissionsValidationAcceptsForTheRoleModelAndRefusesWithoutIt)
{
  RequiredMembersNamespace roleModel;
  RequiredMembersNamespace vendorModel;
  vendorModel.set_default_role_permissions(std::nullopt);
  RolePermissionType grant;
  grant.role_id() = NodeId{1, uint32_t{9001}};
  grant.permissions() = PermissionType{PermissionType::Bit::Browse};
  const std::vector<RolePermissionsUpdate> updates{
    {NodeId{2, uint32_t{1}}, std::vector<RolePermissionType>{grant}}, {NodeId{2, uint32_t{2}}, std::nullopt}};

  Completion<BatchResult<VoidResult>> accepted;
  roleModel.validate_role_permissions_updates_async(RequestInfo{}, updates, accepted.callback());
  ASSERT_TRUE(accepted.wait());
  ASSERT_EQ(accepted.get<0>().items.size(), 2u);
  for (const auto& item : accepted.get<0>().items)
  {
    EXPECT_TRUE(item.is_good()) << to_string(item.status_code());
  }
  EXPECT_EQ(accepted.count(), 1);

  // Without the Role model every update is refused, the one naming no Node included: the model is what the
  // namespace lacks, whatever the update names.
  std::vector<RolePermissionsUpdate> vendorUpdates = updates;
  vendorUpdates.push_back({NodeId{}, std::vector<RolePermissionType>{grant}});
  Completion<BatchResult<VoidResult>> refused;
  vendorModel.validate_role_permissions_updates_async(RequestInfo{}, vendorUpdates, refused.callback());
  ASSERT_TRUE(refused.wait());
  ASSERT_EQ(refused.get<0>().items.size(), 3u);
  for (size_t index = 0; index < refused.get<0>().items.size(); ++index)
  {
    const auto& item = refused.get<0>().items[index];
    EXPECT_EQ(item.status_code().as_status(), Status::BadNotSupported)
      << "update " << index << ": " << to_string(item.status_code());
    EXPECT_NE(item.shared_detail(), nullptr) << "update " << index;
  }
  EXPECT_EQ(refused.count(), 1);
}

// NR-68 item 9 and the documentation of both members: the immediate form taking a Node and the asynchronous
// form taking a RequestInfo answer the Role-model evaluation; an engaged empty NodeId list is
// Bad_InvalidArgument; a subject the immediate form declines is Bad_NotSupported naming that cause.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-EFFECTIVE-PERMISSIONS-NEW-FORMS, scope=function)
TEST(NamespaceDefaults, EffectivePermissionsTakeTheRequestAndANode)
{
  const NodeId role{1, uint32_t{9001}};
  const std::vector<RolePermissionType> browseOnly{grant_of(role, {PermissionType::Bit::Browse})};
  const std::vector<RolePermissionType> browseAndReadGrant{
    grant_of(role, {PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  ImmediateLookupNamespace space;
  space.set_default_role_permissions(browseOnly);
  const NodeId n1Id{2, uint32_t{1}};
  const NodeId n2Id{2, uint32_t{2}};
  const auto n1 = space.hold(object_named(n1Id).with_role_permissions(browseAndReadGrant));
  const auto n2 = space.hold(object_named(n2Id));
  const auto identity = std::make_shared<const AccessIdentity>(
    AccessIdentityKey{1}, std::vector<NodeId>{role}, nullptr, nullptr, String{""});
  const PermissionType browse{PermissionType::Bit::Browse};
  const PermissionType browseAndRead{PermissionType::Bit::Browse, PermissionType::Bit::Read};

  EXPECT_EQ(space.effective_permissions(*identity, n1.get()), std::optional<PermissionType>{browseAndRead});
  EXPECT_EQ(space.effective_permissions(*identity, n2.get()), std::optional<PermissionType>{browse});
  EXPECT_EQ(space.effective_permissions(*identity, static_cast<const Node*>(nullptr)),
    std::optional<PermissionType>{browse});

  Completion<EffectivePermissionsResult> forNodes;
  space.effective_permissions_async(
    RequestInfo{}, identity, std::vector<NodeId>{n1Id, n2Id}, forNodes.callback());
  ASSERT_TRUE(forNodes.wait());
  const auto& answer = forNodes.get<0>();
  ASSERT_EQ(answer.items.size(), 2u) << to_string(answer.batchStatus.status_code());
  ASSERT_TRUE(answer.items[0].is_good()) << to_string(answer.items[0].status_code());
  EXPECT_EQ(answer.items[0].value(), browseAndRead);
  ASSERT_TRUE(answer.items[1].is_good()) << to_string(answer.items[1].status_code());
  EXPECT_EQ(answer.items[1].value(), browse);

  Completion<EffectivePermissionsResult> empty;
  space.effective_permissions_async(RequestInfo{}, identity, std::vector<NodeId>{}, empty.callback());
  ASSERT_TRUE(empty.wait());
  EXPECT_EQ(empty.get<0>().batchStatus.status_code().as_status(), Status::BadInvalidArgument)
    << to_string(empty.get<0>().batchStatus.status_code());
  EXPECT_EQ(empty.count(), 1);

  // A namespace that declines the immediate form for N3: N3 alone is refused, naming the declined answer.
  const NodeId n3Id{2, uint32_t{3}};
  const NodeId n4Id{2, uint32_t{4}};
  DecliningPermissionsNamespace declining{n3Id};
  declining.set_default_role_permissions(browseOnly);
  declining.hold(object_named(n3Id).with_role_permissions(browseAndReadGrant));
  declining.hold(object_named(n4Id));
  Completion<EffectivePermissionsResult> declined;
  declining.effective_permissions_async(
    RequestInfo{}, identity, std::vector<NodeId>{n3Id, n4Id}, declined.callback());
  ASSERT_TRUE(declined.wait());
  EXPECT_EQ(declined.count(), 1);
  const auto& declinedAnswer = declined.get<0>();
  ASSERT_EQ(declinedAnswer.items.size(), 2u) << to_string(declinedAnswer.batchStatus.status_code());
  EXPECT_EQ(declinedAnswer.items[0].status_code().as_status(), Status::BadNotSupported)
    << to_string(declinedAnswer.items[0].status_code());
  ASSERT_NE(declinedAnswer.items[0].shared_detail(), nullptr);
  EXPECT_EQ(declinedAnswer.items[0].shared_detail()->code, "ImmediatePermissionsDeclined");
  ASSERT_TRUE(declinedAnswer.items[1].is_good()) << to_string(declinedAnswer.items[1].status_code());
  EXPECT_EQ(declinedAnswer.items[1].value(), browse);
}

// The immediate form evaluates a Node that no shared_ptr owns, reading that Node's own RolePermissions.
// The owned N2 is the control that the evaluation reads each Node's own RolePermissions.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-EFFECTIVE-PERMISSIONS-NEW-FORMS, scope=function)
TEST(NamespaceDefaults, EffectivePermissionsOfANodeNoSharedPtrOwns)
{
  const NodeId role{1, uint32_t{9001}};
  RequiredMembersNamespace space;
  space.set_default_role_permissions(
    std::vector<RolePermissionType>{grant_of(role, {PermissionType::Bit::Browse})});
  const DescribedNode unowned{object_named(NodeId{2, uint32_t{1}})
                                .with_role_permissions(std::vector<RolePermissionType>{
                                  grant_of(role, {PermissionType::Bit::Browse, PermissionType::Bit::Read})})};
  const auto owned = space.hold(object_named(NodeId{2, uint32_t{2}}));
  const AccessIdentity identity{
    AccessIdentityKey{1}, std::vector<NodeId>{role}, nullptr, nullptr, String{""}};

  std::optional<PermissionType> unownedAnswer;
  EXPECT_NO_THROW(unownedAnswer = space.effective_permissions(identity, &unowned));
  const PermissionType browseAndRead{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  EXPECT_EQ(unownedAnswer, std::optional<PermissionType>{browseAndRead});
  EXPECT_EQ(space.effective_permissions(identity, owned.get()),
    std::optional<PermissionType>{PermissionType{PermissionType::Bit::Browse}});
}

// effective_permissions_async's default evaluates each subject through the immediate form. An evaluation
// that throws for N3 answers N3 alone, with the exception's status and ErrorDetail; N4 is the control that
// the rest of the batch is answered.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-EFFECTIVE-PERMISSIONS-A-THROW-FAILS-ITS-SUBJECT, scope=function)
TEST(NamespaceDefaults, EffectivePermissionsFailOnlyTheSubjectWhoseEvaluationThrows)
{
  const NodeId role{1, uint32_t{9001}};
  const NodeId n3Id{2, uint32_t{3}};
  const NodeId n4Id{2, uint32_t{4}};
  ThrowingPermissionsNamespace space{n3Id};
  space.set_default_role_permissions(
    std::vector<RolePermissionType>{grant_of(role, {PermissionType::Bit::Browse})});
  space.hold(object_named(n3Id));
  space.hold(object_named(n4Id));
  const auto identity = std::make_shared<const AccessIdentity>(
    AccessIdentityKey{1}, std::vector<NodeId>{role}, nullptr, nullptr, String{""});

  Completion<EffectivePermissionsResult> evaluated;
  EXPECT_NO_THROW(space.effective_permissions_async(
    RequestInfo{}, identity, std::vector<NodeId>{n3Id, n4Id}, evaluated.callback()));
  ASSERT_TRUE(evaluated.wait());
  EXPECT_EQ(evaluated.count(), 1);
  const auto& answer = evaluated.get<0>();
  ASSERT_TRUE(answer.batchStatus.is_good()) << to_string(answer.batchStatus.status_code());
  ASSERT_EQ(answer.items.size(), 2u);
  EXPECT_EQ(answer.items[0].status_code().as_status(), Status::BadResourceUnavailable)
    << to_string(answer.items[0].status_code());
  ASSERT_NE(answer.items[0].shared_detail(), nullptr);
  EXPECT_EQ(answer.items[0].shared_detail()->code, "ScriptedPermissionsThrew");
  ASSERT_TRUE(answer.items[1].is_good()) << to_string(answer.items[1].status_code());
  EXPECT_EQ(answer.items[1].value(), PermissionType{PermissionType::Bit::Browse});
}

// NR-4's table of defaults as NR-9, NR-15, NR-16, NR-17 and NR-18 state them: a namespace overriding no
// optional member answers each with its final default.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-FINAL-DEFAULTS, scope=function)
TEST(NamespaceDefaults, AnOptionalMemberNotOverriddenAnswersItsFinalDefault)
{
  RequiredMembersNamespace space;
  const NodeId objectId{2, uint32_t{1}};
  const NodeId variableId{2, uint32_t{2}};
  const NodeId viewId{2, uint32_t{3}};
  const auto object = space.hold(object_named(objectId));
  const auto variable = space.hold(variable_named(variableId));
  space.hold(NodeDescription::view(viewId, QualifiedName{2, "View"}));
  // The View Node's own Reference: a forward Organizes to the Object.
  space.hold_references(
    viewId, {Reference{NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{objectId}, true}});

  const std::vector<WriteValue> writes{
    display_name_write(objectId, "A"), display_name_write(variableId, "B")};
  const std::vector<ValueWriteItem> writeItems{{*object, writes[0]}, {*variable, writes[1]}};
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> write;
  space.write_async(RequestInfo{}, nullptr, writeItems, write.callback());
  ASSERT_TRUE(write.wait());
  ASSERT_EQ(write.get<0>().items.size(), 2u);
  for (const auto& item : write.get<0>().items)
  {
    EXPECT_EQ(item.status_code().as_status(), Status::BadNotWritable)
      << "write_async " << to_string(item.status_code());
  }

  const std::vector<CallMethodRequest> requests{call_of(objectId, variableId), call_of(objectId, variableId)};
  const std::vector<CallItem> callItems{
    {*object, *variable, requests[0], nullptr}, {*object, *variable, requests[1], nullptr}};
  Completion<BatchResult<std::optional<CallResult>>> call;
  space.call_async(RequestInfo{}, nullptr, callItems, call.callback());
  ASSERT_TRUE(call.wait());
  ASSERT_EQ(call.get<0>().items.size(), 2u);
  for (const auto& item : call.get<0>().items)
  {
    EXPECT_FALSE(item.has_value()) << "call_async declines every item";
  }

  auto expectNotSupported = [](const BatchResult<VoidResult>& answer, const char* member)
  {
    ASSERT_EQ(answer.items.size(), 2u) << member;
    for (const auto& item : answer.items)
    {
      EXPECT_EQ(item.status_code().as_status(), Status::BadNotSupported)
        << member << " " << to_string(item.status_code());
    }
  };

  const std::vector<NodeCreation> creations{
    {NodeId{2, uint32_t{10}}, NodeClass::Object, {}}, {NodeId{2, uint32_t{11}}, NodeClass::Object, {}}};
  Completion<BatchResult<NodeResult>> create;
  space.create_nodes_async(RequestInfo{}, creations, create.callback());
  ASSERT_TRUE(create.wait());
  ASSERT_EQ(create.get<0>().items.size(), 2u);
  for (const auto& item : create.get<0>().items)
  {
    EXPECT_EQ(item.status_code().as_status(), Status::BadNotSupported) << "create_nodes_async";
  }

  const std::vector<NodeId> doomed{objectId, variableId};
  Completion<BatchResult<DeleteNodeResult>, std::vector<VersionedNode>> remove;
  space.delete_nodes_async(RequestInfo{}, doomed, ReferenceHalves::Both, remove.callback());
  ASSERT_TRUE(remove.wait());
  ASSERT_EQ(remove.get<0>().items.size(), 2u);
  for (const auto& item : remove.get<0>().items)
  {
    EXPECT_EQ(item.status_code().as_status(), Status::BadNotSupported) << "delete_nodes_async";
  }

  const auto halves = ReferenceChange::both_halves(objectId, NodeId{ReferenceTypeId::Organizes}, variableId);
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> add;
  space.add_references_async(RequestInfo{}, halves, add.callback());
  ASSERT_TRUE(add.wait());
  expectNotSupported(add.get<0>(), "add_references_async");
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> drop;
  space.remove_references_async(RequestInfo{}, halves, drop.callback());
  ASSERT_TRUE(drop.wait());
  expectNotSupported(drop.get<0>(), "remove_references_async");
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> addToView;
  space.add_to_view_async(RequestInfo{}, viewId, doomed, addToView.callback());
  ASSERT_TRUE(addToView.wait());
  expectNotSupported(addToView.get<0>(), "add_to_view_async");

  const std::vector<ExpandedNodeId> candidates{ExpandedNodeId{objectId}, ExpandedNodeId{variableId}};
  Completion<BatchResult<BoolResult>> contains;
  space.view_contains_async(RequestInfo{}, viewId, candidates, contains.callback());
  ASSERT_TRUE(contains.wait());
  ASSERT_EQ(contains.get<0>().items.size(), 2u);
  ASSERT_TRUE(contains.get<0>().items[0].is_good()) << to_string(contains.get<0>().items[0].status_code());
  EXPECT_TRUE(contains.get<0>().items[0].value()) << "the View Node's own Reference target";
  ASSERT_TRUE(contains.get<0>().items[1].is_good()) << to_string(contains.get<0>().items[1].status_code());
  EXPECT_FALSE(contains.get<0>().items[1].value());

  Completion<Result<std::vector<NodeId>>> enumerate;
  space.enumerate_nodes_async(RequestInfo{}, enumerate.callback());
  ASSERT_TRUE(enumerate.wait());
  EXPECT_EQ(enumerate.get<0>().status_code().as_status(), Status::BadNotSupported);

  EXPECT_FALSE(space.find_node(objectId, std::nullopt).has_value()) << "find_node declines";
  EXPECT_NO_THROW(space.release_resume_token(ByteString{0x01}));
}

namespace
{

// A namespace whose lookup makes a new View Node for each NodeId and keeps only a weak_ptr to it, so the Node
// it returns is held by nothing else, and whose Reference read answers later, from the test's step: the
// View's forward Organizes to the NodeId given. The lookup can answer one item more than it was asked for.
class FreshViewNamespace final : public RequiredMembersNamespace
{
public:
  explicit FreshViewNamespace(NodeId member) : mMember{std::move(member)}
  {}

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      auto node = std::make_shared<DescribedNode>(
        NodeDescription::view(nodeId, QualifiedName{nodeId.namespace_index(), "Fresh"}));
      {
        const std::lock_guard lock{mMutex};
        mMade = node;
      }
      answer.items.emplace_back(NodeResult{std::move(node)});
    }
    if (mAnswerOneMore && !answer.items.empty())
    {
      answer.items.push_back(answer.items.front());
    }
    complete(std::move(answer));
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    // The queried Node is kept by address only: the caller holds it until the call completes.
    std::vector<const Node*> nodes;
    for (const auto& query : queries)
    {
      nodes.push_back(&query.node);
    }
    const std::lock_guard lock{mMutex};
    mParked = [this, nodes = std::move(nodes), complete = std::move(complete)]
    {
      BatchResult<NodeReferencesResult> answer;
      for (const Node* node : nodes)
      {
        bool alive = false;
        {
          const std::lock_guard held{mMutex};
          alive = !mMade.expired();
          mAliveWhenAnswered = alive;
        }
        if (!alive)
        {
          answer.items.emplace_back(StatusCode{Status::BadInternalError});
          continue;
        }
        const NodeDescription view = node->attributes();
        ASSERT_EQ(view.node_class(), NodeClass::View);
        answer.items.emplace_back(NodeReferences{
          References{{Reference{NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mMember}, true}}},
          ByteString{}});
      }
      complete(std::move(answer));
    };
  }

  void answer_one_more()
  {
    mAnswerOneMore = true;
  }

  /// Runs the parked Reference read. @return false when none is parked.
  bool answer_parked()
  {
    std::function<void()> parked;
    {
      const std::lock_guard lock{mMutex};
      parked = std::move(mParked);
      mParked = nullptr;
    }
    if (!parked)
    {
      return false;
    }
    parked();
    return true;
  }

  /// Whether the View Node the lookup made was alive when the Reference read answered.
  bool alive_when_answered() const
  {
    const std::lock_guard lock{mMutex};
    return mAliveWhenAnswered;
  }

private:
  NodeId mMember;
  bool mAnswerOneMore{false};
  mutable std::mutex mMutex;
  std::weak_ptr<Node> mMade;
  std::function<void()> mParked;
  bool mAliveWhenAnswered{false};
};

}  // namespace

// NR-16 and the ReferenceQuery contract: view_contains_async's default looks the View Node up and holds it
// until its Reference read answers, after the member has returned and the candidates the caller gave are
// gone. A lookup that answers another number of items fails every candidate with Bad_InternalError
// (LookupItemCountMismatch).
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-THE-VIEW-DEFAULT-KEEPS-THE-VIEW-NODE-UNTIL-ITS-REFERENCES-ANSWER, scope=function)
TEST(NamespaceDefaults, TheViewDefaultKeepsTheViewNodeUntilItsReferencesAnswer)
{
  const NodeId viewId{2, uint32_t{1}};
  const NodeId member{2, uint32_t{2}};
  const NodeId other{2, uint32_t{3}};
  FreshViewNamespace space{member};

  auto candidates = std::make_unique<std::vector<ExpandedNodeId>>(
    std::vector<ExpandedNodeId>{ExpandedNodeId{member}, ExpandedNodeId{other}});
  Completion<BatchResult<BoolResult>> contains;
  space.view_contains_async(RequestInfo{}, viewId, *candidates, contains.callback());
  candidates.reset();
  ASSERT_TRUE(space.answer_parked()) << "the default did not read the View's References";

  EXPECT_TRUE(space.alive_when_answered())
    << "the default released the View Node before its References answered";
  ASSERT_TRUE(contains.wait());
  EXPECT_EQ(contains.count(), 1);
  const auto& answer = contains.get<0>();
  ASSERT_EQ(answer.items.size(), 2u) << to_string(answer.batchStatus.status_code());
  ASSERT_TRUE(answer.items[0].is_good()) << to_string(answer.items[0].status_code());
  ASSERT_TRUE(answer.items[1].is_good()) << to_string(answer.items[1].status_code());
  EXPECT_TRUE(answer.items[0].value()) << "the View's Organizes target is not a member";
  EXPECT_FALSE(answer.items[1].value()) << "a NodeId the View does not reference is a member";

  FreshViewNamespace overAnswering{member};
  overAnswering.answer_one_more();
  const std::vector<ExpandedNodeId> asked{ExpandedNodeId{member}, ExpandedNodeId{other}};
  Completion<BatchResult<BoolResult>> mismatched;
  overAnswering.view_contains_async(RequestInfo{}, viewId, asked, mismatched.callback());
  ASSERT_TRUE(mismatched.wait());
  EXPECT_EQ(mismatched.count(), 1);
  EXPECT_FALSE(overAnswering.answer_parked()) << "the default read References after a mismatched lookup";
  const auto& failed = mismatched.get<0>();
  ASSERT_EQ(failed.items.size(), 2u) << to_string(failed.batchStatus.status_code());
  for (const auto& item : failed.items)
  {
    EXPECT_EQ(item.status_code().as_status(), Status::BadInternalError) << to_string(item.status_code());
    ASSERT_NE(item.shared_detail(), nullptr);
    EXPECT_EQ(item.shared_detail()->code, "LookupItemCountMismatch");
  }
}
