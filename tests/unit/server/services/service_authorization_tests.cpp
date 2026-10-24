// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "deferred_namespace.h"

#include <boost/asio/thread_pool.hpp>

#include "ua_read_service.h"
#include "ua_browse_service.h"
#include <ua_method_service_set.h>
#include "ua_translate_browse_paths_service.h"

#include "ua_attribute_service_set.h"
#include "ua_default_namespace.h"
#include "ua_read_request.h"
#include "ua_browse_request.h"
#include "ua_call_request.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include "ua_data_value.h"
#include "ua_array.h"
#include "ua_localized_text.h"
#include "ua_object_id.h"
#include "ua_namespace_items.h"
#include "ua_role_permission_type.h"
#include "ua_variant.h"
#include "ua_attribute_write_mask.h"

#include "ua_method_id.h"
#include "ua_referencetype_id.h"
#include "ua_method_call_authorization_internal.h"
#include "ua_objecttype_id.h"

#include "access_control_test_support.h"
#include "posting_writes_namespace.h"
#include "ua_access_control.h"
#include "ua_callback_safety.h"

#include "ua_service_fault.h"
#include "ua_verdict_rules.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_server_session_info.h"
#include "ua_access_level_type.h"

#include "ua_session_security.h"
#include "ua_diagnostic_policy.h"
#include "ua_sinks.h"

#include <array>
#include <future>
#include <mutex>
#include <span>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

// The one rule every authorization site applies: exactly one verdict per item, all permitted; anything
// else is a denial, never a permission.
// @relation(AC-SVR-AUTHZ-015-A-VERDICT-LIST-OF-THE-WRONG-SIZE-DENIES, scope=function)
TEST(VerdictRules, AVerdictListOfTheWrongSizeDeniesAndADeniedVerdictNamesItsCause)
{
  using ua::server::detail::first_denial;
  using Verdict = ua::server::AccessControl::Verdict;
  const Verdict permitted{.permitted = true};
  const Verdict denied{.permitted = false, .cause = StatusCode{Status::BadSecurityModeInsufficient}};

  const std::vector<Verdict> none;
  auto d = first_denial(none, 1);
  ASSERT_TRUE(d.has_value()) << "an empty list authorizes nothing";
  EXPECT_EQ(d->as_status(), Status::BadUserAccessDenied);

  const std::vector<Verdict> one{permitted};
  EXPECT_FALSE(first_denial(one, 1).has_value());
  EXPECT_TRUE(first_denial(one, 2).has_value()) << "one verdict for two items is short";

  const std::vector<Verdict> two{permitted, permitted};
  EXPECT_TRUE(first_denial(two, 1).has_value()) << "two verdicts for one item is not a permission either";

  const std::vector<Verdict> mixed{permitted, denied};
  auto cause = first_denial(mixed, 2);
  ASSERT_TRUE(cause.has_value());
  EXPECT_EQ(cause->as_status(), Status::BadSecurityModeInsufficient) << "the denied verdict's own cause";
}

namespace
{

class TestSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  TestSessionInfo(boost::asio::any_io_executor ex, bool identityAvailable)
    : mExecutor(ex), mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->endpointPolicyId = "L/None";
    security->messageSecurityMode = MessageSecurityMode::None;
    security->securityPolicyId = SecurityPolicyId::None;
    mSecurity = std::move(security);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = UserTokenKind::Anonymous;
    mUser = std::move(user);

    if (identityAvailable)
      mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
  }

  TestSessionInfo(boost::asio::any_io_executor ex, std::nullptr_t) : TestSessionInfo(std::move(ex), false)
  {}

  // SessionInfo
  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() const override
  {
    return mServerCfg;
  }

  // SessionSecurityContext
  NodeId session_id() const override
  {
    return NodeId{1, Guid::create_and_generate()};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    if (mPoisonAccessIdentityAfterFirstRead && mAccessIdentityReadCount++ > 0)
      return nullptr;
    return mAccessIdentity;
  }

  void poison_access_identity_after_first_read() const
  {
    mPoisonAccessIdentityAfterFirstRead = true;
  }

  std::size_t access_identity_read_count() const
  {
    return mAccessIdentityReadCount;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, mServerCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  std::shared_ptr<EventSink> event_sink() const override
  {
    // Non-owning: the test owns the sink it sets.
    return mEventSink ? std::shared_ptr<EventSink>(mEventSink, [](EventSink*) {}) : nullptr;
  }

  void set_event_sink(EventSink* eventSink)
  {
    mEventSink = eventSink;
  }

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  ServerConfig mServerCfg;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
  EventSink* mEventSink = nullptr;
  mutable bool mPoisonAccessIdentityAfterFirstRead = false;
  mutable std::size_t mAccessIdentityReadCount = 0;
};

class ControlledRolePermissionsNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<ControlledRolePermissionsNamespace> create(
    std::string uri, boost::asio::any_io_executor executor, bool defer)
  {
    return std::shared_ptr<ControlledRolePermissionsNamespace>{
      new ControlledRolePermissionsNamespace{std::move(uri), std::move(executor), defer}};
  }

  std::future<void> validation_entered()
  {
    return mEntered.get_future();
  }

  // Each update is counted and recorded as one validation; the call completes inline or when the test
  // completes it, with one answer for every update it holds.
  void validate_role_permissions_updates_async(const RequestInfo& request,
    std::span<const RolePermissionsUpdate> updates,
    std::function<void(BatchResult<VoidResult>)> complete) override
  {
    (void)request;
    std::function<void(BatchResult<VoidResult>)> inlineCompletion;
    {
      const std::lock_guard lock(mValidationMutex);
      for (const auto& update : updates)
      {
        ++mValidationCalls;
        mValidatedNode = update.nodeId;
        mValidatedProposal = update.proposed;
      }
      mPendingUpdates = updates.size();
      if (mDefer)
        mDeferredCompletion = std::move(complete);
      else
        inlineCompletion = std::move(complete);
    }
    try
    {
      mEntered.set_value();
    }
    catch (...)
    {
      ua::detail::ignore_expected_exception();
    }
    if (inlineCompletion)
      inlineCompletion(answer_each(VoidResult{}, updates.size()));
  }

  void complete_validation(VoidResult result)
  {
    std::function<void(BatchResult<VoidResult>)> completion;
    std::size_t updates = 0;
    {
      const std::lock_guard lock(mValidationMutex);
      completion = std::move(mDeferredCompletion);
      updates = mPendingUpdates;
    }
    ASSERT_TRUE(completion) << "no deferred RolePermissions validation is pending";
    completion(answer_each(std::move(result), updates));
  }

  size_t validation_calls() const
  {
    const std::lock_guard lock(mValidationMutex);
    return mValidationCalls;
  }

  std::optional<std::vector<RolePermissionType>> validated_proposal() const
  {
    const std::lock_guard lock(mValidationMutex);
    return mValidatedProposal;
  }

private:
  ControlledRolePermissionsNamespace(std::string uri, boost::asio::any_io_executor executor, bool defer)
    : default_ns::Namespace{uri, std::move(executor)}, mDefer{defer}
  {}

  static BatchResult<VoidResult> answer_each(VoidResult answer, std::size_t updates)
  {
    BatchResult<VoidResult> result;
    for (std::size_t i = 0; i < updates; ++i)
      result.items.push_back(answer);
    return result;
  }

  const bool mDefer;
  mutable std::mutex mValidationMutex;
  std::promise<void> mEntered;
  size_t mValidationCalls{0};
  NodeId mValidatedNode;
  std::optional<std::vector<RolePermissionType>> mValidatedProposal;
  std::size_t mPendingUpdates{0};
  std::function<void(BatchResult<VoidResult>)> mDeferredCompletion;
};

class CountingEventSink final : public EventSink
{
public:
  void emit(BaseEvent&) override
  {
    ++mEmitted;
  }

  std::size_t emitted() const
  {
    return mEmitted;
  }

private:
  std::size_t mEmitted = 0;
};

template<typename ResponseT>
ResponseT wait_for_typed_response(std::future<Response>& fut)
{
  auto status = fut.wait_for(1s);
  EXPECT_EQ(status, std::future_status::ready);
  auto resp = fut.get();
  auto* typed = dynamic_cast<ResponseT*>(resp.second.get());
  EXPECT_NE(typed, nullptr);
  return *typed;
}

StatusCode write_role_permissions(std::shared_ptr<TestSessionInfo> sessionInfo,
  boost::asio::any_io_executor executor, const NodeId& nodeId,
  const std::vector<RolePermissionType>& permissions)
{
  WriteRequest request;
  request.request_header().request_handle() = 1;
  WriteValue item;
  item.node_id() = nodeId;
  item.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  item.value() = DataValue{Variant{array_utils::copy_to_array_of_references(permissions)}};
  request.nodes_to_write().payload().push_back(std::move(item));

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(request),
    executor,
    [&completion](Response response) { completion.set_value(std::move(response)); });
  (void)service;
  auto response = responseFuture.get();
  auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
  if (writeResponse == nullptr || writeResponse->results().empty())
    return StatusCode{Status::BadInternalError};
  return writeResponse->results()[0];
}

struct PendingRolePermissionsWrite
{
  std::shared_ptr<AttributeServiceSet> service;
  std::future<Response> response;
};

PendingRolePermissionsWrite start_role_permissions_write(std::shared_ptr<TestSessionInfo> sessionInfo,
  boost::asio::any_io_executor executor, const NodeId& nodeId,
  const std::vector<RolePermissionType>& permissions)
{
  WriteRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().return_diagnostics() = 0xFFFF;
  WriteValue item;
  item.node_id() = nodeId;
  item.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  item.value() = DataValue{Variant{array_utils::copy_to_array_of_references(permissions)}};
  request.nodes_to_write().payload().push_back(std::move(item));

  auto completion = std::make_shared<std::promise<Response>>();
  auto response = completion->get_future();
  auto service = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(request),
    executor,
    [completion](Response result) { completion->set_value(std::move(result)); });
  return PendingRolePermissionsWrite{std::move(service), std::move(response)};
}

WriteResponse finish_role_permissions_write(PendingRolePermissionsWrite& pending)
{
  EXPECT_EQ(pending.response.wait_for(1s), std::future_status::ready);
  auto response = pending.response.get();
  auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
  EXPECT_NE(writeResponse, nullptr);
  return writeResponse ? *writeResponse : WriteResponse{};
}

RolePermissionType make_role_permission(
  const NodeId& roleId, std::initializer_list<PermissionType::Bit> permissions)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = PermissionType{permissions};
  return entry;
}

}  // namespace

// @relation(AC-SVR-AUTHZ-001-NO-UNGOVERNED-CONFIGURATION, scope=function)
TEST(ServiceAuthorizationTests, ReadDeniedWhenNoAuthorizer)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestSessionInfo>(ex, nullptr);

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{0, ObjectId::RootFolder};
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  EXPECT_EQ(rr->results()[0].status(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, BrowseDeniedWhenNoAuthorizer)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestSessionInfo>(ex, nullptr);

  BrowseRequest req;
  req.request_header().request_handle() = 1;
  BrowseDescription bd;
  bd.node_id() = NodeId{0, ObjectId::RootFolder};
  req.nodes_to_browse().payload().push_back(std::move(bd));

  std::promise<BrowseService::BrowseServiceResponse> p;
  auto fut = p.get_future();
  auto svc = BrowseService::create(si, {}, 1, std::move(req), ex, [&](auto r) { p.set_value(std::move(r)); });
  (void)svc;

  auto r = fut.get();
  auto* br = dynamic_cast<BrowseResponse*>(r.response.second.get());
  ASSERT_NE(br, nullptr);
  ASSERT_EQ(br->results().size(), 1u);
  EXPECT_EQ(br->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, CallDeniedWhenNoAuthorizer)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestSessionInfo>(ex, nullptr);

  CallRequest req;
  req.request_header().request_handle() = 1;
  CallMethodRequest cmr;
  cmr.object_id() = NodeId{0, ObjectId::RootFolder};
  cmr.method_id() = NodeId{0, MethodId::Server_GetMonitoredItems};
  req.methods_to_call().payload().push_back(std::move(cmr));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    MethodServiceSet::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* cr = dynamic_cast<CallResponse*>(resp.second.get());
  ASSERT_NE(cr, nullptr);
  ASSERT_EQ(cr->results().size(), 1u);
  EXPECT_EQ(cr->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-AUTHZ-007-CALL-OBJECT-HALF, scope=function)
// @verifies AC-SVR-AUTHZ-007-CALL-OBJECT-HALF
TEST(ServiceAuthorizationTests, DefaultCallPathRequiresPermissionOnObjectAndMethod)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  auto addressSpace = sessionInfo->address_space();
  const NodeId objectId{1, 9010u};
  const NodeId methodId{1, 9011u};
  auto object = addressSpace.try_create_node_sync(objectId, NodeClass::Object, {});
  auto method = addressSpace.try_create_sync<MethodAccessor>(methodId, NodeClass::Method);
  ASSERT_TRUE(object.is_good());
  ASSERT_TRUE(method.is_good());
  method.value().set_executable(true);
  object.value().add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

  auto objectPermissions = ua::test_helpers::all_permissions();
  objectPermissions.reset(PermissionType::Bit::Call);
  ua::test_helpers::set_test_node_permissions(object.value(), objectPermissions);
  NodeAccessor methodNode = method.value();
  ua::test_helpers::set_test_node_permissions(methodNode, ua::test_helpers::all_permissions());

  auto nameSpace = std::dynamic_pointer_cast<default_ns::Namespace>(
    addressSpace.namespace_array().get_namespace(objectId.namespace_index()));
  ASSERT_NE(nameSpace, nullptr);
  auto storedMethod = nameSpace->find_node<Node>(methodId);
  ASSERT_NE(storedMethod, nullptr);
  auto* callSource = storedMethod->method_call_source();
  ASSERT_NE(callSource, nullptr);
  bool handlerInvoked = false;
  callSource->set_call_handler(
    [&handlerInvoked](const CallMethodRequest&,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        callback)
    {
      handlerInvoked = true;
      CallMethodResult result;
      result.status_code() = Status::Good;
      callback(CallResult{std::move(result)});
    });

  CallRequest request;
  request.request_header().request_handle() = 1;
  CallMethodRequest item;
  item.object_id() = objectId;
  item.method_id() = methodId;
  request.methods_to_call().payload().push_back(std::move(item));

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = MethodServiceSet::create(sessionInfo,
    {},
    1,
    std::move(request),
    pool.get_executor(),
    [&completion](Response response) { completion.set_value(std::move(response)); });
  (void)service;
  auto response = responseFuture.get();
  auto* callResponse = dynamic_cast<CallResponse*>(response.second.get());
  ASSERT_NE(callResponse, nullptr);
  ASSERT_EQ(callResponse->results().size(), 1u);
  EXPECT_EQ(callResponse->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_FALSE(handlerInvoked) << "object denial must happen before the Method executes";
  ::ua::test_utils::drain_with_timeout(pool);
}

TEST(ServiceAuthorizationTests, TranslateBrowsePathsDeniedWhenNoAuthorizer)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestSessionInfo>(ex, nullptr);

  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath bp;
  bp.starting_node() = NodeId{0, ObjectId::RootFolder};
  RelativePath rp;
  RelativePathElement el;
  el.reference_type_id() = NodeId{0, ReferenceTypeId::HierarchicalReferences};
  el.is_inverse() = false;
  el.include_subtypes() = true;
  rp.elements().payload().push_back(std::move(el));
  bp.relative_path() = std::move(rp);
  req.browse_paths().payload().push_back(std::move(bp));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = TranslateBrowsePathsService::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* tr = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(resp.second.get());
  ASSERT_NE(tr, nullptr);
  ASSERT_EQ(tr->results().size(), 1u);
  EXPECT_EQ(tr->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, ReadAllowedWhenNamespacePermits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{0, ObjectId::RootFolder};
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  EXPECT_NE(rr->results()[0].status(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE, scope=function)
// @verifies AC-SVR-AUTHZ-014-BIT1-IS-PER-NODE
TEST(ServiceAuthorizationTests, ReadRolePermissionsIsPerNode)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const NodeId allowedNodeId{1, 1003u};
  const NodeId deniedNodeId{1, 1004u};
  auto allowedNode = sessionInfo->address_space().try_create_node_sync(allowedNodeId, NodeClass::Object, {});
  auto deniedNode = sessionInfo->address_space().try_create_node_sync(deniedNodeId, NodeClass::Object, {});
  ASSERT_TRUE(allowedNode.is_good());
  ASSERT_TRUE(deniedNode.is_good());
  ua::test_helpers::set_test_node_permissions(allowedNode.value(), ua::test_helpers::all_permissions());
  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::ReadRolePermissions);
  ua::test_helpers::set_test_node_permissions(deniedNode.value(), deniedPermissions);

  ReadRequest request;
  request.request_header().request_handle() = 1;
  for (const auto& nodeId : {allowedNodeId, deniedNodeId})
  {
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
    request.nodes_to_read().payload().push_back(std::move(item));
  }

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = ReadService::create(sessionInfo,
    {},
    1,
    std::move(request),
    pool.get_executor(),
    [&completion](Response response) { completion.set_value(std::move(response)); });
  (void)service;

  auto response = responseFuture.get();
  auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
  ASSERT_NE(readResponse, nullptr);
  ASSERT_EQ(readResponse->results().size(), 2u);
  EXPECT_TRUE(!readResponse->results()[0].status() || readResponse->results()[0].status()->is_good());
  EXPECT_TRUE(readResponse->results()[0].value().is_array_of_structure());
  EXPECT_FALSE(readResponse->results()[0].value().as<Array<RefStructure<Structure>>>().empty());
  EXPECT_EQ(readResponse->results()[1].status(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(readResponse->results()[1].value().empty());
  ::ua::test_utils::drain_with_timeout(pool);
}

// AttributeService intersects the Namespace verdict's projected write mask with the Node's
// WriteMask; the result cannot enable bits absent from the Node even when policy grants all bits.
TEST(ServiceAuthorizationTests, UserWriteMaskIsMaskedAndCannotEnableNewBits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool auth = true;

  auto si = std::make_shared<TestSessionInfo>(ex, auth);
  auto as = si->address_space();

  const NodeId nodeId{1, 1001u};
  auto createResult = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto& node = createResult.value();

  node.set_write_mask(ua::AttributeWriteMask{ua::AttributeWriteMask::Bit::DisplayName});
  const uint32_t writeMask = node.get_write_mask()->as_underlying_type();
  ASSERT_NE(writeMask, 0u);
  ASSERT_EQ((writeMask & 0x80000000u), 0u);

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::UserWriteMask);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  const auto& dv = rr->results()[0];
  EXPECT_TRUE(!dv.status() || dv.status()->is_good());

  uint32_t userWriteMask{};
  ASSERT_NO_THROW(userWriteMask = dv.value().as<uint32_t>());
  EXPECT_EQ(userWriteMask, writeMask);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 Table 37 separates WriteAttribute from WriteRolePermissions. UserWriteMask must therefore
// retain bit 23 only when the caller holds the latter, independently of the node's WriteMask.
// @verifies AC-SVR-AUTHZ-006-ATTRIBUTE-WRITE-BITS-SEPARATE
TEST(ServiceAuthorizationTests, UserWriteMaskReflectsWriteRolePermissionsBit)
{
  const auto readMask = [](bool grantRolePermissionsWrite)
  {
    boost::asio::thread_pool pool;
    auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
    const NodeId nodeId{1, grantRolePermissionsWrite ? 1011u : 1010u};
    auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
    EXPECT_TRUE(created.is_good());
    if (created.is_bad())
    {
      ::ua::test_utils::drain_with_timeout(pool);
      return uint32_t{};
    }
    created.value().set_write_mask(
      AttributeWriteMask{AttributeWriteMask::Bit::DisplayName, AttributeWriteMask::Bit::RolePermissions});
    PermissionType permissions = ua::test_helpers::all_permissions();
    if (!grantRolePermissionsWrite)
      permissions.reset(PermissionType::Bit::WriteRolePermissions);
    NodeAccessor node = created.value();
    ua::test_helpers::set_test_node_permissions(node, permissions);

    ReadRequest request;
    request.request_header().request_handle() = 1;
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::UserWriteMask);
    request.nodes_to_read().payload().push_back(std::move(item));

    std::promise<Response> completion;
    auto responseFuture = completion.get_future();
    auto service = ReadService::create(sessionInfo,
      {},
      1,
      std::move(request),
      pool.get_executor(),
      [&completion](Response response) { completion.set_value(std::move(response)); });
    (void)service;

    auto response = responseFuture.get();
    auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
    EXPECT_NE(readResponse, nullptr);
    uint32_t result{};
    if (readResponse && readResponse->results().size() == 1)
    {
      EXPECT_TRUE(!readResponse->results()[0].status() || readResponse->results()[0].status()->is_good());
      result = readResponse->results()[0].value().as<uint32_t>();
    }
    ::ua::test_utils::drain_with_timeout(pool);
    return result;
  };

  const AttributeWriteMask disabled{readMask(false)};
  const AttributeWriteMask enabled{readMask(true)};
  EXPECT_TRUE(disabled.test(AttributeWriteMask::Bit::DisplayName));
  EXPECT_FALSE(disabled.test(AttributeWriteMask::Bit::RolePermissions));
  EXPECT_TRUE(enabled.test(AttributeWriteMask::Bit::DisplayName));
  EXPECT_TRUE(enabled.test(AttributeWriteMask::Bit::RolePermissions));
}

// Removed: UserWriteMaskMaskingFailureReturnsZeroWithGoodStatus. The old test verified
// that a separate asynchronous mask call could fail after authorization. Projection is now a pure
// transformation of the already-complete verdict, so there is no second failure surface to test.

TEST(ServiceAuthorizationTests, BrowseAllowedWhenNamespacePermits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  BrowseRequest req;
  req.request_header().request_handle() = 1;
  BrowseDescription bd;
  bd.node_id() = NodeId{0, ObjectId::RootFolder};
  req.nodes_to_browse().payload().push_back(std::move(bd));

  std::promise<BrowseService::BrowseServiceResponse> p;
  auto fut = p.get_future();
  auto svc = BrowseService::create(si, {}, 1, std::move(req), ex, [&](auto r) { p.set_value(std::move(r)); });
  (void)svc;

  auto r = fut.get();
  auto* br = dynamic_cast<BrowseResponse*>(r.response.second.get());
  ASSERT_NE(br, nullptr);
  ASSERT_EQ(br->results().size(), 1u);
  EXPECT_NE(br->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, CallAllowedWhenNamespacePermits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  CallRequest req;
  req.request_header().request_handle() = 1;
  CallMethodRequest cmr;
  cmr.object_id() = NodeId{0, ObjectId::RootFolder};
  cmr.method_id() = NodeId{0, MethodId::Server_GetMonitoredItems};
  req.methods_to_call().payload().push_back(std::move(cmr));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    MethodServiceSet::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* cr = dynamic_cast<CallResponse*>(resp.second.get());
  ASSERT_NE(cr, nullptr);
  ASSERT_EQ(cr->results().size(), 1u);
  EXPECT_NE(cr->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, TranslateBrowsePathsAllowedWhenNamespacePermits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath bp;
  bp.starting_node() = NodeId{0, ObjectId::RootFolder};
  RelativePath rp;
  RelativePathElement el;
  el.reference_type_id() = NodeId{0, ReferenceTypeId::HierarchicalReferences};
  el.is_inverse() = false;
  el.include_subtypes() = true;
  rp.elements().payload().push_back(std::move(el));
  bp.relative_path() = std::move(rp);
  req.browse_paths().payload().push_back(std::move(bp));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = TranslateBrowsePathsService::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* tr = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(resp.second.get());
  ASSERT_NE(tr, nullptr);
  ASSERT_EQ(tr->results().size(), 1u);
  EXPECT_NE(tr->results()[0].status_code(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// AttributeService intersects the Namespace verdict's projected access mask with the Node's
// AccessLevel; the result cannot enable bits absent from the Node even when policy grants all bits.
TEST(ServiceAuthorizationTests, UserAccessLevelIsMaskedAndCannotEnableNewBits)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool auth = true;

  auto si = std::make_shared<TestSessionInfo>(ex, auth);

  // Create a variable node with AccessLevel CurrentRead only.
  const NodeId varId{1, Guid::create_and_generate()};
  auto varResult = si->address_space().try_create_sync<VariableAccessor>(varId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  var.set_access_level(al);

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = varId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::UserAccessLevel);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  ASSERT_TRUE(!rr->results()[0].status() || rr->results()[0].status()->is_good());

  uint8_t masked = rr->results()[0].value().as<uint8_t>();
  EXPECT_EQ(masked, al.as_underlying_type());
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-AUTHZ-011-COMPLETED-VERDICT-PROJECTED-ONCE, scope=function)
TEST(ServiceAuthorizationTests, DeferredReadProjectsCompletedVerdictWithoutRequery)
{
  boost::asio::thread_pool pool{2};
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const auto identity = sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr);

  auto nameSpace =
    ua::test::DeferredNamespace::create("urn:test:deferred-read-projection", pool.get_executor());
  const uint16_t namespaceIndex = sessionInfo->address_space().add_namespace_sync(nameSpace);
  const NodeId variableId{namespaceIndex, 8321u};
  nameSpace->create_node(variableId, NodeClass::Variable);
  auto variable = sessionInfo->address_space().find_node_sync(variableId).as<VariableAccessor>().value();
  variable.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  nameSpace->set_async_permissions(
    identity->key(), variableId, PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
  nameSpace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  ReadRequest request;
  request.request_header().request_handle() = 1;
  ReadValueId item;
  item.node_id() = variableId;
  item.attribute_id() = utils::to_underlying(AttributeId::UserAccessLevel);
  request.nodes_to_read().payload().push_back(std::move(item));

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = ReadService::create(sessionInfo,
    {},
    1,
    std::move(request),
    pool.get_executor(),
    [&completion](Response response) { completion.set_value(std::move(response)); });
  (void)service;

  ASSERT_TRUE(nameSpace->wait_for_pending_resolutions());
  EXPECT_EQ(responseFuture.wait_for(0ms), std::future_status::timeout);
  nameSpace->complete_pending_resolutions();
  ASSERT_EQ(responseFuture.wait_for(1s), std::future_status::ready);
  auto response = responseFuture.get();
  auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
  ASSERT_NE(readResponse, nullptr);
  ASSERT_EQ(readResponse->results().size(), 1u);
  ASSERT_TRUE(!readResponse->results()[0].status() || readResponse->results()[0].status()->is_good());
  const AccessLevelType projected{readResponse->results()[0].value().as<uint8_t>()};
  EXPECT_TRUE(projected.test(AccessLevelType::Bit::CurrentRead));
  EXPECT_FALSE(projected.test(AccessLevelType::Bit::CurrentWrite));
  EXPECT_EQ(nameSpace->permission_questions(), 1u);
  const auto asynchronousCalls = nameSpace->effective_permissions_calls();
  ASSERT_EQ(asynchronousCalls.size(), 1u);
  ASSERT_TRUE(asynchronousCalls[0].nodes.has_value());
  EXPECT_EQ(*asynchronousCalls[0].nodes, std::vector<NodeId>{variableId});

  nameSpace->wait_idle();
  nameSpace->shutdown_async([](VoidResult) {});
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-AUTHZ-020-PROJECTION-NOT-AUDITED, scope=function)
TEST(ServiceAuthorizationTests, UserAccessLevelProjectionDoesNotEmitAnAuditEvent)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  CountingEventSink events;
  sessionInfo->set_event_sink(&events);

  const NodeId variableId{1, Guid::create_and_generate()};
  auto variableResult =
    sessionInfo->address_space().try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  auto& variable = variableResult.value();
  variable.set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
    AccessLevelType::Bit::CurrentWrite,
    AccessLevelType::Bit::HistoryRead,
    AccessLevelType::Bit::HistoryWrite});
  PermissionType permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Write);
  permissions.reset(PermissionType::Bit::InsertHistory);
  permissions.reset(PermissionType::Bit::ModifyHistory);
  permissions.reset(PermissionType::Bit::DeleteHistory);
  NodeAccessor node = variable;
  ua::test_helpers::set_test_node_permissions(node, permissions);

  ReadRequest request;
  request.request_header().request_handle() = 1;
  ReadValueId item;
  item.node_id() = variableId;
  item.attribute_id() = utils::to_underlying(AttributeId::UserAccessLevel);
  request.nodes_to_read().payload().push_back(std::move(item));

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = ReadService::create(sessionInfo,
    {},
    1,
    std::move(request),
    pool.get_executor(),
    [&completion](Response response) { completion.set_value(std::move(response)); });
  (void)service;

  auto response = responseFuture.get();
  auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
  ASSERT_NE(readResponse, nullptr);
  ASSERT_EQ(readResponse->results().size(), 1u);
  ASSERT_TRUE(!readResponse->results()[0].status() || readResponse->results()[0].status()->is_good());
  const AccessLevelType projected{readResponse->results()[0].value().as<uint8_t>()};
  EXPECT_TRUE(projected.test(AccessLevelType::Bit::CurrentRead));
  EXPECT_TRUE(projected.test(AccessLevelType::Bit::HistoryRead));
  EXPECT_FALSE(projected.test(AccessLevelType::Bit::CurrentWrite));
  EXPECT_FALSE(projected.test(AccessLevelType::Bit::HistoryWrite));
  EXPECT_EQ(events.emitted(), 0u);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-048-ROLEPERMISSIONS-WRITABLE-WHEN-ALLOWED, scope=function)
// @relation(AC-SVR-ADDRSP-058-PERMISSIONS-WRITABLE-WHEN-CONFIGURABLE, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteSucceedsWhenCapabilityAndPermissionArePresent)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const NodeId nodeId{1, 9401u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const NodeId securityAdmin{ObjectId::WellKnownRole_SecurityAdmin};
  const std::vector<RolePermissionType> proposed{
    make_role_permission(securityAdmin, {PermissionType::Bit::WriteRolePermissions}),
    make_role_permission(ua::test_helpers::test_access_role_id(), {PermissionType::Bit::Read})};

  EXPECT_TRUE(write_role_permissions(sessionInfo, pool.get_executor(), nodeId, proposed).is_good());
  EXPECT_EQ(created.value().get_role_permissions(), proposed);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-048-ROLEPERMISSIONS-WRITABLE-WHEN-ALLOWED, scope=function)
// @relation(AC-SVR-SECADMIN-049-ROLEPERMISSIONS-NEEDS-NAMESPACE-SUPPORT, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteRequiresTheNodeCapability)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const NodeId nodeId{1, 9402u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const auto original = created.value().get_role_permissions();
  const std::vector<RolePermissionType> proposed{make_role_permission(
    NodeId{ObjectId::WellKnownRole_SecurityAdmin}, {PermissionType::Bit::WriteRolePermissions})};

  EXPECT_EQ(write_role_permissions(sessionInfo, pool.get_executor(), nodeId, proposed).as_status(),
    Status::BadNotWritable);
  EXPECT_EQ(created.value().get_role_permissions(), original);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-050-ROLEPERMISSIONS-WRITE, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteRequiresWriteRolePermissions)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const NodeId nodeId{1, 9403u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  auto callerPermissions = ua::test_helpers::all_permissions();
  callerPermissions.reset(PermissionType::Bit::WriteRolePermissions);
  ua::test_helpers::set_test_node_permissions(created.value(), callerPermissions);
  const std::vector<RolePermissionType> proposed{make_role_permission(
    NodeId{ObjectId::WellKnownRole_SecurityAdmin}, {PermissionType::Bit::WriteRolePermissions})};

  EXPECT_EQ(write_role_permissions(sessionInfo, pool.get_executor(), nodeId, proposed).as_status(),
    Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-052-NO-INOPERABLE-PERMISSIONS, scope=function)
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-NO-GLOBAL-ADMIN, scope=function)
TEST(ServiceAuthorizationTests, OrdinaryNamespaceAcceptsProposalWithoutGlobalAdministratorGrant)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const NodeId nodeId{1, 9404u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const std::vector<RolePermissionType> ordinaryPolicy{
    make_role_permission(ua::test_helpers::test_access_role_id(), {PermissionType::Bit::Read})};

  EXPECT_TRUE(write_role_permissions(sessionInfo, pool.get_executor(), nodeId, ordinaryPolicy).is_good());
  EXPECT_EQ(created.value().get_role_permissions(), ordinaryPolicy);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-052-NO-INOPERABLE-PERMISSIONS, scope=function)
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-DEFERRED, scope=function)
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-NO-GLOBAL-ADMIN, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteWaitsForNamespaceValidationAndPreservesFailure)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  auto controlledNamespace =
    ControlledRolePermissionsNamespace::create("urn:test:role-policy:reject", pool.get_executor(), true);
  controlledNamespace->set_namespace_defaults(
    std::vector<RolePermissionType>{
      make_role_permission(ua::test_helpers::test_access_role_id(), {PermissionType::Bit::Read})},
    std::nullopt);
  const auto namespaceIndex = sessionInfo->address_space().add_namespace_sync(controlledNamespace);
  const NodeId nodeId{namespaceIndex, 9410u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const auto original = created.value().get_role_permissions();
  const std::vector<RolePermissionType> proposal{
    make_role_permission(ua::test_helpers::test_access_role_id(), {PermissionType::Bit::Read})};

  auto entered = controlledNamespace->validation_entered();
  auto pending = start_role_permissions_write(sessionInfo, pool.get_executor(), nodeId, proposal);
  ASSERT_EQ(entered.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(pending.response.wait_for(0ms), std::future_status::timeout);
  EXPECT_EQ(created.value().get_role_permissions(), original)
    << "the Attribute must not mutate before the owning namespace completes validation";

  auto sentinel = StatusCode{Status::BadRequestNotAllowed,
    ErrorDetail::build("SentinelNamespaceOperabilityFailure",
      "The test namespace rejected its prospective policy",
      "ControlledRolePermissionsNamespace")};
  controlledNamespace->complete_validation(VoidResult{sentinel});
  auto response = finish_role_permissions_write(pending);
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].as_status(), Status::BadRequestNotAllowed);
  ASSERT_NE(response.results()[0].shared_detail(), nullptr);
  EXPECT_EQ(response.results()[0].shared_detail()->code, "SentinelNamespaceOperabilityFailure");
  EXPECT_EQ(created.value().get_role_permissions(), original);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-DEFERRED, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteSupportsInlineAndDeferredNamespaceValidation)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const auto testRole = ua::test_helpers::test_access_role_id();
  const std::vector<RolePermissionType> proposal{make_role_permission(testRole, {PermissionType::Bit::Read})};

  auto inlineNamespace =
    ControlledRolePermissionsNamespace::create("urn:test:role-policy:inline", pool.get_executor(), false);
  inlineNamespace->set_namespace_defaults(proposal, std::nullopt);
  const auto inlineIndex = sessionInfo->address_space().add_namespace_sync(inlineNamespace);
  const NodeId inlineNodeId{inlineIndex, 9411u};
  auto inlineNode = sessionInfo->address_space().try_create_node_sync(inlineNodeId, NodeClass::Object, {});
  ASSERT_TRUE(inlineNode.is_good());
  inlineNode.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(inlineNode.value(), ua::test_helpers::all_permissions());

  EXPECT_TRUE(write_role_permissions(sessionInfo, pool.get_executor(), inlineNodeId, proposal).is_good());
  EXPECT_EQ(inlineNamespace->validation_calls(), 1u);
  EXPECT_EQ(inlineNamespace->validated_proposal(), proposal);
  EXPECT_EQ(inlineNode.value().get_role_permissions(), proposal);

  auto deferredNamespace =
    ControlledRolePermissionsNamespace::create("urn:test:role-policy:deferred", pool.get_executor(), true);
  deferredNamespace->set_namespace_defaults(proposal, std::nullopt);
  const auto deferredIndex = sessionInfo->address_space().add_namespace_sync(deferredNamespace);
  const NodeId deferredNodeId{deferredIndex, 9412u};
  auto deferredNode =
    sessionInfo->address_space().try_create_node_sync(deferredNodeId, NodeClass::Object, {});
  ASSERT_TRUE(deferredNode.is_good());
  deferredNode.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(deferredNode.value(), ua::test_helpers::all_permissions());
  const auto deferredOriginal = deferredNode.value().get_role_permissions();

  auto entered = deferredNamespace->validation_entered();
  auto pending = start_role_permissions_write(sessionInfo, pool.get_executor(), deferredNodeId, proposal);
  ASSERT_EQ(entered.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(pending.response.wait_for(0ms), std::future_status::timeout);
  EXPECT_EQ(deferredNode.value().get_role_permissions(), deferredOriginal);
  deferredNamespace->complete_validation(VoidResult{});
  auto response = finish_role_permissions_write(pending);
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].is_good());
  EXPECT_EQ(deferredNamespace->validation_calls(), 1u);
  EXPECT_EQ(deferredNamespace->validated_proposal(), proposal);
  EXPECT_EQ(deferredNode.value().get_role_permissions(), proposal);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-SECADMIN-051-EMPTY-ROLEPERMISSIONS, scope=function)
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-02-DEFERRED, scope=function)
TEST(ServiceAuthorizationTests, EmptyRolePermissionsWriteClearsOnlyAfterNamespaceValidation)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<TestSessionInfo>(pool.get_executor(), true);
  const auto testRole = ua::test_helpers::test_access_role_id();
  const std::vector<RolePermissionType> namespaceDefault{
    make_role_permission(testRole, {PermissionType::Bit::Read})};
  auto controlledNamespace =
    ControlledRolePermissionsNamespace::create("urn:test:role-policy:clear", pool.get_executor(), true);
  controlledNamespace->set_namespace_defaults(namespaceDefault, std::nullopt);
  const auto namespaceIndex = sessionInfo->address_space().add_namespace_sync(controlledNamespace);
  const NodeId nodeId{namespaceIndex, 9405u};
  auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const auto original = created.value().get_role_permissions();

  auto entered = controlledNamespace->validation_entered();
  auto pending = start_role_permissions_write(sessionInfo, pool.get_executor(), nodeId, {});
  ASSERT_EQ(entered.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(pending.response.wait_for(0ms), std::future_status::timeout);
  EXPECT_EQ(created.value().get_role_permissions(), original);
  EXPECT_EQ(controlledNamespace->validation_calls(), 1u);
  EXPECT_FALSE(controlledNamespace->validated_proposal().has_value())
    << "an empty wire array must reach the namespace as a prospective clear, not an explicit deny-all";
  controlledNamespace->complete_validation(VoidResult{});
  auto response = finish_role_permissions_write(pending);
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].is_good());
  EXPECT_FALSE(created.value().get_role_permissions().has_value());
  const auto identity = sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr);
  AccessControl accessControl{sessionInfo->address_space(), 100ms};
  std::promise<std::vector<AccessControl::Verdict>> authorizationPromise;
  auto authorization = authorizationPromise.get_future();
  const std::array items{AccessControl::Item{created.value(), AccessOperation::Read}};
  accessControl.authorize_async(ua::RequestInfo{},
    identity,
    items,
    *sessionInfo->endpoint_security(),
    [&authorizationPromise](std::vector<AccessControl::Verdict> verdicts)
    { authorizationPromise.set_value(std::move(verdicts)); });
  const auto verdicts = authorization.get();
  ASSERT_EQ(verdicts.size(), 1u);
  EXPECT_TRUE(verdicts[0].permitted);
  ::ua::test_utils::drain_with_timeout(pool);
}

// Removed: UserAccessLevelMaskingFailureReturnsZeroWithGoodStatus. Symmetric counterpart
// of UserWriteMaskMaskingFailure: pure verdict projection has no second asynchronous failure
// surface. A denial projects zero directly.

TEST(ServiceAuthorizationTests, ReadUserExecutableIsMaskedByCallPermission)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestSessionInfo>(ex, true);

  const NodeId methodId{1, Guid::create_and_generate()};
  auto methodResult = si->address_space().try_create_sync<MethodAccessor>(methodId, NodeClass::Method);
  ASSERT_TRUE(methodResult.is_good());
  auto& m = methodResult.value();
  m.set_executable(true);
  PermissionType permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Call);
  NodeAccessor methodNode = m;
  ua::test_helpers::set_test_node_permissions(methodNode, permissions);

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = methodId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::UserExecutable);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  ASSERT_TRUE(!rr->results()[0].status() || rr->results()[0].status()->is_good());

  const bool userExec = rr->results()[0].value().as<bool>();
  EXPECT_FALSE(userExec);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 20 section 4.2.1 defines UserWritable as the File's writability after applying the current
// user's access rights. The stored FileHelper value expresses only the static Writable half, so the
// Attribute service must project the owner's live-Value Write verdict into the returned Boolean.
// @relation(AC-SVR-FILE-003-USERWRITABLE, scope=function)
TEST(ServiceAuthorizationTests, FileUserWritableProjectsTheCallingUsersWritePermissionOnItsOwner)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const NodeId fileId{1, 9400u};
  const NodeId userWritableId{1, 9401u};
  const NodeId permittedFileId{1, 9402u};
  const NodeId permittedUserWritableId{1, 9403u};
  auto sessionInfo = std::make_shared<TestSessionInfo>(ex, true);

  auto file = sessionInfo->address_space().create_node_sync(fileId, NodeClass::Object);
  file.set_browse_name(QualifiedName{1, "File"});
  file.set_display_name(LocalizedText{"", "File"});
  file.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FileType});
  auto deniedWritePermissions = ua::test_helpers::all_permissions();
  deniedWritePermissions.reset(PermissionType::Bit::Write);
  ua::test_helpers::set_test_node_permissions(file, deniedWritePermissions);

  auto propertyResult =
    sessionInfo->address_space().try_create_sync<VariableAccessor>(userWritableId, NodeClass::Variable);
  ASSERT_TRUE(propertyResult.is_good());
  auto property = std::move(propertyResult).value();
  property.set_browse_name(QualifiedName{0, "UserWritable"});
  property.set_display_name(LocalizedText{"", "UserWritable"});
  property.set_data_type(NodeId{DataTypeId::Boolean});
  property.set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
  property.write_value_sync(true);
  file.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, userWritableId);
  property.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, fileId, false);

  auto permittedFile = sessionInfo->address_space().create_node_sync(permittedFileId, NodeClass::Object);
  permittedFile.set_browse_name(QualifiedName{1, "PermittedFile"});
  permittedFile.set_display_name(LocalizedText{"", "PermittedFile"});
  permittedFile.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FileType});
  ua::test_helpers::set_test_node_permissions(permittedFile, ua::test_helpers::all_permissions());
  auto permittedPropertyResult = sessionInfo->address_space().try_create_sync<VariableAccessor>(
    permittedUserWritableId, NodeClass::Variable);
  ASSERT_TRUE(permittedPropertyResult.is_good());
  auto permittedProperty = std::move(permittedPropertyResult).value();
  permittedProperty.set_browse_name(QualifiedName{0, "UserWritable"});
  permittedProperty.set_display_name(LocalizedText{"", "UserWritable"});
  permittedProperty.set_data_type(NodeId{DataTypeId::Boolean});
  permittedProperty.set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
  permittedProperty.write_value_sync(true);
  permittedFile.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, permittedUserWritableId);
  permittedProperty.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, permittedFileId, false);

  const auto permittedReferences = permittedProperty.get_references_sync();
  const auto permittedOwner = std::find_if(permittedReferences.begin(),
    permittedReferences.end(),
    [](const Reference& reference)
    { return !reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasProperty}; });
  ASSERT_NE(permittedOwner, permittedReferences.end());
  ASSERT_TRUE(permittedOwner->target_id().is_index_based());
  ASSERT_EQ(permittedOwner->target_id().node_id(), permittedFileId);
  ReadRequest request;
  request.request_header().request_handle() = 1;
  ReadValueId item;
  item.node_id() = userWritableId;
  item.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  request.nodes_to_read().payload().push_back(std::move(item));
  ReadValueId permittedItem;
  permittedItem.node_id() = permittedUserWritableId;
  permittedItem.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  request.nodes_to_read().payload().push_back(std::move(permittedItem));

  std::promise<Response> promise;
  auto future = promise.get_future();
  auto service = AttributeServiceSet::create(sessionInfo,
    {},
    1,
    std::move(request),
    ex,
    [&](Response response) { promise.set_value(std::move(response)); });
  (void)service;

  auto response = wait_for_typed_response<ReadResponse>(future);
  ASSERT_EQ(response.results().size(), 2u);
  ASSERT_TRUE(!response.results()[0].status() || response.results()[0].status()->is_good());
  ASSERT_TRUE(!response.results()[1].status() || response.results()[1].status()->is_good());
  EXPECT_FALSE(response.results()[0].value().as<bool>());
  EXPECT_TRUE(response.results()[1].value().as<bool>());
  ::ua::test_utils::drain_with_timeout(tp);
}

// UserWritable and FileType.Open must be two observations of the same permission. A read-only Open
// does not mutate file contents and remains callable; a write Open is denied before the handler can
// issue a file handle when the caller lacks Write on the owning File Object.
// @relation(AC-SVR-FILE-003-USERWRITABLE, scope=function)
TEST(ServiceAuthorizationTests, MethodCallContextProjectsWritePermissionOnTheCalledObject)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const NodeId fileId{1, 9410u};
  const NodeId openMethodId{1, 9411u};
  const NodeId writableFileId{1, 9412u};
  auto sessionInfo = std::make_shared<TestSessionInfo>(ex, true);

  auto file = sessionInfo->address_space().create_node_sync(fileId, NodeClass::Object);
  file.set_browse_name(QualifiedName{1, "File"});
  file.set_display_name(LocalizedText{"", "File"});
  file.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FileType});
  auto filePermissions = ua::test_helpers::all_permissions();
  filePermissions.reset(PermissionType::Bit::Write);
  ua::test_helpers::set_test_node_permissions(file, filePermissions);

  auto writableFile = sessionInfo->address_space().create_node_sync(writableFileId, NodeClass::Object);
  writableFile.set_browse_name(QualifiedName{1, "WritableFile"});
  writableFile.set_display_name(LocalizedText{"", "WritableFile"});
  writableFile.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::FileType});
  ua::test_helpers::set_test_node_permissions(writableFile, ua::test_helpers::all_permissions());

  auto methodResult =
    sessionInfo->address_space().try_create_sync<MethodAccessor>(openMethodId, NodeClass::Method);
  ASSERT_TRUE(methodResult.is_good());
  auto method = std::move(methodResult).value();
  method.set_browse_name(QualifiedName{0, "Open"});
  method.set_display_name(LocalizedText{"", "Open"});
  method.set_executable(true);
  NodeAccessor methodNodeForPermissions = method;
  ua::test_helpers::set_test_node_permissions(methodNodeForPermissions, ua::test_helpers::all_permissions());
  file.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, openMethodId);
  writableFile.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, openMethodId);

  auto applicationNamespace = std::dynamic_pointer_cast<default_ns::Namespace>(
    sessionInfo->address_space().namespace_array().get_namespace(uint16_t{1}));
  ASSERT_TRUE(applicationNamespace);
  auto methodNode = applicationNamespace->find_node<Node>(openMethodId);
  ASSERT_TRUE(methodNode);
  auto* callSource = methodNode->method_call_source();
  ASSERT_NE(callSource, nullptr);
  auto handlerCalls = std::make_shared<std::atomic_uint32_t>(0);
  auto observedDeniedWrite = std::make_shared<std::atomic_bool>(false);
  auto observedAllowedWrite = std::make_shared<std::atomic_bool>(false);
  ASSERT_TRUE(callSource
                ->set_call_handler(
                  [handlerCalls, observedDeniedWrite, observedAllowedWrite](const CallMethodRequest&,
                    std::shared_ptr<const MethodCallContext>
                      context,
                    std::function<void(CallResult)>
                      complete)
                  {
                    ++*handlerCalls;
                    if (context)
                    {
                      const auto authorization =
                        ua::detail::MethodCallAuthorizationInternalAccess::authorize_object_write(*context);
                      if (authorization.has_value() && authorization->is_bad())
                        *observedDeniedWrite = true;
                      if (authorization.has_value() && authorization->is_good())
                        *observedAllowedWrite = true;
                    }
                    CallMethodResult result;
                    result.status_code() = Status::Good;
                    complete(CallResult{std::move(result)});
                  })
                .is_good());

  CallRequest request;
  request.request_header().request_handle() = 1;
  CallMethodRequest readOpen;
  readOpen.object_id() = fileId;
  readOpen.method_id() = openMethodId;
  readOpen.input_arguments().push_back(Variant{uint8_t{0x01}});
  request.methods_to_call().payload().push_back(std::move(readOpen));
  CallMethodRequest writeOpen;
  writeOpen.object_id() = fileId;
  writeOpen.method_id() = openMethodId;
  writeOpen.input_arguments().push_back(Variant{uint8_t{0x02}});
  request.methods_to_call().payload().push_back(std::move(writeOpen));
  CallMethodRequest allowedWriteOpen;
  allowedWriteOpen.object_id() = writableFileId;
  allowedWriteOpen.method_id() = openMethodId;
  allowedWriteOpen.input_arguments().push_back(Variant{uint8_t{0x02}});
  request.methods_to_call().payload().push_back(std::move(allowedWriteOpen));

  std::promise<Response> promise;
  auto future = promise.get_future();
  auto service = MethodServiceSet::create(sessionInfo,
    {},
    1,
    std::move(request),
    ex,
    [&](Response response) { promise.set_value(std::move(response)); });
  (void)service;

  auto response = wait_for_typed_response<CallResponse>(future);
  ASSERT_EQ(response.results().size(), 3u);
  EXPECT_EQ(response.results()[0].status_code(), Status::Good);
  EXPECT_EQ(response.results()[1].status_code(), Status::Good);
  EXPECT_EQ(response.results()[2].status_code(), Status::Good);
  EXPECT_EQ(handlerCalls->load(), 3u);
  EXPECT_TRUE(observedDeniedWrite->load());
  EXPECT_TRUE(observedAllowedWrite->load());
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Per-item authorization retains its committed AccessIdentity (Stage-2 Theme-1)
// ----------------------------------------------------------------------------
// Each service snapshots `access_identity()` once at start and retains that immutable value across
// asynchronous node resolution. The deterministic poison interface returns null on a second read; success
// therefore proves the continuation did not re-read mutable Session state or accidentally switch to a
// newly activated identity.
// ============================================================================

TEST(ServiceAuthorizationTests, ReadRetainsItsAccessIdentitySnapshotAcrossAsyncResolution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  // A locally-created node forces the async find_node -> per-item gate path (NS0 nodes like RootFolder
  // resolve via a fast path that does not re-read the session context).
  const NodeId nodeId{1, 9300u};
  (void)si->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});

  si->poison_access_identity_after_first_read();

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    ReadService::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  ASSERT_NE(rr, nullptr);
  ASSERT_EQ(rr->results().size(), 1u);
  EXPECT_TRUE(!rr->results()[0].status() || rr->results()[0].status()->is_good());
  EXPECT_EQ(si->access_identity_read_count(), 1u)
    << "one request snapshots one AccessIdentity and retains it across asynchronous node resolution";
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, WriteRetainsItsAccessIdentitySnapshotAcrossAsyncResolution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  const NodeId nodeId{1, 4242u};
  auto createResult = si->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  createResult.value().set_write_mask(ua::AttributeWriteMask{ua::AttributeWriteMask::Bit::DisplayName});

  si->poison_access_identity_after_first_read();

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);
  wv.value() = DataValue{Variant{LocalizedText{"", "new"}}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    AttributeServiceSet::create(si, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* wr = dynamic_cast<WriteResponse*>(resp.second.get());
  ASSERT_NE(wr, nullptr);
  ASSERT_EQ(wr->results().size(), 1u);
  EXPECT_TRUE(wr->results()[0].is_good());
  EXPECT_EQ(si->access_identity_read_count(), 1u)
    << "one request snapshots one AccessIdentity and retains it across asynchronous node resolution";
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, BrowseRetainsItsAccessIdentitySnapshotAcrossAsyncResolution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  const NodeId nodeId{1, 9301u};
  (void)si->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});

  si->poison_access_identity_after_first_read();

  BrowseRequest req;
  req.request_header().request_handle() = 1;
  BrowseDescription bd;
  bd.node_id() = nodeId;
  req.nodes_to_browse().payload().push_back(std::move(bd));

  std::promise<BrowseService::BrowseServiceResponse> p;
  auto fut = p.get_future();
  auto svc = BrowseService::create(si, {}, 1, std::move(req), ex, [&](auto r) { p.set_value(std::move(r)); });
  (void)svc;

  auto r = fut.get();
  auto* br = dynamic_cast<BrowseResponse*>(r.response.second.get());
  ASSERT_NE(br, nullptr);
  ASSERT_EQ(br->results().size(), 1u);
  EXPECT_NE(br->results()[0].status_code(), Status::BadUserAccessDenied);
  EXPECT_EQ(si->access_identity_read_count(), 1u)
    << "one Browse request retains one immutable AccessIdentity snapshot";
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, CallRetainsItsAccessIdentitySnapshotAcrossAsyncResolution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  // Created object + method nodes force the async find_node -> per-item Call gate path.
  const NodeId objectId{1, 9302u};
  const NodeId methodId{1, 9303u};
  (void)si->address_space().try_create_node_sync(objectId, NodeClass::Object, {});
  (void)si->address_space().try_create_sync<MethodAccessor>(methodId, NodeClass::Method);

  si->poison_access_identity_after_first_read();

  CallRequest req;
  req.request_header().request_handle() = 1;
  CallMethodRequest cmr;
  cmr.object_id() = objectId;
  cmr.method_id() = methodId;
  req.methods_to_call().payload().push_back(std::move(cmr));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    MethodServiceSet::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* cr = dynamic_cast<CallResponse*>(resp.second.get());
  ASSERT_NE(cr, nullptr);
  ASSERT_EQ(cr->results().size(), 1u);
  EXPECT_NE(cr->results()[0].status_code(), Status::BadUserAccessDenied);
  EXPECT_EQ(si->access_identity_read_count(), 1u)
    << "one Call request retains one immutable AccessIdentity snapshot";
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ServiceAuthorizationTests, TranslateBrowsePathsRetainsItsAccessIdentitySnapshotAcrossAsyncResolution)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const bool allowAll = true;
  auto si = std::make_shared<TestSessionInfo>(ex, allowAll);

  const NodeId startNodeId{1, 9304u};
  (void)si->address_space().try_create_node_sync(startNodeId, NodeClass::Object, {});

  si->poison_access_identity_after_first_read();

  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;
  BrowsePath bp;
  bp.starting_node() = startNodeId;
  RelativePath rp;
  RelativePathElement el;
  el.reference_type_id() = NodeId{0, ReferenceTypeId::HierarchicalReferences};
  el.is_inverse() = false;
  el.include_subtypes() = true;
  rp.elements().payload().push_back(std::move(el));
  bp.relative_path() = std::move(rp);
  req.browse_paths().payload().push_back(std::move(bp));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = TranslateBrowsePathsService::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* tr = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(resp.second.get());
  ASSERT_NE(tr, nullptr);
  ASSERT_EQ(tr->results().size(), 1u);
  EXPECT_NE(tr->results()[0].status_code(), Status::BadUserAccessDenied);
  EXPECT_EQ(si->access_identity_read_count(), 1u)
    << "one TranslateBrowsePaths request retains one immutable AccessIdentity snapshot";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.2.4 - when the authenticated user lacks the permission to read an Attribute on a
// Node, that entry of `results` is Bad_UserAccessDenied while the Attribute itself remains readable.
// Three ways a plausible implementation gets this wrong: it conflates the user refusal with the
// Attribute refusal (Bad_NotReadable tells a client that no credential will ever help); it lets the
// one denied entry fault the whole Read instead of scattering per entry; or it consults the
// permission only once at request start rather than per Node, so the denial follows every session.
// The permitted arm reads the SAME Node and SAME Attribute with only the Namespace decision changed,
// which is what proves the refusal was the permission and not the Attribute.
// @verifies AC-SVR-ATTR-READ-024-BAD-USERACCESSDENIED
TEST(ServiceAuthorizationTests, ReadWithoutPermissionIsRefusedAndSucceedsForPermittedUser)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const NodeId deniedVarId{1, 9310u};
  const NodeId permittedVarId{1, 9311u};
  const int32_t deniedPayload = 4242;
  const int32_t permittedPayload = 77;

  // A Variable readable in principle: AccessLevel.CurrentRead set and a value actually present, so
  // nothing about the Attribute itself can account for a refusal.
  auto makeReadableVariable = [](AddressSpace as, const NodeId& id, int32_t payload)
  {
    auto varResult = as.try_create_sync<VariableAccessor>(id, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good());
    if (!varResult.is_good())
      return;

    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(al);

    DataValue dv;
    dv.value() = Variant{payload};
    EXPECT_TRUE(varResult.value().try_write_value_sync(std::move(dv)).is_good());
  };

  // --- The user WITHOUT the permission -------------------------------------------------------
  auto deniedSession = std::make_shared<TestSessionInfo>(ex, true);
  makeReadableVariable(deniedSession->address_space(), deniedVarId, deniedPayload);
  makeReadableVariable(deniedSession->address_space(), permittedVarId, permittedPayload);
  auto deniedNode = deniedSession->address_space().try_find_node_sync(deniedVarId);
  ASSERT_TRUE(deniedNode.is_good());
  ua::test_helpers::set_test_node_permissions(deniedNode.value(), PermissionType{});

  ReadRequest deniedReq;
  deniedReq.request_header().request_handle() = 1;
  ReadValueId deniedRvid;
  deniedRvid.node_id() = deniedVarId;
  deniedRvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  deniedReq.nodes_to_read().payload().push_back(std::move(deniedRvid));
  ReadValueId siblingRvid;
  siblingRvid.node_id() = permittedVarId;
  siblingRvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  deniedReq.nodes_to_read().payload().push_back(std::move(siblingRvid));

  std::promise<Response> deniedPromise;
  auto deniedFut = deniedPromise.get_future();
  auto deniedSvc = ReadService::create(deniedSession,
    {},
    1,
    std::move(deniedReq),
    ex,
    [&](Response r) { deniedPromise.set_value(std::move(r)); });
  (void)deniedSvc;

  auto deniedResp = deniedFut.get();
  auto* deniedRead = dynamic_cast<ReadResponse*>(deniedResp.second.get());
  ASSERT_NE(deniedRead, nullptr) << "a denied entry must not fault the whole Read";
  ASSERT_EQ(deniedRead->results().size(), 2u);
  EXPECT_EQ(deniedRead->results()[0].status(), Status::BadUserAccessDenied)
    << "reading an Attribute the user has no permission for must return Bad_UserAccessDenied for "
       "that entry";
  EXPECT_TRUE(!deniedRead->results()[1].status() || deniedRead->results()[1].status()->is_good())
    << "the refusal is per entry: the entry the user may read succeeds in the same Read";
  int32_t siblingValue{};
  ASSERT_NO_THROW(siblingValue = deniedRead->results()[1].value().as<int32_t>());
  EXPECT_EQ(siblingValue, permittedPayload);

  // --- The SAME read as a user WITH the permission --------------------------------------------
  const bool allowAll = true;
  auto permittedSession = std::make_shared<TestSessionInfo>(ex, allowAll);
  makeReadableVariable(permittedSession->address_space(), deniedVarId, deniedPayload);

  ReadRequest permittedReq;
  permittedReq.request_header().request_handle() = 2;
  ReadValueId permittedRvid;
  permittedRvid.node_id() = deniedVarId;
  permittedRvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  permittedReq.nodes_to_read().payload().push_back(std::move(permittedRvid));

  std::promise<Response> permittedPromise;
  auto permittedFut = permittedPromise.get_future();
  auto permittedSvc = ReadService::create(permittedSession,
    {},
    1,
    std::move(permittedReq),
    ex,
    [&](Response r) { permittedPromise.set_value(std::move(r)); });
  (void)permittedSvc;

  auto permittedResp = permittedFut.get();
  auto* permittedRead = dynamic_cast<ReadResponse*>(permittedResp.second.get());
  ASSERT_NE(permittedRead, nullptr);
  ASSERT_EQ(permittedRead->results().size(), 1u);
  EXPECT_TRUE(!permittedRead->results()[0].status() || permittedRead->results()[0].status()->is_good())
    << "the same Node and Attribute must read successfully for a user holding the permission";
  int32_t permittedValue{};
  ASSERT_NO_THROW(permittedValue = permittedRead->results()[0].value().as<int32_t>());
  EXPECT_EQ(permittedValue, deniedPayload);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.2.4 - Bad_UserAccessDenied is the *caller's* refusal, decided against the caller's
// current permission on every Read, and a refused entry carries no data. Two ways a plausible
// implementation gets this wrong that a control arm on a second AddressSpace cannot catch. It can
// bake the first verdict into the Node once resolved - memoising the authorization result, or
// stamping the effective UserAccessLevel to zero on the node - so the denial sticks to the Node for
// every later caller and the permitted read never recovers. Or it can set the refusal StatusCode on
// the entry while still copying the Value in, so the server answers "you may not read this" and
// hands over the very bytes it just refused. This arm holds the AddressSpace, the Node instance and
// the ReadValueId fixed and varies nothing but the Namespace's decision, so the refusal is
// attributable to the permission alone rather than to the Attribute or to the address space.
// @verifies AC-SVR-ATTR-READ-024-BAD-USERACCESSDENIED
TEST(ServiceAuthorizationTests, ReadRefusalFollowsCallerPermissionAndReturnsNoData)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const NodeId varId{1, 9312u};
  const int32_t payload = 8143;

  auto si = std::make_shared<TestSessionInfo>(ex, true);

  // Readable in principle: CurrentRead set and a value actually present, so nothing about the
  // Attribute itself can account for a refusal.
  auto varResult = si->address_space().try_create_sync<VariableAccessor>(varId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  DataValue seed;
  seed.value() = Variant{payload};
  ASSERT_TRUE(varResult.value().try_write_value_sync(std::move(seed)).is_good());
  NodeAccessor permissionNode = varResult.value();
  ua::test_helpers::set_test_node_permissions(permissionNode, PermissionType{});

  // --- The caller WITHOUT the permission ------------------------------------------------------
  ReadRequest deniedReq;
  deniedReq.request_header().request_handle() = 1;
  ReadValueId deniedRvid;
  deniedRvid.node_id() = varId;
  deniedRvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  deniedReq.nodes_to_read().payload().push_back(std::move(deniedRvid));

  std::promise<Response> deniedPromise;
  auto deniedFut = deniedPromise.get_future();
  auto deniedSvc = ReadService::create(
    si, {}, 1, std::move(deniedReq), ex, [&](Response r) { deniedPromise.set_value(std::move(r)); });
  (void)deniedSvc;

  auto deniedResp = deniedFut.get();
  auto* deniedRead = dynamic_cast<ReadResponse*>(deniedResp.second.get());
  ASSERT_NE(deniedRead, nullptr);
  ASSERT_EQ(deniedRead->results().size(), 1u);
  EXPECT_EQ(deniedRead->results()[0].status(), Status::BadUserAccessDenied)
    << "reading an Attribute the caller has no permission for must return Bad_UserAccessDenied";
  EXPECT_TRUE(deniedRead->results()[0].value().empty())
    << "a refused Read must not also hand back the value it refused";

  // --- The SAME Read, same Node, once the caller holds the permission --------------------------
  ua::test_helpers::set_test_node_permissions(permissionNode, ua::test_helpers::all_permissions());

  ReadRequest permittedReq;
  permittedReq.request_header().request_handle() = 2;
  ReadValueId permittedRvid;
  permittedRvid.node_id() = varId;
  permittedRvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  permittedReq.nodes_to_read().payload().push_back(std::move(permittedRvid));

  std::promise<Response> permittedPromise;
  auto permittedFut = permittedPromise.get_future();
  auto permittedSvc = ReadService::create(
    si, {}, 1, std::move(permittedReq), ex, [&](Response r) { permittedPromise.set_value(std::move(r)); });
  (void)permittedSvc;

  auto permittedResp = permittedFut.get();
  auto* permittedRead = dynamic_cast<ReadResponse*>(permittedResp.second.get());
  ASSERT_NE(permittedRead, nullptr);
  ASSERT_EQ(permittedRead->results().size(), 1u);
  EXPECT_TRUE(!permittedRead->results()[0].status() || permittedRead->results()[0].status()->is_good())
    << "the earlier refusal must not persist on the Node once the caller holds the permission";
  ASSERT_FALSE(permittedRead->results()[0].value().empty());
  int32_t permittedPayload{};
  ASSERT_NO_THROW(permittedPayload = permittedRead->results()[0].value().as<int32_t>());
  EXPECT_EQ(permittedPayload, payload);

  ::ua::test_utils::drain_with_timeout(tp);
}

// The RolePermissions write goes to the node's namespace, which may answer by posting to the executor
// the Write runs on. On a one-thread executor a blocking write waits there for an answer that can only
// run there, and the Write never completes; the awaited write must let it complete.
// @relation(AC-SVR-SECADMIN-048-ROLEPERMISSIONS-WRITABLE-WHEN-ALLOWED, scope=function)
TEST(ServiceAuthorizationTests, RolePermissionsWriteCompletesWhenTheNamespaceAnswersByPosting)
{
  ua::test::OneThreadExecutor executor;
  auto sessionInfo = std::make_shared<TestSessionInfo>(executor.executor(), true);
  auto addressSpace = sessionInfo->address_space();
  auto postingNamespace =
    ua::test::PostingWritesNamespace::create("urn:test:posting-writes", executor.executor());
  auto namespaceIndex = addressSpace.try_add_namespace_sync(postingNamespace);
  ASSERT_TRUE(namespaceIndex.is_good());
  RolePermissionType namespacePermission;
  namespacePermission.role_id() = ua::test_helpers::test_access_role_id();
  namespacePermission.permissions() = ua::test_helpers::all_permissions();
  postingNamespace->set_namespace_defaults(
    std::vector<RolePermissionType>{namespacePermission}, std::nullopt);

  const NodeId nodeId{namespaceIndex.value(), 9401u};
  auto created = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  const auto postedBefore = postingNamespace->posted_writes(AttributeId::RolePermissions);
  const NodeId securityAdmin{ObjectId::WellKnownRole_SecurityAdmin};
  const std::vector<RolePermissionType> proposed{
    make_role_permission(securityAdmin, {PermissionType::Bit::WriteRolePermissions}),
    make_role_permission(ua::test_helpers::test_access_role_id(), {PermissionType::Bit::Read})};

  auto pending = start_role_permissions_write(sessionInfo, executor.executor(), nodeId, proposed);
  ASSERT_EQ(pending.response.wait_for(5s), std::future_status::ready)
    << "the RolePermissions write blocked the thread its node's namespace answers on";
  const auto response = finish_role_permissions_write(pending);
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].is_good());
  EXPECT_GT(postingNamespace->posted_writes(AttributeId::RolePermissions), postedBefore)
    << "the Write did not reach the node through the posting namespace";
  EXPECT_EQ(created.value().get_role_permissions(), proposed);
}
