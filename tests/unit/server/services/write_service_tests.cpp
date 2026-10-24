// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "per_item_join.h"

#include <atomic>
#include <future>

#include "ua_attribute_service_set.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_attribute_id.h"
#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_datatype_id.h"
#include "ua_referencetype_id.h"
#include "ua_node.h"
#include "ua_value_rank.h"
#include "ua_variant.h"
#include "ua_default_namespace.h"
#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_service_fault.h"

#include "ua_numeric_range_parser.h"
#include "ua_byte_string.h"
#include "ua_option_set.h"
#include "ua_dynamic_option_set.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"
#include "access_control_test_support.h"
#include "posting_writes_namespace.h"
#include "ua_to_string.h"
#include "ua_diagnostic_bits.h"
#include "ua_object_id.h"
#include "ua_role_permission_type.h"
#include "ua_array.h"
#include "ua_error_detail.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_event_bus.h"
#include "ua_event_notifier_type.h"
#include "ua_date_time.h"
#include "ua_error_detail_keys.h"
#include "ua_value_source.h"
#include "ua_numeric_range_parser.h"

#include <functional>
#include <mutex>
#include <thread>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

class TestWriteSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  TestWriteSessionInfo(boost::asio::any_io_executor ex, bool identityAvailable)
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

  TestWriteSessionInfo(boost::asio::any_io_executor ex, std::nullptr_t)
    : TestWriteSessionInfo(std::move(ex), false)
  {}

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
    return serverCfg;
  }

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
    return mAccessIdentity;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    auto context =
      ua::server::detail::make_diagnostic_security_context(*mSecurity, *mUser, serverCfg.diagnosticPolicy);
    // No DiagnosticInfo is returned on SecurityPolicy None; a test that observes it stands for a secured
    // channel.
    context.securedChannel = context.securedChannel || diagnosticsOnASecuredChannel;
    return context;
  }

  Logger logger() const override
  {
    return {};
  }

  std::shared_ptr<EventSink> event_sink() const override
  {
    // Non-owning: the test owns the sink it sets.
    return eventSink ? std::shared_ptr<EventSink>(eventSink, [](EventSink*) {}) : nullptr;
  }

  ServerConfig serverCfg;
  /// The Server's event sink as this Session sees it; null unless a test that observes audit Events sets it.
  EventSink* eventSink = nullptr;
  /// Whether diagnostics are resolved as for a secured channel; set by a test that observes DiagnosticInfo.
  bool diagnosticsOnASecuredChannel = false;

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
};

auto make_allow_all_authorizer()
{
  return true;
}

WriteResponse do_write(
  std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex, WriteRequest req)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    AttributeServiceSet::create(si, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(2s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Write service timed out";
    return {};
  }

  auto resp = fut.get();
  auto* wr = dynamic_cast<WriteResponse*>(resp.second.get());
  if (!wr)
  {
    // Service fault
    auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
    if (sf)
    {
      WriteResponse result;
      result.response_header() = sf->response_header();
      return result;
    }
    ADD_FAILURE() << "Unexpected response type";
    return {};
  }
  return *wr;
}

DataValue do_read_value(std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex,
  const NodeId& nodeId, AttributeId attributeId)
{
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(attributeId);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  if (!rr || rr->results().empty())
  {
    ADD_FAILURE() << "Read failed";
    return {};
  }
  return rr->results()[0];
}

ReadResponse do_read(
  std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex, ReadRequest req)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(2s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Read service timed out";
    return {};
  }

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  if (!rr)
  {
    auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
    if (sf)
    {
      ReadResponse result;
      result.response_header() = sf->response_header();
      return result;
    }
    ADD_FAILURE() << "Unexpected response type";
    return {};
  }
  return *rr;
}

}  // namespace

// --- Service-Level -----------------------------------------------------------

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-014, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteEmptyRequest_ReturnsBadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  WriteRequest req;
  req.request_header().request_handle() = 1;
  // No nodes_to_write

  auto resp = do_write(si, ex, std::move(req));
  EXPECT_EQ(resp.response_header().service_result(), Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-015, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteTooManyOperations_ReturnsBadTooManyOperations)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerWrite = 1;

  auto as = si->address_space();
  const NodeId nodeId{1, 100u};
  as.try_create_node_sync(nodeId, NodeClass::Variable, {});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (int i = 0; i < 2; ++i)
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{42}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto resp = do_write(si, ex, std::move(req));
  EXPECT_EQ(resp.response_header().service_result(), Status::BadTooManyOperations);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Node Resolution ---------------------------------------------------------

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-018, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteToUnknownNode_ReturnsBadNodeIdUnknown)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = NodeId{1, 9999u};
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Attribute Validation ----------------------------------------------------

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-004, SVR-ATTR-WRITE-019, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteInvalidAttributeId_ReturnsBadAttributeIdInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 200u};
  as.try_create_node_sync(nodeId, NodeClass::Object, {});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = 999;  // Invalid
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadAttributeIdInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Access Control - Value Attribute ----------------------------------------

// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteValueWithCurrentWriteBit_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 300u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-023, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteValueWithoutCurrentWriteBit_ReturnsBadNotWritable)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 301u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);  // No CurrentWrite
  var.set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadNotWritable);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Access Control - Non-Value Attributes -----------------------------------

TEST(WriteServiceTests, WriteDisplayNameWithWriteMaskBit_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 400u};
  auto createResult = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto& node = createResult.value();
  node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  node.set_display_name(LocalizedText{"en", "Original"});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  wv.value().value() = Variant{LocalizedText{"en", "Updated"}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  // Verify the value was actually written
  auto dv = do_read_value(si, ex, nodeId, AttributeId::DisplayName);
  EXPECT_EQ(dv.value().as<LocalizedText>().text(), "Updated");
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-WRITE-023, scope=function)
TEST(WriteServiceTests, WriteDisplayNameWithoutWriteMaskBit_ReturnsBadNotWritable)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 401u};
  auto createResult = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  // No WriteMask set (default: empty)

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  wv.value().value() = Variant{LocalizedText{"en", "Updated"}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadNotWritable);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(WriteServiceTests, WriteDescriptionWithWriteMaskBit_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 402u};
  auto createResult = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto& node = createResult.value();
  node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::Description});
  node.set_description(LocalizedText{"en", "Original"});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Description);
  wv.value().value() = Variant{LocalizedText{"en", "Updated Description"}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Authorization -----------------------------------------------------------

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-024, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteDeniedByNamespace_ReturnsBadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 500u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  NodeAccessor deniedNode = varResult.value();
  ua::test_helpers::set_test_node_permissions(deniedNode, PermissionType{});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-WRITE-024, scope=function)
TEST(WriteServiceTests, WriteWithNoAuthorizer_ReturnsBadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, nullptr);

  auto as = si->address_space();
  const NodeId nodeId{1, 501u};
  as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.58 - a Value change on a Variable whose AccessLevelEx.Constant bit is clear must not
// move the related ConfigurationVersion. The explicit ConfigurationVersion write is the control:
// it proves the version is readable and changeable before the ordinary Value write leaves it alone.
// @relation(AC-SVR-ADDRSP-236-NONCONSTANT-NO-VERSION-BUMP, scope=function)
TEST(WriteServiceTests, NonConstantValueWriteLeavesConfigurationVersionUntouched)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto addressSpace = si->address_space();

  const NodeId processValueId{1, 590u};
  auto processValueResult =
    addressSpace.try_create_sync<VariableAccessor>(processValueId, NodeClass::Variable);
  ASSERT_TRUE(processValueResult.is_good());
  auto& processValue = processValueResult.value();
  processValue.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  processValue.set_access_level_ex(
    AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::CurrentWrite});
  processValue.write_value_sync(int32_t{1});
  const auto accessLevelEx = processValue.get_access_level_ex();
  ASSERT_TRUE(accessLevelEx.has_value());
  EXPECT_FALSE(accessLevelEx->test(AccessLevelExType::Bit::Constant));

  const NodeId configurationVersionId{1, 591u};
  auto configurationVersionResult =
    addressSpace.try_create_sync<VariableAccessor>(configurationVersionId, NodeClass::Variable);
  ASSERT_TRUE(configurationVersionResult.is_good());
  auto& configurationVersion = configurationVersionResult.value();
  configurationVersion.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  configurationVersion.write_value_sync(uint32_t{7});

  const auto writeValue = [&](const NodeId& nodeId, Variant value)
  {
    WriteRequest request;
    request.request_header().request_handle() = 1;
    WriteValue write;
    write.node_id() = nodeId;
    write.attribute_id() = utils::to_underlying(AttributeId::Value);
    write.value().value() = std::move(value);
    request.nodes_to_write().payload().push_back(std::move(write));
    auto response = do_write(si, ex, std::move(request));
    ASSERT_EQ(response.results().size(), 1u);
    EXPECT_TRUE(response.results()[0].is_good());
  };

  writeValue(configurationVersionId, Variant{uint32_t{11}});
  EXPECT_EQ(do_read_value(si, ex, configurationVersionId, AttributeId::Value).value().as<uint32_t>(), 11u);

  writeValue(processValueId, Variant{int32_t{2}});
  EXPECT_EQ(do_read_value(si, ex, processValueId, AttributeId::Value).value().as<int32_t>(), 2);
  EXPECT_EQ(do_read_value(si, ex, configurationVersionId, AttributeId::Value).value().as<uint32_t>(), 11u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- IndexRange --------------------------------------------------------------

// Part 3 section 8.58 makes WriteFullArrayOnly the Node-level declaration that IndexRange writes are not
// supported. Part 4 section section 5.10.4.2 and 5.10.4.4 require exact Bad_WriteNotSupported and prohibit
// any write when that unsupported combination is requested.
// @relation(AC-SVR-ATTR-WRITE-005-INDEXRANGE-NOT-WRITABLE, scope=function)
TEST(WriteServiceTests, WriteFullArrayOnlyRejectsIndexRangeBeforeReadingOrWritingTheValue)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 604u};
  auto variableResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  auto& variable = variableResult.value();
  variable.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable.set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
    AccessLevelExType::Bit::CurrentWrite,
    AccessLevelExType::Bit::WriteFullArrayOnly});

  const Array<int32_t> initial{10, 20, 30, 40};
  variable.write_value_sync(DataValue{Variant{initial}});

  auto* valueSource = variable->external_value_source();
  ASSERT_NE(valueSource, nullptr);
  std::atomic_size_t downstreamReads{0};
  std::atomic_size_t downstreamWrites{0};
  ASSERT_TRUE(valueSource
                ->set_value_source(make_value_source(
                  [initial, &downstreamReads](const ValueSource::ReadContext& /*context*/,
                    const Node&,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      complete)
                  {
                    downstreamReads.fetch_add(1);
                    DataValue value{Variant{initial}};
                    ua::index_range_utils::apply_to_value(value, read.index_range());
                    complete(std::move(value));
                  },
                  [&downstreamWrites](const ValueSource::WriteContext& /*context*/,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      complete)
                  {
                    downstreamWrites.fetch_add(1);
                    complete(ValueSource::Written{});
                  }))
                .is_good());

  WriteRequest request;
  request.request_header().request_handle() = 1;
  WriteValue rangedWrite;
  rangedWrite.node_id() = nodeId;
  rangedWrite.attribute_id() = utils::to_underlying(AttributeId::Value);
  rangedWrite.index_range() = "1";
  rangedWrite.value().value() = Variant{Array<int32_t>{99}};
  request.nodes_to_write().payload().push_back(std::move(rangedWrite));

  auto response = do_write(si, ex, std::move(request));
  ASSERT_EQ(response.results().size(), 1u);
  const StatusCode& result = response.results()[0];
  ASSERT_EQ(result.as_status(), Status::BadWriteNotSupported);
  const auto detail = result.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "IndexRangeWriteNotSupported");
  EXPECT_EQ(detail->summary, "IndexRange writes are not supported when WriteFullArrayOnly is set");
  EXPECT_EQ(detail->source, "AttributeServiceSet");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), to_string(nodeId));

  EXPECT_EQ(downstreamReads.load(), 0u);
  EXPECT_EQ(downstreamWrites.load(), 0u);

  auto after = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_EQ(after.value().as<Array<int32_t>>(), initial);
  EXPECT_EQ(downstreamReads.load(), 1u);
  EXPECT_EQ(downstreamWrites.load(), 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// A clear WriteFullArrayOnly bit is the control: the same valid in-bounds range is supported.
// @relation(AC-SVR-ATTR-WRITE-005-INDEXRANGE-NOT-WRITABLE, scope=function)
TEST(WriteServiceTests, WriteFullArrayOnlyClearAllowsIndexRangeSlice)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 605u};
  auto variableResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  auto& variable = variableResult.value();
  variable.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)
  variable.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable.set_access_level_ex(
    AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::CurrentWrite});
  variable.write_value_sync(DataValue{Variant{Array<int32_t>{10, 20, 30, 40}}});

  WriteRequest request;
  request.request_header().request_handle() = 1;
  WriteValue rangedWrite;
  rangedWrite.node_id() = nodeId;
  rangedWrite.attribute_id() = utils::to_underlying(AttributeId::Value);
  rangedWrite.index_range() = "1";
  rangedWrite.value().value() = Variant{Array<int32_t>{99}};
  request.nodes_to_write().payload().push_back(std::move(rangedWrite));

  auto response = do_write(si, ex, std::move(request));
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].is_good());

  auto after = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_EQ(after.value().as<Array<int32_t>>(), (Array<int32_t>{10, 99, 30, 40}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// WriteFullArrayOnly constrains only IndexRange writes; a whole-array write remains supported.
// @relation(AC-SVR-ATTR-WRITE-005-INDEXRANGE-NOT-WRITABLE, scope=function)
TEST(WriteServiceTests, WriteFullArrayOnlyAllowsWholeArrayWrite)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 606u};
  auto variableResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  auto& variable = variableResult.value();
  variable.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)
  variable.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable.set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
    AccessLevelExType::Bit::CurrentWrite,
    AccessLevelExType::Bit::WriteFullArrayOnly});
  variable.write_value_sync(DataValue{Variant{Array<int32_t>{10, 20, 30, 40}}});

  WriteRequest request;
  request.request_header().request_handle() = 1;
  WriteValue wholeArrayWrite;
  wholeArrayWrite.node_id() = nodeId;
  wholeArrayWrite.attribute_id() = utils::to_underlying(AttributeId::Value);
  wholeArrayWrite.value().value() = Variant{Array<int32_t>{50, 60, 70, 80}};
  request.nodes_to_write().payload().push_back(std::move(wholeArrayWrite));

  auto response = do_write(si, ex, std::move(request));
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].is_good());

  auto after = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_EQ(after.value().as<Array<int32_t>>(), (Array<int32_t>{50, 60, 70, 80}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteWithIndexRange_PartialArrayWrite_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 600u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();
  var.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write initial full array value
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_EQ(initResp.results().size(), 1u);
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Write partial update using IndexRange
  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.index_range() = "1:2";
  wv.value().value() = Variant{Array<int32_t>{99, 88}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  // Read back and verify
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto& arr = dv.value().as<Array<int32_t>>();
  ASSERT_EQ(arr.size(), 5u);
  EXPECT_EQ(arr[0], 10);
  EXPECT_EQ(arr[1], 99);
  EXPECT_EQ(arr[2], 88);
  EXPECT_EQ(arr[3], 40);
  EXPECT_EQ(arr[4], 50);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-ATTR-WRITE-020-INDEXRANGEINVALID, scope=function)
TEST(WriteServiceTests, WriteWithIndexRange_SizeMismatch_ReturnsBadIndexRangeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 601u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();
  var.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write initial array
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{Array<int32_t>{10, 20, 30}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Write with wrong number of elements for range
  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.index_range() = "0:1";
  wv.value().value() = Variant{Array<int32_t>{99, 88, 77}};  // 3 elements for 2-element range
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadIndexRangeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-020, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteWithIndexRange_InvalidSyntax_ReturnsBadIndexRangeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 602u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.index_range() = "abc";
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadIndexRangeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-021, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteWithIndexRange_OnScalar_ReturnsBadIndexRangeNoData)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 603u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write initial scalar value
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{int32_t{42}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Try to write with index range on non-indexable scalar
  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.index_range() = "0";
  wv.value().value() = Variant{int32_t{99}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadIndexRangeNoData);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- The written value against the IndexRange (NR-11 rule 1, DL-115 (1)) ----------------------------------

namespace
{

// What a ranged write answered, and how often the Variable's value source was asked to read and to write.
struct RangedWriteOutcome
{
  StatusCode result;
  std::size_t reads{0};
  std::size_t writes{0};
};

// Writes @p value with @p range to a Variable of DataType @p dataType and ValueRank @p rank whose Value an
// application source holds. The source accepts every write, so a refusal comes from the Write service.
RangedWriteOutcome ranged_write(DataTypeId dataType, int32_t rank, const char* range, Variant value)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  RangedWriteOutcome outcome;
  {
    auto as = si->address_space();
    const NodeId nodeId{1, 650u};
    auto created = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    if (created.is_bad())
    {
      ADD_FAILURE() << "creating the Variable: " << to_string(created.status_code());
      return outcome;
    }
    auto& variable = created.value();
    variable.set_data_type(NodeId{dataType});
    variable.set_value_rank(ValueRank{rank});
    variable.set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto reads = std::make_shared<std::atomic_size_t>(0);
    auto writes = std::make_shared<std::atomic_size_t>(0);
    const auto attached = variable->external_value_source()->set_value_source(make_value_source(
      [reads](const ValueSource::ReadContext&,
        const Node&,
        const ReadValueId&,
        std::function<void(DataValueResult)>
          complete)
      {
        reads->fetch_add(1);
        complete(DataValue{});
      },
      [writes](const ValueSource::WriteContext&,
        const Node&,
        const WriteValue&,
        std::function<void(ValueSource::WriteResult)>
          complete)
      {
        writes->fetch_add(1);
        complete(ValueSource::Written{});
      }));
    if (attached.is_bad())
    {
      ADD_FAILURE() << "attaching the source: " << to_string(attached.status_code());
      return outcome;
    }

    WriteRequest request;
    request.request_header().request_handle() = 1;
    WriteValue write;
    write.node_id() = nodeId;
    write.attribute_id() = utils::to_underlying(AttributeId::Value);
    write.index_range() = range;
    write.value().value() = std::move(value);
    request.nodes_to_write().payload().push_back(std::move(write));
    auto response = do_write(si, ex, std::move(request));
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Write answered " << response.results().size() << " results";
      return outcome;
    }
    outcome.result = response.results()[0];
    outcome.reads = reads->load();
    outcome.writes = writes->load();
  }
  ::ua::test_utils::drain_with_timeout(tp);
  return outcome;
}

// Expects @p outcome to be refused with @p status before the value source saw the write.
void expect_refused_before_the_source(const RangedWriteOutcome& outcome, Status status, const char* what)
{
  EXPECT_EQ(outcome.result.as_status(), status) << what << ": " << to_string(outcome.result);
  EXPECT_EQ(outcome.reads, 0u) << what << ": the Value was read";
  EXPECT_EQ(outcome.writes, 0u) << what << ": the write reached the source";
}

// Expects @p outcome to have reached the value source, which accepted it.
void expect_written_by_the_source(const RangedWriteOutcome& outcome, const char* what)
{
  EXPECT_TRUE(outcome.result.is_good()) << what << ": " << to_string(outcome.result);
  EXPECT_EQ(outcome.writes, 1u) << what << ": the write did not reach the source";
}

}  // namespace

// (a) The value of a ranged write is an array, even of one element (Part 4 5.10.4.2, Table 59). The controls:
// a substring of a scalar String is written as a String, and a ByteString stands for an array of Byte.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-25-A-RANGED-WRITE-VALUE-THAT-IS-NOT-AN-ARRAY-IS-TYPE-MISMATCH, scope=function)
TEST(RangedWriteShape, AValueThatIsNotAnArrayIsTypeMismatch)
{
  expect_refused_before_the_source(ranged_write(DataTypeId::Int32, 1, "1", Variant{int32_t{99}}),
    Status::BadTypeMismatch,
    "an Int32 for one element of an Int32 array");
  expect_refused_before_the_source(ranged_write(DataTypeId::String, 1, "1", Variant{String{"x"}}),
    Status::BadTypeMismatch,
    "a String for one element of a String array");
  expect_refused_before_the_source(ranged_write(DataTypeId::String,
                                     ValueRank::scalar,
                                     "1:3",
                                     Variant{Array<String>{String{"a"}, String{"b"}, String{"c"}}}),
    Status::BadTypeMismatch,
    "a String array for a substring of a scalar String");

  expect_written_by_the_source(
    ranged_write(DataTypeId::Int32, 1, "1", Variant{Array<int32_t>{99}}), "a one-element Int32 array");
  expect_written_by_the_source(
    ranged_write(DataTypeId::String, ValueRank::scalar, "1:3", Variant{String{"abc"}}),
    "a String for a substring of a scalar String");
  expect_written_by_the_source(
    ranged_write(DataTypeId::Byte, 1, "0:2", Variant{ByteString{std::vector<uint8_t>{1, 2, 3}}}),
    "a ByteString for three elements of a Byte array");
}

// (b) The value's size in each dimension equals the range's (Part 4 7.27), whatever the Value held: a range
// reaching past a five-element Value, written with a value sized to the part that exists, is refused. A value
// without ArrayDimensions holds as many elements as a multi-dimensional range selects.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-25-A-RANGED-WRITE-VALUE-OF-ANOTHER-SIZE-IS-INDEX-RANGE-INVALID, scope=function)
TEST(RangedWriteShape, AValueOfAnotherSizeThanTheRangeIsIndexRangeInvalid)
{
  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32, 1, "2:9", Variant{Array<int32_t>{1, 2, 3}}),
    Status::BadIndexRangeInvalid,
    "three elements for the range 2:9");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32, 1, "0:1", Variant{Array<int32_t>{1, 2, 3}}),
    Status::BadIndexRangeInvalid,
    "three elements for the range 0:1");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32,
      2,
      "0:1,1:2",
      Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6}}}),
    Status::BadIndexRangeInvalid,
    "a 2x3 matrix for a 2x2 range");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::String, ValueRank::scalar, "1:3", Variant{String{"ab"}}),
    Status::BadIndexRangeInvalid,
    "two characters for a three-character substring");

  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32, 2, "0:1,1:2", Variant{Array<int32_t>{1, 2, 3}}),
    Status::BadIndexRangeInvalid,
    "three elements without ArrayDimensions for a 2x2 range");

  expect_written_by_the_source(
    ranged_write(DataTypeId::Int32, 1, "2:9", Variant{Array<int32_t>{1, 2, 3, 4, 5, 6, 7, 8}}),
    "eight elements for the range 2:9, the Value held being the source's to judge");
  expect_written_by_the_source(ranged_write(DataTypeId::Int32,
                                 2,
                                 "0:1,1:2",
                                 Variant{Array<int32_t>{Dimensions{2, 2}, std::vector<int32_t>{1, 2, 3, 4}}}),
    "a 2x2 matrix for a 2x2 range");
  expect_written_by_the_source(
    ranged_write(DataTypeId::Int32, 2, "0:1,1:2", Variant{Array<int32_t>{1, 2, 3, 4}}),
    "four elements without ArrayDimensions for a 2x2 range, placed in row-major order");
}

// (c) A String or ByteString array whose range names a substring: the element count and each element's length
// match the range.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-25-A-SUBSTRING-WRITE-ELEMENT-OF-ANOTHER-LENGTH-IS-INDEX-RANGE-INVALID, scope=function)
TEST(RangedWriteShape, ASubstringWriteElementOfAnotherLengthIsIndexRangeInvalid)
{
  expect_refused_before_the_source(
    ranged_write(DataTypeId::String, 1, "0:1,0:2", Variant{Array<String>{String{"abc"}, String{"de"}}}),
    Status::BadIndexRangeInvalid,
    "a two-character element for a three-character substring");
  expect_refused_before_the_source(ranged_write(DataTypeId::ByteString,
                                     1,
                                     "0:1,0:1",
                                     Variant{Array<ByteString>{ByteString{std::vector<uint8_t>{1, 2}},
                                       ByteString{std::vector<uint8_t>{3, 4, 5}}}}),
    Status::BadIndexRangeInvalid,
    "a three-byte element for a two-byte substring");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::String, 1, "0:2,0:1", Variant{Array<String>{String{"ab"}, String{"cd"}}}),
    Status::BadIndexRangeInvalid,
    "two elements for three");

  expect_written_by_the_source(
    ranged_write(DataTypeId::String, 1, "0:1,0:2", Variant{Array<String>{String{"abc"}, String{"def"}}}),
    "two three-character elements for the substring 0:2 of elements 0:1");
}

// (d) Where the ValueRank is Scalar or n, the range has n dimensions, or n + 1 for a String or ByteString:
// Bad_IndexRangeNoData for a scalar or one-dimensional Value, Bad_IndexRangeInvalid for a matrix
// (SVR-ATTR-WRITE-020, -021). With ValueRank Any the rank fit is left to whoever holds the data.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-25-A-RANGE-THAT-DOES-NOT-FIT-A-FIXED-VALUE-RANK-IS-REFUSED, scope=function)
TEST(RangedWriteShape, ARangeThatDoesNotFitAFixedValueRankIsRefused)
{
  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32, ValueRank::scalar, "0", Variant{Array<int32_t>{1}}),
    Status::BadIndexRangeNoData,
    "a range on a scalar Int32");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::Int32,
      1,
      "0:1,0:1",
      Variant{Array<int32_t>{Dimensions{2, 2}, std::vector<int32_t>{1, 2, 3, 4}}}),
    Status::BadIndexRangeNoData,
    "a two-dimension range on an Int32 array");
  expect_refused_before_the_source(ranged_write(DataTypeId::Int32, 2, "0:1", Variant{Array<int32_t>{1, 2}}),
    Status::BadIndexRangeInvalid,
    "a one-dimension range on an Int32 matrix");
  expect_refused_before_the_source(
    ranged_write(DataTypeId::String,
      1,
      "0:1,0:1,0:1",
      Variant{Array<String>{Dimensions{2, 2}, std::vector<String>(4, String{"ab"})}}),
    Status::BadIndexRangeNoData,
    "a three-dimension range on a String array");

  expect_written_by_the_source(ranged_write(DataTypeId::Int32,
                                 ValueRank::any,
                                 "0:1,0:1",
                                 Variant{Array<int32_t>{Dimensions{2, 2}, std::vector<int32_t>{1, 2, 3, 4}}}),
    "a two-dimension range with ValueRank Any");
}

// --- Timestamps --------------------------------------------------------------

// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-007, SVR-ATTR-WRITE-031, scope=function)
TEST(WriteServiceTests, WriteWithSourceTimestamp_Preserved)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 700u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  al.set(AccessLevelType::Bit::TimestampWrite);  // it writes a SourceTimestamp (Part 3 section 8.57)
  varResult.value().set_access_level(al);

  auto sourceTs = DateTime::now();

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{99}};
  wv.value().source_timestamp() = sourceTs;
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  // Read back and verify the value
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_EQ(dv.value().as<int32_t>(), 99);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Multi-Operation ---------------------------------------------------------

TEST(WriteServiceTests, WriteMultipleNodes_AllSucceed)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId1{1, 800u};
  const NodeId nodeId2{1, 801u};

  auto v1 = as.try_create_sync<VariableAccessor>(nodeId1, NodeClass::Variable);
  auto v2 = as.try_create_sync<VariableAccessor>(nodeId2, NodeClass::Variable);
  ASSERT_TRUE(v1.is_good());
  ASSERT_TRUE(v2.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentWrite);
  v1.value().set_access_level(al);
  v2.value().set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;

  WriteValue wv1;
  wv1.node_id() = nodeId1;
  wv1.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv1.value().value() = Variant{int32_t{10}};
  req.nodes_to_write().payload().push_back(std::move(wv1));

  WriteValue wv2;
  wv2.node_id() = nodeId2;
  wv2.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv2.value().value() = Variant{int32_t{20}};
  req.nodes_to_write().payload().push_back(std::move(wv2));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_TRUE(resp.results()[0].is_good());
  EXPECT_TRUE(resp.results()[1].is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(WriteServiceTests, WriteMultipleNodes_PartialFailure)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId goodNodeId{1, 810u};
  const NodeId badNodeId{1, 811u};

  auto varResult = as.try_create_sync<VariableAccessor>(goodNodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);

  // badNodeId doesn't exist

  WriteRequest req;
  req.request_header().request_handle() = 1;

  WriteValue wv1;
  wv1.node_id() = goodNodeId;
  wv1.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv1.value().value() = Variant{int32_t{10}};
  req.nodes_to_write().payload().push_back(std::move(wv1));

  WriteValue wv2;
  wv2.node_id() = badNodeId;
  wv2.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv2.value().value() = Variant{int32_t{20}};
  req.nodes_to_write().payload().push_back(std::move(wv2));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_TRUE(resp.results()[0].is_good());
  EXPECT_EQ(resp.results()[1], Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Value on non-Variable ---------------------------------------------------

// @relation(SVR-ATTR-WRITE-019, scope=function)
TEST(WriteServiceTests, WriteValueOnObject_ReturnsBadAttributeIdInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 900u};
  as.try_create_node_sync(nodeId, NodeClass::Object, {});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadAttributeIdInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- A VariableType's Value (Part 3 section 8.60, WriteMask bit 21)
// -----------------------------------------

namespace
{

// A VariableType of DataType Int32 with the given ValueRank and Value, whose WriteMask sets or clears bit 21
// (ValueForVariableType).
NodeId create_variable_type(AddressSpace& as, uint32_t id, bool valueForVariableType, int32_t valueRank,
  Variant value, NodeId dataType = NodeId{DataTypeId::Int32})
{
  const NodeId typeId{1, id};
  auto created = as.try_create_node_sync(typeId, NodeClass::VariableType, {});
  EXPECT_TRUE(created.is_good()) << "the VariableType could not be created";
  if (created.is_bad())
    return typeId;
  auto type = created.value().as<VariableTypeAccessor>();
  EXPECT_TRUE(type.has_value());
  if (!type.has_value())
    return typeId;
  type->set_data_type(std::move(dataType));
  type->set_value_rank(ValueRank{valueRank});
  type->set_value(DataValue{std::move(value)});
  type->set_write_mask(valueForVariableType
                         ? AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType}
                         : AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  return typeId;
}

WriteRequest value_write(const NodeId& nodeId, Variant value, const char* indexRange = nullptr)
{
  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  if (indexRange != nullptr)
    wv.index_range() = indexRange;
  wv.value().value() = std::move(value);
  req.nodes_to_write().payload().push_back(std::move(wv));
  return req;
}

// The VariableType's Value as a client Reads it; the test fails, naming the status, when the Read is not
// Good.
std::string read_type_value(
  std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex, const NodeId& typeId)
{
  const auto dv = do_read_value(std::move(si), std::move(ex), typeId, AttributeId::Value);
  const auto status = dv.status().value_or(StatusCode{Status::Good});
  EXPECT_EQ(status.as_status(), Status::Good)
    << "reading the VariableType's Value answered " << to_string(status);
  return to_string(dv.value());
}

}  // namespace

// @relation(AC-SVR-ATTR-WRITE-032-BIT21-SET-ACCEPTED, scope=function)
TEST(VariableTypeValueWrite, AcceptedWhenBit21IsSet)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1500u, true, ValueRank::scalar, Variant{int32_t{7}});

  auto resp = do_write(si, ex, value_write(typeId, Variant{int32_t{42}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::Good);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{42}}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-ATTR-WRITE-032-BIT21-CLEAR-NOTWRITABLE, scope=function)
TEST(VariableTypeValueWrite, RefusedWhenBit21IsClear)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1501u, false, ValueRank::scalar, Variant{int32_t{7}});

  auto resp = do_write(si, ex, value_write(typeId, Variant{int32_t{42}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::BadNotWritable);
  ASSERT_NE(resp.results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp.results()[0].shared_detail()->code, "NotWritable");
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{7}}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-ATTR-WRITE-032-VALUE-TYPE-MISMATCH, scope=function)
TEST(VariableTypeValueWrite, AValueOfTheWrongTypeOrShapeIsTypeMismatch)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1502u, true, ValueRank::scalar, Variant{int32_t{7}});

  auto wrongType = do_write(si, ex, value_write(typeId, Variant{String{"seven"}}));
  ASSERT_EQ(wrongType.results().size(), 1u);
  EXPECT_EQ(wrongType.results()[0].as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{7}}));

  auto wrongShape = do_write(si, ex, value_write(typeId, Variant{Array<int32_t>{1, 2}}));
  ASSERT_EQ(wrongShape.results().size(), 1u);
  EXPECT_EQ(wrongShape.results()[0].as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{7}}));

  auto control = do_write(si, ex, value_write(typeId, Variant{int32_t{42}}));
  ASSERT_EQ(control.results().size(), 1u);
  EXPECT_EQ(control.results()[0].as_status(), Status::Good);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{42}}));

  // A DataType that is a subtype of a built-in type: Duration (i=290) is a Double. This fixture has no
  // namespace 0, so the DataType Nodes and the HasSubtype between them are created here, as the NodeSet
  // would provide them; without them the type check cannot find Duration's built-in base. The address space
  // adds the HasSubtype's forward half on Double (NR-70 B8).
  const NodeId doubleDataType{DataTypeId::Double};
  const NodeId durationDataType{DataTypeId::Duration};
  if (as.try_find_node_sync(doubleDataType).is_bad())
  {
    ASSERT_TRUE(as.try_create_sync<DataTypeAccessor>(doubleDataType, NodeClass::DataType).is_good());
  }
  auto duration = as.try_create_sync<DataTypeAccessor>(durationDataType, NodeClass::DataType);
  ASSERT_TRUE(duration.is_good());
  ASSERT_TRUE(
    duration.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{doubleDataType}, false)
      .is_good());
  const auto durationTypeId = create_variable_type(
    as, 1504u, true, ValueRank::scalar, Variant{double{1.5}}, NodeId{DataTypeId::Duration});
  auto durationString = do_write(si, ex, value_write(durationTypeId, Variant{String{"PT1S"}}));
  ASSERT_EQ(durationString.results().size(), 1u);
  EXPECT_EQ(durationString.results()[0].as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(read_type_value(si, ex, durationTypeId), to_string(Variant{double{1.5}}));

  auto durationDouble = do_write(si, ex, value_write(durationTypeId, Variant{double{2.5}}));
  ASSERT_EQ(durationDouble.results().size(), 1u);
  EXPECT_EQ(durationDouble.results()[0].as_status(), Status::Good);
  EXPECT_EQ(read_type_value(si, ex, durationTypeId), to_string(Variant{double{2.5}}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-ATTR-WRITE-032-INDEXRANGE-WRITENOTSUPPORTED, scope=function)
TEST(VariableTypeValueWrite, AnIndexRangeWriteIsWriteNotSupported)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1503u, true, 1, Variant{Array<int32_t>{1, 2, 3}});

  auto resp = do_write(si, ex, value_write(typeId, Variant{Array<int32_t>{9}}, "1"));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::BadWriteNotSupported);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{Array<int32_t>{1, 2, 3}}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- A VariableType's Value: the Permission that authorizes the write, and a null write (DL-28, DL-29) -----

namespace
{

// An Int32 Variable whose AccessLevel sets CurrentRead and CurrentWrite, holding 0.
NodeId create_writable_variable(AddressSpace& as, uint32_t id)
{
  const NodeId variableId{1, id};
  auto created = as.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  EXPECT_TRUE(created.is_good()) << "the Variable could not be created";
  if (created.is_bad())
    return variableId;
  auto& variable = created.value();
  variable.set_data_type(NodeId{DataTypeId::Int32});
  variable.set_value_rank(ValueRank{ValueRank::scalar});
  variable.set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable.write_value_sync(int32_t{0});
  return variableId;
}

// Gives the test Session's Role exactly @p permissions on @p nodeId: the Session holds that Role and no
// other.
void grant_on_node(AddressSpace& as, const NodeId& nodeId, PermissionType permissions)
{
  auto node = as.find_node_sync(nodeId);
  ua::test_helpers::set_test_node_permissions(node, permissions);
}

WriteRequest value_writes(std::vector<std::pair<NodeId, Variant>> items)
{
  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (auto& [nodeId, value] : items)
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = std::move(value);
    req.nodes_to_write().payload().push_back(std::move(wv));
  }
  return req;
}

// The UserWriteMask a Read of @p nodeId returns to the Session; the test fails when the Read is not Good.
AttributeWriteMask user_write_mask(
  std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex, const NodeId& nodeId)
{
  const auto dv = do_read_value(std::move(si), std::move(ex), nodeId, AttributeId::UserWriteMask);
  const auto status = dv.status().value_or(StatusCode{Status::Good});
  EXPECT_EQ(status.as_status(), Status::Good) << "reading the UserWriteMask answered " << to_string(status);
  const auto* mask = dv.value().try_as<uint32_t>();
  return mask == nullptr ? AttributeWriteMask{} : AttributeWriteMask{*mask};
}

// A status and the code of its ErrorDetail, for a failure message.
std::string status_and_detail(const StatusCode& status)
{
  return to_string(status) + (status.shared_detail() ? " (" + status.shared_detail()->code + ")" : "");
}

}  // namespace

// Part 3 section 8.55, Table 37: WriteAttribute "affects the value of a UserWriteMask Attribute" and is
// "valid for all NodeClasses"; Write is "only valid for Variables". DL-28: a VariableType's Value, gated by
// WriteMask bit 21, is authorized for WriteAttribute, so a Session holding WriteAttribute and not Write
// writes it and reads bit 21 set in its UserWriteMask. The Variable V is the control that a Variable's Value
// still asks for Write.
// @relation(AC-SVR-ATTR-WRITE-032-WRITEATTRIBUTE-AUTHORIZES, scope=function)
TEST(VariableTypeValueWrite, WriteAttributeWithoutWriteIsAuthorized)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1505u, true, ValueRank::scalar, Variant{int32_t{7}});
  const auto variableId = create_writable_variable(as, 1506u);
  const PermissionType roleA{
    {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::WriteAttribute}};
  grant_on_node(as, typeId, roleA);
  grant_on_node(as, variableId, roleA);

  EXPECT_TRUE(user_write_mask(si, ex, typeId).test(AttributeWriteMask::Bit::ValueForVariableType))
    << "the UserWriteMask of T does not set bit 21 for a Session holding WriteAttribute";
  auto resp =
    do_write(si, ex, value_writes({{typeId, Variant{int32_t{9}}}, {variableId, Variant{int32_t{9}}}}));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::Good)
    << "the write of T's Value answered " << status_and_detail(resp.results()[0]);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{9}}));
  EXPECT_EQ(resp.results()[1].as_status(), Status::BadUserAccessDenied)
    << "the write of V's Value answered " << status_and_detail(resp.results()[1]);
  ::ua::test_utils::drain_with_timeout(tp);
}

// DL-28, the other half of the pair: a Session holding Write and not WriteAttribute reads bit 21 clear and is
// refused T's Value with Bad_UserAccessDenied, as the well-known Operator is; it still writes V's Value.
// @relation(AC-SVR-ATTR-WRITE-032-WRITE-WITHOUT-WRITEATTRIBUTE-DENIED, scope=function)
TEST(VariableTypeValueWrite, WriteWithoutWriteAttributeIsUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1507u, true, ValueRank::scalar, Variant{int32_t{7}});
  const auto variableId = create_writable_variable(as, 1508u);
  const PermissionType roleB{
    {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write}};
  grant_on_node(as, typeId, roleB);
  grant_on_node(as, variableId, roleB);

  EXPECT_FALSE(user_write_mask(si, ex, typeId).test(AttributeWriteMask::Bit::ValueForVariableType))
    << "the UserWriteMask of T sets bit 21 for a Session without WriteAttribute";
  auto resp =
    do_write(si, ex, value_writes({{typeId, Variant{int32_t{11}}}, {variableId, Variant{int32_t{11}}}}));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::BadUserAccessDenied)
    << "the write of T's Value answered " << status_and_detail(resp.results()[0]);
  EXPECT_EQ(read_type_value(si, ex, typeId), to_string(Variant{int32_t{7}}));
  EXPECT_EQ(resp.results()[1].as_status(), Status::Good)
    << "the write of V's Value answered " << status_and_detail(resp.results()[1]);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.60: an Attribute the Node does not support has its WriteMask bit clear; section 8.7: null
// "indicat[es] that a value is not present". DL-29: a null write of T's Value is held as a null value, so the
// Read answers Good with null rather than Bad_AttributeIdInvalid. U, created without a Value, is the control
// that a VariableType holding no Value still lacks the Attribute.
// @relation(AC-SVR-ATTR-WRITE-032-NULL-WRITE-HELD, scope=function)
TEST(VariableTypeValueWrite, ANullWriteIsHeldAndReadsGoodWithANullValue)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto typeId = create_variable_type(as, 1509u, true, ValueRank::scalar, Variant{int32_t{7}});
  const NodeId withoutValueId{1, 1510u};
  {
    auto created = as.try_create_node_sync(withoutValueId, NodeClass::VariableType, {});
    ASSERT_TRUE(created.is_good()) << "the VariableType U could not be created";
    auto type = created.value().as<VariableTypeAccessor>();
    ASSERT_TRUE(type.has_value());
    type->set_data_type(NodeId{DataTypeId::Int32});
    type->set_value_rank(ValueRank{ValueRank::scalar});
    type->set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
  }

  auto resp = do_write(si, ex, value_write(typeId, Variant{}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::Good)
    << "the null write of T's Value answered " << status_and_detail(resp.results()[0]);
  const auto held = do_read_value(si, ex, typeId, AttributeId::Value);
  EXPECT_EQ(held.status().value_or(StatusCode{Status::Good}).as_status(), Status::Good)
    << "the Read of T's Value answered " << to_string(held.status().value_or(StatusCode{Status::Good}));
  EXPECT_TRUE(held.value().empty()) << "T's Value reads " << to_string(held.value());

  const auto none = do_read_value(si, ex, withoutValueId, AttributeId::Value);
  EXPECT_EQ(none.status().value_or(StatusCode{Status::Good}).as_status(), Status::BadAttributeIdInvalid)
    << "the Read of U's Value answered " << to_string(none.status().value_or(StatusCode{Status::Good}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- A VariableType's Value in either held form (DL-30) ---------------------------------------------------

namespace
{

// The Values a RawValueNamespace's VariableTypes hold, exactly as written. Each is written before a reader
// runs (the write completes on the writing thread; a Read is posted after it), so no lock is taken.
struct RawValues
{
  std::vector<std::pair<NodeId, Variant>> held;

  const Variant* find(const NodeId& nodeId) const
  {
    for (const auto& [id, value] : held)
    {
      if (id == nodeId)
        return &value;
    }
    return nullptr;
  }

  void store(const NodeId& nodeId, Variant value)
  {
    for (auto& [id, stored] : held)
    {
      if (id == nodeId)
      {
        stored = std::move(value);
        return;
      }
    }
    held.emplace_back(nodeId, std::move(value));
  }
};

// The in-memory Node's description, except that a VariableType's Value is the one RawValues holds exactly as
// it was written, without the conversion the in-memory Node makes; the description takes it in either form,
// as a write of it would.
class RawValueNode final : public Node
{
public:
  RawValueNode(shared_ptr<Node> inner, std::shared_ptr<RawValues> values)
    : mInner(std::move(inner)), mValues(std::move(values))
  {}

  NodeDescription attributes() const override
  {
    NodeDescription described = mInner->attributes();
    if (described.node_class() == NodeClass::VariableType)
    {
      if (const auto* held = mValues->find(described.node_id()))
      {
        return described.try_with_attribute(AttributeId::Value, *held).value();
      }
    }
    return described;
  }

  bool deleted() const noexcept override
  {
    return mInner->deleted();
  }

  /// The in-memory Node this one describes.
  const Node& inner() const
  {
    return *mInner;
  }

  /// Whether @p write is of a VariableType's Value, which this Node holds as it is written.
  bool holds_as_written(const WriteValue& write) const
  {
    return static_cast<AttributeId>(write.attribute_id()) == AttributeId::Value &&
           mInner->attributes().node_class() == NodeClass::VariableType;
  }

  ExternalValueSource* external_value_source() noexcept override
  {
    return mInner->external_value_source();
  }

  MethodCallSource* method_call_source() noexcept override
  {
    return mInner->method_call_source();
  }

private:
  shared_ptr<Node> mInner;
  std::shared_ptr<RawValues> mValues;
};

// A namespace whose VariableType Nodes store the Value as it is written, as InitialAttributes (ua_node.h)
// allows any namespace to: every Node it resolves is a RawValueNode over the in-memory Node, whose
// References, Values and other writes are the in-memory Node's.
class RawValueNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<RawValueNamespace> create(string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<RawValueNamespace>(new RawValueNamespace(uri, std::move(executor)));
  }

  /// The Value @p nodeId holds exactly as it was written, or null when none was.
  const Variant* held_value(const NodeId& nodeId) const
  {
    return mValues->find(nodeId);
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    std::vector<ReferenceQuery> own;
    own.reserve(queries.size());
    for (const ReferenceQuery& query : queries)
    {
      own.push_back(ReferenceQuery{.node = in_memory(query.node),
        .nodeId = query.nodeId,
        .direction = query.direction,
        .referenceTypeHint = query.referenceTypeHint,
        .maxReferences = query.maxReferences,
        .resumeToken = query.resumeToken});
    }
    default_ns::Namespace::read_references_async(request, own, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    std::vector<ValueReadItem> own;
    own.reserve(items.size());
    for (const ValueReadItem& item : items)
    {
      own.push_back(ValueReadItem{in_memory(item.node), item.value});
    }
    default_ns::Namespace::read_values_async(
      request, caller, own, maxAge, setSourceTimestamp, std::move(complete));
  }

  /// A VariableType's Value is held as it is written: a DataValue with a status or a timestamp as that
  /// DataValue, a value alone as its Variant. Every other item is written by the in-memory member, to the
  /// in-memory Node.
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    auto join = std::make_shared<test::PerItemJoin<VoidResult>>(items.size(),
      [complete = std::move(complete)](BatchResult<VoidResult> written)
      { complete(std::move(written), {}); });
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const ValueWriteItem& item = items[index];
      const auto* raw = dynamic_cast<const RawValueNode*>(&item.node);
      if (raw != nullptr && raw->holds_as_written(item.value))
      {
        const DataValue& written = item.value.value();
        const bool valueAlone =
          !written.status() && !written.source_timestamp() && !written.server_timestamp();
        mValues->store(item.value.node_id(), valueAlone ? written.value() : Variant{written});
        join->answer(index, VoidResult{});
        continue;
      }
      const ValueWriteItem one[]{ValueWriteItem{in_memory(item.node), item.value}};
      default_ns::Namespace::write_async(request,
        caller,
        one,
        [join, index](BatchResult<VoidResult> written, std::vector<VersionedNode>)
        { join->answer(index, test::only_item(std::move(written))); });
    }
    join->started();
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    auto resolved = default_ns::Namespace::resolve_here(nodeId);
    if (resolved.is_bad())
      return resolved;
    return NodeResult{shared_ptr<Node>{std::make_shared<RawValueNode>(std::move(resolved).value(), mValues)}};
  }

private:
  /// The in-memory Node an item's @p node stands for.
  static const Node& in_memory(const Node& node)
  {
    const auto* raw = dynamic_cast<const RawValueNode*>(&node);
    return raw != nullptr ? raw->inner() : node;
  }

  RawValueNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  std::shared_ptr<RawValues> mValues = std::make_shared<RawValues>();
};

// Adds a RawValueNamespace to @p as, granting the test Session's Role every Permission there, and creates in
// it T1 holding the plain Variant Int32 7 and T2 holding a DataValue of Int32 7 with SourceTimestamp @p
// stamp. Fails the test unless each holds the form it was given.
std::pair<NodeId, NodeId> create_raw_value_types(
  AddressSpace& as, boost::asio::any_io_executor ex, DateTime stamp)
{
  auto rawNamespace = RawValueNamespace::create("urn:test:raw-variable-type-values", std::move(ex));
  RolePermissionType everything;
  everything.role_id() = ua::test_helpers::test_access_role_id();
  everything.permissions() = ua::test_helpers::all_permissions();
  rawNamespace->set_namespace_defaults(std::vector<RolePermissionType>{everything}, std::nullopt);
  const auto index = as.try_add_namespace_sync(rawNamespace);
  EXPECT_TRUE(index.is_good()) << "the namespace could not be added";
  const NodeId t1{index.value_or(uint16_t{1}), uint32_t{1}};
  const NodeId t2{index.value_or(uint16_t{1}), uint32_t{2}};

  DataValue withStamp{Variant{int32_t{7}}};
  withStamp.source_timestamp() = stamp;
  const std::pair<const NodeId*, Variant> given[] = {{&t1, Variant{int32_t{7}}}, {&t2, Variant{withStamp}}};
  for (const auto& [nodeId, value] : given)
  {
    EXPECT_TRUE(as.try_create_node_sync(*nodeId, NodeClass::VariableType, {}).is_good())
      << to_string(*nodeId) << " could not be created";
    auto found = as.try_find_node_sync(*nodeId);
    EXPECT_TRUE(found.is_good()) << to_string(*nodeId) << " could not be found";
    if (found.is_bad())
      continue;
    auto node = std::move(found).value();
    auto type = node.as<VariableTypeAccessor>();
    EXPECT_TRUE(type.has_value());
    if (type.has_value())
      type->set_data_type(NodeId{DataTypeId::Int32});
    EXPECT_TRUE(node.try_write_attribute_sync(AttributeId::Value, value).is_good());
    const Variant* held = rawNamespace->held_value(*nodeId);
    EXPECT_TRUE(held != nullptr && held->is_data_value() == value.is_data_value())
      << to_string(*nodeId) << " does not hold its Value in the form it was given";
  }
  return {t1, t2};
}

}  // namespace

// DL-30: InitialAttributes (ua_node.h) lets a namespace hold a VariableType's Value as the value's Variant or
// as a DataValue, and get_value() reads either: a held DataValue as it is, any other value as the value of a
// DataValue. T2 is the control that a held DataValue is returned as it is, its SourceTimestamp kept.
// @relation(AC-COMP-ADDRSP-CREATE-NODE-INITIAL-ATTRIBUTES-01-GET-VALUE-EITHER-FORM, scope=function)
TEST(VariableTypeAccessor, GetValueReturnsEitherHeldForm)
{
  boost::asio::thread_pool tp;
  auto as = AddressSpace::create("urn:test:variable-type-value-forms", tp.get_executor());
  const auto stamp = DateTime::now();
  const auto [t1, t2] = create_raw_value_types(as, tp.get_executor(), stamp);

  const auto plain = as.find_node_sync(t1).as<VariableTypeAccessor>();
  ASSERT_TRUE(plain.has_value());
  const auto plainValue = plain->get_value();
  ASSERT_TRUE(plainValue.has_value()) << "get_value() returns nothing for a Value held as a plain Variant";
  EXPECT_EQ(to_string(plainValue->value()), to_string(Variant{int32_t{7}}));

  const auto heldForm = as.find_node_sync(t2).as<VariableTypeAccessor>();
  ASSERT_TRUE(heldForm.has_value());
  const auto heldValue = heldForm->get_value();
  ASSERT_TRUE(heldValue.has_value()) << "get_value() returns nothing for a Value held as a DataValue";
  EXPECT_EQ(to_string(heldValue->value()), to_string(Variant{int32_t{7}}));
  EXPECT_EQ(heldValue->source_timestamp(), std::optional<DateTime>{stamp})
    << "the held DataValue was not returned as it is";
  ::ua::test_utils::drain_with_timeout(tp);
}

// DL-30, through the Read service, which takes a VariableType's Value from get_value(): each form reads Good
// with Int32 7.
// @relation(AC-COMP-ADDRSP-CREATE-NODE-INITIAL-ATTRIBUTES-01-GET-VALUE-EITHER-FORM, scope=function)
TEST(VariableTypeValueRead, AValueHeldAsAPlainVariantReadsGood)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto [t1, t2] = create_raw_value_types(as, ex, DateTime::now());

  const std::pair<NodeId, const char*> types[] = {{t1, "T1, a plain Variant"}, {t2, "T2, a DataValue"}};
  for (const auto& [typeId, form] : types)
  {
    const auto dv = do_read_value(si, ex, typeId, AttributeId::Value);
    EXPECT_EQ(dv.status().value_or(StatusCode{Status::Good}).as_status(), Status::Good)
      << form << ": the Read answered " << to_string(dv.status().value_or(StatusCode{Status::Good}));
    EXPECT_EQ(to_string(dv.value()), to_string(Variant{int32_t{7}})) << form;
  }
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- An Attribute other than a Variable's Value: no IndexRange, timestamp or status (DL-6) ----------------

namespace
{

constexpr const char* rangeOne = "1";

WriteValue attribute_write(
  const NodeId& nodeId, AttributeId attributeId, Variant value, const char* indexRange = nullptr)
{
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(attributeId);
  if (indexRange != nullptr)
    wv.index_range() = indexRange;
  wv.value().value() = std::move(value);
  return wv;
}

WriteRequest request_of(std::vector<WriteValue> items)
{
  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (auto& item : items)
    req.nodes_to_write().payload().push_back(std::move(item));
  return req;
}

RolePermissionType role_permission(const NodeId& roleId, PermissionType permissions)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = permissions;
  return entry;
}

// Two entries: the test Session's Role with every permission, and SecurityAdmin with WriteRolePermissions.
std::vector<RolePermissionType> two_role_permissions()
{
  return {role_permission(ua::test_helpers::test_access_role_id(), ua::test_helpers::all_permissions()),
    role_permission(NodeId{ObjectId::WellKnownRole_SecurityAdmin},
      PermissionType{PermissionType::Bit::WriteRolePermissions})};
}

// One entry: the test Session's Role with every permission, so the Session can still write after it.
Variant one_role_permission()
{
  const std::vector<RolePermissionType> one{
    role_permission(ua::test_helpers::test_access_role_id(), ua::test_helpers::all_permissions())};
  return Variant{array_utils::copy_to_array_of_references(one)};
}

NodeId create_object(AddressSpace& as, uint32_t id, std::optional<AttributeWriteMask> writeMask)
{
  const NodeId nodeId{1, id};
  auto created = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  EXPECT_TRUE(created.is_good()) << "the Object " << id << " could not be created";
  if (created.is_bad())
    return nodeId;
  created.value().set_display_name(LocalizedText{"", "Original"});
  created.value().set_write_mask(writeMask);
  return nodeId;
}

std::string display_name_of(AddressSpace& as, const NodeId& nodeId)
{
  auto node = as.find_node_sync(nodeId);
  return std::string{
    static_cast<std::string_view>(node.read_attribute(AttributeId::DisplayName).as<LocalizedText>().text())};
}

size_t role_permission_count(AddressSpace& as, const NodeId& nodeId)
{
  const auto permissions = as.find_node_sync(nodeId).get_role_permissions();
  return permissions ? permissions->size() : 0u;
}

// The item's status and the code of its ErrorDetail, for a failure message.
std::string described(const StatusCode& status)
{
  return to_string(status) + (status.shared_detail() ? " (" + status.shared_detail()->code + ")" : "");
}

void expect_refused(const WriteResponse& resp, size_t item, const char* detailCode, const char* what)
{
  ASSERT_GT(resp.results().size(), item) << what;
  const auto& status = resp.results()[item];
  EXPECT_EQ(status.as_status(), Status::BadWriteNotSupported) << what << " answered " << described(status);
  ASSERT_NE(status.shared_detail(), nullptr) << what << " carries no ErrorDetail";
  EXPECT_EQ(status.shared_detail()->code, detailCode) << what;
}

}  // namespace

// Part 4 section 5.10.4.2, Table 59: "A Server shall return a Bad_WriteNotSupported error if an indexRange is
// provided and writing of indexRange is not possible for the Node." The SDK writes no IndexRange of an
// Attribute other than a Variable's Value (DL-6): an array Attribute (ArrayDimensions), a scalar one
// (DisplayName), the RolePermissions route and a VariableType's Value are each refused whole. The same writes
// with no IndexRange, the ArrayDimensions with two entries, are the control that each Attribute is writable
// and only the range is refused.
// @relation(AC-SVR-ATTR-WRITE-005-NON-VALUE-INDEXRANGE-REFUSED, scope=function)
TEST(NonValueWrite, AnIndexRangeIsRefusedForArrayScalarAndRolePermissionsAttributes)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();

  const auto permissionsNode =
    create_object(as, 1600u, AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  as.find_node_sync(permissionsNode).set_role_permissions(two_role_permissions());
  const NodeId shapeNode{1, 1601u};
  {
    auto created = as.try_create_sync<VariableAccessor>(shapeNode, NodeClass::Variable);
    ASSERT_TRUE(created.is_good());
    created.value().set_data_type(NodeId{DataTypeId::Int32});
    created.value().set_value_rank(ValueRank{2});
    created.value().set_array_dimensions(std::vector<uint32_t>{2, 3});
    created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ArrayDimensions});
  }
  const auto nameNode = create_object(as, 1602u, AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  const auto typeNode = create_variable_type(as, 1603u, true, 1, Variant{Array<int32_t>{1, 2, 3}});

  const auto writes = [&](const char* indexRange)
  {
    // The ranged write keeps [5], refused for its range before its value is looked at; the unranged one sends
    // two entries, which the ValueRank of 2 takes (DL-32).
    Array<uint32_t> dimensions;
    dimensions.payload() = indexRange != nullptr ? std::vector<uint32_t>{5} : std::vector<uint32_t>{4, 6};
    return request_of({attribute_write(
                         permissionsNode, AttributeId::RolePermissions, one_role_permission(), indexRange),
      attribute_write(shapeNode, AttributeId::ArrayDimensions, Variant{std::move(dimensions)}, indexRange),
      attribute_write(nameNode, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}}, indexRange),
      attribute_write(typeNode, AttributeId::Value, Variant{Array<int32_t>{9}}, indexRange)});
  };

  const auto ranged = do_write(si, ex, writes(rangeOne));
  ASSERT_EQ(ranged.results().size(), 4u);
  expect_refused(ranged, 0, "IndexRangeWriteNotSupported", "the ranged RolePermissions write");
  expect_refused(ranged, 1, "IndexRangeWriteNotSupported", "the ranged ArrayDimensions write");
  expect_refused(ranged, 2, "IndexRangeWriteNotSupported", "the ranged DisplayName write");
  expect_refused(ranged, 3, "IndexRangeWriteNotSupported", "the ranged VariableType Value write");

  EXPECT_EQ(role_permission_count(as, permissionsNode), 2u)
    << "the ranged write replaced the RolePermissions";
  EXPECT_EQ(as.find_node_sync(shapeNode).as<VariableAccessor>()->get_array_dimensions(),
    (std::optional<std::vector<uint32_t>>{std::vector<uint32_t>{2, 3}}))
    << "the ranged write changed the ArrayDimensions";
  EXPECT_EQ(display_name_of(as, nameNode), "Original") << "the ranged write changed the DisplayName";
  EXPECT_EQ(read_type_value(si, ex, typeNode), to_string(Variant{Array<int32_t>{1, 2, 3}}));

  const auto whole = do_write(si, ex, writes(nullptr));
  ASSERT_EQ(whole.results().size(), 4u);
  const char* names[] = {"RolePermissions", "ArrayDimensions", "DisplayName", "VariableType Value"};
  for (size_t item = 0; item < 4u; ++item)
  {
    EXPECT_EQ(whole.results()[item].as_status(), Status::Good)
      << "the " << names[item] << " write with no IndexRange answered " << described(whole.results()[item]);
  }
  EXPECT_EQ(as.find_node_sync(shapeNode).as<VariableAccessor>()->get_array_dimensions(),
    (std::optional<std::vector<uint32_t>>{std::vector<uint32_t>{4, 6}}))
    << "the unranged ArrayDimensions write was not stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.2, Table 59: "The Server returns a Bad_WriteNotSupported error if it does not support
// writing of timestamps"; section 5.10.4.4, Table 61: for a combination the Server does not support, "the
// Server shall not perform any write on this Node". These Attributes keep no SourceTimestamp, ServerTimestamp
// or status (DL-6), so each is refused, a Good status with an info bit included (the SDK's choice: the bits
// would otherwise be dropped without a word). A status of 0 and null timestamps are what unset fields encode
// as: the control.
// @relation(AC-SVR-ATTR-WRITE-022-NON-VALUE-TIMESTAMP-OR-STATUS-REFUSED, scope=function)
TEST(NonValueWrite, ATimestampOrNonZeroStatusIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();

  const auto nameNode = create_object(as, 1610u, AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  const auto permissionsNode =
    create_object(as, 1611u, AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  as.find_node_sync(permissionsNode).set_role_permissions(two_role_permissions());
  const auto typeNode = create_variable_type(as, 1612u, true, ValueRank::scalar, Variant{int32_t{7}});

  const auto renamed = [&nameNode]
  {
    return attribute_write(nameNode, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}});
  };
  auto withSourceTimestamp = renamed();
  withSourceTimestamp.value().source_timestamp() = DateTime::now();
  auto withServerTimestamp = renamed();
  withServerTimestamp.value().server_timestamp() = DateTime::now();
  auto withUncertain = renamed();
  withUncertain.value().status() = StatusCode{Status::Uncertain};
  auto withGoodInfoBits = renamed();
  // Severity Good, InfoType DataValue (bit 10) and the Overflow info bit (bit 7).
  withGoodInfoBits.value().status() = StatusCode{StatusCodeValue{0x00000480U}};
  auto permissionsWithTimestamp =
    attribute_write(permissionsNode, AttributeId::RolePermissions, one_role_permission());
  permissionsWithTimestamp.value().source_timestamp() = DateTime::now();
  auto typeValueWithTimestamp = attribute_write(typeNode, AttributeId::Value, Variant{int32_t{42}});
  typeValueWithTimestamp.value().source_timestamp() = DateTime::now();

  const auto refused = do_write(si,
    ex,
    request_of({withSourceTimestamp,
      withServerTimestamp,
      withUncertain,
      withGoodInfoBits,
      permissionsWithTimestamp,
      typeValueWithTimestamp}));
  ASSERT_EQ(refused.results().size(), 6u);
  expect_refused(refused, 0, "TimestampWriteNotSupported", "the DisplayName write with a SourceTimestamp");
  expect_refused(refused, 1, "TimestampWriteNotSupported", "the DisplayName write with a ServerTimestamp");
  expect_refused(refused, 2, "StatusWriteNotSupported", "the DisplayName write with the status Uncertain");
  expect_refused(
    refused, 3, "StatusWriteNotSupported", "the DisplayName write with a Good status and info bits");
  expect_refused(
    refused, 4, "TimestampWriteNotSupported", "the RolePermissions write with a SourceTimestamp");
  expect_refused(
    refused, 5, "TimestampWriteNotSupported", "the VariableType Value write with a SourceTimestamp");

  EXPECT_EQ(display_name_of(as, nameNode), "Original") << "a refused write changed the DisplayName";
  EXPECT_EQ(role_permission_count(as, permissionsNode), 2u) << "a refused write replaced the RolePermissions";
  EXPECT_EQ(read_type_value(si, ex, typeNode), to_string(Variant{int32_t{7}}));

  auto unset = renamed();
  unset.value().status() = StatusCode{Status::Good};
  unset.value().source_timestamp() = DateTime{};
  unset.value().server_timestamp() = DateTime{};
  const auto control = do_write(si, ex, request_of({unset}));
  ASSERT_EQ(control.results().size(), 1u);
  EXPECT_EQ(control.results()[0].as_status(), Status::Good)
    << "the write with null timestamps and the status 0 answered " << described(control.results()[0]);
  EXPECT_EQ(display_name_of(as, nameNode), "Renamed");
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// Keeps the status of every AuditWriteUpdateEvent the bus delivers, by the Node it names.
class AuditWriteRecorder
{
public:
  void record(const BaseEvent& event)
  {
    const auto* audit = dynamic_cast<const AuditWriteUpdateEventPayload*>(&event);
    if (audit == nullptr)
      return;
    const std::lock_guard lock{mMutex};
    mStatuses.emplace_back(audit->sourceNode, audit->status);
  }

  /// The status of the first audit Event naming @p nodeId, or nullopt when none has arrived within 2 s.
  std::optional<bool> status_for(const NodeId& nodeId) const
  {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline)
    {
      {
        const std::lock_guard lock{mMutex};
        for (const auto& [source, status] : mStatuses)
        {
          if (source == nodeId)
            return status;
        }
      }
      std::this_thread::sleep_for(5ms);
    }
    return std::nullopt;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<NodeId, bool>> mStatuses;
};

}  // namespace

// The refusal comes after the answers that say a Client may not write, or that the Attribute does not exist,
// and it is a failed Write, which Part 4 section 6.5.8 requires to be audited ("shall generate audit Events
// for both successful and failed Service invocations"). The first three answers are the controls of the
// order; the audit Event of the refused DisplayName write reports the write as failed.
// @relation(AC-SVR-ATTR-WRITE-022-NON-VALUE-REFUSAL-COMES-AFTER-ACCESS-AND-IS-AUDITED, scope=function)
TEST(NonValueWrite, AccessAndAttributeAnswersComeFirstAndTheRefusalIsAudited)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  si->serverCfg.auditingEnabled = true;
  {
    auto server = as.try_create_sync<ObjectAccessor>(NodeId{ObjectId::Server}, NodeClass::Object);
    ASSERT_TRUE(server.is_good());
    server.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  }
  auto bus = std::make_shared<EventBus>(as);
  auto recorder = std::make_shared<AuditWriteRecorder>();
  bus->set_event_listener([recorder](const BaseEvent& event) { recorder->record(event); });
  ASSERT_TRUE(bus->has_event_interest()) << "precondition: the audit gate sees an interest";
  si->eventSink = bus.get();

  const auto lockedName = create_object(as, 1620u, AttributeWriteMask{AttributeWriteMask::Bit::Description});
  const auto deniedPermissions =
    create_object(as, 1621u, AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
  {
    auto node = as.find_node_sync(deniedPermissions);
    auto withoutWriteRolePermissions = ua::test_helpers::all_permissions();
    withoutWriteRolePermissions.reset(PermissionType::Bit::WriteRolePermissions);
    ua::test_helpers::set_test_node_permissions(node, withoutWriteRolePermissions);
  }
  const auto plainObject = create_object(as, 1622u, AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});

  const auto ranged = do_write(si,
    ex,
    request_of(
      {attribute_write(lockedName, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}}, rangeOne),
        attribute_write(deniedPermissions, AttributeId::RolePermissions, one_role_permission(), rangeOne),
        attribute_write(plainObject, AttributeId::Value, Variant{int32_t{42}}, rangeOne)}));
  ASSERT_EQ(ranged.results().size(), 3u);
  EXPECT_EQ(ranged.results()[0].as_status(), Status::BadNotWritable)
    << "the DisplayName whose WriteMask forbids it answered " << described(ranged.results()[0]);
  EXPECT_EQ(ranged.results()[1].as_status(), Status::BadUserAccessDenied)
    << "the RolePermissions the user may not write answered " << described(ranged.results()[1]);
  EXPECT_EQ(ranged.results()[2].as_status(), Status::BadAttributeIdInvalid)
    << "the Value of an Object answered " << described(ranged.results()[2]);

  const auto writableName =
    create_object(as, 1623u, AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  auto withSourceTimestamp =
    attribute_write(writableName, AttributeId::DisplayName, Variant{LocalizedText{"", "Renamed"}});
  withSourceTimestamp.value().source_timestamp() = DateTime::now();
  const auto refused = do_write(si, ex, request_of({withSourceTimestamp}));
  ASSERT_EQ(refused.results().size(), 1u);
  expect_refused(refused, 0, "TimestampWriteNotSupported", "the DisplayName write with a SourceTimestamp");
  EXPECT_EQ(display_name_of(as, writableName), "Original");

  const auto audited = recorder->status_for(writableName);
  ASSERT_TRUE(audited.has_value()) << "the refused DisplayName write raised no AuditWriteUpdateEvent";
  EXPECT_FALSE(*audited) << "the AuditWriteUpdateEvent reports the refused write as successful";

  si->eventSink = nullptr;
  bus->set_event_listener({});
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- ArrayDimensions written by a Client (DL-32) -----------------------------------------------------------

namespace
{

// A Variable or VariableType of DataType Int32 with ValueRank @p rank and, unless null, the ArrayDimensions
// @p dimensions, whose WriteMask sets bit 1 (ArrayDimensions) only.
NodeId create_dimensioned_node(AddressSpace& as, uint32_t id, NodeClass nodeClass, int32_t rank,
  std::optional<std::vector<uint32_t>> dimensions)
{
  const NodeId nodeId{1, id};
  auto created = as.try_create_node_sync(nodeId, nodeClass, {});
  EXPECT_TRUE(created.is_good()) << "the node " << id << " could not be created";
  if (created.is_bad())
    return nodeId;
  auto node = std::move(created).value();
  if (auto variable = node.as<VariableAccessor>())
  {
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{rank});
    if (dimensions)
      variable->set_array_dimensions(*dimensions);
  }
  else if (auto type = node.as<VariableTypeAccessor>())
  {
    type->set_data_type(NodeId{DataTypeId::Int32});
    type->set_value_rank(ValueRank{rank});
    if (dimensions)
      type->set_array_dimensions(*dimensions);
  }
  node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ArrayDimensions});
  return nodeId;
}

Variant dimensions_of(std::vector<uint32_t> entries)
{
  Array<uint32_t> dimensions;
  dimensions.payload() = std::move(entries);
  return Variant{std::move(dimensions)};
}

WriteResponse write_dimensions(std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex,
  const NodeId& nodeId, Variant dimensions)
{
  return do_write(std::move(si),
    std::move(ex),
    request_of({attribute_write(nodeId, AttributeId::ArrayDimensions, std::move(dimensions))}));
}

constexpr const char* absent = "absent (Bad_AttributeIdInvalid with no value)";

// The ArrayDimensions a Read of @p nodeId returns, or `absent` when it answers Bad_AttributeIdInvalid with no
// value, as for a node created without them.
std::string read_dimensions(
  std::shared_ptr<TestWriteSessionInfo> si, boost::asio::any_io_executor ex, const NodeId& nodeId)
{
  const auto dv = do_read_value(std::move(si), std::move(ex), nodeId, AttributeId::ArrayDimensions);
  const auto status = dv.status().value_or(StatusCode{Status::Good});
  if (status.as_status() == Status::BadAttributeIdInvalid && dv.value().empty())
    return absent;
  if (status.is_bad())
    return "the Read answered " + to_string(status) + " with " + to_string(dv.value());
  return to_string(dv.value());
}

// The value of @p key in the context of @p status's ErrorDetail, or "<none>".
std::string detail_context(const StatusCode& status, std::string_view key)
{
  const auto detail = status.shared_detail();
  if (!detail)
    return "<no ErrorDetail>";
  for (const auto& entry : detail->context)
  {
    if (entry.key == key)
      return std::string{entry.value};
  }
  return "<none>";
}

void expect_rank_mismatch(
  const WriteResponse& resp, const char* expected, const char* actual, const char* what)
{
  ASSERT_EQ(resp.results().size(), 1u) << what;
  const auto& status = resp.results()[0];
  EXPECT_EQ(status.as_status(), Status::BadTypeMismatch) << what << " answered " << described(status);
  ASSERT_NE(status.shared_detail(), nullptr) << what << " carries no ErrorDetail";
  EXPECT_EQ(status.shared_detail()->code, "ValueRankMismatch") << what;
  // The criteria name the counts only where the ValueRank is positive.
  if (expected == nullptr)
    return;
  EXPECT_EQ(detail_context(status, ContextKeys::expected.value()), expected)
    << what << ": the expected count";
  EXPECT_EQ(detail_context(status, ContextKeys::actual.value()), actual) << what << ": the actual count";
}

void expect_written(const WriteResponse& resp, const char* what)
{
  ASSERT_EQ(resp.results().size(), 1u) << what;
  EXPECT_EQ(resp.results()[0].as_status(), Status::Good)
    << what << " answered " << described(resp.results()[0]);
}

}  // namespace

// Part 3 section 8.60, Table 43: bit 1 "Indicates if the ArrayDimensions Attribute is writable";
// section 5.6.2, Table 13 (Variable) and section 5.6.5, Table 14 (VariableType): the number of entries equals
// the ValueRank. DL-32: a ValueRank n greater than 0 takes n entries, on a Variable and on a VariableType.
// @relation(AC-SVR-ATTR-WRITE-033-MATCHING-COUNT-STORED, scope=function)
TEST(NonValueWrite, ArrayDimensionsWithAsManyEntriesAsTheValueRankAreStored)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto v2 = create_dimensioned_node(as, 1700u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto t2 = create_dimensioned_node(as, 1701u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto v1 = create_dimensioned_node(as, 1702u, NodeClass::Variable, 1, std::vector<uint32_t>{5});

  expect_written(write_dimensions(si, ex, v2, dimensions_of({4, 6})), "[4, 6] to V2");
  expect_written(write_dimensions(si, ex, t2, dimensions_of({4, 6})), "[4, 6] to T2");
  expect_written(write_dimensions(si, ex, v1, dimensions_of({7})), "[7] to V1");
  EXPECT_EQ(read_dimensions(si, ex, v2), to_string(dimensions_of({4, 6}))) << "V2";
  EXPECT_EQ(read_dimensions(si, ex, t2), to_string(dimensions_of({4, 6}))) << "T2";
  EXPECT_EQ(read_dimensions(si, ex, v1), to_string(dimensions_of({7}))) << "V1";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.10.4.2, Table 59: a Server may impose validations and "shall return a Bad_TypeMismatch
// error if the validation fails". DL-32: a count other than a positive ValueRank is refused as a Value of the
// wrong rank is, with ValueRankMismatch and the expected and actual counts, and nothing is stored. Fewer and
// more entries on V2, fewer on T2.
// @relation(AC-SVR-ATTR-WRITE-033-WRONG-COUNT-TYPE-MISMATCH, scope=function)
TEST(NonValueWrite, ArrayDimensionsWithAWrongNumberOfEntriesIsValueRankMismatch)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto v2 = create_dimensioned_node(as, 1710u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto t2 = create_dimensioned_node(as, 1711u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto held = to_string(dimensions_of({2, 3}));

  expect_rank_mismatch(write_dimensions(si, ex, v2, dimensions_of({5})), "2", "1", "[5] to V2");
  EXPECT_EQ(read_dimensions(si, ex, v2), held) << "V2 after [5]";
  expect_rank_mismatch(write_dimensions(si, ex, v2, dimensions_of({1, 2, 3})), "2", "3", "[1, 2, 3] to V2");
  EXPECT_EQ(read_dimensions(si, ex, v2), held) << "V2 after [1, 2, 3]";
  expect_rank_mismatch(write_dimensions(si, ex, t2, dimensions_of({2})), "2", "1", "[2] to T2");
  EXPECT_EQ(read_dimensions(si, ex, t2), held) << "T2 after [2]";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 section 5.1.9: "null, empty and zero length arrays are semantically the same". DL-32: null or an
// empty array is accepted at every ValueRank and held as null, which a Read answers as it answers a node
// created without ArrayDimensions (Ve, the control).
// @relation(AC-SVR-ATTR-WRITE-033-NULL-OR-EMPTY-STORED-AS-NULL, scope=function)
TEST(NonValueWrite, ArrayDimensionsNullOrEmptyIsStoredAsNull)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto va = create_dimensioned_node(as, 1720u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto vd = create_dimensioned_node(as, 1721u, NodeClass::Variable, -3, std::vector<uint32_t>{4});
  const auto vb = create_dimensioned_node(as, 1722u, NodeClass::Variable, 2, std::vector<uint32_t>{2, 3});
  const auto vc = create_dimensioned_node(as, 1723u, NodeClass::Variable, -1, std::nullopt);
  const auto tb = create_dimensioned_node(as, 1724u, NodeClass::VariableType, 2, std::vector<uint32_t>{2, 3});
  const auto ve = create_dimensioned_node(as, 1725u, NodeClass::Variable, 2, std::nullopt);

  expect_written(write_dimensions(si, ex, va, Variant{}), "null to Va");
  expect_written(write_dimensions(si, ex, vd, Variant{}), "null to Vd");
  expect_written(write_dimensions(si, ex, vb, dimensions_of({})), "[] to Vb");
  expect_written(write_dimensions(si, ex, vc, dimensions_of({})), "[] to Vc");
  expect_written(write_dimensions(si, ex, tb, dimensions_of({})), "[] to Tb");
  const std::pair<NodeId, const char*> nodes[] = {
    {va, "Va"}, {vd, "Vd"}, {vb, "Vb"}, {vc, "Vc"}, {tb, "Tb"}, {ve, "Ve"}};
  for (const auto& [nodeId, name] : nodes)
    EXPECT_EQ(read_dimensions(si, ex, nodeId), absent) << name;
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.6.2, Table 13: a Variable's ArrayDimensions "shall be null if the Value is not an array";
// section 5.6.5, Table 14: a VariableType's "shall be null if ValueRank <= 0". DL-32 checks what the
// ValueRank makes knowable: Scalar takes no entry, ScalarOrOneDimension one, a VariableType of ValueRank 0 or
// less none, and a Variable of ValueRank 0 or -2 any number. Vom and T0 differ only in NodeClass.
// @relation(AC-SVR-ATTR-WRITE-033-NON-POSITIVE-VALUERANK, scope=function)
TEST(NonValueWrite, ArrayDimensionsAtAValueRankOfZeroOrLess)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  const auto vs = create_dimensioned_node(as, 1730u, NodeClass::Variable, -1, std::nullopt);
  const auto vso = create_dimensioned_node(as, 1731u, NodeClass::Variable, -3, std::nullopt);
  const auto vom = create_dimensioned_node(as, 1732u, NodeClass::Variable, 0, std::nullopt);
  const auto vany = create_dimensioned_node(as, 1733u, NodeClass::Variable, -2, std::nullopt);
  const auto t0 = create_dimensioned_node(as, 1734u, NodeClass::VariableType, 0, std::nullopt);

  expect_rank_mismatch(write_dimensions(si, ex, vs, dimensions_of({3})), nullptr, nullptr, "[3] to Vs");
  EXPECT_EQ(read_dimensions(si, ex, vs), absent) << "Vs after [3]";
  expect_rank_mismatch(
    write_dimensions(si, ex, vso, dimensions_of({2, 2})), nullptr, nullptr, "[2, 2] to Vso");
  EXPECT_EQ(read_dimensions(si, ex, vso), absent) << "Vso after [2, 2]";
  expect_written(write_dimensions(si, ex, vso, dimensions_of({4})), "[4] to Vso");
  EXPECT_EQ(read_dimensions(si, ex, vso), to_string(dimensions_of({4}))) << "Vso after [4]";
  expect_written(write_dimensions(si, ex, vom, dimensions_of({3})), "[3] to Vom");
  EXPECT_EQ(read_dimensions(si, ex, vom), to_string(dimensions_of({3}))) << "Vom after [3]";
  expect_written(write_dimensions(si, ex, vom, dimensions_of({2, 2, 2})), "[2, 2, 2] to Vom");
  EXPECT_EQ(read_dimensions(si, ex, vom), to_string(dimensions_of({2, 2, 2}))) << "Vom after [2, 2, 2]";
  expect_written(write_dimensions(si, ex, vany, dimensions_of({3})), "[3] to Vany");
  EXPECT_EQ(read_dimensions(si, ex, vany), to_string(dimensions_of({3}))) << "Vany after [3]";
  expect_written(write_dimensions(si, ex, vany, dimensions_of({2, 2})), "[2, 2] to Vany");
  EXPECT_EQ(read_dimensions(si, ex, vany), to_string(dimensions_of({2, 2}))) << "Vany after [2, 2]";
  expect_rank_mismatch(write_dimensions(si, ex, t0, dimensions_of({3})), nullptr, nullptr, "[3] to T0");
  EXPECT_EQ(read_dimensions(si, ex, t0), absent) << "T0 after [3]";
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Async Write Path --------------------------------------------------------

TEST(WriteServiceTests, AsyncWriteVariableValue_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1000u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{String{"hello"}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  // Read back to verify
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_EQ(dv.value().as<String>(), "hello");
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- MaxAge Validation -------------------------------------------------------

TEST(ReadServiceTests_MaxAge, NegativeMaxAge_ReturnsBadMaxAgeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1100u};
  as.try_create_node_sync(nodeId, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = -1.0;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  EXPECT_EQ(resp.response_header().service_result(), Status::BadMaxAgeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ReadServiceTests_MaxAge, ZeroMaxAge_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1101u};
  as.try_create_node_sync(nodeId, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = 0.0;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(!resp.results()[0].status() || resp.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ReadServiceTests_MaxAge, LargeMaxAge_Succeeds)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1102u};
  as.try_create_node_sync(nodeId, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  req.max_age() = 999999999.0;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(!resp.results()[0].status() || resp.results()[0].status()->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- IndexRange in Read ------------------------------------------------------

TEST(ReadServiceTests_IndexRange, ReadArrayValueWithIndexRange_ReturnsSlicedArray)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1200u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();
  var.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write initial array
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{Array<int32_t>{10, 20, 30, 40, 50}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Read with IndexRange
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "1:3";
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(!resp.results()[0].status() || resp.results()[0].status()->is_good());

  const auto& arr = resp.results()[0].value().as<Array<int32_t>>();
  ASSERT_EQ(arr.size(), 3u);
  EXPECT_EQ(arr[0], 20);
  EXPECT_EQ(arr[1], 30);
  EXPECT_EQ(arr[2], 40);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ReadServiceTests_IndexRange, ReadScalarStringWithIndexRange_ReturnsSubstring)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1201u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write string value
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{String{"Hello World"}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Read with IndexRange on string
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "0:4";
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(!resp.results()[0].status() || resp.results()[0].status()->is_good());
  EXPECT_EQ(resp.results()[0].value().as<String>(), String{"Hello"});
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceTests_IndexRange, ReadScalarWithIndexRange_ReturnsBadIndexRangeNoData)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1202u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write scalar int
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{int32_t{42}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Read with IndexRange on non-indexable scalar
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "0";
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status().value(), Status::BadIndexRangeNoData);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-ATTR-READ-029, scope=function)
TEST(ReadServiceTests_IndexRange, InvalidIndexRangeSyntax_ReturnsBadIndexRangeInvalid)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 1203u};
  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();
  var.set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  var.set_access_level(al);

  // Write a value so the node has something
  {
    WriteRequest initReq;
    initReq.request_header().request_handle() = 1;
    WriteValue initWv;
    initWv.node_id() = nodeId;
    initWv.attribute_id() = utils::to_underlying(AttributeId::Value);
    initWv.value().value() = Variant{Array<int32_t>{1, 2, 3}};
    initReq.nodes_to_write().payload().push_back(std::move(initWv));
    auto initResp = do_write(si, ex, std::move(initReq));
    ASSERT_TRUE(initResp.results()[0].is_good());
  }

  // Read with invalid IndexRange syntax
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  rvid.index_range() = "abc";
  req.nodes_to_read().payload().push_back(std::move(rvid));

  auto resp = do_read(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status().value(), Status::BadIndexRangeInvalid);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Default-path partial denial (re-expressed from the removed Write override test): in a 3-item batch
// where the namespace denies Write on exactly the MIDDLE node, the denied slot is answered
// Bad_UserAccessDenied and the two surviving writes succeed at their original (non-contiguous) slots.
TEST(WriteServiceTests, PartialAuthzDenialScattersResultsToOriginalSlots)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  const NodeId firstNode{1, 9500u};
  const NodeId deniedNode{1, 9501u};  // the MIDDLE item - denied
  const NodeId lastNode{1, 9502u};

  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  for (const auto& id : {firstNode, deniedNode, lastNode})
  {
    auto varResult = as.try_create_sync<VariableAccessor>(id, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(accessLevel);
    if (id == deniedNode)
    {
      NodeAccessor denied = varResult.value();
      ua::test_helpers::set_test_node_permissions(denied, PermissionType{});
    }
  }

  // Distinct per-slot values so a survivor slot/value swap is observable on read-back.
  const int32_t firstValue = 100;
  const int32_t deniedValue = 101;
  const int32_t lastValue = 102;
  WriteRequest req;
  req.nodes_to_write().resize(3);
  req.nodes_to_write()[0].node_id() = firstNode;
  req.nodes_to_write()[0].value().value() = Variant{firstValue};
  req.nodes_to_write()[1].node_id() = deniedNode;
  req.nodes_to_write()[1].value().value() = Variant{deniedValue};
  req.nodes_to_write()[2].node_id() = lastNode;
  req.nodes_to_write()[2].value().value() = Variant{lastValue};
  for (size_t i = 0; i < 3; ++i)
  {
    req.nodes_to_write()[i].attribute_id() = utils::to_underlying(AttributeId::Value);
  }

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 3u);
  EXPECT_TRUE(resp.results()[0].is_good());
  EXPECT_EQ(resp.results()[1], Status::BadUserAccessDenied);
  EXPECT_TRUE(resp.results()[2].is_good());

  // Read the stored values back: each surviving write must have landed on its OWN node (a scatter
  // index-mapping bug that swapped the survivors would put lastValue on firstNode and vice versa),
  // and the denied write must NOT have taken effect.
  EXPECT_EQ(do_read_value(si, ex, firstNode, AttributeId::Value).value().as<int32_t>(), firstValue);
  EXPECT_EQ(do_read_value(si, ex, lastNode, AttributeId::Value).value().as<int32_t>(), lastValue);
  const auto deniedReadback = do_read_value(si, ex, deniedNode, AttributeId::Value);
  EXPECT_FALSE(deniedReadback.value().is_int32() && deniedReadback.value().as<int32_t>() == deniedValue)
    << "denied write must not have modified the node";

  ::ua::test_utils::drain_with_timeout(tp);
}

// PermissionType separates live-data Write from configuration WriteAttribute.
// Drive both through the same Write service and Node so only the requested
// Attribute changes the authorization operation.
// @relation(AC-SVR-SECADMIN-064-OPERATOR-PERMISSIONS, scope=function)
TEST(WriteServiceTests, ValueAndConfigurationWritesUseDistinctAuthorizationOperations)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();
  auto sessionInfo = std::make_shared<TestWriteSessionInfo>(executor, true);

  const NodeId nodeId{1, 9510u};
  auto variableResult =
    sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(variableResult.is_good());
  variableResult.value().set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentWrite});
  variableResult.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  variableResult.value().set_display_name(LocalizedText{"", "Before"});
  auto liveDataOnly = ua::test_helpers::all_permissions();
  liveDataOnly.reset(PermissionType::Bit::WriteAttribute);
  ua::test_helpers::set_test_node_permissions(variableResult.value(), liveDataOnly);

  WriteRequest request;
  request.nodes_to_write().resize(2);
  request.nodes_to_write()[0].node_id() = nodeId;
  request.nodes_to_write()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
  request.nodes_to_write()[0].value().value() = Variant{int32_t{42}};
  request.nodes_to_write()[1].node_id() = nodeId;
  request.nodes_to_write()[1].attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  request.nodes_to_write()[1].value().value() = Variant{LocalizedText{"", "After"}};

  auto response = do_write(sessionInfo, executor, std::move(request));
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_TRUE(response.results()[0].is_good());
  EXPECT_EQ(response.results()[1], Status::BadUserAccessDenied);
  EXPECT_EQ(sessionInfo->address_space()
              .find_node_sync(nodeId)
              .read_attribute(AttributeId::DisplayName)
              .as<LocalizedText>(),
    (LocalizedText{"", "Before"}));

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// --- DataType obligations on the Write path ----------------------------------

// Part 3 section 8 (OptionSet): a Write whose ValidBits length differs from the Value length must be refused
// with Bad_OutOfRange, in BOTH directions. A plausible implementation checks only the direction it
// happened to hit first (ValidBits longer than Value) and then masks byte-by-byte; the other direction
// reads past the shorter array or silently treats the uncovered bytes as zero, clearing bits the caller
// never mentioned.
// @verifies AC-SVR-ADDRSP-213-VALIDBITS-LENGTH-CHECKED
TEST(WriteServiceTests, OptionSetWriteWithMismatchedValidBitsLengthIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId dataTypeId{1, 5300u};
  const NodeId nodeId{1, 5301u};

  // 16 defined bits, so both test values stay inside the server-defined bit set and the only thing
  // that can refuse the write is the length rule itself.
  EnumDefinition definition;
  for (int64_t bit = 0; bit < 16; ++bit)
  {
    EnumField field;
    field.name() = String{"Bit" + std::to_string(bit)};
    field.value() = bit;
    definition.fields().payload().push_back(std::move(field));
  }

  auto dtResult = as.try_create_sync<DataTypeAccessor>(dataTypeId, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());
  dtResult.value().set_data_type_definition(std::make_shared<EnumDefinition>(definition));

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(dataTypeId);

  auto descriptor = std::make_shared<DynamicEnumTypeDescriptor>(
    String{"TestFlags"}, ExpandedNodeId{dataTypeId}, true, definition);

  auto writeOptionSet = [&](ByteString value, ByteString validBits)
  {
    DynamicOptionSet os{descriptor};
    os.value() = std::move(value);
    os.valid_bits() = std::move(validBits);

    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(os)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Seed a known two-byte value through the service itself (empty ValidBits = wholesale replace), so
  // the "unchanged" assertion below is anchored on a value the Write path really stored.
  {
    auto seeded = writeOptionSet(ByteString({0xA0, 0x0F}), ByteString{});
    ASSERT_EQ(seeded.results().size(), 1u);
    ASSERT_TRUE(seeded.results()[0].is_good());
  }

  // ValidBits SHORTER than Value.
  auto shorter = writeOptionSet(ByteString({0x01, 0x02}), ByteString({0xFF}));
  ASSERT_EQ(shorter.results().size(), 1u);
  EXPECT_EQ(shorter.results()[0], Status::BadOutOfRange);

  // ValidBits LONGER than Value.
  auto longer = writeOptionSet(ByteString({0x01}), ByteString({0xFF, 0x00}));
  ASSERT_EQ(longer.results().size(), 1u);
  EXPECT_EQ(longer.results()[0], Status::BadOutOfRange);

  // Neither refusal may have partially applied: the stored value is still the seeded one.
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<OptionSet>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(stored->value(), ByteString({0xA0, 0x0F}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.8: a Variable may declare an abstract DataType, but a value may not carry one - an
// abstract DataType has no encoding, so what is stored and returned must always be a concrete subtype. Number
// (i=26) is abstract; a plausible implementation compares the written built-in type against the declared
// numeric id, finds no built-in type numbered 26, and falls through - storing a String under a numeric
// declaration, which then reads back as a value of a type no Number decoder can accept.
// @verifies AC-SVR-ADDRSP-122-NO-ABSTRACT-VALUES
TEST(WriteServiceTests, ValueUnderAbstractDataTypeIsAlwaysAConcreteSubtype)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 5310u};
  const NodeId abstractNumberDataType{0, 26u};  // i=26 = Number, an abstract DataType

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(abstractNumberDataType);

  // A concrete subtype of the abstract declaration is accepted.
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{int32_t{42}};
    req.nodes_to_write().payload().push_back(std::move(wv));

    auto resp = do_write(si, ex, std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good());
  }

  // A value that is not a subtype of the abstract declaration is refused, so no value that fails the
  // abstract type's constraint can ever be read back from this Variable.
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{String{"not a number"}};
    req.nodes_to_write().payload().push_back(std::move(wv));

    auto resp = do_write(si, ex, std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_EQ(resp.results()[0], Status::BadTypeMismatch);
  }

  // What the Variable hands back is the concrete subtype, not the refused non-subtype.
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  ASSERT_TRUE(dv.value().is_int32());
  EXPECT_EQ(dv.value().as<int32_t>(), 42);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.8: a published DataTypeDefinition does not change - clients compile decoders from it and
// cache them, so an in-place edit makes every cached decoder wrong with no signal. A plausible
// implementation treats DataTypeDefinition as an ordinary attribute gated only by the WriteMask, so a
// node whose WriteMask permits it would accept the edit; the WriteMask here deliberately names
// DataTypeDefinition, and the DisplayName write proves writes to this node are otherwise honoured.
// @verifies AC-SVR-ADDRSP-126-DATATYPEDEFINITION-IMMUTABLE
TEST(WriteServiceTests, PublishedDataTypeDefinitionCannotBeEdited)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId dataTypeId{1, 5320u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(dataTypeId, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());
  dtResult.value().set_write_mask(
    AttributeWriteMask{AttributeWriteMask::Bit::DataTypeDefinition, AttributeWriteMask::Bit::DisplayName});

  auto published = std::make_shared<EnumDefinition>();
  {
    EnumField field;
    field.name() = String{"Original"};
    field.value() = 1;
    published->fields().payload().push_back(std::move(field));
  }
  dtResult.value().set_data_type_definition(published);

  // Baseline: the definition really is published and readable, so "unchanged" below is falsifiable.
  {
    auto before = do_read_value(si, ex, dataTypeId, AttributeId::DataTypeDefinition);
    const auto* beforeDef = before.value().try_as<EnumDefinition>();
    ASSERT_NE(beforeDef, nullptr);
    ASSERT_EQ(beforeDef->fields().size(), 1u);
    EXPECT_EQ(beforeDef->fields()[0].name(), String{"Original"});
    EXPECT_EQ(beforeDef->fields()[0].value(), 1);
  }

  // Control: the node is writable where its WriteMask says so, so the refusal below is specific to
  // DataTypeDefinition rather than a blanket refusal on this node.
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = dataTypeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"en", "Renamed"}};
    req.nodes_to_write().payload().push_back(std::move(wv));

    auto resp = do_write(si, ex, std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good());
  }

  // The edit: a different definition for the same DataType Node.
  {
    EnumDefinition mutated;
    EnumField field;
    field.name() = String{"Mutated"};
    field.value() = 2;
    mutated.fields().payload().push_back(std::move(field));

    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = dataTypeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::DataTypeDefinition);
    wv.value().value() = Variant{std::move(mutated)};
    req.nodes_to_write().payload().push_back(std::move(wv));

    auto resp = do_write(si, ex, std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_bad()) << "a published DataTypeDefinition must not be editable";
  }

  // The refusal is not cosmetic: the published definition is byte-for-byte the one clients compiled.
  auto after = do_read_value(si, ex, dataTypeId, AttributeId::DataTypeDefinition);
  const auto* afterDef = after.value().try_as<EnumDefinition>();
  ASSERT_NE(afterDef, nullptr);
  ASSERT_EQ(afterDef->fields().size(), 1u);
  EXPECT_EQ(afterDef->fields()[0].name(), String{"Original"});
  EXPECT_EQ(afterDef->fields()[0].value(), 1);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.6.2: when a Variable's AllowNulls Property is FALSE the Server "shall never return a null
// value and shall reject any request writing a null value". Both halves are asserted here because the
// read half is the one a server forgets - refusing the write is natural, and answering Read from an
// uninitialised source with a Good null is equally natural, but a client told nulls cannot occur will
// not check. The write half is easy to miss too: an empty Variant reads as "no value supplied", so the
// value-carrying validation chain is skipped entirely and the null falls straight through to storage.
// @verifies AC-SVR-ADDRSP-086-ALLOWNULLS-FALSE-ENFORCED
TEST(WriteServiceTests, AllowNullsFalseVariableNeitherReturnsNorAcceptsNull)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 5330u};
  const NodeId allowNullsId{1, 5331u};

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(NodeId{0, 6u});  // NS0 i=6 = Int32

  // The AllowNulls Property modelled as Part 3 section 5.6.2 defines it: a Boolean Property browse-named
  // AllowNulls, reached from the Variable by HasProperty (NS0 i=46). The antecedent is a fact of the
  // address space, not a flag handed to the service.
  auto flagResult = as.try_create_sync<VariableAccessor>(allowNullsId, NodeClass::Variable);
  ASSERT_TRUE(flagResult.is_good());
  flagResult.value().set_access_level(al);
  flagResult.value().set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
  flagResult.value().set_data_type(NodeId{0, 1u});  // NS0 i=1 = Boolean
  ASSERT_TRUE(varResult.value().try_add_reference_sync(NodeId{0, 46u}, allowNullsId, true).is_good());

  auto writeTo = [&](const NodeId& target, Variant value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = target;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = std::move(value);
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Set the Property through the service itself, then read it back, so the antecedent really is
  // AllowNulls = FALSE in the address space the Write path consults.
  {
    auto flagWrite = writeTo(allowNullsId, Variant{bool{false}});
    ASSERT_EQ(flagWrite.results().size(), 1u);
    ASSERT_TRUE(flagWrite.results()[0].is_good());

    auto flagRead = do_read_value(si, ex, allowNullsId, AttributeId::Value);
    const auto* flagStored = flagRead.value().try_as<bool>();
    ASSERT_NE(flagStored, nullptr);
    ASSERT_FALSE(*flagStored);
  }

  // (a) Never return null. The Variable has been declared but never given a value - precisely the state
  // in which an unguarded server hands back a Good null.
  {
    auto fresh = do_read_value(si, ex, nodeId, AttributeId::Value);
    ASSERT_TRUE(fresh.status().has_value());
    EXPECT_EQ(fresh.status()->as_status(), Status::BadNoData);
    ASSERT_TRUE(fresh.status()->shared_detail());
    EXPECT_EQ(fresh.status()->shared_detail()->code, "NullValueNotAllowed");
    EXPECT_TRUE(fresh.value().empty());
  }

  // Seed a concrete value so the refusal below is falsifiable on read-back.
  {
    auto seeded = writeTo(nodeId, Variant{int32_t{42}});
    ASSERT_EQ(seeded.results().size(), 1u);
    ASSERT_TRUE(seeded.results()[0].is_good());
  }

  // (b) Reject a Write of null.
  auto nullWrite = writeTo(nodeId, Variant{});
  ASSERT_EQ(nullWrite.results().size(), 1u);
  EXPECT_EQ(nullWrite.results()[0].as_status(), Status::BadTypeMismatch);
  ASSERT_TRUE(nullWrite.results()[0].shared_detail());
  EXPECT_EQ(nullWrite.results()[0].shared_detail()->code, "NullValueNotAllowed");

  // The refusal is not cosmetic, and the read half still holds after it.
  auto after = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_FALSE(after.value().empty()) << "AllowNulls = FALSE forbids ever returning a null value";
  ASSERT_TRUE(after.value().is_int32());
  EXPECT_EQ(after.value().as<int32_t>(), 42);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- String-DataType lexical conformance on the Write path -------------------

// Part 3 section 8.47: a DateString's lexical representation "shall conform to calendar date defined in
// ISO 8601-1:2019". Nothing in the encoding enforces the form - the value is a String either way - so an
// implementation whose only DataType check is "does the written built-in type match the declared type's
// built-in base type" sees String against String, accepts anything, and the malformed value surfaces at
// read time on every client rather than at write time on the one that sent it.
// @verifies AC-SVR-ADDRSP-222-STRING-LEXICAL-CONFORMANCE
TEST(WriteServiceTests, DateStringVariableRefusesAValueThatIsNotAnIso8601CalendarDate)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId dateStringDataType{0, 12881u};  // NS0 i=12881 = DateString
  const NodeId nodeId{1, 5340u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(dateStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(dateStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: a conforming calendar date is accepted, so the refusal below is attributable to the lexical
  // form and not to a blanket refusal of String writes on this Variable.
  const String conforming{"2026-08-09"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto refused = writeString(String{"09/08/2026"});
  ASSERT_EQ(refused.results().size(), 1u);
  EXPECT_TRUE(refused.results()[0].is_bad())
    << "a DateString value that is not an ISO 8601 calendar date must be refused on write";

  // Refused *rather than stored*: the malformed value must never become readable.
  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "the malformed value must not have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.43: a DecimalString "shall conform to decimal type defined in W3C XSD 1.1 Part 2" - a
// period as the decimal separator, no grouping separators, no locale formatting. Locale-formatting a numeric
// string is the natural mistake in a stack that localises text elsewhere, and it yields a value that a
// client in another locale parses differently or not at all. Both malformed shapes are driven, because
// an implementation that rejects only the comma-as-decimal-separator form still admits grouping.
// @verifies AC-SVR-ADDRSP-223-DECIMALSTRING-XSD
TEST(WriteServiceTests, DecimalStringVariableRefusesLocaleFormattedAndGroupedValues)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId decimalStringDataType{0, 12878u};  // NS0 i=12878 = DecimalString
  const NodeId nodeId{1, 5350u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(decimalStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(decimalStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: an XSD-conforming decimal is accepted.
  const String conforming{"-1234.5678"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  // A locale-specific separator (comma as the decimal point).
  auto localeFormatted = writeString(String{"1.234,56"});
  ASSERT_EQ(localeFormatted.results().size(), 1u);
  EXPECT_TRUE(localeFormatted.results()[0].is_bad())
    << "a DecimalString using a locale decimal separator must be refused on write";

  // Grouping separators, which XSD decimal does not admit either.
  auto grouped = writeString(String{"1,234.56"});
  ASSERT_EQ(grouped.results().size(), 1u);
  EXPECT_TRUE(grouped.results()[0].is_bad())
    << "a DecimalString carrying grouping separators must be refused on write";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "neither malformed value may have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.44: a DurationString "shall conform to duration as defined in ISO 8601-1:2019" - one of
// the three String DataTypes carrying an external lexical contract. A server that stores the String
// unvalidated publishes a duration no ISO 8601 parser accepts, and the failure lands on the reader.
// @verifies AC-SVR-ADDRSP-224-DURATIONSTRING-ISO8601
// the DurationString codec validator lands.
TEST(WriteServiceTests, DurationStringVariableRefusesAValueThatIsNotAnIso8601Duration)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId durationStringDataType{0, 12879u};  // NS0 i=12879 = DurationString
  const NodeId nodeId{1, 5360u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(durationStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(durationStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: a conforming ISO 8601 duration is accepted.
  const String conforming{"P1Y2M3DT4H5M6S"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto refused = writeString(String{"1h30m"});
  ASSERT_EQ(refused.results().size(), 1u);
  EXPECT_TRUE(refused.results()[0].is_bad())
    << "a DurationString that is not an ISO 8601 duration must be refused on write";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "the malformed value must not have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.45 with Unicode Annex 15: a NormalizedString "shall be normalized according to ... Form
// C". Two encodings of one string compare unequal byte for byte, so a store that keeps whatever arrived makes
// the same name match sometimes and not others. The clause admits either discipline - normalise on entry
// or refuse - so both outcomes are accepted here, but the decomposed form must never be what comes back.
// U+0041 U+030A (A + COMBINING RING ABOVE) composes to U+00C5.
// @verifies AC-SVR-ADDRSP-225-NORMALIZEDSTRING-NFC
TEST(WriteServiceTests, NormalizedStringVariableStoresNfcOrRefusesTheWrite)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId normalizedStringDataType{0, 12877u};  // NS0 i=12877 = NormalizedString
  const NodeId nodeId{1, 5370u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(normalizedStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(normalizedStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  const String composed{"\xC3\x85"};  // U+00C5, NFC
  const String decomposed{"A\xCC\x8A"};  // U+0041 U+030A, the same character decomposed

  // Seed the composed form so a refusal below is observable as "the store is unchanged".
  {
    auto accepted = writeString(composed);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto decomposedWrite = writeString(decomposed);
  ASSERT_EQ(decomposedWrite.results().size(), 1u);

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_NE(*stored, decomposed) << "a NormalizedString may never hold a non-NFC value";
  // Either discipline lands on the same observation: composed if the write was normalised and accepted,
  // and still the seeded composed value if the write was refused.
  EXPECT_EQ(*stored, composed)
    << "a NormalizedString write must come back composed, or be refused and leave the store untouched"
    << " (write result was " << (decomposedWrite.results()[0].is_good() ? "accepted" : "refused") << ")";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.46: a TimeString "shall conform to time of day as defined in ISO 8601-1:2019". As with the
// other lexically-constrained String types, the encoding carries no constraint, so a server that checks
// only the built-in base type stores a 12-hour clock reading that no ISO 8601 reader can interpret.
// @verifies AC-SVR-ADDRSP-226-TIMESTRING-ISO8601
// the TimeString codec validator lands.
TEST(WriteServiceTests, TimeStringVariableRefusesAValueThatIsNotAnIso8601TimeOfDay)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId timeStringDataType{0, 12880u};  // NS0 i=12880 = TimeString
  const NodeId nodeId{1, 5380u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(timeStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(timeStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: a conforming ISO 8601 time of day is accepted.
  const String conforming{"13:45:30"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto refused = writeString(String{"1:45 PM"});
  ASSERT_EQ(refused.results().size(), 1u);
  EXPECT_TRUE(refused.results()[0].is_bad())
    << "a TimeString that is not an ISO 8601 time of day must be refused on write";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "the malformed value must not have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Second-path hardening for the same String/null obligations --------------

// Part 3 section 5.6.2: with AllowNulls FALSE the Server "shall never return a null value and shall reject
// any request writing a null value". This drives the null through a DataValue that is NOT itself empty - the
// Variant is null but a SourceTimestamp is supplied. A plausible guard decides "did the client supply a
// value?" from whether the DataValue carries anything at all rather than from whether the Variant holds
// one, so a timestamp-bearing DataValue looks like a value-carrying write, skips the null policy, and
// stores the null. Both conjuncts are asserted: the write is refused AND no read ever yields null.
// @verifies AC-SVR-ADDRSP-086-ALLOWNULLS-FALSE-ENFORCED
TEST(WriteServiceTests, AllowNullsFalseRefusesANullValueCarriedByATimestampedDataValue)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId nodeId{1, 5400u};
  const NodeId allowNullsId{1, 5401u};

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  al.set(AccessLevelType::Bit::TimestampWrite);  // it writes a SourceTimestamp (Part 3 section 8.57)
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(NodeId{0, 6u});  // NS0 i=6 = Int32

  // The antecedent is a fact of the address space - a Boolean Property browse-named AllowNulls reached
  // from the Variable by HasProperty (NS0 i=46) - not a flag handed to the service.
  auto flagResult = as.try_create_sync<VariableAccessor>(allowNullsId, NodeClass::Variable);
  ASSERT_TRUE(flagResult.is_good());
  flagResult.value().set_access_level(al);
  flagResult.value().set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
  flagResult.value().set_data_type(NodeId{0, 1u});  // NS0 i=1 = Boolean
  ASSERT_TRUE(varResult.value().try_add_reference_sync(NodeId{0, 46u}, allowNullsId, true).is_good());

  auto writeValue = [&](const NodeId& target, Variant value, bool withTimestamp)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = target;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = std::move(value);
    if (withTimestamp)
      wv.value().source_timestamp() = DateTime::now();
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Establish AllowNulls = FALSE through the service itself and read it back, so the antecedent really
  // holds in the address space the Write path consults.
  {
    auto flagWrite = writeValue(allowNullsId, Variant{bool{false}}, false);
    ASSERT_EQ(flagWrite.results().size(), 1u);
    ASSERT_TRUE(flagWrite.results()[0].is_good());

    auto flagRead = do_read_value(si, ex, allowNullsId, AttributeId::Value);
    const auto* flagStored = flagRead.value().try_as<bool>();
    ASSERT_NE(flagStored, nullptr);
    ASSERT_FALSE(*flagStored);
  }

  // Read half, on a Variable declared but never valued - the state in which an unguarded server answers
  // Good with a null.
  {
    auto fresh = do_read_value(si, ex, nodeId, AttributeId::Value);
    ASSERT_TRUE(fresh.status().has_value());
    EXPECT_EQ(fresh.status()->as_status(), Status::BadNoData);
    ASSERT_TRUE(fresh.status()->shared_detail());
    EXPECT_EQ(fresh.status()->shared_detail()->code, "NullValueNotAllowed");
    EXPECT_TRUE(fresh.value().empty());
  }

  // Seed a concrete value so the refusal below is falsifiable on read-back.
  {
    auto seeded = writeValue(nodeId, Variant{int32_t{7}}, false);
    ASSERT_EQ(seeded.results().size(), 1u);
    ASSERT_TRUE(seeded.results()[0].is_good());
  }

  // Control: a non-null write that also carries a SourceTimestamp is honoured, so the refusal below is
  // attributable to the null and not to the timestamp.
  {
    auto timestamped = writeValue(nodeId, Variant{int32_t{8}}, true);
    ASSERT_EQ(timestamped.results().size(), 1u);
    ASSERT_TRUE(timestamped.results()[0].is_good());
  }

  auto nullWrite = writeValue(nodeId, Variant{}, true);
  ASSERT_EQ(nullWrite.results().size(), 1u);
  EXPECT_EQ(nullWrite.results()[0].as_status(), Status::BadTypeMismatch);
  ASSERT_TRUE(nullWrite.results()[0].shared_detail());
  EXPECT_EQ(nullWrite.results()[0].shared_detail()->code, "NullValueNotAllowed");

  // Write half proven not cosmetic, and read half still holds afterwards.
  auto after = do_read_value(si, ex, nodeId, AttributeId::Value);
  EXPECT_FALSE(after.value().empty()) << "AllowNulls = FALSE forbids ever returning a null value";
  ASSERT_TRUE(after.value().is_int32());
  EXPECT_EQ(after.value().as<int32_t>(), 8);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.47: a DateString's lexical representation "shall conform to calendar date defined in
// ISO 8601-1:2019" - a calendar date, not merely a string shaped like one. The value driven here has the
// exact YYYY-MM-DD shape but names month 13 and day 45, so an implementation that satisfies the clause
// with a shape-only pattern match accepts it and stores a date no calendar reader can resolve. The
// obligation is "refused on write rather than stored", so the store is read back as well.
// @verifies AC-SVR-ADDRSP-222-STRING-LEXICAL-CONFORMANCE
TEST(WriteServiceTests, DateStringVariableRefusesAWellShapedValueThatIsNotACalendarDate)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId dateStringDataType{0, 12881u};  // NS0 i=12881 = DateString
  const NodeId nodeId{1, 5410u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(dateStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(dateStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: a real calendar date is accepted, so the refusals below are attributable to the lexical
  // contract rather than to a blanket refusal of String writes on this Variable.
  const String conforming{"2026-02-28"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  // Right shape, impossible month and day.
  auto outOfRange = writeString(String{"2026-13-45"});
  ASSERT_EQ(outOfRange.results().size(), 1u);
  EXPECT_TRUE(outOfRange.results()[0].is_bad())
    << "a DateString naming month 13 and day 45 is not an ISO 8601 calendar date";

  // Right shape, a day that does not exist in that month of that (non-leap) year.
  auto nonExistentDay = writeString(String{"2026-02-30"});
  ASSERT_EQ(nonExistentDay.results().size(), 1u);
  EXPECT_TRUE(nonExistentDay.results()[0].is_bad())
    << "a DateString naming 30 February is not an ISO 8601 calendar date";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "neither malformed value may have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.43: a DecimalString "shall conform to decimal type defined in W3C XSD 1.1 Part 2". XSD
// decimal admits neither exponent notation nor the special values of xs:double - "1.5E3", "INF" and
// "NaN" are all xs:double lexical forms and none of them is an xs:decimal. An implementation that
// validates by handing the string to a general floating-point parser accepts every one of them, and the
// stored value then loses precision or fails outright in a strict xs:decimal reader.
// @verifies AC-SVR-ADDRSP-223-DECIMALSTRING-XSD
TEST(WriteServiceTests, DecimalStringVariableRefusesExponentAndSpecialFloatNotations)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId decimalStringDataType{0, 12878u};  // NS0 i=12878 = DecimalString
  const NodeId nodeId{1, 5420u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(decimalStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(decimalStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: an XSD-conforming decimal is accepted.
  const String conforming{"1500.00"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto exponent = writeString(String{"1.5E3"});
  ASSERT_EQ(exponent.results().size(), 1u);
  EXPECT_TRUE(exponent.results()[0].is_bad())
    << "exponent notation is xs:double, not xs:decimal, and must be refused on write";

  auto infinity = writeString(String{"INF"});
  ASSERT_EQ(infinity.results().size(), 1u);
  EXPECT_TRUE(infinity.results()[0].is_bad()) << "INF is not a value of the XSD decimal lexical space";

  auto notANumber = writeString(String{"NaN"});
  ASSERT_EQ(notANumber.results().size(), 1u);
  EXPECT_TRUE(notANumber.results()[0].is_bad()) << "NaN is not a value of the XSD decimal lexical space";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "none of the malformed values may have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.44: a DurationString "shall conform to duration as defined in ISO 8601-1:2019". The
// grammar is more than "starts with P": time-of-day components must sit after the T designator, and a
// duration must carry at least one component. "P1S" and "PT" and a bare "P" all satisfy a naive "leading P
// plus recognised designators" check while denoting nothing an ISO 8601 reader can decode.
// @verifies AC-SVR-ADDRSP-224-DURATIONSTRING-ISO8601
TEST(WriteServiceTests, DurationStringVariableRefusesComponentsMisplacedAgainstTheTimeDesignator)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId durationStringDataType{0, 12879u};  // NS0 i=12879 = DurationString
  const NodeId nodeId{1, 5430u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(durationStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(durationStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: seconds correctly placed after the time designator are accepted.
  const String conforming{"PT1S"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  // Time component before the T designator: "1S" in the date part is not a duration.
  auto misplaced = writeString(String{"P1S"});
  ASSERT_EQ(misplaced.results().size(), 1u);
  EXPECT_TRUE(misplaced.results()[0].is_bad())
    << "a seconds component ahead of the T designator is not an ISO 8601 duration";

  // A T designator introducing nothing.
  auto emptyTimePart = writeString(String{"PT"});
  ASSERT_EQ(emptyTimePart.results().size(), 1u);
  EXPECT_TRUE(emptyTimePart.results()[0].is_bad())
    << "a T designator with no time components is not an ISO 8601 duration";

  // A duration with no components at all.
  auto noComponents = writeString(String{"P"});
  ASSERT_EQ(noComponents.results().size(), 1u);
  EXPECT_TRUE(noComponents.results()[0].is_bad()) << "a duration must carry at least one component";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "none of the malformed values may have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.45 with Unicode Annex 15: a NormalizedString "shall be normalized according to ... Form
// C". The decomposition driven here sits at the END of the string rather than at its start - "cafe" followed
// by U+0301 COMBINING ACUTE ACCENT, which composes to "cafe". An implementation that inspects or
// normalises only the leading code point, or that short-circuits once the first character is already
// composed, leaves this value decomposed in the store and the same name then compares unequal to itself.
// The clause admits either discipline, so an accepted write must come back composed and a refused write
// must leave the seeded composed value untouched; both land on the same observation.
// @verifies AC-SVR-ADDRSP-225-NORMALIZEDSTRING-NFC
TEST(WriteServiceTests, NormalizedStringVariableHandlesADecompositionAfterTheFirstCharacter)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId normalizedStringDataType{0, 12877u};  // NS0 i=12877 = NormalizedString
  const NodeId nodeId{1, 5440u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(normalizedStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(normalizedStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  const String composed{"caf\xC3\xA9"};  // "cafe" with U+00E9, NFC
  const String decomposed{"cafe\xCC\x81"};  // "cafe" + U+0301, the same string decomposed

  // Seed the composed form so a refusal is observable as "the store is unchanged", and so the first
  // character being already composed is exactly the condition that misleads a leading-character check.
  {
    auto accepted = writeString(composed);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto decomposedWrite = writeString(decomposed);
  ASSERT_EQ(decomposedWrite.results().size(), 1u);

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_NE(*stored, decomposed) << "a NormalizedString may never hold a non-NFC value";
  EXPECT_EQ(*stored, composed)
    << "a NormalizedString write must come back composed, or be refused and leave the store untouched"
    << " (write result was " << (decomposedWrite.results()[0].is_good() ? "accepted" : "refused") << ")";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 8.46: a TimeString "shall conform to time of day as defined in ISO 8601-1:2019" - a time of
// day, not merely a colon-separated triple. "25:61:61" has the exact hh:mm:ss shape and names no time at
// all, so an implementation that discharges the clause with a shape-only pattern match stores it; and
// "24:00:01" is the trap immediately next to the one value ISO 8601 does allow past midnight, so an
// implementation that special-cases the 24:00:00 end-of-day form by testing only the hour admits it too.
// @verifies AC-SVR-ADDRSP-226-TIMESTRING-ISO8601
TEST(WriteServiceTests, TimeStringVariableRefusesAWellShapedTimeWithOutOfRangeComponents)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());

  auto as = si->address_space();
  const NodeId timeStringDataType{0, 12880u};  // NS0 i=12880 = TimeString
  const NodeId nodeId{1, 5450u};

  auto dtResult = as.try_create_sync<DataTypeAccessor>(timeStringDataType, NodeClass::DataType);
  ASSERT_TRUE(dtResult.is_good());

  auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentRead);
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);
  varResult.value().set_data_type(timeStringDataType);

  auto writeString = [&](String value)
  {
    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(value)};
    req.nodes_to_write().payload().push_back(std::move(wv));
    return do_write(si, ex, std::move(req));
  };

  // Control: a real time of day is accepted, so the refusals below are attributable to the component
  // ranges rather than to a blanket refusal of String writes on this Variable.
  const String conforming{"23:59:59"};
  {
    auto accepted = writeString(conforming);
    ASSERT_EQ(accepted.results().size(), 1u);
    ASSERT_TRUE(accepted.results()[0].is_good());
  }

  auto allFieldsOutOfRange = writeString(String{"25:61:61"});
  ASSERT_EQ(allFieldsOutOfRange.results().size(), 1u);
  EXPECT_TRUE(allFieldsOutOfRange.results()[0].is_bad())
    << "hour 25, minute 61 and second 61 name no ISO 8601 time of day";

  auto pastEndOfDay = writeString(String{"24:00:01"});
  ASSERT_EQ(pastEndOfDay.results().size(), 1u);
  EXPECT_TRUE(pastEndOfDay.results()[0].is_bad())
    << "hour 24 is admissible only as the exact end-of-day 24:00:00";

  auto dv = do_read_value(si, ex, nodeId, AttributeId::Value);
  const auto* stored = dv.value().try_as<String>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(*stored, conforming) << "neither malformed value may have been stored";
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// Registers a namespace whose attribute writes answer by a post to @p executor, open to the test role.
std::pair<std::shared_ptr<ua::test::PostingWritesNamespace>, uint16_t> add_posting_writes_namespace(
  AddressSpace& addressSpace, boost::asio::any_io_executor executor)
{
  auto postingNamespace =
    ua::test::PostingWritesNamespace::create("urn:test:posting-writes", std::move(executor));
  auto index = addressSpace.try_add_namespace_sync(postingNamespace);
  if (index.is_bad())
  {
    ADD_FAILURE() << "registering the posting namespace failed: " << ua::to_string(index.status_code());
    return {postingNamespace, 0};
  }
  RolePermissionType permission;
  permission.role_id() = ua::test_helpers::test_access_role_id();
  permission.permissions() = ua::test_helpers::all_permissions();
  postingNamespace->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
  return {postingNamespace, index.value()};
}

}  // namespace

// A non-Value Attribute is written through the node's namespace, which may answer by posting to the
// executor the Write runs on. On a one-thread executor a blocking setter waits there for an answer that
// can only run there, and the Write never completes; the awaited write must let it complete.
TEST(WriteServiceNonBlocking, NonValueAttributeWriteCompletesWhenTheNamespaceAnswersByPosting)
{
  ua::test::OneThreadExecutor executor;
  auto ex = executor.executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  auto [postingNamespace, namespaceIndex] = add_posting_writes_namespace(as, ex);
  ASSERT_NE(namespaceIndex, 0);

  const NodeId nodeId{namespaceIndex, 400u};
  auto createResult = as.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto& node = createResult.value();
  node.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
  node.set_display_name(LocalizedText{"en", "Original"});
  const auto postedBefore = postingNamespace->posted_writes(AttributeId::DisplayName);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  wv.value().value() = Variant{LocalizedText{"en", "Updated"}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u) << "the Write blocked the thread its node's namespace answers on";
  EXPECT_TRUE(resp.results()[0].is_good());
  EXPECT_GT(postingNamespace->posted_writes(AttributeId::DisplayName), postedBefore)
    << "the Write did not reach the node through the posting namespace";
  EXPECT_EQ(node.read_attribute(AttributeId::DisplayName).as<LocalizedText>().text(), "Updated");
}

// NR-51 rule 3: every layer passes a write item's status through unchanged, so a non-Value write that its
// Node completes with Good_Clamped reaches the Client as Good_Clamped. The second item, whose Node completes
// with plain Good, is the control: a service that copies one fixed code into every good result agrees with
// only one of the two.
// @relation(AC-COMP-SVR-WRITE-ITEM-STATUS-01-GOOD-SUBCODE-PASSES, scope=function)
TEST(WriteGoodSubcode, ANonValueItemKeepsTheGoodSubcodeItsNodeAnswers)
{
  boost::asio::thread_pool tp{2};
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  auto [postingNamespace, namespaceIndex] = add_posting_writes_namespace(as, ex);
  ASSERT_NE(namespaceIndex, 0);

  const NodeId clampingNode{namespaceIndex, 410u};
  const NodeId plainNode{namespaceIndex, 411u};
  for (const auto& nodeId : {clampingNode, plainNode})
  {
    auto created = as.try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good());
    created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    created.value().set_display_name(LocalizedText{"en", "Original"});
  }
  postingNamespace->answer_good_writes_with(clampingNode, StatusCode{Status::GoodClamped});
  const auto postedBefore = postingNamespace->posted_writes(AttributeId::DisplayName);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (const auto& nodeId : {clampingNode, plainNode})
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"en", "Updated"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::GoodClamped)
    << "the Good subcode the Node answered was rebuilt as " << to_string(resp.results()[0]);
  EXPECT_EQ(resp.results()[1].as_status(), Status::Good) << to_string(resp.results()[1]);
  EXPECT_EQ(postingNamespace->posted_writes(AttributeId::DisplayName), postedBefore + 2u)
    << "a write did not reach its Node through the namespace";
  ::ua::test_utils::drain_with_timeout(tp);
}

// The RolePermissions write is a route of its own (Part 18): the Node's write completion is the code under
// test, and the owning namespace's validation of the proposed RolePermissions accepts. The Node completing
// with Good_Clamped is answered Good_Clamped; the second item, whose Node completes with plain Good, is the
// control.
// @relation(AC-COMP-SVR-WRITE-ITEM-STATUS-01-GOOD-SUBCODE-PASSES, scope=function)
TEST(WriteGoodSubcode, ARolePermissionsItemKeepsTheGoodSubcodeItsNodeAnswers)
{
  boost::asio::thread_pool tp{2};
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  auto as = si->address_space();
  auto [postingNamespace, namespaceIndex] = add_posting_writes_namespace(as, ex);
  ASSERT_NE(namespaceIndex, 0);

  const NodeId clampingNode{namespaceIndex, 412u};
  const NodeId plainNode{namespaceIndex, 413u};
  for (const auto& nodeId : {clampingNode, plainNode})
  {
    auto created = as.try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good());
    created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::RolePermissions});
    // The Session may write RolePermissions here (Part 3 Table 37 bit 3).
    ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  }
  postingNamespace->answer_good_writes_with(clampingNode, StatusCode{Status::GoodClamped});
  const auto postedBefore = postingNamespace->posted_writes(AttributeId::RolePermissions);

  RolePermissionType keepsWriteRolePermissions;
  keepsWriteRolePermissions.role_id() = NodeId{ObjectId::WellKnownRole_SecurityAdmin};
  keepsWriteRolePermissions.permissions() = PermissionType{PermissionType::Bit::WriteRolePermissions};
  RolePermissionType readsForTheTestRole;
  readsForTheTestRole.role_id() = ua::test_helpers::test_access_role_id();
  readsForTheTestRole.permissions() = PermissionType{PermissionType::Bit::Read};
  const std::vector<RolePermissionType> proposed{keepsWriteRolePermissions, readsForTheTestRole};

  WriteRequest req;
  req.request_header().request_handle() = 1;
  for (const auto& nodeId : {clampingNode, plainNode})
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
    wv.value().value() = Variant{array_utils::copy_to_array_of_references(proposed)};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::GoodClamped)
    << "the Good subcode the Node answered was rebuilt as " << to_string(resp.results()[0]);
  EXPECT_EQ(resp.results()[1].as_status(), Status::Good) << to_string(resp.results()[1]);
  EXPECT_EQ(postingNamespace->posted_writes(AttributeId::RolePermissions), postedBefore + 2u)
    << "a RolePermissions write did not reach its Node through the namespace";
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// The symbolic id the DiagnosticInfo of @p item names, or "" when it names none.
std::string operation_symbolic_id(const WriteResponse& response, size_t item)
{
  if (item >= response.diagnostic_infos().size())
  {
    return {};
  }
  const auto& diagnostic = response.diagnostic_infos()[item];
  if (!diagnostic.symbolic_id().has_value())
  {
    return {};
  }
  const auto index = static_cast<size_t>(*diagnostic.symbolic_id());
  const auto& strings = response.response_header().string_table();
  return index < strings.size() ? std::string{strings[index]} : std::string{};
}

}  // namespace

// NR-51 rule 3 applied to an Uncertain completion: the item's code passes through unchanged, and its
// ErrorDetail is reported in the item's DiagnosticInfo as a Bad completion's is. The Bad item is the
// control that a detail is reported at all.
// @relation(AC-COMP-SVR-WRITE-ITEM-STATUS-01-UNCERTAIN-PASSES-WITH-DETAIL, scope=function)
TEST(WriteGoodSubcode, AnUncertainNonValueItemKeepsItsCodeAndDetail)
{
  boost::asio::thread_pool tp{2};
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestWriteSessionInfo>(ex, make_allow_all_authorizer());
  si->diagnosticsOnASecuredChannel = true;
  si->serverCfg.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  auto as = si->address_space();
  auto [postingNamespace, namespaceIndex] = add_posting_writes_namespace(as, ex);
  ASSERT_NE(namespaceIndex, 0);

  const NodeId uncertainNode{namespaceIndex, 414u};
  const NodeId badNode{namespaceIndex, 415u};
  for (const auto& nodeId : {uncertainNode, badNode})
  {
    auto created = as.try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good());
    created.value().set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    created.value().set_display_name(LocalizedText{"en", "Original"});
  }
  postingNamespace->answer_good_writes_with(uncertainNode,
    StatusCode{Status::UncertainEngineeringUnitsExceeded,
      ErrorDetail::build(
        "NodeAnswerUncertain", "The Node answered the write Uncertain", "WriteGoodSubcodeTest")});
  postingNamespace->answer_good_writes_with(badNode,
    StatusCode{Status::BadOutOfRange,
      ErrorDetail::build("NodeAnswerBad", "The Node answered the write Bad", "WriteGoodSubcodeTest")});

  WriteRequest req;
  req.request_header().request_handle() = 1;
  req.request_header().return_diagnostics() = diag::operationLevelMask;
  for (const auto& nodeId : {uncertainNode, badNode})
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
    wv.value().value() = Variant{LocalizedText{"en", "Updated"}};
    req.nodes_to_write().payload().push_back(std::move(wv));
  }

  auto resp = do_write(si, ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_EQ(resp.results()[0].as_status(), Status::UncertainEngineeringUnitsExceeded)
    << to_string(resp.results()[0]);
  EXPECT_EQ(resp.results()[1].as_status(), Status::BadOutOfRange) << to_string(resp.results()[1]);
  EXPECT_EQ(operation_symbolic_id(resp, 0), "NodeAnswerUncertain")
    << "the Uncertain item's ErrorDetail is not reported (" << resp.diagnostic_infos().size()
    << " DiagnosticInfos)";
  EXPECT_EQ(operation_symbolic_id(resp, 1), "NodeAnswerBad")
    << "the Bad item's ErrorDetail is not reported (" << resp.diagnostic_infos().size()
    << " DiagnosticInfos)";
  ::ua::test_utils::drain_with_timeout(tp);
}
