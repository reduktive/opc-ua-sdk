// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <future>

#include "ua_attribute_service_set.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_attribute_id.h"
#include "ua_access_level_type.h"
#include "ua_default_namespace.h"
#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_service_fault.h"
#include "ua_option_set.h"
#include "ua_dynamic_option_set.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"

#include "stubs.h"
#include "test_utilities.h"
#include "access_control_test_support.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// --- Test infrastructure -----------------------------------------------------

class TestOptionSetSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  TestOptionSetSessionInfo(boost::asio::any_io_executor ex, bool identityAvailable)
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
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, serverCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  ServerConfig serverCfg;

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
  std::shared_ptr<TestOptionSetSessionInfo> si, boost::asio::any_io_executor ex, WriteRequest req)
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

DataValue do_read_value(std::shared_ptr<TestOptionSetSessionInfo> si, boost::asio::any_io_executor ex,
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

shared_ptr<DynamicEnumTypeDescriptor> make_test_descriptor(std::vector<int64_t> bitNumbers)
{
  EnumDefinition def;
  for (auto bit : bitNumbers)
  {
    EnumField field;
    field.name() = String{fmt::format("Bit{}", bit)};
    field.value() = bit;
    def.fields().payload().push_back(std::move(field));
  }
  return std::make_shared<DynamicEnumTypeDescriptor>(
    String{"TestFlags"}, ExpandedNodeId{NodeId{1, 5000u}}, true, std::move(def));
}

// DataType node ID for our test OptionSet type
const NodeId optionSetDataTypeId{1, 5000u};
// Variable node ID
const NodeId variableId{1, 6000u};

struct OptionSetWriteFixture
{
  ~OptionSetWriteFixture()
  {
    ::ua::test_utils::drain_with_timeout(tp);
  }

  boost::asio::thread_pool tp;
  boost::asio::any_io_executor ex;
  std::shared_ptr<TestOptionSetSessionInfo> si;
  shared_ptr<DynamicEnumTypeDescriptor> descriptor;

  OptionSetWriteFixture(std::vector<int64_t> bitNumbers = {0, 1, 2, 3, 4, 5, 6, 7})
  {
    ex = tp.get_executor();
    si = std::make_shared<TestOptionSetSessionInfo>(ex, make_allow_all_authorizer());
    descriptor = make_test_descriptor(bitNumbers);

    auto as = si->address_space();

    // Create a DataType node with an EnumDefinition describing valid bits
    auto dtResult = as.try_create_sync<DataTypeAccessor>(optionSetDataTypeId, NodeClass::DataType);
    EXPECT_TRUE(dtResult.is_good());
    if (dtResult.is_good())
    {
      auto enumDef = std::make_shared<EnumDefinition>();
      Array<EnumField> fields;
      fields.reserve(bitNumbers.size());
      for (auto bit : bitNumbers)
      {
        EnumField f;
        f.name() = String{fmt::format("Bit{}", bit)};
        f.value() = bit;
        fields.push_back(std::move(f));
      }
      enumDef->fields() = std::move(fields);
      dtResult.value().set_data_type_definition(std::move(enumDef));
    }

    // Create a Variable node with the OptionSet DataType
    auto varResult = as.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good());
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      al.set(AccessLevelType::Bit::CurrentWrite);
      varResult.value().set_access_level(al);
      varResult.value().set_data_type(optionSetDataTypeId);
    }
  }

  void set_initial_value(ByteString value)
  {
    DynamicOptionSet os{descriptor};
    os.value() = std::move(value);
    si->address_space()
      .try_find_sync<VariableAccessor>(variableId)
      .value()
      .try_write_value_sync(Variant{std::move(os)});
  }

  WriteResponse write_option_set(ByteString value, ByteString validBits)
  {
    DynamicOptionSet os{descriptor};
    os.value() = std::move(value);
    os.valid_bits() = std::move(validBits);

    WriteRequest req;
    req.request_header().request_handle() = 1;
    WriteValue wv;
    wv.node_id() = variableId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{std::move(os)};
    req.nodes_to_write().payload().push_back(std::move(wv));

    return do_write(si, ex, std::move(req));
  }

  ByteString read_current_value()
  {
    auto dv = do_read_value(si, ex, variableId, AttributeId::Value);
    const auto* os = dv.value().try_as<OptionSet>();
    if (!os)
    {
      ADD_FAILURE() << "Read value is not an OptionSet";
      return {};
    }
    return os->value();
  }
};

// --- Tests -------------------------------------------------------------------

// F4b (address_space_1_0.md P6): a merge changes the value only; the written StatusCode and SourceTimestamp
// are the client's (OPC 10000-4 section 5.10.4.2), here with StatusWrite and TimestampWrite to allow them.
// @relation(AC-SVR-PROBE-F4B-INDEXRANGE-WRITE-KEEPS-STATUS-AND-TIMESTAMP, scope=function)
TEST(OptionSetWrite, AMergeKeepsTheWrittenStatusAndSourceTimestamp)
{
  OptionSetWriteFixture f;
  f.si->address_space()
    .try_find_sync<VariableAccessor>(variableId)
    .value()
    .set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::StatusWrite,
      AccessLevelType::Bit::TimestampWrite});
  f.set_initial_value({0xA0});

  DynamicOptionSet os{f.descriptor};
  os.value() = ByteString{0x05};
  os.valid_bits() = ByteString{0x0F};
  const DateTime stamp{std::chrono::sys_days{std::chrono::year{2024} / 1 / 1}};
  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = variableId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{std::move(os)};
  wv.value().status() = StatusCode{Status::UncertainInitialValue};
  wv.value().source_timestamp() = stamp;
  req.nodes_to_write().payload().push_back(std::move(wv));
  auto resp = do_write(f.si, f.ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].is_good());

  const auto dv = do_read_value(f.si, f.ex, variableId, AttributeId::Value);
  const auto* merged = dv.value().try_as<OptionSet>();
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->value(), ByteString({0xA5})) << "control: the merge itself";
  EXPECT_EQ(dv.status().value_or(StatusCode{Status::Good}).as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(dv.source_timestamp().has_value());
  EXPECT_EQ(*dv.source_timestamp(), stamp);
}

// @relation(AC-SVR-DA-OPTSET-001-VALIDITY-MERGE, scope=function)
// @verifies AC-SVR-ADDRSP-214-OPTIONSET-WRITE-COMPUTATION
TEST(OptionSetWrite, MergesWithValidBits)
{
  OptionSetWriteFixture f;
  f.set_initial_value({0xA0});

  // Write 0x05 with ValidBits=0x0F (only low nibble)
  auto resp = f.write_option_set({0x05}, {0x0F});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  // Expected: (0x05 & 0x0F) | (0xA0 & 0xF0) = 0x05 | 0xA0 = 0xA5
  EXPECT_EQ(f.read_current_value(), ByteString({0xA5}));
}

// @relation(SVR-DA-OPTSET-003, scope=function)
TEST(OptionSetWrite, EmptyValidBits_WholesaleReplace)
{
  OptionSetWriteFixture f;
  f.set_initial_value({0xA0});

  // Write with empty ValidBits - should replace wholesale
  DynamicOptionSet os{f.descriptor};
  os.value() = ByteString{0x42};
  // os.valid_bits() left empty

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = variableId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value().value() = Variant{std::move(os)};
  req.nodes_to_write().payload().push_back(std::move(wv));

  auto resp = do_write(f.si, f.ex, std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  EXPECT_EQ(f.read_current_value(), ByteString({0x42}));
}

// Covers SVR-ADDRSP-113..121 (coverage-audit retag).
// @relation(SVR-DA-OPTSET-003, scope=function)
TEST(OptionSetWrite, SizeMismatch_BadOutOfRange)
{
  OptionSetWriteFixture f;
  f.set_initial_value({0xA0});

  // ValidBits is 2 bytes but Value is 1 byte
  auto resp = f.write_option_set({0x05}, {0x0F, 0x00});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadOutOfRange);

  // Value should be unchanged
  EXPECT_EQ(f.read_current_value(), ByteString({0xA0}));
}

// @relation(SVR-ATTR-WRITE-025, SVR-ATTR-WRITE-031, SVR-DA-OPTSET-002, scope=function)
// @verifies AC-SVR-ADDRSP-215-VALIDBITS-UNDEFINED-BIT-REFUSED
TEST(OptionSetWrite, InvalidServerBit_BadOutOfRange)
{
  // Only define bits 0-3 as valid on the server
  OptionSetWriteFixture f({0, 1, 2, 3});
  f.set_initial_value({0x00});

  // Client tries to set bit 7 which is not defined
  auto resp = f.write_option_set({0x80}, {0x80});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0], Status::BadOutOfRange);

  // Value should be unchanged
  EXPECT_EQ(f.read_current_value(), ByteString({0x00}));
}

// @relation(SVR-DA-OPTSET-002, scope=function)
TEST(OptionSetWrite, ValidServerBits_Accepted)
{
  // Only define bits 0-3 as valid
  OptionSetWriteFixture f({0, 1, 2, 3});
  f.set_initial_value({0x00});

  // Client sets bits 0 and 1, which are within the defined range
  auto resp = f.write_option_set({0x03}, {0x03});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  EXPECT_EQ(f.read_current_value(), ByteString({0x03}));
}

// @relation(SVR-DA-OPTSET-003, scope=function)
TEST(OptionSetWrite, AllValidBits_FullReplace)
{
  OptionSetWriteFixture f;
  f.set_initial_value({0xA0});

  auto resp = f.write_option_set({0x42}, {0xFF});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  EXPECT_EQ(f.read_current_value(), ByteString({0x42}));
}

TEST(OptionSetWrite, ZeroValidBits_PreservesCurrentValue)
{
  OptionSetWriteFixture f;
  f.set_initial_value({0xA0});

  auto resp = f.write_option_set({0xFF}, {0x00});
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].is_good());

  EXPECT_EQ(f.read_current_value(), ByteString({0xA0}));
}

}  // namespace
