// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Runs the compliance_test_server's own AddressSpaceSeed and checks that it carries what each CTT
// conformance unit looks for before it will test anything. A unit that cannot find its node skips, and a
// skip tests nothing: these are the shapes that turned the skips of 2026-10-01 into executed cases.

#include <gtest/gtest.h>

#include "address_space_seed.h"
#include "compliance_helpers.h"
#include "helpers/requests.h"
#include "server_setup.h"
#include "ua_session_attribute_services.h"
#include "ua_test_server.h"

#include "ua_access_level_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_currency_unit_type.h"
#include "ua_namespace.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_variable_id.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_security_policy.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unistd.h>

namespace
{

/// The seed writes its file-transfer fixtures into the working directory; keep them out of the build tree.
class ScopedWorkingDirectory
{
public:
  ScopedWorkingDirectory()
    : mPrevious{std::filesystem::current_path()},
      mDirectory{
        std::filesystem::temp_directory_path() / ("compliance_seed_coverage_" + std::to_string(::getpid()))}
  {
    std::filesystem::create_directories(mDirectory);
    std::filesystem::current_path(mDirectory);
  }

  ~ScopedWorkingDirectory()
  {
    std::error_code ignored;
    std::filesystem::current_path(mPrevious, ignored);
    std::filesystem::remove_all(mDirectory, ignored);
  }

  ScopedWorkingDirectory(const ScopedWorkingDirectory&) = delete;
  ScopedWorkingDirectory& operator=(const ScopedWorkingDirectory&) = delete;

private:
  std::filesystem::path mPrevious;
  std::filesystem::path mDirectory;
};

class ComplianceSeedCoverage : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();
    mSeed = std::make_unique<ua::compliance_test_server::AddressSpaceSeed>(
      mServer.server(), mSeedWorker.get_executor());
    mNamespaceIndex = address_space().namespace_array().get_namespace_index(
      std::string{ua::compliance_test_server::complianceNamespaceUri});
  }

  void TearDown() override
  {
    mSeed.reset();
    mSeedWorker.join();
  }

  ua::AddressSpace address_space()
  {
    return mServer.server().address_space();
  }

  /// The seeded node with string identifier @p path in the compliance namespace.
  ua::NodeAccessor node(const std::string& path)
  {
    auto found = address_space().try_find_node_sync(ua::NodeId{mNamespaceIndex, path});
    EXPECT_TRUE(found.is_good()) << path << " is not in the address space";
    return found.value();
  }

  /// The Property of @p owner whose BrowseName is @p name (namespace 0), if it has one.
  std::optional<ua::VariableAccessor> property(const ua::NodeAccessor& owner, std::string_view name)
  {
    for (const auto& reference : owner.get_properties_sync())
    {
      auto target = address_space().try_find_node_sync(reference.target_id().node_id());
      if (target.is_bad())
        continue;
      const auto browseName = target.value().get_browse_name();
      if (browseName.namespace_index() == 0 && std::string_view{browseName.name()} == name)
        return target.value().as<ua::VariableAccessor>();
    }
    return std::nullopt;
  }

  ScopedWorkingDirectory mWorkingDirectory;
  ua::test_helpers::TestServer mServer;
  boost::asio::thread_pool mSeedWorker{1};
  std::unique_ptr<ua::compliance_test_server::AddressSpaceSeed> mSeed;
  uint16_t mNamespaceIndex{0};
};

bool writable(const ua::VariableAccessor& variable)
{
  return variable.get_access_level().test(ua::AccessLevelType::Bit::CurrentWrite);
}

}  // namespace

// Data Access DataItems 006-012 and Err-001 write the optional Definition and ValuePrecision Properties of
// the configured DataItems; without them every case skips. Part 8 5.3.1 defines ValuePrecision only for
// Float, Double and DateTime values, and for a DateTime as a time difference in nanoseconds.
TEST_F(ComplianceSeedCoverage, DataItemsCarryAWritableDefinitionAndValuePrecisionWhereItApplies)
{
  for (const auto* type : {"Byte", "DateTime", "Double", "Float", "Int32", "String"})
  {
    const auto item = node(std::string{"Surface.DataAccess.Data."} + type);
    const auto definition = property(item, "Definition");
    ASSERT_TRUE(definition.has_value()) << type << " has no Definition";
    EXPECT_TRUE(writable(*definition)) << type;
    EXPECT_TRUE(definition->read_value_sync().value().is_string()) << type;
  }
  for (const auto* type : {"DateTime", "Double", "Float"})
  {
    const auto precision = property(node(std::string{"Surface.DataAccess.Data."} + type), "ValuePrecision");
    ASSERT_TRUE(precision.has_value()) << type << " has no ValuePrecision";
    EXPECT_TRUE(writable(*precision)) << type;
    EXPECT_GT(precision->read_value_sync().value().as<double>(), 0.0) << type;
  }
  EXPECT_FALSE(property(node("Surface.DataAccess.Data.Int32"), "ValuePrecision").has_value())
    << "ValuePrecision does not apply to an integer";
}

// Base Info Selection List 002-005 need a SelectionListType instance. Its value is one of its Selections,
// each Selection has a description, and RestrictToList is FALSE and read-only - so writing a value outside
// the list succeeds, and a Client cannot switch the restriction on (Part 5 7.18).
TEST_F(ComplianceSeedCoverage, ASelectionListOffersItsValueAmongItsSelections)
{
  const auto list = node("Surface.DataAccess.SelectionList");
  const auto selections = property(list, "Selections");
  const auto descriptions = property(list, "SelectionDescriptions");
  const auto restrict = property(list, "RestrictToList");
  ASSERT_TRUE(selections && descriptions&& restrict);

  const auto values = selections->read_value_sync().value();
  ASSERT_TRUE(values.is_array());
  const auto* choices = values.try_as<ua::Array<int32_t>>();
  ASSERT_NE(choices, nullptr) << "Selections is not typed like the value";
  const auto descriptionValue = descriptions->read_value_sync();
  const auto* texts = descriptionValue.value().try_as<ua::Array<ua::LocalizedText>>();
  ASSERT_NE(texts, nullptr);
  EXPECT_EQ(texts->size(), choices->size());

  const auto current = list.as<ua::VariableAccessor>()->read_value_sync().value();
  const auto* currentValue = current.try_as<int32_t>();
  ASSERT_NE(currentValue, nullptr);
  EXPECT_NE(std::find(choices->begin(), choices->end(), *currentValue), choices->end())
    << "the value is not one of the Selections";

  EXPECT_EQ(restrict->read_value_sync().value(), ua::Variant{false});
  EXPECT_FALSE(writable(*restrict));
}

// The Address Space WriteMask and UserWriteMask units write the Attributes the Boolean scalar declares
// writable; with a WriteMask of 0 they have nothing to test.
TEST_F(ComplianceSeedCoverage, TheBooleanScalarDeclaresDisplayNameAndDescriptionWritable)
{
  const auto mask = node("Surface.Scalars.Boolean").get_write_mask();
  ASSERT_TRUE(mask.has_value());
  EXPECT_TRUE(mask->test(ua::AttributeWriteMask::Bit::DisplayName));
  EXPECT_TRUE(mask->test(ua::AttributeWriteMask::Bit::Description));
}

// Monitor Value Change V2 020 reads the first and last three bytes of each ByteString array element.
TEST_F(ComplianceSeedCoverage, ByteStringArrayElementsAreAtLeastFourBytes)
{
  const auto value =
    node("Surface.Arrays.ByteStringArray").as<ua::VariableAccessor>()->read_value_sync().value();
  const auto* elements = value.try_as<ua::Array<ua::ByteString>>();
  ASSERT_NE(elements, nullptr);
  ASSERT_GE(elements->size(), 4u);
  for (const auto& element : *elements)
    EXPECT_GE(element.size(), 4u);
}

// View Basic 2 017-018: a View in the Views folder whose members include the Scalars folder's Variables.
TEST_F(ComplianceSeedCoverage, AViewInTheViewsFolderContainsTheScalars)
{
  const auto viewNode = node("Surface.ScalarsView");
  ASSERT_EQ(viewNode.get_node_class(), ua::NodeClass::View);
  bool inViewsFolder = false;
  for (const auto& reference :
    address_space().find_node_sync(ua::NodeId{ua::ObjectId::ViewsFolder}).get_references_sync())
    inViewsFolder |= reference.is_forward() && reference.target_id().node_id() == viewNode.get_node_id();
  EXPECT_TRUE(inViewsFolder);
  const auto view = viewNode.as<ua::ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  EXPECT_TRUE(view->is_node_in_view_sync(ua::NodeId{mNamespaceIndex, std::string{"Surface.Scalars.Int32"}}));
  EXPECT_FALSE(view->is_node_in_view_sync(ua::NodeId{ua::ObjectTypeId::FolderType}))
    << "a type definition is not a member";
}

// View Basic 2 005, 015, 016, 020 need one node with a ReferenceType and a subtype of it.
TEST_F(ComplianceSeedCoverage, ReferenceShapesHasAComponentAndAnOrderedComponent)
{
  bool component = false;
  bool ordered = false;
  for (const auto& reference : node("Surface.ReferenceShapes").get_references_sync())
  {
    if (!reference.is_forward())
      continue;
    component |= reference.type_id() == ua::NodeId{ua::ReferenceTypeId::HasComponent};
    ordered |= reference.type_id() == ua::NodeId{ua::ReferenceTypeId::HasOrderedComponent};
  }
  EXPECT_TRUE(component);
  EXPECT_TRUE(ordered);
}

namespace
{
/// The permissions a node's own RolePermissions give @p role, if it lists the Role.
std::optional<ua::PermissionType> permissions_of(const ua::NodeAccessor& node, ua::ObjectId role)
{
  const auto permissions = node.get_role_permissions();
  if (!permissions)
    return std::nullopt;
  for (const auto& entry : *permissions)
  {
    if (entry.role_id() == ua::NodeId{role})
      return entry.permissions();
  }
  return std::nullopt;
}
}  // namespace

// The NotUser settings: the AccessLevel allows the operation and the node's RolePermissions withhold it
// from Observer, the Role of the CTT's anonymous Sessions.
TEST_F(ComplianceSeedCoverage, NotUserNodesWithholdFromObserverWhatTheirAccessLevelAllows)
{
  const auto writeNotUser = node("Surface.SecurityAccess.WriteNotUser");
  EXPECT_TRUE(writable(*writeNotUser.as<ua::VariableAccessor>()));
  const auto writer = permissions_of(writeNotUser, ua::ObjectId::WellKnownRole_Observer);
  ASSERT_TRUE(writer.has_value());
  EXPECT_TRUE(writer->test(ua::PermissionType::Bit::Read));
  EXPECT_FALSE(writer->test(ua::PermissionType::Bit::Write));

  const auto readNotUser = node("Surface.SecurityAccess.ReadNotUser");
  EXPECT_TRUE(
    readNotUser.as<ua::VariableAccessor>()->get_access_level().test(ua::AccessLevelType::Bit::CurrentRead));
  const auto reader = permissions_of(readNotUser, ua::ObjectId::WellKnownRole_Observer);
  ASSERT_TRUE(reader.has_value());
  EXPECT_FALSE(reader->test(ua::PermissionType::Bit::Read));
}

// The compliance server lets the CTT's anonymous Sessions toggle diagnostics (Base Info Diagnostics 018),
// and only there: every other Role keeps namespace 0's default.
TEST_F(ComplianceSeedCoverage, ObserverMayWriteTheDiagnosticsEnabledFlag)
{
  const auto flag =
    address_space().find_node_sync(ua::NodeId{ua::VariableId::Server_ServerDiagnostics_EnabledFlag});
  const auto observer = permissions_of(flag, ua::ObjectId::WellKnownRole_Observer);
  ASSERT_TRUE(observer.has_value());
  EXPECT_TRUE(observer->test(ua::PermissionType::Bit::Write));
  const auto defaults = address_space().namespace_array().get_namespace(0)->default_role_permissions();
  if (defaults)
    EXPECT_EQ(flag.get_role_permissions()->size(), std::max<size_t>(defaults->size(), 1u))
      << "the other Roles keep namespace 0's defaults";
}

// The Events/TriggerNode settings name a Variable whose writes raise an Event; a CurrencyUnit Property backs
// Base Info Currency; the HA Profile array, structure and no-access settings name historised nodes.
TEST_F(ComplianceSeedCoverage, TriggerCurrencyAndShapedHistoryNodesExist)
{
  EXPECT_TRUE(writable(*node("Surface.Live.EventTrigger").as<ua::VariableAccessor>()));

  const auto currency = property(node("Surface.DataAccess.Price"), "CurrencyUnit");
  ASSERT_TRUE(currency.has_value());
  const auto currencyValue = currency->read_value_sync();
  const auto* unit = currencyValue.value().try_as<ua::CurrencyUnitType>();
  ASSERT_NE(unit, nullptr);
  EXPECT_EQ(unit->numeric_code(), 978);
  EXPECT_EQ(std::string_view{unit->alphabetic_code()}, "EUR");

  for (const auto* name :
    {"HistorisedArray", "HistorisedMatrix", "HistorisedStructure", "HistorisedNoAccess"})
    EXPECT_TRUE(node(std::string{"Surface.Live."} + name).as<ua::VariableAccessor>()->get_historizing())
      << name;
  EXPECT_EQ(node("Surface.Live.HistorisedMatrix").as<ua::VariableAccessor>()->get_array_dimensions(),
    (std::vector<uint32_t>{5, 5}));
  const auto noAccess =
    permissions_of(node("Surface.Live.HistorisedNoAccess"), ua::ObjectId::WellKnownRole_Observer);
  ASSERT_TRUE(noAccess.has_value());
  EXPECT_FALSE(noAccess->test(ua::PermissionType::Bit::ReadHistory));
  EXPECT_FALSE(noAccess->test(ua::PermissionType::Bit::Read));
}

// The one-dimensional arrays accept a write of any length, and say so: ArrayDimensions [0], the value Part 3
// 5.6.2 gives an unknown maximum.
// Monitor Items Deadband Filter 015 looks for exactly that before growing and shrinking an array.
TEST_F(ComplianceSeedCoverage, OneDimensionalArraysDeclareAVariableLength)
{
  for (const auto* name : {"Int32Array", "DoubleArray", "ByteStringArray"})
    EXPECT_EQ(node(std::string{"Surface.Arrays."} + name).as<ua::VariableAccessor>()->get_array_dimensions(),
      (std::vector<uint32_t>{0}))
      << name;
}

namespace
{
/// The seed on a server a Client is connected to, for what only the services show.
class ComplianceSeedOverTheWire : public ComplianceWithSession
{
protected:
  void SetUp() override
  {
    ComplianceWithSession::SetUp();
    mSeed = std::make_unique<ua::compliance_test_server::AddressSpaceSeed>(
      mServer.server(), mSeedWorker.get_executor());
    mNamespaceIndex = mServer.server().address_space().namespace_array().get_namespace_index(
      std::string{ua::compliance_test_server::complianceNamespaceUri});
  }

  void TearDown() override
  {
    mSeed.reset();
    mSeedWorker.join();
    ComplianceWithSession::TearDown();
  }

  ScopedWorkingDirectory mWorkingDirectory;
  boost::asio::thread_pool mSeedWorker{1};
  std::unique_ptr<ua::compliance_test_server::AddressSpaceSeed> mSeed;
  uint16_t mNamespaceIndex{0};
};
}  // namespace

// Historical Access Read Raw Err-016 asks a node whose archive keeps no server timestamps for server
// timestamps and expects Bad_TimestampNotSupported (Part 11 6.4); it skips when no such node is configured.
// The node's history answers with source timestamps and refuses server ones.
TEST_F(ComplianceSeedOverTheWire, OneHistorisedNodeKeepsSourceTimestampsOnly)
{
  const ua::NodeId node{mNamespaceIndex, std::string{"Surface.Live.HistorisedSourceTimestampsOnly"}};
  const auto read = [&](ua::TimestampsToReturn timestamps)
  {
    auto request = HistoryReadRawBuilder(ua::DateTime{2000, 1, 1, 0, 0, 0}, ua::DateTime::now(), 10)
                     .timestamps(timestamps)
                     .read(node)
                     .build();
    auto response = mSession->attributes().try_history_read_sync(std::move(request));
    EXPECT_TRUE(response.is_good());
    EXPECT_EQ(response.value().results().size(), 1U);
    return response.value().results()[0].status_code();
  };

  EXPECT_TRUE(read(ua::TimestampsToReturn::Source).is_good());
  EXPECT_EQ(read(ua::TimestampsToReturn::Server), ua::StatusCode{ua::Status::BadTimestampNotSupported});
}

// Security User Anonymous 003 opens an encrypting endpoint that offers no anonymous token and expects an
// anonymous ActivateSession to be refused; it skips when every encrypting endpoint admits anonymous users.
// Exactly one does not, so every other unit keeps the anonymous sessions it relies on.
TEST(ComplianceServerEndpoints, OneEncryptingEndpointAdmitsOnlyIdentifiedUsers)
{
  const auto listener = ua::compliance_test_server::build_listener();
  std::vector<ua::SecurityPolicyId> withoutAnonymous;
  for (const auto& endpoint : listener.endpoints)
  {
    const bool anonymous = std::ranges::any_of(endpoint.userIdentityTokens,
      [](const ua::UserTokenPolicy& token) { return token.token_type() == ua::UserTokenType::Anonymous; });
    if (!anonymous)
    {
      EXPECT_EQ(endpoint.messageSecurityMode, ua::MessageSecurityMode::SignAndEncrypt) << endpoint.name;
      withoutAnonymous.push_back(endpoint.securityPolicyId);
    }
  }
  EXPECT_EQ(withoutAnonymous, std::vector<ua::SecurityPolicyId>{ua::SecurityPolicyId::Basic256Sha256});
}

// The compliance test server serves every SecurityPolicy the SDK implements - the fourteen with
// SecureChannelEnhancements and the legacy RSA policies - once in Sign and once in SignAndEncrypt mode,
// under names that tell the endpoints apart, so a conformance run reaches each policy.
TEST(ComplianceServerEndpoints, EveryPolicyIsServedInSignAndInSignAndEncrypt)
{
  const auto listener = ua::compliance_test_server::build_listener();
  std::set<std::string> names;
  for (const auto& endpoint : listener.endpoints)
    EXPECT_TRUE(names.insert(endpoint.name).second) << "duplicate endpoint name " << endpoint.name;

  const auto served = [&](ua::SecurityPolicyId policy, ua::MessageSecurityMode mode)
  {
    return std::ranges::count_if(listener.endpoints,
      [&](const auto& endpoint)
      { return endpoint.securityPolicyId == policy && endpoint.messageSecurityMode == mode; });
  };
  size_t enhanced = 0;
  for (const auto policy : ua::SecurityPolicy::supported_policy_ids())
  {
    if (policy == ua::SecurityPolicyId::None)
      continue;
    const auto securityPolicy = ua::SecurityPolicy::create(policy);
    if (securityPolicy->is_deprecated() && !ua::compliance_test_server::enableDeprecatedRsaPolicies)
      continue;
    enhanced += securityPolicy->secure_channel_enhancements() ? 1 : 0;
    EXPECT_EQ(served(policy, ua::MessageSecurityMode::Sign), 1) << static_cast<int>(policy);
    EXPECT_EQ(served(policy, ua::MessageSecurityMode::SignAndEncrypt), 1) << static_cast<int>(policy);
  }
  EXPECT_EQ(enhanced, 14u);
}
