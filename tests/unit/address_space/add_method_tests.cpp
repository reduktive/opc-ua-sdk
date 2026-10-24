// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// add_method, bind_method and the typed local call (public API review 2026-10, item 8b sections 9.6, 9.7
// and 9.10): the Method node and its argument Properties come from one description, a binding refuses a
// node whose signature differs and says how, and a failed addition leaves nothing behind.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <vector>

#include "posting_writes_namespace.h"
#include "test_utilities.h"
#include "ua_add_method.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_data_type_registration.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_file_stream.h"
#include "ua_id_type.h"
#include "ua_instance_utils.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

namespace
{

/// A state an application describes with its own enumeration DataType, in its own namespace.
enum class RecipeState : int32_t
{
  Idle = 0,
  Running = 1
};

}  // namespace

template<>
struct ua::DataTypeOf<RecipeState>
{
  static constexpr uint32_t id{3010};
  static constexpr std::string_view namespaceUri{"urn:example:recipes"};
};

namespace
{
using namespace ua;
using namespace ua::xml::nodeset;

void load_ns0(const EncodingLimits& limits, AddressSpace& addressSpace, StructureFactory& structureFactory)
{
  auto lookupFn = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
  register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});
  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});
}

std::optional<std::string> context_value(const ErrorDetail& detail, const ContextKey& key)
{
  for (const auto& entry : detail.context)
  {
    if (entry.key == key.value())
    {
      return entry.value;
    }
  }
  return std::nullopt;
}

class AddMethodTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    load_ns0(make_encoding_limits(ApplicationConfig::load_default()), mAddressSpace, mStructureFactory);
    auto boiler = mAddressSpace.create_node_sync(mBoilerId, NodeClass::Object);
    boiler.set_browse_name(QualifiedName{1, "Boiler"});
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// The Argument entries of the Method's Property @p name; empty when the Property is absent.
  std::vector<Argument> declared(const NodeId& methodId, const std::string& name)
  {
    std::promise<VariableAccessorResult> found;
    instance_utils::find_child_variable_accessor_by_browse_name_async(mAddressSpace,
      methodId,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, name},
      [&found](VariableAccessorResult result) { found.set_value(std::move(result)); });
    auto property = found.get_future().get();
    if (property.is_bad())
    {
      return {};
    }
    std::vector<Argument> arguments;
    const auto value = property.value().read_value_sync();
    for (const auto& element : value.value().as<Array<RefStructure<Structure>>>().payload())
    {
      arguments.push_back(*dynamic_cast<const Argument*>(element.get()));
    }
    return arguments;
  }

  bool references(const NodeId& from, const NodeId& type, const NodeId& to, bool isForward)
  {
    for (const auto& reference : mAddressSpace.find_node_sync(from).get_references_sync())
    {
      if (reference.type_id() == type && reference.target_id().node_id() == to &&
          reference.is_forward() == isForward)
      {
        return true;
      }
    }
    return false;
  }

  boost::asio::thread_pool mPool{2};
  AddressSpace mAddressSpace = AddressSpace::create("urn:test:add-method", mPool.get_executor());
  StructureFactory mStructureFactory;
  const NodeId mBoilerId{1, "Boiler"};
};

MethodResult<double> scale(const MethodCall&, double factor)
{
  if (factor <= 0.0)
  {
    return reject_argument(0, Status::BadOutOfRange);
  }
  return factor * 10.0;
}

TEST_F(AddMethodTest, OneCallPublishesTheSignatureAndAnswersThroughTheHandler)
{
  const auto method = add_method_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Scale"},
    inputs(arg<double>("Factor", "Multiplies the setpoint")),
    outputs(arg<double>("Setpoint")),
    scale,
    MethodConfig{.nodeId = NodeId{1, "Scale"}, .description = LocalizedText{"", "Scales the setpoint"}});

  EXPECT_EQ(method.get_node_id(), (NodeId{1, "Scale"}));
  EXPECT_EQ(method.get_browse_name(), (QualifiedName{1, "Scale"}));
  EXPECT_TRUE(method.get_executable());
  EXPECT_TRUE(references(mBoilerId, NodeId{ReferenceTypeId::HasComponent}, method.get_node_id(), true));
  EXPECT_TRUE(references(method.get_node_id(), NodeId{ReferenceTypeId::HasComponent}, mBoilerId, false))
    << "the Method carries the inverse half, so a delete can find its parent";

  const auto in = declared(method.get_node_id(), "InputArguments");
  ASSERT_EQ(in.size(), 1u);
  EXPECT_EQ(in[0].name(), String{"Factor"});
  EXPECT_EQ(in[0].description().text(), String{"Multiplies the setpoint"});
  EXPECT_EQ(in[0].data_type(), NodeId{DataTypeId::Double});
  EXPECT_EQ(in[0].value_rank(), ValueRank::scalar);
  const auto out = declared(method.get_node_id(), "OutputArguments");
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].name(), String{"Setpoint"});

  EXPECT_EQ(method.call_sync<double>(mBoilerId, 2.0), 20.0);
  const auto rejected = method.try_call_sync<double>(mBoilerId, -1.0);
  EXPECT_EQ(rejected.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_EQ(rejected.argument_results().size(), 1u);
  EXPECT_EQ(rejected.argument_results().at(0), StatusCode{Status::BadOutOfRange});
  EXPECT_THROW((void)method.call_sync<double>(mBoilerId, -1.0), UaException);
}

TEST_F(AddMethodTest, AMethodWithoutArgumentsHasNoArgumentProperties)
{
  int resets = 0;
  const auto method = add_method_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Reset"},
    inputs(),
    outputs(),
    [&resets](const MethodCall&) -> MethodResult<>
    {
      ++resets;
      return {};
    });
  EXPECT_TRUE(declared(method.get_node_id(), "InputArguments").empty());
  EXPECT_TRUE(declared(method.get_node_id(), "OutputArguments").empty());
  method.call_sync<>(mBoilerId);
  EXPECT_EQ(resets, 1);
}

TEST_F(AddMethodTest, TheDefaultNodeIdIsAGuidInTheParentsNamespaceAndNeverNamespaceZero)
{
  const auto underBoiler = add_method_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "A"},
    inputs(),
    outputs(),
    [](const MethodCall&) -> MethodResult<> { return {}; });
  EXPECT_EQ(underBoiler.get_node_id().namespace_index(), 1u);
  EXPECT_EQ(underBoiler.get_node_id().identifier().type(), IdType::Guid);

  const auto underObjects = add_method_sync(mAddressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "B"},
    inputs(),
    outputs(),
    [](const MethodCall&) -> MethodResult<> { return {}; });
  EXPECT_EQ(underObjects.get_node_id().namespace_index(), 1u)
    << "a server's own node may not be in namespace 0 (OPC 10000-5 4.1)";
}

TEST_F(AddMethodTest, AnotherNamespacesDataTypeIsResolvedAndAnUnregisteredOneFailsLeavingNothing)
{
  const NodeId refusedId{1, "Start"};
  const auto refused = try_add_method_sync(
    mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Start"},
    inputs(arg<RecipeState>("State")),
    outputs(),
    [](const MethodCall&, RecipeState) -> MethodResult<> { return {}; },
    MethodConfig{.nodeId = refusedId});
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadInvalidState});
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(context_value(*refused.shared_detail(), ContextKeys::namespaceUri), "urn:example:recipes");
  EXPECT_EQ(mAddressSpace.try_find_node_sync(refusedId).status_code(), StatusCode{Status::BadNodeIdUnknown});

  const auto recipes = mAddressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:example:recipes", mPool.get_executor()));
  const auto method = add_method_sync(
    mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Start"},
    inputs(arg<RecipeState>("State")),
    outputs(arg<RecipeState>("Previous")),
    [](const MethodCall&, RecipeState state) -> MethodResult<RecipeState> { return state; },
    MethodConfig{.nodeId = refusedId});
  const auto in = declared(method.get_node_id(), "InputArguments");
  ASSERT_EQ(in.size(), 1u);
  EXPECT_EQ(in[0].data_type(), (NodeId{recipes, uint32_t{3010}}))
    << "the DataType carries the server's index";
  EXPECT_EQ(method.call_sync<RecipeState>(mBoilerId, RecipeState::Running), RecipeState::Running);
}

TEST_F(AddMethodTest, ANamespaceWithoutCallHandlersFailsWithNotSupportedAndLeavesNothing)
{
  const auto refusing = mAddressSpace.add_namespace_sync(test::PostingWritesNamespace::create(
    "urn:test:no-call-handlers", mPool.get_executor(), test::PostingWritesNamespace::CallHandlers::Refused));
  const NodeId parentId{refusing, "Device"};
  mAddressSpace.create_node_sync(parentId, NodeClass::Object);
  const NodeId methodId{refusing, "Identify"};

  const auto refused = try_add_method_sync(
    mAddressSpace,
    parentId,
    QualifiedName{refusing, "Identify"},
    inputs(),
    outputs(arg<std::string>("SerialNumber")),
    [](const MethodCall&) -> MethodResult<std::string> { return std::string{"SN-1"}; },
    MethodConfig{.nodeId = methodId});
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadNotSupported});
  EXPECT_EQ(mAddressSpace.try_find_node_sync(methodId).status_code(), StatusCode{Status::BadNodeIdUnknown})
    << "the half-made Method is deleted";
}

TEST_F(AddMethodTest, OnTheExecutorTheBlockingFormRefusesAndTheAsyncFormAdds)
{
  std::promise<StatusCode> refused;
  std::promise<Result<MethodAccessor>> added;
  boost::asio::post(mPool.get_executor(),
    [this, &refused, &added]
    {
      refused.set_value(try_add_method_sync(mAddressSpace,
        mBoilerId,
        QualifiedName{1, "X"},
        inputs(),
        outputs(),
        [](const MethodCall&) -> MethodResult<>
        { return {}; }).status_code());
      add_method_async(
        mAddressSpace,
        mBoilerId,
        QualifiedName{1, "Y"},
        inputs(),
        outputs(),
        [](const MethodCall&) -> MethodResult<> { return {}; },
        [&added](Result<MethodAccessor> created) { added.set_value(std::move(created)); });
    });
  auto refusedFuture = refused.get_future();
  auto addedFuture = added.get_future();
  ASSERT_EQ(refusedFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  EXPECT_EQ(refusedFuture.get(), StatusCode{Status::BadWouldBlock});
  ASSERT_EQ(addedFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  EXPECT_TRUE(addedFuture.get().is_good());
}

class BindMethodTest : public AddMethodTest
{
protected:
  void SetUp() override
  {
    AddMethodTest::SetUp();
    mMethod.emplace(add_method_sync(mAddressSpace,
      mBoilerId,
      QualifiedName{1, "Scale"},
      inputs(arg<double>("Factor")),
      outputs(arg<double>("Setpoint")),
      scale,
      MethodConfig{.nodeId = mMethodId}));
  }

  const NodeId mMethodId{1, "Scale"};
  std::optional<MethodAccessor> mMethod;
};

TEST_F(BindMethodTest, AMatchingSignatureReplacesTheHandlerByNodeOrByName)
{
  bind_method_sync(mAddressSpace,
    mMethodId,
    inputs(arg<double>("Factor")),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall&, double factor) -> MethodResult<double> { return factor + 1.0; });
  EXPECT_EQ(mMethod->call_sync<double>(mBoilerId, 2.0), 3.0);

  bind_method_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Scale"},
    inputs(arg<double>("Factor")),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall& call, double factor, MethodResultCallback<double> done)
    {
      EXPECT_EQ(call.object_id(), NodeId(1, "Boiler"));
      done(factor - 1.0);
    });
  EXPECT_EQ(mMethod->call_sync<double>(mBoilerId, 2.0), 1.0);
}

TEST_F(BindMethodTest, EachMismatchIsRefusedWithWhatDiffers)
{
  const auto count = try_bind_method_sync(mAddressSpace,
    mMethodId,
    inputs(),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall&) -> MethodResult<double> { return 0.0; });
  ASSERT_TRUE(count.is_bad());
  EXPECT_EQ(count.status_code(), StatusCode{Status::BadInvalidArgument});
  EXPECT_EQ(count.shared_detail()->code, "MethodArgumentCountMismatch");

  const auto name = try_bind_method_sync(mAddressSpace,
    mMethodId,
    inputs(arg<double>("Gain")),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall&, double) -> MethodResult<double> { return 0.0; });
  ASSERT_TRUE(name.is_bad());
  EXPECT_EQ(name.shared_detail()->code, "MethodArgumentNameMismatch");
  EXPECT_EQ(context_value(*name.shared_detail(), ContextKeys::operationIndex), "0");
  EXPECT_EQ(context_value(*name.shared_detail(), ContextKeys::expected), "Gain");
  EXPECT_EQ(context_value(*name.shared_detail(), ContextKeys::actual), "Factor");

  const auto type = try_bind_method_sync(mAddressSpace,
    mMethodId,
    inputs(arg<float>("Factor")),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall&, float) -> MethodResult<double> { return 0.0; });
  ASSERT_TRUE(type.is_bad());
  EXPECT_EQ(type.shared_detail()->code, "MethodArgumentTypeMismatch");
  EXPECT_EQ(context_value(*type.shared_detail(), ContextKeys::fieldName), "Factor");
  EXPECT_EQ(
    context_value(*type.shared_detail(), ContextKeys::typeExpected), to_string(NodeId{DataTypeId::Float}));
  EXPECT_EQ(
    context_value(*type.shared_detail(), ContextKeys::typeActual), to_string(NodeId{DataTypeId::Double}));

  const auto rank = try_bind_method_sync(mAddressSpace,
    mMethodId,
    inputs(arg<std::vector<double>>("Factor")),
    outputs(arg<double>("Setpoint")),
    [](const MethodCall&, const std::vector<double>&) -> MethodResult<double> { return 0.0; });
  ASSERT_TRUE(rank.is_bad());
  EXPECT_EQ(rank.shared_detail()->code, "MethodArgumentTypeMismatch");
  EXPECT_EQ(context_value(*rank.shared_detail(), ContextKeys::expected), "1");
  EXPECT_EQ(context_value(*rank.shared_detail(), ContextKeys::actual), "-1");

  EXPECT_EQ(mMethod->call_sync<double>(mBoilerId, 2.0), 20.0)
    << "a refused binding leaves the handler as it was";
}

TEST_F(BindMethodTest, ANodeWithoutPropertiesHasNoArgumentsAndAnObjectIsNotAMethod)
{
  const NodeId bareId{1, "Bare"};
  mAddressSpace.create_node_sync(bareId, NodeClass::Method);
  EXPECT_TRUE(try_bind_method_sync(
    mAddressSpace, bareId, inputs(), outputs(), [](const MethodCall&) -> MethodResult<> { return {}; })
                .is_good());
  EXPECT_EQ(try_bind_method_sync(mAddressSpace,
              bareId,
              inputs(arg<double>("Factor")),
              outputs(),
              [](const MethodCall&, double) -> MethodResult<> { return {}; })
              .shared_detail()
              ->code,
    "MethodArgumentCountMismatch");
  EXPECT_EQ(
    try_bind_method_sync(
      mAddressSpace, mBoilerId, inputs(), outputs(), [](const MethodCall&) -> MethodResult<> { return {}; })
      .status_code(),
    StatusCode{Status::BadNodeClassInvalid});
}

TEST_F(BindMethodTest, ATypedCallWhoseOutputsDifferIsATypeMismatch)
{
  const auto wrongType = mMethod->try_call_sync<std::string>(mBoilerId, 2.0);
  EXPECT_EQ(wrongType.status_code(), StatusCode{Status::BadTypeMismatch});
  EXPECT_EQ(wrongType.status_code().shared_detail()->code, "MethodOutputTypeMismatch");
  const auto wrongCount = mMethod->try_call_sync<double, double>(mBoilerId, 2.0);
  EXPECT_EQ(wrongCount.status_code().shared_detail()->code, "MethodOutputsMismatch");
}

}  // namespace
