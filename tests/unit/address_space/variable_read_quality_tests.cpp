// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Which layer reports a bad VALUE quality on an in-process Variable read.
///
/// The SDK offers two reads over the same node, and they answer different questions:
///
///   BaseVariable::read_value_* / instance_utils::read_variable_data_value_async
///       TWO LAYERS (OPC 10000-4, and what the documentation teaches): the Result reports
///       whether the READ worked; the quality of what was read rides on
///       DataValue::status(). A faulted transmitter yields a GOOD Result carrying a
///       Bad-quality DataValue, so the caller gets the last value AND the fact that it is
///       suspect.
///
///   instance_utils::read_variable_value_async
///       FLATTENED, deliberately, for the SDK's own callers - alarm evaluation and the
///       data-access write interceptor - which must not treat a suspect reading as a usable
///       number. A Bad-severity value quality is surfaced AS a bad Result carrying a
///       BadVariableStatus ErrorDetail, and no DataValue is handed back.
///
/// These pin both, because the two used to be one: the public handle routed at the
/// flattening helper, so reading a Bad-quality variable through it threw, contradicting the
/// two-layer model the same SDK documents on its client-side reads.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <future>
#include <atomic>
#include <thread>
#include <fmt/format.h>

#include "ua_address_space.h"
#include "ua_base_data_variable.h"
#include "ua_data_type_registration.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_file_stream.h"
#include "ua_instance_utils.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"
#include "ua_variabletype_id.h"
#include "ua_value_source.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace ua::xml::nodeset;

namespace
{

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

/// A Variable whose read handler always reports a Bad-quality value: the reading is stale,
/// the transmitter has faulted, but the READ itself works perfectly well.
BaseDataVariable make_faulted_variable(AddressSpace& addressSpace, const EncodingLimits& limits)
{
  const InstantiationOptions options{.parentReferenceType = NodeId{ReferenceTypeId::Organizes}};

  auto variable = BaseDataVariable::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{1, "Transmitter"},
    options,
    VariableInstantiationAttributes{.dataType = NodeId{DataTypeId::Double},
      .valueRank = ValueRank::scalar,
      .accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead}})
                    .value();

  variable.set_value_source_sync(make_value_source(
    [](const ValueSource::ReadContext& /*context*/,
      const ua::Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        callback)
    {
      DataValue dataValue;
      dataValue.value() = 0.0;  // the last value, now suspect
      dataValue.status() = StatusCode{Status::Bad};  // quality, NOT an operation failure
      dataValue.server_timestamp() = DateTime::now();
      callback(std::move(dataValue));  // a GOOD result carrying a bad value
    }));
  return variable;
}

}  // namespace

// @relation(AC-COMP-SDK-POST-VARIABLE-QUALITY, scope=function)
TEST(VariableReadQualityTests, HandleReadKeepsBadQualityInsideTheDataValue)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  auto variable = make_faulted_variable(addressSpace, limits);

  const DataValueResult result = variable.try_read_value_sync();
  ASSERT_TRUE(result.is_good()) << "the READ succeeded; a bad value QUALITY must not fail the Result";
  ASSERT_TRUE(result.value().status().has_value());
  EXPECT_TRUE(result.value().status()->is_bad())
    << "the bad quality must survive on the DataValue the caller was handed";
  EXPECT_FALSE(result.value().is_null()) << "the last value must still be delivered";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SDK-POST-VARIABLE-QUALITY, scope=function)
TEST(VariableReadQualityTests, ThrowingHandleReadDoesNotThrowOnBadQuality)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  auto variable = make_faulted_variable(addressSpace, limits);

  // The throwing form throws when the READ fails. A suspect reading is not a failed read,
  // so this must return normally - it used to throw "Variable value has bad status".
  DataValue value;
  ASSERT_NO_THROW(value = variable.read_value_sync());
  ASSERT_TRUE(value.status().has_value());
  EXPECT_TRUE(value.status()->is_bad());

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SDK-POST-VARIABLE-QUALITY, scope=function)
TEST(VariableReadQualityTests, FlatteningHelperStillReportsBadQualityAsAFailedRead)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  auto variable = make_faulted_variable(addressSpace, limits);

  // The SDK's own callers depend on this: an alarm must not evaluate a limit it cannot
  // trust, so for THIS entry point a bad quality is a bad Result.
  std::promise<DataValueResult> promise;
  auto future = promise.get_future();
  instance_utils::read_variable_value_async(
    addressSpace, variable.node_id(), [&promise](DataValueResult r) { promise.set_value(std::move(r)); });
  const DataValueResult flattened = future.get();

  EXPECT_TRUE(flattened.is_bad())
    << "the flattening entry point must surface a bad value quality as a bad Result";
  ASSERT_NE(flattened.error_detail(), nullptr) << "and it must say why, so the caller can diagnose it";
  EXPECT_EQ(flattened.error_detail()->code, "BadVariableStatus");

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// -- Namespace::shutdown_async: stopping the background work that pins the executor ------
//
// A namespace that samples keeps a timer armed on the executor it was given, and an executor
// with work still on it never drains - so joining the pool never returns and the process will
// not exit, with nothing logged to say why. Before this hook existed, sampling stopped only
// when the SERVER WAS DESTROYED, so the documented sequence (shutdown_sync, then join) hung
// for any server with a data subscription.

// @relation(AC-COMP-SDK-POST-NAMESPACE-SHUTDOWN, scope=function)
TEST(NamespaceShutdownTests, DefaultNamespaceStopsSamplingSoTheExecutorCanDrain)
{
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  boost::asio::thread_pool threadPool{2};
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  auto variable = make_faulted_variable(addressSpace, limits);

  // Arm sampling: a monitored item on the default namespace, which is what puts a repeating
  // timer on this pool.
  auto target = addressSpace.namespace_array().get_namespace(variable.node_id().namespace_index());
  ASSERT_NE(target, nullptr);

  std::promise<VoidResult> stopped;
  auto stoppedFuture = stopped.get_future();
  target->shutdown_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });

  ASSERT_EQ(stoppedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "shutdown_async never completed its callback";
  EXPECT_TRUE(stoppedFuture.get().is_good());

  // The proof: the pool drains. Without the hook this join is the hang.
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SDK-POST-NAMESPACE-SHUTDOWN, scope=function)
TEST(NamespaceShutdownTests, ShutdownAsyncIsIdempotent)
{
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  boost::asio::thread_pool threadPool{2};
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  auto target = addressSpace.namespace_array().get_namespace(0);
  ASSERT_NE(target, nullptr);

  // Shutdown and destruction both reach this, so a second call must be a clean no-op.
  for (int round = 0; round < 3; ++round)
  {
    std::promise<VoidResult> stopped;
    auto stoppedFuture = stopped.get_future();
    target->shutdown_async([&stopped](VoidResult r) { stopped.set_value(std::move(r)); });
    ASSERT_EQ(stoppedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "call " << round + 1 << " never completed";
    EXPECT_TRUE(stoppedFuture.get().is_good());
  }

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SDK-POST-NAMESPACE-SHUTDOWN, scope=function)
TEST(NamespaceShutdownTests, AddressSpaceFanOutCompletesOnceForEveryNamespace)
{
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  boost::asio::thread_pool threadPool{2};
  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  // Several namespaces, all of which answer INLINE - the case the fan-out's tally has to be
  // safe against, because a completion can arrive before the loop that asked has finished.
  for (int index = 0; index < 4; ++index)
  {
    addressSpace.add_namespace_sync(
      default_ns::Namespace::create(fmt::format("uri://extra-{}", index), threadPool.get_executor()));
  }

  std::atomic<int> completions{0};
  std::promise<VoidResult> done;
  auto doneFuture = done.get_future();
  addressSpace.shutdown_async(
    [&completions, &done](VoidResult result)
    {
      if (completions.fetch_add(1) == 0)
      {
        done.set_value(std::move(result));
      }
    });

  ASSERT_EQ(doneFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the fan-out never completed";
  EXPECT_TRUE(doneFuture.get().is_good());
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(completions.load(), 1) << "the fan-out completed more than once";

  ::ua::test_utils::drain_with_timeout(threadPool);
}
