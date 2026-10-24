// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// An `*_async` call made without a completion callback still does its work, and its outcome is logged
// instead of being lost (ua::detail::completion_or_log).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "test_utilities.h"
#include "ua_add_method.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_base_data_variable.h"
#include "ua_data_type_registration.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_file.h"
#include "ua_file_stream.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"

#include <boost/asio/thread_pool.hpp>

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

/// Keeps the level and "operation" field of every entry it is given.
class OperationLog : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    for (const auto& field : entry.fields)
    {
      if (field.key == "operation" && std::holds_alternative<std::string_view>(field.value))
      {
        const std::lock_guard lock{mMutex};
        mEntries.emplace_back(entry.level, std::string{std::get<std::string_view>(field.value)});
      }
    }
  }

  /// Waits for an entry for @p operation at @p level.
  bool wait_for(const std::string& operation, LogLevel level)
  {
    const auto deadline = std::chrono::steady_clock::now() + ::ua::test_utils::default_poll_budget();
    while (std::chrono::steady_clock::now() < deadline)
    {
      {
        const std::lock_guard lock{mMutex};
        for (const auto& [kept, name] : mEntries)
        {
          if (kept == level && name == operation)
          {
            return true;
          }
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return false;
  }

private:
  std::mutex mMutex;
  std::vector<std::pair<LogLevel, std::string>> mEntries;
};

class CompletionWithoutCallbackTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.set_logger(
      Logger{mLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "completion-without-callback"});
    load_ns0(make_encoding_limits(ApplicationConfig::load_default()), mAddressSpace, mStructureFactory);
    auto boiler = mAddressSpace.create_node_sync(mBoilerId, NodeClass::Object);
    boiler.set_browse_name(QualifiedName{1, "Boiler"});
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  std::shared_ptr<OperationLog> mLog = std::make_shared<OperationLog>();
  boost::asio::thread_pool mPool{2};
  AddressSpace mAddressSpace =
    AddressSpace::create("urn:test:completion-without-callback", mPool.get_executor());
  StructureFactory mStructureFactory;
  const NodeId mBoilerId{1, "Boiler"};
};

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST_F(CompletionWithoutCallbackTest, AMethodIsStillAdded)
{
  const NodeId methodId{1, "Reset"};
  add_method_async(
    mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Reset"},
    inputs(),
    outputs(),
    [](const MethodCall&) -> MethodResult<> { return {}; },
    {},
    MethodConfig{.nodeId = methodId});

  ASSERT_TRUE(mLog->wait_for("add_method_async", LogLevel::Debug));
  EXPECT_TRUE(mAddressSpace.try_find_node_sync(methodId).is_good());
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST_F(CompletionWithoutCallbackTest, AMethodThatCannotBeAddedIsLoggedAtError)
{
  add_method_async(mAddressSpace,
    NodeId{1, "NoSuchParent"},
    QualifiedName{1, "Reset"},
    inputs(),
    outputs(),
    [](const MethodCall&) -> MethodResult<> { return {}; },
    {});

  EXPECT_TRUE(mLog->wait_for("add_method_async", LogLevel::Error));
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST_F(CompletionWithoutCallbackTest, AGeneratedHandlerSetterStillRegistersTheHandler)
{
  auto file = File::create_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Log"},
    InstantiationOptions{.parentReferenceType = NodeId{ReferenceTypeId::HasComponent}});

  file.set_open_handler_async(
    File::OpenHandler{
      [](const MethodCall&, const File::OpenInputArguments&) -> MethodResult<File::OpenOutputArguments>
      {
        return File::OpenOutputArguments{};
      }},
    {});

  EXPECT_TRUE(mLog->wait_for("File::set_open_handler_async", LogLevel::Debug));
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST_F(CompletionWithoutCallbackTest, AValueIsStillWritten)
{
  auto variable = BaseDataVariable::try_create_sync(mAddressSpace,
    mBoilerId,
    QualifiedName{1, "Setpoint"},
    InstantiationOptions{.parentReferenceType = NodeId{ReferenceTypeId::HasComponent}},
    VariableInstantiationAttributes{.dataType = NodeId{DataTypeId::Int32},
      .valueRank = ValueRank::scalar,
      .accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite}})
                    .value();

  variable.write_value_async(DataValue{Variant{int32_t{7}}}, {});

  ASSERT_TRUE(mLog->wait_for("BaseVariable::write_value_async", LogLevel::Debug));
  const auto read = variable.try_read_value_sync();
  ASSERT_TRUE(read.is_good());
  EXPECT_EQ(read.value().value().as<int32_t>(), 7);
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST_F(CompletionWithoutCallbackTest, ANamespaceIsStillAdded)
{
  mAddressSpace.add_namespace_async(
    default_ns::Namespace::create("urn:test:quietly-added", mPool.get_executor()), {});

  ASSERT_TRUE(mLog->wait_for("add_namespace_async", LogLevel::Debug));
  EXPECT_NE(namespace_array_utils::get_index_lookup_function(mAddressSpace)("urn:test:quietly-added"), 0u);
}

}  // namespace
