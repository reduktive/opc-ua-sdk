// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Tests for the async NodeSet import engine (ua::xml::nodeset::ImportEngine).
//
// The headline property (*) is deadlock-freedom: unlike the retired synchronous Importer (which
// blocked on write_value_async via future.wait()), the async engine can be DRIVEN ON the
// AddressSpace executor thread and still complete - because it never blocks a thread. The sync
// importer would deadlock a single-threaded executor in exactly this scenario.

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <future>
#include <ranges>
#include <string_view>
#include <thread>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_nodeset_import_engine.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_unknown_structure.h"
#include "ua_nodeset_parser.h"

using namespace ua;
using namespace ua::xml::nodeset;

namespace
{

NamespaceAllocator make_allocator(boost::asio::any_io_executor executor)
{
  return [executor = std::move(executor)](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

// A namespace that POSTS its find_nodes_async and create_nodes_async completions onto an executor instead of
// firing them inline like default_ns. This is what makes the deadlock-free property falsifiable:
// on a single-threaded executor, a blocking importer (one that .wait()-ed on these async calls)
// would deadlock, because the posted completion can never run while the only thread is blocked.
// The async engine, which never blocks, completes.
class DeferringNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  DeferringNamespace(shared_ptr<Namespace> inner, boost::asio::any_io_executor executor)
    : mInner(std::move(inner)), mExecutor(std::move(executor))
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    // The whole batch is posted, which is what this fixture is for: nothing it is asked ever answers
    // on the caller's stack. It also declines the synchronous form by inheriting the base default,
    // so a caller cannot get an inline answer out of it by that route either.
    auto inner = mInner;
    std::vector<NodeId> ids(nodeIds.begin(), nodeIds.end());
    boost::asio::post(mExecutor,
      [inner, request, ids = std::move(ids), maxAge, callback = std::move(batchCallback)]() mutable
      { inner->find_nodes_async(request, ids, maxAge, std::move(callback)); });
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    auto inner = mInner;
    std::vector<NodeCreation> creations(nodes.begin(), nodes.end());
    boost::asio::post(mExecutor,
      [inner, request, creations = std::move(creations), complete = std::move(complete)]() mutable
      { inner->create_nodes_async(request, creations, std::move(complete)); });
  }

  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->delete_nodes_async(request, nodes, halves, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->write_async(request, caller, items, std::move(complete));
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->add_references_async(request, changes, std::move(complete));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->remove_references_async(request, changes, std::move(complete));
  }

private:
  shared_ptr<Namespace> mInner;
  boost::asio::any_io_executor mExecutor;

  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }
};

NamespaceAllocator make_deferring_allocator(boost::asio::any_io_executor executor)
{
  return [executor](string_view uri) -> shared_ptr<Namespace>
  {
    return make_shared<DeferringNamespace>(default_ns::Namespace::create(uri, executor), executor);
  };
}

// A namespace that answers every create it makes Uncertain, still holding the Node it created: the answer
// the import refuses without leaving that Node behind.
class UncertainCreatingNamespace final : public DeferringNamespace
{
public:
  using DeferringNamespace::DeferringNamespace;

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    DeferringNamespace::create_nodes_async(request,
      nodes,
      [complete = std::move(complete)](BatchResult<NodeResult> created) mutable
      {
        for (auto& item : created.items)
        {
          if (item.is_good())
          {
            item = NodeResult{std::move(item).value(), StatusCode{Status::UncertainLastUsableValue}};
          }
        }
        complete(std::move(created));
      });
  }
};

NamespaceAllocator make_uncertain_creating_allocator(boost::asio::any_io_executor executor)
{
  return [executor](string_view uri) -> shared_ptr<Namespace>
  {
    return make_shared<UncertainCreatingNamespace>(default_ns::Namespace::create(uri, executor), executor);
  };
}

/// The ErrorDetail with @p code in the cause chain that starts at @p detail, or null when there is none.
const ErrorDetail* detail_in_chain(const ErrorDetail* detail, std::string_view code)
{
  for (; detail != nullptr; detail = detail->cause.get())
  {
    if (detail->code == code)
    {
      return detail;
    }
  }
  return nullptr;
}

std::vector<shared_ptr<NodeSet>> parse_fixture(
  const std::string& fileName, AddressSpace& addressSpace, const StructureFactory& structureFactory)
{
  FileStream inputStream{fileName};
  inputStream.open_for_read();
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  return Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});
}

}  // namespace

// * The whole point of the async engine (D-F): an import driven ON the AS-executor thread of a
// SINGLE-threaded executor completes. The StructValueTranslationFixture contains a Variable with a
// structure value, so the import exercises write_value_async - precisely the call the retired
// importer blocked on with future.wait(), which would deadlock here.
TEST(NodeSetImportEngineTests, ImportDrivenOnAsExecutorThreadCompletes)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};  // single thread - a blocking importer would deadlock
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  StructureFactory structureFactory;
  structureFactory.register_type(
    NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  // Use a namespace that POSTS find/create completions - so a blocking drive would deadlock here.
  auto engine =
    ImportEngine::create(limits, addressSpace, nodeSets, make_deferring_allocator(tp.get_executor()));

  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto completionThread = std::make_shared<std::thread::id>();
  auto future = donePromise->get_future();

  // Drive the import from WITHIN the executor thread (post onto the single-thread pool).
  boost::asio::post(tp.get_executor(),
    [engine, donePromise, completionThread]() mutable
    {
      engine->import_all_async({},
        {},
        [donePromise, completionThread](VoidResult result) mutable
        {
          *completionThread = std::this_thread::get_id();
          donePromise->set_value(std::move(result));
        });
    });

  // Block only on the MAIN test thread (allowed).
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "async import deadlocked on the single-threaded AS executor";
  auto result = future.get();
  EXPECT_TRUE(result.is_good()) << "import failed: 0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().value());

  // Completion fired on the AS executor thread, not the main test thread.
  EXPECT_NE(*completionThread, std::this_thread::get_id());

  // The node was created and its struct-embedded id was translated to the server index.
  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);
  ASSERT_NE(importedNsIndex, 1);
  EXPECT_EQ(engine->nodes_imported(), 2u);  // MyDataType + StructVar

  const NodeId structVarId{importedNsIndex, 5003u};
  auto varResult = addressSpace.try_find_sync<VariableAccessor>(structVarId);
  ASSERT_TRUE(varResult.is_good());
  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());
  ASSERT_TRUE(dvResult.value().value().is_structure());
  const auto* argument = dynamic_cast<const Argument*>(&dvResult.value().value().as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->data_type().namespace_index(), importedNsIndex);
  EXPECT_EQ(argument->data_type().identifier().get_numeric(), 6001u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// A create the namespace answers Uncertain is refused as a lookup's Uncertain answer is, and the Node the
// namespace holds from it is not left in the address space.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(NodeSetImportEngineTests, AnUncertainCreateIsRefusedAndItsNodeRemoved)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;
  structureFactory.register_type(
    NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(
    limits, addressSpace, nodeSets, make_uncertain_creating_allocator(tp.get_executor()));

  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto future = donePromise->get_future();
  engine->import_all_async(
    {}, {}, [donePromise](VoidResult result) mutable { donePromise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError) << to_string(result.status_code());
  const ErrorDetail* refusal = detail_in_chain(result.status_code().detail(), "LookupAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the answer does not carry the refusal: " << to_string(result.status_code());
  EXPECT_EQ(refusal->summary, "The SDK does not act on an answer the namespace is uncertain of");
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(engine->nodes_imported(), 0u);

  // MyDataType and StructVar: whichever the namespace created, it no longer holds.
  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);
  for (const std::uint32_t id : {6001u, 5003u})
  {
    const auto found = addressSpace.try_find_node_sync(NodeId{importedNsIndex, id});
    EXPECT_EQ(found.status_code().as_status(), Status::BadNodeIdUnknown)
      << "i=" << id << " is still in the address space: " << to_string(found.status_code());
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// A malformed node value (namespace index out of range) must short-circuit the import: the
// completion fires exactly once with a bad Result whose ErrorDetail carries the offending node's
// source line:col (D-C / source-location augmentation).
TEST(NodeSetImportEngineTests, ErrorShortCircuitCarriesSourceLocation)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets = parse_fixture("BadNamespaceIndexFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto callCount = std::make_shared<std::atomic<int>>(0);
  auto future = donePromise->get_future();

  engine->import_all_async({},
    {},
    [donePromise, callCount](VoidResult result) mutable
    {
      if (++(*callCount) == 1)
      {
        donePromise->set_value(std::move(result));
      }
    });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  auto result = future.get();
  EXPECT_TRUE(result.is_bad());

  const auto* detail = result.status_code().detail();
  ASSERT_NE(detail, nullptr) << "error must carry an ErrorDetail";
  const std::string location =
    ::ua::test_utils::error_context(detail, ua::ContextKeys::sourceLocation.value());
  EXPECT_FALSE(location.empty()) << "ErrorDetail must carry a source line:col";
  EXPECT_NE(location.find(':'), std::string::npos) << "expected line:col, got '" << location << "'";

  // Give any (incorrectly) duplicated completion a chance to land, then assert it fired once.
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(callCount->load(), 1) << "completion must fire exactly once";

  ::ua::test_utils::drain_with_timeout(tp);
}

// An unresolved ExtensionObject value with the default Fail policy aborts the import cleanly.
TEST(NodeSetImportEngineTests, UnknownStructureFailPolicyAborts)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;  // Argument deliberately NOT registered -> unknown structure

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  // default: fail on unknown structure

  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto future = donePromise->get_future();
  engine->import_all_async(
    {}, {}, [donePromise](VoidResult result) mutable { donePromise->set_value(std::move(result)); });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(future.get().is_bad());

  ::ua::test_utils::drain_with_timeout(tp);
}

// The same fixture imports cleanly under the ImportOpaque policy (the value is preserved opaque).
TEST(NodeSetImportEngineTests, UnknownStructureImportOpaqueSucceeds)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;  // Argument NOT registered

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  engine->set_fail_on_unknown_structure(false);

  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto future = donePromise->get_future();
  engine->import_all_async(
    {}, {}, [donePromise](VoidResult result) mutable { donePromise->set_value(std::move(result)); });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(future.get().is_good());

  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);
  const NodeId structVarId{importedNsIndex, 5003u};
  EXPECT_TRUE(addressSpace.try_find_sync<VariableAccessor>(structVarId).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// Re-importing the same document is idempotent: existing nodes are found and references merged
// (no duplicate-node error), and the second engine reports zero newly-created nodes.
TEST(NodeSetImportEngineTests, IdempotentReimportMergesWithoutError)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;
  structureFactory.register_type(
    NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());

  auto runImport = [&](const shared_ptr<ImportEngine>& engine)
  {
    auto donePromise = std::make_shared<std::promise<VoidResult>>();
    auto future = donePromise->get_future();
    engine->import_all_async(
      {}, {}, [donePromise](VoidResult result) mutable { donePromise->set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    return future.get();
  };

  auto first = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  EXPECT_TRUE(runImport(first).is_good());
  EXPECT_EQ(first->nodes_imported(), 2u);

  auto second = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  EXPECT_TRUE(runImport(second).is_good());
  EXPECT_EQ(second->nodes_imported(), 0u) << "re-import must create no new nodes";

  ::ua::test_utils::drain_with_timeout(tp);
}

// import_node_and_forward_refs imports the seed node plus the transitive closure of its forward
// references. The fixture's ObjectType has a forward HasProperty ref to a property child.
TEST(NodeSetImportEngineTests, ImportNodeAndForwardRefsImportsSubtree)
{
  static constexpr string_view typedefsUri = "urn:example:typedefs";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets =
    parse_fixture("TypeDefinitionReferencesFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());

  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  // The fixture declares urn:example:typedefs at file-local index 1; allocate it up front so we can
  // address the imported nodes by server index.
  auto donePromise = std::make_shared<std::promise<VoidResult>>();
  auto future = donePromise->get_future();
  // ns=1;i=6010 is the ObjectType seed.
  engine->import_node_and_forward_refs_async(NodeId{1, 6010u},
    {},
    {},
    [donePromise](VoidResult result) mutable { donePromise->set_value(std::move(result)); });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(future.get().is_good());

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(typedefsUri);
  ASSERT_NE(nsIndex, 0);

  // Seed + the forward-referenced property child were both imported.
  EXPECT_TRUE(addressSpace.try_find_sync<ObjectTypeAccessor>(NodeId{nsIndex, 6010u}).is_good());
  EXPECT_TRUE(addressSpace.try_find_sync<VariableAccessor>(NodeId{nsIndex, 6011u}).is_good())
    << "forward-referenced property child must be imported";

  ::ua::test_utils::drain_with_timeout(tp);
}

// =================================================================================================
// Synchronous convenience wrappers (try_*_sync / *_sync).
//
// The headline property: these BLOCK on the caller's thread while the executor drives the import on
// ANOTHER thread. Each test below blocks on the main test thread with a SINGLE-threaded pool - if a
// wrapper regressed to blocking the executor thread itself, the import could never make progress and
// the test would hang (caught by the CI watchdog). This is the deadlock-free contract made testable.
// =================================================================================================

// * try_import_all_sync blocks on the caller (main) thread; the single pool worker drives the engine
// to completion and the call returns a good Result with the expected commit count.
TEST(NodeSetImportEngineTests, TryImportAllSyncBlocksOnCallerAndCompletes)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};  // single worker - it must do the driving while main blocks
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  StructureFactory structureFactory;
  structureFactory.register_type(
    NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });

  auto nodeSets = parse_fixture("StructValueTranslationFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  // Called directly on the main thread - blocks here until the pool worker completes the import.
  auto result = engine->try_import_all_sync({}, {});
  ASSERT_TRUE(result.is_good()) << "sync import failed: 0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().value());
  EXPECT_EQ(engine->nodes_imported(), 2u);  // MyDataType + StructVar

  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<VariableAccessor>(NodeId{importedNsIndex, 5003u}).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// import_all_sync (throwing variant) raises UaException when the import fails.
TEST(NodeSetImportEngineTests, ImportAllSyncThrowsOnBadResult)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets = parse_fixture("BadNamespaceIndexFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  EXPECT_THROW(engine->import_all_sync({}, {}), UaException);

  ::ua::test_utils::drain_with_timeout(tp);
}

// try_import_all_sync surfaces the bad Result (never throws) and preserves the ErrorDetail's
// source line:col - the same diagnostic the async form carries.
TEST(NodeSetImportEngineTests, TryImportAllSyncPropagatesSourceLocation)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets = parse_fixture("BadNamespaceIndexFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  auto result = engine->try_import_all_sync({}, {});
  ASSERT_TRUE(result.is_bad());
  const auto* detail = result.status_code().detail();
  ASSERT_NE(detail, nullptr) << "error must carry an ErrorDetail";
  const std::string location =
    ::ua::test_utils::error_context(detail, ua::ContextKeys::sourceLocation.value());
  EXPECT_NE(location.find(':'), std::string::npos) << "expected line:col, got '" << location << "'";

  ::ua::test_utils::drain_with_timeout(tp);
}

// try_import_node_sync imports a single seed node (no forward-reference recursion): the seed is
// created and the commit count is exactly one.
TEST(NodeSetImportEngineTests, TryImportNodeSyncImportsSingleNode)
{
  static constexpr string_view typedefsUri = "urn:example:typedefs";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets =
    parse_fixture("TypeDefinitionReferencesFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  auto result = engine->try_import_node_sync(NodeId{1, 6010u}, {});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(engine->nodes_imported(), 1u) << "import_node must not recurse into forward references";

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(typedefsUri);
  ASSERT_NE(nsIndex, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<ObjectTypeAccessor>(NodeId{nsIndex, 6010u}).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// import_node_and_forward_refs_sync (throwing variant) imports the seed plus its forward-referenced
// subtree and does not throw on success.
TEST(NodeSetImportEngineTests, ImportNodeAndForwardRefsSyncImportsSubtreeWithoutThrowing)
{
  static constexpr string_view typedefsUri = "urn:example:typedefs";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets =
    parse_fixture("TypeDefinitionReferencesFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  EXPECT_NO_THROW(engine->import_node_and_forward_refs_sync(NodeId{1, 6010u}, {}, {}));

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(typedefsUri);
  ASSERT_NE(nsIndex, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<ObjectTypeAccessor>(NodeId{nsIndex, 6010u}).is_good());
  EXPECT_TRUE(addressSpace.try_find_sync<VariableAccessor>(NodeId{nsIndex, 6011u}).is_good())
    << "forward-referenced property child must be imported";

  ::ua::test_utils::drain_with_timeout(tp);
}

// try_import_type_definitions_only_sync imports the type definition (and its type-child instance
// declarations) and returns a good Result.
TEST(NodeSetImportEngineTests, TryImportTypeDefinitionsOnlySyncImportsTypes)
{
  static constexpr string_view typedefsUri = "urn:example:typedefs";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets =
    parse_fixture("TypeDefinitionReferencesFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  auto result = engine->try_import_type_definitions_only_sync("", {}, {});
  ASSERT_TRUE(result.is_good());
  EXPECT_GE(engine->nodes_imported(), 1u);

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(typedefsUri);
  ASSERT_NE(nsIndex, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<ObjectTypeAccessor>(NodeId{nsIndex, 6010u}).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-SM-003-GENERATESEVENT, scope=function)
TEST(NodeSetImportEngineTests, TypeDefinitionsOnlyDerivesBidirectionalStateMachineEventClosureExactlyOnce)
{
  static constexpr string_view fixtureUri = "urn:example:state-machine-closure";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;
  auto nodeSets =
    parse_fixture("StateMachineGeneratesEventFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1U);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  ASSERT_TRUE(engine->try_import_type_definitions_only_sync("", {}, {}).is_good());
  ASSERT_TRUE(engine->try_import_type_definitions_only_sync("", {}, {}).is_good())
    << "re-import must remain idempotent";

  const auto namespaceIndex = addressSpace.namespace_array().get_namespace_index(fixtureUri);
  ASSERT_NE(namespaceIndex, 0U);
  const NodeId machineTypeId{namespaceIndex, 7000U};
  const NodeId missingEventId{namespaceIndex, 7003U};
  const NodeId existingEventId{namespaceIndex, 7004U};
  const NodeId nonEventEffectId{namespaceIndex, 7006U};

  const auto countReference =
    [](const References& references, const NodeId& referenceType, const NodeId& target, bool forward)
  {
    return std::ranges::count_if(references,
      [&referenceType, &target, forward](const Reference& reference)
      {
        return reference.type_id() == referenceType && reference.target_id() == ExpandedNodeId{target} &&
               reference.is_forward() == forward;
      });
  };

  const auto machineReferences = addressSpace.find_node_sync(machineTypeId).get_references_sync();
  EXPECT_EQ(
    countReference(machineReferences, NodeId{ReferenceTypeId::GeneratesEvent}, missingEventId, true), 1);
  EXPECT_EQ(
    countReference(machineReferences, NodeId{ReferenceTypeId::GeneratesEvent}, existingEventId, true), 1);
  EXPECT_EQ(
    countReference(machineReferences, NodeId{ReferenceTypeId::GeneratesEvent}, nonEventEffectId, true), 0);

  const auto missingEventReferences = addressSpace.find_node_sync(missingEventId).get_references_sync();
  EXPECT_EQ(
    countReference(missingEventReferences, NodeId{ReferenceTypeId::GeneratesEvent}, machineTypeId, false), 1);
  const auto existingEventReferences = addressSpace.find_node_sync(existingEventId).get_references_sync();
  EXPECT_EQ(
    countReference(existingEventReferences, NodeId{ReferenceTypeId::GeneratesEvent}, machineTypeId, false),
    1);

  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-SM-003-GENERATESEVENT, scope=function)
TEST(NodeSetImportEngineTests, DerivedStateMachineEventClosureHonoursReferenceFilter)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;
  auto nodeSets =
    parse_fixture("StateMachineGeneratesEventFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1U);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));
  ImportEngine::ImportReferencePredicate rejectGeneratesEvent =
    [](const ua::xml::nodeset::Node&, const ua::xml::nodeset::Node::Reference& reference)
  {
    return reference.typeId != NodeId{ReferenceTypeId::GeneratesEvent};
  };
  ASSERT_TRUE(
    engine->try_import_type_definitions_only_sync("", {}, std::move(rejectGeneratesEvent)).is_good());

  constexpr string_view fixtureUri = "urn:example:state-machine-closure";
  const auto namespaceIndex = addressSpace.namespace_array().get_namespace_index(fixtureUri);
  ASSERT_NE(namespaceIndex, 0U);
  const auto references = addressSpace.find_node_sync(NodeId{namespaceIndex, 7000U}).get_references_sync();
  EXPECT_TRUE(std::ranges::none_of(references,
    [](const Reference& reference)
    { return reference.type_id() == NodeId{ReferenceTypeId::GeneratesEvent}; }));

  ::ua::test_utils::drain_with_timeout(tp);
}

// A DataType's HasProperty children (EnumStrings / EnumValues / OptionSetValues) have the DataType
// itself as their ParentNodeId. The TypeDefinitionsOnly import must pull such a property in WITH the
// type - the property is enumeration/option-set metadata, part of the type definition. Regression for
// the parent-walk that previously imported children of ObjectType/VariableType parents only and
// dropped DataType-property children (NS0 ServerState imported without EnumStrings -> CTT Base Types).
TEST(NodeSetImportEngineTests, TypeDefinitionsOnlyImportsDataTypePropertyChildren)
{
  static constexpr string_view propsUri = "urn:example:datatypeprops";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets = parse_fixture("DataTypePropertyFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  ASSERT_TRUE(engine->try_import_type_definitions_only_sync("", {}, {}).is_good());

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(propsUri);
  ASSERT_NE(nsIndex, 0);

  // The enum DataType imported...
  EXPECT_TRUE(addressSpace.try_find_sync<DataTypeAccessor>(NodeId{nsIndex, 6020u}).is_good());

  // ...and crucially its EnumStrings Property child (parent = the DataType) imported with it,
  // carrying its value. Before the fix this node was silently dropped.
  auto enumStrings = addressSpace.try_find_sync<VariableAccessor>(NodeId{nsIndex, 6021u});
  ASSERT_TRUE(enumStrings.is_good()) << "EnumStrings property of a DataType must import with the type";
  auto value = enumStrings.value().try_read_value_sync();
  ASSERT_TRUE(value.is_good());
  EXPECT_TRUE(value.value().value().is_array()) << "EnumStrings value (ListOfLocalizedText) preserved";

  ::ua::test_utils::drain_with_timeout(tp);
}

// A DataType encoding object (Default Binary / Default XML) carries no ParentNodeId and is reachable
// only via the inverse HasEncoding from its DataType. The TypeDefinitionsOnly import must still pull
// it in (recognised by its HasTypeDefinition = DataTypeEncodingType i=76) so the DataType gains the
// HasEncoding reference clients need to (de)serialise structures. Regression for NS0 ServerStatusDataType
// importing with no HasEncoding references -> CTT Base Info ServerType 001.
TEST(NodeSetImportEngineTests, TypeDefinitionsOnlyImportsDataTypeEncodingObjects)
{
  static constexpr string_view propsUri = "urn:example:datatypeprops";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  auto nodeSets = parse_fixture("DataTypePropertyFixture.NodeSet2.xml", addressSpace, structureFactory);
  ASSERT_EQ(nodeSets.size(), 1u);

  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto engine = ImportEngine::create(limits, addressSpace, nodeSets, make_allocator(tp.get_executor()));

  ASSERT_TRUE(engine->try_import_type_definitions_only_sync("", {}, {}).is_good());

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(propsUri);
  ASSERT_NE(nsIndex, 0);

  // The encoding object imported (before the fix it was silently dropped - no ParentNodeId)...
  EXPECT_TRUE(addressSpace.try_find_sync<ObjectAccessor>(NodeId{nsIndex, 6031u}).is_good())
    << "Default Binary encoding object must import with its DataType";

  // ...and the structure DataType now carries the HasEncoding reference to it.
  auto dataType = addressSpace.try_find_sync<DataTypeAccessor>(NodeId{nsIndex, 6030u});
  ASSERT_TRUE(dataType.is_good());
  auto references = dataType.value().try_get_references_sync();
  ASSERT_TRUE(references.is_good());
  const bool hasEncodingRef = std::ranges::any_of(references.value(),
    [&](const auto& reference)
    {
      return reference.type_id() == NodeId{ReferenceTypeId::HasEncoding} &&
             reference.target_id().node_id() == NodeId{nsIndex, 6031u};
    });
  EXPECT_TRUE(hasEncodingRef) << "DataType must gain a HasEncoding reference to its encoding object";

  ::ua::test_utils::drain_with_timeout(tp);
}

// * D-H (section 6): ONE parsed document imported into TWO address spaces with DIFFERENT resolvers decodes
// its custom-struct value PER-TARGET. Target A's resolver knows the type => typed value; target B's
// does not => preserved opaque. Proves value decode/resolution is an import-time concern bound to the
// target frame (set via set_structure_resolver), not baked into the parsed document. The document is
// parsed ONCE with an empty factory (decode is deferred) and the same `nodeSets` feed both engines.
TEST(NodeSetImportEngineTests, PerTargetResolverDecodesOneDocumentTwoWays)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};

  // Parse ONCE, with an EMPTY structure factory - decode is deferred, so the document is syntactic.
  auto parseAddressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory emptyFactory;
  auto nodeSets =
    parse_fixture("StructValueTranslationFixture.NodeSet2.xml", parseAddressSpace, emptyFactory);
  ASSERT_EQ(nodeSets.size(), 1u);
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());

  // Target A - resolver KNOWS the custom type => the value decodes to a typed Argument.
  {
    auto addressSpaceA = AddressSpace::create("", tp.get_executor());
    StructureFactory knowing;
    knowing.register_type(NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });
    auto engineA = ImportEngine::create(limits, addressSpaceA, nodeSets, make_allocator(tp.get_executor()));
    engineA->set_structure_resolver(knowing.resolver());
    ASSERT_TRUE(engineA->try_import_all_sync({}, {}).is_good());

    const auto nsIndex = addressSpaceA.namespace_array().get_namespace_index(customUri);
    ASSERT_NE(nsIndex, 0);
    auto var = addressSpaceA.try_find_sync<VariableAccessor>(NodeId{nsIndex, 5003u});
    ASSERT_TRUE(var.is_good());
    auto dv = var.value().try_read_value_sync();
    ASSERT_TRUE(dv.is_good());
    ASSERT_TRUE(dv.value().value().is_structure());
    EXPECT_NE(dynamic_cast<const Argument*>(&dv.value().value().as<Structure>()), nullptr)
      << "target A's resolver knows the type => typed decode";
  }

  // Target B - NO resolver override => the document's (empty) parse-time resolver => value stays opaque.
  {
    auto addressSpaceB = AddressSpace::create("", tp.get_executor());
    auto engineB = ImportEngine::create(limits, addressSpaceB, nodeSets, make_allocator(tp.get_executor()));
    engineB->set_fail_on_unknown_structure(false);  // keep opaque rather than abort
    ASSERT_TRUE(engineB->try_import_all_sync({}, {}).is_good());

    const auto nsIndex = addressSpaceB.namespace_array().get_namespace_index(customUri);
    ASSERT_NE(nsIndex, 0);
    auto var = addressSpaceB.try_find_sync<VariableAccessor>(NodeId{nsIndex, 5003u});
    ASSERT_TRUE(var.is_good());
    auto dv = var.value().try_read_value_sync();
    ASSERT_TRUE(dv.is_good());
    ASSERT_TRUE(dv.value().value().is_structure());
    EXPECT_NE(dynamic_cast<const UnknownStructure*>(&dv.value().value().as<Structure>()), nullptr)
      << "target B has no resolver => value preserved opaque";
  }

  ::ua::test_utils::drain_with_timeout(tp);
}
