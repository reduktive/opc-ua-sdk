// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <atomic>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

#include <string>

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_xml_parser.h"

#include "ua_nodeset_export_engine.h"
#include "ua_nodeset_writer.h"

using namespace ua;
using ua::xml::nodeset::ExportEngine;

namespace
{

// A DefaultNamespace that DECLINES enumerate_nodes (BadNotSupported), forcing the export engine's
// browse-traversal fallback, while keeping the real lookup, Reference and creation members so a
// reachable graph can be traversed. Models a remote/proxy namespace that cannot enumerate.
class DecliningNamespace : public default_ns::Namespace
{
public:
  DecliningNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void enumerate_nodes_async(
    const RequestInfo& /*request*/, std::function<void(Result<std::vector<NodeId>>)> callback) override
  {
    callback(Result<std::vector<NodeId>>{StatusCode{Status::BadNotSupported},
      ErrorDetail::build("EnumerateDeclined", "test namespace declines enumeration", "Test")});
  }

  static shared_ptr<DecliningNamespace> create(string_view uri, boost::asio::any_io_executor executor)
  {
    return make_shared<DecliningNamespace>(uri, std::move(executor));
  }
};

// A DefaultNamespace that answers the lookup of chosen Nodes with a chosen code and no Node, and declines
// enumeration when constructed to, so the export meets the answer in its read pass or in its browse
// traversal.
class AnsweringLookupNamespace : public default_ns::Namespace
{
public:
  AnsweringLookupNamespace(string_view uri, boost::asio::any_io_executor executor, bool declineEnumeration)
    : default_ns::Namespace(uri, std::move(executor)), mDeclineEnumeration(declineEnumeration)
  {}

  using default_ns::Namespace::find_node;

  /// Answers every later lookup of @p nodeId with @p answer and no Node.
  void answer_lookup(const NodeId& nodeId, StatusCode answer)
  {
    const std::lock_guard lock{mMutex};
    mAnswers.insert_or_assign(nodeId, std::move(answer));
  }

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> callback) override
  {
    if (!mDeclineEnumeration)
    {
      default_ns::Namespace::enumerate_nodes_async(request, std::move(callback));
      return;
    }
    callback(Result<std::vector<NodeId>>{StatusCode{Status::BadNotSupported},
      ErrorDetail::build("EnumerateDeclined", "test namespace declines enumeration", "Test")});
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    if (auto answer = answer_for(nodeId))
    {
      return NodeResult{std::move(*answer)};
    }
    return default_ns::Namespace::find_node(nodeId, maxAge);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    std::vector<std::optional<StatusCode>> answers;
    answers.reserve(nodeIds.size());
    for (const auto& nodeId : nodeIds)
    {
      answers.push_back(answer_for(nodeId));
    }
    default_ns::Namespace::find_nodes_async(request,
      nodeIds,
      maxAge,
      [answers = std::move(answers), complete = std::move(complete)](BatchResult<NodeResult> found) mutable
      {
        for (std::size_t i = 0; i < found.items.size() && i < answers.size(); ++i)
        {
          if (answers[i])
          {
            found.items[i] = NodeResult{*answers[i]};
          }
        }
        complete(std::move(found));
      });
  }

private:
  std::optional<StatusCode> answer_for(const NodeId& nodeId)
  {
    const std::lock_guard lock{mMutex};
    if (const auto found = mAnswers.find(nodeId); found != mAnswers.end())
    {
      return found->second;
    }
    return std::nullopt;
  }

  const bool mDeclineEnumeration;
  std::mutex mMutex;
  std::map<NodeId, StatusCode> mAnswers;
};

/// Whether @p status is the refusal of an Uncertain lookup: `Bad_InternalError` with the ErrorDetail
/// `LookupAnswerUncertain` whose cause is @p cause.
::testing::AssertionResult is_lookup_refusal(const StatusCode& status, Status cause)
{
  if (status.as_status() != Status::BadInternalError)
  {
    return ::testing::AssertionFailure()
           << "answered 0x" << std::hex << static_cast<uint32_t>(status.as_status());
  }
  const auto& detail = status.shared_detail();
  if (!detail || detail->code != "LookupAnswerUncertain")
  {
    return ::testing::AssertionFailure() << "ErrorDetail " << (detail ? detail->code : std::string{"(none)"});
  }
  if (detail->innerStatus != StatusCode{cause}.value())
  {
    return ::testing::AssertionFailure() << "the cause is 0x" << std::hex << detail->innerStatus;
  }
  return ::testing::AssertionSuccess();
}

std::set<NodeId> to_set(const std::vector<NodeId>& ids)
{
  return std::set<NodeId>{ids.begin(), ids.end()};
}

}  // namespace

// The enumerate path: a DefaultNamespace supports enumeration, so discovery returns exactly the set
// of nodes it owns (mixed numeric + string identifiers), order-independent.
TEST(ExportEngineDiscoverTests, EnumerablePathReturnsAllNodesInTargetNamespace)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());  // ns1 = DefaultNamespace

  const NodeId a{1, "A"};
  const NodeId b{1, 42u};
  const NodeId c{1, "C"};
  ASSERT_TRUE(addressSpace.try_create_node_sync(a, NodeClass::Object, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(b, NodeClass::Variable, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(c, NodeClass::Object, {}).is_good());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto result = engine->try_discover_sync({1});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(to_set(result.value()), (std::set<NodeId>{a, b, c}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// An empty enumerable namespace yields an empty, good result (not an error).
TEST(ExportEngineDiscoverTests, EmptyEnumerableNamespaceYieldsEmptyGoodResult)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto result = engine->try_discover_sync({1});

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

// The traversal fallback: a namespace that declines enumeration is discovered by browsing from the
// standard roots. A small graph (RootFolder -> A -> B) wires the declining namespace's nodes into
// reach; discovery must collect exactly the declining-namespace nodes (not the ns0 root).
TEST(ExportEngineDiscoverTests, TraversalFallbackDiscoversReachableNodesInDecliningNamespace)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto declining = DecliningNamespace::create("urn:declining", tp.get_executor());
  const auto declIndex = addressSpace.add_namespace_sync(declining);
  ASSERT_EQ(declIndex, 2);

  const NodeId root{ObjectId::RootFolder};  // ns0 seed, created here (AddressSpace::create leaves ns0 bare)
  const NodeId nodeA{declIndex, "A"};
  const NodeId nodeB{declIndex, "B"};

  auto rootResult = addressSpace.try_create_node_sync(root, NodeClass::Object, {});
  ASSERT_TRUE(rootResult.is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeA, NodeClass::Object, {}).is_good());
  auto nodeAResult = addressSpace.try_find_node_sync(nodeA);
  ASSERT_TRUE(nodeAResult.is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeB, NodeClass::Variable, {}).is_good());

  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  rootResult.value().add_reference_sync(hasComponent, nodeA, /*isForward=*/true);
  nodeAResult.value().add_reference_sync(hasComponent, nodeB, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto result = engine->try_discover_sync({declIndex});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(to_set(result.value()), (std::set<NodeId>{nodeA, nodeB}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Mixed targets: one enumerable namespace + one declining namespace are both discovered (via their
// respective paths) and merged.
TEST(ExportEngineDiscoverTests, MixedEnumerableAndDecliningNamespacesAreBothDiscovered)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());  // ns1 enumerable
  auto declining = DecliningNamespace::create("urn:declining", tp.get_executor());
  const auto declIndex = addressSpace.add_namespace_sync(declining);
  ASSERT_EQ(declIndex, 2);

  const NodeId enumerable{1, "E"};
  ASSERT_TRUE(addressSpace.try_create_node_sync(enumerable, NodeClass::Object, {}).is_good());

  const NodeId root{ObjectId::RootFolder};
  const NodeId traversed{declIndex, "T"};
  auto rootResult = addressSpace.try_create_node_sync(root, NodeClass::Object, {});
  ASSERT_TRUE(rootResult.is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(traversed, NodeClass::Object, {}).is_good());
  rootResult.value().add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, traversed, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto result = engine->try_discover_sync({1, declIndex});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(to_set(result.value()), (std::set<NodeId>{enumerable, traversed}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// An unknown target namespace index propagates the failing status from enumerate_nodes_async.
TEST(ExportEngineDiscoverTests, UnknownNamespaceIndexPropagatesBadStatus)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto result = engine->try_discover_sync({99});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// The discovery completion is invoked exactly once.
TEST(ExportEngineDiscoverTests, CompletionFiresExactlyOnce)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  ASSERT_TRUE(addressSpace.try_create_node_sync(NodeId{1, "X"}, NodeClass::Object, {}).is_good());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  std::atomic<int> calls{0};
  std::promise<void> first;
  auto firstFired = first.get_future();

  engine->discover_async({1},
    [&calls, &first](Result<std::vector<NodeId>>) mutable
    {
      if (calls.fetch_add(1) == 0)
      {
        first.set_value();
      }
    });

  firstFired.wait();
  ::ua::test_utils::drain_with_timeout(tp);  // flush any (erroneous) further posted work
  EXPECT_EQ(calls.load(), 1);
}

// End-to-end read pass + serialization: an object and a variable wired by a HasComponent reference
// export to a NodeSet2 document that carries their ids, the reference, and the namespace table - and
// parses as well-formed XML rooted at <UANodeSet>. (Variable instance *values* go through the async
// read_value/value-source path and are a 4b' follow-up; this asserts the attribute + reference pass.)
TEST(ExportEngineExportTests, ExportsObjectAndVariableWithReferences)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId objectId{1, "Obj"};
  const NodeId variableId{1, "Var"};

  auto objectResult = addressSpace.try_create_node_sync(objectId, NodeClass::Object, {});
  ASSERT_TRUE(objectResult.is_good());
  objectResult.value().set_browse_name(QualifiedName{1, "Obj"});
  objectResult.value().set_display_name(LocalizedText{"", "Obj"});

  auto variableResult = addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {});
  ASSERT_TRUE(variableResult.is_good());
  variableResult.value().set_browse_name(QualifiedName{1, "Var"});
  variableResult.value().set_display_name(LocalizedText{"", "Var"});

  objectResult.value().add_reference_sync(
    NodeId{ReferenceTypeId::HasComponent}, variableId, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  settings.models = {ua::xml::nodeset::NodeSetModel{
    String{"urn:test"}, String{"1.0.0"}, DateTime{2024, 1, 1, 0, 0, 0, 0}, {}}};
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  const std::string& xml = result.value().document;

  EXPECT_NE(xml.find("<NamespaceUris><Uri>urn:test</Uri></NamespaceUris>"), npos) << xml;
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << xml;
  EXPECT_NE(xml.find("<UAVariable NodeId=\"ns=1;s=Var\""), npos) << xml;
  EXPECT_NE(xml.find("<Reference ReferenceType=\"i=47\" IsForward=\"true\">ns=1;s=Var</Reference>"), npos)
    << xml;

  // Well-formed and rooted at <UANodeSet>.
  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto root = context.xml_element().get_first_child();
  ASSERT_TRUE(root.has_value()) << xml;
  EXPECT_EQ(std::string(root->get_name()), "UANodeSet") << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// Exporting an empty target namespace still produces a valid, well-formed document (header only).
TEST(ExportEngineExportTests, EmptyNamespaceProducesValidDocument)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good());
  std::string xml = result.value().document;
  EXPECT_NE(xml.find("<UANodeSet"), npos) << xml;
  // An empty document is a valid self-closed <UANodeSet/>; assert well-formedness + root rather than
  // a literal close tag.
  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto root = context.xml_element().get_first_child();
  ASSERT_TRUE(root.has_value()) << xml;
  EXPECT_EQ(std::string(root->get_name()), "UANodeSet") << xml;
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Variable's live value is read on the async path and emitted as a `<Value>`, and any NodeId
// embedded in that value is namespace-translated server->file. Exporting a single namespace whose
// SERVER index is 2 maps it to FILE index 1, so the value's embedded `ns=2;i=5001` must surface as
// `ns=1;i=5001` - proving the embedded-id translator is wired into the value encoder.
TEST(ExportEngineExportTests, ExportsVariableValueWithTranslatedEmbeddedId)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());  // ns1
  auto second = default_ns::Namespace::create("urn:second", tp.get_executor());
  const auto secondIndex = addressSpace.add_namespace_sync(second);
  ASSERT_EQ(secondIndex, 2);

  const NodeId targetId{secondIndex, 5001u};
  const NodeId variableId{secondIndex, 5002u};
  auto targetResult = addressSpace.try_create_node_sync(targetId, NodeClass::Object, {});
  ASSERT_TRUE(targetResult.is_good());
  targetResult.value().set_browse_name(QualifiedName{secondIndex, "Target"});
  auto variableResult = addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {});
  ASSERT_TRUE(variableResult.is_good());
  variableResult.value().set_browse_name(QualifiedName{secondIndex, "Var"});

  // Write a NodeId value whose embedded namespace is the SERVER index 2.
  auto variableAccessor = addressSpace.try_find_sync<VariableAccessor>(variableId);
  ASSERT_TRUE(variableAccessor.is_good());
  ASSERT_TRUE(
    variableAccessor.value().try_write_value_sync(DataValue{Variant{NodeId{secondIndex, 5001u}}}).is_good());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  auto discovered = engine->try_discover_sync({secondIndex});
  ASSERT_TRUE(discovered.is_good());
  EXPECT_EQ(discovered.value().size(), 2u);

  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {secondIndex};
  auto result = engine->try_export_sync(settings);
  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  const std::string& xml = result.value().document;

  // The single exported namespace maps to file index 1 and is reported in the summary.
  EXPECT_EQ(result.value().namespacesWritten.size(), 1u);
  EXPECT_EQ(result.value().namespacesWritten.front().uri, "urn:second");
  EXPECT_EQ(result.value().namespacesWritten.front().serverIndex, 1);
  EXPECT_EQ(result.value().nodesExported, 2u);

  // ns=2 is the only referenced non-zero namespace, so it maps to file index 1.
  EXPECT_NE(xml.find("<NamespaceUris><Uri>urn:second</Uri></NamespaceUris>"), npos) << xml;
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;i=5001\""), npos) << xml;
  EXPECT_NE(xml.find("<UAVariable NodeId=\"ns=1;i=5002\""), npos) << xml;
  // The embedded NodeId value (server index 2) is translated to file index 1 inside `<Value>`. The
  // XML NodeId encoding wraps the id text in an `<Identifier>` element.
  EXPECT_NE(xml.find("<Identifier>ns=1;i=5001</Identifier>"), npos) << xml;
  // No raw server index 2 leaks into the file.
  EXPECT_EQ(xml.find("ns=2;"), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// node_filter excludes nodes: a predicate keeping only one of two discovered nodes exports exactly
// that node, and the summary count reflects it.
TEST(ExportEngineExportTests, NodeFilterExcludesNodes)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto keep = addressSpace.try_create_node_sync(NodeId{1, 10u}, NodeClass::Object, {});
  ASSERT_TRUE(keep.is_good());
  keep.value().set_browse_name(QualifiedName{1, "Keep"});
  auto drop = addressSpace.try_create_node_sync(NodeId{1, 20u}, NodeClass::Object, {});
  ASSERT_TRUE(drop.is_good());
  drop.value().set_browse_name(QualifiedName{1, "Drop"});

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  settings.nodeFilter = [](const ua::xml::nodeset::ExportedNode& node)
  {
    return node.nodeId.identifier().get_numeric() == 10u;
  };
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  EXPECT_EQ(result.value().nodesExported, 1u);
  const std::string& xml = result.value().document;
  EXPECT_NE(xml.find("NodeId=\"ns=1;i=10\""), npos) << xml;
  EXPECT_EQ(xml.find("NodeId=\"ns=1;i=20\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// reference_filter excludes references: a predicate dropping HasComponent (i=47) leaves the node but
// omits that reference from `<References>`.
TEST(ExportEngineExportTests, ReferenceFilterExcludesReferences)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId objectId{1, "Obj"};
  const NodeId variableId{1, "Var"};
  auto objectResult = addressSpace.try_create_node_sync(objectId, NodeClass::Object, {});
  ASSERT_TRUE(objectResult.is_good());
  objectResult.value().set_browse_name(QualifiedName{1, "Obj"});
  auto variableResult = addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {});
  ASSERT_TRUE(variableResult.is_good());
  variableResult.value().set_browse_name(QualifiedName{1, "Var"});
  objectResult.value().add_reference_sync(
    NodeId{ReferenceTypeId::HasComponent}, variableId, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  settings.referenceFilter = [](const ua::xml::nodeset::ExportedReference& reference)
  {
    return reference.referenceTypeId != NodeId{ReferenceTypeId::HasComponent};
  };
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  const std::string& xml = result.value().document;
  // Both nodes still export, but the HasComponent reference is gone (no i=47 reference remains).
  EXPECT_NE(xml.find("<UAObject NodeId=\"ns=1;s=Obj\""), npos) << xml;
  EXPECT_EQ(xml.find("ReferenceType=\"i=47\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// Scope::TypeDefinitionsOnly exports type-definition nodes (here an ObjectType) and omits instance
// nodes (an Object).
TEST(ExportEngineExportTests, ScopeTypeDefinitionsOnlyExcludesInstances)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto type = addressSpace.try_create_node_sync(NodeId{1, 100u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(type.is_good());
  type.value().set_browse_name(QualifiedName{1, "MyType"});
  auto instance = addressSpace.try_create_node_sync(NodeId{1, 200u}, NodeClass::Object, {});
  ASSERT_TRUE(instance.is_good());
  instance.value().set_browse_name(QualifiedName{1, "MyInstance"});

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  settings.scope = ExportEngine::ExportScope::TypeDefinitionsOnly;
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  EXPECT_EQ(result.value().nodesExported, 1u);
  const std::string& xml = result.value().document;
  EXPECT_NE(xml.find("<UAObjectType NodeId=\"ns=1;i=100\""), npos) << xml;
  EXPECT_EQ(xml.find("NodeId=\"ns=1;i=200\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// emit_aliases: a reference type with a resolvable browse name is emitted in an `<Aliases>` table and
// substituted for its raw id in `<Reference ReferenceType=...>`.
TEST(ExportEngineExportTests, EmitsAliasesForResolvableReferenceTypes)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId referenceTypeId{1, 300u};
  auto refType = addressSpace.try_create_node_sync(referenceTypeId, NodeClass::ReferenceType, {});
  ASSERT_TRUE(refType.is_good());
  refType.value().set_browse_name(QualifiedName{1, "Controls"});

  auto source = addressSpace.try_create_node_sync(NodeId{1, "A"}, NodeClass::Object, {});
  ASSERT_TRUE(source.is_good());
  source.value().set_browse_name(QualifiedName{1, "A"});
  auto target = addressSpace.try_create_node_sync(NodeId{1, "B"}, NodeClass::Object, {});
  ASSERT_TRUE(target.is_good());
  target.value().set_browse_name(QualifiedName{1, "B"});
  source.value().add_reference_sync(referenceTypeId, NodeId{1, "B"}, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};  // emitAliases defaults to true
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  const std::string& xml = result.value().document;
  EXPECT_NE(xml.find("<Aliases><Alias Alias=\"Controls\">ns=1;i=300</Alias></Aliases>"), npos) << xml;
  EXPECT_NE(xml.find("ReferenceType=\"Controls\""), npos) << xml;
  EXPECT_EQ(xml.find("ReferenceType=\"ns=1;i=300\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// emit_aliases disabled: no `<Aliases>` table, and reference types keep their raw ids.
TEST(ExportEngineExportTests, EmitAliasesDisabledKeepsRawIds)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId referenceTypeId{1, 300u};
  auto refType = addressSpace.try_create_node_sync(referenceTypeId, NodeClass::ReferenceType, {});
  ASSERT_TRUE(refType.is_good());
  refType.value().set_browse_name(QualifiedName{1, "Controls"});
  auto source = addressSpace.try_create_node_sync(NodeId{1, "A"}, NodeClass::Object, {});
  ASSERT_TRUE(source.is_good());
  source.value().set_browse_name(QualifiedName{1, "A"});
  auto target = addressSpace.try_create_node_sync(NodeId{1, "B"}, NodeClass::Object, {});
  ASSERT_TRUE(target.is_good());
  target.value().set_browse_name(QualifiedName{1, "B"});
  source.value().add_reference_sync(referenceTypeId, NodeId{1, "B"}, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  settings.emitAliases = false;
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  const std::string& xml = result.value().document;
  EXPECT_EQ(xml.find("<Aliases>"), npos) << xml;
  EXPECT_NE(xml.find("ReferenceType=\"ns=1;i=300\""), npos) << xml;

  ::ua::test_utils::drain_with_timeout(tp);
}

// A node whose mandatory BrowseName cannot be read is skipped (not emitted with an invalid empty
// BrowseName), keeping the document schema-valid. Optional attributes are still best-effort.
TEST(ExportEngineExportTests, NodeWithoutBrowseNameIsSkippedNotEmittedInvalid)
{
  constexpr auto npos = std::string::npos;
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto named = addressSpace.try_create_node_sync(NodeId{1, 10u}, NodeClass::Object, {});
  ASSERT_TRUE(named.is_good());
  named.value().set_browse_name(QualifiedName{1, "Named"});
  // Created without a browse name. `get_browse_name` answers with an empty name rather than
  // throwing, so the export reads that name and refuses the node explicitly; either way it is
  // skipped rather than emitted with an invalid empty BrowseName.
  auto unnamed = addressSpace.try_create_node_sync(NodeId{1, 20u}, NodeClass::Object, {});
  ASSERT_TRUE(unnamed.is_good());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {1};
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_good()) << static_cast<uint32_t>(result.status_code().as_status());
  EXPECT_EQ(result.value().nodesExported, 1u);
  const std::string& xml = result.value().document;
  EXPECT_NE(xml.find("NodeId=\"ns=1;i=10\""), npos) << xml;
  EXPECT_EQ(xml.find("NodeId=\"ns=1;i=20\""), npos) << xml;  // skipped, not emitted
  EXPECT_EQ(xml.find("BrowseName=\"\""), npos) << xml;  // never an invalid empty browse name

  ::ua::test_utils::drain_with_timeout(tp);
}

// A bad discovery status (unknown namespace) propagates out of the export.
TEST(ExportEngineExportTests, UnknownNamespacePropagatesBadStatus)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {99};
  auto result = engine->try_export_sync(settings);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// The read pass refuses a Node whose lookup is answered Uncertain instead of leaving it out of the document,
// and still skips one whose lookup is answered Bad.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ExportEngineExportTests, AnUncertainLookupInTheReadPassFailsTheExport)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto answering = std::make_shared<AnsweringLookupNamespace>("urn:answering", tp.get_executor(), false);
  const auto index = addressSpace.add_namespace_sync(answering);

  const NodeId kept{index, "Kept"};
  const NodeId gone{index, "Gone"};
  const NodeId uncertain{index, "Uncertain"};
  for (const auto& nodeId : {kept, gone, uncertain})
  {
    auto created = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good());
    created.value().set_browse_name(QualifiedName{index, "Name"});
  }
  answering->answer_lookup(gone, StatusCode{Status::BadNodeIdUnknown});

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = {index};

  // Control: a Bad lookup leaves its Node out and the export succeeds.
  auto skipped = engine->try_export_sync(settings);
  ASSERT_TRUE(skipped.is_good()) << static_cast<uint32_t>(skipped.status_code().as_status());
  EXPECT_EQ(skipped.value().nodesExported, 2u);

  answering->answer_lookup(uncertain, StatusCode{Status::UncertainLastUsableValue});
  auto refused = engine->try_export_sync(settings);
  EXPECT_TRUE(is_lookup_refusal(refused.status_code(), Status::UncertainLastUsableValue));
  ::ua::test_utils::drain_with_timeout(tp);
}

// The browse traversal refuses a reachable Node whose lookup is answered Uncertain, rather than skipping it
// and every Node reached only through it.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ExportEngineDiscoverTests, AnUncertainLookupInTheTraversalFailsTheDiscovery)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto answering = std::make_shared<AnsweringLookupNamespace>("urn:answering", tp.get_executor(), true);
  const auto index = addressSpace.add_namespace_sync(answering);

  const NodeId root{ObjectId::RootFolder};
  const NodeId nodeA{index, "A"};
  const NodeId nodeB{index, "B"};
  auto rootResult = addressSpace.try_create_node_sync(root, NodeClass::Object, {});
  ASSERT_TRUE(rootResult.is_good());
  auto nodeAResult = addressSpace.try_create_node_sync(nodeA, NodeClass::Object, {});
  ASSERT_TRUE(nodeAResult.is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeB, NodeClass::Object, {}).is_good());
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  rootResult.value().add_reference_sync(hasComponent, nodeA, /*isForward=*/true);
  nodeAResult.value().add_reference_sync(hasComponent, nodeB, /*isForward=*/true);

  auto engine = ExportEngine::create(EncodingLimits{}, addressSpace);
  answering->answer_lookup(nodeA, StatusCode{Status::UncertainLastUsableValue});
  auto result = engine->try_discover_sync({index});

  EXPECT_TRUE(is_lookup_refusal(result.status_code(), Status::UncertainLastUsableValue));
  ::ua::test_utils::drain_with_timeout(tp);
}
