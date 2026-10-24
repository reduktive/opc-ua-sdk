// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The namespace conformance suite (COMP-ADDRSP-NAMESPACE-INTERFACE, 1.0 plan ASD-7 and section 5.2.8):
// the contract of the batched Namespace members, run against every namespace the parameter names.
// Each arm discharges the criterion it cites; an arm whose behaviour lands in a later unit is marked
// with the Defect that blocks it.
//
// The fixture registers the namespace under test with an AddressSpace and builds its subjects - the
// Object, the Variable, the Method, the View and three scalar Variables - through today's creation
// path. Every stimulus then goes through the namespace's own batched members, called through a
// `Namespace&`, and every Node an item carries is one the namespace's own lookup returned.

#include <gtest/gtest.h>

#include "described_conformance_namespace.h"
#include "test_utilities.h"
#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_attribute_write_mask.h"
#include "ua_browse_direction.h"
#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_default_namespace.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_option_set.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_namespace_authorization.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_option_set.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_status.h"
#include "ua_structure_definition.h"
#include "ua_structure_type.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <latch>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

// --- The parameter -----------------------------------------------------------------------------------

// Installs the handler of a Method through the MethodCallSource its Node offers, as the Nodes of a namespace
// with a Node class of its own do.
StatusCode install_through_method_call_source(
  Namespace& space, const NodeId& method, MethodCallSource::CallHandler handler)
{
  const std::optional<NodeResult> found = space.find_node(method, std::nullopt);
  if (!found.has_value() || found->is_bad())
  {
    return StatusCode{Status::BadNodeIdUnknown};
  }
  auto* callSource = found->value()->method_call_source();
  if (callSource == nullptr)
  {
    return StatusCode{Status::BadNotSupported};
  }
  return callSource->set_call_handler(std::move(handler));
}

// One namespace the suite runs against. A namespace that does not offer a subject an arm needs says so
// here, and the arm then stops (component statement, "How the criteria are discharged").
struct NamespaceUnderTest
{
  std::string name;
  std::function<shared_ptr<Namespace>(boost::asio::any_io_executor)> make;
  bool offersCreation{true};
  bool offersViews{true};
  // Installs the handler the calls of a Method run, the way the namespace's application does.
  std::function<StatusCode(Namespace&, const NodeId&, MethodCallSource::CallHandler)> installCallHandler{
    install_through_method_call_source};
};

void PrintTo(const NamespaceUnderTest& subject, std::ostream* out)
{
  *out << subject.name;
}

NamespaceUnderTest in_memory_namespace()
{
  return NamespaceUnderTest{"InMemory",
    [](boost::asio::any_io_executor executor) -> shared_ptr<Namespace>
    {
      return default_ns::Namespace::create("urn:test:namespace-conformance:in-memory", std::move(executor));
    }};
}

// A namespace written against the public headers alone, serving the Nodes of a DescribedNodes store; its
// Methods' handlers are installed through the namespace, since its Nodes offer no MethodCallSource.
NamespaceUnderTest described_nodes_namespace()
{
  return NamespaceUnderTest{"DescribedNodes",
    [](boost::asio::any_io_executor) -> shared_ptr<Namespace>
    {
      return std::make_shared<ua::test::DescribedConformanceNamespace>(
        String{"urn:test:namespace-conformance:described-nodes"});
    },
    true,
    true,
    [](Namespace& space, const NodeId& method, MethodCallSource::CallHandler handler)
    {
      return dynamic_cast<ua::test::DescribedConformanceNamespace&>(space).set_call_handler(
        method, std::move(handler));
    }};
}

// --- Completion recording ----------------------------------------------------------------------------

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

// Lets work the namespace may still have queued run, so that a second completion would be seen.
void let_work_drain()
{
  std::this_thread::sleep_for(100ms);
}

// A monitoring sink that records every sample it receives.
class RecordingSink final : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    const std::lock_guard lock{mMutex};
    for (auto& sample : samples)
    {
      mSamples.push_back(std::move(sample));
    }
    mReady.notify_all();
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  // Waits until a sample holding @p expected has arrived.
  bool wait_for(const Array<int32_t>& expected)
  {
    std::unique_lock lock{mMutex};
    return mReady.wait_for(
      lock, ::ua::test_utils::default_poll_budget(), [this, &expected] { return holds_locked(expected); });
  }

  bool holds(const Array<int32_t>& expected)
  {
    const std::lock_guard lock{mMutex};
    return holds_locked(expected);
  }

private:
  bool holds_locked(const Array<int32_t>& expected) const
  {
    for (const auto& [id, value] : mSamples)
    {
      const auto* array = value.value().try_as<Array<int32_t>>();
      if (array != nullptr && *array == expected)
      {
        return true;
      }
    }
    return false;
  }

  std::mutex mMutex;
  std::condition_variable mReady;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
};

// --- Request builders --------------------------------------------------------------------------------

ReadValueId value_of(const NodeId& nodeId, const char* range = nullptr)
{
  ReadValueId read;
  read.node_id() = nodeId;
  read.attribute_id() = utils::to_underlying(AttributeId::Value);
  if (range != nullptr)
  {
    read.index_range() = range;
  }
  return read;
}

WriteValue display_name_write(const NodeId& nodeId, const char* text)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(AttributeId::DisplayName);
  write.value() = DataValue{Variant{LocalizedText{LocaleId{"en"}, String{text}}}};
  return write;
}

WriteValue value_write(const NodeId& nodeId, Variant value, const char* range = nullptr)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(AttributeId::Value);
  write.value() = DataValue{std::move(value)};
  if (range != nullptr)
  {
    write.index_range() = range;
  }
  return write;
}

CallMethodRequest call_of(const NodeId& objectId, const NodeId& methodId, int32_t input)
{
  CallMethodRequest request;
  request.object_id() = objectId;
  request.method_id() = methodId;
  request.input_arguments().payload().push_back(Variant{input});
  return request;
}

std::optional<int32_t> first_output(const std::optional<CallResult>& result)
{
  if (!result || !result->is_good() || result->value().output_arguments().payload().empty())
  {
    return std::nullopt;
  }
  return result->value().output_arguments().payload()[0].as<int32_t>();
}

std::optional<Array<int32_t>> int32_array(const DataValueResult& result)
{
  if (!result.is_good())
  {
    return std::nullopt;
  }
  const auto* array = result.value().value().try_as<Array<int32_t>>();
  if (array == nullptr)
  {
    return std::nullopt;
  }
  return *array;
}

bool holds_reference(const References& references, const NodeId& type, const NodeId& target, bool isForward)
{
  for (const auto& reference : references)
  {
    if (reference.type_id() == type && reference.target_id() == ExpandedNodeId{target} &&
        reference.is_forward() == isForward)
    {
      return true;
    }
  }
  return false;
}

std::vector<Reference> to_vector(const References& references)
{
  return std::vector<Reference>(references.begin(), references.end());
}

const NodeId hasComponent{ReferenceTypeId::HasComponent};
const NodeId hasOrderedComponent{ReferenceTypeId::HasOrderedComponent};
const NodeId hasProperty{ReferenceTypeId::HasProperty};
const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
const NodeId organizes{ReferenceTypeId::Organizes};
const NodeId int32DataType{0, uint32_t{6}};
const NodeId uint32DataType{0, uint32_t{7}};
const NodeId stringDataType{0, uint32_t{12}};
const NodeId baseObjectType{0, uint32_t{58}};
const Array<int32_t> initialArray{10, 20, 30, 40, 50};

// --- The fixture -------------------------------------------------------------------------------------

class NamespaceConformance : public ::testing::TestWithParam<NamespaceUnderTest>
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:namespace-conformance", mPool.get_executor()));
    mNamespace = GetParam().make(mPool.get_executor());
    ASSERT_NE(mNamespace, nullptr);
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
    mObject = NodeId{mIndex, "Object"};
    mVariable = NodeId{mIndex, "Variable"};
    mMethod = NodeId{mIndex, "Method"};
    mView = NodeId{mIndex, "View"};
    mScalar1 = NodeId{mIndex, "Scalar1"};
    mScalar2 = NodeId{mIndex, "Scalar2"};
    mScalar3 = NodeId{mIndex, "Scalar3"};
    build_subjects();
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  Namespace& ns()
  {
    return *mNamespace;
  }

  InitialAttributes names(const char* name) const
  {
    return InitialAttributes{
      {AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{mIndex, name})},
      {AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{LocaleId{"en"}, String{name}})}};
  }

  // A Variable readable and writable by its Value, whose DisplayName is writable.
  void create_variable(const NodeId& nodeId, const char* name, const NodeId& dataType, int32_t valueRank,
    Variant value, QualifiedName browseName = {})
  {
    auto attributes = names(name);
    if (!browseName.name().empty())
    {
      attributes[0].second = attribute_wire::browse_name(browseName);
    }
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    AttributeWriteMask writeMask;
    writeMask.set(AttributeWriteMask::Bit::DisplayName);
    attributes.emplace_back(AttributeId::DataType, attribute_wire::data_type(dataType));
    attributes.emplace_back(AttributeId::ValueRank, attribute_wire::value_rank(ValueRank{valueRank}));
    attributes.emplace_back(AttributeId::AccessLevel, attribute_wire::access_level(accessLevel));
    attributes.emplace_back(AttributeId::WriteMask, attribute_wire::write_mask(writeMask));
    auto variable = mAddressSpace->create_sync<VariableAccessor>(nodeId, NodeClass::Variable, attributes);
    variable.write_value_sync(DataValue{std::move(value)});
  }

  // Stores both halves of a Reference through today's path, which stores one half per call.
  void link(const NodeId& source, const NodeId& type, const NodeId& target)
  {
    mAddressSpace->find_node_sync(source).add_reference_sync(type, target);
    mAddressSpace->find_node_sync(target).add_reference_sync(type, ExpandedNodeId{source}, false);
  }

  void build_subjects()
  {
    auto object = mAddressSpace->create_sync<ObjectAccessor>(mObject, NodeClass::Object, names("Object"));
    (void)object.try_add_reference_sync(hasTypeDefinition, baseObjectType);

    create_variable(mVariable, "Variable", int32DataType, 1, Variant{initialArray});
    create_variable(mScalar1, "Scalar1", int32DataType, ValueRank::scalar, Variant{int32_t{1}});
    create_variable(mScalar2, "Scalar2", int32DataType, ValueRank::scalar, Variant{int32_t{2}});
    create_variable(mScalar3, "Scalar3", int32DataType, ValueRank::scalar, Variant{int32_t{3}});

    auto methodAttributes = names("Method");
    methodAttributes.emplace_back(AttributeId::Executable, attribute_wire::executable(true));
    (void)mAddressSpace->create_sync<MethodAccessor>(mMethod, NodeClass::Method, methodAttributes);
    // The handler answers its input as its output, and Bad_InvalidArgument for the input 0.
    const StatusCode installed = GetParam().installCallHandler(ns(),
      mMethod,
      [](const CallMethodRequest& request,
        shared_ptr<const MethodCallContext>,
        std::function<void(CallResult)>
          callback)
      {
        const auto& inputs = request.input_arguments().payload();
        const int32_t input = inputs.empty() ? 0 : inputs[0].as<int32_t>();
        if (input == 0)
        {
          callback(CallResult{StatusCode{Status::BadInvalidArgument}});
          return;
        }
        CallMethodResult result;
        result.output_arguments().payload().push_back(Variant{input});
        callback(CallResult{std::move(result)});
      });
    ASSERT_TRUE(installed.is_good()) << to_string(installed);

    link(mObject, hasComponent, mMethod);
    link(mObject, organizes, mScalar1);
    link(mObject, organizes, mScalar2);
    link(mObject, organizes, mScalar3);

    if (GetParam().offersViews)
    {
      auto view = mAddressSpace->create_sync<ViewAccessor>(mView, NodeClass::View, names("View"));
      ASSERT_TRUE(view.try_add_node_to_view_sync(mObject).is_good());
      ASSERT_TRUE(view.try_add_node_to_view_sync(mScalar2).is_good());
    }
  }

  // --- Calls through the namespace's members ---

  std::vector<NodeResult> lookup(std::vector<NodeId> nodeIds)
  {
    Completion<BatchResult<NodeResult>> found;
    ns().find_nodes_async(mRequest, nodeIds, std::nullopt, found.callback());
    if (!found.wait())
    {
      ADD_FAILURE() << "find_nodes_async did not complete";
      return {};
    }
    auto& batch = found.get<0>();
    return std::vector<NodeResult>(batch.items.begin(), batch.items.end());
  }

  // The Node the namespace's lookup answers for @p nodeId, or null with a failure recorded.
  shared_ptr<Node> hold(const NodeId& nodeId)
  {
    auto items = lookup({nodeId});
    if (items.size() != 1)
    {
      ADD_FAILURE() << "find_nodes_async answered " << items.size() << " items for one NodeId";
      return nullptr;
    }
    if (!items[0].is_good())
    {
      ADD_FAILURE() << "find_nodes_async answered " << to_string(items[0].status_code()) << " for "
                    << to_string(nodeId);
      return nullptr;
    }
    return items[0].value();
  }

  BatchResult<DataValueResult> read_values(std::span<const ValueReadItem> items)
  {
    Completion<BatchResult<DataValueResult>> read;
    ns().read_values_async(mRequest, nullptr, items, Duration{0}, false, read.callback());
    EXPECT_TRUE(read.wait());
    return read.count() > 0 ? read.get<0>() : BatchResult<DataValueResult>{};
  }

  DataValueResult read_value(const Node& node, const NodeId& nodeId)
  {
    const ReadValueId read = value_of(nodeId);
    const std::vector<ValueReadItem> items{{node, read}};
    auto batch = read_values(items);
    if (batch.items.size() != 1)
    {
      return DataValueResult{StatusCode{Status::BadInternalError}};
    }
    return batch.items[0];
  }

  std::pair<BatchResult<VoidResult>, std::vector<VersionedNode>> write(std::span<const ValueWriteItem> items)
  {
    Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> written;
    ns().write_async(mRequest, nullptr, items, written.callback());
    EXPECT_TRUE(written.wait());
    if (written.count() == 0)
    {
      return {};
    }
    return {written.get<0>(), written.get<1>()};
  }

  NodeReferencesResult read_references(const Node& node, const NodeId& nodeId, BrowseDirection direction,
    std::vector<NodeId> hint = {}, uint32_t maxReferences = 0, ByteString resumeToken = {})
  {
    const std::vector<ReferenceQuery> queries{
      ReferenceQuery{node, nodeId, direction, std::move(hint), maxReferences, std::move(resumeToken)}};
    Completion<BatchResult<NodeReferencesResult>> read;
    ns().read_references_async(mRequest, queries, read.callback());
    if (!read.wait() || read.get<0>().items.size() != 1)
    {
      return NodeReferencesResult{StatusCode{Status::BadInternalError}};
    }
    return read.get<0>().items[0];
  }

  // The References @p nodeId holds in @p direction, read unpaged, or empty with a failure recorded.
  References references_of(const NodeId& nodeId, BrowseDirection direction)
  {
    auto node = hold(nodeId);
    if (!node)
    {
      return {};
    }
    auto read = read_references(*node, nodeId, direction);
    if (!read.is_good())
    {
      ADD_FAILURE() << "read_references_async answered " << to_string(read.status_code()) << " for "
                    << to_string(nodeId);
      return {};
    }
    return read.value().references;
  }

  std::pair<BatchResult<VoidResult>, std::vector<VersionedNode>> add_references(
    std::vector<ReferenceChange> changes)
  {
    Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> added;
    ns().add_references_async(mRequest, changes, added.callback());
    EXPECT_TRUE(added.wait());
    if (added.count() == 0)
    {
      return {};
    }
    return {added.get<0>(), added.get<1>()};
  }

  BatchResult<VoidResult> remove_references(std::vector<ReferenceChange> changes)
  {
    Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> removed;
    ns().remove_references_async(mRequest, changes, removed.callback());
    EXPECT_TRUE(removed.wait());
    return removed.count() > 0 ? removed.get<0>() : BatchResult<VoidResult>{};
  }

  BatchResult<NodeResult> create_nodes(std::vector<NodeCreation> creations)
  {
    Completion<BatchResult<NodeResult>> created;
    ns().create_nodes_async(mRequest, creations, created.callback());
    EXPECT_TRUE(created.wait());
    return created.count() > 0 ? created.get<0>() : BatchResult<NodeResult>{};
  }

  BatchResult<DeleteNodeResult> delete_nodes(std::vector<NodeId> nodeIds)
  {
    Completion<BatchResult<DeleteNodeResult>, std::vector<VersionedNode>> deleted;
    ns().delete_nodes_async(mRequest, nodeIds, ReferenceHalves::Both, deleted.callback());
    EXPECT_TRUE(deleted.wait());
    return deleted.count() > 0 ? deleted.get<0>() : BatchResult<DeleteNodeResult>{};
  }

  BatchResult<BoolResult> view_contains(std::vector<ExpandedNodeId> candidates)
  {
    Completion<BatchResult<BoolResult>> contains;
    ns().view_contains_async(mRequest, mView, candidates, contains.callback());
    EXPECT_TRUE(contains.wait());
    return contains.count() > 0 ? contains.get<0>() : BatchResult<BoolResult>{};
  }

  std::pair<BatchResult<VoidResult>, std::vector<VersionedNode>> add_to_view(std::vector<NodeId> nodeIds)
  {
    Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> added;
    ns().add_to_view_async(mRequest, mView, nodeIds, added.callback());
    EXPECT_TRUE(added.wait());
    if (added.count() == 0)
    {
      return {};
    }
    return {added.get<0>(), added.get<1>()};
  }

  // The Node the address space's lookup reaches for @p nodeId, through today's accessor.
  std::optional<NodeAccessor> address_space_node(const NodeId& nodeId)
  {
    Completion<BatchResult<NodeAccessorResult>> found;
    const std::vector<NodeId> nodeIds{nodeId};
    mAddressSpace->find_nodes_async(nodeIds, found.callback());
    if (!found.wait() || found.get<0>().items.size() != 1 || !found.get<0>().items[0].is_good())
    {
      return std::nullopt;
    }
    return found.get<0>().items[0].value();
  }

  NodeCreation object_creation(const NodeId& nodeId, const char* name) const
  {
    return NodeCreation{nodeId, NodeClass::Object, names(name)};
  }

  boost::asio::thread_pool mPool{2};
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<Namespace> mNamespace;
  const RequestInfo mRequest{};
  uint16_t mIndex{0};
  NodeId mObject;
  NodeId mVariable;
  NodeId mMethod;
  NodeId mView;
  NodeId mScalar1;
  NodeId mScalar2;
  NodeId mScalar3;
};

}  // namespace

// === COMP-ADDRSP-NAMESPACE-INTERFACE-02: Node::deleted() and Node::attributes() ========================

// NR-44 rules 1 and 5: the deleted Node is marked before the delete completes, the other is not, and the
// deleted NodeId is no longer found.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-02-HELD-NODE-SAYS-DELETED, scope=function)
TEST_P(NamespaceConformance, ANodeHeldAcrossItsDeleteSaysItIsDeleted)
{
  auto a = hold(mScalar1);
  auto b = hold(mScalar3);
  ASSERT_TRUE(a && b);
  EXPECT_FALSE(a->deleted());

  auto inCompletion = std::make_shared<std::promise<std::pair<bool, bool>>>();
  auto answered = inCompletion->get_future();
  const std::vector<NodeId> toDelete{mScalar1};
  ns().delete_nodes_async(mRequest,
    toDelete,
    ReferenceHalves::Both,
    [a, b, inCompletion](BatchResult<DeleteNodeResult> result, std::vector<VersionedNode>)
    {
      EXPECT_EQ(result.items.size(), 1u);
      if (!result.items.empty())
      {
        EXPECT_TRUE(result.items[0].is_good()) << to_string(result.items[0].status_code());
      }
      inCompletion->set_value({a->deleted(), b->deleted()});
    });
  ASSERT_EQ(answered.wait_for(::ua::test_utils::default_poll_budget()), std::future_status::ready);
  const auto [aDeleted, bDeleted] = answered.get();
  EXPECT_TRUE(aDeleted);
  EXPECT_FALSE(bDeleted);

  auto later = lookup({mScalar1});
  ASSERT_EQ(later.size(), 1u);
  EXPECT_EQ(later[0].status_code().as_status(), Status::BadNodeIdUnknown)
    << to_string(later[0].status_code());
}

// NR-44 and NR-70 A1: deleted() is read without the Node's lock while the namespace deletes the Node; an
// answer never goes back from true to false.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-02-DELETED-READ-DURING-DELETE, scope=function)
TEST_P(NamespaceConformance, DeletedIsSafeToReadWhileTheNodeIsDeleted)
{
  if (!GetParam().offersCreation)
  {
    GTEST_SKIP() << GetParam().name << " does not offer Node creation";
  }
  constexpr uint32_t rounds = 200;
  constexpr int readsAfterTrue = 16;
  for (uint32_t round = 0; round < rounds; ++round)
  {
    const NodeId nodeId{mIndex, uint32_t{10000} + round};
    auto created = create_nodes({object_creation(nodeId, "Transient")});
    ASSERT_EQ(created.items.size(), 1u);
    ASSERT_TRUE(created.items[0].is_good())
      << "round " << round << ": " << to_string(created.items[0].status_code());
    auto node = hold(nodeId);
    ASSERT_TRUE(node) << "round " << round;

    std::latch start{3};
    std::atomic<bool> deleteCompleted{false};

    struct ReaderOutcome
    {
      bool sawTrue{false};
      bool wentBack{false};
    };

    ReaderOutcome outcomes[2];
    auto reader = [&node, &start, &deleteCompleted](ReaderOutcome& outcome)
    {
      start.arrive_and_wait();
      const auto deadline = std::chrono::steady_clock::now() + ::ua::test_utils::default_poll_budget();
      while (!outcome.sawTrue)
      {
        if (node->deleted())
        {
          outcome.sawTrue = true;
        }
        else if (deleteCompleted.load() || std::chrono::steady_clock::now() > deadline)
        {
          // The delete has completed: the flag must already read true.
          outcome.sawTrue = node->deleted();
          break;
        }
      }
      for (int i = 0; outcome.sawTrue && i < readsAfterTrue; ++i)
      {
        if (!node->deleted())
        {
          outcome.wentBack = true;
        }
      }
    };
    std::thread first{reader, std::ref(outcomes[0])};
    std::thread second{reader, std::ref(outcomes[1])};
    start.arrive_and_wait();
    auto deleted = delete_nodes({nodeId});
    deleteCompleted.store(true);
    first.join();
    second.join();

    ASSERT_EQ(deleted.items.size(), 1u);
    ASSERT_TRUE(deleted.items[0].is_good())
      << "round " << round << ": " << to_string(deleted.items[0].status_code());
    ASSERT_TRUE(outcomes[0].sawTrue && outcomes[1].sawTrue) << "round " << round;
    ASSERT_FALSE(outcomes[0].wentBack || outcomes[1].wentBack) << "round " << round;
  }
}

// NR-1 rule 2 and NR-21 rule 5: attributes() returns a whole copy while a write to the Node is applied.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-02-ATTRIBUTES-READ-DURING-WRITE, scope=function)
TEST_P(NamespaceConformance, AttributesIsSafeToReadWhileAWriteIsApplied)
{
  constexpr int iterations = 1000;
  auto node = hold(mVariable);
  ASSERT_TRUE(node);

  std::latch start{2};
  std::atomic<bool> writerDone{false};
  std::atomic<int> goodWrites{0};
  std::optional<StatusCode> firstFailure;
  std::thread writer{[this, &start, &writerDone, &goodWrites, &firstFailure, &node]
    {
      start.arrive_and_wait();
      for (int i = 0; i < iterations; ++i)
      {
        const WriteValue value = display_name_write(mVariable, i % 2 == 0 ? "A" : "B");
        const std::vector<ValueWriteItem> items{{*node, value}};
        Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> written;
        ns().write_async(mRequest, nullptr, items, written.callback());
        if (!written.wait() || written.get<0>().items.size() != 1 || !written.get<0>().items[0].is_good())
        {
          firstFailure = written.count() > 0 && written.get<0>().items.size() == 1
                           ? written.get<0>().items[0].status_code()
                           : StatusCode{Status::BadInternalError};
          break;
        }
        goodWrites.fetch_add(1);
      }
      writerDone.store(true);
    }};

  std::vector<std::string> torn;
  int reads = 0;
  start.arrive_and_wait();
  while (!writerDone.load())
  {
    const NodeDescription description = node->attributes();
    const LocalizedText displayName = description.display_name();
    ++reads;
    const bool whole = displayName.locale() == LocaleId{"en"} &&
                       (displayName.text() == String{"Variable"} || displayName.text() == String{"A"} ||
                         displayName.text() == String{"B"});
    if (!whole && torn.size() < 5)
    {
      torn.push_back(to_string(displayName));
    }
  }
  writer.join();

  ASSERT_FALSE(firstFailure.has_value()) << "write_async answered " << to_string(*firstFailure);
  EXPECT_EQ(goodWrites.load(), iterations);
  EXPECT_TRUE(torn.empty()) << "first DisplayName read that was not one written whole: " << torn.front();
  const NodeDescription last = node->attributes();
  EXPECT_EQ(last.display_name().text(), String{"B"});
}

// === COMP-ADDRSP-NAMESPACE-INTERFACE-05: completion, item order, lookup =================================

// NR-8 and ASD-3: every batched member completes exactly once with one result per item, each at its
// item's index.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-COMPLETES-ONCE-WITH-ONE-RESULT-PER-ITEM, scope=function)
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-RESULTS-IN-ITEM-ORDER, scope=function)
TEST_P(NamespaceConformance, EveryBatchedMemberCompletesOnceWithOneResultPerItemInOrder)
{
  const NodeId unknown{mIndex, "NoSuchNode"};

  // The lookup: a known NodeId, an unknown one and another known one.
  Completion<BatchResult<NodeResult>> find;
  const std::vector<NodeId> lookupIds{mScalar1, unknown, mScalar3};
  ns().find_nodes_async(mRequest, lookupIds, std::nullopt, find.callback());
  ASSERT_TRUE(find.wait());
  {
    const auto& items = find.get<0>().items;
    ASSERT_EQ(items.size(), 3u);
    ASSERT_TRUE(items[0].is_good()) << to_string(items[0].status_code());
    EXPECT_EQ(items[1].status_code().as_status(), Status::BadNodeIdUnknown)
      << to_string(items[1].status_code());
    ASSERT_TRUE(items[2].is_good()) << to_string(items[2].status_code());
    const NodeDescription firstNode = items[0].value()->attributes();
    const NodeDescription lastNode = items[2].value()->attributes();
    EXPECT_EQ(firstNode.node_id(), mScalar1);
    EXPECT_EQ(lastNode.node_id(), mScalar3);
  }

  auto object = hold(mObject);
  auto method = hold(mMethod);
  auto scalar1 = hold(mScalar1);
  auto scalar2 = hold(mScalar2);
  auto scalar3 = hold(mScalar3);
  ASSERT_TRUE(object && method && scalar1 && scalar2 && scalar3);

  // References of three Nodes.
  Completion<BatchResult<NodeReferencesResult>> references;
  const std::vector<ReferenceQuery> queries{ReferenceQuery{*object, mObject, BrowseDirection::Forward},
    ReferenceQuery{*scalar1, mScalar1, BrowseDirection::Forward},
    ReferenceQuery{*scalar3, mScalar3, BrowseDirection::Forward}};
  ns().read_references_async(mRequest, queries, references.callback());

  // Values of three Variables holding 1, 2 and 3.
  Completion<BatchResult<DataValueResult>> values;
  const std::vector<ReadValueId> reads{value_of(mScalar1), value_of(mScalar2), value_of(mScalar3)};
  const std::vector<ValueReadItem> readItems{
    {*scalar1, reads[0]}, {*scalar2, reads[1]}, {*scalar3, reads[2]}};
  ns().read_values_async(mRequest, nullptr, readItems, Duration{0}, false, values.callback());

  // Writes, the second of a Value an Object does not have.
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> writes;
  const std::vector<WriteValue> writeValues{display_name_write(mScalar1, "One"),
    value_write(mObject, Variant{int32_t{1}}),
    display_name_write(mScalar3, "Three")};
  const std::vector<ValueWriteItem> writeItems{
    {*scalar1, writeValues[0]}, {*object, writeValues[1]}, {*scalar3, writeValues[2]}};
  ns().write_async(mRequest, nullptr, writeItems, writes.callback());

  // Calls whose handler answers the output arguments 1, 2 and 3.
  Completion<BatchResult<std::optional<CallResult>>> calls;
  const std::vector<CallMethodRequest> callRequests{
    call_of(mObject, mMethod, 1), call_of(mObject, mMethod, 2), call_of(mObject, mMethod, 3)};
  const std::vector<CallItem> callItems{{*object, *method, callRequests[0], nullptr},
    {*object, *method, callRequests[1], nullptr},
    {*object, *method, callRequests[2], nullptr}};
  ns().call_async(mRequest, nullptr, callItems, calls.callback());

  // View membership of a member, a non-member and a member.
  Completion<BatchResult<BoolResult>> contains;
  const std::vector<ExpandedNodeId> candidates{
    ExpandedNodeId{mObject}, ExpandedNodeId{mVariable}, ExpandedNodeId{mScalar2}};
  ns().view_contains_async(mRequest, mView, candidates, contains.callback());

  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> viewAdds;
  const std::vector<NodeId> viewMembers{mVariable, mMethod, mScalar1};
  ns().add_to_view_async(mRequest, mView, viewMembers, viewAdds.callback());

  // Creation, the second of a NodeId the namespace already holds.
  const NodeId x1{mIndex, "X1"};
  const NodeId x3{mIndex, "X3"};
  Completion<BatchResult<NodeResult>> creates;
  const std::vector<NodeCreation> creations{
    object_creation(x1, "X1"), object_creation(mObject, "Object"), object_creation(x3, "X3")};
  ns().create_nodes_async(mRequest, creations, creates.callback());
  ASSERT_TRUE(creates.wait());

  Completion<BatchResult<DeleteNodeResult>, std::vector<VersionedNode>> deletes;
  const std::vector<NodeId> toDelete{x1, unknown, x3};
  ns().delete_nodes_async(mRequest, toDelete, ReferenceHalves::Both, deletes.callback());

  // Reference halves, the second a half the Object already holds.
  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> referenceAdds;
  const std::vector<ReferenceChange> adds{ReferenceChange{mObject, hasComponent, ExpandedNodeId{mVariable}},
    ReferenceChange{mObject, hasComponent, ExpandedNodeId{mMethod}},
    ReferenceChange{mScalar1, organizes, ExpandedNodeId{mScalar3}}};
  ns().add_references_async(mRequest, adds, referenceAdds.callback());
  ASSERT_TRUE(referenceAdds.wait());

  Completion<BatchResult<VoidResult>, std::vector<VersionedNode>> referenceRemoves;
  const std::vector<ReferenceChange> removals{
    ReferenceChange{mObject, hasComponent, ExpandedNodeId{mVariable}},
    ReferenceChange{mObject, organizes, ExpandedNodeId{mVariable}},
    ReferenceChange{mScalar1, organizes, ExpandedNodeId{mScalar3}}};
  ns().remove_references_async(mRequest, removals, referenceRemoves.callback());

  Completion<BatchResult<VoidResult>> validations;
  const std::vector<RolePermissionsUpdate> updates{RolePermissionsUpdate{mScalar1, std::nullopt},
    RolePermissionsUpdate{unknown, std::nullopt},
    RolePermissionsUpdate{mScalar3, std::nullopt}};
  ns().validate_role_permissions_updates_async(mRequest, updates, validations.callback());

  Completion<EffectivePermissionsResult> permissions;
  const auto identity = std::make_shared<const AccessIdentity>(
    AccessIdentityKey{1}, std::vector<NodeId>{}, nullptr, nullptr, String{""});
  ns().effective_permissions_async(
    mRequest, identity, std::vector<NodeId>{mScalar1, unknown, mScalar3}, permissions.callback());

  // Monitoring, the second item of a NodeId the namespace does not hold. As CreateMonitoredItems does, each
  // item the namespace's lookup answered carries that Node; the unknown one carries none.
  auto sink = std::make_shared<RecordingSink>();
  std::vector<MonitoringCreateItem> monitoringItems(3);
  const NodeId monitored[] = {mScalar1, unknown, mScalar3};
  for (size_t i = 0; i < 3; ++i)
  {
    monitoringItems[i].nodeId = monitored[i];
    if (i != 1)
    {
      monitoringItems[i].node = hold(monitored[i]);
    }
    monitoringItems[i].monitoredItemId = static_cast<IntegerId>(i + 1);
    monitoringItems[i].sink = sink;
  }
  Completion<BatchResult<MonitoringCreateItemResult>> monitoringCreates;
  ns().create_monitoring_async(mRequest, nullptr, monitoringItems, monitoringCreates.callback());
  ASSERT_TRUE(monitoringCreates.wait());
  std::vector<MonitoringHandle> handles{0, 0xFFFFFFFFu, 0};
  {
    const auto& items = monitoringCreates.get<0>().items;
    if (items.size() == 3 && items[0].is_good() && items[2].is_good())
    {
      handles[0] = items[0].value().handle;
      handles[2] = items[2].value().handle;
    }
  }
  Completion<BatchResult<MonitoringModifyItemResult>> monitoringModifies;
  const std::vector<MonitoringModifyItem> modifications{MonitoringModifyItem{handles[0], Duration{0}, 1},
    MonitoringModifyItem{handles[1], Duration{0}, 1},
    MonitoringModifyItem{handles[2], Duration{0}, 1}};
  ns().modify_monitoring_async(mRequest, modifications, monitoringModifies.callback());
  ASSERT_TRUE(monitoringModifies.wait());
  Completion<BatchResult<VoidResult>> monitoringDeletes;
  ns().delete_monitoring_async(mRequest, handles, monitoringDeletes.callback());

  ASSERT_TRUE(references.wait() && values.wait() && writes.wait() && calls.wait() && contains.wait() &&
              viewAdds.wait() && deletes.wait() && referenceRemoves.wait() && validations.wait() &&
              permissions.wait() && monitoringDeletes.wait());
  let_work_drain();

  // Each completion ran once with three results.
  EXPECT_EQ(find.count(), 1);
  EXPECT_EQ(references.count(), 1);
  EXPECT_EQ(values.count(), 1);
  EXPECT_EQ(writes.count(), 1);
  EXPECT_EQ(calls.count(), 1);
  EXPECT_EQ(contains.count(), 1);
  EXPECT_EQ(viewAdds.count(), 1);
  EXPECT_EQ(creates.count(), 1);
  EXPECT_EQ(deletes.count(), 1);
  EXPECT_EQ(referenceAdds.count(), 1);
  EXPECT_EQ(referenceRemoves.count(), 1);
  EXPECT_EQ(validations.count(), 1);
  EXPECT_EQ(permissions.count(), 1);
  EXPECT_EQ(monitoringCreates.count(), 1);
  EXPECT_EQ(monitoringModifies.count(), 1);
  EXPECT_EQ(monitoringDeletes.count(), 1);
  EXPECT_EQ(references.get<0>().items.size(), 3u);
  EXPECT_EQ(writes.get<0>().items.size(), 3u);
  EXPECT_EQ(viewAdds.get<0>().items.size(), 3u);
  EXPECT_EQ(creates.get<0>().items.size(), 3u);
  EXPECT_EQ(deletes.get<0>().items.size(), 3u);
  EXPECT_EQ(referenceAdds.get<0>().items.size(), 3u);
  EXPECT_EQ(referenceRemoves.get<0>().items.size(), 3u);
  EXPECT_EQ(validations.get<0>().items.size(), 3u);
  EXPECT_EQ(permissions.get<0>().items.size(), 3u);
  EXPECT_EQ(monitoringCreates.get<0>().items.size(), 3u);
  EXPECT_EQ(monitoringModifies.get<0>().items.size(), 3u);
  EXPECT_EQ(monitoringDeletes.get<0>().items.size(), 3u);

  // Each result sits at its item's index.
  const auto& valueItems = values.get<0>().items;
  ASSERT_EQ(valueItems.size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    ASSERT_TRUE(valueItems[i].is_good()) << i << ": " << to_string(valueItems[i].status_code());
    EXPECT_EQ(valueItems[i].value().value().as<int32_t>(), static_cast<int32_t>(i + 1));
  }
  const auto& callResults = calls.get<0>().items;
  ASSERT_EQ(callResults.size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(first_output(callResults[i]), std::optional<int32_t>{static_cast<int32_t>(i + 1)}) << i;
  }
  const auto& membership = contains.get<0>().items;
  ASSERT_EQ(membership.size(), 3u);
  ASSERT_TRUE(membership[0].is_good() && membership[1].is_good() && membership[2].is_good());
  EXPECT_TRUE(membership[0].value());
  EXPECT_FALSE(membership[1].value());
  EXPECT_TRUE(membership[2].value());
  // The other members' results follow their items: the failing item fails alone.
  const auto& writeResults = writes.get<0>().items;
  EXPECT_TRUE(writeResults.size() == 3 && writeResults[0].is_good() && writeResults[1].is_bad() &&
              writeResults[2].is_good());
  const auto& createResults = creates.get<0>().items;
  EXPECT_TRUE(createResults.size() == 3 && createResults[0].is_good() && createResults[1].is_bad() &&
              createResults[2].is_good());
  const auto& deleteResults = deletes.get<0>().items;
  EXPECT_TRUE(deleteResults.size() == 3 && deleteResults[0].is_good() && deleteResults[1].is_bad() &&
              deleteResults[2].is_good());
  const auto& addResults = referenceAdds.get<0>().items;
  ASSERT_EQ(addResults.size(), 3u);
  EXPECT_TRUE(addResults[0].is_good()) << to_string(addResults[0].status_code());
  EXPECT_EQ(addResults[1].status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(addResults[1].status_code());
  EXPECT_TRUE(addResults[2].is_good()) << to_string(addResults[2].status_code());
  const auto& monitoringResults = monitoringCreates.get<0>().items;
  EXPECT_TRUE(monitoringResults.size() == 3 && monitoringResults[0].is_good() &&
              monitoringResults[1].is_bad() && monitoringResults[2].is_good());
}

// NR-1 rule 4: while the Node for a NodeId is held, every lookup of that NodeId answers that Node.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-ONE-NODE-PER-NODEID, scope=function)
TEST_P(NamespaceConformance, RepeatedLookupsWhileANodeIsHeldReturnThatNode)
{
  auto held = hold(mVariable);
  ASSERT_TRUE(held);

  auto again = lookup({mVariable, mObject});
  ASSERT_EQ(again.size(), 2u);
  ASSERT_TRUE(again[0].is_good()) << to_string(again[0].status_code());
  EXPECT_EQ(again[0].value().get(), held.get());

  const auto immediate = ns().find_node(mVariable, std::nullopt);
  if (immediate.has_value())
  {
    ASSERT_TRUE(immediate->is_good()) << to_string(immediate->status_code());
    EXPECT_EQ(immediate->value().get(), held.get());
  }
}

// NR-1 rule 3 and Part 4 section 7.39.2: an unknown NodeId fails its own item with Bad_NodeIdUnknown,
// whatever its identifier form.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-UNKNOWN-NODEID-NODEID-UNKNOWN, scope=function)
TEST_P(NamespaceConformance, ALookupOfAnUnknownNodeIdAnswersNodeIdUnknown)
{
  auto items = lookup({mObject,
    NodeId{mIndex, uint32_t{987654}},
    NodeId{mIndex, "NoSuchNode"},
    NodeId{mIndex, Guid::parse("72962B91-FA75-4AE6-8D28-B404DC7DAF63")},
    NodeId{mIndex, ByteString({0xDE, 0xAD, 0xBE, 0xEF})},
    mVariable});
  ASSERT_EQ(items.size(), 6u);
  ASSERT_TRUE(items[0].is_good()) << to_string(items[0].status_code());
  ASSERT_TRUE(items[5].is_good()) << to_string(items[5].status_code());
  const NodeDescription first = items[0].value()->attributes();
  const NodeDescription last = items[5].value()->attributes();
  EXPECT_EQ(first.node_id(), mObject);
  EXPECT_EQ(last.node_id(), mVariable);
  for (size_t i = 1; i <= 4; ++i)
  {
    EXPECT_TRUE(items[i].is_bad()) << i;
    EXPECT_EQ(items[i].status_code().as_status(), Status::BadNodeIdUnknown)
      << i << ": " << to_string(items[i].status_code());
  }
}

// NR-4: enumeration follows creation and deletion, or the namespace does not offer it at all.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-ENUMERATION-FOLLOWS-CREATE-AND-DELETE, scope=function)
TEST_P(NamespaceConformance, EnumerationFollowsCreationAndDeletion)
{
  if (!GetParam().offersCreation)
  {
    GTEST_SKIP() << GetParam().name << " does not offer Node creation";
  }
  auto enumerate = [this]
  {
    Completion<Result<std::vector<NodeId>>> listed;
    ns().enumerate_nodes_async(mRequest, listed.callback());
    EXPECT_TRUE(listed.wait());
    return listed.count() > 0 ? listed.get<0>() : Result<std::vector<NodeId>>{StatusCode{Status::BadTimeout}};
  };
  auto lists = [](const std::vector<NodeId>& nodeIds, const NodeId& nodeId)
  {
    return std::find(nodeIds.begin(), nodeIds.end(), nodeId) != nodeIds.end();
  };
  const NodeId x{mIndex, "X"};

  const auto before = enumerate();
  auto created = create_nodes({object_creation(x, "X")});
  const auto afterCreate = enumerate();
  auto deleted = delete_nodes({x});
  const auto afterDelete = enumerate();

  if (before.is_bad() && before.status_code().as_status() == Status::BadNotSupported)
  {
    RecordProperty("alternative", "enumeration not offered");
    EXPECT_EQ(afterCreate.status_code().as_status(), Status::BadNotSupported);
    EXPECT_EQ(afterDelete.status_code().as_status(), Status::BadNotSupported);
    return;
  }
  ASSERT_TRUE(before.is_good()) << to_string(before.status_code());
  EXPECT_TRUE(lists(before.value(), mObject));
  EXPECT_TRUE(lists(before.value(), mVariable));
  EXPECT_TRUE(lists(before.value(), mMethod));
  EXPECT_FALSE(lists(before.value(), x));
  ASSERT_EQ(created.items.size(), 1u);
  ASSERT_TRUE(created.items[0].is_good()) << to_string(created.items[0].status_code());
  ASSERT_TRUE(afterCreate.is_good()) << to_string(afterCreate.status_code());
  EXPECT_TRUE(lists(afterCreate.value(), x));
  ASSERT_EQ(deleted.items.size(), 1u);
  ASSERT_TRUE(deleted.items[0].is_good()) << to_string(deleted.items[0].status_code());
  ASSERT_TRUE(afterDelete.is_good()) << to_string(afterDelete.status_code());
  EXPECT_FALSE(lists(afterDelete.value(), x));
}

// NR-1 rule 1: the address space's lookup reaches the object the namespace's own lookup hands out.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-05-ADDRESS-SPACE-LOOKUP-REACHES-THE-NAMESPACES-NODE, scope=function)
TEST_P(NamespaceConformance, TheAddressSpacesLookupReturnsTheNamespacesNode)
{
  auto accessor = address_space_node(mVariable);
  ASSERT_TRUE(accessor.has_value());
  auto held = hold(mVariable);
  ASSERT_TRUE(held);
  EXPECT_EQ(&**accessor, held.get());
}

// === COMP-ADDRSP-NAMESPACE-INTERFACE-06: References and Values read ====================================

// NR-9: References read with maxReferences come in pages whose union is the unpaged read.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-06-REFERENCES-PAGED, scope=function)
TEST_P(NamespaceConformance, ReferencesArePagedByMaxReferencesAndResumeToken)
{
  auto object = hold(mObject);
  ASSERT_TRUE(object);

  const auto unpaged = read_references(*object, mObject, BrowseDirection::Both);
  ASSERT_TRUE(unpaged.is_good()) << to_string(unpaged.status_code());
  EXPECT_TRUE(unpaged.value().resumeToken.empty());
  const auto all = to_vector(unpaged.value().references);
  ASSERT_GE(all.size(), 5u);

  std::vector<Reference> paged;
  ByteString token;
  for (int page = 0; page < 16; ++page)
  {
    const auto answer = read_references(*object, mObject, BrowseDirection::Both, {}, 2, token);
    ASSERT_TRUE(answer.is_good()) << "page " << page << ": " << to_string(answer.status_code());
    const auto references = to_vector(answer.value().references);
    EXPECT_LE(references.size(), 2u) << "page " << page;
    paged.insert(paged.end(), references.begin(), references.end());
    token = answer.value().resumeToken;
    if (token.empty())
    {
      break;
    }
  }
  EXPECT_TRUE(token.empty()) << "the pages did not end";
  EXPECT_EQ(paged.size(), all.size());
  for (const auto& reference : all)
  {
    EXPECT_EQ(std::count(paged.begin(), paged.end(), reference), 1);
  }

  const auto firstPage = read_references(*object, mObject, BrowseDirection::Both, {}, 2);
  ASSERT_TRUE(firstPage.is_good()) << to_string(firstPage.status_code());
  ASSERT_FALSE(firstPage.value().resumeToken.empty());
  EXPECT_NO_THROW(ns().release_resume_token(firstPage.value().resumeToken));
  const auto afterRelease = read_references(*object, mObject, BrowseDirection::Both);
  ASSERT_TRUE(afterRelease.is_good()) << to_string(afterRelease.status_code());
  EXPECT_EQ(to_vector(afterRelease.value().references).size(), all.size());
}

// NR-61: a hint leaves a Reference out only when its type is neither a hinted type nor a subtype of one.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-06-HINT-KEEPS-SUBTYPES, scope=function)
TEST_P(NamespaceConformance, AHintedReadKeepsReferencesOfASubtype)
{
  const NodeId hinted{mIndex, "Hinted"};
  (void)mAddressSpace->create_sync<ObjectAccessor>(hinted, NodeClass::Object, names("Hinted"));
  link(hinted, hasComponent, mScalar1);
  link(hinted, hasOrderedComponent, mScalar2);
  link(hinted, hasProperty, mScalar3);
  auto node = hold(hinted);
  ASSERT_TRUE(node);

  const auto withHint = read_references(*node, hinted, BrowseDirection::Forward, {hasComponent});
  ASSERT_TRUE(withHint.is_good()) << to_string(withHint.status_code());
  EXPECT_TRUE(holds_reference(withHint.value().references, hasComponent, mScalar1, true));
  EXPECT_TRUE(holds_reference(withHint.value().references, hasOrderedComponent, mScalar2, true));

  const auto withoutHint = read_references(*node, hinted, BrowseDirection::Forward);
  ASSERT_TRUE(withoutHint.is_good()) << to_string(withoutHint.status_code());
  EXPECT_TRUE(holds_reference(withoutHint.value().references, hasComponent, mScalar1, true));
  EXPECT_TRUE(holds_reference(withoutHint.value().references, hasOrderedComponent, mScalar2, true));
  EXPECT_TRUE(holds_reference(withoutHint.value().references, hasProperty, mScalar3, true));
}

// Part 4 section 7.27: a ranged read returns only the range, what lies within the value past its upper
// bound, and Bad_IndexRangeNoData when the range starts past the value.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-06-RANGED-VALUE-READ, scope=function)
TEST_P(NamespaceConformance, ARangedValueReadReturnsOnlyTheRange)
{
  auto node = hold(mVariable);
  ASSERT_TRUE(node);
  const std::vector<ReadValueId> reads{
    value_of(mVariable, "1:2"), value_of(mVariable, "4:9"), value_of(mVariable, "7:8"), value_of(mVariable)};
  const std::vector<ValueReadItem> items{
    {*node, reads[0]}, {*node, reads[1]}, {*node, reads[2]}, {*node, reads[3]}};
  const auto batch = read_values(items);
  ASSERT_EQ(batch.items.size(), 4u);
  EXPECT_EQ(int32_array(batch.items[0]), (std::optional<Array<int32_t>>{Array<int32_t>{20, 30}}))
    << to_string(batch.items[0].status_code());
  EXPECT_EQ(int32_array(batch.items[1]), (std::optional<Array<int32_t>>{Array<int32_t>{50}}))
    << to_string(batch.items[1].status_code());
  EXPECT_TRUE(batch.items[2].is_bad());
  EXPECT_EQ(batch.items[2].status_code().as_status(), Status::BadIndexRangeNoData)
    << to_string(batch.items[2].status_code());
  EXPECT_EQ(int32_array(batch.items[3]), std::optional<Array<int32_t>>{initialArray})
    << to_string(batch.items[3].status_code());
}

// NR-1 rule 5 and NR-43: an item carrying a Node this namespace did not return fails alone.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-06-FOREIGN-NODE-FAILS-ITS-ITEM, scope=function)
TEST_P(NamespaceConformance, AForeignNodeFailsOnlyItsItem)
{
  // Another namespace with a Node class of its own, holding a Variable of the same identifier.
  auto other = default_ns::Namespace::create("urn:test:namespace-conformance:other", mPool.get_executor());
  auto otherIndex = mAddressSpace->try_add_namespace_sync(other);
  ASSERT_TRUE(otherIndex.is_good()) << to_string(otherIndex.status_code());
  const NodeId otherVariable{otherIndex.value(), "Variable"};
  (void)mAddressSpace->create_sync<VariableAccessor>(otherVariable, NodeClass::Variable, names("Variable"));
  Completion<BatchResult<NodeResult>> otherLookup;
  const std::vector<NodeId> otherIds{otherVariable};
  static_cast<Namespace&>(*other).find_nodes_async(mRequest, otherIds, std::nullopt, otherLookup.callback());
  ASSERT_TRUE(otherLookup.wait());
  ASSERT_EQ(otherLookup.get<0>().items.size(), 1u);
  ASSERT_TRUE(otherLookup.get<0>().items[0].is_good());
  auto foreign = otherLookup.get<0>().items[0].value();

  auto own = hold(mVariable);
  auto object = hold(mObject);
  ASSERT_TRUE(own && object);

  auto expectForeign = [this](const auto& result, const char* member)
  {
    EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument)
      << member << ": " << to_string(result.status_code());
    const auto detail = result.shared_detail();
    ASSERT_NE(detail, nullptr) << member;
    EXPECT_EQ(detail->code, "ForeignNode") << member;
    bool namesNodeId = false;
    for (const auto& fact : detail->context)
    {
      namesNodeId =
        namesNodeId || (fact.key == ContextKeys::nodeId.value() && fact.value == to_string(mVariable));
    }
    EXPECT_TRUE(namesNodeId) << member << ": the detail does not name " << to_string(mVariable);
  };

  const ReadValueId read = value_of(mVariable);
  const std::vector<ValueReadItem> readItems{{*own, read}, {*foreign, read}, {*object, read}};
  const auto reads = read_values(readItems);
  ASSERT_EQ(reads.items.size(), 3u);
  EXPECT_EQ(int32_array(reads.items[0]), std::optional<Array<int32_t>>{initialArray});
  expectForeign(reads.items[1], "read_values_async");
  expectForeign(reads.items[2], "read_values_async");

  const WriteValue changed = value_write(mVariable, Variant{Array<int32_t>{1, 2, 3, 4, 5}});
  const std::vector<ValueWriteItem> foreignWrites{{*foreign, changed}, {*object, changed}};
  const WriteValue unchanged = value_write(mVariable, Variant{initialArray});
  const std::vector<ValueWriteItem> writeItems{{*own, unchanged}, foreignWrites[0], foreignWrites[1]};
  const auto writes = write(writeItems);
  ASSERT_EQ(writes.first.items.size(), 3u);
  EXPECT_TRUE(writes.first.items[0].is_good()) << to_string(writes.first.items[0].status_code());
  expectForeign(writes.first.items[1], "write_async");
  expectForeign(writes.first.items[2], "write_async");
  EXPECT_EQ(int32_array(read_value(*own, mVariable)), std::optional<Array<int32_t>>{initialArray});
}

// NR-44 rule 5: an item carrying a Node the namespace has deleted fails alone with Bad_NodeIdUnknown.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-06-DELETED-NODE-IN-AN-ITEM, scope=function)
TEST_P(NamespaceConformance, ADeletedNodeInAnItemAnswersNodeIdUnknown)
{
  auto variable = hold(mVariable);
  auto v2 = hold(mScalar2);
  ASSERT_TRUE(variable && v2);
  const auto deleted = delete_nodes({mScalar2});
  ASSERT_EQ(deleted.items.size(), 1u);
  ASSERT_TRUE(deleted.items[0].is_good()) << to_string(deleted.items[0].status_code());

  auto expectUnknown = [](const auto& result, const char* member)
  {
    EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown)
      << member << ": " << to_string(result.status_code());
    const auto detail = result.shared_detail();
    EXPECT_TRUE(detail == nullptr || detail->code != "ForeignNode") << member;
  };

  const std::vector<ReadValueId> reads{value_of(mVariable), value_of(mScalar2)};
  const std::vector<ValueReadItem> readItems{{*variable, reads[0]}, {*v2, reads[1]}};
  const auto readAnswer = read_values(readItems);
  ASSERT_EQ(readAnswer.items.size(), 2u);
  EXPECT_EQ(int32_array(readAnswer.items[0]), std::optional<Array<int32_t>>{initialArray});
  expectUnknown(readAnswer.items[1], "read_values_async");

  const std::vector<WriteValue> writeValues{
    display_name_write(mVariable, "Renamed"), display_name_write(mScalar2, "Renamed")};
  const std::vector<ValueWriteItem> writeItems{{*variable, writeValues[0]}, {*v2, writeValues[1]}};
  const auto writeAnswer = write(writeItems);
  ASSERT_EQ(writeAnswer.first.items.size(), 2u);
  EXPECT_TRUE(writeAnswer.first.items[0].is_good()) << to_string(writeAnswer.first.items[0].status_code());
  expectUnknown(writeAnswer.first.items[1], "write_async");

  const std::vector<ReferenceQuery> queries{ReferenceQuery{*variable, mVariable, BrowseDirection::Both},
    ReferenceQuery{*v2, mScalar2, BrowseDirection::Both}};
  Completion<BatchResult<NodeReferencesResult>> references;
  ns().read_references_async(mRequest, queries, references.callback());
  ASSERT_TRUE(references.wait());
  const auto& referenceAnswer = references.get<0>().items;
  ASSERT_EQ(referenceAnswer.size(), 2u);
  EXPECT_TRUE(referenceAnswer[0].is_good()) << to_string(referenceAnswer[0].status_code());
  expectUnknown(referenceAnswer[1], "read_references_async");
}

// === COMP-ADDRSP-NAMESPACE-INTERFACE-07: writes, References, creation, calls, Views, monitoring ========

// NR-1 rule 2 and NR-3: a non-Value write is applied to the Node handed out before the completion runs.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-NON-VALUE-WRITE-SEEN-AT-COMPLETION, scope=function)
TEST_P(NamespaceConformance, ANonValueWriteIsSeenByAttributesWhenTheWriteCompletes)
{
  auto node = hold(mVariable);
  ASSERT_TRUE(node);
  const WriteValue rename = display_name_write(mVariable, "Renamed");
  const std::vector<ValueWriteItem> items{{*node, rename}};
  auto seen = std::make_shared<std::promise<std::pair<StatusCode, String>>>();
  auto answered = seen->get_future();
  ns().write_async(mRequest,
    nullptr,
    items,
    [node, seen](BatchResult<VoidResult> result, std::vector<VersionedNode>)
    {
      const NodeDescription description = node->attributes();
      const StatusCode status =
        result.items.size() == 1 ? result.items[0].status_code() : StatusCode{Status::BadInternalError};
      seen->set_value({status, description.display_name().text()});
    });
  ASSERT_EQ(answered.wait_for(::ua::test_utils::default_poll_budget()), std::future_status::ready);
  const auto [status, inCompletion] = answered.get();
  EXPECT_TRUE(status.is_good()) << to_string(status);
  EXPECT_EQ(inCompletion, String{"Renamed"});

  auto again = hold(mVariable);
  ASSERT_TRUE(again);
  const NodeDescription afterwards = again->attributes();
  EXPECT_EQ(afterwards.display_name().text(), String{"Renamed"});
}

// Part 4 section 7.27: a ranged write changes only the range, and a range past the value is refused.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-RANGED-VALUE-WRITE, scope=function)
TEST_P(NamespaceConformance, ARangedValueWriteWritesOnlyTheRange)
{
  auto node = hold(mVariable);
  ASSERT_TRUE(node);
  const WriteValue inRange = value_write(mVariable, Variant{Array<int32_t>{7, 8}}, "1:2");
  const auto first = write(std::vector<ValueWriteItem>{{*node, inRange}});
  ASSERT_EQ(first.first.items.size(), 1u);
  const auto afterFirst = int32_array(read_value(*node, mVariable));

  const WriteValue pastEnd = value_write(mVariable, Variant{Array<int32_t>{1, 2}}, "7:8");
  const auto second = write(std::vector<ValueWriteItem>{{*node, pastEnd}});
  ASSERT_EQ(second.first.items.size(), 1u);
  const auto afterSecond = int32_array(read_value(*node, mVariable));

  if (first.first.items[0].status_code().as_status() == Status::BadWriteNotSupported)
  {
    RecordProperty("alternative", "ranged writes not supported");
    EXPECT_EQ(second.first.items[0].status_code().as_status(), Status::BadWriteNotSupported);
    EXPECT_EQ(afterSecond, std::optional<Array<int32_t>>{initialArray});
    return;
  }
  EXPECT_TRUE(first.first.items[0].is_good()) << to_string(first.first.items[0].status_code());
  EXPECT_EQ(afterFirst, (std::optional<Array<int32_t>>{Array<int32_t>{10, 7, 8, 40, 50}}));
  EXPECT_EQ(second.first.items[0].status_code().as_status(), Status::BadIndexRangeNoData)
    << to_string(second.first.items[0].status_code());
  EXPECT_EQ(afterSecond, (std::optional<Array<int32_t>>{Array<int32_t>{10, 7, 8, 40, 50}}));
}

// Part 3 section 8 (OptionSet): a write changes only the bits its ValidBits select.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-OPTIONSET-VALIDBITS-WRITE, scope=function)
TEST_P(NamespaceConformance, AnOptionSetWriteAppliesOnlyTheValidBits)
{
  // An OptionSet DataType of four bits, and a Variable of it.
  const NodeId optionsType{mIndex, "OptionsType"};
  EnumDefinition definition;
  for (int64_t bit = 0; bit < 4; ++bit)
  {
    EnumField field;
    field.name() = String{"Bit" + std::to_string(bit)};
    field.value() = bit;
    definition.fields().payload().push_back(std::move(field));
  }
  auto dataType =
    mAddressSpace->create_sync<DataTypeAccessor>(optionsType, NodeClass::DataType, names("OptionsType"));
  dataType.set_data_type_definition(std::make_shared<EnumDefinition>(definition));
  const auto descriptor = std::make_shared<DynamicEnumTypeDescriptor>(
    String{"OptionsType"}, ExpandedNodeId{optionsType}, true, definition);
  const NodeId options{mIndex, "Options"};
  DynamicOptionSet initial{descriptor};
  initial.value() = ByteString({0x05});
  initial.valid_bits() = ByteString({0x0F});
  create_variable(options, "Options", optionsType, ValueRank::scalar, Variant{std::move(initial)});
  auto node = hold(options);
  ASSERT_TRUE(node);

  DynamicOptionSet written{descriptor};
  written.value() = ByteString({0x0A});
  written.valid_bits() = ByteString({0x03});
  const WriteValue writeRequest = value_write(options, Variant{std::move(written)});
  const auto answer = write(std::vector<ValueWriteItem>{{*node, writeRequest}});
  ASSERT_EQ(answer.first.items.size(), 1u);
  EXPECT_TRUE(answer.first.items[0].is_good()) << to_string(answer.first.items[0].status_code());

  const auto read = read_value(*node, options);
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  const auto* stored = read.value().value().try_as<OptionSet>();
  ASSERT_NE(stored, nullptr);
  EXPECT_EQ(stored->value(), ByteString({0x06}));
}

// NR-30 and Part 3 section 4.3.4: a half the source already holds, by the same type or a subtype, is
// refused and stores nothing.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-DUPLICATE-REFERENCE-REFUSED, scope=function)
TEST_P(NamespaceConformance, AddingAReferenceAlreadyHeldIsDuplicateReferenceNotAllowed)
{
  const ReferenceChange component{mObject, hasComponent, ExpandedNodeId{mVariable}};
  const ReferenceChange orderedComponent{mObject, hasOrderedComponent, ExpandedNodeId{mVariable}};
  const auto first = add_references({component});
  const auto second = add_references({component});
  const auto third = add_references({orderedComponent});
  ASSERT_EQ(first.first.items.size(), 1u);
  ASSERT_EQ(second.first.items.size(), 1u);
  ASSERT_EQ(third.first.items.size(), 1u);
  EXPECT_TRUE(first.first.items[0].is_good()) << to_string(first.first.items[0].status_code());
  EXPECT_EQ(second.first.items[0].status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(second.first.items[0].status_code());
  EXPECT_EQ(third.first.items[0].status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(third.first.items[0].status_code());

  const auto references = references_of(mObject, BrowseDirection::Forward);
  int toVariable = 0;
  for (const auto& reference : references)
  {
    if (reference.target_id() == ExpandedNodeId{mVariable} &&
        (reference.type_id() == hasComponent || reference.type_id() == hasOrderedComponent))
    {
      ++toVariable;
    }
  }
  EXPECT_EQ(toVariable, 1);
  EXPECT_TRUE(holds_reference(references, hasComponent, mVariable, true));
}

// NR-30 rule 3 and NR-63: a change stores or removes only the half it names; both_halves names both.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-A-CHANGE-STORES-ONLY-ITS-HALF, scope=function)
TEST_P(NamespaceConformance, AReferenceChangeStoresOnlyTheHalfItNames)
{
  const auto oneHalf = add_references({ReferenceChange{mObject, organizes, ExpandedNodeId{mMethod}}});
  ASSERT_EQ(oneHalf.first.items.size(), 1u);
  EXPECT_TRUE(oneHalf.first.items[0].is_good()) << to_string(oneHalf.first.items[0].status_code());
  EXPECT_TRUE(holds_reference(references_of(mObject, BrowseDirection::Forward), organizes, mMethod, true));
  EXPECT_FALSE(holds_reference(references_of(mMethod, BrowseDirection::Inverse), organizes, mObject, false));

  const auto pair = ReferenceChange::both_halves(mObject, organizes, mVariable);
  const auto bothHalves = add_references({pair[0], pair[1]});
  ASSERT_EQ(bothHalves.first.items.size(), 2u);
  EXPECT_TRUE(bothHalves.first.items[0].is_good()) << to_string(bothHalves.first.items[0].status_code());
  EXPECT_TRUE(bothHalves.first.items[1].is_good()) << to_string(bothHalves.first.items[1].status_code());
  EXPECT_TRUE(holds_reference(references_of(mObject, BrowseDirection::Forward), organizes, mVariable, true));
  EXPECT_TRUE(holds_reference(references_of(mVariable, BrowseDirection::Inverse), organizes, mObject, false));

  const auto removal = remove_references({ReferenceChange{mObject, organizes, ExpandedNodeId{mVariable}}});
  ASSERT_EQ(removal.items.size(), 1u);
  EXPECT_TRUE(removal.items[0].is_good()) << to_string(removal.items[0].status_code());
  EXPECT_FALSE(holds_reference(references_of(mObject, BrowseDirection::Forward), organizes, mVariable, true));
  EXPECT_TRUE(holds_reference(references_of(mVariable, BrowseDirection::Inverse), organizes, mObject, false));
}

// NR-15 and NR-44: a created Node is found with its attributes; deleting it removes it and this
// namespace's References to it.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-CREATE-THEN-DELETE, scope=function)
TEST_P(NamespaceConformance, ACreatedNodeIsFoundAndADeletedNodeAndTheReferencesToItAreGone)
{
  if (!GetParam().offersCreation)
  {
    GTEST_SKIP() << GetParam().name << " does not offer Node creation";
  }
  const NodeId x{mIndex, "X"};
  const auto created = create_nodes({NodeCreation{x,
    NodeClass::Object,
    InitialAttributes{{AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{mIndex, "X"})},
      {AttributeId::DisplayName,
        attribute_wire::display_name(LocalizedText{LocaleId{"en"}, String{"Created"}})}}}});
  ASSERT_EQ(created.items.size(), 1u);
  ASSERT_TRUE(created.items[0].is_good()) << to_string(created.items[0].status_code());
  const auto createdNode = created.items[0].value();
  ASSERT_NE(createdNode, nullptr);
  const NodeDescription description = createdNode->attributes();
  EXPECT_EQ(description.node_id(), x);
  EXPECT_EQ(description.node_class(), NodeClass::Object);
  EXPECT_EQ(description.browse_name().name(), String{"X"});
  EXPECT_EQ(description.display_name().text(), String{"Created"});
  auto found = lookup({x});
  ASSERT_EQ(found.size(), 1u);
  ASSERT_TRUE(found[0].is_good()) << to_string(found[0].status_code());
  EXPECT_EQ(found[0].value().get(), createdNode.get());

  const auto linked = add_references({ReferenceChange{mObject, organizes, ExpandedNodeId{x}}});
  ASSERT_EQ(linked.first.items.size(), 1u);
  ASSERT_TRUE(linked.first.items[0].is_good()) << to_string(linked.first.items[0].status_code());

  const auto deleted = delete_nodes({x});
  ASSERT_EQ(deleted.items.size(), 1u);
  EXPECT_TRUE(deleted.items[0].is_good()) << to_string(deleted.items[0].status_code());
  auto gone = lookup({x});
  ASSERT_EQ(gone.size(), 1u);
  EXPECT_EQ(gone[0].status_code().as_status(), Status::BadNodeIdUnknown) << to_string(gone[0].status_code());
  for (const auto& reference : references_of(mObject, BrowseDirection::Both))
  {
    EXPECT_NE(reference.target_id(), ExpandedNodeId{x});
  }
}

// NR-42 A-7 and NR-68: a held Method's call is answered with its handler's result, a Bad one included;
// a Method the namespace does not hold is declined.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-CALL-TAKEN-OR-DECLINED, scope=function)
TEST_P(NamespaceConformance, ACallIsTakenWhenTheMethodIsHeldAndDeclinedOtherwise)
{
  auto object = hold(mObject);
  auto method = hold(mMethod);
  ASSERT_TRUE(object && method);
  // A Method another namespace holds; the test's namespace 0 holds no Methods.
  auto other =
    default_ns::Namespace::create("urn:test:namespace-conformance:other-method", mPool.get_executor());
  auto otherIndex = mAddressSpace->try_add_namespace_sync(other);
  ASSERT_TRUE(otherIndex.is_good()) << to_string(otherIndex.status_code());
  const NodeId foreignMethodId{otherIndex.value(), "Method"};
  (void)mAddressSpace->create_sync<MethodAccessor>(foreignMethodId, NodeClass::Method, names("Method"));
  auto foreignMethod = address_space_node(foreignMethodId);
  ASSERT_TRUE(foreignMethod.has_value());

  const std::vector<CallMethodRequest> requests{
    call_of(mObject, mMethod, 1), call_of(mObject, foreignMethodId, 1), call_of(mObject, mMethod, 0)};
  const std::vector<CallItem> items{{*object, *method, requests[0], nullptr},
    {*object, **foreignMethod, requests[1], nullptr},
    {*object, *method, requests[2], nullptr}};
  Completion<BatchResult<std::optional<CallResult>>> calls;
  ns().call_async(mRequest, nullptr, items, calls.callback());
  ASSERT_TRUE(calls.wait());
  const auto& results = calls.get<0>().items;
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(first_output(results[0]), std::optional<int32_t>{1});
  EXPECT_FALSE(results[1].has_value());
  ASSERT_TRUE(results[2].has_value());
  EXPECT_EQ(results[2]->status_code().as_status(), Status::BadInvalidArgument)
    << to_string(results[2]->status_code());
}

// NR-42 and Part 3 section 5.4: a NodeId added to a View is then a member, and another is not.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-VIEW-MEMBERSHIP-FOLLOWS-ADD, scope=function)
TEST_P(NamespaceConformance, ANodeAddedToAViewIsThenContainedInIt)
{
  if (!GetParam().offersViews)
  {
    GTEST_SKIP() << GetParam().name << " does not offer Views";
  }
  const auto before = view_contains({ExpandedNodeId{mVariable}, ExpandedNodeId{mMethod}});
  ASSERT_EQ(before.items.size(), 2u);
  ASSERT_TRUE(before.items[0].is_good()) << to_string(before.items[0].status_code());
  ASSERT_TRUE(before.items[1].is_good()) << to_string(before.items[1].status_code());
  EXPECT_FALSE(before.items[0].value());
  EXPECT_FALSE(before.items[1].value());

  const auto added = add_to_view({mVariable});
  ASSERT_EQ(added.first.items.size(), 1u);
  if (added.first.items[0].status_code().as_status() == Status::BadNotSupported)
  {
    RecordProperty("alternative", "adding to a View not offered");
    return;
  }
  EXPECT_TRUE(added.first.items[0].is_good()) << to_string(added.first.items[0].status_code());

  const auto after = view_contains({ExpandedNodeId{mVariable}, ExpandedNodeId{mMethod}});
  ASSERT_EQ(after.items.size(), 2u);
  ASSERT_TRUE(after.items[0].is_good()) << to_string(after.items[0].status_code());
  ASSERT_TRUE(after.items[1].is_good()) << to_string(after.items[1].status_code());
  EXPECT_TRUE(after.items[0].value());
  EXPECT_FALSE(after.items[1].value());
}

// NR-42 A-10: a monitoring handle delivers samples until its delete answers, and none after.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-MONITORING-RELEASED-ON-DELETE, scope=function)
TEST_P(NamespaceConformance, MonitoringDeliversUntilItsHandleIsDeleted)
{
  auto node = hold(mVariable);
  ASSERT_TRUE(node);
  auto sink = std::make_shared<RecordingSink>();
  MonitoringCreateItem item;
  item.nodeId = mVariable;
  item.node = node;
  item.monitoredItemId = 1;
  item.sink = sink;
  Completion<BatchResult<MonitoringCreateItemResult>> created;
  ns().create_monitoring_async(
    mRequest, nullptr, std::vector<MonitoringCreateItem>{item}, created.callback());
  ASSERT_TRUE(created.wait());
  ASSERT_EQ(created.get<0>().items.size(), 1u);
  ASSERT_TRUE(created.get<0>().items[0].is_good()) << to_string(created.get<0>().items[0].status_code());
  const MonitoringHandle handle = created.get<0>().items[0].value().handle;
  EXPECT_NE(handle, 0u);

  const Array<int32_t> firstValue{1, 2, 3, 4, 5};
  const WriteValue firstWrite = value_write(mVariable, Variant{firstValue});
  const auto written = write(std::vector<ValueWriteItem>{{*node, firstWrite}});
  ASSERT_EQ(written.first.items.size(), 1u);
  ASSERT_TRUE(written.first.items[0].is_good()) << to_string(written.first.items[0].status_code());
  EXPECT_TRUE(sink->wait_for(firstValue));

  Completion<BatchResult<MonitoringModifyItemResult>> modified;
  ns().modify_monitoring_async(mRequest,
    std::vector<MonitoringModifyItem>{MonitoringModifyItem{handle, Duration{0}, 1}},
    modified.callback());
  ASSERT_TRUE(modified.wait());
  ASSERT_EQ(modified.get<0>().items.size(), 1u);
  EXPECT_TRUE(modified.get<0>().items[0].is_good()) << to_string(modified.get<0>().items[0].status_code());

  Completion<BatchResult<VoidResult>> deleted;
  ns().delete_monitoring_async(mRequest, std::vector<MonitoringHandle>{handle}, deleted.callback());
  ASSERT_TRUE(deleted.wait());
  ASSERT_EQ(deleted.get<0>().items.size(), 1u);
  EXPECT_TRUE(deleted.get<0>().items[0].is_good()) << to_string(deleted.get<0>().items[0].status_code());

  const Array<int32_t> secondValue{6, 7, 8, 9, 10};
  const WriteValue secondWrite = value_write(mVariable, Variant{secondValue});
  const auto rewritten = write(std::vector<ValueWriteItem>{{*node, secondWrite}});
  ASSERT_EQ(rewritten.first.items.size(), 1u);
  ASSERT_TRUE(rewritten.first.items[0].is_good()) << to_string(rewritten.first.items[0].status_code());
  let_work_drain();
  EXPECT_FALSE(sink->holds(secondValue));
}

// NR-36 and NR-63: a Reference added to a versioned Node advances its NodeVersion and reports it; one
// added to a Node created in the operation reports it unadvanced; an unversioned Node is not reported.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-VERSIONED-NODE-ADVANCED-AND-REPORTED, scope=function)
TEST_P(NamespaceConformance, AVersionedNodeIsAdvancedAndReported)
{
  const NodeId nodeVersion{mIndex, "ObjectNodeVersion"};
  create_variable(nodeVersion,
    "NodeVersion",
    stringDataType,
    ValueRank::scalar,
    Variant{String{"1"}},
    QualifiedName{0, "NodeVersion"});
  link(mObject, hasProperty, nodeVersion);
  auto version = hold(nodeVersion);
  ASSERT_TRUE(version);
  auto readVersion = [this, &version, &nodeVersion]
  {
    const auto read = read_value(*version, nodeVersion);
    EXPECT_TRUE(read.is_good()) << to_string(read.status_code());
    return read.is_good() ? read.value().value() : Variant{};
  };
  const Variant v1 = readVersion();

  const auto first = add_references({ReferenceChange{mObject, organizes, ExpandedNodeId{mMethod}}});
  ASSERT_EQ(first.first.items.size(), 1u);
  EXPECT_TRUE(first.first.items[0].is_good()) << to_string(first.first.items[0].status_code());
  ASSERT_EQ(first.second.size(), 1u);
  EXPECT_EQ(first.second[0].node, mObject);
  EXPECT_EQ(first.second[0].affectedType, baseObjectType);
  const Variant v2 = readVersion();
  EXPECT_NE(v2, v1);

  ReferenceChange created{mObject, organizes, ExpandedNodeId{mVariable}};
  created.sourceCreated = true;
  const auto second = add_references({created});
  ASSERT_EQ(second.first.items.size(), 1u);
  EXPECT_TRUE(second.first.items[0].is_good()) << to_string(second.first.items[0].status_code());
  ASSERT_EQ(second.second.size(), 1u);
  EXPECT_EQ(second.second[0].node, mObject);
  EXPECT_EQ(second.second[0].affectedType, baseObjectType);
  EXPECT_EQ(readVersion(), v2);

  const auto third = add_references({ReferenceChange{mMethod, organizes, ExpandedNodeId{mVariable}}});
  ASSERT_EQ(third.first.items.size(), 1u);
  EXPECT_TRUE(third.first.items[0].is_good()) << to_string(third.first.items[0].status_code());
  EXPECT_TRUE(third.second.empty());
}

// NR-55 and Part 3 section 5.4 Table 10: a View whose only change is its ViewVersion is not reported.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-VIEW-VERSION-CHANGE-NOT-LISTED, scope=function)
TEST_P(NamespaceConformance, AViewWhoseOnlyChangeIsItsViewVersionIsNotListed)
{
  if (!GetParam().offersViews)
  {
    GTEST_SKIP() << GetParam().name << " does not offer Views";
  }
  const NodeId viewVersion{mIndex, "ViewVersion"};
  create_variable(viewVersion,
    "ViewVersion",
    uint32DataType,
    ValueRank::scalar,
    Variant{uint32_t{1}},
    QualifiedName{0, "ViewVersion"});
  link(mView, hasProperty, viewVersion);

  const auto added = add_to_view({mVariable});
  ASSERT_EQ(added.first.items.size(), 1u);
  EXPECT_TRUE(added.first.items[0].is_good()) << to_string(added.first.items[0].status_code());
  EXPECT_TRUE(added.second.empty());

  const auto contains = view_contains({ExpandedNodeId{mVariable}});
  ASSERT_EQ(contains.items.size(), 1u);
  ASSERT_TRUE(contains.items[0].is_good()) << to_string(contains.items[0].status_code());
  EXPECT_TRUE(contains.items[0].value());
}

// === COMP-ADDRSP-NAMESPACE-INTERFACE-08: shutdown and re-entry ==========================================

// ASD-6: shutdown_async completes exactly once, with a good result, while a Node is held.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-SHUTDOWN-COMPLETES-ONCE, scope=function)
TEST_P(NamespaceConformance, ShutdownCompletesExactlyOnce)
{
  auto held = hold(mVariable);
  EXPECT_TRUE(held);
  Completion<VoidResult> shutdown;
  ns().shutdown_async(shutdown.callback());
  ASSERT_TRUE(shutdown.wait());
  let_work_drain();
  EXPECT_EQ(shutdown.count(), 1);
  EXPECT_TRUE(shutdown.get<0>().is_good()) << to_string(shutdown.get<0>().status_code());
}

// ASD-3: a member called from inside another member's completion completes, without deadlock.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-08-MEMBER-CALLED-FROM-A-COMPLETION, scope=function)
TEST_P(NamespaceConformance, AMemberCalledFromAnotherMembersCompletionCompletes)
{
  struct Chain
  {
    Namespace* space{nullptr};
    RequestInfo request;
    NodeId variable;
    NodeId object;
    std::vector<NodeId> variableIds;
    std::vector<NodeId> objectIds;
    shared_ptr<Node> variableNode;
    ReadValueId read;
    std::vector<ValueReadItem> readItems;
    WriteValue rename;
    std::vector<ValueWriteItem> writeItems;
    std::promise<DataValueResult> readAnswer;
    std::promise<NodeResult> lookupAnswer;
    std::promise<VoidResult> writeAnswer;
  };

  auto chain = std::make_shared<Chain>();
  chain->space = &ns();
  chain->variable = mVariable;
  chain->object = mObject;
  chain->variableIds = {mVariable};
  chain->objectIds = {mObject};
  chain->read = value_of(mVariable);
  chain->rename = display_name_write(mVariable, "Renamed");
  auto readAnswer = chain->readAnswer.get_future();
  auto lookupAnswer = chain->lookupAnswer.get_future();
  auto writeAnswer = chain->writeAnswer.get_future();

  chain->space->find_nodes_async(chain->request,
    chain->variableIds,
    std::nullopt,
    [chain](BatchResult<NodeResult> found)
    {
      if (found.items.size() != 1 || !found.items[0].is_good())
      {
        const StatusCode failed =
          found.items.size() == 1 ? found.items[0].status_code() : StatusCode{Status::BadInternalError};
        chain->readAnswer.set_value(DataValueResult{failed});
        chain->lookupAnswer.set_value(NodeResult{failed});
        chain->writeAnswer.set_value(VoidResult{failed});
        return;
      }
      chain->variableNode = found.items[0].value();
      chain->readItems.push_back(ValueReadItem{*chain->variableNode, chain->read});
      chain->space->read_values_async(chain->request,
        nullptr,
        chain->readItems,
        Duration{0},
        false,
        [chain](BatchResult<DataValueResult> read)
        {
          chain->readAnswer.set_value(
            read.items.size() == 1 ? read.items[0] : DataValueResult{StatusCode{Status::BadInternalError}});
          chain->space->find_nodes_async(chain->request,
            chain->objectIds,
            std::nullopt,
            [chain](BatchResult<NodeResult> inner)
            {
              chain->lookupAnswer.set_value(
                inner.items.size() == 1 ? inner.items[0] : NodeResult{StatusCode{Status::BadInternalError}});
            });
          chain->writeItems.push_back(ValueWriteItem{*chain->variableNode, chain->rename});
          chain->space->write_async(chain->request,
            nullptr,
            chain->writeItems,
            [chain](BatchResult<VoidResult> written, std::vector<VersionedNode>)
            {
              chain->writeAnswer.set_value(written.items.size() == 1
                                             ? written.items[0]
                                             : VoidResult{StatusCode{Status::BadInternalError}});
            });
        });
    });

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  ASSERT_EQ(readAnswer.wait_until(deadline), std::future_status::ready);
  ASSERT_EQ(lookupAnswer.wait_until(deadline), std::future_status::ready);
  ASSERT_EQ(writeAnswer.wait_until(deadline), std::future_status::ready);
  const auto read = readAnswer.get();
  EXPECT_EQ(int32_array(read), std::optional<Array<int32_t>>{initialArray}) << to_string(read.status_code());
  const auto inner = lookupAnswer.get();
  ASSERT_TRUE(inner.is_good()) << to_string(inner.status_code());
  const NodeDescription innerNode = inner.value()->attributes();
  EXPECT_EQ(innerNode.node_id(), mObject);
  const auto written = writeAnswer.get();
  EXPECT_TRUE(written.is_good()) << to_string(written.status_code());
}

// An accessor setter given no value clears its optional Attribute in every namespace: the description removes
// AccessRestrictions, MinimumSamplingInterval, AccessLevelEx and DataTypeDefinition on a null (R3).
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-A-NULL-REMOVES-THE-OPTIONAL-ATTRIBUTES-A-SETTER-CLEARS, scope=function)
TEST_P(NamespaceConformance, TheClearingSettersRemoveTheirAttributes)
{
  const NodeId variableId{mIndex, "Clearing:V"};
  const NodeId objectId{mIndex, "Clearing:O"};
  const NodeId dataTypeId{mIndex, "Clearing:D"};
  auto variable =
    mAddressSpace->create_sync<VariableAccessor>(variableId, NodeClass::Variable, names("ClearingV"));
  auto object = mAddressSpace->create_sync<ObjectAccessor>(objectId, NodeClass::Object, names("ClearingO"));
  auto dataType =
    mAddressSpace->create_sync<DataTypeAccessor>(dataTypeId, NodeClass::DataType, names("ClearingD"));

  variable.set_minimum_sampling_interval(Duration{100});
  variable.set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::NonatomicRead});
  object.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::SigningRequired});
  auto definition = std::make_shared<StructureDefinition>();
  definition->structure_type() = StructureType::Structure;
  definition->base_data_type() = NodeId{DataTypeId::Structure};
  dataType.set_data_type_definition(definition);
  ASSERT_TRUE(variable.get_minimum_sampling_interval().has_value());
  ASSERT_TRUE(variable.get_access_level_ex().has_value());
  ASSERT_TRUE(object.get_access_restrictions().has_value());
  ASSERT_NE(dataType.get_data_type_definition(), nullptr);

  EXPECT_NO_THROW(variable.set_minimum_sampling_interval(std::nullopt));
  EXPECT_NO_THROW(variable.set_access_level_ex(std::nullopt));
  EXPECT_NO_THROW(object.set_access_restrictions(std::nullopt));
  EXPECT_NO_THROW(dataType.set_data_type_definition(nullptr));

  EXPECT_FALSE(variable.get_minimum_sampling_interval().has_value())
    << "MinimumSamplingInterval was not cleared";
  EXPECT_FALSE(variable.get_access_level_ex().has_value()) << "AccessLevelEx was not cleared";
  EXPECT_FALSE(object.get_access_restrictions().has_value()) << "AccessRestrictions were not cleared";
  EXPECT_EQ(dataType.get_data_type_definition(), nullptr) << "DataTypeDefinition was not cleared";
}

// AccessLevelEx holds AccessLevel as its low 8 bits (OPC 10000-3 5.6.2) in every namespace: a write of either
// sets both, and at creation the last of the two given decides (R3).
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-ACCESS-LEVEL-AND-ACCESS-LEVEL-EX-ARE-ONE-VALUE, scope=function)
TEST_P(NamespaceConformance, AccessLevelAndAccessLevelExAreOneValue)
{
  auto variable = mAddressSpace->create_sync<VariableAccessor>(
    NodeId{mIndex, "Coupled:V"}, NodeClass::Variable, names("CoupledV"));

  variable.set_access_level_ex(AccessLevelExType{0x103u});
  EXPECT_EQ(variable.get_access_level().as_underlying_type(), 0x03u)
    << "a write of AccessLevelEx did not set AccessLevel";
  variable.set_access_level(AccessLevelType{0x01u});
  ASSERT_TRUE(variable.get_access_level_ex().has_value());
  EXPECT_EQ(variable.get_access_level_ex()->as_underlying_type(), 0x101u)
    << "a write of AccessLevel did not set AccessLevelEx's low byte, or lost its high bits";

  auto attributes = names("CoupledW");
  attributes.emplace_back(
    AttributeId::AccessLevelEx, attribute_wire::access_level_ex(AccessLevelExType{0x203u}));
  attributes.emplace_back(AttributeId::AccessLevel, attribute_wire::access_level(AccessLevelType{0x01u}));
  auto created = mAddressSpace->create_sync<VariableAccessor>(
    NodeId{mIndex, "Coupled:W"}, NodeClass::Variable, attributes);
  EXPECT_EQ(created.get_access_level().as_underlying_type(), 0x01u);
  ASSERT_TRUE(created.get_access_level_ex().has_value());
  EXPECT_EQ(created.get_access_level_ex()->as_underlying_type(), 0x201u)
    << "the AccessLevel given last did not decide AccessLevelEx's low byte";
}

INSTANTIATE_TEST_SUITE_P(
  Namespaces, NamespaceConformance, ::testing::Values(in_memory_namespace(), described_nodes_namespace()));
