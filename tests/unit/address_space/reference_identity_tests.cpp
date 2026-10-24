// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A Node holds a Reference once (SVR-ADDRSP-260, NR-68 item 8, NR-70 F14). Part 3 section 4.3.4: "each Node
// can reference another Node with the same ReferenceType only once", and "Any subtypes of concrete
// ReferenceTypes are considered to be equal to the base concrete ReferenceTypes when identifying References".
// Part 4 section 5.7.3.4, Table 27: "Bad_DuplicateReferenceNotAllowed The reference type between the nodes is
// already defined." The in-memory namespace is driven through its Nodes' add, and the if-not-present helpers
// through the NodeAccessor, the routes the NodeSet import and instantiation take.

#include <gtest/gtest.h>

#include "../../behaviour_pins/phase_4_4_address_space/fake_async_namespace.h"
#include "../../behaviour_pins/phase_4_4_address_space/fake_node.h"
#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_default_base_node.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node_accessor.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

const NodeId organizes{ReferenceTypeId::Organizes};
const NodeId hasComponent{ReferenceTypeId::HasComponent};
const NodeId hasOrderedComponent{ReferenceTypeId::HasOrderedComponent};
const NodeId hasAddIn{ReferenceTypeId::HasAddIn};
// A type the address space does not pair, so that a duplicate add reaches the caller as the namespace answers
// it.
const NodeId hasDictionaryEntry{ReferenceTypeId::HasDictionaryEntry};

/// Reads @p node's References as a list of "type -> target" strings, forward ones only, sorted.
std::vector<std::string> forward_references(const NodeAccessor& node)
{
  std::vector<std::string> listed;
  auto held = node.try_get_references_sync();
  if (held.is_bad())
  {
    ADD_FAILURE() << "the References could not be read: " << to_string(held.status_code());
    return listed;
  }
  for (const auto& reference : held.value())
  {
    if (reference.is_forward())
      listed.push_back(to_string(reference.type_id()) + " -> " + to_string(reference.target_id().node_id()));
  }
  std::sort(listed.begin(), listed.end());
  return listed;
}

std::string ref(const NodeId& type, const NodeId& target)
{
  return to_string(type) + " -> " + to_string(target);
}

std::vector<std::string> sorted(std::vector<std::string> listed)
{
  std::sort(listed.begin(), listed.end());
  return listed;
}

/// The value of @p key in @p status's ErrorDetail context, if it has one.
std::optional<std::string> context_value(const StatusCode& status, std::string_view key)
{
  const auto detail = status.shared_detail();
  if (!detail)
    return std::nullopt;
  for (const auto& entry : detail->context)
  {
    if (entry.key == key)
      return std::string{entry.value};
  }
  return std::nullopt;
}

class InMemoryReferences : public ::testing::Test
{
protected:
  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor object(uint32_t identifier)
  {
    const NodeId nodeId{1, identifier};
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, {});
    EXPECT_TRUE(created.is_good()) << to_string(created.status_code());
    return std::move(created).value();
  }

  VoidResult add_if_not_present_async(NodeAccessor& node, const NodeId& type, const NodeId& target)
  {
    std::promise<VoidResult> answered;
    auto answer = answered.get_future();
    node.add_reference_if_not_present_async(type,
      target,
      true,
      ReferenceHalves::Both,
      [&answered](VoidResult result) { answered.set_value(std::move(result)); });
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "add_reference_if_not_present_async never answered";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return answer.get();
  }

  VoidResult add_batch_if_not_present(NodeAccessor& node, std::vector<Reference> references)
  {
    std::promise<VoidResult> answered;
    auto answer = answered.get_future();
    node.add_references_if_not_present_async(std::move(references),
      ReferenceHalves::Both,
      [&answered](VoidResult result) { answered.set_value(std::move(result)); });
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "add_references_if_not_present_async never answered";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return answer.get();
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace{
    AddressSpace::create("urn:test:reference-identity", mThreadPool.get_executor())};
};

using AddReferencesIfNotPresent = InMemoryReferences;
using ReferenceRemoval = InMemoryReferences;

/// An address space with a FakeAsyncNamespace registered. The namespace holds the Objects a test makes and
/// answers each Reference read and each Reference added at one of them with the answers the test stages for
/// that Object, recording each.
class ScriptedReferenceNodes
{
public:
  ScriptedReferenceNodes()
    : mAddressSpace(AddressSpace::create("urn:test:reference-identity-scripted", mPool.get_executor())),
      mFake(ua::test::behaviour_pins::FakeAsyncNamespace::create("urn:test:reference-identity-scripted:ns")),
      mIndex(mAddressSpace.add_namespace_sync(mFake))
  {}

  /// The fake namespace's index: an Object it holds has a NodeId of this index, because the address space
  /// routes an accessor's operations by its Node's own NodeId.
  uint16_t index() const noexcept
  {
    return mIndex;
  }

  ua::test::behaviour_pins::FakeAsyncNamespace& fake() noexcept
  {
    return *mFake;
  }

  /// The accessor the address space hands out for an Object of @p nodeId held by the fake namespace.
  NodeAccessor accessor_for(const NodeId& nodeId)
  {
    mFake->hold(nodeId, std::make_shared<ua::test::behaviour_pins::FakeNode>(nodeId, NodeClass::Object));
    return mAddressSpace.find_node_sync(nodeId);
  }

private:
  boost::asio::thread_pool mPool{1};
  AddressSpace mAddressSpace;
  std::shared_ptr<ua::test::behaviour_pins::FakeAsyncNamespace> mFake;
  uint16_t mIndex;
};

}  // namespace

// HasDictionaryEntry, which the address space does not pair: a paired type's held half answers Good through
// an accessor (NR-30 rule 4). The add to C is the control that a Reference to another target is still stored.
// @relation(AC-SVR-ADDRSP-260-REPEATED-ADD-REFUSED, scope=function)
TEST_F(InMemoryReferences, ARepeatedAddIsDuplicateReferenceNotAllowed)
{
  auto a = object(100);
  const NodeId b = object(101).get_node_id();
  const NodeId c = object(102).get_node_id();

  EXPECT_TRUE(a.try_add_reference_sync(hasDictionaryEntry, b).is_good());
  EXPECT_EQ(a.try_add_reference_sync(hasDictionaryEntry, b).status_code().as_status(),
    Status::BadDuplicateReferenceNotAllowed)
    << "a Reference the Node already holds was added again";
  EXPECT_TRUE(a.try_add_reference_sync(hasDictionaryEntry, c).is_good());

  EXPECT_EQ(forward_references(a), sorted({ref(hasDictionaryEntry, b), ref(hasDictionaryEntry, c)}));
}

// HasOrderedComponent is a subtype of HasComponent, which is concrete, so beside a held HasComponent to B it
// is the same Reference. Organizes shares no concrete supertype with HasComponent: the control that the
// identity is not "any Reference to the same target".
// @relation(AC-SVR-ADDRSP-260-SUBTYPE-OF-HELD-CONCRETE-TYPE-IS-DUPLICATE, scope=function)
TEST_F(InMemoryReferences, AHasOrderedComponentBesideAHeldHasComponentIsADuplicate)
{
  auto a = object(200);
  const NodeId b = object(201).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, b).is_good());

  // The held HasComponent is not the HasOrderedComponent asked for, so the refusal says so, and the address
  // space, which pairs both types, does not take it as held (NR-30 rule 4).
  const auto ordered = a.try_add_reference_sync(hasOrderedComponent, b);
  EXPECT_EQ(ordered.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << "a HasOrderedComponent was stored beside a HasComponent to the same target";
  ASSERT_NE(ordered.shared_detail(), nullptr);
  EXPECT_EQ(ordered.shared_detail()->code, "DuplicateReferenceOfAnotherType");
  EXPECT_TRUE(a.try_add_reference_sync(organizes, b).is_good());

  EXPECT_EQ(forward_references(a), sorted({ref(hasComponent, b), ref(organizes, b)}));
}

// A batch holding a Reference the Node holds, or one Reference twice, stores nothing: the caller that gets
// Bad_DuplicateReferenceNotAllowed knows nothing was stored. The third batch is the control.
// @relation(AC-SVR-ADDRSP-260-BATCH-REFUSED-WHOLE, scope=function)
TEST_F(InMemoryReferences, ABatchHoldingAHeldOrRepeatedReferenceIsRefusedWhole)
{
  auto a = object(300);
  // The in-memory Node's own batch member: an accessor's multi-form sends one change per Reference through
  // its namespace, each answered alone (DL-59 (6)).
  auto* node = dynamic_cast<default_ns::BaseNode*>(&*a);
  ASSERT_NE(node, nullptr);
  const auto addToNode = [node](std::vector<Reference> references)
  {
    std::promise<VoidResult> added;
    node->add_references_async(
      std::move(references), [&added](VoidResult result) { added.set_value(std::move(result)); });
    return added.get_future().get();
  };
  const NodeId b = object(301).get_node_id();
  const NodeId c = object(302).get_node_id();
  const NodeId d = object(303).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(organizes, b).is_good());

  const auto withHeld =
    addToNode({Reference{organizes, ExpandedNodeId{c}, true}, Reference{organizes, ExpandedNodeId{b}, true}});
  EXPECT_EQ(withHeld.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(withHeld.status_code());
  EXPECT_EQ(forward_references(a), sorted({ref(organizes, b)}))
    << "a batch holding a held Reference stored some of it";

  const auto repeated =
    addToNode({Reference{organizes, ExpandedNodeId{d}, true}, Reference{organizes, ExpandedNodeId{d}, true}});
  EXPECT_EQ(repeated.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(repeated.status_code());
  EXPECT_EQ(forward_references(a), sorted({ref(organizes, b)}))
    << "a batch holding one Reference twice stored some of it";

  const auto fresh =
    addToNode({Reference{organizes, ExpandedNodeId{c}, true}, Reference{organizes, ExpandedNodeId{d}, true}});
  EXPECT_TRUE(fresh.is_good()) << to_string(fresh.status_code());
  EXPECT_EQ(forward_references(a), sorted({ref(organizes, b), ref(organizes, c), ref(organizes, d)}));
}

// DL-11 (restated): asked for a HasOrderedComponent to B while a HasComponent to B is held, the helper cannot
// give the type asked for, so it refuses, naming both types and the target, and adds nothing.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-USES-IDENTITY, scope=function)
TEST_F(AddReferencesIfNotPresent, AHeldSupertypeOfTheTypeAskedForIsRefused)
{
  auto a = object(400);
  const NodeId b = object(401).get_node_id();
  const NodeId c = object(402).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, b).is_good());
  ASSERT_TRUE(a.try_add_reference_sync(hasOrderedComponent, c).is_good());
  const auto held = sorted({ref(hasComponent, b), ref(hasOrderedComponent, c)});

  const auto checkRefusal = [&](const VoidResult& refused, const char* route)
  {
    EXPECT_EQ(refused.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
      << route << ": " << to_string(refused.status_code());
    ASSERT_NE(refused.shared_detail(), nullptr) << route;
    EXPECT_EQ(refused.shared_detail()->code, "DuplicateReferenceOfAnotherType") << route;
    EXPECT_EQ(context_value(refused.status_code(), ContextKeys::typeActual.value()), to_string(hasComponent))
      << route;
    EXPECT_EQ(
      context_value(refused.status_code(), ContextKeys::typeExpected.value()), to_string(hasOrderedComponent))
      << route;
    EXPECT_EQ(context_value(refused.status_code(), ContextKeys::nodeId.value()), to_string(b)) << route;
    EXPECT_EQ(forward_references(a), held) << route << ": the helper added a Reference";
  };
  checkRefusal(add_if_not_present_async(a, hasOrderedComponent, b), "asynchronous");
  checkRefusal(a.try_add_reference_if_not_present_sync(hasOrderedComponent, b), "synchronous");
}

// The control: asked for a HasComponent to C while a HasOrderedComponent to C is held, the Reference held is
// of a subtype of the type asked for, so a Browse for HasComponent finds it; the helper answers Good and adds
// nothing.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-USES-IDENTITY, scope=function)
TEST_F(AddReferencesIfNotPresent, AHeldSubtypeOfTheTypeAskedForCountsAsPresent)
{
  auto a = object(500);
  const NodeId b = object(501).get_node_id();
  const NodeId c = object(502).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, b).is_good());
  ASSERT_TRUE(a.try_add_reference_sync(hasOrderedComponent, c).is_good());
  const auto held = sorted({ref(hasComponent, b), ref(hasOrderedComponent, c)});

  const auto asynchronous = add_if_not_present_async(a, hasComponent, c);
  EXPECT_TRUE(asynchronous.is_good()) << to_string(asynchronous.status_code());
  EXPECT_EQ(forward_references(a), held) << "asynchronous: a HasComponent was added beside the held subtype";
  const auto synchronous = a.try_add_reference_if_not_present_sync(hasComponent, c);
  EXPECT_TRUE(synchronous.is_good()) << to_string(synchronous.status_code());
  EXPECT_EQ(forward_references(a), held) << "synchronous: a HasComponent was added beside the held subtype";
}

// DL-11 (as amended after the fourth review): the References of a batch that are the same Reference, with the
// one the Node holds, are decided together, and a group whose types do not form one line of subtypes cannot
// be held as asked: the batch helper adds none of the batch. On A the group is the held HasComponent to B and
// a requested HasOrderedComponent to B; on D it is two siblings, HasOrderedComponent and HasAddIn to F (both
// direct subtypes of the concrete HasComponent, Part 5 sections 11.8 and 11.21), given in both orders.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-BATCH-WITH-A-CONFLICT-ADDS-NONE, scope=function)
// @relation(AC-SVR-ADDRSP-260-IMPORT-DISAGREEING-HALVES-FAIL, scope=function)
TEST_F(AddReferencesIfNotPresent, ABatchWithOneConflictingItemAddsNone)
{
  auto a = object(600);
  const NodeId b = object(601).get_node_id();
  const NodeId c = object(602).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, b).is_good());
  auto d = object(603);
  const NodeId e = object(604).get_node_id();
  const NodeId f = object(605).get_node_id();

  const auto expectRefused = [](const VoidResult& refused, const char* what)
  {
    EXPECT_EQ(refused.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
      << what << ": " << to_string(refused.status_code());
    ASSERT_NE(refused.shared_detail(), nullptr) << what;
    EXPECT_EQ(refused.shared_detail()->code, "DuplicateReferenceOfAnotherType") << what;
  };

  expectRefused(add_batch_if_not_present(a,
                  {Reference{organizes, ExpandedNodeId{c}, true},
                    Reference{hasOrderedComponent, ExpandedNodeId{b}, true}}),
    "the batch with a held conflict");
  EXPECT_EQ(forward_references(a), sorted({ref(hasComponent, b)}))
    << "the batch with a held conflict added some";

  expectRefused(add_batch_if_not_present(d,
                  {Reference{organizes, ExpandedNodeId{e}, true},
                    Reference{hasOrderedComponent, ExpandedNodeId{f}, true},
                    Reference{hasAddIn, ExpandedNodeId{f}, true}}),
    "the batch with HasOrderedComponent then HasAddIn to F");
  EXPECT_TRUE(forward_references(d).empty())
    << "the batch with HasOrderedComponent then HasAddIn to F added some: "
    << ::testing::PrintToString(forward_references(d));

  expectRefused(add_batch_if_not_present(d,
                  {Reference{organizes, ExpandedNodeId{e}, true},
                    Reference{hasAddIn, ExpandedNodeId{f}, true},
                    Reference{hasOrderedComponent, ExpandedNodeId{f}, true}}),
    "the batch with HasAddIn then HasOrderedComponent to F");
  EXPECT_TRUE(forward_references(d).empty())
    << "the batch with HasAddIn then HasOrderedComponent to F added some: "
    << ::testing::PrintToString(forward_references(d));
}

// The control (DL-11 as amended): a type and its subtype form one line, so the group can be held as asked, by
// its most derived member once. G is given HasComponent then HasOrderedComponent to H, J the reverse order,
// and K already holds the HasOrderedComponent to H.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-BATCH-WITH-A-CONFLICT-ADDS-NONE, scope=function)
TEST_F(AddReferencesIfNotPresent, ABatchWithATypeAndItsSubtypeAddsTheSubtypeInEitherOrder)
{
  const NodeId h = object(611).get_node_id();
  auto g = object(610);
  auto j = object(612);
  auto k = object(613);
  ASSERT_TRUE(k.try_add_reference_sync(hasOrderedComponent, h).is_good());
  const auto onlyTheSubtype = sorted({ref(hasOrderedComponent, h)});

  const auto typeFirst = add_batch_if_not_present(g,
    {Reference{hasComponent, ExpandedNodeId{h}, true},
      Reference{hasOrderedComponent, ExpandedNodeId{h}, true}});
  EXPECT_TRUE(typeFirst.is_good()) << "G, HasComponent then HasOrderedComponent: "
                                   << to_string(typeFirst.status_code());
  EXPECT_EQ(forward_references(g), onlyTheSubtype) << "G, HasComponent then HasOrderedComponent";

  const auto subtypeFirst = add_batch_if_not_present(j,
    {Reference{hasOrderedComponent, ExpandedNodeId{h}, true},
      Reference{hasComponent, ExpandedNodeId{h}, true}});
  EXPECT_TRUE(subtypeFirst.is_good())
    << "J, HasOrderedComponent then HasComponent: " << to_string(subtypeFirst.status_code());
  EXPECT_EQ(forward_references(j), onlyTheSubtype) << "J, HasOrderedComponent then HasComponent";

  const auto subtypeHeld = add_batch_if_not_present(k,
    {Reference{hasComponent, ExpandedNodeId{h}, true},
      Reference{hasOrderedComponent, ExpandedNodeId{h}, true}});
  EXPECT_TRUE(subtypeHeld.is_good()) << "K, holding the subtype: " << to_string(subtypeHeld.status_code());
  EXPECT_EQ(forward_references(k), onlyTheSubtype) << "K, holding the subtype";
}

// The dependency-failure arm (CO6): the Node's add answers Bad_DuplicateReferenceNotAllowed. In the first
// call it does so once because another caller added HasDictionaryEntry to B after the helper read A's
// References: the helper reads again, drops B and adds C alone. In the second, A holds no Reference to D and
// the add refuses anyway: a refusal that removes nothing from the batch is reported, after a bounded number
// of attempts.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-RETRIES-AFTER-A-CONCURRENT-ADD, scope=function)
TEST_F(AddReferencesIfNotPresent, AConcurrentAddIsFilteredAndRetriedAndAFruitlessRefusalIsReported)
{
  ScriptedReferenceNodes nodes;
  // One Node A per call, so that each call's staged answers and recorded additions are its own.
  const NodeId concurrent{nodes.index(), uint32_t{700}};
  const NodeId refusing{nodes.index(), uint32_t{704}};
  const NodeId b{1, uint32_t{701}};
  const NodeId c{1, uint32_t{702}};
  const NodeId d{1, uint32_t{703}};
  const auto addIfNotPresent = [&nodes](const NodeId& node, std::vector<Reference> references)
  {
    NodeAccessor accessor = nodes.accessor_for(node);
    std::promise<VoidResult> answered;
    auto answer = answered.get_future();
    accessor.add_references_if_not_present_async(std::move(references),
      ReferenceHalves::Both,
      [&answered](VoidResult result) { answered.set_value(std::move(result)); });
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "add_references_if_not_present_async never answered";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return answer.get();
  };

  // Through the namespace each Reference of the batch is one change, answered alone (DL-59 (6)): B is
  // refused, having been added concurrently, and C is stored, so the read after the refusal finds both.
  auto& fake = nodes.fake();
  fake.set_next_get_references(concurrent, NodeAccessor::ReferencesResult{References{}});
  fake.set_next_add_reference(concurrent, VoidResult{StatusCode{Status::BadDuplicateReferenceNotAllowed}});
  fake.set_next_add_reference(concurrent, VoidResult{});
  fake.set_next_get_references(concurrent,
    NodeAccessor::ReferencesResult{
      References{std::vector<Reference>{Reference{hasDictionaryEntry, ExpandedNodeId{b}, true},
        Reference{hasDictionaryEntry, ExpandedNodeId{c}, true}}}});
  const auto retried = addIfNotPresent(concurrent,
    {Reference{hasDictionaryEntry, ExpandedNodeId{b}, true},
      Reference{hasDictionaryEntry, ExpandedNodeId{c}, true}});
  EXPECT_TRUE(retried.is_good()) << "a refusal caused by a concurrent add was reported: "
                                 << to_string(retried.status_code());
  EXPECT_EQ(fake.recorded_get_references_count(concurrent), 2u) << "the helper did not read the Node again";
  const auto adds = fake.recorded_add_reference_calls(concurrent);
  ASSERT_EQ(adds.size(), 2u) << "the helper offered a Reference the Node holds again";
  EXPECT_EQ(adds[0].target, ExpandedNodeId{b});
  EXPECT_EQ(adds[1].target, ExpandedNodeId{c});

  for (int attempt = 0; attempt < 3; ++attempt)
  {
    fake.set_next_get_references(refusing, NodeAccessor::ReferencesResult{References{}});
    fake.set_next_add_reference(refusing, VoidResult{StatusCode{Status::BadDuplicateReferenceNotAllowed}});
  }
  const auto fruitless = addIfNotPresent(refusing, {Reference{hasDictionaryEntry, ExpandedNodeId{d}, true}});
  EXPECT_EQ(fruitless.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << to_string(fruitless.status_code());
  EXPECT_LE(fake.recorded_add_reference_calls(refusing).size(), 2u)
    << "a refusal that removed nothing from the batch was retried again";
}

// The dependency-failure arm (CO6) for a single Reference: the Node's add answers
// Bad_DuplicateReferenceNotAllowed. In (1) another caller added HasDictionaryEntry to B after the helper read
// the Node's References, so the second read holds it and the helper answers Good. In (2) no read holds it, so
// the refusal is the answer. Either way the Node is asked to add once per call, on the asynchronous and the
// synchronous path alike.
// @relation(AC-SVR-ADDRSP-260-IF-NOT-PRESENT-SINGLE-ADD-REREADS-AFTER-A-CONCURRENT-ADD, scope=function)
TEST_F(AddReferencesIfNotPresent, ASingleAddRefusedAsADuplicateReadsTheNodeAgain)
{
  ScriptedReferenceNodes nodes;
  auto& fake = nodes.fake();
  const NodeId b{1, uint32_t{721}};
  const Reference dictionaryEntryToB{hasDictionaryEntry, ExpandedNodeId{b}, true};
  // Each case asks a Node of its own, so that its staged answers and recorded additions are its own.
  const auto addedConcurrently = [&nodes, &fake, &dictionaryEntryToB](uint32_t identifier)
  {
    const NodeId node{nodes.index(), identifier};
    fake.set_next_get_references(node, NodeAccessor::ReferencesResult{References{}});
    fake.set_next_add_reference(node, VoidResult{StatusCode{Status::BadDuplicateReferenceNotAllowed}});
    fake.set_next_get_references(
      node, NodeAccessor::ReferencesResult{References{std::vector<Reference>{dictionaryEntryToB}}});
    return node;
  };
  const auto neverHeld = [&nodes, &fake](uint32_t identifier)
  {
    const NodeId node{nodes.index(), identifier};
    // Enough answers for a helper that adds a second time, so that doing so shows as a second add.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
      fake.set_next_get_references(node, NodeAccessor::ReferencesResult{References{}});
      fake.set_next_add_reference(node, VoidResult{StatusCode{Status::BadDuplicateReferenceNotAllowed}});
    }
    return node;
  };
  const auto addAsync = [&b, &nodes](const NodeId& node)
  {
    NodeAccessor accessor = nodes.accessor_for(node);
    std::promise<VoidResult> answered;
    auto answer = answered.get_future();
    accessor.add_reference_if_not_present_async(hasDictionaryEntry,
      b,
      true,
      ReferenceHalves::Both,
      [&answered](VoidResult result) { answered.set_value(std::move(result)); });
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "add_reference_if_not_present_async never answered";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return answer.get();
  };
  const auto addSync = [&b, &nodes](const NodeId& node)
  {
    NodeAccessor accessor = nodes.accessor_for(node);
    return accessor.try_add_reference_if_not_present_sync(hasDictionaryEntry, b, true);
  };

  // (1) The Reference refused as a duplicate is held when the Node is read again.
  {
    const NodeId node = addedConcurrently(720);
    const auto result = addAsync(node);
    EXPECT_EQ(result.status_code().as_status(), Status::Good)
      << "async: a refusal caused by a concurrent add was reported: " << to_string(result.status_code());
    EXPECT_EQ(fake.recorded_add_reference_calls(node).size(), 1u)
      << "async: the Node was not asked to add once";
  }
  {
    const NodeId node = addedConcurrently(722);
    const auto result = addSync(node);
    EXPECT_EQ(result.status_code().as_status(), Status::Good)
      << "sync: a refusal caused by a concurrent add was reported: " << to_string(result.status_code());
    EXPECT_EQ(fake.recorded_add_reference_calls(node).size(), 1u)
      << "sync: the Node was not asked to add once";
  }

  // (2) No read holds the Reference: the refusal is the answer.
  {
    const NodeId node = neverHeld(723);
    const auto result = addAsync(node);
    EXPECT_EQ(result.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
      << "async: " << to_string(result.status_code());
    EXPECT_EQ(fake.recorded_add_reference_calls(node).size(), 1u)
      << "async: the Node was not asked to add once";
  }
  {
    const NodeId node = neverHeld(724);
    const auto result = addSync(node);
    EXPECT_EQ(result.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
      << "sync: " << to_string(result.status_code());
    EXPECT_EQ(fake.recorded_add_reference_calls(node).size(), 1u)
      << "sync: the Node was not asked to add once";
  }
}

// Part 3 section 4.3.4: "Any subtypes of concrete ReferenceTypes are considered to be equal to the base
// concrete ReferenceTypes when identifying References." A removal naming HasComponent to X names the held
// HasOrderedComponent to X (DL-11 as amended: a removal matches as an add does). The Organizes to Y is the
// control that only the Reference named is removed.
// @relation(AC-SVR-ADDRSP-260-REMOVAL-USES-IDENTITY, scope=function)
TEST_F(ReferenceRemoval, ARemovalNamingTheBaseTypeRemovesAHeldSubtype)
{
  auto a = object(700);
  const NodeId x = object(701).get_node_id();
  const NodeId y = object(702).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasOrderedComponent, x).is_good());
  ASSERT_TRUE(a.try_add_reference_sync(organizes, y).is_good());

  std::promise<VoidResult> answered;
  auto answer = answered.get_future();
  a.remove_reference_async(hasComponent,
    ExpandedNodeId{x},
    true,
    ReferenceHalves::Both,
    [&answered](VoidResult result) { answered.set_value(std::move(result)); });
  ASSERT_EQ(answer.wait_for(5s), std::future_status::ready) << "remove_reference_async never answered";
  const auto removed = answer.get();
  EXPECT_TRUE(removed.is_good()) << "the removal answered " << to_string(removed.status_code());
  EXPECT_EQ(forward_references(a), sorted({ref(organizes, y)}))
    << "the HasOrderedComponent to X is still held after a removal naming HasComponent to X";
}

// Part 3 section 4.3.4 holds in both directions: a removal naming HasOrderedComponent to Z names the held
// HasComponent to Z. Organizes, a concrete type unrelated to HasComponent, is the control that a removal does
// not identify a Reference of an unrelated type; the Organizes to Y is held throughout.
// @relation(AC-SVR-ADDRSP-260-REMOVAL-USES-IDENTITY, scope=function)
TEST_F(ReferenceRemoval, ARemovalNamingASubtypeRemovesAHeldBaseType)
{
  auto a = object(710);
  const NodeId z = object(711).get_node_id();
  const NodeId y = object(712).get_node_id();
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, z).is_good());
  ASSERT_TRUE(a.try_add_reference_sync(organizes, y).is_good());
  const auto removeForward = [&a, &z](const NodeId& type)
  {
    std::promise<VoidResult> answered;
    auto answer = answered.get_future();
    a.remove_reference_async(type,
      ExpandedNodeId{z},
      true,
      ReferenceHalves::Both,
      [&answered](VoidResult result) { answered.set_value(std::move(result)); });
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "remove_reference_async never answered";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return answer.get();
  };

  removeForward(organizes);
  EXPECT_EQ(forward_references(a), sorted({ref(hasComponent, z), ref(organizes, y)}))
    << "a removal naming Organizes to Z removed a Reference of the unrelated type HasComponent";

  const auto removed = removeForward(hasOrderedComponent);
  EXPECT_TRUE(removed.is_good()) << "the removal answered " << to_string(removed.status_code());
  EXPECT_EQ(forward_references(a), sorted({ref(organizes, y)}))
    << "the HasComponent to Z is still held after a removal naming HasOrderedComponent to Z";
}
