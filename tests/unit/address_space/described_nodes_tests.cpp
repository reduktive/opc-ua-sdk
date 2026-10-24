// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-NAMESPACE-INTERFACE-03: DescribedNodes holds one Node per NodeId while it is held, applies
// confirmed writes, answers held by maxAge and forgets a removed Node.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_byte_string.h"
#include "ua_described_nodes.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <latch>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

LocalizedText text(std::string_view locale, std::string_view value)
{
  return LocalizedText{LocaleId{locale}, String{value}};
}

NodeDescription object_named(const NodeId& nodeId, const LocalizedText& displayName)
{
  return NodeDescription::object(nodeId, QualifiedName{nodeId.namespace_index(), "Object"})
    .with_display_name(displayName);
}

LocalizedText display_name_of(const Node& node)
{
  const NodeDescription description = node.attributes();
  return description.display_name();
}

// The text a DisplayName holds for one locale, or nullopt.
std::optional<String> text_for(const Node& node, std::string_view locale)
{
  return display_name_of(node).text_for_locale(locale);
}

}  // namespace

// NR-1 rule 5: node_for for a NodeId already held returns that Node, now carrying the new description.
// The four identifier forms and a second namespace index are the classes a NodeId key distinguishes.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-ONE-NODE-PER-NODEID-WHILE-HELD, scope=function)
TEST(DescribedNodesStore, OneNodePerNodeIdWhileHeld)
{
  DescribedNodes store;
  const std::vector<NodeId> nodeIds{NodeId{2, uint32_t{1001}},
    NodeId{2, std::string_view{"a"}},
    NodeId{2, Guid::parse("72962B91-FA75-4AE6-8D28-B404DC7DAF63")},
    NodeId{2, ByteString{0x01, 0x02, 0x03}}};

  std::vector<shared_ptr<Node>> first;
  for (const auto& nodeId : nodeIds)
  {
    first.push_back(store.node_for(object_named(nodeId, text("en", "first"))));
    ASSERT_NE(first.back(), nullptr) << to_string(nodeId);
  }
  for (size_t index = 0; index < nodeIds.size(); ++index)
  {
    SCOPED_TRACE(to_string(nodeIds[index]));
    const auto second = store.node_for(object_named(nodeIds[index], text("en", "second")));
    EXPECT_EQ(second.get(), first[index].get());
    EXPECT_EQ(store.held(nodeIds[index], std::nullopt).get(), first[index].get());
    EXPECT_EQ(display_name_of(*first[index]), text("en", "second"));
  }
  for (size_t index = 0; index < first.size(); ++index)
  {
    for (size_t other = index + 1; other < first.size(); ++other)
    {
      EXPECT_NE(first[index].get(), first[other].get()) << index << " and " << other;
    }
  }

  const auto otherNamespace = store.node_for(object_named(NodeId{3, uint32_t{1001}}, text("en", "first")));
  ASSERT_NE(otherNamespace, nullptr);
  for (const auto& node : first)
  {
    EXPECT_NE(otherNamespace.get(), node.get());
  }
}

// NR-1 rule 5: the store keeps nothing once the last holder lets go.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-NOTHING-HELD-AFTER-LAST-HOLDER, scope=function)
TEST(DescribedNodesStore, NothingIsHeldOnceTheLastHolderLetsGo)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{1}};
  std::weak_ptr<Node> released;
  {
    auto node = store.node_for(object_named(nodeId, text("en", "first")));
    ASSERT_NE(node, nullptr);
    released = node;
  }

  EXPECT_TRUE(released.expired());
  EXPECT_EQ(store.held(nodeId, std::nullopt), nullptr);
  const auto again = store.node_for(object_named(nodeId, text("en", "second")));
  ASSERT_NE(again, nullptr);
  EXPECT_EQ(display_name_of(*again), text("en", "second"));
}

// NR-1 rule 5, NR-3 rule 3 and Part 4 section 5.10.4.1: a LocalizedText write is merged per locale, in the five
// classes that clause treats differently; every other attribute is replaced whole.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-RECORD-WRITE-MERGES-LOCALIZED-TEXT, scope=function)
TEST(DescribedNodesStore, RecordWriteMergesLocalizedTextPerLocale)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{1}};
  const auto node =
    store.node_for(object_named(nodeId, text("en", "Pump").with_translation(LocaleId{"de"}, String{"Pumpe"}))
                     .with_write_mask(AttributeWriteMask{uint32_t{0}}));
  ASSERT_NE(node, nullptr);

  auto write = [&](const LocalizedText& value)
  {
    const auto result = store.record_write(nodeId, AttributeId::DisplayName, Variant{value});
    EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
  };

  write(text("fr", "Pompe"));  // (a) a new locale is added
  EXPECT_EQ(text_for(*node, "en"), std::optional<String>{String{"Pump"}});
  EXPECT_EQ(text_for(*node, "de"), std::optional<String>{String{"Pumpe"}});
  EXPECT_EQ(text_for(*node, "fr"), std::optional<String>{String{"Pompe"}});

  write(text("en", "Main pump"));  // (b) a held locale is overwritten
  EXPECT_EQ(text_for(*node, "en"), std::optional<String>{String{"Main pump"}});
  EXPECT_EQ(text_for(*node, "de"), std::optional<String>{String{"Pumpe"}});
  EXPECT_EQ(text_for(*node, "fr"), std::optional<String>{String{"Pompe"}});

  write(LocalizedText{LocaleId{"de"}, String{}});  // (c) a null text deletes that locale
  EXPECT_EQ(text_for(*node, "de"), std::nullopt);
  EXPECT_EQ(text_for(*node, "en"), std::optional<String>{String{"Main pump"}});
  EXPECT_EQ(text_for(*node, "fr"), std::optional<String>{String{"Pompe"}});

  write(LocalizedText{LocaleId{}, String{"P-1"}});  // (d) a null locale sets the invariant locale
  EXPECT_EQ(text_for(*node, ""), std::optional<String>{String{"P-1"}});
  EXPECT_EQ(text_for(*node, "en"), std::optional<String>{String{"Main pump"}});

  write(LocalizedText{LocaleId{}, String{}});  // (e) null locale and null text delete every locale
  EXPECT_EQ(display_name_of(*node).translation_count(), 0u);

  const auto mask = store.record_write(nodeId, AttributeId::WriteMask, Variant{uint32_t{5}});
  EXPECT_TRUE(mask.is_good()) << to_string(mask.status_code());
  const NodeDescription description = node->attributes();
  EXPECT_EQ(description.write_mask(), std::optional<AttributeWriteMask>{AttributeWriteMask{uint32_t{5}}});
}

// NR-1 rule 5 and NR-44: record_write and remove for a NodeId the store does not hold change nothing,
// so a Node made later for that NodeId carries neither the write nor a deleted state.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-UNHELD-NODEID-UNCHANGED, scope=function)
TEST(DescribedNodesStore, AnOperationOnANodeIdNotHeldChangesNothing)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{7}};

  EXPECT_NO_THROW((void)store.record_write(nodeId, AttributeId::DisplayName, Variant{text("en", "Changed")}));
  EXPECT_NO_THROW(store.remove(nodeId));

  const auto node = store.node_for(object_named(nodeId, text("en", "Original")));
  ASSERT_NE(node, nullptr);
  EXPECT_FALSE(node->deleted());
  EXPECT_EQ(display_name_of(*node), text("en", "Original"));
}

// NR-1 rules 3 and 5, Part 4 section 5.10.2.2: held answers the Node only when its description is no older than
// maxAge; nullopt accepts any age; a NodeId never held is not answered.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-HELD-RESPECTS-MAXAGE, scope=function)
TEST(DescribedNodesStore, HeldRespectsMaxAge)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{1}};
  const auto node = store.node_for(object_named(nodeId, text("en", "aged")));
  ASSERT_NE(node, nullptr);
  std::this_thread::sleep_for(60ms);

  EXPECT_EQ(store.held(nodeId, std::nullopt).get(), node.get()) << "maxAge nullopt";
  EXPECT_EQ(store.held(nodeId, Duration{10000}).get(), node.get()) << "maxAge 10,000 ms";
  EXPECT_EQ(store.held(nodeId, Duration{10}), nullptr) << "maxAge 10 ms";
  EXPECT_EQ(store.held(nodeId, Duration{0}), nullptr) << "maxAge 0";
  EXPECT_EQ(store.held(NodeId{2, uint32_t{2}}, std::nullopt), nullptr) << "never given";
}

// NR-44: remove marks the held Node deleted and forgets it; a later node_for makes a new Node, which the
// old holder does not see.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-REMOVE-MARKS-DELETED, scope=function)
TEST(DescribedNodesStore, RemoveMarksDeletedAndALaterNodeForIsNew)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{1}};
  const auto oldNode = store.node_for(object_named(nodeId, text("en", "old")));
  ASSERT_NE(oldNode, nullptr);

  store.remove(nodeId);
  EXPECT_TRUE(oldNode->deleted());
  EXPECT_EQ(store.held(nodeId, std::nullopt), nullptr);

  const auto newNode = store.node_for(object_named(nodeId, text("en", "new")));
  ASSERT_NE(newNode, nullptr);
  EXPECT_NE(newNode.get(), oldNode.get());
  EXPECT_FALSE(newNode->deleted());
  EXPECT_EQ(display_name_of(*newNode), text("en", "new"));
  EXPECT_EQ(display_name_of(*oldNode), text("en", "old"));
  EXPECT_TRUE(oldNode->deleted());
}

// NR-21 rule 5 and NR-1 rule 5: concurrent node_for calls for one NodeId return one Node, and concurrent
// record_write calls on one Node keep both changes. Two locales make a lost change visible.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-CONCURRENT-CALLS-KEEP-ONE-NODE-AND-EVERY-CHANGE, scope=function)
TEST(DescribedNodesStore, ConcurrentCallsOnOneNodeIdKeepOneNodeAndEveryChange)
{
  DescribedNodes store;
  for (uint32_t round = 0; round < 500; ++round)
  {
    const NodeId nodeId{2, uint32_t{10000} + round};
    shared_ptr<Node> found[2];
    {
      std::latch start{2};
      auto find = [&](size_t slot)
      {
        start.arrive_and_wait();
        found[slot] = store.node_for(object_named(nodeId, text("en", "x")));
      };
      std::thread first{find, 0};
      std::thread second{find, 1};
      first.join();
      second.join();
    }
    ASSERT_NE(found[0], nullptr) << "round " << round;
    ASSERT_EQ(found[0].get(), found[1].get()) << "round " << round;

    {
      std::latch start{2};
      auto write = [&](const LocalizedText& value)
      {
        start.arrive_and_wait();
        (void)store.record_write(nodeId, AttributeId::DisplayName, Variant{value});
      };
      std::thread german{write, text("de", "y")};
      std::thread french{write, text("fr", "z")};
      german.join();
      french.join();
    }
    const LocalizedText displayName = display_name_of(*found[0]);
    ASSERT_EQ(displayName.text_for_locale("en"), std::optional<String>{String{"x"}}) << "round " << round;
    ASSERT_EQ(displayName.text_for_locale("de"), std::optional<String>{String{"y"}}) << "round " << round;
    ASSERT_EQ(displayName.text_for_locale("fr"), std::optional<String>{String{"z"}}) << "round " << round;
  }
}

// NR-21 rules 2 and 5: a description taken before a change keeps reading its own body, through
// references taken from it; the address-sanitizer job reports a body freed under it.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-DESCRIPTION-TAKEN-BEFORE-WRITE-KEEPS-ITS-VALUES, scope=function)
TEST(DescribedNodesStore, ADescriptionTakenBeforeAWriteKeepsItsValues)
{
  DescribedNodes store;
  const NodeId nodeId{2, uint32_t{1}};
  const auto node = store.node_for(object_named(nodeId, text("en", "before")));
  ASSERT_NE(node, nullptr);
  const NodeDescription before = node->attributes();
  const LocalizedText& reference = before.display_name();

  const auto written = store.record_write(nodeId, AttributeId::DisplayName, Variant{text("en", "after")});
  EXPECT_TRUE(written.is_good()) << to_string(written.status_code());

  EXPECT_EQ(reference, text("en", "before"));
  EXPECT_EQ(before.display_name(), text("en", "before"));
  EXPECT_EQ(display_name_of(*node), text("en", "after"));
}

namespace
{

// The record's gateway author: a namespace that answers lookups with DescribedNodes::node_for through
// find_nodes_async alone. It serves no References and no Values.
class DescribedGatewayNamespace final : public Namespace
{
public:
  explicit DescribedGatewayNamespace(shared_ptr<DescribedNodes> store) : mStore(std::move(store))
  {}

  String uri() const override
  {
    return String{"urn:test:described-gateway"};
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      answer.items.emplace_back(mStore->node_for(
        NodeDescription::object(nodeId, QualifiedName{nodeId.namespace_index(), "Gateway node"})
          .with_display_name(LocalizedText{LocaleId{"en"}, String{"Original"}})));
    }
    complete(std::move(answer));
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    for (std::size_t i = 0; i < queries.size(); ++i)
    {
      answer.items.emplace_back(NodeReferences{});
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answer.items.emplace_back(StatusCode{Status::BadNotReadable});
    }
    complete(std::move(answer));
  }

private:
  shared_ptr<DescribedNodes> mStore;
};

}  // namespace

// NR-1 rules 1, 4 and 5 and NR-20 rule 2: a production lookup enters through the address space and
// reaches the Node the store holds; a write recorded on the store is seen through the accessor.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-03-ADDRESS-SPACE-LOOKUP-RETURNS-HELD-NODE, scope=function)
TEST(DescribedNodesStore, AnAddressSpaceLookupReturnsTheHeldNode)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:described-gateway-app", pool.get_executor());
    auto store = std::make_shared<DescribedNodes>();
    auto gateway = std::make_shared<DescribedGatewayNamespace>(store);
    const auto registered = addressSpace.try_add_namespace_sync(gateway);
    ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
    const NodeId nodeId{registered.value(), uint32_t{1}};

    std::promise<BatchResult<NodeAccessorResult>> looked;
    auto lookedUp = looked.get_future();
    const std::vector<NodeId> nodeIds{nodeId};
    addressSpace.find_nodes_async(nodeIds,
      [promise = std::make_shared<std::promise<BatchResult<NodeAccessorResult>>>(std::move(looked))](
        BatchResult<NodeAccessorResult> result) { promise->set_value(std::move(result)); });
    ASSERT_EQ(lookedUp.wait_for(::ua::test_utils::default_poll_budget()), std::future_status::ready);
    const auto answer = lookedUp.get();
    ASSERT_EQ(answer.items.size(), 1u);
    ASSERT_TRUE(answer.items[0].is_good()) << to_string(answer.items[0].status_code());
    const NodeAccessor accessor = answer.items[0].value();

    EXPECT_EQ(&*accessor, store->held(nodeId, std::nullopt).get());
    const auto written = store->record_write(
      nodeId, AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{"Renamed"}}});
    EXPECT_TRUE(written.is_good()) << to_string(written.status_code());
    const NodeDescription description = accessor->attributes();
    EXPECT_EQ(description.display_name(), (LocalizedText{LocaleId{"en"}, String{"Renamed"}}));
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
