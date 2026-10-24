// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Reading a BrowseName is total.
///
/// OPC 10000-3 makes BrowseName mandatory on every NodeClass, but nothing in the SDK forces an
/// in-process caller to supply one, so a node can hold no BrowseName attribute at all. Asking such
/// a node for its name used to throw from the `Variant` cast, which pushed the cost of a malformed
/// node onto every caller: the Read service wrapped its comparisons in a catch-all, and two call
/// sites - one of them inside a strand handler, where a throw is a process abort - had no handler
/// at all.
///
/// `get_browse_name` now answers the question instead of refusing it: an absent name reads back as
/// an empty `QualifiedName`. Callers that need to distinguish "absent" from "present" test the name,
/// and the attribute Read reports `BadAttributeIdInvalid` for an absent BrowseName exactly as it
/// already does for an absent DisplayName.

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include "monitored_item_probe.h"
#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_wire.h"
#include "ua_node_accessor.h"
#include "ua_default_object_node.h"
#include "ua_node_utilities.h"
#include "ua_qualified_name.h"
#include "ua_to_string.h"

using namespace ua;

namespace
{

/// A namespace holding one named node and one node created bare, the way a minimal test Object is.
struct Fixture
{
  boost::asio::thread_pool pool{1};
  AddressSpace addressSpace{AddressSpace::create("urn:browse-name", pool.get_executor())};

  NodeAccessor named{addressSpace.create_node_sync(NodeId{1, uint32_t{1}}, NodeClass::Object,
    InitialAttributes{{AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{1, "Named"})}})};

  NodeAccessor nameless{addressSpace.create_node_sync(NodeId{1, uint32_t{2}}, NodeClass::Object)};

  DataValue read(const NodeAccessor& node, AttributeId id)
  {
    return node_utils::read_node_sync_attribute(node, id, TimestampsToReturn::Both, {}, {});
  }
};

}  // namespace

// --- the accessor ------------------------------------------------------------------------------

TEST(BrowseNameTotalReadTests, ANodeWithoutABrowseNameReadsBackEmptyRatherThanThrowing)
{
  Fixture fixture;

  QualifiedName browseName{7, "untouched"};
  ASSERT_NO_THROW(browseName = fixture.nameless.get_browse_name());

  EXPECT_TRUE(browseName.name().empty());
  EXPECT_EQ(browseName, QualifiedName{});
}

TEST(BrowseNameTotalReadTests, ANodeWithABrowseNameStillReadsItBack)
{
  Fixture fixture;

  EXPECT_EQ(fixture.named.get_browse_name(), (QualifiedName{1, "Named"}));
}

TEST(BrowseNameTotalReadTests, AnEmptyNameIsDistinguishableFromAPresentOne)
{
  Fixture fixture;

  // The whole point of answering rather than throwing: the caller still gets to tell them apart,
  // by asking about the name rather than by catching.
  EXPECT_FALSE(fixture.named.get_browse_name().name().empty());
  EXPECT_TRUE(fixture.nameless.get_browse_name().name().empty());
}

// --- the attribute Read ------------------------------------------------------------------------

// The node holds a description, which has a BrowseName and a DisplayName whatever the creation gave (NR-21
// rule 5): a node created without a BrowseName holds the null name, and reads it Good.
TEST(BrowseNameTotalReadTests, ANodeCreatedWithoutABrowseNameReadsTheNullName)
{
  Fixture fixture;

  DataValue result;
  ASSERT_NO_THROW(result = fixture.read(fixture.nameless, AttributeId::BrowseName));

  EXPECT_FALSE(result.status().has_value() && !result.status()->is_good());
  ASSERT_TRUE(result.value().is_qualified_name());
  EXPECT_EQ(result.value().as<QualifiedName>(), QualifiedName{});
}

// A DisplayName not given is the description's default, the BrowseName's text.
TEST(BrowseNameTotalReadTests, ANodeCreatedWithoutADisplayNameReadsItsBrowseNameText)
{
  Fixture fixture;

  const auto result = fixture.read(fixture.named, AttributeId::DisplayName);
  EXPECT_FALSE(result.status().has_value() && !result.status()->is_good());
  ASSERT_TRUE(result.value().is_localized_text());
  EXPECT_EQ(result.value().as<LocalizedText>().text(), String{"Named"});
}

// An optional attribute the node was not given is not carried, and reads Bad_AttributeIdInvalid.
TEST(BrowseNameTotalReadTests, AnOptionalAttributeNotGivenReportsBadAttributeIdInvalid)
{
  Fixture fixture;

  const auto result = fixture.read(fixture.nameless, AttributeId::Description);
  ASSERT_TRUE(result.status().has_value());
  EXPECT_EQ(result.status()->as_status(), Status::BadAttributeIdInvalid);
}

TEST(BrowseNameTotalReadTests, ReadingAPresentBrowseNameIsGood)
{
  Fixture fixture;

  const auto result = fixture.read(fixture.named, AttributeId::BrowseName);

  // A successful read leaves the status unset rather than writing an explicit Good.
  EXPECT_FALSE(result.status().has_value() && result.status()->is_bad());
  EXPECT_EQ(result.value().as<QualifiedName>(), (QualifiedName{1, "Named"}));
}

// --- typed storage -----------------------------------------------------------------------------
//
// NodeId and BrowseName are held in typed form on the default node rather than as Variants in the
// attribute list, because every service that authorizes an operation asks for the NodeId and the
// Read path compares BrowseNames, both once per operation. The storage is an implementation detail:
// these pin that no caller can tell, whichever way it is reached.

TEST(TypedNodeAttributeStorageTests, NodeIdReadsBackTheSameThroughBothPaths)
{
  Fixture fixture;

  const NodeId expected{1, uint32_t{1}};
  EXPECT_EQ(fixture.named.get_node_id(), expected);
  EXPECT_EQ(fixture.named.read_attribute(AttributeId::NodeId).as<NodeId>(), expected);
}

TEST(TypedNodeAttributeStorageTests, BrowseNameReadsBackTheSameThroughBothPaths)
{
  Fixture fixture;

  const QualifiedName expected{1, "Named"};
  EXPECT_EQ(fixture.named.get_browse_name(), expected);
  EXPECT_EQ(fixture.named.read_attribute(AttributeId::BrowseName).as<QualifiedName>(), expected);
}

TEST(TypedNodeAttributeStorageTests, ABrowseNameNotGivenReadsBackAsTheNullName)
{
  Fixture fixture;

  // The generic path reads the description the typed one reads: the null name, not an empty Variant.
  const auto stored = fixture.nameless.read_attribute(AttributeId::BrowseName);
  ASSERT_TRUE(stored.is_qualified_name());
  EXPECT_EQ(stored.as<QualifiedName>(), fixture.nameless.get_browse_name());
}

TEST(TypedNodeAttributeStorageTests, WritingABrowseNameIsVisibleToBothPaths)
{
  Fixture fixture;

  fixture.nameless.set_browse_name(QualifiedName{3, "LaterNamed"});

  EXPECT_EQ(fixture.nameless.get_browse_name(), (QualifiedName{3, "LaterNamed"}));
  EXPECT_EQ(fixture.nameless.read_attribute(AttributeId::BrowseName).as<QualifiedName>(),
    (QualifiedName{3, "LaterNamed"}));
}

TEST(TypedNodeAttributeStorageTests, OverwritingABrowseNameReplacesIt)
{
  Fixture fixture;

  fixture.named.set_browse_name(QualifiedName{2, "Renamed"});

  EXPECT_EQ(fixture.named.get_browse_name(), (QualifiedName{2, "Renamed"}));
}

TEST(TypedNodeAttributeStorageTests, WritingABrowseNameIsReportedToAnItemMonitoringIt)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:browse-name", tp.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 900}, NodeClass::Object);
  auto sink = std::make_shared<test::RecordingSampleSink>();
  const auto created = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 900},
      .attributeId = AttributeId::BrowseName,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = sink});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  accessor.write_attribute_sync(AttributeId::BrowseName, Variant{QualifiedName{5, "Watched"}});

  // Moving the storage must not cost the monitored item its notification, nor change what it observes.
  ASSERT_TRUE(sink->wait_for_samples(1, std::chrono::seconds{1}));
  const auto received = sink->samples().front().second;
  ASSERT_TRUE(received.value().is_qualified_name());
  EXPECT_EQ(received.value().as<QualifiedName>(), (QualifiedName{5, "Watched"}));

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, created.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(TypedNodeAttributeStorageTests, WritingABrowseNameOfTheWrongTypeIsRefused)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:browse-name", tp.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 901}, NodeClass::Object);

  const auto result = accessor.try_write_attribute_sync(AttributeId::BrowseName, Variant{int32_t{7}});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadTypeMismatch);

  // ...and the refusal leaves the node as it was.
  EXPECT_TRUE(accessor.get_browse_name().name().empty());
}
